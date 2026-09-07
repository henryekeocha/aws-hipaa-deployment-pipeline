# ---------------------------------------------------------------------------
# Audit module
#
# Everything that observes the environment lives here:
#
#   * a customer-managed KMS key dedicated to audit data (separate from the
#     application data key so that key custody for "the evidence" is separate
#     from key custody for "the records" -- a compromised application key
#     must not also decrypt the audit trail that would expose the compromise),
#   * a hardened CloudTrail bucket (versioned, WORM, access-logged, TLS-only),
#   * a shared log-delivery bucket used by S3 server access logging, ALB
#     access logs, VPC flow logs and SSM Session Manager session transcripts,
#   * CloudTrail itself, with log-file validation enabled, and
#   * an AWS Config recorder plus a starter set of managed rules that
#     continuously evaluate the controls this repo claims to implement.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  partition     = data.aws_partition.current.partition
  region        = data.aws_region.current.name
  trail_name    = "${var.name_prefix}-trail"
  trail_bucket  = "${var.name_prefix}-cloudtrail-${local.account_id}-${local.region}"
  logs_bucket   = "${var.name_prefix}-access-logs-${local.account_id}-${local.region}"
  config_bucket = "${var.name_prefix}-config-${local.account_id}-${local.region}"
  trail_arn     = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}

# ---------------------------------------------------------------------------
# KMS key for audit data
# ---------------------------------------------------------------------------

# The key policy is deliberately narrow. Only two things can use this key:
# the account's IAM administration path (so the key is not orphaned), and the
# two AWS services that must encrypt audit records on our behalf. Application
# roles are NOT granted access -- the app tier can write audit events through
# CloudTrail, but it can never read the trail back.
data "aws_iam_policy_document" "audit_key" {
  statement {
    sid    = "EnableAccountKeyAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudTrailToEncryptLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogsToEncryptLogGroups"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "audit" {
  description = "CMK for CloudTrail, AWS Config and audit log groups (${var.name_prefix})"
  policy      = data.aws_iam_policy_document.audit_key.json

  # Annual rotation is a cheap, automatic control; the deletion window gives a
  # 30-day window to abort an accidental key destruction, which would otherwise
  # render the entire audit archive unreadable.
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, { Name = "${var.name_prefix}-audit-key" })
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${var.name_prefix}-audit"
  target_key_id = aws_kms_key.audit.key_id
}

# ---------------------------------------------------------------------------
# Shared log-delivery bucket
#
# Destination for S3 server access logs, ALB access logs, VPC flow logs and
# SSM Session Manager transcripts. AWS log-delivery mechanisms differ in their
# support for SSE-KMS with a customer-managed key, and several of them require
# the delivery service to be able to read the key. Rather than widen the audit
# key policy to four more service principals, this bucket uses SSE-S3
# (AES-256, AWS-managed keys). Data is still encrypted at rest; the trade-off
# is key custody, not encryption, and the sensitive artifact -- the CloudTrail
# archive itself -- does use the customer-managed key.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "logs" {
  bucket = local.logs_bucket
  tags   = merge(var.tags, { Name = local.logs_bucket })
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    # ACLs disabled entirely; access is governed by bucket policy and IAM only.
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"
    filter {}

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 365
      storage_class = "GLACIER"
    }
    expiration {
      days = var.audit_log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.logs]
}

data "aws_iam_policy_document" "logs" {
  # Transmission security: reject any request that did not arrive over TLS,
  # including the log-delivery services below.
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # S3 server access logging (the CloudTrail bucket logs its own reads here).
  statement {
    sid    = "AllowS3ServerAccessLogging"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/s3-access-logs/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # ALB access logs.
  statement {
    sid    = "AllowELBAccessLogging"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/alb-access-logs/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # VPC flow logs.
  statement {
    sid    = "AllowVPCFlowLogDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/vpc-flow-logs/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AllowVPCFlowLogAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket     = aws_s3_bucket.logs.id
  policy     = data.aws_iam_policy_document.logs.json
  depends_on = [aws_s3_bucket_public_access_block.logs]
}
