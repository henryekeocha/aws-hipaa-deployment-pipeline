# ---------------------------------------------------------------------------
# AWS Config
#
# CloudTrail answers "what happened?". AWS Config answers "what is the
# configuration right now, and does it still comply?" -- which is the evidence
# an auditor asks for under 45 CFR 164.308(a)(8) (evaluation). The managed
# rules below are chosen to continuously re-test the specific claims this
# repository makes elsewhere in the code.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "config" {
  bucket = local.config_bucket
  tags   = merge(var.tags, { Name = local.config_bucket })
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "config" {
  bucket        = aws_s3_bucket.config.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/config/"
}

data "aws_iam_policy_document" "config_bucket" {
  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.config.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.config.arn, "${aws_s3_bucket.config.arn}/*"]
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
}

resource "aws_s3_bucket_policy" "config" {
  bucket     = aws_s3_bucket.config.id
  policy     = data.aws_iam_policy_document.config_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.config]
}

data "aws_iam_policy_document" "config_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "${var.name_prefix}-config-recorder"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
  tags               = var.tags
}

# AWS_ConfigRole is the AWS-managed, purpose-built read-only policy for the
# Config recorder: it grants Describe/List/Get across services so Config can
# snapshot resource state, and nothing that can mutate a resource.
resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Delivery to the Config bucket is granted explicitly and narrowly, rather than
# via a broad s3:* on all buckets.
data "aws_iam_policy_document" "config_delivery" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]
  }

  statement {
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.audit.arn]
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  name   = "config-delivery"
  role   = aws_iam_role.config.id
  policy = data.aws_iam_policy_document.config_delivery.json
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.name_prefix}-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config.id
  s3_key_prefix  = "AWSLogs/${local.account_id}/Config"

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.config,
  ]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# Each rule below maps to a claim made elsewhere in this repository, so drift
# away from the documented posture surfaces as a NON_COMPLIANT finding instead
# of going unnoticed until the next manual review.
locals {
  config_rules = {
    # data module: storage_encrypted = true with a customer-managed key
    rds-storage-encrypted = "RDS_STORAGE_ENCRYPTED"
    # data module: publicly_accessible = false
    rds-instance-public-access-check = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
    # compute module: encrypted root volume
    encrypted-volumes = "ENCRYPTED_VOLUMES"
    # compute module: http_tokens = "required"
    ec2-imdsv2-check = "EC2_IMDSv2_CHECK"
    # compute module: no port 22 ingress anywhere
    restricted-ssh = "INCOMING_SSH_DISABLED"
    # audit + data modules: public access blocked on every bucket
    s3-bucket-public-read-prohibited  = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    s3-bucket-public-write-prohibited = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    # audit module: this trail stays on
    cloudtrail-enabled = "CLOUD_TRAIL_ENABLED"
    # iam module: humans authenticate with MFA, not long-lived keys
    iam-user-mfa-enabled = "IAM_USER_MFA_ENABLED"
    # ssm module: instances stay patched against the baseline
    ec2-managedinstance-patch-compliance-status = "EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK"
  }
}

resource "aws_config_config_rule" "managed" {
  for_each = local.config_rules

  name = "${var.name_prefix}-${each.key}"

  source {
    owner             = "AWS"
    source_identifier = each.value
  }

  tags       = var.tags
  depends_on = [aws_config_configuration_recorder_status.main]
}
