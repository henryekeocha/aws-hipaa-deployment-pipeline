# ---------------------------------------------------------------------------
# CloudTrail archive bucket
#
# This is the tamper-evidence store. Four properties matter for an audit:
#   1. versioning        -- an overwrite cannot destroy the prior object
#   2. object lock       -- new objects are write-once for the retention period
#   3. access logging    -- reads of the audit trail are themselves audited
#   4. TLS-only policy   -- the trail cannot be fetched over plaintext HTTP
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "trail" {
  bucket = local.trail_bucket

  # Object Lock can only be enabled at bucket creation time; it cannot be added
  # to an existing bucket. Enabling it here also force-enables versioning.
  object_lock_enabled = true

  tags = merge(var.tags, { Name = local.trail_bucket })
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      # Customer-managed key, NOT the aws/s3 default key: key policy, rotation
      # and deletion are all under our control and are themselves auditable.
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    # S3 Bucket Keys cut KMS request volume (and cost) on high-object-count
    # buckets without weakening the encryption.
    bucket_key_enabled = true
  }
}

# GOVERNANCE mode rather than COMPLIANCE: an operator holding the explicit
# s3:BypassGovernanceRetention permission can still remove an object (useful if
# PHI is ever written here in error and must be deleted). COMPLIANCE mode would
# make deletion impossible for anyone, including the account root, until the
# retention period expires. Choose per your organisation's legal guidance.
resource "aws_s3_bucket_object_lock_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.trail]
}

resource "aws_s3_bucket_logging" "trail" {
  bucket        = aws_s3_bucket.trail.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/cloudtrail/"
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "retain-audit-records"
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
  }

  depends_on = [aws_s3_bucket_versioning.trail]
}

# Only the CloudTrail service principal may write here, and only for this
# account's own trail (aws:SourceArn). Note there is no Allow statement for any
# human or application role: read access is granted separately and explicitly
# to auditors, so day-to-day operators cannot read or alter the trail.
data "aws_iam_policy_document" "trail" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
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

  # Defence in depth against a misconfigured client silently downgrading the
  # archive to SSE-S3 or no encryption at all.
  statement {
    sid       = "DenyUnencryptedObjectUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket     = aws_s3_bucket.trail.id
  policy     = data.aws_iam_policy_document.trail.json
  depends_on = [aws_s3_bucket_public_access_block.trail]
}

# ---------------------------------------------------------------------------
# CloudTrail -> S3 + CloudWatch Logs
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.audit.arn
  tags              = var.tags
}

data "aws_iam_policy_document" "trail_cwl_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

# Scoped to exactly one log group and two write actions. CloudTrail can append
# events; it cannot list, read back or delete them.
data "aws_iam_policy_document" "trail_cwl" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:*"]
  }
}

resource "aws_iam_role" "trail_cwl" {
  name               = "${var.name_prefix}-cloudtrail-cwl"
  assume_role_policy = data.aws_iam_policy_document.trail_cwl_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "trail_cwl" {
  name   = "cloudtrail-to-cloudwatch-logs"
  role   = aws_iam_role.trail_cwl.id
  policy = data.aws_iam_policy_document.trail_cwl.json
}

resource "aws_cloudtrail" "main" {
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.trail.id
  s3_key_prefix  = ""

  # Account-wide coverage: every region, plus global (IAM, STS, CloudFront)
  # events, so an attacker cannot simply operate in an unmonitored region.
  is_multi_region_trail         = true
  include_global_service_events = true

  # Emits a signed digest file per hour; `aws cloudtrail validate-logs` can
  # then prove after the fact that no log file was modified or deleted.
  # This is the concrete control behind the HIPAA "Integrity" safeguard.
  enable_log_file_validation = true

  kms_key_id                 = aws_kms_key.audit.arn
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_cwl.arn
  enable_logging             = true

  # Management events capture the control plane (who changed what). The S3 data
  # event selector additionally captures object-level reads and writes, which
  # is what tells you whether anyone actually touched a PHI object.
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:${local.partition}:s3"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]

  tags = merge(var.tags, { Name = local.trail_name })
}
