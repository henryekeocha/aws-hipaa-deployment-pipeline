# ---------------------------------------------------------------------------
# CodeDeploy module
#
# The only path by which code reaches a production instance.
#
# This matters more than it sounds. Because there is no SSH and no bastion, an
# engineer physically cannot hand-edit a file on a running host and walk away;
# a change ships as a versioned, immutable bundle in S3, is applied by an
# agent, is validated by a lifecycle hook, and is rolled back automatically if
# the validation or the alarms say it went badly. That gives the deployment
# path the same property the audit story needs: every change to the system that
# handles ePHI is attributable, reviewable and reversible.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id     = data.aws_caller_identity.current.account_id
  partition      = data.aws_partition.current.partition
  region         = data.aws_region.current.name
  bucket_name    = "${var.name_prefix}-deploy-artifacts-${local.account_id}-${local.region}"
  app_name       = "${var.name_prefix}-app"
  notify_enabled = var.notification_email != ""
}

# ---------------------------------------------------------------------------
# Artifact bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "artifacts" {
  bucket = local.bucket_name
  tags   = merge(var.tags, { Name = local.bucket_name })
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Versioning is not just durability here: CodeDeploy addresses a revision by
# object version, so an immutable, addressable history of exactly what was
# deployed is a by-product of turning it on.
resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-revisions"
    status = "Enabled"
    filter {}

    expiration {
      days = var.artifact_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.artifacts]
}

data "aws_iam_policy_document" "artifacts" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
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

resource "aws_s3_bucket_policy" "artifacts" {
  bucket     = aws_s3_bucket.artifacts.id
  policy     = data.aws_iam_policy_document.artifacts.json
  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

# WHY THIS IS SCOPED THE WAY IT IS
# The CodeDeploy agent on each instance pulls the revision itself, so the
# instance role needs read access to this bucket -- and only read, and only to
# this bucket. There is no s3:PutObject: an instance cannot publish a revision,
# so a compromised host cannot inject a bundle that would then be deployed
# across the rest of the fleet. kms:Decrypt is constrained by kms:ViaService to
# calls arriving through S3, so the same grant cannot be reused to read an
# encrypted snapshot or a SecureString.
data "aws_iam_policy_document" "instance_artifact_read" {
  statement {
    sid       = "ReadDeploymentBundles"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
  }

  statement {
    sid       = "ListBundleLocations"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.artifacts.arn]
  }

  statement {
    sid       = "DecryptBundlesViaS3Only"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "instance_artifact_read" {
  name   = "read-deployment-artifacts"
  role   = var.instance_role_name
  policy = data.aws_iam_policy_document.instance_artifact_read.json
}

# ---------------------------------------------------------------------------
# Deployment notifications
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "deployments" {
  name              = "${var.name_prefix}-deployments"
  kms_master_key_id = "alias/aws/sns"
  tags              = var.tags
}

data "aws_iam_policy_document" "deployments_topic" {
  statement {
    sid    = "AllowCodeDeployToPublish"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["codedeploy.amazonaws.com"]
    }
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.deployments.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "deployments" {
  arn    = aws_sns_topic.deployments.arn
  policy = data.aws_iam_policy_document.deployments_topic.json
}

resource "aws_sns_topic_subscription" "deployments_email" {
  count = local.notify_enabled ? 1 : 0

  topic_arn = aws_sns_topic.deployments.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# ---------------------------------------------------------------------------
# CodeDeploy application and deployment group
# ---------------------------------------------------------------------------

resource "aws_codedeploy_app" "main" {
  name             = local.app_name
  compute_platform = "Server"
  tags             = var.tags
}

resource "aws_codedeploy_deployment_group" "main" {
  app_name              = aws_codedeploy_app.main.name
  deployment_group_name = "${var.name_prefix}-production"
  service_role_arn      = var.service_role_arn
  autoscaling_groups    = [var.autoscaling_group_name]

  # AllAtOnce applies to the *green* fleet, which is a brand-new set of
  # instances taking no live traffic. Traffic only moves once those instances
  # pass the ALB health check and the ValidateService hook in app/appspec.yml,
  # so there is no window in which users hit a half-deployed fleet.
  deployment_config_name = "CodeDeployDefault.AllAtOnce"

  deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type   = "BLUE_GREEN"
  }

  blue_green_deployment_config {
    # Provision an identical replacement fleet by copying the existing ASG's
    # launch template and settings, rather than deploying in place. Nothing is
    # mutated on a running instance, which is what makes a release reversible.
    green_fleet_provisioning_option {
      action = "COPY_AUTO_SCALING_GROUP"
    }

    # Shift traffic as soon as the green fleet is healthy. Switch to
    # STOP_DEPLOYMENT with a wait_time_in_minutes if a human sign-off is
    # required before a release becomes live.
    deployment_ready_option {
      action_on_timeout = "CONTINUE_DEPLOYMENT"
    }

    # The blue fleet is kept alive for the rollback window before termination.
    terminate_blue_instances_on_deployment_success {
      action                           = "TERMINATE"
      termination_wait_time_in_minutes = var.termination_wait_minutes
    }
  }

  load_balancer_info {
    target_group_info {
      name = var.target_group_name
    }
  }

  # ROLLBACK ON FAILURE
  # DEPLOYMENT_FAILURE covers a failed lifecycle hook -- including the
  # ValidateService hook, which curls the health endpoint on the green fleet
  # before any traffic is shifted. DEPLOYMENT_STOP_ON_ALARM covers the case
  # where the code deploys cleanly but behaves badly under real traffic: the
  # unhealthy-host and 5xx alarms from the compute module fire, and CodeDeploy
  # shifts traffic back to the blue fleet, which is still running.
  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE", "DEPLOYMENT_STOP_ON_ALARM"]
  }

  dynamic "alarm_configuration" {
    for_each = length(var.rollback_alarm_names) > 0 ? [1] : []
    content {
      enabled = true
      alarms  = var.rollback_alarm_names

      # If CloudWatch cannot be polled, treat that as a reason to stop rather
      # than to proceed blind.
      ignore_poll_alarm_failure = false
    }
  }

  trigger_configuration {
    trigger_name       = "deployment-outcome"
    trigger_target_arn = aws_sns_topic.deployments.arn
    trigger_events = [
      "DeploymentSuccess",
      "DeploymentFailure",
      "DeploymentRollback",
      "DeploymentStop",
    ]
  }

  tags = var.tags

  depends_on = [aws_sns_topic_policy.deployments]
}
