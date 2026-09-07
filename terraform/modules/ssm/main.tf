# ---------------------------------------------------------------------------
# Systems Manager module
#
# Three jobs, all of which exist to remove a reason someone would otherwise
# want SSH:
#
#   1. Session Manager -- IAM-authenticated, fully recorded shell access with
#      no inbound port, no bastion host and no key material to manage.
#   2. Patch Manager   -- a baseline plus a maintenance window, so
#      "we apply security patches" is a scheduled, evidenced control rather
#      than a promise (45 CFR 164.308(a)(5)(ii)(B)).
#   3. Parameter Store -- encrypted configuration, so secrets live in a
#      versioned, access-logged, KMS-protected store instead of in an AMI, a
#      user-data script, an environment file in git, or Terraform state.
#
# The SSM agent needs no inbound connectivity at all: it dials out to the
# Systems Manager endpoints (via the interface VPC endpoints created in the
# network module), which is precisely why the application security group can
# have exactly one ingress rule.
# ---------------------------------------------------------------------------

data "aws_region" "current" {}

locals {
  session_log_group = "/aws/ssm/${var.name_prefix}/sessions"
  patch_log_group   = "/aws/ssm/${var.name_prefix}/patching"
}

# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "sessions" {
  name              = local.session_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "patching" {
  name              = local.patch_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

# The document name is fixed by AWS: a Session-type document called exactly
# "SSM-SessionManagerRunShell" becomes the account's default session
# preferences in this region. Creating it in Terraform is what stops session
# logging from being a console setting somebody can quietly switch off.
#
# The settings below are the audit control:
#   * every keystroke and every byte of output is streamed to S3 and to
#     CloudWatch Logs, both encrypted,
#   * kmsKeyId adds end-to-end encryption of the session channel itself, so the
#     transcript is protected in transit as well as at rest,
#   * runAsEnabled pins sessions to a non-root service account rather than
#     ssm-user with sudo, and
#   * idle sessions time out instead of lingering as an unattended open shell
#     on a host that handles ePHI (45 CFR 164.312(a)(2)(iii)).
resource "aws_ssm_document" "session_preferences" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Session Manager preferences: encrypted, dual-destination session logging"
    sessionType   = "Standard_Stream"
    inputs = {
      s3BucketName                = var.session_logs_bucket
      s3KeyPrefix                 = var.session_logs_prefix
      s3EncryptionEnabled         = true
      cloudWatchLogGroupName      = aws_cloudwatch_log_group.sessions.name
      cloudWatchEncryptionEnabled = true
      cloudWatchStreamingEnabled  = true
      kmsKeyId                    = var.kms_key_id
      idleSessionTimeout          = var.idle_session_timeout_minutes
      runAsEnabled                = true
      runAsDefaultUser            = "appuser"
      shellProfile = {
        linux = "cd /opt/hipaa-demo-app && export PS1='[hipaa-demo \\W]$ '"
      }
    }
  })

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Patch Manager
# ---------------------------------------------------------------------------

resource "aws_ssm_patch_baseline" "app" {
  name             = "${var.name_prefix}-al2023-baseline"
  description      = "Security and critical bugfix patches for Amazon Linux 2023 application instances"
  operating_system = "AMAZON_LINUX_2023"

  # Anything auto-approved by this baseline is treated as a CRITICAL compliance
  # item, so a host that misses a window shows up as NON_COMPLIANT in the
  # Config rule rather than drifting quietly.
  approved_patches_compliance_level = "CRITICAL"

  # A short soak between a patch's release and its automatic approval trades a
  # few days of exposure for protection against a bad vendor patch taking the
  # fleet down. Seven days is a common middle ground; shorten it for actively
  # exploited CVEs, which should be pushed out of band anyway.
  approval_rule {
    approve_after_days  = var.patch_approval_delay_days
    compliance_level    = "CRITICAL"
    enable_non_security = false

    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security"]
    }

    patch_filter {
      key    = "SEVERITY"
      values = ["Critical", "Important"]
    }
  }

  approval_rule {
    approve_after_days  = 14
    compliance_level    = "HIGH"
    enable_non_security = false

    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Bugfix"]
    }
  }

  tags = var.tags
}

# Binds every instance tagged PatchGroup = <value> to the baseline above. The
# compute module applies that tag at launch, so instances are covered from
# first boot rather than after someone remembers to register them.
resource "aws_ssm_patch_group" "app" {
  baseline_id = aws_ssm_patch_baseline.app.id
  patch_group = var.patch_group
}

resource "aws_ssm_maintenance_window" "patching" {
  name                       = "${var.name_prefix}-patching"
  description                = "Weekly patch installation window for application instances"
  schedule                   = var.maintenance_window_schedule
  schedule_timezone          = var.maintenance_window_timezone
  duration                   = 3
  cutoff                     = 1
  allow_unassociated_targets = false

  tags = var.tags
}

resource "aws_ssm_maintenance_window_target" "patching" {
  window_id     = aws_ssm_maintenance_window.patching.id
  name          = "${var.name_prefix}-patch-targets"
  description   = "Instances carrying the PatchGroup tag"
  resource_type = "INSTANCE"

  targets {
    key    = "tag:PatchGroup"
    values = [var.patch_group]
  }
}

resource "aws_ssm_maintenance_window_task" "patching" {
  window_id        = aws_ssm_maintenance_window.patching.id
  name             = "${var.name_prefix}-install-patches"
  description      = "Run AWS-RunPatchBaseline in Install mode"
  task_type        = "RUN_COMMAND"
  task_arn         = "AWS-RunPatchBaseline"
  priority         = 1
  service_role_arn = var.maintenance_window_role_arn

  # Patch half the fleet at a time and abort if two hosts fail, so a bad patch
  # cannot take the whole service down before anyone notices.
  max_concurrency = "50%"
  max_errors      = "2"

  targets {
    key    = "WindowTargetIds"
    values = [aws_ssm_maintenance_window_target.patching.id]
  }

  task_invocation_parameters {
    run_command_parameters {
      document_version = "$DEFAULT"
      timeout_seconds  = 3600

      parameter {
        name   = "Operation"
        values = ["Install"]
      }

      parameter {
        name   = "RebootOption"
        values = ["RebootIfNeeded"]
      }

      cloudwatch_config {
        cloudwatch_log_group_name = aws_cloudwatch_log_group.patching.name
        cloudwatch_output_enabled = true
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Parameter Store
#
# "Secrets are never hardcoded" is only true if there is somewhere else for
# them to live. These two parameters demonstrate the pattern the application
# actually uses: it calls GetParametersByPath at start-up, scoped to the one
# path its instance role is allowed to read.
# ---------------------------------------------------------------------------

resource "aws_ssm_parameter" "app_feature_flags" {
  name        = "${var.parameter_store_path}/feature-flags"
  description = "Non-sensitive application configuration"
  type        = "String"
  value       = jsonencode({ audit_verbose = true, phi_field_masking = true })
  tier        = "Standard"

  tags = var.tags
}

# The SecureString is encrypted with the customer-managed key from the data
# module, so reading it requires BOTH ssm:GetParameter on this path AND
# kms:Decrypt on that key -- and, per the instance role policy, only through
# Systems Manager. Every read is a CloudTrail event naming the principal.
#
# The value here is a placeholder. The real value is written out of band (by a
# human with a break-glass role, or by a rotation Lambda) and ignore_changes
# stops Terraform from ever reading it back into state or overwriting it on the
# next apply. This is the whole point: the secret exists in exactly one place,
# and that place is not this repository, a CI variable, or a state file.
resource "aws_ssm_parameter" "app_api_token" {
  name        = "${var.parameter_store_path}/third-party-api-token"
  description = "Placeholder for a downstream API credential -- set out of band, never in Terraform"
  type        = "SecureString"
  key_id      = var.kms_key_arn
  value       = "REPLACE_ME_OUT_OF_BAND"
  tier        = "Standard"

  lifecycle {
    ignore_changes = [value]
  }

  tags = var.tags
}
