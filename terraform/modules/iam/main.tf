# ---------------------------------------------------------------------------
# IAM module
#
# Four identities, each with the smallest permission set that still lets it do
# its job:
#
#   1. the EC2 instance profile  -- what the application runs as
#   2. the CodeDeploy service role -- what performs deployments
#   3. the SSM maintenance window role -- what runs patching
#   4. the operator role         -- how a human reaches an instance, with MFA
#
# Every policy below carries a comment explaining the scoping decision, because
# "why is this permission here?" is the question an auditor actually asks, and
# a policy nobody can justify is a policy that will eventually be too wide.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.name

  # Parameter ARNs omit the leading slash of the parameter name.
  parameter_path_arn = "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter/${trimprefix(var.parameter_store_path, "/")}"

  app_log_group_arn_pattern = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:${var.app_log_group_prefix}*"
}

# ---------------------------------------------------------------------------
# 1. EC2 instance profile
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "instance_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.name_prefix}-instance-role"
  description        = "Application instance role: SSM agent, scoped logging, scoped config read"
  assume_role_policy = data.aws_iam_policy_document.instance_assume.json
  tags               = var.tags
}

# WHY THIS MANAGED POLICY, AND WHY ONLY THIS ONE
# AmazonSSMManagedInstanceCore is the minimum permission set the SSM agent
# needs to register with Systems Manager and hold a Session Manager channel
# open. Granting it is precisely what makes SSH unnecessary: the agent dials
# out to the SSM service, so no inbound port -- and therefore no bastion host,
# no key pair and no port 22 rule -- is required anywhere in this stack.
# It deliberately does NOT include AmazonSSMFullAccess (which would let an
# instance run commands on *other* instances) or the EC2 read APIs that would
# let a compromised host enumerate the rest of the estate.
resource "aws_iam_role_policy_attachment" "instance_ssm_core" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# WHY THIS IS SCOPED THE WAY IT IS
# Write-only, and only into this application's own log-group namespace. The
# instance can create streams and append events; it cannot call
# logs:DeleteLogGroup or logs:PutRetentionPolicy, so a process running on a
# compromised host cannot destroy or shorten the audit trail that records the
# compromise. Nor can it read any other workload's logs, which in a
# PHI-handling estate may themselves contain sensitive fields.
data "aws_iam_policy_document" "instance_logs" {
  statement {
    sid    = "WriteOwnApplicationLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = [
      local.app_log_group_arn_pattern,
      "${local.app_log_group_arn_pattern}:log-stream:*",
    ]
  }

  # DescribeLogGroups cannot be resource-scoped by the API, so it is granted
  # separately and on its own -- it leaks log group names, nothing else.
  statement {
    sid       = "DiscoverLogGroups"
    effect    = "Allow"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }

  # The CloudWatch agent publishes memory and disk metrics. PutMetricData has
  # no resource-level ARN, so the namespace condition is the only available
  # boundary -- without it, an instance could overwrite metrics that alarms and
  # deployment rollbacks depend on.
  statement {
    sid       = "PublishOwnMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = [var.cloudwatch_metrics_namespace]
    }
  }
}

resource "aws_iam_role_policy" "instance_logs" {
  name   = "application-observability"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance_logs.json
}

# WHY THIS IS SCOPED THE WAY IT IS
# The application reads its configuration from one Parameter Store path and
# nothing else. Two boundaries are stacked here:
#   * the SSM actions are limited to ARNs under this application's path, so the
#     instance cannot read another team's database credentials, and
#   * kms:Decrypt on the application CMK is constrained by kms:ViaService to
#     calls arriving through Systems Manager. Even with this policy, code on
#     the instance cannot use the key directly to decrypt an EBS snapshot or an
#     S3 object -- only to unseal a SecureString it was already allowed to read.
# No ssm:PutParameter is granted: configuration flows one way, from the
# reviewed pipeline into the instance, never back out of a running host.
data "aws_iam_policy_document" "instance_parameters" {
  statement {
    sid    = "ReadOwnConfiguration"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
    ]
    resources = [
      local.parameter_path_arn,
      "${local.parameter_path_arn}/*",
    ]
  }

  statement {
    sid       = "DecryptSecureStringsViaSSMOnly"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.app_kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "instance_parameters" {
  name   = "read-scoped-parameters"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance_parameters.json
}

# WHY THIS IS SCOPED THE WAY IT IS
# Session Manager writes a transcript of every interactive session to S3 and
# CloudWatch Logs, and the *instance* is what uploads it. Write access is
# limited to this one prefix of the audit bucket; there is no s3:GetObject and
# no s3:DeleteObject, so an operator cannot read back or scrub the recording of
# what they just did. That asymmetry is what makes the session log usable as
# evidence rather than merely as a convenience.
data "aws_iam_policy_document" "instance_session_logging" {
  statement {
    sid       = "WriteSessionTranscripts"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${var.session_logs_bucket_arn}/${var.session_logs_prefix}/*"]
  }

  statement {
    sid       = "ReadBucketEncryptionSettings"
    effect    = "Allow"
    actions   = ["s3:GetEncryptionConfiguration"]
    resources = [var.session_logs_bucket_arn]
  }
}

resource "aws_iam_role_policy" "instance_session_logging" {
  name   = "session-transcript-upload"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.instance_session_logging.json
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name_prefix}-instance-profile"
  role = aws_iam_role.instance.name
  tags = var.tags
}

# ---------------------------------------------------------------------------
# 2. CodeDeploy service role
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "codedeploy_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["codedeploy.amazonaws.com"]
    }
    # Confused-deputy protection: only CodeDeploy acting on behalf of THIS
    # account can assume the role.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "codedeploy" {
  name               = "${var.name_prefix}-codedeploy-role"
  description        = "CodeDeploy service role: ASG and ELB orchestration only"
  assume_role_policy = data.aws_iam_policy_document.codedeploy_assume.json
  tags               = var.tags
}

# WHY THIS MANAGED POLICY
# AWSCodeDeployRole is the AWS-maintained policy for exactly this job: describe
# and update Auto Scaling groups, register and deregister targets on ELB/ALB,
# read EC2 and tag state, and publish deployment notifications. It contains no
# data-plane permissions at all -- CodeDeploy can replace instances but cannot
# read S3 objects, decrypt with our CMK or touch the database. Hand-rolling an
# equivalent policy is possible but tends to drift behind AWS's own updates as
# blue/green internals change, so the managed policy is the safer choice here;
# the narrowing that actually matters is the PassRole constraint below.
resource "aws_iam_role_policy_attachment" "codedeploy_managed" {
  role       = aws_iam_role.codedeploy.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSCodeDeployRole"
}

# WHY THIS IS SCOPED THE WAY IT IS
# Blue/green with COPY_AUTO_SCALING_GROUP means CodeDeploy launches a
# replacement fleet, which requires it to pass an instance profile to EC2.
# Unconstrained, iam:PassRole is a privilege-escalation primitive: it would let
# anyone who can create a deployment launch an instance carrying ANY role in
# the account, including an administrator role. Both conditions matter -- the
# resource limits it to this one application role, and PassedToService limits
# it to EC2 so the role cannot be handed to some other service.
data "aws_iam_policy_document" "codedeploy_pass_role" {
  statement {
    sid       = "PassOnlyTheApplicationInstanceRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.instance.arn]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "codedeploy_pass_role" {
  name   = "pass-instance-role-to-ec2-only"
  role   = aws_iam_role.codedeploy.id
  policy = data.aws_iam_policy_document.codedeploy_pass_role.json
}

# ---------------------------------------------------------------------------
# 3. Systems Manager maintenance window role
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "maintenance_window_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "maintenance_window" {
  name               = "${var.name_prefix}-ssm-maintenance-window-role"
  description        = "Runs Patch Manager tasks during the maintenance window"
  assume_role_policy = data.aws_iam_policy_document.maintenance_window_assume.json
  tags               = var.tags
}

# WHY THIS MANAGED POLICY
# AmazonSSMMaintenanceWindowRole grants only what a maintenance window needs to
# invoke a Run Command / Automation task against registered targets. It cannot
# create instances, change security groups or read application data -- patching
# authority is separate from deployment authority, so a compromise of the
# patching path does not become a way to ship code.
resource "aws_iam_role_policy_attachment" "maintenance_window_managed" {
  role       = aws_iam_role.maintenance_window.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonSSMMaintenanceWindowRole"
}

# ---------------------------------------------------------------------------
# 4. Human operator role (the only interactive path to an instance)
# ---------------------------------------------------------------------------

# WHY THIS IS SCOPED THE WAY IT IS
# There is no SSH key, no bastion and no inbound port 22 anywhere in this
# stack, so this role is how a human gets a shell -- and it is deliberately
# uncomfortable to hold:
#   * assuming it requires an MFA credential presented within the last hour
#     (45 CFR 164.312(d), person or entity authentication),
#   * sessions are capped at one hour, so access naturally expires,
#   * StartSession is allowed only against instances carrying a specific tag,
#     which makes "which hosts can this person reach?" a tag query rather than
#     a guess, and
#   * port-forwarding documents are explicitly denied. Without that Deny, an
#     operator could tunnel the private database port to a laptop and pull ePHI
#     out through a channel that the session transcript would not capture.
data "aws_iam_policy_document" "operator_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
    condition {
      test     = "NumericLessThan"
      variable = "aws:MultiFactorAuthAge"
      values   = ["3600"]
    }
  }
}

resource "aws_iam_role" "operator" {
  name                 = "${var.name_prefix}-operator-role"
  description          = "MFA-gated, session-logged Session Manager access to tagged instances"
  assume_role_policy   = data.aws_iam_policy_document.operator_assume.json
  max_session_duration = 3600
  tags                 = var.tags
}

data "aws_iam_policy_document" "operator" {
  statement {
    sid       = "StartSessionsOnTaggedInstancesOnly"
    effect    = "Allow"
    actions   = ["ssm:StartSession"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/${var.operator_session_tag_key}"
      values   = [var.operator_session_tag_value]
    }
  }

  statement {
    sid    = "UseTheLoggedShellDocument"
    effect = "Allow"
    actions = [
      "ssm:StartSession",
      "ssm:GetDocument",
      "ssm:DescribeDocument",
    ]
    resources = [
      "arn:${local.partition}:ssm:${local.region}:${local.account_id}:document/SSM-SessionManagerRunShell",
      "arn:${local.partition}:ssm:${local.region}::document/AWS-StartInteractiveCommand",
    ]
  }

  statement {
    sid    = "DenyPortForwardingTunnels"
    effect = "Deny"
    actions = [
      "ssm:StartSession",
    ]
    resources = [
      "arn:${local.partition}:ssm:${local.region}::document/AWS-StartPortForwardingSession",
      "arn:${local.partition}:ssm:${local.region}::document/AWS-StartPortForwardingSessionToRemoteHost",
      "arn:${local.partition}:ssm:${local.region}::document/AWS-StartSSHSession",
    ]
  }

  # Session IDs are named "<caller>-<random>", so this ARN pattern lets an
  # operator resume or kill their own session and nobody else's -- one
  # engineer cannot terminate another's session mid-incident, and cannot
  # hijack a session that is already attached to a host.
  statement {
    sid    = "ManageOwnSessionsOnly"
    effect = "Allow"
    actions = [
      "ssm:TerminateSession",
      "ssm:ResumeSession",
    ]
    resources = ["arn:${local.partition}:ssm:${local.region}:${local.account_id}:session/$${aws:username}-*"]
  }

  statement {
    sid    = "ReadOnlyDiscovery"
    effect = "Allow"
    actions = [
      "ssm:DescribeSessions",
      "ssm:GetConnectionStatus",
      "ssm:DescribeInstanceInformation",
      "ec2:DescribeInstances",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "operator" {
  name   = "session-manager-access"
  role   = aws_iam_role.operator.id
  policy = data.aws_iam_policy_document.operator.json
}
