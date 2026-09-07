# ---------------------------------------------------------------------------
# Data module
#
# A PostgreSQL instance that is assumed to hold ePHI, plus the customer-managed
# KMS key that protects application data across the whole stack (database
# storage, EBS root volumes, Parameter Store SecureStrings and the application
# log groups).
#
# WHY A CUSTOMER-MANAGED KEY RATHER THAN THE AWS-MANAGED DEFAULT
# The aws/rds default key would technically satisfy "encrypted at rest", but a
# customer-managed key (CMK) is what makes the control auditable and revocable:
#   * its key policy is ours, so we can enumerate exactly which principals may
#     decrypt, and deny everyone else,
#   * every Encrypt/Decrypt/GenerateDataKey call appears in CloudTrail with the
#     calling principal, which is the evidence trail for 164.312(b),
#   * annual rotation is under our control and provable,
#   * disabling or scheduling deletion of the key cryptographically cuts off
#     access to the data -- a containment lever the AWS-managed key does not
#     offer, and
#   * an AWS-managed key cannot be shared cross-account under controlled terms,
#     which blocks the usual disaster-recovery and BAA-partner patterns.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  partition   = data.aws_partition.current.partition
  region      = data.aws_region.current.name
  identifier  = "${var.name_prefix}-postgres"
  db_port     = 5432
  family      = "postgres${var.engine_version}"
  logs_prefix = "/aws/rds/instance/${local.identifier}"
}

data "aws_iam_policy_document" "app_key" {
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

  # Scoped by encryption context to this account's log groups only, so the
  # CloudWatch Logs service cannot be used as a confused deputy to decrypt
  # database snapshots or Parameter Store values with the same key.
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

  # Lets Auto Scaling launch instances with CMK-encrypted EBS root volumes.
  # Without this grant path the ASG cannot start an instance at all.
  statement {
    sid    = "AllowAutoScalingToUseKeyForEBS"
    effect = "Allow"
    principals {
      type = "AWS"
      identifiers = [
        "arn:${local.partition}:iam::${local.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
      ]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant",
    ]
    resources = ["*"]
  }
}

resource "aws_kms_key" "app" {
  description             = "CMK for application data at rest: RDS, EBS, SSM SecureString (${var.name_prefix})"
  policy                  = data.aws_iam_policy_document.app_key.json
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(var.tags, { Name = "${var.name_prefix}-app-key" })
}

resource "aws_kms_alias" "app" {
  name          = "alias/${var.name_prefix}-app"
  target_key_id = aws_kms_key.app.key_id
}

# ---------------------------------------------------------------------------
# Network placement
# ---------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name        = "${var.name_prefix}-db-subnets"
  description = "Private subnets for ${local.identifier}"
  subnet_ids  = var.private_subnet_ids

  tags = merge(var.tags, { Name = "${var.name_prefix}-db-subnets" })
}

resource "aws_security_group" "db" {
  name        = "${var.name_prefix}-db-sg"
  description = "PostgreSQL access from the application tier only"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, { Name = "${var.name_prefix}-db-sg" })
}

# The single ingress rule references the application security group by ID, not
# by CIDR. Membership of that group -- not an IP address that could be reused
# by some other workload -- is what grants database reachability.
resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "PostgreSQL from the application tier"
  referenced_security_group_id = var.app_security_group_id
  from_port                    = local.db_port
  to_port                      = local.db_port
  ip_protocol                  = "tcp"
}

# No egress rules are declared. A database has no reason to originate
# connections, and an empty egress set is a meaningful barrier to exfiltration
# if the instance is ever compromised.

# ---------------------------------------------------------------------------
# Engine configuration
# ---------------------------------------------------------------------------

resource "aws_db_parameter_group" "main" {
  name        = "${var.name_prefix}-postgres-params"
  family      = local.family
  description = "TLS enforcement and connection auditing for ${local.identifier}"

  # Transmission security: rds.force_ssl rejects any non-TLS connection at the
  # engine, so encryption in transit does not depend on every client
  # remembering to ask for it.
  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  # Audit controls: record who connected, when they disconnected, and every
  # DDL statement executed against the database.
  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  tags = var.tags
}

# Pre-creating the log groups (rather than letting RDS create them implicitly)
# is what allows retention and CMK encryption to be set on them.
resource "aws_cloudwatch_log_group" "database" {
  for_each = toset(["postgresql", "upgrade"])

  name              = "${local.logs_prefix}/${each.value}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.app.arn

  tags = var.tags
}

resource "aws_db_instance" "main" {
  identifier     = local.identifier
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = "gp3"

  # Encryption at rest with the customer-managed key described above. Automated
  # backups, read replicas and snapshots inherit this key.
  storage_encrypted = true
  kms_key_id        = aws_kms_key.app.arn

  db_name  = var.database_name
  username = var.master_username

  # The master password is generated and rotated by AWS Secrets Manager. It is
  # never written to a variable, a tfvars file or Terraform state -- which is
  # the whole point: state files are frequently the weakest link in an
  # otherwise encrypted stack.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.app.arn

  # Application principals authenticate with short-lived IAM auth tokens rather
  # than a shared static password (45 CFR 164.312(d), person or entity
  # authentication).
  iam_database_authentication_enabled = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  port                   = local.db_port

  # Never true. The instance has no public IP and no route to an internet
  # gateway; this flag is the belt to that architecture's braces.
  publicly_accessible = false

  multi_az                 = var.multi_az
  backup_retention_period  = var.backup_retention_days
  backup_window            = "07:00-08:00"
  maintenance_window       = "sun:08:30-sun:09:30"
  copy_tags_to_snapshot    = true
  delete_automated_backups = false

  # Minor versions carry the security patches; major upgrades stay manual so
  # they can be tested first.
  auto_minor_version_upgrade  = true
  allow_major_version_upgrade = false
  apply_immediately           = false

  # Forces clients onto a current CA bundle for TLS validation.
  ca_cert_identifier = "rds-ca-rsa2048-g1"

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.app.arn
  performance_insights_retention_period = 7

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  parameter_group_name            = aws_db_parameter_group.main.name

  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.identifier}-final-${formatdate("YYYYMMDDhhmmss", timestamp())}"

  tags = merge(var.tags, { Name = local.identifier, DataClassification = "ePHI" })

  lifecycle {
    # The final snapshot identifier embeds a timestamp, which would otherwise
    # show up as spurious drift on every plan.
    ignore_changes = [final_snapshot_identifier]
  }

  depends_on = [aws_cloudwatch_log_group.database]
}
