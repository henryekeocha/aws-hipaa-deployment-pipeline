# ---------------------------------------------------------------------------
# HIPAA-aligned AWS deployment pipeline -- root module
#
# Composition order, and why it is what it is:
#
#   audit    -> creates the log destinations everything else writes to, so it
#               comes first: an environment that starts logging after the fact
#               has a gap in its audit trail.
#   network  -> the VPC, and the flow logs that ship into the audit bucket.
#   compute  -> owns the application security group, so it is created before
#               the data tier that references it as an ingress source.
#   data     -> the CMK and the PHI-bearing database.
#   iam      -> roles scoped against the key, the bucket and the parameter path
#               those two modules created.
#   ssm      -> Session Manager, patching and configuration.
#   codedeploy -> the delivery path, wired to the ASG, the target group and the
#               rollback alarms from the compute module.
#
# Nothing here handles ePHI itself; the sample application is a hello-world.
# The point of the repository is the control plane around it.
# ---------------------------------------------------------------------------

locals {
  name_prefix = "${var.project_name}-${var.environment}"

  # Shared naming for cross-module references. Keeping these in one place means
  # the IAM policy scope and the resource that policy protects cannot drift
  # apart -- a classic source of accidentally over-broad permissions.
  parameter_store_path = "/${var.project_name}/${var.environment}/app"
  app_log_group_prefix = "/${var.project_name}/${var.environment}"
  metrics_namespace    = "HIPAADemo/${var.environment}"
  patch_group          = "${var.project_name}-${var.environment}-app"
  session_logs_prefix  = "ssm-session-logs"

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------
# Audit: CloudTrail, AWS Config, log destinations
# ---------------------------------------------------------------------------

module "audit" {
  source = "./modules/audit"

  name_prefix              = local.name_prefix
  audit_log_retention_days = var.audit_log_retention_days
  tags                     = local.tags
}

# ---------------------------------------------------------------------------
# Network: VPC, subnets, NAT, VPC endpoints, flow logs
# ---------------------------------------------------------------------------

module "network" {
  source = "./modules/network"

  name_prefix             = local.name_prefix
  vpc_cidr                = var.vpc_cidr
  availability_zone_count = var.availability_zone_count
  single_nat_gateway      = var.single_nat_gateway
  flow_logs_bucket_arn    = module.audit.logs_bucket_arn
  tags                    = local.tags
}

# ---------------------------------------------------------------------------
# Data: customer-managed KMS key and the PHI-bearing database
#
# The application security group is created by the compute module and consumed
# here as the sole permitted ingress source. Terraform resolves this at the
# resource level, so the two modules reference each other's outputs without a
# dependency cycle.
# ---------------------------------------------------------------------------

module "data" {
  source = "./modules/data"

  name_prefix           = local.name_prefix
  vpc_id                = module.network.vpc_id
  private_subnet_ids    = module.network.private_subnet_ids
  app_security_group_id = module.compute.app_security_group_id

  engine_version        = var.db_engine_version
  instance_class        = var.db_instance_class
  allocated_storage     = var.db_allocated_storage
  backup_retention_days = var.db_backup_retention_days
  multi_az              = var.db_multi_az
  deletion_protection   = var.db_deletion_protection
  log_retention_days    = var.log_retention_days

  tags = local.tags
}

# ---------------------------------------------------------------------------
# IAM: least-privilege roles for instances, deployments, patching and humans
# ---------------------------------------------------------------------------

module "iam" {
  source = "./modules/iam"

  name_prefix                  = local.name_prefix
  app_kms_key_arn              = module.data.kms_key_arn
  parameter_store_path         = local.parameter_store_path
  app_log_group_prefix         = local.app_log_group_prefix
  session_logs_bucket_arn      = module.audit.logs_bucket_arn
  session_logs_prefix          = local.session_logs_prefix
  cloudwatch_metrics_namespace = local.metrics_namespace

  tags = local.tags
}

# ---------------------------------------------------------------------------
# Compute: ALB, Auto Scaling group, rollback alarms
# ---------------------------------------------------------------------------

module "compute" {
  source = "./modules/compute"

  name_prefix        = local.name_prefix
  vpc_id             = module.network.vpc_id
  vpc_cidr_block     = module.network.vpc_cidr_block
  public_subnet_ids  = module.network.public_subnet_ids
  private_subnet_ids = module.network.private_subnet_ids

  app_port      = var.app_port
  instance_type = var.instance_type

  kms_key_arn           = module.data.kms_key_arn
  instance_profile_name = module.iam.instance_profile_name

  access_logs_bucket         = module.audit.logs_bucket_name
  certificate_arn            = var.certificate_arn
  enable_deletion_protection = var.alb_deletion_protection

  min_size         = var.asg_min_size
  max_size         = var.asg_max_size
  desired_capacity = var.asg_desired_capacity

  log_group_prefix     = local.app_log_group_prefix
  log_retention_days   = var.log_retention_days
  parameter_store_path = local.parameter_store_path
  metrics_namespace    = local.metrics_namespace
  patch_group          = local.patch_group

  tags = local.tags
}

# ---------------------------------------------------------------------------
# Systems Manager: session access, patching, configuration
# ---------------------------------------------------------------------------

module "ssm" {
  source = "./modules/ssm"

  name_prefix                 = local.name_prefix
  kms_key_arn                 = module.data.kms_key_arn
  kms_key_id                  = module.data.kms_key_id
  session_logs_bucket         = module.audit.logs_bucket_name
  session_logs_prefix         = local.session_logs_prefix
  maintenance_window_role_arn = module.iam.maintenance_window_role_arn
  patch_group                 = local.patch_group
  parameter_store_path        = local.parameter_store_path
  log_retention_days          = var.log_retention_days

  tags = local.tags
}

# ---------------------------------------------------------------------------
# CodeDeploy: the only path from a commit to a running instance
# ---------------------------------------------------------------------------

module "codedeploy" {
  source = "./modules/codedeploy"

  name_prefix              = local.name_prefix
  service_role_arn         = module.iam.codedeploy_role_arn
  instance_role_name       = module.iam.instance_role_name
  autoscaling_group_name   = module.compute.autoscaling_group_name
  target_group_name        = module.compute.target_group_name
  kms_key_arn              = module.data.kms_key_arn
  rollback_alarm_names     = module.compute.deployment_alarm_names
  termination_wait_minutes = var.blue_fleet_termination_wait_minutes
  notification_email       = var.deployment_notification_email

  tags = local.tags
}
