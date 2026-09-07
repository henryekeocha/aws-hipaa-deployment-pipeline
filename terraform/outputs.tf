# ---------------------------------------------------------------------------
# Outputs are limited to what an operator needs to use or verify the stack.
# Nothing sensitive is exposed: no credentials, no secret values, no key
# material. The RDS master password lives only in Secrets Manager, and the
# SecureString parameter's value is never read into state.
# ---------------------------------------------------------------------------

output "application_url" {
  description = "Public entry point for the application."
  value       = var.certificate_arn != "" ? "https://${module.compute.alb_dns_name}" : "http://${module.compute.alb_dns_name}"
}

output "alb_dns_name" {
  description = "DNS name of the load balancer. Point a Route 53 alias record here."
  value       = module.compute.alb_dns_name
}

output "vpc_id" {
  description = "ID of the VPC."
  value       = module.network.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnets hosting the application and data tiers."
  value       = module.network.private_subnet_ids
}

output "autoscaling_group_name" {
  description = "Auto Scaling group backing the application."
  value       = module.compute.autoscaling_group_name
}

output "codedeploy_application_name" {
  description = "CodeDeploy application to deploy revisions into."
  value       = module.codedeploy.application_name
}

output "codedeploy_deployment_group_name" {
  description = "CodeDeploy deployment group to deploy revisions into."
  value       = module.codedeploy.deployment_group_name
}

output "deployment_artifacts_bucket" {
  description = "Bucket to upload deployment bundles to."
  value       = module.codedeploy.artifacts_bucket_name
}

output "database_endpoint" {
  description = "Database endpoint. Resolvable only from inside the VPC."
  value       = module.data.db_instance_endpoint
}

output "database_master_secret_arn" {
  description = "Secrets Manager secret holding the RDS-managed master credentials."
  value       = module.data.master_user_secret_arn
}

output "application_kms_key_arn" {
  description = "Customer-managed key protecting application data at rest."
  value       = module.data.kms_key_arn
}

output "audit_kms_key_arn" {
  description = "Customer-managed key protecting audit data at rest."
  value       = module.audit.audit_kms_key_arn
}

output "cloudtrail_bucket" {
  description = "Bucket holding the CloudTrail archive."
  value       = module.audit.cloudtrail_bucket_name
}

output "audit_logs_bucket" {
  description = "Bucket holding ALB access logs, VPC flow logs, S3 access logs and SSM session transcripts."
  value       = module.audit.logs_bucket_name
}

output "operator_role_arn" {
  description = "Assume this role (with MFA) to open a Session Manager shell. There is no SSH alternative."
  value       = module.iam.operator_role_arn
}

output "session_manager_command" {
  description = "Example command for opening a recorded shell on an instance."
  value       = "aws ssm start-session --target <instance-id> --region ${var.aws_region}"
}

output "parameter_store_path" {
  description = "Path the application reads its configuration from."
  value       = local.parameter_store_path
}
