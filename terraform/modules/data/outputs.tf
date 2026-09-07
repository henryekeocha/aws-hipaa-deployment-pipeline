output "kms_key_arn" {
  description = "ARN of the customer-managed KMS key protecting application data at rest."
  value       = aws_kms_key.app.arn
}

output "kms_key_id" {
  description = "Key ID of the application data CMK."
  value       = aws_kms_key.app.key_id
}

output "kms_key_alias" {
  description = "Alias of the application data CMK."
  value       = aws_kms_alias.app.name
}

output "db_instance_arn" {
  description = "ARN of the database instance."
  value       = aws_db_instance.main.arn
}

output "db_instance_address" {
  description = "Hostname of the database endpoint (resolvable only inside the VPC)."
  value       = aws_db_instance.main.address
}

output "db_instance_endpoint" {
  description = "host:port of the database endpoint."
  value       = aws_db_instance.main.endpoint
}

output "db_port" {
  description = "Port the database listens on."
  value       = local.db_port
}

output "db_security_group_id" {
  description = "Security group protecting the database."
  value       = aws_security_group.db.id
}

output "master_user_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the RDS-managed master credentials."
  value       = try(aws_db_instance.main.master_user_secret[0].secret_arn, null)
}

output "database_name" {
  description = "Name of the initial database."
  value       = aws_db_instance.main.db_name
}
