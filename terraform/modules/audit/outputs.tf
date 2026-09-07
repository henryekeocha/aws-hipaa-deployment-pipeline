output "audit_kms_key_arn" {
  description = "ARN of the customer-managed KMS key protecting audit data."
  value       = aws_kms_key.audit.arn
}

output "cloudtrail_bucket_name" {
  description = "Name of the CloudTrail archive bucket."
  value       = aws_s3_bucket.trail.id
}

output "cloudtrail_bucket_arn" {
  description = "ARN of the CloudTrail archive bucket."
  value       = aws_s3_bucket.trail.arn
}

output "logs_bucket_name" {
  description = "Name of the shared log-delivery bucket (ALB, VPC flow, S3 access, SSM sessions)."
  value       = aws_s3_bucket.logs.id
}

output "logs_bucket_arn" {
  description = "ARN of the shared log-delivery bucket."
  value       = aws_s3_bucket.logs.arn
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail."
  value       = aws_cloudtrail.main.arn
}

output "config_recorder_name" {
  description = "Name of the AWS Config configuration recorder."
  value       = aws_config_configuration_recorder.main.name
}
