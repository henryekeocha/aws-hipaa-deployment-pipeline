output "application_name" {
  description = "Name of the CodeDeploy application."
  value       = aws_codedeploy_app.main.name
}

output "deployment_group_name" {
  description = "Name of the CodeDeploy deployment group."
  value       = aws_codedeploy_deployment_group.main.deployment_group_name
}

output "artifacts_bucket_name" {
  description = "Bucket holding versioned deployment bundles."
  value       = aws_s3_bucket.artifacts.id
}

output "artifacts_bucket_arn" {
  description = "ARN of the deployment artifact bucket."
  value       = aws_s3_bucket.artifacts.arn
}

output "notifications_topic_arn" {
  description = "SNS topic publishing deployment outcomes."
  value       = aws_sns_topic.deployments.arn
}
