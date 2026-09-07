output "patch_baseline_id" {
  description = "ID of the Patch Manager baseline."
  value       = aws_ssm_patch_baseline.app.id
}

output "maintenance_window_id" {
  description = "ID of the patching maintenance window."
  value       = aws_ssm_maintenance_window.patching.id
}

output "session_preferences_document" {
  description = "Name of the Session Manager preferences document."
  value       = aws_ssm_document.session_preferences.name
}

output "session_log_group_name" {
  description = "CloudWatch log group receiving Session Manager transcripts."
  value       = aws_cloudwatch_log_group.sessions.name
}

output "parameter_names" {
  description = "Parameter Store entries created for the application."
  value = [
    aws_ssm_parameter.app_feature_flags.name,
    aws_ssm_parameter.app_api_token.name,
  ]
}
