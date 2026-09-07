output "instance_role_name" {
  description = "Name of the EC2 instance role."
  value       = aws_iam_role.instance.name
}

output "instance_role_arn" {
  description = "ARN of the EC2 instance role."
  value       = aws_iam_role.instance.arn
}

output "instance_profile_name" {
  description = "Name of the EC2 instance profile."
  value       = aws_iam_instance_profile.instance.name
}

output "instance_profile_arn" {
  description = "ARN of the EC2 instance profile."
  value       = aws_iam_instance_profile.instance.arn
}

output "codedeploy_role_arn" {
  description = "ARN of the CodeDeploy service role."
  value       = aws_iam_role.codedeploy.arn
}

output "maintenance_window_role_arn" {
  description = "ARN of the Systems Manager maintenance window role."
  value       = aws_iam_role.maintenance_window.arn
}

output "operator_role_arn" {
  description = "ARN of the MFA-gated human operator role."
  value       = aws_iam_role.operator.arn
}
