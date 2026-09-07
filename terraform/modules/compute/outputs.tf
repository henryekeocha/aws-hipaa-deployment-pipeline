output "alb_arn" {
  description = "ARN of the application load balancer."
  value       = aws_lb.main.arn
}

output "alb_dns_name" {
  description = "Public DNS name of the load balancer."
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "Hosted zone ID of the load balancer, for Route 53 alias records."
  value       = aws_lb.main.zone_id
}

output "alb_security_group_id" {
  description = "Security group attached to the load balancer."
  value       = aws_security_group.alb.id
}

output "app_security_group_id" {
  description = "Security group attached to application instances."
  value       = aws_security_group.app.id
}

output "target_group_name" {
  description = "Name of the target group, referenced by the CodeDeploy deployment group."
  value       = aws_lb_target_group.app.name
}

output "target_group_arn" {
  description = "ARN of the target group."
  value       = aws_lb_target_group.app.arn
}

output "autoscaling_group_name" {
  description = "Name of the Auto Scaling group, referenced by the CodeDeploy deployment group."
  value       = aws_autoscaling_group.app.name
}

output "launch_template_id" {
  description = "ID of the launch template."
  value       = aws_launch_template.app.id
}

output "app_log_group_name" {
  description = "CloudWatch log group receiving application logs."
  value       = aws_cloudwatch_log_group.app.name
}

output "deployment_alarm_names" {
  description = "Alarms that trigger an automatic CodeDeploy rollback."
  value = [
    aws_cloudwatch_metric_alarm.unhealthy_hosts.alarm_name,
    aws_cloudwatch_metric_alarm.http_5xx.alarm_name,
  ]
}
