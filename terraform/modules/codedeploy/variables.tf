variable "name_prefix" {
  description = "Prefix applied to all resource names created by this module."
  type        = string
}

variable "service_role_arn" {
  description = "ARN of the CodeDeploy service role (from the iam module)."
  type        = string
}

variable "instance_role_name" {
  description = <<-EOT
    Name of the EC2 instance role. This module attaches a read-only policy for
    its own artifact bucket to that role, rather than making the iam module
    aware of a bucket it does not own -- each module grants access to the
    resources it creates, which keeps the permission grant next to the thing
    being protected.
  EOT
  type        = string
}

variable "autoscaling_group_name" {
  description = "Auto Scaling group the deployment group targets."
  type        = string
}

variable "target_group_name" {
  description = "ALB target group CodeDeploy shifts traffic through."
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the application CMK used to encrypt deployment artifacts."
  type        = string
}

variable "rollback_alarm_names" {
  description = "CloudWatch alarms that stop and roll back an in-flight deployment."
  type        = list(string)
  default     = []
}

variable "termination_wait_minutes" {
  description = <<-EOT
    How long the original (blue) fleet is kept running after traffic has
    shifted. This is the rollback window: while these instances exist, reverting
    is a traffic shift rather than a redeploy.
  EOT
  type        = number
  default     = 15
}

variable "artifact_retention_days" {
  description = "How long deployment bundles are retained in the artifact bucket."
  type        = number
  default     = 180
}

variable "notification_email" {
  description = "Optional email address subscribed to deployment notifications. Leave empty to skip."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to every taggable resource in this module."
  type        = map(string)
  default     = {}
}
