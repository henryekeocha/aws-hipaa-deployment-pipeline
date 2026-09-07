variable "name_prefix" {
  description = "Prefix applied to all resource names created by this module."
  type        = string
}

variable "app_kms_key_arn" {
  description = "ARN of the application data CMK (from the data module)."
  type        = string
}

variable "parameter_store_path" {
  description = "Parameter Store path prefix the instance role may read, e.g. /hipaa-demo/app."
  type        = string
}

variable "app_log_group_prefix" {
  description = "CloudWatch Logs name prefix the instance role may write to."
  type        = string
}

variable "session_logs_bucket_arn" {
  description = "ARN of the bucket that receives SSM Session Manager transcripts."
  type        = string
}

variable "session_logs_prefix" {
  description = "Key prefix within the session logs bucket."
  type        = string
  default     = "ssm-session-logs"
}

variable "cloudwatch_metrics_namespace" {
  description = "The only CloudWatch metrics namespace instances may publish into."
  type        = string
  default     = "HIPAADemo/App"
}

variable "operator_session_tag_key" {
  description = "Instance tag key that gates human Session Manager access."
  type        = string
  default     = "SSMSessionAccess"
}

variable "operator_session_tag_value" {
  description = "Instance tag value that gates human Session Manager access."
  type        = string
  default     = "allowed"
}

variable "tags" {
  description = "Tags applied to every taggable resource in this module."
  type        = map(string)
  default     = {}
}
