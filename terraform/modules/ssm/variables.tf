variable "name_prefix" {
  description = "Prefix applied to all resource names created by this module."
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the application CMK used for SecureString parameters and session logs."
  type        = string
}

variable "kms_key_id" {
  description = "Key ID of the application CMK (Session Manager preferences want the key ID)."
  type        = string
}

variable "session_logs_bucket" {
  description = "Bucket name that receives Session Manager transcripts."
  type        = string
}

variable "session_logs_prefix" {
  description = "Key prefix for session transcripts. Must match the instance role policy."
  type        = string
  default     = "ssm-session-logs"
}

variable "maintenance_window_role_arn" {
  description = "ARN of the role Patch Manager tasks run as (from the iam module)."
  type        = string
}

variable "patch_group" {
  description = "Value of the PatchGroup tag that binds instances to the patch baseline."
  type        = string
}

variable "parameter_store_path" {
  description = "Path prefix under which application configuration parameters live."
  type        = string
}

variable "log_retention_days" {
  description = "Retention for session and patching log groups."
  type        = number
  default     = 365
}

variable "patch_approval_delay_days" {
  description = "Days a patch is held after release before automatic approval."
  type        = number
  default     = 7
}

variable "maintenance_window_schedule" {
  description = "Cron expression for the patching maintenance window."
  type        = string
  default     = "cron(0 3 ? * SUN *)"
}

variable "maintenance_window_timezone" {
  description = "IANA timezone the maintenance window schedule is evaluated in."
  type        = string
  default     = "Etc/UTC"
}

variable "idle_session_timeout_minutes" {
  description = "Minutes of inactivity after which Session Manager terminates a session."
  type        = string
  default     = "15"
}

variable "tags" {
  description = "Tags applied to every taggable resource in this module."
  type        = map(string)
  default     = {}
}
