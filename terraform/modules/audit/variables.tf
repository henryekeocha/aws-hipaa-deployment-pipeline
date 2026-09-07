variable "name_prefix" {
  description = "Prefix applied to all resource names created by this module."
  type        = string
}

variable "tags" {
  description = "Tags applied to every taggable resource in this module."
  type        = map(string)
  default     = {}
}

variable "audit_log_retention_days" {
  description = <<-EOT
    Retention for CloudTrail objects, in days. HIPAA 45 CFR 164.316(b)(2)(i)
    requires documentation (which auditors generally read to include the
    security records that evidence it) be retained for six years. 2557 days
    ~= 7 years, giving a margin over the six-year floor.
  EOT
  type        = number
  default     = 2557
}

variable "object_lock_retention_days" {
  description = "WORM retention applied to new CloudTrail objects via S3 Object Lock (GOVERNANCE mode)."
  type        = number
  default     = 2557
}
