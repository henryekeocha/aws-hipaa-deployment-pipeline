variable "name_prefix" {
  description = "Prefix applied to all resource names created by this module."
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC the database lives in."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for the DB subnet group. Must span at least two AZs."
  type        = list(string)
}

variable "app_security_group_id" {
  description = "Security group ID of the application tier. The only source permitted to reach the database port."
  type        = string
}

variable "engine_version" {
  description = "PostgreSQL major version."
  type        = string
  default     = "16"
}

variable "instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.medium"
}

variable "allocated_storage" {
  description = "Initial storage in GiB."
  type        = number
  default     = 50
}

variable "max_allocated_storage" {
  description = "Upper bound for storage autoscaling in GiB."
  type        = number
  default     = 200
}

variable "database_name" {
  description = "Name of the initial database."
  type        = string
  default     = "appdb"
}

variable "master_username" {
  description = "Master username. The password is generated and stored by AWS Secrets Manager, never by Terraform."
  type        = string
  default     = "app_admin"
}

variable "backup_retention_days" {
  description = "Automated backup retention in days (maximum 35 for RDS automated backups)."
  type        = number
  default     = 35

  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 35
    error_message = "Backup retention must be between 7 and 35 days."
  }
}

variable "multi_az" {
  description = "Run a synchronous standby in a second AZ."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Block accidental deletion of the instance."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for exported database logs."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every taggable resource in this module."
  type        = map(string)
  default     = {}
}
