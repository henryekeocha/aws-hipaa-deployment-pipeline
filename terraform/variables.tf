variable "aws_region" {
  description = "AWS region to deploy into. Confirm the region is in scope of your AWS Business Associate Addendum before using it for ePHI."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short project identifier used as a name prefix. Lowercase letters, digits and hyphens."
  type        = string
  default     = "hipaa-demo"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,20}$", var.project_name))
    error_message = "project_name must be 2-21 characters of lowercase letters, digits or hyphens, and start with a letter or digit."
  }
}

variable "environment" {
  description = "Environment name, e.g. dev, staging, prod."
  type        = string
  default     = "prod"
}

# --- Network ---------------------------------------------------------------

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "availability_zone_count" {
  description = "Number of availability zones to span. Minimum two."
  type        = number
  default     = 2
}

variable "single_nat_gateway" {
  description = "Use one shared NAT gateway (cheaper) instead of one per AZ (resilient). Set to false for production."
  type        = bool
  default     = true
}

# --- Data ------------------------------------------------------------------

variable "db_engine_version" {
  description = "PostgreSQL major version."
  type        = string
  default     = "16"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.medium"
}

variable "db_allocated_storage" {
  description = "Initial database storage in GiB."
  type        = number
  default     = 50
}

variable "db_backup_retention_days" {
  description = "Automated backup retention in days (7-35)."
  type        = number
  default     = 35
}

variable "db_multi_az" {
  description = "Run a synchronous standby in a second availability zone."
  type        = bool
  default     = true
}

variable "db_deletion_protection" {
  description = "Block accidental deletion of the database instance."
  type        = bool
  default     = true
}

# --- Compute ---------------------------------------------------------------

variable "app_port" {
  description = "TCP port the sample application listens on."
  type        = number
  default     = 8080
}

variable "instance_type" {
  description = "EC2 instance type for application instances."
  type        = string
  default     = "t3.small"
}

variable "asg_min_size" {
  description = "Minimum number of application instances."
  type        = number
  default     = 2
}

variable "asg_max_size" {
  description = "Maximum number of application instances."
  type        = number
  default     = 6
}

variable "asg_desired_capacity" {
  description = "Starting number of application instances."
  type        = number
  default     = 2
}

variable "certificate_arn" {
  description = <<-EOT
    ACM certificate ARN for the ALB's HTTPS listener. Required for any
    environment handling ePHI: without it the listener is plain HTTP and
    transmission security (45 CFR 164.312(e)) is not satisfied.
  EOT
  type        = string
  default     = ""
}

variable "alb_deletion_protection" {
  description = "Prevent accidental deletion of the load balancer."
  type        = bool
  default     = true
}

# --- Observability and retention -------------------------------------------

variable "log_retention_days" {
  description = "CloudWatch Logs retention for application, session and patching logs."
  type        = number
  default     = 365
}

variable "audit_log_retention_days" {
  description = "S3 retention for CloudTrail records. Defaults to seven years, above the six-year HIPAA documentation floor."
  type        = number
  default     = 2557
}

# --- Deployment ------------------------------------------------------------

variable "deployment_notification_email" {
  description = "Optional address subscribed to deployment success/failure notifications."
  type        = string
  default     = ""
}

variable "blue_fleet_termination_wait_minutes" {
  description = "Minutes the previous fleet is kept alive after a blue/green cutover, as a fast rollback path."
  type        = number
  default     = 15
}
