variable "name_prefix" {
  description = "Prefix applied to all resource names created by this module."
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC."
  type        = string
}

variable "vpc_cidr_block" {
  description = "CIDR block of the VPC, used to scope instance egress."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnets for the internet-facing load balancer."
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnets for the Auto Scaling group."
  type        = list(string)
}

variable "app_port" {
  description = "TCP port the application listens on."
  type        = number
  default     = 8080
}

variable "instance_type" {
  description = "EC2 instance type for application instances."
  type        = string
  default     = "t3.small"
}

variable "root_volume_size" {
  description = "Root EBS volume size in GiB."
  type        = number
  default     = 20
}

variable "kms_key_arn" {
  description = "ARN of the application CMK used to encrypt EBS volumes and log groups."
  type        = string
}

variable "instance_profile_name" {
  description = "Name of the EC2 instance profile (from the iam module)."
  type        = string
}

variable "access_logs_bucket" {
  description = "Bucket name that receives ALB access logs."
  type        = string
}

variable "access_logs_prefix" {
  description = "Key prefix for ALB access logs. Must match the audit bucket policy."
  type        = string
  default     = "alb-access-logs"
}

variable "certificate_arn" {
  description = <<-EOT
    ACM certificate ARN for the HTTPS listener. When set, the load balancer
    terminates TLS 1.2+ and port 80 does nothing but redirect to 443. When
    empty, a plain HTTP listener is created so the stack can be stood up in a
    sandbox without a domain -- which is NOT an acceptable configuration for
    anything carrying ePHI. See the transmission-security note in
    docs/hipaa-safeguards-mapping.md.
  EOT
  type        = string
  default     = ""
}

variable "ssl_policy" {
  description = "ELB security policy for the HTTPS listener. The default permits TLS 1.2 and 1.3 only."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "min_size" {
  description = "Minimum number of application instances."
  type        = number
  default     = 2
}

variable "max_size" {
  description = "Maximum number of application instances."
  type        = number
  default     = 6
}

variable "desired_capacity" {
  description = "Starting number of application instances."
  type        = number
  default     = 2
}

variable "log_group_prefix" {
  description = "CloudWatch Logs namespace for application logs."
  type        = string
}

variable "log_retention_days" {
  description = "Retention for application log groups."
  type        = number
  default     = 365
}

variable "parameter_store_path" {
  description = "Parameter Store path the application reads its configuration from."
  type        = string
}

variable "metrics_namespace" {
  description = "CloudWatch metrics namespace for the application."
  type        = string
  default     = "HIPAADemo/App"
}

variable "operator_session_tag_key" {
  description = "Tag key that marks instances as reachable via Session Manager."
  type        = string
  default     = "SSMSessionAccess"
}

variable "operator_session_tag_value" {
  description = "Tag value that marks instances as reachable via Session Manager."
  type        = string
  default     = "allowed"
}

variable "patch_group" {
  description = "Value of the PatchGroup tag, which binds instances to the Patch Manager baseline."
  type        = string
}

variable "enable_deletion_protection" {
  description = "Prevent accidental deletion of the load balancer."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to every taggable resource in this module."
  type        = map(string)
  default     = {}
}
