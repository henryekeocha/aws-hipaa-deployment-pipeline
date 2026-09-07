variable "name_prefix" {
  description = "Prefix applied to all resource names created by this module."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "availability_zone_count" {
  description = "Number of AZs to spread subnets across. Two is the minimum for RDS Multi-AZ and for an ALB."
  type        = number
  default     = 2

  validation {
    condition     = var.availability_zone_count >= 2
    error_message = "At least two availability zones are required for a highly available deployment."
  }
}

variable "single_nat_gateway" {
  description = <<-EOT
    When true, all private subnets egress through one NAT gateway (cheaper, but
    the NAT is a single point of failure). Set to false for production, where
    each AZ gets its own NAT gateway so an AZ outage cannot take down egress
    for the surviving AZ.
  EOT
  type        = bool
  default     = true
}

variable "flow_logs_bucket_arn" {
  description = "ARN of the S3 bucket that receives VPC flow logs (provided by the audit module)."
  type        = string
}

variable "tags" {
  description = "Tags applied to every taggable resource in this module."
  type        = map(string)
  default     = {}
}
