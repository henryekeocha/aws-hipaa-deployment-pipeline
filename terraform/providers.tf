terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # ---------------------------------------------------------------------------
  # REMOTE STATE
  #
  # Left commented out so that `terraform init -backend=false` works in CI and
  # on a fresh clone without touching an AWS account. Configure it before any
  # real use: Terraform state for this stack contains resource identifiers,
  # security group rules and endpoint addresses, and state files are a common
  # place for sensitive material to leak out of an otherwise encrypted estate.
  #
  # This stack deliberately keeps ePHI and credentials out of state -- the RDS
  # master password is managed by Secrets Manager and the SecureString
  # parameter's value is ignored by lifecycle rules -- but the bucket should
  # still be encrypted, versioned and locked down like any other audit artifact.
  #
  # backend "s3" {
  #   bucket       = "my-terraform-state-bucket"
  #   key          = "hipaa-demo/terraform.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   kms_key_id   = "arn:aws:kms:us-east-1:123456789012:key/..."
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.aws_region

  # Applied to every resource that supports tagging. Cost allocation and
  # incident scoping both start with being able to answer "what belongs to this
  # system?" from tags alone.
  default_tags {
    tags = {
      Project         = var.project_name
      Environment     = var.environment
      ManagedBy       = "terraform"
      Compliance      = "hipaa-aligned"
      DataSensitivity = "ephi"
    }
  }
}
