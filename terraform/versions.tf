
terraform {
  # Terraform 1.8 is required for cross-resource moving of resources, which is used in this module to move the
  # Cloudflare DNS records from the old resource name (cloudflare_record) to the new resource name
  # (cloudflare_dns_record).
  required_version = ">= 1.8"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }

    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}
