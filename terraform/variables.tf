variable "app_name" {
  type        = string
  description = "A short name for this application, example: backup-service"
  default     = "twosv-api"
}

variable "app_env" {
  type        = string
  description = "Environment name, ex: prod, stage, dev"
}

variable "aws_access_key_id" {
  type        = string
  description = "Access Key ID for user with permissions to create resources for CDK"
}

variable "aws_region" {
  description = "Primary AWS region where this lambda will be deployed"
  type        = string
}

variable "aws_region_secondary" {
  description = "Secondary AWS region where this lambda will be deployed"
  type        = string
}

variable "aws_secret_access_key" {
  type        = string
  description = "Secret access Key ID for user with permissions to create resources for CDK"
}

variable "cloudflare_token" {
  description = "The Cloudflare limited access API token"
  type        = string
}

variable "cloudflare_domain" {
  description = "Cloudflare zone (domain) for DNS records"
  type        = string
}

/*
 * AWS tag values
 */

variable "app_customer" {
  description = "customer name to use for the itse_app_customer tag"
  type        = string
  default     = "shared"
}

variable "app_environment" {
  description = "environment name to use for the itse_app_environment tag, e.g. staging, production"
  type        = string
  default     = "production"
}

variable "app_name_tag" {
  description = "app name to use for the itse_app_name tag"
  type        = string
  default     = "idp"
}

/*
 * GitHub OIDC authorization
 */

variable "github_oidc_provider_arn" {
  description = <<-EOT
    ARN of the OIDC provider for GitHub in AWS IAM, used for GitHub Actions to authenticate to AWS. The provider
    can be created in Terraform using the `aws_iam_openid_connect_provider` resource. Specify the URL as
    "https://token.actions.githubusercontent.com" and the client_id_list as ["sts.amazonaws.com"].
  EOT
  type        = string
}

variable "github_repository" {
  description = <<-EOT
    GitHub repository that should be granted access to the OIDC provider for GitHub. Format should be 'owner/repo'.
  EOT
  type        = string
}

/*
 * SES configuration for alerts
 */

variable "ses_domain_identity_arn" {
  description = "ARN of the SES domain identity to use for sending email alerts"
  type        = string
}
variable "alerts_email" {
  description = "Email address to use for sending alerts"
  type        = string
}
