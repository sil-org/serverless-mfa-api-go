
variable "aws_region" {
  description = "The primary AWS region (e.g. us-east-2)"
  type        = string
}

variable "aws_region_secondary" {
  description = "The secondary AWS region (e.g. us-west-2)"
  type        = string
}

variable "cloudflare_proxy_status" {
  description = "Set the Cloudflare CNAME proxy status"
  type        = bool
  default     = true
}

variable "cloudflare_zone_name" {
  description = "The Cloudflare zone (aka domain) name"
  type        = string
}

variable "primary_api_gateway_domain" {
  description = "The API Gateway primary region's endpoint domain name"
  type        = string
}

variable "secondary_api_gateway_domain" {
  description = "The API Gateway secondary region's endpoint domain name"
  type        = string
}

variable "subdomain" {
  description = "The subdomain for the public CNAME record."
  type        = string
}
