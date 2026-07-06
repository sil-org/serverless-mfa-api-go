
locals {
  aws_region           = data.aws_region.primary.region
  aws_region_secondary = data.aws_region.secondary.region
}

data "aws_region" "primary" {}

data "aws_region" "secondary" {
  provider = aws.secondary
}

module "api_gateway_domains_and_certs" {
  source = "../api-gateway-domains-and-certs"

  api_name              = var.api_name
  api_stage             = var.serverless_stage
  certificate_subdomain = var.subdomain
  cloudflare_zone_name  = var.cloudflare_zone_name

  providers = {
    aws           = aws
    aws.secondary = aws.secondary
  }
}

module "fail_over_cnames" {
  source = "../fail-over-cnames"

  aws_region                   = local.aws_region
  aws_region_secondary         = local.aws_region_secondary
  cloudflare_proxy_status      = var.cloudflare_proxy_status
  cloudflare_zone_name         = var.cloudflare_zone_name
  primary_api_gateway_domain   = module.api_gateway_domains_and_certs.primary_api_gateway_domain
  secondary_api_gateway_domain = module.api_gateway_domains_and_certs.secondary_api_gateway_domain
  subdomain                    = var.subdomain
}
