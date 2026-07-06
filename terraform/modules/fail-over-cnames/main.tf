
locals {
  primary_region_subdomain   = "${var.subdomain}-${var.aws_region}"
  secondary_region_subdomain = "${var.subdomain}-${var.aws_region_secondary}"

  primary_region_intermediate_domain   = "${local.primary_region_subdomain}.${var.cloudflare_zone_name}"
  secondary_region_intermediate_domain = "${local.secondary_region_subdomain}.${var.cloudflare_zone_name}"

  primary_region_summary   = "${var.aws_region}: ${local.primary_region_intermediate_domain}"
  secondary_region_summary = "${var.aws_region_secondary}: ${local.secondary_region_intermediate_domain}"
}

data "cloudflare_zone" "this" {
  name = var.cloudflare_zone_name
}

// Example: "api.example.com" --> "api-us-east-1.example.com"
resource "cloudflare_record" "public_cname" {
  depends_on = [
    cloudflare_record.primary_region_cname,
    cloudflare_record.secondary_region_cname
  ]

  comment = "Public CNAME record. Change this for easy fail over. ${local.primary_region_summary} / ${local.secondary_region_summary}"
  name    = var.subdomain
  proxied = var.cloudflare_proxy_status
  ttl     = 1 # ttl must be set to 1 when proxied is true
  type    = "CNAME"
  value   = local.primary_region_intermediate_domain # <-- This controls which region to use by default.
  zone_id = data.cloudflare_zone.this.id
}

// Example: "api-us-east-1.example.com" --> "d-abcde12345.execute-api.us-east-1.amazonaws.com"
resource "cloudflare_record" "primary_region_cname" {
  comment = "Intermediate CNAME for ${var.aws_region}. DO NOT manually change this."
  name    = local.primary_region_subdomain
  proxied = var.cloudflare_proxy_status
  ttl     = 1 # ttl must be set to 1 when proxied is true
  type    = "CNAME"
  value   = var.primary_api_gateway_domain
  zone_id = data.cloudflare_zone.this.id
}

// Example: "api-us-west-2.example.com" --> "d-zyxwv67890.execute-api.us-west-2.amazonaws.com"
resource "cloudflare_record" "secondary_region_cname" {
  comment = "Intermediate CNAME for ${var.aws_region_secondary}. DO NOT manually change this."
  name    = local.secondary_region_subdomain
  proxied = var.cloudflare_proxy_status
  ttl     = 1 # ttl must be set to 1 when proxied is true
  type    = "CNAME"
  value   = var.secondary_api_gateway_domain
  zone_id = data.cloudflare_zone.this.id
}
