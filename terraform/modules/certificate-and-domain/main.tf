
locals {
  full_domain_name = "${var.certificate_subdomain}.${var.cloudflare_zone_name}"
}

module "domain" {
  source     = "../api-gateway-custom-domain"
  depends_on = [aws_acm_certificate_validation.this]

  api_name        = var.api_name
  certificate_arn = aws_acm_certificate_validation.this.certificate_arn
  domain_name     = local.full_domain_name
  stage           = var.api_stage
}


data "cloudflare_zone" "this" {
  filter = {
    name = var.cloudflare_zone_name
  }
}

resource "aws_acm_certificate" "this" {
  domain_name       = local.full_domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "cloudflare_dns_record" "validation" {
  count = var.create_dns_validation ? 1 : 0

  name    = tolist(aws_acm_certificate.this.domain_validation_options)[0].resource_record_name
  content = tolist(aws_acm_certificate.this.domain_validation_options)[0].resource_record_value
  type    = tolist(aws_acm_certificate.this.domain_validation_options)[0].resource_record_type
  zone_id = data.cloudflare_zone.this.id
  proxied = false
  ttl     = 1
}

moved {
  from = "cloudflare_record.validation"
  to   = "cloudflare_dns_record.validation"
}

resource "aws_acm_certificate_validation" "this" {
  certificate_arn = aws_acm_certificate.this.arn
}
