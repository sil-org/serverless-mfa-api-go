
output "primary_api_gateway_domain" {
  value = module.primary_region.regional_domain_name
}

output "secondary_api_gateway_domain" {
  value = module.secondary_region.regional_domain_name
}
