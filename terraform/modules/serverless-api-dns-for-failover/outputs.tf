
output "primary_region_domain_name" {
  value = module.fail_over_cnames.primary_region_intermediate_domain
}

output "primary_region_summary" {
  value = module.fail_over_cnames.primary_region_summary
}

output "secondary_region_domain_name" {
  value = module.fail_over_cnames.secondary_region_intermediate_domain
}

output "secondary_region_summary" {
  value = module.fail_over_cnames.secondary_region_summary
}
