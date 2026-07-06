
terraform {
  required_version = ">= 1.0"

  required_providers {
    cloudflare = {
      source = "cloudflare/cloudflare"

      // 4.39.0 and later versions deprecated cloudflare_record.value
      // constraining to earlier versions while waiting for version 5 to mature
      version = ">= 2.0.0, < 4.39.0"
    }
  }
}
