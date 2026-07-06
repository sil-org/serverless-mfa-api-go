
variable "api_name" {
  description = "Short name of the API (as shown in AWS API Gateway). It probably consists of your Serverless service name and stage (e.g. either 'my-api-dev' or 'dev-my-api')."
  type        = string
}

variable "cloudflare_proxy_status" {
  description = "Set the Cloudflare CNAME proxy status"
  type        = bool
  default     = true
}

variable "cloudflare_zone_name" {
  description = "Cloudflare zone (aka domain) name"
  type        = string
}

variable "serverless_stage" {
  description = "Short name for the stage (aka environment): 'dev' or 'prod'"
  type        = string
}

variable "subdomain" {
  description = "The subdomain for the public CNAME record (e.g. 'my-api')"
  type        = string
}
