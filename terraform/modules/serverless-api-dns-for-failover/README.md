# Terraform module for adding DNS-based fail-over capability to a Serverless API

This module sets up custom domain names (with corresponding AWS ACM
certificates) and a CNAME record (in Cloudflare) for a Serverless Framework
based API running in AWS Lambda behind API Gateway.

It uses Cloudflare for all DNS records, and it uses regional API Gateway
endpoints, with a DNS (CNAME) record that can be easily switched to point at
either AWS region's instance of your Serverless API.

This assumes that your API is running in two AWS regions.
