locals {
  stage_for_api = var.app_env == "dev" ? var.app_env : var.app_environment
  api_name      = "${var.app_name}-${local.stage_for_api}"
  aws_account   = data.aws_caller_identity.this.account_id
}

data "aws_caller_identity" "this" {}

# CDK IAM user
resource "aws_iam_user" "cdk" {
  name = "${var.app_name}-${var.app_env}-cdk"
}

resource "aws_iam_access_key" "cdk" {
  user = aws_iam_user.cdk.name
}

resource "aws_iam_policy" "cdk" {
  name        = "${var.app_name}-${var.app_env}-cdk"
  description = "CDK deployment policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = "arn:aws:iam::*:role/cdk-*"
    }]
  })
}

resource "aws_iam_user_policy_attachment" "cdk" {
  user       = aws_iam_user.cdk.name
  policy_arn = aws_iam_policy.cdk.arn
}

// Set up custom domain name for easier fail-over.
module "dns_for_failover" {
  source  = "silinternational/serverless-api-dns-for-failover/aws"
  version = "~> 0.6.0"

  api_name             = local.api_name
  cloudflare_zone_name = var.cloudflare_domain
  serverless_stage     = local.stage_for_api
  subdomain            = var.app_name

  providers = {
    aws           = aws
    aws.secondary = aws.secondary
  }
}

// Create role for lambda function
resource "aws_iam_role" "lambdaRole" {
  name = "${var.app_name}-${var.app_env}-lambdaRole"

  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "lambda.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}

data "template_file" "lambdaRolePolicy" {
  template = file("${path.module}/lambda-role-policy.json")
  vars = {
    aws_account = local.aws_account
    app_name    = var.app_name
    app_env     = var.app_env
    table_arns = join(",", compact([
      "\"arn:aws:dynamodb:*:${local.aws_account}:table/${aws_dynamodb_table.api_key.name}\"",
      "\"arn:aws:dynamodb:*:${local.aws_account}:table/${aws_dynamodb_table.webauthn.name}\"",
      "\"arn:aws:dynamodb:*:${local.aws_account}:table/${aws_dynamodb_table.totp.name}\"",
    ]))
  }
}

resource "aws_iam_role_policy" "lambdaRolePolicy" {
  name   = "${var.app_name}-${var.app_env}-lambdaRolePolicy"
  role   = aws_iam_role.lambdaRole.id
  policy = data.template_file.lambdaRolePolicy.rendered
}

// DynamoDB tables
resource "aws_dynamodb_table" "api_key" {
  name                        = "mfa-api_${var.app_env}_api-key_global"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "value"
  deletion_protection_enabled = true
  stream_enabled              = true
  stream_view_type            = "NEW_IMAGE"

  attribute {
    name = "value"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  replica {
    region_name = var.aws_region_secondary
  }

  lifecycle {
    ignore_changes = [replica]
  }
}

resource "aws_dynamodb_table" "totp" {
  name                        = "mfa-api_${var.app_env}_totp_global"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "uuid"
  deletion_protection_enabled = true
  stream_enabled              = true
  stream_view_type            = "NEW_IMAGE"

  attribute {
    name = "uuid"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  replica {
    region_name = var.aws_region_secondary
  }

  lifecycle {
    ignore_changes = [replica]
  }
}

variable "webauthn_stream_view_type" {
  description = "TEMPORARY: added to resolve an anomaly in the mfa-api_dev_u2f_global table"
  type        = string
  default     = "NEW_IMAGE"
}

resource "aws_dynamodb_table" "webauthn" {
  name                        = "mfa-api_${var.app_env}_u2f_global"
  hash_key                    = "uuid"
  billing_mode                = "PAY_PER_REQUEST"
  deletion_protection_enabled = true
  stream_enabled              = true
  stream_view_type            = var.webauthn_stream_view_type

  attribute {
    name = "uuid"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  replica {
    region_name = var.aws_region_secondary
  }

  lifecycle {
    ignore_changes = [replica]
  }
}
