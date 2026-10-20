# Pilot: one Lambda function whose CloudWatch log group has no retention, so its logs
# are kept forever. That is the single gap this pilot exercises: as an IaC Finding
# before apply, and as an IOM in the Falcon console after it. Everything else is the
# minimum a function needs. Apply only in the sandbox account; TF_VAR_region selects
# the AWS region (us-gov-west-1 in GovCloud). The fix is one line, marked below.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
  # GitLab-managed Terraform state; the pipeline passes the address and the job token.
  # Locally: terraform init -backend=false
  backend "http" {}
}

variable "region" {
  type        = string
  description = "AWS region of the sandbox account, for example us-gov-west-1."
}

provider "aws" {
  region = var.region
}

data "aws_partition" "current" {}

locals {
  function_name = "fcs-gate-pilot"
}

# Tags are literal on each resource: the scanner reads attributes as written and does
# not follow a local or variable, so `tags = local.tags` still raises "Resource Not
# Using Tags" (observed on the first live scans).

data "archive_file" "handler" {
  type        = "zip"
  output_path = "${path.module}/handler.zip"
  source {
    filename = "handler.py"
    content  = "def handler(event, context):\n    return {\"ok\": True}\n"
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "pilot" {
  name_prefix        = "fcs-gate-pilot-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags = {
    Project = "fcs-deploy-gate-pilot"
    Owner   = "security"
  }
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.pilot.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# The function's log group, declared so that Terraform owns it rather than Lambda
# creating it on first invoke. Without retention_in_days the group keeps logs forever:
# that is the pilot's Finding, "CloudWatch Without Retention Period Specified",
# informational. The fix: add  retention_in_days = 30  to this block. The scanner also
# raises "CloudWatch Log Group Without KMS" (medium) here; that one is excluded in the
# demo, since a customer-managed key is outside what this pilot is about.
resource "aws_cloudwatch_log_group" "pilot" {
  name = "/aws/lambda/${local.function_name}"
  tags = {
    Project = "fcs-deploy-gate-pilot"
    Owner   = "security"
  }
}

resource "aws_lambda_function" "pilot" {
  function_name    = local.function_name
  role             = aws_iam_role.pilot.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  tags = {
    Project = "fcs-deploy-gate-pilot"
    Owner   = "security"
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.pilot, aws_iam_role_policy_attachment.logs]
}
