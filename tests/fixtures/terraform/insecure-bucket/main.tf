# A deliberately insecure bucket for the Gate's first live run and the IOM mapping
# measurement: public, unencrypted, unlogged, untagged. It carries no credentials of any
# kind. Scan it freely; apply it only in the sandbox account, with `-var region=...`, and
# destroy it afterwards (`force_destroy` lets `terraform destroy` empty it first).
#
# What the scan should report, by what each block opens or omits: public access (the
# access block turned off, the public-read ACL, the bucket policy granting s3:GetObject
# to everyone), no server-side encryption configuration, no access logging, no
# versioning, and a bucket without a single tag. One caveat for the mapping measurement:
# AWS encrypts every new bucket with SSE-S3 by default, so the applied bucket is encrypted
# at rest; expect the IaC Finding for the missing encryption configuration, but perhaps
# no IOM for it.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  description = "AWS region of the sandbox account; only an apply needs it, the scan does not."
  type        = string
}

provider "aws" {
  region = var.region
}

resource "aws_s3_bucket" "insecure" {
  bucket_prefix = "fcs-deploy-gate-fixture-"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "insecure" {
  bucket = aws_s3_bucket.insecure.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "insecure" {
  bucket                  = aws_s3_bucket.insecure.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "insecure" {
  depends_on = [
    aws_s3_bucket_ownership_controls.insecure,
    aws_s3_bucket_public_access_block.insecure,
  ]
  bucket = aws_s3_bucket.insecure.id
  acl    = "public-read"
}

resource "aws_s3_bucket_policy" "insecure" {
  depends_on = [aws_s3_bucket_public_access_block.insecure]
  bucket     = aws_s3_bucket.insecure.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.insecure.arn}/*"
    }]
  })
}
