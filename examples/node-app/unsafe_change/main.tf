# DELIBERATELY UNSAFE FIXTURE
# This Terraform makes an S3 bucket world-readable. The gatekeeper's
# iac.public_s3 policy should flag it and block the merge.
resource "aws_s3_bucket" "public_assets" {
  bucket = "gatekeeper-demo-public-assets"
}

resource "aws_s3_bucket_acl" "public_assets" {
  bucket = aws_s3_bucket.public_assets.id
  acl    = "public-read"
}
