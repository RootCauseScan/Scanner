resource "aws_s3_bucket" "b" {
  bucket = "mybucket"
  acl    = "private"
  tags = {
    Environment = "Dev"
    Team = "DevOps"
  }
  versioning {
    enabled = true
  }
  lifecycle_rule {
    id      = "log"
    enabled = true
    transition {
      days          = 30
      storage_class = "GLACIER"
    }
  }
  cors_rule {
    allowed_methods = ["GET", "PUT"]
  }
}
