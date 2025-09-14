resource "aws_s3_bucket" "b" {
  bucket = "mybucket"
  acl    = "private"
}
