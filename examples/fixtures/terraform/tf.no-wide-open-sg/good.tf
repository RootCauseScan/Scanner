resource "aws_security_group" "good" {
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
  }
}
