resource "aws_security_group" "bad" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
