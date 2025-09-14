resource "aws_instance" "bad" {
  ami = "ami-123456"
  instance_type = "t2.micro"
  tags = {
    Name = "bad"
  # missing closing brace for resource block
