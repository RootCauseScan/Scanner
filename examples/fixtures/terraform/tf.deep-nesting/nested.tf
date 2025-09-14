module "network" {
  source = "./network"

  vpc = {
    cidr_block = "10.0.0.0/16"
    subnets = [
      {
        cidr = "10.0.1.0/24"
        az   = "us-west-1a"
        tags = {
          Name = "public"
        }
      },
      {
        cidr = "10.0.2.0/24"
        az   = "us-west-1b"
        tags = {
          Name  = "private"
          Extra = [1, "two", true]
        }
      }
    ]
  }
}
