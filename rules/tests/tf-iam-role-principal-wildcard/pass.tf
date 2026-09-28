assume_role_policy = jsonencode({
  Principal = { Service = "ec2.amazonaws.com" }
})
