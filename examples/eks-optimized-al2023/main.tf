provider "aws" {
  region = local.region
}

locals {
  name               = "ex-${basename(path.cwd)}"
  kubernetes_version = "1.33"
  region             = "us-east-1"
  instance_type      = "t3.medium"

  tags = {
    Test       = local.name
    GithubRepo = "terraform-aws-eks"
    GithubOrg  = "terraform-aws-modules"
  }
}

################################################################################
# Data Sources
################################################################################

# Get the latest EKS optimized AL2023 AMI
data "aws_ami" "eks_al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amazon-eks-node-al2023-x86_64-standard-${local.kubernetes_version}-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Get default VPC
data "aws_vpc" "default" {
  default = true
}

# Get default subnets
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Get availability zones that support the instance type
data "aws_ec2_instance_type_offerings" "available" {
  filter {
    name   = "instance-type"
    values = [local.instance_type]
  }

  location_type = "availability-zone"
}

# Get subnet info to match with available AZs
data "aws_subnet" "default" {
  for_each = toset(data.aws_subnets.default.ids)
  id       = each.value
}

# Find a subnet in an AZ that supports the instance type
locals {
  available_azs = toset(data.aws_ec2_instance_type_offerings.available.locations)
  
  # Find the first subnet that's in an AZ supporting our instance type
  available_subnet = [
    for subnet_id, subnet in data.aws_subnet.default :
    subnet_id if contains(local.available_azs, subnet.availability_zone)
  ][0]
}

################################################################################
# IAM Role for EC2 Instance
################################################################################

resource "aws_iam_role" "ec2_ssm_role" {
  name = "${local.name}-ec2-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = local.tags
}

# Attach SSM managed policy for Session Manager
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Create instance profile
resource "aws_iam_instance_profile" "ec2_ssm_profile" {
  name = "${local.name}-ec2-ssm-profile"
  role = aws_iam_role.ec2_ssm_role.name

  tags = local.tags
}

################################################################################
# Security Group
################################################################################

resource "aws_security_group" "instance" {
  name        = "${local.name}-instance-sg"
  description = "Security group for EKS AL2023 test instance"
  vpc_id      = data.aws_vpc.default.id

  # Allow outbound traffic for SSM, updates, etc.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    local.tags,
    {
      Name = "${local.name}-instance-sg"
    }
  )
}

################################################################################
# EC2 Instance
################################################################################

resource "aws_instance" "eks_al2023" {
  ami                    = data.aws_ami.eks_al2023.id
  instance_type          = local.instance_type
  iam_instance_profile   = aws_iam_instance_profile.ec2_ssm_profile.name
  vpc_security_group_ids = [aws_security_group.instance.id]
  subnet_id              = local.available_subnet

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    delete_on_termination = true
    encrypted             = true
  }

  tags = merge(
    local.tags,
    {
      Name = "${local.name}-eks-al2023-node"
    }
  )
}

################################################################################
# Outputs
################################################################################

output "instance_id" {
  description = "The ID of the EC2 instance"
  value       = aws_instance.eks_al2023.id
}

output "instance_name" {
  description = "The name tag of the EC2 instance"
  value       = aws_instance.eks_al2023.tags["Name"]
}

output "ami_id" {
  description = "The AMI ID used for the instance"
  value       = data.aws_ami.eks_al2023.id
}

output "ami_name" {
  description = "The AMI name used for the instance"
  value       = data.aws_ami.eks_al2023.name
}

output "ssm_connect_command" {
  description = "Command to connect to the instance via SSM Session Manager"
  value       = "aws ssm start-session --target ${aws_instance.eks_al2023.id} --region ${local.region}"
}

output "availability_zone" {
  description = "The availability zone where the instance is deployed"
  value       = data.aws_subnet.default[local.available_subnet].availability_zone
}

output "subnet_id" {
  description = "The subnet ID where the instance is deployed"
  value       = local.available_subnet
}
