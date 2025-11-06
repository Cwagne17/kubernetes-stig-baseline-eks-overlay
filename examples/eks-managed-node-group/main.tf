provider "aws" {
  region = local.region
}

locals {
  name               = "ex-${basename(path.cwd)}"
  kubernetes_version = "1.33"
  region             = "us-east-1"

  tags = {
    Test       = local.name
    GithubRepo = "kubernetes-stig-baseline-eks-overlay"
  }
}

################################################################################
# Data Sources
################################################################################

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "availability-zone"
    values = ["${local.region}a", "${local.region}b", "${local.region}c"]
  }
}

################################################################################
# EKS Module
################################################################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.0"

  name    = local.name
  kubernetes_version = local.kubernetes_version

  create_kms_key = var.enable_encryption
  # There is a bug in the module where the default is {} but toggle is checking for null
  encryption_config = !var.enable_encryption ? null : {}

  # EKS Addons
  addons = {
    coredns = {}
    eks-pod-identity-agent = {
      before_compute = true
    }
    kube-proxy = {}
    vpc-cni = {
      before_compute = true
    }
  }

  vpc_id     = data.aws_vpc.default.id
  subnet_ids = data.aws_subnets.default.ids

  # Enable both public and private endpoint access
  endpoint_public_access  = true
  endpoint_private_access = true

  enable_cluster_creator_admin_permissions = true

  eks_managed_node_groups = {
    al2023_worker_node = {
      # Starting on 1.30, AL2023 is the default AMI type for EKS managed node groups
      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = ["t3.medium"]

      min_size     = 1
      max_size     = 1
      desired_size = 1

      # Enable SSM Session Manager access
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }

      tags = local.tags
    },
    windows_worker_node = {
      ami_type       = "WINDOWS_CORE_2022_x86_64"
      instance_types = ["t3.medium"]

      min_size     = 1
      max_size     = 1
      desired_size = 1

      # Enable SSM Session Manager access
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }

      tags = local.tags
    }
  }

  tags = local.tags
}
