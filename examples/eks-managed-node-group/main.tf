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

  name               = local.name
  kubernetes_version = local.kubernetes_version

  # STIG V-242430: Enable encryption at rest for Kubernetes secrets
  # Kubernetes etcd must have encryption for communication
  # Compensating control for etcd encryption in managed EKS environment
  create_kms_key = true

  # STIG V-242461: Kubernetes API Server audit logs must be enabled
  # STIG V-242462: The Kubernetes API Server must be set to audit log max size
  # STIG V-242465: The Kubernetes API Server audit log path must be set
  # Enable all control plane logging types to CloudWatch Logs
  # Logs include: api, audit, authenticator, controllerManager, scheduler
  enabled_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

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

      # STIG-compliant kubelet configuration for Linux
      # Ref https://awslabs.github.io/amazon-eks-ami/nodeadm/doc/api/
      cloudinit_pre_nodeadm = [
        {
          content_type = "application/node.eks.aws"
          content      = <<-EOT
            ---
            apiVersion: node.eks.aws/v1alpha1
            kind: NodeConfig
            spec:
              kubelet:
                config:
                  # STIG V-242386: Enable PodSecurity feature gate
                  featureGates:
                    PodSecurity: true
                    # STIG V-242403: Disable DynamicKubeletConfig
                    DynamicKubeletConfig: false
                  
                  # STIG V-242402: Set streaming connection idle timeout to 5 minutes or less
                  streamingConnectionIdleTimeout: 5m
          EOT
        }
      ]

      # STIG V-242393: Worker nodes must not have sshd service running
      # STIG V-242394: Worker nodes must not have sshd service enabled
      post_bootstrap_user_data = <<-EOT
        #!/bin/bash
        systemctl stop sshd
        systemctl disable sshd
      EOT

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

      # STIG-compliant kubelet configuration for Windows
      # Ref https://awslabs.github.io/amazon-eks-ami/nodeadm/doc/api/
      cloudinit_pre_nodeadm = [
        {
          content_type = "application/node.eks.aws"
          content      = <<-EOT
            ---
            apiVersion: node.eks.aws/v1alpha1
            kind: NodeConfig
            spec:
              kubelet:
                config:
                  # STIG V-242386: Enable PodSecurity feature gate
                  featureGates:
                    PodSecurity: true
                    # STIG V-242403: Disable DynamicKubeletConfig
                    DynamicKubeletConfig: false
                  
                  # STIG V-242402: Set streaming connection idle timeout to 5 minutes or less
                  streamingConnectionIdleTimeout: 5m
          EOT
        }
      ]

      # STIG V-242393: Worker nodes must not have sshd service running (RDP on Windows)
      # STIG V-242394: Worker nodes must not have sshd service enabled (RDP on Windows)
      post_bootstrap_user_data = <<-EOT
        <powershell>
        Stop-Service -Name TermService -Force
        Set-Service -Name TermService -StartupType Disabled
        </powershell>
      EOT

      tags = local.tags
    }
  }

  tags = local.tags
}
