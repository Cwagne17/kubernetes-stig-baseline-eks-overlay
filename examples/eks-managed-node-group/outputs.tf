
output "cluster_name" {
  description = "The name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "configure_kubectl" {
  description = "Configure kubectl: run the following command to update your kubeconfig"
  value       = "aws eks update-kubeconfig --region ${local.region} --name ${module.eks.cluster_name}"
}

output "node_group_id" {
  description = "EKS managed node group ID"
  value       = module.eks.eks_managed_node_groups["al2023"].node_group_id
}
