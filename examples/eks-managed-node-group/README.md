# EKS Optimized AL2023 Example

This example deploys a complete Amazon EKS cluster with AL2023 managed node groups for STIG compliance testing. The nodes are configured with kubelet settings that can be tested with the InSpec profile via AWS SSM Session Manager.

## Architecture

- **VPC**: Uses default VPC in your AWS account
- **EKS Cluster**: Kubernetes 1.33
- **Managed Node Group**: AL2023 with t3.medium instances
- **Node Configuration**: Custom kubelet settings including `protectKernelDefaults: true`
- **Access**: SSM Session Manager enabled for InSpec testing

## Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform >= 1.3 or OpenTofu
- kubectl installed
- cinc-auditor installed
- train-awsssm plugin installed

## Setup

### 1. Install train-awsssm Plugin

From the repository root:

```bash
make install-ssm
```

Or manually:

```bash
cinc-auditor plugin install train-awsssm
```

### 2. Deploy Infrastructure

```bash
cd examples/eks-optimized-al2023
terraform init
terraform apply
```

This will create:

- EKS cluster with control plane (uses default VPC)
- Managed node group with 1 AL2023 node in default subnets
- All required IAM roles and security groups

**Note**: This deployment takes approximately 15-20 minutes.

### 3. Configure kubectl

After deployment, configure kubectl to access your cluster:

```bash
aws eks update-kubeconfig --region us-east-1 --name $(terraform output -raw cluster_name)
```

Verify connectivity:

```bash
kubectl get nodes
```

### 4. Get Node Instance ID

Find the instance ID of a worker node for InSpec testing:

```bash
# Get node name from kubectl
NODE_NAME=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')

# Extract instance ID from node name (format: ip-xxx-xxx-xxx-xxx.region.compute.internal)
INSTANCE_ID=$(kubectl get node $NODE_NAME -o jsonpath='{.spec.providerID}' | cut -d'/' -f5)

echo "Instance ID: $INSTANCE_ID"
```

Or using AWS CLI:

```bash
# Get ASG name from Terraform output
ASG_NAME=$(terraform output -raw node_group_autoscaling_group_names | jq -r '.[0]')

# Get instance ID from ASG
INSTANCE_ID=$(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names $ASG_NAME \
  --region us-east-1 \
  --query 'AutoScalingGroups[0].Instances[0].InstanceId' \
  --output text)

echo "Instance ID: $INSTANCE_ID"
```

## Running InSpec Tests

Run the InSpec profile against an EKS node via SSM:

```bash
# From the examples/eks-optimized-al2023 directory
cinc-auditor exec ../.. \
  -t awsssm://$INSTANCE_ID \
  --region=us-east-1 \
  --reporter cli json:../../output/results.json
```

## Viewing Results

Start Heimdall Lite to view results:

```bash
# From repository root
cd ../..
make serve
```

Open http://localhost:8080 and upload `output/results.json`

## Testing Specific Controls

The node group is pre-configured with kubelet settings for STIG testing:

```yaml
kubelet:
  config:
    protectKernelDefaults: true
    shutdownGracePeriod: 30s
    shutdownGracePeriodCriticalPods: 10s
```

These settings can be verified via the InSpec controls in the profile.

## Cleanup

When finished testing:

```bash
terraform destroy
```

**Note**: Destruction takes approximately 10-15 minutes.

## Notes

- **Default VPC Required**: This example uses your default VPC and subnets
- Nodes are deployed in default subnets (typically public with internet gateway)
- SSM Session Manager is used for InSpec access (no SSH required)
- Nodes use the latest EKS optimized AL2023 AMI
- EKS cluster creator is automatically granted admin permissions

## Costs

Running this example will incur AWS charges for:

- EKS control plane (~$0.10/hour)
- EC2 instances (t3.medium)
- EBS volumes

Estimated cost: ~$2-3 per day if left running (lower cost due to using default VPC).
