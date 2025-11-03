# EKS Optimized AL2023 Example

This example deploys an EC2 instance with the latest EKS optimized Amazon Linux 2023 AMI and configures it for testing with InSpec via AWS SSM Session Manager.

## Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform/OpenTofu
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
tofu init
tofu apply
```

### 3. Get Instance ID

After deployment, get the instance ID:

```bash
INSTANCE_ID=$(tofu output -raw instance_id)
echo $INSTANCE_ID
```

## Running InSpec Tests

### Option 1: Direct Command

Run the InSpec profile against the EC2 instance via SSM:

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

## Cleanup

When finished testing:

```bash
terraform destroy
```

## Notes

- The instance is deployed in the default VPC with no public IP
- SSM Session Manager is used for remote access (no SSH required)
- The instance uses the latest EKS optimized AL2023 AMI for Kubernetes 1.33
- IMDSv2 is enforced for enhanced security
- Root volume is encrypted by default
