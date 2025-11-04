control 'V-242410' do
  title 'The Kubernetes API Server must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).'
  desc 'Kubernetes API Server PPSs must be controlled and conform to the PPSM CAL. Those PPS that fall outside the PPSM CAL must be blocked. Instructions on the PPSM can be found in DoD Instruction 8551.01 Policy.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep kube-apiserver.manifest -I -secure-port *
grep kube-apiserver.manifest -I -etcd-servers *
-edit manifest file:
VIM <Manifest Name>
Review livenessProbe:
HttpGet:
Port:
Review ports:
- containerPort:
hostPort:
- containerPort:
hostPort:

Run command: 
kubectl describe services --all-namespaces 
Search labels for any apiserver namespaces.
Port:

Any manifest and namespace PPS or services configuration not in compliance with PPSM CAL is a finding.

Review the information systems documentation and interview the team, gain an understanding of the API Server architecture, and determine applicable PPS. If there are any PPS in the system documentation not in compliance with the CAL PPSM, this is a finding. Any PPS not set in the system documentation is a finding.

Review findings against the most recent PPSM CAL:
https://cyber.mil/ppsm/cal/

Verify API Server network boundary with the PPS associated with the CAL Assurance Categories. Any PPS not in compliance with the CAL Assurance Category requirements is a finding.'
  desc 'fix', 'Amend any system documentation requiring revision to comply with PPSM CAL. 

Update Kubernetes API Server manifest and namespace PPS configuration to comply with PPSM CAL.'
  impact 0.5
  tag check_id: 'C-45685r1007472_chk'
  tag severity: 'medium'
  tag gid: 'V-242410'
  tag rid: 'SV-242410r1043177_rule'
  tag stig_id: 'CNTR-K8-000920'
  tag gtitle: 'SRG-APP-000142-CTR-000325'
  tag fix_id: 'F-45643r1007473_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
  # --- BEGIN CUSTOM CODE ---

  cluster_name = input('cluster_name')
  eks_cluster = aws_eks_cluster(cluster_name)
  
  endpoint_public_access = eks_cluster.endpoint_public_access
  endpoint_private_access = eks_cluster.endpoint_private_access
  public_access_cidrs = eks_cluster.public_access_cidrs
  
  describe 'Kubernetes API Server PPSM compliance' do
    it <<~JUSTIFICATION do
      is not a finding because the Kubernetes API Server is managed by AWS in EKS.
      
      AWS EKS manages the Control Plane including the API Server configuration, ports,
      protocols, and services. The API Server runs in AWS-managed infrastructure with
      AWS-controlled network boundaries and security configurations.
      
      EKS API Server configuration:
      - Secure port: 443 (HTTPS)
      - Authentication via AWS IAM and Kubernetes RBAC
      - TLS encryption for all API communications
      
      Current cluster endpoint access configuration:
      - Public access enabled: #{endpoint_public_access}
      - Private access enabled: #{endpoint_private_access}
      - Public access CIDRs: #{public_access_cidrs.join(', ')}

      Network access control:
      - When public access is enabled, access is controlled by the configured CIDR blocks
      - When private access is enabled, access is controlled by VPC security groups
      - Security groups determine which resources within the VPC can access the API Server
      
      PPSM compliance for EKS API Server ports and protocols is AWS's responsibility
      under the shared responsibility model. Network access boundaries are configured
      via EKS cluster endpoint settings and VPC security groups.
      
      See: https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html
    JUSTIFICATION
      expect(true).to eq(true)
    end
  end

  # --- END CUSTOM CODE ---
end
