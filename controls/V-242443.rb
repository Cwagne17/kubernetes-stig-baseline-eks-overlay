control 'V-242443' do
  title 'Kubernetes must contain the latest updates as authorized by IAVMs, CTOs, DTMs, and STIGs.'
  desc 'Kubernetes software must stay up to date with the latest patches, service packs, and hot fixes. Not updating the Kubernetes control plane will expose the organization to vulnerabilities.

Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant container platform components may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the IAVM process.

The container platform components will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The container platform registry will ensure the images are current. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Authenticate on the Kubernetes Control Plane. Run the command:
kubectl version --short

If kubectl version has a setting not supporting Kubernetes skew policy, this is a finding.

Note: Kubernetes Skew Policy can be found at: https://kubernetes.io/docs/setup/release/version-skew-policy/#supported-versions'
  desc 'fix', 'Upgrade Kubernetes to the supported version. Institute and adhere to the policies and procedures to ensure that patches are consistently applied within the time allowed.'
  impact 0.5
  tag check_id: 'C-45718r863908_chk'
  tag severity: 'medium'
  tag gid: 'V-242443'
  tag rid: 'SV-242443r961683_rule'
  tag stig_id: 'CNTR-K8-002720'
  tag gtitle: 'SRG-APP-000456-CTR-001125'
  tag fix_id: 'F-45676r712684_fix'
  tag 'documentable'
  tag cci: ['CCI-002635']
  tag nist: ['SI-3 (10) (a)']
  # --- BEGIN CUSTOM CODE ---
  only_if('cluster pass') { run_scope.cluster? }

  # EKS Context: Cluster version is managed by AWS and can be queried via EKS API.
  # Manual review required to verify version is current per IAVM/CTO/DTM/STIG guidance.
  
  cluster_name = input('cluster_name')
  eks_cluster = aws_eks_cluster(cluster_name)

  describe 'Kubernetes version compliance' do
    it 'requires manual review of cluster version against current IAVM/CTO/DTM/STIG requirements' do
      skip <<~MSG
        Manual verification required to ensure Kubernetes version is current.
        
        Current EKS cluster version: #{eks_cluster.version}
        Cluster: #{cluster_name}
        
        Verify this version is supported per Kubernetes skew policy and current security guidance:
        - Kubernetes Skew Policy: https://kubernetes.io/docs/setup/release/version-skew-policy/#supported-versions
        - EKS Supported Versions: https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html
      MSG
    end
  end
  # --- END CUSTOM CODE ---
end
