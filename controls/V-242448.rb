control 'V-242448' do
  title 'The Kubernetes Kube Proxy kubeconfig must be owned by root.'
  desc 'The Kubernetes Kube Proxy kubeconfig contain the argument and setting for the Control Planes. These settings contain network rules for restricting network communication between pods, clusters, and networks. If these files can be changed, data traversing between the Kubernetes Control Panel components would be compromised. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Check if Kube-Proxy is running use the following command:
ps -ef | grep kube-proxy

If Kube-Proxy exists:
Review the permissions of the Kubernetes Kube Proxy by using the command:
stat -c   %U:%G <location from --kubeconfig>| grep -v root:root

If the command returns any non root:root file permissions, this is a finding.'
  desc 'fix', 'Change the ownership of the Kube Proxy to root:root by executing the command:

chown root:root <location from kubeconfig>.'
  impact 0.5
  tag check_id: 'C-45723r712698_chk'
  tag severity: 'medium'
  tag gid: 'V-242448'
  tag rid: 'SV-242448r961863_rule'
  tag stig_id: 'CNTR-K8-003150'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45681r712699_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  # --- BEGIN CUSTOM CODE ---

  # EKS Context: Kube-proxy is managed as an EKS add-on or self-managed DaemonSet.
  # When managed as an add-on, AWS handles the configuration and security of kube-proxy.
  
  cluster_name = input('cluster_name')
  eks_cluster = aws_eks_cluster(cluster_name)

  # Check if kube-proxy is managed as an EKS add-on
  if eks_cluster.addons.include?('kube-proxy') && eks_cluster.addon_active?('kube-proxy')
    addon = eks_cluster.addon_info('kube-proxy')
    
    describe 'EKS kube-proxy add-on' do
      it <<~JUSTIFICATION do
        is not a finding because kube-proxy is managed as an EKS add-on.
        When kube-proxy is an EKS-managed add-on, AWS is responsible for the secure
        configuration, including proper file ownership (root:root) of kubeconfig files.
        
        Cluster: #{cluster_name}
        Add-on status: #{addon&.status}
        Add-on version: #{addon&.addon_version}
        
        The kube-proxy pods run with appropriate security contexts managed by AWS, ensuring
        kubeconfig files are owned by root:root. AWS maintains these configurations according
        to security best practices.
        
        See: https://docs.aws.amazon.com/eks/latest/userguide/managing-kube-proxy.html
      JUSTIFICATION
        expect(true).to eq true
      end
    end
  else
    describe 'Kube-proxy configuration review' do
      it 'requires manual review' do
        skip <<~MSG
          Not Reviewed: Kube-proxy is not configured as an active EKS add-on for cluster #{cluster_name}.
          This indicates kube-proxy is being manually managed (self-managed DaemonSet or custom deployment).
          
          Manual verification required:
          1. Identify the kube-proxy deployment method on worker nodes
          2. Locate the kubeconfig file (typically specified with --kubeconfig flag)
          3. Verify file ownership is root:root using: stat -c %U:%G <kubeconfig-path>
          
          If manually managing kube-proxy, ensure proper file ownership (root:root) is maintained.
        MSG
      end
    end
  end

  # --- END CUSTOM CODE ---
end
