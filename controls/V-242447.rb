control 'V-242447' do
  title 'The Kubernetes Kube Proxy kubeconfig must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes Kube Proxy kubeconfig contain the argument and setting for the Control Planes. These settings contain network rules for restricting network communication between pods, clusters, and networks. If these files can be changed, data traversing between the Kubernetes Control Panel components would be compromised. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Check if Kube-Proxy is running and obtain --kubeconfig parameter use the following command:
ps -ef | grep kube-proxy

If Kube-Proxy exists:
Review the permissions of the Kubernetes Kube Proxy by using the command:
stat -c %a <location from --kubeconfig>

If the file has permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of the Kube Proxy to "644" by executing the command:

chmod 644 <location from kubeconfig>.'
  impact 0.5
  tag check_id: 'C-45722r712695_chk'
  tag severity: 'medium'
  tag gid: 'V-242447'
  tag rid: 'SV-242447r961863_rule'
  tag stig_id: 'CNTR-K8-003140'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45680r821611_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  # --- BEGIN CUSTOM CODE ---
  only_if('node pass') { run_scope.node? }

  # EKS Context: Kube-proxy is managed as an EKS add-on or self-managed DaemonSet.
  # When managed as an add-on, AWS handles the configuration and security of kube-proxy.
  
  cluster_name = input('cluster_name')
  eks_cluster = aws_eks_cluster(cluster_name)

  # Check if kube-proxy is managed as an EKS add-on
  if eks_cluster.addons.include?('kube-proxy') && eks_cluster.addon_active?('kube-proxy')
    addon = eks_cluster.addon_info('kube-proxy')
    
    describe 'EKS kube-proxy add-on' do
      it <<~JUSTIFICATION do
        is not a finding because kube-proxy is deployed as an EKS-managed add-on.
        When kube-proxy is an EKS add-on, it runs as a DaemonSet with configuration managed
        via Kubernetes ConfigMaps rather than static kubeconfig files on disk.
        
        Access control is enforced through Kubernetes RBAC, not filesystem permissions where 
        only users with appropriate Kubernetes API permissions (e.g., Cluster Admin) can modify
        the configuration
        
        Add-on status: #{addon&.status}
        Add-on version: #{addon&.addon_version}
        
        See: https://docs.aws.amazon.com/eks/latest/userguide/managing-kube-proxy.html
      JUSTIFICATION
        expect(true).to eq true
      end
    end
  else
    describe 'Kube-proxy configuration review' do
      skip <<~MSG
        Kube-proxy is not configured as an active EKS add-on for cluster #{cluster_name}.
        This indicates kube-proxy is being manually managed (self-managed DaemonSet or custom deployment).
        
        Manual verification required:
        1. Identify the kube-proxy deployment method on worker nodes
        2. Locate the kubeconfig file (typically specified with --kubeconfig flag)
        3. Verify file permissions are 644 or more restrictive using: stat -c %a <kubeconfig-path>
        
        If manually managing kube-proxy, ensure proper file permissions are maintained.
      MSG
    end
  end
  # --- END CUSTOM CODE ---
end
