control 'V-242444' do
  title 'The Kubernetes component manifests must be owned by root.'
  desc 'The Kubernetes manifests are those files that contain the arguments and settings for the Control Plane services. These services are etcd, the api server, controller, proxy, and scheduler. If these files can be changed, the scheduler will be implementing the changes immediately. Many of the security settings within the document are implemented through these manifests.'
  desc 'check', 'Review the ownership of the Kubernetes manifests files by using the command:

stat -c %U:%G /etc/kubernetes/manifests/* | grep -v root:root

If the command returns any non root:root file permissions, this is a finding.'
  desc 'fix', 'Change the ownership of the manifest files to root: root by executing the command:

chown root:root /etc/kubernetes/manifests/*'
  impact 0.5
  tag check_id: 'C-45719r712686_chk'
  tag severity: 'medium'
  tag gid: 'V-242444'
  tag rid: 'SV-242444r961863_rule'
  tag stig_id: 'CNTR-K8-003110'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45677r712687_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  # --- BEGIN CUSTOM CODE ---
  describe 'Control-plane component manifests must be owned by root' do
    it <<~JUSTIFICATION do
      is not a finding because control-plane manifest files under /etc/kubernetes/manifests
      are configured by the Kubernetes control plane managed by EKS.
      AWS is responsible for proper ownership and permissions on control plane hosts.
      See https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html#control-plane
    JUSTIFICATION
      expect(true).to eq true
    end
  end
  # --- END CUSTOM CODE ---
end
