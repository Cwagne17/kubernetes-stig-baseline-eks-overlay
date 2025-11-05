control 'V-242455' do
  title 'The Kubernetes kubeadm.conf must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes kubeadm.conf contains sensitive information regarding the cluster nodes configuration. If this file can be modified, the Kubernetes Platform Plane would be degraded or compromised for malicious intent. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Review the kubeadm.conf file :

Get the path for kubeadm.conf by running:
systemctl status kubelet

Note the configuration file installed by the kubeadm is written to
(Default Location: /etc/systemd/system/kubelet.service.d/10-kubeadm.conf)
stat -c %a  <kubeadm.conf path>

If the file has permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of kubeadm.conf to "644" by executing the command:

chmod 644 <kubeadm.conf path>'
  impact 0.5
  tag check_id: 'C-45730r754820_chk'
  tag severity: 'medium'
  tag gid: 'V-242455'
  tag rid: 'SV-242455r961863_rule'
  tag stig_id: 'CNTR-K8-003220'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45688r754821_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  # --- BEGIN CUSTOM CODE ---
  only_if('cluster pass') { run_scope.cluster? }

  describe 'Kubeadm configuration file permissions in EKS' do
    it <<~JUSTIFICATION do
      is not a finding because EKS does not use kubeadm.
      The control plane is fully managed by Amazon EKS and does not rely on kubeadm for configuration.
      See https://docs.aws.amazon.com/eks/latest/best-practices/control-plane.html
    JUSTIFICATION
      expect(true).to eq(true)
    end
  end
  # --- END CUSTOM CODE ---
end
