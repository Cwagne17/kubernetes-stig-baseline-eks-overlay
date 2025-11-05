control 'V-242453' do
  title 'The Kubernetes kubelet KubeConfig file must be owned by root.'
  desc 'The Kubernetes kubelet agent registers nodes with the API server and performs health checks to containers within pods. If these files can be modified, the information system would be unaware of pod or container degradation. Many of the security settings within the document are implemented through this file.'
  desc 'check', 'Review the Kubernetes Kubelet conf files by using the command:

stat -c %U:%G /etc/kubernetes/kubelet.conf| grep -v root:root

If the command returns any non root:root file permissions, this is a finding.'
  desc 'fix', 'Change the ownership of the kubelet.conf to root: root by executing the command:

chown root:root /etc/kubernetes/kubelet.conf'
  impact 0.5
  tag check_id: 'C-45728r712713_chk'
  tag severity: 'medium'
  tag gid: 'V-242453'
  tag rid: 'SV-242453r961863_rule'
  tag stig_id: 'CNTR-K8-003200'
  tag gtitle: 'SRG-APP-000516-CTR-001325'
  tag fix_id: 'F-45686r712714_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  # --- BEGIN CUSTOM CODE ---
  only_if('node pass') { run_scope.node? }

  kubelet_kubeconfig_path = input('kubelet_kubeconfig_path')

  describe 'Kubelet kubeconfig file ownership' do
    subject { file(kubelet_kubeconfig_path) }

    it 'must exist' do
      expect(subject).to exist
    end

    it 'must be owned by root' do
      expect(subject.owner).to eq('root')
    end

    it 'must have root as group owner' do
      expect(subject.group).to eq('root')
    end
  end
  # --- END CUSTOM CODE ---
end
