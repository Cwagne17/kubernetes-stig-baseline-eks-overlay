control 'V-242456' do
  title 'The Kubernetes kubelet config must have file permissions set to 644 or more restrictive.'
  desc 'The Kubernetes kubelet agent registers nodes with the API server and performs health checks to containers within pods. If this file can be modified, the information system would be unaware of pod or container degradation.'
  desc 'check', 'Review the permissions of the Kubernetes config.yaml by using the command:

stat -c %a /var/lib/kubelet/config.yaml

If any of the files are have permissions more permissive than "644", this is a finding.'
  desc 'fix', 'Change the permissions of the config.yaml to "644" by executing the command:

chmod 644 /var/lib/kubelet/config.yaml'
  impact 0.5
  tag check_id: 'C-45731r712722_chk'
  tag severity: 'medium'
  tag gid: 'V-242456'
  tag rid: 'SV-242456r961863_rule'
  tag stig_id: 'CNTR-K8-003230'
  tag gtitle: 'SRG-APP-000516-CTR-001330'
  tag fix_id: 'F-45689r821617_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  # --- BEGIN CUSTOM CODE ---
  only_if('node pass') { run_scope.node? }

  kl = kubelet
  config_file = file(kl.config_file)

  describe 'Kubelet configuration file permissions' do
    it 'must exist' do
      expect(config_file).to exist
    end

    if os.windows?
      it 'must have secure Windows ACLs for kubelet configuration file' do
        expect(config_file.user_permissions).to eq(
          'NT AUTHORITY\\SYSTEM' => 'FullControl',
          'BUILTIN\\Administrators' => 'FullControl',
          'BUILTIN\\Users' => 'ReadAndExecute, Synchronize'
        )
      end
    else
      it 'must have Unix permissions of 0644 or more restrictive' do
        expect(config_file).not_to be_more_permissive_than('0644')
      end
    end
  end
  # --- END CUSTOM CODE ---
end
