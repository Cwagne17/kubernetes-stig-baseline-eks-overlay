control 'V-242406' do
  title 'The Kubernetes KubeletConfiguration file must be owned by root.'
  desc 'The kubelet configuration file contains the runtime configuration of the kubelet service. If an attacker can gain access to this file, changes can be made to open vulnerabilities and bypass user authorizations inherent within Kubernetes with RBAC implemented.'
  desc 'check', 'On the Kubernetes Control Plane and Worker nodes, run the command:
ps -ef | grep kubelet

Check the config file (path identified by: --config):

Change to the directory identified by --config (example /etc/sysconfig/) run the command:
ls -l kubelet

Each kubelet configuration file must be owned by root:root.

If any manifest file is not owned by root:root, this is a finding.'
  desc 'fix', 'On the Control Plane and Worker nodes, change to the --config directory. Run the command:
chown root:root kubelet

To verify the change took place, run the command:
ls -l kubelet

The kubelet file should now be owned by root:root.'
  impact 0.5
  tag check_id: 'C-45681r863815_chk'
  tag severity: 'medium'
  tag gid: 'V-242406'
  tag rid: 'SV-242406r960960_rule'
  tag stig_id: 'CNTR-K8-000880'
  tag gtitle: 'SRG-APP-000133-CTR-000300'
  tag fix_id: 'F-45639r863816_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  # --- BEGIN CUSTOM CODE ---
  only_if('node pass') { run_scope.node? }

  kl = kubelet
  config_file = file(kl.config_file)

  describe 'Kubelet configuration file ownership' do
    it 'must exist' do
      expect(config_file).to exist
    end

    if os.windows?
      it 'must be owned by BUILTIN\\Administrators on Windows' do
        expect(config_file.owner).to eq('BUILTIN\\Administrators')
      end
    else
      it 'must be owned by root on Unix' do
        expect(config_file.owner).to eq('root')
      end

      it 'must have root as group owner on Unix' do
        expect(config_file.group).to eq('root')
      end
    end
  end
  # --- END CUSTOM CODE ---
end
