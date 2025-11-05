control 'V-242387' do
  title 'The Kubernetes Kubelet must have the "readOnlyPort" flag disabled.'
  desc 'Kubelet serves a small REST API with read access to port 10255. The read-only port for Kubernetes provides no authentication or authorization security control. Providing unrestricted access on port 10255 exposes Kubernetes pods and containers to malicious attacks or compromise. Port 10255 is deprecated and should be disabled.'
  desc 'check', 'On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

If the "--read-only-port" option exists, this is a finding. 

Note the path to the config file (identified by --config).

Run the command:
grep -i readOnlyPort <path_to_config_file>

If the setting "readOnlyPort" exists and is not set to "0", this is a finding.'
  desc 'fix', 'On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "--read-only-port" option if present.

Note the path to the config file (identified by --config).

Edit the config file: 
Set "readOnlyPort" to "0" or remove the setting.

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.7
  tag check_id: 'C-45662r918147_chk'
  tag severity: 'high'
  tag gid: 'V-242387'
  tag rid: 'SV-242387r960792_rule'
  tag stig_id: 'CNTR-K8-000330'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45620r918148_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  # --- BEGIN CUSTOM CODE ---
  only_if('node pass') { run_scope.node? }

  # EKS Context: This check applies to Worker Nodes only.
  # The Control Plane is fully managed by AWS and not accessible for inspection.
  
  kl = kubelet
  read_only_port = kl.get_config_value('readOnlyPort')

  describe 'Kubelet --read-only-port command-line flag' do
    it 'should not be present on Worker Nodes' do
      expect(kl.flags.key?('read-only-port')).to eq(false), <<~MSG
        The --read-only-port command-line flag was found on the kubelet process.
        Current value: #{kl.flags['read-only-port']}
      MSG
    end
  end

  describe 'Kubelet config readOnlyPort' do
    it 'should be disabled (set to 0 or absent)' do
      expect([nil, 0]).to include(read_only_port), <<~MSG
        The kubelet readOnlyPort must be disabled by setting it to 0 or removing it.
        Config path: #{kl.config_path}
        Current value: #{read_only_port.inspect}
      MSG
    end
  end

  # --- END CUSTOM CODE ---
end
