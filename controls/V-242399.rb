control 'V-242399' do
  title 'Kubernetes DynamicKubeletConfig must not be enabled.'
  desc 'Kubernetes allows a user to configure kubelets with dynamic configurations. When dynamic configuration is used, the kubelet will watch for changes to the configuration file. When changes are made, the kubelet will automatically restart. Allowing this capability bypasses access restrictions and authorizations. Using this capability, an attacker can lower the security posture of the kubelet, which includes allowing the ability to run arbitrary commands in any container running on that node.'
  desc 'check', %q(This check is only applicable for Kubernetes versions 1.25 and older.  

On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

In each manifest file, if the feature-gates does not exist, or does not contain the "DynamicKubeletConfig" flag, or sets the flag to "true", this is a finding.

On each Control Plane and Worker node, run the command:
ps -ef | grep kubelet

Verify the "feature-gates" option is not present.

Note the path to the config file (identified by --config).

Inspect the content of the config file:
If the "featureGates" setting is not present, or does not contain the "DynamicKubeletConfig", or sets the flag to "true", this is a finding.)
  desc 'fix', %q(This fix is only applicable to Kubernetes version 1.25 and older.

On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Edit the manifest files so that every manifest has a "--feature-gates" setting with "DynamicKubeletConfig=false".

On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "feature-gates" option if present.

Note the path to the config file (identified by --config).

Edit the config file: 
Add a "featureGates" setting if one does not yet exist. Add the feature gate "DynamicKubeletConfig=false".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet)
  impact 0.5
  tag check_id: 'C-45674r918162_chk'
  tag severity: 'medium'
  tag gid: 'V-242399'
  tag rid: 'SV-242399r960792_rule'
  tag stig_id: 'CNTR-K8-000460'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45632r918163_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  # --- BEGIN CUSTOM CODE ---
  only_if('node pass') { run_scope.node }
  
  # EKS Context: This check applies to Worker Nodes only.
  # EKS-managed Control Plane nodes are not accessible for direct inspection.
  # Note: DynamicKubeletConfig is only applicable for Kubernetes versions 1.25 and older.
  
  kl = kubelet
  feature_gates_cfg = kl.get_config_value('featureGates')
  
  # Check 1: --feature-gates flag must not be present in kubelet command line
  describe 'Kubelet --feature-gates command-line flag' do
    it 'should not be present on Worker Nodes' do
      expect(kl.flags.key?('feature-gates')).to eq(false), <<~MSG
        The --feature-gates command-line flag was found on the kubelet process.
        Current value: #{kl.flags['feature-gates']}
      MSG
    end
  end
  
  # Check 2: featureGates must be present with DynamicKubeletConfig explicitly disabled
  describe 'Kubelet config featureGates' do
    it 'should be present in the kubelet configuration' do
      expect(feature_gates_cfg).not_to be_nil, <<~MSG
        The featureGates setting is not present in the kubelet configuration.
        Config path: #{kl.config_path}
      MSG
    end
    
    it 'should have DynamicKubeletConfig present and set to false' do
      has_key = feature_gates_cfg&.key?('DynamicKubeletConfig') || false
      value = feature_gates_cfg&.fetch('DynamicKubeletConfig', nil)
      
      expect(has_key && value == false).to eq(true), <<~MSG
        DynamicKubeletConfig is not properly configured in featureGates.
        Config path: #{kl.config_path}
        Has DynamicKubeletConfig key: #{has_key}
        Current value: #{value.inspect}
        Current featureGates: #{feature_gates_cfg.inspect}
      MSG
    end
  end
  
  # --- END CUSTOM CODE ---
end
