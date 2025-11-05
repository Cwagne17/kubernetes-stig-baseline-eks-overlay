control 'V-254801' do
  title 'Kubernetes must enable PodSecurity admission controller on static pods and Kubelets.'
  desc 'PodSecurity admission controller is a component that validates and enforces security policies for pods running within a Kubernetes cluster. It is responsible for evaluating the security context and configuration of pods against defined policies. 

To enable PodSecurity admission controller on Static Pods (kube-apiserver, kube-controller-manager, or kube-schedule), the argument "--feature-gates=PodSecurity=true" must be set.

To enable PodSecurity admission controller on Kubelets, the featureGates PodSecurity=true argument must be set.

(Note: The PodSecurity feature gate is GA as of  v1.25.)'
  desc 'check', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

For each manifest file, if the "--feature-gates" setting does not exist, does not contain the "--PodSecurity" flag, or sets the flag to "false", this is a finding.

On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

If the "--feature-gates" option exists, this is a finding. 

Note the path to the config file (identified by --config).

Inspect the content of the config file:
If the "featureGates" setting is not present, does not contain the "PodSecurity" flag, or sets the flag to "false", this is a finding.)
  desc 'fix', %q(On the Control Plane, change to the manifests' directory at /etc/kubernetes/manifests and run the command:
grep -i feature-gates *

Ensure the argument "--feature-gates=PodSecurity=true" is present in each manifest file.

On each Control Plane and Worker Node, run the command:
ps -ef | grep kubelet

Remove the "--feature-gates" option if present.

Note the path to the config file (identified by --config).

Edit the Kubernetes Kubelet config file: 
Add a "featureGates" setting if one does not yet exist. Add the feature gate "PodSecurity=true".

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet)
  impact 0.7
  tag check_id: 'C-58412r918278_chk'
  tag severity: 'high'
  tag gid: 'V-254801'
  tag rid: 'SV-254801r961359_rule'
  tag stig_id: 'CNTR-K8-002001'
  tag gtitle: 'SRG-APP-000342-CTR-000775'
  tag fix_id: 'F-58358r918213_fix'
  tag 'documentable'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']
  # --- BEGIN CUSTOM CODE ---
  only_if('node pass') { run_scope.node? }
  
  # EKS Context: This check applies to Worker Nodes only.
  # EKS-managed Control Plane nodes are not accessible for direct inspection.
  # Note: PodSecurity feature gate is GA (generally available) as of Kubernetes v1.25.
  
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
  
  # Check 2: featureGates must be present with PodSecurity explicitly enabled
  describe 'Kubelet config featureGates' do
    it 'should be present in the kubelet configuration' do
      expect(feature_gates_cfg).not_to be_nil, <<~MSG
        The featureGates setting is not present in the kubelet configuration.
        Config path: #{kl.config_path}
      MSG
    end
    
    it 'should have PodSecurity explicitly set to true' do
      expect(feature_gates_cfg&.fetch('PodSecurity', nil)).to eq(true), <<~MSG
        The PodSecurity feature gate is not explicitly enabled in the kubelet configuration.
        Config path: #{kl.config_path}
        Current featureGates: #{feature_gates_cfg.inspect}
      MSG
    end
  end
  
  # --- END CUSTOM CODE ---
end
