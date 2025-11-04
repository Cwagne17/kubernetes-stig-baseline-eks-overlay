control 'V-242392' do
  title 'The Kubernetes kubelet must enable explicit authorization.'
  desc 'Kubelet is the primary agent on each node. The API server communicates with each kubelet to perform tasks such as starting/stopping pods. By default, kubelets allow all authenticated requests, even anonymous ones, without requiring any authorization checks from the API server. This default behavior bypasses any authorization controls put in place to limit what users may perform within the Kubernetes cluster. To change this behavior, the default setting of AlwaysAllow for the authorization mode must be set to "Webhook".'
  desc 'check', %q(Run the following command on each Worker Node:
ps -ef | grep kubelet
Verify that the --authorization-mode exists and is set to "Webhook".

If the --authorization-mode argument is not set to "Webhook" or doesn't exist, this is a finding.)
  desc 'fix', 'Edit the Kubernetes Kubelet service file in the --config directory on the Kubernetes Worker Node:

Set the value of "--authorization-mode" to "Webhook" in KUBELET_SYSTEM_PODS_ARGS variable.

Restart the kubelet service using the following command:

systemctl daemon-reload && systemctl restart kubelet'
  impact 0.7
  tag check_id: 'C-45667r1069459_chk'
  tag severity: 'high'
  tag gid: 'V-242392'
  tag rid: 'SV-242392r1069461_rule'
  tag stig_id: 'CNTR-K8-000380'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45625r1069460_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  # --- BEGIN CUSTOM CODE ---

  # EKS Context: This check applies to Worker Nodes only.
  # The Control Plane is fully managed by AWS and not accessible for inspection.
  
  kl = kubelet
  authorization_mode = kl.get_config_value('authorization', 'mode')

  describe 'Kubelet --authorization-mode command-line flag' do
    it 'should not be present on Worker Nodes' do
      expect(kl.flags.key?('authorization-mode')).to eq(false), <<~MSG
        The --authorization-mode command-line flag was found on the kubelet process.
        Current value: #{kl.flags['authorization-mode']}
      MSG
    end
  end

  describe 'Kubelet config authorization.mode' do
    it 'should be set to Webhook' do
      expect(authorization_mode).to eq('Webhook'), <<~MSG
        The kubelet authorization mode must be set to Webhook for explicit authorization.
        Config path: #{kl.config_path}
        Current value: #{authorization_mode.inspect}
      MSG
    end
  end

  # --- END CUSTOM CODE ---
end
