control 'V-242404' do
  title 'Kubernetes Kubelet must deny hostname override.'
  desc 'Kubernetes allows for the overriding of hostnames. Allowing this feature to be implemented within the kubelets may break the TLS setup between the kubelet service and the API server. This setting also can make it difficult to associate logs with nodes if security analytics needs to take place. The better practice is to setup nodes with resolvable FQDNs and avoid overriding the hostnames.'
  desc 'check', 'On the Control Plane and Worker nodes, run the command:
ps -ef | grep kubelet

If the option "--hostname-override" is present, this is a finding.'
  desc 'fix', 'Run the command:  
systemctl status kubelet.  
Note the path to the drop-in file.

Determine the path to the environment file(s) with the command: 
grep -i EnvironmentFile <path_to_drop_in_file>.

Remove the "--hostname-override" option from any environment file where it is present.  

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.5
  tag check_id: 'C-45679r918165_chk'
  tag severity: 'medium'
  tag gid: 'V-242404'
  tag rid: 'SV-242404r960960_rule'
  tag stig_id: 'CNTR-K8-000850'
  tag gtitle: 'SRG-APP-000133-CTR-000290'
  tag fix_id: 'F-45637r918166_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  # --- BEGIN CUSTOM CODE ---
  only_if('node pass') { run_scope.node? }

  # EKS Context: Amazon EKS-optimized AMIs use --hostname-override by default
  # to set the node name to match the EC2 instance's private DNS name.
  # This is required for proper cluster join and node identification in EKS.

  hostname_override_flag = kubelet.flags['hostname-override']

  describe 'Kubelet --hostname-override flag' do
    it 'should not be present' do
      expect(hostname_override_flag).to be_nil, <<~MSG
        The --hostname-override flag was found on the kubelet process.
        
        Amazon EKS nodes register to the API server using the instance's EC2 private DNS 
        name. On EKS-optimized AMIs, bootstrap/nodeadm may pass --hostname-override for 
        consistency, but with the AWS cloud provider enabled, kubelet uses provider logic 
        for the node name and can ignore the flag. Either way, nodes register with the EC2 
        private DNS name.
        
        While the STIG recommends avoiding hostname override, EKS requires this for proper
        cluster operation. Consider accepting this as a risk or implementing compensating
        controls such as ensuring DNS resolution is properly configured and monitoring node
        registration events.
        
        See: https://docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html
        Current command: #{kl.cmdline}
      MSG
    end
  end

  # --- END CUSTOM CODE ---
end
