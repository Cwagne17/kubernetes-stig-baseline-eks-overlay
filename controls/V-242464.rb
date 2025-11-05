control 'V-242464' do
  title 'The Kubernetes API Server audit log retention must be set.'
  desc 'The Kubernetes API Server must set enough storage to retain logs for monitoring suspicious activity and system misconfiguration, and provide evidence for Cyber Security Investigations.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i audit-log-maxage * 

If the setting "audit-log-maxage" is not set in the Kubernetes API Server manifest file or it is set less than "30", this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--audit-log-maxage" to a minimum of "30".'
  impact 0.5
  tag check_id: 'C-45739r863931_chk'
  tag severity: 'medium'
  tag gid: 'V-242464'
  tag rid: 'SV-242464r961863_rule'
  tag stig_id: 'CNTR-K8-003310'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45697r863932_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  # --- BEGIN CUSTOM CODE ---
  only_if('cluster pass') { run_scope.cluster? }

  # EKS Context: Audit logs are sent to CloudWatch Logs with configurable retention policies.
  # The audit-log-maxage setting is not applicable as logs are not stored as rotating files.
  
  cluster_name = input('cluster_name')
  eks_cluster = aws_eks_cluster(cluster_name)
  
  describe 'Kubernetes API Server audit logs' do
    it 'should have EKS cluster audit logs enabled' do
      expect(eks_cluster.audit_logging_enabled?).to eq(true), <<~MSG
        EKS cluster audit logging is not enabled for cluster #{cluster_name}.
      MSG
    end
  end
  # --- END CUSTOM CODE ---
end
