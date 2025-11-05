control 'V-242463' do
  title 'The Kubernetes API Server must be set to audit log maximum backup.'
  desc 'The Kubernetes API Server must set enough storage to retain logs for monitoring suspicious activity and system misconfiguration, and provide evidence for Cyber Security Investigations.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i audit-log-maxbackup * 

If the setting "audit-log-maxbackup" is not set in the Kubernetes API Server manifest file or it is set less than "10", this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the value of "--audit-log-maxbackup" to a minimum of "10".'
  impact 0.5
  tag check_id: 'C-45738r863928_chk'
  tag severity: 'medium'
  tag gid: 'V-242463'
  tag rid: 'SV-242463r961863_rule'
  tag stig_id: 'CNTR-K8-003300'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45696r863929_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  # --- BEGIN CUSTOM CODE ---
  only_if('cluster pass') { run_scope.cluster? }

  # EKS Context: Audit logs are sent to CloudWatch Logs, not stored as files with backup rotation.
  # CloudWatch Logs provides managed log storage with configurable retention policies.
  
  cluster_name = input('cluster_name')
  eks_cluster = aws_eks_cluster(cluster_name)

  describe 'Kubernetes API Server audit logs' do
    it 'should have EKS cluster audit logs enabled to send to CloudWatch Logs' do
      expect(eks_cluster.audit_logging_enabled?).to eq(true), <<~MSG
        EKS cluster audit logging is not enabled for cluster #{cluster_name}.
      MSG
    end
  end
  # --- END CUSTOM CODE ---
end
