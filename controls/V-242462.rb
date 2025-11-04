control 'V-242462' do
  title 'The Kubernetes API Server must be set to audit log max size.'
  desc 'The Kubernetes API Server must be set for enough storage to retain log information over the period required. When audit logs are large in size, the monitoring service for events becomes degraded. The function of the maximum log file size is to set these limits.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i audit-log-maxsize * 

If the setting "--audit-log-maxsize" is not set in the Kubernetes API Server manifest file or it is set to less than "100", this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. 

Set the value of "--audit-log-maxsize" to a minimum of "100".'
  impact 0.5
  tag check_id: 'C-45737r927135_chk'
  tag severity: 'medium'
  tag gid: 'V-242462'
  tag rid: 'SV-242462r961863_rule'
  tag stig_id: 'CNTR-K8-003290'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45695r927136_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  # --- BEGIN CUSTOM CODE ---

  # EKS Context: Audit logs are sent to CloudWatch Logs, not stored as files with size limits.
  # CloudWatch Logs provides scalable, managed log storage with configurable retention.
  
  cluster_name = input('cluster_name')
  eks_cluster = aws_eks_cluster(cluster_name)

  describe 'Kubernetes API Server audit logs' do
    it 'should have EKS cluster audit logs enabled to send to CloudWatch Logs' do
      expect(eks_cluster.audit_logging_enabled?).to eq(true), <<~MSG
        EKS cluster audit logging is not enabled for cluster #{cluster_name}.
        Enable audit logging first before configuring retention settings.
        
        aws eks update-cluster-config --region $AWS_REGION --name #{cluster_name} \\
          --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
      MSG
    end
  end

  # --- END CUSTOM CODE ---
end
