control 'V-242461' do
  title 'Kubernetes API Server audit logs must be enabled.'
  desc 'Kubernetes API Server validates and configures pods and services for the API object. The REST operation provides frontend functionality to the cluster share state. Enabling audit logs provides a way to monitor and identify security risk events or misuse of information. Audit logs are necessary to provide evidence in the case the Kubernetes API Server is compromised requiring a Cyber Security Investigation.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
grep -i audit-policy-file * 

If the setting "audit-policy-file" is not set or is found in the Kubernetes API manifest file without valid content, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the argument "--audit-policy-file" to "log file directory".'
  impact 0.5
  tag check_id: 'C-45736r863922_chk'
  tag severity: 'medium'
  tag gid: 'V-242461'
  tag rid: 'SV-242461r961863_rule'
  tag stig_id: 'CNTR-K8-003280'
  tag gtitle: 'SRG-APP-000516-CTR-001335'
  tag fix_id: 'F-45694r863923_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  # --- BEGIN CUSTOM CODE ---

  # EKS Context: Audit logging in EKS is configured to send logs to CloudWatch Logs.
  # The audit-policy-file setting is AWS-managed and not directly accessible.
  
  cluster_name = input('cluster_name')
  eks_cluster = aws_eks_cluster(cluster_name)

  describe 'Kubernetes API Server audit logs' do
    it 'should have EKS cluster audit logs enabled to send to CloudWatch' do
      # EKS sends audit logs to CloudWatch Logs when enabled
      # Current enabled log types: #{eks_cluster.enabled_log_types.inspect}
      
      expect(eks_cluster.audit_logging_enabled?).to eq(true), <<~MSG
        EKS cluster audit logging is not enabled for cluster #{cluster_name}.
        
        Enable audit logging to send Kubernetes API Server audit logs to CloudWatch Logs with:
        aws eks update-cluster-config --region $AWS_REGION --name #{cluster_name} \\
          --logging '{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'
        
        See: https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
      MSG
    end
  end

  # --- END CUSTOM CODE ---
end
