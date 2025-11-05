control 'V-274884' do
  title 'Kubernetes must limit Secret access on a need-to-know basis.'
  desc 'Kubernetes secrets may store sensitive information such as passwords, tokens, and keys. Access to these secrets should be limited to a need-to-know basis via Kubernetes RBAC.'
  desc 'check', 'Review the Kubernetes accounts and their corresponding roles. 

If any accounts have read (list, watch, get) access to Secrets without a documented organizational requirement, this is a finding. 

Run the below command to list the workload resources for applications deployed to Kubernetes:
kubectl get all -A -o yaml 

If Secrets are attached to applications without a documented requirement, this is a finding.'
  desc 'fix', 'For Kubernetes accounts that have read access to Secrets without a documented requirement, modify the corresponding Role or ClusterRole to remove list, watch, and get privileges for Secrets.'
  impact 0.5
  tag check_id: 'C-78985r1107234_chk'
  tag severity: 'medium'
  tag gid: 'V-274884'
  tag rid: 'SV-274884r1107236_rule'
  tag stig_id: 'CNTR-K8-001163'
  tag gtitle: 'SRG-APP-000429-CTR-001060'
  tag fix_id: 'F-78890r1107235_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
  # --- BEGIN CUSTOM CODE ---
  only_if('cluster pass') { run_scope.cluster? }

  # Get RBAC roles and workloads for manual review
  roles_cmd = kubectl_client('get roles,clusterroles -A -o json')
  bindings_cmd = kubectl_client('get rolebindings,clusterrolebindings -A -o json')
  workloads_cmd = kubectl_client('get all -A -o json')
  
  describe 'Kubernetes RBAC Secret access' do
    skip <<~MSG
      Manual review required: Verify all Secret access is limited to documented organizational requirements.
      
      Roles and ClusterRoles:
      #{roles_cmd.success? ? roles_cmd.stdout : "Unable to retrieve: #{roles_cmd.error_message}"}
      
      RoleBindings and ClusterRoleBindings:
      #{bindings_cmd.success? ? bindings_cmd.stdout : "Unable to retrieve: #{bindings_cmd.error_message}"}
      
      Workload resources:
      #{workloads_cmd.success? ? workloads_cmd.stdout : "Unable to retrieve: #{workloads_cmd.error_message}"}
    MSG
  end
  # --- END CUSTOM CODE ---
end
