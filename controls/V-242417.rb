control 'V-242417' do
  title 'Kubernetes must separate user functionality.'
  desc 'Separating user functionality from management functionality is a requirement for all the components within the Kubernetes Control Plane. Without the separation, users may have access to management functions that can degrade the Kubernetes architecture and the services being offered, and can offer a method to bypass testing and validation of functions before introduced into a production environment.'
  desc 'check', 'On the Control Plane, run the command:
kubectl get pods --all-namespaces

Review the namespaces and pods that are returned. Kubernetes system namespaces are kube-node-lease, kube-public, and kube-system.

If any user pods are present in the Kubernetes system namespaces, this is a finding.'
  desc 'fix', 'Move any user pods that are present in the Kubernetes system namespaces to user specific namespaces.'
  impact 0.5
  tag check_id: 'C-45692r863840_chk'
  tag severity: 'medium'
  tag gid: 'V-242417'
  tag rid: 'SV-242417r961095_rule'
  tag stig_id: 'CNTR-K8-001360'
  tag gtitle: 'SRG-APP-000211-CTR-000530'
  tag fix_id: 'F-45650r712606_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
  # --- BEGIN CUSTOM CODE ---

  # System namespaces that should only contain Kubernetes system components
  system_namespaces = ['kube-system', 'kube-node-lease', 'kube-public']
  
  pods_cmd = kubectl_client('get pods --all-namespaces -o json')
  
  if pods_cmd.success? && pods_cmd.json
    all_pods = pods_cmd.json['items'] || []
    
    system_namespaces.each do |ns|
      namespace_pods = all_pods.select { |p| p.dig('metadata', 'namespace') == ns }
      
      # Identify potential user pods (heuristic: not starting with kube-, not in known system prefixes)
      system_prefixes = ['kube-', 'calico-', 'coredns', 'etcd', 'aws-', 'ebs-', 'efs-', 'vpc-', 'eks-']
      
      user_pods = namespace_pods.select do |pod|
        pod_name = pod.dig('metadata', 'name')
        # Consider it a user pod if it doesn't start with any system prefix
        !system_prefixes.any? { |prefix| pod_name.start_with?(prefix) }
      end
      
      describe "System namespace '#{ns}'" do
        it 'should not contain user pods' do
          if user_pods.any?
            fail <<~MSG
              Found #{user_pods.length} potential user pod(s) in system namespace '#{ns}'.
              System namespaces should only contain Kubernetes system components.
              Review each pod to confirm whether it is a user application or legitimate system component.
              
              Potential user pods:
              #{user_pods.map { |p| "  - #{p.dig('metadata', 'name')}" }.join("\n")}
            MSG
          else
            expect(user_pods).to be_empty
          end
        end
      end
    end
  end

  # --- END CUSTOM CODE ---
end
