control 'V-242395' do
  title 'Kubernetes dashboard must not be enabled.'
  desc 'While the Kubernetes dashboard is not inherently insecure on its own, it is often coupled with a misconfiguration of Role-Based Access control (RBAC) permissions that can unintentionally over-grant access. It is not commonly protected with "NetworkPolicies", preventing all pods from being able to reach it. In increasingly rare circumstances, the Kubernetes dashboard is exposed publicly to the internet.'
  desc 'check', 'From the Control Plane, run the command:

kubectl get pods --all-namespaces -l k8s-app=kubernetes-dashboard

If any resources are returned, this is a finding.'
  desc 'fix', 'Delete the Kubernetes dashboard deployment with the following command:

kubectl delete deployment kubernetes-dashboard --namespace=kube-system'
  impact 0.5
  tag check_id: 'C-45670r863786_chk'
  tag severity: 'medium'
  tag gid: 'V-242395'
  tag rid: 'SV-242395r960792_rule'
  tag stig_id: 'CNTR-K8-000420'
  tag gtitle: 'SRG-APP-000033-CTR-000095'
  tag fix_id: 'F-45628r712540_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  # --- BEGIN CUSTOM CODE ---
  only_if('cluster pass') { run_scope.cluster? }

  # Check for Kubernetes dashboard pods
  dashboard_cmd = kubectl_client('get pods --all-namespaces -l k8s-app=kubernetes-dashboard -o json')
  
  if dashboard_cmd.success? && dashboard_cmd.json
    dashboard_pods = dashboard_cmd.json['items'] || []
    
    describe 'Kubernetes dashboard' do
      it 'should not be enabled' do
        expect(dashboard_pods).to be_empty, <<~MSG
          Found #{dashboard_pods.length} Kubernetes dashboard pod(s) running.
          The dashboard should be removed unless absolutely required.
          
          Dashboard pods:
          #{dashboard_pods.map { |p| "  - #{p.dig('metadata', 'name')} in namespace #{p.dig('metadata', 'namespace')}" }.join("\n")}
        MSG
      end
    end
  end

  # --- END CUSTOM CODE ---
end
