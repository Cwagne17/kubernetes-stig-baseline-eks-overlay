control 'V-242415' do
  title 'Secrets in Kubernetes must not be stored as environment variables.'
  desc 'Secrets, such as passwords, keys, tokens, and certificates must not be stored as environment variables. These environment variables are accessible inside Kubernetes by the "Get Pod" API call, and by any system, such as CI/CD pipeline, which has access to the definition file of the container. Secrets must be mounted from files or stored within password vaults.'
  desc 'check', 'Follow these steps to check, from the Kubernetes control plane, if secrets are stored as environment variables.

1. Find All Pods Using Secrets in Environment Variables.

To list all pods using secrets as environment variables, execute:

kubectl get pods --all-namespaces -o yaml | grep -A5 "secretKeyRef"

If any of the values returned reference environment variables, this is a finding.

2. Check Environment Variables in a Specific Pod.

To check if a specific pod is using secrets as environment variables, execute:

kubectl get pods -n <namespace>
(Replace <namespace> with the actual namespace, or omit -n <namespace> to check in the default namespace.)
kubectl describe pod <pod-name> -n <namespace> | grep -A5 "Environment:"

If secrets are used, output like the following will be displayed:

Environment:
  SECRET_USERNAME:   <set from secret: my-secret key: username>
  SECRET_PASSWORD:   <set from secret: my-secret key: password>

If the output is similar to this, the pod is using Kubernetes secrets as environment variables, and this is a finding.

3. Check the Pod YAML for Secret Usage.

To check the full YAML definition for environment variables, execute:

kubectl get pod <pod-name> -n <namespace> -o yaml | grep -A5 "env:"

Example output:
yaml
CopyEdit
env:
  - name: SECRET_USERNAME
    valueFrom:
      secretKeyRef:
        name: my-secret
        key: username

This means the pod is pulling the secret named my-secret and setting SECRET_USERNAME from its username key.

If the pod is pulling a secret and setting an environment variable in the "env:", this is a finding.

4. Check Secrets in a Deployment, StatefulSet, or DaemonSet.

If the pod is managed by a Deployment, StatefulSet, or DaemonSet, check their configurations:

kubectl get deployment <deployment-name> -n <namespace> -o yaml | grep -A5 "env:"

or

For all Deployments in all namespaces:

kubectl get deployments --all-namespaces -o yaml | grep -A5 "env:"

If the pod is pulling a secret and setting an environment variable in the "env:", this is a finding.

5. Check Environment Variables Inside a Running Pod.

If needed, check the environment variables inside a running pod:

kubectl exec -it <pod-name> -n <namespace> -- env | grep SECRET

If any of the values returned reference environment variables, this is a finding.'
  desc 'fix', 'Any secrets stored as environment variables must be moved to the secret files with the proper protections and enforcements or placed within a password vault.'
  impact 0.7
  tag check_id: 'C-45690r1069465_chk'
  tag severity: 'high'
  tag gid: 'V-242415'
  tag rid: 'SV-242415r1069466_rule'
  tag stig_id: 'CNTR-K8-001160'
  tag gtitle: 'SRG-APP-000171-CTR-000435'
  tag fix_id: 'F-45648r712600_fix'
  tag 'documentable'
  tag cci: ['CCI-004062', 'CCI-000196']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (c)']
  # --- BEGIN CUSTOM CODE ---
  only_if('cluster pass') { run_scope.cluster? }

  # Get all pods and check for secrets in environment variables
  pods_cmd = kubectl_client('get pods --all-namespaces -o json')
  
  if pods_cmd.success? && pods_cmd.json
    all_pods = pods_cmd.json['items'] || []
    
    pods_with_secrets = []
    all_pods.each do |pod|
      pod_name = pod.dig('metadata', 'name')
      pod_namespace = pod.dig('metadata', 'namespace')
      containers = pod.dig('spec', 'containers') || []
      
      containers.each do |container|
        env_vars = container['env'] || []
        env_from = container['envFrom'] || []
        
        has_secret_env = env_vars.any? do |env|
          env.key?('valueFrom') && env['valueFrom'].key?('secretKeyRef')
        end
        
        has_secret_env_from = env_from.any? { |ef| ef.key?('secretRef') }
        
        if has_secret_env || has_secret_env_from
          pods_with_secrets << {
            name: pod_name,
            namespace: pod_namespace,
            container: container['name']
          }
        end
      end
    end
  end
  
  describe 'Secrets stored as environment variables' do
    if pods_cmd.success? && pods_cmd.json
      it 'should not be used in any pods' do
        expect(pods_with_secrets).to be_empty, <<~MSG
          Found #{pods_with_secrets.length} pod(s) using Secrets as environment variables.
          Secrets should be mounted as files, not environment variables.
          
          Pods with secret environment variables:
          #{pods_with_secrets.map { |p| "  - Pod: #{p[:name]} (namespace: #{p[:namespace]}, container: #{p[:container]})" }.join("\n")}
        MSG
      end
    end
  end
  # --- END CUSTOM CODE ---
end
