# frozen_string_literal: true
require 'shellwords'

class KubectlClient < Inspec.resource(1)
  name 'kubectl_client'
  supports platform: 'unix'
  desc 'Execute kubectl commands and parse output (JSON preferred).'
  example <<~EX
    describe kubectl_client('get pods -A -o=json') do
      its('json') { should_not be_nil }
    end

    describe kubectl_client('get nodes -o=wide') do
      its('table.headers') { should include 'NAME' }
    end
  EX

  def initialize(cmd, kubeconfig: nil, context: nil, namespace: nil)
    @cmd = build_cmd(cmd, kubeconfig, context, namespace)
    @result = inspec.command(@cmd)
  end

  def stdout
    @result.stdout
  end

  def stderr
    @result.stderr
  end

  def exit_status
    @result.exit_status
  end

  def success?
    @result.exit_status == 0
  end

  def connectivity_error?
    # Check for common kubectl connectivity error patterns
    stderr.include?('Unable to connect to the server') ||
      stderr.include?('connection refused') ||
      stderr.include?('no such host') ||
      stderr.include?('dial tcp') ||
      stderr.include?('context deadline exceeded') ||
      stderr.include?('i/o timeout')
  end

  def error_message
    return nil if success?
    
    if connectivity_error?
      'Unable to connect to Kubernetes cluster. Verify cluster access and kubeconfig.'
    else
      stderr.strip
    end
  end

  def json
    begin
      require 'json'
      JSON.parse(@result.stdout)
    rescue JSON::ParserError
      nil
    end
  end

  def table
    # Simple tabular parser: first line is headers (split on whitespace),
    # remaining lines are rows
    lines = @result.stdout.lines.map(&:rstrip).reject(&:empty?)
    return { 'headers' => [], 'rows' => [] } if lines.empty?

    headers = lines.first.split(/\s+/)
    rows = lines[1..].map { |ln| ln.split(/\s+/, headers.length) }
    { 'headers' => headers, 'rows' => rows }
  end

  # Helper method to get all namespaces
  def self.get_namespaces(kubeconfig: nil, context: nil)
    client = new('get namespaces -o json', kubeconfig: kubeconfig, context: context)
    return [] unless client.success?
    
    client.json&.dig('items') || []
  end

  # Helper method to get resources of a specific type
  def self.get_resources(resource_type, namespace: nil, kubeconfig: nil, context: nil)
    cmd = "get #{resource_type} -o json"
    client = new(cmd, kubeconfig: kubeconfig, context: context, namespace: namespace)
    return [] unless client.success?
    
    client.json&.dig('items') || []
  end

  # Helper method to check if a resource exists
  def self.resource_exists?(resource_type, name, namespace: nil, kubeconfig: nil, context: nil)
    cmd = "get #{resource_type} #{name} --ignore-not-found -o name"
    client = new(cmd, kubeconfig: kubeconfig, context: context, namespace: namespace)
    client.success? && !client.stdout.strip.empty?
  end

  # Helper method to get pods using secrets as environment variables
  def self.get_pods_with_secret_env_vars(kubeconfig: nil, context: nil)
    pods = get_resources('pods', kubeconfig: kubeconfig, context: context)
    pods_with_secrets = []
    
    pods.each do |pod|
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
    
    pods_with_secrets
  end

  def to_s
    "kubectl_client(#{@cmd})"
  end

  private

  def build_cmd(cmd, kubeconfig, context, namespace)
    parts = ['kubectl']
    parts += ['--kubeconfig', Shellwords.escape(kubeconfig)] if kubeconfig
    parts += ['--context', Shellwords.escape(context)] if context
    parts += ['-n', Shellwords.escape(namespace)] if namespace
    parts << cmd
    parts.join(' ')
  end
end
