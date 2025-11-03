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
