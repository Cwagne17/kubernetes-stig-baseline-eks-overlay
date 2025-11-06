class Kubelet < Inspec.resource(1)
  name 'kubelet'

  def initialize
    @os = inspec.os
    @cmdline = discover_kubelet_process_command_line
    @flags = parse_command_line_flags(@cmdline)
    @cfg_path = discover_config_file_path
    @cfg = read_config_file(@cfg_path)
  end

  def cmdline
    @cmdline
  end

  def flags
    @flags
  end

  def config_path
    @cfg_path
  end

  # Hash from json/yaml resource
  def config
    @cfg
  end

  # Convenience: nested lookup (keys can be strings or symbols)
  def get_config_value(*path)
    cur = @cfg
    path.flatten.each do |k|
      return nil unless cur.is_a?(Hash)
      cur = cur[k] || cur[k.to_s]
    end
    cur
  end

  # Convenience methods for common file paths
  def config_file
    @cfg_path
  end

  def ca_file
    path = get_config_value('authentication', 'x509', 'clientCAFile')
    # normalize slashes on Windows
    @os.windows? ? normalize_windows_path(path) : path
  end

  def kubeconfig
    path = @flags['kubeconfig']

    # normalize slashes on Windows
    @os.windows? ? normalize_windows_path(path) : path
  end

  private

  def discover_kubelet_process_command_line
    if @os.windows?
      # On Windows, use PowerShell to get the full command line with arguments
      # inspec.processes uses Get-Process which only returns the path, not the arguments
      cmd = inspec.command('(Get-WmiObject Win32_Process -Filter "name=\'kubelet.exe\'").CommandLine')
      return '' unless cmd.exit_status == 0
      cmd.stdout.to_s.strip
    else
      procs = inspec.processes('kubelet')
      cmds  = procs.commands&.reject { |c| c.to_s.empty? } || []
      cmds.map(&:to_s).map(&:strip).reject(&:empty?).first.to_s
    end
  end

  def parse_command_line_flags(cmd)
    flags = {}
    return flags if cmd.to_s.empty?
    
    # Normalize line breaks and extra whitespace that can appear in Windows output
    normalized_cmd = cmd.to_s.gsub(/\r?\n/, ' ').gsub(/\s+/, ' ').strip
    
    # Supports: --flag, --flag=value, --flag value
    normalized_cmd.scan(/--([A-Za-z0-9-]+)(?:=([^\s"]+|"[^"]*")|\s+([^\s"]+|"[^"]*"))?/).each do |name, v1, v2|
      value = (v1 || v2 || 'true').to_s.gsub(/^"|"$/, '')
      flags[name] = value
    end
    flags
  end

  def discover_config_file_path
    path =
      @flags['config'] ||
      get_default_config_file_paths.find { |p| config_file_exists?(p) }
    # normalize slashes on Windows
    @os.windows? ? normalize_windows_path(path) : path
  end

  def read_config_file(path)
    return {} unless config_file_exists?(path)
    inspec.json(path).params || {}
  end

  def get_default_config_file_paths
    if @os.windows?
      [
        'C:\\ProgramData\\kubernetes\\kubelet-config.json',
        'C:\\etc\\kubernetes\\kubelet\\config.json',
        'C:\\var\\lib\\kubelet\\config.yaml'
      ]
    else
      [
        '/etc/kubernetes/kubelet/config.json',
        '/var/lib/kubelet/config.yaml'
      ]
    end
  end

  def config_file_exists?(path)
    path && inspec.file(path).exist? && inspec.file(path).size > 0
  end

  def normalize_windows_path(path)
    return nil if path.nil?
    path.to_s.tr('/', '\\').gsub('"','').gsub("'",'')
  end
end

def kubelet
  Kubelet.new
end
