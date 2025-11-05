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
    get_config_value('authentication', 'x509', 'clientCAFile')
  end

  def kubeconfig
    @flags['kubeconfig']
  end

  private

  def discover_kubelet_process_command_line
    procs = inspec.processes('kubelet')
    cmds  = procs.commands&.reject { |c| c.to_s.empty? } || []

    cmds.map(&:to_s).map(&:strip).reject(&:empty?).first.to_s
  end

  def parse_command_line_flags(cmd)
    flags = {}
    return flags if cmd.to_s.empty?
    # Supports: --flag, --flag=value, --flag value
    cmd.scan(/--([A-Za-z0-9-]+)(?:=(\S+)|\s+(\S+))?/).each do |name, v1, v2|
      flags[name] = v1 || v2 || 'true'
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
