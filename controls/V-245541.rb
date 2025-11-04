control 'V-245541' do
  title 'Kubernetes Kubelet must not disable timeouts.'
  desc 'Idle connections from the Kubelet can be used by unauthorized users to perform malicious activity to the nodes, pods, containers, and cluster within the Kubernetes Control Plane. Setting the streamingConnectionIdleTimeout defines the maximum time an idle session is permitted prior to disconnect. Setting the value to "0" never disconnects any idle sessions. Idle timeouts must never be set to "0" and should be defined at "5m" (the default is 4hr).'
  desc 'check', 'Follow these steps to check streaming-connection-idle-timeout:

1. On the Control Plane, run the command:

ps -ef | grep kubelet

If the "--streaming-connection-idle-timeout" option exists, this is a finding.

Note the path to the config file (identified by --config).

2. Run the command:

grep -i streamingConnectionIdleTimeout <path_to_config_file>

If the setting "streamingConnectionIdleTimeout" is set to less than "5m" or is not configured, this is a finding.'
  desc 'fix', 'Follow these steps to configure streaming-connection-idle-timeout:
1. On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "--streaming-connection-idle-timeout" option if present.

Note the path to the config file (identified by --config).

2. Edit the Kubernetes Kubelet file in the --config directory on the Kubernetes Control Plane:

Set the argument "streamingConnectionIdleTimeout" to a value of "5m".'
  impact 0.5
  tag check_id: 'C-48816r1069467_chk'
  tag severity: 'medium'
  tag gid: 'V-245541'
  tag rid: 'SV-245541r1069469_rule'
  tag stig_id: 'CNTR-K8-001300'
  tag gtitle: 'SRG-APP-000190-CTR-000500'
  tag fix_id: 'F-48771r1069468_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
  # --- BEGIN CUSTOM CODE ---

  # EKS Context: This check applies to Worker Nodes.
  # The streamingConnectionIdleTimeout controls how long idle streaming connections
  # (exec, attach, port-forward) remain open before being terminated.
  
  kl = kubelet
  streaming_timeout = kl.get_config_value('streamingConnectionIdleTimeout')

  describe 'Kubelet --streaming-connection-idle-timeout command-line flag' do
    it 'should not be present on Worker Nodes' do
      expect(kl.flags.key?('streaming-connection-idle-timeout')).to eq(false), <<~MSG
        The --streaming-connection-idle-timeout command-line flag was found on the kubelet process.
        Current value: #{kl.flags['streaming-connection-idle-timeout']}
      MSG
    end
  end

  describe 'Kubelet config streamingConnectionIdleTimeout' do
    it 'should be configured and set to 5m or greater' do
      # Must not be nil
      expect(streaming_timeout).not_to be_nil, <<~MSG
        The streamingConnectionIdleTimeout must be explicitly configured in the kubelet configuration.
        Config path: #{kl.config_path}
        Current value: nil
        Required: "5m" or greater (e.g., "10m", "1h")
      MSG
      
      # Parse duration string (e.g., "5m", "10m", "1h", "4h")
      duration_match = streaming_timeout.to_s.match(/^(\d+)(h|m|s)$/)
      
      if duration_match.nil?
        skip "Unable to parse streamingConnectionIdleTimeout value: #{streaming_timeout.inspect}"
      end
      
      value = duration_match[1].to_i
      unit = duration_match[2]
      
      # Convert to minutes
      minutes = case unit
               when 'h' then value * 60
               when 'm' then value
               when 's' then value / 60.0
               end
      
      # Must be 5m or greater
      expect(minutes).to be >= 5, <<~MSG
        The streamingConnectionIdleTimeout must be set to at least 5 minutes to prevent indefinite idle connections.
        Config path: #{kl.config_path}
        Current value: #{streaming_timeout.inspect} (#{minutes} minutes)
        Required: "5m" or greater
      MSG
    end
  end

  # --- END CUSTOM CODE ---
end
