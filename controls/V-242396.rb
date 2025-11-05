control 'V-242396' do
  title 'Kubernetes Kubectl cp command must give expected access and results.'
  desc 'One of the tools heavily used to interact with containers in the Kubernetes cluster is kubectl. The command is the tool System Administrators used to create, modify, and delete resources. One of the capabilities of the tool is to copy files to and from running containers (i.e., kubectl cp). The command uses the "tar" command of the container to copy files from the container to the host executing the "kubectl cp" command. If the "tar" command on the container has been replaced by a malicious user, the command can copy files anywhere on the host machine. This flaw has been fixed in later versions of the tool. It is recommended to use kubectl versions newer than 1.12.9.'
  desc 'check', 'From the Control Plane and each Worker node, check the version of kubectl by executing the command:

kubectl version --client

If the Control Plane or any Worker nodes are not using kubectl version 1.12.9 or newer, this is a finding.'
  desc 'fix', 'Upgrade the Control Plane and Worker nodes to the latest version of kubectl.'
  impact 0.5
  tag check_id: 'C-45671r863788_chk'
  tag severity: 'medium'
  tag gid: 'V-242396'
  tag rid: 'SV-242396r960792_rule'
  tag stig_id: 'CNTR-K8-000430'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag fix_id: 'F-45629r863789_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  # --- BEGIN CUSTOM CODE ---
  only_if('node pass') { run_scope.node? }

  # EKS Context: kubectl is typically not installed on Worker Nodes.
  # It's installed on Control Plane nodes (managed by AWS) or administrative workstations.
  
  # Check if kubectl is installed
  kubectl_path = command('which kubectl').stdout.strip
  
  unless command('which kubectl').exit_status == 0
    describe 'kubectl installation' do
      it <<~JUSTIFICATION do
        is not a finding because kubectl is not installed on this Worker Node.
        EKS Worker Nodes do not require kubectl installation as they run the kubelet agent
        to communicate with the Control Plane. kubectl is typically only installed on
        administrative workstations or bastion hosts used to manage the cluster.
        See https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html
      JUSTIFICATION
        expect(true).to eq true
      end
    end
    next
  end

  # If kubectl is installed, check the version
  kubectl_version_output = command('kubectl version --client -o json 2>/dev/null || kubectl version --client --short 2>/dev/null').stdout
  
  # Try to parse version from output
  if kubectl_version_output =~ /"gitVersion":\s*"v?(\d+\.\d+\.\d+)"/
    version_string = Regexp.last_match(1)
  elsif kubectl_version_output =~ /Client Version:\s*v?(\d+\.\d+\.\d+)/
    version_string = Regexp.last_match(1)
  else
    version_string = nil
  end

  describe 'kubectl version' do
    it 'should be 1.12.9 or newer' do
      skip 'Unable to determine kubectl version from output' if version_string.nil?
      
      version_parts = version_string.split('.').map(&:to_i)
      major, minor, patch = version_parts
      
      # Check if version is >= 1.12.9
      is_compliant = (major > 1) ||
                     (major == 1 && minor > 12) ||
                     (major == 1 && minor == 12 && patch >= 9)
      
      expect(is_compliant).to eq(true), <<~MSG
        kubectl version must be 1.12.9 or newer to prevent vulnerabilities in the 'kubectl cp' command.
        Current version: #{version_string}
        Minimum required: 1.12.9
        kubectl path: #{kubectl_path}
      MSG
    end
  end

  # --- END CUSTOM CODE ---
end
