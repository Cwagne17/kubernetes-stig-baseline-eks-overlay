control 'V-242408' do
  title 'The Kubernetes manifest files must have least privileges.'
  desc 'The manifest files contain the runtime configuration of the API server, scheduler, controller, and etcd. If an attacker can gain access to these files, changes can be made to open vulnerabilities and bypass user authorizations inherent within Kubernetes with RBAC implemented.

'
  desc 'check', 'On both Control Plane and Worker Nodes, change to the /etc/kubernetes/manifest directory. Run the command:
ls -l *

Each manifest file must have permissions "644" or more restrictive.

If any manifest file is less restrictive than "644", this is a finding.'
  desc 'fix', 'On both Control Plane and Worker Nodes, change to the /etc/kubernetes/manifest directory. Run the command:
chmod 644 *

To verify the change took place, run the command:
ls -l *

All the manifest files should now have privileges of "644".'
  impact 0.5
  tag check_id: 'C-45683r918172_chk'
  tag severity: 'medium'
  tag gid: 'V-242408'
  tag rid: 'SV-242408r960960_rule'
  tag stig_id: 'CNTR-K8-000900'
  tag gtitle: 'SRG-APP-000133-CTR-000310'
  tag fix_id: 'F-45641r918173_fix'
  tag satisfies: ['SRG-APP-000133-CTR-000310', 'SRG-APP-000133-CTR-000295', 'SRG-APP-000516-CTR-001335']
  tag 'documentable'
  tag cci: ['CCI-001499', 'CCI-000366']
  tag nist: ['CM-5 (6)', 'CM-6 b']
  # --- BEGIN CUSTOM CODE ---
  only_if('node pass') { run_scope.node? }

  # EKS Context: This check applies to both Control Plane and Worker Nodes.
  # On EKS Worker Nodes, the /etc/kubernetes/manifests directory typically does not exist
  # as static pods are not used. This is the expected and secure configuration.
  
  manifest_dir = '/etc/kubernetes/manifests'

  # If directory doesn't exist, this is expected for EKS Worker Nodes (not a finding)
  unless file(manifest_dir).exist?
    describe 'Manifest directory compliance' do
      it <<~JUSTIFICATION do
        is not a finding because the /etc/kubernetes/manifests directory does not exist.
        This is the expected and secure configuration for EKS Worker Nodes.
        EKS Worker Nodes do not use static pods, which helps ensure all pods are properly
        governed by the API Server and subject to admission control policies.
      JUSTIFICATION
        expect(true).to eq true
      end
    end
    next
  end

  # Get all files in the manifest directory
  manifest_files = command("find #{manifest_dir} -maxdepth 1 -type f").stdout.split("\n").reject(&:empty?)
  
  # If directory exists but is empty, this is also expected (not a finding)
  if manifest_files.empty?
    describe 'Manifest directory compliance' do
      it <<~JUSTIFICATION do
        is not a finding because the /etc/kubernetes/manifests directory exists but contains no manifest files.
        This is the expected configuration for EKS Worker Nodes where static pods are not used.
        Static pods on Worker Nodes would bypass API Server admission control and are not recommended.
      JUSTIFICATION
        expect(true).to eq true
      end
    end
    next
  end

  # If manifest files exist, check their permissions
  manifest_files.each do |manifest_file|
    manifest = file(manifest_file)
    
    describe "Manifest file #{manifest_file}" do
      it 'must exist' do
        expect(manifest).to exist
      end

      if os.windows?
        it 'must have secure Windows ACLs' do
          expect(manifest.user_permissions).to eq(
            'NT AUTHORITY\\SYSTEM' => 'FullControl',
            'BUILTIN\\Administrators' => 'FullControl',
            'BUILTIN\\Users' => 'ReadAndExecute, Synchronize'
          )
        end
      else
        it 'must have Unix permissions of 0644 or more restrictive' do
          expect(manifest).not_to be_more_permissive_than('0644')
        end
      end
    end
  end

  # --- END CUSTOM CODE ---
end
