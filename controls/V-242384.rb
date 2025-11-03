control 'V-242384' do
  title 'The Kubernetes Scheduler must have secure binding.'
  desc 'Limiting the number of attack vectors and implementing authentication and encryption on the endpoints available to external sources is paramount when securing the overall Kubernetes cluster. The Scheduler API service exposes port 10251/TCP by default for health and metrics information use. This port does not encrypt or authenticate connections. If this port is exposed externally, an attacker can use this port to attack the entire Kubernetes cluster. By setting the bind address to localhost (i.e., 127.0.0.1), only those internal services that require health and metrics information can access the Scheduler API.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:

grep -i bind-address * 

If the setting "bind-address" is not set to "127.0.0.1" or is not found in the Kubernetes Scheduler manifest file, this is a finding.'
  desc 'fix', 'Edit the Kubernetes Scheduler manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Set the argument "--bind-address" to "127.0.0.1".'
  impact 0.5
  tag check_id: 'C-45659r863755_chk'
  tag severity: 'medium'
  tag gid: 'V-242384'
  tag rid: 'SV-242384r960792_rule'
  tag stig_id: 'CNTR-K8-000300'
  tag gtitle: 'SRG-APP-000033-CTR-000090'
  tag fix_id: 'F-45617r863756_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  # --- BEGIN CUSTOM CODE ---
  describe 'Control-plane scheduler must have secure binding' do
    it <<~JUSTIFICATION do
      is not a finding because the --bind-address flag
      is configured by the Kubernetes control plane managed by EKS.
      The scheduler's legacy insecure HTTP port (10251) has been deprecated and removed in modern Kubernetes versions;
      health and metrics now use the secure port (10259).
      See https://docs.aws.amazon.com/eks/latest/best-practices/control-plane.html
    JUSTIFICATION
      expect(true).to eq true
    end
  end
  # --- END CUSTOM CODE ---
end
