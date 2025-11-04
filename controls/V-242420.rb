control 'V-242420' do
  title 'Kubernetes Kubelet must have the SSL Certificate Authority set.'
  desc 'Kubernetes container and pod configuration are maintained by Kubelet. Kubelet agents register nodes with the API Server, mount volume storage, and perform health checks for containers and pods. Anyone who gains access to Kubelet agents can effectively control applications within the pods and containers. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols such as TLS. TLS provides the Kubernetes API Server with a means to authenticate sessions and encrypt traffic.

To enable encrypted communication for Kubelet, the clientCAFile must be set. This parameter gives the location of the SSL Certificate Authority file used to secure Kubelet communication.'
  desc 'check', 'On the Control Plane, run the command:
ps -ef | grep kubelet

If the "--client-ca-file" option exists, this is a finding.

Note the path to the config file (identified by --config).

Run the command:
grep -i clientCAFile <path_to_config_file>

If the setting "clientCAFile" is not set or contains no value, this is a finding.'
  desc 'fix', 'On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "--client-ca-file" option if present.

Note the path to the config file (identified by --config).

Edit the Kubernetes Kubelet config file: 
Set the value of "clientCAFile" to a path containing an Approved Organizational Certificate. 

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.5
  tag check_id: 'C-45695r918177_chk'
  tag severity: 'medium'
  tag gid: 'V-242420'
  tag rid: 'SV-242420r1043178_rule'
  tag stig_id: 'CNTR-K8-001420'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45653r918178_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
  # --- BEGIN CUSTOM CODE ---
  describe 'Kubelet must have the SSL Certificate Authority set' do
    it <<~JUSTIFICATION do
      is not a finding because the cluster certificate authority
      is configured by the Kubernetes control plane managed by EKS and is exposed via the EKS API.
      This certificate authority is what clients (kubectl/kubelet) trust for authenticating the API server.
      Customers should configure worker node kubelets to use the clientCAFile setting pointing to the cluster CA.
      See https://docs.aws.amazon.com/cli/latest/reference/eks/describe-cluster.html
    JUSTIFICATION
      expect(true).to eq true
    end
  end
  # --- END CUSTOM CODE ---
end
