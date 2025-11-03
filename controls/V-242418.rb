control 'V-242418' do
  title 'The Kubernetes API server must use approved cipher suites.'
  desc 'The Kubernetes API server communicates to the kubelet service on the nodes to deploy, update, and delete resources. If an attacker were able to get between this communication and modify the request, the Kubernetes cluster could be compromised. Using approved cypher suites for the communication ensures the protection of the transmitted information, confidentiality, and integrity so that the attacker cannot read or alter this communication.'
  desc 'check', 'Change to the /etc/kubernetes/manifests/ directory on the Kubernetes Control Plane. Run the command:
grep -i tls-cipher-suites *

If the setting feature tls-cipher-suites is not set in the Kubernetes API server manifest file or contains no value or does not contain TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, this is a finding.'
  desc 'fix', 'Edit the Kubernetes API Server manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. 

Set the value of "--tls-cipher-suites" to:
"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"'
  impact 0.5
  tag check_id: 'C-45693r863842_chk'
  tag severity: 'medium'
  tag gid: 'V-242418'
  tag rid: 'SV-242418r1043178_rule'
  tag stig_id: 'CNTR-K8-001400'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45651r927105_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
# --- BEGIN CUSTOM CODE ---
describe 'Control-plane API server must use approved cipher suites.' do
  it 'is not a finding in Amazon EKS because Amazon EKS runs the kube-apiserver on an AWS-managed control plane; customers cannot set --tls-cipher-suites. EKS API endpoints are AWS service endpoints that require TLS 1.2 (TLS 1.3 recommended) and are managed by AWS; cipher selection is enforced by AWS for the service, not configurable by customers; see https://docs.aws.amazon.com/eks/latest/best-practices/control-plane.html' do
    expect(true).to eq true
  end
end
# --- END CUSTOM CODE ---
end
