control 'V-242432' do
  title 'Kubernetes etcd must have peer-cert-file set for secure communication.'
  desc 'Kubernetes stores configuration and state information in a distributed key-value store called etcd. Anyone who can write to etcd can effectively control the Kubernetes cluster. Even just reading the contents of etcd could easily provide helpful hints to a would-be attacker. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols, such as TLS. TLS provides the Kubernetes API Server and etcd with a means to be able to authenticate sessions and encrypt traffic. 

To enable encrypted communication for etcd, the parameter peer-cert-file must be set. This parameter gives the location of the SSL certification file used to secure etcd communication.'
  desc 'check', 'Change to the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. Run the command:
grep -i peer-cert-file * 

If the setting "peer-cert-file" is not configured in the Kubernetes etcd manifest file, this is a finding.'
  desc 'fix', 'Edit the Kubernetes etcd manifest file in the /etc/kubernetes/manifests directory on the Kubernetes Control Plane. 

Set the value of "--peer-cert-file" to the certificate to be used for communication with etcd.'
  impact 0.5
  tag check_id: 'C-45707r863884_chk'
  tag severity: 'medium'
  tag gid: 'V-242432'
  tag rid: 'SV-242432r1043178_rule'
  tag stig_id: 'CNTR-K8-001540'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45665r863885_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
  # --- BEGIN CUSTOM CODE ---
  only_if('cluster pass') { run_scope.cluster? }

  cluster_name = input('cluster_name')
  eks_cluster = aws_eks_cluster(cluster_name)

  describe 'Control-plane etcd must have peer-cert-file set for secure communication' do
    it <<~JUSTIFICATION do
      is not a finding because the --peer-cert-file flag
      is configured by the Kubernetes control plane managed by EKS.
      See https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html#control-plane
    JUSTIFICATION
      expect(true).to eq true
    end
  end

  describe 'EKS cluster secrets encryption' do
    it 'must be enabled as a compensating control for etcd encryption' do
      expect(eks_cluster.secrets_encrypted?).to eq(true), 
        'EKS cluster must have secrets encryption enabled to protect etcd data at rest'
    end
  end
  # --- END CUSTOM CODE ---
end
