control 'V-242425' do
  title 'Kubernetes Kubelet must enable tlsCertFile for client authentication to secure service.'
  desc 'Kubernetes container and pod configuration are maintained by Kubelet. Kubelet agents register nodes with the API Server, mount volume storage, and perform health checks for containers and pods. Anyone who gains access to Kubelet agents can effectively control applications within the pods and containers. Using authenticity protection, the communication can be protected against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

The communication session is protected by utilizing transport encryption protocols such as TLS. TLS provides the Kubernetes API Server with a means to authenticate sessions and encrypt traffic.

To enable encrypted communication for Kubelet, the parameter tlsCertFile must be set. This parameter gives the location of the SSL Certificate Authority file used to secure Kubelet communication.'
  desc 'check', 'On the Control Plane, run the command:
ps -ef | grep kubelet

If the argument for "--tls-cert-file" option exists, this is a finding. 

Note the path to the config file (identified by --config).

Run the command:
grep -i tlsCertFile <path_to_config_file>

If the setting "tlsCertFile" is not set or contains no value, this is a finding.'
  desc 'fix', 'On the Control Plane, run the command:
ps -ef | grep kubelet

Remove the "--tls-cert-file" option if present.

Note the path to the config file (identified by --config).

Edit the Kubernetes Kubelet config file: 
Set "tlsCertFile" to a path containing an Approved Organization Certificate. 

Restart the kubelet service using the following command:
systemctl daemon-reload && systemctl restart kubelet'
  impact 0.5
  tag check_id: 'C-45700r918183_chk'
  tag severity: 'medium'
  tag gid: 'V-242425'
  tag rid: 'SV-242425r1043178_rule'
  tag stig_id: 'CNTR-K8-001470'
  tag gtitle: 'SRG-APP-000219-CTR-000550'
  tag fix_id: 'F-45658r918184_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
  # --- BEGIN CUSTOM CODE ---

  # EKS Context: Kubelet TLS configuration is managed by AWS using serverTLSBootstrap.
  # EKS automatically configures kubelet with serverTLSBootstrap enabled, which allows
  # kubelet to automatically request and rotate its own serving certificates from the
  # Kubernetes CA without requiring static tlsCertFile configuration.
  
  describe 'Kubelet TLS certificate configuration' do
    it <<~JUSTIFICATION do
      is not a finding because EKS manages kubelet TLS certificates using serverTLSBootstrap.
      
      EKS kubelet is configured with serverTLSBootstrap enabled, which provides automatic
      certificate generation and rotation for kubelet serving certificates. This eliminates
      the need for static tlsPrivateKeyFile and tlsCertFile configuration.
      
      The kubelet automatically:
      - Requests a serving certificate from the Kubernetes CA
      - Uses the certificate for secure communication with the API Server
      - Rotates certificates before expiration
      
      Current kubelet configuration shows serverTLSBootstrap: #{kubelet.get_config_value('serverTLSBootstrap')}
      
      This approach is more secure than static certificate files as it enables automatic
      rotation and reduces the risk of expired certificates.
      
      See: https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/
    JUSTIFICATION
      expect(kubelet.get_config_value('serverTLSBootstrap')).to eq(true)
    end
  end

  # --- END CUSTOM CODE ---
end
