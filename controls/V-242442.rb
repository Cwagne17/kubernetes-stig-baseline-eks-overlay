control 'V-242442' do
  title 'Kubernetes must remove old components after updated versions have been installed.'
  desc 'Previous versions of Kubernetes components that are not removed after updates have been installed may be exploited by adversaries by allowing the vulnerabilities to still exist within the cluster. It is important for Kubernetes to remove old pods when newer pods are created using new images to always be at the desired security state.'
  desc 'check', %q(To view all pods and the images used to create the pods, from the Control Plane, run the following command:
kubectl get pods --all-namespaces -o jsonpath="{..image}" | \
tr -s '[[:space:]]' '\n' | \
sort | \
uniq -c

Review the images used for pods running within Kubernetes.

If there are multiple versions of the same image, this is a finding.)
  desc 'fix', 'Remove any old pods that are using older images. On the Control Plane, run the command:
kubectl delete pod podname
(Note: "podname" is the name of the pod to delete.)'
  impact 0.5
  tag check_id: 'C-45717r863905_chk'
  tag severity: 'medium'
  tag gid: 'V-242442'
  tag rid: 'SV-242442r961677_rule'
  tag stig_id: 'CNTR-K8-002700'
  tag gtitle: 'SRG-APP-000454-CTR-001110'
  tag fix_id: 'F-45675r863906_fix'
  tag 'documentable'
  tag cci: ['CCI-002647']
  tag nist: ['SI-4 d']
  # --- BEGIN CUSTOM CODE ---

  # Get all pod images across all namespaces
  pods_cmd = kubectl_client('get pods --all-namespaces -o json')
  
  if pods_cmd.success? && pods_cmd.json
    all_pods = pods_cmd.json['items'] || []
    
    # Extract all images used
    images = []
    all_pods.each do |pod|
      containers = pod.dig('spec', 'containers') || []
      containers.each do |container|
        images << container['image'] if container['image']
      end
      
      init_containers = pod.dig('spec', 'initContainers') || []
      init_containers.each do |container|
        images << container['image'] if container['image']
      end
    end
    
    # Group images by base name (without tag/digest)
    image_groups = {}
    images.each do |image|
      # Parse image to get base name (repo/name without tag)
      base = image.split(':').first.split('@').first
      image_groups[base] ||= []
      image_groups[base] << image unless image_groups[base].include?(image)
    end
    
    # Find images with multiple versions
    images_with_multiple_versions = image_groups.select { |_, versions| versions.length > 1 }
    
    describe 'Container images' do
      it 'should not have multiple versions of the same image deployed' do
        expect(images_with_multiple_versions).to be_empty, <<~MSG
          Found #{images_with_multiple_versions.length} image(s) with multiple versions deployed.
          Old pods have not been removed after updates.

          Images with multiple versions:
          #{images_with_multiple_versions.map { |base, versions|
            "  - #{base}:\n" + versions.map { |v| "      #{v}" }.join("\n")
          }.join("\n")}
        MSG
      end
    end
  end

  # --- END CUSTOM CODE ---
end
