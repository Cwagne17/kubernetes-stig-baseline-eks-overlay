# frozen_string_literal: true
require 'aws-sdk-eks'

class AwsEksCluster < Inspec.resource(1)
  name 'aws_eks_cluster'
  supports platform: 'aws'
  desc 'Lookup an EKS cluster by name using aws-sdk-eks'

  def initialize(cluster_name)
    @cluster_name = cluster_name
    @exists = false
    @cluster = nil
    begin
      client = Aws::EKS::Client.new
      resp = client.describe_cluster(name: cluster_name)
      @cluster = resp.cluster
      @exists = !@cluster.nil?
    rescue Aws::EKS::Errors::ResourceNotFoundException
      @exists = false
    rescue StandardError => e
      fail_resource("aws_eks_cluster(#{cluster_name}) error: #{e.message}")
    end
  end
end
