# frozen_string_literal: true
require 'aws-sdk-eks'

class AwsEksCluster < Inspec.resource(1)
  name 'aws_eks_cluster'
  supports platform: 'aws'
  desc 'Lookup an EKS cluster by name using aws-sdk-eks'
  example <<~EX
    describe aws_eks_cluster('my-eks') do
      it { should exist }
      its('version')  { should cmp >= '1.29' }
      its('status')   { should cmp 'ACTIVE' }
    end
  EX

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

  def exists?
    @exists
  end

  def to_s
    "aws_eks_cluster(#{@cluster_name})"
  end

  def arn
    @cluster&.arn
  end

  def version
    @cluster&.version
  end

  def status
    @cluster&.status
  end

  def endpoint
    @cluster&.endpoint
  end

  def logging
    @cluster&.logging
  end

  def created_at
    @cluster&.created_at
  end
end
