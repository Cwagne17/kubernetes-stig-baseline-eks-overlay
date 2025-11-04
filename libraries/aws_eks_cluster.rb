# frozen_string_literal: true
require 'aws-sdk-eks'

class AwsEksCluster < Inspec.resource(1)
  name 'aws_eks_cluster'
  supports platform: 'aws'
  supports platform: 'unix'
  desc 'Lookup an EKS cluster by name using aws-sdk-eks'

  attr_reader :cluster_name, :cluster

  def initialize(cluster_name)
    @cluster_name = cluster_name
    @exists = false
    @cluster = nil
    @client = nil
    begin
      @client = Aws::EKS::Client.new
      resp = @client.describe_cluster(name: cluster_name)
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

  # Cluster version
  def version
    return nil unless exists?
    @cluster.version
  end

  # Encryption configuration for secrets
  def encryption_config
    return nil unless exists?
    @cluster.encryption_config
  end

  def secrets_encrypted?
    return false unless exists?
    return false if encryption_config.nil? || encryption_config.empty?
    
    # Check if any encryption config has 'secrets' as a resource
    encryption_config.any? do |config|
      config.resources&.include?('secrets')
    end
  end

  # Audit logging configuration
  def logging
    return nil unless exists?
    @cluster.logging
  end

  def audit_logging_enabled?
    return false unless exists?
    return false if logging.nil?
    
    enabled_types = logging.cluster_logging&.select { |log| log.enabled }&.flat_map(&:types) || []
    enabled_types.include?('audit')
  end

  def enabled_log_types
    return [] unless exists?
    return [] if logging.nil?
    
    logging.cluster_logging&.select { |log| log.enabled }&.flat_map(&:types) || []
  end

  # EKS Add-ons
  def addons
    return [] unless exists?
    return @addons if defined?(@addons)
    
    begin
      resp = @client.list_addons(cluster_name: @cluster_name)
      @addons = resp.addons || []
    rescue StandardError => e
      fail_resource("Failed to list add-ons: #{e.message}")
      @addons = []
    end
    @addons
  end

  def addon_info(addon_name)
    return nil unless exists?
    return nil unless addons.include?(addon_name)
    
    begin
      resp = @client.describe_addon(
        cluster_name: @cluster_name,
        addon_name: addon_name
      )
      resp.addon
    rescue StandardError => e
      fail_resource("Failed to describe add-on #{addon_name}: #{e.message}")
      nil
    end
  end

  def addon_active?(addon_name)
    info = addon_info(addon_name)
    return false if info.nil?
    info.status == 'ACTIVE'
  end

  # OIDC provider for IRSA
  def oidc_provider
    return nil unless exists?
    @cluster.identity&.oidc&.issuer
  end

  # Cluster endpoint
  def endpoint
    return nil unless exists?
    @cluster.endpoint
  end

  # VPC configuration
  def vpc_id
    return nil unless exists?
    @cluster.resources_vpc_config&.vpc_id
  end

  def subnet_ids
    return [] unless exists?
    @cluster.resources_vpc_config&.subnet_ids || []
  end

  def security_group_ids
    return [] unless exists?
    @cluster.resources_vpc_config&.security_group_ids || []
  end

  def endpoint_public_access
    return nil unless exists?
    @cluster.resources_vpc_config&.endpoint_public_access
  end

  def endpoint_private_access
    return nil unless exists?
    @cluster.resources_vpc_config&.endpoint_private_access
  end
end
