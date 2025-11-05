# libraries/run_scope.rb
# Helper resource to gate controls by execution scope.
# Usage in controls:
#   only_if('cluster pass') { run_scope.cluster? }
#   only_if('node pass')    { run_scope.node? }

class StigRunScope < Inspec.resource(1)
  name 'run_scope'

  def initialize
    super
  end

  def cluster?
    scope_value.casecmp('cluster').zero?
  end

  def node?
    scope_value.casecmp('node').zero?
  end

  def to_s
    'run_scope helper'
  end

  private

  def scope_value
    # Access the input from the profile context
    @scope_value ||= begin
      # Try to find the input in the registry for this profile
      input_obj = Inspec::InputRegistry.find_or_register_input(
        'run_scope',
        'kubernetes-stig-baseline'
      )
      input_obj.value.to_s
    end
  end
end
