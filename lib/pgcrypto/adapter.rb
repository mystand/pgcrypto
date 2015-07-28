require 'pgcrypto'
require 'pgcrypto/crypt'
require 'pgcrypto/manipulation'

module PGCrypto
  def self.build_adapter!
    Class.new(PGCrypto.base_adapter) do
      include PGCrypto::AdapterMethods
    end
  end

  def self.rebuild_adapter!
    remove_const(:Adapter) if const_defined? :Adapter
    const_set(:Adapter, build_adapter!)
  end

  module AdapterMethods
    ADAPTER_NAME = 'PGCrypto'

    def quote(*args, &block)
      if args.first.is_a?(Arel::Nodes::SqlLiteral)
        args.first
      else
        super
      end
    end

    def to_sql(arel, binds = [], *args)
      a, b = PGCrypto::Manipulation.process_arel( arel, binds )
      super( a, b, *args)
    end

    # Uncomment this next method if you want some helpful debug output during development:
    # def exec_query(*args)
    #   unless args[1].try(:strip).try(:downcase) == 'schema' || !$pgcrypto_debug
    #     puts
    #     puts " ------------------ #{args[1]}: #{args[0].inspect}"
    #     puts
    #   end
    #   super(*args)
    # end

  end

  Adapter = build_adapter!

end
