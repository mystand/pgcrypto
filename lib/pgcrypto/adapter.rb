require 'pgcrypto'
require 'pgcrypto/crypt'

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
      case arel
      when Arel::InsertManager
        pgcrypto_insert(arel, binds)
      when Arel::SelectManager
        pgcrypto_select(arel, binds)
      when Arel::UpdateManager
        pgcrypto_update(arel, binds)
      end
      super(arel, binds, *args)
    end

    # Uncomment this next method if you want some helpful debug output during development:
    # def exec_query(*args)
    #   unless args[1].try(:strip).try(:downcase) == 'schema'
    #     puts
    #     puts " ------------------ #{args[1]}: #{args[0].inspect}"
    #     puts
    #   end
    #   super(*args)
    # end

    private

    def pgcrypto_insert(arel, binds = [])
      if table = PGCrypto[arel.ast.relation.name.to_s]
        arel.ast.columns.each_with_index do |column, i|
          if options = table[column.name.to_sym]
            next unless (key = PGCrypto.keys.public_key( options ))
            expr = arel.ast.values.expressions[i]
            case expr
            when nil
              expr = null_literal
            when Arel::Nodes::BindParam
              if chosen_bind = binds.detect{ |b| b.first.name == column.name }
                expr = chosen_bind.last.nil? ? null_literal : PGCrypto::Crypt.encrypt_string( chosen_bind.last, key, self )
                binds.delete( chosen_bind )
              else
                raise "Could not find binding for column #{column.name}!"
              end
            when String
              expr = PGCrypto::Crypt.encrypt_string( expr, key, self )
            else
              raise "Unknown node class presented to pgcrypto_insert: #{expr.class.to_s}!"
            end
            arel.ast.values.expressions[i] = expr

          end
        end
      end
    end

    def pgcrypto_select(arel, binds = [])
      # We start by looping through each "core," which is just a
      # SelectStatement and correcting plain-text queries against an encrypted
      # column...
      arel.ast.cores.each do |core|
        next unless core.is_a?(Arel::Nodes::SelectCore)

        pgcrypto_translate_selects(core, core.projections) if core.projections
        pgcrypto_translate_selects(core, core.having) if core.having

        # Loop through each WHERE to determine whether or not we need to refer
        # to its decrypted counterpart
        pgcrypto_translate_wheres_for_select(core)
      end
    end

    def pgcrypto_update(arel, binds = [])
      table_name = arel.ast.relation.name.to_s
      if columns = PGCrypto[table_name]
        # Find all columns with encryption instructions and encrypt them
        arel.ast.values.each do |value|
          if value.respond_to?(:left) && options = columns[column_name = value.left.name]
            next unless (key = PGCrypto.keys.public_key( options ))
            case value.right
            when nil
              value.right = null_literal
            when Arel::Nodes::BindParam
              if chosen_bind = binds.detect{ |b| b.first.name == column_name }
                value.right = chosen_bind.last.nil? ? null_literal : PGCrypto::Crypt.encrypt_string( chosen_bind.last, key, self )
                binds.delete( chosen_bind )
              else
                raise "Could not find binding for column #{column_name}!"
              end
            when String
              value.right = PGCrypto::Crypt.encrypt_string( value.right, key, self )
            else
              raise "Unknown node class presented to pgcrypto_update: #{value.class.to_s}!"
            end

          end
        end
        # Find any where clauses that refer to encrypted columns and correct them
        arel.ast.wheres.each do |where|
          pgcrypto_translate_where( where, table_name, columns )
        end
      end
    end

    def pgcrypto_translate_selects(core, selects)
      table_name = core.source.left.name
      columns = PGCrypto[table_name]
      return if columns.empty?

      untouched_columns = columns.keys.map(&:to_s)

      selects.each_with_index do |select, i|
        next unless select.respond_to?(:name)

        select_name = select.name.to_s
        if untouched_columns.include?(select_name)
          next unless (key = PGCrypto.keys.private_key(columns[select_name.to_sym]))
          decrypt = PGCrypto::Crypt.decrypt_column(table_name, select_name, key)
          selects[i] = decrypt.as(select_name)
          untouched_columns.delete(select_name)
        end
      end

      splat_projection = selects.find { |select| select.respond_to?(:name) && select.name == '*' }
      if untouched_columns.any? && splat_projection
        untouched_columns.each do |column|
          next unless (key = PGCrypto.keys.private_key(columns[column.to_sym]))
          decrypt = PGCrypto::Crypt.decrypt_column(table_name, column, key)
          core.projections.push(decrypt.as(column))
        end
      end
    end

    def pgcrypto_translate_wheres_for_select(core)
      table_name = core.source.left.name
      columns = PGCrypto[table_name]
      return if columns.empty?

      core.wheres.each do |where|
        pgcrypto_translate_where( where, table_name, columns )
      end
    end

    def pgcrypto_translate_where( where, table_name, columns )
      if where.respond_to?(:children)
        # Loop through the children to replace them with a decrypted counterpart
        where.children.each do |child|

          next unless child.respond_to?(:left) && options = columns[child.left.name.to_s]
          key = PGCrypto.keys.private_key( options )
          child.left = PGCrypto::Crypt.decrypt_column(table_name, child.left.name, key)

          # Prevent ActiveRecord from re-casting the value to binary
          case child.right
          when String
            child.right = quoted_literal( child.right )
          when Arel::Nodes::Casted
            child.right = quoted_literal( child.right.val )
          when Array
            child.right = child.right.map do |item|
              case item
              when Arel::Nodes::Casted
                quoted_literal( item.val )
              else
                raise "Unknown node class presented to block in pgcrypto_translate_wheres: #{item.class.to_s}!"
              end
            end
          when Arel::Nodes::BindParam
            # Do nothing -- ActiveRecord will pass the correct binding and cast it appropriately.
          else
            raise "Unknown node class presented to pgcrypto_translate_wheres: #{child.right.class.to_s}!"
          end

        end
      end
    end

    def null_literal
      Arel::Nodes::SqlLiteral.new('NULL')
    end

    def quoted_literal( str )
      Arel::Nodes::SqlLiteral.new("'#{quote_string( str )}'")
    end

  end

  Adapter = build_adapter!

end
