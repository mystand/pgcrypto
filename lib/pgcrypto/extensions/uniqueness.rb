module PGCrypto::Extensions
  module Uniqueness

    def self.included( base )
      base.class_eval do

        # We redefine this method to correctly process the raw relations built by this validator. Original source found at
        # https://github.com/rails/rails/blob/4-2-stable/activerecord/lib/active_record/validations/uniqueness.rb#L80
        def scope_relation(record, table, relation)
          return relation unless Array(options[:scope]).present?
          Array(options[:scope]).each do |scope_item|
            if reflection = record.class._reflect_on_association(scope_item)
              scope_value = record.send(reflection.foreign_key)
              scope_item  = reflection.foreign_key
            else
              scope_value = record._read_attribute(scope_item)
            end
            relation = relation.and(table[scope_item].eq(scope_value))
          end
          PGCrypto::Manipulation.process_raw_relation( relation )
        end

      end
    end

  end
end

# Load immediately. Or load later. It's all good with us.
if defined? ActiveRecord::Validations::UniquenessValidator
  ActiveRecord::Validations::UniquenessValidator.send( :include, PGCrypto::Extensions::Uniqueness )
else
  ActiveSupport.on_load(:active_record) do
    ActiveRecord::Validations::UniquenessValidator.send( :include, PGCrypto::Extensions::Uniqueness )
  end
end
