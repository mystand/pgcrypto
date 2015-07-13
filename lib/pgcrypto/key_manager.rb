module PGCrypto
  class KeyManager < Hash
    def []=(key, value)
      unless value.is_a?(Key)
        value = Key.new(value)
      end
      value.name = key
      super key, value
    end
    def private_key( options = {} )
      determine_key( :private, options )
    end
    def public_key( options = {} )
      determine_key( :public, options )
    end
    private
    def determine_key( side, options = {} )
      ref = ( PGCrypto.mode == :symmetric ? :symmetric : side.to_sym )
      options[ ref ] || self[ ref ]
    end
  end
end
