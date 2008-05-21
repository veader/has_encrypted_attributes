module Has                                  #:nodoc:
  module EncryptedAttributes                #:nodoc:
    class NoEncryptionKeyGiven < Exception  #:nodoc:
    end
  
    def self.included(base)                 #:nodoc:
      base.extend Encrypted
    end
  
    module Encrypted
      def has_encrypted_attributes(options={})
        cattr_accessor :encrypted_key_assoc, :encrypted_key_method, :encrypted_key_value, :encrypted_exceptions, :encrypted_block_size, :encrypted_max_key_len
        self.encrypted_key_assoc    = options[:association] || nil
        self.encrypted_key_method   = options[:key_method] || :key
        self.encrypted_key_value    = options[:key] || nil
        self.encrypted_exceptions   = options[:except].map(&:to_s) rescue []
        self.encrypted_block_size   = 8
        self.encrypted_max_key_len  = 56
      
        include InstanceMethods
        
        before_save :encrypt_attributes
        after_save :decrypt_attributes # decrypt the attributes in case we need them after save
      end
    end
  
    module InstanceMethods
      def encrypt_attributes(key=nil)
        exclude_usual_suspects # TODO: figure out how to move this
        key = find_key(key)
        
        self.attributes.reject { |a,v| self.encrypted_exceptions.include?(a) }.each do |attr,value|
          next unless value
          self.send("#{attr}=", encrypt_attribute(value,key)) rescue raise("#{attr} has value of #{value} which is not a string")
        end
      end
    
      def decrypt_attributes(key=nil)
        exclude_usual_suspects # TODO: figure out how to move this
        key = find_key(key)
        
        self.attributes.reject { |a,v| self.encrypted_exceptions.include?(a) }.each do |attr,value|
          next unless value
          self.send("#{attr}=", decrypt_attribute(value,key))
        end
      end
      
      def encryption_key
        find_key
      end

    protected
      def after_find
        decrypt_attributes
      end
      
      def exclude_usual_suspects
        # TODO: figure out how to look for types such as datetimes and integers
        exclude = %w(created_at created_on updated_at updated_on id)
        # exclude the association ID if we are using an associaiton
        exclude << "#{self.encrypted_key_assoc.to_s}_id" if self.encrypted_key_assoc
        exclude.each do |m|
          self.encrypted_exceptions << m unless self.encrypted_exceptions.include?(m)
        end
      end

      def find_key(key=nil)
        k = \
        if key # use the key given
          key
        elsif self.encrypted_key_value # use key given in definition
          self.encrypted_key_value
        elsif self.encrypted_key_assoc && self.encrypted_key_method
          # use the key from the association given in definition
          self.send(encrypted_key_assoc).send(encrypted_key_method) rescue nil
        else
          nil
        end
        raise NoEncryptionKeyGiven unless k
        k[0,self.encrypted_max_key_len] # make sure key is not too long
      end

      def encrypt_attribute(str, key)
        raise unless str.is_a?(String)
        blowfish = Crypt::Blowfish.new(key)
        
        # split text into blocks and encrypt
        blocks = (0..(str.length/self.encrypted_block_size)).collect do |i|
          # we need to pad up to block size
          blowfish.encrypt_block(str[(i*self.encrypted_block_size),8].ljust(self.encrypted_block_size))
        end

        blocks.join
      end
      
      def decrypt_attribute(str, key)
        blowfish = Crypt::Blowfish.new(key)

        # split text into blocks and decrypt
        blocks = (0..(str.length/self.encrypted_block_size)).collect do |i|
          t = str[(i*self.encrypted_block_size),8]
          # make sure the block isn't empty before trying to decrypt it
          next if t.strip.empty?
          blowfish.decrypt_block(t) rescue nil
        end
        
        blocks.compact.join.strip!
      end
    end
  end
end