require 'base64'
require 'digest/sha2'
require 'exceptions'

begin
  require 'openssl'
rescue
  raise Has::EncryptedAttributes::RubyCompiledWithoutOpenSSL
end

begin
  OpenSSL::Cipher::Cipher.new('BF-CBC')
rescue
  raise Has::EncryptedAttributes::BlowfishCBCAlgorithmNotSupportedByOpenSSL
end

module Has                   #:nodoc:
  module EncryptedAttributes #:nodoc:
    def self.included(base)  #:nodoc:
      base.extend Encrypted
    end

    module Encrypted
      def has_encrypted_attributes(options={})
        cattr_accessor :encrypted_key_assoc, :encrypted_key_method,
                       :encrypted_key_value, :encrypted_exceptions,
                       :encrypted_block_size, :encrypted_max_key_len,
                       :encrypted_attributes
        self.encrypted_block_size  = 8
        self.encrypted_max_key_len = 56
        self.encrypted_key_assoc   = options[:association] || nil
        self.encrypted_key_method  = options[:key_method]  || :key
        self.encrypted_key_value   = options[:key]         || nil
        self.encrypted_exceptions  = options[:except]      || []
        self.encrypted_attributes  = options[:only]        || []

        include InstanceMethods

        before_save :encrypt_attributes
        # decrypt the attributes in case we need them after save
        after_save :decrypt_attributes
      end
    end

    module InstanceMethods
      def encrypt_attributes(key=nil)
        key = find_key(key)
        prepare_encryption_attributes

        if self.encrypted_attributes.blank?
          attributes_without_excluded.each do |attr,value|
            next unless value
            self.send("#{attr}=", encrypt_attribute(value,key)) rescue nil
          end
        else
          # use the :only clause
          self.encrypted_attributes.each do |attr|
            value = self.send(attr)
            next unless value
            self.send("#{attr}=", encrypt_attribute(value, key)) rescue nil
          end
        end
      end

      def decrypt_attributes(key=nil)
        key = find_key(key)
        prepare_encryption_attributes

        if self.encrypted_attributes.blank?
          attributes_without_excluded.each do |attr,value|
            next unless value
            self.send("#{attr}=", decrypt_attribute(value,key)) rescue nil
          end
        else
          # use the :only clause
          self.encrypted_attributes.each do |attr|
            value = self.send(attr)
            next unless value
            self.send("#{attr}=", decrypt_attribute(value, key)) rescue nil
          end
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
        # TODO: remove some types such as date/time and integers
        exclude = %w(created_at created_on updated_at updated_on id)

        # exclude the association ID if we are using an associaiton
        if self.encrypted_key_assoc
          exclude << "#{self.encrypted_key_assoc.to_s}_id"
        end

        self.encrypted_exceptions |= exclude
      end

      def attributes_without_excluded
        self.attributes.reject { |a,v| self.encrypted_exceptions.include?(a) }
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

      def encrypt_attribute(plaintext, key)
        raise unless plaintext.is_a?(String)

        blowfish     = OpenSSL::Cipher::Cipher.new('BF-CBC')
        blowfish.key = key = Digest::SHA2.hexdigest(key)
        blowfish.iv  = iv  = Digest::SHA2.hexdigest(key)

        blowfish.encrypt
        encrypted = blowfish.update(plaintext)
        Base64.encode64(encrypted << blowfish.final)
      end

      def decrypt_attribute(encrypted, key)
        blowfish     = OpenSSL::Cipher::Cipher.new('BF-CBC')
        blowfish.key = key = Digest::SHA2.hexdigest(key)
        blowfish.iv  = iv  = Digest::SHA2.hexdigest(key)

        blowfish.decrypt
        decrypted =  blowfish.update(Base64.decode64(encrypted))
        decrypted << blowfish.final
      end

      def prepare_encryption_attributes
        # TODO: figure out a better place for this to happen at the beginning
        self.encrypted_exceptions = \
                          fix_encryption_options(self.encrypted_exceptions)
        self.encrypted_attributes = \
                          fix_encryption_options(self.encrypted_attributes)
        exclude_usual_suspects
      end

      def fix_encryption_options(value)
        case
        when value.blank?
          []
        when value.is_a?(Array)
          value.map(&:to_s)
        else
          [value.to_s]
        end.reject { |el| el.blank? }
      end
    end
  end
end