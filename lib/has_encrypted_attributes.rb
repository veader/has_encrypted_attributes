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
      def normalize_hae_options(opts)
        (opts.is_a?(Array) ? opts : [ opts ]).reject(&:blank?).map(&:to_s)
      end

      def has_encrypted_attributes(opts = {})
        (opts = opts.to_options).assert_valid_keys(
          :association, :key_method, :key, :only, :except)

        cattr_accessor :encrypted_attr_opts
        self.encrypted_attr_opts = Struct.new(:only, :except,
          :key_holder, :key_value, :key_method).new

        encrypted_attr_opts.key_holder = opts[:association] || nil
        encrypted_attr_opts.key_method = (opts[:key_method] || :key).to_sym
        encrypted_attr_opts.key_value  = opts[:key]
        encrypted_attr_opts.only       = normalize_hae_options opts[:only]
        encrypted_attr_opts.except     = normalize_hae_options opts[:except]

        # Don't encrypt the association ID if we are using one:
        if encrypted_attr_opts.key_holder
          encrypted_attr_opts.except |= [
            "#{encrypted_attr_opts.key_holder}_id" ]
        end

        # Don't encrypt these usual suspects:
        encrypted_attr_opts.except |= %W[ lock_version
          created_at created_on updated_at updated_on #{primary_key} ]

        include InstanceMethods

        self.before_save :encrypt_attributes!
        self.after_save  :decrypt_attributes!
        self.after_find  :decrypt_attributes!
      end
    end

    module InstanceMethods

    protected

      def after_find
        decrypt_attributes!
      end

    private

      def encrypt_attributes!
        @plaintext_cache ||= {}

        attributes_needing_encryption.each do |secret|
          if send("#{secret}_changed?".to_sym)
            @plaintext_cache[secret] = self[secret]
            self[secret] = encrypt_plaintext(self[secret])
          end
        end
      end

      def decrypt_attributes!
        @plaintext_cache ||= {}

        attributes_needing_encryption.each do |secret|
          self[secret] = \
            (@plaintext_cache[secret] ||= decrypt_encrypted(self[secret]))
        end
      end

      def attributes_needing_encryption
        @_attributes_needing_encryption ||= begin
          if encrypted_attr_opts.only.present?
            encrypted_attr_opts.only - encrypted_attr_opts.except
          else
            attribute_names - encrypted_attr_opts.except
          end
        end
      end

      def encryption_key
        @encryption_key ||= begin
          key_holder = if encrypted_attr_opts.key_holder.present?
            self.send(encrypted_attr_opts.key_holder.to_sym)
          else
            self
          end

          key = if encrypted_attr_opts.key_value.present?
            encrypted_attr_opts.key_value # use key given in definition
          elsif key_holder && encrypted_attr_opts.key_method
            # use the key from the association given in definition
            if key_holder.respond_to?(encrypted_attr_opts.key_method)
              key_holder.send(encrypted_attr_opts.key_method)
            end
          end

          raise NoEncryptionKeyGiven unless key.present?
          Digest::SHA512.hexdigest(key)
        end
      end

      def encrypt_plaintext(plaintext)
        return nil if plaintext.blank?

        blowfish = initialize_blowfish
        blowfish.encrypt

        encrypted = blowfish.update plaintext.to_s
        Base64.encode64(encrypted << blowfish.final).chomp
      end

      # exception must have changed names over time. safeguard...
      OpenSSLCipherError = OpenSSL::Cipher.const_defined?(:CipherError) ? \
              OpenSSL::Cipher::CipherError : \
              OpenSSL::CipherError

      def decrypt_encrypted(encrypted)
        return nil if encrypted.blank?

        begin
          blowfish = initialize_blowfish
          blowfish.decrypt

          decrypted =  blowfish.update Base64.decode64(encrypted)
          decrypted << blowfish.final
        rescue OpenSSLCipherError
          encrypted # return the original if the decrypt fails.
        end
      end

      def initialize_blowfish
        blowfish     = OpenSSL::Cipher::Cipher.new 'BF-CBC'
        blowfish.key = encryption_key[ 0 ... blowfish.key_len ]
        blowfish.iv  = encryption_key[ 0 ... blowfish.iv_len  ]
        blowfish
      end
    end
  end
end