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

      def has_encrypted_attributes(options = {})
        cattr_accessor :encrypted_key_assoc, :encrypted_key_method,
                       :encrypted_key_value

        self.encrypted_key_assoc  = options[:association] || nil
        self.encrypted_key_method = options[:key_method]  || :key
        self.encrypted_key_method = encrypted_key_method.to_sym
        self.encrypted_key_value  = options[:key]

        to_encrypt = normalize_hae_options(options[:only])

        # Encrypt all attributes (so far) if 'only' was not given:
        to_encrypt = columns.map { |c| c.name.to_s } if to_encrypt.blank?

        # But not the association ID if we are using one:
        to_encrypt -= [ "#{encrypted_key_assoc}_id" ] if encrypted_key_assoc

        # And not these usual suspects:
        to_encrypt -= %W[
          created_at created_on updated_at updated_on #{primary_key} ]

        # And finally, not the ones the user chose to exclude:
        to_encrypt -= normalize_hae_options(options[:except])

        # Define the attr_accessors that encrypt/decrypt on demand:
        to_encrypt.each do |mth|
          define_method(mth.to_sym) do
            @plaintext_cache      ||= {}
            @plaintext_cache[mth] ||= if @attributes[mth].nil?
              nil
            else
              decrypt_encrypted(@attributes[mth])
            end
          end

          define_method("#{mth}=".to_sym) do |plaintext|
            @plaintext_cache      ||= {}
            @plaintext_cache[mth]   = plaintext

            @attributes[mth] = if plaintext.blank?
              nil
            else
              encrypt_plaintext plaintext.to_s
            end
          end
        end

        include InstanceMethods
      end
    end

    module InstanceMethods

    private
      def key_holder
        self.send(encrypted_key_assoc)
      end

      def encryption_key
        @encryption_key ||= begin
          key = if encrypted_key_value.present?
            encrypted_key_value # use key given in definition
          elsif encrypted_key_assoc && encrypted_key_method
            # use the key from the association given in definition
            if key_holder.respond_to?(encrypted_key_method)
              key_holder.send(encrypted_key_method)
            end
          end

          raise NoEncryptionKeyGiven unless key.present?
          Digest::SHA512.hexdigest(key)
        end
      end

      def encrypt_plaintext(plaintext)
        blowfish = initialize_blowfish
        blowfish.encrypt

        encrypted = blowfish.update plaintext.to_s
        Base64.encode64(encrypted << blowfish.final).chomp
      end

      def decrypt_encrypted(encrypted)
        blowfish = initialize_blowfish
        blowfish.decrypt

        decrypted =  blowfish.update Base64.decode64(encrypted)
        decrypted << blowfish.final
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