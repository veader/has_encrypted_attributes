require 'has_encrypted_attributes'
require 'crypt/blowfish'
require 'base64'

ActiveRecord::Base.class_eval do
  include Has::EncryptedAttributes
end
