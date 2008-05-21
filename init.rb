require 'has_encrypted_attributes'
require 'crypt/blowfish'

ActiveRecord::Base.class_eval do
  include Has::EncryptedAttributes
end
