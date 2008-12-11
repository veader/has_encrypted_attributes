require 'has_encrypted_attributes'

ActiveRecord::Base.class_eval do
  include Has::EncryptedAttributes
end
