class User < ActiveRecord::Base
  has_one :secret
end