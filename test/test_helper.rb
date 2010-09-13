$:.unshift(File.dirname(__FILE__) + '/../lib')
RAILS_ROOT = File.dirname(__FILE__)
# RAILS_GEM_VERSION = '2.0.2' unless defined? RAILS_GEM_VERSION

require 'rubygems'
require 'leftright' rescue nil
require 'sqlite3'
require 'test/unit'
require 'active_record'
require 'active_record/fixtures'
require "#{File.dirname(__FILE__)}/../init"

config = YAML::load(IO.read(File.dirname(__FILE__) + '/database.yml'))
ActiveRecord::Base.logger = Logger.new(File.dirname(__FILE__) + '/test.log')
ActiveRecord::Base.establish_connection(config[ENV['DB'] || 'sqlite3'])

if File.exist?(File.dirname(__FILE__) + '/schema.rb')
  load(File.dirname(__FILE__) + '/schema.rb')
end
