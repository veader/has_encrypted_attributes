require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'

desc 'Default: run unit tests.'
task :default => [:clean_db, :test]

desc 'Remove the stale db file'
task :clean_db do
  `rm -f #{File.dirname(__FILE__)}/test/encrypted_attrs.sqlite3.db`
end

desc 'Test the has_encrypted_attributes plugin.'
Rake::TestTask.new(:test) do |t|
  t.libs << 'lib'
  t.pattern = 'test/**/*_test.rb'
  t.verbose = true
end

namespace :test do
  desc 'Run the tests under ruby-prof'
  task :profile => [ :enable_test_profiling, :test ]
  task(:enable_test_profiling) { ENV['ENABLE_TEST_PROFILING'] = 'yep' }
end

desc 'Generate documentation for the has_encrypted_attributes plugin.'
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'HasEncryptedAttributes'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('README')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
