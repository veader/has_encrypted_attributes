require File.dirname(__FILE__) + '/test_helper'
require 'pp'

begin
  require 'ruby-prof'
rescue LoadError
  nil
end

class User < ActiveRecord::Base
  has_one :secret
end

include Has::EncryptedAttributes

class HasEncryptedAttributesTest < Test::Unit::TestCase

  if defined?(RubyProf) && ENV['ENABLE_TEST_PROFILING']
    include RubyProf::Test
    PROFILE_OPTIONS[:output_dir] =
      File.join(File.dirname(__FILE__), '..', 'profile')
  end

  def teardown
    @secret_klass = nil
  end

  # ========================================================================
  # TEST setup

  def test_should_require_key
    secret_klass = setup_with_key_value_defined(nil)

    assert_raise(NoEncryptionKeyGiven) {
      secret_klass.create(:who_killed_jfk => 'test')
    }

    setup_with_association_no_key_defined
    assert_raise(NoEncryptionKeyGiven) {
      secret_klass.create(:who_killed_jfk => 'test')
    }

    setup_with_association_with_key_defined
    assert_raise(NoEncryptionKeyGiven) {
      secret_klass.create(:who_killed_jfk => 'test')
    }
  end

  # ========================================================================
  # TEST :except and :only statements

  def test_should_allow_single_symbol_attributes_in_except_param
    @secret_klass = setup_with_key_value_defined

    do_nonencryption_test
  end

  def test_should_allow_single_string_attributes_in_except_param
    @secret_klass = setup_with_key_value_defined('45FGIRG91923G', true)

    do_nonencryption_test
  end

  def test_should_allow_arrays_of_symbols_in_except_param
    @secret_klass = setup_with_key_value_defined_exception_as_array

    do_nonencryption_test
  end

  def test_should_allow_arrays_of_strings_in_except_param
    @secret_klass = setup_with_key_value_defined_exception_as_array(
      '45FGIRG91923G', true)

    do_nonencryption_test
  end

  def test_should_allow_single_symbol_attributes_in_only_clause
    @secret_klass = setup_with_key_value_defined_and_only_clause

    do_encryption_test2
  end

  def test_should_allow_single_string_attributes_in_only_clause
    @secret_klass = setup_with_key_value_defined_and_only_clause(
      '45FGIRG91923G', true)

    do_encryption_test2
  end

  def test_should_allow_arrays_of_symbols_in_only_clause
    @secret_klass = setup_with_key_value_defined_and_only_clause_as_array

    do_encryption_test2
  end

  def test_should_allow_arrays_of_strings_in_only_clause
    @secret_klass = setup_with_key_value_defined_and_only_clause_as_array(
      'FGIRG91923G', true)

    do_encryption_test2
  end

  # ========================================================================
  # TEST :except in action

  def test_should_not_encrypt_exception_attributes_with_set_key
    @secret_klass = setup_with_key_value_defined

    do_nonencryption_test
  end

  def test_should_not_encrypt_exception_attributes_with_assoc_key
    @secret_klass = setup_with_association_no_key_defined
    user = create_user

    do_nonencryption_test(user)
  end

  def test_should_not_encrypt_exception_attributes_with_assoc_alt_key
    @secret_klass = setup_with_association_with_key_defined
    user = create_user

    do_nonencryption_test(user)
  end

  # ========================================================================
  # TEST :only in action

  def test_should_encrypt_only_attributes_in_only_clause
    @secret_klass = setup_with_key_value_defined_and_only_clause

    jfk_assassin = 'Myster Man'
    president = 'George Dubbya Bush'
    secret = @secret_klass.create(:who_killed_jfk    => jfk_assassin,
                                     :current_president => president)
    sql1 = "SELECT current_president FROM secrets WHERE ID = #{secret.id};"
    sql2 = "SELECT who_killed_jfk FROM secrets WHERE ID = #{secret.id};"
    assert_not_equal president,
      @secret_klass.connection.select_rows(sql1)[0][0]

    assert_equal jfk_assassin,
      @secret_klass.connection.select_rows(sql2)[0][0]
  end

  # ========================================================================
  # TEST encryption in action

  def test_should_encrypt_attributes_with_set_key
    @secret_klass = setup_with_key_value_defined

    do_encryption_test
  end

  def test_should_encrypt_attributes_with_key_method_on_self
    @secret_klass = setup_with_key_method_on_self

    do_encryption_test
  end

  def test_should_encrypt_attributes_with_assoc_key
    @secret_klass = setup_with_association_no_key_defined
    user = create_user

    do_encryption_test(user)
  end

  def test_should_encrypt_attributes_with_assoc_alt_key
    @secret_klass = setup_with_association_with_key_defined
    user = create_user

    do_encryption_test(user)
  end

  def test_should_safely_work_with_saves_when_no_changes_found
    @secret_klass = setup_with_key_value_defined

    jfk_assassin = 'Mystery Man'
    secret = @secret_klass.create(:who_killed_jfk => jfk_assassin)
    assert_equal jfk_assassin, secret.who_killed_jfk
    assert secret.changes.blank?
    secret.save # should be a no-op
    assert_equal jfk_assassin, secret.who_killed_jfk
  end

  # ========================================================================
  # TEST after_* in action

  def test_should_show_unencrypted_attributes_in_model_after_save
    @secret_klass = setup_with_key_value_defined

    jfk_assassin = 'Mystery Man'
    secret = @secret_klass.create(:who_killed_jfk => jfk_assassin)
    assert_equal jfk_assassin, secret.who_killed_jfk
  end

  def xtest_should_show_unencrypted_attributes_in_model_after_reload
    @secret_klass = setup_with_key_value_defined

    jfk_assassin = 'Mystery Man'
    secret = @secret_klass.create(:who_killed_jfk => jfk_assassin)
    assert_equal jfk_assassin, secret.reload.who_killed_jfk
  end

  def test_should_show_unencrypted_attributes_in_model_after_find
    @secret_klass = setup_with_key_value_defined

    jfk_assassin = 'Mystery Man'
    secret = @secret_klass.create(:who_killed_jfk => jfk_assassin)
    assert_equal jfk_assassin, @secret_klass.find(secret.id).who_killed_jfk
  end

# ========================================================================
private
  def new_secret_class
    klass = Class.new(ActiveRecord::Base)
    klass.set_table_name :secrets
    klass.belongs_to     :user
    klass
  end

  def setup_with_association_no_key_defined
    klass = new_secret_class
    klass.has_encrypted_attributes :association => :user,
                                   :except      => [:current_president]
    klass
  end

  def setup_with_key_method_on_self
    klass = new_secret_class
    klass.has_encrypted_attributes :key_method  => :super_secret_key,
                                   :except      => [:current_president]
    klass.class_eval do
      def super_secret_key
        '45FGIRG91923G'
      end
    end

    klass
  end

  def setup_with_association_with_key_defined
    klass = new_secret_class
    klass.has_encrypted_attributes :association => :user,
                                   :key_method  => :alternate_key,
                                   :except      => [:current_president]
    klass
  end

  def setup_with_key_value_defined(key='45FGIRG91923G', use_string=false)
    klass = new_secret_class
    exceptions = (use_string ? 'current_president' : :current_president)
    klass.has_encrypted_attributes :key => key, :except => exceptions
    klass
  end

  def setup_with_key_value_defined_exception_as_array( \
      key='45FGIRG91923G', use_string=false )

    klass = new_secret_class

    exceptions = if use_string
      ['current_president', 'who_killed_jfk']
    else
      [:current_president, :who_killed_jfk]
    end
    klass.has_encrypted_attributes :key => key, :except => exceptions
    klass
  end

  def setup_with_key_value_defined_and_only_clause( \
      key='59234ARI85A', use_string=false )

    klass = new_secret_class

    only_clause = (use_string ? 'current_president' : :current_president)
    klass.has_encrypted_attributes :key => key, :only => only_clause
    klass
  end

  def setup_with_key_value_defined_and_only_clause_as_array( \
      key='59234ARI85A', use_string=false )

    klass = new_secret_class

    only_clause = if use_string
      ['current_president', 'who_killed_jfk']
    else
      [:current_president, :who_killed_jfk]
    end
    klass.has_encrypted_attributes :key => key, :only => only_clause
    klass
  end

  def create_user
    User.create :login         => 'veader',
                :key           => 'test1234',
                :alternate_key => 'test4321'
  end

  def do_encryption_test(user=nil)
    jfk_assassin = 'Mystery Man'
    secret = @secret_klass.create(:who_killed_jfk => jfk_assassin, :user => user)
    sql    = "SELECT who_killed_jfk FROM secrets WHERE ID = #{secret.id};"
    assert_not_equal jfk_assassin, @secret_klass.connection.select_rows(sql)[0][0]
  end

  def do_encryption_test2
    president = 'George Dubbya Bush'
    secret = @secret_klass.create(:current_president => president)
    sql    = "SELECT current_president FROM secrets WHERE ID = #{secret.id};"
    assert_not_equal president, @secret_klass.connection.select_rows(sql)[0][0]
  end

  def do_nonencryption_test(user=nil)
    president = 'George Dubbya Bush'
    secret = @secret_klass.create(:current_president => president, :user => user)
    sql    = "SELECT current_president FROM secrets WHERE ID = #{secret.id};"
    assert_equal president, @secret_klass.connection.select_rows(sql)[0][0]
  end
end