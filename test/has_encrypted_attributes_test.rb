require File.dirname(__FILE__) + '/test_helper'
require 'pp'

include Has::EncryptedAttributes

class HasEncryptedAttributesTest < Test::Unit::TestCase
  fixtures :users, :secrets

  def setup
    # ActiveRecord::Base.logger = Logger.new(STDOUT)
    # ActiveRecord::Base.clear_active_connections!
  end

  # ========================================================================
  # TEST setup

  def test_should_allow_association
    setup_with_association_no_key_defined

    secret = Secret.new
    assert_equal :user, secret.encrypted_key_assoc
    assert_equal :key, secret.encrypted_key_method
    assert_nil secret.encrypted_key_value
  end

  def test_should_allow_association_with_alt_key
    setup_with_association_with_key_defined

    secret = Secret.new
    assert_equal :user, secret.encrypted_key_assoc
    assert_equal :alternate_key, secret.encrypted_key_method
    assert_nil secret.encrypted_key_value
  end

  def test_should_allow_explicit_key
    key = 'test1234'
    setup_with_key_value_defined(key)

    secret = Secret.new
    assert_nil secret.encrypted_key_assoc
    assert_equal key, secret.encrypted_key_value
  end

  def test_should_require_key
    setup_with_key_value_defined(nil)

    assert_raise(NoEncryptionKeyGiven) {
      Secret.create(:who_killed_jfk => 'test')
    }

    setup_with_association_no_key_defined
    assert_raise(NoEncryptionKeyGiven) {
      Secret.create(:who_killed_jfk => 'test')
    }

    setup_with_association_with_key_defined
    assert_raise(NoEncryptionKeyGiven) {
      Secret.create(:who_killed_jfk => 'test')
    }
  end

  # ========================================================================
  # TEST :except and :only statements

  def test_should_allow_single_symbol_attributes_in_except_param
    setup_with_key_value_defined

    do_nonencryption_test
  end

  def test_should_allow_single_string_attributes_in_except_param
    setup_with_key_value_defined('45FGIRG91923G', true)

    do_nonencryption_test
  end

  def test_should_allow_arrays_of_symbols_in_except_param
    setup_with_key_value_defined_exception_as_array

    do_nonencryption_test
  end

  def test_should_allow_arrays_of_strings_in_except_param
    setup_with_key_value_defined_exception_as_array('45FGIRG91923G', true)

    do_nonencryption_test
  end

  def test_should_allow_single_symbol_attributes_in_only_clause
    setup_with_key_value_defined_and_only_clause

    do_encryption_test2
  end

  def test_should_allow_single_string_attributes_in_only_clause
    setup_with_key_value_defined_and_only_clause('45FGIRG91923G', true)

    do_encryption_test2
  end

  def test_should_allow_arrays_of_symbols_in_only_clause
    setup_with_key_value_defined_and_only_clause_as_array

    do_encryption_test2
  end

  def test_should_allow_arrays_of_strings_in_only_clause
    setup_with_key_value_defined_and_only_clause_as_array('FGIRG91923G', true)

    do_encryption_test2
  end

  # ========================================================================
  # TEST :except in action

  def test_should_not_encrypt_exception_attributes_with_set_key
    setup_with_key_value_defined

    do_nonencryption_test
  end

  def test_should_not_encrypt_exception_attributes_with_assoc_key
    setup_with_association_no_key_defined
    user = create_user

    do_nonencryption_test(user)
  end

  def test_should_not_encrypt_exception_attributes_with_assoc_alt_key
    setup_with_association_with_key_defined
    user = create_user

    do_nonencryption_test(user)
  end

  # ========================================================================
  # TEST :only in action

  def test_should_encrypt_only_attributes_in_only_clause
    setup_with_key_value_defined_and_only_clause

    jfk_assassin = 'Myster Man'
    president = 'George Dubbya Bush'
    secret = Secret.create(:who_killed_jfk    => jfk_assassin,
                           :current_president => president)
    sql1 = "SELECT current_president FROM secrets WHERE ID = #{secret.id};"
    sql2 = "SELECT who_killed_jfk FROM secrets WHERE ID = #{secret.id};"
    assert_not_equal president, Secret.connection.select_rows(sql1)[0][0]
    assert_equal jfk_assassin,  Secret.connection.select_rows(sql2)[0][0]
  end

  # ========================================================================
  # TEST encryption in action

  def test_should_encrypt_attributes_with_set_key
    setup_with_key_value_defined

    do_encryption_test
  end

  def test_should_encrypt_attributes_wth_assoc_key
    setup_with_association_no_key_defined
    user = create_user

    do_encryption_test(user)
  end

  def test_should_encrypt_attributes_with_assoc_alt_key
    setup_with_association_with_key_defined
    user = create_user

    do_encryption_test(user)
  end

  # ========================================================================
  # TEST after_* in action

  def test_should_show_unencrypted_attributes_in_model_after_save
    setup_with_key_value_defined

    jfk_assassin = 'Mystery Man'
    secret = Secret.create(:who_killed_jfk => jfk_assassin)
    assert_equal jfk_assassin, secret.who_killed_jfk
  end

# ========================================================================
private
  def setup_with_association_no_key_defined
    Secret.has_encrypted_attributes :association => :user,
                                    :except      => [:current_president]
  end

  def setup_with_association_with_key_defined
    Secret.has_encrypted_attributes :association => :user,
                                    :key_method  => :alternate_key,
                                    :except      => [:current_president]
  end

  def setup_with_key_value_defined(key='45FGIRG91923G', use_string=false)
    exceptions = (use_string ? 'current_president' : :current_president)
    Secret.has_encrypted_attributes :key => key, :except => exceptions
  end

  def setup_with_key_value_defined_exception_as_array( \
      key='45FGIRG91923G', use_string=false )

    exceptions = if use_string
      ['current_president', 'who_killed_jfk']
    else
      [:current_president, :who_killed_jfk]
    end
    Secret.has_encrypted_attributes :key => key, :except => exceptions
  end

  def setup_with_key_value_defined_and_only_clause( \
      key='59234ARI85A', use_string=false )

    only_clause = (use_string ? 'current_president' : :current_president)
    Secret.has_encrypted_attributes :key => key, :only => only_clause
  end

  def setup_with_key_value_defined_and_only_clause_as_array( \
      key='59234ARI85A', use_string=false )

    only_clause = if use_string
      ['current_president', 'who_killed_jfk']
    else
      [:current_president, :who_killed_jfk]
    end
    Secret.has_encrypted_attributes :key => key, :only => only_clause
  end

  def create_user
    User.create :login         => 'veader',
                :key           => 'test1234',
                :alternate_key => 'test4321'
  end

  def do_encryption_test(user=nil)
    jfk_assassin = 'Mystery Man'
    secret = Secret.create(:who_killed_jfk => jfk_assassin, :user => user)
    sql    = "SELECT who_killed_jfk FROM secrets WHERE ID = #{secret.id};"
    assert_not_equal jfk_assassin, Secret.connection.select_rows(sql)[0][0]
  end

  def do_encryption_test2
    president = 'George Dubbya Bush'
    secret = Secret.create(:current_president => president)
    sql    = "SELECT current_president FROM secrets WHERE ID = #{secret.id};"
    assert_not_equal president, Secret.connection.select_rows(sql)[0][0]
  end

  def do_nonencryption_test(user=nil)
    president = 'George Dubbya Bush'
    secret = Secret.create(:current_president => president, :user => user)
    sql    = "SELECT current_president FROM secrets WHERE ID = #{secret.id};"
    assert_equal president, Secret.connection.select_rows(sql)[0][0]
  end
end