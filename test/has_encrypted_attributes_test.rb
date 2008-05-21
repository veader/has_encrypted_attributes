require File.dirname(__FILE__) + '/test_helper'
require 'pp'

include Has::EncryptedAttributes

class HasEncryptedAttributesTest < Test::Unit::TestCase
  fixtures :users, :secrets
  
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
  
  def test_should_not_encrypt_exception_attributes1
    setup_with_key_value_defined
    
    president = 'George Dubbya Bush'
    secret = Secret.create(:current_president => president)
    assert_equal president, Secret.connection.select_rows("SELECT current_president FROM secrets WHERE ID = #{secret.id};")[0][0]
  end

  def test_should_not_encrypt_exception_attributes2
    setup_with_association_no_key_defined
    user = create_user
    
    president = 'George Dubbya Bush'
    secret = Secret.create(:current_president => president, :user => user)
    assert_equal president, Secret.connection.select_rows("SELECT current_president FROM secrets WHERE ID = #{secret.id};")[0][0]
  end

  def test_should_not_encrypt_exception_attributes3
    setup_with_association_with_key_defined
    user = create_user
    
    president = 'George Dubbya Bush'
    secret = Secret.create(:current_president => president, :user => user)
    assert_equal president, Secret.connection.select_rows("SELECT current_president FROM secrets WHERE ID = #{secret.id};")[0][0]
  end
  
  def test_should_encrypt_attributes1
    setup_with_key_value_defined
    
    jfk_assassin = 'Myster Man'
    secret = Secret.create(:who_killed_jfk => jfk_assassin)
    assert_not_equal jfk_assassin, Secret.connection.select_rows("SELECT who_killed_jfk FROM secrets WHERE ID = #{secret.id};")[0][0]
  end

  def test_should_encrypt_attributes2
    setup_with_association_no_key_defined
    user = create_user

    jfk_assassin = 'Myster Man'
    secret = Secret.create(:who_killed_jfk => jfk_assassin, :user => user)
    assert_not_equal jfk_assassin, Secret.connection.select_rows("SELECT who_killed_jfk FROM secrets WHERE ID = #{secret.id};")[0][0]
  end

  def test_should_encrypt_attributes3
    setup_with_association_with_key_defined
    user = create_user
    
    jfk_assassin = 'Myster Man'
    secret = Secret.create(:who_killed_jfk => jfk_assassin, :user => user)
    assert_not_equal jfk_assassin, Secret.connection.select_rows("SELECT who_killed_jfk FROM secrets WHERE ID = #{secret.id};")[0][0]
  end
  
  def test_should_show_unencrypted_attributes_in_model_after_save
    setup_with_key_value_defined
    
    jfk_assassin = 'Myster Man'
    secret = Secret.create(:who_killed_jfk => jfk_assassin)
    assert_equal jfk_assassin, secret.who_killed_jfk
  end

private
  def setup_with_association_no_key_defined
    Secret.has_encrypted_attributes :association => :user, :except => [:current_president]
  end
  
  def setup_with_association_with_key_defined
    Secret.has_encrypted_attributes :association => :user, :key_method => :alternate_key, :except => [:current_president]
  end
  
  def setup_with_key_value_defined(key='45FGIRG91923G')
    Secret.has_encrypted_attributes :key => key, :except => [:current_president]
  end
  
  def create_user
    User.create(:login => 'veader', :key => 'test1234', :alternate_key => 'test4321')
  end
end
