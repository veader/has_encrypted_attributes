module Has                                  #:nodoc:
  module EncryptedAttributes                #:nodoc:
    class NoEncryptionKeyGiven                      < Exception; end #:nodoc:
    class RubyCompiledWithoutOpenSSL                < Exception; end #:nodoc:
    class BlowfishCBCAlgorithmNotSupportedByOpenSSL < Exception; end #:nodoc:
  end
end
