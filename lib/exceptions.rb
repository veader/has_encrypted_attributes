module Has                                  #:nodoc:
  module EncryptedAttributes                #:nodoc:
    class NoEncryptionKeyGiven             < Exception; end #:nodoc:
    class RubyCompiledWithoutOpenSSL       < Exception; end #:nodoc:
    class BlowfishCBCAlgorithmNotSupported < Exception; end #:nodoc:
  end
end
