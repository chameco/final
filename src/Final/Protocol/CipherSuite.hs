module Final.Protocol.CipherSuite where

import Control.Exception.Safe (MonadThrow)

import Data.ByteString.Lazy (ByteString)
import Data.Maybe (fromJust)
import Data.Word (Word8)

import Final.Cipher as Cipher
-- import Final.Cipher.RSA
import Final.Cipher.ChaCha20
import Final.Hash as Hash
import Final.Hash.SHA256

data CipherSuite m = CipherSuite {  suiteName :: String
                                 ,  encrypt :: ByteString -> ByteString -> m ByteString
                                 ,  decrypt :: ByteString -> ByteString -> m ByteString
                                 }

createSuite :: forall a b m. (Cipher a, Hash b, MonadThrow m) => String -> CipherSuite m
createSuite n = CipherSuite n (encryptWithCipher cipher) (decryptWithCipher cipher)
  where cipher = Cipher.impl @a
        -- hash = Hash.impl @b

getCipherSuite :: forall m. MonadThrow m => (Word8, Word8) -> CipherSuite m
getCipherSuite = fromJust . flip lookup
  [ ((0x00, 0x00), createSuite @IDSymmetric @SHA256 "TLS_NULL_WITH_NULL_NULL"),
    ((0xCC, 0xA8), createSuite @ChaCha20 @SHA256 "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
  ]
