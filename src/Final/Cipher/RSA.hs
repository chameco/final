module Final.Cipher.RSA where

import Data.Binary (encode, decode)

import System.Random

import Final.Utility
import Final.Cipher

data RSA
instance Cipher RSA where
  type EncryptionKey RSA = (Integer, Integer)
  type DecryptionKey RSA = (Integer, Integer, Integer)
  type Plaintext RSA = Integer
  type Ciphertext RSA = Integer
  impl = Implementation
    { encrypt = \(e, n) m -> modExp m e n
    , decrypt = \(d, p, q) c -> modExp c d (p * q)
    , generateDecryptionKey = \g -> undefined
    , deriveEncryptionKey = \(d, p, q) -> (undefined, p * q)
    , parseEncryptionKey = decode
    , parseDecryptionKey = decode
    , parsePlaintext = decode
    , renderPlaintext = encode
    , parseCiphertext = decode
    , renderCiphertext = encode
    }
