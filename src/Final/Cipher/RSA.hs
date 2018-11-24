module Final.Cipher.RSA where

import Data.Binary (encode, decode)

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
    , generateDecryptionKey = \gen ->
        let (p, gen') = genPrimeBits gen 1024
            (q, gen'') = genPrimeBits gen' 1024
            (d, gen''') = genCoprime gen'' $ carmichaelTotient p q
        in if p == q
           then generateDecryptionKey (impl :: Impl RSA) gen''
           else ((d, p, q), gen''')
    , deriveEncryptionKey = \(d, p, q) -> (modInv d $ carmichaelTotient p q, p * q)
    , parseEncryptionKey = decode
    , renderEncryptionKey = encode
    , parseDecryptionKey = decode
    , renderDecryptionKey = encode
    , parsePlaintext = decode
    , renderPlaintext = encode
    , parseCiphertext = decode
    , renderCiphertext = encode
    }
