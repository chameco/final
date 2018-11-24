module Final.Cipher.RSA where

import Data.Binary (encode)

import Final.Cipher
import Final.Utility.Modular
import Final.Utility.Prime

data RSA
instance Cipher RSA where
  type EncryptionKey RSA = (Integer, Integer)
  type DecryptionKey RSA = (Integer, Integer, Integer)
  type Plaintext RSA = Integer
  type Ciphertext RSA = Integer
  name = "RSA"
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
    , parseEncryptionKey = undefined
    , renderEncryptionKey = encode
    , parseDecryptionKey = undefined
    , renderDecryptionKey = encode
    , parsePlaintext = undefined
    , renderPlaintext = encode
    , parseCiphertext = undefined
    , renderCiphertext = encode
    }
