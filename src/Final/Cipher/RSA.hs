module Final.Cipher.RSA where

import Control.Exception.Safe

import qualified Data.ByteString.Lazy as BS

import Final.Cipher
import Final.Utility.Modular
import Final.Utility.Prime
import Final.Utility.ByteString

data RSA
instance Cipher RSA where
  type EncryptionKey RSA = (Integer, Integer)
  type DecryptionKey RSA = (Integer, Integer, Integer)
  type Plaintext RSA = [Integer]
  type Ciphertext RSA = [Integer]
  name = "RSA"
  impl = Implementation
    { encrypt = \(e, n) ms -> (\m -> modExp m e n) <$> ms
    , decrypt = \(d, p, q) cs -> (\c -> modExp c d (p * q)) <$> cs
    , generateDecryptionKey = \gen ->
        let (p, gen') = genPrimeBits gen 1024
            (q, gen'') = genPrimeBits gen' 1024
            (d, gen''') = genCoprime gen'' $ carmichaelTotient p q
        in if p == q
           then generateDecryptionKey (impl :: Impl RSA) gen''
           else ((d, p, q), gen''')
    , deriveEncryptionKey = \(d, p, q) -> (modInv d $ carmichaelTotient p q, p * q)
    , parseEncryptionKey = \bs -> let (ebs, nbs) = BS.splitAt 2048 bs
                                  in if BS.length bs == 2 * 2048
                                     then pure (byteStringToIntegerBE ebs, byteStringToIntegerBE nbs)
                                     else throwString "Invalid RSA encryption key"
    , renderEncryptionKey = \(e, n) -> integerToByteStringBE 2048 e <> integerToByteStringBE 2048 n
    , parseDecryptionKey = \bs -> let (dbs, rest) = BS.splitAt 2048 bs
                                      (pbs, qbs) = BS.splitAt 2048 rest
                                  in if BS.length bs == 3 * 2048
                                     then pure (byteStringToIntegerBE dbs, byteStringToIntegerBE pbs, byteStringToIntegerBE qbs)
                                     else throwString "Invalid RSA decryption key"
    , renderDecryptionKey = \(d, p, q) -> mconcat [ integerToByteStringBE 2048 d
                                                  , integerToByteStringBE 2048 p
                                                  , integerToByteStringBE 2048 q
                                                  ]
    , parsePlaintext = pure . fmap byteStringToIntegerBE . splitEvery 128
    , renderPlaintext = mconcat . integersToByteStringsBE 0
    , parseCiphertext = pure . fmap byteStringToIntegerBE . splitEvery 2048
    , renderCiphertext = mconcat . integersToByteStringsBE 2048
    }
