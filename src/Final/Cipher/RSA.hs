{-|
Implement textbook (non-semantically-secure) RSA.
|-}
module Final.Cipher.RSA where

import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import System.Random

import Final.Utility.Modular
import Final.Utility.Prime
import Final.Utility.ByteString

decodeRSAEncryptionKey :: ByteString -> (Integer, Integer)
decodeRSAEncryptionKey bs = (byteStringToIntegerBE ebs, byteStringToIntegerBE nbs)
  where (ebs, nbs) = BS.splitAt 2048 bs

decodeRSADecryptionKey :: ByteString -> (Integer, Integer, Integer)
decodeRSADecryptionKey bs = (byteStringToIntegerBE dbs, byteStringToIntegerBE pbs, byteStringToIntegerBE qbs)
  where (dbs, rest) = BS.splitAt 2048 bs
        (pbs, qbs) = BS.splitAt 2048 rest

encodeRSAEncryptionKey :: (Integer, Integer) -> ByteString
encodeRSAEncryptionKey (e, n) = integerToByteStringBE 2048 e <> integerToByteStringBE 2048 n

encodeRSADecryptionKey :: (Integer, Integer, Integer) -> ByteString
encodeRSADecryptionKey (d, p, q) = mconcat [ integerToByteStringBE 2048 d
                                           , integerToByteStringBE 2048 p
                                           , integerToByteStringBE 2048 q
                                           ]

decodeRSAPlaintext :: ByteString -> [Integer]
decodeRSAPlaintext = fmap byteStringToIntegerBE . splitEvery 128

decodeRSACiphertext :: ByteString -> [Integer]
decodeRSACiphertext = fmap byteStringToIntegerBE . splitEvery 2048

encodeRSAPlaintext :: [Integer] -> ByteString
encodeRSAPlaintext = mconcat . integersToByteStringsBE 0

encodeRSACiphertext :: [Integer] -> ByteString
encodeRSACiphertext = mconcat . integersToByteStringsBE 2048

-- | Generate a RSA private key using Miller-Rabin.
generatePrivateKeyRSA :: RandomGen g => g -> (ByteString, g)
generatePrivateKeyRSA gen = if p == q
                            then generatePrivateKeyRSA gen''
                            else (encodeRSADecryptionKey (d, p, q), gen''')
  where (p, gen') = genPrimeBits gen 1024
        (q, gen'') = genPrimeBits gen' 1024
        (d, gen''') = genCoprime gen'' $ carmichaelTotient p q

-- | Derive a public key from an RSA private key.
derivePublicKeyRSA :: ByteString -> ByteString
derivePublicKeyRSA bs = case decodeRSADecryptionKey bs of
  (d, p, q) -> encodeRSAEncryptionKey (modInv d $ carmichaelTotient p q, p * q)

encryptRSA :: (Integer, Integer) -> [Integer] -> [Integer]
encryptRSA (e, n) ms = (\m -> modExp m e n) <$> ms

decryptRSA :: (Integer, Integer, Integer) -> [Integer] -> [Integer]
decryptRSA (d, p, q) cs = (\c -> modExp c d (p * q)) <$> cs
