module Final.Cipher.RSA where

import Control.Exception.Safe

import Data.Word (Word8)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import Final.Cipher
import Final.Utility.Modular
import Final.Utility.Prime

throwLeft :: (Exception e, MonadThrow m) => Either e a -> m a
throwLeft (Left e) = throwM e 
throwLeft (Right x) = pure x

byteStringToInteger :: ByteString -> Integer
byteStringToInteger = foldr (\x y -> y * 256 + fromIntegral x) 0 . unpad . BS.unpack
  where unpad (0:bs) = unpad bs
        unpad x = x

integerToByteString :: Int -> Integer -> ByteString
integerToByteString padding = BS.pack . pad . rep
  where rep :: Integer -> [Word8]
        rep 0 = []
        rep n = fromIntegral (rem n 256):rep (quot n 256)
        pad :: [Word8] -> [Word8]
        pad l | length l >= padding = l
              | otherwise = pad (0:l)

splitEvery :: Int -> ByteString -> [ByteString]
splitEvery n bs
  | BS.length bs <= fromIntegral n = [bs]
  | otherwise = case BS.splitAt (fromIntegral n) bs of (x, rest) -> x:splitEvery n rest

integersToByteStrings :: Int -> [Integer] -> [ByteString]
integersToByteStrings _ [] = []
integersToByteStrings _ [x] = [integerToByteString 0 x]
integersToByteStrings padding (x:xs) = integerToByteString padding x:integersToByteStrings padding xs

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
                                     then pure (byteStringToInteger ebs, byteStringToInteger nbs)
                                     else throwString "Invalid RSA encryption key"
    , renderEncryptionKey = \(e, n) -> integerToByteString 2048 e <> integerToByteString 2048 n
    , parseDecryptionKey = \bs -> let (dbs, rest) = BS.splitAt 2048 bs
                                      (pbs, qbs) = BS.splitAt 2048 rest
                                  in if BS.length bs == 3 * 2048
                                     then pure (byteStringToInteger dbs, byteStringToInteger pbs, byteStringToInteger qbs)
                                     else throwString "Invalid RSA decryption key"
    , renderDecryptionKey = \(d, p, q) -> mconcat [ integerToByteString 2048 d
                                                  , integerToByteString 2048 p
                                                  , integerToByteString 2048 q
                                                  ]
    , parsePlaintext = pure . fmap byteStringToInteger . splitEvery 128
    , renderPlaintext = mconcat . integersToByteStrings 0
    , parseCiphertext = pure . fmap byteStringToInteger . splitEvery 2048
    , renderCiphertext = mconcat . integersToByteStrings 2048
    }
