{-
This module contains an implementation of X25519 as described in RFC 7748.
-}
module Final.Cipher.ECC where

import Data.Bits (shiftL, shiftR, (.&.), (.|.), xor)
import Data.Word (Word8)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import System.Random

import Final.Utility.Modular
import Final.Utility.ByteString

p :: Integer
p = (2 :: Integer)^(255 :: Integer) - 19

decodeLittleEndian :: ByteString -> Integer
decodeLittleEndian = sum . fmap (\(i, x) -> shiftL (fromIntegral x) (8 * i)) . zip [0,1..quot (255 + 7) 8] . BS.unpack

decodeUCoordinate :: ByteString -> Integer
decodeUCoordinate = decodeLittleEndian

encodeUCoordinate :: Integer -> ByteString
encodeUCoordinate u = BS.pack $ fmap (\i -> fromIntegral (shiftR u' (8 * i))) [0,1..quot (255 + 7) 8]
  where u' :: Integer
        u' = mod u p

decodeScalar25519 :: ByteString -> Integer
decodeScalar25519 = decodeLittleEndian . BS.pack . fmap transform . zip [0,1..] . BS.unpack
  where transform :: (Integer, Word8) -> Word8
        transform (0, b) = b .&. 248
        transform (31, b) = (b .&. 127) .|. 64
        transform (_, b) = b

cswap :: Integer -> Integer -> Integer -> (Integer, Integer)
cswap swap x2 x3 = (xor x2 dummy, xor x3 dummy)
  where dummy :: Integer
        dummy = (mask * swap) .&. xor x2 x3
        mask :: Integer
        mask = shiftL 1 512 - 1 

x25519 :: Integer -> Integer -> ByteString
x25519 k u = let (x2, z2, x3, z3, swap) = go (255 - 1) (1, 0, u, 1, 0)
                 (x2', _) = cswap swap x2 x3
                 (z2', _) = cswap swap z2 z3
             in BS.take 32 . encodeUCoordinate $ mod (x2' * modExp z2' (p - 2) p) p
  where x1 :: Integer
        x1 = u
        go :: Int -> (Integer, Integer, Integer, Integer, Integer) -> (Integer, Integer, Integer, Integer, Integer)
        go t (x2, z2, x3, z3, swap)
          | t >= 0 = go (t - 1) (x2'', z2'', x3'', z3'', swap')
          | otherwise = (x2, z2, x3, z3, swap)
          where kt = shiftR k t .&. 1
                (x2', x3') = cswap (xor swap kt) x2 x3
                (z2', z3') = cswap (xor swap kt) z2 z3
                swap' = kt
                a = mod (x2' + z2') p
                aa = modExp a 2 p
                b = mod (x2' - z2') p
                bb = modExp b 2 p
                e = mod (aa - bb) p
                c = mod (x3' + z3') p
                d = mod (x3' - z3') p
                da = mod (d * a) p
                cb = mod (c * b) p
                ff = modExp (mod (da + cb) p) 2 p
                gg = modExp (mod (da - cb) p) 2 p
                x3'' = ff
                z3'' = mod (x1 * gg) p
                x2'' = mod (aa * bb) p
                z2'' = mod (e * mod (aa + mod (121665 * e) p) p) p

generatePrivateKeyECDHE :: RandomGen g => g -> (ByteString, g)
generatePrivateKeyECDHE = flip randomByteString 32

derivePublicKeyECDHE :: ByteString -> ByteString
derivePublicKeyECDHE priv = x25519 (decodeScalar25519 priv) 9

computeSharedSecretECDHE :: ByteString -> ByteString -> ByteString
computeSharedSecretECDHE priv pub = x25519 (decodeScalar25519 priv) (decodeUCoordinate pub)
