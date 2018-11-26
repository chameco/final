module Final.Hash.SHA1 where

import Numeric (showHex)

import Data.Char (ord)
import Data.Word
import Data.Bits
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Vector (Vector, (!))
import qualified Data.Vector as V

import Final.Hash
import Final.Utility.ByteString

type HashValues = (Word32, Word32, Word32, Word32, Word32)

padMessage :: ByteString -> ByteString
padMessage bs = bs <> padding <> len
  where paddingDiff = 56 - mod (BS.length bs) 64
        paddingLength = fromIntegral $ if paddingDiff <= 0 then 512 - paddingDiff else paddingDiff
        paddingWords = case replicate paddingLength 0 of (x:xs) -> (x .|. 0b10000000):xs; [] -> []
        padding = BS.pack paddingWords
        len = integerToByteString 8 . fromIntegral $ BS.length bs

mergeWords :: Word8 -> Word8 -> Word8 -> Word8 -> Word32
mergeWords a b c d =
  shiftL (fromIntegral a) 24
  .|. shiftL (fromIntegral b) 16
  .|. shiftL (fromIntegral c) 8
  .|. fromIntegral d

unpackWord32 :: ByteString -> [Word32]
unpackWord32 = go . BS.unpack
  where go (a:b:c:d:xs) = mergeWords a b c d:go xs
        go _ = []

hashChunk :: HashValues -> Vector Word32 -> HashValues
hashChunk hs@(h0, h1, h2, h3, h4) msg = (h0 + a, h1 + b, h2 + c, h3 + d, h4 + e)
  where (a, b, c, d, e) = go hs 0
        buildW :: Vector Word32 -> Int -> Vector Word32
        buildW v i
          | i >= 80 = v
          | otherwise = buildW v' (i + 1)
          where v' = v <> V.singleton (rotateL (v ! (i - 3) `xor` v ! (i - 8) `xor` v ! (i - 14) `xor` v ! (i - 16)) 1)
        w :: Vector Word32
        w = buildW msg 16
        processValues :: HashValues -> Int -> Word32 -> Word32 -> HashValues
        processValues (a', b', c', d', e') i f k = (temp, a', rotateL b' 30, c', d')
          where temp = rotateL a' 5 + f + e' + k + (w ! i)
        go :: HashValues -> Int -> HashValues
        go hs'@(_, b', c', d', _) i
          | 0 <= i && i <= 19 = go (processValues hs' i ((b' .&. c') .|. (complement b' .&. d')) 0x5A827999) (i + 1)
          | 20 <= i && i <= 39 = go (processValues hs' i (b' `xor` c' `xor` d') 0x6ED9EBA1) (i + 1)
          | 40 <= i && i <= 59 = go (processValues hs' i ((b' .&. c') .|. (b' .&. d') .|. (c' .&. d')) 0x8F1BBCDC) (i + 1)
          | 60 <= i && i <= 79 = go (processValues hs' i (b' `xor` c' `xor` d') 0xCA62C1D6) (i + 1)
          | otherwise = hs'

mergeHashValues :: HashValues -> Integer
mergeHashValues (h0, h1, h2, h3, h4) =
  shiftL (fromIntegral h0) 128
  .|. shiftL (fromIntegral h1) 96
  .|. shiftL (fromIntegral h2) 64
  .|. shiftL (fromIntegral h3) 32
  .|. fromIntegral h4

data SHA1
instance Hash SHA1 where
  type Plaintext SHA1 = [Vector Word32]
  type Hashtext SHA1 = Integer
  name = "SHA1"
  impl = Implementation
    { hash = mergeHashValues . foldl hashChunk (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    , parsePlaintext = fmap (V.fromList . unpackWord32) . splitEvery 64 . padMessage
    , renderHashtext = BS.pack . fmap (fromIntegral . ord) . ($"") . showHex
    }
