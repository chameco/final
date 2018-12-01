module Final.Utility.ByteString where

import Control.Arrow (first)

import Data.Kind
import Data.Word (Word8, Word32)
import Data.Bits
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import System.Random

byteStringToInteger :: ByteString -> Integer
byteStringToInteger = foldr (\x y -> y * 256 + fromIntegral x) 0 . reverse . unpad . BS.unpack
  where unpad (0:bs) = unpad bs
        unpad x = x

integerToByteString :: Int -> Integer -> ByteString
integerToByteString padding = BS.pack . pad . reverse . rep
  where rep :: Integer -> [Word8]
        rep 0 = []
        rep n = fromIntegral (rem n 256):rep (quot n 256)
        pad :: [Word8] -> [Word8]
        pad l | length l >= padding = l
              | otherwise = pad (0:l)

padByteString :: Int -> ByteString -> ByteString
padByteString padding bs | BS.length bs >= p = bs
                         | otherwise = padByteString padding ("0" <> bs)
  where p = fromIntegral padding

splitEvery :: Int -> ByteString -> [ByteString]
splitEvery n bs
  | BS.length bs <= fromIntegral n = [bs]
  | otherwise = case BS.splitAt (fromIntegral n) bs of (x, rest) -> x:splitEvery n rest

integersToByteStrings :: Int -> [Integer] -> [ByteString]
integersToByteStrings _ [] = []
integersToByteStrings _ [x] = [integerToByteString 0 x]
integersToByteStrings padding (x:xs) = integerToByteString padding x:integersToByteStrings padding xs

mergeWords :: Word8 -> Word8 -> Word8 -> Word8 -> Word32
mergeWords a b c d =
  shiftL (fromIntegral a) 24
  .|. shiftL (fromIntegral b) 16
  .|. shiftL (fromIntegral c) 8
  .|. fromIntegral d

unmergeWord :: Word32 -> [Word8]
unmergeWord x =
  fromIntegral
  <$> [shiftR (x .&. 0xff000000) 24
      , shiftR (x .&. 0x00ff0000) 16
      , shiftR (x .&. 0x0000ff00) 8
      , x .&. 0x000000ff]

unpackWord32 :: ByteString -> [Word32]
unpackWord32 = go . BS.unpack
  where go (a:b:c:d:xs) = mergeWords a b c d:go xs
        go _ = []

packWord32 :: [Word32] -> ByteString
packWord32 = BS.pack . concatMap unmergeWord

randomWord8 :: RandomGen g => g -> (Word8, g)
randomWord8 = randomR (0, 255)

randomByteString :: forall (g :: Type). RandomGen g => g -> Int -> (ByteString, g)
randomByteString gen = first BS.pack . go gen
  where go :: g -> Int -> ([Word8], g)
        go gen' 0 = ([], gen')
        go gen' n = first (b:) $ go gen'' (n - 1)
          where (b, gen'') = randomWord8 gen'
