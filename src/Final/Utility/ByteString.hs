{-|
Helper functions for working with binary data.
|-}
module Final.Utility.ByteString where

import Control.Arrow (first)

import Data.Kind
import Data.Word (Word8, Word32)
import Data.Bits
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Vector (Vector)
import qualified Data.Vector as V (fromList)

import Numeric (showHex)

import System.Random

rep :: Integer -> [Word8]
rep 0 = []
rep n = fromIntegral (rem n 256):rep (quot n 256)

-- | Convert binary data to an integer, assuming little-endian encoding.
byteStringToIntegerLE :: ByteString -> Integer
byteStringToIntegerLE = foldr (\x y -> y * 256 + fromIntegral x) 0 . unpad . BS.unpack
  where unpad (0:bs) = unpad bs
        unpad x = x

-- | Convert binary data to an integer, assuming big-endian encoding.
byteStringToIntegerBE :: ByteString -> Integer
byteStringToIntegerBE = foldr (\x y -> y * 256 + fromIntegral x) 0 . reverse . unpad . BS.unpack
  where unpad (0:bs) = unpad bs
        unpad x = x

-- | Convert an integer to padded binary data, assuming little-endian encoding.
integerToByteStringLE :: Int -> Integer -> ByteString
integerToByteStringLE padding = BS.pack . pad . rep
  where pad :: [Word8] -> [Word8]
        pad l | length l >= padding = l
              | otherwise = pad (0:l)

-- | Convert an integer to padded binary data, assuming big-endian encoding.
integerToByteStringBE :: Int -> Integer -> ByteString
integerToByteStringBE padding = BS.pack . pad . reverse . rep
  where pad :: [Word8] -> [Word8]
        pad l | length l >= padding = l
              | otherwise = pad (0:l)

-- | Split binary data at the given interval.
splitEvery :: Int -> ByteString -> [ByteString]
splitEvery n bs
  | BS.length bs <= fromIntegral n = [bs]
  | otherwise = case BS.splitAt (fromIntegral n) bs of (x, rest) -> x:splitEvery n rest

-- | Convert several integers to binary data, padding all but the last.
integersToByteStringsBE :: Int -> [Integer] -> [ByteString]
integersToByteStringsBE _ [] = []
integersToByteStringsBE _ [x] = [integerToByteStringBE 0 x]
integersToByteStringsBE padding (x:xs) = integerToByteStringBE padding x:integersToByteStringsBE padding xs

-- | Combine four bytes, assuming they are given in little-endian order.
mergeWordsLE :: Word8 -> Word8 -> Word8 -> Word8 -> Word32
mergeWordsLE a b c d =
  shiftL (fromIntegral d) 24
  .|. shiftL (fromIntegral c) 16
  .|. shiftL (fromIntegral b) 8
  .|. fromIntegral a

-- | Combine four bytes, assuming they are given in big-endian order.
mergeWordsBE :: Word8 -> Word8 -> Word8 -> Word8 -> Word32
mergeWordsBE a b c d =
  shiftL (fromIntegral a) 24
  .|. shiftL (fromIntegral b) 16
  .|. shiftL (fromIntegral c) 8
  .|. fromIntegral d

-- | Split a 32-bit word into four bytes, assuming little-endian encoding.
unmergeWordLE :: Word32 -> [Word8]
unmergeWordLE x =
  fromIntegral
  <$> [ x .&. 0x000000ff
      , shiftR (x .&. 0x0000ff00) 8
      , shiftR (x .&. 0x00ff0000) 16
      , shiftR (x .&. 0xff000000) 24]

-- | Split a 32-bit word into four bytes, assuming big-endian encoding.
unmergeWordBE :: Word32 -> [Word8]
unmergeWordBE x =
  fromIntegral
  <$> [shiftR (x .&. 0xff000000) 24
      , shiftR (x .&. 0x00ff0000) 16
      , shiftR (x .&. 0x0000ff00) 8
      , x .&. 0x000000ff]

-- | Unpack binary data into a list of 32-bit words, assuming little-endian encoding.
unpackWord32LE :: ByteString -> [Word32]
unpackWord32LE = go . BS.unpack
  where go (a:b:c:d:xs) = mergeWordsLE a b c d:go xs
        go _ = []

-- | Unpack binary data into a list of 32-bit words, assuming big-endian encoding.
unpackWord32BE :: ByteString -> [Word32]
unpackWord32BE = go . BS.unpack
  where go (a:b:c:d:xs) = mergeWordsBE a b c d:go xs
        go _ = []

-- | Pack a list of 32-bit words into binary data, assuming little-endian encoding.
packWord32LE :: [Word32] -> ByteString
packWord32LE = BS.pack . concatMap unmergeWordLE

-- | Pack a list of 32-bit words into binary data, assuming big-endian encoding.
packWord32BE :: [Word32] -> ByteString
packWord32BE = BS.pack . concatMap unmergeWordBE

-- | Randomly generate a single byte.
randomWord8 :: RandomGen g => g -> (Word8, g)
randomWord8 = randomR (0, 255)

-- | Randomly generate binary data of the given length.
randomByteString :: forall (g :: Type). RandomGen g => g -> Int -> (ByteString, g)
randomByteString gen = first BS.pack . go gen
  where go :: g -> Int -> ([Word8], g)
        go gen' 0 = ([], gen')
        go gen' n = first (b:) $ go gen'' (n - 1)
          where (b, gen'') = randomWord8 gen'

-- | Pad an input for SHA-1 or SHA256.
padMessage :: ByteString -> [Vector Word32]
padMessage bs = fmap (V.fromList . unpackWord32BE) $ splitEvery 64 $ bs <> padding <> len
  where paddingDiff = 56 - mod (BS.length bs) 64
        paddingLength = fromIntegral $ if paddingDiff <= 0 then 512 - paddingDiff else paddingDiff
        paddingWords = case replicate paddingLength 0 of (x:xs) -> (x .|. 0b10000000):xs; [] -> []
        padding = BS.pack paddingWords
        len = integerToByteStringBE 8
              . flip (mod :: Integer -> Integer -> Integer) (((^) :: Integer -> Integer -> Integer) 2 64)
              . (*8) . fromIntegral $ BS.length bs

-- | Render binary data in hexadecimal.
toHex :: ByteString -> String
toHex = concatMap (pad . ($"") . showHex) . BS.unpack
  where pad [x] = '0':[x]
        pad x = x
