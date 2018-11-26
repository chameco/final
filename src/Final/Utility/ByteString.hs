module Final.Utility.ByteString where

import Data.Word (Word8)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

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
