module Final.Cipher.ChaCha20 where

import Control.Exception.Safe

import Data.Word
import Data.Bits
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Vector (Vector, (!))
import qualified Data.Vector as V

import Final.Cipher
import Final.Utility.ByteString

quarterRound :: (Word32, Word32, Word32, Word32) -> (Word32, Word32, Word32, Word32)
quarterRound (a, b, c, d) = (a'', b'''', c'', d'''')
  where a' = a + b; d' = d `xor` a'; d'' = d' `rotateL` 16
        c' = c + d; b' = b `xor` c'; b'' = b' `rotateL` 12
        a'' = a' + b''; d''' = d''`xor` a; d'''' = d''' `rotateL` 8
        c'' = c' + d''''; b''' = b `xor` c; b'''' = b''' `rotateL` 7

chaChaRound :: Vector Word32 -> Vector Word32
chaChaRound x = V.fromList [x0', x1', x2', x3', x4', x5', x6', x7'
                           , x8', x9', x10', x11', x12', x13', x14', x15']
  where (x0, x4, x8, x12) = quarterRound (x ! 0, x ! 4, x ! 8, x ! 12)
        (x1, x5, x9, x13) = quarterRound (x ! 1, x ! 5, x ! 9, x ! 13)
        (x2, x6, x10, x14) = quarterRound (x ! 2, x ! 6, x ! 10, x ! 14)
        (x3, x7, x11, x15) = quarterRound (x ! 3, x ! 7, x ! 11, x ! 15)
        (x0', x5', x10', x15') = quarterRound (x0, x5, x10, x15)
        (x1', x6', x11', x12') = quarterRound (x1, x6, x11, x12)
        (x2', x7', x8', x13') = quarterRound (x2, x7, x8, x13)
        (x3', x4', x9', x14') = quarterRound (x3, x4, x9, x14)

chaChaBlock :: Vector Word32 -> Vector Word32
chaChaBlock input = V.zipWith (+) x $ go 0 x  
  where go :: Int -> Vector Word32 -> Vector Word32
        go i | i >= 10 = id
             | otherwise = go (i + 1) . chaChaRound
        x :: Vector Word32
        x = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] <> input

chaChaZipXor :: [Word8] -> [Word32] -> [Word8]
chaChaZipXor (x1:x2:x3:x4:xs) (y:ys) = zipWith xor [x1, x2, x3, x4] (unmergeWord y) ++ chaChaZipXor xs ys
chaChaZipXor (x1:x2:x3:xs) (y:ys) = zipWith xor [x1, x2, x3] (unmergeWord y) ++ chaChaZipXor xs ys
chaChaZipXor (x1:x2:xs) (y:ys) = zipWith xor [x1, x2] (unmergeWord y) ++ chaChaZipXor xs ys
chaChaZipXor (x1:xs) (y:ys) = zipWith xor [x1] (unmergeWord y) ++ chaChaZipXor xs ys
chaChaZipXor _ _ = []

chaChaEncrypt :: Vector Word32 -> Word32 -> Vector Word32 -> [[Word8]] -> [[Word8]]
chaChaEncrypt key counter nonce plaintext =
  (\(i, block) -> chaChaZipXor block . V.toList . chaChaBlock $ key <> [counter + i] <> nonce)
  <$> zip [0..] plaintext

unpackPartialWord32 :: ByteString -> [Word32]
unpackPartialWord32 = go . BS.unpack
  where go (a:b:c:d:xs) = mergeWords a b c d:go xs
        go (a:b:c:xs) = (shiftL (fromIntegral a) 24 .|. shiftL (fromIntegral b) 16 .|. shiftL (fromIntegral c) 8):go xs
        go (a:b:xs) = (shiftL (fromIntegral a) 24 .|. shiftL (fromIntegral b) 16):go xs
        go (a:xs) = shiftL (fromIntegral a) 24:go xs
        go [] = []

parseMessage :: MonadThrow m => ByteString -> m [[Word8]]
parseMessage = pure . fmap BS.unpack . splitEvery 64

renderMessage :: [[Word8]] -> ByteString
renderMessage = BS.pack . mconcat

data ChaCha20
instance Cipher ChaCha20 where
  type EncryptionKey ChaCha20 = Vector Word32
  type DecryptionKey ChaCha20 = Vector Word32
  type Plaintext ChaCha20 = [[Word8]]
  type Ciphertext ChaCha20 = [[Word8]]
  name = "ChaCha20"
  impl = Implementation
    { encrypt = \k -> chaChaEncrypt k 0 [0, 0, 0] -- TODO: Increment nonce
    , decrypt = \k -> chaChaEncrypt k 0 [0, 0, 0]
    , generateDecryptionKey = undefined
    , deriveEncryptionKey = id
    , parseEncryptionKey = pure . V.fromList . unpackWord32
    , renderEncryptionKey = BS.pack . concatMap unmergeWord . V.toList
    , parseDecryptionKey = pure . V.fromList . unpackWord32
    , renderDecryptionKey = BS.pack . concatMap unmergeWord . V.toList
    , parsePlaintext = parseMessage
    , renderPlaintext = renderMessage
    , parseCiphertext = parseMessage
    , renderCiphertext = renderMessage
    }
