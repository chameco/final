module Final.Cipher.ChaCha20 where

import Control.Exception.Safe
import Control.Arrow (first)

import Data.Word
import Data.Bits
-- import Data.Binary
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Vector (Vector, (!))
import qualified Data.Vector as V

import System.Endian (toBE32)

import Final.Cipher
import Final.Utility.ByteString

-- instance Binary a => Binary (Vector a) where
--   put = put . V.toList
--   get = V.fromList <$> get

quarterRound :: (Word32, Word32, Word32, Word32) -> (Word32, Word32, Word32, Word32)
quarterRound (a, b, c, d) = (a'', b'''', c'', d'''')
  where a' = a + b; d' = d `xor` a'; d'' = d' `rotateL` 16
        c' = c + d''; b' = b `xor` c'; b'' = b' `rotateL` 12
        a'' = a' + b''; d''' = d''`xor` a''; d'''' = d''' `rotateL` 8
        c'' = c' + d''''; b''' = b'' `xor` c''; b'''' = b''' `rotateL` 7

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
chaChaBlock input = V.zipWith (+) x $ foldr1 (.) (replicate 10 chaChaRound) x
  where x :: Vector Word32
        x = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] <> input

chaChaZipXor :: [Word8] -> [Word32] -> [Word8]
chaChaZipXor (x1:x2:x3:x4:xs) (y:ys) = zipWith xor [x1, x2, x3, x4] (unmergeWordLE y) ++ chaChaZipXor xs ys
chaChaZipXor (x1:x2:x3:xs) (y:ys) = zipWith xor [x1, x2, x3] (unmergeWordLE y) ++ chaChaZipXor xs ys
chaChaZipXor (x1:x2:xs) (y:ys) = zipWith xor [x1, x2] (unmergeWordLE y) ++ chaChaZipXor xs ys
chaChaZipXor (x1:xs) (y:ys) = zipWith xor [x1] (unmergeWordLE y) ++ chaChaZipXor xs ys
chaChaZipXor _ _ = []

chaChaEncrypt :: Vector Word32 -> Word32 -> Vector Word32 -> [[Word8]] -> [[Word8]]
chaChaEncrypt key counter nonce plaintext =
  (\(i, block) -> chaChaZipXor block . V.toList . chaChaBlock . V.fromList . unpackWord32LE . packWord32BE . V.toList $ mconcat [key, [toBE32 (counter + i)], nonce])
  <$> zip [0..] plaintext

unpackPartialWord32 :: ByteString -> [Word32]
unpackPartialWord32 = go . BS.unpack
  where go (a:b:c:d:xs) = mergeWordsLE a b c d:go xs
        go (a:b:c:xs) = (shiftL (fromIntegral a) 24 .|. shiftL (fromIntegral b) 16 .|. shiftL (fromIntegral c) 8):go xs
        go (a:b:xs) = (shiftL (fromIntegral a) 24 .|. shiftL (fromIntegral b) 16):go xs
        go (a:xs) = shiftL (fromIntegral a) 24:go xs
        go [] = []

chaChaParseMessage :: MonadThrow m => ByteString -> m [[Word8]]
chaChaParseMessage = pure . fmap BS.unpack . splitEvery 64

chaChaRenderMessage :: [[Word8]] -> ByteString
chaChaRenderMessage = BS.pack . mconcat

chaChaParseNonce :: MonadThrow m => ByteString -> m (Vector Word32)
chaChaParseNonce d = if BS.length d == 12
                     then pure . V.fromList $ unpackWord32LE d
                     else throwString "Invalid ChaCha20 nonce"

chaChaParseKey :: MonadThrow m => ByteString -> m (Vector Word32)
chaChaParseKey d = if BS.length d == 32
                   then pure . V.fromList $ unpackWord32LE d
                   else throwString "Invalid ChaCha20 key"

chaChaRenderKey :: Vector Word32 -> ByteString
chaChaRenderKey = packWord32LE . V.toList

poly1305DeriveKey :: Vector Word32 -> Vector Word32 -> (Vector Word32, Vector Word32)
poly1305DeriveKey key nonce = V.splitAt 4 . V.take 8 . chaChaBlock . V.fromList . unpackWord32LE . packWord32BE . V.toList $ mconcat [key, [0], nonce]

poly1305 :: (Vector Word32, Vector Word32) -> ByteString -> ByteString
poly1305 (rv, sv) = serialize . accumulate 0 . align
  where p :: Integer
        p = 0x3fffffffffffffffffffffffffffffffb
        r :: Integer
        r = (byteStringToIntegerLE . packWord32BE $ V.toList rv) .&. 0x0ffffffc0ffffffc0ffffffc0fffffff
        s :: Integer
        s = byteStringToIntegerLE . packWord32BE $ V.toList sv
        align :: ByteString -> [Integer]
        align = fmap (byteStringToIntegerLE . BS.pack . (<>[0x01]) . BS.unpack)  . splitEvery 16
        accumulate :: Integer -> [Integer] -> Integer
        accumulate = foldl (\a n -> mod ((a + n) * r) p)
        serialize :: Integer -> ByteString
        serialize x = BS.take 16 $ integerToByteStringLE 16 (x + s)

chaCha20Poly1305AEAD :: MonadThrow m => ByteString -> ByteString -> ByteString -> ByteString -> m (ByteString, ByteString)
chaCha20Poly1305AEAD key' nonce' plaintext' aad = do
  key <- chaChaParseKey key'
  nonce <- chaChaParseNonce nonce'
  plaintext <- chaChaParseMessage plaintext'
  let poly1305Key = poly1305DeriveKey key nonce
      ciphertext = chaChaRenderMessage $ chaChaEncrypt key 1 nonce plaintext
      padding1 = BS.pack $ replicate (16 - mod (fromIntegral $ BS.length aad) 16) 0
      padding2 = BS.pack $ replicate (16 - mod (fromIntegral $ BS.length ciphertext) 16) 0
      input = mconcat
        [ aad
        , padding1
        , ciphertext
        , padding2
        , integerToByteStringLE 64 . fromIntegral $ BS.length aad
        , integerToByteStringLE 64 . fromIntegral $ BS.length ciphertext
        ]
      tag = poly1305 poly1305Key input
  pure (ciphertext, tag)

chaCha20Poly1305UnAEAD :: MonadThrow m => ByteString -> ByteString -> (ByteString, ByteString) -> ByteString -> m (Maybe ByteString)
chaCha20Poly1305UnAEAD key' nonce' (ciphertext', tag) aad = do
  key <- chaChaParseKey key'
  nonce <- chaChaParseNonce nonce'
  ciphertext <- chaChaParseMessage ciphertext'
  let poly1305Key = poly1305DeriveKey key nonce
      plaintext = chaChaRenderMessage $ chaChaEncrypt key 1 nonce ciphertext
      padding1 = BS.pack $ replicate (16 - mod (fromIntegral $ BS.length aad) 16) 0
      padding2 = BS.pack $ replicate (16 - mod (fromIntegral $ BS.length ciphertext') 16) 0
      input = mconcat
        [ aad
        , padding1
        , ciphertext'
        , padding2
        , integerToByteStringLE 64 . fromIntegral $ BS.length aad
        , integerToByteStringLE 64 . fromIntegral $ BS.length ciphertext'
        ]
      tag' = poly1305 poly1305Key input
  pure $ if tag == tag'
         then Just plaintext
         else Nothing

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
    , generateDecryptionKey = first (V.fromList . unpackWord32LE) . flip randomByteString 32
    , deriveEncryptionKey = id
    , parseEncryptionKey = chaChaParseKey
    , renderEncryptionKey = chaChaRenderKey
    , parseDecryptionKey = chaChaParseKey
    , renderDecryptionKey = chaChaRenderKey
    , parsePlaintext = chaChaParseMessage
    , renderPlaintext = chaChaRenderMessage
    , parseCiphertext = chaChaParseMessage
    , renderCiphertext = chaChaRenderMessage
    }
