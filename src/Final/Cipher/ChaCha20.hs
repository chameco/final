{-|
Implement the ChaCha20-Poly1305 AEAD as described in RFC 7539.
|-}
module Final.Cipher.ChaCha20 where

import Control.Exception.Safe

import Data.Word
import Data.Bits
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Vector (Vector, (!))
import qualified Data.Vector as V

import System.Endian (toBE32)

import Final.Utility.ByteString

-- | Perform a single ChaCha20 quarter-round.
quarterRound :: (Word32, Word32, Word32, Word32) -> (Word32, Word32, Word32, Word32)
quarterRound (a, b, c, d) = (a'', b'''', c'', d'''')
  where a' = a + b; d' = d `xor` a'; d'' = d' `rotateL` 16
        c' = c + d''; b' = b `xor` c'; b'' = b' `rotateL` 12
        a'' = a' + b''; d''' = d''`xor` a''; d'''' = d''' `rotateL` 8
        c'' = c' + d''''; b''' = b'' `xor` c''; b'''' = b''' `rotateL` 7

-- | Perform an entire ChaCha20 double round, consisting of eight quarter-rounds.
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

-- | Compute the entire 20-round ChaCha20 block.
chaChaBlock :: Vector Word32 -> Vector Word32
chaChaBlock input = V.zipWith (+) x $ foldr1 (.) (replicate 10 chaChaRound) x
  where x :: Vector Word32
        x = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] <> input

-- | Combine plaintext with ChaCha20 keystream.
chaChaZipXor :: [Word8] -> [Word32] -> [Word8]
chaChaZipXor (x1:x2:x3:x4:xs) (y:ys) = zipWith xor [x1, x2, x3, x4] (unmergeWordLE y) ++ chaChaZipXor xs ys
chaChaZipXor (x1:x2:x3:xs) (y:ys) = zipWith xor [x1, x2, x3] (unmergeWordLE y) ++ chaChaZipXor xs ys
chaChaZipXor (x1:x2:xs) (y:ys) = zipWith xor [x1, x2] (unmergeWordLE y) ++ chaChaZipXor xs ys
chaChaZipXor (x1:xs) (y:ys) = zipWith xor [x1] (unmergeWordLE y) ++ chaChaZipXor xs ys
chaChaZipXor _ _ = []

-- | Encrypt a plaintext using ChaCha20 with the given key, nonce, and block counter.
chaChaEncrypt :: Vector Word32 -> Word32 -> Vector Word32 -> [[Word8]] -> [[Word8]]
chaChaEncrypt key counter nonce plaintext =
  (\(i, block) -> chaChaZipXor block . V.toList . chaChaBlock . V.fromList . unpackWord32LE . packWord32BE . V.toList $ mconcat [key, [toBE32 (counter + i)], nonce])
  <$> zip [0..] plaintext

-- | Derive a Poly1305 key from a ChaCha20 key and nonce as described in section 2.6 of RFC 7539.
poly1305DeriveKey :: Vector Word32 -> Vector Word32 -> (Vector Word32, Vector Word32)
poly1305DeriveKey key nonce = V.splitAt 4 . V.take 8 . chaChaBlock . V.fromList . unpackWord32LE . packWord32BE . V.toList $ mconcat [key, [0], nonce]

-- | Compute MAC with Poly1305.
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

chaChaDecodeMessage :: MonadThrow m => ByteString -> m [[Word8]]
chaChaDecodeMessage = pure . fmap BS.unpack . splitEvery 64

chaChaEncodeMessage :: [[Word8]] -> ByteString
chaChaEncodeMessage = BS.pack . mconcat

chaChaDecodeNonce :: MonadThrow m => ByteString -> m (Vector Word32)
chaChaDecodeNonce d = if BS.length d == 12
                      then pure . V.fromList $ unpackWord32LE d
                      else throwString "Invalid ChaCha20 nonce"

chaChaDecodeKey :: MonadThrow m => ByteString -> m (Vector Word32)
chaChaDecodeKey d = if BS.length d == 32
                    then pure . V.fromList $ unpackWord32LE d
                    else throwString "Invalid ChaCha20 key"

-- | Encrypt and tag a message using the ChaCha20-Poly1305 AEAD.
chaCha20Poly1305AEAD :: MonadThrow m => ByteString -> ByteString -> ByteString -> ByteString -> m (ByteString, ByteString)
chaCha20Poly1305AEAD key' nonce' plaintext' aad = do
  key <- chaChaDecodeKey key'
  nonce <- chaChaDecodeNonce nonce'
  plaintext <- chaChaDecodeMessage plaintext'
  let poly1305Key = poly1305DeriveKey key nonce
      ciphertext = chaChaEncodeMessage $ chaChaEncrypt key 1 nonce plaintext
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

-- | Decrypt and verify a tagged message using the ChaCha20-Poly1305 AEAD.
chaCha20Poly1305UnAEAD :: MonadThrow m => ByteString -> ByteString -> (ByteString, ByteString) -> ByteString -> m (Maybe ByteString)
chaCha20Poly1305UnAEAD key' nonce' (ciphertext', tag) aad = do
  key <- chaChaDecodeKey key'
  nonce <- chaChaDecodeNonce nonce'
  ciphertext <- chaChaDecodeMessage ciphertext'
  let poly1305Key = poly1305DeriveKey key nonce
      plaintext = chaChaEncodeMessage $ chaChaEncrypt key 1 nonce ciphertext
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
