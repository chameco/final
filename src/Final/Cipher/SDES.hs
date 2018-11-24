module Final.Cipher.SDES where

import Control.Arrow
import Control.Exception.Safe

import Data.Kind (Type)
import Data.Char (ord)
import Data.Tuple (swap)
import Data.Word (Word8)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import Final.Cipher
import Final.Utility.Natural
import Final.Utility.Finite
import Final.Utility.Vector
import Final.Utility.Bits
import Final.Utility.Permutation

-- | The initial permutation for SDES.
initialPermutation :: Bits Eight -> Bits Eight
initialPermutation = permuteVector table
  where table :: Permutation Eight Eight
        table = Cons f2 . Cons f6 . Cons f3 . Cons f1 . Cons f4 . Cons f8 . Cons f5 $ Cons f7 Empty

-- | Compute the value of an SDES f-box from a given 8-bit partial key.
fbox :: Bits Eight -> Bits Four -> Bits Four
fbox key = expansionPermutation >>> xorBits key >>> splitVector8 >>> first substitution1 >>> second substitution2 >>> uncurry concatVector >>> finalPermutation
  where expansionPermutation :: Bits Four -> Bits Eight
        expansionPermutation bs = concatVector (permuteVector table1 bs) (permuteVector table2 bs)
          where table1 :: Permutation Four Four
                table1 = Cons f4 . Cons f1 . Cons f2 $ Cons f3 Empty
                table2 :: Permutation Four Four
                table2 = Cons f2 . Cons f3 . Cons f4 $ Cons f1 Empty
        substitution1 :: Bits Four -> Bits Two
        substitution1 (Cons False (Cons False (Cons False (Cons False Empty)))) = Cons False $ Cons True Empty
        substitution1 (Cons False (Cons False (Cons False (Cons True Empty))))  = Cons True  $ Cons True Empty
        substitution1 (Cons False (Cons False (Cons True (Cons False Empty))))  = Cons False $ Cons False Empty
        substitution1 (Cons False (Cons False (Cons True (Cons True Empty))))   = Cons True  $ Cons False Empty
        substitution1 (Cons False (Cons True (Cons False (Cons False Empty))))  = Cons True  $ Cons True Empty
        substitution1 (Cons False (Cons True (Cons False (Cons True Empty))))   = Cons False $ Cons True Empty
        substitution1 (Cons False (Cons True (Cons True (Cons False Empty))))   = Cons True  $ Cons False Empty
        substitution1 (Cons False (Cons True (Cons True (Cons True Empty))))    = Cons False $ Cons False Empty
        substitution1 (Cons True (Cons False (Cons False (Cons False Empty))))  = Cons False $ Cons False Empty
        substitution1 (Cons True (Cons False (Cons False (Cons True Empty))))   = Cons True  $ Cons True Empty
        substitution1 (Cons True (Cons False (Cons True (Cons False Empty))))   = Cons True  $ Cons False Empty
        substitution1 (Cons True (Cons False (Cons True (Cons True Empty))))    = Cons False $ Cons True Empty
        substitution1 (Cons True (Cons True (Cons False (Cons False Empty))))   = Cons False $ Cons True Empty
        substitution1 (Cons True (Cons True (Cons False (Cons True Empty))))    = Cons True  $ Cons True Empty
        substitution1 (Cons True (Cons True (Cons True (Cons False Empty))))    = Cons True  $ Cons True Empty
        substitution1 (Cons True (Cons True (Cons True (Cons True Empty))))     = Cons True  $ Cons False Empty
        substitution2 :: Bits Four -> Bits Two
        substitution2 (Cons False (Cons False (Cons False (Cons False Empty)))) = Cons False $ Cons False Empty
        substitution2 (Cons False (Cons False (Cons False (Cons True Empty))))  = Cons True  $ Cons False Empty
        substitution2 (Cons False (Cons False (Cons True (Cons False Empty))))  = Cons False $ Cons True Empty
        substitution2 (Cons False (Cons False (Cons True (Cons True Empty))))   = Cons False $ Cons False Empty
        substitution2 (Cons False (Cons True (Cons False (Cons False Empty))))  = Cons True  $ Cons False Empty
        substitution2 (Cons False (Cons True (Cons False (Cons True Empty))))   = Cons False $ Cons True Empty
        substitution2 (Cons False (Cons True (Cons True (Cons False Empty))))   = Cons True  $ Cons True Empty
        substitution2 (Cons False (Cons True (Cons True (Cons True Empty))))    = Cons True  $ Cons True Empty
        substitution2 (Cons True (Cons False (Cons False (Cons False Empty))))  = Cons True  $ Cons True Empty
        substitution2 (Cons True (Cons False (Cons False (Cons True Empty))))   = Cons True  $ Cons False Empty
        substitution2 (Cons True (Cons False (Cons True (Cons False Empty))))   = Cons False $ Cons False Empty
        substitution2 (Cons True (Cons False (Cons True (Cons True Empty))))    = Cons False $ Cons True Empty
        substitution2 (Cons True (Cons True (Cons False (Cons False Empty))))   = Cons False $ Cons True Empty
        substitution2 (Cons True (Cons True (Cons False (Cons True Empty))))    = Cons False $ Cons False Empty
        substitution2 (Cons True (Cons True (Cons True (Cons False Empty))))    = Cons False $ Cons False Empty
        substitution2 (Cons True (Cons True (Cons True (Cons True Empty))))     = Cons True  $ Cons True Empty
        finalPermutation :: Bits Four -> Bits Four
        finalPermutation = permuteVector table
          where table :: Permutation Four Four
                table = Cons f2 . Cons f4 . Cons f3 $ Cons f1 Empty

-- | A single round of Feistel transformation given an 8-bit partial key.
feistel :: Bits Eight -> (Bits Four, Bits Four) -> (Bits Four, Bits Four)
feistel key (l, r) = (r, xorBits l (fbox key r))

-- | The final permutation for SDES (undoing the initial permutation).
inverseInitialPermutation :: Bits Eight -> Bits Eight
inverseInitialPermutation = permuteVector table
  where table :: Permutation Eight Eight
        table = Cons f4 . Cons f1 . Cons f3 . Cons f5 . Cons f7 . Cons f2 . Cons f8 $ Cons f6 Empty

-- | Perform SDES given the 8-bit two partial keys.
doSDES :: (Bits Eight, Bits Eight) -> Bits Eight -> Bits Eight
doSDES (k1, k2) = initialPermutation >>> splitVector8 >>> feistel k1 >>> feistel k2 >>> swap >>> uncurry concatVector >>> inverseInitialPermutation

-- | Compute the two 8-bit partial keys from a full 10-bit key.
splitKey :: Bits Ten -> (Bits Eight, Bits Eight)
splitKey key = (first (uncurry concatVector >>> key8Permutation) >>> second (first rotateLeft >>> second rotateLeft >>> uncurry concatVector >>> key8Permutation)) (fives, fives)
  where fives = (key10Permutation >>> splitVector10 >>> first rotateLeft >>> second rotateLeft) key
        key10Permutation :: Bits Ten -> Bits Ten
        key10Permutation = permuteVector table
          where table :: Permutation Ten Ten
                table = Cons f3 . Cons f5 . Cons f2 . Cons f7 . Cons f4 . Cons f10 . Cons f1 . Cons f9 . Cons f8 $ Cons f6 Empty
        key8Permutation :: Bits Ten -> Bits Eight
        key8Permutation = popVector >>> popVector >>> permuteVector table
          where table :: Permutation Eight Eight
                table = Cons f4 . Cons f1 . Cons f5 . Cons f2 . Cons f6 . Cons f3 . Cons f8 $ Cons f7 Empty 
        rotateLeft :: Bits Five -> Bits Five
        rotateLeft (Cons b bs) = concatVector bs (Cons b Empty)

-- | Helper for performing encryption of a byte given a 10-bit key.
encryptSDES :: Bits Ten -> Bits Eight -> Bits Eight
encryptSDES = splitKey >>> doSDES

-- | Helper for performing decryption of a byte given a 10-bit key.
decryptSDES :: Bits Ten -> Bits Eight -> Bits Eight
decryptSDES = splitKey >>> swap >>> doSDES

byteToWord8 :: Bits Eight -> Word8
byteToWord8 bits = go (lengthVector bits - 1) bits
  where go :: forall (n :: Natural). Int -> Bits n -> Word8
        go _ Empty = 0
        go l (Cons b bs) = (if b then 1 else 0) * 2^l + go (l - 1) bs

word8ToByte :: forall (m :: Type -> Type). MonadThrow m => Word8 -> m (Bits Eight)
word8ToByte = extract . pad . reverse . rep
  where rep :: Word8 -> [Bool]
        rep 0 = []
        rep n = (rem n 2 == 1):rep (quot n 2)
        pad :: [Bool] -> [Bool]
        pad l | length l >= 8 = l
              | otherwise = pad (False:l)
        extract :: [Bool] -> m (Bits Eight)
        extract (b1:b2:b3:b4:b5:b6:b7:b8:_) = pure . Cons b1 . Cons b2 . Cons b3 . Cons b4 . Cons b5 . Cons b6 . Cons b7 $ Cons b8 Empty
        extract _ = throwString "Invalid byte"

buildKey :: forall (m :: Type -> Type). MonadThrow m => ByteString -> m (Bits Ten)
buildKey = extract . fmap (== (fromIntegral $ ord '1')) . BS.unpack
  where extract :: [Bool] -> m (Bits Ten)
        extract (b1:b2:b3:b4:b5:b6:b7:b8:b9:b10:_) =
          pure . Cons b1 . Cons b2 . Cons b3 . Cons b4 . Cons b5
          . Cons b6 . Cons b7 . Cons b8 . Cons b9 $ Cons b10 Empty
        extract _ = throwString "Invalid key"

data SDES
instance Cipher SDES where
  type EncryptionKey SDES = Bits Ten
  type DecryptionKey SDES = Bits Ten
  type Plaintext SDES = [Bits Eight]
  type Ciphertext SDES = [Bits Eight]
  name = "SDES"
  impl = Implementation
    { encrypt = \k m -> encryptSDES k <$> m
    , decrypt = \k c -> decryptSDES k <$> c
    , generateDecryptionKey = undefined
    , deriveEncryptionKey = id
    , parseEncryptionKey = buildKey
    , renderEncryptionKey = undefined
    , parseDecryptionKey = buildKey
    , renderDecryptionKey = undefined
    , parsePlaintext = mapM word8ToByte . BS.unpack
    , renderPlaintext = BS.pack . fmap byteToWord8
    , parseCiphertext = mapM word8ToByte . BS.unpack
    , renderCiphertext = BS.pack . fmap byteToWord8
    }
