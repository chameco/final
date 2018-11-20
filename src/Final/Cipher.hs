{-# LANGUAGE UndecidableInstances #-}

module Final.Cipher where

import Data.Kind
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

data Implementation_ a e d = Implementation_
  { encrypt_ :: e -> ByteString -> ByteString
  , decrypt_ :: d -> ByteString -> ByteString
  , parseEncryptionKey_ :: ByteString -> e
  , parseDecryptionKey_ :: ByteString -> d
  }

class Cipher (a :: Type) where
  type family EncryptionKey a = (b :: Type) | b -> a
  type family DecryptionKey a = (b :: Type) | b -> a
  type family Implementation a :: Type
  type Implementation a = Implementation_ a (EncryptionKey a) (DecryptionKey a)
  implementation :: Implementation_ a (EncryptionKey a) (DecryptionKey a)

encrypt :: Cipher a => EncryptionKey a -> ByteString -> ByteString
encrypt = encrypt_ implementation
decrypt :: Cipher a => DecryptionKey a -> ByteString -> ByteString
decrypt = decrypt_ implementation
parseEncryptionKey :: Cipher a => ByteString -> EncryptionKey a
parseEncryptionKey = parseEncryptionKey_ implementation
parseDecryptionKey :: Cipher a => ByteString -> DecryptionKey a
parseDecryptionKey = parseDecryptionKey_ implementation

data CipherMap (k :: Type) :: Type where
  NoCipher :: Eq k => CipherMap k
  SomeCipher :: forall (a :: Type) (e :: Type) (d :: Type) (k :: Type). Eq k => k -> Implementation_ a e d -> CipherMap k -> CipherMap k

encryptWith :: Eq k => CipherMap k -> k -> ByteString -> ByteString -> Maybe ByteString
encryptWith NoCipher _ _ _ = Nothing
encryptWith (SomeCipher i c rest) i' k d
  | i == i' = pure $ encrypt_ c (parseEncryptionKey_ c k) d
  | otherwise = encryptWith rest i' k d

data IDSymmetric
instance Cipher IDSymmetric where
  type EncryptionKey IDSymmetric = ()
  type DecryptionKey IDSymmetric = ()
  implementation = Implementation_
    { encrypt_ = const BS.reverse
    , decrypt_ = const BS.reverse
    , parseEncryptionKey_ = const ()
    , parseDecryptionKey_ = const ()
    }

data IDPKC
data E1 = E1
data E2 = E2
instance Cipher IDPKC where
  type EncryptionKey IDPKC = E1
  type DecryptionKey IDPKC = E2
  implementation = Implementation_
    { encrypt_ = const id
    , decrypt_ = const id
    , parseEncryptionKey_ = const E1
    , parseDecryptionKey_ = const E2
    }

foo :: CipherMap Int
foo = SomeCipher 1337 (implementation :: Implementation IDSymmetric)
      . SomeCipher 31337 (implementation :: Implementation IDPKC)
      $ NoCipher

bar :: Maybe ByteString 
bar = encryptWith foo 1337 "the key" "hello, world"
