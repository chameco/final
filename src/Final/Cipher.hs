{-# LANGUAGE UndecidableInstances #-}

module Final.Cipher
  ( Implementation(..)
  , Cipher, Impl, impl
  , Lookup(..)
  , encryptWith, decryptWith
  ) where

import Data.Kind
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)

data Implementation (a :: Type) (e :: Type) (d :: Type) (p :: Type) (c :: Type) = Implementation
  { encrypt :: e -> p -> c
  , decrypt :: d -> c -> p
  , parseEncryptionKey :: ByteString -> e
  , parseDecryptionKey :: ByteString -> d
  , parsePlaintext :: ByteString -> p
  , renderPlaintext :: p -> ByteString
  , parseCiphertext :: ByteString -> c
  , renderCiphertext :: c -> ByteString
  }

class Cipher (a :: Type) where
  type family EncryptionKey a :: Type
  type family DecryptionKey a :: Type
  type family Plaintext a :: Type
  type family Ciphertext a :: Type
  type family Impl a :: Type
  type Impl a = Implementation a (EncryptionKey a) (DecryptionKey a) (Plaintext a) (Ciphertext a)
  impl :: Implementation a (EncryptionKey a) (DecryptionKey a) (Plaintext a) (Ciphertext a)

data Lookup :: Type -> Type where
  None :: forall (k :: Type). Eq k => Lookup k
  Some :: forall (k :: Type) (a :: Type) (e :: Type) (d :: Type) (p :: Type) (c :: Type).
    Eq k => k -> Implementation a e d p c -> Lookup k -> Lookup k

encryptWith :: Eq k => Lookup k -> k -> ByteString -> ByteString -> Maybe ByteString
encryptWith None _ _ _ = Nothing
encryptWith (Some i c rest) i' key x
  | i == i' = pure . renderCiphertext c . encrypt c (parseEncryptionKey c key) $ parsePlaintext c x
  | otherwise = encryptWith rest i' key x

decryptWith :: Eq k => Lookup k -> k -> ByteString -> ByteString -> Maybe ByteString
decryptWith None _ _ _ = Nothing
decryptWith (Some i c rest) i' key x
  | i == i' = pure . renderPlaintext c . decrypt c (parseDecryptionKey c key) $ parseCiphertext c x
  | otherwise = encryptWith rest i' key x

data IDSymmetric
instance Cipher IDSymmetric where
  type EncryptionKey IDSymmetric = ()
  type DecryptionKey IDSymmetric = ()
  type Plaintext IDSymmetric = ByteString
  type Ciphertext IDSymmetric = ByteString
  impl = Implementation
    { encrypt = const BS.reverse
    , decrypt = const BS.reverse
    , parseEncryptionKey = const ()
    , parseDecryptionKey = const ()
    , parsePlaintext = id
    , renderPlaintext = id
    , parseCiphertext = id
    , renderCiphertext = id
    }

data IDPKC
data E1 = E1
data E2 = E2
instance Cipher IDPKC where
  type EncryptionKey IDPKC = E1
  type DecryptionKey IDPKC = E2
  type Plaintext IDPKC = ByteString
  type Ciphertext IDPKC = ByteString
  impl = Implementation
    { encrypt = const id
    , decrypt = const id
    , parseEncryptionKey = const E1
    , parseDecryptionKey = const E2
    , parsePlaintext = id
    , renderPlaintext = id
    , parseCiphertext = id
    , renderCiphertext = id
    }

foo :: Lookup Text
foo = Some "IDSymmetric" (impl :: Impl IDSymmetric)
      . Some "IDPKC" (impl :: Impl IDPKC)
      $ None

bar :: Maybe ByteString 
bar = encryptWith foo "IDSymmetric" "the key" "hello, world"
