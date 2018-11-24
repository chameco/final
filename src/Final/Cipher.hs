{-# LANGUAGE UndecidableInstances #-}
{-
This module contains definitions for type-level crypto-systems (symmetric and public).
-}
module Final.Cipher
  ( Implementation(..)
  , Cipher, EncryptionKey, DecryptionKey, Plaintext, Ciphertext, Impl, impl, name
  , Lookup(..)
  , constructLookup, usingCipher, encryptWithCipher, decryptWithCipher
  ) where

import Data.Kind
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS
import Data.Text (Text)

import System.Random

-- TODO Maybe move ErrorMessage contents to type level?
type ErrorMessage = ByteString

-- | An implementation of a @Cipher a@ with @EncryptionKey e@, @DecryptionKey d@, @Plaintext p@, and @Ciphertext c@
data Implementation (a :: Type) (e :: Type) (d :: Type) (p :: Type) (c :: Type) = Implementation
  { encrypt :: e -> p -> c
  , decrypt :: d -> c -> p
  , generateDecryptionKey :: forall (g :: Type). RandomGen g => g -> (d, g)
  , deriveEncryptionKey :: d -> e
  , parseEncryptionKey :: ByteString -> Either ErrorMessage e
  , renderEncryptionKey :: e -> ByteString
  , parseDecryptionKey :: ByteString -> Either ErrorMessage d
  , renderDecryptionKey :: d -> ByteString
  , parsePlaintext :: ByteString -> Either ErrorMessage p
  , renderPlaintext :: p -> ByteString
  , parseCiphertext :: ByteString -> Either ErrorMessage c
  , renderCiphertext :: c -> ByteString
  }

-- | A wrapper to shorten 'Implementation' types
type Impl a = Implementation a (EncryptionKey a) (DecryptionKey a) (Plaintext a) (Ciphertext a)

-- | Complete crypto-systems with corresponding encryption/decryption keys,
-- plain/ciphertexts, and implementation.
class Cipher (a :: Type) where
  -- | The encryption key type for a specific 'Cipher'
  type family EncryptionKey a :: Type
  -- | The decryption key type for a specific 'Cipher'
  type family DecryptionKey a :: Type
  -- | The plaintext type for a specific 'Cipher'
  type family Plaintext a :: Type
  -- | The ciphertext type for a specific 'Cipher'
  type family Ciphertext a :: Type
  -- | The default name of a 'Cipher', should be unique
  name :: Text
  -- | The concrete 'Implementation' of a cipher
  impl :: Impl a

-- | A GADT representing a list of 'Cipher's
data Lookup :: Type -> Type where
  None :: forall (k :: Type). Eq k => Lookup k
  Some :: forall (k :: Type) (a :: Type).
    (Cipher a, Eq k) => k -> Impl a -> Lookup k -> Lookup k

instance Show k => Show (Lookup k) where
  show None = "|"
  show (Some k _ rest) = '|' : mconcat [show k, ", ", show rest]

-- | A helper function to construct a Lookup using the default Cipher name
-- > constructLookup @IDPKC None == Lookup "IDPKC" (impl :: Impl IDPKC) None
constructLookup :: forall a. Cipher a => Lookup Text -> Lookup Text
constructLookup = Some (name @a) (impl @a)

-- | Applies the given function to the corresponding cipher if present
-- > (fromJust $ usingCipher table "IDSymmetric" encryptWithCipher) "the key" "hello, world" == Right "dlrow ,olleh"
usingCipher :: Eq k => Lookup k -> k -> (forall a. Cipher a => Impl a -> b) -> Maybe b
usingCipher None _ _ = Nothing
usingCipher (Some i c rest) i' f
  | i == i' = pure $ f c
  | otherwise = usingCipher rest i' f

-- | Using the given cipher create an encryption function that parses the given key and message and returns
-- either an error or the encrypted ByteString
encryptWithCipher :: Cipher a => Impl a -> ByteString -> ByteString -> Either ErrorMessage ByteString
encryptWithCipher cipher k m = fmap (renderCiphertext cipher) $ encrypt cipher <$> key <*> msg
  where
    key = parseEncryptionKey cipher k
    msg = parsePlaintext cipher m

-- | Using the given cipher create an decryption function that parses the given key and message and returns
-- either an error or the decrypted ByteString
decryptWithCipher :: Cipher a => Impl a -> ByteString -> ByteString -> Either ErrorMessage ByteString
decryptWithCipher cipher k m = fmap (renderPlaintext cipher) $ decrypt cipher <$> key <*> msg
  where
    key = parseDecryptionKey cipher k
    msg = parseCiphertext cipher m

data IDSymmetric
instance Cipher IDSymmetric where
  type EncryptionKey IDSymmetric = ()
  type DecryptionKey IDSymmetric = ()
  type Plaintext IDSymmetric = ByteString
  type Ciphertext IDSymmetric = ByteString
  name = "IDSymmetric"
  impl = Implementation
    { encrypt = const BS.reverse
    , decrypt = const BS.reverse
    , generateDecryptionKey = ((),)
    , deriveEncryptionKey = id
    , parseEncryptionKey = Right . const ()
    , renderEncryptionKey = undefined
    , parseDecryptionKey = Right . const ()
    , renderDecryptionKey = undefined
    , parsePlaintext = Right
    , renderPlaintext = id
    , parseCiphertext = Right
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
  name = "IDPKC"
  impl = Implementation
    { encrypt = const id
    , decrypt = const id
    , generateDecryptionKey = (E2,)
    , deriveEncryptionKey = const E1
    , parseEncryptionKey = Right . const E1
    , renderEncryptionKey = undefined
    , parseDecryptionKey = Right . const E2
    , renderDecryptionKey = undefined
    , parsePlaintext = Right
    , renderPlaintext = id
    , parseCiphertext = Right
    , renderCiphertext = id
    }

