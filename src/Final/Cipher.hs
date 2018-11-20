module Final.Cipher where

import Data.Kind
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

data Encrypted (a :: Type) :: Type where
  Wrapped :: BS.ByteString -> Encrypted a

class Cipher (a :: Type) where
  type family EncryptionKey (a :: Type) = (b :: Type) | b -> a
  type family DecryptionKey (a :: Type) = (b :: Type) | b -> a
  parseEncryptionKey :: ByteString -> EncryptionKey a
  parseDecryptionKey :: ByteString -> DecryptionKey a
  encrypt :: EncryptionKey a -> ByteString -> ByteString
  decrypt :: DecryptionKey a -> ByteString -> ByteString

data IDSymmetric
instance Cipher IDSymmetric where
  type EncryptionKey IDSymmetric = ()
  type DecryptionKey IDSymmetric = ()
  encrypt _ = BS.reverse
  decrypt _ = BS.reverse

data IDPKC
data E1 = E1
data E2 = E2
instance Cipher IDPKC where
  type EncryptionKey IDPKC = E1
  type DecryptionKey IDPKC = E2
  encrypt _ = id
  decrypt _ = id
  
data CipherAbstract a = CipherAbstract { encrypt_ :: EncryptionKey a -> ByteString -> ByteString
                                       , decrypt_ :: DecryptionKey a -> ByteString -> ByteString
                                       , parseEncryptionKey_ :: ByteString -> EncryptionKey a
                                       , parseDecryptionKey_ :: ByteString -> DecryptionKey a
                                       }

genericEncrypt :: Cipher a => CipherAbstract a -> ByteString -> ByteString -> ByteString
genericEncrypt c = encrypt_ c . parseEncryptionKey_ c

newtype CipherConcrete = CipherConcrete (forall (a :: Type). Cipher a => CipherAbstract a)

-- foo :: CipherConcrete -> ByteString -> ByteString -> ByteString
-- foo (CipherConcrete c) = genericEncrypt c

data CipherMap :: Type where
  None :: CipherMap
  Some :: forall (a :: Type). Cipher a => Int -> CipherAbstract a -> CipherMap -> CipherMap

lookupCipherEncrypt :: CipherMap -> Int -> ByteString -> ByteString -> Maybe ByteString
lookupCipherEncrypt None _ _ _ = Nothing
lookupCipherEncrypt (Some i c rest) i' k d | i == i' = pure $ encrypt_ c (parseEncryptionKey_ c k) d | otherwise = lookupCipherEncrypt rest i' k d

idSymmetricAbstract :: CipherAbstract IDSymmetric
idSymmetricAbstract = CipherAbstract { encrypt_ = encrypt
                                     , decrypt_ = decrypt
                                     , parseEncryptionKey_ = parseEncryptionKey
                                     , parseDecryptionKey_ = parseDecryptionKey
                                     }

idPKCAbstract :: CipherAbstract IDPKC
idPKCAbstract = CipherAbstract { encrypt_ = encrypt
                               , decrypt_ = decrypt
                               , parseEncryptionKey_ = parseEncryptionKey
                               , parseDecryptionKey_ = parseDecryptionKey
                               }

foo :: CipherMap
foo  = Some 1337 idSymmetricAbstract
       . Some 31337 idPKCAbstract
       $ None

bar :: Maybe ByteString
bar = lookupCipherEncrypt foo 1337 "the key" "hello, world"
