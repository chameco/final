{-# LANGUAGE UndecidableInstances #-}

module Final.Hash
  ( Implementation(..)
  , Hash, Plaintext, Hashtext, Impl, impl, name
  , Lookup(..)
  , constructLookup, hashWith
  ) where

import Data.Kind
import Data.ByteString.Lazy (ByteString)
import Data.Text (Text)

data Implementation (a :: Type) (p :: Type) (h :: Type) = Implementation
  { hash :: p -> h
  , parsePlaintext :: ByteString -> p
  , renderHashtext :: h -> ByteString
  }

type Impl a = Implementation a (Plaintext a) (Hashtext a)

class Hash (a :: Type) where
  type family Plaintext a :: Type
  type family Hashtext a :: Type
  name :: Text
  impl :: Implementation a (Plaintext a) (Hashtext a)

data Lookup (k :: Type) :: Type where
  None :: forall (k :: Type). Eq k => Lookup k
  Some :: forall (k :: Type) (a :: Type).
    (Hash a, Eq k) => k -> Impl a -> Lookup k -> Lookup k

instance Show k => Show (Lookup k) where
  show None = "|"
  show (Some k _ rest) = '|' : mconcat [show k, ", ", show rest]

constructLookup :: forall a. Hash a => Lookup Text -> Lookup Text
constructLookup = Some (name @a) (impl @a)

hashWith :: Eq k => Lookup k -> k -> ByteString -> Maybe ByteString
hashWith None _ _ = Nothing
hashWith (Some i c rest) i' d
  | i == i' = pure . renderHashtext c . hash c $ parsePlaintext c d
  | otherwise = hashWith rest i' d
