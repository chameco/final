{-# LANGUAGE UndecidableInstances #-}

module Final.Hash
  ( Implementation(..)
  , Hash, Impl, impl
  , Lookup(..)
  , hashWith
  ) where

import Data.Kind
import Data.ByteString (ByteString)

data Implementation (a :: Type) (p :: Type) (h :: Type) = Implementation
  { hash :: p -> h
  , parsePlaintext :: ByteString -> p
  , renderHashtext :: h -> ByteString
  }

class Hash (a :: Type) where
  type family Plaintext a :: Type
  type family Hashtext a :: Type
  type family Impl a :: Type
  type Impl a = Implementation a (Plaintext a) (Hashtext a)
  impl :: Implementation a (Plaintext a) (Hashtext a)

data Lookup (k :: Type) :: Type where
  NoHash :: forall (k :: Type). Eq k => Lookup k
  SomeHash :: forall (k :: Type) (a :: Type) (p :: Type) (h :: Type).
    Eq k => k -> Implementation a p h -> Lookup k -> Lookup k

hashWith :: Eq k => Lookup k -> k -> ByteString -> Maybe ByteString
hashWith NoHash _ _ = Nothing
hashWith (SomeHash i c rest) i' d
  | i == i' = pure . renderHashtext c . hash c $ parsePlaintext c d
  | otherwise = hashWith rest i' d
