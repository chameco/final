module Final.Utility.Vector where

import Data.Binary
import Data.Kind (Type)
import Data.Singletons

import Final.Utility.Natural
import Final.Utility.Finite

data Vector (a :: Type) :: Natural -> Type where
  Empty :: forall (a :: Type). Vector a 'Zero
  Cons :: forall (a :: Type) (n :: Natural). a -> Vector a n -> Vector a ('Successor n)
deriving instance forall (a :: Type) (n :: Natural). Show a => Show (Vector a n)
deriving instance forall (a :: Type) (n :: Natural). Eq a => Eq (Vector a n)
deriving instance forall (a :: Type) (n :: Natural). Ord a => Ord (Vector a n)

instance forall (n :: Natural) (a :: Type). Binary a => Binary (Vector a n) where
  put = put . toList
  get = undefined

toList :: forall (n :: Natural) (a :: Type). Vector a n -> [a]
toList Empty = []
toList (Cons x rest) = x : toList rest

replicate :: forall (a :: Type) (n :: Natural). SingI n => a -> Vector a n
replicate a = replicate_ sing
  where
    replicate_ :: forall (m :: Natural). SNatural m -> Vector a m
    replicate_ SZero = Empty
    replicate_ (SSuccessor n) = Cons a $ replicate_ n

fromList :: forall (a :: Type) (n :: Natural). SingI n => [a] -> Vector a n
fromList = fromList_ sing
  where
    fromList_ :: forall (m :: Natural). SNatural m -> [a] -> Vector a m
    fromList_ SZero _ = Empty
    fromList_ _ [] = error "Not enough elements to construct the vector"
    fromList_ (SSuccessor n) (x:xs) = Cons x $ fromList_ n xs

lengthVector :: forall (n :: Natural) (a :: Type). Vector a n -> Int
lengthVector Empty = 0
lengthVector (Cons _ bs) = 1 + lengthVector bs

indexVector :: forall (n :: Natural) (a :: Type). Finite n -> Vector a n -> a
indexVector One (Cons b _) = b
indexVector (Also x) (Cons _ bs) = indexVector x bs

concatVector :: forall (n :: Natural) (m :: Natural) (a :: Type). Vector a n -> Vector a m -> Vector a (Add m n)
concatVector Empty x = x
concatVector (Cons b bs) x = Cons b $ concatVector bs x

popVector :: forall (n :: Natural) (a :: Type). Vector a ('Successor n) -> Vector a n
popVector (Cons _ bs) = bs

splitVector4 :: forall (a :: Type). Vector a Four -> (Vector a Two, Vector a Two)
splitVector4 (Cons a (Cons b rest)) = (Cons a $ Cons b Empty, rest)

splitVector8 :: forall (a :: Type). Vector a Eight -> (Vector a Four, Vector a Four)
splitVector8 (Cons a (Cons b (Cons c (Cons d rest)))) = (Cons a . Cons b . Cons c $ Cons d Empty, rest)

splitVector10 :: forall (a :: Type). Vector a Ten -> (Vector a Five, Vector a Five)
splitVector10 (Cons a (Cons b (Cons c (Cons d (Cons e rest))))) = (Cons a . Cons b . Cons c . Cons d $ Cons e Empty, rest)
