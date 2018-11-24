module Final.Utility.Permutation where

import Data.Kind (Type)

import Final.Utility.Natural
import Final.Utility.Finite
import Final.Utility.Vector

type Permutation n m = Vector (Finite m) n

permuteVector :: forall (a :: Type) (n :: Natural). Permutation n n -> Vector a n -> Vector a n
permuteVector perm bs = go perm
  where go :: forall (m :: Natural). Permutation m n -> Vector a m
        go Empty = Empty
        go (Cons p ps) = Cons (indexVector p bs) $ go ps
