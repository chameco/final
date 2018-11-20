module Final.Utility.Byte where

import Data.Kind (Type)

import Final.Utility.Types

data Vector (a :: Type) :: Natural -> Type where
  Empty :: forall (a :: Type). Vector a 'Zero
  Cons :: forall (a :: Type) (n :: Natural). a -> Vector a n -> Vector a ('Successor n)
deriving instance forall (a :: Type) (n :: Natural). Show a => Show (Vector a n)
deriving instance forall (a :: Type) (n :: Natural). Eq a => Eq (Vector a n)

type Byte = Vector Bit Eight

xor :: Byte -> Byte -> Byte
xor (Cons x1 (Cons x2 (Cons x3 (Cons x4 (Cons x5 (Cons x6 (Cons x7 (Cons x8 Empty))))))))
  (Cons y1 (Cons y2 (Cons y3 (Cons y4 (Cons y5 (Cons y6 (Cons y7 (Cons y8 Empty))))))))
  = Cons (x x1 y1) $ Cons (x x2 y2) $ Cons (x x3 y3) $ Cons (x x4 y4)
  $ Cons (x x5 y5) $ Cons (x x6 y6) $ Cons (x x7 y7) $ Cons (x x8 y8) Empty
  where x :: Bit -> Bit -> Bit
        x Off Off = Off
        x On On = Off
        x _ _ = On

instance Semigroup Byte where (<>) = xor
