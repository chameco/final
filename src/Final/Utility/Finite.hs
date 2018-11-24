module Final.Utility.Finite where

import Data.Kind (Type)

import Final.Utility.Natural

data Finite :: Natural -> Type where
  One :: forall (n :: Natural). Finite ('Successor n)
  Also :: forall (n :: Natural). Finite n -> Finite ('Successor n)
deriving instance forall (n :: Natural). Show (Finite n)
deriving instance forall (n :: Natural). Eq (Finite n)

f1 :: forall (n :: Natural). Finite ('Successor n)
f1 = One
f2 :: forall (n :: Natural). Finite ('Successor ('Successor n))
f2 = Also f1
f3 :: forall (n :: Natural). Finite ('Successor ('Successor ('Successor n)))
f3 = Also f2
f4 :: forall (n :: Natural). Finite ('Successor ('Successor ('Successor ('Successor n))))
f4 = Also f3
f5 :: forall (n :: Natural). Finite ('Successor ('Successor ('Successor ('Successor ('Successor n)))))
f5 = Also f4
f6 :: forall (n :: Natural). Finite ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor n))))))
f6 = Also f5
f7 :: forall (n :: Natural). Finite ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor n)))))))
f7 = Also f6
f8 :: forall (n :: Natural). Finite ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor n))))))))
f8 = Also f7
f9 :: forall (n :: Natural). Finite ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor n)))))))))
f9 = Also f8
f10 :: forall (n :: Natural). Finite ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor ('Successor n))))))))))
f10 = Also f9
