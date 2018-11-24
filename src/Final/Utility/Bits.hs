module Final.Utility.Bits where

import Final.Utility.Natural
import Final.Utility.Vector

type Bits n = Vector Bool n

xorBits :: forall (n :: Natural). Bits n -> Bits n -> Bits n
xorBits Empty Empty = Empty
xorBits (Cons b bs) (Cons b' bs') = Cons (xor b b') $ xorBits bs bs'
  where xor :: Bool -> Bool -> Bool
        xor True False = True
        xor False True = True
        xor _ _ = False
