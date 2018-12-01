{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE TemplateHaskell      #-}

module Final.Utility.Natural where

import Data.Kind (Type)
import Data.Singletons.TH

$(singletons [d|
  data Natural :: Type where
    Zero :: Natural
    Successor :: Natural -> Natural
    deriving (Show, Eq)
  |])

natValue :: forall (n :: Natural). SingI n => Int
natValue = natValue_ (sing :: Sing n)
  where
    natValue_ :: forall (m :: Natural). SNatural m -> Int
    natValue_ = \case
      SZero -> 0
      SSuccessor n -> succ $ natValue_ n

type family Add x y :: Natural where
  Add x 'Zero = x
  Add x ('Successor y) = 'Successor (Add x y)

type family Sub x y :: Natural where
  Sub x 'Zero = x
  Sub 'Zero y = 'Zero
  Sub ('Successor x) ('Successor y) = Sub x y

type family Mul x y :: Natural where
  Mul x 'Zero = 'Zero
  Mul x ('Successor y) = Add x (Mul x y)

type One = 'Successor 'Zero
type Two = 'Successor One
type Three = 'Successor Two
type Four = 'Successor Three
type Five = 'Successor Four
type Six = 'Successor Five
type Seven = 'Successor Six
type Eight = 'Successor Seven
type Nine = 'Successor Eight
type Ten = 'Successor Nine
