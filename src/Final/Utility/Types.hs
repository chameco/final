{-# LANGUAGE UndecidableInstances #-}

module Final.Utility.Types where

import Data.Kind (Type)

data Bit :: Type where
  Off :: Bit
  On :: Bit
  deriving (Show, Eq)

data Natural :: Type where
  Zero :: Natural
  Successor :: Natural -> Natural
  deriving (Show, Eq)

data SNatural :: Natural -> Type where
  SZero :: SNatural 'Zero
  SSuccessor :: forall (n :: Natural). SNatural n -> SNatural ('Successor n)

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

data Finite :: Natural -> Type where
  One :: forall (n :: Natural). Finite ('Successor n)
  Also :: forall (n :: Natural). Finite n -> Finite ('Successor n)
deriving instance forall (n :: Natural). Show (Finite n)
deriving instance forall (n :: Natural). Eq (Finite n)
