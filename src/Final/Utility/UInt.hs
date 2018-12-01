module Final.Utility.UInt where

import Data.Bits (testBit)
import Data.Singletons (SingI)
import Final.Utility.Bits
import Final.Utility.Natural
import Final.Utility.Vector
import Prelude hiding (replicate)

newtype UInt (n :: Natural) = UInt (Bits n)
deriving instance forall (n :: Natural). Eq (UInt n)
deriving instance forall (n :: Natural). Ord (UInt n)

zero :: forall (n :: Natural). SingI n => UInt n
zero = UInt $ replicate False

asInteger :: Integral a => (Integer -> Integer -> Integer) -> a -> a -> a
asInteger f a b = fromInteger $ f (toInteger a) (toInteger b)

instance forall (n :: Natural). SingI n => Show (UInt n) where
  show = show . toInteger

instance forall (n :: Natural). SingI n => Num (UInt n) where
  (+) = asInteger (+)
  (*) = asInteger (*)
  abs = id
  signum = const 1
  fromInteger = UInt . fromList . reverse . flip map [0..natValue @n - 1] . testBit
  (-) = asInteger (-)

instance forall (n :: Natural). SingI n => Real (UInt n) where
  toRational = toRational . toInteger

instance forall (n :: Natural). SingI n => Enum (UInt n) where
  toEnum = fromIntegral
  fromEnum = fromIntegral

instance forall (n :: Natural). SingI n => Integral (UInt n) where
  quotRem = undefined -- TODO Implement
  toInteger (UInt n) = foldl (\y x -> y*2 + (if x then 1 else 0)) 0 $ toList n
