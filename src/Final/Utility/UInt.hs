module Final.Utility.UInt where

import Control.Arrow
import Data.Binary
import qualified Data.Bits as Standard (Bits)
import Data.Bits
import Data.Singletons (SingI)
import qualified Final.Utility.Bits as Utility (Bits)
import Final.Utility.Natural
import Final.Utility.Vector hiding (fromList)
import qualified Final.Utility.Vector as Vec (fromList)
import Prelude hiding (replicate)

newtype UInt (n :: Natural) = UInt (Utility.Bits n)
deriving instance forall (n :: Natural). Eq (UInt n)
deriving instance forall (n :: Natural). Ord (UInt n)

fromList :: forall (n :: Natural). SingI n => [Bool] -> UInt n
fromList = UInt . Vec.fromList

splitWord8 :: forall (n :: Natural). SingI n => UInt n -> [Word8]
splitWord8 (UInt n) = readWords $ toList n
  where readWords :: [Bool] -> [Word8]
        readWords = splitAt 8 >>> \case
          ([], []) -> []
          (x, xs) -> fromIntegral (fromList @Eight x) : readWords xs

asInteger :: Integral a => (Integer -> Integer -> Integer) -> a -> a -> a
asInteger f a b = fromInteger $ f (toInteger a) (toInteger b)

-- TODO Send only as many bytes as necessary to conform to TLS
instance forall (n :: Natural). SingI n => Binary (UInt n) where
  put (UInt n) = put $ toList n
  get = UInt . Vec.fromList <$> get

instance forall (n :: Natural). SingI n => Show (UInt n) where
  show = show . toInteger

instance forall (n :: Natural). SingI n => Num (UInt n) where
  (+) = asInteger (+)
  (*) = asInteger (*)
  abs = id
  signum = const 1
  fromInteger = UInt . Vec.fromList . reverse . flip map [0..natValue @n - 1] . testBit
  (-) = asInteger (-)

instance forall (n :: Natural). SingI n => Real (UInt n) where
  toRational = toRational . toInteger

instance forall (n :: Natural). SingI n => Enum (UInt n) where
  toEnum = fromIntegral
  fromEnum = fromIntegral

instance forall (n :: Natural). SingI n => Integral (UInt n) where
  quotRem (toInteger -> a) (toInteger -> b) = (fromInteger $ quot a b, fromInteger $ rem a b)
  toInteger (UInt n) = foldl (\y x -> y*2 + (if x then 1 else 0)) 0 $ toList n

instance forall (n :: Natural). SingI n => Standard.Bits (UInt n) where
  (.&.) = asInteger (.&.)
  (.|.) = asInteger (.|.)
  xor = asInteger xor
  complement = fromInteger . complement . toInteger
  shift = (fromInteger .) . shift . toInteger
  rotate = (fromInteger .) . rotate . toInteger
  bitSize _ = natValue @n
  bitSizeMaybe = const $ pure (natValue @n)
  isSigned = const False
  testBit = testBit . toInteger
  bit = fromInteger . bit
  popCount = popCount . toInteger
