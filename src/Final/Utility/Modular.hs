{-|
Helper functions for modular arithmetic
|-}
module Final.Utility.Modular where

import Data.Bits

-- | Perform modular exponentiation: modExp a b n == a^b mod n
modExp :: Integer -> Integer -> Integer -> Integer
modExp base e n = go (mod base n) e 1
  where go :: Integer -> Integer -> Integer -> Integer
        go _ 0 acc = acc
        go base' e' acc = go (mod (base' ^ (2 :: Integer)) n) (shiftR e' 1) (if testBit e' 0 then mod (base' * acc) n else acc)

-- | Compute the modular inverse.
modInv :: Integer -> Integer -> Integer
modInv a m
  | inv < 0 = m + inv
  | otherwise = inv
  where euclidean :: Integer -> Integer -> (Integer, Integer, Integer)
        euclidean a' 0 = (1, 0, a')
        euclidean a' b' = (t, s - q * t, result)
          where (q, r) = quotRem a' b'
                (s, t, result) = euclidean b' r
        inv = case euclidean a m of (x, _, _) -> x
