module Final.Utility where

import Control.Arrow

import Data.Kind
import Data.Bits

import System.Random

-- | Perform modular exponentiation: modExp a b n == a^b mod n
modExp :: Integer -> Integer -> Integer -> Integer
modExp base e n = go (mod base n) e 1
  where go :: Integer -> Integer -> Integer -> Integer
        go _ 0 acc = acc
        go base' e' acc = go (mod (base' ^ (2 :: Integer)) n) (shiftR e' 1) (if testBit e' 0 then mod (base' * acc) n else acc)
-- mod ((if testBit e 0 then base' else 1) * modExp (mod (base' ^ (2 :: Integer)) n) (shiftR e 1) n) n

modInv :: Integer -> Integer -> Integer
modInv a m
  | inv < 0 = m - inv
  | otherwise = inv
  where euclidean :: Integer -> Integer -> (Integer, Integer, Integer)
        euclidean a' 0 = (1, 0, a')
        euclidean a' b' = (t, s - q * t, result)
          where (q, r) = quotRem a' b'
                (s, t, result) = euclidean b' r
        inv = case euclidean a m of (x, _, _) -> x

-- | Test if a number is prime using the Miller-Rabin probabilistic primality test.
millerRabin :: forall (g :: Type). RandomGen g => g -> Integer -> Integer -> (Bool, g)
millerRabin gen' k' n = go gen' k'
  where decompose :: Integer -> (Integer, Integer)
        decompose m
          | mod m 2 == 0 = first succ $ decompose (quot m 2)
          | otherwise = (0, m)
        (r, d) = decompose (n - 1)
        go :: g -> Integer -> (Bool, g)
        go gen 0 = (True, gen)
        go gen k
          | x == 1 || x == n - 1 = go gen'' (k - 1)
          | elem (n - 1) $ take (fromIntegral $ r - 1) xs = go gen'' (k - 1)
          | otherwise = (False, gen'')
          where (a, gen'') = randomR (2, n - 2) gen
                x = modExp a d n
                xs = x:fmap (\x' -> modExp x' 2 n) xs

-- | Randomly generate a prime number of a certain bit length.
genPrimeBits :: forall (g :: Type). RandomGen g => g -> Integer -> (Integer, g)
genPrimeBits gen n
  | p = (a, gen'')
  | otherwise = genPrimeBits gen'' n
  where a :: Integer
        (a, gen') = randomR (2 ^ n, 2 ^ (n + 1)) gen
        (p, gen'') = millerRabin gen' 40 a

genCoprime :: forall (g :: Type). RandomGen g => g -> Integer -> (Integer, g)
genCoprime gen n
  | gcd a n == 1 = (a, gen')
  | otherwise = genCoprime gen' n
  where a :: Integer
        (a, gen') = randomR (2, n - 1) gen

carmichaelTotient :: Integer -> Integer -> Integer
carmichaelTotient p q = lcm (p - 1) (q - 1)
