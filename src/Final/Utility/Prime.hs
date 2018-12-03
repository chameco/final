{-|
Helper functions for working with prime numbers.
|-}
module Final.Utility.Prime where

import Control.Arrow

import Data.Kind

import System.Random

import Final.Utility.Modular

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

-- | Randomly generate a number coprime with the give number. 
genCoprime :: forall (g :: Type). RandomGen g => g -> Integer -> (Integer, g)
genCoprime gen n
  | gcd a n == 1 = (a, gen')
  | otherwise = genCoprime gen' n
  where a :: Integer
        (a, gen') = randomR (2, n - 1) gen

-- | Compute the Carmichael totient λ of two numbers.
carmichaelTotient :: Integer -> Integer -> Integer
carmichaelTotient p q = lcm (p - 1) (q - 1)
