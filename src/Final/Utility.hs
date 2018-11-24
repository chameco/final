module Final.Utility where

import Data.Bits

modExp :: Integer -> Integer -> Integer -> Integer
modExp _ 0 _ = 1
modExp base e n = mod ((if testBit e 0 then base' else 1) * modExp (mod (base' ^ (2 :: Integer)) n) (shiftR e 1) n) n
  where base' :: Integer
        base' = mod base n
