module Final.Utility.Bits where

import Data.Char (ord)
import Data.Word (Word8)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

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

showBits :: forall (n :: Natural). Bits n -> ByteString
showBits = BS.pack . go 
  where go :: forall (m :: Natural). Bits m -> [Word8]
        go Empty = []
        go (Cons True bs) = fromIntegral (ord '1'):go bs
        go (Cons False bs) = fromIntegral (ord '0'):go bs