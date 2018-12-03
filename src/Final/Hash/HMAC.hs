module Final.Hash.HMAC (hmac) where

import Data.Bits (xor)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import Final.Hash.SHA256 (sha256)

hmac :: ByteString -> ByteString -> ByteString 
hmac k m = sha256 $ mconcat
  [ BS.pack $ BS.zipWith xor k' opad
  , sha256 $ mconcat
    [ BS.pack $ BS.zipWith xor k' ipad
    , m
    ]
  ]
  where ipad = BS.pack $ replicate 64 0x36
        opad = BS.pack $ replicate 64 0x5c
        k' = if BS.length k > 64 then sha256 k else pad k
        pad x | BS.length x >= 64 = x
              | otherwise = pad (x <> BS.pack [0])
