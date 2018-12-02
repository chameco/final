module Final.Protocol.KeyExchange where

import Control.Concurrent.MVar

import Data.Binary
import Data.ByteString.Lazy (toStrict)
import Data.Tuple (swap)

import Final.Utility.Modular

import GHC.Generics

import Network.Socket (Socket)
import Network.Socket.ByteString

import System.Random

p :: Integer
p = 23

g :: Integer
g = 5

data ClientDiffieHellmanPublic = ClientDiffieHellmanPublic {dh_p :: Integer, dh_g :: Integer, dh_Ys :: Integer}
  deriving (Generic, Show)
instance Binary ClientDiffieHellmanPublic

clientDiffieHellman :: RandomGen g => Socket -> MVar g -> IO Integer
clientDiffieHellman sock randomGen = do
  y <- modifyMVar randomGen $ pure . swap . randomR (1,p)
  let msg = ClientDiffieHellmanPublic p g $ modExp g y p
  print msg
  send sock $ toStrict $ encode msg
  
  pure 0
