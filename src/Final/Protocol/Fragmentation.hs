module Final.Protocol.Fragmentation where

import Data.ByteString.Lazy hiding (putStrLn)
import Data.ByteString.Lazy.Char8 (putStrLn)
import Data.Binary
import Data.Sequence

import Final.Protocol
import Final.Utility.Natural
import Final.Utility.UInt

import GHC.Generics (Generic)

import Network.Socket (Socket)
import Network.Socket.ByteString

import Prelude hiding (putStrLn)

type UInt16 = UInt (Mul Four Four)

data TLSPlaintext = ApplicationData ByteString | Handshake HandshakeType deriving (Show, Generic)
instance Binary TLSPlaintext

-- data ContentType = ApplicationData deriving (Show, Enum, Generic)
-- instance Binary ContentType

readFragment :: Socket -> IO ()
readFragment sock = do
  msg <- recv sock (2^14)
  putStrLn $ fromStrict msg
