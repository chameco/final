module Final.Protocol.Fragmentation where

import Control.Monad

import Data.ByteString.Lazy as BS hiding (putStrLn)
import Data.Binary
import Data.Int (Int64)

-- import Final.Protocol
import Final.Protocol.Handshake
import Final.Utility.Natural
import Final.Utility.UInt

import GHC.Generics (Generic)

import Network.Socket (Socket)

import Prelude hiding (putStrLn)

type UInt16 = UInt (Mul Four Four)
type MAC = ByteString -> ByteString
type Encryption = ByteString -> ByteString
type Decryption = ByteString -> ByteString

data TLSPlaintext = AlertMessage Alert | ApplicationData ByteString | Handshake HandshakeType deriving (Show)
instance Binary TLSPlaintext where
  put text = do
    put $ contentType text
    put $ ProtocolVersion 3 3
    let fragment = getFragment text
    put $ BS.length fragment
    put fragment
  get = get @Word8 <*
        get @ProtocolVersion <*
        get @Int64 >>= \case
          21 -> AlertMessage <$> get
          22 -> Handshake <$> get
          23 -> ApplicationData <$> get
          _  -> error "Unsupported ContentType"

contentType :: TLSPlaintext -> Word8
contentType (AlertMessage _)    = 21
contentType (Handshake _)       = 22
contentType (ApplicationData _) = 23

getFragment :: TLSPlaintext -> ByteString
getFragment (AlertMessage d)    = encode d
getFragment (ApplicationData d) = d
getFragment (Handshake d)       = encode d

data TLSCiphertext = GenericStreamCipher {content :: ByteString, mac :: ByteString} deriving (Generic)
instance Binary TLSCiphertext

-- toCiphertext :: ConnectionState -> ByteString -> TLSPlaintext -> TLSCiphertext
-- toCiphertext (ConnectionState encrypt _ mac) seq_num = GenericStreamCipher (encrypt content) $ mac $ BS.concat [seq_num, ]

toPlaintext :: ConnectionState -> ByteString -> TLSCiphertext -> Maybe TLSPlaintext
toPlaintext = undefined

data ConnectionState = ConnectionState {encryptFunc :: Encryption, decryptFunc :: Decryption, mac :: MAC}
-- nextMessage :: ConnectionState -> IO TLSPlaintext
-- nextMessage 

-- data ContentType = ApplicationData deriving (Show, Enum, Generic)
-- instance Binary ContentType

readPayload :: Socket -> IO TLSPlaintext
readPayload = undefined
