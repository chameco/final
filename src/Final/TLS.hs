module Final.TLS where

import Data.Word (Word8)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv, sendAll)

clientSendHello :: Socket -> IO ()
clientSendHello = undefined

clientRecvHello :: Socket -> IO ByteString -- Assume server supports everything we request
clientRecvHello = undefined

clientRecvCert :: Socket -> IO ()
clientRecvCert = undefined

clientRecvKey :: Socket -> IO ByteString
clientRecvKey = undefined

clientRecvHelloDone :: Socket -> IO ()
clientRecvHelloDone = undefined

clientSendKeyExchange :: Socket -> IO ()
clientSendKeyExchange = undefined

clientSendChangeCipherSpec :: Socket -> IO ()
clientSendChangeCipherSpec = undefined

clientSendHandshakeFinished :: Socket -> IO ()
clientSendHandshakeFinished = undefined

clientRecvChangeCipherSpec :: Socket -> IO ()
clientRecvChangeCipherSpec = undefined

clientRecvHandshakeFinished :: Socket -> IO ()
clientRecvHandshakeFinished = undefined
