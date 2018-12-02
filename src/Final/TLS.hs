module Final.TLS where

import Data.Word (Word8)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

clientSendHello :: IO ()
clientSendHello = undefined

clientRecvHello :: IO ByteString -- Assume server supports everything we request
clientRecvHello = undefined

clientRecvCert :: IO ()
clientRecvCert = undefined

clientRecvKey :: IO ByteString
clientRecvKey = undefined

clientRecvHelloDone :: IO ()
clientRecvHelloDone = undefined

clientSendKeyExchange :: IO ()
clientSendKeyExchange = undefined

clientSendChangeCipherSpec :: IO ()
clientSendChangeCipherSpec = undefined

clientSendHandshakeFinished :: IO ()
clientSendHandshakeFinished = undefined

clientRecvChangeCipherSpec :: IO ()
clientRecvChangeCipherSpec = undefined

clientRecvHandshakeFinished :: IO ()
clientRecvHandshakeFinished = undefined
