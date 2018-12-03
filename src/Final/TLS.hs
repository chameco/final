module Final.TLS where

import Data.Word (Word8)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS
import qualified Data.ByteString as BS.S

import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv, sendAll)

import Final.Utility.ByteString

addHandshakeRecordHeader :: ByteString -> BS.S.ByteString
addHandshakeRecordHeader d = BS.S.pack $ mconcat
  [ [ 0x16 -- Handshake record
    , 0x03, 0x03 -- TLS 1.2
    ]
  , BS.unpack . integerToByteStringBE 2 . fromIntegral $ BS.length d
  , BS.unpack d
  ]

buildExtensionServerName :: ByteString -> ByteString
buildExtensionServerName hostname = BS.pack $ mconcat
  [ [ 0x00, 0x00 -- Server name extension
    ]
  , BS.unpack . integerToByteStringBE 2 $ (len + 5) -- Length of extension data
  , BS.unpack . integerToByteStringBE 2 $ (len + 3) -- Length of list entry
  , [ 0x00 -- List entry is a DNS hostname
    ]
  , BS.unpack . integerToByteStringBE 2 $ len -- Length of hostname
  , BS.unpack hostname
  ]
  where len = fromIntegral $ BS.length hostname

buildExtensionSupportedGroups :: ByteString
buildExtensionSupportedGroups = BS.pack
  [ 0x00, 0x0a -- Supported groups extension
  , 0x00, 0x04 -- 4 bytes of supported groups data follow
  , 0x00, 0x02 -- 2 bytes of data in the supported groups list
  , 0x00, 0x1d -- Assigned value for x25519
  ]

buildExtensionECPointsFormat :: ByteString
buildExtensionECPointsFormat = BS.pack
  [ 0x00, 0x0b -- EC points format extension
  , 0x00, 0x02 -- 2 bytes of EC points format data follow
  , 0x01 -- 1 byte of data in the supported groups list
  , 0x00 -- No compression
  ]

clientSendHello :: Socket -> ByteString -> ByteString -> IO ()
clientSendHello sock rand hostname = sendAll sock . addHandshakeRecordHeader . BS.pack $ mconcat
  [ [ 0x01 -- Client hello
    -- 3-byte length here
    , 0x03, 0x03 -- TLS 1.2
    ]
  , BS.unpack rand
  , [ 0x00 -- Don't provide a session ID
    , 0x00, 0x02 -- Two bytes of ciphersuite data follow
    , 0xcc, 0xa8 -- We support TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    , 0x01 -- One byte of compression method data follows
    , 0x00 -- No compression
    ]
  , BS.unpack . integerToByteStringBE 2 . fromIntegral $ BS.length extensions -- Length of extensions
  , BS.unpack extensions
  ]
  where extensions = mconcat
          [ buildExtensionServerName hostname
          , buildExtensionSupportedGroups
          , buildExtensionECPointsFormat
          ]

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
