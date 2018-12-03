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

addHandshakeHeader :: Word8 -> ByteString -> ByteString
addHandshakeHeader t d = BS.pack $ mconcat
  [ [ t
    ]
  , BS.unpack . integerToByteStringBE 3 . fromIntegral $ BS.length d
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

buildExtensionSignatureAlgorithms :: ByteString
buildExtensionSignatureAlgorithms = BS.pack
  [ 0x00, 0x0d -- Signature algorithms extension
  , 0x00, 0x04 -- 4 bytes of signature algorithms data follow
  , 0x00, 0x02 -- 2 bytes of data in the algorithms list
  , 0x04, 0x01 -- Assigned value for RSA/PKCS1/SHA256
  ]

buildExtensionRenegotiationInfo :: ByteString
buildExtensionRenegotiationInfo = BS.pack
  [ 0xff, 0x01 -- Renegotiation info extension
  , 0x00, 0x01 -- 1 byte of renegotiation info data follows
  , 0x00 -- This is a new connection
  ]

buildExtensionSCT :: ByteString
buildExtensionSCT = BS.pack
  [ 0x00, 0x12 -- SCT extension
  , 0x00, 0x00 -- 0 bytes of SCT data follow
  ]

clientSendHello :: Socket -> ByteString -> ByteString -> IO ()
clientSendHello sock rand hostname = sendAll sock . addHandshakeRecordHeader . addHandshakeHeader 0x01 . BS.pack $ mconcat
  [ [ 0x03, 0x03 -- TLS 1.2
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
          , buildExtensionSignatureAlgorithms
          , buildExtensionRenegotiationInfo
          , buildExtensionSCT
          ]

clientRecvHello :: Socket -> IO ByteString -- Assume server supports everything we request
clientRecvHello = undefined

clientRecvCert :: Socket -> IO ()
clientRecvCert = undefined

clientRecvKey :: Socket -> IO ByteString
clientRecvKey = undefined

clientRecvHelloDone :: Socket -> IO ()
clientRecvHelloDone = undefined

clientSendKeyExchange :: Socket -> ByteString -> IO ()
clientSendKeyExchange sock pub = sendAll sock . addHandshakeRecordHeader . addHandshakeHeader 0x10 $ mconcat
  [ integerToByteStringBE 1 . fromIntegral $ BS.length pub
  , pub
  ]

clientSendChangeCipherSpec :: Socket -> IO ()
clientSendChangeCipherSpec sock = sendAll sock $ BS.S.pack
  [ 0x14 -- Change cipher spec record
  , 0x03, 0x03 -- TLS 1.2
  , 0x00, 0x01 -- 1 byte of change cipher spec data follows
  , 0x01
  ]

clientSendHandshakeFinished :: Socket -> ByteString -> ByteString -> IO ()
clientSendHandshakeFinished sock eiv ctext = sendAll sock . addHandshakeRecordHeader $ mconcat
  [ eiv
  , ctext
  ]

clientRecvChangeCipherSpec :: Socket -> IO ()
clientRecvChangeCipherSpec = undefined

clientRecvHandshakeFinished :: Socket -> IO ()
clientRecvHandshakeFinished = undefined
