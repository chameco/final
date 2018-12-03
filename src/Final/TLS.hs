module Final.TLS where

import Data.Word (Word8)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import Final.Utility.ByteString

addHandshakeRecordHeader :: ByteString -> ByteString
addHandshakeRecordHeader d = BS.pack $ mconcat
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

clientBuildHello :: ByteString -> ByteString -> ByteString
clientBuildHello rand hostname = addHandshakeRecordHeader . addHandshakeHeader 0x01 . BS.pack $ mconcat
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
          [ extensionServerName
          , extensionSupportedGroups
          , extensionECPointsFormat
          , extensionSignatureAlgorithms
          , extensionRenegotiationInfo
          , extensionSCT
          ]
        extensionServerName = BS.pack $ mconcat
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
        extensionSupportedGroups = BS.pack
          [ 0x00, 0x0a -- Supported groups extension
          , 0x00, 0x04 -- 4 bytes of supported groups data follow
          , 0x00, 0x02 -- 2 bytes of data in the supported groups list
          , 0x00, 0x1d -- Assigned value for x25519
          ]
        extensionECPointsFormat = BS.pack
          [ 0x00, 0x0b -- EC points format extension
          , 0x00, 0x02 -- 2 bytes of EC points format data follow
          , 0x01 -- 1 byte of data in the supported groups list
          , 0x00 -- No compression
          ]
        extensionSignatureAlgorithms = BS.pack
          [ 0x00, 0x0d -- Signature algorithms extension
          , 0x00, 0x04 -- 4 bytes of signature algorithms data follow
          , 0x00, 0x02 -- 2 bytes of data in the algorithms list
          , 0x04, 0x01 -- Assigned value for RSA/PKCS1/SHA256
          ]
        extensionRenegotiationInfo = BS.pack
          [ 0xff, 0x01 -- Renegotiation info extension
          , 0x00, 0x01 -- 1 byte of renegotiation info data follows
          , 0x00 -- This is a new connection
          ]
        extensionSCT = BS.pack
          [ 0x00, 0x12 -- SCT extension
          , 0x00, 0x00 -- 0 bytes of SCT data follow
          ]

clientParseHello :: ByteString -> () -- Assume server supports everything we request
clientParseHello = undefined

clientParseCert :: ByteString -> ()
clientParseCert = undefined

clientParseKey :: ByteString -> ByteString
clientParseKey = undefined

clientParseHelloDone :: ByteString -> ()
clientParseHelloDone = undefined

clientBuildKeyExchange :: ByteString -> ByteString
clientBuildKeyExchange pub = addHandshakeRecordHeader . addHandshakeHeader 0x10 $ mconcat
  [ integerToByteStringBE 1 . fromIntegral $ BS.length pub
  , pub
  ]

clientBuildChangeCipherSpec :: ByteString
clientBuildChangeCipherSpec = BS.pack
  [ 0x14 -- Change cipher spec record
  , 0x03, 0x03 -- TLS 1.2
  , 0x00, 0x01 -- 1 byte of change cipher spec data follows
  , 0x01
  ]

clientBuildHandshakeFinished :: ByteString -> ByteString -> ByteString
clientBuildHandshakeFinished eiv ctext = addHandshakeRecordHeader $ mconcat
  [ eiv
  , ctext
  ]

clientParseChangeCipherSpec :: ByteString -> ()
clientParseChangeCipherSpec = undefined

clientParseHandshakeFinished :: ByteString -> ()
clientParseHandshakeFinished = undefined
