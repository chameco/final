{-|
Generating and parsing TLS 1.2.
|-}
module Final.TLS where

import Control.Exception.Safe
import Control.Monad.IO.Class
import Control.Monad

import Data.Word (Word8, Word32)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv)

import Final.Utility.ByteString
  
recvLazy :: MonadIO m => Int -> Socket -> m ByteString
recvLazy n sock = liftIO (BS.fromStrict <$> recv sock n)

-- | Add the appropriate record header to handshake data.
addHandshakeRecordHeader :: ByteString -> ByteString
addHandshakeRecordHeader d = BS.pack $ mconcat
  [ [ 0x16 -- Handshake record
    , 0x03, 0x03 -- TLS 1.2
    ]
  , BS.unpack . integerToByteStringBE 2 . fromIntegral $ BS.length d
  , BS.unpack d
  ]

-- | Parse a record header, expecting the record will contain handshake data.
parseHandshakeRecordHeader :: MonadThrow m => ByteString -> m (Word8, (Word8, Word8), Word32)
parseHandshakeRecordHeader d = case BS.unpack d of
  [t, v1, v2, l1, l2] -> if t == 0x16
    then pure (t, (v1, v2), mergeWordsBE 0 0 l1 l2)
    else throwString $ mconcat ["Expected handshake record but received \"", show t, "\""]
  _ -> throwString $ mconcat ["Failed to parse handshake record header \"", toHex d, "\""]

-- | Add the appropriate record header to application data.
addApplicationDataRecordHeader :: ByteString -> ByteString
addApplicationDataRecordHeader d = BS.pack $ mconcat
  [ [ 0x17 -- Handshake record
    , 0x03, 0x03 -- TLS 1.2
    ]
  , BS.unpack . integerToByteStringBE 2 . fromIntegral $ BS.length d
  , BS.unpack d
  ]

-- | Parse a record header, expecting the record will contain application data.
parseApplicationDataRecordHeader :: MonadThrow m => ByteString -> m (Word8, (Word8, Word8), Word32)
parseApplicationDataRecordHeader d = case BS.unpack d of
  [t, v1, v2, l1, l2] -> if t == 0x17
    then pure (t, (v1, v2), mergeWordsBE 0 0 l1 l2)
    else throwString $ mconcat ["Expected application data but received \"", show t, "\""]
  _ -> throwString $ mconcat ["Failed to parse application data record header \"", toHex d, "\""]

-- | Add the appropriate handshake header for a given handshake type.
addHandshakeHeader :: Word8 -> ByteString -> ByteString
addHandshakeHeader t d = BS.pack $ mconcat
  [ [ t
    ]
  , BS.unpack . integerToByteStringBE 3 . fromIntegral $ BS.length d
  , BS.unpack d
  ]

-- | Parse a handshake header, expecting the handshake will be the given type.
parseHandshakeHeader :: MonadThrow m => Word8 -> ByteString -> m (Word8, Word32, ByteString)
parseHandshakeHeader et d = case BS.unpack d of
  (t:l1:l2:l3:rest) -> if et == t
    then pure (t, mergeWordsBE 0 l1 l2 l3, BS.pack rest)
    else throwString $ mconcat ["Expected handshake type \"", show et, "\" but received \"", show t, "\""]
  _ -> throwString $ mconcat ["Failed to parse handshake header \"", toHex d, "\""]

-- | Receive a record header, and use the length field to receive the handshake body.
recvHandshake :: (MonadThrow m, MonadIO m) => Socket -> Word8 -> m ByteString
recvHandshake sock t = do
  record_data <- recvLazy 5 sock
  (_, _, handshake_len) <- parseHandshakeRecordHeader record_data
  handshake_data <- recvLazy (fromIntegral handshake_len) sock
  (_, _, d) <- parseHandshakeHeader t handshake_data
  pure d

-- | Receive a record header, and use the length field to receive the rest of the application data.
recvApplicationData :: (MonadThrow m, MonadIO m) => Socket -> m ByteString
recvApplicationData sock = do
  record_data <- recvLazy 5 sock
  (_, _, data_len) <- parseApplicationDataRecordHeader record_data
  recvLazy (fromIntegral data_len) sock

-- | Construct a ServerHello message.
serverBuildHello :: ByteString -> ByteString
serverBuildHello rand = addHandshakeRecordHeader . addHandshakeHeader 0x02 . BS.pack $ mconcat
  [ [ 0x03, 0x03 -- TLS 1.2
    ]
  , BS.unpack rand
  , [ 0x00 -- Don't provide a session ID
    , 0xcc, 0xa8 -- Hardcoded to select TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    , 0x00 -- Null compression method
    ]
  -- , BS.unpack . integerToByteStringBE 2 . fromIntegral $ BS.length $ extensions hostname -- Length of extensions
  -- , BS.unpack $ extensions hostname
  ]

-- | Construct a ClientHello message.
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
  , BS.unpack . integerToByteStringBE 2 . fromIntegral $ BS.length $ extensions hostname -- Length of extensions
  , BS.unpack $ extensions hostname
  ]

-- | Construct the TLS extension data.
extensions :: ByteString -> ByteString
extensions hostname = mconcat
  [ extensionServerName hostname
  , extensionSupportedGroups
  , extensionECPointsFormat
  , extensionSignatureAlgorithms
  , extensionRenegotiationInfo
  , extensionSCT
  ]

extensionServerName :: ByteString -> ByteString
extensionServerName hostname = BS.pack $ mconcat
  [ [0x00, 0x00] -- Server name extension
  , BS.unpack . integerToByteStringBE 2 $ (len + 5) -- Length of extension data
  , BS.unpack . integerToByteStringBE 2 $ (len + 3) -- Length of list entry
  , [0x00] -- List entry is a DNS hostname
  , BS.unpack . integerToByteStringBE 2 $ len -- Length of hostname
  , BS.unpack hostname
  ]
  where len = fromIntegral $ BS.length hostname

extensionSupportedGroups :: ByteString
extensionSupportedGroups = BS.pack
  [ 0x00, 0x0a -- Supported groups extension
  , 0x00, 0x04 -- 4 bytes of supported groups data follow
  , 0x00, 0x02 -- 2 bytes of data in the supported groups list
  , 0x00, 0x1d -- Assigned value for x25519
  ]

extensionECPointsFormat :: ByteString
extensionECPointsFormat = BS.pack
  [ 0x00, 0x0b -- EC points format extension
  , 0x00, 0x02 -- 2 bytes of EC points format data follow
  , 0x01 -- 1 byte of data in the supported groups list
  , 0x00 -- No compression
  ]

extensionSignatureAlgorithms :: ByteString
extensionSignatureAlgorithms = BS.pack
  [ 0x00, 0x0d -- Signature algorithms extension
  , 0x00, 0x04 -- 4 bytes of signature algorithms data follow
  , 0x00, 0x02 -- 2 bytes of data in the algorithms list
  , 0x04, 0x01 -- Assigned value for RSA/PKCS1/SHA256
  ]

extensionRenegotiationInfo :: ByteString
extensionRenegotiationInfo = BS.pack
  [ 0xff, 0x01 -- Renegotiation info extension
  , 0x00, 0x01 -- 1 byte of renegotiation info data follows
  , 0x00 -- This is a new connection
  ]

extensionSCT :: ByteString
extensionSCT = BS.pack
  [ 0x00, 0x12 -- SCT extension
  , 0x00, 0x00 -- 0 bytes of SCT data follow
  ]

type CipherSuite = (Word8, Word8)

-- | Receive and parse a ClientHello message, returning the client random data and a list of cipher suites.
serverRecvHello :: forall m. (MonadThrow m, MonadIO m) => Socket -> m (ByteString, [CipherSuite])
serverRecvHello sock = do
  helloMsg <- recvHandshake sock 0x01
  case BS.unpack helloMsg of
    (0x03 : 0x03 : rest) -> readRandomBytes $ splitAt 32 rest
    (_:_:_) -> throwString $ mconcat ["Unsupported TLS version"]
    _ -> throwString $ mconcat ["Failed to parse server hello"]
  where readRandomBytes :: ([Word8], [Word8]) -> m (ByteString, [CipherSuite])
        readRandomBytes (rand, _:cipherSuites) = (BS.pack rand,) <$> readCipherSuites (drop 3 cipherSuites)
        readRandomBytes _ = throwString "Missing cipher suites after Session ID byte"
        readCipherSuites :: [Word8] -> m [CipherSuite]
        readCipherSuites [] = pure []
        readCipherSuites (x1:x2:rest) = ((x1,x2) :) <$> readCipherSuites rest
        readCipherSuites _ = throwString "Failed to parse list of cipher suites"

-- | Receive and parse a ServerHello message, returning the server random data.
clientRecvHello :: (MonadThrow m, MonadIO m) => Socket -> m ByteString
clientRecvHello sock = do
  hello_data <- recvHandshake sock 0x02
  case BS.unpack hello_data of
    (_:_:rest) -> pure . BS.pack $ take 32 rest
    _ -> throwString $ mconcat ["Failed to parse server hello \"", toHex hello_data, "\""]

-- | Receive and ignore a ServerCertificate message.
clientRecvCert :: (MonadThrow m, MonadIO m) => Socket -> m ()
clientRecvCert = void . flip recvHandshake 0x0b

-- | Construct a ServerHelloDone message.
serverBuildHelloDone :: ByteString
serverBuildHelloDone = addHandshakeRecordHeader . addHandshakeHeader 0x0e $ BS.replicate 3 0

-- | Receive and ignore a ServerHelloDone message.
clientRecvHelloDone :: (MonadThrow m, MonadIO m) => Socket -> m ()
clientRecvHelloDone = void . flip recvHandshake 0x0e

-- | Construct a ServerKeyExchange message for the given ECDHE public key.
serverBuildKeyExchange :: ByteString -> ByteString
serverBuildKeyExchange pub = addHandshakeRecordHeader . addHandshakeHeader 0x0c $ mconcat
  [ BS.pack
    [ 0x03 -- Named curve
    , 0x00, 0x1d -- Curve x25519
    ]
  , integerToByteStringBE 1 . fromIntegral $ BS.length pub
  , pub
  ]

-- | Receive and parse a ServerKeyExchange message, returning the ECDHE public key.
clientRecvKeyExchange :: (MonadThrow m, MonadIO m) => Socket -> m ByteString
clientRecvKeyExchange sock = do
  key_data <- recvHandshake sock 0x0c
  case BS.unpack key_data of
    (_:_:_:len:rest) -> pure . BS.pack $ take (fromIntegral len) rest
    _ -> throwString $ mconcat ["Failed to parse server key \"", toHex key_data, "\""]

-- | Construct a ClientKeyExchange message for the given ECDHE public key.
clientBuildKeyExchange :: ByteString -> ByteString
clientBuildKeyExchange pub = addHandshakeRecordHeader . addHandshakeHeader 0x10 $ mconcat
  [ integerToByteStringBE 1 . fromIntegral $ BS.length pub
  , pub
  ]

-- | Receive and parse a ClientKeyExchange message, returning the ECDHE public key.
serverRecvKeyExchange :: (MonadThrow m, MonadIO m) => Socket -> m ByteString
serverRecvKeyExchange sock = do
  key_data <- recvHandshake sock 0x10
  case BS.unpack key_data of
    (len:rest) -> pure . BS.pack $ take (fromIntegral len) rest
    _ -> throwString $ mconcat ["Failed to parse client key \"", toHex key_data, "\""]

-- | Construct a ChangeCipherSpec message (for either client or server).
buildChangeCipherSpec :: ByteString
buildChangeCipherSpec = BS.pack
  [ 0x14 -- Change cipher spec record
  , 0x03, 0x03 -- TLS 1.2
  , 0x00, 0x01 -- 1 byte of change cipher spec data follows
  , 0x01
  ]

-- | Receive and ignore a ChangeCipherSpec message.
recvChangeCipherSpec :: (MonadThrow m, MonadIO m) => Socket -> m ()
recvChangeCipherSpec = void . recvLazy 6

-- | Construct a HandshakeFinished plaintext from the verification data.
buildHandshakeFinishedPlaintext :: ByteString -> ByteString
buildHandshakeFinishedPlaintext = addHandshakeHeader 0x14

-- | Construct a HandshakeFinished record from the encrypted handshake message and IV.
buildHandshakeFinished :: ByteString -> ByteString -> ByteString
buildHandshakeFinished eiv ctext = addHandshakeRecordHeader $ mconcat
  [ eiv
  , ctext
  ]

-- | Receive and parse a HandshakeFinished record, returning the encrypted body.
recvHandshakeFinished :: (MonadThrow m, MonadIO m) => Socket -> m ByteString
recvHandshakeFinished sock = do
  record_data <- recvLazy 5 sock
  (_, _, handshake_len) <- parseHandshakeRecordHeader record_data
  recvLazy (fromIntegral handshake_len) sock

-- | Construct an ApplicationData record from the encrypted message and IV.
buildApplicationData :: ByteString -> ByteString -> ByteString
buildApplicationData eiv ctext = addApplicationDataRecordHeader $ mconcat
  [ eiv
  , ctext
  ]
