module Final.Protocol where

import Data.Binary
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS (unpack, toStrict)
import Data.Functor ((<&>))
import Data.Word (Word32)
import Final.Utility.Bits (Bits)
import Final.Utility.Natural
import GHC.Generics (Generic)
import Network.Socket (Socket)
import Network.Socket.ByteString
import Numeric (showHex)

prettyPrint :: ByteString -> String
prettyPrint = concat . map (flip showHex "") . BS.unpack

data ProtocolVersion = ProtocolVersion {major :: Word8, minor :: Word8} deriving Generic
-- TLSv1.2 (ProtocolVersion 3 3) should serialize to 0x0303
instance Binary ProtocolVersion

data AlertLevel = Warning | Fatal
instance Binary AlertLevel where
  put Warning = put (1 :: Word8)
  put Fatal = put (2 :: Word8)
  get = get @Word8 <&> \case
          1 -> Warning
          2 -> Fatal
          _ -> error "Error deserializing an AlertLevel"

data AlertDescription = CloseNotify
                      | UnexpectedMessage
                      | BadRecordMAC
                      | DecryptionFailedRESERVED
                      | RecordOverflow
                      | DecompressionFailure
                      | HandshakeFailure
                      | NoCertificateRESERVED
                      | BadCertificate
                      | UnsupportedCertificate
                      | CertificateRevoked
                      | CertificateExpired
                      | CertificateUnknown
                      | IllegalParameter
                      | UnknownCA
                      | AccessDenied
                      | DecodeError
                      | DecryptError
                      deriving Generic
instance Binary AlertDescription

data Alert = Alert AlertLevel AlertDescription deriving Generic
instance Binary Alert

data SessionID
data CipherSuite
data CompressionMethod
data Extension

data HandshakeType =  HelloRequest
                    | ClientHello { client_version :: ProtocolVersion
                                  , random :: Random
                                  , session_id :: SessionID
                                  , cipher_suites :: [CipherSuite]
                                  , compression_methods :: [CompressionMethod]
                                  , extensions :: [Extension]
                                  }
                    | ServerHello { server_version :: ProtocolVersion
                                  , random :: Random
                                  , session_id :: SessionID
                                  , cipher_suite :: CipherSuite
                                  , compression_method :: CompressionMethod
                                  , extensions :: [Extension]
                                  }
                    | Certificate -- TODO https://tools.ietf.org/html/rfc5246#section-7.4.2
                    | ServerKeyExchange -- TODO https://tools.ietf.org/html/rfc5246#section-7.4.3
                    | CertificateRequest -- TODO https://tools.ietf.org/html/rfc5246#section-7.4.4
                    | ServerHelloDone
                    | CertificateVerify -- TODO https://tools.ietf.org/html/rfc5246#section-7.4.8
                    | ClientKeyExchange -- TODO https://tools.ietf.org/html/rfc5246#section-7.4.7
                    | Finished -- TODO https://tools.ietf.org/html/rfc5246#section-7.4.9

data Random = Random {time :: Word32, random :: Bits Eight} deriving Generic
instance Binary Random

generateRandom :: IO Random
generateRandom = undefined

type UInt24 = Bits (Add (Mul Ten Two) Four)

clientHello :: Socket -> IO Bool
clientHello sock = do
  -- TODO https://tools.ietf.org/html/rfc5246#section-7.4.1.2
  random <- generateRandom
  send sock $ BS.toStrict $ encode random
  pure False

serverHello :: Socket -> IO Bool
serverHello sock = do
  pure False
