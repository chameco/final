module Final.Protocol.Handshake where

import Control.Applicative
import Control.Concurrent.MVar
import Control.Exception (bracket)

import Data.Binary
import Data.ByteString.Lazy (ByteString)
import Data.ByteString.Lazy.Char8 hiding (head, map, concat)
import qualified Data.ByteString.Lazy as BS
import Data.Functor ((<&>))
import Data.List
import Data.Tuple (swap)
import Data.Word (Word32)

import Final.Cipher as Cipher
import Final.Cipher.RSA
import Final.Hash as Hash
import Final.Hash.SHA256
import Final.Utility.UInt as UInt
import Final.Utility.Natural
import Final.Utility.Vector as Vec

import GHC.Generics (Generic)

import Network.Socket hiding (send, recv)
import Network.Socket.ByteString

import Numeric (showHex)

import Prelude hiding (putStrLn)

import System.Random

data ProtocolVersion = ProtocolVersion {major :: Word8, minor :: Word8} deriving (Generic, Show)
-- TLSv1.2 (ProtocolVersion 3 3) should serialize to 0x0303
instance Binary ProtocolVersion

data AlertLevel = Warning | Fatal deriving Show
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
                      deriving (Show, Generic)
instance Binary AlertDescription

data Alert = Alert AlertLevel AlertDescription deriving (Show, Generic)
instance Binary Alert

type SessionID = ()
-- data SessionID deriving Generic
-- instance Binary SessionID

data CipherSuite deriving Generic
instance Binary CipherSuite
instance Show CipherSuite where
  show = const $ show ()

data CompressionMethod deriving Generic
instance Binary CompressionMethod
instance Show CompressionMethod where
  show = const $ show ()

data Extension deriving Generic
instance Binary Extension
instance Show Extension where
  show = const $ show ()

data HandshakeType =  HelloRequest
                    | ClientHello { client_version :: ProtocolVersion
                                  , random :: RandomStruct
                                  , session_id :: SessionID
                                  , cipher_suites :: [CipherSuite]
                                  , compression_methods :: [CompressionMethod]
                                  , extensions :: [Extension]
                                  }
                    | ServerHello { server_version :: ProtocolVersion
                                  , random :: RandomStruct
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
                    deriving (Generic, Show)
instance Binary HandshakeType

data RandomStruct = Random {time :: Word32, random :: Vector Word8 (Mul Four Seven)} deriving (Generic, Show)
instance Binary RandomStruct

generateRandom :: RandomGen g => MVar g -> IO RandomStruct
generateRandom = undefined
-- generateRandom = withMVar Random 0 (Vec.fromList $ randomRs (0,255) g)

sendclientHello :: RandomGen g => MVar g -> Socket -> IO ()
sendclientHello g sock = do
  -- TODO https://tools.ietf.org/html/rfc5246#section-7.4.1.2
  random' <- generateRandom g
  send sock $ BS.toStrict $ encode $ ClientHello
    (ProtocolVersion 3 3)
    random'
    ()
    []
    []
    []
  -- <- recv
  pure ()