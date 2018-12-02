module Final.Protocol where

import Control.Applicative
import Control.Concurrent.MVar
import Control.Exception (bracket)

import Debug.Trace

import Data.Binary
import Data.Bits
import Data.ByteString.Lazy (ByteString)
import Data.ByteString.Lazy.Char8 hiding (head, map, concat)
import qualified Data.ByteString.Lazy as BS
import Data.List
import Data.Tuple (swap)

import Final.Cipher as Cipher
import Final.Cipher.ChaCha20
import Final.Hash as Hash
import Final.Hash.SHA256
import Final.Hash.SHA1 (SHA1)
import Final.Protocol.KeyExchange
import Final.Utility.UInt as UInt
import Final.Utility.Natural

import Network.Socket hiding (send, recv)
import Network.Socket.ByteString

import Numeric (showHex)

import Prelude hiding (putStrLn)

import System.Random

prettyPrint :: ByteString -> String
prettyPrint = concat . map (flip showHex "") . BS.unpack

type UInt24 = UInt (Add (Mul Ten Two) Four)

cipher :: Cipher.Impl ChaCha20
cipher = Cipher.impl

prf :: Hash.Impl SHA256
prf = Hash.impl

kPad :: forall a. Hash a => ByteString -> ByteString
kPad k
  | kLen > b = hashWithF (Hash.impl @a) k
  | otherwise = BS.append k $ BS.replicate (fromIntegral $ b - kLen) 0
  where b = blockSize @a
        kLen = toInteger $ BS.length k

-- TODO Incorrect values
hmac :: forall a. Hash a => Hash.Impl a -> ByteString -> ByteString -> ByteString
hmac h (kPad @a -> k) m = Prelude.foldr pad m ([0x5c, 0x36] :: [Word8])
  where pad = (hashWithF h .) . BS.append . flip BS.map k . xor

-- p :: Hash.Impl a -> ByteString -> HashText a -> [HashText a]
-- p f secret seed = hash f 
--   where a :: [HashText a]
--         a = iterate (hash f secret) seed

-- testServer :: IO ()
testServer = withSocketsDo $ do
  randomGen <- getStdGen >>= newMVar
  bracket open close body
  where
    resolve port = do
      let hints = defaultHints {addrFlags = [AI_PASSIVE], addrSocketType = Stream}
      fmap head $ getAddrInfo (Just hints) Nothing (Just port)
    open = do
      addr <- resolve "3000"
      sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
      setSocketOption sock ReuseAddr 1
      bind sock $ addrAddress addr
      listen sock 10
      return sock
    body sock = do
      (conn :: Socket, peer) <- accept sock
      putStrLn $ append "Connection from " (pack $ show peer)
      full@(ClientDiffieHellmanPublic dh_p dh_g dh_Ys) <- decode . fromStrict <$> recv conn (2^15)
      print full
      (msg, privateKey) <- decode . fromStrict <$> recv conn (2^15)
      putStrLn $ renderPlaintext cipher $ decrypt cipher privateKey msg

-- testClient :: IO ()
testClient = withSocketsDo $ do
  randomGen <- getStdGen >>= newMVar
  bracket open close $ talk randomGen
  where
    resolve host port = do
      let hints = defaultHints {addrSocketType = Stream}
      fmap head $ getAddrInfo (Just hints) (Just host) (Just port)
    open = do
      addr <- resolve "127.0.0.1" "3000"
      sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
      connect sock $ addrAddress addr
      return sock
    talk randomGen sock = do
      clientDiffieHellman sock randomGen
      privateKey <- modifyMVar randomGen (pure . swap . generateDecryptionKey cipher)
      let publicKey = deriveEncryptionKey cipher privateKey
      msg <- Cipher.parsePlaintext cipher "Hello World"
      send sock $ toStrict $ encode (encrypt cipher publicKey msg, privateKey)

data ConnectionState = Temporary

test :: IO ()
test = do
  currentState <- newMVar Temporary
  pendingState <- newMVar Temporary
  sock <- undefined
  readPayload sock >>= \case
    (Handshake HelloRequest) -> undefined -- TODO start handshake
    (AlertMessage a) -> undefined -- TODO https://tools.ietf.org/html/rfc5246#section-7.2
    (ApplicationData _) -> undefined -- TODO handle data with currentState
  pure ()

-- serverHello :: Socket -> IO Bool
-- serverHello sock = do
--   pure False
