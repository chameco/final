module Final.Protocol where

import Control.Applicative
import Control.Concurrent.MVar
import Control.Exception (bracket)

import Data.Binary
import Data.ByteString.Lazy (ByteString)
import Data.ByteString.Lazy.Char8 hiding (head, map, concat)
import qualified Data.ByteString.Lazy as BS
import Data.List
import Data.Tuple (swap)

import Final.Cipher as Cipher
import Final.Cipher.RSA
import Final.Hash as Hash
import Final.Hash.SHA256
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

cipher :: Cipher.Impl RSA
cipher = Cipher.impl

prf :: Hash.Impl SHA256
prf = Hash.impl

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
      privateKey <- modifyMVar randomGen (pure . swap . generateDecryptionKey cipher)
      let publicKey = deriveEncryptionKey cipher privateKey
      msg <- Cipher.parsePlaintext cipher "Hello World"
      send sock $ toStrict $ encode (encrypt cipher publicKey msg, privateKey)

-- serverHello :: Socket -> IO Bool
-- serverHello sock = do
--   pure False
