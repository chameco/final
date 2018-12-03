module Final.Protocol where

import Control.Applicative
import Control.Exception (bracket)

import Data.ByteString.Lazy (ByteString)
import Data.ByteString.Lazy.Char8 hiding (head, map, concat)
import qualified Data.ByteString.Lazy as BS
import Data.List

import Final.Protocol.CipherSuite

import Network.Socket hiding (send, recv)
import Network.Socket.ByteString

import Numeric (showHex)

import Prelude hiding (putStrLn)

prettyPrint :: ByteString -> String
prettyPrint = concat . map (flip showHex "") . BS.unpack

testServer :: IO ()
testServer = withSocketsDo $ do
  -- randomGen <- getStdGen >>= newMVar
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
      server conn

testClient :: IO ()
testClient = withSocketsDo $ do
  bracket open close client
  where
    resolve host port = do
      let hints = defaultHints {addrSocketType = Stream}
      fmap head $ getAddrInfo (Just hints) (Just host) (Just port)
    open = do
      addr <- resolve "127.0.0.1" "3000"
      sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
      connect sock $ addrAddress addr
      return sock

server :: Socket -> IO ()
server sock = do
  let (CipherSuite _ _ decrypt) = getCipherSuite (0xCC, 0xA8)
  msg <- fromStrict <$> recv sock (2^(15 :: Int))
  decrypt (BS.replicate 32 10) msg >>= putStrLn
  pure ()

client :: Socket -> IO ()
client sock = do
  let (CipherSuite _ encrypt _) = getCipherSuite (0xCC, 0xA8)
  msg <- encrypt (BS.replicate 32 10) "Hello World"
  putStrLn msg
  send sock $ toStrict msg
  pure ()

data ConnectionState = Temporary
