module Main where

import Control.Monad
import Control.Exception.Safe

import Data.Char (chr)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import Final.Utility.ByteString
import Final.Hash.SHA256 (sha256)
import Final.Hash.HMAC (hmac)
import Final.Cipher.ECC (generatePrivateKeyECDHE, derivePublicKeyECDHE, computeSharedSecretECDHE)
import Final.Cipher.ChaCha20 (chaCha20Poly1305AEAD, chaCha20Poly1305UnAEAD)
import Final.TLS

import System.Random

import qualified Network.Socket as Net
import Network.Socket.ByteString (sendAll)

deriveMasterSecret :: ByteString -> ByteString -> ByteString -> ByteString
deriveMasterSecret server_rand client_rand premaster = p1 <> BS.take 16 p2
  where seed = "master secret" <> client_rand <> server_rand
        a1 = hmac premaster seed
        a2 = hmac premaster a1
        p1 = hmac premaster (a1 <> seed)
        p2 = hmac premaster (a2 <> seed)

client :: ByteString -> Int -> IO ()
client host port = do
  addr:_ <- Net.getAddrInfo
    (Just $ Net.defaultHints { Net.addrSocketType = Net.Stream })
    (Just . fmap (chr . fromIntegral) $ BS.unpack host)
    (Just $ show port)
  bracket (Net.socket (Net.addrFamily addr) (Net.addrSocketType addr) (Net.addrProtocol addr)) Net.close $ \sock -> do
    Net.connect sock $ Net.addrAddress addr
    (rand, gen) <- flip randomByteString 32 <$> getStdGen 

    let hello = clientBuildHello rand host
    sendAll sock $ BS.toStrict hello

    serverrand <- clientRecvHello sock

    otherpub <- clientRecvKeyExchange sock
    let (priv, gen') = generatePrivateKeyECDHE gen
        pub = derivePublicKeyECDHE priv
        premaster = computeSharedSecretECDHE priv otherpub
        master = deriveMasterSecret serverrand rand premaster

    clientRecvHelloDone sock

    let keyExchange = clientBuildKeyExchange pub
    sendAll sock $ BS.toStrict keyExchange

    let changeCipherSpec = buildChangeCipherSpec
    sendAll sock $ BS.toStrict changeCipherSpec

    let seed = "client finished" <> sha256 (mconcat [hello, keyExchange, changeCipherSpec])

    undefined

main :: IO ()
main = undefined
