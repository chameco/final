module Main where

import Control.Arrow (second)
import Control.Monad
import Control.Exception.Safe

import Data.Bits (xor)
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

expandMasterSecret :: ByteString -> ByteString -> ByteString -> (ByteString, ByteString, ByteString, ByteString)
expandMasterSecret server_rand client_rand master = (client_key, server_key, client_iv, server_iv)
  where seed = "key expansion" <> server_rand <> client_rand
        as = iterate (hmac master) seed
        ps = hmac master . (<>seed) <$> as
        material = BS.concat ps
        (client_key, rest) = BS.splitAt 32 material
        (server_key, rest') = BS.splitAt 32 rest
        (client_iv, server_iv) = BS.splitAt 12 $ BS.take 24 rest'

server :: Int -> IO ()
server port = bracket open Net.close $ (>>= body . fst) . Net.accept
  where
    open = do
      let hints = Net.defaultHints {Net.addrFlags = [Net.AI_PASSIVE], Net.addrSocketType = Net.Stream}
      addr <- head <$> Net.getAddrInfo (Just hints) Nothing (Just $ show port)
      sock <- Net.socket (Net.addrFamily addr) (Net.addrSocketType addr) (Net.addrProtocol addr)
      Net.setSocketOption sock Net.ReuseAddr 1
      Net.bind sock $ Net.addrAddress addr
      Net.listen sock 10
      return sock
    body sock = do
      _ <- serverRecvHello sock -- TODO Use returned list of cipher suites
      (rand, gen) <- flip randomByteString 32 <$> getStdGen
      let hello = serverBuildHello rand
      sendAll sock $ BS.toStrict hello

      let (priv, gen') = generatePrivateKeyECDHE gen
      let pub = derivePublicKeyECDHE priv
      let keyExchange = serverBuildKeyExchange pub
      sendAll sock $ BS.toStrict keyExchange
      
      sendAll sock $ BS.toStrict serverBuildHelloDone

      clientPub <- serverRecvKeyExchange sock
      let sharedSecret = computeSharedSecretECDHE priv clientPub

      sendAll sock $ BS.toStrict buildChangeCipherSpec

      let handshakeFinishedPlaintext = buildHandshakeFinishedPlaintext verify
          sequence_number = 0
          aad = integerToByteStringBE 8 sequence_number <> BS.pack [0x16, 0x03, 0x03] <> integerToByteStringBE 2 (fromIntegral $ BS.length verify)
          nonce = BS.pack $ BS.zipWith xor (integerToByteStringBE 12 sequence_number) client_iv
      (ciphertext, tag) <- chaCha20Poly1305AEAD client_key nonce handshakeFinishedPlaintext aad
      let handshakeFinished = buildHandshakeFinished nonce $ ciphertext <> tag
      sendAll sock $ BS.toStrict handshakeFinished

      pure ()

client :: ByteString -> Int -> IO ()
client host port = do
  addr:_ <- Net.getAddrInfo
    (Just $ Net.defaultHints { Net.addrSocketType = Net.Stream })
    (Just . fmap (chr . fromIntegral) $ BS.unpack host)
    (Just $ show port)
  bracket (Net.socket (Net.addrFamily addr) (Net.addrSocketType addr) (Net.addrProtocol addr)) Net.close $ \sock -> do
    Net.connect sock $ Net.addrAddress addr
    (client_rand, gen) <- flip randomByteString 32 <$> getStdGen 

    let hello = clientBuildHello client_rand host
    sendAll sock $ BS.toStrict hello

    server_rand <- clientRecvHello sock

    otherpub <- clientRecvKeyExchange sock
    let (priv, gen') = generatePrivateKeyECDHE gen
        pub = derivePublicKeyECDHE priv
        premaster = computeSharedSecretECDHE priv otherpub
        master = deriveMasterSecret server_rand client_rand premaster
        (client_key, server_key, client_iv, server_iv) = expandMasterSecret server_rand client_rand premaster

    clientRecvHelloDone sock

    let keyExchange = clientBuildKeyExchange pub
    sendAll sock $ BS.toStrict keyExchange

    let changeCipherSpec = buildChangeCipherSpec
    sendAll sock $ BS.toStrict changeCipherSpec

    let seed = "client finished" <> sha256 (mconcat [hello, keyExchange, changeCipherSpec])
        a1 = hmac master seed
        p1 = hmac master (a1 <> seed)
        verify = BS.take 12 p1

    let handshakeFinishedPlaintext = buildHandshakeFinishedPlaintext verify
        sequence_number = 0
        aad = integerToByteStringBE 8 sequence_number <> BS.pack [0x16, 0x03, 0x03] <> integerToByteStringBE 2 (fromIntegral $ BS.length verify)
        nonce = BS.pack $ BS.zipWith xor (integerToByteStringBE 12 sequence_number) client_iv
    (ciphertext, tag) <- chaCha20Poly1305AEAD client_key nonce handshakeFinishedPlaintext aad
    let handshakeFinished = buildHandshakeFinished nonce $ ciphertext <> tag
    sendAll sock $ BS.toStrict handshakeFinished

    void $ recvChangeCipherSpec sock
    void $ recvHandshakeFinished sock

main :: IO ()
main = undefined
