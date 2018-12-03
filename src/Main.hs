module Main where

import Control.Concurrent.MVar
import Control.Monad
import Control.Exception.Safe

import Data.Bits (xor)
import Data.Char (chr)
import Data.Tuple (swap)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import Final.Utility.ByteString
import Final.Hash.SHA256 (sha256)
import Final.Hash.HMAC (hmac)
import Final.Cipher.ECC (generatePrivateKeyECDHE, derivePublicKeyECDHE, computeSharedSecretECDHE)
import Final.Cipher.ChaCha20 (chaCha20Poly1305AEAD)
import Final.TLS

import System.Random

import qualified Network.Socket as Net
import Network.Socket.ByteString (sendAll)

pureModifyMVar :: MVar g -> (g -> (b, g)) -> IO b
pureModifyMVar v f = modifyMVar v $ pure . swap . f

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

verify :: ByteString -> ByteString -> [ByteString] -> ByteString
verify master input messages = BS.take 12 p1
  where seed = input <> sha256 (mconcat messages)
        a1 = hmac master seed
        p1 = hmac master (a1 <> seed)

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
      randomGen <- getStdGen >>= newMVar
      (client_rand, _cipher_suites) <- serverRecvHello sock -- TODO Use returned list of cipher suites
      server_rand <- modifyMVar randomGen $ pure . swap . flip randomByteString 32
      let hello = serverBuildHello server_rand
      sendAll sock $ BS.toStrict hello

      priv <- pureModifyMVar randomGen generatePrivateKeyECDHE
      let pub = derivePublicKeyECDHE priv
          keyExchange = serverBuildKeyExchange pub
      sendAll sock $ BS.toStrict keyExchange
      
      sendAll sock $ BS.toStrict serverBuildHelloDone

      otherPub <- serverRecvKeyExchange sock
      let premaster = computeSharedSecretECDHE priv otherPub
          master = deriveMasterSecret server_rand client_rand premaster
          (_, server_key, _, server_iv) = expandMasterSecret server_rand client_rand premaster
      
      print master
      sendAll sock $ BS.toStrict buildChangeCipherSpec

      let verify_data = verify master "server finished" [hello, keyExchange, buildChangeCipherSpec]

      let handshakeFinishedPlaintext = buildHandshakeFinishedPlaintext verify_data
          sequence_number = 0
          aad = integerToByteStringBE 8 sequence_number <> BS.pack [0x16, 0x03, 0x03] <> integerToByteStringBE 2 (fromIntegral $ BS.length verify_data)
          nonce = BS.pack $ BS.zipWith xor (integerToByteStringBE 12 sequence_number) server_iv
      (ciphertext, tag) <- chaCha20Poly1305AEAD server_key nonce handshakeFinishedPlaintext aad
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
    randomGen <- getStdGen >>= newMVar
    client_rand <- modifyMVar randomGen $ pure . swap . generatePrivateKeyECDHE

    let hello = clientBuildHello client_rand host
    sendAll sock $ BS.toStrict hello

    server_rand <- clientRecvHello sock

    otherpub <- clientRecvKeyExchange sock
    priv <- pureModifyMVar randomGen generatePrivateKeyECDHE
    let pub = derivePublicKeyECDHE priv
        premaster = computeSharedSecretECDHE priv otherpub
        master = deriveMasterSecret server_rand client_rand premaster
        (client_key, _, client_iv, _) = expandMasterSecret server_rand client_rand premaster

    print master
    clientRecvHelloDone sock

    let keyExchange = clientBuildKeyExchange pub
    sendAll sock $ BS.toStrict keyExchange

    sendAll sock $ BS.toStrict buildChangeCipherSpec

    let verify_data = verify master "client finished" [hello, keyExchange, buildChangeCipherSpec]

    let handshakeFinishedPlaintext = buildHandshakeFinishedPlaintext verify_data
        sequence_number = 0
        aad = integerToByteStringBE 8 sequence_number <> BS.pack [0x16, 0x03, 0x03] <> integerToByteStringBE 2 (fromIntegral $ BS.length verify_data)
        nonce = BS.pack $ BS.zipWith xor (integerToByteStringBE 12 sequence_number) client_iv
    (ciphertext, tag) <- chaCha20Poly1305AEAD client_key nonce handshakeFinishedPlaintext aad
    let handshakeFinished = buildHandshakeFinished nonce $ ciphertext <> tag
    sendAll sock $ BS.toStrict handshakeFinished

    void $ recvChangeCipherSpec sock
    void $ recvHandshakeFinished sock

main :: IO ()
main = undefined
