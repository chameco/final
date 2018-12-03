module Main where

import Control.Concurrent.MVar
import Control.Monad
import Control.Exception.Safe

import Data.Bits (xor)
import Data.Char (ord)
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

import Options.Applicative

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

server :: Options -> IO ()
server o = bracket open Net.close $ (>>= body . fst) . Net.accept
  where
    open = do
      let hints = Net.defaultHints {Net.addrFlags = [Net.AI_PASSIVE], Net.addrSocketType = Net.Stream}
      addr <- head <$> Net.getAddrInfo (Just hints) Nothing (Just . show $ port o)
      sock <- Net.socket (Net.addrFamily addr) (Net.addrSocketType addr) (Net.addrProtocol addr)
      Net.setSocketOption sock Net.ReuseAddr 1
      Net.bind sock $ Net.addrAddress addr
      Net.listen sock 10
      putStrLn $ mconcat ["Listening on port \"", show $ port o, "\""]
      return sock
    body sock = do
      putStrLn "Accepted connection from client"
      randomGen <- getStdGen >>= newMVar

      -- Receive Client Hello
      (client_rand, _cipher_suites) <- serverRecvHello sock -- TODO Use returned list of cipher suites
      putStrLn $ mconcat ["Received random data \"", toHex client_rand, "\""]

      -- Send Server Hello
      server_rand <- modifyMVar randomGen $ pure . swap . flip randomByteString 32
      putStrLn $ mconcat ["Generated random data \"", toHex server_rand, "\""]
      let hello = serverBuildHello server_rand
      sendAll sock $ BS.toStrict hello
      putStrLn $ mconcat ["Sent ServerHello \"", toHex hello, "\""]

      -- Server Key Exchange Generation
      priv <- pureModifyMVar randomGen generatePrivateKeyECDHE
      let pub = derivePublicKeyECDHE priv
          keyExchange = serverBuildKeyExchange pub
      putStrLn $ mconcat ["Generated ECDHE private key \"", toHex priv, "\""]
      putStrLn $ mconcat ["Derived ECDHE public key \"", toHex pub, "\""]
      
      -- Server Key Exchange
      sendAll sock $ BS.toStrict keyExchange
      putStrLn $ mconcat ["Sent ServerKeyExchange \"", toHex keyExchange, "\""]
      
      -- Server Hello Done
      sendAll sock $ BS.toStrict serverBuildHelloDone
      putStrLn $ mconcat ["Sent ServerHelloDone \"", toHex serverBuildHelloDone, "\""]

      -- Receive Client Key Exchange
      otherPub <- serverRecvKeyExchange sock
      putStrLn $ mconcat ["Received client ECDHE public key \"", toHex otherPub, "\""]
      let premaster = computeSharedSecretECDHE priv otherPub
          master = deriveMasterSecret server_rand client_rand premaster
          (client_key, server_key, client_iv, server_iv) = expandMasterSecret server_rand client_rand premaster
      putStrLn $ mconcat ["Computed premaster secret \"", toHex premaster, "\""]
      putStrLn $ mconcat ["Derived partial master secret \"", toHex master, "\""]
      putStrLn $ mconcat ["Expanded master secret to client write key \"", toHex client_key
                         , "\", server write key \"", toHex server_key
                         , "\", client IV \"", toHex client_iv
                         , "\", and server IV \"", toHex server_iv
                         ]

      -- Send Server Change Cipher Spec
      sendAll sock $ BS.toStrict buildChangeCipherSpec
      putStrLn $ mconcat ["Sent ServerChangeCipherSpec \"", toHex buildChangeCipherSpec, "\""]

      let verify_data = verify master "server finished" [hello, keyExchange, buildChangeCipherSpec]
          handshakeFinishedPlaintext = buildHandshakeFinishedPlaintext verify_data
          sequence_number = 0
          aad = integerToByteStringBE 8 sequence_number <> BS.pack [0x16, 0x03, 0x03] <> integerToByteStringBE 2 (fromIntegral $ BS.length verify_data)
          nonce = BS.pack $ BS.zipWith xor (integerToByteStringBE 12 sequence_number) server_iv
      (ciphertext, tag) <- chaCha20Poly1305AEAD server_key nonce handshakeFinishedPlaintext aad
      putStrLn $ mconcat ["Built verification data \"", toHex verify_data, "\""]
      putStrLn $ mconcat ["Encrypted verification data to \"", toHex ciphertext, "\" with MAC \"", toHex tag, "\""]

      -- Send Server Handshake Finished
      let handshakeFinished = buildHandshakeFinished nonce $ ciphertext <> tag
      sendAll sock $ BS.toStrict handshakeFinished
      putStrLn $ mconcat ["Sent ServerHandshakeFinished \"", toHex handshakeFinished, "\""]

      pure ()

client :: Options -> IO ()
client o = do
  addr:_ <- Net.getAddrInfo
    (Just $ Net.defaultHints { Net.addrSocketType = Net.Stream })
    (Just $ host o)
    (Just . show $ port o)
  bracket (Net.socket (Net.addrFamily addr) (Net.addrSocketType addr) (Net.addrProtocol addr)) Net.close $ \sock -> do
    putStrLn $ mconcat ["Attempting to connect to \"", host o, "\" on port \"", show $ port o, "\""]
    Net.connect sock $ Net.addrAddress addr
    putStrLn "Connected!"
    randomGen <- getStdGen >>= newMVar

    -- Send Client Hello
    client_rand <- pureModifyMVar randomGen generatePrivateKeyECDHE
    putStrLn $ mconcat ["Generated random data \"", toHex client_rand, "\""]

    let hello = clientBuildHello client_rand (BS.pack . fmap (fromIntegral . ord) $ host o)
    sendAll sock $ BS.toStrict hello
    putStrLn $ mconcat ["Sent ClientHello \"", toHex hello, "\""]

    -- Receive Server Hello
    server_rand <- clientRecvHello sock
    putStrLn $ mconcat ["Received random data \"", toHex server_rand, "\""]

    -- Receive Server Key Exchange
    otherPub <- clientRecvKeyExchange sock
    putStrLn $ mconcat ["Received server ECDHE public key \"", toHex otherPub, "\""]

    -- Client Key Exchange Generation
    priv <- pureModifyMVar randomGen generatePrivateKeyECDHE
    let pub = derivePublicKeyECDHE priv
        premaster = computeSharedSecretECDHE priv otherPub
        master = deriveMasterSecret server_rand client_rand premaster
        (client_key, server_key, client_iv, server_iv) = expandMasterSecret server_rand client_rand premaster
    putStrLn $ mconcat ["Generated ECDHE private key \"", toHex priv, "\""]
    putStrLn $ mconcat ["Derived ECDHE public key \"", toHex pub, "\""]
    putStrLn $ mconcat ["Computed premaster secret \"", toHex premaster, "\""]
    putStrLn $ mconcat ["Derived partial master secret \"", toHex master, "\""]
    putStrLn $ mconcat ["Expanded master secret to client write key \"", toHex client_key
                       , "\", server write key \"", toHex server_key
                       , "\", client IV \"", toHex client_iv
                       , "\", and server IV \"", toHex server_iv
                       ]

    -- Receive Server Hello Done
    clientRecvHelloDone sock
    putStrLn "Received ServerHelloDone"

    -- Send Client Key Exchange
    let keyExchange = clientBuildKeyExchange pub
    sendAll sock $ BS.toStrict keyExchange
    putStrLn $ mconcat ["Sent ClientKeyExchange \"", toHex keyExchange, "\""]

    -- Send Client Change Cipher Spec
    sendAll sock $ BS.toStrict buildChangeCipherSpec
    putStrLn $ mconcat ["Sent ClientChangeCipherSpec \"", toHex buildChangeCipherSpec, "\""]

    let verify_data = verify master "client finished" [hello, keyExchange, buildChangeCipherSpec]
        handshakeFinishedPlaintext = buildHandshakeFinishedPlaintext verify_data
        sequence_number = 0
        aad = integerToByteStringBE 8 sequence_number <> BS.pack [0x16, 0x03, 0x03] <> integerToByteStringBE 2 (fromIntegral $ BS.length verify_data)
        nonce = BS.pack $ BS.zipWith xor (integerToByteStringBE 12 sequence_number) client_iv
    (ciphertext, tag) <- chaCha20Poly1305AEAD client_key nonce handshakeFinishedPlaintext aad
    putStrLn $ mconcat ["Built verification data \"", toHex verify_data, "\""]
    putStrLn $ mconcat ["Encrypted verification data to \"", toHex ciphertext, "\" with MAC \"", toHex tag, "\""]

    -- Send Client Handshake Finished
    let handshakeFinished = buildHandshakeFinished nonce $ ciphertext <> tag
    sendAll sock $ BS.toStrict handshakeFinished
    putStrLn $ mconcat ["Sent ClientHandshakeFinished \"", toHex handshakeFinished, "\""]

    -- Receive Server Change Cipher Spec
    void $ recvChangeCipherSpec sock
    putStrLn "Received ServerChangeCipherspec"

    -- Receive Server Handshake Finished
    void $ recvHandshakeFinished sock
    putStrLn "Received ServerHandshakeFinished"

data Options = Options { port :: Integer
                       , host :: String
                       , cmd :: Options -> IO ()
                       } 

main :: IO ()
main = do
  opts <- execParser . flip info idm . (<**>helper) $ Options
    <$> option auto (long "port" <> metavar "PORT" <> value 3000 <> help "Port")
    <*> strOption (long "host" <> metavar "HOST" <> value "127.0.0.1" <> help "Hostname")
    <*> subparser (mconcat [ command "client" (info (pure client) idm)
                           , command "server" (info (pure server) idm)
                           ])
  cmd opts opts
