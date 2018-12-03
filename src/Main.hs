module Main where

import Control.Concurrent.MVar
import Control.Monad
import Control.Monad.IO.Class
import Control.Exception.Safe

import Data.Bits (xor)
import Data.Char (chr, ord)
import Data.Tuple (swap)
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as BS

import Final.Utility.ByteString
import Final.Hash.SHA256 (sha256)
import Final.Hash.HMAC (hmac)
import Final.Cipher.ECC (generatePrivateKeyECDHE, derivePublicKeyECDHE, computeSharedSecretECDHE)
import Final.Cipher.ChaCha20 (chaCha20Poly1305AEAD, chaCha20Poly1305UnAEAD)
import Final.TLS

import System.Random
import System.IO (hFlush, stdout)

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

expandMasterSecret :: ByteString -> ByteString -> ByteString -> (ByteString, ByteString, ByteString, ByteString, ByteString)
expandMasterSecret server_rand client_rand master = (client_key, server_key, client_iv, server_iv, rest''')
  where seed = "key expansion" <> server_rand <> client_rand
        as = iterate (hmac master) seed
        ps = hmac master . (<>seed) <$> as
        material = BS.concat ps
        (client_key, rest) = BS.splitAt 32 material
        (server_key, rest') = BS.splitAt 32 rest
        (client_iv, rest'') = BS.splitAt 12 rest'
        (server_iv, rest''') = BS.splitAt 12 rest''

verify :: ByteString -> ByteString -> [ByteString] -> ByteString
verify master input messages = BS.take 12 p1
  where seed = input <> sha256 (mconcat messages)
        a1 = hmac master seed
        p1 = hmac master (a1 <> seed)

sendEncrypted :: (MonadThrow m, MonadIO m) => Net.Socket -> Integer -> ByteString -> ByteString -> ByteString -> m ()
sendEncrypted sock sequence_number key eiv msg = if BS.length msg > 65535
  then throwString "Message too long"
  else let aad = integerToByteStringBE 8 sequence_number <> BS.pack [0x16, 0x03, 0x03] <> integerToByteStringBE 2 (fromIntegral $ BS.length msg)
           nonce = BS.pack $ BS.zipWith xor (integerToByteStringBE 12 sequence_number) eiv
       in do (ciphertext, tag) <- chaCha20Poly1305AEAD key nonce msg aad
             liftIO . putStrLn $ mconcat ["Computed nonce \"", toHex nonce, "\" and AAD \"", toHex aad, "\""]
             liftIO . putStrLn $ mconcat ["Encrypted message to \"", toHex ciphertext
                                         , "\" with tag \"", toHex tag
                                         , "\" and IV \"", toHex eiv, "\""
                                         ]
             void . liftIO . sendAll sock . BS.toStrict . buildApplicationData eiv $ tag <> ciphertext

recvEncrypted :: (MonadThrow m, MonadIO m) => Net.Socket -> Integer -> ByteString -> m ByteString
recvEncrypted sock sequence_number key = do
  (eiv, rest) <- BS.splitAt 12 <$> recvApplicationData sock
  let (tag, ciphertext) = BS.splitAt 16 rest
      aad = integerToByteStringBE 8 sequence_number <> BS.pack [0x16, 0x03, 0x03] <> integerToByteStringBE 2 (fromIntegral $ BS.length ciphertext)
      nonce = BS.pack $ BS.zipWith xor (integerToByteStringBE 12 sequence_number) eiv
  liftIO . putStrLn $ mconcat ["Received ciphertext \"", toHex ciphertext
                              , "\" tag \"" , toHex tag
                              , "\" and IV \"", toHex eiv, "\""
                              ]
  liftIO . putStrLn $ mconcat ["Computed nonce \"", toHex nonce, "\" and AAD \"", toHex aad, "\""]
  md <- chaCha20Poly1305UnAEAD key nonce (ciphertext, tag) aad
  case md of
    Nothing -> throwString $ mconcat ["Failed to decrypt/validate ciphertext \"", toHex ciphertext, "\" with tag \"", toHex tag, "\""]
    Just d -> pure d

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
          (client_key, server_key, client_iv, server_iv, randstream) = expandMasterSecret server_rand client_rand premaster
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
      putStrLn $ mconcat ["Encrypted verification data to \"", toHex ciphertext, "\" with tag \"", toHex tag, "\""]

      -- Send Server Handshake Finished
      let handshakeFinished = buildHandshakeFinished nonce $ tag <> ciphertext
      sendAll sock $ BS.toStrict handshakeFinished
      putStrLn $ mconcat ["Sent ServerHandshakeFinished \"", toHex handshakeFinished, "\""]

      -- Receive Client Change Cipher Spec
      void $ recvChangeCipherSpec sock
      putStrLn "Received ClientChangeCipherspec"

      (remote_eiv, remote_rest) <- BS.splitAt 12 <$> recvHandshakeFinished sock
      let (remote_tag, remote_ciphertext) = BS.splitAt 16 remote_rest
      putStrLn $ mconcat ["Received ClientHandshakeFinished with ciphertext \"", toHex remote_ciphertext
                         , "\" tag \"" , toHex remote_tag
                         , "\" and IV \"", toHex remote_eiv, "\""
                         ]
      let remote_verify_data = verify master "client finished" [clientBuildHello client_rand (BS.pack . fmap (fromIntegral . ord) $ host o)
                                                               , clientBuildKeyExchange otherPub
                                                               , buildChangeCipherSpec
                                                               ]
          remote_sequence_number = 0
          remote_aad = integerToByteStringBE 8 remote_sequence_number <> BS.pack [0x16, 0x03, 0x03] <> integerToByteStringBE 2 (fromIntegral $ BS.length remote_verify_data)
          remote_nonce = BS.pack $ BS.zipWith xor (integerToByteStringBE 12 remote_sequence_number) client_iv
      putStrLn $ mconcat ["Built remote verification data \"", toHex remote_verify_data, "\""]
      remote_msg <- chaCha20Poly1305UnAEAD client_key remote_nonce (remote_ciphertext, remote_tag) remote_aad
      case remote_msg of
        Nothing -> throwString "Failed to decrypt ServerHandshakefinished ciphertext!"
        Just d -> do
          putStrLn $ mconcat ["Decrypted ClientHandshakeFinished ciphertext to \"", toHex d, "\""]
          (_, _, vd) <- parseHandshakeHeader 0x14 d
          if vd /= remote_verify_data
            then throwString $ mconcat ["Expected verification data \"", toHex remote_verify_data, "\", received \"", toHex vd, "\""]
            else putStrLn "Established encrypted channel!" >> serverLoop sock (server_key, client_key) 1 randstream

serverLoop :: (MonadThrow m, MonadIO m) => Net.Socket -> (ByteString, ByteString) -> Integer -> ByteString -> m ()
serverLoop sock keys@(server_key, client_key) sequence_number r = do
  let (eiv, r') = BS.splitAt 12 r
  d <- recvEncrypted sock sequence_number client_key
  sendEncrypted sock sequence_number server_key eiv $ BS.reverse d
  serverLoop sock keys (sequence_number + 1) r'

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
        (client_key, server_key, client_iv, server_iv, randstream) = expandMasterSecret server_rand client_rand premaster
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
        sequence_number = 0
        aad = integerToByteStringBE 8 sequence_number <> BS.pack [0x16, 0x03, 0x03] <> integerToByteStringBE 2 (fromIntegral $ BS.length verify_data)
        nonce = BS.pack $ BS.zipWith xor (integerToByteStringBE 12 sequence_number) client_iv
        handshakeFinishedPlaintext = buildHandshakeFinishedPlaintext verify_data
    (ciphertext, tag) <- chaCha20Poly1305AEAD client_key nonce handshakeFinishedPlaintext aad
    putStrLn $ mconcat ["Built verification data \"", toHex verify_data, "\""]
    putStrLn $ mconcat ["Encrypted verification data to \"", toHex ciphertext, "\" with tag \"", toHex tag, "\""]

    -- Send Client Handshake Finished
    let handshakeFinished = buildHandshakeFinished nonce $ tag <> ciphertext
    sendAll sock $ BS.toStrict handshakeFinished
    putStrLn $ mconcat ["Sent ClientHandshakeFinished \"", toHex handshakeFinished, "\""]

    -- Receive Server Change Cipher Spec
    void $ recvChangeCipherSpec sock
    putStrLn "Received ServerChangeCipherspec"

    -- Receive Server Handshake Finished
    (remote_eiv, remote_rest) <- BS.splitAt 12 <$> recvHandshakeFinished sock
    let (remote_tag, remote_ciphertext) = BS.splitAt 16 remote_rest
    putStrLn $ mconcat ["Received ServerHandshakeFinished with ciphertext \"", toHex remote_ciphertext
                       , "\" tag \"" , toHex remote_tag
                       , "\" and IV \"", toHex remote_eiv, "\""
                       ]
    let remote_verify_data = verify master "server finished" [serverBuildHello server_rand, serverBuildKeyExchange otherPub, buildChangeCipherSpec]
        remote_sequence_number = 0
        remote_aad = integerToByteStringBE 8 remote_sequence_number <> BS.pack [0x16, 0x03, 0x03] <> integerToByteStringBE 2 (fromIntegral $ BS.length remote_verify_data)
        remote_nonce = BS.pack $ BS.zipWith xor (integerToByteStringBE 12 remote_sequence_number) server_iv
    putStrLn $ mconcat ["Built remote verification data \"", toHex remote_verify_data, "\""]
    remote_msg <- chaCha20Poly1305UnAEAD server_key remote_nonce (remote_ciphertext, remote_tag) remote_aad
    case remote_msg of
      Nothing -> throwString "Failed to decrypt ServerHandshakefinished ciphertext!"
      Just d -> do
        putStrLn $ mconcat ["Decrypted ServerHandshakeFinished ciphertext to \"", toHex d, "\""]
        (_, _, vd) <- parseHandshakeHeader 0x14 d
        if vd /= remote_verify_data
          then throwString $ mconcat ["Expected verification data \"", toHex remote_verify_data, "\", received \"", toHex vd, "\""]
          else putStrLn "Established encrypted channel!" >> clientLoop sock (server_key, client_key) 1 randstream

clientLoop :: (MonadThrow m, MonadIO m) => Net.Socket -> (ByteString, ByteString) -> Integer -> ByteString -> m ()
clientLoop sock keys@(server_key, client_key) sequence_number r = do
  let (eiv, r') = BS.splitAt 12 r
  d <- liftIO (putStr "> " >> hFlush stdout >> getLine)
  sendEncrypted sock sequence_number client_key eiv . BS.pack $ fmap (fromIntegral . ord) d
  resp <- recvEncrypted sock sequence_number server_key
  liftIO . putStrLn . fmap (chr . fromIntegral) $ BS.unpack resp
  clientLoop sock keys (sequence_number + 1) r'

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
