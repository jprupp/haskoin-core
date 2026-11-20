{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCashNode.Handshake
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- The life of a connection in Bitcoin Cash Node 29.2.0: framing errors, the
-- handshake (@version@, @extversion@, @verack@, @sendaddrv2@), @reject@,
-- @ping@ and @pong@, the ban score and what the node does when it crosses
-- @-banscore@, and the inactivity timeouts.
--
-- Each handler translates one upstream block of code, named in its
-- documentation with the file and lines. The order of the checks inside a
-- handler is the upstream order, because it decides what a peer sees when a
-- message breaks more than one rule: a @version@ from a peer that is both
-- too old and lacks the required services gets the @reject@ about services,
-- which upstream checks first.
--
-- The handshake differs from Bitcoin Core in three ways a peer can see:
--
-- * Bitcoin Cash Node still sends BIP 61 @reject@ messages by default.
-- * It has its own @extversion@ handshake, used when both sides offer
--   @NODE_EXTVERSION@; then @extversion@ takes the place of @sendaddrv2@ and
--   @verack@ in the answer to @version@.
-- * It scores misbehaviour with integers, and acts on the score only when it
--   crosses @-banscore@.
module Haskoin.Network.Protocol.BitcoinCashNode.Handshake
  ( initializeNode,
    frameError,
    bloomPrologue,
    receiveReject,
    receiveVersion,
    duplicateVersion,
    missingVersion,
    receiveExtVersion,
    receiveVerAck,
    receiveSendAddrV2,
    priorToVerAck,
    receivePing,
    receivePong,
    unknownCommand,
    parseError,
    sendRejectsAndCheckIfShouldDiscourage,
    inactivityCheck,
    sendPing,
    sanitizeString,
    hasAllDesirableServices,
  )
where

import Control.Monad (forM_, replicateM, unless, when)
import Control.Monad.RWS.Strict (get, gets, modify')
import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as C
import Data.Bytes.Get (getByteString, runGetS)
import Data.Bytes.Serial (deserialize)
import Data.Int (Int64)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Word (Word64)
import Haskoin.Network.Common
  ( MessageCommand (..),
    NetworkAddress (..),
    Ping (..),
    Pong (..),
    VarInt (..),
    VarString (..),
    Version (..),
    sockToHostAddress,
  )
import Haskoin.Network.CompactBlock (SendCompact (..))
import Haskoin.Network.Message (Message (..))
import Haskoin.Network.Protocol.BitcoinCashNode.Constants
import Haskoin.Network.Protocol.BitcoinCashNode.Options
import Haskoin.Network.Protocol.BitcoinCashNode.State
import Haskoin.Network.Protocol.Types
import Network.Socket (SockAddr (..))
import Numeric (showHex)

-- | Send our @version@ to a peer that the node connected to, which upstream
-- does as soon as the connection opens (@InitializeNode@,
-- @src\/net_processing.cpp:799-801@). The machine has no effect at @start@,
-- so it sends the @version@ before whatever the first input does.
initializeNode :: M ()
initializeNode = do
  s <- get
  when (isOutbound s.conn.connectionType && not s.versionSent) $
    pushNodeVersion (netProcessing 800 "InitializeNode: version to an outbound peer")

-- | Our @version@ (@PushNodeVersion@, @src\/net_processing.cpp:761-785@):
-- protocol 70016, the services offered to this peer, the time, the peer's
-- address (unknown to the machine, so the null address), a null address of
-- ours with our services, our nonce, our user agent, our height and the relay
-- flag, false in blocks-only mode.
pushNodeVersion :: Cite -> M ()
pushNodeVersion c = do
  o <- options
  e <- env
  s <- get
  let none = sockToHostAddress (SockAddrInet6 0 0 (0, 0, 0, 0) 0)
      v =
        Version
          { version = fromIntegral protocolVersion,
            services = s.ourServices,
            timestamp = e.now `div` 1000000,
            addrRecv = NetworkAddress 0 none,
            addrSend = NetworkAddress s.ourServices none,
            nonce = s.localNonce,
            userAgent = VarString (subVersion o),
            startHeight = fromIntegral e.tip.height,
            relay = not o.blocksOnly
          }
  modify' (\st -> st {versionSent = True})
  send (MVersion v) c

-- | What a framing error does (@CNode::ReceiveMsgBytes@ and
-- @PeerLogicValidation::ProcessMessages@):
--
-- * a header of a message that is too large closes the connection as soon as
--   it arrives, without misbehaviour (@src\/net.cpp:689@);
-- * the magic of another network discourages the address and closes every
--   connection from it, whatever the permissions of the peer
--   (@src\/net_processing.cpp:3876-3888@);
-- * a bad command drops the message (@src\/net_processing.cpp:3892-3896@);
-- * a bad checksum discourages the address and closes its connections, whatever
--   the permissions (@src\/net_processing.cpp:3902-3914@).
--
-- A payload that does not parse is not a framing error upstream: it reaches
-- the handler of its command, which throws. The top module routes
-- 'BadPayload' there.
frameError :: FrameError -> M ()
frameError = \case
  WrongMagic _ -> do
    emit Discourage (netProcessing 3882 "PROCESSMESSAGE: INVALID MESSAGESTART")
    disconnect ProtocolViolation (netProcessing 3884 "DisconnectNode(pfrom->addr)")
  BadCommand _ ->
    ignore (netProcessing 3893 "PROCESSMESSAGE: ERRORS IN HEADER")
  Oversized _ _ ->
    disconnect ProtocolViolation (netCpp 689 "Oversized header detected")
  BadChecksum _ -> do
    emit Discourage (netProcessing 3910 "CHECKSUM ERROR")
    disconnect ProtocolViolation (netProcessing 3912 "DisconnectNode(pfrom->addr)")
  BadPayload _ ->
    -- routed by the top module; never reached
    return ()

-- | @filterload@ and @filteradd@ when the node does not offer @NODE_BLOOM@ to
-- this peer, checked before anything else, even before @version@
-- (@src\/net_processing.cpp:2012-2023@): misbehaviour of 100 from a peer of
-- version 70011 or later, else a plain disconnect. Returns whether it acted.
bloomPrologue :: M Bool
bloomPrologue = do
  o <- options
  s <- get
  if offersBloom o s.perms
    then return False
    else do
      if s.peerVersion >= noBloomVersion
        then misbehaving 100 (netProcessing 2017 "no-bloom-version")
        else disconnect ProtocolViolation (netProcessing 2020 "bloom message without NODE_BLOOM")
      return True

-- | A @reject@ is only logged, in any state, even before @version@
-- (@src\/net_processing.cpp:2025-2051@). A @reject@ that does not parse is
-- caught there too, so that it never draws a @reject@ back.
receiveReject :: M ()
receiveReject = ignore (netProcessing 2050 "Reject")

-- | Any message but @version@, @reject@ and the Bloom case before @version@
-- (@src\/net_processing.cpp:2308-2313@).
missingVersion :: M ()
missingVersion = misbehaving 10 (netProcessing 2311 "missing-version")

-- | The checks of @version@ in upstream order (@src\/net_processing.cpp:2053-2306@).
receiveVersion :: Version -> M ()
receiveVersion v = do
  o <- options
  e <- env
  s <- get
  inbound <- isInbound
  noban <- hasPerm PermNoBan
  let ver = fromIntegral v.version :: Int
      nTime = max 0 v.timestamp
      ct = s.conn.connectionType
      subver = sanitizeString v.userAgent
      beforeParen = fst (BS.break (== 0x28) subver)
      rejected =
        [ r
        | r <- o.rejectSubVersions,
          not (BS.null r),
          r `BS.isInfixOf` beforeParen
        ]
  if s.peerVersion /= 0
    then duplicateVersion
    else do
      unless inbound $
        process "record the services of the peer in addrman" $
          netProcessing 2087 "SetServices"
      let desirable = desirableServices e v.services
      if expectServices ct && not (hasAllDesirableServices e v.services)
        then do
          sendReject MCVersion 0x40 (T.pack ("Expected to offer services " <> hex8 desirable)) Nothing $
            netProcessing 2100 "does not offer the expected services"
          disconnect Unsuitable (netProcessing 2104 "does not offer the expected services")
        else
          if ver < minPeerProtoVersion
            then do
              sendReject MCVersion 0x11 "Version must be 31800 or greater" Nothing $
                netProcessing 2117 "using obsolete version"
              disconnect Unsuitable (netProcessing 2121 "using obsolete version")
            else
              if not (null rejected) && ct /= Manual && not noban
                then disconnect Unsuitable (netProcessing 2148 "-rejectsubversion")
                else
                  if inbound && e.ownNonce v.nonce
                    then disconnect ProtocolViolation (netProcessing 2165 "connected to self")
                    else accept o e inbound v nTime subver
  where
    hex8 w = let h = showHex w "" in replicate (8 - length h) '0' <> h

-- | A second @version@ (@src\/net_processing.cpp:2054-2066@): a @reject@
-- and a score of 1, checked before the payload is read.
duplicateVersion :: M ()
duplicateVersion = do
  sendReject MCVersion 0x12 "Duplicate version message" Nothing $
    netProcessing 2060 "Duplicate version message"
  misbehaving 1 (netProcessing 2064 "multiple-version")

-- | The part of @version@ after the checks that can refuse it
-- (@src\/net_processing.cpp:2169-2305@).
accept :: Options -> Env -> Bool -> Version -> Int64 -> ByteString -> M ()
accept o e inbound v nTime subver = do
  s0 <- get
  let ct = s0.conn.connectionType
      ver = fromIntegral v.version :: Int
      vServices = v.services
  when inbound $
    pushNodeVersion (netProcessing 2175 "PushNodeVersion to an inbound peer")
  modify' (\s -> s {peerServices = vServices})
  if vServices .&. nodeExtVersion /= 0 && o.useExtVersion
    then do
      send (MOther extVersionCommand ourExtVersion) $
        netProcessing 2193 "extversion instead of verack"
      modify' (\s -> s {extVersionExpected = True})
    else pushVerAck ver (netProcessing 2197 "PushVerACK")
  noban <- hasPerm PermNoBan
  let isClient = vServices .&. nodeNetwork == 0 && vServices .&. nodeNetworkLimited == 0
      isLimited = vServices .&. nodeNetwork == 0 && vServices .&. nodeNetworkLimited /= 0
  modify' $ \s ->
    s
      { peerSubVer = TE.decodeLatin1 subver,
        peerStartHeight = v.startHeight,
        client = isClient,
        limitedNode = isLimited,
        peerVersion = ver,
        preferredDownload = (not inbound || noban) && ct /= AddrFetch && not isClient
      }
  modifyRelay (\r -> r {relayTxes = v.relay})
  when (not inbound && ct /= BlockRelayOnly) $ do
    when (o.listen && not e.initialBlockDownload) $
      forM_ e.localAddress $ \a -> do
        pushAddress a
        process "advertise our address" (netProcessing 2257 "advertising address")
    pushGetAddrOnce (netProcessing 2267 "PushGetAddrOnceIfAfterVerAck")
    process "mark the address good in addrman" (netProcessing 2271 "MarkAddressGood")
  let offset = nTime - e.now `div` 1000000
  modify' (\s -> s {timeOffset = offset})
  if nTime < genesisTime o
    then
      misbehaving 20 $
        netProcessing 2293 "Ignoring invalid timestamp in version message"
    else
      unless inbound $
        process "sample the clock of the peer" (netProcessing 2298 "AddTimeData")
  when (ct == Feeler) $
    disconnect Done (netProcessing 2303 "feeler connection done")

-- | Our @extversion@: a map with the key 0 (version) set to 100, which is
-- version 0.1.0 (@src\/extversion.h:50-52,75@).
ourExtVersion :: ByteString
ourExtVersion = BS.pack [0x01, 0x00, 0x01, 0x64]

-- | The services the node wants from an outbound peer
-- (@GetDesirableServiceFlags@, @src\/protocol.cpp:184-190@):
-- @NODE_NETWORK_LIMITED@ suffices out of initial block download, if the peer
-- offers it.
desirableServices :: Env -> Word64 -> Word64
desirableServices e srv
  | srv .&. nodeNetworkLimited /= 0 && not e.initialBlockDownload = nodeNetworkLimited
  | otherwise = nodeNetwork

-- | The peer offers all the services the node wants
-- (@HasAllDesirableServiceFlags@, @src\/protocol.h@).
hasAllDesirableServices :: Env -> Word64 -> Bool
hasAllDesirableServices e srv =
  let d = desirableServices e srv in srv .&. d == d

-- | Connections that must offer the desirable services
-- (@ExpectServicesFromConn@, @src\/net.h:1078-1091@).
expectServices :: ConnectionType -> Bool
expectServices = \case
  OutboundFullRelay -> True
  BlockRelayOnly -> True
  AddrFetch -> True
  _ -> False

-- | @sendaddrv2@ to peers of version 70016 or later, then @verack@
-- (@PushVerACK@, @src\/net_processing.cpp:1890-1902@). A version of 0 means
-- the peer's.
pushVerAck :: Int -> Cite -> M ()
pushVerAck ver0 _ = do
  pv <- gets (.peerVersion)
  let ver = if ver0 == 0 then pv else ver0
  when (ver >= featureNegotiationVersion) $
    send MSendAddrV2 (netProcessing 1897 "PushVerACK: SENDADDRV2")
  send MVerAck (netProcessing 1901 "PushVerACK: VERACK")
  modify' (\s -> s {verAckSent = True})

-- | @getaddr@ once to a peer the node connected to, after our @verack@
-- (@PushGetAddrOnceIfAfterVerAck@, @src\/net_processing.cpp:1870-1883@). It
-- opens the address token bucket by 1000 for the reply.
pushGetAddrOnce :: Cite -> M ()
pushGetAddrOnce _ = do
  s <- get
  inbound <- isInbound
  when (not inbound && s.verAckSent && not s.getAddrSent) $ do
    send MGetAddr (netProcessing 1875 "PushGetAddrOnceIfAfterVerAck: GETADDR")
    modify' (\st -> st {getAddrSent = True})
    modifyRelay $ \r ->
      r
        { getAddrPending = True,
          addrTokens = r.addrTokens + fromIntegral maxAddrToSend
        }

-- | @extversion@ after @version@ (@src\/net_processing.cpp:2315-2341@). The
-- expectation flag is cleared before any check, so a peer whose
-- @extversion@ does not parse never gets our @verack@ when its own arrives.
receiveExtVersion :: Maybe ByteString -> M ()
receiveExtVersion mpayload = do
  modify' (\s -> s {extVersionExpected = False})
  done <- gets (.connected)
  if done
    then disconnect ProtocolViolation (netProcessing 2319 "extversion message after verack")
    else case mpayload >>= parseExtVersion of
      Nothing -> parseError (MCOther extVersionCommand)
      Just () -> do
        modify' (\s -> s {extVersionEnabled = True})
        pushVerAck 0 (netProcessing 2336 "PushVerACK after extversion")
        pushGetAddrOnce (netProcessing 2338 "GETADDR after extversion")

-- | Parse an @extversion@ payload as @extversion::Message::Unserialize@
-- does (@src\/extversion.h:155-176@): at most 100000 bytes, at most 8192
-- keys, each a compact size and a byte vector, and the value of key 0 a
-- compact size.
parseExtVersion :: ByteString -> Maybe ()
parseExtVersion bs
  | BS.length bs > extVersionMaxSize = Nothing
  | otherwise = either (const Nothing) Just (runGetS parser bs)
  where
    parser = do
      VarInt n <- deserialize
      when (n > extVersionMaxKeys) $ fail "too many keys"
      _ <- replicateM (fromIntegral n) entry
      return ()
    entry = do
      VarInt key <- deserialize
      VarInt len <- deserialize
      value <- getByteString (fromIntegral len)
      when (key == 0) $
        case runGetS deserialize value :: Either String VarInt of
          Left err -> fail err
          Right _ -> return ()
      return ()

-- | @verack@ (@src\/net_processing.cpp:2346-2391@). Duplicates are not
-- checked: each one sends @sendheaders@ and @sendcmpct@ again.
receiveVerAck :: M ()
receiveVerAck = do
  s <- get
  when s.extVersionExpected $ do
    pushVerAck 0 (netProcessing 2366 "PushVerACK: peer answered extversion with verack")
    pushGetAddrOnce (netProcessing 2368 "GETADDR after verack")
  when (s.peerVersion >= sendHeadersVersion) $
    send MSendHeaders (netProcessing 2376 "SENDHEADERS")
  when (s.peerVersion >= shortIdsBlocksVersion) $
    send (MSendCompact (SendCompact False 1)) (netProcessing 2385 "SENDCMPCT")
  modify' (\st -> st {connected = True})

-- | @sendaddrv2@ (@src\/net_processing.cpp:2393-2402@): allowed only before
-- the peer's @verack@.
receiveSendAddrV2 :: M ()
receiveSendAddrV2 = do
  done <- gets (.connected)
  if done
    then disconnect ProtocolViolation (netProcessing 2397 "SENDADDRV2 after VERACK")
    else modify' (\s -> s {wantsAddrV2 = True})

-- | Any other message between @version@ and the peer's @verack@: dropped
-- without misbehaviour (@src\/net_processing.cpp:2404-2408@).
priorToVerAck :: M ()
priorToVerAck = ignore (netProcessing 2405 "Unsupported message prior to verack")

-- | @ping@ (@src\/net_processing.cpp:3530-3551@): a @pong@ with the same
-- nonce from peers above version 60000; a short payload throws ('Nothing').
receivePing :: Maybe Word64 -> M ()
receivePing mnonce = do
  pv <- gets (.peerVersion)
  if pv > bip0031Version
    then case mnonce of
      Nothing -> parseError MCPing
      Just n -> send (MPong (Pong n)) (netProcessing 3548 "PONG")
    else ignore (netProcessing 3531 "ping of a peer of version 60000 or less")

-- | @pong@ (@src\/net_processing.cpp:3553-3610@). It never draws misbehaviour;
-- it ends the outstanding ping when the nonce matches, when it is zero, or
-- when the payload is short ('Nothing').
receivePong :: Maybe Word64 -> M ()
receivePong mnonce = do
  s <- get
  t <- nowM
  case mnonce of
    Nothing -> finish (netProcessing 3596 "Short payload")
    Just n
      | s.pingNonceSent == 0 ->
          ignore (netProcessing 3591 "Unsolicited pong without ping")
      | n == s.pingNonceSent -> do
          let rtt = t - s.pingStart
          when (rtt > 0) $
            modify' $ \st ->
              st
                { pingTime = Just rtt,
                  minPingTime = Just (maybe rtt (min rtt) st.minPingTime)
                }
          finish (netProcessing 3607 "ping finished")
      | n == 0 -> finish (netProcessing 3587 "Nonce zero")
      | otherwise -> ignore (netProcessing 3582 "Nonce mismatch")
  where
    finish c = do
      modify' (\st -> st {pingNonceSent = 0})
      ignore c

-- | A command that no handler takes, after the handshake
-- (@src\/net_processing.cpp:3765-3768@).
unknownCommand :: M ()
unknownCommand = ignore (netProcessing 3766 "Unknown command")

-- | A payload that throws while its handler reads it: a @reject@ with code
-- @REJECT_MALFORMED@, no misbehaviour (@src\/net_processing.cpp:3927-3934@).
parseError :: MessageCommand -> M ()
parseError cmd =
  sendReject cmd 0x01 "error parsing message" Nothing $
    netProcessing 3929 "error parsing message"

-- | Run after each message and at each pass of @SendMessages@
-- (@SendRejectsAndCheckIfShouldDiscourage@, @src\/net_processing.cpp:3771-3810@):
-- send the @reject@s of invalid blocks, then act on a crossed ban score:
-- nothing for a @noban@ or manual peer, a plain disconnect for a local
-- address, and otherwise discouragement of the address and the end of every
-- connection from it. Returns whether the score was acted on.
sendRejectsAndCheckIfShouldDiscourage :: M Bool
sendRejectsAndCheckIfShouldDiscourage = do
  o <- options
  rs <- gets (.blockRejects)
  when o.enableBip61 $
    forM_ rs (`send` netProcessing 3777 "reject of an invalid block")
  modify' (\s -> s {blockRejects = []})
  s <- get
  if not s.shouldDiscourage
    then return False
    else do
      modify' (\st -> st {shouldDiscourage = False})
      noban <- hasPerm PermNoBan
      if
        | noban -> return ()
        | s.conn.connectionType == Manual -> return ()
        | s.conn.peerIsLocal ->
            disconnect Misbehaviour $
              netProcessing 3799 "disconnecting but not discouraging local peer"
        | otherwise -> do
            emit Discourage (netProcessing 3803 "Discourage")
            disconnect Misbehaviour (netProcessing 3805 "DisconnectNode(pnode->addr)")
      return True

-- | The inactivity check of the socket thread (@CConnman::InactivityCheck@,
-- @src\/net.cpp:1272-1303@). Nothing is checked until the connection is
-- older than @-peertimeout@; then the first rule that holds closes it. Times
-- are compared in whole seconds, as upstream does but for the ping.
inactivityCheck :: M ()
inactivityCheck = do
  o <- options
  s <- get
  t <- nowM
  let secs x = x `div` 1000000
      nowS = secs t
      recvLimit
        | s.peerVersion > bip0031Version = secs timeoutInterval
        | otherwise = secs oldPeerReceiveTimeout
  when (nowS - secs s.conn.openedAt > o.peerTimeout) $
    if
      | s.lastRecv == 0 || s.lastSend == 0 ->
          disconnect Timeout (netCpp 1280 "socket no message in first seconds")
      | nowS - secs s.lastSend > secs timeoutInterval ->
          disconnect Timeout (netCpp 1284 "socket sending timeout")
      | nowS - secs s.lastRecv > recvLimit ->
          disconnect Timeout (netCpp 1290 "socket receive timeout")
      | s.pingNonceSent /= 0 && s.pingStart + timeoutInterval < t ->
          disconnect Timeout (netCpp 1296 "ping timeout")
      | not s.connected ->
          disconnect Timeout (netCpp 1300 "version handshake timeout")
      | otherwise -> return ()

-- | The ping of @SendMessages@ (@src\/net_processing.cpp:4161-4190@): when an
-- operator asked for one, or when none is outstanding and the last one is
-- older than two minutes. The first ping goes out on the first pass after
-- the handshake. Peers of version 60000 or less get a @ping@ without a nonce
-- and are not expected to answer.
sendPing :: M ()
sendPing = do
  s <- get
  t <- nowM
  when (s.pingQueued || (s.pingNonceSent == 0 && s.pingStart + pingInterval < t)) $ do
    nonce <- nonZero
    modify' (\st -> st {pingQueued = False, pingStart = t})
    if s.peerVersion > bip0031Version
      then do
        modify' (\st -> st {pingNonceSent = nonce})
        send (MPing (Ping nonce)) (netProcessing 4183 "PING")
      else do
        modify' (\st -> st {pingNonceSent = 0})
        send (MOther "ping" BS.empty) (netProcessing 4188 "PING without nonce")
  where
    nonZero = do
      w <- randomWord
      if w == 0 then nonZero else return w

-- | Keep the characters of a user agent that @SanitizeString@ keeps by
-- default: letters, digits and @ .,;-_\/:?\@()@
-- (@src\/util\/strencodings.cpp:32-34@).
sanitizeString :: VarString -> ByteString
sanitizeString (VarString bs) = BS.filter safe bs
  where
    safe w = C.elem (toEnum (fromIntegral w)) allowed
    allowed =
      C.pack
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;-_/:?@()"
