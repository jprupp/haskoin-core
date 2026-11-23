{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCore.Handshake
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- The life of a connection to Bitcoin Core 32.1, apart from blocks and
-- relay: framing errors, the handshake (@version@, @verack@ and the
-- messages allowed between them: @wtxidrelay@, @sendaddrv2@, @feature@,
-- @sendtxrcncl@), @ping@ and @pong@, the inactivity checks and the
-- punishment of misbehaviour.
--
-- Each handler names the upstream function it translates and the lines
-- that decide. Most of them are in @ProcessMessage@ of
-- @src\/net_processing.cpp@; the framing and inactivity rules are in
-- @src\/net.cpp@.
--
-- The handshake of Bitcoin Core is lenient in one direction and strict in
-- the other. Before the peer's @version@, every other message is dropped
-- without a word; between @version@ and @verack@, only the feature
-- negotiation messages count, and the rest are dropped. But a feature
-- negotiation message after @verack@ closes the connection, because the
-- features must be fixed before either side relies on them.
module Haskoin.Network.Protocol.BitcoinCore.Handshake
  ( -- * Framing
    badFrame,

    -- * Handshake
    pushNodeVersion,
    handleVersion,
    handleVerAck,
    handleWtxidRelay,
    handleSendAddrV2,
    handleFeature,
    handleSendTxRcncl,

    -- * Ping
    handlePing,
    handlePong,
    maybeSendPing,

    -- * Timers and punishment
    inactivityCheck,
    shouldRunInactivityChecks,
    maybeDiscourageAndDisconnect,

    -- * Shared rules
    rejectIncomingTxs,
    setupAddressRelay,
    maybeDisconnectForTxRelayCapacity,
  )
where

import Control.Monad (unless, when)
import Data.Bits ((.&.), (.|.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get (getBytes, isEmpty, runGetS)
import Data.Bytes.Serial (deserialize)
import Data.Int (Int64)
import Data.Word (Word64)
import Haskoin.Network.Common
  ( Inv (..),
    InvType (..),
    InvVector (..),
    NetworkAddress (..),
    Ping (..),
    Pong (..),
    SendTxRcncl (..),
    VarInt (..),
    VarString (..),
    Version (..),
    nodeNetwork,
    nodeNetworkLimited,
    nodeWitness,
    sockToHostAddress,
  )
import Haskoin.Network.CompactBlock (SendCompact (..))
import Haskoin.Network.Data (Network (..))
import Haskoin.Network.Message (Message (..))
import Haskoin.Network.Protocol.BitcoinCore.Constants
import Haskoin.Network.Protocol.BitcoinCore.Machine
import Haskoin.Network.Protocol.BitcoinCore.State
import Haskoin.Network.Protocol.Types
import Haskoin.Transaction.Common (TxHash (..), txHash)
import Network.Socket (SockAddr (..))

-- | Bytes from the peer that are not a message the node accepts
-- (@V1Transport::readHeader@, @V1Transport::GetReceivedMessage@,
-- @V2Transport::ProcessReceivedPacketBytes@ and the exception handler of
-- @ProcessMessages@). A wrong magic or a size over the limit is a transport
-- error and closes the socket at once; a wrong checksum or a malformed
-- command name drops the message; a payload that does not parse throws in
-- @ProcessMessage@, which @ProcessMessages@ catches and logs.
badFrame :: FrameError -> M ()
badFrame err = do
  s <- getS
  case err of
    WrongMagic _
      | s.transport == TransportV2 ->
          disconnect ProtocolViolation $
            netCpp 1144 "V2 transport error: V1 peer with wrong MessageStart"
      | otherwise ->
          disconnect ProtocolViolation $
            netCpp 765 "Header error: Wrong MessageStart"
    Oversized _ _
      | s.transport == TransportV2 ->
          disconnect ProtocolViolation $
            netCpp 1230 "V2 transport error: packet too large"
      | otherwise ->
          disconnect ProtocolViolation $
            netCpp 773 "Header error: Size too large"
    BadChecksum _ -> ignore $ netCpp 836 "Header error: Wrong checksum"
    BadCommand _ -> ignore $ netCpp 840 "Header error: Invalid message type"
    BadPayload _ -> ignore $ netProcessing 5493 "Exception caught"

-- | @PushNodeVersion@: the node's @version@. A private broadcast connection
-- sends an anonymous one: no services, time 0, height 0, the user agent
-- @\/pynode:0.0.1\/@ and no relay. The address of the peer in @addr_recv@ is
-- left empty here: the machine does not know it, and upstream leaves it
-- empty for inbound peers' services and for unroutable addresses.
pushNodeVersion :: M ()
pushNodeVersion = do
  s <- getS
  o <- opts
  e <- env
  rejects <- rejectIncomingTxs
  let pb = s.connectionType == PrivateBroadcast
      zeroAddr = sockToHostAddress (SockAddrInet6 0 0 (0, 0, 0, 0) 0)
      services = if pb then 0 else s.ourServices
      v =
        Version
          { version = if pb then privateBroadcastVersion else protocolVersion,
            services = services,
            timestamp = if pb then 0 else e.now `div` 1000000,
            addrRecv = NetworkAddress 0 zeroAddr,
            addrSend = NetworkAddress services zeroAddr,
            nonce = s.localNonce,
            userAgent = VarString (if pb then "/pynode:0.0.1/" else o.userAgent),
            startHeight = if pb then 0 else fromIntegral e.tip.height,
            relay = not pb && not rejects
          }
  send (MVersion v) $ netProcessing 1675 "send version message"
  modifyS $ \st -> st {versionSent = True}

-- | @RejectIncomingTxs@: the node told the peer not to send transactions,
-- and disconnects it if it does: a block-relay-only or feeler connection,
-- or @-blocksonly@ without 'PermRelay'.
rejectIncomingTxs :: M Bool
rejectIncomingTxs = do
  s <- getS
  o <- opts
  return $
    s.connectionType == BlockRelayOnly
      || s.connectionType == Feeler
      || (o.blocksOnly && not (hasPermission PermRelay s))

-- | @SetupAddressRelay@: start address relay with the peer, unless the
-- connection is block-relay-only or a feeler. Outbound peers start at their
-- @version@, inbound peers at their first @addr@, @addrv2@ or @getaddr@.
setupAddressRelay :: M Bool
setupAddressRelay = do
  s <- getS
  if s.connectionType == BlockRelayOnly || s.connectionType == Feeler
    then return False
    else do
      putS s {addrRelay = True}
      return True

-- | @MaybeDisconnectForTxRelayCapacity@: an inbound peer that relays
-- transactions takes one of the limited slots for them
-- (@-inboundrelaypercent@). When they are full, the node evicts another
-- such peer, and only if it cannot does it drop this one. Which peer goes
-- is a decision across peers: @txRelayInboundFull@ of t'Env' says that none
-- could. True when the peer is dropped.
maybeDisconnectForTxRelayCapacity :: M Bool
maybeDisconnectForTxRelayCapacity = do
  s <- getS
  e <- env
  if s.connectionType /= Inbound || not s.relaysTxs || not e.txRelayInboundFull
    then return False
    else do
      disconnect Resources $
        netProcessing 5415 "failed to find a tx-relaying eviction candidate"
      return True

-- | The services the node wants from an outbound peer
-- (@GetDesirableServiceFlags@): @NODE_NETWORK | NODE_WITNESS@, or
-- @NODE_NETWORK_LIMITED | NODE_WITNESS@ from a limited peer when the tip
-- is less than 144 blocks old by the clock.
desirableServices :: Word64 -> M Word64
desirableServices services = do
  e <- env
  o <- opts
  let spacing = max 1 (fromIntegral o.network.targetSpacing) :: Int64
      depth = (e.now `div` 1000000 - fromIntegral e.tip.time) `div` spacing
  return $
    if services .&. nodeNetworkLimited /= 0 && depth < nodeNetworkLimitedAllowConnBlocks
      then nodeNetworkLimited .|. nodeWitness
      else nodeNetwork .|. nodeWitness

-- | Whether the connection type requires services (@ExpectServicesFromConn@).
expectServices :: ConnectionType -> Bool
expectServices t = t `elem` [OutboundFullRelay, BlockRelayOnly, AddrFetch, PrivateBroadcast]

-- | @version@ (@ProcessMessage@, @src\/net_processing.cpp@, from line 3837).
handleVersion :: Version -> M ()
handleVersion v = do
  s0 <- getS
  when (s0.peerVersion /= Nothing) $ do
    ignore $ netProcessing 3839 "redundant version message"
    stop
  let services = v.services
  desirable <- desirableServices services
  when (expectServices s0.connectionType && desirable .&. services /= desirable) $ do
    disconnect Unsuitable $
      netProcessing 3871 "peer does not offer the expected services"
    stop
  when (v.version < minPeerProtoVersion) $ do
    disconnect ProtocolViolation $ netProcessing 3878 "peer using obsolete version"
    stop
  e <- env
  when (s0.connectionType == Inbound && e.ownNonce v.nonce) $ do
    disconnect ProtocolViolation $ netProcessing 3904 "connected to self"
    stop
  when (s0.connectionType == Inbound) pushNodeVersion
  let advertised =
        if s0.connectionType == PrivateBroadcast
          then privateBroadcastVersion
          else protocolVersion
      common = min v.version advertised
      VarString ua = v.userAgent
      makeTxRelay =
        s0.connectionType /= BlockRelayOnly
          && s0.connectionType /= Feeler
          && (v.relay || s0.ourServices .&. nodeBloomBit /= 0)
  modifyS $ \s ->
    s
      { peerVersion = Just v.version,
        commonVersion = common,
        theirServices = services,
        peerUserAgent = ua,
        txRelay = if makeTxRelay then Just (newTxRelay v.relay) else s.txRelay,
        relaysTxs = s.relaysTxs || (makeTxRelay && v.relay)
      }
  when (s0.connectionType == PrivateBroadcast) $ do
    if v.relay
      then send MVerAck $ netProcessing 3957 "private broadcast: verack"
      else
        disconnect Unsuitable $
          netProcessing 3961 "does not support transaction relay (connected in vain)"
    stop
  when (common >= wtxidRelayVersion) $
    send MWtxidRelay $
      netProcessing 3967 "wtxidrelay"
  when (common >= 70016) $
    send MSendAddrV2 $
      netProcessing 3976 "sendaddrv2"
  o <- opts
  s1 <- getS
  when
    ( common >= wtxidRelayVersion
        && o.txReconciliation
        && maybe False (.relayTxs) s1.txRelay
        && s1.connectionType /= AddrFetch
        && not o.blocksOnly
    )
    $ do
      salt <- random nextWord64
      modifyS $ \s -> s {reconciliation = PreRegistered salt}
      send (MSendTxRcncl (SendTxRcncl txReconciliationVersion salt)) $
        netProcessing 3990 "sendtxrcncl"
  dropped <- maybeDisconnectForTxRelayCapacity
  when dropped stop
  send MVerAck $ netProcessing 4003 "verack"
  let canServe = services .&. (nodeNetwork .|. nodeNetworkLimited) /= 0
      inbound = s0.connectionType == Inbound
      preferred =
        (not inbound || hasPermission PermNoBan s0)
          && s0.connectionType /= AddrFetch
          && canServe
  modifyBlocks $ \b -> b {preferredDownload = preferred}
  unless inbound $ do
    getaddr <- setupAddressRelay
    when getaddr $ do
      send MGetAddr $ netProcessing 4027 "getaddr"
      modifyS $ \s ->
        s {getAddrSent = True, addrTokens = s.addrTokens + fromIntegral maxAddrToSend}
  when (common <= 70012) $
    send (MAlert finalAlert) $
      netProcessing 4063 "final alert"
  when (s0.connectionType == Feeler) $
    disconnect Done $
      netProcessing 4069 "feeler connection completed"
  where
    nodeBloomBit = 4 :: Word64

-- | @verack@ (@ProcessMessage@, from line 4080). On a private broadcast
-- connection, the node announces its transaction at once. Otherwise it
-- offers compact blocks in low-bandwidth mode, forgets an Erlay
-- registration that did not complete, and the handshake is done.
handleVerAck :: M ()
handleVerAck = do
  s <- getS
  when s.successfullyConnected $ do
    ignore $ netProcessing 4082 "ignoring redundant verack message"
    stop
  when (s.connectionType == PrivateBroadcast) $ do
    modifyS $ \st -> st {successfullyConnected = True}
    e <- env
    case e.privateBroadcastTx of
      Nothing ->
        disconnect Done $
          netProcessing 3816 "no more transactions for private broadcast (connected in vain)"
      Just tx -> do
        let TxHash h = txHash tx
        modifyS $ \st -> st {privateTx = Just (txHash tx)}
        send (MInv (Inv [InvVector InvTx h])) $
          netProcessing 3825 "P2P handshake completed, sending INV"
    stop
  when (s.commonVersion >= shortIdsBlocksVersion) $
    send (MSendCompact (SendCompact False cmpctBlocksVersion)) $
      netProcessing 4134 "sendcmpct"
  o <- opts
  when (o.txReconciliation && (not s.wtxidRelay || s.reconciliation /= Registered)) $
    modifyS $
      \st -> st {reconciliation = NoReconciliation}
  modifyS $ \st -> st {successfullyConnected = True}

-- | @wtxidrelay@ (from line 4192): allowed only before @verack@, and
-- counted only with a common version of 70016 or more.
handleWtxidRelay :: M ()
handleWtxidRelay = do
  s <- getS
  when s.successfullyConnected $ do
    disconnect ProtocolViolation $ netProcessing 4196 "wtxidrelay received after verack"
    stop
  if s.commonVersion >= wtxidRelayVersion
    then
      if s.wtxidRelay
        then ignore $ netProcessing 4204 "ignoring duplicate wtxidrelay"
        else putS s {wtxidRelay = True}
    else ignore $ netProcessing 4207 "ignoring wtxidrelay due to old common version"

-- | @sendaddrv2@ (from line 4214): allowed only before @verack@, with any
-- version.
handleSendAddrV2 :: M ()
handleSendAddrV2 = do
  s <- getS
  if s.successfullyConnected
    then disconnect ProtocolViolation $ netProcessing 4218 "sendaddrv2 received after verack"
    else putS s {wantsAddrV2 = True}

-- | @feature@ of BIP 434 (from line 4225), which this library does not know
-- and receives as @MOther "feature"@. Allowed only before @verack@ and with
-- a common version of 70017; the payload must be a feature id of 4 to 80
-- bytes and data of at most 512 bytes, with nothing after. No feature is
-- known in 32.1, so a good one is logged and ignored.
handleFeature :: ByteString -> M ()
handleFeature payload = do
  s <- getS
  when s.successfullyConnected $ do
    disconnect ProtocolViolation $ netProcessing 4229 "feature received after verack"
    stop
  when (s.commonVersion < featureVersion) $ do
    disconnect ProtocolViolation $
      netProcessing 4234 "feature received with incompatible version"
    stop
  case runGetS parseFeature payload of
    Right (fid, True)
      | B.length fid >= 4 -> ignore $ netProcessing 4260 "unknown feature advertised"
    _ -> disconnect ProtocolViolation $ netProcessing 4250 "invalid feature payload"
  where
    parseFeature = do
      fid <- limited maxFeatureIdLength
      _ <- limited maxFeatureDataLength
      end <- isEmpty
      return (fid, end)
    limited n = do
      VarInt l <- deserialize
      if l > fromIntegral n
        then fail "too long"
        else getBytes (fromIntegral l)

-- | @sendtxrcncl@ of Erlay (from line 4267).
handleSendTxRcncl :: SendTxRcncl -> M ()
handleSendTxRcncl m = do
  o <- opts
  s <- getS
  unless o.txReconciliation $ do
    ignore $ netProcessing 4269 "sendtxrcncl ignored, txreconciliation not enabled"
    stop
  when s.successfullyConnected $ do
    disconnect ProtocolViolation $ netProcessing 4275 "sendtxrcncl received after verack"
    stop
  rejects <- rejectIncomingTxs
  when rejects $ do
    disconnect ProtocolViolation $
      netProcessing 4282 "sendtxrcncl received to which we indicated no tx relay"
    stop
  unless (maybe False (.relayTxs) s.txRelay) $ do
    disconnect ProtocolViolation $
      netProcessing 4292 "sendtxrcncl received which indicated no tx relay to us"
    stop
  case s.reconciliation of
    NoReconciliation ->
      ignore $ netProcessing 4304 "Ignore unexpected txreconciliation signal"
    Registered ->
      disconnect ProtocolViolation $
        netProcessing 4310 "sendtxrcncl received from already registered peer"
    PreRegistered _
      | min m.version txReconciliationVersion < 1 ->
          disconnect ProtocolViolation $ netProcessing 4314 "txreconciliation protocol violation"
      | otherwise -> putS s {reconciliation = Registered}

-- | @ping@ (from line 5217): a pong with the same nonce when the common
-- version is above 60000, nothing otherwise.
handlePing :: Ping -> M ()
handlePing (Ping n) = do
  s <- getS
  if s.commonVersion > bip0031Version
    then send (MPong (Pong n)) $ netProcessing 5232 "pong"
    else ignore $ netProcessing 5218 "ping of an old version: no pong"

-- | @ProcessPong@ (from line 5890). Problems are logged, never punished.
-- A pong that matches finishes the ping and measures it; on a private
-- broadcast connection it also means the transaction arrived, and the node
-- disconnects. A pong with nonce zero cancels the ping; another wrong
-- nonce leaves it waiting.
handlePong :: Pong -> M ()
handlePong (Pong n) = do
  s <- getS
  t <- now
  if s.pingNonceSent == 0
    then ignore $ netProcessing 5929 "Unsolicited pong without ping"
    else
      if n == s.pingNonceSent
        then do
          let rtt = t - s.pingStart
          putS
            s
              { pingNonceSent = 0,
                lastPingTime = if rtt >= 0 then Just rtt else s.lastPingTime,
                minPingTime =
                  if rtt >= 0 then Just (maybe rtt (min rtt) s.minPingTime) else s.minPingTime
              }
          when (rtt >= 0 && s.connectionType == PrivateBroadcast) $ do
            process "private broadcast: transaction received" $
              netProcessing 5910 "NodeConfirmedReception"
            disconnect Done $
              netProcessing 5913 "Got a PONG (the transaction will probably reach the network)"
        else
          if n == 0
            then do
              putS s {pingNonceSent = 0}
              ignore $ netProcessing 5925 "Nonce zero"
            else ignore $ netProcessing 5921 "Nonce mismatch"

-- | @ShouldRunInactivityChecks@: the connection is older than
-- @-peertimeout@.
shouldRunInactivityChecks :: M Bool
shouldRunInactivityChecks = do
  s <- getS
  o <- opts
  t <- now
  return (s.connectedAt + o.peerTimeout < t)

-- | @CConnman::InactivityCheck@ (@src\/net.cpp@, from line 2045), run by
-- the socket thread for every peer. Once the connection is older than
-- @-peertimeout@: nothing ever received or sent, nothing sent or received
-- for 20 minutes, or a handshake still not done, closes it. The send buffer
-- check (@fPauseSend@) is not modelled: the machine has no buffers.
inactivityCheck :: M ()
inactivityCheck = do
  run <- shouldRunInactivityChecks
  when run $ do
    s <- getS
    t <- now
    case (s.lastRecv, s.lastSend) of
      (Just r, Just w)
        | t > w + timeoutInterval ->
            disconnect Timeout $ netCpp 2075 "socket sending timeout"
        | t > r + timeoutInterval ->
            disconnect Timeout $ netCpp 2083 "socket receive timeout"
        | not s.successfullyConnected ->
            disconnect Timeout $
              if s.transport == TransportV2 && s.peerVersion == Nothing
                then netCpp 2099 "V2 handshake timeout"
                else netCpp 2101 "version handshake timeout"
        | otherwise -> return ()
      _ -> disconnect Timeout $ netCpp 2067 "socket no message in first seconds"

-- | @MaybeSendPing@ (from line 5697): disconnect when a ping has waited 20
-- minutes; otherwise send one when asked to, or when none is waiting and
-- the last was sent more than 2 minutes ago. The first ping goes out at
-- the first pass after the handshake, because @m_ping_start@ starts at the
-- epoch.
maybeSendPing :: M ()
maybeSendPing = do
  s <- getS
  t <- now
  run <- shouldRunInactivityChecks
  when (run && s.pingNonceSent /= 0 && t > s.pingStart + timeoutInterval) $ do
    disconnect Timeout $ netProcessing 5706 "ping timeout"
    stop
  let due = s.pingQueued || (s.pingNonceSent == 0 && t > s.pingStart + pingInterval)
  when due $ do
    nonce <- random nonZero
    if s.commonVersion > bip0031Version
      then do
        modifyS $ \st -> st {pingQueued = False, pingStart = t, pingNonceSent = nonce}
        send (MPing (Ping nonce)) $ netProcessing 5731 "ping"
      else do
        modifyS $ \st -> st {pingQueued = False, pingStart = t, pingNonceSent = 0}
        send (MOther "ping" B.empty) $ netProcessing 5735 "ping without nonce"
  where
    nonZero g =
      let (w, g') = nextWord64 g
       in if w == 0 then nonZero g' else (w, g')

-- | @MaybeDiscourageAndDisconnect@ (from line 5364), run first in every
-- @SendMessages@. A peer with 'PermNoBan' and a manual connection are never
-- punished. A private broadcast peer, and a local one (which includes an
-- inbound Tor peer), are disconnected without discouragement: discouraging
-- the address of the local Tor proxy would discourage every Tor peer. Any
-- other peer is discouraged, which disconnects every connection from its
-- address. True when the peer was disconnected.
maybeDiscourageAndDisconnect :: M Bool
maybeDiscourageAndDisconnect = do
  s <- getS
  case s.shouldDiscourage of
    Nothing -> return False
    Just why -> do
      putS s {shouldDiscourage = Nothing}
      if
        | hasPermission PermNoBan s -> return False
        | s.connectionType == Manual -> return False
        | s.connectionType == PrivateBroadcast -> do
            disconnect Misbehaviour $
              netProcessing 5389 "Disconnecting misbehaving private broadcast peer"
            return True
        | s.isLocal -> do
            disconnect Misbehaviour $
              netProcessing 5398 "disconnecting but not discouraging local peer"
            return True
        | otherwise -> do
            emit Discourage why
            disconnect Misbehaviour $ netProcessing 5405 "Disconnecting and discouraging peer"
            return True
