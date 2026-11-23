{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCore
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- The protocol machine of Bitcoin Core 32.1 (commit @f0de87f0@), the
-- reference node of the Bitcoin networks: how it treats one peer, message by
-- message and timer by timer, as a pure function.
--
-- = Purpose
--
-- A program that talks to Bitcoin Core, such as haskoin-node, must know
-- what the node does with each message: which ones it drops before the
-- handshake, which ones close the connection, which ones get the address
-- discouraged, when it pings and how long it waits. None of that is in the
-- BIPs. This module is a translation of the code that decides it,
-- @ProcessMessage@, @SendMessages@ and their helpers in
-- @src\/net_processing.cpp@, and the transport and inactivity rules of
-- @src\/net.cpp@, with a t'Cite' of the deciding line behind every t'Effect'.
-- It serves as an oracle for tests, and as a map for a reader of the
-- upstream code. The report @doc\/protocol\/bitcoin-core.md@ of the
-- repository describes the same rules in prose, with links to the same
-- lines, and changes with this module.
--
-- = Use
--
-- > let o = defaultOptions btc
-- >     s0 = start o setup
-- >     (s1, effects) = step o env s0 (Receive (MVersion ver))
--
-- The machine is one connection. 'Receive' is one message going through
-- @ProcessMessage@, followed by the punishment check that opens
-- @SendMessages@, since upstream runs @SendMessages@ for the same peer
-- right after each message. 'Tick' is the rest of @SendMessages@ and the
-- inactivity checks of the socket thread, which upstream runs about every
-- 100 milliseconds; a caller should tick as often, and before each message
-- if it wants upstream's order exactly. 'Notify' is news from the rest of
-- the node: a new tip, a transaction to announce, a block to request.
--
-- An outbound connection sends the node's @version@ on its first pass. A
-- message from an outbound peer that arrives before that pass makes the
-- machine send the @version@ first, as upstream processes no message
-- before it.
--
-- = The four networks
--
-- One machine serves the four Bitcoin chains; 'defaultOptions' fills in
-- what differs:
--
-- * __main__ (@btc@): minimum chain work @0x0145ec036acc5ba740052af1a0@,
--   magic @f9beb4d9@. While the tip has less work, @getheaders@ gets an
--   empty answer, @sendheaders@ is not sent, and an outbound peer whose
--   chain has less work is dropped during initial block download.
-- * __testnet3__ (@btcTest@): minimum chain work
--   @0x17f49f702147f10c0eb6@, magic @0b110907@. Upstream skips the
--   difficulty transition check of the low-work headers sync, which the
--   t'Env' answers.
-- * __testnet4__ (@btcTest4@): minimum chain work
--   @0x0e346a558455ade8eca9@, magic @1c163f28@; BIP 94 is enforced by
--   header validation, in the t'Env'.
-- * __regtest__ (@btcRegTest@): minimum chain work 0, so @getheaders@ is
--   always answered, @sendheaders@ goes out as soon as the peer is known to
--   have any block, and the anti-DoS threshold of headers is the work of
--   the tip less 144 blocks. Upstream allows a mock clock on regtest; the
--   machine always takes the time from the t'Env'.
--
-- Every timer, limit and protocol version is the same on the four chains,
-- and so is the block interval of 600 seconds that several timers scale
-- by.
--
-- = Connection types and permissions
--
-- 'start' expands the configured 'Permissions' as upstream does: a bare
-- @-whitelist@ ('PermImplicit') gives 'PermNoBan' (which includes
-- 'PermDownload'), 'PermMempool', and 'PermRelay' unless @-blocksonly@ is
-- set or @-whitelistrelay@ is off, and 'PermForceRelay' (which includes
-- 'PermRelay') with @-whitelistforcerelay@. A peer with 'PermNoBan' and a
-- 'Manual' connection are never punished for misbehaviour; a local peer,
-- and an inbound Tor peer, whose address is that of the local proxy, are
-- disconnected without discouragement. The connection types differ in
-- what the node expects of the peer's services, whether it relays
-- transactions and addresses, and the timers that apply; the report has
-- the table.
--
-- = What is simplified
--
-- Validation, the mempool and every decision that spans peers come from the
-- t'Env' or as a 'Notification'; each submodule says what it leaves out.
-- The machine has no send buffer, so the back-pressure of @fPauseSend@ is
-- not modelled, and a @getdata@ is served at once. Upstream keeps
-- rolling Bloom filters of known transactions and addresses, which forget;
-- the machine keeps sets, which do not.
module Haskoin.Network.Protocol.BitcoinCore
  ( -- * Machine
    upstream,
    Options (..),
    defaultOptions,
    State,
    start,
    step,

    -- * Inspection
    handshakeComplete,
    versionReceived,
    isDisconnected,
    discouragementPending,
    blocksInFlight,
    pingOutstanding,
    txRelayEnabled,
    addrRelayEnabled,
    permissionsOf,
    commonVersionOf,
    peerServicesOf,
    ourServicesOf,
    wtxidRelayOf,
    wantsAddrV2Of,
    prefersHeadersOf,
    compactBlocksOf,
    feeFilterOf,
    syncStartedOf,
    expandPermissions,
    localServices,
  )
where

import Control.Monad (unless, when)
import Data.ByteString qualified as B
import Data.Bytes.Get (getWord64le, getWord8, runGetS)
import Data.Int (Int32)
import Data.Word (Word64)
import Haskoin.Network.Common (Addr (..), AddrV2 (..), Inv (..), toNetworkAddressV2)
import Haskoin.Network.CompactBlock (SendCompact (..))
import Haskoin.Network.Message (Message (..))
import Haskoin.Network.Protocol.BitcoinCore.Blocks
import Haskoin.Network.Protocol.BitcoinCore.Constants
import Haskoin.Network.Protocol.BitcoinCore.Handshake
import Haskoin.Network.Protocol.BitcoinCore.Machine
import Haskoin.Network.Protocol.BitcoinCore.Relay
import Haskoin.Network.Protocol.BitcoinCore.State
import Haskoin.Network.Protocol.Types

-- | One step of the machine: the new state and what the node did, in
-- order. Nothing happens to a connection that the node already decided to
-- close.
step :: Options -> Env -> State -> Input -> (State, [Effect])
step o e s input
  | s.disconnected = (s, [])
  | otherwise = runM o e s $ case input of
      Receive m -> do
        received
        outboundVersionFirst
        scoped (processMessage m)
        _ <- maybeDiscourageAndDisconnect
        return ()
      BadFrame err -> do
        received
        outboundVersionFirst
        badFrame err
      Tick -> do
        scoped inactivityCheck
        alive <- not . (.disconnected) <$> getS
        when alive sendMessages
      Notify n -> notify n
  where
    received = do
      t <- now
      modifyS $ \st -> st {lastRecv = Just t}
    outboundVersionFirst = do
      st <- getS
      when (st.connectionType /= Inbound && not st.versionSent) $ do
        pushNodeVersion
        modifyS $ \x -> x {versionSent = True}

-- | @ProcessMessage@ (@src\/net_processing.cpp@, line 3828): the gates in
-- upstream order, then the handler of the command.
processMessage :: Message -> M ()
processMessage m = do
  case m of
    MVersion v -> handleVersion v >> stop
    _ -> return ()
  s <- getS
  when (s.peerVersion == Nothing) $ do
    ignore $ netProcessing 4076 "non-version message before version handshake"
    stop
  case m of
    MVerAck -> handleVerAck >> stop
    MSendHeaders -> handleSendHeaders >> stop
    MSendCompact sc -> handleSendCmpct sc >> stop
    MOther "sendcmpct" p -> rawSendCmpct p >> stop
    MWtxidRelay -> handleWtxidRelay >> stop
    MSendAddrV2 -> handleSendAddrV2 >> stop
    MOther "feature" p -> handleFeature p >> stop
    MSendTxRcncl r -> handleSendTxRcncl r >> stop
    _ -> return ()
  unless s.successfullyConnected $ do
    ignore $ netProcessing 4321 "Unsupported message prior to verack"
    stop
  when (s.connectionType == PrivateBroadcast) $
    case m of
      MPong _ -> return ()
      MGetData _ -> return ()
      _ -> do
        ignore $ netProcessing 4327 "Ignoring incoming message on private broadcast connection"
        stop
  case m of
    MAddr (Addr as) -> handleAddrs False (map toNetworkAddressV2 as)
    MAddrV2 (AddrV2 as) -> handleAddrs True as
    MInv inv -> handleInv inv
    MGetData gd -> handleGetData gd
    MGetBlocks gb -> handleGetBlocks gb
    MGetBlockTxn r -> handleGetBlockTxn r
    MGetHeaders gh -> handleGetHeaders gh
    MTx tx -> handleTx tx
    MCompactBlock cb -> handleCmpctBlock cb
    MBlockTxn bt -> handleBlockTxn bt
    MHeaders hs -> handleHeaders hs
    MBlock b -> handleBlock b
    MGetAddr -> handleGetAddr
    MMempool -> handleMempool
    MPing p -> handlePing p
    MPong p -> handlePong p
    MFilterLoad f -> handleFilterLoad f
    MFilterAdd f -> handleFilterAdd f
    MFilterClear -> handleFilterClear
    MFeeFilter f -> handleFeeFilter f
    MGetCFilters r -> handleGetCFilters r
    MGetCFHeaders r -> handleGetCFHeaders r
    MGetCFCheckpt r -> handleGetCFCheckpt r
    MNotFound nf -> handleNotFound nf
    _ -> ignore $ netProcessing 5360 "Unknown message type"

-- | A @sendcmpct@ that the caller passes as raw bytes. t'SendCompact' reads
-- the announce byte as a flag, so the one rule it cannot carry, an announce
-- byte above 1, which is misbehaviour, is checked here (line 4172).
rawSendCmpct :: B.ByteString -> M ()
rawSendCmpct p =
  case runGetS ((,) <$> getWord8 <*> getWord64le) p of
    Left _ -> ignore $ netProcessing 5493 "Exception caught"
    Right (hb, v)
      | hb > 1 -> do
          let c = netProcessing 4173 "invalid sendcmpct announce field"
          misbehaving c
          ignore c
      | otherwise -> handleSendCmpct (SendCompact (hb == 1) v)

-- | @SendMessages@ (line 6059), after the inactivity checks.
sendMessages :: M ()
sendMessages = do
  gone <- maybeDiscourageAndDisconnect
  when gone stop
  s0 <- getS
  when (s0.connectionType /= Inbound && not s0.versionSent) $ do
    pushNodeVersion
    modifyS $ \x -> x {versionSent = True}
  s <- getS
  unless s.successfullyConnected stop
  t <- now
  when (s.connectionType == PrivateBroadcast) $ do
    when (s.connectedAt + privateBroadcastLifetime < t) $
      disconnect Timeout $
        netProcessing 6093 "did not complete the transaction send within the lifetime"
    stop
  when (s.connectionType == AddrFetch && t - s.connectedAt > 10 * avgAddressBroadcastInterval) $ do
    disconnect Done $ netProcessing 6100 "addrfetch connection timeout"
    stop
  scoped maybeSendPing
  whenM ((.disconnected) <$> getS) stop
  maybeSendAddr
  maybeSendSendHeaders
  initialGetHeaders
  blockEntries <- sendBlockAnnouncements
  txEntries <- sendTxTrickle
  sendInvs (blockEntries ++ txEntries)
  scoped blockTimeouts
  whenM ((.disconnected) <$> getS) stop
  considerEviction
  whenM ((.disconnected) <$> getS) stop
  maybeSendFeeFilter
  where
    sendInvs [] = return ()
    sendInvs xs = do
      let (now', rest) = splitAt maxInvSz xs
      send (MInv (Inv now')) $ netProcessing 6438 "inv"
      sendInvs rest

-- | News from the rest of the node.
notify :: Notification -> M ()
notify n = case n of
  NewTip hs -> newTip hs
  TxAccepted tx -> txAccepted tx
  RelayAddress a -> relayAddress a
  HighBandwidth on -> highBandwidth on
  RequestBlock h -> requestBlock h
  RequestTx h -> requestTx h
  OperatorDisconnect -> disconnect Resources $ netCpp 3967 "disconnect by id"
  MarkStalling -> markStalling
  PingRequested -> modifyS $ \s -> s {pingQueued = True}
  NewPoWValidBlock h -> newPoWValidBlock h
  Evict -> disconnect Resources $ netCpp 1749 "selected for eviction"

-- | The permissions of the peer, expanded.
permissionsOf :: State -> Permissions
permissionsOf s = s.permissions

-- | The common protocol version (@m_greatest_common_version@).
commonVersionOf :: State -> Int32
commonVersionOf s = s.commonVersion

-- | The services the peer offered in its @version@.
peerServicesOf :: State -> Word64
peerServicesOf s = s.theirServices

-- | The services the node offers to the peer.
ourServicesOf :: State -> Word64
ourServicesOf s = s.ourServices

-- | The peer relays transactions by wtxid (BIP 339).
wtxidRelayOf :: State -> Bool
wtxidRelayOf s = s.wtxidRelay

-- | The peer asked for @addrv2@ (BIP 155).
wantsAddrV2Of :: State -> Bool
wantsAddrV2Of s = s.wantsAddrV2

-- | The peer sent @sendheaders@.
prefersHeadersOf :: State -> Bool
prefersHeadersOf s = s.blocks.prefersHeaders

-- | Compact blocks: whether the peer offered them, whether it wants them
-- pushed, and whether the node chose it for high bandwidth.
compactBlocksOf :: State -> (Bool, Bool, Bool)
compactBlocksOf s = (s.blocks.providesCmpct, s.blocks.requestedHbCmpct, s.blocks.highBandwidthTo)

-- | The fee filter that the peer sent, if transaction relay exists.
feeFilterOf :: State -> Maybe Word64
feeFilterOf s = (.feeFilterReceived) <$> s.txRelay

-- | The initial headers sync started with the peer (@fSyncStarted@).
syncStartedOf :: State -> Bool
syncStartedOf s = s.blocks.syncStarted
