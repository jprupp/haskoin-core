{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCashNode
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- The protocol machine of Bitcoin Cash Node 29.2.0: how that node treats one
-- peer on the Bitcoin Cash networks, translated from its source.
--
-- = What it is for
--
-- A program that talks to Bitcoin Cash Node, such as haskoin-node, must know
-- what the node does with each message to behave well: which messages it
-- drops before the handshake, which ones cost ban score and how much, when it
-- pings and how long it waits for the answer, what a whitelisted peer may do.
-- None of this is in a specification. This machine is that map, with the
-- upstream file and line behind every t'Effect', so that it can be checked
-- against the code, used as an oracle in tests, and brought forward to the
-- next release.
--
-- = How it is built
--
-- 'step' takes the options, the t'Env' (the chain, the mempool and the rest of
-- the node as seen at that moment), the t'State' of the connection and one
-- 'Input', and returns the next state and the effects in the order the node
-- produces them. It is a pure function; randomness comes from the t'Rng' in the
-- state, seeded by the @seed@ of the t'Setup'.
--
-- The modules follow the upstream code:
--
-- * "Haskoin.Network.Protocol.BitcoinCashNode.Handshake": framing, the
--   handshake, @ping@, the ban score, the inactivity timeouts;
-- * "Haskoin.Network.Protocol.BitcoinCashNode.Blocks": headers, blocks,
--   compact blocks, block announcements and download timers;
-- * "Haskoin.Network.Protocol.BitcoinCashNode.Relay": transactions,
--   double-spend proofs, Bloom filters, addresses, and the @inv@ trickle;
-- * "Haskoin.Network.Protocol.BitcoinCashNode.Options",
--   "Haskoin.Network.Protocol.BitcoinCashNode.State" and
--   "Haskoin.Network.Protocol.BitcoinCashNode.Constants": the options, the
--   state and the constants, each with its upstream name.
--
-- An input goes through the same gates as a message upstream
-- (@PeerLogicValidation::ProcessMessages@ and @ProcessMessage@,
-- @src\/net_processing.cpp:1999-3950@):
--
-- 1. Nothing is processed once the node decided to close the connection.
-- 2. @filterload@ and @filteradd@ when the node offers no Bloom filters.
-- 3. @reject@, accepted in any state and only logged.
-- 4. @version@.
-- 5. Anything else before @version@ costs 10 (\"missing-version\").
-- 6. @extversion@, @verack@ and @sendaddrv2@.
-- 7. Anything else before the peer's @verack@ is dropped.
-- 8. The handler of the command; an unknown command is dropped.
-- 9. After the message, the @reject@s of invalid blocks are sent and a crossed
--    ban score is acted on.
--
-- A 'Tick' runs the inactivity check of the socket thread, then
-- @SendMessages@ once the handshake is complete: ping, the ban score, our
-- address, queued addresses, the first @getheaders@, block announcements,
-- @inv@s, the download timers, the chain-sync check, @getdata@ and
-- @feefilter@, in that order (@src\/net_processing.cpp:4143-4848@).
--
-- = Bitcoin Cash Node and Bitcoin Core
--
-- The code base is Bitcoin Core of about 0.19 with Bitcoin Cash changes. A
-- peer sees these differences from Bitcoin Core 32.1: integer ban scores with
-- a threshold (@-banscore@, 100), BIP 61 @reject@ messages, a bad checksum
-- that discourages the address, the @extversion@ handshake, double-spend
-- proofs (@dsproof-beta@), no @wtxidrelay@, @sendtxrcncl@, BIP 157 filters or
-- encrypted transport, no block-relay-only connections in practice, compact
-- blocks of version 1 with 32-bit positions, and messages of up to twice the
-- block size for blocks.
--
-- = Permissions and connection types
--
-- Only inbound peers have permissions ('effectivePermissions'): a bare
-- @-whitelist@ gives @noban@, @mempool@ and, by default, @relay@. A @noban@
-- peer is never discouraged or disconnected for its score, is served
-- @getheaders@ during initial block download, gets transactions announced at
-- every pass, and may break the upload target. A manual peer is not punished
-- for its score either, and a local address is disconnected without being
-- discouraged. Feelers leave after @version@, address-fetch connections after
-- the first @addr@. Outbound full-relay peers must offer the services the
-- node wants, are checked for a chain with enough work, and get our address
-- and a @getaddr@.
--
-- = The four networks
--
-- One machine per network is these rules with 'defaultOptions' of the
-- network. The rules are the same on all of them; what differs:
--
-- * __bch__ (main): magic e3e1f3e8, genesis time 1231006505, default block size
--   32 MB, so 112 transactions per announcement; minimum chain work of the
--   network.
-- * __bchTest__ (testnet3): magic f4e5f3f4, genesis time 1296688602, 32 MB
--   blocks.
-- * __bchTest4__ (testnet4): magic e2b7daaf, genesis time 1597811185, 2 MB
--   blocks, so 7 transactions per announcement.
-- * __bchRegTest__ (regtest): magic dab5bffa, genesis time 1296688602, 32 MB
--   blocks, minimum chain work 0, so a headers chain never has too little
--   work.
--
-- The magic and the size limit of block messages (twice the block size) are
-- checked by the caller, which reports 'WrongMagic' and 'Oversized'. A
-- @version@ older than the genesis block costs 20. All timeouts and scores
-- are the same on every network; the target spacing is 600 seconds on all.
--
-- = What the machine leaves out
--
-- See the module headers for details. In short: decisions across peers come
-- as 'Notification's (which block to download from whom, eviction, which
-- peers get an address), validation comes from the t'Env', the rolling Bloom
-- filters of known inventory are exact sets, and the parts of the protocol
-- that need bytes the library does not parse (a short @version@, more entries
-- than the library's parser allows) cannot be fed to it as messages: the
-- caller gets 'BadPayload' for them, which the machine treats as a payload
-- that does not parse.
--
-- The report @doc\/protocol\/bitcoin-cash-node.md@ describes the same rules
-- in prose with links to the upstream lines, and changes with this module.
module Haskoin.Network.Protocol.BitcoinCashNode
  ( -- * The machine
    upstream,
    Options (..),
    defaultOptions,
    State,
    start,
    step,

    -- * Inspecting a connection
    handshakeComplete,
    peerVersionOf,
    isClosing,
    banScoreOf,
    permissionsOf,
    servicesOffered,
    negotiatedAddrV2,
    negotiatedExtVersion,
    prefersHeaders,
    highBandwidthFrom,
    highBandwidthTo,
    relaysTransactions,
    blocksInFlight,
    txsInFlight,
    pingOutstanding,
    bestKnownBlock,
    preferredDownloadPeer,

    -- * Permissions and services
    effectivePermissions,
    localServices,
  )
where

import Control.Monad (forM_, unless, void, when)
import Control.Monad.RWS.Strict (get, gets, modify')
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Bytes.Get (getWord64le, runGetS)
import Data.Map.Strict qualified as Map
import Data.Word (Word64)
import Haskoin.Block.Common (BlockHash)
import Haskoin.Network.Common
  ( Addr (..),
    AddrV2 (..),
    GetData (..),
    MessageCommand (..),
    Ping (..),
    Pong (..),
    stringToCommand,
    toNetworkAddressV2,
  )
import Haskoin.Network.Message (Message (..))
import Haskoin.Network.Protocol.BitcoinCashNode.Blocks
import Haskoin.Network.Protocol.BitcoinCashNode.Constants
import Haskoin.Network.Protocol.BitcoinCashNode.Handshake
import Haskoin.Network.Protocol.BitcoinCashNode.Options
import Haskoin.Network.Protocol.BitcoinCashNode.Relay
import Haskoin.Network.Protocol.BitcoinCashNode.State
import Haskoin.Network.Protocol.Types
import Haskoin.Transaction.Common (TxHash)

-- | The release whose source this machine translates.
upstream :: Upstream
upstream =
  Upstream
    { project = "Bitcoin Cash Node",
      release = "29.2.0",
      tag = "v29.2.0",
      commit = "07576013c91ff4a3a74acd85f189c69121cdad1b",
      repository = "https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node"
    }

-- | The state when a connection opens. An outbound connection sends our
-- @version@ with the first input, which upstream sends at once
-- (@InitializeNode@, @src\/net_processing.cpp:787-808@).
start :: Options -> Setup -> State
start = initialState

-- | One step of the machine: the new state and what the node did, in order.
step :: Options -> Env -> State -> Input -> (State, [Effect])
step o e s i = runM o e s (input i)

input :: Input -> M ()
input i = do
  closing <- gets (.closing)
  if closing
    then case i of
      Receive _ -> ignore (netProcessing 3836 "message after the decision to disconnect")
      BadFrame _ -> ignore (netProcessing 3836 "message after the decision to disconnect")
      _ -> return ()
    else do
      initializeNode
      case i of
        Receive m -> do
          received
          dispatch m
          void sendRejectsAndCheckIfShouldDiscourage
        BadFrame (BadPayload cmd) -> do
          received
          badPayload cmd
          void sendRejectsAndCheckIfShouldDiscourage
        BadFrame f -> do
          received
          frameError f
        Tick -> tick
        Notify n -> notify n
  where
    received = do
      t <- nowM
      modify' (\s -> s {lastRecv = t})

-- | Steps 2 to 8 of the gates of a message.
dispatch :: Message -> M ()
dispatch m = do
  acted <- if isBloomLoad m then bloomPrologue else return False
  unless acted $ case m of
    MReject _ -> receiveReject
    MVersion v -> receiveVersion v
    _ -> do
      pv <- gets (.peerVersion)
      if pv == 0 then missingVersion else afterVersion
  where
    isBloomLoad = \case
      MFilterLoad _ -> True
      MFilterAdd _ -> True
      _ -> False
    afterVersion = case m of
      MOther c p | c == extVersionCommand -> receiveExtVersion (Just p)
      MVerAck -> receiveVerAck
      MSendAddrV2 -> receiveSendAddrV2
      _ -> do
        done <- gets (.connected)
        if done then handle m else priorToVerAck

-- | The handlers of the commands after the handshake.
handle :: Message -> M ()
handle = \case
  MAddr (Addr xs) -> receiveAddr (map toNetworkAddressV2 xs)
  MAddrV2 (AddrV2 xs) -> receiveAddr xs
  MSendHeaders -> receiveSendHeaders
  MSendCompact sc -> receiveSendCmpct sc
  MInv i -> receiveInv i
  MGetData g -> receiveGetData g
  MGetBlocks g -> receiveGetBlocks g
  MGetBlockTxn g -> receiveGetBlockTxn g
  MGetHeaders g -> receiveGetHeaders g
  MTx tx -> receiveTx tx
  MCompactBlock cb -> receiveCmpctBlock cb
  MBlockTxn bt -> receiveBlockTxn bt
  MHeaders h -> receiveHeaders h
  MBlock b -> receiveBlock b
  MGetAddr -> receiveGetAddr
  MMempool -> receiveMempool
  MPing (Ping n) -> receivePing (Just n)
  MPong (Pong n) -> receivePong (Just n)
  MOther "ping" p -> receivePing (nonceOf p)
  MOther "pong" p -> receivePong (nonceOf p)
  MFilterLoad f -> receiveFilterLoad f
  MFilterAdd f -> receiveFilterAdd f
  MFilterClear -> receiveFilterClear
  MFeeFilter f -> receiveFeeFilter f
  MNotFound n -> receiveNotFound n
  MOther c p | c == dsProofCommand -> receiveDsProof (Just p)
  _ -> unknownCommand

-- | The nonce at the start of a raw @ping@ or @pong@ payload.
nonceOf :: ByteString -> Maybe Word64
nonceOf p
  | BS.length p >= 8 = either (const Nothing) Just (runGetS getWord64le (BS.take 8 p))
  | otherwise = Nothing

-- | A payload that does not parse, through the same gates as a message: the
-- handler that would read it throws, and the node answers with a @reject@
-- (@src\/net_processing.cpp:3927-3934@). Commands whose handler does not read
-- the payload are handled as if it were empty, and @pong@ and
-- @dsproof-beta@ handle a bad payload themselves.
badPayload :: ByteString -> M ()
badPayload cmd = do
  acted <-
    if cmd `elem` ["filterload", "filteradd"]
      then bloomPrologue
      else return False
  unless acted $ do
    pv <- gets (.peerVersion)
    done <- gets (.connected)
    if
      | cmd == "reject" -> receiveReject
      | cmd == "version" ->
          if pv /= 0 then duplicateVersion else parseError MCVersion
      | pv == 0 -> missingVersion
      | cmd == extVersionCommand -> receiveExtVersion Nothing
      | cmd == "verack" -> receiveVerAck
      | cmd == "sendaddrv2" -> receiveSendAddrV2
      | not done -> priorToVerAck
      | cmd == "sendheaders" -> receiveSendHeaders
      | cmd == "getaddr" -> receiveGetAddr
      | cmd == "mempool" -> receiveMempool
      | cmd == "filterclear" -> receiveFilterClear
      | cmd == "pong" -> receivePong Nothing
      | cmd == "ping" -> receivePing Nothing
      | cmd == dsProofCommand -> receiveDsProof Nothing
      | otherwise -> case stringToCommand cmd of
          MCOther _ -> unknownCommand
          c
            | c `elem` handled -> parseError c
            | otherwise -> unknownCommand
  where
    handled =
      [ MCAddr,
        MCAddrV2,
        MCInv,
        MCGetData,
        MCNotFound,
        MCGetBlocks,
        MCGetHeaders,
        MCTx,
        MCBlock,
        MCHeaders,
        MCFilterLoad,
        MCFilterAdd,
        MCFeeFilter,
        MCSendCmpct,
        MCCmpctBlock,
        MCGetBlockTxn,
        MCBlockTxn
      ]

-- | Time passes: the inactivity check, then @SendMessages@ once the peer's
-- @verack@ has arrived (@src\/net_processing.cpp:4149-4151@).
tick :: M ()
tick = do
  inactivityCheck
  s <- get
  when (s.connected && not s.closing) sendMessages

-- | @SendMessages@ (@src\/net_processing.cpp:4143-4848@).
sendMessages :: M ()
sendMessages = do
  sendPing
  discouraged <- sendRejectsAndCheckIfShouldDiscourage
  unless discouraged $ do
    advertiseLocal
    sendAddresses
    initialGetHeaders
    blockAnnouncements
    sendInventory
    stopped <- downloadTimers
    unless stopped $ do
      considerEviction
      blocks <- blockRequests
      proofs <- dsProofRequests
      txs <- txRequests
      forM_ (chunksOf maxGetDataSize (blocks <> proofs <> txs)) $ \c ->
        send (MGetData (GetData c)) (netProcessing 4743 "GETDATA")
      sendFeeFilter
  where
    chunksOf _ [] = []
    chunksOf n xs = let (a, b) = splitAt n xs in a : chunksOf n b

-- | News from the rest of the node.
notify :: Notification -> M ()
notify = \case
  NewTip hs -> updatedBlockTip hs
  TxAccepted tx -> txAccepted tx
  RelayAddress a -> relayAddress a
  HighBandwidth b -> highBandwidth b
  RequestBlock h -> requestBlock h
  RequestTx h -> requestTx h
  OperatorDisconnect -> disconnect Resources (netCpp 2728 "DisconnectNode")
  PingRequested -> modify' (\s -> s {pingQueued = True})
  MarkStalling -> stalling
  Penalty n r -> misbehaving n (netProcessing 905 r)
  NewDoubleSpendProof h tx -> newDoubleSpendProof h tx
  NewPoWValidBlock hdr -> newPoWValidBlock hdr
  Evict -> disconnect Resources (netCpp 1018 "AttemptToEvictConnection")

-- | The peer's @verack@ has arrived (@fSuccessfullyConnected@).
handshakeComplete :: State -> Bool
handshakeComplete s = s.connected

-- | The protocol version of the peer, once its @version@ has arrived.
peerVersionOf :: State -> Maybe Int
peerVersionOf s = if s.peerVersion == 0 then Nothing else Just s.peerVersion

-- | The node decided to close the connection (@fDisconnect@).
isClosing :: State -> Bool
isClosing s = s.closing

-- | The ban score of the peer (@nMisbehavior@).
banScoreOf :: State -> Int
banScoreOf s = s.misbehavior

-- | The permissions of the peer, after the node expanded them.
permissionsOf :: State -> Permissions
permissionsOf s = s.perms

-- | The services the node offers this peer.
servicesOffered :: State -> Word64
servicesOffered s = s.ourServices

-- | The peer sent @sendaddrv2@ in time.
negotiatedAddrV2 :: State -> Bool
negotiatedAddrV2 s = s.wantsAddrV2

-- | The peer's @extversion@ was accepted.
negotiatedExtVersion :: State -> Bool
negotiatedExtVersion s = s.extVersionEnabled

-- | The peer sent @sendheaders@.
prefersHeaders :: State -> Bool
prefersHeaders s = s.blocks.preferHeaders

-- | The peer asked for high-bandwidth compact blocks.
highBandwidthFrom :: State -> Bool
highBandwidthFrom s = s.blocks.preferHeaderAndIds

-- | The node asked the peer for high-bandwidth compact blocks.
highBandwidthTo :: State -> Bool
highBandwidthTo s = s.blocks.highBandwidthTo

-- | The node announces transactions to the peer (@fRelayTxes@).
relaysTransactions :: State -> Bool
relaysTransactions s = s.relay.relayTxes

-- | Blocks requested from the peer, oldest first.
blocksInFlight :: State -> [BlockHash]
blocksInFlight s = map (.inFlightHash) s.blocks.inFlight

-- | Transactions requested from the peer and not answered yet.
txsInFlight :: State -> [TxHash]
txsInFlight s =
  [h | (h, TxAnnouncement _ (TxRequested _)) <- Map.toList s.relay.announcements]

-- | The nonce of the ping that waits for its @pong@.
pingOutstanding :: State -> Maybe Word64
pingOutstanding s = if s.pingNonceSent == 0 then Nothing else Just s.pingNonceSent

-- | The best block the peer is known to have.
bestKnownBlock :: State -> Maybe BlockInfo
bestKnownBlock s = s.blocks.bestKnown

-- | The peer is a preferred source of downloads (@fPreferredDownload@).
preferredDownloadPeer :: State -> Bool
preferredDownloadPeer s = s.preferredDownload
