{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCore.State
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- The options of a Bitcoin Core 32.1 node and the state that it keeps about
-- one peer, for the machine of "Haskoin.Network.Protocol.BitcoinCore".
--
-- Upstream spreads the state of a peer over three structures: @CNode@ in
-- @src\/net.h@ (the connection: transport, permissions, handshake flags),
-- @Peer@ in @src\/net_processing.cpp@ (what the protocol negotiated: ping,
-- address relay, transaction relay) and @CNodeState@ in the same file (what
-- the block download knows, under @cs_main@). t'State' keeps them in one
-- record, with the block part in t'BlockState' and the transaction part in
-- t'TxRelay'. Each field names its upstream counterpart, so that a reader of
-- either code can find the other.
--
-- What is left out of the state is what only the rest of the node needs:
-- statistics for eviction, byte counters, the address manager. Global
-- tables that several peers share, such as the blocks in flight from all
-- peers, are asked of the t'Env' instead.
module Haskoin.Network.Protocol.BitcoinCore.State
  ( -- * Options
    Options (..),
    defaultOptions,
    localServices,

    -- * State
    State (..),
    TxRelay (..),
    BlockState (..),
    InFlight (..),
    ChainSync (..),
    Reconciliation (..),
    start,
    expandPermissions,
    hasPermission,
    newTxRelay,

    -- * Inspection
    handshakeComplete,
    versionReceived,
    isDisconnected,
    discouragementPending,
    blocksInFlight,
    pingOutstanding,
    txRelayEnabled,
    addrRelayEnabled,
  )
where

import Control.DeepSeq (NFData)
import Data.Bits ((.|.))
import Data.ByteString (ByteString)
import Data.Int (Int32)
import Data.Maybe (isJust)
import Data.Set (Set)
import Data.Set qualified as Set
import Data.Word (Word16, Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Block.Common (BlockHash)
import Haskoin.Network.Bloom (BloomFilter)
import Haskoin.Network.Common
  ( AddressNetwork (..),
    NetworkAddressV2,
    nodeBloom,
    nodeCompactFilters,
    nodeNetwork,
    nodeNetworkLimited,
    nodeP2PV2,
    nodeWitness,
  )
import Haskoin.Network.CompactBlock (CompactBlock)
import Haskoin.Network.Data (Network (..))
import Haskoin.Network.Protocol.BitcoinCore.Constants
import Haskoin.Network.Protocol.Types
import Haskoin.Transaction.Common (TxHash)

-- | The options of the node that change what a peer sees. Each field is a
-- command-line option of @bitcoind@, or a constant of the chain that the
-- node takes from its chain parameters. 'defaultOptions' gives the values
-- of a node started with no options.
data Options = Options
  { -- | the chain, which gives the magic bytes and the minimum chain work
    network :: !Network,
    -- | @-blocksonly@ (default off): the node tells its peers not to send
    -- transactions, and disconnects those that do unless they have
    -- 'PermRelay' (@ignore_incoming_txs@)
    blocksOnly :: !Bool,
    -- | @-peerbloomfilters@ (default off): the node offers @NODE_BLOOM@ and
    -- serves BIP 37 filters and the @mempool@ message
    peerBloomFilters :: !Bool,
    -- | @-peerblockfilters@ (default off): the node offers
    -- @NODE_COMPACT_FILTERS@ and serves BIP 157 filters
    peerBlockFilters :: !Bool,
    -- | @-txreconciliation@ (default off, debug only): the node sends and
    -- accepts @sendtxrcncl@ (Erlay, BIP 330)
    txReconciliation :: !Bool,
    -- | @-maxuploadtarget@ in bytes a day, 0 for none (the default). Whether
    -- the target is reached is @uploadTargetReached@ and
    -- @historicalUploadTargetReached@ of t'Env'; this field only says whether
    -- there is one.
    maxUploadTarget :: !Word64,
    -- | @-listen@ (default on): the node advertises its own address
    listen :: !Bool,
    -- | @-prune@ (default off): a pruned node offers @NODE_NETWORK_LIMITED@
    -- without @NODE_NETWORK@, and refuses deep blocks
    prune :: !Bool,
    -- | @-v2transport@ (default on): the node offers @NODE_P2P_V2@
    v2Transport :: !Bool,
    -- | @-whitelistrelay@: 'Nothing' for the upstream default, which is on
    -- unless @-blocksonly@ is set, and on whenever @-whitelistforcerelay@ is
    -- (@src\/init.cpp@ soft-sets it)
    whitelistRelay :: !(Maybe Bool),
    -- | @-whitelistforcerelay@ (default off)
    whitelistForceRelay :: !Bool,
    -- | @-peertimeout@ (default 60 seconds): how long a new connection has
    -- to finish its handshake before the inactivity checks apply
    peerTimeout :: !Micros,
    -- | @-minimumchainwork@ (debug only), by default
    -- @minimumChainWork@ of t'Network' of the chain
    minimumChainWork :: !Integer,
    -- | @-minrelaytxfee@ (default 100 satoshi per 1000 virtual bytes), the
    -- floor of the fee filter that the node sends
    minRelayTxFee :: !Word64,
    -- | the user agent, @\/Satoshi:32.1.0\/@ unless @-uacomment@ adds to it
    userAgent :: !ByteString
  }
  deriving (Eq, Show, Generic, NFData)

-- | The options of a node started on a chain with no options. The chain
-- gives the magic bytes and the minimum chain work; every other default is
-- the same on the four Bitcoin chains.
defaultOptions :: Network -> Options
defaultOptions net =
  Options
    { network = net,
      blocksOnly = False,
      peerBloomFilters = False,
      peerBlockFilters = False,
      txReconciliation = False,
      maxUploadTarget = 0,
      listen = True,
      prune = False,
      v2Transport = True,
      whitelistRelay = Nothing,
      whitelistForceRelay = False,
      peerTimeout = defaultPeerConnectTimeout,
      minimumChainWork = net.minimumChainWork,
      minRelayTxFee = defaultMinRelayTxFee,
      userAgent = defaultUserAgent
    }

-- | The services that the node offers to every peer (@g_local_services@):
-- @NODE_NETWORK_LIMITED | NODE_WITNESS@ always, @NODE_NETWORK@ unless
-- pruned, @NODE_P2P_V2@ with @-v2transport@, @NODE_COMPACT_FILTERS@ with
-- @-peerblockfilters@ and @NODE_BLOOM@ with @-peerbloomfilters@
-- (@src\/init.cpp@).
localServices :: Options -> Word64
localServices o =
  foldr
    (.|.)
    (nodeNetworkLimited .|. nodeWitness)
    [ if o.prune then 0 else nodeNetwork,
      if o.v2Transport then nodeP2PV2 else 0,
      if o.peerBlockFilters then nodeCompactFilters else 0,
      if o.peerBloomFilters then nodeBloom else 0
    ]

-- | The state of Erlay for the peer (@TxReconciliationTracker@).
data Reconciliation
  = -- | nothing was sent or registered
    NoReconciliation
  | -- | the node sent @sendtxrcncl@ with this salt (@PreRegisterPeer@)
    PreRegistered !Word64
  | -- | the peer answered with its own @sendtxrcncl@ (@RegisterPeer@)
    Registered
  deriving (Eq, Show, Generic, NFData)

-- | Transaction relay with the peer (@Peer::TxRelay@). It exists only if the
-- connection is not block-relay-only or a feeler, and the peer asked for
-- transactions in its @version@ or the node offers it Bloom filters.
data TxRelay = TxRelay
  { -- | @m_relay_txs@: the peer wants transaction announcements
    relayTxs :: !Bool,
    -- | @m_bloom_filter@: the BIP 37 filter of the peer
    bloomFilter :: !(Maybe BloomFilter),
    -- | @m_tx_inventory_known_filter@: transactions announced by the peer or
    -- to it. Upstream it is a rolling Bloom filter of 50,000 entries, which
    -- forgets; here it is a set, which does not.
    knownTxs :: !(Set TxHash),
    -- | @m_tx_inventory_to_send@: transactions to announce at the next
    -- trickle, by wtxid
    toSend :: ![TxHash],
    -- | @m_send_mempool@: the peer sent @mempool@
    sendMempool :: !Bool,
    -- | @m_next_inv_send_time@: the next trickle; 0 until the first
    -- @SendMessages@ after the handshake
    nextInvSend :: !Micros,
    -- | @m_fee_filter_received@: the fee filter of the peer
    feeFilterReceived :: !Word64
  }
  deriving (Eq, Show, Generic, NFData)

-- | A new t'TxRelay'.
newTxRelay :: Bool -> TxRelay
newTxRelay r =
  TxRelay
    { relayTxs = r,
      bloomFilter = Nothing,
      knownTxs = Set.empty,
      toSend = [],
      sendMempool = False,
      nextInvSend = 0,
      feeFilterReceived = 0
    }

-- | A block requested from the peer (@QueuedBlock@).
data InFlight = InFlight
  { block :: !BlockHash,
    -- | @partialBlock@: the compact block being completed, if the request
    -- is a @getblocktxn@
    partial :: !(Maybe CompactBlock),
    -- | @partialBlock->header.IsNull()@: @FillBlock@ already used the
    -- compact block, so a second @blocktxn@ for it is misbehaviour
    filled :: !Bool
  }
  deriving (Eq, Show, Generic, NFData)

-- | The chain sync check of an outbound peer (@CNodeState::ChainSyncTimeoutState@).
data ChainSync = ChainSync
  { -- | @m_timeout@, 0 when unset
    timeout :: !Micros,
    -- | @m_work_header@: the tip when the timer started
    workHeader :: !(Maybe BlockHash),
    -- | @m_sent_getheaders@
    sentGetHeaders :: !Bool,
    -- | @m_protect@: one of the four outbound peers never evicted this way
    protect :: !Bool
  }
  deriving (Eq, Show, Generic, NFData)

-- | What the block download knows of the peer: the fields of @CNodeState@
-- and the block fields of @Peer@.
data BlockState = BlockState
  { -- | @fPreferredDownload@
    preferredDownload :: !Bool,
    -- | @pindexBestKnownBlock@: the best block that the peer has
    bestKnownBlock :: !(Maybe BlockHash),
    -- | @hashLastUnknownBlock@: an announced block that the node did not know
    lastUnknownBlock :: !(Maybe BlockHash),
    -- | @pindexBestHeaderSent@
    bestHeaderSent :: !(Maybe BlockHash),
    -- | @fSyncStarted@: the initial @getheaders@ went to this peer
    syncStarted :: !Bool,
    -- | @m_headers_sync_timeout@; 'Nothing' for the maximum, never
    headersSyncTimeout :: !(Maybe Micros),
    -- | @m_last_getheaders_timestamp@; 'Nothing' for the epoch
    lastGetHeaders :: !(Maybe Micros),
    -- | @m_headers_sync@: a low-work headers sync is running from this
    -- block, the parent of its first header
    lowWorkSync :: !(Maybe BlockHash),
    -- | @m_inv_triggered_getheaders_before_sync@
    invTriggeredGetHeaders :: !Bool,
    -- | @m_stalling_since@
    stallingSince :: !(Maybe Micros),
    -- | @vBlocksInFlight@, oldest first
    inFlight :: ![InFlight],
    -- | @m_downloading_since@
    downloadingSince :: !Micros,
    -- | @m_prefers_headers@: the peer sent @sendheaders@
    prefersHeaders :: !Bool,
    -- | @m_sent_sendheaders@
    sentSendHeaders :: !Bool,
    -- | @m_provides_cmpctblocks@: the peer sent @sendcmpct@ of version 2
    providesCmpct :: !Bool,
    -- | @m_requested_hb_cmpctblocks@: the peer wants compact blocks pushed
    requestedHbCmpct :: !Bool,
    -- | @m_bip152_highbandwidth_to@: the node chose the peer as a
    -- high-bandwidth compact block peer
    highBandwidthTo :: !Bool,
    -- | @m_chain_sync@
    chainSync :: !ChainSync,
    -- | @m_last_block_announcement@
    lastBlockAnnouncement :: !(Maybe Micros),
    -- | @m_blocks_for_headers_relay@
    forHeadersRelay :: ![BlockHash],
    -- | @m_blocks_for_inv_relay@
    forInvRelay :: ![BlockHash],
    -- | @m_continuation_block@ of a @getblocks@ answer
    continuationBlock :: !(Maybe BlockHash)
  }
  deriving (Eq, Show, Generic, NFData)

-- | What the node keeps about one peer.
data State = State
  { -- | @m_conn_type@
    connectionType :: !ConnectionType,
    -- | @m_permission_flags@, expanded by 'expandPermissions'
    permissions :: !Permissions,
    -- | address network of the peer
    peerNetwork :: !AddressNetwork,
    -- | the transport of the connection (@m_transport@)
    transport :: !TransportVersion,
    -- | @addr.IsLocal()@: a local address, or an inbound Tor peer, whose
    -- address is that of the local proxy
    isLocal :: !Bool,
    -- | @m_connected@
    connectedAt :: !Micros,
    -- | the randomness of the node for this peer
    rng :: !Rng,
    -- | @Peer::m_our_services@: what the node offers to this peer
    ourServices :: !Word64,
    -- | @nLocalHostNonce@, the nonce of the node's @version@
    localNonce :: !Word64,
    -- | @fDisconnect@
    disconnected :: !Bool,
    -- | @m_should_discourage@, with the place of the @Misbehaving@ call
    shouldDiscourage :: !(Maybe Cite),
    -- | @m_outbound_version_message_sent@, or for an inbound peer that the
    -- node answered its @version@
    versionSent :: !Bool,
    -- | @CNode::nVersion@: the peer's version, 'Nothing' before its @version@
    peerVersion :: !(Maybe Int32),
    -- | @m_greatest_common_version@
    commonVersion :: !Int32,
    -- | @Peer::m_their_services@
    theirServices :: !Word64,
    -- | @cleanSubVer@
    peerUserAgent :: !ByteString,
    -- | @fSuccessfullyConnected@: the peer's @verack@ came
    successfullyConnected :: !Bool,
    -- | @m_last_send@; 'Nothing' before the first byte
    lastSend :: !(Maybe Micros),
    -- | @m_last_recv@; 'Nothing' before the first byte
    lastRecv :: !(Maybe Micros),
    -- | @m_wtxid_relay@
    wtxidRelay :: !Bool,
    -- | @m_wants_addrv2@
    wantsAddrV2 :: !Bool,
    -- | Erlay registration
    reconciliation :: !Reconciliation,
    -- | @m_ping_nonce_sent@, 0 for none
    pingNonceSent :: !Word64,
    -- | @m_ping_start@
    pingStart :: !Micros,
    -- | @m_ping_queued@
    pingQueued :: !Bool,
    -- | @m_last_ping_time@
    lastPingTime :: !(Maybe Micros),
    -- | @m_min_ping_time@
    minPingTime :: !(Maybe Micros),
    -- | @Peer::m_tx_relay@
    txRelay :: !(Maybe TxRelay),
    -- | @CNode::m_relays_txs@
    relaysTxs :: !Bool,
    -- | @m_addr_relay_enabled@
    addrRelay :: !Bool,
    -- | @m_addr_known@. Upstream a rolling Bloom filter of 5,000 entries;
    -- here a set of addresses as network, bytes and port.
    addrKnown :: !(Set (Word8, ByteString, Word16)),
    -- | @m_addrs_to_send@
    addrsToSend :: ![NetworkAddressV2],
    -- | @m_getaddr_sent@
    getAddrSent :: !Bool,
    -- | @m_getaddr_recvd@
    getAddrRecvd :: !Bool,
    -- | @m_addr_token_bucket@
    addrTokens :: !Double,
    -- | @m_addr_token_timestamp@
    addrTokensAt :: !Micros,
    -- | @m_next_addr_send@
    nextAddrSend :: !Micros,
    -- | @m_next_local_addr_send@
    nextLocalAddrSend :: !Micros,
    -- | @m_fee_filter_sent@
    feeFilterSent :: !Word64,
    -- | @m_next_send_feefilter@
    nextFeeFilter :: !Micros,
    -- | the transaction announced on a private broadcast connection
    privateTx :: !(Maybe TxHash),
    -- | the block download
    blocks :: !BlockState
  }
  deriving (Eq, Show, Generic, NFData)

-- | Expand the permissions of a peer as Bitcoin Core does. A bare
-- @-whitelist@ or @-whitebind@ ('PermImplicit') gives 'PermNoBan',
-- 'PermMempool', 'PermRelay' unless @-whitelistrelay@ is off, and
-- 'PermForceRelay' with @-whitelistforcerelay@; the flag 'PermImplicit'
-- itself is cleared (@AddWhitelistPermissionFlags@, @src\/net.cpp@). Then
-- the flags that include others are expanded as their bit masks do in
-- @src\/net_permissions.h@: 'PermForceRelay' includes 'PermRelay', and
-- 'PermNoBan' includes 'PermDownload'.
expandPermissions :: Options -> Permissions -> Permissions
expandPermissions o ps0 = implied (implicit ps0)
  where
    relayDefault = case o.whitelistRelay of
      Just b -> b
      Nothing -> not o.blocksOnly || o.whitelistForceRelay
    implicit ps
      | PermImplicit `Set.member` ps =
          Set.unions
            [ Set.delete PermImplicit ps,
              Set.fromList [PermNoBan, PermMempool],
              if relayDefault || o.whitelistForceRelay then Set.singleton PermRelay else Set.empty,
              if o.whitelistForceRelay then Set.singleton PermForceRelay else Set.empty
            ]
      | otherwise = ps
    implied ps =
      Set.unions
        [ ps,
          if PermForceRelay `Set.member` ps then Set.singleton PermRelay else Set.empty,
          if PermNoBan `Set.member` ps then Set.singleton PermDownload else Set.empty
        ]

-- | Whether the peer has a permission (@HasPermission@).
hasPermission :: Permission -> State -> Bool
hasPermission p s = p `Set.member` s.permissions

-- | The state when a connection opens: what @CNode@'s constructor and
-- @InitializeNode@ set up. The node offers @NODE_BLOOM@ to a peer with
-- 'PermBloomFilter' even without @-peerbloomfilters@.
start :: Options -> Setup -> State
start o s =
  let perms = expandPermissions o s.permissions
      (nonce, g) = nextWord64 (Rng s.seed)
      ours
        | PermBloomFilter `Set.member` perms = localServices o .|. nodeBloom
        | otherwise = localServices o
      onionInbound = s.connectionType == Inbound && s.peerNetwork `elem` [AddrTorV2, AddrTorV3]
   in State
        { connectionType = s.connectionType,
          permissions = perms,
          peerNetwork = s.peerNetwork,
          transport = s.transport,
          isLocal = s.peerIsLocal || onionInbound,
          connectedAt = s.openedAt,
          rng = g,
          ourServices = ours,
          localNonce = nonce,
          disconnected = False,
          shouldDiscourage = Nothing,
          versionSent = False,
          peerVersion = Nothing,
          commonVersion = initProtoVersion,
          theirServices = 0,
          peerUserAgent = "",
          successfullyConnected = False,
          lastSend = Nothing,
          lastRecv = Nothing,
          wtxidRelay = False,
          wantsAddrV2 = False,
          reconciliation = NoReconciliation,
          pingNonceSent = 0,
          pingStart = 0,
          pingQueued = False,
          lastPingTime = Nothing,
          minPingTime = Nothing,
          txRelay = Nothing,
          relaysTxs = False,
          addrRelay = False,
          addrKnown = Set.empty,
          addrsToSend = [],
          getAddrSent = False,
          getAddrRecvd = False,
          addrTokens = 1,
          addrTokensAt = s.openedAt,
          nextAddrSend = 0,
          nextLocalAddrSend = 0,
          feeFilterSent = 0,
          nextFeeFilter = 0,
          privateTx = Nothing,
          blocks =
            BlockState
              { preferredDownload = False,
                bestKnownBlock = Nothing,
                lastUnknownBlock = Nothing,
                bestHeaderSent = Nothing,
                syncStarted = False,
                headersSyncTimeout = Just 0,
                lastGetHeaders = Nothing,
                lowWorkSync = Nothing,
                invTriggeredGetHeaders = False,
                stallingSince = Nothing,
                inFlight = [],
                downloadingSince = 0,
                prefersHeaders = False,
                sentSendHeaders = False,
                providesCmpct = False,
                requestedHbCmpct = False,
                highBandwidthTo = False,
                chainSync = ChainSync 0 Nothing False False,
                lastBlockAnnouncement = Nothing,
                forHeadersRelay = [],
                forInvRelay = [],
                continuationBlock = Nothing
              }
        }

-- | The peer's @verack@ came: the handshake is complete
-- (@fSuccessfullyConnected@).
handshakeComplete :: State -> Bool
handshakeComplete s = s.successfullyConnected

-- | The peer's @version@ was accepted (@nVersion != 0@).
versionReceived :: State -> Bool
versionReceived s = isJust s.peerVersion

-- | The node decided to close the connection (@fDisconnect@).
isDisconnected :: State -> Bool
isDisconnected s = s.disconnected

-- | The peer misbehaved and the node has not acted on it yet
-- (@m_should_discourage@), with the place that decided it.
discouragementPending :: State -> Maybe Cite
discouragementPending s = s.shouldDiscourage

-- | The blocks requested from the peer and not received, oldest first.
blocksInFlight :: State -> [BlockHash]
blocksInFlight s = map (.block) s.blocks.inFlight

-- | A ping waits for its pong: its nonce and when it was sent.
pingOutstanding :: State -> Maybe (Word64, Micros)
pingOutstanding s
  | s.pingNonceSent == 0 = Nothing
  | otherwise = Just (s.pingNonceSent, s.pingStart)

-- | The node announces transactions to the peer: there is a t'TxRelay' and
-- its @m_relay_txs@ is set.
txRelayEnabled :: State -> Bool
txRelayEnabled s = maybe False (.relayTxs) s.txRelay

-- | The node relays addresses to the peer (@m_addr_relay_enabled@).
addrRelayEnabled :: State -> Bool
addrRelayEnabled s = s.addrRelay
