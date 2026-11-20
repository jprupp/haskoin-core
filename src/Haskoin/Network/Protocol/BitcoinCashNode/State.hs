{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCashNode.State
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- What Bitcoin Cash Node 29.2.0 keeps about one peer, and the small language
-- in which the handlers of the machine are written.
--
-- Upstream splits this state between @CNode@ (@src\/net.h@), which the
-- socket thread and the message thread share, and @CNodeState@
-- (@src\/net_processing.cpp:269-385@), which @cs_main@ guards. The split is
-- about locks, not meaning, so the machine keeps one record with three parts:
-- the connection and handshake in t'State', the blocks in t'BlockState', and
-- the relay of transactions, proofs and addresses in t'RelayState'. Each field
-- names the upstream field it stands for.
--
-- Two kinds of upstream state are modelled more simply, and say so where they
-- are kept: the rolling Bloom filters that remember what a peer knows
-- (@filterInventoryKnown@, @addrKnown@) are exact sets here, and the
-- per-peer part of the global @TxRequestTracker@ is a map of this peer's
-- announcements.
--
-- Handlers run in 'M', a reader of the options and the environment, a writer
-- of t'Effect's in the order the node produces them, and a state. The helpers
-- 'send', 'misbehaving' and 'disconnect' keep the bookkeeping that every
-- handler needs in one place: the time of the last send for the inactivity
-- check, the ban score and its threshold, and the flag that stops all
-- processing once the node has decided to close the connection.
module Haskoin.Network.Protocol.BitcoinCashNode.State
  ( -- * State
    State (..),
    BlockState (..),
    RelayState (..),
    InFlight (..),
    TxAnnouncement (..),
    TxRequestState (..),
    ChainSync (..),
    AddrKey,
    addrKey,
    initialState,

    -- * Handlers
    M,
    runM,
    options,
    env,
    nowM,
    emit,
    send,
    ignore,
    process,
    misbehaving,
    disconnect,
    modifyBlocks,
    modifyRelay,
    randomWord,
    randomDelay,
    hasPerm,
    isInbound,
    connType,
    inIBD,
    pushAddress,
    rejectMessage,
    sendReject,
  )
where

import Control.DeepSeq (NFData)
import Control.Monad (when)
import Control.Monad.RWS.Strict (RWS, asks, get, gets, modify', runRWS, tell)
import Data.ByteString qualified as BS
import Data.Maybe (isJust)
import Data.Text.Encoding qualified as TE
import Data.Int (Int32, Int64)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Sequence qualified as Seq
import Data.Set (Set)
import Data.Set qualified as Set
import Data.Text (Text)
import Data.ByteString (ByteString)
import Data.Word (Word16, Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Block.Common (BlockHash)
import Haskoin.Crypto.Hash (Hash256)
import Haskoin.Network.Bloom (BloomFilter (..), BloomFlags (..))
import Haskoin.Network.Common
  ( MessageCommand,
    NetworkAddressV2 (..),
    Reject (..),
    RejectCode (..),
    VarString (..),
    addressNetworkId,
    fromNetworkAddressV2,
  )
import Haskoin.Network.CompactBlock (CompactBlock)
import Haskoin.Network.Message (Message (..))
import Haskoin.Network.Protocol.BitcoinCashNode.Constants
import Haskoin.Network.Protocol.BitcoinCashNode.Options
import Haskoin.Network.Protocol.Types
import Haskoin.Transaction.Common (TxHash)

-- | What the node keeps about a peer. The connection and handshake fields
-- are here, those of the block and relay families in t'BlockState' and
-- t'RelayState'.
data State = State
  { -- | the connection as it opened
    conn :: !Setup,
    -- | the permissions after 'effectivePermissions' (@m_permissionFlags@)
    perms :: !Permissions,
    -- | services offered to this peer (@nLocalServices@, @src\/net.h:955@)
    ourServices :: !Word64,
    -- | randomness of the node for this connection
    rng :: !Rng,
    -- | the node decided to close the connection (@fDisconnect@,
    -- @src\/net.h:844@); nothing is processed after it
    closing :: !Bool,
    -- | our @version@ was sent (outbound connections, at @InitializeNode@)
    versionSent :: !Bool,
    -- | nonce of our @version@ (@nLocalHostNonce@, @src\/net.h:953@)
    localNonce :: !Word64,
    -- | protocol version of the peer, 0 before its @version@ (@nVersion@,
    -- @src\/net.h:806@)
    peerVersion :: !Int,
    -- | services of the peer (@nServices@, @src\/net.h:776@)
    peerServices :: !Word64,
    -- | start height of the peer, -1 if unknown (@nStartingHeight@)
    peerStartHeight :: !Int32,
    -- | user agent of the peer after @SanitizeString@ (@cleanSubVer@)
    peerSubVer :: !Text,
    -- | the peer serves neither the whole chain nor its recent part
    -- (@fClient@, @src\/net.h:822@)
    client :: !Bool,
    -- | the peer serves only the recent part of the chain
    -- (@m_limited_node@, @src\/net.h:824@)
    limitedNode :: !Bool,
    -- | we sent @extversion@ and wait for the peer's (@extversionExpected@)
    extVersionExpected :: !Bool,
    -- | the peer's @extversion@ was parsed (@extversionEnabled@)
    extVersionEnabled :: !Bool,
    -- | the peer sent @sendaddrv2@ (@m_wants_addrv2@, @src\/net.h:829@)
    wantsAddrV2 :: !Bool,
    -- | the peer's @verack@ arrived (@fSuccessfullyConnected@,
    -- @src\/net.h:843@)
    connected :: !Bool,
    -- | we sent a @verack@ (@mapSendBytesPerMsgType[VERACK] > 0@)
    verAckSent :: !Bool,
    -- | we sent a @getaddr@ (@mapSendBytesPerMsgType[GETADDR] > 0@)
    getAddrSent :: !Bool,
    -- | offset of the peer's clock in seconds (@nTimeOffset@)
    timeOffset :: !Int64,
    -- | time of the last bytes received, 0 for never (@nLastRecv@)
    lastRecv :: !Micros,
    -- | time of the last bytes sent, 0 for never (@nLastSend@)
    lastSend :: !Micros,
    -- | nonce of the ping that waits for its pong, 0 for none
    -- (@nPingNonceSent@, @src\/net.h:917@)
    pingNonceSent :: !Word64,
    -- | when the last ping was sent (@nPingUsecStart@, @src\/net.h:919@)
    pingStart :: !Micros,
    -- | the last round trip (@nPingUsecTime@)
    pingTime :: !(Maybe Micros),
    -- | the best round trip (@nMinPingUsecTime@)
    minPingTime :: !(Maybe Micros),
    -- | an operator asked for a ping (@fPingQueued@)
    pingQueued :: !Bool,
    -- | the ban score (@nMisbehavior@, @src\/net_processing.cpp:275@)
    misbehavior :: !Int,
    -- | the score crossed @-banscore@ and the node has not acted on it yet
    -- (@fShouldDiscourage@, @src\/net_processing.cpp:277@)
    shouldDiscourage :: !Bool,
    -- | @reject@ messages for invalid blocks from this peer, waiting to be
    -- sent (@CNodeState::rejects@)
    blockRejects :: ![Message],
    -- | the peer counts as a preferred download source
    -- (@fPreferredDownload@, @src\/net_processing.cpp:306@)
    preferredDownload :: !Bool,
    blocks :: !BlockState,
    relay :: !RelayState
  }
  deriving (Eq, Show, Generic, NFData)

-- | A block requested from this peer (@QueuedBlock@,
-- @src\/net_processing.cpp:164-175@).
data InFlight = InFlight
  { inFlightHash :: !BlockHash,
    -- | the header is known (@fValidatedHeaders@)
    validatedHeaders :: !Bool,
    -- | the compact block being completed (@partialBlock@)
    partial :: !(Maybe CompactBlock)
  }
  deriving (Eq, Show, Generic, NFData)

-- | The outbound chain-sync check (@m_chain_sync@,
-- @src\/net_processing.cpp:341-354@).
data ChainSync = ChainSync
  { -- | deadline in seconds, 0 for none (@m_timeout@)
    syncTimeout :: !Int64,
    -- | the tip whose work the peer must reach (@m_work_header@)
    workHeader :: !(Maybe BlockInfo),
    -- | the last-chance @getheaders@ was sent (@m_sent_getheaders@)
    sentGetHeaders :: !Bool,
    -- | the peer is protected from this check (@m_protect@)
    protect :: !Bool
  }
  deriving (Eq, Show, Generic, NFData)

-- | What the node keeps about blocks for this peer.
data BlockState = BlockState
  { -- | best block the peer is known to have (@pindexBestKnownBlock@)
    bestKnown :: !(Maybe BlockInfo),
    -- | last announced hash the node did not know (@hashLastUnknownBlock@)
    lastUnknown :: !(Maybe BlockHash),
    -- | best header sent to the peer (@pindexBestHeaderSent@)
    bestHeaderSent :: !(Maybe BlockInfo),
    -- | streak of headers that did not connect (@nUnconnectingHeaders@)
    unconnecting :: !Int,
    -- | the initial @getheaders@ went out (@fSyncStarted@)
    syncStarted :: !Bool,
    -- | deadline of the headers sync, 'maxBound' once caught up
    -- (@nHeadersSyncTimeout@)
    headersSyncTimeout :: !Micros,
    -- | when the peer started holding back the download window, 0 for
    -- never (@nStallingSince@)
    stallingSince :: !Micros,
    -- | blocks requested from this peer, oldest first (@vBlocksInFlight@)
    inFlight :: ![InFlight],
    -- | when the oldest block in flight started downloading
    -- (@nDownloadingSince@)
    downloadingSince :: !Micros,
    -- | the peer sent @sendheaders@ (@fPreferHeaders@)
    preferHeaders :: !Bool,
    -- | the peer asked for high-bandwidth compact blocks
    -- (@fPreferHeaderAndIDs@)
    preferHeaderAndIds :: !Bool,
    -- | the peer sent @sendcmpct@ of version 1 (@fProvidesHeaderAndIDs@,
    -- @fSupportsDesiredCmpctVersion@)
    providesHeaderAndIds :: !Bool,
    -- | we chose the peer for high-bandwidth compact blocks
    -- (@m_bip152_highbandwidth_to@)
    highBandwidthTo :: !Bool,
    -- | the outbound chain-sync check
    chainSync :: !ChainSync,
    -- | time of the last new block announcement with more work than the tip
    -- (@m_last_block_announcement@)
    lastBlockAnnouncement :: !Int64,
    -- | hashes of new tips to announce (@vBlockHashesToAnnounce@)
    toAnnounce :: ![BlockHash],
    -- | block hashes to announce by @inv@ (@vInventoryBlockToSend@)
    blockInvs :: ![BlockHash],
    -- | last hash of a 500-block @getblocks@ reply (@hashContinue@)
    hashContinue :: !(Maybe BlockHash),
    -- | blocks that the rest of the node asked this peer for, to request
    -- in the next pass
    toRequest :: ![BlockHash]
  }
  deriving (Eq, Show, Generic, NFData)

-- | Where an announced transaction stands (@TxRequestTracker@ states,
-- @src\/txrequest.h:18-202@).
data TxRequestState
  = -- | announced, not requested yet (@CANDIDATE@)
    TxCandidate
  | -- | requested, with the time the request expires (@REQUESTED@)
    TxRequested !Micros
  deriving (Eq, Show, Generic, NFData)

-- | A transaction announced by this peer.
data TxAnnouncement = TxAnnouncement
  { -- | when it may be requested (@reqtime@)
    reqTime :: !Micros,
    txState :: !TxRequestState
  }
  deriving (Eq, Show, Generic, NFData)

-- | What the node keeps about the relay of transactions, double-spend
-- proofs and addresses for this peer.
data RelayState = RelayState
  { -- | the peer wants transactions (@fRelayTxes@, @src\/net.h:850@)
    relayTxes :: !Bool,
    -- | the peer's Bloom filter (@pfilter@, @src\/net.h:854@). It is never
    -- null upstream: an empty filter matches everything.
    bloom :: !BloomFilter,
    -- | hashes the peer knows (@filterInventoryKnown@, a rolling Bloom
    -- filter upstream, an exact set here)
    knownInv :: !(Set Hash256),
    -- | transactions to announce (@setInventoryTxToSendTopoSorted@); the
    -- order of the mempool is the order of arrival here
    txsToSend :: ![TxHash],
    -- | proof ids to announce (@vInventoryToSend@)
    otherInvs :: ![Hash256],
    -- | next time to announce transactions (@nNextInvSend@)
    nextInvSend :: !Micros,
    -- | the peer sent @mempool@ (@fSendMempool@)
    sendMempool :: !Bool,
    -- | when the node last answered @mempool@, in seconds, 0 for never
    -- (@timeLastMempoolReq@)
    lastMempoolReq :: !Int64,
    -- | the peer's @feefilter@ (@minFeeFilter@)
    minFeeFilter :: !Word64,
    -- | the last @feefilter@ we sent (@lastSentFeeFilter@)
    lastSentFeeFilter :: !Word64,
    -- | next time to send @feefilter@ (@nextSendTimeFeeFilter@)
    nextFeeFilter :: !Micros,
    -- | addresses to send (@vAddrToSend@)
    addrToSend :: ![NetworkAddressV2],
    -- | addresses the peer knows (@addrKnown@, a rolling Bloom filter
    -- upstream, an exact set here)
    addrKnown :: !(Set AddrKey),
    -- | we asked for addresses and wait for the reply (@fGetAddr@)
    getAddrPending :: !Bool,
    -- | we answered a @getaddr@ (@fSentAddr@)
    sentAddr :: !Bool,
    -- | the address rate limiter (@m_addr_token_bucket@)
    addrTokens :: !Double,
    -- | when the bucket was last filled (@m_addr_token_timestamp@)
    addrTokenTime :: !Micros,
    -- | next time to send addresses (@m_next_addr_send@)
    nextAddrSend :: !Micros,
    -- | next time to advertise our address (@m_next_local_addr_send@)
    nextLocalAddrSend :: !Micros,
    -- | this peer's transaction announcements (its part of @m_txrequest@)
    announcements :: !(Map TxHash TxAnnouncement),
    -- | proof ids to request (@dsproofGetDatasToBatch@)
    dsProofsToRequest :: ![Hash256]
  }
  deriving (Eq, Show, Generic, NFData)

-- | The state when a connection opens (@CNode@ constructor,
-- @CNodeState@ constructor and @InitializeNode@).
initialState :: Options -> Setup -> State
initialState o s =
  State
    { conn = s,
      perms = ps,
      ourServices = localServices o ps,
      rng = g1,
      closing = False,
      versionSent = False,
      localNonce = nonce,
      peerVersion = 0,
      peerServices = 0,
      peerStartHeight = -1,
      peerSubVer = "",
      client = False,
      limitedNode = False,
      extVersionExpected = False,
      extVersionEnabled = False,
      wantsAddrV2 = False,
      connected = False,
      verAckSent = False,
      getAddrSent = False,
      timeOffset = 0,
      lastRecv = 0,
      lastSend = 0,
      pingNonceSent = 0,
      pingStart = 0,
      pingTime = Nothing,
      minPingTime = Nothing,
      pingQueued = False,
      misbehavior = 0,
      shouldDiscourage = False,
      blockRejects = [],
      preferredDownload = False,
      blocks =
        BlockState
          { bestKnown = Nothing,
            lastUnknown = Nothing,
            bestHeaderSent = Nothing,
            unconnecting = 0,
            syncStarted = False,
            headersSyncTimeout = 0,
            stallingSince = 0,
            inFlight = [],
            downloadingSince = 0,
            preferHeaders = False,
            preferHeaderAndIds = False,
            providesHeaderAndIds = False,
            highBandwidthTo = False,
            chainSync = ChainSync 0 Nothing False False,
            lastBlockAnnouncement = 0,
            toAnnounce = [],
            blockInvs = [],
            hashContinue = Nothing,
            toRequest = []
          },
      relay =
        RelayState
          { relayTxes = False,
            bloom = emptyFilter,
            knownInv = Set.empty,
            txsToSend = [],
            otherInvs = [],
            nextInvSend = 0,
            sendMempool = False,
            lastMempoolReq = 0,
            minFeeFilter = 0,
            lastSentFeeFilter = 0,
            nextFeeFilter = 0,
            addrToSend = [],
            addrKnown = Set.empty,
            getAddrPending = False,
            sentAddr = False,
            addrTokens = 1,
            addrTokenTime = s.openedAt,
            nextAddrSend = 0,
            nextLocalAddrSend = 0,
            announcements = Map.empty,
            dsProofsToRequest = []
          }
    }
  where
    ps = effectivePermissions o s
    (nonce, g1) = nextWord64 (Rng s.seed)

-- | The filter of a new connection, @CBloomFilter()@: empty, so that it
-- matches every transaction (@src\/net.cpp:2878@).
emptyFilter :: BloomFilter
emptyFilter = BloomFilter Seq.empty 0 0 BloomUpdateNone

-- | The key of an address in @addrKnown@: network, bytes and port
-- (@CService::GetKey@).
type AddrKey = (Word8, ByteString, Word16)

-- | The key of an address.
addrKey :: NetworkAddressV2 -> AddrKey
addrKey a = (addressNetworkId a.network, a.address, a.port)

-- | The language of the handlers: a reader of the options and the
-- environment, a writer of effects, and the state.
type M = RWS (Options, Env) [Effect] State

-- | Run a handler.
runM :: Options -> Env -> State -> M () -> (State, [Effect])
runM o e s m = let ((), s', es) = runRWS m (o, e) s in (s', es)

-- | The options.
options :: M Options
options = asks fst

-- | The environment.
env :: M Env
env = asks snd

-- | The current time.
nowM :: M Micros
nowM = asks (\(_, e) -> e.now)

-- | Produce an effect.
emit :: Action -> Cite -> M ()
emit a c = tell [Effect a c]

-- | Send a message, and note the time for the inactivity check.
send :: Message -> Cite -> M ()
send m c = do
  t <- nowM
  modify' (\s -> s {lastSend = t})
  emit (Send m) c

-- | Drop the message without an answer.
ignore :: Cite -> M ()
ignore = emit Ignore

-- | An effect on the rest of the node that the peer does not see.
process :: Text -> Cite -> M ()
process t = emit (Process t)

-- | Add to the ban score, as @Misbehaving@ does
-- (@src\/net_processing.cpp:894-919@): a score of 0 does nothing, and the
-- threshold is crossed when the old score was below @-banscore@ and the new
-- one is not. The node acts on it after the message, or at the next pass of
-- @SendMessages@.
misbehaving :: Int -> Cite -> M ()
misbehaving n c = when (n /= 0) $ do
  o <- options
  old <- gets (.misbehavior)
  let new = old + n
  emit (Misbehave n) c
  modify' $ \s ->
    s
      { misbehavior = new,
        shouldDiscourage =
          s.shouldDiscourage || (new >= o.banScore && old < o.banScore)
      }

-- | Close the connection (@fDisconnect = true@).
disconnect :: DisconnectReason -> Cite -> M ()
disconnect r c = do
  modify' (\s -> s {closing = True})
  emit (Disconnect r) c

-- | Change the block state.
modifyBlocks :: (BlockState -> BlockState) -> M ()
modifyBlocks f = modify' (\s -> s {blocks = f s.blocks})

-- | Change the relay state.
modifyRelay :: (RelayState -> RelayState) -> M ()
modifyRelay f = modify' (\s -> s {relay = f s.relay})

-- | 64 random bits.
randomWord :: M Word64
randomWord = do
  g <- gets (.rng)
  let (w, g') = nextWord64 g
  modify' (\s -> s {rng = g'})
  return w

-- | A delay from an exponential distribution of this mean
-- (@PoissonNextSend@, @src\/net.cpp:2980-2984@).
randomDelay :: Micros -> M Micros
randomDelay mean = do
  g <- gets (.rng)
  let (d, g') = poissonDelay mean g
  modify' (\s -> s {rng = g'})
  return d

-- | The peer has this permission.
hasPerm :: Permission -> M Bool
hasPerm p = gets (Set.member p . (.perms))

-- | The type of the connection.
connType :: M ConnectionType
connType = gets (.conn.connectionType)

-- | The peer connected to the node.
isInbound :: M Bool
isInbound = (== Inbound) <$> connType

-- | The node is in initial block download.
inIBD :: M Bool
inIBD = (.initialBlockDownload) <$> env

-- | Queue an address for the peer, as @CNode::PushAddress@ does
-- (@src\/net.h:993-1010@): only an address the peer does not know, and that
-- it can read: an @addrv2@-only address goes only to a peer that sent
-- @sendaddrv2@. A full queue of 1000 has a random entry replaced.
pushAddress :: NetworkAddressV2 -> M ()
pushAddress a = do
  s <- get
  let known = addrKey a `Set.member` s.relay.addrKnown
      readable = s.wantsAddrV2 || isJust (fromNetworkAddressV2 a)
      valid = not (BS.null a.address)
      queue = s.relay.addrToSend
  when (valid && not known && readable) $
    if length queue >= maxAddrToSend
      then do
        w <- randomWord
        let i = fromIntegral (w `mod` fromIntegral (length queue))
            queue' = take i queue <> [a] <> drop (i + 1) queue
        modifyRelay (\r -> r {addrToSend = queue'})
      else modifyRelay (\r -> r {addrToSend = queue <> [a]})

-- | A @reject@ message, if the code is one that the library can send. The
-- reason is cut to 111 bytes (@MAX_REJECT_MESSAGE_LENGTH@).
rejectMessage :: MessageCommand -> Word8 -> Text -> Maybe Hash256 -> Maybe Message
rejectMessage cmd code reason h = do
  c <- case code of
    0x01 -> Just RejectMalformed
    0x10 -> Just RejectInvalid
    0x11 -> Just RejectObsolete
    0x12 -> Just RejectDuplicate
    0x40 -> Just RejectNonStandard
    0x41 -> Just RejectDust
    0x42 -> Just RejectInsufficientFee
    0x43 -> Just RejectCheckpoint
    _ -> Nothing
  let r = BS.take maxRejectMessageLength (TE.encodeUtf8 reason)
  return (MReject (Reject cmd c (VarString r) h))

-- | Send a @reject@ if @-enablebip61@ is on (the default) and the code is
-- one between 1 and 0xff that the library knows.
sendReject :: MessageCommand -> Word8 -> Text -> Maybe Hash256 -> Cite -> M ()
sendReject cmd code reason h c = do
  o <- options
  when o.enableBip61 $
    mapM_ (`send` c) (rejectMessage cmd code reason h)
