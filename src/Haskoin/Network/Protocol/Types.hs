{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.Types
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- The vocabulary shared by the protocol machines of
-- "Haskoin.Network.Protocol.BitcoinCore" and
-- "Haskoin.Network.Protocol.BitcoinCashNode".
--
-- A machine is a translation of how one reference node treats one peer. The
-- node is the side being modelled, and the peer is the other end of the
-- connection: usually the program that uses this library. The machine is a
-- pure function from the state that the node keeps about the peer, the
-- environment of the node and one 'Input', to the next state and the
-- t'Effect's that the node produces. It opens no socket and reads no clock:
-- the caller brings the time, the randomness and the answers about the chain
-- and the mempool in an t'Env'.
--
-- Every t'Effect' carries a t'Cite': the place in the upstream source that
-- produces it, and a short reason. A caller can check what the node would do
-- and see where in the upstream code it is decided. The upstream versions that
-- were read are named by t'Upstream'.
--
-- The design keeps three things apart:
--
-- * the t'Setup' of a connection, fixed when it opens: who opened it, the
--   permissions of the peer, its address network;
-- * the t'Env', the answers about the rest of the node that a decision needs,
--   given again at each step because the chain and the mempool change between
--   messages;
-- * the state, private to each machine, which only the machine changes.
--
-- The alternatives were rejected for these reasons. A machine that ran in a
-- monad over the node's own chain store would tie the library to one store.
-- A machine that returned requests for the environment and waited for the
-- answers would turn each message into a dialogue and make the tests long.
-- A pure t'Env' of answers keeps each step one function call, and a test
-- states the chain it assumes in one record.
module Haskoin.Network.Protocol.Types
  ( -- * Upstream code
    Upstream (..),
    Cite (..),
    cite,

    -- * Connections
    ConnectionType (..),
    isOutbound,
    Permission (..),
    Permissions,
    TransportVersion (..),
    Setup (..),

    -- * Time
    Micros,
    seconds,
    millis,

    -- * Inputs
    Input (..),
    FrameError (..),
    Notification (..),

    -- * Outputs
    Effect (..),
    Action (..),
    DisconnectReason (..),

    -- * The environment
    Env (..),
    BlockInfo (..),
    BlockStatus (..),
    HeadersVerdict (..),
    BlockVerdict (..),
    TxVerdict (..),
    defaultEnv,

    -- * Randomness
    Rng (..),
    nextWord64,
    randomBelow,
    poissonDelay,

    -- * Verdicts of compact blocks and double-spend proofs
    CompactVerdict (..),
    DsProofVerdict (..),
  )
where

import Control.DeepSeq (NFData)
import Data.Bits (shiftR, xor, (.&.))
import Data.ByteString (ByteString)
import Data.Int (Int64)
import Data.Set (Set)
import Data.Text (Text)
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Block.Common (Block, BlockHash, BlockHeader, BlockHeight, BlockLocator)
import Haskoin.Block.Merkle (MerkleBlock)
import Haskoin.Crypto.Hash (Hash256)
import Haskoin.Network.BlockFilter
  ( CFCheckpt,
    CFHeaders,
    CFilter,
    GetCFCheckpt,
    GetCFHeaders,
    GetCFilters,
  )
import Haskoin.Network.Bloom (BloomFilter)
import Haskoin.Network.Common (AddressNetwork (..), NetworkAddressV2)
import Haskoin.Network.CompactBlock (CompactBlock)
import Haskoin.Network.Message (Message)
import Haskoin.Transaction.Common (Tx, TxHash)

-- | A release of a reference node whose source a machine translates.
data Upstream = Upstream
  { -- | name of the project, such as @Bitcoin Core@
    project :: !Text,
    -- | release, such as @32.1@
    release :: !Text,
    -- | Git tag of the release
    tag :: !Text,
    -- | commit that the tag names, whose source was read
    commit :: !Text,
    -- | where the source is published
    repository :: !Text
  }
  deriving (Eq, Show, Read, Generic, NFData)

-- | Where in the upstream source a decision is made, and why. The file is a
-- path from the root of the repository of the t'Upstream' release, and the line
-- is the line of that file at its commit.
data Cite = Cite
  { file :: !FilePath,
    line :: !Int,
    -- | the reason in a few words, often the string that the node logs
    reason :: !Text
  }
  deriving (Eq, Ord, Show, Read, Generic, NFData)

-- | Build a t'Cite'.
cite :: FilePath -> Int -> Text -> Cite
cite = Cite

-- | Who opened a connection and why, as the node sees it
-- (@ConnectionType@ in both nodes). A program that connects to a node is an
-- 'Inbound' peer of that node. The node opens the other types itself.
data ConnectionType
  = -- | the peer connected to the node
    Inbound
  | -- | the node connected to relay blocks, transactions and addresses
    OutboundFullRelay
  | -- | the node connected because of @-addnode@ or @-connect@, or an RPC
    Manual
  | -- | a short connection to test that an address is reachable
    Feeler
  | -- | an outbound connection that relays blocks only
    BlockRelayOnly
  | -- | a short connection to ask for addresses (@-seednode@)
    AddrFetch
  | -- | Bitcoin Core only: a short connection to send one of the node's own
    -- transactions privately
    PrivateBroadcast
  deriving (Eq, Ord, Show, Read, Enum, Bounded, Generic, NFData)

-- | Whether the node opened the connection.
isOutbound :: ConnectionType -> Bool
isOutbound Inbound = False
isOutbound _ = True

-- | Permissions that the node grants a peer because of @-whitelist@ or
-- @-whitebind@ (@NetPermissionFlags@). A peer that matches neither has none.
-- The implications between them differ: on Bitcoin Core 'PermNoBan' brings
-- 'PermDownload', and Bitcoin Cash Node has no 'PermDownload'. Each machine
-- expands a set of permissions as its node does; see its documentation.
data Permission
  = -- | may load a Bloom filter even if the node does not offer them
    PermBloomFilter
  | -- | transactions are taken from it even in blocks-only mode
    PermRelay
  | -- | its transactions are relayed even when the node already has them
    PermForceRelay
  | -- | Bitcoin Core only: may download blocks during initial block download
    -- and past the upload target
    PermDownload
  | -- | is never discouraged, banned or disconnected for misbehaviour
    PermNoBan
  | -- | may send a @mempool@ message
    PermMempool
  | -- | gets addresses without the address cache, and sends any number
    PermAddr
  | -- | the permissions come from a bare @-whitelist@ or @-whitebind@ with no
    -- list of flags, so that options such as @-whitelistrelay@ apply
    PermImplicit
  deriving (Eq, Ord, Show, Read, Enum, Bounded, Generic, NFData)

-- | A set of permissions.
type Permissions = Set Permission

-- | Transport of a connection. Bitcoin Core speaks the encrypted transport of
-- BIP 324 when both sides offer it. Bitcoin Cash Node speaks the first one
-- only. The machine sees messages, not bytes: the transport changes only how
-- a framing error is handled.
data TransportVersion
  = -- | the original framing: magic, command, length and checksum
    TransportV1
  | -- | the encrypted transport of BIP 324
    TransportV2
  deriving (Eq, Ord, Show, Read, Enum, Bounded, Generic, NFData)

-- | What the node knows about a connection when it opens.
data Setup = Setup
  { connectionType :: !ConnectionType,
    -- | permissions as configured, before the machine expands them
    permissions :: !Permissions,
    -- | address network of the peer
    peerNetwork :: !AddressNetwork,
    -- | the peer's address is a local one, such as 127.0.0.1
    peerIsLocal :: !Bool,
    transport :: !TransportVersion,
    -- | time when the connection opened
    openedAt :: !Micros,
    -- | seed of the randomness of the node for this connection
    seed :: !Word64
  }
  deriving (Eq, Show, Read, Generic, NFData)

-- | Time in microseconds since the Unix epoch, or a length of time in
-- microseconds. Both nodes keep time in microseconds where it matters to the
-- protocol, and in seconds elsewhere.
type Micros = Int64

-- | Microseconds in a number of seconds.
seconds :: Int64 -> Micros
seconds = (* 1000000)

-- | Microseconds in a number of milliseconds.
millis :: Int64 -> Micros
millis = (* 1000)

-- | Something that happens to a connection.
data Input
  = -- | a message from the peer, whole and with a good checksum
    Receive !Message
  | -- | bytes from the peer that are not a message the node accepts
    BadFrame !FrameError
  | -- | time has passed: the node runs its timers and its sending loop for this
    -- peer (@SendMessages@), which both nodes run about every 100 ms
    Tick
  | -- | something happened in the rest of the node that this peer may hear of
    Notify !Notification
  deriving (Eq, Show, Generic)

-- | Ways that bytes from a peer can fail to be a message.
data FrameError
  = -- | the header starts with the magic of another network
    WrongMagic !Word32
  | -- | the command is not printable ASCII padded with zeros
    BadCommand !ByteString
  | -- | the payload is larger than the node accepts for this command
    Oversized !ByteString !Word32
  | -- | the checksum does not match the payload
    BadChecksum !ByteString
  | -- | the command is known but its payload does not parse: the command,
    -- then the bytes of the payload. A node reads some payloads that the
    -- parser of the library refuses, and with the bytes a machine can read
    -- them as its node does. The Bitcoin Core machine does so for a
    -- @sendcmpct@ with an announce byte above 1.
    BadPayload !ByteString !ByteString
  deriving (Eq, Show, Read, Generic, NFData)

-- | News from the rest of the node.
data Notification
  = -- | the active chain has a new tip; the blocks are the new ones, oldest
    -- first, so that the node can announce them
    NewTip ![BlockHeader]
  | -- | a transaction entered the mempool and may be announced
    TxAccepted !Tx
  | -- | an address that the node relays to some of its peers
    RelayAddress !NetworkAddressV2
  | -- | the node chose this peer for high-bandwidth compact blocks, or stopped
    -- choosing it
    HighBandwidth !Bool
  | -- | the node wants this block from this peer
    RequestBlock !BlockHash
  | -- | the node wants this transaction from this peer
    RequestTx !TxHash
  | -- | an operator asked to disconnect the peer
    OperatorDisconnect
  | -- | the download of blocks waits on this peer: it holds the first block
    -- of the download window and other peers have nothing left to fetch
    -- (@m_stalling_since@ of Bitcoin Core, @nStallingSince@ of Bitcoin Cash
    -- Node, set by another peer's download pass)
    MarkStalling
  | -- | an operator asked for a ping to this peer (RPC @ping@,
    -- @m_ping_queued@ of Bitcoin Core, @fPingQueued@ of Bitcoin Cash Node)
    PingRequested
  | -- | a block passed its proof of work and merkle checks and extends the
    -- tip, before full validation (@NewPoWValidBlock@), so that it can be
    -- announced at once to high-bandwidth compact block peers
    NewPoWValidBlock !BlockHeader
  | -- | misbehaviour charged to this peer from outside its own messages, with
    -- the score and the reason: an orphan transaction it sent turned out
    -- invalid, an orphan double-spend proof it sent turned out invalid or
    -- expired (@Misbehaving@ called from the rest of the node)
    Penalty !Int !Text
  | -- | a double-spend proof with this id was accepted for this transaction
    -- and may be announced (@TransactionDoubleSpent@ of Bitcoin Cash Node)
    NewDoubleSpendProof !Hash256 !Tx
  | -- | the node chose this peer to make room: inbound eviction, an extra
    -- outbound peer, or a tx-relaying inbound peer over the limit
    Evict
  deriving (Eq, Show, Generic)

-- | Something that the node does, with the place in the source that does it.
data Effect = Effect
  { action :: !Action,
    because :: !Cite
  }
  deriving (Eq, Show, Generic)

-- | The things a node can do to a peer.
data Action
  = -- | send this message to the peer
    Send !Message
  | -- | drop the message without an answer, which is what the peer observes
    Ignore
  | -- | add to the ban score of the peer (Bitcoin Cash Node), and the reason
    Misbehave !Int
  | -- | mark the peer to be discouraged and disconnected (Bitcoin Core);
    -- a discouraged address is the first to be evicted when inbound slots run
    -- out, and the node does not connect to it again
    Discourage
  | -- | ban the address of the peer, for the given number of seconds
    Ban !Int64
  | -- | close the connection
    Disconnect !DisconnectReason
  | -- | hand a block, header or transaction to validation, or another effect
    -- on the node outside this connection; the peer does not see it
    Process !Text
  deriving (Eq, Show, Generic)

-- | Why the node closed a connection.
data DisconnectReason
  = -- | the peer broke a rule of the protocol
    ProtocolViolation
  | -- | the peer misbehaved and has no permission that protects it
    Misbehaviour
  | -- | a timer ran out
    Timeout
  | -- | the connection was short-lived by design: a feeler, an address fetch
    Done
  | -- | the peer lacks what this kind of connection needs
    Unsuitable
  | -- | the operator or the node's own resource limits
    Resources
  deriving (Eq, Ord, Show, Read, Enum, Bounded, Generic, NFData)

-- | What the node knows about one block.
data BlockInfo = BlockInfo
  { hash :: !BlockHash,
    height :: !BlockHeight,
    status :: !BlockStatus,
    -- | the block is on the active chain
    inActiveChain :: !Bool,
    -- | total work of the chain up to this block, @nChainWork@
    work :: !Integer,
    -- | time in the header, in seconds
    time :: !Word32
  }
  deriving (Eq, Show, Read, Generic, NFData)

-- | How far the node has got with a block it knows.
data BlockStatus
  = -- | the node has the header only
    HeaderOnly
  | -- | the node has the whole block
    HaveData
  | -- | the block or one of its ancestors is invalid
    Invalid
  deriving (Eq, Ord, Show, Read, Enum, Bounded, Generic, NFData)

-- | What validation says of a @headers@ message.
data HeadersVerdict
  = -- | they connect and are valid; the last one is now known at this height
    HeadersAccepted !BlockHeight
  | -- | the first one does not connect to a header the node knows
    HeadersUnconnected
  | -- | they do not follow one another
    HeadersNonContinuous
  | -- | one is invalid, with the reason that validation gives
    HeadersInvalid !Text
  | -- | they connect but carry too little work to be kept
    HeadersLowWork
  | -- | a header fails its own proof of work (@CheckHeadersPoW@)
    HeadersBadPoW
  | -- | a header was already known to be invalid (@BLOCK_CACHED_INVALID@)
    HeadersCachedInvalid
  | -- | a header has a time too far in the future (@BLOCK_TIME_FUTURE@),
    -- which may become valid later
    HeadersTimeFuture
  | -- | one is invalid, with the misbehaviour score and the reason that
    -- validation gives (@CValidationState::IsInvalid(nDoS)@)
    HeadersRejected !Int !Text
  deriving (Eq, Show, Read, Generic, NFData)

-- | What validation says of a @block@.
data BlockVerdict
  = BlockAccepted
  | -- | the node already had it
    BlockDuplicate
  | -- | invalid by consensus; the flag is true when a peer can be blamed
    -- for it, false for errors such as a mutated block
    BlockInvalid !Bool !Text
  | -- | does not connect to a known header
    BlockMissingParent
  | -- | its merkle root or witness commitment does not match its
    -- transactions (@IsBlockMutated@), which may be the fault of the relay
    -- and not of the block
    BlockMutated
  | -- | the block was already known to be invalid (@BLOCK_CACHED_INVALID@)
    BlockCachedInvalid
  | -- | invalid, with the reject code, the misbehaviour score and the reason
    -- that validation gives
    BlockRejected !Word8 !Int !Text
  deriving (Eq, Show, Read, Generic, NFData)

-- | What the mempool says of a @tx@.
data TxVerdict
  = TxAcceptedToMempool
  | -- | already in the mempool or confirmed
    TxAlreadyKnown
  | -- | a parent is missing: an orphan
    TxOrphan
  | -- | refused by policy, not consensus
    TxPolicyReject !Text
  | -- | invalid by consensus
    TxConsensusInvalid !Text
  | -- | refused, with the reject code, the misbehaviour score and the reason
    -- that @AcceptToMemoryPool@ gives
    TxRejected !Word8 !Int !Text
  deriving (Eq, Show, Read, Generic, NFData)

-- | Answers about the rest of the node that a decision needs. The caller
-- builds one before each step from its model of the node.
data Env = Env
  { -- | the current time
    now :: !Micros,
    -- | the tip of the active chain
    tip :: !BlockInfo,
    -- | the node is in initial block download
    initialBlockDownload :: !Bool,
    -- | a block the node knows, by its hash
    lookupBlock :: BlockHash -> Maybe BlockInfo,
    -- | the block of the active chain at a height
    blockAtHeight :: BlockHeight -> Maybe BlockInfo,
    -- | a block's header
    headerOf :: BlockHash -> Maybe BlockHeader,
    -- | a block's data, if the node has it and has not pruned it
    blockData :: BlockHash -> Maybe Block,
    -- | validation of a @headers@ message
    checkHeaders :: [BlockHeader] -> HeadersVerdict,
    -- | validation of a @block@ message
    checkBlock :: Block -> BlockVerdict,
    -- | the mempool's verdict on a @tx@ message
    checkTx :: Tx -> TxVerdict,
    -- | a transaction from the mempool, by txid or wtxid
    mempoolTx :: TxHash -> Maybe Tx,
    -- | every transaction in the mempool, for the @mempool@ message
    mempoolTxs :: [Tx],
    -- | minimum fee rate of the mempool, in satoshi per 1000 bytes
    mempoolMinFee :: !Word64,
    -- | the node is reindexing or importing blocks (@LoadingBlocks@)
    loadingBlocks :: !Bool,
    -- | the best header the node knows, which may be ahead of the tip
    -- (@m_best_header@)
    bestHeader :: !BlockInfo,
    -- | a block locator that starts at a block (@GetLocator@)
    locatorFrom :: BlockHash -> BlockLocator,
    -- | the nonce is that of one of the node's own outbound connections
    -- still in its handshake, so the peer is the node itself
    -- (@CheckIncomingNonce@ fails)
    ownNonce :: Word64 -> Bool,
    -- | too many inbound peers relay transactions and none of the others
    -- can be evicted (@EvictTxPeerIfFull@ fails)
    txRelayInboundFull :: !Bool,
    -- | @-maxuploadtarget@ is reached for any block
    -- (@OutboundTargetReached(false)@)
    uploadTargetReached :: !Bool,
    -- | @-maxuploadtarget@ is reached for historical blocks
    -- (@OutboundTargetReached(true)@)
    historicalUploadTargetReached :: !Bool,
    -- | number of other peers that a block is being downloaded from
    inFlightElsewhere :: BlockHash -> Int,
    -- | number of blocks in flight from all the other peers
    -- (@mapBlocksInFlight@ less this peer)
    otherBlocksInFlight :: !Int,
    -- | number of other peers with blocks in flight
    -- (@m_peers_downloading_from@ less this peer)
    otherPeersDownloading :: !Int,
    -- | number of other peers with headers sync started (@nSyncStarted@
    -- less this peer)
    otherSyncStarted :: !Int,
    -- | number of other preferred download peers
    -- (@m_num_preferred_download_peers@)
    otherPreferredDownload :: !Int,
    -- | number of other outbound peers protected from chain sync eviction
    -- (@m_outbound_peers_with_protect_from_disconnect@)
    otherProtectedOutbound :: !Int,
    -- | the addresses that answer a @getaddr@; the flag asks for a fresh
    -- answer instead of the cached one (@GetAddresses@)
    addressesForPeer :: Bool -> [NetworkAddressV2],
    -- | the address of the node that it advertises to this peer
    -- (@GetLocalAddrForPeer@)
    localAddress :: !(Maybe NetworkAddressV2),
    -- | the transaction to send on a private broadcast connection
    -- (@PickTxForSend@)
    privateBroadcastTx :: !(Maybe Tx),
    -- | a compact block for a block the node has (@CBlockHeaderAndShortTxIDs@)
    compactBlockOf :: BlockHash -> Maybe CompactBlock,
    -- | reconstruction of a compact block from the mempool
    -- (@PartiallyDownloadedBlock::InitData@)
    initCompact :: CompactBlock -> CompactVerdict,
    -- | completion of a compact block with the transactions of a @blocktxn@
    -- (@PartiallyDownloadedBlock::FillBlock@)
    fillCompact :: CompactBlock -> [Tx] -> CompactVerdict,
    -- | a filtered block for a Bloom filter: the @merkleblock@, the matching
    -- transactions and the filter as the matches updated it
    -- ('Haskoin.Network.Bloom.bloomRelevantBlock' gives the matches and the
    -- filter)
    filteredBlock :: BloomFilter -> BlockHash -> Maybe (MerkleBlock, [Tx], BloomFilter),
    -- | fee rate of a transaction of the mempool, in satoshi per 1000 bytes
    txFeeRate :: TxHash -> Maybe Word64,
    -- | the filters of a @getcfilters@, if the filter index has them
    blockFilters :: GetCFilters -> Maybe [CFilter],
    -- | the answer to a @getcfheaders@, if the filter index has it
    blockFilterHeaders :: GetCFHeaders -> Maybe CFHeaders,
    -- | the answer to a @getcfcheckpt@, if the filter index has it
    blockFilterCheckpoint :: GetCFCheckpt -> Maybe CFCheckpt,
    -- | how many other peers have blocks in flight with known headers,
    -- @nPeersWithValidatedDownloads@ without this peer
    otherValidatedDownloads :: !Int,
    -- | the size limit of the next block, when it differs from the default
    -- of the chain (ABLA, @GetNextBlockSizeLimit@)
    nextBlockSizeLimit :: !(Maybe Word64),
    -- | the node already has the transaction: mempool, orphan pool, recent
    -- rejects or the coins of the tip (@AlreadyHave@ for @MSG_TX@)
    knownTx :: TxHash -> Bool,
    -- | the transaction is in the filter of recent rejects
    recentlyRejected :: TxHash -> Bool,
    -- | a transaction that the node announced to some peer in the last 15
    -- minutes (@mapRelay@)
    relayedTx :: TxHash -> Maybe Tx,
    -- | when a transaction entered the mempool, in seconds
    mempoolTime :: TxHash -> Maybe Int64,
    -- | the node has this double-spend proof, or rejected it
    knownDsProof :: Hash256 -> Bool,
    -- | the payload of a stored double-spend proof, orphans included
    dsProof :: Hash256 -> Maybe ByteString,
    -- | validation of the payload of a @dsproof-beta@ message
    checkDsProof :: ByteString -> DsProofVerdict,
    -- | the most recent block that the node validated, @m_most_recent_block@
    recentBlock :: !(Maybe Block)
  }
  deriving (Generic)

-- | An environment of a node that has only the genesis block and an empty
-- mempool, at the given time, to change with record updates.
defaultEnv :: BlockInfo -> Block -> Micros -> Env
defaultEnv genesis block t =
  Env
    { now = t,
      tip = genesis,
      initialBlockDownload = True,
      lookupBlock = \h -> if h == genesis.hash then Just genesis else Nothing,
      blockAtHeight = \n -> if n == 0 then Just genesis else Nothing,
      headerOf = const Nothing,
      blockData = \h -> if h == genesis.hash then Just block else Nothing,
      checkHeaders = const HeadersUnconnected,
      checkBlock = const BlockMissingParent,
      checkTx = const TxOrphan,
      mempoolTx = const Nothing,
      mempoolTxs = [],
      mempoolMinFee = 1000,
      loadingBlocks = False,
      bestHeader = genesis,
      locatorFrom = \h -> [h],
      ownNonce = const False,
      txRelayInboundFull = False,
      uploadTargetReached = False,
      historicalUploadTargetReached = False,
      inFlightElsewhere = const 0,
      otherBlocksInFlight = 0,
      otherPeersDownloading = 0,
      otherSyncStarted = 0,
      otherPreferredDownload = 0,
      otherProtectedOutbound = 0,
      addressesForPeer = const [],
      localAddress = Nothing,
      privateBroadcastTx = Nothing,
      compactBlockOf = const Nothing,
      initCompact = const CompactFailed,
      fillCompact = \_ _ -> CompactInvalid,
      filteredBlock = \_ _ -> Nothing,
      txFeeRate = const Nothing,
      blockFilters = const Nothing,
      blockFilterHeaders = const Nothing,
      blockFilterCheckpoint = const Nothing,
      otherValidatedDownloads = 0,
      nextBlockSizeLimit = Nothing,
      knownTx = const False,
      recentlyRejected = const False,
      relayedTx = const Nothing,
      mempoolTime = const Nothing,
      knownDsProof = const False,
      dsProof = const Nothing,
      checkDsProof = const (DsProofInvalid "no validation"),
      recentBlock = Nothing
    }

-- | What the mempool says of a double-spend proof
-- (@DoubleSpendProof::validate@ and the checks before it).
data DsProofVerdict
  = -- | valid, and the first proof for its transaction: stored and announced
    DsProofValid
  | -- | the transaction that spends the outpoint already has a proof
    DsProofDuplicate
  | -- | the coin or the transaction that spends it is missing: kept as an
    -- orphan proof
    DsProofOrphan
  | -- | invalid, or the payload does not parse, with the reason
    DsProofInvalid !Text
  deriving (Eq, Show, Read, Generic, NFData)

-- | The randomness of a machine: a SplitMix64 generator, which is small and
-- fast and good enough for timers and nonces. The upstream nodes use their own
-- random sources, so the values never match theirs; the distributions do.
newtype Rng = Rng Word64
  deriving (Eq, Show, Read, Generic, NFData)

-- | The next 64 random bits.
nextWord64 :: Rng -> (Word64, Rng)
nextWord64 (Rng s) =
  let s' = s + 0x9e3779b97f4a7c15
      z1 = (s' `xor` (s' `shiftR` 30)) * 0xbf58476d1ce4e5b9
      z2 = (z1 `xor` (z1 `shiftR` 27)) * 0x94d049bb133111eb
   in (z2 `xor` (z2 `shiftR` 31), Rng s')

-- | A random number from zero to one less than the bound, which must be more
-- than zero.
randomBelow :: Word64 -> Rng -> (Word64, Rng)
randomBelow n g =
  let (w, g') = nextWord64 g
   in (w `mod` n, g')

-- | A delay drawn from an exponential distribution of the given mean, as
-- @rand_exp_duration@ of Bitcoin Core and @PoissonNextSend@ of Bitcoin Cash
-- Node, which both nodes use to time the announcements of transactions and
-- addresses.
poissonDelay :: Micros -> Rng -> (Micros, Rng)
poissonDelay mean g =
  let (w, g') = nextWord64 g
      -- 48 bits of the word make a number in (0, 1], as upstream does.
      u = (fromIntegral (w .&. 0xffffffffffff) + 1) / 281474976710656 :: Double
   in (round (negate (log u) * fromIntegral mean), g')

-- | What the node makes of a compact block when it tries to rebuild the
-- block from its mempool (@ReadStatus@ of @PartiallyDownloadedBlock@).
data CompactVerdict
  = -- | the message is malformed (@READ_STATUS_INVALID@): the peer is at
    -- fault
    CompactInvalid
  | -- | the rebuild failed in a way the peer cannot be blamed for, such as a
    -- collision of short ids (@READ_STATUS_FAILED@)
    CompactFailed
  | -- | the block is whole
    CompactComplete !Block
  | -- | these positions of transactions are missing
    CompactMissing ![Word32]
  deriving (Eq, Show, Read, Generic, NFData)
