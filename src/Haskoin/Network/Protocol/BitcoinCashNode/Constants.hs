{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCashNode.Constants
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- The constants of Bitcoin Cash Node 29.2.0 that decide what a peer sees,
-- each with the file and line of the upstream source that defines it, and the
-- helpers that build a 'Cite' into that source.
--
-- The values are copied, not computed, so that a reader can check each one
-- against the upstream line named next to it. When a new upstream release
-- changes one, the line moves too: the report @doc\/protocol\/bitcoin-cash-node.md@
-- says how to bring both forward together.
module Haskoin.Network.Protocol.BitcoinCashNode.Constants
  ( -- * Citing the source
    netProcessing,
    netCpp,
    netH,
    protocolCpp,

    -- * Protocol versions (@src\/version.h@)
    protocolVersion,
    minPeerProtoVersion,
    bip0031Version,
    noBloomVersion,
    sendHeadersVersion,
    feeFilterVersion,
    shortIdsBlocksVersion,
    invalidCbNoBanVersion,
    featureNegotiationVersion,

    -- * Service bits (@src\/protocol.h@)
    nodeNetwork,
    nodeBloom,
    nodeBitcoinCash,
    nodeNetworkLimited,
    nodeExtVersion,

    -- * Limits
    maxInvSize,
    maxAddrToSend,
    maxLocatorSize,
    maxHeadersResults,
    maxBlocksToAnnounce,
    maxUnconnectingHeaders,
    maxBlocksInTransitPerPeer,
    maxCmpctBlocksInflightPerBlock,
    maxCmpctBlockDepth,
    nodeNetworkLimitedMinBlocks,
    maxRejectMessageLength,
    maxBloomFilterSize,
    maxHashFuncs,
    maxScriptElementSize,
    maxPeerTxAnnouncements,
    maxPeerTxRequestInFlight,
    maxDsProofGetDatas,
    maxGetDataSize,
    maxMoney,
    extVersionMaxSize,
    extVersionMaxKeys,
    maxOutboundPeersToProtect,

    -- * Times
    pingInterval,
    timeoutInterval,
    oldPeerReceiveTimeout,
    blockStallingTimeout,
    headersDownloadTimeoutBase,
    headersDownloadTimeoutPerHeader,
    chainSyncTimeout,
    headersResponseTime,
    staleRelayAge,
    historicalBlockAge,
    nonPrefPeerTxDelay,
    overloadedPeerTxDelay,
    getDataTxInterval,
    avgAddressBroadcastInterval,
    avgLocalAddressBroadcastInterval,
    avgFeeFilterBroadcastInterval,
    maxFeeFilterChangeDelay,
    targetSpacing,

    -- * Address relay
    maxAddrRatePerSecond,
    maxAddrProcessingTokenBucket,

    -- * Inventory types (@src\/protocol.h@)
    msgDoubleSpendProof,

    -- * Commands that the library does not know
    extVersionCommand,
    dsProofCommand,
  )
where

import Data.ByteString (ByteString)
import Data.Int (Int64)
import Data.Text (Text)
import Data.Word (Word32, Word64)
import Haskoin.Network.Protocol.Types (Cite, Micros, cite, seconds)

-- | A place in @src\/net_processing.cpp@, where most decisions are made.
netProcessing :: Int -> Text -> Cite
netProcessing = cite "src/net_processing.cpp"

-- | A place in @src\/net.cpp@: sockets, timeouts, connections.
netCpp :: Int -> Text -> Cite
netCpp = cite "src/net.cpp"

-- | A place in @src\/net.h@.
netH :: Int -> Text -> Cite
netH = cite "src/net.h"

-- | A place in @src\/protocol.cpp@: message headers and service flags.
protocolCpp :: Int -> Text -> Cite
protocolCpp = cite "src/protocol.cpp"

-- | @PROTOCOL_VERSION@, @src\/version.h:11@.
protocolVersion :: Int
protocolVersion = 70016

-- | @MIN_PEER_PROTO_VERSION@, @src\/version.h:17@: older peers are
-- disconnected.
minPeerProtoVersion :: Int
minPeerProtoVersion = 31800

-- | @BIP0031_VERSION@, @src\/version.h:20@: peers above it get pings with a
-- nonce and answer them.
bip0031Version :: Int
bip0031Version = 60000

-- | @NO_BLOOM_VERSION@, @src\/version.h:24@: from this version, Bloom
-- messages to a node that does not offer them are misbehaviour.
noBloomVersion :: Int
noBloomVersion = 70011

-- | @SENDHEADERS_VERSION@, @src\/version.h:28@.
sendHeadersVersion :: Int
sendHeadersVersion = 70012

-- | @FEEFILTER_VERSION@, @src\/version.h:32@.
feeFilterVersion :: Int
feeFilterVersion = 70013

-- | @SHORT_IDS_BLOCKS_VERSION@, @src\/version.h:35@.
shortIdsBlocksVersion :: Int
shortIdsBlocksVersion = 70014

-- | @INVALID_CB_NO_BAN_VERSION@, @src\/version.h:38@: fast compact block
-- announcements go only to peers of this version or later.
invalidCbNoBanVersion :: Int
invalidCbNoBanVersion = 70015

-- | @FEATURE_NEGOTIATION_BEFORE_VERACK_VERSION@, @src\/version.h:47@: the
-- node sends @sendaddrv2@ before its @verack@ to peers of this version.
featureNegotiationVersion :: Int
featureNegotiationVersion = 70016

-- | @NODE_NETWORK@, @src\/protocol.h@.
nodeNetwork :: Word64
nodeNetwork = 1

-- | @NODE_BLOOM@, @src\/protocol.h@.
nodeBloom :: Word64
nodeBloom = 4

-- | @NODE_BITCOIN_CASH@, @src\/protocol.h@.
nodeBitcoinCash :: Word64
nodeBitcoinCash = 32

-- | @NODE_NETWORK_LIMITED@, @src\/protocol.h@.
nodeNetworkLimited :: Word64
nodeNetworkLimited = 1024

-- | @NODE_EXTVERSION@, @src\/protocol.h@.
nodeExtVersion :: Word64
nodeExtVersion = 2048

-- | @MAX_INV_SZ@, @src\/net.h:68@.
maxInvSize :: Int
maxInvSize = 50000

-- | @MAX_ADDR_TO_SEND@, @src\/net.h:75@.
maxAddrToSend :: Int
maxAddrToSend = 1000

-- | @MAX_LOCATOR_SZ@, @src\/net.h:73@.
maxLocatorSize :: Int
maxLocatorSize = 101

-- | @MAX_HEADERS_RESULTS@, @src\/validation.h:111@.
maxHeadersResults :: Int
maxHeadersResults = 2000

-- | @MAX_BLOCKS_TO_ANNOUNCE@, @src\/validation.h:161@.
maxBlocksToAnnounce :: Int
maxBlocksToAnnounce = 8

-- | @MAX_UNCONNECTING_HEADERS@, @src\/validation.h:164@.
maxUnconnectingHeaders :: Int
maxUnconnectingHeaders = 10

-- | @MAX_BLOCKS_IN_TRANSIT_PER_PEER@, @src\/validation.h:100@.
maxBlocksInTransitPerPeer :: Int
maxBlocksInTransitPerPeer = 16

-- | @MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK@, @src\/net_processing.h:61@.
maxCmpctBlocksInflightPerBlock :: Int
maxCmpctBlocksInflightPerBlock = 3

-- | @MAX_CMPCTBLOCK_DEPTH@, @src\/validation.h:116@.
maxCmpctBlockDepth :: Word32
maxCmpctBlockDepth = 5

-- | @NODE_NETWORK_LIMITED_MIN_BLOCKS@, @src\/validation.h:241@.
nodeNetworkLimitedMinBlocks :: Word32
nodeNetworkLimitedMinBlocks = 288

-- | @MAX_REJECT_MESSAGE_LENGTH@, @src\/validation.h:130@.
maxRejectMessageLength :: Int
maxRejectMessageLength = 111

-- | @MAX_BLOOM_FILTER_SIZE@, @src\/bloom.h:18@.
maxBloomFilterSize :: Int
maxBloomFilterSize = 36000

-- | @MAX_HASH_FUNCS@, @src\/bloom.h:19@.
maxHashFuncs :: Word32
maxHashFuncs = 50

-- | @MAX_SCRIPT_ELEMENT_SIZE_LEGACY@, @src\/script\/vm_limits.h:10@: the
-- largest item of a @filteradd@.
maxScriptElementSize :: Int
maxScriptElementSize = 520

-- | @MAX_PEER_TX_ANNOUNCEMENTS@, @src\/net_processing.cpp:104@.
maxPeerTxAnnouncements :: Int
maxPeerTxAnnouncements = 100000

-- | @MAX_PEER_TX_REQUEST_IN_FLIGHT@, @src\/net_processing.cpp:102@.
maxPeerTxRequestInFlight :: Int
maxPeerTxRequestInFlight = 100

-- | @MAX_DSPROOF_GET_DATAS_TO_BATCH@, @src\/net_processing.cpp:146@.
maxDsProofGetDatas :: Int
maxDsProofGetDatas = 5000

-- | @MAX_GETDATA_SZ@, @src\/net_processing.cpp:115@.
maxGetDataSize :: Int
maxGetDataSize = 1000

-- | @MAX_MONEY@ in satoshi, the bound of @MoneyRange@ (@src\/amount.h@).
maxMoney :: Word64
maxMoney = 21000000 * 100000000

-- | @extversion::Message::MaxSize()@, @src\/extversion.h:117@.
extVersionMaxSize :: Int
extVersionMaxSize = 100000

-- | @extversion::Message::MaxNumKeys()@, @src\/extversion.h:120@.
extVersionMaxKeys :: Word64
extVersionMaxKeys = 8192

-- | @MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT@,
-- @src\/net_processing.cpp:73@.
maxOutboundPeersToProtect :: Int
maxOutboundPeersToProtect = 4

-- | @PING_INTERVAL@, @src\/net.h:59@.
pingInterval :: Micros
pingInterval = seconds 120

-- | @TIMEOUT_INTERVAL@, @src\/net.h:64@.
timeoutInterval :: Micros
timeoutInterval = seconds 1200

-- | The receive timeout of peers of version 60000 or less,
-- @src\/net.cpp:1287@.
oldPeerReceiveTimeout :: Micros
oldPeerReceiveTimeout = seconds (90 * 60)

-- | @BLOCK_STALLING_TIMEOUT@, @src\/validation.h:105@.
blockStallingTimeout :: Micros
blockStallingTimeout = seconds 2

-- | @HEADERS_DOWNLOAD_TIMEOUT_BASE@, @src\/net_processing.cpp:66@.
headersDownloadTimeoutBase :: Micros
headersDownloadTimeoutBase = seconds (15 * 60)

-- | @HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER@, @src\/net_processing.cpp:68@.
headersDownloadTimeoutPerHeader :: Micros
headersDownloadTimeoutPerHeader = 1000

-- | @CHAIN_SYNC_TIMEOUT@ in seconds, @src\/net_processing.cpp:79@.
chainSyncTimeout :: Int64
chainSyncTimeout = 20 * 60

-- | @HEADERS_RESPONSE_TIME@ in seconds, @src\/net_processing.cpp:4023@.
headersResponseTime :: Int64
headersResponseTime = 120

-- | @STALE_RELAY_AGE_LIMIT@ in seconds, @src\/net_processing.cpp:96@.
staleRelayAge :: Int64
staleRelayAge = 30 * 24 * 60 * 60

-- | @HISTORICAL_BLOCK_AGE@ in seconds, @src\/net_processing.cpp:99@.
historicalBlockAge :: Int64
historicalBlockAge = 7 * 24 * 60 * 60

-- | @NONPREF_PEER_TX_DELAY@, @src\/net_processing.cpp:106@.
nonPrefPeerTxDelay :: Micros
nonPrefPeerTxDelay = seconds 2

-- | @OVERLOADED_PEER_TX_DELAY@, @src\/net_processing.cpp:108@.
overloadedPeerTxDelay :: Micros
overloadedPeerTxDelay = seconds 2

-- | @GETDATA_TX_INTERVAL@, @src\/net_processing.cpp:110@.
getDataTxInterval :: Micros
getDataTxInterval = seconds 60

-- | @AVG_ADDRESS_BROADCAST_INTERVAL@, @src\/net_processing.cpp:127@.
avgAddressBroadcastInterval :: Micros
avgAddressBroadcastInterval = seconds 30

-- | @AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL@, @src\/net_processing.cpp:123@.
avgLocalAddressBroadcastInterval :: Micros
avgLocalAddressBroadcastInterval = seconds (24 * 60 * 60)

-- | @AVG_FEEFILTER_BROADCAST_INTERVAL@, @src\/net_processing.cpp:131@.
avgFeeFilterBroadcastInterval :: Micros
avgFeeFilterBroadcastInterval = seconds (10 * 60)

-- | @MAX_FEEFILTER_CHANGE_DELAY@, @src\/net_processing.cpp:135@.
maxFeeFilterChangeDelay :: Micros
maxFeeFilterChangeDelay = seconds (5 * 60)

-- | @nPowTargetSpacing@ in seconds: 600 on every chain of Bitcoin Cash Node
-- (@src\/chainparams.cpp@), which the timers of block download use.
targetSpacing :: Int64
targetSpacing = 600

-- | @MAX_ADDR_RATE_PER_SECOND@, @src\/net.h:80@.
maxAddrRatePerSecond :: Double
maxAddrRatePerSecond = 0.1

-- | @MAX_ADDR_PROCESSING_TOKEN_BUCKET@, @src\/net.h:86@.
maxAddrProcessingTokenBucket :: Double
maxAddrProcessingTokenBucket = 1000

-- | @MSG_DOUBLESPENDPROOF@, @src\/protocol.h:453@.
msgDoubleSpendProof :: Word32
msgDoubleSpendProof = 0x94a0

-- | The command of the @extversion@ message, @src\/protocol.cpp:51@.
extVersionCommand :: ByteString
extVersionCommand = "extversion"

-- | The command of the double-spend proof message, @src\/protocol.cpp:52@.
dsProofCommand :: ByteString
dsProofCommand = "dsproof-beta"
