{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCore.Constants
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- The constants of Bitcoin Core 32.1 that the protocol machine of
-- "Haskoin.Network.Protocol.BitcoinCore" uses, each with the name it has
-- upstream, and the helpers that build a t'Cite' into that release.
--
-- They live apart from the rules so that a new release can be checked
-- against one list: a constant that changes upstream changes here, and the
-- rules that read it follow. None of them depends on the network: Bitcoin
-- Core uses the same timeouts, limits and versions on every chain, and what
-- differs by chain is in 'Haskoin.Network.Data.Network'.
module Haskoin.Network.Protocol.BitcoinCore.Constants
  ( -- * Upstream
    upstream,
    netProcessing,
    netCpp,

    -- * Protocol versions
    protocolVersion,
    privateBroadcastVersion,
    initProtoVersion,
    minPeerProtoVersion,
    bip0031Version,
    sendHeadersVersion,
    feeFilterVersion,
    shortIdsBlocksVersion,
    invalidCbNoBanVersion,
    wtxidRelayVersion,
    featureVersion,
    locatorVersion,
    cmpctBlocksVersion,
    txReconciliationVersion,

    -- * Timers
    timeoutInterval,
    defaultPeerConnectTimeout,
    pingInterval,
    privateBroadcastLifetime,
    avgAddressBroadcastInterval,
    avgLocalAddressBroadcastInterval,
    headersDownloadTimeoutBase,
    headersDownloadTimeoutPerHeader,
    headersResponseTime,
    chainSyncTimeout,
    blockStallingTimeoutDefault,
    inboundInventoryBroadcastInterval,
    outboundInventoryBroadcastInterval,
    avgFeeFilterBroadcastInterval,
    maxFeeFilterChangeDelay,

    -- * Limits
    maxInvSz,
    maxGetDataSz,
    maxLocatorSz,
    maxHeadersResults,
    maxBlocksInTransitPerPeer,
    maxBlocksToAnnounce,
    maxCmpctBlockDepth,
    maxBlockTxnDepth,
    maxCmpctBlocksInflightPerBlock,
    maxGetCFiltersSize,
    maxGetCFHeadersSize,
    nodeNetworkLimitedMinBlocks,
    nodeNetworkLimitedAllowConnBlocks,
    maxAddrToSend,
    maxAddrRatePerSecond,
    maxAddrProcessingTokenBucket,
    maxBloomFilterSize,
    maxHashFuncs,
    maxScriptElementSize,
    maxMoney,
    maxPeerTxAnnouncements,
    maxFeatureIdLength,
    maxFeatureDataLength,
    staleRelayAge,
    defaultMinRelayTxFee,
    defaultUserAgent,
    finalAlert,
  )
where

import Data.ByteString (ByteString)
import Data.Bytes.Get (runGetS)
import Data.Bytes.Serial (deserialize)
import Data.Int (Int32, Int64)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Word (Word32, Word64)
import Haskoin.Network.Common (Alert)
import Haskoin.Network.Protocol.Types
import Haskoin.Util (decodeHex)

-- | The release whose source the machine translates.
upstream :: Upstream
upstream =
  Upstream
    { project = "Bitcoin Core",
      release = "32.1",
      tag = "v32.1",
      commit = "f0de87f040621468b956f01f526a43a010310501",
      repository = "https://github.com/bitcoin/bitcoin"
    }

-- | A t'Cite' of @src\/net_processing.cpp@, where nearly every rule lives.
netProcessing :: Int -> Text -> Cite
netProcessing = cite "src/net_processing.cpp"

-- | A t'Cite' of @src\/net.cpp@: transport, inactivity and the sending filter
-- of private broadcast connections.
netCpp :: Int -> Text -> Cite
netCpp = cite "src/net.cpp"

-- | @PROTOCOL_VERSION@, the version that the node advertises
-- (@src\/node\/protocol_version.h@).
protocolVersion :: Int32
protocolVersion = 70017

-- | The version that a private broadcast connection advertises, to look
-- like an older and more common node (@CNode::AdvertisedVersion@,
-- @src\/net.h@).
privateBroadcastVersion :: Int32
privateBroadcastVersion = 70016

-- | @INIT_PROTO_VERSION@: the common version before the peer's @version@.
initProtoVersion :: Int32
initProtoVersion = 209

-- | @MIN_PEER_PROTO_VERSION@: older peers are disconnected.
minPeerProtoVersion :: Int32
minPeerProtoVersion = 31800

-- | @BIP0031_VERSION@: above it, a ping carries a nonce and gets a pong.
bip0031Version :: Int32
bip0031Version = 60000

-- | @SENDHEADERS_VERSION@.
sendHeadersVersion :: Int32
sendHeadersVersion = 70012

-- | @FEEFILTER_VERSION@.
feeFilterVersion :: Int32
feeFilterVersion = 70013

-- | @SHORT_IDS_BLOCKS_VERSION@: the node offers compact blocks from here.
shortIdsBlocksVersion :: Int32
shortIdsBlocksVersion = 70014

-- | @INVALID_CB_NO_BAN_VERSION@: compact blocks may be announced to the
-- peer before they are fully validated.
invalidCbNoBanVersion :: Int32
invalidCbNoBanVersion = 70015

-- | @WTXID_RELAY_VERSION@: @wtxidrelay@, @sendaddrv2@ and @sendtxrcncl@.
wtxidRelayVersion :: Int32
wtxidRelayVersion = 70016

-- | @FEATURE_VERSION@: the @feature@ message of BIP 434.
featureVersion :: Int32
featureVersion = 70017

-- | @CBlockLocator::DUMMY_VERSION@, the version field of the locators that
-- the node sends (@src\/primitives\/block.h@).
locatorVersion :: Word32
locatorVersion = 70016

-- | @CMPCTBLOCKS_VERSION@: the only compact block version (2, with
-- witnesses).
cmpctBlocksVersion :: Word64
cmpctBlocksVersion = 2

-- | @TXRECONCILIATION_VERSION@ of Erlay (BIP 330).
txReconciliationVersion :: Word32
txReconciliationVersion = 1

-- | @TIMEOUT_INTERVAL@, 20 minutes: ping timeout and inactivity.
timeoutInterval :: Micros
timeoutInterval = seconds (20 * 60)

-- | @DEFAULT_PEER_CONNECT_TIMEOUT@, 60 seconds (@-peertimeout@).
defaultPeerConnectTimeout :: Micros
defaultPeerConnectTimeout = seconds 60

-- | @PING_INTERVAL@, 2 minutes.
pingInterval :: Micros
pingInterval = seconds 120

-- | @PRIVATE_BROADCAST_MAX_CONNECTION_LIFETIME@, 3 minutes.
privateBroadcastLifetime :: Micros
privateBroadcastLifetime = seconds 180

-- | @AVG_ADDRESS_BROADCAST_INTERVAL@, 30 seconds. An address fetch
-- connection lives ten times as long.
avgAddressBroadcastInterval :: Micros
avgAddressBroadcastInterval = seconds 30

-- | @AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL@, 24 hours.
avgLocalAddressBroadcastInterval :: Micros
avgLocalAddressBroadcastInterval = seconds 86400

-- | @HEADERS_DOWNLOAD_TIMEOUT_BASE@, 15 minutes.
headersDownloadTimeoutBase :: Micros
headersDownloadTimeoutBase = seconds (15 * 60)

-- | @HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER@, 1 millisecond.
headersDownloadTimeoutPerHeader :: Micros
headersDownloadTimeoutPerHeader = millis 1

-- | @HEADERS_RESPONSE_TIME@, 2 minutes.
headersResponseTime :: Micros
headersResponseTime = seconds 120

-- | @CHAIN_SYNC_TIMEOUT@, 20 minutes.
chainSyncTimeout :: Micros
chainSyncTimeout = seconds (20 * 60)

-- | @BLOCK_STALLING_TIMEOUT_DEFAULT@, 2 seconds. Upstream doubles it, up to
-- 64 seconds, each time it disconnects a peer for stalling, and lets it
-- decay as blocks connect; that is state of the whole node and is not
-- modelled.
blockStallingTimeoutDefault :: Micros
blockStallingTimeoutDefault = seconds 2

-- | @INBOUND_INVENTORY_BROADCAST_INTERVAL@, 5 seconds.
inboundInventoryBroadcastInterval :: Micros
inboundInventoryBroadcastInterval = seconds 5

-- | @OUTBOUND_INVENTORY_BROADCAST_INTERVAL@, 2 seconds.
outboundInventoryBroadcastInterval :: Micros
outboundInventoryBroadcastInterval = seconds 2

-- | @AVG_FEEFILTER_BROADCAST_INTERVAL@, 10 minutes.
avgFeeFilterBroadcastInterval :: Micros
avgFeeFilterBroadcastInterval = seconds 600

-- | @MAX_FEEFILTER_CHANGE_DELAY@, 5 minutes.
maxFeeFilterChangeDelay :: Micros
maxFeeFilterChangeDelay = seconds 300

-- | @MAX_INV_SZ@: entries of an @inv@ or @getdata@.
maxInvSz :: Int
maxInvSz = 50000

-- | @MAX_GETDATA_SZ@: entries of a @getdata@ that the node sends.
maxGetDataSz :: Int
maxGetDataSz = 1000

-- | @MAX_LOCATOR_SZ@.
maxLocatorSz :: Int
maxLocatorSz = 101

-- | @MAX_HEADERS_RESULTS@.
maxHeadersResults :: Int
maxHeadersResults = 2000

-- | @MAX_BLOCKS_IN_TRANSIT_PER_PEER@.
maxBlocksInTransitPerPeer :: Int
maxBlocksInTransitPerPeer = 16

-- | @MAX_BLOCKS_TO_ANNOUNCE@: more new blocks than this go out as @inv@.
maxBlocksToAnnounce :: Int
maxBlocksToAnnounce = 8

-- | @MAX_CMPCTBLOCK_DEPTH@.
maxCmpctBlockDepth :: Int
maxCmpctBlockDepth = 5

-- | @MAX_BLOCKTXN_DEPTH@.
maxBlockTxnDepth :: Int
maxBlockTxnDepth = 10

-- | @MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK@.
maxCmpctBlocksInflightPerBlock :: Int
maxCmpctBlocksInflightPerBlock = 3

-- | @MAX_GETCFILTERS_SIZE@.
maxGetCFiltersSize :: Int
maxGetCFiltersSize = 1000

-- | @MAX_GETCFHEADERS_SIZE@.
maxGetCFHeadersSize :: Int
maxGetCFHeadersSize = 2000

-- | @NODE_NETWORK_LIMITED_MIN_BLOCKS@.
nodeNetworkLimitedMinBlocks :: Int
nodeNetworkLimitedMinBlocks = 288

-- | @NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS@.
nodeNetworkLimitedAllowConnBlocks :: Int64
nodeNetworkLimitedAllowConnBlocks = 144

-- | @MAX_ADDR_TO_SEND@.
maxAddrToSend :: Int
maxAddrToSend = 1000

-- | @MAX_ADDR_RATE_PER_SECOND@.
maxAddrRatePerSecond :: Double
maxAddrRatePerSecond = 0.1

-- | @MAX_ADDR_PROCESSING_TOKEN_BUCKET@.
maxAddrProcessingTokenBucket :: Double
maxAddrProcessingTokenBucket = 1000

-- | @MAX_BLOOM_FILTER_SIZE@ (@src\/common\/bloom.h@).
maxBloomFilterSize :: Int
maxBloomFilterSize = 36000

-- | @MAX_HASH_FUNCS@ (@src\/common\/bloom.h@).
maxHashFuncs :: Word32
maxHashFuncs = 50

-- | @MAX_SCRIPT_ELEMENT_SIZE@: the largest @filteradd@.
maxScriptElementSize :: Int
maxScriptElementSize = 520

-- | @MAX_MONEY@ in satoshi.
maxMoney :: Word64
maxMoney = 2100000000000000

-- | @MAX_PEER_TX_ANNOUNCEMENTS@ (@src\/node\/txdownloadman.h@).
maxPeerTxAnnouncements :: Int
maxPeerTxAnnouncements = 5000

-- | @MAX_FEATUREID_LENGTH@ (@src\/protocol.h@).
maxFeatureIdLength :: Int
maxFeatureIdLength = 80

-- | @MAX_FEATUREDATA_LENGTH@ (@src\/protocol.h@).
maxFeatureDataLength :: Int
maxFeatureDataLength = 512

-- | @STALE_RELAY_AGE_LIMIT@, 30 days, in seconds.
staleRelayAge :: Int64
staleRelayAge = 30 * 24 * 60 * 60

-- | @DEFAULT_MIN_RELAY_TX_FEE@, in satoshi per 1000 virtual bytes.
defaultMinRelayTxFee :: Word64
defaultMinRelayTxFee = 100

-- | The user agent of a node with no @-uacomment@ (@FormatSubVersion@).
defaultUserAgent :: ByteString
defaultUserAgent = "/Satoshi:32.1.0/"

-- | The final @alert@ that the node sends to peers of version 70012 or
-- older (@ProcessMessage@, @src\/net_processing.cpp@): the last message of
-- the retired alert system, which tells old nodes that its key is public.
finalAlert :: Alert
finalAlert =
  either error id . runGetS deserialize . fromMaybe (error "finalAlert: bad hex") . decodeHex $
    "60010000000000000000000000ffffff7f00000000ffffff7ffeffff7f01ffffff7f\
    \00000000ffffff7f00ffffff7f002f555247454e543a20416c657274206b657920\
    \636f6d70726f6d697365642c2075706772616465207265717569726564004630\
    \440220653febd6410f470f6bae11cad19c48413becb1ac2c17f908fd0fd53bdc\
    \3abd5202206d0e9c96fe88d4a0f01ed9dedae2b6f9e00da94cad0fecaae66ecf\
    \689bf71b50"
