{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCashNode.Options
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- The command-line options of Bitcoin Cash Node 29.2.0 that change what a
-- peer sees, with their upstream defaults, and the derived settings of one
-- connection: the permissions as the node expands them, and the services it
-- offers the peer.
--
-- Only options that change the protocol of one connection are here. Options
-- that change validation, such as @-maxreorgdepth@ or @-finalizeheaders@,
-- reach the machine through the verdicts of the t'Env', and options that
-- change decisions across peers, such as @-maxconnections@, through
-- 'Notification's. The rate limiter of @-peerratelimit@ and the random drops
-- of @-dropmessagestest@ have no default and are left out.
--
-- The defaults are the same on the four networks of Bitcoin Cash Node that
-- this library knows, with one exception: the default block size of the
-- chain, which scales the number of transactions announced at a time. That
-- comes from the t'Network' in 'defaultOptions'.
module Haskoin.Network.Protocol.BitcoinCashNode.Options
  ( Options (..),
    defaultOptions,
    effectivePermissions,
    localServices,
    offersBloom,
    whitelistRelayEffective,
    subVersion,
    genesisTime,
  )
where

import Control.DeepSeq (NFData)
import Data.Bits ((.|.))
import Data.ByteString (ByteString)
import Data.ByteString.Char8 qualified as C
import Data.Int (Int64)
import Data.Set qualified as Set
import Data.Word (Word64)
import GHC.Generics (Generic)
import Haskoin.Block.Common (BlockHeader (..))
import Haskoin.Network.Data (Network (..))
import Haskoin.Network.Protocol.BitcoinCashNode.Constants
import Haskoin.Network.Protocol.Types

-- | The options of a node that change the protocol of a connection. Each
-- field names its upstream option and where it is read.
data Options = Options
  { -- | the network; one machine per network is these rules with the
    -- defaults of 'defaultOptions'
    network :: !Network,
    -- | @-enablebip61@, default true (@src\/net_processing.h:58@): send
    -- @reject@ messages
    enableBip61 :: !Bool,
    -- | @-banscore@, default 100 (@src\/validation.h:150@): the score at which
    -- a peer is discouraged, read at each call of @Misbehaving@
    -- (@src\/net_processing.cpp:906@)
    banScore :: !Int,
    -- | @-peertimeout@ in seconds, default 60 (@src\/net.h:104@): no
    -- inactivity check until a connection is this old, and the handshake must
    -- end within it
    peerTimeout :: !Int64,
    -- | @-blocksonly@, default false (@src\/net.h:102@): the node does not
    -- relay transactions, says so in its @version@, and drops those it gets
    blocksOnly :: !Bool,
    -- | @-peerbloomfilters@, default true (@src\/validation.h:166@): offer
    -- @NODE_BLOOM@
    peerBloomFilters :: !Bool,
    -- | @-useextversion@, default false (@src\/extversion.h:24@): offer
    -- @NODE_EXTVERSION@ and use the @extversion@ handshake with peers that
    -- offer it too
    useExtVersion :: !Bool,
    -- | @-whitelistrelay@: 'Nothing' for the upstream default, which is true
    -- unless @-blocksonly@ soft-sets it false and @-whitelistforcerelay@
    -- soft-sets it true again (@src\/init.cpp:1504-1520@)
    whitelistRelay :: !(Maybe Bool),
    -- | @-whitelistforcerelay@, default false (@src\/net.h:53@)
    whitelistForceRelay :: !Bool,
    -- | @-rejectsubversion@, none by default: peers whose user agent contains
    -- one of these, before its first parenthesis, are disconnected
    -- (@src\/net_processing.cpp:2133-2153@)
    rejectSubVersions :: ![ByteString],
    -- | @-uacomment@, none by default: comments in our user agent
    uaComments :: ![ByteString],
    -- | @-listen@, default true (@src\/net.h:94@): the node advertises its own
    -- address only when it listens
    listen :: !Bool,
    -- | @-feefilter@, default true (@src\/validation.h:155@): send @feefilter@
    feeFilter :: !Bool,
    -- | @-minrelaytxfee@ in satoshi per 1000 bytes, default 1000
    -- (@src\/validation.h:68@): the floor of the @feefilter@ we send
    minRelayTxFee :: !Word64,
    -- | @-txbroadcastinterval@ in milliseconds, default 500
    -- (@src\/net_processing.h:32@): the mean time between announcements of
    -- transactions; 0 announces at every pass
    txBroadcastInterval :: !Int64,
    -- | @-txbroadcastrate@ in transactions per second per MB of block size,
    -- default 7 (@src\/net_processing.h:38@)
    txBroadcastRate :: !Double,
    -- | @-doublespendproof@, default true (@src\/dsproof\/dsproof.cpp:17@)
    doubleSpendProof :: !Bool,
    -- | @-prune@ other than 0, default off: the node does not offer
    -- @NODE_NETWORK@ (@src\/init.cpp:2806-2807@)
    prune :: !Bool,
    -- | the default block size of the chain in bytes
    -- (@nDefaultConsensusBlockSize@, @src\/chainparams.cpp@), the size
    -- limit of the next block when the t'Env' gives none
    defaultBlockSize :: !Word64
  }
  deriving (Eq, Show, Generic, NFData)

-- | The options of a node started with none on a network. They are the same
-- on all networks but for 'defaultBlockSize', which is 32 MB on main,
-- testnet3 and regtest, and 2 MB on testnet4
-- (@src\/chainparams.cpp:158,417,642,1181@).
defaultOptions :: Network -> Options
defaultOptions net =
  Options
    { network = net,
      enableBip61 = True,
      banScore = 100,
      peerTimeout = 60,
      blocksOnly = False,
      peerBloomFilters = True,
      useExtVersion = False,
      whitelistRelay = Nothing,
      whitelistForceRelay = False,
      rejectSubVersions = [],
      uaComments = [],
      listen = True,
      feeFilter = True,
      minRelayTxFee = 1000,
      txBroadcastInterval = 500,
      txBroadcastRate = 7,
      doubleSpendProof = True,
      prune = False,
      defaultBlockSize = fromIntegral net.maxBlockSize
    }

-- | The value of @-whitelistrelay@ after the soft settings of
-- @src\/init.cpp:1504-1520@: @-blocksonly@ turns it off, and
-- @-whitelistforcerelay@ turns it on again.
whitelistRelayEffective :: Options -> Bool
whitelistRelayEffective o = case o.whitelistRelay of
  Just b -> b
  Nothing
    | o.whitelistForceRelay -> True
    | otherwise -> not o.blocksOnly

-- | The permissions of a peer as @CConnman::AcceptConnection@ sets them
-- (@src\/net.cpp:1036-1052@, @src\/net.cpp:1130@).
--
-- * Only inbound peers have permissions: the node consults @-whitelist@ and
--   @-whitebind@ only when it accepts a connection, so an outbound peer,
--   manual ones included, has none.
-- * An entry without flags ('PermImplicit') becomes @noban@ and @mempool@,
--   with @relay@ if @-whitelistrelay@ and @forcerelay@ if
--   @-whitelistforcerelay@.
-- * @forcerelay@ implies @relay@: its bits include those of @relay@
--   (@src\/net_permissions.h@).
-- * There is no @download@ permission in Bitcoin Cash Node, so
--   'PermDownload' is dropped.
effectivePermissions :: Options -> Setup -> Permissions
effectivePermissions o s
  | isOutbound s.connectionType = Set.empty
  | otherwise = forceImpliesRelay (Set.delete PermDownload implicit)
  where
    given = s.permissions
    implicit
      | PermImplicit `Set.member` given =
          Set.unions
            [ Set.delete PermImplicit given,
              Set.fromList [PermNoBan, PermMempool],
              if whitelistRelayEffective o then Set.singleton PermRelay else Set.empty,
              if o.whitelistForceRelay then Set.singleton PermForceRelay else Set.empty
            ]
      | otherwise = given
    forceImpliesRelay ps
      | PermForceRelay `Set.member` ps = Set.insert PermRelay ps
      | otherwise = ps

-- | The services the node offers this peer (@nLocalServices@):
-- @NODE_NETWORK | NODE_NETWORK_LIMITED@ (@src\/init.cpp:1568@), without
-- @NODE_NETWORK@ when pruned (@src\/init.cpp:2806-2807@), @NODE_BLOOM@ with
-- @-peerbloomfilters@ (@src\/init.cpp:2005-2007@), always
-- @NODE_BITCOIN_CASH@ (@src\/init.cpp:2012@), @NODE_EXTVERSION@ with
-- @-useextversion@ (@src\/init.cpp:2016-2018@), and @NODE_BLOOM@ for an
-- inbound peer with the @bloomfilter@ permission (@src\/net.cpp:1123-1126@).
localServices :: Options -> Permissions -> Word64
localServices o perms =
  foldr
    (.|.)
    nodeBitcoinCash
    [ if o.prune then 0 else nodeNetwork,
      nodeNetworkLimited,
      if offersBloom o perms then nodeBloom else 0,
      if o.useExtVersion then nodeExtVersion else 0
    ]

-- | The node offers @NODE_BLOOM@ to this peer (@pfrom->GetLocalServices() &
-- NODE_BLOOM@).
offersBloom :: Options -> Permissions -> Bool
offersBloom o perms = o.peerBloomFilters || PermBloomFilter `Set.member` perms

-- | The sub-version string that the node puts in its @version@, built as
-- @FormatSubVersion@ does (@src\/clientversion.cpp:103-118@): the client
-- name and release between slashes, with the @-uacomment@ values in
-- parentheses.
subVersion :: Options -> ByteString
subVersion o =
  mconcat
    [ "/Bitcoin Cash Node:29.2.0",
      case o.uaComments of
        [] -> ""
        cs -> "(" <> C.intercalate "; " cs <> ")",
      "/"
    ]

-- | The time of the genesis block of the network, in seconds: a @version@
-- with an earlier time is misbehaviour (@src\/net_processing.cpp:2289@).
genesisTime :: Options -> Int64
genesisTime o = fromIntegral o.network.genesisHeader.timestamp
