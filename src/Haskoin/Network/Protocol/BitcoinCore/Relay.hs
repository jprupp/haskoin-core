{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCore.Relay
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Transactions and addresses on a connection to Bitcoin Core 32.1:
-- @inv@ (with its block entries handed to
-- "Haskoin.Network.Protocol.BitcoinCore.Blocks"), @getdata@, @tx@,
-- @notfound@, @mempool@, @feefilter@, the BIP 37 filter messages, @addr@,
-- @addrv2@ and @getaddr@, and what the node sends on its own: the trickle
-- of transaction announcements, address relay and the fee filter.
--
-- Two facts of 32.1 shape this module. No transaction is ever punished:
-- an invalid one only goes into the node's reject filters, and the only
-- penalties of relay are oversized @inv@, @getdata@ and @addr@ messages
-- and abuse of Bloom filters. And the pace of announcements is set by two
-- token buckets shared by all inbound and all outbound peers
-- (@InvToSendBucket@); the machine leaves those to the node, which tells
-- each peer what to announce with 'TxAccepted', and keeps only the
-- per-peer trickle timer.
--
-- Other simplifications, each because the decision spans peers or needs
-- the mempool's internals: the transaction download (@TxDownloadManager@,
-- with its delays, limits and orphan handling) is the node's, which asks
-- this peer for a transaction with 'RequestTx'; a transaction in the
-- mempool is served to any peer, while upstream serves only those that
-- entered the mempool before the last announcement to that peer; queued
-- announcements are sorted by fee rate, where upstream sorts by mining
-- score; and an address that arrives is handed to the node with 'Process'
-- instead of being relayed here, since the node picks the peers that
-- relay it.
module Haskoin.Network.Protocol.BitcoinCore.Relay
  ( -- * Messages
    handleInv,
    handleGetData,
    handleTx,
    handleNotFound,
    handleMempool,
    handleFeeFilter,
    handleFilterLoad,
    handleFilterAdd,
    handleFilterClear,
    handleAddrs,
    handleGetAddr,

    -- * Sending
    sendTxTrickle,
    maybeSendAddr,
    maybeSendFeeFilter,
    feeFilterBuckets,
    roundFeeFilter,

    -- * Notifications
    txAccepted,
    relayAddress,
    requestTx,
  )
where

import Control.Monad (forM_, unless, when)
import Data.Bits ((.&.))
import Data.List (sortOn)
import Data.Maybe (isJust, mapMaybe)
import Data.Ord (Down (..))
import Data.Set qualified as Set
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Word (Word16, Word64, Word8)
import Haskoin.Block.Common (BlockHash (..))
import Haskoin.Network.Bloom
  ( BloomFilter (..),
    FilterAdd (..),
    FilterLoad (..),
    bloomInsert,
    bloomRelevantUpdate,
  )
import Haskoin.Network.Common
  ( AddrV2 (..),
    FeeFilter (..),
    GetData (..),
    Inv (..),
    InvType (..),
    InvVector (..),
    NetworkAddressV2 (..),
    NotFound (..),
    addressNetworkId,
    addressNetworkLength,
    nodeNetwork,
    nodeNetworkLimited,
    nodeWitness,
  )
import Haskoin.Network.Common qualified as C
import Haskoin.Network.Message (Message (..))
import Haskoin.Network.Protocol.BitcoinCore.Blocks (blockInvs, getBlockData)
import Haskoin.Network.Protocol.BitcoinCore.Constants
import Haskoin.Network.Protocol.BitcoinCore.Handshake
  ( maybeDisconnectForTxRelayCapacity,
    maybeSendPing,
    rejectIncomingTxs,
    setupAddressRelay,
  )
import Haskoin.Network.Protocol.BitcoinCore.Machine
import Haskoin.Network.Protocol.BitcoinCore.State
import Haskoin.Network.Protocol.Types
import Haskoin.Transaction.Common (OutPoint (..), Tx (..), TxHash (..), TxIn (..), txHash, txWitnessHash)

-- | Transaction entries of an inventory (@IsGenTxMsg@).
isTxInv :: InvType -> Bool
isTxInv t = t `elem` [InvTx, InvWTx, InvWitnessTx]

-- | The hash under which the peer knows a transaction: the wtxid if it
-- relays by wtxid, else the txid.
knownHash :: State -> Tx -> TxHash
knownHash s tx = if s.wtxidRelay then txWitnessHash tx else txHash tx

-- | @AddKnownTx@.
addKnownTx :: TxHash -> M ()
addKnownTx h = modifyTxRelay $ \r -> r {knownTxs = Set.insert h r.knownTxs}

-- | @inv@ (line 4347). More than 50,000 entries is misbehaviour. The
-- entries of the type the peer does not relay by (txid or wtxid) are
-- skipped. A transaction entry from a peer that was told not to send
-- transactions closes the connection at once; others go to the node's
-- transaction download, except in initial block download.
handleInv :: Inv -> M ()
handleInv (Inv ivs) = do
  when (length ivs > maxInvSz) $ do
    let c = netProcessing 4352 "inv message size"
    misbehaving c
    ignore c
    stop
  rejects <- rejectIncomingTxs
  s <- getS
  e <- env
  let relevant iv
        | s.wtxidRelay = iv.invType /= InvTx
        | otherwise = iv.invType /= InvWTx
      go _ blocks [] = return blocks
      go seen blocks (iv : rest)
        | not (relevant iv) = go seen blocks rest
        | iv.invType == InvBlock = go seen (BlockHash iv.invHash : blocks) rest
        | isTxInv iv.invType = do
            when rejects $ do
              blockInvs (reverse blocks)
              disconnect ProtocolViolation $
                netProcessing 4394 "transaction inv sent in violation of protocol"
              stop
            let key = (iv.invType == InvWTx, iv.invHash)
            if Set.member key seen
              then go seen blocks rest
              else do
                addKnownTx (TxHash iv.invHash)
                unless e.initialBlockDownload $
                  process "transaction announcement" $ netProcessing 4404 "AddTxAnnouncement"
                go (Set.insert key seen) blocks rest
        | otherwise = do
            ignore $ netProcessing 4408 "Unknown inv type"
            go seen blocks rest
  blocks <- go Set.empty [] ivs
  blockInvs (reverse blocks)

-- | @getdata@ (line 4443) and @ProcessGetData@ (line 2764). On a private
-- broadcast connection, only the one transaction that the node announced
-- may be asked for. Elsewhere the entries are served in order: a run of
-- transactions, with one @notfound@ for those the node lacks, then one
-- block, then the next run. Upstream spreads this over several passes when
-- the send buffer fills; the machine serves all at once.
handleGetData :: GetData -> M ()
handleGetData (GetData ivs) = do
  when (length ivs > maxInvSz) $ do
    let c = netProcessing 4448 "getdata message size"
    misbehaving c
    ignore c
    stop
  pb <- isPrivateBroadcast
  when pb $ do
    privateGetData ivs
    stop
  serve ivs
  where
    serve [] = return ()
    serve items = do
      let (txs, rest) = span (isTxInv . (.invType)) items
      missing <- concat <$> mapM serveTx txs
      unless (null missing) $
        send (MNotFound (NotFound missing)) $ netProcessing 2831 "notfound"
      case rest of
        [] -> return ()
        (iv : more) -> do
          when (iv.invType `elem` [InvBlock, InvWitnessBlock, InvMerkleBlock, InvCompactBlock]) $
            scoped (getBlockData iv)
          s <- getS
          unless s.disconnected (serve more)
    serveTx iv = do
      s <- getS
      e <- env
      case s.txRelay of
        Nothing -> return []
        Just _ -> case e.mempoolTx (TxHash iv.invHash) of
          Just tx -> do
            let tx' = if iv.invType == InvTx then tx {witness = []} else tx
            send (MTx tx') $ netProcessing 2793 "tx"
            return []
          Nothing -> return [iv]

-- | The @getdata@ of a private broadcast connection (line 4458): exactly
-- the announced transaction, by txid, gets the transaction and a ping
-- whose pong confirms the delivery. Anything else closes the connection.
privateGetData :: [InvVector] -> M ()
privateGetData ivs = do
  s <- getS
  e <- env
  case (s.privateTx, e.privateBroadcastTx) of
    (Just h, Just tx)
      | [iv] <- ivs, iv.invType == InvTx, TxHash iv.invHash == h -> do
          send (MTx tx) $ netProcessing 4473 "private broadcast: tx"
          modifyS $ \st -> st {pingQueued = True}
          maybeSendPing
      | otherwise ->
          disconnect ProtocolViolation $ netProcessing 4480 "got an unexpected GETDATA message"
    _ -> disconnect ProtocolViolation $ netProcessing 4463 "got GETDATA without sending an INV"

-- | @tx@ (line 4708). From a peer told not to send transactions it closes
-- the connection; in initial block download it is dropped. Otherwise the
-- mempool judges it, and whatever the verdict the peer is not punished.
-- A peer with 'PermForceRelay' gets a transaction the node already has
-- relayed again.
handleTx :: Tx -> M ()
handleTx tx = do
  rejects <- rejectIncomingTxs
  when rejects $ do
    disconnect ProtocolViolation $ netProcessing 4711 "transaction sent in violation of protocol"
    stop
  e <- env
  when e.initialBlockDownload $ do
    ignore $ netProcessing 4718 "transaction during initial block download"
    stop
  s <- getS
  addKnownTx (knownHash s tx)
  case e.checkTx tx of
    TxAlreadyKnown
      | hasPermission PermForceRelay s ->
          if isJust (e.mempoolTx (txHash tx))
            then process "force relay" $ netProcessing 4749 "Force relaying tx"
            else ignore $ netProcessing 4744 "Not relaying non-mempool transaction from forcerelay peer"
      | otherwise -> ignore $ netProcessing 4738 "transaction already known: not validated"
    TxAcceptedToMempool ->
      process "transaction accepted" $ netProcessing 4769 "ProcessValidTx"
    TxOrphan -> do
      let parents = [p.hash | i <- tx.inputs, let p = i.outpoint]
      forM_ parents addKnownTx
      process "orphan transaction: parents requested" $ netProcessing 4773 "ProcessInvalidTx (missing inputs)"
    TxPolicyReject _ ->
      process "transaction rejected" $ netProcessing 4773 "ProcessInvalidTx"
    TxConsensusInvalid _ ->
      process "transaction rejected" $ netProcessing 4773 "ProcessInvalidTx"

-- | @notfound@ (line 5343): the transaction entries mark the node's
-- requests to this peer as failed, so that another peer is asked. Never a
-- penalty.
handleNotFound :: NotFound -> M ()
handleNotFound (NotFound ivs)
  | length ivs <= maxPeerTxAnnouncements + maxBlocksInTransitPerPeer
      && any (isTxInv . (.invType)) ivs =
      process "transaction requests failed" $ netProcessing 5355 "ReceivedNotFound"
  | otherwise = ignore $ netProcessing 5347 "notfound without transactions"

-- | @mempool@ of BIP 35 (line 5187): allowed when the node offers Bloom
-- filters to the peer or the peer has 'PermMempool'. A refused request
-- closes the connection, unless the peer has 'PermNoBan'. The answer goes
-- out at the next trickle.
handleMempool :: M ()
handleMempool = do
  s <- getS
  o <- opts
  e <- env
  let bloom = s.ourServices .&. C.nodeBloom /= 0
      mempoolPerm = hasPermission PermMempool s
      noban = hasPermission PermNoBan s
  when (not bloom && not mempoolPerm) $ do
    if noban
      then ignore $ netProcessing 5197 "mempool request with bloom filters disabled (noban)"
      else disconnect ProtocolViolation $ netProcessing 5195 "mempool request with bloom filters disabled"
    stop
  when (o.maxUploadTarget > 0 && e.uploadTargetReached && not mempoolPerm) $ do
    if noban
      then ignore $ netProcessing 5207 "mempool request with bandwidth limit reached (noban)"
      else disconnect Resources $ netProcessing 5205 "mempool request with bandwidth limit reached"
    stop
  modifyTxRelay $ \r -> r {sendMempool = True}

-- | @feefilter@ of BIP 133 (line 5316): kept when it is a valid amount.
handleFeeFilter :: FeeFilter -> M ()
handleFeeFilter (FeeFilter rate)
  | rate <= maxMoney = modifyTxRelay $ \r -> r {feeFilterReceived = rate}
  | otherwise = ignore $ netProcessing 5319 "feefilter out of range"

-- | Whether the node offers @NODE_BLOOM@ to the peer.
offersBloom :: State -> Bool
offersBloom s = s.ourServices .&. C.nodeBloom /= 0

-- | @filterload@ of BIP 37 (line 5242). Without @NODE_BLOOM@ offered, it
-- closes the connection, even for a peer with 'PermNoBan'. A filter over
-- 36,000 bytes or 50 hash functions is misbehaviour. A loaded filter turns
-- transaction relay on.
handleFilterLoad :: FilterLoad -> M ()
handleFilterLoad (FilterLoad bf) = do
  s <- getS
  unless (offersBloom s) $ do
    disconnect ProtocolViolation $
      netProcessing 5245 "filterload received despite not offering bloom services"
    stop
  if length bf.array > maxBloomFilterSize || bf.functions > maxHashFuncs
    then do
      let c = netProcessing 5254 "too-large bloom filter"
      misbehaving c
      ignore c
    else case s.txRelay of
      Nothing -> ignore $ netProcessing 5255 "filterload without transaction relay"
      Just _ -> do
        modifyTxRelay $ \r -> r {bloomFilter = Just bf, relayTxs = True}
        modifyS $ \st -> st {relaysTxs = True}
        _ <- maybeDisconnectForTxRelayCapacity
        return ()

-- | @filteradd@ (line 5268): data over 520 bytes, or no filter loaded, is
-- misbehaviour.
handleFilterAdd :: FilterAdd -> M ()
handleFilterAdd (FilterAdd bytes) = do
  s <- getS
  unless (offersBloom s) $ do
    disconnect ProtocolViolation $
      netProcessing 5271 "filteradd received despite not offering bloom services"
    stop
  let bad = do
        let c = netProcessing 5291 "bad filteradd message"
        misbehaving c
        ignore c
  if B.length bytes > maxScriptElementSize
    then bad
    else case s.txRelay of
      Nothing -> return ()
      Just r -> case r.bloomFilter of
        Nothing -> bad
        Just bf -> modifyTxRelay $ \x -> x {bloomFilter = Just (bloomInsert bf bytes)}

-- | @filterclear@ (line 5296): drop the filter and relay every
-- transaction.
handleFilterClear :: M ()
handleFilterClear = do
  s <- getS
  unless (offersBloom s) $ do
    disconnect ProtocolViolation $
      netProcessing 5299 "filterclear received despite not offering bloom services"
    stop
  case s.txRelay of
    Nothing -> ignore $ netProcessing 5303 "filterclear without transaction relay"
    Just _ -> do
      modifyTxRelay $ \r -> r {bloomFilter = Nothing, relayTxs = True}
      modifyS $ \st -> st {relaysTxs = True}
      _ <- maybeDisconnectForTxRelayCapacity
      return ()

-- | The key of an address in the known set.
addrKey :: NetworkAddressV2 -> (Word8, ByteString, Word16)
addrKey a = (addressNetworkId a.network, a.address, a.port)

-- | @ProcessAddrs@ (line 5972), for @addr@ and @addrv2@. No address relay
-- with block-relay-only and feeler connections. More than 1,000 addresses
-- is misbehaviour. A token bucket, refilled at 0.1 a second, limits how
-- many are processed, unless the peer has 'PermAddr'. An address fetch
-- connection is done once it gets more than one address.
handleAddrs :: Bool -> [NetworkAddressV2] -> M ()
handleAddrs v2 addrs = do
  ok <- setupAddressRelay
  unless ok $ do
    ignore $ netProcessing 5978 "ignoring addr message from block-relay-only or feeler peer"
    stop
  when (length addrs > maxAddrToSend) $ do
    let c =
          netProcessing 5984 $
            if v2 then "addrv2 message size" else "addr message size"
    misbehaving c
    ignore c
    stop
  t <- now
  s <- getS
  let elapsed = max 0 (fromIntegral (t - s.addrTokensAt) / 1000000) :: Double
      bucket0
        | s.addrTokens < maxAddrProcessingTokenBucket =
            min maxAddrProcessingTokenBucket (s.addrTokens + elapsed * maxAddrRatePerSecond)
        | otherwise = s.addrTokens
      rateLimited = not (hasPermission PermAddr s)
      step' (bucket, acc) a
        | bucket < 1 && rateLimited = (bucket, acc)
        | bucket < 1 = (bucket, a : acc)
        | otherwise = (bucket - 1, a : acc)
      (bucket1, taken) = foldl step' (bucket0, []) addrs
      useful a =
        a.services .&. (nodeNetwork + nodeNetworkLimited) /= 0
          || a.services .&. (nodeNetwork + nodeWitness) == nodeNetwork + nodeWitness
      kept = filter useful (reverse taken)
  putS
    s
      { addrTokens = bucket1,
        addrTokensAt = t,
        addrKnown = foldr (Set.insert . addrKey) s.addrKnown kept,
        getAddrSent = if length addrs < 1000 then False else s.getAddrSent
      }
  unless (null kept) $
    process "addresses to the address manager" $ netProcessing 6049 "addrman Add"
  s' <- getS
  when (s'.connectionType == AddrFetch && length addrs > 1) $
    disconnect Done $ netProcessing 6055 "addrfetch connection completed"

-- | @getaddr@ (line 5151): answered once, and only for an inbound peer.
-- The answer, from the node's cache unless the peer has 'PermAddr', goes
-- out with the next address send.
handleGetAddr :: M ()
handleGetAddr = do
  s <- getS
  e <- env
  when (s.connectionType /= Inbound) $ do
    ignore $ netProcessing 5158 "Ignoring getaddr from an outbound connection"
    stop
  _ <- setupAddressRelay
  when s.getAddrRecvd $ do
    ignore $ netProcessing 5169 "Ignoring repeated getaddr"
    stop
  modifyS $ \st -> st {getAddrRecvd = True, addrsToSend = []}
  forM_ (e.addressesForPeer (hasPermission PermAddr s)) pushAddress

-- | Whether an address can go to the peer: addresses that the old format
-- cannot carry go only to peers that sent @sendaddrv2@ (@IsAddrCompatible@).
addrCompatible :: State -> NetworkAddressV2 -> Bool
addrCompatible s a = s.wantsAddrV2 || isJust (C.fromNetworkAddressV2 a)

-- | @PushAddress@: queue an address unless the peer knows it or cannot
-- take it; a full queue replaces a random entry.
pushAddress :: NetworkAddressV2 -> M ()
pushAddress a = do
  s <- getS
  let valid = maybe True (== fromIntegral (lengthOf a)) (addressNetworkLength a.network)
  when (valid && not (Set.member (addrKey a) s.addrKnown) && addrCompatible s a) $
    if length s.addrsToSend >= maxAddrToSend
      then do
        i <- random (randomBelow (fromIntegral (length s.addrsToSend)))
        let (before, after) = splitAt (fromIntegral i) s.addrsToSend
        modifyS $ \st -> st {addrsToSend = before ++ [a] ++ drop 1 after}
      else modifyS $ \st -> st {addrsToSend = st.addrsToSend ++ [a]}
  where
    lengthOf x = B.length x.address

-- | @MaybeSendAddr@ (line 5740): with address relay on, the node's own
-- address about once a day (at once the first time, in a message of its
-- own), and the queue of addresses about every 30 seconds, as @addrv2@ to
-- a peer that asked for it and @addr@ otherwise.
maybeSendAddr :: M ()
maybeSendAddr = do
  s <- getS
  o <- opts
  e <- env
  t <- now
  when s.addrRelay $ do
    when (o.listen && not e.initialBlockDownload && s.nextLocalAddrSend < t) $ do
      when (s.nextLocalAddrSend /= 0) $ modifyS $ \st -> st {addrKnown = Set.empty}
      forM_ e.localAddress $ \la0 -> do
        let la = la0 {services = s.ourServices, time = fromIntegral (t `div` 1000000)}
        if s.nextLocalAddrSend == 0
          then when (addrCompatible s la) $ sendAddrs [la] $ netProcessing 5767 "self-announcement"
          else pushAddress la
      d <- random (poissonDelay avgLocalAddressBroadcastInterval)
      modifyS $ \st -> st {nextLocalAddrSend = t + d}
    s1 <- getS
    when (t > s1.nextAddrSend) $ do
      d <- random (poissonDelay avgAddressBroadcastInterval)
      let fresh = go s1.addrKnown s1.addrsToSend
          go _ [] = []
          go known (a : rest)
            | Set.member (addrKey a) known = go known rest
            | otherwise = a : go (Set.insert (addrKey a) known) rest
          known' = foldr (Set.insert . addrKey) s1.addrKnown s1.addrsToSend
      modifyS $ \st -> st {nextAddrSend = t + d, addrKnown = known', addrsToSend = []}
      unless (null fresh) $ sendAddrs fresh $ netProcessing 5805 "addr"
  where
    sendAddrs as c = do
      s <- getS
      if s.wantsAddrV2
        then send (MAddrV2 (AddrV2 as)) c
        else send (MAddr (C.Addr (mapMaybe C.fromNetworkAddressV2 as))) c

-- | The fee filter buckets (@MakeFeeSet@ in
-- @src\/policy\/fees\/block_policy_estimator.cpp@): 0, then 50 satoshi per
-- 1000 virtual bytes rising by a tenth up to 10,000,000.
feeFilterBuckets :: [Double]
feeFilterBuckets = 0 : takeWhile (<= 1e7) (iterate (* 1.1) 50)

-- | @FeeFilterRounder::round@: the first bucket at or above the fee rate,
-- or, two times in three, the bucket below it, so that the filter does not
-- reveal the mempool exactly.
roundFeeFilter :: Word64 -> Rng -> (Word64, Rng)
roundFeeFilter x g =
  let (r, g') = nextWord64 g
      above = dropWhile (< fromIntegral x) feeFilterBuckets
      below = takeWhile (< fromIntegral x) feeFilterBuckets
      pick = case above of
        [] -> last feeFilterBuckets
        (a : _)
          | not (null below) && (r .&. 0xffffffff) `mod` 3 /= 0 -> last below
          | otherwise -> a
   in (truncate pick, g')

-- | @MaybeSendFeefilter@ (line 5838): about every 10 minutes, the minimum
-- fee rate of the mempool, rounded, and the maximum during initial block
-- download. Not in blocks-only mode, nor to a peer with 'PermForceRelay',
-- nor on a block-relay-only connection.
maybeSendFeeFilter :: M ()
maybeSendFeeFilter = do
  s <- getS
  o <- opts
  e <- env
  t <- now
  let skip =
        o.blocksOnly
          || s.commonVersion < feeFilterVersion
          || hasPermission PermForceRelay s
          || s.connectionType == BlockRelayOnly
  unless skip $ do
    let maxFilter = truncate (last feeFilterBuckets) :: Word64
        current = if e.initialBlockDownload then maxMoney else e.mempoolMinFee
    when (not e.initialBlockDownload && s.feeFilterSent == maxFilter) $
      modifyS $ \st -> st {nextFeeFilter = 0}
    s1 <- getS
    if t > s1.nextFeeFilter
      then do
        rounded <- random (roundFeeFilter current)
        let toSend = max rounded o.minRelayTxFee
        when (toSend /= s1.feeFilterSent) $ do
          send (MFeeFilter (FeeFilter toSend)) $ netProcessing 5867 "feefilter"
          modifyS $ \st -> st {feeFilterSent = toSend}
        d <- random (poissonDelay avgFeeFilterBroadcastInterval)
        modifyS $ \st -> st {nextFeeFilter = t + d}
      else
        when
          ( t + maxFeeFilterChangeDelay < s1.nextFeeFilter
              && ( current < 3 * s1.feeFilterSent `div` 4
                     || current > 4 * s1.feeFilterSent `div` 3
                 )
          )
          $ do
            d <- random (randomBelow (fromIntegral maxFeeFilterChangeDelay))
            modifyS $ \st -> st {nextFeeFilter = t + fromIntegral d}

-- | The transaction part of the trickle (lines 6327 to 6436): when the
-- timer of the peer fires (always, for a peer with 'PermNoBan'), the
-- answer to @mempool@ and the queued transactions, less those under the
-- peer's fee filter, those it knows and those its Bloom filter rejects.
-- Returns the entries for the @inv@, which the caller sends after the
-- block entries.
sendTxTrickle :: M [InvVector]
sendTxTrickle = do
  s <- getS
  e <- env
  t <- now
  case s.txRelay of
    Nothing -> return []
    Just r0 -> do
      fire <-
        if r0.nextInvSend < t
          then do
            let mean
                  | s.connectionType == Inbound = inboundInventoryBroadcastInterval
                  | otherwise = outboundInventoryBroadcastInterval
            d <- random (poissonDelay mean)
            modifyTxRelay $ \r -> r {nextInvSend = t + d}
            return True
          else return (hasPermission PermNoBan s)
      if not fire
        then return []
        else do
          unless r0.relayTxs $ modifyTxRelay $ \r -> r {toSend = []}
          mempoolInvs <-
            if r0.sendMempool
              then do
                modifyTxRelay $ \r -> r {sendMempool = False, toSend = []}
                concat <$> mapM (announce False) e.mempoolTxs
              else return []
          pending <- maybe [] (.toSend) . (.txRelay) <$> getS
          let queued = mapMaybe e.mempoolTx pending
              byFee = sortOn (Down . maybe 0 id . e.txFeeRate . txHash) queued
          modifyTxRelay $ \r -> r {toSend = []}
          queuedInvs <- concat <$> mapM (announce True) byFee
          return (mempoolInvs ++ queuedInvs)
  where
    announce checkKnown tx = do
      s <- getS
      e <- env
      case s.txRelay of
        Nothing -> return []
        Just r -> do
          let h = knownHash s tx
              rate = maybe 0 id (e.txFeeRate (txHash tx))
              inv = InvVector (if s.wtxidRelay then InvWTx else InvTx) h.get
          if rate < r.feeFilterReceived || (checkKnown && Set.member h r.knownTxs)
            then return []
            else case r.bloomFilter of
              Just bf -> case bloomRelevantUpdate bf tx of
                Nothing -> return []
                Just bf' -> do
                  modifyTxRelay $ \x -> x {bloomFilter = Just bf', knownTxs = Set.insert h x.knownTxs}
                  return [inv]
              Nothing -> do
                addKnownTx h
                return [inv]

-- | A transaction entered the mempool and the node's announcement buckets
-- released it (@InitiateTxBroadcastToAll@ and @ProcessInvBacklog@): queue
-- it for the next trickle, for a peer with transaction relay that has had
-- its first pass after the handshake.
txAccepted :: Tx -> M ()
txAccepted tx = do
  s <- getS
  case s.txRelay of
    Just r
      | r.nextInvSend /= 0 ->
          modifyTxRelay $ \x -> x {toSend = x.toSend ++ [txWitnessHash tx]}
    _ -> return ()

-- | The node relays an address through this peer (@RelayAddress@ chose
-- it): queue it if address relay is on.
relayAddress :: NetworkAddressV2 -> M ()
relayAddress a = do
  s <- getS
  when s.addrRelay $ pushAddress a

-- | The node's transaction download asks the peer for a transaction (line
-- 6552): by wtxid from a peer that relays by wtxid, by txid with the
-- witness flag otherwise.
requestTx :: TxHash -> M ()
requestTx h = do
  s <- getS
  when (s.successfullyConnected && isJust s.txRelay) $ do
    let t
          | s.wtxidRelay = InvWTx
          | s.theirServices .&. nodeWitness /= 0 = InvWitnessTx
          | otherwise = InvTx
    send (MGetData (GetData [InvVector t h.get])) $ netProcessing 6553 "getdata for a transaction"
