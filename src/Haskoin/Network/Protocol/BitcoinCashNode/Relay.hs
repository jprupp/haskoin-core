{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCashNode.Relay
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- How Bitcoin Cash Node 29.2.0 relays transactions, double-spend proofs and
-- addresses with one peer: @inv@, @getdata@, @tx@, @notfound@,
-- @dsproof-beta@, @mempool@, @feefilter@, the BIP 37 filters, @addr@,
-- @addrv2@ and @getaddr@, and the parts of @SendMessages@ that announce
-- inventory, send addresses, request transactions and proofs, and send
-- @feefilter@.
--
-- @inv@ and @getdata@ are here although they carry blocks too: the handlers
-- walk the entries in order and hand the block entries to
-- "Haskoin.Network.Protocol.BitcoinCashNode.Blocks", as upstream does in one
-- loop.
--
-- What the machine simplifies, and why:
--
-- * The @TxRequestTracker@ is global: it asks for a transaction from the best
--   of the peers that announced it. The machine keeps this peer's
--   announcements and requests them as if this peer were the only one;
--   'RequestTx' lets the rest of the node force a request.
-- * Transactions to announce are kept in order of arrival; upstream sorts
--   them by their order in the mempool.
-- * @mapRelay@, the transactions announced to any peer in the last 15
--   minutes, is global and comes from 'relayedTx'.
-- * The random shuffle of a large @addr@ under rate limiting, the choice of
--   the peers an address is relayed to, and the bans are global or random
--   and are left out: relayed and stored addresses are 'Process' effects.
-- * Addresses are routable when their bytes are not all zero.
-- * The shared timer of announcements to inbound peers
--   (@PoissonNextSendInbound@) is a timer of this peer with the same mean.
module Haskoin.Network.Protocol.BitcoinCashNode.Relay
  ( -- * Messages
    receiveInv,
    receiveGetData,
    receiveTx,
    receiveNotFound,
    receiveDsProof,
    receiveMempool,
    receiveFeeFilter,
    receiveFilterLoad,
    receiveFilterAdd,
    receiveFilterClear,
    receiveAddr,
    receiveGetAddr,

    -- * Notifications
    txAccepted,
    relayAddress,
    newDoubleSpendProof,
    requestTx,

    -- * SendMessages
    advertiseLocal,
    sendAddresses,
    sendInventory,
    dsProofRequests,
    txRequests,
    sendFeeFilter,
  )
where

import Control.Monad (foldM, forM_, unless, when)
import Control.Monad.RWS.Strict (get, gets)
import Data.Bits ((.&.), (.|.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.List (sortOn)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe, mapMaybe)
import Data.Set qualified as Set
import Data.Word (Word64)
import Haskoin.Block.Common (BlockHash (..))
import Haskoin.Crypto.Hash (Hash256)
import Haskoin.Network.Bloom
  ( BloomFilter (..),
    FilterAdd (..),
    FilterLoad (..),
    bloomInsert,
    bloomRelevantUpdate,
  )
import Haskoin.Network.Common
  ( Addr (..),
    AddrV2 (..),
    FeeFilter (..),
    GetData (..),
    Inv (..),
    InvType (..),
    InvVector (..),
    MessageCommand (..),
    NetworkAddressV2 (..),
    NotFound (..),
    fromNetworkAddressV2,
  )
import Haskoin.Network.Message (Message (..))
import Haskoin.Network.Protocol.BitcoinCashNode.Blocks (afterInv, getBlockData, receiveBlockInv)
import Haskoin.Network.Protocol.BitcoinCashNode.Constants
import Haskoin.Network.Protocol.BitcoinCashNode.Handshake (hasAllDesirableServices)
import Haskoin.Network.Protocol.BitcoinCashNode.Options
import Haskoin.Network.Protocol.BitcoinCashNode.State
import Haskoin.Network.Protocol.Types
import Haskoin.Transaction.Common (OutPoint (..), Tx (..), TxHash (..), TxIn (..), txHash)

-- * Helpers

-- | The inventory type of a double-spend proof.
dsProofType :: InvType
dsProofType = InvType msgDoubleSpendProof

-- | Remember that the peer knows a hash (@AddInventoryKnown@,
-- @src\/net.h:1012-1015@).
addKnown :: Hash256 -> M ()
addKnown h = modifyRelay (\r -> r {knownInv = Set.insert h r.knownInv})

-- | Transactions are taken from this peer: the node relays them, or the peer
-- has the @relay@ permission (@src\/net_processing.cpp:2550-2556@).
acceptsTxs :: M Bool
acceptsTxs = do
  o <- options
  relayPerm <- hasPerm PermRelay
  return (not o.blocksOnly || relayPerm)

-- | @AddTxAnnouncement@ (@src\/net_processing.cpp:1958-1980@): track a
-- transaction the peer has. Non-preferred peers wait 2 seconds more, and so
-- do peers with 100 requests in flight; a peer without @relay@ may have at
-- most 100000 announcements.
addTxAnnouncement :: TxHash -> M ()
addTxAnnouncement h = do
  s <- get
  t <- nowM
  relayPerm <- hasPerm PermRelay
  let anns = s.relay.announcements
      inFlightCount = length [() | TxAnnouncement _ (TxRequested _) <- Map.elems anns]
      delay =
        (if s.preferredDownload then 0 else nonPrefPeerTxDelay)
          + (if not relayPerm && inFlightCount >= maxPeerTxRequestInFlight then overloadedPeerTxDelay else 0)
  unless ((not relayPerm && Map.size anns >= maxPeerTxAnnouncements) || Map.member h anns) $
    modifyRelay $ \r ->
      r {announcements = Map.insert h (TxAnnouncement (t + delay) TxCandidate) anns}

-- | The filter of the peer matches the transaction, and is updated as
-- @IsRelevantAndUpdate@ does.
filterMatches :: Tx -> M Bool
filterMatches tx = do
  o <- options
  f <- gets (.relay.bloom)
  case bloomRelevantUpdate o.network f tx of
    Nothing -> return False
    Just f' -> do
      modifyRelay (\r -> r {bloom = f'})
      return True

-- | An address the node can use: its bytes are not all zero.
routable :: NetworkAddressV2 -> Bool
routable a = BS.any (/= 0) a.address

-- * Messages

-- | @inv@ (@src\/net_processing.cpp:2537-2622@).
receiveInv :: Inv -> M ()
receiveInv (Inv xs)
  | length xs > maxInvSize = misbehaving 20 (netProcessing 2546 "oversized-inv")
  | otherwise = do
      best <- foldM entry Nothing xs
      afterInv best
  where
    entry best iv
      | iv.invType == InvBlock = do
          c <- receiveBlockInv (BlockHash iv.invHash)
          return (maybe best Just c)
      | otherwise = best <$ otherEntry iv

-- | An entry of an @inv@ that is not a block
-- (@src\/net_processing.cpp:2583-2613@).
otherEntry :: InvVector -> M ()
otherEntry iv = do
  o <- options
  e <- env
  ok <- acceptsTxs
  addKnown iv.invHash
  let have = case iv.invType of
        InvTx -> e.knownTx (TxHash iv.invHash)
        t | t == dsProofType -> e.knownDsProof iv.invHash
        _ -> True
  if
    | not ok -> ignore (netProcessing 2587 "transaction inv sent in violation of protocol")
    | have || e.initialBlockDownload -> return ()
    | iv.invType == dsProofType ->
        if o.doubleSpendProof
          then do
            q <- gets (.relay.dsProofsToRequest)
            if length q < maxDsProofGetDatas
              then modifyRelay (\r -> r {dsProofsToRequest = q <> [iv.invHash]})
              else ignore (netProcessing 2600 "DSProof batch queue full")
          else ignore (netProcessing 2605 "DSProof INV ignored, -doublespendproof=0")
    | otherwise -> addTxAnnouncement (TxHash iv.invHash)

-- | @getdata@ (@src\/net_processing.cpp:2624-2645@ and @ProcessGetData@,
-- @src\/net_processing.cpp:1478-1585@). Upstream answers a run of
-- transactions and proofs, then one block, then sends @notfound@ for the run,
-- and does not read the peer's next message until the queue is empty. The
-- machine answers the whole queue in one step, in that order.
receiveGetData :: GetData -> M ()
receiveGetData (GetData xs)
  | length xs > maxInvSize = misbehaving 20 (netProcessing 2629 "too-many-inv")
  | otherwise = processGetData xs

processGetData :: [InvVector] -> M ()
processGetData [] = return ()
processGetData q = do
  let (run, rest) = span txOrProof q
  missing <- concat <$> mapM serveTx run
  rest' <- case rest of
    [] -> return []
    (x : more) -> do
      if x.invType `elem` [InvBlock, InvMerkleBlock, InvCompactBlock]
        then getBlockData x
        else ignore (netProcessing 1543 "getdata of an unknown type")
      return more
  unless (null missing) $
    send (MNotFound (NotFound missing)) (netProcessing 1583 "NOTFOUND")
  closing <- gets (.closing)
  unless closing $ processGetData rest'
  where
    txOrProof iv = iv.invType == InvTx || iv.invType == dsProofType

-- | One transaction or proof of a @getdata@
-- (@src\/net_processing.cpp:1500-1533@): a transaction announced to any
-- peer in the last 15 minutes, or one from the mempool that was there when
-- this peer last got an answer to @mempool@; a stored proof, orphans
-- included. Returns the entry when it is not found.
serveTx :: InvVector -> M [InvVector]
serveTx iv = do
  o <- options
  e <- env
  s <- get
  if iv.invType == InvTx
    then do
      let h = TxHash iv.invHash
          fromMempool = do
            tx <- e.mempoolTx h
            t <- e.mempoolTime h
            if s.relay.lastMempoolReq /= 0 && t <= s.relay.lastMempoolReq
              then Just tx
              else Nothing
      case e.relayedTx h of
        Just tx -> [] <$ send (MTx tx) (netProcessing 1504 "TX from mapRelay")
        Nothing -> case fromMempool of
          Just tx -> [] <$ send (MTx tx) (netProcessing 1512 "TX from the mempool")
          Nothing -> return [iv]
    else case (o.doubleSpendProof, e.dsProof iv.invHash) of
      (True, Just p) -> [] <$ send (MOther dsProofCommand p) (netProcessing 1521 "DSPROOF")
      _ -> return [iv]

-- | @tx@ (@src\/net_processing.cpp:2856-3020@).
receiveTx :: Tx -> M ()
receiveTx tx = do
  ok <- acceptsTxs
  if not ok
    then ignore (netProcessing 2862 "transaction sent in violation of protocol")
    else do
      e <- env
      let h = txHash tx
      addKnown h.get
      modifyRelay (\r -> r {announcements = Map.delete h r.announcements})
      if e.knownTx h
        then rejectedPath 0
        else case e.checkTx tx of
          TxAcceptedToMempool ->
            process "relay the transaction and reconsider orphans" $
              netProcessing 2891 "AcceptToMemoryPool: accepted"
          TxAlreadyKnown -> rejectedPath 0
          TxOrphan -> orphan e
          TxPolicyReject r -> invalid h 0x40 0 r
          TxConsensusInvalid r -> invalid h 0x10 100 r
          TxRejected code dos r -> invalid h code dos r
  where
    orphan e
      | any (e.recentlyRejected . (.outpoint.hash)) tx.inputs =
          process "not keeping orphan with rejected parents" $
            netProcessing 2942 "not keeping orphan with rejected parents"
      | otherwise = do
          forM_ tx.inputs $ \i -> do
            let p = i.outpoint.hash
            addKnown p.get
            unless (e.knownTx p) $ addTxAnnouncement p
          process "keep the transaction as an orphan" (netProcessing 2928 "AddTx to the orphanage")
    rejectedPath :: Int -> M ()
    rejectedPath dos = do
      force <- hasPerm PermForceRelay
      when force $
        if dos == 0
          then process "force relay" (netProcessing 2970 "Force relaying tx from whitelisted peer")
          else process "not relayed" (netProcessing 2974 "Not relaying invalid transaction")
    invalid h code dos r = do
      rejectedPath dos
      when (code > 0) $
        sendReject MCTx code r (Just h.get) (netProcessing 3009 "reject of a transaction")
      when (dos > 0) $ misbehaving dos (netProcessing 3016 r)

-- | @notfound@ (@src\/net_processing.cpp:3750-3763@): the requests of the
-- transactions named end; block entries are ignored, and so is a message of
-- more than 100016 entries.
receiveNotFound :: NotFound -> M ()
receiveNotFound (NotFound xs)
  | length xs > maxPeerTxAnnouncements + maxBlocksInTransitPerPeer =
      ignore (netProcessing 3753 "notfound too large")
  | otherwise =
      forM_ [TxHash iv.invHash | iv <- xs, iv.invType == InvTx] $ \h ->
        modifyRelay (\r -> r {announcements = Map.delete h r.announcements})

-- | @dsproof-beta@ (@src\/net_processing.cpp:3680-3748@). Unsolicited proofs
-- are processed in full, even in blocks-only mode. An invalid proof, or one
-- that does not parse ('Nothing'), costs 10 unless the peer has @noban@;
-- upstream charges it through a signal (@src\/net_processing.cpp:4865-4872@).
receiveDsProof :: Maybe ByteString -> M ()
receiveDsProof mp = do
  o <- options
  e <- env
  noban <- hasPerm PermNoBan
  let verdict = maybe (DsProofInvalid "does not parse") e.checkDsProof mp
  if not o.doubleSpendProof
    then ignore (netProcessing 3682 "dsproof received while disabled")
    else case verdict of
      DsProofDuplicate -> ignore (netProcessing 3698 "proof for an outpoint that has one")
      DsProofValid -> process "store and announce the proof" (netProcessing 3744 "TransactionDoubleSpent")
      DsProofOrphan -> process "keep the proof as an orphan" (netProcessing 3720 "addOrphan")
      DsProofInvalid r -> do
        process "mark the proof rejected" (netProcessing 3732 r)
        unless noban $ misbehaving 10 (netProcessing 4870 "bad-dsproof")

-- | @mempool@ (@src\/net_processing.cpp:3500-3528@): allowed when the node
-- offers Bloom filters or the peer has the @mempool@ permission, and the
-- upload target is not reached; otherwise a disconnect, or nothing for a
-- @noban@ peer. The answer goes out with the next announcement of
-- transactions.
receiveMempool :: M ()
receiveMempool = do
  o <- options
  e <- env
  s <- get
  mempoolPerm <- hasPerm PermMempool
  noban <- hasPerm PermNoBan
  if
    | not (offersBloom o s.perms) && not mempoolPerm ->
        if noban
          then ignore (netProcessing 3510 "mempool request with bloom filters disabled")
          else disconnect Unsuitable (netProcessing 3508 "mempool request with bloom filters disabled")
    | e.uploadTargetReached && not mempoolPerm ->
        if noban
          then ignore (netProcessing 3522 "mempool request with bandwidth limit reached")
          else disconnect Resources (netProcessing 3520 "mempool request with bandwidth limit reached")
    | otherwise -> modifyRelay (\r -> r {sendMempool = True})

-- | @feefilter@ (@src\/net_processing.cpp:3666-3678@): kept when it is a
-- valid amount, ignored otherwise.
receiveFeeFilter :: FeeFilter -> M ()
receiveFeeFilter (FeeFilter r)
  | r <= maxMoney = modifyRelay (\x -> x {minFeeFilter = r})
  | otherwise = ignore (netProcessing 3669 "feefilter out of the money range")

-- | @filterload@ (@src\/net_processing.cpp:3612-3626@), after the check of
-- @NODE_BLOOM@ that comes first: a filter over the size limits costs 100,
-- a good one replaces the filter and turns on the relay of transactions.
receiveFilterLoad :: FilterLoad -> M ()
receiveFilterLoad (FilterLoad f)
  | length f.array > maxBloomFilterSize || f.functions > maxHashFuncs =
      misbehaving 100 (netProcessing 3619 "oversized-bloom-filter")
  | otherwise = modifyRelay (\r -> r {bloom = f, relayTxes = True})

-- | @filteradd@ (@src\/net_processing.cpp:3628-3655@): an item over 520
-- bytes costs 100. There is always a filter upstream, so a @filteradd@
-- without @filterload@ adds to the empty filter, which still matches
-- everything.
receiveFilterAdd :: FilterAdd -> M ()
receiveFilterAdd (FilterAdd bs)
  | BS.length bs > maxScriptElementSize =
      misbehaving 100 (netProcessing 3652 "invalid-filteradd")
  | otherwise = modifyRelay (\r -> r {bloom = bloomInsert r.bloom bs})

-- | @filterclear@ (@src\/net_processing.cpp:3657-3664@): no check of
-- @NODE_BLOOM@; the filter is reset only when the node offers Bloom filters,
-- and the relay of transactions turns on in any case.
receiveFilterClear :: M ()
receiveFilterClear = do
  o <- options
  s <- get
  modifyRelay $ \r ->
    r
      { bloom = if offersBloom o s.perms then BloomFilter mempty 0 0 r.bloom.flags else r.bloom,
        relayTxes = True
      }

-- | @addr@ and @addrv2@ (@src\/net_processing.cpp:2410-2511@): more than
-- 1000 costs 20; then the token bucket limits how many are taken, unless the
-- peer has the @addr@ permission. An address-fetch connection ends after
-- the first one.
receiveAddr :: [NetworkAddressV2] -> M ()
receiveAddr xs
  | length xs > maxAddrToSend = misbehaving 20 (netProcessing 2425 "oversized-addr")
  | otherwise = do
      e <- env
      t <- nowM
      addrPerm <- hasPerm PermAddr
      r0 <- gets (.relay)
      let refill
            | r0.addrTokens < maxAddrProcessingTokenBucket =
                min
                  maxAddrProcessingTokenBucket
                  (r0.addrTokens + fromIntegral (max 0 (t - r0.addrTokenTime)) / 1e6 * maxAddrRatePerSecond)
            | otherwise = r0.addrTokens
          nowS = fromIntegral (t `div` 1000000) :: Word64
      modifyRelay (\r -> r {addrTokens = refill, addrTokenTime = t})
      kept <- concat <$> mapM (one e addrPerm nowS) xs
      pending <- gets (.relay.getAddrPending)
      let relayable =
            [ a
            | a <- kept,
              fromIntegral a.time > nowS - 600,
              not pending,
              length xs <= 10,
              routable a
            ]
      unless (null relayable) $
        process "relay the addresses to two peers" (netProcessing 2491 "RelayAddress")
      unless (null kept) $
        process "add the addresses to addrman" (netProcessing 2503 "AddNewAddresses")
      when (length xs < maxAddrToSend) $
        modifyRelay (\r -> r {getAddrPending = False})
      ct <- connType
      when (ct == AddrFetch) $
        disconnect Done (netProcessing 2508 "address fetch done")
  where
    one e addrPerm nowS a = do
      tokens <- gets (.relay.addrTokens)
      if tokens < 1 && not addrPerm
        then return []
        else do
          when (tokens >= 1) $ modifyRelay (\r -> r {addrTokens = r.addrTokens - 1})
          let useful = a.services .&. (nodeNetwork .|. nodeNetworkLimited) /= 0
          if not useful && not (hasAllDesirableServices e a.services)
            then return []
            else do
              let fixed
                    | a.time <= 100000000 || fromIntegral a.time > nowS + 600 =
                        NetworkAddressV2
                          { time = fromIntegral (nowS - 5 * 24 * 60 * 60),
                            services = a.services,
                            network = a.network,
                            address = a.address,
                            port = a.port
                          }
                    | otherwise = a
              modifyRelay (\r -> r {addrKnown = Set.insert (addrKey fixed) r.addrKnown})
              return [fixed]

-- | @getaddr@ (@src\/net_processing.cpp:3463-3498@): answered once, and only
-- to an inbound peer, with a fresh sample for the @addr@ permission and the
-- cached answer otherwise; the addresses go out with the next @addr@.
receiveGetAddr :: M ()
receiveGetAddr = do
  e <- env
  inbound <- isInbound
  sent <- gets (.relay.sentAddr)
  addrPerm <- hasPerm PermAddr
  if
    | not inbound -> ignore (netProcessing 3471 "Ignoring getaddr from an outbound connection")
    | sent -> ignore (netProcessing 3479 "Ignoring repeated getaddr")
    | otherwise -> do
        modifyRelay (\r -> r {sentAddr = True, addrToSend = []})
        mapM_ pushAddress (e.addressesForPeer addrPerm)

-- * Notifications

-- | A transaction entered the mempool (@RelayTransaction@,
-- @src\/net_processing.cpp:1188-1197@): queued for a peer past its
-- handshake that does not know it.
txAccepted :: Tx -> M ()
txAccepted tx = do
  s <- get
  let h = txHash tx
  when (s.connected && not (h.get `Set.member` s.relay.knownInv)) $
    modifyRelay (\r -> r {txsToSend = r.txsToSend <> [h | h `notElem` r.txsToSend]})

-- | The node relays an address to this peer (@RelayAddress@,
-- @src\/net_processing.cpp:1199-1233@, which picks the peers).
relayAddress :: NetworkAddressV2 -> M ()
relayAddress = pushAddress

-- | A double-spend proof to announce (@TransactionDoubleSpent@,
-- @src\/net_processing.cpp:4850-4863@): to a peer that wants transactions
-- and whose filter matches the transaction.
newDoubleSpendProof :: Hash256 -> Tx -> M ()
newDoubleSpendProof h tx = do
  s <- get
  when (s.connected && s.relay.relayTxes) $ do
    m <- filterMatches tx
    known <- gets (Set.member h . (.relay.knownInv))
    when (m && not known) $
      modifyRelay (\r -> r {otherInvs = r.otherInvs <> [h]})

-- | The rest of the node wants this transaction from this peer: an
-- announcement that may be requested at once.
requestTx :: TxHash -> M ()
requestTx h = do
  t <- nowM
  modifyRelay $ \r ->
    r {announcements = Map.insertWith (\_ old -> old) h (TxAnnouncement t TxCandidate) r.announcements}

-- * SendMessages

-- | Advertise our address once a day on average, from the first pass after
-- the handshake, out of initial block download
-- (@src\/net_processing.cpp:4203-4207@, @AdvertiseLocal@,
-- @src\/net.cpp:183-209@).
advertiseLocal :: M ()
advertiseLocal = do
  o <- options
  e <- env
  r <- gets (.relay)
  when (not e.initialBlockDownload && r.nextLocalAddrSend < e.now) $ do
    when o.listen $ mapM_ pushAddress e.localAddress
    d <- randomDelay avgLocalAddressBroadcastInterval
    modifyRelay (\x -> x {nextLocalAddrSend = e.now + d})

-- | Send the queued addresses every 30 seconds on average
-- (@src\/net_processing.cpp:4212-4247@), as @addrv2@ to a peer that sent
-- @sendaddrv2@ and as @addr@ otherwise, at most 1000 to a message.
sendAddresses :: M ()
sendAddresses = do
  t <- nowM
  r <- gets (.relay)
  v2 <- gets (.wantsAddrV2)
  when (r.nextAddrSend < t) $ do
    d <- randomDelay avgAddressBroadcastInterval
    let fresh = dedupe r.addrKnown r.addrToSend
    modifyRelay $ \x ->
      x
        { nextAddrSend = t + d,
          addrToSend = [],
          addrKnown = foldr (Set.insert . addrKey) x.addrKnown fresh
        }
    forM_ (chunks maxAddrToSend fresh) $ \c ->
      if v2
        then send (MAddrV2 (AddrV2 c)) (netProcessing 4240 "ADDRV2")
        else send (MAddr (Addr (mapMaybe fromNetworkAddressV2 c))) (netProcessing 4240 "ADDR")
  where
    dedupe _ [] = []
    dedupe known (a : as)
      | addrKey a `Set.member` known = dedupe known as
      | otherwise = a : dedupe (Set.insert (addrKey a) known) as

-- | Split a list into pieces of at most this length.
chunks :: Int -> [a] -> [[a]]
chunks _ [] = []
chunks n xs = let (a, b) = splitAt n xs in a : chunks n b

-- | The @inv@ messages of a pass (@src\/net_processing.cpp:4461-4654@):
-- block hashes and proofs at once, and transactions when the trickle timer
-- fires (at every pass for a @noban@ peer), with the answer to @mempool@
-- first. Transactions go at most @nMaxBroadcasts@ at a time, only if the
-- peer wants them, they are still in the mempool, they pay the peer's
-- @feefilter@ and match its filter.
sendInventory :: M ()
sendInventory = do
  o <- options
  e <- env
  s <- get
  noban <- hasPerm PermNoBan
  inbound <- isInbound
  let t = e.now
      blockLimit = maybe o.defaultBlockSize id e.nextBlockSizeLimit
      interval = o.txBroadcastInterval
      maxBroadcasts =
        ceiling
          ( o.txBroadcastRate
              * (fromIntegral blockLimit / 1000000)
              * (fromIntegral (max interval 1) / 1000)
          ) ::
          Int
      blockInvs = [InvVector InvBlock h.get | h <- s.blocks.blockInvs]
      proofInvs = [InvVector dsProofType h | h <- s.relay.otherInvs]
  modifyBlocks (\b -> b {blockInvs = []})
  modifyRelay (\r -> r {otherInvs = []})
  timerFired <-
    if interval == 0 || s.relay.nextInvSend < t
      then do
        d <- randomDelay (millis (if inbound then interval else interval `div` 2))
        modifyRelay (\r -> r {nextInvSend = t + d})
        return True
      else return False
  let trickle = noban || timerFired
  when (trickle && not s.relay.relayTxes) $
    modifyRelay (\r -> r {txsToSend = []})
  mempoolInvs <-
    if trickle && s.relay.sendMempool
      then do
        modifyRelay (\r -> r {sendMempool = False})
        xs <- concat <$> mapM (mempoolEntry e) e.mempoolTxs
        modifyRelay (\r -> r {lastMempoolReq = t `div` 1000000})
        return xs
      else return []
  txInvs <-
    if trickle
      then announce e maxBroadcasts
      else return []
  let invs = blockInvs <> proofInvs <> mempoolInvs <> txInvs
  unless (null txInvs) $
    process "keep the announced transactions for 15 minutes" $
      netProcessing 4638 "mapRelay"
  forM_ (chunks maxInvSize invs) $ \c ->
    send (MInv (Inv c)) (netProcessing 4652 "INV")
  where
    passesFee e h = do
      f <- gets (.relay.minFeeFilter)
      return (f == 0 || fromMaybe 0 (e.txFeeRate h) >= f)
    mempoolEntry e tx = do
      let h = txHash tx
      modifyRelay (\r -> r {txsToSend = filter (/= h) r.txsToSend})
      fee <- passesFee e h
      if not fee
        then return []
        else do
          m <- filterMatches tx
          if not m
            then return []
            else do
              addKnown h.get
              return [InvVector InvTx h.get]
    announce e n
      | n <= 0 = return []
      | otherwise = do
          q <- gets (.relay.txsToSend)
          case q of
            [] -> return []
            (h : rest) -> do
              modifyRelay (\r -> r {txsToSend = rest})
              known <- gets (Set.member h.get . (.relay.knownInv))
              fee <- passesFee e h
              case e.mempoolTx h of
                Just tx | not known && fee -> do
                  m <- filterMatches tx
                  if m
                    then do
                      addKnown h.get
                      (InvVector InvTx h.get :) <$> announce e (n - 1)
                    else announce e n
                _ -> announce e n

-- | The proofs to request in this pass (@src\/net_processing.cpp:4776-4785@):
-- every queued one the node does not have yet.
dsProofRequests :: M [InvVector]
dsProofRequests = do
  e <- env
  q <- gets (.relay.dsProofsToRequest)
  modifyRelay (\r -> r {dsProofsToRequest = []})
  return [InvVector dsProofType h | h <- q, not (e.knownDsProof h)]

-- | The transactions to request in this pass
-- (@src\/net_processing.cpp:4787-4809@): requests older than a minute
-- expire without penalty, then each announcement whose time has come is
-- requested, unless the node got the transaction meanwhile.
txRequests :: M [InvVector]
txRequests = do
  e <- env
  anns <- gets (.relay.announcements)
  let t = e.now
      live = Map.filter (not . expired t) anns
      ready =
        sortOn
          (\(h, a) -> (a.reqTime, h))
          [(h, a) | (h, a@(TxAnnouncement _ TxCandidate)) <- Map.toList live, a.reqTime <= t]
      want = [h | (h, _) <- ready, not (e.knownTx h)]
      forget = [h | (h, _) <- ready, e.knownTx h]
      requested = TxAnnouncement t (TxRequested (t + getDataTxInterval))
      anns' =
        foldr Map.delete (foldr (`Map.insert` requested) live want) forget
  modifyRelay (\r -> r {announcements = anns'})
  return [InvVector InvTx h.get | h <- want]
  where
    expired t (TxAnnouncement _ (TxRequested x)) = x <= t
    expired _ _ = False

-- | @feefilter@ (@src\/net_processing.cpp:4815-4846@): to peers of version
-- 70013 or later without @forcerelay@, every 10 minutes on average and
-- sooner after a large change, when the rounded minimum fee of the mempool
-- differs from the last one sent.
sendFeeFilter :: M ()
sendFeeFilter = do
  o <- options
  e <- env
  s <- get
  force <- hasPerm PermForceRelay
  let t = e.now
      current = e.mempoolMinFee
      lastSent = s.relay.lastSentFeeFilter
  when (s.peerVersion >= feeFilterVersion && o.feeFilter && not force) $
    if t > s.relay.nextFeeFilter
      then do
        rounded <- roundFee current
        let toSend = max rounded o.minRelayTxFee
        when (toSend /= lastSent) $ do
          send (MFeeFilter (FeeFilter toSend)) (netProcessing 4829 "FEEFILTER")
          modifyRelay (\r -> r {lastSentFeeFilter = toSend})
        d <- randomDelay avgFeeFilterBroadcastInterval
        modifyRelay (\r -> r {nextFeeFilter = t + d})
      else when
        ( t + maxFeeFilterChangeDelay < s.relay.nextFeeFilter
            && (current < 3 * lastSent `div` 4 || current > 4 * lastSent `div` 3)
        )
        $ do
          w <- randomWord
          let secs = fromIntegral (w `mod` 300)
          modifyRelay (\r -> r {nextFeeFilter = t + seconds secs})

-- | @FeeFilterRounder::round@ (@src\/policy\/fees.cpp:21-29@): the bucket at
-- or above the fee, moved one bucket down two times in three. The buckets
-- are 0 and 500 times powers of 1.1 up to 1e7 satoshi per 1000 bytes.
roundFee :: Word64 -> M Word64
roundFee fee = do
  w <- randomWord
  let (below, above) = span (< fee) feeSet
      pick = case (below, above) of
        ([], x : _) -> x
        (_, []) -> last below
        (_, x : _)
          | w `mod` 3 /= 0 -> last below
          | otherwise -> x
  return pick
  where
    feeSet = 0 : takeWhile (<= 10000000) (map floor (iterate (* 1.1) (500 :: Double)))
