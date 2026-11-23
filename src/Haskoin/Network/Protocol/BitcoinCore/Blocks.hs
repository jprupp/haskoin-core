{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCore.Blocks
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Headers and blocks on a connection to Bitcoin Core 32.1: the messages
-- that move them (@getheaders@, @headers@, @getblocks@, the block part of
-- @inv@ and @getdata@, @block@, @sendheaders@, @sendcmpct@, @cmpctblock@,
-- @getblocktxn@, @blocktxn@, and the BIP 157 requests), the announcements
-- of new blocks, and the timers of the block download.
--
-- Bitcoin Core treats headers as the backbone of the download: a peer that
-- announces a block it does not know gets a @getheaders@, not a
-- @getdata@; blocks are requested only once their headers connect. The
-- rules against abuse follow from that. A header that fails validation, or
-- a block that does, gets the peer discouraged, but only when the fault is
-- the peer's: a block from a compact block reconstruction may be wrong
-- because of a collision of short ids, and is forgiven.
--
-- What the machine leaves to the t'Env':
--
-- * validation of headers and blocks (@checkHeaders@ of t'Env',
--   @checkBlock@ of t'Env'), and the block index (@lookupBlock@ of t'Env',
--   @blockAtHeight@ of t'Env');
-- * the choice of the blocks to download from which peer
--   (@FindNextBlocksToDownload@), which spans peers: the node asks for a
--   block with 'RequestBlock' and marks a staller with 'MarkStalling';
-- * the low-work headers sync (@HeadersSyncState@), whose commitments the
--   machine does not keep: it follows the presync as long as
--   @checkHeaders@ of t'Env' says the headers have too little work, and treats
--   any other verdict as the end of it;
-- * the choice of high-bandwidth compact block peers, which comes as
--   'HighBandwidth'.
--
-- Where upstream asks whether one block is an ancestor of another
-- (@GetAncestor@), the machine can answer only for blocks of the active
-- chain, through @blockAtHeight@ of t'Env'; for a block off the active chain it
-- compares hashes. The difference shows only in announcements after a
-- reorganisation.
module Haskoin.Network.Protocol.BitcoinCore.Blocks
  ( -- * Messages
    handleSendHeaders,
    handleSendCmpct,
    blockInvs,
    handleGetHeaders,
    handleHeaders,
    handleGetBlocks,
    getBlockData,
    handleBlock,
    handleCmpctBlock,
    handleGetBlockTxn,
    handleBlockTxn,
    handleGetCFilters,
    handleGetCFHeaders,
    handleGetCFCheckpt,

    -- * Sending
    maybeSendSendHeaders,
    initialGetHeaders,
    sendBlockAnnouncements,
    blockTimeouts,
    considerEviction,

    -- * Notifications
    newTip,
    newPoWValidBlock,
    highBandwidth,
    requestBlock,
    markStalling,

    -- * Helpers
    canServeBlocks,
    syncFromPeer,
  )
where

import Control.Monad (forM_, unless, when)
import Data.Bits ((.&.))
import Data.List (find)
import Data.Maybe (fromMaybe, isJust, isNothing)
import Data.Word (Word32)
import Haskoin.Block.Common
  ( Block (..),
    BlockHash (..),
    BlockHeader (..),
    BlockHeight,
    BlockLocator,
    GetBlocks (..),
    GetHeaders (..),
    Headers (..),
    headerHash,
  )
import Haskoin.Block.Headers (headerWork)
import Haskoin.Network.BlockFilter
  ( GetCFCheckpt (..),
    GetCFHeaders (..),
    GetCFilters (..),
  )
import Haskoin.Network.Common
  ( GetData (..),
    Inv (..),
    InvType (..),
    InvVector (..),
    VarInt (..),
    nodeBloom,
    nodeCompactFilters,
    nodeNetwork,
    nodeNetworkLimited,
    nodeWitness,
  )
import Haskoin.Network.CompactBlock
  ( BlockTxn (..),
    CompactBlock (..),
    GetBlockTxn (..),
    SendCompact (..),
  )
import Haskoin.Network.Data (Network (..))
import Haskoin.Network.Message (Message (..))
import Haskoin.Network.Protocol.BitcoinCore.Constants
import Haskoin.Network.Protocol.BitcoinCore.Machine
import Haskoin.Network.Protocol.BitcoinCore.State
import Haskoin.Network.Protocol.Types
import Haskoin.Transaction.Common (Tx (..))

-- | The zero hash, the stop hash of every locator the node sends.
zeroHash :: BlockHash
zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

-- | @CanServeBlocks@: the peer offers @NODE_NETWORK@ or
-- @NODE_NETWORK_LIMITED@.
canServeBlocks :: State -> Bool
canServeBlocks s = s.theirServices .&. (nodeNetwork + nodeNetworkLimited) /= 0

-- | The inventory type of a block request (@GetFetchFlags@): with witness
-- when the peer offers @NODE_WITNESS@.
blockRequest :: State -> BlockHash -> InvVector
blockRequest s (BlockHash h)
  | s.theirServices .&. nodeWitness /= 0 = InvVector InvWitnessBlock h
  | otherwise = InvVector InvBlock h

-- | @CanDirectFetch@: the tip is less than 20 block intervals old.
canDirectFetch :: M Bool
canDirectFetch = do
  e <- env
  o <- opts
  let spacing = fromIntegral o.network.targetSpacing
  return (fromIntegral e.tip.time > e.now `div` 1000000 - 20 * spacing)

-- | @GetAntiDoSWorkThreshold@: the work a new chain must show before its
-- headers are stored, the larger of the minimum chain work and the work of
-- the tip less 144 blocks of its own proof. The proof of the tip is
-- estimated from the work of the tip's header.
antiDoSThreshold :: M Integer
antiDoSThreshold = do
  e <- env
  o <- opts
  let proof = maybe 0 headerWork (e.headerOf e.tip.hash)
  return (max o.minimumChainWork (e.tip.work - 144 * proof))

-- | @MaybeSendGetHeaders@: send a @getheaders@ unless one went out less
-- than 2 minutes ago and is still unanswered.
maybeSendGetHeaders :: BlockLocator -> Cite -> M Bool
maybeSendGetHeaders loc c = do
  s <- getS
  t <- now
  let recent = maybe False (\l -> t - l <= headersResponseTime) s.blocks.lastGetHeaders
  if recent
    then return False
    else do
      send (MGetHeaders (GetHeaders locatorVersion loc zeroHash)) c
      modifyBlocks $ \b -> b {lastGetHeaders = Just t}
      return True

-- | @ProcessBlockAvailability@ and @UpdateBlockAvailability@: raise the
-- best block known to the peer when the node knows the block and it has
-- more work; otherwise remember the hash for later.
updateBlockAvailability :: BlockHash -> M ()
updateBlockAvailability h = do
  e <- env
  processBlockAvailability
  case e.lookupBlock h of
    Just bi | bi.work > 0 -> raiseBestKnown bi
    _ -> modifyBlocks $ \b -> b {lastUnknownBlock = Just h}

-- | @ProcessBlockAvailability@: promote the last unknown block once the
-- node knows it.
processBlockAvailability :: M ()
processBlockAvailability = do
  s <- getS
  e <- env
  forM_ s.blocks.lastUnknownBlock $ \u ->
    case e.lookupBlock u of
      Just bi | bi.work > 0 -> do
        raiseBestKnown bi
        modifyBlocks $ \b -> b {lastUnknownBlock = Nothing}
      _ -> return ()

-- | Set the best known block if it has at least the work of the last one.
raiseBestKnown :: BlockInfo -> M ()
raiseBestKnown bi = do
  e <- env
  s <- getS
  let bestWork = maybe (-1) (.work) (s.blocks.bestKnownBlock >>= e.lookupBlock)
  when (bi.work >= bestWork) $
    modifyBlocks $
      \b -> b {bestKnownBlock = Just bi.hash}

-- | The work of the best block known to the peer.
bestKnownWork :: M (Maybe Integer)
bestKnownWork = do
  s <- getS
  e <- env
  return $ (.work) <$> (s.blocks.bestKnownBlock >>= e.lookupBlock)

-- | @PeerHasHeader@: the block is an ancestor of the best block known to
-- the peer or of the best header sent to it. Ancestors are known only on
-- the active chain.
peerHasHeader :: BlockInfo -> M Bool
peerHasHeader bi = do
  s <- getS
  e <- env
  let ancestorOf h = case e.lookupBlock h of
        Nothing -> False
        Just top
          | top.hash == bi.hash -> True
          | top.inActiveChain && bi.inActiveChain -> top.height >= bi.height
          | otherwise -> False
  return $ maybe False ancestorOf s.blocks.bestKnownBlock || maybe False ancestorOf s.blocks.bestHeaderSent

-- | @BlockRequestAllowed@: a block of the active chain, or a valid one at
-- most 30 days older than the best header. Upstream also bounds the work
-- between them; the machine checks the time only.
blockRequestAllowed :: BlockInfo -> M Bool
blockRequestAllowed bi = do
  e <- env
  return $
    bi.inActiveChain
      || ( bi.status == HaveData
             && fromIntegral e.bestHeader.time - fromIntegral bi.time < staleRelayAge
         )

-- | Mark a block as requested from the peer (@BlockRequested@).
blockRequested :: BlockHash -> Maybe CompactBlock -> M ()
blockRequested h pc = do
  t <- now
  modifyBlocks $ \b ->
    b
      { inFlight = b.inFlight ++ [InFlight h pc False],
        downloadingSince = if null b.inFlight then t else b.downloadingSince
      }

-- | @RemoveBlockRequest@ for this peer. The stalling mark goes with it.
removeBlockRequest :: BlockHash -> M ()
removeBlockRequest h = do
  t <- now
  modifyBlocks $ \b ->
    let rest = filter ((/= h) . (.block)) b.inFlight
        wasFirst = case b.inFlight of
          (x : _) -> x.block == h
          [] -> False
     in if length rest == length b.inFlight
          then b
          else
            b
              { inFlight = rest,
                stallingSince = Nothing,
                downloadingSince = if wasFirst then max t b.downloadingSince else b.downloadingSince
              }

-- | @sendheaders@ (line 4160): the peer wants new blocks announced with
-- headers. Accepted before @verack@; it cannot be undone.
handleSendHeaders :: M ()
handleSendHeaders = modifyBlocks $ \b -> b {prefersHeaders = True}

-- | @sendcmpct@ (line 4165). An announce field above 1 is misbehaviour,
-- even before @verack@; a version other than 2 is ignored.
handleSendCmpct :: SendCompact -> M ()
handleSendCmpct sc
  | sc.version /= cmpctBlocksVersion =
      ignore $ netProcessing 4178 "sendcmpct of an unknown version"
  | otherwise =
      modifyBlocks $ \b -> b {providesCmpct = True, requestedHbCmpct = sc.announce}

-- | The block entries of an @inv@ (lines 4377 to 4438), after the
-- transaction entries were looked at by the caller. Each @MSG_BLOCK@
-- updates what the peer has. The last one the node lacks may trigger a
-- @getheaders@: from a peer the headers sync started with, or from one
-- other peer per new block. The node never asks for an announced block
-- directly.
blockInvs :: [BlockHash] -> M ()
blockInvs hs = do
  e <- env
  best <- foldBest hs
  forM_ best $ \_ -> do
    s <- getS
    when (s.blocks.syncStarted || not s.blocks.invTriggeredGetHeaders) $ do
      _ <-
        maybeSendGetHeaders (e.locatorFrom e.bestHeader.hash) $
          netProcessing 4425 "getheaders after block inv"
      unless s.blocks.syncStarted $
        modifyBlocks $
          \b -> b {invTriggeredGetHeaders = True}
  where
    foldBest = go Nothing
    go acc [] = return acc
    go acc (h : rest) = do
      e <- env
      s <- getS
      updateBlockAvailability h
      let have = isJust (e.lookupBlock h)
          requested = any ((== h) . (.block)) s.blocks.inFlight || e.inFlightElsewhere h > 0
      if not have && not e.loadingBlocks && not requested
        then go (Just h) rest
        else go acc rest

-- | @getheaders@ (line 4629). Serves up to 2000 headers of the active
-- chain after the fork point of the locator, or the one header named by
-- the stop hash when the locator is empty. While the tip has less than the
-- minimum chain work, a peer without 'PermDownload' gets an empty
-- @headers@.
handleGetHeaders :: GetHeaders -> M ()
handleGetHeaders gh = do
  e <- env
  o <- opts
  s <- getS
  when (length gh.locator > maxLocatorSz) $ do
    disconnect ProtocolViolation $ netProcessing 4636 "getheaders locator size too large"
    stop
  when e.loadingBlocks $ do
    ignore $ netProcessing 4641 "Ignoring getheaders while importing/reindexing"
    stop
  when (e.tip.work < o.minimumChainWork && not (hasPermission PermDownload s)) $ do
    send (MHeaders (Headers [])) $
      netProcessing 4655 "active chain has too little work; sending empty response"
    stop
  start' <-
    if null gh.locator
      then case e.lookupBlock gh.stop of
        Nothing -> do
          ignore $ netProcessing 4666 "getheaders for an unknown stop hash"
          stop
        Just bi -> do
          ok <- blockRequestAllowed bi
          unless ok $ do
            ignore $ netProcessing 4669 "ignoring request for old block header that isn't in the main chain"
            stop
          return (Just bi)
      else return (fmap succ (Just (forkHeight e gh.locator)) >>= e.blockAtHeight)
  let walk _ Nothing = []
      walk n (Just bi)
        | n <= 0 = []
        | bi.hash == gh.stop = [bi]
        | n == 1 = [bi]
        | not (null gh.locator) || bi.inActiveChain = bi : walk (n - 1) (e.blockAtHeight (bi.height + 1))
        | otherwise = [bi]
      bis = if null gh.locator then maybe [] (: []) start' else walk maxHeadersResults start'
      hdrs = [(h, VarInt 0) | Just h <- map (e.headerOf . (.hash)) bis]
      lastSent = case bis of
        [] -> e.tip.hash
        _ -> (last bis).hash
  modifyBlocks $ \b -> b {bestHeaderSent = Just lastSent}
  send (MHeaders (Headers hdrs)) $ netProcessing 4704 "headers"

-- | @FindForkInGlobalIndex@: the height of the first locator entry on the
-- active chain, or of the genesis block when none is.
forkHeight :: Env -> BlockLocator -> BlockHeight
forkHeight e loc =
  case find (.inActiveChain) [bi | Just bi <- map e.lookupBlock loc] of
    Just bi -> bi.height
    Nothing -> 0

-- | @headers@ (line 5066): too many is misbehaviour, then
-- @processHeaders@.
handleHeaders :: Headers -> M ()
handleHeaders (Headers hs) = do
  e <- env
  when e.loadingBlocks $ do
    ignore $ netProcessing 5068 "Unexpected headers message received"
    stop
  when (length hs > maxHeadersResults) $ do
    let c = netProcessing 5076 "headers message size"
    misbehaving c
    ignore c
    stop
  processHeaders False (map fst hs)

-- | @ProcessHeadersMessage@ (line 3216). In order: an empty message ends a
-- low-work sync; a header with bad proof of work or a broken sequence is
-- misbehaviour; a running low-work sync takes the headers; headers that do
-- not connect get a @getheaders@ back; headers of too little work start or
-- feed the low-work sync; then validation, which may punish; then a full
-- message asks for more, the peer's best block moves, and blocks may be
-- fetched at once.
processHeaders :: Bool -> [BlockHeader] -> M ()
processHeaders viaCompact hs = do
  e <- env
  s0 <- getS
  when (null hs) $ do
    modifyBlocks $ \b -> b {lowWorkSync = Nothing, lastGetHeaders = Nothing}
    stop
  let verdict = e.checkHeaders hs
      chained = and (zipWith (\a b -> b.prev == headerHash a) hs (drop 1 hs))
      full = length hs == maxHeadersResults
      lastH = headerHash (last hs)
      firstPrev = case hs of
        (x : _) -> x.prev
        [] -> zeroHash
  when (verdict == HeadersBadPoW) $ do
    let c = netProcessing 2867 "header with invalid proof of work"
    misbehaving c
    ignore c
    stop
  when (not chained || verdict == HeadersNonContinuous) $ do
    let c = netProcessing 2873 "non-continuous headers sequence"
    misbehaving c
    ignore c
    stop
  -- IsContinuationOfLowWorkHeadersSync
  haveSync <- case s0.blocks.lowWorkSync of
    Just chainStart
      | verdict == HeadersLowWork ->
          if full
            then do
              modifyBlocks $ \b -> b {lastGetHeaders = Nothing}
              _ <-
                maybeSendGetHeaders (lastH : e.locatorFrom chainStart) $
                  netProcessing 2944 "more getheaders for low-work headers sync"
              stop
            else do
              modifyBlocks $ \b -> b {lowWorkSync = Nothing}
              ignore $
                cite "src/headerssync.cpp" 103 "Initial headers sync aborted: incomplete headers message"
              stop
      | otherwise -> do
          modifyBlocks $ \b -> b {lowWorkSync = Nothing}
          return False
    Nothing -> return False
  parent <- case e.lookupBlock firstPrev of
    Just p | verdict /= HeadersUnconnected -> return p
    _ -> do
      -- HandleUnconnectingHeaders
      _ <-
        maybeSendGetHeaders (e.locatorFrom e.bestHeader.hash) $
          netProcessing 2903 "received header that does not connect: getheaders"
      updateBlockAvailability lastH
      stop
  modifyBlocks $ \b -> b {lastGetHeaders = Nothing}
  let known = e.lookupBlock lastH
      ancestorOfBest = maybe False (\k -> k.inActiveChain || k.hash == e.bestHeader.hash) known
      alreadyValidated = ancestorOfBest || hasPermission PermNoBan s0
      claimed = parent.work + sum (map headerWork hs)
  threshold <- antiDoSThreshold
  when (not alreadyValidated && (verdict == HeadersLowWork || claimed < threshold)) $ do
    if full
      then do
        modifyBlocks $ \b -> b {lowWorkSync = Just firstPrev, lastGetHeaders = Nothing}
        _ <-
          maybeSendGetHeaders (lastH : e.locatorFrom firstPrev) $
            netProcessing 2944 "initial getheaders for low-work headers sync"
        return ()
      else ignore $ netProcessing 3056 "Ignoring low-work chain"
    stop
  case verdict of
    HeadersInvalid _ -> punish "invalid header received" (netProcessing 2063 "invalid header received")
    HeadersCachedInvalid
      | s0.connectionType /= Inbound && not viaCompact -> do
          let c = netProcessing 2056 "invalid header received (cached invalid)"
          misbehaving c
          ignore c
          stop
      | otherwise -> do
          ignore $ netProcessing 2059 "cached invalid header: not punished"
          stop
    HeadersTimeFuture -> do
      ignore $ netProcessing 2070 "header from the future: not punished"
      stop
    _ -> return ()
  process "headers" $ netProcessing 3339 "ProcessNewBlockHeaders"
  let lastHeight = case verdict of
        HeadersAccepted h -> h
        _ -> parent.height + fromIntegral (length hs)
      lastInfo =
        fromMaybe
          BlockInfo
            { hash = lastH,
              height = lastHeight,
              status = HeaderOnly,
              inActiveChain = False,
              work = claimed,
              time = (last hs).timestamp
            }
          known
      receivedNew = isNothing known
  when (full && not haveSync) $ do
    _ <-
      maybeSendGetHeaders (lastH : e.locatorFrom firstPrev) $
        netProcessing 3364 "more getheaders"
    return ()
  -- UpdatePeerStateForReceivedHeaders
  processBlockAvailability
  raiseBestKnown lastInfo
  when (receivedNew && lastInfo.work > e.tip.work) $ do
    t <- now
    modifyBlocks $ \b -> b {lastBlockAnnouncement = Just t}
  o <- opts
  s1 <- getS
  bestWork <- fromMaybe lastInfo.work <$> bestKnownWork
  when
    ( e.initialBlockDownload
        && not full
        && bestWork < o.minimumChainWork
        && s1.connectionType `elem` [OutboundFullRelay, BlockRelayOnly]
    )
    $ do
      disconnect Unsuitable $
        netProcessing 3196 "outbound peer headers chain has insufficient work"
      stop
  when
    ( s1.connectionType == OutboundFullRelay
        && e.otherProtectedOutbound < 4
        && bestWork >= e.tip.work
        && not s1.blocks.chainSync.protect
    )
    $ modifyBlocks
    $ \b -> b {chainSync = b.chainSync {protect = True}}
  headersDirectFetch lastInfo (zip hs (scanl1 (+) (map headerWork hs)))
  where
    punish :: String -> Cite -> M ()
    punish _ c = do
      misbehaving c
      ignore c
      stop

-- | @HeadersDirectFetchBlocks@ (line 3099): when the tip is recent and
-- the new headers lead to more work, ask at once for up to 16 of their
-- blocks that the node lacks, oldest first, as one @getdata@. A lone block
-- from a peer that offers compact blocks is asked as a compact block when
-- nothing else is in flight.
headersDirectFetch :: BlockInfo -> [(BlockHeader, Integer)] -> M ()
headersDirectFetch lastInfo _ = do
  e <- env
  o <- opts
  direct <- canDirectFetch
  when (direct && lastInfo.status /= Invalid && e.tip.work <= lastInfo.work) $ do
    s <- getS
    let walk acc h n
          | n > maxBlocksInTransitPerPeer = (acc, False)
          | otherwise = case e.lookupBlock h of
              Just bi | bi.inActiveChain -> (acc, True)
              mbi ->
                let have = maybe False ((== HaveData) . (.status)) mbi
                    requested =
                      any ((== h) . (.block)) s.blocks.inFlight || e.inFlightElsewhere h > 0
                    acc' = if have || requested then acc else h : acc
                 in case e.headerOf h of
                      Just hd -> walk acc' hd.prev (length acc' + if have || requested then n else n)
                      Nothing -> (acc', False)
        (toFetch, reached) = walk [] lastInfo.hash (0 :: Int)
    if not reached
      then ignore $ netProcessing 3123 "Large reorg, won't direct fetch"
      else do
        let budget = maxBlocksInTransitPerPeer - length s.blocks.inFlight
            chosen = take (max 0 budget) toFetch
        forM_ chosen $ \h -> blockRequested h Nothing
        unless (null chosen) $ do
          let invs = map (blockRequest s) chosen
              compact =
                not o.blocksOnly
                  && s.blocks.providesCmpct
                  && length chosen == 1
                  && e.otherBlocksInFlight + length s.blocks.inFlight == 0
              invs' = case chosen of
                [BlockHash one] | compact -> [InvVector InvCompactBlock one]
                _ -> invs
          send (MGetData (GetData invs')) $ netProcessing 3154 "headers direct fetch"

-- | @getblocks@ (line 4495): queue up to 500 hashes of the active chain
-- after the fork point, to go out as @inv@ at the next pass. The 500th
-- becomes the continuation block.
handleGetBlocks :: GetBlocks -> M ()
handleGetBlocks gb = do
  e <- env
  o <- opts
  when (length gb.locator > maxLocatorSz) $ do
    disconnect ProtocolViolation $ netProcessing 4501 "getblocks locator size too large"
    stop
  let first = forkHeight e gb.locator + 1
      pruneFloor = fromIntegral e.tip.height - 282 :: Integer
      go n h acc
        | n <= 0 = (reverse acc, Nothing)
        | otherwise = case e.blockAtHeight h of
            Nothing -> (reverse acc, Nothing)
            Just bi
              | bi.hash == gb.stop -> (reverse acc, Nothing)
              | o.prune && (bi.status /= HaveData || fromIntegral bi.height <= pruneFloor) ->
                  (reverse acc, Nothing)
              | n == 1 -> (reverse (bi.hash : acc), Just bi.hash)
              | otherwise -> go (n - 1 :: Int) (h + 1) (bi.hash : acc)
      (hashes, cont) = go 500 first []
  modifyBlocks $ \b ->
    b
      { forInvRelay = b.forInvRelay ++ hashes,
        continuationBlock = maybe b.continuationBlock Just cont
      }

-- | @ProcessGetBlockData@ (line 2564): one block entry of a @getdata@.
-- Unknown and unservable blocks get no answer at all, not even
-- @notfound@.
getBlockData :: InvVector -> M ()
getBlockData iv = do
  s <- getS
  e <- env
  o <- opts
  let h = BlockHash iv.invHash
      filtered = iv.invType == InvMerkleBlock
  when (filtered && s.ourServices .&. nodeBloom == 0) $ do
    disconnect ProtocolViolation $
      netProcessing 2570 "filtered block request received when NODE_BLOOM service disabled"
    stop
  bi <- case e.lookupBlock h of
    Nothing -> do
      ignore $ netProcessing 2613 "getdata for an unknown block"
      stop
    Just x -> return x
  ok <- blockRequestAllowed bi
  unless ok $ do
    ignore $ netProcessing 2616 "ignoring request for old block that isn't in the main chain"
    stop
  let historical = fromIntegral e.bestHeader.time - fromIntegral bi.time > (7 * 86400 :: Integer)
  when
    ( o.maxUploadTarget > 0
        && e.historicalUploadTargetReached
        && (historical || filtered)
        && not (hasPermission PermDownload s)
    )
    $ do
      disconnect Resources $ netProcessing 2625 "historical block serving limit reached"
      stop
  let limited = s.ourServices .&. nodeNetworkLimited /= 0 && s.ourServices .&. nodeNetwork == 0
      depth = fromIntegral e.tip.height - fromIntegral bi.height :: Integer
  when
    ( not (hasPermission PermNoBan s)
        && limited
        && depth > fromIntegral nodeNetworkLimitedMinBlocks + 2
    )
    $ do
      disconnect Resources $
        netProcessing 2635 "Ignore block request below NODE_NETWORK_LIMITED threshold"
      stop
  when (bi.status /= HaveData) $ do
    ignore $ netProcessing 2641 "getdata for a block without data"
    stop
  blk <- case e.blockData h of
    Nothing -> do
      disconnect Resources $ netProcessing 2674 "Block was pruned before it could be read"
      stop
    Just b -> return b
  direct <- canDirectFetch
  case iv.invType of
    InvBlock -> send (MBlock (stripWitness blk)) $ netProcessing 2681 "block without witness"
    InvWitnessBlock -> send (MBlock blk) $ netProcessing 2683 "block with witness"
    InvMerkleBlock ->
      case s.txRelay >>= (.bloomFilter) of
        Nothing -> ignore $ netProcessing 2694 "filtered block request without a filter"
        Just bf -> case e.filteredBlock bf h of
          Nothing -> ignore $ netProcessing 2694 "filtered block request without a filter"
          Just (mb, txs, bf') -> do
            modifyTxRelay $ \r -> r {bloomFilter = Just bf'}
            send (MMerkleBlock mb) $ netProcessing 2695 "merkleblock"
            forM_ txs $ \tx ->
              send (MTx (stripTx tx)) $ netProcessing 2703 "matched transaction of merkleblock"
    InvCompactBlock
      | direct && fromIntegral bi.height >= (fromIntegral e.tip.height - maxCmpctBlockDepth :: Int) ->
          case e.compactBlockOf h of
            Just cb -> send (MCompactBlock cb) $ netProcessing 2717 "cmpctblock"
            Nothing -> send (MBlock blk) $ netProcessing 2720 "block instead of cmpctblock"
      | otherwise -> send (MBlock blk) $ netProcessing 2720 "block instead of cmpctblock"
    _ -> return ()
  s' <- getS
  when (s'.blocks.continuationBlock == Just h) $ do
    let BlockHash th = e.tip.hash
    send (MInv (Inv [InvVector InvBlock th])) $ netProcessing 2734 "continuation inv of getblocks"
    modifyBlocks $ \b -> b {continuationBlock = Nothing}
  where
    stripTx tx = tx {witness = []}
    stripWitness b = b {txs = map stripTx b.txs}

-- | @block@ (line 5104). A block that does not match its own merkle root
-- or witness commitment is misbehaviour when its parent is known. The
-- block goes to validation, which reports through @BlockChecked@: an
-- invalid block from this peer is punished by @MaybePunishNodeForBlock@.
handleBlock :: Block -> M ()
handleBlock blk = do
  e <- env
  when e.loadingBlocks $ do
    ignore $ netProcessing 5108 "Unexpected block message received"
    stop
  let h = headerHash blk.header
      verdict = e.checkBlock blk
      parentKnown = isJust (e.lookupBlock blk.header.prev)
  when (parentKnown && verdict == BlockMutated) $ do
    let c = netProcessing 5123 "mutated block"
    misbehaving c
    removeBlockRequest h
    ignore c
    stop
  removeBlockRequest h
  processBlock False verdict h

-- | @ProcessBlock@ and @BlockChecked@ (lines 3680 and 2328): hand the
-- block to validation and judge the verdict. A block from a compact block
-- reconstruction is judged leniently.
processBlock :: Bool -> BlockVerdict -> BlockHash -> M ()
processBlock viaCompact verdict _ = do
  process "block" $ netProcessing 3683 "ProcessNewBlock"
  s <- getS
  case verdict of
    BlockAccepted -> return ()
    BlockDuplicate -> return ()
    BlockInvalid blame _
      | blame && not viaCompact -> misbehaving $ netProcessing 2047 "invalid block (consensus)"
      | otherwise -> return ()
    BlockMutated
      | not viaCompact -> misbehaving $ netProcessing 2047 "invalid block (mutated)"
      | otherwise -> return ()
    BlockCachedInvalid
      | not viaCompact && s.connectionType /= Inbound ->
          misbehaving $ netProcessing 2056 "invalid block (cached invalid)"
      | otherwise -> return ()
    BlockMissingParent -> misbehaving $ netProcessing 2067 "invalid block (missing parent)"

-- | @cmpctblock@ (line 4785). Ignored in blocks-only mode and from a peer
-- that never offered compact blocks. A block the node did not ask for is
-- taken only from a peer it chose for high bandwidth. When the block is
-- near the tip, the node tries to rebuild it from its mempool and asks for
-- the missing transactions with @getblocktxn@; a block too far ahead is
-- treated as an announcement of its header.
handleCmpctBlock :: CompactBlock -> M ()
handleCmpctBlock cb = do
  e <- env
  o <- opts
  s <- getS
  when e.loadingBlocks $ do
    ignore $ netProcessing 4789 "Unexpected cmpctblock message received"
    stop
  when o.blocksOnly $ do
    ignore $ netProcessing 4791 "cmpctblock in blocks-only mode"
    stop
  unless s.blocks.providesCmpct $ do
    ignore $ netProcessing 4799 "cmpctblock from a peer that did not send sendcmpct"
    stop
  let hdr = cb.header
      h = headerHash hdr
  prev <- case e.lookupBlock hdr.prev of
    Nothing -> do
      if not e.initialBlockDownload
        then do
          ok <-
            maybeSendGetHeaders (e.locatorFrom e.bestHeader.hash) $
              netProcessing 4817 "cmpctblock that does not connect: getheaders"
          unless ok $ ignore $ netProcessing 4819 "cmpctblock that does not connect"
        else ignore $ netProcessing 4819 "cmpctblock that does not connect"
      stop
    Just p -> return p
  threshold <- antiDoSThreshold
  let work = prev.work + headerWork hdr
  when (work < threshold) $ do
    ignore $ netProcessing 4822 "Ignoring low-work compact block"
    stop
  let known = e.lookupBlock h
      receivedNew = isNothing known
  case e.checkHeaders [hdr] of
    HeadersInvalid _ -> punishCompact
    HeadersBadPoW -> punishCompact
    HeadersNonContinuous -> punishCompact
    HeadersUnconnected -> punishCompact
    HeadersCachedInvalid -> do
      ignore $ netProcessing 2059 "cached invalid header via cmpctblock: not punished"
      stop
    HeadersTimeFuture -> do
      ignore $ netProcessing 2070 "header from the future via cmpctblock: not punished"
      stop
    _ -> return ()
  let info =
        fromMaybe
          BlockInfo
            { hash = h,
              height = prev.height + 1,
              status = HeaderOnly,
              inActiveChain = False,
              work = work,
              time = hdr.timestamp
            }
          known
  processBlockAvailability
  raiseBestKnown info
  when (receivedNew && work > e.tip.work) $ do
    t <- now
    modifyBlocks $ \b -> b {lastBlockAnnouncement = Just t}
  when (info.status == HaveData) $ do
    ignore $ netProcessing 4870 "cmpctblock for a block the node has"
    stop
  s1 <- getS
  let elsewhere = e.inFlightElsewhere h
      mine = find ((== h) . (.block)) s1.blocks.inFlight
      fromThisPeer = isJust mine
      alreadyInFlight = elsewhere + (if fromThisPeer then 1 else 0)
      firstInFlight = alreadyInFlight == 0 || (fromThisPeer && elsewhere == 0)
  when (not fromThisPeer && not s1.blocks.highBandwidthTo) $ do
    ignore $ netProcessing 4889 "unsolicited compact block"
    stop
  when (work <= e.tip.work) $ do
    if fromThisPeer
      then send (MGetData (GetData [blockRequest s1 h])) $ netProcessing 4899 "getdata for a block with less work"
      else ignore $ netProcessing 4901 "compact block with less work than the tip"
    stop
  direct <- canDirectFetch
  when (alreadyInFlight == 0 && not direct) $ do
    ignore $ netProcessing 4906 "compact block while the tip is old"
    stop
  if fromIntegral info.height <= (fromIntegral e.tip.height + 2 :: Integer)
    then
      if (alreadyInFlight < maxCmpctBlocksInflightPerBlock && length s1.blocks.inFlight < maxBlocksInTransitPerPeer)
        || fromThisPeer
        then do
          case mine of
            Just ifl | isJust ifl.partial -> do
              ignore $ netProcessing 4921 "already syncing this compact block"
              stop
            Just _ -> modifyBlocks $ \b -> b {inFlight = map (setPartial h) b.inFlight}
            Nothing -> blockRequested h (Just cb)
          case e.initCompact cb of
            CompactInvalid -> do
              removeBlockRequest h
              let c = netProcessing 4929 "invalid compact block"
              misbehaving c
              ignore c
            CompactFailed
              | firstInFlight ->
                  send (MGetData (GetData [blockRequest s1 h])) $
                    netProcessing 4936 "compact block failed to reconstruct: getdata"
              | otherwise -> do
                  removeBlockRequest h
                  ignore $ netProcessing 4939 "compact block failed to reconstruct"
            CompactComplete blk -> completeFromCompact h blk
            CompactMissing idx
              | firstInFlight ->
                  send (MGetBlockTxn (GetBlockTxn h idx)) $ netProcessing 4955 "getblocktxn"
              | s1.blocks.highBandwidthTo
                  && (s1.connectionType /= Inbound || alreadyInFlight < maxCmpctBlocksInflightPerBlock - 1) ->
                  send (MGetBlockTxn (GetBlockTxn h idx)) $ netProcessing 4965 "getblocktxn (parallel)"
              | otherwise -> do
                  removeBlockRequest h
                  ignore $ netProcessing 4968 "compact block: not asking for transactions"
        else case e.initCompact cb of
          CompactComplete blk -> do
            process "block from compact block" $ netProcessing 5036 "ProcessBlock (reconstructed)"
            processBlock True (e.checkBlock blk) h
          _ -> ignore $ netProcessing 4980 "compact block failed optimistic reconstruction"
    else
      if fromThisPeer
        then send (MGetData (GetData [blockRequest s1 h])) $ netProcessing 4996 "getdata for a compact block far ahead"
        else processHeaders True [hdr]
  where
    setPartial h ifl
      | ifl.block == h = ifl {partial = Just cb, filled = False}
      | otherwise = ifl
    punishCompact = do
      let c = netProcessing 2063 "invalid header via cmpctblock"
      misbehaving c
      ignore c
      stop

-- | A block rebuilt from a compact block and its transactions goes to
-- validation, judged as coming through a compact block.
completeFromCompact :: BlockHash -> Block -> M ()
completeFromCompact h blk = do
  e <- env
  removeBlockRequest h
  processBlock True (e.checkBlock blk) h

-- | @getblocktxn@ (line 4560): the transactions of a recent block, or the
-- whole block when it is more than 10 blocks deep. An empty list of
-- positions closes the connection; a position past the end is
-- misbehaviour.
handleGetBlockTxn :: GetBlockTxn -> M ()
handleGetBlockTxn req = do
  e <- env
  when (null req.indexes) $ do
    disconnect ProtocolViolation $ netProcessing 4567 "getblocktxn received with no transaction indexes"
    stop
  bi <- case e.lookupBlock req.hash of
    Just bi | bi.status == HaveData -> return bi
    _ -> do
      ignore $ netProcessing 4595 "getblocktxn for a block we don't have"
      stop
  if fromIntegral bi.height >= (fromIntegral e.tip.height - maxBlockTxnDepth :: Int)
    then case e.blockData req.hash of
      Nothing -> ignore $ netProcessing 4595 "getblocktxn for a block we don't have"
      Just blk -> do
        let n = fromIntegral (length blk.txs) :: Word32
        if any (>= n) req.indexes
          then do
            let c = netProcessing 2849 "getblocktxn with out-of-bounds tx indices"
            misbehaving c
            ignore c
          else
            send (MBlockTxn (BlockTxn req.hash [blk.txs !! fromIntegral i | i <- req.indexes])) $
              netProcessing 2860 "blocktxn"
    else getBlockData (InvVector InvWitnessBlock req.hash.get)

-- | @blocktxn@ (line 5049) and @ProcessCompactBlockTxns@ (line 3697).
handleBlockTxn :: BlockTxn -> M ()
handleBlockTxn bt = do
  e <- env
  s <- getS
  when e.loadingBlocks $ do
    ignore $ netProcessing 5054 "Unexpected blocktxn message received"
    stop
  let h = bt.hash
      elsewhere = e.inFlightElsewhere h
  ifl <- case find (\i -> i.block == h && isJust i.partial) s.blocks.inFlight of
    Nothing -> do
      ignore $ netProcessing 3721 "block transactions for block we weren't expecting"
      stop
    Just i -> return i
  when ifl.filled $ do
    removeBlockRequest h
    let c = netProcessing 3732 "previous compact block reconstruction attempt failed"
    misbehaving c
    ignore c
    stop
  let firstInFlight = elsewhere == 0
  case ifl.partial of
    Nothing -> return ()
    Just cb -> case e.fillCompact cb bt.transactions of
      CompactInvalid -> do
        removeBlockRequest h
        let c = netProcessing 3743 "invalid compact block/non-matching block transactions"
        misbehaving c
        ignore c
      CompactComplete blk -> completeFromCompact h blk
      _
        | firstInFlight -> do
            modifyBlocks $ \b -> b {inFlight = map markFilled b.inFlight}
            send (MGetData (GetData [blockRequest s h])) $
              netProcessing 3753 "compact block failed to reconstruct: getdata"
        | otherwise -> do
            removeBlockRequest h
            ignore $ netProcessing 3756 "compact block failed to reconstruct"
  where
    markFilled i
      | i.block == bt.hash = i {filled = True}
      | otherwise = i

-- | @PrepareBlockFilterRequest@ (line 3518): the checks that every BIP 157
-- request passes. Every failure closes the connection, without
-- discouragement.
prepareFilterRequest :: Word32 -> Maybe Word32 -> BlockHash -> Int -> M ()
prepareFilterRequest ftype mstart stopHash maxSize = do
  s <- getS
  e <- env
  when (ftype /= 0 || s.ourServices .&. nodeCompactFilters == 0) $ do
    disconnect ProtocolViolation $ netProcessing 3530 "peer requested unsupported block filter type"
    stop
  stopInfo <- case e.lookupBlock stopHash of
    Nothing -> do
      disconnect ProtocolViolation $ netProcessing 3542 "peer sent getcf* with unknown or old stop hash"
      stop
    Just bi -> do
      ok <- blockRequestAllowed bi
      unless ok $ do
        disconnect ProtocolViolation $ netProcessing 3542 "peer sent getcf* with unknown or old stop hash"
        stop
      return bi
  forM_ mstart $ \start' -> do
    when (start' > stopInfo.height) $ do
      disconnect ProtocolViolation $ netProcessing 3552 "peer sent getcf* with start height above stop height"
      stop
    when (fromIntegral (stopInfo.height - start') >= maxSize) $ do
      disconnect ProtocolViolation $ netProcessing 3558 "peer requested too many cfilters/cfheaders"
      stop

-- | @getcfilters@ (line 3571).
handleGetCFilters :: GetCFilters -> M ()
handleGetCFilters r = do
  prepareFilterRequest (fromIntegral r.filterType) (Just r.startHeight) r.stopHash maxGetCFiltersSize
  e <- env
  case e.blockFilters r of
    Nothing -> ignore $ netProcessing 3589 "failed to find block filter"
    Just fs -> forM_ fs $ \f -> send (MCFilter f) $ netProcessing 3596 "cfilter"

-- | @getcfheaders@ (line 3600).
handleGetCFHeaders :: GetCFHeaders -> M ()
handleGetCFHeaders r = do
  prepareFilterRequest (fromIntegral r.filterType) (Just r.startHeight) r.stopHash maxGetCFHeadersSize
  e <- env
  case e.blockFilterHeaders r of
    Nothing -> ignore $ netProcessing 3624 "failed to find block filter header"
    Just m -> send (MCFHeaders m) $ netProcessing 3635 "cfheaders"

-- | @getcfcheckpt@ (line 3642).
handleGetCFCheckpt :: GetCFCheckpt -> M ()
handleGetCFCheckpt r = do
  prepareFilterRequest (fromIntegral r.filterType) Nothing r.stopHash maxBound
  e <- env
  case e.blockFilterCheckpoint r of
    Nothing -> ignore $ netProcessing 3668 "failed to find block filter header"
    Just m -> send (MCFCheckpt m) $ netProcessing 3674 "cfcheckpt"

-- | @MaybeSendSendHeaders@ (line 5817): once the peer is known to have a
-- block with more than the minimum chain work, tell it to announce blocks
-- with headers. Sent once.
maybeSendSendHeaders :: M ()
maybeSendSendHeaders = do
  s <- getS
  o <- opts
  w <- bestKnownWork
  when (not s.blocks.sentSendHeaders && s.commonVersion >= sendHeadersVersion) $
    forM_ w $ \work ->
      when (work > o.minimumChainWork) $ do
        send MSendHeaders $ netProcessing 5832 "sendheaders"
        modifyBlocks $ \b -> b {sentSendHeaders = True}

-- | Whether the node syncs headers and blocks from the peer
-- (@sync_blocks_and_headers_from_peer@, line 6123): a preferred download
-- peer, or any peer that can serve blocks (not an address fetch) when there
-- is no preferred one or nothing is in flight.
syncFromPeer :: M Bool
syncFromPeer = do
  s <- getS
  e <- env
  return $
    s.blocks.preferredDownload
      || ( canServeBlocks s
             && s.connectionType /= AddrFetch
             && ( e.otherPreferredDownload == 0
                    || e.otherBlocksInFlight + length s.blocks.inFlight == 0
                )
         )

-- | The initial @getheaders@ (line 6146): to the first peer to sync from,
-- or to every peer once the best header is less than a day old. It starts
-- the headers sync timeout.
initialGetHeaders :: M ()
initialGetHeaders = do
  s <- getS
  e <- env
  o <- opts
  sync <- syncFromPeer
  when (not s.blocks.syncStarted && canServeBlocks s && not e.loadingBlocks)
    $ when
      ( (e.otherSyncStarted == 0 && sync)
          || fromIntegral e.bestHeader.time > e.now `div` 1000000 - 86400
      )
    $ do
      let startFrom = maybe e.bestHeader.hash (.prev) (e.headerOf e.bestHeader.hash)
          startHash = if e.bestHeader.height == 0 then e.bestHeader.hash else startFrom
      sent <- maybeSendGetHeaders (e.locatorFrom startHash) $ netProcessing 6159 "initial getheaders"
      when sent $ do
        let behind = max 0 (e.now `div` 1000000 - fromIntegral e.bestHeader.time)
            spacing = max 1 (fromIntegral o.network.targetSpacing)
            timeout =
              e.now + headersDownloadTimeoutBase + headersDownloadTimeoutPerHeader * behind `div` spacing
        modifyBlocks $ \b -> b {syncStarted = True, headersSyncTimeout = Just timeout}

-- | The block announcements of @SendMessages@ (lines 6178 to 6325): the
-- new blocks queued by 'newTip' go out as one @cmpctblock@ to a peer that
-- asked for high-bandwidth compact blocks, as @headers@ to a peer that
-- sent @sendheaders@, and otherwise as an @inv@ of the newest; then the
-- @inv@ of blocks queued by @getblocks@.
sendBlockAnnouncements :: M [InvVector]
sendBlockAnnouncements = do
  e <- env
  s <- getS
  let queue = s.blocks.forHeadersRelay
      b = s.blocks
      revert0 =
        (not b.prefersHeaders && (not b.requestedHbCmpct || length queue > 1))
          || length queue > maxBlocksToAnnounce
  processBlockAvailability
  (revert, hdrs, bestIdx) <-
    if revert0
      then return (True, [], Nothing)
      else collect e queue
  revert' <-
    if not revert && not (null hdrs)
      then case bestIdx of
        Just best
          | length hdrs == 1 && b.requestedHbCmpct -> do
              case e.compactBlockOf best.hash of
                Just cb -> send (MCompactBlock cb) $ netProcessing 6262 "sending header-and-ids"
                Nothing -> return ()
              modifyBlocks $ \bs -> bs {bestHeaderSent = Just best.hash}
              return False
          | b.prefersHeaders -> do
              send (MHeaders (Headers [(h, VarInt 0) | h <- hdrs])) $ netProcessing 6275 "headers announcement"
              modifyBlocks $ \bs -> bs {bestHeaderSent = Just best.hash}
              return False
        _ -> return True
      else return revert
  when (revert' && not (null queue)) $ do
    let lastHash = last queue
    case e.lookupBlock lastHash of
      Just bi -> do
        has <- peerHasHeader bi
        unless has $ modifyBlocks $ \bs -> bs {forInvRelay = bs.forInvRelay ++ [lastHash]}
      Nothing -> return ()
  modifyBlocks $ \bs -> bs {forHeadersRelay = []}
  s' <- getS
  let invs = [InvVector InvBlock h | BlockHash h <- s'.blocks.forInvRelay]
  modifyBlocks $ \bs -> bs {forInvRelay = []}
  return invs
  where
    collect :: Env -> [BlockHash] -> M (Bool, [BlockHeader], Maybe BlockInfo)
    collect e queue = go queue Nothing False []
      where
        go [] best _ acc = return (False, reverse acc, best)
        go (h : rest) best found acc =
          case e.lookupBlock h of
            Nothing -> return (True, [], Nothing)
            Just bi
              | not bi.inActiveChain -> return (True, [], Nothing)
              | otherwise -> do
                  let hdr = e.headerOf h
                      chainsOn = case (best, hdr) of
                        (Just p, Just hd) -> hd.prev == p.hash
                        (Just _, Nothing) -> False
                        (Nothing, _) -> True
                  if not chainsOn
                    then return (True, [], Nothing)
                    else
                      if found
                        then go rest (Just bi) True (maybe acc (: acc) hdr)
                        else do
                          has <- peerHasHeader bi
                          if has
                            then go rest (Just bi) False acc
                            else do
                              parentHas <- case hdr >>= e.lookupBlock . (.prev) of
                                Nothing -> return (bi.height == 0)
                                Just p -> peerHasHeader p
                              if parentHas
                                then go rest (Just bi) True (maybe acc (: acc) hdr)
                                else return (True, [], Nothing)

-- | The block timers of @SendMessages@ (lines 6440 to 6501): a stalling
-- peer, a block that takes too long, and a headers sync that takes too
-- long. A peer with 'PermNoBan' is not disconnected for the last one: its
-- sync starts over with another peer.
blockTimeouts :: M ()
blockTimeouts = do
  s <- getS
  e <- env
  o <- opts
  t <- now
  forM_ s.blocks.stallingSince $ \since ->
    when (since < t - blockStallingTimeoutDefault) $ do
      disconnect Timeout $ netProcessing 6446 "Peer is stalling block download"
      stop
  unless (null s.blocks.inFlight) $ do
    let spacing = seconds (fromIntegral o.network.targetSpacing)
        allowed = spacing + (spacing * fromIntegral e.otherPeersDownloading) `div` 2
    when (t > s.blocks.downloadingSince + allowed) $ do
      disconnect Timeout $ netProcessing 6465 "Timeout downloading block"
      stop
  when s.blocks.syncStarted $
    forM_ s.blocks.headersSyncTimeout $ \deadline ->
      if fromIntegral e.bestHeader.time <= t `div` 1000000 - 86400
        then
          when (t > deadline && e.otherSyncStarted == 0 && e.otherPreferredDownload >= 1) $
            if hasPermission PermNoBan s
              then modifyBlocks $ \b -> b {syncStarted = False, headersSyncTimeout = Just 0}
              else do
                disconnect Timeout $ netProcessing 6481 "Timeout downloading headers"
                stop
        else modifyBlocks $ \b -> b {headersSyncTimeout = Nothing}

-- | @ConsiderEviction@ (line 5501): an outbound peer, unless protected,
-- must show a chain with the work of the tip within 20 minutes of falling
-- behind; then it gets a @getheaders@ and 2 more minutes.
considerEviction :: M ()
considerEviction = do
  s <- getS
  e <- env
  t <- now
  let cs = s.blocks.chainSync
      outbound = s.connectionType `elem` [OutboundFullRelay, BlockRelayOnly]
  when (not cs.protect && outbound && s.blocks.syncStarted) $ do
    w <- bestKnownWork
    let workHeaderWork = cs.workHeader >>= e.lookupBlock >>= Just . (.work)
    if
      | maybe False (>= e.tip.work) w ->
          when (cs.timeout /= 0) $
            setChainSync (ChainSync 0 Nothing False cs.protect)
      | cs.timeout == 0 || (isJust workHeaderWork && isJust w && w >= workHeaderWork) ->
          setChainSync (ChainSync (t + chainSyncTimeout) (Just e.tip.hash) False cs.protect)
      | cs.timeout > 0 && t > cs.timeout ->
          if cs.sentGetHeaders
            then disconnect Unsuitable $ netProcessing 5538 "Outbound peer has old chain"
            else do
              let from = fromMaybe e.tip.hash (cs.workHeader >>= e.headerOf >>= Just . (.prev))
              _ <-
                maybeSendGetHeaders (e.locatorFrom from) $
                  netProcessing 5545 "sending getheaders to outbound peer to verify chain work"
              setChainSync cs {sentGetHeaders = True, timeout = t + headersResponseTime}
      | otherwise -> return ()
  where
    setChainSync c = modifyBlocks $ \b -> b {chainSync = c}

-- | @UpdatedBlockTip@ (line 2290): outside initial block download, queue
-- up to 8 of the new blocks for announcement to the peer.
newTip :: [BlockHeader] -> M ()
newTip hdrs = do
  e <- env
  unless e.initialBlockDownload $ do
    let hashes = reverse (take maxBlocksToAnnounce (reverse (map headerHash hdrs)))
    modifyBlocks $ \b -> b {forHeadersRelay = b.forHeadersRelay ++ hashes}

-- | @NewPoWValidBlock@ (line 2235): a new block that extends the tip goes
-- at once as @cmpctblock@ to a peer that asked for high-bandwidth compact
-- blocks, has the parent and not the block, before full validation.
newPoWValidBlock :: BlockHeader -> M ()
newPoWValidBlock hdr = do
  s <- getS
  e <- env
  let h = headerHash hdr
  when (s.successfullyConnected && s.commonVersion >= invalidCbNoBanVersion && s.blocks.requestedHbCmpct) $ do
    hasBlock <- maybe (return False) peerHasHeader (e.lookupBlock h)
    hasParent <- case e.lookupBlock hdr.prev of
      Just p -> peerHasHeader p
      Nothing -> return False
    when (not hasBlock && hasParent) $
      forM_ (e.compactBlockOf h) $ \cb -> do
        send (MCompactBlock cb) $ netProcessing 2280 "NewPoWValidBlock sending header-and-ids"
        modifyBlocks $ \b -> b {bestHeaderSent = Just h}

-- | @MaybeSetPeerAsAnnouncingHeaderAndIDs@ (line 1372): the node chose the
-- peer as one of its three high-bandwidth compact block peers, or dropped
-- it. Only for a peer that offered compact blocks, outside blocks-only.
highBandwidth :: Bool -> M ()
highBandwidth on = do
  s <- getS
  o <- opts
  when (s.successfullyConnected && s.blocks.providesCmpct && not o.blocksOnly && on /= s.blocks.highBandwidthTo) $ do
    send (MSendCompact (SendCompact on cmpctBlocksVersion)) $
      if on
        then netProcessing 1412 "sendcmpct high bandwidth"
        else netProcessing 1422 "sendcmpct low bandwidth (displaced)"
    modifyBlocks $ \b -> b {highBandwidthTo = on}

-- | The node asks the peer for a block (@FindNextBlocksToDownload@ and
-- @BlockRequested@, line 6534, or @FetchBlock@). Ignored when 16 blocks
-- are already in flight, the peer cannot serve blocks, or the handshake is
-- not done.
requestBlock :: BlockHash -> M ()
requestBlock h = do
  s <- getS
  when (s.successfullyConnected && canServeBlocks s && length s.blocks.inFlight < maxBlocksInTransitPerPeer) $
    unless (any ((== h) . (.block)) s.blocks.inFlight) $ do
      blockRequested h Nothing
      send (MGetData (GetData [blockRequest s h])) $ netProcessing 6562 "getdata for blocks"

-- | The block download waits on this peer (line 6541).
markStalling :: M ()
markStalling = do
  t <- now
  s <- getS
  when (isNothing s.blocks.stallingSince && not (null s.blocks.inFlight)) $
    modifyBlocks $
      \b -> b {stallingSince = Just t}
