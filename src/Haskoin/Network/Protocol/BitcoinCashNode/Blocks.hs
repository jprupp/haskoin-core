{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCashNode.Blocks
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- How Bitcoin Cash Node 29.2.0 moves headers and blocks with one peer:
-- @getheaders@, @headers@, @getblocks@, the block part of @getdata@,
-- @block@, @sendheaders@, @sendcmpct@, @cmpctblock@, @getblocktxn@,
-- @blocktxn@, the announcements of new blocks, and the timers of block
-- download.
--
-- The code base of Bitcoin Cash Node is close to Bitcoin Core 0.19 here:
-- there is no anti-DoS headers pre-sync, headers of low work are stored as
-- soon as they validate, compact blocks are of version 1 only with 32-bit
-- positions, and an invalid block costs the score that validation gives,
-- unless it came from a compact block.
--
-- What the machine simplifies, and why:
--
-- * Which blocks to download, and from whom, is decided across peers
--   (@FindNextBlocksToDownload@). The rest of the node says it with
--   'RequestBlock', and the machine requests the block at the next pass of
--   @SendMessages@. The direct fetch after a @headers@ message is local to
--   the peer and is modelled.
-- * The block index is the t'Env'. After a @headers@ or @cmpctblock@ that
--   validation accepts, the machine looks the header up in 'lookupBlock'; a
--   caller should answer for headers that its 'checkHeaders' accepts. When it
--   does not, the machine assumes the header has one unit of work per block
--   of height above the tip.
-- * A header's ancestry is found by walking 'headerOf' back, at most 2016
--   steps; blocks of the active chain are found by height.
-- * The count of outbound peers protected from the chain-sync check (at most
--   4) is global, and the machine assumes there is room.
module Haskoin.Network.Protocol.BitcoinCashNode.Blocks
  ( -- * Messages
    receiveSendHeaders,
    receiveSendCmpct,
    receiveBlockInv,
    afterInv,
    receiveGetHeaders,
    receiveHeaders,
    receiveGetBlocks,
    receiveGetBlockTxn,
    receiveBlock,
    receiveCmpctBlock,
    receiveBlockTxn,
    getBlockData,

    -- * Notifications
    updatedBlockTip,
    newPoWValidBlock,
    highBandwidth,
    requestBlock,
    stalling,

    -- * SendMessages
    initialGetHeaders,
    blockAnnouncements,
    downloadTimers,
    considerEviction,
    blockRequests,

    -- * Chain helpers
    locatorOf,
    blockInfoOf,
  )
where

import Control.Monad (forM_, unless, when)
import Control.Monad.RWS.Strict (get, gets, modify')
import Data.Bits ((.&.))
import Data.Int (Int64)
import Data.Maybe (fromMaybe, isJust, isNothing, mapMaybe)
import Haskoin.Block.Common
  ( Block (..),
    BlockHash (..),
    BlockHeader (..),
    BlockHeight,
    GetBlocks (..),
    GetHeaders (..),
    Headers (..),
    headerHash,
  )
import Haskoin.Block.Merkle (MerkleBlock (..), buildPartialMerkle)
import Haskoin.Network.Bloom (bloomRelevantBlock)
import Haskoin.Network.Common
  ( GetData (..),
    Inv (..),
    InvType (..),
    InvVector (..),
    MessageCommand (..),
    VarInt (..),
  )
import Haskoin.Network.CompactBlock
  ( BlockTxn (..),
    CompactBlock (..),
    GetBlockTxn (..),
    SendCompact (..),
  )
import Haskoin.Network.Data (Network (..))
import Haskoin.Network.Message (Message (..))
import Haskoin.Network.Protocol.BitcoinCashNode.Constants
import Haskoin.Network.Protocol.BitcoinCashNode.Options (Options (..))
import Haskoin.Network.Protocol.BitcoinCashNode.State
import Haskoin.Network.Protocol.Types
import Haskoin.Transaction.Common (txHash)

-- * Chain helpers

-- | What the node knows of a block, or what it assumes of a header that
-- validation accepted but the t'Env' does not know: the height given, and one
-- unit of work per block above the tip.
blockInfoOf :: Env -> BlockHeader -> BlockHeight -> BlockInfo
blockInfoOf e h height =
  fromMaybe synth (e.lookupBlock hash)
  where
    hash = headerHash h
    synth =
      BlockInfo
        { hash = hash,
          height = height,
          status = HeaderOnly,
          inActiveChain = False,
          work = e.tip.work + fromIntegral height - fromIntegral e.tip.height,
          time = h.timestamp
        }

-- | The parent of a block, if the node knows it.
parentOf :: Env -> BlockInfo -> Maybe BlockInfo
parentOf e b
  | b.inActiveChain && b.height > 0 = e.blockAtHeight (b.height - 1)
  | otherwise = e.headerOf b.hash >>= e.lookupBlock . (.prev)

-- | The ancestor of a block at a height (@CBlockIndex::GetAncestor@), found
-- by height on the active chain and by walking parents elsewhere.
ancestorAt :: Env -> BlockHeight -> BlockInfo -> Maybe BlockInfo
ancestorAt e h b
  | h > b.height = Nothing
  | b.inActiveChain = e.blockAtHeight h
  | otherwise = go (2016 :: Int) b
  where
    go 0 _ = Nothing
    go n x
      | x.height == h = Just x
      | x.inActiveChain = e.blockAtHeight h
      | otherwise = parentOf e x >>= go (n - 1)

-- | Is the first block an ancestor of the second, or the same?
isAncestorOf :: Env -> BlockInfo -> BlockInfo -> Bool
isAncestorOf e a b = ((.hash) <$> ancestorAt e a.height b) == Just a.hash

-- | The locator of a block (@CChain::GetLocator@): ten steps back one at a
-- time, then steps that double, and the genesis block.
locatorOf :: Env -> BlockInfo -> [BlockHash]
locatorOf e b = go b.height (1 :: BlockHeight) (0 :: Int)
  where
    go h stp n =
      case ancestorAt e h b of
        Nothing -> genesis
        Just x
          | h == 0 -> [x.hash]
          | otherwise ->
              let stp' = if n + 1 > 10 then stp * 2 else stp
                  h' = if stp' >= h then 0 else h - stp'
               in x.hash : go h' stp' (n + 1)
    genesis = maybe [] (\g -> [g.hash]) (e.blockAtHeight 0)

-- | The block of the active chain after the fork with a locator
-- (@FindForkInGlobalIndex@, @src\/validation.cpp:311-328@, then
-- @ChainActive().Next@): the first locator hash on the active chain, the
-- tip when a hash descends from it, else the genesis block.
startAfterFork :: Env -> [BlockHash] -> Maybe BlockInfo
startAfterFork e locator = e.blockAtHeight (fork.height + 1)
  where
    fork = case mapMaybe pick locator of
      (x : _) -> x
      [] -> fromMaybe e.tip (e.blockAtHeight 0)
    pick h = do
      b <- e.lookupBlock h
      if
        | b.inActiveChain -> Just b
        | isAncestorOf e e.tip b -> Just e.tip
        | otherwise -> Nothing

-- | The tip is recent enough to fetch blocks as they are announced
-- (@CanDirectFetch@, @src\/net_processing.cpp:623-627@): younger than 20
-- block intervals.
canDirectFetch :: Env -> Bool
canDirectFetch e =
  fromIntegral e.tip.time > e.now `div` 1000000 - targetSpacing * 20

-- | The block may be served (@BlockRequestAllowed@,
-- @src\/net_processing.cpp:936-950@): on the active chain, or validated and
-- less than 30 days older than the best header. The proof-equivalent time
-- of upstream is left out.
blockRequestAllowed :: Env -> BlockInfo -> Bool
blockRequestAllowed e b =
  b.inActiveChain
    || ( b.status == HaveData
           && fromIntegral e.bestHeader.time - fromIntegral b.time < staleRelayAge
       )

-- | @ProcessBlockAvailability@ (@src\/net_processing.cpp:514-529@): promote
-- the last unknown hash once the node knows it.
processBlockAvailability :: M ()
processBlockAvailability = do
  e <- env
  bs <- gets (.blocks)
  forM_ bs.lastUnknown $ \h ->
    forM_ (e.lookupBlock h) $ \b ->
      when (b.work > 0) $
        modifyBlocks $ \x ->
          x
            { bestKnown = better x.bestKnown b,
              lastUnknown = Nothing
            }
  where
    better Nothing b = Just b
    better (Just a) b = if b.work >= a.work then Just b else Just a

-- | @UpdateBlockAvailability@ (@src\/net_processing.cpp:532-552@): the peer
-- has this block, so the best block it has may move.
updateBlockAvailability :: BlockHash -> Maybe BlockInfo -> M ()
updateBlockAvailability h known = do
  processBlockAvailability
  e <- env
  case maybe (e.lookupBlock h) Just known of
    Just b | b.work > 0 ->
      modifyBlocks $ \x ->
        x
          { bestKnown = case x.bestKnown of
              Just a | a.work > b.work -> Just a
              _ -> Just b
          }
    _ -> modifyBlocks (\x -> x {lastUnknown = Just h})

-- | @PeerHasHeader@ (@src\/net_processing.cpp:628-639@): the block is an
-- ancestor of the best block the peer has, or of the best header sent to it.
peerHasHeader :: BlockInfo -> M Bool
peerHasHeader b = do
  e <- env
  bs <- gets (.blocks)
  let under = maybe False (isAncestorOf e b)
  return (under bs.bestKnown || under bs.bestHeaderSent)

-- | @MarkBlockAsInFlight@ (@src\/net_processing.cpp:462-506@). Returns false
-- when the block is in flight from this peer already.
markInFlight :: BlockHash -> Bool -> Maybe CompactBlock -> M Bool
markInFlight h validated partialBlock = do
  bs <- gets (.blocks)
  if any ((== h) . (.inFlightHash)) bs.inFlight
    then return False
    else do
      t <- nowM
      modifyBlocks $ \x ->
        x
          { inFlight = x.inFlight <> [InFlight h validated partialBlock],
            downloadingSince = if null x.inFlight then t else x.downloadingSince
          }
      return True

-- | @MarkBlockAsReceived@ for this peer (@src\/net_processing.cpp:413-457@).
-- Returns whether the block was in flight from it.
markReceived :: BlockHash -> M Bool
markReceived h = do
  bs <- gets (.blocks)
  t <- nowM
  case break ((== h) . (.inFlightHash)) bs.inFlight of
    (_, []) -> return False
    (before, _ : after) -> do
      modifyBlocks $ \x ->
        x
          { inFlight = before <> after,
            downloadingSince =
              if null before then max x.downloadingSince t else x.downloadingSince,
            stallingSince = 0
          }
      return True

-- | A @getheaders@ with the locator of the best header and no stop.
getHeadersFrom :: BlockInfo -> Cite -> M ()
getHeadersFrom b c = do
  e <- env
  send (MGetHeaders (GetHeaders (fromIntegral protocolVersion) (locatorOf e b) zeroHash)) c

-- | The null hash, for a @getheaders@ with no stop.
zeroHash :: BlockHash
zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

-- | A @getdata@ for one block.
getDataBlock :: InvType -> BlockHash -> Cite -> M ()
getDataBlock t h = send (MGetData (GetData [InvVector t h.get]))

-- * Messages

-- | @sendheaders@ (@src\/net_processing.cpp:2513-2517@): announce new blocks
-- with @headers@. The payload is not read, and there is no way back.
receiveSendHeaders :: M ()
receiveSendHeaders = modifyBlocks (\b -> b {preferHeaders = True})

-- | @sendcmpct@ (@src\/net_processing.cpp:2520-2535@): only version 1 is
-- known; a later message overrides the high-bandwidth flag.
receiveSendCmpct :: SendCompact -> M ()
receiveSendCmpct sc
  | sc.version == 1 =
      modifyBlocks $ \b ->
        b {providesHeaderAndIds = True, preferHeaderAndIds = sc.announce}
  | otherwise = ignore (netProcessing 2523 "sendcmpct of a version other than 1")

-- | One @MSG_BLOCK@ entry of an @inv@ (@src\/net_processing.cpp:2573-2579@):
-- the peer has the block; an unknown block not in flight anywhere is a
-- candidate for the @getheaders@ that follows the loop. Returns the
-- candidate.
receiveBlockInv :: BlockHash -> M (Maybe BlockHash)
receiveBlockInv h = do
  e <- env
  updateBlockAvailability h Nothing
  bs <- gets (.blocks)
  let known = isJust (e.lookupBlock h)
      requested = e.inFlightElsewhere h > 0 || any ((== h) . (.inFlightHash)) bs.inFlight
  return (if not known && not requested then Just h else Nothing)

-- | After the entries of an @inv@: one @getheaders@ up to the last unknown
-- block (@src\/net_processing.cpp:2616-2619@). No @getdata@ goes out for a
-- block @inv@; the download follows the headers.
afterInv :: Maybe BlockHash -> M ()
afterInv = mapM_ $ \h -> do
  e <- env
  send (MGetHeaders (GetHeaders (fromIntegral protocolVersion) (locatorOf e e.bestHeader) h)) $
    netProcessing 2617 "getheaders after a block inv"

-- | @getheaders@ (@src\/net_processing.cpp:2777-2853@).
receiveGetHeaders :: GetHeaders -> M ()
receiveGetHeaders gh = do
  e <- env
  noban <- hasPerm PermNoBan
  if
    | length gh.locator > maxLocatorSize ->
        disconnect ProtocolViolation (netProcessing 2786 "getheaders locator size")
    | e.initialBlockDownload && not noban ->
        ignore (netProcessing 2793 "Ignoring getheaders: initial block download")
    | null gh.locator ->
        case e.lookupBlock gh.stop of
          Nothing -> ignore (netProcessing 2804 "getheaders for an unknown block")
          Just b
            | not (blockRequestAllowed e b) ->
                ignore (netProcessing 2810 "old block header that isn't in the main chain")
            | otherwise -> reply e (Just b)
    | otherwise -> reply e (startAfterFork e gh.locator)
  where
    reply e start = do
      let blocksFrom = case start of
            Nothing -> []
            Just b
              | b.inActiveChain -> walk e b.height maxHeadersResults
              | otherwise -> [b]
          sent = blocksFrom
          headers = mapMaybe (e.headerOf . (.hash)) sent
      modifyBlocks $ \x ->
        x {bestHeaderSent = Just (if null sent then e.tip else last sent)}
      send (MHeaders (Headers [(h, VarInt 0) | h <- headers])) $
        netProcessing 2852 "headers in reply to getheaders"
    walk e h n
      | n <= 0 = []
      | otherwise = case e.blockAtHeight h of
          Nothing -> []
          Just b
            | b.hash == gh.stop -> [b]
            | otherwise -> b : walk e (h + 1) (n - 1)

-- | @headers@ (@src\/net_processing.cpp:3393-3425@): more than 2000 is
-- misbehaviour; headers from an outbound peer that is not manual are
-- punished more for a known invalid block.
receiveHeaders :: Headers -> M ()
receiveHeaders (Headers hs)
  | length hs > maxHeadersResults =
      misbehaving 20 (netProcessing 3409 "too-many-headers")
  | otherwise = do
      ct <- connType
      processHeaders (map fst hs) (ct /= Inbound && ct /= Manual)

-- | @ProcessHeadersMessage@ (@src\/net_processing.cpp:1606-1865@).
processHeaders :: [BlockHeader] -> Bool -> M ()
processHeaders [] _ = ignore (netProcessing 1615 "empty headers")
processHeaders hs@(first : rest) punishDuplicateInvalid = do
  e <- env
  let lastH = last hs
      lastHash = headerHash lastH
      count = length hs
      continuous = and (zipWith (\a b -> b.prev == headerHash a) hs rest)
  if isNothing (e.lookupBlock first.prev) && count < maxBlocksToAnnounce
    then do
      modifyBlocks (\b -> b {unconnecting = b.unconnecting + 1})
      getHeadersFrom e.bestHeader (netProcessing 1635 "headers that do not connect")
      updateBlockAvailability lastHash Nothing
      n <- gets (.blocks.unconnecting)
      when (n `mod` maxUnconnectingHeaders == 0) $
        misbehaving 20 (netProcessing 1655 "too-many-unconnected-headers")
    else
      if not continuous
        then misbehaving 20 (netProcessing 1665 "disconnected-header")
        else do
          let receivedNew = isNothing (e.lookupBlock lastHash)
          case e.checkHeaders hs of
            HeadersRejected dos r -> invalid e dos r
            HeadersInvalid r -> invalid e 100 r
            HeadersUnconnected -> invalid e 10 "prev-blk-not-found"
            HeadersNonContinuous -> misbehaving 20 (netProcessing 1665 "disconnected-header")
            HeadersLowWork -> accepted e receivedNew count (blockInfoOf e lastH e.tip.height)
            HeadersAccepted height -> accepted e receivedNew count (blockInfoOf e lastH height)
  where
    invalid e dos r = do
      misbehaving dos (netProcessing 1686 r)
      let knownInvalid =
            any
              (\h -> maybe False ((== Invalid) . (.status)) (e.lookupBlock (headerHash h)))
              hs
      when (punishDuplicateInvalid && knownInvalid) $
        disconnect Misbehaviour (netProcessing 1721 "known invalid header from an outbound peer")
    accepted e receivedNew count lastInfo = do
      t <- nowM
      modifyBlocks (\b -> b {unconnecting = 0})
      updateBlockAvailability lastInfo.hash (Just lastInfo)
      when (receivedNew && lastInfo.work > e.tip.work) $
        modifyBlocks (\b -> b {lastBlockAnnouncement = t `div` 1000000})
      when (count == maxHeadersResults) $
        getHeadersFrom lastInfo (netProcessing 1759 "getheaders after 2000 headers")
      directFetch e lastInfo
      ibdCheck e count
      protectCheck e
    directFetch e lastInfo =
      when (canDirectFetch e && lastInfo.status /= Invalid && e.tip.work <= lastInfo.work) $ do
        bs <- gets (.blocks)
        let candidates = reverse hs
            inActive h = maybe False (.inActiveChain) (e.lookupBlock (headerHash h))
            outside = takeWhile (not . inActive) candidates
            reachesChain = length outside < length candidates || parentInChain
            parentInChain = maybe False (.inActiveChain) (e.lookupBlock first.prev)
            wanted h =
              let hh = headerHash h
               in maybe True ((/= HaveData) . (.status)) (e.lookupBlock hh)
                    && e.inFlightElsewhere hh == 0
                    && not (any ((== hh) . (.inFlightHash)) bs.inFlight)
            toFetch = take (maxBlocksInTransitPerPeer + 1) (filter wanted outside)
        if not reachesChain
          then ignore (netProcessing 1789 "Large reorg, won't direct fetch")
          else do
            requested <- fetchEarliestFirst (map headerHash (reverse toFetch))
            unless (null requested) $ do
              nInFlight <- gets (length . (.blocks.inFlight))
              let compact =
                    bs.providesHeaderAndIds
                      && length requested == 1
                      && e.otherBlocksInFlight + nInFlight == 1
                  ty = if compact then InvCompactBlock else InvBlock
              send (MGetData (GetData [InvVector ty h.get | h <- requested])) $
                netProcessing 1822 "direct fetch"
    fetchEarliestFirst [] = return []
    fetchEarliestFirst (h : more) = do
      n <- gets (length . (.blocks.inFlight))
      if n >= maxBlocksInTransitPerPeer
        then return []
        else do
          _ <- markInFlight h True Nothing
          (h :) <$> fetchEarliestFirst more
    ibdCheck e count = do
      o <- options
      ct <- connType
      bk <- gets (.blocks.bestKnown)
      let lowWork = maybe False (\b -> b.work < o.network.minimumChainWork) bk
      when
        ( e.initialBlockDownload
            && count /= maxHeadersResults
            && lowWork
            && ct `elem` [OutboundFullRelay, BlockRelayOnly]
        )
        $ disconnect Unsuitable (netProcessing 1846 "headers chain has insufficient work")
    protectCheck e = do
      s <- get
      case s.blocks.bestKnown of
        Just bk
          | not s.closing
              && s.conn.connectionType == OutboundFullRelay
              && not s.blocks.chainSync.protect
              && bk.work >= e.tip.work ->
              modifyBlocks $ \b -> b {chainSync = b.chainSync {protect = True}}
        _ -> return ()

-- | @getblocks@ (@src\/net_processing.cpp:2649-2727@): up to 500 block
-- hashes after the fork, announced by @inv@ at the next pass, excluding the
-- stop hash; a pruned node stops at blocks it may not have.
receiveGetBlocks :: GetBlocks -> M ()
receiveGetBlocks gb
  | length gb.locator > maxLocatorSize =
      disconnect ProtocolViolation (netProcessing 2656 "getblocks locator size")
  | otherwise = do
      e <- env
      o <- options
      let pruneLimit = fromIntegral e.tip.height - (288 - 3600 `div` targetSpacing)
          go _ Nothing = []
          go n (Just b)
            | b.hash == gb.stop = []
            | o.prune && (b.status /= HaveData || fromIntegral b.height <= pruneLimit) = []
            | n <= 1 = [(b, True)]
            | otherwise = (b, False) : go (n - 1 :: Int) (e.blockAtHeight (b.height + 1))
          found = go 500 (startAfterFork e gb.locator)
      forM_ found $ \(b, isLast) -> do
        modifyBlocks (\x -> x {blockInvs = x.blockInvs <> [b.hash]})
        when isLast $ modifyBlocks (\x -> x {hashContinue = Just b.hash})
      if null found
        then ignore (netProcessing 2717 "getblocks: nothing after the fork")
        else process "block hashes queued for inv" (netProcessing 2717 "PushInventory(MSG_BLOCK)")

-- | @getblocktxn@ (@src\/net_processing.cpp:2730-2775@). Bitcoin Cash Node
-- disconnects a peer that asks for no transaction. For the most recent block
-- it answers at once; for any other block it has, it sends the whole block.
receiveGetBlockTxn :: GetBlockTxn -> M ()
receiveGetBlockTxn g
  | null g.indexes = disconnect ProtocolViolation (netProcessing 2738 "getblocktxn with no indexes")
  | otherwise = do
      e <- env
      case e.recentBlock of
        Just b
          | headerHash b.header == g.hash -> sendBlockTransactions b
        _ -> case e.lookupBlock g.hash of
          Just bi
            | bi.status == HaveData -> getBlockData (InvVector InvBlock g.hash.get)
          _ -> ignore (netProcessing 2761 "getblocktxn for a block we don't have")
  where
    sendBlockTransactions b
      | any (\i -> fromIntegral i >= length b.txs) g.indexes =
          misbehaving 100 (netProcessing 1592 "out-of-bound-tx-index")
      | otherwise =
          send (MBlockTxn (BlockTxn g.hash [b.txs !! fromIntegral i | i <- g.indexes])) $
            netProcessing 1603 "BLOCKTXN"

-- | One block entry of a @getdata@ (@ProcessGetBlockData@,
-- @src\/net_processing.cpp:1235-1476@).
getBlockData :: InvVector -> M ()
getBlockData inv = do
  e <- env
  s <- get
  noban <- hasPerm PermNoBan
  let h = BlockHash inv.invHash
      pruned = s.ourServices .&. nodeNetworkLimited /= 0 && s.ourServices .&. nodeNetwork == 0
  case e.lookupBlock h of
    Nothing -> ignore (netProcessing 1272 "getdata for an unknown block")
    Just b
      | not (blockRequestAllowed e b) ->
          ignore (netProcessing 1274 "old block that isn't in the main chain")
      | e.historicalUploadTargetReached
          && ( fromIntegral e.bestHeader.time - fromIntegral b.time > historicalBlockAge
                 || inv.invType == InvMerkleBlock
             )
          && not noban ->
          disconnect Resources (netProcessing 1297 "historical block serving limit reached")
      | not noban
          && pruned
          && e.tip.height > b.height
          && e.tip.height - b.height > nodeNetworkLimitedMinBlocks + 2 ->
          disconnect Resources (netProcessing 1316 "block beyond the depth a pruned node serves")
      | otherwise -> case (b.status, e.blockData h) of
          (HaveData, Just blk) -> serve e b blk
          _ -> ignore (netProcessing 1321 "block data not on disk")
  where
    serve e b blk = do
      case inv.invType of
        InvMerkleBlock -> filtered blk
        InvCompactBlock
          | canDirectFetch e && b.height + maxCmpctBlockDepth >= e.tip.height,
            Just cb <- e.compactBlockOf b.hash ->
              send (MCompactBlock cb) (netProcessing 1445 "CMPCTBLOCK in reply to getdata")
        _ -> send (MBlock blk) (netProcessing 1379 "BLOCK in reply to getdata")
      hc <- gets (.blocks.hashContinue)
      when (hc == Just b.hash) $ do
        send (MInv (Inv [InvVector InvBlock e.tip.hash.get])) $
          netProcessing 1472 "inv of the tip after hashContinue"
        modifyBlocks (\x -> x {hashContinue = Nothing})
    filtered blk = do
      f0 <- gets (.relay.bloom)
      o <- options
      let (matches, f1) = bloomRelevantBlock o.network f0 blk.txs
          marked = zip blk.txs matches
          (flags, hashes) = buildPartialMerkle [(txHash tx, m) | (tx, m) <- marked]
          mb =
            MerkleBlock
              { header = blk.header,
                txn = fromIntegral (length blk.txs),
                hashes = hashes,
                flags = flags
              }
      modifyRelay (\r -> r {bloom = f1})
      send (MMerkleBlock mb) (netProcessing 1414 "MERKLEBLOCK")
      forM_ [tx | (tx, True) <- marked] $ \tx ->
        send (MTx tx) (netProcessing 1426 "matched transaction of a merkle block")

-- | @block@ (@src\/net_processing.cpp:3427-3461@): processed with force when
-- requested from this peer, or from a @noban@ peer out of initial block
-- download; any peer that sent it can be punished for it.
receiveBlock :: Block -> M ()
receiveBlock b = do
  e <- env
  noban <- hasPerm PermNoBan
  let h = headerHash b.header
  wasInFlight <- markReceived h
  let force = (noban && not e.initialBlockDownload) || wasInFlight
  processNewBlock b True force

-- | @ProcessBlockFromNode@ and @BlockChecked@ (@src\/net_processing.cpp:1983-1998@,
-- @src\/net_processing.cpp:1094-1130@): validation, then a queued @reject@
-- and misbehaviour for an invalid block when the source can be punished,
-- or the choice of the peer for high-bandwidth compact blocks when the block
-- was the only one in flight.
processNewBlock :: Block -> Bool -> Bool -> M ()
processNewBlock b punish force = do
  e <- env
  let h = headerHash b.header
  process (if force then "ProcessNewBlock, forced" else "ProcessNewBlock") $
    netProcessing 1986 "ProcessNewBlock"
  case e.checkBlock b of
    BlockAccepted -> do
      _ <- markReceived h
      nInFlight <- gets (length . (.blocks.inFlight))
      when (not e.initialBlockDownload && e.otherBlocksInFlight == 0 && nInFlight == 0) $
        selectHighBandwidth
    BlockDuplicate -> ignore (netProcessing 1996 "block already known")
    BlockMissingParent -> ignore (netProcessing 1105 "prev-blk-not-found: no reject")
    BlockInvalid blame r -> rejected h 0x10 (if blame then 100 else 0) r
    BlockRejected code dos r -> rejected h code dos r
  where
    rejected h code dos r =
      when (code > 0) $ do
        o <- options
        let msg = rejectMessage MCBlock code r (Just h.get)
        when o.enableBip61 $
          forM_ msg $
            \m -> modify' (\s -> s {blockRejects = s.blockRejects <> [m]})
        when (dos > 0 && punish) $ misbehaving dos (netProcessing 1114 r)

-- | @MaybeSetPeerAsAnnouncingHeaderAndIDs@ (@src\/net_processing.cpp:560-610@)
-- for this peer: ask it for high-bandwidth compact blocks if it offers
-- them. Which peer it replaces among the three is decided across peers.
selectHighBandwidth :: M ()
selectHighBandwidth = do
  bs <- gets (.blocks)
  when (bs.providesHeaderAndIds && not bs.highBandwidthTo) $ do
    send (MSendCompact (SendCompact True 1)) (netProcessing 601 "SENDCMPCT high-bandwidth")
    modifyBlocks (\x -> x {highBandwidthTo = True})

-- | @cmpctblock@ (@src\/net_processing.cpp:3022-3298@).
receiveCmpctBlock :: CompactBlock -> M ()
receiveCmpctBlock cb = do
  e <- env
  let hdr = cb.header
      h = headerHash hdr
  if isNothing (e.lookupBlock hdr.prev)
    then
      if e.initialBlockDownload
        then ignore (netProcessing 3049 "cmpctblock that does not connect, in IBD")
        else getHeadersFrom e.bestHeader (netProcessing 3043 "cmpctblock that does not connect")
    else do
      let receivedNew = isNothing (e.lookupBlock h)
          parentHeight = maybe 0 (.height) (e.lookupBlock hdr.prev)
      case e.checkHeaders [hdr] of
        HeadersRejected dos r -> headerInvalid dos r
        HeadersInvalid r -> headerInvalid 100 r
        HeadersUnconnected -> headerInvalid 10 "prev-blk-not-found"
        HeadersNonContinuous -> headerInvalid 20 "disconnected-header"
        _ -> withHeader e h receivedNew (blockInfoOf e hdr (parentHeight + 1))
  where
    headerInvalid dos r
      | dos > 0 = misbehaving dos (netProcessing 3067 r)
      | otherwise = ignore (netProcessing 3069 r)
    withHeader e h receivedNew info = do
      t <- nowM
      updateBlockAvailability h (Just info)
      when (receivedNew && info.work > e.tip.work) $
        modifyBlocks (\b -> b {lastBlockAnnouncement = t `div` 1000000})
      bs <- gets (.blocks)
      inbound <- isInbound
      let mine = filter ((== h) . (.inFlightHash)) bs.inFlight
          requested = not (null mine)
          elsewhere = e.inFlightElsewhere h
          alreadyInFlight = elsewhere + (if requested then 1 else 0)
          firstInFlight = requested && elsewhere == 0
      if
        | info.status == HaveData -> ignore (netProcessing 3111 "block already stored")
        | info.work <= e.tip.work ->
            if requested
              then getDataBlock InvBlock h (netProcessing 3129 "cmpctblock of less work, requested")
              else ignore (netProcessing 3131 "cmpctblock of less work")
        | alreadyInFlight == 0 && not (canDirectFetch e) ->
            ignore (netProcessing 3137 "cmpctblock while the tip is old")
        | info.height <= e.tip.height + 2 ->
            if (alreadyInFlight < maxCmpctBlocksInflightPerBlock && length bs.inFlight < maxBlocksInTransitPerPeer)
              || requested
              then
                if any (isJust . (.partial)) mine
                  then ignore (netProcessing 3161 "already syncing this compact block")
                  else do
                    if requested
                      then modifyBlocks $ \b ->
                        b {inFlight = [if f.inFlightHash == h then f {partial = Just cb} else f | f <- b.inFlight]}
                      else () <$ markInFlight h True (Just cb)
                    initData e h firstInFlight inbound alreadyInFlight
              else reconstruct e
        | requested -> getDataBlock InvBlock h (netProcessing 3243 "cmpctblock too far ahead, requested")
        | otherwise -> processHeaders [cb.header] False
    initData e h firstInFlight inbound alreadyInFlight = do
      bs <- gets (.blocks)
      case e.initCompact cb of
        CompactInvalid -> do
          _ <- markReceived h
          misbehaving 100 (netProcessing 3170 "invalid-cmpctblk")
        CompactFailed
          | firstInFlight -> getDataBlock InvBlock h (netProcessing 3179 "compact block collision")
          | otherwise -> () <$ markReceived h
        -- Nothing is missing: upstream completes the block as if an empty
        -- @blocktxn@ had come (@src\/net_processing.cpp:3193-3199@).
        CompactComplete _ -> receiveBlockTxn (BlockTxn h [])
        CompactMissing [] -> receiveBlockTxn (BlockTxn h [])
        CompactMissing ixs
          | firstInFlight
              || (bs.highBandwidthTo && (not inbound || alreadyInFlight < maxCmpctBlocksInflightPerBlock - 1)) ->
              send (MGetBlockTxn (GetBlockTxn h ixs)) (netProcessing 3213 "GETBLOCKTXN")
          | otherwise -> () <$ markReceived h
    reconstruct e =
      case e.initCompact cb of
        CompactComplete blk -> processNewBlock blk False True
        CompactMissing [] -> case e.fillCompact cb [] of
          CompactComplete blk -> processNewBlock blk False True
          _ -> ignore (netProcessing 3227 "compact block not rebuilt from the mempool")
        _ -> ignore (netProcessing 3227 "compact block not rebuilt from the mempool")

-- | @blocktxn@ (@src\/net_processing.cpp:3300-3391@): completes the compact
-- block in flight from this peer. An invalid block rebuilt this way is never
-- punished (BIP 152), but its @reject@ is still sent.
receiveBlockTxn :: BlockTxn -> M ()
receiveBlockTxn bt = do
  e <- env
  bs <- gets (.blocks)
  let h = bt.hash
  case [cb | f <- bs.inFlight, f.inFlightHash == h, Just cb <- [f.partial]] of
    [] -> ignore (netProcessing 3320 "blocktxn for a block not requested")
    (cb : _) -> case e.fillCompact cb bt.transactions of
      CompactInvalid -> do
        _ <- markReceived h
        misbehaving 100 (netProcessing 3332 "invalid-cmpctblk-txns")
      -- A fill that reports missing transactions cannot happen upstream;
      -- it is taken as a failed fill.
      CompactMissing _
        | e.inFlightElsewhere h == 0 ->
            getDataBlock InvBlock h (netProcessing 3342 "compact block reconstruction failed")
        | otherwise -> () <$ markReceived h
      CompactFailed
        | e.inFlightElsewhere h == 0 ->
            getDataBlock InvBlock h (netProcessing 3342 "compact block reconstruction failed")
        | otherwise -> () <$ markReceived h
      CompactComplete blk -> do
        _ <- markReceived h
        processNewBlock blk False True

-- * Notifications

-- | @UpdatedBlockTip@ (@src\/net_processing.cpp:1051-1088@): out of initial
-- block download, queue up to 8 new blocks for announcement to a peer whose
-- start height is not far above the new tip.
updatedBlockTip :: [BlockHeader] -> M ()
updatedBlockTip hs = do
  e <- env
  s <- get
  unless (e.initialBlockDownload || null hs) $ do
    let newHeight = maybe e.tip.height (.height) (e.lookupBlock (headerHash (last hs)))
        floorHeight
          | s.peerStartHeight /= -1 = fromIntegral s.peerStartHeight - 2000
          | otherwise = 0 :: Int64
        hashes = reverse (take maxBlocksToAnnounce (reverse (map headerHash hs)))
    when (fromIntegral newHeight > floorHeight) $
      modifyBlocks (\b -> b {toAnnounce = b.toAnnounce <> hashes})

-- | @NewPoWValidBlock@ (@src\/net_processing.cpp:1002-1045@): a new block
-- that passed the header checks goes as @cmpctblock@ at once to a
-- high-bandwidth peer of version 70015 or later that has its parent.
newPoWValidBlock :: BlockHeader -> M ()
newPoWValidBlock hdr = do
  e <- env
  s <- get
  when (s.peerVersion >= invalidCbNoBanVersion && not s.closing) $ do
    processBlockAvailability
    let h = headerHash hdr
    case (e.lookupBlock h, e.lookupBlock hdr.prev) of
      (Just b, Just parent) -> do
        has <- peerHasHeader b
        hasParent <- peerHasHeader parent
        when (s.blocks.preferHeaderAndIds && not has && hasParent) $
          forM_ (e.compactBlockOf h) $ \cb -> do
            send (MCompactBlock cb) (netProcessing 1041 "fast CMPCTBLOCK announcement")
            modifyBlocks (\x -> x {bestHeaderSent = Just b})
      _ -> return ()

-- | The node chose this peer for high-bandwidth compact blocks, or dropped it
-- for another (@MaybeSetPeerAsAnnouncingHeaderAndIDs@,
-- @src\/net_processing.cpp:560-610@).
highBandwidth :: Bool -> M ()
highBandwidth True = selectHighBandwidth
highBandwidth False = do
  bs <- gets (.blocks)
  when bs.highBandwidthTo $ do
    send (MSendCompact (SendCompact False 1)) (netProcessing 590 "SENDCMPCT low-bandwidth")
    modifyBlocks (\x -> x {highBandwidthTo = False})

-- | The rest of the node wants this block from this peer; it is requested at
-- the next pass of @SendMessages@, where @FindNextBlocksToDownload@ would
-- have picked it.
requestBlock :: BlockHash -> M ()
requestBlock h = modifyBlocks (\b -> b {toRequest = b.toRequest <> [h]})

-- | Another peer's download pass found this peer holding back the window
-- (@src\/net_processing.cpp:4768-4771@).
stalling :: M ()
stalling = do
  t <- nowM
  modifyBlocks (\b -> b {stallingSince = if b.stallingSince == 0 then t else b.stallingSince})

-- * SendMessages

-- | Download from this peer if it is preferred, or if no peer is and it
-- serves blocks (@fFetch@, @src\/net_processing.cpp:4256-4257@).
fetchFrom :: M Bool
fetchFrom = do
  e <- env
  s <- get
  return $
    s.preferredDownload
      || (e.otherPreferredDownload == 0 && not s.client && s.conn.connectionType /= AddrFetch)

-- | The first @getheaders@ (@src\/net_processing.cpp:4259-4293@): from one
-- peer during initial block download, from every peer that serves blocks
-- once the best header is less than a day old.
initialGetHeaders :: M ()
initialGetHeaders = do
  e <- env
  s <- get
  fetch <- fetchFrom
  let t = e.now
      bestTime = fromIntegral e.bestHeader.time :: Int64
  when (not s.blocks.syncStarted && not s.client) $
    when ((e.otherSyncStarted == 0 && fetch) || bestTime > t `div` 1000000 - 24 * 60 * 60) $ do
      let timeout =
            t
              + headersDownloadTimeoutBase
              + headersDownloadTimeoutPerHeader * (t `div` 1000000 - bestTime) `div` targetSpacing
          start = fromMaybe e.bestHeader (parentOf e e.bestHeader)
      modifyBlocks (\b -> b {syncStarted = True, headersSyncTimeout = timeout})
      getHeadersFrom start (netProcessing 4288 "initial getheaders")

-- | The announcements of new blocks (@src\/net_processing.cpp:4307-4458@):
-- @headers@ to a peer that sent @sendheaders@, @cmpctblock@ to a
-- high-bandwidth peer for one block, and otherwise an @inv@ of the last new
-- block, which goes out with the other @inv@s of the pass.
blockAnnouncements :: M ()
blockAnnouncements = do
  e <- env
  bs <- gets (.blocks)
  let q = bs.toAnnounce
      revert0 =
        (not bs.preferHeaders && (not bs.preferHeaderAndIds || length q > 1))
          || length q > maxBlocksToAnnounce
  processBlockAvailability
  (revert, best, headers) <-
    if revert0
      then return (True, Nothing, [])
      else collect e q Nothing False []
  revert' <-
    if not revert && not (null headers)
      then do
        bs' <- gets (.blocks)
        if
          | length headers == 1 && bs'.preferHeaderAndIds,
            Just b <- best,
            Just cb <- e.compactBlockOf b.hash -> do
              send (MCompactBlock cb) (netProcessing 4393 "header-and-ids announcement")
              modifyBlocks (\x -> x {bestHeaderSent = best})
              return False
          | bs'.preferHeaders -> do
              send (MHeaders (Headers [(h, VarInt 0) | h <- headers])) $
                netProcessing 4423 "headers announcement"
              modifyBlocks (\x -> x {bestHeaderSent = best})
              return False
          | otherwise -> return True
      else return revert
  when (revert' && not (null q)) $ do
    let h = last q
    case e.lookupBlock h of
      Just b -> do
        has <- peerHasHeader b
        unless has $ modifyBlocks (\x -> x {blockInvs = x.blockInvs <> [h]})
      Nothing -> return ()
  modifyBlocks (\x -> x {toAnnounce = []})
  where
    collect _ [] best _ acc = return (False, best, reverse acc)
    collect e (h : rest) best found acc =
      case e.lookupBlock h of
        Nothing -> return (True, best, [])
        Just b
          | not b.inActiveChain -> return (True, best, [])
          | Just p <- best,
            fmap (.prev) (e.headerOf h) /= Just p.hash ->
              return (True, best, [])
          | otherwise -> do
              let hdr = e.headerOf h
              if found
                then collect e rest (Just b) True (maybe acc (: acc) hdr)
                else do
                  has <- peerHasHeader b
                  if has
                    then collect e rest (Just b) False acc
                    else do
                      parentKnown <- case parentOf e b of
                        Nothing -> return (b.height == 0)
                        Just p -> peerHasHeader p
                      if parentKnown
                        then collect e rest (Just b) True (maybe acc (: acc) hdr)
                        else return (True, best, [])

-- | The timers of block download, in upstream order
-- (@src\/net_processing.cpp:4656-4730@): stalling, the download timeout and
-- the headers sync timeout. Returns whether the peer was disconnected,
-- which ends the pass.
downloadTimers :: M Bool
downloadTimers = do
  e <- env
  bs <- gets (.blocks)
  noban <- hasPerm PermNoBan
  pref <- gets (.preferredDownload)
  let t = e.now
      perPeer = 1000000 + 500000 * fromIntegral e.otherValidatedDownloads
      deadline = bs.downloadingSince + targetSpacing * perPeer
      bestTime = fromIntegral e.bestHeader.time :: Int64
  if
    | bs.stallingSince /= 0 && bs.stallingSince < t - blockStallingTimeout -> do
        disconnect Timeout (netProcessing 4665 "is stalling block download")
        return True
    | not (null bs.inFlight) && t > deadline -> do
        disconnect Timeout (netProcessing 4688 "Timeout downloading block")
        return True
    | bs.syncStarted && bs.headersSyncTimeout < maxBound ->
        if bestTime <= t `div` 1000000 - 24 * 60 * 60
          then
            if t > bs.headersSyncTimeout && e.otherSyncStarted == 0 && e.otherPreferredDownload >= 1
              then
                if not noban
                  then do
                    disconnect Timeout (netProcessing 4710 "Timeout downloading headers")
                    return True
                  else do
                    _ <- return pref
                    modifyBlocks (\b -> b {syncStarted = False, headersSyncTimeout = 0})
                    process "headers sync restarts with another peer" $
                      netProcessing 4720 "Timeout downloading headers from whitelisted peer"
                    return False
              else return False
          else do
            modifyBlocks (\b -> b {headersSyncTimeout = maxBound})
            return False
    | otherwise -> return False

-- | The chain-sync check of outbound peers (@ConsiderEviction@,
-- @src\/net_processing.cpp:3951-4035@): an outbound full-relay peer whose best
-- block has less work than our tip gets 20 minutes to catch up, then one
-- @getheaders@ and two more minutes, then is disconnected. Manual, feeler,
-- address-fetch and inbound peers are exempt, and so are up to four
-- protected peers.
considerEviction :: M ()
considerEviction = do
  e <- env
  s <- get
  let cs = s.blocks.chainSync
      t = e.now `div` 1000000
      ct = s.conn.connectionType
      bk = s.blocks.bestKnown
      caughtUp = maybe False (\b -> b.work >= e.tip.work) bk
  when (not cs.protect && ct `elem` [OutboundFullRelay, BlockRelayOnly] && s.blocks.syncStarted) $
    if
      | caughtUp ->
          when (cs.syncTimeout /= 0) $
            setCs (ChainSync 0 Nothing False cs.protect)
      | cs.syncTimeout == 0
          || ( case (cs.workHeader, bk) of
                 (Just w, Just b) -> b.work >= w.work
                 _ -> False
             ) ->
          setCs (ChainSync (t + chainSyncTimeout) (Just e.tip) False cs.protect)
      | cs.syncTimeout > 0 && t > cs.syncTimeout ->
          if cs.sentGetHeaders
            then disconnect Timeout (netProcessing 4001 "chain sync timeout: for old chain")
            else do
              let w = fromMaybe e.tip cs.workHeader
                  from = fromMaybe w (parentOf e w)
              getHeadersFrom from (netProcessing 4015 "getheaders for the chain-sync check")
              setCs (ChainSync (t + headersResponseTime) cs.workHeader True cs.protect)
      | otherwise -> return ()
  where
    setCs c = modifyBlocks (\b -> b {chainSync = c})

-- | The blocks to request in this pass (@src\/net_processing.cpp:4753-4774@):
-- those the rest of the node asked for, while the peer serves blocks and
-- has fewer than 16 in flight. Returns the entries of the @getdata@.
blockRequests :: M [InvVector]
blockRequests = do
  e <- env
  s <- get
  fetch <- fetchFrom
  let ok =
        not s.client
          && ((fetch && not s.limitedNode) || not e.initialBlockDownload)
  if not ok
    then return []
    else do
      let q = s.blocks.toRequest
      modifyBlocks (\b -> b {toRequest = []})
      concat <$> mapM one q
  where
    one h = do
      n <- gets (length . (.blocks.inFlight))
      if n >= maxBlocksInTransitPerPeer
        then return []
        else do
          e <- env
          new <- markInFlight h (isJust (e.lookupBlock h)) Nothing
          return [InvVector InvBlock h.get | new]
