{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Block.Headers
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Block chain header synchronization and proof-of-work consensus functions.
module Haskoin.Block.Headers
  ( -- * Block Headers
    BlockNode (..),
    BlockHeaders (..),
    BlockWork,
    genesisNode,
    genesisBlock,
    isGenesis,
    chooseBest,

    -- ** Header Store
    parentBlock,
    getParents,
    getAncestor,
    splitPoint,
    connectBlocks,
    connectBlock,
    blockLocator,

    -- ** Header Memory Store
    HeaderMemory (..),
    ShortBlockHash,
    BlockMap,
    shortBlockHash,
    initialChain,
    genesisMap,

    -- ** Validation
    validBlock,
    validCP,
    afterLastCP,
    bip34,
    validVersion,
    validTimeWarp,
    medianTime,
    mtp,

    -- ** Difficulty
    nextWorkRequired,
    nextPowWorkRequired,
    calcNextWork,
    lastNoMinDiff,
    diffInterval,
    nextEdaWorkRequired,
    nextDaaWorkRequired,
    computeTarget,
    getSuitableBlock,
    nextAsertWorkRequired,
    asertAnchor,
    computeAsertBits,
    isValidPOW,
    blockPOW,
    headerWork,

    -- ** Helper Functions
    blockLocatorNodes,
    skipHeight,
    appendBlocks,
    mineBlock,
    computeSubsidy,
    firstGreaterOrEqual,
    lastSmallerOrEqual,
  )
where

import Control.DeepSeq
import Control.Monad (mzero, unless, when)
import Control.Monad.Except (ExceptT (..), runExceptT, throwError)
import Control.Monad.State.Strict as State (StateT, get, gets, lift, modify)
import Control.Monad.Trans.Maybe
import Data.Binary (Binary (..))
import Data.Bits (shiftL, shiftR, (.&.))
import Data.ByteString qualified as B
import Data.ByteString.Short (ShortByteString, fromShort, toShort)
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Function (on)
import Data.HashMap.Strict (HashMap)
import Data.HashMap.Strict qualified as HashMap
import Data.Hashable
import Data.Int (Int32)
import Data.List (sort)
import Data.Maybe (fromMaybe, isJust)
import Data.Ord (comparing)
import Data.Serialize (Serialize (..))
import Data.Typeable (Typeable)
import Data.Word (Word32, Word64)
import GHC.Generics (Generic)
import Haskoin.Block.Common
import Haskoin.Crypto
import Haskoin.Network.Data
import Haskoin.Util
import Numeric (showHex)

-- | Short version of the block hash. Uses the good end of the hash (the part
-- that doesn't have a long string of zeroes).
type ShortBlockHash = Word64

-- | Memory-based map to a serialized 'BlockNode' data structure.
-- 'ShortByteString' is used to avoid memory fragmentation and make the data
-- structure compact.
type BlockMap = HashMap ShortBlockHash ShortByteString

-- | Represents accumulated work in the block chain so far.
type BlockWork = Integer

-- | Data structure representing a block header and its position in the
-- block chain.
data BlockNode = BlockNode
  { header :: !BlockHeader,
    height :: !BlockHeight,
    -- | accumulated work so far
    work :: !BlockWork,
    -- | skip magic block hash
    skip :: !BlockHash
  }
  deriving (Show, Read, Generic, Hashable, NFData)

instance Serial BlockNode where
  deserialize = do
    header <- deserialize
    height <- getWord32le
    work <- getInteger
    if height == 0
      then do
        let skip = headerHash header
        return BlockNode {..}
      else do
        skip <- deserialize
        return BlockNode {..}
  serialize bn = do
    serialize $ bn.header
    putWord32le $ bn.height
    putInteger $ bn.work
    case bn.height of
      0 -> return ()
      _ -> serialize $ bn.skip

instance Serialize BlockNode where
  put = serialize
  get = deserialize

instance Binary BlockNode where
  put = serialize
  get = deserialize

-- | Two nodes are the same when they hold the same header.
instance Eq BlockNode where
  (==) = (==) `on` (.header)

-- | Nodes are ordered by height, then by header, so that equal nodes compare
-- as equal and nodes at the same height still have a total order.
instance Ord BlockNode where
  compare = comparing (\bn -> (bn.height, bn.header))

-- | Memory-based header tree.
data HeaderMemory = HeaderMemory
  { blocks :: !BlockMap,
    best :: !BlockNode
  }
  deriving (Eq, Typeable, Show, Read, Generic, Hashable, NFData)

-- | Typeclass for block header chain storage monad.
class (Monad m) => BlockHeaders m where
  -- | Add a new 'BlockNode' to the chain. Does not validate.
  addBlockHeader :: BlockNode -> m ()

  -- | Get a 'BlockNode' associated with a 'BlockHash'.
  getBlockHeader :: BlockHash -> m (Maybe BlockNode)

  -- | Locate the 'BlockNode' for the highest block in the chain
  getBestBlockHeader :: m BlockNode

  -- | Set the highest block in the chain.
  setBestBlockHeader :: BlockNode -> m ()

  -- | Add a continuous bunch of block headers the chain. Does not validate.
  addBlockHeaders :: [BlockNode] -> m ()
  addBlockHeaders = mapM_ addBlockHeader

instance (Monad m) => BlockHeaders (StateT HeaderMemory m) where
  addBlockHeader = modify . addBlockHeaderMemory
  getBlockHeader bh = getBlockHeaderMemory bh <$> State.get
  getBestBlockHeader = gets (.best)
  setBestBlockHeader bn = modify $ \s -> s {best = bn}

-- | Initialize memory-based chain.
initialChain :: Network -> HeaderMemory
initialChain net =
  HeaderMemory
    { blocks = genesisMap net,
      best = genesisNode net
    }

-- | Initialize map for memory-based chain.
genesisMap :: Network -> BlockMap
genesisMap net =
  HashMap.singleton
    (shortBlockHash (headerHash net.genesisHeader))
    (toShort (runPutS (serialize (genesisNode net))))

-- | Add block header to memory block map.
addBlockHeaderMemory :: BlockNode -> HeaderMemory -> HeaderMemory
addBlockHeaderMemory bn s = s {blocks = addBlockToMap bn s.blocks}

-- | Get block header from memory block map.
getBlockHeaderMemory :: BlockHash -> HeaderMemory -> Maybe BlockNode
getBlockHeaderMemory bh s = do
  bs <- shortBlockHash bh `HashMap.lookup` s.blocks
  eitherToMaybe . runGetS deserialize $ fromShort bs

-- | Calculate short block hash taking eight non-zero bytes from the 16-byte
-- hash. This function will take the bytes that are not on the zero-side of the
-- hash, making colissions between short block hashes difficult.
shortBlockHash :: BlockHash -> ShortBlockHash
shortBlockHash =
  either error id . runGetS deserialize . B.take 8 . runPutS . serialize

-- | Add a block to memory-based block map.
addBlockToMap :: BlockNode -> BlockMap -> BlockMap
addBlockToMap node =
  HashMap.insert
    (shortBlockHash $ headerHash $ node.header)
    (toShort $ runPutS $ serialize node)

-- | Get the ancestor of the provided 'BlockNode' at the specified
-- 'BlockHeight'.
getAncestor ::
  (BlockHeaders m) =>
  BlockHeight ->
  BlockNode ->
  m (Maybe BlockNode)
getAncestor height node
  | height > node.height = return Nothing
  | otherwise = go node
  where
    e1 = error "Could not get current walk skip"
    e2 = error "Could not get previous walk skip"
    go walk
      | walk.height > height =
          let height_b = skipHeight (walk.height)
              height_a = skipHeight (walk.height - 1)
              not_genesis = not (isGenesis walk)
              is_b = height_b == height
              below_b = height_b > height
              at_or_below_a = height <= height_a
              far_enough = height_b - 2 > height_a && at_or_below_a
              recurse_b = below_b && not far_enough
              cond = not_genesis && (is_b || recurse_b)
           in if cond
                then do
                  walk' <- fromMaybe e1 <$> getBlockHeader walk.skip
                  go walk'
                else do
                  walk' <- fromMaybe e2 <$> getBlockHeader walk.header.prev
                  go walk'
      | otherwise = return $ Just walk

-- | Is the provided 'BlockNode' the Genesis block?
isGenesis :: BlockNode -> Bool
isGenesis BlockNode {height = 0} = True
isGenesis _ = False

-- | Build the genesis 'BlockNode' for the supplied 'Network'.
genesisNode :: Network -> BlockNode
genesisNode net =
  BlockNode
    { header = net.genesisHeader,
      height = 0,
      work = headerWork net.genesisHeader,
      skip = headerHash net.genesisHeader
    }

-- | Validate a list of continuous block headers and import them into the
-- block chain. Each header is validated against the headers before it and
-- added to the store as it passes, so a failure keeps the headers that came
-- before it and makes the last of them the best block when it has the most
-- work. Return 'Left' on failure with error information, otherwise the new
-- nodes with the newest one first.
connectBlocks ::
  (BlockHeaders m) =>
  Network ->
  -- | current time
  Timestamp ->
  [BlockHeader] ->
  m (Either String [BlockNode])
connectBlocks _ _ [] = return $ Right []
connectBlocks net t bhs
  | not (chained bhs) = return $ Left "Blocks to connect do not form a chain"
  | otherwise = do
      best <- getBestBlockHeader
      (result, nodes, best') <- go best [] bhs
      when (best' /= best) $ setBestBlockHeader best'
      return $ either Left (const (Right nodes)) result
  where
    chained (h1 : h2 : hs) = headerHash h1 == h2.prev && chained (h2 : hs)
    chained _ = True
    go best nodes [] = return (Right (), nodes, best)
    go best nodes (bh : rest) =
      connectHeader net t best bh >>= \case
        Left err -> return (Left err, nodes, best)
        Right node -> go (chooseBest best node) (node : nodes) rest

-- | Block's parent. If the block header is in the store, its parent must also
-- be there. No block header get deleted or pruned from the store.
parentBlock ::
  (BlockHeaders m) =>
  BlockHeader ->
  m (Maybe BlockNode)
parentBlock = getBlockHeader . (.prev)

-- | Validate and connect single block header to the block chain. Return 'Left'
-- if fails to be validated.
connectBlock ::
  (BlockHeaders m) =>
  Network ->
  -- | current time
  Timestamp ->
  BlockHeader ->
  m (Either String BlockNode)
connectBlock net t bh =
  runExceptT $ do
    best <- lift getBestBlockHeader
    node <- ExceptT $ connectHeader net t best bh
    let best' = chooseBest best node
    when (best' /= best) $ lift $ setBestBlockHeader best'
    return node

-- | Validate one header against the store and add it to the store. The best
-- block passed in is only used by the checkpoint rule and is not updated.
connectHeader ::
  (BlockHeaders m) =>
  Network ->
  Timestamp ->
  BlockNode ->
  BlockHeader ->
  m (Either String BlockNode)
connectHeader net t best bh =
  runExceptT $ do
    par <-
      maybeToExceptT
        "Could not get parent block"
        (MaybeT (parentBlock bh))
    pars <- lift $ getParents 10 par
    skipNode <-
      lift (getAncestor (skipHeight (par.height + 1)) par) >>= \case
        Just sk -> return sk
        Nothing ->
          throwError $
            "BUG: Could not get skip for block "
              ++ show (headerHash par.header)
    requiredBits <- lift $ nextWorkRequired net par bh
    node <- ExceptT . return $ validBlock net t best par pars bh skipNode requiredBits
    lift $ addBlockHeader node
    return node

-- | Validate this block header. Build a 'BlockNode' if successful. The checks
-- follow @CheckBlockHeader@ and @ContextualCheckBlockHeader@ in Bitcoin Core.
validBlock ::
  Network ->
  -- | current time
  Timestamp ->
  -- | best block
  BlockNode ->
  -- | immediate parent
  BlockNode ->
  -- | 10 parents above
  [BlockNode] ->
  -- | header to validate
  BlockHeader ->
  -- | skip node (black magic)
  BlockNode ->
  -- | difficulty bits the chain requires, from 'nextWorkRequired'
  Word32 ->
  Either String BlockNode
validBlock net t bb par pars bh sk requiredBits = do
  let mt = medianTime . map (.header.timestamp) $ par : pars
      nt = bh.timestamp
      hh = headerHash bh
      nv = bh.version
      ng = par.height + 1
      aw = par.work + headerWork bh
  unless (isValidPOW net bh) $
    Left $
      "Proof of work failed: " ++ show (headerHash bh)
  unless (bh.bits == requiredBits) $
    Left $
      "Incorrect difficulty bits: " ++ showBits bh.bits ++ ", expected " ++ showBits requiredBits
  unless (toInteger nt <= toInteger t + 2 * 60 * 60) $
    Left $
      "Invalid header timestamp: " ++ show nt
  -- The timestamp must be strictly above the median time past.
  unless (nt > mt) $
    Left $
      "Block timestamp too early: " ++ show nt
  unless (validTimeWarp net ng par.header.timestamp nt) $
    Left $
      "Block timestamp too early for retarget: " ++ show nt
  unless (afterLastCP net (bb.height) ng) $
    Left $
      "Rewriting pre-checkpoint chain: " ++ show ng
  unless (validCP net ng hh) $
    Left $
      "Rejected checkpoint: " ++ show ng
  unless (bip34 net ng hh) $
    Left $
      "Rejected BIP-34 block: " ++ show hh
  unless (validVersion net ng nv) $
    Left $
      "Invalid block version: " ++ show nv
  return
    BlockNode
      { header = bh,
        height = ng,
        work = aw,
        skip = headerHash sk.header
      }
  where
    showBits b = "0x" ++ showHex b ""

-- | Return the median of all provided timestamps. Can be unsorted. For an
-- even count the upper of the two middle values is taken, as Bitcoin Core
-- does. Error on empty list.
medianTime :: [Timestamp] -> Timestamp
medianTime ts
  | null ts = error "Cannot compute median time of empty header list"
  | otherwise = sort ts !! (length ts `div` 2)

-- | Median time past of a block: the median of the timestamps of the block and
-- its ten closest ancestors, or fewer near genesis. This is
-- @GetMedianTimePast@ in Bitcoin Core.
mtp :: (BlockHeaders m) => BlockNode -> m Timestamp
mtp bn = do
  pars <- getParents 10 bn
  return $ medianTime $ map (.header.timestamp) (bn : pars)

-- | Calculate the height of the skip (magic) block that corresponds to the
-- given height. The block hash of the ancestor at that height will be placed on
-- the 'BlockNode' structure to help locate ancestors at any height quickly.
skipHeight :: BlockHeight -> BlockHeight
skipHeight height
  | height < 2 = 0
  | height .&. 1 /= 0 = invertLowestOne (invertLowestOne $ height - 1) + 1
  | otherwise = invertLowestOne height

-- | Part of the skip black magic calculation.
invertLowestOne :: BlockHeight -> BlockHeight
invertLowestOne height = height .&. (height - 1)

-- | Get a number of parents for the provided block.
getParents ::
  (BlockHeaders m) =>
  Int ->
  BlockNode ->
  -- | starts from immediate parent
  m [BlockNode]
getParents = getpars []
  where
    getpars acc 0 _ = return $ reverse acc
    getpars acc n BlockNode {..}
      | height == 0 = return $ reverse acc
      | otherwise = do
          parM <- getBlockHeader header.prev
          case parM of
            Just bn -> getpars (bn : acc) (n - 1) bn
            Nothing -> error "BUG: All non-genesis blocks should have a parent"

-- | Verify that checkpoint location is valid.
validCP ::
  Network ->
  -- | new child height
  BlockHeight ->
  -- | new child hash
  BlockHash ->
  Bool
validCP net height newChildHash =
  case lookup height net.checkpoints of
    Just cpHash -> cpHash == newChildHash
    Nothing -> True

-- | New block height above the last checkpoint imported. Used to prevent a
-- reorg below the highest checkpoint that was already imported.
afterLastCP ::
  Network ->
  -- | best height
  BlockHeight ->
  -- | new imported block height
  BlockHeight ->
  Bool
afterLastCP net bestHeight newChildHeight =
  case [c | (c, _) <- net.checkpoints, c <= bestHeight] of
    [] -> True
    reached -> maximum reached < newChildHeight

-- | This block should be at least version 2 (BIP34). Block height must be
-- included in the coinbase transaction to prevent non-unique transaction
-- hashes.
bip34 ::
  Network ->
  -- | new child height
  BlockHeight ->
  -- | new child hash
  BlockHash ->
  Bool
bip34 net height hsh
  | height /= net.bip34Height = True
  | otherwise = maybe True (== hsh) net.bip34Hash

-- | Check if the provided block height and version are valid. The version is
-- a signed 32-bit number in Bitcoin Core, so values with the top bit set are
-- negative and count as below version 2.
validVersion ::
  Network ->
  -- | new child height
  BlockHeight ->
  -- | new child version
  Word32 ->
  Bool
validVersion net height version
  | signedVersion < 2 = height < net.bip34Height
  | signedVersion < 3 = height < net.bip66Height
  | signedVersion < 4 = height < net.bip65Height
  | otherwise = True
  where
    signedVersion = fromIntegral version :: Int32

-- | BIP94 time warp rule: the first block of a retarget period may not be more
-- than 600 seconds earlier than its parent.
validTimeWarp ::
  Network ->
  -- | new child height
  BlockHeight ->
  -- | parent timestamp
  Timestamp ->
  -- | new child timestamp
  Timestamp ->
  Bool
validTimeWarp net height parent child
  | net.bip94 && height `mod` diffInterval net == 0 =
      toInteger child + 600 >= toInteger parent
  | otherwise = True

-- | Find last block with normal, as opposed to minimum difficulty (for test
-- networks).
lastNoMinDiff :: (BlockHeaders m) => Network -> BlockNode -> m BlockNode
lastNoMinDiff _ bn@BlockNode {height = 0} = return bn
lastNoMinDiff net bn = do
  let i = bn.height `mod` diffInterval net /= 0
      c = encodeCompact net.powLimit
      l = bn.header.bits == c
      e1 =
        error $
          "Could not get block header for parent of "
            ++ show (headerHash bn.header)
  if i && l
    then do
      bn' <- fromMaybe e1 <$> getBlockHeader (bn.header.prev)
      lastNoMinDiff net bn'
    else return bn

-- | Test network rule: a block more than twice the target spacing after its
-- parent may be mined at the minimum difficulty.
minDiffGap :: Network -> BlockNode -> BlockHeader -> Bool
minDiffGap net par bh =
  toInteger bh.timestamp > toInteger par.header.timestamp + 2 * toInteger net.targetSpacing

-- | Returns the work required on a block header given the previous block. This
-- corresponds to @GetNextWorkRequired@ in Bitcoin Core and Bitcoin Cash Node.
nextWorkRequired ::
  (BlockHeaders m) =>
  Network ->
  BlockNode ->
  BlockHeader ->
  m Word32
nextWorkRequired net par bh
  -- Bitcoin Cash Node never retargets on regtest, before picking an algorithm.
  | usesCashRules && net.powNoRetarget = return par.header.bits
  | otherwise =
      asertAnchor net par >>= \case
        Just anchor -> nextAsertWorkRequired net anchor par bh
        Nothing
          | activeAt net.daaHeight -> nextDaaWorkRequired net par bh
          | activeAt net.edaHeight -> nextEdaWorkRequired net par bh
          | otherwise -> nextPowWorkRequired net par bh
  where
    usesCashRules =
      isJust net.edaHeight || isJust net.daaHeight || isJust net.asertActivationTime
    activeAt = maybe False (\h -> par.height + 1 >= h)

-- | Find out the next amount of work required according to the Emergency
-- Difficulty Adjustment (EDA) algorithm from Bitcoin Cash. This corresponds to
-- @GetNextEDAWorkRequired@ in Bitcoin Cash Node.
nextEdaWorkRequired ::
  (BlockHeaders m) => Network -> BlockNode -> BlockHeader -> m Word32
nextEdaWorkRequired net par bh
  | (par.height + 1) `mod` diffInterval net == 0 =
      nextPowWorkRequired net par bh
  | net.minDiffBlocks =
      if minDiffGap net par bh
        then return powLimitBits
        else (.header.bits) <$> lastNoMinDiff net par
  | par.header.bits == powLimitBits =
      return powLimitBits
  | otherwise = do
      par6 <- fromMaybe e1 <$> getAncestor (par.height - 6) par
      parMtp <- mtp par
      par6Mtp <- mtp par6
      -- If producing the last six blocks took less than twelve hours the
      -- difficulty stays. Otherwise the target grows by a quarter.
      if toInteger parMtp - toInteger par6Mtp < 12 * 3600
        then return par.header.bits
        else do
          let (target, _) = decodeCompact par.header.bits
              target' = target + (target `shiftR` 2)
          return $ encodeCompact (min net.powLimit target')
  where
    powLimitBits = encodeCompact net.powLimit
    e1 = error "Could not get seventh ancestor of block"

-- | Find the next amount of work required according to the Difficulty
-- Adjustment Algorithm (DAA) from Bitcoin Cash. This corresponds to
-- @GetNextCashWorkRequired@ in Bitcoin Cash Node. The parent must be at or
-- above the difficulty interval height.
nextDaaWorkRequired ::
  (BlockHeaders m) => Network -> BlockNode -> BlockHeader -> m Word32
nextDaaWorkRequired net par bh
  | net.minDiffBlocks && minDiffGap net par bh = return (encodeCompact net.powLimit)
  | otherwise = do
      unless (par.height >= diffInterval net) $
        error "Block height below difficulty interval"
      l <- getSuitableBlock par
      par144 <- fromMaybe e1 <$> getAncestor (par.height - 144) par
      f <- getSuitableBlock par144
      let nextTarget = computeTarget net f l
      if nextTarget > net.powLimit
        then return $ encodeCompact net.powLimit
        else return $ encodeCompact nextTarget
  where
    e1 = error "Cannot get ancestor at parent - 144 height"

firstGreaterOrEqual ::
  (BlockHeaders m) =>
  Network ->
  (BlockNode -> m Ordering) ->
  m (Maybe BlockNode)
firstGreaterOrEqual = binSearch False

lastSmallerOrEqual ::
  (BlockHeaders m) =>
  Network ->
  (BlockNode -> m Ordering) ->
  m (Maybe BlockNode)
lastSmallerOrEqual = binSearch True

binSearch ::
  (BlockHeaders m) =>
  Bool ->
  Network ->
  (BlockNode -> m Ordering) ->
  m (Maybe BlockNode)
binSearch top net f = runMaybeT $ do
  (a, b) <- lift $ extremes net
  go a b
  where
    go a b = do
      m <- lift $ middleBlock a b
      a' <- lift $ f a
      b' <- lift $ f b
      m' <- lift $ f m
      r (a, a') (b, b') (m, m')
    r (a, a') (b, b') (m, m')
      | out_of_bounds a' b' = mzero
      | select_first a' = return a
      | select_last b' = return b
      | no_middle a b = choose_one a b
      | is_between a' m' = go a m
      | is_between m' b' = go m b
      | otherwise = mzero
    select_first a'
      | not top = a' /= LT
      | otherwise = False
    select_last b'
      | top = b' /= GT
      | otherwise = False
    out_of_bounds a' b'
      | top = a' == GT
      | otherwise = b' == LT
    no_middle a b = b.height - a.height <= 1
    is_between a' b' = a' /= GT && b' /= LT
    choose_one a b
      | top = return a
      | otherwise = return b

extremes :: (BlockHeaders m) => Network -> m (BlockNode, BlockNode)
extremes net = do
  b <- getBestBlockHeader
  return (genesisNode net, b)

middleBlock :: (BlockHeaders m) => BlockNode -> BlockNode -> m BlockNode
middleBlock a b =
  getAncestor h b >>= \case
    Nothing -> error "You fell into a pit full of mud and snakes"
    Just x -> return x
  where
    h = middleOf a.height b.height

middleOf :: (Integral a) => a -> a -> a
middleOf a b = a + ((b - a) `div` 2)

-- | Anchor block of the aserti3-2d algorithm for the chain that ends at the
-- given block: the earliest ancestor, or the block itself, whose median time
-- past reaches the activation time. The anchor is the last block whose
-- difficulty came from the previous algorithm. Returns 'Nothing' when the
-- block's own median time past is still below the activation time, in which
-- case the previous algorithm applies to its children.
asertAnchor :: (BlockHeaders m) => Network -> BlockNode -> m (Maybe BlockNode)
asertAnchor net tip =
  case net.asertActivationTime of
    Nothing -> return Nothing
    Just activation -> do
      tipMtp <- mtp tip
      if tipMtp < activation
        then return Nothing
        else Just <$> search activation 0 tip.height
  where
    -- The median time past never decreases along a chain, so a binary search
    -- over the heights finds the first block that reaches the activation
    -- time. The upper bound always satisfies it.
    search activation lo hi
      | lo >= hi = ancestorAt lo
      | otherwise = do
          let mid = lo + (hi - lo) `div` 2
          midMtp <- mtp =<< ancestorAt mid
          if midMtp >= activation
            then search activation lo mid
            else search activation (mid + 1) hi
    ancestorAt h = fromMaybe e <$> getAncestor h tip
    e = error "asertAnchor: could not get ancestor"

-- | Find the next amount of work required according to the aserti3-2d
-- algorithm. This corresponds to @GetNextASERTWorkRequired@ in Bitcoin Cash
-- Node.
nextAsertWorkRequired ::
  (BlockHeaders m) =>
  Network ->
  -- | anchor block, see 'asertAnchor'
  BlockNode ->
  -- | parent of the new block
  BlockNode ->
  -- | new block header
  BlockHeader ->
  m Word32
nextAsertWorkRequired net anchor par bh
  | net.minDiffBlocks && minDiffGap net par bh = return (encodeCompact net.powLimit)
  | otherwise = do
      -- The clock starts at the anchor's parent. A genesis anchor has no
      -- parent, so its own timestamp is used, as Bitcoin Cash Node does.
      anchorParentTime <-
        if isGenesis anchor
          then return anchor.header.timestamp
          else (.header.timestamp) . fromMaybe e <$> getBlockHeader anchor.header.prev
      -- The formula is evaluated at the parent, as GetNextASERTWorkRequired
      -- does: the time and the height are the parent's. A block's own
      -- timestamp never changes its own difficulty. The minimum-difficulty
      -- rule above is the only use of the new header.
      let timeDiff = toInteger par.header.timestamp - toInteger anchorParentTime
          heightDiff = toInteger par.height - toInteger anchor.height
      return $
        computeAsertBits net.powLimit net.asertHalfLife anchor.header.bits timeDiff heightDiff
  where
    e = error "Could not get parent of ASERT anchor block"

idealBlockTime :: Integer
idealBlockTime = 10 * 60

rBits :: Int
rBits = 16

radix :: Integer
radix = 1 `shiftL` rBits

-- | The aserti3-2d formula: the target of the anchor block, doubled for every
-- half-life that the chain runs behind its ideal schedule and halved for every
-- half-life it runs ahead, in 16.16 fixed point with a cubic approximation of
-- the exponential.
computeAsertBits ::
  -- | proof-of-work limit (largest target) of the network
  Integer ->
  -- | half-life in seconds
  Integer ->
  -- | bits of the anchor block
  Word32 ->
  -- | seconds from the anchor's parent to the parent of the new block
  Integer ->
  -- | blocks from the anchor to the parent of the new block
  Integer ->
  Word32
computeAsertBits powLimit halflife anchorBits timeDiff heightDiff
  | target == 0 = encodeCompact 1
  | target > powLimit = encodeCompact powLimit
  | otherwise = encodeCompact target
  where
    anchorTarget = fst (decodeCompact anchorBits)
    -- Exponent in 16.16 fixed point. The reference C++ code truncates toward
    -- zero, hence quot.
    expo = ((timeDiff - idealBlockTime * (heightDiff + 1)) * radix) `quot` halflife
    -- Whole half-lives (an arithmetic shift, so rounded down) and the
    -- fractional part in [0, radix).
    shifts = expo `shiftR` rBits
    frac = expo - shifts * radix
    -- 2 ^ (frac / radix) in 16.16 fixed point.
    factor =
      radix
        + ( (195766423245049 * frac + 971821376 * frac ^ (2 :: Int) + 5127 * frac ^ (3 :: Int) + 2 ^ (47 :: Int))
              `shiftR` (rBits * 3)
          )
    scaled = anchorTarget * factor
    shifted
      | shifts < 0 = scaled `shiftR` fromInteger (negate shifts)
      | otherwise = scaled `shiftL` fromInteger shifts
    target = shifted `shiftR` rBits

-- | Compute Bitcoin Cash DAA target for a new block, like @ComputeTarget@ in
-- Bitcoin Cash Node.
computeTarget ::
  Network ->
  -- | first suitable block of the window
  BlockNode ->
  -- | last suitable block of the window
  BlockNode ->
  Integer
computeTarget net firstBlock lastBlock =
  let spacing = toInteger net.targetSpacing
      work = (lastBlock.work - firstBlock.work) * spacing
      actual = toInteger lastBlock.header.timestamp - toInteger firstBlock.header.timestamp
      clamped = max (72 * spacing) (min (288 * spacing) actual)
      work' = work `div` clamped
   in -- (2^256 - work) / work, as the unsigned negation in the reference code
      (2 ^ (256 :: Int) - work') `div` work'

-- | Get suitable block for Bitcoin Cash DAA computation: the block with the
-- median timestamp among the given block, its parent and its grandparent. On
-- equal timestamps the same block as Bitcoin Cash Node's sorting network is
-- chosen.
getSuitableBlock :: (BlockHeaders m) => BlockNode -> m BlockNode
getSuitableBlock par = do
  unless (par.height >= 3) $ error "Block height is less than three"
  parents <- getParents 2 par
  case parents of
    [parent, grandparent] -> return $ medianOfThree grandparent parent par
    _ -> error "Could not get the two parents of the block"
  where
    later x y = x.header.timestamp > y.header.timestamp
    -- Oldest first, swapping only on a strictly later timestamp.
    medianOfThree b0 b1 b2 =
      let (c0, c2) = if later b0 b2 then (b2, b0) else (b0, b2)
          (d0, d1) = if later c0 b1 then (b1, c0) else (c0, b1)
          (e1, _) = if later d1 c2 then (c2, d1) else (d1, c2)
       in const e1 d0

-- | Returns the work required on a block header given the previous block. This
-- coresponds to bitcoind function GetNextWorkRequired in main.cpp.
nextPowWorkRequired ::
  (BlockHeaders m) => Network -> BlockNode -> BlockHeader -> m Word32
nextPowWorkRequired net par bh
  | (par.height + 1) `mod` diffInterval net /= 0 =
      if net.minDiffBlocks
        then
          if minDiffGap net par bh
            then return $ encodeCompact net.powLimit
            else do
              d <- lastNoMinDiff net par
              return d.header.bits
        else return par.header.bits
  | otherwise = do
      -- First block of the retarget period that ends with the parent.
      f <- fromMaybe e1 <$> getAncestor (par.height - (diffInterval net - 1)) par
      -- BIP94 bases the retarget on the first block of the period, which
      -- cannot use the min-difficulty exception, instead of the last one.
      let h
            | net.bip94 = (par.header :: BlockHeader) {bits = f.header.bits}
            | otherwise = par.header
      return $ calcNextWork net h f.header.timestamp
  where
    e1 = error "Could not get ancestor for block header"

-- | Computes the work required for the first block in a new retarget period.
-- The actual timespan is limited to a quarter and four times the target
-- timespan. A negative timespan, when the last block is dated before the
-- first, is limited like a short one.
calcNextWork ::
  Network ->
  -- | last block in previous retarget (parent)
  BlockHeader ->
  -- | timestamp of first block in previous retarget
  Timestamp ->
  Word32
calcNextWork net header firstTime
  | net.powNoRetarget = header.bits
  | new > net.powLimit = encodeCompact net.powLimit
  | otherwise = encodeCompact new
  where
    timespan = toInteger net.targetTimespan
    actual = toInteger header.timestamp - toInteger firstTime
    clamped = max (timespan `div` 4) (min (timespan * 4) actual)
    new = fst (decodeCompact header.bits) * clamped `div` timespan

-- | Returns True if the difficulty target (bits) of the header is valid and the
-- proof of work of the header matches the advertised difficulty target. This
-- function corresponds to the function @CheckProofOfWork@ from @bitcoind@ in
-- @main.cpp@.
isValidPOW :: Network -> BlockHeader -> Bool
isValidPOW net h
  | target <= 0 || over || target > net.powLimit = False
  | otherwise = blockPOW (headerHash h) <= fromIntegral target
  where
    (target, over) = decodeCompact h.bits

-- | Returns the proof of work of a block header hash as an 'Integer' number.
blockPOW :: BlockHash -> Integer
blockPOW = bsToInteger . B.reverse . runPutS . serialize

-- | Returns the work represented by this block. Work is defined as the number
-- of tries needed to solve a block in the average case with respect to the
-- target. A header whose bits are negative, overflow or are zero has no work,
-- like @GetBlockProof@ in Bitcoin Core.
headerWork :: BlockHeader -> Integer
headerWork bh
  | target <= 0 || over = 0
  | otherwise = largestHash `div` (target + 1)
  where
    (target, over) = decodeCompact bh.bits
    largestHash = 1 `shiftL` 256

-- | Number of blocks on average between difficulty cycles (2016 blocks).
diffInterval :: Network -> Word32
diffInterval net = net.targetTimespan `div` net.targetSpacing

-- | Compare two blocks to get the best: the one with more accumulated work,
-- then the higher one. When both are equal the first argument is kept, so
-- callers pass the block they already have first and the block that was seen
-- first stays the best.
chooseBest :: BlockNode -> BlockNode -> BlockNode
chooseBest b1 b2
  | b1.work == b2.work =
      if b1.height >= b2.height
        then b1
        else b2
  | b1.work > b2.work = b1
  | otherwise = b2

-- | Get list of blocks for a block locator: the ten blocks below the best, then
-- blocks at exponentially growing distances, then genesis. This is
-- @LocatorEntries@ in Bitcoin Core.
blockLocatorNodes :: (BlockHeaders m) => BlockNode -> m [BlockNode]
blockLocatorNodes best =
  reverse <$> go [] (0 :: Int) best 1
  where
    e1 = error "Could not get ancestor"
    go acc count node step
      | isGenesis node = return (node : acc)
      | otherwise = do
          let acc' = node : acc
              count' = count + 1
              height = if node.height > step then node.height - step else 0
              step' = if count' > 10 then step * 2 else step
          ancestor <- fromMaybe e1 <$> getAncestor height node
          go acc' count' ancestor step'

-- | Get block locator.
blockLocator :: (BlockHeaders m) => BlockNode -> m BlockLocator
blockLocator bn = map (headerHash . (.header)) <$> blockLocatorNodes bn

-- | Become rich beyond your wildest dreams.
mineBlock :: Network -> Word32 -> BlockHeader -> BlockHeader
mineBlock net seed h =
  case filter (isValidPOW net) [h {nonce = i} | i <- (+ seed) <$> [0 .. maxBound]] of
    (mined : _) -> mined
    [] -> error "mineBlock: no nonce satisfies the target"

-- | Generate and append new blocks (mining). Only practical in regtest network.
-- Every block is dated one target spacing after its parent, so the chain
-- passes the median time past rule.
appendBlocks ::
  Network ->
  -- | random seed
  Word32 ->
  BlockHeader ->
  Int ->
  [BlockHeader]
appendBlocks _ _ _ 0 = []
appendBlocks net seed bh i =
  bh' : appendBlocks net seed bh' (i - 1)
  where
    bh' =
      mineBlock
        net
        seed
        bh
          { -- Version 4 passes the version rules of BIP34, BIP65 and BIP66
            -- at any height. Regtest applies them from height 1.
            version = 4,
            prev = headerHash bh,
            timestamp = bh.timestamp + net.targetSpacing,
            -- Just to make it different in every header
            merkle = sha256 $ runPutS $ serialize seed
          }

-- | Find the last common block ancestor between provided block headers.
splitPoint :: (BlockHeaders m) => BlockNode -> BlockNode -> m BlockNode
splitPoint l r = do
  let h = min l.height r.height
  ll <- fromMaybe e <$> getAncestor h l
  lr <- fromMaybe e <$> getAncestor h r
  f ll lr
  where
    e = error "BUG: Could not get ancestor at lowest height"
    f ll lr =
      if ll == lr
        then return lr
        else do
          let h = ll.height - 1
          pl <- fromMaybe e <$> getAncestor h ll
          pr <- fromMaybe e <$> getAncestor h lr
          f pl pr

-- | Generate the entire Genesis block for 'Network'.
genesisBlock :: Network -> Block
genesisBlock net = Block net.genesisHeader [net.genesisTx]

-- | Compute block subsidy at particular height.
computeSubsidy :: Network -> BlockHeight -> Word64
computeSubsidy net height =
  let halvings = height `div` net.halvingInterval
      ini = 50 * 100 * 1000 * 1000
   in if halvings >= 64
        then 0
        else ini `shiftR` fromIntegral halvings
