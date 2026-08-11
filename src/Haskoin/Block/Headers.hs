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

    -- ** Helper Functions
    appendBlocks,
    validBlock,
    validCP,
    afterLastCP,
    bip34,
    validVersion,
    lastNoMinDiff,
    nextWorkRequired,
    nextEdaWorkRequired,
    nextDaaWorkRequired,
    nextAsertWorkRequired,
    computeAsertBits,
    computeTarget,
    getSuitableBlock,
    nextPowWorkRequired,
    calcNextWork,
    isValidPOW,
    blockPOW,
    headerWork,
    diffInterval,
    blockLocatorNodes,
    mineBlock,
    computeSubsidy,
    mtp,
    firstGreaterOrEqual,
    lastSmallerOrEqual,
  )
where

import Control.Applicative ((<|>))
import Control.DeepSeq
import Control.Monad (guard, mzero, unless, when)
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
import Data.List (sort, sortBy)
import Data.Maybe (fromMaybe, listToMaybe)
import Data.Serialize (Serialize (..))
import Data.Typeable (Typeable)
import Data.Word (Word32, Word64)
import GHC.Generics (Generic)
import Haskoin.Block.Common
import Haskoin.Crypto
import Haskoin.Network.Data
import Haskoin.Transaction.Genesis
import Haskoin.Util

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

instance Eq BlockNode where
  (==) = (==) `on` (.header)

instance Ord BlockNode where
  compare = compare `on` (.height)

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

-- | Validate a list of continuous block headers and import them to the
-- block chain. Return 'Left' on failure with error information.
connectBlocks ::
  (BlockHeaders m) =>
  Network ->
  -- | current time
  Timestamp ->
  [BlockHeader] ->
  m (Either String [BlockNode])
connectBlocks _ _ [] = return $ Right []
connectBlocks net t bhs@(bh : _) =
  runExceptT $ do
    unless (chained bhs) $
      throwError "Blocks to connect do not form a chain"
    par <-
      maybeToExceptT
        "Could not get parent block"
        (MaybeT (parentBlock bh))
    pars <- lift $ getParents 10 par
    bb <- lift getBestBlockHeader
    go par [] bb par pars bhs >>= \case
      bns@(bn : _) -> do
        lift $ addBlockHeaders bns
        let bb' = chooseBest bn bb
        when (bb' /= bb) $ lift $ setBestBlockHeader bb'
        return bns
      _ -> undefined
  where
    chained (h1 : h2 : hs) = headerHash h1 == h2.prev && chained (h2 : hs)
    chained _ = True
    skipit lbh ls par
      | sh == lbh.height = return lbh
      | sh < lbh.height = do
          skM <- lift $ getAncestor sh lbh
          case skM of
            Just sk -> return sk
            Nothing ->
              throwError $
                "BUG: Could not get skip for block "
                  ++ show (headerHash $ par.header)
      | otherwise = do
          let sn = ls !! fromIntegral (par.height - sh)
          when (sn.height /= sh) $
            throwError "BUG: Node height not right in skip"
          return sn
      where
        sh = skipHeight (par.height + 1)
    go _ acc _ _ _ [] = return acc
    go lbh acc bb par pars (h : hs) = do
      sk <- skipit lbh acc par
      bn <- ExceptT . return $ validBlock net t bb par pars h sk
      go lbh (bn : acc) (chooseBest bn bb) bn (take 10 $ par : pars) hs

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
    par <-
      maybeToExceptT
        "Could not get parent block"
        (MaybeT (parentBlock bh))
    pars <- lift $ getParents 10 par
    skM <- lift $ getAncestor (skipHeight (par.height + 1)) par
    sk <-
      case skM of
        Just sk -> return sk
        Nothing ->
          throwError $
            "BUG: Could not get skip for block "
              ++ show (headerHash $ par.header)
    bb <- lift getBestBlockHeader
    bn <- ExceptT . return $ validBlock net t bb par pars bh sk
    let bb' = chooseBest bb bn
    lift $ addBlockHeader bn
    when (bb /= bb') . lift $ setBestBlockHeader bb'
    return bn

-- | Validate this block header. Build a 'BlockNode' if successful.
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
  Either String BlockNode
validBlock net t bb par pars bh sk = do
  let mt = medianTime . map (.header.timestamp) $ par : pars
      nt = bh.timestamp
      hh = headerHash bh
      nv = bh.version
      ng = par.height + 1
      aw = par.work + headerWork bh
  unless (isValidPOW net bh) $
    Left $
      "Proof of work failed: " ++ show (headerHash bh)
  unless (nt <= t + 2 * 60 * 60) $
    Left $
      "Invalid header timestamp: " ++ show nt
  unless (nt >= mt) $
    Left $
      "Block timestamp too early: " ++ show nt
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

-- | Return the median of all provided timestamps. Can be unsorted. Error on
-- empty list.
medianTime :: [Timestamp] -> Timestamp
medianTime ts
  | null ts = error "Cannot compute median time of empty header list"
  | otherwise = sort ts !! (length ts `div` 2)

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
  case lM of
    Just l -> l < newChildHeight
    Nothing -> True
  where
    lM =
      listToMaybe . reverse $
        [c | (c, _) <- net.checkpoints, c <= bestHeight]

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
  | fst net.bip34Block == 0 = True
  | fst net.bip34Block == height = snd net.bip34Block == hsh
  | otherwise = True

-- | Check if the provided block height and version are valid.
validVersion ::
  Network ->
  -- | new child height
  BlockHeight ->
  -- | new child version
  Word32 ->
  Bool
validVersion net height version
  | version < 2 = height < fst net.bip34Block
  | version < 3 = height < net.bip66Height
  | version < 4 = height < net.bip65Height
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

-- | Returns the work required on a block header given the previous block. This
-- coresponds to @bitcoind@ function @GetNextWorkRequired@ in @main.cpp@.
nextWorkRequired ::
  (BlockHeaders m) =>
  Network ->
  BlockNode ->
  BlockHeader ->
  m Word32
nextWorkRequired net par bh = do
  ma <- getAsertAnchor net
  case asert ma <|> daa <|> eda <|> pow of
    Just f -> f par bh
    Nothing -> error "Could not determine difficulty algorithm"
  where
    asert ma = do
      anchor <- ma
      guard (par.height > anchor.height)
      return $ nextAsertWorkRequired net anchor
    daa = do
      daa_height <- net.daaHeight
      guard (par.height + 1 >= daa_height)
      return $ nextDaaWorkRequired net
    eda = do
      eda_height <- net.edaHeight
      guard (par.height + 1 >= eda_height)
      return $ nextEdaWorkRequired net
    pow = return $ nextPowWorkRequired net

-- | Find out the next amount of work required according to the Emergency
-- Difficulty Adjustment (EDA) algorithm from Bitcoin Cash.
nextEdaWorkRequired ::
  (BlockHeaders m) => Network -> BlockNode -> BlockHeader -> m Word32
nextEdaWorkRequired net par bh
  | par.height + 1 `mod` diffInterval net == 0 =
      nextWorkRequired net par bh
  | mindiff = return (encodeCompact net.powLimit)
  | par.header.bits == encodeCompact net.powLimit =
      return (encodeCompact net.powLimit)
  | otherwise = do
      par6 <- fromMaybe e1 <$> getAncestor (par.height - 6) par
      pars <- getParents 10 par
      pars6 <- getParents 10 par6
      let par6med =
            medianTime $ map (.header.timestamp) (par6 : pars6)
          parmed = medianTime $ map (.header.timestamp) (par : pars)
          mtp6 = parmed - par6med
      if mtp6 < 12 * 3600
        then return $ par.header.bits
        else
          return $
            let (diff, _) = decodeCompact par.header.bits
                ndiff = diff + (diff `shiftR` 2)
             in if net.powLimit > ndiff
                  then encodeCompact net.powLimit
                  else encodeCompact ndiff
  where
    mindiff = bh.timestamp > par.header.timestamp + net.targetSpacing * 2
    e1 = error "Could not get seventh ancestor of block"

-- | Find the next amount of work required according to the Difficulty
-- Adjustment Algorithm (DAA) from Bitcoin Cash.
nextDaaWorkRequired ::
  (BlockHeaders m) => Network -> BlockNode -> BlockHeader -> m Word32
nextDaaWorkRequired net par bh
  | mindiff = return (encodeCompact net.powLimit)
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
    mindiff = bh.timestamp > par.header.timestamp + net.targetSpacing * 2

mtp :: (BlockHeaders m) => BlockNode -> m Timestamp
mtp bn
  | bn.height == 0 = return 0
  | otherwise = do
      pars <- getParents 11 bn
      return $ medianTime (map (.header.timestamp) pars)

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

-- TODO: Use known anchor after fork
getAsertAnchor :: (BlockHeaders m) => Network -> m (Maybe BlockNode)
getAsertAnchor net =
  case net.asertActivationTime of
    Nothing -> return Nothing
    Just act -> firstGreaterOrEqual net (f act)
  where
    f act bn = do
      m <- mtp bn
      return $ compare m act

-- | Find the next amount of work required according to the aserti3-2d algorithm.
nextAsertWorkRequired ::
  (BlockHeaders m) =>
  Network ->
  BlockNode ->
  BlockNode ->
  BlockHeader ->
  m Word32
nextAsertWorkRequired net anchor par bh = do
  anchor_parent <-
    fromMaybe e_fork <$> getBlockHeader anchor.header.prev
  let anchor_parent_time = toInteger anchor_parent.header.timestamp
      time_diff = current_time - anchor_parent_time
  return $ computeAsertBits halflife anchor_bits time_diff height_diff
  where
    halflife = net.asertHalfLife
    anchor_height = toInteger anchor.height
    anchor_bits = anchor.header.bits
    current_height = toInteger par.height + 1
    height_diff = current_height - anchor_height
    current_time = toInteger bh.timestamp
    e_fork = error "Could not get fork block header"

idealBlockTime :: Integer
idealBlockTime = 10 * 60

rBits :: Int
rBits = 16

radix :: Integer
radix = 1 `shiftL` rBits

maxBits :: Word32
maxBits = 0x1d00ffff

maxTarget :: Integer
maxTarget = fst $ decodeCompact maxBits

computeAsertBits ::
  Integer ->
  Word32 ->
  Integer ->
  Integer ->
  Word32
computeAsertBits halflife anchor_bits time_diff height_diff =
  if e2 >= 0 && e2 < 65536
    then
      if g4 == 0
        then encodeCompact 1
        else
          if g4 > maxTarget
            then maxBits
            else encodeCompact g4
    else error $ "Exponent not in range: " ++ show e2
  where
    g1 = fst (decodeCompact anchor_bits)
    e1 =
      ((time_diff - idealBlockTime * (height_diff + 1)) * radix)
        `quot` halflife
    s = e1 `shiftR` rBits
    e2 = e1 - s * radix
    g2 =
      g1
        * ( radix
              + ( (195766423245049 * e2 + 971821376 * e2 ^ 2 + 5127 * e2 ^ 3 + 2 ^ 47)
                    `shiftR` (rBits * 3)
                )
          )
    g3 =
      if s < 0
        then g2 `shiftR` negate (fromIntegral s)
        else g2 `shiftL` fromIntegral s
    g4 = g3 `shiftR` rBits

-- | Compute Bitcoin Cash DAA target for a new block.
computeTarget :: Network -> BlockNode -> BlockNode -> Integer
computeTarget net f l =
  let work = (l.work - f.work) * fromIntegral net.targetSpacing
      tspan = l.header.timestamp - f.header.timestamp
      tspan'
        | tspan > 288 * net.targetSpacing =
            288 * net.targetSpacing
        | tspan < 72 * net.targetSpacing =
            72 * net.targetSpacing
        | otherwise = tspan
      work' = work `div` fromIntegral tspan'
   in 2 ^ (256 :: Integer) `div` work'

-- | Get suitable block for Bitcoin Cash DAA computation.
getSuitableBlock :: (BlockHeaders m) => BlockNode -> m BlockNode
getSuitableBlock par = do
  unless (par.height >= 3) $ error "Block height is less than three"
  blocks <- (par :) <$> getParents 2 par
  return $ sortBy (compare `on` (.header.timestamp)) blocks !! 1

-- | Returns the work required on a block header given the previous block. This
-- coresponds to bitcoind function GetNextWorkRequired in main.cpp.
nextPowWorkRequired ::
  (BlockHeaders m) => Network -> BlockNode -> BlockHeader -> m Word32
nextPowWorkRequired net par bh
  | par.height + 1 `mod` diffInterval net /= 0 =
      if net.minDiffBlocks
        then
          if ht > pt + delta
            then return $ encodeCompact net.powLimit
            else do
              d <- lastNoMinDiff net par
              return d.header.bits
        else return par.header.bits
  | otherwise = do
      let rh = par.height - diffInterval net - 1
      a <- fromMaybe e1 <$> getAncestor rh par
      let t = a.header.timestamp
      return $ calcNextWork net par.header t
  where
    e1 = error "Could not get ancestor for block header"
    pt = par.header.timestamp
    ht = bh.timestamp
    delta = net.targetSpacing * 2

-- | Computes the work required for the first block in a new retarget period.
calcNextWork ::
  Network ->
  -- | last block in previous retarget (parent)
  BlockHeader ->
  -- | timestamp of first block in previous retarget
  Timestamp ->
  Word32
calcNextWork net header time
  | net.powNoRetarget = header.bits
  | new > net.powLimit = encodeCompact net.powLimit
  | otherwise = encodeCompact new
  where
    s = header.timestamp - time
    n
      | s < net.targetTimespan `div` 4 = net.targetTimespan `div` 4
      | s > net.targetTimespan * 4 = net.targetTimespan * 4
      | otherwise = s
    l = fst $ decodeCompact header.bits
    new = l * fromIntegral n `div` fromIntegral net.targetTimespan

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
-- target.
headerWork :: BlockHeader -> Integer
headerWork bh = largestHash `div` (target + 1)
  where
    target = fst $ decodeCompact bh.bits
    largestHash = 1 `shiftL` 256

-- | Number of blocks on average between difficulty cycles (2016 blocks).
diffInterval :: Network -> Word32
diffInterval net = net.targetTimespan `div` net.targetSpacing

-- | Compare two blocks to get the best.
chooseBest :: BlockNode -> BlockNode -> BlockNode
chooseBest b1 b2
  | b1.work == b2.work =
      if b1.height >= b2.height
        then b1
        else b2
  | b1.work > b2.work = b1
  | otherwise = b2

-- | Get list of blocks for a block locator.
blockLocatorNodes :: (BlockHeaders m) => BlockNode -> m [BlockNode]
blockLocatorNodes best =
  reverse <$> go [] best 1
  where
    e1 = error "Could not get ancestor"
    go loc bn n =
      let loc' = bn : loc
          n' =
            if length loc' > 10
              then n * 2
              else 1
       in if bn.height < n'
            then do
              a <- fromMaybe e1 <$> getAncestor 0 bn
              return $ a : loc'
            else do
              let h = bn.height - n'
              bn' <- fromMaybe e1 <$> getAncestor h bn
              go loc' bn' n'

-- | Get block locator.
blockLocator :: (BlockHeaders m) => BlockNode -> m BlockLocator
blockLocator bn = map (headerHash . (.header)) <$> blockLocatorNodes bn

-- | Become rich beyond your wildest dreams.
mineBlock :: Network -> Word32 -> BlockHeader -> BlockHeader
mineBlock net seed h =
  head
    [ j
    | i <- (+ seed) <$> [0 .. maxBound],
      let j = h {nonce = i},
      isValidPOW net j
    ]

-- | Generate and append new blocks (mining). Only practical in regtest network.
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
          { prev = headerHash bh,
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
genesisBlock :: Network -> Ctx -> Block
genesisBlock net ctx = Block net.genesisHeader [genesisTx ctx]

-- | Compute block subsidy at particular height.
computeSubsidy :: Network -> BlockHeight -> Word64
computeSubsidy net height =
  let halvings = height `div` net.halvingInterval
      ini = 50 * 100 * 1000 * 1000
   in if halvings >= 64
        then 0
        else ini `shiftR` fromIntegral halvings
