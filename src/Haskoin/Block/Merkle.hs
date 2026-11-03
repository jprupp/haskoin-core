{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Block.Merkle
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Function to deal with Merkle trees inside blocks.
module Haskoin.Block.Merkle
  ( -- * Merkle Blocks
    MerkleBlock (..),
    MerkleRoot,
    FlagBits,
    PartialMerkleTree,
    buildMerkleRoot,
    merkleBlockTxs,
    testMerkleRoot,
    buildPartialMerkle,
    extractMatches,
    decodeMerkleFlags,
    encodeMerkleFlags,
    calcTreeHeight,
    calcTreeWidth,
    hash2,
    calcHash,
    splitIn,
    boolsToWord8,
  )
where

import Control.DeepSeq
import Control.Monad (when)
import Data.Binary (Binary (..))
import Data.Bits
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Either (isRight)
import Data.Hashable
import Data.Serialize (Serialize (..))
import qualified Data.Vector as V
import Data.Word (Word32, Word8)
import GHC.Generics
import Haskoin.Block.Common
import Haskoin.Crypto.Hash
import Haskoin.Network.Common
import Haskoin.Network.Data
import Haskoin.Transaction.Common

-- | Hash of the block's Merkle root.
type MerkleRoot = Hash256

-- | Bits that are used to rebuild partial merkle tree transaction hash list.
type FlagBits = [Bool]

-- | Partial Merkle tree for a filtered block.
type PartialMerkleTree = [Hash256]

-- | Filtered block: a block with a partial Merkle tree that only includes the
-- transactions that pass a bloom filter that was negotiated.
data MerkleBlock = MerkleBlock
  { -- | block header
    header :: !BlockHeader,
    -- | total number of transactions in block
    txn :: !Word32,
    -- | hashes in depth-first order
    hashes :: !PartialMerkleTree,
    -- | bits to rebuild partial merkle tree
    flags :: !FlagBits
  }
  deriving (Eq, Show, Read, Generic, Hashable, NFData)

instance Serial MerkleBlock where
  deserialize = do
    header <- deserialize
    ntx <- getWord32le
    hashes <- getVarIntList deserialize
    flagBytes <- getVarIntList getWord8
    return $ MerkleBlock header ntx hashes (decodeMerkleFlags flagBytes)

  serialize (MerkleBlock h ntx hashes flags) = do
    serialize h
    putWord32le ntx
    putVarIntList serialize hashes
    putVarIntList putWord8 (encodeMerkleFlags flags)

instance Binary MerkleBlock where
  put = serialize
  get = deserialize

instance Serialize MerkleBlock where
  put = serialize
  get = deserialize

-- | Unpack Merkle flags into 'FlagBits' structure. The least significant bit
-- of each byte comes first.
decodeMerkleFlags :: [Word8] -> FlagBits
decodeMerkleFlags = concatMap (\w -> map (testBit w) [0 .. 7])

-- | Pack Merkle flags from 'FlagBits'. The last byte is padded with zero bits.
encodeMerkleFlags :: FlagBits -> [Word8]
encodeMerkleFlags bs = map boolsToWord8 $ splitIn 8 bs

-- | Computes the height of a Merkle tree.
calcTreeHeight ::
  -- | number of transactions (leaf nodes)
  Int ->
  -- | height of the merkle tree
  Int
calcTreeHeight ntx
  | ntx < 2 = 0
  | even ntx = 1 + calcTreeHeight (ntx `div` 2)
  | otherwise = calcTreeHeight $ ntx + 1

-- | Computes the width of a Merkle tree at a specific height. The transactions
-- are at height 0.
calcTreeWidth ::
  -- | number of transactions (leaf nodes)
  Int ->
  -- | height at which we want to compute the width
  Int ->
  -- | width of the Merkle tree
  Int
calcTreeWidth ntx h = (ntx + (1 `shiftL` h) - 1) `shiftR` h

-- | Every level of a Merkle tree, leaves first and root last. Each level
-- lists its nodes from left to right. A level with an odd number of nodes
-- pairs its last node with itself to build the level above.
type MerkleLevels = [V.Vector Hash256]

-- | Build all levels of the Merkle tree over the given leaves, in linear
-- time. Also report whether some node combines two identical hashes, which
-- Bitcoin Core calls a mutated tree (CVE-2012-2459). The last node of an odd
-- level pairing with itself does not count as a duplicate.
merkleLevels :: [Hash256] -> (MerkleLevels, Bool)
merkleLevels leaves = go (V.fromList leaves) False []
  where
    go level mutated above
      | V.length level <= 1 = (reverse (level : above), mutated)
      | otherwise = go (V.fromList parents) (mutated || duplicated) (level : above)
      where
        count = V.length level
        pairs = [(level V.! i, level V.! min (i + 1) (count - 1)) | i <- [0, 2 .. count - 1]]
        parents = [hash2 l r | (l, r) <- pairs]
        duplicated = or [level V.! i == level V.! (i + 1) | i <- [0, 2 .. count - 2]]

-- | Computes the root of a Merkle tree from a list of leaf node hashes. Fails
-- for an empty list, since a block has at least its coinbase, and for a
-- mutated tree, in which two sibling nodes are identical (CVE-2012-2459). A
-- block with duplicate transactions is invalid, and its mutated tree has the
-- same root as the valid block it was derived from.
buildMerkleRoot ::
  -- | transaction hashes (leaf nodes)
  [TxHash] ->
  -- | root of the Merkle tree
  Either String MerkleRoot
buildMerkleRoot [] = Left "buildMerkleRoot: a block needs at least one transaction"
buildMerkleRoot txs
  | mutated = Left "buildMerkleRoot: duplicate transaction hashes (mutated tree)"
  | otherwise = Right (V.head (last levels))
  where
    (levels, mutated) = merkleLevels (map (.get) txs)

-- | Concatenate and compute double SHA256.
hash2 :: Hash256 -> Hash256 -> Hash256
hash2 a b = doubleSHA256 $ runPutS (serialize a) <> runPutS (serialize b)

-- | Computes the hash of a specific node in a Merkle tree. Builds the whole
-- tree, so use 'buildMerkleRoot' or 'buildPartialMerkle' for more than one
-- node.
calcHash ::
  -- | height of the node
  Int ->
  -- | position of the node (0 for the leftmost node)
  Int ->
  -- | transaction hashes (leaf nodes)
  [TxHash] ->
  -- | hash of the node at the specified position
  Hash256
calcHash height pos txs
  | height < 0 || pos < 0 = error "calcHash: Invalid parameters"
  | otherwise = (levels !! height) V.! pos
  where
    (levels, _) = merkleLevels (map (.get) txs)

-- | Build a partial Merkle tree. Provide a list of tuples with all transaction
-- hashes in the block, and whether the transaction is to be included in the
-- partial tree. Returns a flag bits structure and the computed partial Merkle
-- tree.
buildPartialMerkle ::
  -- | transaction hash and whether to include
  [(TxHash, Bool)] ->
  -- | flag bits and partial Merkle tree
  (FlagBits, PartialMerkleTree)
buildPartialMerkle [] = ([], [])
buildPartialMerkle txs = traverseAndBuild levels matches (length levels - 1) 0
  where
    (levels, _) = merkleLevels (map ((.get) . fst) txs)
    matches = matchLevels (map snd txs)

-- | For every level of the tree, whether each node has a matching transaction
-- somewhere below it. Shaped like the levels of 'merkleLevels'.
matchLevels :: [Bool] -> [V.Vector Bool]
matchLevels leafMatches = go (V.fromList leafMatches) []
  where
    go level above
      | V.length level <= 1 = reverse (level : above)
      | otherwise = go (V.fromList parents) (level : above)
      where
        count = V.length level
        parents = [level V.! i || level V.! min (i + 1) (count - 1) | i <- [0, 2 .. count - 1]]

-- | Depth-first walk that records the partial Merkle tree, like
-- @CPartialMerkleTree::TraverseAndBuild@ in Bitcoin Core. A node with no match
-- below it is stored as a single hash. A node with a match is descended into.
traverseAndBuild ::
  MerkleLevels -> [V.Vector Bool] -> Int -> Int -> (FlagBits, PartialMerkleTree)
traverseAndBuild levels matches height pos
  | height == 0 || not match = ([match], [node])
  | otherwise = (match : leftBits ++ rightBits, leftHashes ++ rightHashes)
  where
    match = (matches !! height) V.! pos
    node = (levels !! height) V.! pos
    (leftBits, leftHashes) = traverseAndBuild levels matches (height - 1) (pos * 2)
    (rightBits, rightHashes)
      | pos * 2 + 1 < V.length (levels !! (height - 1)) =
          traverseAndBuild levels matches (height - 1) (pos * 2 + 1)
      | otherwise = ([], [])

-- | Depth-first walk that rebuilds a node of the partial Merkle tree, like
-- @CPartialMerkleTree::TraverseAndExtract@ in Bitcoin Core. Returns the hash
-- of the node, the matching transactions below it and the flags and hashes
-- that are still unused.
traverseAndExtract ::
  Int ->
  Int ->
  Int ->
  FlagBits ->
  PartialMerkleTree ->
  Either String (Hash256, [TxHash], FlagBits, PartialMerkleTree)
traverseAndExtract height pos ntx flags hashes =
  case flags of
    [] -> Left "extractMatches: ran out of flag bits"
    (parentOfMatch : flags')
      | height == 0 || not parentOfMatch ->
          -- a leaf, or a subtree without matches: its hash is stored as is
          case hashes of
            [] -> Left "extractMatches: ran out of hashes"
            (h : hashes') ->
              Right (h, [TxHash h | height == 0 && parentOfMatch], flags', hashes')
      | otherwise -> do
          (left, leftMatches, flags'', hashes'') <-
            traverseAndExtract (height - 1) (pos * 2) ntx flags' hashes
          if pos * 2 + 1 < calcTreeWidth ntx (height - 1)
            then do
              (right, rightMatches, flags''', hashes''') <-
                traverseAndExtract (height - 1) (pos * 2 + 1) ntx flags'' hashes''
              -- Two branches never hash the same set of distinct transactions.
              when (left == right) $
                Left "extractMatches: identical left and right branches (mutated tree)"
              return (hash2 left right, leftMatches ++ rightMatches, flags''', hashes''')
            else return (hash2 left left, leftMatches, flags'', hashes'')

-- | Extracts the matching hashes from a partial merkle tree. This will return
-- the list of transaction hashes that have been included (set to true) in
-- a call to 'buildPartialMerkle'.
extractMatches ::
  Network ->
  FlagBits ->
  PartialMerkleTree ->
  -- | number of transaction at height 0 (leaf nodes)
  Int ->
  -- | Merkle root and list of matching transaction hashes
  Either String (MerkleRoot, [TxHash])
extractMatches net flags hashes ntx
  | ntx == 0 =
      Left "extractMatches: number of transactions can not be 0"
  | ntx > net.maxBlockSize `div` 60 =
      Left "extractMatches: number of transactions excessively high"
  | length hashes > ntx =
      Left "extractMatches: More hashes provided than the number of transactions"
  | length flags < length hashes =
      Left "extractMatches: At least one bit per node and one bit per hash"
  | otherwise = do
      (root, matches, unusedFlags, unusedHashes) <-
        traverseAndExtract (calcTreeHeight ntx) 0 ntx flags hashes
      let bitsUsed = length flags - length unusedFlags
      -- Only the padding of the last flag byte may stay unused.
      when ((bitsUsed + 7) `div` 8 /= (length flags + 7) `div` 8) $
        Left "extractMatches: All bits were not consumed"
      when (not (null unusedHashes)) $
        Left "extractMatches: All hashes were not consumed"
      return (root, matches)

-- | Helper function to split a list in chunks 'Int' length. Last chunk may be
-- smaller.
splitIn :: Int -> [a] -> [[a]]
splitIn _ [] = []
splitIn c xs = xs1 : splitIn c xs2
  where
    (xs1, xs2) = splitAt c xs

-- | Pack up to eight bools in a byte.
boolsToWord8 :: [Bool] -> Word8
boolsToWord8 [] = 0
boolsToWord8 xs = foldl setBit 0 (map snd $ filter fst $ zip xs [0 .. 7])

-- | Get matching transactions from Merkle block.
merkleBlockTxs :: Network -> MerkleBlock -> Either String [TxHash]
merkleBlockTxs net b = do
  (root, ths) <- extractMatches net b.flags b.hashes (fromIntegral b.txn)
  when (root /= b.header.merkle) $
    Left "merkleBlockTxs: Merkle root incorrect"
  return ths

-- | Check if Merkle block root is valid against the block header.
testMerkleRoot :: Network -> MerkleBlock -> Bool
testMerkleRoot net = isRight . merkleBlockTxs net
