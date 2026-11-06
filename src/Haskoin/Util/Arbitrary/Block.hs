{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}

-- |
-- Module      : Haskoin.Test.Block
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
module Haskoin.Util.Arbitrary.Block where

import qualified Data.HashMap.Strict as HashMap
import Haskoin.Block
import Haskoin.Crypto (Ctx)
import Haskoin.Network.Data
import Haskoin.Transaction.Common (Tx, TxHash (..), txHash)
import Haskoin.Util.Arbitrary.Crypto
import Haskoin.Util.Arbitrary.Network
import Haskoin.Util.Arbitrary.Transaction
import Haskoin.Util.Arbitrary.Util
import Test.QuickCheck

-- | Block of arbitrary transactions. The header has the Merkle root of the
-- transactions when there are some. On a network without SegWit the
-- transactions have no witness, as a block of that network has none.
arbitraryBlock :: Network -> Ctx -> Gen Block
arbitraryBlock net ctx = do
  h <- arbitraryBlockHeader
  c <- choose (0, 10)
  txs <- vectorOf c (arbitraryNetworkTx net ctx)
  let header = case buildMerkleRoot (map txHash txs) of
        Right root -> (h :: BlockHeader) {merkle = root}
        Left _ -> h
  return $ Block header txs

-- | Arbitrary transaction of the kind a peer of the network sends: with or
-- without a witness where the network has SegWit, without one elsewhere.
arbitraryNetworkTx :: Network -> Ctx -> Gen Tx
arbitraryNetworkTx net ctx
  | net.segWit = arbitraryTx net ctx
  | otherwise = arbitraryLegacyTx net ctx

-- | Block header with random hash.
arbitraryBlockHeader :: Gen BlockHeader
arbitraryBlockHeader =
  BlockHeader
    <$> arbitrary
    <*> arbitraryBlockHash
    <*> arbitraryHash256
    <*> arbitrary
    <*> arbitrary
    <*> arbitrary

-- | Arbitrary block hash.
arbitraryBlockHash :: Gen BlockHash
arbitraryBlockHash = BlockHash <$> arbitraryHash256

-- | Arbitrary 'GetBlocks' object with at least one block hash.
arbitraryGetBlocks :: Gen GetBlocks
arbitraryGetBlocks =
  GetBlocks
    <$> arbitrary
    <*> listOf1 arbitraryBlockHash
    <*> arbitraryBlockHash

-- | Arbitrary 'GetHeaders' object with at least one block header.
arbitraryGetHeaders :: Gen GetHeaders
arbitraryGetHeaders =
  GetHeaders
    <$> arbitrary
    <*> listOf1 arbitraryBlockHash
    <*> arbitraryBlockHash

-- | Arbitrary 'Headers' object with at least one block header.
arbitraryHeaders :: Gen Headers
arbitraryHeaders =
  Headers <$> listOf1 ((,) <$> arbitraryBlockHeader <*> arbitraryVarInt)

-- | Arbitrary 'MerkleBlock' that holds a valid proof: a partial Merkle tree
-- over one to thirty distinct transaction hashes, with any subset of them
-- matching, under a header that has the Merkle root of those hashes. The
-- flags are padded with zero bits to whole bytes, as they are on the wire.
arbitraryMerkleBlock :: Gen MerkleBlock
arbitraryMerkleBlock = do
  bh <- arbitraryBlockHeader
  n <- choose (1, 30)
  hashes <- (TxHash <$> arbitraryHash256) `vectorOfDistinct` n
  matches <- vectorOf n arbitrary
  let (flags, partial) = buildPartialMerkle (zip hashes matches)
      padding = (8 - length flags `mod` 8) `mod` 8
      root = either (const bh.merkle) id (buildMerkleRoot hashes)
  return $
    MerkleBlock
      (bh :: BlockHeader) {merkle = root}
      (fromIntegral n)
      partial
      (flags ++ replicate padding False)
  where
    vectorOfDistinct gen k = go k []
      where
        go 0 acc = return acc
        go i acc = do
          x <- gen `suchThat` (`notElem` acc)
          go (i - 1 :: Int) (x : acc)

-- | Arbitrary 'BlockNode'. One in ten is at height zero, like a genesis
-- node, whose skip hash is its own hash and is not serialized.
arbitraryBlockNode :: Gen BlockNode
arbitraryBlockNode =
  frequency [(1, genesisLike), (9, above)]
  where
    genesisLike = do
      h <- arbitraryBlockHeader
      w <- arbitrarySizedNatural
      return $ BlockNode h 0 w (headerHash h)
    above =
      BlockNode
        <$> arbitraryBlockHeader
        <*> choose (1, maxBound)
        <*> arbitrarySizedNatural
        <*> arbitraryBlockHash

-- | Arbitrary 'HeaderMemory'
arbitraryHeaderMemory :: Gen HeaderMemory
arbitraryHeaderMemory = do
  ls <- listOf $ (,) <$> arbitrary <*> arbitraryBSS
  HeaderMemory (HashMap.fromList ls) <$> arbitraryBlockNode
