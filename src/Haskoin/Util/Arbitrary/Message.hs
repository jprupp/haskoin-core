-- |
-- Module      : Haskoin.Test.Message
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
module Haskoin.Util.Arbitrary.Message where

import Data.List (nub, sort)
import Data.Word (Word32)
import Haskoin.Crypto (Ctx)
import Haskoin.Network.BlockFilter
import Haskoin.Network.CompactBlock
import Haskoin.Network.Data
import Haskoin.Network.Message
import Haskoin.Util.Arbitrary.Block
import Haskoin.Util.Arbitrary.Crypto
import Haskoin.Util.Arbitrary.Network
import Haskoin.Util.Arbitrary.Transaction
import Haskoin.Util.Arbitrary.Util
import Test.QuickCheck

-- | Arbitrary 'MessageHeader'.
arbitraryMessageHeader :: Gen MessageHeader
arbitraryMessageHeader =
  MessageHeader
    <$> arbitrary
    <*> arbitraryMessageCommand
    <*> arbitrary
    <*> arbitraryCheckSum32

-- | Arbitrary 'SendCompact'.
arbitrarySendCompact :: Gen SendCompact
arbitrarySendCompact = SendCompact <$> arbitrary <*> elements [1, 2]

-- | Strictly increasing block positions.
arbitraryPositions :: Gen [Word32]
arbitraryPositions = nub . sort <$> listOf arbitrary

-- | Arbitrary 'CompactBlock'.
arbitraryCompactBlock :: Network -> Ctx -> Gen CompactBlock
arbitraryCompactBlock net ctx = do
  positions <- arbitraryPositions
  CompactBlock
    <$> arbitraryBlockHeader
    <*> arbitrary
    <*> listOf (choose (0, maxShortId))
    <*> mapM (\i -> PrefilledTx i <$> arbitraryTx net ctx) positions

-- | Arbitrary 'GetBlockTxn'.
arbitraryGetBlockTxn :: Gen GetBlockTxn
arbitraryGetBlockTxn = GetBlockTxn <$> arbitraryBlockHash <*> arbitraryPositions

-- | Arbitrary 'BlockTxn'.
arbitraryBlockTxn :: Network -> Ctx -> Gen BlockTxn
arbitraryBlockTxn net ctx = BlockTxn <$> arbitraryBlockHash <*> listOf (arbitraryTx net ctx)

-- | Arbitrary 'GetCFilters'.
arbitraryGetCFilters :: Gen GetCFilters
arbitraryGetCFilters = GetCFilters <$> arbitrary <*> arbitrary <*> arbitraryBlockHash

-- | Arbitrary 'CFilter'.
arbitraryCFilter :: Gen CFilter
arbitraryCFilter = CFilter <$> arbitrary <*> arbitraryBlockHash <*> arbitraryBS

-- | Arbitrary 'GetCFHeaders'.
arbitraryGetCFHeaders :: Gen GetCFHeaders
arbitraryGetCFHeaders = GetCFHeaders <$> arbitrary <*> arbitrary <*> arbitraryBlockHash

-- | Arbitrary 'CFHeaders'.
arbitraryCFHeaders :: Gen CFHeaders
arbitraryCFHeaders =
  CFHeaders
    <$> arbitrary
    <*> arbitraryBlockHash
    <*> arbitraryHash256
    <*> listOf arbitraryHash256

-- | Arbitrary 'GetCFCheckpt'.
arbitraryGetCFCheckpt :: Gen GetCFCheckpt
arbitraryGetCFCheckpt = GetCFCheckpt <$> arbitrary <*> arbitraryBlockHash

-- | Arbitrary 'CFCheckpt'.
arbitraryCFCheckpt :: Gen CFCheckpt
arbitraryCFCheckpt = CFCheckpt <$> arbitrary <*> arbitraryBlockHash <*> listOf arbitraryHash256

-- | Arbitrary 'Message' of every kind, including one of an unknown command.
arbitraryMessage :: Network -> Ctx -> Gen Message
arbitraryMessage net ctx =
  oneof
    [ MVersion <$> arbitraryVersion,
      return MVerAck,
      MAddr <$> arbitraryAddr1,
      MAddrV2 <$> arbitraryAddrV2,
      return MSendAddrV2,
      MInv <$> arbitraryInv1,
      MGetData <$> arbitraryGetData,
      MNotFound <$> arbitraryNotFound,
      MGetBlocks <$> arbitraryGetBlocks,
      MGetHeaders <$> arbitraryGetHeaders,
      MTx <$> arbitraryTx net ctx,
      MBlock <$> arbitraryBlock net ctx,
      MMerkleBlock <$> arbitraryMerkleBlock,
      MHeaders <$> arbitraryHeaders,
      return MGetAddr,
      MFilterLoad <$> arbitraryFilterLoad,
      MFilterAdd <$> arbitraryFilterAdd,
      return MFilterClear,
      MPing <$> arbitraryPing,
      MPong <$> arbitraryPong,
      MAlert <$> arbitraryAlert,
      return MMempool,
      MReject <$> arbitraryReject,
      return MSendHeaders,
      MFeeFilter <$> arbitraryFeeFilter,
      MSendCompact <$> arbitrarySendCompact,
      MCompactBlock <$> arbitraryCompactBlock net ctx,
      MGetBlockTxn <$> arbitraryGetBlockTxn,
      MBlockTxn <$> arbitraryBlockTxn net ctx,
      MGetCFilters <$> arbitraryGetCFilters,
      MCFilter <$> arbitraryCFilter,
      MGetCFHeaders <$> arbitraryGetCFHeaders,
      MCFHeaders <$> arbitraryCFHeaders,
      MGetCFCheckpt <$> arbitraryGetCFCheckpt,
      MCFCheckpt <$> arbitraryCFCheckpt,
      return MWtxidRelay,
      MSendTxRcncl <$> arbitrarySendTxRcncl,
      MOther <$> arbitraryOtherCommand <*> arbitraryBS
    ]
