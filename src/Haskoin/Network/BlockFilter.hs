{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.BlockFilter
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Messages of client-side block filtering (BIP 157): @getcfilters@,
-- @cfilter@, @getcfheaders@, @cfheaders@, @getcfcheckpt@ and @cfcheckpt@.
-- The filters themselves are defined by BIP 158.
module Haskoin.Network.BlockFilter
  ( FilterType,
    basicFilterType,
    GetCFilters (..),
    CFilter (..),
    GetCFHeaders (..),
    CFHeaders (..),
    GetCFCheckpt (..),
    CFCheckpt (..),
  )
where

import Control.DeepSeq
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Serialize (Serialize (..))
import Data.Word (Word32, Word8)
import GHC.Generics (Generic)
import Haskoin.Block.Common (BlockHash)
import Haskoin.Crypto.Hash (Hash256)
import Haskoin.Network.Common

-- | Kind of filter, as defined by BIP 158.
type FilterType = Word8

-- | The basic filter type of BIP 158, the only one defined so far.
basicFilterType :: FilterType
basicFilterType = 0

-- | The @getcfilters@ message. It asks for the filters of a range of blocks.
-- BIP 157 limits a range to 1000 blocks.
data GetCFilters = GetCFilters
  { -- | kind of filter
    filterType :: !FilterType,
    -- | height of the first block of the range
    startHeight :: !Word32,
    -- | hash of the last block of the range
    stopHash :: !BlockHash
  }
  deriving (Eq, Show, Generic, NFData)

instance Serial GetCFilters where
  deserialize = GetCFilters <$> getWord8 <*> getWord32le <*> deserialize
  serialize g = do
    putWord8 g.filterType
    putWord32le g.startHeight
    serialize g.stopHash

instance Binary GetCFilters where
  put = serialize
  get = deserialize

instance Serialize GetCFilters where
  put = serialize
  get = deserialize

-- | The @cfilter@ message: the filter of one block.
data CFilter = CFilter
  { -- | kind of filter
    filterType :: !FilterType,
    -- | hash of the block the filter is for
    blockHash :: !BlockHash,
    -- | the serialized filter
    filterBytes :: !ByteString
  }
  deriving (Eq, Show, Generic, NFData)

instance Serial CFilter where
  deserialize = CFilter <$> getWord8 <*> deserialize <*> getVarIntBytes
  serialize c = do
    putWord8 c.filterType
    serialize c.blockHash
    putVarIntBytes c.filterBytes

instance Binary CFilter where
  put = serialize
  get = deserialize

instance Serialize CFilter where
  put = serialize
  get = deserialize

-- | The @getcfheaders@ message. It asks for the filter hashes of a range of
-- blocks, with the filter header before the range. BIP 157 limits a range to
-- 2000 blocks.
data GetCFHeaders = GetCFHeaders
  { -- | kind of filter
    filterType :: !FilterType,
    -- | height of the first block of the range
    startHeight :: !Word32,
    -- | hash of the last block of the range
    stopHash :: !BlockHash
  }
  deriving (Eq, Show, Generic, NFData)

instance Serial GetCFHeaders where
  deserialize = GetCFHeaders <$> getWord8 <*> getWord32le <*> deserialize
  serialize g = do
    putWord8 g.filterType
    putWord32le g.startHeight
    serialize g.stopHash

instance Binary GetCFHeaders where
  put = serialize
  get = deserialize

instance Serialize GetCFHeaders where
  put = serialize
  get = deserialize

-- | The @cfheaders@ message, the answer to 'GetCFHeaders'. The filter header
-- of each block is the double SHA-256 of its filter hash and the previous
-- filter header.
data CFHeaders = CFHeaders
  { -- | kind of filter
    filterType :: !FilterType,
    -- | hash of the last block of the range
    stopHash :: !BlockHash,
    -- | filter header of the block before the range
    previousHeader :: !Hash256,
    -- | filter hash of every block of the range
    filterHashes :: ![Hash256]
  }
  deriving (Eq, Show, Generic, NFData)

-- | A message of more than 'maxFilterHashes' filter hashes fails the parse,
-- as BIP 157 requires.
instance Serial CFHeaders where
  deserialize =
    CFHeaders
      <$> getWord8
      <*> deserialize
      <*> deserialize
      <*> getVarIntListMax "cfheaders" maxFilterHashes deserialize
  serialize c = do
    putWord8 c.filterType
    serialize c.stopHash
    serialize c.previousHeader
    putVarIntList serialize c.filterHashes

instance Binary CFHeaders where
  put = serialize
  get = deserialize

instance Serialize CFHeaders where
  put = serialize
  get = deserialize

-- | The @getcfcheckpt@ message. It asks for the filter headers at every
-- thousandth block up to the given one.
data GetCFCheckpt = GetCFCheckpt
  { -- | kind of filter
    filterType :: !FilterType,
    -- | hash of the last block of the chain to cover
    stopHash :: !BlockHash
  }
  deriving (Eq, Show, Generic, NFData)

instance Serial GetCFCheckpt where
  deserialize = GetCFCheckpt <$> getWord8 <*> deserialize
  serialize g = do
    putWord8 g.filterType
    serialize g.stopHash

instance Binary GetCFCheckpt where
  put = serialize
  get = deserialize

instance Serialize GetCFCheckpt where
  put = serialize
  get = deserialize

-- | The @cfcheckpt@ message, the answer to 'GetCFCheckpt'.
data CFCheckpt = CFCheckpt
  { -- | kind of filter
    filterType :: !FilterType,
    -- | hash of the last block of the chain covered
    stopHash :: !BlockHash,
    -- | filter headers at heights 1000, 2000, and so on
    filterHeaders :: ![Hash256]
  }
  deriving (Eq, Show, Generic, NFData)

instance Serial CFCheckpt where
  deserialize = CFCheckpt <$> getWord8 <*> deserialize <*> getVarIntList deserialize
  serialize c = do
    putWord8 c.filterType
    serialize c.stopHash
    putVarIntList serialize c.filterHeaders

instance Binary CFCheckpt where
  put = serialize
  get = deserialize

instance Serialize CFCheckpt where
  put = serialize
  get = deserialize
