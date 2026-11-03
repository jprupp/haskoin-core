{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.CompactBlock
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Messages of the compact block relay protocol (BIP 152): @sendcmpct@,
-- @cmpctblock@, @getblocktxn@ and @blocktxn@.
module Haskoin.Network.CompactBlock
  ( SendCompact (..),
    CompactBlock (..),
    PrefilledTx (..),
    GetBlockTxn (..),
    BlockTxn (..),
    maxShortId,
  )
where

import Control.DeepSeq
import Control.Monad (when)
import Data.Binary (Binary (..))
import Data.Bits (shiftL, shiftR, (.|.))
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Serialize (Serialize (..))
import Data.Word (Word32, Word64)
import GHC.Generics (Generic)
import Haskoin.Block.Common (BlockHash, BlockHeader)
import Haskoin.Network.Common
import Haskoin.Transaction.Common (Tx)

-- | The @sendcmpct@ message. It tells the peer whether to announce new blocks
-- as compact blocks, and which version of the protocol to use. Version 1
-- identifies transactions by their txid and version 2 by their wtxid.
data SendCompact = SendCompact
  { -- | announce blocks with @cmpctblock@ instead of @inv@ or @headers@
    announce :: !Bool,
    -- | compact block protocol version
    version :: !Word64
  }
  deriving (Eq, Show, Read, Generic, NFData)

instance Serial SendCompact where
  deserialize = SendCompact <$> ((/= 0) <$> getWord8) <*> getWord64le
  serialize (SendCompact a v) = do
    putWord8 (if a then 1 else 0)
    putWord64le v

instance Binary SendCompact where
  put = serialize
  get = deserialize

instance Serialize SendCompact where
  put = serialize
  get = deserialize

-- | Largest short transaction identifier. Short identifiers are six bytes.
maxShortId :: Word64
maxShortId = 0xffffffffffff

getShortId :: (MonadGet m) => m Word64
getShortId = do
  low <- getWord32le
  high <- getWord16le
  return $ fromIntegral high `shiftL` 32 .|. fromIntegral low

putShortId :: (MonadPut m) => Word64 -> m ()
putShortId x
  | x > maxShortId = error ("Short transaction id does not fit six bytes: " ++ show x)
  | otherwise = do
      putWord32le (fromIntegral x)
      putWord16le (fromIntegral (x `shiftR` 32))

-- | A transaction sent along with a compact block, with its position in the
-- block.
data PrefilledTx = PrefilledTx
  { -- | position of the transaction in the block
    index :: !Word32,
    -- | the transaction
    tx :: !Tx
  }
  deriving (Eq, Show, Generic, NFData)

-- | The @cmpctblock@ message: a block header with short identifiers for most
-- of its transactions, and the full transactions the sender expects the peer
-- to lack. Positions in the block are absolute here; on the wire each one is
-- encoded as its distance from the previous one, as BIP 152 requires.
data CompactBlock = CompactBlock
  { -- | block header
    header :: !BlockHeader,
    -- | nonce the short identifiers were computed with
    nonce :: !Word64,
    -- | short identifiers of the transactions not sent in full
    shortIds :: ![Word64],
    -- | transactions sent in full, in order of their position
    prefilled :: ![PrefilledTx]
  }
  deriving (Eq, Show, Generic, NFData)

instance Serial CompactBlock where
  deserialize =
    CompactBlock
      <$> deserialize
      <*> getWord64le
      <*> getVarIntList getShortId
      <*> getDifferentialList (\i -> PrefilledTx i <$> deserialize)

  serialize c = do
    serialize c.header
    putWord64le c.nonce
    putVarIntList putShortId c.shortIds
    putDifferentialList (.index) (serialize . (.tx)) c.prefilled

instance Binary CompactBlock where
  put = serialize
  get = deserialize

instance Serialize CompactBlock where
  put = serialize
  get = deserialize

-- | The @getblocktxn@ message. It asks for the transactions at the given
-- positions of a block. Positions are absolute here and differentially
-- encoded on the wire.
data GetBlockTxn = GetBlockTxn
  { -- | hash of the block
    hash :: !BlockHash,
    -- | positions of the wanted transactions, in increasing order
    indexes :: ![Word32]
  }
  deriving (Eq, Show, Generic, NFData)

instance Serial GetBlockTxn where
  deserialize = GetBlockTxn <$> deserialize <*> getDifferentialList return
  serialize g = do
    serialize g.hash
    putDifferentialList id (const (return ())) g.indexes

instance Binary GetBlockTxn where
  put = serialize
  get = deserialize

instance Serialize GetBlockTxn where
  put = serialize
  get = deserialize

-- | The @blocktxn@ message, the answer to 'GetBlockTxn'.
data BlockTxn = BlockTxn
  { -- | hash of the block
    hash :: !BlockHash,
    -- | the requested transactions, in the order they were asked for
    transactions :: ![Tx]
  }
  deriving (Eq, Show, Generic, NFData)

instance Serial BlockTxn where
  deserialize = BlockTxn <$> deserialize <*> getVarIntList deserialize
  serialize b = do
    serialize b.hash
    putVarIntList serialize b.transactions

instance Binary BlockTxn where
  put = serialize
  get = deserialize

instance Serialize BlockTxn where
  put = serialize
  get = deserialize

-- | Read a list whose elements each start with a block position. The first
-- position is written as is, and every later one as its distance from the
-- previous position minus one. A position that does not fit 32 bits fails
-- the parse.
getDifferentialList :: (MonadGet m) => (Word32 -> m a) -> m [a]
getDifferentialList element = do
  VarInt count <- deserialize
  when (count > maxListSize) $
    fail ("List count too large: " ++ show count)
  go count Nothing
  where
    go 0 _ = return []
    go n previous = do
      VarInt distance <- deserialize
      let position = toInteger distance + maybe 0 (\p -> toInteger p + 1) previous
      when (position > 0xffffffff) $
        fail ("Block position does not fit 32 bits: " ++ show position)
      let i = fromInteger position
      x <- element i
      (x :) <$> go (n - 1) (Just i)

-- | Write a list whose elements each carry a block position, in the encoding
-- that 'getDifferentialList' reads. Positions must be strictly increasing,
-- otherwise their distances cannot be encoded and this is an error.
putDifferentialList :: (MonadPut m) => (a -> Word32) -> (a -> m ()) -> [a] -> m ()
putDifferentialList position element xs = do
  putVarInt (length xs)
  go Nothing xs
  where
    go _ [] = return ()
    go previous (x : rest) = do
      let i = position x
      case previous of
        Nothing -> putVarInt i
        Just p
          | i > p -> putVarInt (i - p - 1)
          | otherwise ->
              error ("Block positions must be strictly increasing: " ++ show p ++ " then " ++ show i)
      element x
      go (Just i) rest
