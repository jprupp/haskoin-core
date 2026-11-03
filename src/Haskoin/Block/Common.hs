{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Block.Common
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Common data types and functions to handle blocks from the block chain.
module Haskoin.Block.Common
  ( -- * Blocks
    Block (..),
    BlockHeight,
    Timestamp,
    BlockHeader (..),
    headerHash,
    BlockLocator,
    GetBlocks (..),
    GetHeaders (..),
    BlockHeaderCount,
    BlockHash (..),
    blockHashToHex,
    hexToBlockHash,
    Headers (..),
    decodeCompact,
    encodeCompact,
  )
where

import Control.DeepSeq
import Control.Monad
import Data.Aeson
import Data.Aeson.Encoding
import Data.Binary (Binary (..))
import Data.Bits
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as L
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Hashable
import Data.Maybe
import Data.Serialize (Serialize (..))
import Data.String
import Data.String.Conversions
import Data.Text (Text)
import Data.Word
import GHC.Generics
import Haskoin.Crypto.Hash
import Haskoin.Network.Common
import Haskoin.Transaction.Common
import Haskoin.Util.Helpers
import Text.Read qualified as R

-- | Height of a block in the block chain, starting at 0 for Genesis.
type BlockHeight = Word32

-- | Block timestamp as Unix time (seconds since 1970-01-01 00:00 UTC).
type Timestamp = Word32

-- | Block header and transactions.
data Block = Block
  { header :: !BlockHeader,
    txs :: ![Tx]
  }
  deriving (Eq, Show, Read, Generic, Hashable, NFData)

instance Serial Block where
  deserialize = do
    header <- deserialize
    txs <- getVarIntList deserialize
    return $ Block header txs
  serialize (Block h txs) = do
    serialize h
    putVarIntList serialize txs

instance Serialize Block where
  get = deserialize
  put = serialize

instance Binary Block where
  get = deserialize
  put = serialize

instance ToJSON Block where
  toJSON (Block h t) =
    object ["header" .= h, "transactions" .= t]
  toEncoding (Block h t) =
    pairs $
      mconcat
        [ "header" `pair` toEncoding h,
          "transactions" `pair` list toEncoding t
        ]

instance FromJSON Block where
  parseJSON =
    withObject "Block" $ \o ->
      Block <$> o .: "header" <*> o .: "transactions"

-- | Block header hash. To be serialized reversed for display purposes.
newtype BlockHash = BlockHash {get :: Hash256}
  deriving (Eq, Ord, Generic, Hashable, Serial, NFData)

instance Serialize BlockHash where
  put = serialize
  get = deserialize

instance Binary BlockHash where
  put = serialize
  get = deserialize

instance Show BlockHash where
  showsPrec _ = shows . blockHashToHex

instance Read BlockHash where
  readPrec = do
    R.String str <- R.lexP
    maybe R.pfail return $ hexToBlockHash $ cs str

instance IsString BlockHash where
  fromString s =
    fromMaybe (error "Could not read block hash from hex string") $
      hexToBlockHash $
        cs s

instance FromJSON BlockHash where
  parseJSON =
    withText "BlockHash" $
      maybe mzero return . hexToBlockHash

instance ToJSON BlockHash where
  toJSON = String . blockHashToHex
  toEncoding (BlockHash h) = reversedHexEncoding h

-- | Block hashes are reversed with respect to the in-memory byte order in a
-- block hash when displayed.
blockHashToHex :: BlockHash -> Text
blockHashToHex (BlockHash h) = reversedHex h

-- | Convert a human-readable hex block hash into a 'BlockHash'. Bytes are
-- reversed as normal. The text must hold exactly 32 bytes of hex.
hexToBlockHash :: Text -> Maybe BlockHash
hexToBlockHash = fmap BlockHash . hexToReversedHash

-- | Hex of a 256-bit hash in display order, which is the reverse of its byte
-- order in memory. Block hashes and Merkle roots are shown this way.
reversedHex :: Hash256 -> Text
reversedHex = encodeHex . B.reverse . runPutS . serialize

-- | JSON encoding of a 256-bit hash in display order.
reversedHexEncoding :: Hash256 -> Encoding
reversedHexEncoding = hexEncoding . L.reverse . runPutL . serialize

-- | Parse hex in display order into a 256-bit hash. Any input that is not
-- exactly 32 bytes of hex is rejected instead of being truncated.
hexToReversedHash :: Text -> Maybe Hash256
hexToReversedHash hex = do
  bs <- decodeHex hex
  guard (B.length bs == 32)
  eitherToMaybe $ runGetS deserialize $ B.reverse bs

-- | Data type recording information of a 'Block'. The hash of a block is
-- defined as the hash of this data structure, serialized. The block mining
-- process involves finding a partial hash collision by varying the nonce in the
-- 'BlockHeader' and/or additional entropy in the coinbase 'Transaction' of this
-- 'Block'. Variations in the coinbase will result in different merkle roots in
-- the 'BlockHeader'.
--
-- The JSON form shows the previous block hash and the Merkle root in display
-- order, like the @getblockheader@ RPC call of Bitcoin Core.
data BlockHeader = BlockHeader
  { version :: !Word32, --  4 bytes

    -- | hash of the previous block (parent)
    prev :: !BlockHash, -- 32 bytes

    -- | root of the merkle tree of transactions
    merkle :: !Hash256, -- 32 bytes

    -- | unix timestamp
    timestamp :: !Timestamp, --  4 bytes

    -- | difficulty target
    bits :: !Word32, --  4 bytes

    -- | random nonce
    nonce :: !Word32 --  4 bytes
  }
  deriving (Eq, Ord, Show, Read, Generic, Hashable, NFData)

-- 80 bytes

instance ToJSON BlockHeader where
  toJSON (BlockHeader v p m t b n) =
    object
      [ "version" .= v,
        "prevblock" .= p,
        "merkleroot" .= reversedHex m,
        "timestamp" .= t,
        "bits" .= b,
        "nonce" .= n
      ]
  toEncoding (BlockHeader v p m t b n) =
    pairs $
      mconcat
        [ "version" `pair` word32 v,
          "prevblock" `pair` toEncoding p,
          "merkleroot" `pair` reversedHexEncoding m,
          "timestamp" `pair` toEncoding t,
          "bits" `pair` toEncoding b,
          "nonce" `pair` toEncoding n
        ]

instance FromJSON BlockHeader where
  parseJSON =
    withObject "BlockHeader" $ \o ->
      BlockHeader
        <$> o .: "version"
        <*> o .: "prevblock"
        <*> (merkleRoot =<< o .: "merkleroot")
        <*> o .: "timestamp"
        <*> o .: "bits"
        <*> o .: "nonce"
    where
      merkleRoot = maybe (fail "Invalid Merkle root") return . hexToReversedHash

instance Serial BlockHeader where
  deserialize = do
    v <- getWord32le
    p <- deserialize
    m <- deserialize
    t <- getWord32le
    b <- getWord32le
    n <- getWord32le
    return
      BlockHeader
        { version = v,
          prev = p,
          merkle = m,
          timestamp = t,
          bits = b,
          nonce = n
        }
  serialize (BlockHeader v p m bt bb n) = do
    putWord32le v
    serialize p
    serialize m
    putWord32le bt
    putWord32le bb
    putWord32le n

instance Binary BlockHeader where
  put = serialize
  get = deserialize

instance Serialize BlockHeader where
  put = serialize
  get = deserialize

-- | Compute hash of 'BlockHeader'.
headerHash :: BlockHeader -> BlockHash
headerHash = BlockHash . doubleSHA256 . runPutS . serialize

-- | A block locator is a set of block headers, denser towards the best block
-- and sparser towards the genesis block. It starts at the highest block known.
-- It is used by a node to synchronize against the network. When the locator is
-- provided to a peer, it will send back block hashes starting from the first
-- block in the locator that it recognizes.
type BlockLocator = [BlockHash]

-- | Data type representing a getblocks message request. It is used in the
-- bitcoin protocol to retrieve blocks from a peer by providing it a
-- 'BlockLocator' object. The response to a 'GetBlocks' message is an 'Inv'
-- message containing a list of block hashes that the peer believes this node is
-- missing. The number of block hashes in that inv message will end at the stop
-- block hash, at at the tip of the chain, or after 500 entries, whichever comes
-- earlier.
data GetBlocks = GetBlocks
  { version :: !Word32,
    -- | block locator object
    locator :: !BlockLocator,
    -- | hash of the last desired block
    stop :: !BlockHash
  }
  deriving (Eq, Show, Read, Generic, NFData)

instance Serial GetBlocks where
  deserialize =
    GetBlocks
      <$> getWord32le
      <*> getVarIntList deserialize
      <*> deserialize
  serialize (GetBlocks v xs h) = do
    putWord32le v
    putVarIntList serialize xs
    serialize h

instance Serialize GetBlocks where
  put = serialize
  get = deserialize

-- | Similar to the 'GetBlocks' message type but for retrieving block headers
-- only. The response to a 'GetHeaders' request is a 'Headers' message
-- containing a list of block headers. A maximum of 2000 block headers can be
-- returned. 'GetHeaders' is used by simplified payment verification (SPV)
-- clients to exclude block contents when synchronizing the block chain.
data GetHeaders = GetHeaders
  { version :: !Word32,
    -- | block locator object
    locator :: !BlockLocator,
    -- | hash of the last desired block header
    stop :: !BlockHash
  }
  deriving (Eq, Show, Read, Generic, NFData)

instance Serial GetHeaders where
  deserialize =
    GetHeaders
      <$> getWord32le
      <*> getVarIntList deserialize
      <*> deserialize
  serialize (GetHeaders v xs h) = do
    putWord32le v
    putVarIntList serialize xs
    serialize h

instance Serialize GetHeaders where
  put = serialize
  get = deserialize

instance Binary GetHeaders where
  put = serialize
  get = deserialize

-- | 'BlockHeader' type with a transaction count as 'VarInt'
type BlockHeaderCount = (BlockHeader, VarInt)

-- | The 'Headers' type is used to return a list of block headers in
-- response to a 'GetHeaders' message.
newtype Headers = Headers
  { -- | list of block headers with transaction count
    list :: [BlockHeaderCount]
  }
  deriving (Eq, Show, Read, Generic, NFData)

instance Serial Headers where
  deserialize = Headers <$> getVarIntList (liftM2 (,) deserialize deserialize)
  serialize (Headers xs) =
    putVarIntList (\(a, b) -> serialize a >> serialize b) xs

instance Serialize Headers where
  put = serialize
  get = deserialize

instance Binary Headers where
  put = serialize
  get = deserialize

-- | Decode the compact number used in the difficulty target of a block.
--
-- The compact format is a representation of a whole number \(N\) using an
-- unsigned 32-bit number similar to a floating point format. The most
-- significant 8 bits are the unsigned exponent of base 256. This exponent can
-- be thought of as the number of bytes of \(N\). The lower 23 bits are the
-- mantissa. Bit number 24 represents the sign of \(N\).
--
-- \[
-- N = -1^{sign} \times mantissa \times 256^{exponent-3}
-- \]
decodeCompact ::
  Word32 ->
  -- | true means overflow
  (Integer, Bool)
decodeCompact nCompact = (if neg then res * (-1) else res, over)
  where
    nSize :: Int
    nSize = fromIntegral nCompact `shiftR` 24
    nWord' :: Word32
    nWord' = nCompact .&. 0x007fffff
    nWord :: Word32
    nWord
      | nSize <= 3 = nWord' `shiftR` (8 * (3 - nSize))
      | otherwise = nWord'
    res :: Integer
    res
      | nSize <= 3 = fromIntegral nWord
      | otherwise = fromIntegral nWord `shiftL` (8 * (nSize - 3))
    neg = nWord /= 0 && (nCompact .&. 0x00800000) /= 0
    over =
      nWord /= 0
        && ( nSize > 34
               || nWord > 0xff && nSize > 33
               || nWord > 0xffff && nSize > 32
           )

-- | Encode an 'Integer' to the compact number format used in the difficulty
-- target of a block. The exponent is a single byte, so numbers that need more
-- than 255 bytes cannot be encoded and raise an error, as the assertion in
-- Bitcoin Core does.
encodeCompact :: Integer -> Word32
encodeCompact i
  | nSize > 255 = error "encodeCompact: number too large for the compact format"
  | otherwise = nCompact
  where
    i' = abs i
    neg = i < 0
    nSize' :: Int
    nSize' =
      let f 0 = 0
          f n = 1 + f (n `shiftR` 8)
       in f i'
    nCompact''' :: Word32
    nCompact'''
      | nSize' <= 3 = fromIntegral $ (low64 .&. i') `shiftL` (8 * (3 - nSize'))
      | otherwise = fromIntegral $ low64 .&. (i' `shiftR` (8 * (nSize' - 3)))
    nCompact'' :: Word32
    nSize :: Int
    (nCompact'', nSize)
      | nCompact''' .&. 0x00800000 /= 0 = (nCompact''' `shiftR` 8, nSize' + 1)
      | otherwise = (nCompact''', nSize')
    nCompact' :: Word32
    nCompact' = nCompact'' .|. (fromIntegral nSize `shiftL` 24)
    nCompact :: Word32
    nCompact
      | neg && (nCompact' .&. 0x007fffff /= 0) = nCompact' .|. 0x00800000
      | otherwise = nCompact'
    low64 :: Integer
    low64 = 0xffffffffffffffff
