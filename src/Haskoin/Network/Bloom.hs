{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Bloom
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Bloom filters are used to reduce data transfer when synchronizing thin cients.
-- When bloom filters are used a client will obtain filtered blocks that only
-- contain transactions that pass the bloom filter. Transactions announced via inv
-- messages also pass the filter.
module Haskoin.Network.Bloom
  ( -- * Bloom Filters
    BloomFlags (..),
    BloomFilter (..),
    FilterLoad (..),
    FilterAdd (..),
    maxBloomSize,
    maxHashFuncs,
    maxFilterAddSize,
    bloomCreate,
    bloomInsert,
    bloomContains,
    isBloomValid,
    isBloomEmpty,
    isBloomFull,
    acceptsFilters,
    bloomRelevantUpdate,
    scriptPushData,
  )
where

import Control.Applicative ((<|>))
import Control.DeepSeq
import Control.Monad (when)
import Crypto.Secp256k1 (Ctx)
import Data.Binary (Binary (..))
import Data.Bits
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Foldable qualified as F
import Data.Hash.Murmur (murmur3)
import Data.List (foldl')
import Data.Sequence qualified as S
import Data.Serialize (Serialize (..))
import Data.Serialize qualified as Ser
import Data.Word
import GHC.Generics (Generic)
import Haskoin.Network.Common
import Haskoin.Script.Common
import Haskoin.Script.Standard
import Haskoin.Transaction.Common
import Haskoin.Util.Marshal

-- | Largest filter a peer may load, in bytes. 20,000 items with fp rate
-- < 0.1% or 10,000 items and <0.0001%.
maxBloomSize :: Int
maxBloomSize = 36000

-- | Largest number of hash functions a filter may use.
maxHashFuncs :: Word32
maxHashFuncs = 50

-- | Largest data element a 'FilterAdd' message may carry, in bytes. It is
-- the largest element a script can push (@MAX_SCRIPT_ELEMENT_SIZE@).
maxFilterAddSize :: Int
maxFilterAddSize = 520

ln2Squared :: Double
ln2Squared = 0.4804530139182014246671025263266649717305529515945455

ln2 :: Double
ln2 = 0.6931471805599453094172321214581765680755001343602552

bitMask :: [Word8]
bitMask = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]

-- | The bloom flags are used to tell the remote peer how to auto-update
-- the provided bloom filter.
data BloomFlags
  = -- | never update
    BloomUpdateNone
  | -- | auto-update on all outputs
    BloomUpdateAll
  | -- | auto-update on pay-to-pubkey or pay-to-multisig (default)
    BloomUpdateP2PubKeyOnly
  deriving (Eq, Show, Read, Generic, NFData)

-- | Only the two low bits of the flags byte count, as with the
-- @BLOOM_UPDATE_MASK@ of Bitcoin Core. The value 3 means no update.
instance Serial BloomFlags where
  deserialize = go . (.&. 3) =<< getWord8
    where
      go 1 = return BloomUpdateAll
      go 2 = return BloomUpdateP2PubKeyOnly
      go _ = return BloomUpdateNone

  serialize f = putWord8 $ case f of
    BloomUpdateNone -> 0
    BloomUpdateAll -> 1
    BloomUpdateP2PubKeyOnly -> 2

instance Binary BloomFlags where
  get = deserialize
  put = serialize

instance Serialize BloomFlags where
  get = deserialize
  put = serialize

-- | A bloom filter is a probabilistic data structure that SPV clients send to
-- other peers to filter the set of transactions received from them. Bloom
-- filters can have false positives but not false negatives. Some transactions
-- that pass the filter may not be relevant to the receiving peer. By
-- controlling the false positive rate, SPV nodes can trade off bandwidth
-- versus privacy.
data BloomFilter = BloomFilter
  { -- | bloom filter data
    array :: !(S.Seq Word8),
    -- | number of hash functions for this filter
    functions :: !Word32,
    -- | hash function random nonce
    tweak :: !Word32,
    -- | bloom filter auto-update flags
    flags :: !BloomFlags
  }
  deriving (Eq, Show, Read, Generic, NFData)

-- | A filter with more than 'maxBloomSize' bytes or more than 'maxHashFuncs'
-- hash functions fails the parse, as Bitcoin Core refuses such a
-- @filterload@ message.
instance Serial BloomFilter where
  deserialize = do
    VarInt len <- deserialize
    when (len > fromIntegral maxBloomSize) $
      fail ("Bloom filter of " ++ show len ++ " bytes is too large")
    bytes <- getByteString (fromIntegral len)
    functions <- getWord32le
    when (functions > maxHashFuncs) $
      fail ("Bloom filter with " ++ show functions ++ " hash functions has too many")
    tweak <- getWord32le
    flags <- deserialize
    return BloomFilter {array = S.fromList (BS.unpack bytes), ..}

  serialize BloomFilter {..} = do
    putVarInt $ S.length array
    mapM_ putWord8 (F.toList array)
    putWord32le functions
    putWord32le tweak
    serialize flags

instance Binary BloomFilter where
  put = serialize
  get = deserialize

instance Serialize BloomFilter where
  put = serialize
  get = deserialize

-- | Set a new bloom filter on the peer connection.
newtype FilterLoad = FilterLoad {filter :: BloomFilter}
  deriving (Eq, Show, Read, Generic)
  deriving newtype (NFData)

instance Serial FilterLoad where
  deserialize = FilterLoad <$> deserialize
  serialize (FilterLoad f) = serialize f

instance Binary FilterLoad where
  put = serialize
  get = deserialize

instance Serialize FilterLoad where
  put = serialize
  get = deserialize

-- | Add the given data element to the connections current filter without
-- requiring a completely new one to be set.
newtype FilterAdd = FilterAdd {get :: ByteString}
  deriving (Eq, Show, Read, Generic)
  deriving newtype (NFData)

-- | An element longer than 'maxFilterAddSize' fails the parse, as Bitcoin
-- Core refuses such a @filteradd@ message.
instance Serial FilterAdd where
  deserialize = do
    dat <- getVarIntBytes
    when (BS.length dat > maxFilterAddSize) $
      fail ("filteradd element of " ++ show (BS.length dat) ++ " bytes is too long")
    return $ FilterAdd dat

  serialize (FilterAdd bs) = putVarIntBytes bs

instance Binary FilterAdd where
  put = serialize
  get = deserialize

instance Serialize FilterAdd where
  put = serialize
  get = deserialize

-- | Build a bloom filter that will provide the given false positive rate when
-- the given number of elements have been inserted. The size is capped at
-- 'maxBloomSize' and the number of hash functions at 'maxHashFuncs'. A filter
-- built for many more elements than fit in 'maxBloomSize' gets zero hash
-- functions and then matches everything, as in Bitcoin Core.
bloomCreate ::
  -- | number of elements
  Int ->
  -- | false positive rate
  Double ->
  -- | random nonce (tweak) for the hash function
  Word32 ->
  -- | bloom filter flags
  BloomFlags ->
  -- | bloom filter
  BloomFilter
bloomCreate numElem fpRate =
  BloomFilter (S.replicate bloomSize 0) numHashF
  where
    -- Bloom filter size in bytes
    bloomSize = truncate $ min a b / 8
    -- Suggested size in bits
    a = -1 / ln2Squared * fromIntegral numElem * log fpRate
    -- Maximum size in bits
    b = fromIntegral $ maxBloomSize * 8
    numHashF
      | numElem == 0 = 0
      | otherwise = truncate $ min c (fromIntegral maxHashFuncs)
    -- Suggested number of hash functions
    c = fromIntegral bloomSize * 8 / fromIntegral numElem * ln2

bloomHash :: BloomFilter -> Word32 -> ByteString -> Word32
bloomHash b hashNum bs =
  murmur3 seed bs `mod` (fromIntegral (S.length (b.array)) * 8)
  where
    seed = hashNum * 0xfba4c795 + b.tweak

-- | Bit positions that the hash functions of a filter map some data to. There
-- are as many as the filter has hash functions. The filter must not be empty.
bloomBits :: BloomFilter -> ByteString -> [Word32]
bloomBits b bs =
  map (\i -> bloomHash b i bs) (take (fromIntegral b.functions) [0 ..])

-- | Insert arbitrary data into a bloom filter. Returns the new bloom filter
-- containing the new data. An empty filter stays empty.
bloomInsert ::
  -- | Original bloom filter
  BloomFilter ->
  -- | New data to insert
  ByteString ->
  -- | Bloom filter containing the new data
  BloomFilter
bloomInsert b bs
  | S.null b.array = b
  | otherwise = b {array = foldl' setBit' b.array (bloomBits b bs)}
  where
    setBit' s i =
      S.adjust
        (.|. bitMask !! fromIntegral (7 .&. i))
        (fromIntegral $ i `shiftR` 3)
        s

-- | Tests if some arbitrary data matches the filter. This can be either because
-- the data was inserted into the filter or because it is a false positive. An
-- empty filter, and a filter with no hash functions, match everything.
bloomContains ::
  -- | Bloom filter
  BloomFilter ->
  -- | Data that will be checked against the given bloom filter
  ByteString ->
  -- | Returns True if the data matches the filter
  Bool
bloomContains b bs
  | S.null b.array = True
  | otherwise = all isSet (bloomBits b bs)
  where
    isSet i =
      S.index b.array (fromIntegral $ i `shiftR` 3)
        .&. (bitMask !! fromIntegral (7 .&. i))
        /= 0

-- | Data elements pushed by a script, in order, without the empty ones. The
-- scan stops at the first byte sequence that is not a valid operation, as
-- @GetOp@ does in Bitcoin Core, and keeps the elements found before it.
scriptPushData :: ByteString -> [ByteString]
scriptPushData = either (const []) id . runGetS pushes
  where
    pushes :: Ser.Get [ByteString]
    pushes = do
      done <- isEmpty
      if done
        then return []
        else do
          op <- (Just <$> deserialize) <|> return Nothing
          case op of
            Nothing -> return []
            Just (OP_PUSHDATA d _)
              | not (BS.null d) -> (d :) <$> pushes
            Just _ -> pushes

-- | Checks if any output of a transaction matches the filter, as
-- @IsRelevantAndUpdate@ does in Bitcoin Core. An output matches when any data
-- element pushed by its script is in the filter. The outpoint of a matching
-- output is inserted according to the flags: always with 'BloomUpdateAll',
-- only for pay-to-pubkey and pay-to-multisig outputs with
-- 'BloomUpdateP2PubKeyOnly', and never with 'BloomUpdateNone'. The result is
-- 'Nothing' when no output matches, and otherwise the filter with the
-- outpoints added, which lets a future transaction spending them match too.
-- Non-standard output scripts are scanned like any other. An empty filter
-- matches every transaction and gets no outpoints.
bloomRelevantUpdate ::
  Ctx ->
  -- | Bloom filter
  BloomFilter ->
  -- | Tx that may (or may not) have relevant outputs
  Tx ->
  -- | Returns an updated bloom filter adding relevant output
  Maybe BloomFilter
bloomRelevantUpdate ctx b tx
  | S.null b.array = Just b
  | found = Just updated
  | otherwise = Nothing
  where
    (found, updated) = foldl' step (False, b) (zip [0 ..] tx.outputs)
    step :: (Bool, BloomFilter) -> (Word32, TxOut) -> (Bool, BloomFilter)
    step (f, cur) (i, out)
      | any (bloomContains cur) (scriptPushData out.script) =
          (True, addOutpoint cur i out)
      | otherwise = (f, cur)
    addOutpoint :: BloomFilter -> Word32 -> TxOut -> BloomFilter
    addOutpoint cur i out =
      case b.flags of
        BloomUpdateAll -> bloomInsert cur (outpoint i)
        BloomUpdateP2PubKeyOnly
          | paysToKeys out.script -> bloomInsert cur (outpoint i)
        _ -> cur
    outpoint i = runPutS $ serialize $ OutPoint {hash = txHash tx, index = i}
    paysToKeys script =
      case unmarshal ctx script of
        Right o -> isPayPK o || isPayMulSig o
        Left _ -> False

-- | Returns True if the filter is empty (all bytes set to 0x00)
isBloomEmpty :: BloomFilter -> Bool
isBloomEmpty b = all (== 0x00) $ F.toList b.array

-- | Returns True if the filter is full (all bytes set to 0xff)
isBloomFull :: BloomFilter -> Bool
isBloomFull b = all (== 0xff) $ F.toList b.array

-- | Tests if a given bloom filter is valid.
isBloomValid ::
  -- | Bloom filter to test
  BloomFilter ->
  -- | True if the given filter is valid
  Bool
isBloomValid BloomFilter {..} =
  S.length array <= maxBloomSize && functions <= maxHashFuncs

-- | Does the peer with these version services accept bloom filters?
acceptsFilters :: Word64 -> Bool
acceptsFilters srv = srv .&. nodeBloom /= 0
