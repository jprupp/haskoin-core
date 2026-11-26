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
-- Bloom filters are used to reduce data transfer when synchronizing thin clients.
-- When bloom filters are used a client will obtain filtered blocks that only
-- contain transactions that pass the bloom filter. Transactions announced via inv
-- messages also pass the filter.
--
-- The module has both sides of BIP 37. A client builds its filter with
-- 'bloomCreate' and 'bloomInsert'. A node tests a transaction that it relays
-- with 'bloomRelevantUpdate', and the transactions of a block that it serves
-- with 'bloomRelevantBlock'.
--
-- The node side takes the t'Network', because Bitcoin Cash Node does not match
-- as Bitcoin Core does, in three places:
--
-- * A block of Bitcoin Cash holds its transactions in the order of their
--   ids, so a transaction may stand before the one it spends. The node
--   therefore reads the outputs of the whole block first, and the inputs
--   after. Use 'bloomRelevantBlock' for a block: a fold of
--   'bloomRelevantUpdate' misses such a spender.
-- * An output of Bitcoin Cash may carry tokens in front of its locking
--   script. The node matches the locking script only.
-- * The bare multisig that 'BloomUpdateP2PubKeyOnly' follows has at most 16
--   keys on Bitcoin Cash, each a direct push. On Bitcoin it has at most 20,
--   pushed in any way.
--
-- A network is one of Bitcoin Cash when it has a fork id ('sigHashForkId').
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
    bloomRelevantBlock,
    scriptPushData,
  )
where

import Control.Applicative ((<|>))
import Control.DeepSeq
import Control.Monad (guard, when)
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
import Data.Maybe (fromMaybe, isJust)
import Data.Sequence qualified as S
import Data.Serialize (Serialize (..))
import Data.Serialize qualified as Ser
import Data.Word
import GHC.Generics (Generic)
import Haskoin.Network.Common
import Haskoin.Network.Data (Network (..))
import Haskoin.Script.CashToken (splitTokenData)
import Haskoin.Script.Common
import Haskoin.Transaction.Common

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
--
-- The function is total. The rate is a probability between 0 and 1, and the
-- reference nodes give no value outside of that (the conversion they make is
-- undefined in C++), so the arguments are read by what they ask for:
--
-- * No element, or a count below 0, or a rate of 1 or more: nothing has to
--   be told apart, so the result is the filter of no bytes, which matches
--   everything. A caller with a wrong argument then hears of every
--   transaction and misses none.
-- * A rate of 0 or less, or one that is not a number: the largest filter,
--   which is the nearest a filter comes to no false positive.
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
    -- Bloom filter size in bytes. The guards come before any conversion of
    -- a number that is negative, infinite or not a number.
    bloomSize
      | numElem <= 0 || fpRate >= 1 = 0
      | fpRate > 0 = truncate $ min a b / 8
      | otherwise = maxBloomSize
    -- Suggested size in bits
    a = -1 / ln2Squared * fromIntegral numElem * log fpRate
    -- Maximum size in bits
    b = fromIntegral $ maxBloomSize * 8
    numHashF
      | numElem <= 0 = 0
      | otherwise = truncate $ min c (fromIntegral maxHashFuncs)
    -- Suggested number of hash functions. The bits per element are divided
    -- as integers first, as in the constructor of CBloomFilter in Bitcoin
    -- Core, so that both pick the same number.
    c = fromIntegral ((bloomSize * 8) `div` numElem) * ln2

bloomHash :: BloomFilter -> Word32 -> ByteString -> Word32
bloomHash b hashNum bs =
  murmur3 seed bs `mod` (fromIntegral (S.length (b.array)) * 8)
  where
    seed = hashNum * 0xfba4c795 + b.tweak

-- | Bit positions that the hash functions of a filter map some data to. There
-- are as many as the filter has hash functions. The filter must have bytes.
bloomBits :: BloomFilter -> ByteString -> [Word32]
bloomBits b bs =
  map (\i -> bloomHash b i bs) (take (fromIntegral b.functions) [0 ..])

-- | Insert arbitrary data into a bloom filter. Returns the new bloom filter
-- containing the new data. A filter of no bytes stays as it is, and so does
-- a filter with no hash functions.
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
-- the data was inserted into the filter or because it is a false positive. A
-- filter of no bytes, and a filter with no hash functions, match everything.
-- A filter that has bytes and hash functions and no bit set matches nothing:
-- that is the filter for which 'isBloomEmpty' is the right question.
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

-- | Tells whether a transaction is relevant to a filter, and updates the
-- filter, as @CBloomFilter::IsRelevantAndUpdate@ does in the node of the
-- network (Bitcoin Core, or Bitcoin Cash Node on a network with a fork id)
-- and as BIP 37 specifies. A transaction is relevant when the filter
-- contains:
--
-- 1. its hash, or
-- 2. a data element pushed by one of its output scripts, or
-- 3. an outpoint that one of its inputs spends, or
-- 4. a data element pushed by one of its input scripts.
--
-- The result is 'Nothing' for a transaction that is not relevant, and
-- otherwise the filter. For each output that matches, its outpoint is
-- inserted according to the flags: always with 'BloomUpdateAll', only for
-- pay-to-pubkey and bare multisig outputs with 'BloomUpdateP2PubKeyOnly', and
-- never with 'BloomUpdateNone'. This lets a later transaction that spends the
-- output match through rule 3. As in the nodes, the inputs are looked at
-- only when neither the hash nor an output matched.
--
-- Pay-to-pubkey and multisig are told by the shape of the script, as
-- @Solver@ does in the node: a key is any push of 33 bytes that starts
-- with 02 or 03, or of 65 bytes that starts with 04, 06 or 07. It does not
-- have to be a point of the curve. A multisig has from 1 to 20 keys on
-- Bitcoin, pushed in any way. On Bitcoin Cash it has from 1 to 16 keys, and
-- each is a direct push. Non-standard scripts are scanned like any other. A
-- filter of no bytes matches every transaction and gets no outpoints.
--
-- On Bitcoin Cash the output script is the locking script alone: the tokens
-- that an output may carry in front of it are not matched. A field that
-- starts with the token prefix byte and has no well-formed prefix is a
-- locking script as a whole, as the node reads it.
--
-- This is the test for one transaction, such as one that a node relays. For
-- the transactions of a block use 'bloomRelevantBlock': on Bitcoin Cash a
-- fold of this function over a block does not give the answer of the node.
bloomRelevantUpdate ::
  -- | the network, which selects the rules of its reference node
  Network ->
  -- | Bloom filter
  BloomFilter ->
  -- | transaction to test
  Tx ->
  -- | the filter, updated, when the transaction is relevant
  Maybe BloomFilter
bloomRelevantUpdate net b tx
  | found = Just updated
  | matchInputs b tx = Just b
  | otherwise = Nothing
  where
    (found, updated) = matchOutputs net b tx

-- | Tells which transactions of a block are relevant to a filter, and
-- updates the filter, as @CMerkleBlock@ does in the node of the network when
-- it builds a filtered block. The transactions are given in the order of the
-- block. The result has one flag for each of them, in that order, and the
-- filter as the block left it, which the node keeps for the peer. Give the
-- flags to 'Haskoin.Block.Merkle.buildPartialMerkle' for the @merkleblock@
-- message, and send the transactions whose flag is set after it.
--
-- On Bitcoin a transaction comes after the ones it spends, and each
-- transaction is tested once with 'bloomRelevantUpdate', on the filter as
-- the transactions before it left it.
--
-- On Bitcoin Cash the transactions of a block are in the order of their ids,
-- so a transaction may stand before the one it spends. One pass would test
-- its inputs before the output it spends is in the filter, and miss it.
-- Bitcoin Cash Node therefore makes two passes, and so does this function:
-- the hash and the outputs of every transaction first, which update the
-- filter, then the inputs of the transactions that did not match, on the
-- filter as the whole block left it. Two folds of 'bloomRelevantUpdate' are
-- not the same thing: the second would test the outputs again, on a filter
-- that holds the outpoints of later transactions.
--
-- The time grows with the size of the block.
bloomRelevantBlock ::
  -- | the network, which selects the rules of its reference node
  Network ->
  -- | Bloom filter of the peer
  BloomFilter ->
  -- | transactions of the block, in the order of the block
  [Tx] ->
  -- | one flag for each transaction, and the filter after the block
  ([Bool], BloomFilter)
bloomRelevantBlock net b txs
  | cashRules net = (zipWith (||) found (map (matchInputs afterOutputs) txs), afterOutputs)
  | otherwise = inOrder whole b txs
  where
    (found, afterOutputs) = inOrder (matchOutputs net) b txs
    whole f tx = maybe (False, f) (\f' -> (True, f')) (bloomRelevantUpdate net f tx)

-- | Run a match over transactions in order, each one on the filter as the
-- ones before it left it. The fold is strict, so that a block of many
-- transactions builds no chain of suspended filters.
inOrder ::
  (BloomFilter -> Tx -> (Bool, BloomFilter)) ->
  BloomFilter ->
  [Tx] ->
  ([Bool], BloomFilter)
inOrder match b0 txs = (reverse flags, final)
  where
    (flags, final) = foldl' step ([], b0) txs
    step (acc, b) tx =
      let (found, b') = match b tx
       in found `seq` b' `seq` (found : acc, b')

-- | Does the network follow the rules of Bitcoin Cash Node? It does when it
-- has a fork id.
cashRules :: Network -> Bool
cashRules net = isJust net.sigHashForkId

-- | The first half of the match, @MatchAndInsertOutputs@ in Bitcoin Cash
-- Node: does the filter contain the hash of the transaction, or a data
-- element of one of its output scripts? The filter comes back with the
-- outpoints that the flags ask for.
matchOutputs :: Network -> BloomFilter -> Tx -> (Bool, BloomFilter)
matchOutputs net b tx
  -- a shortcut: a filter of no bytes contains every hash and takes no insert
  | S.null b.array = (True, b)
  | otherwise = (hashFound || outputFound, updated)
  where
    hash = txHash tx
    hashFound = bloomContains b (runPutS (serialize hash))
    (outputFound, updated) = foldl' step (False, b) (zip [0 ..] tx.outputs)
    step :: (Bool, BloomFilter) -> (Word32, TxOut) -> (Bool, BloomFilter)
    step (f, cur) (i, out)
      | any (bloomContains cur) (scriptPushData script) =
          (True, addOutpoint cur i script)
      | otherwise = (f, cur)
      where
        script = lockingScript net out
    addOutpoint :: BloomFilter -> Word32 -> ByteString -> BloomFilter
    addOutpoint cur i script =
      case b.flags of
        BloomUpdateAll -> bloomInsert cur (outpoint i)
        BloomUpdateP2PubKeyOnly
          | paysToKeys net script -> bloomInsert cur (outpoint i)
        _ -> cur
    outpoint i = runPutS $ serialize $ OutPoint {hash = hash, index = i}

-- | The second half of the match, @MatchInputs@ in Bitcoin Cash Node: does
-- the filter contain an outpoint that the transaction spends, or a data
-- element of one of its input scripts? The filter does not change.
matchInputs :: BloomFilter -> Tx -> Bool
matchInputs b tx = any inputMatches tx.inputs
  where
    inputMatches :: TxIn -> Bool
    inputMatches input =
      bloomContains b (runPutS (serialize input.outpoint))
        || any (bloomContains b) (scriptPushData input.script)

-- | The locking script of an output, which is what the filter is tested
-- against. On Bitcoin it is the script field. On Bitcoin Cash the token
-- prefix is taken off, and a field whose prefix is not well formed is all
-- locking script, as @UnwrapScriptPubKey@ leaves it in Bitcoin Cash Node.
lockingScript :: Network -> TxOut -> ByteString
lockingScript net out
  | cashRules net = either (const out.script) snd (splitTokenData out.script)
  | otherwise = out.script

-- | Is the script pay-to-pubkey or bare multisig, as @Solver@ classifies them
-- in the node of the network (@MatchPayToPubkey@ and @MatchMultisig@)? Keys
-- are tested by size and first byte only.
--
-- The two nodes have the same pay-to-pubkey and not the same multisig.
-- Bitcoin Core takes up to 20 keys (@MAX_PUBKEYS_PER_MULTISIG@), with a
-- number above 16 written as a push of one byte, and a key pushed in any
-- way. Bitcoin Cash Node takes the numbers 'OP_1' to 'OP_16' only, and a key
-- as a direct push only.
paysToKeys :: Network -> ByteString -> Bool
paysToKeys net script = payToPubkey || multisig
  where
    opCheckSig = 0xac
    payToPubkey =
      or
        [ BS.length script == size + 2
            && BS.head script == fromIntegral size
            && BS.last script == opCheckSig
            && validKeySize (BS.take size (BS.drop 1 script))
        | size <- [65, 33]
        ]
    multisig =
      case runGetS deserialize script :: Either String Script of
        Right (Script (m : rest)) ->
          case span isKey rest of
            (keys, [n, OP_CHECKMULTISIG]) -> fromMaybe False $ do
              required <- keyCount m
              total <- keyCount n
              return (required <= total && total == length keys)
            _ -> False
        _ -> False
    cash = cashRules net
    maxKeys = if cash then 16 else 20
    -- 'scriptNumber' gives no number below 1
    keyCount op = do
      count <- scriptNumber op
      guard (count <= maxKeys)
      return count
    isKey (OP_PUSHDATA bs kind) = validKeySize bs && (not cash || kind == OPCODE)
    isKey _ = False

-- | @CPubKey::ValidSize@ of Bitcoin Core: 33 bytes after 02 or 03, 65 bytes
-- after 04, 06 or 07.
validKeySize :: ByteString -> Bool
validKeySize key =
  case BS.uncons key of
    Just (prefix, _)
      | prefix == 2 || prefix == 3 -> BS.length key == 33
      | prefix == 4 || prefix == 6 || prefix == 7 -> BS.length key == 65
    _ -> False

-- | The number that a script operation stands for in a multisig template,
-- as @GetScriptNumber@ reads it in Bitcoin Core: 'OP_1' to 'OP_16', or a
-- minimal push of one byte for 17 and above. It is never below 1.
scriptNumber :: ScriptOp -> Maybe Int
scriptNumber op =
  case op of
    OP_PUSHDATA bs OPCODE
      | BS.length bs == 1 && BS.head bs > 16 && BS.head bs < 0x80 ->
          Just (fromIntegral (BS.head bs))
    OP_PUSHDATA {} -> Nothing
    OP_0 -> Nothing
    OP_1NEGATE -> Nothing
    _ -> do
      bs <- pushOpData op
      guard (BS.length bs == 1)
      return (fromIntegral (BS.head bs))

-- | Returns True if no bit of the filter is set (all bytes are 0x00). Such a
-- filter matches nothing, with two exceptions that match everything: a
-- filter of no bytes, for which this is True too, and a filter with no hash
-- functions. Ask 'bloomContains' what a filter matches.
isBloomEmpty :: BloomFilter -> Bool
isBloomEmpty b = all (== 0x00) $ F.toList b.array

-- | Returns True if every bit of the filter is set (all bytes are 0xff).
-- Such a filter matches everything. It is True for a filter of no bytes
-- too, which also matches everything. A filter with no hash functions
-- matches everything whatever its bits are, so it may not be full.
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
