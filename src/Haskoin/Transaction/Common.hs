{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Transaction.Common
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Code related to transactions parsing and serialization.
module Haskoin.Transaction.Common
  ( -- * Transactions
    Tx (..),
    TxIn (..),
    TxOut (..),
    OutPoint (..),
    TxHash (..),
    WitnessData,
    WitnessStack,
    WitnessStackItem,
    txHash,
    txWitnessHash,
    txWeight,
    txVirtualSize,
    hexToTxHash,
    txHashToHex,
    nosigTxHash,
    hasWitness,
    decodeTx,
    decodeLegacyTx,
    parseLegacyTx,
    nullOutPoint,
  )
where

import Control.Applicative ((<|>))
import Control.DeepSeq
import Control.Monad (forM_, guard, liftM2, mzero, replicateM, unless, when, (<=<))
import Data.Aeson as A
import Data.Aeson.Encoding qualified as E
import Data.Bifunctor (first)
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Builder (char7)
import Data.ByteString.Lazy qualified as BL
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Either (isLeft)
import Data.Hashable (Hashable (..))
import Data.Maybe (fromMaybe)
import Data.Serialize (Serialize (..))
import Data.String (IsString, fromString)
import Data.String.Conversions (cs)
import Data.Text (Text)
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Crypto.Hash
import Haskoin.Network.Common
import Haskoin.Util.Direct (decodeDirect, encodeDirect, getDirect, putDirect, sizeDirect)
import Haskoin.Util.Helpers
import Text.Read as R

-- | A hash that identifies a transaction: the transaction id of 'txHash',
-- which leaves the witness out, or the witness transaction id of
-- 'txWitnessHash', which includes it. Shown in hex with the bytes reversed,
-- as block explorers and Bitcoin Core show it.
newtype TxHash = TxHash {get :: Hash256}
  deriving (Eq, Ord, Generic)
  deriving newtype (Hashable, NFData)

instance Serial TxHash where
  serialize (TxHash h) = serialize h
  {-# INLINE serialize #-}
  deserialize = TxHash <$> deserialize
  {-# INLINE deserialize #-}

instance Serialize TxHash where
  put = serialize
  get = deserialize

instance Binary TxHash where
  put = serialize
  get = deserialize

instance Show TxHash where
  showsPrec _ = shows . txHashToHex

instance Read TxHash where
  readPrec = do
    R.String str <- R.lexP
    maybe R.pfail return $ hexToTxHash $ cs str

instance IsString TxHash where
  fromString s =
    let e = error "Could not read transaction hash from hex string"
     in fromMaybe e $ hexToTxHash $ cs s

instance FromJSON TxHash where
  parseJSON =
    withText "txid" $
      maybe mzero return . hexToTxHash

instance ToJSON TxHash where
  toJSON = A.String . txHashToHex
  toEncoding (TxHash h) = hexEncodingReversed h.get

-- | Hash of the transaction with every input script and the whole witness
-- removed, so that it is the same before and after signing, whether the
-- signatures go in the input scripts or in the witness.
nosigTxHash :: Tx -> TxHash
nosigTxHash Tx {..} =
  TxHash (doubleSHA256 (encodeDirect (serialize tx)))
  where
    tx = Tx {inputs = map clr inputs, witness = [], ..}
    clr TxIn {..} = TxIn {script = B.empty, ..}

-- | Convert transaction hash to hex form, reversing bytes.
txHashToHex :: TxHash -> Text
txHashToHex (TxHash h) = encodeHexReversed h.get

-- | Convert transaction hash from hex, reversing bytes. The hex must be
-- exactly 32 bytes long, as @uint256::FromHex@ requires in Bitcoin Core.
hexToTxHash :: Text -> Maybe TxHash
hexToTxHash hex = do
  bs <- B.reverse <$> decodeHex hex
  guard (B.length bs == 32)
  h <- either (const Nothing) Just (runGetS deserialize bs)
  return $ TxHash h

-- | Witness stack for SegWit transactions.
type WitnessData = [WitnessStack]

-- | Witness stack for SegWit transactions.
type WitnessStack = [WitnessStackItem]

-- | Witness stack item for SegWit transactions.
type WitnessStackItem = ByteString

-- | Data type representing a transaction.
--
-- __Equality.__ The witness is a list beside the inputs, so one transaction
-- can be written in several ways: with no list or with a list of empty
-- stacks, with or without the empty stacks of its last inputs, with or
-- without stacks beyond its inputs. All of them are written as the same
-- bytes and have the same ids, and 'Eq', 'Ord' and 'Hashable' take them for
-- one transaction: two values are equal when they have the same version,
-- inputs, outputs and lock time, and the same witness stack for each input.
-- @CTransaction::Equals@ of Bitcoin Core compares the same fields, and
-- there each input holds its own stack. So a transaction is equal to itself
-- after it is written and read, and a 'Data.Set.Set' or a
-- 'Data.HashMap.Strict.HashMap' counts it once. 'Show' and the field
-- 'witness' still give the list as it was built.
--
-- The derived instances compared the lists, so that a transaction with a
-- list of empty stacks was not the one it was read back as. To compare the
-- bytes instead would cost a serialization for each comparison. To allow
-- one list only, the constructor would have to be hidden, and every
-- program that builds or updates a transaction would break.
data Tx = Tx
  { -- | transaction data format version
    version :: !Word32,
    -- | list of transaction inputs
    inputs :: ![TxIn],
    -- | list of transaction outputs
    outputs :: ![TxOut],
    -- | witness data for the transaction: one stack per input, or empty
    -- when no input has a witness. A transaction whose stacks are all empty
    -- has no witness: it is serialized without the witness marker, as
    -- Bitcoin Core serializes it, and reads back with an empty list here.
    -- An input that the list leaves out has an empty stack, and a stack
    -- beyond the inputs is not part of the transaction.
    witness :: !WitnessData,
    -- | earliest mining height or time
    locktime :: !Word32
  }
  deriving (Show, Read, Generic, NFData)

instance Eq Tx where
  a == b = txContent a == txContent b

-- | The order of the fields: version, inputs, outputs, witness, lock time.
instance Ord Tx where
  compare a b = compare (txContent a) (txContent b)

instance Hashable Tx where
  hashWithSalt salt = hashWithSalt salt . txContent

-- | What makes a transaction, whatever the way its witness list is
-- written: the fields in their order, with the witness of 'witnessStacks'
txContent :: Tx -> (Word32, [TxIn], [TxOut], WitnessData, Word32)
txContent tx = (tx.version, tx.inputs, tx.outputs, witnessStacks tx, tx.locktime)

-- | The witness as it is written: one stack for each input, or no stack
-- when no input has a witness. Every way to write the witness list of one
-- transaction gives the same stacks.
witnessStacks :: Tx -> WitnessData
witnessStacks tx
  | hasWitness tx = take (length tx.inputs) (tx.witness ++ repeat [])
  | otherwise = []

-- | Compute transaction hash: the transaction id, which leaves the witness
-- out.
txHash :: Tx -> TxHash
txHash tx = TxHash (doubleSHA256 (encodeDirect (putLegacyTx tx)))

-- | The witness transaction id of BIP 141: the hash of the transaction with
-- its witness. It is the same as 'txHash' when the transaction has no
-- witness, as @GetWitnessHash@ gives it in Bitcoin Core.
txWitnessHash :: Tx -> TxHash
txWitnessHash tx = TxHash (doubleSHA256 (encodeDirect (serialize tx)))

-- | The weight of the transaction in weight units, as BIP 141 defines it:
-- three times the size without the witness, plus the size with it. The
-- sizes are counted, and the transaction is not written to get them.
txWeight :: Tx -> Int
txWeight tx = 3 * sizeDirect (putLegacyTx tx) + sizeDirect (serialize tx)

-- | The virtual size of the transaction in virtual bytes, as BIP 141
-- defines it: the weight divided by four, rounded up. Fees are charged by
-- virtual byte.
--
-- Bitcoin Core charges a transaction that is dense in signature operations
-- for 5 virtual bytes per operation when that is more than this size
-- (@GetVirtualTransactionSize@ in @policy/policy.cpp@). This function does
-- not count signature operations.
txVirtualSize :: Tx -> Int
txVirtualSize tx = (txWeight tx + 3) `div` 4

-- | Whether any input of the transaction has a witness, as @HasWitness@
-- tells in Bitcoin Core. A transaction whose stacks are all empty has
-- none. Only the stacks of the inputs count: the witness list has one
-- stack per input, and a stack beyond the inputs belongs to no input and
-- is not written.
hasWitness :: Tx -> Bool
hasWitness tx = any (not . null) (take (length tx.inputs) tx.witness)

-- | Read a transaction from bytes that hold the transaction and nothing
-- else, as @DecodeHexTx@ requires in Bitcoin Core. 'deserialize' reads a
-- transaction from the front of a longer input, as a block needs it to,
-- and so it does not notice bytes that follow. Use this function for a
-- transaction that arrives on its own.
--
-- __A transaction with no inputs.__ The bytes are read as Bitcoin Core
-- reads a transaction from a peer, a block or its mempool: a zero after
-- the version is the marker of BIP 144, and not an input count. So this
-- function and 'deserialize' do not read back a transaction with no inputs
-- that has outputs, which 'serialize' writes: with one output the answer
-- is 'Left', or in rare cases another transaction, and with more a 'Left'.
-- Such a transaction is not valid, but a program may hand one to a funder,
-- as with @fundrawtransaction@ of Bitcoin Core. Read it with
-- 'decodeLegacyTx'. This function does not try both formats, as the
-- decoding tools of Bitcoin Core do: some bytes are a whole transaction in
-- both, and the choice between the two would then be a guess. When bytes
-- with that zero are not a transaction, the error says that they were
-- read in the extended format.
--
-- On a network without SegWit, read a transaction of a peer with
-- 'Haskoin.Network.Data.getNetworkTx': Bitcoin Cash Node has the old
-- format only.
decodeTx :: ByteString -> Either String Tx
decodeTx bytes = first extended (wholeTx deserialize bytes)
  where
    extended reason
      | zeroAfterVersion && notRead =
          "Read in the extended format of BIP 144, since the byte after the version is zero \
          \(decodeLegacyTx reads a transaction with no inputs): "
            <> reason
      | otherwise = reason
    zeroAfterVersion = B.take 1 (B.drop 4 bytes) == B.singleton 0x00
    -- Bytes left over after a transaction are another fault
    notRead = isLeft (decodeDirect deserialize bytes :: Either String Tx)

-- | Read a transaction in the old format, without the marker, flags and
-- witness of BIP 144, from bytes that hold the transaction and nothing
-- else. It reads what 'decodeTx' does not: a transaction with no inputs.
-- It does not read a transaction with a witness. Use it where the bytes
-- are known to be in the old format: a transaction that waits for its
-- inputs, the unsigned transaction of a PSBT, a transaction of a network
-- without SegWit. 'parseLegacyTx' is the same reader for the front of a
-- longer input.
decodeLegacyTx :: ByteString -> Either String Tx
decodeLegacyTx bytes = wholeTx parseLegacyTx bytes

-- | Run a reader of a transaction on bytes that must hold the transaction
-- and nothing else. It is inlined with both arguments, as 'decodeDirect'
-- is, so that the reader is compiled for the monad that reads the bytes
-- where they are: write a caller with its bytes, and not point-free, or it
-- runs several times slower.
wholeTx :: (forall m. (MonadGet m) => m Tx) -> ByteString -> Either String Tx
wholeTx reader bytes = decodeDirect whole bytes
  where
    whole :: (MonadGet m) => m Tx
    whole = do
      tx <- reader
      done <- isEmpty
      unless done $ fail "Trailing bytes after transaction"
      return tx
{-# INLINE wholeTx #-}

-- | A transaction from its hex. The hex must hold the transaction and
-- nothing else, as @DecodeHexTx@ requires in Bitcoin Core.
instance IsString Tx where
  fromString =
    fromMaybe e . (eitherToMaybe . decodeTx <=< decodeHex) . cs
    where
      e = error "Could not read transaction from hex string"

instance Serial Tx where
  deserialize = do
    flags <- lookAhead witnessFlags
    case flags of
      Nothing -> parseLegacyTx
      Just 0x00 -> parseLegacyTx
      Just 0x01 -> parseWitnessTx
      Just other -> fail $ "Unknown transaction optional data: flags " ++ show other
  {-# INLINEABLE deserialize #-}
  serialize tx
    | hasWitness tx = putWitnessTx tx
    | otherwise = putLegacyTx tx
  {-# INLINEABLE serialize #-}

instance Binary Tx where
  put = serialize
  get = deserialize

-- | Through cereal a transaction is written and read on a buffer directly,
-- with the functions of "Haskoin.Util.Direct": a node hashes, stores and
-- loads transactions all day, and the builder and the continuations of
-- cereal took several times as long as the bytes themselves. The bytes and
-- the errors are those of the 'Serial' instance.
instance Serialize Tx where
  put tx = putDirect (serialize tx)
  get = getDirect deserialize

putInOut :: (MonadPut m) => Tx -> m ()
putInOut tx = do
  putVarIntList serialize tx.inputs
  putVarIntList serialize tx.outputs
{-# INLINEABLE putInOut #-}

-- | Non-SegWit transaction serializer.
putLegacyTx :: (MonadPut m) => Tx -> m ()
putLegacyTx tx = do
  putWord32le tx.version
  putInOut tx
  putWord32le tx.locktime
{-# INLINEABLE putLegacyTx #-}

-- | Witness transaction serializer. One stack is written per input: an
-- input without a stack gets an empty one, and stacks beyond the inputs
-- are not written.
putWitnessTx :: (MonadPut m) => Tx -> m ()
putWitnessTx tx = do
  putWord32le tx.version
  putWord8 0x00
  putWord8 0x01
  putInOut tx
  putWitnessData $ take n (tx.witness ++ repeat [])
  putWord32le tx.locktime
  where
    n = length tx.inputs
{-# INLINEABLE putWitnessTx #-}

-- | The flags byte of the extended format of BIP 144, when the transaction
-- has one: the byte after an input count of zero, as @UnserializeTransaction@
-- reads it in Bitcoin Core. A transaction whose input count is not zero has
-- no flags. Only the flags 0x01, the witness, and 0x00, which Bitcoin Core
-- reads as a transaction with no inputs and no outputs, are known; any other
-- value fails the parse there with "Unknown transaction optional data".
witnessFlags :: (MonadGet m) => m (Maybe Word8)
witnessFlags = do
  _ <- getWord32le
  marker <- getWord8
  if marker == 0x00
    then Just <$> getWord8
    else return Nothing
{-# INLINEABLE witnessFlags #-}

-- | Non-SegWit transaction deserializer: the old format, without the
-- marker, flags and witness of BIP 144. Use it where the bytes are known
-- to be in that format, as the unsigned transaction of a PSBT is. There a
-- transaction with no inputs reads as such, whereas 'deserialize' reads
-- the byte after an empty input list as the flags of BIP 144, as Bitcoin
-- Core does when it allows a witness. Every count is bounded by
-- 'maxListSize', as @ReadCompactSize@ bounds it in Bitcoin Core.
-- 'decodeLegacyTx' runs it on bytes that hold a transaction and nothing
-- else.
parseLegacyTx :: (MonadGet m) => m Tx
parseLegacyTx = do
  version <- getWord32le
  inputs <- getVarIntList deserialize
  outputs <- getVarIntList deserialize
  locktime <- getWord32le
  return Tx {witness = [], ..}
{-# INLINEABLE parseLegacyTx #-}

-- | Witness transaction deserializer. A transaction with the witness marker
-- must have a witness: one whose stacks are all empty fails, as it does in
-- Bitcoin Core ("Superfluous witness record").
parseWitnessTx :: (MonadGet m) => m Tx
parseWitnessTx = do
  version <- getWord32le
  m <- getWord8
  f <- getWord8
  unless (m == 0x00 && f == 0x01) $ fail "Not a witness transaction"
  inputs <- getVarIntList deserialize
  outputs <- getVarIntList deserialize
  witness <- parseWitnessData $ length inputs
  unless (any (not . null) witness) $
    fail "Superfluous witness record"
  locktime <- getWord32le
  return Tx {..}
{-# INLINEABLE parseWitnessTx #-}

-- | Witness data deserializer. Requires count of inputs.
parseWitnessData :: (MonadGet m) => Int -> m WitnessData
parseWitnessData n = replicateM n (getVarIntList getVarIntBytes)
{-# INLINEABLE parseWitnessData #-}

-- | Witness data serializer.
putWitnessData :: (MonadPut m) => WitnessData -> m ()
putWitnessData = mapM_ (putVarIntList putVarIntBytes)
{-# INLINEABLE putWitnessData #-}

-- | The witness of the JSON form has one stack per input, or none at all:
-- a stack without an input would not be part of the transaction.
instance FromJSON Tx where
  parseJSON = withObject "Tx" $ \o -> do
    version <- o .: "version"
    inputs <- o .: "inputs"
    outputs <- o .: "outputs"
    witness <- mapM (mapM f) =<< o .: "witnessdata"
    locktime <- o .: "locktime"
    unless (null witness || length witness == length inputs) $
      fail "The witness data must have one stack per input, or none"
    return Tx {..}
    where
      f = maybe mzero return . decodeHex

-- | The witness is written as the bytes have it: one stack per input, or
-- none when no input has a witness. So 'FromJSON' reads back what this
-- writes, for any witness list.
instance ToJSON Tx where
  toJSON tx =
    object
      [ "version" .= tx.version,
        "inputs" .= tx.inputs,
        "outputs" .= tx.outputs,
        "witnessdata" .= fmap (fmap encodeHex) (witnessStacks tx),
        "locktime" .= tx.locktime
      ]
  toEncoding tx =
    pairs $
      mconcat
        [ "version" `E.pair` E.word32 tx.version,
          "inputs" `E.pair` E.list toEncoding tx.inputs,
          "outputs" `E.pair` E.list toEncoding tx.outputs,
          "witnessdata" `E.pair` E.list (E.list f) (witnessStacks tx),
          "locktime" `E.pair` E.word32 tx.locktime
        ]
    where
      f = hexEncoding . BL.fromStrict

-- | Data type representing a transaction input.
data TxIn = TxIn
  { -- | output being spent
    outpoint :: !OutPoint,
    -- | signatures and redeem script
    script :: !ByteString,
    -- | lock-time using sequence numbers (BIP-68)
    sequence :: !Word32
  }
  deriving (Eq, Show, Read, Ord, Generic, Hashable, NFData)

instance Serial TxIn where
  deserialize =
    TxIn <$> deserialize <*> getVarIntBytes <*> getWord32le
  {-# INLINEABLE deserialize #-}

  serialize (TxIn o s q) = do
    serialize o
    putVarIntBytes s
    putWord32le q
  {-# INLINEABLE serialize #-}

instance Binary TxIn where
  get = deserialize
  put = serialize

instance Serialize TxIn where
  get = getDirect deserialize
  put x = putDirect (serialize x)

instance FromJSON TxIn where
  parseJSON =
    withObject "TxIn" $ \o ->
      TxIn
        <$> o .: "prevoutput"
        <*> (maybe mzero return . decodeHex =<< o .: "inputscript")
        <*> o .: "sequence"

instance ToJSON TxIn where
  toJSON (TxIn o s q) =
    object
      [ "prevoutput" .= o,
        "inputscript" .= encodeHex s,
        "sequence" .= q
      ]
  toEncoding (TxIn o s q) =
    pairs $
      mconcat
        [ "prevoutput" `E.pair` toEncoding o,
          "inputscript" `E.pair` hexEncoding (BL.fromStrict s),
          "sequence" `E.pair` E.word32 q
        ]

-- | Data type representing a transaction output.
data TxOut = TxOut
  { -- | value of output is satoshi
    value :: !Word64,
    -- | pubkey script
    script :: !ByteString
  }
  deriving (Eq, Show, Read, Ord, Generic, Hashable, NFData)

instance Serial TxOut where
  deserialize = TxOut <$> getWord64le <*> getVarIntBytes
  {-# INLINEABLE deserialize #-}

  serialize (TxOut o s) = do
    putWord64le o
    putVarIntBytes s
  {-# INLINEABLE serialize #-}

instance Binary TxOut where
  put = serialize
  get = deserialize

-- | Read on a buffer directly, like a transaction. Written through the
-- builder of cereal: for a value of two or three fields that costs less than
-- a buffer of its own, which 'putDirect' would allocate and then copy.
instance Serialize TxOut where
  put = serialize
  get = getDirect deserialize

instance FromJSON TxOut where
  parseJSON =
    withObject "TxOut" $ \o -> do
      value <- o .: "value"
      t <- o .: "outputscript"
      script <- maybe mzero return (decodeHex t)
      return TxOut {..}

instance ToJSON TxOut where
  toJSON (TxOut o s) =
    object ["value" .= o, "outputscript" .= encodeHex s]
  toEncoding (TxOut o s) =
    pairs $
      mconcat
        [ "value" `E.pair` E.word64 o,
          "outputscript" `E.pair` hexEncoding (BL.fromStrict s)
        ]

-- | The 'OutPoint' refers to a transaction output being spent.
data OutPoint = OutPoint
  { -- | hash of previous transaction
    hash :: !TxHash,
    -- | position of output in previous transaction
    index :: !Word32
  }
  deriving (Show, Read, Eq, Ord, Generic, Hashable, NFData)

instance Serial OutPoint where
  deserialize = do
    (h, i) <- liftM2 (,) deserialize getWord32le
    return $ OutPoint h i
  {-# INLINEABLE deserialize #-}
  serialize (OutPoint h i) = serialize h >> putWord32le i
  {-# INLINEABLE serialize #-}

instance Binary OutPoint where
  put = serialize
  get = deserialize

-- | Read on a buffer directly, and written through the builder of cereal,
-- like a 'TxOut'.
instance Serialize OutPoint where
  put = serialize
  get = getDirect deserialize

instance FromJSON OutPoint where
  parseJSON =
    withObject "OutPoint" $ \o ->
      OutPoint <$> o .: "txid" <*> o .: "index"

instance ToJSON OutPoint where
  toJSON (OutPoint h i) = object ["txid" .= h, "index" .= i]
  toEncoding (OutPoint h i) =
    pairs $
      mconcat
        [ "txid" `E.pair` toEncoding h,
          "index" `E.pair` E.word32 i
        ]

-- | Outpoint used in coinbase transactions.
nullOutPoint :: OutPoint
nullOutPoint =
  OutPoint
    { hash = "0000000000000000000000000000000000000000000000000000000000000000",
      index = maxBound
    }
