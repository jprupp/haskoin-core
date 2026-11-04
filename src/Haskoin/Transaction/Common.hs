{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
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
    nullOutPoint,
  )
where

import Control.Applicative ((<|>))
import Control.DeepSeq
import Control.Monad (forM_, guard, liftM2, mzero, replicateM, unless, when, (<=<))
import Data.Aeson as A
import Data.Aeson.Encoding qualified as E
import Data.Binary (Binary (..))
import Data.Bool (bool)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Builder (char7)
import Data.ByteString.Lazy qualified as BL
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Hashable (Hashable)
import Data.Maybe (fromMaybe)
import Data.Serialize (Serialize (..))
import Data.String (IsString, fromString)
import Data.String.Conversions (cs)
import Data.Text (Text)
import Data.Word (Word32, Word64)
import GHC.Generics (Generic)
import Haskoin.Crypto.Hash
import Haskoin.Network.Common
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
  deserialize = TxHash <$> deserialize

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
  toEncoding = hexEncoding . BL.reverse . runPutL . serialize

-- | Hash of the transaction with every input script and the whole witness
-- removed, so that it is the same before and after signing, whether the
-- signatures go in the input scripts or in the witness.
nosigTxHash :: Tx -> TxHash
nosigTxHash Tx {..} =
  TxHash . doubleSHA256 . runPutS $ serialize tx
  where
    tx = Tx {inputs = map clr inputs, witness = [], ..}
    clr TxIn {..} = TxIn {script = B.empty, ..}

-- | Convert transaction hash to hex form, reversing bytes.
txHashToHex :: TxHash -> Text
txHashToHex (TxHash h) =
  encodeHex . B.reverse . runPutS $ serialize h

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
    witness :: !WitnessData,
    -- | earliest mining height or time
    locktime :: !Word32
  }
  deriving (Show, Read, Eq, Ord, Generic, Hashable, NFData)

-- | Compute transaction hash: the transaction id, which leaves the witness
-- out.
txHash :: Tx -> TxHash
txHash tx = TxHash . doubleSHA256 . runPutS $ serialize tx {witness = []}

-- | The witness transaction id of BIP 141: the hash of the transaction with
-- its witness. It is the same as 'txHash' when the transaction has no
-- witness, as @GetWitnessHash@ gives it in Bitcoin Core.
txWitnessHash :: Tx -> TxHash
txWitnessHash = TxHash . doubleSHA256 . runPutS . serialize

-- | The weight of the transaction in weight units, as BIP 141 defines it:
-- three times the size without the witness, plus the size with it.
txWeight :: Tx -> Int
txWeight tx =
  3 * B.length (runPutS (serialize tx {witness = []})) + B.length (runPutS (serialize tx))

-- | The virtual size of the transaction in virtual bytes, as BIP 141
-- defines it: the weight divided by four, rounded up. Fees are charged by
-- virtual byte.
txVirtualSize :: Tx -> Int
txVirtualSize tx = (txWeight tx + 3) `div` 4

-- | Whether any input of the transaction has a witness, as @HasWitness@
-- tells in Bitcoin Core. A transaction whose stacks are all empty has
-- none.
hasWitness :: Tx -> Bool
hasWitness = any (not . null) . (.witness)

instance IsString Tx where
  fromString =
    fromMaybe e . (eitherToMaybe . runGetS deserialize <=< decodeHex) . cs
    where
      e = error "Could not read transaction from hex string"

instance Serial Tx where
  deserialize = isWitnessTx >>= bool parseLegacyTx parseWitnessTx
  serialize tx
    | hasWitness tx = putWitnessTx tx
    | otherwise = putLegacyTx tx

instance Binary Tx where
  put = serialize
  get = deserialize

instance Serialize Tx where
  put = serialize
  get = deserialize

putInOut :: (MonadPut m) => Tx -> m ()
putInOut tx = do
  putVarIntList serialize tx.inputs
  putVarIntList serialize tx.outputs

-- | Non-SegWit transaction serializer.
putLegacyTx :: (MonadPut m) => Tx -> m ()
putLegacyTx tx = do
  putWord32le tx.version
  putInOut tx
  putWord32le tx.locktime

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

isWitnessTx :: (MonadGet m) => m Bool
isWitnessTx = lookAhead $ do
  _ <- getWord32le
  m <- getWord8
  f <- getWord8
  return (m == 0x00 && f == 0x01)

-- | Non-SegWit transaction deserializer. Every count is bounded by
-- 'maxListSize', as @ReadCompactSize@ bounds it in Bitcoin Core.
parseLegacyTx :: (MonadGet m) => m Tx
parseLegacyTx = do
  version <- getWord32le
  inputs <- getVarIntList deserialize
  outputs <- getVarIntList deserialize
  when (null inputs && length outputs == 0x01) $
    fail "Witness transaction"
  locktime <- getWord32le
  return Tx {witness = [], ..}

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

-- | Witness data deserializer. Requires count of inputs.
parseWitnessData :: (MonadGet m) => Int -> m WitnessData
parseWitnessData n = replicateM n (getVarIntList getVarIntBytes)

-- | Witness data serializer.
putWitnessData :: (MonadPut m) => WitnessData -> m ()
putWitnessData = mapM_ (putVarIntList putVarIntBytes)

instance FromJSON Tx where
  parseJSON = withObject "Tx" $ \o ->
    Tx
      <$> o .: "version"
      <*> o .: "inputs"
      <*> o .: "outputs"
      <*> (mapM (mapM f) =<< o .: "witnessdata")
      <*> o .: "locktime"
    where
      f = maybe mzero return . decodeHex

instance ToJSON Tx where
  toJSON (Tx v i o w l) =
    object
      [ "version" .= v,
        "inputs" .= i,
        "outputs" .= o,
        "witnessdata" .= fmap (fmap encodeHex) w,
        "locktime" .= l
      ]
  toEncoding (Tx v i o w l) =
    pairs $
      mconcat
        [ "version" `E.pair` E.word32 v,
          "inputs" `E.pair` E.list toEncoding i,
          "outputs" `E.pair` E.list toEncoding o,
          "witnessdata" `E.pair` E.list (E.list f) w,
          "locktime" `E.pair` E.word32 l
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

  serialize (TxIn o s q) = do
    serialize o
    putVarIntBytes s
    putWord32le q

instance Binary TxIn where
  get = deserialize
  put = serialize

instance Serialize TxIn where
  get = deserialize
  put = serialize

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

  serialize (TxOut o s) = do
    putWord64le o
    putVarIntBytes s

instance Binary TxOut where
  put = serialize
  get = deserialize

instance Serialize TxOut where
  put = serialize
  get = deserialize

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
  serialize (OutPoint h i) = serialize h >> putWord32le i

instance Binary OutPoint where
  put = serialize
  get = deserialize

instance Serialize OutPoint where
  put = serialize
  get = deserialize

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
