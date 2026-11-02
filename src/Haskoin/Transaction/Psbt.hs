{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Transaction.Psbt
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Partially signed Bitcoin transactions, the format of
-- [BIP 174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki),
-- in its version 0 and in version 2, the version of
-- [BIP 370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki).
--
-- A PSBT is five magic bytes, then maps of keys and values: one global map,
-- then one map per input and one per output of the transaction. A key is a
-- type and some data. The spec gives the keys and values of the fields it
-- defines, and leaves the type 0xFC to proprietary fields, under an
-- identifier of the software that writes them.
--
-- In version 0, the global map holds the unsigned transaction. In version
-- 2, the maps hold the transaction field by field: its version and a
-- fallback lock time in the global map, the output each input spends and
-- its sequence in the map of the input, the amount and script of each
-- output in its map, so that inputs and outputs can be added. The lock
-- time is the one the inputs require, or the fallback. Here a PSBT of
-- either version has its unsigned transaction, 'unsignedTx': the one of
-- the global map, or the one the fields describe.
--
-- The maps are kept as they are read, byte for byte, so that every field
-- passes through, known or not. A map is written with its keys in order, as
-- Bitcoin Core writes it. A PSBT that breaks the spec is refused when it is
-- read: a key out of shape, a key twice in a map, a value that does not
-- decode, a field of the other version, a field version 2 requires
-- missing, bytes after the last map.
--
-- The fields the spec defines are read and written with the functions
-- below. The roles of the spec are here too: a creator ('psbtOf'), a
-- constructor ('addInput', 'addOutput'), a combiner ('combinePsbt'), a
-- signer ('signPsbt'), a finalizer ('finalizePsbt') and a transaction
-- extractor ('psbtTransaction'). An updater is the functions that insert
-- fields, and 'setInputSequence'.
module Haskoin.Transaction.Psbt
  ( -- * A PSBT
    Psbt (..),
    PsbtVersion (..),
    Key (..),
    PsbtMap,
    psbtOf,
    psbtOfMaps,
    withVersion,
    psbtId,
    combinePsbt,
    psbtTransaction,

    -- * The inputs and outputs of version 2
    addInput,
    addOutput,
    setInputSequence,
    Modifiable (..),
    txModifiable,
    insertTxModifiable,
    deleteTxModifiable,
    fallbackLockTime,
    requiredTimeLockTime,
    insertRequiredTimeLockTime,
    requiredHeightLockTime,
    insertRequiredHeightLockTime,

    -- * Bytes and text
    psbtMagic,
    isPsbt,
    encodePsbt,
    decodePsbt,
    encodePsbtBase64,
    decodePsbtBase64,

    -- * The global fields
    Derivation (..),
    xpubRecords,
    insertXpubRecord,

    -- * The fields of an input
    nonWitnessUtxo,
    insertNonWitnessUtxo,
    witnessUtxo,
    insertWitnessUtxo,
    partialSignatures,
    hasPartialSignatures,
    insertPartialSignature,
    deletePartialSignatures,
    sigHashType,
    insertSigHashType,
    deleteSigHashType,
    inputRedeemScript,
    insertInputRedeemScript,
    inputWitnessScript,
    insertInputWitnessScript,
    inputDerivations,
    insertInputDerivation,
    finalScriptSig,
    insertFinalScriptSig,
    finalScriptWitness,
    insertFinalScriptWitness,

    -- * The fields of an output
    outputRedeemScript,
    insertOutputRedeemScript,
    outputWitnessScript,
    insertOutputWitnessScript,
    outputDerivations,
    insertOutputDerivation,

    -- * Proprietary fields
    Proprietary (..),
    proprietaryKey,
    proprietaryOf,
    lookupProprietary,
    insertProprietary,

    -- * Signing
    Signer,
    keySigner,
    xPrvSigner,
    signPsbt,
    afterSignature,

    -- * Finalizing
    finalizePsbt,
  )
where

import Control.Applicative ((<|>))
import Control.DeepSeq (NFData)
import Control.Monad (ap, forM, forM_, guard, replicateM, unless, when, zipWithM)
import Crypto.Secp256k1 (Ctx, SecKey, derivePubKey)
import Data.Bifunctor (first)
import Data.Bits (shiftL, testBit, (.&.), (.|.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Base64.Types (extractBase64)
import Data.ByteString.Base64 (decodeBase64Untyped, encodeBase64')
import Data.Char (toUpper)
import Data.List (stripPrefix)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Maybe (catMaybes, fromMaybe, isJust, listToMaybe, mapMaybe)
import Data.Serialize qualified as S
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Crypto.Hash (addressHash)
import Haskoin.Crypto.Keys.Common
import Haskoin.Crypto.Keys.Extended
import Haskoin.Network.Common (VarInt (..))
import Haskoin.Network.Data
import Haskoin.Script.Common
import Haskoin.Script.SigHash
import Haskoin.Script.Standard
import Haskoin.Transaction.Builder.Sign (SigInput (..), makeSignature)
import Haskoin.Transaction.Common
import Haskoin.Transaction.Segwit (isSegwit)
import Haskoin.Util
import Numeric (showHex)

{- A PSBT -}

-- | A key of a map: its type, and the data after the type byte. Most
-- fields have none; a derivation or a signature has the public key it is
-- of.
data Key = Key
  { keyType :: !Word8,
    keyData :: !ByteString
  }
  deriving (Eq, Ord, Show, Read, Generic)
  deriving anyclass (NFData)

-- | A map of a PSBT. It is written with its keys in order, the type first,
-- as Bitcoin Core writes it.
type PsbtMap = Map Key ByteString

-- | The version of a PSBT: 0, the version of BIP 174, whose global map
-- holds the unsigned transaction, or 2, the version of BIP 370, whose maps
-- hold the transaction field by field, so that inputs and outputs can be
-- added. There is no version 1.
data PsbtVersion = Version0 | Version2
  deriving (Eq, Ord, Show, Read, Generic)
  deriving anyclass (NFData)

versionNumber :: PsbtVersion -> Word32
versionNumber Version0 = 0
versionNumber Version2 = 2

-- | A PSBT: its version, the unsigned transaction, the global map, and the
-- maps of the inputs and of the outputs, one each, in the order of the
-- transaction. In version 0, the global map is kept without the unsigned
-- transaction. In version 2, the maps keep the fields that describe the
-- transaction, and the unsigned transaction is the one they describe, with
-- the lock time they determine.
data Psbt = Psbt
  { version :: !PsbtVersion,
    unsignedTx :: !Tx,
    globals :: !PsbtMap,
    inputs :: ![PsbtMap],
    outputs :: ![PsbtMap]
  }
  deriving (Eq, Show, Read, Generic)
  deriving anyclass (NFData)

-- | The PSBT of a transaction, with nothing else, as the creator of the
-- spec makes it, in version 0: the transaction without its input scripts
-- and witness, and an empty map per input and per output. 'withVersion'
-- makes it one of version 2.
psbtOf :: Tx -> Psbt
psbtOf tx =
  Psbt
    { version = Version0,
      unsignedTx = Tx tx.version [TxIn input.outpoint B.empty input.sequence | input <- tx.inputs] tx.outputs [] tx.locktime,
      globals = Map.empty,
      inputs = Map.empty <$ tx.inputs,
      outputs = Map.empty <$ tx.outputs
    }

-- | The PSBT whose maps these are, as they are in its bytes: the global
-- map names the version, and holds the unsigned transaction in version 0.
-- The maps are checked against the spec of the version, and in version 2
-- the transaction is read from their fields.
psbtOfMaps :: PsbtMap -> [PsbtMap] -> [PsbtMap] -> Either String Psbt
psbtOfMaps globals inputs outputs = do
  (version, inputCount, outputCount) <- countsOf globals
  unless (length inputs == inputCount) $
    Left ("The PSBT has " <> show (length inputs) <> " inputs, and its global map counts " <> show inputCount)
  unless (length outputs == outputCount) $
    Left ("The PSBT has " <> show (length outputs) <> " outputs, and its global map counts " <> show outputCount)
  forM_ (zip [0 :: Int ..] inputs) $ \(i, m) -> checkMap ("input " <> show i) version inputFields m
  forM_ (zip [0 :: Int ..] outputs) $ \(i, m) -> checkMap ("output " <> show i) version outputFields m
  tx <- case version of
    Version0 -> unsignedTxOf globals
    Version2 -> transactionOf globals inputs outputs
  return $ Psbt version tx (Map.delete unsignedTxKey globals) inputs outputs

-- | The PSBT in the version given, as BIP 370 converts one. To version 2:
-- the transaction goes in the fields of the maps, its lock time as the
-- fallback. To version 0: the fields of version 2 leave the maps, and the
-- transaction keeps the lock time they determined.
withVersion :: PsbtVersion -> Psbt -> Psbt
withVersion v psbt
  | v == psbt.version = psbt
  | v == Version2 =
      Psbt
        Version2
        tx
        (withTxFields tx (insertPlainField versionType (word32le 2) psbt.globals))
        (zipWith withInputFields tx.inputs psbt.inputs)
        (zipWith withOutputFields tx.outputs psbt.outputs)
  | otherwise =
      Psbt
        Version0
        tx
        (without globalV2Types (deletePlainField versionType psbt.globals))
        (without inputV2Types <$> psbt.inputs)
        (without outputV2Types <$> psbt.outputs)
  where
    tx = psbt.unsignedTx
    without :: [Word8] -> PsbtMap -> PsbtMap
    without types = Map.filterWithKey (\key _ -> key.keyType `notElem` types)

-- | What identifies a PSBT: the id of its unsigned transaction. In version
-- 2 the sequence of every input is taken as 0 for it, as BIP 370 says,
-- since an updater may change the sequences.
psbtId :: Psbt -> TxHash
psbtId psbt = txHash $ case psbt.version of
  Version0 -> tx
  Version2 -> Tx tx.version [TxIn input.outpoint input.script 0 | input <- tx.inputs] tx.outputs tx.witness tx.locktime
  where
    tx = psbt.unsignedTx

-- | The PSBT with the fields of both, as the combiner of the spec makes
-- it. Both must be of the same version and of the same transaction. A
-- field both have, with different values, keeps the value of the first.
-- The flags of version 2 are combined as Bitcoin Core combines them:
-- inputs and outputs stay modifiable only when both say so, and a
-- SIGHASH_SINGLE signature of either is kept.
combinePsbt :: Psbt -> Psbt -> Either String Psbt
combinePsbt a b = do
  unless (a.version == b.version) $ Left "The PSBTs are not of the same version"
  unless (psbtId a == psbtId b) $ Left "The PSBTs are not of the same transaction"
  let globals = combinedFlags (Map.union a.globals b.globals)
      inputs = zipWith Map.union a.inputs b.inputs
      outputs = zipWith Map.union a.outputs b.outputs
  case a.version of
    Version0 -> return $ Psbt Version0 a.unsignedTx globals inputs outputs
    Version2 -> (\tx -> Psbt Version2 tx globals inputs outputs) <$> transactionOf globals inputs outputs
  where
    combinedFlags globals = case (flagsOf a, flagsOf b) of
      (Nothing, Nothing) -> globals
      (x, y) ->
        let fx = fromMaybe noFlags x
            fy = fromMaybe noFlags y
         in insertTxModifiable
              (Modifiable (fx.inputsModifiable && fy.inputsModifiable) (fx.outputsModifiable && fy.outputsModifiable) (fx.hasSigHashSingle || fy.hasSigHashSingle) (fx.undefinedBits .&. fy.undefinedBits))
              globals
    flagsOf :: Psbt -> Maybe Modifiable
    flagsOf psbt = either (const Nothing) id (txModifiable psbt.globals)

-- | The transaction of a PSBT with the final script and witness of every
-- input that has them, as the transaction extractor of the spec builds
-- it. An input without them stays unsigned.
psbtTransaction :: Psbt -> Either String Tx
psbtTransaction psbt = do
  finals <- forM (zip psbt.unsignedTx.inputs psbt.inputs) $ \(input, m) -> do
    stack <- fromMaybe [] <$> finalScriptWitness m
    let scriptSig = fromMaybe B.empty (finalScriptSig m)
    return (TxIn input.outpoint scriptSig input.sequence, stack)
  let stacks = snd <$> finals
      witness = if all null stacks then [] else stacks
  return $ Tx psbt.unsignedTx.version (fst <$> finals) psbt.unsignedTx.outputs witness psbt.unsignedTx.locktime

{- The inputs and outputs of version 2 -}

-- | The PSBT with an input added at the end, as the constructor of BIP 370
-- adds one: the output it spends and its sequence from the input given,
-- and the fields of the map given, such as the lock time it requires. A
-- PSBT of version 0 takes none, nor one whose inputs are not modifiable.
-- A lock time the input requires must fit the other inputs, and must not
-- change the lock time of the transaction once an input is signed. Added
-- at the end, the input leaves every SIGHASH_SINGLE signature paired with
-- its output.
addInput :: TxIn -> PsbtMap -> Psbt -> Either String Psbt
addInput input m psbt = do
  flags <- modifiableOf psbt
  unless flags.inputsModifiable $ Left "The inputs of the PSBT may not be modified"
  when (any ((== input.outpoint) . (.outpoint)) psbt.unsignedTx.inputs) $
    Left "An input of the PSBT spends that output already"
  let inputs = psbt.inputs <> [withInputFields input m]
      globals = withCounts (length inputs) (length psbt.outputs) psbt.globals
  tx <- transactionOf globals inputs psbt.outputs
  when (any hasSignatures psbt.inputs && tx.locktime /= psbt.unsignedTx.locktime) $
    Left "An input is signed already: the lock time may not change"
  return $ Psbt Version2 tx globals inputs psbt.outputs

-- | The PSBT with an output added at the end, as the constructor of BIP
-- 370 adds one: its amount and script from the output given, and the
-- fields of the map given. A PSBT of version 0 takes none, nor one whose
-- outputs are not modifiable.
addOutput :: TxOut -> PsbtMap -> Psbt -> Either String Psbt
addOutput output m psbt = do
  flags <- modifiableOf psbt
  unless flags.outputsModifiable $ Left "The outputs of the PSBT may not be modified"
  let outputs = psbt.outputs <> [withOutputFields output m]
      globals = withCounts (length psbt.inputs) (length outputs) psbt.globals
  tx <- transactionOf globals psbt.inputs outputs
  return $ Psbt Version2 tx globals psbt.inputs outputs

-- | The flags of a PSBT of version 2, none set when it has no field of
-- them. A PSBT of version 0 takes no input or output.
modifiableOf :: Psbt -> Either String Modifiable
modifiableOf psbt = do
  unless (psbt.version == Version2) $ Left "A PSBT of version 0 takes no input or output: its transaction is fixed"
  fromMaybe noFlags <$> txModifiable psbt.globals

-- | Whether an input has a signature: one that is not final, or its final
-- script or witness
hasSignatures :: PsbtMap -> Bool
hasSignatures m = hasPartialSignatures m || isFinal m

-- | The PSBT with the sequence of the input at the index set, as an
-- updater of BIP 370 may set one. The sequences of a PSBT of version 0
-- are in its unsigned transaction, which is fixed.
setInputSequence :: Int -> Word32 -> Psbt -> Either String Psbt
setInputSequence i sequence' psbt = do
  unless (psbt.version == Version2) $ Left "The sequences of a PSBT of version 0 are in its unsigned transaction, which is fixed"
  unless (i >= 0 && i < length psbt.inputs) $ Left ("The PSBT has no input " <> show i)
  let inputs = [if j == i then insertPlainField sequenceType (word32le sequence') m else m | (j, m) <- zip [0 ..] psbt.inputs]
  tx <- transactionOf psbt.globals inputs psbt.outputs
  return $ Psbt Version2 tx psbt.globals inputs psbt.outputs

-- | The global map with the fields of version 2 that describe the
-- transaction: its version, its lock time as the fallback, and the number
-- of its inputs and outputs
withTxFields :: Tx -> PsbtMap -> PsbtMap
withTxFields tx =
  insertPlainField txVersionType (word32le tx.version)
    . insertPlainField fallbackLockTimeType (word32le tx.locktime)
    . withCounts (length tx.inputs) (length tx.outputs)

withCounts :: Int -> Int -> PsbtMap -> PsbtMap
withCounts inputCount outputCount =
  insertPlainField inputCountType (compactSize (fromIntegral inputCount))
    . insertPlainField outputCountType (compactSize (fromIntegral outputCount))

-- | The map of an input with the fields of version 2 that describe it: the
-- id of the transaction it spends from, the index of the output, and its
-- sequence
withInputFields :: TxIn -> PsbtMap -> PsbtMap
withInputFields input =
  insertPlainField prevTxidType (S.encode input.outpoint.hash)
    . insertPlainField outputIndexType (word32le input.outpoint.index)
    . insertPlainField sequenceType (word32le input.sequence)

-- | The map of an output with the fields of version 2 that describe it:
-- its amount and its script
withOutputFields :: TxOut -> PsbtMap -> PsbtMap
withOutputFields output =
  insertPlainField amountType (word64le output.value)
    . insertPlainField outScriptType output.script

{- The types of the spec -}

unsignedTxType, xpubType, txVersionType, fallbackLockTimeType, inputCountType, outputCountType, txModifiableType, versionType :: Word8
unsignedTxType = 0x00
xpubType = 0x01
txVersionType = 0x02
fallbackLockTimeType = 0x03
inputCountType = 0x04
outputCountType = 0x05
txModifiableType = 0x06
versionType = 0xfb

nonWitnessUtxoType, witnessUtxoType, partialSigType, sigHashTypeType, inRedeemScriptType, inWitnessScriptType, inDerivationType, finalScriptSigType, finalScriptWitnessType :: Word8
nonWitnessUtxoType = 0x00
witnessUtxoType = 0x01
partialSigType = 0x02
sigHashTypeType = 0x03
inRedeemScriptType = 0x04
inWitnessScriptType = 0x05
inDerivationType = 0x06
finalScriptSigType = 0x07
finalScriptWitnessType = 0x08

prevTxidType, outputIndexType, sequenceType, requiredTimeType, requiredHeightType :: Word8
prevTxidType = 0x0e
outputIndexType = 0x0f
sequenceType = 0x10
requiredTimeType = 0x11
requiredHeightType = 0x12

outRedeemScriptType, outWitnessScriptType, outDerivationType, amountType, outScriptType :: Word8
outRedeemScriptType = 0x00
outWitnessScriptType = 0x01
outDerivationType = 0x02
amountType = 0x03
outScriptType = 0x04

-- | The types of the fields of version 2, which version 0 excludes, by
-- map
globalV2Types, inputV2Types, outputV2Types :: [Word8]
globalV2Types = [txVersionType, fallbackLockTimeType, inputCountType, outputCountType, txModifiableType]
inputV2Types = [prevTxidType, outputIndexType, sequenceType, requiredTimeType, requiredHeightType]
outputV2Types = [amountType, outScriptType]

-- | The lock times from this value are times, below it heights
lockTimeThreshold :: Word32
lockTimeThreshold = 500000000

proprietaryType :: Word8
proprietaryType = 0xfc

-- | The key of the unsigned transaction in the global map
unsignedTxKey :: Key
unsignedTxKey = Key unsignedTxType B.empty

{- Bytes -}

-- | The five bytes every PSBT starts with: "psbt" and 0xff
psbtMagic :: ByteString
psbtMagic = B.pack [0x70, 0x73, 0x62, 0x74, 0xff]

-- | Whether the bytes are those of a PSBT, by their first five
isPsbt :: ByteString -> Bool
isPsbt = B.isPrefixOf psbtMagic

-- | The bytes of a PSBT: the magic, the global map, with the unsigned
-- transaction in version 0, then the maps of the inputs and of the outputs
encodePsbt :: Psbt -> ByteString
encodePsbt psbt =
  B.concat $ psbtMagic : encodeMap globals : (encodeMap <$> psbt.inputs) <> (encodeMap <$> psbt.outputs)
  where
    globals = case psbt.version of
      Version0 -> Map.insert unsignedTxKey (S.encode psbt.unsignedTx) psbt.globals
      Version2 -> psbt.globals

-- | A map: each key and value after its length, the keys in order, then a
-- zero byte
encodeMap :: PsbtMap -> ByteString
encodeMap m =
  B.concat [sized (B.cons key.keyType key.keyData) <> sized value | (key, value) <- Map.toAscList m]
    <> B.singleton 0

-- | Bytes after their length, as a compact size integer
sized :: ByteString -> ByteString
sized bytes = compactSize (fromIntegral (B.length bytes)) <> bytes

-- | A compact size integer, in its shortest form
compactSize :: Word64 -> ByteString
compactSize = S.encode . VarInt

-- | A 32-bit integer, little-endian
word32le :: Word32 -> ByteString
word32le = S.runPut . S.putWord32le

-- | A 64-bit integer, little-endian
word64le :: Word64 -> ByteString
word64le = S.runPut . S.putWord64le

-- | The PSBT the bytes hold, or why they hold none: not a PSBT, or one that
-- breaks the spec
decodePsbt :: ByteString -> Either String Psbt
decodePsbt = parseAll psbtParser "the last map"

-- | The text of a PSBT, in base64, as the spec gives it for text
encodePsbtBase64 :: Psbt -> ByteString
encodePsbtBase64 = extractBase64 . encodeBase64' . encodePsbt

-- | The PSBT of a base64 text, around which spaces and line breaks are
-- left aside
decodePsbtBase64 :: ByteString -> Either String Psbt
decodePsbtBase64 text = do
  bytes <- first (const "Not the base64 text of a PSBT") $ decodeBase64Untyped (B.filter (`notElem` spaces) text)
  decodePsbt bytes
  where
    spaces = [0x20, 0x09, 0x0a, 0x0d]

{- Reading bytes -}

-- | A reader of bytes, which stops at the first byte out of place with a
-- sentence saying so
newtype BytesParser a = BytesParser (ByteString -> Either String (a, ByteString))

instance Functor BytesParser where
  fmap f (BytesParser p) = BytesParser $ \bytes -> do
    (a, rest) <- p bytes
    return (f a, rest)

instance Applicative BytesParser where
  pure a = BytesParser $ \bytes -> Right (a, bytes)
  (<*>) = ap

instance Monad BytesParser where
  BytesParser p >>= f = BytesParser $ \bytes -> do
    (a, rest) <- p bytes
    let BytesParser q = f a
    q rest

refuse :: String -> BytesParser a
refuse reason = BytesParser $ \_ -> Left reason

-- | Read all the bytes with the parser: nothing may follow what it reads
parseAll :: BytesParser a -> String -> ByteString -> Either String a
parseAll (BytesParser p) what bytes = do
  (a, rest) <- p bytes
  unless (B.null rest) $ Left ("Bytes follow " <> what)
  return a

-- | The next bytes, which must be there. What they are part of names
-- them in the refusal.
bytesOf :: Int -> String -> BytesParser ByteString
bytesOf n what = BytesParser $ \bytes ->
  if B.length bytes < n
    then Left ("The PSBT ends inside " <> what)
    else Right (B.splitAt n bytes)

-- | All the bytes left
restOf :: BytesParser ByteString
restOf = BytesParser $ \bytes -> Right (bytes, B.empty)

-- | A compact size integer: one byte below 0xfd, or 0xfd, 0xfe or 0xff and
-- two, four or eight bytes, little-endian, in the shortest form, as
-- Bitcoin Core reads it
compactSizeOf :: String -> BytesParser Word64
compactSizeOf what = do
  first' <- B.head <$> bytesOf 1 what
  case first' of
    0xfd -> longer 2 0xfd
    0xfe -> longer 4 0x10000
    0xff -> longer 8 0x100000000
    _ -> return (fromIntegral first')
  where
    longer :: Int -> Word64 -> BytesParser Word64
    longer n least = do
      value <- B.foldr (\b acc -> acc `shiftL` 8 .|. fromIntegral b) 0 <$> bytesOf n what
      when (value < least) $ refuse ("A length in " <> what <> " is not in its shortest form")
      return value

-- | A length, which must fit in memory
lengthOf :: String -> BytesParser Int
lengthOf what = do
  n <- compactSizeOf what
  when (n > fromIntegral (maxBound :: Int)) $ refuse ("A length in " <> what <> " is beyond any PSBT")
  return (fromIntegral n)

-- | Bytes after their length
sizedBytes :: String -> BytesParser ByteString
sizedBytes what = lengthOf what >>= (`bytesOf` what)

-- | A map: keys and values up to a zero byte, each key once
mapOf :: String -> BytesParser PsbtMap
mapOf what = go Map.empty
  where
    go m = do
      keyLength <- lengthOf what
      if keyLength == 0
        then return m
        else do
          keyBytes <- bytesOf keyLength what
          value <- sizedBytes what
          let key = Key (B.head keyBytes) (B.tail keyBytes)
          when (Map.member key m) $
            refuse (capital what <> " has the key " <> showKey key <> " twice")
          go (Map.insert key value m)

psbtParser :: BytesParser Psbt
psbtParser = do
  magic <- bytesOf 5 "the magic bytes"
  unless (magic == psbtMagic) $ refuse "Not a PSBT: the bytes do not start with the magic bytes of BIP 174"
  globals <- mapOf "the global map"
  (_, inputCount, outputCount) <- either refuse return (countsOf globals)
  inputs <- forM [0 .. inputCount - 1] $ \i -> mapOf ("input " <> show i)
  outputs <- forM [0 .. outputCount - 1] $ \i -> mapOf ("output " <> show i)
  either refuse return (psbtOfMaps globals inputs outputs)

-- | The version a global map names, and the number of inputs and of
-- outputs: those of the unsigned transaction in version 0, those the map
-- counts in version 2. The map is checked against the spec of the version
-- first.
countsOf :: PsbtMap -> Either String (PsbtVersion, Int, Int)
countsOf globals = do
  version <- versionOf globals
  checkMap "the global map" version globalFields globals
  case version of
    Version0 -> do
      tx <- unsignedTxOf globals
      return (Version0, length tx.inputs, length tx.outputs)
    Version2 -> do
      _ <- requiredField "The global map" "transaction version" txVersionType decodeWord32le globals
      inputCount <- requiredField "The global map" "input count" inputCountType decodeCount globals
      outputCount <- requiredField "The global map" "output count" outputCountType decodeCount globals
      return (Version2, inputCount, outputCount)

-- | The version the global map names with PSBT_GLOBAL_VERSION: 0 when it
-- names none
versionOf :: PsbtMap -> Either String PsbtVersion
versionOf globals = case plainField versionType globals of
  Nothing -> Right Version0
  Just bytes -> do
    n <- first ("The global map: the value of the key 0xfb " <>) (decodeWord32le bytes)
    case n of
      0 -> Right Version0
      2 -> Right Version2
      _ -> Left ("The PSBT is of version " <> show n <> ": only versions 0 and 2 are supported")

-- | The unsigned transaction of the global map of version 0, which must be
-- there, in the serialization without witness, with no input script
unsignedTxOf :: PsbtMap -> Either String Tx
unsignedTxOf globals = do
  bytes <- maybe (Left "The global map has no unsigned transaction") Right (Map.lookup unsignedTxKey globals)
  tx <- decodeFully "The unsigned transaction" bytes
  unless (null tx.witness && S.encode tx == bytes) $
    Left "The unsigned transaction is not in the serialization without witness"
  unless (all (B.null . (.script)) tx.inputs) $
    Left "The unsigned transaction has an input with a script"
  return tx

-- | The transaction the fields of version 2 describe: its version from
-- the global map, the lock time the inputs require or the fallback, an
-- input per input map from the id of the transaction it spends from, the
-- index of the output and the sequence, final when the map has none, and
-- an output per output map from its amount and script
transactionOf :: PsbtMap -> [PsbtMap] -> [PsbtMap] -> Either String Tx
transactionOf globals inputs outputs = do
  version <- requiredField "The global map" "transaction version" txVersionType decodeWord32le globals
  locktime <- lockTimeOf globals inputs
  txInputs <- forM (zip [0 :: Int ..] inputs) $ \(i, m) -> do
    let place = "Input " <> show i
    hash <- requiredField place "previous transaction id" prevTxidType decodeTxHash m
    index <- requiredField place "output index" outputIndexType decodeWord32le m
    sequence' <- fromMaybe 0xffffffff <$> optionalField "The sequence" sequenceType decodeWord32le m
    return (TxIn (OutPoint hash index) B.empty sequence')
  txOutputs <- forM (zip [0 :: Int ..] outputs) $ \(i, m) -> do
    let place = "Output " <> show i
    value <- requiredField place "amount" amountType decodeWord64le m
    script <- requiredField place "script" outScriptType Right m
    return (TxOut value script)
  return (Tx version txInputs txOutputs [] locktime)

-- | The lock time of a PSBT of version 2, as BIP 370 determines it. An
-- input may require a lock time as a height, as a time, or either, with
-- both. When no input requires one, it is the fallback lock time of the
-- global map, 0 without one. Otherwise it is the greatest of the kind every
-- input that requires one takes, a height when every one takes a height.
-- When some inputs take a height only and others a time only, no lock time
-- fits them.
lockTimeOf :: PsbtMap -> [PsbtMap] -> Either String Word32
lockTimeOf globals inputs = do
  fallback <- fromMaybe 0 <$> fallbackLockTime globals
  required <- forM inputs $ \m -> (,) <$> requiredTimeLockTime m <*> requiredHeightLockTime m
  let asking = [r | r@(time, height) <- required, isJust time || isJust height]
      heights = [height | (_, Just height) <- asking]
      times = [time | (Just time, _) <- asking]
  case () of
    _
      | null asking -> Right fallback
      | length heights == length asking -> Right (maximum heights)
      | length times == length asking -> Right (maximum times)
      | otherwise -> Left "No lock time fits every input: some require a height, others a time"

-- | A field a map must have, decoded. Its absence, or a value out of shape,
-- names the map and the field.
requiredField :: String -> String -> Word8 -> (ByteString -> Either String a) -> PsbtMap -> Either String a
requiredField what name t decode m = do
  bytes <- maybe (Left (what <> " has no " <> name)) Right (plainField t m)
  first ((what <> ": the " <> name <> " ") <>) (decode bytes)

-- | A field a map may have, decoded, named in a refusal
optionalField :: String -> Word8 -> (ByteString -> Either String a) -> PsbtMap -> Either String (Maybe a)
optionalField name t decode = traverse (first ((name <> " ") <>) . decode) . plainField t

-- | A value decoded from all the bytes given, or a refusal naming it
decodeFully :: (S.Serialize a) => String -> ByteString -> Either String a
decodeFully what bytes = case S.runGetState S.get bytes 0 of
  Right (a, rest) | B.null rest -> Right a
  _ -> Left (what <> " does not decode")

-- | A sentence that starts with the words given
capital :: String -> String
capital (c : rest) = toUpper c : rest
capital [] = []

-- | A key as a refusal names it: its type in hexadecimal, and its data
showKey :: Key -> String
showKey key =
  "0x" <> hexByte key.keyType <> (if B.null key.keyData then "" else " with the data " <> concatMap hexByte (B.unpack key.keyData))
  where
    hexByte b = (if b < 16 then "0" else "") <> showHex b ""

{- The shapes of the spec -}

-- | The data of a key of the spec: none, a public key, or an extended
-- public key
data KeyShape = NoData | PublicKeyData | XpubData

-- | A field the spec defines: the shape of its key, the versions of the
-- PSBT that may hold it, and a check of its value given the data of the
-- key
data Field = Field
  { shape :: KeyShape,
    versions :: [PsbtVersion],
    checkValue :: ByteString -> ByteString -> Either String ()
  }

-- | The fields the spec defines for a map, by type
type Fields = Map Word8 Field

-- | A field of both versions whose key carries no data
plain :: (ByteString -> Either String ()) -> Field
plain = Field NoData [Version0, Version2] . const

-- | A field of version 2 only whose key carries no data
plain2 :: (ByteString -> Either String ()) -> Field
plain2 = Field NoData [Version2] . const

-- | Check every key of a map against the spec: the keys of the fields it
-- defines must be of the version, must have their shape and their values
-- must decode, and a proprietary key must have its identifier and subtype.
-- Other keys are not the spec's to check.
checkMap :: String -> PsbtVersion -> Fields -> PsbtMap -> Either String ()
checkMap what version fields m = forM_ (Map.toList m) $ \(key, value) ->
  first ((capital what <> ": ") <>) $
    case Map.lookup key.keyType fields of
      Just field -> do
        unless (version `elem` field.versions) $
          Left ("the key " <> showKey key <> " is not of PSBT version " <> show (versionNumber version))
        checkShape field.shape key
        first (("the value of the key " <> showKey key <> " ") <>) $ field.checkValue key.keyData value
      Nothing
        | key.keyType == proprietaryType -> () <$ proprietaryOf key
        | otherwise -> return ()

checkShape :: KeyShape -> Key -> Either String ()
checkShape shape key = case shape of
  NoData -> unless (B.null key.keyData) $ Left ("the key " <> showKey key <> " carries data")
  PublicKeyData -> unless (isPublicKeyBytes key.keyData) $ Left ("the key " <> showKey key <> " is not a public key")
  XpubData -> unless (B.length key.keyData == 78) $ Left ("the key " <> showKey key <> " is not an extended public key")

-- | Whether the bytes have the length and the first byte of a public key,
-- compressed or not. Whether they are a point of the curve is checked
-- where the key is used.
isPublicKeyBytes :: ByteString -> Bool
isPublicKeyBytes bytes = case B.unpack (B.take 1 bytes) of
  [0x02] -> B.length bytes == 33
  [0x03] -> B.length bytes == 33
  [0x04] -> B.length bytes == 65
  _ -> False

-- The unsigned transaction is checked apart, by 'unsignedTxOf', and the
-- version by 'versionOf'
globalFields :: Fields
globalFields =
  Map.fromList
    [ (unsignedTxType, Field NoData [Version0] (const anyValue)),
      (xpubType, Field XpubData [Version0, Version2] xpubValue),
      (txVersionType, plain2 word32Value),
      (fallbackLockTimeType, plain2 word32Value),
      (inputCountType, plain2 countValue),
      (outputCountType, plain2 countValue),
      (txModifiableType, plain2 flagsValue),
      (versionType, plain word32Value)
    ]
  where
    -- The path of an extended key has one index per level of its depth,
    -- the fifth byte of the key
    xpubValue keyData value = do
      derivation <- decodeDerivation value
      unless (length (pathToList derivation.path) == fromIntegral (B.index keyData 4)) $
        Left "has a path that is not as deep as the key"
    countValue value = () <$ decodeCount value
    flagsValue value = unless (B.length value == 1) $ Left "is not a byte of flags"

inputFields :: Fields
inputFields =
  Map.fromList
    [ (nonWitnessUtxoType, plain txValue),
      (witnessUtxoType, plain txOutValue),
      (partialSigType, Field PublicKeyData [Version0, Version2] (const anyValue)),
      (sigHashTypeType, plain word32Value),
      (inRedeemScriptType, plain scriptValue),
      (inWitnessScriptType, plain scriptValue),
      (inDerivationType, Field PublicKeyData [Version0, Version2] (const derivationValue)),
      (finalScriptSigType, plain anyValue),
      (finalScriptWitnessType, plain witnessValue),
      (prevTxidType, plain2 txHashValue),
      (outputIndexType, plain2 word32Value),
      (sequenceType, plain2 word32Value),
      (requiredTimeType, plain2 timeLockValue),
      (requiredHeightType, plain2 heightLockValue)
    ]
  where
    txValue value = () <$ (decodeTx value :: Either String Tx)
    txOutValue value = () <$ (decodeTxOut value :: Either String TxOut)
    witnessValue value = () <$ decodeWitness value
    txHashValue value = () <$ decodeTxHash value
    timeLockValue value = do
      time <- decodeWord32le value
      unless (time >= lockTimeThreshold) $ Left ("is a time lock below " <> show lockTimeThreshold)
    heightLockValue value = do
      height <- decodeWord32le value
      unless (height > 0 && height < lockTimeThreshold) $ Left ("is not a height between 1 and " <> show (lockTimeThreshold - 1))

outputFields :: Fields
outputFields =
  Map.fromList
    [ (outRedeemScriptType, plain scriptValue),
      (outWitnessScriptType, plain scriptValue),
      (outDerivationType, Field PublicKeyData [Version0, Version2] (const derivationValue)),
      (amountType, plain2 amountValue),
      (outScriptType, plain2 anyValue)
    ]
  where
    amountValue value = () <$ decodeWord64le value

word32Value :: ByteString -> Either String ()
word32Value value = () <$ decodeWord32le value

anyValue :: ByteString -> Either String ()
anyValue _ = Right ()

derivationValue :: ByteString -> Either String ()
derivationValue value = () <$ decodeDerivation value

scriptValue :: ByteString -> Either String ()
scriptValue value = () <$ decodeScript value

decodeTx :: ByteString -> Either String Tx
decodeTx = decodeFully "is not a transaction: it"

decodeTxOut :: ByteString -> Either String TxOut
decodeTxOut = decodeFully "is not an output: it"

decodeScript :: ByteString -> Either String Script
decodeScript = decodeFully "is not a script: it"

decodeWord32le :: ByteString -> Either String Word32
decodeWord32le bytes
  | B.length bytes == 4 = Right $ B.foldr (\b acc -> acc `shiftL` 8 .|. fromIntegral b) 0 bytes
  | otherwise = Left "is not a 32-bit integer"

decodeWord64le :: ByteString -> Either String Word64
decodeWord64le bytes
  | B.length bytes == 8 = Right $ B.foldr (\b acc -> acc `shiftL` 8 .|. fromIntegral b) 0 bytes
  | otherwise = Left "is not a 64-bit integer"

decodeTxHash :: ByteString -> Either String TxHash
decodeTxHash = decodeFully "is not a transaction id: it"

-- | A count, as a compact size integer in its shortest form
decodeCount :: ByteString -> Either String Int
decodeCount bytes = do
  n <- first (const "is not a count") (parseAll (compactSizeOf "a count") "a count" bytes)
  when (n > fromIntegral (maxBound :: Int)) $ Left "is a count beyond any PSBT"
  return (fromIntegral n)

-- | A witness stack: the number of items, then each item after its length
decodeWitness :: ByteString -> Either String WitnessStack
decodeWitness = parseAll stack "the final witness"
  where
    stack = do
      count <- lengthOf "the final witness"
      replicateM count (sizedBytes "the final witness")

encodeWitness :: WitnessStack -> ByteString
encodeWitness stack = compactSize (fromIntegral (length stack)) <> B.concat (sized <$> stack)

{- Derivations -}

-- | How a key derives: the fingerprint of the key the path starts from,
-- the master key's as the spec wants it, and the path from it. A key
-- whose origin is unknown is named by its own fingerprint and an empty
-- path, or by the fingerprint of an ancestor and the path from it.
data Derivation = Derivation
  { fingerprint :: !Fingerprint,
    path :: !DerivPath
  }
  deriving (Eq, Show, Read, Generic)
  deriving anyclass (NFData)

encodeDerivation :: Derivation -> ByteString
encodeDerivation derivation =
  S.encode derivation.fingerprint <> B.concat (word32le <$> pathToList derivation.path)

-- | A derivation: four bytes of fingerprint, then four per index of the
-- path, little-endian
decodeDerivation :: ByteString -> Either String Derivation
decodeDerivation bytes = do
  unless (B.length bytes >= 4 && (B.length bytes - 4) `mod` 4 == 0) $
    Left "is not a fingerprint and a path"
  let (fingerprintBytes, pathBytes) = B.splitAt 4 bytes
  fingerprint <- decodeFully "is not a fingerprint: it" fingerprintBytes
  indices <- mapM decodeWord32le (chunksOf 4 pathBytes)
  return $ Derivation fingerprint (listToPath indices)

chunksOf :: Int -> ByteString -> [ByteString]
chunksOf n bytes
  | B.null bytes = []
  | otherwise = let (chunk, rest) = B.splitAt n bytes in chunk : chunksOf n rest

-- | The records of the type whose keys are public keys, in the order of
-- the map, with their values decoded
publicKeyRecords :: Word8 -> Ctx -> (ByteString -> Either String a) -> PsbtMap -> Either String [(PublicKey, a)]
publicKeyRecords t ctx decodeValue m =
  forM [(key, value) | (key, value) <- Map.toAscList m, key.keyType == t] $ \(key, value) -> do
    public <- first (const ("The key " <> showKey key <> " is not a public key")) (unmarshal ctx key.keyData)
    decoded <- first (("The value of the key " <> showKey key <> " ") <>) (decodeValue value)
    return (public, decoded)

derivationsOf :: Word8 -> Ctx -> PsbtMap -> Either String [(PublicKey, Derivation)]
derivationsOf t ctx = publicKeyRecords t ctx decodeDerivation

insertDerivation :: Word8 -> Ctx -> PublicKey -> Derivation -> PsbtMap -> PsbtMap
insertDerivation t ctx public derivation = Map.insert (Key t (marshal ctx public)) (encodeDerivation derivation)

-- | The derivations of the keys of an input: PSBT_IN_BIP32_DERIVATION
inputDerivations :: Ctx -> PsbtMap -> Either String [(PublicKey, Derivation)]
inputDerivations = derivationsOf inDerivationType

insertInputDerivation :: Ctx -> PublicKey -> Derivation -> PsbtMap -> PsbtMap
insertInputDerivation = insertDerivation inDerivationType

-- | The derivations of the keys of an output: PSBT_OUT_BIP32_DERIVATION
outputDerivations :: Ctx -> PsbtMap -> Either String [(PublicKey, Derivation)]
outputDerivations = derivationsOf outDerivationType

insertOutputDerivation :: Ctx -> PublicKey -> Derivation -> PsbtMap -> PsbtMap
insertOutputDerivation = insertDerivation outDerivationType

-- | The extended public keys of the global map, with their derivations:
-- PSBT_GLOBAL_XPUB. Those of another network, by their version bytes, are
-- left aside.
xpubRecords :: Network -> Ctx -> PsbtMap -> Either String [(XPubKey, Derivation)]
xpubRecords net ctx m =
  fmap catMaybes . forM [(key, value) | (key, value) <- Map.toAscList m, key.keyType == xpubType] $ \(key, value) -> do
    derivation <- first (("The value of the key " <> showKey key <> " ") <>) (decodeDerivation value)
    return $ (\xpub -> (xpub, derivation)) <$> eitherToMaybe (unmarshal (net, ctx) key.keyData)

insertXpubRecord :: Network -> Ctx -> XPubKey -> Derivation -> PsbtMap -> PsbtMap
insertXpubRecord net ctx xpub derivation = Map.insert (Key xpubType (marshal (net, ctx) xpub)) (encodeDerivation derivation)

{- The fields of an input and of an output -}

-- | The field of a type whose key carries no data, if the map has it
plainField :: Word8 -> PsbtMap -> Maybe ByteString
plainField t = Map.lookup (Key t B.empty)

insertPlainField :: Word8 -> ByteString -> PsbtMap -> PsbtMap
insertPlainField t = Map.insert (Key t B.empty)

deletePlainField :: Word8 -> PsbtMap -> PsbtMap
deletePlainField t = Map.delete (Key t B.empty)

-- | The whole transaction the input spends from: PSBT_IN_NON_WITNESS_UTXO
nonWitnessUtxo :: PsbtMap -> Either String (Maybe Tx)
nonWitnessUtxo = traverse (first ("The previous transaction " <>) . decodeTx) . plainField nonWitnessUtxoType

insertNonWitnessUtxo :: Tx -> PsbtMap -> PsbtMap
insertNonWitnessUtxo = insertPlainField nonWitnessUtxoType . S.encode

-- | The output the input spends, alone: PSBT_IN_WITNESS_UTXO
witnessUtxo :: PsbtMap -> Either String (Maybe TxOut)
witnessUtxo = traverse (first ("The witness output " <>) . decodeTxOut) . plainField witnessUtxoType

insertWitnessUtxo :: TxOut -> PsbtMap -> PsbtMap
insertWitnessUtxo = insertPlainField witnessUtxoType . S.encode

-- | The signatures of the input that are not final, by the public key each
-- is of, in the order of the map: PSBT_IN_PARTIAL_SIG. A signature is as
-- it goes in a script, with its sighash byte last.
partialSignatures :: Ctx -> PsbtMap -> Either String [(PublicKey, ByteString)]
partialSignatures ctx = publicKeyRecords partialSigType ctx Right

-- | Whether the input carries a signature that is not final
hasPartialSignatures :: PsbtMap -> Bool
hasPartialSignatures = any ((== partialSigType) . (.keyType)) . Map.keys

insertPartialSignature :: Ctx -> PublicKey -> ByteString -> PsbtMap -> PsbtMap
insertPartialSignature ctx public = Map.insert (Key partialSigType (marshal ctx public))

-- | The map without its signatures that are not final, as a finalizer
-- leaves it
deletePartialSignatures :: PsbtMap -> PsbtMap
deletePartialSignatures = Map.filterWithKey (\key _ -> key.keyType /= partialSigType)

-- | The sighash the input is to be signed with: PSBT_IN_SIGHASH_TYPE
sigHashType :: PsbtMap -> Either String (Maybe SigHash)
sigHashType = traverse (fmap fromIntegral . first ("The sighash type " <>) . decodeWord32le) . plainField sigHashTypeType

insertSigHashType :: SigHash -> PsbtMap -> PsbtMap
insertSigHashType = insertPlainField sigHashTypeType . word32le . fromIntegral

-- | The map without the sighash the input was to be signed with, as a
-- finalizer leaves it
deleteSigHashType :: PsbtMap -> PsbtMap
deleteSigHashType = deletePlainField sigHashTypeType

-- | The script of a type whose key carries no data, if the map has it
scriptField :: Word8 -> String -> PsbtMap -> Either String (Maybe Script)
scriptField t what = traverse (first ((what <> " ") <>) . decodeScript) . plainField t

insertScriptField :: Word8 -> Script -> PsbtMap -> PsbtMap
insertScriptField t = insertPlainField t . S.encode

-- | The redeem script of the P2SH coin an input spends:
-- PSBT_IN_REDEEM_SCRIPT
inputRedeemScript :: PsbtMap -> Either String (Maybe Script)
inputRedeemScript = scriptField inRedeemScriptType "The redeem script"

insertInputRedeemScript :: Script -> PsbtMap -> PsbtMap
insertInputRedeemScript = insertScriptField inRedeemScriptType

-- | The witness script of the P2WSH coin an input spends:
-- PSBT_IN_WITNESS_SCRIPT
inputWitnessScript :: PsbtMap -> Either String (Maybe Script)
inputWitnessScript = scriptField inWitnessScriptType "The witness script"

insertInputWitnessScript :: Script -> PsbtMap -> PsbtMap
insertInputWitnessScript = insertScriptField inWitnessScriptType

-- | The input script of a signed input: PSBT_IN_FINAL_SCRIPTSIG
finalScriptSig :: PsbtMap -> Maybe ByteString
finalScriptSig = plainField finalScriptSigType

insertFinalScriptSig :: ByteString -> PsbtMap -> PsbtMap
insertFinalScriptSig = insertPlainField finalScriptSigType

-- | The witness of a signed input: PSBT_IN_FINAL_SCRIPTWITNESS
finalScriptWitness :: PsbtMap -> Either String (Maybe WitnessStack)
finalScriptWitness = traverse decodeWitness . plainField finalScriptWitnessType

insertFinalScriptWitness :: WitnessStack -> PsbtMap -> PsbtMap
insertFinalScriptWitness = insertPlainField finalScriptWitnessType . encodeWitness

-- | The redeem script of a P2SH output: PSBT_OUT_REDEEM_SCRIPT
outputRedeemScript :: PsbtMap -> Either String (Maybe Script)
outputRedeemScript = scriptField outRedeemScriptType "The redeem script"

insertOutputRedeemScript :: Script -> PsbtMap -> PsbtMap
insertOutputRedeemScript = insertScriptField outRedeemScriptType

-- | The witness script of a P2WSH output: PSBT_OUT_WITNESS_SCRIPT
outputWitnessScript :: PsbtMap -> Either String (Maybe Script)
outputWitnessScript = scriptField outWitnessScriptType "The witness script"

insertOutputWitnessScript :: Script -> PsbtMap -> PsbtMap
insertOutputWitnessScript = insertScriptField outWitnessScriptType

{- The fields of version 2 -}

-- | The flags of PSBT_GLOBAL_TX_MODIFIABLE: whether inputs may be added,
-- whether outputs may be added, and whether an input is signed with
-- SIGHASH_SINGLE, which pairs it with the output at its index. The other
-- bits of the byte are not defined; they are kept as they are.
data Modifiable = Modifiable
  { inputsModifiable :: !Bool,
    outputsModifiable :: !Bool,
    hasSigHashSingle :: !Bool,
    undefinedBits :: !Word8
  }
  deriving (Eq, Show, Read, Generic)
  deriving anyclass (NFData)

-- | No flag set
noFlags :: Modifiable
noFlags = Modifiable False False False 0

-- | The flags of the global map, if it has the field: PSBT_GLOBAL_TX_MODIFIABLE
txModifiable :: PsbtMap -> Either String (Maybe Modifiable)
txModifiable = optionalField "The modifiable flags" txModifiableType decodeFlags
  where
    decodeFlags value = case B.unpack value of
      [byte] -> Right $ Modifiable (testBit byte 0) (testBit byte 1) (testBit byte 2) (byte .&. 0xf8)
      _ -> Left "are not one byte"

insertTxModifiable :: Modifiable -> PsbtMap -> PsbtMap
insertTxModifiable flags = insertPlainField txModifiableType (B.singleton byte)
  where
    byte = bit 0 flags.inputsModifiable .|. bit 1 flags.outputsModifiable .|. bit 2 flags.hasSigHashSingle .|. (flags.undefinedBits .&. 0xf8)
    bit :: Int -> Bool -> Word8
    bit n set = if set then 1 `shiftL` n else 0

-- | The global map without the flags, which a constructor may remove once
-- nothing is to be added
deleteTxModifiable :: PsbtMap -> PsbtMap
deleteTxModifiable = deletePlainField txModifiableType

-- | The lock time of the transaction when no input requires one:
-- PSBT_GLOBAL_FALLBACK_LOCKTIME
fallbackLockTime :: PsbtMap -> Either String (Maybe Word32)
fallbackLockTime = optionalField "The fallback lock time" fallbackLockTimeType decodeWord32le

-- | The least time, as a Unix timestamp, the input requires as the lock
-- time of the transaction: PSBT_IN_REQUIRED_TIME_LOCKTIME
requiredTimeLockTime :: PsbtMap -> Either String (Maybe Word32)
requiredTimeLockTime = optionalField "The required time lock time" requiredTimeType decodeWord32le

insertRequiredTimeLockTime :: Word32 -> PsbtMap -> PsbtMap
insertRequiredTimeLockTime = insertPlainField requiredTimeType . word32le

-- | The least block height the input requires as the lock time of the
-- transaction: PSBT_IN_REQUIRED_HEIGHT_LOCKTIME
requiredHeightLockTime :: PsbtMap -> Either String (Maybe Word32)
requiredHeightLockTime = optionalField "The required height lock time" requiredHeightType decodeWord32le

insertRequiredHeightLockTime :: Word32 -> PsbtMap -> PsbtMap
insertRequiredHeightLockTime = insertPlainField requiredHeightType . word32le

{- Proprietary fields -}

-- | A proprietary field, of type 0xFC: the identifier of the software it
-- belongs to, its subtype under that identifier, and the data after the
-- subtype, none for most
data Proprietary = Proprietary
  { identifier :: !ByteString,
    subtype :: !Word64,
    extra :: !ByteString
  }
  deriving (Eq, Show, Read, Generic)
  deriving anyclass (NFData)

-- | The key of a proprietary field: the type 0xFC, the identifier after
-- its length, the subtype as a compact size integer, and the data
proprietaryKey :: Proprietary -> Key
proprietaryKey p =
  Key proprietaryType (sized p.identifier <> compactSize p.subtype <> p.extra)

-- | The proprietary field a key is, if it is one: nothing for a key of
-- another type, a refusal for a proprietary key without its identifier
-- and subtype
proprietaryOf :: Key -> Either String (Maybe Proprietary)
proprietaryOf key
  | key.keyType /= proprietaryType = Right Nothing
  | otherwise =
      first (const ("the proprietary key " <> showKey key <> " has no identifier and subtype")) $
        Just <$> parseAll (Proprietary <$> sizedBytes what <*> compactSizeOf what <*> restOf) what key.keyData
  where
    what = "a proprietary key"

-- | The value of the proprietary field of the identifier and subtype,
-- with no data after the subtype, if the map has it
lookupProprietary :: ByteString -> Word64 -> PsbtMap -> Maybe ByteString
lookupProprietary identifier subtype = Map.lookup (proprietaryKey (Proprietary identifier subtype B.empty))

insertProprietary :: ByteString -> Word64 -> ByteString -> PsbtMap -> PsbtMap
insertProprietary identifier subtype = Map.insert (proprietaryKey (Proprietary identifier subtype B.empty))

{- Signing -}

-- | Where a signer gets the private key of a public key that a derivation
-- record names, if it has it
type Signer = PublicKey -> Derivation -> Maybe SecKey

-- | A signer that holds one private key, for the records of its public
-- key
keySigner :: Ctx -> SecKey -> Signer
keySigner ctx secret public _ = do
  guard (public.point == derivePubKey ctx secret)
  return secret

-- | A signer that derives from an extended private key. A record names a
-- key it derives by the fingerprint of the extended key and the path from
-- it, or, when the origin of the extended key is given, by the
-- fingerprint of that origin and the path from it, which starts with the
-- path of the extended key.
xPrvSigner :: Ctx -> XPrvKey -> Maybe Derivation -> Signer
xPrvSigner ctx xprv originM public derivation = do
  path <- relative
  let secret = (derivePath ctx path xprv).key
  guard (public.point == derivePubKey ctx secret)
  return secret
  where
    own = xPubFP ctx (deriveXPubKey ctx xprv)
    relative
      | derivation.fingerprint == own = Just derivation.path
      | Just origin <- originM, derivation.fingerprint == origin.fingerprint =
          listToPath <$> stripPrefix (pathToList origin.path) (pathToList derivation.path)
      | otherwise = Nothing

-- | Sign every input the signer has keys for, as the signer of the spec
-- does: a signature goes in the input, with the public key, for every
-- derivation record whose key the signer has. An input is signed against
-- the coin it spends, from its witness output or its previous transaction,
-- with the sighash it asks for, SIGHASH_ALL when it asks for none. A P2SH
-- coin needs its redeem script in the input, and a P2WSH coin its witness
-- script. An input without its coin, or with a final script already, is
-- left as it is.
signPsbt :: Network -> Ctx -> Signer -> Psbt -> Either String Psbt
signPsbt net ctx signer psbt = do
  signed <- forM (zip3 [0 ..] psbt.unsignedTx.inputs psbt.inputs) $ \(i, input, m) -> do
    coinM <- spentOutput input m
    case coinM of
      Just coin | not (isFinal m) -> do
        sighash <- fromMaybe sigHashAll <$> sigHashType m
        sigInput <- signingInput ctx input coin sighash m
        records <- inputDerivations ctx m
        let signature :: PublicKey -> SecKey -> ByteString
            signature public secret = encodeTxSig net ctx (makeSignature net ctx psbt.unsignedTx i sigInput (PrivateKey secret public.compress))
            keys = [(public, secret) | (public, d) <- records, Just secret <- [signer public d]]
        return (foldr (\(public, secret) -> insertPartialSignature ctx public (signature public secret)) m keys, [sighash | not (null keys)])
      _ -> return (m, [])
  return $ foldr afterSignature (Psbt psbt.version psbt.unsignedTx psbt.globals (fst <$> signed) psbt.outputs) (concatMap snd signed)

-- | The PSBT after a signature with the sighash was added, as the signer
-- of BIP 370 leaves the flags of version 2: inputs may no longer be added
-- unless the sighash has ANYONECANPAY, outputs no longer unless it is
-- NONE, and the PSBT has a SIGHASH_SINGLE signature when it is SINGLE. A
-- PSBT of version 0 has no flags.
afterSignature :: SigHash -> Psbt -> Psbt
afterSignature sighash psbt = case psbt.version of
  Version0 -> psbt
  Version2
    | isJust beforeM || after /= noFlags -> Psbt Version2 psbt.unsignedTx (insertTxModifiable after psbt.globals) psbt.inputs psbt.outputs
    | otherwise -> psbt
  where
    beforeM = either (const Nothing) id (txModifiable psbt.globals)
    before = fromMaybe noFlags beforeM
    after =
      before
        { inputsModifiable = before.inputsModifiable && anyoneCanPay sighash,
          outputsModifiable = before.outputsModifiable && isSigHashNone sighash,
          hasSigHashSingle = before.hasSigHashSingle || isSigHashSingle sighash
        }

-- | Whether an input has its final script or witness
isFinal :: PsbtMap -> Bool
isFinal m = any (`Map.member` m) [Key finalScriptSigType B.empty, Key finalScriptWitnessType B.empty]

-- | The output an input spends, from the fields of the input: its witness
-- output, or the output of its previous transaction, which must be the
-- transaction the input spends from
spentOutput :: TxIn -> PsbtMap -> Either String (Maybe TxOut)
spentOutput input m = do
  witnessM <- witnessUtxo m
  parentM <- nonWitnessUtxo m
  case (witnessM, parentM) of
    (Just coin, _) -> return (Just coin)
    (Nothing, Just parent) -> do
      unless (txHash parent == input.outpoint.hash) $
        Left "The previous transaction of the input is not the one it spends"
      maybe (Left "The input spends an output its previous transaction does not have") (return . Just) $
        listToMaybe (drop (fromIntegral input.outpoint.index) parent.outputs)
    (Nothing, Nothing) -> return Nothing

-- | What an input is signed against: the script of its coin, with the
-- redeem script of a P2SH coin and the witness script of a P2WSH coin
-- from the input, as 'makeSignature' wants them
signingInput :: Ctx -> TxIn -> TxOut -> SigHash -> PsbtMap -> Either String SigInput
signingInput ctx input coin sighash m = do
  coinScript <- first ("The script of the coin " <>) (unmarshal ctx coin.script)
  redeemM <- traverse (decodeOutput ctx) =<< inputRedeemScript m
  witnessM <- traverse (decodeOutput ctx) =<< inputWitnessScript m
  -- A SegWit coin, nested in P2SH or not, is signed against its witness
  -- program; any other against its own script
  let script = case redeemM of
        Just redeem | not (isSegwit coinScript), isSegwit redeem -> redeem
        _ -> coinScript
  return
    SigInput
      { script = script,
        value = coin.value,
        outpoint = input.outpoint,
        sighash = sighash,
        redeem = witnessM <|> redeemM
      }

{- Finalizing -}

-- | Finalize every input whose signatures suffice for the coin it spends,
-- as the finalizer of the spec does: the final script and witness go in
-- the input, and its partial signatures, sighash type, redeem script,
-- witness script and derivation records go, as Bitcoin Core clears them.
-- Its coin and the keys the spec does not define stay. The coins
-- finalized are those of P2PK, P2PKH and multisig scripts, P2SH coins
-- with their redeem script, P2WPKH coins, and P2WSH coins with their
-- witness script, nested in P2SH or not. Any other input, or one without
-- enough signatures, stays as it is.
finalizePsbt :: Ctx -> Psbt -> Either String Psbt
finalizePsbt ctx psbt = do
  inputs <- zipWithM finalized psbt.unsignedTx.inputs psbt.inputs
  return $ Psbt psbt.version psbt.unsignedTx psbt.globals inputs psbt.outputs
  where
    finalized input m = do
      coinM <- spentOutput input m
      case coinM of
        Just coin | not (isFinal m) -> do
          coinScript <- first ("The script of the coin " <>) (unmarshal ctx coin.script)
          finals <- finalScripts ctx m coinScript
          return $ case finals of
            Just (scriptSig, stack) ->
              foldr ($) (cleared m) $
                [insertFinalScriptSig scriptSig | not (B.null scriptSig)]
                  <> [insertFinalScriptWitness stack | not (null stack)]
            Nothing -> m
        _ -> return m
    cleared =
      deletePartialSignatures
        . deleteSigHashType
        . deletePlainField inRedeemScriptType
        . deletePlainField inWitnessScriptType
        . Map.filterWithKey (\key _ -> key.keyType /= inDerivationType)

-- | The final script and witness of an input, from its partial signatures
-- and the script of its coin, when they suffice
finalScripts :: Ctx -> PsbtMap -> ScriptOutput -> Either String (Maybe (ByteString, WitnessStack))
finalScripts ctx m coinScript = do
  signatures <- partialSignatures ctx m
  redeemM <- inputRedeemScript m
  witnessM <- inputWitnessScript m
  let signatureOf public = lookup public signatures
      signatureOfHash h = listToMaybe [(public, signature) | (public, signature) <- signatures, addressHash (marshal ctx public) == h]
      enough keys n = let found = mapMaybe signatureOf keys in if length found >= n then Just (take n found) else Nothing
      -- The items a script is spent with: the pushes of an input script,
      -- or the items of a witness
      items script = case script of
        PayPK public -> (: []) <$> signatureOf public
        PayPKHash h -> withKey <$> signatureOfHash h
        PayMulSig keys n -> (B.empty :) <$> enough keys n
        PayWitnessPKHash h -> withKey <$> signatureOfHash h
        _ -> Nothing
      withKey :: (PublicKey, ByteString) -> [ByteString]
      withKey (public, signature) = [signature, marshal ctx public]
      scriptOf = S.encode . Script . map opPushData
      -- The witness of a SegWit coin: the items of its program, with the
      -- witness script last for P2WSH
      witnessOf script = case script of
        PayWitnessScriptHash _ -> do
          witnessScript <- witnessM
          guard (toP2WSH witnessScript == script)
          inner <- eitherToMaybe (decodeOutput ctx witnessScript)
          (<> [S.encode witnessScript]) <$> items inner
        _ -> items script
  return $ case coinScript of
    PayScriptHash _ -> do
      redeem <- redeemM
      guard (toP2SH redeem == coinScript)
      inner <- eitherToMaybe (decodeOutput ctx redeem)
      if isSegwit inner
        then (scriptOf [S.encode redeem],) <$> witnessOf inner
        else (\found -> (scriptOf (found <> [S.encode redeem]), [])) <$> items inner
    _
      | isSegwit coinScript -> (B.empty,) <$> witnessOf coinScript
      | otherwise -> (\found -> (scriptOf found, [])) <$> items coinScript
