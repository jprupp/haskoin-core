{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
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
-- missing, bytes after the last map. So is what Bitcoin Core refuses when
-- it reads a PSBT: a key type that is not a compact size integer in its
-- shortest form, a public key that is not a point of the curve, a partial
-- signature that is not in the encoding of BIP 66 with a defined sighash
-- byte, a previous transaction that is not the one its input spends, and
-- a script tree that is not whole.
--
-- The amounts a PSBT states are claims of whoever wrote it, unless the
-- input carries its previous transaction. 'inputCoins' tells which coins
-- are checked, 'psbtFee' gives the fee from checked coins only, and the
-- signers want the previous transaction of a SegWit version 0 coin
-- ('requirePreviousTx'). The derivation records of outputs are claims
-- too: to treat an output as change, derive its key and compare.
--
-- The fields the spec defines are read and written with the functions
-- below, with the Taproot fields of
-- [BIP 371](https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki).
-- The roles of the spec are here too: a creator ('psbtOf'), a
-- constructor ('addInput', 'addOutput'), a combiner ('combinePsbt'), a
-- signer ('signPsbt'), a finalizer ('finalizePsbt') and a transaction
-- extractor ('psbtTransaction'), which wants every input final. An updater
-- is the functions that insert fields, and 'setInputSequence'.
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
    psbtPartialTransaction,

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

    -- * The Taproot fields of an input
    tapKeySig,
    insertTapKeySig,
    tapScriptSigs,
    insertTapScriptSig,
    TapLeafScript (..),
    tapLeafScripts,
    insertTapLeafScript,
    TapDerivation (..),
    inputTapDerivations,
    insertInputTapDerivation,
    inputTapInternalKey,
    insertInputTapInternalKey,
    inputTapMerkleRoot,
    insertInputTapMerkleRoot,

    -- * The fields of an output
    outputRedeemScript,
    insertOutputRedeemScript,
    outputWitnessScript,
    insertOutputWitnessScript,
    outputDerivations,
    insertOutputDerivation,
    outputTapInternalKey,
    insertOutputTapInternalKey,
    outputTapTree,
    insertOutputTapTree,
    outputTapDerivations,
    insertOutputTapDerivation,

    -- * Proprietary fields
    Proprietary (..),
    proprietaryKey,
    proprietaryOf,
    lookupProprietary,
    insertProprietary,

    -- * The coins of a PSBT
    InputCoin (..),
    inputCoins,
    psbtFee,

    -- * Signing
    Signer (..),
    defaultSigHashes,
    keySigner,
    xPrvSigner,
    signPsbt,
    afterSignature,

    -- * Finalizing
    finalizePsbt,
  )
where

import Control.DeepSeq (NFData)
import Control.Monad (ap, forM, forM_, guard, replicateM, unless, when, zipWithM)
import Crypto.Hash (Digest, SHA256, digestFromByteString)
import Crypto.Secp256k1 (Ctx, PubKey, SecKey, derivePubKey, exportXOnlyPubKey, importXOnlyPubKey, signSchnorr, verifySchnorr)
import Data.Bifunctor (first)
import Data.Bits (complement, shiftL, testBit, (.&.), (.|.))
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Base64.Types (extractBase64)
import Data.ByteString.Base64 (decodeBase64Untyped, encodeBase64')
import Data.Char (toUpper)
import Data.List (find, nubBy, stripPrefix)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Maybe (catMaybes, fromMaybe, isJust, isNothing, listToMaybe, mapMaybe, maybeToList)
import Data.Serialize qualified as S
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Crypto.Hash (Hash160, addressHash)
import Haskoin.Crypto.Keys.Common
import Haskoin.Crypto.Keys.Extended
import Haskoin.Crypto.Signature (hashToMsg, verifyHashSig)
import Haskoin.Network.Common (VarInt (..))
import Haskoin.Network.Data
import Haskoin.Script.Common
import Haskoin.Script.SigHash
import Haskoin.Script.Standard
import Haskoin.Transaction.Builder.Sign (SigInput (..), makeSigHash, makeSignature)
import Haskoin.Transaction.Common hiding (decodeTx)
import Haskoin.Transaction.Segwit (isSegwit)
import Haskoin.Transaction.Taproot
import Haskoin.Util
import Numeric (showHex)
import Text.Read (readMaybe)

{- A PSBT -}

-- | A key of a map: its type, and the data after the type byte. Most
-- fields have none; a derivation or a signature has the public key it is
-- of. The type of a key is a compact size integer. Every type the spec
-- defines fits one byte. A type from 253 on takes three or five bytes on
-- the wire: its first byte, 0xfd or 0xfe, is the 'keyType' here, and the
-- other bytes of the type are the start of the 'keyData', where
-- 'decodePsbt' requires them to be the shortest form of the type.
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
--
-- In version 2 the record so holds the transaction twice. 'signPsbt' signs
-- 'unsignedTx', and 'encodePsbt' writes the maps. A record update that
-- changes one and not the other gives a PSBT whose bytes describe another
-- transaction than the one that is signed. Change the transaction of such a
-- PSBT with 'addInput', 'addOutput' and 'psbtOfMaps', which keep the two in
-- step.
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
  forM_ (zip3 [0 :: Int ..] tx.inputs inputs) $ \(i, input, m) ->
    first (("Input " <> show i <> ": ") <>) (checkPreviousTx input m)
  return $ Psbt version tx (Map.delete unsignedTxKey globals) inputs outputs

-- | The previous transaction of an input, when its map has one, must be
-- the transaction the input spends from and have the output it spends, as
-- Bitcoin Core requires when it reads a PSBT ("Non-witness UTXO does not
-- match outpoint hash", psbt.h)
checkPreviousTx :: TxIn -> PsbtMap -> Either String ()
checkPreviousTx input m = do
  parentM <- nonWitnessUtxo m
  forM_ parentM (previousOutput input)

-- | The output an input spends, from its previous transaction: the
-- transaction must be the one the input names, and have that output
previousOutput :: TxIn -> Tx -> Either String TxOut
previousOutput input parent = do
  unless (txHash parent == input.outpoint.hash) $
    Left "the previous transaction is not the one the input spends"
  maybe (Left "the input spends an output its previous transaction does not have") Right $
    listToMaybe (drop (fromIntegral input.outpoint.index) parent.outputs)

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

-- | The transaction of a PSBT whose inputs are all final, with their final
-- scripts and witnesses, as the transaction extractor of the spec builds
-- it. BIP 174 has the extractor check "whether all inputs have complete
-- scriptSigs and scriptWitnesses" first, and Bitcoin Core gives no
-- transaction otherwise (@FinalizeAndExtractPSBT@), so an input that is
-- not final is refused here. 'psbtPartialTransaction' takes such a PSBT.
--
-- The final scripts are taken as they are: nothing runs them. Finalize
-- with 'finalizePsbt', which verifies the signatures it uses, or verify
-- the transaction before it is sent.
psbtTransaction :: Psbt -> Either String Tx
psbtTransaction psbt = do
  forM_ (zip [0 :: Int ..] psbt.inputs) $ \(i, m) ->
    unless (isFinal m) $ Left ("Input " <> show i <> " is not final")
  psbtPartialTransaction psbt

-- | The transaction of a PSBT with the final script and witness of every
-- input that has them. An input without them stays unsigned, so the
-- transaction may not be valid yet: this is for looking at a PSBT that is
-- still being signed, not for sending. 'psbtTransaction' is the extractor.
psbtPartialTransaction :: Psbt -> Either String Tx
psbtPartialTransaction psbt = do
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
-- its output. The map is checked against the spec as a map read from
-- bytes is: a field out of shape, or a previous transaction that is not
-- the one the input spends, is refused.
addInput :: TxIn -> PsbtMap -> Psbt -> Either String Psbt
addInput input m psbt = do
  flags <- modifiableOf psbt
  unless flags.inputsModifiable $ Left "The inputs of the PSBT may not be modified"
  when (any ((== input.outpoint) . (.outpoint)) psbt.unsignedTx.inputs) $
    Left "An input of the PSBT spends that output already"
  let added = withInputFields input m
      inputs = psbt.inputs <> [added]
      globals = withCounts (length inputs) (length psbt.outputs) psbt.globals
      place = "input " <> show (length psbt.inputs)
  -- The same checks as when a PSBT is read, so that the bytes written are
  -- bytes 'decodePsbt' reads
  checkMap place Version2 inputFields added
  first ((capital place <> ": ") <>) (checkPreviousTx input added)
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
  let added = withOutputFields output m
      outputs = psbt.outputs <> [added]
      globals = withCounts (length psbt.inputs) (length outputs) psbt.globals
  checkMap ("output " <> show (length psbt.outputs)) Version2 outputFields added
  tx <- transactionOf globals psbt.inputs outputs
  return $ Psbt Version2 tx globals psbt.inputs outputs

-- | The flags of a PSBT of version 2, none set when it has no field of
-- them. A PSBT of version 0 takes no input or output.
modifiableOf :: Psbt -> Either String Modifiable
modifiableOf psbt = do
  unless (psbt.version == Version2) $ Left "A PSBT of version 0 takes no input or output: its transaction is fixed"
  fromMaybe noFlags <$> txModifiable psbt.globals

-- | Whether an input has a signature: one that is not final, a Taproot
-- one, or its final script or witness
hasSignatures :: PsbtMap -> Bool
hasSignatures m = hasPartialSignatures m || isFinal m || any ((`elem` [tapKeySigType, tapScriptSigType]) . (.keyType)) (Map.keys m)

-- | The PSBT with the sequence of the input at the index set, as an
-- updater of BIP 370 may set one. The sequences of a PSBT of version 0
-- are in its unsigned transaction, which is fixed. An input that is
-- signed keeps its sequence, since every signature commits to it.
setInputSequence :: Int -> Word32 -> Psbt -> Either String Psbt
setInputSequence i sequence' psbt = do
  unless (psbt.version == Version2) $ Left "The sequences of a PSBT of version 0 are in its unsigned transaction, which is fixed"
  unless (i >= 0 && i < length psbt.inputs) $ Left ("The PSBT has no input " <> show i)
  when (hasSignatures (psbt.inputs !! i)) $ Left ("Input " <> show i <> " is signed already: its sequence may not change")
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

nonWitnessUtxoType, witnessUtxoType, partialSigType, sigHashTypeType, inRedeemScriptType, inWitnessScriptType, inDerivationType, finalScriptSigType, finalScriptWitnessType, tapKeySigType, tapScriptSigType, tapLeafScriptType, inTapDerivationType, inTapInternalKeyType, tapMerkleRootType :: Word8
nonWitnessUtxoType = 0x00
witnessUtxoType = 0x01
partialSigType = 0x02
sigHashTypeType = 0x03
inRedeemScriptType = 0x04
inWitnessScriptType = 0x05
inDerivationType = 0x06
finalScriptSigType = 0x07
finalScriptWitnessType = 0x08
tapKeySigType = 0x13
tapScriptSigType = 0x14
tapLeafScriptType = 0x15
inTapDerivationType = 0x16
inTapInternalKeyType = 0x17
tapMerkleRootType = 0x18

prevTxidType, outputIndexType, sequenceType, requiredTimeType, requiredHeightType :: Word8
prevTxidType = 0x0e
outputIndexType = 0x0f
sequenceType = 0x10
requiredTimeType = 0x11
requiredHeightType = 0x12

outRedeemScriptType, outWitnessScriptType, outDerivationType, amountType, outScriptType, outTapInternalKeyType, outTapTreeType, outTapDerivationType :: Word8
outRedeemScriptType = 0x00
outWitnessScriptType = 0x01
outDerivationType = 0x02
amountType = 0x03
outScriptType = 0x04
outTapInternalKeyType = 0x05
outTapTreeType = 0x06
outTapDerivationType = 0x07

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
          either refuse return (checkKeyType what keyBytes)
          value <- sizedBytes what
          let key = Key (B.head keyBytes) (B.tail keyBytes)
          when (Map.member key m) $
            refuse (capital what <> " has the key " <> showKey key <> " twice")
          go (Map.insert key value m)

-- | The type of a key is a compact size integer at the start of the key.
-- Every type the spec defines is below 0xfd and so is the first byte. A
-- type from 0xfd on takes three, five or nine bytes: it must be whole, in
-- its shortest form, and at most 'maxCompactSize', as Bitcoin Core reads
-- it (@ReadCompactSize@ in serialize.h). Such a key is kept as its first
-- byte and, as its data, the bytes after it.
checkKeyType :: String -> ByteString -> Either String ()
checkKeyType what keyBytes = case B.unpack (B.take 1 keyBytes) of
  [0xfd] -> longer 2 0xfd
  [0xfe] -> longer 4 0x10000
  [0xff] -> longer 8 0x100000000
  _ -> Right ()
  where
    longer :: Int -> Word64 -> Either String ()
    longer n least = do
      let bytes = B.take n (B.drop 1 keyBytes)
      unless (B.length bytes == n) $
        Left (capital what <> " has a key that ends inside its type")
      let value = B.foldr (\b acc -> acc `shiftL` 8 .|. fromIntegral b) 0 bytes
      when (value < least) $
        Left (capital what <> " has a key whose type is not in its shortest form")
      when (value > maxCompactSize) $
        Left (capital what <> " has a key whose type is beyond any type")

-- | The largest compact size integer Bitcoin Core reads: its @MAX_SIZE@
maxCompactSize :: Word64
maxCompactSize = 0x02000000

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
-- there, in the serialization without witness, with no input script. It
-- is read with 'parseLegacyTx', as Bitcoin Core reads it without allowing
-- a witness, so that a transaction with no inputs, which the spec allows,
-- is not taken for the extended format of BIP 144.
unsignedTxOf :: PsbtMap -> Either String Tx
unsignedTxOf globals = do
  bytes <- maybe (Left "The global map has no unsigned transaction") Right (Map.lookup unsignedTxKey globals)
  tx <- case S.runGetState parseLegacyTx bytes 0 of
    Right (parsed, rest) | B.null rest -> Right parsed
    _ -> Left "The unsigned transaction does not decode"
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

-- | A key as a refusal names it: its type in hexadecimal, and its data.
-- Only the first 'maxShownKeyData' bytes of the data are written, then
-- its length, so that whoever writes a PSBT cannot make a refusal as
-- long as they like.
showKey :: Key -> String
showKey key =
  "0x" <> hexByte key.keyType <> (if B.null key.keyData then "" else " with the data " <> shown)
  where
    hexByte b = (if b < 16 then "0" else "") <> showHex b ""
    hexOf = concatMap hexByte . B.unpack
    shown
      | B.length key.keyData <= maxShownKeyData = hexOf key.keyData
      | otherwise = hexOf (B.take maxShownKeyData key.keyData) <> "… (" <> show (B.length key.keyData) <> " bytes)"

-- | How many bytes of the data of a key a refusal writes: enough for a
-- compressed public key, which is 33 bytes
maxShownKeyData :: Int
maxShownKeyData = 40

{- The shapes of the spec -}

-- | The data of a key of the spec: none, a public key, an extended public
-- key, an x-only public key, an x-only public key with a leaf hash, or a
-- control block
data KeyShape = NoData | PublicKeyData | XpubData | XOnlyKeyData | KeyAndLeafData | ControlBlockData

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
  XpubData -> unless (isXpubBytes key.keyData) $ Left ("the key " <> showKey key <> " is not an extended public key")
  XOnlyKeyData -> unless (B.length key.keyData == 32) $ Left ("the key " <> showKey key <> " is not an x-only public key")
  KeyAndLeafData -> unless (B.length key.keyData == 64) $ Left ("the key " <> showKey key <> " is not an x-only public key and a leaf hash")
  ControlBlockData -> unless (isControlBlockLength (B.length key.keyData)) $ Left ("the key " <> showKey key <> " is not a control block")

-- | Whether a control block may have the length: 33 bytes plus 32 per
-- node, with at most 'maxControlBlockNodes' nodes
isControlBlockLength :: Int -> Bool
isControlBlockLength len =
  len >= 33 && (len - 33) `mod` 32 == 0 && (len - 33) `div` 32 <= maxControlBlockNodes

-- | Whether the bytes are a public key, compressed or not: they have the
-- length and the first byte of one, and are a point of the curve, as
-- Bitcoin Core requires of the keys of a PSBT (@IsFullyValid@ in psbt.h).
-- The point is checked through the 'Read' instance of the binding, which
-- parses the hexadecimal form of a key without a context.
isPublicKeyBytes :: ByteString -> Bool
isPublicKeyBytes bytes = shaped && isJust (readMaybe (show (encodeHex bytes)) :: Maybe PubKey)
  where
    shaped = case B.unpack (B.take 1 bytes) of
      [0x02] -> B.length bytes == 33
      [0x03] -> B.length bytes == 33
      [0x04] -> B.length bytes == 65
      _ -> False

-- | Whether the bytes are an extended public key as BIP 32 serializes
-- one: 78 bytes that end with a compressed public key
isXpubBytes :: ByteString -> Bool
isXpubBytes bytes = B.length bytes == 78 && B.length key == 33 && isPublicKeyBytes key
  where
    key = B.drop 45 bytes

-- | Whether the bytes are a signature as a script holds one: in the
-- encoding BIP 66 requires, with its sighash byte last. This is
-- @IsValidSignatureEncoding@ of Bitcoin Core (script/interpreter.cpp),
-- line for line. It checks the shape of the bytes, not the range of the
-- two numbers.
isSignatureEncoding :: ByteString -> Bool
isSignatureEncoding sig =
  -- Minimum and maximum size
  size >= 9
    && size <= 73
    -- A signature is of type 0x30 (compound)
    && at 0 == 0x30
    -- The length covers the entire signature, without the sighash byte
    && fromIntegral (at 1) == size - 3
    -- The length of the S element is still inside the signature
    && 5 + lenR < size
    -- The lengths of the two elements add up to the signature
    && lenR + lenS + 7 == size
    -- R is an integer, not empty, not negative, with no needless zero byte
    && at 2 == 0x02
    && lenR /= 0
    && at 4 .&. 0x80 == 0
    && not (lenR > 1 && at 4 == 0x00 && at 5 .&. 0x80 == 0)
    -- S is an integer, not empty, not negative, with no needless zero byte
    && at (lenR + 4) == 0x02
    && lenS /= 0
    && at (lenR + 6) .&. 0x80 == 0
    && not (lenS > 1 && at (lenR + 6) == 0x00 && at (lenR + 7) .&. 0x80 == 0)
  where
    size = B.length sig
    at = B.index sig
    lenR = fromIntegral (at 3) :: Int
    lenS = fromIntegral (at (5 + lenR)) :: Int

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
      (partialSigType, Field PublicKeyData [Version0, Version2] (const partialSigValue)),
      (sigHashTypeType, plain word32Value),
      (inRedeemScriptType, plain scriptValue),
      (inWitnessScriptType, plain scriptValue),
      (inDerivationType, Field PublicKeyData [Version0, Version2] (const derivationValue)),
      (finalScriptSigType, plain anyValue),
      (finalScriptWitnessType, plain witnessValue),
      (tapKeySigType, plain tapSigValue),
      (tapScriptSigType, Field KeyAndLeafData [Version0, Version2] (const tapSigValue)),
      (tapLeafScriptType, Field ControlBlockData [Version0, Version2] (const leafScriptValue)),
      (inTapDerivationType, Field XOnlyKeyData [Version0, Version2] (const tapDerivationValue)),
      (inTapInternalKeyType, plain xOnlyKeyValue),
      (tapMerkleRootType, plain hashValue),
      (prevTxidType, plain2 txHashValue),
      (outputIndexType, plain2 word32Value),
      (sequenceType, plain2 word32Value),
      (requiredTimeType, plain2 timeLockValue),
      (requiredHeightType, plain2 heightLockValue)
    ]
  where
    txValue value = () <$ (decodeTx value :: Either String Tx)
    -- Bitcoin Core checks a partial signature with the flags DERSIG and
    -- STRICTENC when it reads a PSBT: the encoding of BIP 66, and a sighash
    -- byte that is ALL, NONE or SINGLE, with ANYONECANPAY or not. The fork
    -- id flag is let through here, since the decoder knows no network; the
    -- signer and the finalizer check it.
    partialSigValue value =
      unless (isSignatureEncoding value && not (isSigHashUnknown (fromIntegral (B.last value)))) $
        Left "is not a signature in the encoding of BIP 66 with a defined sighash byte"
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
      (outScriptType, plain2 anyValue),
      (outTapInternalKeyType, plain xOnlyKeyValue),
      (outTapTreeType, plain tapTreeValue),
      (outTapDerivationType, Field XOnlyKeyData [Version0, Version2] (const tapDerivationValue))
    ]
  where
    amountValue value = () <$ decodeWord64le value

tapSigValue :: ByteString -> Either String ()
tapSigValue value = () <$ first ("is not a Taproot signature: " <>) (decodeTaprootSig value)

leafScriptValue :: ByteString -> Either String ()
leafScriptValue value = when (B.null value) $ Left "has no leaf version"

tapDerivationValue :: ByteString -> Either String ()
tapDerivationValue value = () <$ decodeTapDerivation value

xOnlyKeyValue :: ByteString -> Either String ()
xOnlyKeyValue value = unless (B.length value == 32) $ Left "is not an x-only public key"

hashValue :: ByteString -> Either String ()
hashValue value = unless (B.length value == 32) $ Left "is not a 32-byte hash"

-- | A script tree as Bitcoin Core accepts one when it reads a PSBT: not
-- empty, no leaf deeper than 128, every leaf version even, and the leaves
-- those of one whole tree in depth-first order
tapTreeValue :: ByteString -> Either String ()
tapTreeValue value = do
  leaves <- decodeTapTree value
  when (null leaves) $ Left "is an empty script tree"
  when (any ((> maxControlBlockNodes) . fromIntegral . (.depth)) leaves) $
    Left ("has a leaf deeper than " <> show maxControlBlockNodes)
  when (any (odd . (.version)) leaves) $ Left "has a leaf with an odd leaf version"
  when (isNothing (tapTreeFromLeaves leaves)) $ Left "is not a whole script tree"

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

-- | The derivations of the keys of an output: PSBT_OUT_BIP32_DERIVATION.
-- A record is a claim of whoever wrote the PSBT. To treat an output as
-- change, derive the key and compare it with the script of the output.
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

{- The Taproot fields of BIP 371 -}

-- | The key path signature of a Taproot input: PSBT_IN_TAP_KEY_SIG
tapKeySig :: PsbtMap -> Either String (Maybe TaprootSignature)
tapKeySig = optionalField "The key path signature" tapKeySigType decodeTaprootSig

insertTapKeySig :: TaprootSignature -> PsbtMap -> PsbtMap
insertTapKeySig = insertPlainField tapKeySigType . encodeTaprootSig

-- | The script path signatures of a Taproot input, each by the x-only key
-- and the leaf hash it is for: PSBT_IN_TAP_SCRIPT_SIG
tapScriptSigs :: Ctx -> PsbtMap -> Either String [((PubKey, Digest SHA256), TaprootSignature)]
tapScriptSigs ctx m =
  forM [(key, value) | (key, value) <- Map.toAscList m, key.keyType == tapScriptSigType] $ \(key, value) -> do
    let (keyBytes, leafBytes) = B.splitAt 32 key.keyData
    leafKey <- maybe (Left ("The key " <> showKey key <> " is not an x-only public key and a leaf hash")) Right $ importXOnlyPubKey ctx keyBytes
    leaf <- maybe (Left ("The key " <> showKey key <> " is not an x-only public key and a leaf hash")) Right $ digestOf leafBytes
    signature <- first (("The value of the key " <> showKey key <> " ") <>) (decodeTaprootSig value)
    return ((leafKey, leaf), signature)

insertTapScriptSig :: Ctx -> PubKey -> Digest SHA256 -> TaprootSignature -> PsbtMap -> PsbtMap
insertTapScriptSig ctx leafKey leaf signature =
  Map.insert (Key tapScriptSigType (exportXOnlyPubKey ctx leafKey <> BA.convert leaf)) (encodeTaprootSig signature)

-- | A leaf script a Taproot input may be spent with, and the control
-- block that commits it to the output key: PSBT_IN_TAP_LEAF_SCRIPT
data TapLeafScript = TapLeafScript
  { controlBlock :: !ByteString,
    script :: !Script,
    leafVersion :: !TapLeafVersion
  }
  deriving (Eq, Show, Read, Generic)
  deriving anyclass (NFData)

-- | The leaf scripts of a Taproot input, with their control blocks:
-- PSBT_IN_TAP_LEAF_SCRIPT
tapLeafScripts :: Ctx -> PsbtMap -> Either String [TapLeafScript]
tapLeafScripts ctx m =
  forM [(key, value) | (key, value) <- Map.toAscList m, key.keyType == tapLeafScriptType] $ \(key, value) -> do
    _ <- first (const ("The key " <> showKey key <> " is not a control block")) (decodeControlBlock ctx key.keyData)
    when (B.null value) $ Left ("The value of the key " <> showKey key <> " has no leaf version")
    script <- first (("The value of the key " <> showKey key <> " ") <>) (decodeScript (B.init value))
    return (TapLeafScript key.keyData script (B.last value))

insertTapLeafScript :: TapLeafScript -> PsbtMap -> PsbtMap
insertTapLeafScript leaf =
  Map.insert (Key tapLeafScriptType leaf.controlBlock) (S.encode leaf.script <> B.singleton leaf.leafVersion)

-- | How an x-only key of a Taproot input or output derives, and the
-- leaves it appears in: the value of PSBT_IN_TAP_BIP32_DERIVATION and
-- PSBT_OUT_TAP_BIP32_DERIVATION. The internal key has no leaf.
data TapDerivation = TapDerivation
  { leafHashes :: ![Digest SHA256],
    derivation :: !Derivation
  }
  deriving (Eq, Show, Generic)

encodeTapDerivation :: TapDerivation -> ByteString
encodeTapDerivation d =
  compactSize (fromIntegral (length d.leafHashes)) <> B.concat (BA.convert <$> d.leafHashes) <> encodeDerivation d.derivation

-- | A Taproot derivation: the number of leaf hashes, the hashes, then the
-- fingerprint and the path
decodeTapDerivation :: ByteString -> Either String TapDerivation
decodeTapDerivation = parseAll record "a Taproot derivation"
  where
    record = do
      count <- lengthOf "a Taproot derivation"
      hashes <- replicateM count (bytesOf 32 "a Taproot derivation")
      leaves <- maybe (refuse "is not a Taproot derivation") return (mapM digestOf hashes)
      rest <- restOf
      derivation <- either refuse return (decodeDerivation rest)
      return (TapDerivation leaves derivation)

tapDerivationsOf :: Word8 -> Ctx -> PsbtMap -> Either String [(PubKey, TapDerivation)]
tapDerivationsOf t ctx m =
  forM [(key, value) | (key, value) <- Map.toAscList m, key.keyType == t] $ \(key, value) -> do
    public <- maybe (Left ("The key " <> showKey key <> " is not an x-only public key")) Right (importXOnlyPubKey ctx key.keyData)
    decoded <- first (("The value of the key " <> showKey key <> " ") <>) (decodeTapDerivation value)
    return (public, decoded)

insertTapDerivation :: Word8 -> Ctx -> PubKey -> TapDerivation -> PsbtMap -> PsbtMap
insertTapDerivation t ctx public d = Map.insert (Key t (exportXOnlyPubKey ctx public)) (encodeTapDerivation d)

-- | The derivations of the x-only keys of a Taproot input, each with the
-- leaves it appears in: PSBT_IN_TAP_BIP32_DERIVATION. The key is the
-- point of even y with that x coordinate.
inputTapDerivations :: Ctx -> PsbtMap -> Either String [(PubKey, TapDerivation)]
inputTapDerivations = tapDerivationsOf inTapDerivationType

insertInputTapDerivation :: Ctx -> PubKey -> TapDerivation -> PsbtMap -> PsbtMap
insertInputTapDerivation = insertTapDerivation inTapDerivationType

-- | The derivations of the x-only keys of a Taproot output:
-- PSBT_OUT_TAP_BIP32_DERIVATION. A record is a claim of whoever wrote the
-- PSBT, as for 'outputDerivations'.
outputTapDerivations :: Ctx -> PsbtMap -> Either String [(PubKey, TapDerivation)]
outputTapDerivations = tapDerivationsOf outTapDerivationType

insertOutputTapDerivation :: Ctx -> PubKey -> TapDerivation -> PsbtMap -> PsbtMap
insertOutputTapDerivation = insertTapDerivation outTapDerivationType

xOnlyKeyField :: Word8 -> String -> Ctx -> PsbtMap -> Either String (Maybe PubKey)
xOnlyKeyField t what ctx = optionalField what t (maybe (Left "is not an x-only public key") Right . importXOnlyPubKey ctx)

insertXOnlyKeyField :: Word8 -> Ctx -> PubKey -> PsbtMap -> PsbtMap
insertXOnlyKeyField t ctx = insertPlainField t . exportXOnlyPubKey ctx

-- | The internal key of the Taproot coin an input spends:
-- PSBT_IN_TAP_INTERNAL_KEY. The key is the point of even y with that x
-- coordinate.
inputTapInternalKey :: Ctx -> PsbtMap -> Either String (Maybe PubKey)
inputTapInternalKey = xOnlyKeyField inTapInternalKeyType "The internal key"

insertInputTapInternalKey :: Ctx -> PubKey -> PsbtMap -> PsbtMap
insertInputTapInternalKey = insertXOnlyKeyField inTapInternalKeyType

-- | The root of the script tree of the Taproot coin an input spends:
-- PSBT_IN_TAP_MERKLE_ROOT
inputTapMerkleRoot :: PsbtMap -> Either String (Maybe (Digest SHA256))
inputTapMerkleRoot = optionalField "The Merkle root" tapMerkleRootType (maybe (Left "is not a 32-byte hash") Right . digestOf)

insertInputTapMerkleRoot :: Digest SHA256 -> PsbtMap -> PsbtMap
insertInputTapMerkleRoot = insertPlainField tapMerkleRootType . BA.convert

-- | The internal key of a Taproot output: PSBT_OUT_TAP_INTERNAL_KEY
outputTapInternalKey :: Ctx -> PsbtMap -> Either String (Maybe PubKey)
outputTapInternalKey = xOnlyKeyField outTapInternalKeyType "The internal key"

insertOutputTapInternalKey :: Ctx -> PubKey -> PsbtMap -> PsbtMap
insertOutputTapInternalKey = insertXOnlyKeyField outTapInternalKeyType

-- | The script tree of a Taproot output, as its leaves depth first:
-- PSBT_OUT_TAP_TREE. 'tapTreeFromLeaves' builds the tree.
outputTapTree :: PsbtMap -> Either String (Maybe [TapLeaf])
outputTapTree = optionalField "The script tree" outTapTreeType decodeTapTree

insertOutputTapTree :: [TapLeaf] -> PsbtMap -> PsbtMap
insertOutputTapTree leaves = insertPlainField outTapTreeType (B.concat (encodeLeaf <$> leaves))
  where
    encodeLeaf :: TapLeaf -> ByteString
    encodeLeaf leaf = B.pack [leaf.depth, leaf.version] <> sized (S.encode leaf.script)

-- | A script tree: for each leaf, its depth, its leaf version and its
-- script after its length
decodeTapTree :: ByteString -> Either String [TapLeaf]
decodeTapTree = parseAll leaves "a script tree"
  where
    leaves = do
      rest <- restOf
      if B.null rest
        then return []
        else do
          BytesParser (\_ -> Right ((), rest)) -- put the bytes back
          depth <- B.head <$> bytesOf 1 "a script tree"
          version <- B.head <$> bytesOf 1 "a script tree"
          scriptBytes <- sizedBytes "a script tree"
          script <- either refuse return (decodeScript scriptBytes)
          (TapLeaf depth version script :) <$> leaves

-- | A 32-byte hash as a digest
digestOf :: ByteString -> Maybe (Digest SHA256)
digestOf = digestFromByteString

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

-- | Where a signer gets its private keys: by a derivation record naming a
-- public key, or by the hash of a public key when the input has no record
-- for it. A key that is not held is 'Nothing'. The signer also says which
-- sighash types it agrees to sign with, and whether it wants the previous
-- transaction of a SegWit version 0 coin.
data Signer = Signer
  { -- | the private key of the public key a derivation record names
    keyOfRecord :: PublicKey -> Derivation -> Maybe SecKey,
    -- | the private key whose public key, compressed or not, has the hash
    keyOfHash :: Hash160 -> Maybe PrivateKey,
    -- | the sighash types the signer signs with. An input that asks for
    -- another type is refused, as BIP 174 asks of a signer. The fork id
    -- flag does not count, since the network decides it.
    acceptedSigHashes :: [SigHash],
    -- | whether a SegWit version 0 coin (P2WPKH or P2WSH, nested in P2SH
    -- or not) is signed only when the input carries its previous
    -- transaction. A BIP 143 signature commits to the amount of its own
    -- coin and to no other. With the witness output alone, whoever writes
    -- the PSBT can lie about the amount of one coin of the signer in each
    -- of two signing rounds, keep the valid signature of each round, and
    -- make a transaction that pays the difference as fee
    -- (CVE-2020-14199). BIP 174 lets a signer "fail to sign a segwit
    -- input if a non-witness UTXO is not provided" for this reason. A
    -- Taproot signature commits to the amount of every coin and needs no
    -- such care.
    requirePreviousTx :: Bool
  }

-- | The sighash types a signer accepts unless told otherwise:
-- 'sigHashDefault', which a Taproot input uses when it asks for none, and
-- 'sigHashAll'. The other types leave part of the transaction out of the
-- signature, so a PSBT written by someone else may not ask for them on its
-- own; a signer that agrees to them lists them, for example
-- @(keySigner ctx key) {acceptedSigHashes = sigHashNone : defaultSigHashes}@.
defaultSigHashes :: [SigHash]
defaultSigHashes = [sigHashDefault, sigHashAll]

-- | Whether the signer accepts the sighash type: it is one of its types,
-- the fork id flag aside
acceptsSigHash :: Signer -> SigHash -> Bool
acceptsSigHash signer sighash =
  withoutForkId sighash `elem` map withoutForkId signer.acceptedSigHashes
  where
    withoutForkId = (.&. complement forkIdBit)
    forkIdBit = fromIntegral (fromEnum SIGHASH_FORKID)

-- | A signer that holds one private key, for the records of its public
-- key and for the hash of its public key in either form. It wants the
-- previous transaction of a SegWit version 0 coin ('requirePreviousTx').
-- A caller that has checked the amounts of its coins another way, for
-- example against its own records, turns that off with
-- @(keySigner ctx key) {requirePreviousTx = False}@.
keySigner :: Ctx -> SecKey -> Signer
keySigner ctx secret =
  Signer
    { keyOfRecord = \public _ -> do
        guard (public.point == derivePubKey ctx secret)
        return secret,
      keyOfHash = \h -> find ((== h) . addressHash . marshal ctx . derivePublicKey ctx) [PrivateKey secret True, PrivateKey secret False],
      acceptedSigHashes = defaultSigHashes,
      requirePreviousTx = True
    }

-- | A signer that derives from an extended private key. A record names a
-- key it derives by the fingerprint of the extended key and the path from
-- it, or, when the origin of the extended key is given, by the
-- fingerprint of that origin and the path from it, which starts with the
-- path of the extended key. A path the key cannot follow, such as one
-- deeper than the 255 levels of BIP 32 or one with a hardened step
-- below a key that cannot derive it, names no key. It has no key for a
-- hash, since it cannot know which path to derive. Like 'keySigner', it
-- wants the previous transaction of a SegWit version 0 coin.
xPrvSigner :: Ctx -> XPrvKey -> Maybe Derivation -> Signer
xPrvSigner ctx xprv originM =
  Signer
    { keyOfRecord = \public derivation -> do
        path <- relative derivation
        secret <- (.key) <$> eitherToMaybe (tryDerivePath ctx path xprv)
        guard (public.point == derivePubKey ctx secret)
        return secret,
      keyOfHash = const Nothing,
      acceptedSigHashes = defaultSigHashes,
      requirePreviousTx = True
    }
  where
    own = xPubFP ctx (deriveXPubKey ctx xprv)
    relative :: Derivation -> Maybe DerivPath
    relative derivation
      | derivation.fingerprint == own = Just derivation.path
      | Just origin <- originM, derivation.fingerprint == origin.fingerprint =
          listToPath <$> stripPrefix (pathToList origin.path) (pathToList derivation.path)
      | otherwise = Nothing

-- | Sign every input the signer has keys for, as the signer of the spec
-- does. An input is signed against the coin it spends, from its previous
-- transaction, whose id must be the one the input spends, or from its
-- witness output alone, which only a witness signature may use, as BIP
-- 174 requires.
--
-- The keys are those the script that is signed names: the script of the
-- coin, its redeem script or its witness script. The signer is asked for
-- the key of a derivation record only when that script names the key of
-- the record, and for the key of each hash the script names. A key that
-- the script does not name gets no signature, whatever the records say,
-- and a P2SH coin without its redeem script or a P2WSH coin without its
-- witness script gets none either, as BIP 174 has it: "If a Signer cannot
-- sign a transaction, it must not add a Partial Signature."
--
-- The sighash is the one the input asks for. When it asks for none it is
-- SIGHASH_ALL, with the fork id flag on a network that has one. A type no
-- node accepts, or one the signer does not accept ('acceptedSigHashes'),
-- is refused on any input that has its coin, as Bitcoin Core refuses a
-- PSBT with a sighash type the caller did not ask for.
--
-- An input the signer holds a key for is refused, with the reason, when:
--
-- * its redeem script does not hash to the coin, or its witness script to
--   the witness program;
-- * it is a legacy coin known from its witness output only;
-- * it is a SegWit version 0 coin known from its witness output only and
--   the signer wants the previous transaction ('requirePreviousTx');
-- * the key is uncompressed and the coin is a SegWit version 0 one, which
--   no node relays and Bitcoin Core does not sign;
-- * it is a legacy coin asked to sign SIGHASH_SINGLE with no output at its
--   index, as 'makeSignature' explains.
--
-- A Taproot coin is signed by its key path when the input has its internal
-- key, which with the Merkle root must give the output key, and by each of
-- its leaf scripts that is a single key check (@<key> OP_CHECKSIG@) and
-- that its control block commits to the output key, with 'sigHashDefault'
-- when the input asks for no sighash. The BIP 341 digest commits to the
-- output every input spends, so every input must have its coin then.
--
-- An input without its coin, with a final script already, with a coin,
-- redeem script or witness script that is no standard template, or for
-- which the signer holds no key, is left as it is.
signPsbt :: Network -> Ctx -> Signer -> Psbt -> Either String Psbt
signPsbt net ctx signer psbt = do
  coins <- spentOutputs psbt
  let allCoins = mapM (fmap fst) coins
  signed <- forM (zip3 [0 ..] (zip tx.inputs psbt.inputs) coins) $ \(i, (input, m), coinM) ->
    first (("Input " <> show i <> ": ") <>) $ case coinM of
      Just (coin, witnessOnly)
        | not (isFinal m),
          Right coinScript <- unmarshal ctx coin.script -> do
            sighashM <- sigHashType m
            if isTaprootCoin coinScript
              then signTaproot i m coinScript sighashM allCoins
              else signEcdsa i input m coin coinScript witnessOnly sighashM
      _ -> return (m, [])
  return $ foldr afterSignature (Psbt psbt.version tx psbt.globals (fst <$> signed) psbt.outputs) (concatMap snd signed)
  where
    tx = psbt.unsignedTx

    -- A signature per key the signer holds among those the script names,
    -- for a coin signed with ECDSA
    signEcdsa i input m coin coinScript witnessOnly sighashM = do
      let sighash = fromMaybe (defaultEcdsaSigHash net) sighashM
      checkEcdsaSigHash net sighash
      unless (acceptsSigHash signer sighash) $
        Left (notAcceptedSigHash sighash)
      scriptsM <- inputScripts ctx coinScript m
      case scriptsM of
        Nothing -> return (m, [])
        Just scripts -> do
          keys <- heldKeys m (maybe [] (scriptKeyHashes ctx) scripts.signedScript)
          if null keys
            then return (m, [])
            else do
              forM_ scripts.mismatch Left
              let witnessCoin = isSegwit scripts.program
              when (witnessOnly && not witnessCoin) $
                Left "the coin is given as a witness output only, which may not be signed with a non-witness signature"
              when (witnessOnly && witnessCoin && signer.requirePreviousTx) $
                Left "the coin is given as a witness output only, and the signer requires the previous transaction of a SegWit version 0 coin"
              when (witnessCoin && not (all (.compress) keys)) $
                Left "a SegWit version 0 coin may not be signed with an uncompressed key"
              let sigInput = signingInput input coin sighash scripts
              signatures <- forM keys $ \key -> do
                signature <- makeSignature net ctx tx i sigInput key
                return (derivePublicKey ctx key, encodeTxSig net ctx signature)
              return (foldr (\(public, sig) -> insertPartialSignature ctx public sig) m signatures, [sighash])

    -- The keys the signer holds among those whose hashes the script that
    -- is signed names. The signer is asked for the key of a derivation
    -- record only when the hash of the key of the record is one of them,
    -- so the work it does is bounded by the script, however many records
    -- the PSBT carries. A key the signer gives is kept only when it is the
    -- key that was asked for.
    heldKeys :: PsbtMap -> [Hash160] -> Either String [PrivateKey]
    heldKeys m named = do
      let namedRecords = [(key, value) | (key, value) <- Map.toAscList m, key.keyType == inDerivationType, addressHash key.keyData `elem` named]
      recordKeys <- forM namedRecords $ \(key, value) -> do
        public <- first (const ("The key " <> showKey key <> " is not a public key")) (unmarshal ctx key.keyData)
        derivation <- first (("The value of the key " <> showKey key <> " ") <>) (decodeDerivation value)
        return [PrivateKey secret public.compress | Just secret <- [signer.keyOfRecord public derivation], derivePubKey ctx secret == public.point]
      let hashKeys = [key | h <- named, Just key <- [signer.keyOfHash h], addressHash (marshal ctx (derivePublicKey ctx key)) == h]
      return $ nubBy (\a b -> derivePublicKey ctx a == derivePublicKey ctx b) (concat recordKeys <> hashKeys)

    -- A key path signature, and one per leaf that is a single key check,
    -- for a Taproot coin
    signTaproot i m coinScript sighashM allCoins = do
      let sighash = fromMaybe sigHashDefault sighashM
      unless (isTaprootSigHash sighash) $
        Left ("the sighash type " <> show (fromIntegral sighash :: Word32) <> " is not one a Taproot signature may use")
      unless (acceptsSigHash signer sighash) $
        Left (notAcceptedSigHash sighash)
      spent <- maybe (Left "a Taproot signature needs the output every input spends") Right allCoins
      program <- taprootProgram coinScript
      internalM <- inputTapInternalKey ctx m
      rootM <- inputTapMerkleRoot m
      records <- inputTapDerivations ctx m
      leaves <- tapLeafScripts ctx m
      -- The secret key of an x-only key, by a record of that key which
      -- the test accepts, or by the hash of the key. A key the signer
      -- gives is kept only when it is the key that was asked for.
      let heldXOnly accepts public =
            listToMaybe . filter (sameX public . derivePubKey ctx) . catMaybes $
              [signer.keyOfRecord (PublicKey candidate True) d.derivation | (recordKey, d) <- records, sameX recordKey public, accepts d, candidate <- bothParities public]
                <> [(.key) <$> signer.keyOfHash (addressHash (marshal ctx (PublicKey candidate True))) | candidate <- bothParities public]
      keySig <- case internalM of
        Nothing -> return []
        Just internal -> do
          let expected = taprootOutputKey ctx (TaprootOutput internal (MASTCommitment <$> rootM))
          unless (exportXOnlyPubKey ctx expected == program) $
            Left "the internal key and the Merkle root do not give the output key of the coin"
          -- Any record of the internal key will do: BIP 371 lists in a
          -- record the leaves the key is in, and the internal key may be
          -- in a leaf too
          case heldXOnly (const True) internal of
            Nothing -> return []
            Just secret -> do
              tweaked <- maybe (Left "the key cannot be tweaked") Right (taprootOutputSecKey ctx secret (MASTCommitment <$> rootM))
              h <- taprootSigHash tx spent i sighash Nothing Nothing
              signature <- taprootSignature (signSchnorr ctx tweaked (hashToMsg h)) sighash
              return [insertTapKeySig signature]
      scriptSigs <- fmap concat . forM leaves $ \leaf -> case singleKeyLeaf ctx leaf of
        Just leafKey
          -- Only a leaf of the coin is signed: its control block must
          -- commit it to the output key
          | Just outKey <- importXOnlyPubKey ctx program,
            commitsLeaf ctx outKey leaf,
            Just secret <- heldXOnly ((hashOfLeaf `elem`) . (.leafHashes)) leafKey -> do
              h <- taprootSigHash tx spent i sighash Nothing (Just (hashOfLeaf, 0xffffffff))
              signature <- taprootSignature (signSchnorr ctx secret (hashToMsg h)) sighash
              return [insertTapScriptSig ctx leafKey hashOfLeaf signature]
          where
            hashOfLeaf = leafHash leaf.leafVersion leaf.script
        _ -> return []
      let inserts = keySig <> scriptSigs
      return (foldr ($) m inserts, [sighash | not (null inserts)])

    sameX a b = exportXOnlyPubKey ctx a == exportXOnlyPubKey ctx b
    -- The two points with the x coordinate of the key
    bothParities public =
      mapMaybe (\prefix -> (.point) <$> eitherToMaybe (unmarshal ctx (B.cons prefix (exportXOnlyPubKey ctx public)) :: Either String PublicKey)) [0x02, 0x03]

-- | The sighash type of an ECDSA signature for an input that asks for
-- none: SIGHASH_ALL, with the fork id flag on a network that has one
defaultEcdsaSigHash :: Network -> SigHash
defaultEcdsaSigHash net
  | isJust net.sigHashForkId = setForkIdFlag sigHashAll
  | otherwise = sigHashAll

-- | The hashes of the keys a script names: the keys a coin of that script
-- is signed with
scriptKeyHashes :: Ctx -> ScriptOutput -> [Hash160]
scriptKeyHashes ctx = \case
  PayPK public -> [addressHash (marshal ctx public)]
  PayPKHash h -> [h]
  PayWitnessPKHash h -> [h]
  PayMulSig publics _ -> map (addressHash . marshal ctx) publics
  _ -> []

-- | The leaf key of a leaf script that is a single key check, @<key>
-- OP_CHECKSIG@ of leaf version 0xc0
singleKeyLeaf :: Ctx -> TapLeafScript -> Maybe PubKey
singleKeyLeaf ctx leaf = case leaf.script.ops of
  [OP_PUSHDATA keyBytes OPCODE, OP_CHECKSIG]
    | leaf.leafVersion == tapscriptLeafVersion -> importXOnlyPubKey ctx keyBytes
  _ -> Nothing

-- | Whether the control block of a leaf script commits the leaf to the
-- output key of the coin
commitsLeaf :: Ctx -> PubKey -> TapLeafScript -> Bool
commitsLeaf ctx outKey leaf = case decodeControlBlock ctx leaf.controlBlock of
  Right (v, internalKey, proof) ->
    verifyScriptPathData ctx outKey (ScriptPathData Nothing [] leaf.script (odd v) (v .&. 0xfe) internalKey proof Nothing)
  Left _ -> False

-- | The error for a sighash type the signer does not accept
notAcceptedSigHash :: SigHash -> String
notAcceptedSigHash sighash =
  "the sighash type " <> show (fromIntegral sighash :: Word32) <> " is not one the signer accepts"

-- | A sighash type an ECDSA signature may carry on the network: one of
-- ALL, NONE and SINGLE, with ANYONECANPAY or not, and the fork id flag
-- exactly on the networks with a fork id
checkEcdsaSigHash :: Network -> SigHash -> Either String ()
checkEcdsaSigHash net sighash = do
  when (isSigHashUnknown sighash) $
    Left ("the sighash type " <> show (fromIntegral sighash :: Word32) <> " is not one a node accepts")
  when (isJust net.sigHashForkId && not (hasForkIdFlag sighash)) $
    Left "the sighash type lacks the fork id flag the network requires"
  when (isNothing net.sigHashForkId && hasForkIdFlag sighash) $
    Left "the sighash type has a fork id flag the network does not use"

-- | Whether a coin is a Taproot output, and its program
isTaprootCoin :: ScriptOutput -> Bool
isTaprootCoin = either (const False) (const True) . taprootProgram

taprootProgram :: ScriptOutput -> Either String ByteString
taprootProgram = \case
  PayWitness 1 program | B.length program == 32 -> Right program
  _ -> Left "not a Taproot output"

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

{- The coins of a PSBT -}

-- | The coin an input of a PSBT spends, as the PSBT gives it
data InputCoin = InputCoin
  { -- | the output the input spends: its amount and its script
    coin :: !TxOut,
    -- | 'True' when the coin is the output of the previous transaction of
    -- the input, whose id the input names, so that it cannot be made up.
    -- 'False' when the PSBT gives the output alone (PSBT_IN_WITNESS_UTXO):
    -- its amount is then a claim of whoever wrote the PSBT.
    fromPreviousTx :: !Bool
  }
  deriving (Eq, Show, Read, Generic)
  deriving anyclass (NFData)

-- | The coin every input of a PSBT spends, 'Nothing' for an input that
-- carries none. A previous transaction must be the one its input spends
-- and have the output it spends, and a witness output given with it must
-- be that output.
--
-- An amount with 'fromPreviousTx' is checked. Another is only checked by a
-- signature that commits to it: a SegWit version 0 signature commits to
-- the amount of its own coin, and a Taproot signature to the amount of
-- every coin of the transaction. Show a user amounts and a fee from
-- checked coins only, or from a PSBT in which the user signs a Taproot
-- input.
inputCoins :: Psbt -> Either String [Maybe InputCoin]
inputCoins psbt = map (fmap (\(output, witnessOnly) -> InputCoin output (not witnessOnly))) <$> spentOutputs psbt

-- | The fee of the transaction of a PSBT: what its coins hold above what
-- its outputs pay. Every input must carry its previous transaction, so
-- that no amount is a claim ('inputCoins' tells which are). A PSBT whose
-- outputs pay more than its coins hold has no fee.
psbtFee :: Psbt -> Either String Word64
psbtFee psbt = do
  coins <- inputCoins psbt
  amounts <- forM (zip [0 :: Int ..] coins) $ \(i, coinM) -> case coinM of
    Nothing -> Left ("Input " <> show i <> " has no coin")
    Just found
      | found.fromPreviousTx -> Right (toInteger found.coin.value)
      | otherwise -> Left ("Input " <> show i <> ": the coin is given as a witness output only, so its amount is not checked")
  let fee = sum amounts - sum (toInteger . (.value) <$> psbt.unsignedTx.outputs)
  when (fee < 0) $ Left "The outputs pay more than the coins hold"
  return (fromInteger fee)

-- | The output every input spends, from the fields of each input, and
-- whether it is known from the witness output alone
spentOutputs :: Psbt -> Either String [Maybe (TxOut, Bool)]
spentOutputs psbt =
  forM (zip3 [0 :: Int ..] psbt.unsignedTx.inputs psbt.inputs) $ \(i, input, m) ->
    first (("Input " <> show i <> ": ") <>) (spentOutput input m)

-- | The output an input spends, from the fields of the input: the output
-- of its previous transaction, which must be the transaction the input
-- spends from, or else its witness output alone. With both, the witness
-- output must be that output. The flag tells when the witness output
-- alone is known, which only a witness signature may rely on.
spentOutput :: TxIn -> PsbtMap -> Either String (Maybe (TxOut, Bool))
spentOutput input m = do
  witnessM <- witnessUtxo m
  parentM <- nonWitnessUtxo m
  case (parentM, witnessM) of
    (Just parent, _) -> do
      output <- previousOutput input parent
      forM_ witnessM $ \witnessCoin ->
        unless (witnessCoin == output) $
          Left "the witness output of the input is not the output of its previous transaction"
      return (Just (output, False))
    (Nothing, Just output) -> return (Just (output, True))
    (Nothing, Nothing) -> return Nothing

-- | What the scripts of an input say about how its coin is signed
data InputScripts = InputScripts
  { -- | the script the coin is signed against: the script of the coin, or
    -- the witness program its redeem script is when it is nested in P2SH
    program :: ScriptOutput,
    -- | the script that names the keys: the script of the coin, its
    -- redeem script or its witness script. 'Nothing' when the input does
    -- not have the redeem or witness script its coin needs.
    signedScript :: Maybe ScriptOutput,
    -- | why a redeem or witness script of the input does not fit its coin
    mismatch :: Maybe String
  }

-- | The scripts of an input, from the script of its coin and its redeem
-- and witness scripts. A redeem script must hash to the coin, and a
-- witness script to the witness program, as BIP 174 requires of a signer:
-- one that does not is reported in 'mismatch'. 'Nothing' when the script
-- that names the keys is no standard template: the library cannot sign or
-- finalize such an input, and leaves it to others.
inputScripts :: Ctx -> ScriptOutput -> PsbtMap -> Either String (Maybe InputScripts)
inputScripts ctx coinScript m = do
  redeemM <- inputRedeemScript m
  witnessM <- inputWitnessScript m
  let redeemOutM = decodeOutput ctx <$> redeemM
      witnessOutM = decodeOutput ctx <$> witnessM
      -- A SegWit coin, nested in P2SH or not, is signed against its witness
      -- program; any other against its own script
      program = case redeemOutM of
        Just (Right redeem) | not (isSegwit coinScript), isSegwit redeem -> redeem
        _ -> coinScript
      redeemMismatch = case redeemM of
        Just redeem
          | not (isPayScriptHash coinScript) -> Just "the input has a redeem script, but its coin is not pay-to-script-hash"
          | toP2SH redeem /= Right coinScript -> Just "the redeem script of the input does not hash to its coin"
        _ -> Nothing
      witnessMismatch = case witnessM of
        Just witness
          | not (isPayWitnessScriptHash program) -> Just "the input has a witness script, but its coin is not pay-to-witness-script-hash"
          | toP2WSH witness /= Right program -> Just "the witness script of the input does not hash to its witness program"
        _ -> Nothing
      -- The script that names the keys, as it decodes
      naming = case program of
        PayWitnessScriptHash _ -> witnessOutM
        PayScriptHash _ -> redeemOutM
        _ -> Just (Right program)
  return $ case naming of
    Just (Left _) -> Nothing
    _ ->
      Just
        InputScripts
          { program = program,
            signedScript = naming >>= eitherToMaybe,
            mismatch = listToMaybe (catMaybes [redeemMismatch, witnessMismatch])
          }

-- | What an input is signed against, as 'makeSignature' wants it: the
-- script of its coin or its witness program, with the redeem script of a
-- P2SH coin or the witness script of a P2WSH coin
signingInput :: TxIn -> TxOut -> SigHash -> InputScripts -> SigInput
signingInput input output sighash scripts =
  SigInput
    { script = scripts.program,
      value = output.value,
      outpoint = input.outpoint,
      sighash = sighash,
      redeem = case scripts.program of
        PayWitnessScriptHash _ -> scripts.signedScript
        PayScriptHash _ -> scripts.signedScript
        _ -> Nothing
    }

{- Finalizing -}

-- | Finalize every input whose signatures suffice for the coin it spends,
-- as the finalizer of the spec does: the final script and witness go in
-- the input, and its partial signatures, sighash type, redeem script,
-- witness script, derivation records and Taproot fields go, as Bitcoin
-- Core clears them. Its coin and the keys the spec does not define stay.
--
-- Only the signatures of the keys the script of the coin names are
-- looked at. Each one is verified first, against the digest of the coin,
-- which is computed once per sighash type. A signature that does not
-- verify, or is of an uncompressed key on a SegWit version 0 coin, is
-- refused, as @PSBTInputSignedAndVerified@ and the standard script flags
-- refuse it in Bitcoin Core. Every signature of the input must use the
-- sighash type the input names, and SIGHASH_ALL when it names none
-- (SIGHASH_DEFAULT for a Taproot coin, and with the fork id flag on a
-- network that has one), as Bitcoin Core requires.
--
-- The coins finalized are those of P2PK, P2PKH and multisig scripts, P2SH
-- coins with their redeem script, P2WPKH coins, P2WSH coins with their
-- witness script, nested in P2SH or not, and Taproot coins by their key
-- path signature or by a leaf script that is a single key check. Any
-- other input stays as it is: one without enough signatures, one whose
-- scripts are no standard template, and a legacy coin known from its
-- witness output only, which Bitcoin Core does not finalize either.
finalizePsbt :: Network -> Ctx -> Psbt -> Either String Psbt
finalizePsbt net ctx psbt = do
  coins <- spentOutputs psbt
  let allCoins = mapM (fmap fst) coins
  inputs <- forM (zip3 [0 ..] (zip tx.inputs psbt.inputs) coins) $ \(i, (input, m), coinM) ->
    first (("Input " <> show i <> ": ") <>) $ case coinM of
      Just (output :: TxOut, witnessOnly)
        | not (isFinal m),
          Right coinScript <- unmarshal ctx output.script -> do
            finals <-
              if isTaprootCoin coinScript
                then finalTaprootScripts ctx tx allCoins i m coinScript
                else finalScripts net ctx tx i input output witnessOnly coinScript m
            return $ case finals of
              Just (scriptSig, stack) ->
                foldr ($) (cleared m) $
                  [insertFinalScriptSig scriptSig | not (B.null scriptSig)]
                    <> [insertFinalScriptWitness stack | not (null stack)]
              Nothing -> m
      _ -> return m
  return $ Psbt psbt.version tx psbt.globals inputs psbt.outputs
  where
    tx = psbt.unsignedTx
    cleared = Map.filterWithKey (\key _ -> key.keyType `notElem` clearedTypes)
    clearedTypes =
      [partialSigType, sigHashTypeType, inRedeemScriptType, inWitnessScriptType, inDerivationType, tapKeySigType, tapScriptSigType, tapLeafScriptType, inTapDerivationType, inTapInternalKeyType, tapMerkleRootType]

-- | The final script and witness of an input signed with ECDSA, from the
-- partial signatures of the keys its script names, when they suffice.
-- Each of those signatures is verified first.
finalScripts :: Network -> Ctx -> Tx -> Int -> TxIn -> TxOut -> Bool -> ScriptOutput -> PsbtMap -> Either String (Maybe (ByteString, WitnessStack))
finalScripts net ctx tx i input output witnessOnly coinScript m = do
  sighashM <- sigHashType m
  scriptsM <- inputScripts ctx coinScript m
  case scriptsM of
    Nothing -> return Nothing
    Just scripts
      -- Only a witness signature may rely on a witness output
      | witnessOnly && not (isSegwit scripts.program) -> return Nothing
      | otherwise -> do
          forM_ scripts.mismatch Left
          let asked = fromMaybe (defaultEcdsaSigHash net) sighashM
              otherType keyBytes =
                Left $
                  "the signature of the key " <> quoted keyBytes <> case sighashM of
                    Just _ -> " does not use the sighash type of the input"
                    Nothing -> " does not use SIGHASH_ALL, and the input names no sighash type"
              sigInput = signingInput input output asked scripts
              named = maybe [] (namedSignatures ctx m) scripts.signedScript
          -- The signatures of the keys the script names: each is a
          -- signature, of the sighash type asked, by a key the coin may be
          -- spent with
          checked <- forM named $ \(public, bytes) -> do
            (sig, sh) <- case decodeTxSig net ctx bytes of
              Right (TxSignature sig sh) -> return (sig, sh)
              _ -> Left ("the signature of the key " <> quoted (marshal ctx public) <> " is not a valid signature")
            unless (sh == asked) $ otherType (marshal ctx public)
            when (isSegwit scripts.program && not public.compress) $
              Left ("the signature of the key " <> quoted (marshal ctx public) <> " is of an uncompressed key, which a SegWit version 0 coin may not be spent with")
            return (public, sig)
          -- Every other signature of the input uses that sighash type too:
          -- its last byte tells, and nothing else of it is looked at
          forM_ [(key, sig) | (key, sig) <- Map.toAscList m, key.keyType == partialSigType] $ \(key, sig) ->
            unless (not (B.null sig) && B.last sig == fromIntegral (asked .&. 0xff)) $ otherType key.keyData
          if null checked
            then return Nothing
            else do
              -- One digest serves every signature, since all use one type
              digest <- makeSigHash net ctx tx i sigInput.script output.value asked sigInput.redeem
              forM_ checked $ \(public, sig) ->
                unless (verifyHashSig ctx digest sig public.point) $
                  Left ("the signature of the key " <> quoted (marshal ctx public) <> " does not verify")
              return (assemble scripts named)
  where
    quoted = show . encodeHex
    -- The final script and witness, from the signatures of the keys the
    -- script names
    assemble :: InputScripts -> [(PublicKey, ByteString)] -> Maybe (ByteString, WitnessStack)
    assemble scripts named = case coinScript of
      PayScriptHash _ -> do
        redeem <- either (const Nothing) id (inputRedeemScript m)
        if isSegwit scripts.program
          then (scriptOf [S.encode redeem],) <$> witnessOf scripts named
          else (\found -> (scriptOf (found <> [S.encode redeem]), [])) <$> (items named =<< scripts.signedScript)
      _
        | isSegwit coinScript -> (B.empty,) <$> witnessOf scripts named
        | otherwise -> (\found -> (scriptOf found, [])) <$> (items named =<< scripts.signedScript)
    -- The witness of a SegWit coin: the items of its program, with the
    -- witness script last for P2WSH
    witnessOf :: InputScripts -> [(PublicKey, ByteString)] -> Maybe [ByteString]
    witnessOf scripts named = case scripts.program of
      PayWitnessScriptHash _ -> do
        witnessScript <- either (const Nothing) id (inputWitnessScript m)
        (<> [S.encode witnessScript]) <$> (items named =<< scripts.signedScript)
      _ -> items named =<< scripts.signedScript
    -- The items a script is spent with: the pushes of an input script,
    -- or the items of a witness
    items :: [(PublicKey, ByteString)] -> ScriptOutput -> Maybe [ByteString]
    items named = \case
      PayPK public -> (: []) <$> lookup public named
      PayPKHash h -> withKey <$> ofHash named h
      PayMulSig keys n -> (B.empty :) <$> enough named keys n
      PayWitnessPKHash h -> withKey <$> ofHash named h
      _ -> Nothing
    ofHash :: [(PublicKey, ByteString)] -> Hash160 -> Maybe (PublicKey, ByteString)
    ofHash named h = listToMaybe [(public, signature) | (public, signature) <- named, addressHash (marshal ctx public) == h]
    enough :: [(PublicKey, ByteString)] -> [PublicKey] -> Int -> Maybe [ByteString]
    enough named keys n = let found = mapMaybe (`lookup` named) keys in if length found >= n then Just (take n found) else Nothing
    withKey :: (PublicKey, ByteString) -> [ByteString]
    withKey (public, signature) = [signature, marshal ctx public]
    scriptOf = S.encode . Script . map opPushData

-- | The partial signatures of an input whose keys the script names, in
-- the order of the map. A key is named by a script of public keys when it
-- is one of them, and by a script of a key hash when it has that hash.
-- The others are not looked at, so their number costs nothing.
namedSignatures :: Ctx -> PsbtMap -> ScriptOutput -> [(PublicKey, ByteString)]
namedSignatures ctx m script =
  [ (public, sig)
  | (key, sig) <- Map.toAscList m,
    key.keyType == partialSigType,
    addressHash key.keyData `elem` named,
    Right public <- [unmarshal ctx key.keyData]
  ]
  where
    named = scriptKeyHashes ctx script

-- | The final witness of a Taproot input: its key path signature, or the
-- signature of the first leaf script that is a single key check with the
-- script and its control block. Every signature is verified first,
-- against the output key and the digest of its leaf. A signature must
-- use the sighash type the input names, and SIGHASH_DEFAULT when it names
-- none, as Bitcoin Core requires.
finalTaprootScripts :: Ctx -> Tx -> Maybe [TxOut] -> Int -> PsbtMap -> ScriptOutput -> Either String (Maybe (ByteString, WitnessStack))
finalTaprootScripts ctx tx allCoins i m coinScript = do
  program <- taprootProgram coinScript
  outKey <- maybe (Left "the coin is not a Taproot output") Right (importXOnlyPubKey ctx program)
  sighashM <- sigHashType m
  keySigM <- tapKeySig m
  scriptSigs <- tapScriptSigs ctx m
  leaves <- tapLeafScripts ctx m
  let sameType :: TaprootSignature -> Either String ()
      sameType signature = case sighashM of
        Just asked -> unless (signature.hash == asked) $ Left "a Taproot signature does not use the sighash type of the input"
        Nothing -> unless (signature.hash == sigHashDefault) $ Left "a Taproot signature does not use SIGHASH_DEFAULT, and the input names no sighash type"
  -- Every signature of the input, used or not, as Bitcoin Core checks them
  mapM_ sameType (maybeToList keySigM <> map snd scriptSigs)
  case keySigM of
    Just signature -> do
      spent <- maybe (Left "a Taproot signature needs the output every input spends") Right allCoins
      digest <- taprootSigHash tx spent i signature.hash Nothing Nothing
      unless (verifySchnorr ctx outKey signature.sig (hashToMsg digest)) $
        Left "the key path signature does not verify"
      return (Just (B.empty, [encodeTaprootSig signature]))
    Nothing -> do
      let candidates =
            [ (leaf, leafKey, signature)
            | leaf <- leaves,
              Just leafKey <- [singleKeyLeaf ctx leaf],
              Just signature <- [lookup (leafKey, leafHash leaf.leafVersion leaf.script) [((k, h), sig) | ((k, h), sig) <- scriptSigs, sameX k leafKey]]
            ]
      case candidates of
        [] -> return Nothing
        (leaf, leafKey, signature) : _ -> do
          spent <- maybe (Left "a Taproot signature needs the output every input spends") Right allCoins
          unless (commitsLeaf ctx outKey leaf) $
            Left "the control block of the leaf does not commit it to the output key"
          digest <- taprootSigHash tx spent i signature.hash Nothing (Just (leafHash leaf.leafVersion leaf.script, 0xffffffff))
          unless (verifySchnorr ctx leafKey signature.sig (hashToMsg digest)) $
            Left "the script path signature does not verify"
          return (Just (B.empty, [encodeTaprootSig signature, S.encode leaf.script, leaf.controlBlock]))
  where
    sameX a b = exportXOnlyPubKey ctx a == exportXOnlyPubKey ctx b
