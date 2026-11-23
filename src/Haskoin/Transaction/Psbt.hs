{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
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
-- __The order of the rules.__ Where the BIPs decide, the module does what
-- they say. Where they are silent or leave a choice open, it does what
-- Bitcoin Core does, checked against Bitcoin Core 32.1 on regtest. Where
-- neither decides, it takes the safer choice for the user. The few places
-- where it does not do as Bitcoin Core are named where they are: in
-- 'decodePsbt', 'signPsbt', 'finalizePsbt', 'combinePsbt' and
-- 'psbtTransaction'.
--
-- The maps are kept as they are read, byte for byte, so that every field
-- passes through, known or not. A map is written with its keys in the
-- order of their bytes, the type first. BIP 174 fixes no order, and
-- Bitcoin Core writes another one, so the two write the same PSBT with
-- other bytes, and each reads the bytes of the other. 'decodePsbt' tells
-- what is refused when a PSBT is read.
--
-- The signer and the finalizer take one input at a time, as Bitcoin Core
-- does: an input that cannot be signed or finalized stays as it is, and
-- the others go on. 'signPsbt' and 'finalizePsbt' give the rules.
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
-- The hash preimages of BIP 174 and the MuSig2 fields of
-- [BIP 373](https://github.com/bitcoin/bips/blob/master/bip-0373.mediawiki)
-- are checked when a PSBT is read, and kept: the module does not sign with
-- them.
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

import Control.Applicative ((<|>))
import Control.DeepSeq (NFData)
import Control.Monad (ap, forM, forM_, guard, mfilter, replicateM, unless, when, zipWithM)
import Crypto.Hash (Digest, SHA256, digestFromByteString)
import Crypto.Secp256k1 (PubKey, SecKey, derivePubKey, exportXOnlyPubKey, importPubKey, importXOnlyPubKey, signSchnorr, verifySchnorr)
import Data.Base64.Types (extractBase64)
import Data.Bifunctor (first)
import Data.Bits (complement, shiftL, testBit, (.&.), (.|.))
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Base64 (decodeBase64Untyped, encodeBase64')
import Data.Char (toUpper)
import Data.List (find, minimumBy, nubBy, stripPrefix)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Maybe (catMaybes, fromMaybe, isJust, isNothing, listToMaybe, mapMaybe, maybeToList)
import Data.Ord (comparing)
import Data.Serialize qualified as S
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Crypto.Hash (Hash160, addressHash, doubleSHA256, ripemd160, sha256)
import Haskoin.Crypto.Keys.Common
import Haskoin.Crypto.Keys.Extended
import Haskoin.Crypto.Signature (hashToMsg, verifyHashSig)
import Haskoin.Network.Common (VarInt (..))
import Haskoin.Network.Data
import Haskoin.Script.Common
import Haskoin.Script.SigHash
import Haskoin.Script.Standard
import Haskoin.Transaction.Builder.Sign (SigInput (..), makeSigHashWith, makeSignatureWith)
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

-- | A map of a PSBT. It is written with its keys in the order of their
-- bytes, the type first. BIP 174 fixes no order. Bitcoin Core writes
-- another one: the fields in the order of its code, a partial signature
-- by the hash of its key, the fields of version 2 after the Taproot
-- fields. So the bytes of the library and those of Bitcoin Core differ
-- for the same PSBT.
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
-- Every field of both is kept, as BIP 174 asks: "The resulting PSBT must
-- contain all of the key-value pairs from each of the PSBTs". Bitcoin Core
-- drops the fields of the signers from an input that is final, which
-- 'finalizePsbt' does here.
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
-- The check is the one of BIP 174, "by checking for the presence of" the
-- final fields: an input needs no coin for it. Bitcoin Core also wants
-- the coin of each input, to run its final script.
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

-- The preimages of BIP 174, and the MuSig2 fields of BIP 373
ripemd160Type, sha256Type, hash160Type, hash256Type, inMusigParticipantsType, musigNonceType, musigPartialSigType :: Word8
ripemd160Type = 0x0a
sha256Type = 0x0b
hash160Type = 0x0c
hash256Type = 0x0d
inMusigParticipantsType = 0x1a
musigNonceType = 0x1b
musigPartialSigType = 0x1c

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

-- The MuSig2 field of an output, of BIP 373
outMusigParticipantsType :: Word8
outMusigParticipantsType = 0x08

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
-- breaks the spec.
--
-- __What is refused.__ A key out of shape, a key twice in a map, a value
-- that does not decode, a field of the other version, a field that
-- version 2 requires and that is missing, bytes after the last map. The
-- fields checked are those of BIP 174, BIP 370, BIP 371 and BIP 373. And
-- what Bitcoin Core refuses when it reads a PSBT: a key type that is not a
-- compact size integer in its shortest form, a public key that is not a
-- point of the curve, a partial signature that is not in the encoding of
-- BIP 66 with a defined sighash byte, a previous transaction that is not
-- the one its input spends, a script tree that is not whole, and an
-- extended key of depth 0 that has a child number or a parent fingerprint,
-- which BIP 32 gives to no master key.
--
-- __What is read as bytes.__ Where a BIP gives a field as bytes, any bytes
-- are read, as Bitcoin Core reads them, and the function that gives the
-- field refuses those that it cannot use: a redeem script, a witness
-- script or a leaf script that is no list of opcodes ('inputRedeemScript',
-- 'tapLeafScripts', 'outputTapTree'), an x-only key that is no point of
-- the curve, and a Taproot signature of 65 bytes whose last byte is no
-- sighash type of BIP 341 ('tapKeySig'). The signer and the finalizer
-- leave such an input as it is.
--
-- __Where a BIP is stricter than Bitcoin Core,__ the BIP is followed, and
-- Bitcoin Core reads what is refused here:
--
-- * a hash preimage that does not hash to its key. BIP 174: the preimage
--   "must equal the key when run through" the algorithm of the field;
-- * a control block of more than 128 nodes, the most BIP 341 allows;
-- * an extended key with a path that is not as deep as the key. BIP 174:
--   "The number of 32 bit unsigned integer indexes must match the depth
--   provided in the extended public key".
--
-- __A PSBT of version 2 without a lock time.__ When some inputs require a
-- height and others a time, no lock time fits them all, and the PSBT has
-- no transaction. BIP 370 lists such a PSBT with the note that its lock
-- time "cannot be computed", and Bitcoin Core reads it and gives no
-- transaction. A t'Psbt' here always has its unsigned transaction, so
-- such a PSBT is refused. Nobody can sign it.
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
-- key, an x-only public key, an x-only public key with a leaf hash, a
-- control block, a hash of some bytes, a compressed public key, or the
-- compressed keys of a MuSig2 participant and of the aggregate with a leaf
-- hash or none
data KeyShape
  = NoData
  | PublicKeyData
  | XpubData
  | XOnlyKeyData
  | KeyAndLeafData
  | ControlBlockData
  | HashData Int
  | CompressedKeyData
  | MusigSignerData

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
  HashData size -> unless (B.length key.keyData == size) $ Left ("the key " <> showKey key <> " is not a hash of " <> show size <> " bytes")
  CompressedKeyData -> unless (isCompressedKeyBytes key.keyData) $ Left ("the key " <> showKey key <> " is not a compressed public key")
  MusigSignerData ->
    unless (B.length key.keyData `elem` [66, 98] && all isCompressedKeyBytes [B.take 33 key.keyData, B.take 33 (B.drop 33 key.keyData)]) $
      Left ("the key " <> showKey key <> " is not a participant key and an aggregate key, with a leaf hash or none")

-- | Whether a control block may have the length: 33 bytes plus 32 per
-- node, with at most 'maxControlBlockNodes' nodes
isControlBlockLength :: Int -> Bool
isControlBlockLength len =
  len >= 33 && (len - 33) `mod` 32 == 0 && (len - 33) `div` 32 <= maxControlBlockNodes

-- | Whether the bytes are a public key, compressed or not: they have the
-- length and the first byte of one, and are a point of the curve, as
-- Bitcoin Core requires of the keys of a PSBT (@IsFullyValid@ in psbt.h).
isPublicKeyBytes :: ByteString -> Bool
isPublicKeyBytes bytes = shaped && isJust (importPubKey bytes)
  where
    shaped = case B.unpack (B.take 1 bytes) of
      [0x02] -> B.length bytes == 33
      [0x03] -> B.length bytes == 33
      [0x04] -> B.length bytes == 65
      _ -> False

-- | Whether the bytes are a compressed public key: 33 bytes that are a
-- point of the curve
isCompressedKeyBytes :: ByteString -> Bool
isCompressedKeyBytes bytes = B.length bytes == 33 && isPublicKeyBytes bytes

-- | Whether the bytes are an extended public key as BIP 32 serializes
-- one: 78 bytes that end with a compressed public key. A key of depth 0 is
-- a master key, which has no parent fingerprint and the child number 0:
-- Bitcoin Core reads no other key of depth 0 (@CExtPubKey::Decode@).
isXpubBytes :: ByteString -> Bool
isXpubBytes bytes = B.length bytes == 78 && isCompressedKeyBytes (B.drop 45 bytes) && (depth /= 0 || B.all (== 0) parentAndChild)
  where
    depth = B.index bytes 4
    parentAndChild = B.take 8 (B.drop 5 bytes)

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
      -- BIP 174 gives the two scripts as bytes, and Bitcoin Core reads
      -- any. 'inputRedeemScript' and 'inputWitnessScript' refuse bytes that
      -- are no list of opcodes.
      (inRedeemScriptType, plain anyValue),
      (inWitnessScriptType, plain anyValue),
      (inDerivationType, Field PublicKeyData [Version0, Version2] (const derivationValue)),
      (finalScriptSigType, plain anyValue),
      (finalScriptWitnessType, plain witnessValue),
      (ripemd160Type, preimageOf 20 (S.encode . ripemd160)),
      (sha256Type, preimageOf 32 (S.encode . sha256)),
      (hash160Type, preimageOf 20 (S.encode . addressHash)),
      (hash256Type, preimageOf 32 (S.encode . doubleSHA256)),
      (tapKeySigType, plain tapSigValue),
      (tapScriptSigType, Field KeyAndLeafData [Version0, Version2] (const tapSigValue)),
      (tapLeafScriptType, Field ControlBlockData [Version0, Version2] (const leafScriptValue)),
      (inTapDerivationType, Field XOnlyKeyData [Version0, Version2] (const tapDerivationValue)),
      (inTapInternalKeyType, plain xOnlyKeyValue),
      (tapMerkleRootType, plain hashValue),
      (inMusigParticipantsType, Field CompressedKeyData [Version0, Version2] (const compressedKeysValue)),
      (musigNonceType, Field MusigSignerData [Version0, Version2] (const (sizedValue 66 "is not a public nonce of 66 bytes"))),
      (musigPartialSigType, Field MusigSignerData [Version0, Version2] (const (sizedValue 32 "is not a partial signature of 32 bytes"))),
      (prevTxidType, plain2 txHashValue),
      (outputIndexType, plain2 word32Value),
      (sequenceType, plain2 word32Value),
      (requiredTimeType, plain2 timeLockValue),
      (requiredHeightType, plain2 heightLockValue)
    ]
  where
    -- BIP 174: the preimage "must equal the key when run through" the
    -- algorithm of the field. Bitcoin Core checks the size of the key only.
    preimageOf size hash = Field (HashData size) [Version0, Version2] $ \keyData value ->
      unless (hash value == keyData) $ Left "is not the preimage of the hash in its key"
    sizedValue size refusal value = unless (B.length value == size) $ Left refusal
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
    [ (outRedeemScriptType, plain anyValue),
      (outWitnessScriptType, plain anyValue),
      (outDerivationType, Field PublicKeyData [Version0, Version2] (const derivationValue)),
      (amountType, plain2 amountValue),
      (outScriptType, plain2 anyValue),
      (outTapInternalKeyType, plain xOnlyKeyValue),
      (outTapTreeType, plain tapTreeValue),
      (outTapDerivationType, Field XOnlyKeyData [Version0, Version2] (const tapDerivationValue)),
      (outMusigParticipantsType, Field CompressedKeyData [Version0, Version2] (const compressedKeysValue))
    ]
  where
    amountValue value = () <$ decodeWord64le value

-- | A Taproot signature as BIP 371 gives it and as Bitcoin Core reads it:
-- 64 or 65 bytes. The last byte of 65 is not looked at: 'tapKeySig' and
-- 'tapScriptSigs' refuse one that is no sighash type of BIP 341, and
-- 'finalizePsbt' makes no witness of it.
tapSigValue :: ByteString -> Either String ()
tapSigValue value =
  unless (B.length value `elem` [64, 65]) $
    () <$ first ("is not a Taproot signature: " <>) (decodeTaprootSig value)

-- | The compressed public keys of the participants of a MuSig2 aggregate
-- key (BIP 373), one after the other, each a point of the curve
compressedKeysValue :: ByteString -> Either String ()
compressedKeysValue value =
  unless (all isCompressedKeyBytes (chunksOf 33 value)) $ Left "is not a list of compressed public keys"

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
--
-- The script of a leaf is read as bytes, as BIP 371 gives it: only
-- 'outputTapTree' asks that it is a list of opcodes.
tapTreeValue :: ByteString -> Either String ()
tapTreeValue value = do
  leaves <- parseTapTree (const (Right (Script []))) value
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
publicKeyRecords :: Word8 -> (ByteString -> Either String a) -> PsbtMap -> Either String [(PublicKey, a)]
publicKeyRecords t decodeValue m =
  forM [(key, value) | (key, value) <- Map.toAscList m, key.keyType == t] $ \(key, value) -> do
    public <- first (const ("The key " <> showKey key <> " is not a public key")) (decodeSerial key.keyData)
    decoded <- first (("The value of the key " <> showKey key <> " ") <>) (decodeValue value)
    return (public, decoded)

derivationsOf :: Word8 -> PsbtMap -> Either String [(PublicKey, Derivation)]
derivationsOf t = publicKeyRecords t decodeDerivation

insertDerivation :: Word8 -> PublicKey -> Derivation -> PsbtMap -> PsbtMap
insertDerivation t public derivation = Map.insert (Key t (encodeSerial public)) (encodeDerivation derivation)

-- | The derivations of the keys of an input: PSBT_IN_BIP32_DERIVATION
inputDerivations :: PsbtMap -> Either String [(PublicKey, Derivation)]
inputDerivations = derivationsOf inDerivationType

insertInputDerivation :: PublicKey -> Derivation -> PsbtMap -> PsbtMap
insertInputDerivation = insertDerivation inDerivationType

-- | The derivations of the keys of an output: PSBT_OUT_BIP32_DERIVATION.
-- A record is a claim of whoever wrote the PSBT. To treat an output as
-- change, derive the key and compare it with the script of the output.
outputDerivations :: PsbtMap -> Either String [(PublicKey, Derivation)]
outputDerivations = derivationsOf outDerivationType

insertOutputDerivation :: PublicKey -> Derivation -> PsbtMap -> PsbtMap
insertOutputDerivation = insertDerivation outDerivationType

-- | The extended public keys of the global map, with their derivations:
-- PSBT_GLOBAL_XPUB. Those of another network, by their version bytes, are
-- left aside.
xpubRecords :: Network -> PsbtMap -> Either String [(XPubKey, Derivation)]
xpubRecords net m =
  fmap catMaybes . forM [(key, value) | (key, value) <- Map.toAscList m, key.keyType == xpubType] $ \(key, value) -> do
    derivation <- first (("The value of the key " <> showKey key <> " ") <>) (decodeDerivation value)
    return $ (\xpub -> (xpub, derivation)) <$> eitherToMaybe (unmarshal net key.keyData)

insertXpubRecord :: Network -> XPubKey -> Derivation -> PsbtMap -> PsbtMap
insertXpubRecord net xpub derivation = Map.insert (Key xpubType (marshal net xpub)) (encodeDerivation derivation)

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
partialSignatures :: PsbtMap -> Either String [(PublicKey, ByteString)]
partialSignatures = publicKeyRecords partialSigType Right

-- | Whether the input carries a signature that is not final
hasPartialSignatures :: PsbtMap -> Bool
hasPartialSignatures = any ((== partialSigType) . (.keyType)) . Map.keys

insertPartialSignature :: PublicKey -> ByteString -> PsbtMap -> PsbtMap
insertPartialSignature public = Map.insert (Key partialSigType (encodeSerial public))

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
tapScriptSigs :: PsbtMap -> Either String [((PubKey, Digest SHA256), TaprootSignature)]
tapScriptSigs m =
  forM [(key, value) | (key, value) <- Map.toAscList m, key.keyType == tapScriptSigType] $ \(key, value) -> do
    let (keyBytes, leafBytes) = B.splitAt 32 key.keyData
    leafKey <- maybe (Left ("The key " <> showKey key <> " is not an x-only public key and a leaf hash")) Right $ importXOnlyPubKey keyBytes
    leaf <- maybe (Left ("The key " <> showKey key <> " is not an x-only public key and a leaf hash")) Right $ digestOf leafBytes
    signature <- first (("The value of the key " <> showKey key <> " ") <>) (decodeTaprootSig value)
    return ((leafKey, leaf), signature)

insertTapScriptSig :: PubKey -> Digest SHA256 -> TaprootSignature -> PsbtMap -> PsbtMap
insertTapScriptSig leafKey leaf signature =
  Map.insert (Key tapScriptSigType (exportXOnlyPubKey leafKey <> BA.convert leaf)) (encodeTaprootSig signature)

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
tapLeafScripts :: PsbtMap -> Either String [TapLeafScript]
tapLeafScripts = sequence . tapLeafScriptEntries

-- | Each leaf script of a Taproot input, or why it is refused: a control
-- block whose internal key is no point of the curve, or a script that is
-- not a list of opcodes. 'decodePsbt' reads such an entry, as Bitcoin Core
-- does, and a leaf of an unknown leaf version may hold any bytes. The
-- signer and the finalizer take the entries one by one, so that one they
-- cannot use does not hide the others.
tapLeafScriptEntries :: PsbtMap -> [Either String TapLeafScript]
tapLeafScriptEntries m =
  [ do
      _ <- first (const ("The key " <> showKey key <> " is not a control block")) (decodeControlBlock key.keyData)
      when (B.null value) $ Left ("The value of the key " <> showKey key <> " has no leaf version")
      script <- first (("The value of the key " <> showKey key <> " ") <>) (decodeScript (B.init value))
      return (TapLeafScript key.keyData script (B.last value))
  | (key, value) <- Map.toAscList m,
    key.keyType == tapLeafScriptType
  ]

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

tapDerivationsOf :: Word8 -> PsbtMap -> Either String [(PubKey, TapDerivation)]
tapDerivationsOf t m =
  forM [(key, value) | (key, value) <- Map.toAscList m, key.keyType == t] $ \(key, value) -> do
    public <- maybe (Left ("The key " <> showKey key <> " is not an x-only public key")) Right (importXOnlyPubKey key.keyData)
    decoded <- first (("The value of the key " <> showKey key <> " ") <>) (decodeTapDerivation value)
    return (public, decoded)

insertTapDerivation :: Word8 -> PubKey -> TapDerivation -> PsbtMap -> PsbtMap
insertTapDerivation t public d = Map.insert (Key t (exportXOnlyPubKey public)) (encodeTapDerivation d)

-- | The derivations of the x-only keys of a Taproot input, each with the
-- leaves it appears in: PSBT_IN_TAP_BIP32_DERIVATION. The key is the
-- point of even y with that x coordinate.
inputTapDerivations :: PsbtMap -> Either String [(PubKey, TapDerivation)]
inputTapDerivations = tapDerivationsOf inTapDerivationType

insertInputTapDerivation :: PubKey -> TapDerivation -> PsbtMap -> PsbtMap
insertInputTapDerivation = insertTapDerivation inTapDerivationType

-- | The derivations of the x-only keys of a Taproot output:
-- PSBT_OUT_TAP_BIP32_DERIVATION. A record is a claim of whoever wrote the
-- PSBT, as for 'outputDerivations'.
outputTapDerivations :: PsbtMap -> Either String [(PubKey, TapDerivation)]
outputTapDerivations = tapDerivationsOf outTapDerivationType

insertOutputTapDerivation :: PubKey -> TapDerivation -> PsbtMap -> PsbtMap
insertOutputTapDerivation = insertTapDerivation outTapDerivationType

xOnlyKeyField :: Word8 -> String -> PsbtMap -> Either String (Maybe PubKey)
xOnlyKeyField t what = optionalField what t (maybe (Left "is not an x-only public key") Right . importXOnlyPubKey)

insertXOnlyKeyField :: Word8 -> PubKey -> PsbtMap -> PsbtMap
insertXOnlyKeyField t = insertPlainField t . exportXOnlyPubKey

-- | The internal key of the Taproot coin an input spends:
-- PSBT_IN_TAP_INTERNAL_KEY. The key is the point of even y with that x
-- coordinate.
inputTapInternalKey :: PsbtMap -> Either String (Maybe PubKey)
inputTapInternalKey = xOnlyKeyField inTapInternalKeyType "The internal key"

insertInputTapInternalKey :: PubKey -> PsbtMap -> PsbtMap
insertInputTapInternalKey = insertXOnlyKeyField inTapInternalKeyType

-- | The root of the script tree of the Taproot coin an input spends:
-- PSBT_IN_TAP_MERKLE_ROOT
inputTapMerkleRoot :: PsbtMap -> Either String (Maybe (Digest SHA256))
inputTapMerkleRoot = optionalField "The Merkle root" tapMerkleRootType (maybe (Left "is not a 32-byte hash") Right . digestOf)

insertInputTapMerkleRoot :: Digest SHA256 -> PsbtMap -> PsbtMap
insertInputTapMerkleRoot = insertPlainField tapMerkleRootType . BA.convert

-- | The internal key of a Taproot output: PSBT_OUT_TAP_INTERNAL_KEY
outputTapInternalKey :: PsbtMap -> Either String (Maybe PubKey)
outputTapInternalKey = xOnlyKeyField outTapInternalKeyType "The internal key"

insertOutputTapInternalKey :: PubKey -> PsbtMap -> PsbtMap
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
decodeTapTree = parseTapTree (first ("has a leaf whose script " <>) . decodeScript)

-- | The leaves of a script tree, with the script of each leaf read from
-- its bytes by the function given
parseTapTree :: (ByteString -> Either String Script) -> ByteString -> Either String [TapLeaf]
parseTapTree scriptOf = parseAll leaves "a script tree"
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
          script <- either refuse return (scriptOf scriptBytes)
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
-- @(keySigner key) {acceptedSigHashes = sigHashNone : defaultSigHashes}@.
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
-- @(keySigner key) {requirePreviousTx = False}@.
keySigner :: SecKey -> Signer
keySigner secret =
  Signer
    { keyOfRecord = \public _ -> do
        guard (public.point == derivePubKey secret)
        return secret,
      keyOfHash = \h -> find ((== h) . addressHash . encodeSerial . derivePublicKey) [PrivateKey secret True, PrivateKey secret False],
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
xPrvSigner :: XPrvKey -> Maybe Derivation -> Signer
xPrvSigner xprv originM =
  Signer
    { keyOfRecord = \public derivation -> do
        path <- relative derivation
        secret <- (.key) <$> eitherToMaybe (tryDerivePath path xprv)
        guard (public.point == derivePubKey secret)
        return secret,
      keyOfHash = const Nothing,
      acceptedSigHashes = defaultSigHashes,
      requirePreviousTx = True
    }
  where
    own = xPubFP (deriveXPubKey xprv)
    relative :: Derivation -> Maybe DerivPath
    relative derivation
      | derivation.fingerprint == own = Just derivation.path
      | Just origin <- originM,
        derivation.fingerprint == origin.fingerprint =
          listToPath <$> stripPrefix (pathToList origin.path) (pathToList derivation.path)
      | otherwise = Nothing

-- | Sign every input the signer has keys for, as the signer of the spec
-- does. An input is signed against the coin it spends: the output of its
-- previous transaction, whose id must be the one the input spends, or,
-- without that transaction, its witness output, which only a witness
-- signature may use, as BIP 174 requires. A witness output beside the
-- previous transaction is not read, as Bitcoin Core does not read it.
--
-- __One input at a time.__ The parties of a transaction fill a PSBT in
-- turn, so an input that this signer cannot sign is the normal case and
-- not a fault. BIP 174 names one case in which a signer must fail, the
-- sighash type, and for the rest says "If a Signer cannot sign a
-- transaction, it must not add a Partial Signature." So the signer does as
-- Bitcoin Core does (@SignPSBTInput@): it refuses the whole PSBT for a
-- sighash type only, and an input that it cannot or may not sign stays as
-- it is while the other inputs are signed. The cost of that choice is that
-- the result does not say why an input has no signature: compare the
-- inputs before and after.
--
-- __What refuses the PSBT.__ The sighash type of an input is the one it
-- asks for. When it asks for none it is SIGHASH_ALL, with the fork id flag
-- on a network that has one, and SIGHASH_DEFAULT for a Taproot coin. On
-- any input that has its coin and is not final, whoever it belongs to:
--
-- * a type that no node accepts for the kind of coin, or that the signer
--   does not accept ('acceptedSigHashes'). BIP 174: "If a sighash type is
--   provided, the signer must check that the sighash is acceptable. If
--   unacceptable, they must fail";
-- * a signature that the input already has and that is of another type,
--   as Bitcoin Core checks it: a partial signature by its last byte, a
--   Taproot signature by its length and its last byte.
--
-- A previous transaction that is not the one its input spends refuses the
-- PSBT too. 'decodePsbt' does not read such a PSBT.
--
-- __What leaves an input as it is.__ An input without its coin, or final
-- already, and an input for which the signer holds no key. And, although
-- the signer holds a key:
--
-- * a redeem script that does not hash to the coin, or a witness script
--   that does not hash to the witness program, and either script on a coin
--   that has none. BIP 174 has a signer check both before it signs.
--   Bitcoin Core signs a coin that carries a script it does not use;
-- * a P2SH coin without its redeem script, a P2WSH coin without its
--   witness script, and a coin, redeem script or witness script that is no
--   standard template;
-- * a P2SH coin whose redeem script has more than 'maxRedeemScriptSize'
--   bytes, which no transaction can spend. Bitcoin Core adds a signature
--   to it, which serves nothing;
-- * a legacy coin known from its witness output only: "If a witness UTXO
--   is provided, no non-witness signature may be created";
-- * a SegWit version 0 coin known from its witness output only, when the
--   signer wants the previous transaction ('requirePreviousTx');
-- * a SegWit version 0 coin of more than 'maxSatoshi', which Bitcoin Core
--   does not sign;
-- * a legacy coin asked to sign SIGHASH_SINGLE with no output at its
--   index, as 'Haskoin.Transaction.Builder.makeSignature' explains, and a
--   Taproot coin in that case, for which BIP 341 defines no digest.
--
-- An uncompressed key gets no signature on a SegWit version 0 coin, which
-- no node relays and Bitcoin Core does not sign, and the other keys of
-- that coin are still signed with. A key that has a signature on the input
-- already is not signed with again: the signature that is there stays, as
-- in Bitcoin Core.
--
-- __The keys.__ They are those that the script that is signed names: the
-- script of the coin, its redeem script or its witness script. The signer
-- is asked for the key of a derivation record only when that script names
-- the key of the record, and for the key of each hash the script names. A
-- key that the script does not name gets no signature, whatever the
-- records say.
--
-- __Taproot.__ A Taproot coin is signed only when every input of the PSBT
-- has its coin, since the BIP 341 digest commits to the output that every
-- input spends. It is signed by its key path when the signer holds the
-- internal key that the input names and that key gives the coin, or when
-- it holds the output key of the coin itself. Otherwise it is signed by
-- each of its leaf scripts that is the check of one key (@\<key\>
-- OP_CHECKSIG@ of the leaf version 0xc0) that the signer holds. As in
-- Bitcoin Core (@SignTaproot@):
--
-- * an input that has a key path signature, or gets one, gets no leaf
--   signature;
-- * a leaf is signed by the leaf version in the value of its entry,
--   whatever its control block holds, and whether or not the control block
--   commits the leaf to the coin. Such a signature is for this input and
--   this leaf alone, so it spends nothing, and 'finalizePsbt' makes a
--   witness only of a leaf that its control block commits;
-- * the key of a leaf is found by the record of that key, whichever leaves
--   the record lists.
--
-- In one case the signer does not do as Bitcoin Core: an internal key that
-- does not give, with the Merkle root of the input, the output key of the
-- coin. Bitcoin Core signs with it when its wallet holds it, and that
-- signature verifies for no coin and then stops the owner of the input,
-- whose finalizer takes the key path signature first. The signer adds
-- none: BIP 174 has a signer make only valid signatures.
--
-- A field that cannot be used gives no key and refuses nothing: an
-- internal key that is no point of the curve, a Merkle root that is not a
-- hash, a record that does not decode. On a network without SegWit a
-- script of the form of a Taproot output is no Taproot coin.
--
-- __Cost.__ A PSBT that another party wrote can hold thousands of leaf
-- scripts and of derivation records on one input, and thousands of leaves
-- in one record, at no cost to its writer. The signer asks for the key of
-- each leaf script once, however many entries have that script, and finds
-- the record of a key by a lookup. So the time it takes grows with the
-- size of the input, and not with the product of two of those numbers.
-- The hashes that the digests of the inputs share are computed once for
-- the PSBT ('taprootTxHashes' for the Taproot inputs, 'txSigHashes' for
-- the SegWit version 0 inputs), so the time for all the inputs grows with
-- the size of the PSBT, and not with the number of its signatures times
-- the size of its transaction. A legacy input is the exception: its
-- digest hashes a copy of the whole transaction, in Bitcoin Core too.
signPsbt :: Network -> Signer -> Psbt -> Either String Psbt
signPsbt net signer psbt = do
  coins <- spentOutputs psbt
  let hashes = taprootHashes tx coins
      sigHashes = txSigHashes tx
  signed <- forM (zip3 [0 ..] (zip tx.inputs psbt.inputs) coins) $ \(i, (input, m), coinM) ->
    first (("Input " <> show i <> ": ") <>) $ case coinM of
      Just (coin, witnessOnly) | not (isFinal m) -> do
        sighash <- fromMaybe (defaultSigHash net coin) <$> sigHashType m
        checkSigHash net coin sighash
        unless (acceptsSigHash signer sighash) $
          Left (notAcceptedSigHash sighash)
        unless (signaturesUse sighash m) $
          Left ("a signature of the input does not use the sighash type " <> show (fromIntegral sighash :: Word32))
        return . fromMaybe (m, []) $
          if isTaprootCoin net coin
            then signTaproot signer hashes i m coin sighash
            else signEcdsa net signer sigHashes i input m coin witnessOnly sighash
      _ -> return (m, [])
  return $ foldr afterSignature (Psbt psbt.version tx psbt.globals (fst <$> signed) psbt.outputs) (concatMap snd signed)
  where
    tx = psbt.unsignedTx

-- | An input with a signature of each key that the signer holds among
-- those the script names, for a coin signed with ECDSA, and the sighash
-- type used. 'Nothing' when no signature is added: the input is left as it
-- is, for each reason that 'signPsbt' lists.
signEcdsa ::
  Network -> Signer -> TxSigHashes -> Int -> TxIn -> PsbtMap -> TxOut -> Bool -> SigHash -> Maybe (PsbtMap, [SigHash])
signEcdsa net signer sigHashes i input m coin witnessOnly sighash = do
  spend <- inputSpend coin m
  let witnessCoin = isSegwit spend.program
  -- BIP 174 has the signer check the scripts that the input provides
  guard (not spend.strayScript)
  -- Only a witness signature may rely on a witness output, and a signer
  -- may want the previous transaction for that one too
  guard (not witnessOnly || (witnessCoin && not signer.requirePreviousTx))
  guard (not witnessCoin || coin.value <= net.maxSatoshi)
  let sigInput = signingInput input coin sighash spend
      signatures =
        [ (public, encodeTxSig net signature)
        | key <- heldKeys signer m (scriptKeyHashes spend.naming),
          key.compress || not witnessCoin,
          let public = derivePublicKey key,
          Map.notMember (Key partialSigType (encodeSerial public)) m,
          Right signature <- [makeSignatureWith net sigHashes i sigInput key]
        ]
  guard (not (null signatures))
  return (foldr (uncurry insertPartialSignature) m signatures, [sighash])

-- | The keys the signer holds among those whose hashes the script that is
-- signed names. The signer is asked for the key of a derivation record
-- only when the hash of the key of the record is one of them, so the work
-- it does is bounded by the script, however many records the PSBT carries.
-- A key the signer gives is kept only when it is the key that was asked
-- for. A record that does not decode names no key.
heldKeys :: Signer -> PsbtMap -> [Hash160] -> [PrivateKey]
heldKeys signer m named = nubBy (\a b -> derivePublicKey a == derivePublicKey b) (recordKeys <> hashKeys)
  where
    recordKeys =
      [ PrivateKey secret public.compress
      | (key, value) <- Map.toAscList m,
        key.keyType == inDerivationType,
        addressHash key.keyData `elem` named,
        Right public <- [decodeSerial key.keyData :: Either String PublicKey],
        Right derivation <- [decodeDerivation value],
        Just secret <- [signer.keyOfRecord public derivation],
        derivePubKey secret == public.point
      ]
    hashKeys = [key | h <- named, Just key <- [signer.keyOfHash h], addressHash (encodeSerial (derivePublicKey key)) == h]

-- | An input with a key path signature, or else one signature for each
-- leaf that is the check of a key the signer holds, for a Taproot coin,
-- and the sighash type used. 'Nothing' when no signature is added: while
-- another input lacks its coin, since the BIP 341 digest commits to the
-- output that every input spends, when the signer holds no key, and when
-- the digest does not exist (SIGHASH_SINGLE with no output at the index).
--
-- As Bitcoin Core (@SignTaproot@): a signature that the input has stays,
-- and an input that has or gets a key path signature gets no leaf
-- signature.
signTaproot :: Signer -> Maybe TaprootTxHashes -> Int -> PsbtMap -> TxOut -> SigHash -> Maybe (PsbtMap, [SigHash])
signTaproot signer hashesM i m coin sighash = do
  hashes <- hashesM
  let held = heldTaprootKeys signer (taprootProgram coin) m
      signatureFor secret leafM = eitherToMaybe $ do
        h <- taprootSigHashWith hashes i sighash Nothing ((,0xffffffff) <$> leafM)
        taprootSignature (signSchnorr secret (hashToMsg h)) sighash
      hasKeySig = Map.member (Key tapKeySigType B.empty) m
      keySig =
        [ insertTapKeySig signature
        | not hasKeySig,
          Just secret <- [held.keyPathKey],
          Just signature <- [signatureFor secret Nothing]
        ]
      leafSigs =
        [ insertTapScriptSig leafKey hashOfLeaf signature
        | not hasKeySig,
          null keySig,
          (leafKey, hashOfLeaf, secret) <- held.leafKeys,
          Map.notMember (tapScriptSigKey (exportXOnlyPubKey leafKey) hashOfLeaf) m,
          Just signature <- [signatureFor secret (Just hashOfLeaf)]
        ]
      added = keySig <> leafSigs
  guard (not (null added))
  return (foldr ($) m added, [sighash])

-- | The secret keys a signer holds for a Taproot input
data TaprootKeys = TaprootKeys
  { -- | the secret key that signs the key path of the coin: the secret
    -- key of the internal key, tweaked, or the one of the output key
    keyPathKey :: Maybe SecKey,
    -- | for each leaf the signer can sign: the key of the leaf, the hash
    -- of the leaf, and the secret key
    leafKeys :: [(PubKey, Digest SHA256, SecKey)]
  }

-- | The keys a signer holds for a Taproot input whose coin has the witness
-- program: the key of its key path, and the key of each leaf script that
-- is the check of one key ('singleKeyLeaves').
--
-- The key path has two keys, tried in the order of Bitcoin Core. First the
-- internal key that the input names, when the signer holds it. It counts
-- only when it gives, with the Merkle root of the input, the output key of
-- the coin, as BIP 174 has a signer make only valid signatures: Bitcoin
-- Core signs with an internal key that does not, and that signature
-- verifies for no coin. Then the output key of the coin itself, for a coin
-- that pays to a key with no tweak.
--
-- A leaf counts whatever its control block holds, as in Bitcoin Core.
--
-- A field that cannot be used gives no key and no refusal: an internal key
-- that is no point of the curve, a Merkle root that is not a hash, a
-- record that does not decode. A signer holds no key for such a field, and
-- the input may belong to another party, whose fields are not the signer's
-- to judge.
heldTaprootKeys :: Signer -> ByteString -> PsbtMap -> TaprootKeys
heldTaprootKeys signer program m =
  TaprootKeys
    { keyPathKey = ofInternalKey <|> (importXOnlyPubKey program >>= held),
      leafKeys =
        [ (leafKey, leafHashBytes tapscriptLeafVersion script, secret)
        | script <- Map.keys (singleKeyLeaves m),
          Just leafKey <- [importXOnlyPubKey (leafKeyBytes script)],
          Just secret <- [held leafKey]
        ]
    }
  where
    ofInternalKey = do
      internal <- either (const Nothing) id (inputTapInternalKey m)
      commitment <- fmap MASTCommitment <$> eitherToMaybe (inputTapMerkleRoot m)
      guard ((exportXOnlyPubKey <$> taprootOutputKey (TaprootOutput internal commitment)) == Right program)
      secret <- held internal
      taprootOutputSecKey secret commitment
    -- The record of each x-only key, by the 32 bytes of the key. An input
    -- has at most one record for a key, since the key is the key of the
    -- entry in its map. A key finds its record here by a lookup: a walk
    -- through the records for each leaf would take time by the product of
    -- two numbers that whoever wrote the PSBT chooses. Any record of a key
    -- will do, whichever leaves it lists: Bitcoin Core finds a key by its
    -- record and does not read the list.
    recordOf = Map.fromList [(key.keyData, value) | (key, value) <- Map.toAscList m, key.keyType == inTapDerivationType]
    -- The secret key of an x-only key, by the record of that key or by the
    -- hash of the key. A key the signer gives is kept only when it is the
    -- key that was asked for.
    held :: PubKey -> Maybe SecKey
    held public =
      listToMaybe . filter (sameX public . derivePubKey) . catMaybes $
        [ signer.keyOfRecord (PublicKey candidate True) record.derivation
        | Just (Right record) <- [decodeTapDerivation <$> Map.lookup (exportXOnlyPubKey public) recordOf],
          candidate <- bothParities public
        ]
          <> [ (.key) <$> signer.keyOfHash (addressHash (encodeSerial (PublicKey candidate True)))
             | candidate <- bothParities public
             ]
    sameX a b = exportXOnlyPubKey a == exportXOnlyPubKey b
    -- The two points with the x coordinate of the key
    bothParities public =
      [ candidate.point
      | prefix <- [0x02, 0x03],
        Right candidate <- [decodeSerial (B.cons prefix (exportXOnlyPubKey public)) :: Either String PublicKey]
      ]

-- | The sighash type of an ECDSA signature for an input that asks for
-- none: SIGHASH_ALL, with the fork id flag on a network that has one
defaultEcdsaSigHash :: Network -> SigHash
defaultEcdsaSigHash net
  | isJust net.sigHashForkId = setForkIdFlag sigHashAll
  | otherwise = sigHashAll

-- | The hashes of the keys a script names: the keys a coin of that script
-- is signed with
scriptKeyHashes :: ScriptOutput -> [Hash160]
scriptKeyHashes = \case
  PayPK public -> [addressHash (encodeSerial public)]
  PayPKHash h -> [h]
  PayWitnessPKHash h -> [h]
  PayMulSig publics _ -> map (addressHash . encodeSerial) publics
  _ -> []

-- | The leaf scripts of a Taproot input that are the check of one key,
-- @\<key\> OP_CHECKSIG@ of the leaf version 0xc0, which is the leaf that
-- the signer signs and the finalizer spends: the bytes of each script,
-- with the control blocks of its entries. One script has an entry for each
-- place it has in the tree.
--
-- The entry is read as Bitcoin Core reads it: the leaf version is the one
-- of its value, and nothing is asked of the control block, nor of the 32
-- bytes of the key. BIP 342 gives the script its meaning for the leaf
-- version 0xc0 only.
singleKeyLeaves :: PsbtMap -> Map ByteString [ByteString]
singleKeyLeaves m =
  Map.fromListWith
    (<>)
    [ (B.init value, [key.keyData])
    | (key, value) <- Map.toAscList m,
      key.keyType == tapLeafScriptType,
      -- The push of 32 bytes, OP_CHECKSIG, and the leaf version
      B.length value == 35,
      B.head value == 0x20,
      B.index value 33 == 0xac,
      B.last value == tapscriptLeafVersion
    ]

-- | The 32 bytes of the key of a script of 'singleKeyLeaves'
leafKeyBytes :: ByteString -> ByteString
leafKeyBytes = B.take 32 . B.drop 1

-- | The key of the entry of a script path signature: PSBT_IN_TAP_SCRIPT_SIG
-- with the 32 bytes of the x-only key and the leaf hash
tapScriptSigKey :: ByteString -> Digest SHA256 -> Key
tapScriptSigKey keyBytes leaf = Key tapScriptSigType (keyBytes <> BA.convert leaf)

-- | Whether a control block commits a leaf script of the leaf version 0xc0
-- to the output key of the coin, with that leaf version. A spend takes the
-- leaf version from the first byte of the control block (BIP 341): one
-- that holds another version spends another leaf, which is not the one
-- that was signed.
commitsLeaf :: PubKey -> ByteString -> ByteString -> Bool
commitsLeaf outKey control scriptBytes = case decodeControlBlock control of
  Right (v, internalKey, proof)
    | v .&. 0xfe == tapscriptLeafVersion ->
        verifyScriptPathData outKey $
          ScriptPathData Nothing [] (Script []) (odd v) tapscriptLeafVersion internalKey proof (Just scriptBytes)
  _ -> False

-- | Whether every signature of an input is of the sighash type, as Bitcoin
-- Core checks it before it signs or finalizes an input (@SignPSBTInput@),
-- by the bytes alone: a Taproot signature of 64 bytes is of
-- SIGHASH_DEFAULT, one of 65 bytes of the type of its last byte, and a
-- partial signature of the type of its last byte. For SIGHASH_DEFAULT,
-- which no ECDSA signature has, Bitcoin Core does not look at the partial
-- signatures.
signaturesUse :: SigHash -> PsbtMap -> Bool
signaturesUse sighash m
  | sighash == sigHashDefault = all ((== 64) . B.length) taprootSignatures
  | otherwise = all (\value -> B.length value == 65 && ofType value) taprootSignatures && all ofType (valuesOf [partialSigType])
  where
    valuesOf types = [value | (key, value) <- Map.toAscList m, key.keyType `elem` types]
    taprootSignatures = valuesOf [tapKeySigType, tapScriptSigType]
    ofType value = not (B.null value) && fromIntegral (B.last value) == sighash

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

-- | The sighash type of an input that asks for none: SIGHASH_DEFAULT for a
-- Taproot coin, and that of 'defaultEcdsaSigHash' for any other
defaultSigHash :: Network -> TxOut -> SigHash
defaultSigHash net coin
  | isTaprootCoin net coin = sigHashDefault
  | otherwise = defaultEcdsaSigHash net

-- | A sighash type a signature of the coin may carry on the network
checkSigHash :: Network -> TxOut -> SigHash -> Either String ()
checkSigHash net coin sighash
  | isTaprootCoin net coin =
      unless (isTaprootSigHash sighash) $
        Left ("the sighash type " <> show (fromIntegral sighash :: Word32) <> " is not one a Taproot signature may use")
  | otherwise = checkEcdsaSigHash net sighash

-- | Whether a coin is a Taproot output: a witness program of version 1 and
-- 32 bytes, on a network that has SegWit. The bytes of the script tell, as
-- in Bitcoin Core (@IsPayToTaproot@). On a network without SegWit the same
-- bytes are a script that anyone can spend, and no Taproot rule applies.
isTaprootCoin :: Network -> TxOut -> Bool
isTaprootCoin net coin = net.segWit && B.length coin.script == 34 && B.take 2 coin.script == "\x51\x20"

-- | The witness program of a Taproot coin: the 32 bytes of its output key
taprootProgram :: TxOut -> ByteString
taprootProgram coin = B.drop 2 coin.script

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
-- and have the output it spends. It gives the coin, and a witness output
-- beside it is not read, as in Bitcoin Core.
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

-- | The hashes that the BIP 341 digests of the Taproot inputs share, once
-- every input has its coin: the digest commits to the output that every
-- input spends. The signer and the finalizer take them once for a PSBT, as
-- Bitcoin Core does (@PrecomputePSBTData@), so that a digest takes time by
-- the size of its own input, and not by the size of the transaction.
taprootHashes :: Tx -> [Maybe (TxOut, Bool)] -> Maybe TaprootTxHashes
taprootHashes tx coins = mapM (fmap fst) coins >>= eitherToMaybe . taprootTxHashes tx

-- | The output an input spends, from the fields of the input: the output
-- of its previous transaction, which must be the transaction the input
-- spends from, or else its witness output alone. The flag tells when the
-- witness output alone is known, which only a witness signature may rely
-- on. With both, the previous transaction gives the coin and the witness
-- output is not read, as in Bitcoin Core (@PSBTInput::GetUTXO@): the id of
-- the previous transaction is checked, and a witness output is a claim.
spentOutput :: TxIn -> PsbtMap -> Either String (Maybe (TxOut, Bool))
spentOutput input m = do
  parentM <- nonWitnessUtxo m
  case parentM of
    Just parent -> (\output -> Just (output, False)) <$> previousOutput input parent
    Nothing -> fmap (,True) <$> witnessUtxo m

-- | How a coin signed with ECDSA is spent, from its script and the redeem
-- and witness scripts of its input
data Spend = Spend
  { -- | the script the coin is signed against: the script of the coin, or
    -- the witness program its redeem script is when it is nested in P2SH
    program :: ScriptOutput,
    -- | the script that names the keys: the script of the coin, its
    -- redeem script or its witness script. It is a P2PK, P2PKH or multisig
    -- script, or the P2WPKH program itself.
    naming :: ScriptOutput,
    -- | the redeem script of a P2SH coin
    redeemScript :: Maybe Script,
    -- | the witness script of a P2WSH coin, nested in P2SH or not
    witnessScript :: Maybe Script,
    -- | whether the input has a redeem script or a witness script that is
    -- not the one of its coin
    strayScript :: Bool
  }

-- | How the coin of an input is spent, as Bitcoin Core solves it
-- (@ProduceSignature@). A redeem script serves only when it hashes to the
-- P2SH coin, and a witness script only when it hashes to the witness
-- program, which is what BIP 174 has a signer check. 'Nothing' for a coin
-- that the library cannot sign or finalize, which is left to others:
--
-- * a coin without the script it commits to, or with one that does not
--   parse;
-- * a redeem script of more than 'maxRedeemScriptSize' bytes, or a
--   witness script of more than 'maxWitnessScriptSize': no transaction
--   can spend the coin. Bitcoin Core adds a signature to such a coin, and
--   makes no final script of it;
-- * a script that names the keys and is no standard template;
-- * a script hash or a witness program where none may be: a P2SH script as
--   redeem script, or a P2SH script or a witness program as witness
--   script. Such a script is run as a script and not as a commitment, so
--   no signature spends the coin.
inputSpend :: TxOut -> PsbtMap -> Maybe Spend
inputSpend coin m = do
  coinScript <- eitherToMaybe (decodeSerial coin.script)
  let given field = either (const Nothing) id (field m)
      redeemM = mfilter ((== Right coinScript) . toP2SH) (given inputRedeemScript)
  program <- case coinScript of
    PayScriptHash _ -> do
      redeem <- redeemM >>= eitherToMaybe . decodeOutput
      return (if isSegwit redeem then redeem else coinScript)
    _ -> Just coinScript
  let witnessM = mfilter ((== Right program) . toP2WSH) (given inputWitnessScript)
  naming <- case program of
    PayWitnessScriptHash _ -> witnessM >>= eitherToMaybe . decodeOutput >>= keyScript
    PayScriptHash _ -> redeemM >>= eitherToMaybe . decodeOutput >>= keyScript
    PayWitnessPKHash _ -> Just program
    _ -> keyScript program
  return
    Spend
      { program = program,
        naming = naming,
        redeemScript = redeemM,
        witnessScript = witnessM,
        strayScript =
          (Map.member (Key inRedeemScriptType B.empty) m && isNothing redeemM)
            || (Map.member (Key inWitnessScriptType B.empty) m && isNothing witnessM)
      }
  where
    keyScript out = case out of
      PayPK _ -> Just out
      PayPKHash _ -> Just out
      PayMulSig _ _ -> Just out
      _ -> Nothing

-- | What an input is signed against, as 'makeSignatureWith' wants it: the
-- script of its coin or its witness program, with the redeem script of a
-- P2SH coin or the witness script of a P2WSH coin
signingInput :: TxIn -> TxOut -> SigHash -> Spend -> SigInput
signingInput input output sighash spend =
  SigInput
    { script = spend.program,
      value = output.value,
      outpoint = input.outpoint,
      sighash = sighash,
      redeem = case spend.program of
        PayWitnessScriptHash _ -> Just spend.naming
        PayScriptHash _ -> Just spend.naming
        _ -> Nothing
    }

{- Finalizing -}

-- | Finalize every input whose signatures suffice for the coin it spends,
-- as the finalizer of the spec does: the final script and witness go in
-- the input, and its partial signatures, sighash type, redeem script,
-- witness script, derivation records, hash preimages, Taproot fields and
-- MuSig2 fields go, as Bitcoin Core drops them. Its coin and the keys the
-- library does not define stay. An input that is final already loses
-- those fields too.
--
-- __One input at a time.__ BIP 174: "For each input, the Input Finalizer
-- determines if the input has enough data to pass validation." An input
-- that does not is left as it is, and the others are finalized, as in
-- Bitcoin Core (@FinalizePSBT@), which refuses nothing. The only refusal
-- here is for a previous transaction that is not the one its input spends,
-- which 'decodePsbt' does not read either. 'psbtTransaction' tells whether
-- every input is final.
--
-- __The final script.__ The finalizer makes the one script that Bitcoin
-- Core would make, and then checks it. When it does not pass, the input is
-- left, and no other choice of signatures is tried:
--
-- * a multisig takes the signatures of the first keys, in the order of the
--   script, that have one, as many as it requires;
-- * a Taproot coin takes its key path signature when it has one, and
--   otherwise the signed leaf whose witness is smallest: the one with the
--   shortest control block, since the leaves are the check of one key.
--
-- Each signature that is used must verify against the digest of the coin
-- and be one that nodes relay: no high S, and no uncompressed key on a
-- SegWit version 0 coin. A leaf must be committed to the coin by its
-- control block, with the leaf version 0xc0. A signature that is not used
-- is not verified, so it cannot stop an input that is ready.
--
-- __The sighash type.__ Every signature of the input, used or not, must be
-- of the type the input names: BIP 174 has the finalizer "fail to finalize
-- that input if any signature does not match the specified sighash type".
-- When the input names none, Bitcoin Core wants SIGHASH_ALL, with the fork
-- id flag on a network that has one, and SIGHASH_DEFAULT for a Taproot
-- coin, where it does not look at partial signatures.
--
-- __What is left as it is.__ Besides an input without enough signatures:
-- one without its coin, one whose scripts are no standard template, a
-- legacy coin known from its witness output only, a Taproot coin whose
-- output key is no point of the curve, which nobody can spend, and a
-- signed Taproot coin while another input of the PSBT lacks its coin,
-- since the digest of a Taproot signature commits to the output every
-- input spends and the signature cannot be verified before.
--
-- A redeem script or a witness script on a coin that has none does not
-- stop the finalizer, as it does not stop Bitcoin Core: BIP 174 gives that
-- check to the signer.
--
-- The coins finalized are those of P2PK, P2PKH and multisig scripts, P2SH
-- coins with their redeem script, P2WPKH coins, P2WSH coins with their
-- witness script, nested in P2SH or not, and Taproot coins by their key
-- path signature or by a leaf script that is the check of one key.
--
-- __Cost.__ A Taproot input of a PSBT that another party wrote can hold
-- thousands of leaf scripts and of script path signatures, at no cost to
-- its writer. A leaf finds its signature by a lookup, so the time such an
-- input takes grows with its size, and not with the product of the two
-- numbers. The hashes that the digests of the inputs share are computed
-- once for the PSBT ('taprootTxHashes' for the Taproot inputs,
-- 'txSigHashes' for the SegWit version 0 inputs), so the time for all the
-- inputs grows with the size of the PSBT, and not with its square. A
-- legacy input is the exception: its digest hashes a copy of the whole
-- transaction, in Bitcoin Core too.
finalizePsbt :: Network -> Psbt -> Either String Psbt
finalizePsbt net psbt = do
  coins <- spentOutputs psbt
  let hashes = taprootHashes tx coins
      sigHashes = txSigHashes tx
  inputs <- forM (zip3 [0 ..] (zip tx.inputs psbt.inputs) coins) $ \(i, (input, m), coinM) ->
    first (("Input " <> show i <> ": ") <>) $ case coinM of
      _ | isFinal m -> return (cleared m)
      Nothing -> return m
      Just (coin, witnessOnly) -> do
        sighashM <- sigHashType m
        let sighash = fromMaybe (defaultSigHash net coin) sighashM
            finals
              -- BIP 174 asks it of every signature when the input names a
              -- type, also for the type 0, which no partial signature has
              | not (signaturesUse sighash m) || (sighashM == Just sigHashDefault && hasPartialSignatures m) = Nothing
              | isTaprootCoin net coin = finalTaproot hashes i m coin
              | otherwise = finalEcdsa net sigHashes i input m coin witnessOnly sighash
        return (maybe m (finalized m) finals)
  return $ Psbt psbt.version tx psbt.globals inputs psbt.outputs
  where
    tx = psbt.unsignedTx
    finalized m (scriptSig, stack) =
      foldr ($) (cleared m) $
        [insertFinalScriptSig scriptSig | not (B.null scriptSig)]
          <> [insertFinalScriptWitness stack | not (null stack)]
    cleared = Map.filterWithKey (\key _ -> key.keyType `notElem` clearedTypes)
    clearedTypes =
      [ partialSigType,
        sigHashTypeType,
        inRedeemScriptType,
        inWitnessScriptType,
        inDerivationType,
        ripemd160Type,
        sha256Type,
        hash160Type,
        hash256Type,
        tapKeySigType,
        tapScriptSigType,
        tapLeafScriptType,
        inTapDerivationType,
        inTapInternalKeyType,
        tapMerkleRootType,
        inMusigParticipantsType,
        musigNonceType,
        musigPartialSigType
      ]

-- | The final script and witness of an input signed with ECDSA, from the
-- partial signatures that its script takes, when they suffice and each of
-- them verifies. 'Nothing' leaves the input as it is.
finalEcdsa ::
  Network -> TxSigHashes -> Int -> TxIn -> PsbtMap -> TxOut -> Bool -> SigHash -> Maybe (ByteString, WitnessStack)
finalEcdsa net sigHashes i input m coin witnessOnly sighash = do
  spend <- inputSpend coin m
  let witnessCoin = isSegwit spend.program
      sigInput = signingInput input coin sighash spend
  -- Only a witness signature may rely on a witness output
  guard (witnessCoin || not witnessOnly)
  used <- usedSignatures spend.naming (namedSignatures m spend.naming)
  digest <- eitherToMaybe (makeSigHashWith net sigHashes i sigInput.script coin.value sighash sigInput.redeem)
  -- One digest serves every signature: all are of the sighash type, by
  -- 'signaturesUse'
  forM_ used $ \(public, bytes) -> do
    TxSignature signature _ <- eitherToMaybe (decodeTxSig net bytes)
    guard (public.compress || not witnessCoin)
    guard (verifyHashSig digest signature public.point)
  let items = case spend.naming of
        PayPK _ -> map snd used
        PayMulSig _ _ -> B.empty : map snd used
        _ -> concat [[signature, encodeSerial public] | (public, signature) <- used]
      redeemItem = S.encode <$> maybeToList spend.redeemScript
      witnessItem = S.encode <$> maybeToList spend.witnessScript
      pushes = S.encode . Script . map opPushData
  return $
    if witnessCoin
      then (pushes redeemItem, items <> witnessItem)
      else (pushes (items <> redeemItem), [])

-- | The signatures that a script takes, among those of the keys it names:
-- the one of its key, or for a multisig those of its first keys that have
-- one, in the order of the script and as many as it requires, which is
-- the choice of Bitcoin Core (@SignStep@). 'Nothing' when they do not
-- suffice.
usedSignatures :: ScriptOutput -> [(PublicKey, ByteString)] -> Maybe [(PublicKey, ByteString)]
usedSignatures naming named = case naming of
  PayPK public -> (: []) . (public,) <$> lookup public named
  PayPKHash h -> (: []) <$> ofHash h
  PayWitnessPKHash h -> (: []) <$> ofHash h
  PayMulSig keys n
    | length found >= n -> Just (take n found)
    where
      found = [(key, signature) | key <- keys, Just signature <- [lookup key named]]
  _ -> Nothing
  where
    ofHash h = find ((== h) . addressHash . encodeSerial . fst) named

-- | The partial signatures of an input whose keys the script names, in
-- the order of the map. A key is named by a script of public keys when it
-- is one of them, and by a script of a key hash when it has that hash.
-- The others are not looked at, so their number costs nothing.
namedSignatures :: PsbtMap -> ScriptOutput -> [(PublicKey, ByteString)]
namedSignatures m script =
  [ (public, sig)
  | (key, sig) <- Map.toAscList m,
    key.keyType == partialSigType,
    addressHash key.keyData `elem` named,
    Right public <- [decodeSerial key.keyData]
  ]
  where
    named = scriptKeyHashes script

-- | The final witness of a Taproot input: its key path signature, or the
-- signature of a leaf script that is the check of one key, with the
-- script and its control block. The witness is the one Bitcoin Core makes
-- (@SignTaproot@): the key path signature when the input has one, and
-- otherwise the leaf of 'smallestSignedLeaf'. 'Nothing' leaves the input
-- as it is: when it has no signature to use, when the signature does not
-- verify or the control block does not commit the leaf to the coin, when
-- the output key is no point of the curve, and while another input lacks
-- its coin, since the signature cannot be verified before.
finalTaproot :: Maybe TaprootTxHashes -> Int -> PsbtMap -> TxOut -> Maybe (ByteString, WitnessStack)
finalTaproot hashesM i m coin = do
  hashes <- hashesM
  outKey <- importXOnlyPubKey (taprootProgram coin)
  let verified public leafM bytes = do
        signature <- eitherToMaybe (decodeTaprootSig bytes)
        digest <- eitherToMaybe (taprootSigHashWith hashes i signature.hash Nothing ((,0xffffffff) <$> leafM))
        guard (verifySchnorr public signature.sig (hashToMsg digest))
  (B.empty,) <$> case plainField tapKeySigType m of
    Just bytes -> [bytes] <$ verified outKey Nothing bytes
    Nothing -> do
      (script, control, bytes) <- smallestSignedLeaf m
      leafKey <- importXOnlyPubKey (leafKeyBytes script)
      guard (commitsLeaf outKey control script)
      [bytes, script, control] <$ verified leafKey (Just (leafHashBytes tapscriptLeafVersion script)) bytes

-- | The signed leaf of a Taproot input that Bitcoin Core spends
-- (@SignTaproot@): its script, its control block and its signature. A leaf
-- is signed when the input has a signature entry for its key and its leaf
-- hash. Bitcoin Core takes each leaf with its shortest control block, and
-- among the leaves the one whose witness is smallest. The leaves of
-- 'singleKeyLeaves' have scripts of one size, and all the signatures of an
-- input have one size ('signaturesUse'), so that is the leaf with the
-- shortest control block. Among equals the first counts: by the bytes of
-- the script for the leaves, and by the bytes for the control blocks.
--
-- A leaf finds its signature by a lookup: a walk through the signatures
-- for each leaf would take time by the product of two numbers that whoever
-- wrote the PSBT chooses.
smallestSignedLeaf :: PsbtMap -> Maybe (ByteString, ByteString, ByteString)
smallestSignedLeaf m
  | null signed = Nothing
  | otherwise = Just (minimumBy (comparing (\(_, control, _) -> B.length control)) signed)
  where
    signed =
      [ (script, minimumBy (comparing B.length <> compare) controls, signature)
      | (script, controls) <- Map.toAscList (singleKeyLeaves m),
        Just signature <- [Map.lookup (tapScriptSigKey (leafKeyBytes script) (leafHashBytes tapscriptLeafVersion script)) m]
      ]
