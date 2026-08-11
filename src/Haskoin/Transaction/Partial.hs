{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Transaction.Partial
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : matt@bitnomial.com
-- Stability   : experimental
-- Portability : POSIX
--
-- Code related to PSBT parsing and serialization.
module Haskoin.Transaction.Partial
  ( -- * Partially-Signed Transactions
    PSBT (..),
    getPSBT,
    putPSBT,
    Input (..),
    getInput,
    putInput,
    Output (..),
    getOutput,
    putOutput,
    UnknownMap (..),
    Key (..),
    merge,
    mergeMany,
    mergeInput,
    mergeOutput,
    complete,
    finalTransaction,
    emptyPSBT,
    emptyInput,
    emptyOutput,

    -- ** Signing
    PSBTSigner,
    getSignerKey,
    secKeySigner,
    xPrvSigner,
    signPSBT,
  )
where

import Control.Applicative ((<|>))
import Control.DeepSeq (NFData)
import Control.Monad (foldM, guard, replicateM, unless, void)
import Crypto.Secp256k1
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial (Serial (..))
import Data.Either (fromRight)
import Data.HashMap.Strict (HashMap)
import Data.HashMap.Strict qualified as HashMap
import Data.Hashable (Hashable)
import Data.List (foldl')
import Data.Maybe (fromMaybe, isJust)
import Data.Serialize (Get, Put, Serialize (..))
import Data.Serialize qualified as S
import Data.String.Conversions (cs)
import GHC.Generics (Generic)
import GHC.Word (Word32, Word8)
import Haskoin.Address (Address, pubKeyAddr, pubKeyAddress)
import Haskoin.Crypto.Keys.Common
import Haskoin.Crypto.Keys.Extended
import Haskoin.Network.Common
import Haskoin.Network.Data
import Haskoin.Script.Common
import Haskoin.Script.SigHash
import Haskoin.Script.Standard
import Haskoin.Transaction.Builder.Sign
import Haskoin.Transaction.Common
import Haskoin.Transaction.Segwit
import Haskoin.Util
import Numeric (showHex)

-- | PSBT data type as specified in
-- [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki).
-- This contains an unsigned transaction, inputs and outputs, and unspecified
-- extra data. There is one input per input in the unsigned transaction, and one
-- output per output in the unsigned transaction. The inputs and outputs in the
-- 'PSBT' line up by index with the inputs and outputs in
-- the unsigned transaction.
data PSBT = PSBT
  { unsignedTransaction :: Tx,
    globalUnknown :: UnknownMap,
    inputs :: [Input],
    outputs :: [Output]
  }
  deriving (Show, Read, Eq, Generic)
  deriving anyclass (NFData)

-- | Inputs contain all of the data needed to sign a transaction and all of the
-- resulting signature data after signing.
data Input = Input
  { nonWitnessUtxo :: Maybe Tx,
    witnessUtxo :: Maybe TxOut,
    partialSigs :: HashMap PublicKey ByteString,
    sigHashType :: Maybe SigHash,
    inputRedeemScript :: Maybe Script,
    inputWitnessScript :: Maybe Script,
    inputHDKeypaths :: HashMap PublicKey (Fingerprint, [KeyIndex]),
    finalScriptSig :: Maybe Script,
    finalScriptWitness :: Maybe WitnessStack,
    inputUnknown :: UnknownMap
  }
  deriving (Show, Read, Eq, Generic)
  deriving anyclass (NFData)

-- | Outputs can contain information needed to spend the output at a later date.
data Output = Output
  { outputRedeemScript :: Maybe Script,
    outputWitnessScript :: Maybe Script,
    outputHDKeypaths :: HashMap PublicKey (Fingerprint, [KeyIndex]),
    outputUnknown :: UnknownMap
  }
  deriving (Show, Read, Eq, Generic)
  deriving anyclass (NFData)

-- | A map of raw PSBT keys to byte strings for extra data. The 'keyType' field
-- cannot overlap with any of the reserved 'keyType' fields specified in the
-- PSBT specification.
newtype UnknownMap = UnknownMap {unknownMap :: HashMap Key ByteString}
  deriving (Show, Read, Eq, Generic)
  deriving newtype (Semigroup, Monoid, NFData)

-- | Raw keys for the map type used in PSBTs.
data Key = Key
  { keyType :: Word8,
    key :: ByteString
  }
  deriving (Show, Read, Eq, Generic, NFData, Hashable)

-- | Take two 'PSBT's and merge them. The
-- 'unsignedTransaction' field in both must be the same.
merge ::
  PSBT ->
  PSBT ->
  Maybe PSBT
merge psbt1 psbt2
  | psbt1.unsignedTransaction == psbt2.unsignedTransaction =
      Just $
        psbt1
          { globalUnknown = psbt1.globalUnknown <> psbt2.globalUnknown,
            inputs = zipWith mergeInput psbt1.inputs psbt2.inputs,
            outputs = zipWith mergeOutput psbt1.outputs psbt2.outputs
          }
merge _ _ = Nothing

-- | A version of 'merge' for a collection of PSBTs.
--
-- @since 0.21.0
mergeMany :: [PSBT] -> Maybe PSBT
mergeMany (psbt : psbts) = foldM merge psbt psbts
mergeMany _ = Nothing

mergeInput :: Input -> Input -> Input
mergeInput a b =
  Input
    { nonWitnessUtxo =
        if isJust witUtx
          then Nothing
          else a.nonWitnessUtxo <|> b.nonWitnessUtxo,
      witnessUtxo =
        witUtx,
      sigHashType =
        a.sigHashType <|> b.sigHashType,
      partialSigs =
        a.partialSigs <> b.partialSigs,
      inputHDKeypaths =
        a.inputHDKeypaths <> b.inputHDKeypaths,
      inputUnknown =
        a.inputUnknown <> b.inputUnknown,
      inputRedeemScript =
        a.inputRedeemScript <|> b.inputRedeemScript,
      inputWitnessScript =
        a.inputWitnessScript <|> b.inputWitnessScript,
      finalScriptSig =
        a.finalScriptSig <|> b.finalScriptSig,
      finalScriptWitness =
        a.finalScriptWitness <|> b.finalScriptWitness
    }
  where
    witUtx = a.witnessUtxo <|> b.witnessUtxo

mergeOutput :: Output -> Output -> Output
mergeOutput a b =
  Output
    { outputRedeemScript =
        a.outputRedeemScript <|> b.outputRedeemScript,
      outputWitnessScript =
        a.outputWitnessScript <|> b.outputWitnessScript,
      outputHDKeypaths =
        a.outputHDKeypaths <> b.outputHDKeypaths,
      outputUnknown =
        a.outputUnknown <> b.outputUnknown
    }

-- | A abstraction which covers varying key configurations.  Use the 'Semigroup'
-- instance to create signers for sets of keys: `signerA <> signerB` can sign
-- anything for which `signerA` or `signerB` could sign.
--
-- @since 0.21@
newtype PSBTSigner = PSBTSigner
  { unPSBTSigner ::
      PublicKey ->
      Maybe (Fingerprint, DerivPath) ->
      Maybe SecKey
  }

instance Semigroup PSBTSigner where
  PSBTSigner signer1 <> PSBTSigner signer2 =
    PSBTSigner $ \pubKey origin ->
      signer1 pubKey origin <|> signer2 pubKey origin

instance Monoid PSBTSigner where
  mempty = PSBTSigner $ \_ _ -> Nothing

-- | Fetch the secret key for the given 'PublicKey' if possible.
--
-- @since 0.21@
getSignerKey :: PSBTSigner -> PublicKey -> Maybe (Fingerprint, DerivPath) -> Maybe SecKey
getSignerKey = (.unPSBTSigner)

-- | This signer can sign for one key.
--
-- @since 0.21@
secKeySigner :: Ctx -> SecKey -> PSBTSigner
secKeySigner ctx theSecKey =
  PSBTSigner signer
  where
    signer requiredKey _
      | requiredKey.point == derivePubKey ctx theSecKey = Just theSecKey
      | otherwise = Nothing

-- | This signer can sign with any child key, provided that derivation information is present.
--
-- @since 0.21@
xPrvSigner ::
  Ctx ->
  XPrvKey ->
  -- | Origin data, if the input key is explicitly a child key
  Maybe (Fingerprint, DerivPath) ->
  PSBTSigner
xPrvSigner ctx xprv origin = PSBTSigner signer
  where
    signer pubKey (Just hdData)
      | result@(Just theSecKey) <- maybe noOrigin onOrigin origin hdData,
        pubKey.point == derivePubKey ctx theSecKey =
          result
    signer _ _ = Nothing

    noOrigin (fp, path)
      | thisFP == fp = Just $ deriveSecKey path
      | otherwise = Nothing

    onOrigin (originFP, originPath) (fp, path)
      | thisFP == fp = Just $ deriveSecKey path
      | originFP == fp =
          deriveSecKey <$> adjustPath (pathToList originPath) (pathToList path)
      | otherwise = Nothing

    deriveSecKey path = (derivePath ctx path xprv).key

    thisFP = xPubFP ctx $ deriveXPubKey ctx xprv

    -- The origin path should be a prefix of the target path if we match the
    -- origin fingerprint.  We need to remove this prefix.
    adjustPath :: [KeyIndex] -> [KeyIndex] -> Maybe DerivPath
    adjustPath (originIx : originTail) (thisIx : thisTail)
      | originIx == thisIx = adjustPath originTail thisTail
      | otherwise = Nothing
    adjustPath [] thePath = Just $ listToPath thePath
    adjustPath _ _ = Nothing

-- | Update a PSBT with signatures when possible.  This function uses
-- 'inputHDKeypaths' in order to calculate secret keys.
--
-- @since 0.21@
signPSBT ::
  Network ->
  Ctx ->
  PSBTSigner ->
  PSBT ->
  PSBT
signPSBT net ctx signer PSBT {..} =
  PSBT {inputs = f <$> zip [0 ..] inputs, ..}
  where
    f = addSigsForInput net ctx signer unsignedTransaction

addSigsForInput :: Network -> Ctx -> PSBTSigner -> Tx -> (Int, Input) -> Input
addSigsForInput net ctx signer tx (ix, input) =
  maybe input (onPrevTxOut net ctx signer tx ix input) $
    Left <$> input.nonWitnessUtxo <|> Right <$> input.witnessUtxo

onPrevTxOut ::
  Network ->
  Ctx ->
  PSBTSigner ->
  Tx ->
  Int ->
  Input ->
  Either Tx TxOut ->
  Input
onPrevTxOut net ctx signer tx ix input prevTxData =
  input
    { partialSigs = newSigs <> input.partialSigs
    }
  where
    newSigs = HashMap.mapWithKey sigForInput sigKeys
    sigForInput thePubKey theSecKey =
      encodeTxSig net ctx . makeSignature net ctx tx ix theSigInput $
        PrivateKey theSecKey thePubKey.compress

    theSigInput =
      SigInput
        { -- Must be the segwit input script for segwit spends (even nested)
          script = fromMaybe theInputScript segwitInput,
          value = prevTxOut.value,
          outpoint = thePrevOutPoint,
          sighash = fromMaybe sigHashAll input.sigHashType,
          -- Must be the witness script for segwit spends (even nested)
          redeem = theWitnessScript <|> theRedeemScript
        }

    prevTxOut =
      let rf = ((!! (fromIntegral . (.index)) thePrevOutPoint) . (.outputs))
       in either rf id prevTxData
    thePrevOutPoint = (tx.inputs !! ix).outpoint

    segwitInput = justWhen isSegwit theInputScript <|> (justWhen isSegwit =<< theRedeemScript)

    theInputScript = fromRight inputScriptErr $ (unmarshal ctx . (.script)) prevTxOut
    inputScriptErr = error "addSigsForInput: Unable to decode input script"

    theRedeemScript = case decodeOutput ctx <$> input.inputRedeemScript of
      Just (Right script) -> Just script
      Just Left {} -> error "addSigsForInput: Unable to decode redeem script"
      _ -> Nothing

    theWitnessScript = case decodeOutput ctx <$> input.inputWitnessScript of
      Just (Right script) -> Just script
      Just Left {} -> error "addSigsForInput: Unable to decode witness script"
      _ -> Nothing

    sigKeys = HashMap.mapMaybeWithKey getSignerKey input.inputHDKeypaths
    getSignerKey pubKey (fp, ixs) = (.unPSBTSigner) signer pubKey $ Just (fp, listToPath ixs)

-- | Take partial signatures from all of the 'Input's and finalize the signature.
complete ::
  Ctx ->
  PSBT ->
  PSBT
complete ctx PSBT {..} =
  PSBT {inputs = map (completeInput . analyzeInputs) (indexed inputs), ..}
  where
    analyzeInputs (i, input) =
      (,)
        (outputScript =<< input.witnessUtxo <|> nonWitScript)
        input
      where
        nonWitScript = getPrevOut i =<< input.nonWitnessUtxo

    getPrevOut i tx =
      (tx.outputs !!?) . fromIntegral . (.outpoint.index)
        =<< unsignedTransaction.inputs !!? i
    xs !!? i = lookup i $ indexed xs

    outputScript = eitherToMaybe . unmarshal ctx . (.script)

    completeInput (Nothing, input) = input
    completeInput (Just script, input) = pruneInputFields $ completeSig ctx input script

    -- If we have final scripts, we can get rid of data for signing following
    -- the Bitcoin Core implementation.
    pruneInputFields input
      | isJust input.finalScriptSig || isJust input.finalScriptWitness =
          input
            { partialSigs = mempty,
              inputHDKeypaths = mempty,
              inputRedeemScript = Nothing,
              inputWitnessScript = Nothing,
              sigHashType = Nothing
            }
      | otherwise = input

    indexed :: [a] -> [(Word32, a)]
    indexed = zip [0 ..]

completeSig :: Ctx -> Input -> ScriptOutput -> Input
completeSig ctx input (PayPK k) =
  input
    { finalScriptSig =
        eitherToMaybe . runGetS deserialize
          =<< HashMap.lookup k input.partialSigs
    }
completeSig ctx input (PayPKHash h)
  | [(k, sig)] <- HashMap.toList input.partialSigs,
    pubKeyAddress h == pubKeyAddr ctx k =
      input
        { finalScriptSig =
            Just $
              Script
                [ opPushData sig,
                  opPushData (marshal ctx k)
                ]
        }
completeSig ctx input (PayMulSig pubKeys m)
  | length sigs >= m =
      input {finalScriptSig = Just finalSig}
  where
    sigs = collectSigs m pubKeys input
    finalSig = Script $ OP_0 : map opPushData sigs
completeSig ctx input (PayScriptHash h)
  | Just rdmScript <- input.inputRedeemScript,
    PayScriptHash h == toP2SH rdmScript,
    Right decodedScript <- decodeOutput ctx rdmScript,
    not (isPayScriptHash decodedScript) =
      pushScript rdmScript $ completeSig ctx input decodedScript
  where
    pushScript rdmScript updatedInput =
      updatedInput
        { finalScriptSig =
            Just $
              fromMaybe (Script mempty) updatedInput.finalScriptSig
                `scriptAppend` serializedRedeemScript rdmScript
        }
    scriptAppend (Script script1) (Script script2) = Script $ script1 <> script2
completeSig ctx input (PayWitnessPKHash h)
  | [(k, sig)] <- HashMap.toList input.partialSigs,
    pubKeyAddress h == pubKeyAddr ctx k =
      input {finalScriptWitness = Just [sig, marshal ctx k]}
completeSig ctx input (PayWitnessScriptHash h)
  | Just witScript <- input.inputWitnessScript,
    PayWitnessScriptHash h == toP2WSH witScript,
    Right decodedScript <- decodeOutput ctx witScript =
      completeWitnessSig ctx input decodedScript
completeSig _ input _ = input

serializedRedeemScript :: Script -> Script
serializedRedeemScript = Script . pure . opPushData . runPutS . serialize

completeWitnessSig :: Ctx -> Input -> ScriptOutput -> Input
completeWitnessSig ctx input script@(PayMulSig pubKeys m)
  | length sigs >= m =
      input {finalScriptWitness = Just finalWit}
  where
    sigs = collectSigs m pubKeys input
    finalWit = mempty : sigs <> [marshal ctx script]
completeWitnessSig _ input _ = input

collectSigs :: Int -> [PublicKey] -> Input -> [ByteString]
collectSigs m pubKeys input =
  take m . reverse $ foldl' lookupKey [] pubKeys
  where
    lookupKey sigs key =
      maybe sigs (: sigs) $
        HashMap.lookup key input.partialSigs

-- | Take a finalized 'PSBT' and produce the signed final
-- transaction. You may need to call 'complete' on the
-- 'PSBT' before producing the final transaction.
finalTransaction :: PSBT -> Tx
finalTransaction psbt =
  setInputs
    . foldl' finalizeInput ([], [])
    $ zip tx.inputs psbt.inputs
  where
    tx = psbt.unsignedTransaction
    hasWitness = any (isJust . (.finalScriptWitness)) psbt.inputs
    setInputs (ins, witData) =
      tx
        { inputs = reverse ins,
          witness = if hasWitness then reverse witData else []
        }
    finalizeInput (ins, witData) (TxIn {..}, psbtInput) =
      ( TxIn
          { script =
              maybe
                mempty
                (runPutS . serialize)
                psbtInput.finalScriptSig,
            ..
          }
          : ins,
        fromMaybe [] psbtInput.finalScriptWitness : witData
      )

-- | Take an unsigned transaction and produce an empty
-- 'PSBT'
emptyPSBT :: Tx -> PSBT
emptyPSBT tx =
  PSBT
    { unsignedTransaction = tx,
      globalUnknown = mempty,
      inputs = replicate (length tx.inputs) emptyInput,
      outputs = replicate (length tx.outputs) emptyOutput
    }

emptyInput :: Input
emptyInput =
  Input
    Nothing
    Nothing
    HashMap.empty
    Nothing
    Nothing
    Nothing
    HashMap.empty
    Nothing
    Nothing
    (UnknownMap HashMap.empty)

emptyOutput :: Output
emptyOutput = Output Nothing Nothing HashMap.empty (UnknownMap HashMap.empty)

getPSBT :: (MonadGet m) => Ctx -> m PSBT
getPSBT ctx = do
  magic <- getBytes 4
  unless (magic == "psbt") $
    fail $
      "Expected magic = 'psbt' but got '" ++ cs magic ++ "'"
  headerSep <- getWord8
  unless (headerSep == 0xff) $
    fail $
      "Expected headerSep = 0xff but got 0x" ++ showHex headerSep ""

  keySize <- getWord8
  unless (keySize == 1) $
    fail $
      "Expected keySize = 1 but got " ++ show keySize
  globalUnsignedTxType <- getWord8
  unless (globalUnsignedTxType == 0x00) $
    fail $
      "Expected globalUnsignedTxType = 0x00 but got 0x"
        ++ showHex globalUnsignedTxType ""
  unsignedTransaction <- getSizedBytes deserialize
  unless (all (B.null . (.script)) unsignedTransaction.inputs) $
    fail $
      "Not all inputs from unsignedTransaction have empty scripts"
  unless (null unsignedTransaction.witness) $
    fail $
      "Not all witnesses from unsignedTransaction are empty"

  globalUnknown <- deserialize
  globalEnd <- getWord8
  unless (globalEnd == 0x00) $
    fail $
      "Expected globalEnd == 0x00 but got 0x" ++ showHex globalEnd ""

  inputs <-
    replicateM
      (length unsignedTransaction.inputs)
      (getInput ctx)
  outputs <-
    replicateM
      (length unsignedTransaction.outputs)
      (getOutput ctx)

  return
    PSBT
      { unsignedTransaction,
        globalUnknown,
        inputs,
        outputs
      }

putPSBT :: (MonadPut m) => Ctx -> PSBT -> m ()
putPSBT
  ctx
  PSBT
    { unsignedTransaction,
      globalUnknown,
      inputs,
      outputs
    } = do
    putByteString "psbt"
    putWord8 0xff -- Header separator
    putWord8 0x01 -- Key size
    putWord8 0x00 -- Unsigned Transaction type
    putSizedBytes $ S.encode unsignedTransaction
    serialize globalUnknown
    putWord8 0x00 -- Global end
    mapM_ (putInput ctx) inputs
    mapM_ (putOutput ctx) outputs

instance Serial Key where
  deserialize = do
    VarInt keySize <- deserialize
    unless (keySize > 0) $
      fail $
        "Expected keySize > 0 but got " ++ show keySize
    t <- getWord8
    k <- getBytes (fromIntegral keySize - 1)
    return (Key t k)

  serialize (Key t k) = do
    putVarInt $ 1 + B.length k
    putWord8 t
    putByteString k

instance Binary Key where
  put = serialize
  get = deserialize

instance Serialize Key where
  put = serialize
  get = deserialize

instance Serial UnknownMap where
  deserialize = go HashMap.empty
    where
      getItem m = do
        k <- deserialize
        VarString v <- deserialize
        go $ HashMap.insert k v m
      go m = do
        isEnd <- lookAhead getWord8
        if isEnd == 0x00
          then return (UnknownMap m)
          else getItem m

  serialize (UnknownMap m) =
    void $
      HashMap.traverseWithKey
        (\k v -> serialize k >> serialize (VarString v))
        m

getInput :: (MonadGet m) => Ctx -> m Input
getInput ctx =
  getMap (getInputItem ctx) setInputUnknown emptyInput
  where
    setInputUnknown f input =
      input
        { inputUnknown =
            UnknownMap (f input.inputUnknown.unknownMap)
        }

putInput :: (MonadPut m) => Ctx -> Input -> m ()
putInput
  ctx
  Input
    { nonWitnessUtxo,
      witnessUtxo,
      partialSigs,
      sigHashType,
      inputRedeemScript,
      inputWitnessScript,
      inputHDKeypaths,
      finalScriptSig,
      finalScriptWitness,
      inputUnknown
    } = do
    whenJust
      (putKeyValue InNonWitnessUtxo . S.encode)
      nonWitnessUtxo
    whenJust
      (putKeyValue InWitnessUtxo . S.encode)
      witnessUtxo
    putPartialSig partialSigs
    whenJust
      putSigHash
      sigHashType
    whenJust
      (putKeyValue InRedeemScript . S.encode)
      inputRedeemScript
    whenJust
      (putKeyValue InWitnessScript . S.encode)
      inputWitnessScript
    putHDPath ctx InBIP32Derivation inputHDKeypaths
    whenJust
      (putKeyValue InFinalScriptSig . S.encode)
      finalScriptSig
    whenJust
      (putKeyValue InFinalScriptWitness . putFinalScriptWitness)
      finalScriptWitness
    serialize inputUnknown
    putWord8 0x00
    where
      putPartialSig =
        putPubKeyMap ctx serialize InPartialSig . fmap VarString
      putSigHash sigHash = do
        putKey InSigHashType
        putWord8 0x04
        putWord32le (fromIntegral sigHash)
      putFinalScriptWitness witnessStack = runPutS $ do
        serialize $ (VarInt . fromIntegral . length) witnessStack
        mapM_ (serialize . VarString) witnessStack

getOutput :: (MonadGet m) => Ctx -> m Output
getOutput ctx = getMap (getOutputItem ctx) setOutputUnknown emptyOutput
  where
    setOutputUnknown f output =
      output
        { outputUnknown =
            UnknownMap (f output.outputUnknown.unknownMap)
        }

putOutput :: (MonadPut m) => Ctx -> Output -> m ()
putOutput
  ctx
  Output
    { outputRedeemScript,
      outputWitnessScript,
      outputHDKeypaths,
      outputUnknown
    } = do
    whenJust
      (putKeyValue OutRedeemScript . S.encode)
      outputRedeemScript
    whenJust
      (putKeyValue OutWitnessScript . S.encode)
      outputWitnessScript
    putHDPath
      ctx
      OutBIP32Derivation
      outputHDKeypaths
    serialize outputUnknown
    putWord8 0x00

putSizedBytes :: (MonadPut m) => ByteString -> m ()
putSizedBytes bs = do
  putVarInt (B.length bs)
  putByteString bs

getSizedBytes :: (MonadGet m) => Get a -> m a
getSizedBytes =
  getNested $ (\(VarInt i) -> fromIntegral i) <$> deserialize

putKeyValue :: (Enum t, MonadPut m) => t -> ByteString -> m ()
putKeyValue t v = do
  putKey t
  putSizedBytes v

putKey :: (Enum t, MonadPut m) => t -> m ()
putKey t = do
  putVarInt (1 :: Word8)
  putWord8 (enumWord8 t)

getMap ::
  (Bounded t, Enum t, MonadGet m) =>
  (Int -> a -> t -> m a) ->
  ((HashMap Key ByteString -> HashMap Key ByteString) -> a -> a) ->
  a ->
  m a
getMap getMapItem setUnknown = go
  where
    getItem keySize m (Right t) =
      getMapItem (fromIntegral keySize - 1) m t >>= go
    getItem keySize m (Left t) = do
      k <- getBytes (fromIntegral keySize - 1)
      VarString v <- deserialize
      go $ setUnknown (HashMap.insert (Key t k) v) m
    go m = do
      keySize <- (\(VarInt i) -> i) <$> deserialize
      if keySize == 0
        then return m
        else getItem keySize m . word8Enum =<< getWord8

data InputType
  = InNonWitnessUtxo
  | InWitnessUtxo
  | InPartialSig
  | InSigHashType
  | InRedeemScript
  | InWitnessScript
  | InBIP32Derivation
  | InFinalScriptSig
  | InFinalScriptWitness
  deriving (Show, Eq, Enum, Bounded, Generic)
  deriving anyclass (NFData)

data OutputType
  = OutRedeemScript
  | OutWitnessScript
  | OutBIP32Derivation
  deriving (Show, Eq, Enum, Bounded, Generic)
  deriving anyclass (NFData)

getInputItem ::
  (MonadGet m) =>
  Ctx ->
  Int ->
  Input ->
  InputType ->
  m Input
getInputItem ctx 0 input@Input {nonWitnessUtxo = Nothing} InNonWitnessUtxo = do
  utxo <- getSizedBytes deserialize
  return input {nonWitnessUtxo = Just utxo}
getInputItem ctx 0 input@Input {witnessUtxo = Nothing} InWitnessUtxo = do
  utxo <- getSizedBytes deserialize
  return input {witnessUtxo = Just utxo}
getInputItem ctx keySize input InPartialSig = do
  (k, v) <- getPartialSig
  return
    input
      { partialSigs = HashMap.insert k v input.partialSigs
      }
  where
    getPartialSig =
      (,)
        <$> isolate keySize (marshalGet ctx :: Get PublicKey)
        <*> ((\(VarString s) -> s) <$> deserialize)
getInputItem ctx 0 input@Input {sigHashType = Nothing} InSigHashType = do
  VarInt size <- deserialize
  unless (size == 0x04) $
    fail $
      "Expected size == 0x04 but got 0x" ++ showHex size ""
  sigHash <- fromIntegral <$> getWord32le
  return $ input {sigHashType = Just sigHash}
getInputItem ctx 0 input@Input {inputRedeemScript = Nothing} InRedeemScript = do
  script <- getSizedBytes deserialize
  return $ input {inputRedeemScript = Just script}
getInputItem ctx 0 input@Input {inputWitnessScript = Nothing} InWitnessScript = do
  script <- getSizedBytes deserialize
  return $ input {inputWitnessScript = Just script}
getInputItem ctx keySize input InBIP32Derivation = do
  (k, v) <- getHDPath ctx keySize
  return
    input
      { inputHDKeypaths = HashMap.insert k v input.inputHDKeypaths
      }
getInputItem ctx 0 input@Input {finalScriptSig = Nothing} InFinalScriptSig = do
  script <- getSizedBytes deserialize
  return $ input {finalScriptSig = Just script}
getInputItem ctx 0 input@Input {finalScriptWitness = Nothing} InFinalScriptWitness = do
  scripts <- map (\(VarString s) -> s) <$> getVarIntList
  return $ input {finalScriptWitness = Just scripts}
  where
    getVarIntList = getSizedBytes $ do
      VarInt n <- deserialize -- Item count
      replicateM (fromIntegral n) deserialize
getInputItem ctx keySize input inputType =
  fail "Incorrect key size for input item or item already existed"

getOutputItem :: (MonadGet m) => Ctx -> Int -> Output -> OutputType -> m Output
getOutputItem ctx 0 output@Output {outputRedeemScript = Nothing} OutRedeemScript = do
  script <- getSizedBytes deserialize
  return $ output {outputRedeemScript = Just script}
getOutputItem ctx 0 output@Output {outputWitnessScript = Nothing} OutWitnessScript = do
  script <- getSizedBytes deserialize
  return $ output {outputWitnessScript = Just script}
getOutputItem ctx keySize output OutBIP32Derivation = do
  (k, v) <- getHDPath ctx keySize
  return $ output {outputHDKeypaths = HashMap.insert k v output.outputHDKeypaths}
getOutputItem ctx keySize output outputType =
  fail "Incorrect key size for output item or item already existed"

getHDPath ::
  forall m.
  (MonadGet m) =>
  Ctx ->
  Int ->
  m (PublicKey, (Fingerprint, [KeyIndex]))
getHDPath ctx keySize =
  (,)
    <$> isolate keySize (marshalGet ctx :: Get PublicKey)
    <*> ((\(PSBTHDPath s) -> s) <$> deserialize)

putHDPath ::
  (Enum t, MonadPut m) =>
  Ctx ->
  t ->
  HashMap PublicKey (Fingerprint, [KeyIndex]) ->
  m ()
putHDPath ctx t = putPubKeyMap ctx serialize t . fmap PSBTHDPath

newtype PSBTHDPath = PSBTHDPath {unPSBTHDPath :: (Fingerprint, [KeyIndex])}
  deriving (Show, Eq, Generic)
  deriving newtype (NFData)

instance Serial PSBTHDPath where
  deserialize = do
    VarInt valueSize <- deserialize
    unless (valueSize `mod` 4 == 0) $
      fail $
        "Expected valueSize = 4 but got " ++ show valueSize
    let numIndices = (fromIntegral valueSize - 4) `div` 4
    PSBTHDPath
      <$> isolate
        (fromIntegral valueSize)
        ((,) <$> deserialize <*> getKeyIndexList numIndices)
    where
      getKeyIndexList n = replicateM n getWord32le

  serialize (PSBTHDPath (fp, kis)) = do
    putVarInt (B.length bs)
    putByteString bs
    where
      bs = runPutS $ serialize fp >> mapM_ putWord32le kis

instance Binary PSBTHDPath where
  put = serialize
  get = deserialize

instance Serialize PSBTHDPath where
  put = serialize
  get = deserialize

putPubKeyMap ::
  (Enum t, MonadPut m) =>
  Ctx ->
  (a -> m ()) ->
  t ->
  HashMap PublicKey a ->
  m ()
putPubKeyMap ctx f t =
  void . HashMap.traverseWithKey putItem
  where
    putItem k v = do
      serialize $ Key (enumWord8 t) (marshal ctx k)
      f v

enumWord8 :: (Enum a) => a -> Word8
enumWord8 = fromIntegral . fromEnum

word8Enum :: forall a. (Bounded a, Enum a) => Word8 -> Either Word8 a
word8Enum n | n <= enumWord8 (maxBound :: a) = Right . toEnum $ fromIntegral n
word8Enum n = Left n

whenJust :: (Monad m) => (a -> m ()) -> Maybe a -> m ()
whenJust = maybe (return ())

justWhen :: (a -> Bool) -> a -> Maybe a
justWhen test x = if test x then Just x else Nothing

isolate :: (MonadGet m) => Int -> Get a -> m a
isolate length getVal = do
  bs <- getByteString length
  either fail return (runGetS getVal bs)

getNested :: (MonadGet m) => m Int -> Get a -> m a
getNested getLength getVal = do
  length <- getLength
  isolate length getVal
