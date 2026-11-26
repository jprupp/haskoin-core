{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Transaction.Builder.Sign
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Types and logic for signing transactions.
module Haskoin.Transaction.Builder.Sign
  ( SigInput (..),
    makeSignature,
    makeSignatureWith,
    makeSigHash,
    makeSigHashWith,
    signTx,
    findInputIndex,
    signInput,
    signTaprootInput,
    buildInput,
    inputSpends,
    sigKeys,
  )
where

import Control.DeepSeq
import Control.Monad
import Crypto.Secp256k1
import Data.Aeson
import Data.Aeson.Encoding
import qualified Data.ByteString as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Either
import Data.Hashable
import Data.List
import qualified Data.Map.Strict as Map
import Data.Maybe
import qualified Data.Vector as V
import Data.Word
import GHC.Generics
import Haskoin.Address
import Haskoin.Crypto.Hash
import Haskoin.Crypto.Keys.Common
import Haskoin.Crypto.Signature
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction.Common
import Haskoin.Transaction.Segwit
import Haskoin.Transaction.Taproot
import Haskoin.Util

-- | Data type used to specify the signing parameters of a transaction input.
-- To sign an input, the previous output script, outpoint and sighash are
-- required. When signing a pay to script hash output, an additional redeem
-- script is required. A Taproot output ('PayWitness' version 1) is signed
-- by its key path, with 'sigHashDefault' or one of the hash types
-- 'isTaprootSigHash' accepts.
--
-- A 'SigInput' is an instruction to the signer, and the signer follows it.
-- When it comes from someone else, for example as JSON, check it first:
--
-- * The hash type. Any type a node accepts is signed, including
--   'sigHashNone' and 'sigHashSingle', which leave outputs unsigned.
-- * The value of a legacy coin. The legacy digest does not commit to it, so
--   a wrong value still gives a valid signature, and the fee is then not
--   what the value suggests. Only the previous transaction settles it.
--   The digests of SegWit, Taproot and Bitcoin Cash commit to the value.
data SigInput = SigInput
  { -- | output script to spend
    script :: !ScriptOutput,
    -- | output script value
    value :: !Word64,
    -- | outpoint to spend
    outpoint :: !OutPoint,
    -- | signature type
    sighash :: !SigHash,
    -- | redeem script
    redeem :: !(Maybe RedeemScript)
  }
  deriving (Show, Read, Eq, Generic, NFData)

instance ToJSON SigInput where
  toJSON (SigInput s v o h r) =
    object $
      [ "pkscript" .= toJSON s,
        "value" .= v,
        "outpoint" .= o,
        "sighash" .= h
      ]
        ++ [ "redeem" .= toJSON r
           | r <- maybeToList r
           ]

  toEncoding (SigInput s v o h r) =
    pairs $
      mconcat
        [ "pkscript" `pair` toEncoding s,
          "value" `pair` word64 v,
          "outpoint" `pair` toEncoding o,
          "sighash" `pair` toEncoding h,
          maybe mempty (pair "redeem" . toEncoding) r
        ]

instance FromJSON SigInput where
  parseJSON =
    withObject "SigInput" $ \o ->
      SigInput
        <$> (parseJSON =<< o .: "pkscript")
        <*> o .: "value"
        <*> o .: "outpoint"
        <*> o .: "sighash"
        <*> (mapM parseJSON =<< o .:? "redeem")

-- | Sign a transaction by providing the 'SigInput' signing parameters and a
-- list of private keys. The signature is computed deterministically as defined
-- in RFC-6979.
--
-- An input is signed with the keys of the list that its coin asks for. An
-- input whose coin asks for none of them is left as it is, so that several
-- parties can sign in turn. The result is then 'Right' with that input
-- unsigned: use 'Haskoin.Transaction.Builder.verifyStdTx' to tell whether
-- the transaction is complete.
--
-- A SegWit version 0 coin is signed with a compressed key only, and fails
-- when its key is uncompressed. Nodes do not relay such a spend
-- (@SCRIPT_VERIFY_WITNESS_PUBKEYTYPE@ in Bitcoin Core), although a block
-- may hold it. 'signInput' signs with the key it is given, in the form it
-- is given.
--
-- An input signed with 'SIGHASH_SINGLE' needs an output at its index, or
-- the whole call fails: see 'signInput'.
--
-- The hashes that the digests of the inputs share are computed once for the
-- transaction ('TxSigHashes' for SegWit version 0 and for a network with a
-- fork id, 'TaprootTxHashes' for Taproot), and not once for each input. A
-- legacy input of Bitcoin shares nothing: its digest hashes a copy of the
-- whole transaction, in Bitcoin Core too.
signTx ::
  Network ->
  -- | transaction to sign
  Tx ->
  -- | signing parameters, with nesting flag
  [(SigInput, Bool)] ->
  -- | private keys to sign with
  [SecKey] ->
  -- | signed transaction
  Either String Tx
signTx net otx sigis allKeys
  | null ti = Left "signTx: Transaction has no inputs"
  | otherwise = do
      signed <- forM (zip [0 ..] (inputSpends otx)) $ \(i, spend) ->
        maybe (Right (spend, False)) (go i spend) (Map.lookup i found)
      let spends = map fst signed
      return
        otx
          { inputs = zipWith (\TxIn {..} (signedScript, _) -> TxIn {script = signedScript, ..}) ti spends,
            witness = if any snd signed then map snd spends else otx.witness
          }
  where
    ti = otx.inputs
    -- The signing parameters of each input, by its index
    found = Map.fromList [(i, sigi) | (sigi, i) <- findInputIndex ((.outpoint) . fst) sigis ti]
    -- The public keys of the secret keys are derived once for the whole
    -- transaction, not once per input
    index = keyIndex allKeys
    -- An input signed with the keys that its coin asks for, and whether
    -- that gave it a witness. Each input is signed on its own input script
    -- and witness stack, and the transaction is put together once: its
    -- lists would be walked up to the input for each signature.
    go i spend (sigi@(SigInput so _ _ sh rdmM, _)) = do
      keys <- indexedSigKeys index so rdmM
      if isTaprootOutput so
        then do
          unless net.segWit $ Left "signTx: this network has no Taproot"
          (spent, hashes) <- taprootCoins
          let digest = taprootSigHashWith hashes i sh Nothing Nothing
              sign (script, _) k = do
                stack <- digest >>= taprootKeyWitness sh k.key (spent V.! i)
                when wrongStackCount $ Left "signTaprootInput: Invalid number of witness stacks"
                return (script, stack)
          signedSpend <- foldM sign spend keys
          return (signedSpend, not (null keys))
        else do
          let sign s k = do
                s' <- signSpend net sigHashes i sigi k s
                when (isSegwit so && wrongStackCount) $ Left "Invalid number of witness stacks"
                return s'
          signedSpend <- foldM sign spend keys
          return (signedSpend, isSegwit so && not (null keys))
    -- A transaction that has witness stacks must have one for each input
    wrongStackCount = not (null otx.witness) && length otx.witness /= length ti
    -- What the digests of the inputs share. No digest commits to an input
    -- script or to a witness, so the hashes of the unsigned transaction
    -- hold while its inputs are signed.
    sigHashes = txSigHashes otx
    -- The outputs every input spends, which a Taproot signature commits
    -- to, and the hashes that the digests of the Taproot inputs share.
    taprootCoins = do
      spent <- spentOutputs
      hashes <- taprootTxHashes otx spent
      return (V.fromList spent, hashes)
    -- A nested SegWit program is spent as its P2SH wrapper
    spentOutputs =
      forM ti $ \txin ->
        case Map.lookup txin.outpoint parameters of
          Just (s, nested) -> (\so -> TxOut s.value (encodeSerial so)) <$> coinScript s nested
          Nothing -> Left "signTx: a Taproot signature needs the output every input spends"
    -- The signing parameters of each outpoint: the first given for it
    parameters = Map.fromListWith (\_ first -> first) [(s.outpoint, (s, nested)) | (s, nested) <- sigis]
    coinScript s nested
      | nested && isSegwit s.script = toP2SH =<< encodeOutput s.script
      | otherwise = Right s.script

-- | The input script and the witness stack of each input of a transaction,
-- in order: what signing an input changes. The stack is empty when the
-- transaction has no stack for the input.
inputSpends :: Tx -> [(B.ByteString, WitnessStack)]
inputSpends tx = zip (map (.script) tx.inputs) (tx.witness <> repeat [])

-- | The input script and the witness stack of one input. An index that the
-- transaction does not have gives empty ones: the digest refuses it.
inputSpend :: Tx -> Int -> (B.ByteString, WitnessStack)
inputSpend tx i
  | i < 0 = (B.empty, [])
  | otherwise = fromMaybe (B.empty, []) (listToMaybe (drop i (inputSpends tx)))

-- | The witness of a transaction with the stack of one input replaced. A
-- transaction without witness gets an empty stack for every other input.
-- Fails with the message when it has stacks, and not one for each input.
withStack :: String -> Tx -> Int -> WitnessStack -> Either String WitnessData
withStack wrongCount tx i stack
  | null tx.witness = Right (updateIndex i (replicate n []) (const stack))
  | length tx.witness /= n = Left wrongCount
  | otherwise = Right (updateIndex i tx.witness (const stack))
  where
    n = length tx.inputs

-- | Whether the output is a Taproot output: a witness program of version 1
-- that is 32 bytes long
isTaprootOutput :: ScriptOutput -> Bool
isTaprootOutput = \case
  PayWitness 1 program -> B.length program == 32
  _ -> False

-- | Sign a Taproot input by its key path, as BIP 341 defines it: the
-- Schnorr signature of the digest of 'taprootSigHash' goes in the witness
-- of the input, with its hash type byte unless the type is
-- 'sigHashDefault'. The secret key is the one of the output key, which
-- 'taprootOutputSecKey' derives from the internal key. The outputs spent
-- are those of every input, in order. Fails when the index is out of
-- range, when the spent outputs do not match the inputs, when the hash
-- type is not one 'isTaprootSigHash' accepts, when the output that the
-- input spends is not a Taproot output, or when the secret key is not the
-- key of that output: a signature of another key would make a transaction
-- that no node accepts.
--
-- This signs one input, and its digest hashes the whole transaction
-- ('taprootSigHash'). 'signTx' signs every input of a transaction with the
-- hashes that their digests share computed once.
signTaprootInput ::
  Tx ->
  -- | outputs spent, one per input
  [TxOut] ->
  -- | input index
  Int ->
  SigHash ->
  -- | the secret key of the output key
  SecKey ->
  Either String Tx
signTaprootInput tx spent i sh secret = do
  -- The digest checks the index and the number of spent outputs
  h <- taprootSigHash tx spent i sh Nothing Nothing
  stack <- taprootKeyWitness sh secret (spent !! i) h
  stacks <- withStack "signTaprootInput: Invalid number of witness stacks" tx i stack
  return tx {witness = stacks}

-- | The witness of a Taproot input spent by its key path: the signature of
-- the digest of the input, which the caller computed for the hash type,
-- by the secret key of the output that the input spends
taprootKeyWitness :: SigHash -> SecKey -> TxOut -> Hash256 -> Either String WitnessStack
taprootKeyWitness sh secret coin h = do
  outputKey <- case B.unpack coin.script of
    0x51 : 0x20 : program | length program == 32 -> Right (B.pack program)
    _ -> Left "signTaprootInput: the output spent is not a Taproot output"
  unless (exportXOnlyPubKey (derivePubKey secret) == outputKey) $
    Left "signTaprootInput: the key is not the key of the output"
  signature <- taprootSignature (signSchnorr secret (hashToMsg h)) sh
  return [encodeTaprootSig signature]

-- | Sign a single input in a transaction deterministically (RFC-6979).  The
-- nesting flag only affects the behavior of segwit inputs.
--
-- The key must be one the coin asks a signature of: the key of a
-- pay-to-public-key coin, the key whose hash a coin pays to, or a key of a
-- multisig. Any other key fails, since its signature would make an input
-- that no node accepts. The key is used in the form given, compressed or
-- not. That is the way to spend a SegWit coin of an uncompressed key on
-- purpose, which 'signTx' refuses. Nodes do not relay that spend, so
-- 'Haskoin.Transaction.Builder.verifyStdInput' answers 'False' for it.
--
-- An input signed with 'SIGHASH_SINGLE' at an index that has no output is
-- refused, whatever its coin. That signature commits to no output, as one
-- of 'SIGHASH_NONE' does. No BIP has a rule for a signer here, and the
-- transaction signer of Bitcoin Core makes no such signature
-- (@SignTransaction@: "Only sign SIGHASH_SINGLE if there's a corresponding
-- output"), nor does the one of Bitcoin Cash Node. 'makeSignature' gives
-- the signature of a SegWit coin and of a coin of Bitcoin Cash to a caller
-- that wants it.
signInput ::
  Network ->
  Tx ->
  Int ->
  -- | boolean flag: nest input
  (SigInput, Bool) ->
  PrivateKey ->
  Either String Tx
signInput net tx i sigi@(SigInput so _ _ _ _, _) key = do
  (signedScript, stack) <- signSpend net (txSigHashes tx) i sigi key (inputSpend tx i)
  stacks <- if isSegwit so then withStack "Invalid number of witness stacks" tx i stack else Right tx.witness
  return tx {inputs = updateIndex i tx.inputs (\TxIn {..} -> TxIn {script = signedScript, ..}), witness = stacks}

-- | 'signInput' on the input script and the witness stack of the input,
-- with what the digests of the inputs share. It gives the two as the
-- signature leaves them. The hashes are those of the transaction before
-- any input was signed, which hold for it afterwards: see 'TxSigHashes'.
signSpend ::
  Network ->
  TxSigHashes ->
  Int ->
  (SigInput, Bool) ->
  PrivateKey ->
  (B.ByteString, WitnessStack) ->
  Either String (B.ByteString, WitnessStack)
signSpend net hashes i (sigIn@(SigInput so val _ sh rdmM), nest) key spend@(script, stack) = do
  when (isTaprootOutput so) $
    Left "signInput: a Taproot input is signed with signTaprootInput"
  when (isSigHashSingle sh && i >= length (sigHashesTx hashes).outputs) $
    Left "signInput: SIGHASH_SINGLE without an output at the input index"
  let pub = derivePublicKey key
  unless (keyOfCoin so rdmM pub) $
    Left "signInput: the key is not a key of the coin"
  sig <- makeSignatureWith net hashes i sigIn key
  si <- spendInput net hashes i so val rdmM sig pub spend
  if isSegwit so
    then do
      signedStack <- toWitnessStack net <$> calcWitnessProgram net so si
      return (if nest then marshal net (NestedWitnessInput so) else script, signedStack)
    else return (marshal net si, stack)

-- | Whether the public key is one that the coin asks a signature of
keyOfCoin :: ScriptOutput -> Maybe RedeemScript -> PublicKey -> Bool
keyOfCoin so rdmM pub = case (so, rdmM) of
  (PayPK p, Nothing) -> p == pub
  (PayPKHash h, Nothing) -> keyHash == h
  (PayMulSig ps _, Nothing) -> pub `elem` ps
  (PayScriptHash _, Just rdm) -> keyOfCoin rdm Nothing pub
  (PayWitnessPKHash h, _) -> keyHash == h
  (PayWitnessScriptHash _, Just rdm) -> keyOfCoin rdm Nothing pub
  _ -> False
  where
    keyHash = addressHash (encodeSerial pub)

-- | Associate an input index to each value in a list
findInputIndex ::
  -- | extract an outpoint
  (a -> OutPoint) ->
  -- | input list
  [a] ->
  -- | reference list of inputs
  [TxIn] ->
  [(a, Int)]
findInputIndex getOutPoint as ti =
  mapMaybe g $ zip (matchTemplate as ti f) [0 ..]
  where
    f s txin = getOutPoint s == txin.outpoint
    g (Just s, i) = Just (s, i)
    g (Nothing, _) = Nothing

-- | Find from the list of provided private keys which one is required to sign
-- the 'ScriptOutput'. For a Taproot output, the key returned is the secret
-- key of the output key: a key whose x-only public key is the output key,
-- or the tweak of a key without a script tree, as BIP 86 spends.
--
-- A legacy coin is matched with each key in its compressed and in its
-- uncompressed form. A SegWit version 0 coin, native or nested, takes a
-- compressed key only: when the key it asks for is uncompressed, the
-- result is an error, because nodes do not relay such a spend
-- (@SCRIPT_VERIFY_WITNESS_PUBKEYTYPE@ in Bitcoin Core).
sigKeys ::
  ScriptOutput ->
  Maybe RedeemScript ->
  [SecKey] ->
  Either String [PrivateKey]
sigKeys so rdmM keys = indexedSigKeys (keyIndex keys) so rdmM

-- | The secret keys of a signer with what is derived from them, so that it
-- is derived once for a whole transaction
data KeyIndex = KeyIndex
  { -- | each key in its compressed and then in its uncompressed form, with
    -- its public key and the hash of that public key
    forms :: [(PrivateKey, PublicKey, Hash160)],
    -- | for each key, the Taproot output keys it spends, as x-only bytes,
    -- with the secret key of each: the key itself, then its tweak without
    -- a script tree
    outputKeys :: [[(B.ByteString, SecKey)]]
  }

keyIndex :: [SecKey] -> KeyIndex
keyIndex keys =
  KeyIndex
    { forms =
        [ (PrivateKey k compressed, pub, addressHash (encodeSerial pub))
        | k <- keys,
          let point = derivePubKey k,
          compressed <- [True, False],
          let pub = PublicKey point compressed
        ],
      outputKeys =
        [ (xOnly k, k) : [(xOnly tweaked, tweaked) | Just tweaked <- [taprootOutputSecKey k Nothing]]
        | k <- keys
        ]
    }
  where
    xOnly = exportXOnlyPubKey . derivePubKey

-- | 'sigKeys' on keys that are indexed already
indexedSigKeys :: KeyIndex -> ScriptOutput -> Maybe RedeemScript -> Either String [PrivateKey]
indexedSigKeys index = go False
  where
    -- The flag tells whether the keys sign inside a SegWit version 0 witness
    go witness so rdmM = case (so, rdmM) of
      (PayPK p, Nothing) ->
        compressedIn witness . take 1 $ [prv | (prv, pub, _) <- index.forms, pub == p]
      (PayPKHash h, Nothing) ->
        compressedIn witness . take 1 $ [prv | (prv, _, keyHash) <- index.forms, keyHash == h]
      (PayMulSig ps r, Nothing) ->
        compressedIn witness . take r $ [prv | (prv, pub, _) <- index.forms, pub `elem` ps]
      (PayScriptHash _, Just rdm) -> go witness rdm Nothing
      (PayWitnessPKHash h, _) -> go True (PayPKHash h) Nothing
      (PayWitnessScriptHash _, Just rdm) -> go True rdm Nothing
      (PayWitness 1 program, Nothing)
        | B.length program == 32 ->
            return [PrivateKey k True | Just k <- map (lookup program) index.outputKeys]
      _ -> Left "sigKeys: Could not decode output script"
    compressedIn witness found
      | witness && not (all (.compress) found) =
          Left "sigKeys: a SegWit input is signed with a compressed key only, and this coin pays to an uncompressed key"
      | otherwise = Right found

-- | Construct an input for a transaction given a signature, public key and data
-- about the previous output.
buildInput ::
  Network ->
  -- | transaction where input will be added
  Tx ->
  -- | input index where signature will go
  Int ->
  -- | output script being spent
  ScriptOutput ->
  -- | amount of previous output
  Word64 ->
  -- | redeem script if pay-to-script-hash
  Maybe RedeemScript ->
  TxSignature ->
  PublicKey ->
  Either String ScriptInput
buildInput net tx i so val rdmM sig pub = do
  when (i < 0 || i >= length tx.inputs) $ Left "buildInput: Invalid input index"
  spendInput net (txSigHashes tx) i so val rdmM sig pub (inputSpend tx i)

-- | 'buildInput' on the input script and the witness stack of the input,
-- which hold the signatures that a multisig input has already, with what
-- the digests of the inputs share: see 'signSpend'
spendInput ::
  Network ->
  TxSigHashes ->
  Int ->
  ScriptOutput ->
  Word64 ->
  Maybe RedeemScript ->
  TxSignature ->
  PublicKey ->
  (B.ByteString, WitnessStack) ->
  Either String ScriptInput
spendInput net hashes i so val rdmM sig pub spend = do
  when (isTaprootOutput so) $ Left "buildInput: a Taproot input has no input script"
  case (so, rdmM) of
    (PayScriptHash _, Just rdm) ->
      buildScriptHashInput rdm
    (PayWitnessScriptHash _, Just rdm) ->
      buildScriptHashInput rdm
    (PayWitnessPKHash _, Nothing) ->
      return . RegularInput $ SpendPKHash sig pub
    (_, Nothing) ->
      buildRegularInput so
    _ -> Left "buildInput: Invalid output/redeem script combination"
  where
    buildRegularInput = \case
      PayPK _ -> return $ RegularInput $ SpendPK sig
      PayPKHash _ -> return $ RegularInput $ SpendPKHash sig pub
      PayMulSig msPubs r -> do
        let mSigs = take r $ catMaybes $ matchTemplate allSigs msPubs f
            allSigs = nub $ sig : existingSigs net so spend
        return $ RegularInput $ SpendMulSig mSigs
      _ -> Left "buildInput: Invalid output/redeem script combination"
    buildScriptHashInput rdm = do
      inp <- buildRegularInput rdm
      return $ ScriptHashInput inp.get rdm
    f (TxSignature x sh) p =
      either (const False) (\m -> verifyHashSig m x p.point) $
        makeSigHashWith net hashes i so val sh rdmM
    f TxSignatureEmpty _ = False

-- | Apply heuristics to extract the signatures that an input holds, in its
-- input script and in its witness stack.
existingSigs :: Network -> ScriptOutput -> (B.ByteString, WitnessStack) -> [TxSignature]
existingSigs net so (script, stack) = insSigs <> witSigs
  where
    insSigs = case unmarshal net script of
      Right (ScriptHashInput (SpendMulSig xs) _) -> xs
      Right (RegularInput (SpendMulSig xs)) -> xs
      _ -> []
    witSigs
      | not $ isSegwit so = []
      | otherwise = rights $ decodeTxSig net <$> stack

-- | Produce a structured representation of a deterministic (RFC-6979)
-- signature over an input. On a network with a fork id, such as Bitcoin
-- Cash, the 'SIGHASH_FORKID' flag is added to the 'SigHash' of the
-- 'SigInput', since every signature there must carry it. Fails when the
-- input index is out of range or the output script cannot be encoded.
--
-- The signer refuses what a node would refuse, with the reason:
--
-- * A hash type that does not fit in the one byte a signature carries, one
--   that is not 'sigHashAll', 'sigHashNone' or 'sigHashSingle' with or
--   without 'setAnyoneCanPay' (the test of @IsDefinedHashtypeSignature@ in
--   Bitcoin Core), and the fork id flag on a network without a fork id.
--   On Bitcoin Cash this refuses @SIGHASH_UTXOS@ too, whose digest the
--   library does not compute.
-- * A pay-to-script-hash coin without its redeem script, with a redeem
--   script over 'maxRedeemScriptSize' bytes, or with one that does not
--   hash to the coin. The same for a pay-to-witness-script-hash coin and
--   its witness script, with 'maxWitnessScriptSize'. The limit of a redeem
--   script is the one place where the signer is stricter than a node: a
--   node of Bitcoin Cash accepts a longer one since May 2025, and the
--   library keeps one limit on every network ('maxRedeemScriptSize').
-- * A SegWit coin on a network without SegWit.
-- * On a network with a fork id, a signature that comes out 64 bytes long
--   ('isCashSchnorrLength'). Bitcoin Cash reads that length as a Schnorr
--   signature, so no node takes the transaction. The nonce is that of RFC
--   6979, so the same key and digest give the same signature again: the
--   caller changes the transaction, its fee for instance, and signs again.
--   The specification of Bitcoin Cash gives one chance in 2^49 for this.
--
-- A legacy input signed with 'SIGHASH_SINGLE' at an index that has no
-- output is refused. The digest of that case is the constant 1, which
-- commits to nothing, so the signature would spend any other coin of the
-- key wherever the same case comes up. Bitcoin Core computes that digest
-- in @SignatureHash@, and so does 'txSigHash', since a node must verify
-- such signatures; a signer has no reason to make one. The BIP 143 digest
-- of a SegWit input and the fork id digest of Bitcoin Cash commit to the
-- coin in that case, so those are signed here, as the PSBT signer of
-- Bitcoin Core signs them. 'signInput' and 'signTx' refuse them too, as
-- its transaction signer does.
--
-- The key is not checked against the coin here: 'signInput' does that.
--
-- This is the function for one signature. For the signatures of several
-- inputs of one transaction, 'makeSignatureWith' does not hash the
-- transaction again for each of them.
makeSignature :: Network -> Tx -> Int -> SigInput -> PrivateKey -> Either String TxSignature
makeSignature net = makeSignatureWith net . txSigHashes

-- | 'makeSignature' for the transaction of the 'TxSigHashes', from the
-- hashes that the digests of its inputs share. It gives the signature that
-- 'makeSignature' gives, and fails as it does.
makeSignatureWith :: Network -> TxSigHashes -> Int -> SigInput -> PrivateKey -> Either String TxSignature
makeSignatureWith net hashes i (SigInput so val _ sh rdmM) key = do
  when (isSegwit so && not net.segWit) $
    Left "makeSignature: this network has no SegWit"
  when (sh > 0xff) $
    Left $
      "makeSignature: the hash type " <> shown <> " does not fit in the one byte of a signature"
  when (isNothing net.sigHashForkId && hasForkIdFlag sh) $
    Left $
      "makeSignature: the hash type " <> shown <> " has the fork id flag, which this network does not use"
  when (isSigHashUnknown sh') $
    Left $
      "makeSignature: the hash type " <> shown <> " is not one a node accepts"
  committedScript
  m <- makeSigHashWith net hashes i so val sh' rdmM
  when (signsConstantDigest && i >= length (sigHashesTx hashes).outputs) $
    Left "makeSignature: SIGHASH_SINGLE without an output at the input index"
  let sig = signHash key.key m
  when (isJust net.sigHashForkId && isCashSchnorrLength sig) $
    Left
      "makeSignature: the signature is 64 bytes long, which this network reads as a Schnorr signature: \
      \change the transaction and sign again"
  return $ TxSignature sig sh'
  where
    shown = show (toInteger sh)
    sh'
      | isJust net.sigHashForkId = setForkIdFlag sh
      | otherwise = sh
    signsConstantDigest =
      isSigHashSingle sh' && not (isSegwit so) && isNothing net.sigHashForkId
    -- A coin that commits to a script is signed only with that script
    committedScript = case (so, rdmM) of
      (PayScriptHash h, Just rdm) -> do
        committed <- p2shScriptHash =<< encodeOutput rdm
        unless (committed == h) $ Left "makeSignature: the redeem script does not hash to the coin"
      (PayScriptHash _, Nothing) ->
        Left "makeSignature: a pay-to-script-hash coin needs its redeem script"
      (PayWitnessScriptHash h, Just rdm) -> do
        committed <- p2wshScriptHash =<< encodeOutput rdm
        unless (committed == h) $ Left "makeSignature: the witness script does not hash to the coin"
      (PayWitnessScriptHash _, Nothing) ->
        Left "makeSignature: a pay-to-witness-script-hash coin needs its witness script"
      _ -> Right ()

-- | A function which selects the digest algorithm and parameters as appropriate
--
-- @since 0.11.0.0
makeSigHash ::
  Network ->
  Tx ->
  Int ->
  ScriptOutput ->
  Word64 ->
  SigHash ->
  Maybe RedeemScript ->
  Either String Hash256
makeSigHash net = makeSigHashWith net . txSigHashes

-- | 'makeSigHash' for the transaction of the 'TxSigHashes', from the
-- hashes that the digests of its inputs share. It gives the digest that
-- 'makeSigHash' gives, and fails as it does.
makeSigHashWith ::
  Network ->
  TxSigHashes ->
  Int ->
  ScriptOutput ->
  Word64 ->
  SigHash ->
  Maybe RedeemScript ->
  Either String Hash256
makeSigHashWith net hashes i so val sh rdmM = do
  when (isTaprootOutput so) $
    Left "makeSigHash: the digest of a Taproot input is taprootSigHash"
  script <- encodeOutput so'
  h net hashes script val i sh
  where
    so' = case so of
      PayWitnessPKHash h' -> PayPKHash h'
      _ -> fromMaybe so rdmM
    h
      | isSegwit so = txSigHashForkIdWith
      | otherwise = txSigHashWith
