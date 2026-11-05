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
    makeSigHash,
    signTx,
    findInputIndex,
    signInput,
    signTaprootInput,
    buildInput,
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
import Data.Maybe
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

instance MarshalJSON Ctx SigInput where
  marshalValue ctx (SigInput s v o h r) =
    object $
      [ "pkscript" .= marshalValue ctx s,
        "value" .= v,
        "outpoint" .= o,
        "sighash" .= h
      ]
        ++ [ "redeem" .= marshalValue ctx r
           | r <- maybeToList r
           ]

  marshalEncoding ctx (SigInput s v o h r) =
    pairs $
      mconcat
        [ "pkscript" `pair` marshalEncoding ctx s,
          "value" `pair` word64 v,
          "outpoint" `pair` toEncoding o,
          "sighash" `pair` toEncoding h,
          maybe mempty (pair "redeem" . marshalEncoding ctx) r
        ]

  unmarshalValue ctx =
    withObject "SigInput" $ \o ->
      SigInput
        <$> (unmarshalValue ctx =<< o .: "pkscript")
        <*> o .: "value"
        <*> o .: "outpoint"
        <*> o .: "sighash"
        <*> (mapM (unmarshalValue ctx) =<< o .:? "redeem")

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
signTx ::
  Network ->
  Ctx ->
  -- | transaction to sign
  Tx ->
  -- | signing parameters, with nesting flag
  [(SigInput, Bool)] ->
  -- | private keys to sign with
  [SecKey] ->
  -- | signed transaction
  Either String Tx
signTx net ctx otx sigis allKeys
  | null ti = Left "signTx: Transaction has no inputs"
  | otherwise = foldM go otx $ findInputIndex ((.outpoint) . fst) sigis ti
  where
    ti = otx.inputs
    -- The public keys of the secret keys are derived once for the whole
    -- transaction, not once per input
    index = keyIndex ctx allKeys
    go tx (sigi@(SigInput so _ _ sh rdmM, _), i) = do
      keys <- indexedSigKeys index so rdmM
      if isTaprootOutput so
        then do
          unless net.segWit $ Left "signTx: this network has no Taproot"
          spent <- spentOutputs
          foldM (\t k -> signTaprootInput ctx t spent i sh k.key) tx keys
        else foldM (\t k -> signInput net ctx t i sigi k) tx keys
    -- The outputs every input spends, which a Taproot signature commits
    -- to: a nested SegWit program is spent as its P2SH wrapper
    spentOutputs =
      forM ti $ \txin ->
        case find ((== txin.outpoint) . (.outpoint) . fst) sigis of
          Just (s, nested) -> (\so -> TxOut s.value (marshal ctx so)) <$> coinScript s nested
          Nothing -> Left "signTx: a Taproot signature needs the output every input spends"
    coinScript s nested
      | nested && isSegwit s.script = toP2SH =<< encodeOutput ctx s.script
      | otherwise = Right s.script

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
signTaprootInput ::
  Ctx ->
  Tx ->
  -- | outputs spent, one per input
  [TxOut] ->
  -- | input index
  Int ->
  SigHash ->
  -- | the secret key of the output key
  SecKey ->
  Either String Tx
signTaprootInput ctx tx spent i sh secret = do
  -- The digest checks the index and the number of spent outputs
  h <- taprootSigHash tx spent i sh Nothing Nothing
  outputKey <- case B.unpack (spent !! i).script of
    0x51 : 0x20 : program | length program == 32 -> Right (B.pack program)
    _ -> Left "signTaprootInput: the output spent is not a Taproot output"
  unless (exportXOnlyPubKey ctx (derivePubKey ctx secret) == outputKey) $
    Left "signTaprootInput: the key is not the key of the output"
  signature <- taprootSignature (signSchnorr ctx secret (hashToMsg h)) sh
  let stacks
        | null tx.witness = replicate (length tx.inputs) []
        | otherwise = tx.witness
  unless (length stacks == length tx.inputs) $
    Left "signTaprootInput: Invalid number of witness stacks"
  return tx {witness = updateIndex i stacks (const [encodeTaprootSig signature])}

-- | Sign a single input in a transaction deterministically (RFC-6979).  The
-- nesting flag only affects the behavior of segwit inputs.
--
-- The key must be one the coin asks a signature of: the key of a
-- pay-to-public-key coin, the key whose hash a coin pays to, or a key of a
-- multisig. Any other key fails, since its signature would make an input
-- that no node accepts. The key is used in the form given, compressed or
-- not. That is the way to spend a SegWit coin of an uncompressed key on
-- purpose, which 'signTx' refuses.
signInput ::
  Network ->
  Ctx ->
  Tx ->
  Int ->
  -- | boolean flag: nest input
  (SigInput, Bool) ->
  PrivateKey ->
  Either String Tx
signInput net ctx tx i (sigIn@(SigInput so val _ _ rdmM), nest) key = do
  when (isTaprootOutput so) $
    Left "signInput: a Taproot input is signed with signTaprootInput"
  let pub = derivePublicKey ctx key
  unless (keyOfCoin ctx so rdmM pub) $
    Left "signInput: the key is not a key of the coin"
  sig <- makeSignature net ctx tx i sigIn key
  si <- buildInput net ctx tx i so val rdmM sig pub
  w <- updatedWitnessData net ctx tx i so si
  return tx {inputs = nextTxIn so si, witness = w}
  where
    f si TxIn {..} = TxIn {script = marshal (net, ctx) si, ..}
    g so' = f (NestedWitnessInput so')
    nextTxIn so' si
      | isSegwit so' && nest = updateIndex i tx.inputs (g so')
      | isSegwit so' = tx.inputs
      | otherwise = updateIndex i tx.inputs (f si)

-- | Whether the public key is one that the coin asks a signature of
keyOfCoin :: Ctx -> ScriptOutput -> Maybe RedeemScript -> PublicKey -> Bool
keyOfCoin ctx so rdmM pub = case (so, rdmM) of
  (PayPK p, Nothing) -> p == pub
  (PayPKHash h, Nothing) -> keyHash == h
  (PayMulSig ps _, Nothing) -> pub `elem` ps
  (PayScriptHash _, Just rdm) -> keyOfCoin ctx rdm Nothing pub
  (PayWitnessPKHash h, _) -> keyHash == h
  (PayWitnessScriptHash _, Just rdm) -> keyOfCoin ctx rdm Nothing pub
  _ -> False
  where
    keyHash = addressHash (marshal ctx pub)

-- | Add the witness data of the transaction given segwit parameters for an input.
--
-- @since 0.11.0.0
updatedWitnessData ::
  Network ->
  Ctx ->
  Tx ->
  Int ->
  ScriptOutput ->
  ScriptInput ->
  Either String WitnessData
updatedWitnessData net ctx tx i so si
  | isSegwit so =
      updateWitness . toWitnessStack net ctx =<< calcWitnessProgram net ctx so si
  | otherwise =
      return tx.witness
  where
    updateWitness w
      | null tx.witness = return $ updateIndex i defaultStack (const w)
      | length tx.witness /= n = Left "Invalid number of witness stacks"
      | otherwise = return $ updateIndex i tx.witness (const w)
    defaultStack = replicate n $ toWitnessStack net ctx EmptyWitnessProgram
    n = length tx.inputs

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
  Ctx ->
  ScriptOutput ->
  Maybe RedeemScript ->
  [SecKey] ->
  Either String [PrivateKey]
sigKeys ctx so rdmM keys = indexedSigKeys (keyIndex ctx keys) so rdmM

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

keyIndex :: Ctx -> [SecKey] -> KeyIndex
keyIndex ctx keys =
  KeyIndex
    { forms =
        [ (PrivateKey k compressed, pub, addressHash (marshal ctx pub))
        | k <- keys,
          let point = derivePubKey ctx k,
          compressed <- [True, False],
          let pub = PublicKey point compressed
        ],
      outputKeys =
        [ (xOnly k, k) : [(xOnly tweaked, tweaked) | Just tweaked <- [taprootOutputSecKey ctx k Nothing]]
        | k <- keys
        ]
    }
  where
    xOnly = exportXOnlyPubKey ctx . derivePubKey ctx

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
  Ctx ->
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
buildInput net ctx tx i so val rdmM sig pub = do
  when (i < 0 || i >= length tx.inputs) $ Left "buildInput: Invalid input index"
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
            allSigs = nub $ sig : parseExistingSigs net ctx tx so i
        return $ RegularInput $ SpendMulSig mSigs
      _ -> Left "buildInput: Invalid output/redeem script combination"
    buildScriptHashInput rdm = do
      inp <- buildRegularInput rdm
      return $ ScriptHashInput inp.get rdm
    f (TxSignature x sh) p =
      either (const False) (\m -> verifyHashSig ctx m x p.point) $
        makeSigHash net ctx tx i so val sh rdmM
    f TxSignatureEmpty _ = False

-- | Apply heuristics to extract the signatures for a particular input that are
-- embedded in the transaction.
--
-- @since 0.11.0.0
parseExistingSigs :: Network -> Ctx -> Tx -> ScriptOutput -> Int -> [TxSignature]
parseExistingSigs net ctx tx so i = insSigs <> witSigs
  where
    insSigs = case unmarshal (net, ctx) scp of
      Right (ScriptHashInput (SpendMulSig xs) _) -> xs
      Right (RegularInput (SpendMulSig xs)) -> xs
      _ -> []
    scp = (tx.inputs !! i).script
    witSigs
      | not $ isSegwit so = []
      | length tx.witness <= i = []
      | otherwise = rights $ decodeTxSig net ctx <$> (tx.witness !! i)

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
--   its witness script, with 'maxWitnessScriptSize'.
-- * A SegWit coin on a network without SegWit.
--
-- A legacy input signed with 'SIGHASH_SINGLE' at an index that has no
-- output is refused. The digest of that case is the constant 1, which
-- commits to nothing, so the signature would spend any other coin of the
-- key wherever the same case comes up. Bitcoin Core computes that digest
-- in @SignatureHash@, and so does 'txSigHash', since a node must verify
-- such signatures; a signer has no reason to make one. The BIP 143 digest
-- of a SegWit input and the fork id digest of Bitcoin Cash commit to the
-- coin in that case, so those are signed.
--
-- The key is not checked against the coin here: 'signInput' does that.
makeSignature :: Network -> Ctx -> Tx -> Int -> SigInput -> PrivateKey -> Either String TxSignature
makeSignature net ctx tx i (SigInput so val _ sh rdmM) key = do
  when (isSegwit so && not net.segWit) $
    Left "makeSignature: this network has no SegWit"
  when (sh > 0xff) $
    Left $ "makeSignature: the hash type " <> shown <> " does not fit in the one byte of a signature"
  when (isNothing net.sigHashForkId && hasForkIdFlag sh) $
    Left $ "makeSignature: the hash type " <> shown <> " has the fork id flag, which this network does not use"
  when (isSigHashUnknown sh') $
    Left $ "makeSignature: the hash type " <> shown <> " is not one a node accepts"
  committedScript
  m <- makeSigHash net ctx tx i so val sh' rdmM
  when (signsConstantDigest && i >= length tx.outputs) $
    Left "makeSignature: SIGHASH_SINGLE without an output at the input index"
  return $ TxSignature (signHash ctx key.key m) sh'
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
        committed <- p2shScriptHash =<< encodeOutput ctx rdm
        unless (committed == h) $ Left "makeSignature: the redeem script does not hash to the coin"
      (PayScriptHash _, Nothing) ->
        Left "makeSignature: a pay-to-script-hash coin needs its redeem script"
      (PayWitnessScriptHash h, Just rdm) -> do
        committed <- p2wshScriptHash =<< encodeOutput ctx rdm
        unless (committed == h) $ Left "makeSignature: the witness script does not hash to the coin"
      (PayWitnessScriptHash _, Nothing) ->
        Left "makeSignature: a pay-to-witness-script-hash coin needs its witness script"
      _ -> Right ()

-- | A function which selects the digest algorithm and parameters as appropriate
--
-- @since 0.11.0.0
makeSigHash ::
  Network ->
  Ctx ->
  Tx ->
  Int ->
  ScriptOutput ->
  Word64 ->
  SigHash ->
  Maybe RedeemScript ->
  Either String Hash256
makeSigHash net ctx tx i so val sh rdmM = do
  when (isTaprootOutput so) $
    Left "makeSigHash: the digest of a Taproot input is taprootSigHash"
  script <- encodeOutput ctx so'
  h net tx script val i sh
  where
    so' = case so of
      PayWitnessPKHash h' -> PayPKHash h'
      _ -> fromMaybe so rdmM
    h
      | isSegwit so = txSigHashForkId
      | otherwise = txSigHash
