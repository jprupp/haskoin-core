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
    go tx (sigi@(SigInput so _ _ sh rdmM, _), i) = do
      keys <- sigKeys ctx so rdmM allKeys
      if isTaprootOutput so
        then do
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
      | nested && isSegwit s.script = toP2SH <$> encodeOutput ctx s.script
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
-- range, when the spent outputs do not match the inputs, or when the hash
-- type is not one 'isTaprootSigHash' accepts.
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
  h <- taprootSigHash tx spent i sh Nothing Nothing
  let signature = TaprootSignature (signSchnorr ctx secret (hashToMsg h)) sh
      stacks
        | null tx.witness = replicate (length tx.inputs) []
        | otherwise = tx.witness
  unless (length stacks == length tx.inputs) $
    Left "signTaprootInput: Invalid number of witness stacks"
  return tx {witness = updateIndex i stacks (const [encodeTaprootSig signature])}

-- | Sign a single input in a transaction deterministically (RFC-6979).  The
-- nesting flag only affects the behavior of segwit inputs.
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
  sig <- makeSignature net ctx tx i sigIn key
  si <- buildInput net ctx tx i so val rdmM sig $ derivePublicKey ctx key
  w <- updatedWitnessData net ctx tx i so si
  return tx {inputs = nextTxIn so si, witness = w}
  where
    f si TxIn {..} = TxIn {script = marshal (net, ctx) si, ..}
    g so' = f (NestedWitnessInput so')
    nextTxIn so' si
      | isSegwit so' && nest = updateIndex i tx.inputs (g so')
      | isSegwit so' = tx.inputs
      | otherwise = updateIndex i tx.inputs (f si)

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
sigKeys ::
  Ctx ->
  ScriptOutput ->
  Maybe RedeemScript ->
  [SecKey] ->
  Either String [PrivateKey]
sigKeys ctx so rdmM keys =
  case (so, rdmM) of
    (PayPK p, Nothing) ->
      return . map fst . maybeToList $ find ((== p) . snd) zipKeys
    (PayPKHash h, Nothing) -> return $ keyByHash h
    (PayMulSig ps r, Nothing) ->
      return $ map fst $ take r $ filter ((`elem` ps) . snd) zipKeys
    (PayScriptHash _, Just rdm) -> sigKeys ctx rdm Nothing keys
    (PayWitnessPKHash h, _) -> return $ keyByHash h
    (PayWitnessScriptHash _, Just rdm) -> sigKeys ctx rdm Nothing keys
    (PayWitness 1 program, Nothing)
      | B.length program == 32 ->
          return [PrivateKey k True | Just k <- map (taprootKey program) keys]
    _ -> Left "sigKeys: Could not decode output script"
  where
    zipKeys =
      [ (prv, pub)
      | k <- keys,
        t <- [True, False],
        let prv = wrapSecKey t k,
        let pub = derivePublicKey ctx prv
      ]
    keyByHash h = fmap fst . maybeToList . findKey h $ zipKeys
    findKey h = find $ (== Just h) . addressHash160 . pubKeyAddr ctx . snd
    -- The secret key of a Taproot output key: the key itself when its
    -- x-only public key is the output key, or its tweak without a tree
    taprootKey program k
      | exportXOnlyPubKey ctx (derivePubKey ctx k) == program = Just k
      | Just tweaked <- taprootOutputSecKey ctx k Nothing,
        exportXOnlyPubKey ctx (derivePubKey ctx tweaked) == program =
          Just tweaked
      | otherwise = Nothing

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
-- A legacy input signed with 'SIGHASH_SINGLE' at an index that has no
-- output is refused. The digest of that case is the constant 1, which
-- commits to nothing, so the signature would spend any other coin of the
-- key wherever the same case comes up. Bitcoin Core computes that digest
-- in @SignatureHash@, and so does 'txSigHash', since a node must verify
-- such signatures; a signer has no reason to make one. The BIP 143 digest
-- of a SegWit input and the fork id digest of Bitcoin Cash commit to the
-- coin in that case, so those are signed.
makeSignature :: Network -> Ctx -> Tx -> Int -> SigInput -> PrivateKey -> Either String TxSignature
makeSignature net ctx tx i (SigInput so val _ sh rdmM) key = do
  m <- makeSigHash net ctx tx i so val sh' rdmM
  when (signsConstantDigest && i >= length tx.outputs) $
    Left "makeSignature: SIGHASH_SINGLE without an output at the input index"
  return $ TxSignature (signHash ctx key.key m) sh'
  where
    sh'
      | isJust net.sigHashForkId = setForkIdFlag sh
      | otherwise = sh
    signsConstantDigest =
      isSigHashSingle sh' && not (isSegwit so) && isNothing net.sigHashForkId

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
