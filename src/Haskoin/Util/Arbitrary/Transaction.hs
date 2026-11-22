{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}

-- |
-- Module      : Haskoin.Test.Transaction
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
module Haskoin.Util.Arbitrary.Transaction where

import Control.Monad
import Data.ByteString qualified as BS
import Data.Either (fromRight)
import Data.List (findIndex, nub, nubBy, permutations)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe, isNothing)
import Data.Word (Word32, Word64)
import Haskoin.Address
import Haskoin.Crypto.Keys.Common
import Haskoin.Crypto.Keys.Extended (XPubKey (..), listToPath)
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction
import Haskoin.Transaction.Segwit (isSegwit)
import Haskoin.Util
import Haskoin.Util.Arbitrary.Crypto
import Haskoin.Util.Arbitrary.Keys
import Haskoin.Util.Arbitrary.Script
import Haskoin.Util.Arbitrary.Util
import Test.QuickCheck

-- | A coin for testing: its value, and the kind of input it is spent with.
data TestCoin = TestCoin
  { getTestCoin :: Word64,
    getTestCoinKind :: InputKind
  }
  deriving (Eq, Show)

instance Coin TestCoin where
  coinValue = (.getTestCoin)
  coinInputKind = (.getTestCoinKind)

-- | Arbitrary transaction hash (for non-existent transaction).
arbitraryTxHash :: Gen TxHash
arbitraryTxHash = TxHash <$> arbitraryHash256

-- | Arbitrary amount of Satoshi as 'Word64' (Between 1 and 21e14), spent
-- with an arbitrary kind of input. A third of the amounts are below 10,000
-- satoshi, near the fees and the dust thresholds, a third below one coin,
-- and a third anywhere up to the 21 million coins.
arbitrarySatoshi :: Network -> Gen TestCoin
arbitrarySatoshi net = TestCoin <$> amount <*> arbitraryInputKind
  where
    amount = oneof [choose (1, 10000), choose (1, 100000000), choose (1, net.maxSatoshi)]

-- | Arbitrary kind of input that can exist. A SegWit multisig has
-- parameters from 'arbitraryMSParam', up to 20 keys. A pay-to-script-hash
-- multisig has them from 'arbitraryP2SHMSParamC', up to the 15 compressed
-- keys that fit a redeem script.
arbitraryInputKind :: Gen InputKind
arbitraryInputKind = do
  (m, n) <- arbitraryMSParam
  (mP2SH, nP2SH) <- arbitraryP2SHMSParamC
  elements
    [ InputPK,
      InputPKHash,
      InputUncompressedPKHash,
      InputMulSig mP2SH nP2SH,
      InputWitnessPKHash,
      InputWitnessMulSig m n,
      InputNestedWitnessPKHash,
      InputNestedWitnessMulSig m n,
      InputTaproot
    ]

-- | Arbitrary kind of output. An 'OutputScript' is up to 10000 bytes, the
-- most a script may have.
arbitraryOutputKind :: Gen OutputKind
arbitraryOutputKind =
  oneof
    [ elements
        [ OutputPKHash,
          OutputScriptHash,
          OutputScript32Hash,
          OutputWitnessPKHash,
          OutputWitnessScriptHash,
          OutputTaproot
        ],
      OutputScript <$> choose (0, 10000)
    ]

-- | Arbitrary 'OutPoint'.
arbitraryOutPoint :: Gen OutPoint
arbitraryOutPoint = OutPoint <$> arbitraryTxHash <*> arbitrary

-- | Arbitrary 'TxOut'.
arbitraryTxOut :: Network -> Gen TxOut
arbitraryTxOut net =
  TxOut
    <$> (getTestCoin <$> arbitrarySatoshi net)
    <*> (encodeSerial <$> arbitraryScriptOutput net)

-- | Arbitrary 'TxIn'.
arbitraryTxIn :: Network -> Gen TxIn
arbitraryTxIn net =
  TxIn
    <$> arbitraryOutPoint
    <*> (marshal net <$> arbitraryScriptInput net)
    <*> arbitrary

-- | Arbitrary transaction. Can be regular or with witnesses.
arbitraryTx :: Network -> Gen Tx
arbitraryTx net =
  oneof [arbitraryLegacyTx net, arbitraryWitnessTx net]

-- | Arbitrary regular transaction.
arbitraryLegacyTx :: Network -> Gen Tx
arbitraryLegacyTx net = arbitraryWLTx net False

-- | Arbitrary witness transaction (witness data is fake). At least one
-- input has a witness item, since a transaction whose stacks are all
-- empty has no witness.
arbitraryWitnessTx :: Network -> Gen Tx
arbitraryWitnessTx net = arbitraryWLTx net True

-- | Arbitrary witness or legacy transaction.
arbitraryWLTx :: Network -> Bool -> Gen Tx
arbitraryWLTx net wit = do
  ni <- choose (1, 5)
  no <- choose (1, 5)
  inps <- vectorOf ni (arbitraryTxIn net)
  outs <- vectorOf no (arbitraryTxOut net)
  let uniqueInps = nubBy (\a b -> a.outpoint == b.outpoint) inps
  w <-
    if wit
      then (:) <$> listOf1 arbitraryBS <*> vectorOf (length uniqueInps - 1) (listOf arbitraryBS)
      else return []
  Tx <$> arbitrary <*> pure uniqueInps <*> pure outs <*> pure w <*> arbitrary

-- | Arbitrary transaction containing only inputs of type 'SpendPKHash',
-- 'SpendScriptHash' (multisig) and outputs of type 'PayPKHash' and 'PaySH'.
-- Only compressed public keys are used.
arbitraryAddrOnlyTx :: Network -> Gen Tx
arbitraryAddrOnlyTx net = do
  ni <- choose (1, 5)
  no <- choose (1, 5)
  inps <- vectorOf ni (arbitraryAddrOnlyTxIn net)
  outs <- vectorOf no (arbitraryAddrOnlyTxOut net)
  Tx <$> arbitrary <*> pure inps <*> pure outs <*> pure [] <*> arbitrary

-- | Like 'arbitraryAddrOnlyTx' without empty signatures in the inputs.
arbitraryAddrOnlyTxFull :: Network -> Gen Tx
arbitraryAddrOnlyTxFull net = do
  ni <- choose (1, 5)
  no <- choose (1, 5)
  inps <- vectorOf ni (arbitraryAddrOnlyTxInFull net)
  outs <- vectorOf no (arbitraryAddrOnlyTxOut net)
  Tx <$> arbitrary <*> pure inps <*> pure outs <*> pure [] <*> arbitrary

-- | Arbitrary TxIn that can only be of type 'SpendPKHash' or 'SpendScriptHash'
-- (multisig). Only compressed public keys are used.
arbitraryAddrOnlyTxIn :: Network -> Gen TxIn
arbitraryAddrOnlyTxIn net = do
  inp <- oneof [arbitraryPKHashInput net, arbitraryMulSigSHInput net]
  TxIn <$> arbitraryOutPoint <*> pure (marshal net inp) <*> arbitrary

-- | like 'arbitraryAddrOnlyTxIn' with no empty signatures.
arbitraryAddrOnlyTxInFull :: Network -> Gen TxIn
arbitraryAddrOnlyTxInFull net = do
  inp <-
    oneof [arbitraryPKHashInputFullC net, arbitraryMulSigSHInputFullC net]
  TxIn <$> arbitraryOutPoint <*> pure (marshal net inp) <*> arbitrary

-- | Arbitrary 'TxOut' that can only be of type 'PayPKHash' or 'PaySH'.
arbitraryAddrOnlyTxOut :: Network -> Gen TxOut
arbitraryAddrOnlyTxOut net = do
  v <- getTestCoin <$> arbitrarySatoshi net
  out <- oneof [arbitraryPKHashOutput, arbitrarySHOutput]
  return $ TxOut v $ encodeSerial out

-- | Arbitrary 'SigInput' with the corresponding private keys used
-- to generate the 'ScriptOutput' or 'RedeemScript'. On a network with
-- SegWit, it may be a SegWit version 0 output, or a Taproot output spent
-- by its key path. The signer refuses those on a network without SegWit.
arbitrarySigInput :: Network -> Gen (SigInput, [PrivateKey])
arbitrarySigInput net =
  oneof $
    legacySigInputs net
      <> concat [witnessSigInputs net <> [wrapKey <$> arbitraryTaprootSigInput net] | net.segWit]

-- | Arbitrary 'SigInput' of a coin that is not a witness program: locked to
-- a key, to a key hash, to a multisig script, or to the hash of one of
-- those scripts.
arbitraryLegacySigInput :: Network -> Gen (SigInput, [PrivateKey])
arbitraryLegacySigInput = oneof . legacySigInputs

-- | Arbitrary 'SigInput' of a SegWit version 0 coin: a witness key hash or
-- a witness script hash. Only a network with SegWit has such coins.
arbitraryWitnessSigInput :: Network -> Gen (SigInput, [PrivateKey])
arbitraryWitnessSigInput = oneof . witnessSigInputs

legacySigInputs :: Network -> [Gen (SigInput, [PrivateKey])]
legacySigInputs net =
  [ wrapKey <$> arbitraryPKSigInput net,
    wrapKey <$> arbitraryPKHashSigInput net,
    arbitraryMSSigInput net,
    arbitrarySHSigInput net
  ]

witnessSigInputs :: Network -> [Gen (SigInput, [PrivateKey])]
witnessSigInputs net =
  [ wrapKey <$> arbitraryWPKHSigInput net,
    arbitraryWSHSigInput net
  ]

-- | Arbitrary 'SigInput' of a Taproot output without a script tree, spent
-- by its key path with the key of the internal key, as a wallet of BIP 86
-- spends. The sighash is one a Taproot signature may use, other than
-- SIGHASH_SINGLE, which needs an output at the index of the input.
arbitraryTaprootSigInput :: Network -> Gen (SigInput, PrivateKey)
arbitraryTaprootSigInput net = do
  (k, p) <- arbitraryKeyPair
  val <- getTestCoin <$> arbitrarySatoshi net
  op <- arbitraryOutPoint
  sh <- elements [sigHashDefault, sigHashAll, sigHashNone, setAnyoneCanPay sigHashAll, setAnyoneCanPay sigHashNone]
  let out = taprootScriptOutput (TaprootOutput p.point Nothing)
  return (SigInput out val op sh Nothing, k)

-- | Arbitrary 'SigInput' with a 'ScriptOutput' of type 'PayPK'.
arbitraryPKSigInput :: Network -> Gen (SigInput, PrivateKey)
arbitraryPKSigInput net = arbitraryAnyInput net False

-- | Arbitrary 'SigInput' with a 'ScriptOutput' of type 'PayPKHash'.
arbitraryPKHashSigInput :: Network -> Gen (SigInput, PrivateKey)
arbitraryPKHashSigInput net = arbitraryAnyInput net True

-- | Arbitrary 'SigInput' of a key in either form.
arbitraryAnyInput :: Network -> Bool -> Gen (SigInput, PrivateKey)
arbitraryAnyInput net = arbitraryAnyInputOf arbitraryKeyPair net

-- | Arbitrary 'SigInput' with a 'ScriptOutput' of type 'PayPKHash', when
-- the flag is set, or 'PayPK', of a key from the generator given.
arbitraryAnyInputOf ::
  Gen (PrivateKey, PublicKey) -> Network -> Bool -> Gen (SigInput, PrivateKey)
arbitraryAnyInputOf keyPair net pkh = do
  (k, p) <- keyPair
  let out
        | pkh = case addressHash160 (pubKeyAddr p) of
            Just h -> PayPKHash h
            Nothing -> error "Could not get Hash160 from address"
        | otherwise = PayPK p
  (val, op, sh) <- arbitraryInputStuff net
  return (SigInput out val op sh Nothing, k)

-- | Arbitrary value, out point and sighash for an input.
arbitraryInputStuff :: Network -> Gen (Word64, OutPoint, SigHash)
arbitraryInputStuff net = do
  val <- getTestCoin <$> arbitrarySatoshi net
  op <- arbitraryOutPoint
  sh <- arbitraryValidSigHash net
  return (val, op, sh)

-- | Arbitrary 'SigInput' with a 'ScriptOutput' of type 'PayMulSig'.
arbitraryMSSigInput :: Network -> Gen (SigInput, [PrivateKey])
arbitraryMSSigInput = arbitraryMSSigInputOf arbitraryMSParam

-- | Arbitrary 'SigInput' with a 'ScriptOutput' of type 'PayMulSig', whose m
-- of n parameters come from the given generator.
arbitraryMSSigInputOf ::
  Gen (Int, Int) -> Network -> Gen (SigInput, [PrivateKey])
arbitraryMSSigInputOf params net = arbitraryMSSigInputWith arbitraryKeyPair params net

-- | Arbitrary 'SigInput' with a 'ScriptOutput' of type 'PayMulSig', whose
-- keys and m of n parameters come from the given generators.
arbitraryMSSigInputWith ::
  Gen (PrivateKey, PublicKey) -> Gen (Int, Int) -> Network -> Gen (SigInput, [PrivateKey])
arbitraryMSSigInputWith keyPair params net = do
  (m, n) <- params
  ks <- vectorOf n keyPair
  let out = PayMulSig (map snd ks) m
  (val, op, sh) <- arbitraryInputStuff net
  perm <- choose (0, n - 1)
  let ksPerm = map fst $ take m $ permutations ks !! perm
  return (SigInput out val op sh Nothing, ksPerm)

-- | Arbitrary 'SigInput' with 'ScriptOutput' of type 'PaySH' and a
-- 'RedeemScript'. A multisig redeem script has at most 7 keys, so that it
-- fits the 520 bytes of a pay-to-script-hash redeem script with keys of any
-- form.
arbitrarySHSigInput :: Network -> Gen (SigInput, [PrivateKey])
arbitrarySHSigInput net = do
  (SigInput rdm val op sh _, ks) <-
    oneof
      [ wrapKey <$> arbitraryPKSigInput net,
        wrapKey <$> arbitraryPKHashSigInput net,
        arbitraryMSSigInputOf arbitraryP2SHMSParam net
      ]
  let out = case either (const Nothing) addressHash160 (payToScriptAddress rdm) of
        Just h -> PayScriptHash h
        Nothing -> error "Could not get Hash160 from address"
  return (SigInput out val op sh $ Just rdm, ks)

-- | Arbitrary 'SigInput' with a 'ScriptOutput' of type 'PayWitnessPKHash'.
-- The key is compressed, as nodes require of a SegWit version 0 input.
arbitraryWPKHSigInput :: Network -> Gen (SigInput, PrivateKey)
arbitraryWPKHSigInput net = do
  (k, p) <- arbitraryKeyPairC
  (val, op, sh) <- arbitraryInputStuff net
  let out = case addressHash160 (pubKeyAddr p) of
        Just h -> PayWitnessPKHash h
        Nothing -> error "Could not get Hash160 from address"
  return (SigInput out val op sh Nothing, k)

-- | Arbitrary 'SigInput' with a 'ScriptOutput' of type
-- 'PayWitnessScriptHash' and its witness script. The keys of the witness
-- script are compressed, as nodes require of a SegWit version 0 input.
arbitraryWSHSigInput :: Network -> Gen (SigInput, [PrivateKey])
arbitraryWSHSigInput net = do
  (SigInput rdm val op sh _, ks) <-
    oneof
      [ wrapKey <$> arbitraryAnyInputOf arbitraryKeyPairC net False,
        wrapKey <$> arbitraryAnyInputOf arbitraryKeyPairC net True,
        arbitraryMSSigInputWith arbitraryKeyPairC arbitraryMSParam net
      ]
  let out = case either (const Nothing) addressHash256 (payToWitnessScriptAddress rdm) of
        Just h -> PayWitnessScriptHash h
        Nothing -> error "Could not get Hash256 from address"
  return (SigInput out val op sh $ Just rdm, ks)

-- | Arbitrary 'Tx' (empty 'TxIn'), 'SigInputs' and private keys that can be
-- passed to 'signTx' or 'detSignTx' to fully sign the 'Tx'. The outputs
-- spend no more than the inputs hold.
arbitrarySigningData :: Network -> Gen (Tx, [SigInput], [PrivateKey])
arbitrarySigningData net = do
  ni <- choose (1, 5)
  arbitrarySigningDataOf net =<< vectorOf ni (arbitrarySigInput net)

-- | 'arbitrarySigningData' for these coins and their keys, to choose what
-- the transaction spends. Of two coins with the same outpoint, the first is
-- kept. The inputs of the transaction are in an arbitrary order.
arbitrarySigningDataOf :: Network -> [(SigInput, [PrivateKey])] -> Gen (Tx, [SigInput], [PrivateKey])
arbitrarySigningDataOf net sigis = do
  v <- arbitrary
  let uSigis = nubBy (\(a, _) (b, _) -> a.outpoint == b.outpoint) sigis
  -- The signer refuses SIGHASH_SINGLE on an input without an output at
  -- its index, so every input gets an output when one asks for it
  no <- choose (if any (isSigHashSingle . (.sighash) . fst) uSigis then length uSigis else 1, 5)
  inps <- forM uSigis $ \(s, _) -> TxIn s.outpoint BS.empty <$> arbitrary
  outs <- arbitraryOutputsWithin net (sum (map ((.value) . fst) uSigis)) no
  l <- arbitrary
  perm <- choose (0, length inps - 1)
  let tx = Tx v (permutations inps !! perm) outs [] l
      keys = concatMap snd uSigis
  return (tx, map fst uSigis, keys)

-- | Whether the input is to be signed with SIGHASH_SINGLE over the legacy
-- digest, which is the constant 1 when the input has no output at its
-- index. 'makeSignature' refuses to sign that. 'signTx' refuses
-- SIGHASH_SINGLE on any input without an output at its index, so the
-- generators here ask 'isSigHashSingle' alone.
legacySingle :: Network -> SigInput -> Bool
legacySingle net si =
  isSigHashSingle si.sighash && not (isSegwit si.script) && isNothing net.sigHashForkId

-- | Arbitrary outputs whose values add up to at most the amount given
arbitraryOutputsWithin :: Network -> Word64 -> Int -> Gen [TxOut]
arbitraryOutputsWithin net total count =
  vectorOf count $
    TxOut
      <$> choose (0, total `div` fromIntegral count)
      <*> (encodeSerial <$> arbitraryScriptOutput net)

-- | Arbitrary transaction with empty inputs.
arbitraryEmptyTx :: Network -> Gen Tx
arbitraryEmptyTx net = do
  v <- arbitrary
  no <- choose (1, 5)
  ni <- choose (1, 5)
  outs <- vectorOf no (arbitraryTxOut net)
  ops <- vectorOf ni arbitraryOutPoint
  t <- arbitrary
  s <- arbitrary
  return $ Tx v (map (\op -> TxIn op BS.empty s) (nub ops)) outs [] t

-- | Arbitrary partially-signed transactions. The outputs spend no more
-- than the coins hold.
arbitraryPartialTxs ::
  Network -> Gen ([Tx], [(ScriptOutput, Word64, OutPoint, Int, Int)])
arbitraryPartialTxs net = do
  empty <- arbitraryEmptyTx net
  coins <- forM (map (.outpoint) empty.inputs) $ \op -> (,) op <$> arbitraryData
  outs <- arbitraryOutputsWithin net (sum [val | (_, (_, val, _, _, _, _)) <- coins]) (length empty.outputs)
  let tx = Tx empty.version empty.inputs outs [] empty.locktime
  res <-
    forM coins $ \(op, (so, val, rdmM, prvs, m, n)) -> do
      txs <- mapM (singleSig so val rdmM tx op . (.key)) prvs
      return (txs, (so, val, op, m, n))
  return (concatMap fst res, map snd res)
  where
    singleSig so val rdmM tx op prv = do
      -- The signer refuses SIGHASH_SINGLE on an input without an output
      -- at its index
      let index = fromMaybe 0 (findIndex ((== op) . (.outpoint)) tx.inputs)
          refused sh = index >= length tx.outputs && isSigHashSingle sh
      sh <- arbitraryValidSigHash net `suchThat` (not . refused)
      let sigi = SigInput so val op sh rdmM
      return . fromRight (error "Could not decode transaction") $
        signTx net tx [sigi] [prv]
    arbitraryData = do
      -- At most 7 keys, so that the script also fits a pay-to-script-hash
      -- redeem script
      (m, n) <- arbitraryP2SHMSParam
      val <- getTestCoin <$> arbitrarySatoshi net
      nPrv <- choose (m, n)
      keys <- vectorOf n arbitraryKeyPair
      perm <- choose (0, length keys - 1)
      let pubKeys = map snd keys
          prvKeys = take nPrv $ permutations (map fst keys) !! perm
      let so = PayMulSig pubKeys m
      let h =
            fromMaybe
              (error "Could not get Hash160 from address")
              (either (const Nothing) addressHash160 (payToScriptAddress so))
      elements
        [ (so, val, Nothing, prvKeys, m, n),
          ( PayScriptHash h,
            val,
            Just so,
            prvKeys,
            m,
            n
          )
        ]

wrapKey :: (SigInput, PrivateKey) -> (SigInput, [PrivateKey])
wrapKey (s, k) = (s, [k])

-- | Arbitrary PSBT of a transaction of the network, of version 0 or 2,
-- with fields of every kind: previous transactions, witness outputs,
-- partial signatures, sighash types, scripts, final scripts, derivation
-- records, extended public keys, the Taproot fields, proprietary fields,
-- and keys the spec does not define. An input that carries a previous
-- transaction spends an output of it, as 'decodePsbt' requires. One PSBT
-- in ten has no input. One of version 2 may have its flags, and lock
-- times its inputs require.
arbitraryPsbt :: Network -> Gen Psbt
arbitraryPsbt net = do
  drawn <- arbitraryTx net
  inputs0 <- frequency [(9, return drawn.inputs), (1, return [])]
  parents <- mapM (const (oneof [return Nothing, Just <$> spendable])) inputs0
  let spend input = maybe input (\(parent, index) -> TxIn (OutPoint (txHash parent) index) input.script input.sequence)
      base = psbtOf (Tx drawn.version (zipWith spend inputs0 parents) drawn.outputs [] drawn.locktime)
  globals <- globalFields
  inputs <- mapM inputFields parents
  outputs <- mapM (const outputFields) base.outputs
  let version0 = Psbt Version0 base.unsignedTx globals inputs outputs
  oneof [return version0, version2 version0]
  where
    -- A transaction with at least one output, and the index of one of them
    spendable = do
      parent <- arbitraryTx net
      extra <- arbitraryTxOut net
      let outputs = if null parent.outputs then [extra] else parent.outputs
      index <- choose (0, length outputs - 1)
      return (Tx parent.version parent.inputs outputs parent.witness parent.locktime, fromIntegral index)
    -- The same PSBT in version 2, with flags at times, and lock times the
    -- inputs require: all heights, all times, or both in every input, so
    -- that one fits them all. The PSBT is rebuilt from its maps for the
    -- lock time they determine.
    version2 version0 = do
      let converted = withVersion Version2 version0
      -- The bits the spec does not define are those from the fourth on: a multiple of 8
      flagsM <- oneof [return Nothing, Just <$> (Modifiable <$> arbitrary <*> arbitrary <*> arbitrary <*> ((8 *) <$> choose (0, 31)))]
      kind <- choose (0 :: Int, 2)
      inputs <- forM converted.inputs $ \m -> do
        asks <- arbitrary
        height <- choose (1, 499999999)
        time <- choose (500000000, maxBound)
        return $
          if not asks
            then m
            else case kind of
              0 -> insertRequiredHeightLockTime height m
              1 -> insertRequiredTimeLockTime time m
              _ -> insertRequiredHeightLockTime height (insertRequiredTimeLockTime time m)
      let globals = maybe id insertTxModifiable flagsM converted.globals
      either (error . ("arbitraryPsbt: " <>)) return (psbtOfMaps globals inputs converted.outputs)
    -- Types from 0x20 to 0x7f are none the spec defines for any map. A
    -- type from 253 on is written over three bytes: 0xfd, then the type
    -- over two bytes, little-endian, which are the start of the key data.
    unknownFields = Map.fromList <$> resize 3 (listOf (oneof [unknownField, wideTypeField, proprietaryField]))
    unknownField = (,) <$> (Key <$> choose (0x20, 0x7f) <*> arbitraryBS) <*> arbitraryBS
    wideTypeField = do
      wide <- choose (0xfd, 0xffff :: Int)
      rest <- arbitraryBS
      (,) (Key 0xfd (BS.pack [fromIntegral (wide `mod` 256), fromIntegral (wide `div` 256)] <> rest)) <$> arbitraryBS
    proprietaryField = (,) <$> (proprietaryKey <$> (Proprietary <$> arbitraryBS <*> arbitrary <*> arbitraryBS)) <*> arbitraryBS
    globalFields = do
      m <- unknownFields
      xpubs <- resize 2 (listOf xpubRecord)
      return (foldr ($) m xpubs)
    -- The path of an extended key has one index per level of its depth
    xpubRecord = do
      xpub <- arbitraryXPubKey
      path <- listToPath <$> vectorOf (fromIntegral xpub.depth) arbitrary
      (\fingerprint -> insertXpubRecord net xpub (Derivation fingerprint path)) <$> arbitraryFingerprint
    inputFields parentM = do
      m <- unknownFields
      fields <-
        sequence
          [ return (maybe id (insertNonWitnessUtxo . fst) parentM),
            maybeField (insertWitnessUtxo <$> arbitraryTxOut net),
            maybeField (insertSigHashType . fromIntegral <$> (arbitrary :: Gen Word32)),
            maybeField (insertInputRedeemScript <$> arbitraryScript),
            maybeField (insertInputWitnessScript <$> arbitraryScript),
            maybeField (insertFinalScriptSig <$> arbitraryBS),
            maybeField (insertFinalScriptWitness <$> resize 3 (listOf arbitraryBS)),
            derivations insertInputDerivation,
            partialSignatures,
            maybeField (insertInputTapInternalKey <$> point),
            maybeField (insertInputTapMerkleRoot <$> digest),
            maybeField (insertTapKeySig <$> arbitraryTapSig),
            maybeField (insertTapScriptSig <$> point <*> digest <*> arbitraryTapSig),
            maybeField (insertTapLeafScript <$> leafScript),
            maybeField (insertInputTapDerivation <$> point <*> tapDerivation)
          ]
      return (foldr ($) m fields)
    outputFields = do
      m <- unknownFields
      fields <-
        sequence
          [ maybeField (insertOutputRedeemScript <$> arbitraryScript),
            maybeField (insertOutputWitnessScript <$> arbitraryScript),
            derivations insertOutputDerivation,
            maybeField (insertOutputTapInternalKey <$> point),
            maybeField (insertOutputTapTree <$> scriptTree),
            maybeField (insertOutputTapDerivation <$> point <*> tapDerivation)
          ]
      return (foldr ($) m fields)
    maybeField gen = oneof [return id, gen]
    derivations insert = do
      records <- resize 2 (listOf ((,) <$> (snd <$> arbitraryKeyPair) <*> (Derivation <$> arbitraryFingerprint <*> arbitraryDerivPath)))
      return $ foldr (\(key, derivation) inserted -> insert key derivation . inserted) id records
    -- Signatures of a sighash type the network defines, under keys that
    -- need not be theirs: a PSBT is read without verifying them
    partialSignatures = do
      signatures <- resize 2 (listOf ((,) <$> (snd <$> arbitraryKeyPair) <*> ((\(_, _, signature) -> encodeTxSig net signature) <$> arbitraryTxSignature net)))
      return $ foldr (\(key, signature) inserted -> insertPartialSignature key signature . inserted) id signatures
    point = (.point) . snd <$> arbitraryKeyPair
    digest = leafHash 0xc0 <$> arbitraryScript
    -- 64 bytes, alone or with one of the six sighash bytes of BIP 341
    arbitraryTapSig = do
      bytes <- arbitraryBSn 64
      sighash <- elements [[], [0x01], [0x02], [0x03], [0x81], [0x82], [0x83]]
      return (fromRight (error "arbitraryPsbt: Taproot signature") (decodeTaprootSig (bytes <> BS.pack sighash)))
    leafScript = do
      internal <- point
      nodes <- resize 3 (listOf digest)
      (\script -> TapLeafScript (encodeControlBlock 0xc0 internal nodes) script 0xc0) <$> arbitraryScript
    tapDerivation = TapDerivation <$> resize 2 (listOf digest) <*> (Derivation <$> arbitraryFingerprint <*> arbitraryDerivPath)
    -- The leaves of a whole tree: one leaf alone, or two under the root
    scriptTree =
      oneof
        [ (\script -> [TapLeaf 0 0xc0 script]) <$> arbitraryScript,
          (\a b -> [TapLeaf 1 0xc0 a, TapLeaf 1 0xc0 b]) <$> arbitraryScript <*> arbitraryScript
        ]
