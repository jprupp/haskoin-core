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
import Data.List (nub, nubBy, permutations)
import Data.Maybe (fromMaybe)
import Data.Word (Word64)
import Haskoin.Address
import Haskoin.Crypto (Ctx)
import Haskoin.Crypto.Keys.Common
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary.Crypto
import Haskoin.Util.Arbitrary.Keys
import Haskoin.Util.Arbitrary.Script
import Haskoin.Util.Arbitrary.Util
import Test.QuickCheck

-- | Wrapped coin value for testing.
newtype TestCoin = TestCoin {getTestCoin :: Word64}
  deriving (Eq, Show)

instance Coin TestCoin where
  coinValue = getTestCoin

-- | Arbitrary transaction hash (for non-existent transaction).
arbitraryTxHash :: Gen TxHash
arbitraryTxHash = TxHash <$> arbitraryHash256

-- | Arbitrary amount of Satoshi as 'Word64' (Between 1 and 21e14)
arbitrarySatoshi :: Network -> Gen TestCoin
arbitrarySatoshi net = TestCoin <$> choose (1, net.maxSatoshi)

-- | Arbitrary 'OutPoint'.
arbitraryOutPoint :: Gen OutPoint
arbitraryOutPoint = OutPoint <$> arbitraryTxHash <*> arbitrary

-- | Arbitrary 'TxOut'.
arbitraryTxOut :: Network -> Ctx -> Gen TxOut
arbitraryTxOut net ctx =
  TxOut
    <$> (getTestCoin <$> arbitrarySatoshi net)
    <*> (marshal ctx <$> arbitraryScriptOutput net ctx)

-- | Arbitrary 'TxIn'.
arbitraryTxIn :: Network -> Ctx -> Gen TxIn
arbitraryTxIn net ctx =
  TxIn
    <$> arbitraryOutPoint
    <*> (marshal (net, ctx) <$> arbitraryScriptInput net ctx)
    <*> arbitrary

-- | Arbitrary transaction. Can be regular or with witnesses.
arbitraryTx :: Network -> Ctx -> Gen Tx
arbitraryTx net ctx =
  oneof [arbitraryLegacyTx net ctx, arbitraryWitnessTx net ctx]

-- | Arbitrary regular transaction.
arbitraryLegacyTx :: Network -> Ctx -> Gen Tx
arbitraryLegacyTx net ctx = arbitraryWLTx net ctx False

-- | Arbitrary witness transaction (witness data is fake).
arbitraryWitnessTx :: Network -> Ctx -> Gen Tx
arbitraryWitnessTx net ctx = arbitraryWLTx net ctx True

-- | Arbitrary witness or legacy transaction.
arbitraryWLTx :: Network -> Ctx -> Bool -> Gen Tx
arbitraryWLTx net ctx wit = do
  ni <- choose (1, 5)
  no <- choose (1, 5)
  inps <- vectorOf ni (arbitraryTxIn net ctx)
  outs <- vectorOf no (arbitraryTxOut net ctx)
  let uniqueInps = nubBy (\a b -> a.outpoint == b.outpoint) inps
  w <-
    if wit
      then vectorOf (length uniqueInps) (listOf arbitraryBS)
      else return []
  Tx <$> arbitrary <*> pure uniqueInps <*> pure outs <*> pure w <*> arbitrary

-- | Arbitrary transaction containing only inputs of type 'SpendPKHash',
-- 'SpendScriptHash' (multisig) and outputs of type 'PayPKHash' and 'PaySH'.
-- Only compressed public keys are used.
arbitraryAddrOnlyTx :: Network -> Ctx -> Gen Tx
arbitraryAddrOnlyTx net ctx = do
  ni <- choose (1, 5)
  no <- choose (1, 5)
  inps <- vectorOf ni (arbitraryAddrOnlyTxIn net ctx)
  outs <- vectorOf no (arbitraryAddrOnlyTxOut net ctx)
  Tx <$> arbitrary <*> pure inps <*> pure outs <*> pure [] <*> arbitrary

-- | Like 'arbitraryAddrOnlyTx' without empty signatures in the inputs.
arbitraryAddrOnlyTxFull :: Network -> Ctx -> Gen Tx
arbitraryAddrOnlyTxFull net ctx = do
  ni <- choose (1, 5)
  no <- choose (1, 5)
  inps <- vectorOf ni (arbitraryAddrOnlyTxInFull net ctx)
  outs <- vectorOf no (arbitraryAddrOnlyTxOut net ctx)
  Tx <$> arbitrary <*> pure inps <*> pure outs <*> pure [] <*> arbitrary

-- | Arbitrary TxIn that can only be of type 'SpendPKHash' or 'SpendScriptHash'
-- (multisig). Only compressed public keys are used.
arbitraryAddrOnlyTxIn :: Network -> Ctx -> Gen TxIn
arbitraryAddrOnlyTxIn net ctx = do
  inp <- oneof [arbitraryPKHashInput net ctx, arbitraryMulSigSHInput net ctx]
  TxIn <$> arbitraryOutPoint <*> pure (marshal (net, ctx) inp) <*> arbitrary

-- | like 'arbitraryAddrOnlyTxIn' with no empty signatures.
arbitraryAddrOnlyTxInFull :: Network -> Ctx -> Gen TxIn
arbitraryAddrOnlyTxInFull net ctx = do
  inp <-
    oneof [arbitraryPKHashInputFullC net ctx, arbitraryMulSigSHInputFullC net ctx]
  TxIn <$> arbitraryOutPoint <*> pure (marshal (net, ctx) inp) <*> arbitrary

-- | Arbitrary 'TxOut' that can only be of type 'PayPKHash' or 'PaySH'.
arbitraryAddrOnlyTxOut :: Network -> Ctx -> Gen TxOut
arbitraryAddrOnlyTxOut net ctx = do
  v <- getTestCoin <$> arbitrarySatoshi net
  out <- oneof [arbitraryPKHashOutput, arbitrarySHOutput]
  return $ TxOut v $ marshal ctx out

-- | Arbitrary 'SigInput' with the corresponding private keys used
-- to generate the 'ScriptOutput' or 'RedeemScript'.
arbitrarySigInput :: Network -> Ctx -> Gen (SigInput, [PrivateKey])
arbitrarySigInput net ctx =
  oneof
    [ wrapKey <$> arbitraryPKSigInput net ctx,
      wrapKey <$> arbitraryPKHashSigInput net ctx,
      arbitraryMSSigInput net ctx,
      arbitrarySHSigInput net ctx,
      wrapKey <$> arbitraryWPKHSigInput net ctx,
      arbitraryWSHSigInput net ctx
    ]

-- | Arbitrary 'SigInput' with a 'ScriptOutput' of type 'PayPK'.
arbitraryPKSigInput :: Network -> Ctx -> Gen (SigInput, PrivateKey)
arbitraryPKSigInput net ctx = arbitraryAnyInput net ctx False

-- | Arbitrary 'SigInput' with a 'ScriptOutput' of type 'PayPKHash'.
arbitraryPKHashSigInput :: Network -> Ctx -> Gen (SigInput, PrivateKey)
arbitraryPKHashSigInput net ctx = arbitraryAnyInput net ctx True

-- | Arbitrary 'SigInput'.
arbitraryAnyInput :: Network -> Ctx -> Bool -> Gen (SigInput, PrivateKey)
arbitraryAnyInput net ctx pkh = do
  (k, p) <- arbitraryKeyPair ctx
  let out
        | pkh = case addressHash160 (pubKeyAddr ctx p) of
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
arbitraryMSSigInput :: Network -> Ctx -> Gen (SigInput, [PrivateKey])
arbitraryMSSigInput net ctx = do
  (m, n) <- arbitraryMSParam
  ks <- vectorOf n (arbitraryKeyPair ctx)
  let out = PayMulSig (map snd ks) m
  (val, op, sh) <- arbitraryInputStuff net
  perm <- choose (0, n - 1)
  let ksPerm = map fst $ take m $ permutations ks !! perm
  return (SigInput out val op sh Nothing, ksPerm)

-- | Arbitrary 'SigInput' with 'ScriptOutput' of type 'PaySH' and a
-- 'RedeemScript'.
arbitrarySHSigInput :: Network -> Ctx -> Gen (SigInput, [PrivateKey])
arbitrarySHSigInput net ctx = do
  (SigInput rdm val op sh _, ks) <-
    oneof
      [ wrapKey <$> arbitraryPKSigInput net ctx,
        wrapKey <$> arbitraryPKHashSigInput net ctx,
        arbitraryMSSigInput net ctx
      ]
  let out = case addressHash160 (payToScriptAddress ctx rdm) of
        Just h -> PayScriptHash h
        Nothing -> error "Could not get Hash160 from address"
  return (SigInput out val op sh $ Just rdm, ks)

arbitraryWPKHSigInput :: Network -> Ctx -> Gen (SigInput, PrivateKey)
arbitraryWPKHSigInput net ctx = do
  (k, p) <- arbitraryKeyPair ctx
  (val, op, sh) <- arbitraryInputStuff net
  let out = case addressHash160 (pubKeyAddr ctx p) of
        Just h -> PayWitnessPKHash h
        Nothing -> error "Could not get Hash160 from address"
  return (SigInput out val op sh Nothing, k)

arbitraryWSHSigInput :: Network -> Ctx -> Gen (SigInput, [PrivateKey])
arbitraryWSHSigInput net ctx = do
  (SigInput rdm val op sh _, ks) <-
    oneof
      [ wrapKey <$> arbitraryPKSigInput net ctx,
        wrapKey <$> arbitraryPKHashSigInput net ctx,
        arbitraryMSSigInput net ctx
      ]
  let out = case addressHash256 (payToWitnessScriptAddress ctx rdm) of
        Just h -> PayWitnessScriptHash h
        Nothing -> error "Could not get Hash256 from address"
  return (SigInput out val op sh $ Just rdm, ks)

-- | Arbitrary 'Tx' (empty 'TxIn'), 'SigInputs' and private keys that can be
-- passed to 'signTx' or 'detSignTx' to fully sign the 'Tx'.
arbitrarySigningData :: Network -> Ctx -> Gen (Tx, [SigInput], [PrivateKey])
arbitrarySigningData net ctx = do
  v <- arbitrary
  ni <- choose (1, 5)
  no <- choose (1, 5)
  sigis <- vectorOf ni (arbitrarySigInput net ctx)
  let uSigis = nubBy (\(a, _) (b, _) -> a.outpoint == b.outpoint) sigis
  inps <- forM uSigis $ \(s, _) -> TxIn s.outpoint BS.empty <$> arbitrary
  outs <- vectorOf no (arbitraryTxOut net ctx)
  l <- arbitrary
  perm <- choose (0, length inps - 1)
  let tx = Tx v (permutations inps !! perm) outs [] l
      keys = concatMap snd uSigis
  return (tx, map fst uSigis, keys)

-- | Arbitrary transaction with empty inputs.
arbitraryEmptyTx :: Network -> Ctx -> Gen Tx
arbitraryEmptyTx net ctx = do
  v <- arbitrary
  no <- choose (1, 5)
  ni <- choose (1, 5)
  outs <- vectorOf no (arbitraryTxOut net ctx)
  ops <- vectorOf ni arbitraryOutPoint
  t <- arbitrary
  s <- arbitrary
  return $ Tx v (map (\op -> TxIn op BS.empty s) (nub ops)) outs [] t

-- | Arbitrary partially-signed transactions.
arbitraryPartialTxs ::
  Network -> Ctx -> Gen ([Tx], [(ScriptOutput, Word64, OutPoint, Int, Int)])
arbitraryPartialTxs net ctx = do
  tx <- arbitraryEmptyTx net ctx
  res <-
    forM (map (.outpoint) tx.inputs) $ \op -> do
      (so, val, rdmM, prvs, m, n) <- arbitraryData
      txs <- mapM (singleSig so val rdmM tx op . (.key)) prvs
      return (txs, (so, val, op, m, n))
  return (concatMap fst res, map snd res)
  where
    singleSig so val rdmM tx op prv = do
      sh <- arbitraryValidSigHash net
      let sigi = SigInput so val op sh rdmM
      return . fromRight (error "Could not decode transaction") $
        signTx net ctx tx [sigi] [prv]
    arbitraryData = do
      (m, n) <- arbitraryMSParam
      val <- getTestCoin <$> arbitrarySatoshi net
      nPrv <- choose (m, n)
      keys <- vectorOf n (arbitraryKeyPair ctx)
      perm <- choose (0, length keys - 1)
      let pubKeys = map snd keys
          prvKeys = take nPrv $ permutations (map fst keys) !! perm
      let so = PayMulSig pubKeys m
      let h =
            fromMaybe
              (error "Could not get Hash160 from address")
              (addressHash160 (payToScriptAddress ctx so))
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
