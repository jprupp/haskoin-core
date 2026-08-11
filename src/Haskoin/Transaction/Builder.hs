{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Transaction.Builder
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Code to simplify transaction creation, signing, fee calculation and coin
-- selection.
module Haskoin.Transaction.Builder
  ( -- * Transaction Builder
    buildAddrTx,
    buildTx,
    buildInput,
    SigInput (..),
    signTx,
    signNestedWitnessTx,
    makeSignature,
    signInput,
    signNestedInput,
    verifyStdTx,
    mergeTxs,
    sigKeys,
    mergeTxInput,
    findSigInput,
    verifyStdInput,

    -- * Coin Selection
    Coin (..),
    chooseCoins,
    chooseCoinsSink,
    chooseMSCoins,
    chooseMSCoinsSink,
    countMulSig,
    greedyAddSink,
    guessTxFee,
    guessMSTxFee,
    guessTxSize,
    guessMSSize,
  )
where

import Control.Applicative ((<|>))
import Control.Arrow (first)
import Control.Monad (foldM, unless)
import Control.Monad.Identity (runIdentity)
import Crypto.Secp256k1
import Data.ByteString qualified as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Conduit (ConduitT, Void, await, runConduit, (.|))
import Data.Conduit.List (sourceList)
import Data.Either (fromRight, rights)
import Data.List (nub)
import Data.Maybe (catMaybes, fromJust, isJust)
import Data.String.Conversions (cs)
import Data.Text (Text)
import Data.Word (Word64)
import Haskoin.Address
import Haskoin.Crypto.Hash (Hash256, addressHash)
import Haskoin.Crypto.Keys.Common
import Haskoin.Crypto.Signature
import Haskoin.Network.Common
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction.Builder.Sign (SigInput, buildInput, makeSignature, sigKeys)
import Haskoin.Transaction.Builder.Sign qualified as Sign
import Haskoin.Transaction.Common
import Haskoin.Transaction.Segwit
import Haskoin.Util

-- | Any type can be used as a Coin if it can provide a value in Satoshi.
-- The value is used in coin selection algorithms.
class Coin c where
  coinValue :: c -> Word64

-- | Coin selection algorithm for normal (non-multisig) transactions. This
-- function returns the selected coins together with the amount of change to
-- send back to yourself, taking the fee into account.
chooseCoins ::
  (Coin c) =>
  -- | value to send
  Word64 ->
  -- | fee per byte
  Word64 ->
  -- | number of outputs (including change)
  Int ->
  -- | try to find better solutions
  Bool ->
  -- | list of ordered coins to choose from
  [c] ->
  -- | coin selection and change
  Either String ([c], Word64)
chooseCoins target fee nOut continue coins =
  runIdentity . runConduit $
    sourceList coins .| chooseCoinsSink target fee nOut continue

-- | Coin selection algorithm for normal (non-multisig) transactions. This
-- function returns the selected coins together with the amount of change to
-- send back to yourself, taking the fee into account. This version uses a Sink
-- for conduit-based coin selection.
chooseCoinsSink ::
  (Monad m, Coin c) =>
  -- | value to send
  Word64 ->
  -- | fee per byte
  Word64 ->
  -- | number of outputs (including change)
  Int ->
  -- | try to find better solution
  Bool ->
  -- | coin selection and change
  ConduitT c Void m (Either String ([c], Word64))
chooseCoinsSink target fee nOut continue
  | target > 0 =
      maybeToEither err
        <$> greedyAddSink target (guessTxFee fee nOut) continue
  | otherwise = return $ Left "chooseCoins: Target must be > 0"
  where
    err = "chooseCoins: No solution found"

-- | Coin selection algorithm for multisig transactions. This function returns
-- the selected coins together with the amount of change to send back to
-- yourself, taking the fee into account. This function assumes all the coins
-- are script hash outputs that send funds to a multisignature address.
chooseMSCoins ::
  (Coin c) =>
  -- | value to send
  Word64 ->
  -- | fee per byte
  Word64 ->
  -- | m of n multisig
  (Int, Int) ->
  -- | number of outputs (including change)
  Int ->
  -- | try to find better solution
  Bool ->
  [c] ->
  -- | coin selection change amount
  Either String ([c], Word64)
chooseMSCoins target fee ms nOut continue coins =
  runIdentity . runConduit $
    sourceList coins .| chooseMSCoinsSink target fee ms nOut continue

-- | Coin selection algorithm for multisig transactions. This function returns
-- the selected coins together with the amount of change to send back to
-- yourself, taking the fee into account. This function assumes all the coins
-- are script hash outputs that send funds to a multisignature address. This
-- version uses a Sink if you need conduit-based coin selection.
chooseMSCoinsSink ::
  (Monad m, Coin c) =>
  -- | value to send
  Word64 ->
  -- | fee per byte
  Word64 ->
  -- | m of n multisig
  (Int, Int) ->
  -- | number of outputs (including change)
  Int ->
  -- | try to find better solution
  Bool ->
  -- | coin selection and change
  ConduitT c Void m (Either String ([c], Word64))
chooseMSCoinsSink target fee ms nOut continue
  | target > 0 =
      maybeToEither err
        <$> greedyAddSink target (guessMSTxFee fee ms nOut) continue
  | otherwise = return $ Left "chooseMSCoins: Target must be > 0"
  where
    err = "chooseMSCoins: No solution found"

-- | Select coins greedily by starting from an empty solution. If the 'continue'
-- flag is set, the algorithm will try to find a better solution in the stream
-- after a solution is found. If the next solution found is not strictly better
-- than the previously found solution, the algorithm stops and returns the
-- previous solution. If the continue flag is not set, the algorithm will return
-- the first solution it finds in the stream.
greedyAddSink ::
  (Monad m, Coin c) =>
  -- | value to send
  Word64 ->
  -- | coin count to fee function
  (Int -> Word64) ->
  -- | try to find better solutions
  Bool ->
  -- | coin selection and change
  ConduitT c Void m (Maybe ([c], Word64))
greedyAddSink target guessFee continue =
  go [] 0 [] 0
  where
    -- The goal is the value we must reach (including the fee) for a certain
    -- amount of selected coins.
    goal c = target + guessFee c
    go acc aTot ps pTot =
      await >>= \case
        -- A coin is available in the stream
        Just coin -> do
          let val = coinValue coin
          -- We have reached the goal using this coin
          if val + aTot >= goal (length acc + 1)
            then -- If we want to continue searching for better solutions
              if continue
                then -- This solution is the first one or
                -- This solution is better than the previous one
                  if pTot == 0 || val + aTot < pTot
                    then -- Continue searching for better solutions in the stream
                      go [] 0 (coin : acc) (val + aTot)
                    else -- Otherwise, we stop here and return the previous
                    -- solution
                      return $ Just (ps, pTot - goal (length ps))
                else -- Otherwise, return this solution
                  return $
                    Just (coin : acc, val + aTot - goal (length acc + 1))
            else -- We have not yet reached the goal. Add the coin to the
            -- accumulator
              go (coin : acc) (val + aTot) ps pTot
        -- We reached the end of the stream
        Nothing ->
          return $
            if null ps
              then -- If no solution was found, return Nothing
                Nothing
              else -- If we have a solution, return it
                Just (ps, pTot - goal (length ps))

-- | Estimate tranasction fee to pay based on transaction size estimation.
guessTxFee :: Word64 -> Int -> Int -> Word64
guessTxFee byteFee nOut nIn =
  byteFee * fromIntegral (guessTxSize nIn [] nOut 0)

-- | Same as 'guessTxFee' but for multisig transactions.
guessMSTxFee :: Word64 -> (Int, Int) -> Int -> Int -> Word64
guessMSTxFee byteFee ms nOut nIn =
  byteFee * fromIntegral (guessTxSize 0 (replicate nIn ms) nOut 0)

-- | Computes an upper bound on the size of a transaction based on some known
-- properties of the transaction.
guessTxSize ::
  -- | number of regular transaction inputs
  Int ->
  -- | multisig m of n for each input
  [(Int, Int)] ->
  -- | number of P2PKH outputs
  Int ->
  -- | number of P2SH outputs
  Int ->
  -- | upper bound on transaction size
  Int
guessTxSize pki msi pkout msout =
  8 + inpLen + inp + outLen + out
  where
    inpLen =
      B.length
        . runPutS
        . serialize
        . VarInt
        . fromIntegral
        $ length msi + pki
    outLen =
      B.length
        . runPutS
        . serialize
        . VarInt
        . fromIntegral
        $ pkout + msout
    inp = pki * 148 + sum (map guessMSSize msi)
    -- (20: hash160) + (5: opcodes) +
    -- (1: script len) + (8: Word64)
    out =
      pkout * 34
        +
        -- (20: hash160) + (3: opcodes) +
        -- (20: hash160) + (3: opcodes) +
        -- (20: hash160) + (3: opcodes) +
        -- (20: hash160) + (3: opcodes) +
        -- (1: script len) + (8: Word64)
        -- (1: script len) + (8: Word64)
        -- (1: script len) + (8: Word64)
        -- (1: script len) + (8: Word64)

        -- (20: hash160) + (3: opcodes) +

        -- (20: hash160) + (3: opcodes) +
        -- (1: script len) + (8: Word64)
        -- (1: script len) + (8: Word64)

        -- (20: hash160) + (3: opcodes) +
        -- (20: hash160) + (3: opcodes) +
        -- (1: script len) + (8: Word64)
        -- (1: script len) + (8: Word64)

        -- (20: hash160) + (3: opcodes) +
        -- (1: script len) + (8: Word64)
        msout * 32

-- | Size of a multisig P2SH input.
guessMSSize :: (Int, Int) -> Int
guessMSSize (m, n) =
  -- OutPoint (36) + Sequence (4) + Script
  40
    + fromIntegral (B.length $ runPutS . serialize $ VarInt $ fromIntegral scp)
    + scp
  where
    -- OP_M + n*PubKey + OP_N + OP_CHECKMULTISIG

    rdm =
      fromIntegral $
        B.length $
          runPutS $
            serialize $
              opPushData $
                B.replicate (n * 34 + 3) 0
    -- Redeem + m*sig + OP_0
    scp = rdm + m * 73 + 1

{- Build a new Tx -}

-- | Build a transaction by providing a list of outpoints as inputs
-- and a list of recipient addresses and amounts as outputs.
buildAddrTx :: Network -> Ctx -> [OutPoint] -> [(Text, Word64)] -> Either String Tx
buildAddrTx net ctx ops rcps =
  buildTx ctx ops <$> mapM f rcps
  where
    f (aTxt, v) =
      maybeToEither ("buildAddrTx: Invalid address " <> cs aTxt) $ do
        a <- textToAddr net aTxt
        o <- addressToOutput a
        return (o, v)

-- | Build a transaction by providing a list of outpoints as inputs
-- and a list of 'ScriptOutput' and amounts as outputs.
buildTx :: Ctx -> [OutPoint] -> [(ScriptOutput, Word64)] -> Tx
buildTx ctx ops rcpts =
  Tx 1 (toIn <$> ops) (toOut <$> rcpts) [] 0
  where
    toIn op = TxIn op B.empty maxBound
    toOut (o, v) = TxOut v $ marshal ctx o

-- | Sign a transaction by providing the 'SigInput' signing parameters and a
-- list of private keys. The signature is computed deterministically as defined
-- in RFC-6979.
--
-- Example: P2SH-P2WKH
--
-- > sigIn = SigInput (PayWitnessPKHash h) 100000 op sigHashAll Nothing
-- > signedTx = signTx btc unsignedTx [sigIn] [key]
--
-- Example: P2SH-P2WSH multisig
--
-- > sigIn = SigInput (PayWitnessScriptHash h) 100000 op sigHashAll (Just $ PayMulSig [p1,p2,p3] 2)
-- > signedTx = signTx btc unsignedTx [sigIn] [k1,k3]
signTx ::
  Network ->
  Ctx ->
  -- | transaction to sign
  Tx ->
  -- | signing parameters
  [SigInput] ->
  -- | private keys to sign with
  [SecKey] ->
  -- | signed transaction
  Either String Tx
signTx net ctx tx si = Sign.signTx net ctx tx $ notNested <$> si
  where
    notNested s = (s, False)

-- | This function differs from 'signTx' by assuming all segwit inputs are
-- P2SH-nested.  Use the same signing parameters for segwit inputs as in 'signTx'.
signNestedWitnessTx ::
  Network ->
  Ctx ->
  -- | transaction to sign
  Tx ->
  -- | signing parameters
  [SigInput] ->
  -- | private keys to sign with
  [SecKey] ->
  -- | signed transaction
  Either String Tx
signNestedWitnessTx net ctx tx si = Sign.signTx net ctx tx $ nested <$> si
  where
    -- NOTE: the nesting flag is ignored for non-segwit inputs
    nested s = (s, True)

-- | Sign a single input in a transaction deterministically (RFC-6979).
signInput ::
  Network -> Ctx -> Tx -> Int -> SigInput -> PrivateKey -> Either String Tx
signInput net ctx tx i si =
  Sign.signInput net ctx tx i (si, False)

-- | Like 'signInput' but treat segwit inputs as nested
signNestedInput ::
  Network -> Ctx -> Tx -> Int -> SigInput -> PrivateKey -> Either String Tx
signNestedInput net ctx tx i si =
  Sign.signInput net ctx tx i (si, True)

-- | Order the 'SigInput' with respect to the transaction inputs. This allows
-- the user to provide the 'SigInput' in any order. Users can also provide only
-- a partial set of 'SigInput' entries.
findSigInput :: [SigInput] -> [TxIn] -> [(SigInput, Int)]
findSigInput = Sign.findInputIndex (.outpoint)

{- Merge multisig transactions -}

-- | Merge partially-signed multisig transactions.  This function does not
-- support segwit and P2SH-segwit inputs.  Use PSBTs to merge transactions with
-- segwit inputs.
mergeTxs ::
  Network ->
  Ctx ->
  [Tx] ->
  [(ScriptOutput, Word64, OutPoint)] ->
  Either String Tx
mergeTxs net ctx txs os
  | null txs = Left "Transaction list is empty"
  | length (nub emptyTxs) /= 1 = Left "Transactions do not match"
  | length txs == 1 = return $ head txs
  | otherwise = foldM (mergeTxInput net ctx txs) (head emptyTxs) outs
  where
    zipOp = zip (matchTemplate os (head txs).inputs f) [0 ..]
    outs =
      map (first $ (\(o, v, _) -> (o, v)) . fromJust) $
        filter (isJust . fst) zipOp
    f (_, _, o) txin = o == txin.outpoint
    emptyTxs = map (\tx -> foldl clearInput tx outs) txs
    ins is i = updateIndex i is (\TxIn {..} -> TxIn {script = B.empty, ..})
    clearInput tx (_, i) =
      Tx tx.version (ins tx.inputs i) tx.outputs [] tx.locktime

-- | Merge input from partially-signed multisig transactions.  This function
-- does not support segwit and P2SH-segwit inputs.
mergeTxInput ::
  Network ->
  Ctx ->
  [Tx] ->
  Tx ->
  ((ScriptOutput, Word64), Int) ->
  Either String Tx
mergeTxInput net ctx txs tx ((so, val), i) = do
  -- Ignore transactions with empty inputs
  let ins = map ((.script) . (!! i) . (.inputs)) txs
  sigRes <- mapM extractSigs $ filter (not . B.null) ins
  let rdm = snd $ head sigRes
  unless (all ((== rdm) . snd) sigRes) $ Left "Redeem scripts do not match"
  si <- marshal (net, ctx) <$> go (nub $ concatMap fst sigRes) so rdm
  let ins' = updateIndex i tx.inputs (\TxIn {..} -> TxIn {script = si, ..})
  return $ Tx tx.version ins' tx.outputs [] tx.locktime
  where
    go allSigs out rdmM =
      case out of
        PayMulSig msPubs r ->
          let sigs =
                take r $
                  catMaybes $
                    matchTemplate allSigs msPubs $
                      f out
           in return $ RegularInput $ SpendMulSig sigs
        PayScriptHash _ ->
          case rdmM of
            Just rdm -> do
              si <- go allSigs rdm Nothing
              return $ ScriptHashInput si.get rdm
            _ -> Left "Invalid output script type"
        _ -> Left "Invalid output script type"
    extractSigs si =
      case unmarshal (net, ctx) si of
        Right (RegularInput (SpendMulSig sigs)) ->
          Right (sigs, Nothing)
        Right (ScriptHashInput (SpendMulSig sigs) rdm) ->
          Right (sigs, Just rdm)
        _ -> Left "Invalid script input type"
    f out (TxSignature x sh) p =
      verifyHashSig
        ctx
        (txSigHash net tx (encodeOutput ctx out) val i sh)
        x
        p.point
    f _ TxSignatureEmpty _ = False

{- Tx verification -}

-- | Verify if a transaction is valid and all of its inputs are standard.
verifyStdTx ::
  Network -> Ctx -> Tx -> [(ScriptOutput, Word64, OutPoint)] -> Bool
verifyStdTx net ctx tx xs =
  not (null tx.inputs) && all go (zip (matchTemplate xs tx.inputs f) [0 ..])
  where
    f (_, _, o) txin = o == txin.outpoint
    go (Just (so, val, _), i) = verifyStdInput net ctx tx i so val
    go _ = False

-- | Verify if a transaction input is valid and standard.
verifyStdInput :: Network -> Ctx -> Tx -> Int -> ScriptOutput -> Word64 -> Bool
verifyStdInput net ctx tx i so0 val
  | isSegwit so0 =
      fromRight False $ (inp == mempty &&) . verifySegwitInput so0 <$> wp so0
  | otherwise =
      or $
        rights
          [ verifyLegacyInput so0 <$> unmarshal (net, ctx) inp,
            nestedScriptOutput >>= \so -> verifyNestedInput so0 so <$> wp so
          ]
  where
    inp = (tx.inputs !! i).script
    theTxSigHash so = Sign.makeSigHash net ctx tx i so val

    ws :: WitnessStack
    ws
      | length tx.witness > i = tx.witness !! i
      | otherwise = []

    wp :: ScriptOutput -> Either String (Maybe ScriptOutput, SimpleInput)
    wp so = decodeWitnessInput net ctx =<< viewWitnessProgram net ctx so ws

    nestedScriptOutput :: Either String ScriptOutput
    nestedScriptOutput =
      runGetS deserialize inp >>= dec . ops
      where
        ops (Script ops') = ops'
        dec = \case
          [OP_PUSHDATA bs _] -> unmarshal ctx bs
          _ -> Left "nestedScriptOutput: not a nested output"

    verifyLegacyInput :: ScriptOutput -> ScriptInput -> Bool
    verifyLegacyInput so si = case (so, si) of
      (PayPK pub, RegularInput (SpendPK (TxSignature sig sh))) ->
        verifyHashSig ctx (theTxSigHash so sh Nothing) sig pub.point
      (PayPKHash h, RegularInput (SpendPKHash (TxSignature sig sh) pub)) ->
        pubKeyAddr ctx pub == p2pkhAddr h
          && verifyHashSig ctx (theTxSigHash so sh Nothing) sig pub.point
      (PayMulSig pubs r, RegularInput (SpendMulSig sigs)) ->
        countMulSig net ctx tx out val i ((.point) <$> pubs) sigs == r
      (PayScriptHash h, ScriptHashInput si' rdm) ->
        payToScriptAddress ctx rdm == p2shAddr h && verifyLegacyInput rdm (RegularInput si')
      _ -> False
      where
        out = encodeOutput ctx so

    verifySegwitInput ::
      ScriptOutput -> (Maybe ScriptOutput, SimpleInput) -> Bool
    verifySegwitInput so (rdm, si) = case (so, rdm, si) of
      ( PayWitnessPKHash h,
        Nothing,
        SpendPKHash (TxSignature sig sh) pub
        ) ->
          let keytest = pubKeyWitnessAddr ctx pub == p2wpkhAddr h
              sighash = theTxSigHash so sh Nothing
              pkpoint = pub.point
              verify = verifyHashSig ctx sighash sig pkpoint
           in keytest && verify
      ( PayWitnessScriptHash h,
        Just rdm'@(PayPK pub),
        SpendPK (TxSignature sig sh)
        ) ->
          let keytest = payToWitnessScriptAddress ctx rdm' == p2wshAddr h
              sighash = theTxSigHash so sh $ Just rdm'
              pkpoint = pub.point
              verify = verifyHashSig ctx sighash sig pkpoint
           in keytest && verify
      ( PayWitnessScriptHash h,
        Just rdm'@(PayPKHash kh),
        SpendPKHash (TxSignature sig sh) pub
        ) ->
          let keytest = payToWitnessScriptAddress ctx rdm' == p2wshAddr h
              addrtest = addressHash (marshal ctx pub) == kh
              pkpoint = pub.point
              sighash = theTxSigHash so sh $ Just rdm'
              verify = verifyHashSig ctx sighash sig pkpoint
           in keytest && addrtest && verify
      ( PayWitnessScriptHash h,
        Just rdm'@(PayMulSig pubs r),
        SpendMulSig sigs
        ) ->
          let keytest = payToWitnessScriptAddress ctx rdm' == p2wshAddr h
              pkpoints = (.point) <$> pubs
              hashfun sh = theTxSigHash so sh $ Just rdm'
              verify = countMulSig' ctx hashfun pkpoints sigs == r
           in keytest && verify
      _ -> False

    verifyNestedInput ::
      ScriptOutput -> ScriptOutput -> (Maybe RedeemScript, SimpleInput) -> Bool
    verifyNestedInput so so' x = case so of
      PayScriptHash h -> payToScriptAddress ctx so' == p2shAddr h && verifySegwitInput so' x
      _ -> False

-- | Count the number of valid signatures for a multi-signature transaction.
countMulSig ::
  Network ->
  Ctx ->
  Tx ->
  Script ->
  Word64 ->
  Int ->
  [PubKey] ->
  [TxSignature] ->
  Int
countMulSig net ctx tx out val i =
  countMulSig' ctx h
  where
    h = txSigHash net tx out val i

countMulSig' :: Ctx -> (SigHash -> Hash256) -> [PubKey] -> [TxSignature] -> Int
countMulSig' _ _ [] _ = 0
countMulSig' _ _ _ [] = 0
countMulSig' ctx h (_ : pubs) (TxSignatureEmpty : sigs) =
  countMulSig' ctx h pubs sigs
countMulSig' ctx h (pub : pubs) sigs@(TxSignature sig sh : sigs')
  | verifyHashSig ctx (h sh) sig pub = 1 + countMulSig' ctx h pubs sigs'
  | otherwise = countMulSig' ctx h pubs sigs
