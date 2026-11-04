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
    signTaprootInput,
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
    countMulSig,
    greedyAddSink,

    -- * Size and fee estimation
    InputKind (..),
    OutputKind (..),
    guessTxWeight,
    guessTxSize,
    guessTxFee,
    inputWeight,
    outputSize,
  )
where

import Control.Monad (foldM, unless)
import Control.Monad.Identity (runIdentity)
import Crypto.Secp256k1
import Data.ByteString qualified as B
import Data.Conduit (ConduitT, Void, await, runConduit, (.|))
import Data.Conduit.List (sourceList)
import Data.Either (fromRight, rights)
import Data.List (find, nub)
import Data.Maybe (catMaybes, fromJust, isJust, mapMaybe)
import Data.String.Conversions (cs)
import Data.Text (Text)
import Data.Word (Word64)
import Haskoin.Address
import Haskoin.Crypto.Hash (Hash256, addressHash)
import Haskoin.Crypto.Keys.Common
import Haskoin.Crypto.Signature
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction.Builder.Sign (SigInput, buildInput, makeSignature, sigKeys, signTaprootInput)
import Haskoin.Transaction.Builder.Sign qualified as Sign
import Haskoin.Transaction.Common
import Haskoin.Transaction.Segwit
import Haskoin.Transaction.Taproot
import Haskoin.Util

-- | Any type can be used as a Coin if it can provide a value in Satoshi and
-- say how it is spent. The value and the kind of input are used in coin
-- selection algorithms, to reach the amount and to estimate the fee.
class Coin c where
  coinValue :: c -> Word64
  coinInputKind :: c -> InputKind

-- | Coin selection algorithm. This function returns the selected coins
-- together with the amount of change to send back to yourself, taking the
-- fee into account. The fee is estimated from the kind of input each coin
-- is spent with and the kinds of the outputs, with 'guessTxFee'.
chooseCoins ::
  (Coin c) =>
  -- | value to send
  Word64 ->
  -- | fee per virtual byte
  Word64 ->
  -- | outputs of the transaction, including the change
  [OutputKind] ->
  -- | try to find better solutions
  Bool ->
  -- | list of ordered coins to choose from
  [c] ->
  -- | coin selection and change
  Either String ([c], Word64)
chooseCoins target fee outputs continue coins =
  runIdentity . runConduit $
    sourceList coins .| chooseCoinsSink target fee outputs continue

-- | Coin selection algorithm. This function returns the selected coins
-- together with the amount of change to send back to yourself, taking the
-- fee into account. This version uses a Sink for conduit-based coin
-- selection.
chooseCoinsSink ::
  (Monad m, Coin c) =>
  -- | value to send
  Word64 ->
  -- | fee per virtual byte
  Word64 ->
  -- | outputs of the transaction, including the change
  [OutputKind] ->
  -- | try to find better solution
  Bool ->
  -- | coin selection and change
  ConduitT c Void m (Either String ([c], Word64))
chooseCoinsSink target fee outputs continue
  | target > 0 =
      maybeToEither err
        <$> greedyAddSink target feeOf continue
  | otherwise = return $ Left "chooseCoins: Target must be > 0"
  where
    err = "chooseCoins: No solution found"
    feeOf coins = guessTxFee fee (map coinInputKind coins) outputs

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
  -- | fee of a transaction that spends the coins given
  ([c] -> Word64) ->
  -- | try to find better solutions
  Bool ->
  -- | coin selection and change
  ConduitT c Void m (Maybe ([c], Word64))
greedyAddSink target guessFee continue =
  go [] 0 [] 0
  where
    -- The goal is the value we must reach (including the fee) for a certain
    -- selection of coins.
    goal coins = target + guessFee coins
    go acc aTot ps pTot =
      await >>= \case
        -- A coin is available in the stream
        Just coin -> do
          let val = coinValue coin
          -- We have reached the goal using this coin
          if val + aTot >= goal (coin : acc)
            then -- If we want to continue searching for better solutions
              if continue
                then -- This solution is the first one or
                -- This solution is better than the previous one
                  if pTot == 0 || val + aTot < pTot
                    then -- Continue searching for better solutions in the stream
                      go [] 0 (coin : acc) (val + aTot)
                    else -- Otherwise, we stop here and return the previous
                    -- solution
                      return $ Just (ps, pTot - goal ps)
                else -- Otherwise, return this solution
                  return $
                    Just (coin : acc, val + aTot - goal (coin : acc))
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
                Just (ps, pTot - goal ps)

{- Size and fee estimation -}

-- | The kind of input a coin is spent with, which decides the bytes it
-- takes once signed. Keys are compressed, as every SegWit kind requires,
-- unless the kind says otherwise. A multisig kind is @m@ of @n@, with @n@
-- up to 'maxMultisigKeys'.
--
-- Some inputs the library signs have no kind: bare multisig,
-- pay-to-script-hash or pay-to-witness-script-hash of a single key,
-- multisig with an uncompressed key, and Taproot spent by a script path.
data InputKind
  = -- | pay-to-public-key. Its input is the signature alone, so the
    -- compression of the key does not matter.
    InputPK
  | -- | pay-to-public-key-hash
    InputPKHash
  | -- | pay-to-public-key-hash with an uncompressed, 65-byte key
    InputUncompressedPKHash
  | -- | pay-to-script-hash multisig, @m@ of @n@
    InputMulSig Int Int
  | -- | pay-to-witness-public-key-hash
    InputWitnessPKHash
  | -- | pay-to-witness-script-hash multisig, @m@ of @n@
    InputWitnessMulSig Int Int
  | -- | pay-to-witness-public-key-hash nested in pay-to-script-hash
    InputNestedWitnessPKHash
  | -- | pay-to-witness-script-hash multisig nested in pay-to-script-hash
    InputNestedWitnessMulSig Int Int
  | -- | Taproot, spent by its key path
    InputTaproot
  deriving (Eq, Show, Read)

-- | The kind of an output, which decides its size. An output of any other
-- script is 'OutputScript' with the size of the script, so every output
-- has a kind.
data OutputKind
  = -- | pay-to-public-key-hash
    OutputPKHash
  | -- | pay-to-script-hash
    OutputScriptHash
  | -- | pay-to-script-hash of a 256-bit hash, the P2SH32 of Bitcoin Cash
    OutputScript32Hash
  | -- | pay-to-witness-public-key-hash
    OutputWitnessPKHash
  | -- | pay-to-witness-script-hash
    OutputWitnessScriptHash
  | -- | Taproot
    OutputTaproot
  | -- | any other script, of that many bytes: bare multisig, a data
    -- carrier, or a witness program of another version
    OutputScript Int
  deriving (Eq, Show, Read)

-- | An upper bound on the weight, in weight units of BIP 141, of a signed
-- transaction with the inputs and outputs given. A signature is counted as
-- 72 bytes with its hash type, the most a low-S DER signature takes, and a
-- Taproot signature as 65 bytes.
guessTxWeight :: [InputKind] -> [OutputKind] -> Int
guessTxWeight inputs outputs = 4 * base + witness
  where
    base =
      8 -- version and lock time
        + varIntSize (length inputs)
        + sum (map (fst . inputWeight) inputs)
        + varIntSize (length outputs)
        + sum (map outputSize outputs)
    witnessBytes = map (snd . inputWeight) inputs
    -- A transaction with a witness has the marker and the flag, and a
    -- witness stack for every input. The stack of an input without a
    -- witness is one byte, its count of zero.
    witness
      | any (> 0) witnessBytes = 2 + sum (map (max 1) witnessBytes)
      | otherwise = 0

-- | An upper bound on the virtual size, in virtual bytes of BIP 141, of a
-- signed transaction with the inputs and outputs given: its weight divided
-- by four, rounded up. Nodes charge fees by virtual byte.
guessTxSize :: [InputKind] -> [OutputKind] -> Int
guessTxSize inputs outputs = (guessTxWeight inputs outputs + 3) `div` 4

-- | Estimate the fee to pay, from a fee rate per virtual byte and the
-- inputs and outputs of the transaction.
guessTxFee :: Word64 -> [InputKind] -> [OutputKind] -> Word64
guessTxFee feeRate inputs outputs =
  feeRate * fromIntegral (guessTxSize inputs outputs)

-- | The bytes an input of the kind takes: in the transaction without its
-- witness, and in the witness. A kind without a witness counts no witness
-- bytes. Its empty stack takes one byte when another input has a witness,
-- which 'guessTxWeight' counts.
inputWeight :: InputKind -> (Int, Int)
inputWeight = \case
  InputPK -> (prefix + withSize sigPush, 0)
  InputPKHash -> (prefix + withSize (sigPush + keyPush), 0)
  InputUncompressedPKHash -> (prefix + withSize (sigPush + uncompressedKeyPush), 0)
  InputMulSig m n -> (prefix + withSize (1 + m * sigPush + push (multisig m n)), 0)
  InputWitnessPKHash -> (prefix + 1, pkhWitness)
  InputWitnessMulSig m n -> (prefix + 1, multisigWitness m n)
  InputNestedWitnessPKHash -> (prefix + withSize (push 22), pkhWitness)
  InputNestedWitnessMulSig m n -> (prefix + withSize (push 34), multisigWitness m n)
  InputTaproot -> (prefix + 1, 1 + withSize 65)
  where
    -- the outpoint and the sequence
    prefix = 36 + 4
    -- a signature with its hash type, pushed: 1 + 72
    sigPush = push 72
    -- a compressed key, pushed
    keyPush = push 33
    -- an uncompressed key, pushed
    uncompressedKeyPush = push 65
    -- bytes after their count
    withSize n = varIntSize n + n
    -- OP_m, the compressed keys pushed, OP_n and OP_CHECKMULTISIG
    multisig m n = count m + 34 * n + count n + 1
    -- a count of a multisig script: OP_1 to OP_16, or a one-byte push of
    -- one byte from 17 to 'maxMultisigKeys'
    count c
      | c <= 16 = 1
      | otherwise = 2
    -- the number of items, the signature and the key
    pkhWitness = 1 + withSize 72 + withSize 33
    -- the number of items, the empty item, the signatures and the script
    multisigWitness m n = 1 + 1 + m * withSize 72 + withSize (multisig m n)

-- | The bytes an output of the kind takes: its amount, and its script with
-- its size
outputSize :: OutputKind -> Int
outputSize = \case
  OutputPKHash -> 8 + withSize 25
  OutputScriptHash -> 8 + withSize 23
  OutputScript32Hash -> 8 + withSize 35
  OutputWitnessPKHash -> 8 + withSize 22
  OutputWitnessScriptHash -> 8 + withSize 34
  OutputTaproot -> 8 + withSize 34
  OutputScript n -> 8 + withSize n
  where
    withSize n = varIntSize n + n

-- | The bytes of a push of that many bytes
push :: Int -> Int
push n
  | n <= 75 = 1 + n
  | n <= 0xff = 2 + n
  | n <= 0xffff = 3 + n
  | otherwise = 5 + n

-- | The bytes of a count as a 'VarInt'
varIntSize :: Int -> Int
varIntSize n
  | n < 0xfd = 1
  | n <= 0xffff = 3
  | n <= 0xffffffff = 5
  | otherwise = 9

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
-- A 'SigInput' whose script is 'PayWitnessPKHash' or 'PayWitnessScriptHash'
-- is a native SegWit input: the signature goes in the witness and the input
-- script stays empty. For a SegWit program nested in pay-to-script-hash, use
-- 'signNestedWitnessTx'.
--
-- A 'SigInput' whose script is a Taproot output is signed by its key path,
-- with a key whose x-only public key is the output key, or whose tweak
-- without a script tree is the output key, as a wallet of BIP 86 spends. The
-- BIP 341 digest commits to the output every input spends, so every input
-- of the transaction must have a 'SigInput' then.
--
-- Example: P2WPKH
--
-- > sigIn = SigInput (PayWitnessPKHash h) 100000 op sigHashAll Nothing
-- > signedTx = signTx btc ctx unsignedTx [sigIn] [key]
--
-- Example: P2SH-P2WSH multisig
--
-- > sigIn = SigInput (PayWitnessScriptHash h) 100000 op sigHashAll (Just $ PayMulSig [p1,p2,p3] 2)
-- > signedTx = signNestedWitnessTx btc ctx unsignedTx [sigIn] [k1,k3]
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

-- | Sign a single input in a transaction deterministically (RFC-6979). A
-- Taproot input is signed with 'signTaprootInput' instead, since its
-- digest needs the output every input spends.
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
-- segwit inputs. An input that no transaction has signed stays unsigned.
mergeTxs ::
  Network ->
  Ctx ->
  [Tx] ->
  [(ScriptOutput, Word64, OutPoint)] ->
  Either String Tx
mergeTxs net ctx txs os = case txs of
  [] -> Left "Transaction list is empty"
  [tx] -> return tx
  tx : _
    | length (nub emptyTxs) /= 1 -> Left "Transactions do not match"
    | otherwise -> foldM (mergeTxInput net ctx txs) (clearAll tx) (outs tx)
  where
    zipOp tx = zip (matchTemplate os tx.inputs f) [0 ..]
    outs tx =
      [ ((o, v), i)
      | (Just (o, v, _), i) <- zipOp tx
      ]
    f (_, _, o) txin = o == txin.outpoint
    emptyTxs = map clearAll txs
    clearAll tx = foldl clearInput tx (outs tx)
    ins is i = updateIndex i is (\TxIn {..} -> TxIn {script = B.empty, ..})
    clearInput tx (_, i) =
      Tx tx.version (ins tx.inputs i) tx.outputs [] tx.locktime

-- | Merge input from partially-signed multisig transactions.  This function
-- does not support segwit and P2SH-segwit inputs. When no transaction has a
-- script for the input, the input is left as it is.
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
  case sigRes of
    [] -> return tx
    (_, rdm) : _ -> do
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
      either (const False) (\h -> verifyHashSig ctx h x p.point) $
        encodeOutput ctx out >>= \s -> txSigHash net tx s val i sh
    f _ TxSignatureEmpty _ = False

{- Tx verification -}

-- | Verify that every input of the transaction spends one of the coins
-- given with a standard input that verifies ('verifyStdInput'), and that
-- the outputs do not spend more than the coins hold. Other rules of
-- @CheckTransaction@ in Bitcoin Core, such as the limits on sizes and
-- amounts and the absence of duplicate inputs, are not checked.
verifyStdTx ::
  Network -> Ctx -> Tx -> [(ScriptOutput, Word64, OutPoint)] -> Bool
verifyStdTx net ctx tx coins =
  not (null tx.inputs)
    && all (verifyStdInput net ctx tx coins) [0 .. length tx.inputs - 1]
    && spent <= available
  where
    spent = sum (map (toInteger . (.value)) tx.outputs)
    available = sum [toInteger v | (_, v, _) <- matched]
    matched = catMaybes (matchTemplate coins tx.inputs (\(_, _, o) txin -> o == txin.outpoint))

-- | Verify that an input spends one of the coins given with a standard
-- input that verifies: a signature of the right key and digest for
-- pay-to-public-key, pay-to-public-key-hash, multisig and pay-to-script-hash
-- inputs, their SegWit forms, native or nested in pay-to-script-hash, and
-- Taproot inputs spent by the key path or by a script path whose leaf is a
-- single key check. An input that is not a witness program must have no
-- witness, as @VerifyScript@ requires in Bitcoin Core. Other script path
-- spends need script execution and are not verified: they are refused.
verifyStdInput :: Network -> Ctx -> Tx -> [(ScriptOutput, Word64, OutPoint)] -> Int -> Bool
verifyStdInput net ctx tx coins i
  | i < 0 || i >= length tx.inputs = False
  | otherwise = case coinOf (tx.inputs !! i) of
      Nothing -> False
      Just (so0, val)
        | isSegwit so0 ->
            fromRight False $ (B.null inp &&) . verifySegwitInput so0 val <$> wp so0
        | isTaproot so0 ->
            B.null inp && verifyTaprootInput so0
        | otherwise ->
            or $
              rights
                [ (\si -> null ws && verifyLegacyInput so0 val si) <$> unmarshal (net, ctx) inp,
                  nestedScriptOutput >>= \so -> verifyNestedInput so0 so val <$> wp so
                ]
  where
    inp = (tx.inputs !! i).script
    coinOf txin = find (\(_, _, o) -> o == txin.outpoint) coins >>= \(so, val, _) -> Just (so, val)
    theTxSigHash so val = Sign.makeSigHash net ctx tx i so val

    -- A signature verifies only when its digest could be computed.
    checkSig :: Either String Hash256 -> Sig -> PubKey -> Bool
    checkSig h sig pub = either (const False) (\m -> verifyHashSig ctx m sig pub) h

    ws :: WitnessStack
    ws
      | length tx.witness > i = tx.witness !! i
      | otherwise = []

    wp :: ScriptOutput -> Either String (Maybe ScriptOutput, SimpleInput)
    wp so = decodeWitnessInput net ctx =<< viewWitnessProgram net ctx so ws

    nestedScriptOutput :: Either String ScriptOutput
    nestedScriptOutput = case unmarshal (net, ctx) inp of
      Right (NestedWitnessInput so) -> Right so
      _ -> Left "nestedScriptOutput: not a nested output"

    verifyLegacyInput :: ScriptOutput -> Word64 -> ScriptInput -> Bool
    verifyLegacyInput so val si = case (so, si) of
      (PayPK pub, RegularInput (SpendPK (TxSignature sig sh))) ->
        checkSig (theTxSigHash so val sh Nothing) sig pub.point
      (PayPKHash h, RegularInput (SpendPKHash (TxSignature sig sh) pub)) ->
        pubKeyAddr ctx pub == p2pkhAddr h
          && checkSig (theTxSigHash so val sh Nothing) sig pub.point
      (PayMulSig pubs r, RegularInput (SpendMulSig sigs)) ->
        either (const False) (\out -> countMulSig net ctx tx out val i ((.point) <$> pubs) sigs == r) $
          encodeOutput ctx so
      (PayScriptHash h, ScriptHashInput si' rdm) ->
        payToScriptAddress ctx rdm == p2shAddr h && verifyLegacyInput rdm val (RegularInput si')
      _ -> False

    verifySegwitInput ::
      ScriptOutput -> Word64 -> (Maybe ScriptOutput, SimpleInput) -> Bool
    verifySegwitInput so val (rdm, si) = case (so, rdm, si) of
      ( PayWitnessPKHash h,
        Nothing,
        SpendPKHash (TxSignature sig sh) pub
        ) ->
          -- Compare the key hash only. An uncompressed key is non-standard
          -- here but still valid by consensus, so verification accepts it.
          let keytest = pubKeyAddr ctx pub == p2pkhAddr h
              sighash = theTxSigHash so val sh Nothing
              pkpoint = pub.point
              verify = checkSig sighash sig pkpoint
           in keytest && verify
      ( PayWitnessScriptHash h,
        Just rdm'@(PayPK pub),
        SpendPK (TxSignature sig sh)
        ) ->
          let keytest = payToWitnessScriptAddress ctx rdm' == p2wshAddr h
              sighash = theTxSigHash so val sh $ Just rdm'
              pkpoint = pub.point
              verify = checkSig sighash sig pkpoint
           in keytest && verify
      ( PayWitnessScriptHash h,
        Just rdm'@(PayPKHash kh),
        SpendPKHash (TxSignature sig sh) pub
        ) ->
          let keytest = payToWitnessScriptAddress ctx rdm' == p2wshAddr h
              addrtest = addressHash (marshal ctx pub) == kh
              pkpoint = pub.point
              sighash = theTxSigHash so val sh $ Just rdm'
              verify = checkSig sighash sig pkpoint
           in keytest && addrtest && verify
      ( PayWitnessScriptHash h,
        Just rdm'@(PayMulSig pubs r),
        SpendMulSig sigs
        ) ->
          let keytest = payToWitnessScriptAddress ctx rdm' == p2wshAddr h
              pkpoints = (.point) <$> pubs
              hashfun sh = theTxSigHash so val sh $ Just rdm'
              verify = countMulSig' ctx hashfun pkpoints sigs == r
           in keytest && verify
      _ -> False

    verifyNestedInput ::
      ScriptOutput -> ScriptOutput -> Word64 -> (Maybe RedeemScript, SimpleInput) -> Bool
    verifyNestedInput so so' val x = case so of
      PayScriptHash h -> payToScriptAddress ctx so' == p2shAddr h && verifySegwitInput so' val x
      _ -> False

    -- The outputs every input spends, in order, which the Taproot digest
    -- commits to
    spentOutputs :: Maybe [TxOut]
    spentOutputs = mapM (fmap (\(so, val) -> TxOut val (marshal ctx so)) . coinOf) tx.inputs

    verifyTaprootInput :: ScriptOutput -> Bool
    verifyTaprootInput so = fromRight False $ do
      outKey <- case so of
        PayWitness 1 program -> maybe (Left "not an output key") Right (importXOnlyPubKey ctx program)
        _ -> Left "not a Taproot output"
      spent <- maybe (Left "a spent output is missing") Right spentOutputs
      let schnorr sigBytes annex leaf = do
            TaprootSignature sig sh <- decodeTaprootSig sigBytes
            h <- taprootSigHash tx spent i sh annex leaf
            return (sig, h)
      case viewTaprootWitness ctx ws of
        Just (KeyPathSpend sigBytes annex) -> do
          (sig, h) <- schnorr sigBytes annex Nothing
          return (verifySchnorr ctx outKey sig (hashToMsg h))
        Just (ScriptPathSpend spd) -> case (spd.script.ops, spd.stack) of
          ([OP_PUSHDATA keyBytes OPCODE, OP_CHECKSIG], [sigBytes])
            | spd.leafVersion == tapscriptLeafVersion -> do
                leafKey <- maybe (Left "not an x-only key") Right (importXOnlyPubKey ctx keyBytes)
                (sig, h) <- schnorr sigBytes spd.annex (Just (leafHash spd.leafVersion spd.script, 0xffffffff))
                return (verifyScriptPathData ctx outKey spd && verifySchnorr ctx leafKey sig (hashToMsg h))
          _ -> Left "script path spends other than a single key check are not verified"
        Nothing -> Left "not a Taproot witness"

-- | Whether an output script is a Taproot output: a witness program of
-- version 1 that is 32 bytes long
isTaproot :: ScriptOutput -> Bool
isTaproot = \case
  PayWitness 1 program -> B.length program == 32
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

countMulSig' :: Ctx -> (SigHash -> Either String Hash256) -> [PubKey] -> [TxSignature] -> Int
countMulSig' _ _ [] _ = 0
countMulSig' _ _ _ [] = 0
countMulSig' ctx h (_ : pubs) (TxSignatureEmpty : sigs) =
  countMulSig' ctx h pubs sigs
countMulSig' ctx h (pub : pubs) sigs@(TxSignature sig sh : sigs')
  | either (const False) (\m -> verifyHashSig ctx m sig pub) (h sh) =
      1 + countMulSig' ctx h pubs sigs'
  | otherwise = countMulSig' ctx h pubs sigs
