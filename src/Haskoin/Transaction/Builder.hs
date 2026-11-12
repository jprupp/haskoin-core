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
    InputVerdict (..),
    judgeInputs,

    -- * Coin Selection
    Coin (..),
    chooseCoins,
    chooseCoinsSink,
    countMulSig,
    greedyAddSink,
    maxStandardTxWeight,

    -- * Size and fee estimation
    InputKind (..),
    OutputKind (..),
    guessTxWeight,
    guessTxSize,
    guessTxFee,
    inputWeight,
    outputSize,
    dustThreshold,
  )
where

import Control.Monad (foldM, unless, when)
import Control.Monad.Identity (runIdentity)
import Crypto.Secp256k1
import Data.Bits (popCount, testBit)
import Data.ByteString qualified as B
import Data.Bytes.Get (runGetS)
import Data.Bytes.Serial (deserialize)
import Data.Conduit (ConduitT, Void, await, runConduit, (.|))
import Data.Conduit.List (sourceList)
import Data.Either (fromRight, rights)
import Data.List (nub)
import Data.Map.Strict qualified as Map
import Data.Maybe (catMaybes, isNothing)
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

-- | The weight above which nodes do not relay a transaction: the
-- @MAX_STANDARD_TX_WEIGHT@ of Bitcoin Core (@policy/policy.h@). A Bitcoin
-- Cash transaction has no witness, so its weight is four times its size,
-- and the limit is the 100,000 bytes of @MAX_STANDARD_TX_SIZE@ in Bitcoin
-- Cash Node.
maxStandardTxWeight :: Int
maxStandardTxWeight = 400000

-- | Coin selection algorithm. This function returns the selected coins
-- together with the amount of change to send back to yourself, taking the
-- fee into account. The fee is estimated from the kind of input each coin
-- is spent with and the kinds of the outputs, as 'guessTxFee' estimates it.
--
-- The coins are taken in the order of the list until they cover the target
-- and the fee. The selection fails when the coins do not suffice, when a
-- kind of input or output is not valid, and when the transaction would
-- weigh more than 'maxStandardTxWeight', which nodes do not relay.
--
-- The change can be any amount, including one below 'dustThreshold'. Nodes
-- do not relay a transaction with an output below that threshold, so leave
-- such a change to the fee instead of making an output for it.
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
-- selection. See 'chooseCoins'.
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
  | target == 0 = return $ Left "chooseCoins: Target must be > 0"
  | Left e <- mapM_ checkOutputKind outputs = return $ Left ("chooseCoins: " <> e)
  | otherwise = go emptySelection Nothing
  where
    outputBytes = varIntSize (length outputs) + sum (map outputSize outputs)
    -- What the coins of a selection must reach: the target and the fee of
    -- the transaction they make. Amounts are added as unbounded integers,
    -- so that no sum wraps around.
    goal sel = toInteger target + toInteger fee * toInteger ((selectionWeight outputBytes sel + 3) `div` 4)
    go sel previous =
      await >>= \case
        Nothing -> return $ maybe (Left "chooseCoins: No solution found") solution previous
        Just coin -> case addCoin coin sel of
          Left e -> return $ Left ("chooseCoins: " <> e)
          Right sel'
            -- A heavier transaction is not relayed. Coins only add weight,
            -- so nothing further in the stream can complete this selection.
            | selectionWeight outputBytes sel' > maxStandardTxWeight ->
                return $ maybe (Left tooHeavy) solution previous
            | sel'.total < goal sel' -> go sel' previous
            | not continue -> return (solution sel')
            -- This solution is the first one, or it takes less than the
            -- previous one: look for a better one in the rest of the stream
            | maybe True (\p -> sel'.total < p.total) previous -> go emptySelection (Just sel')
            | otherwise -> return $ maybe (Left "chooseCoins: No solution found") solution previous
    solution sel
      | change > toInteger (maxBound :: Word64) = Left "chooseCoins: The change does not fit in 64 bits"
      | otherwise = Right (sel.coins, fromInteger change)
      where
        change = sel.total - goal sel
    tooHeavy =
      "chooseCoins: The selection exceeds the standard transaction weight of " <> show maxStandardTxWeight

-- | The coins selected so far, with the sums that give the weight of the
-- transaction they make. The sums are kept as coins are added, so that
-- adding a coin does not walk over the coins before it.
data Selection c = Selection
  { -- | the coins, the last one added first
    coins :: [c],
    count :: !Int,
    -- | the sum of the values
    total :: !Integer,
    -- | the bytes of the inputs outside the witness
    baseBytes :: !Int,
    -- | the bytes of the witness stacks, an input without a witness
    -- counting the one byte of its empty stack
    stackBytes :: !Int,
    -- | whether an input has a witness
    hasStack :: !Bool
  }

emptySelection :: Selection c
emptySelection = Selection [] 0 0 0 0 False

addCoin :: (Coin c) => c -> Selection c -> Either String (Selection c)
addCoin coin sel = do
  let kind = coinInputKind coin
  checkInputKind kind
  let (base, stack) = inputWeight kind
  return
    Selection
      { coins = coin : sel.coins,
        count = sel.count + 1,
        total = sel.total + toInteger (coinValue coin),
        baseBytes = sel.baseBytes + base,
        stackBytes = sel.stackBytes + max 1 stack,
        hasStack = sel.hasStack || stack > 0
      }

-- | The weight of the transaction that spends the coins of a selection to
-- outputs of the size given, counted as 'guessTxWeight' counts it
selectionWeight :: Int -> Selection c -> Int
selectionWeight outputBytes sel = 4 * base + witness
  where
    base = 8 + varIntSize sel.count + sel.baseBytes + outputBytes
    witness
      | sel.hasStack = 2 + sel.stackBytes
      | otherwise = 0

-- | Select coins greedily by starting from an empty solution. If the 'continue'
-- flag is set, the algorithm will try to find a better solution in the stream
-- after a solution is found. If the next solution found is not strictly better
-- than the previously found solution, the algorithm stops and returns the
-- previous solution. If the continue flag is not set, the algorithm will return
-- the first solution it finds in the stream.
--
-- The fee function is called on the coins taken so far each time a coin is
-- added. Amounts are added as unbounded integers, so that no sum wraps
-- around. The result is 'Nothing' when no selection covers the target and
-- its fee, or when the change does not fit in 64 bits. 'chooseCoinsSink'
-- does not use this function: it also bounds the weight of the selection.
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
  go [] 0 Nothing
  where
    -- The goal is the value we must reach (including the fee) for a certain
    -- selection of coins.
    goal coins = toInteger target + toInteger (guessFee coins)
    go acc aTot previous =
      await >>= \case
        -- A coin is available in the stream
        Just coin -> do
          let tot = aTot + toInteger (coinValue coin)
          if tot < goal (coin : acc)
            then -- We have not yet reached the goal. Add the coin to the
            -- accumulator
              go (coin : acc) tot previous
            else
              if not continue
                then return $ solution (coin : acc, tot)
                else -- This solution is the first one, or it is better than
                -- the previous one: continue searching for better solutions
                -- in the stream. Otherwise, stop here and return the
                -- previous solution.
                  if maybe True ((tot <) . snd) previous
                    then go [] 0 (Just (coin : acc, tot))
                    else return $ solution =<< previous
        -- We reached the end of the stream
        Nothing -> return $ solution =<< previous
    solution (coins, tot)
      | change > toInteger (maxBound :: Word64) = Nothing
      | otherwise = Just (coins, fromInteger change)
      where
        change = tot - goal coins

{- Size and fee estimation -}

-- | The kind of input a coin is spent with, which decides the bytes it
-- takes once signed. Keys are compressed, as every SegWit kind requires,
-- unless the kind says otherwise. A multisig kind is @m@ of @n@, with @m@
-- from 1 to @n@. A SegWit multisig has up to 'maxMultisigKeys' keys. A
-- pay-to-script-hash multisig has up to 15: its redeem script is at most
-- 'maxRedeemScriptSize' bytes, and 15 compressed keys make 513.
--
-- 'guessTxFee' and 'chooseCoins' refuse a kind outside these ranges.
-- 'inputWeight', 'guessTxWeight' and 'guessTxSize' do not check: on such a
-- kind their result means nothing.
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

-- | Whether an input kind is one that can exist, see 'InputKind'
checkInputKind :: InputKind -> Either String ()
checkInputKind kind = case kind of
  InputMulSig m n -> multisig m n 15
  InputWitnessMulSig m n -> multisig m n maxMultisigKeys
  InputNestedWitnessMulSig m n -> multisig m n maxMultisigKeys
  _ -> Right ()
  where
    multisig m n most =
      unless (1 <= m && m <= n && n <= most) $
        Left $
          "The input kind " <> show kind <> " is not valid: m of n needs 1 <= m <= n <= " <> show most

-- | Whether an output kind is one that can exist: a script is from 0 to
-- 10,000 bytes long
checkOutputKind :: OutputKind -> Either String ()
checkOutputKind kind = case kind of
  OutputScript n
    | n < 0 || n > maxWitnessScriptSize ->
        Left $ "The output kind " <> show kind <> " is not valid: a script has from 0 to 10000 bytes"
  _ -> Right ()

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
--
-- Bitcoin Core charges for signature operations as well: its size for fee
-- purposes is the larger of this size and 5 virtual bytes per signature
-- operation (@GetVirtualTransactionSize@ with @DEFAULT_BYTES_PER_SIGOP@ of
-- 20, in @policy/policy.cpp@). That only exceeds the size for transactions
-- dense in signature operations, such as one that pays to many bare
-- multisig outputs. This estimate, like 'txVirtualSize', leaves it out.
guessTxSize :: [InputKind] -> [OutputKind] -> Int
guessTxSize inputs outputs = (guessTxWeight inputs outputs + 3) `div` 4

-- | Estimate the fee to pay, from a fee rate per virtual byte and the
-- inputs and outputs of the transaction. Fails for a kind of input or
-- output that cannot exist, see 'InputKind', and for a fee that does not
-- fit in 64 bits.
guessTxFee :: Word64 -> [InputKind] -> [OutputKind] -> Either String Word64
guessTxFee feeRate inputs outputs = do
  mapM_ (prefixed . checkInputKind) inputs
  mapM_ (prefixed . checkOutputKind) outputs
  -- Multiplied as unbounded integers, so that the fee cannot wrap around
  let fee = toInteger feeRate * toInteger (guessTxSize inputs outputs)
  when (fee > toInteger (maxBound :: Word64)) $
    Left "guessTxFee: The fee does not fit in 64 bits"
  return (fromInteger fee)
  where
    prefixed = either (Left . ("guessTxFee: " <>)) Right

-- | The amount below which nodes do not relay an output of the kind, at
-- the default dust relay fee of Bitcoin Core, 3,000 satoshi per 1,000
-- virtual bytes: three satoshi for each byte of the output and of the
-- smallest input that spends it. This is @GetDustThreshold@ of Bitcoin
-- Core (@policy/policy.cpp@), which counts 148 bytes for the input of an
-- output without a witness and 67 for the input of a witness program. It
-- gives 546 satoshi for pay-to-public-key-hash, 294 for
-- pay-to-witness-public-key-hash, and 330 for pay-to-witness-script-hash
-- and Taproot. Bitcoin Cash Node gives the same amounts for the outputs
-- it has.
--
-- An 'OutputScript' is counted as an output without a witness. For a
-- witness program of another version this is more than Bitcoin Core asks,
-- which is the safe side. A data carrier output is never dust, whatever
-- this function says of its size.
dustThreshold :: OutputKind -> Word64
dustThreshold kind = 3 * fromIntegral (outputSize kind + spendSize)
  where
    spendSize = case kind of
      OutputWitnessPKHash -> witnessSpend
      OutputWitnessScriptHash -> witnessSpend
      OutputTaproot -> witnessSpend
      _ -> 32 + 4 + 1 + 107 + 4
    -- The script of the input counts a quarter in a witness
    witnessSpend = 32 + 4 + 1 + (107 `div` 4) + 4

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
-- and a list of recipient addresses and amounts as outputs. The
-- transaction has version 1, no lock time, and final sequence numbers, so
-- it does not signal replacement (BIP 125).
--
-- Fails for an address that is not one of the network, and for an amount
-- above the 'maxSatoshi' of the network, as @createrawtransaction@ of
-- Bitcoin Core refuses an amount out of range. Like that call, it does not
-- check what needs the whole transaction: amounts that add up to more
-- than 'maxSatoshi', and an outpoint listed twice. Nodes refuse a
-- transaction with either, and so does 'verifyStdTx' for the second.
--
-- Nothing is added for change: what the outputs do not spend is the fee.
buildAddrTx :: Network -> Ctx -> [OutPoint] -> [(Text, Word64)] -> Either String Tx
buildAddrTx net ctx ops rcps = do
  when (any ((> net.maxSatoshi) . snd) rcps) $
    Left $ "buildAddrTx: An amount is above the maximum of " <> show net.maxSatoshi <> " satoshi"
  buildTx ctx ops <$> mapM f rcps
  where
    f (aTxt, v) =
      maybeToEither ("buildAddrTx: Invalid address " <> cs aTxt) $ do
        a <- textToAddr net aTxt
        o <- addressToOutput a
        return (o, v)

-- | Build a transaction by providing a list of outpoints as inputs
-- and a list of 'ScriptOutput' and amounts as outputs. It has no network
-- to check against, so it builds what it is given, whatever the amounts.
-- 'buildAddrTx' refuses an amount above the maximum of its network.
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
-- An input is signed with the keys of the list that its coin asks for. An
-- input whose coin asks for none of them is left as it is, so that several
-- parties can sign in turn. The result is then 'Right' with that input
-- unsigned: use 'verifyStdTx' to tell whether the transaction is complete.
--
-- The signer refuses, with the reason, what would make a transaction that
-- nodes do not accept: a hash type that is not defined, a redeem or a
-- witness script that does not hash to its coin or is too long, a SegWit
-- or Taproot coin on a network without SegWit, and a SegWit version 0 coin
-- whose key is uncompressed. See 'makeSignature' and 'sigKeys'. It signs
-- any defined hash type that a 'SigInput' asks for, 'sigHashNone' and
-- 'sigHashSingle' included, so check a 'SigInput' that comes from someone
-- else.
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
-- The witness is not merged: the transactions must have the same one, and
-- the result keeps it, so that a SegWit input signed before the multisig
-- signers took their copies stays signed.
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
      Tx tx.version (ins tx.inputs i) tx.outputs tx.witness tx.locktime

-- | Merge input from partially-signed multisig transactions.  This function
-- does not support segwit and P2SH-segwit inputs. When no transaction has a
-- script for the input, the input is left as it is. Fails when one of the
-- transactions has no input at the index. The witness of the transaction
-- is kept.
mergeTxInput ::
  Network ->
  Ctx ->
  [Tx] ->
  Tx ->
  ((ScriptOutput, Word64), Int) ->
  Either String Tx
mergeTxInput net ctx txs tx ((so, val), i) = do
  when (i < 0 || any ((<= i) . length . (.inputs)) (tx : txs)) $
    Left "mergeTxInput: input index out of range"
  -- Ignore transactions with empty inputs
  let ins = map ((.script) . (!! i) . (.inputs)) txs
  sigRes <- mapM extractSigs $ filter (not . B.null) ins
  case sigRes of
    [] -> return tx
    (_, rdm) : _ -> do
      unless (all ((== rdm) . snd) sigRes) $ Left "Redeem scripts do not match"
      si <- marshal (net, ctx) <$> go (nub $ concatMap fst sigRes) so rdm
      let ins' = updateIndex i tx.inputs (\TxIn {..} -> TxIn {script = si, ..})
      return $ Tx tx.version ins' tx.outputs tx.witness tx.locktime
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
-- given with a standard input that verifies ('verifyStdInput'), that no
-- two inputs spend the same coin, and that the outputs do not spend more
-- than the coins hold. Other rules of @CheckTransaction@ in Bitcoin Core,
-- such as the limits on sizes and amounts, are not checked, and neither
-- are lock times.
--
-- This is not a script interpreter. It answers 'True' only for the
-- standard kinds of input listed at 'verifyStdInput', and 'False' for any
-- other script, valid or not. For those kinds it follows consensus: it
-- does not answer 'True' for an input that no block can contain.
verifyStdTx ::
  Network -> Ctx -> Tx -> [(ScriptOutput, Word64, OutPoint)] -> Bool
verifyStdTx net ctx tx coins =
  not (null tx.inputs)
    && Map.size (Map.fromList [(i.outpoint, ()) | i <- tx.inputs]) == length tx.inputs
    && all (verifyInput net ctx tx spent) [0 .. length tx.inputs - 1]
    && maybe False (\outs -> toSpend <= sum (map (toInteger . snd) outs)) (sequence spent.coins)
  where
    -- The coins are looked up once for the whole transaction
    spent = spentCoins ctx tx coins
    toSpend = sum (map (toInteger . (.value)) tx.outputs)

-- | The coin of each input of a transaction, and the outputs that the
-- Taproot digest commits to. 'verifyStdTx' computes this once, so that the
-- time it takes does not grow with the square of the number of inputs.
data SpentCoins = SpentCoins
  { -- | the coin of each input, in order, when it is among those given
    coins :: [Maybe (ScriptOutput, Word64)],
    -- | the output every input spends, when every coin is given
    outputs :: Maybe [TxOut]
  }

spentCoins :: Ctx -> Tx -> [(ScriptOutput, Word64, OutPoint)] -> SpentCoins
spentCoins ctx tx given =
  SpentCoins
    { coins = found,
      outputs = map (\(so, val) -> TxOut val (marshal ctx so)) <$> sequence found
    }
  where
    -- The first coin given for an outpoint is its coin
    byOutPoint = Map.fromListWith (\_ first -> first) [(o, (so, val)) | (so, val, o) <- given]
    found = map (\i -> Map.lookup i.outpoint byOutPoint) tx.inputs

-- | Verify that an input spends one of the coins given with a standard
-- input that verifies: a signature of the right key and digest for
-- pay-to-public-key, pay-to-public-key-hash, multisig and pay-to-script-hash
-- inputs, their SegWit forms, native or nested in pay-to-script-hash, and
-- Taproot inputs spent by the key path or by a script path whose leaf is a
-- single key check or a multisig. The multisig of Taproot is @multi_a@ of
-- the output descriptors: a key and @OP_CHECKSIG@, then a key and
-- @OP_CHECKSIGADD@ for each other key, the number of signatures asked
-- for, and @OP_NUMEQUAL@; its witness has an item for every key, that of
-- the last key first, empty for a key that did not sign. An input that
-- is not a witness program must have no witness, as @VerifyScript@
-- requires in Bitcoin Core. Other script path spends need script
-- execution and are not verified: they are refused.
--
-- The answer is never 'True' for an input that no block can contain:
--
-- * A multisig input has exactly as many signatures as its script
--   requires, each of a key of the script, in the order of the keys, and
--   no other item. @OP_CHECKMULTISIG@ takes that many signatures from the
--   top of the stack, and the item below them, its dummy element, must be
--   empty (BIP 147). So an item more, after the signatures or among them,
--   makes the operation fail.
-- * The input script of a SegWit program nested in pay-to-script-hash is
--   the push of the program and nothing else (BIP 141).
-- * A redeem script is at most 'maxRedeemScriptSize' bytes, and a witness
--   script at most 'maxWitnessScriptSize'.
-- * A network without SegWit has no witness inputs.
--
-- The answer can be 'False' for an input that a block may hold but that
-- nodes do not relay:
--
-- * A signature is read with 'decodeTxSig', which applies the relay rules:
--   low S and a defined hash type.
-- * A legacy multisig input with an empty item before its signatures
--   leaves that item on the stack. Consensus allows it outside a witness,
--   and the @CLEANSTACK@ rule of the relay policy does not.
--
-- An uncompressed key in a SegWit input is accepted, since a block may
-- hold it, although nodes do not relay it.
verifyStdInput :: Network -> Ctx -> Tx -> [(ScriptOutput, Word64, OutPoint)] -> Int -> Bool
verifyStdInput net ctx tx coins = verifyInput net ctx tx (spentCoins ctx tx coins)

-- | 'verifyStdInput' on coins that are looked up already
verifyInput :: Network -> Ctx -> Tx -> SpentCoins -> Int -> Bool
verifyInput net ctx tx spent i
  | i < 0 || i >= length tx.inputs = False
  | otherwise = case spent.coins !! i of
      Nothing -> False
      Just (so0, val)
        | isSegwit so0 ->
            net.segWit && fromRight False ((B.null inp &&) . verifySegwitInput so0 val <$> wp so0)
        | isTaproot so0 ->
            net.segWit && B.null inp && verifyTaprootInput so0
        | otherwise ->
            or $
              rights
                [ (\si -> null ws && verifyLegacyInput so0 val si) <$> unmarshal (net, ctx) inp,
                  nestedScriptOutput >>= \so -> verifyNestedInput so0 so val <$> wp so
                ]
  where
    inp = (tx.inputs !! i).script
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

    -- The witness program of an input script that is its push and nothing
    -- else, on a network that has SegWit
    nestedScriptOutput :: Either String ScriptOutput
    nestedScriptOutput = case unmarshal (net, ctx) inp of
      Right (NestedWitnessInput so)
        | net.segWit && inp == marshal (net, ctx) (NestedWitnessInput so) -> Right so
      _ -> Left "nestedScriptOutput: not a nested output"

    -- OP_CHECKMULTISIG takes the signatures the script requires from the
    -- top of the stack, and each must verify against a later key than the
    -- one before. An empty item among them is no signature. An item more
    -- pushes a signature into the place of the dummy element, which must
    -- be empty. Only an empty item before the signatures does not fail the
    -- operation: it stays on the stack, which the relay rules refuse.
    multisigVerifies :: (SigHash -> Either String Hash256) -> [PubKey] -> Int -> [TxSignature] -> Bool
    multisigVerifies hashfun pubs r sigs =
      -- With exactly r items, r of them verify only when none is empty
      length sigs == r && countMulSig' ctx hashfun pubs sigs == r

    verifyLegacyInput :: ScriptOutput -> Word64 -> ScriptInput -> Bool
    verifyLegacyInput so val si = case (so, si) of
      (PayPK pub, RegularInput (SpendPK (TxSignature sig sh))) ->
        checkSig (theTxSigHash so val sh Nothing) sig pub.point
      (PayPKHash h, RegularInput (SpendPKHash (TxSignature sig sh) pub)) ->
        pubKeyAddr ctx pub == p2pkhAddr h
          && checkSig (theTxSigHash so val sh Nothing) sig pub.point
      (PayMulSig pubs r, RegularInput (SpendMulSig sigs)) ->
        either (const False) (\out -> multisigVerifies (txSigHash net tx out val i) ((.point) <$> pubs) r sigs) $
          encodeOutput ctx so
      (PayScriptHash h, ScriptHashInput si' rdm) ->
        payToScriptAddress ctx rdm == Right (p2shAddr h) && verifyLegacyInput rdm val (RegularInput si')
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
          let keytest = payToWitnessScriptAddress ctx rdm' == Right (p2wshAddr h)
              sighash = theTxSigHash so val sh $ Just rdm'
              pkpoint = pub.point
              verify = checkSig sighash sig pkpoint
           in keytest && verify
      ( PayWitnessScriptHash h,
        Just rdm'@(PayPKHash kh),
        SpendPKHash (TxSignature sig sh) pub
        ) ->
          let keytest = payToWitnessScriptAddress ctx rdm' == Right (p2wshAddr h)
              addrtest = addressHash (marshal ctx pub) == kh
              pkpoint = pub.point
              sighash = theTxSigHash so val sh $ Just rdm'
              verify = checkSig sighash sig pkpoint
           in keytest && addrtest && verify
      ( PayWitnessScriptHash h,
        Just rdm'@(PayMulSig pubs r),
        SpendMulSig sigs
        ) ->
          let keytest = payToWitnessScriptAddress ctx rdm' == Right (p2wshAddr h)
              pkpoints = (.point) <$> pubs
              hashfun sh = theTxSigHash so val sh $ Just rdm'
              verify = multisigVerifies hashfun pkpoints r sigs
           in keytest && verify
      _ -> False

    verifyNestedInput ::
      ScriptOutput -> ScriptOutput -> Word64 -> (Maybe RedeemScript, SimpleInput) -> Bool
    verifyNestedInput so so' val x = case so of
      PayScriptHash h -> payToScriptAddress ctx so' == Right (p2shAddr h) && verifySegwitInput so' val x
      _ -> False

    verifyTaprootInput :: ScriptOutput -> Bool
    verifyTaprootInput so = fromRight False $ do
      outKey <- case so of
        PayWitness 1 program -> maybe (Left "not an output key") Right (importXOnlyPubKey ctx program)
        _ -> Left "not a Taproot output"
      -- The outputs every input spends, in order, which the Taproot digest
      -- commits to
      spentOutputs <- maybe (Left "a spent output is missing") Right spent.outputs
      let schnorr sigBytes annex leaf = do
            TaprootSignature sig sh <- decodeTaprootSig sigBytes
            h <- taprootSigHash tx spentOutputs i sh annex leaf
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
          -- The multisig of Taproot, @multi_a@ of the output descriptors:
          -- a key and OP_CHECKSIG, then a key and OP_CHECKSIGADD for each
          -- other key, the number of signatures asked for, and
          -- OP_NUMEQUAL. The witness has an item for every key, that of
          -- the last key first: a signature, or nothing for a key that
          -- did not sign. A signature that does not verify fails the
          -- script, it does not count for nothing (BIP 342).
          (ops, items)
            | spd.leafVersion == tapscriptLeafVersion,
              Just (keys, asked) <- multiA ops,
              length items == length keys -> do
                let leaf = Just (leafHash spd.leafVersion spd.script, 0xffffffff)
                    signs keyBytes sigBytes
                      | B.null sigBytes = Right False
                      | otherwise = do
                          key <- maybe (Left "not an x-only key") Right (importXOnlyPubKey ctx keyBytes)
                          (sig, h) <- schnorr sigBytes spd.annex leaf
                          if verifySchnorr ctx key sig (hashToMsg h)
                            then Right True
                            else Left "a signature that does not verify"
                signed <- sequence (zipWith signs keys (reverse items))
                return (verifyScriptPathData ctx outKey spd && length (filter id signed) == asked)
          _ -> Left "script path spends other than key checks are not verified"
        Nothing -> Left "not a Taproot witness"

-- | What can be said of the signature of an input without running its
-- script.
data InputVerdict
  = -- | the input is one of the standard kinds and its signatures verify
    -- ('verifyStdInput')
    InputVerified
  | -- | the input spends a coin locked to one key, with the signature and
    -- key that such a coin takes, and they do not open it: no node takes
    -- the transaction
    InputForged
  | -- | neither: a script that is not run here, a coin that was not
    -- given, a hash type other than all, an encoding that is not read
    InputUndecided
  deriving (Eq, Show)

-- | Judge each input of a transaction, given the output it spends, in
-- order, as it is in the transaction that made it: 'Nothing' for one that
-- is not known.
--
-- 'verifyStdTx' answers 'False' both for a forged signature and for a
-- script it does not read. To refuse a transaction before sending it,
-- those have to be told apart: a wrong 'InputForged' turns away a good
-- transaction, while 'InputUndecided' only leaves the question to a
-- node. So 'InputForged' is said of little, and only where there is
-- nothing to run:
--
-- * a coin locked to a key hash, to a key, to a witness key hash, to one
--   nested in a script hash, or to a Taproot key, spent by the key and
--   not by a script;
-- * with exactly the items such an input has, and a hash type of all;
-- * whose key is not the one the coin names, or whose signature does not
--   verify over the digest.
--
-- On Bitcoin Cash it reads what 'verifyStdInput' does not: a Schnorr
-- signature ('verifyCashSchnorr'), of one key or in a multisig, bare or in
-- a script hash, and a coin that holds tokens, whose digest covers them
-- ('txSigHashCashToken'). Inputs of those kinds are 'InputVerified' here
-- and not by 'verifyStdInput'. A multisig is never 'InputForged': one
-- that does not verify is 'InputUndecided'.
judgeInputs :: Network -> Ctx -> Tx -> [Maybe TxOut] -> [InputVerdict]
judgeInputs net ctx tx given = zipWith judge [0 ..] decoded
  where
    prevs = take (length tx.inputs) (given <> repeat Nothing)
    forked = net.sigHashForkId /= Nothing
    split bytes
      | forked = splitTokenPrefix bytes
      | otherwise = Just (B.empty, bytes)
    decoded = map (>>= decode) prevs
    decode o = do
      (prefix, script) <- split o.script
      so <- eitherToMaybe (unmarshal ctx script)
      return (prefix, so, o.value)
    spent =
      SpentCoins
        { coins = [d >>= \(prefix, so, v) -> if B.null prefix then Just (so, v) else Nothing | d <- decoded],
          outputs = sequence prevs
        }
    judge :: Int -> Maybe (B.ByteString, ScriptOutput, Word64) -> InputVerdict
    judge _ Nothing = InputUndecided
    judge i (Just (prefix, so, val))
      | B.null prefix && verifyInput net ctx tx spent i = InputVerified
      | otherwise = case so of
          PayPKHash h
            | null ws, Just [sig, pub] <- pushes -> keyed (addressHash pub == h) sig pub legacy
          PayPK pub
            | null ws, Just [sig] <- pushes -> signed sig pub.point legacy
          PayWitnessPKHash h
            | net.segWit, B.null inp, [sig, pub] <- ws -> keyed (addressHash pub == h) sig pub (segwit so)
          PayScriptHash h
            | net.segWit,
              Just [program] <- pushes,
              addressHash program == h,
              Right nested@(PayWitnessPKHash kh) <- unmarshal ctx program,
              [sig, pub] <- ws ->
                keyed (addressHash pub == kh) sig pub (segwit nested)
          PayWitness 1 program
            | net.segWit, B.length program == 32, B.null inp, [sig] <- ws -> taproot program sig
          PayMulSig keys asked
            | forked, null ws, Just (bits : sigs) <- pushes -> cashMultisig so keys asked bits sigs
          PayScriptHash h
            | forked,
              null ws,
              Just items@(_ : _ : _) <- pushes,
              addressHash (last items) == h,
              Right redeem@(PayMulSig keys asked) <- unmarshal ctx (last items),
              bits : sigs <- init items ->
                cashMultisig redeem keys asked bits sigs
          _ -> InputUndecided
      where
        inp = (tx.inputs !! i).script
        ws = if length tx.witness > i then tx.witness !! i else []
        -- the items of an input script that only pushes data
        pushes = case runGetS deserialize inp of
          Right (Script ops) -> mapM pushed ops
          Left _ -> Nothing
        -- a small number is pushed by an opcode of its own
        pushed = \case
          OP_PUSHDATA d _ -> Just d
          op -> B.singleton . fromIntegral <$> eitherToMaybe (scriptOpToInt op)
        legacy sh = do
          script <- encodeOutput ctx so
          if forked then txSigHashCashToken net tx prefix script val i sh else txSigHash net tx script val i sh
        segwit out sh = Sign.makeSigHash net ctx tx i out val sh Nothing
        -- a coin that names the hash of its key: another key does not
        -- open it, whatever it signed
        keyed named sig pub digest
          | not named = InputForged
          | otherwise = maybe InputUndecided (\k -> signed sig k digest) (importPubKey ctx pub)
        -- Forged is said of the hash type "all" only. With another hash
        -- type a signature that verifies is verified, and one that does
        -- not is left alone.
        signed sig key digest
          | B.null sig || not (readable (B.last sig)) = InputUndecided
          | otherwise = case digest (fromIntegral (B.last sig)) of
              Left _ -> InputUndecided
              Right m
                -- on Bitcoin Cash a signature of 64 bytes is a Schnorr one
                | forked && B.length body == 64 -> sure (verifyCashSchnorr ctx key body m)
                | otherwise -> maybe InputUndecided (\s -> sure (verifyHashSig ctx m s key)) (decodeStrictSig ctx body)
          where
            body = B.init sig
            sure ok
              | ok = InputVerified
              | B.last sig == (if forked then 0x41 else 0x01) = InputForged
              | otherwise = InputUndecided
        -- The hash types whose digest is computed here. On Bitcoin Cash:
        -- all, none or single, with the fork id, alone or with "anyone
        -- can pay"; not the one that covers every coin spent.
        readable ht
          | forked = ht `elem` [0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3]
          | otherwise = ht == 0x01
        -- A multisig of Bitcoin Cash signed with Schnorr signatures. In
        -- place of the empty item that a multisig takes first there is a
        -- field of bits, one for each key in the order of the script,
        -- the first key lowest, set for the keys that signed. It has
        -- exactly the bytes that hold a bit for every key, no bit past
        -- the keys, and as many bits set as signatures are asked for.
        -- The signatures follow in the order of their keys, and every
        -- one must be a Schnorr signature that verifies. This is
        -- OP_CHECKMULTISIG of Bitcoin Cash Node, since November 2019.
        cashMultisig script keys asked bits sigs
          | B.null bits = InputUndecided
          | B.length bits /= (length keys + 7) `div` 8 = InputUndecided
          | field >= 2 ^ length keys || popCount field /= asked || length sigs /= asked = InputUndecided
          | all good (zip signers sigs) = InputVerified
          | otherwise = InputUndecided
          where
            field = B.foldr (\w acc -> acc * 256 + toInteger w) 0 bits :: Integer
            signers = [k | (n, k) <- zip [0 ..] keys, testBit field n]
            good (key, sig) =
              B.length sig == 65
                && readable (B.last sig)
                && either
                  (const False)
                  (verifyCashSchnorr ctx key.point (B.init sig))
                  (encodeOutput ctx script >>= \code -> cashDigest code (fromIntegral (B.last sig)))
            cashDigest code = txSigHashCashToken net tx prefix code val i
        taproot program sig = fromRight InputUndecided $ do
          key <- maybe (Left "not a key") Right (importXOnlyPubKey ctx program)
          outs <- maybe (Left "a spent output is missing") Right spent.outputs
          TaprootSignature s sh <- decodeTaprootSig sig
          unless (sh == sigHashDefault || sh == sigHashAll) $ Left "another hash type"
          m <- taprootSigHash tx outs i sh Nothing Nothing
          return (verdict (verifySchnorr ctx key s (hashToMsg m)))
        verdict ok = if ok then InputVerified else InputForged

-- | The keys of a Taproot multisig script and the number of signatures it
-- asks for, if the script is one: see 'verifyStdInput'.
multiA :: [ScriptOp] -> Maybe ([B.ByteString], Int)
multiA (OP_PUSHDATA first OPCODE : OP_CHECKSIG : rest) = go [first] rest
  where
    go keys (OP_PUSHDATA key OPCODE : OP_CHECKSIGADD : more) = go (key : keys) more
    go keys [number, OP_NUMEQUAL]
      | Right asked <- scriptOpToInt number,
        asked <= length keys,
        all ((== 32) . B.length) keys =
          Just (reverse keys, asked)
    go _ _ = Nothing
multiA _ = Nothing

-- | Whether an output script is a Taproot output: a witness program of
-- version 1 that is 32 bytes long
isTaproot :: ScriptOutput -> Bool
isTaproot = \case
  PayWitness 1 program -> B.length program == 32
  _ -> False

-- | Count the signatures of a multisig input that verify against the keys
-- of its script, taken in the order of the keys. An empty item counts for
-- nothing and passes over one key.
--
-- The count is not a verdict. An input is valid when it has exactly the
-- signatures its script requires and all of them count, which
-- 'verifyStdInput' checks. An input with an item more, or with an empty
-- item, can count enough signatures and still fail @OP_CHECKMULTISIG@.
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
