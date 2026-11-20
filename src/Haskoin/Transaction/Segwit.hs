{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Transaction.Segwit
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Types to represent segregated witness data and auxilliary functions to
-- manipulate it.  See [BIP 141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
-- and [BIP 143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki) for
-- details.
module Haskoin.Transaction.Segwit
  ( -- * Segwit
    WitnessProgram (..),
    WitnessProgramPKH (..),
    WitnessProgramSH (..),
    isSegwit,
    viewWitnessProgram,
    decodeWitnessInput,
    calcWitnessProgram,
    simpleInputStack,
    toWitnessStack,
  )
where

import Control.Monad (unless)
import Crypto.Secp256k1
import Data.ByteString (ByteString)
import Data.Bytes.Get (runGetS)
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (Serial (deserialize, serialize))
import Haskoin.Crypto.Keys.Common
import Haskoin.Network.Data
import Haskoin.Script.Common
import Haskoin.Script.SigHash
import Haskoin.Script.Standard
import Haskoin.Transaction.Common
import Haskoin.Util.Marshal

-- | Test if a 'ScriptOutput' is P2WPKH or P2WSH
--
-- @since 0.11.0.0
isSegwit :: ScriptOutput -> Bool
isSegwit = \case
  PayWitnessPKHash {} -> True
  PayWitnessScriptHash {} -> True
  _ -> False

-- | High level represenation of a (v0) witness program
--
-- @since 0.11.0.0
data WitnessProgram
  = P2WPKH WitnessProgramPKH
  | P2WSH WitnessProgramSH
  | EmptyWitnessProgram
  deriving (Eq, Show)

-- | Encode a witness program
--
-- @since 0.11.0.0
toWitnessStack :: Network -> WitnessProgram -> WitnessStack
toWitnessStack net = \case
  P2WPKH (WitnessProgramPKH sig key) ->
    [encodeTxSig net sig, encodeSerial key]
  P2WSH (WitnessProgramSH stack scr) ->
    stack <> [runPutS (serialize scr)]
  EmptyWitnessProgram ->
    mempty

-- | High level representation of a P2WPKH witness
--
-- @since 0.11.0.0
data WitnessProgramPKH = WitnessProgramPKH
  { signature :: !TxSignature,
    key :: !PublicKey
  }
  deriving (Eq, Show)

-- | High-level representation of a P2WSH witness
--
-- @since 0.11.0.0
data WitnessProgramSH = WitnessProgramSH
  { stack :: ![ByteString],
    script :: !Script
  }
  deriving (Eq, Show)

-- | Calculate the witness program from the transaction data
--
-- @since 0.11.0.0
viewWitnessProgram ::
  Network ->
  ScriptOutput ->
  WitnessStack ->
  Either String WitnessProgram
viewWitnessProgram net so witness = case so of
  PayWitnessPKHash _ | length witness == 2 -> do
    sig <- decodeTxSig net (head witness)
    pubkey <- decodePubKey $ witness !! 1
    return . P2WPKH $ WitnessProgramPKH sig pubkey
  PayWitnessScriptHash _ | not (null witness) -> do
    redeemScript <- runGetS deserialize $ last witness
    return . P2WSH $ WitnessProgramSH (init witness) redeemScript
  _
    | null witness -> return EmptyWitnessProgram
    | otherwise -> Left "viewWitnessProgram: Invalid witness program"

-- | Match a witness program with the standard inputs. For a
-- pay-to-witness-public-key-hash coin the answer is the signature and the
-- key. For a pay-to-witness-script-hash coin it is the witness script as a
-- 'ScriptOutput', and the input that such a script takes.
--
-- A 'ScriptOutput' does not keep the bytes of a script: see 'decodeOutput'.
-- The caller only has 'encodeOutput' of the value returned here to hash
-- and to sign, as 'Haskoin.Transaction.Builder.verifyStdInput' does. So a
-- witness script that 'encodeOutput' would write back as other bytes is
-- refused, as 'decodeInput' refuses such a redeem script. That is a
-- multisig whose keys are not direct pushes.
--
-- Without this refusal, a spend verifies although its witness script is
-- not the one the coin commits to: the hash and the digest are taken on
-- the script written back, which is the one of the coin. By consensus the
-- hash of the bytes in the witness must be the witness program (BIP 141),
-- so no block holds that spend.
--
-- The cost: the spend of a coin that does commit to such a script is not
-- read here, although a block may hold it. Nodes do not relay that spend
-- (the @MINIMALDATA@ rule of the relay policy), and the signer of this
-- library cannot make it.
--
-- @since 0.11.0.0
decodeWitnessInput ::
  Network ->
  WitnessProgram ->
  Either String (Maybe ScriptOutput, SimpleInput)
decodeWitnessInput net = \case
  P2WPKH (WitnessProgramPKH sig key) -> return (Nothing, SpendPKHash sig key)
  P2WSH (WitnessProgramSH st scr) -> do
    so <- decodeOutput scr
    -- A 'Script' is written as the bytes it was read from, so equal
    -- scripts are equal bytes.
    unless (encodeOutput so == Right scr) $
      Left "decodeWitnessInput: the witness script is not in the form that encodeOutput writes"
    fmap (Just so,) $ case (so, st) of
      (PayPK _, [sigBS]) ->
        SpendPK <$> decodeTxSig net sigBS
      (PayPKHash _, [sigBS, keyBS]) ->
        SpendPKHash
          <$> decodeTxSig net sigBS
          <*> decodePubKey keyBS
      (PayMulSig _ _, "" : sigsBS) ->
        SpendMulSig
          <$> traverse (decodeTxSig net) sigsBS
      _ -> Left "decodeWitnessInput: Non-standard script output"
  EmptyWitnessProgram -> Left "decodeWitnessInput: Empty witness program"

-- | Create the witness program for a standard input
--
-- @since 0.11.0.0
calcWitnessProgram ::
  Network ->
  ScriptOutput ->
  ScriptInput ->
  Either String WitnessProgram
calcWitnessProgram net so si = case (so, si) of
  (PayWitnessPKHash {}, RegularInput (SpendPKHash sig pk)) ->
    Right $ p2wpkh sig pk
  (PayScriptHash {}, RegularInput (SpendPKHash sig pk)) ->
    Right $ p2wpkh sig pk
  (PayWitnessScriptHash {}, ScriptHashInput i o) ->
    p2wsh i o
  (PayScriptHash {}, ScriptHashInput i o) ->
    p2wsh i o
  _ -> Left "calcWitnessProgram: Invalid segwit SigInput"
  where
    p2wpkh sig =
      P2WPKH . WitnessProgramPKH sig
    p2wsh i o =
      P2WSH . WitnessProgramSH (simpleInputStack net i) <$> encodeOutput o

-- | Create the witness stack required to spend a standard P2WSH input
--
-- @since 0.11.0.0
simpleInputStack :: Network -> SimpleInput -> [ByteString]
simpleInputStack net = \case
  SpendPK sig -> [f sig]
  SpendPKHash sig k -> [f sig, encodeSerial k]
  SpendMulSig sigs -> "" : fmap f sigs
  where
    f TxSignatureEmpty = ""
    f sig = encodeTxSig net sig
