{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Script.Standard
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Standard scripts like pay-to-public-key, pay-to-public-key-hash,
-- pay-to-script-hash, pay-to-multisig and corresponding SegWit variants.
module Haskoin.Script.Standard
  ( -- * Standard Script Outputs
    ScriptOutput (..),
    RedeemScript,
    isPayPK,
    isPayPKHash,
    isPayMulSig,
    isPayScriptHash,
    isPayWitness,
    isPayWitnessPKHash,
    isPayWitnessScriptHash,
    isPayScript32Hash,
    isDataCarrier,
    encodeOutput,
    decodeOutput,
    toP2SH,
    toP2WSH,
    sortMulSig,

    -- * Standard Script Inputs
    ScriptInput (..),
    SimpleInput (..),
    encodeInput,
    decodeInput,
    isSpendPK,
    isSpendPKHash,
    isSpendMulSig,
    isScriptHashInput,
  )
where

import Control.Applicative ((<|>))
import Control.DeepSeq
import Control.Monad (guard, liftM2, (<=<))
import Crypto.Secp256k1
import Data.Aeson (ToJSON (..), Value (..), withText)
import Data.Aeson.Encoding (Encoding, text)
import Data.Aeson.Types (Parser)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Function (on)
import Data.Hashable
import Data.List (sortBy)
import Data.Maybe (fromJust, isJust)
import Data.Word (Word8)
import GHC.Generics (Generic)
import Haskoin.Crypto.Hash
import Haskoin.Crypto.Keys.Common
import Haskoin.Network.Data
import Haskoin.Script.Common
import Haskoin.Script.SigHash
import Haskoin.Util

-- | Data type describing standard transaction output scripts. Output scripts
-- provide the conditions that must be fulfilled for someone to spend the funds
-- in a transaction output.
data ScriptOutput
  = -- | pay to public key
    PayPK {key :: !PublicKey}
  | -- | pay to public key hash
    PayPKHash {hash160 :: !Hash160}
  | -- | multisig
    PayMulSig
      { keys :: ![PublicKey],
        required :: !Int
      }
  | -- | pay to a script hash
    PayScriptHash {hash160 :: !Hash160}
  | -- | pay to witness public key hash
    PayWitnessPKHash {hash160 :: !Hash160}
  | -- | pay to witness script hash
    PayWitnessScriptHash {hash256 :: !Hash256}
  | -- | another pay to witness address
    PayWitness
      { version :: !Word8,
        bytes :: !ByteString
      }
  | -- | pay to a script hash (256-bit)
    PayScript32Hash {hash256 :: !Hash256}
  | -- | provably unspendable data carrier
    DataCarrier {bytes :: !ByteString}
  deriving (Eq, Show, Read, Generic, NFData)

instance MarshalJSON Ctx ScriptOutput where
  unmarshalValue ctx =
    withText "ScriptOutput" $ \t ->
      case decodeHex t of
        Nothing -> fail "Could not decode hex script"
        Just bs -> either fail return $ unmarshal ctx bs

  marshalValue ctx = String . encodeHex . marshal ctx

  marshalEncoding ctx = hexEncoding . runPutL . marshalPut ctx

-- | Is script a pay-to-public-key output?
isPayPK :: ScriptOutput -> Bool
isPayPK (PayPK _) = True
isPayPK _ = False

-- | Is script a pay-to-pub-key-hash output?
isPayPKHash :: ScriptOutput -> Bool
isPayPKHash (PayPKHash _) = True
isPayPKHash _ = False

-- | Is script a pay-to-multi-sig output?
isPayMulSig :: ScriptOutput -> Bool
isPayMulSig (PayMulSig _ _) = True
isPayMulSig _ = False

-- | Is script a pay-to-script-hash output?
isPayScriptHash :: ScriptOutput -> Bool
isPayScriptHash (PayScriptHash _) = True
isPayScriptHash _ = False

-- | Is script a pay-to-witness-pub-key-hash output?
isPayWitnessPKHash :: ScriptOutput -> Bool
isPayWitnessPKHash (PayWitnessPKHash _) = True
isPayWitnessPKHash _ = False

-- | Is script a pay-to-witness-script-hash output?
isPayWitnessScriptHash :: ScriptOutput -> Bool
isPayWitnessScriptHash (PayWitnessScriptHash _) = True
isPayWitnessScriptHash _ = False

-- | Is script paying to a different type of witness address?
isPayWitness :: ScriptOutput -> Bool
isPayWitness (PayWitness _ _) = True
isPayWitness _ = False

-- | Is script paying to 256-bit script hash?
isPayScript32Hash :: ScriptOutput -> Bool
isPayScript32Hash (PayScript32Hash _) = True
isPayScript32Hash _ = False

-- | Is script a data carrier output?
isDataCarrier :: ScriptOutput -> Bool
isDataCarrier (DataCarrier _) = True
isDataCarrier _ = False

-- | Tries to decode a 'ScriptOutput' from a 'Script'. This can fail if the
-- script is not recognized as any of the standard output types.
decodeOutput :: Ctx -> Script -> Either String ScriptOutput
decodeOutput ctx s = case s.ops of
  -- Pay to PubKey
  [OP_PUSHDATA bs _, OP_CHECKSIG]
    | B.length bs == 33 || B.length bs == 65 ->
        PayPK <$> unmarshal ctx bs
    | otherwise ->
        Left "decodeOutput: public key must be 33 or 65 bytes long"
  -- Pay to PubKey Hash
  [OP_DUP, OP_HASH160, OP_PUSHDATA bs _, OP_EQUALVERIFY, OP_CHECKSIG]
    | B.length bs == 20 ->
        PayPKHash <$> runGetS deserialize bs
    | otherwise ->
        Left "decodeOutput: public key hash must be 20 bytes long"
  -- Pay to Script Hash
  [OP_HASH160, OP_PUSHDATA bs _, OP_EQUAL]
    | B.length bs == 20 ->
        PayScriptHash <$> runGetS deserialize bs
    | otherwise ->
        Left "decodeOutput: script hash must be 20 bytes long"
  -- Pay to 256-bit Script Hash
  [OP_HASH256, OP_PUSHDATA bs _, OP_EQUAL]
    | B.length bs == 32 ->
        PayScript32Hash <$> runGetS deserialize bs
    | otherwise ->
        Left "decodeOutput: script hash must be 32 bytes long"
  -- Pay to Witness
  [OP_0, OP_PUSHDATA bs OPCODE]
    | B.length bs == 20 ->
        PayWitnessPKHash <$> runGetS deserialize bs
    | B.length bs == 32 ->
        PayWitnessScriptHash <$> runGetS deserialize bs
    | otherwise ->
        Left "decodeOutput: version 0 segwit must be 20 or 32 bytes long"
  -- Other Witness
  [ver, OP_PUSHDATA bs _]
    | Just wv <- opWitnessVersion ver,
      B.length bs >= 2,
      B.length bs <= 40 ->
        Right $ PayWitness wv bs
  -- Provably unspendable data carrier output
  [OP_RETURN, OP_PUSHDATA bs _] -> Right $ DataCarrier bs
  -- Pay to MultiSig Keys
  _ -> case matchPayMulSig ctx s of
    Right x -> return x
    Left _ -> Left "decodeOutput: Non-standard output"

witnessVersionOp :: Word8 -> Maybe ScriptOp
witnessVersionOp 0 = Just OP_0
witnessVersionOp 1 = Just OP_1
witnessVersionOp 2 = Just OP_2
witnessVersionOp 3 = Just OP_3
witnessVersionOp 4 = Just OP_4
witnessVersionOp 5 = Just OP_5
witnessVersionOp 6 = Just OP_6
witnessVersionOp 7 = Just OP_7
witnessVersionOp 8 = Just OP_8
witnessVersionOp 9 = Just OP_9
witnessVersionOp 10 = Just OP_10
witnessVersionOp 11 = Just OP_11
witnessVersionOp 12 = Just OP_12
witnessVersionOp 13 = Just OP_13
witnessVersionOp 14 = Just OP_14
witnessVersionOp 15 = Just OP_15
witnessVersionOp 16 = Just OP_16
witnessVersionOp _ = Nothing

opWitnessVersion :: ScriptOp -> Maybe Word8
opWitnessVersion OP_0 = Just 0
opWitnessVersion OP_1 = Just 1
opWitnessVersion OP_2 = Just 2
opWitnessVersion OP_3 = Just 3
opWitnessVersion OP_4 = Just 4
opWitnessVersion OP_5 = Just 5
opWitnessVersion OP_6 = Just 6
opWitnessVersion OP_7 = Just 7
opWitnessVersion OP_8 = Just 8
opWitnessVersion OP_9 = Just 9
opWitnessVersion OP_10 = Just 10
opWitnessVersion OP_11 = Just 11
opWitnessVersion OP_12 = Just 12
opWitnessVersion OP_13 = Just 13
opWitnessVersion OP_14 = Just 14
opWitnessVersion OP_15 = Just 15
opWitnessVersion OP_16 = Just 16
opWitnessVersion _ = Nothing

-- | Computes a 'Script' from a standard 'ScriptOutput'.
encodeOutput :: Ctx -> ScriptOutput -> Script
encodeOutput ctx s = Script $ case s of
  -- Pay to PubKey
  (PayPK k) -> [opPushData $ marshal ctx k, OP_CHECKSIG]
  -- Pay to PubKey Hash Address
  (PayPKHash h) ->
    [ OP_DUP,
      OP_HASH160,
      opPushData $ runPutS $ serialize h,
      OP_EQUALVERIFY,
      OP_CHECKSIG
    ]
  -- Pay to MultiSig Keys
  (PayMulSig ps r)
    | r <= length ps ->
        let opM = intToScriptOp r
            opN = intToScriptOp $ length ps
            keys = map (opPushData . marshal ctx) ps
         in opM : keys ++ [opN, OP_CHECKMULTISIG]
    | otherwise -> error "encodeOutput: PayMulSig r must be <= than pkeys"
  -- Pay to Script Hash Address
  (PayScriptHash h) ->
    [OP_HASH160, opPushData $ runPutS $ serialize h, OP_EQUAL]
  -- Pay to Witness PubKey Hash Address
  (PayWitnessPKHash h) ->
    [OP_0, opPushData $ runPutS $ serialize h]
  (PayWitnessScriptHash h) ->
    [OP_0, opPushData $ runPutS $ serialize h]
  (PayWitness v h) ->
    [ case witnessVersionOp v of
        Nothing -> error "encodeOutput: invalid witness version"
        Just c -> c,
      opPushData h
    ]
  -- Provably unspendable output
  (DataCarrier d) -> [OP_RETURN, opPushData d]

instance Marshal Ctx ScriptOutput where
  marshalGet ctx = do
    script <- deserialize
    case decodeOutput ctx script of
      Left e -> fail e
      Right o -> return o
  marshalPut ctx = serialize . encodeOutput ctx

-- | Encode script as pay-to-script-hash script
toP2SH :: Script -> ScriptOutput
toP2SH = PayScriptHash . addressHash . runPutS . serialize

-- | Encode script as a pay-to-witness-script-hash script
toP2WSH :: Script -> ScriptOutput
toP2WSH = PayWitnessScriptHash . sha256 . runPutS . serialize

-- | Match @[OP_N, PubKey1, ..., PubKeyM, OP_M, OP_CHECKMULTISIG]@
matchPayMulSig :: Ctx -> Script -> Either String ScriptOutput
matchPayMulSig ctx (Script ops) = case splitAt (length ops - 2) ops of
  (m : xs, [n, OP_CHECKMULTISIG]) -> do
    (intM, intN) <- liftM2 (,) (scriptOpToInt m) (scriptOpToInt n)
    if intM <= intN && length xs == intN
      then liftM2 PayMulSig (go xs) (return intM)
      else Left "matchPayMulSig: Invalid M or N parameters"
  _ -> Left "matchPayMulSig: script did not match output template"
  where
    go (OP_PUSHDATA bs _ : xs)
      | B.length bs == 33 || B.length bs == 65 =
          liftM2 (:) (unmarshal ctx bs) (go xs)
      | otherwise =
          Left "matchPayMulSig: public key must be 33 or 65 bytes long"
    go [] =
      Right []
    go _ =
      Left "matchPayMulSig: invalid multisig opcode"

-- | Sort the public keys of a multisig output in ascending order by comparing
-- their compressed serialized representations. Refer to BIP-67.
sortMulSig :: Ctx -> ScriptOutput -> ScriptOutput
sortMulSig ctx out = case out of
  PayMulSig keys r ->
    PayMulSig
      (sortBy (compare `on` marshal ctx) keys)
      r
  _ -> error "Can only call orderMulSig on PayMulSig scripts"

-- | Data type describing standard transaction input scripts. Input scripts
-- provide the signing data required to unlock the coins of the output they are
-- trying to spend, except in pay-to-witness-public-key-hash and
-- pay-to-script-hash transactions.
data SimpleInput
  = SpendPK
      { -- | transaction signature
        signature :: !TxSignature
      }
  | SpendPKHash
      { -- | embedded signature
        signature :: !TxSignature,
        -- | public key
        key :: !PublicKey
      }
  | SpendMulSig
      { -- | list of signatures
        signatures :: ![TxSignature]
      }
  deriving (Eq, Show, Read, Generic, NFData)

-- | Returns true if the input script is spending from a pay-to-public-key
-- output.
isSpendPK :: ScriptInput -> Bool
isSpendPK (RegularInput (SpendPK _)) = True
isSpendPK _ = False

-- | Returns true if the input script is spending from a pay-to-public-key-hash
-- output.
isSpendPKHash :: ScriptInput -> Bool
isSpendPKHash (RegularInput (SpendPKHash _ _)) = True
isSpendPKHash _ = False

-- | Returns true if the input script is spending a multisig output.
isSpendMulSig :: ScriptInput -> Bool
isSpendMulSig (RegularInput (SpendMulSig _)) = True
isSpendMulSig _ = False

-- | Returns true if the input script is spending a pay-to-script-hash output.
isScriptHashInput :: ScriptInput -> Bool
isScriptHashInput (ScriptHashInput _ _) = True
isScriptHashInput _ = False

-- | A redeem script is the output script serialized into the spending input
-- script. It must be included in inputs that spend pay-to-script-hash outputs.
type RedeemScript = ScriptOutput

-- | Standard input script high-level representation.
data ScriptInput
  = RegularInput
      { -- | get wrapped simple input
        get :: !SimpleInput
      }
  | ScriptHashInput
      { -- | get simple input associated with redeem script
        get :: !SimpleInput,
        -- | redeem script
        redeem :: !RedeemScript
      }
  deriving (Show, Read, Eq, Generic, NFData)

-- | Heuristic to decode an input script into one of the standard types.
decodeSimpleInput :: Network -> Ctx -> Script -> Either String SimpleInput
decodeSimpleInput net ctx (Script ops) =
  maybeToEither errMsg $ matchPK ops <|> matchPKHash ops <|> matchMulSig ops
  where
    matchPK [op] = SpendPK <$> f op
    matchPK _ = Nothing
    matchPKHash [op, OP_PUSHDATA pub _] =
      SpendPKHash <$> f op <*> eitherToMaybe (unmarshal ctx pub)
    matchPKHash _ = Nothing
    matchMulSig (x : xs) = do
      guard $ x == OP_0
      SpendMulSig <$> mapM f xs
    matchMulSig _ = Nothing
    f OP_0 = return TxSignatureEmpty
    f (OP_PUSHDATA "" OPCODE) = f OP_0
    f (OP_PUSHDATA bs _) = eitherToMaybe $ decodeTxSig net ctx bs
    f _ = Nothing
    errMsg = "decodeInput: Could not decode script input"

-- | Heuristic to decode a 'ScriptInput' from a 'Script'. This function fails if
-- the script can not be parsed as a standard script input.
decodeInput :: Network -> Ctx -> Script -> Either String ScriptInput
decodeInput net ctx s@(Script ops) =
  maybeToEither errMsg $ matchSimpleInput <|> matchPayScriptHash
  where
    matchSimpleInput =
      RegularInput <$> eitherToMaybe (decodeSimpleInput net ctx s)
    matchPayScriptHash =
      case splitAt (length s.ops - 1) ops of
        (is, [OP_PUSHDATA bs _]) -> do
          rdm <- eitherToMaybe $ unmarshal ctx bs
          inp <- eitherToMaybe $ decodeSimpleInput net ctx $ Script is
          return $ ScriptHashInput inp rdm
        _ -> Nothing
    errMsg = "decodeInput: Could not decode script input"

instance Marshal (Network, Ctx) ScriptInput where
  marshalGet (net, ctx) =
    deserialize >>= either fail return . decodeInput net ctx

  marshalPut (net, ctx) =
    serialize . encodeInput net ctx

-- | Encode a standard input into a script.
encodeInput :: Network -> Ctx -> ScriptInput -> Script
encodeInput net ctx s = case s of
  RegularInput ri -> encodeSimpleInput net ctx ri
  ScriptHashInput i o ->
    Script $ (encodeSimpleInput net ctx i).ops ++ [opPushData $ marshal ctx o]

-- | Encode a standard 'SimpleInput' into opcodes as an input 'Script'.
encodeSimpleInput :: Network -> Ctx -> SimpleInput -> Script
encodeSimpleInput net ctx s =
  Script $
    case s of
      SpendPK ts -> [f ts]
      SpendPKHash ts p -> [f ts, opPushData $ marshal ctx p]
      SpendMulSig xs -> OP_0 : map f xs
  where
    f TxSignatureEmpty = OP_0
    f ts = opPushData $ encodeTxSig net ctx ts
