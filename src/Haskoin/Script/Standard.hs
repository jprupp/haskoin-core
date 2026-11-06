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
    maxMultisigKeys,
    maxRedeemScriptSize,
    maxWitnessScriptSize,
    encodeOutput,
    decodeOutput,
    toP2SH,
    toP2WSH,
    p2shScriptHash,
    p2wshScriptHash,
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
    isNestedWitnessInput,
  )
where

import Control.Applicative ((<|>))
import Control.DeepSeq
import Control.Monad (guard, unless)
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
  | -- | multisig of 1 to 'maxMultisigKeys' keys
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
  | -- | witness program of version 1 to 16, from 2 to 40 bytes long
    PayWitness
      { version :: !Word8,
        bytes :: !ByteString
      }
  | -- | pay to a script hash (256-bit)
    PayScript32Hash {hash256 :: !Hash256}
  | -- | provably unspendable data carrier: @OP_RETURN@ followed by the data
    -- of each push, which may be no push at all
    DataCarrier {pushes :: ![ByteString]}
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

-- | The most keys a multisig output can have: @MAX_PUBKEYS_PER_MULTISIG@ of
-- Bitcoin Core.
--
-- Twenty keys fit in a bare multisig output and in a pay-to-witness-script-hash
-- output. They do not fit in a pay-to-script-hash output, whose redeem script
-- is limited to 'maxRedeemScriptSize' bytes. That is 15 compressed keys
-- (3 + 15 × 34 = 513 bytes) or 7 uncompressed keys (3 + 7 × 66 = 465 bytes).
maxMultisigKeys :: Int
maxMultisigKeys = 20

-- | The largest redeem script a pay-to-script-hash output can have, in bytes.
-- The redeem script is one push in the input script, and consensus limits a
-- push to 520 bytes: @MAX_SCRIPT_ELEMENT_SIZE@ of Bitcoin Core. Coins sent to
-- the hash of a larger script can never be spent.
maxRedeemScriptSize :: Int
maxRedeemScriptSize = 520

-- | The largest witness script a pay-to-witness-script-hash output can have,
-- in bytes: @MAX_SCRIPT_SIZE@ of Bitcoin Core, 10,000. The interpreter fails
-- on a larger script, so coins sent to its hash can never be spent.
--
-- This is the consensus limit. The relay policy of Bitcoin Core is stricter:
-- it only relays a spend whose witness script is at most 3,600 bytes
-- (@MAX_STANDARD_P2WSH_SCRIPT_SIZE@). This library does not enforce that.
maxWitnessScriptSize :: Int
maxWitnessScriptSize = 10000

-- | Tries to decode a 'ScriptOutput' from a 'Script'. This can fail if the
-- script is not recognized as any of the standard output types.
--
-- The templates are matched on their exact bytes, as Bitcoin Core matches
-- them: the hash or key of a pay-to-public-key, pay-to-public-key-hash,
-- pay-to-script-hash or witness output must be a direct push ('OPCODE'). A
-- script that writes it with @OP_PUSHDATA1@ is not that output type. By
-- consensus it is not a pay-to-script-hash or witness output at all, and
-- anyone can spend it, so it must not be shown as the address it looks like.
-- The counts of a multisig output are @OP_1@ to @OP_16@, or a one-byte push
-- for 17 to 'maxMultisigKeys', and a key must fill its push exactly.
--
-- A 'ScriptOutput' describes what a script does, not its bytes. Two kinds of
-- script decode to a value that 'encodeOutput' writes back as other bytes:
-- a multisig whose keys are not direct pushes, and a data carrier whose data
-- is not pushed in the shortest way. Bitcoin Core gives those the same type
-- (@multisig@ and @nulldata@). So never hash or sign the result of
-- @encodeOutput@ in place of a script that came from somewhere else. Hash
-- and sign the bytes of that script. 'decodeInput' refuses a redeem script
-- that would not come back as the same bytes.
--
-- Three kinds of script that the @Solver@ of Bitcoin Core classifies are not
-- decoded here, because a 'PublicKey' holds a point of the curve:
--
-- * A pay-to-public-key output, or a multisig output, with a key of the
--   hybrid form (first byte 0x06 or 0x07). The @Solver@ only checks the size
--   and the first byte of a key. Such keys are valid by consensus and refused
--   by the relay policy.
--
-- * The same outputs with a key of the right size that is not a point of the
--   curve. Protocols that store data in bare multisig outputs make those.
--
-- * @OP_RETURN@ followed by @OP_RESERVED@, which the push-only test of
--   Bitcoin Core counts as a push.
--
-- On Bitcoin Cash, an output that holds tokens starts with the token prefix
-- byte 0xef and is not decoded. See 'Haskoin.Script.SigHash.txSigHashForkId'
-- for what is not supported on that network.
decodeOutput :: Ctx -> Script -> Either String ScriptOutput
decodeOutput ctx s = case s.ops of
  -- Pay to PubKey
  [OP_PUSHDATA bs OPCODE, OP_CHECKSIG] ->
    PayPK <$> decodePubKey ctx bs
  -- Pay to PubKey Hash
  [OP_DUP, OP_HASH160, OP_PUSHDATA bs OPCODE, OP_EQUALVERIFY, OP_CHECKSIG]
    | B.length bs == 20 ->
        PayPKHash <$> runGetS deserialize bs
    | otherwise ->
        Left "decodeOutput: public key hash must be 20 bytes long"
  -- Pay to Script Hash
  [OP_HASH160, OP_PUSHDATA bs OPCODE, OP_EQUAL]
    | B.length bs == 20 ->
        PayScriptHash <$> runGetS deserialize bs
    | otherwise ->
        Left "decodeOutput: script hash must be 20 bytes long"
  -- Pay to 256-bit Script Hash
  [OP_HASH256, OP_PUSHDATA bs OPCODE, OP_EQUAL]
    | B.length bs == 32 ->
        PayScript32Hash <$> runGetS deserialize bs
    | otherwise ->
        Left "decodeOutput: script hash must be 32 bytes long"
  -- Witness programs
  [ver, OP_PUSHDATA bs OPCODE]
    | Just 0 <- opWitnessVersion ver -> case B.length bs of
        20 -> PayWitnessPKHash <$> runGetS deserialize bs
        32 -> PayWitnessScriptHash <$> runGetS deserialize bs
        _ -> Left "decodeOutput: version 0 segwit must be 20 or 32 bytes long"
    | Just wv <- opWitnessVersion ver,
      B.length bs >= minWitnessProgramLength,
      B.length bs <= maxWitnessProgramLength ->
        Right $ PayWitness wv bs
  -- Provably unspendable data carrier output
  OP_RETURN : rest
    | Just ds <- mapM pushOpData rest -> Right $ DataCarrier ds
  -- Pay to MultiSig Keys
  _ -> case matchPayMulSig ctx s of
    Right x -> return x
    Left _ -> Left "decodeOutput: Non-standard output"

-- | Shortest and longest witness program, in bytes, as BIP 141 defines them.
minWitnessProgramLength, maxWitnessProgramLength :: Int
minWitnessProgramLength = 2
maxWitnessProgramLength = 40

-- | The opcode that starts a witness program of a version.
witnessVersionOp :: Word8 -> Maybe ScriptOp
witnessVersionOp 0 = Just OP_0
witnessVersionOp v = eitherToMaybe $ intToScriptOp $ fromIntegral v

-- | The witness version that an opcode starts.
opWitnessVersion :: ScriptOp -> Maybe Word8
opWitnessVersion OP_0 = Just 0
opWitnessVersion op = fromIntegral <$> eitherToMaybe (scriptOpToInt op)

-- | Computes a 'Script' from a standard 'ScriptOutput'. Fails for a value
-- that no script can express: a 'PayMulSig' whose required count is not
-- between 1 and its number of keys, or with more than 'maxMultisigKeys' keys,
-- and a 'PayWitness' whose version is not 1 to 16 or whose program is not 2
-- to 40 bytes long. A version 0 program is a 'PayWitnessPKHash' or a
-- 'PayWitnessScriptHash'.
encodeOutput :: Ctx -> ScriptOutput -> Either String Script
encodeOutput ctx s = Script <$> case s of
  -- Pay to PubKey
  (PayPK k) -> Right [opPushData $ marshal ctx k, OP_CHECKSIG]
  -- Pay to PubKey Hash Address
  (PayPKHash h) ->
    Right
      [ OP_DUP,
        OP_HASH160,
        opPushData $ runPutS $ serialize h,
        OP_EQUALVERIFY,
        OP_CHECKSIG
      ]
  -- Pay to MultiSig Keys
  (PayMulSig ps r)
    | r < 1 ->
        Left "encodeOutput: multisig must require at least one signature"
    | r > n ->
        Left "encodeOutput: multisig requires more signatures than it has keys"
    | n > maxMultisigKeys ->
        Left "encodeOutput: multisig has more than 20 keys"
    | otherwise ->
        let keys = map (opPushData . marshal ctx) ps
         in Right $ multisigCountOp r : keys ++ [multisigCountOp n, OP_CHECKMULTISIG]
    where
      n = length ps
  -- Pay to Script Hash Address
  (PayScriptHash h) ->
    Right [OP_HASH160, opPushData $ runPutS $ serialize h, OP_EQUAL]
  -- Pay to 256-bit Script Hash Address
  (PayScript32Hash h) ->
    Right [OP_HASH256, opPushData $ runPutS $ serialize h, OP_EQUAL]
  -- Pay to Witness PubKey Hash Address
  (PayWitnessPKHash h) ->
    Right [OP_0, opPushData $ runPutS $ serialize h]
  (PayWitnessScriptHash h) ->
    Right [OP_0, opPushData $ runPutS $ serialize h]
  (PayWitness v h)
    | v == 0 ->
        Left "encodeOutput: a version 0 witness output is PayWitnessPKHash or PayWitnessScriptHash"
    | B.length h < minWitnessProgramLength || B.length h > maxWitnessProgramLength ->
        Left "encodeOutput: witness program must be 2 to 40 bytes long"
    | Just c <- witnessVersionOp v ->
        Right [c, opPushData h]
    | otherwise ->
        Left "encodeOutput: witness version must be 16 or less"
  -- Provably unspendable output
  (DataCarrier ds) -> Right $ OP_RETURN : map opPushData ds

-- | The 'Script' of a 'ScriptOutput' is the binary form. Writing a value that
-- 'encodeOutput' rejects fails with an 'error' call, since 'marshalPut'
-- cannot report a failure.
instance Marshal Ctx ScriptOutput where
  marshalGet ctx = do
    script <- deserialize
    case decodeOutput ctx script of
      Left e -> fail e
      Right o -> return o
  marshalPut ctx = either error serialize . encodeOutput ctx

-- | The pay-to-script-hash output of a redeem script. Fails for a script
-- longer than 'maxRedeemScriptSize' bytes, which could never be spent.
toP2SH :: Script -> Either String ScriptOutput
toP2SH = fmap PayScriptHash . p2shScriptHash

-- | The pay-to-witness-script-hash output of a witness script. Fails for a
-- script longer than 'maxWitnessScriptSize' bytes, which could never be
-- spent.
toP2WSH :: Script -> Either String ScriptOutput
toP2WSH = fmap PayWitnessScriptHash . p2wshScriptHash

-- | The hash that a pay-to-script-hash output commits to: HASH160 of the
-- serialized redeem script. Fails for a script longer than
-- 'maxRedeemScriptSize' bytes.
p2shScriptHash :: Script -> Either String Hash160
p2shScriptHash script
  | size > maxRedeemScriptSize =
      Left $
        "The redeem script is "
          <> show size
          <> " bytes long, and a pay-to-script-hash redeem script can have at most "
          <> show maxRedeemScriptSize
  | otherwise = Right (addressHash bytes)
  where
    bytes = runPutS (serialize script)
    size = B.length bytes

-- | The hash that a pay-to-witness-script-hash output commits to: SHA256 of
-- the serialized witness script. Fails for a script longer than
-- 'maxWitnessScriptSize' bytes.
p2wshScriptHash :: Script -> Either String Hash256
p2wshScriptHash script
  | size > maxWitnessScriptSize =
      Left $
        "The witness script is "
          <> show size
          <> " bytes long, and a pay-to-witness-script-hash witness script can have at most "
          <> show maxWitnessScriptSize
  | otherwise = Right (sha256 bytes)
  where
    bytes = runPutS (serialize script)
    size = B.length bytes

-- | Match @[OP_M, PubKey1, ..., PubKeyN, OP_N, OP_CHECKMULTISIG]@ with M and N
-- from 1 to 'maxMultisigKeys' and M at most N.
matchPayMulSig :: Ctx -> Script -> Either String ScriptOutput
matchPayMulSig ctx (Script ops) = case splitAt (length ops - 2) ops of
  (m : xs, [n, OP_CHECKMULTISIG]) -> do
    intM <- maybeToEither "matchPayMulSig: invalid M parameter" $ opMultisigCount m
    intN <- maybeToEither "matchPayMulSig: invalid N parameter" $ opMultisigCount n
    unless (intM <= intN && length xs == intN) $
      Left "matchPayMulSig: Invalid M or N parameters"
    keys <- mapM key xs
    return $ PayMulSig keys intM
  _ -> Left "matchPayMulSig: script did not match output template"
  where
    key (OP_PUSHDATA bs _) = decodePubKey ctx bs
    key _ = Left "matchPayMulSig: invalid multisig opcode"

-- | The count that a multisig opcode stands for: @OP_1@ to @OP_16@, or a
-- one-byte push of 17 to 'maxMultisigKeys'. Bitcoin Core reads the count as a
-- minimal script number, so a push of a byte from 1 to 16 is not a count.
opMultisigCount :: ScriptOp -> Maybe Int
opMultisigCount op = case op of
  OP_PUSHDATA bs OPCODE
    | B.length bs == 1,
      let n = fromIntegral (B.head bs),
      n > 16 && n <= maxMultisigKeys ->
        Just n
  _ -> eitherToMaybe $ scriptOpToInt op

-- | The opcode of a multisig count from 1 to 'maxMultisigKeys'.
multisigCountOp :: Int -> ScriptOp
multisigCountOp n =
  either (const $ OP_PUSHDATA (B.singleton $ fromIntegral n) OPCODE) id $
    intToScriptOp n

-- | Sort the public keys of a multisig output in ascending order by comparing
-- their serialized representations. Refer to BIP-67, which defines the order
-- for compressed keys. Any other output is returned unchanged.
sortMulSig :: Ctx -> ScriptOutput -> ScriptOutput
sortMulSig ctx out = case out of
  PayMulSig keys r ->
    PayMulSig
      (sortBy (compare `on` marshal ctx) keys)
      r
  _ -> out

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

-- | Returns true if the input script is spending a pay-to-script-hash output
-- that wraps a SegWit program.
isNestedWitnessInput :: ScriptInput -> Bool
isNestedWitnessInput (NestedWitnessInput _) = True
isNestedWitnessInput _ = False

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
  | -- | input of a pay-to-script-hash output that wraps a SegWit program
    -- (P2SH-P2WPKH or P2SH-P2WSH): the script only pushes the witness output
    -- script, and the signatures are in the witness
    NestedWitnessInput
      { -- | the wrapped 'PayWitnessPKHash' or 'PayWitnessScriptHash' output
        redeem :: !RedeemScript
      }
  deriving (Show, Read, Eq, Generic, NFData)

-- | The signature that a script element stands for: an empty push is
-- 'TxSignatureEmpty', any other push must decode as a signature.
sigOp :: Network -> Ctx -> ScriptOp -> Maybe TxSignature
sigOp net ctx op = do
  bs <- pushOpData op
  if B.null bs
    then return TxSignatureEmpty
    else eitherToMaybe $ decodeTxSig net ctx bs

-- | Heuristic to decode an input script into one of the standard types, when
-- the output it spends is not known. A single empty push is read as a
-- 'SpendPK' with an empty signature, although it is also the form of a
-- 'SpendMulSig' without signatures.
decodeSimpleInput :: Network -> Ctx -> Script -> Either String SimpleInput
decodeSimpleInput net ctx (Script ops) =
  maybeToEither errMsg $ matchPK ops <|> matchPKHash ops <|> matchMulSig ops
  where
    matchPK [op] = SpendPK <$> f op
    matchPK _ = Nothing
    matchPKHash [op, OP_PUSHDATA pub _] =
      SpendPKHash <$> f op <*> eitherToMaybe (decodePubKey ctx pub)
    matchPKHash _ = Nothing
    matchMulSig (OP_0 : xs) = SpendMulSig <$> mapM f xs
    matchMulSig _ = Nothing
    f = sigOp net ctx
    errMsg = "decodeInput: Could not decode script input"

-- | Decode the input of a pay-to-script-hash output as the redeem script
-- requires: one signature for 'PayPK', a signature and a key for
-- 'PayPKHash', and @OP_0@ followed by the signatures, possibly none, for
-- 'PayMulSig'. Other redeem scripts have no standard input.
decodeSimpleInputFor ::
  Network -> Ctx -> RedeemScript -> [ScriptOp] -> Maybe SimpleInput
decodeSimpleInputFor net ctx rdm ops = case (rdm, ops) of
  (PayPK _, [op]) -> SpendPK <$> f op
  (PayPKHash _, [op, OP_PUSHDATA pub _]) ->
    SpendPKHash <$> f op <*> eitherToMaybe (decodePubKey ctx pub)
  (PayMulSig _ _, OP_0 : xs) -> SpendMulSig <$> mapM f xs
  _ -> Nothing
  where
    f = sigOp net ctx

-- | Heuristic to decode a 'ScriptInput' from a 'Script'. This function fails if
-- the script can not be parsed as a standard script input.
--
-- A script whose last element is a standard output script is the input of a
-- pay-to-script-hash output. The elements before it must be the input that
-- the redeem script requires, see 'ScriptHashInput'. When the redeem script
-- is a SegWit program and nothing comes before it, the input is a
-- 'NestedWitnessInput'.
--
-- What this function reads is the standard form that nodes relay, not every
-- input that a block may hold:
--
-- * A signature must be a 'TxSignature': strict DER, a low S value and a
--   defined hash type. An input with a signature that is valid by consensus
--   alone does not decode. See 'TxSignature'.
--
-- * The redeem script must be in the form that 'encodeOutput' writes, byte
--   for byte. Bitcoin Core's @Solver@ also calls a script a multisig when a
--   key is pushed with @OP_PUSHDATA1@, but a 'ScriptOutput' cannot hold the
--   form of a push, so such a script would come back out as other bytes with
--   another hash. It is refused here, so that 'Haskoin.Address.inputAddress'
--   is always the hash of the bytes the input carries, and so that encoding
--   a decoded input never rewrites its redeem script. Spending such a script
--   breaks the @MINIMALDATA@ rule of the relay policy, so no standard
--   transaction has one.
--
-- * The witness program of a 'NestedWitnessInput' must be a direct push and
--   the only element of the script. BIP 141 makes any other form invalid by
--   consensus: "the scriptSig must be exactly a push of the BIP16
--   redeemScript".
decodeInput :: Network -> Ctx -> Script -> Either String ScriptInput
decodeInput net ctx s@(Script ops) =
  maybeToEither errMsg $ matchSimpleInput <|> matchPayScriptHash
  where
    matchSimpleInput =
      RegularInput <$> eitherToMaybe (decodeSimpleInput net ctx s)
    matchPayScriptHash =
      case splitAt (length s.ops - 1) ops of
        (is, [OP_PUSHDATA bs pushType]) -> do
          rdm <- eitherToMaybe $ unmarshal ctx bs
          guard (canonical rdm bs)
          case (is, rdm) of
            ([], PayWitnessPKHash _) -> nested pushType rdm
            ([], PayWitnessScriptHash _) -> nested pushType rdm
            _ -> do
              inp <- decodeSimpleInputFor net ctx rdm is
              return $ ScriptHashInput inp rdm
        _ -> Nothing
    -- The redeem script, written back, gives the bytes that were pushed.
    canonical rdm bs =
      fmap (runPutS . serialize) (encodeOutput ctx rdm) == Right bs
    -- A witness program is 22 or 34 bytes, so its only valid push is the
    -- direct one.
    nested pushType rdm = do
      guard (pushType == OPCODE)
      return (NestedWitnessInput rdm)
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
  NestedWitnessInput o ->
    Script [opPushData $ marshal ctx o]

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
