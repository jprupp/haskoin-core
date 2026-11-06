{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Script.SigHash
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Transaction signatures and related functions.
module Haskoin.Script.SigHash
  ( -- * Script Signatures
    SigHash (..),
    SigHashFlag (..),
    sigHashAll,
    sigHashNone,
    sigHashSingle,
    sigHashDefault,
    anyoneCanPay,
    hasForkIdFlag,
    setAnyoneCanPay,
    setForkIdFlag,
    isSigHashAll,
    isSigHashNone,
    isSigHashSingle,
    isSigHashUnknown,
    sigHashAddForkId,
    sigHashGetForkId,
    sigHashAddNetworkId,
    txSigHash,
    txSigHashForkId,
    TxSignature (..),
    decodeTxSig,
    encodeTxSig,
  )
where

import Control.DeepSeq
import Control.Monad
import Crypto.Secp256k1
import Data.Aeson
import Data.Bits
import Data.Bool (bool)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Hashable
import Data.Maybe
import Data.Scientific
import Data.Word
import GHC.Generics (Generic)
import Haskoin.Crypto.Hash
import Haskoin.Crypto.Signature
import Haskoin.Network.Common
import Haskoin.Network.Data
import Haskoin.Script.Common
import Haskoin.Transaction.Common
import Haskoin.Util

-- | Constant representing a SIGHASH flag that controls what is being signed.
data SigHashFlag
  = -- | sign all outputs
    SIGHASH_ALL
  | -- | sign no outputs
    SIGHASH_NONE
  | -- | sign the output index corresponding to the input
    SIGHASH_SINGLE
  | -- | replay protection for Bitcoin Cash transactions
    SIGHASH_FORKID
  | -- | new inputs can be added
    SIGHASH_ANYONECANPAY
  deriving (Eq, Ord, Show, Read, Generic, Bounded)

instance NFData SigHashFlag

instance Hashable SigHashFlag

-- | 'fromEnum' gives the value of the flag in a hash type byte, and 'toEnum'
-- reads it back. The values are not consecutive, so the functions that list
-- flags walk the constructors in their order instead of counting: @[minBound
-- ..]@ is the five flags. 'toEnum' of a number that is no flag, 'succ' of the
-- last flag and 'pred' of the first raise an error, as they do for any
-- enumeration.
instance Enum SigHashFlag where
  fromEnum SIGHASH_ALL = 0x01
  fromEnum SIGHASH_NONE = 0x02
  fromEnum SIGHASH_SINGLE = 0x03
  fromEnum SIGHASH_FORKID = 0x40
  fromEnum SIGHASH_ANYONECANPAY = 0x80
  toEnum 0x01 = SIGHASH_ALL
  toEnum 0x02 = SIGHASH_NONE
  toEnum 0x03 = SIGHASH_SINGLE
  toEnum 0x40 = SIGHASH_FORKID
  toEnum 0x80 = SIGHASH_ANYONECANPAY
  toEnum _ = error "Not a valid sighash flag"
  succ flag
    | flag == maxBound = error "succ: SIGHASH_ANYONECANPAY is the last sighash flag"
    | otherwise = sigHashFlags !! (flagPosition flag + 1)
  pred flag
    | flag == minBound = error "pred: SIGHASH_ALL is the first sighash flag"
    | otherwise = sigHashFlags !! (flagPosition flag - 1)
  enumFrom flag = enumFromTo flag maxBound
  enumFromTo from to = map (sigHashFlags !!) [flagPosition from .. flagPosition to]
  enumFromThen from next
    | next >= from = enumFromThenTo from next maxBound
    | otherwise = enumFromThenTo from next minBound
  enumFromThenTo from next to =
    map (sigHashFlags !!) [flagPosition from, flagPosition next .. flagPosition to]

-- | The flags in the order of their constructors.
sigHashFlags :: [SigHashFlag]
sigHashFlags =
  [ SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_FORKID,
    SIGHASH_ANYONECANPAY
  ]

-- | The position of a flag in 'sigHashFlags'.
flagPosition :: SigHashFlag -> Int
flagPosition flag = length (takeWhile (/= flag) sigHashFlags)

-- | Data type representing the different ways a transaction can be signed.
-- When producing a signature, a hash of the transaction is used as the message
-- to be signed. The 'SigHash' parameter controls which parts of the
-- transaction are used or ignored to produce the transaction hash. The idea is
-- that if some part of a transaction is not used to produce the transaction
-- hash, then you can change that part of the transaction after producing a
-- signature without invalidating that signature.
--
-- If the 'SIGHASH_ANYONECANPAY' flag is set (true), then only the current input
-- is signed. Otherwise, all of the inputs of a transaction are signed. The
-- default value for 'SIGHASH_ANYONECANPAY' is unset (false).
newtype SigHash
  = SigHash Word32
  deriving (Eq, Ord, Enum, Show, Read, Generic)
  deriving newtype (Bits, Integral, Num, Real, Hashable, NFData)

instance FromJSON SigHash where
  parseJSON =
    withScientific "sighash" $
      maybe mzero (return . SigHash) . toBoundedInteger

instance ToJSON SigHash where
  toJSON = Number . fromIntegral
  toEncoding (SigHash n) = toEncoding n

-- | SIGHASH_DEFAULT of BIP 341: the hash type 0, which a Taproot key path
-- signature leaves out and which signs like 'sigHashAll'. It is only valid
-- in Taproot signatures.
sigHashDefault :: SigHash
sigHashDefault = 0

-- | SIGHASH_NONE as a byte.
sigHashNone :: SigHash
sigHashNone = fromIntegral $ fromEnum SIGHASH_NONE

-- | SIGHASH_ALL as a byte.
sigHashAll :: SigHash
sigHashAll = fromIntegral $ fromEnum SIGHASH_ALL

-- | SIGHASH_SINGLE as a byte.
sigHashSingle :: SigHash
sigHashSingle = fromIntegral $ fromEnum SIGHASH_SINGLE

-- | SIGHASH_FORKID as a byte.
sigHashForkId :: SigHash
sigHashForkId = fromIntegral $ fromEnum SIGHASH_FORKID

-- | SIGHASH_ANYONECANPAY as a byte.
sigHashAnyoneCanPay :: SigHash
sigHashAnyoneCanPay = fromIntegral $ fromEnum SIGHASH_ANYONECANPAY

-- | Set SIGHASH_FORKID flag.
setForkIdFlag :: SigHash -> SigHash
setForkIdFlag = (.|. sigHashForkId)

-- | Set SIGHASH_ANYONECANPAY flag.
setAnyoneCanPay :: SigHash -> SigHash
setAnyoneCanPay = (.|. sigHashAnyoneCanPay)

-- | Is the SIGHASH_FORKID flag set?
hasForkIdFlag :: SigHash -> Bool
hasForkIdFlag = (/= 0) . (.&. sigHashForkId)

-- | Is the SIGHASH_ANYONECANPAY flag set?
anyoneCanPay :: SigHash -> Bool
anyoneCanPay = (/= 0) . (.&. sigHashAnyoneCanPay)

-- | Returns 'True' if the 'SigHash' has the value 'SIGHASH_ALL'.
isSigHashAll :: SigHash -> Bool
isSigHashAll = (== sigHashAll) . (.&. 0x1f)

-- | Returns 'True' if the 'SigHash' has the value 'SIGHASH_NONE'.
isSigHashNone :: SigHash -> Bool
isSigHashNone = (== sigHashNone) . (.&. 0x1f)

-- | Returns 'True' if the 'SigHash' has the value 'SIGHASH_SINGLE'.
isSigHashSingle :: SigHash -> Bool
isSigHashSingle = (== sigHashSingle) . (.&. 0x1f)

-- | Is the hash type byte one that no node accepts in a signature? This is
-- the test of @IsDefinedHashtypeSignature@ in Bitcoin Core, which the
-- @STRICTENC@ flag enforces: after masking the 'SIGHASH_ANYONECANPAY' and
-- 'SIGHASH_FORKID' bits, the byte must be 'SIGHASH_ALL', 'SIGHASH_NONE' or
-- 'SIGHASH_SINGLE'. Whether the 'SIGHASH_FORKID' bit itself is allowed
-- depends on the network, see 'decodeTxSig'. Only the low byte is looked at,
-- since a fork id may sit in the upper bytes.
isSigHashUnknown :: SigHash -> Bool
isSigHashUnknown sh = base < sigHashAll || base > sigHashSingle
  where
    base = (sh .&. 0xff) .&. complement (sigHashAnyoneCanPay .|. sigHashForkId)

-- | Add a fork id to a 'SigHash'.
sigHashAddForkId :: SigHash -> Word32 -> SigHash
sigHashAddForkId sh w = (fromIntegral w `shiftL` 8) .|. (sh .&. 0x000000ff)

-- | Add fork id of a particular network to a 'SigHash'.
sigHashAddNetworkId :: Network -> SigHash -> SigHash
sigHashAddNetworkId net =
  (`sigHashAddForkId` fromMaybe 0 net.sigHashForkId)

-- | Get fork id from 'SigHash'.
sigHashGetForkId :: SigHash -> Word32
sigHashGetForkId (SigHash n) = fromIntegral $ n `shiftR` 8

-- | Computes the hash that will be used for signing a transaction input that
-- is not a SegWit input.
--
-- The script is the @scriptCode@ of the input: the output script being spent,
-- or the redeem script for a pay-to-script-hash output. If that script
-- contains 'OP_CODESEPARATOR', the caller must pass the part after the last
-- 'OP_CODESEPARATOR' executed before the signature check, as consensus
-- defines it. Any 'OP_CODESEPARATOR' left in that part is removed here, as
-- @SerializeScriptCode@ does in Bitcoin Core.
--
-- Bitcoin Core makes a second change to the script before it hashes a legacy
-- input: @FindAndDelete@ removes every push of the signature being checked.
-- This function does not do that. The standard output scripts never hold a
-- signature, so nothing is lost for them. A caller that verifies another
-- legacy script must remove the pushes of the signature from the script
-- first.
--
-- The hash type is written as four bytes, as Bitcoin Core writes the
-- @nHashType@ it is given. A signature only carries the low byte, so a
-- 'SigHash' above 0xff gives a digest that no signature can match.
--
-- On a network with a fork id, such as Bitcoin Cash, every signature must use
-- the fork id digest of 'txSigHashForkId', so the 'SigHash' must carry the
-- 'SIGHASH_FORKID' flag and the digest is computed by that function. A
-- 'SigHash' without the flag fails, instead of producing a digest no node
-- accepts.
--
-- Fails when the input index is not an index of the transaction.
txSigHash ::
  Network ->
  -- | transaction to sign
  Tx ->
  -- | script from output being spent
  Script ->
  -- | value of output being spent
  Word64 ->
  -- | index of input being signed
  Int ->
  -- | what to sign
  SigHash ->
  -- | hash to be signed
  Either String Hash256
txSigHash net tx out v i sh
  | i < 0 || i >= length tx.inputs =
      Left "txSigHash: input index out of range"
  | isJust net.sigHashForkId && not (hasForkIdFlag sh) =
      Left "txSigHash: SIGHASH_FORKID is required on this network"
  | isJust net.sigHashForkId =
      txSigHashForkId net tx out v i sh
  | otherwise = do
      let newIn = buildInputs tx.inputs fout i sh
      -- When SigSingle and input index > outputs, then sign integer 1
      return . fromMaybe one $ do
        newOut <- buildOutputs tx.outputs i sh
        let newTx = Tx tx.version newIn newOut [] tx.locktime
        return . doubleSHA256 . runPutS $ do
          serialize newTx
          putWord32le $ fromIntegral sh
  where
    fout = Script $ filter (/= OP_CODESEPARATOR) out.ops
    one = "0100000000000000000000000000000000000000000000000000000000000000"

-- | Build transaction inputs for computing sighashes. With
-- 'SIGHASH_ANYONECANPAY' only the signed input remains. With 'SIGHASH_NONE'
-- or 'SIGHASH_SINGLE' the sequence numbers of the other inputs are zero. Any
-- other base type, including the undefined ones, behaves as 'SIGHASH_ALL',
-- as in Bitcoin Core.
buildInputs :: [TxIn] -> Script -> Int -> SigHash -> [TxIn]
buildInputs txins out i sh
  | anyoneCanPay sh = [serialOut (txins !! i)]
  | isSigHashNone sh || isSigHashSingle sh = zipWith noSeq single [0 ..]
  | otherwise = single
  where
    serialOut TxIn {..} = TxIn {script = runPutS $ serialize out, ..}
    emptyIn TxIn {..} = TxIn {script = B.empty, ..}
    emptyIns = map emptyIn txins
    single = updateIndex i emptyIns serialOut
    noSeq TxIn {..} j = TxIn {sequence = if i == j then sequence else 0, ..}

-- | Build transaction outputs for computing sighashes. 'SIGHASH_NONE' signs
-- no output. 'SIGHASH_SINGLE' signs the output at the input index, with the
-- outputs before it blanked, and gives 'Nothing' when there is no such
-- output. Any other base type signs every output.
buildOutputs :: [TxOut] -> Int -> SigHash -> Maybe [TxOut]
buildOutputs txos i sh
  | isSigHashNone sh = return []
  | not (isSigHashSingle sh) = return txos
  | i >= length txos = Nothing
  | otherwise = return $ buffer ++ [txos !! i]
  where
    buffer = replicate i $ TxOut maxBound B.empty

-- | Compute the digest of BIP 143, used for SegWit version 0 inputs on
-- Bitcoin and, with the fork id of the network, for every input on Bitcoin
-- Cash.
--
-- The script is the @scriptCode@ of BIP 143: the pay-to-public-key-hash
-- script of the key for a pay-to-witness-public-key-hash input, or the
-- witness script for a pay-to-witness-script-hash input. If it contains
-- 'OP_CODESEPARATOR', the caller must pass the part after the last one
-- executed before the signature check. Unlike 'txSigHash', nothing is removed
-- from that part, as BIP 143 specifies.
--
-- The last field of the digest is the hash type as four bytes. On a network
-- without a fork id it is the 'SigHash' as given, which is what
-- @SignatureHash@ of Bitcoin Core writes. A signature only carries the low
-- byte, so a 'SigHash' above 0xff gives a digest that no signature can
-- match. On a network with a fork id it is the low byte with the fork id of
-- the network in the three bytes above it.
--
-- What is not supported on Bitcoin Cash, where Bitcoin Cash Node is the
-- reference:
--
-- * @SIGHASH_UTXOS@ (0x20), which adds a hash of all the coins spent to the
--   digest. 'isSigHashUnknown' treats the bit as undefined, so 'decodeTxSig'
--   refuses such a signature.
--
-- * Coins that hold tokens. Their digest also covers the token data, and
--   their output script starts with the prefix byte 0xef, which
--   'Haskoin.Script.Standard.decodeOutput' does not read. A signature made
--   here for such a coin is not valid.
--
-- * Schnorr signatures, see 'TxSignature'.
--
-- Fails when the input index is not an index of the transaction.
txSigHashForkId ::
  Network ->
  -- | transaction to sign
  Tx ->
  -- | script from output being spent
  Script ->
  -- | value of output being spent
  Word64 ->
  -- | index of input being signed
  Int ->
  -- | what to sign
  SigHash ->
  -- | hash to be signed
  Either String Hash256
txSigHashForkId net tx out v i sh
  | i < 0 || i >= length tx.inputs =
      Left "txSigHashForkId: input index out of range"
  | otherwise = Right . doubleSHA256 . runPutS $ do
    putWord32le tx.version
    serialize hashPrevouts
    serialize hashSequence
    serialize (tx.inputs !! i).outpoint
    putScript out
    putWord64le v
    putWord32le (tx.inputs !! i).sequence
    serialize hashOutputs
    putWord32le tx.locktime
    putWord32le $ fromIntegral hashType
  where
    hashType = case net.sigHashForkId of
      Just forkId -> sigHashAddForkId sh forkId
      Nothing -> sh
    hashPrevouts
      | not (anyoneCanPay sh) =
          doubleSHA256 . runPutS $ mapM_ (serialize . (.outpoint)) tx.inputs
      | otherwise = zeros
    hashSequence
      | not (anyoneCanPay sh || isSigHashSingle sh || isSigHashNone sh) =
          doubleSHA256 . runPutS $ mapM_ (putWord32le . (.sequence)) tx.inputs
      | otherwise = zeros
    hashOutputs
      | not (isSigHashSingle sh || isSigHashNone sh) =
          doubleSHA256 . runPutS $ mapM_ serialize tx.outputs
      | isSigHashSingle sh && i < length tx.outputs =
          doubleSHA256 . runPutS $ serialize $ tx.outputs !! i
      | otherwise = zeros
    putScript s = do
      let encodedScript = runPutS $ serialize s
      putVarInt $ B.length encodedScript
      putByteString encodedScript
    zeros :: Hash256
    zeros = "0000000000000000000000000000000000000000000000000000000000000000"

-- | Data type representing a signature together with a 'SigHash'. The 'SigHash'
-- is serialized as one byte at the end of an ECDSA 'Sig'. All signatures in
-- transaction inputs are of type 'TxSignature'.
--
-- This is the form of a signature that nodes relay. The binary and JSON
-- forms, and 'decodeTxSig', apply the three signature rules of the standard
-- script flags of Bitcoin Core, and one rule of the network:
--
-- * @DERSIG@: strict DER, as BIP 66 defines it, with r and s between 1 and
--   the curve order minus 1.
--
-- * @LOW_S@: s is at most half the curve order.
--
-- * @STRICTENC@: the hash type byte is defined ('isSigHashUnknown').
--
-- * The 'SIGHASH_FORKID' flag is set exactly on the networks that have a
--   fork id.
--
-- Nothing may follow the hash type byte.
--
-- Only the first rule is a consensus rule, and only since BIP 66. A block
-- can therefore hold signatures that do not decode: one with a high S, one
-- with an undefined hash type byte, and, before BIP 66 activated, one in a
-- looser DER form. An input with such a signature fails
-- 'Haskoin.Script.Standard.decodeInput', and has no
-- 'Haskoin.Address.inputAddress'. This type is not a parser for the whole
-- chain history. 'Haskoin.Crypto.Signature.decodeStrictSig' reads a
-- signature under BIP 66 alone.
--
-- On Bitcoin Cash, a signature of 64 bytes followed by the hash type byte is
-- a Schnorr signature, which Bitcoin Cash Node accepts in @OP_CHECKSIG@.
-- This type only holds ECDSA signatures, so those do not decode either.
data TxSignature
  = TxSignature
      { sig :: !Sig,
        hash :: !SigHash
      }
  | TxSignatureEmpty
  deriving (Eq, Show, Read, Generic, NFData)

instance Marshal (Network, Ctx) TxSignature where
  marshalPut (net, ctx) TxSignatureEmpty = return ()
  marshalPut (net, ctx) (TxSignature sig (SigHash n)) = do
    marshalPut ctx sig
    putWord8 (fromIntegral n)

  marshalGet (net, ctx) =
    bool decode empty =<< isEmpty
    where
      empty = return TxSignatureEmpty
      decode = do
        sig <- marshalGet ctx
        unless (isCanonicalHalfOrder ctx sig) $
          fail "Non-canonical signature: S value is unnecessarily high"
        sh <- fromIntegral <$> getWord8
        when (isSigHashUnknown sh) $
          fail "Non-canonical signature: unknown hashtype byte"
        when (isNothing net.sigHashForkId && hasForkIdFlag sh) $
          fail "Non-canonical signature: invalid network for forkId"
        when (isJust net.sigHashForkId && not (hasForkIdFlag sh)) $
          fail "Non-canonical signature: SIGHASH_FORKID is required on this network"
        return $ TxSignature sig sh

instance MarshalJSON (Network, Ctx) TxSignature where
  marshalValue (net, ctx) = String . encodeHex . encodeTxSig net ctx
  marshalEncoding s = hexEncoding . runPutL . marshalPut s
  unmarshalValue (net, ctx) =
    withText "TxSignature" $ \t ->
      case decodeHex t of
        Nothing -> fail "Cannot decode hex signature"
        Just b -> case decodeTxSig net ctx b of
          Left e -> fail e
          Right s -> return s

-- | Serialize a signature with its hash type byte. 'TxSignatureEmpty' is the
-- empty string.
encodeTxSig :: Network -> Ctx -> TxSignature -> ByteString
encodeTxSig net ctx = runPutS . marshalPut (net, ctx)

-- | Parse a signature with its hash type byte, under the rules listed at
-- 'TxSignature': strict DER, a low S, a defined hash type, and the fork id
-- flag that the network asks for. The empty string is 'TxSignatureEmpty'. A
-- signature that is valid by consensus alone does not decode.
decodeTxSig :: Network -> Ctx -> ByteString -> Either String TxSignature
decodeTxSig net ctx =
  runGetS $ do
    sig <- marshalGet (net, ctx)
    e <- isEmpty
    unless e $
      fail "Non-canonical signature: multiple hashtype bytes"
    return sig
