{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedRecordDot #-}

-- |
-- Module      : Haskoin.Test.Script
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
module Haskoin.Util.Arbitrary.Script where

import Crypto.Secp256k1
import Data.ByteString qualified as B
import Data.Maybe
import Data.Word
import Haskoin.Address
import Haskoin.Crypto.Keys.Common
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction.Common
import Haskoin.Util
import Haskoin.Util.Arbitrary.Address
import Haskoin.Util.Arbitrary.Crypto
import Haskoin.Util.Arbitrary.Keys
import Haskoin.Util.Arbitrary.Util
import Test.QuickCheck

-- | Arbitrary 'Script' with random script ops.
arbitraryScript :: Gen Script
arbitraryScript = Script <$> listOf arbitraryScriptOp

-- | Arbitrary push of random data. Most pushes are minimal, see
-- 'opPushData'. Some use a longer 'PushDataType' than the data needs, and the
-- lengths reach every 'PushDataType', so that every encoding is exercised.
arbitraryPushOp :: Gen ScriptOp
arbitraryPushOp = do
  len <- frequency [(6, choose (0, 75)), (2, choose (76, 255)), (1, choose (256, 300))]
  bs <- arbitraryBSn len
  let -- An empty payload with OPCODE is the byte of OP_0, so it is not kept.
      types =
        [OPCODE | len >= 1, len <= 75]
          ++ [OPDATA1 | len <= 255]
          ++ [OPDATA2, OPDATA4]
  frequency
    [ (3, return $ opPushData bs),
      (1, OP_PUSHDATA bs <$> elements types)
    ]

-- | Arbitrary 'ScriptOp' (push operations have random data).
arbitraryScriptOp :: Gen ScriptOp
arbitraryScriptOp =
  oneof
    -- Pushing Data
    [ arbitraryPushOp,
      return OP_0,
      return OP_1NEGATE,
      return OP_RESERVED,
      return OP_1,
      return OP_2,
      return OP_3,
      return OP_4,
      return OP_5,
      return OP_6,
      return OP_7,
      return OP_8,
      return OP_9,
      return OP_10,
      return OP_11,
      return OP_12,
      return OP_13,
      return OP_14,
      return OP_15,
      return OP_16,
      -- Flow control
      return OP_NOP,
      return OP_VER,
      return OP_IF,
      return OP_NOTIF,
      return OP_VERIF,
      return OP_VERNOTIF,
      return OP_ELSE,
      return OP_ENDIF,
      return OP_VERIFY,
      return OP_RETURN,
      -- Stack operations
      return OP_TOALTSTACK,
      return OP_FROMALTSTACK,
      return OP_IFDUP,
      return OP_DEPTH,
      return OP_DROP,
      return OP_DUP,
      return OP_NIP,
      return OP_OVER,
      return OP_PICK,
      return OP_ROLL,
      return OP_ROT,
      return OP_SWAP,
      return OP_TUCK,
      return OP_2DROP,
      return OP_2DUP,
      return OP_3DUP,
      return OP_2OVER,
      return OP_2ROT,
      return OP_2SWAP,
      -- Splice
      return OP_CAT,
      return OP_SUBSTR,
      return OP_LEFT,
      return OP_RIGHT,
      return OP_SIZE,
      -- Bitwise logic
      return OP_INVERT,
      return OP_AND,
      return OP_OR,
      return OP_XOR,
      return OP_EQUAL,
      return OP_EQUALVERIFY,
      return OP_RESERVED1,
      return OP_RESERVED2,
      -- Arithmetic
      return OP_1ADD,
      return OP_1SUB,
      return OP_2MUL,
      return OP_2DIV,
      return OP_NEGATE,
      return OP_ABS,
      return OP_NOT,
      return OP_0NOTEQUAL,
      return OP_ADD,
      return OP_SUB,
      return OP_MUL,
      return OP_DIV,
      return OP_MOD,
      return OP_LSHIFT,
      return OP_RSHIFT,
      return OP_BOOLAND,
      return OP_BOOLOR,
      return OP_NUMEQUAL,
      return OP_NUMEQUALVERIFY,
      return OP_NUMNOTEQUAL,
      return OP_LESSTHAN,
      return OP_GREATERTHAN,
      return OP_LESSTHANOREQUAL,
      return OP_GREATERTHANOREQUAL,
      return OP_MIN,
      return OP_MAX,
      return OP_WITHIN,
      -- Crypto
      return OP_RIPEMD160,
      return OP_SHA1,
      return OP_SHA256,
      return OP_HASH160,
      return OP_HASH256,
      return OP_CODESEPARATOR,
      return OP_CHECKSIG,
      return OP_CHECKSIGVERIFY,
      return OP_CHECKMULTISIG,
      return OP_CHECKMULTISIGVERIFY,
      -- Expansion
      return OP_NOP1,
      return OP_CHECKLOCKTIMEVERIFY,
      return OP_CHECKSEQUENCEVERIFY,
      return OP_NOP4,
      return OP_NOP5,
      return OP_NOP6,
      return OP_NOP7,
      return OP_NOP8,
      return OP_NOP9,
      return OP_NOP10,
      -- Bitcoin Cash Nov 2018 hard fork
      return OP_CHECKDATASIG,
      return OP_CHECKDATASIGVERIFY,
      -- Bitcoin Cash May 2020 hard fork
      return OP_REVERSEBYTES,
      -- Other
      return OP_PUBKEYHASH,
      return OP_PUBKEY,
      return $ OP_INVALIDOPCODE 0xff
    ]

-- | Arbtirary 'ScriptOp' with a value in @[OP_1 .. OP_16]@.
arbitraryIntScriptOp :: Gen ScriptOp
arbitraryIntScriptOp =
  elements
    [ OP_1,
      OP_2,
      OP_3,
      OP_4,
      OP_5,
      OP_6,
      OP_7,
      OP_8,
      OP_9,
      OP_10,
      OP_11,
      OP_12,
      OP_13,
      OP_14,
      OP_15,
      OP_16
    ]

-- | Arbitrary 'PushDataType'.
arbitraryPushDataType :: Gen PushDataType
arbitraryPushDataType = elements [OPCODE, OPDATA1, OPDATA2, OPDATA4]

-- | Arbitrary 'SigHash' (including invalid/unknown sighash codes).
arbitrarySigHash :: Gen SigHash
arbitrarySigHash = fromIntegral <$> (arbitrary :: Gen Word32)

-- | Arbitrary valid 'SigHash'. On a network with a fork id, the
-- 'SIGHASH_FORKID' flag is always set, since every signature there must
-- carry it.
arbitraryValidSigHash :: Network -> Gen SigHash
arbitraryValidSigHash net = do
  sh <- elements [sigHashAll, sigHashNone, sigHashSingle]
  let f1
        | isJust net.sigHashForkId = setForkIdFlag
        | otherwise = id
  f2 <- elements [id, setAnyoneCanPay]
  return $ f1 $ f2 sh

arbitrarySigHashFlag :: Gen SigHashFlag
arbitrarySigHashFlag =
  elements
    [ SIGHASH_ALL,
      SIGHASH_NONE,
      SIGHASH_SINGLE,
      SIGHASH_FORKID,
      SIGHASH_ANYONECANPAY
    ]

-- | Arbitrary message hash, private key and corresponding 'TxSignature'. The
-- signature is generated deterministically using a random message and a random
-- private key.
arbitraryTxSignature :: Network -> Gen (TxHash, SecKey, TxSignature)
arbitraryTxSignature net = do
  (m, key, sig) <- arbitrarySignature
  sh <- (fromIntegral <$> (arbitrary :: Gen Word8)) `suchThat` filterBad
  let txsig = TxSignature sig sh
  return (TxHash m, key, txsig)
  where
    filterBad sh =
      not $
        isSigHashUnknown sh
          || isNothing net.sigHashForkId && hasForkIdFlag sh
          || isJust net.sigHashForkId && not (hasForkIdFlag sh)

-- | Arbitrary transaction signature that could also be empty.
arbitraryTxSignatureEmpty :: Network -> Gen TxSignature
arbitraryTxSignatureEmpty net =
  frequency
    [ (1, return TxSignatureEmpty),
      (10, lst3 <$> arbitraryTxSignature net)
    ]

-- | Arbitrary m of n parameters, with n up to 'maxMultisigKeys'. Such a
-- multisig fits a bare output or a pay-to-witness-script-hash output. For a
-- pay-to-script-hash output use 'arbitraryP2SHMSParam'.
arbitraryMSParam :: Gen (Int, Int)
arbitraryMSParam = do
  m <- choose (1, maxMultisigKeys)
  n <- choose (m, maxMultisigKeys)
  return (m, n)

-- | The most keys of a pay-to-script-hash multisig whatever the form of its
-- keys. A redeem script is at most 520 bytes, and an uncompressed key takes
-- 66 of them with its push: 3 + 7 × 66 = 465, and 8 keys would be 531.
maxP2SHMultisigKeys :: Int
maxP2SHMultisigKeys = 7

-- | The most compressed keys of a pay-to-script-hash multisig. A compressed
-- key takes 34 bytes with its push: 3 + 15 × 34 = 513, and 16 keys would be
-- 547.
maxP2SHMultisigKeysC :: Int
maxP2SHMultisigKeysC = 15

-- | Arbitrary m of n parameters of a multisig whose script fits a
-- pay-to-script-hash redeem script with keys of any form: n up to
-- 'maxP2SHMultisigKeys'.
arbitraryP2SHMSParam :: Gen (Int, Int)
arbitraryP2SHMSParam = do
  m <- choose (1, maxP2SHMultisigKeys)
  n <- choose (m, maxP2SHMultisigKeys)
  return (m, n)

-- | Arbitrary m of n parameters of a multisig of compressed keys whose
-- script fits a pay-to-script-hash redeem script: n up to
-- 'maxP2SHMultisigKeysC'.
arbitraryP2SHMSParamC :: Gen (Int, Int)
arbitraryP2SHMSParamC = do
  m <- choose (1, maxP2SHMultisigKeysC)
  n <- choose (m, maxP2SHMultisigKeysC)
  return (m, n)

-- | Arbitrary 'ScriptOutput' (Can by any valid type).
arbitraryScriptOutput :: Network -> Gen ScriptOutput
arbitraryScriptOutput net =
  oneof $
    [ arbitraryPKOutput,
      arbitraryPKHashOutput,
      arbitraryMSOutput,
      arbitrarySHOutput,
      arbitraryDCOutput
    ]
      ++ ( if net.segWit
             then
               [ arbitraryWPKHashOutput,
                 arbitraryWSHOutput,
                 arbitraryWitOutput
               ]
             else []
         )
      -- Pay-to-script-hash with a 256-bit hash exists on the networks that
      -- have CashAddr.
      ++ [arbitrarySH32Output | isJust net.cashAddrPrefix]

-- | Arbitrary 'ScriptOutput' of type 'PayPK', 'PayPKHash' or 'PayMS'
-- (Not 'PayScriptHash', 'DataCarrier', or SegWit)
arbitrarySimpleOutput :: Gen ScriptOutput
arbitrarySimpleOutput =
  oneof
    [ arbitraryPKOutput,
      arbitraryPKHashOutput,
      arbitraryMSOutput
    ]

-- | Arbitrary 'ScriptOutput' of type 'PayPK'
arbitraryPKOutput :: Gen ScriptOutput
arbitraryPKOutput = PayPK . snd <$> arbitraryKeyPair

-- | Arbitrary 'ScriptOutput' of type 'PayPKHash'
arbitraryPKHashOutput :: Gen ScriptOutput
arbitraryPKHashOutput = PayPKHash <$> arbitraryHash160

-- | Arbitrary 'PayWitnessPKHash' output.
arbitraryWPKHashOutput :: Gen ScriptOutput
arbitraryWPKHashOutput = PayWitnessPKHash <$> arbitraryHash160

-- | Arbitrary 'PayWitnessScriptHash' output.
arbitraryWSHOutput :: Gen ScriptOutput
arbitraryWSHOutput = PayWitnessScriptHash <$> arbitraryHash256

arbitraryWitOutput :: Gen ScriptOutput
arbitraryWitOutput = do
  ver <- choose (1, 16)
  len <- choose (2, 40)
  ws <- vectorOf len arbitrary
  let bs = B.pack ws
  return $ PayWitness ver bs

-- | Arbitrary 'ScriptOutput' of type 'PayMS'.
arbitraryMSOutput :: Gen ScriptOutput
arbitraryMSOutput = do
  (m, n) <- arbitraryMSParam
  keys <- map snd <$> vectorOf n arbitraryKeyPair
  return $ PayMulSig keys m

-- | Arbitrary 'ScriptOutput' of type 'PayMS', only using compressed keys.
arbitraryMSOutputC :: Gen ScriptOutput
arbitraryMSOutputC = do
  (m, n) <- arbitraryMSParam
  keys <-
    map snd
      <$> vectorOf n (arbitraryKeyPair `suchThat` ((.compress) . snd))
  return $ PayMulSig keys m

-- | Arbitrary multisig that fits a pay-to-script-hash redeem script: up to
-- 7 keys of any form, or up to 15 compressed keys.
arbitraryP2SHMSOutput :: Gen ScriptOutput
arbitraryP2SHMSOutput =
  oneof
    [ do
        (m, n) <- arbitraryP2SHMSParam
        keys <- map snd <$> vectorOf n arbitraryKeyPair
        return $ PayMulSig keys m,
      arbitraryP2SHMSOutputC
    ]

-- | Arbitrary multisig of compressed keys that fits a pay-to-script-hash
-- redeem script: up to 15 keys.
arbitraryP2SHMSOutputC :: Gen ScriptOutput
arbitraryP2SHMSOutputC = do
  (m, n) <- arbitraryP2SHMSParamC
  keys <-
    map snd
      <$> vectorOf n (arbitraryKeyPair `suchThat` ((.compress) . snd))
  return $ PayMulSig keys m

-- | Arbitrary 'ScriptOutput' of type 'PayScript32Hash'.
arbitrarySH32Output :: Gen ScriptOutput
arbitrarySH32Output = PayScript32Hash <$> arbitraryHash256

-- | Arbitrary 'ScriptOutput' of type 'PayScriptHash'.
arbitrarySHOutput :: Gen ScriptOutput
arbitrarySHOutput = do
  address <- arbitraryScriptAddress
  case addressHash160 address of
    Just h -> return $ PayScriptHash h
    Nothing -> error "Could not get Hash160 from address"

-- | Arbitrary 'ScriptOutput' of type 'DataCarrier', with any number of
-- pushes, including none and empty ones.
arbitraryDCOutput :: Gen ScriptOutput
arbitraryDCOutput = DataCarrier <$> listOf arbitraryBS

-- | Arbitrary 'ScriptInput'. A nested witness input is only drawn on a
-- network that has SegWit.
arbitraryScriptInput :: Network -> Gen ScriptInput
arbitraryScriptInput net =
  oneof $
    [ arbitraryPKInput net,
      arbitraryPKHashInput net,
      arbitraryMSInput net,
      arbitrarySHInput net
    ]
      ++ [arbitraryNestedWitnessInput | net.segWit]

-- | Arbitrary 'ScriptInput' of type 'NestedWitnessInput', wrapping a
-- 'PayWitnessPKHash' or a 'PayWitnessScriptHash'.
arbitraryNestedWitnessInput :: Gen ScriptInput
arbitraryNestedWitnessInput =
  NestedWitnessInput <$> oneof [arbitraryWPKHashOutput, arbitraryWSHOutput]

-- | Arbitrary 'ScriptInput' of type 'SpendPK', 'SpendPKHash' or 'SpendMulSig'
-- (not 'ScriptHashInput')
arbitrarySimpleInput :: Network -> Gen ScriptInput
arbitrarySimpleInput net =
  oneof
    [ arbitraryPKInput net,
      arbitraryPKHashInput net,
      arbitraryMSInput net
    ]

-- | Arbitrary 'ScriptInput' of type 'SpendPK'.
arbitraryPKInput :: Network -> Gen ScriptInput
arbitraryPKInput net = RegularInput . SpendPK <$> arbitraryTxSignatureEmpty net

-- | Arbitrary 'ScriptInput' of type 'SpendPK'.
arbitraryPKHashInput :: Network -> Gen ScriptInput
arbitraryPKHashInput net = do
  sig <- arbitraryTxSignatureEmpty net
  key <- snd <$> arbitraryKeyPair
  return $ RegularInput $ SpendPKHash sig key

-- | Like 'arbitraryPKHashInput' without empty signatures.
arbitraryPKHashInputFull :: Network -> Gen ScriptInput
arbitraryPKHashInputFull net = do
  sig <- lst3 <$> arbitraryTxSignature net
  key <- snd <$> arbitraryKeyPair
  return $ RegularInput $ SpendPKHash sig key

-- | Like above but only compressed.
arbitraryPKHashInputFullC :: Network -> Gen ScriptInput
arbitraryPKHashInputFullC net = do
  sig <- lst3 <$> arbitraryTxSignature net
  key <- fmap snd $ arbitraryKeyPair `suchThat` ((.compress) . snd)
  return $ RegularInput $ SpendPKHash sig key

-- | Arbitrary 'ScriptInput' of type 'SpendMulSig'.
arbitraryMSInput :: Network -> Gen ScriptInput
arbitraryMSInput net = do
  m <- fst <$> arbitraryMSParam
  sigs <- vectorOf m (arbitraryTxSignatureEmpty net)
  return $ RegularInput $ SpendMulSig sigs

-- | Arbitrary 'ScriptInput' of type 'ScriptHashInput', whose input fits its
-- redeem script: a 'SpendPK' for a 'PayPK', a 'SpendPKHash' for a
-- 'PayPKHash', a 'SpendMulSig' for a 'PayMulSig'.
arbitrarySHInput :: Network -> Gen ScriptInput
arbitrarySHInput net =
  oneof
    [ do
        sig <- arbitraryTxSignatureEmpty net
        ScriptHashInput (SpendPK sig) <$> arbitraryPKOutput,
      do
        sig <- arbitraryTxSignatureEmpty net
        key <- snd <$> arbitraryKeyPair
        ScriptHashInput (SpendPKHash sig key) <$> arbitraryPKHashOutput,
      arbitraryMulSigSHInput net
    ]

-- | Arbitrary 'ScriptInput' of type 'ScriptHashInput' containing a
-- 'RedeemScript' of type 'PayMulSig' and an input of type 'SpendMulSig'. The
-- redeem script is at most 520 bytes long, as a pay-to-script-hash redeem
-- script must be.
arbitraryMulSigSHInput :: Network -> Gen ScriptInput
arbitraryMulSigSHInput net =
  arbitraryP2SHMSOutput >>= \case
    rdm@(PayMulSig _ m) -> do
      sigs <- vectorOf m (arbitraryTxSignatureEmpty net)
      return $ ScriptHashInput (SpendMulSig sigs) rdm
    _ -> undefined

-- | Arbitrary 'ScriptInput' of type 'ScriptHashInput' containing a
-- 'RedeemScript' of type 'PayMulSig' and an input of type 'SpendMulSig'.
arbitraryMulSigSHInputC :: Network -> Gen ScriptInput
arbitraryMulSigSHInputC net =
  arbitraryP2SHMSOutputC >>= \case
    rdm@(PayMulSig _ m) -> do
      sigs <- vectorOf m (arbitraryTxSignatureEmpty net)
      return $ ScriptHashInput (SpendMulSig sigs) rdm
    _ -> undefined

-- | Like 'arbitraryMulSigSHCInput' with no empty signatures.
arbitraryMulSigSHInputFull :: Network -> Gen ScriptInput
arbitraryMulSigSHInputFull net =
  arbitraryP2SHMSOutput >>= \case
    rdm@(PayMulSig _ m) -> do
      sigs <- map lst3 <$> vectorOf m (arbitraryTxSignature net)
      return $ ScriptHashInput (SpendMulSig sigs) rdm
    _ -> undefined

-- | Like 'arbitraryMulSigSHCInput' with no empty signatures.
arbitraryMulSigSHInputFullC :: Network -> Gen ScriptInput
arbitraryMulSigSHInputFullC net =
  arbitraryP2SHMSOutputC >>= \case
    rdm@(PayMulSig _ m) -> do
      sigs <- map lst3 <$> vectorOf m (arbitraryTxSignature net)
      return $ ScriptHashInput (SpendMulSig sigs) rdm
    _ -> undefined
