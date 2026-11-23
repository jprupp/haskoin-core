{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.ScriptSpec (spec) where

import Control.Exception (evaluate)
import Control.Monad
import Crypto.Secp256k1 (Sig)
import Data.Aeson as A
import Data.Aeson.Types as A (parseMaybe)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Default (def)
import Data.Either
import Data.List
import Data.Maybe
import Data.String
import Data.String.Conversions (cs)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Word
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.HUnit as HUnit
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Text.Read

identityTests :: IdentityTests
identityTests =
  def
    { readTests =
        [ ReadBox arbitrarySigHash,
          ReadBox arbitrarySigHashFlag,
          ReadBox arbitraryScript,
          ReadBox arbitraryPushDataType,
          ReadBox arbitraryScriptOp,
          ReadBox (arbitraryScriptOutput =<< arbitraryNetwork),
          ReadBox (arbitraryScriptInput =<< arbitraryNetwork)
        ],
      jsonTests =
        [ JsonBox arbitraryScript,
          JsonBox arbitraryOutPoint,
          JsonBox arbitrarySigHash,
          JsonBox (arbitraryScriptOutput =<< arbitraryNetwork),
          JsonBox (fst <$> (arbitrarySigInput =<< arbitraryNetwork))
        ],
      marshalJsonTests =
        [ MarshalJsonBox $ do
            n <- arbitraryNetwork
            (_, _, ts) <- arbitraryTxSignature n
            return (n, ts)
        ],
      serialTests =
        [ SerialBox arbitraryScriptOp,
          SerialBox arbitraryScript,
          SerialBox (arbitraryScriptOutput =<< arbitraryNetwork)
        ],
      marshalTests =
        [ MarshalBox $ do
            n <- arbitraryNetwork
            (_, _, ts) <- arbitraryTxSignature n
            return (n, ts),
          MarshalBox $ do
            n <- arbitraryNetwork
            i <- arbitraryScriptInput n
            return (n, i)
        ]
    }

spec :: Spec
spec = do
  testIdentity $ identityTests
  describe "opcodes" opcodeSpec
  describe "push operations" pushSpec
  describe "small integer opcodes" smallIntSpec
  describe "standard outputs" $ outputSpec
  describe "standard inputs" $ inputSpec
  describe "sighash types" sigHashTypeSpec
  describe "sighash digests" $ digestSpec
  describe "transaction signatures" $ txSignatureSpec
  describe "btc scripts" $ props btc
  describe "bch scripts" $ props bch
  describe "multi signatures" $
    zipWithM_ (curry mapMulSigVector) mulSigVectors [0 ..]
  describe "signature decoding" $
    zipWithM_ (curry (sigDecodeMap btc)) scriptSigSignatures [0 ..]
  describe "Script vectors" $
    it "Can encode script vectors" encodeScriptVector

{- Fixtures -}

hex :: Text -> ByteString
hex = fromJust . decodeHex

-- | The generator point of secp256k1 as a compressed public key. Its hash160
-- is 751e76e8199196d454941c45d1b3a323f1433bd6, the witness program of the
-- BIP 173 example address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.
gKeyHex :: Text
gKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

-- | The x and y coordinates of the same key. Its y is even, so its hybrid
-- form starts with 0x06.
gUncompressedXY :: Text
gUncompressedXY =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
  \483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

gKey :: PublicKey
gKey = either error id $ decodeSerial $ hex gKeyHex

gHash :: Hash160
gHash = "751e76e8199196d454941c45d1b3a323f1433bd6"

-- | The two keys of the first BIP 67 test vector, in the order the vector
-- lists them before sorting.
bip67KeyA, bip67KeyB :: Text
bip67KeyA = "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8"
bip67KeyB = "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f"

bip67Key :: Text -> PublicKey
bip67Key = either error id . decodeSerial . hex

-- | The 2-of-2 script of the first BIP 67 test vector, keys sorted: 71 bytes.
bip67ScriptHex :: Text
bip67ScriptHex = "5221" <> bip67KeyB <> "21" <> bip67KeyA <> "52ae"

-- | A strict DER signature from the input of transaction
-- 1983a69265920c24f89aac81942b1a59f7eb30821a8b3fb258f88882b6336053, without
-- its hash type byte. It is 70 bytes, so with the hash type byte a push of it
-- starts with 0x47.
sigDerHex :: Text
sigDerHex =
  "304402205ca6249f43538908151fe67b26d020306c0e59fa206cf9f3ccf641f33357119d\
  \02206c82f244d04ac0a48024fb9cc246b66e58598acf206139bdb7b75a2941a2b1e4"

sigDer :: Sig
sigDer = fromJust $ decodeStrictSig $ hex sigDerHex

-- | An ECDSA signature whose DER form is 64 bytes, without its hash type
-- byte: r and s take 0x1d = 29 bytes each. Bitcoin Core 32.1 put it in a
-- block on regtest, and Bitcoin Cash Node 29.2.0 refused it, in the
-- transactions of "Haskoin.Transaction.VerdictSpec".
shortDerHex :: Text
shortDerHex =
  "303e021d412389f0428046438bea9c0e2427db23ab0bce6fe36d851e0dc86b41ed\
  \021d20576521b06f9bc52aacf1dee9900a53c82c9e9ad11dae4edc0d6164db"

-- | The signature with SIGHASH_ALL, pushed in a script.
sigAllPushHex :: Text
sigAllPushHex = "47" <> sigDerHex <> "01"

-- | The unsigned transaction of the native P2WPKH example of BIP 143.
bip143Tx :: Tx
bip143Tx =
  "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f\
  \0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57\
  \b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85\
  \c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2\
  \f0167faa815988ac11000000"

-- | That transaction without its second output, so that its second input
-- has no output at its index.
bip143OneOutputTx :: Tx
bip143OneOutputTx =
  "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f\
  \0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57\
  \b90ec68a0100000000ffffffff01202cb206000000001976a9148280b37df378db99f66f85\
  \c95a783a76ac7a6d5988ac11000000"

-- | The scriptCode of the second input of that transaction: the P2PKH script
-- of the key that the P2WPKH output pays to.
bip143ScriptCode :: Script
bip143ScriptCode =
  either error id $
    runGetS deserialize $
      hex "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"

-- | The private key of that input in BIP 143. Its public key hashes to
-- 1d0f172a0ecb48aee1be1f2687d2963ae33f71a1.
bip143Key :: PrivateKey
bip143Key =
  wrapSecKey True . fromJust . secKey $
    hex "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"

-- | The value of the output that the second input spends: 6 BTC.
bip143Value :: Word64
bip143Value = 600000000

-- | The digest BIP 143 gives for that input with SIGHASH_ALL.
bip143Digest :: Hash256
bip143Digest = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"

-- | The fork id digest of Bitcoin Cash for the second input of that
-- transaction, for each of the six hash types. They were computed with
-- Python (hashlib) from the text of BIP 143.
bip143CashDigests :: [(SigHash, Hash256)]
bip143CashDigests =
  [ (0x41, "467f411d178762db122a6aced76370a1c8324355bf0796502bf82eeaeda86a35"),
    (0x42, "c0876aa9dfd131ac207be062e389741416a87a5d1b28e4857c178990454dd498"),
    (0x43, "abb61ba86e14313425d25846ed3a30904de1f081e013d80c385e165c2af1e020"),
    (0xc1, "a5890ce40dc95a89717ae6fa3c9d60bcf9372539058c7e9a0cd8ff7909723326"),
    (0xc2, "e58ebfd50f957a45c5f68439e55c6ae6054a3310ff2a116efa07d2bda2527bd3"),
    (0xc3, "4e303851715b6ee36582740f43cc288c969e88afc641f14e3e8e68d32c406c1b")
  ]

-- | Opcodes by their byte, from the script specification.
namedOpcodes :: [(Word8, ScriptOp)]
namedOpcodes =
  [ (0x4f, OP_1NEGATE),
    (0x50, OP_RESERVED),
    (0x51, OP_1),
    (0x60, OP_16),
    (0x61, OP_NOP),
    (0x62, OP_VER),
    (0x63, OP_IF),
    (0x64, OP_NOTIF),
    (0x67, OP_ELSE),
    (0x68, OP_ENDIF),
    (0x69, OP_VERIFY),
    (0x6a, OP_RETURN),
    (0x6b, OP_TOALTSTACK),
    (0x6c, OP_FROMALTSTACK),
    (0x73, OP_IFDUP),
    (0x74, OP_DEPTH),
    (0x75, OP_DROP),
    (0x76, OP_DUP),
    (0x7c, OP_SWAP),
    (0x7e, OP_CAT),
    (0x82, OP_SIZE),
    (0x87, OP_EQUAL),
    (0x88, OP_EQUALVERIFY),
    (0x8b, OP_1ADD),
    (0x93, OP_ADD),
    (0x94, OP_SUB),
    (0x9c, OP_NUMEQUAL),
    (0xa5, OP_WITHIN),
    (0xa6, OP_RIPEMD160),
    (0xa7, OP_SHA1),
    (0xa8, OP_SHA256),
    (0xa9, OP_HASH160),
    (0xaa, OP_HASH256),
    (0xab, OP_CODESEPARATOR),
    (0xac, OP_CHECKSIG),
    (0xad, OP_CHECKSIGVERIFY),
    (0xae, OP_CHECKMULTISIG),
    (0xaf, OP_CHECKMULTISIGVERIFY),
    (0xb0, OP_NOP1),
    (0xb1, OP_CHECKLOCKTIMEVERIFY),
    (0xb2, OP_CHECKSEQUENCEVERIFY),
    (0xb3, OP_NOP4),
    (0xb9, OP_NOP10),
    (0xba, OP_CHECKDATASIG),
    (0xbb, OP_CHECKDATASIGVERIFY),
    (0xbc, OP_REVERSEBYTES),
    (0xbd, OP_INVALIDOPCODE 0xbd),
    (0xc0, OP_INPUTINDEX),
    (0xc1, OP_ACTIVEBYTECODE),
    (0xc2, OP_TXVERSION),
    (0xc3, OP_TXINPUTCOUNT),
    (0xc4, OP_TXOUTPUTCOUNT),
    (0xc5, OP_TXLOCKTIME),
    (0xc6, OP_UTXOVALUE),
    (0xc7, OP_UTXOBYTECODE),
    (0xc8, OP_OUTPOINTTXHASH),
    (0xc9, OP_OUTPOINTINDEX),
    (0xca, OP_INPUTBYTECODE),
    (0xcb, OP_INPUTSEQUENCENUMBER),
    (0xcc, OP_OUTPUTVALUE),
    (0xcd, OP_OUTPUTBYTECODE),
    (0xce, OP_UTXOTOKENCATEGORY),
    (0xcf, OP_UTXOTOKENCOMMITMENT),
    (0xd0, OP_UTXOTOKENAMOUNT),
    (0xd1, OP_OUTPUTTOKENCATEGORY),
    (0xd2, OP_OUTPUTTOKENCOMMITMENT),
    (0xd3, OP_OUTPUTTOKENAMOUNT),
    (0xd4, OP_RESERVED3),
    (0xd5, OP_RESERVED4),
    (0xd6, OP_INVALIDOPCODE 0xd6),
    (0xfc, OP_INVALIDOPCODE 0xfc),
    (0xfd, OP_PUBKEYHASH),
    (0xfe, OP_PUBKEY),
    (0xff, OP_INVALIDOPCODE 0xff)
  ]

-- | The bytes that Bitcoin Cash names differently, with the constructor and
-- the pattern synonym of the Bitcoin Cash name.
bitcoinCashNames :: [(Word8, ScriptOp, ScriptOp)]
bitcoinCashNames =
  [ (0x65, OP_VERIF, OP_BEGIN),
    (0x66, OP_VERNOTIF, OP_UNTIL),
    (0x7f, OP_SUBSTR, OP_SPLIT),
    (0x80, OP_LEFT, OP_NUM2BIN),
    (0x81, OP_RIGHT, OP_BIN2NUM),
    (0x89, OP_RESERVED1, OP_DEFINE),
    (0x8a, OP_RESERVED2, OP_INVOKE),
    (0x8d, OP_2MUL, OP_LSHIFTNUM),
    (0x8e, OP_2DIV, OP_RSHIFTNUM),
    (0x98, OP_LSHIFT, OP_LSHIFTBIN),
    (0x99, OP_RSHIFT, OP_RSHIFTBIN),
    (0xba, OP_CHECKDATASIG, OP_CHECKSIGADD)
  ]

-- | Opcodes with the names that @GetOpName@ gives them in Bitcoin Core 32.1
-- and in Bitcoin Cash Node 29.2.0.
opNames :: [(ScriptOp, Text, Text)]
opNames =
  [ (OP_0, "0", "0"),
    (OP_1NEGATE, "-1", "-1"),
    (OP_16, "16", "16"),
    (OP_PUSHDATA "a" OPCODE, "OP_UNKNOWN", "OP_UNKNOWN"),
    (OP_PUSHDATA "a" OPDATA1, "OP_PUSHDATA1", "OP_PUSHDATA1"),
    (OP_PUSHDATA "a" OPDATA4, "OP_PUSHDATA4", "OP_PUSHDATA4"),
    (OP_DUP, "OP_DUP", "OP_DUP"),
    (OP_CHECKSIG, "OP_CHECKSIG", "OP_CHECKSIG"),
    (OP_VERIF, "OP_VERIF", "OP_BEGIN"),
    (OP_VERNOTIF, "OP_VERNOTIF", "OP_UNTIL"),
    (OP_SUBSTR, "OP_SUBSTR", "OP_SPLIT"),
    (OP_LEFT, "OP_LEFT", "OP_NUM2BIN"),
    (OP_RIGHT, "OP_RIGHT", "OP_BIN2NUM"),
    (OP_RESERVED1, "OP_RESERVED1", "OP_DEFINE"),
    (OP_RESERVED2, "OP_RESERVED2", "OP_INVOKE"),
    (OP_2MUL, "OP_2MUL", "OP_LSHIFTNUM"),
    (OP_2DIV, "OP_2DIV", "OP_RSHIFTNUM"),
    (OP_LSHIFT, "OP_LSHIFT", "OP_LSHIFTBIN"),
    (OP_RSHIFT, "OP_RSHIFT", "OP_RSHIFTBIN"),
    (OP_CHECKDATASIG, "OP_CHECKSIGADD", "OP_CHECKDATASIG"),
    (OP_CHECKDATASIGVERIFY, "OP_UNKNOWN", "OP_CHECKDATASIGVERIFY"),
    (OP_REVERSEBYTES, "OP_UNKNOWN", "OP_REVERSEBYTES"),
    (OP_INPUTINDEX, "OP_UNKNOWN", "OP_INPUTINDEX"),
    (OP_OUTPUTTOKENAMOUNT, "OP_UNKNOWN", "OP_OUTPUTTOKENAMOUNT"),
    (OP_RESERVED4, "OP_UNKNOWN", "OP_RESERVED4"),
    (OP_PUBKEYHASH, "OP_UNKNOWN", "OP_UNKNOWN"),
    (OP_INVALIDOPCODE 0xef, "OP_UNKNOWN", "SPECIAL_TOKEN_PREFIX"),
    (OP_INVALIDOPCODE 0xff, "OP_INVALIDOPCODE", "OP_UNKNOWN"),
    (OP_INVALIDOPCODE 0xac, "OP_CHECKSIG", "OP_CHECKSIG")
  ]

{- Opcodes and pushes -}

opcodeSpec :: Spec
opcodeSpec = do
  it "reads every byte from 0x4f to 0xff as one opcode that writes back to that byte" $
    forM_ [0x4f .. 0xff] $ \b ->
      (b, fmap (runPutS . serialize) (runGetS deserialize (B.singleton b) :: Either String ScriptOp))
        `shouldBe` (b, Right (B.singleton b))
  it "names the opcodes of the specification" $
    forM_ namedOpcodes $ \(b, op) -> do
      (b, runGetS deserialize (B.singleton b)) `shouldBe` (b, Right op)
      (b, runPutS (serialize op)) `shouldBe` (b, B.singleton b)
  it "reads the byte 0x00 as OP_0" $
    runGetS deserialize (B.singleton 0x00) `shouldBe` Right OP_0
  it "calls opcode 0xba OP_CHECKSIGADD too, as Tapscript does" $ do
    OP_CHECKSIGADD `shouldBe` OP_CHECKDATASIG
    runPutS (serialize OP_CHECKSIGADD) `shouldBe` B.singleton 0xba
    (case OP_CHECKDATASIG of OP_CHECKSIGADD -> True; _ -> False) `shouldBe` True
  it "calls the twelve bytes that Bitcoin Cash renamed by both names" $
    forM_ bitcoinCashNames $ \(b, op, alias) -> do
      (b, alias) `shouldBe` (b, op)
      (b, runPutS (serialize alias)) `shouldBe` (b, B.singleton b)
  it "names opcodes as the reference node of each network does" $
    forM_ opNames $ \(op, core, bchn) -> do
      -- Every network of a chain, its testnets included, names them alike.
      forM_ allNets $ \net -> do
        let name = if isJust net.sigHashForkId then bchn else core
        (op, net.name, opName net op) `shouldBe` (op, net.name, name)
  it "shows and reads opcode names" $ do
    show OP_CHECKLOCKTIMEVERIFY `shouldBe` "OP_CHECKLOCKTIMEVERIFY"
    readMaybe "OP_DUP" `shouldBe` Just OP_DUP
    readMaybe "OP_FOO" `shouldBe` (Nothing :: Maybe ScriptOp)
  it "writes a script as the bytes of its opcodes and reads them back" $ do
    runPutS (serialize (Script [OP_1, OP_2, OP_ADD])) `shouldBe` hex "515293"
    runGetS deserialize (hex "515293") `shouldBe` Right (Script [OP_1, OP_2, OP_ADD])
    runGetS deserialize B.empty `shouldBe` Right (Script [])
  it "serializes a script to JSON as its hex and reads it back" $ do
    A.encode (Script [OP_1, OP_2, OP_ADD]) `shouldBe` "\"515293\""
    A.decode "\"515293\"" `shouldBe` Just (Script [OP_1, OP_2, OP_ADD])
    A.decode "\"zz\"" `shouldBe` (Nothing :: Maybe Script)
    A.decode "\"4c\"" `shouldBe` (Nothing :: Maybe Script)
    A.decode "515293" `shouldBe` (Nothing :: Maybe Script)
  describe "push data wire format" $ do
    it "writes data of 1 to 75 bytes after the byte of its length" $ do
      runPutS (serialize (OP_PUSHDATA (hex "aa") OPCODE)) `shouldBe` hex "01aa"
      runPutS (serialize (OP_PUSHDATA (B.replicate 75 0xcc) OPCODE))
        `shouldBe` B.singleton 0x4b <> B.replicate 75 0xcc
    it "writes data of 76 to 255 bytes after 0x4c and one length byte" $ do
      runPutS (serialize (OP_PUSHDATA (B.replicate 76 0xcc) OPDATA1))
        `shouldBe` hex "4c4c" <> B.replicate 76 0xcc
      runPutS (serialize (OP_PUSHDATA (B.replicate 255 0xcc) OPDATA1))
        `shouldBe` hex "4cff" <> B.replicate 255 0xcc
    it "writes data of 256 to 65535 bytes after 0x4d and two length bytes, little endian" $ do
      runPutS (serialize (OP_PUSHDATA (B.replicate 256 0xcc) OPDATA2))
        `shouldBe` hex "4d0001" <> B.replicate 256 0xcc
      runPutS (serialize (OP_PUSHDATA (B.replicate 65535 0xcc) OPDATA2))
        `shouldBe` hex "4dffff" <> B.replicate 65535 0xcc
    it "writes data of 65536 bytes or more after 0x4e and four length bytes, little endian" $
      runPutS (serialize (OP_PUSHDATA (B.replicate 65536 0xcc) OPDATA4))
        `shouldBe` hex "4e00000100" <> B.replicate 65536 0xcc
    it "reads each push type back with its payload" $ do
      runGetS deserialize (hex "01aa") `shouldBe` Right (OP_PUSHDATA (hex "aa") OPCODE)
      runGetS deserialize (hex "4c4c" <> B.replicate 76 0xcc)
        `shouldBe` Right (OP_PUSHDATA (B.replicate 76 0xcc) OPDATA1)
      runGetS deserialize (hex "4d0001" <> B.replicate 256 0xcc)
        `shouldBe` Right (OP_PUSHDATA (B.replicate 256 0xcc) OPDATA2)
      runGetS deserialize (hex "4e00000100" <> B.replicate 65536 0xcc)
        `shouldBe` Right (OP_PUSHDATA (B.replicate 65536 0xcc) OPDATA4)
    it "keeps a push that uses a longer type than its data needs" $ do
      runGetS deserialize (hex "4c01aa") `shouldBe` Right (OP_PUSHDATA (hex "aa") OPDATA1)
      runGetS deserialize (hex "4d0100aa") `shouldBe` Right (OP_PUSHDATA (hex "aa") OPDATA2)
      runGetS deserialize (hex "4e01000000aa") `shouldBe` Right (OP_PUSHDATA (hex "aa") OPDATA4)
      runGetS deserialize (hex "4c00") `shouldBe` Right (OP_PUSHDATA "" OPDATA1)
      runPutS (serialize (OP_PUSHDATA (hex "aa") OPDATA1)) `shouldBe` hex "4c01aa"
      runPutS (serialize (OP_PUSHDATA (hex "aa") OPDATA2)) `shouldBe` hex "4d0100aa"
      runPutS (serialize (OP_PUSHDATA (hex "aa") OPDATA4)) `shouldBe` hex "4e01000000aa"
    it "fails to read a push whose data is missing" $ do
      runGetS deserialize (hex "4c") `shouldSatisfy` (isLeft :: Either String ScriptOp -> Bool)
      runGetS deserialize (hex "02aa") `shouldSatisfy` (isLeft :: Either String ScriptOp -> Bool)
      runGetS deserialize (hex "4d0500aa") `shouldSatisfy` (isLeft :: Either String ScriptOp -> Bool)
      runGetS deserialize (hex "4e01000000") `shouldSatisfy` (isLeft :: Either String ScriptOp -> Bool)
      runGetS deserialize (hex "514c") `shouldSatisfy` (isLeft :: Either String Script -> Bool)
    it "fails to write a push whose payload does not fit its type" $ do
      evaluate (runPutS (serialize (OP_PUSHDATA (B.replicate 76 0) OPCODE))) `shouldThrow` anyErrorCall
      evaluate (runPutS (serialize (OP_PUSHDATA (B.replicate 256 0) OPDATA1))) `shouldThrow` anyErrorCall
      evaluate (runPutS (serialize (OP_PUSHDATA (B.replicate 65536 0) OPDATA2))) `shouldThrow` anyErrorCall

pushSpec :: Spec
pushSpec = do
  describe "opPushData" $ do
    it "uses OP_0 for the empty string" $
      opPushData "" `shouldBe` OP_0
    it "uses OP_1 to OP_16 for one byte from 1 to 16" $ do
      opPushData "\x01" `shouldBe` OP_1
      opPushData "\x10" `shouldBe` OP_16
    it "uses OP_1NEGATE for the byte 0x81" $
      opPushData "\x81" `shouldBe` OP_1NEGATE
    it "pushes any other single byte as data" $ do
      opPushData "\x00" `shouldBe` OP_PUSHDATA "\x00" OPCODE
      opPushData "\x11" `shouldBe` OP_PUSHDATA "\x11" OPCODE
      opPushData "\x80" `shouldBe` OP_PUSHDATA "\x80" OPCODE
    it "picks the smallest push type for the length of the data" $ do
      opPushData (B.replicate 75 0) `shouldBe` OP_PUSHDATA (B.replicate 75 0) OPCODE
      opPushData (B.replicate 76 0) `shouldBe` OP_PUSHDATA (B.replicate 76 0) OPDATA1
      opPushData (B.replicate 255 0) `shouldBe` OP_PUSHDATA (B.replicate 255 0) OPDATA1
      opPushData (B.replicate 256 0) `shouldBe` OP_PUSHDATA (B.replicate 256 0) OPDATA2
      opPushData (B.replicate 65535 0) `shouldBe` OP_PUSHDATA (B.replicate 65535 0) OPDATA2
      opPushData (B.replicate 65536 0) `shouldBe` OP_PUSHDATA (B.replicate 65536 0) OPDATA4
    prop "makes a minimal push that pushes the data" $
      forAll arbitraryBS $ \bs ->
        let op = opPushData bs
         in (isMinimalPush op, pushOpData op) `shouldBe` (True, Just bs)
  describe "pushOpData" $ do
    it "gives the data that a push opcode puts on the stack" $ do
      pushOpData OP_0 `shouldBe` Just ""
      pushOpData OP_1 `shouldBe` Just "\x01"
      pushOpData OP_16 `shouldBe` Just "\x10"
      pushOpData OP_1NEGATE `shouldBe` Just "\x81"
      pushOpData (OP_PUSHDATA "\xaa\xbb" OPDATA2) `shouldBe` Just "\xaa\xbb"
    it "gives nothing for an opcode that pushes nothing" $ do
      pushOpData OP_RESERVED `shouldBe` Nothing
      pushOpData OP_DUP `shouldBe` Nothing
      pushOpData OP_PUBKEY `shouldBe` Nothing
      pushOpData (OP_INVALIDOPCODE 0xff) `shouldBe` Nothing
  describe "isPushOp" $ do
    it "is true for the opcodes that push data" $
      forM_ [OP_0, OP_1NEGATE, OP_1, OP_16, OP_PUSHDATA "" OPDATA1, OP_PUSHDATA "\xaa" OPCODE] $ \op ->
        (op, isPushOp op) `shouldBe` (op, True)
    it "is false for every other opcode" $
      forM_ [OP_RESERVED, OP_NOP, OP_DUP, OP_CHECKSIG, OP_PUBKEYHASH, OP_INVALIDOPCODE 0xff] $ \op ->
        (op, isPushOp op) `shouldBe` (op, False)
  describe "isMinimalPush" $ do
    it "is true for the shortest encoding of the data"
      $ forM_
        [ OP_0,
          OP_1,
          OP_16,
          OP_1NEGATE,
          OP_PUSHDATA "\x11" OPCODE,
          OP_PUSHDATA "\x00" OPCODE,
          OP_PUSHDATA (B.replicate 75 0) OPCODE,
          OP_PUSHDATA (B.replicate 76 0) OPDATA1,
          OP_PUSHDATA (B.replicate 256 0) OPDATA2,
          OP_PUSHDATA (B.replicate 65536 0) OPDATA4
        ]
      $ \op -> (B.length (runPutS (serialize op)), isMinimalPush op) `shouldSatisfy` snd
    it "is false for a longer encoding of the same data"
      $ forM_
        [ OP_PUSHDATA "" OPCODE,
          OP_PUSHDATA "\x01" OPCODE,
          OP_PUSHDATA "\x81" OPCODE,
          OP_PUSHDATA (B.replicate 75 0) OPDATA1,
          OP_PUSHDATA (B.replicate 255 0) OPDATA2,
          OP_PUSHDATA (B.replicate 256 0) OPDATA4
        ]
      $ \op -> (B.length (runPutS (serialize op)), isMinimalPush op) `shouldSatisfy` (not . snd)
    it "is false for an opcode that pushes nothing" $
      isMinimalPush OP_DUP `shouldBe` False

smallIntSpec :: Spec
smallIntSpec = do
  it "maps 1 to 16 to OP_1 to OP_16" $ do
    intToScriptOp 1 `shouldBe` Right OP_1
    intToScriptOp 16 `shouldBe` Right OP_16
    scriptOpToInt OP_1 `shouldBe` Right 1
    scriptOpToInt OP_16 `shouldBe` Right 16
  it "fails for an integer outside 1 to 16" $ do
    intToScriptOp 0 `shouldSatisfy` isLeft
    intToScriptOp 17 `shouldSatisfy` isLeft
    intToScriptOp (-1) `shouldSatisfy` isLeft
  it "fails for an opcode that is not OP_1 to OP_16" $ do
    scriptOpToInt OP_0 `shouldSatisfy` isLeft
    scriptOpToInt OP_1NEGATE `shouldSatisfy` isLeft
    scriptOpToInt (OP_PUSHDATA "\x01" OPCODE) `shouldSatisfy` isLeft
    scriptOpToInt (OP_PUSHDATA (B.replicate 100 0) OPCODE) `shouldSatisfy` isLeft
  prop "has intToScriptOp . scriptOpToInt identity" $
    forAll arbitraryIntScriptOp $ \i ->
      (intToScriptOp =<< scriptOpToInt i) `shouldBe` Right i

{- Standard outputs -}

-- | Standard output scripts with their decoded form: name, hex, value.
standardOutputs :: [(String, Text, ScriptOutput)]
standardOutputs =
  [ ("P2PK", "21" <> gKeyHex <> "ac", PayPK g),
    ("P2PKH", "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", PayPKHash gHash),
    -- The P2SH-P2WPKH example of BIP 143.
    ( "P2SH",
      "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387",
      PayScriptHash "4733f37cf4db86fbc2efed2500b4f4e49f312023"
    ),
    ( "P2SH32",
      "aa20" <> thirtyTwo <> "87",
      PayScript32Hash "5d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"
    ),
    -- The BIP 173 example addresses.
    ("P2WPKH", "0014751e76e8199196d454941c45d1b3a323f1433bd6", PayWitnessPKHash gHash),
    ( "P2WSH",
      "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
      PayWitnessScriptHash "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
    ),
    -- The first output of the BIP 341 wallet test vectors.
    ( "P2TR",
      "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
      PayWitness 1 (hex "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343")
    ),
    ("witness v16 of 40 bytes", "6028" <> T.replicate 40 "01", PayWitness 16 (B.replicate 40 1)),
    ("witness v1 of 2 bytes", "51020102", PayWitness 1 "\x01\x02"),
    -- The first BIP 67 test vector.
    ("2-of-2 multisig", bip67ScriptHex, PayMulSig [bip67Key bip67KeyB, bip67Key bip67KeyA] 2),
    -- 17 and 20 are one-byte pushes, as Bitcoin Core writes counts above 16.
    ( "17-of-20 multisig",
      "0111" <> T.concat (replicate 20 ("21" <> gKeyHex)) <> "0114ae",
      PayMulSig (replicate 20 g) 17
    ),
    ("OP_RETURN alone", "6a", DataCarrier []),
    ("OP_RETURN with 36 bytes", "6a24" <> T.replicate 36 "ab", DataCarrier [B.replicate 36 0xab]),
    ("OP_RETURN with two pushes", "6a021122023344", DataCarrier ["\x11\x22", "\x33\x44"]),
    ("OP_RETURN with an empty push", "6a00", DataCarrier [""]),
    ("OP_RETURN with OP_1", "6a51", DataCarrier ["\x01"]),
    ("OP_RETURN with OP_1NEGATE", "6a4f", DataCarrier ["\x81"])
  ]
  where
    g = gKey
    thirtyTwo = "5d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"

-- | Scripts that look like a standard output but are not one: name, hex.
nonStandardOutputs :: [(String, Text)]
nonStandardOutputs =
  [ -- Not witness programs by consensus: the program is not a direct push.
    ("P2WPKH with OP_PUSHDATA1", "004c14" <> twenty),
    ("P2WSH with OP_PUSHDATA1", "004c20" <> thirtyTwo),
    ("P2TR with OP_PUSHDATA1", "514c20" <> thirtyTwo),
    ("P2TR with OP_PUSHDATA2", "514d2000" <> thirtyTwo),
    ("witness v0 of 25 bytes with OP_PUSHDATA1", "004c19" <> T.replicate 25 "01"),
    -- Not pay-to-script-hash by consensus.
    ("P2SH with OP_PUSHDATA1", "a94c14" <> twenty <> "87"),
    ("P2SH32 with OP_PUSHDATA1", "aa4c20" <> thirtyTwo <> "87"),
    -- Non-standard in Bitcoin Core.
    ("P2PKH with OP_PUSHDATA1", "76a94c14" <> twenty <> "88ac"),
    ("P2PK with OP_PUSHDATA1", "4c21" <> gKeyHex <> "ac"),
    -- The same keys as a multisig of direct pushes, in other bytes: a value
    -- of 'ScriptOutput' has no place for the form of a push. Bitcoin Core
    -- calls these multisig, and Bitcoin Cash Node does not. 0x21 = 33, the
    -- length of the key, in one, two and four bytes.
    ("multisig with a key pushed with OP_PUSHDATA1", "514c21" <> gKeyHex <> "51ae"),
    ("multisig with a key pushed with OP_PUSHDATA2", "514d2100" <> gKeyHex <> "51ae"),
    ("multisig with a key pushed with OP_PUSHDATA4", "514e21000000" <> gKeyHex <> "51ae"),
    ("multisig with one of two keys pushed with OP_PUSHDATA1", "5121" <> gKeyHex <> "4c21" <> gKeyHex <> "52ae"),
    -- Wrong lengths.
    ("witness v0 of 25 bytes", "0019" <> T.replicate 25 "01"),
    ("witness v1 of 41 bytes", "5129" <> T.replicate 41 "01"),
    ("witness v1 of 1 byte", "510101"),
    ("P2PKH with a 19-byte hash", "76a913" <> T.replicate 19 "ab" <> "88ac"),
    ("P2PKH with a 21-byte hash", "76a915" <> T.replicate 21 "ab" <> "88ac"),
    ("P2SH with a 19-byte hash", "a913" <> T.replicate 19 "ab" <> "87"),
    ("P2SH with a 21-byte hash", "a915" <> T.replicate 21 "ab" <> "87"),
    ("P2SH32 with a 31-byte hash", "aa1f" <> T.replicate 31 "cd" <> "87"),
    ("P2SH32 with a 33-byte hash", "aa21" <> T.replicate 33 "cd" <> "87"),
    -- A key must fill its push.
    ("P2PK with 32 bytes after a compressed key", "41" <> gKeyHex <> thirtyTwo <> "ac"),
    ("multisig with 32 bytes after a compressed key", "5141" <> gKeyHex <> thirtyTwo <> "51ae"),
    ("P2PK with a 32-byte key", "20" <> thirtyTwo <> "ac"),
    -- Multisig counts.
    ("multisig with a count of 0", "0021" <> gKeyHex <> "51ae"),
    ("multisig with OP_1NEGATE as count", "4f21" <> gKeyHex <> "51ae"),
    ("multisig with 1 as a byte push", "010121" <> gKeyHex <> "0101ae"),
    -- Bitcoin Core reads a count as a minimal script number: 16 is OP_16,
    -- and 17 is a direct push of one byte.
    ("multisig with 16 as a byte push", "0110" <> T.concat (replicate 16 ("21" <> gKeyHex)) <> "60ae"),
    ("multisig with 17 pushed with OP_PUSHDATA1", "4c0111" <> T.concat (replicate 17 ("21" <> gKeyHex)) <> "0111ae"),
    ("multisig with 21 keys", "0115" <> T.concat (replicate 21 ("21" <> gKeyHex)) <> "0115ae"),
    ("multisig requiring more signatures than keys", "5221" <> gKeyHex <> "51ae"),
    ("multisig whose key count is wrong", "5121" <> gKeyHex <> "52ae"),
    ("multisig ending in OP_CHECKMULTISIGVERIFY", "5121" <> gKeyHex <> "51af"),
    ("multisig without OP_CHECKMULTISIG", "5121" <> gKeyHex <> "51"),
    -- Not an output template at all.
    ("empty script", ""),
    ("OP_1", "51"),
    ("OP_RETURN followed by OP_DUP", "6a76"),
    ("OP_RETURN with a truncated push", "6a4c")
  ]
  where
    twenty = T.replicate 20 "ab"
    thirtyTwo = T.replicate 32 "cd"

outputSpec :: Spec
outputSpec = do
  let g = gKey
      decodeHexOutput = decodeSerial . hex :: Text -> Either String ScriptOutput
      encodeHexOutput = fmap (encodeHex . runPutS . serialize) . encodeOutput
  it "decodes the standard output templates" $
    forM_ standardOutputs $ \(name, h, out) ->
      (name, decodeHexOutput h) `shouldBe` (name, Right out)
  it "encodes the standard outputs to their templates" $
    forM_ standardOutputs $ \(name, h, out) ->
      (name, encodeHexOutput out) `shouldBe` (name, Right h)
  it "rejects scripts that only look like a standard output" $
    forM_ nonStandardOutputs $ \(name, h) ->
      (name, decodeHexOutput h) `shouldSatisfy` (isLeft . snd)
  it "writes a data carrier back with the shortest pushes, which can be other bytes" $
    (encodeHexOutput =<< decodeHexOutput "6a4c0401020304") `shouldBe` Right "6a0401020304"
  it "does not decode a key that is not a point of the curve, where Bitcoin Core only checks its size" $ do
    -- decodescript of Bitcoin Core 32.1 says pubkey, pubkey, pubkey and
    -- multisig for these four scripts. A PublicKey of this library is a
    -- point, so they have no ScriptOutput.
    -- The key of private key 1 in hybrid form: 06, x and y.
    decodeHexOutput ("4106" <> gUncompressedXY <> "ac") `shouldSatisfy` isLeft
    -- 33 and 65 bytes with a valid first byte that are not on the curve
    decodeHexOutput ("2102" <> T.replicate 32 "ff" <> "ac") `shouldSatisfy` isLeft
    decodeHexOutput ("4104" <> T.replicate 64 "ff" <> "ac") `shouldSatisfy` isLeft
    -- A 1-of-2 multisig whose second key is not on the curve
    decodeHexOutput ("5121" <> gKeyHex <> "2102" <> T.replicate 32 "ff" <> "52ae") `shouldSatisfy` isLeft
  it "does not decode OP_RETURN followed by OP_RESERVED, which Bitcoin Core counts as a push" $
    decodeHexOutput "6a50" `shouldSatisfy` isLeft
  it "does not decode a Bitcoin Cash output that holds tokens" $
    -- The token prefix 0xef, a 32-byte category, the bitfield 0x10 for a
    -- fungible amount, the amount 100, then a pay-to-public-key-hash script
    decodeHexOutput ("ef" <> T.replicate 32 "aa" <> "1064" <> "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac")
      `shouldSatisfy` isLeft
  it "has 20 as the most multisig keys" $
    maxMultisigKeys `shouldBe` 20
  it "refuses to encode a multisig that no script can express" $ do
    encodeOutput (PayMulSig [] 0) `shouldSatisfy` isLeft
    encodeOutput (PayMulSig [g] 0) `shouldSatisfy` isLeft
    encodeOutput (PayMulSig [g] 2) `shouldSatisfy` isLeft
    encodeOutput (PayMulSig (replicate 21 g) 1) `shouldSatisfy` isLeft
  it "refuses to encode a witness program outside the versions and lengths of BIP 141" $ do
    encodeOutput (PayWitness 0 (B.replicate 20 1)) `shouldSatisfy` isLeft
    encodeOutput (PayWitness 17 (B.replicate 20 1)) `shouldSatisfy` isLeft
    encodeOutput (PayWitness 1 "\x01") `shouldSatisfy` isLeft
    encodeOutput (PayWitness 1 (B.replicate 41 1)) `shouldSatisfy` isLeft
  it "fails with an error call when marshalling an output that cannot be encoded" $
    evaluate (encodeSerial (PayMulSig [] 0)) `shouldThrow` anyErrorCall
  it "marshals an output to JSON as the hex of its script" $ do
    toJSON (PayPKHash gHash) `shouldBe` A.String "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
    A.parseMaybe parseJSON (A.String "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac")
      `shouldBe` Just (PayPKHash gHash)
    A.parseMaybe parseJSON (A.String ("004c14" <> T.replicate 20 "ab"))
      `shouldBe` (Nothing :: Maybe ScriptOutput)
  describe "toP2SH and toP2WSH" $ do
    it "hashes the redeem script of the P2SH-P2WPKH example of BIP 143" $
      toP2SH (Script [OP_0, opPushData (hex "79091972186c449eb1ded22b78e40d009bdf0089")])
        `shouldBe` Right (PayScriptHash "4733f37cf4db86fbc2efed2500b4f4e49f312023")
    it "hashes the witness script of the P2WSH example of BIP 143" $
      toP2WSH bip143WitnessScript
        `shouldBe` Right (PayWitnessScriptHash "5d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0")
    it "toP2SH takes a redeem script of 520 bytes, the most a push can hold" $
      -- 520 one-byte opcodes. HASH160 computed with Python (hashlib, embit).
      toP2SH (Script (replicate 520 OP_NOP))
        `shouldBe` Right (PayScriptHash "b5c90009be7bc8faa0add03f76ee9c88fd36d6b4")
    it "toP2SH refuses a redeem script of 521 bytes" $
      toP2SH (Script (replicate 521 OP_NOP))
        `shouldBe` Left "The redeem script is 521 bytes long, and a pay-to-script-hash redeem script can have at most 520"
    it "toP2WSH takes a witness script of 10,000 bytes, the most the interpreter runs" $
      toP2WSH (Script (replicate 10000 OP_NOP))
        -- SHA256 of 10,000 bytes 0x61, computed with Python (hashlib)
        `shouldBe` Right (PayWitnessScriptHash "27dd1f61b867b6a0f6e9d8a41c43231de52107e53ae424de8f847b821db4b711")
    it "toP2WSH refuses a witness script of 10,001 bytes" $
      toP2WSH (Script (replicate 10001 OP_NOP))
        `shouldBe` Left "The witness script is 10001 bytes long, and a pay-to-witness-script-hash witness script can have at most 10000"
    it "p2shScriptHash and p2wshScriptHash give the hashes those outputs commit to" $ do
      p2shScriptHash (Script [OP_0, opPushData (hex "79091972186c449eb1ded22b78e40d009bdf0089")])
        `shouldBe` Right "4733f37cf4db86fbc2efed2500b4f4e49f312023"
      p2wshScriptHash bip143WitnessScript
        `shouldBe` Right "5d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"
    it "names the two limits" $ do
      maxRedeemScriptSize `shouldBe` 520
      maxWitnessScriptSize `shouldBe` 10000
  describe "sortMulSig" $ do
    it "sorts the keys of the first BIP 67 test vector" $ do
      let unsorted = PayMulSig [bip67Key bip67KeyA, bip67Key bip67KeyB] 2
      encodeHexOutput (sortMulSig unsorted) `shouldBe` Right bip67ScriptHex
      (addrToText btc <$> payToScriptAddress (sortMulSig unsorted))
        `shouldBe` Right (Just "39bgKC7RFbpoCRbtD5KEdkYKtNyhpsNa3Z")
    it "leaves any other output unchanged" $
      sortMulSig (PayPKHash gHash) `shouldBe` PayPKHash gHash
    prop "sorts the keys by their serialized bytes" $
      forAll arbitraryMSOutput $ \out ->
        let keyList = map encodeSerial (sortMulSig out).keys
         in keyList `shouldBe` sort keyList
  it "classifies every output type with exactly its own predicate" $ do
    let samples =
          [ PayPK g,
            PayPKHash gHash,
            PayMulSig [g] 1,
            PayScriptHash gHash,
            PayWitnessPKHash gHash,
            PayWitnessScriptHash "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
            PayWitness 1 "\x01\x02",
            PayScript32Hash "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
            DataCarrier []
          ]
        predicates =
          [ isPayPK,
            isPayPKHash,
            isPayMulSig,
            isPayScriptHash,
            isPayWitnessPKHash,
            isPayWitnessScriptHash,
            isPayWitness,
            isPayScript32Hash,
            isDataCarrier
          ]
    [[p s | s <- samples] | p <- predicates]
      `shouldBe` [[i == j | j <- [0 .. 8 :: Int]] | i <- [0 .. 8]]
  where
    bip143WitnessScript =
      either error id $
        runGetS deserialize $
          hex
            "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aead\
            \ab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"

{- Standard inputs -}

-- | Standard input scripts with their decoded form: name, hex, value.
standardInputs :: [(String, Text, ScriptInput)]
standardInputs =
  [ ("P2PK", sigAllPushHex, RegularInput (SpendPK sig)),
    ("P2PKH", sigAllPushHex <> "21" <> gKeyHex, RegularInput (SpendPKHash sig g)),
    ("2-of-n multisig", "00" <> sigAllPushHex <> sigAllPushHex, RegularInput (SpendMulSig [sig, sig])),
    ("multisig with one empty signature", "0000" <> sigAllPushHex, RegularInput (SpendMulSig [TxSignatureEmpty, sig])),
    ("P2PKH with an empty signature", "0021" <> gKeyHex, RegularInput (SpendPKHash TxSignatureEmpty g)),
    -- The P2SH-P2WPKH and P2SH-P2WSH examples of BIP 143.
    ( "P2SH-P2WPKH",
      "16001479091972186c449eb1ded22b78e40d009bdf0089",
      NestedWitnessInput (PayWitnessPKHash "79091972186c449eb1ded22b78e40d009bdf0089")
    ),
    ( "P2SH-P2WSH",
      "2200205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0",
      NestedWitnessInput (PayWitnessScriptHash "5d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0")
    ),
    ("P2SH multisig without signatures yet", "0047" <> bip67ScriptHex, ScriptHashInput (SpendMulSig []) multisig),
    ("P2SH multisig with one signature", "00" <> sigAllPushHex <> "47" <> bip67ScriptHex, ScriptHashInput (SpendMulSig [sig]) multisig),
    ("P2SH P2PK", sigAllPushHex <> "2321" <> gKeyHex <> "ac", ScriptHashInput (SpendPK sig) (PayPK g)),
    ( "P2SH P2PKH",
      sigAllPushHex <> "21" <> gKeyHex <> "1976a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
      ScriptHashInput (SpendPKHash sig g) (PayPKHash gHash)
    )
  ]
  where
    g = gKey
    sig = TxSignature sigDer sigHashAll
    multisig = PayMulSig [bip67Key bip67KeyB, bip67Key bip67KeyA] 2

-- | Scripts that are not a standard input: name, hex.
nonStandardInputs :: [(String, Text)]
nonStandardInputs =
  [ ("a push that is not a signature", "03010203"),
    ("a signature with a key followed by 32 bytes", sigAllPushHex <> "41" <> gKeyHex <> T.replicate 32 "ee"),
    ("a multisig redeem script without OP_0 before the signatures", sigAllPushHex <> "47" <> bip67ScriptHex),
    ("OP_0 before the signature of a P2PK redeem script", "00" <> sigAllPushHex <> "2321" <> gKeyHex <> "ac"),
    ("two signatures for a P2PKH redeem script", sigAllPushHex <> sigAllPushHex <> "1976a914751e76e8199196d454941c45d1b3a323f1433bd688ac"),
    ("a P2SH script as redeem script", sigAllPushHex <> "17a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"),
    ("a data carrier as redeem script", sigAllPushHex <> "026a00"),
    ("a signature before a nested witness program", sigAllPushHex <> "16001479091972186c449eb1ded22b78e40d009bdf0089"),
    ("a signature before a nested P2WSH program", sigAllPushHex <> "2200205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"),
    -- BIP 141: the script must be exactly a push of the program. A push
    -- with OP_PUSHDATA1 is invalid by consensus.
    ("a nested P2WPKH program pushed with OP_PUSHDATA1", "4c16001479091972186c449eb1ded22b78e40d009bdf0089"),
    ("a nested P2WSH program pushed with OP_PUSHDATA1", "4c2200205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"),
    -- The redeem script must be in the form this library writes, or its
    -- hash would change when it is written back.
    ("a multisig redeem script whose key is pushed with OP_PUSHDATA1", "0026514c21" <> gKeyHex <> "51ae"),
    ("a nested witness program of version 1", "22512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"),
    ("a redeem script alone that is not a witness program", "2321" <> gKeyHex <> "ac"),
    ("a non-push opcode", "76")
  ]

inputSpec :: Spec
inputSpec = do
  let g = gKey
      decodeHexInput = unmarshal btc . hex :: Text -> Either String ScriptInput
      encodeHexInput = encodeHex . marshal btc
  it "decodes the standard input scripts" $
    forM_ standardInputs $ \(name, h, inp) ->
      (name, decodeHexInput h) `shouldBe` (name, Right inp)
  it "encodes the standard inputs to their scripts" $
    forM_ standardInputs $ \(name, h, inp) ->
      (name, encodeHexInput inp) `shouldBe` (name, h)
  it "rejects scripts that are not a standard input" $
    forM_ nonStandardInputs $ \(name, h) ->
      (name, decodeHexInput h) `shouldSatisfy` (isLeft . snd)
  it "reads the multisig redeem script in its direct push form, which the one above is not" $
    decodeHexInput ("00255121" <> gKeyHex <> "51ae")
      `shouldBe` Right (ScriptHashInput (SpendMulSig []) (PayMulSig [g] 1))
  it "reads a redeem script pushed with OP_PUSHDATA1, and writes it back with a direct push" $ do
    -- The push of the redeem script is not part of what is hashed, so its
    -- form does not change the address of the input
    let decoded = decodeHexInput ("004c255121" <> gKeyHex <> "51ae")
    decoded `shouldBe` Right (ScriptHashInput (SpendMulSig []) (PayMulSig [g] 1))
    (encodeHexInput <$> decoded) `shouldBe` Right ("00255121" <> gKeyHex <> "51ae")
  it "does not decode an input whose signature only consensus accepts" $ do
    -- A high S: r = 1 and s = n - 1, which is strict DER
    let highS = "3026020101022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
    -- 40 bytes of signature and the hash type byte: a push of 41 bytes
    decodeHexInput ("29" <> highS <> "01" <> "21" <> gKeyHex) `shouldSatisfy` isLeft
    -- An undefined hash type byte, 0x04
    decodeHexInput ("47" <> sigDerHex <> "04" <> "21" <> gKeyHex) `shouldSatisfy` isLeft
  it "reads a single empty push as a pay-to-public-key input with an empty signature" $ do
    -- The same script is a multisig input without signatures. Without the
    -- output script, the single-signature reading is taken.
    decodeInput btc (Script [OP_0]) `shouldBe` Right (RegularInput (SpendPK TxSignatureEmpty))
    decodeInput btc (Script [OP_0, OP_0]) `shouldBe` Right (RegularInput (SpendMulSig [TxSignatureEmpty]))
    decodeInput btc (Script [OP_0, OP_0, OP_0, OP_0])
      `shouldBe` Right (RegularInput (SpendMulSig (replicate 3 TxSignatureEmpty)))
  it "writes an empty signature as OP_0" $ do
    encodeHexInput (RegularInput (SpendPK TxSignatureEmpty)) `shouldBe` "00"
    encodeHexInput (RegularInput (SpendMulSig [TxSignatureEmpty, TxSignatureEmpty])) `shouldBe` "000000"
    encodeHexInput (RegularInput (SpendMulSig [])) `shouldBe` "00"
  it "classifies every input type with exactly its own predicate" $ do
    let samples =
          [ RegularInput (SpendPK TxSignatureEmpty),
            RegularInput (SpendPKHash TxSignatureEmpty g),
            RegularInput (SpendMulSig []),
            ScriptHashInput (SpendPK TxSignatureEmpty) (PayPK g),
            NestedWitnessInput (PayWitnessPKHash gHash)
          ]
        predicates = [isSpendPK, isSpendPKHash, isSpendMulSig, isScriptHashInput, isNestedWitnessInput]
    [[p s | s <- samples] | p <- predicates]
      `shouldBe` [[i == j | j <- [0 .. 4 :: Int]] | i <- [0 .. 4]]

{- Sighash types -}

sigHashTypeSpec :: Spec
sigHashTypeSpec = do
  it "can correctly show" $ do
    show (0x00 :: SigHash) `shouldBe` "SigHash " <> show (0x00 :: Word32)
    show (0x01 :: SigHash) `shouldBe` "SigHash " <> show (0x01 :: Word32)
    show (0xff :: SigHash) `shouldBe` "SigHash " <> show (0xff :: Word32)
    show (0xabac3344 :: SigHash)
      `shouldBe` "SigHash "
        <> show (0xabac3344 :: Word32)
  it "can add a forkid" $ do
    0x00 `sigHashAddForkId` 0x00 `shouldBe` 0x00
    0xff `sigHashAddForkId` 0x00ffffff `shouldBe` 0xffffffff
    0xffff `sigHashAddForkId` 0x00aaaaaa `shouldBe` 0xaaaaaaff
    0xffff `sigHashAddForkId` 0xaaaaaaaa `shouldBe` 0xaaaaaaff
    0xffff `sigHashAddForkId` 0x00004444 `shouldBe` 0x004444ff
    0xff01 `sigHashAddForkId` 0x44440000 `shouldBe` 0x44000001
    0xff03 `sigHashAddForkId` 0x00550000 `shouldBe` 0x55000003
  it "can extract a forkid" $ do
    sigHashGetForkId 0x00000000 `shouldBe` 0x00000000
    sigHashGetForkId 0x80000000 `shouldBe` 0x00800000
    sigHashGetForkId 0xffffffff `shouldBe` 0x00ffffff
    sigHashGetForkId 0xabac3403 `shouldBe` 0x00abac34
  it "adds the fork id of the network, which is 0 on Bitcoin Cash" $ do
    sigHashAddNetworkId btc 0x01 `shouldBe` 0x01
    sigHashAddNetworkId bch 0x41 `shouldBe` 0x41
    sigHashAddNetworkId bch 0xaa0041 `shouldBe` 0x41
  it "can build some vectors" $ do
    sigHashAll `shouldBe` 0x01
    sigHashNone `shouldBe` 0x02
    sigHashSingle `shouldBe` 0x03
    setForkIdFlag sigHashAll `shouldBe` 0x41
    setAnyoneCanPay sigHashAll `shouldBe` 0x81
    setAnyoneCanPay (setForkIdFlag sigHashAll) `shouldBe` 0xc1
  it "can test flags" $ do
    hasForkIdFlag sigHashAll `shouldBe` False
    hasForkIdFlag (setForkIdFlag sigHashAll) `shouldBe` True
    anyoneCanPay sigHashAll `shouldBe` False
    anyoneCanPay (setAnyoneCanPay sigHashAll) `shouldBe` True
    isSigHashAll sigHashNone `shouldBe` False
    isSigHashAll sigHashAll `shouldBe` True
    isSigHashAll 0x81 `shouldBe` True
    isSigHashNone sigHashSingle `shouldBe` False
    isSigHashNone sigHashNone `shouldBe` True
    isSigHashNone 0xc2 `shouldBe` True
    isSigHashSingle sigHashAll `shouldBe` False
    isSigHashSingle sigHashSingle `shouldBe` True
    isSigHashSingle 0x43 `shouldBe` True
  it "knows the hash type bytes that IsDefinedHashtypeSignature of Bitcoin Core accepts" $ do
    forM_ [0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0x41, 0xc1, 0xc3] $ \sh ->
      (sh, isSigHashUnknown sh) `shouldBe` (sh, False)
    forM_ [0x00, 0x04, 0x05, 0x1f, 0x20, 0x21, 0x22, 0x40, 0x80, 0xc0, 0xff] $ \sh ->
      (sh, isSigHashUnknown sh) `shouldBe` (sh, True)
  it "ignores a fork id above the hash type byte" $
    isSigHashUnknown 0x00aa0041 `shouldBe` False
  it "gives the flags their values" $ do
    fromEnum SIGHASH_ALL `shouldBe` 0x01
    fromEnum SIGHASH_NONE `shouldBe` 0x02
    fromEnum SIGHASH_SINGLE `shouldBe` 0x03
    fromEnum SIGHASH_FORKID `shouldBe` 0x40
    fromEnum SIGHASH_ANYONECANPAY `shouldBe` 0x80
  prop "has toEnum . fromEnum identity on flags" $
    forAll arbitrarySigHashFlag $
      \f -> toEnum (fromEnum f) `shouldBe` f
  it "has no flag for other values" $
    evaluate (toEnum 0x05 :: SigHashFlag) `shouldThrow` anyErrorCall
  it "lists the flags in the order of their constructors" $ do
    [minBound .. maxBound] `shouldBe` [SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_FORKID, SIGHASH_ANYONECANPAY]
    [SIGHASH_ALL ..] `shouldBe` [SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_FORKID, SIGHASH_ANYONECANPAY]
    [SIGHASH_NONE .. SIGHASH_FORKID] `shouldBe` [SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_FORKID]
    [SIGHASH_ALL, SIGHASH_SINGLE ..] `shouldBe` [SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY]
    [SIGHASH_ANYONECANPAY, SIGHASH_FORKID ..] `shouldBe` [SIGHASH_ANYONECANPAY, SIGHASH_FORKID, SIGHASH_SINGLE, SIGHASH_NONE, SIGHASH_ALL]
  it "steps from a flag to the next and the previous one" $ do
    -- The values of SIGHASH_SINGLE and SIGHASH_FORKID are 0x03 and 0x40
    succ SIGHASH_SINGLE `shouldBe` SIGHASH_FORKID
    pred SIGHASH_FORKID `shouldBe` SIGHASH_SINGLE
    evaluate (succ SIGHASH_ANYONECANPAY) `shouldThrow` anyErrorCall
    evaluate (pred SIGHASH_ALL) `shouldThrow` anyErrorCall
  it "serializes to JSON as a number and reads only 32-bit values" $ do
    A.encode (0x81 :: SigHash) `shouldBe` "129"
    A.decode "129" `shouldBe` Just (0x81 :: SigHash)
    A.decode "-1" `shouldBe` (Nothing :: Maybe SigHash)
    A.decode "4294967296" `shouldBe` (Nothing :: Maybe SigHash)
    A.decode "1.5" `shouldBe` (Nothing :: Maybe SigHash)

{- Digests -}

-- | The digests of every input of a transaction, from the hashes that the
-- inputs share. Each digest is the one that the test of the function for
-- one digest states.
sharedHashesSpec :: Spec
sharedHashesSpec = do
  let hashes = txSigHashes bip143Tx
  it "computes the BIP 143 digests of the P2WPKH example from the hashes that its inputs share" $ do
    txSigHashForkIdWith btc hashes bip143ScriptCode bip143Value 1 sigHashAll
      `shouldBe` Right bip143Digest
    txSigHashForkIdWith btc hashes bip143ScriptCode bip143Value 1 (setAnyoneCanPay sigHashAll)
      `shouldBe` Right "fc5b6bbc855883bcfdaefb77071740ccde4929f15e6a13286584e779b2529d91"
  it "computes the fork id digests of Bitcoin Cash for its six hash types from those hashes" $
    forM_ bip143CashDigests $ \(sh, digest) -> do
      (sh, txSigHashWith bch hashes bip143ScriptCode bip143Value 1 sh) `shouldBe` (sh, Right digest)
      (sh, txSigHashCashTokenWith bch hashes "" bip143ScriptCode bip143Value 1 sh) `shouldBe` (sh, Right digest)
  it "computes the legacy digest of Bitcoin for the transaction of those hashes" $
    txSigHashWith btc hashes bip143ScriptCode bip143Value 1 sigHashAll
      `shouldBe` Right "c46030820cbc48402a47cc5b5d3d41648f4e3a711f56b804d601d09dc112a6a4"
  it "puts no output in the digest of SIGHASH_SINGLE when the input has no output at its index, from those hashes" $ do
    let oneOutput = txSigHashes bip143OneOutputTx
    txSigHashForkIdWith btc oneOutput bip143ScriptCode bip143Value 1 sigHashSingle
      `shouldBe` Right "471a6e7963aa0c328ee12392fb1a345148edf326b4223660e1a770fdc2826435"
    txSigHashForkIdWith btc oneOutput bip143ScriptCode bip143Value 0 sigHashSingle
      `shouldBe` Right "0ef4fc221b524ce37251444160588c6989d6bc88b60c47a6ff7ded04173636c4"
  it "fails with those hashes for an input index the transaction does not have" $ do
    let legacy i = txSigHashWith btc hashes bip143ScriptCode bip143Value i sigHashAll
        bip143 i = txSigHashForkIdWith btc hashes bip143ScriptCode bip143Value i sigHashAll
    legacy 2 `shouldBe` Left "txSigHash: input index out of range"
    legacy (-1) `shouldBe` Left "txSigHash: input index out of range"
    bip143 2 `shouldBe` Left "txSigHashForkId: input index out of range"
    bip143 (-1) `shouldBe` Left "txSigHashForkId: input index out of range"
  it "requires SIGHASH_FORKID on Bitcoin Cash with those hashes" $
    txSigHashWith bch hashes bip143ScriptCode bip143Value 1 sigHashAll
      `shouldBe` Left "txSigHash: SIGHASH_FORKID is required on this network"
  it "gives back the transaction that the hashes were made from" $
    sigHashesTx hashes `shouldBe` bip143Tx
  -- The signature that BIP 143 gives for the second input of its example
  it "makeSignatureWith signs the P2WPKH example of BIP 143 with the signature of the BIP, from those hashes" $ do
    let coin = PayWitnessPKHash "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
        outpoint = (bip143Tx.inputs !! 1).outpoint
        sigInput = SigInput coin bip143Value outpoint sigHashAll Nothing
    fmap (encodeHex . encodeTxSig btc) (makeSignatureWith btc hashes 1 sigInput bip143Key)
      `shouldBe` Right
        "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a\
        \0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
  -- The digest of that case is the constant 1, which commits to nothing
  it "makeSignatureWith refuses SIGHASH_SINGLE on a legacy input without an output at its index" $ do
    let coin = PayPKHash "1d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
        outpoint = (bip143OneOutputTx.inputs !! 1).outpoint
        sigInput = SigInput coin bip143Value outpoint sigHashSingle Nothing
    makeSignatureWith btc (txSigHashes bip143OneOutputTx) 1 sigInput bip143Key
      `shouldBe` Left "makeSignature: SIGHASH_SINGLE without an output at the input index"

digestSpec :: Spec
digestSpec = do
  it "computes the BIP 143 digest of the P2WPKH example" $
    txSigHashForkId btc bip143Tx bip143ScriptCode bip143Value 1 sigHashAll
      `shouldBe` Right bip143Digest
  -- The digests below were computed with Python (hashlib) from the text of
  -- BIP 143 and from the legacy algorithm, not with this library.
  it "computes the BIP 143 digest of that input with SIGHASH_ALL and SIGHASH_ANYONECANPAY" $
    txSigHashForkId btc bip143Tx bip143ScriptCode bip143Value 1 (setAnyoneCanPay sigHashAll)
      `shouldBe` Right "fc5b6bbc855883bcfdaefb77071740ccde4929f15e6a13286584e779b2529d91"
  it "writes the hash type of the BIP 143 digest as four bytes on Bitcoin, as Bitcoin Core does" $
    -- The preimage ends in 01 01 00 00 for the hash type 0x101. A signature
    -- only carries one byte, so no signature matches this digest.
    txSigHashForkId btc bip143Tx bip143ScriptCode bip143Value 1 0x101
      `shouldBe` Right "991a362ee6f2b8a004118aa1f098165a84df10b434f5d14c9cb18661309423ef"
  it "writes the hash type of the legacy digest as four bytes" $ do
    txSigHash btc bip143Tx bip143ScriptCode bip143Value 1 sigHashAll
      `shouldBe` Right "c46030820cbc48402a47cc5b5d3d41648f4e3a711f56b804d601d09dc112a6a4"
    txSigHash btc bip143Tx bip143ScriptCode bip143Value 1 0x101
      `shouldBe` Right "8e4ac2d7b4f759fdd01de9b78a2c46fe361316f397b214c7f0f98f073128aa4c"
  it "computes the fork id digest of Bitcoin Cash for each of its six hash types" $
    -- The fork id of Bitcoin Cash is 0, so the last four bytes of the
    -- preimage are the hash type byte and three zero bytes
    forM_ bip143CashDigests $
      \(sh, digest) ->
        (sh, txSigHashForkId bch bip143Tx bip143ScriptCode bip143Value 1 sh) `shouldBe` (sh, Right digest)
  it "fails for an input index the transaction does not have" $ do
    txSigHash btc bip143Tx bip143ScriptCode bip143Value 2 sigHashAll `shouldSatisfy` isLeft
    txSigHash btc bip143Tx bip143ScriptCode bip143Value (-1) sigHashAll `shouldSatisfy` isLeft
    txSigHashForkId btc bip143Tx bip143ScriptCode bip143Value 2 sigHashAll `shouldSatisfy` isLeft
    txSigHashForkId btc bip143Tx bip143ScriptCode bip143Value (-1) sigHashAll `shouldSatisfy` isLeft
  it "removes OP_CODESEPARATOR from the script code of the legacy digest, as SerializeScriptCode of Bitcoin Core does" $
    -- The same digest as for the script code without the opcode
    txSigHash btc bip143Tx (Script (OP_CODESEPARATOR : bip143ScriptCode.ops)) bip143Value 1 sigHashAll
      `shouldBe` Right "c46030820cbc48402a47cc5b5d3d41648f4e3a711f56b804d601d09dc112a6a4"
  it "keeps OP_CODESEPARATOR in the script code of the BIP 143 digest" $
    -- The script code is then 26 bytes: ab, then the 25 bytes of the script
    txSigHashForkId btc bip143Tx (Script (OP_CODESEPARATOR : bip143ScriptCode.ops)) bip143Value 1 sigHashAll
      `shouldBe` Right "f58633c60526565d17f4a38d202ab3cfc26fb900abd2f49cf2252488b5240964"
  -- BIP 143: hashOutputs is 32 zero bytes when the type is SINGLE and the
  -- input index is not below the number of outputs. The transaction is the
  -- example without its second output, and the digests were computed with
  -- Python (hashlib) from the text of the BIP.
  it "puts no output in the BIP 143 digest of SIGHASH_SINGLE when the input has no output at its index" $ do
    txSigHashForkId btc bip143OneOutputTx bip143ScriptCode bip143Value 1 sigHashSingle
      `shouldBe` Right "471a6e7963aa0c328ee12392fb1a345148edf326b4223660e1a770fdc2826435"
    txSigHashForkId btc bip143OneOutputTx bip143ScriptCode bip143Value 0 sigHashSingle
      `shouldBe` Right "0ef4fc221b524ce37251444160588c6989d6bc88b60c47a6ff7ded04173636c4"
    txSigHashForkId bch bip143OneOutputTx bip143ScriptCode bip143Value 1 0x43
      `shouldBe` Right "655196fc3fcfa9cfc37922e03bf9ff86e1ad2892e18065f032b11afd6c9902d0"
  sharedHashesSpec
  it "requires SIGHASH_FORKID on Bitcoin Cash" $
    txSigHash bch bip143Tx bip143ScriptCode bip143Value 1 sigHashAll `shouldSatisfy` isLeft
  it "uses the fork id digest on Bitcoin Cash" $
    -- The digest of the table above for the hash type 0x41
    txSigHash bch bip143Tx bip143ScriptCode bip143Value 1 (setForkIdFlag sigHashAll)
      `shouldBe` Right "467f411d178762db122a6aced76370a1c8324355bf0796502bf82eeaeda86a35"
  it "uses the legacy digest on Bitcoin even with the SIGHASH_FORKID flag" $
    -- The legacy digest with the four hash type bytes 41 00 00 00
    txSigHash btc bip143Tx bip143ScriptCode bip143Value 1 (setForkIdFlag sigHashAll)
      `shouldBe` Right "5e0f360ad7f9a80982d2529061f963a8afe63dbb010eb01a94abfa4626797129"

{- Transaction signatures -}

txSignatureSpec :: Spec
txSignatureSpec = do
  let sig = sigDer
  it "writes the signature followed by its hash type byte" $ do
    encodeTxSig btc (TxSignature sig sigHashAll) `shouldBe` hex (sigDerHex <> "01")
    encodeTxSig btc (TxSignature sig 0x81) `shouldBe` hex (sigDerHex <> "81")
    encodeTxSig bch (TxSignature sig 0x41) `shouldBe` hex (sigDerHex <> "41")
  it "writes an empty signature as the empty string" $
    encodeTxSig btc TxSignatureEmpty `shouldBe` ""
  it "reads a signature with its hash type byte" $ do
    decodeTxSig btc (hex (sigDerHex <> "01")) `shouldBe` Right (TxSignature sig 0x01)
    decodeTxSig btc (hex (sigDerHex <> "82")) `shouldBe` Right (TxSignature sig 0x82)
    decodeTxSig bch (hex (sigDerHex <> "c3")) `shouldBe` Right (TxSignature sig 0xc3)
  it "reads the empty string as an empty signature" $
    decodeTxSig btc "" `shouldBe` Right TxSignatureEmpty
  it "requires the SIGHASH_FORKID flag exactly on networks with a fork id" $ do
    decodeTxSig btc (hex (sigDerHex <> "41")) `shouldSatisfy` isLeft
    decodeTxSig btc (hex (sigDerHex <> "c1")) `shouldSatisfy` isLeft
    decodeTxSig bch (hex (sigDerHex <> "01")) `shouldSatisfy` isLeft
    decodeTxSig bch (hex (sigDerHex <> "81")) `shouldSatisfy` isLeft
  it "rejects a hash type byte that no node accepts" $
    forM_ ["00", "04", "20", "21", "ff"] $ \sh ->
      (sh, decodeTxSig btc (hex (sigDerHex <> sh))) `shouldSatisfy` (isLeft . snd)
  it "rejects a signature with a high S, the LOW_S rule of the relay policy" $ do
    -- r = 1 and s = n - 1. The encoding is strict DER, and consensus
    -- accepts it. decodeStrictSig reads it, decodeTxSig does not.
    let highS = "3026020101022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
    decodeTxSig btc (hex (highS <> "01"))
      `shouldBe` Left "Failed reading: Non-canonical signature: S value is unnecessarily high\nEmpty call stack\n"
    isJust (decodeStrictSig (hex highS)) `shouldBe` True
  it "names the rule when it rejects an undefined hash type byte, the STRICTENC rule" $
    decodeTxSig btc (hex (sigDerHex <> "04"))
      `shouldBe` Left "Failed reading: Non-canonical signature: unknown hashtype byte\nEmpty call stack\n"
  it "rejects a signature whose r is padded with a zero byte, the DERSIG rule of BIP 66" $
    -- 02 02 00 01 is the integer 1 with a needless leading zero
    decodeTxSig btc (hex "300702020001020101" <> "\x01") `shouldSatisfy` isLeft
  it "rejects bytes after the hash type byte" $
    decodeTxSig btc (hex (sigDerHex <> "0101")) `shouldSatisfy` isLeft
  it "rejects bytes after the hash type byte in the binary form too" $
    (unmarshal btc (hex (sigDerHex <> "01deadbeef")) :: Either String TxSignature)
      `shouldSatisfy` isLeft
  it "does not read a Schnorr signature on Bitcoin Cash, which this type cannot hold" $
    -- 64 bytes and the hash type byte 0x41. Bitcoin Cash Node takes a
    -- 64-byte signature as Schnorr.
    decodeTxSig bch (B.replicate 64 0x11 <> "\x41") `shouldSatisfy` isLeft
  it "does not read an ECDSA signature of 64 bytes on Bitcoin Cash, where a node reads a Schnorr signature" $
    -- r and s take 29 bytes each: 6 + 29 + 29 = 64
    decodeTxSig bch (hex (shortDerHex <> "41"))
      `shouldBe` Left
        "Failed reading: Non-canonical signature: a signature of 64 bytes is a Schnorr signature on this network\n\
        \Empty call stack\n"
  it "reads an ECDSA signature of 64 bytes on Bitcoin, where a block may hold it" $
    decodeTxSig btc (hex (shortDerHex <> "01")) `shouldSatisfy` isRight
  it "does not read SIGHASH_UTXOS on Bitcoin Cash, which the digest does not support" $
    -- 0x61 is SIGHASH_ALL with SIGHASH_UTXOS and SIGHASH_FORKID
    decodeTxSig bch (hex (sigDerHex <> "61"))
      `shouldBe` Left "Failed reading: Non-canonical signature: unknown hashtype byte\nEmpty call stack\n"
  it "rejects a signature without a hash type byte" $
    decodeTxSig btc (hex sigDerHex) `shouldSatisfy` isLeft
  it "rejects a signature that is not strict DER" $
    decodeTxSig btc (hex ("3045022100" <> T.drop 8 sigDerHex <> "01")) `shouldSatisfy` isLeft
  it "marshals a signature to JSON as its hex" $ do
    marshalValue btc (TxSignature sig sigHashAll) `shouldBe` A.String (sigDerHex <> "01")
    A.parseMaybe (unmarshalValue btc) (A.String (sigDerHex <> "01")) `shouldBe` Just (TxSignature sig sigHashAll)
    A.parseMaybe (unmarshalValue btc) (A.String (sigDerHex <> "41")) `shouldBe` (Nothing :: Maybe TxSignature)

{- Per-network properties and vectors -}

props :: Network -> Spec
props net = do
  standardSpec net
  strictSigSpec net
  scriptSpec net
  txSigHashForkIdSpec net
  forkIdScriptSpec net
  sigHashSpec net
  txSigHashSpec net

standardSpec :: Network -> Spec
standardSpec net = do
  prop "has decodeOutput . encodeOutput identity" $
    forAll (arbitraryScriptOutput net) $ \so ->
      (decodeOutput =<< encodeOutput so) `shouldBe` Right so
  prop "has decodeInput . encodeInput identity" $
    forAll (arbitraryScriptInput net) $ \si ->
      (decodeInput net . encodeInput net) si `shouldBe` Right si
  prop "gives every encodable output a script that decodes to it" $
    forAll (arbitraryScriptOutput net) $ \so ->
      decodeSerial (encodeSerial so) `shouldBe` Right so

-- | The file @data/script_tests.json@ is not the @script_tests.json@ of
-- Bitcoin Core, which has more than a thousand vectors for its interpreter.
-- It is a selection of 86 of them on the standard templates, edited for a
-- library without an interpreter:
--
-- * 41 vectors carry the word DISABLED in their flags and do not run. They
--   need script execution or a rule this library does not have.
--
-- * 9 vectors that Bitcoin Core expects to pass without a policy flag have
--   the result NONSTRICT in place of OK. The signature or the input of each
--   one breaks a relay rule, such as strict DER, a low S, a defined hash type
--   or an empty dummy element. This library reads the relay form only, so it
--   refuses them.
--
-- * One vector, about the fork id flag, is not in Bitcoin Core.
--
-- So 45 vectors run: 9 valid spends and 36 refusals.
scriptSpec :: Network -> Spec
scriptSpec net =
  when (net.name == "btc") $
    it "verifies the 45 standard-template vectors selected from script_tests.json of Bitcoin Core" $ do
      xs <- readTestFile "script_tests.json" :: IO [A.Value]
      let vectorsA =
            mapMaybe (A.decode . A.encode) xs ::
              [(String, String, String, String, String)]
          vectorsB =
            mapMaybe (A.decode . A.encode) xs ::
              [([Word64], String, String, String, String, String)]
          vectors =
            map (\(a, b, c, d, e) -> ([0], a, b, c, d, e)) vectorsA
              <> vectorsB
          -- A vector is disabled by the word DISABLED in its flags
          enabled = [v | v@(_, _, _, flags, _, _) <- vectors, not ("DISABLED" `isInfixOf` flags)]
      length vectors `shouldBe` 86
      length enabled `shouldBe` 45
      length [() | (_, _, _, _, "OK", _) <- enabled] `shouldBe` 9
      forM_ enabled $ \([val], siStr, soStr, _, res, desc) -> do
        let scriptSig = parseScript siStr
            scriptPubKey = parseScript soStr
            out = decodeSerial scriptPubKey
            sat = val * 100000000
            tx = spendTx scriptPubKey sat scriptSig
            ver o = verifyStdInput net tx [(o, sat, (head tx.inputs).outpoint)] 0
            valid = either (const False) ver out
        assertBool desc $ if res == "OK" then valid else not valid
        -- A vector refused for the form of its input, not for a wrong
        -- signature, must already fail to read as a standard input. That
        -- tells such a refusal from an unrelated one.
        when (res `elem` encodingErrors) $
          assertBool (desc <> ": the input is not in the relay form") $
            isLeft (decodeInput net =<< runGetS deserialize scriptSig)
  where
    -- The results of Bitcoin Core that name a rule on the form of an input,
    -- and NONSTRICT, which this file uses for a form only consensus accepts
    encodingErrors =
      [ "SIG_DER",
        "SIG_HASHTYPE",
        "SIG_NULLDUMMY",
        "SIG_PUSHONLY",
        "CLEANSTACK",
        "ILLEGAL_FORKID",
        "NONSTRICT"
      ]

forkIdScriptSpec :: Network -> Spec
forkIdScriptSpec net =
  when (isJust net.sigHashForkId) $
    it "can verify scripts from forkid_script_tests.json file" $ do
      xs <- readTestFile "forkid_script_tests.json" :: IO [A.Value]
      let vectors =
            mapMaybe (A.decode . A.encode) xs ::
              [ ( [Word64],
                  String,
                  String,
                  String,
                  String,
                  String
                )
              ]
      length vectors `shouldBe` 3
      forM_ vectors $ \([valBTC], siStr, soStr, _, res, _) -> do
        let val = valBTC * 100000000
            scriptSig = parseScript siStr
            scriptPubKey = parseScript soStr
            out = decodeSerial scriptPubKey
            tx = spendTx scriptPubKey val scriptSig
            ver o = verifyStdInput net tx [(o, val, (head tx.inputs).outpoint)] 0
            valid = either (const False) ver out
        case res of
          "OK" -> valid `shouldBe` True
          _ -> valid `shouldBe` False

creditTx :: ByteString -> Word64 -> Tx
creditTx scriptPubKey val =
  Tx 1 [txI] [txO] [] 0
  where
    txO = TxOut {value = val, script = scriptPubKey}
    txI =
      TxIn
        { outpoint = nullOutPoint,
          script = runPutS $ serialize $ Script [OP_0, OP_0],
          sequence = maxBound
        }

spendTx :: ByteString -> Word64 -> ByteString -> Tx
spendTx scriptPubKey val scriptSig =
  Tx 1 [txI] [txO] [] 0
  where
    txO = TxOut {value = val, script = B.empty}
    txI =
      TxIn
        { outpoint = OutPoint (txHash $ creditTx scriptPubKey val) 0,
          script = scriptSig,
          sequence = maxBound
        }

parseScript :: String -> ByteString
parseScript str =
  B.concat $ fromMaybe err $ mapM f $ words str
  where
    f = decodeHex . cs . dropHex . replaceToken
    dropHex ('0' : 'x' : xs) = xs
    dropHex xs = xs
    err = error $ "Could not decode script: " <> str

replaceToken :: String -> String
replaceToken str = case readMaybe $ "OP_" <> str of
  Just opcode -> "0x" <> cs (encodeHex $ runPutS $ serialize (opcode :: ScriptOp))
  _ -> str

strictSigSpec :: Network -> Spec
strictSigSpec net =
  when (net.name == "btc") $ do
    it "can decode strict signatures" $ do
      xs <- readTestFile "sig_strict.json"
      let vectors = mapMaybe decodeHex xs
      length vectors `shouldBe` 3
      forM_ vectors $ \sig ->
        let eitherSig :: Either String TxSignature
            eitherSig = decodeTxSig net sig
         in eitherSig `shouldSatisfy` isRight
    it "refuses the non-strict signatures, each for the rule its label names" $ do
      xs <- readTestFile "sig_nonstrict.json" :: IO [Text]
      -- The file is a list of labels, each followed by the signatures it
      -- describes. A signature is DER followed by a hash type byte.
      let labelled = [(label, sig) | (label, Just sig) <- zip (labelsOf xs) (map decodeHex xs)]
      length labelled `shouldBe` 17
      forM_ labelled $ \(label, sig) -> do
        let name = cs label <> " " <> cs (encodeHex sig)
            strictDer = isJust (decodeStrictSig (B.init sig))
            refusal = either id (const "accepted") (decodeTxSig net sig)
        case label of
          -- Strict DER, and a hash type byte that is not defined
          "hashtype:" -> do
            assertBool name strictDer
            assertBool name ("unknown hashtype byte" `isInfixOf` refusal)
          -- Strict DER, and an S above half the curve order
          "High S:" -> do
            assertBool name strictDer
            assertBool name ("S value is unnecessarily high" `isInfixOf` refusal)
          -- Every other label names a rule of BIP 66
          _ -> do
            assertBool name (not strictDer)
            assertBool name (refusal /= "accepted")

-- | The label that describes each entry of @sig_nonstrict.json@: an entry
-- that is not hex is a label, and it holds for the entries after it.
labelsOf :: [Text] -> [Text]
labelsOf = drop 1 . scanl (\label x -> if isNothing (decodeHex x) then x else label) ""

txSigHashSpec :: Network -> Spec
txSigHashSpec net =
  when (net.name == "btc") $
    it "can produce valid sighashes from sighash.json test vectors" $ do
      xs <- readTestFile "sighash.json" :: IO [A.Value]
      let vectors =
            mapMaybe (A.decode . A.encode) xs ::
              [ ( String,
                  String,
                  Int,
                  Integer,
                  String
                )
              ]
      length vectors `shouldBe` 500
      forM_ vectors $ \(txStr, scpStr, i, shI, resStr) -> do
        let tx = fromString txStr
            s =
              fromMaybe (error $ "Could not decode script: " <> cs scpStr) $
                eitherToMaybe . runGetS deserialize =<< decodeHex (cs scpStr)
            sh = fromIntegral shI
            res =
              eitherToMaybe . runGetS deserialize . B.reverse
                =<< decodeHex (cs resStr)
        -- A vector that did not decode would compare Nothing with Nothing
        res `shouldSatisfy` isJust
        eitherToMaybe (txSigHash net tx s 0 i sh) `shouldBe` res

txSigHashForkIdSpec :: Network -> Spec
txSigHashForkIdSpec net =
  when (net.name == "btc") $
    -- The file holds the thirteen digests of the examples of BIP 143. None
    -- has the SIGHASH_FORKID bit, so they run on Bitcoin. The fork id digest
    -- of Bitcoin Cash has literal values in the digest tests above.
    it "computes the thirteen BIP 143 digests of forkid_sighash.json" $ do
      xs <- readTestFile "forkid_sighash.json" :: IO [A.Value]
      let vectors =
            mapMaybe (A.decode . A.encode) xs ::
              [ ( String,
                  String,
                  Int,
                  Word64,
                  Integer,
                  String
                )
              ]
      length vectors `shouldBe` 13
      forM_ vectors $ \(txStr, scpStr, i, val, shI, resStr) -> do
        let tx = fromString txStr
            s =
              fromMaybe (error $ "Could not decode script: " <> cs scpStr) $
                eitherToMaybe . runGetS deserialize =<< decodeHex (cs scpStr)
            sh = fromIntegral shI
            res = eitherToMaybe . runGetS deserialize =<< decodeHex (cs resStr)
        res `shouldSatisfy` isJust
        eitherToMaybe (txSigHashForkId net tx s val i sh) `shouldBe` res

sigHashSpec :: Network -> Spec
sigHashSpec net = do
  it "can decodeTxSig . encode a TxSignature" $
    property $
      forAll (arbitraryTxSignature net) $ \(_, _, ts) ->
        let f = decodeTxSig net . encodeTxSig net
         in f ts `shouldBe` Right ts
  if isNothing net.sigHashForkId
    then
      it "can produce the sighash one" $
        property $
          forAll (arbitraryTx net) $
            forAll arbitraryScript . testSigHashOne net
    else it "never produces the sighash one, since the fork id digest has no such case" $
      property $
        forAll (arbitraryTx net) $ \tx ->
          forAll arbitraryScript $ \s ->
            not (null tx.inputs) ==>
              txSigHash net tx s 0 (length tx.inputs - 1) (setForkIdFlag sigHashSingle)
                `shouldSatisfy` \res -> isRight res && res /= Right sigHashOne

-- | The digest that the legacy algorithm gives for SIGHASH_SINGLE without a
-- matching output.
sigHashOne :: Hash256
sigHashOne = "0100000000000000000000000000000000000000000000000000000000000000"

testSigHashOne :: Network -> Tx -> Script -> Word64 -> Bool -> Property
testSigHashOne net tx s val acp =
  not (null tx.inputs) ==>
    if length tx.inputs > length tx.outputs
      then res `shouldBe` Right sigHashOne
      else res `shouldNotBe` Right sigHashOne
  where
    res = txSigHash net tx s val (length tx.inputs - 1) (f sigHashSingle)
    f =
      if acp
        then setAnyoneCanPay
        else id

{- Parse tests from bitcoin-qt repository -}

mapMulSigVector :: ((Text, Text), Int) -> Spec
mapMulSigVector (v, i) =
  it name $ runMulSigVector v
  where
    name = "check multisig vector " <> show i

runMulSigVector :: (Text, Text) -> Assertion
runMulSigVector (a, ops) = assertBool "multisig vector" $ Just a == b
  where
    s = do
      s' <- decodeHex ops
      eitherToMaybe $ runGetS deserialize s'
    b = do
      o <- s
      d <- eitherToMaybe $ decodeOutput o
      addrToText btc =<< eitherToMaybe (payToScriptAddress d)

sigDecodeMap :: Network -> (Text, Int) -> Spec
sigDecodeMap net (_, i) =
  it ("check signature " ++ show i) func
  where
    func = testSigDecode net $ scriptSigSignatures !! i

testSigDecode :: Network -> Text -> Assertion
testSigDecode net str =
  let bs = fromJust $ decodeHex str
      eitherSig = decodeTxSig net bs
   in assertBool
        ( unwords
            [ "Decode failed:",
              fromLeft (error "Decode did not fail") eitherSig
            ]
        )
        $ isRight eitherSig

mulSigVectors :: [(Text, Text)]
mulSigVectors =
  [ ( "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
      "52410491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb\
      \129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8\
      \334f864104865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253\
      \e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccf\
      \fef4ec687441048d2455d2403e08708fc1f556002f1b6cd83f992d085097f997\
      \4ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f\
      \322a1863d4621353ae"
    )
  ]

scriptSigSignatures :: [Text]
scriptSigSignatures =
  -- Signature in input of txid
  -- 1983a69265920c24f89aac81942b1a59f7eb30821a8b3fb258f88882b6336053
  [ "304402205ca6249f43538908151fe67b26d020306c0e59fa206cf9f3ccf641f333\
    \57119d02206c82f244d04ac0a48024fb9cc246b66e58598acf206139bdb7b75a29\
    \41a2b1e401"
    -- Signature in input of txid
    -- fb0a1d8d34fa5537e461ac384bac761125e1bfa7fec286fa72511240fa66864d.
    -- Strange DER sizes, but in Blockchain. Now invalid as Haskoin can only
    -- decode strict signatures.
    -- "3048022200002b83d59c1d23c08efd82ee0662fec23309c3adbcbd1f0b8695378d\
    -- \b4b14e736602220000334a96676e58b1bb01784cb7c556dd8ce1c220171904da22\
    -- \e18fe1e7d1510db501"
  ]

encodeScriptVector :: Assertion
encodeScriptVector =
  assertEqual "Encode script" res (encodeHex $ runPutS $ serialize s)
  where
    res =
      "514104cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58b\
      \bfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d\
      \348ac4410461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2f\
      \cfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b\
      \25c15342af52ae"
    s =
      Script
        [ OP_1,
          opPushData $
            d
              "04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef5\
              \8bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d\
              \11fcdd0d348ac4",
          opPushData $
            d
              "0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcf\
              \deb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39\
              \f58b25c15342af",
          OP_2,
          OP_CHECKMULTISIG
        ]
    d = fromJust . decodeHex
