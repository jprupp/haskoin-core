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

identityTests :: Ctx -> IdentityTests
identityTests ctx =
  def
    { readTests =
        [ ReadBox arbitrarySigHash,
          ReadBox arbitrarySigHashFlag,
          ReadBox arbitraryScript,
          ReadBox arbitraryPushDataType,
          ReadBox arbitraryScriptOp,
          ReadBox ((`arbitraryScriptOutput` ctx) =<< arbitraryNetwork),
          ReadBox ((`arbitraryScriptInput` ctx) =<< arbitraryNetwork)
        ],
      jsonTests =
        [ JsonBox arbitraryScript,
          JsonBox arbitraryOutPoint,
          JsonBox arbitrarySigHash
        ],
      marshalJsonTests =
        [ MarshalJsonBox $ do
            n <- arbitraryNetwork
            (_, _, ts) <- arbitraryTxSignature n ctx
            return ((n, ctx), ts),
          MarshalJsonBox $ do
            n <- arbitraryNetwork
            o <- arbitraryScriptOutput n ctx
            return (ctx, o),
          MarshalJsonBox $ do
            n <- arbitraryNetwork
            (i, _) <- arbitrarySigInput n ctx
            return (ctx, i)
        ],
      serialTests =
        [ SerialBox arbitraryScriptOp,
          SerialBox arbitraryScript
        ],
      marshalTests =
        [ MarshalBox $ do
            n <- arbitraryNetwork
            (_, _, ts) <- arbitraryTxSignature n ctx
            return ((n, ctx), ts),
          MarshalBox $ do
            n <- arbitraryNetwork
            o <- arbitraryScriptOutput n ctx
            return (ctx, o),
          MarshalBox $ do
            n <- arbitraryNetwork
            i <- arbitraryScriptInput n ctx
            return ((n, ctx), i)
        ]
    }

spec :: Spec
spec = prepareContext $ \ctx -> do
  testIdentity $ identityTests ctx
  describe "opcodes" opcodeSpec
  describe "push operations" pushSpec
  describe "small integer opcodes" smallIntSpec
  describe "standard outputs" $ outputSpec ctx
  describe "standard inputs" $ inputSpec ctx
  describe "sighash types" sigHashTypeSpec
  describe "sighash digests" $ digestSpec ctx
  describe "transaction signatures" $ txSignatureSpec ctx
  describe "btc scripts" $ props btc ctx
  describe "bch scripts" $ props bch ctx
  describe "multi signatures" $
    zipWithM_ (curry (mapMulSigVector ctx)) mulSigVectors [0 ..]
  describe "signature decoding" $
    zipWithM_ (curry (sigDecodeMap btc ctx)) scriptSigSignatures [0 ..]
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

gKey :: Ctx -> PublicKey
gKey ctx = either error id $ unmarshal ctx $ hex gKeyHex

gHash :: Hash160
gHash = "751e76e8199196d454941c45d1b3a323f1433bd6"

-- | The two keys of the first BIP 67 test vector, in the order the vector
-- lists them before sorting.
bip67KeyA, bip67KeyB :: Text
bip67KeyA = "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8"
bip67KeyB = "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f"

bip67Key :: Ctx -> Text -> PublicKey
bip67Key ctx = either error id . unmarshal ctx . hex

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

sigDer :: Ctx -> Sig
sigDer ctx = fromJust $ decodeStrictSig ctx $ hex sigDerHex

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

-- | The scriptCode of the second input of that transaction: the P2PKH script
-- of the key that the P2WPKH output pays to.
bip143ScriptCode :: Script
bip143ScriptCode =
  either error id $
    runGetS deserialize $
      hex "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"

-- | The value of the output that the second input spends: 6 BTC.
bip143Value :: Word64
bip143Value = 600000000

-- | The digest BIP 143 gives for that input with SIGHASH_ALL.
bip143Digest :: Hash256
bip143Digest = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"

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
    (0xfc, OP_INVALIDOPCODE 0xfc),
    (0xfd, OP_PUBKEYHASH),
    (0xfe, OP_PUBKEY),
    (0xff, OP_INVALIDOPCODE 0xff)
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
    it "is true for the shortest encoding of the data" $
      forM_
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
    it "is false for a longer encoding of the same data" $
      forM_
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
standardOutputs :: Ctx -> [(String, Text, ScriptOutput)]
standardOutputs ctx =
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
    ("2-of-2 multisig", bip67ScriptHex, PayMulSig [bip67Key ctx bip67KeyB, bip67Key ctx bip67KeyA] 2),
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
    g = gKey ctx
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
    -- Wrong lengths.
    ("witness v0 of 25 bytes", "0019" <> T.replicate 25 "01"),
    ("witness v1 of 41 bytes", "5129" <> T.replicate 41 "01"),
    ("witness v1 of 1 byte", "510101"),
    ("P2PKH with a 19-byte hash", "76a913" <> T.replicate 19 "ab" <> "88ac"),
    ("P2SH with a 21-byte hash", "a915" <> T.replicate 21 "ab" <> "87"),
    -- A key must fill its push.
    ("P2PK with 32 bytes after a compressed key", "41" <> gKeyHex <> thirtyTwo <> "ac"),
    ("multisig with 32 bytes after a compressed key", "5141" <> gKeyHex <> thirtyTwo <> "51ae"),
    ("P2PK with a 32-byte key", "20" <> thirtyTwo <> "ac"),
    -- Multisig counts.
    ("multisig with a count of 0", "0021" <> gKeyHex <> "51ae"),
    ("multisig with OP_1NEGATE as count", "4f21" <> gKeyHex <> "51ae"),
    ("multisig with 1 as a byte push", "010121" <> gKeyHex <> "0101ae"),
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

outputSpec :: Ctx -> Spec
outputSpec ctx = do
  let g = gKey ctx
      decodeHexOutput = unmarshal ctx . hex :: Text -> Either String ScriptOutput
      encodeHexOutput = fmap (encodeHex . runPutS . serialize) . encodeOutput ctx
  it "decodes the standard output templates" $
    forM_ (standardOutputs ctx) $ \(name, h, out) ->
      (name, decodeHexOutput h) `shouldBe` (name, Right out)
  it "encodes the standard outputs to their templates" $
    forM_ (standardOutputs ctx) $ \(name, h, out) ->
      (name, encodeHexOutput out) `shouldBe` (name, Right h)
  it "rejects scripts that only look like a standard output" $
    forM_ nonStandardOutputs $ \(name, h) ->
      (name, decodeHexOutput h) `shouldSatisfy` (isLeft . snd)
  it "accepts a multisig key pushed with OP_PUSHDATA1, as the solver of Bitcoin Core does" $
    decodeHexOutput ("514c21" <> gKeyHex <> "51ae") `shouldBe` Right (PayMulSig [g] 1)
  it "has 20 as the most multisig keys" $
    maxMultisigKeys `shouldBe` 20
  it "refuses to encode a multisig that no script can express" $ do
    encodeOutput ctx (PayMulSig [] 0) `shouldSatisfy` isLeft
    encodeOutput ctx (PayMulSig [g] 0) `shouldSatisfy` isLeft
    encodeOutput ctx (PayMulSig [g] 2) `shouldSatisfy` isLeft
    encodeOutput ctx (PayMulSig (replicate 21 g) 1) `shouldSatisfy` isLeft
  it "refuses to encode a witness program outside the versions and lengths of BIP 141" $ do
    encodeOutput ctx (PayWitness 0 (B.replicate 20 1)) `shouldSatisfy` isLeft
    encodeOutput ctx (PayWitness 17 (B.replicate 20 1)) `shouldSatisfy` isLeft
    encodeOutput ctx (PayWitness 1 "\x01") `shouldSatisfy` isLeft
    encodeOutput ctx (PayWitness 1 (B.replicate 41 1)) `shouldSatisfy` isLeft
  it "fails with an error call when marshalling an output that cannot be encoded" $
    evaluate (marshal ctx (PayMulSig [] 0)) `shouldThrow` anyErrorCall
  it "marshals an output to JSON as the hex of its script" $ do
    marshalValue ctx (PayPKHash gHash) `shouldBe` A.String "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
    A.parseMaybe (unmarshalValue ctx) (A.String "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac")
      `shouldBe` Just (PayPKHash gHash)
    A.parseMaybe (unmarshalValue ctx) (A.String ("004c14" <> T.replicate 20 "ab"))
      `shouldBe` (Nothing :: Maybe ScriptOutput)
  describe "toP2SH and toP2WSH" $ do
    it "hashes the redeem script of the P2SH-P2WPKH example of BIP 143" $
      toP2SH (Script [OP_0, opPushData (hex "79091972186c449eb1ded22b78e40d009bdf0089")])
        `shouldBe` PayScriptHash "4733f37cf4db86fbc2efed2500b4f4e49f312023"
    it "hashes the witness script of the P2WSH example of BIP 143" $
      toP2WSH bip143WitnessScript
        `shouldBe` PayWitnessScriptHash "5d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0"
  describe "sortMulSig" $ do
    it "sorts the keys of the first BIP 67 test vector" $ do
      let unsorted = PayMulSig [bip67Key ctx bip67KeyA, bip67Key ctx bip67KeyB] 2
      encodeHexOutput (sortMulSig ctx unsorted) `shouldBe` Right bip67ScriptHex
      addrToText btc (payToScriptAddress ctx (sortMulSig ctx unsorted))
        `shouldBe` Just "39bgKC7RFbpoCRbtD5KEdkYKtNyhpsNa3Z"
    it "leaves any other output unchanged" $
      sortMulSig ctx (PayPKHash gHash) `shouldBe` PayPKHash gHash
    prop "sorts the keys by their serialized bytes" $
      forAll (arbitraryMSOutput ctx) $ \out ->
        let keyList = map (marshal ctx) (sortMulSig ctx out).keys
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
standardInputs :: Ctx -> [(String, Text, ScriptInput)]
standardInputs ctx =
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
    g = gKey ctx
    sig = TxSignature (sigDer ctx) sigHashAll
    multisig = PayMulSig [bip67Key ctx bip67KeyB, bip67Key ctx bip67KeyA] 2

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
    ("a nested witness program of version 1", "22512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"),
    ("a redeem script alone that is not a witness program", "2321" <> gKeyHex <> "ac"),
    ("a non-push opcode", "76")
  ]

inputSpec :: Ctx -> Spec
inputSpec ctx = do
  let g = gKey ctx
      decodeHexInput = unmarshal (btc, ctx) . hex :: Text -> Either String ScriptInput
      encodeHexInput = encodeHex . marshal (btc, ctx)
  it "decodes the standard input scripts" $
    forM_ (standardInputs ctx) $ \(name, h, inp) ->
      (name, decodeHexInput h) `shouldBe` (name, Right inp)
  it "encodes the standard inputs to their scripts" $
    forM_ (standardInputs ctx) $ \(name, h, inp) ->
      (name, encodeHexInput inp) `shouldBe` (name, h)
  it "rejects scripts that are not a standard input" $
    forM_ nonStandardInputs $ \(name, h) ->
      (name, decodeHexInput h) `shouldSatisfy` (isLeft . snd)
  it "reads a single empty push as a pay-to-public-key input with an empty signature" $ do
    -- The same script is a multisig input without signatures. Without the
    -- output script, the single-signature reading is taken.
    decodeInput btc ctx (Script [OP_0]) `shouldBe` Right (RegularInput (SpendPK TxSignatureEmpty))
    decodeInput btc ctx (Script [OP_0, OP_0]) `shouldBe` Right (RegularInput (SpendMulSig [TxSignatureEmpty]))
    decodeInput btc ctx (Script [OP_0, OP_0, OP_0, OP_0])
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
  it "serializes to JSON as a number and reads only 32-bit values" $ do
    A.encode (0x81 :: SigHash) `shouldBe` "129"
    A.decode "129" `shouldBe` Just (0x81 :: SigHash)
    A.decode "-1" `shouldBe` (Nothing :: Maybe SigHash)
    A.decode "4294967296" `shouldBe` (Nothing :: Maybe SigHash)
    A.decode "1.5" `shouldBe` (Nothing :: Maybe SigHash)

{- Digests -}

digestSpec :: Ctx -> Spec
digestSpec ctx = do
  it "computes the BIP 143 digest of the P2WPKH example" $
    txSigHashForkId btc bip143Tx bip143ScriptCode bip143Value 1 sigHashAll
      `shouldBe` Right bip143Digest
  it "appends the hash type as four bytes, so other flags change the digest" $
    txSigHashForkId btc bip143Tx bip143ScriptCode bip143Value 1 (setAnyoneCanPay sigHashAll)
      `shouldNotBe` Right bip143Digest
  it "fails for an input index the transaction does not have" $ do
    txSigHash btc bip143Tx bip143ScriptCode bip143Value 2 sigHashAll `shouldSatisfy` isLeft
    txSigHash btc bip143Tx bip143ScriptCode bip143Value (-1) sigHashAll `shouldSatisfy` isLeft
    txSigHashForkId btc bip143Tx bip143ScriptCode bip143Value 2 sigHashAll `shouldSatisfy` isLeft
    txSigHashForkId btc bip143Tx bip143ScriptCode bip143Value (-1) sigHashAll `shouldSatisfy` isLeft
  it "removes OP_CODESEPARATOR from the script code of the legacy digest, as FindAndDelete does" $
    txSigHash btc bip143Tx (Script (OP_CODESEPARATOR : bip143ScriptCode.ops)) bip143Value 1 sigHashAll
      `shouldBe` txSigHash btc bip143Tx bip143ScriptCode bip143Value 1 sigHashAll
  it "keeps OP_CODESEPARATOR in the script code of the BIP 143 digest" $
    txSigHashForkId btc bip143Tx (Script (OP_CODESEPARATOR : bip143ScriptCode.ops)) bip143Value 1 sigHashAll
      `shouldNotBe` Right bip143Digest
  it "requires SIGHASH_FORKID on Bitcoin Cash" $
    txSigHash bch bip143Tx bip143ScriptCode bip143Value 1 sigHashAll `shouldSatisfy` isLeft
  it "uses the fork id digest on Bitcoin Cash" $ do
    txSigHash bch bip143Tx bip143ScriptCode bip143Value 1 (setForkIdFlag sigHashAll)
      `shouldBe` txSigHashForkId bch bip143Tx bip143ScriptCode bip143Value 1 (setForkIdFlag sigHashAll)
    -- The hash type 0x41 goes into the digest, so it differs from the
    -- Bitcoin digest of the same input with 0x01.
    txSigHash bch bip143Tx bip143ScriptCode bip143Value 1 (setForkIdFlag sigHashAll)
      `shouldNotBe` Right bip143Digest
  it "uses the legacy digest on Bitcoin even with the SIGHASH_FORKID flag" $
    txSigHash btc bip143Tx bip143ScriptCode bip143Value 1 (setForkIdFlag sigHashAll)
      `shouldNotBe` Right bip143Digest

{- Transaction signatures -}

txSignatureSpec :: Ctx -> Spec
txSignatureSpec ctx = do
  let sig = sigDer ctx
  it "writes the signature followed by its hash type byte" $ do
    encodeTxSig btc ctx (TxSignature sig sigHashAll) `shouldBe` hex (sigDerHex <> "01")
    encodeTxSig btc ctx (TxSignature sig 0x81) `shouldBe` hex (sigDerHex <> "81")
    encodeTxSig bch ctx (TxSignature sig 0x41) `shouldBe` hex (sigDerHex <> "41")
  it "writes an empty signature as the empty string" $
    encodeTxSig btc ctx TxSignatureEmpty `shouldBe` ""
  it "reads a signature with its hash type byte" $ do
    decodeTxSig btc ctx (hex (sigDerHex <> "01")) `shouldBe` Right (TxSignature sig 0x01)
    decodeTxSig btc ctx (hex (sigDerHex <> "82")) `shouldBe` Right (TxSignature sig 0x82)
    decodeTxSig bch ctx (hex (sigDerHex <> "c3")) `shouldBe` Right (TxSignature sig 0xc3)
  it "reads the empty string as an empty signature" $
    decodeTxSig btc ctx "" `shouldBe` Right TxSignatureEmpty
  it "requires the SIGHASH_FORKID flag exactly on networks with a fork id" $ do
    decodeTxSig btc ctx (hex (sigDerHex <> "41")) `shouldSatisfy` isLeft
    decodeTxSig btc ctx (hex (sigDerHex <> "c1")) `shouldSatisfy` isLeft
    decodeTxSig bch ctx (hex (sigDerHex <> "01")) `shouldSatisfy` isLeft
    decodeTxSig bch ctx (hex (sigDerHex <> "81")) `shouldSatisfy` isLeft
  it "rejects a hash type byte that no node accepts" $
    forM_ ["00", "04", "20", "21", "ff"] $ \sh ->
      (sh, decodeTxSig btc ctx (hex (sigDerHex <> sh))) `shouldSatisfy` (isLeft . snd)
  it "rejects bytes after the hash type byte" $
    decodeTxSig btc ctx (hex (sigDerHex <> "0101")) `shouldSatisfy` isLeft
  it "rejects a signature without a hash type byte" $
    decodeTxSig btc ctx (hex sigDerHex) `shouldSatisfy` isLeft
  it "rejects a signature that is not strict DER" $
    decodeTxSig btc ctx (hex ("3045022100" <> T.drop 8 sigDerHex <> "01")) `shouldSatisfy` isLeft
  it "marshals a signature to JSON as its hex" $ do
    marshalValue (btc, ctx) (TxSignature sig sigHashAll) `shouldBe` A.String (sigDerHex <> "01")
    A.parseMaybe (unmarshalValue (btc, ctx)) (A.String (sigDerHex <> "01")) `shouldBe` Just (TxSignature sig sigHashAll)
    A.parseMaybe (unmarshalValue (btc, ctx)) (A.String (sigDerHex <> "41")) `shouldBe` (Nothing :: Maybe TxSignature)

{- Per-network properties and vectors -}

props :: Network -> Ctx -> Spec
props net ctx = do
  standardSpec net ctx
  strictSigSpec net ctx
  scriptSpec net ctx
  txSigHashForkIdSpec net
  forkIdScriptSpec net ctx
  sigHashSpec net ctx
  txSigHashSpec net

standardSpec :: Network -> Ctx -> Spec
standardSpec net ctx = do
  prop "has decodeOutput . encodeOutput identity" $
    forAll (arbitraryScriptOutput net ctx) $ \so ->
      (decodeOutput ctx =<< encodeOutput ctx so) `shouldBe` Right so
  prop "has decodeInput . encodeInput identity" $
    forAll (arbitraryScriptInput net ctx) $ \si ->
      (decodeInput net ctx . encodeInput net ctx) si `shouldBe` Right si
  prop "gives every encodable output a script that decodes to it" $
    forAll (arbitraryScriptOutput net ctx) $ \so ->
      unmarshal ctx (marshal ctx so) `shouldBe` Right so

scriptSpec :: Network -> Ctx -> Spec
scriptSpec net ctx =
  when (net.name == "btc") $
    it "can verify standard scripts from script_tests.json file" $ do
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
      length vectors `shouldBe` 86
      forM_ vectors $ \([val], siStr, soStr, flags, res, desc) ->
        -- We can disable specific tests by adding a DISABLED flag in the data
        unless ("DISABLED" `isInfixOf` flags) $ do
          let scriptSig = parseScript siStr
              scriptPubKey = parseScript soStr
              out = unmarshal ctx scriptPubKey
              sat = val * 100000000
              tx = spendTx scriptPubKey sat scriptSig
              ver o = verifyStdInput net ctx tx [(o, sat, (head tx.inputs).outpoint)] 0
              valid = either (const False) ver out
          assertBool desc $ if res == "OK" then valid else not valid

forkIdScriptSpec :: Network -> Ctx -> Spec
forkIdScriptSpec net ctx =
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
            out = unmarshal ctx scriptPubKey
            tx = spendTx scriptPubKey val scriptSig
            ver o = verifyStdInput net ctx tx [(o, val, (head tx.inputs).outpoint)] 0
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

strictSigSpec :: Network -> Ctx -> Spec
strictSigSpec net ctx =
  when (net.name == "btc") $ do
    it "can decode strict signatures" $ do
      xs <- readTestFile "sig_strict.json"
      let vectors = mapMaybe decodeHex xs
      length vectors `shouldBe` 3
      forM_ vectors $ \sig ->
        let eitherSig :: Either String TxSignature
            eitherSig = decodeTxSig net ctx sig
         in eitherSig `shouldSatisfy` isRight
    it "can detect non-strict signatures" $ do
      xs <- readTestFile "sig_nonstrict.json"
      let vectors = mapMaybe decodeHex xs
      length vectors `shouldBe` 17
      forM_ vectors $ \sig ->
        let eitherSig = decodeTxSig net ctx sig
         in eitherSig `shouldSatisfy` isLeft

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
        eitherToMaybe (txSigHash net tx s 0 i sh) `shouldBe` res

txSigHashForkIdSpec :: Network -> Spec
txSigHashForkIdSpec net =
  when (net.name == "btc") $
    it "can produce valid sighashes from forkid_sighash.json test vectors" $ do
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
        eitherToMaybe (txSigHashForkId net tx s val i sh) `shouldBe` res

sigHashSpec :: Network -> Ctx -> Spec
sigHashSpec net ctx = do
  it "can decodeTxSig . encode a TxSignature" $
    property $
      forAll (arbitraryTxSignature net ctx) $ \(_, _, ts) ->
        let f = decodeTxSig net ctx . encodeTxSig net ctx
         in f ts `shouldBe` Right ts
  if isNothing net.sigHashForkId
    then
      it "can produce the sighash one" $
        property $
          forAll (arbitraryTx net ctx) $
            forAll arbitraryScript . testSigHashOne net
    else
      it "never produces the sighash one, since the fork id digest has no such case" $
        property $
          forAll (arbitraryTx net ctx) $ \tx ->
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

mapMulSigVector :: Ctx -> ((Text, Text), Int) -> Spec
mapMulSigVector ctx (v, i) =
  it name $ runMulSigVector ctx v
  where
    name = "check multisig vector " <> show i

runMulSigVector :: Ctx -> (Text, Text) -> Assertion
runMulSigVector ctx (a, ops) = assertBool "multisig vector" $ Just a == b
  where
    s = do
      s' <- decodeHex ops
      eitherToMaybe $ runGetS deserialize s'
    b = do
      o <- s
      d <- eitherToMaybe $ decodeOutput ctx o
      addrToText btc $ payToScriptAddress ctx d

sigDecodeMap :: Network -> Ctx -> (Text, Int) -> Spec
sigDecodeMap net ctx (_, i) =
  it ("check signature " ++ show i) func
  where
    func = testSigDecode net ctx $ scriptSigSignatures !! i

testSigDecode :: Network -> Ctx -> Text -> Assertion
testSigDecode net ctx str =
  let bs = fromJust $ decodeHex str
      eitherSig = decodeTxSig net ctx bs
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
