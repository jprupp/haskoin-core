{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.Crypto.SignatureSpec (spec) where

import Control.Monad
import Data.Bits (testBit)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Maybe
import Data.Serialize as S
import Data.String.Conversions (cs)
import Data.Text (Text)
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Script
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.HUnit
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

spec :: Spec
spec = prepareContext $ \ctx -> do
  describe "Signature property checks" $ do
    prop "verifies signature" $
      forAll (arbitrarySignature ctx) $ \(m, key', sig) ->
        verifyHashSig ctx m sig (derivePubKey ctx key')
    prop "s component less than half order" $
      forAll (arbitrarySignature ctx) $
        isCanonicalHalfOrder ctx . lst3
    prop "encoded signature is canonical" $
      forAll (arbitrarySignature ctx) $
        testIsCanonical ctx . lst3
    prop "decodeStrictSig . exportSig identity" $
      forAll (arbitrarySignature ctx) $
        (\s -> decodeStrictSig ctx (exportSig ctx s) == Just s) . lst3
    prop "importSig . exportSig identity" $
      forAll (arbitrarySignature ctx) $
        (\s -> importSig ctx (exportSig ctx s) == Just s) . lst3
    prop "signature JSON identity" $
      forAll (arbitrarySignature ctx) $
        (\s -> (unmarshalJSON ctx . marshalJSON ctx) s == Just s) . lst3
    prop "getSig . putSig identity" $
      forAll (arbitrarySignature ctx) $
        (\s -> unmarshal ctx (marshal ctx s) == Right s) . lst3
  describe "Signature vectors" $ do
    it "passes RFC6979 test vectors" $
      checkDistSig ctx $ \file1 file2 -> do
        vectors <- readTestFile file1 :: IO [(Text, Text, Text)]
        vectorsDER <- readTestFile file2 :: IO [(Text, Text, Text)]
        mapM_ (testRFC6979Vector ctx . toVector) vectors
        mapM_ (testRFC6979DERVector ctx . toVector) vectorsDER
  describe "BIP143 signature vectors" $ do
    it "agrees with BIP143 p2wpkh example" $
      testBip143p2wpkh ctx
    it "agrees with BIP143 p2sh-p2wpkh example" $
      testBip143p2shp2wpkh ctx
    it "builds a p2wsh multisig transaction" $
      testP2WSHMulsig ctx
    it "agrees with BIP143 p2sh-p2wsh multisig example" $
      testBip143p2shp2wpkhMulsig ctx

-- github.com/bitcoin/bitcoin/blob/master/src/script.cpp
-- from function IsCanonicalSignature
testIsCanonical :: Ctx -> Sig -> Bool
testIsCanonical ctx sig =
  not $
    -- Non-canonical signature: too short
    (len < 8)
      ||
      -- Non-canonical signature: too long
      (len > 72)
      ||
      -- Non-canonical signature: wrong type
      (BS.index s 0 /= 0x30)
      ||
      -- Non-canonical signature: wrong length marker
      (BS.index s 1 /= len - 2)
      ||
      -- Non-canonical signature: S length misplaced
      (5 + rlen >= len)
      ||
      -- Non-canonical signature: R+S length mismatch
      (rlen + slen + 6 /= len)
      ||
      -- Non-canonical signature: R value type mismatch
      (BS.index s 2 /= 0x02)
      ||
      -- Non-canonical signature: R length is zero
      (rlen == 0)
      ||
      -- Non-canonical signature: R value negative
      testBit (BS.index s 4) 7
      ||
      -- Non-canonical signature: R value excessively padded
      ( rlen > 1
          && BS.index s 4 == 0
          && not (testBit (BS.index s 5) 7)
      )
      ||
      -- Non-canonical signature: S value type mismatch
      (BS.index s (fromIntegral rlen + 4) /= 0x02)
      ||
      -- Non-canonical signature: S length is zero
      (slen == 0)
      ||
      -- Non-canonical signature: S value negative
      testBit (BS.index s (fromIntegral rlen + 6)) 7
      ||
      -- Non-canonical signature: S value excessively padded
      ( slen > 1
          && BS.index s (fromIntegral rlen + 6) == 0
          && not (testBit (BS.index s (fromIntegral rlen + 7)) 7)
      )
  where
    s = exportSig ctx sig
    len = fromIntegral $ BS.length s
    rlen = BS.index s 3
    slen = BS.index s (fromIntegral rlen + 5)

-- RFC6979 note: Different libraries of libsecp256k1 use different constants
-- to produce a nonce. Thus, their deterministric signatures will be different.
-- We still want to test against fixed signatures so we need a way to switch
-- between implementations. We check the output of signMsg 1 0

data ValidImpl
  = ImplCore
  | ImplCash

implSig :: Ctx -> Text
implSig ctx =
  encodeHex $
    exportSig ctx $
      signMsg
        ctx
        "0000000000000000000000000000000000000000000000000000000000000001"
        "0000000000000000000000000000000000000000000000000000000000000000"

-- We have test vectors for these cases
validImplMap :: Map Text ValidImpl
validImplMap =
  Map.fromList
    [ ( "3045022100a0b37f8fba683cc68f6574cd43b39f0343a50008bf6ccea9d13231\
        \d9e7e2e1e4022011edc8d307254296264aebfc3dc76cd8b668373a072fd64665\
        \b50000e9fcce52",
        ImplCore
      ),
      ( "304402200581361d23e645be9e3efe63a9a2ac2e8dd0c70ba3ac8554c9befe06\
        \0ad0b36202207d8172f1e259395834793d81b17e986f1e6131e4734969d2f4ae\
        \3a9c8bc42965",
        ImplCash
      )
    ]

getImpl :: Ctx -> Maybe ValidImpl
getImpl ctx = implSig ctx `Map.lookup` validImplMap

rfc6979files :: ValidImpl -> (FilePath, FilePath)
rfc6979files ImplCore = ("rfc6979core.json", "rfc6979DERcore.json")
rfc6979files ImplCash = ("rfc6979cash.json", "rfc6979DERcash.json")

checkDistSig :: Ctx -> (FilePath -> FilePath -> Assertion) -> Assertion
checkDistSig ctx go =
  case rfc6979files <$> getImpl ctx of
    Just (file1, file2) -> go file1 file2
    _ -> assertFailure "invalid RFC6979 signature"

{- Trezor RFC 6979 Test Vectors -}
-- github.com/trezor/python-ecdsa/blob/master/ecdsa/test_pyecdsa.py

toVector :: (Text, Text, Text) -> (SecKey, ByteString, Text)
toVector (prv, m, res) = (fromJust $ (secKey <=< decodeHex) prv, cs m, res)

testRFC6979Vector :: Ctx -> (SecKey, ByteString, Text) -> Assertion
testRFC6979Vector ctx (prv, m, res) = do
  assertEqual "RFC 6979 Vector" res (encodeHex (exportCompactSig ctx s).get)
  assertBool "Signature is valid" $ verifyHashSig ctx h s (derivePubKey ctx prv)
  assertBool "Signature is canonical" $ testIsCanonical ctx s
  assertBool "Signature is normalized" $ isCanonicalHalfOrder ctx s
  where
    h = sha256 m
    s = signHash ctx prv h

-- Test vectors from:
-- https://crypto.stackexchange.com/questions/20838/request-for-data-to-test-deterministic-ecdsa-signature-algorithm-for-secp256k1

testRFC6979DERVector :: Ctx -> (SecKey, ByteString, Text) -> Assertion
testRFC6979DERVector ctx (prv, m, res) = do
  assertEqual "RFC 6979 DER Vector" res (encodeHex $ exportSig ctx s)
  assertBool "DER Signature is valid" $ verifyHashSig ctx h s (derivePubKey ctx prv)
  assertBool "DER Signature is canonical" $ testIsCanonical ctx s
  assertBool "DER Signature is normalized" $ isCanonicalHalfOrder ctx s
  where
    h = sha256 m
    s = signHash ctx prv h

-- Reproduce the P2WPKH example from BIP 143
testBip143p2wpkh :: Ctx -> Assertion
testBip143p2wpkh ctx =
  case getImpl ctx of
    Just ImplCore ->
      assertEqual "BIP143 Core p2wpkh" (Right signedTxCore) generatedSignedTx
    Just ImplCash ->
      assertEqual "BIP143 ABC p2wpkh" (Right signedTxCash) generatedSignedTx
    Nothing -> assertFailure "Invalid secp256k1 library"
  where
    signedTxCore =
      "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433\
      \541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742f\
      \a9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1\
      \c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89\
      \d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffff\
      \ffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac\
      \7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0\
      \167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32\
      \a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f33\
      \58f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e\
      \7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
    signedTxCash =
      "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433\
      \541db4e4ad969f000000004847304402200fbc9dad97500334e47c2dca50096a\
      \2117c01952c2870102e320823d21c36229022007cb36c2b141d11c08ef81d948\
      \f148332fc09fe8f6d226aaaf8ba6ae0d8a66ba01eeffffffef51e1b804cc89d1\
      \82d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffff\
      \ff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a\
      \6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f016\
      \7faa815988ac0002473044022011cb891cee521eb1fc7aef681655a881288553\
      \fc024cff9cee5007bae5e6b8c602200b89d60ee2f98aa9a645dad59cd680b4b6\
      \25f343efcd3e7fb70852100ef601890121025476c2e83188368da1ff3e292e7a\
      \cafcdb3566bb0ad253f62fc70f07aeee635711000000"
    unsignedTx =
      "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541d\
      \b4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b\
      \1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb20600000000\
      \1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d0000\
      \00001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
    Just key0 =
      secHexKey
        "bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866"
    pubKey0 = toPubKey ctx key0
    Just key1 =
      secHexKey
        "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"
    [op0, op1] = (.outpoint) <$> unsignedTx.inputs
    sigIn0 = SigInput (PayPK pubKey0) 625000000 op0 sigHashAll Nothing
    Just h = addressHash160 . pubKeyWitnessAddr ctx $ toPubKey ctx key1
    sigIn1 = SigInput (PayWitnessPKHash h) 600000000 op1 sigHashAll Nothing
    generatedSignedTx = signTx btc ctx unsignedTx [sigIn0, sigIn1] [key0, key1]

-- Reproduce the P2SH-P2WPKH example from BIP 143
testBip143p2shp2wpkh :: Ctx -> Assertion
testBip143p2shp2wpkh ctx =
  case getImpl ctx of
    Just ImplCore ->
      assertEqual "BIP143 Core p2sh-p2wpkh" (Right signedTxCore) generatedSignedTx
    Just ImplCash ->
      assertEqual "BIP143 Cash p2sh-p2wpkh" (Right signedTxCash) generatedSignedTx
    Nothing -> assertFailure "Invalid secp256k1 library"
  where
    signedTxCore =
      "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092\
      \ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009b\
      \df0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bb\
      \c043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fe\
      \a7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a1\
      \0d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d\
      \877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c7\
      \4d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
    signedTxCash =
      "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092\
      \ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009b\
      \df0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bb\
      \c043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fe\
      \a7ad0402e8bd8ad6d77c88ac024730440220091c78fd1e21535f6ddc45515e4c\
      \afca15cdf344765d72c1529fb82d3ada2d1802204a980d5e37d0b04f5e1185a0\
      \f97295c383764e9a4b08d8bd1161b33c6719139a012103ad1d8e89212f0b92c7\
      \4d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
    unsignedTx =
      "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d\
      \3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7\
      \f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b\
      \1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
    Just key0 =
      secHexKey
        "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf"
    op0 = (head unsignedTx.inputs).outpoint
    Just h = addressHash160 . pubKeyWitnessAddr ctx $ toPubKey ctx key0
    sigIn0 = SigInput (PayWitnessPKHash h) 1000000000 op0 sigHashAll Nothing
    generatedSignedTx = signNestedWitnessTx btc ctx unsignedTx [sigIn0] [key0]

-- P2WSH multisig example (tested against bitcoin-core 0.19.0.1)
testP2WSHMulsig :: Ctx -> Assertion
testP2WSHMulsig ctx =
  case getImpl ctx of
    Just ImplCore ->
      assertEqual "Core p2wsh multisig" (Right signedTxCore) generatedSignedTx
    Just ImplCash ->
      assertEqual "Cash p2wsh multisig" (Right signedTxCash) generatedSignedTx
    Nothing -> assertFailure "Invalid secp256k1 library"
  where
    signedTxCore =
      "01000000000101d2e34df5d7ee565208eddd231548916b9b0e99f4f5071f8961\
      \34a448c5fb07bf0100000000ffffffff01f0b9f505000000001976a9143d5a35\
      \2cab583b12fbcb26d1269b4a2c951a33ad88ac0400483045022100fad4fedd2b\
      \b4c439c64637eb8e9150d9020a7212808b8dc0578d5ff5b4ad65fe0220714640\
      \f261b37eb3106310bf853f4b706e51436fb6b64c2ab00768814eb55b98014730\
      \44022100baff4e4ceea4022b9725a2e6f6d77997a554f858165b91ac8c16c983\
      \3008bee9021f5f70ebc3f8580dc0a5e96451e3697bdf1f1f5883944f0f33ab0c\
      \fb272354040169522102ba46d3bb8db74c77c6cf082db57fc0548058fcdea811\
      \549e186526e3d10caf6721038ac8aef2dd9cea5e7d66e2f6e23f177a6c21f69e\
      \a311fa0c85d81badb6b37ceb2103d96d2bfbbc040faaf93491d69e2bfe9695e2\
      \d8e007a7f26db96c2ee42db15dc953ae00000000"
    signedTxCash =
      "01000000000101d2e34df5d7ee565208eddd231548916b9b0e99f4f5071f8961\
      \34a448c5fb07bf0100000000ffffffff01f0b9f505000000001976a9143d5a35\
      \2cab583b12fbcb26d1269b4a2c951a33ad88ac0400483045022100b79bf3714a\
      \50f8f0e2f946034361ba4f6567b796d55910d89e98720d2e99f98c0220134879\
      \518002df23e80a058475fa8b10bc4182bedfecd5f85e446a00f211ea53014830\
      \45022100ce3c77480d664430a7544c1a962d1ae31151109a528a37e5bccc92ba\
      \2e460ad10220317bc9a71d0c3471058d16d4c3b1ea99616208db6b9b9040fb81\
      \0a7fa27f72b40169522102ba46d3bb8db74c77c6cf082db57fc0548058fcdea8\
      \11549e186526e3d10caf6721038ac8aef2dd9cea5e7d66e2f6e23f177a6c21f6\
      \9ea311fa0c85d81badb6b37ceb2103d96d2bfbbc040faaf93491d69e2bfe9695\
      \e2d8e007a7f26db96c2ee42db15dc953ae00000000"
    unsignedTx =
      "0100000001d2e34df5d7ee565208eddd231548916b9b0e99f4f5071f896134a4\
      \48c5fb07bf0100000000ffffffff01f0b9f505000000001976a9143d5a352cab\
      \583b12fbcb26d1269b4a2c951a33ad88ac00000000"
    op0 = (head unsignedTx.inputs).outpoint
    Just keys =
      traverse
        secHexKey
        [ "3030303030303030303030303030303030303030303030303030303030303031",
          "3030303030303030303030303030303030303030303030303030303030303032",
          "3030303030303030303030303030303030303030303030303030303030303033"
        ]
    rdm = PayMulSig (toPubKey ctx <$> keys) 2
    sigIn =
      SigInput
        (toP2WSH $ encodeOutput ctx rdm)
        100000000
        op0
        sigHashAll
        (Just rdm)
    generatedSignedTx = signTx btc ctx unsignedTx [sigIn] (take 2 keys)

-- Reproduce the P2SH-P2WSH multisig example from BIP 143
testBip143p2shp2wpkhMulsig :: Ctx -> Assertion
testBip143p2shp2wpkhMulsig ctx =
  case getImpl ctx of
    Just ImplCore ->
      assertEqual
        "BIP143 Core p2sh-p2wsh multisig"
        (Right signedTxCore)
        generatedSignedTx
    Just ImplCash ->
      assertEqual
        "BIP143 Core p2sh-p2wsh multisig"
        (Right signedTxCash)
        generatedSignedTx
    Nothing -> assertFailure "Invalid secp256k1 library"
  where
    signedTxCore =
      "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa10\
      \6c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b8\
      \9af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914\
      \389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976\
      \a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206a\
      \c44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b02\
      \20367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870\
      \ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1\
      \e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa26955\
      \78cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e613\
      \9ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9f\
      \e7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d5\
      \0b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf\
      \88f91265f5a942e96213afae16d83321c8b31bb342142a14d163814830450221\
      \00a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a4\
      \07022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e\
      \1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d\
      \8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa8\
      \4c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b33\
      \34e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c\
      \3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b97\
      \81957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a\
      \21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba0\
      \4d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b330\
      \2ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000"
    signedTxCash =
      "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa10\
      \6c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b8\
      \9af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914\
      \389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976\
      \a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac0800483045022100\
      \b70b684ef0d17b51adf71c0dae932beca5d447dd5eec03394328436bdba836e7\
      \0220208ebfd7408d21e41da11d8287655528385429d3fe300bee241f10944339\
      \5b580147304402204b5f9bc06c8f0a252b9842ea44785853beb1638002cec5f2\
      \489d73e5f6f5109302204f3b132b32638835d4b1a651e7d18dc93c10192db553\
      \999932af6a8e3d8a153202483045022100e0ed8d3a245a138c751d74e1359aee\
      \6a52476ddf33a3a9a5f0c2ad30147319650220581318187061ad0f48fc4f5c85\
      \1822e554d59977005b8de4b78bf2ce2fe8399703483045022100a0a40abc581e\
      \4b725775a3aa93bf0f0fd9a02ad3aa0f93483214784a47ba5387022069151c30\
      \f85a7e20c8671107c5af884ee4c5a82bd06398327fa68a993f7cc64b81473044\
      \022016d828460f6fab3cf89ae4b87c8f02c11c798cf739967f3b7406e7367c29\
      \ae8b022079e82b822eb6c37a66efabc3f0b40a2b98c52f848d36463f6623cbdc\
      \fe675812824730440220225a14ba7434858dbb5e6e0a0969ddf3b5455edaabf9\
      \9f5773d1f59e7816b918022047ed1ab87840a74f7e9489f3af051e5fd26b790f\
      \b308c79f4b0ed73c0422795d83cf56210307b8ae49ac90a048e9b53357a2354b\
      \3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac\
      \5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b\
      \9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a\
      \9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94b\
      \a04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3\
      \302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000"
    unsignedTx =
      "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1c\
      \a29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd\
      \9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a3\
      \3f950689af511e6e84c138dbbd3c3ee41588ac00000000"
    op0 = (head unsignedTx.inputs).outpoint
    rawKeys =
      [ "730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6",
        "11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3",
        "77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661",
        "14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49",
        "fe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323",
        "428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890"
      ]
    Just keys = traverse secHexKey rawKeys
    rdm = PayMulSig (toPubKey ctx <$> keys) 6
    sigIn sh = SigInput (toP2WSH $ encodeOutput ctx rdm) 987654321 op0 sh (Just rdm)
    sigHashesA = [sigHashAll, sigHashNone, sigHashSingle]
    sigHashesB = setAnyoneCanPay <$> sigHashesA
    sigIns = sigIn <$> (sigHashesA <> sigHashesB)
    generatedSignedTx = foldM addSig unsignedTx $ zip sigIns keys
    addSig tx (sigIn', key') = signNestedWitnessTx btc ctx tx [sigIn'] [key']

secHexKey :: Text -> Maybe SecKey
secHexKey = decodeHex >=> secKey

toPubKey :: Ctx -> SecKey -> PublicKey
toPubKey ctx = derivePublicKey ctx . wrapSecKey True
