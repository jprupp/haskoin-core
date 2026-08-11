{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.NetworkSpec (spec) where

import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Default (def)
import Data.Maybe (fromJust)
import Data.Text (Text)
import Data.Word (Word32)
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network
import Haskoin.Network.Constants
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.HUnit (Assertion, assertBool, assertEqual)
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

identityTests :: IdentityTests
identityTests =
  def
    { serialTests =
        [ SerialBox arbitraryVarInt,
          SerialBox arbitraryVarString,
          SerialBox arbitraryNetworkAddress,
          SerialBox arbitraryInvType,
          SerialBox arbitraryInvVector,
          SerialBox arbitraryInv1,
          SerialBox arbitraryVersion,
          SerialBox arbitraryAddr1,
          SerialBox arbitraryAlert,
          SerialBox arbitraryReject,
          SerialBox arbitraryRejectCode,
          SerialBox arbitraryGetData,
          SerialBox arbitraryNotFound,
          SerialBox arbitraryPing,
          SerialBox arbitraryPong,
          SerialBox arbitraryMessageCommand,
          SerialBox arbitraryMessageHeader,
          SerialBox arbitraryBloomFlags,
          SerialBox arbitraryBloomFilter,
          SerialBox arbitraryFilterLoad,
          SerialBox arbitraryFilterAdd
        ]
    }

spec :: Spec
spec = prepareContext $ \ctx -> do
  testIdentity identityTests
  describe "Custom identity tests" $ do
    prop "Data.Serialize Encoding for type Message" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitraryMessage net ctx) $
          customCerealID (getMessage net) (putMessage net)
  describe "bloom filters" $ do
    it "bloom filter vector 1" bloomFilter1
    it "bloom filter vector 2" bloomFilter2
    it "bloom filter vector 3" $ bloomFilter3 ctx
  describe "relevant bloom filter update" $ do
    it "Relevant Update" $ relevantOutputUpdated ctx
    it "Irrelevant Update" $ irrelevantOutputNotUpdated ctx

bloomFilter :: Word32 -> Text -> Assertion
bloomFilter n x = do
  assertBool "Bloom filter doesn't contain vector 1" $ bloomContains f1 v1
  assertBool "Bloom filter contains something it should not" $
    not $
      bloomContains f1 v2
  assertBool "Bloom filter doesn't contain vector 3" $ bloomContains f3 v3
  assertBool "Bloom filter doesn't contain vector 4" $ bloomContains f4 v4
  assertBool "Bloom filter serialization is incorrect" $
    runPutS (serialize f4) == bs
  where
    f0 = bloomCreate 3 0.01 n BloomUpdateAll
    f1 = bloomInsert f0 v1
    f3 = bloomInsert f1 v3
    f4 = bloomInsert f3 v4
    v1 = fromJust $ decodeHex "99108ad8ed9bb6274d3980bab5a85c048f0950c8"
    v2 = fromJust $ decodeHex "19108ad8ed9bb6274d3980bab5a85c048f0950c8"
    v3 = fromJust $ decodeHex "b5a2c786d9ef4658287ced5914b37a1b4aa32eee"
    v4 = fromJust $ decodeHex "b9300670b4c5366e95b2699e8b18bc75e5f729c5"
    bs = fromJust $ decodeHex x

bloomFilter1 :: Assertion
bloomFilter1 = bloomFilter 0 "03614e9b050000000000000001"

bloomFilter2 :: Assertion
bloomFilter2 = bloomFilter 2147483649 "03ce4299050000000100008001"

bloomFilter3 :: Ctx -> Assertion
bloomFilter3 ctx =
  assertBool "Bloom filter serialization is incorrect" $
    runPutS (serialize f2) == bs
  where
    f0 = bloomCreate 2 0.001 0 BloomUpdateAll
    f1 = bloomInsert f0 $ marshal ctx p
    f2 = bloomInsert f1 $ runPutS $ serialize $ fromJust $ addressHash160 $ pubKeyAddr ctx p
    k = fromJust $ fromWif btc "5Kg1gnAjaLfKiwhhPpGS3QfRg2m6awQvaj98JCZBZQ5SuS2F15C"
    p = derivePublicKey ctx k
    bs = fromJust $ decodeHex "038fc16b080000000000000001"

relevantOutputUpdated :: Ctx -> Assertion
relevantOutputUpdated ctx =
  assertBool "Bloom filter output updated" $
    any (bloomContains bf2) spendTxInput
  where
    bf0 = bloomCreate 10 0.000001 0 BloomUpdateAll
    relevantOutputHash = fromJust $ decodeHex "03f47604ea2736334151081e13265b4fe38e6fa8"
    bf1 = bloomInsert bf0 relevantOutputHash
    bf2 = fromJust $ bloomRelevantUpdate ctx bf1 relevantTx
    spendTxInput = runPutS . serialize . (.outpoint) <$> spendRelevantTx.inputs

irrelevantOutputNotUpdated :: Ctx -> Assertion
irrelevantOutputNotUpdated ctx = assertEqual "Bloom filter not updated" Nothing bf2
  where
    bf0 = bloomCreate 10 0.000001 0 BloomUpdateAll
    relevantOutputHash = fromJust $ decodeHex "03f47604ea2736334151081e13265b4fe38e6fa8"
    bf1 = bloomInsert bf0 relevantOutputHash
    bf2 = bloomRelevantUpdate ctx bf1 unrelatedTx

-- Random transaction (57dc904f32ad4daab7b321dd469e8791ad09df784cdd273a73985150a4f225e9)
relevantTx :: Tx
relevantTx =
  Tx
    { version = 1,
      inputs =
        [ TxIn
            { outpoint = OutPoint "35fe9017b7e3af592920b56fa06ac02faf0c52cdb19dcb416129ac71c95d060e" 1,
              script = fromJust $ decodeHex "473044022032fc8eef299b7e94b9a986a6aa2dcb9733ab804bef80df995e443b9c1f8c604202203335df7a2e2b4789451cdb4b2b05a786a81c51519eb6a567fd6fe8cd7b2d33fe014104272502dc63a512dad1473cb82a71be9baf4f4303abd1ff6028fc8a78e1f3aec1218907119dec14f07354850758ff0948e88a904fa411c4df7d5444414ec64ad6",
              sequence = 4294967295
            }
        ],
      outputs =
        [ TxOut {value = 100000000, script = fromJust $ decodeHex "76a91403f47604ea2736334151081e13265b4fe38e6fa888ac"},
          TxOut {value = 107980000, script = fromJust $ decodeHex "76a91481cc186a2f4a69f633ed4bf10ef4a78be13effdd88ac"}
        ],
      witness = [],
      locktime = 0
    }

-- Transaction that spends above (fd6e3b693b844aa431fad46765c1aa019a6b13aebfa9dae916b3ffa43283a300)
spendRelevantTx :: Tx
spendRelevantTx =
  Tx
    { version = 1,
      inputs =
        [ TxIn
            { outpoint = OutPoint "57dc904f32ad4daab7b321dd469e8791ad09df784cdd273a73985150a4f225e9" 0,
              script = fromJust $ decodeHex "483045022100ecc334821e4e94cc2fdc841d5ad147d5bb942b993ba81460cc446e0410afa811022015fcbc542b734dbb61a05ec06012095096de5839c50808fe56f2b315e877c20d012103fb64e5792fa586172339b776b7017d3d529358cb73be6406a1fc994228d14f88",
              sequence = 4294967295
            },
          TxIn
            { outpoint = OutPoint "cfee6a8d6e68e8fd16df6fff010afffcd19d7e075aa7b707dd1bae6adc420042" 0,
              script = fromJust $ decodeHex "47304402200e6bb95fa606f254d17089d83c4ceeb19c5d1699b4faddcd4f1f1568286e6b650220087fb8439f31e1b30e47710d095422405f601d6151f2f93e125e1a08a6e29ad4012103b49252e8fc6d5b49c8d14ee71fab45591df4a126a6c453c724f3d356e38f0cee",
              sequence = 4294967295
            }
        ],
      outputs =
        [ TxOut {value = 3851100, script = fromJust $ decodeHex "76a914a297cae82a9a3b932bf023ae274fe2585295c9ca88ac"},
          TxOut {value = 111000000, script = fromJust $ decodeHex "76a9148f952c38600a61385974acc30a64f74407f9801488ac"}
        ],
      witness = [],
      locktime = 0
    }

-- This random transaction is unrelated to the others
unrelatedTx :: Tx
unrelatedTx =
  Tx
    { version = 1,
      inputs =
        [ TxIn
            { outpoint = OutPoint "3ec3a71431c68e5d978a5fb4a0a1081d8bee8384d8aa4c06b1fbaf9413e2214f" 20,
              script = fromJust $ decodeHex "483045022100ec9c202c9d3140b973aca9d7f21a82138aa4cfa43fddc5419098ac5e26a6f152022010848fd688f290ae010fb5cb493410caa03145fc12445900ec1ad2bde33aecd9012102c7445e72d723f99a0064526c28269d07f47c8fd81531a94a8d3bf5ebd5e23ef1",
              sequence = 4294967295
            }
        ],
      outputs =
        [ TxOut {value = 12600000, script = fromJust $ decodeHex "76a9148fef3b7051de8cc44e966159e7ea37f4520187e888ac"}
        ],
      witness = [],
      locktime = 0
    }
