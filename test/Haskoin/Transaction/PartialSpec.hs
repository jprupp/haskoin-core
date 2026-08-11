{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}

module Haskoin.Transaction.PartialSpec (spec) where

import Control.Monad ((<=<))
import Data.Aeson (FromJSON, parseJSON, withObject, (.:))
import Data.Bifunctor (first)
import Data.ByteString (ByteString)
import Data.ByteString.Base64 (decodeBase64Untyped)
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Either (fromRight, isLeft, isRight)
import Data.HashMap.Strict (fromList, singleton)
import Data.Maybe (fromJust, isJust)
import Data.Serialize
import Data.Text (Text)
import Data.Text qualified as Text
import Data.Text.Encoding (encodeUtf8)
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.HUnit (Assertion, assertBool, assertEqual)
import Test.Hspec
import Test.QuickCheck

spec :: Spec
spec = prepareContext $ \ctx ->
  describe "PSBT unit tests" $ do
    it "encodes trivial PSBT" $
      (encodeHex . runPut . putPSBT ctx) trivialPSBT == trivialPSBTHex
    it "decodes trivial PSBT" $
      decodeHexPSBT ctx trivialPSBTHex == Right trivialPSBT
    it "encodes and decodes non-empty transactions" $
      (runGet (getPSBT ctx) . runPut . putPSBT ctx) nonEmptyTransactionPSBT == Right nonEmptyTransactionPSBT
    it "does not decode invalid BIP test vectors" $
      mapM_ (invalidVecTest ctx) invalidVec
    it "encodes valid BIP test vectors" $
      mapM_ (uncurry (encodeVecTest ctx)) validEncodeVec
    it "decodes valid BIP test vectors" $
      mapM_ (uncurry (decodeVecTest ctx)) $
        zip [1 ..] validVec
    it "decodes vector 2" $ vec2Test ctx
    it "decodes vector 3" $ vec3Test ctx
    it "decodes vector 4" $ vec4Test ctx
    it "decodes vector 5" $ vec5Test ctx
    it "decodes vector 6" $ vec6Test ctx
    it "signed and finalized P2PKH PSBTs verify" $
      property $
        forAll (arbitraryKeyPair ctx) $
          verifyNonWitnessPSBT btc ctx . unfinalizedPkhPSBT btc ctx
    it "signed and finalized multisig PSBTs verify" $
      property $
        forAll (arbitraryMultiSig ctx) $
          verifyNonWitnessPSBT btc ctx . unfinalizedMsPSBT btc ctx
    it "encodes and decodes PSBT with final witness script" $
      (fmap (encodeHex . runPut . putPSBT ctx) . decodeHexPSBT ctx) validVec7Hex == Right validVec7Hex
    it "handles complex PSBTs correctly" $ complexPsbtTest ctx
    it "calculates keys properly" $ psbtSignerTest ctx

vec2Test :: Ctx -> Assertion
vec2Test ctx = do
  psbt <- decodeHexPSBTM ctx "Cannot parse validVec2" validVec2Hex
  assertEqual "2 inputs" 2 (length psbt.inputs)
  assertEqual "2 outputs" 2 (length psbt.outputs)
  assertBool "final script sig" $ isJust (head psbt.inputs).finalScriptSig

  let rdmScript = fromJust (psbt.inputs !! 1).inputRedeemScript
  assertBool "p2wpkh" $ (isPayWitnessPKHash <$> decodeOutput ctx rdmScript) == Right True

  let scrptPubKey = witnessScriptPubKey ctx (psbt.inputs !! 1)
      rdmScriptP2SH = toP2SH rdmScript
  assertEqual "redeem script pubkey equal" rdmScriptP2SH scrptPubKey
  assertEqual "expected redeem script" (expectedOut ctx) rdmScriptP2SH

  mapM_ (assertEqual "outputs are empty" emptyOutput) psbt.outputs

vec3Test :: Ctx -> Assertion
vec3Test ctx = do
  psbt <- decodeHexPSBTM ctx "Cannot parse validVec3" validVec3Hex
  assertEqual "1 input" 1 (length psbt.inputs)
  assertEqual "2 outputs" 2 (length psbt.outputs)
  let (txInput : _) = psbt.unsignedTransaction.inputs
      (firstInput : _) = psbt.inputs
      Just utx = firstInput.nonWitnessUtxo
      OutPoint prevHash prevVOut = txInput.outpoint
  assertEqual "txids of inputs match" prevHash (txHash utx)
  let prevOutputKey =
        fromRight (error "Could not decode key")
          . unmarshal ctx
          . (.script)
          $ utx.outputs !! fromIntegral prevVOut
  assertBool "p2pkh" $ isPayPKHash prevOutputKey
  assertEqual "sighash type" sigHashAll (fromJust firstInput.sigHashType)

vec4Test :: Ctx -> Assertion
vec4Test ctx = do
  psbt <- decodeHexPSBTM ctx "Cannot parse validVec4" validVec4Hex
  assertEqual "2 inputs" 2 (length psbt.inputs)
  assertEqual "2 outputs" 2 (length psbt.outputs)
  let (firstInput : _) = psbt.inputs
      (_ : secondInput : _) = psbt.inputs
  assertEqual "first input not final script sig" Nothing firstInput.finalScriptSig
  assertEqual "second input not final script sig" Nothing secondInput.finalScriptSig

  let Just rdmScript = secondInput.inputRedeemScript
  assertBool "p2wpkh" $ (isPayWitnessPKHash <$> decodeOutput ctx rdmScript) == Right True

  let scrptPubKey = witnessScriptPubKey ctx secondInput
      rdmScriptP2SH = toP2SH rdmScript
  assertEqual "redeem script pubkey equal" rdmScriptP2SH scrptPubKey
  assertEqual "expected redeem script" (expectedOut ctx) rdmScriptP2SH

  assertBool "all non-empty outputs" $ emptyOutput `notElem` psbt.outputs

vec5Test :: Ctx -> Assertion
vec5Test ctx = do
  psbt <- decodeHexPSBTM ctx "Cannot parse validVec5" validVec5Hex
  assertEqual "Correctly decode PSBT" expectedPsbt psbt
  let (input : _) = psbt.inputs

  let Just rdmScript = input.inputRedeemScript
  assertBool "p2wsh" $ (isPayWitnessScriptHash <$> decodeOutput ctx rdmScript) == Right True

  let scrptPubKey = witnessScriptPubKey ctx input
      rdmScriptP2SH = toP2SH rdmScript
  assertEqual "redeem script pubkey equal" rdmScriptP2SH scrptPubKey
  assertEqual "expected redeem script" expectedOut2 rdmScriptP2SH
  where
    expectedOut2 =
      fromRight (error "could not decode expected output")
        . unmarshal ctx
        . fromJust
        $ decodeHex "a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87"
    -- From the bitcoind decodepsbt rpc call
    expectedPsbt =
      PSBT
        { unsignedTransaction =
            Tx
              { version = 2,
                inputs =
                  [ TxIn
                      { outpoint =
                          OutPoint
                            { hash = "39bc5c3b33d66ce3d7852a7942331e3ec10f8ba50f225fc41fb5dfa523239a27",
                              index = 0
                            },
                        script = "",
                        sequence = 4294967295
                      }
                  ],
                outputs =
                  [ TxOut
                      { value = 199908000,
                        script = (fromJust . decodeHex) "76a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac"
                      }
                  ],
                witness = mempty,
                locktime = 0
              },
          globalUnknown = mempty,
          inputs =
            [ Input
                { nonWitnessUtxo = Nothing,
                  witnessUtxo =
                    Just
                      ( TxOut
                          { value = 199909013,
                            script = (fromJust . decodeHex) "a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87"
                          }
                      ),
                  partialSigs =
                    fromList
                      [ ( PublicKey
                            { point =
                                fromJust $
                                  importPubKey ctx
                                    =<< decodeHex
                                      "03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46",
                              compress = True
                            },
                          (fromJust . decodeHex) "304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a01"
                        )
                      ],
                  sigHashType = Nothing,
                  inputRedeemScript =
                    Just
                      . fromRight (error "vec5Test: Could not decode redeem script")
                      . decode
                      . fromJust
                      $ decodeHex "0020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681",
                  inputWitnessScript =
                    Just
                      . fromRight (error "vec5Test: Could not decode witness script")
                      . decode
                      . fromJust
                      $ decodeHex "522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae",
                  inputHDKeypaths =
                    fromList
                      [ ( PublicKey
                            { point =
                                fromJust $
                                  importPubKey ctx
                                    =<< decodeHex
                                      "03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46",
                              compress = True
                            },
                          ("b4a6ba67", [hardIndex 0, hardIndex 0, hardIndex 4])
                        ),
                        ( PublicKey
                            { point =
                                fromJust $
                                  importPubKey ctx
                                    =<< decodeHex
                                      "03de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd",
                              compress = True
                            },
                          ("b4a6ba67", [hardIndex 0, hardIndex 0, hardIndex 5])
                        )
                      ],
                  finalScriptSig = Nothing,
                  finalScriptWitness = Nothing,
                  inputUnknown = mempty
                }
            ],
          outputs =
            [ Output
                { outputRedeemScript = Nothing,
                  outputWitnessScript = Nothing,
                  outputHDKeypaths = mempty,
                  outputUnknown = mempty
                }
            ]
        }
    hardIndex = (+ 2 ^ 31)

vec6Test :: Ctx -> Assertion
vec6Test ctx = do
  psbt <- decodeHexPSBTM ctx "Cannot parse validVec6" validVec6Hex
  assertEqual "1 input" 1 (length psbt.inputs)
  assertEqual "1 output" 1 (length psbt.outputs)

  let tx = psbt.unsignedTransaction
  assertEqual "correct transaction" "75c5c9665a570569ad77dd1279e6fd4628a093c4dcbf8d41532614044c14c115" (txHash tx)

  assertEqual "correct unknowns" expectedUnknowns (head psbt.inputs).inputUnknown
  where
    expectedUnknowns =
      UnknownMap $
        singleton
          (Key 0x0f (fromJust $ decodeHex "010203040506070809"))
          (fromJust $ decodeHex "0102030405060708090a0b0c0d0e0f")

complexPsbtTest :: Ctx -> Assertion
complexPsbtTest ctx = do
  complex <- readTestFileParser (parseComplexJSON ctx) "complex_psbt.json"

  let computedCombinedPsbt = mergeMany $ complexSignedPsbts complex
      expectedCombinedPsbt = stripRedundantUtxos $ complexCombinedPsbt complex
  assertEqual "combined psbt" computedCombinedPsbt (Just expectedCombinedPsbt)

  let computedCompletePsbt = complete ctx $ complexCombinedPsbt complex
      expectedCompletePsbt = complexCompletePsbt complex
  assertEqual "complete psbt" computedCompletePsbt expectedCompletePsbt

  let computedFinalTx = finalTransaction $ complexCompletePsbt complex
  assertEqual "final tx" computedFinalTx (complexFinalTx complex)
  where
    stripRedundantUtxos PSBT {..} = PSBT {inputs = stripRedundantUtxo <$> inputs, ..}
    stripRedundantUtxo input
      | Just {} <- input.witnessUtxo = input {nonWitnessUtxo = Nothing}
      | otherwise = input

psbtSignerTest :: Ctx -> Assertion
psbtSignerTest ctx = do
  assertEqual "recover explicit secret key" (Just theSecKey) (getSignerKey signer thePubKey Nothing)
  assertEqual
    "recover key for origin path"
    (Just originPathSecKey)
    (getSignerKey signer originPathPubKey (Just (rootFP, originKeyPath)))
  assertEqual
    "recover key for direct path"
    (Just directPathSecKey)
    (getSignerKey signer directPathPubKey (Just (keyFP, directPath)))
  where
    signer = secKeySigner ctx theSecKey <> xPrvSigner ctx xprv (Just origin)

    Just theSecKey = secKey "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    thePubKey = PublicKey {point = derivePubKey ctx theSecKey, compress = True}

    rootXPrv = makeXPrvKey "PSBTSignerTest"
    rootFP = xPubFP ctx $ deriveXPubKey ctx rootXPrv
    xprv = derivePath ctx keyPath rootXPrv
    keyFP = xPubFP ctx $ deriveXPubKey ctx xprv
    keyPath = Deriv :| 444
    origin = (rootFP, keyPath)

    originKeyPath = Deriv :| 444 :/ 0
    originPathSecKey = (derivePath ctx originKeyPath rootXPrv).key
    originPathPubKey = PublicKey {point = derivePubKey ctx originPathSecKey, compress = True}

    directPath = Deriv :/ 1
    directPathSecKey = (derivePath ctx directPath xprv).key
    directPathPubKey = PublicKey {point = derivePubKey ctx directPathSecKey, compress = True}

expectedOut :: Ctx -> ScriptOutput
expectedOut ctx =
  fromRight (error "could not decode expected output")
    . unmarshal ctx
    . fromJust
    $ decodeHex "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"

witnessScriptPubKey :: Ctx -> Input -> ScriptOutput
witnessScriptPubKey ctx =
  fromRight (error "could not decode witness utxo")
    . unmarshal ctx
    . (.script)
    . fromJust
    . (.witnessUtxo)

decodeHexPSBT :: Ctx -> Text -> Either String PSBT
decodeHexPSBT ctx = runGet (getPSBT ctx) . fromJust . decodeHex

decodeHexPSBTM :: (Monad m, MonadFail m) => Ctx -> String -> Text -> m PSBT
decodeHexPSBTM ctx errMsg = either (fail . (errMsg <>) . (": " <>)) return . decodeHexPSBT ctx

hexScript :: Text -> ByteString
hexScript =
  either (error "Could not decode script") encodeScript
    . runGetS deserialize
    . fromJust
    . decodeHex
  where
    encodeScript :: Script -> ByteString
    encodeScript = runPutS . serialize

invalidVecTest :: Ctx -> Text -> Assertion
invalidVecTest ctx = assertBool "invalid psbt" . isLeft . decodeHexPSBT ctx

decodeVecTest :: Ctx -> Int -> Text -> Assertion
decodeVecTest ctx i = assertBool (show i <> " decodes correctly") . isRight . decodeHexPSBT ctx

encodeVecTest :: Ctx -> PSBT -> Text -> Assertion
encodeVecTest ctx psbt hex =
  assertEqual
    "encodes correctly"
    ((runPut . putPSBT ctx) psbt)
    ((fromJust . decodeHex) hex)

trivialPSBT :: PSBT
trivialPSBT =
  PSBT
    { unsignedTransaction = Tx {version = 2, inputs = [], outputs = [], witness = [], locktime = 0},
      globalUnknown = UnknownMap mempty,
      inputs = [],
      outputs = []
    }

trivialPSBTHex :: Text
trivialPSBTHex = "70736274ff01000a0200000000000000000000"

nonEmptyTransactionPSBT :: PSBT
nonEmptyTransactionPSBT = emptyPSBT testTx1

verifyNonWitnessPSBT :: Network -> Ctx -> PSBT -> Bool
verifyNonWitnessPSBT net ctx psbt =
  verifyStdTx net ctx (finalTransaction (complete ctx psbt)) sigData
  where
    sigData = inputSigData =<< zip psbt.inputs psbt.unsignedTransaction.inputs
    decodeOutScript = fromRight (error "Could not parse output script") . unmarshal ctx
    inputSigData (input@Input {}, txInput@TxIn {}) =
      map
        (\(TxOut val script) -> (decodeOutScript script, val, txInput.outpoint))
        (fromJust input.nonWitnessUtxo).outputs

unfinalizedPkhPSBT :: Network -> Ctx -> (PrivateKey, PublicKey) -> PSBT
unfinalizedPkhPSBT net ctx (prvKey, pubKey) =
  let PSBT {..} = emptyPSBT currTx
   in PSBT {inputs = [input], ..}
  where
    input =
      emptyInput
        { nonWitnessUtxo = Just prevTx,
          partialSigs = singleton pubKey sig
        }
    currTx =
      unfinalizedTx (txHash prevTx)
    prevTx =
      testUtxo [prevOut]
    prevOutScript =
      fromJust $ addressToScript ctx (pubKeyAddr ctx pubKey)
    prevOut =
      TxOut
        { value = 200000000,
          script = runPutS (serialize prevOutScript)
        }
    h = txSigHash net currTx prevOutScript prevOut.value 0 sigHashAll
    sig =
      encodeTxSig net ctx $
        TxSignature (signHash ctx prvKey.key h) sigHashAll

arbitraryMultiSig :: Ctx -> Gen ([(PrivateKey, PublicKey)], Int)
arbitraryMultiSig ctx = do
  (m, n) <- arbitraryMSParam
  keys <- vectorOf n (arbitraryKeyPair ctx)
  return (keys, m)

unfinalizedMsPSBT :: Network -> Ctx -> ([(PrivateKey, PublicKey)], Int) -> PSBT
unfinalizedMsPSBT net ctx (keys, m) =
  let PSBT {..} = emptyPSBT currTx
   in PSBT {inputs = [input], ..}
  where
    input =
      emptyInput
        { nonWitnessUtxo = Just prevTx,
          partialSigs = sigs,
          inputRedeemScript = Just prevOutScript
        }
    currTx = unfinalizedTx (txHash prevTx)
    prevTx = testUtxo [prevOut]
    prevOutScript = encodeOutput ctx $ PayMulSig (map snd keys) m
    prevOut =
      TxOut
        { value = 200000000,
          script = marshal ctx (toP2SH prevOutScript)
        }
    h = txSigHash net currTx prevOutScript prevOut.value 0 sigHashAll
    sigs = fromList $ map sig keys
    sig (prvKey@PrivateKey {key}, pubKey) =
      let sh = signHash ctx key h
          ts = TxSignature sh sigHashAll
       in (pubKey, encodeTxSig net ctx ts)

unfinalizedTx :: TxHash -> Tx
unfinalizedTx prevHash =
  Tx
    { version = 2,
      inputs =
        [ TxIn
            { outpoint = OutPoint prevHash 0,
              script = "",
              sequence = 4294967294
            }
        ],
      outputs =
        [ TxOut {value = 99999699, script = hexScript "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"},
          TxOut {value = 100000000, script = hexScript "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"}
        ],
      witness = [],
      locktime = 1257139
    }

invalidVec :: [Text]
invalidVec =
  [ "0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300",
    "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000",
    "70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000",
    "70736274ff000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000",
    "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000000",
    "70736274ff020001550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
    "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac000000000002010020955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
    "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87210203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
    "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a01020400220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
    "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d568102050047522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
    "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae210603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd10b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000",
    "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f0000000000020000bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000",
    "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000020700da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000",
    "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903020800da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000",
    "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00210203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58710d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000",
    "70736274ff0100730200000001301ae986e516a1ec8ac5b4bc6573d32f83b465e23ad76167d68b38e730b4dbdb0000000000ffffffff02747b01000000000017a91403aa17ae882b5d0d54b25d63104e4ffece7b9ea2876043993b0000000017a914b921b1ba6f722e4bfa83b6557a3139986a42ec8387000000000001011f00ca9a3b00000000160014d2d94b64ae08587eefc8eeb187c601e939f9037c0203000100000000010016001462e9e982fff34dd8239610316b090cd2a3b747cb000100220020876bad832f1d168015ed41232a9ea65a1815d9ef13c0ef8759f64b5b2b278a65010125512103b7ce23a01c5b4bf00a642537cdfabb315b668332867478ef51309d2bd57f8a8751ae00",
    "70736274ff0100730200000001301ae986e516a1ec8ac5b4bc6573d32f83b465e23ad76167d68b38e730b4dbdb0000000000ffffffff02747b01000000000017a91403aa17ae882b5d0d54b25d63104e4ffece7b9ea2876043993b0000000017a914b921b1ba6f722e4bfa83b6557a3139986a42ec8387000000000001011f00ca9a3b00000000160014d2d94b64ae08587eefc8eeb187c601e939f9037c0002000016001462e9e982fff34dd8239610316b090cd2a3b747cb000100220020876bad832f1d168015ed41232a9ea65a1815d9ef13c0ef8759f64b5b2b278a65010125512103b7ce23a01c5b4bf00a642537cdfabb315b668332867478ef51309d2bd57f8a8751ae00",
    "70736274ff0100730200000001301ae986e516a1ec8ac5b4bc6573d32f83b465e23ad76167d68b38e730b4dbdb0000000000ffffffff02747b01000000000017a91403aa17ae882b5d0d54b25d63104e4ffece7b9ea2876043993b0000000017a914b921b1ba6f722e4bfa83b6557a3139986a42ec8387000000000001011f00ca9a3b00000000160014d2d94b64ae08587eefc8eeb187c601e939f9037c00010016001462e9e982fff34dd8239610316b090cd2a3b747cb000100220020876bad832f1d168015ed41232a9ea65a1815d9ef13c0ef8759f64b5b2b278a6521010025512103b7ce23a01c5b4bf00a642537cdfabb315b668332867478ef51309d2bd57f8a8751ae00"
  ]

validEncodeVec :: [(PSBT, Text)]
validEncodeVec = [(validVec1, validVec1Hex)]

testTx1 :: Tx
testTx1 =
  Tx
    { version = 2,
      inputs =
        [ TxIn
            { outpoint = OutPoint "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126" 0,
              script = "",
              sequence = 4294967294
            }
        ],
      outputs =
        [ TxOut {value = 99999699, script = hexScript "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"},
          TxOut {value = 100000000, script = hexScript "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787"}
        ],
      witness = [],
      locktime = 1257139
    }

testUtxo :: [TxOut] -> Tx
testUtxo prevOuts =
  Tx
    { version = 1,
      inputs =
        [ TxIn
            { outpoint = OutPoint "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389" 1,
              script = hexScript "160014be18d152a9b012039daf3da7de4f53349eecb985",
              sequence = 4294967295
            },
          TxIn
            { outpoint = OutPoint "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886" 1,
              script = hexScript "160014fe3e9ef1a745e974d902c4355943abcb34bd5353",
              sequence = 4294967295
            }
        ],
      outputs = prevOuts,
      witness =
        [ [ fromJust $ decodeHex "304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c01",
            fromJust $ decodeHex "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105"
          ],
          [ fromJust $ decodeHex "3045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01",
            fromJust $ decodeHex "0223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3"
          ]
        ],
      locktime = 0
    }

testUtxo1 :: Tx
testUtxo1 =
  testUtxo
    [ TxOut {value = 200000000, script = hexScript "76a91485cff1097fd9e008bb34af709c62197b38978a4888ac"},
      TxOut {value = 190303501938, script = hexScript "a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587"}
    ]

validVec1 :: PSBT
validVec1 =
  let PSBT {..} = emptyPSBT testTx1
   in PSBT {inputs = [emptyInput {nonWitnessUtxo = Just testUtxo1}], ..}

validVec :: [Text]
validVec = [validVec1Hex, validVec2Hex, validVec3Hex, validVec4Hex, validVec5Hex, validVec6Hex]

validVec1Hex :: Text
validVec1Hex = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000"

validVec2Hex :: Text
validVec2Hex = "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000"

validVec3Hex :: Text
validVec3Hex = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001030401000000000000"

validVec4Hex :: Text
validVec4Hex = "70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000100df0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e13000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb8230800220202ead596687ca806043edc3de116cdf29d5e9257c196cd055cf698c8d02bf24e9910b4a6ba670000008000000080020000800022020394f62be9df19952c5587768aeb7698061ad2c4a25c894f47d8c162b4d7213d0510b4a6ba6700000080010000800200008000"

validVec5Hex :: Text
validVec5Hex = "70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000"

validVec6Hex :: Text
validVec6Hex = "70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000a0f0102030405060708090f0102030405060708090a0b0c0d0e0f0000"

-- Example of a PSBT with a `finalWitnessScript`
validVec7Hex :: Text
validVec7Hex = "70736274ff0100520200000001815dd29e16fd2f567a040ce24f5337fb9cfd0c05bacd8890714a33edc7cbbc920000000000ffffffff0192f1052a01000000160014ef9ade26f63015d57f4ecdb268d1a9b8d6cd8872000000000001008402000000010000000000000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff0200f2052a010000001600145f4ffa19dbbe464561c50fc4d8d8ac0b41009dd20000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90000000001011f00f2052a010000001600145f4ffa19dbbe464561c50fc4d8d8ac0b41009dd201086b02473044022026a9f7afdb0128970bb3577e536ec3d3dc10c1e82650d11c9da1df9003b31d0202202258b11f962f12e0897c642cd6f38a0181db17197f3693a530c9431eb44dde7d0121033dc786e9628bb6c41c08fceb9b37458ad7a95e7e6b04e0bde45b6879398c3ac100220203a6affb58dda998a4ffdce652feb91038fdfc78c748ae687372e11292af8d312d101c4c5bfc00000080000000800100008000"

data ComplexPSBT = ComplexPSBT
  { complexSignedPsbts :: [PSBT],
    complexCombinedPsbt :: PSBT,
    complexCompletePsbt :: PSBT,
    complexFinalTx :: Tx
  }
  deriving (Eq, Show)

parseComplexJSON ctx = withObject "ComplexPSBT" $ \obj -> do
  ComplexPSBT
    <$> sequence
      [ psbtField "miner_psbt" obj,
        psbtField "p2pkh_psbt" obj,
        psbtField "p2sh_ms_1_psbt" obj,
        psbtField "p2sh_ms_2_psbt" obj,
        psbtField "p2sh_pk_psbt" obj,
        psbtField "p2sh_wsh_pk_psbt" obj,
        psbtField "p2sh_wsh_ms_1_psbt" obj,
        psbtField "p2sh_wsh_ms_2_psbt" obj,
        psbtField "p2wpkh_psbt" obj,
        psbtField "p2wsh_pk_psbt" obj,
        psbtField "p2wsh_ms_1_psbt" obj,
        psbtField "p2wsh_ms_2_psbt" obj
      ]
    <*> psbtField "combined_psbt" obj
    <*> psbtField "complete_psbt" obj
    <*> (obj .: "final_tx" >>= parseTx)
  where
    parseTx =
      either fail pure
        . ( decode
              <=< maybe (Left "hex") Right
                . decodeHex
          )
    parsePsbt =
      either fail pure
        . ( runGet (getPSBT ctx)
              <=< first Text.unpack . decodeBase64Untyped
          )
        . encodeUtf8
    psbtField fieldName obj =
      obj .: fieldName >>= parsePsbt
