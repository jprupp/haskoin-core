{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- | Transactions: their ids, their bytes and sizes, building, signing and
-- verifying them, merging partial signatures, coin selection and fee
-- estimation, the SegWit witness helpers and the genesis coinbases.
module Haskoin.TransactionSpec (spec) where

import Control.Exception (evaluate)
import Control.Monad (forM_, guard, unless)
import Data.Aeson (decode, eitherDecode)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Default (def)
import Data.Either
import Data.List (find, inits, isInfixOf)
import Data.Maybe
import Data.String (fromString)
import Data.String.Conversions
import Data.Text (Text)
import Data.Text qualified as T
import Data.Word (Word32, Word64)
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.HUnit
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Text.Read (readMaybe)

identityTests :: Ctx -> IdentityTests
identityTests ctx =
  def
    { readTests =
        [ ReadBox arbitraryTxHash,
          ReadBox $ flip arbitraryTx ctx =<< arbitraryNetwork,
          ReadBox $ flip arbitraryTxIn ctx =<< arbitraryNetwork,
          ReadBox $ flip arbitraryTxOut ctx =<< arbitraryNetwork,
          ReadBox arbitraryOutPoint
        ],
      jsonTests =
        [ JsonBox arbitraryTxHash,
          JsonBox $ flip arbitraryTx ctx =<< arbitraryNetwork,
          JsonBox $ flip arbitraryWitnessTx ctx =<< arbitraryNetwork,
          JsonBox $ flip arbitraryLegacyTx ctx =<< arbitraryNetwork,
          JsonBox $ flip arbitraryTxIn ctx =<< arbitraryNetwork,
          JsonBox $ flip arbitraryTxOut ctx =<< arbitraryNetwork,
          JsonBox arbitraryOutPoint
        ],
      serialTests =
        [ SerialBox $ flip arbitraryTx ctx =<< arbitraryNetwork,
          SerialBox $ flip arbitraryWitnessTx ctx =<< arbitraryNetwork,
          SerialBox $ flip arbitraryLegacyTx ctx =<< arbitraryNetwork,
          SerialBox $ flip arbitraryTxIn ctx =<< arbitraryNetwork,
          SerialBox $ flip arbitraryTxOut ctx =<< arbitraryNetwork,
          SerialBox arbitraryOutPoint
        ]
    }

spec :: Spec
spec = prepareContext $ \ctx -> do
  testIdentity $ identityTests ctx
  describe "Transaction properties" $ do
    prop "decode and encode txid" $
      forAll arbitraryTxHash $
        \h -> hexToTxHash (txHashToHex h) == Just h
    prop "from string transaction id" $
      forAll arbitraryTxHash $
        \h -> fromString (cs $ txHashToHex h) == h
    prop "building address tx" $
      forAll arbitraryNetAddress $ \(net, addr) ->
        forAll (arbitrarySatoshi net) $ testBuildAddrTx net ctx addr
    prop "the size guess is at least the virtual size of a signed legacy transaction, with little slack" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitraryAddrOnlyTxFull net ctx) (testGuessSize net ctx)
    prop "the weight guess is at least the weight of a signed transaction whose inputs have a kind" $
      forAll arbitraryNetwork $ \net -> testGuessWeight net ctx False
    prop "the weight guess is at least the weight of a signed transaction with its SegWit inputs nested" $
      forAll arbitraryNetwork $ \net -> testGuessWeight net ctx True
    prop "choose coins" $
      forAll arbitraryNetwork $ \net ->
        forAll (listOf (arbitrarySatoshi net)) $ \coins ->
          forAll (listOf arbitraryOutputKind) (testChooseCoins coins)
    prop "sign and validate transaction" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitrarySigningData net ctx) (testDetSignTx net ctx)
    prop "sign and validate (nested) transaction" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitrarySigningData net ctx) (testDetSignNestedTx net ctx)
    prop "merge partially signed transactions" $
      forAll arbitraryNetwork $ \net ->
        property $ forAll (arbitraryPartialTxs net ctx) (testMergeTx net ctx)
    prop "nosigTxHash does not change when a transaction is signed, whether in the input scripts or in the witness" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitrarySigningData net ctx) $ \(tx, sigis, prv) ->
          nosigTxHash (either error id (signTx net ctx tx sigis (map (.key) prv))) === nosigTxHash tx
  describe "Transaction vectors" $ do
    it "compute txid from tx" $ mapM_ testTxidVector txidVectors
    it "build pkhash transaction (generated from bitcoind)" $
      mapM_ (testPKHashVector ctx) pkHashVectors
  idsSpec
  bytesSpec ctx
  sizeSpec ctx
  coinSelectionSpec
  verificationSpec ctx
  mergeSpec ctx
  taprootSigningSpec ctx
  segwitSpec ctx
  genesisSpec

-- Txid Vectors

testTxidVector :: (Text, Text) -> Assertion
testTxidVector (tid, tx) =
  assertEqual "txid" (Just tid) (txHashToHex . txHash <$> txM)
  where
    txM = eitherToMaybe . runGetS deserialize =<< decodeHex tx

txidVectors :: [(Text, Text)]
txidVectors =
  [ ( "23b397edccd3740a74adb603c9756370fafcde9bcc4483eb271ecad09a94dd63",
      "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa4\
      \3ad90ba26000000000490047304402203f16c6f40162ab686621ef3000b04e75\
      \418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb\
      \60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f0000000000\
      \1976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000"
    ),
    ( "c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73",
      "01000000010276b76b07f4935c70acf54fbf1f438a4c397a9fb7e633873c4dd3\
      \bc062b6b40000000008c493046022100d23459d03ed7e9511a47d13292d3430a\
      \04627de6235b6e51a40f9cd386f2abe3022100e7d25b080f0bb8d8d5f878bba7\
      \d54ad2fda650ea8d158a33ee3cbd11768191fd004104b0e2c879e4daf7b9ab68\
      \350228c159766676a14f5815084ba166432aab46198d4cca98fa3e9981d0a90b\
      \2effc514b76279476550ba3663fdcaff94c38420e9d5000000000100093d0000\
      \0000001976a9149a7b0f3b80c6baaeedce0a0842553800f832ba1f88ac000000\
      \00"
    ),
    ( "f7fdd091fa6d8f5e7a8c2458f5c38faffff2d3f1406b6e4fe2c99dcc0d2d1cbb",
      "01000000023d6cf972d4dff9c519eff407ea800361dd0a121de1da8b6f4138a2\
      \f25de864b4000000008a4730440220ffda47bfc776bcd269da4832626ac332ad\
      \fca6dd835e8ecd83cd1ebe7d709b0e022049cffa1cdc102a0b56e0e04913606c\
      \70af702a1149dc3b305ab9439288fee090014104266abb36d66eb4218a6dd31f\
      \09bb92cf3cfa803c7ea72c1fc80a50f919273e613f895b855fb7465ccbc8919a\
      \d1bd4a306c783f22cd3227327694c4fa4c1c439affffffff21ebc9ba20594737\
      \864352e95b727f1a565756f9d365083eb1a8596ec98c97b7010000008a473044\
      \0220503ff10e9f1e0de731407a4a245531c9ff17676eda461f8ceeb8c06049fa\
      \2c810220c008ac34694510298fa60b3f000df01caa244f165b727d4896eb84f8\
      \1e46bcc4014104266abb36d66eb4218a6dd31f09bb92cf3cfa803c7ea72c1fc8\
      \0a50f919273e613f895b855fb7465ccbc8919ad1bd4a306c783f22cd32273276\
      \94c4fa4c1c439affffffff01f0da5200000000001976a914857ccd42dded6df3\
      \2949d4646dfa10a92458cfaa88ac00000000"
    ),
    ( "afd9c17f8913577ec3509520bd6e5d63e9c0fd2a5f70c787993b097ba6ca9fae",
      "010000000370ac0a1ae588aaf284c308d67ca92c69a39e2db81337e563bf40c5\
      \9da0a5cf63000000006a4730440220360d20baff382059040ba9be98947fd678\
      \fb08aab2bb0c172efa996fd8ece9b702201b4fb0de67f015c90e7ac8a193aeab\
      \486a1f587e0f54d0fb9552ef7f5ce6caec032103579ca2e6d107522f012cd00b\
      \52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff7d815b6447e35fbe\
      \a097e00e028fb7dfbad4f3f0987b4734676c84f3fcd0e804010000006b483045\
      \022100c714310be1e3a9ff1c5f7cacc65c2d8e781fc3a88ceb063c6153bf9506\
      \50802102200b2d0979c76e12bb480da635f192cc8dc6f905380dd4ac1ff35a4f\
      \68f462fffd032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e3\
      \77c48f526a44741affffffff3f1f097333e4d46d51f5e77b53264db8f7f5d2e1\
      \8217e1099957d0f5af7713ee010000006c493046022100b663499ef73273a378\
      \8dea342717c2640ac43c5a1cf862c9e09b206fcb3f6bb8022100b09972e75972\
      \d9148f2bdd462e5cb69b57c1214b88fc55ca638676c07cfc10d8032103579ca2\
      \e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffff\
      \ff0380841e00000000001976a914bfb282c70c4191f45b5a6665cad1682f2c9c\
      \fdfb88ac80841e00000000001976a9149857cc07bed33a5cf12b9c5e0500b675\
      \d500c81188ace0fd1c00000000001976a91443c52850606c872403c0601e69fa\
      \34b26f62db4a88ac00000000"
    )
  ]

-- Build address transactions vectors generated from bitcoin-core raw tx API

testPKHashVector :: Ctx -> ([(Text, Word32)], [(Text, Word64)], Text) -> Assertion
testPKHashVector ctx (is, os, res) =
  assertEqual
    "Build PKHash Tx"
    (Right res)
    (encodeHex . runPutS . serialize <$> txE)
  where
    txE = buildAddrTx btc ctx (map f is) os
    f (tid, ix) = OutPoint (fromJust $ hexToTxHash tid) ix

pkHashVectors :: [([(Text, Word32)], [(Text, Word64)], Text)]
pkHashVectors =
  [ ( [ ( "eb29eba154166f6541ebcc9cbdf5088756e026af051f123bcfb526df594549db",
          14
        )
      ],
      [("14LsRquZfURNFrzpcLVGdaHTfAPjjwiSPb", 90000000)],
      "0100000001db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654\
      \a1eb29eb0e00000000ffffffff01804a5d05000000001976a91424aa604689cc58\
      \2292b97668bedd91dd5bf9374c88ac00000000"
    ),
    ( [ ( "eb29eba154166f6541ebcc9cbdf5088756e026af051f123bcfb526df594549db",
          0
        ),
        ( "0001000000000000000000000000000000000000000000000000000000000000",
          2147483647
        )
      ],
      [ ("14LsRquZfURNFrzpcLVGdaHTfAPjjwiSPb", 1),
        ("19VCgS642vzEA1sdByoSn6GsWBwraV8D4n", 2100000000000000)
      ],
      "0100000002db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654\
      \a1eb29eb0000000000ffffffff0000000000000000000000000000000000000000\
      \000000000000000000000100ffffff7f00ffffffff0201000000000000001976a9\
      \1424aa604689cc582292b97668bedd91dd5bf9374c88ac0040075af07507001976\
      \a9145d16672f53981ff21c5f42b40d1954993cbca54f88ac00000000"
    ),
    ( [ ( "eb29eba154166f6541ebcc9cbdf5088756e026af051f123bcfb526df594549db",
          0
        ),
        ( "0001000000000000000000000000000000000000000000000000000000000000",
          2147483647
        )
      ],
      [],
      "0100000002db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654a\
      \1eb29eb0000000000ffffffff000000000000000000000000000000000000000000\
      \0000000000000000000100ffffff7f00ffffffff0000000000"
    ),
    ( [],
      [ ("14LsRquZfURNFrzpcLVGdaHTfAPjjwiSPb", 1),
        ("19VCgS642vzEA1sdByoSn6GsWBwraV8D4n", 2100000000000000)
      ],
      "01000000000201000000000000001976a91424aa604689cc582292b97668bedd91d\
      \d5bf9374c88ac0040075af07507001976a9145d16672f53981ff21c5f42b40d1954\
      \993cbca54f88ac00000000"
    )
  ]

-- Transaction Properties --

testBuildAddrTx :: Network -> Ctx -> Address -> TestCoin -> IO ()
testBuildAddrTx net ctx a coin
  | isPubKeyAddress a = (PayPKHash <$> addressHash160 a) `shouldBe` Just out
  | isScriptAddress a = (PayScriptHash <$> addressHash160 a) `shouldBe` Just out
  | otherwise = discard
  where
    out = either error id $ do
      tx <- buildAddrTx net ctx [] [(fromJust (addrToText net a), coin.getTestCoin)]
      unmarshal ctx (head tx.outputs).script

-- The guess is an upper bound on the virtual size that counts 72 bytes
-- per signature. A signature with a short r or s is 1 or 2 bytes less.
testGuessSize :: Network -> Ctx -> Tx -> Bool
testGuessSize net ctx tx =
  guess >= size && guess <= size + 2 * signatures
  where
    guess = guessTxSize (map inputKind ins) (map outputKind outs)
    size = txVirtualSize tx
    ins = map (either error id . unmarshal (net, ctx) . (.script)) tx.inputs
    outs = map (either error id . unmarshal ctx . (.script)) tx.outputs
    inputKind (ScriptHashInput _ (PayMulSig keys r)) = InputMulSig r (length keys)
    inputKind _ = InputPKHash
    outputKind o
      | isPayPKHash o = OutputPKHash
      | otherwise = OutputScriptHash
    signatures = sum (map sigCount ins)
    sigCount (ScriptHashInput (SpendMulSig sigs) _) = length sigs
    sigCount _ = 1

-- The guess is an upper bound on the weight of the transaction once signed:
-- by signTx, or by signNestedWitnessTx with its SegWit inputs nested. Only
-- signing data whose inputs all have a kind is generated.
testGuessWeight :: Network -> Ctx -> Bool -> Property
testGuessWeight net ctx nested =
  forAll (arbitrarySigningData net ctx `suchThat` allKnown) $ \(tx, sigis, keys) ->
    let signed = either error id (sign net ctx tx sigis (map (.key) keys))
        kinds = mapMaybe (sigInputKind ctx nested keys) sigis
        guess = guessTxWeight kinds (map (txOutKind ctx) tx.outputs)
     in counterexample ("weight " <> show (txWeight signed) <> ", guess " <> show guess) $
          txWeight signed <= guess
  where
    sign = if nested then signNestedWitnessTx else signTx
    allKnown (_, sigis, keys) = all (isJust . sigInputKind ctx nested keys) sigis

-- The kind of input a SigInput is signed as, when the estimator has one.
-- The key of a public key hash is found among the signing keys, to tell
-- whether it is compressed. These are left out, since the estimator has no
-- kind for them: bare multisig, pay-to-script-hash and
-- pay-to-witness-script-hash of a single key, multisig with an uncompressed
-- key, and pay-to-witness-public-key-hash with an uncompressed key, which
-- the estimator counts as compressed.
sigInputKind :: Ctx -> Bool -> [PrivateKey] -> SigInput -> Maybe InputKind
sigInputKind ctx nested keys si = case (si.script, si.redeem) of
  (PayPK _, Nothing) -> Just InputPK
  (PayPKHash h, Nothing) -> do
    k <- keyOfHash h
    Just $ if k.compress then InputPKHash else InputUncompressedPKHash
  (PayScriptHash _, Just (PayMulSig ps m)) -> compressedMultisig InputMulSig ps m
  (PayWitnessPKHash h, Nothing) -> do
    k <- keyOfHash h
    guard k.compress
    Just $ if nested then InputNestedWitnessPKHash else InputWitnessPKHash
  (PayWitnessScriptHash _, Just (PayMulSig ps m)) ->
    compressedMultisig (if nested then InputNestedWitnessMulSig else InputWitnessMulSig) ps m
  (PayWitness 1 program, Nothing) | B.length program == 32 -> Just InputTaproot
  _ -> Nothing
  where
    keyOfHash h = find (\k -> addressHash160 (pubKeyAddr ctx (derivePublicKey ctx k)) == Just h) keys
    compressedMultisig kind ps m = do
      guard (all (.compress) ps)
      Just (kind m (length ps))

-- The kind of an output, from its script. A script of no named kind is
-- 'OutputScript' with its size.
txOutKind :: Ctx -> TxOut -> OutputKind
txOutKind ctx out = case unmarshal ctx out.script of
  Right (PayPKHash _) -> OutputPKHash
  Right (PayScriptHash _) -> OutputScriptHash
  Right (PayScript32Hash _) -> OutputScript32Hash
  Right (PayWitnessPKHash _) -> OutputWitnessPKHash
  Right (PayWitnessScriptHash _) -> OutputWitnessScriptHash
  Right (PayWitness 1 program) | B.length program == 32 -> OutputTaproot
  _ -> OutputScript (B.length out.script)

-- A selection covers the target, the fee of the coins chosen, and the
-- change. When there is no selection, no prefix of the coins covers the
-- target and its own fee, since the coins are taken in order.
testChooseCoins :: [TestCoin] -> [OutputKind] -> Word64 -> Word64 -> Property
testChooseCoins coins outs target byteFee =
  case chooseCoins target byteFee outs True coins of
    Right (chosen, change) ->
      sum (map coinValue chosen) === target + change + fee chosen
    Left _ ->
      property $ target == 0 || all (\prefix -> sum (map coinValue prefix) < target + fee prefix) (drop 1 (inits coins))
  where
    fee cs = guessTxFee byteFee (map coinInputKind cs) outs

{- Signing Transactions -}

testDetSignTx :: Network -> Ctx -> (Tx, [SigInput], [PrivateKey]) -> Bool
testDetSignTx net ctx (tx, sigis, prv) =
  not verify1 && not verify2 && verify3
  where
    verify1 = verifyStdTx net ctx tx verData
    verify2 = verifyStdTx net ctx txSigP verData
    verify3 = verifyStdTx net ctx txSigC verData
    txSigP = either error id $ signTx net ctx tx sigis (map (.key) (tail prv))
    txSigC = either error id $ signTx net ctx txSigP sigis [(head prv).key]
    sigData SigInput {..} = (script, value, outpoint)
    verData = map sigData sigis

testDetSignNestedTx :: Network -> Ctx -> (Tx, [SigInput], [PrivateKey]) -> Bool
testDetSignNestedTx net ctx (tx, sigis, prv) =
  not verify1 && not verify2 && verify3
  where
    verify1 = verifyStdTx net ctx tx verData
    verify2 = verifyStdTx net ctx txSigP verData
    verify3 = verifyStdTx net ctx txSigC verData
    txSigP =
      either error id $
        signNestedWitnessTx net ctx tx sigis ((.key) <$> tail prv)
    txSigC =
      either error id $
        signNestedWitnessTx net ctx txSigP sigis [(head prv).key]
    verData = handleSegwit <$> sigis
    handleSegwit (SigInput s v o _ _)
      | isSegwit s = (toP2SH (either error id (encodeOutput ctx s)), v, o)
      | otherwise = (s, v, o)

testMergeTx :: Network -> Ctx -> ([Tx], [(ScriptOutput, Word64, OutPoint, Int, Int)]) -> Bool
testMergeTx net ctx (txs, os) =
  and
    [ isRight mergeRes,
      length mergedTx.inputs == length os,
      if enoughSigs
        then isValid
        else not isValid,
      -- Signature count == min (length txs) (sum required signatures)
      sum (map snd sigMap) == min (length txs) (sum (map fst sigMap))
    ]
  where
    outs = map (\(so, val, op, _, _) -> (so, val, op)) os
    mergeRes = mergeTxs net ctx txs outs
    mergedTx = fromRight (error "Could not merge") mergeRes
    isValid = verifyStdTx net ctx mergedTx outs
    enoughSigs = all (\(m, c) -> c >= m) sigMap
    sigFun (_, _, _, m, _) inp = (m, sigCnt inp)
    sigMap = zipWith sigFun os mergedTx.inputs
    sigCnt inp =
      case unmarshal (net, ctx) inp.script of
        Right (RegularInput (SpendMulSig sigs)) -> length sigs
        Right (ScriptHashInput (SpendMulSig sigs) _) -> length sigs
        _ -> error "Invalid input script type"

{- Ids -}

-- The id of the genesis coinbase, in display order
genesisTxId :: Text
genesisTxId = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

-- The signed transaction of the P2WPKH example of BIP 143: 343 bytes, 233
-- without its witness
bip143SignedTx :: Text
bip143SignedTx =
  "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"

hexBytes :: Text -> ByteString
hexBytes = fromJust . decodeHex

parseTx :: Text -> Either String Tx
parseTx = runGetS deserialize . hexBytes

idsSpec :: Spec
idsSpec =
  describe "Transaction ids" $ do
    it "hexToTxHash reads 32 bytes of hex in display order, in either case" $ do
      fmap (encodeHex . runPutS . serialize) (hexToTxHash genesisTxId)
        `shouldBe` Just "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
      hexToTxHash "4A5E1E4BAAB89F3A32518A88C31BC87F618F76673E2CC77AB2127B7AFDEDA33B" `shouldBe` hexToTxHash genesisTxId
      fmap txHashToHex (hexToTxHash genesisTxId) `shouldBe` Just genesisTxId

    it "hexToTxHash refuses hex that is not exactly 32 bytes, or not hex" $ do
      hexToTxHash (genesisTxId <> "ff") `shouldBe` Nothing
      hexToTxHash (T.take 62 genesisTxId) `shouldBe` Nothing
      hexToTxHash "" `shouldBe` Nothing
      hexToTxHash "zz5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b" `shouldBe` Nothing

    it "the Read, string and JSON forms of a transaction id refuse 33 bytes" $ do
      (readMaybe (show (cs (genesisTxId <> "ff") :: String)) :: Maybe TxHash) `shouldBe` Nothing
      (decode (cs ("\"" <> genesisTxId <> "ff\"")) :: Maybe TxHash) `shouldBe` Nothing
      (decode (cs ("{\"txid\":\"" <> genesisTxId <> "ff\",\"index\":0}")) :: Maybe OutPoint) `shouldBe` Nothing
      (decode (cs ("{\"txid\":\"" <> genesisTxId <> "\",\"index\":0}")) :: Maybe OutPoint) `shouldBe` Just (OutPoint (fromJust (hexToTxHash genesisTxId)) 0)

    it "the witness transaction id of the BIP 143 example is the hash of all its bytes, and its id leaves the witness out" $ do
      tx <- either fail return (parseTx bip143SignedTx)
      txHashToHex (txHash tx) `shouldBe` "e8151a2af31c368a35053ddd4bdb285a8595c769a3ad83e0fa02314a602d4609"
      txHashToHex (txWitnessHash tx) `shouldBe` "c36c38370907df2324d9ce9d149d191192f338b37665a82e78e76a12c909b762"

    it "the witness transaction id of a transaction without witness is its id" $
      txWitnessHash mainnetGenesisTx `shouldBe` txHash mainnetGenesisTx

    -- The genesis coinbase with its input script removed hashes to
    -- 2a9487e4…78c1, which is neither its id nor the hash of its script
    it "nosigTxHash is the hash of the transaction with its input scripts and witness removed" $ do
      txHashToHex (nosigTxHash mainnetGenesisTx) `shouldBe` "2a9487e467412bc4b0a993a770bc73d5f4230f0ea5907b3f5df2669f0d7e78c1"
      tx <- either fail return (parseTx bip143SignedTx)
      let unsigned = Tx tx.version [TxIn i.outpoint "" i.sequence | i <- tx.inputs] tx.outputs [] tx.locktime
      nosigTxHash tx `shouldBe` nosigTxHash unsigned
      nosigTxHash unsigned `shouldBe` txHash unsigned

{- Bytes -}

bytesSpec :: Ctx -> Spec
bytesSpec ctx =
  describe "Transaction bytes" $ do
    -- The bytes of the first pkhash vector, with the input count written
    -- as 0xffffffffffffffff, which wraps around to -1 as an Int
    it "refuse a count that is beyond the limit of a list" $ do
      parseTx ("01000000" <> "ffffffffffffffffff" <> "02" <> "804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac" <> "804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac" <> "00000000")
        `shouldSatisfy` either ("List count too large" `isInfixOf`) (const False)
      parseTx ("01000000" <> "0001" <> "01db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654a1eb29eb0e00000000ffffffff01804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac" <> "ffffffffffffffffff" <> "00000000")
        `shouldSatisfy` either ("List count too large" `isInfixOf`) (const False)
      parseTx ("01000000" <> "01db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654a1eb29eb0e000000" <> "ffffffffffffffffff" <> "ffffffff" <> "01804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac" <> "00000000")
        `shouldSatisfy` either ("Byte count too large" `isInfixOf`) (const False)

    it "refuse the witness marker on a transaction whose witness is empty, as Bitcoin Core does" $ do
      parseTx ("01000000" <> "0001" <> "01db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654a1eb29eb0e00000000ffffffff01804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac" <> "00" <> "00000000")
        `shouldSatisfy` either ("Superfluous witness record" `isInfixOf`) (const False)
      -- No inputs, so no witness at all
      parseTx ("01000000" <> "0001" <> "00" <> "01804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac" <> "00000000")
        `shouldSatisfy` either ("Superfluous witness record" `isInfixOf`) (const False)

    -- An input count of zero makes the next byte the flags of BIP 144
    it "refuse a flags byte other than the witness bit after an empty input list, as Bitcoin Core does" $ do
      parseTx ("01000000" <> "00" <> "02" <> "02e80300000000000000e8030000000000000000000000")
        `shouldSatisfy` either ("Unknown transaction optional data" `isInfixOf`) (const False)
      parseTx ("01000000" <> "00" <> "03" <> "01db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654a1eb29eb0e00000000ffffffff01804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac" <> "00" <> "00000000")
        `shouldSatisfy` either ("Unknown transaction optional data" `isInfixOf`) (const False)

    it "read an empty input list with a zero flags byte as a transaction with no inputs and no outputs, as Bitcoin Core does" $
      parseTx ("01000000" <> "00" <> "00" <> "00000000") `shouldBe` Right (Tx 1 [] [] [] 0)

    it "refuse a literal with bytes after the transaction" $ do
      let legacy = "0100000001db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654a1eb29eb0e00000000ffffffff01804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac00000000"
      length (fromString legacy :: Tx).inputs `shouldBe` 1
      evaluate (fromString (legacy <> "00") :: Tx) `shouldThrow` errorCall "Could not read transaction from hex string"

    it "write a transaction whose witness stacks are all empty without the marker, and read it back without witness" $ do
      let legacy = "0100000001db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654a1eb29eb0e00000000ffffffff01804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac00000000"
      tx <- either fail return (parseTx legacy)
      hasWitness tx `shouldBe` False
      hasWitness tx {witness = [[]]} `shouldBe` False
      hasWitness tx {witness = [["x"]]} `shouldBe` True
      encodeHex (runPutS (serialize tx {witness = [[]]})) `shouldBe` legacy
      runGetS deserialize (runPutS (serialize tx {witness = [[]]})) `shouldBe` Right tx
      txWitnessHash tx {witness = [[]]} `shouldBe` txHash tx

    it "write one witness stack per input" $ do
      let legacy = "0100000001db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654a1eb29eb0e00000000ffffffff01804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac00000000"
      tx <- either fail return (parseTx legacy)
      -- A second stack has no input to go with
      fmap (.witness) (runGetS deserialize (runPutS (serialize tx {witness = [["ab"], ["cd"]]})) :: Either String Tx) `shouldBe` Right [["ab"]]

    it "give the weight and the virtual size of BIP 141: the BIP 143 example and the genesis coinbase" $ do
      tx <- either fail return (parseTx bip143SignedTx)
      -- 3 × 233 + 343 = 1042 weight units, 260.5 rounded up
      txWeight tx `shouldBe` 1042
      txVirtualSize tx `shouldBe` 261
      -- 204 bytes without witness: four times the size
      txWeight mainnetGenesisTx `shouldBe` 816
      txVirtualSize mainnetGenesisTx `shouldBe` 204

    it "the JSON form of an output refuses a negative amount" $ do
      (eitherDecode "{\"value\":-1,\"outputscript\":\"\"}" :: Either String TxOut) `shouldSatisfy` isLeft
      (eitherDecode "{\"value\":5000000000,\"outputscript\":\"51\"}" :: Either String TxOut) `shouldBe` Right (TxOut 5000000000 "\x51")

{- Sizes and fees -}

sizeSpec :: Ctx -> Spec
sizeSpec ctx =
  describe "Size and fee estimation" $ do
    it "counts the bytes of each kind of input, without and with witness" $ do
      -- outpoint 36, sequence 4, script length 1, signature push 73
      inputWeight InputPK `shouldBe` (114, 0)
      -- outpoint 36, sequence 4, script length 1, signature push 73, key push 34
      inputWeight InputPKHash `shouldBe` (148, 0)
      -- the same with a 65-byte key: push 66
      inputWeight InputUncompressedPKHash `shouldBe` (180, 0)
      -- an empty script; the witness: count 1, signature 73, key 34
      inputWeight InputWitnessPKHash `shouldBe` (41, 108)
      -- the push of the 22-byte program: 23 bytes after their length
      inputWeight InputNestedWitnessPKHash `shouldBe` (64, 108)
      -- the witness: count 1, a 65-byte signature after its length
      inputWeight InputTaproot `shouldBe` (41, 67)
      -- OP_0, two signatures of 73, the 105-byte script pushed with OP_PUSHDATA1 (107): 254 bytes, after a 3-byte length
      inputWeight (InputMulSig 2 3) `shouldBe` (297, 0)
      -- the witness: count 1, the empty item 1, two signatures of 73, the script after its length 106
      inputWeight (InputWitnessMulSig 2 3) `shouldBe` (41, 254)
      -- the push of the 34-byte program: 35 bytes after their length
      inputWeight (InputNestedWitnessMulSig 2 3) `shouldBe` (76, 254)
      -- OP_0, one signature, the 37-byte script pushed directly (38): 112 bytes
      inputWeight (InputMulSig 1 1) `shouldBe` (153, 0)

    it "counts two bytes for each count of a multisig script above 16" $ do
      -- 17-of-20: OP_m 2, 20 keys of 34 (680), OP_n 2, OP_CHECKMULTISIG 1: a 685-byte script.
      -- OP_0, 17 signatures of 73 (1241), the script pushed with OP_PUSHDATA2 (688): 1930 bytes after a 3-byte length, and 40
      inputWeight (InputMulSig 17 20) `shouldBe` (1973, 0)
      -- the witness: count 1, the empty item 1, 17 signatures of 73 (1241), the 685-byte script after its 3-byte length (688)
      inputWeight (InputWitnessMulSig 17 20) `shouldBe` (41, 1931)
      inputWeight (InputNestedWitnessMulSig 17 20) `shouldBe` (76, 1931)
      -- 1-of-17: OP_1 1, 17 keys (578), a two-byte count, OP_CHECKMULTISIG: 582 bytes.
      -- OP_0, one signature (73), OP_PUSHDATA2 (585): 659 bytes after a 3-byte length, and 40
      inputWeight (InputMulSig 1 17) `shouldBe` (702, 0)
      -- 16-of-16 keeps one-byte counts: 1 + 544 + 1 + 1 = 547 bytes.
      -- OP_0, 16 signatures (1168), OP_PUSHDATA2 (550): 1719 bytes after a 3-byte length, and 40
      inputWeight (InputMulSig 16 16) `shouldBe` (1762, 0)

    it "counts the bytes of each kind of output" $ do
      outputSize OutputPKHash `shouldBe` 34
      outputSize OutputScriptHash `shouldBe` 32
      -- amount 8, length 1, OP_HASH256, a 32-byte push, OP_EQUAL: 35
      outputSize OutputScript32Hash `shouldBe` 44
      outputSize OutputWitnessPKHash `shouldBe` 31
      outputSize OutputWitnessScriptHash `shouldBe` 43
      outputSize OutputTaproot `shouldBe` 43
      -- a bare 1-of-1 multisig script, OP_1, a 33-byte key push, OP_1, OP_CHECKMULTISIG: 37 bytes after a 1-byte length
      outputSize (OutputScript 37) `shouldBe` 46
      -- an empty script is its 1-byte length
      outputSize (OutputScript 0) `shouldBe` 9
      -- a 1000-byte script after its 3-byte length
      outputSize (OutputScript 1000) `shouldBe` 1011

    it "gives the weight and virtual size of a transaction of each shape" $ do
      -- 8 + 1 + 148 + 1 + 34 = 192 bytes, no witness
      guessTxWeight [InputPKHash] [OutputPKHash] `shouldBe` 768
      guessTxSize [InputPKHash] [OutputPKHash] `shouldBe` 192
      -- 8 + 1 + 41 + 1 + 31 = 82 bytes without witness, 2 + 108 of witness: 438 units, 109.5 rounded up
      guessTxWeight [InputWitnessPKHash] [OutputWitnessPKHash] `shouldBe` 438
      guessTxSize [InputWitnessPKHash] [OutputWitnessPKHash] `shouldBe` 110
      -- 8 + 1 + 64 + 1 + 32 = 106 bytes, 110 of witness: 534 units
      guessTxSize [InputNestedWitnessPKHash] [OutputScriptHash] `shouldBe` 134
      -- 8 + 1 + 41 + 1 + 43 = 94 bytes, 2 + 67 of witness: 445 units
      guessTxSize [InputTaproot] [OutputTaproot] `shouldBe` 112
      -- 8 + 1 + 297 + 1 + 34 + 32 = 373 bytes, no witness
      guessTxSize [InputMulSig 2 3] [OutputPKHash, OutputScriptHash] `shouldBe` 373
      -- 8 + 1 + 41 + 1 + 43 = 94 bytes, 2 + 254 of witness: 632 units
      guessTxSize [InputWitnessMulSig 2 3] [OutputWitnessScriptHash] `shouldBe` 158
      -- 8 + 1 + 76 + 1 + 34 = 120 bytes, 256 of witness: 736 units
      guessTxSize [InputNestedWitnessMulSig 2 3] [OutputPKHash] `shouldBe` 184
      -- 8 + 1 + 148 + 41 + 1 + 34 = 233 bytes; the witness: 2, the empty stack of the legacy input 1, 108: 1043 units, 260.75 rounded up
      guessTxSize [InputPKHash, InputWitnessPKHash] [OutputPKHash] `shouldBe` 261

    it "counts the empty witness stack of each input without a witness when another has one" $ do
      -- 4 + 1 + 3 × 148 + 41 + 1 + 34 + 4 = 529 bytes; the witness: 2 + 1 + 1 + 1 + 108 = 113; 3 × 529 + 642 = 2229 units, 557.25 rounded up
      guessTxWeight [InputPKHash, InputPKHash, InputPKHash, InputWitnessPKHash] [OutputPKHash] `shouldBe` 2229
      guessTxSize [InputPKHash, InputPKHash, InputPKHash, InputWitnessPKHash] [OutputPKHash] `shouldBe` 558
      -- 8 + 1 + 114 + 41 + 1 + 44 = 209 bytes; the witness: 2 + 1 + 67 = 70: 906 units, 226.5 rounded up
      guessTxWeight [InputPK, InputTaproot] [OutputScript32Hash] `shouldBe` 906
      guessTxSize [InputPK, InputTaproot] [OutputScript32Hash] `shouldBe` 227
      -- without a witness, no stack is counted: 4 × (8 + 1 + 296 + 1 + 34)
      guessTxWeight [InputPKHash, InputPKHash] [OutputPKHash] `shouldBe` 1360

    it "charges the fee rate per virtual byte" $ do
      guessTxFee 10 [InputPKHash] [OutputPKHash] `shouldBe` 1920
      guessTxFee 10 [InputWitnessPKHash] [OutputWitnessPKHash] `shouldBe` 1100
      guessTxFee 0 [InputPKHash] [OutputPKHash] `shouldBe` 0

    it "is at least the virtual size of a signed P2WPKH spend, and of a Taproot key path spend" $ do
      (k0, _) <- generate (arbitraryKeyPair ctx)
      -- SegWit keys are compressed
      let k = PrivateKey k0.key True
          p = derivePublicKey ctx k
          h = fromJust (addressHash160 (pubKeyAddr ctx p))
          op = OutPoint (fromJust (hexToTxHash genesisTxId)) 0
          witnessTx = buildTx ctx [op] [(PayWitnessPKHash h, 90000)]
          taprootOutput = taprootScriptOutput ctx (TaprootOutput p.point Nothing)
          taprootTx = buildTx ctx [op] [(taprootOutput, 90000)]
      signedWitness <- either fail return (signTx btc ctx witnessTx [SigInput (PayWitnessPKHash h) 100000 op sigHashAll Nothing] [k.key])
      signedTaproot <- either fail return (signTx btc ctx taprootTx [SigInput taprootOutput 100000 op sigHashDefault Nothing] [k.key])
      -- The witness of the taproot spend is 64 bytes, one less than counted
      txVirtualSize signedWitness `shouldSatisfy` (\v -> v <= 110 && v >= 108)
      txVirtualSize signedTaproot `shouldSatisfy` (\v -> v <= 112 && v >= 111)

{- Coin selection -}

coinSelectionSpec :: Spec
coinSelectionSpec =
  describe "Coin selection" $ do
    -- One P2PKH input and two P2PKH outputs: 8 + 1 + 148 + 1 + 68 = 226
    -- virtual bytes, 2260 satoshi at 10 satoshi per virtual byte. The first
    -- coin covers 60000 + 2260, with 37740 of change.
    it "selects the first coins that cover the target and the fee of the transaction they make" $ do
      let coins = [TestCoin 100000 InputPKHash, TestCoin 50000 InputPKHash]
      chooseCoins 60000 10 [OutputPKHash, OutputPKHash] False coins `shouldBe` Right ([TestCoin 100000 InputPKHash], 37740)
      chooseCoins 60000 10 [OutputPKHash, OutputPKHash] True coins `shouldBe` Right ([TestCoin 100000 InputPKHash], 37740)

    -- Two P2WPKH inputs and one P2WPKH output: 8 + 1 + 82 + 1 + 31 = 123
    -- bytes without witness, 2 + 216 with it: 710 units, 178 virtual
    -- bytes, 1780 satoshi. Neither coin alone covers 60000 and the fee of
    -- one input (8 + 1 + 41 + 1 + 31 = 82, 2 + 108: 438 units, 110 bytes,
    -- 1100 satoshi), both together do, with 90000 - 60000 - 1780 of change.
    it "adds coins until they cover the target and the fee, which grows with them" $ do
      let coins = [TestCoin 50000 InputWitnessPKHash, TestCoin 40000 InputWitnessPKHash]
      chooseCoins 60000 10 [OutputWitnessPKHash] False coins `shouldBe` Right ([TestCoin 40000 InputWitnessPKHash, TestCoin 50000 InputWitnessPKHash], 28220)

    it "looks for a smaller solution after the first when asked to continue" $ do
      let coins = [TestCoin 30000 InputPKHash, TestCoin 40000 InputPKHash, TestCoin 65000 InputPKHash]
      -- 30000 + 40000 covers 60000 + 10 × (8 + 1 + 296 + 1 + 34) = 60000 + 3400; then 65000 alone covers 60000 + 1920, and is smaller
      chooseCoins 60000 10 [OutputPKHash] False coins `shouldBe` Right ([TestCoin 40000 InputPKHash, TestCoin 30000 InputPKHash], 6600)
      chooseCoins 60000 10 [OutputPKHash] True coins `shouldBe` Right ([TestCoin 65000 InputPKHash], 3080)

    it "refuses a target of zero and reports when the coins do not suffice" $ do
      chooseCoins 0 10 [OutputPKHash] False [TestCoin 100000 InputPKHash] `shouldBe` Left "chooseCoins: Target must be > 0"
      chooseCoins 100000 10 [OutputPKHash] False [TestCoin 100000 InputPKHash] `shouldBe` Left "chooseCoins: No solution found"
      chooseCoins 1 10 [OutputPKHash] False ([] :: [TestCoin]) `shouldBe` Left "chooseCoins: No solution found"

{- Verification -}

verificationSpec :: Ctx -> Spec
verificationSpec ctx =
  describe "Verification" $ do
    let coinOf = OutPoint (fromJust (hexToTxHash genesisTxId))
    it "accepts a correct P2PKH spend, and refuses a witness on its input, a wrong key, a wrong amount and a missing coin" $ do
      (k, p) <- generate (arbitraryKeyPair ctx)
      (_, other) <- generate (arbitraryKeyPair ctx)
      let h = fromJust (addressHash160 (pubKeyAddr ctx p))
          otherHash = fromJust (addressHash160 (pubKeyAddr ctx other))
          op = coinOf 0
          tx = buildTx ctx [op] [(PayPKHash h, 90000)]
      signed <- either fail return (signTx btc ctx tx [SigInput (PayPKHash h) 100000 op sigHashAll Nothing] [k.key])
      verifyStdTx btc ctx signed [(PayPKHash h, 100000, op)] `shouldBe` True
      verifyStdTx btc ctx signed {witness = [["junk"]]} [(PayPKHash h, 100000, op)] `shouldBe` False
      verifyStdTx btc ctx signed [(PayPKHash otherHash, 100000, op)] `shouldBe` False
      -- The legacy digest does not commit to the amount, but the outputs may not spend more than the coin
      verifyStdTx btc ctx signed [(PayPKHash h, 89999, op)] `shouldBe` False
      verifyStdTx btc ctx signed [(PayPKHash h, 100000, coinOf 1)] `shouldBe` False
      verifyStdTx btc ctx signed [] `shouldBe` False
      verifyStdInput btc ctx signed [(PayPKHash h, 100000, op)] 0 `shouldBe` True
      verifyStdInput btc ctx signed [(PayPKHash h, 100000, op)] 1 `shouldBe` False
      verifyStdInput btc ctx signed [(PayPKHash h, 100000, op)] (-1) `shouldBe` False

    it "refuses a transaction without inputs, and the outputs of a transaction spending more than its coins" $ do
      (k, p) <- generate (arbitraryKeyPair ctx)
      let h = fromJust (addressHash160 (pubKeyAddr ctx p))
          ops = [coinOf 0, coinOf 1]
          tx = buildTx ctx ops [(PayPKHash h, 150000)]
          sigis = [SigInput (PayPKHash h) 100000 op sigHashAll Nothing | op <- ops]
          coins = [(PayPKHash h, 100000, op) | op <- ops]
      signed <- either fail return (signTx btc ctx tx sigis [k.key])
      verifyStdTx btc ctx signed coins `shouldBe` True
      verifyStdTx btc ctx signed (take 1 coins) `shouldBe` False
      verifyStdTx btc ctx (buildTx ctx [] [(PayPKHash h, 1)]) [] `shouldBe` False
      -- The same coins hold less than the outputs spend
      verifyStdTx btc ctx signed [(PayPKHash h, 70000, op) | op <- ops] `shouldBe` False

    it "signs SIGHASH_SINGLE on a legacy input with an output at its index and on a SegWit input, but refuses it on a legacy input without one" $ do
      (k, p) <- generate (arbitraryKeyPair ctx)
      let h = fromJust (addressHash160 (pubKeyAddr ctx p))
          ops = [coinOf 0, coinOf 1]
          -- one output, so input 1 has none at its index
          tx = buildTx ctx ops [(PayPKHash h, 150000)]
          legacy op = SigInput (PayPKHash h) 100000 op sigHashSingle Nothing
          segwit op = SigInput (PayWitnessPKHash h) 100000 op sigHashSingle Nothing
      signedFirst <- either fail return (signTx btc ctx tx [legacy (coinOf 0)] [k.key])
      verifyStdInput btc ctx signedFirst [(PayPKHash h, 100000, coinOf 0)] 0 `shouldBe` True
      signTx btc ctx tx [legacy (coinOf 1)] [k.key] `shouldBe` Left "makeSignature: SIGHASH_SINGLE without an output at the input index"
      -- The BIP 143 digest commits to the coin even without an output
      signedWitness <- either fail return (signTx btc ctx tx [segwit (coinOf 1)] [k.key])
      verifyStdInput btc ctx signedWitness [(PayWitnessPKHash h, 100000, coinOf 1)] 1 `shouldBe` True

    -- A node accepts the signature over the constant digest 1 that a
    -- legacy SIGHASH_SINGLE input without an output has, so the verifier
    -- must too, although the signer refuses to make one
    it "accepts a legacy SIGHASH_SINGLE signature over the constant digest 1, as a node does" $ do
      (k, p) <- generate (arbitraryKeyPair ctx)
      let h = fromJust (addressHash160 (pubKeyAddr ctx p))
          ops = [coinOf 0, coinOf 1]
          tx = buildTx ctx ops [(PayPKHash h, 150000)]
          one = "0100000000000000000000000000000000000000000000000000000000000000" :: Hash256
          overOne = marshal (btc, ctx) (RegularInput (SpendPKHash (TxSignature (signHash ctx k.key one) sigHashSingle) p))
          spent = Tx tx.version [TxIn (coinOf 0) "" 0xffffffff, TxIn (coinOf 1) overOne 0xffffffff] tx.outputs [] tx.locktime
          spentFirst = Tx tx.version [TxIn (coinOf 0) overOne 0xffffffff, TxIn (coinOf 1) "" 0xffffffff] tx.outputs [] tx.locktime
      verifyStdInput btc ctx spent [(PayPKHash h, 100000, coinOf 1)] 1 `shouldBe` True
      -- The same signature on input 0, which has an output, does not verify
      verifyStdInput btc ctx spentFirst [(PayPKHash h, 100000, coinOf 0)] 0 `shouldBe` False

    it "refuses a SegWit input with a non-empty input script and a wrong amount" $ do
      (k, p) <- generate (arbitraryKeyPair ctx)
      let h = fromJust (addressHash160 (pubKeyAddr ctx p))
          op = coinOf 0
          tx = buildTx ctx [op] [(PayWitnessPKHash h, 90000)]
      signed <- either fail return (signTx btc ctx tx [SigInput (PayWitnessPKHash h) 100000 op sigHashAll Nothing] [k.key])
      verifyStdTx btc ctx signed [(PayWitnessPKHash h, 100000, op)] `shouldBe` True
      -- The BIP 143 digest commits to the amount
      verifyStdTx btc ctx signed [(PayWitnessPKHash h, 100001, op)] `shouldBe` False
      let pushed = Tx signed.version [TxIn op "\x51" i.sequence | i <- signed.inputs] signed.outputs signed.witness signed.locktime
      verifyStdTx btc ctx pushed [(PayWitnessPKHash h, 100000, op)] `shouldBe` False

{- Merging -}

mergeSpec :: Ctx -> Spec
mergeSpec ctx =
  describe "Merging partially signed transactions" $ do
    it "leaves an input that no transaction signed unsigned, and merges the others" $ do
      (k1, p1) <- generate (arbitraryKeyPair ctx)
      (k2, p2) <- generate (arbitraryKeyPair ctx)
      let ms = PayMulSig [p1, p2] 2
          so = PayScriptHash (fromJust (addressHash160 (payToScriptAddress ctx ms)))
          ops = [OutPoint (fromJust (hexToTxHash genesisTxId)) 0, OutPoint (fromJust (hexToTxHash genesisTxId)) 1]
          tx = buildTx ctx ops [(PayPKHash (fromJust (addressHash160 (pubKeyAddr ctx p1))), 90000)]
          coins = [(so, 100000, op) | op <- ops]
          sigi = SigInput so 100000 (head ops) sigHashAll (Just ms)
      a <- either fail return (signTx btc ctx tx [sigi] [k1.key])
      b <- either fail return (signTx btc ctx tx [sigi] [k2.key])
      merged <- either fail return (mergeTxs btc ctx [a, b] coins)
      (merged.inputs !! 1).script `shouldBe` ""
      verifyStdInput btc ctx merged coins 0 `shouldBe` True
      verifyStdTx btc ctx merged coins `shouldBe` False
      -- The second input signed by both completes the transaction
      let sigi2 = SigInput so 100000 (ops !! 1) sigHashAll (Just ms)
      c <- either fail return (signTx btc ctx tx [sigi2] [k1.key])
      d <- either fail return (signTx btc ctx tx [sigi2] [k2.key])
      complete <- either fail return (mergeTxs btc ctx [a, b, c, d] coins)
      verifyStdTx btc ctx complete coins `shouldBe` True

    it "countMulSig counts the signatures that verify, in key order" $ do
      (k1, p1) <- generate (arbitraryKeyPair ctx)
      (k2, p2) <- generate (arbitraryKeyPair ctx)
      (k3, p3) <- generate (arbitraryKeyPair ctx)
      let ms = PayMulSig [p1, p2, p3] 2
          msScript = either error id (encodeOutput ctx ms)
          op = OutPoint (fromJust (hexToTxHash genesisTxId)) 0
          tx = buildTx ctx [op] [(PayPKHash (fromJust (addressHash160 (pubKeyAddr ctx p1))), 90000)]
          sigOf k = TxSignature (signHash ctx k.key (either error id (txSigHash btc tx msScript 100000 0 sigHashAll))) sigHashAll
          count = countMulSig btc ctx tx msScript 100000 0 (map (.point) [p1, p2, p3])
      count [sigOf k1, sigOf k3] `shouldBe` 2
      count [sigOf k1, sigOf k2, sigOf k3] `shouldBe` 3
      count [sigOf k1, TxSignatureEmpty, sigOf k3] `shouldBe` 2
      -- A signature out of key order is not counted, nor a signature of another digest
      count [sigOf k3, sigOf k1] `shouldBe` 1
      count [TxSignature (signHash ctx k1.key (sha256 ("other" :: ByteString))) sigHashAll] `shouldBe` 0
      count [] `shouldBe` 0

    it "findSigInput pairs the signing parameters with the index of their input" $ do
      let ops = [OutPoint (fromJust (hexToTxHash genesisTxId)) i | i <- [0 .. 2]]
          tx = buildTx ctx ops []
          sigi op = SigInput (PayPKHash "0000000000000000000000000000000000000000") 1 op sigHashAll Nothing
      map snd (findSigInput [sigi (ops !! 2), sigi (ops !! 0)] tx.inputs) `shouldBe` [0, 2]
      findSigInput [sigi (OutPoint (fromJust (hexToTxHash genesisTxId)) 9)] tx.inputs `shouldBe` []

    it "buildInput refuses an index out of range, a Taproot output and a mismatched redeem script" $ do
      (k, p) <- generate (arbitraryKeyPair ctx)
      let op = OutPoint (fromJust (hexToTxHash genesisTxId)) 0
          tx = buildTx ctx [op] []
          sig = TxSignature (signHash ctx k.key (sha256 ("digest" :: ByteString))) sigHashAll
          h = fromJust (addressHash160 (pubKeyAddr ctx p))
      buildInput btc ctx tx 1 (PayPKHash h) 1 Nothing sig p `shouldBe` Left "buildInput: Invalid input index"
      buildInput btc ctx tx 0 (taprootScriptOutput ctx (TaprootOutput p.point Nothing)) 1 Nothing sig p `shouldBe` Left "buildInput: a Taproot input has no input script"
      buildInput btc ctx tx 0 (PayPKHash h) 1 (Just (PayPK p)) sig p `shouldBe` Left "buildInput: Invalid output/redeem script combination"
      buildInput btc ctx tx 0 (PayPKHash h) 1 Nothing sig p `shouldBe` Right (RegularInput (SpendPKHash sig p))

    it "refuses an empty list and transactions that differ" $ do
      mergeTxs btc ctx [] [] `shouldBe` Left "Transaction list is empty"
      let op = OutPoint (fromJust (hexToTxHash genesisTxId)) 0
          one = buildTx ctx [op] []
          other = buildTx ctx [op] [(PayPK (PublicKey (derivePubKey ctx (fromJust (secKey (B.replicate 32 1)))) True), 1)]
      mergeTxs btc ctx [one] [] `shouldBe` Right one
      mergeTxs btc ctx [one, other] [] `shouldBe` Left "Transactions do not match"

{- Taproot -}

taprootSigningSpec :: Ctx -> Spec
taprootSigningSpec ctx =
  describe "Taproot key path signing" $ do
    let op = OutPoint (fromJust (hexToTxHash genesisTxId)) 0
    it "signs with the internal key of an output without script tree, as BIP 86 spends, and with the output key itself" $ do
      (k, p) <- generate (arbitraryKeyPair ctx)
      let so = taprootScriptOutput ctx (TaprootOutput p.point Nothing)
          tx = buildTx ctx [op] [(so, 90000)]
          sigi = SigInput so 100000 op sigHashDefault Nothing
          tweaked = fromJust (taprootOutputSecKey ctx k.key Nothing)
      byInternal <- either fail return (signTx btc ctx tx [sigi] [k.key])
      byOutput <- either fail return (signTx btc ctx tx [sigi] [tweaked])
      byInternal `shouldBe` byOutput
      map length byInternal.witness `shouldBe` [1]
      map (B.length . head) byInternal.witness `shouldBe` [64]
      verifyStdTx btc ctx byInternal [(so, 100000, op)] `shouldBe` True
      -- A signature with a hash type is 65 bytes and verifies as well
      withType <- either fail return (signTx btc ctx tx [sigi {sighash = setAnyoneCanPay sigHashAll}] [k.key])
      map (B.length . head) withType.witness `shouldBe` [65]
      verifyStdTx btc ctx withType [(so, 100000, op)] `shouldBe` True
      -- Another key does not sign
      (other, _) <- generate (arbitraryKeyPair ctx)
      fmap (.witness) (signTx btc ctx tx [sigi] [other.key]) `shouldBe` Right []

    it "needs the output every input spends, and refuses signInput" $ do
      (k, p) <- generate (arbitraryKeyPair ctx)
      let so = taprootScriptOutput ctx (TaprootOutput p.point Nothing)
          other = OutPoint (fromJust (hexToTxHash genesisTxId)) 1
          tx = buildTx ctx [op, other] [(so, 90000)]
          sigi = SigInput so 100000 op sigHashDefault Nothing
      signTx btc ctx tx [sigi] [k.key] `shouldBe` Left "signTx: a Taproot signature needs the output every input spends"
      signInput btc ctx tx 0 sigi k `shouldBe` Left "signInput: a Taproot input is signed with signTaprootInput"
      signTaprootInput ctx tx [TxOut 100000 (marshal ctx so)] 0 sigHashDefault k.key `shouldBe` Left "taprootSigHash: one spent output per input is required"
      signTaprootInput ctx tx [TxOut 100000 (marshal ctx so), TxOut 1 ""] 0 (setForkIdFlag sigHashAll) k.key `shouldBe` Left "taprootSigHash: invalid hash type 65"

{- SegWit helpers -}

segwitSpec :: Ctx -> Spec
segwitSpec ctx =
  describe "SegWit witness helpers" $ do
    (k, p) <- runIO (generate (arbitraryKeyPair ctx))
    let digest = sha256 ("message" :: ByteString)
        sig = TxSignature (signHash ctx k.key digest) sigHashAll
        sigBytes = encodeTxSig btc ctx sig
        keyBytes = marshal ctx p
        h = fromJust (addressHash160 (pubKeyAddr ctx p))
        multisig = PayMulSig [p] 1
        multisigScript = either error id (encodeOutput ctx multisig)
        wsh = toP2WSH multisigScript
    it "isSegwit is true for the version 0 programs only" $ do
      isSegwit (PayWitnessPKHash h) `shouldBe` True
      isSegwit wsh `shouldBe` True
      isSegwit (PayPKHash h) `shouldBe` False
      isSegwit (PayWitness 1 (B.replicate 32 0)) `shouldBe` False

    it "a simple input stacks its signatures, keys and the empty item of multisig" $ do
      simpleInputStack btc ctx (SpendPK sig) `shouldBe` [sigBytes]
      simpleInputStack btc ctx (SpendPKHash sig p) `shouldBe` [sigBytes, keyBytes]
      simpleInputStack btc ctx (SpendMulSig [sig, TxSignatureEmpty]) `shouldBe` ["", sigBytes, ""]

    it "a witness program encodes to its stack, with the script last for P2WSH" $ do
      toWitnessStack btc ctx (P2WPKH (WitnessProgramPKH sig p)) `shouldBe` [sigBytes, keyBytes]
      toWitnessStack btc ctx (P2WSH (WitnessProgramSH ["", sigBytes] multisigScript)) `shouldBe` ["", sigBytes, runPutS (serialize multisigScript)]
      toWitnessStack btc ctx EmptyWitnessProgram `shouldBe` []

    it "a witness is read against the output it spends" $ do
      viewWitnessProgram btc ctx (PayWitnessPKHash h) [sigBytes, keyBytes] `shouldBe` Right (P2WPKH (WitnessProgramPKH sig p))
      viewWitnessProgram btc ctx (PayWitnessPKHash h) [sigBytes] `shouldBe` Left "viewWitnessProgram: Invalid witness program"
      viewWitnessProgram btc ctx wsh ["", sigBytes, runPutS (serialize multisigScript)] `shouldBe` Right (P2WSH (WitnessProgramSH ["", sigBytes] multisigScript))
      viewWitnessProgram btc ctx (PayPKHash h) [] `shouldBe` Right EmptyWitnessProgram
      viewWitnessProgram btc ctx (PayPKHash h) [sigBytes] `shouldBe` Left "viewWitnessProgram: Invalid witness program"

    it "a witness program decodes to the input it stands for" $ do
      decodeWitnessInput btc ctx (P2WPKH (WitnessProgramPKH sig p)) `shouldBe` Right (Nothing, SpendPKHash sig p)
      decodeWitnessInput btc ctx (P2WSH (WitnessProgramSH ["", sigBytes] multisigScript)) `shouldBe` Right (Just multisig, SpendMulSig [sig])
      decodeWitnessInput btc ctx (P2WSH (WitnessProgramSH [sigBytes] multisigScript)) `shouldBe` Left "decodeWitnessInput: Non-standard script output"
      decodeWitnessInput btc ctx EmptyWitnessProgram `shouldBe` Left "decodeWitnessInput: Empty witness program"

    it "a witness program is computed from a standard input, native or nested" $ do
      calcWitnessProgram btc ctx (PayWitnessPKHash h) (RegularInput (SpendPKHash sig p)) `shouldBe` Right (P2WPKH (WitnessProgramPKH sig p))
      calcWitnessProgram btc ctx (toP2SH (either error id (encodeOutput ctx (PayWitnessPKHash h)))) (RegularInput (SpendPKHash sig p)) `shouldBe` Right (P2WPKH (WitnessProgramPKH sig p))
      calcWitnessProgram btc ctx wsh (ScriptHashInput (SpendMulSig [sig]) multisig) `shouldBe` Right (P2WSH (WitnessProgramSH ["", sigBytes] multisigScript))
      calcWitnessProgram btc ctx (PayPKHash h) (RegularInput (SpendPKHash sig p)) `shouldBe` Left "calcWitnessProgram: Invalid segwit SigInput"

{- Genesis -}

genesisSpec :: Spec
genesisSpec =
  describe "Genesis coinbases" $ do
    it "genesisCoinbase builds a version 1 transaction with one null input and one output of 50 BTC" $ do
      let tx = genesisCoinbase "in" "out"
      tx `shouldBe` Tx 1 [TxIn nullOutPoint "in" 0xffffffff] [TxOut 5000000000 "out"] [] 0
      nullOutPoint `shouldBe` OutPoint "0000000000000000000000000000000000000000000000000000000000000000" 0xffffffff
    it "the mainnet coinbase has the id of the genesis block's only transaction" $
      txHashToHex (txHash mainnetGenesisTx) `shouldBe` "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    it "the testnet4 coinbase has its own id" $
      txHashToHex (txHash testnet4GenesisTx) `shouldBe` "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"
