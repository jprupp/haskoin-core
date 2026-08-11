{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Haskoin.TransactionSpec (spec) where

import Control.Monad (unless)
import Data.ByteString qualified as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Default (def)
import Data.Either
import Data.Maybe
import Data.String (fromString)
import Data.String.Conversions
import Data.Text (Text)
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
    prop "guess transaction size" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitraryAddrOnlyTxFull net ctx) (testGuessSize net ctx)
    prop "choose coins" $
      forAll arbitraryNetwork $ \net ->
        forAll (listOf (arbitrarySatoshi net)) testChooseCoins
    prop "choose multisig coins" $
      forAll arbitraryNetwork $ \net ->
        forAll arbitraryMSParam $
          forAll (listOf (arbitrarySatoshi net)) . testChooseMSCoins
    prop "sign and validate transaction" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitrarySigningData net ctx) (testDetSignTx net ctx)
    prop "sign and validate (nested) transaction" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitrarySigningData net ctx) (testDetSignNestedTx net ctx)
    prop "merge partially signed transactions" $
      forAll arbitraryNetwork $ \net ->
        property $ forAll (arbitraryPartialTxs net ctx) (testMergeTx net ctx)
  describe "Transaction vectors" $ do
    it "compute txid from tx" $ mapM_ testTxidVector txidVectors
    it "build pkhash transaction (generated from bitcoind)" $
      mapM_ (testPKHashVector ctx) pkHashVectors

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
testBuildAddrTx net ctx a (TestCoin v)
  | isPubKeyAddress a = (PayPKHash <$> addressHash160 a) `shouldBe` Just out
  | isScriptAddress a = (PayScriptHash <$> addressHash160 a) `shouldBe` Just out
  | otherwise = discard
  where
    out = either error id $ do
      tx <- buildAddrTx net ctx [] [(fromJust (addrToText net a), v)]
      unmarshal ctx (head tx.outputs).script

-- We compute an upper bound but it should be close enough to the real size
-- We give 2 bytes of slack on every signature (1 on r and 1 on s)
testGuessSize :: Network -> Ctx -> Tx -> Bool
testGuessSize net ctx tx =
  guess >= len && guess <= len + 2 * delta
  where
    delta = pki + sum (map fst msi)
    guess = guessTxSize pki msi pkout msout
    len = B.length $ runPutS $ serialize tx
    ins = map f tx.inputs
    f i = either error id $ unmarshal (net, ctx) i.script
    pki = length $ filter isSpendPKHash ins
    msi = concatMap shData ins
    shData (ScriptHashInput _ (PayMulSig keys r)) = [(r, length keys)]
    shData _ = []
    out = map (either error id . unmarshal ctx . (.script)) tx.outputs
    pkout = length $ filter isPayPKHash out
    msout = length $ filter isPayScriptHash out

testChooseCoins :: [TestCoin] -> Word64 -> Word64 -> Int -> Property
testChooseCoins coins target byteFee nOut =
  nOut >= 0 ==>
    case chooseCoins target byteFee nOut True coins of
      Right (chosen, change) ->
        let outSum = sum $ map coinValue chosen
            fee = guessTxFee byteFee nOut (length chosen)
         in outSum == target + change + fee
      Left _ ->
        let fee = guessTxFee byteFee nOut (length coins)
         in target == 0 || s < target + fee
  where
    s = sum $ map coinValue coins

testChooseMSCoins ::
  (Int, Int) ->
  [TestCoin] ->
  Word64 ->
  Word64 ->
  Int ->
  Property
testChooseMSCoins (m, n) coins target byteFee nOut =
  nOut >= 0 ==>
    case chooseMSCoins target byteFee (m, n) nOut True coins of
      Right (chosen, change) ->
        let outSum = sum $ map coinValue chosen
            fee = guessMSTxFee byteFee (m, n) nOut (length chosen)
         in outSum == target + change + fee
      Left _ ->
        let fee = guessMSTxFee byteFee (m, n) nOut (length coins)
         in target == 0 || s < target + fee
  where
    s = sum $ map coinValue coins

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
      | isSegwit s = (toP2SH (encodeOutput ctx s), v, o)
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
