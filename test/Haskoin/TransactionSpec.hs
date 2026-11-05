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
import Data.Aeson (decode, eitherDecode, withObject, (.:))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Default (def)
import Data.Either
import Data.List (find, inits, isInfixOf, isPrefixOf)
import Data.Maybe
import Data.String (fromString)
import Data.String.Conversions
import Data.Text (Text)
import Data.Text qualified as T
import Data.Word (Word32, Word64, Word8)
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
  buildSpec ctx
  verificationSpec ctx
  coreSignedSpec ctx
  consensusSpec ctx
  thiefSpec ctx
  signerSpec ctx
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
-- change, and weighs no more than nodes relay. The sums are made as
-- unbounded integers, so that a sum that wraps around cannot pass. When
-- there is no selection, no prefix of the coins both fits that weight and
-- covers the target and its own fee, since the coins are taken in order.
testChooseCoins :: [TestCoin] -> [OutputKind] -> Word64 -> Word64 -> Property
testChooseCoins coins outs target byteFee =
  case chooseCoins target byteFee outs True coins of
    Right (chosen, change) ->
      (value chosen, weight chosen <= maxStandardTxWeight)
        === (toInteger target + toInteger change + fee chosen, True)
    Left _ ->
      property $ target == 0 || not (any covers (takeWhile ((<= maxStandardTxWeight) . weight) (drop 1 (inits coins))))
  where
    value = sum . map (toInteger . coinValue)
    weight cs = guessTxWeight (map coinInputKind cs) outs
    -- The fee rate times the virtual size, which is the weight over four, rounded up
    fee cs = toInteger byteFee * toInteger ((weight cs + 3) `div` 4)
    covers prefix = value prefix >= toInteger target + fee prefix

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
      | isSegwit s = (either error id (toP2SH =<< encodeOutput ctx s), v, o)
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

-- | The key pair whose secret key is the number given, in compressed form.
-- Tests use these fixed keys, so that a failure can be run again.
fixedKey :: Ctx -> Word8 -> (PrivateKey, PublicKey)
fixedKey ctx n = (k, derivePublicKey ctx k)
  where
    k = wrapSecKey True (fromJust (secKey (B.replicate 31 0 <> B.singleton n)))

-- | The same key pair with the public key in uncompressed form
fixedKeyU :: Ctx -> Word8 -> (PrivateKey, PublicKey)
fixedKeyU ctx n = (k, derivePublicKey ctx k)
  where
    k = wrapSecKey False (fst (fixedKey ctx n)).key

-- | HASH160 of a public key as it is serialized
keyHash :: Ctx -> PublicKey -> Hash160
keyHash ctx = addressHash . marshal ctx

-- | A coin to spend: an output of the genesis coinbase transaction id
coinAt :: Word32 -> OutPoint
coinAt = OutPoint (fromJust (hexToTxHash genesisTxId))

-- | The transaction with the script of one input replaced
withInputScript :: Tx -> Int -> ByteString -> Tx
withInputScript tx i script =
  Tx tx.version (zipWith replace [0 :: Int ..] tx.inputs) tx.outputs tx.witness tx.locktime
  where
    replace j input
      | j == i = TxIn input.outpoint script input.sequence
      | otherwise = input

-- | The transaction with its witness replaced
withWitness :: Tx -> WitnessData -> Tx
withWitness tx stacks = Tx tx.version tx.inputs tx.outputs stacks tx.locktime

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

    it "decodeTx reads a transaction on its own, and refuses bytes after it" $ do
      let legacy = "0100000001db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654a1eb29eb0e00000000ffffffff01804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac00000000"
      fmap txHash (decodeTx (hexBytes legacy)) `shouldBe` fmap txHash (parseTx legacy)
      fmap (length . (.inputs)) (decodeTx (hexBytes legacy)) `shouldBe` Right 1
      decodeTx (hexBytes (legacy <> "00")) `shouldSatisfy` either ("Trailing bytes after transaction" `isInfixOf`) (const False)
      decodeTx (hexBytes bip143SignedTx <> "\x00") `shouldSatisfy` either ("Trailing bytes after transaction" `isInfixOf`) (const False)
      fmap txWeight (decodeTx (hexBytes bip143SignedTx)) `shouldBe` Right 1042

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
      -- A second stack has no input to go with, so its bytes are not written
      fmap (.witness) (decodeTx (runPutS (serialize tx {witness = [["ab"], ["cd"]]}))) `shouldBe` Right [["ab"]]

    -- Only an input has a witness. A stack beyond the inputs is not part of
    -- the transaction, so it must not turn the witness format on.
    it "a witness item in a stack beyond the inputs is not a witness" $ do
      let legacy = "0100000001db494559df26b5cf3b121f05af26e0568708f5bd9ccceb41656f1654a1eb29eb0e00000000ffffffff01804a5d05000000001976a91424aa604689cc582292b97668bedd91dd5bf9374c88ac00000000"
      tx <- either fail return (parseTx legacy)
      let beyond = withWitness tx [[], ["ab"]]
      hasWitness beyond `shouldBe` False
      encodeHex (runPutS (serialize beyond)) `shouldBe` legacy
      txWitnessHash beyond `shouldBe` txHash tx
      -- 85 bytes, four weight units each
      txWeight beyond `shouldBe` 340

    it "write an empty stack for an input that the witness list leaves out" $ do
      let tx = Tx 1 [TxIn (coinAt 0) "" 0xffffffff, TxIn (coinAt 1) "" 0xffffffff] [TxOut 1 "\x51"] [["ab"]] 0
          input n = "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" <> n <> "00" <> "ffffffff"
      -- version, marker and flag, two inputs, one output of 1 satoshi to
      -- OP_1, the stack of one item "ab", the empty stack, lock time
      encodeHex (runPutS (serialize tx))
        `shouldBe` "01000000" <> "0001" <> "02" <> input "00000000" <> input "01000000" <> "01" <> "0100000000000000" <> "0151" <> "0102" <> "6162" <> "00" <> "00000000"

    it "the JSON form of a transaction has one witness stack per input, or none" $ do
      let json stacks = cs ("{\"version\":1,\"inputs\":[{\"prevoutput\":{\"txid\":\"" <> genesisTxId <> "\",\"index\":0},\"inputscript\":\"\",\"sequence\":4294967295}],\"outputs\":[],\"witnessdata\":" <> stacks <> ",\"locktime\":0}")
      fmap (.witness) (decode (json "[]") :: Maybe Tx) `shouldBe` Just []
      fmap (.witness) (decode (json "[[\"6162\"]]") :: Maybe Tx) `shouldBe` Just [["ab"]]
      (decode (json "[[\"6162\"],[\"6364\"]]") :: Maybe Tx) `shouldBe` Nothing
      (decode "{\"version\":1,\"inputs\":[],\"outputs\":[],\"witnessdata\":[[\"6162\"]],\"locktime\":0}" :: Maybe Tx) `shouldBe` Nothing

    -- 253 is the first count that takes three bytes: fd, then 253 as two
    -- bytes. Each input without a script is 41 bytes, and the output of an
    -- empty script 9: 4 + 3 + 253 × 41 + 1 + 9 + 4 = 10394 bytes.
    it "write and read a count of 253 inputs in three bytes" $ do
      let tx = Tx 1 [TxIn (coinAt i) "" 0xffffffff | i <- [0 .. 252]] [TxOut 1 ""] [] 0
          bytes = runPutS (serialize tx)
      B.length bytes `shouldBe` 10394
      encodeHex (B.take 3 (B.drop 4 bytes)) `shouldBe` "fdfd00"
      fmap (length . (.inputs)) (runGetS deserialize bytes :: Either String Tx) `shouldBe` Right 253

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
      -- the witness: count 1, the empty item 1, 17 signatures of 73 (1241), the 685-byte script after its 3-byte length (688)
      inputWeight (InputWitnessMulSig 17 20) `shouldBe` (41, 1931)
      inputWeight (InputNestedWitnessMulSig 17 20) `shouldBe` (76, 1931)

    -- A redeem script is at most 520 bytes, so 15 compressed keys are the
    -- most of a pay-to-script-hash multisig
    it "counts the largest pay-to-script-hash multisig, 15 of 15" $
      -- OP_15, 15 keys of 34 (510), OP_15, OP_CHECKMULTISIG: a 513-byte script.
      -- OP_0, 15 signatures of 73 (1095), the script pushed with OP_PUSHDATA2 (516): 1612 bytes after a 3-byte length, and 40
      inputWeight (InputMulSig 15 15) `shouldBe` (1655, 0)

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
      guessTxFee 10 [InputPKHash] [OutputPKHash] `shouldBe` Right 1920
      guessTxFee 10 [InputWitnessPKHash] [OutputWitnessPKHash] `shouldBe` Right 1100
      guessTxFee 0 [InputPKHash] [OutputPKHash] `shouldBe` Right 0

    -- 192 bytes at 2^58 satoshi per byte is three times 2^64
    it "refuses a fee that does not fit in 64 bits" $ do
      guessTxFee 288230376151711744 [InputPKHash] [OutputPKHash] `shouldBe` Left "guessTxFee: The fee does not fit in 64 bits"
      -- 192 × 96076792050570581 = 2^64 - 64, the largest multiple of 192 below 2^64
      guessTxFee 96076792050570581 [InputPKHash] [OutputPKHash] `shouldBe` Right 18446744073709551552
      guessTxFee 96076792050570582 [InputPKHash] [OutputPKHash] `shouldBe` Left "guessTxFee: The fee does not fit in 64 bits"

    it "refuses a kind of input or output that cannot exist" $ do
      -- 16 compressed keys make a redeem script of 547 bytes
      guessTxFee 1 [InputMulSig 16 16] [OutputPKHash] `shouldBe` Left "guessTxFee: The input kind InputMulSig 16 16 is not valid: m of n needs 1 <= m <= n <= 15"
      guessTxFee 1 [InputMulSig 3 2] [OutputPKHash] `shouldBe` Left "guessTxFee: The input kind InputMulSig 3 2 is not valid: m of n needs 1 <= m <= n <= 15"
      guessTxFee 1 [InputWitnessMulSig 0 2] [OutputPKHash] `shouldBe` Left "guessTxFee: The input kind InputWitnessMulSig 0 2 is not valid: m of n needs 1 <= m <= n <= 20"
      guessTxFee 1 [InputNestedWitnessMulSig 1 21] [OutputPKHash] `shouldBe` Left "guessTxFee: The input kind InputNestedWitnessMulSig 1 21 is not valid: m of n needs 1 <= m <= n <= 20"
      guessTxFee 1 [InputPKHash] [OutputScript (-1)] `shouldBe` Left "guessTxFee: The output kind OutputScript (-1) is not valid: a script has from 0 to 10000 bytes"
      chooseCoins 1000 1 [OutputPKHash] False [TestCoin 100000 (InputMulSig (-30) 2)]
        `shouldBe` Left "chooseCoins: The input kind InputMulSig (-30) 2 is not valid: m of n needs 1 <= m <= n <= 15"

    -- GetDustThreshold of Bitcoin Core at 3 satoshi per byte: the output
    -- and the smallest input that spends it, 148 bytes without a witness
    -- and 67 with one
    it "gives the dust threshold of each kind of output" $ do
      -- (34 + 148) × 3
      dustThreshold OutputPKHash `shouldBe` 546
      -- (32 + 148) × 3
      dustThreshold OutputScriptHash `shouldBe` 540
      -- (31 + 67) × 3
      dustThreshold OutputWitnessPKHash `shouldBe` 294
      -- (43 + 67) × 3
      dustThreshold OutputWitnessScriptHash `shouldBe` 330
      dustThreshold OutputTaproot `shouldBe` 330
      -- a bare 1-of-1 multisig: (46 + 148) × 3
      dustThreshold (OutputScript 37) `shouldBe` 582

    it "is at least the virtual size of a signed P2WPKH spend, and of a Taproot key path spend" $ do
      let (k, p) = fixedKey ctx 1
          h = fromJust (addressHash160 (pubKeyAddr ctx p))
          op = OutPoint (fromJust (hexToTxHash genesisTxId)) 0
          witnessTx = buildTx ctx [op] [(PayWitnessPKHash h, 90000)]
          taprootOutput = taprootScriptOutput ctx (TaprootOutput p.point Nothing)
          taprootTx = buildTx ctx [op] [(taprootOutput, 90000)]
      signedWitness <- either fail return (signTx btc ctx witnessTx [SigInput (PayWitnessPKHash h) 100000 op sigHashAll Nothing] [k.key])
      signedTaproot <- either fail return (signTx btc ctx taprootTx [SigInput taprootOutput 100000 op sigHashDefault Nothing] [k.key])
      -- 82 bytes without witness. The witness: marker and flag 2, count 1,
      -- the signature with its hash type after its length, 72 or 73, and
      -- the key after its length 34: 437 or 438 units, 110 virtual bytes
      -- either way
      txVirtualSize signedWitness `shouldBe` 110
      -- 94 bytes without witness. The witness: 2, count 1, a 64-byte
      -- signature after its length 65: 444 units, one less than the guess
      txVirtualSize signedTaproot `shouldBe` 111

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

    -- One P2PKH input and one P2PKH output are 192 bytes: 1920 satoshi
    it "selects a coin that covers the target and the fee exactly, with no change" $
      chooseCoins 98080 10 [OutputPKHash] False [TestCoin 100000 InputPKHash] `shouldBe` Right ([TestCoin 100000 InputPKHash], 0)

    -- With no fee, each coin alone covers the target, and the second is no
    -- smaller than the first
    it "keeps the first solution when a later one is not smaller" $
      chooseCoins 60000 0 [OutputPKHash] True [TestCoin 70000 InputPKHash, TestCoin 70000 InputWitnessPKHash]
        `shouldBe` Right ([TestCoin 70000 InputPKHash], 10000)

    -- 2^64 - 101 plus the fee of 192 is above 2^64, and must not wrap
    -- around to 91
    it "refuses a target that the coins cannot cover, even when target and fee add up to more than 2^64" $ do
      chooseCoins 18446744073709551515 1 [OutputPKHash] False [TestCoin 1000 InputPKHash] `shouldBe` Left "chooseCoins: No solution found"
      -- 192 bytes at 2^58 satoshi per byte is three times 2^64
      chooseCoins 60000 288230376151711744 [OutputPKHash] False [TestCoin 100000 InputPKHash] `shouldBe` Left "chooseCoins: No solution found"

    -- 1 + (2^64 - 1) = 2^64 covers 5 with 2^64 - 5 of change
    it "adds coin values without wrapping around" $
      chooseCoins 5 0 [OutputPKHash] False [TestCoin 1 InputPKHash, TestCoin 18446744073709551615 InputPKHash]
        `shouldBe` Right ([TestCoin 18446744073709551615 InputPKHash, TestCoin 1 InputPKHash], 18446744073709551611)

    -- k P2WPKH inputs and one P2WPKH output, for k from 253: 4 × (8 + 3 +
    -- 41 k + 1 + 31) + 2 + 108 k = 174 + 272 k weight units. 1469 inputs
    -- are 399742 units, 99936 virtual bytes, and 1470 are 400014, above the
    -- 400000 that nodes relay.
    it "selects up to the standard transaction weight and no further" $ do
      let coins = replicate 2000 (TestCoin 10000 InputWitnessPKHash)
      -- 1469 coins hold 14690000, less 99936 of fee at 1 satoshi per byte
      fmap (\(chosen, change) -> (length chosen, change)) (chooseCoins 14590064 1 [OutputWitnessPKHash] False coins) `shouldBe` Right (1469, 0)
      chooseCoins 14590065 1 [OutputWitnessPKHash] False coins `shouldBe` Left "chooseCoins: The selection exceeds the standard transaction weight of 400000"

    it "refuses a target of zero and reports when the coins do not suffice" $ do
      chooseCoins 0 10 [OutputPKHash] False [TestCoin 100000 InputPKHash] `shouldBe` Left "chooseCoins: Target must be > 0"
      chooseCoins 100000 10 [OutputPKHash] False [TestCoin 100000 InputPKHash] `shouldBe` Left "chooseCoins: No solution found"
      chooseCoins 1 10 [OutputPKHash] False ([] :: [TestCoin]) `shouldBe` Left "chooseCoins: No solution found"

{- Building -}

buildSpec :: Ctx -> Spec
buildSpec ctx =
  describe "Building a transaction to addresses" $ do
    let address = "14LsRquZfURNFrzpcLVGdaHTfAPjjwiSPb"
    -- AmountFromValue of Bitcoin Core refuses an amount out of range when
    -- createrawtransaction builds a transaction
    it "refuses an amount above the 21 million coins that can exist" $ do
      buildAddrTx btc ctx [coinAt 0] [(address, 2100000000000000)] `shouldSatisfy` isRight
      buildAddrTx btc ctx [coinAt 0] [(address, 2100000000000001)] `shouldBe` Left "buildAddrTx: An amount is above the maximum of 2100000000000000 satoshi"
      buildAddrTx btc ctx [coinAt 0] [(address, 18446744073709551615)] `shouldBe` Left "buildAddrTx: An amount is above the maximum of 2100000000000000 satoshi"

    it "refuses an address of another network" $
      buildAddrTx bch ctx [coinAt 0] [("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", 1000)] `shouldBe` Left "buildAddrTx: Invalid address bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

{- Verification -}

verificationSpec :: Ctx -> Spec
verificationSpec ctx =
  describe "Verification" $ do
    let coinOf = OutPoint (fromJust (hexToTxHash genesisTxId))
    it "accepts a correct P2PKH spend, and refuses a witness on its input, a wrong key, a wrong amount and a missing coin" $ do
      let (k, p) = fixedKey ctx 1
          (_, other) = fixedKey ctx 2
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
      let (k, p) = fixedKey ctx 1
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
      let (k, p) = fixedKey ctx 1
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
      let (k, p) = fixedKey ctx 1
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
      let (k, p) = fixedKey ctx 1
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
      let (k1, p1) = fixedKey ctx 1
          (k2, p2) = fixedKey ctx 2
      let ms = PayMulSig [p1, p2] 2
          so = PayScriptHash (fromJust (either (const Nothing) addressHash160 (payToScriptAddress ctx ms)))
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

    it "keeps the witness of an input that is not merged" $ do
      let (k1, p1) = fixedKey ctx 1
          (k2, p2) = fixedKey ctx 2
          (k3, p3) = fixedKey ctx 3
          ms = PayMulSig [p1, p2] 2
          so = either error id (toP2SH =<< encodeOutput ctx ms)
          wpkh = PayWitnessPKHash (keyHash ctx p3)
          tx = buildTx ctx [coinAt 0, coinAt 1] [(PayPKHash (keyHash ctx p1), 150000)]
          msSigi = SigInput so 100000 (coinAt 0) sigHashAll (Just ms)
          coins = [(so, 100000, coinAt 0), (wpkh, 100000, coinAt 1)]
      withSegwit <- either fail return (signTx btc ctx tx [SigInput wpkh 100000 (coinAt 1) sigHashAll Nothing] [k3.key])
      a <- either fail return (signTx btc ctx withSegwit [msSigi] [k1.key])
      b <- either fail return (signTx btc ctx withSegwit [msSigi] [k2.key])
      merged <- either fail return (mergeTxs btc ctx [a, b] [(so, 100000, coinAt 0)])
      merged.witness `shouldBe` withSegwit.witness
      verifyStdTx btc ctx merged coins `shouldBe` True

    it "mergeTxInput refuses an index that a transaction does not have" $ do
      let (_, p1) = fixedKey ctx 1
          ms = PayMulSig [p1] 1
          tx = buildTx ctx [coinAt 0] []
          short = buildTx ctx [] []
      mergeTxInput btc ctx [tx] tx ((ms, 100000), 3) `shouldBe` Left "mergeTxInput: input index out of range"
      mergeTxInput btc ctx [tx, short] tx ((ms, 100000), 0) `shouldBe` Left "mergeTxInput: input index out of range"

    it "refuses to merge inputs that carry different redeem scripts" $ do
      let (k1, p1) = fixedKey ctx 1
          (k2, p2) = fixedKey ctx 2
          (_, p3) = fixedKey ctx 3
          msA = PayMulSig [p1, p2] 2
          msB = PayMulSig [p1, p2, p3] 2
          hashOf ms = either error id (toP2SH =<< encodeOutput ctx ms)
          tx = buildTx ctx [coinAt 0] [(PayPKHash (keyHash ctx p1), 90000)]
      a <- either fail return (signTx btc ctx tx [SigInput (hashOf msA) 100000 (coinAt 0) sigHashAll (Just msA)] [k1.key])
      b <- either fail return (signTx btc ctx tx [SigInput (hashOf msB) 100000 (coinAt 0) sigHashAll (Just msB)] [k2.key])
      mergeTxs btc ctx [a, b] [(hashOf msA, 100000, coinAt 0)] `shouldBe` Left "Redeem scripts do not match"

    it "countMulSig counts the signatures that verify, in key order" $ do
      let (k1, p1) = fixedKey ctx 1
          (k2, p2) = fixedKey ctx 2
          (k3, p3) = fixedKey ctx 3
      let ms = PayMulSig [p1, p2, p3] 2
          msScript = either error id (encodeOutput ctx ms)
          op = OutPoint (fromJust (hexToTxHash genesisTxId)) 0
          tx = buildTx ctx [op] [(PayPKHash (fromJust (addressHash160 (pubKeyAddr ctx p1))), 90000)]
          sigOf k = TxSignature (signHash ctx k.key (either error id (txSigHash btc tx msScript 100000 0 sigHashAll))) sigHashAll
          count = countMulSig btc ctx tx msScript 100000 0 (map (.point) [p1, p2, p3])
      count [sigOf k1, sigOf k3] `shouldBe` 2
      count [sigOf k1, sigOf k2, sigOf k3] `shouldBe` 3
      -- The count is not a verdict: verifyStdInput refuses this input
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
      let (k, p) = fixedKey ctx 1
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
      let (k, p) = fixedKey ctx 1
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
      let (other, _) = fixedKey ctx 2
      fmap (.witness) (signTx btc ctx tx [sigi] [other.key]) `shouldBe` Right []

    it "needs the output every input spends, and refuses signInput" $ do
      let (k, p) = fixedKey ctx 1
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
    let (k, p) = fixedKey ctx 1
        digest = sha256 ("message" :: ByteString)
        sig = TxSignature (signHash ctx k.key digest) sigHashAll
        sigBytes = encodeTxSig btc ctx sig
        keyBytes = marshal ctx p
        h = fromJust (addressHash160 (pubKeyAddr ctx p))
        multisig = PayMulSig [p] 1
        multisigScript = either error id (encodeOutput ctx multisig)
        wsh = either error id (toP2WSH multisigScript)
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
      calcWitnessProgram btc ctx (either error id (toP2SH =<< encodeOutput ctx (PayWitnessPKHash h))) (RegularInput (SpendPKHash sig p)) `shouldBe` Right (P2WPKH (WitnessProgramPKH sig p))
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

{- Transactions signed by Bitcoin Core -}

-- | The vectors of data/core_signed_txs.json: the kind of coin, the signed
-- transaction in hex, and the output script in hex and the amount of the
-- coin that each of its two inputs spends
coreSignedVectors :: IO [(String, Text, Text, Word64)]
coreSignedVectors = readTestFileParser file "core_signed_txs.json"
  where
    file = withObject "file" $ \o -> o .: "vectors" >>= mapM vector
    vector = withObject "vector" $ \v -> (,,,) <$> v .: "kind" <*> v .: "tx" <*> v .: "script" <*> v .: "amount"

-- These signatures were made by Bitcoin Core 32.1 on regtest, not by the
-- library, so they check the verifier against an independent signer.
coreSignedSpec :: Ctx -> Spec
coreSignedSpec ctx =
  describe "Transactions signed by Bitcoin Core" $ do
    let verdict coinAmount (_, txHex, scriptHex, amount) = do
          tx <- decodeTx (hexBytes txHex)
          coin <- unmarshal ctx (hexBytes scriptHex)
          return (verifyStdTx btcRegTest ctx tx [(coin, coinAmount amount, i.outpoint) | i <- tx.inputs])
        kindOf (kind, _, _, _) = kind
        -- The kinds whose digest commits to the amount of the coin
        commitsToAmount v = any (`isPrefixOf` kindOf v) ["p2w", "p2sh-p2w", "p2tr"]

    -- 16 kinds of coin with the six hash types of ECDSA, and the default
    -- type as well for the Taproot key path: 16 × 6 + 1
    it "verifies the 97 spends of the file, of every kind of coin and hash type" $ do
      vectors <- coreSignedVectors
      length vectors `shouldBe` 97
      [kindOf v | v <- vectors, verdict id v /= Right True] `shouldBe` []

    -- 6 SegWit kinds with six hash types and the Taproot key path with seven
    it "refuses the 43 SegWit and Taproot spends of the file when the coin is given with one satoshi more" $ do
      vectors <- filter commitsToAmount <$> coreSignedVectors
      length vectors `shouldBe` 43
      [kindOf v | v <- vectors, verdict (+ 1) v /= Right False] `shouldBe` []

{- Inputs that no block can contain -}

-- A 2-of-3 multisig coin of the fixed keys 1, 2 and 3, in its three forms:
-- bare, pay-to-script-hash and pay-to-witness-script-hash. Each test gives
-- the signature items of the input, and gets the verdict for each form.
consensusSpec :: Ctx -> Spec
consensusSpec ctx =
  describe "Verification of inputs that no block can contain" $ do
    let (k1, p1) = fixedKey ctx 1
        (k2, p2) = fixedKey ctx 2
        (k3, p3) = fixedKey ctx 3
        (k4, _) = fixedKey ctx 4
        op = coinAt 0
        tx = buildTx ctx [op] [(PayPKHash (keyHash ctx p1), 90000)]
        ms = PayMulSig [p1, p2, p3] 2
        msScript = either error id (encodeOutput ctx ms)
        -- The digest that a signature of the bare and the pay-to-script-hash
        -- form signs, and the BIP 143 digest of the witness form
        legacyDigest = either error id (txSigHash btc tx msScript 100000 0 sigHashAll)
        witnessDigest = either error id (txSigHashForkId btc tx msScript 100000 0 sigHashAll)
        sig digest k = TxSignature (signHash ctx k.key digest) sigHashAll
        p2sh = either error id (toP2SH msScript)
        p2wsh = either error id (toP2WSH msScript)
        bare items = withInputScript tx 0 (marshal (btc, ctx) (RegularInput (SpendMulSig items)))
        hashed items = withInputScript tx 0 (marshal (btc, ctx) (ScriptHashInput (SpendMulSig items) ms))
        inWitness items = withWitness tx [simpleInputStack btc ctx (SpendMulSig items) <> [runPutS (serialize msScript)]]
        verdicts itemsOf =
          ( verifyStdInput btc ctx (bare (itemsOf legacyDigest)) [(ms, 100000, op)] 0,
            verifyStdInput btc ctx (hashed (itemsOf legacyDigest)) [(p2sh, 100000, op)] 0,
            verifyStdInput btc ctx (inWitness (itemsOf witnessDigest)) [(p2wsh, 100000, op)] 0
          )

    it "accepts a 2-of-3 multisig input with the signatures of two of its keys, in key order" $ do
      verdicts (\d -> [sig d k1, sig d k2]) `shouldBe` (True, True, True)
      verdicts (\d -> [sig d k1, sig d k3]) `shouldBe` (True, True, True)

    -- OP_CHECKMULTISIG takes as many signatures as the script requires. An
    -- item more becomes its dummy element, which must be empty.
    it "refuses a 2-of-3 multisig input with a third item after its two signatures" $ do
      verdicts (\d -> [sig d k1, sig d k2, sig d k4]) `shouldBe` (False, False, False)
      verdicts (\d -> [sig d k1, sig d k2, sig d k3]) `shouldBe` (False, False, False)

    -- The two items taken as signatures are the empty one and the last.
    -- The first signature is left in the place of the dummy element.
    it "refuses a 2-of-3 multisig input with an empty item among its signatures" $ do
      verdicts (\d -> [sig d k1, TxSignatureEmpty, sig d k3]) `shouldBe` (False, False, False)
      verdicts (\d -> [sig d k1, TxSignatureEmpty]) `shouldBe` (False, False, False)

    -- The empty item becomes the dummy element, and the one written for
    -- that stays on the stack. A witness must leave a clean stack (BIP
    -- 141). The legacy forms may be in a block, but nodes do not relay them
    -- (CLEANSTACK), and the verifier refuses what is not relayed.
    it "refuses a 2-of-3 multisig input with an empty item before its two signatures" $
      verdicts (\d -> [TxSignatureEmpty, sig d k1, sig d k2]) `shouldBe` (False, False, False)

    it "refuses a 2-of-3 multisig input with one signature, or with two out of key order" $ do
      verdicts (\d -> [sig d k1]) `shouldBe` (False, False, False)
      verdicts (\d -> [sig d k3, sig d k1]) `shouldBe` (False, False, False)

    -- BIP 141: the input script of a nested witness program "must be
    -- exactly a push of the BIP16 redeemScript"
    it "refuses a P2SH-P2WPKH input whose script pushes the program with OP_PUSHDATA1" $ do
      let h = keyHash ctx p1
          coin = either error id (toP2SH =<< encodeOutput ctx (PayWitnessPKHash h))
          sigi = SigInput (PayWitnessPKHash h) 100000 op sigHashAll Nothing
          program = B.pack [0x00, 0x14] <> runPutS (serialize h)
      signed <- either fail return (signNestedWitnessTx btc ctx tx [sigi] [k1.key])
      (head signed.inputs).script `shouldBe` B.singleton 0x16 <> program
      verifyStdInput btc ctx signed [(coin, 100000, op)] 0 `shouldBe` True
      verifyStdInput btc ctx (withInputScript signed 0 (B.pack [0x4c, 0x16] <> program)) [(coin, 100000, op)] 0 `shouldBe` False

    it "refuses a Taproot input that has an input script" $ do
      let so = taprootScriptOutput ctx (TaprootOutput p1.point Nothing)
      signed <- either fail return (signTx btc ctx tx [SigInput so 100000 op sigHashDefault Nothing] [k1.key])
      verifyStdInput btc ctx signed [(so, 100000, op)] 0 `shouldBe` True
      verifyStdInput btc ctx (withInputScript signed 0 "\x51") [(so, 100000, op)] 0 `shouldBe` False

    -- CheckTransaction of Bitcoin Core: bad-txns-inputs-duplicate
    it "refuses a transaction that lists the same outpoint twice" $ do
      let h = keyHash ctx p1
          twice = buildTx ctx [op, op] [(PayPKHash h, 90000)]
          sigi = SigInput (PayPKHash h) 100000 op sigHashAll Nothing
      signed <- either fail return (signTx btc ctx twice [sigi, sigi] [k1.key])
      map (B.null . (.script)) signed.inputs `shouldBe` [False, False]
      verifyStdTx btc ctx signed [(PayPKHash h, 100000, op)] `shouldBe` False
      verifyStdTx btc ctx signed [(PayPKHash h, 100000, op), (PayPKHash h, 100000, op)] `shouldBe` False

    it "refuses a transaction with no inputs and no outputs" $
      verifyStdTx btc ctx (Tx 1 [] [] [] 0) [] `shouldBe` False

    it "accepts outputs that spend exactly what the coins hold, and refuses one satoshi more" $ do
      let h = keyHash ctx p1
          sigi = SigInput (PayPKHash h) 100000 op sigHashAll Nothing
          exact = buildTx ctx [op] [(PayPKHash h, 100000)]
          over = buildTx ctx [op] [(PayPKHash h, 100001)]
      signedExact <- either fail return (signTx btc ctx exact [sigi] [k1.key])
      signedOver <- either fail return (signTx btc ctx over [sigi] [k1.key])
      verifyStdTx btc ctx signedExact [(PayPKHash h, 100000, op)] `shouldBe` True
      verifyStdTx btc ctx signedOver [(PayPKHash h, 100000, op)] `shouldBe` False

    -- Bitcoin Cash has no SegWit, so a witness program is no template there
    it "refuses a witness spend on a network without SegWit" $ do
      let h = keyHash ctx p1
          forkId = setForkIdFlag sigHashAll
          code = either error id (encodeOutput ctx (PayPKHash h))
          digest = either error id (txSigHashForkId bch tx code 100000 0 forkId)
          stack = [encodeTxSig bch ctx (TxSignature (signHash ctx k1.key digest) forkId), marshal ctx p1]
      verifyStdInput bch ctx (withWitness tx [stack]) [(PayWitnessPKHash h, 100000, op)] 0 `shouldBe` False

{- A coin spent with a key or a script that is not its own -}

-- In each test the thief signs the right digest of the coin with key 2, and
-- puts key 2, or a script of key 2, where the coin commits to key 1.
thiefSpec :: Ctx -> Spec
thiefSpec ctx =
  describe "Verification of a coin spent with a key or a script that is not its own" $ do
    let (k1, p1) = fixedKey ctx 1
        (k2, p2) = fixedKey ctx 2
        h1 = keyHash ctx p1
        h2 = keyHash ctx p2
        op = coinAt 0
        tx = buildTx ctx [op] [(PayPKHash h1, 90000)]
        script = either error id . encodeOutput ctx
        legacy code = either error id (txSigHash btc tx (script code) 100000 0 sigHashAll)
        bip143 code = either error id (txSigHashForkId btc tx (script code) 100000 0 sigHashAll)
        sig digest k = TxSignature (signHash ctx k.key digest) sigHashAll
        owner sigi = either error id (signTx btc ctx tx [sigi] [k1.key])
        ownerNested sigi = either error id (signNestedWitnessTx btc ctx tx [sigi] [k1.key])

    it "refuses a P2PKH coin spent with another key" $ do
      let coin = PayPKHash h1
          thief = withInputScript tx 0 (marshal (btc, ctx) (RegularInput (SpendPKHash (sig (legacy coin) k2) p2)))
      verifyStdInput btc ctx (owner (SigInput coin 100000 op sigHashAll Nothing)) [(coin, 100000, op)] 0 `shouldBe` True
      verifyStdInput btc ctx thief [(coin, 100000, op)] 0 `shouldBe` False

    it "refuses a P2SH coin spent with another redeem script" $ do
      let coin = either error id (toP2SH (script (PayPK p1)))
          thief = withInputScript tx 0 (marshal (btc, ctx) (ScriptHashInput (SpendPK (sig (legacy (PayPK p2)) k2)) (PayPK p2)))
      verifyStdInput btc ctx (owner (SigInput coin 100000 op sigHashAll (Just (PayPK p1)))) [(coin, 100000, op)] 0 `shouldBe` True
      verifyStdInput btc ctx thief [(coin, 100000, op)] 0 `shouldBe` False

    it "refuses a P2WPKH coin spent with another key" $ do
      let coin = PayWitnessPKHash h1
          thief = withWitness tx [[encodeTxSig btc ctx (sig (bip143 (PayPKHash h1)) k2), marshal ctx p2]]
      verifyStdInput btc ctx (owner (SigInput coin 100000 op sigHashAll Nothing)) [(coin, 100000, op)] 0 `shouldBe` True
      verifyStdInput btc ctx thief [(coin, 100000, op)] 0 `shouldBe` False

    it "refuses a P2WSH coin spent with another witness script" $ do
      let own = PayMulSig [p1] 1
          other = PayMulSig [p2] 1
          coin = either error id (toP2WSH (script own))
          thief = withWitness tx [["", encodeTxSig btc ctx (sig (bip143 other) k2), runPutS (serialize (script other))]]
      verifyStdInput btc ctx (owner (SigInput coin 100000 op sigHashAll (Just own))) [(coin, 100000, op)] 0 `shouldBe` True
      verifyStdInput btc ctx thief [(coin, 100000, op)] 0 `shouldBe` False

    it "refuses a P2SH-P2WPKH coin spent with the program of another key" $ do
      let coin = either error id (toP2SH (script (PayWitnessPKHash h1)))
          thief =
            withWitness
              (withInputScript tx 0 (marshal (btc, ctx) (NestedWitnessInput (PayWitnessPKHash h2))))
              [[encodeTxSig btc ctx (sig (bip143 (PayPKHash h2)) k2), marshal ctx p2]]
      verifyStdInput btc ctx (ownerNested (SigInput (PayWitnessPKHash h1) 100000 op sigHashAll Nothing)) [(coin, 100000, op)] 0 `shouldBe` True
      verifyStdInput btc ctx thief [(coin, 100000, op)] 0 `shouldBe` False

{- What the signer refuses -}

signerSpec :: Ctx -> Spec
signerSpec ctx =
  describe "What the signer refuses" $ do
    let (k1, p1) = fixedKey ctx 1
        (k2, _) = fixedKey ctx 2
        (k1u, p1u) = fixedKeyU ctx 1
        h1 = keyHash ctx p1
        op = coinAt 0
        -- Two outputs, so that SIGHASH_SINGLE has one at the index of the input
        tx = buildTx ctx [op] [(PayPKHash h1, 50000), (PayPKHash h1, 40000)]
        signWith net coin sh = signTx net ctx tx [SigInput coin 100000 op sh Nothing] [k1.key]

    it "signs the six hash types that a node accepts" $
      forM_ [0x01, 0x02, 0x03, 0x81, 0x82, 0x83] $ \sh -> do
        signWith btc (PayPKHash h1) sh `shouldSatisfy` isRight
        signWith btc (PayWitnessPKHash h1) sh `shouldSatisfy` isRight

    -- IsDefinedHashtypeSignature of Bitcoin Core: without the
    -- SIGHASH_ANYONECANPAY bit the byte is 1, 2 or 3
    it "refuses a hash type that no node accepts on Bitcoin" $
      forM_ [PayPKHash h1, PayWitnessPKHash h1] $ \coin -> do
        signWith btc coin 0x00 `shouldBe` Left "makeSignature: the hash type 0 is not one a node accepts"
        signWith btc coin 0x04 `shouldBe` Left "makeSignature: the hash type 4 is not one a node accepts"
        signWith btc coin 0x21 `shouldBe` Left "makeSignature: the hash type 33 is not one a node accepts"
        signWith btc coin 0x80 `shouldBe` Left "makeSignature: the hash type 128 is not one a node accepts"
        signWith btc coin 0xff `shouldBe` Left "makeSignature: the hash type 255 has the fork id flag, which this network does not use"
        signWith btc coin 0x41 `shouldBe` Left "makeSignature: the hash type 65 has the fork id flag, which this network does not use"

    -- A signature carries one byte of hash type, and the digest four
    it "refuses a hash type that does not fit in one byte" $ do
      signWith btc (PayPKHash h1) 0x101 `shouldBe` Left "makeSignature: the hash type 257 does not fit in the one byte of a signature"
      signWith btc (PayWitnessPKHash h1) 0x101 `shouldBe` Left "makeSignature: the hash type 257 does not fit in the one byte of a signature"
      signWith bch (PayPKHash h1) 0x101 `shouldBe` Left "makeSignature: the hash type 257 does not fit in the one byte of a signature"

    -- 0x20 is SIGHASH_UTXOS on Bitcoin Cash, whose digest the library does
    -- not compute
    it "refuses a hash type that it cannot sign on Bitcoin Cash, and adds the fork id flag to the others" $ do
      signWith bch (PayPKHash h1) 0x04 `shouldBe` Left "makeSignature: the hash type 4 is not one a node accepts"
      signWith bch (PayPKHash h1) 0x21 `shouldBe` Left "makeSignature: the hash type 33 is not one a node accepts"
      signed <- either fail return (signWith bch (PayPKHash h1) 0x01)
      -- The signature is the first push of the input script, and its last byte the hash type
      fmap (\si -> case si of RegularInput (SpendPKHash (TxSignature _ sh) _) -> Just sh; _ -> Nothing) (unmarshal (bch, ctx) (head signed.inputs).script)
        `shouldBe` Right (Just 0x41)

    it "refuses a pay-to-script-hash coin whose redeem script is over 520 bytes" $ do
      let rdm = PayMulSig [snd (fixedKey ctx n) | n <- [1 .. 16]] 1
          -- OP_1, 16 keys of 34 bytes with their push, OP_16, OP_CHECKMULTISIG: 547 bytes
          h = addressHash (runPutS (serialize (either error id (encodeOutput ctx rdm))))
      signTx btc ctx tx [SigInput (PayScriptHash h) 100000 op sigHashAll (Just rdm)] [k1.key]
        `shouldBe` Left "The redeem script is 547 bytes long, and a pay-to-script-hash redeem script can have at most 520"

    it "refuses a pay-to-witness-script-hash coin whose witness script is over 10000 bytes" $ do
      let rdm = DataCarrier [B.replicate 10000 0]
          -- OP_RETURN, OP_PUSHDATA2 with its two length bytes, 10000 bytes: 10004
          h = sha256 (runPutS (serialize (either error id (encodeOutput ctx rdm))))
      makeSignature btc ctx tx 0 (SigInput (PayWitnessScriptHash h) 100000 op sigHashAll (Just rdm)) k1
        `shouldBe` Left "The witness script is 10004 bytes long, and a pay-to-witness-script-hash witness script can have at most 10000"

    it "refuses a redeem script or a witness script that does not hash to the coin, and a coin without its script" $ do
      let other = "0000000000000000000000000000000000000000" :: Hash160
          other32 = "0000000000000000000000000000000000000000000000000000000000000000" :: Hash256
          rdm = PayPK p1
      makeSignature btc ctx tx 0 (SigInput (PayScriptHash other) 100000 op sigHashAll (Just rdm)) k1
        `shouldBe` Left "makeSignature: the redeem script does not hash to the coin"
      makeSignature btc ctx tx 0 (SigInput (PayWitnessScriptHash other32) 100000 op sigHashAll (Just rdm)) k1
        `shouldBe` Left "makeSignature: the witness script does not hash to the coin"
      makeSignature btc ctx tx 0 (SigInput (PayScriptHash other) 100000 op sigHashAll Nothing) k1
        `shouldBe` Left "makeSignature: a pay-to-script-hash coin needs its redeem script"
      makeSignature btc ctx tx 0 (SigInput (PayWitnessScriptHash other32) 100000 op sigHashAll Nothing) k1
        `shouldBe` Left "makeSignature: a pay-to-witness-script-hash coin needs its witness script"

    -- SCRIPT_VERIFY_WITNESS_PUBKEYTYPE of Bitcoin Core: no node relays a
    -- SegWit version 0 spend with an uncompressed key
    it "signTx refuses a SegWit coin of an uncompressed key, native, in a witness script or nested" $ do
      let hu = keyHash ctx p1u
          refusal = Left "sigKeys: a SegWit input is signed with a compressed key only, and this coin pays to an uncompressed key"
          wsh rdm = PayWitnessScriptHash (sha256 (runPutS (serialize (either error id (encodeOutput ctx rdm)))))
      signTx btc ctx tx [SigInput (PayWitnessPKHash hu) 100000 op sigHashAll Nothing] [k1.key] `shouldBe` refusal
      signNestedWitnessTx btc ctx tx [SigInput (PayWitnessPKHash hu) 100000 op sigHashAll Nothing] [k1.key] `shouldBe` refusal
      signTx btc ctx tx [SigInput (wsh (PayPK p1u)) 100000 op sigHashAll (Just (PayPK p1u))] [k1.key] `shouldBe` refusal
      signTx btc ctx tx [SigInput (wsh (PayMulSig [p1u] 1)) 100000 op sigHashAll (Just (PayMulSig [p1u] 1))] [k1.key] `shouldBe` refusal
      -- The same key signs a legacy coin in its uncompressed form
      signTx btc ctx tx [SigInput (PayPKHash hu) 100000 op sigHashAll Nothing] [k1.key] `shouldSatisfy` isRight

    -- A block accepts such a spend, so one who knows what it does can still
    -- make it, with the key in the form to use
    it "signInput signs a SegWit coin with the uncompressed key it is given" $ do
      let hu = keyHash ctx p1u
          sigi = SigInput (PayWitnessPKHash hu) 100000 op sigHashAll Nothing
      signed <- either fail return (signInput btc ctx tx 0 sigi k1u)
      map (map B.length) signed.witness `shouldSatisfy` (\w -> map (drop 1) w == [[65]])
      verifyStdInput btc ctx signed [(PayWitnessPKHash hu, 100000, op)] 0 `shouldBe` True

    it "refuses to sign a SegWit or a Taproot coin on a network without SegWit" $ do
      let so = taprootScriptOutput ctx (TaprootOutput p1.point Nothing)
      signWith bch (PayWitnessPKHash h1) sigHashAll `shouldBe` Left "makeSignature: this network has no SegWit"
      signTx bch ctx tx [SigInput so 100000 op sigHashDefault Nothing] [k1.key] `shouldBe` Left "signTx: this network has no Taproot"

    it "signInput refuses a key that is not a key of the coin" $ do
      signInput btc ctx tx 0 (SigInput (PayPKHash h1) 100000 op sigHashAll Nothing) k2 `shouldBe` Left "signInput: the key is not a key of the coin"
      signInput btc ctx tx 0 (SigInput (PayWitnessPKHash h1) 100000 op sigHashAll Nothing) k2 `shouldBe` Left "signInput: the key is not a key of the coin"
      signInput btc ctx tx 0 (SigInput (PayMulSig [p1] 1) 100000 op sigHashAll Nothing) k2 `shouldBe` Left "signInput: the key is not a key of the coin"
      signInput btc ctx tx 0 (SigInput (PayPKHash h1) 100000 op sigHashAll Nothing) k1 `shouldSatisfy` isRight

    it "signTaprootInput refuses a key that is not the key of the output, and an output that is not Taproot" $ do
      let so = taprootScriptOutput ctx (TaprootOutput p1.point Nothing)
          spent = [TxOut 100000 (marshal ctx so)]
          tweaked = fromJust (taprootOutputSecKey ctx k1.key Nothing)
      -- The internal key is not the key of the output: its tweak is
      signTaprootInput ctx tx spent 0 sigHashDefault k1.key `shouldBe` Left "signTaprootInput: the key is not the key of the output"
      signTaprootInput ctx tx spent 0 sigHashDefault tweaked `shouldSatisfy` isRight
      signTaprootInput ctx tx [TxOut 100000 (marshal ctx (PayWitnessPKHash h1))] 0 sigHashDefault tweaked
        `shouldBe` Left "signTaprootInput: the output spent is not a Taproot output"

    it "refuses to sign a SegWit input of a transaction whose witness list does not match its inputs" $ do
      let two = buildTx ctx [op, coinAt 1] [(PayPKHash h1, 90000)]
          sigi = SigInput (PayWitnessPKHash h1) 100000 (coinAt 1) sigHashAll Nothing
          ms = PayMulSig [p1] 1
          wsh = either error id (toP2WSH =<< encodeOutput ctx ms)
      signTx btc ctx (withWitness two [[]]) [sigi] [k1.key] `shouldBe` Left "Invalid number of witness stacks"
      signTx btc ctx (withWitness two [[]]) [SigInput wsh 100000 (coinAt 1) sigHashAll (Just ms)] [k1.key] `shouldBe` Left "Invalid number of witness stacks"
      signTx btc ctx two [sigi] [k1.key] `shouldSatisfy` isRight
