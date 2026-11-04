{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Taproot: the script trees, output keys and control blocks of the BIP
-- 341 vectors, key path spending with its signature digest, the witness of
-- a spend, and the BIP 86 addresses.
module Haskoin.Transaction.TaprootSpec (spec) where

import Control.Applicative ((<|>))
import Control.Monad (forM, forM_, zipWithM_, (<=<))
import Crypto.Hash (Digest, SHA256, digestFromByteString)
import Data.Aeson
import Data.Aeson.Types
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Bytes.Get (runGetS)
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (deserialize, serialize)
import Data.Either (isLeft)
import Data.Maybe (fromJust, isJust, isNothing)
import Data.Serialize qualified as S
import Data.Text (Text)
import Data.Word (Word32, Word64)
import Haskoin
import Haskoin.Util.Arbitrary
import Test.HUnit (assertBool, (@?=))
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck

spec :: Spec
spec = prepareContext $ \ctx -> do
  TestVector {testScriptPubKey, testKeyPath} <-
    runIO $
      readTestFileParser (testVectorParseJSON ctx) "bip341.json"
  describe "Script trees and output keys, from the scriptPubKey vectors of BIP 341" $ do
    it "calculate the leaf hashes and the Merkle root" $
      mapM_ testHashes testScriptPubKey
    it "build the output key" $
      mapM_ (testOutputKey ctx) testScriptPubKey
    it "build the script output" $
      mapM_ (testScriptOutput ctx) testScriptPubKey
    it "build the control blocks, which verify the script path" $
      mapM_ (testControlBlocks ctx) testScriptPubKey
    it "give the address" $
      mapM_ (testAddress ctx) testScriptPubKey
    it "list the leaves of a tree depth first and build the tree back from them" $
      mapM_ testTreeLeaves testScriptPubKey

  describe "The output key" $ do
    -- BIP 341 tweaks the x-only internal key, so the output does not
    -- depend on the parity of the y coordinate of the key given
    prop "is the same for a key and its negation" $
      forAll (arbitraryKeyPair ctx) $ \(_, p) ->
        let x = exportXOnlyPubKey ctx p.point
            negated = (.point) (either error id (unmarshal ctx (BS.cons (if keyParity ctx p.point == 0 then 0x03 else 0x02) x)) :: PublicKey)
         in taprootScriptOutput ctx (TaprootOutput negated Nothing) === taprootScriptOutput ctx (TaprootOutput p.point Nothing)

    prop "has the x coordinate of the public key of the output secret key" $
      forAll (arbitraryKeyPair ctx) $ \(k, p) ->
        let tweaked = fromJust (taprootOutputSecKey ctx k.key Nothing)
         in exportXOnlyPubKey ctx (derivePubKey ctx tweaked) === exportXOnlyPubKey ctx (taprootOutputKey ctx (TaprootOutput p.point Nothing))

    -- The test vectors of BIP 86: the keys at m/86'/0'/0'/0/0, 0/1 and
    -- 1/0 of the mnemonic "abandon ... about"
    forM_ bip86Vectors $ \(path, internalKey, outputKey, address) ->
      it ("of the BIP 86 key at " <> show path <> " is " <> show outputKey) $ do
        let root = fromJust (xPrvImport btc "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")
            secret = (derivePath ctx (path :: DerivPath) root).key
            output = TaprootOutput (derivePubKey ctx secret) Nothing
        encodeHex (exportXOnlyPubKey ctx (derivePubKey ctx secret)) `shouldBe` internalKey
        encodeHex (exportXOnlyPubKey ctx (taprootOutputKey ctx output)) `shouldBe` outputKey
        encodeHex (marshal ctx (taprootScriptOutput ctx output)) `shouldBe` "5120" <> outputKey
        (addrToText btc =<< outputAddress ctx (taprootScriptOutput ctx output)) `shouldBe` Just address
        -- The output secret key signs for the output key
        fmap (encodeHex . exportXOnlyPubKey ctx . derivePubKey ctx) (taprootOutputSecKey ctx secret Nothing) `shouldBe` Just outputKey

  describe "Key path spending, from the keyPathSpending vector of BIP 341" $ do
    forM_ testKeyPath.cases $ \c ->
      it ("input " <> show c.index <> ": the tweak, the digest and the signature, with hash type " <> show (fromIntegral c.hashType :: Word32)) $ do
        let output = TaprootOutput (derivePubKey ctx c.internalSecret) (MASTCommitment <$> c.merkleRoot)
            program = BS.drop 2 (testKeyPath.spent !! c.index).script
        encodeHex (exportXOnlyPubKey ctx (derivePubKey ctx c.internalSecret)) `shouldBe` c.internalPubKey
        exportXOnlyPubKey ctx (taprootOutputKey ctx output) `shouldBe` program
        let tweaked = fromJust (taprootOutputSecKey ctx c.internalSecret (MASTCommitment <$> c.merkleRoot))
        tweaked `shouldBe` fromJust (secKey (hexBytes c.tweakedSecret))
        digest <- expectRight (taprootSigHash testKeyPath.unsignedTx testKeyPath.spent c.index c.hashType Nothing Nothing)
        encodeHex (runPutS (serialize digest)) `shouldBe` c.sigHash
        -- The signature of the vector was made with 32 zero bytes of
        -- auxiliary randomness, as signSchnorr signs
        encodeHex (encodeTaprootSig (TaprootSignature (signSchnorr ctx tweaked (hashToMsg digest)) c.hashType)) `shouldBe` head c.witness

    it "the fully signed transaction of the vector verifies against the coins it spends" $
      verifyStdTx btc ctx testKeyPath.signedTx (coinsOf ctx testKeyPath) `shouldBe` True

    it "the fully signed transaction of the vector does not verify when a Taproot coin is given a wrong amount" $ do
      let coins = [(so, if i == (0 :: Int) then v + 1 else v, op) | (i, (so, v, op)) <- zip [0 ..] (coinsOf ctx testKeyPath)]
      verifyStdTx btc ctx testKeyPath.signedTx coins `shouldBe` False

    it "signTx signs the Taproot inputs of the vector by their key path with the internal keys, and the result verifies" $ do
      let tx = testKeyPath.unsignedTx
          coins = coinsOf ctx testKeyPath
          -- The internal keys of the Taproot inputs, with the key of the
          -- output as signTx finds it: the tweak of a key without a tree
          -- is the output only when the vector has no Merkle root
          noTree = [c | c <- testKeyPath.cases, isNothing c.merkleRoot]
          sigInputs = [SigInput so v op c.hashType Nothing | c <- noTree, let (so, v, op) = coins !! c.index]
          others = [SigInput so v op sigHashAll Nothing | (i, (so, v, op)) <- zip [0 ..] coins, i `notElem` map (.index) noTree]
      signed <- expectRight (signTx btc ctx tx (sigInputs <> others) (map (.internalSecret) noTree))
      forM_ noTree $ \c ->
        (signed.witness !! c.index) `shouldBe` [hexBytes (head c.witness)]

    it "taprootSigHash refuses an index out of range, a hash type a Taproot signature may not use, missing coins and SIGHASH_SINGLE without an output" $ do
      let tx = testKeyPath.unsignedTx
          spent = testKeyPath.spent
      taprootSigHash tx spent 9 sigHashDefault Nothing Nothing `shouldBe` Left "taprootSigHash: input index out of range"
      taprootSigHash tx spent (-1) sigHashDefault Nothing Nothing `shouldBe` Left "taprootSigHash: input index out of range"
      taprootSigHash tx (take 8 spent) 0 sigHashDefault Nothing Nothing `shouldBe` Left "taprootSigHash: one spent output per input is required"
      taprootSigHash tx spent 0 0x04 Nothing Nothing `shouldBe` Left "taprootSigHash: invalid hash type 4"
      taprootSigHash tx spent 0 (setForkIdFlag sigHashAll) Nothing Nothing `shouldBe` Left "taprootSigHash: invalid hash type 65"
      -- The transaction has two outputs: input 3 has none at its index
      taprootSigHash tx spent 3 sigHashSingle Nothing Nothing `shouldBe` Left "taprootSigHash: SIGHASH_SINGLE without an output at the input index"

    it "taprootSigHash commits to the annex and to the leaf of a script path spend" $ do
      let tx = testKeyPath.unsignedTx
          spent = testKeyPath.spent
          digest annex leaf = fmap (encodeHex . runPutS . serialize) (taprootSigHash tx spent 0 sigHashDefault annex leaf)
          leaf = leafHash tapscriptLeafVersion (Script [OP_1])
      digest Nothing Nothing `shouldNotBe` digest (Just "\x50") Nothing
      digest Nothing Nothing `shouldNotBe` digest Nothing (Just (leaf, 0xffffffff))
      digest Nothing (Just (leaf, 0xffffffff)) `shouldNotBe` digest Nothing (Just (leaf, 0))

  describe "Taproot signatures" $ do
    it "are 64 bytes with the default hash type, and 65 with another" $ do
      let sig = fromJust (schnorrSig (BS.replicate 64 7))
      encodeTaprootSig (TaprootSignature sig sigHashDefault) `shouldBe` BS.replicate 64 7
      encodeTaprootSig (TaprootSignature sig sigHashAll) `shouldBe` BS.replicate 64 7 <> "\x01"
      encodeTaprootSig (TaprootSignature sig (setAnyoneCanPay sigHashSingle)) `shouldBe` BS.replicate 64 7 <> "\x83"
      decodeTaprootSig (BS.replicate 64 7) `shouldBe` Right (TaprootSignature sig sigHashDefault)
      decodeTaprootSig (BS.replicate 64 7 <> "\x02") `shouldBe` Right (TaprootSignature sig sigHashNone)

    it "are refused with a hash type byte of zero, an undefined one, or another length" $ do
      decodeTaprootSig (BS.replicate 64 7 <> "\x00") `shouldBe` Left "decodeTaprootSig: invalid hash type byte 0"
      decodeTaprootSig (BS.replicate 64 7 <> "\x04") `shouldBe` Left "decodeTaprootSig: invalid hash type byte 4"
      decodeTaprootSig (BS.replicate 64 7 <> "\x41") `shouldBe` Left "decodeTaprootSig: invalid hash type byte 65"
      decodeTaprootSig (BS.replicate 63 7) `shouldBe` Left "decodeTaprootSig: a signature is 64 or 65 bytes, not 63"
      decodeTaprootSig (BS.replicate 66 7) `shouldBe` Left "decodeTaprootSig: a signature is 64 or 65 bytes, not 66"

    it "may use the default, ALL, NONE and SINGLE hash types, with ANYONECANPAY or not, and no other" $ do
      filter isTaprootSigHash [0 .. 0xff] `shouldBe` [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83]
      sigHashDefault `shouldBe` 0

  describe "Witnesses" $ do
    let (_, p) = bip86Key ctx
        -- The internal key as a control block gives it back: the point of even y
        internalKey = fromJust (importXOnlyPubKey ctx (exportXOnlyPubKey ctx p.point))
        leaf = Script [OP_2DROP, OP_1]
        tree = MASTBranch (MASTLeaf tapscriptLeafVersion leaf) (MASTLeaf tapscriptLeafVersion (Script [OP_1]))
        output = TaprootOutput internalKey (Just tree)
        outputKey = taprootOutputKey ctx output
        [(_, _, proof), _] = getMerkleProofs tree
        spend = ScriptPathData {annex = Nothing, stack = ["aa", "bbbb"], script = leaf, extIsOdd = odd (keyParity ctx outputKey), leafVersion = tapscriptLeafVersion, internalKey, control = proof}
        control = encodeControlBlock ctx (tapscriptLeafVersion + keyParity ctx outputKey) internalKey proof
        scriptBytes = runPutS (serialize leaf)

    it "a key path spend is one signature, with the annex after it when there is one" $ do
      encodeTaprootWitness ctx (KeyPathSpend "sig" Nothing) `shouldBe` ["sig"]
      encodeTaprootWitness ctx (KeyPathSpend "sig" (Just "\x50\&annex")) `shouldBe` ["sig", "\x50\&annex"]
      viewTaprootWitness ctx ["sig"] `shouldBe` Just (KeyPathSpend "sig" Nothing)
      viewTaprootWitness ctx ["sig", "\x50\&annex"] `shouldBe` Just (KeyPathSpend "sig" (Just "\x50\&annex"))
      -- One item is the signature even when it starts with the annex byte
      viewTaprootWitness ctx ["\x50sig"] `shouldBe` Just (KeyPathSpend "\x50sig" Nothing)
      viewTaprootWitness ctx [] `shouldBe` Nothing

    it "a script path spend is the stack, the script and the control block, in the order of BIP 341, then the annex" $ do
      encodeTaprootWitness ctx (ScriptPathSpend spend) `shouldBe` ["aa", "bbbb", scriptBytes, control]
      encodeTaprootWitness ctx (ScriptPathSpend spend {annex = Just "\x50"}) `shouldBe` ["aa", "bbbb", scriptBytes, control, "\x50"]
      viewTaprootWitness ctx ["aa", "bbbb", scriptBytes, control] `shouldBe` Just (ScriptPathSpend spend)
      viewTaprootWitness ctx ["aa", "bbbb", scriptBytes, control, "\x50"] `shouldBe` Just (ScriptPathSpend spend {annex = Just "\x50"})
      viewTaprootWitness ctx [scriptBytes, control] `shouldBe` Just (ScriptPathSpend spend {stack = []})
      -- The control block and the script in the other order are not a
      -- spend: the script is not a control block
      viewTaprootWitness ctx [control, scriptBytes] `shouldBe` Nothing

    it "a script path spend verifies against its output key, and not with the other parity or another proof" $ do
      verifyScriptPathData ctx outputKey spend `shouldBe` True
      verifyScriptPathData ctx outputKey spend {extIsOdd = not spend.extIsOdd} `shouldBe` False
      verifyScriptPathData ctx outputKey spend {control = []} `shouldBe` False
      verifyScriptPathData ctx outputKey spend {script = Script [OP_1]} `shouldBe` False
      verifyScriptPathData ctx (taprootOutputKey ctx (TaprootOutput internalKey Nothing)) spend `shouldBe` False

    it "a control block is 33 bytes plus 32 per node, with at most 128 nodes" $ do
      let node = BS.replicate 32 1
          base = BS.take 33 control
          short = BS.take 20 control
          tooLong = control <> "junk"
          deepest = base <> BS.concat (replicate 128 node)
          tooDeep = base <> BS.concat (replicate 129 node)
      maxControlBlockNodes `shouldBe` 128
      fmap (\(v, k, nodes) -> (v, exportXOnlyPubKey ctx k == exportXOnlyPubKey ctx internalKey, length nodes)) (decodeControlBlock ctx deepest) `shouldBe` Right (tapscriptLeafVersion + keyParity ctx outputKey, True, 128)
      decodeControlBlock ctx short `shouldBe` Left "decodeControlBlock: a control block is 33 bytes plus 32 per node, not 20"
      decodeControlBlock ctx tooLong `shouldBe` Left "decodeControlBlock: a control block is 33 bytes plus 32 per node, not 69"
      decodeControlBlock ctx tooDeep `shouldBe` Left "decodeControlBlock: more than 128 nodes"
      viewTaprootWitness ctx [scriptBytes, short] `shouldBe` Nothing
      viewTaprootWitness ctx [scriptBytes, tooLong] `shouldBe` Nothing
      viewTaprootWitness ctx [scriptBytes, tooDeep] `shouldBe` Nothing
      fmap (\case ScriptPathSpend d -> length d.control; _ -> 0) (viewTaprootWitness ctx [scriptBytes, deepest]) `shouldBe` Just 128

    it "a control block starts with the leaf version and the parity bit, then the x-only internal key" $
      encodeHex (encodeControlBlock ctx 0xc1 p.point [])
        `shouldBe` "c1cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"

    prop "encoding a witness and viewing it gives the witness back" $
      forAll ((,) <$> arbitraryBS1 <*> arbitraryMaybe arbitraryBS) $ \(sig, annexData) ->
        let annex = ("\x50" <>) <$> annexData
            spendWith a = ScriptPathSpend spend {annex = a}
         in (viewTaprootWitness ctx (encodeTaprootWitness ctx (KeyPathSpend sig annex)), viewTaprootWitness ctx (encodeTaprootWitness ctx (spendWith annex)))
              === (Just (KeyPathSpend sig annex), Just (spendWith annex))

  describe "Script trees as their leaves" $ do
    let a = MASTLeaf 0xc0 (Script [OP_1])
        b = MASTLeaf 0xc0 (Script [OP_2])
        c = MASTLeaf 0xc0 (Script [OP_3])
        leafOf d (MASTLeaf v s) = TapLeaf d v s
        leafOf _ _ = error "not a leaf"
    it "lists the leaves depth first with their depth" $ do
      tapTreeLeaves (MASTBranch (MASTBranch a b) c) `shouldBe` Just [leafOf 2 a, leafOf 2 b, leafOf 1 c]
      tapTreeLeaves a `shouldBe` Just [leafOf 0 a]
      tapTreeLeaves (MASTBranch a (MASTCommitment (mastCommitment b))) `shouldBe` Nothing
    it "builds the tree back from its leaves, with the same commitment" $ do
      let tree = MASTBranch (MASTBranch a b) c
      fmap mastCommitment (tapTreeFromLeaves [leafOf 2 a, leafOf 2 b, leafOf 1 c]) `shouldBe` Just (mastCommitment tree)
      fmap mastCommitment (tapTreeFromLeaves [leafOf 0 a]) `shouldBe` Just (mastCommitment a)
      fmap mastCommitment (tapTreeFromLeaves [leafOf 1 a, leafOf 2 b, leafOf 2 c]) `shouldBe` Just (mastCommitment (MASTBranch a (MASTBranch b c)))
    it "refuses leaves that do not make one tree" $ do
      tapTreeFromLeaves [] `shouldBe` Nothing
      tapTreeFromLeaves [leafOf 1 a] `shouldBe` Nothing
      tapTreeFromLeaves [leafOf 1 a, leafOf 1 b, leafOf 1 c] `shouldBe` Nothing
      tapTreeFromLeaves [leafOf 129 a] `shouldBe` Nothing

  describe "X-only keys" $ do
    it "serialize to the x coordinate, and read back as the point of even y" $ do
      let (_, p) = bip86Key ctx
          x = exportXOnlyPubKey ctx p.point
      marshal ctx (XOnlyPubKey p.point) `shouldBe` x
      fmap (keyParity ctx . (.point)) (unmarshal ctx x :: Either String XOnlyPubKey) `shouldBe` Right 0
      fmap (XOnlyPubKey p.point ==) (unmarshal ctx x) `shouldBe` Right True
      unmarshalJSON ctx (marshalJSON ctx (XOnlyPubKey p.point)) `shouldBe` Just (XOnlyPubKey p.point)
      (unmarshal ctx (BS.replicate 32 0xff) :: Either String XOnlyPubKey) `shouldSatisfy` isLeft
    it "the parity of a key is that of its y coordinate" $ do
      keyParity ctx (fromJust (importPubKey ctx (hexBytes "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))) `shouldBe` 0
      keyParity ctx (fromJust (importPubKey ctx (hexBytes "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))) `shouldBe` 1
    it "the Tapscript leaf version is 0xc0" $
      tapscriptLeafVersion `shouldBe` 0xc0

-- | The first key of the BIP 86 vectors, m/86'/0'/0'/0/0
bip86Key :: Ctx -> (PrivateKey, PublicKey)
bip86Key ctx = (PrivateKey secret True, PublicKey (derivePubKey ctx secret) True)
  where
    root = fromJust (xPrvImport btc "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")
    secret = (derivePath ctx ("m/86'/0'/0'/0/0" :: DerivPath) root).key

-- | The test vectors of BIP 86: path, internal key, output key, address
bip86Vectors :: [(DerivPath, Text, Text, Text)]
bip86Vectors =
  [ ("m/86'/0'/0'/0/0", "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115", "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
    ("m/86'/0'/0'/0/1", "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145", "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb", "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"),
    ("m/86'/0'/0'/1/0", "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef", "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc", "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7")
  ]

hexBytes :: Text -> ByteString
hexBytes = fromJust . decodeHex

expectRight :: Either String a -> IO a
expectRight = either fail return

coinsOf :: Ctx -> KeyPathVector -> [(ScriptOutput, Word64, OutPoint)]
coinsOf ctx v =
  [ (either error id (unmarshal ctx coin.script), coin.value, input.outpoint)
  | (input, coin) <- zip v.unsignedTx.inputs v.spent
  ]

testHashes :: TestScriptPubKey -> IO ()
testHashes testData =
  mapM_ checkMASTDetails $ ((.mast) . tspkGiven) testData
  where
    checkMASTDetails theMAST = do
      -- Leaf hashes
      (Just . getLeafHashes) theMAST @?= (spkiLeafHashes . tspkIntermediary) testData
      -- Merkle root
      (Just . BA.convert . mastCommitment) theMAST @?= (spkiMerkleRoot . tspkIntermediary) testData

    getLeafHashes = \case
      MASTBranch branchL branchR -> getLeafHashes branchL <> getLeafHashes branchR
      leaf@MASTLeaf {} -> [BA.convert $ mastCommitment leaf]
      MASTCommitment {} -> mempty -- The test vectors have complete trees

testOutputKey :: Ctx -> TestScriptPubKey -> IO ()
testOutputKey ctx testData = do
  XOnlyPubKey (taprootOutputKey ctx theOutput) @?= theOutputKey
  where
    theOutput = tspkGiven testData
    theOutputKey = XOnlyPubKey . spkiTweakedPubKey $ tspkIntermediary testData

testScriptOutput :: Ctx -> TestScriptPubKey -> IO ()
testScriptOutput ctx testData =
  taprootScriptOutput ctx (tspkGiven testData) @?= (spkeScriptPubKey . tspkExpected) testData

testControlBlocks :: Ctx -> TestScriptPubKey -> IO ()
testControlBlocks ctx testData = do
  mapM_ onExamples exampleControlBlocks
  mapM_ checkVerification scriptPathSpends
  where
    theOutput = tspkGiven testData
    theOutputKey = taprootOutputKey ctx theOutput
    exampleControlBlocks = spkeControlBlocks $ tspkExpected testData
    -- The control block is the last item of the witness: the stack is
    -- empty, so it comes after the script
    calculatedControlBlocks =
      last . encodeTaprootWitness ctx . ScriptPathSpend <$> scriptPathSpends
    scriptPathSpends =
      mkScriptPathSpend <$> maybe mempty getMerkleProofs theOutput.mast
    mkScriptPathSpend (leafVersion, script, proof) =
      ScriptPathData
        { annex = Nothing,
          stack = mempty,
          script,
          extIsOdd = odd $ keyParity ctx theOutputKey,
          leafVersion,
          internalKey = theOutput.internalKey,
          control = proof
        }
    onExamples = zipWithM_ (@?=) calculatedControlBlocks
    checkVerification = assertBool "Script verifies" . verifyScriptPathData ctx theOutputKey

testAddress :: Ctx -> TestScriptPubKey -> IO ()
testAddress ctx testData =
  computedAddress @?= (Just . spkeAddress . tspkExpected) testData
  where
    computedAddress =
      (addrToText btc <=< outputAddress ctx)
        . taprootScriptOutput ctx
        $ tspkGiven testData

testTreeLeaves :: TestScriptPubKey -> IO ()
testTreeLeaves testData =
  forM_ (tspkGiven testData).mast $ \theMAST -> do
    let leaves = tapTreeLeaves theMAST
    leaves `shouldSatisfy` isJust
    fmap mastCommitment (tapTreeFromLeaves =<< leaves) `shouldBe` Just (mastCommitment theMAST)

newtype SpkGiven = SpkGiven {unSpkGiven :: TaprootOutput}

spkGivenParseJSON :: Ctx -> Value -> Parser SpkGiven
spkGivenParseJSON ctx = withObject "SpkGiven" $ \obj -> do
  pxopk@XOnlyPubKey {} <- unmarshalValue ctx =<< obj .: "internalPubkey"
  tree <- traverse parseScriptTree =<< obj .:? "scriptTree"
  return $ SpkGiven $ TaprootOutput pxopk.point tree
  where
    parseScriptTree v =
      parseScriptLeaf v
        <|> parseScriptBranch v
        <|> fail "Unable to parse scriptTree"
    parseScriptLeaf = withObject "ScriptTree leaf" $ \obj ->
      MASTLeaf
        <$> obj .: "leafVersion"
        <*> (obj .: "script" >>= hexScript)
    parseScriptBranch v =
      parseJSON v >>= \case
        [v1, v2] -> MASTBranch <$> parseScriptTree v1 <*> parseScriptTree v2
        _ -> fail "ScriptTree branch"
    hexScript = either fail pure . runGetS deserialize <=< jsonHex

data SpkIntermediary = SpkIntermediary
  { spkiLeafHashes :: Maybe [ByteString],
    spkiMerkleRoot :: Maybe ByteString,
    spkiTweakedPubKey :: PubKey
  }

spkIntermediaryParseJSON :: Ctx -> Value -> Parser SpkIntermediary
spkIntermediaryParseJSON ctx = withObject "SpkIntermediary" $ \obj ->
  SpkIntermediary
    <$> (obj .:? "leafHashes" >>= (traverse . traverse) jsonHex)
    <*> (obj .: "merkleRoot" >>= traverse jsonHex)
    <*> fmap
      (\(XOnlyPubKey k) -> k)
      (unmarshalValue ctx =<< obj .: "tweakedPubkey")

data SpkExpected = SpkExpected
  { spkeScriptPubKey :: ScriptOutput,
    spkeControlBlocks :: Maybe [ByteString],
    spkeAddress :: Text
  }

spkExpectedParseJSON :: Ctx -> Value -> Parser SpkExpected
spkExpectedParseJSON ctx = withObject "SpkExpected" $ \obj ->
  SpkExpected
    <$> (unmarshalValue ctx =<< obj .: "scriptPubKey")
    <*> ((traverse . traverse) jsonHex =<< obj .:? "scriptPathControlBlocks")
    <*> obj .: "bip350Address"

data TestScriptPubKey = TestScriptPubKey
  { tspkGiven :: TaprootOutput,
    tspkIntermediary :: SpkIntermediary,
    tspkExpected :: SpkExpected
  }

testScriptPubKeyParseJSON :: Ctx -> Value -> Parser TestScriptPubKey
testScriptPubKeyParseJSON ctx = withObject "TestScriptPubKey" $ \obj -> do
  given <- unSpkGiven <$> (spkGivenParseJSON ctx =<< obj .: "given")
  inter <- spkIntermediaryParseJSON ctx =<< obj .: "intermediary"
  expect <- spkExpectedParseJSON ctx =<< obj .: "expected"
  return $ TestScriptPubKey given inter expect

-- | The keyPathSpending vector: the unsigned transaction, the outputs it
-- spends, one case per Taproot input, and the fully signed transaction
data KeyPathVector = KeyPathVector
  { unsignedTx :: Tx,
    spent :: [TxOut],
    cases :: [KeyPathCase],
    signedTx :: Tx
  }

data KeyPathCase = KeyPathCase
  { index :: Int,
    internalSecret :: SecKey,
    merkleRoot :: Maybe (Digest SHA256),
    hashType :: SigHash,
    internalPubKey :: Text,
    tweakedSecret :: Text,
    sigHash :: Text,
    witness :: [Text]
  }

keyPathParseJSON :: Value -> Parser KeyPathVector
keyPathParseJSON = withObject "keyPathSpending" $ \obj -> do
  given <- obj .: "given"
  rawTx <- given .: "rawUnsignedTx" >>= jsonHex
  tx <- either fail return (S.decode rawTx)
  utxos <- given .: "utxosSpent"
  spent <- forM utxos $ \u -> TxOut <$> u .: "amountSats" <*> (u .: "scriptPubKey" >>= jsonHex)
  inputCases <- obj .: "inputSpending"
  cases <- forM inputCases $ \c -> do
    g <- c .: "given"
    i <- c .: "intermediary"
    e <- c .: "expected"
    secretBytes <- g .: "internalPrivkey" >>= jsonHex
    rootM <- g .: "merkleRoot" >>= traverse jsonHex
    KeyPathCase
      <$> g .: "txinIndex"
      <*> maybe (fail "internal private key") return (secKey secretBytes)
      <*> pure (digestFromByteString =<< rootM)
      <*> (fromIntegral <$> (g .: "hashType" :: Parser Word32))
      <*> i .: "internalPubkey"
      <*> i .: "tweakedPrivkey"
      <*> i .: "sigHash"
      <*> e .: "witness"
  aux <- obj .: "auxiliary"
  signedRaw <- aux .: "fulledSignedTx" >>= jsonHex
  signed <- either fail return (S.decode signedRaw)
  return (KeyPathVector tx spent cases signed)

data TestVector = TestVector
  { testScriptPubKey :: [TestScriptPubKey],
    testKeyPath :: KeyPathVector
  }

testVectorParseJSON :: Ctx -> Value -> Parser TestVector
testVectorParseJSON ctx = withObject "TestVector" $ \obj ->
  TestVector
    <$> (mapM (testScriptPubKeyParseJSON ctx) =<< obj .: "scriptPubKey")
    <*> (obj .: "keyPathSpending" >>= \case [v] -> keyPathParseJSON v; _ -> fail "one keyPathSpending vector")

jsonHex :: Text -> Parser ByteString
jsonHex = maybe (fail "Unable to decode hex") pure . decodeHex
