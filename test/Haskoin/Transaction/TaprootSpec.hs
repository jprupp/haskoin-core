{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}

-- | Taproot: the script trees, output keys and control blocks of the BIP
-- 341 vectors, key path spending with its signature digest, the witness of
-- a spend, and the BIP 86 addresses.
module Haskoin.Transaction.TaprootSpec (spec) where

import Control.Applicative ((<|>))
import Control.Monad (forM, forM_, (<=<))
import Crypto.Hash (Digest, SHA256, digestFromByteString, hashFinalize, hashUpdate)
import Data.Aeson
import Data.Aeson.Types
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Bytes.Get (runGetS)
import Data.Bytes.Put (putByteString, putWord8, runPutS)
import Data.Bytes.Serial (deserialize, serialize)
import Data.Bytes.VarInt qualified as Base128
import Data.Either (isLeft)
import Data.Maybe (fromJust, isJust, isNothing)
import Data.Serialize qualified as S
import Data.Text (Text)
import Data.Text qualified
import Data.Word (Word32, Word64, Word8)
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
        (addrToText btc =<< outputAddress btc ctx (taprootScriptOutput ctx output)) `shouldBe` Just address
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
        fmap (encodeHex . encodeTaprootSig) (taprootSignature (signSchnorr ctx tweaked (hashToMsg digest)) c.hashType) `shouldBe` Right (head c.witness)

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

    -- The witness of each input is in the vector, so this checks the
    -- signer against the BIP for all seven inputs and hash types
    it "signTaprootInput signs each Taproot input of the vector with its output secret key, and gives the witness of the vector" $
      forM_ testKeyPath.cases $ \c -> do
        let tweaked = fromJust (taprootOutputSecKey ctx c.internalSecret (MASTCommitment <$> c.merkleRoot))
        signed <- expectRight (signTaprootInput ctx testKeyPath.unsignedTx testKeyPath.spent c.index c.hashType tweaked)
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
      fmap encodeTaprootSig (taprootSignature sig sigHashDefault) `shouldBe` Right (BS.replicate 64 7)
      fmap encodeTaprootSig (taprootSignature sig sigHashAll) `shouldBe` Right (BS.replicate 64 7 <> "\x01")
      fmap encodeTaprootSig (taprootSignature sig (setAnyoneCanPay sigHashSingle)) `shouldBe` Right (BS.replicate 64 7 <> "\x83")
      fmap (\s -> (s.sig, s.hash)) (decodeTaprootSig (BS.replicate 64 7)) `shouldBe` Right (sig, sigHashDefault)
      fmap (\s -> (s.sig, s.hash)) (decodeTaprootSig (BS.replicate 64 7 <> "\x02")) `shouldBe` Right (sig, sigHashNone)

    it "are not built with a hash type that Taproot does not define" $ do
      let sig = fromJust (schnorrSig (BS.replicate 64 7))
      taprootSignature sig 0x04 `shouldBe` Left "taprootSignature: invalid hash type 4"
      taprootSignature sig 0x41 `shouldBe` Left "taprootSignature: invalid hash type 65"
      taprootSignature sig 0x80 `shouldBe` Left "taprootSignature: invalid hash type 128"
      -- Cut to one byte, 0x100 would be a 65-byte signature ending in 00,
      -- which BIP 341 forbids, and 0x101 would say SIGHASH_ALL
      taprootSignature sig 0x100 `shouldBe` Left "taprootSignature: invalid hash type 256"
      taprootSignature sig 0x101 `shouldBe` Left "taprootSignature: invalid hash type 257"

    it "of each of the seven hash types are 64 or 65 bytes that read back as the same signature" $ do
      let sig = fromJust (schnorrSig (BS.replicate 64 7))
      forM_ [(0x00, 64), (0x01, 65), (0x02, 65), (0x03, 65), (0x81, 65), (0x82, 65), (0x83, 65)] $ \(hashType, size) -> do
        signature <- expectRight (taprootSignature sig hashType)
        BS.length (encodeTaprootSig signature) `shouldBe` size
        decodeTaprootSig (encodeTaprootSig signature) `shouldBe` Right signature

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
        spend = ScriptPathData {annex = Nothing, stack = ["aa", "bbbb"], script = leaf, extIsOdd = odd (keyParity ctx outputKey), leafVersion = tapscriptLeafVersion, internalKey, control = proof, opaqueScript = Nothing}
        control = encodeControlBlock ctx (tapscriptLeafVersion + keyParity ctx outputKey) internalKey proof
        scriptBytes = runPutS (serialize leaf)

    it "a key path spend is one signature, with the annex after it when there is one" $ do
      encodeTaprootWitness ctx (KeyPathSpend "sig" Nothing) `shouldBe` Right ["sig"]
      encodeTaprootWitness ctx (KeyPathSpend "sig" (Just "\x50\&annex")) `shouldBe` Right ["sig", "\x50\&annex"]
      viewTaprootWitness ctx ["sig"] `shouldBe` Just (KeyPathSpend "sig" Nothing)
      viewTaprootWitness ctx ["sig", "\x50\&annex"] `shouldBe` Just (KeyPathSpend "sig" (Just "\x50\&annex"))
      -- One item is the signature even when it starts with the annex byte
      viewTaprootWitness ctx ["\x50sig"] `shouldBe` Just (KeyPathSpend "\x50sig" Nothing)
      viewTaprootWitness ctx [] `shouldBe` Nothing

    it "a script path spend is the stack, the script and the control block, in the order of BIP 341, then the annex" $ do
      encodeTaprootWitness ctx (ScriptPathSpend spend) `shouldBe` Right ["aa", "bbbb", scriptBytes, control]
      encodeTaprootWitness ctx (ScriptPathSpend spend {annex = Just "\x50"}) `shouldBe` Right ["aa", "bbbb", scriptBytes, control, "\x50"]
      viewTaprootWitness ctx ["aa", "bbbb", scriptBytes, control] `shouldBe` Just (ScriptPathSpend spend)
      viewTaprootWitness ctx ["aa", "bbbb", scriptBytes, control, "\x50"] `shouldBe` Just (ScriptPathSpend spend {annex = Just "\x50"})
      viewTaprootWitness ctx [scriptBytes, control] `shouldBe` Just (ScriptPathSpend spend {stack = []})
      -- The control block and the script in the other order are not a
      -- spend: the script is not a control block
      viewTaprootWitness ctx [control, scriptBytes] `shouldBe` Nothing

    -- BIP 342: a Tapscript that holds an OP_SUCCESSx opcode succeeds, "even
    -- if later bytes in the tapscript would fail to decode otherwise". 50 is
    -- OP_SUCCESS80, and 4c is an OP_PUSHDATA1 with no length after it.
    it "a script path spend is read whatever the bytes of its script are" $ do
      let opaque = "\x50\x4c"
          opaqueControl = encodeControlBlock ctx 0xc0 internalKey []
          expected = ScriptPathData {annex = Nothing, stack = [], script = Script [], extIsOdd = False, leafVersion = 0xc0, internalKey, control = [], opaqueScript = Just opaque}
      viewTaprootWitness ctx [opaque, opaqueControl] `shouldBe` Just (ScriptPathSpend expected)
      scriptPathScriptBytes expected `shouldBe` opaque
      encodeTaprootWitness ctx (ScriptPathSpend expected) `shouldBe` Right [opaque, opaqueControl]
      -- A leaf of another version, whose bytes are a push cut short
      fmap (\case ScriptPathSpend d -> (d.leafVersion, d.opaqueScript); _ -> (0, Nothing)) (viewTaprootWitness ctx ["\x02\xaa", encodeControlBlock ctx 0xc2 internalKey []])
        `shouldBe` Just (0xc2, Just "\x02\xaa")

    it "a script path spend of bytes that are not opcodes verifies against the output key that commits to those bytes" $ do
      let opaque = "\x50\x4c"
          key = taprootOutputKey ctx (TaprootOutput internalKey (Just (MASTCommitment (leafHashBytes 0xc0 opaque))))
          opaqueSpend = ScriptPathData {annex = Nothing, stack = [], script = Script [], extIsOdd = odd (keyParity ctx key), leafVersion = 0xc0, internalKey, control = [], opaqueScript = Just opaque}
      verifyScriptPathData ctx key opaqueSpend `shouldBe` True
      verifyScriptPathData ctx key opaqueSpend {opaqueScript = Just "\x50\x4d"} `shouldBe` False

    it "a witness is not written with an annex that is empty or does not start with 0x50" $ do
      encodeTaprootWitness ctx (KeyPathSpend "sig" (Just "hello")) `shouldBe` Left "encodeTaprootWitness: an annex starts with 0x50"
      encodeTaprootWitness ctx (KeyPathSpend "sig" (Just "")) `shouldBe` Left "encodeTaprootWitness: an annex starts with 0x50"
      encodeTaprootWitness ctx (ScriptPathSpend spend {annex = Just "hello"}) `shouldBe` Left "encodeTaprootWitness: an annex starts with 0x50"

    it "a witness is written with a proof of 128 hashes, and not with one of 129" $ do
      let node = fromJust (digestFromByteString @SHA256 (BS.replicate 32 1))
      -- two stack items, the script and the control block
      fmap length (encodeTaprootWitness ctx (ScriptPathSpend spend {control = replicate 128 node})) `shouldBe` Right 4
      encodeTaprootWitness ctx (ScriptPathSpend spend {control = replicate 129 node}) `shouldBe` Left "encodeTaprootWitness: a control block holds at most 128 nodes"

    it "a witness is not written with a leaf version that a control block cannot carry" $ do
      encodeTaprootWitness ctx (ScriptPathSpend spend {leafVersion = 0xc1}) `shouldBe` Left "encodeTaprootWitness: a control block cannot carry the leaf version 193"
      encodeTaprootWitness ctx (ScriptPathSpend spend {leafVersion = 0x50}) `shouldBe` Left "encodeTaprootWitness: a control block cannot carry the leaf version 80"

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
            viewed witness = viewTaprootWitness ctx =<< eitherToMaybe (encodeTaprootWitness ctx witness)
         in (viewed (KeyPathSpend sig annex), viewed (spendWith annex))
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

  describe "Leaf hashes" $ do
    -- BIP 341: the tapleaf hash is hash_TapLeaf(v || compact_size(size of s) || s).
    -- The literals were computed from that sentence with Python's hashlib:
    -- SHA256(SHA256("TapLeaf") || SHA256("TapLeaf") || c0 || length || script),
    -- for a script of n bytes 0x61 (OP_NOP).
    it "of a script of 127 bytes, whose length is written 7f" $
      digestHex (leafHash 0xc0 (Script (replicate 127 OP_NOP))) `shouldBe` "768beb2ec05d13f86bef3b81dda9ce0b4f22d82a6a5ec5ab5a5f2ca6da6567d0"
    it "of a script of 128 bytes, whose length is written 80" $
      digestHex (leafHash 0xc0 (Script (replicate 128 OP_NOP))) `shouldBe` "8c247c24a8b5def0f3cc6fe79098bf761275c4c4e1b27739d6b5caf7fabe0ef7"
    it "of a script of 252 bytes, whose length is written fc" $
      digestHex (leafHash 0xc0 (Script (replicate 252 OP_NOP))) `shouldBe` "bed46d76590727c80034f9c383ca18e25e1c71ede72a134ccf772d2852747408"
    it "of a script of 253 bytes, whose length is written fd fd 00" $
      digestHex (leafHash 0xc0 (Script (replicate 253 OP_NOP))) `shouldBe` "03a32feb39d860fbc91750ba7ad075ce987a0b1a86828115748e07e32e3dfc5d"

    -- tr(cba52b43…6970,multi_a(2,b2fff6fd…,53f8149c…,a07f1b7d…,b7e3bfb9…)).
    -- Bitcoin Core 32.1 gives this leaf hash and this output script
    -- (decodepsbt and deriveaddresses on regtest). The leaf is 138 bytes:
    -- 4 keys × 34 bytes + OP_2 + OP_NUMEQUAL.
    it "of the 138-byte multi_a leaf is the one Bitcoin Core derives, and so is the output script" $ do
      let leaf = scriptOf multiALeaf
          internal = fromJust (importXOnlyPubKey ctx (hexBytes "cba52b4389f798ec8ba66d9520ce532af2fe642b970010e2fbd0ec36bce36970"))
      BS.length (hexBytes multiALeaf) `shouldBe` 138
      digestHex (leafHash 0xc0 leaf) `shouldBe` "c6831caa9b274f379336d6bcc789aa6e82760d573e3750b97df37e624d8e6c90"
      encodeHex (marshal ctx (taprootScriptOutput ctx (TaprootOutput internal (Just (MASTLeaf 0xc0 leaf)))))
        `shouldBe` "51207fd815afed80f6bc581ac94aa52d85c50d2bddff7347e1094936eb71e2f18936"

    it "of script bytes that are not a list of opcodes is taken on the bytes" $
      -- 50 4c is OP_SUCCESS80 followed by an OP_PUSHDATA1 with no length.
      -- SHA256(tag || tag || c0 || 02 || 50 4c), computed with Python's hashlib.
      digestHex (leafHashBytes 0xc0 "\x50\x4c") `shouldBe` "070bb467edca609e1a3246a8ba31e6266509d0d4e74e5fb2a32359b5f1565272"

  -- Versions up to 1.5.1 wrote the script length of a leaf as a base-128
  -- varint. For a leaf of 128 bytes or more that gave another leaf hash,
  -- and so another output key. Coins sent to such an output are still
  -- reachable: the old leaf hash goes in the tree as a commitment. The old
  -- values below were printed by the unfixed library and recomputed in
  -- Python with the base-128 length.
  describe "An output made by versions up to 1.5.1 with a leaf of 128 bytes or more" $ do
    let internalSecret = fromJust (secKey (hexBytes "01c58048b9108d028cdde54d8ea8fa545cd4145157fad6e5a908809c7e35388d"))
        internal = derivePubKey ctx internalSecret
        oldLeafHash = leafHashBefore152 0xc0 (scriptOf multiALeaf)
        xOnly = encodeHex . exportXOnlyPubKey ctx
    it "has a leaf hash that is rebuilt with the base-128 length" $ do
      xOnly internal `shouldBe` "cba52b4389f798ec8ba66d9520ce532af2fe642b970010e2fbd0ec36bce36970"
      digestHex oldLeafHash `shouldBe` "4a0b2a93f8430729d9467c0bc91d26d54b63802e627783bf808694c8e8dbc372"
    it "has the output key of the tree that holds the old leaf hash as a commitment" $
      xOnly (taprootOutputKey ctx (TaprootOutput internal (Just (MASTCommitment oldLeafHash))))
        `shouldBe` "15e87fb4cb019af07cf16fa2b9a8451536bd86321dcc11053c70d9038ec97c80"
    it "is spent by its key path with the secret key tweaked with that commitment" $
      fmap (xOnly . derivePubKey ctx) (taprootOutputSecKey ctx internalSecret (Just (MASTCommitment oldLeafHash)))
        `shouldBe` Just "15e87fb4cb019af07cf16fa2b9a8451536bd86321dcc11053c70d9038ec97c80"
    it "keeps the script path of a short leaf next to the long one" $ do
      -- The tree {pk(1cf7198d…2500), multi_a leaf}
      let short = Script [opPushData (hexBytes "1cf7198d10d0552c8df4d0380372a5fa224a1226fc3a49546a416086442d2500"), OP_CHECKSIG]
          oldTree = MASTBranch (MASTLeaf 0xc0 short) (MASTCommitment oldLeafHash)
          oldKey = taprootOutputKey ctx (TaprootOutput internal (Just oldTree))
          proofs = [proof | (_, _, proof) <- getMerkleProofs oldTree]
          spendOf proof = ScriptPathData {annex = Nothing, stack = [], script = short, extIsOdd = odd (keyParity ctx oldKey), leafVersion = 0xc0, internalKey = internal, control = proof, opaqueScript = Nothing}
      xOnly oldKey `shouldBe` "120ed04aacce013f8ed3b63a53143aec81a4c05fa0a263a693d14aa8bebd7efd"
      map (map digestHex) proofs `shouldBe` [["4a0b2a93f8430729d9467c0bc91d26d54b63802e627783bf808694c8e8dbc372"]]
      map (verifyScriptPathData ctx oldKey . spendOf) proofs `shouldBe` [True]
    it "is not the output of the same tree today" $ do
      let short = Script [opPushData (hexBytes "1cf7198d10d0552c8df4d0380372a5fa224a1226fc3a49546a416086442d2500"), OP_CHECKSIG]
          tree = MASTBranch (MASTLeaf 0xc0 short) (MASTLeaf 0xc0 (scriptOf multiALeaf))
      -- Root and key computed in Python from the text of BIP 341
      digestHex (mastCommitment tree) `shouldBe` "4bff8cf0bd46ff4d4470c11a7f407dfee7078c7675b877691310c0ee0058c620"
      xOnly (taprootOutputKey ctx (TaprootOutput internal (Just tree))) `shouldBe` "b672ffdc20bf79cf4bda88ec7a0ad9c53c91e032f2bc169af425eae9dac8afe0"

  describe "Merkle proofs" $ do
    -- tr(ecd5eddb…7670,{pk(A),{pk(B),{pk(C),pk(D)}}}). The Merkle root and
    -- the four control blocks are what Bitcoin Core 32.1 prints in
    -- decodepsbt for this descriptor. A proof lists the siblings from the
    -- leaf up to the root, as taproot_tree_helper does in BIP 341.
    it "of a tree of depth 3 give each leaf the control block Bitcoin Core gives it" $ do
      let pkLeaf key = MASTLeaf 0xc0 (Script [opPushData (hexBytes key), OP_CHECKSIG])
          a = pkLeaf "1cf7198d10d0552c8df4d0380372a5fa224a1226fc3a49546a416086442d2500"
          b = pkLeaf "d1a2717d14f4798094719c904372393797b88d365766d95a021333fe3e6a526c"
          c = pkLeaf "5807c60bab1f93b36747e3d120c29fa898ab37e616b3b7635b21e5a71888e6da"
          d = pkLeaf "33045c7755fc6aef51859ad00d7393f1d23ff8b0bd6acf0d6c6d7a72502d905a"
          tree = MASTBranch a (MASTBranch b (MASTBranch c d))
          internal = fromJust (importXOnlyPubKey ctx (hexBytes "ecd5eddb647ff233131e292cef048228bce3a3b045319d563b57d59e294c7670"))
          outputKey = taprootOutputKey ctx (TaprootOutput internal (Just tree))
          controlBlocks = [encodeHex (encodeControlBlock ctx (0xc0 + keyParity ctx outputKey) internal proof) | (_, _, proof) <- getMerkleProofs tree]
      digestHex (mastCommitment tree) `shouldBe` "e0f4dd44e6affb70c64661b32d78666ce2296fcdf9abdcbbe9482e91398f4ac5"
      controlBlocks
        `shouldBe` [ "c1ecd5eddb647ff233131e292cef048228bce3a3b045319d563b57d59e294c7670cd8b2619baff8006c3b4f8d86a79d76d2a636b226a43602aa7b17908152a2db6",
                     "c1ecd5eddb647ff233131e292cef048228bce3a3b045319d563b57d59e294c767096de41a8ea89de5ab00d7fe07ca5ef19dc4877e8869b08d70228add11bb98965c0243dd79cee2b5ec8ac1e254869b9a9a0a4a40a684a13e28ec8ef013588a1f3",
                     "c1ecd5eddb647ff233131e292cef048228bce3a3b045319d563b57d59e294c76701995a0d81bdbda264923687c3593a67e5cba9b2adab467777885a6177368f3dbd864c47073b2a8367b8943dde8f76cd8856a071faf86f3bfb2680c6adc1fbddec0243dd79cee2b5ec8ac1e254869b9a9a0a4a40a684a13e28ec8ef013588a1f3",
                     "c1ecd5eddb647ff233131e292cef048228bce3a3b045319d563b57d59e294c7670a6f339703d444033227bbd073048f0821f6c31b9441d7b986af598bdaf3a5c77d864c47073b2a8367b8943dde8f76cd8856a071faf86f3bfb2680c6adc1fbddec0243dd79cee2b5ec8ac1e254869b9a9a0a4a40a684a13e28ec8ef013588a1f3"
                   ]

  describe "Any script tree" $ do
    prop "has the Merkle root and the proofs that taproot_tree_helper of BIP 341 gives" $
      forAll (arbitraryMAST True) $ \tree ->
        let (paths, root) = referenceTree tree
         in ( BA.convert (mastCommitment tree) :: ByteString,
              [(runPutS (serialize script), map BA.convert proof) | (_, script, proof) <- getMerkleProofs tree]
            )
              === (root, paths)
    prop "gives each leaf a proof of as many hashes as the leaf is deep, which verifies against the output key" $
      forAll (arbitraryMAST True) $ \tree ->
        let (_, p) = bip86Key ctx
            internal = fromJust (importXOnlyPubKey ctx (exportXOnlyPubKey ctx p.point))
            outputKey = taprootOutputKey ctx (TaprootOutput internal (Just tree))
            spendOf (version, script, proof) = ScriptPathData {annex = Nothing, stack = [], script, extIsOdd = odd (keyParity ctx outputKey), leafVersion = version, internalKey = internal, control = proof, opaqueScript = Nothing}
            proofs = getMerkleProofs tree
         in (map (\(_, _, proof) -> length proof) proofs, map (verifyScriptPathData ctx outputKey . spendOf) proofs)
              === (leafDepths tree, map (const True) proofs)
    prop "without a commitment is built back from the list of its leaves" $
      forAll (arbitraryMAST False) $ \tree ->
        fmap mastCommitment (tapTreeFromLeaves =<< tapTreeLeaves tree) === Just (mastCommitment tree)
    prop "lists its leaves with the depths they have" $
      forAll (arbitraryMAST False) $ \tree ->
        fmap (map (fromIntegral . (.depth))) (tapTreeLeaves tree) === Just (leafDepths tree)

  describe "Script path spends from Bitcoin mainnet" $ do
    spends <- runIO (readTestFileParser mainnetSpendsParseJSON "taproot_mainnet_spends.json")
    -- Each spend of the file is in a mainnet block, so its script and its
    -- control block do commit to the output key of the coin it spends.
    it "are read, and each script and control block commit to the output key of the coin spent" $ do
      length spends `shouldBe` 24
      let verdict (txid, spentScript, witness) =
            ( txid,
              case (viewTaprootWitness ctx witness, importXOnlyPubKey ctx (BS.drop 2 spentScript)) of
                (Just (ScriptPathSpend spd), Just outputKey) -> verifyScriptPathData ctx outputKey spd
                _ -> False
            )
      filter (not . snd) (map verdict spends) `shouldBe` []

  describe "The signature digest, on transactions that Bitcoin Core 32.1 mined on regtest" $ do
    let digestOf tx spent hashType annex leaf = fmap (encodeHex . runPutS . serialize) (taprootSigHash tx spent 0 hashType annex leaf)
        coin = TxOut 100000 . hexBytes
        digest32 = fromJust . digestFromByteString @SHA256 . hexBytes
    it "of a key path spend with an annex commits to the annex with its length" $
      digestOf (txOf keyPathAnnexTx) [coin "512028066f61c28af1ecb48c7948f8b5770838eec15223c8697a8e40510c2c29ea04"] sigHashDefault (Just (hexBytes "5068656c6c6f")) Nothing
        `shouldBe` Right "36a6017a9e1b1d246643172c6f0a9fe93136afd5f3e12d43b29a1f52a70a014f"
    it "of a script path spend with an annex and SIGHASH_ALL" $
      digestOf (txOf scriptPathAnnexTx) [coin "5120a354b6c111a5f8339fd8ea5bc6147f8ca829029188e4d3f7622751417328be18"] sigHashAll (Just (hexBytes "50616e6e6578206f662061207363726970742070617468")) (Just (digest32 "3da27bc75f49edd14e69e2cb4a3de1b00d614fd6049f2b5bb3403e39f4dbef51", 0xffffffff))
        `shouldBe` Right "1a8471791448654da927da98e00df97d853a79a5cc9b903ea59562dc2df4d591"
    it "of a script path spend commits to the position of the last OP_CODESEPARATOR executed" $ do
      let tx = txOf codeSeparatorTx
          spent = [coin "512057d7dc3026daad454ab05b7a533b5d3746fc726234ee966d0bc1464f19837426"]
          leaf = digest32 "9e8a23f6730007920039b3d164b85c54f69ff80f103fbf70c837e25918ffec59"
      -- The first key signs before the separator: position 0xffffffff
      digestOf tx spent sigHashDefault Nothing (Just (leaf, 0xffffffff)) `shouldBe` Right "0adc9a14a76ffe44333da52277f6cf8a469f9cd0caaceaf06283f204c06ed7e3"
      -- The second key signs after the separator, which is opcode number 2
      digestOf tx spent sigHashDefault Nothing (Just (leaf, 2)) `shouldBe` Right "057a66c7ba4129c6d30565056a76a6ac7189ebae58ec6ff7ef630ea7ad24bca9"
    it "is refused for an annex that does not start with 0x50, or that is empty" $ do
      let tx = txOf keyPathAnnexTx
          spent = [coin "512028066f61c28af1ecb48c7948f8b5770838eec15223c8697a8e40510c2c29ea04"]
      digestOf tx spent sigHashDefault (Just "hello") Nothing `shouldBe` Left "taprootSigHash: an annex starts with 0x50"
      digestOf tx spent sigHashDefault (Just "") Nothing `shouldBe` Left "taprootSigHash: an annex starts with 0x50"
    it "is refused with SIGHASH_SINGLE at the first input that has no output at its index" $
      -- The transaction of the BIP 341 vector has two outputs: input 2 is
      -- the first input without one
      taprootSigHash testKeyPath.unsignedTx testKeyPath.spent 2 sigHashSingle Nothing Nothing
        `shouldBe` Left "taprootSigHash: SIGHASH_SINGLE without an output at the input index"

  describe "verifyStdTx on Taproot inputs" $ do
    let coinOfTx = oneCoin ctx
    it "accepts the key path spend with an annex that Bitcoin Core 32.1 mined on regtest" $ do
      let tx = txOf keyPathAnnexTx
      verifyStdTx btc ctx tx (coinOfTx tx "512028066f61c28af1ecb48c7948f8b5770838eec15223c8697a8e40510c2c29ea04") `shouldBe` True
    it "accepts the script path spend of a single key leaf with an annex that Bitcoin Core 32.1 mined on regtest" $ do
      let tx = txOf scriptPathAnnexTx
      verifyStdTx btc ctx tx (coinOfTx tx "5120a354b6c111a5f8339fd8ea5bc6147f8ca829029188e4d3f7622751417328be18") `shouldBe` True
    -- The witness holds a valid signature of the leaf key over the leaf
    -- "<key> OP_CHECKSIG", and a control block that names the same key as
    -- internal key. The coin's output key does not commit to that leaf.
    it "refuses a script path spend whose leaf the output key of the coin does not commit to" $ do
      let tx = txOf uncommittedLeafTx
      verifyStdTx btc ctx tx (coinOfTx tx "5120da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21") `shouldBe` False
    it "refuses a Taproot input that has an input script" $ do
      let tx = txOf keyPathAnnexTx
          withScript = tx {inputs = [i {script = "\x51"} | i <- tx.inputs]} :: Tx
      verifyStdTx btc ctx withScript (coinOfTx tx "512028066f61c28af1ecb48c7948f8b5770838eec15223c8697a8e40510c2c29ea04") `shouldBe` False

    -- BIP 342 defines the rules of leaf version 0xc0 only. A leaf of another
    -- version is not a Tapscript, so its key check is not something this
    -- function can vouch for.
    it "verifies the script path spend of a single key leaf of version 0xc0, and not of version 0xc2" $ do
      let (leafSecret, leafPublic) = bip86Key ctx
          internal = fromJust (importXOnlyPubKey ctx (hexBytes "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
          leafScript = Script [opPushData (exportXOnlyPubKey ctx leafPublic.point), OP_CHECKSIG]
          outpoint = OutPoint "1111111111111111111111111111111111111111111111111111111111111111" 0
          spendWith version = do
            let output = TaprootOutput internal (Just (MASTLeaf version leafScript))
                coinScript = taprootScriptOutput ctx output
                unsigned = buildTx ctx [outpoint] [(coinScript, 99000)]
            digest <- taprootSigHash unsigned [TxOut 100000 (marshal ctx coinScript)] 0 sigHashDefault Nothing (Just (leafHash version leafScript, 0xffffffff))
            signature <- taprootSignature (signSchnorr ctx leafSecret.key (hashToMsg digest)) sigHashDefault
            witness <-
              encodeTaprootWitness ctx . ScriptPathSpend $
                ScriptPathData {annex = Nothing, stack = [encodeTaprootSig signature], script = leafScript, extIsOdd = odd (keyParity ctx (taprootOutputKey ctx output)), leafVersion = version, internalKey = internal, control = [], opaqueScript = Nothing}
            return (verifyStdTx btc ctx (Tx unsigned.version unsigned.inputs unsigned.outputs [witness] unsigned.locktime) [(coinScript, 100000, outpoint)])
      spendWith 0xc0 `shouldBe` Right True
      spendWith 0xc2 `shouldBe` Right False

  describe "Control blocks" $
    it "are refused when the internal key is not the x coordinate of a point" $
      -- ff…ff is above the field size, so it is no x coordinate
      decodeControlBlock ctx ("\xc0" <> BS.replicate 32 0xff) `shouldBe` Left "decodeControlBlock: the internal key is not an x-only public key"

  describe "X-only keys as text and bytes" $ do
    let x = "7a338b2a113a14b5a008560cbf5d3c46a6c282967c05f739f30668d32fc538b5"
        json t = unmarshalJSON ctx (encode (String t)) :: Maybe XOnlyPubKey
    it "are read from the hex of 32 bytes" $
      fmap (encodeHex . marshal ctx) (json x) `shouldBe` Just x
    it "are refused from the hex of 33 bytes, of 64 bytes and of 31 bytes" $ do
      json (x <> "ff") `shouldBe` Nothing
      json (x <> x) `shouldBe` Nothing
      json (Data.Text.dropEnd 2 x) `shouldBe` Nothing
    it "are refused from 33 bytes" $
      (unmarshal ctx (hexBytes x <> "\xff") :: Either String XOnlyPubKey) `shouldSatisfy` isLeft

  describe "The depth limit of a script tree" $ do
    -- BIP 341: a control block holds at most 128 nodes, so a leaf deeper
    -- than 128 can never be spent. Bitcoin Core's TaprootBuilder refuses a
    -- depth above TAPROOT_CONTROL_MAX_NODE_COUNT = 128.
    let leaf = MASTLeaf 0xc0 (Script [OP_1])
        -- A tree whose two deepest leaves are at depth n
        chain :: Int -> MAST
        chain 0 = leaf
        chain n = MASTBranch leaf (chain (n - 1))
        chainLeaves :: Int -> [TapLeaf]
        chainLeaves n = [TapLeaf (fromIntegral d) 0xc0 (Script [OP_1]) | d <- [1 .. n]] <> [TapLeaf (fromIntegral n) 0xc0 (Script [OP_1])]
    it "lists the leaves of a tree whose deepest leaves are at depth 128" $
      fmap (map (.depth)) (tapTreeLeaves (chain 128)) `shouldBe` Just ([1 .. 128] <> [128])
    it "does not list the leaves of a tree whose deepest leaves are at depth 129" $
      fmap length (tapTreeLeaves (chain 129)) `shouldBe` Nothing
    it "does not list the leaves of a tree whose deepest leaves are at depth 256" $
      fmap length (tapTreeLeaves (chain 256)) `shouldBe` Nothing
    it "builds the tree of leaves down to depth 128, and not down to depth 129" $ do
      fmap mastCommitment (tapTreeFromLeaves (chainLeaves 128)) `shouldBe` Just (mastCommitment (chain 128))
      fmap mastCommitment (tapTreeFromLeaves (chainLeaves 129)) `shouldBe` Nothing
    it "checkTapTree accepts a tree down to depth 128 and refuses one down to depth 129" $ do
      checkTapTree (chain 128) `shouldBe` Right ()
      checkTapTree (chain 129) `shouldBe` Left "checkTapTree: a node is deeper than 128"
      checkTapTree (MASTBranch leaf (MASTCommitment (mastCommitment leaf))) `shouldBe` Right ()
    it "checkTapTree refuses a leaf version that a control block cannot carry" $ do
      -- BIP 341: the leaf version is c[0] & 0xfe, so it is even, and it
      -- cannot be 0x50, which would read as an annex
      checkTapTree (MASTLeaf 0xc2 (Script [OP_1])) `shouldBe` Right ()
      checkTapTree (MASTLeaf 0xc1 (Script [OP_1])) `shouldBe` Left "checkTapTree: the leaf version 193 is odd"
      checkTapTree (MASTLeaf 0x50 (Script [OP_1])) `shouldBe` Left "checkTapTree: the leaf version 0x50 would read as an annex"
    it "the proof of a leaf at depth 128 verifies, and the proof of a leaf at depth 129 does not" $ do
      let (_, p) = bip86Key ctx
          internal = fromJust (importXOnlyPubKey ctx (exportXOnlyPubKey ctx p.point))
          deepest tree =
            let outputKey = taprootOutputKey ctx (TaprootOutput internal (Just tree))
                (version, script, proof) = last (getMerkleProofs tree)
                spend = ScriptPathData {annex = Nothing, stack = [], script, extIsOdd = odd (keyParity ctx outputKey), leafVersion = version, internalKey = internal, control = proof, opaqueScript = Nothing}
             in (length proof, verifyScriptPathData ctx outputKey spend)
      deepest (chain 128) `shouldBe` (128, True)
      deepest (chain 129) `shouldBe` (129, False)

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

-- | The leaf hash as versions up to 1.5.1 computed it: the script length is
-- the base-128 varint of the bytes package, where BIP 341 has a CompactSize.
-- The two are the same byte for a length below 128 only.
leafHashBefore152 :: Word8 -> Script -> Digest SHA256
leafHashBefore152 version script =
  hashFinalize . hashUpdate (initTaggedHash "TapLeaf") . runPutS $ do
    putWord8 version
    serialize (Base128.VarInt (BS.length bytes))
    putByteString bytes
  where
    bytes = runPutS (serialize script)

-- | @taproot_tree_helper@ of BIP 341, written from the text of the BIP with
-- SHA256 alone: for each leaf its script bytes and its path, and the hash
-- of the tree. A branch known only by its commitment has no leaves.
referenceTree :: MAST -> ([(ByteString, [ByteString])], ByteString)
referenceTree = \case
  MASTLeaf version script ->
    let bytes = runPutS (serialize script)
     in ([(bytes, [])], tagged "TapLeaf" (BS.singleton version <> compactSize (BS.length bytes) <> bytes))
  MASTBranch l r ->
    let (left, leftHash) = referenceTree l
        (right, rightHash) = referenceTree r
     in ( [(leaf, path <> [rightHash]) | (leaf, path) <- left] <> [(leaf, path <> [leftHash]) | (leaf, path) <- right],
          tagged "TapBranch" (min leftHash rightHash <> max leftHash rightHash)
        )
  MASTCommitment commitment -> ([], BA.convert commitment)
  where
    hash32 = runPutS . serialize . sha256
    tagged tag message = hash32 (hash32 tag <> hash32 tag <> message)
    compactSize :: Int -> ByteString
    compactSize n
      | n < 0xfd = BS.singleton (fromIntegral n)
      | n <= 0xffff = BS.pack [0xfd, fromIntegral (n `mod` 256), fromIntegral (n `div` 256)]
      | otherwise = error "referenceTree: script too long for this test"

-- | The depth of each leaf of a tree, depth first
leafDepths :: MAST -> [Int]
leafDepths = go 0
  where
    go d = \case
      MASTBranch l r -> go (d + 1) l <> go (d + 1) r
      MASTLeaf {} -> [d]
      MASTCommitment {} -> []

-- | A script tree of depth 0 to 6. The scripts are 1 to 600 bytes long, so
-- that their lengths fall on both sides of 128 and of 253, where the
-- CompactSize of the leaf hash changes. With the flag set, one node in ten
-- is known only by its commitment.
arbitraryMAST :: Bool -> Gen MAST
arbitraryMAST withCommitments = choose (0, 6 :: Int) >>= go
  where
    go 0 = node
    go d = frequency [(1, node), (3, MASTBranch <$> go (d - 1) <*> go (d - 1))]
    node
      | withCommitments = frequency [(9, leaf), (1, commitment)]
      | otherwise = leaf
    leaf = MASTLeaf <$> elements [0xc0, 0xc0, 0xc0, 0xc2] <*> script
    commitment = MASTCommitment . fromJust . digestFromByteString . BS.pack <$> vectorOf 32 arbitrary
    script = do
      n <- frequency [(3, choose (1, 127)), (3, choose (128, 252)), (2, choose (253, 600)), (2, elements [127, 128, 252, 253])]
      return (Script (replicate n OP_NOP))

digestHex :: Digest SHA256 -> Text
digestHex = encodeHex . BA.convert

scriptOf :: Text -> Script
scriptOf = either error id . runGetS deserialize . hexBytes

-- | The coin of 100,000 satoshi that the first input of a transaction
-- spends, with the output script given in hex
oneCoin :: Ctx -> Tx -> Text -> [(ScriptOutput, Word64, OutPoint)]
oneCoin ctx tx script = [(either error id (unmarshal ctx (hexBytes script)), 100000, (head tx.inputs).outpoint)]

txOf :: Text -> Tx
txOf = either error id . S.decode . hexBytes

-- | multi_a(2,A,B,C,D) of BIP 387: <A> OP_CHECKSIG <B> OP_CHECKSIGADD <C>
-- OP_CHECKSIGADD <D> OP_CHECKSIGADD OP_2 OP_NUMEQUAL
multiALeaf :: Text
multiALeaf = "20b2fff6fd9636bea638845402774fa41b7ab1a68e757c669949fa2f35d0949fedac2053f8149cd733fed0b0eb50388db3f142638bdc819f6ae6ac5d81d0a8caebc9afba20a07f1b7d9804bdc3cf63f30b8f69b2ef53b0fc68d9253ed61b9c31593f5cb075ba20b7e3bfb9e6cb88e668fee38674cef6d155bba19a5cc7403678bf91a7b7a52725ba529c"

-- | Transactions that Bitcoin Core 32.1 accepted in a regtest block. Each
-- spends one coin of 100,000 satoshi.
keyPathAnnexTx, scriptPathAnnexTx, codeSeparatorTx :: Text
keyPathAnnexTx = "010000000001016a7d9c7f155cc46f63ab350387f74b6a585d7a179941592d6fb2151e384740810100000000ffffffff01d07e010000000000160014cabe51bbc4203c9221901541c9e9d3ac219e6ca80240dac56ae755419956efbb11ff69d46916c956612e03bdafe382e48ca1fc4bdf12fc768daf297548a89d22f19451c08107e763523a88d10b9a5044de20789895d2065068656c6c6f00000000"
scriptPathAnnexTx = "010000000001016be84449b8f2ec0559b321b2aed59ba273f79710a73c5a7e3cbce8e57178c2260100000000ffffffff01d07e010000000000160014cabe51bbc4203c9221901541c9e9d3ac219e6ca80441fe2a5388123bdc28dc0635796683a24418375c1e94b9d9074889d4b6865224dd6a0ae16d63d454d1dcdbd86f7291f5be5ce2d0cb785adddc1cbd9bd9b8cda3bd012220864f1c660fd3842d2b45acae2d2c181378c3c397d9c8f6a36dce7e1b3f2fa01fac21c1bc4d541d1be26036455459e9fd4fb8c9e2b829b17eb18fb5f66bbbdedc1c61681750616e6e6578206f66206120736372697074207061746800000000"
codeSeparatorTx = "01000000000101a1b61db207932647112026e232f793c6d807f666f46ebb23b526e68342630f820100000000ffffffff01d07e010000000000160014cabe51bbc4203c9221901541c9e9d3ac219e6ca8044093e3dfc003f3d11aca5c6301aa52f55fe916b01036710653c56ff829d393489a26834188c932372f93aadf116a55c540f68e049f2b17b69760ea22190b944b57401f03095eb9fe08f9462b86196fccd3dfffc2702c6c0b186593bed2ae31f4b963a5b36a40a4c0c76c3da7caf03f39b358773ce914999a772d638d3f5f18d49aa945201da5064215e4cad73afbc2f5cc5d1c537452b49b3660ab201ef739b808950e5cadab203ef9208927082a726fea24d87dabbb476a30c669f1aa0d98bdfc29ad7e30d33dac21c0db5c3a57b4b60a18c53d60623fc64fbd97c21fe61e9a0508919f1bbe7e658aa900000000"

-- | A script path spend of a coin whose output key does not commit to the
-- leaf. The leaf is "<key> OP_CHECKSIG", its signature is valid, and the
-- control block names the same key as internal key.
uncommittedLeafTx :: Text
uncommittedLeafTx = "0100000000010111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01b8820100000000001600149b652a14674a506079f574d20ca7daef6f9a66bb0340ef928ef7a11908475a2f841e482cf8e72e356cccd6f2a1d0c954527fcc2f6f9a49e62e422d55bbacbabb1676fdcc422ff5fc8ad6b0dfcb29219af450769da1602220c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac21c0c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee500000000"

-- | The spends of data/taproot_mainnet_spends.json: transaction id, output
-- script of the coin spent, witness items
mainnetSpendsParseJSON :: Value -> Parser [(Text, ByteString, [ByteString])]
mainnetSpendsParseJSON = withObject "mainnet spends" $ \obj -> do
  spends <- obj .: "spends"
  forM spends $ \s ->
    (,,)
      <$> s .: "txid"
      <*> (s .: "spentScript" >>= jsonHex)
      <*> (s .: "witness" >>= mapM jsonHex)

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
      either error last . encodeTaprootWitness ctx . ScriptPathSpend <$> scriptPathSpends
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
          control = proof,
          opaqueScript = Nothing
        }
    onExamples expected = map encodeHex calculatedControlBlocks @?= map encodeHex expected
    checkVerification = assertBool "Script verifies" . verifyScriptPathData ctx theOutputKey

testAddress :: Ctx -> TestScriptPubKey -> IO ()
testAddress ctx testData =
  computedAddress @?= (Just . spkeAddress . tspkExpected) testData
  where
    computedAddress =
      (addrToText btc <=< outputAddress btc ctx)
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
  signedRaw <- aux .: "fullySignedTx" >>= jsonHex
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
