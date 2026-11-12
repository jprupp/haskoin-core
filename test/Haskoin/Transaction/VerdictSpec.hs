{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.Transaction.VerdictSpec (spec) where

import Crypto.Secp256k1
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get (runGetS)
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (deserialize, serialize)
import Data.Either (rights)
import Data.Maybe (fromJust, mapMaybe)
import Data.Word (Word64, Word8)
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

secret :: Word8 -> SecKey
secret n = fromJust (secKey (B.replicate 31 0 <> B.singleton n))

-- | The compressed bytes of the public key of a secret.
pubBytes :: Ctx -> SecKey -> ByteString
pubBytes ctx = exportPubKey ctx True . derivePubKey ctx

coin :: OutPoint
coin = OutPoint "0101010101010101010101010101010101010101010101010101010101010101" 0

-- | A transaction that spends the coin and pays most of 100,000.
spending :: ByteString -> [ByteString] -> Tx
spending inputScript witness =
  Tx
    { version = 2,
      inputs = [TxIn coin inputScript maxBound],
      outputs = [TxOut 90000 (B.replicate 25 0x51)],
      witness = [witness | not (null witness)],
      locktime = 0
    }

-- | An input script that pushes these items.
pushing :: [ByteString] -> ByteString
pushing = runPutS . serialize . Script . map opPushData

-- | Pay one satoshi less: what was signed is no longer what is there.
tampered :: Tx -> Tx
tampered tx = tx {outputs = [o {value = o.value - 1} | o <- tx.outputs]}

ecdsa :: Ctx -> SecKey -> Word8 -> Either String Hash256 -> ByteString
ecdsa ctx k hashType = either error (\h -> exportSig ctx (signHash ctx k h) <> B.singleton hashType)

-- | A Schnorr signature of Bitcoin Cash, made the plain way: this is a
-- test, and the nonce is not a secret worth keeping.
cashSchnorr :: Ctx -> SecKey -> Hash256 -> ByteString
cashSchnorr ctx k h = head (mapMaybe attempt [1 ..])
  where
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 :: Integer
    p = 2 ^ (256 :: Int) - 2 ^ (32 :: Int) - 977 :: Integer
    word256 i = let b = integerToBS i in B.replicate (32 - B.length b) 0 <> b
    d = bsToInteger k.get
    attempt nonce = do
      r <- derivePubKey ctx <$> secKey (word256 nonce)
      let (x, y) = B.splitAt 32 (B.drop 1 (exportPubKey ctx False r))
          square = powMod (bsToInteger y) ((p - 1) `div` 2) == 1
          e = bsToInteger (runPutS (serialize (sha256 (x <> pubBytes ctx k <> runPutS (serialize h))))) `mod` n
      if square then Just (x <> word256 ((nonce + e * d) `mod` n)) else Nothing
    powMod _ 0 = 1 :: Integer
    powMod b i
      | even i = let half = powMod b (i `div` 2) in half * half `mod` p
      | otherwise = b * powMod b (i - 1) `mod` p

spec :: Spec
spec = prepareContext $ \ctx -> do
  let k = secret 7
      pub = pubBytes ctx k
      h160 = addressHash pub
      value = 100000 :: Word64
      prev so = Just (TxOut value (marshal ctx so))
      pkhScript = either error id (encodeOutput ctx (PayPKHash h160))
      three net tx prevOut = do
        judgeInputs net ctx tx [prevOut] `shouldBe` [InputVerified]
        judgeInputs net ctx (tampered tx) [prevOut] `shouldBe` [InputForged]
        judgeInputs net ctx tx [Nothing] `shouldBe` [InputUndecided]

  describe "judgeInputs on coins of one key" $ do
    it "tells a key hash input that verifies from a forged one, and from one it cannot see" $ do
      let unsigned = spending "" []
          sig = ecdsa ctx k 0x01 (txSigHash btc unsigned pkhScript value 0 sigHashAll)
      three btc (spending (pushing [sig, pub]) []) (prev (PayPKHash h160))
    it "says forged of another key than the one the coin names" $ do
      let other = secret 8
          unsigned = spending "" []
          sig = ecdsa ctx other 0x01 (txSigHash btc unsigned pkhScript value 0 sigHashAll)
      judgeInputs btc ctx (spending (pushing [sig, pubBytes ctx other]) []) [prev (PayPKHash h160)]
        `shouldBe` [InputForged]
    it "does the same for a witness key hash, plain and nested" $ do
      let unsigned = spending "" []
          sig = ecdsa ctx k 0x01 (txSigHashForkId btc unsigned pkhScript value 0 sigHashAll)
          program = marshal ctx (PayWitnessPKHash h160)
      three btc (spending "" [sig, pub]) (prev (PayWitnessPKHash h160))
      three btc (spending (pushing [program]) [sig, pub]) (prev (PayScriptHash (addressHash program)))
    it "does the same for a Taproot key" $ do
      let outKey = B.drop 1 pub
          out = TxOut value (marshal ctx (PayWitness 1 outKey))
          -- the secret of the key with an even y, whichever of the two it is
          signed = head (rights [signTaprootInput ctx (spending "" []) [out] 0 sigHashDefault s | s <- [k, negated]])
          negated = fromJust (secKey . (.get) =<< tweakNegate ctx =<< tweak k.get)
      three btc signed (Just out)
    it "leaves a hash type other than all, and a script, to a node" $ do
      let unsigned = spending "" []
          none = ecdsa ctx k 0x02 (txSigHash btc unsigned pkhScript value 0 sigHashNone)
      judgeInputs btc ctx (tampered (spending (pushing [none, pub]) [])) [prev (PayPKHash h160)]
        `shouldBe` [InputVerified]
      judgeInputs btc ctx (spending (pushing ["anything"]) []) [prev (PayScriptHash h160)]
        `shouldBe` [InputUndecided]

  describe "judgeInputs on Bitcoin Cash" $ do
    let unsigned = spending "" []
        digest prefix = txSigHashCashToken bch unsigned prefix pkhScript value 0 (setForkIdFlag sigHashAll)
        tokens = B.singleton 0xef <> B.replicate 32 0xaa <> B.pack [0x10, 0xfd, 0xe8, 0x03]
    it "reads a Schnorr signature" $ do
      let sig = cashSchnorr ctx k (either error id (digest "")) <> B.singleton 0x41
      B.length sig `shouldBe` 65
      three bch (spending (pushing [sig, pub]) []) (prev (PayPKHash h160))
    it "reads an ECDSA signature" $
      three bch (spending (pushing [ecdsa ctx k 0x41 (digest ""), pub]) []) (prev (PayPKHash h160))
    it "reads a coin that holds tokens, whose digest covers them" $ do
      let withTokens = Just (TxOut value (tokens <> marshal ctx (PayPKHash h160)))
      three bch (spending (pushing [ecdsa ctx k 0x41 (digest tokens), pub]) []) withTokens
      three bch (spending (pushing [cashSchnorr ctx k (either error id (digest tokens)) <> "\x41", pub]) []) withTokens
      -- signed as if the coin held none: not a signature of this coin
      judgeInputs bch ctx (spending (pushing [ecdsa ctx k 0x41 (digest ""), pub]) []) [withTokens]
        `shouldBe` [InputForged]

  describe "judgeInputs on what Bitcoin Cash Node signed" $ do
    -- Two transactions of the wallet of Bitcoin Cash Node 29.2.0 on
    -- regtest, both with Schnorr signatures. The first spends a coinbase
    -- of 50 coins to the same key and makes 1,000 fungible tokens. The
    -- second spends that output, tokens and all.
    let parse h = either error id (runGetS deserialize (fromJust (decodeHex h))) :: Tx
        genesis =
          parse
            "0200000001f28fd1cdb4293ae6bb76e580c5a3469fb926690471f3ffb798ef0a\
          \cda9886525000000006441e31c237fe3a1a45f6c32c779c78025f29bd735fa44\
          \d18c182bc1c08fbbcab25f08cbd8c1937dccd38acf37ef2bf8907e75029d622c\
          \5a9f6f5161ffe534fa2775412103bcacac8993931b1f0867991841a140425906\
          \839d26c4c906a737a4f2f29dd79effffffff01c0aff629010000003eeff28fd1\
          \cdb4293ae6bb76e580c5a3469fb926690471f3ffb798ef0acda988652510fde8\
          \0376a9145dd6bc82b5a42053b8f7802e68d296ac3578537a88ac00000000"
        spend =
          parse
            "0200000001db5f2a09c11a2aaceb0d9bfa755006380257d48dab94a73cfd4d69\
          \c2e2d122a6000000006441f52f838cf46e41b8c630334d2b6edefdb49f67fd19\
          \45ee864321da50b1fa652b6b2db4b517110ee5598cbf5193eac763a56d59bfe2\
          \e20d8f3fb9af4b08bfe340412103bcacac8993931b1f0867991841a140425906\
          \839d26c4c906a737a4f2f29dd79effffffff01806de729010000003eeff28fd1\
          \cdb4293ae6bb76e580c5a3469fb926690471f3ffb798ef0acda988652510fde8\
          \0376a9145dd6bc82b5a42053b8f7802e68d296ac3578537a88ac00000000"
        coinbase = TxOut 5000000000 (fromJust (decodeHex "76a9145dd6bc82b5a42053b8f7802e68d296ac3578537a88ac"))
    it "verifies its Schnorr signature of a coin without tokens" $ do
      judgeInputs bchRegTest ctx genesis [Just coinbase] `shouldBe` [InputVerified]
      judgeInputs bchRegTest ctx (tampered genesis) [Just coinbase] `shouldBe` [InputForged]
    it "verifies its Schnorr signature of a coin that holds tokens" $ do
      let held = head genesis.outputs
      fmap fst (splitTokenPrefix held.script) `shouldSatisfy` maybe False (not . B.null)
      judgeInputs bchRegTest ctx spend [Just held] `shouldBe` [InputVerified]
      judgeInputs bchRegTest ctx (tampered spend) [Just held] `shouldBe` [InputForged]
      -- the same coin without its tokens is another coin
      let bare = held {script = maybe held.script snd (splitTokenPrefix held.script)} :: TxOut
      judgeInputs bchRegTest ctx spend [Just bare] `shouldBe` [InputForged]

  describe "judgeInputs on a multisig of Bitcoin Cash signed with Schnorr signatures" $ do
    let secrets = map secret [11, 12, 13]
        keys = map (wrapPubKey True . derivePubKey ctx) secrets
        twoOfThree = PayMulSig keys 2
        redeem = marshal ctx twoOfThree
        locked = prev (PayScriptHash (addressHash redeem))
        code = either error id (encodeOutput ctx twoOfThree)
        digest = either error id (txSigHashForkId bch (spending "" []) code value 0 (setForkIdFlag sigHashAll))
        sign s = cashSchnorr ctx s digest <> B.singleton 0x41
        -- the field of bits is a small number, pushed by its own opcode
        spendWith bits sigs =
          spending (runPutS (serialize (Script ([bits] <> map opPushData (sigs <> [redeem]))))) []
        verdict tx = judgeInputs bch ctx tx [locked]
    it "verifies the signatures of the keys that the bits name, in the order of the keys" $ do
      verdict (spendWith OP_5 [sign (head secrets), sign (secrets !! 2)]) `shouldBe` [InputVerified]
      verdict (spendWith OP_3 [sign (head secrets), sign (secrets !! 1)]) `shouldBe` [InputVerified]
      verdict (spendWith OP_6 [sign (secrets !! 1), sign (secrets !! 2)]) `shouldBe` [InputVerified]
    it "does not verify bits that name other keys, too many or too few, or keys past the last" $ do
      let sigs = [sign (head secrets), sign (secrets !! 2)]
      verdict (spendWith OP_3 sigs) `shouldBe` [InputUndecided]
      verdict (spendWith OP_7 sigs) `shouldBe` [InputUndecided]
      verdict (spendWith OP_1 sigs) `shouldBe` [InputUndecided]
      verdict (spendWith OP_9 sigs) `shouldBe` [InputUndecided]
      -- in the other order
      verdict (spendWith OP_5 (reverse sigs)) `shouldBe` [InputUndecided]
    it "does not verify what was not signed, nor an ECDSA signature among them" $ do
      verdict (tampered (spendWith OP_5 [sign (head secrets), sign (secrets !! 2)])) `shouldBe` [InputUndecided]
      let ecdsaSig = ecdsa ctx (head secrets) 0x41 (Right digest)
      verdict (spendWith OP_5 [ecdsaSig, sign (secrets !! 2)]) `shouldBe` [InputUndecided]

  describe "verifyStdInput on a multisig of Taproot" $ do
    let secrets = map secret [11, 12, 13]
        xOnly = B.drop 1 . pubBytes ctx
        leaf =
          Script $
            [opPushData (xOnly (head secrets)), OP_CHECKSIG]
              <> concat [[opPushData (xOnly s), OP_CHECKSIGADD] | s <- drop 1 secrets]
              <> [OP_2, OP_NUMEQUAL]
        internal = derivePubKey ctx (secret 14)
        tree = TaprootOutput {internalKey = internal, mast = Just (MASTLeaf tapscriptLeafVersion leaf)}
        out = TxOut value (marshal ctx (taprootScriptOutput ctx tree))
        unsigned = spending "" []
        leafOf = Just (leafHash tapscriptLeafVersion leaf, 0xffffffff)
        digest = either error id (taprootSigHash unsigned [out] 0 sigHashDefault Nothing leafOf)
        sign s = (signSchnorr ctx s (hashToMsg digest)).get
        spendWith items =
          let path =
                ScriptPathSpend
                  ScriptPathData
                    { annex = Nothing,
                      stack = items,
                      script = leaf,
                      extIsOdd = odd (keyParity ctx (taprootOutputKey ctx tree)),
                      leafVersion = tapscriptLeafVersion,
                      internalKey = internal,
                      control = [],
                      opaqueScript = Nothing
                    }
           in unsigned {witness = [either error id (encodeTaprootWitness ctx path)]} :: Tx
        verdict tx = judgeInputs btc ctx tx [Just out]
    it "verifies two signatures of three keys, with an item for each key, the last first" $ do
      verdict (spendWith [sign (secrets !! 2), "", sign (head secrets)]) `shouldBe` [InputVerified]
      verdict (spendWith ["", sign (secrets !! 1), sign (head secrets)]) `shouldBe` [InputVerified]
      let lastTwo = spendWith [sign (secrets !! 2), sign (secrets !! 1), ""]
      verifyStdInput btc ctx lastTwo [(taprootScriptOutput ctx tree, value, coin)] 0 `shouldBe` True
    it "does not verify one signature, three, a signature of another key, or one of other outputs" $ do
      verdict (spendWith ["", "", sign (head secrets)]) `shouldBe` [InputUndecided]
      verdict (spendWith [sign (secrets !! 2), sign (secrets !! 1), sign (head secrets)]) `shouldBe` [InputUndecided]
      -- the signature of the first key where that of the third goes
      verdict (spendWith [sign (head secrets), "", sign (head secrets)]) `shouldBe` [InputUndecided]
      verdict (tampered (spendWith [sign (secrets !! 2), "", sign (head secrets)])) `shouldBe` [InputUndecided]
      -- an item for a key is missing
      verdict (spendWith [sign (secrets !! 1), sign (head secrets)]) `shouldBe` [InputUndecided]

  describe "splitTokenPrefix" $ do
    let category = B.replicate 32 0xaa
        script = "\x76\xa9"
    it "leaves a script without tokens alone" $
      splitTokenPrefix script `shouldBe` Just ("", script)
    it "takes off fungible tokens, a non-fungible one, and one with a commitment" $ do
      let fungible = "\xef" <> category <> "\x10\x05"
          nft = "\xef" <> category <> "\x22"
          committed = "\xef" <> category <> "\x70\x02\xbe\xef\xfd\x00\x01"
      splitTokenPrefix (fungible <> script) `shouldBe` Just (fungible, script)
      splitTokenPrefix (nft <> script) `shouldBe` Just (nft, script)
      splitTokenPrefix (committed <> script) `shouldBe` Just (committed, script)
    it "refuses a prefix that is not well formed" $ do
      -- no tokens at all, a commitment without a token to carry it, an
      -- amount of zero, a number not in its shortest form, and one cut short
      splitTokenPrefix ("\xef" <> category <> "\x00" <> script) `shouldBe` Nothing
      splitTokenPrefix ("\xef" <> category <> "\x50\x01\x00\x01" <> script) `shouldBe` Nothing
      splitTokenPrefix ("\xef" <> category <> "\x10\x00" <> script) `shouldBe` Nothing
      splitTokenPrefix ("\xef" <> category <> "\x10\xfd\x05\x00" <> script) `shouldBe` Nothing
      splitTokenPrefix ("\xef" <> category) `shouldBe` Nothing

  describe "judgeInputs on signed transactions" $
    prop "never says forged of an input that verifies" $
      forAll (elements [btc, bch] >>= \net -> (,) net <$> arbitrarySigningData net ctx) $ \(net, (tx, sigis, keys)) ->
        case signTx net ctx tx sigis (map (.key) keys) of
          Left _ -> property True
          Right signed ->
            let prevOf i = lookup i.outpoint [(s.outpoint, TxOut s.value (marshal ctx s.script)) | s <- sigis]
                verdicts = judgeInputs net ctx signed (map prevOf signed.inputs)
                coins = [(s.script, s.value, s.outpoint) | s <- sigis]
             in counterexample (show verdicts) $
                  InputForged `notElem` verdicts
                    && (not (verifyStdTx net ctx signed coins) || all (== InputVerified) verdicts)
