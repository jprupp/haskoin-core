{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
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
import Data.Text (Text)
import Data.Word (Word16, Word64, Word8)
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

hex :: Text -> ByteString
hex = fromJust . decodeHex

secret :: Word16 -> SecKey
secret n = fromJust (secKey (B.replicate 30 0 <> B.pack [fromIntegral (n `div` 256), fromIntegral n]))

-- | The compressed bytes of the public key of a secret.
pubBytes :: SecKey -> ByteString
pubBytes = exportPubKey True . derivePubKey

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

ecdsa :: SecKey -> Word8 -> Either String Hash256 -> ByteString
ecdsa k hashType = either error (\h -> exportSig (signHash k h) <> B.singleton hashType)

-- | A Schnorr signature of Bitcoin Cash, made the plain way: this is a
-- test, and the nonce is not a secret worth keeping.
cashSchnorr :: SecKey -> Hash256 -> ByteString
cashSchnorr k h = head (mapMaybe attempt [1 ..])
  where
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 :: Integer
    p = 2 ^ (256 :: Int) - 2 ^ (32 :: Int) - 977 :: Integer
    word256 i = let b = integerToBS i in B.replicate (32 - B.length b) 0 <> b
    d = bsToInteger k.get
    attempt nonce = do
      r <- derivePubKey <$> secKey (word256 nonce)
      let (x, y) = B.splitAt 32 (B.drop 1 (exportPubKey False r))
          square = powMod (bsToInteger y) ((p - 1) `div` 2) == 1
          e = bsToInteger (runPutS (serialize (sha256 (x <> pubBytes k <> runPutS (serialize h))))) `mod` n
      if square then Just (x <> word256 ((nonce + e * d) `mod` n)) else Nothing
    powMod _ 0 = 1 :: Integer
    powMod b i
      | even i = let half = powMod b (i `div` 2) in half * half `mod` p
      | otherwise = b * powMod b (i - 1) `mod` p

spec :: Spec
spec = do
  let k = secret 7
      pub = pubBytes k
      h160 = addressHash pub
      value = 100000 :: Word64
      prev so = Just (TxOut value (encodeSerial so))
      pkhScript = either error id (encodeOutput (PayPKHash h160))
      three net tx prevOut = do
        judgeInputs net tx [prevOut] `shouldBe` [InputVerified]
        judgeInputs net (tampered tx) [prevOut] `shouldBe` [InputForged]
        judgeInputs net tx [Nothing] `shouldBe` [InputUndecided]

  describe "judgeInputs on coins of one key" $ do
    it "tells a key hash input that verifies from a forged one, and from one it cannot see" $ do
      let unsigned = spending "" []
          sig = ecdsa k 0x01 (txSigHash btc unsigned pkhScript value 0 sigHashAll)
      three btc (spending (pushing [sig, pub]) []) (prev (PayPKHash h160))
    it "says forged of another key than the one the coin names" $ do
      let other = secret 8
          unsigned = spending "" []
          sig = ecdsa other 0x01 (txSigHash btc unsigned pkhScript value 0 sigHashAll)
      judgeInputs btc (spending (pushing [sig, pubBytes other]) []) [prev (PayPKHash h160)]
        `shouldBe` [InputForged]
    it "does the same for a witness key hash, plain and nested" $ do
      let unsigned = spending "" []
          sig = ecdsa k 0x01 (txSigHashForkId btc unsigned pkhScript value 0 sigHashAll)
          program = encodeSerial (PayWitnessPKHash h160)
      three btc (spending "" [sig, pub]) (prev (PayWitnessPKHash h160))
      three btc (spending (pushing [program]) [sig, pub]) (prev (PayScriptHash (addressHash program)))
    it "does the same for a Taproot key" $ do
      let outKey = B.drop 1 pub
          out = TxOut value (encodeSerial (PayWitness 1 outKey))
          -- the secret of the key with an even y, whichever of the two it is
          signed = head (rights [signTaprootInput (spending "" []) [out] 0 sigHashDefault s | s <- [k, negated]])
          negated = fromJust (secKey . (.get) =<< tweakNegate =<< tweak k.get)
      three btc signed (Just out)
    it "leaves a hash type other than all, and a script, to a node" $ do
      let unsigned = spending "" []
          none = ecdsa k 0x02 (txSigHash btc unsigned pkhScript value 0 sigHashNone)
      judgeInputs btc (tampered (spending (pushing [none, pub]) [])) [prev (PayPKHash h160)]
        `shouldBe` [InputVerified]
      judgeInputs btc (spending (pushing ["anything"]) []) [prev (PayScriptHash h160)]
        `shouldBe` [InputUndecided]

    -- BIP 141: the input script of a witness program nested in a script
    -- hash "must be exactly a push of the BIP16 redeemScript". Bitcoin Core
    -- takes the shortest push only, in a block too. The digest does not
    -- cover the input script, so the signature is as good with any push.
    it "leaves a nested witness key hash to a node when its program is not pushed by its length" $ do
      let -- version 0 and the hash of the key, and the coin locked to the hash of those 22 bytes
          program = hex "00145dedfbf9ea599dd4e3ca6a80b333c472fd0b3f69"
          locked = Just (TxOut value (hex "a9146ba336543ab7de40a61b3b192cbc51449f9700b087"))
          sig =
            hex
              "304402203e31df15158bff1249b9d8cf8606b9e8ecafc487afbc1c1b1a5d490d\
              \882756260220368907754469222876fb2914f4dae1f697b30f7c1a2d1115ae16\
              \122e61ab444601"
          spend push = spending (hex push <> program) [sig, pub]
          verdict tx = judgeInputs btc tx [locked]
      -- the push of 0x16 = 22 bytes
      verdict (spend "16") `shouldBe` [InputVerified]
      -- OP_PUSHDATA1, OP_PUSHDATA2 and OP_PUSHDATA4, with a length of 22
      verdict (spend "4c16") `shouldBe` [InputUndecided]
      verdict (spend "4d1600") `shouldBe` [InputUndecided]
      verdict (spend "4e16000000") `shouldBe` [InputUndecided]
      -- not the form of such an input: not called forged either
      verdict (tampered (spend "4c16")) `shouldBe` [InputUndecided]

  -- On Bitcoin a block may hold these inputs, and nodes do not relay them.
  -- 'verifyStdInput' refuses them, and nothing else says verified there.
  describe "judgeInputs on what Bitcoin does not relay" $ do
    it "leaves a signature with a high S to a node" $ do
      let locked = Just (TxOut value (hex "76a9145dedfbf9ea599dd4e3ca6a80b333c472fd0b3f6988ac"))
          lowS =
            hex
              "3044022053d92d1e62bcca206dd7c77d38678770a59da63dcac8cb937fb29f2d\
              \17e7578c022019a9519939d9302a8d5af75a9d8b8c69852044e1669d2faa3d70\
              \c1df8dea332301"
          -- the same signature with n - S for S, n being the order of the
          -- curve: n - 19a95199...8dea3323 = e656ae66...424c0e1e
          highS =
            hex
              "3045022053d92d1e62bcca206dd7c77d38678770a59da63dcac8cb937fb29f2d\
              \17e7578c022100e656ae66c626cfd572a508a562747395358e980548ab709182\
              \619cad424c0e1e01"
          verdict sig = judgeInputs btc (spending (pushing [sig, pub]) []) [locked]
      verdict lowS `shouldBe` [InputVerified]
      verdict highS `shouldBe` [InputUndecided]
    it "leaves a hybrid key to a node" $ do
      let -- the key with both coordinates, after 0x06 for an even y
          hybrid =
            hex
              "065cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9\
              \bc6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264\
              \da"
          -- a coin locked to the hash of those 65 bytes, and the signature that spends it
          locked = Just (TxOut value (hex "76a914db71dd1ddf9d451854b7ec1bdba7ba5e317da0ba88ac"))
          sig =
            hex
              "3044022048cf36bd41def24e245932e5546cb6b379875b7bdf50001bbd7aef3a\
              \95296c8b022014cc18d596e34a5832971472930ecd76a7b10457ddda46d474f6\
              \c6a9f305c7a501"
          spend = spending (pushing [sig, hybrid]) []
      judgeInputs btc spend [locked] `shouldBe` [InputUndecided]
      judgeInputs btc (tampered spend) [locked] `shouldBe` [InputForged]

  -- BIP 141: the last item of the witness is the witness script, and
  -- "SHA256 of the witnessScript must match the 32-byte witness program" of
  -- the coin. A multisig script has other spellings with the same keys:
  -- each key after OP_PUSHDATA1 and its length. They are other bytes, with
  -- another hash. The witness is not part of the transaction id, so anyone
  -- can make that copy of a spend seen on the network, without a key. The
  -- signatures stay as they are. The four spends below went to
  -- Bitcoin Core 32.1 on regtest. It mined the two with the script of the
  -- coin. It refused the two others, in a block too: "Witness program hash
  -- mismatch".
  describe "verifyStdTx and judgeInputs on the witness script of a multisig" $ do
    let -- two signatures of three keys, each key after the push of its 0x21 = 33 bytes
        committed =
          hex
            "5221031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5\
            \dd078f21024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451\
            \a7254d07662102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3\
            \c5bdbdcb1fe33753ae"
        -- the same script with OP_PUSHDATA1 before the length of each key: 0x4c 0x21
        respelled =
          hex
            "524c21031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9\
            \d5dd078f4c21024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374\
            \c451a7254d07664c2102531fe6068134503d2723133227c867ac8fa6c83c537e\
            \9a44c3c5bdbdcb1fe33753ae"
        -- the script of a coin locked to the committed script: version 0 and its SHA-256
        native = hex "002063ae81f48889f3ebcce92fc39fbb9fe63e409780e0855ec83a4fd3fbabdb1d97"
        -- the script of a coin locked to the hash of those 34 bytes, which its spend pushes
        nested = hex "a914564d22ea4f58d584581a583a1c166b3bac576c9387"
        nativeSigs =
          [ hex
              "3045022100ed7967e9c66f5d5a564fbcc29f50665bcbd32ce570e60745fdad78\
              \4624f4fe280220162ab62660b642ff8eba5ab63d35b2364c5a231bb86323c01e\
              \f1c72649bbebf601",
            hex
              "304402200f50fde78f7e99ed7e3e62e8daeaba614906874e97badc436611e9bb\
              \e36b968302205091d9399745a5bc6c195521bab9db4176dc629589e914310946\
              \871a363fac3d01"
          ]
        nestedSigs =
          [ hex
              "3045022100f89c908335723920c0a73d9a64f15d84870b2b210c08d17932eb76\
              \08838a49fc02205942d6ddb90f463c0a14f02ba50fb54722d88f54163e05289c\
              \bcfd9fd8162e9101",
            hex
              "3045022100b2968abc569b51be887d7232a39809c7fc89ff85217b5a4fb51f25\
              \7328f03a2202201866428e3a11412b028f344aa31aa529c50749c25357213ddd\
              \4041db6409530001"
          ]
        funding = "718e60722e5e95b5d5e8b51c7b127d7a4abe13c7d3b3dc39a3329f6dd2e025ec"
        -- The spend of an output of the funding transaction, a coin of
        -- 1,000,000: it pays 998,000, and its witness is the empty item of
        -- a multisig, the signatures and the witness script.
        spend n inputScript sigs witnessScript =
          Tx
            { version = 2,
              inputs = [TxIn (OutPoint funding n) inputScript maxBound],
              outputs = [TxOut 998000 (hex "001479b000887626b294a914501a4cd226b58b235983")],
              witness = [[""] <> sigs <> [witnessScript]],
              locktime = 0
            }
        spendNative = spend 0 "" nativeSigs
        spendNested = spend 1 (pushing [native]) nestedSigs
        -- the answers of 'verifyStdTx' and of 'judgeInputs' for the spend of a coin
        verdicts locked tx =
          ( verifyStdTx btc tx [(either error id (decodeSerial locked), 1000000, (head tx.inputs).outpoint)],
            judgeInputs btc tx [Just (TxOut 1000000 locked)]
          )
    it "verify the spend whose witness script is the one the coin commits to, native and nested" $ do
      verdicts native (spendNative committed) `shouldBe` (True, [InputVerified])
      verdicts nested (spendNested committed) `shouldBe` (True, [InputVerified])
    it "do not verify the spend whose witness script has the same keys in other bytes" $ do
      verdicts native (spendNative respelled) `shouldBe` (False, [InputUndecided])
      verdicts nested (spendNested respelled) `shouldBe` (False, [InputUndecided])
    it "the transaction id is the same with either witness script" $ do
      txHash (spendNative committed) `shouldBe` "839c20e76404a63c13f52ba1d0315a021da94d2bf1db35b6cdd87e0a0c184849"
      txHash (spendNative respelled) `shouldBe` "839c20e76404a63c13f52ba1d0315a021da94d2bf1db35b6cdd87e0a0c184849"
      txHash (spendNested committed) `shouldBe` "ef83742b3c751f249a87c7bd3c1b67b4c31178f0717ce34db4267822e68ed530"
      txHash (spendNested respelled) `shouldBe` "ef83742b3c751f249a87c7bd3c1b67b4c31178f0717ce34db4267822e68ed530"

  describe "judgeInputs on Bitcoin Cash" $ do
    let unsigned = spending "" []
        digest prefix = txSigHashCashToken bch unsigned prefix pkhScript value 0 (setForkIdFlag sigHashAll)
        tokens = B.singleton 0xef <> B.replicate 32 0xaa <> B.pack [0x10, 0xfd, 0xe8, 0x03]
    it "reads a Schnorr signature" $ do
      let sig = cashSchnorr k (either error id (digest "")) <> B.singleton 0x41
      B.length sig `shouldBe` 65
      three bch (spending (pushing [sig, pub]) []) (prev (PayPKHash h160))
    it "reads an ECDSA signature" $
      three bch (spending (pushing [ecdsa k 0x41 (digest ""), pub]) []) (prev (PayPKHash h160))
    it "reads a coin that holds tokens, whose digest covers them" $ do
      let withTokens = Just (TxOut value (tokens <> encodeSerial (PayPKHash h160)))
      three bch (spending (pushing [ecdsa k 0x41 (digest tokens), pub]) []) withTokens
      three bch (spending (pushing [cashSchnorr k (either error id (digest tokens)) <> "\x41", pub]) []) withTokens
      -- signed as if the coin held none: not a signature of this coin
      judgeInputs bch (spending (pushing [ecdsa k 0x41 (digest ""), pub]) []) [withTokens]
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
      judgeInputs bchRegTest genesis [Just coinbase] `shouldBe` [InputVerified]
      judgeInputs bchRegTest (tampered genesis) [Just coinbase] `shouldBe` [InputForged]
    it "verifies its Schnorr signature of a coin that holds tokens" $ do
      let held = head genesis.outputs
      fmap fst (splitTokenPrefix held.script) `shouldSatisfy` maybe False (not . B.null)
      judgeInputs bchRegTest spend [Just held] `shouldBe` [InputVerified]
      judgeInputs bchRegTest (tampered spend) [Just held] `shouldBe` [InputForged]
      -- the same coin without its tokens is another coin
      let bare = held {script = maybe held.script snd (splitTokenPrefix held.script)} :: TxOut
      judgeInputs bchRegTest spend [Just bare] `shouldBe` [InputForged]

  describe "judgeInputs on a multisig of Bitcoin Cash signed with Schnorr signatures" $ do
    let secrets = map secret [11, 12, 13]
        keys = map (wrapPubKey True . derivePubKey) secrets
        twoOfThree = PayMulSig keys 2
        redeem = encodeSerial twoOfThree
        locked = prev (PayScriptHash (addressHash redeem))
        code = either error id (encodeOutput twoOfThree)
        digest = either error id (txSigHashForkId bch (spending "" []) code value 0 (setForkIdFlag sigHashAll))
        sign s = cashSchnorr s digest <> B.singleton 0x41
        -- the field of bits is a small number, pushed by its own opcode
        spendWith bits sigs =
          spending (runPutS (serialize (Script ([bits] <> map opPushData (sigs <> [redeem]))))) []
        verdict tx = judgeInputs bch tx [locked]
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
      let ecdsaSig = ecdsa (head secrets) 0x41 (Right digest)
      verdict (spendWith OP_5 [ecdsaSig, sign (secrets !! 2)]) `shouldBe` [InputUndecided]

  describe "verifyStdInput on a multisig of Taproot" $ do
    let xOnly = B.drop 1 . pubBytes
        internal = derivePubKey (secret 14)
        unsigned = spending "" []
        -- A coin of one leaf, the multisig of the keys of these secrets
        -- that asks for this number of signatures: its tree, its output,
        -- the signature of a secret over the spend of the leaf, and that
        -- spend with these witness items.
        multisigCoin asked keys = (tree, out, sign, spendWith)
          where
            leaf =
              Script $
                [opPushData (xOnly (head keys)), OP_CHECKSIG]
                  <> concat [[opPushData (xOnly s), OP_CHECKSIGADD] | s <- drop 1 keys]
                  <> [asked, OP_NUMEQUAL]
            tree = TaprootOutput {internalKey = internal, mast = Just (MASTLeaf tapscriptLeafVersion leaf)}
            out = TxOut value (encodeSerial (taprootScriptOutput tree))
            leafOf = Just (leafHash tapscriptLeafVersion leaf, 0xffffffff)
            digest = either error id (taprootSigHash unsigned [out] 0 sigHashDefault Nothing leafOf)
            sign s = (signSchnorr s (hashToMsg digest)).get
            spendWith items =
              let path =
                    ScriptPathSpend
                      ScriptPathData
                        { annex = Nothing,
                          stack = items,
                          script = leaf,
                          extIsOdd = odd (keyParity (taprootOutputKey tree)),
                          leafVersion = tapscriptLeafVersion,
                          internalKey = internal,
                          control = [],
                          opaqueScript = Nothing
                        }
               in unsigned {witness = [either error id (encodeTaprootWitness path)]} :: Tx
        secrets = map secret [11, 12, 13]
        (tree, out, sign, spendWith) = multisigCoin OP_2 secrets
        verdict tx = judgeInputs btc tx [Just out]
        -- The spend of a leaf that asks for one signature of this many
        -- keys, signed by the first key: an empty item for each other key,
        -- then the signature. The answers of 'verifyStdInput' and of
        -- 'judgeInputs' for it.
        oneOf count = (verifyStdInput btc spend [(taprootScriptOutput bigTree, value, coin)] 0, verdictOf)
          where
            keys = map secret [1001 .. 1000 + count]
            (bigTree, bigOut, bigSign, bigSpend) = multisigCoin OP_1 keys
            spend = bigSpend (replicate (fromIntegral count - 1) "" <> [bigSign (secret 1001)])
            verdictOf = judgeInputs btc spend [Just bigOut]
    it "verifies two signatures of three keys, with an item for each key, the last first" $ do
      verdict (spendWith [sign (secrets !! 2), "", sign (head secrets)]) `shouldBe` [InputVerified]
      verdict (spendWith ["", sign (secrets !! 1), sign (head secrets)]) `shouldBe` [InputVerified]
      let lastTwo = spendWith [sign (secrets !! 2), sign (secrets !! 1), ""]
      verifyStdInput btc lastTwo [(taprootScriptOutput tree, value, coin)] 0 `shouldBe` True
    it "does not verify one signature, three, a signature of another key, or one of other outputs" $ do
      verdict (spendWith ["", "", sign (head secrets)]) `shouldBe` [InputUndecided]
      verdict (spendWith [sign (secrets !! 2), sign (secrets !! 1), sign (head secrets)]) `shouldBe` [InputUndecided]
      -- the signature of the first key where that of the third goes
      verdict (spendWith [sign (head secrets), "", sign (head secrets)]) `shouldBe` [InputUndecided]
      verdict (tampered (spendWith [sign (secrets !! 2), "", sign (head secrets)])) `shouldBe` [InputUndecided]
      -- an item for a key is missing
      verdict (spendWith [sign (secrets !! 1), sign (head secrets)]) `shouldBe` [InputUndecided]
    -- The stack holds at most 1000 items after each opcode (BIP 342). The
    -- witness puts an item there for each key, and the script first pushes
    -- a key on top of them: 999 + 1 = 1000.
    it "verifies a leaf of 999 keys, the most that a block can hold" $
      oneOf 999 `shouldBe` (True, [InputVerified])
    -- 1000 + 1 = 1001 items. Bitcoin Core 32.1 refuses the spend in a
    -- block: "Stack size limit exceeded".
    it "does not verify a leaf of 1000 keys, whose signature is good: no block can hold its spend" $
      oneOf 1000 `shouldBe` (False, [InputUndecided])

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
      forAll (elements [btc, bch] >>= \net -> (,) net <$> arbitrarySigningData net) $ \(net, (tx, sigis, keys)) ->
        case signTx net tx sigis (map (.key) keys) of
          Left _ -> property True
          Right signed ->
            let prevOf i = lookup i.outpoint [(s.outpoint, TxOut s.value (encodeSerial s.script)) | s <- sigis]
                verdicts = judgeInputs net signed (map prevOf signed.inputs)
                coins = [(s.script, s.value, s.outpoint) | s <- sigis]
             in counterexample (show verdicts) $
                  InputForged `notElem` verdicts
                    && (not (verifyStdTx net signed coins) || all (== InputVerified) verdicts)
