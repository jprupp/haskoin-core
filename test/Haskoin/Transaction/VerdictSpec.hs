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

-- | The transaction of these bytes.
txOf :: Text -> Tx
txOf = either error id . runGetS deserialize . hex

-- | The answer of 'judgeInputs' for a transaction whose one input spends a
-- coin of 1,000,000 with this script.
judged :: Network -> ByteString -> Tx -> [InputVerdict]
judged net locked tx = judgeInputs net tx [Just (TxOut 1000000 locked)]

-- | The answers of 'verifyStdTx' and of 'judgeInputs' for such a
-- transaction. The script of the coin must be a standard output.
verdicts :: Network -> ByteString -> Tx -> (Bool, [InputVerdict])
verdicts net locked = verdictsOf net [locked]

-- | The same answers for a transaction of several inputs, which spend coins
-- of 1,000,000 with these scripts, in order.
verdictsOf :: Network -> [ByteString] -> Tx -> (Bool, [InputVerdict])
verdictsOf net locked tx =
  ( verifyStdTx net tx [(either error id (decodeSerial l), 1000000, i.outpoint) | (l, i) <- zip locked tx.inputs],
    judgeInputs net tx [Just (TxOut 1000000 l) | l <- locked]
  )

-- | Every signed transaction with one input in this spelling gets these
-- three answers: that of 'verifyStdTx', the verdict of 'judgeInputs' on that
-- input, and whether it says verified of every other input, which are as
-- the signer wrote them. 'verifyStdTx' gets every coin that it can take: a
-- script that is no standard output cannot be given to it.
answersFor :: Network -> Spelling -> (Bool, InputVerdict, Bool) -> Property
answersFor net spelling expected =
  forAll (arbitraryRespelled net spelling) $ \r -> answers r === expected
  where
    answers r = case splitAt r.index (judgeInputs net r.tx (map Just r.coins)) of
      (before, verdict : after) ->
        (verifyStdTx net r.tx (coinsOf r), verdict, all (== InputVerified) (before <> after))
      _ -> error "answersFor: no verdict for the input"
    coinsOf r = [(so, c.value, i.outpoint) | (c, i) <- zip r.coins r.tx.inputs, Right so <- [decodeSerial c.script]]

-- | A multisig script: two signatures of three keys, each key after the
-- push of its 0x21 = 33 bytes.
directPushes :: ByteString
directPushes =
  hex
    "5221031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5\
    \dd078f21024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451\
    \a7254d07662102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3\
    \c5bdbdcb1fe33753ae"

-- | The same script with OP_PUSHDATA1 before the length of each key: 0x4c
-- 0x21.
longPushes :: ByteString
longPushes =
  hex
    "524c21031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9\
    \d5dd078f4c21024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374\
    \c451a7254d07664c2102531fe6068134503d2723133227c867ac8fa6c83c537e\
    \9a44c3c5bdbdcb1fe33753ae"

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
    -- No key hashes to the hash that the coin names but its key, so the
    -- script fails before the signature is looked at.
    it "says forged of an empty item where the key goes, pushed by OP_0" $ do
      let unsigned = spending "" []
          sig = ecdsa k 0x01 (txSigHash btc unsigned pkhScript value 0 sigHashAll)
          inputScript = runPutS (serialize (Script [opPushData sig, OP_0]))
      judgeInputs btc (spending inputScript []) [prev (PayPKHash h160)] `shouldBe` [InputForged]
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
    let -- the script whose hash the coins hold, and its other spelling
        committed = directPushes
        respelled = longPushes
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
    it "verify the spend whose witness script is the one the coin commits to, native and nested" $ do
      verdicts btc native (spendNative committed) `shouldBe` (True, [InputVerified])
      verdicts btc nested (spendNested committed) `shouldBe` (True, [InputVerified])
    it "do not verify the spend whose witness script has the same keys in other bytes" $ do
      verdicts btc native (spendNative respelled) `shouldBe` (False, [InputUndecided])
      verdicts btc nested (spendNested respelled) `shouldBe` (False, [InputUndecided])
    it "the transaction id is the same with either witness script" $ do
      txHash (spendNative committed) `shouldBe` "839c20e76404a63c13f52ba1d0315a021da94d2bf1db35b6cdd87e0a0c184849"
      txHash (spendNative respelled) `shouldBe` "839c20e76404a63c13f52ba1d0315a021da94d2bf1db35b6cdd87e0a0c184849"
      txHash (spendNested committed) `shouldBe` "ef83742b3c751f249a87c7bd3c1b67b4c31178f0717ce34db4267822e68ed530"
      txHash (spendNested respelled) `shouldBe` "ef83742b3c751f249a87c7bd3c1b67b4c31178f0717ce34db4267822e68ed530"

  -- The signature of a multisig input covers the bytes of the script of its
  -- coin. A coin can be locked to a multisig script whose keys are pushed
  -- by OP_PUSHDATA1: a signature over the script with direct pushes does
  -- not open it. A 'ScriptOutput' has no place for the form of a push, so
  -- such a script is not read as a multisig, and its spend is left to a
  -- node. The spends below went to a node on regtest. Each coin holds
  -- 1,000,000.
  describe "judgeInputs on a multisig coin whose keys are not direct pushes, on Bitcoin" $ do
    -- Three spends of outputs of one transaction, each with two signatures,
    -- as Bitcoin Core 32.1 judged them.
    it "verifies the spend of the coin with direct pushes, which the node mined" $
      verdicts
        btc
        directPushes
        ( txOf
            "0200000001ec25e0d26d9f32a339dcb3d3c713be4a7a7d127b1cb5e8d5b5955e\
            \2e72608e71060000009300483045022100a5387c1620665c031ce80a104208f6\
            \26374a0781027150f14eb64634b04ec72b022041ffaaf22514397786df9b2b68\
            \661fdea31c817631279b08e020f8b20362346701483045022100a92973c2d2fe\
            \b0879cbc3087b19ed14e28a30317e8a5762da9745aaa3b911a8602207d379d91\
            \88205de7b9716dcad08808a1cf6f878e503100fd5abd265ae3a4641401ffffff\
            \ff01703a0f000000000016001479b000887626b294a914501a4cd226b58b2359\
            \8300000000"
        )
        `shouldBe` (True, [InputVerified])
    -- The node refused it in a block: "Script evaluated without error but
    -- finished with a false/empty top stack element".
    it "leaves to a node a spend signed over the script with direct pushes, which no block holds" $
      judged
        btc
        longPushes
        ( txOf
            "0200000001ec25e0d26d9f32a339dcb3d3c713be4a7a7d127b1cb5e8d5b5955e\
            \2e72608e71020000009300483045022100e88795128ae0b9b6d40c214ec18db0\
            \af30f8e767d56aa310a833453ffd8756eb02202824216c8d9970a0e87410a68e\
            \16a016a399f3c96fee7ce55f1060a4bb7685ed014830450221009353260467d9\
            \ed68eb8f410a5a20320fcfed9409720649ab1614366d929e6ad002207fa39e2c\
            \96d486e4434f82a19bb0bcfcea387e42ea1352eef5483668319307db01ffffff\
            \ff01703a0f000000000016001479b000887626b294a914501a4cd226b58b2359\
            \8300000000"
        )
        `shouldBe` [InputUndecided]
    -- The node took it in a block, and refused to relay it: "Data push
    -- larger than necessary".
    it "leaves to a node a spend signed over the script of the coin, which a block may hold" $
      judged
        btc
        longPushes
        ( txOf
            "0200000001ec25e0d26d9f32a339dcb3d3c713be4a7a7d127b1cb5e8d5b5955e\
            \2e72608e7102000000910047304402207470ee65b26aa2d695dd8600a1855b7b\
            \2a7a5c9fb0aff53c30468a7ac984ae3f02207bc27899ce27a2dcd083d5206ed2\
            \93335f6bef709c165a5cb317eba7954bdd3801473044022023a558b88ac8809c\
            \5a33000ec7b017b6cf52878bb1bca227dec708ae8cfe6d2302200aa7dd56cf11\
            \bd84894d140f4db2c055de9b13f01b19e7eb0ca571df11ed784801ffffffff01\
            \703a0f000000000016001479b000887626b294a914501a4cd226b58b23598300\
            \000000"
        )
        `shouldBe` [InputUndecided]

  -- On Bitcoin Cash every push must be the shortest one, in a block too. A
  -- coin whose script pushes its keys by OP_PUSHDATA1 can never be spent:
  -- Bitcoin Cash Node 29.2.0 refused each of these spends in a block, "Data
  -- push larger than necessary", and drops the peer that sends one.
  describe "judgeInputs on a multisig coin whose keys are not direct pushes, on Bitcoin Cash" $ do
    let -- two signatures of three keys, each key after the push of its 0x21 = 33 bytes
        direct =
          hex
            "522103bed082a6f8b35a9ac543ddc156457e7a1fb5d7137e4c5386ec562faaff\
            \3a35ca2102136dcd2e55f06b38331491ccc9768f0d4f77dc956b64384d431c6a\
            \1c6986615821021d1e6f9a58d67a27fe816ce13bec19c3bdd826af44ed65cc46\
            \e75b8314782bef53ae"
        -- the same script with OP_PUSHDATA1 before the length of each key: 0x4c 0x21
        long =
          hex
            "524c2103bed082a6f8b35a9ac543ddc156457e7a1fb5d7137e4c5386ec562faa\
            \ff3a35ca4c2102136dcd2e55f06b38331491ccc9768f0d4f77dc956b64384d43\
            \1c6a1c698661584c21021d1e6f9a58d67a27fe816ce13bec19c3bdd826af44ed\
            \65cc46e75b8314782bef53ae"
        -- the scripts of the coins locked to the hash of each of the two scripts
        hashOfDirect = hex "a914a693c2298e10413786f327a0520cf62bf1653ab887"
        hashOfLong = hex "a9143f449a91b806d6829814e309a919369b1446a71987"
    it "verifies the spends of the coins with direct pushes, which the node mined" $ do
      -- ECDSA signatures, of the bare coin
      verdicts
        bchRegTest
        direct
        ( txOf
            "02000000012f3a23a55f10c78a8ee83e665cbdc7b3a1cf2815ff2e67a661bf4e\
            \dc778fa63c0300000092004830450221008f7f827d134d4cb2e0205997dd838b\
            \72f6d6fffe657fa0473c725ba9c4ce9ffa02201ae06e89fe8aa760b882904448\
            \be6f38d2001e9f01d6ede050182a7706a8bd6941473044022049831b15326b0f\
            \ef2e1fea8115b51d457c2bdac599fababd95f7e25136888c2702201ca9878c61\
            \01d926d6590b776874b70bc6502220b0b072c761ee3dd1cf446d1441ffffffff\
            \01703a0f00000000001976a91471b6ade29bcdff95817522a958176e1a10a65d\
            \bf88ac00000000"
        )
        `shouldBe` (True, [InputVerified])
      -- Schnorr signatures, of the coin locked to the hash of the script
      judged
        bchRegTest
        hashOfDirect
        ( txOf
            "02000000012f3a23a55f10c78a8ee83e665cbdc7b3a1cf2815ff2e67a661bf4e\
            \dc778fa63c02000000f0534184d3472649c647ab263caccefb7f5f73e2b01a81\
            \378defc71e24aad0d0a114449b09ba4ec67cdd4615d077df229f4e30abbb5370\
            \bdb1ac1e2a37382199aac6064141e408d335002105856d9d10e4d6715923f212\
            \628e3aead2b576e643ab1ecd373a5cf0228c91bb6ec811f77ec0918bd6e05235\
            \e025227fd5bb8154019acc71b9f1414c69522103bed082a6f8b35a9ac543ddc1\
            \56457e7a1fb5d7137e4c5386ec562faaff3a35ca2102136dcd2e55f06b383314\
            \91ccc9768f0d4f77dc956b64384d431c6a1c6986615821021d1e6f9a58d67a27\
            \fe816ce13bec19c3bdd826af44ed65cc46e75b8314782bef53aeffffffff0170\
            \3a0f00000000001976a91471b6ade29bcdff95817522a958176e1a10a65dbf88\
            \ac00000000"
        )
        `shouldBe` [InputVerified]
    it "leaves to a node a spend of the bare coin with ECDSA signatures over the script with direct pushes" $
      judged
        bchRegTest
        long
        ( txOf
            "02000000012f3a23a55f10c78a8ee83e665cbdc7b3a1cf2815ff2e67a661bf4e\
            \dc778fa63c00000000910047304402206e1f326182c3958f2431249f8b20ef02\
            \2bdbf522543fb9250d153495deda45b1022058566b3cb6e3ea0d58031e811178\
            \1d5f84a0287165f73122338c499800480fa94147304402205647841b5b7406a5\
            \5e4a791ab5388608d09c3adb962ca6bd44c2c71a4262b5bc02206ebaab455b02\
            \e3c52653cae4c43a0e5cc36a149354b3fd5f66c7b25c96ebd7d141ffffffff01\
            \703a0f00000000001976a91471b6ade29bcdff95817522a958176e1a10a65dbf\
            \88ac00000000"
        )
        `shouldBe` [InputUndecided]
    it "leaves to a node a spend of the bare coin with Schnorr signatures over the script with direct pushes" $
      judged
        bchRegTest
        long
        ( txOf
            "02000000012f3a23a55f10c78a8ee83e665cbdc7b3a1cf2815ff2e67a661bf4e\
            \dc778fa63c00000000855341507484b8ba32cb475c439383248cb9b5e911454e\
            \bc9f009675dcec9a76f12e2ffd034897bd7b45adc70a49f455abfa05d46e5e0f\
            \602a950e4b8419edd4708c154141277f382eeca3e93a8ef0ca54ead15ea2d351\
            \34cb2c0466df1993f328b1933d40c3a548d4efb9b3ed840b2fdfb58240ef9cda\
            \982baebc9d3764ac6606ec08409d41ffffffff01703a0f00000000001976a914\
            \71b6ade29bcdff95817522a958176e1a10a65dbf88ac00000000"
        )
        `shouldBe` [InputUndecided]
    it "leaves to a node such a spend of the coin locked to the hash of the script" $
      judged
        bchRegTest
        hashOfLong
        ( txOf
            "02000000012f3a23a55f10c78a8ee83e665cbdc7b3a1cf2815ff2e67a661bf4e\
            \dc778fa63c01000000f35341c867eaec03b91941010cda272a0745f944e9d7f8\
            \7904232eacd59012db39b35be264e5bfedc52e802cb3ce39620ec1d28500b68f\
            \1b8235210c0c8cf985ba9d414141b089c593e1b3152a04a280ea50402523017e\
            \2b725ba3da7d32c91cf8fb34ab75a676957d280bfeabf17f3bb18e501381b785\
            \5be35fe62495194643e61caf9ebe414c6c524c2103bed082a6f8b35a9ac543dd\
            \c156457e7a1fb5d7137e4c5386ec562faaff3a35ca4c2102136dcd2e55f06b38\
            \331491ccc9768f0d4f77dc956b64384d431c6a1c698661584c21021d1e6f9a58\
            \d67a27fe816ce13bec19c3bdd826af44ed65cc46e75b8314782bef53aeffffff\
            \ff01703a0f00000000001976a91471b6ade29bcdff95817522a958176e1a10a6\
            \5dbf88ac00000000"
        )
        `shouldBe` [InputUndecided]

  -- Bitcoin Cash applies to every block three rules of encoding that Bitcoin
  -- applies only to what it relays: the S of an ECDSA signature is low
  -- (LOW_S), a key is compressed or uncompressed (STRICTENC), and data is
  -- pushed by the shortest push that holds it (MINIMALDATA). Each
  -- transaction below went to Bitcoin Cash Node 29.2.0 on regtest. Its first
  -- input is a plain spend, and its second input is the one that the test
  -- is about. The node took the transactions that keep the three rules. It
  -- refused each other one with "mandatory-script-verify-flag-failed", the
  -- reason for which it drops the peer that sent the transaction.
  describe "verifyStdTx and judgeInputs on what no block of Bitcoin Cash holds" $ do
    let -- the script of the coin of the first input, locked to a key hash
        first = hex "76a914670caa79e51d78ed0c583b89ff39d9c49b7199e788ac"
        -- the coin of the second input, locked to the hash of the key 02552c63...2a84
        keyHash = hex "76a914db3f00d429f2715383cc594258ec11d6de52669788ac"
        -- a transaction up to the input script of its second input, which
        -- spends the coin locked to the key hash
        start =
          "0200000002bd30e74505225b6e250d6254e743c9375329f1ec140c0f330c2a81\
          \fe77493ab60f0000006b483045022100df1a1c4bef63f9d732768d57b3cd690b\
          \6d343029b41fe88f5d19f251338face902201661eaffaf61e3a60c055d736289\
          \60ae09346c5f77e38c415a59e7812c0e28b041210256b328b30c8bf5839e2405\
          \8747879408bdb36241dc9c2e7c619faa12b2920967fdffffffbd30e74505225b\
          \6e250d6254e743c9375329f1ec140c0f330c2a81fe77493ab603000000"
        -- what follows that input script: the sequence, two outputs and the lock time
        end =
          "fdffffff02a0bb0d00000000001976a91479b000887626b294a914501a4cd226\
          \b58b23598388acc07a1000000000001976a914ebc0ee0b2ab9e8277a600c2514\
          \75e22a3241a1c188ac00000000"
        -- the answers for the transaction whose second input has this
        -- script, written after its length
        spend script = verdictsOf bchRegTest [first, keyHash] (txOf (start <> script <> end))
    it "verify the spends that keep the three rules, which the node took" $ do
      -- an ECDSA signature after the push of its 0x48 = 72 bytes, then the
      -- key after the push of its 0x21 = 33 bytes
      spend
        "6b483045022100fe866c7d7a79393c11175ad82fc8de9350f31a11394a827fcb\
        \bf66ea1d2cf0b302204ed891157ee41a89f5a4c23fe3e4fc2f1cd1498d4e5ec3\
        \75029f6f849e137f4e412102552c630b64b54bf50210c9e253d38bd4949c72e2\
        \2873500f6285c2bede312a84"
        `shouldBe` (True, [InputVerified, InputVerified])
      -- a Schnorr signature after the push of its 0x41 = 65 bytes, which
      -- 'verifyStdTx' does not read
      spend
        "64412eafe74e802f469cb0fcbdbbe31884691f205a1a56b2d93b36d779323f47\
        \05cc25358fda1954d7b9f39a5f4221f6d08850b2b799ebfd0abdcb1f44ce0cea\
        \a70b412102552c630b64b54bf50210c9e253d38bd4949c72e22873500f6285c2\
        \bede312a84"
        `shouldBe` (False, [InputVerified, InputVerified])
    it "do not verify an ECDSA signature with a high S" $
      -- the first signature above with n - S for S, n being the order of
      -- the curve: n - 4ed89115...9e137f4e = b1276eea...3222c1f3
      spend
        "6c493046022100fe866c7d7a79393c11175ad82fc8de9350f31a11394a827fcb\
        \bf66ea1d2cf0b3022100b1276eea811be5760a5b3dc01c1b03cf9ddd935960e9\
        \dcc6bd32ef083222c1f3412102552c630b64b54bf50210c9e253d38bd4949c72\
        \e22873500f6285c2bede312a84"
        `shouldBe` (False, [InputVerified, InputUndecided])
    it "do not verify a key in the hybrid form" $
      -- The second input spends a coin locked to the hash of the same key
      -- written with both coordinates after 0x06, and its signature is
      -- good.
      verdictsOf
        bchRegTest
        [first, hex "76a9143f20fee78bcb773cf5be7ee3f12e7ffc340830c788ac"]
        ( txOf
            "0200000002bd30e74505225b6e250d6254e743c9375329f1ec140c0f330c2a81\
            \fe77493ab60f0000006b483045022100c3d639833017a65fa7bed3a3cd7f9c85\
            \c60cc0f55a70d84719bc9e8fda30bde9022078aee3f447ed47044c7947b62619\
            \b05b61f6128b1abd9687f2de29b04ed0ba5f41210256b328b30c8bf5839e2405\
            \8747879408bdb36241dc9c2e7c619faa12b2920967fdffffffbd30e74505225b\
            \6e250d6254e743c9375329f1ec140c0f330c2a81fe77493ab60d0000008b4830\
            \45022100c151bff7da6ba95495aacb8ff59e2c6b7b49764121ae559e11242713\
            \d29b5b5c022029eafd90bc648920c18f6ecbc4678e3a6f5214e9a0774cda0beb\
            \827cb6905c91414106552c630b64b54bf50210c9e253d38bd4949c72e2287350\
            \0f6285c2bede312a84e3ca35a0c8c0cf4c40398e720377e1ee09c7a6b0fd0568\
            \3d5fe02d8f68231466fdffffff02a0bb0d00000000001976a91479b000887626\
            \b294a914501a4cd226b58b23598388acc07a1000000000001976a914ebc0ee0b\
            \2ab9e8277a600c251475e22a3241a1c188ac00000000"
        )
        `shouldBe` (False, [InputVerified, InputUndecided])
    it "do not verify a key or an ECDSA signature that is not pushed by the shortest push" $ do
      -- the valid spend with OP_PUSHDATA1 before the length of the key: 0x4c 0x21
      spend
        "6c483045022100fe866c7d7a79393c11175ad82fc8de9350f31a11394a827fcb\
        \bf66ea1d2cf0b302204ed891157ee41a89f5a4c23fe3e4fc2f1cd1498d4e5ec3\
        \75029f6f849e137f4e414c2102552c630b64b54bf50210c9e253d38bd4949c72\
        \e22873500f6285c2bede312a84"
        `shouldBe` (False, [InputVerified, InputUndecided])
      -- the valid spend with OP_PUSHDATA2 before the length of the signature: 0x4d 0x48 0x00
      spend
        "6d4d48003045022100fe866c7d7a79393c11175ad82fc8de9350f31a11394a82\
        \7fcbbf66ea1d2cf0b302204ed891157ee41a89f5a4c23fe3e4fc2f1cd1498d4e\
        \5ec375029f6f849e137f4e412102552c630b64b54bf50210c9e253d38bd4949c\
        \72e22873500f6285c2bede312a84"
        `shouldBe` (False, [InputVerified, InputUndecided])
    it "do not verify a Schnorr signature that is not pushed by the shortest push" $
      -- the valid spend with OP_PUSHDATA4 before the length of the signature: 0x4e 0x41 0x00 0x00 0x00
      spend
        "684e410000002eafe74e802f469cb0fcbdbbe31884691f205a1a56b2d93b36d7\
        \79323f4705cc25358fda1954d7b9f39a5f4221f6d08850b2b799ebfd0abdcb1f\
        \44ce0ceaa70b412102552c630b64b54bf50210c9e253d38bd4949c72e2287350\
        \0f6285c2bede312a84"
        `shouldBe` (False, [InputVerified, InputUndecided])
    it "do not verify a multisig with Schnorr signatures whose field of bits is not pushed by its opcode" $ do
      let -- the coin of the second input: two signatures of three keys
          twoOfThree =
            hex
              "522102552c630b64b54bf50210c9e253d38bd4949c72e22873500f6285c2bede\
              \312a8421030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d\
              \67d412d17721022f1b310f4c065331bc0d79ba4661bb9822d67d7c4a1b0a1892\
              \e1fd0cd23aa68d53ae"
          -- a transaction up to the input script of its second input,
          -- which spends that coin
          startOfMultisig =
            "0200000002bd30e74505225b6e250d6254e743c9375329f1ec140c0f330c2a81\
            \fe77493ab60f0000006a47304402207b92790f3145f2c30048db725e7e184d0f\
            \56e2d921ec5d7548118e8bb75e4c9b022026f590f98b3d50c6fe8c4e19ef62c5\
            \4160813fb917b5d03b2c7419a5165fab7d41210256b328b30c8bf5839e240587\
            \47879408bdb36241dc9c2e7c619faa12b2920967fdffffffbd30e74505225b6e\
            \250d6254e743c9375329f1ec140c0f330c2a81fe77493ab606000000"
          spendOfMultisig script =
            verdictsOf bchRegTest [first, twoOfThree] (txOf (startOfMultisig <> script <> end))
      -- The bits 0b011 name the first two keys. The node took them as
      -- OP_3, the byte 0x53, before the two signatures.
      spendOfMultisig
        "85534189ad1a4e4571427393606bf673906fcd23b34b272565c61c402b02f3bf\
        \0f70391154fb060bc776c427772c1ec7379f3c31b14171bcdc978867887acbba\
        \3d5dbb4141f77f97c4a106af0a26e39a0dd7cb740ba1e0c2bc90cddb70adc18c\
        \89b1969f0a5f0c4e02f0182b3c2c816d11bfb0568b1381d22e1c308fa5d081b7\
        \f44543351b41"
        `shouldBe` (False, [InputVerified, InputVerified])
      -- the same bits as one byte of data after OP_PUSHDATA1: 0x4c 0x01 0x03
      spendOfMultisig
        "874c01034189ad1a4e4571427393606bf673906fcd23b34b272565c61c402b02\
        \f3bf0f70391154fb060bc776c427772c1ec7379f3c31b14171bcdc978867887a\
        \cbba3d5dbb4141f77f97c4a106af0a26e39a0dd7cb740ba1e0c2bc90cddb70ad\
        \c18c89b1969f0a5f0c4e02f0182b3c2c816d11bfb0568b1381d22e1c308fa5d0\
        \81b7f44543351b41"
        `shouldBe` (False, [InputVerified, InputUndecided])
    -- The second input spends a coin locked to the hash of a script that
    -- asks for two signatures of eight keys. The first and the last key
    -- sign, so the bits are 0b10000001, the byte 0x81.
    describe "a multisig with Schnorr signatures whose field of bits is 0x81" $ do
      let twoOfEight = hex "a914cc42e7ae705e45609df7c35f91739beb07503a9a87"
          -- a transaction up to the input script of its second input
          startOfEight =
            "020000000297840471ad17d047f8eaeea6be46191efe4b06de6ff022bfe7531b\
            \75539f49a3100000006b483045022100c716c53177583c6cba7d5821e4cc5efb\
            \a9f55f5b8bdad8dd841687449318cf2f0220160b350f4c8ff8dec0470624947a\
            \d71ac8d6cbfc12930ba49df8b9c05f098f5941210256b328b30c8bf5839e2405\
            \8747879408bdb36241dc9c2e7c619faa12b2920967fdffffff97840471ad17d0\
            \47f8eaeea6be46191efe4b06de6ff022bfe7531b75539f49a30d000000"
          -- what follows the bits in that input script: the two signatures,
          -- and the script of 0x0113 = 275 bytes after OP_PUSHDATA2
          afterBits =
            "4142ca12be6b6f5ffef66a83bdeac7384577fd651e34383da87ed19ebca0f8e0\
            \2fcdbb95bb8b706787119e73d084c0f350273abbdec260704b622e11356137f6\
            \d541418a7a0a965224e2b0524fbfbe9da002d7f892ebdcf834d1e81290c910ac\
            \1a276fca0598732282028495ef858d6c900e10244f996860fa0e18e25818167c\
            \88d0f7414d1301522102552c630b64b54bf50210c9e253d38bd4949c72e22873\
            \500f6285c2bede312a8421030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9\
            \a39ed93346d03d67d412d17721022f1b310f4c065331bc0d79ba4661bb9822d6\
            \7d7c4a1b0a1892e1fd0cd23aa68d210299c2aa85d2b21a62f396907a802a58e5\
            \21dafd5bddaccbd72786eea189bc4dc921021a7a569e91dbf60581509c7fc946\
            \d1003b60c7dee85299538db6353538d595742103a92c9b7cac68758de5783ed8\
            \e5123598e4ad137091e42987d3bad8a08e35bf3d21034f355bdcb7cc0af728ef\
            \3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa21036360e856310ce5d2\
            \94e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f758ae"
          spendOfEight script = verdictsOf bchRegTest [first, twoOfEight] (txOf (startOfEight <> script <> end))
      -- The shortest push of the byte 0x81 is OP_1NEGATE, the byte 0x4f. The
      -- input script is 1 + 410 = 411 bytes long, 0x019b.
      it "verify it when OP_1NEGATE pushes the bits, which the node took" $
        spendOfEight ("fd9b014f" <> afterBits) `shouldBe` (False, [InputVerified, InputVerified])
      -- The same bits as one byte of data: 0x01 0x81. The node: "Data push
      -- larger than necessary".
      it "do not verify it when the bits are pushed as a byte of data" $
        spendOfEight ("fd9c010181" <> afterBits) `shouldBe` (False, [InputVerified, InputUndecided])
    it "on Bitcoin, still verify a key that is not pushed by the shortest push, which a block may hold" $ do
      let sig = ecdsa k 0x01 (txSigHash btc (spending "" []) pkhScript value 0 sigHashAll)
          -- the key after OP_PUSHDATA1 and its length
          tx = spending (runPutS (serialize (Script [opPushData sig, OP_PUSHDATA pub OPDATA1]))) []
      verifyStdTx btc tx [(PayPKHash h160, value, coin)] `shouldBe` True
      judgeInputs btc tx [prev (PayPKHash h160)] `shouldBe` [InputVerified]

  -- Transactions that Bitcoin Cash Node 29.2.0 and Bitcoin Core 32.1 judged
  -- on regtest. Each has one input, signed by the key 03974d27...ce40 with a
  -- good ECDSA signature whose r and s take 29 bytes each: its DER form is
  -- 6 + 29 + 29 = 64 bytes, where most signatures have 70 to 72. Bitcoin
  -- Cash Node reads a signature of 64 bytes as a Schnorr signature. It
  -- refused both transactions with "mandatory-script-verify-flag-failed",
  -- the reason for which it drops the peer that sent the transaction.
  describe "verifyStdTx and judgeInputs on an ECDSA signature of 64 bytes" $ do
    it "on Bitcoin Cash, say forged of a key hash input, where the node reads a Schnorr signature" $
      -- The node: "Signature must be zero for failed CHECK(MULTI)SIG
      -- operation". The signature is after the push of its 0x41 = 65
      -- bytes: 64 and the hash type.
      verdicts
        bchRegTest
        (hex "76a91473dd2b9cb7ce0af55615372357094ba779b743e588ac")
        ( txOf
            "02000000012106f47f465220eccf0f8bf413656ba995d6e2241703ca77b2bc32\
            \053a922e2c000000006441303e021d412389f0428046438bea9c0e2427db23ab\
            \0bce6fe36d851e0dc86b41ed021d20576521b06f9bc52aacf1dee9900a53c82c\
            \9e9ad11dae4edc0d6164db412103974d27bb4ae05f5f64805ba2d39802f702e1\
            \3213b52d10e048e7daaf063bce40ffffffff01583e0f00000000001976a91400\
            \79e2c6e56eccf59e088ee40cfd3b503362157c88acec135901"
        )
        `shouldBe` (False, [InputForged])
    it "on Bitcoin Cash, do not verify a multisig input, where the node takes no signature of that length" $
      -- The node: "Signature cannot be 65 bytes in CHECKMULTISIG". The coin
      -- is locked to the hash of a script that asks for one signature of
      -- two keys.
      verdicts
        bchRegTest
        (hex "a914d52daac634cd249e6674061cf065f05cf388213587")
        ( txOf
            "0200000001d0f0c7264bb826a67ef0ec644850b16b222507010305eddc64cb69\
            \193f57531b000000008b0041303e021d412389f0428046438bea9c0e2427db23\
            \ab0bce6fe36d851e0dc86b41ed021d2bb4f160b75b0483b12fa6b358c685c20c\
            \04299e64c997a0605bbaeea94147512103974d27bb4ae05f5f64805ba2d39802\
            \f702e13213b52d10e048e7daaf063bce402102d77b272781a48f7a51de424305\
            \f88043665e45d084546195268a458c675db59552aeffffffff01583e0f000000\
            \00001976a9140079e2c6e56eccf59e088ee40cfd3b503362157c88ac29983f00"
        )
        `shouldBe` (False, [InputUndecided])
    it "on Bitcoin, verify a witness key hash input, which the node put in a block" $
      verdicts
        btcRegTest
        (hex "001473dd2b9cb7ce0af55615372357094ba779b743e5")
        ( txOf
            "02000000000101a9e92b1b6c32297125fbe2ec62992e4f0367bb79e16d6bf2e6\
            \192c681e7bc3480100000000ffffffff01583e0f00000000001976a9140079e2\
            \c6e56eccf59e088ee40cfd3b503362157c88ac0241303e021d412389f0428046\
            \438bea9c0e2427db23ab0bce6fe36d851e0dc86b41ed021d45d27dbe1a69e0b6\
            \a7fdd755a5050c8aa396901d3d6e15a054bead1bda012103974d27bb4ae05f5f\
            \64805ba2d39802f702e13213b52d10e048e7daaf063bce40904ce700"
        )
        `shouldBe` (True, [InputVerified])

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
    let genesis =
          txOf
            "0200000001f28fd1cdb4293ae6bb76e580c5a3469fb926690471f3ffb798ef0a\
            \cda9886525000000006441e31c237fe3a1a45f6c32c779c78025f29bd735fa44\
            \d18c182bc1c08fbbcab25f08cbd8c1937dccd38acf37ef2bf8907e75029d622c\
            \5a9f6f5161ffe534fa2775412103bcacac8993931b1f0867991841a140425906\
            \839d26c4c906a737a4f2f29dd79effffffff01c0aff629010000003eeff28fd1\
            \cdb4293ae6bb76e580c5a3469fb926690471f3ffb798ef0acda988652510fde8\
            \0376a9145dd6bc82b5a42053b8f7802e68d296ac3578537a88ac00000000"
        spend =
          txOf
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

  -- A spend can be written in other bytes with every signature still good:
  -- see "Haskoin.Util.Arbitrary.Spelling". Each property below makes signed
  -- transactions of one to four inputs with one input in such a spelling,
  -- and states three answers: that of 'verifyStdTx', the verdict of
  -- 'judgeInputs' on that input, and whether every other input is verified.
  -- The signatures are good, so the verdict is never forged.
  --
  -- MINIMALDATA, LOW_S, STRICTENC and WITNESS_PUBKEYTYPE are rules of the
  -- relay policy of Bitcoin Core: a block may hold an input that breaks
  -- one. The verifiers take the first and the last, and leave the two
  -- others to a node.
  describe "verifyStdTx and judgeInputs on a good spend written a way that Bitcoin does not relay" $ do
    prop "verify an input script that pushes an item by a longer push" $
      answersFor btc LongPush (True, InputVerified, True)
    prop "verify a SegWit input of an uncompressed key" $
      answersFor btc UncompressedKey (True, InputVerified, True)
    prop "do not verify a signature with a high S" $
      answersFor btc HighS (False, InputUndecided, True)
    prop "do not verify a key in the hybrid form" $
      answersFor btc HybridKey (False, InputUndecided, True)

  -- BIP 141: the input script of a nested input is exactly the push of its
  -- program, and the witness script hashes to the program. BIP 16: the
  -- redeem script hashes to the coin. A signature covers the bytes of the
  -- script of its coin.
  describe "verifyStdTx and judgeInputs on a good spend written a way that no block of Bitcoin holds" $ do
    prop "do not verify a nested witness program that is pushed by a longer push" $
      answersFor btc LongProgramPush (False, InputUndecided, True)
    prop "do not verify a redeem script or a witness script in other bytes than the coin commits to" $
      answersFor btc UncommittedScript (False, InputUndecided, True)
    prop "do not verify a coin locked to another spelling of the script that was signed" $
      answersFor btc UnsignedScript (False, InputUndecided, True)

  -- MINIMALDATA, LOW_S and STRICTENC are rules of every block of Bitcoin
  -- Cash: they are among the MANDATORY_SCRIPT_VERIFY_FLAGS of Bitcoin Cash
  -- Node.
  describe "verifyStdTx and judgeInputs on a good spend written a way that no block of Bitcoin Cash holds" $ do
    prop "do not verify an input script that pushes an item by a longer push" $
      answersFor bch LongPush (False, InputUndecided, True)
    prop "do not verify a signature with a high S" $
      answersFor bch HighS (False, InputUndecided, True)
    prop "do not verify a key in the hybrid form" $
      answersFor bch HybridKey (False, InputUndecided, True)
    prop "do not verify a redeem script in other bytes than the coin commits to" $
      answersFor bch UncommittedScript (False, InputUndecided, True)
    prop "do not verify a coin locked to another spelling of the script that was signed" $
      answersFor bch UnsignedScript (False, InputUndecided, True)

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
