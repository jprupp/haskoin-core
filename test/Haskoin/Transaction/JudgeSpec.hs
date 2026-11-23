{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.Transaction.JudgeSpec (spec) where

import Crypto.Secp256k1
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (serialize)
import Data.Maybe (fromJust)
import Data.Serialize (encode)
import Data.Word (Word32, Word64, Word8)
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction hiding (Coin (..))
import Haskoin.Transaction.Judge
import Haskoin.Util
import Test.Hspec

-- | An output, told apart by a number.
output :: Word32 -> OutPoint
output n = OutPoint (TxHash (doubleSHA256 (encode n))) n

-- | A transaction that spends outputs and pays a value.
spending :: [OutPoint] -> Word64 -> Tx
spending ins v =
  Tx
    { version = 2,
      inputs = [TxIn {outpoint = o, script = "", sequence = maxBound} | o <- ins],
      outputs = [TxOut {value = v, script = B.replicate 25 1}],
      witness = [],
      locktime = 0
    }

-- | A coin of a value that nothing is known of: not in a block, and with
-- a script whose spending cannot be judged.
held :: Word64 -> Coin
held v = Coin {output = TxOut v "", mined = Nothing, coinbase = False}

-- | An input script that pushes a word, which 'rulesOf' reads.
saying :: ByteString -> ByteString
saying word = encode (Script [opPushData word])

-- | The chain at block 1000.
--
-- The signatures are judged by the scripts of the test: an input script
-- that pushes @forged@ is forged, one that pushes @script@ cannot be told,
-- and any other verifies. 'judgeInputs' itself is tested in
-- "Haskoin.Transaction.VerdictSpec".
rulesOf :: Rules
rulesOf = Rules {net = btc, inputs = \tx _ -> map verdict tx.inputs, height = 1000, medianTime = 1600000000}
  where
    verdict :: TxIn -> InputVerdict
    verdict i
      | i.script == saying "forged" = InputForged
      | i.script == saying "script" = InputUndecided
      | otherwise = InputVerified

-- | The front of the script of an output that holds tokens: the category,
-- the flags, the commitment if there is one, and the amount if not zero.
withTokens :: ByteString -> Maybe (Word8, ByteString) -> Word64 -> ByteString
withTokens category nft amount =
  B.concat
    [ "\xef",
      category,
      B.singleton (nftFlags .|. (if amount > 0 then 0x10 else 0)),
      maybe "" (\(_, c) -> if B.null c then "" else B.singleton (fromIntegral (B.length c)) <> c) nft,
      if amount > 0 then compact amount else "",
      "\x76\xa9\x14" <> B.replicate 20 7 <> "\x88\xac"
    ]
  where
    nftFlags = case nft of
      Nothing -> 0
      Just (capability, c) -> 0x20 .|. capability .|. (if B.null c then 0 else 0x40)
    compact v
      | v < 0xfd = B.singleton (fromIntegral v)
      | otherwise = "\xfd" <> B.pack [fromIntegral v, fromIntegral (v `div` 256)]
    a .|. b = a + b

-- | A secret key, and the compressed bytes of its public key.
secret :: SecKey
secret = fromJust (secKey (B.replicate 31 0 <> B.singleton 7))

public :: ByteString
public = exportPubKey True (derivePubKey secret)

-- | A coin of 100,000 locked to the hash of that key.
keyCoin :: TxOut
keyCoin = TxOut 100000 (encodeSerial (PayPKHash (addressHash public)))

-- | A coin of 100,000 locked by a script, which nothing here runs.
scriptCoin :: TxOut
scriptCoin = TxOut 100000 ("\xa9\x14" <> B.replicate 20 7 <> "\x87")

-- | A transaction of Bitcoin that spends output 1, signed by the key as
-- the spend of 'keyCoin'.
signed :: Tx
signed = unsigned {inputs = [TxIn (output 1) (runPutS (serialize (Script (map opPushData [sig, public])))) maxBound]}
  where
    unsigned = spending [output 1] 90000
    locking = either error id (encodeOutput (PayPKHash (addressHash public)))
    digest = either error id (txSigHash btc unsigned locking 100000 0 sigHashAll)
    sig = exportSig (signHash secret digest) <> B.singleton 0x01

spec :: Spec
spec = do
  let check = judge rulesOf
  describe "a transaction to publish" $ do
    let tx = spending [output 1, output 2] 1500
    it "lets through a transaction that spends what is there" $
      check tx [held 1000, held 500] `shouldBe` Right Nothing
    it "refuses an output it does not know, and one spent in a block" $ do
      check tx [held 1000, Missing] `shouldBe` Left (UnknownOutput (output 2))
      let by = (output 9).hash
      check tx [Spent by, held 1000] `shouldBe` Left (SpentOutput (output 1) by)
    it "refuses outputs worth more than the inputs" $
      check tx [held 1000, held 499] `shouldBe` Left Overspent
    it "refuses the same output twice, a coinbase, and nothing to spend or pay" $ do
      check (spending [output 1, output 1] 1) [held 1, held 1] `shouldBe` Left (DuplicateInput (output 1))
      check (spending [nullOutPoint] 1) [Missing] `shouldBe` Left IsCoinbase
      check (spending [] 1) [] `shouldBe` Left NoInputs
      check (spending [output 1] 1) {outputs = []} [held 1] `shouldBe` Left NoOutputs
    it "refuses a coinbase that is not a hundred blocks old" $ do
      let young h = Coin {output = TxOut 1000 "", mined = Just h, coinbase = True}
          one = spending [output 1] 900
      check one [young 902] `shouldBe` Left (Immature (output 1))
      check one [young 901] `shouldBe` Right Nothing
      check one [(young 902) {coinbase = False}] `shouldBe` Right Nothing
    it "refuses a lock time that has not passed, unless every input waives it" $ do
      let locked n = (spending [output 1] 900) {locktime = n, inputs = [TxIn (output 1) "" 0]} :: Tx
      check (locked 1000) [held 1000] `shouldBe` Right Nothing
      check (locked 1001) [held 1000] `shouldBe` Left (NotFinal 1001)
      check (locked 1599999999) [held 1000] `shouldBe` Right Nothing
      check (locked 1600000000) [held 1000] `shouldBe` Left (NotFinal 1600000000)
      check ((locked 1001) {inputs = [TxIn (output 1) "" maxBound]} :: Tx) [held 1000] `shouldBe` Right Nothing
    it "refuses an output worth less than it costs to spend, and not one that holds data" $ do
      let paying v script = (spending [output 1] 0) {outputs = [TxOut v script]} :: Tx
          keyHash = "\x76\xa9\x14" <> B.replicate 20 7 <> "\x88\xac"
          witnessKeyHash = "\x00\x14" <> B.replicate 20 7
      check (paying 545 keyHash) [held 1000] `shouldBe` Left (Dust 0)
      check (paying 546 keyHash) [held 1000] `shouldBe` Right Nothing
      check (paying 293 witnessKeyHash) [held 1000] `shouldBe` Left (Dust 0)
      check (paying 294 witnessKeyHash) [held 1000] `shouldBe` Right Nothing
      check (paying 0 "\x6a\x04data") [held 1000] `shouldBe` Right Nothing
    it "refuses a forged signature, and names the input it cannot judge" $ do
      let signedBy items = (spending [output 1, output 2] 900) {inputs = zipWith input [1 ..] items} :: Tx
          input n item = TxIn (output n) (saying item) maxBound
      check (signedBy ["good", "forged"]) [held 1000, held 1000] `shouldBe` Left (Forged 1)
      check (signedBy ["good", "script"]) [held 1000, held 1000] `shouldBe` Right (Just 1)
      check (signedBy ["good", "good"]) [held 1000, held 1000] `shouldBe` Right Nothing
    it "refuses a version that nodes do not take: 1 to 3 on Bitcoin, 1 and 2 on Bitcoin Cash" $ do
      let versioned v = (spending [output 1] 900) {version = v} :: Tx
          cash = judge rulesOf {net = bch}
      check (versioned 3) [held 1000] `shouldBe` Right Nothing
      check (versioned 0) [held 1000] `shouldBe` Left (BadVersion 0)
      check (versioned 4) [held 1000] `shouldBe` Left (BadVersion 4)
      cash (versioned 2) [held 1000] `shouldBe` Right Nothing
      cash (versioned 3) [held 1000] `shouldBe` Left (BadVersion 3)
    it "refuses an input script that does more than push, or pushes in a longer form than it needs" $ do
      let scripted ops = (spending [output 1] 900) {inputs = [TxIn (output 1) (encode (Script ops)) maxBound]} :: Tx
          signature = B.replicate 71 1
      check (scripted [opPushData signature, opPushData (B.replicate 33 2)]) [held 1000] `shouldBe` Right Nothing
      -- a push of 71 bytes takes one byte for its length, not two
      check (scripted [OP_PUSHDATA signature OPDATA1]) [held 1000] `shouldBe` Left (NotMinimal 0)
      -- the number 1 is OP_1, and the empty string OP_0
      check (scripted [OP_PUSHDATA "\x01" OPCODE]) [held 1000] `shouldBe` Left (NotMinimal 0)
      check (scripted [OP_0, OP_1, OP_1NEGATE]) [held 1000] `shouldBe` Right Nothing
      check (scripted [opPushData signature, OP_DUP]) [held 1000] `shouldBe` Left (NotPushOnly 0)
      -- bytes that are not a script at all
      check ((spending [output 1] 900) {inputs = [TxIn (output 1) "\x4c" maxBound]} :: Tx) [held 1000]
        `shouldBe` Left (NotPushOnly 0)

  describe "the tokens of Bitcoin Cash" $ do
    let category = B.replicate 32 9
        -- a category made by this transaction: the id of what its first
        -- input spends, whose index is 0
        newCategory = encode (OutPoint (TxHash (doubleSHA256 ("genesis" :: ByteString))) 0).hash
        from n = OutPoint (output n).hash n
        tx ins outs = (spending ins 0) {outputs = [TxOut 1000 s | s <- outs]} :: Tx
        coin s = TxOut 1000 s
        plain = "\x76\xa9\x14" <> B.replicate 20 7 <> "\x88\xac"
        fungible c n = withTokens c Nothing n
        nft c capability commitment = withTokens c (Just (capability, commitment)) 0
    it "lets tokens through as the inputs hold them" $ do
      tokenRules (tx [from 1] [fungible category 400, fungible category 600]) [coin (fungible category 1000)]
        `shouldBe` Right ()
      -- burnt: fewer out than in
      tokenRules (tx [from 1] [fungible category 10]) [coin (fungible category 1000)] `shouldBe` Right ()
      tokenRules (tx [from 1] [plain]) [coin plain] `shouldBe` Right ()
    it "refuses more fungible tokens out than in" $
      tokenRules (tx [from 1, from 2] [fungible category 2000]) [coin (fungible category 1000), coin plain]
        `shouldBe` Left (TokensUnbacked (concatMap (const "09") [1 .. 32 :: Int]))
    it "makes tokens of a new category at will, from an input that spends an output 0" $ do
      let genesisId = TxHash (doubleSHA256 ("genesis" :: ByteString))
          genesis =
            (tx [] [fungible newCategory 5000, nft newCategory 2 ""])
              { inputs = [TxIn (OutPoint genesisId 0) "" maxBound]
              } ::
              Tx
      tokenRules genesis [coin plain] `shouldBe` Right ()
      -- the same category from an input that spends an output 1 is not new
      let notNew = genesis {inputs = [TxIn (OutPoint genesisId 1) "" maxBound]} :: Tx
      tokenRules notNew [coin plain] `shouldSatisfy` either (const True) (const False)
    it "refuses tokens not written as tokens are" $
      tokenRules (tx [from 1] ["\xef\x01"]) [coin plain] `shouldBe` Left (BadTokens 0)
    it "keeps non-fungible tokens to what the inputs allow" $ do
      let keep = tx [from 1] [nft category 0 "a"]
      -- the same immutable token passes on; another commitment does not
      tokenRules keep [coin (nft category 0 "a")] `shouldBe` Right ()
      tokenRules keep [coin (nft category 0 "b")] `shouldSatisfy` either (const True) (const False)
      -- a mutable one becomes any one token, not two
      tokenRules keep [coin (nft category 1 "x")] `shouldBe` Right ()
      tokenRules (tx [from 1] [nft category 0 "a", nft category 0 "b"]) [coin (nft category 1 "x")]
        `shouldSatisfy` either (const True) (const False)
      -- a minting one makes any, and only a minting one makes one that mints
      tokenRules (tx [from 1] [nft category 0 "a", nft category 2 "b"]) [coin (nft category 2 "")]
        `shouldBe` Right ()
      tokenRules (tx [from 1] [nft category 2 "b"]) [coin (nft category 1 "")]
        `shouldSatisfy` either (const True) (const False)

  describe "a transaction that a peer sent" $ do
    let relayed = judgeRelayed btc
    it "says that every signature verifies of a spend of a coin locked to one key" $
      relayed signed [keyCoin] `shouldBe` Right Nothing
    it "refuses it when what was signed is not what is there" $ do
      let tampered = signed {outputs = [o {value = o.value - 1} | o <- signed.outputs]} :: Tx
      relayed tampered [keyCoin] `shouldBe` Left (Forged 0)
    it "names the input that spends a coin locked by a script, which it cannot judge" $
      relayed signed [scriptCoin] `shouldBe` Right (Just 0)
    it "refuses outputs worth more than the inputs, whatever the signatures" $
      relayed signed [keyCoin {value = 89999}] `shouldBe` Left Overspent
    it "refuses the same output twice, a coinbase, and nothing to spend or pay" $ do
      relayed (spending [output 1, output 1] 1) [keyCoin, keyCoin] `shouldBe` Left (DuplicateInput (output 1))
      relayed (spending [nullOutPoint] 1) [keyCoin] `shouldBe` Left IsCoinbase
      relayed (spending [] 1) [] `shouldBe` Left NoInputs
      relayed (spending [output 1] 1) {outputs = []} [keyCoin] `shouldBe` Left NoOutputs
    it "does not hold it to the policy of a node: dust, a version, a lock time that has not passed" $ do
      -- 'judge' refuses each of these; of a transaction that a node
      -- relayed they say nothing
      let odd' = (spending [output 1] 1) {version = 9, locktime = 4000000000, inputs = [TxIn (output 1) "" 0]} :: Tx
      judge rulesOf odd' [held 100000] `shouldSatisfy` either (const True) (const False)
      relayed odd' [scriptCoin] `shouldBe` Right (Just 0)
    it "holds a transaction of Bitcoin Cash to the rules of the tokens" $ do
      let category = B.replicate 32 9
          made = (spending [output 1] 0) {outputs = [TxOut 1000 (withTokens category Nothing 5)]} :: Tx
      judgeRelayed bch made [scriptCoin] `shouldBe` Left (TokensUnbacked (concatMap (const "09") [1 .. 32 :: Int]))
      -- on Bitcoin those bytes are a script like any other
      judgeRelayed btc made [scriptCoin] `shouldBe` Right (Just 0)
