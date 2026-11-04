{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- | The PSBT format of BIP 174, and its version 2 of BIP 370: the vectors
-- of both BIPs, the bytes of a PSBT and the refusals of what breaks the
-- spec, the fields of the spec, the roles: combining, signing, finalizing
-- and extracting, and the inputs and outputs a PSBT of version 2 takes.
module Haskoin.Transaction.PsbtSpec (spec) where

import Control.Monad (foldM, forM_)
import Data.Aeson ((.:), (.:?))
import Data.Aeson qualified as Json
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Either (isLeft)
import Data.List (isSuffixOf)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromJust, fromMaybe)
import Data.Serialize qualified as S
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Data.Word (Word32, Word64)
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck

{- The vectors of the BIP -}

-- The vectors live in data/psbt_bip174.json, copied from the BIP. Each has
-- the case the BIP gives, its hex, and its base64 when the BIP gives it.
data Vector = Vector
  { vecCase :: String,
    vecHex :: Text,
    vecBase64 :: Maybe Text
  }

instance Json.FromJSON Vector where
  parseJSON = Json.withObject "vector" $ \o -> Vector <$> o .: "case" <*> o .: "hex" <*> o .:? "base64"

-- | The invalid PSBTs, the valid ones, the PSBTs of the walk-through of the
-- roles, in the order of the BIP, and the transaction its extractor gives
data Vectors = Vectors
  { invalid :: [Vector],
    valid :: [Vector],
    roles :: [Vector],
    extracted :: Vector
  }

instance Json.FromJSON Vectors where
  parseJSON = Json.withObject "vectors" $ \o -> Vectors <$> o .: "invalid" <*> o .: "valid" <*> o .: "roles" <*> o .: "extracted"

-- The PSBTs of the walk-through, by their place in it
creator, updater, updaterWithSigHash, firstSigner, secondSigner, combiner, finalizer, unknownA, unknownB, unknownCombined, toCombineA, toCombineB, combined :: Vectors -> Vector
creator v = roles v !! 0
updater v = roles v !! 1
updaterWithSigHash v = roles v !! 2
firstSigner v = roles v !! 3
secondSigner v = roles v !! 4
combiner v = roles v !! 5
finalizer v = roles v !! 6
unknownA v = roles v !! 7
unknownB v = roles v !! 8
unknownCombined v = roles v !! 9
toCombineA v = roles v !! 10
toCombineB v = roles v !! 11
combined v = roles v !! 12

hexBytes :: Text -> ByteString
hexBytes = fromJust . decodeHex

bytesOf :: Vector -> ByteString
bytesOf = hexBytes . vecHex

expectRight :: Either String a -> IO a
expectRight = either fail return

forceRight :: Either String a -> a
forceRight = either error id

fingerprintOf :: Text -> Fingerprint
fingerprintOf = forceRight . textToFingerprint

-- | The PSBT of a vector, which must decode
psbtOfVector :: Vector -> IO Psbt
psbtOfVector v = expectRight (decodePsbt (bytesOf v))

-- | The map of the input, or of the output, at the index
inputAt, outputAt :: Int -> Psbt -> PsbtMap
inputAt i psbt = psbt.inputs !! i
outputAt i psbt = psbt.outputs !! i

-- | A PSBT with the maps of its inputs replaced
withInputs :: [PsbtMap] -> Psbt -> Psbt
withInputs inputs psbt = Psbt psbt.version psbt.unsignedTx psbt.globals inputs psbt.outputs

-- | The PSBT with the flags given in its global map
withFlags :: Modifiable -> Psbt -> Psbt
withFlags flags psbt = Psbt psbt.version psbt.unsignedTx (insertTxModifiable flags psbt.globals) psbt.inputs psbt.outputs

spec :: Spec
spec = do
  vectors <- runIO (readTestFile "psbt_bip174.json" :: IO Vectors)
  vectors370 <- runIO (readTestFile "psbt_bip370.json" :: IO Vectors370)
  prepareContext $ \ctx -> do
    vectorsSpec vectors
    vectors370Spec vectors370
    rolesSpec ctx vectors
    version2Spec
    bytesSpec vectors
    fieldsSpec ctx vectors
    signingSpec ctx
    complexSpec ctx
    core32Spec ctx
    propertiesSpec ctx

{- The vectors of BIP 370 -}

-- The vectors of BIP 370 live in data/psbt_bip370.json: the invalid
-- PSBTs, the valid ones, and the PSBTs of its lock time cases, each with
-- the lock time the BIP computes, none when it cannot be computed
data LockTimeVector = LockTimeVector
  { ltCase :: String,
    ltHex :: Text,
    ltLockTime :: Maybe Word32
  }

instance Json.FromJSON LockTimeVector where
  parseJSON = Json.withObject "vector" $ \o -> LockTimeVector <$> o .: "case" <*> o .: "hex" <*> o .:? "locktime"

data Vectors370 = Vectors370
  { refused :: [Vector],
    accepted :: [Vector],
    lockTimes :: [LockTimeVector]
  }

instance Json.FromJSON Vectors370 where
  parseJSON = Json.withObject "vectors" $ \o -> Vectors370 <$> o .: "invalid" <*> o .: "valid" <*> o .: "locktime"

-- | Why each invalid PSBT of BIP 370 is refused, in the order of the BIP:
-- a field of the other version, a field version 2 requires missing, a
-- lock time out of its range
refusals370 :: [String]
refusals370 =
  [ "The global map: the key 0x00 is not of PSBT version 2",
    "The global map: the key 0x02 is not of PSBT version 0",
    "The global map: the key 0x03 is not of PSBT version 0",
    "The global map: the key 0x04 is not of PSBT version 0",
    "The global map: the key 0x05 is not of PSBT version 0",
    "The global map: the key 0x06 is not of PSBT version 0",
    "Input 0: the key 0x0e is not of PSBT version 0",
    "Input 0: the key 0x0f is not of PSBT version 0",
    "Input 0: the key 0x10 is not of PSBT version 0",
    "Input 0: the key 0x11 is not of PSBT version 0",
    "Input 0: the key 0x12 is not of PSBT version 0",
    "Output 0: the key 0x03 is not of PSBT version 0",
    "Output 0: the key 0x04 is not of PSBT version 0",
    "The global map: the key 0x00 is not of PSBT version 2",
    "The global map has no input count",
    "The global map has no output count",
    "The global map has no transaction version",
    "Input 0 has no previous transaction id",
    "Input 0 has no output index",
    "Output 0 has no amount",
    "Output 0 has no script",
    "Input 0: the value of the key 0x11 is a time lock below 500000000",
    "Input 0: the value of the key 0x12 is not a height between 1 and 499999999",
    "Input 0: the value of the key 0x12 is not a height between 1 and 499999999"
  ]

vectors370Spec :: Vectors370 -> Spec
vectors370Spec vectors = do
  describe "The invalid PSBTs of BIP 370 are refused, each for its reason" $
    forM_ (zip vectors.refused refusals370) $ \(v, reason) ->
      it v.vecCase $ decodePsbt (bytesOf v) `shouldBe` Left reason

  describe "The valid PSBTs of BIP 370 are read as version 2, and written back byte for byte" $
    forM_ vectors.accepted $ \v ->
      it v.vecCase $ do
        psbt <- psbtOfVector v
        psbt.version `shouldBe` Version2
        encodePsbt psbt `shouldBe` bytesOf v

  describe "The transaction of a PSBT of version 2 is the one its fields describe" $
    -- The first valid PSBT of the BIP: one input, two outputs, nothing
    -- else. Its input has no sequence field, so its sequence is final,
    -- and no input requires a lock time, nor is a fallback given: lock
    -- time 0.
    it "for the first valid PSBT of the BIP, with a sequence and a lock time that no field gives" $ do
      psbt <- psbtOfVector (vectors.accepted !! 0)
      psbt.unsignedTx
        `shouldBe` Tx
          2
          [TxIn (OutPoint "c85f81844094f9f0eec1e41f8d63e0a99e9f73dc725d7319871c9c4121d90a0b" 0) "" 0xffffffff]
          [ TxOut 800000000 (hexBytes "0014c430f64c4756da310dbd1a085572ef299926272c"),
            TxOut 199998859 (hexBytes "00144dd193ac964a56ac1b9e1cca8454fe2f474f8513")
          ]
          []
          0

  describe "The lock time of a PSBT of version 2 is the one BIP 370 determines" $
    forM_ vectors.lockTimes $ \v ->
      it v.ltCase $
        ((.unsignedTx.locktime) <$> decodePsbt (hexBytes v.ltHex))
          `shouldBe` maybe (Left "No lock time fits every input: some require a height, others a time") Right v.ltLockTime

{- The vectors -}

vectorsSpec :: Vectors -> Spec
vectorsSpec vectors = do
  describe "The invalid PSBTs of BIP 174 are refused" $
    forM_ vectors.invalid $ \v ->
      it v.vecCase $ decodePsbt (bytesOf v) `shouldSatisfy` isLeft

  describe "The valid PSBTs of BIP 174 are read, and written back byte for byte" $
    forM_ vectors.valid $ \v ->
      it v.vecCase $ (encodePsbt <$> decodePsbt (bytesOf v)) `shouldBe` Right (bytesOf v)

  describe "The valid PSBTs of BIP 174 read the same from their base64 text" $
    forM_ [(v, text) | v <- vectors.valid, Just text <- [v.vecBase64]] $ \(v, text) ->
      it v.vecCase $ (encodePsbt <$> decodePsbtBase64 (encodeUtf8 text)) `shouldBe` Right (bytesOf v)

  -- The combiner's PSBT of the two signed ones lists the signatures of
  -- its second input out of order: see 'rolesSpec'
  describe "The PSBTs of the roles of BIP 174 are read, and written back byte for byte" $
    forM_ [v | v <- vectors.roles, v.vecCase /= (combiner vectors).vecCase] $ \v ->
      it v.vecCase $ (encodePsbt <$> decodePsbt (bytesOf v)) `shouldBe` Right (bytesOf v)

rolesSpec :: Ctx -> Vectors -> Spec
rolesSpec ctx vectors =
  describe "The roles of BIP 174" $ do
    it "the creator's PSBT is the unsigned transaction with empty maps" $ do
      psbt <- psbtOfVector (creator vectors)
      psbtOf psbt.unsignedTx `shouldBe` psbt

    it "the transaction extractor gives the transaction of the finalizer's PSBT" $ do
      psbt <- psbtOfVector (finalizer vectors)
      (S.encode <$> psbtTransaction psbt) `shouldBe` Right (bytesOf (extracted vectors))

    it "the transaction of a PSBT without final scripts is the unsigned one" $ do
      psbt <- psbtOfVector (creator vectors)
      psbtTransaction psbt `shouldBe` Right psbt.unsignedTx

    -- The spec does not say in which order a combiner writes the keys of a
    -- map. The BIP's combiner lists the two signatures of the second input
    -- out of order; the keys of a map are written in order here, as
    -- Bitcoin Core writes them. The PSBTs are the same, byte for byte once
    -- the BIP's is written back.
    it "the combiner's PSBT is that of the two signers combined, whatever the order of its inputs" $ do
      a <- psbtOfVector (firstSigner vectors)
      b <- psbtOfVector (secondSigner vectors)
      both <- psbtOfVector (combiner vectors)
      combinePsbt a b `shouldBe` Right both
      combinePsbt b a `shouldBe` Right both
      encodePsbt both `shouldNotBe` bytesOf (combiner vectors)
      decodePsbt (encodePsbt both) `shouldBe` Right both

    it "the two PSBTs with unknown keys combine as the combiner of the BIP that orders keys lexicographically does" $ do
      a <- psbtOfVector (unknownA vectors)
      b <- psbtOfVector (unknownB vectors)
      (encodePsbt <$> combinePsbt a b) `shouldBe` Right (bytesOf (unknownCombined vectors))
      (encodePsbt <$> combinePsbt b a) `shouldBe` Right (bytesOf (unknownCombined vectors))

    it "the two PSBTs to combine give the combiner's PSBT" $ do
      a <- psbtOfVector (toCombineA vectors)
      b <- psbtOfVector (toCombineB vectors)
      (encodePsbt <$> combinePsbt a b) `shouldBe` Right (bytesOf (combined vectors))

    it "PSBTs of different transactions are not combined" $ do
      a <- psbtOfVector (creator vectors)
      combinePsbt a (psbtOf emptyTx) `shouldBe` Left "The PSBTs are not of the same transaction"

    it "the updater's PSBT with SIGHASH_ALL is the updater's PSBT with the sighash type on every input" $ do
      psbt <- psbtOfVector (updater vectors)
      encodePsbt (withInputs (insertSigHashType sigHashAll <$> psbt.inputs) psbt) `shouldBe` bytesOf (updaterWithSigHash vectors)

    it "the finalizer's PSBT is the combiner's PSBT finalized" $ do
      psbt <- psbtOfVector (combiner vectors)
      (encodePsbt <$> finalizePsbt ctx psbt) `shouldBe` Right (bytesOf (finalizer vectors))

    it "the finalizer leaves an input without enough signatures as it is" $ do
      psbt <- psbtOfVector (firstSigner vectors)
      finalizePsbt ctx psbt `shouldBe` Right psbt

{- The roles of version 2 -}

-- | The input and output of the PSBTs below: the coin and the first output
-- of the first valid PSBT of BIP 370, and another output of the same
-- transaction as the coin
coinInput, otherInput :: TxIn
coinInput = TxIn (OutPoint "c85f81844094f9f0eec1e41f8d63e0a99e9f73dc725d7319871c9c4121d90a0b" 0) "" 0xfffffffd
otherInput = TxIn (OutPoint "c85f81844094f9f0eec1e41f8d63e0a99e9f73dc725d7319871c9c4121d90a0b" 1) "" 0xfffffffd

paidOutput :: TxOut
paidOutput = TxOut 800000000 (hexBytes "0014c430f64c4756da310dbd1a085572ef299926272c")

version2Spec :: Spec
version2Spec =
  describe "A PSBT of version 2" $ do
    -- A creator of BIP 370 starts with no input and no output. The
    -- created one, with its flags set so that inputs and outputs can be
    -- added, and with the input and the output added.
    let created = withVersion Version2 (psbtOf (Tx 2 [] [] [] 0))
        modifiable = withFlags (Modifiable True True False 0) created
        built = forceRight (addOutput paidOutput Map.empty =<< addInput coinInput Map.empty modifiable)
        -- The same without its flags, as a constructor leaves it once
        -- nothing is to be added
        unflagged = Psbt Version2 built.unsignedTx (deleteTxModifiable built.globals) built.inputs built.outputs
        requiring field value = addInput otherInput (field value Map.empty)

    -- The fields of the global map: the transaction version 2, the
    -- fallback lock time 0, the two counts of 0, and the PSBT version 2
    it "is created with no input and no output, and the fields that describe its transaction" $
      encodeHex (encodePsbt created) `shouldBe` "70736274ff0102040200000001030400000000010401000105010001fb040200000000"

    it "takes no input or output unless its flags allow it" $ do
      addInput coinInput Map.empty created `shouldBe` Left "The inputs of the PSBT may not be modified"
      addOutput paidOutput Map.empty created `shouldBe` Left "The outputs of the PSBT may not be modified"

    -- The input is described by the id of the transaction it spends from,
    -- in the byte order of a transaction, the index of the output and its
    -- sequence; the output by its amount and its script
    it "takes an input and an output at the end, counted, described in their maps, and in its transaction" $ do
      built.unsignedTx `shouldBe` Tx 2 [coinInput] [paidOutput] [] 0
      Map.lookup (Key 0x04 "") built.globals `shouldBe` Just "\x01"
      Map.lookup (Key 0x05 "") built.globals `shouldBe` Just "\x01"
      inputAt 0 built
        `shouldBe` Map.fromList
          [ (Key 0x0e "", hexBytes "0b0ad921419c1c8719735d72dc739f9ea9e0638d1fe4c1eef0f9944084815fc8"),
            (Key 0x0f "", hexBytes "00000000"),
            (Key 0x10 "", hexBytes "fdffffff")
          ]
      outputAt 0 built `shouldBe` Map.fromList [(Key 0x03 "", hexBytes "0008af2f00000000"), (Key 0x04 "", hexBytes "0014c430f64c4756da310dbd1a085572ef299926272c")]

    it "refuses an input that spends an output it spends already" $
      addInput coinInput Map.empty built `shouldBe` Left "An input of the PSBT spends that output already"

    it "is not of version 0, which takes no input or output" $
      addInput coinInput Map.empty (psbtOf emptyTx) `shouldBe` Left "A PSBT of version 0 takes no input or output: its transaction is fixed"

    it "takes the lock time its inputs require: the greatest height when every one that requires a lock time takes a height" $ do
      withHeight <- expectRight (addInput coinInput (insertRequiredHeightLockTime 10000 Map.empty) modifiable)
      withHeight.unsignedTx.locktime `shouldBe` 10000
      ((.unsignedTx.locktime) <$> requiring insertRequiredHeightLockTime 9000 withHeight) `shouldBe` Right 10000
      requiring insertRequiredTimeLockTime 1657048460 withHeight `shouldBe` Left "No lock time fits every input: some require a height, others a time"

    -- The input of the PSBT has its final script
    it "refuses an input that changes the lock time once an input is signed, and takes one that keeps it" $ do
      let signed = withInputs [insertFinalScriptSig "\x00" (inputAt 0 built)] built
      requiring insertRequiredHeightLockTime 10000 signed `shouldBe` Left "An input is signed already: the lock time may not change"
      ((.unsignedTx.locktime) <$> addInput otherInput Map.empty signed) `shouldBe` Right 0

    it "takes a sequence for an input, in its transaction and in its map, as an updater sets one" $ do
      updated <- expectRight (setInputSequence 0 1 built)
      map (.sequence) updated.unsignedTx.inputs `shouldBe` [1]
      Map.lookup (Key 0x10 "") (inputAt 0 updated) `shouldBe` Just (hexBytes "01000000")
      setInputSequence 1 1 built `shouldBe` Left "The PSBT has no input 1"
      setInputSequence 0 1 (psbtOf emptyTx) `shouldBe` Left "The sequences of a PSBT of version 0 are in its unsigned transaction, which is fixed"

    -- The id of its transaction with the sequence of its input at 0: the
    -- same whatever the sequence. A PSBT of version 0 is identified by
    -- its transaction as it is, with the sequence 0xfffffffd here.
    it "is identified by its transaction with every sequence at 0" $ do
      psbtId built `shouldBe` "79dd9a151a6cfc0dc3b7779a697817a80544e2c9dc0cfb399ecc7fa3b4da8f2c"
      (psbtId <$> setInputSequence 0 1 built) `shouldBe` Right "79dd9a151a6cfc0dc3b7779a697817a80544e2c9dc0cfb399ecc7fa3b4da8f2c"
      psbtId (withVersion Version0 built) `shouldBe` "7ca9f2c2ff60a7a3f7efdaa703bfb23b9415639e07b71e194bafb4d592e2c405"

    it "combines with the same PSBT whose sequence an updater changed, and keeps the sequence of the first" $ do
      updated <- expectRight (setInputSequence 0 1 built)
      (map (.sequence) . (.unsignedTx.inputs) <$> combinePsbt built updated) `shouldBe` Right [0xfffffffd]
      (map (.sequence) . (.unsignedTx.inputs) <$> combinePsbt updated built) `shouldBe` Right [1]

    it "does not combine with a PSBT of version 0" $
      combinePsbt built (withVersion Version0 built) `shouldBe` Left "The PSBTs are not of the same version"

    -- The first lets inputs be added and has a SIGHASH_SINGLE signature;
    -- the second lets inputs and outputs be added, with the undefined
    -- bit 3 set
    it "combines its flags as Bitcoin Core does: modifiable only when both say so, with a SIGHASH_SINGLE signature of either" $ do
      (txModifiable . (.globals) <$> combinePsbt (withFlags (Modifiable True False True 0) built) (withFlags (Modifiable True True False 8) built))
        `shouldBe` Right (Right (Just (Modifiable True False True 0)))
      (txModifiable . (.globals) <$> combinePsbt unflagged (withFlags (Modifiable True False True 0) built))
        `shouldBe` Right (Right (Just (Modifiable False False True 0)))

    it "once signed, takes no more inputs unless the sighash has ANYONECANPAY, no more outputs unless it is NONE, and tells a SIGHASH_SINGLE signature" $ do
      let open = withFlags (Modifiable True True False 0) built
          flagsAfter sighash psbt = txModifiable (afterSignature sighash psbt).globals
      flagsAfter sigHashAll open `shouldBe` Right (Just (Modifiable False False False 0))
      flagsAfter (setAnyoneCanPay sigHashNone) open `shouldBe` Right (Just (Modifiable True True False 0))
      flagsAfter sigHashSingle open `shouldBe` Right (Just (Modifiable False False True 0))
      flagsAfter sigHashAll unflagged `shouldBe` Right Nothing
      flagsAfter sigHashSingle unflagged `shouldBe` Right (Just (Modifiable False False True 0))

    it "converted to version 0 is the PSBT of its transaction" $
      withVersion Version0 built `shouldBe` psbtOf (Tx 2 [coinInput] [paidOutput] [] 0)

{- Bytes -}

-- | A transaction with nothing in it: version 0, no input, no output, lock
-- time 0, which is "0000000000000000000000" over ten bytes
emptyTx :: Tx
emptyTx = Tx 0 [] [] [] 0

-- | The global map of the PSBT of 'emptyTx': the key of the unsigned
-- transaction, one byte of type 0x00, and the ten bytes of the transaction
emptyTxEntry :: Text
emptyTxEntry = "01000a00000000000000000000"

bytesSpec :: Vectors -> Spec
bytesSpec vectors =
  describe "The bytes of a PSBT" $ do
    -- The vector of the BIP for a transaction without inputs or outputs
    it "are the magic bytes, the unsigned transaction, and a map for each input and output" $
      encodePsbt (psbtOf emptyTx) `shouldBe` hexBytes ("70736274ff" <> emptyTxEntry <> "00")

    -- The key is 7 bytes: the type 0xfc, the identifier "test" after its
    -- length 4, and the subtype 0. The value is the 3 bytes of "btc".
    it "write a key as its length, its type and its data, and its value after its length" $
      encodePsbt (Psbt Version0 emptyTx (insertProprietary "test" 0 "btc" Map.empty) [] [])
        `shouldBe` hexBytes ("70736274ff" <> emptyTxEntry <> "07fc047465737400" <> "03627463" <> "00")

    it "write the keys of a map in order, the type first, whatever the order they were added" $ do
      let globals = Map.fromList [(Key 0x20 "", hexBytes "bb"), (Key 0x10 (hexBytes "01"), hexBytes "aa")]
      encodePsbt (Psbt Version0 emptyTx globals [] [])
        `shouldBe` hexBytes ("70736274ff" <> emptyTxEntry <> "02100101aa" <> "012001bb" <> "00")

    it "write the unsigned transaction without the input scripts and the witness of a signed one" $ do
      signed <- expectRight $ S.decode (bytesOf (extracted vectors))
      psbt <- psbtOfVector (finalizer vectors)
      (psbtOf signed).unsignedTx `shouldBe` psbt.unsignedTx

    it "tell a PSBT from other bytes by its first five" $ do
      isPsbt (bytesOf (creator vectors)) `shouldBe` True
      isPsbt "{\"tx\": \"0200\"}" `shouldBe` False

    it "accept the unsigned transaction after another key of the global map" $
      decodePsbt (hexBytes ("70736274ff" <> "012001bb" <> emptyTxEntry <> "00"))
        `shouldBe` Right (Psbt Version0 emptyTx (Map.fromList [(Key 0x20 "", hexBytes "bb")]) [] [])

    it "refuse what is not a PSBT" $
      decodePsbt "{\"tx\": \"0200\"}" `shouldBe` Left "Not a PSBT: the bytes do not start with the magic bytes of BIP 174"

    it "refuse a key twice in a map, naming it" $
      decodePsbt (hexBytes ("70736274ff" <> emptyTxEntry <> "012001aa" <> "012001bb" <> "00"))
        `shouldBe` Left "The global map has the key 0x20 twice"

    it "refuse bytes after the last map" $
      decodePsbt (bytesOf (creator vectors) <> "\0") `shouldBe` Left "Bytes follow the last map"

    -- Version 1 was never defined
    it "refuse a PSBT of a version other than 0 and 2" $
      decodePsbt (hexBytes ("70736274ff" <> emptyTxEntry <> "01fb0401000000" <> "00"))
        `shouldBe` Left "The PSBT is of version 1: only versions 0 and 2 are supported"

    -- The length of the first key, 1, written over three bytes
    it "refuse a length that is not in its shortest form" $
      decodePsbt (hexBytes ("70736274ff" <> "fd0100" <> "000a00000000000000000000" <> "00"))
        `shouldBe` Left "A length in the global map is not in its shortest form"

    -- The PSBT with 0 inputs and 2 outputs of the BIP, without the two
    -- bytes that end its output maps
    it "refuse bytes that end inside a map" $ do
      let withoutOutputs = bytesOf (vectors.valid !! 9)
      decodePsbt (B.take (B.length withoutOutputs - 2) withoutOutputs) `shouldBe` Left "The PSBT ends inside output 0"

    it "refuse a key of the spec that carries data it should not, naming it" $
      decodePsbt (bytesOf (vectors.invalid !! 15)) `shouldBe` Left "Input 0: the key 0x03 with the data 00 carries data"

    it "refuse a derivation key that is not a public key" $
      decodePsbt (bytesOf (vectors.invalid !! 10)) `shouldSatisfy` either ("is not a public key" `isSuffixOf`) (const False)

    it "read the base64 text of a PSBT, with spaces and line breaks around it" $ do
      let v = vectors.valid !! 0
      (encodePsbt <$> decodePsbtBase64 (" " <> encodeUtf8 (fromMaybe "" v.vecBase64) <> "\n")) `shouldBe` Right (bytesOf v)

    it "write the base64 text the BIP gives" $ do
      let v = vectors.valid !! 0
      psbt <- psbtOfVector v
      Just (encodePsbtBase64 psbt) `shouldBe` (encodeUtf8 <$> v.vecBase64)

    it "refuse text that is not base64" $
      decodePsbtBase64 "not base64!" `shouldBe` Left "Not the base64 text of a PSBT"

{- Fields -}

-- | The signature of the first signer of the BIP on the first input, as
-- Bitcoin Core decodes its PSBT
firstSignature :: Text
firstSignature = "3044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01"

-- | The key of the first signer of the BIP, at m/0'/0'/0' of the master
-- key d90c6a4f
firstKey :: Text
firstKey = "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f"

-- The literal values below are those Bitcoin Core 25.0 shows for the
-- vectors with decodepsbt.
fieldsSpec :: Ctx -> Vectors -> Spec
fieldsSpec ctx vectors =
  describe "The fields of a PSBT" $ do
    let publicKey text = forceRight (unmarshal ctx (hexBytes text)) :: PublicKey
        shown :: [(PublicKey, Derivation)] -> [(Text, Derivation)]
        shown records = [(encodeHex (marshal ctx key), derivation) | (key, derivation) <- records]

    it "read the derivation records of an input: the public key, the fingerprint of the master key and the path" $ do
      psbt <- psbtOfVector (updater vectors)
      records <- expectRight $ inputDerivations ctx (inputAt 0 psbt)
      shown records
        `shouldBe` [ (firstKey, Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/0'"),
                     ("02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7", Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/1'")
                   ]

    it "read the derivation records of an output" $ do
      psbt <- psbtOfVector (updater vectors)
      records <- expectRight $ outputDerivations ctx (outputAt 0 psbt)
      shown records `shouldBe` [("03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771", Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/4'")]

    -- The path is 0' (0x80000000) three times, each over four bytes,
    -- little-endian
    it "write a derivation record as the public key under the type, and the fingerprint then the path, four bytes an index" $ do
      let key = publicKey firstKey
      Map.toList (insertInputDerivation ctx key (Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/0'") Map.empty)
        `shouldBe` [(Key 0x06 (hexBytes firstKey), hexBytes ("d90c6a4f" <> "00000080" <> "00000080" <> "00000080"))]
      Map.keys (insertOutputDerivation ctx key (Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/4'") Map.empty)
        `shouldBe` [Key 0x02 (hexBytes firstKey)]

    it "read the sighash type of an input, when it has one" $ do
      with <- psbtOfVector (updaterWithSigHash vectors)
      without <- psbtOfVector (updater vectors)
      mapM sigHashType with.inputs `shouldBe` Right [Just sigHashAll, Just sigHashAll]
      mapM sigHashType without.inputs `shouldBe` Right [Nothing, Nothing]

    -- SIGHASH_ALL with the FORKID flag of Bitcoin Cash, 0x41
    it "write the sighash type over four bytes, little-endian, and drop it as a finalizer does" $ do
      Map.toList (insertSigHashType (setForkIdFlag sigHashAll) Map.empty) `shouldBe` [(Key 0x03 "", hexBytes "41000000")]
      Map.keys (deleteSigHashType (insertSigHashType sigHashAll (insertNonWitnessUtxo emptyTx Map.empty))) `shouldBe` [Key 0x00 ""]

    it "read the whole previous transaction of an input" $ do
      psbt <- psbtOfVector (vectors.valid !! 0)
      parent <- expectRight $ nonWitnessUtxo (inputAt 0 psbt)
      (txHashToHex . txHash <$> parent) `shouldBe` Just "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126"

    it "write a previous transaction under the type 0x00" $ do
      psbt <- psbtOfVector (vectors.valid !! 0)
      parent <- expectRight $ nonWitnessUtxo (inputAt 0 psbt)
      Map.toList (insertNonWitnessUtxo emptyTx Map.empty) `shouldBe` [(Key 0x00 "", hexBytes "00000000000000000000")]
      nonWitnessUtxo (maybe Map.empty (`insertNonWitnessUtxo` Map.empty) parent) `shouldBe` Right parent

    -- The second input of the vector spends 1 BTC at a P2SH address
    it "read the output an input spends when the PSBT has it alone, and write it under the type 0x01" $ do
      psbt <- psbtOfVector (vectors.valid !! 1)
      let coin = TxOut 100000000 (hexBytes "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787")
      mapM witnessUtxo psbt.inputs `shouldBe` Right [Nothing, Just coin]
      Map.toList (insertWitnessUtxo coin Map.empty) `shouldBe` [(Key 0x01 "", hexBytes "00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787")]

    it "tell an input with partial signatures from one without" $ do
      partial <- psbtOfVector (vectors.valid !! 4)
      unsigned <- psbtOfVector (vectors.valid !! 0)
      hasPartialSignatures (inputAt 0 partial) `shouldBe` True
      hasPartialSignatures (inputAt 0 unsigned) `shouldBe` False

    -- The first signer of the BIP signs the first input with SIGHASH_ALL,
    -- the last byte 01 of the signature
    it "read the partial signatures of an input: the public key, and the signature with its sighash byte" $ do
      psbt <- psbtOfVector (firstSigner vectors)
      records <- expectRight (partialSignatures ctx (inputAt 0 psbt))
      [(encodeHex (marshal ctx key), encodeHex signature) | (key, signature) <- records] `shouldBe` [(firstKey, firstSignature)]

    it "write a partial signature under the type 0x02 with the public key, and drop them all as a finalizer does" $ do
      let m = insertPartialSignature ctx (publicKey firstKey) (hexBytes firstSignature) (insertSigHashType sigHashAll Map.empty)
      Map.toList m `shouldBe` [(Key 0x02 (hexBytes firstKey), hexBytes firstSignature), (Key 0x03 "", hexBytes "01000000")]
      Map.toList (deletePartialSignatures m) `shouldBe` [(Key 0x03 "", hexBytes "01000000")]

    -- The second input of the updater's PSBT spends a P2SH-P2WSH coin: a
    -- 2-of-2 multisig behind a witness program
    it "read the redeem script and the witness script of an input, and write them under the types 0x04 and 0x05" $ do
      psbt <- psbtOfVector (updater vectors)
      let redeem = Script [OP_0, opPushData (hexBytes "8c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903")]
          witness = Script [OP_2, opPushData (hexBytes "03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc"), opPushData (hexBytes "023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73"), OP_2, OP_CHECKMULTISIG]
      inputRedeemScript (inputAt 1 psbt) `shouldBe` Right (Just redeem)
      inputWitnessScript (inputAt 1 psbt) `shouldBe` Right (Just witness)
      inputRedeemScript (inputAt 0 psbt) `shouldSatisfy` (\found -> fmap (const ()) found == Right () && found /= Right Nothing)
      Map.toList (insertInputRedeemScript redeem (insertInputWitnessScript witness Map.empty))
        `shouldBe` [ (Key 0x04 "", hexBytes "00208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903"),
                     (Key 0x05 "", hexBytes "522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae")
                   ]

    it "read the redeem script and the witness script of an output, and write them under the types 0x00 and 0x01" $ do
      let redeem = Script [OP_0, opPushData (hexBytes "8c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903")]
          witness = Script [OP_1, OP_CHECKMULTISIG]
          m = insertOutputRedeemScript redeem (insertOutputWitnessScript witness Map.empty)
      Map.keys m `shouldBe` [Key 0x00 "", Key 0x01 ""]
      outputRedeemScript m `shouldBe` Right (Just redeem)
      outputWitnessScript m `shouldBe` Right (Just witness)
      outputWitnessScript Map.empty `shouldBe` Right Nothing

    it "read the final script and witness of a signed input" $ do
      psbt <- psbtOfVector (finalizer vectors)
      let first' = inputAt 0 psbt
          second = inputAt 1 psbt
      finalScriptSig first'
        `shouldBe` Just (hexBytes "00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae")
      finalScriptWitness first' `shouldBe` Right Nothing
      finalScriptSig second `shouldBe` Just (hexBytes "2200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903")
      finalScriptWitness second
        `shouldBe` Right
          ( Just
              [ "",
                hexBytes "3044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01",
                hexBytes "3044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d201",
                hexBytes "522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae"
              ]
          )

    it "write a final script under the type 0x07, and a final witness as the number of its items then each after its length" $ do
      Map.toList (insertFinalScriptSig (hexBytes "aabb") Map.empty) `shouldBe` [(Key 0x07 "", hexBytes "aabb")]
      Map.toList (insertFinalScriptWitness [hexBytes "aabb", ""] Map.empty) `shouldBe` [(Key 0x08 "", hexBytes "0202aabb00")]

    it "read the extended public keys of the global map, with their derivations, and write them under the type 0x01" $ do
      psbt <- psbtOfVector (vectors.valid !! 7)
      let xpub = fromJust $ xPubImport btc ctx "xpub6CpGH79LXVkeiux2ZPWMpEubBrRfgcGCgy2HiagyN6NW3qdioJaqFYyD1fG6LDfxWEhMXJqcDuU5VneKt5UQYUGPa5Mfxdw2D2NArwX5TBm"
          record = (xpub, Derivation (fingerprintOf "27569c50") "m/49'/0'/0'")
      xpubRecords btc ctx psbt.globals `shouldBe` Right [record]
      let m = insertXpubRecord btc ctx xpub (snd record) Map.empty
      Map.keys m `shouldBe` [Key 0x01 (marshal (btc, ctx) xpub)]
      xpubRecords btc ctx m `shouldBe` Right [record]

    -- The two keys of the vector are of the test network
    it "leave aside the extended public keys of another network" $ do
      psbt <- psbtOfVector (vectors.valid !! 5)
      let tpub text = fromJust $ xPubImport btcTest ctx text
      xpubRecords btc ctx psbt.globals `shouldBe` Right []
      xpubRecords btcTest ctx psbt.globals
        `shouldBe` Right
          [ (tpub "tpubDBkJeJo2X94Yq3RVz65DoUgyLUkaDrkfyrn2VcgyCRSKCRonvKvCF2FpYDGJWDkdRHBajXJGpc63GnumUt63ySvqCu2XaTRGVTKMYGuFk9H", Derivation (fingerprintOf "d90c6a4f") "m/174'/0'"),
            (tpub "tpubDBkJeJo2X94YsvtBEU1eKoibEWiNv51nW5iHhs6VZp59jsE6nen8KZMFyGHuGbCvqjRqirgeMcfpVBkttpUUT6brm4duzSGoZeTbhqCNUu6", Derivation (fingerprintOf "d90c6a4f") "m/174'/1'")
          ]

    it "write a proprietary key as the type 0xfc, the identifier after its length, the subtype and the data" $ do
      proprietaryKey (Proprietary "test" 1 (hexBytes "ab")) `shouldBe` Key 0xfc (hexBytes "047465737401ab")
      proprietaryOf (Key 0xfc (hexBytes "047465737401ab")) `shouldBe` Right (Just (Proprietary "test" 1 (hexBytes "ab")))
      proprietaryOf (Key 0x20 "") `shouldBe` Right Nothing
      proprietaryOf (Key 0xfc "") `shouldBe` Left "the proprietary key 0xfc has no identifier and subtype"

    it "look a proprietary field up by its identifier and subtype" $ do
      let m = insertProprietary "test" 3 "Rent" Map.empty
      lookupProprietary "test" 3 m `shouldBe` Just "Rent"
      lookupProprietary "test" 2 m `shouldBe` Nothing
      lookupProprietary "other" 3 m `shouldBe` Nothing

{- Signing and finalizing -}

-- | A coin of 2 BTC at the script, spent whole by a transaction paying
-- two outputs, as a PSBT with the coin on its input: the whole previous
-- transaction, and the output alone for a SegWit coin
spendingPsbt :: Ctx -> ScriptOutput -> (Psbt, [(ScriptOutput, Word64, OutPoint)])
spendingPsbt ctx coinScript = (Psbt Version0 tx Map.empty [input] [Map.empty, Map.empty], [(coinScript, 200000000, outpoint)])
  where
    parent = Tx 1 [TxIn (OutPoint "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389" 1) "" 0xffffffff] [TxOut 200000000 (marshal ctx coinScript)] [] 0
    outpoint = OutPoint (txHash parent) 0
    tx =
      Tx
        2
        [TxIn outpoint "" 0xfffffffe]
        [ TxOut 99999699 (hexBytes "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac"),
          TxOut 100000000 (hexBytes "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787")
        ]
        []
        1257139
    input
      | isSegwit coinScript = insertWitnessUtxo (TxOut 200000000 (marshal ctx coinScript)) Map.empty
      | otherwise = insertNonWitnessUtxo parent Map.empty

-- | A derivation record of a key, which a signer needs: the fingerprint
-- and the path are those of the BIP's first signer
recordOf :: Ctx -> PublicKey -> PsbtMap -> PsbtMap
recordOf ctx public = insertInputDerivation ctx public (Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/0'")

-- | A signer holding the keys
keysSigner :: Ctx -> [PrivateKey] -> Signer
keysSigner ctx keys public derivation = foldr (\key found -> keySigner ctx key.key public derivation `orElse` found) Nothing keys
  where
    orElse (Just a) _ = Just a
    orElse Nothing b = b

-- | Whether the transaction of the PSBT, once signed with the keys and
-- finalized, verifies against the coins it spends
signsAndVerifies :: Network -> Ctx -> [PrivateKey] -> (Psbt, [(ScriptOutput, Word64, OutPoint)]) -> Either String Bool
signsAndVerifies net ctx keys (psbt, coins) = do
  signed <- signPsbt net ctx (keysSigner ctx keys) psbt
  final <- finalizePsbt ctx signed
  tx <- psbtTransaction final
  return (verifyStdTx net ctx tx coins)

signingSpec :: Ctx -> Spec
signingSpec ctx =
  describe "Signing and finalizing" $ do
    prop "a P2PKH coin, signed with the key of its address and finalized, verifies" $
      forAll (arbitraryKeyPair ctx) $ \(secret, public) ->
        let (psbt, coins) = spendingPsbt ctx (PayPKHash (addressHash (marshal ctx public)))
            withRecord = withInputs (recordOf ctx public <$> psbt.inputs) psbt
         in signsAndVerifies btc ctx [secret] (withRecord, coins) === Right True

    -- The finalized input keeps its coin, its final script, and the
    -- fields of version 2: the transaction it spends from, the output
    -- index and the sequence
    prop "a P2PKH coin of a PSBT of version 2, signed and finalized, verifies, and the PSBT stays of version 2 with the fields of its input" $
      forAll (arbitraryKeyPair ctx) $ \(secret, public) ->
        let (psbt, coins) = spendingPsbt ctx (PayPKHash (addressHash (marshal ctx public)))
            version2 = withVersion Version2 (withInputs (recordOf ctx public <$> psbt.inputs) psbt)
            final = finalizePsbt ctx =<< signPsbt btc ctx (keysSigner ctx [secret]) version2
         in (signsAndVerifies btc ctx [secret] (version2, coins), (.version) <$> final, Map.keys . inputAt 0 <$> final)
              === (Right True, Right Version2, Right [Key 0x00 "", Key 0x07 "", Key 0x0e "", Key 0x0f "", Key 0x10 ""])

    prop "a P2SH multisig coin, signed with enough of its keys and finalized, verifies" $
      forAll ((,) <$> arbitraryMSParam <*> arbitraryKeyPair ctx) $ \((m, n), _) ->
        forAll (vectorOf n (arbitraryKeyPair ctx)) $ \pairs ->
          let redeem = either error id $ encodeOutput ctx (PayMulSig (snd <$> pairs) m)
              (psbt, coins) = spendingPsbt ctx (toP2SH redeem)
              withFields = withInputs ((insertInputRedeemScript redeem . foldr (\(_, public) f -> recordOf ctx public . f) id pairs) <$> psbt.inputs) psbt
           in signsAndVerifies btc ctx (fst <$> take m pairs) (withFields, coins) === Right True

    prop "a P2WPKH coin, and a P2SH-P2WPKH one with its redeem script, signed and finalized, verify" $
      forAll (arbitraryKeyPair ctx) $ \(secret, public) ->
        let program = PayWitnessPKHash (addressHash (marshal ctx public))
            (native, nativeCoins) = spendingPsbt ctx program
            redeem = either error id $ encodeOutput ctx program
            (nested, nestedCoins) = spendingPsbt ctx (toP2SH redeem)
            nativeWithRecord = withInputs (recordOf ctx public <$> native.inputs) native
            nestedWithFields = withInputs ((insertInputRedeemScript redeem . recordOf ctx public) <$> nested.inputs) nested
         in signsAndVerifies btc ctx [secret] (nativeWithRecord, nativeCoins) === Right True
              .&&. signsAndVerifies btc ctx [secret] (nestedWithFields, nestedCoins) === Right True

    prop "a P2WSH multisig coin with its witness script, nested in P2SH or not, signed and finalized, verifies" $
      forAll arbitraryMSParam $ \(m, n) ->
        forAll (vectorOf n (arbitraryKeyPair ctx)) $ \pairs ->
          let witness = either error id $ encodeOutput ctx (PayMulSig (snd <$> pairs) m)
              program = toP2WSH witness
              records = foldr (\(_, public) f -> recordOf ctx public . f) id pairs
              (native, nativeCoins) = spendingPsbt ctx program
              (nested, nestedCoins) = spendingPsbt ctx (toP2SH programScript)
              nativeWithFields = withInputs ((insertInputWitnessScript witness . records) <$> native.inputs) native
              nestedWithFields = withInputs ((insertInputRedeemScript programScript . insertInputWitnessScript witness . records) <$> nested.inputs) nested
              programScript = either error id $ encodeOutput ctx program
           in signsAndVerifies btc ctx (fst <$> take m pairs) (nativeWithFields, nativeCoins) === Right True
                .&&. signsAndVerifies btc ctx (fst <$> take m pairs) (nestedWithFields, nestedCoins) === Right True

    it "signs with the sighash the input asks for, SIGHASH_ALL when it asks for none" $ do
      (secret, public) <- generate (arbitraryKeyPair ctx)
      let (psbt, _) = spendingPsbt ctx (PayPKHash (addressHash (marshal ctx public)))
          asking sh = withInputs ((recordOf ctx public . maybe id insertSigHashType sh) <$> psbt.inputs) psbt
          sighashOf signed = map (B.last . snd) <$> partialSignatures ctx (inputAt 0 signed)
      (sighashOf =<< signPsbt btc ctx (keySigner ctx secret.key) (asking Nothing)) `shouldBe` Right [0x01]
      (sighashOf =<< signPsbt btc ctx (keySigner ctx secret.key) (asking (Just sigHashNone))) `shouldBe` Right [0x02]

    it "leaves an input without its coin, or signed already, as it is" $ do
      (secret, public) <- generate (arbitraryKeyPair ctx)
      let (psbt, _) = spendingPsbt ctx (PayPKHash (addressHash (marshal ctx public)))
          withoutCoin = withInputs [recordOf ctx public Map.empty] psbt
          final = withInputs ((insertFinalScriptSig "a script" . recordOf ctx public) <$> psbt.inputs) psbt
      signPsbt btc ctx (keySigner ctx secret.key) withoutCoin `shouldBe` Right withoutCoin
      signPsbt btc ctx (keySigner ctx secret.key) final `shouldBe` Right final

    it "refuses a previous transaction that is not the one the input spends" $ do
      (_, public) <- generate (arbitraryKeyPair ctx)
      let (psbt, _) = spendingPsbt ctx (PayPKHash (addressHash (marshal ctx public)))
          wrong = withInputs [insertNonWitnessUtxo emptyTx Map.empty] psbt
      signPsbt btc ctx (\_ _ -> Nothing) wrong `shouldBe` Left "The previous transaction of the input is not the one it spends"

    -- The derivation records name keys by the master key, b4a6ba67 with
    -- the full path, or by the extended key given, with the path from it
    it "finds the key an extended private key derives, by its own fingerprint or by the origin given" $ do
      let root = makeXPrvKey "PSBT signer test"
          rootFingerprint = xPubFP ctx (deriveXPubKey ctx root)
          account = derivePath ctx (Deriv :| 444 :: HardPath) root
          accountFingerprint = xPubFP ctx (deriveXPubKey ctx account)
          secretAt path = (derivePath ctx (path :: DerivPath) root).key
          publicOf secret = PublicKey (derivePubKey ctx secret) True
          signer = xPrvSigner ctx account (Just (Derivation rootFingerprint "m/444'"))
          unknownOrigin = xPrvSigner ctx account Nothing
      signer (publicOf (secretAt "m/444'/0")) (Derivation rootFingerprint "m/444'/0") `shouldBe` Just (secretAt "m/444'/0")
      signer (publicOf (secretAt "m/444'/1")) (Derivation accountFingerprint "m/1") `shouldBe` Just (secretAt "m/444'/1")
      signer (publicOf (secretAt "m/444'/1")) (Derivation rootFingerprint "m/445'/1") `shouldBe` Nothing
      signer (publicOf (secretAt "m/444'/1")) (Derivation accountFingerprint "m/2") `shouldBe` Nothing
      unknownOrigin (publicOf (secretAt "m/444'/0")) (Derivation rootFingerprint "m/444'/0") `shouldBe` Nothing
      unknownOrigin (publicOf (secretAt "m/444'/0")) (Derivation accountFingerprint "m/0") `shouldBe` Just (secretAt "m/444'/0")

{- A PSBT of every kind of coin -}

-- | The PSBTs of data/complex_psbt.json: a transaction of twelve coins
-- of every kind, signed by Bitcoin Core one coin at a time, their
-- combination, its finalization and the transaction it gives
data Complex = Complex
  { signedPsbts :: [Psbt],
    combinedPsbt :: Psbt,
    completePsbt :: Psbt,
    finalTx :: Tx
  }

instance Json.FromJSON Complex where
  parseJSON = Json.withObject "complex" $ \o ->
    Complex
      <$> mapM (psbtAt o) ["miner_psbt", "p2pkh_psbt", "p2sh_ms_1_psbt", "p2sh_ms_2_psbt", "p2sh_pk_psbt", "p2sh_wsh_pk_psbt", "p2sh_wsh_ms_1_psbt", "p2sh_wsh_ms_2_psbt", "p2wpkh_psbt", "p2wsh_pk_psbt", "p2wsh_ms_1_psbt", "p2wsh_ms_2_psbt"]
      <*> psbtAt o "combined_psbt"
      <*> psbtAt o "complete_psbt"
      <*> (either fail return . S.decode . hexBytes =<< o .: "final_tx")
    where
      psbtAt o name = either fail return . decodePsbtBase64 . encodeUtf8 =<< o .: name

complexSpec :: Ctx -> Spec
complexSpec ctx =
  describe "The PSBT of twelve coins of every kind, which Bitcoin Core signed one at a time" $ do
    complex <- runIO (readTestFile "complex_psbt.json" :: IO Complex)
    it "combines into the PSBT Core combined" $
      case complex.signedPsbts of
        first' : rest -> foldM combinePsbt first' rest `shouldBe` Right complex.combinedPsbt
        [] -> expectationFailure "No signed PSBT"

    it "finalizes into the PSBT Core finalized" $
      finalizePsbt ctx complex.combinedPsbt `shouldBe` Right complex.completePsbt

    it "gives the transaction Core extracted" $
      psbtTransaction complex.completePsbt `shouldBe` Right complex.finalTx

{- The files of Bitcoin Core 32.1 -}

-- The files live in data/psbt_core32.json: the PSBT of a payment as
-- walletcreatefundedpsbt gives it in version 0 and in version 2, the
-- version 2 one signed by walletprocesspsbt without finalizing, then
-- finalized, and the transaction finalizepsbt extracts
data Core32 = Core32
  { preparedV0 :: Psbt,
    preparedV2 :: Psbt,
    signedV2 :: Psbt,
    finalizedV2 :: Psbt,
    extractedTx :: Tx
  }

instance Json.FromJSON Core32 where
  parseJSON = Json.withObject "core32" $ \o ->
    Core32
      <$> psbtAt o "prepared_v0"
      <*> psbtAt o "prepared_v2"
      <*> psbtAt o "signed_v2"
      <*> psbtAt o "finalized_v2"
      <*> (either fail return . S.decode . hexBytes =<< o .: "final_tx")
    where
      psbtAt o name = either fail return . decodePsbtBase64 . encodeUtf8 =<< o .: name

core32Spec :: Ctx -> Spec
core32Spec ctx =
  describe "The files of Bitcoin Core 32.1, which writes version 2 unless asked for version 0" $ do
    core <- runIO (readTestFile "psbt_core32.json" :: IO Core32)
    it "are the same payment in both versions: the version 2 file is the version 0 file converted, and back" $ do
      core.preparedV2.version `shouldBe` Version2
      core.preparedV2.unsignedTx `shouldBe` core.preparedV0.unsignedTx
      withVersion Version2 core.preparedV0 `shouldBe` core.preparedV2
      withVersion Version0 core.preparedV2 `shouldBe` core.preparedV0

    it "finalize into the PSBT Core finalized" $
      finalizePsbt ctx core.signedV2 `shouldBe` Right core.finalizedV2

    it "give the transaction Core extracted" $
      psbtTransaction core.finalizedV2 `shouldBe` Right core.extractedTx

    -- The records name the key of the coin by the fingerprint bc560f95 of
    -- a seed and the path m/44'/0'/0'/0/0: the account key at m/44'/0'/0'
    -- of that seed signs. The coin is 50 BTC at the P2PKH script of that
    -- key.
    it "are signed with the account key the records name, into a transaction that verifies" $ do
      let account = fromJust (xPrvImport btc "xprv9yHxeaLAZvxXb9VtJNesqk8avfN8misGAW9DUW9eacZJNqsfZxqKLmK5jfmvFideQqGesviJeagzSQYCuQySjgvt7TdfowKja5aJqbgyuNh")
          signer = xPrvSigner ctx account (Just (Derivation (fingerprintOf "bc560f95") "m/44'/0'/0'"))
      coin <- expectRight (unmarshal ctx (hexBytes "76a914c80d55223e2f1061363add2a7b0363c285bf298d88ac"))
      final <- expectRight (finalizePsbt ctx =<< signPsbt btc ctx signer core.preparedV2)
      tx <- expectRight (psbtTransaction final)
      final.version `shouldBe` Version2
      verifyStdTx btc ctx tx [(coin, 5000000000, OutPoint "fede72ccadbf9f16f826e3078578b0660526a37b48d4f894ab26f4cf5a95e89c" 0)] `shouldBe` True

{- Properties -}

propertiesSpec :: Ctx -> Spec
propertiesSpec ctx =
  describe "Any PSBT" $ do
    prop "is read back as it was written" $
      forAll (arbitraryPsbt btc ctx) $ \psbt -> decodePsbt (encodePsbt psbt) == Right psbt

    prop "is read back from its base64 text" $
      forAll (arbitraryPsbt btc ctx) $ \psbt -> decodePsbtBase64 (encodePsbtBase64 psbt) == Right psbt

    prop "combined with itself is itself" $
      forAll (arbitraryPsbt btc ctx) $ \psbt -> combinePsbt psbt psbt == Right psbt
