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
import Data.Bits (xor)
import Data.ByteString qualified as B
import Data.List (isPrefixOf, isSuffixOf)
import Crypto.Hash (Digest, SHA256, digestFromByteString)
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (serialize)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromJust, fromMaybe, isJust, listToMaybe, mapMaybe)
import Data.Serialize qualified as S
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding (encodeUtf8)
import Data.Word (Word32, Word64, Word8)
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

-- | The secret keys 1, 2 and 3 of the signer tests. Their public keys are
-- the points G, 2G and 3G of the curve.
secretOne, secretTwo, secretThree :: SecKey
secretOne = "0000000000000000000000000000000000000000000000000000000000000001"
secretTwo = "0000000000000000000000000000000000000000000000000000000000000002"
secretThree = "0000000000000000000000000000000000000000000000000000000000000003"

-- | The compressed public key of a secret key
compressedKey :: Ctx -> SecKey -> PublicKey
compressedKey ctx secret = PublicKey (derivePubKey ctx secret) True

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
  vectors371 <- runIO (readTestFile "psbt_bip371.json" :: IO Vectors371)
  prepareContext $ \ctx -> do
    vectorsSpec vectors
    vectors370Spec vectors370
    rolesSpec ctx vectors
    version2Spec
    bytesSpec vectors
    fieldsSpec ctx vectors
    signingSpec ctx
    signerChecksSpec ctx
    signerScopeSpec ctx
    coinsSpec ctx
    version2FieldsSpec
    taprootChecksSpec ctx vectors371
    decoderChecksSpec
    taprootSpec ctx vectors371
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

-- | Why each invalid PSBT of BIP 174 is refused, in the order of the BIP,
-- as the start of the reason. The cases are: no magic bytes, a map
-- missing, a script in the unsigned transaction, no unsigned transaction,
-- a key twice, twelve keys whose data is not what their type takes, and
-- an unsigned transaction that is not in the serialization without witness
-- or not whole.
refusals174 :: [String]
refusals174 =
  [ "Not a PSBT: the bytes do not start with the magic bytes of BIP 174",
    "The PSBT ends inside output 0",
    "The unsigned transaction has an input with a script",
    "The global map has no unsigned transaction",
    "Input 0 has the key 0x00 twice",
    "The global map: the key 0x00 with the data 01 carries data",
    "Input 0: the key 0x01 with the data 00 carries data",
    "Input 0: the key 0x02 with the data 03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd is not a public key",
    "Input 0: the key 0x04 with the data 00 carries data",
    "Input 0: the key 0x05 with the data 00 carries data",
    "Input 0: the key 0x06 with the data 03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd is not a public key",
    "Input 0: the key 0x00 with the data 00 carries data",
    "Input 0: the key 0x07 with the data 00 carries data",
    "Input 1: the key 0x08 with the data 00 carries data",
    "Output 0: the key 0x02 with the data 03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca587 is not a public key",
    "Input 0: the key 0x03 with the data 00 carries data",
    "Output 0: the key 0x00 with the data 00 carries data",
    "Output 1: the key 0x01 with the data 0025512103b7ce23a01c5b4bf00a642537cdfabb315b668332867478ef51309d",
    "The unsigned transaction does not decode",
    "The unsigned transaction does not decode"
  ]

vectorsSpec :: Vectors -> Spec
vectorsSpec vectors = do
  describe "The invalid PSBTs of BIP 174 are refused, each for its reason" $
    forM_ (zip vectors.invalid refusals174) $ \(v, reason) ->
      it v.vecCase $ decodePsbt (bytesOf v) `shouldSatisfy` either (reason `isPrefixOf`) (const False)

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

    -- BIP 174: the extractor "checks whether all inputs have complete
    -- scriptSigs and scriptWitnesses", and otherwise "must not modify the
    -- PSBT". Bitcoin Core gives no transaction then (FinalizeAndExtractPSBT).
    it "the transaction extractor refuses a PSBT with an input that is not final" $ do
      psbt <- psbtOfVector (creator vectors)
      psbtTransaction psbt `shouldBe` Left "Input 0 is not final"

    it "the transaction of a PSBT that is still being signed has the final scripts of the inputs that have them" $ do
      unsigned <- psbtOfVector (creator vectors)
      psbtPartialTransaction unsigned `shouldBe` Right unsigned.unsignedTx
      final <- psbtOfVector (finalizer vectors)
      -- The second input loses its final script and witness
      let halfFinal = withInputs [inputAt 0 final, Map.delete (Key 0x07 "") (Map.delete (Key 0x08 "") (inputAt 1 final))] final
      psbtTransaction halfFinal `shouldBe` Left "Input 1 is not final"
      (map (B.null . (.script)) . (.inputs) <$> psbtPartialTransaction halfFinal) `shouldBe` Right [False, True]
      ((.witness) <$> psbtPartialTransaction halfFinal) `shouldBe` Right []

    -- The updater's PSBT gives the coin of its second input, a P2SH-P2WSH
    -- one, as a witness output only, as BIP 174 did before CVE-2020-14199
    -- was known. A signer that wants previous transactions refuses it.
    it "a signer that trusts witness outputs makes the first signer's PSBT of the BIP from the updater's, and the second signer's" $ do
      psbt <- psbtOfVector (updaterWithSigHash vectors)
      let master = fromJust (xPrvImport btcTest "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF")
          trusting = (xPrvSigner ctx master Nothing) {requirePreviousTx = False}
          holding paths = trusting {keyOfRecord = \public derivation -> if derivation.path `elem` paths then trusting.keyOfRecord public derivation else Nothing}
      (encodePsbt <$> signPsbt btcTest ctx (holding ["m/0'/0'/0'", "m/0'/0'/2'"]) psbt) `shouldBe` Right (bytesOf (firstSigner vectors))
      (encodePsbt <$> signPsbt btcTest ctx (holding ["m/0'/0'/1'", "m/0'/0'/3'"]) psbt) `shouldBe` Right (bytesOf (secondSigner vectors))
      signPsbt btcTest ctx (xPrvSigner ctx master Nothing) psbt
        `shouldBe` Left "Input 1: the coin is given as a witness output only, and the signer requires the previous transaction of a SegWit version 0 coin"

    -- The four cases the BIP lists under "Fails Signer checks", signed
    -- with the master key of the BIP. The input at fault never gains a
    -- signature. The numbers are the partial signatures of each input.
    describe "a signer adds no signature to the input at fault of the PSBTs that fail the signer checks of the BIP" $ do
      let master = fromJust (xPrvImport btcTest "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF")
          trusting = (xPrvSigner ctx master Nothing) {requirePreviousTx = False}
          counts = mapM (fmap length . partialSignatures ctx) . (.inputs)
          failing i = psbtOfVector (vectors.valid !! i)
      -- No record names a key, so the signer holds none: nothing is signed
      it "a witness output for a legacy coin" $ do
        psbt <- failing 10
        counts psbt `shouldBe` Right [0, 0]
        (counts =<< signPsbt btcTest ctx trusting psbt) `shouldBe` Right [0, 0]
      -- The redeem script of input 0 is no standard script, and does not
      -- hash to the coin. Input 1 is sound and is signed.
      it "a redeem script that does not match the coin, with the previous transaction" $ do
        psbt <- failing 11
        counts psbt `shouldBe` Right [1, 1]
        (counts =<< signPsbt btcTest ctx trusting psbt) `shouldBe` Right [1, 2]
      it "a redeem script that does not match the coin, with the witness output" $ do
        psbt <- failing 12
        signPsbt btcTest ctx trusting psbt `shouldBe` Left "Input 1: the redeem script of the input does not hash to its coin"
      -- The witness script of input 1 is no standard script. Input 0 is
      -- sound and is signed.
      it "a witness script that does not match the redeem script" $ do
        psbt <- failing 13
        counts psbt `shouldBe` Right [1, 1]
        (counts =<< signPsbt btcTest ctx trusting psbt) `shouldBe` Right [2, 1]

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
      (encodePsbt <$> finalizePsbt btc ctx psbt) `shouldBe` Right (bytesOf (finalizer vectors))

    it "the finalizer leaves an input without enough signatures as it is" $ do
      psbt <- psbtOfVector (firstSigner vectors)
      finalizePsbt btc ctx psbt `shouldBe` Right psbt

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
      -- A signature commits to the sequence of its input
      setInputSequence 0 1 (withInputs [insertFinalScriptSig "\x00" (inputAt 0 built)] built) `shouldBe` Left "Input 0 is signed already: its sequence may not change"

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
-- transaction, or the output alone for a Taproot coin, whose signature
-- commits to the output of every input (BIP 341)
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
    input = case coinScript of
      PayWitness 1 _ -> insertWitnessUtxo (TxOut 200000000 (marshal ctx coinScript)) Map.empty
      _ -> insertNonWitnessUtxo parent Map.empty

-- | A derivation record of a key, which a signer needs: the fingerprint
-- and the path are those of the BIP's first signer
recordOf :: Ctx -> PublicKey -> PsbtMap -> PsbtMap
recordOf ctx public = insertInputDerivation ctx public (Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/0'")

-- | A signer holding the keys
keysSigner :: Ctx -> [PrivateKey] -> Signer
keysSigner ctx keys =
  Signer
    { keyOfRecord = \public derivation -> listToMaybe (mapMaybe (\key -> (keySigner ctx key.key).keyOfRecord public derivation) keys),
      keyOfHash = \h -> listToMaybe (mapMaybe (\key -> (keySigner ctx key.key).keyOfHash h) keys),
      acceptedSigHashes = defaultSigHashes,
      requirePreviousTx = True
    }

-- | Whether the transaction of the PSBT, once signed with the keys and
-- finalized, verifies against the coins it spends
signsAndVerifies :: Network -> Ctx -> [PrivateKey] -> (Psbt, [(ScriptOutput, Word64, OutPoint)]) -> Either String Bool
signsAndVerifies net ctx keys (psbt, coins) = do
  signed <- signPsbt net ctx (keysSigner ctx keys) psbt
  final <- finalizePsbt net ctx signed
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
            final = finalizePsbt btc ctx =<< signPsbt btc ctx (keysSigner ctx [secret]) version2
         in (signsAndVerifies btc ctx [secret] (version2, coins), (.version) <$> final, Map.keys . inputAt 0 <$> final)
              === (Right True, Right Version2, Right [Key 0x00 "", Key 0x07 "", Key 0x0e "", Key 0x0f "", Key 0x10 ""])

    prop "a P2SH multisig coin, signed with enough of its keys and finalized, verifies" $
      -- At most 7 keys: the redeem script of more uncompressed keys would be
      -- over the 520 bytes a P2SH redeem script can have
      forAll ((,) <$> arbitraryP2SHMSParam <*> arbitraryKeyPair ctx) $ \((m, n), _) ->
        forAll (vectorOf n (arbitraryKeyPair ctx)) $ \pairs ->
          let redeem = either error id $ encodeOutput ctx (PayMulSig (snd <$> pairs) m)
              (psbt, coins) = spendingPsbt ctx (either error id (toP2SH redeem))
              withFields = withInputs ((insertInputRedeemScript redeem . foldr (\(_, public) f -> recordOf ctx public . f) id pairs) <$> psbt.inputs) psbt
           in signsAndVerifies btc ctx (fst <$> take m pairs) (withFields, coins) === Right True

    -- The keys are compressed: a SegWit version 0 coin is not signed with
    -- an uncompressed key, which 'signerScopeSpec' tests
    prop "a P2WPKH coin, and a P2SH-P2WPKH one with its redeem script, signed and finalized, verify" $
      forAll (arbitraryKeyPairC ctx) $ \(secret, public) ->
        let program = PayWitnessPKHash (addressHash (marshal ctx public))
            (native, nativeCoins) = spendingPsbt ctx program
            redeem = either error id $ encodeOutput ctx program
            (nested, nestedCoins) = spendingPsbt ctx (either error id (toP2SH redeem))
            nativeWithRecord = withInputs (recordOf ctx public <$> native.inputs) native
            nestedWithFields = withInputs ((insertInputRedeemScript redeem . recordOf ctx public) <$> nested.inputs) nested
         in signsAndVerifies btc ctx [secret] (nativeWithRecord, nativeCoins) === Right True
              .&&. signsAndVerifies btc ctx [secret] (nestedWithFields, nestedCoins) === Right True

    prop "a P2WSH multisig coin with its witness script, nested in P2SH or not, signed and finalized, verifies" $
      forAll arbitraryMSParam $ \(m, n) ->
        forAll (vectorOf n (arbitraryKeyPairC ctx)) $ \pairs ->
          let witness = either error id $ encodeOutput ctx (PayMulSig (snd <$> pairs) m)
              program = either error id (toP2WSH witness)
              records = foldr (\(_, public) f -> recordOf ctx public . f) id pairs
              (native, nativeCoins) = spendingPsbt ctx program
              (nested, nestedCoins) = spendingPsbt ctx (either error id (toP2SH programScript))
              nativeWithFields = withInputs ((insertInputWitnessScript witness . records) <$> native.inputs) native
              nestedWithFields = withInputs ((insertInputRedeemScript programScript . insertInputWitnessScript witness . records) <$> nested.inputs) nested
              programScript = either error id $ encodeOutput ctx program
           in signsAndVerifies btc ctx (fst <$> take m pairs) (nativeWithFields, nativeCoins) === Right True
                .&&. signsAndVerifies btc ctx (fst <$> take m pairs) (nestedWithFields, nestedCoins) === Right True

    it "signs with the sighash the input asks for when the signer accepts it, SIGHASH_ALL when it asks for none" $ do
      let secret = PrivateKey secretOne True
          public = derivePublicKey ctx secret
          (psbt, _) = spendingPsbt ctx (PayPKHash (addressHash (marshal ctx public)))
          asking sh = withInputs ((recordOf ctx public . maybe id insertSigHashType sh) <$> psbt.inputs) psbt
          sighashOf signed = map (B.last . snd) <$> partialSignatures ctx (inputAt 0 signed)
          acceptingNone = (keySigner ctx secret.key) {acceptedSigHashes = sigHashNone : defaultSigHashes}
      (sighashOf =<< signPsbt btc ctx (keySigner ctx secret.key) (asking Nothing)) `shouldBe` Right [0x01]
      (sighashOf =<< signPsbt btc ctx (keySigner ctx secret.key) (asking (Just sigHashAll))) `shouldBe` Right [0x01]
      -- SIGHASH_NONE leaves the outputs unsigned, so the signer must agree to it
      signPsbt btc ctx (keySigner ctx secret.key) (asking (Just sigHashNone)) `shouldBe` Left "Input 0: the sighash type 2 is not one the signer accepts"
      (sighashOf =<< signPsbt btc ctx acceptingNone (asking (Just sigHashNone))) `shouldBe` Right [0x02]

    it "leaves an input without its coin, or signed already, as it is" $ do
      let secret = PrivateKey secretOne True
          public = derivePublicKey ctx secret
          (psbt, _) = spendingPsbt ctx (PayPKHash (addressHash (marshal ctx public)))
          withoutCoin = withInputs [recordOf ctx public Map.empty] psbt
          final = withInputs ((insertFinalScriptSig "a script" . recordOf ctx public) <$> psbt.inputs) psbt
      signPsbt btc ctx (keySigner ctx secret.key) withoutCoin `shouldBe` Right withoutCoin
      signPsbt btc ctx (keySigner ctx secret.key) final `shouldBe` Right final

    it "refuses a previous transaction that is not the one the input spends" $ do
      let public = compressedKey ctx secretOne
          (psbt, _) = spendingPsbt ctx (PayPKHash (addressHash (marshal ctx public)))
          wrong = withInputs [insertNonWitnessUtxo emptyTx Map.empty] psbt
      signPsbt btc ctx (Signer (\_ _ -> Nothing) (const Nothing) defaultSigHashes True) wrong `shouldBe` Left "Input 0: the previous transaction is not the one the input spends"

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
      signer.keyOfRecord (publicOf (secretAt "m/444'/0")) (Derivation rootFingerprint "m/444'/0") `shouldBe` Just (secretAt "m/444'/0")
      signer.keyOfRecord (publicOf (secretAt "m/444'/1")) (Derivation accountFingerprint "m/1") `shouldBe` Just (secretAt "m/444'/1")
      signer.keyOfRecord (publicOf (secretAt "m/444'/1")) (Derivation rootFingerprint "m/445'/1") `shouldBe` Nothing
      signer.keyOfRecord (publicOf (secretAt "m/444'/1")) (Derivation accountFingerprint "m/2") `shouldBe` Nothing
      unknownOrigin.keyOfRecord (publicOf (secretAt "m/444'/0")) (Derivation rootFingerprint "m/444'/0") `shouldBe` Nothing
      unknownOrigin.keyOfRecord (publicOf (secretAt "m/444'/0")) (Derivation accountFingerprint "m/0") `shouldBe` Just (secretAt "m/444'/0")
      -- An extended key cannot know which path a hash is at
      signer.keyOfHash (addressHash (marshal ctx (publicOf (secretAt "m/444'/0")))) `shouldBe` Nothing

{- A PSBT of every kind of coin -}

-- | The PSBTs of a file that scripts/create_complex_psbt_data.sh wrote: a
-- transaction of nine coins of every kind, signed by twelve wallets of
-- Bitcoin Core one at a time, their combination, its finalization and the
-- transaction it gives
data Complex = Complex
  { initialPsbt :: Psbt,
    signedPsbts :: [Psbt],
    combinedPsbt :: Psbt,
    completePsbt :: Psbt,
    finalTx :: Tx
  }

instance Json.FromJSON Complex where
  parseJSON = Json.withObject "complex" $ \o ->
    Complex
      <$> psbtAt o "initial_psbt"
      <*> mapM (psbtAt o) ["miner_psbt", "p2pkh_psbt", "p2sh_ms_1_psbt", "p2sh_ms_2_psbt", "p2sh_pk_psbt", "p2sh_wsh_pk_psbt", "p2sh_wsh_ms_1_psbt", "p2sh_wsh_ms_2_psbt", "p2wpkh_psbt", "p2wsh_pk_psbt", "p2wsh_ms_1_psbt", "p2wsh_ms_2_psbt"]
      <*> psbtAt o "combined_psbt"
      <*> psbtAt o "complete_psbt"
      <*> (either fail return . S.decode . hexBytes =<< o .: "final_tx")
    where
      psbtAt o name = either fail return . decodePsbtBase64 . encodeUtf8 =<< o .: name

complexSpec :: Ctx -> Spec
complexSpec ctx = do
  -- data/complex_psbt.json is the file of an older Bitcoin Core, in
  -- version 0. Each wallet finalized the coins it could complete alone.
  describe "The PSBT of nine coins of every kind, which twelve wallets of Bitcoin Core signed one at a time" $ do
    complex <- runIO (readTestFile "complex_psbt.json" :: IO Complex)
    complexChecks ctx complex

  -- data/psbt_complex_core32.json is the file of Bitcoin Core 32.1, in
  -- version 2. The wallets signed with finalize=false, so that the
  -- combination holds partial signatures only.
  describe "The PSBT of nine coins of every kind, which twelve wallets of Bitcoin Core 32.1 signed without finalizing" $ do
    complex <- runIO (readTestFile "psbt_complex_core32.json" :: IO Complex)
    it "is a version 2 PSBT whose combination has no final input" $ do
      complex.combinedPsbt.version `shouldBe` Version2
      length complex.combinedPsbt.inputs `shouldBe` 9
      -- Types 0x07 and 0x08 are the final script and the final witness
      length [key | input <- complex.combinedPsbt.inputs, key <- Map.keys input, key.keyType `elem` [0x07, 0x08]] `shouldBe` 0
    complexChecks ctx complex

-- | What holds for both files: the library combines, finalizes and
-- extracts what Bitcoin Core combined, finalized and extracted
complexChecks :: Ctx -> Complex -> Spec
complexChecks ctx complex = do
  -- The PSBT Core created has no entry that a signed one lacks
  it "adds nothing to a signed PSBT when the PSBT Core created is combined with it" $
    mapM (combinePsbt complex.initialPsbt) complex.signedPsbts `shouldBe` Right complex.signedPsbts

  it "combines into the PSBT Core combined" $
    case complex.signedPsbts of
      first' : rest -> foldM combinePsbt first' rest `shouldBe` Right complex.combinedPsbt
      [] -> expectationFailure "No signed PSBT"

  it "finalizes into the PSBT Core finalized" $
    finalizePsbt btc ctx complex.combinedPsbt `shouldBe` Right complex.completePsbt

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
      finalizePsbt btc ctx core.signedV2 `shouldBe` Right core.finalizedV2

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
      final <- expectRight (finalizePsbt btc ctx =<< signPsbt btc ctx signer core.preparedV2)
      tx <- expectRight (psbtTransaction final)
      final.version `shouldBe` Version2
      verifyStdTx btc ctx tx [(coin, 5000000000, OutPoint "fede72ccadbf9f16f826e3078578b0660526a37b48d4f894ab26f4cf5a95e89c" 0)] `shouldBe` True

{- The checks of the signer and the finalizer -}

signerChecksSpec :: Ctx -> Spec
signerChecksSpec ctx =
  describe "The checks of the signer and the finalizer" $ do
    let secret = PrivateKey secretOne True
        public = derivePublicKey ctx secret
        otherPublic = compressedKey ctx secretTwo
        (psbt, coins) = spendingPsbt ctx (PayPKHash (addressHash (marshal ctx public)))
        parent = fromJust (either (const Nothing) id (nonWitnessUtxo (inputAt 0 psbt)))
        coin = head parent.outputs
        withInput m = withInputs [m] psbt
        signer = keySigner ctx secret.key
        signed m = signPsbt btc ctx signer (withInput (recordOf ctx public m))
        signatureCount s = fmap length (partialSignatures ctx (inputAt 0 s))

    it "refuses to sign a legacy coin known from its witness output only, which only a witness signature may use" $
      signed (insertWitnessUtxo coin Map.empty)
        `shouldBe` Left "Input 0: the coin is given as a witness output only, which may not be signed with a non-witness signature"

    it "takes the coin from the previous transaction first, and refuses a witness output that is not that output" $ do
      (signatureCount =<< signed (insertWitnessUtxo coin (insertNonWitnessUtxo parent Map.empty))) `shouldBe` Right 1
      signed (insertWitnessUtxo (TxOut 1 coin.script) (insertNonWitnessUtxo parent Map.empty))
        `shouldBe` Left "Input 0: the witness output of the input is not the output of its previous transaction"

    it "refuses a sighash type no node accepts, and one whose fork id flag does not fit the network" $ do
      signed (insertSigHashType 0 (insertNonWitnessUtxo parent Map.empty)) `shouldBe` Left "Input 0: the sighash type 0 is not one a node accepts"
      signed (insertSigHashType 0x21 (insertNonWitnessUtxo parent Map.empty)) `shouldBe` Left "Input 0: the sighash type 33 is not one a node accepts"
      signed (insertSigHashType (setForkIdFlag sigHashAll) (insertNonWitnessUtxo parent Map.empty)) `shouldBe` Left "Input 0: the sighash type has a fork id flag the network does not use"
      signPsbt bch ctx signer (withInput (recordOf ctx public (insertSigHashType sigHashAll (insertNonWitnessUtxo parent Map.empty))))
        `shouldBe` Left "Input 0: the sighash type lacks the fork id flag the network requires"
      -- With the flag, the Bitcoin Cash digest signs
      (signatureCount =<< signPsbt bch ctx signer (withInput (recordOf ctx public (insertSigHashType (setForkIdFlag sigHashAll) (insertNonWitnessUtxo parent Map.empty))))) `shouldBe` Right 1

    it "refuses a sighash type the signer does not accept, and signs with it once the signer lists it" $ do
      let acceptingSingle = signer {acceptedSigHashes = [sigHashSingle]}
          askingSingle = insertSigHashType sigHashSingle (insertNonWitnessUtxo parent Map.empty)
      signed askingSingle `shouldBe` Left "Input 0: the sighash type 3 is not one the signer accepts"
      (signatureCount =<< signPsbt btc ctx acceptingSingle (withInput (recordOf ctx public askingSingle))) `shouldBe` Right 1
      -- ANYONECANPAY makes another type: 0x81 is not 0x01
      signed (insertSigHashType (setAnyoneCanPay sigHashAll) (insertNonWitnessUtxo parent Map.empty)) `shouldBe` Left "Input 0: the sighash type 129 is not one the signer accepts"

    -- Two coins of the same script, spent by one transaction with one
    -- output: input 1 has no output at its index
    it "refuses SIGHASH_SINGLE on a legacy coin whose input has no output at its index, and signs it on a SegWit coin" $ do
      let witnessCoin = TxOut 200000000 (marshal ctx (PayWitnessPKHash (addressHash (marshal ctx public))))
          parentOf c = Tx 1 [TxIn (OutPoint "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389" 1) "" 0xffffffff] [c, c] [] 0
          spendingBoth p = Tx 2 [TxIn (OutPoint (txHash p) 0) "" 0xfffffffe, TxIn (OutPoint (txHash p) 1) "" 0xfffffffe] [TxOut 399999000 (hexBytes "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac")] [] 0
          askingSingle p = recordOf ctx public (insertSigHashType sigHashSingle (insertNonWitnessUtxo p Map.empty))
          psbtOf p = Psbt Version0 (spendingBoth p) Map.empty [askingSingle p, askingSingle p] [Map.empty]
          acceptingSingle = signer {acceptedSigHashes = [sigHashSingle]}
      signPsbt btc ctx acceptingSingle (psbtOf (parentOf coin)) `shouldBe` Left "Input 1: makeSignature: SIGHASH_SINGLE without an output at the input index"
      -- The BIP 143 digest commits to the coin, so the SegWit signature is fine
      (signatureCount =<< signPsbt btc ctx acceptingSingle (psbtOf (parentOf witnessCoin))) `shouldBe` Right 1
      (fmap length . partialSignatures ctx . inputAt 1 =<< signPsbt btc ctx acceptingSingle (psbtOf (parentOf witnessCoin))) `shouldBe` Right 1

    it "refuses a redeem script that does not hash to the coin, and one on a coin that is not pay-to-script-hash" $ do
      let ms = PayMulSig [public, otherPublic] 1
          msScript = either error id (encodeOutput ctx ms)
          wrongScript = either error id (encodeOutput ctx (PayMulSig [otherPublic, public] 1))
          (p2sh, _) = spendingPsbt ctx (either error id (toP2SH msScript))
          p2shParent = fromJust (either (const Nothing) id (nonWitnessUtxo (inputAt 0 p2sh)))
          p2shInput m = withInputs [recordOf ctx public (insertNonWitnessUtxo p2shParent m)] p2sh
      (signatureCount =<< signPsbt btc ctx signer (p2shInput (insertInputRedeemScript msScript Map.empty))) `shouldBe` Right 1
      signPsbt btc ctx signer (p2shInput (insertInputRedeemScript wrongScript Map.empty))
        `shouldBe` Left "Input 0: the redeem script of the input does not hash to its coin"
      signed (insertInputRedeemScript msScript (insertNonWitnessUtxo parent Map.empty))
        `shouldBe` Left "Input 0: the input has a redeem script, but its coin is not pay-to-script-hash"

    it "refuses a witness script that does not hash to the witness program" $ do
      let ms = PayMulSig [public, otherPublic] 1
          msScript = either error id (encodeOutput ctx ms)
          wrongScript = either error id (encodeOutput ctx (PayMulSig [otherPublic, public] 1))
          (p2wsh, _) = spendingPsbt ctx (either error id (toP2WSH msScript))
          p2wshInput m = withInputs [recordOf ctx public (Map.union m (inputAt 0 p2wsh))] p2wsh
      (signatureCount =<< signPsbt btc ctx signer (p2wshInput (insertInputWitnessScript msScript Map.empty))) `shouldBe` Right 1
      signPsbt btc ctx signer (p2wshInput (insertInputWitnessScript wrongScript Map.empty))
        `shouldBe` Left "Input 0: the witness script of the input does not hash to its witness program"
      signed (insertInputWitnessScript msScript (insertNonWitnessUtxo parent Map.empty))
        `shouldBe` Left "Input 0: the input has a witness script, but its coin is not pay-to-witness-script-hash"

    it "leaves an input whose coin script is not standard as it is, and signs the others" $ do
      let weird = TxOut 1000 (runPutS (serialize (Script [OP_1])))
          parent2 = Tx 1 parent.inputs [coin, weird] [] 0
          op0 = OutPoint (txHash parent2) 0
          op1 = OutPoint (txHash parent2) 1
          tx = Tx 2 [TxIn op0 "" 0xfffffffe, TxIn op1 "" 0xfffffffe] psbt.unsignedTx.outputs [] 0
          both = Psbt Version0 tx Map.empty [recordOf ctx public (insertNonWitnessUtxo parent2 Map.empty), insertNonWitnessUtxo parent2 Map.empty] [Map.empty, Map.empty]
      s <- expectRight (signPsbt btc ctx signer both)
      map hasPartialSignatures s.inputs `shouldBe` [True, False]
      f <- expectRight (finalizePsbt btc ctx s)
      map (isJust . finalScriptSig) f.inputs `shouldBe` [True, False]

    it "signs a coin whose key it holds without a derivation record, by the hash of the key" $ do
      (signatureCount =<< signPsbt btc ctx signer (withInput (insertNonWitnessUtxo parent Map.empty))) `shouldBe` Right 1
      -- A multisig coin names its keys
      let ms = PayMulSig [public, otherPublic] 1
          msScript = either error id (encodeOutput ctx ms)
          (p2sh, p2shCoins) = spendingPsbt ctx (either error id (toP2SH msScript))
          p2shParent = fromJust (either (const Nothing) id (nonWitnessUtxo (inputAt 0 p2sh)))
          p2shFields = withInputs [insertInputRedeemScript msScript (insertNonWitnessUtxo p2shParent Map.empty)] p2sh
      s <- expectRight (signPsbt btc ctx signer p2shFields)
      signatureCount s `shouldBe` Right 1
      signsAndVerifies btc ctx [secret] (p2shFields, p2shCoins) `shouldBe` Right True
      -- The other key is not held
      (signatureCount =<< signPsbt btc ctx (keySigner ctx secret.key) (fst (spendingPsbt ctx (PayPKHash (addressHash (marshal ctx otherPublic)))))) `shouldBe` Right 0
      coins `seq` return ()

    it "the finalizer refuses a signature that is not a signature, one with another sighash type than the input asks, and one that does not verify" $ do
      s <- expectRight (signed (insertNonWitnessUtxo parent Map.empty))
      signature <- case either error id (partialSignatures ctx (inputAt 0 s)) of
        [(_, sig)] -> return sig
        _ -> fail "one signature"
      let withSig sig m = withInput (insertPartialSignature ctx public sig m)
          keyHex = show (encodeHex (marshal ctx public))
      finalizePsbt btc ctx (withSig "3045aa" (insertNonWitnessUtxo parent Map.empty))
        `shouldBe` Left ("Input 0: the signature of the key " <> keyHex <> " is not a valid signature")
      finalizePsbt btc ctx (withSig signature (insertSigHashType sigHashNone (insertNonWitnessUtxo parent Map.empty)))
        `shouldBe` Left ("Input 0: the signature of the key " <> keyHex <> " does not use the sighash type of the input")
      -- The signature of the same key on another transaction
      let sameKeyOther = withInputs [recordOf ctx public (insertNonWitnessUtxo parent Map.empty)] (Psbt Version0 (Tx 2 psbt.unsignedTx.inputs [] [] 0) Map.empty psbt.inputs [])
      elsewhere <- expectRight (signPsbt btc ctx signer sameKeyOther)
      foreignSig <- case either error id (partialSignatures ctx (inputAt 0 elsewhere)) of
        [(_, sig)] -> return sig
        _ -> fail "one signature"
      finalizePsbt btc ctx (withSig foreignSig (insertNonWitnessUtxo parent Map.empty))
        `shouldBe` Left ("Input 0: the signature of the key " <> keyHex <> " does not verify")
      -- The right signature finalizes
      f <- expectRight (finalizePsbt btc ctx (withSig signature (insertNonWitnessUtxo parent Map.empty)))
      isJust (finalScriptSig (inputAt 0 f)) `shouldBe` True

{- Taproot -}

data Vectors371 = Vectors371
  { refused371 :: [Vector],
    accepted371 :: [Vector]
  }

instance Json.FromJSON Vectors371 where
  parseJSON = Json.withObject "vectors" $ \o -> Vectors371 <$> o .: "invalid" <*> o .: "valid"

-- | Why each invalid PSBT of BIP 371 is refused, as the end of the reason
refusals371 :: [String]
refusals371 =
  [ "Input 0: the value of the key 0x17 is not an x-only public key",
    "Input 0: the value of the key 0x13 is not a Taproot signature: decodeTaprootSig: a signature is 64 or 65 bytes, not 63",
    "Input 0: the value of the key 0x13 is not a Taproot signature: decodeTaprootSig: a signature is 64 or 65 bytes, not 66",
    "is not an x-only public key",
    "Output 1: the value of the key 0x05 is not an x-only public key",
    "is not an x-only public key",
    "is not an x-only public key and a leaf hash",
    "is not a Taproot signature: decodeTaprootSig: a signature is 64 or 65 bytes, not 66",
    "is not a Taproot signature: decodeTaprootSig: a signature is 64 or 65 bytes, not 63",
    "is not a control block",
    "is not a control block"
  ]

taprootSpec :: Ctx -> Vectors371 -> Spec
taprootSpec ctx vectors =
  describe "The Taproot fields of BIP 371" $ do
    describe "the invalid PSBTs are refused, each for its reason" $
      forM_ (zip vectors.refused371 refusals371) $ \(v, reason) ->
        it v.vecCase $ decodePsbt (bytesOf v) `shouldSatisfy` either (reason `isSuffixOf`) (const False)

    describe "the valid PSBTs are read, and written back byte for byte" $
      forM_ vectors.accepted371 $ \v ->
        it v.vecCase $ (encodePsbt <$> decodePsbt (bytesOf v)) `shouldBe` Right (bytesOf v)

    let vectorAt i = psbtOfVector (vectors.accepted371 !! i)
        xOnly text = fromJust (importXOnlyPubKey ctx (hexBytes text))
        digest text = fromJust (digestFromByteString (hexBytes text)) :: Digest SHA256
        keyScript text = Script [opPushData (hexBytes text), OP_CHECKSIG]

    it "read the internal key and the derivation of a key path input" $ do
      psbt <- vectorAt 0
      inputTapInternalKey ctx (inputAt 0 psbt) `shouldBe` Right (Just (xOnly "fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232"))
      inputTapDerivations ctx (inputAt 0 psbt) `shouldBe` Right [(xOnly "fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232", TapDerivation [] (Derivation (fingerprintOf "772b2da7") "m/86'/1'/0'/1/0"))]
      inputTapMerkleRoot (inputAt 0 psbt) `shouldBe` Right Nothing
      tapKeySig (inputAt 0 psbt) `shouldBe` Right Nothing

    it "read the key path signature of a signed input, and finalize it into a witness of that signature" $ do
      psbt <- vectorAt 1
      let sigHex = "bb53ec917bad9d906af1ba87181c48b86ace5aae2b53605a725ca74625631476fc6f5baedaf4f2ee0f477f36f58f3970d5b8273b7e497b97af2e3f125c97af34"
          sig = fromJust (schnorrSig (hexBytes sigHex))
      tapKeySig (inputAt 0 psbt) `shouldBe` (Just <$> taprootSignature sig sigHashDefault)
      final <- expectRight (finalizePsbt btc ctx psbt)
      finalScriptWitness (inputAt 0 final) `shouldBe` Right (Just [hexBytes sigHex])
      Map.keys (inputAt 0 final) `shouldBe` [Key 0x01 "", Key 0x08 ""]
      tx <- expectRight (psbtTransaction final)
      let coin = TxOut 5000000000 (hexBytes "51205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757")
      verifyStdTx btc ctx tx [(either error id (unmarshal ctx coin.script), coin.value, (head tx.inputs).outpoint)] `shouldBe` True

    it "read the internal key and the derivation of a key path output" $ do
      psbt <- vectorAt 2
      outputTapInternalKey ctx (outputAt 0 psbt) `shouldBe` Right (Just (xOnly "1124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e671"))
      outputTapDerivations ctx (outputAt 0 psbt) `shouldBe` Right [(xOnly "1124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e671", TapDerivation [] (Derivation (fingerprintOf "772b2da7") "m/86'/1'/0'/0/5"))]
      outputTapTree (outputAt 0 psbt) `shouldBe` Right Nothing

    it "read the leaf scripts, the derivations with their leaves, the internal key and the Merkle root of a script path input" $ do
      psbt <- vectorAt 3
      leaves <- expectRight (tapLeafScripts ctx (inputAt 0 psbt))
      map (.script) leaves
        `shouldBe` [ keyScript "2cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2",
                     keyScript "4320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b2",
                     keyScript "fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca9"
                   ]
      map (.leafVersion) leaves `shouldBe` [0xc0, 0xc0, 0xc0]
      map (B.length . (.controlBlock)) leaves `shouldBe` [97, 65, 97]
      inputTapInternalKey ctx (inputAt 0 psbt) `shouldBe` Right (Just (xOnly "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))
      inputTapMerkleRoot (inputAt 0 psbt) `shouldBe` Right (Just (digest "f0362e2f75a6f420a5bde3eb221d96ae6720cf25f81890c95b1d775acb515e65"))
      records <- expectRight (inputTapDerivations ctx (inputAt 0 psbt))
      lookup (xOnly "2cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2") records
        `shouldBe` Just (TapDerivation [digest "cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09"] (Derivation (fingerprintOf "772b2da7") "m/86'/1'/2'/0/0"))
      lookup (xOnly "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0") records
        `shouldBe` Just (TapDerivation [] (Derivation (fingerprintOf "7c461e5d") "m"))
      -- The leaf hash of the record is the hash of the leaf script
      leafHash 0xc0 (keyScript "2cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2") `shouldBe` digest "cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09"
      -- The control blocks commit the leaves to the output key, with the Merkle root
      let outKey = fromJust (importXOnlyPubKey ctx (hexBytes "c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b692"))
      forM_ leaves $ \leaf -> do
        (v, internal, proof) <- expectRight (decodeControlBlock ctx leaf.controlBlock)
        verifyScriptPathData ctx outKey (ScriptPathData Nothing [] leaf.script (odd v) 0xc0 internal proof Nothing) `shouldBe` True

    it "read the script tree of a script path output, whose leaves build the tree of its output key" $ do
      psbt <- vectorAt 4
      let leaves =
            [ TapLeaf 2 0xc0 (keyScript "736e572900fe1252589a2143c8f3c79f71a0412d2353af755e9701c782694a02"),
              TapLeaf 2 0xc0 (keyScript "631c5f3b5832b8fbdebfb19704ceeb323c21f40f7a24f43d68ef0cc26b125969"),
              TapLeaf 1 0xc0 (keyScript "44faa49a0338de488c8dfffecdfb6f329f380bd566ef20c8df6d813eab1c4273")
            ]
      outputTapTree (outputAt 0 psbt) `shouldBe` Right (Just leaves)
      outputTapInternalKey ctx (outputAt 0 psbt) `shouldBe` Right (Just (xOnly "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))
      let tree = fromJust (tapTreeFromLeaves leaves)
          output = TaprootOutput (xOnly "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0") (Just tree)
      marshal ctx (taprootScriptOutput ctx output) `shouldBe` (head psbt.unsignedTx.outputs).script
      Map.lookup (Key 0x06 "") (insertOutputTapTree leaves Map.empty) `shouldBe` Map.lookup (Key 0x06 "") (outputAt 0 psbt)
      records <- expectRight (outputTapDerivations ctx (outputAt 0 psbt))
      length records `shouldBe` 4

    it "read the script path signatures of a signed input, and finalize it with the first leaf that has one" $ do
      psbt <- vectorAt 5
      sigs <- expectRight (tapScriptSigs ctx (inputAt 0 psbt))
      map (\((k, h), s) -> (exportXOnlyPubKey ctx k, h, B.length (encodeTaprootSig s))) sigs
        `shouldBe` [ (hexBytes "2cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2", digest "cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09", 64),
                     (hexBytes "4320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b2", digest "115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f8", 64),
                     (hexBytes "fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca9", digest "6f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970", 64)
                   ]
      final <- expectRight (finalizePsbt btc ctx psbt)
      witness <- expectRight (finalScriptWitness (inputAt 0 final))
      fmap (map B.length) witness `shouldBe` Just [64, 34, 97]
      tx <- expectRight (psbtTransaction final)
      let coin = TxOut 5000000000 (hexBytes "5120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b692")
      verifyStdTx btc ctx tx [(either error id (unmarshal ctx coin.script), coin.value, (head tx.inputs).outpoint)] `shouldBe` True

    it "write the fields back as they were read" $
      forM_ [0 .. 5] $ \i -> do
        psbt <- vectorAt i
        forM_ psbt.inputs $ \m -> do
          key <- expectRight (inputTapInternalKey ctx m)
          forM_ key $ \k -> Map.lookup (Key 0x17 "") (insertInputTapInternalKey ctx k Map.empty) `shouldBe` Map.lookup (Key 0x17 "") m
          root <- expectRight (inputTapMerkleRoot m)
          forM_ root $ \r -> Map.lookup (Key 0x18 "") (insertInputTapMerkleRoot r Map.empty) `shouldBe` Map.lookup (Key 0x18 "") m
          sig <- expectRight (tapKeySig m)
          forM_ sig $ \s -> Map.lookup (Key 0x13 "") (insertTapKeySig s Map.empty) `shouldBe` Map.lookup (Key 0x13 "") m
          leaves <- expectRight (tapLeafScripts ctx m)
          Map.toList (foldr insertTapLeafScript Map.empty leaves) `shouldBe` [(k, v) | (k, v) <- Map.toList m, k.keyType == 0x15]
          records <- expectRight (inputTapDerivations ctx m)
          Map.toList (foldr (uncurry (insertInputTapDerivation ctx)) Map.empty records) `shouldBe` [(k, v) | (k, v) <- Map.toList m, k.keyType == 0x16]
          sigs <- expectRight (tapScriptSigs ctx m)
          Map.toList (foldr (\((k, h), s) -> insertTapScriptSig ctx k h s) Map.empty sigs) `shouldBe` [(k, v) | (k, v) <- Map.toList m, k.keyType == 0x14]
        forM_ psbt.outputs $ \m -> do
          key <- expectRight (outputTapInternalKey ctx m)
          forM_ key $ \k -> Map.lookup (Key 0x05 "") (insertOutputTapInternalKey ctx k Map.empty) `shouldBe` Map.lookup (Key 0x05 "") m
          records <- expectRight (outputTapDerivations ctx m)
          Map.toList (foldr (uncurry (insertOutputTapDerivation ctx)) Map.empty records) `shouldBe` [(k, v) | (k, v) <- Map.toList m, k.keyType == 0x07]

    prop "a Taproot coin without script tree, signed by its key path with the internal key and finalized, verifies" $
      forAll (arbitraryKeyPair ctx) $ \(secret, public) ->
        let coinScript = taprootScriptOutput ctx (TaprootOutput public.point Nothing)
            (psbt, coins) = spendingPsbt ctx coinScript
            fields = insertInputTapInternalKey ctx public.point . insertInputTapDerivation ctx public.point (TapDerivation [] (Derivation (fingerprintOf "d90c6a4f") "m/86'/0'/0'/0/0"))
            withFields = withInputs (fields <$> psbt.inputs) psbt
            signed = signPsbt btc ctx (keySigner ctx secret.key) withFields
         in (signsAndVerifies btc ctx [secret] (withFields, coins), fmap (fmap (fmap (.hash)) . tapKeySig . inputAt 0) signed) === (Right True, Right (Right (Just sigHashDefault)))

    prop "a Taproot coin with a leaf that checks one key, signed by that leaf and finalized, verifies" $
      forAll ((,) <$> arbitraryKeyPair ctx <*> arbitraryKeyPair ctx) $ \((secret, public), (_, internal)) ->
        let leaf = Script [opPushData (exportXOnlyPubKey ctx public.point), OP_CHECKSIG]
            tree = MASTBranch (MASTLeaf 0xc0 leaf) (MASTLeaf 0xc0 (Script [OP_RETURN]))
            output = TaprootOutput internal.point (Just tree)
            coinScript = taprootScriptOutput ctx output
            (psbt, coins) = spendingPsbt ctx coinScript
            proof = case getMerkleProofs tree of
              (_, _, p) : _ -> p
              [] -> []
            control = encodeControlBlock ctx (0xc0 + keyParity ctx (taprootOutputKey ctx output)) internal.point proof
            fields =
              insertInputTapInternalKey ctx internal.point
                . insertInputTapMerkleRoot (mastCommitment tree)
                . insertTapLeafScript (TapLeafScript control leaf 0xc0)
                . insertInputTapDerivation ctx public.point (TapDerivation [leafHash 0xc0 leaf] (Derivation (fingerprintOf "d90c6a4f") "m/86'/0'/0'/0/1"))
            withFields = withInputs (fields <$> psbt.inputs) psbt
         in signsAndVerifies btc ctx [secret] (withFields, coins) === Right True

    it "the signer refuses a sighash type a Taproot signature may not use, and an internal key that does not give the coin" $ do
      let secret = PrivateKey secretOne True
          public = derivePublicKey ctx secret
          other = compressedKey ctx secretTwo
          coinScript = taprootScriptOutput ctx (TaprootOutput public.point Nothing)
          (psbt, _) = spendingPsbt ctx coinScript
          withFields m = withInputs [m (insertInputTapInternalKey ctx public.point (inputAt 0 psbt))] psbt
      signPsbt btc ctx (keySigner ctx secret.key) (withFields (insertSigHashType (setForkIdFlag sigHashAll))) `shouldBe` Left "Input 0: the sighash type 65 is not one a Taproot signature may use"
      signPsbt btc ctx (keySigner ctx secret.key) (withInputs [insertInputTapInternalKey ctx other.point (inputAt 0 psbt)] psbt) `shouldBe` Left "Input 0: the internal key and the Merkle root do not give the output key of the coin"
      -- Without the internal key, the input is left alone
      signPsbt btc ctx (keySigner ctx secret.key) psbt `shouldBe` Right psbt

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

    -- The combiner of BIP 174 keeps every entry that either PSBT has. The
    -- key type 0x7e is one no map knows.
    prop "combined with a copy that has one more entry in every map, in either order, is that copy" $
      forAll (arbitraryPsbt btc ctx) $ \psbt ->
        let oneMore = Map.insert (Key 0x7e "combiner test") "one more entry"
            copy = Psbt psbt.version psbt.unsignedTx (oneMore psbt.globals) (oneMore <$> psbt.inputs) (oneMore <$> psbt.outputs)
         in combinePsbt psbt copy == Right copy && combinePsbt copy psbt == Right copy

{- What the decoder refuses -}

-- | The unsigned transaction of 'tinyPsbt': version 2, one input that
-- spends output 0 of the transaction whose id bytes are 00 01 … 1f, one
-- output of 1,000 satoshi, lock time 0. It is 82 bytes long.
tinyTx :: Text
tinyTx = "0200000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000000ffffffff01e803000000000000160014111111111111111111111111111111111111111100000000"

-- | A PSBT of version 0 over 'tinyTx', with the entries given, in hex, in
-- its global map, in the map of its input and in the map of its output.
-- An entry is a key after its length, then a value after its length. The
-- first entry is the transaction: 0x52 is its 82 bytes.
tinyPsbt :: Text -> Text -> Text -> ByteString
tinyPsbt globalEntries inputEntries outputEntries =
  hexBytes ("70736274ff" <> "010052" <> tinyTx <> globalEntries <> "00" <> inputEntries <> "00" <> outputEntries <> "00")

-- | The same payment as 'tinyPsbt' in version 2, with the entries given in
-- the map of its input: the transaction version 2, one input, one output
-- and the PSBT version 2 in the global map, the transaction id and the
-- output index 0 in the input, the amount and the script in the output.
tinyPsbt2 :: Text -> ByteString
tinyPsbt2 inputEntries =
  hexBytes $
    "70736274ff"
      <> ("01020402000000" <> "01040101" <> "01050101" <> "01fb0402000000" <> "00")
      <> (inputEntries <> "010e20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" <> "010f0400000000" <> "00")
      <> ("010308e803000000000000" <> "01041600141111111111111111111111111111111111111111" <> "00")

-- | 33 bytes that start like a compressed public key and are no point of
-- the curve: the x coordinate ff…ff is above the field size
notAPoint :: Text
notAPoint = "02" <> T.replicate 32 "ff"

-- | A public key of the BIP 174 vectors
aPoint :: Text
aPoint = "029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f"

-- | A transaction of 61 bytes that the input of 'tinyTx' does not spend:
-- one input, one output of 5,000 satoshi with the script OP_1
anotherTx :: Text
anotherTx = "0100000001" <> T.replicate 32 "00" <> "ffffffff" <> "00" <> "ffffffff" <> "01" <> "8813000000000000" <> "0151" <> "00000000"

-- | A leaf of a script tree as PSBT_OUT_TAP_TREE lists it: its depth, its
-- leaf version, and after its length of 34 bytes the script
-- @<32 bytes of 0x22> OP_CHECKSIG@. It is 37 bytes long.
treeLeaf :: Text -> Text -> Text
treeLeaf depth version = depth <> version <> "22" <> "20" <> T.replicate 32 "22" <> "ac"

decoderChecksSpec :: Spec
decoderChecksSpec =
  describe "What the decoder refuses, as Bitcoin Core 32.1 does" $ do
    it "reads the small PSBT that the cases below add one entry to, in both versions" $ do
      (encodePsbt <$> decodePsbt (tinyPsbt "" "" "")) `shouldBe` Right (tinyPsbt "" "" "")
      (encodePsbt <$> decodePsbt (tinyPsbt2 "")) `shouldBe` Right (tinyPsbt2 "")

    -- The type of a key is a compact size integer. fd0000 is 0, and fd0200
    -- is 2, over three bytes where one is enough.
    it "refuses a key whose type is not in its shortest form" $ do
      decodePsbt (tinyPsbt "03fd000001aa" "" "") `shouldBe` Left "The global map has a key whose type is not in its shortest form"
      decodePsbt (tinyPsbt "" "03fd020001aa" "") `shouldBe` Left "Input 0 has a key whose type is not in its shortest form"
      decodePsbt (tinyPsbt "" "" "09ff010000000000000001aa") `shouldBe` Left "Output 0 has a key whose type is not in its shortest form"

    -- fe announces a type of four more bytes, and the key has one more
    it "refuses a key that ends inside its type" $
      decodePsbt (tinyPsbt "" "02fe0101aa" "") `shouldBe` Left "Input 0 has a key that ends inside its type"

    -- Bitcoin Core reads no compact size above 0x02000000. fe00000003 is
    -- 0x03000000, and ff0000000001000000 is 2^32.
    it "refuses a key whose type is above the largest compact size Bitcoin Core reads" $ do
      decodePsbt (tinyPsbt "" "05fe0000000301aa" "") `shouldBe` Left "Input 0 has a key whose type is beyond any type"
      decodePsbt (tinyPsbt "" "09ff000000000100000001aa" "") `shouldBe` Left "Input 0 has a key whose type is beyond any type"

    -- fdfd00 is the type 253 and fe00000002 the type 0x02000000, both in
    -- their shortest form
    it "reads a key whose type takes three or five bytes, and writes it back" $ do
      (encodePsbt <$> decodePsbt (tinyPsbt "" "03fdfd0001aa" "")) `shouldBe` Right (tinyPsbt "" "03fdfd0001aa" "")
      (encodePsbt <$> decodePsbt (tinyPsbt "" "05fe0000000201aa" "")) `shouldBe` Right (tinyPsbt "" "05fe0000000201aa" "")

    -- The key is the type 0x02 and 33 bytes, 34 in all (0x22). The value is
    -- a signature of nine bytes, the smallest BIP 66 allows, with SIGHASH_ALL.
    it "refuses a partial signature under a key that is not a point of the curve" $
      decodePsbt (tinyPsbt "" ("2202" <> notAPoint <> "09300602010102010101") "")
        `shouldBe` Left ("Input 0: the key 0x02 with the data " <> T.unpack notAPoint <> " is not a public key")

    it "reads a partial signature that is in the encoding of BIP 66 with a defined sighash byte" $
      (encodePsbt <$> decodePsbt (tinyPsbt "" ("2202" <> aPoint <> "09300602010102010101") ""))
        `shouldBe` Right (tinyPsbt "" ("2202" <> aPoint <> "09300602010102010101") "")

    -- "garbage" in ASCII, then no value at all, then the signature above
    -- with the sighash byte 0x04, which no node accepts
    it "refuses a partial signature that is not in the encoding of BIP 66, or whose sighash byte is not defined" $ do
      let refusal = Left ("Input 0: the value of the key 0x02 with the data " <> T.unpack aPoint <> " is not a signature in the encoding of BIP 66 with a defined sighash byte")
      decodePsbt (tinyPsbt "" ("2202" <> aPoint <> "0767617262616765") "") `shouldBe` refusal
      decodePsbt (tinyPsbt "" ("2202" <> aPoint <> "00") "") `shouldBe` refusal
      decodePsbt (tinyPsbt "" ("2202" <> aPoint <> "09300602010102010104") "") `shouldBe` refusal

    -- Each value ends with the sighash byte 0x01, which is defined, and
    -- breaks one rule of BIP 66: bytes that are no DER at all, a length
    -- byte that does not cover the signature (0x07 for 6 bytes), an R that
    -- is negative (0x80), and an R with a zero byte it does not need (0001)
    it "refuses a partial signature with a defined sighash byte that breaks a rule of BIP 66" $ do
      let refusal = Left ("Input 0: the value of the key 0x02 with the data " <> T.unpack aPoint <> " is not a signature in the encoding of BIP 66 with a defined sighash byte")
      decodePsbt (tinyPsbt "" ("2202" <> aPoint <> "0aaabbccddeeff00112201") "") `shouldBe` refusal
      decodePsbt (tinyPsbt "" ("2202" <> aPoint <> "09300702010102010101") "") `shouldBe` refusal
      decodePsbt (tinyPsbt "" ("2202" <> aPoint <> "09300602018002010101") "") `shouldBe` refusal
      decodePsbt (tinyPsbt "" ("2202" <> aPoint <> "0a30070202000102010101") "") `shouldBe` refusal

    -- The value is the fingerprint d90c6a4f and the path m/0'
    it "refuses a derivation record under a key that is not a point of the curve, on an input and on an output" $ do
      decodePsbt (tinyPsbt "" ("2206" <> notAPoint <> "08d90c6a4f00000080") "")
        `shouldBe` Left ("Input 0: the key 0x06 with the data " <> T.unpack notAPoint <> " is not a public key")
      decodePsbt (tinyPsbt "" "" ("2202" <> notAPoint <> "08d90c6a4f00000080"))
        `shouldBe` Left ("Output 0: the key 0x02 with the data " <> T.unpack notAPoint <> " is not a public key")

    -- The key is the type 0x01 and the 78 bytes of an extended key, 79 in
    -- all (0x4f): the version 0488b21e, depth 0, no parent, index 0, a chain
    -- code of zeros, and the public key
    it "refuses an extended public key whose key is not a point of the curve" $ do
      let xpubWith key = "4f01" <> "0488b21e" <> "00" <> "00000000" <> "00000000" <> T.replicate 32 "00" <> key <> "04d90c6a4f"
      (encodePsbt <$> decodePsbt (tinyPsbt (xpubWith aPoint) "" "")) `shouldBe` Right (tinyPsbt (xpubWith aPoint) "" "")
      decodePsbt (tinyPsbt (xpubWith notAPoint) "" "") `shouldSatisfy` either ("is not an extended public key" `isSuffixOf`) (const False)

    -- 0x3d is the 61 bytes of the transaction
    it "refuses a previous transaction that is not the one the input spends, in both versions" $ do
      decodePsbt (tinyPsbt "" ("01003d" <> anotherTx) "") `shouldBe` Left "Input 0: the previous transaction is not the one the input spends"
      decodePsbt (tinyPsbt2 ("01003d" <> anotherTx)) `shouldBe` Left "Input 0: the previous transaction is not the one the input spends"

    -- An empty tree, then a leaf of the leaf version 0xc1, a leaf at depth
    -- 129 (0x81), one leaf alone at depth 1, and three leaves at depth 1.
    -- 0x25 is the 37 bytes of a leaf, 0x6f the 111 bytes of three.
    it "refuses a script tree that is empty, has an odd leaf version, a leaf deeper than 128, or leaves that make no tree" $ do
      decodePsbt (tinyPsbt "" "" "010600") `shouldBe` Left "Output 0: the value of the key 0x06 is an empty script tree"
      decodePsbt (tinyPsbt "" "" ("010625" <> treeLeaf "00" "c1")) `shouldBe` Left "Output 0: the value of the key 0x06 has a leaf with an odd leaf version"
      decodePsbt (tinyPsbt "" "" ("010625" <> treeLeaf "81" "c0")) `shouldBe` Left "Output 0: the value of the key 0x06 has a leaf deeper than 128"
      decodePsbt (tinyPsbt "" "" ("010625" <> treeLeaf "01" "c0")) `shouldBe` Left "Output 0: the value of the key 0x06 is not a whole script tree"
      decodePsbt (tinyPsbt "" "" ("01066f" <> treeLeaf "01" "c0" <> treeLeaf "01" "c0" <> treeLeaf "01" "c0")) `shouldBe` Left "Output 0: the value of the key 0x06 is not a whole script tree"

    it "reads a script tree of one leaf at depth 0, and one of two leaves at depth 1" $ do
      (encodePsbt <$> decodePsbt (tinyPsbt "" "" ("010625" <> treeLeaf "00" "c0"))) `shouldBe` Right (tinyPsbt "" "" ("010625" <> treeLeaf "00" "c0"))
      (encodePsbt <$> decodePsbt (tinyPsbt "" "" ("01064a" <> treeLeaf "01" "c0" <> treeLeaf "01" "c0"))) `shouldBe` Right (tinyPsbt "" "" ("01064a" <> treeLeaf "01" "c0" <> treeLeaf "01" "c0"))

    -- The length 1 of the value "aa", over five bytes and over nine
    it "refuses a length written over five or nine bytes that is not in its shortest form" $ do
      decodePsbt (hexBytes ("70736274ff" <> emptyTxEntry <> "0120" <> "fe01000000" <> "aa" <> "00")) `shouldBe` Left "A length in the global map is not in its shortest form"
      decodePsbt (hexBytes ("70736274ff" <> emptyTxEntry <> "0120" <> "ff0100000000000000" <> "aa" <> "00")) `shouldBe` Left "A length in the global map is not in its shortest form"

    -- The key is the type 0x15 and a control block of 33 bytes plus 32 per
    -- node. 128 nodes make 4,130 bytes with the type (fd2210), and 129 make
    -- 4,162 (fd4210). The value is a script of 34 bytes and the leaf version.
    it "refuses a control block of 129 nodes, and reads one of 128" $ do
      let leafEntry nodes len = len <> "15" <> "c0" <> T.replicate 32 "22" <> T.replicate (32 * nodes) "33" <> "23" <> "20" <> T.replicate 32 "22" <> "ac" <> "c0"
      (B.length . encodePsbt <$> decodePsbt (tinyPsbt "" (leafEntry 128 "fd2210") "")) `shouldBe` Right (B.length (tinyPsbt "" (leafEntry 128 "fd2210") ""))
      decodePsbt (tinyPsbt "" (leafEntry 129 "fd4210") "") `shouldSatisfy` either ("is not a control block" `isSuffixOf`) (const False)

    -- An extended key of depth 0 has no path. The value is the fingerprint
    -- and the one index 0'.
    it "refuses an extended public key of depth 0 with a path of one index" $ do
      let xpub = "4f01" <> "0488b21e" <> "00" <> "00000000" <> "00000000" <> T.replicate 32 "00" <> aPoint <> "08d90c6a4f00000080"
      decodePsbt (tinyPsbt xpub "" "") `shouldSatisfy` either ("has a path that is not as deep as the key" `isSuffixOf`) (const False)

    -- Two entries with the same key: the type 0x20 and 1,000 bytes of 0xab,
    -- 1,001 in all (fde903)
    it "names at most 40 bytes of the data of a key in a refusal, then its length" $ do
      let entry = "fde903" <> "20" <> T.replicate 1000 "ab" <> "00"
      decodePsbt (tinyPsbt (entry <> entry) "" "")
        `shouldBe` Left ("The global map has the key 0x20 with the data " <> concat (replicate 40 "ab") <> "… (1000 bytes) twice")

{- What the signer and the finalizer sign, and what they leave alone -}

-- | A transaction that spends the two outputs of a previous transaction
-- paying the two scripts, as a PSBT with that previous transaction on both
-- inputs. Each output holds 2 BTC.
spendingTwo :: ByteString -> ByteString -> Psbt
spendingTwo scriptA scriptB = Psbt Version0 tx Map.empty [input, input] [Map.empty]
  where
    parent = Tx 1 [TxIn (OutPoint "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389" 1) "" 0xffffffff] [TxOut 200000000 scriptA, TxOut 200000000 scriptB] [] 0
    tx = Tx 2 [TxIn (OutPoint (txHash parent) 0) "" 0xfffffffe, TxIn (OutPoint (txHash parent) 1) "" 0xfffffffe] [TxOut 399990000 (hexBytes "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac")] [] 0
    input = insertNonWitnessUtxo parent Map.empty

signerScopeSpec :: Ctx -> Spec
signerScopeSpec ctx =
  describe "What the signer and the finalizer sign, and what they leave alone" $ do
    let secret = PrivateKey secretOne True
        public = derivePublicKey ctx secret
        otherPublic = compressedKey ctx secretTwo
        signer = keySigner ctx secretOne
        ownScript = marshal ctx (PayPKHash (addressHash (marshal ctx public)))
        otherScript = marshal ctx (PayPKHash (addressHash (marshal ctx otherPublic)))
        (psbt, _) = spendingPsbt ctx (PayPKHash (addressHash (marshal ctx public)))
        parent = fromJust (either (const Nothing) id (nonWitnessUtxo (inputAt 0 psbt)))
        coin = head parent.outputs
        signatureCounts = mapM (fmap length . partialSignatures ctx) . (.inputs)
        keyHex = show (encodeHex (marshal ctx public))

    -- BIP 32 gives a key a depth of one byte, so no key is 256 steps below
    -- another
    it "a signer built from an extended key holds no key for a record whose path has 256 steps" $ do
      let master = makeXPrvKey "PSBT signer test"
          tooDeep = Derivation (xPubFP ctx (deriveXPubKey ctx master)) (listToPath (replicate 256 0))
      (xPrvSigner ctx master Nothing).keyOfRecord public tooDeep `shouldBe` Nothing

    it "signing leaves unsigned an input whose record names the signer's key with a path of 256 steps" $ do
      let master = makeXPrvKey "PSBT signer test"
          tooDeep = Derivation (xPubFP ctx (deriveXPubKey ctx master)) (listToPath (replicate 256 0))
          withRecord = withInputs (insertInputDerivation ctx public tooDeep <$> psbt.inputs) psbt
      (signatureCounts =<< signPsbt btc ctx (xPrvSigner ctx master Nothing) withRecord) `shouldBe` Right [0]

    -- The second record names a key the coin does not pay. A signer that
    -- derives a key for every record can be made to work without end.
    it "asks the signer for the key of a record only when the script of the coin names that key" $ do
      let onlyOwn = signer {keyOfRecord = \asked _ -> if asked == public then Just secretOne else error "asked for the key of a record the coin does not name"}
          withRecords = withInputs ((recordOf ctx public . recordOf ctx otherPublic) <$> psbt.inputs) psbt
      (signatureCounts =<< signPsbt btc ctx onlyOwn withRecords) `shouldBe` Right [1]

    -- The coin pays the hash of key 2, and the record names key 1, which
    -- the signer holds. BIP 174: "If a Signer cannot sign a transaction, it
    -- must not add a Partial Signature."
    it "adds no signature for a key the script of the coin does not name, even when a derivation record names it" $ do
      let (other, _) = spendingPsbt ctx (PayPKHash (addressHash (marshal ctx otherPublic)))
      (signatureCounts =<< signPsbt btc ctx signer (withInputs (recordOf ctx public <$> other.inputs) other)) `shouldBe` Right [0]

    it "adds no signature to a P2WSH coin whose witness script is missing, nor to a P2SH coin whose redeem script is missing" $ do
      let multisig = forceRight (encodeOutput ctx (PayMulSig [public, otherPublic] 2))
          (p2wsh, _) = spendingPsbt ctx (forceRight (toP2WSH multisig))
          (p2sh, _) = spendingPsbt ctx (forceRight (toP2SH multisig))
      (signatureCounts =<< signPsbt btc ctx signer (withInputs (recordOf ctx public <$> p2wsh.inputs) p2wsh)) `shouldBe` Right [0]
      (signatureCounts =<< signPsbt btc ctx signer (withInputs (recordOf ctx public <$> p2sh.inputs) p2sh)) `shouldBe` Right [0]

    it "signs a P2SH-P2WPKH coin with its redeem script by the hash of its key, without a derivation record" $ do
      let redeem = forceRight (encodeOutput ctx (PayWitnessPKHash (addressHash (marshal ctx public))))
          (nested, _) = spendingPsbt ctx (forceRight (toP2SH redeem))
      (signatureCounts =<< signPsbt btc ctx signer (withInputs (insertInputRedeemScript redeem <$> nested.inputs) nested)) `shouldBe` Right [1]

    -- 0x41 is SIGHASH_ALL (0x01) with SIGHASH_FORKID (0x40)
    it "on the Bitcoin Cash networks, signs an input that asks for no sighash type with SIGHASH_ALL and the fork id flag" $
      forM_ [bch, bchTest, bchTest4, bchRegTest] $ \net ->
        (map (B.last . snd) <$> (partialSignatures ctx . inputAt 0 =<< signPsbt net ctx signer psbt)) `shouldBe` Right [0x41]

    -- Input 0 is a coin of key 1. Input 1 is a P2WSH coin of someone else,
    -- whose witness script is <key 2> OP_CHECKSIGVERIFY <144>
    -- OP_CHECKSEQUENCEVERIFY, which is no template the library knows.
    it "signs and finalizes its own input, and leaves alone an input whose witness script is not a standard template" $ do
      let timelocked = Script [opPushData (marshal ctx otherPublic), OP_CHECKSIGVERIFY, opPushData "\x90\x00", OP_CHECKSEQUENCEVERIFY]
          both = spendingTwo ownScript (marshal ctx (forceRight (toP2WSH timelocked)))
          withScript = withInputs [inputAt 0 both, insertInputWitnessScript timelocked (inputAt 1 both)] both
      signed <- expectRight (signPsbt btc ctx signer withScript)
      signatureCounts signed `shouldBe` Right [1, 0]
      inputAt 1 signed `shouldBe` inputAt 1 withScript
      final <- expectRight (finalizePsbt btc ctx signed)
      map (isJust . finalScriptSig) final.inputs `shouldBe` [True, False]
      inputAt 1 final `shouldBe` inputAt 1 withScript

    -- Input 1 is a P2PKH coin of key 2, known from its output alone. The
    -- signer could not sign it anyway. Bitcoin Core leaves such an input
    -- unsigned and signs the others.
    it "leaves alone a legacy coin known from its witness output only when it holds no key for it, and signs its own input" $ do
      let both = spendingTwo ownScript otherScript
          witnessOnly = withInputs [inputAt 0 both, insertWitnessUtxo (TxOut 200000000 otherScript) Map.empty] both
      (signatureCounts =<< signPsbt btc ctx signer witnessOnly) `shouldBe` Right [1, 0]

    -- Bitcoin Core refuses the whole PSBT too: a sighash type that the
    -- caller did not ask for is a mismatch on any input that has its coin
    it "refuses a PSBT in which another party's input asks for a sighash type the signer does not accept" $ do
      let both = spendingTwo ownScript otherScript
          asking = withInputs [inputAt 0 both, insertSigHashType (setAnyoneCanPay sigHashSingle) (inputAt 1 both)] both
      signPsbt btc ctx signer asking `shouldBe` Left "Input 1: the sighash type 131 is not one the signer accepts"

    it "refuses to sign a SegWit version 0 coin with an uncompressed key" $ do
      let uncompressed = PublicKey public.point False
          (p2wpkh, _) = spendingPsbt ctx (PayWitnessPKHash (addressHash (marshal ctx uncompressed)))
      signPsbt btc ctx signer p2wpkh `shouldBe` Left "Input 0: a SegWit version 0 coin may not be signed with an uncompressed key"

    -- The signature is a real one of key 1, on another coin. The finalizer
    -- must refuse it for the form of the key, whatever it signs.
    it "the finalizer refuses a signature of an uncompressed key on a SegWit version 0 coin" $ do
      let uncompressed = PublicKey public.point False
          (p2wpkh, _) = spendingPsbt ctx (PayWitnessPKHash (addressHash (marshal ctx uncompressed)))
      signed <- expectRight (signPsbt btc ctx signer psbt)
      signature <- case partialSignatures ctx (inputAt 0 signed) of
        Right [(_, sig)] -> return sig
        _ -> fail "one signature"
      finalizePsbt btc ctx (withInputs (insertPartialSignature ctx uncompressed signature <$> p2wpkh.inputs) p2wpkh)
        `shouldBe` Left ("Input 0: the signature of the key " <> show (encodeHex (marshal ctx uncompressed)) <> " is of an uncompressed key, which a SegWit version 0 coin may not be spent with")

    -- The second signature is the one of key 1, filed under key 2: it does
    -- not verify for key 2. The coin does not name key 2, so the finalizer
    -- has no reason to look at it.
    it "the finalizer does not look at a partial signature of a key the script of the coin does not name" $ do
      signed <- expectRight (signPsbt btc ctx signer psbt)
      signature <- case partialSignatures ctx (inputAt 0 signed) of
        Right [(_, sig)] -> return sig
        _ -> fail "one signature"
      let withStray = withInputs (insertPartialSignature ctx otherPublic signature <$> signed.inputs) signed
      (finalScriptSig . inputAt 0 <$> finalizePsbt btc ctx withStray) `shouldBe` (finalScriptSig . inputAt 0 <$> finalizePsbt btc ctx signed)
      (isJust . finalScriptSig . inputAt 0 <$> finalizePsbt btc ctx withStray) `shouldBe` Right True

    -- Bitcoin Core takes SIGHASH_ALL for an input that names no sighash
    -- type, and gives no final script when a signature uses another
    it "the finalizer refuses a SIGHASH_NONE signature on an input that names no sighash type" $ do
      let acceptingNone = signer {acceptedSigHashes = [sigHashNone]}
      signed <- expectRight (signPsbt btc ctx acceptingNone (withInputs (insertSigHashType sigHashNone <$> psbt.inputs) psbt))
      finalizePsbt btc ctx (withInputs (deleteSigHashType <$> signed.inputs) signed)
        `shouldBe` Left ("Input 0: the signature of the key " <> keyHex <> " does not use SIGHASH_ALL, and the input names no sighash type")

    it "the finalizer leaves alone a signed legacy coin that is known from its witness output only" $ do
      signed <- expectRight (signPsbt btc ctx signer psbt)
      let witnessOnly = withInputs [insertWitnessUtxo coin (Map.delete (Key 0x00 "") (inputAt 0 signed))] signed
      finalizePsbt btc ctx witnessOnly `shouldBe` Right witnessOnly

    -- A signer written by a caller may answer with a key that is not the
    -- one asked for. Its signature would be of no use to anyone.
    it "signs with a key the signer gives only when it is the key the coin names" $ do
      let wrongByRecord = signer {keyOfRecord = \_ _ -> Just secretTwo, keyOfHash = const Nothing}
          wrongByHash = signer {keyOfRecord = \_ _ -> Nothing, keyOfHash = const (Just (PrivateKey secretTwo True))}
          withRecord = withInputs (recordOf ctx public <$> psbt.inputs) psbt
      (signatureCounts =<< signPsbt btc ctx wrongByRecord withRecord) `shouldBe` Right [0]
      (signatureCounts =<< signPsbt btc ctx wrongByHash psbt) `shouldBe` Right [0]

    it "a signer of one key holds no key for the record of another key" $ do
      let record = Derivation (fingerprintOf "00000000") "m/0"
      (keySigner ctx secretOne).keyOfRecord otherPublic record `shouldBe` Nothing
      (keySigner ctx secretOne).keyOfRecord public record `shouldBe` Just secretOne

    -- The time lock 100 is below 500,000,000, so it would be read as a height
    it "a constructor refuses an input whose map breaks the spec, such as a required time lock below 500000000" $ do
      let modifiable = withFlags (Modifiable True True False 0) (withVersion Version2 (psbtOf (Tx 2 [] [] [] 0)))
      addInput coinInput (Map.singleton (Key 0x11 "") (hexBytes "64000000")) modifiable
        `shouldBe` Left "Input 0: the value of the key 0x11 is a time lock below 500000000"
      addOutput paidOutput (Map.singleton (Key 0x06 "") "") modifiable
        `shouldBe` Left "Output 0: the value of the key 0x06 is an empty script tree"
      -- The previous transaction has one output, and the input spends its second
      let previous = Tx 1 [coinInput] [paidOutput] [] 0
      addInput (TxIn (OutPoint (txHash previous) 1) "" 0xffffffff) (insertNonWitnessUtxo previous Map.empty) modifiable
        `shouldBe` Left "Input 0: the input spends an output its previous transaction does not have"
      addInput (TxIn (OutPoint (txHash previous) 0) "" 0xffffffff) (insertNonWitnessUtxo emptyTx Map.empty) modifiable
        `shouldBe` Left "Input 0: the previous transaction is not the one the input spends"

    -- 0065cd1d is 500,000,000, the first lock time that is a time, and
    -- ff64cd1d is 499,999,999
    it "a required time lock of 500000000 is the lock time of the transaction, and one of 499999999 is refused" $ do
      ((.unsignedTx.locktime) <$> decodePsbt (tinyPsbt2 "0111040065cd1d")) `shouldBe` Right 500000000
      decodePsbt (tinyPsbt2 "011104ff64cd1d") `shouldBe` Left "Input 0: the value of the key 0x11 is a time lock below 500000000"

{- The checks on Taproot signatures -}

-- | The PSBT with each of its input maps changed
onInputs :: (PsbtMap -> PsbtMap) -> Psbt -> Psbt
onInputs f psbt = withInputs (f <$> psbt.inputs) psbt

-- | The map with the entries of one key type changed
onKeyType :: Word8 -> (Key -> ByteString -> (Key, ByteString)) -> PsbtMap -> PsbtMap
onKeyType t f m = Map.fromList [if key.keyType == t then f key value else (key, value) | (key, value) <- Map.toList m]

-- | Bytes with their last bit flipped
flipLastBit :: ByteString -> ByteString
flipLastBit bytes = B.init bytes <> B.singleton (B.last bytes `xor` 1)

-- | An entry with the last bit of its value flipped, and one with the last
-- bit of the data of its key flipped
flipValue, flipKeyData :: Key -> ByteString -> (Key, ByteString)
flipValue key value = (key, flipLastBit value)
flipKeyData key value = (Key key.keyType (flipLastBit key.keyData), value)

taprootChecksSpec :: Ctx -> Vectors371 -> Spec
taprootChecksSpec ctx vectors =
  describe "The checks on Taproot signatures" $ do
    let vectorAt i = psbtOfVector (vectors.accepted371 !! i)
        internal = derivePubKey ctx secretOne
        leafKey = derivePubKey ctx secretTwo
        leaf = Script [opPushData (exportXOnlyPubKey ctx leafKey), OP_CHECKSIG]
        tree = MASTBranch (MASTLeaf 0xc0 leaf) (MASTLeaf 0xc0 (Script [OP_RETURN]))
        output = TaprootOutput internal (Just tree)
        control = encodeControlBlock ctx (0xc0 + keyParity ctx (taprootOutputKey ctx output)) internal [leafHash 0xc0 (Script [OP_RETURN])]
        (withTree, _) = spendingPsbt ctx (taprootScriptOutput ctx output)
        treeFields = insertInputTapInternalKey ctx internal . insertInputTapMerkleRoot (mastCommitment tree) . insertTapLeafScript (TapLeafScript control leaf 0xc0)
        derivation = Derivation (fingerprintOf "d90c6a4f") "m/86'/0'/0'/0/0"
        -- A signer that finds its keys by derivation record only, as one
        -- built from an extended key does
        byRecord secret = (keySigner ctx secret) {keyOfHash = const Nothing}

    it "the finalizer refuses a key path signature that does not verify" $ do
      psbt <- vectorAt 1
      finalizePsbt btc ctx (onInputs (onKeyType 0x13 flipValue) psbt)
        `shouldBe` Left "Input 0: the key path signature does not verify"

    it "the finalizer refuses a script path signature that does not verify" $ do
      psbt <- vectorAt 5
      finalizePsbt btc ctx (onInputs (onKeyType 0x14 flipValue) psbt)
        `shouldBe` Left "Input 0: the script path signature does not verify"

    it "the finalizer refuses a leaf whose control block does not commit it to the output key" $ do
      psbt <- vectorAt 5
      finalizePsbt btc ctx (onInputs (onKeyType 0x15 flipKeyData) psbt)
        `shouldBe` Left "Input 0: the control block of the leaf does not commit it to the output key"

    -- The signatures of both vectors are 64 bytes, which is SIGHASH_DEFAULT
    it "the finalizer refuses a Taproot signature that does not use the sighash type the input names" $ do
      keyPath <- vectorAt 1
      scriptPath <- vectorAt 5
      finalizePsbt btc ctx (onInputs (insertSigHashType sigHashAll) keyPath) `shouldBe` Left "Input 0: a Taproot signature does not use the sighash type of the input"
      finalizePsbt btc ctx (onInputs (insertSigHashType sigHashAll) scriptPath) `shouldBe` Left "Input 0: a Taproot signature does not use the sighash type of the input"

    -- Bitcoin Core takes SIGHASH_DEFAULT for a Taproot input that names no
    -- sighash type, and then wants every signature to be 64 bytes
    it "the finalizer refuses a SIGHASH_ALL key path signature on an input that names no sighash type" $ do
      let (keyOnly, _) = spendingPsbt ctx (taprootScriptOutput ctx (TaprootOutput internal Nothing))
          asking = onInputs (insertSigHashType sigHashAll . insertInputTapInternalKey ctx internal) keyOnly
      signed <- expectRight (signPsbt btc ctx (keySigner ctx secretOne) asking)
      (fmap (fmap (.hash)) . tapKeySig . inputAt 0) signed `shouldBe` Right (Just sigHashAll)
      finalizePsbt btc ctx (onInputs deleteSigHashType signed)
        `shouldBe` Left "Input 0: a Taproot signature does not use SIGHASH_DEFAULT, and the input names no sighash type"

    it "the signer refuses a Taproot coin that asks for a sighash type the signer does not accept" $ do
      let (keyOnly, _) = spendingPsbt ctx (taprootScriptOutput ctx (TaprootOutput internal Nothing))
      signPsbt btc ctx (keySigner ctx secretOne) (onInputs (insertSigHashType sigHashSingle . insertInputTapInternalKey ctx internal) keyOnly)
        `shouldBe` Left "Input 0: the sighash type 3 is not one the signer accepts"

    -- BIP 371: the leaf hashes of a record "are of the leaves which involve
    -- this public key". A key that is the internal key and also a leaf key
    -- has a record with a leaf hash, and Bitcoin Core writes it that way.
    it "signs the key path of a Taproot coin when the record of its internal key lists a leaf" $ do
      let record = insertInputTapDerivation ctx internal (TapDerivation [leafHash 0xc0 leaf] derivation)
      signed <- expectRight (signPsbt btc ctx (byRecord secretOne) (onInputs (record . treeFields) withTree))
      (fmap isJust . tapKeySig . inputAt 0) signed `shouldBe` Right True

    it "signs a leaf with the key of a record that lists that leaf, and not with one that lists another leaf" $ do
      let listing hashes = insertInputTapDerivation ctx leafKey (TapDerivation hashes derivation)
          signatures f = fmap length . tapScriptSigs ctx . inputAt 0 =<< signPsbt btc ctx (byRecord secretTwo) (onInputs (f . treeFields) withTree)
      signatures (listing [leafHash 0xc0 leaf]) `shouldBe` Right 1
      signatures (listing [leafHash 0xc0 (Script [OP_RETURN])]) `shouldBe` Right 0

    -- The leaf is in no tree of the coin: its control block names another
    -- internal key
    it "signs no leaf whose control block does not commit it to the coin" $ do
      let stray = encodeControlBlock ctx 0xc0 leafKey [leafHash 0xc0 (Script [OP_RETURN])]
          fields = insertInputTapInternalKey ctx internal . insertInputTapMerkleRoot (mastCommitment tree) . insertTapLeafScript (TapLeafScript stray leaf 0xc0)
      signed <- expectRight (signPsbt btc ctx (keySigner ctx secretTwo) (onInputs fields withTree))
      (fmap length . tapScriptSigs ctx . inputAt 0) signed `shouldBe` Right 0

    it "signs a Taproot coin of a PSBT of version 2 by its key path, and the PSBT stays of version 2" $ do
      let (keyOnly, coins) = spendingPsbt ctx (taprootScriptOutput ctx (TaprootOutput internal Nothing))
          version2 = withVersion Version2 (onInputs (insertInputTapInternalKey ctx internal) keyOnly)
      final <- expectRight (finalizePsbt btc ctx =<< signPsbt btc ctx (keySigner ctx secretOne) version2)
      final.version `shouldBe` Version2
      tx <- expectRight (psbtTransaction final)
      verifyStdTx btc ctx tx coins `shouldBe` True

{- The coins of a PSBT, and the previous transaction a signer may require -}

coinsSpec :: Ctx -> Spec
coinsSpec ctx =
  describe "The coins of a PSBT" $ do
    let public = compressedKey ctx secretOne
        signer = keySigner ctx secretOne
        program = PayWitnessPKHash (addressHash (marshal ctx public))
        (psbt, _) = spendingPsbt ctx program
        parent = fromJust (either (const Nothing) id (nonWitnessUtxo (inputAt 0 psbt)))
        output = head parent.outputs
        witnessOnly = withInputs [insertWitnessUtxo output Map.empty] psbt
        signatureCounts = mapM (fmap length . partialSignatures ctx) . (.inputs)

    it "tells the coin of each input, and whether it comes from the previous transaction of the input" $ do
      inputCoins psbt `shouldBe` Right [Just (InputCoin output True)]
      inputCoins witnessOnly `shouldBe` Right [Just (InputCoin output False)]
      inputCoins (withInputs [Map.empty] psbt) `shouldBe` Right [Nothing]

    -- The coin holds 200,000,000 satoshi and the outputs pay 99,999,699 and
    -- 100,000,000: 200,000,000 − 199,999,699 = 301
    it "gives the fee when every coin comes from its previous transaction" $
      psbtFee psbt `shouldBe` Right 301

    it "gives no fee when the amount of a coin is only a claim, when a coin is missing, or when the outputs pay more than the coins hold" $ do
      psbtFee witnessOnly `shouldBe` Left "Input 0: the coin is given as a witness output only, so its amount is not checked"
      psbtFee (withInputs [Map.empty] psbt) `shouldBe` Left "Input 0 has no coin"
      -- The same transaction with one more output of 302 satoshi
      let tx = psbt.unsignedTx
          paysMore = Psbt Version0 (Tx tx.version tx.inputs (tx.outputs <> [TxOut 302 ""]) [] tx.locktime) Map.empty psbt.inputs [Map.empty, Map.empty, Map.empty]
      psbtFee paysMore `shouldBe` Left "The outputs pay more than the coins hold"

    -- BIP 174: "The Signer may choose to fail to sign a segwit input if a
    -- non-witness UTXO is not provided."
    it "a signer refuses a SegWit version 0 coin known from its witness output only, and signs it with its previous transaction" $ do
      signPsbt btc ctx signer witnessOnly
        `shouldBe` Left "Input 0: the coin is given as a witness output only, and the signer requires the previous transaction of a SegWit version 0 coin"
      (signatureCounts =<< signPsbt btc ctx signer psbt) `shouldBe` Right [1]
      (signatureCounts =<< signPsbt btc ctx signer (withInputs [insertWitnessUtxo output (inputAt 0 psbt)] psbt)) `shouldBe` Right [1]

    it "a signer told to trust witness outputs signs a SegWit version 0 coin known from its witness output only" $
      (signatureCounts =<< signPsbt btc ctx (signer {requirePreviousTx = False}) witnessOnly) `shouldBe` Right [1]

    -- CVE-2020-14199. The signer holds two coins of 15 and 20 BTC. The
    -- writer of the PSBT understates the first as 5 BTC and overstates the
    -- second. A signature of each input commits to the amount of that input
    -- alone, so the signature of the second input would be valid in a
    -- transaction that burns the 10 BTC of difference as fee.
    it "a signer refuses a PSBT that states the amounts of its SegWit version 0 coins without their previous transactions" $ do
      let both = spendingTwo (marshal ctx program) (marshal ctx program)
          claimed = withInputs [insertWitnessUtxo (TxOut 500000000 (marshal ctx program)) Map.empty, insertWitnessUtxo (TxOut 2000000000 (marshal ctx program)) Map.empty] both
      signPsbt btc ctx signer claimed
        `shouldBe` Left "Input 0: the coin is given as a witness output only, and the signer requires the previous transaction of a SegWit version 0 coin"

    -- A Taproot signature commits to the amount of every coin (BIP 341)
    it "a signer signs a Taproot coin known from its witness output only" $ do
      let internal = derivePubKey ctx secretOne
          (taproot, _) = spendingPsbt ctx (taprootScriptOutput ctx (TaprootOutput internal Nothing))
      (fmap isJust . tapKeySig . inputAt 0 =<< signPsbt btc ctx signer (withInputs (insertInputTapInternalKey ctx internal <$> taproot.inputs) taproot)) `shouldBe` Right True

{- The fields of version 2, read one by one -}

version2FieldsSpec :: Spec
version2FieldsSpec =
  describe "The lock time fields of a PSBT of version 2" $ do
    -- 0x03 is the fallback lock time of the global map, 0x11 and 0x12 the
    -- lock times an input requires as a time and as a height
    it "read the fallback lock time of the global map, when it has one" $ do
      fallbackLockTime (Map.singleton (Key 0x03 "") (hexBytes "10270000")) `shouldBe` Right (Just 10000)
      fallbackLockTime Map.empty `shouldBe` Right Nothing
      fallbackLockTime (Map.singleton (Key 0x03 "") (hexBytes "1027")) `shouldSatisfy` either ("is not a 32-bit integer" `isSuffixOf`) (const False)

    it "read the lock times an input requires, as a time and as a height" $ do
      requiredTimeLockTime (Map.singleton (Key 0x11 "") (hexBytes "0065cd1d")) `shouldBe` Right (Just 500000000)
      requiredHeightLockTime (Map.singleton (Key 0x12 "") (hexBytes "10270000")) `shouldBe` Right (Just 10000)
      requiredTimeLockTime Map.empty `shouldBe` Right Nothing
      requiredHeightLockTime Map.empty `shouldBe` Right Nothing

    -- The global map of version 2 with no input and no output: the
    -- transaction version 2, the two counts of 0, and the PSBT version 2
    it "build a PSBT from its maps, and refuse maps that are not as many as the global map counts" $ do
      let globals = Map.fromList [(Key 0x02 "", hexBytes "02000000"), (Key 0x04 "", hexBytes "00"), (Key 0x05 "", hexBytes "00"), (Key 0xfb "", hexBytes "02000000")]
      (encodeHex . encodePsbt <$> psbtOfMaps globals [] []) `shouldBe` Right "70736274ff01020402000000010401000105010001fb040200000000"
      psbtOfMaps globals [Map.empty] [] `shouldBe` Left "The PSBT has 1 inputs, and its global map counts 0"
      psbtOfMaps globals [] [Map.empty] `shouldBe` Left "The PSBT has 1 outputs, and its global map counts 0"
