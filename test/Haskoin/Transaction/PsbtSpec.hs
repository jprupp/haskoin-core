{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
{-# OPTIONS_GHC -Wno-deprecations #-}

-- | The PSBT format of BIP 174, and its version 2 of BIP 370: the vectors
-- of both BIPs, the bytes of a PSBT and the refusals of what breaks the
-- spec, the fields of the spec, the roles: combining, signing, finalizing
-- and extracting, and the inputs and outputs a PSBT of version 2 takes.
module Haskoin.Transaction.PsbtSpec (spec) where

import BitcoinCore
import Control.Exception (evaluate)
import Control.Monad (foldM, forM, forM_)
import Crypto.Hash (Digest, SHA256, digestFromByteString)
import Data.Aeson ((.:), (.:?), (.=))
import Data.Aeson qualified as Json
import Data.Aeson.Key qualified as Key
import Data.Bits (xor)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as BL
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (serialize)
import Data.List (isPrefixOf, isSuffixOf)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromJust, fromMaybe, isJust, listToMaybe, mapMaybe)
import Data.Serialize qualified as S
import Data.String (fromString)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Word (Word32, Word64, Word8)
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Numeric (showHex)
import System.Environment (lookupEnv)
import System.Timeout (timeout)
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
compressedKey :: SecKey -> PublicKey
compressedKey secret = PublicKey (derivePubKey secret) True

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
  vectors373 <- runIO (readTestFile "psbt_bip373.json" :: IO Vectors371)
  do
    vectorsSpec vectors
    vectors370Spec vectors370
    rolesSpec vectors
    version2Spec
    bytesSpec vectors
    fieldsSpec vectors
    signingSpec
    signerChecksSpec
    signerScopeSpec
    inputByInputSpec
    coinsSpec
    version2FieldsSpec
    taprootChecksSpec vectors371
    taprootCostSpec
    decoderChecksSpec
    taprootSpec vectors371
    musig2Spec vectors373
    complexSpec
    core32Spec
    coreSigningSpec
    coreComplexSpec
    propertiesSpec

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

rolesSpec :: Vectors -> Spec
rolesSpec vectors =
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
    -- was known.
    it "a signer that trusts witness outputs makes the first signer's PSBT of the BIP from the updater's, and the second signer's" $ do
      psbt <- psbtOfVector (updaterWithSigHash vectors)
      let master = fromJust (xPrvImport btcTest "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF")
          trusting = (xPrvSigner master Nothing) {requirePreviousTx = False}
          holding paths = trusting {keyOfRecord = \public derivation -> if derivation.path `elem` paths then trusting.keyOfRecord public derivation else Nothing}
      (encodePsbt <$> signPsbt btcTest (holding ["m/0'/0'/0'", "m/0'/0'/2'"]) psbt) `shouldBe` Right (bytesOf (firstSigner vectors))
      (encodePsbt <$> signPsbt btcTest (holding ["m/0'/0'/1'", "m/0'/0'/3'"]) psbt) `shouldBe` Right (bytesOf (secondSigner vectors))

    -- The master key of the BIP holds the two keys of each input. Input 0
    -- has its previous transaction. Input 1 is the P2SH-P2WSH coin known
    -- from its witness output only.
    it
      "a signer that wants previous transactions signs the input \
      \of the updater's PSBT that has one, and leaves the other"
      $ do
        psbt <- psbtOfVector (updaterWithSigHash vectors)
        let master = fromJust (xPrvImport btcTest "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF")
        signed <- expectRight (signPsbt btcTest (xPrvSigner master Nothing) psbt)
        mapM (fmap length . partialSignatures) signed.inputs `shouldBe` Right [2, 0]
        inputAt 1 signed `shouldBe` inputAt 1 psbt

    -- The four cases the BIP lists under "Fails Signer checks", signed
    -- with the master key of the BIP. The input at fault never gains a
    -- signature. The numbers are the partial signatures of each input.
    describe "a signer adds no signature to the input at fault of the PSBTs that fail the signer checks of the BIP" $ do
      let master = fromJust (xPrvImport btcTest "tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF")
          trusting = (xPrvSigner master Nothing) {requirePreviousTx = False}
          counts = mapM (fmap length . partialSignatures) . (.inputs)
          failing i = psbtOfVector (vectors.valid !! i)
      -- No record names a key, so the signer holds none: nothing is signed
      it "a witness output for a legacy coin" $ do
        psbt <- failing 10
        counts psbt `shouldBe` Right [0, 0]
        (counts =<< signPsbt btcTest trusting psbt) `shouldBe` Right [0, 0]
      -- The redeem script of input 0 is no standard script, and does not
      -- hash to the coin. Input 1 is sound and is signed.
      it "a redeem script that does not match the coin, with the previous transaction" $ do
        psbt <- failing 11
        counts psbt `shouldBe` Right [1, 1]
        (counts =<< signPsbt btcTest trusting psbt) `shouldBe` Right [1, 2]
      -- The redeem script of input 1 does not hash to the coin. Input 0
      -- is sound and is signed.
      it "a redeem script that does not match the coin, with the witness output" $ do
        psbt <- failing 12
        counts psbt `shouldBe` Right [1, 1]
        (counts =<< signPsbt btcTest trusting psbt) `shouldBe` Right [2, 1]
      -- The witness script of input 1 is no standard script. Input 0 is
      -- sound and is signed.
      it "a witness script that does not match the redeem script" $ do
        psbt <- failing 13
        counts psbt `shouldBe` Right [1, 1]
        (counts =<< signPsbt btcTest trusting psbt) `shouldBe` Right [2, 1]

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
      (encodePsbt <$> finalizePsbt btc psbt) `shouldBe` Right (bytesOf (finalizer vectors))

    it "the finalizer leaves an input without enough signatures as it is" $ do
      psbt <- psbtOfVector (firstSigner vectors)
      finalizePsbt btc psbt `shouldBe` Right psbt

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
fieldsSpec :: Vectors -> Spec
fieldsSpec vectors =
  describe "The fields of a PSBT" $ do
    let publicKey text = forceRight (decodeSerial (hexBytes text)) :: PublicKey
        shown :: [(PublicKey, Derivation)] -> [(Text, Derivation)]
        shown records = [(encodeHex (encodeSerial key), derivation) | (key, derivation) <- records]

    it "read the derivation records of an input: the public key, the fingerprint of the master key and the path" $ do
      psbt <- psbtOfVector (updater vectors)
      records <- expectRight $ inputDerivations (inputAt 0 psbt)
      shown records
        `shouldBe` [ (firstKey, Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/0'"),
                     ("02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7", Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/1'")
                   ]

    it "read the derivation records of an output" $ do
      psbt <- psbtOfVector (updater vectors)
      records <- expectRight $ outputDerivations (outputAt 0 psbt)
      shown records `shouldBe` [("03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771", Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/4'")]

    -- The path is 0' (0x80000000) three times, each over four bytes,
    -- little-endian
    it "write a derivation record as the public key under the type, and the fingerprint then the path, four bytes an index" $ do
      let key = publicKey firstKey
      Map.toList (insertInputDerivation key (Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/0'") Map.empty)
        `shouldBe` [(Key 0x06 (hexBytes firstKey), hexBytes ("d90c6a4f" <> "00000080" <> "00000080" <> "00000080"))]
      Map.keys (insertOutputDerivation key (Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/4'") Map.empty)
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
      records <- expectRight (partialSignatures (inputAt 0 psbt))
      [(encodeHex (encodeSerial key), encodeHex signature) | (key, signature) <- records] `shouldBe` [(firstKey, firstSignature)]

    it "write a partial signature under the type 0x02 with the public key, and drop them all as a finalizer does" $ do
      let m = insertPartialSignature (publicKey firstKey) (hexBytes firstSignature) (insertSigHashType sigHashAll Map.empty)
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
      let xpub = fromJust $ xPubImport btc "xpub6CpGH79LXVkeiux2ZPWMpEubBrRfgcGCgy2HiagyN6NW3qdioJaqFYyD1fG6LDfxWEhMXJqcDuU5VneKt5UQYUGPa5Mfxdw2D2NArwX5TBm"
          record = (xpub, Derivation (fingerprintOf "27569c50") "m/49'/0'/0'")
      xpubRecords btc psbt.globals `shouldBe` Right [record]
      let m = insertXpubRecord btc xpub (snd record) Map.empty
      Map.keys m `shouldBe` [Key 0x01 (marshal btc xpub)]
      xpubRecords btc m `shouldBe` Right [record]

    -- The two keys of the vector are of the test network
    it "leave aside the extended public keys of another network" $ do
      psbt <- psbtOfVector (vectors.valid !! 5)
      let tpub text = fromJust $ xPubImport btcTest text
      xpubRecords btc psbt.globals `shouldBe` Right []
      xpubRecords btcTest psbt.globals
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
spendingPsbt :: ScriptOutput -> (Psbt, [(ScriptOutput, Word64, OutPoint)])
spendingPsbt coinScript = (Psbt Version0 tx Map.empty [input] [Map.empty, Map.empty], [(coinScript, 200000000, outpoint)])
  where
    parent = Tx 1 [TxIn (OutPoint "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389" 1) "" 0xffffffff] [TxOut 200000000 (encodeSerial coinScript)] [] 0
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
      PayWitness 1 _ -> insertWitnessUtxo (TxOut 200000000 (encodeSerial coinScript)) Map.empty
      _ -> insertNonWitnessUtxo parent Map.empty

-- | A derivation record of a key, which a signer needs: the fingerprint
-- and the path are those of the BIP's first signer
recordOf :: PublicKey -> PsbtMap -> PsbtMap
recordOf public = insertInputDerivation public (Derivation (fingerprintOf "d90c6a4f") "m/0'/0'/0'")

-- | A signer holding the keys
keysSigner :: [PrivateKey] -> Signer
keysSigner keys =
  Signer
    { keyOfRecord = \public derivation -> listToMaybe (mapMaybe (\key -> (keySigner key.key).keyOfRecord public derivation) keys),
      keyOfHash = \h -> listToMaybe (mapMaybe (\key -> (keySigner key.key).keyOfHash h) keys),
      acceptedSigHashes = defaultSigHashes,
      requirePreviousTx = True
    }

-- | Whether the transaction of the PSBT, once signed with the keys and
-- finalized, verifies against the coins it spends
signsAndVerifies :: Network -> [PrivateKey] -> (Psbt, [(ScriptOutput, Word64, OutPoint)]) -> Either String Bool
signsAndVerifies net keys (psbt, coins) = do
  signed <- signPsbt net (keysSigner keys) psbt
  final <- finalizePsbt net signed
  tx <- psbtTransaction final
  return (verifyStdTx net tx coins)

signingSpec :: Spec
signingSpec =
  describe "Signing and finalizing" $ do
    prop "a P2PKH coin, signed with the key of its address and finalized, verifies" $
      forAll arbitraryKeyPair $ \(secret, public) ->
        let (psbt, coins) = spendingPsbt (PayPKHash (addressHash (encodeSerial public)))
            withRecord = withInputs (recordOf public <$> psbt.inputs) psbt
         in signsAndVerifies btc [secret] (withRecord, coins) === Right True

    -- The finalized input keeps its coin, its final script, and the
    -- fields of version 2: the transaction it spends from, the output
    -- index and the sequence
    prop "a P2PKH coin of a PSBT of version 2, signed and finalized, verifies, and the PSBT stays of version 2 with the fields of its input" $
      forAll arbitraryKeyPair $ \(secret, public) ->
        let (psbt, coins) = spendingPsbt (PayPKHash (addressHash (encodeSerial public)))
            version2 = withVersion Version2 (withInputs (recordOf public <$> psbt.inputs) psbt)
            final = finalizePsbt btc =<< signPsbt btc (keysSigner [secret]) version2
         in (signsAndVerifies btc [secret] (version2, coins), (.version) <$> final, Map.keys . inputAt 0 <$> final)
              === (Right True, Right Version2, Right [Key 0x00 "", Key 0x07 "", Key 0x0e "", Key 0x0f "", Key 0x10 ""])

    prop "a P2SH multisig coin, signed with enough of its keys and finalized, verifies" $
      -- At most 7 keys: the redeem script of more uncompressed keys would be
      -- over the 520 bytes a P2SH redeem script can have
      forAll ((,) <$> arbitraryP2SHMSParam <*> arbitraryKeyPair) $ \((m, n), _) ->
        forAll (vectorOf n arbitraryKeyPair) $ \pairs ->
          let redeem = either error id $ encodeOutput (PayMulSig (snd <$> pairs) m)
              (psbt, coins) = spendingPsbt (either error id (toP2SH redeem))
              withFields = withInputs ((insertInputRedeemScript redeem . foldr (\(_, public) f -> recordOf public . f) id pairs) <$> psbt.inputs) psbt
           in signsAndVerifies btc (fst <$> take m pairs) (withFields, coins) === Right True

    -- The keys are compressed: a SegWit version 0 coin is not signed with
    -- an uncompressed key, which 'signerScopeSpec' tests
    prop "a P2WPKH coin, and a P2SH-P2WPKH one with its redeem script, signed and finalized, verify" $
      forAll arbitraryKeyPairC $ \(secret, public) ->
        let program = PayWitnessPKHash (addressHash (encodeSerial public))
            (native, nativeCoins) = spendingPsbt program
            redeem = either error id $ encodeOutput program
            (nested, nestedCoins) = spendingPsbt (either error id (toP2SH redeem))
            nativeWithRecord = withInputs (recordOf public <$> native.inputs) native
            nestedWithFields = withInputs ((insertInputRedeemScript redeem . recordOf public) <$> nested.inputs) nested
         in signsAndVerifies btc [secret] (nativeWithRecord, nativeCoins) === Right True
              .&&. signsAndVerifies btc [secret] (nestedWithFields, nestedCoins) === Right True

    prop "a P2WSH multisig coin with its witness script, nested in P2SH or not, signed and finalized, verifies" $
      forAll arbitraryMSParam $ \(m, n) ->
        forAll (vectorOf n arbitraryKeyPairC) $ \pairs ->
          let witness = either error id $ encodeOutput (PayMulSig (snd <$> pairs) m)
              program = either error id (toP2WSH witness)
              records = foldr (\(_, public) f -> recordOf public . f) id pairs
              (native, nativeCoins) = spendingPsbt program
              (nested, nestedCoins) = spendingPsbt (either error id (toP2SH programScript))
              nativeWithFields = withInputs ((insertInputWitnessScript witness . records) <$> native.inputs) native
              nestedWithFields = withInputs ((insertInputRedeemScript programScript . insertInputWitnessScript witness . records) <$> nested.inputs) nested
              programScript = either error id $ encodeOutput program
           in signsAndVerifies btc (fst <$> take m pairs) (nativeWithFields, nativeCoins) === Right True
                .&&. signsAndVerifies btc (fst <$> take m pairs) (nestedWithFields, nestedCoins) === Right True

    it "signs with the sighash the input asks for when the signer accepts it, SIGHASH_ALL when it asks for none" $ do
      let secret = PrivateKey secretOne True
          public = derivePublicKey secret
          (psbt, _) = spendingPsbt (PayPKHash (addressHash (encodeSerial public)))
          asking sh = withInputs ((recordOf public . maybe id insertSigHashType sh) <$> psbt.inputs) psbt
          sighashOf signed = map (B.last . snd) <$> partialSignatures (inputAt 0 signed)
          acceptingNone = (keySigner secret.key) {acceptedSigHashes = sigHashNone : defaultSigHashes}
      (sighashOf =<< signPsbt btc (keySigner secret.key) (asking Nothing)) `shouldBe` Right [0x01]
      (sighashOf =<< signPsbt btc (keySigner secret.key) (asking (Just sigHashAll))) `shouldBe` Right [0x01]
      -- SIGHASH_NONE leaves the outputs unsigned, so the signer must agree to it
      signPsbt btc (keySigner secret.key) (asking (Just sigHashNone)) `shouldBe` Left "Input 0: the sighash type 2 is not one the signer accepts"
      (sighashOf =<< signPsbt btc acceptingNone (asking (Just sigHashNone))) `shouldBe` Right [0x02]

    it "leaves an input without its coin, or signed already, as it is" $ do
      let secret = PrivateKey secretOne True
          public = derivePublicKey secret
          (psbt, _) = spendingPsbt (PayPKHash (addressHash (encodeSerial public)))
          withoutCoin = withInputs [recordOf public Map.empty] psbt
          final = withInputs ((insertFinalScriptSig "a script" . recordOf public) <$> psbt.inputs) psbt
      signPsbt btc (keySigner secret.key) withoutCoin `shouldBe` Right withoutCoin
      signPsbt btc (keySigner secret.key) final `shouldBe` Right final

    it "refuses a previous transaction that is not the one the input spends" $ do
      let public = compressedKey secretOne
          (psbt, _) = spendingPsbt (PayPKHash (addressHash (encodeSerial public)))
          wrong = withInputs [insertNonWitnessUtxo emptyTx Map.empty] psbt
      signPsbt btc (Signer (\_ _ -> Nothing) (const Nothing) defaultSigHashes True) wrong `shouldBe` Left "Input 0: the previous transaction is not the one the input spends"

    -- The derivation records name keys by the master key, b4a6ba67 with
    -- the full path, or by the extended key given, with the path from it
    it "finds the key an extended private key derives, by its own fingerprint or by the origin given" $ do
      let root = makeXPrvKey "PSBT signer test"
          rootFingerprint = xPubFP (deriveXPubKey root)
          account = derivePath (Deriv :| 444 :: HardPath) root
          accountFingerprint = xPubFP (deriveXPubKey account)
          secretAt path = (derivePath (path :: DerivPath) root).key
          publicOf secret = PublicKey (derivePubKey secret) True
          signer = xPrvSigner account (Just (Derivation rootFingerprint "m/444'"))
          unknownOrigin = xPrvSigner account Nothing
      signer.keyOfRecord (publicOf (secretAt "m/444'/0")) (Derivation rootFingerprint "m/444'/0") `shouldBe` Just (secretAt "m/444'/0")
      signer.keyOfRecord (publicOf (secretAt "m/444'/1")) (Derivation accountFingerprint "m/1") `shouldBe` Just (secretAt "m/444'/1")
      signer.keyOfRecord (publicOf (secretAt "m/444'/1")) (Derivation rootFingerprint "m/445'/1") `shouldBe` Nothing
      signer.keyOfRecord (publicOf (secretAt "m/444'/1")) (Derivation accountFingerprint "m/2") `shouldBe` Nothing
      unknownOrigin.keyOfRecord (publicOf (secretAt "m/444'/0")) (Derivation rootFingerprint "m/444'/0") `shouldBe` Nothing
      unknownOrigin.keyOfRecord (publicOf (secretAt "m/444'/0")) (Derivation accountFingerprint "m/0") `shouldBe` Just (secretAt "m/444'/0")
      -- An extended key cannot know which path a hash is at
      signer.keyOfHash (addressHash (encodeSerial (publicOf (secretAt "m/444'/0")))) `shouldBe` Nothing

{- A PSBT of every kind of coin -}

-- | The PSBTs of a transaction of nine coins of every kind, signed by
-- twelve wallets of Bitcoin Core one at a time, their combination, its
-- finalization and the transaction it gives: read from a file of the
-- repository, or made by a node of Bitcoin Core as the tests run
-- ('coreComplexSpec')
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

complexSpec :: Spec
complexSpec = do
  -- data/complex_psbt.json is the file of an older Bitcoin Core, in
  -- version 0. Each wallet finalized the coins it could complete alone.
  describe "The PSBT of nine coins of every kind, which twelve wallets of Bitcoin Core signed one at a time" $ do
    complex <- runIO (readTestFile "complex_psbt.json" :: IO Complex)
    before (return complex) complexChecks

  -- data/psbt_complex_core32.json is the file of Bitcoin Core 32.1, in
  -- version 2. The wallets signed with finalize=false, so that the
  -- combination holds partial signatures only.
  describe "The PSBT of nine coins of every kind, which twelve wallets of Bitcoin Core 32.1 signed without finalizing" $ do
    complex <- runIO (readTestFile "psbt_complex_core32.json" :: IO Complex)
    before (return complex) $ do
      version2Combination
      complexChecks

-- | The combination of PSBTs that Bitcoin Core 32.1 signed without
-- finalizing them
version2Combination :: SpecWith Complex
version2Combination =
  it "is a version 2 PSBT whose combination has no final input" $ \complex -> do
    complex.combinedPsbt.version `shouldBe` Version2
    length complex.combinedPsbt.inputs `shouldBe` 9
    -- Types 0x07 and 0x08 are the final script and the final witness
    length [key | input <- complex.combinedPsbt.inputs, key <- Map.keys input, key.keyType `elem` [0x07, 0x08]]
      `shouldBe` 0

-- | What holds for both files, and for what a node makes as the tests run:
-- the library combines, finalizes and extracts what Bitcoin Core combined,
-- finalized and extracted
complexChecks :: SpecWith Complex
complexChecks = do
  -- The PSBT Core created has no entry that a signed one lacks
  it "adds nothing to a signed PSBT when the PSBT Core created is combined with it" $ \complex ->
    mapM (combinePsbt complex.initialPsbt) complex.signedPsbts `shouldBe` Right complex.signedPsbts

  it "combines into the PSBT Core combined" $ \complex ->
    case complex.signedPsbts of
      first' : rest -> foldM combinePsbt first' rest `shouldBe` Right complex.combinedPsbt
      [] -> expectationFailure "No signed PSBT"

  it "finalizes into the PSBT Core finalized" $ \complex ->
    finalizePsbt btc complex.combinedPsbt `shouldBe` Right complex.completePsbt

  it "gives the transaction Core extracted" $ \complex ->
    psbtTransaction complex.completePsbt `shouldBe` Right complex.finalTx

{- Against a node of Bitcoin Core -}

-- | A key of the tests against Bitcoin Core, made from a label, with its
-- public key in hexadecimal and its private key in the wallet import format
-- of regtest, as descriptors write them
data TestKey = TestKey
  { private :: PrivateKey,
    publicHex :: Text,
    wif :: Text
  }

testKey :: ByteString -> TestKey
testKey label =
  TestKey
    { private = private,
      publicHex = encodeHex (encodeSerial (derivePublicKey private)),
      wif = toWif btcRegTest private
    }
  where
    -- A seed has 16 bytes at least
    private = wrapSecKey True (makeXPrvKey ("Key of the tests against Bitcoin Core: " <> label)).key

-- | The library signs the PSBTs that Bitcoin Core makes for coins of every
-- kind that both sign, and Bitcoin Core finalizes them and accepts their
-- transactions into its mempool. The library finalizes each into the same
-- transaction. Two of the three keys of a multisig coin sign apart, and
-- Bitcoin Core combines what they signed.
coreSigningSpec :: Spec
coreSigningSpec =
  describe ("Bitcoin Core " <> coreVersion <> " accepts the transactions of its PSBTs that the library signs") $
    aroundNode withMiner $
      forM_ kinds $ \(name, descriptor, signers) ->
        it ("for a coin of " <> T.unpack name) $ \node -> signedByLibrary node name descriptor signers
  where
    k1 = testKey "PSBT key 1"
    k2 = testKey "PSBT key 2"
    k3 = testKey "PSBT key 3"
    single = k1.publicHex
    multi = "sortedmulti(2," <> T.intercalate "," [k1.publicHex, k2.publicHex, k3.publicHex] <> ")"
    kinds =
      [ ("p2pkh", "pkh(" <> single <> ")", [k1]),
        ("p2sh-pk", "sh(pk(" <> single <> "))", [k1]),
        ("p2sh-ms", "sh(" <> multi <> ")", [k1, k2]),
        ("p2sh-wpkh", "sh(wpkh(" <> single <> "))", [k1]),
        ("p2sh-wsh-ms", "sh(wsh(" <> multi <> "))", [k1, k2]),
        ("p2wpkh", "wpkh(" <> single <> ")", [k1]),
        ("p2wsh-ms", "wsh(" <> multi <> ")", [k1, k2])
      ]
    -- The miner has the coinbases of a hundred blocks to spend
    withMiner node = do
      _ <- rpc node "createwallet" [Json.String "miner"]
      mine node 200
      return node

-- | The miner pays a coin to a descriptor. A wallet that watches the
-- descriptor, without its keys, makes a PSBT that spends the coin. The
-- library signs it with each key, and Bitcoin Core combines and finalizes
-- the result, and accepts its transaction.
signedByLibrary :: Node -> Text -> Text -> [TestKey] -> Expectation
signedByLibrary node name descriptor keys = do
  -- walletcreatefundedpsbt takes the lock time before the options
  let lockTime = Json.toJSON (0 :: Int)
  public <- textAt "descriptor" =<< rpc node "getdescriptorinfo" [Json.String descriptor]
  address <- firstText =<< rpc node "deriveaddresses" [Json.String public]
  -- The coin is output 0 of the funding transaction
  funding <-
    textAt "psbt"
      =<< walletRpc
        node
        "miner"
        "walletcreatefundedpsbt"
        [ emptyArray,
          Json.object [Key.fromText address .= (1 :: Int)],
          lockTime,
          Json.object ["changePosition" .= (1 :: Int)]
        ]
  fundingSigned <- textAt "psbt" =<< walletRpc node "miner" "walletprocesspsbt" [Json.String funding]
  fundingTx <- textAt "hex" =<< rpc node "finalizepsbt" [Json.String fundingSigned]
  fundingTxid <- rpc node "sendrawtransaction" [Json.String fundingTx]

  let watcher = "watch-" <> name
  _ <- rpc node "createwallet" [Json.String watcher, Json.Bool True]
  importDescriptor node watcher public
  mine node 10
  payee <- text =<< walletRpc node "miner" "getnewaddress" []
  change <- walletRpc node "miner" "getnewaddress" []
  -- The watcher has no address of its own, so the miner gets the change
  unsigned <-
    textAt "psbt"
      =<< walletRpc
        node
        watcher
        "walletcreatefundedpsbt"
        [ Json.toJSON [Json.object ["txid" .= fundingTxid, "vout" .= (0 :: Int)]],
          Json.object [Key.fromText payee .= (0.8 :: Double)],
          lockTime,
          Json.object ["changeAddress" .= change]
        ]

  psbt <- fromBase64 unsigned
  signed <- mapM (\k -> either fail return (signPsbt btcRegTest (keySigner k.private.key) psbt)) keys
  combined <- case signed of
    [one] -> return one
    _ -> fromBase64 =<< text =<< rpc node "combinepsbt" [Json.toJSON (map toBase64 signed)]
  finalized <- rpc node "finalizepsbt" [Json.String (toBase64 combined)]
  at "complete" finalized `shouldReturn` Json.Bool True
  tx <- either fail return . S.decode . hexBytes =<< textAt "hex" finalized
  (psbtTransaction =<< finalizePsbt btcRegTest combined) `shouldBe` Right tx
  rpc node "sendrawtransaction" [Json.String (encodeHex (S.encode tx))]
    `shouldReturn` Json.String (txHashToHex (txHash tx))

-- | 'complexChecks' on PSBTs that a node of Bitcoin Core makes and signs as
-- the tests run, as it made data/psbt_complex_core32.json. Set the variable
-- @HASKOIN_COMPLEX_PSBT@ to the path of a file to keep them there, in the
-- form of that file.
coreComplexSpec :: Spec
coreComplexSpec =
  describe
    ( "The PSBT of nine coins of every kind, which twelve wallets of Bitcoin Core "
        <> coreVersion
        <> " sign as the tests run"
    )
    $ aroundNode complexOfNode
    $ do
      version2Combination
      complexChecks

-- | Eight coins, one of each kind and each in wallets of its own, and the
-- change of the miner that paid them: a PSBT spends all nine, each wallet
-- signs it without finalizing, and Bitcoin Core combines, finalizes and
-- extracts. The transaction pays almost all of the change in fees, which
-- does not matter, since it is never sent.
complexOfNode :: Node -> IO Complex
complexOfNode node = do
  _ <- rpc node "createwallet" [Json.String "miner"]
  miner <- text =<< walletRpc node "miner" "getnewaddress" []
  mine node 101
  singles <-
    mapM
      single
      [ ("p2pkh", \k -> "pkh(" <> k <> ")"),
        ("p2sh_pk", \k -> "sh(pk(" <> k <> "))"),
        ("p2sh_wsh_pk", \k -> "sh(wsh(pk(" <> k <> ")))"),
        ("p2wpkh", \k -> "wpkh(" <> k <> ")"),
        ("p2wsh_pk", \k -> "wsh(pk(" <> k <> "))")
      ]
  multis <-
    mapM
      multi
      [ ("p2sh_ms", \m -> "sh(" <> m <> ")"),
        ("p2sh_wsh_ms", \m -> "sh(wsh(" <> m <> "))"),
        ("p2wsh_ms", \m -> "wsh(" <> m <> ")")
      ]
  let coins = singles <> multis
  let amounts = Json.object [Key.fromText a .= (0.5 :: Double) | (a, _) <- coins]
  funding <- text =<< walletRpc node "miner" "sendmany" [Json.String "", amounts]
  outputs <- list =<< at "vout" =<< rpc node "getrawtransaction" [Json.String funding, Json.Bool True]
  initial <-
    text
      =<< rpc
        node
        "createpsbt"
        [ Json.toJSON [Json.object ["txid" .= funding, "vout" .= i] | i <- [0 .. length outputs - 1]],
          Json.toJSON [Json.object [Key.fromText miner .= (3.99 :: Double)]]
        ]
  -- Each wallet leaves its signatures as partial signatures. Without
  -- finalize=false, Core would finalize the inputs it can complete alone.
  let signers = "miner" : concatMap snd coins
  -- The arguments: the PSBT, sign, the sighash type, bip32derivs, finalize
  let unfinalized = [Json.String initial, Json.Bool True, "ALL", Json.Bool True, Json.Bool False]
  signed <- forM signers $ \w -> textAt "psbt" =<< walletRpc node w "walletprocesspsbt" unfinalized
  combined <- text =<< rpc node "combinepsbt" [Json.toJSON signed]
  complete <- textAt "psbt" =<< rpc node "finalizepsbt" [Json.String combined, Json.Bool False]
  final <- textAt "hex" =<< rpc node "finalizepsbt" [Json.String combined, Json.Bool True]
  let file =
        Json.object $
          ["initial_psbt" .= initial]
            <> [Key.fromText (w <> "_psbt") .= s | (w, s) <- zip signers signed]
            <> ["combined_psbt" .= combined, "complete_psbt" .= complete, "final_tx" .= final]
  lookupEnv "HASKOIN_COMPLEX_PSBT" >>= mapM_ (\path -> BL.writeFile path (Json.encode file))
  case Json.fromJSON file of
    Json.Success complex -> return complex
    Json.Error e -> fail ("The PSBTs of the node do not read: " <> e)
  where
    -- A wallet holds the private key of the coin
    single (name, wrap) = do
      let k = testKey (encodeUtf8 ("complex " <> name))
      _ <- rpc node "createwallet" [Json.String name]
      importDescriptor node name =<< withChecksum (wrap k.wif)
      (,[name]) <$> addressOf (wrap k.publicHex)
    -- Three wallets each hold one of the private keys of the coin, and the
    -- first two sign
    multi (name, wrap) = do
      let ks = [testKey (encodeUtf8 ("complex " <> name <> " " <> T.pack (show i))) | i <- [1 .. 3 :: Int]]
          keysOf i = [if j == i then k.wif else k.publicHex | (j, k) <- zip [1 ..] ks]
          sorted i = "sortedmulti(2," <> T.intercalate "," (keysOf i) <> ")"
          wallets = [name <> "_" <> T.pack (show i) | i <- [1 .. 3 :: Int]]
      forM_ (zip [1 ..] wallets) $ \(i, w) -> do
        _ <- rpc node "createwallet" [Json.String w]
        importDescriptor node w =<< withChecksum (wrap (sorted i))
      (,take 2 wallets) <$> addressOf (wrap (sorted (0 :: Int)))
    withChecksum d = (\c -> d <> "#" <> c) <$> (textAt "checksum" =<< rpc node "getdescriptorinfo" [Json.String d])
    addressOf d = do
      public <- textAt "descriptor" =<< rpc node "getdescriptorinfo" [Json.String d]
      firstText =<< rpc node "deriveaddresses" [Json.String public]

-- | Mine blocks that pay the wallet of the miner
mine :: Node -> Int -> IO ()
mine node n = do
  address <- walletRpc node "miner" "getnewaddress" []
  _ <- rpc node "generatetoaddress" [Json.toJSON n, address]
  return ()

-- | Import a descriptor into a wallet, or fail with the reason the wallet
-- gives
importDescriptor :: Node -> Text -> Text -> IO ()
importDescriptor node wallet descriptor = do
  let request = Json.object ["desc" .= descriptor, "timestamp" .= ("now" :: Text)]
  results <- list =<< walletRpc node wallet "importdescriptors" [Json.toJSON [request]]
  forM_ results $ \r ->
    at "success" r >>= \case
      Json.Bool True -> return ()
      _ -> fail ("The wallet " <> T.unpack wallet <> " refused " <> T.unpack descriptor <> ": " <> show r)

emptyArray :: Json.Value
emptyArray = Json.toJSON ([] :: [Json.Value])

text :: Json.Value -> IO Text
text (Json.String t) = return t
text v = fail ("Not text: " <> show v)

list :: Json.Value -> IO [Json.Value]
list v = case Json.fromJSON v of
  Json.Success l -> return l
  Json.Error _ -> fail ("Not a list: " <> show v)

firstText :: Json.Value -> IO Text
firstText v =
  list v >>= \case
    first' : _ -> text first'
    [] -> fail "An empty list"

fromBase64 :: Text -> IO Psbt
fromBase64 = either fail return . decodePsbtBase64 . encodeUtf8

toBase64 :: Psbt -> Text
toBase64 = decodeUtf8 . encodePsbtBase64

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

core32Spec :: Spec
core32Spec =
  describe "The files of Bitcoin Core 32.1, which writes version 2 unless asked for version 0" $ do
    core <- runIO (readTestFile "psbt_core32.json" :: IO Core32)
    it "are the same payment in both versions: the version 2 file is the version 0 file converted, and back" $ do
      core.preparedV2.version `shouldBe` Version2
      core.preparedV2.unsignedTx `shouldBe` core.preparedV0.unsignedTx
      withVersion Version2 core.preparedV0 `shouldBe` core.preparedV2
      withVersion Version0 core.preparedV2 `shouldBe` core.preparedV0

    it "finalize into the PSBT Core finalized" $
      finalizePsbt btc core.signedV2 `shouldBe` Right core.finalizedV2

    it "give the transaction Core extracted" $
      psbtTransaction core.finalizedV2 `shouldBe` Right core.extractedTx

    -- The records name the key of the coin by the fingerprint bc560f95 of
    -- a seed and the path m/44'/0'/0'/0/0: the account key at m/44'/0'/0'
    -- of that seed signs. The coin is 50 BTC at the P2PKH script of that
    -- key.
    it "are signed with the account key the records name, into a transaction that verifies" $ do
      let account = fromJust (xPrvImport btc "xprv9yHxeaLAZvxXb9VtJNesqk8avfN8misGAW9DUW9eacZJNqsfZxqKLmK5jfmvFideQqGesviJeagzSQYCuQySjgvt7TdfowKja5aJqbgyuNh")
          signer = xPrvSigner account (Just (Derivation (fingerprintOf "bc560f95") "m/44'/0'/0'"))
      coin <- expectRight (decodeSerial (hexBytes "76a914c80d55223e2f1061363add2a7b0363c285bf298d88ac"))
      final <- expectRight (finalizePsbt btc =<< signPsbt btc signer core.preparedV2)
      tx <- expectRight (psbtTransaction final)
      final.version `shouldBe` Version2
      verifyStdTx btc tx [(coin, 5000000000, OutPoint "fede72ccadbf9f16f826e3078578b0660526a37b48d4f894ab26f4cf5a95e89c" 0)] `shouldBe` True

{- The checks of the signer and the finalizer -}

signerChecksSpec :: Spec
signerChecksSpec =
  describe "The checks of the signer and the finalizer" $ do
    let secret = PrivateKey secretOne True
        public = derivePublicKey secret
        otherPublic = compressedKey secretTwo
        (psbt, coins) = spendingPsbt (PayPKHash (addressHash (encodeSerial public)))
        parent = fromJust (either (const Nothing) id (nonWitnessUtxo (inputAt 0 psbt)))
        coin = head parent.outputs
        withInput m = withInputs [m] psbt
        signer = keySigner secret.key
        signed m = signPsbt btc signer (withInput (recordOf public m))
        signatureCount s = fmap length (partialSignatures (inputAt 0 s))

    -- BIP 174: "If a witness UTXO is provided, no non-witness signature
    -- may be created"
    it
      "adds no signature to a legacy coin known from its witness \
      \output only, which only a witness signature may use"
      $ do
        (signatureCount =<< signed (insertWitnessUtxo coin Map.empty)) `shouldBe` Right 0
        let trusting = signer {requirePreviousTx = False}
        (signatureCount =<< signPsbt btc trusting (withInput (insertWitnessUtxo coin Map.empty)))
          `shouldBe` Right 0

    -- The witness output beside the previous transaction claims 1 satoshi.
    -- The coin holds 200,000,000. Bitcoin Core takes the previous
    -- transaction and does not read the witness output then.
    it "takes the coin from the previous transaction, and does not look at a witness output beside it" $ do
      let claiming = insertWitnessUtxo (TxOut 1 coin.script) (insertNonWitnessUtxo parent Map.empty)
      (signatureCount =<< signed (insertWitnessUtxo coin (insertNonWitnessUtxo parent Map.empty))) `shouldBe` Right 1
      (signatureCount =<< signed claiming) `shouldBe` Right 1
      inputCoins (withInput claiming) `shouldBe` Right [Just (InputCoin (TxOut 200000000 coin.script) True)]

    it "refuses a sighash type no node accepts, and one whose fork id flag does not fit the network" $ do
      signed (insertSigHashType 0 (insertNonWitnessUtxo parent Map.empty)) `shouldBe` Left "Input 0: the sighash type 0 is not one a node accepts"
      signed (insertSigHashType 0x21 (insertNonWitnessUtxo parent Map.empty)) `shouldBe` Left "Input 0: the sighash type 33 is not one a node accepts"
      signed (insertSigHashType (setForkIdFlag sigHashAll) (insertNonWitnessUtxo parent Map.empty)) `shouldBe` Left "Input 0: the sighash type has a fork id flag the network does not use"
      signPsbt bch signer (withInput (recordOf public (insertSigHashType sigHashAll (insertNonWitnessUtxo parent Map.empty))))
        `shouldBe` Left "Input 0: the sighash type lacks the fork id flag the network requires"
      -- With the flag, the Bitcoin Cash digest signs
      (signatureCount =<< signPsbt bch signer (withInput (recordOf public (insertSigHashType (setForkIdFlag sigHashAll) (insertNonWitnessUtxo parent Map.empty))))) `shouldBe` Right 1

    it "refuses a sighash type the signer does not accept, and signs with it once the signer lists it" $ do
      let acceptingSingle = signer {acceptedSigHashes = [sigHashSingle]}
          askingSingle = insertSigHashType sigHashSingle (insertNonWitnessUtxo parent Map.empty)
      signed askingSingle `shouldBe` Left "Input 0: the sighash type 3 is not one the signer accepts"
      (signatureCount =<< signPsbt btc acceptingSingle (withInput (recordOf public askingSingle))) `shouldBe` Right 1
      -- ANYONECANPAY makes another type: 0x81 is not 0x01
      signed (insertSigHashType (setAnyoneCanPay sigHashAll) (insertNonWitnessUtxo parent Map.empty)) `shouldBe` Left "Input 0: the sighash type 129 is not one the signer accepts"

    -- Two coins of the same script, spent by one transaction with one
    -- output: input 1 has no output at its index
    it
      "adds no SIGHASH_SINGLE signature to a legacy input that has no output at \
      \its index, signs the input that has one, and signs both on SegWit coins"
      $ do
        let witnessCoin = TxOut 200000000 (encodeSerial (PayWitnessPKHash (addressHash (encodeSerial public))))
            parentOf c = Tx 1 [TxIn (OutPoint "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389" 1) "" 0xffffffff] [c, c] [] 0
            spendingBoth p = Tx 2 [TxIn (OutPoint (txHash p) 0) "" 0xfffffffe, TxIn (OutPoint (txHash p) 1) "" 0xfffffffe] [TxOut 399999000 (hexBytes "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac")] [] 0
            askingSingle p = recordOf public (insertSigHashType sigHashSingle (insertNonWitnessUtxo p Map.empty))
            psbtOf p = Psbt Version0 (spendingBoth p) Map.empty [askingSingle p, askingSingle p] [Map.empty]
            acceptingSingle = signer {acceptedSigHashes = [sigHashSingle]}
        signedLegacy <- expectRight (signPsbt btc acceptingSingle (psbtOf (parentOf coin)))
        mapM (fmap length . partialSignatures) signedLegacy.inputs `shouldBe` Right [1, 0]
        -- The BIP 143 digest commits to the coin, so the SegWit signature is fine
        (signatureCount =<< signPsbt btc acceptingSingle (psbtOf (parentOf witnessCoin))) `shouldBe` Right 1
        (fmap length . partialSignatures . inputAt 1 =<< signPsbt btc acceptingSingle (psbtOf (parentOf witnessCoin))) `shouldBe` Right 1

    -- BIP 174: "If a redeemScript is provided, the scriptPubKey must be
    -- for that redeemScript"
    it
      "adds no signature when the redeem script does not hash \
      \to the coin, nor when the coin is not pay-to-script-hash"
      $ do
        let ms = PayMulSig [public, otherPublic] 1
            msScript = either error id (encodeOutput ms)
            wrongScript = either error id (encodeOutput (PayMulSig [otherPublic, public] 1))
            (p2sh, _) = spendingPsbt (either error id (toP2SH msScript))
            p2shParent = fromJust (either (const Nothing) id (nonWitnessUtxo (inputAt 0 p2sh)))
            p2shInput m = withInputs [recordOf public (insertNonWitnessUtxo p2shParent m)] p2sh
        (signatureCount =<< signPsbt btc signer (p2shInput (insertInputRedeemScript msScript Map.empty))) `shouldBe` Right 1
        (signatureCount =<< signPsbt btc signer (p2shInput (insertInputRedeemScript wrongScript Map.empty)))
          `shouldBe` Right 0
        (signatureCount =<< signed (insertInputRedeemScript msScript (insertNonWitnessUtxo parent Map.empty)))
          `shouldBe` Right 0

    -- BIP 174: "If a witnessScript is provided, the scriptPubKey or the
    -- redeemScript must be for that witnessScript"
    it
      "adds no signature when the witness script does not hash to \
      \the witness program, nor when the coin has no witness script"
      $ do
        let ms = PayMulSig [public, otherPublic] 1
            msScript = either error id (encodeOutput ms)
            wrongScript = either error id (encodeOutput (PayMulSig [otherPublic, public] 1))
            (p2wsh, _) = spendingPsbt (either error id (toP2WSH msScript))
            p2wshInput m = withInputs [recordOf public (Map.union m (inputAt 0 p2wsh))] p2wsh
        (signatureCount =<< signPsbt btc signer (p2wshInput (insertInputWitnessScript msScript Map.empty))) `shouldBe` Right 1
        (signatureCount =<< signPsbt btc signer (p2wshInput (insertInputWitnessScript wrongScript Map.empty)))
          `shouldBe` Right 0
        (signatureCount =<< signed (insertInputWitnessScript msScript (insertNonWitnessUtxo parent Map.empty)))
          `shouldBe` Right 0

    it "leaves an input whose coin script is not standard as it is, and signs the others" $ do
      let weird = TxOut 1000 (runPutS (serialize (Script [OP_1])))
          parent2 = Tx 1 parent.inputs [coin, weird] [] 0
          op0 = OutPoint (txHash parent2) 0
          op1 = OutPoint (txHash parent2) 1
          tx = Tx 2 [TxIn op0 "" 0xfffffffe, TxIn op1 "" 0xfffffffe] psbt.unsignedTx.outputs [] 0
          both = Psbt Version0 tx Map.empty [recordOf public (insertNonWitnessUtxo parent2 Map.empty), insertNonWitnessUtxo parent2 Map.empty] [Map.empty, Map.empty]
      s <- expectRight (signPsbt btc signer both)
      map hasPartialSignatures s.inputs `shouldBe` [True, False]
      f <- expectRight (finalizePsbt btc s)
      map (isJust . finalScriptSig) f.inputs `shouldBe` [True, False]

    it "signs a coin whose key it holds without a derivation record, by the hash of the key" $ do
      (signatureCount =<< signPsbt btc signer (withInput (insertNonWitnessUtxo parent Map.empty))) `shouldBe` Right 1
      -- A multisig coin names its keys
      let ms = PayMulSig [public, otherPublic] 1
          msScript = either error id (encodeOutput ms)
          (p2sh, p2shCoins) = spendingPsbt (either error id (toP2SH msScript))
          p2shParent = fromJust (either (const Nothing) id (nonWitnessUtxo (inputAt 0 p2sh)))
          p2shFields = withInputs [insertInputRedeemScript msScript (insertNonWitnessUtxo p2shParent Map.empty)] p2sh
      s <- expectRight (signPsbt btc signer p2shFields)
      signatureCount s `shouldBe` Right 1
      signsAndVerifies btc [secret] (p2shFields, p2shCoins) `shouldBe` Right True
      -- The other key is not held
      (signatureCount =<< signPsbt btc (keySigner secret.key) (fst (spendingPsbt (PayPKHash (addressHash (encodeSerial otherPublic)))))) `shouldBe` Right 0
      coins `seq` return ()

    it
      "the finalizer leaves alone an input whose signature is not a signature, \
      \has another sighash type than the input asks, or does not verify"
      $ do
        s <- expectRight (signed (insertNonWitnessUtxo parent Map.empty))
        signature <- case either error id (partialSignatures (inputAt 0 s)) of
          [(_, sig)] -> return sig
          _ -> fail "one signature"
        let withSig sig m = withInput (insertPartialSignature public sig m)
            leftAlone unsigned = finalizePsbt btc unsigned `shouldBe` Right unsigned
        -- 3045aa01 ends with the byte of SIGHASH_ALL, and is no signature
        leftAlone (withSig "\x30\x45\xaa\x01" (insertNonWitnessUtxo parent Map.empty))
        leftAlone (withSig signature (insertSigHashType sigHashNone (insertNonWitnessUtxo parent Map.empty)))
        -- The signature of the same key on another transaction
        let sameKeyOther = withInputs [recordOf public (insertNonWitnessUtxo parent Map.empty)] (Psbt Version0 (Tx 2 psbt.unsignedTx.inputs [] [] 0) Map.empty psbt.inputs [])
        elsewhere <- expectRight (signPsbt btc signer sameKeyOther)
        foreignSig <- case either error id (partialSignatures (inputAt 0 elsewhere)) of
          [(_, sig)] -> return sig
          _ -> fail "one signature"
        leftAlone (withSig foreignSig (insertNonWitnessUtxo parent Map.empty))
        -- The right signature finalizes
        f <- expectRight (finalizePsbt btc (withSig signature (insertNonWitnessUtxo parent Map.empty)))
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

-- | Why each invalid PSBT of BIP 373 is refused, as the end of the reason.
-- An x-only key has 32 bytes where the BIP wants a compressed key of 33.
refusals373 :: [String]
refusals373 =
  [ "is not a compressed public key",
    "is not a list of compressed public keys",
    "is not a compressed public key",
    "is not a list of compressed public keys",
    "is not a participant key and an aggregate key, with a leaf hash or none",
    "is not a participant key and an aggregate key, with a leaf hash or none",
    "is not a public nonce of 66 bytes",
    "is not a participant key and an aggregate key, with a leaf hash or none",
    "is not a participant key and an aggregate key, with a leaf hash or none",
    "is not a partial signature of 32 bytes"
  ]

-- The vectors live in data/psbt_bip373.json, copied from the BIP. The
-- library keeps the MuSig2 fields and does not sign with them.
musig2Spec :: Vectors371 -> Spec
musig2Spec vectors =
  describe "The MuSig2 fields of BIP 373" $ do
    describe "the invalid PSBTs are refused, each for its reason" $
      forM_ (zip vectors.refused371 refusals373) $ \(v, reason) ->
        it v.vecCase $ decodePsbt (bytesOf v) `shouldSatisfy` either (reason `isSuffixOf`) (const False)

    describe "the valid PSBTs are read, and written back byte for byte" $
      forM_ vectors.accepted371 $ \v ->
        it v.vecCase $ (encodePsbt <$> decodePsbt (bytesOf v)) `shouldBe` Right (bytesOf v)

    it "there are 10 invalid PSBTs and 14 valid ones" $
      (length vectors.refused371, length vectors.accepted371) `shouldBe` (10, 14)

    -- The key is the type and a compressed key, 34 bytes (0x22). The value
    -- is no key, then one key, then one key and a byte, then a key that
    -- is no point of the curve.
    it "reads participant keys that are compressed public keys, as many as there are, on an input and on an output" $
      forM_ ["00", "21" <> aPoint, "42" <> aPoint <> aPoint] $ \value -> do
        (encodePsbt <$> decodePsbt (tinyPsbt "" ("221a" <> aPoint <> value) ""))
          `shouldBe` Right (tinyPsbt "" ("221a" <> aPoint <> value) "")
        (encodePsbt <$> decodePsbt (tinyPsbt "" "" ("2208" <> aPoint <> value)))
          `shouldBe` Right (tinyPsbt "" "" ("2208" <> aPoint <> value))

    it "refuses participant keys that are not whole compressed public keys on the curve" $ do
      let refusal what =
            Left . mconcat $
              [ what <> ": the value of the key 0x1a with the data " <> T.unpack aPoint,
                " is not a list of compressed public keys"
              ]
      decodePsbt (tinyPsbt "" ("221a" <> aPoint <> "22" <> aPoint <> "00") "") `shouldBe` refusal "Input 0"
      decodePsbt (tinyPsbt "" ("221a" <> aPoint <> "21" <> notAPoint) "") `shouldBe` refusal "Input 0"
      decodePsbt (tinyPsbt "" ("221a" <> notAPoint <> "00") "")
        `shouldBe` Left
          ("Input 0: the key 0x1a with the data " <> T.unpack notAPoint <> " is not a compressed public key")

    -- The generator of the curve as an uncompressed key of 65 bytes: with
    -- the type, a key of 66 bytes (0x42)
    it "refuses an aggregate key that is an uncompressed public key" $ do
      let generator =
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
            \483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
      decodePsbt (tinyPsbt "" ("421a" <> generator <> "00") "")
        `shouldSatisfy` either ("is not a compressed public key" `isSuffixOf`) (const False)

    -- The key is the type, a participant key and an aggregate key, 67 bytes
    -- (0x43), or 99 (0x63) with a leaf hash. A nonce has 66 bytes (0x42)
    -- and a partial signature 32 (0x20).
    it "reads a public nonce and a partial signature, with a leaf hash or none" $ do
      let nonce = "42" <> T.replicate 66 "ab"
          partial = "20" <> T.replicate 32 "ab"
          leafHash' = T.replicate 32 "cd"
      let entries =
            [ "431b" <> aPoint <> aPoint <> nonce,
              "631b" <> aPoint <> aPoint <> leafHash' <> nonce,
              "431c" <> aPoint <> aPoint <> partial,
              "631c" <> aPoint <> aPoint <> leafHash' <> partial
            ]
      forM_ entries $ \entry ->
        (encodePsbt <$> decodePsbt (tinyPsbt "" entry "")) `shouldBe` Right (tinyPsbt "" entry "")

    it
      "refuses a public nonce or a partial signature under a \
      \key that is no point of the curve, or of another length"
      $ do
        let nonce = "42" <> T.replicate 66 "ab"
            refused entry =
              decodePsbt (tinyPsbt "" entry "")
                `shouldSatisfy` either (noSignerKey `isSuffixOf`) (const False)
            noSignerKey = "is not a participant key and an aggregate key, with a leaf hash or none"
        refused ("431b" <> notAPoint <> aPoint <> nonce)
        refused ("431b" <> aPoint <> notAPoint <> nonce)
        refused ("441b" <> aPoint <> aPoint <> "cd" <> nonce)
        refused ("431c" <> aPoint <> notAPoint <> "20" <> T.replicate 32 "ab")

    it "refuses a public nonce that has not 66 bytes, and a partial signature that has not 32" $ do
      decodePsbt (tinyPsbt "" ("431b" <> aPoint <> aPoint <> "41" <> T.replicate 65 "ab") "")
        `shouldSatisfy` either ("is not a public nonce of 66 bytes" `isSuffixOf`) (const False)
      decodePsbt (tinyPsbt "" ("431c" <> aPoint <> aPoint <> "21" <> T.replicate 33 "ab") "")
        `shouldSatisfy` either ("is not a partial signature of 32 bytes" `isSuffixOf`) (const False)

taprootSpec :: Vectors371 -> Spec
taprootSpec vectors =
  describe "The Taproot fields of BIP 371" $ do
    describe "the invalid PSBTs are refused, each for its reason" $
      forM_ (zip vectors.refused371 refusals371) $ \(v, reason) ->
        it v.vecCase $ decodePsbt (bytesOf v) `shouldSatisfy` either (reason `isSuffixOf`) (const False)

    describe "the valid PSBTs are read, and written back byte for byte" $
      forM_ vectors.accepted371 $ \v ->
        it v.vecCase $ (encodePsbt <$> decodePsbt (bytesOf v)) `shouldBe` Right (bytesOf v)

    let vectorAt i = psbtOfVector (vectors.accepted371 !! i)
        xOnly text = fromJust (importXOnlyPubKey (hexBytes text))
        digest text = fromJust (digestFromByteString (hexBytes text)) :: Digest SHA256
        keyScript text = Script [opPushData (hexBytes text), OP_CHECKSIG]

    it "read the internal key and the derivation of a key path input" $ do
      psbt <- vectorAt 0
      inputTapInternalKey (inputAt 0 psbt) `shouldBe` Right (Just (xOnly "fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232"))
      inputTapDerivations (inputAt 0 psbt) `shouldBe` Right [(xOnly "fe349064c98d6e2a853fa3c9b12bd8b304a19c195c60efa7ee2393046d3fa232", TapDerivation [] (Derivation (fingerprintOf "772b2da7") "m/86'/1'/0'/1/0"))]
      inputTapMerkleRoot (inputAt 0 psbt) `shouldBe` Right Nothing
      tapKeySig (inputAt 0 psbt) `shouldBe` Right Nothing

    it "read the key path signature of a signed input, and finalize it into a witness of that signature" $ do
      psbt <- vectorAt 1
      let sigHex = "bb53ec917bad9d906af1ba87181c48b86ace5aae2b53605a725ca74625631476fc6f5baedaf4f2ee0f477f36f58f3970d5b8273b7e497b97af2e3f125c97af34"
          sig = fromJust (schnorrSig (hexBytes sigHex))
      tapKeySig (inputAt 0 psbt) `shouldBe` (Just <$> taprootSignature sig sigHashDefault)
      final <- expectRight (finalizePsbt btc psbt)
      finalScriptWitness (inputAt 0 final) `shouldBe` Right (Just [hexBytes sigHex])
      Map.keys (inputAt 0 final) `shouldBe` [Key 0x01 "", Key 0x08 ""]
      tx <- expectRight (psbtTransaction final)
      let coin = TxOut 5000000000 (hexBytes "51205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757")
      verifyStdTx btc tx [(either error id (decodeSerial coin.script), coin.value, (head tx.inputs).outpoint)] `shouldBe` True

    it "read the internal key and the derivation of a key path output" $ do
      psbt <- vectorAt 2
      outputTapInternalKey (outputAt 0 psbt) `shouldBe` Right (Just (xOnly "1124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e671"))
      outputTapDerivations (outputAt 0 psbt) `shouldBe` Right [(xOnly "1124da7aec92ccd06c954562647f437b138b95721a84be2bf2276bbddab3e671", TapDerivation [] (Derivation (fingerprintOf "772b2da7") "m/86'/1'/0'/0/5"))]
      outputTapTree (outputAt 0 psbt) `shouldBe` Right Nothing

    it "read the leaf scripts, the derivations with their leaves, the internal key and the Merkle root of a script path input" $ do
      psbt <- vectorAt 3
      leaves <- expectRight (tapLeafScripts (inputAt 0 psbt))
      map (.script) leaves
        `shouldBe` [ keyScript "2cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2",
                     keyScript "4320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b2",
                     keyScript "fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca9"
                   ]
      map (.leafVersion) leaves `shouldBe` [0xc0, 0xc0, 0xc0]
      map (B.length . (.controlBlock)) leaves `shouldBe` [97, 65, 97]
      inputTapInternalKey (inputAt 0 psbt) `shouldBe` Right (Just (xOnly "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))
      inputTapMerkleRoot (inputAt 0 psbt) `shouldBe` Right (Just (digest "f0362e2f75a6f420a5bde3eb221d96ae6720cf25f81890c95b1d775acb515e65"))
      records <- expectRight (inputTapDerivations (inputAt 0 psbt))
      lookup (xOnly "2cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2") records
        `shouldBe` Just (TapDerivation [digest "cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09"] (Derivation (fingerprintOf "772b2da7") "m/86'/1'/2'/0/0"))
      lookup (xOnly "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0") records
        `shouldBe` Just (TapDerivation [] (Derivation (fingerprintOf "7c461e5d") "m"))
      -- The leaf hash of the record is the hash of the leaf script
      leafHash 0xc0 (keyScript "2cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2") `shouldBe` digest "cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09"
      -- The control blocks commit the leaves to the output key, with the Merkle root
      let outKey = fromJust (importXOnlyPubKey (hexBytes "c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b692"))
      forM_ leaves $ \leaf -> do
        (v, internal, proof) <- expectRight (decodeControlBlock leaf.controlBlock)
        verifyScriptPathData outKey (ScriptPathData Nothing [] leaf.script (odd v) 0xc0 internal proof Nothing) `shouldBe` True

    it "read the script tree of a script path output, whose leaves build the tree of its output key" $ do
      psbt <- vectorAt 4
      let leaves =
            [ TapLeaf 2 0xc0 (keyScript "736e572900fe1252589a2143c8f3c79f71a0412d2353af755e9701c782694a02"),
              TapLeaf 2 0xc0 (keyScript "631c5f3b5832b8fbdebfb19704ceeb323c21f40f7a24f43d68ef0cc26b125969"),
              TapLeaf 1 0xc0 (keyScript "44faa49a0338de488c8dfffecdfb6f329f380bd566ef20c8df6d813eab1c4273")
            ]
      outputTapTree (outputAt 0 psbt) `shouldBe` Right (Just leaves)
      outputTapInternalKey (outputAt 0 psbt) `shouldBe` Right (Just (xOnly "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))
      let tree = fromJust (tapTreeFromLeaves leaves)
          output = TaprootOutput (xOnly "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0") (Just tree)
      encodeSerial (forceRight (taprootScriptOutput output)) `shouldBe` (head psbt.unsignedTx.outputs).script
      Map.lookup (Key 0x06 "") (insertOutputTapTree leaves Map.empty) `shouldBe` Map.lookup (Key 0x06 "") (outputAt 0 psbt)
      records <- expectRight (outputTapDerivations (outputAt 0 psbt))
      length records `shouldBe` 4

    -- The tree of the vector has one leaf at depth 1 and two at depth 2,
    -- and all three are signed. A control block is 33 bytes and 32 for
    -- each level: 65 bytes at depth 1, 97 at depth 2.
    it
      "read the script path signatures of a signed input, and finalize \
      \it with the signed leaf that has the shortest control block"
      $ do
        psbt <- vectorAt 5
        sigs <- expectRight (tapScriptSigs (inputAt 0 psbt))
        map (\((k, h), s) -> (exportXOnlyPubKey k, h, B.length (encodeTaprootSig s))) sigs
          `shouldBe` [ (hexBytes "2cb13ac68248de806aa6a3659cf3c03eb6821d09c8114a4e868febde865bb6d2", digest "cd970e15f53fc0c82f950fd560ffa919b76172be017368a89913af074f400b09", 64),
                       (hexBytes "4320b0bf16f011b53ea7be615924aa7f27e5d29ad20ea1155d848676c3bad1b2", digest "115f2e490af7cc45c4f78511f36057ce5c5a5c56325a29fb44dfc203f356e1f8", 64),
                       (hexBytes "fa0f7a3cef3b1d0c0a6ce7d26e17ada0b2e5c92d19efad48b41859cb8a451ca9", digest "6f7d62059e9497a1a4a267569d9876da60101aff38e3529b9b939ce7f91ae970", 64)
                     ]
        final <- expectRight (finalizePsbt btc psbt)
        witness <- expectRight (finalScriptWitness (inputAt 0 final))
        fmap (map B.length) witness `shouldBe` Just [64, 34, 65]
        tx <- expectRight (psbtTransaction final)
        let coin = TxOut 5000000000 (hexBytes "5120c2247efbfd92ac47f6f40b8d42d169175a19fa9fa10e4a25d7f35eb4dd85b692")
        verifyStdTx btc tx [(either error id (decodeSerial coin.script), coin.value, (head tx.inputs).outpoint)] `shouldBe` True

    it "write the fields back as they were read" $
      forM_ [0 .. 5] $ \i -> do
        psbt <- vectorAt i
        forM_ psbt.inputs $ \m -> do
          key <- expectRight (inputTapInternalKey m)
          forM_ key $ \k -> Map.lookup (Key 0x17 "") (insertInputTapInternalKey k Map.empty) `shouldBe` Map.lookup (Key 0x17 "") m
          root <- expectRight (inputTapMerkleRoot m)
          forM_ root $ \r -> Map.lookup (Key 0x18 "") (insertInputTapMerkleRoot r Map.empty) `shouldBe` Map.lookup (Key 0x18 "") m
          sig <- expectRight (tapKeySig m)
          forM_ sig $ \s -> Map.lookup (Key 0x13 "") (insertTapKeySig s Map.empty) `shouldBe` Map.lookup (Key 0x13 "") m
          leaves <- expectRight (tapLeafScripts m)
          Map.toList (foldr insertTapLeafScript Map.empty leaves) `shouldBe` [(k, v) | (k, v) <- Map.toList m, k.keyType == 0x15]
          records <- expectRight (inputTapDerivations m)
          Map.toList (foldr (uncurry insertInputTapDerivation) Map.empty records) `shouldBe` [(k, v) | (k, v) <- Map.toList m, k.keyType == 0x16]
          sigs <- expectRight (tapScriptSigs m)
          Map.toList (foldr (\((k, h), s) -> insertTapScriptSig k h s) Map.empty sigs) `shouldBe` [(k, v) | (k, v) <- Map.toList m, k.keyType == 0x14]
        forM_ psbt.outputs $ \m -> do
          key <- expectRight (outputTapInternalKey m)
          forM_ key $ \k -> Map.lookup (Key 0x05 "") (insertOutputTapInternalKey k Map.empty) `shouldBe` Map.lookup (Key 0x05 "") m
          records <- expectRight (outputTapDerivations m)
          Map.toList (foldr (uncurry insertOutputTapDerivation) Map.empty records) `shouldBe` [(k, v) | (k, v) <- Map.toList m, k.keyType == 0x07]

    prop "a Taproot coin without script tree, signed by its key path with the internal key and finalized, verifies" $
      forAll arbitraryKeyPair $ \(secret, public) ->
        let coinScript = forceRight (taprootScriptOutput (TaprootOutput public.point Nothing))
            (psbt, coins) = spendingPsbt coinScript
            fields = insertInputTapInternalKey public.point . insertInputTapDerivation public.point (TapDerivation [] (Derivation (fingerprintOf "d90c6a4f") "m/86'/0'/0'/0/0"))
            withFields = withInputs (fields <$> psbt.inputs) psbt
            signed = signPsbt btc (keySigner secret.key) withFields
         in (signsAndVerifies btc [secret] (withFields, coins), fmap (fmap (fmap (.hash)) . tapKeySig . inputAt 0) signed) === (Right True, Right (Right (Just sigHashDefault)))

    prop "a Taproot coin with a leaf that checks one key, signed by that leaf and finalized, verifies" $
      forAll ((,) <$> arbitraryKeyPair <*> arbitraryKeyPair) $ \((secret, public), (_, internal)) ->
        let leaf = Script [opPushData (exportXOnlyPubKey public.point), OP_CHECKSIG]
            tree = MASTBranch (MASTLeaf 0xc0 leaf) (MASTLeaf 0xc0 (Script [OP_RETURN]))
            output = TaprootOutput internal.point (Just tree)
            coinScript = forceRight (taprootScriptOutput output)
            (psbt, coins) = spendingPsbt coinScript
            proof = case getMerkleProofs tree of
              (_, _, p) : _ -> p
              [] -> []
            control = encodeControlBlock (0xc0 + keyParity (forceRight (taprootOutputKey output))) internal.point proof
            fields =
              insertInputTapInternalKey internal.point
                . insertInputTapMerkleRoot (mastCommitment tree)
                . insertTapLeafScript (TapLeafScript control leaf 0xc0)
                . insertInputTapDerivation public.point (TapDerivation [leafHash 0xc0 leaf] (Derivation (fingerprintOf "d90c6a4f") "m/86'/0'/0'/0/1"))
            withFields = withInputs (fields <$> psbt.inputs) psbt
         in signsAndVerifies btc [secret] (withFields, coins) === Right True

    it "the signer refuses a sighash type a Taproot signature may not use" $ do
      let public = derivePublicKey (PrivateKey secretOne True)
          (psbt, _) = spendingPsbt (forceRight (taprootScriptOutput (TaprootOutput public.point Nothing)))
          fields = insertSigHashType (setForkIdFlag sigHashAll) . insertInputTapInternalKey public.point
      signPsbt btc (keySigner secretOne) (onInputs fields psbt)
        `shouldBe` Left "Input 0: the sighash type 65 is not one a Taproot signature may use"

    -- The coin is the one of key 1, and the input names key 2 as its
    -- internal key. A signature of key 2 would verify for no coin, and BIP
    -- 174 has a signer make only valid signatures. Bitcoin Core does not
    -- refuse such a PSBT, so the input is left as it is.
    it "the signer adds no key path signature when the internal key of the input does not give the coin" $ do
      let public = derivePublicKey (PrivateKey secretOne True)
          other = compressedKey secretTwo
          (psbt, _) = spendingPsbt (forceRight (taprootScriptOutput (TaprootOutput public.point Nothing)))
          naming = withInputs [insertInputTapInternalKey other.point (inputAt 0 psbt)] psbt
      -- The signer of key 2 holds the internal key that the input names
      signPsbt btc (keySigner secretTwo) naming `shouldBe` Right naming
      -- The signer of key 1 holds no key that the input names
      signPsbt btc (keySigner secretOne) naming `shouldBe` Right naming
      -- Without the internal key, the input is left alone
      signPsbt btc (keySigner secretOne) psbt `shouldBe` Right psbt

{- Properties -}

propertiesSpec :: Spec
propertiesSpec =
  describe "Any PSBT" $ do
    prop "is read back as it was written" $
      forAll (arbitraryPsbt btc) $
        \psbt -> decodePsbt (encodePsbt psbt) == Right psbt

    prop "is read back from its base64 text" $
      forAll (arbitraryPsbt btc) $
        \psbt -> decodePsbtBase64 (encodePsbtBase64 psbt) == Right psbt

    prop "combined with itself is itself" $
      forAll (arbitraryPsbt btc) $
        \psbt -> combinePsbt psbt psbt == Right psbt

    -- The combiner of BIP 174 keeps every entry that either PSBT has. The
    -- key type 0x7e is one no map knows.
    prop "combined with a copy that has one more entry in every map, in either order, is that copy" $
      forAll (arbitraryPsbt btc) $ \psbt ->
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

    -- BIP 32: a master key has depth 0, no parent fingerprint and the child
    -- number 0. Bitcoin Core reads no other extended key of depth 0. Here
    -- the child number 1, then the parent fingerprint 00000001.
    it "refuses an extended public key of depth 0 that has a child number or a parent fingerprint" $ do
      let xpubWith parent child =
            "4f01" <> "0488b21e" <> "00" <> parent <> child <> T.replicate 32 "00" <> aPoint <> "04d90c6a4f"
      decodePsbt (tinyPsbt (xpubWith "00000000" "00000001") "" "")
        `shouldSatisfy` either ("is not an extended public key" `isSuffixOf`) (const False)
      decodePsbt (tinyPsbt (xpubWith "00000001" "00000000") "" "")
        `shouldSatisfy` either ("is not an extended public key" `isSuffixOf`) (const False)

    -- BIP 174 gives a redeem script and a witness script as bytes, and
    -- Bitcoin Core reads any. 4c is OP_PUSHDATA1 without its length.
    it "reads a redeem script and a witness script that are no list of opcodes, on an input and on an output" $ do
      let withScript =
            [ tinyPsbt "" "0104014c" "",
              tinyPsbt "" "0105014c" "",
              tinyPsbt "" "" "0100014c",
              tinyPsbt "" "" "0101014c"
            ]
      forM_ withScript $ \bytes ->
        (encodePsbt <$> decodePsbt bytes) `shouldBe` Right bytes
      (inputRedeemScript . inputAt 0 <$> decodePsbt (tinyPsbt "" "0104014c" ""))
        `shouldBe` Right (Left "The redeem script is not a script: it does not decode")

    -- One leaf at depth 0 of the leaf version 0xc0, whose script of one
    -- byte is 4c: four bytes in all
    it "reads a script tree whose leaf script is no list of opcodes" $ do
      (encodePsbt <$> decodePsbt (tinyPsbt "" "" "01060400c0014c")) `shouldBe` Right (tinyPsbt "" "" "01060400c0014c")
      (outputTapTree . outputAt 0 <$> decodePsbt (tinyPsbt "" "" "01060400c0014c"))
        `shouldBe` Right (Left "The script tree has a leaf whose script is not a script: it does not decode")

    -- The key is the type and the hash of the empty string by the
    -- algorithm of the field, 21 bytes (0x15) or 33 (0x21). The value is
    -- the empty string.
    let ripemd160OfEmpty = "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        sha256OfEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        hash160OfEmpty = "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
        hash256OfEmpty = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        preimageKeys =
          [("150a", ripemd160OfEmpty), ("210b", sha256OfEmpty), ("150c", hash160OfEmpty), ("210d", hash256OfEmpty)]

    it "reads a hash preimage under its hash, for RIPEMD160, SHA256, HASH160 and HASH256" $
      forM_ preimageKeys $ \(start, hash) ->
        (encodePsbt <$> decodePsbt (tinyPsbt "" (start <> hash <> "00") ""))
          `shouldBe` Right (tinyPsbt "" (start <> hash <> "00") "")

    -- BIP 174: the preimage "must equal the key when run through" the
    -- algorithm. The value is one byte of zero, under the hash of the
    -- empty string.
    it "refuses a hash preimage that does not hash to its key" $ do
      let refusal t hash =
            Left . mconcat $
              [ "Input 0: the value of the key 0x" <> t <> " with the data " <> T.unpack hash,
                " is not the preimage of the hash in its key"
              ]
      decodePsbt (tinyPsbt "" ("150a" <> ripemd160OfEmpty <> "0100") "") `shouldBe` refusal "0a" ripemd160OfEmpty
      decodePsbt (tinyPsbt "" ("210b" <> sha256OfEmpty <> "0100") "") `shouldBe` refusal "0b" sha256OfEmpty
      decodePsbt (tinyPsbt "" ("150c" <> hash160OfEmpty <> "0100") "") `shouldBe` refusal "0c" hash160OfEmpty
      decodePsbt (tinyPsbt "" ("210d" <> hash256OfEmpty <> "0100") "") `shouldBe` refusal "0d" hash256OfEmpty

    -- RIPEMD160 and HASH160 give 20 bytes, SHA256 and HASH256 give 32. Each
    -- key here has 5 bytes of data.
    it "refuses a hash preimage whose key is not a hash of the size of its algorithm" $ do
      decodePsbt (tinyPsbt "" "060a11111111110100" "")
        `shouldBe` Left "Input 0: the key 0x0a with the data 1111111111 is not a hash of 20 bytes"
      decodePsbt (tinyPsbt "" "060b11111111110100" "")
        `shouldBe` Left "Input 0: the key 0x0b with the data 1111111111 is not a hash of 32 bytes"
      decodePsbt (tinyPsbt "" "060c11111111110100" "")
        `shouldBe` Left "Input 0: the key 0x0c with the data 1111111111 is not a hash of 20 bytes"
      decodePsbt (tinyPsbt "" "060d11111111110100" "")
        `shouldBe` Left "Input 0: the key 0x0d with the data 1111111111 is not a hash of 32 bytes"

    -- BIP 371 gives a signature as 64 or 65 bytes, and Bitcoin Core reads
    -- any bytes of that length. The last bytes 0x00 and 0x04 name no
    -- sighash type that BIP 341 allows, so no witness is made of these.
    -- 0x41 is 65 bytes, and the key of a script path signature is the type
    -- and 64 bytes, also 0x41.
    it "reads a Taproot signature of 65 bytes whatever its last byte, as a key path and as a script path signature" $
      forM_ ["00", "04"] $ \lastByte -> do
        let keyPath = "0113" <> "41" <> T.replicate 64 "ab" <> lastByte
            scriptPath = "4114" <> T.replicate 64 "22" <> "41" <> T.replicate 64 "ab" <> lastByte
        (encodePsbt <$> decodePsbt (tinyPsbt "" keyPath "")) `shouldBe` Right (tinyPsbt "" keyPath "")
        (encodePsbt <$> decodePsbt (tinyPsbt "" scriptPath "")) `shouldBe` Right (tinyPsbt "" scriptPath "")

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

signerScopeSpec :: Spec
signerScopeSpec =
  describe "What the signer and the finalizer sign, and what they leave alone" $ do
    let secret = PrivateKey secretOne True
        public = derivePublicKey secret
        otherPublic = compressedKey secretTwo
        signer = keySigner secretOne
        ownScript = encodeSerial (PayPKHash (addressHash (encodeSerial public)))
        otherScript = encodeSerial (PayPKHash (addressHash (encodeSerial otherPublic)))
        (psbt, _) = spendingPsbt (PayPKHash (addressHash (encodeSerial public)))
        parent = fromJust (either (const Nothing) id (nonWitnessUtxo (inputAt 0 psbt)))
        coin = head parent.outputs
        signatureCounts = mapM (fmap length . partialSignatures) . (.inputs)

    -- BIP 32 gives a key a depth of one byte, so no key is 256 steps below
    -- another
    it "a signer built from an extended key holds no key for a record whose path has 256 steps" $ do
      let master = makeXPrvKey "PSBT signer test"
          tooDeep = Derivation (xPubFP (deriveXPubKey master)) (listToPath (replicate 256 0))
      (xPrvSigner master Nothing).keyOfRecord public tooDeep `shouldBe` Nothing

    it "signing leaves unsigned an input whose record names the signer's key with a path of 256 steps" $ do
      let master = makeXPrvKey "PSBT signer test"
          tooDeep = Derivation (xPubFP (deriveXPubKey master)) (listToPath (replicate 256 0))
          withRecord = withInputs (insertInputDerivation public tooDeep <$> psbt.inputs) psbt
      (signatureCounts =<< signPsbt btc (xPrvSigner master Nothing) withRecord) `shouldBe` Right [0]

    -- The second record names a key the coin does not pay. A signer that
    -- derives a key for every record can be made to work without end.
    it "asks the signer for the key of a record only when the script of the coin names that key" $ do
      let onlyOwn = signer {keyOfRecord = \asked _ -> if asked == public then Just secretOne else error "asked for the key of a record the coin does not name"}
          withRecords = withInputs ((recordOf public . recordOf otherPublic) <$> psbt.inputs) psbt
      (signatureCounts =<< signPsbt btc onlyOwn withRecords) `shouldBe` Right [1]

    -- The coin pays the hash of key 2, and the record names key 1, which
    -- the signer holds. BIP 174: "If a Signer cannot sign a transaction, it
    -- must not add a Partial Signature."
    it "adds no signature for a key the script of the coin does not name, even when a derivation record names it" $ do
      let (other, _) = spendingPsbt (PayPKHash (addressHash (encodeSerial otherPublic)))
      (signatureCounts =<< signPsbt btc signer (withInputs (recordOf public <$> other.inputs) other)) `shouldBe` Right [0]

    it "adds no signature to a P2WSH coin whose witness script is missing, nor to a P2SH coin whose redeem script is missing" $ do
      let multisig = forceRight (encodeOutput (PayMulSig [public, otherPublic] 2))
          (p2wsh, _) = spendingPsbt (forceRight (toP2WSH multisig))
          (p2sh, _) = spendingPsbt (forceRight (toP2SH multisig))
      (signatureCounts =<< signPsbt btc signer (withInputs (recordOf public <$> p2wsh.inputs) p2wsh)) `shouldBe` Right [0]
      (signatureCounts =<< signPsbt btc signer (withInputs (recordOf public <$> p2sh.inputs) p2sh)) `shouldBe` Right [0]

    it "signs a P2SH-P2WPKH coin with its redeem script by the hash of its key, without a derivation record" $ do
      let redeem = forceRight (encodeOutput (PayWitnessPKHash (addressHash (encodeSerial public))))
          (nested, _) = spendingPsbt (forceRight (toP2SH redeem))
      (signatureCounts =<< signPsbt btc signer (withInputs (insertInputRedeemScript redeem <$> nested.inputs) nested)) `shouldBe` Right [1]

    -- 0x41 is SIGHASH_ALL (0x01) with SIGHASH_FORKID (0x40)
    it "on the Bitcoin Cash networks, signs an input that asks for no sighash type with SIGHASH_ALL and the fork id flag" $
      forM_ [bch, bchTest3, bchTest4, bchRegTest] $ \net ->
        (map (B.last . snd) <$> (partialSignatures . inputAt 0 =<< signPsbt net signer psbt)) `shouldBe` Right [0x41]

    -- Input 0 is a coin of key 1. Input 1 is a P2WSH coin of someone else,
    -- whose witness script is <key 2> OP_CHECKSIGVERIFY <144>
    -- OP_CHECKSEQUENCEVERIFY, which is no template the library knows.
    it "signs and finalizes its own input, and leaves alone an input whose witness script is not a standard template" $ do
      let timelocked = Script [opPushData (encodeSerial otherPublic), OP_CHECKSIGVERIFY, opPushData "\x90\x00", OP_CHECKSEQUENCEVERIFY]
          both = spendingTwo ownScript (encodeSerial (forceRight (toP2WSH timelocked)))
          withScript = withInputs [inputAt 0 both, insertInputWitnessScript timelocked (inputAt 1 both)] both
      signed <- expectRight (signPsbt btc signer withScript)
      signatureCounts signed `shouldBe` Right [1, 0]
      inputAt 1 signed `shouldBe` inputAt 1 withScript
      final <- expectRight (finalizePsbt btc signed)
      map (isJust . finalScriptSig) final.inputs `shouldBe` [True, False]
      inputAt 1 final `shouldBe` inputAt 1 withScript

    -- One signature of the keys 1 and 2, each key pushed by OP_PUSHDATA1
    -- (0x4c) and its length 0x21 = 33, where a multisig of the library has
    -- the length alone. The signature of a multisig covers the bytes of the
    -- script, and a 'ScriptOutput' has no place for the form of a push: the
    -- signer would sign the script with direct pushes, which is another
    -- script. So this one is no standard template, although the signer
    -- holds key 1.
    let longPushes =
          Script
            [ OP_1,
              OP_PUSHDATA (hexBytes "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") OPDATA1,
              OP_PUSHDATA (hexBytes "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5") OPDATA1,
              OP_2,
              OP_CHECKMULTISIG
            ]

    it "signs and finalizes its own input, and leaves alone a multisig coin whose keys are pushed by OP_PUSHDATA1" $ do
      let both = spendingTwo ownScript (runPutS (serialize longPushes))
          withRecord = withInputs [inputAt 0 both, recordOf public (inputAt 1 both)] both
      signed <- expectRight (signPsbt btc signer withRecord)
      signatureCounts signed `shouldBe` Right [1, 0]
      inputAt 1 signed `shouldBe` inputAt 1 withRecord
      final <- expectRight (finalizePsbt btc signed)
      map (isJust . finalScriptSig) final.inputs `shouldBe` [True, False]
      inputAt 1 final `shouldBe` inputAt 1 withRecord

    it "adds no signature to a P2SH or P2WSH coin that commits to such a multisig, and gives no error" $ do
      let (p2sh, _) = spendingPsbt (forceRight (toP2SH longPushes))
          (p2wsh, _) = spendingPsbt (forceRight (toP2WSH longPushes))
          withRedeem = withInputs (recordOf public . insertInputRedeemScript longPushes <$> p2sh.inputs) p2sh
          withWitness = withInputs (recordOf public . insertInputWitnessScript longPushes <$> p2wsh.inputs) p2wsh
      signPsbt btc signer withRedeem `shouldBe` Right withRedeem
      signPsbt btc signer withWitness `shouldBe` Right withWitness

    -- Bitcoin Core signs the bytes of the script, and a block may hold its
    -- spend. The finalizer does not judge a signature of a script it does
    -- not read.
    it "the finalizer leaves alone such a multisig coin that holds a signature over the bytes of its script" $ do
      let both = spendingTwo ownScript (runPutS (serialize longPushes))
          digest = forceRight (txSigHash btc both.unsignedTx longPushes 200000000 1 sigHashAll)
          signature = encodeTxSig btc (TxSignature (signHash secretOne digest) sigHashAll)
          withSignature = withInputs [inputAt 0 both, insertPartialSignature public signature (inputAt 1 both)] both
      finalizePsbt btc withSignature `shouldBe` Right withSignature

    -- Input 1 is a P2PKH coin of key 2, known from its output alone. The
    -- signer could not sign it anyway. Bitcoin Core leaves such an input
    -- unsigned and signs the others.
    it "leaves alone a legacy coin known from its witness output only when it holds no key for it, and signs its own input" $ do
      let both = spendingTwo ownScript otherScript
          witnessOnly = withInputs [inputAt 0 both, insertWitnessUtxo (TxOut 200000000 otherScript) Map.empty] both
      (signatureCounts =<< signPsbt btc signer witnessOnly) `shouldBe` Right [1, 0]

    -- Input 0 is a coin of key 1. Input 1 is a Taproot coin of someone
    -- else, the coin of the BIP 371 vectors, with one entry that Bitcoin
    -- Core 32.1 reads and that nobody can sign or finalize with. Core signs
    -- input 0 of each. 79be…1798 is the x coordinate of the point G, and 5
    -- is the x coordinate of no point of the curve: 5³ + 7 = 132 is not a
    -- square modulo the field prime.
    let theirTaproot = hexBytes "51205a2c2cf5b52cf31f83ad2e8da63ff03183ecd8f609c7510ae8a48e03910a0757"
        pointG = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        noPoint = "0000000000000000000000000000000000000000000000000000000000000005"
        -- A leaf hash that is the hash of no leaf, and 64 bytes that are
        -- the signature of nobody
        noLeaf = T.replicate 32 "cd"
        noSignature = T.replicate 64 "ab"
        -- What the entry is, the type of its key, the data of its key and
        -- its value
        unusable =
          [ ("a leaf script that is cut short", 0x15, "c0" <> pointG, "4cc0"),
            ("a leaf script whose control block names a key that is no point", 0x15, "c0" <> noPoint, "51c0"),
            ("an internal key that is no point", 0x17, "", noPoint),
            ("a derivation record of a key that is no point", 0x16, noPoint, "0000000000"),
            ("a script path signature of a key that is no point", 0x14, noPoint <> noLeaf, noSignature)
          ]

    forM_ unusable $ \(what, keyType, keyData, value) ->
      it ("signs and finalizes its own input, and leaves alone a Taproot coin of another party that has " <> what) $ do
        let both = spendingTwo ownScript theirTaproot
            entry = Map.insert (Key keyType (hexBytes keyData)) (hexBytes value)
            withEntry = withInputs [inputAt 0 both, entry (inputAt 1 both)] both
        decodePsbt (encodePsbt withEntry) `shouldBe` Right withEntry
        signed <- expectRight (signPsbt btc signer withEntry)
        signatureCounts signed `shouldBe` Right [1, 0]
        inputAt 1 signed `shouldBe` inputAt 1 withEntry
        final <- expectRight (finalizePsbt btc signed)
        map (isJust . finalScriptSig) final.inputs `shouldBe` [True, False]
        inputAt 1 final `shouldBe` inputAt 1 withEntry

    -- A key path signature of a BIP 371 vector, for another transaction
    let vectorSignature =
          hexBytes
            "bb53ec917bad9d906af1ba87181c48b86ace5aae2b53605a725ca74625631476\
            \fc6f5baedaf4f2ee0f477f36f58f3970d5b8273b7e497b97af2e3f125c97af34"

    -- Nobody can spend such a coin, with a signature or without one
    it "signs and finalizes its own input, and leaves alone a Taproot coin whose output key is no point" $ do
      let both = spendingTwo ownScript (hexBytes ("5120" <> noPoint))
          claimed = withInputs [inputAt 0 both, Map.insert (Key 0x13 "") vectorSignature (inputAt 1 both)] both
      forM_ [both, claimed] $ \psbt' -> do
        signed <- expectRight (signPsbt btc signer psbt')
        signatureCounts signed `shouldBe` Right [1, 0]
        final <- expectRight (finalizePsbt btc signed)
        map (isJust . finalScriptSig) final.inputs `shouldBe` [True, False]
        inputAt 1 final `shouldBe` inputAt 1 psbt'

    -- The parties of a PSBT add their coins in turn. Input 0 is a Taproot
    -- coin of someone else, and the owner of input 1 has not added its coin
    -- yet. A Taproot signature needs the coin of every input, and this
    -- signer has none to make.
    it "leaves alone a Taproot coin of another party while another input has no coin yet" $ do
      let both = spendingTwo theirTaproot ownScript
          waiting = withInputs [inputAt 0 both, Map.empty] both
      signPsbt btc signer waiting `shouldBe` Right waiting

    -- Input 0 is a legacy coin of the signer and input 1 a Taproot coin of
    -- the signer. The owner of input 2 has not added its coin yet, and the
    -- digest of a Taproot signature commits to the coin of every input.
    -- Bitcoin Core signs input 0 and leaves input 1, and refuses nothing.
    it "signs its legacy coin, and leaves its Taproot coin unsigned while another input has no coin yet" $ do
      let keyPathCoin = forceRight (taprootScriptOutput (TaprootOutput public.point Nothing))
          both = spendingTwo ownScript (encodeSerial keyPathCoin)
          third = TxIn (OutPoint "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389" 0) "" 0xfffffffe
          tx = Tx 2 (both.unsignedTx.inputs <> [third]) both.unsignedTx.outputs [] 0
          ownTaproot = insertInputTapInternalKey public.point (inputAt 1 both)
          waiting = Psbt Version0 tx Map.empty [inputAt 0 both, ownTaproot, Map.empty] both.outputs
      signed <- expectRight (signPsbt btc signer waiting)
      signatureCounts signed `shouldBe` Right [1, 0, 0]
      drop 1 signed.inputs `shouldBe` [ownTaproot, Map.empty]

    -- Without the coin of input 1 nobody can tell whether a Taproot
    -- signature verifies, so the input is not ready, and Bitcoin Core
    -- leaves it too.
    it "the finalizer leaves alone a signed Taproot coin while another input has no coin yet" $ do
      let both = spendingTwo theirTaproot ownScript
          waiting = withInputs [Map.insert (Key 0x13 "") vectorSignature (inputAt 0 both), Map.empty] both
      finalizePsbt btc waiting `shouldBe` Right waiting

    -- Bitcoin Core refuses the whole PSBT too: a sighash type that the
    -- caller did not ask for is a mismatch on any input that has its coin
    it "refuses a PSBT in which another party's input asks for a sighash type the signer does not accept" $ do
      let both = spendingTwo ownScript otherScript
          asking = withInputs [inputAt 0 both, insertSigHashType (setAnyoneCanPay sigHashSingle) (inputAt 1 both)] both
      signPsbt btc signer asking `shouldBe` Left "Input 1: the sighash type 131 is not one the signer accepts"

    -- No node relays the spend of such a coin, and Bitcoin Core does not
    -- sign it
    it "adds no signature of an uncompressed key to a SegWit version 0 coin" $ do
      let uncompressed = PublicKey public.point False
          (p2wpkh, _) = spendingPsbt (PayWitnessPKHash (addressHash (encodeSerial uncompressed)))
      signPsbt btc signer p2wpkh `shouldBe` Right p2wpkh

    -- The signer of the library makes no such signature, so this one is
    -- made here, as Bitcoin Core of an older version would have. It
    -- verifies, and the input still may not be final.
    it "the finalizer leaves alone a SegWit version 0 coin with a valid signature of an uncompressed key" $ do
      let uncompressed = PublicKey public.point False
          (p2wpkh, _) = spendingPsbt (PayWitnessPKHash (addressHash (encodeSerial uncompressed)))
          scriptCode = forceRight (encodeOutput (PayPKHash (addressHash (encodeSerial uncompressed))))
          digest = forceRight (txSigHashForkId btc p2wpkh.unsignedTx scriptCode 200000000 0 sigHashAll)
          signature = encodeTxSig btc (TxSignature (signHash secretOne digest) sigHashAll)
          claimed = withInputs (insertPartialSignature uncompressed signature <$> p2wpkh.inputs) p2wpkh
      finalizePsbt btc claimed `shouldBe` Right claimed

    -- The second signature is the one of key 1, filed under key 2: it does
    -- not verify for key 2. The coin does not name key 2, so the finalizer
    -- has no reason to look at it.
    it "the finalizer does not look at a partial signature of a key the script of the coin does not name" $ do
      signed <- expectRight (signPsbt btc signer psbt)
      signature <- case partialSignatures (inputAt 0 signed) of
        Right [(_, sig)] -> return sig
        _ -> fail "one signature"
      let withStray = withInputs (insertPartialSignature otherPublic signature <$> signed.inputs) signed
      (finalScriptSig . inputAt 0 <$> finalizePsbt btc withStray) `shouldBe` (finalScriptSig . inputAt 0 <$> finalizePsbt btc signed)
      (isJust . finalScriptSig . inputAt 0 <$> finalizePsbt btc withStray) `shouldBe` Right True

    -- Bitcoin Core takes SIGHASH_ALL for an input that names no sighash
    -- type, and gives no final script when a signature uses another
    it "the finalizer leaves alone an input that names no sighash type and has a SIGHASH_NONE signature" $ do
      let acceptingNone = signer {acceptedSigHashes = [sigHashNone]}
      signed <- expectRight (signPsbt btc acceptingNone (withInputs (insertSigHashType sigHashNone <$> psbt.inputs) psbt))
      let unnamed = withInputs (deleteSigHashType <$> signed.inputs) signed
      finalizePsbt btc unnamed `shouldBe` Right unnamed

    it "the finalizer leaves alone a signed legacy coin that is known from its witness output only" $ do
      signed <- expectRight (signPsbt btc signer psbt)
      let witnessOnly = withInputs [insertWitnessUtxo coin (Map.delete (Key 0x00 "") (inputAt 0 signed))] signed
      finalizePsbt btc witnessOnly `shouldBe` Right witnessOnly

    -- A signer written by a caller may answer with a key that is not the
    -- one asked for. Its signature would be of no use to anyone.
    it "signs with a key the signer gives only when it is the key the coin names" $ do
      let wrongByRecord = signer {keyOfRecord = \_ _ -> Just secretTwo, keyOfHash = const Nothing}
          wrongByHash = signer {keyOfRecord = \_ _ -> Nothing, keyOfHash = const (Just (PrivateKey secretTwo True))}
          withRecord = withInputs (recordOf public <$> psbt.inputs) psbt
      (signatureCounts =<< signPsbt btc wrongByRecord withRecord) `shouldBe` Right [0]
      (signatureCounts =<< signPsbt btc wrongByHash psbt) `shouldBe` Right [0]

    it "a signer of one key holds no key for the record of another key" $ do
      let record = Derivation (fingerprintOf "00000000") "m/0"
      (keySigner secretOne).keyOfRecord otherPublic record `shouldBe` Nothing
      (keySigner secretOne).keyOfRecord public record `shouldBe` Just secretOne

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

{- One input at a time -}

-- Bitcoin Core signs and finalizes a PSBT one input at a time
-- (SignPSBTInput). An input that it cannot sign or finalize stays as it
-- is, and the others go on. Its signer refuses a whole PSBT for a sighash
-- type only. Each case here was given to Bitcoin Core 32.1 on regtest.
inputByInputSpec :: Spec
inputByInputSpec =
  describe "The signer and the finalizer take one input at a time" $ do
    let public = compressedKey secretOne
        uncompressed = PublicKey public.point False
        publicTwo = compressedKey secretTwo
        publicThree = compressedKey secretThree
        signer = keySigner secretOne
        ownPkh = PayPKHash (addressHash (encodeSerial public))
        ownWpkh = PayWitnessPKHash (addressHash (encodeSerial public))
        theirPkh = PayPKHash (addressHash (encodeSerial publicTwo))
        signatureCounts = mapM (fmap length . partialSignatures) . (.inputs)
        leftAlone psbt = finalizePsbt btc psbt `shouldBe` Right psbt
        signatureOf key psbt = fromJust . lookup key <$> expectRight (partialSignatures (inputAt 0 psbt))
        -- 64 bytes that are the signature of nobody
        noSignature = B.replicate 64 0xab

    {- The signer -}

    -- Input 1 is a coin of key 2 with a signature of the type SIGHASH_NONE,
    -- and asks for no type, so it is signed with SIGHASH_ALL, the type 1
    it
      "the signer refuses a PSBT in which an input has a signature \
      \of another sighash type than the one it is signed with"
      $ do
        let both = spendingTwo (encodeSerial ownPkh) (encodeSerial theirPkh)
            acceptingNone = (keySigner secretTwo) {acceptedSigHashes = sigHashNone : defaultSigHashes}
        let askingNone = withInputs [inputAt 0 both, insertSigHashType sigHashNone (inputAt 1 both)] both
        asking <- expectRight (signPsbt btc acceptingNone askingNone)
        signatureCounts asking `shouldBe` Right [0, 1]
        signPsbt btc signer (onInputs deleteSigHashType asking)
          `shouldBe` Left "Input 1: a signature of the input does not use the sighash type 1"

    -- A Taproot signature of 65 bytes names its type in its last byte. An
    -- input that asks for no type is signed with SIGHASH_DEFAULT, the type
    -- 0, whose signatures have 64 bytes.
    it "the signer refuses a PSBT whose Taproot input has a signature of 65 bytes and asks for no sighash type" $ do
      let (keyOnly, _) = spendingPsbt (forceRight (taprootScriptOutput (TaprootOutput public.point Nothing)))
          asking = onInputs (insertSigHashType sigHashAll . insertInputTapInternalKey public.point) keyOnly
      signed <- expectRight (signPsbt btc signer asking)
      signPsbt btc signer (onInputs deleteSigHashType signed)
        `shouldBe` Left "Input 0: a signature of the input does not use the sighash type 0"

    -- BIP 370 has a signer change the flags of version 2 "if the Signer
    -- added a signature". Both coins are of key 2, one signed with ECDSA and
    -- one a Taproot coin, and the signer holds key 1.
    it "the signer leaves the flags of a version 2 PSBT as they are when it adds no signature" $ do
      let theirKeyPath = forceRight (taprootScriptOutput (TaprootOutput publicTwo.point Nothing))
      forM_ [theirPkh, theirKeyPath] $ \coin -> do
        let open = withFlags (Modifiable True True False 0) (withVersion Version2 (fst (spendingPsbt coin)))
        signPsbt btc signer open `shouldBe` Right open

    -- The signature that is there is the one of key 2 for a coin of its
    -- own, filed under key 1. Bitcoin Core does not sign again for a key
    -- that has a signature.
    it "the signer keeps the signature that an input has under its key already" $ do
      theirs <-
        signatureOf publicTwo =<< expectRight (signPsbt btc (keySigner secretTwo) (fst (spendingPsbt theirPkh)))
      let already = onInputs (insertPartialSignature public theirs) (fst (spendingPsbt ownPkh))
      signPsbt btc signer already `shouldBe` Right already

    it
      "the signer signs its coin that has its previous transaction, \
      \and leaves its coin known from its witness output only"
      $ do
        let both = spendingTwo (encodeSerial ownWpkh) (encodeSerial ownWpkh)
            witnessOutputOnly = insertWitnessUtxo (TxOut 200000000 (encodeSerial ownWpkh)) Map.empty
            mixed = withInputs [inputAt 0 both, witnessOutputOnly] both
        signed <- expectRight (signPsbt btc signer mixed)
        signatureCounts signed `shouldBe` Right [1, 0]
        inputAt 1 signed `shouldBe` inputAt 1 mixed

    it "the signer signs a P2WSH multisig with its compressed key, and not with its uncompressed key" $ do
      let multisig = forceRight (encodeOutput (PayMulSig [uncompressed, public, publicTwo] 2))
          (p2wsh, _) = spendingPsbt (forceRight (toP2WSH multisig))
      signed <- expectRight (signPsbt btc signer (onInputs (insertInputWitnessScript multisig) p2wsh))
      (map fst <$> partialSignatures (inputAt 0 signed)) `shouldBe` Right [public]

    -- The witness script of a P2WSH coin runs as a script: one that is a
    -- witness program leaves two items, and no signature spends the coin
    it
      "the signer adds no signature to a P2WSH coin whose witness script \
      \is a P2WPKH program, and the finalizer leaves a signed one alone"
      $ do
        let program = forceRight (encodeOutput ownWpkh)
            (nested, _) = spendingPsbt (forceRight (toP2WSH program))
            withScript = onInputs (insertInputWitnessScript program) nested
        signPsbt btc signer withScript `shouldBe` Right withScript
        signature <- signatureOf public =<< expectRight (signPsbt btc signer (fst (spendingPsbt ownWpkh)))
        leftAlone (onInputs (insertPartialSignature public signature) withScript)

    -- A multisig of 8 uncompressed keys is 3 + 8 × 66 = 531 bytes, over
    -- the 520 bytes that a transaction can push, so nothing spends the
    -- coin. Bitcoin Core adds a signature all the same, and makes no final
    -- script of it. The library does not sign what cannot be spent, as
    -- 'makeSignature' refuses it.
    it "the signer adds no signature to a P2SH coin whose redeem script is longer than 520 bytes" $ do
      let uncompressedTwo = PublicKey publicTwo.point False
          long = forceRight (encodeOutput (PayMulSig (uncompressed : replicate 7 uncompressedTwo) 1))
          (p2sh, _) = spendingPsbt (PayScriptHash (addressHash (runPutS (serialize long))))
      B.length (runPutS (serialize long)) `shouldBe` 531
      signPsbt btc signer (onInputs (insertInputRedeemScript long) p2sh)
        `shouldBe` Right (onInputs (insertInputRedeemScript long) p2sh)

    -- 2,100,000,000,000,000 satoshi are 21 million bitcoin, all there will
    -- be. Bitcoin Core makes no SegWit version 0 signature above it.
    it "the signer adds no signature to a SegWit version 0 coin that holds more than 21 million bitcoin" $ do
      let (psbt, _) = spendingPsbt ownWpkh
          trusting = signer {requirePreviousTx = False}
          claiming amount = withInputs [insertWitnessUtxo (TxOut amount (encodeSerial ownWpkh)) Map.empty] psbt
      (signatureCounts =<< signPsbt btc trusting (claiming 2100000000000000)) `shouldBe` Right [1]
      signPsbt btc trusting (claiming 2100000000000001) `shouldBe` Right (claiming 2100000000000001)

    -- 4c is OP_PUSHDATA1 without its length: a script that does not parse
    it "the signer refuses a sighash type that it does not accept on an input whose coin script does not parse" $ do
      let both = spendingTwo (encodeSerial ownPkh) "\x4c"
          asking = withInputs [inputAt 0 both, insertSigHashType sigHashNone (inputAt 1 both)] both
      (signatureCounts =<< signPsbt btc signer both) `shouldBe` Right [1, 0]
      signPsbt btc signer asking `shouldBe` Left "Input 1: the sighash type 2 is not one the signer accepts"

    {- The signer, on Taproot coins -}

    -- A coin with the leaf of key 1 under the internal key of key 2, and
    -- one with the same leaf under the internal key of key 1
    let leaf = Script [opPushData (exportXOnlyPubKey public.point), OP_CHECKSIG]
        other = Script [OP_RETURN]
        treeUnder internal = onInputs fields psbt
          where
            tree = MASTBranch (MASTLeaf 0xc0 leaf) (MASTLeaf 0xc0 other)
            output = TaprootOutput internal (Just tree)
            parity = keyParity (forceRight (taprootOutputKey output))
            control = encodeControlBlock (0xc0 + parity) internal [leafHash 0xc0 other]
            (psbt, _) = spendingPsbt (forceRight (taprootScriptOutput output))
            fields =
              insertInputTapInternalKey internal
                . insertInputTapMerkleRoot (mastCommitment tree)
                . insertTapLeafScript (TapLeafScript control leaf 0xc0)
        keyPathSigned = fmap isJust . tapKeySig . inputAt 0
        leavesSigned = fmap length . tapScriptSigs . inputAt 0

    it "the signer signs the leaf of its key on a Taproot coin whose internal key it does not hold" $ do
      signed <- expectRight (signPsbt btc signer (treeUnder publicTwo.point))
      (keyPathSigned signed, leavesSigned signed) `shouldBe` (Right False, Right 1)

    it "the signer signs the key path alone when it holds the internal key and the key of a leaf" $ do
      signed <- expectRight (signPsbt btc signer (treeUnder public.point))
      (keyPathSigned signed, leavesSigned signed) `shouldBe` (Right True, Right 0)

    it
      "the signer signs no leaf of a Taproot input that has \
      \a key path signature already, and keeps that signature"
      $ do
        let already = onInputs (Map.insert (Key 0x13 "") noSignature) (treeUnder publicTwo.point)
        signPsbt btc signer already `shouldBe` Right already

    it "the signer keeps the key path signature that a Taproot input has already, when it holds the internal key" $ do
      let already = onInputs (Map.insert (Key 0x13 "") noSignature) (treeUnder public.point)
      signPsbt btc signer already `shouldBe` Right already

    it "the signer keeps the signature that a leaf has under its key already" $ do
      let entry = Key 0x14 (exportXOnlyPubKey public.point <> convert (leafHash 0xc0 leaf))
          already = onInputs (Map.insert entry noSignature) (treeUnder publicTwo.point)
      signPsbt btc signer already `shouldBe` Right already

    -- 5120 and the x coordinate of key 1: a coin whose output key is key 1
    -- itself, as the descriptor rawtr() makes one
    it
      "the signer signs the key path of a Taproot coin whose output \
      \key is its own key, when the input names no internal key"
      $ do
        let (raw, coins) = spendingPsbt (PayWitness 1 (exportXOnlyPubKey public.point))
        tx <- expectRight (psbtTransaction =<< finalizePsbt btc =<< signPsbt btc signer raw)
        verifyStdTx btc tx coins `shouldBe` True

    -- Two coins of the signer and one output: input 1 has no output at its
    -- index, and BIP 341 gives SIGHASH_SINGLE no digest there
    it
      "the signer signs the Taproot input that has an output at its \
      \index for SIGHASH_SINGLE, and leaves the one that has none"
      $ do
        let coin = encodeSerial (PayWitness 1 (exportXOnlyPubKey public.point))
            asking = onInputs (insertSigHashType sigHashSingle) (spendingTwo coin coin)
        signed <- expectRight (signPsbt btc (signer {acceptedSigHashes = [sigHashSingle]}) asking)
        mapM (fmap isJust . tapKeySig) signed.inputs `shouldBe` Right [True, False]
        inputAt 1 signed `shouldBe` inputAt 1 asking

    -- Bitcoin Cash has no SegWit and no Taproot: the script is one that
    -- anyone can spend there
    it
      "on Bitcoin Cash, the signer and the finalizer leave \
      \alone a coin whose script has the form of a Taproot output"
      $ do
        let (raw, _) = spendingPsbt (PayWitness 1 (exportXOnlyPubKey public.point))
        signPsbt bch signer raw `shouldBe` Right raw
        signedOnBitcoin <- expectRight (signPsbt btc signer raw)
        finalizePsbt bch signedOnBitcoin `shouldBe` Right signedOnBitcoin

    {- The finalizer -}

    it
      "the finalizer finalizes the input that is ready, and \
      \leaves alone the input whose signature does not verify"
      $ do
        let both = spendingTwo (encodeSerial ownPkh) (encodeSerial ownPkh)
        signed <- expectRight (signPsbt btc signer both)
        first <- signatureOf public signed
        -- The signature of input 0, on input 1
        let swapped = withInputs [inputAt 0 signed, insertPartialSignature public first (inputAt 1 signed)] signed
        final <- expectRight (finalizePsbt btc swapped)
        map (isJust . finalScriptSig) final.inputs `shouldBe` [True, False]
        inputAt 1 final `shouldBe` inputAt 1 swapped

    -- A P2WSH coin of two signatures of the keys 1, 2 and 3, signed by all
    -- three
    let multisig = forceRight (encodeOutput (PayMulSig [public, publicTwo, publicThree] 2))
        (twoOfThree, twoOfThreeCoins) = spendingPsbt (forceRight (toP2WSH multisig))
        allThree = keysSigner [PrivateKey secretOne True, PrivateKey secretTwo True, PrivateKey secretThree True]
        signedByAll = expectRight (signPsbt btc allThree (onInputs (insertInputWitnessScript multisig) twoOfThree))

    -- Bitcoin Core takes the first signatures in the order of the keys of
    -- the script, and does not try another choice when its witness fails
    it
      "the finalizer takes the signatures of the first keys of a multisig, \
      \and leaves the input alone when one of them does not verify"
      $ do
        signed <- signedByAll
        second <- signatureOf publicTwo signed
        leftAlone (onInputs (insertPartialSignature public second) signed)

    -- The witness of a P2WSH multisig: an empty item, the signatures, the
    -- witness script
    it "the finalizer does not look at a signature of a multisig that it does not use" $ do
      signed <- signedByAll
      first <- signatureOf public signed
      second <- signatureOf publicTwo signed
      final <- expectRight (finalizePsbt btc (onInputs (insertPartialSignature publicThree first) signed))
      finalScriptWitness (inputAt 0 final) `shouldBe` Right (Just ["", first, second, runPutS (serialize multisig)])
      (flip (verifyStdTx btc) twoOfThreeCoins <$> psbtTransaction final) `shouldBe` Right True

    -- BIP 174 has the signer check the scripts of an input, and says
    -- nothing of them to the finalizer. Bitcoin Core finalizes.
    it
      "the finalizer finalizes a P2WPKH coin that also has a redeem \
      \script and a witness script, which such a coin does not use"
      $ do
        let (plain, coins) = spendingPsbt ownWpkh
        signed <- expectRight (signPsbt btc signer plain)
        let stray = onInputs (insertInputRedeemScript multisig . insertInputWitnessScript multisig) signed
        tx <- expectRight (psbtTransaction =<< finalizePsbt btc stray)
        verifyStdTx btc tx coins `shouldBe` True

    -- The input asks for no type, so its signatures are of SIGHASH_ALL,
    -- and a Taproot signature of 64 bytes is of SIGHASH_DEFAULT
    it "the finalizer leaves alone a signed P2WPKH coin that also has a Taproot signature of 64 bytes" $ do
      signed <- expectRight (signPsbt btc signer (fst (spendingPsbt ownWpkh)))
      leftAlone (onInputs (Map.insert (Key 0x13 "") noSignature) signed)

    -- BIP 174: the finalizer "must fail to finalize that input if any
    -- signature does not match the specified sighash type"
    it "the finalizer leaves alone an input that asks for the sighash type 0 and has a SIGHASH_ALL signature" $ do
      signed <- expectRight (signPsbt btc signer (fst (spendingPsbt ownWpkh)))
      leftAlone (onInputs (insertSigHashType sigHashDefault) signed)

    -- The same rule on a Taproot coin. Its key path signature has 64 bytes,
    -- so it is of the type 0. The partial signature is one of key 1 for
    -- another coin, of the type SIGHASH_ALL. Bitcoin Core does not look at
    -- it, and finalizes the input.
    it "the finalizer leaves alone a Taproot input that asks for the sighash type 0 and has a partial signature" $ do
      let (keyOnly, _) = spendingPsbt (forceRight (taprootScriptOutput (TaprootOutput public.point Nothing)))
          asking = onInputs (insertSigHashType sigHashDefault . insertInputTapInternalKey public.point) keyOnly
      signed <- expectRight (signPsbt btc signer asking)
      -- Without the partial signature, the witness is the key path signature
      (fmap (fmap length) . finalScriptWitness . inputAt 0 =<< finalizePsbt btc signed) `shouldBe` Right (Just 1)
      stray <- signatureOf public =<< expectRight (signPsbt btc signer (fst (spendingPsbt ownPkh)))
      leftAlone (onInputs (insertPartialSignature public stray) signed)

    it "the finalizer clears the fields of the signers from an input that is final already" $ do
      signed <- expectRight (signPsbt btc signer (fst (spendingPsbt ownPkh)))
      final <- expectRight (finalizePsbt btc signed)
      hasPartialSignatures (inputAt 0 final) `shouldBe` False
      finalizePsbt btc (onInputs (Map.union (inputAt 0 signed)) final) `shouldBe` Right final

    -- BIP 174 has the finalizer clear every field of an input but its coin
    -- and the keys that the spec does not define. The types 0x0a to 0x0d
    -- are the four hash preimages, and 0x1a to 0x1c the MuSig2 fields.
    it "the finalizer clears the hash preimages and the MuSig2 fields from the input that it finalizes" $ do
      signed <- expectRight (signPsbt btc signer (fst (spendingPsbt ownPkh)))
      let extra = Map.fromList [(Key t "", "") | t <- [0x0a, 0x0b, 0x0c, 0x0d, 0x1a, 0x1b, 0x1c]]
      final <- expectRight (finalizePsbt btc signed)
      Map.keys (inputAt 0 final) `shouldBe` [Key 0x00 "", Key 0x07 ""]
      finalizePsbt btc (onInputs (Map.union extra) signed) `shouldBe` Right final

    {- The finalizer, on Taproot coins -}

    -- A coin under the internal key of key 3. The leaf of key 1 is at depth
    -- 1, with a control block of 65 bytes. The leaf of key 2 is at depth 2,
    -- with one of 97 bytes. Both are signed.
    let near = Script [opPushData (exportXOnlyPubKey public.point), OP_CHECKSIG]
        far = Script [opPushData (exportXOnlyPubKey publicTwo.point), OP_CHECKSIG]
        twoDepths =
          MASTBranch (MASTLeaf 0xc0 near) (MASTBranch (MASTLeaf 0xc0 far) (MASTLeaf 0xc0 (Script [OP_RETURN])))
        deepOutput = TaprootOutput publicThree.point (Just twoDepths)
        controlOf script =
          head
            [ encodeControlBlock (0xc0 + keyParity (forceRight (taprootOutputKey deepOutput))) publicThree.point proof
            | (_, s, proof) <- getMerkleProofs twoDepths,
              s == script
            ]
        (deep, _) = spendingPsbt (forceRight (taprootScriptOutput deepOutput))
        bothLeaves =
          insertTapLeafScript (TapLeafScript (controlOf near) near 0xc0)
            . insertTapLeafScript (TapLeafScript (controlOf far) far 0xc0)
        bothKeys = keysSigner [PrivateKey secretOne True, PrivateKey secretTwo True]
        signedLeaves = expectRight (signPsbt btc bothKeys (onInputs bothLeaves deep))
        signatureOfLeaf point script psbt =
          encodeTaprootSig . fromJust . lookup (point, leafHash 0xc0 script)
            <$> expectRight (tapScriptSigs (inputAt 0 psbt))

    -- Bitcoin Core takes the smallest witness
    it "the finalizer spends a Taproot coin by the signed leaf that has the shortest control block" $ do
      signed <- signedLeaves
      signature <- signatureOfLeaf public.point near signed
      (B.length (controlOf near), B.length (controlOf far)) `shouldBe` (65, 97)
      final <- expectRight (finalizePsbt btc signed)
      finalScriptWitness (inputAt 0 final)
        `shouldBe` Right (Just [signature, runPutS (serialize near), controlOf near])

    -- The leaf of key 1 is listed under a second control block, of 97
    -- bytes, which commits it to no coin and comes first by its bytes.
    -- Bitcoin Core takes the shortest control block of a leaf.
    it "the finalizer takes the shortest control block of a leaf that the input lists under two" $ do
      signed <- signedLeaves
      signature <- signatureOfLeaf public.point near signed
      let stray = B.cons 0xc0 (B.replicate 96 0)
          listedTwice = Map.insert (Key 0x15 stray) (runPutS (serialize near) <> "\xc0")
      (stray < controlOf near) `shouldBe` True
      final <- expectRight (finalizePsbt btc (onInputs listedTwice signed))
      finalScriptWitness (inputAt 0 final)
        `shouldBe` Right (Just [signature, runPutS (serialize near), controlOf near])

    -- The leaf of key 1 now has a control block of 65 bytes that commits
    -- it to another tree. Bitcoin Core takes the smallest witness, which
    -- fails, and does not try the other leaf.
    it
      "the finalizer does not try another leaf when the signed leaf \
      \with the shortest control block is not committed to the coin"
      $ do
        signed <- signedLeaves
        let stray = encodeControlBlock 0xc0 publicThree.point [leafHash 0xc0 (Script [OP_RETURN])]
            moved =
              Map.insert (Key 0x15 stray) (runPutS (serialize near) <> "\xc0")
                . Map.delete (Key 0x15 (controlOf near))
        leftAlone (onInputs moved signed)

    it
      "the finalizer leaves alone a Taproot input whose key path \
      \signature does not verify, although a signed leaf would spend it"
      $ do
        signed <- signedLeaves
        leftAlone (onInputs (Map.insert (Key 0x13 "") noSignature) signed)

    -- 5 is the x coordinate of no point of the curve. A leaf that checks
    -- such a key has the form of a leaf of one key, and Bitcoin Core takes
    -- it when it has an entry of a signature and the shortest control
    -- block.
    it
      "the finalizer does not try another leaf when the signed leaf \
      \with the shortest control block checks a key that is no point"
      $ do
        let noPoint = B.replicate 31 0x00 <> "\x05"
            noKeyLeaf = Script [opPushData noPoint, OP_CHECKSIG]
            tree =
              MASTBranch
                (MASTLeaf 0xc0 noKeyLeaf)
                (MASTBranch (MASTLeaf 0xc0 far) (MASTLeaf 0xc0 (Script [OP_RETURN])))
            output = TaprootOutput publicThree.point (Just tree)
            control script =
              head
                [ encodeControlBlock (0xc0 + keyParity (forceRight (taprootOutputKey output))) publicThree.point proof
                | (_, s, proof) <- getMerkleProofs tree,
                  s == script
                ]
            (psbt, _) = spendingPsbt (forceRight (taprootScriptOutput output))
            entries =
              insertTapLeafScript (TapLeafScript (control noKeyLeaf) noKeyLeaf 0xc0)
                . insertTapLeafScript (TapLeafScript (control far) far 0xc0)
            claimed = Map.insert (Key 0x14 (noPoint <> convert (leafHash 0xc0 noKeyLeaf))) noSignature
        signed <- expectRight (signPsbt btc (keySigner secretTwo) (onInputs entries psbt))
        (fmap length . tapScriptSigs . inputAt 0) signed `shouldBe` Right 1
        (isJust <$>) . finalScriptWitness . inputAt 0 <$> finalizePsbt btc signed `shouldBe` Right (Right True)
        leftAlone (onInputs claimed signed)

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

taprootChecksSpec :: Vectors371 -> Spec
taprootChecksSpec vectors =
  describe "The checks on Taproot signatures" $ do
    let vectorAt i = psbtOfVector (vectors.accepted371 !! i)
        internal = derivePubKey secretOne
        leafKey = derivePubKey secretTwo
        leaf = Script [opPushData (exportXOnlyPubKey leafKey), OP_CHECKSIG]
        tree = MASTBranch (MASTLeaf 0xc0 leaf) (MASTLeaf 0xc0 (Script [OP_RETURN]))
        output = TaprootOutput internal (Just tree)
        parity = keyParity (forceRight (taprootOutputKey output))
        control = encodeControlBlock (0xc0 + parity) internal [leafHash 0xc0 (Script [OP_RETURN])]
        (withTree, _) = spendingPsbt (forceRight (taprootScriptOutput output))
        treeFields = insertInputTapInternalKey internal . insertInputTapMerkleRoot (mastCommitment tree) . insertTapLeafScript (TapLeafScript control leaf 0xc0)
        derivation = Derivation (fingerprintOf "d90c6a4f") "m/86'/0'/0'/0/0"
        -- A signer that finds its keys by derivation record only, as one
        -- built from an extended key does
        byRecord secret = (keySigner secret) {keyOfHash = const Nothing}

        leftAlone psbt = finalizePsbt btc psbt `shouldBe` Right psbt
        witnessItems = fmap (fmap length) . finalScriptWitness . inputAt 0

    -- A key path spend has one witness item, and the script path spend of
    -- the vector three: the signature, the script and the control block
    it "the finalizer finalizes the key path and the script path of the BIP 371 vectors" $ do
      keyPath <- vectorAt 1
      scriptPath <- vectorAt 5
      (witnessItems <$> finalizePsbt btc keyPath) `shouldBe` Right (Right (Just 1))
      (witnessItems <$> finalizePsbt btc scriptPath) `shouldBe` Right (Right (Just 3))

    it "the finalizer leaves alone an input whose key path signature does not verify" $ do
      psbt <- vectorAt 1
      leftAlone (onInputs (onKeyType 0x13 flipValue) psbt)

    it "the finalizer leaves alone an input whose script path signature does not verify" $ do
      psbt <- vectorAt 5
      leftAlone (onInputs (onKeyType 0x14 flipValue) psbt)

    it "the finalizer leaves alone a signed leaf whose control block does not commit it to the output key" $ do
      psbt <- vectorAt 5
      leftAlone (onInputs (onKeyType 0x15 flipKeyData) psbt)

    -- The signatures of both vectors are 64 bytes, which is SIGHASH_DEFAULT
    it "the finalizer leaves alone a Taproot input whose signature does not use the sighash type the input names" $ do
      keyPath <- vectorAt 1
      scriptPath <- vectorAt 5
      leftAlone (onInputs (insertSigHashType sigHashAll) keyPath)
      leftAlone (onInputs (insertSigHashType sigHashAll) scriptPath)

    -- Bitcoin Core takes SIGHASH_DEFAULT for a Taproot input that names no
    -- sighash type, and then wants every signature to be 64 bytes
    it "the finalizer leaves alone an input that names no sighash type and has a SIGHASH_ALL key path signature" $ do
      let (keyOnly, _) = spendingPsbt (forceRight (taprootScriptOutput (TaprootOutput internal Nothing)))
          asking = onInputs (insertSigHashType sigHashAll . insertInputTapInternalKey internal) keyOnly
      signed <- expectRight (signPsbt btc (keySigner secretOne) asking)
      (fmap (fmap (.hash)) . tapKeySig . inputAt 0) signed `shouldBe` Right (Just sigHashAll)
      leftAlone (onInputs deleteSigHashType signed)

    it "the signer refuses a Taproot coin that asks for a sighash type the signer does not accept" $ do
      let (keyOnly, _) = spendingPsbt (forceRight (taprootScriptOutput (TaprootOutput internal Nothing)))
      signPsbt btc (keySigner secretOne) (onInputs (insertSigHashType sigHashSingle . insertInputTapInternalKey internal) keyOnly)
        `shouldBe` Left "Input 0: the sighash type 3 is not one the signer accepts"

    -- BIP 371: the leaf hashes of a record "are of the leaves which involve
    -- this public key". A key that is the internal key and also a leaf key
    -- has a record with a leaf hash, and Bitcoin Core writes it that way.
    it "signs the key path of a Taproot coin when the record of its internal key lists a leaf" $ do
      let record = insertInputTapDerivation internal (TapDerivation [leafHash 0xc0 leaf] derivation)
      signed <- expectRight (signPsbt btc (byRecord secretOne) (onInputs (record . treeFields) withTree))
      (fmap isJust . tapKeySig . inputAt 0) signed `shouldBe` Right True

    -- Bitcoin Core finds the key of a leaf by the record of the key, and
    -- does not read the leaves that the record lists
    it "signs a leaf with the key of a record of that key, whichever leaves the record lists" $ do
      let listing hashes = insertInputTapDerivation leafKey (TapDerivation hashes derivation)
          signatures f = fmap length . tapScriptSigs . inputAt 0 =<< signPsbt btc (byRecord secretTwo) (onInputs (f . treeFields) withTree)
      signatures (listing [leafHash 0xc0 leaf]) `shouldBe` Right 1
      signatures (listing [leafHash 0xc0 (Script [OP_RETURN])]) `shouldBe` Right 1
      signatures (listing []) `shouldBe` Right 1
      signatures id `shouldBe` Right 0

    -- The leaf is in no tree of the coin: its control block names another
    -- internal key. Bitcoin Core signs each leaf that an input lists and
    -- does not read the control block. The signature is for this input and
    -- this leaf alone, so it spends nothing, and the finalizer makes no
    -- witness of it.
    it
      "signs a leaf that the input lists whatever its control \
      \block commits to, and the finalizer leaves that input alone"
      $ do
        let stray = encodeControlBlock 0xc0 leafKey [leafHash 0xc0 (Script [OP_RETURN])]
            fields = insertInputTapInternalKey internal . insertInputTapMerkleRoot (mastCommitment tree) . insertTapLeafScript (TapLeafScript stray leaf 0xc0)
        signed <- expectRight (signPsbt btc (keySigner secretTwo) (onInputs fields withTree))
        (fmap length . tapScriptSigs . inputAt 0) signed `shouldBe` Right 1
        leftAlone signed

    -- A signer written by a caller may answer with a key that is not the
    -- one asked for. Its signature would verify for no key of the coin.
    -- The input names key 1 as its internal key and key 2 in its leaf, each
    -- with a record, and the signer answers with key 3.
    it "signs neither the key path nor a leaf with a key the signer gives when it is not the key asked for" $ do
      let records =
            insertInputTapDerivation internal (TapDerivation [] derivation)
              . insertInputTapDerivation leafKey (TapDerivation [leafHash 0xc0 leaf] derivation)
          unsigned = onInputs (records . treeFields) withTree
          wrongByRecord = (keySigner secretThree) {keyOfRecord = \_ _ -> Just secretThree, keyOfHash = const Nothing}
          keyThree = PrivateKey secretThree True
          wrongByHash = (keySigner secretThree) {keyOfRecord = \_ _ -> Nothing, keyOfHash = const (Just keyThree)}
      signPsbt btc wrongByRecord unsigned `shouldBe` Right unsigned
      signPsbt btc wrongByHash unsigned `shouldBe` Right unsigned

    -- A coin whose tree holds the leaf of key 2 with the first leaf
    -- version, and an input that has this leaf under a control block with
    -- the second leaf version, and names the third in its value. The record
    -- of key 2 lists the hash of the leaf with the third.
    let leafOfVersion inTree inControl named = onInputs fields psbt
          where
            treeOf = MASTBranch (MASTLeaf inTree leaf) (MASTLeaf 0xc0 (Script [OP_RETURN]))
            outputOf = TaprootOutput internal (Just treeOf)
            parity = keyParity (forceRight (taprootOutputKey outputOf))
            controlOf = encodeControlBlock (inControl + parity) internal [leafHash 0xc0 (Script [OP_RETURN])]
            (psbt, _) = spendingPsbt (forceRight (taprootScriptOutput outputOf))
            fields =
              insertInputTapInternalKey internal
                . insertInputTapMerkleRoot (mastCommitment treeOf)
                . insertTapLeafScript (TapLeafScript controlOf leaf named)
                . insertInputTapDerivation leafKey (TapDerivation [leafHash named leaf] derivation)
        scriptSignatures = fmap length . tapScriptSigs . inputAt 0
        -- A valid signature of key 2 for the leaf of version 0xc0, on the
        -- input of the PSBT
        signedLeaf unsigned = onInputs (insertTapScriptSig leafKey hashOfLeaf signature) unsigned
          where
            coin = fromJust (either (const Nothing) id (witnessUtxo (inputAt 0 unsigned)))
            hashOfLeaf = leafHash 0xc0 leaf
            ofLeaf = Just (hashOfLeaf, 0xffffffff)
            digest = forceRight (taprootSigHash unsigned.unsignedTx [coin] 0 sigHashDefault Nothing ofLeaf)
            signature = forceRight (taprootSignature (signSchnorr secretTwo (hashToMsg digest)) sigHashDefault)

    -- BIP 342 gives <key> OP_CHECKSIG its meaning, and the signature its
    -- digest, for the leaf version 0xc0 only
    it "signs a leaf of the leaf version 0xc0, and not the same leaf of the leaf version 0xc2" $ do
      (scriptSignatures =<< signPsbt btc (byRecord secretTwo) (leafOfVersion 0xc0 0xc0 0xc0)) `shouldBe` Right 1
      (scriptSignatures =<< signPsbt btc (byRecord secretTwo) (leafOfVersion 0xc2 0xc2 0xc2)) `shouldBe` Right 0

    -- Bitcoin Core signs the leaf of the value, of version 0xc0, and does
    -- not read the control block. A spend takes the leaf version of the
    -- control block: in the first case the leaf of the entry is not in the
    -- tree, in the second it is and its control block spends a leaf that
    -- is not. The finalizer makes no witness of either.
    it "signs a leaf by the leaf version of its value, whatever leaf version its control block has" $ do
      (scriptSignatures =<< signPsbt btc (byRecord secretTwo) (leafOfVersion 0xc2 0xc2 0xc0)) `shouldBe` Right 1
      (scriptSignatures =<< signPsbt btc (byRecord secretTwo) (leafOfVersion 0xc0 0xc2 0xc0)) `shouldBe` Right 1

    -- The witness would spend the leaf of version 0xc2: one that nodes do
    -- not relay in the first case, and that is not in the tree in the
    -- second. Bitcoin Core does not finalize such an input, and refuses
    -- nothing.
    it "the finalizer leaves alone a signed leaf whose leaf version is not the one of its control block" $ do
      forM_ [leafOfVersion 0xc2 0xc2 0xc0, leafOfVersion 0xc0 0xc2 0xc0] $ \entry ->
        finalizePsbt btc (signedLeaf entry) `shouldBe` Right (signedLeaf entry)

    -- A Merkle root is a hash of 32 bytes, and this one has 31. The decoder
    -- refuses such a PSBT, and a program can still build one. The signer
    -- holds the internal key, and cannot tell which coin the key gives.
    it "the signer adds no key path signature to its own coin when the Merkle root of the input is not a hash" $ do
      let (keyOnly, _) = spendingPsbt (forceRight (taprootScriptOutput (TaprootOutput internal Nothing)))
          shortRoot = Map.insert (Key 0x18 "") (B.replicate 31 0x00)
          named = onInputs (shortRoot . insertInputTapInternalKey internal) keyOnly
      signPsbt btc (keySigner secretOne) named `shouldBe` Right named

    it "signs a Taproot coin of a PSBT of version 2 by its key path, and the PSBT stays of version 2" $ do
      let (keyOnly, coins) = spendingPsbt (forceRight (taprootScriptOutput (TaprootOutput internal Nothing)))
          version2 = withVersion Version2 (onInputs (insertInputTapInternalKey internal) keyOnly)
      final <- expectRight (finalizePsbt btc =<< signPsbt btc (keySigner secretOne) version2)
      final.version `shouldBe` Version2
      tx <- expectRight (psbtTransaction final)
      verifyStdTx btc tx coins `shouldBe` True

{- The time a Taproot input with many leaves, records and signatures takes -}

-- | The secret key that is the number, for the tests that need many keys
secretOf :: Int -> SecKey
secretOf i = fromString (replicate (64 - length digits) '0' <> digits)
  where
    digits = showHex i ""

-- | A PSBT that spends a Taproot coin whose script tree has the leaves, all
-- at the depth given, so they are a power of two. The internal key of the
-- coin is the point G. The input has the coin, and each leaf that the test
-- keeps, with the control block of its place in the tree.
spendingTree :: (Script -> Bool) -> Word8 -> [Script] -> Psbt
spendingTree kept depth scripts = onInputs (\m -> foldr insertTapLeafScript m leaves) psbt
  where
    internal = derivePubKey secretOne
    tree = fromJust (tapTreeFromLeaves [TapLeaf depth 0xc0 script | script <- scripts])
    output = TaprootOutput internal (Just tree)
    control = encodeControlBlock (0xc0 + keyParity (forceRight (taprootOutputKey output))) internal
    (psbt, _) = spendingPsbt (forceRight (taprootScriptOutput output))
    leaves =
      [ TapLeafScript (control proof) script version
      | (version, script, proof) <- getMerkleProofs tree,
        kept script
      ]

-- A PSBT that another party wrote can hold thousands of leaf scripts,
-- derivation records and signatures on one input, at no cost to its
-- writer. The signer and the finalizer once compared each leaf with each
-- record or signature. The seconds in the comments are those of that code
-- built without optimisation, on the computer where the tests were
-- written. The code that looks up takes 0.1 to 0.5 seconds there.
taprootCostSpec :: Spec
taprootCostSpec =
  describe "A Taproot input takes time by its size, and not by the square of its size: in under three seconds" $ do
    let keyLeaf secret = Script [opPushData (exportXOnlyPubKey (derivePubKey secret)), OP_CHECKSIG]
        -- 2048 leaves at depth 11, each the check of a key of its own
        leaves = [keyLeaf (secretOf i) | i <- [1001 .. 3048]]
        -- 16384 keys that are in no leaf
        strangers = [derivePubKey (secretOf i) | i <- [100001 .. 116384]]
        derivation = Derivation (fingerprintOf "d90c6a4f") "m/86'/0'/0'/0/0"
        -- Whether the work leaves the PSBT as it is, when it answers within
        -- the seconds. The PSBT is built before the time starts.
        leavesAlone :: Int -> (Psbt -> Either String Psbt) -> Psbt -> IO (Maybe Bool)
        leavesAlone seconds work psbt = do
          _ <- evaluate (B.length (encodePsbt psbt))
          timeout (seconds * 1000000) (evaluate (work psbt == Right psbt))

    -- 2048 leaves × 16384 records = 33,554,432 comparisons of two keys: 13 seconds
    it "the signer leaves alone 2048 leaves and 16384 records of keys it does not hold" $ do
      let records m = foldr (\key -> insertInputTapDerivation key (TapDerivation [] derivation)) m strangers
      leavesAlone 3 (signPsbt btc (keySigner secretThree)) (onInputs records (spendingTree (const True) 11 leaves))
        `shouldReturn` Just True

    -- The signatures are 64 bytes that verify for no key, filed under a
    -- leaf hash that is the hash of no leaf of the input.
    -- 2048 leaves × 16384 signatures = 33,554,432 comparisons of two keys: 13 seconds
    it "the finalizer leaves alone 2048 leaves and 16384 signatures that are for none of them" $ do
      let signature key = Map.insert (Key 0x14 (exportXOnlyPubKey key <> B.replicate 32 0xaa)) (B.replicate 64 0x01)
          signatures m = foldr signature m strangers
      leavesAlone 3 (finalizePsbt btc) (onInputs signatures (spendingTree (const True) 11 leaves))
        `shouldReturn` Just True

    -- One leaf can be at many places of a tree, and the input then has it
    -- once for each place, each time with another control block. Here the
    -- tree has 8192 leaves at depth 13: the same key check 4096 times, each
    -- beside a leaf of its own. The record of the key lists 262144 leaves,
    -- and not that one.
    -- 4096 places × 262144 leaf hashes = 1,073,741,824 comparisons of two hashes: 13 seconds
    it "the signer leaves alone one leaf at 4096 places, whose record lists 262144 other leaves" $ do
      let own = keyLeaf secretTwo
          beside i = Script [opPushData (S.encode i), OP_DROP]
          others = [fromJust (digestFromByteString (B.replicate 28 0 <> S.encode i)) | i <- [1 .. 262144 :: Word32]]
          record = insertInputTapDerivation (derivePubKey secretTwo) (TapDerivation others derivation)
          scripts = concat [[own, beside i] | i <- [1 .. 4096 :: Word32]]
      leavesAlone 3 (signPsbt btc (keySigner secretThree)) (onInputs record (spendingTree (== own) 13 scripts))
        `shouldReturn` Just True

{- The coins of a PSBT, and the previous transaction a signer may require -}

coinsSpec :: Spec
coinsSpec =
  describe "The coins of a PSBT" $ do
    let public = compressedKey secretOne
        signer = keySigner secretOne
        program = PayWitnessPKHash (addressHash (encodeSerial public))
        (psbt, _) = spendingPsbt program
        parent = fromJust (either (const Nothing) id (nonWitnessUtxo (inputAt 0 psbt)))
        output = head parent.outputs
        witnessOnly = withInputs [insertWitnessUtxo output Map.empty] psbt
        signatureCounts = mapM (fmap length . partialSignatures) . (.inputs)

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
    it
      "a signer leaves unsigned a SegWit version 0 coin known from its \
      \witness output only, and signs it with its previous transaction"
      $ do
        signPsbt btc signer witnessOnly `shouldBe` Right witnessOnly
        (signatureCounts =<< signPsbt btc signer psbt) `shouldBe` Right [1]
        (signatureCounts =<< signPsbt btc signer (withInputs [insertWitnessUtxo output (inputAt 0 psbt)] psbt)) `shouldBe` Right [1]

    it "a signer told to trust witness outputs signs a SegWit version 0 coin known from its witness output only" $
      (signatureCounts =<< signPsbt btc (signer {requirePreviousTx = False}) witnessOnly) `shouldBe` Right [1]

    -- CVE-2020-14199. The signer holds two coins of 15 and 20 BTC. The
    -- writer of the PSBT understates the first as 5 BTC and overstates the
    -- second. A signature of each input commits to the amount of that input
    -- alone, so the signature of the second input would be valid in a
    -- transaction that burns the 10 BTC of difference as fee.
    it
      "a signer signs no SegWit version 0 coin of a PSBT that \
      \states the amounts without the previous transactions"
      $ do
        let both = spendingTwo (encodeSerial program) (encodeSerial program)
            claimed = withInputs [insertWitnessUtxo (TxOut 500000000 (encodeSerial program)) Map.empty, insertWitnessUtxo (TxOut 2000000000 (encodeSerial program)) Map.empty] both
        signPsbt btc signer claimed `shouldBe` Right claimed

    -- A Taproot signature commits to the amount of every coin (BIP 341)
    it "a signer signs a Taproot coin known from its witness output only" $ do
      let internal = derivePubKey secretOne
          (taproot, _) = spendingPsbt (forceRight (taprootScriptOutput (TaprootOutput internal Nothing)))
      (fmap isJust . tapKeySig . inputAt 0 =<< signPsbt btc signer (withInputs (insertInputTapInternalKey internal <$> taproot.inputs) taproot)) `shouldBe` Right True

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
