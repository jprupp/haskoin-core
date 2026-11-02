{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- | The PSBT format of BIP 174: the vectors of the BIP, the bytes of a
-- PSBT and the refusals of what breaks the spec, the fields of the spec,
-- and the roles: combining, signing, finalizing and extracting.
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
import Data.Word (Word64)
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
withInputs inputs psbt = Psbt psbt.unsignedTx psbt.globals inputs psbt.outputs

spec :: Spec
spec = do
  vectors <- runIO (readTestFile "psbt_bip174.json" :: IO Vectors)
  prepareContext $ \ctx -> do
    vectorsSpec vectors
    rolesSpec ctx vectors
    bytesSpec vectors
    fieldsSpec ctx vectors
    signingSpec ctx
    complexSpec ctx
    propertiesSpec ctx

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
      encodePsbt (Psbt emptyTx (insertProprietary "test" 0 "btc" Map.empty) [] [])
        `shouldBe` hexBytes ("70736274ff" <> emptyTxEntry <> "07fc047465737400" <> "03627463" <> "00")

    it "write the keys of a map in order, the type first, whatever the order they were added" $ do
      let globals = Map.fromList [(Key 0x20 "", hexBytes "bb"), (Key 0x10 (hexBytes "01"), hexBytes "aa")]
      encodePsbt (Psbt emptyTx globals [] [])
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
        `shouldBe` Right (Psbt emptyTx (Map.fromList [(Key 0x20 "", hexBytes "bb")]) [] [])

    it "refuse what is not a PSBT" $
      decodePsbt "{\"tx\": \"0200\"}" `shouldBe` Left "Not a PSBT: the bytes do not start with the magic bytes of BIP 174"

    it "refuse a key twice in a map, naming it" $
      decodePsbt (hexBytes ("70736274ff" <> emptyTxEntry <> "012001aa" <> "012001bb" <> "00"))
        `shouldBe` Left "The global map has the key 0x20 twice"

    it "refuse bytes after the last map" $
      decodePsbt (bytesOf (creator vectors) <> "\0") `shouldBe` Left "Bytes follow the last map"

    it "refuse a PSBT of another version" $
      decodePsbt (hexBytes ("70736274ff" <> emptyTxEntry <> "01fb0402000000" <> "00"))
        `shouldBe` Left "The global map: the value of the key 0xfb is PSBT version 2: only version 0 is supported"

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
spendingPsbt ctx coinScript = (Psbt tx Map.empty [input] [Map.empty, Map.empty], [(coinScript, 200000000, outpoint)])
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

    prop "a P2SH multisig coin, signed with enough of its keys and finalized, verifies" $
      forAll ((,) <$> arbitraryMSParam <*> arbitraryKeyPair ctx) $ \((m, n), _) ->
        forAll (vectorOf n (arbitraryKeyPair ctx)) $ \pairs ->
          let redeem = encodeOutput ctx (PayMulSig (snd <$> pairs) m)
              (psbt, coins) = spendingPsbt ctx (toP2SH redeem)
              withFields = withInputs ((insertInputRedeemScript redeem . foldr (\(_, public) f -> recordOf ctx public . f) id pairs) <$> psbt.inputs) psbt
           in signsAndVerifies btc ctx (fst <$> take m pairs) (withFields, coins) === Right True

    prop "a P2WPKH coin, and a P2SH-P2WPKH one with its redeem script, signed and finalized, verify" $
      forAll (arbitraryKeyPair ctx) $ \(secret, public) ->
        let program = PayWitnessPKHash (addressHash (marshal ctx public))
            (native, nativeCoins) = spendingPsbt ctx program
            redeem = encodeOutput ctx program
            (nested, nestedCoins) = spendingPsbt ctx (toP2SH redeem)
            nativeWithRecord = withInputs (recordOf ctx public <$> native.inputs) native
            nestedWithFields = withInputs ((insertInputRedeemScript redeem . recordOf ctx public) <$> nested.inputs) nested
         in signsAndVerifies btc ctx [secret] (nativeWithRecord, nativeCoins) === Right True
              .&&. signsAndVerifies btc ctx [secret] (nestedWithFields, nestedCoins) === Right True

    prop "a P2WSH multisig coin with its witness script, nested in P2SH or not, signed and finalized, verifies" $
      forAll arbitraryMSParam $ \(m, n) ->
        forAll (vectorOf n (arbitraryKeyPair ctx)) $ \pairs ->
          let witness = encodeOutput ctx (PayMulSig (snd <$> pairs) m)
              program = toP2WSH witness
              records = foldr (\(_, public) f -> recordOf ctx public . f) id pairs
              (native, nativeCoins) = spendingPsbt ctx program
              (nested, nestedCoins) = spendingPsbt ctx (toP2SH (encodeOutput ctx program))
              nativeWithFields = withInputs ((insertInputWitnessScript witness . records) <$> native.inputs) native
              nestedWithFields = withInputs ((insertInputRedeemScript (encodeOutput ctx program) . insertInputWitnessScript witness . records) <$> nested.inputs) nested
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
