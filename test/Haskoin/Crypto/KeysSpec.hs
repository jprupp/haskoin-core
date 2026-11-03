{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.Crypto.KeysSpec (spec) where

import Control.Lens
import Control.Monad
import Data.Aeson as A
import Data.Aeson.Lens
import Data.ByteString qualified as B
import Data.ByteString.Char8 qualified as C
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Default (def)
import Data.Either (isLeft)
import Data.Maybe
import Data.Serialize qualified as S
import Data.String (fromString)
import Data.String.Conversions (cs)
import Data.Text (Text)
import Data.Text qualified as T
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Script
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.HUnit
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

identityTests :: Ctx -> IdentityTests
identityTests ctx =
  def
    { readTests =
        [ ReadBox (arbitrary :: Gen SecKey),
          ReadBox arbitraryPrivateKey,
          ReadBox (arbitraryPublicKey ctx)
        ],
      marshalJsonTests =
        [ MarshalJsonBox $ (,) <$> arbitraryNetwork <*> arbitraryPrivateKey,
          MarshalJsonBox ((,) ctx <$> arbitraryPublicKey ctx)
        ],
      serialTests =
        [ SerialBox arbitraryPrivateKey
        ],
      marshalTests =
        [ MarshalBox ((,) ctx <$> arbitraryPublicKey ctx)
        ]
    }

spec :: Spec
spec = prepareContext $ \ctx -> do
  describe "Key pair property checks" $ do
    testIdentity $ identityTests ctx
    prop "Public key is canonical" $
      forAll (arbitraryKeyPair ctx) (isCanonicalPubKey ctx . snd)
    prop "Key pair key show . read identity" $
      forAll (arbitraryKeyPair ctx) $ \x ->
        (read . show) x == x
    prop "Public key binary serialization" $ do
      forAll (arbitraryKeyPair ctx) $ \(sec, pub) ->
        (unmarshal ctx . marshal ctx) pub == Right pub
    prop "fromWif . toWif identity" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitraryKeyPair ctx) $ \(key, _) ->
          (fromWif net . toWif net) key == Just key
    prop "WIF binary identity" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitraryKeyPair ctx) $ \(key, _) ->
          (runGetS deserialize . runPutS . serialize) key == Right key
  describe "Bitcoin core vectors /src/test/key_tests.cpp" $ do
    it "Passes WIF decoding tests" testPrivkey
    it "Passes SecKey compression tests" testPrvKeyCompressed
    it "Passes PubKey compression tests" $ testKeyCompressed ctx
    it "Passes address matching tests" $ testMatchingAddress ctx
    it "Passes signature verification" $ testSigs ctx
    it "Passes deterministic signing tests" $ testDetSigning ctx
  describe "MiniKey vectors" $
    it "Passes MiniKey decoding tests" testMiniKey
  describe "Secret key range" $ do
    it "accepts the smallest secret key, 1" $
      decodeSecKey (B.replicate 31 0 <> B.singleton 1) `shouldBe` Just secKey1
    it "accepts the largest secret key, n - 1" $
      decodeSecKey (hex "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
        `shouldSatisfy` isJust
    it "refuses the zero key" $
      decodeSecKey (B.replicate 32 0) `shouldBe` Nothing
    it "refuses the curve order n" $
      decodeSecKey (hex "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
        `shouldBe` Nothing
    it "refuses a key that is not 32 bytes" $ do
      decodeSecKey (B.replicate 31 1) `shouldBe` Nothing
      decodeSecKey (B.replicate 33 1) `shouldBe` Nothing
  describe "WIF" $ do
    it "decodes the compressed WIF of key 1" $
      fromWif btc "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        `shouldBe` Just (wrapSecKey True secKey1)
    it "decodes the uncompressed WIF of key 1" $
      fromWif btc "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"
        `shouldBe` Just (wrapSecKey False secKey1)
    it "refuses the WIF of key 0" $ do
      fromWif btc "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73Nd2Mcv1" `shouldBe` Nothing
      fromWif btc "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU" `shouldBe` Nothing
    it "refuses the WIF of the curve order n" $ do
      fromWif btc "L5oLkpV3aqBjhki6LmvChTCV6odsp4SXM6FfU2Gppt5kFqRzExJJ" `shouldBe` Nothing
      fromWif btc "5Km2kuu7vtFDPpxywn4u3NLpbr5jKpTB3jsuDU2KYEqetwr388P" `shouldBe` Nothing
    it "refuses a compressed WIF whose flag byte is not 0x01" $
      -- key 1 followed by the flag byte 0x02
      fromWif btc "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sfZr2ym" `shouldBe` Nothing
    it "refuses the WIF of another network" $ do
      -- key 1 with the testnet prefix 0xef
      fromWif btc "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA" `shouldBe` Nothing
      fromWif btcTest "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA"
        `shouldBe` Just (wrapSecKey True secKey1)
    it "refuses a Base58Check string with no payload" $
      -- "3QJmnh" is the Base58Check encoding of the empty string
      fromWif btc "3QJmnh" `shouldBe` Nothing
    it "refuses a string longer than any WIF" $
      fromWif btc (T.replicate 53 "z") `shouldBe` Nothing
    it "fails the JSON parse of an invalid WIF instead of throwing" $ do
      (unmarshalJSON btc "\"3QJmnh\"" :: Maybe PrivateKey) `shouldBe` Nothing
      (unmarshalJSON btc "\"KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73Nd2Mcv1\"" :: Maybe PrivateKey)
        `shouldBe` Nothing
  describe "Mini keys" $ do
    it "decodes a 22-character mini key" $
      -- the example key of the Bitcoin wiki
      fromMiniKey "S4b3N3oGqDqR5jNuxEvDwf"
        `shouldBe` Just (wrapSecKey False "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
    it "refuses a mini key whose check byte is not zero" $
      -- SHA-256 of "S4b3N3oGqDqR5jNuxEvDwg?" starts with 0x8f
      fromMiniKey "S4b3N3oGqDqR5jNuxEvDwg" `shouldBe` Nothing
    it "refuses a mini key of another length" $
      fromMiniKey "S4b3N3oGqDqR5jNuxEvDw" `shouldBe` Nothing
  describe "Key tweaks" $ do
    it "adding a zero tweak leaves the secret key unchanged" $
      tweakSecKey ctx secKey1 zeroHash `shouldBe` Just secKey1
    it "adding one to secret key 1 gives secret key 2" $
      tweakSecKey ctx secKey1 oneHash
        `shouldBe` Just "0000000000000000000000000000000000000000000000000000000000000002"
    it "refuses a tweak that brings the secret key to zero" $
      -- 1 + (n - 1) = n, which is 0 modulo n
      tweakSecKey ctx secKey1 orderMinusOneHash `shouldBe` Nothing
    it "refuses a tweak at or above the curve order" $
      tweakSecKey ctx secKey1 orderHash `shouldBe` Nothing
    it "adding one to the public key of 1 gives the public key of 2" $
      tweakPubKey ctx (pubKey1 ctx) oneHash `shouldBe` Just (pubKey2 ctx)
    it "refuses a tweak that brings the public key to infinity" $
      tweakPubKey ctx (pubKey1 ctx) orderMinusOneHash `shouldBe` Nothing
    prop "tweaking the public key matches tweaking the secret key" $
      forAll arbitraryPrivateKey $ \k ->
        forAll arbitraryHash256 $ \t ->
          (derivePubKey ctx <$> tweakSecKey ctx k.key t)
            == tweakPubKey ctx (derivePubKey ctx k.key) t
  describe "Public key text forms" $ do
    it "parses a compressed public key from JSON" $
      unmarshalJSON ctx "\"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\""
        `shouldBe` Just (wrapPubKey True (pubKey1 ctx))
    it "parses an uncompressed public key from JSON" $
      unmarshalJSON
        ctx
        "\"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
        \483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8\""
        `shouldBe` Just (wrapPubKey False (pubKey1 ctx))
    it "refuses a public key with trailing bytes" $
      (unmarshalJSON ctx "\"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798deadbeef\"" :: Maybe PublicKey)
        `shouldBe` Nothing
    it "refuses a public key with an unknown prefix byte" $
      (unmarshalJSON ctx "\"0579be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"" :: Maybe PublicKey)
        `shouldBe` Nothing
    it "refuses a point that is not on the curve" $
      -- the invalid public key of BIP32 test vector 5
      (unmarshalJSON ctx "\"020000000000000000000000000000000000000000000000000000000000000007\"" :: Maybe PublicKey)
        `shouldBe` Nothing
  describe "Binary private key" $
    it "refuses a serialized zero key" $
      (runGetS deserialize (B.replicate 33 0) :: Either String PrivateKey) `shouldSatisfy` isLeft
  describe "key_io_valid.json vectors" $ do
    vectors <- runIO (readTestFile "key_io_valid.json" :: IO [(Text, Text, A.Value)])
    it "Passes the key_io_valid.json vectors" $
      mapM_ (testKeyIOValidVector ctx) vectors
  describe "key_io_invalid.json vectors" $ do
    vectors <- runIO (readTestFile "key_io_invalid.json" :: IO [[Text]])
    it "Passes the key_io_invalid.json vectors" $
      mapM_ (testKeyIOInvalidVector ctx) vectors

hex :: Text -> B.ByteString
hex = fromJust . decodeHex

-- | The secret key 1.
secKey1 :: SecKey
secKey1 = "0000000000000000000000000000000000000000000000000000000000000001"

-- | Public keys of the secret keys 1 and 2, that is G and 2G.
pubKey1, pubKey2 :: Ctx -> PubKey
pubKey1 ctx = fromJust $ importPubKey ctx $ hex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
pubKey2 ctx = fromJust $ importPubKey ctx $ hex "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

-- | Tweaks of 0, 1, n - 1 and n, where n is the curve order.
zeroHash, oneHash, orderMinusOneHash, orderHash :: Hash256
zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
oneHash = "0000000000000000000000000000000000000000000000000000000000000001"
orderMinusOneHash = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
orderHash = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

-- github.com/bitcoin/bitcoin/blob/master/src/script.cpp
-- from function IsCanonicalPubKey
isCanonicalPubKey :: Ctx -> PublicKey -> Bool
isCanonicalPubKey ctx p =
  not $
    -- Non-canonical public key: too short
    (B.length bs < 33)
      ||
      -- Non-canonical public key: invalid length for uncompressed key
      (B.index bs 0 == 4 && B.length bs /= 65)
      ||
      -- Non-canonical public key: invalid length for compressed key
      (B.index bs 0 `elem` [2, 3] && B.length bs /= 33)
      ||
      -- Non-canonical public key: compressed nor uncompressed
      (B.index bs 0 `notElem` [2, 3, 4])
  where
    bs = marshal ctx p

testMiniKey :: Assertion
testMiniKey =
  assertEqual "fromMiniKey" (Just res) (go "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy")
  where
    go = fmap (encodeHex . (.key.get)) . fromMiniKey
    res = "4c7a9640c72dc2099f23715d0c8a0d8a35f8906e3cab61dd3f78b67bf887c9ab"

-- Test vectors from:
-- https://github.com/bitcoin/bitcoin/blob/master/src/test/key_io_tests.cpp

testKeyIOValidVector :: Ctx -> (Text, Text, A.Value) -> Assertion
testKeyIOValidVector ctx (a, payload, obj)
  | disabled = return () -- There are invalid version 1 bech32 addresses
  | isPrv = do
      -- Test from WIF to SecKey
      let isComp = obj ^?! key "isCompressed" . _Bool
          prvKeyM = fromWif net a
          prvKeyHexM = encodeHex . (.key.get) <$> prvKeyM
      assertBool "Valid PrvKey" $ isJust prvKeyM
      assertEqual "Valid compression" (Just isComp) ((.compress) <$> prvKeyM)
      assertEqual "WIF matches payload" (Just payload) prvKeyHexM
      let prvAsPubM :: Maybe ScriptOutput
          prvAsPubM = (eitherToMaybe . unmarshal ctx <=< decodeHex) a
      assertBool "PrvKey is invalid ScriptOutput" $ isNothing prvAsPubM
      -- Test from SecKey to WIF
      let secM = secKey =<< decodeHex payload
          wifM = toWif net . wrapSecKey isComp <$> secM
      assertEqual "Payload matches WIF" (Just a) wifM
  | otherwise = do
      -- Test Addr to Script
      let addrM = textToAddr net a
          outputM = addressToOutput =<< addrM
          scriptM = encodeHex . marshal ctx <$> outputM
      assertBool ("Valid Address " <> cs a) $ isJust addrM
      assertEqual "Address matches payload" (Just payload) scriptM
      let pubAsWifM = fromWif net a
          pubAsSecM = secKey =<< decodeHex a
      assertBool "Address is invalid Wif" $ isNothing pubAsWifM
      assertBool "Address is invalid PrvKey" $ isNothing pubAsSecM
      -- Test Script to Addr
      let outM = eitherToMaybe . unmarshal ctx =<< decodeHex payload
          resM = addrToText net =<< outputAddress ctx =<< outM
      assertEqual "Payload matches address" (Just a) resM
  where
    isPrv = obj ^?! key "isPrivkey" . _Bool
    disabled = fromMaybe False $ obj ^? key "disabled" . _Bool
    chain = obj ^?! key "chain" . _String
    net =
      case chain of
        "main" -> btc
        "test" -> btcTest
        "regtest" -> btcRegTest
        _ -> error "Invalid chain key in key_io_valid.json"

testKeyIOInvalidVector :: Ctx -> [Text] -> Assertion
testKeyIOInvalidVector ctx [a] = do
  let wifMs = (`fromWif` a) <$> allNets
      secKeyM = (secKey <=< decodeHex) a
      scriptM :: Maybe ScriptOutput
      scriptM = (eitherToMaybe . unmarshal ctx <=< decodeHex) a
  assertBool "Payload is invalid WIF" $ all isNothing wifMs
  assertBool "Payload is invalid SecKey" $ isNothing secKeyM
  assertBool "Payload is invalid Script" $ isNothing scriptM
testKeyIOInvalidVector _ _ = assertFailure "Invalid test vector"

-- Test vectors from:
-- https://github.com/bitcoin/bitcoin/blob/master/src/test/key_tests.cpp

testPrivkey :: Assertion
testPrivkey = do
  assertBool "Key 1" $ isJust $ fromWif btc strSecret1
  assertBool "Key 2" $ isJust $ fromWif btc strSecret2
  assertBool "Key 1C" $ isJust $ fromWif btc strSecret1C
  assertBool "Key 2C" $ isJust $ fromWif btc strSecret2C
  assertBool "Bad key" $ isNothing $ fromWif btc strAddressBad

testPrvKeyCompressed :: Assertion
testPrvKeyCompressed = do
  assertBool "Key 1" $ not sec1.compress
  assertBool "Key 2" $ not sec2.compress
  assertBool "Key 1C" sec1C.compress
  assertBool "Key 2C" sec2C.compress

testKeyCompressed :: Ctx -> Assertion
testKeyCompressed ctx = do
  assertBool "Key 1" $ not (pub1 ctx).compress
  assertBool "Key 2" $ not (pub2 ctx).compress
  assertBool "Key 1C" (pub1C ctx).compress
  assertBool "Key 2C" (pub2C ctx).compress

testMatchingAddress :: Ctx -> Assertion
testMatchingAddress ctx = do
  assertEqual "Key 1" (Just addr1) $ addrToText btc (pubKeyAddr ctx (pub1 ctx))
  assertEqual "Key 2" (Just addr2) $ addrToText btc (pubKeyAddr ctx (pub2 ctx))
  assertEqual "Key 1C" (Just addr1C) $ addrToText btc (pubKeyAddr ctx (pub1C ctx))
  assertEqual "Key 2C" (Just addr2C) $ addrToText btc (pubKeyAddr ctx (pub2C ctx))

testSigs :: Ctx -> Assertion
testSigs ctx = forM_ sigMsg $ testSignature ctx . doubleSHA256

sigMsg :: [B.ByteString]
sigMsg =
  [ mconcat ["Very secret message ", C.pack (show (i :: Int)), ": 11"]
  | i <- [0 .. 15]
  ]

testSignature :: Ctx -> Hash256 -> Assertion
testSignature ctx h = do
  let sign1 = signHash ctx sec1.key h
      sign2 = signHash ctx sec2.key h
      sign1C = signHash ctx sec1C.key h
      sign2C = signHash ctx sec2C.key h
  assertBool "Key 1, Sign1" $ verifyHashSig ctx h sign1 (pub1 ctx).point
  assertBool "Key 1, Sign2" $ not $ verifyHashSig ctx h sign2 (pub1 ctx).point
  assertBool "Key 1, Sign1C" $ verifyHashSig ctx h sign1C (pub1 ctx).point
  assertBool "Key 1, Sign2C" $ not $ verifyHashSig ctx h sign2C (pub1 ctx).point
  assertBool "Key 2, Sign1" $ not $ verifyHashSig ctx h sign1 (pub2 ctx).point
  assertBool "Key 2, Sign2" $ verifyHashSig ctx h sign2 (pub2 ctx).point
  assertBool "Key 2, Sign1C" $ not $ verifyHashSig ctx h sign1C (pub2 ctx).point
  assertBool "Key 2, Sign2C" $ verifyHashSig ctx h sign2C (pub2 ctx).point
  assertBool "Key 1C, Sign1" $ verifyHashSig ctx h sign1 (pub1C ctx).point
  assertBool "Key 1C, Sign2" $ not $ verifyHashSig ctx h sign2 (pub1C ctx).point
  assertBool "Key 1C, Sign1C" $ verifyHashSig ctx h sign1C (pub1C ctx).point
  assertBool "Key 1C, Sign2C" $ not $ verifyHashSig ctx h sign2C (pub1C ctx).point
  assertBool "Key 2C, Sign1" $ not $ verifyHashSig ctx h sign1 (pub2C ctx).point
  assertBool "Key 2C, Sign2" $ verifyHashSig ctx h sign2 (pub2C ctx).point
  assertBool "Key 2C, Sign1C" $ not $ verifyHashSig ctx h sign1C (pub2C ctx).point
  assertBool "Key 2C, Sign2C" $ verifyHashSig ctx h sign2C (pub2C ctx).point

testDetSigning :: Ctx -> Assertion
testDetSigning ctx = do
  let m = doubleSHA256 ("Very deterministic message" :: B.ByteString)
  assertEqual
    "Det sig 1"
    (signHash ctx sec1.key m)
    (signHash ctx sec1C.key m)
  assertEqual
    "Det sig 2"
    (signHash ctx sec2.key m)
    (signHash ctx sec2C.key m)

strSecret1, strSecret2, strSecret1C, strSecret2C :: Text
strSecret1 = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj"
strSecret2 = "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3"
strSecret1C = "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw"
strSecret2C = "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g"

sec1, sec2, sec1C, sec2C :: PrivateKey
sec1 = fromJust $ fromWif btc strSecret1
sec2 = fromJust $ fromWif btc strSecret2
sec1C = fromJust $ fromWif btc strSecret1C
sec2C = fromJust $ fromWif btc strSecret2C

addr1, addr2, addr1C, addr2C :: Text
addr1 = "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ"
addr2 = "1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ"
addr1C = "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs"
addr2C = "1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs"

strAddressBad :: Text
strAddressBad = "1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF"

pub1, pub2, pub1C, pub2C :: Ctx -> PublicKey
pub1 ctx = derivePublicKey ctx sec1
pub2 ctx = derivePublicKey ctx sec2
pub1C ctx = derivePublicKey ctx sec1C
pub2C ctx = derivePublicKey ctx sec2C
