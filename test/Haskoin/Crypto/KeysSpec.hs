{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.Crypto.KeysSpec (spec) where

import Control.Exception (evaluate)
import Control.Lens
import Control.Monad
import Data.Aeson as A
import Data.Aeson.Lens
import Data.ByteString qualified as B
import Data.ByteString.Char8 qualified as C
import Data.Char (isAsciiLower, isAsciiUpper, toLower, toUpper)
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Default (def)
import Data.Either (isLeft)
import Data.List (isInfixOf)
import Data.Maybe
import Data.Serialize qualified as S
import Data.String (fromString)
import Data.String.Conversions (cs)
import Data.Text (Text)
import Data.Text qualified as T
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Network.Data (Network (..))
import Haskoin.Script
import Haskoin.Util
import Haskoin.Util.Arbitrary
import System.Timeout (timeout)
import Test.HUnit
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

identityTests :: Ctx -> IdentityTests
identityTests ctx =
  def
    { readTests =
        [ ReadBox (arbitrary :: Gen SecKey),
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
    prop "a compressed key is written in 33 bytes starting with 02 or 03, an uncompressed key in 65 bytes starting with 04" $
      forAll (arbitraryKeyPair ctx) $ \(_, pub) ->
        let bytes = marshal ctx pub
         in if pub.compress
              then B.length bytes == 33 && B.head bytes `elem` [0x02, 0x03]
              else B.length bytes == 65 && B.head bytes == 0x04
    prop "Public key show . read identity" $
      forAll (arbitraryKeyPair ctx) $ \(_, pub) ->
        (read . show) pub == pub
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
    it "refuses a string of a million characters at once, without decoding it" $
      -- Decoding that much Base58 takes minutes. The length check comes first.
      timeout 1000000 (evaluate (fromWif btc (T.replicate 1000000 "z")))
        `shouldReturn` Just Nothing
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
    it "decodes a 30-character mini key" $
      -- the sample key of the Bitcoin wiki
      fromMiniKey "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy"
        `shouldBe` Just (wrapSecKey False "4c7a9640c72dc2099f23715d0c8a0d8a35f8906e3cab61dd3f78b67bf887c9ab")
    it "refuses a mini key of 21 or 23 characters, even with a zero check byte" $ do
      -- SHA-256 of each string followed by "?" starts with 0x00
      fromMiniKey "S4b3N3oGqDqR5jNuxE1Be" `shouldBe` Nothing
      fromMiniKey "S4b3N3oGqDqR5jNuxEvD13Z" `shouldBe` Nothing
    it "refuses a string that does not start with S" $
      -- 22 Base58 characters with a zero check byte
      fromMiniKey "T4b3N3oGqDqR5jNuxEv13r" `shouldBe` Nothing
    it "refuses a character outside the Base58 alphabet" $ do
      -- 22 characters with a zero check byte: one holds the digit 0, the
      -- other the letters O, I and l and underscores
      fromMiniKey "S4b3N3oGqDqR5jNux0v1B7" `shouldBe` Nothing
      fromMiniKey "0OIl_______________607" `shouldBe` Nothing
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
    it "refuses a hybrid public key" $
      -- 06, then x and the even y of the public key of 1. Consensus takes
      -- this form, the relay rules of Bitcoin Core do not, and this library
      -- reads keys in the two standard forms only.
      ( unmarshalJSON
          ctx
          "\"0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
          \483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8\"" ::
          Maybe PublicKey
      )
        `shouldBe` Nothing
    it "refuses a point that is not on the curve" $
      -- the invalid public key of BIP32 test vector 5
      (unmarshalJSON ctx "\"020000000000000000000000000000000000000000000000000000000000000007\"" :: Maybe PublicKey)
        `shouldBe` Nothing
  describe "Binary private key" $ do
    it "is the 32 bytes of the key, then 01 for a compressed public key or 00" $ do
      runPutS (serialize (wrapSecKey True secKey1))
        `shouldBe` hex "000000000000000000000000000000000000000000000000000000000000000101"
      runPutS (serialize (wrapSecKey False secKey1))
        `shouldBe` hex "000000000000000000000000000000000000000000000000000000000000000100"
      runGetS deserialize (hex "000000000000000000000000000000000000000000000000000000000000000101")
        `shouldBe` Right (wrapSecKey True secKey1)
    it "refuses a serialized zero key" $
      (runGetS deserialize (B.replicate 33 0) :: Either String PrivateKey) `shouldSatisfy` isLeft
    it "refuses the curve order n as a serialized key" $
      (runGetS deserialize (hex "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414101") :: Either String PrivateKey)
        `shouldSatisfy` either ("curve order" `isInfixOf`) (const False)
  describe "Showing a private key" $ do
    -- The secret of key 1 must not appear in the text
    it "does not reveal the secret" $
      show (PrivateKey "0000000000000000000000000000000000000000000000000000000000000001" True)
        `shouldBe` "PrivateKey {key = <redacted>, compress = True}"
    it "nests in parentheses like a derived instance" $
      show (Just (PrivateKey "0000000000000000000000000000000000000000000000000000000000000001" False))
        `shouldBe` "Just (PrivateKey {key = <redacted>, compress = False})"
  describe "key_io vectors of Bitcoin Core 32.1" $ do
    valid <- runIO (readTestFile "key_io_valid.json" :: IO [(Text, Text, A.Value)])
    invalid <- runIO (readTestFile "key_io_invalid.json" :: IO [[Text]])
    it "the files hold 70 valid and 70 invalid vectors" $ do
      length valid `shouldBe` 70
      length invalid `shouldBe` 70
    it "reads and writes every valid private key and address" $
      mapM_ (testKeyIOValidVector ctx) valid
    it "refuses every invalid string as an address and as a private key, on every network" $
      mapM_ testKeyIOInvalidVector invalid

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

testMiniKey :: Assertion
testMiniKey =
  assertEqual "fromMiniKey" (Just res) (go "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy")
  where
    go = fmap (encodeHex . (.key.get)) . fromMiniKey
    res = "4c7a9640c72dc2099f23715d0c8a0d8a35f8906e3cab61dd3f78b67bf887c9ab"

-- Test vectors from src/test/data/key_io_valid.json and key_io_invalid.json of
-- Bitcoin Core 32.1. The checks are those of src/test/key_io_tests.cpp.

-- | One valid vector: a string, the bytes it stands for and its chain. For a
-- private key the bytes are the secret, for an address the output script.
testKeyIOValidVector :: Ctx -> (Text, Text, A.Value) -> Assertion
testKeyIOValidVector ctx (string, payload, metadata)
  | isPrivkey = do
      let compressed = metadata ^?! key "isCompressed" . _Bool
          secret = fromMaybe (error "bad secret in the vector file") (secKey (hex payload))
      assertEqual
        ("the WIF " <> cs string <> " holds the key and its compression flag")
        (Just (payload, compressed))
        ((\k -> (encodeHex k.key.get, k.compress)) <$> fromWif net string)
      assertEqual
        ("the key is written as the WIF " <> cs string)
        string
        (toWif net (wrapSecKey compressed secret))
      assertEqual
        ("the WIF " <> cs string <> " is not an address")
        Nothing
        (textToAddr net string)
  | otherwise = do
      assertEqual
        ("the address " <> cs string <> " pays to the script")
        (Just payload)
        (encodeHex <$> (addressToScriptBS ctx =<< textToAddr net string))
      assertEqual
        ("the script is written as the address " <> cs string)
        (Just string)
        (addrToText net =<< eitherToMaybe (scriptToAddressBS net ctx (hex payload)))
      -- With the case of every letter flipped, a Bech32 address reads the
      -- same and a Base58 address does not read
      assertEqual
        ("the address " <> cs string <> " with its case flipped")
        (if tryCaseFlip then Just payload else Nothing)
        (encodeHex <$> (addressToScriptBS ctx =<< textToAddr net (flipCase string)))
      assertEqual
        ("the address " <> cs string <> " is not a private key")
        Nothing
        (fromWif net string)
  where
    isPrivkey = metadata ^?! key "isPrivkey" . _Bool
    tryCaseFlip = fromMaybe False (metadata ^? key "tryCaseFlip" . _Bool)
    net =
      case metadata ^?! key "chain" . _String of
        "main" -> btc
        "testnet4" -> btcTest4
        "regtest" -> btcRegTest
        -- This library has no signet. Signet writes keys and addresses as
        -- testnet3 does: the same version bytes and the prefix "tb"
        "signet" -> btcTest
        chain -> error ("Unknown chain in key_io_valid.json: " <> cs chain)

-- | Upper-case letters become lower-case and the reverse.
flipCase :: Text -> Text
flipCase = T.map flipLetter
  where
    flipLetter c
      | isAsciiLower c = toUpper c
      | isAsciiUpper c = toLower c
      | otherwise = c

-- | One invalid vector: a string that is no address and no private key, on
-- any network.
testKeyIOInvalidVector :: [Text] -> Assertion
testKeyIOInvalidVector [string] =
  forM_ [btc, btcTest, btcTest4, btcRegTest] $ \net -> do
    assertEqual
      (show string <> " is not an address on " <> net.name)
      Nothing
      (textToAddr net string)
    assertEqual
      (show string <> " is not a private key on " <> net.name)
      Nothing
      (fromWif net string)
testKeyIOInvalidVector _ = assertFailure "Invalid test vector"

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
