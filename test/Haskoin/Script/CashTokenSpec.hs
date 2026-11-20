{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.Script.CashTokenSpec (spec) where

import Control.DeepSeq (force)
import Control.Exception (evaluate)
import Control.Monad (forM_)
import Data.Aeson (Value, eitherDecode, parseJSON, toJSON, (.:))
import Data.Aeson.Types (Parser, parseEither, withObject)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy qualified as BL
import Data.Default (def)
import Data.Either (isLeft)
import Data.Maybe (fromJust, isNothing)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding (encodeUtf8)
import Haskoin.Script
import Haskoin.Transaction.Common (TxHash, hexToTxHash)
import Haskoin.Util
import Haskoin.Util.Arbitrary
import System.Timeout (timeout)
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck (forAll)

identityTests :: IdentityTests
identityTests =
  def
    { readTests = [ReadBox arbitraryTokenData],
      jsonTests = [JsonBox arbitraryTokenData],
      serialTests = [SerialBox arbitraryTokenData]
    }

spec :: Spec
spec = do
  testIdentity identityTests
  describe "splitTokenData" $ do
    prop "reads back what encodeTokenPrefix writes, with any script after it" $
      forAll arbitraryTokenData $ \t ->
        forAll arbitraryBS $ \script -> do
          let prefix = fromJust (encodeTokenPrefix t)
          splitTokenData (prefix <> script) `shouldBe` Right (Just t, script)
          splitTokenPrefix (prefix <> script) `shouldBe` Just (prefix, script)
    it "gives a script without the prefix byte back whole" $ do
      splitTokenData "" `shouldBe` Right (Nothing, "")
      splitTokenData p2pkh `shouldBe` Right (Nothing, p2pkh)
    it "reads the prefix of output 4 of the example transaction" $ do
      let field = fromJust (decodeHex (prefixHex <> p2pkhHex))
      splitTokenData field `shouldBe` Right (Just (TokenData category 110830 Nothing), p2pkh)
  describe "encodeTokenPrefix" $ do
    it "refuses data without tokens" $
      encodeTokenPrefix (TokenData category 0 Nothing) `shouldSatisfy` isNothing
    it "refuses an amount above the maximum" $
      encodeTokenPrefix (TokenData category (maxTokenAmount + 1) Nothing)
        `shouldSatisfy` isNothing
    it "writes an NFT without a commitment or an amount" $ do
      let t = TokenData category 0 (Just (NFToken MintingCapability ""))
      -- the prefix byte and the category, then the flags: NFT and minting
      fmap encodeHex (encodeTokenPrefix t) `shouldBe` Just (T.take 66 prefixHex <> "22")
  describe "JSON" $ do
    it "takes the amount as a number too" $
      eitherDecode (tokenJson "110830") `shouldBe` Right (TokenData category 110830 Nothing)
    it "refuses data without tokens" $
      (eitherDecode (tokenJson "\"0\"") :: Either String TokenData) `shouldSatisfy` isLeft
    it "refuses a negative amount" $
      (eitherDecode (tokenJson "-1") :: Either String TokenData) `shouldSatisfy` isLeft
    it "refuses an amount above the maximum, as a string or a number" $ do
      (eitherDecode (tokenJson "\"9223372036854775808\"") :: Either String TokenData) `shouldSatisfy` isLeft
      (eitherDecode (tokenJson "9223372036854775808") :: Either String TokenData) `shouldSatisfy` isLeft
      eitherDecode (tokenJson "\"9223372036854775807\"")
        `shouldBe` Right (TokenData category maxTokenAmount Nothing)
    it "takes only decimal digits in a string amount" $
      forM_ ["0x10", "0o20", "0b1", " 16", "16 ", "(16)", "016", "+16", "1e1", "", "\x0661"] $ \a ->
        (eitherDecode (tokenJson ("\"" <> a <> "\"")) :: Either String TokenData) `shouldSatisfy` isLeft
    it "refuses a number with a huge exponent at once" $ do
      -- Building this number would take seconds and hundreds of megabytes.
      result <- timeout 1000000 (evaluate (force (eitherDecode (tokenJson "1e100000000") :: Either String TokenData)))
      fmap isLeft result `shouldBe` Just True
    it "refuses a number that is not whole" $
      (eitherDecode (tokenJson "1.5") :: Either String TokenData) `shouldSatisfy` isLeft
  describe "CashTokens test vectors" $ do
    it "reads and writes every valid token prefix" $ do
      vectors <- readTestFile "cashtokens_prefix_valid.json" :: IO [Value]
      length vectors `shouldBe` 62
      forM_ vectors $ \v -> do
        (hex, json) <- either fail return (parseEither validVector v)
        t <- either fail return (parseEither parseJSON json)
        splitTokenData (fromJust (decodeHex hex)) `shouldBe` Right (Just t, "")
        fmap encodeHex (encodeTokenPrefix t) `shouldBe` Just hex
        toJSON t `shouldBe` json
    it "refuses every invalid token prefix" $ do
      vectors <- readTestFile "cashtokens_prefix_invalid.json" :: IO [Value]
      length vectors `shouldBe` 55
      forM_ vectors $ \v -> do
        hex <- either fail return (parseEither (withObject "vector" (.: "prefix")) v)
        let bytes = fromJust (decodeHex hex)
        splitTokenData bytes `shouldSatisfy` isLeft
        splitTokenPrefix bytes `shouldBe` Nothing
  where
    validVector :: Value -> Parser (Text, Value)
    validVector = withObject "vector" $ \o -> (,) <$> o .: "prefix" <*> o .: "data"

-- | The JSON of tokens of 'category' with an amount, given as JSON.
tokenJson :: Text -> BL.ByteString
tokenJson amount =
  BL.fromStrict . encodeUtf8 $
    "{\"category\":\"" <> categoryHex <> "\",\"amount\":" <> amount <> "}"

-- | Category of the tokens in BCH transaction
-- e3abdbdc093c08cab3d6c23c320ca61f23c6e2cf4d8b3058398dcf0e78f5a809.
category :: TxHash
category = fromJust (hexToTxHash categoryHex)

categoryHex :: Text
categoryHex = "7fe0cd5197494e47ade81eb164dcdbd51859ffbe581fe4a818085d56b2f3062c"

-- | Token prefix of output 4 of that transaction: 110,830 fungible tokens.
prefixHex :: Text
prefixHex =
  "ef2c06f3b2565d0818a8e41f58beff5918d5dbdc6\
  \4b11ee8ad474e499751cde07f10feeeb00100"

p2pkhHex :: Text
p2pkhHex = "76a9146e0810ceea13412b73feb41566a3d2d0ce54e10188ac"

p2pkh :: ByteString
p2pkh = fromJust (decodeHex p2pkhHex)
