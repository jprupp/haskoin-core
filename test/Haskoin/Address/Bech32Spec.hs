{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.Address.Bech32Spec (spec) where

import Control.Monad
import Data.Bits (xor)
import Data.ByteString (ByteString)
import Data.ByteString qualified as ByteString
import Data.Char (chr, ord, toLower)
import Data.Maybe
import Data.String.Conversions
import Data.Text (Text, append, pack, snoc, uncons)
import Data.Text qualified as Text
import Data.Word (Word8)
import Haskoin.Address
import Haskoin.Address.Bech32
import Haskoin.Util
import Test.HUnit
import Test.Hspec

spec :: Spec
spec = do
  describe "bech32 checksum" $ do
    it "should be valid" $
      forM_ validChecksums (uncurry testValidChecksum)
    it "should be invalid" $
      forM_ invalidChecksums testInvalidChecksum
    it "should be case-insensitive" $
      all ((== Just "test12hrzfj") . flip (bech32Encode Bech32) []) hrpCaseVariants
  describe "bech32 address" $ do
    it "passes the BIP-173 and BIP-350 valid address vectors" $
      forM_ validAddresses testValidAddress
    it "rejects the BIP-173 and BIP-350 invalid address vectors" $
      forM_ invalidAddresses testInvalidAddress
    it "rejects an address with a non-ASCII look-alike character" $
      -- U+017F in place of s
      segwitDecode "tb" "tb1qrp33g0q5c5tx\x017Fp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
        `shouldBe` Nothing
    it "rejects an address whose padding bits are not zero" $
      segwitDecode "bc" "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf308468nf"
        `shouldBe` Nothing
    it "rejects an address with an extra zero group" $
      segwitDecode "bc" "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qqnuhcm0"
        `shouldBe` Nothing
    it "rejects an address for another human-readable part" $
      segwitDecode "tb" "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" `shouldBe` Nothing
    it "decodes the version and program of a P2WPKH address" $
      segwitDecode "bc" "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        `shouldBe` Just (0, ByteString.unpack (fromJust (decodeHex "751e76e8199196d454941c45d1b3a323f1433bd6")))
  describe "bech32 encoding/decoding" $ do
    it "should not encode long data string" $
      assert . isNothing $
        bech32Encode Bech32 "bc" (replicate 82 (word5 (1 :: Word8)))
    it "should not encode bad version number" $
      assert $
        isNothing $
          segwitEncode "bc" 17 []
    it "should not encode invalid length for version 0" $
      assert $
        isNothing $
          segwitEncode "bc" 0 (replicate 30 1)
    it "should relax length restrictions for versions other than 0" $
      assert $
        isJust $
          segwitEncode "bc" 1 (replicate 30 1)
    it "should not encode another long data string" $
      assert $
        isNothing $
          segwitEncode "bc" 1 (replicate 41 1)
    it "should not encode empty human readable part" $
      assert $
        isNothing $
          bech32Encode Bech32 "" []
    it "should not decode empty human-readable part" $
      assert $
        isNothing $
          bech32Decode "10a06t8"
    it "human-readable part should be case-insensitive" $
      bech32Encode Bech32 "HRP" [] `shouldBe` bech32Encode Bech32 "hrp" []
    it "rejects a human-readable part with a non-ASCII character" $
      bech32Encode Bech32 "b\x00e9" [] `shouldBe` Nothing
    it "rejects a string with a non-ASCII character" $
      isNothing (bech32Decode "a12uel5l\x00e9") `shouldBe` True
    it "rejects a string longer than 90 characters" $
      isNothing (bech32Decode ("a1" <> Text.replicate 89 "q")) `shouldBe` True
  describe "base conversion" $ do
    it "toBase32 splits bytes into five-bit groups and pads with zero bits" $
      -- 11111111 becomes 11111 and 11100
      map fromWord5 (toBase32 [0xff]) `shouldBe` [31, 28 :: Int]
    it "toBase32 needs no padding for five bytes" $
      map fromWord5 (toBase32 [1, 2, 3, 4, 5]) `shouldBe` [0, 4, 1, 0, 6, 1, 0, 5 :: Int]
    it "toBase256 reverses toBase32" $
      toBase256 (map word5 [31, 28 :: Int]) `shouldBe` Just [0xff]
    it "toBase256 rejects padding bits that are not zero" $
      toBase256 (map word5 [31, 31 :: Int]) `shouldBe` Nothing
    it "toBase256 rejects padding wide enough to hold a whole group" $
      toBase256 (map word5 [31, 28, 0 :: Int]) `shouldBe` Nothing
    it "word5 keeps the low five bits" $
      fromWord5 (word5 (33 :: Int)) `shouldBe` (1 :: Int)
    it "bech32Const tells the two encodings apart" $ do
      bech32Const Bech32 `shouldBe` 1
      bech32Const Bech32m `shouldBe` 0x2bc830a3

testValidChecksum :: Bech32Encoding -> Bech32 -> Assertion
testValidChecksum enc checksum = case bech32Decode checksum of
  Nothing -> assertFailure (show checksum)
  Just (enc', resultHRP, resultData) -> do
    assertEqual (show checksum ++ " encoding incorrect") enc enc'
    -- test that a corrupted checksum fails decoding.
    let (hrp, rest) = Text.breakOnEnd "1" checksum
        Just (first, rest') = uncons rest
        checksumCorrupted = (hrp `snoc` chr (ord first `xor` 1)) `append` rest'
    assertBool (show checksum ++ " corrupted") $
      isNothing (bech32Decode checksumCorrupted)
    -- test that re-encoding the decoded checksum results in the same checksum.
    let checksumEncoded = bech32Encode enc' resultHRP resultData
        expectedChecksum = Just $ Text.toLower checksum
    assertEqual
      (show checksum ++ " re-encode")
      expectedChecksum
      checksumEncoded

testInvalidChecksum :: Bech32 -> Assertion
testInvalidChecksum checksum =
  assertBool (show checksum) (isNothing $ bech32Decode checksum)

testValidAddress :: (Text, Text) -> Assertion
testValidAddress (address, hexscript) = do
  let address' = Text.toLower address
      hrp = Text.take 2 address'
  case segwitDecode hrp address of
    Nothing ->
      assertFailure (Text.unpack address <> ": decode failed")
    Just (witver, witprog) -> do
      assertEqual
        (show address)
        (decodeHex hexscript)
        (Just $ segwitScriptPubkey witver witprog)
      assertEqual
        (show address)
        (Just address')
        (segwitEncode hrp witver witprog)

testInvalidAddress :: Text -> Assertion
testInvalidAddress address = do
  assertBool (show address) (isNothing $ segwitDecode "bc" address)
  assertBool (show address) (isNothing $ segwitDecode "tb" address)

segwitScriptPubkey :: Word8 -> [Word8] -> ByteString
segwitScriptPubkey witver witprog =
  ByteString.pack $ witver' : fromIntegral (length witprog) : witprog
  where
    witver' = if witver == 0 then 0 else witver + 0x50

validChecksums :: [(Bech32Encoding, Text)]
validChecksums =
  [ ( Bech32,
      "A12UEL5L"
    ),
    ( Bech32,
      "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs"
    ),
    ( Bech32,
      "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"
    ),
    ( Bech32,
      "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j"
    ),
    ( Bech32,
      "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"
    ),
    ( Bech32m,
      "A1LQFN3A"
    ),
    ( Bech32m,
      "a1lqfn3a"
    ),
    ( Bech32m,
      "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6"
    ),
    ( Bech32m,
      "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx"
    ),
    ( Bech32m,
      "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8"
    ),
    ( Bech32m,
      "split1checkupstagehandshakeupstreamerranterredcaperredlc445v"
    ),
    ( Bech32m,
      "?1v759aa"
    )
  ]

invalidChecksums :: [Text]
invalidChecksums =
  [ " 1nwldj5",
    "\DEL1axkwrx",
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt\xFF"
  ]

validAddresses :: [(Text, Text)]
validAddresses =
  [ ( "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
      "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    ),
    ( "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
      "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
    ),
    ( "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
      "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
    ),
    ( "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
      "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    ),
    ( "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
      "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
    ),
    ( "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
      "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"
    ),
    ( "BC1SW50QGDZ25J",
      "6002751e"
    ),
    ( "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
      "5210751e76e8199196d454941c45d1b3a323"
    ),
    ( "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
      "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
    ),
    ( "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
      "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"
    ),
    ( "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
      "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
  ]

invalidAddresses :: [Text]
invalidAddresses =
  [ "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
    "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
    "bc1rw5uspcuh",
    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
    "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    "bc1gmk9yu",
    "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
    "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
    "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
    "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
    "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
    "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
    "bc1pw5dgrnzv",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j"
  ]

hrpCaseVariants :: [Text]
hrpCaseVariants = map Text.pack hrpTestPermutations

hrpTestPermutations :: [String]
hrpTestPermutations = do
  a <- ['t', 'T']
  b <- ['e', 'E']
  c <- ['s', 'S']
  d <- ['t', 'T']
  return [a, b, c, d]
