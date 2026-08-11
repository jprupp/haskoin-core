{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.AddressSpec (spec) where

import Control.Monad
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Default (def)
import Data.Maybe (fromJust, isJust)
import Data.Text (Text)
import Data.Text qualified as T
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.HUnit
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

identityTests :: Network -> IdentityTests
identityTests net =
  def
    { readTests = [ReadBox (arbitraryAddress net)],
      serialTests = [SerialBox (arbitraryAddress net)],
      marshalJsonTests = [MarshalJsonBox arbitraryNetAddress]
    }

spec :: Spec
spec = prepareContext $ \ctx -> do
  forM_ allNets $ \net -> testIdentity $ identityTests net
  describe "Address properties" $ do
    prop "encodes and decodes base58 bytestring" $
      forAll arbitraryBS $ \bs ->
        decodeBase58 (encodeBase58 bs) `shouldBe` Just bs
    prop "encodes and decodes base58 bytestring with checksum" $
      forAll arbitraryBS $ \bs ->
        decodeBase58Check (encodeBase58Check bs) `shouldBe` Just bs
    prop "textToAddr . addrToText identity" $
      forAll arbitraryNetAddress $ \(net, a) ->
        (textToAddr net =<< addrToText net a) `shouldBe` Just a
    prop "outputAddress . addressToOutput identity" $
      forAll arbitraryNetAddress $ \(net, a) ->
        not (isCashAddress a) ==>
          (outputAddress ctx =<< addressToOutput a) `shouldBe` Just a
  describe "Address vectors" $ do
    it "Passes Base58 vectors 1" $
      mapM_ testVector vectors
    it "Passes Base58 vectors 2" $
      mapM_ testBase58Vector base58Vectors
    it "Passes Base58 invalid decoding vectors" $
      mapM_ testBase58InvalidVector base58InvalidVectors
    it "Passes Base58Check invalid decoding vectors" $
      mapM_ testBase58ChkInvalidVector base58ChkInvalidVectors
    it "Passes addresses witness p2sh(pwpkh) vectors" $
      mapM_ (testCompatWitnessVector ctx) compatWitnessVectors

testVector :: (ByteString, Text, Text) -> Assertion
testVector (bs, e, chk) = do
  assertEqual "encodeBase58" e b58
  assertEqual "encodeBase58Check" chk b58Chk
  assertEqual "decodeBase58" (Just bs) (decodeBase58 b58)
  assertEqual "decodeBase58Check" (Just bs) (decodeBase58Check b58Chk)
  where
    b58 = encodeBase58 bs
    b58Chk = encodeBase58Check bs

vectors :: [(ByteString, Text, Text)]
vectors =
  [ (B.empty, "", "3QJmnh"),
    (B.pack [0], "1", "1Wh4bh"),
    (B.pack [0, 0, 0, 0], "1111", "11114bdQda"),
    (B.pack [0, 0, 1, 0, 0], "11LUw", "113CUwsFVuo"),
    (B.pack [255], "5Q", "VrZDWwe"),
    ( B.pack [0, 0, 0, 0] `B.append` B.pack [1 .. 255],
      "1111cWB5HCBdLjAuqGGReWE3R3CguuwSjw6RHn39s2yuDRTS5N\
      \sBgNiFpWgAnEx6VQi8csexkgYw3mdYrMHr8x9i7aEwP8kZ7vcc\
      \XWqKDvGv3u1GxFKPuAkn8JCPPGDMf3vMMnbzm6Nh9zh1gcNsMv\
      \H3ZNLmP5fSG6DGbbi2tuwMWPthr4boWwCxf7ewSgNQeacyozhK\
      \DDQQ1qL5fQFUW52QKUZDZ5fw3KXNQJMcNTcaB723LchjeKun7M\
      \uGW5qyCBZYzA1KjofN1gYBV3NqyhQJ3Ns746GNuf9N2pQPmHz4\
      \xpnSrrfCvy6TVVz5d4PdrjeshsWQwpZsZGzvbdAdN8MKV5QsBDY",
      "111151KWPPBRzdWPr1ASeu172gVgLf1YfUp6VJyk6K9t4cLqYt\
      \FHcMa2iX8S3NJEprUcW7W5LvaPRpz7UG7puBj5STE3nKhCGt5e\
      \ckYq7mMn5nT7oTTic2BAX6zDdqrmGCnkszQkzkz8e5QLGDjf7K\
      \eQgtEDm4UER6DMSdBjFQVa6cHrrJn9myVyyhUrsVnfUk2WmNFZ\
      \vkWv3Tnvzo2cJ1xW62XDfUgYz1pd97eUGGPuXvDFfLsBVd1dfd\
      \UhPwxW7pMPgdWHTmg5uqKGFF6vE4xXpAqZTbTxRZjCDdTn68c2\
      \wrcxApm8hq3JX65Hix7VtcD13FF8b7BzBtwjXq1ze6NMjKgUcq\
      \pJTN9vt"
    )
  ]

-- Test vectors from:
-- https://github.com/bitcoin/bitcoin/blob/master/src/test/data/base58_encode_decode.json

testBase58Vector :: (Text, Text) -> Assertion
testBase58Vector (a, b) = do
  assertEqual "encodeBase58 match" b (encodeBase58 bsA)
  assertEqual "decodeBase58 match" a (encodeHex bsB)
  assertEqual "bytestring match" bsA bsB
  where
    bsA = fromJust $ decodeHex a
    bsB = fromJust $ decodeBase58 b

base58Vectors :: [(Text, Text)]
base58Vectors =
  [ ("", ""),
    ("61", "2g"),
    ("626262", "a3gV"),
    ("636363", "aPEr"),
    ( "73696d706c792061206c6f6e6720737472696e67",
      "2cFupjhnEsSn59qHXstmK2ffpLv2"
    ),
    ( "00eb15231dfceb60925886b67d065299925915aeb172c06647",
      "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"
    ),
    ("516b6fcd0f", "ABnLTmg"),
    ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
    ("572e4794", "3EFU7m"),
    ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
    ("10c8511e", "Rt5zm"),
    ("00000000000000000000", "1111111111"),
    ( "000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252a\
      \da93ff480d6dd43dc62a641155a5",
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    ),
    ( "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c\
      \1d1e1f202122232425262728292a2b2c2d2e2f30313233343536373839\
      \3a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50515253545556\
      \5758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70717273\
      \7475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90\
      \9192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacad\
      \aeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9ca\
      \cbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7\
      \e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
      "1cWB5HCBdLjAuqGGReWE3R3CguuwSjw6RHn39s2yuDRTS5NsBgNiFpWgAn\
      \Ex6VQi8csexkgYw3mdYrMHr8x9i7aEwP8kZ7vccXWqKDvGv3u1GxFKPuAk\
      \n8JCPPGDMf3vMMnbzm6Nh9zh1gcNsMvH3ZNLmP5fSG6DGbbi2tuwMWPthr\
      \4boWwCxf7ewSgNQeacyozhKDDQQ1qL5fQFUW52QKUZDZ5fw3KXNQJMcNTc\
      \aB723LchjeKun7MuGW5qyCBZYzA1KjofN1gYBV3NqyhQJ3Ns746GNuf9N2\
      \pQPmHz4xpnSrrfCvy6TVVz5d4PdrjeshsWQwpZsZGzvbdAdN8MKV5QsBDY"
    )
  ]

-- Test vectors from:
-- https://github.com/bitcoin/bitcoin/blob/master/src/test/base58_tests.cpp

testBase58InvalidVector :: (Text, Maybe Text) -> Assertion
testBase58InvalidVector (a, resM) =
  assertEqual "decodeBase58 invalid match" resM (encodeHex <$> decodeBase58 a)

base58InvalidVectors :: [(Text, Maybe Text)]
base58InvalidVectors =
  [ ("invalid", Nothing),
    ("\0invalid", Nothing),
    ("good", Just "768320"),
    ("bad0IOl", Nothing),
    ("goodbad0IOl", Nothing),
    ("good\0bad0IOl", Nothing)
    --  Haskoin does not remove white spaces before decoding base58 strings
    -- , (" \t\n\v\f\r skip \r\f\v\n\t a", Nothing)
    -- , (" \t\n\v\f\r skip \r\f\v\n\t ", Just "971a55")
  ]

testBase58ChkInvalidVector :: (Text, Maybe Text) -> Assertion
testBase58ChkInvalidVector (a, resM) =
  assertEqual
    "decodeBase58Check invalid match"
    resM
    (encodeHex <$> decodeBase58Check a)

base58ChkInvalidVectors :: [(Text, Maybe Text)]
base58ChkInvalidVectors =
  [ ("3vQB7B6MrGQZaxCuFg4oh", Just "68656c6c6f20776f726c64"),
    ("3vQB7B6MrGQZaxCuFg4oi", Nothing),
    ("3vQB7B6MrGQZaxCuFg4oh0IOl", Nothing),
    ("3vQB7B6MrGQZaxCuFg4oh\00IOl", Nothing)
  ]

testCompatWitnessVector :: Ctx -> (Network, Text, Text) -> Assertion
testCompatWitnessVector ctx (net, seckey, addr) = do
  let seckeyM = fromWif net seckey
  assertBool "decode seckey" (isJust seckeyM)
  let pubkey = derivePublicKey ctx (fromJust seckeyM)
  let addrM = addrToText btcTest (pubKeyCompatWitnessAddr ctx pubkey)
  assertBool "address can be encoded" (isJust addrM)
  assertEqual "witness address matches" addr (fromJust addrM)

compatWitnessVectors :: [(Network, Text, Text)]
compatWitnessVectors =
  [ ( btcTest,
      "cNUnpYpMsJXYCERYBciJnsWBpcYEFjdcbq6dxj4SskGhs7uHuJ7Q",
      "2N6PDTueBHvXzW61B4oe5SW1D3v2Z3Vpbvw"
    )
  ]
