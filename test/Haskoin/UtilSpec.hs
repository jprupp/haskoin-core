{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | The helpers of "Haskoin.Util": bytes and hex, integers, lists and
-- templates, bit conversion, JSON options, the serialization helpers and
-- the marshalling classes.
module Haskoin.UtilSpec (spec) where

import Control.Exception (ErrorCall, evaluate)
import System.Timeout (timeout)
import Control.Monad.Except (ExceptT, runExceptT)
import Data.Aeson
import Data.Aeson.Encoding (encodingToLazyByteString)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Builder (toLazyByteString)
import Data.ByteString.Lazy qualified as BL
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Default (def)
import Data.Either (isLeft)
import Data.Foldable (toList)
import Data.Int (Int32, Int64)
import Data.IntMap qualified as IntMap
import Data.List (isInfixOf, permutations)
import Data.Maybe
import Data.Sequence qualified as Seq
import Data.Serialize qualified as S
import Data.Word (Word8)
import GHC.Generics (Generic)
import Haskoin.Crypto
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

identityTests :: IdentityTests
identityTests =
  def
    { readTests =
        [ ReadBox arbitraryNetwork
        ]
    }

-- A record and a sum type for the JSON options
data Point = Point {ptX :: Int, ptY :: Int}
  deriving (Eq, Show, Generic)

instance ToJSON Point where
  toJSON = genericToJSON (dropFieldLabel 2)

instance FromJSON Point where
  parseJSON = genericParseJSON (dropFieldLabel 2)

data Shape = SCircle {scRadius :: Int} | SSquare {ssSide :: Int}
  deriving (Eq, Show, Generic)

instance ToJSON Shape where
  toJSON = genericToJSON (dropSumLabels 1 2 "type")

instance FromJSON Shape where
  parseJSON = genericParseJSON (dropSumLabels 1 2 "type")

spec :: Spec
spec = prepareContext $ \ctx ->
  describe "utility functions" $ do
    testIdentity identityTests

    describe "Integers and bytes" $ do
      it "integerToBS writes big-endian bytes without leading zeros, and zero as one byte" $ do
        integerToBS 0 `shouldBe` "\x00"
        integerToBS 1 `shouldBe` "\x01"
        integerToBS 256 `shouldBe` "\x01\x00"
        integerToBS 0xdeadbeef `shouldBe` "\xde\xad\xbe\xef"
      it "integerToBS refuses a negative number" $
        evaluate (integerToBS (-1)) `shouldThrow` anyErrorCall
      it "bsToInteger reads big-endian bytes, and nothing as zero" $ do
        bsToInteger "\x01\x00" `shouldBe` 256
        bsToInteger "\x00\x00\x01" `shouldBe` 1
        bsToInteger "" `shouldBe` 0
      prop "bsToInteger . integerToBS gives back a number that is not negative" bytesOfNonNegative

    describe "Hex" $ do
      it "encodes lower case and decodes either case" $ do
        encodeHex "\xab\xcd" `shouldBe` "abcd"
        encodeHexLazy "\xab\xcd" `shouldBe` "abcd"
        decodeHex "abcd" `shouldBe` Just "\xab\xcd"
        decodeHex "ABCD" `shouldBe` Just "\xab\xcd"
        decodeHexLazy "ABCD" `shouldBe` Just "\xab\xcd"
        decodeHex "" `shouldBe` Just ""
      it "refuses an odd length, a character that is not hex, and spaces" $ do
        decodeHex "abc" `shouldBe` Nothing
        decodeHex "0g" `shouldBe` Nothing
        decodeHex " 00" `shouldBe` Nothing
        decodeHex "00 " `shouldBe` Nothing
        decodeHexLazy "abc" `shouldBe` Nothing
      it "hexEncoding is a JSON string of hex, and hexBuilder the hex alone" $ do
        encodingToLazyByteString (hexEncoding "\xab\xcd") `shouldBe` "\"abcd\""
        toLazyByteString (hexBuilder "\xab\xcd") `shouldBe` "abcd"
      prop "decodeHex . encodeHex" $ forAll arbitraryBS fromToHex
      prop "decodeHexLazy . encodeHexLazy" $ forAll arbitraryBS $ \bs -> decodeHexLazy (encodeHexLazy (BL.fromStrict bs)) == Just (BL.fromStrict bs)

    describe "getBits" $ do
      it "takes that many bits from the start, padded with zero bits" $ do
        getBits 4 "\xff\x00" `shouldBe` "\xf0"
        getBits 8 "\xff\x00" `shouldBe` "\xff"
        getBits 12 "\xff\xff" `shouldBe` "\xff\xf0"
        getBits 0 "\xff" `shouldBe` ""
      it "raises an error when the bytes do not hold that many bits" $ do
        evaluate (getBits 12 "\xff") `shouldThrow` anyErrorCall
        evaluate (getBits 4 "") `shouldThrow` anyErrorCall
        evaluate (getBits (-1) "\xff") `shouldThrow` anyErrorCall

    describe "Maybe and Either" $ do
      prop "eitherToMaybe" testEitherToMaybe
      prop "maybeToEither" testMaybeToEither
      it "liftMaybe and liftEither lift into ExceptT" $ do
        runExceptT (liftMaybe "none" (Just (1 :: Int))) `shouldReturn` Right 1
        runExceptT (liftMaybe "none" (Nothing :: Maybe Int)) `shouldReturn` Left "none"
        runExceptT (liftEither (Right (2 :: Int)) :: ExceptT' Int) `shouldReturn` Right 2
        runExceptT (liftEither (Left "bad") :: ExceptT' Int) `shouldReturn` Left "bad"

    describe "updateIndex" $ do
      it "changes the element at the index, and nothing when the index is out of range" $ do
        updateIndex 1 [1, 2, 3 :: Int] (* 10) `shouldBe` [1, 20, 3]
        updateIndex 0 [1, 2, 3 :: Int] (* 10) `shouldBe` [10, 2, 3]
        updateIndex 3 [1, 2, 3 :: Int] (* 10) `shouldBe` [1, 2, 3]
        updateIndex (-1) [1, 2, 3 :: Int] (* 10) `shouldBe` [1, 2, 3]
      prop "compare updateIndex with Data.Sequence" testUpdateIndex

    describe "matchTemplate" $ do
      it "gives for each element of the template the first matching input, each input once" $ do
        matchTemplate [1, 2, 2 :: Int] [2, 2, 3] (==) `shouldBe` [Just 2, Just 2, Nothing]
        matchTemplate [2 :: Int] [2, 2] (==) `shouldBe` [Just 2, Nothing]
        matchTemplate [] [1, 2 :: Int] (==) `shouldBe` [Nothing, Nothing]
        matchTemplate [1 :: Int] [] (==) `shouldBe` []
        matchTemplate ["a", "bb" :: String] [2, 1 :: Int] (\s n -> length s == n) `shouldBe` [Just "bb", Just "a"]
      prop "matchTemplate" testMatchTemplate
      prop "testing matchTemplate with two lists" testMatchTemplateLen

    describe "Triples" $
      it "fst3, snd3 and lst3 take the parts of a triple" $ do
        fst3 (1 :: Int, "b", 'c') `shouldBe` 1
        snd3 (1 :: Int, "b", 'c') `shouldBe` "b"
        lst3 (1 :: Int, "b", 'c') `shouldBe` 'c'

    describe "JSON options" $ do
      it "dropFieldLabel drops the prefix of a field and lowers its case" $ do
        encode (Point 1 2) `shouldBe` "{\"x\":1,\"y\":2}"
        decode "{\"x\":1,\"y\":2}" `shouldBe` Just (Point 1 2)
      it "dropSumLabels also drops the prefix of a constructor, which goes in the tag field" $ do
        encode (SCircle 3) `shouldBe` "{\"radius\":3,\"type\":\"circle\"}"
        encode (SSquare 4) `shouldBe` "{\"side\":4,\"type\":\"square\"}"
        decode "{\"type\":\"square\",\"side\":4}" `shouldBe` Just (SSquare 4)

    describe "convertBits" $ do
      -- 0xff is 11111111: the group 11111 and 111 padded to 11100
      it "regroups bits, padding the last group with zeros when asked" $ do
        convertBits True 8 5 [0xff] `shouldBe` Just [31, 28]
        convertBits True 5 8 [1] `shouldBe` Just [8]
        convertBits True 8 5 [] `shouldBe` Just []
      it "without padding, refuses leftover bits that are not zero or that could hold a whole digit" $ do
        convertBits False 5 8 [31, 28] `shouldBe` Just [255]
        convertBits False 5 8 [31, 31] `shouldBe` Nothing
        convertBits False 5 8 [1, 0] `shouldBe` Just [8]
        convertBits False 5 8 [1] `shouldBe` Nothing
        convertBits False 5 8 [] `shouldBe` Just []
      -- The data part of the BIP 173 address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4, as 5-bit groups, is the key hash of its example
      it "converts the 5-bit groups of the BIP 173 example to its 20-byte program" $
        fmap (B.pack . map fromIntegral) (convertBits False 5 8 [14, 20, 15, 7, 13, 26, 0, 25, 18, 6, 11, 13, 8, 21, 4, 20, 3, 17, 2, 29, 3, 12, 29, 3, 4, 15, 24, 20, 6, 14, 30, 22])
          `shouldBe` Just "\x75\x1e\x76\xe8\x19\x91\x96\xd4\x54\x94\x1c\x45\xd1\xb3\xa3\x23\xf1\x43\x3b\xd6"
      it "refuses a digit that does not fit the width it is converted from" $
        -- 256 needs nine bits. The BIP 173 reference returns None here.
        convertBits True 8 5 [256] `shouldBe` Nothing
      it "refuses a width that is zero, negative or too wide for a Word, instead of looping" $ do
        -- The comparison is made inside the time limit, so that a result
        -- that never ends cannot be forced outside it.
        let refused frombits tobits digits =
              timeout 100000 (evaluate (convertBits True frombits tobits digits == Nothing))
        refused 8 0 [1] `shouldReturn` Just True
        refused 8 (-1) [1] `shouldReturn` Just True
        refused 0 8 [1] `shouldReturn` Just True
        refused (-8) 5 [1] `shouldReturn` Just True
        -- 60 + 8 bits do not fit the 64 bits of the accumulator
        refused 60 8 [1] `shouldReturn` Just True
      prop "converting to 5 bits with padding and back gives the bytes" $
        forAll arbitraryBS $ \bs ->
          let groups = fromJust (convertBits True 8 5 (map fromIntegral (B.unpack bs)))
           in fmap (map fromIntegral) (convertBits False 5 8 groups) === Just (B.unpack bs)

    describe "Serialization helpers" $ do
      it "putList and getList write a 64-bit count then the elements" $ do
        runPutS (putList putWord8 [1, 2]) `shouldBe` "\x00\x00\x00\x00\x00\x00\x00\x02\x01\x02"
        runGetS (getList getWord8) "\x00\x00\x00\x00\x00\x00\x00\x02\x01\x02" `shouldBe` Right [1, 2]
        runGetS (getList getWord8) "\x00\x00\x00\x00\x00\x00\x00\x00" `shouldBe` Right ([] :: [Word8])
      it "getList refuses a count that does not fit an Int instead of reading an empty list" $
        runGetS (getList getWord8) "\xff\xff\xff\xff\xff\xff\xff\xff\x41" `shouldSatisfy` isLeft
      it "putMaybe and getMaybe write a tag byte" $ do
        runPutS (putMaybe putWord8 Nothing) `shouldBe` "\x00"
        runPutS (putMaybe putWord8 (Just 7)) `shouldBe` "\x01\x07"
        runGetS (getMaybe getWord8) "\x01\x07" `shouldBe` Right (Just 7)
        runGetS (getMaybe getWord8) "\x00" `shouldBe` Right (Nothing :: Maybe Word8)
        runGetS (getMaybe getWord8) "\x02" `shouldSatisfy` isLeft
      it "putLengthBytes and getLengthBytes write a 64-bit length then the bytes" $ do
        runPutS (putLengthBytes "abc") `shouldBe` "\x00\x00\x00\x00\x00\x00\x00\x03\&abc"
        runGetS getLengthBytes "\x00\x00\x00\x00\x00\x00\x00\x03\&abc" `shouldBe` Right "abc"
        runGetS getLengthBytes "\xff\xff\xff\xff\xff\xff\xff\xff\x41" `shouldSatisfy` isLeft
        runGetS getLengthBytes "\x00\x00\x00\x00\x00\x00\x00\x03\&ab" `shouldSatisfy` isLeft
      it "putInteger writes a 32-bit number after a zero byte, and a wider one with its sign, its length and its bytes" $ do
        runPutS (putInteger 0) `shouldBe` "\x00\x00\x00\x00\x00"
        runPutS (putInteger (-1)) `shouldBe` "\x00\xff\xff\xff\xff"
        runPutS (putInteger 2147483647) `shouldBe` "\x00\x7f\xff\xff\xff"
        -- 2^31: sign 1, four bytes, little-endian
        runPutS (putInteger 2147483648) `shouldBe` "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x80"
        -- -(2^31 + 1): sign 0xff
        runPutS (putInteger (-2147483649)) `shouldBe` "\x01\xff\x00\x00\x00\x00\x00\x00\x00\x04\x01\x00\x00\x80"
      it "getInteger reads both forms back" $ do
        runGetS getInteger "\x00\xff\xff\xff\xff" `shouldBe` Right (-1)
        runGetS getInteger "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x80" `shouldBe` Right 2147483648
        runGetS getInteger "\x01\xff\x00\x00\x00\x00\x00\x00\x00\x04\x01\x00\x00\x80" `shouldBe` Right (-2147483649)
      -- A number has one encoding, the one putInteger writes. The cases
      -- below are other ways to write a number that getInteger used to read.
      it "getInteger refuses a tag byte other than 0 and 1" $
        -- tag 2, then sign 0, length 1 and the byte 5
        runGetS getInteger "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x05"
          `shouldSatisfy` either ("tag" `isInfixOf`) (const False)
      it "getInteger refuses a sign byte other than 0x01 and 0xff" $ do
        -- 2^31 with the sign bytes 0x00 and 0x02
        runGetS getInteger "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x80"
          `shouldSatisfy` either ("sign" `isInfixOf`) (const False)
        runGetS getInteger "\x01\x02\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x80"
          `shouldSatisfy` either ("sign" `isInfixOf`) (const False)
      it "getInteger refuses a wide number with zero bytes at its top" $
        -- 2^31 in five bytes, little-endian, the fifth being zero
        runGetS getInteger "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x80\x00"
          `shouldSatisfy` either ("shortest" `isInfixOf`) (const False)
      it "getInteger refuses the wide form of a number that fits 32 bits" $ do
        -- 5, and -2^31, which both fit the form with a zero tag
        runGetS getInteger "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x05"
          `shouldSatisfy` either ("shortest" `isInfixOf`) (const False)
        runGetS getInteger "\x01\xff\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x80"
          `shouldSatisfy` either ("shortest" `isInfixOf`) (const False)
      it "getInteger refuses a wide number of no bytes" $
        runGetS getInteger "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"
          `shouldSatisfy` either ("shortest" `isInfixOf`) (const False)
      it "getInteger reads the smallest 32-bit number, -2^31" $
        runGetS getInteger "\x00\x80\x00\x00\x00" `shouldBe` Right (-2147483648)
      it "getInteger reads a number of 200,000 bytes in well under two seconds" $ do
        -- 256^200000 - 1: every byte is 0xff. The old reader took 11 seconds.
        let input = "\x01\x01\x00\x00\x00\x00\x00\x03\x0d\x40" <> B.replicate 200000 0xff
            expected = 256 ^ (200000 :: Int) - 1 :: Integer
        timeout 2000000 (evaluate (runGetS getInteger input == Right expected))
          `shouldReturn` Just True
      prop "getInteger . putInteger" $ \i -> runGetS getInteger (runPutS (putInteger i)) === Right (i :: Integer)
      prop "getInteger . putInteger for wide numbers" $ \(i :: Integer) (k :: Int) ->
        let n = i * 2 ^ (abs k `mod` 256) in runGetS getInteger (runPutS (putInteger n)) === Right n
      -- Versions before 0.20 wrote the chain work of a header with the
      -- Integer instance of cereal. Headers stored then must still read.
      prop "getInteger reads what the Integer instance of cereal writes" $ \(i :: Integer) (k :: Int) ->
        let n = i * 2 ^ (abs k `mod` 256) in runGetS getInteger (S.encode n) === Right n
      it "putInt32be and putInt64be write two's complement, big-endian" $ do
        runPutS (putInt32be (-1)) `shouldBe` "\xff\xff\xff\xff"
        runPutS (putInt32be minBound) `shouldBe` "\x80\x00\x00\x00"
        runPutS (putInt32be 1) `shouldBe` "\x00\x00\x00\x01"
        runPutS (putInt64be (-2)) `shouldBe` "\xff\xff\xff\xff\xff\xff\xff\xfe"
        runPutS (putInt64be minBound) `shouldBe` "\x80\x00\x00\x00\x00\x00\x00\x00"
        runGetS getInt32be "\x80\x00\x00\x00" `shouldBe` Right (minBound :: Int32)
        runGetS getInt64be "\xff\xff\xff\xff\xff\xff\xff\xfe" `shouldBe` Right (-2 :: Int64)
      prop "getInt32be . putInt32be" $ \i -> runGetS getInt32be (runPutS (putInt32be i)) === Right (i :: Int32)
      prop "getInt64be . putInt64be" $ \i -> runGetS getInt64be (runPutS (putInt64be i)) === Right (i :: Int64)
      it "putIntMap and getIntMap write the pairs in key order after their count" $ do
        let m = IntMap.fromList [(2, 20), (1, 10 :: Word8)]
        runPutS (putIntMap (putWord8 . fromIntegral) putWord8 m) `shouldBe` "\x00\x00\x00\x00\x00\x00\x00\x02\x01\x0a\x02\x14"
        runGetS (getIntMap (fromIntegral <$> getWord8) getWord8) "\x00\x00\x00\x00\x00\x00\x00\x02\x01\x0a\x02\x14" `shouldBe` Right m
      it "getIntMap refuses keys that are not in ascending order, such as a key given twice" $ do
        -- two pairs with the key 1
        runGetS (getIntMap (fromIntegral <$> getWord8) getWord8) "\x00\x00\x00\x00\x00\x00\x00\x02\x01\x0a\x01\x0b"
          `shouldSatisfy` either ("ascending" `isInfixOf`) (const False)
        -- the keys 2 then 1
        runGetS (getIntMap (fromIntegral <$> getWord8) getWord8) "\x00\x00\x00\x00\x00\x00\x00\x02\x02\x14\x01\x0a"
          `shouldSatisfy` either ("ascending" `isInfixOf`) (const False)
      it "putTwo and getTwo write a pair" $ do
        runPutS (putTwo putWord8 putWord16be (1, 2)) `shouldBe` "\x01\x00\x02"
        runGetS (getTwo getWord8 getWord16be) "\x01\x00\x02" `shouldBe` Right (1, 2)

    describe "Marshalling" $ do
      let key = fromJust (secKey (B.replicate 32 1))
          public = PublicKey (derivePubKey ctx key) True
      it "marshal and unmarshal round trip, strict and lazy" $ do
        unmarshal ctx (marshal ctx public) `shouldBe` Right public
        unmarshalLazy ctx (marshalLazy ctx public) `shouldBe` Right public
        (unmarshalLazy ctx "junk" :: Either String PublicKey) `shouldSatisfy` isLeft
      it "unmarshal refuses bytes after the value, strict and lazy" $ do
        -- the compressed public key of secret key 1, then one more byte
        let bytes = fromJust (decodeHex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ff")
        (unmarshal ctx bytes :: Either String PublicKey)
          `shouldSatisfy` either ("bytes left over" `isInfixOf`) (const False)
        (unmarshalLazy ctx (BL.fromStrict bytes) :: Either String PublicKey)
          `shouldSatisfy` either ("bytes left over" `isInfixOf`) (const False)
      it "marshalJSON and unmarshalJSON round trip, and refuse what is not the value" $ do
        unmarshalJSON ctx (marshalJSON ctx public) `shouldBe` Just public
        (unmarshalJSON ctx "\"junk\"" :: Maybe PublicKey) `shouldBe` Nothing
        (unmarshalJSON ctx "{" :: Maybe PublicKey) `shouldBe` Nothing

    describe "Test helpers" $ do
      it "customCerealID tells whether a getter reads what a putter writes" $ do
        customCerealID S.getWord8 S.putWord8 7 `shouldBe` True
        customCerealID S.getWord16be S.putWord16le 7 `shouldBe` False
      it "readTestFile reads a JSON file of the data directory" $ do
        value <- readTestFile "sig_strict.json" :: IO Value
        value `shouldSatisfy` \v -> case v of Array _ -> True; _ -> False
        parsed <- readTestFileParser parseJSON "sig_strict.json" :: IO [Value]
        length parsed `shouldSatisfy` (> 0)
      it "readTestFile raises an error for a file that is not there" $
        (readTestFile "no-such-file.json" :: IO Value) `shouldThrow` anyException

type ExceptT' a = ExceptTString a

type ExceptTString a = ExceptT String IO a

-- | integerToBS takes no negative number, so the absolute value is tested.
bytesOfNonNegative :: Integer -> Bool
bytesOfNonNegative i = bsToInteger (integerToBS $ abs i) == abs i

fromToHex :: ByteString -> Bool
fromToHex bs = decodeHex (encodeHex bs) == Just bs

testUpdateIndex :: [Int] -> Int -> Int -> Bool
testUpdateIndex xs v i =
  updateIndex i xs (const v) == toList (Seq.update i v $ Seq.fromList xs)

testMatchTemplate :: [Int] -> Int -> Bool
testMatchTemplate as i = catMaybes res == bs
  where
    res = matchTemplate as bs (==)
    idx =
      if null as
        then 0
        else i `mod` length as
    bs = permutations as !! idx

testMatchTemplateLen :: [Int] -> [Int] -> Bool
testMatchTemplateLen as bs = length bs == length res
  where
    res = matchTemplate as bs (==)

testEitherToMaybe :: Either String Int -> Bool
testEitherToMaybe (Right v) = eitherToMaybe (Right v) == Just v
testEitherToMaybe e = isNothing (eitherToMaybe e)

testMaybeToEither :: Maybe Int -> String -> Bool
testMaybeToEither (Just v) str = maybeToEither str (Just v) == Right v
testMaybeToEither m str = maybeToEither str m == Left str
