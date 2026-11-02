{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.Address.CashAddrSpec (spec) where

import Control.Monad
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Char8 qualified as Char8
import Data.Maybe
import Data.String.Conversions
import Data.Text (Text)
import Haskoin.Address
import Haskoin.Network.Constants
import Haskoin.Util
import Test.HUnit
import Test.Hspec

spec :: Spec
spec = do
  describe "cashaddr checksum test vectors" $ do
    it "prefix:x64nx6hz" $ do
      let mpb = cash32decode "prefix:x64nx6hz"
      mpb `shouldBe` Just ("prefix", "")
    it "p:gpf8m4h7" $ do
      let mpb = cash32decode "p:gpf8m4h7"
      mpb `shouldBe` Just ("p", "")
    it "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn" $ do
      let mpb =
            cash32decode
              "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn"
      mpb
        `shouldBe` Just
          ( "bitcoincash",
            "\NULD2\DC4\199BT\182\&5\207\132e:V\215\198u\190w\223"
          )
    it "bchtest:testnetaddress4d6njnut" $ do
      let mpb = cash32decode "bchtest:testnetaddress4d6njnut"
      mpb `shouldBe` Just ("bchtest", "^`\185\229}kG\152")
    it "bchreg:555555555555555555555555555555555555555555555udxmlmrz" $ do
      let mpb =
            cash32decode
              "bchreg:555555555555555555555555555555555555555555555udxmlmrz"
      mpb
        `shouldBe` Just
          ( "bchreg",
            "\165)JR\148\165)JR\148\165)JR\148\165)JR\148\165)JR\148\165)J"
          )
  describe "cashaddr to base58 translation test vectors" $ do
    it "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu" $ do
      let addr =
            addrToText bch
              =<< textToAddr btc "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"
      addr
        `shouldBe` Just "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
    it "1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR" $ do
      let addr =
            addrToText bch
              =<< textToAddr btc "1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR"
      addr
        `shouldBe` Just "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy"
    it "16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb" $ do
      let addr =
            addrToText bch
              =<< textToAddr btc "16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb"
      addr
        `shouldBe` Just "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r"
    it "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC" $ do
      let addr =
            addrToText bch
              =<< textToAddr btc "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC"
      addr
        `shouldBe` Just "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"
    it "3LDsS579y7sruadqu11beEJoTjdFiFCdX4" $ do
      let addr =
            addrToText bch
              =<< textToAddr btc "3LDsS579y7sruadqu11beEJoTjdFiFCdX4"
      addr
        `shouldBe` Just "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e"
    it "31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw" $ do
      let addr =
            addrToText bch
              =<< textToAddr btc "31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw"
      addr
        `shouldBe` Just "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37"
  describe "base58 to cashaddr translation test vectors" $ do
    it "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a" $ do
      let addr =
            addrToText btc
              =<< textToAddr
                bch
                "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
      addr `shouldBe` Just "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"
    it "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy" $ do
      let addr =
            addrToText btc
              =<< textToAddr
                bch
                "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy"
      addr `shouldBe` Just "1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR"
    it "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r" $ do
      let addr =
            addrToText btc
              =<< textToAddr
                bch
                "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r"
      addr `shouldBe` Just "16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb"
    it "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq" $ do
      let addr =
            addrToText btc
              =<< textToAddr
                bch
                "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"
      addr `shouldBe` Just "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC"
    it "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e" $ do
      let addr =
            addrToText btc
              =<< textToAddr
                bch
                "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e"
      addr `shouldBe` Just "3LDsS579y7sruadqu11beEJoTjdFiFCdX4"
    it "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37" $ do
      let addr =
            addrToText btc
              =<< textToAddr
                bch
                "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37"
      addr `shouldBe` Just "31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw"
  describe "cashaddr larger test vectors" $
    forM_ (zip [0 ..] vectors) $ \(i, vec) ->
      it ("cashaddr test vector " <> show (i :: Int)) $ testCashAddr vec
  describe "cashAddrDecode" $ do
    it "decodes a lowercase address with its prefix" $
      cashAddrDecode bch "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
        `shouldBe` Just (0, hash20)
    it "decodes an address without prefix" $
      cashAddrDecode bch "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
        `shouldBe` Just (0, hash20)
    it "decodes an address in all uppercase" $
      cashAddrDecode bch "BITCOINCASH:QPM2QSZNHKS23Z7629MMS6S4CWEF74VCWVY22GDX6A"
        `shouldBe` Just (0, hash20)
    it "decodes a token-aware address with its type" $
      cashAddrDecode bch "bitcoincash:zpm2qsznhks23z7629mms6s4cwef74vcwvrqekrq9w"
        `shouldBe` Just (2, hash20)
    it "rejects a mixed case prefix" $
      cashAddrDecode bch "BitcoinCash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
        `shouldBe` Nothing
    it "rejects mixed case data" $
      cashAddrDecode bch "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdX6A"
        `shouldBe` Nothing
    it "rejects the prefix of another network" $
      cashAddrDecode bch "bchtest:qpm2qsznhks23z7629mms6s4cwef74vcwvqcw003ap"
        `shouldBe` Nothing
    it "rejects an address of another network given without prefix" $
      cashAddrDecode bch "qpm2qsznhks23z7629mms6s4cwef74vcwvqcw003ap"
        `shouldBe` Nothing
    it "rejects a non-ASCII look-alike character" $
      -- U+212A in place of K
      cashAddrDecode bch "BITCOINCASH:QPM2QSZNH\x212AS23Z7629MMS6S4CWEF74VCWVY22GDX6A"
        `shouldBe` Nothing
    it "rejects padding bits that are not zero" $
      cashAddrDecode bch "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcw0c0g40rx7"
        `shouldBe` Nothing
    it "rejects an extra zero group" $
      cashAddrDecode bch "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvq5xhgekz9"
        `shouldBe` Nothing
    it "rejects a bad checksum" $
      cashAddrDecode bch "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6q"
        `shouldBe` Nothing
    it "has no result on a network without CashAddr" $
      cashAddrDecode btc "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
        `shouldBe` Nothing
  describe "cashAddrEncode" $ do
    it "encodes a P2PKH hash" $
      cashAddrEncode bch 0 hash20
        `shouldBe` Just "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
    it "encodes a token-aware P2SH32 hash" $
      cashAddrEncode bch 3 hash32
        `shouldBe` Just "bitcoincash:rvvxx9puznz3v6qyh5vjqv6kmgfkexzk0rx56faphrrr99syjqexy30vcqxv4"
    it "uses the prefix of the network" $ do
      cashAddrEncode bchTest 0 hash20
        `shouldBe` Just "bchtest:qpm2qsznhks23z7629mms6s4cwef74vcwvqcw003ap"
      cashAddrEncode bchRegTest 0 hash20
        `shouldBe` Just "bchreg:qpm2qsznhks23z7629mms6s4cwef74vcwv6ycwvz78"
    it "rejects a type above 15" $
      cashAddrEncode bch 16 hash20 `shouldBe` Nothing
    it "rejects a hash with a length the standard does not allow" $
      cashAddrEncode bch 0 (B.replicate 21 1) `shouldBe` Nothing
    it "has no result on a network without CashAddr" $
      cashAddrEncode btc 0 hash20 `shouldBe` Nothing
  describe "cash32 low level" $ do
    it "cash32encode writes the prefix, the data and the checksum" $ do
      cash32encode "prefix" "" `shouldBe` "prefix:x64nx6hz"
      cash32encode "bitcoincash" (B.cons 0 hash20)
        `shouldBe` "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
    it "cash32decode needs a prefix" $ do
      cash32decode "x64nx6hz" `shouldBe` Nothing
      cash32decode ":x64nx6hz" `shouldBe` Nothing
    it "cash32decode rejects mixed case" $
      cash32decode "Prefix:x64nx6hz" `shouldBe` Nothing
    it "cash32decode rejects a non-ASCII prefix" $
      cash32decode "pr\x00e9fix:x64nx6hz" `shouldBe` Nothing
    it "cash32decode rejects data shorter than a checksum" $
      cash32decode "prefix:x64nx6h" `shouldBe` Nothing
    it "cash32encodeType and cash32decodeType carry the type and the length" $ do
      cash32encodeType "pref" 1 hashF5
        `shouldBe` Just "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5"
      cash32decodeType "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5"
        `shouldBe` Just ("pref", 1, hashF5)
    it "cash32encodeType rejects a length the standard does not allow" $
      cash32encodeType "pref" 1 (B.replicate 21 1) `shouldBe` Nothing
    it "cash32decodeType rejects mixed case" $
      cash32decodeType "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtkS5" `shouldBe` Nothing
  describe "version byte" $ do
    it "decodeVersionByte splits the type and the hash size" $ do
      -- type in the high four bits, size code in the low three bits
      decodeVersionByte 0 `shouldBe` Just (0, 20)
      decodeVersionByte 11 `shouldBe` Just (1, 32)
      decodeVersionByte 16 `shouldBe` Just (2, 20)
      decodeVersionByte 127 `shouldBe` Just (15, 64)
    it "decodeVersionByte rejects a set high bit" $
      decodeVersionByte 128 `shouldBe` Nothing
    it "encodeVersionByte packs the type and the hash size" $ do
      encodeVersionByte 0 20 `shouldBe` Just 0
      encodeVersionByte 1 32 `shouldBe` Just 11
      encodeVersionByte 15 64 `shouldBe` Just 127
    it "encodeVersionByte rejects a type above 15" $
      encodeVersionByte 16 20 `shouldBe` Nothing
    it "encodeVersionByte rejects a hash size the standard does not allow" $
      encodeVersionByte 0 21 `shouldBe` Nothing

{- Fixtures -}

-- | HASH160 behind the Bitcoin Cash translation vectors above.
hash20 :: ByteString
hash20 = fromJust $ decodeHex "76a04053bda0a88bda5177b86a15c3b29f559873"

-- | SHA256 behind the BIP-173 P2WSH vector.
hash32 :: ByteString
hash32 = fromJust $ decodeHex "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"

-- | Hash from the CashAddr specification vectors.
hashF5 :: ByteString
hashF5 = fromJust $ decodeHex "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"

{- Various utilities -}

testCashAddr :: (Int, CashVersion, Cash32, Text) -> Assertion
testCashAddr (len, typ, addr, hex) = do
  let mbs = decodeHex hex
  assertBool "Could not decode hex payload from test vector" (isJust mbs)
  let mlow = cash32decode addr
  assertBool "Could not decode low level address" (isJust mlow)
  let Just (_, lbs) = mlow
  assertEqual "Low-level payload size incorrect" len (Char8.length lbs - 1)
  assertEqual "Low-level payload doesn't match" bs (Char8.tail lbs)
  let mdec = cash32decodeType addr
  assertBool ("Could not decode test address: " <> cs addr) (isJust mdec)
  assertEqual "Length doesn't match" len (Char8.length pay)
  assertEqual "Version doesn't match" typ ver
  assertEqual "Payload doesn't match" bs pay
  where
    Just bs = decodeHex hex
    Just (_, ver, pay) = cash32decodeType addr

-- | All vectors starting with @pref@ had the wrong version in the spec
-- document.
vectors :: [(Int, CashVersion, Text, Text)]
vectors =
  [ ( 20,
      0,
      "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
      "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"
    ),
    ( 20,
      1,
      "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",
      "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"
    ),
    ( 20,
      1,
      "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5",
      "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"
    ),
    ( 20,
      15,
      "prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf",
      "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"
    ),
    ( 24,
      0,
      "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0",
      "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"
    ),
    ( 24,
      1,
      "bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr",
      "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"
    ),
    ( 24,
      1,
      "pref:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2khlwwk5v",
      "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"
    ),
    ( 24,
      15,
      "prefix:09adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2p29kc2lp",
      "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"
    ),
    ( 28,
      0,
      "bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz",
      "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"
    ),
    ( 28,
      1,
      "bchtest:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcvs7md7wt",
      "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"
    ),
    ( 28,
      1,
      "pref:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcrsr6gzkn",
      "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"
    ),
    ( 28,
      15,
      "prefix:0gagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkc5djw8s9g",
      "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"
    ),
    ( 32,
      0,
      "bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake",
      "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"
    ),
    ( 32,
      1,
      "bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6",
      "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"
    ),
    ( 32,
      1,
      "pref:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq4k9m7qf9",
      "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"
    ),
    ( 32,
      15,
      "prefix:0vch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxqsh6jgp6w",
      "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"
    ),
    ( 40,
      0,
      "bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz",
      "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"
    ),
    ( 40,
      1,
      "bchtest:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm6ynej",
      "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"
    ),
    ( 40,
      1,
      "pref:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv0vx5z0w3",
      "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"
    ),
    ( 40,
      15,
      "prefix:0nq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvwsvctzqy",
      "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"
    ),
    ( 48,
      0,
      "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl",
      "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"
    ),
    ( 48,
      1,
      "bchtest:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqnzf7mt6x",
      "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"
    ),
    ( 48,
      1,
      "pref:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqjntdfcwg",
      "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"
    ),
    ( 48,
      15,
      "prefix:0h3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqakcssnmn",
      "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"
    ),
    ( 56,
      0,
      "bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f",
      "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"
    ),
    ( 56,
      1,
      "bchtest:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqs6kgdsg2g",
      "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"
    ),
    ( 56,
      1,
      "pref:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsammyqffl",
      "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"
    ),
    ( 56,
      15,
      "prefix:0mvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsgjrqpnw8",
      "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"
    ),
    ( 64,
      0,
      "bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w",
      "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"
    ),
    ( 64,
      1,
      "bchtest:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mc773cwez",
      "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"
    ),
    ( 64,
      1,
      "pref:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mg7pj3lh8",
      "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"
    ),
    ( 64,
      15,
      "prefix:0lg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96ms92w6845",
      "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"
    )
  ]
