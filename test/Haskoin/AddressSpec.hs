{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.AddressSpec (spec) where

import Control.DeepSeq (force)
import Control.Exception (evaluate)
import Control.Monad
import Data.Aeson (Value (String))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get (runGetS)
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (deserialize, serialize)
import Data.Default (def)
import Data.Either (isLeft)
import Data.Maybe (fromJust, isJust)
import Data.Text (Text)
import Data.Text qualified as T
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Util
import Haskoin.Util.Arbitrary
import System.Timeout (timeout)
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
  describe "Base58" $ do
    it "decodes digits by their position in the alphabet" $
      -- 2 is digit 1 and 1 is digit 0, so 1 × 58 + 0 = 58
      decodeBase58 "21" `shouldBe` Just (B.pack [58])
    it "rejects a character outside the alphabet" $
      decodeBase58 "0" `shouldBe` Nothing
    it "rejects a non-ASCII character whose code point ends in a digit byte" $
      -- U+0131 is 0x131. Its low byte 0x31 is the digit 1.
      decodeBase58 "2\x0131" `shouldBe` Nothing
    it "rejects a checked string shorter than a checksum" $
      decodeBase58Check "1" `shouldBe` Nothing
  describe "Smart constructors" $ do
    it "witnessAddress builds a P2WPKH address from version 0 and 20 bytes" $
      witnessAddress 0 hash20Bytes `shouldBe` Just (WitnessPubKeyAddress hash20)
    it "witnessAddress builds a P2WSH address from version 0 and 32 bytes" $
      witnessAddress 0 hash32Bytes `shouldBe` Just (WitnessScriptAddress hash32)
    it "witnessAddress rejects version 0 with another program length" $
      witnessAddress 0 (B.replicate 21 1) `shouldBe` Nothing
    it "witnessAddress keeps version 1 with 32 bytes as a Taproot address" $ do
      let Just a = witnessAddress 1 hash32Bytes
      isWitnessAddress a `shouldBe` True
      addressVersion a `shouldBe` 1
      addressBytes a `shouldBe` hash32Bytes
    it "witnessAddress rejects a version above 16" $
      witnessAddress 17 hash32Bytes `shouldBe` Nothing
    it "witnessAddress rejects a program shorter than 2 bytes" $
      witnessAddress 1 (B.pack [1]) `shouldBe` Nothing
    it "witnessAddress rejects a program longer than 40 bytes" $
      witnessAddress 1 (B.replicate 41 1) `shouldBe` Nothing
    it "cashAddress builds a P2PKH address from type 0 and 20 bytes" $
      cashAddress 0 hash20Bytes `shouldBe` Just (PubKeyAddress hash20)
    it "cashAddress builds a P2SH address from type 1 and 20 bytes" $
      cashAddress 1 hash20Bytes `shouldBe` Just (ScriptAddress hash20)
    it "cashAddress builds a P2SH32 address from type 1 and 32 bytes" $
      cashAddress 1 hash32Bytes `shouldBe` Just (Script32Address hash32)
    it "cashAddress keeps a token-aware address as a generic CashAddr" $ do
      let Just a = cashAddress 2 hash20Bytes
      isCashAddress a `shouldBe` True
      addressVersion a `shouldBe` 2
      addressBytes a `shouldBe` hash20Bytes
    it "cashAddress rejects a type above 15" $
      cashAddress 16 hash20Bytes `shouldBe` Nothing
    it "cashAddress rejects a hash length the standard does not allow" $
      cashAddress 0 (B.replicate 21 1) `shouldBe` Nothing
  describe "Address predicates" $
    it "each predicate is true only for its own kind of address" $
      forM_ predicateTable $ \(name, a, kind) ->
        assertEqual name [k == kind | k <- [0 .. 6]] (map ($ a) predicates)
  describe "Address accessors" $ do
    it "addressHash160 gives the hash of every address paying to a 160-bit hash" $ do
      addressHash160 p2pkh `shouldBe` Just hash20
      addressHash160 p2sh `shouldBe` Just hash20
      addressHash160 p2wpkh `shouldBe` Just hash20
      addressHash160 tokenP2pkh `shouldBe` Just hash20
      addressHash160 tokenP2sh `shouldBe` Just hash20
    it "addressHash160 gives nothing for other kinds" $ do
      addressHash160 p2wsh `shouldBe` Nothing
      addressHash160 p2tr `shouldBe` Nothing
      addressHash160 cash15 `shouldBe` Nothing
    it "addressHash256 gives the hash of every address paying to a 256-bit hash" $ do
      addressHash256 p2wsh `shouldBe` Just hash32
      addressHash256 p2sh32 `shouldBe` Just hash32
      addressHash256 tokenP2sh32 `shouldBe` Just hash32
    it "addressHash256 gives nothing for other kinds" $ do
      addressHash256 p2pkh `shouldBe` Nothing
      addressHash256 p2tr `shouldBe` Nothing
    it "addressVersion is the witness version of SegWit kinds" $ do
      addressVersion p2wpkh `shouldBe` 0
      addressVersion p2wsh `shouldBe` 0
      addressVersion p2tr `shouldBe` 1
      addressVersion witness16 `shouldBe` 16
    it "addressVersion is the CashAddr type of other kinds" $ do
      addressVersion p2pkh `shouldBe` 0
      addressVersion p2sh `shouldBe` 1
      addressVersion p2sh32 `shouldBe` 1
      addressVersion tokenP2pkh `shouldBe` 2
      addressVersion tokenP2sh `shouldBe` 3
      addressVersion cash15 `shouldBe` 15
    it "addressBytes is the raw hash or program without any prefix" $ do
      addressBytes p2pkh `shouldBe` hash20Bytes
      addressBytes p2sh `shouldBe` hash20Bytes
      addressBytes p2wpkh `shouldBe` hash20Bytes
      addressBytes p2wsh `shouldBe` hash32Bytes
      addressBytes p2sh32 `shouldBe` hash32Bytes
      addressBytes p2tr `shouldBe` hash32Bytes
      addressBytes witness16 `shouldBe` B.pack [1 .. 40]
      addressBytes tokenP2pkh `shouldBe` hash20Bytes
      addressBytes cash15 `shouldBe` B.pack [1 .. 24]
  describe "addrToText" $ do
    it "encodes every address kind on every network" $
      forM_ textTable $ \(net, a, txt) ->
        assertEqual (net.name <> " " <> T.unpack txt) (Just txt) (addrToText net a)
    it "uses the testnet prefixes on every test and regression network" $ do
      addrToText btcTest4 p2pkh `shouldBe` Just "mrLC19Je2BuWQDkWSTriGYPyQJXKkkBmCx"
      addrToText btcRegTest p2sh `shouldBe` Just "2N44ThNe8NXHyv4bsX8AoVCXquBRW94Ls7W"
      addrToText btcTest4 p2wpkh `shouldBe` Just "tb1qw6syq5aa5z5ghkj3w7ux59wrk204txrn0swsqg"
      addrToText btcRegTest p2wpkh `shouldBe` Just "bcrt1qw6syq5aa5z5ghkj3w7ux59wrk204txrndehahp"
      addrToText bchTest4 p2pkh `shouldBe` Just "bchtest:qpm2qsznhks23z7629mms6s4cwef74vcwvqcw003ap"
      addrToText bchRegTest p2pkh `shouldBe` Just "bchreg:qpm2qsznhks23z7629mms6s4cwef74vcwv6ycwvz78"
    it "has no text for a SegWit address on a Bitcoin Cash network" $ do
      addrToText bch p2wpkh `shouldBe` Nothing
      addrToText bch p2wsh `shouldBe` Nothing
      addrToText bch p2tr `shouldBe` Nothing
    it "has no text for P2SH32 or a CashAddr kind on a Bitcoin network" $ do
      addrToText btc p2sh32 `shouldBe` Nothing
      addrToText btc tokenP2pkh `shouldBe` Nothing
      addrToText btc cash15 `shouldBe` Nothing
  describe "addrToBase58, addrToBech32 and addrToCash" $ do
    it "addrToBase58 gives the legacy form of a Bitcoin Cash address" $ do
      addrToBase58 bch p2pkh `shouldBe` Just "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"
      addrToBase58 bch p2sh `shouldBe` Just "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC"
      addrToBase58 bchTest p2sh `shouldBe` Just "2N44ThNe8NXHyv4bsX8AoVCXquBRW94Ls7W"
    it "addrToBase58 has no form for other kinds" $ do
      addrToBase58 btc p2wpkh `shouldBe` Nothing
      addrToBase58 bch p2sh32 `shouldBe` Nothing
      addrToBase58 bch tokenP2pkh `shouldBe` Nothing
    it "addrToBech32 encodes SegWit kinds on SegWit networks only" $ do
      addrToBech32 btc p2wpkh `shouldBe` Just "bc1qw6syq5aa5z5ghkj3w7ux59wrk204txrn9k4rmm"
      addrToBech32 btc p2pkh `shouldBe` Nothing
      addrToBech32 bch p2wpkh `shouldBe` Nothing
    it "addrToCash encodes on Bitcoin Cash networks only" $ do
      addrToCash bch p2pkh `shouldBe` Just "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
      addrToCash btc p2pkh `shouldBe` Nothing
      addrToCash bch p2wpkh `shouldBe` Nothing
  describe "textToAddr" $ do
    it "decodes every form that addrToText encodes" $
      forM_ textTable $ \(net, a, txt) ->
        assertEqual (net.name <> " " <> T.unpack txt) (Just a) (textToAddr net txt)
    it "accepts a CashAddr without prefix" $
      textToAddr bch "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a" `shouldBe` Just p2pkh
    it "accepts a CashAddr in all uppercase" $
      textToAddr bch "BITCOINCASH:QPM2QSZNHKS23Z7629MMS6S4CWEF74VCWVY22GDX6A" `shouldBe` Just p2pkh
    it "accepts a Bech32 address in all uppercase" $
      textToAddr btc "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
        `shouldBe` Just (WitnessPubKeyAddress "751e76e8199196d454941c45d1b3a323f1433bd6")
    it "accepts a legacy Base58 address on a Bitcoin Cash network" $
      textToAddr bch "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu" `shouldBe` Just p2pkh
    it "rejects a CashAddr with a mixed case prefix" $
      textToAddr bch "BitcoinCash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a" `shouldBe` Nothing
    it "rejects a CashAddr with mixed case data" $
      textToAddr bch "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdX6A" `shouldBe` Nothing
    it "rejects a Bech32 address with mixed case" $
      textToAddr btcTest "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7" `shouldBe` Nothing
    it "rejects a CashAddr whose padding bits are not zero" $
      textToAddr bch "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcw0c0g40rx7" `shouldBe` Nothing
    it "rejects a CashAddr with an extra zero group" $
      textToAddr bch "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvq5xhgekz9" `shouldBe` Nothing
    it "rejects a Bech32 address whose padding bits are not zero" $
      textToAddr btc "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf308468nf" `shouldBe` Nothing
    it "rejects a Bech32 address with an extra zero group" $
      textToAddr btc "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qqnuhcm0" `shouldBe` Nothing
    it "rejects a Base58 address with a non-ASCII look-alike character" $
      -- U+0141 in place of A
      textToAddr btc "1BpEi6DfD\x0141UFd7GtittLSdBeYJvcoaVggu" `shouldBe` Nothing
    it "rejects a Bech32 address with a non-ASCII look-alike character" $
      -- U+017F in place of s
      textToAddr btcTest "tb1qrp33g0q5c5tx\x017Fp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7" `shouldBe` Nothing
    it "rejects a CashAddr with a non-ASCII look-alike character" $
      -- U+212A in place of K
      textToAddr bch "BITCOINCASH:QPM2QSZNH\x212AS23Z7629MMS6S4CWEF74VCWVY22GDX6A" `shouldBe` Nothing
    it "rejects an address of another network" $
      forM_ otherNetworkTable $ \(net, txt) ->
        assertEqual (net.name <> " " <> T.unpack txt) Nothing (textToAddr net txt)
    it "rejects a Base58 address with a bad checksum" $
      textToAddr btc "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggv" `shouldBe` Nothing
    it "rejects a Base58 payload that is not 21 bytes" $ do
      -- version byte, the hash and one extra byte
      textToAddr btc "1pjVWN2segoHYNh9Hv1ap6hzhC7eqEpz8oy" `shouldBe` Nothing
      -- version byte and 19 bytes of hash
      textToAddr btc "13T7H7AfZfPwWvz51tBGjWVhDz5TJEMr9" `shouldBe` Nothing
    it "rejects a Base58 version byte that is neither P2PKH nor P2SH" $
      -- version byte 1 and the hash
      textToAddr btc "b9qhCWwvLw8SYQykKDevkTSApBZZqXzeV" `shouldBe` Nothing
    it "rejects surrounding whitespace" $
      textToAddr btc " 1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu\n" `shouldBe` Nothing
    it "rejects a long string of Base58 characters without decoding it" $
      timeout 2000000 (evaluate (textToAddr btc (T.replicate 500000 "z")))
        `shouldReturn` Just Nothing
  describe "Addresses from public keys" $ do
    it "pubKeyAddr hashes a compressed key" $
      addrToText btc (pubKeyAddr ctx (compressedKey ctx))
        `shouldBe` Just "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    it "pubKeyAddr hashes an uncompressed key in its uncompressed form" $
      addrToText btc (pubKeyAddr ctx (uncompressedKey ctx))
        `shouldBe` Just "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
    it "pubKeyWitnessAddr gives the P2WPKH address of a compressed key" $
      (addrToText btc =<< pubKeyWitnessAddr ctx (compressedKey ctx))
        `shouldBe` Just "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    it "pubKeyWitnessAddr refuses an uncompressed key" $
      pubKeyWitnessAddr ctx (uncompressedKey ctx) `shouldBe` Nothing
    it "pubKeyCompatWitnessAddr gives the P2SH-P2WPKH address of a compressed key" $
      (addrToText btc =<< pubKeyCompatWitnessAddr ctx (compressedKey ctx))
        `shouldBe` Just "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
    it "pubKeyCompatWitnessAddr refuses an uncompressed key" $
      pubKeyCompatWitnessAddr ctx (uncompressedKey ctx) `shouldBe` Nothing
    it "p2pkhAddr, p2shAddr, p2wpkhAddr and p2wshAddr wrap a hash" $ do
      addrToText btc (p2pkhAddr hash20) `shouldBe` Just "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"
      addrToText btc (p2shAddr hash20) `shouldBe` Just "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC"
      addrToText btc (p2wpkhAddr hash20) `shouldBe` Just "bc1qw6syq5aa5z5ghkj3w7ux59wrk204txrn9k4rmm"
      addrToText btc (p2wshAddr hash32) `shouldBe` Just "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
  describe "Addresses from scripts" $ do
    it "payToScriptAddress hashes the output script with HASH160" $
      addrToText btc (payToScriptAddress ctx (multisig ctx))
        `shouldBe` Just "38fEX6RbBBMmpu3nbbuULku1xyrrzqqqnE"
    it "payToWitnessScriptAddress hashes the output script with SHA256" $
      addrToText btc (payToWitnessScriptAddress ctx (multisig ctx))
        `shouldBe` Just "bc1qd6e6c86xp56gw8pty8suuqhscpttea2c5m2fggzjkxzk5nl9faks5pehxu"
    it "payToNestedScriptAddress wraps the P2WSH script in P2SH" $
      addrToText btc (payToNestedScriptAddress ctx (multisig ctx))
        `shouldBe` Just "3JSuZ22mPR2aD5bf77KsGi36V5ar3p87LX"
  describe "addressToOutput, addressToScript and addressToScriptBS" $ do
    it "builds the locking script of every address kind" $
      forM_ scriptTable $ \(a, hex) ->
        assertEqual (T.unpack hex) (Just hex) (encodeHex <$> addressToScriptBS ctx a)
    it "pays a token-aware P2PKH address with the plain P2PKH script" $
      (encodeHex <$> addressToScriptBS ctx tokenP2pkh)
        `shouldBe` Just "76a91476a04053bda0a88bda5177b86a15c3b29f55987388ac"
    it "pays a token-aware P2SH address with the plain P2SH script" $
      (encodeHex <$> addressToScriptBS ctx tokenP2sh)
        `shouldBe` Just "a91476a04053bda0a88bda5177b86a15c3b29f55987387"
    it "pays a token-aware P2SH32 address with the plain P2SH32 script" $
      (encodeHex <$> addressToScriptBS ctx tokenP2sh32)
        `shouldBe` Just "aa201863143c14c5166804bd19203356da136c985678cd4d27a1b8c632960490326287"
    it "has no script for a CashAddr type with no known script" $ do
      addressToOutput cash15 `shouldBe` Nothing
      addressToOutput (fromJust (cashAddress 0 hash32Bytes)) `shouldBe` Nothing
      addressToOutput (fromJust (cashAddress 2 hash32Bytes)) `shouldBe` Nothing
    it "addressToOutput gives the matching ScriptOutput" $ do
      addressToOutput p2pkh `shouldBe` Just (PayPKHash hash20)
      addressToOutput p2wsh `shouldBe` Just (PayWitnessScriptHash hash32)
      addressToOutput p2tr `shouldBe` Just (PayWitness 1 hash32Bytes)
      addressToOutput tokenP2sh32 `shouldBe` Just (PayScript32Hash hash32)
    it "addressToScript gives the script AST" $
      ((.ops) <$> addressToScript ctx p2sh)
        `shouldBe` Just [OP_HASH160, OP_PUSHDATA hash20Bytes OPCODE, OP_EQUAL]
  describe "outputAddress, scriptToAddress and scriptToAddressBS" $ do
    it "recovers the address of every standard locking script" $
      forM_ scriptTable $ \(a, hex) ->
        assertEqual (T.unpack hex) (Right a) (scriptToAddressBS ctx (fromJust (decodeHex hex)))
    it "scriptToAddress works on the script AST" $
      (scriptToAddress ctx =<< runGetS deserialize (fromJust (decodeHex "76a91476a04053bda0a88bda5177b86a15c3b29f55987388ac")))
        `shouldBe` Right p2pkh
    it "has no address for a pay-to-public-key script" $
      scriptToAddressBS ctx (fromJust (decodeHex p2pkScript))
        `shouldBe` Left "Could not decode address"
    it "has no address for a bare multisig script" $
      scriptToAddressBS ctx (fromJust (decodeHex multisigScript))
        `shouldBe` Left "Could not decode address"
    it "has no address for a data carrier script" $
      scriptToAddressBS ctx (fromJust (decodeHex "6a04deadbeef"))
        `shouldBe` Left "Could not decode address"
    it "fails on a script that is not standard" $
      scriptToAddressBS ctx (fromJust (decodeHex "51")) `shouldSatisfy` isLeft
    it "outputAddress has no address for a pay-to-public-key output" $
      outputAddress ctx (PayPK (compressedKey ctx)) `shouldBe` Nothing
  describe "inputAddress" $ do
    it "gives the P2PKH address of the key in a public key hash input" $
      (addrToText btc =<< inputAddress ctx (RegularInput (SpendPKHash TxSignatureEmpty (compressedKey ctx))))
        `shouldBe` Just "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    it "gives the P2SH address of the redeem script in a script hash input" $
      (addrToText btc =<< inputAddress ctx (ScriptHashInput (SpendMulSig [TxSignatureEmpty]) (multisig ctx)))
        `shouldBe` Just "38fEX6RbBBMmpu3nbbuULku1xyrrzqqqnE"
    it "gives the P2SH address of the wrapped program in a nested witness input" $
      -- The P2SH-P2WPKH example of BIP 143: redeem script 0014 79091972…,
      -- script hash 4733f37cf4db86fbc2efed2500b4f4e49f312023.
      (addrToText btc =<< inputAddress ctx (NestedWitnessInput (PayWitnessPKHash "79091972186c449eb1ded22b78e40d009bdf0089")))
        `shouldBe` Just "38BW8nqpHSWpkf5sXrQd2xYwvnPJwP59ic"
    it "has no address for a pay-to-public-key input" $
      inputAddress ctx (RegularInput (SpendPK TxSignatureEmpty)) `shouldBe` Nothing
    it "has no address for a bare multisig input" $
      inputAddress ctx (RegularInput (SpendMulSig [TxSignatureEmpty])) `shouldBe` Nothing
  describe "Binary serialization" $ do
    it "writes a P2PKH address as a type byte and the hash" $
      encodeHex (runPutS (serialize p2pkh))
        `shouldBe` "0076a04053bda0a88bda5177b86a15c3b29f559873"
    it "writes a Taproot address as a type byte, the version and the sized program" $
      encodeHex (runPutS (serialize p2tr))
        `shouldBe` "0401" <> "0000000000000020" <> "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
    it "writes a token-aware address as a type byte, the CashAddr type and the sized hash" $
      encodeHex (runPutS (serialize tokenP2pkh))
        `shouldBe` "0602" <> "0000000000000014" <> "76a04053bda0a88bda5177b86a15c3b29f559873"
    it "rejects an unknown type byte" $
      deserializeAddress "0776a04053bda0a88bda5177b86a15c3b29f559873" `shouldSatisfy` isLeft
    it "rejects a witness version above 16" $
      deserializeAddress ("0411" <> "0000000000000002" <> "0102") `shouldSatisfy` isLeft
    it "rejects a witness program longer than 40 bytes" $
      deserializeAddress ("0401" <> "0000000000000029" <> T.replicate 41 "01") `shouldSatisfy` isLeft
    it "rejects a sized payload whose length does not fit in memory" $
      deserializeAddress ("0401" <> "ffffffffffffffff" <> "0102") `shouldSatisfy` isLeft
    it "reads a version 0 witness program as the P2WPKH constructor" $
      deserializeAddress ("0400" <> "0000000000000014" <> "76a04053bda0a88bda5177b86a15c3b29f559873")
        `shouldBe` Right (WitnessPubKeyAddress hash20)
    it "reads a CashAddr of type 0 with 20 bytes as the P2PKH constructor" $
      deserializeAddress ("0600" <> "0000000000000014" <> "76a04053bda0a88bda5177b86a15c3b29f559873")
        `shouldBe` Right (PubKeyAddress hash20)
    it "rejects a CashAddr with a hash size the standard does not allow" $
      deserializeAddress ("0602" <> "0000000000000015" <> T.replicate 21 "01") `shouldSatisfy` isLeft
  describe "JSON" $ do
    it "encodes an address as its text form" $ do
      marshalValue btc p2pkh `shouldBe` String "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"
      marshalJSON btc p2pkh `shouldBe` "\"1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu\""
      marshalJSON bch tokenP2pkh `shouldBe` "\"bitcoincash:zpm2qsznhks23z7629mms6s4cwef74vcwvrqekrq9w\""
    it "decodes the text form" $
      unmarshalJSON btc "\"1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu\"" `shouldBe` Just p2pkh
    it "rejects text that is not an address" $ do
      unmarshalJSON btc "\"hello\"" `shouldBe` (Nothing :: Maybe Address)
      unmarshalJSON btc "null" `shouldBe` (Nothing :: Maybe Address)
    it "fails loudly instead of writing null when the address has no text form" $ do
      evaluate (force (marshalValue bch p2wpkh)) `shouldThrow` anyErrorCall
      evaluate (force (marshalJSON btc p2sh32)) `shouldThrow` anyErrorCall

{- Fixtures -}

-- | HASH160 behind the CashAddr translation vectors.
hash20 :: Hash160
hash20 = "76a04053bda0a88bda5177b86a15c3b29f559873"

hash20Bytes :: ByteString
hash20Bytes = fromJust $ decodeHex "76a04053bda0a88bda5177b86a15c3b29f559873"

-- | SHA256 behind the BIP-173 P2WSH vector.
hash32 :: Hash256
hash32 = "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"

hash32Bytes :: ByteString
hash32Bytes = fromJust $ decodeHex "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"

p2pkh, p2sh, p2wpkh, p2wsh, p2sh32, p2tr, witness16 :: Address
p2pkh = pubKeyAddress hash20
p2sh = scriptAddress hash20
p2wpkh = witnessPubKeyAddress hash20
p2wsh = witnessScriptAddress hash32
p2sh32 = script32Address hash32
p2tr = fromJust $ witnessAddress 1 hash32Bytes
witness16 = fromJust $ witnessAddress 16 (B.pack [1 .. 40])

tokenP2pkh, tokenP2sh, tokenP2sh32, cash15 :: Address
tokenP2pkh = fromJust $ cashAddress 2 hash20Bytes
tokenP2sh = fromJust $ cashAddress 3 hash20Bytes
tokenP2sh32 = fromJust $ cashAddress 3 hash32Bytes
cash15 = fromJust $ cashAddress 15 (B.pack [1 .. 24])

predicates :: [Address -> Bool]
predicates =
  [ isPubKeyAddress,
    isScriptAddress,
    isWitnessPubKeyAddress,
    isWitnessScriptAddress,
    isWitnessAddress,
    isScript32Address,
    isCashAddress
  ]

-- | Each address with the index of the only predicate that holds for it.
predicateTable :: [(String, Address, Int)]
predicateTable =
  [ ("P2PKH", p2pkh, 0),
    ("P2SH", p2sh, 1),
    ("P2WPKH", p2wpkh, 2),
    ("P2WSH", p2wsh, 3),
    ("P2TR", p2tr, 4),
    ("P2SH32", p2sh32, 5),
    ("token-aware P2PKH", tokenP2pkh, 6)
  ]

-- | Text form of every address kind on the main networks.
textTable :: [(Network, Address, Text)]
textTable =
  [ (btc, p2pkh, "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"),
    (btc, p2sh, "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC"),
    (btc, p2wpkh, "bc1qw6syq5aa5z5ghkj3w7ux59wrk204txrn9k4rmm"),
    (btc, p2wsh, "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"),
    (btc, p2tr, "bc1prp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qj0fj5d"),
    (btc, witness16, "bc1sqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ruszzg3rysjjvfeg7dt0md"),
    (btcTest, p2pkh, "mrLC19Je2BuWQDkWSTriGYPyQJXKkkBmCx"),
    (btcTest, p2sh, "2N44ThNe8NXHyv4bsX8AoVCXquBRW94Ls7W"),
    (btcTest, p2wpkh, "tb1qw6syq5aa5z5ghkj3w7ux59wrk204txrn0swsqg"),
    (btcTest, p2wsh, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"),
    (btcTest, p2tr, "tb1prp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q98lawz"),
    (bch, p2pkh, "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
    (bch, p2sh, "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"),
    (bch, p2sh32, "bitcoincash:pvvxx9puznz3v6qyh5vjqv6kmgfkexzk0rx56faphrrr99syjqexyrusee847"),
    (bch, tokenP2pkh, "bitcoincash:zpm2qsznhks23z7629mms6s4cwef74vcwvrqekrq9w"),
    (bch, tokenP2sh, "bitcoincash:rpm2qsznhks23z7629mms6s4cwef74vcwv59yeyr7n"),
    (bch, tokenP2sh32, "bitcoincash:rvvxx9puznz3v6qyh5vjqv6kmgfkexzk0rx56faphrrr99syjqexy30vcqxv4"),
    (bch, cash15, "bitcoincash:0yqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9cc7akt68km"),
    (bchTest, p2pkh, "bchtest:qpm2qsznhks23z7629mms6s4cwef74vcwvqcw003ap"),
    (bchTest, p2sh, "bchtest:ppm2qsznhks23z7629mms6s4cwef74vcwvhanqgjxu")
  ]

-- | Valid addresses of one network that another network must reject.
otherNetworkTable :: [(Network, Text)]
otherNetworkTable =
  [ (btc, "mrLC19Je2BuWQDkWSTriGYPyQJXKkkBmCx"),
    (btc, "tb1qw6syq5aa5z5ghkj3w7ux59wrk204txrn0swsqg"),
    (btc, "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
    (btc, "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
    (btcTest, "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"),
    (btcTest, "bc1qw6syq5aa5z5ghkj3w7ux59wrk204txrn9k4rmm"),
    (btcRegTest, "tb1qw6syq5aa5z5ghkj3w7ux59wrk204txrn0swsqg"),
    (bch, "bc1qw6syq5aa5z5ghkj3w7ux59wrk204txrn9k4rmm"),
    (bch, "bchtest:qpm2qsznhks23z7629mms6s4cwef74vcwvqcw003ap"),
    (bch, "qpm2qsznhks23z7629mms6s4cwef74vcwvqcw003ap"),
    (bchTest, "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a")
  ]

-- | Locking script of every address kind that has one.
scriptTable :: [(Address, Text)]
scriptTable =
  [ (p2pkh, "76a91476a04053bda0a88bda5177b86a15c3b29f55987388ac"),
    (p2sh, "a91476a04053bda0a88bda5177b86a15c3b29f55987387"),
    (p2sh32, "aa201863143c14c5166804bd19203356da136c985678cd4d27a1b8c632960490326287"),
    (p2wpkh, "001476a04053bda0a88bda5177b86a15c3b29f559873"),
    (p2wsh, "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
    (p2tr, "51201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
    (witness16, "6028" <> "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728")
  ]

-- | Public key of private key 1, in both forms.
compressedKey, uncompressedKey :: Ctx -> PublicKey
compressedKey ctx =
  derivePublicKey ctx . fromJust $
    fromWif btc "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
uncompressedKey ctx =
  derivePublicKey ctx . fromJust $
    fromWif btc "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"

-- | Public key of private key 2.
secondKey :: Ctx -> PublicKey
secondKey ctx =
  either error id . unmarshal ctx . fromJust $
    decodeHex "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

-- | 1-of-2 multisig of the keys of private keys 1 and 2.
multisig :: Ctx -> ScriptOutput
multisig ctx = PayMulSig [compressedKey ctx, secondKey ctx] 1

multisigScript :: Text
multisigScript =
  "5121"
    <> "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    <> "21"
    <> "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    <> "52ae"

-- | Pay to the public key of private key 1.
p2pkScript :: Text
p2pkScript = "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"

deserializeAddress :: Text -> Either String Address
deserializeAddress = runGetS deserialize . fromJust . decodeHex

{- Vectors -}

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
  let addrM = addrToText btcTest =<< pubKeyCompatWitnessAddr ctx pubkey
  assertBool "address can be encoded" (isJust addrM)
  assertEqual "witness address matches" addr (fromJust addrM)

compatWitnessVectors :: [(Network, Text, Text)]
compatWitnessVectors =
  [ ( btcTest,
      "cNUnpYpMsJXYCERYBciJnsWBpcYEFjdcbq6dxj4SskGhs7uHuJ7Q",
      "2N6PDTueBHvXzW61B4oe5SW1D3v2Z3Vpbvw"
    )
  ]
