{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- The vectors of the reference implementation live in
-- data/slip39_vectors.json, copied from
-- https://github.com/trezor/python-shamir-mnemonic/blob/master/vectors.json:
-- a description, the mnemonics, the master secret they give with the
-- passphrase "TREZOR" (empty when they must be refused) and the BIP-32 key
-- of that secret. The split cases in data/slip39_split.json were made by
-- test/Haskoin/Crypto/Keys/slip39_verify.py, an implementation of the
-- specification independent of this one: a scheme, the parameters and the
-- random values of a split, and the mnemonics they must give. The word list
-- in data/slip39_wordlist.txt is the file of the specification.
module Haskoin.Crypto.Keys.Slip39Spec (spec) where

import Control.Monad (forM_)
import Crypto.Hash (SHA256 (..), hashWith)
import Crypto.Random (drgNewTest, withDRG)
import Data.Aeson (FromJSON (..), withObject, (.:))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Char (ord)
import Data.List (nub, sort, subsequences)
import Data.Map.Strict qualified as M
import Data.Maybe (fromJust)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as E
import Data.Text.IO qualified as TIO
import Data.Vector qualified as V
import Haskoin (btc, makeXPrvKey, xPrvExport)
import Haskoin.Crypto.Keys.Slip39
import Haskoin.Util (decodeHex, encodeHex, readTestFile)
import Test.Hspec
import Test.QuickCheck

-- | A case of data/slip39_split.json.
data SplitCase = SplitCase
  { caseDescription :: Text,
    caseScheme :: Scheme,
    caseIdentifier :: Int,
    caseExtendable :: Bool,
    caseIterationExponent :: Int,
    casePassphrase :: Text,
    caseMasterSecret :: ByteString,
    caseRandom :: [SplitRandom],
    caseMnemonics :: [[Text]]
  }

instance FromJSON SplitCase where
  parseJSON = withObject "SplitCase" $ \o ->
    SplitCase
      <$> o .: "description"
      <*> (o .: "scheme" >>= withObject "Scheme" (\s -> Scheme <$> s .: "groupThreshold" <*> s .: "groups"))
      <*> o .: "identifier"
      <*> o .: "extendable"
      <*> o .: "iterationExponent"
      <*> o .: "passphrase"
      <*> (hex <$> o .: "masterSecret")
      <*> (o .: "random" >>= mapM (withObject "SplitRandom" (\r -> SplitRandom <$> (map hex <$> r .: "shares") <*> (hex <$> r .: "digest"))))
      <*> o .: "mnemonics"

hex :: Text -> ByteString
hex = fromJust . decodeHex

spec :: Spec
spec = do
  vectors <- runIO (readTestFile "slip39_vectors.json" :: IO [(Text, [Text], Text, Text)])
  splitCases <- runIO (readTestFile "slip39_split.json" :: IO [SplitCase])
  wordListFile <- runIO (TIO.readFile "data/slip39_wordlist.txt")
  describe "the word list" $ do
    it "has the 1024 words of the specification, academic to zero" $ do
      V.length slip39WordList `shouldBe` 1024
      V.head slip39WordList `shouldBe` "academic"
      V.last slip39WordList `shouldBe` "zero"
    it "is the published file, by its SHA-256" $
      -- sha256sum of slip-0039/wordlist.txt in the slips repository, one
      -- word per line with a newline after each
      show (hashWith SHA256 (E.encodeUtf8 (T.unlines (V.toList slip39WordList))))
        `shouldBe` "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"
    it "is the file in the data directory, word for word" $
      V.toList slip39WordList `shouldBe` T.lines wordListFile
    it "is sorted" $
      V.toList slip39WordList `shouldBe` sort (V.toList slip39WordList)
    it "has words of 4 to 8 letters" $
      forM_ slip39WordList $ \w -> T.length w `shouldSatisfy` (\n -> n >= 4 && n <= 8)
    it "has distinct first four letters" $
      length (nub (map (T.take 4) (V.toList slip39WordList))) `shouldBe` 1024
    it "gives each word its index" $ do
      M.lookup "academic" slip39WordListMap `shouldBe` Just 0
      M.lookup "satoshi" slip39WordListMap `shouldBe` Just 781
      M.lookup "zero" slip39WordListMap `shouldBe` Just 1023
      M.size slip39WordListMap `shouldBe` 1024
    it "reads the words of a mnemonic in any case" $
      mnemonicToIndices "Academic ZERO satoshi" `shouldBe` Right [0, 1023, 781]
    it "names a word that is not in the list" $
      mnemonicToIndices "academic abandon" `shouldBe` Left "The word \"abandon\" is not in the SLIP-39 word list"
    it "writes indices as words" $
      indicesToMnemonic [0, 781, 1023] `shouldBe` "academic satoshi zero"

  describe "the field GF(256)" $ do
    it "multiplies 0x57 by 0x83 to 0xc1, the example of FIPS 197" $
      gfMul 0x57 0x83 `shouldBe` 0xc1
    it "multiplies 0x57 by 0x13 to 0xfe, the other example of FIPS 197" $
      gfMul 0x57 0x13 `shouldBe` 0xfe
    it "multiplies 2 by 0x80 to 0x1b: 0x100 reduced by x^8 + x^4 + x^3 + x + 1" $
      gfMul 2 0x80 `shouldBe` 0x1b
    it "multiplies by zero to zero and by one to the byte itself" $ property $ \a ->
      (gfMul a 0, gfMul 0 a, gfMul a 1, gfMul 1 a) === (0, 0, a, a)
    it "commutes" $ property $ \a b ->
      gfMul a b === gfMul b a
    it "inverts 0x53 to 0xca, the example of the AES S-box" $ do
      gfInv 0x53 `shouldBe` Just 0xca
      gfMul 0x53 0xca `shouldBe` 1
    it "inverts 3, the generator, to 0xf6" $
      gfInv 3 `shouldBe` Just 0xf6
    it "has no inverse of zero" $ do
      gfInv 0 `shouldBe` Nothing
      gfDiv 1 0 `shouldBe` Nothing
    it "multiplies every non-zero byte by its inverse to one" $
      forM_ [1 .. 255] $ \a -> (gfMul a <$> gfInv a) `shouldBe` Just 1
    it "divides 0xc1 by 0x83 to 0x57" $
      gfDiv 0xc1 0x83 `shouldBe` Just 0x57

  describe "interpolation" $ do
    it "takes the line through (0, 0x00) and (1, 0x80) to (2, 0x1b)" $
      -- f(x) = 0x80 x, and 2 times 0x80 is 0x1b in the field
      interpolate 2 [(0, "\x00"), (1, "\x80")] `shouldBe` Right "\x1b"
    it "takes that line to (3, 0x9b)" $
      -- 3 times 0x80 is 0x180, reduced by 0x11b to 0x9b
      interpolate 3 [(0, "\x00"), (1, "\x80")] `shouldBe` Right "\x9b"
    it "takes the line through (1, 0x01) and (2, 0x03) to (0, 0xf6) and (3, 0xf4)" $ do
      -- the slope is (3 xor 1) / (2 xor 1) = 2 / 3 = 2 times 0xf6 = 0xf7, so
      -- f(0) = 1 xor 0xf7 = 0xf6 and f(3) = 0xf6 xor 3 times 0xf7 = 0xf6 xor 2
      interpolate 0 [(1, "\x01"), (2, "\x03")] `shouldBe` Right "\xf6"
      interpolate 3 [(1, "\x01"), (2, "\x03")] `shouldBe` Right "\xf4"
    it "interpolates each byte on its own" $
      -- the first byte as the line through 0x00 and 0x80, the second
      -- through 0x00 and 0x01: f(2) = 2
      interpolate 2 [(0, "\x00\x00"), (1, "\x80\x01")] `shouldBe` Right "\x1b\x02"
    it "gives the constant of a constant polynomial anywhere" $
      interpolate 200 [(5, B.pack [0 .. 15]), (9, B.pack [0 .. 15])] `shouldBe` Right (B.pack [0 .. 15])
    it "gives a point its own value" $
      interpolate 1 [(0, "\x00"), (1, "\x80")] `shouldBe` Right "\x80"
    it "refuses no points" $
      interpolate 1 [] `shouldBe` Left "There are no shares to interpolate"
    it "refuses two points at one index" $
      interpolate 2 [(1, "\x01"), (1, "\x03")] `shouldBe` Left "The shares do not have distinct indices"
    it "refuses values of different lengths" $
      interpolate 2 [(0, "\x01"), (1, "\x03\x04")] `shouldBe` Left "The shares do not have the same length"

  describe "the checksum" $ do
    -- The first vector: 17 data words then "critical decision keyboard"
    let vector1Words = [248, 288, 0, 0, 17, 753, 521, 840, 372, 497, 155, 670, 192, 448, 297, 249, 23]
    it "makes the three words critical decision keyboard for the first vector" $ do
      rs1024Checksum (customizationString False) vector1Words `shouldBe` [173, 196, 496]
      indicesToMnemonic [173, 196, 496] `shouldBe` "critical decision keyboard"
    it "verifies the first vector" $
      rs1024Verify (customizationString False) (vector1Words ++ [173, 196, 496]) `shouldBe` True
    it "fails when the last word changes to kidney" $
      rs1024Verify (customizationString False) (vector1Words ++ [173, 196, 497]) `shouldBe` False
    it "has a polymod of 1 for a valid mnemonic after its customization string" $
      rs1024Polymod (customizationString False ++ vector1Words ++ [173, 196, 496]) `shouldBe` 1
    it "feeds shamir or shamir_extendable to the polymod as ASCII" $ do
      customizationString False `shouldBe` map ord "shamir"
      customizationString True `shouldBe` map ord "shamir_extendable"
    it "verifies an extendable share under shamir_extendable only" $ do
      -- Vector 42, an extendable share
      let indices = indicesOf (mnemonicOf vectors 42)
      rs1024Verify (customizationString True) indices `shouldBe` True
      rs1024Verify (customizationString False) indices `shouldBe` False
    it "verifies every mnemonic of the valid vectors" $
      forM_ [(d, m) | (d, ms, s, _) <- vectors, s /= "", m <- ms] $ \(d, m) -> do
        let indices = indicesOf m
            -- the extendable flag is bit 24 of the 40-bit header, bit 4 of the second word
            ext = odd ((indices !! 1) `div` 16)
        (d, rs1024Verify (customizationString ext) indices) `shouldBe` (d, True)

  describe "share mnemonics" $ do
    it "decodes the share of the first vector" $
      decodeShare (mnemonicOf vectors 1) `shouldBe` Right vector1
    it "encodes it back to its 20 words" $
      encodeShare vector1 `shouldBe` Right (mnemonicOf vectors 1)
    it "decodes an extendable share with an iteration exponent of 3" $
      -- Vector 42
      decodeShare (mnemonicOf vectors 42)
        `shouldBe` Right (singleShare 29019 True 3 (hex "9e8773c7313b11d3bfe219291976433b"))
    it "decodes a share of 33 words as 32 bytes of value" $
      -- Vector 20
      decodeShare (mnemonicOf vectors 20)
        `shouldBe` Right (singleShare 29172 False 0 (hex "d772fee46424e100bec16d165f1fcc346d1e8d909da580f9f9f04ea5c788d212"))
    it "encodes a 32-byte value as 33 words and a 16-byte one as 20" $ do
      fmap (length . T.words) (encodeShare vector1) `shouldBe` Right 20
      fmap (length . T.words) (encodeShare vector1 {value = B.replicate 32 0}) `shouldBe` Right 33
    it "encodes a 20-byte value as 23 words, with no padding" $
      -- 160 bits is 16 words exactly
      fmap (length . T.words) (encodeShare vector1 {value = B.replicate 20 0}) `shouldBe` Right 23
    it "reads words in upper case" $
      decodeShare (T.toUpper (mnemonicOf vectors 1)) `shouldBe` Right vector1
    it "refuses 19 words" $
      -- Vector 39
      decodeShare (mnemonicOf vectors 39) `shouldBe` Left "The mnemonic has 19 words, but a share has at least 20"
    it "refuses 21 words, which would leave 12 bits of padding" $
      -- Vector 40
      decodeShare (mnemonicOf vectors 40) `shouldBe` Left "The mnemonic has 21 words, which is not a valid share length"
    it "refuses a wrong checksum" $
      -- Vector 2: the first vector with its last word changed
      decodeShare (mnemonicOf vectors 2) `shouldBe` Left "The checksum of the mnemonic is invalid"
    it "refuses padding bits that are not zero" $
      -- Vector 3
      decodeShare (mnemonicOf vectors 3) `shouldBe` Left "The padding bits of the share value are not zero"
    it "refuses a group threshold above the group count" $
      -- Vector 10, first share
      decodeShare (mnemonicOf vectors 10) `shouldBe` Left "The group threshold is greater than the group count"
    it "refuses a word that is not in the list" $
      decodeShare "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision abandon"
        `shouldBe` Left "The word \"abandon\" is not in the SLIP-39 word list"
    it "refuses to encode an identifier of 16 bits" $
      encodeShare (singleShare 32768 False 0 vector1.value) `shouldBe` Left "The identifier must be between 0 and 32767, not 32768"
    it "refuses to encode an iteration exponent of 16" $
      encodeShare (singleShare 7945 False 16 vector1.value) `shouldBe` Left "The iteration exponent must be between 0 and 15, not 16"
    it "refuses to encode a group index of 16" $
      encodeShare vector1 {groupIndex = 16} `shouldBe` Left "The group index must be between 0 and 15, not 16"
    it "refuses to encode a group threshold of 0" $
      encodeShare (groupShare 0 1 vector1.value) `shouldBe` Left "The group threshold must be between 1 and 16, not 0"
    it "refuses to encode a group count of 17" $
      encodeShare vector1 {groupCount = 17} `shouldBe` Left "The group count must be between 1 and 16, not 17"
    it "refuses to encode a group threshold above the group count" $
      encodeShare (groupShare 2 1 vector1.value) `shouldBe` Left "The group threshold is greater than the group count"
    it "refuses to encode a member index of 16" $
      encodeShare vector1 {memberIndex = 16} `shouldBe` Left "The member index must be between 0 and 15, not 16"
    it "refuses to encode a member threshold of 17" $
      encodeShare vector1 {memberThreshold = 17} `shouldBe` Left "The member threshold must be between 1 and 16, not 17"
    it "refuses to encode a value of 15 bytes" $
      encodeShare vector1 {value = B.replicate 15 0} `shouldBe` Left "The share value must have at least 16 bytes, not 15"
    it "refuses to encode a value of 17 bytes" $
      encodeShare vector1 {value = B.replicate 17 0} `shouldBe` Left "The share value must have an even number of bytes, not 17"
    it "shows a share without its value" $
      show vector1
        `shouldBe` "Share {identifier = 7945, extendable = False, iterationExponent = 0, groupIndex = 0, groupThreshold = 1, groupCount = 1, memberIndex = 0, memberThreshold = 1, value = <redacted>}"

  describe "splitting and recovering a secret" $ do
    let secret = "ABCDEFGHIJKLMNOP"
        digestRandom = B.pack [0 .. 11]
        noRandom = SplitRandom [] B.empty
        -- 2-of-3 of the secret with that random part: the verifier's values
        share0 = (0, hex "8459b115d432d65461876350dc3ade25")
        share1 = (1, hex "2b463c939175931f2cc82e1b997d9b7e")
        share2 = (2, hex "c167b0025ebc5cc2fb19f9c656b45493")
        twoOfThree = [share0, share1, share2]
    it "gives the secret itself as every share at a threshold of 1" $
      splitSecret 1 3 secret noRandom `shouldBe` Right [(0, secret), (1, secret), (2, secret)]
    it "splits 2-of-3 as the verifier does, from the random part of the digest share" $
      splitSecret 2 3 secret (SplitRandom [] digestRandom) `shouldBe` Right twoOfThree
    it "recovers the secret from any two of the three" $
      forM_ [[share0, share1], [share1, share2], [share0, share2]] $ \two ->
        recoverSecret 2 two `shouldBe` Right secret
    it "recovers it from all three as well" $
      recoverSecret 2 twoOfThree `shouldBe` Right secret
    it "splits 3-of-4 as the verifier does, from a random share and the random part" $
      -- The random share takes index 0 as it is
      splitSecret 3 4 secret (SplitRandom [B.pack [0x10 .. 0x1f]] (B.pack [0x20 .. 0x2b]))
        `shouldBe` Right
          [ (0, hex "101112131415161718191a1b1c1d1e1f"),
            (1, hex "7d29eb177172737c75767770797a7b64"),
            (2, hex "009af86a90059252089d0aac980d9a96"),
            (3, hex "6da2016ef562f73965f267c7fd6affed")
          ]
    it "refuses the digest when a share of another secret is mixed in" $
      -- the share at index 1 of the 2-of-3 of "abcdefghijklmnop" with the same random part
      recoverSecret 2 [share0, (1, hex "b086c5a043a741cdfe1afcc94baf49ac")]
        `shouldBe` Left "The digest of the secret does not match"
    it "refuses the digest when a share is corrupted" $
      recoverSecret 2 [share0, (1, hex "2b463c939175931f2cc82e1b997d9b7f")]
        `shouldBe` Left "The digest of the secret does not match"
    it "recovers the first share at a threshold of 1" $
      recoverSecret 1 [(4, secret), (5, "ponmlkjihgfedcba")] `shouldBe` Right secret
    it "refuses no shares" $
      recoverSecret 2 [] `shouldBe` Left "There are no shares to recover the secret from"
    it "refuses a threshold of 0" $
      splitSecret 0 3 secret noRandom `shouldBe` Left "The threshold must be at least 1"
    it "refuses a threshold above the share count" $
      splitSecret 4 3 secret noRandom `shouldBe` Left "The threshold is greater than the number of shares"
    it "refuses 17 shares" $
      splitSecret 2 17 secret noRandom `shouldBe` Left "The number of shares is greater than 16"
    it "refuses a secret of 15 bytes" $
      splitSecret 1 1 (B.take 15 secret) noRandom `shouldBe` Left "The secret must have at least 16 bytes, not 15"
    it "refuses a secret of 17 bytes" $
      splitSecret 1 1 (secret <> "Q") noRandom `shouldBe` Left "The secret must have an even number of bytes, not 17"
    it "refuses random shares at a threshold of 1" $
      splitSecret 1 1 secret (SplitRandom [secret] B.empty) `shouldBe` Left "A split with a threshold of 1 takes 0 random shares"
    it "refuses a random part at a threshold of 1" $
      splitSecret 1 1 secret (SplitRandom [] digestRandom) `shouldBe` Left "The random part of the digest share must have 0 bytes"
    it "refuses too few random shares" $
      splitSecret 3 4 secret (SplitRandom [] digestRandom) `shouldBe` Left "A split with a threshold of 3 takes 1 random shares"
    it "refuses a random share of another length" $
      splitSecret 3 4 secret (SplitRandom [B.take 15 secret] digestRandom) `shouldBe` Left "A random share must be as long as the secret"
    it "refuses a random part of another length" $
      splitSecret 2 3 secret (SplitRandom [] (B.take 11 digestRandom)) `shouldBe` Left "The random part of the digest share must have 12 bytes"
    it "sizes the random values: none at threshold 1, T - 2 shares and n - 4 bytes otherwise" $ do
      splitRandomSizes 1 16 `shouldBe` (0, 16, 0)
      splitRandomSizes 2 16 `shouldBe` (0, 16, 12)
      splitRandomSizes 5 32 `shouldBe` (3, 32, 28)
    it "recovers any random secret from any threshold of its shares" $
      property $ forAll ((,) <$> bytesOf 16 <*> bytesOf 12) $ \(s, r) ->
        case splitSecret 2 3 s (SplitRandom [] r) of
          Right shares -> all ((== Right s) . recoverSecret 2) [two | two <- subsequences shares, length two == 2]
          Left _ -> False

  describe "the passphrase" $ do
    let secret = "ABCDEFGHIJKLMNOP"
        ems = EncryptedMasterSecret {identifier = 7945, extendable = False, iterationExponent = 0, ciphertext = hex "11bc609d21747c49ba78c0701293e417"}
    it "decrypts the encrypted master secret of the first vector with TREZOR" $
      decryptMasterSecret "TREZOR" ems `shouldBe` Right (hex "bb54aac4b89dc868ba37d9cc21b2cece")
    it "encrypts that master secret back" $
      encryptMasterSecret 7945 False 0 "TREZOR" (hex "bb54aac4b89dc868ba37d9cc21b2cece") `shouldBe` Right ems
    it "encrypts ABCDEFGHIJKLMNOP under an empty passphrase as the verifier does" $
      fmap (.ciphertext) (encryptMasterSecret 1 True 0 "" secret) `shouldBe` Right (hex "7b78e5f690282c25aa183fa39a23dd02")
    it "ignores the identifier when the backup is extendable" $
      fmap (.ciphertext) (encryptMasterSecret 2 True 0 "" secret) `shouldBe` Right (hex "7b78e5f690282c25aa183fa39a23dd02")
    it "salts with the identifier when the backup is not extendable" $ do
      fmap (.ciphertext) (encryptMasterSecret 1 False 0 "" secret) `shouldBe` Right (hex "3162b7863d3710ef05f35feaa08fbc54")
      fmap (.ciphertext) (encryptMasterSecret 2 False 0 "" secret) `shouldBe` Right (hex "90330cd4eef5857777c6a09793195a23")
    it "gives another ciphertext under another passphrase" $
      fmap (.ciphertext) (encryptMasterSecret 1 True 0 "TREZOR" secret) `shouldBe` Right (hex "c5462e7421d4c690de1668d6a3bfd337")
    it "gives another ciphertext under another iteration exponent" $
      fmap (.ciphertext) (encryptMasterSecret 1 True 1 "" secret) `shouldBe` Right (hex "d51a2d68cb0adf27958873071f5253ac")
    it "decrypts to another master secret under a wrong passphrase, without an error" $
      decryptMasterSecret "trezor" ems `shouldSatisfy` \r -> r /= Right (hex "bb54aac4b89dc868ba37d9cc21b2cece") && either (const False) (const True) r
    it "accepts the first and the last printable ASCII characters" $
      fmap (const ()) (encryptMasterSecret 1 True 0 " ~" secret) `shouldBe` Right ()
    it "refuses a passphrase outside printable ASCII" $
      encryptMasterSecret 1 True 0 "café" secret
        `shouldBe` Left "The passphrase must contain only printable ASCII characters, code points 32 to 126"
    it "refuses a control character in the passphrase" $
      encryptMasterSecret 1 True 0 "a\tb" secret
        `shouldBe` Left "The passphrase must contain only printable ASCII characters, code points 32 to 126"
    it "still decrypts a share made with such a passphrase, as UTF-8" $
      -- Made by version 0.3.0 of the reference implementation with the
      -- passphrase "café", from its tests
      combineMnemonics "café" ["acid fawn academic academic company fridge picture cage pecan glance privacy carpet should public pharmacy eclipse percent python together flavor"]
        `shouldBe` Right secret
    it "refuses a master secret of 15 bytes" $
      encryptMasterSecret 1 True 0 "" (B.take 15 secret) `shouldBe` Left "The master secret must have at least 16 bytes, not 15"
    it "refuses a master secret of 17 bytes" $
      encryptMasterSecret 1 True 0 "" (secret <> "Q") `shouldBe` Left "The master secret must have an even number of bytes, not 17"
    it "refuses an identifier of 16 bits" $
      encryptMasterSecret 32768 True 0 "" secret `shouldBe` Left "The identifier must be between 0 and 32767, not 32768"
    it "refuses an iteration exponent of 16" $
      encryptMasterSecret 1 True 16 "" secret `shouldBe` Left "The iteration exponent must be between 0 and 15, not 16"
    it "refuses to decrypt a ciphertext of 15 bytes" $
      decryptMasterSecret "" ems {ciphertext = B.take 15 ems.ciphertext} `shouldBe` Left "The encrypted master secret must have at least 16 bytes, not 15"
    it "shows an encrypted master secret without its ciphertext" $
      show ems `shouldBe` "EncryptedMasterSecret {identifier = 7945, extendable = False, iterationExponent = 0, ciphertext = <redacted>}"
    it "decrypts what it encrypts, for any secret and passphrase" $
      property $ forAll ((,) <$> bytesOf 16 <*> listOf (elements [' ' .. '~'])) $ \(s, p) ->
        (encryptMasterSecret 5 True 0 (T.pack p) s >>= decryptMasterSecret (T.pack p)) === Right s

  describe "generating shares" $ do
    forM_ splitCases $ \c -> do
      it ("splits " <> T.unpack c.caseDescription <> " as the verifier does") $
        (generateSharesWith c.caseScheme c.caseIdentifier c.caseExtendable c.caseIterationExponent c.casePassphrase c.caseMasterSecret c.caseRandom >>= traverse (traverse encodeShare))
          `shouldBe` Right c.caseMnemonics
      it ("combines any threshold of the shares of " <> T.unpack c.caseDescription) $
        forM_ (thresholdSubsets c) $ \subset ->
          combineMnemonics c.casePassphrase subset `shouldBe` Right c.caseMasterSecret
    it "gives the 2-of-3 case these three mnemonics" $
      -- The second split case, written out: the first three words are the
      -- identifier 42, the flag and the exponent 1; the fourth differs by
      -- the member index
      generateSharesWith (Scheme 1 [(2, 3)]) 42 True 1 "TREZOR" "ABCDEFGHIJKLMNOP" [SplitRandom [] B.empty, SplitRandom [] (hex "698c2ccb37ff81b7f5603f9b")]
        `shouldBe` Right
          [ [ share 42 True 1 0 1 1 0 2 "acid fawn academic acid club member living lawsuit sunlight pancake market lend peasant sunlight glad simple infant organize grant infant",
              share 42 True 1 0 1 1 1 2 "acid fawn academic agency bracelet transfer march argue wits exact dough parcel animal traveler dictate river military salt satisfy payment",
              share 42 True 1 0 1 1 2 2 "acid fawn academic always advocate either wine oasis solution goat toxic injury radar romantic shrimp check warmth fangs ending mineral"
            ]
          ]
    it "refuses a scheme without groups" $
      generateSharesWith (Scheme 1 []) 1 True 0 "" "ABCDEFGHIJKLMNOP" [] `shouldBe` Left "A scheme has at least one group"
    it "refuses a scheme of 17 groups" $
      generateSharesWith (Scheme 1 (replicate 17 (1, 1))) 1 True 0 "" "ABCDEFGHIJKLMNOP" [] `shouldBe` Left "A scheme has at most 16 groups"
    it "refuses a group threshold of 0" $
      generateSharesWith (Scheme 0 [(1, 1)]) 1 True 0 "" "ABCDEFGHIJKLMNOP" [] `shouldBe` Left "The group threshold must be between 1 and 1, not 0"
    it "refuses a group threshold above the number of groups" $
      generateSharesWith (Scheme 3 [(1, 1), (1, 1)]) 1 True 0 "" "ABCDEFGHIJKLMNOP" [] `shouldBe` Left "The group threshold must be between 1 and 2, not 3"
    it "refuses a member count of 17" $
      generateSharesWith (Scheme 1 [(2, 17)]) 1 True 0 "" "ABCDEFGHIJKLMNOP" [] `shouldBe` Left "The member count of group 1 must be between 1 and 16, not 17"
    it "refuses a member threshold of 0" $
      generateSharesWith (Scheme 1 [(0, 3)]) 1 True 0 "" "ABCDEFGHIJKLMNOP" [] `shouldBe` Left "The member threshold of group 1 must be between 1 and 3, not 0"
    it "refuses a member threshold above the member count" $
      generateSharesWith (Scheme 1 [(1, 1), (4, 3)]) 1 True 0 "" "ABCDEFGHIJKLMNOP" [] `shouldBe` Left "The member threshold of group 2 must be between 1 and 3, not 4"
    it "refuses a group of several members with a member threshold of 1" $
      generateSharesWith (Scheme 1 [(1, 3)]) 1 True 0 "" "ABCDEFGHIJKLMNOP" [] `shouldBe` Left "A group with a member threshold of 1 has one member, but group 1 has 3"
    it "refuses random values for the wrong number of splits" $
      generateSharesWith (Scheme 1 [(1, 1)]) 1 True 0 "" "ABCDEFGHIJKLMNOP" [SplitRandom [] B.empty]
        `shouldBe` Left "A scheme of 1 groups takes 2 sets of random values: one for the split among the groups, then one per group"
    it "refuses a master secret of 15 bytes before drawing anything" $
      fst (withDRG (drgNewTest (1, 2, 3, 4, 5)) (generateShares (Scheme 1 [(2, 3)]) True 0 "" "ABCDEFGHIJKLMNO"))
        `shouldBe` Left "The master secret must have at least 16 bytes, not 15"
    it "draws a 15-bit identifier and shares of which any two of three rebuild the secret" $ do
      let secret = "ABCDEFGHIJKLMNOP"
          drawn = fst (withDRG (drgNewTest (1, 2, 3, 4, 5)) (generateShares (Scheme 1 [(2, 3)]) True 0 "" secret))
      case drawn of
        Right [shares] -> do
          length shares `shouldBe` 3
          length (nub (map (.identifier) shares)) `shouldBe` 1
          forM_ shares $ \s -> do
            s.identifier `shouldSatisfy` (\i -> i >= 0 && i <= 32767)
            (s.extendable, s.iterationExponent, s.groupIndex, s.groupThreshold, s.groupCount, s.memberThreshold) `shouldBe` (True, 0, 0, 1, 1, 2)
          map (.memberIndex) shares `shouldBe` [0, 1, 2]
          forM_ [two | two <- subsequences shares, length two == 2] $ \two ->
            (combineShares two >>= decryptMasterSecret "") `shouldBe` Right secret
        other -> expectationFailure ("expected one group of three shares, got " <> show other)
    it "draws the same shares from the same random state and others from another" $ do
      let draw seed = fst (withDRG (drgNewTest seed) (generateMnemonics (Scheme 1 [(2, 3)]) True 0 "" "ABCDEFGHIJKLMNOP"))
      draw (1, 2, 3, 4, 5) `shouldBe` draw (1, 2, 3, 4, 5)
      draw (1, 2, 3, 4, 5) `shouldNotBe` draw (6, 7, 8, 9, 10)
    it "draws shares with the system's randomness that rebuild a two-level scheme" $ do
      let secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
      drawn <- generateMnemonics (Scheme 2 [(1, 1), (2, 3), (3, 5)]) True 0 "pass" secret
      case drawn of
        Right [[a], bs, cs] -> do
          combineMnemonics "pass" (a : take 2 bs) `shouldBe` Right secret
          combineMnemonics "pass" (take 2 bs ++ take 3 cs) `shouldBe` Right secret
          combineMnemonics "pass" (a : drop 2 cs) `shouldBe` Right secret
          combineMnemonics "pass" (a : take 1 bs) `shouldBe` Left "Group 1 has 1 share, but its member threshold is 2"
        other -> expectationFailure ("expected groups of 1, 3 and 5 shares, got " <> show other)

  describe "combining shares" $ do
    it "rebuilds the encrypted master secret of the first vector from its one share" $
      combineShares [vector1]
        `shouldBe` Right EncryptedMasterSecret {identifier = 7945, extendable = False, iterationExponent = 0, ciphertext = hex "11bc609d21747c49ba78c0701293e417"}
    it "refuses no shares" $
      combineShares [] `shouldBe` Left "There are no shares to combine"
    it "refuses no mnemonics" $
      combineMnemonics "" [] `shouldBe` Left "There are no shares to combine"
    it "refuses shares that differ on the extendable flag" $
      combineShares [vector1, (singleShare 7945 True 0 vector1.value) {memberIndex = 1}] `shouldBe` Left "The shares do not have the same extendable flag"
    it "refuses shares whose values differ in length" $
      combineShares [vector1, vector1 {memberIndex = 1, value = B.replicate 32 0}] `shouldBe` Left "The shares do not have the same length of their values"
    it "refuses a share with a field out of range" $
      combineShares [vector1 {memberIndex = 16}] `shouldBe` Left "The member index must be between 0 and 15, not 16"
    it "refuses more groups than the group threshold" $
      combineShares [groupShare 1 2 vector1.value, (groupShare 1 2 vector1.value) {groupIndex = 1}]
        `shouldBe` Left "The shares come from 2 groups, but the group threshold is 1"
    it "refuses more shares than the member threshold of a group" $
      combineShares [vector1, vector1 {memberIndex = 1}] `shouldBe` Left "Group 0 has 2 shares, but its member threshold is 1"

  describe "the shares of another implementation" $ do
    -- From the tests of Sparrow's library: eight groups of one member, five
    -- of them needed, and the value of the fifth share starts with a zero
    -- byte, which a conversion through a number would drop
    let sparrow =
          [ "budget surprise agency romp clay quiet spew favorite purchase thumb observe sympathy acrobat presence unfold focus already tricycle diagnose muscle",
            "budget surprise birthday romp breathe scroll intend humidity aspect plains isolate crystal blimp dragon garbage both kind dance human craft",
            "budget surprise cleanup romp early remove uncover hearing lamp firefly ounce species submit snake phrase genuine tactics mustang desire artist",
            "budget surprise desert romp deny easy senior arena smirk average single smart fatal lecture threaten eyebrow lunar carve indicate romantic",
            "budget surprise email romp academic anxiety sister nylon fake makeup spine breathe window true recall desktop shelter divorce luck screw"
          ]
    it "keeps the zero byte at the head of a share value" $
      fmap (\s -> (s.groupIndex, s.groupThreshold, s.groupCount, s.memberThreshold, encodeHex s.value)) (decodeShare (last sparrow))
        `shouldBe` Right (4, 5, 8, 1, "000bf319a1478ab5418bedeb2de34f26")
    it "rebuilds the master secret from five of the eight groups" $
      fmap encodeHex (combineMnemonics "" sparrow) `shouldBe` Right "609d9cf21c065a88e9f5b97c0e6928c6"

  describe "the vectors of the reference implementation" $ do
    it "has 45 vectors, 15 of them valid" $ do
      length vectors `shouldBe` 45
      length [() | (_, _, s, _) <- vectors, s /= ""] `shouldBe` 15
    forM_ (zip [1 :: Int ..] vectors) $ \(n, (d, ms, secret, xprv)) ->
      if secret /= ""
        then it (T.unpack d <> ": gives the master secret and its BIP-32 key") $ do
          combineMnemonics "TREZOR" ms `shouldBe` Right (hex secret)
          xPrvExport btc (makeXPrvKey (hex secret)) `shouldBe` xprv
        else it (T.unpack d <> ": is refused") $
          combineMnemonics "TREZOR" ms `shouldBe` Left (refusalOf n)

-- | The share of the first vector.
vector1 :: Share
vector1 = singleShare 7945 False 0 (hex "11bc609d21747c49ba78c0701293e417")

-- | A share of a 1-of-1 split with the identifier, the flag, the exponent
-- and the value given.
singleShare :: Int -> Bool -> Int -> ByteString -> Share
singleShare i ext e v =
  Share
    { identifier = i,
      extendable = ext,
      iterationExponent = e,
      groupIndex = 0,
      groupThreshold = 1,
      groupCount = 1,
      memberIndex = 0,
      memberThreshold = 1,
      value = v
    }

-- | The first vector's share with the group threshold and count given.
groupShare :: Int -> Int -> ByteString -> Share
groupShare threshold count v =
  Share
    { identifier = 7945,
      extendable = False,
      iterationExponent = 0,
      groupIndex = 0,
      groupThreshold = threshold,
      groupCount = count,
      memberIndex = 0,
      memberThreshold = 1,
      value = v
    }

-- | The indices of a mnemonic's words, which must all be in the list.
indicesOf :: Text -> [Int]
indicesOf = either error id . mnemonicToIndices

-- | The one mnemonic, or the first, of a vector by its number.
mnemonicOf :: [(Text, [Text], Text, Text)] -> Int -> Text
mnemonicOf vectors n = case vectors !! (n - 1) of
  (_, m : _, _, _) -> m
  (d, [], _, _) -> error ("vector without mnemonics: " <> T.unpack d)

-- | Why each invalid vector is refused, by its number.
refusalOf :: Int -> String
refusalOf n = case n of
  2 -> checksum
  3 -> padding
  5 -> oneShareOfTwo 0
  6 -> differ "identifier"
  7 -> differ "iteration exponent"
  8 -> differ "group threshold"
  9 -> differ "group count"
  10 -> thresholdAboveCount
  11 -> duplicate
  12 -> memberThresholds
  13 -> digest
  14 -> oneGroupOfTwo
  15 -> oneGroupOfTwo
  16 -> oneShareOfTwo 3
  21 -> checksum
  22 -> padding
  24 -> oneShareOfTwo 0
  25 -> differ "identifier"
  26 -> differ "iteration exponent"
  27 -> differ "group threshold"
  28 -> differ "group count"
  29 -> thresholdAboveCount
  30 -> duplicate
  31 -> memberThresholds
  32 -> digest
  33 -> oneGroupOfTwo
  34 -> oneGroupOfTwo
  35 -> oneShareOfTwo 3
  39 -> "The mnemonic has 19 words, but a share has at least 20"
  40 -> "The mnemonic has 21 words, which is not a valid share length"
  _ -> error ("vector " <> show n <> " is valid")
  where
    checksum = "The checksum of the mnemonic is invalid"
    padding = "The padding bits of the share value are not zero"
    differ what = "The shares do not have the same " <> what
    thresholdAboveCount = "The group threshold is greater than the group count"
    duplicate = "Group 0 has two shares with the member index 2"
    memberThresholds = "The shares of group 0 do not have the same member threshold"
    digest = "The digest of the secret does not match"
    oneGroupOfTwo = "The shares come from 1 group, but the group threshold is 2"
    oneShareOfTwo g = "Group " <> show (g :: Int) <> " has 1 share, but its member threshold is 2"

-- | Every set of mnemonics of a split case that meets its scheme: enough
-- groups, and enough members of each.
thresholdSubsets :: SplitCase -> [[Text]]
thresholdSubsets c =
  [ concat members
    | chosen <- subsequences (zip (map fst c.caseScheme.groups) c.caseMnemonics),
      length chosen == c.caseScheme.groupThreshold,
      members <- mapM (\(threshold, ms) -> [ms' | ms' <- subsequences ms, length ms' == threshold]) chosen
  ]

-- | A share of the given fields, decoded from its mnemonic for its value.
share :: Int -> Bool -> Int -> Int -> Int -> Int -> Int -> Int -> Text -> Share
share i ext e gi gt gc mi mt mnemonic =
  case decodeShare mnemonic of
    Right s
      | (s.identifier, s.extendable, s.iterationExponent, s.groupIndex, s.groupThreshold, s.groupCount, s.memberIndex, s.memberThreshold) == (i, ext, e, gi, gt, gc, mi, mt) -> s
      | otherwise -> error ("the mnemonic does not carry the fields given: " <> show s)
    Left err -> error err

bytesOf :: Int -> Gen ByteString
bytesOf n = B.pack <$> vectorOf n arbitrary
