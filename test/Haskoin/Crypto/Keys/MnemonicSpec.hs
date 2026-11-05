{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Haskoin.Crypto.Keys.MnemonicSpec (spec) where

import Control.Monad (forM_, zipWithM_)
import Crypto.Hash (SHA256 (..), hashWith)
import Data.Bits (shiftR, (.&.))
import Data.ByteString qualified as BS
import Data.Either (fromRight)
import Data.List (isPrefixOf)
import Data.Map.Strict qualified as M
import Data.Maybe (fromJust)
import Data.Serialize (Serialize, encode)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as E
import Data.Text.IO qualified as TIO
import Data.Vector qualified as V
import Data.Word (Word32, Word64)
import Haskoin (btc)
import Haskoin.Crypto
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.HUnit
import Test.Hspec
import Test.QuickCheck hiding ((.&.))

spec :: Spec
spec =
  describe "mnemonic" $ do
    -- data/bip39_wordlist.txt is bip-0039/english.txt of the BIPs repository,
    -- and data/bip39_vectors.json the vectors.json of python-mnemonic, which
    -- the BIP points to; its English vectors are also written out below as
    -- trezorVectors
    wordListFile <- runIO (TIO.readFile "data/bip39_wordlist.txt")
    vectorsFile <- runIO (readTestFile "bip39_vectors.json" :: IO (M.Map Text [(Text, Mnemonic, Text, Text)]))
    it "entropy to mnemonic sentence" toMnemonicTest
    it "mnemonic sentence to entropy" fromMnemonicTest
    it "mnemonic sentence to seed" mnemonicToSeedTest
    it "mnemonic sentence with invalid checksum" fromMnemonicInvalidTest
    it "empty mnemonic sentence is invalid" $ sequence_ [emptyMnemonicTest]
    it "generate 12 words" $ property toMnemonic128
    it "generate 15 words" $ property toMnemonic160
    it "generate 24 words" $ property toMnemonic256
    it "refuses 64 bytes of entropy" $ property toMnemonic512
    it "generate any allowed number of words" toMnemonicVar
    it "refuses entropy below 16 bytes" toMnemonicTooShort
    it "encode and decode 128-bit entropy" $ property fromToMnemonic128
    it "encode and decode 160-bit entropy" $ property fromToMnemonic160
    it "encode and decode 256-bit entropy" $ property fromToMnemonic256
    it "encode and decode n-bit entropy" fromToMnemonicVar
    it "convert 128-bit mnemonic to seed" $ property mnemonicToSeed128
    it "convert 160-bit mnemonic to seed" $ property mnemonicToSeed160
    it "convert 256-bit mnemonic to seed" $ property mnemonicToSeed256
    it "convert n-bit mnemonic to seed" mnemonicToSeedVar
    it "get bits" $ property getBitsByteCount
    it "get end bits" $ property getBitsEndBits
    it "passes the Trezor vectors" trezorVectorTests
    it "refuses entropy of 4 bytes" $
      toMnemonic (BS.replicate 4 0)
        `shouldBe` Left "toMnemonic: minimum entropy is 16 bytes (128 bits)"
    it "refuses entropy of 64 bytes" $
      toMnemonic (BS.replicate 64 0)
        `shouldBe` Left "toMnemonic: maximum entropy is 32 bytes (256 bits)"
    it "refuses entropy that is not a multiple of 4 bytes" $
      toMnemonic (BS.replicate 17 0)
        `shouldBe` Left "toMnemonic: entropy must be multiples of 4 bytes"
    it "gives 12 to 24 words for 16 to 32 bytes of entropy" $
      -- (bytes * 8 + bytes * 8 / 32) / 11 words: 16 bytes give 132 / 11 = 12
      forM_ [(16, 12), (20, 15), (24, 18), (28, 21), (32, 24)] $ \(bytes, count) ->
        fmap (length . T.words) (toMnemonic (BS.replicate bytes 0)) `shouldBe` Right count
    it "refuses a sentence of 3 words" $
      fromMnemonic "abandon abandon ability"
        `shouldBe` Left "fromMnemonic: wrong number of words: 3"
    it "refuses a sentence of 48 words" $
      fromMnemonic (T.unwords (replicate 48 "abandon"))
        `shouldBe` Left "fromMnemonic: wrong number of words: 48"
    it "refuses a sentence of only whitespace" $
      fromMnemonic "   " `shouldBe` Left "fromMnemonic: wrong number of words: 0"
    it "refuses a word that is not in the list" $
      fromMnemonic "Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        `shouldBe` Left "fromMnemonic: words not in the list: Abandon"
    it "matches words after NFKD normalisation" $
      -- the first word in fullwidth letters, which NFKD maps back to ASCII
      fmap encodeHex (fromMnemonic "ａｂａｎｄｏｎ abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        `shouldBe` Right "00000000000000000000000000000000"
    it "normalises the passphrase to NFKD before deriving the seed" $ do
      -- PBKDF2-HMAC-SHA512, 2048 rounds, of the sentence with the salt
      -- "mnemonic" ++ NFKD("café"), as python-mnemonic computes it. The
      -- precomposed and the decomposed spelling must give the same seed.
      fmap encodeHex (mnemonicToSeed "caf\x00e9" abandon12) `shouldBe` Right cafeSeed
      fmap encodeHex (mnemonicToSeed "cafe\x0301" abandon12) `shouldBe` Right cafeSeed
    it "has the 2048 BIP39 words in order" $ do
      V.length wordList `shouldBe` 2048
      wordList V.! 0 `shouldBe` "abandon"
      wordList V.! 2047 `shouldBe` "zoo"
      M.size wordListMap `shouldBe` 2048
      M.lookup "abandon" wordListMap `shouldBe` Just 0
      M.lookup "zoo" wordListMap `shouldBe` Just 2047
    it "has the published English word list, by its SHA-256" $
      -- sha256sum of bip-0039/english.txt in the BIPs repository, one word
      -- per line with a newline after each
      show (hashWith SHA256 (E.encodeUtf8 (T.unlines (V.toList wordList))))
        `shouldBe` "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    it "has the word list of the data directory, word for word" $
      V.toList wordList `shouldBe` T.lines wordListFile
    it "has the 24 English vectors of the published file, as written out here" $ do
      M.lookup "english" vectorsFile `shouldBe` Just trezorVectors
      length trezorVectors `shouldBe` 24
    it "accepts the 24-word sentence of Trezor's firmware tests" $
      -- 22 times "abstract", then "artefact electric"; the entropy is the
      -- 11-bit index of each word in a row, 6 for abstract, 36 and 572
      fmap encodeHex (fromMnemonic (T.unwords (replicate 22 "abstract" ++ ["artefact", "electric"])))
        `shouldBe` Right "00e01c0380700e01c0380700e01c0380700e01c0380700e01c0380700e01c33a"
    it "refuses each old vector sentence with a word put in front, as Trezor's firmware does" $
      -- 13, 19 or 25 words
      forM_ mss $ \m ->
        fromMnemonic ("above " <> m) `shouldBe` Left ("fromMnemonic: wrong number of words: " <> show (length (T.words m) + 1))
    it "refuses each old vector sentence without its first word, as Trezor's firmware does" $
      -- 11, 17 or 23 words
      forM_ mss $ \m ->
        fromMnemonic (T.unwords (drop 1 (T.words m))) `shouldBe` Left ("fromMnemonic: wrong number of words: " <> show (length (T.words m) - 1))
    it "refuses the wrong-checksum sentence of python-mnemonic's tests" $
      fromMnemonic "bless cloud wheel regular tiny venue bird web grief security dignity zoo"
        `shouldSatisfy` either ("fromMnemonic: checksum failed:" `isPrefixOf`) (const False)
    it "refuses the sentences of the JavaScript library's custom word list, naming their words" $
      -- bitcoinjs/bip39 tests them against a word list of its own
      fromMnemonic "aband0n aband0n aband0n aband0n aband0n aband0n aband0n aband0n aband0n aband0n aband0n ab0ut"
        `shouldBe` Left "fromMnemonic: words not in the list: aband0n aband0n aband0n aband0n aband0n aband0n aband0n aband0n aband0n aband0n aband0n ab0ut"
    it "gives 15 and 21 words for 20 and 28 bytes of entropy, with their seeds and keys" $
      -- The published vectors have no 15- or 21-word case. These were
      -- computed with an independent Python implementation of BIP39 from
      -- hashlib: the checksum is the first 5 or 7 bits of the SHA-256 of
      -- the entropy, the seed is PBKDF2-HMAC-SHA512 of the sentence with
      -- 2048 rounds and the salt "mnemonic" ++ "TREZOR", and the key is
      -- the BIP32 master key of the seed.
      forM_ fifteenAndTwentyOneWordVectors $ \(entTxt, mnem, seedTxt, xprvTxt) -> do
        let ent = fromJust (decodeHex entTxt)
        toMnemonic ent `shouldBe` Right mnem
        fmap encodeHex (mnemonicToSeed "TREZOR" mnem) `shouldBe` Right seedTxt
        fmap (xPrvExport btc . makeXPrvKey) (mnemonicToSeed "TREZOR" mnem) `shouldBe` Right xprvTxt

-- | The first Trezor sentence, for 16 zero bytes of entropy.
abandon12 :: Mnemonic
abandon12 =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

-- | Seed of 'abandon12' with the passphrase "café".
cafeSeed :: Text
cafeSeed =
  "af8bbd2566df7b69d926f2b09dfdbd75db6c994a3399b2cc65f928d63e3fd4e6\
  \1218ee0d15f8c810be4d45e66d47b43c15a5cc753976b1666912377ff7ae9818"

toMnemonicTest :: Assertion
toMnemonicTest = zipWithM_ f ents mss
  where
    f e m = assertEqual "" m . h $ e
    h =
      fromRight (error "Could not decode mnemonic sentence")
        . toMnemonic
        . fromJust
        . decodeHex

fromMnemonicTest :: Assertion
fromMnemonicTest = zipWithM_ f ents mss
  where
    f e = assertEqual "" e . h
    h =
      encodeHex
        . fromRight (error "Could not decode mnemonic sentence")
        . fromMnemonic

mnemonicToSeedTest :: Assertion
mnemonicToSeedTest = zipWithM_ f mss seeds
  where
    f m s = assertEqual "" s . h $ m
    h =
      encodeHex
        . fromRight (error "Could not decode mnemonic seed")
        . mnemonicToSeed "TREZOR"

fromMnemonicInvalidTest :: Assertion
fromMnemonicInvalidTest = mapM_ f invalidMss
  where
    f = assertBool "" . h
    h m = case fromMnemonic m of
      Right _ -> False
      Left err -> "fromMnemonic: checksum failed:" `isPrefixOf` err

emptyMnemonicTest :: Assertion
emptyMnemonicTest =
  assertBool "" $
    case fromMnemonic "" of
      Right _ -> False
      Left err -> "fromMnemonic: empty mnemonic" `isPrefixOf` err

trezorVectorTests :: Assertion
trezorVectorTests =
  forM_ trezorVectors $ \(entTxt, mnem, seedTxt, xprvTxt) -> do
    let ent = fromJust $ decodeHex entTxt
        seed = fromJust $ decodeHex seedTxt
        xprv = fromJust $ xPrvImport btc xprvTxt
    assertEqual "toMnemonic" (Right mnem) $ toMnemonic ent
    assertEqual "mnemonicToSeed" (Right seed) $ mnemonicToSeed "TREZOR" mnem
    assertEqual "xPrv" xprv $ makeXPrvKey seed

-- The next three lists are the English vectors of an earlier vectors.json
-- of python-mnemonic, whose random cases (from the 13th on) were replaced
-- later; Trezor's firmware still tests the sentences as valid.
ents :: [Text]
ents =
  [ "00000000000000000000000000000000",
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "80808080808080808080808080808080",
    "ffffffffffffffffffffffffffffffff",
    "000000000000000000000000000000000000000000000000",
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "808080808080808080808080808080808080808080808080",
    "ffffffffffffffffffffffffffffffffffffffffffffffff",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    "8080808080808080808080808080808080808080808080808080808080808080",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "77c2b00716cec7213839159e404db50d",
    "b63a9c59a6e641f288ebc103017f1da9f8290b3da6bdef7b",
    "3e141609b97933b66a060dcddc71fad1d91677db872031e85f4c015c5e7e8982",
    "0460ef47585604c5660618db2e6a7e7f",
    "72f60ebac5dd8add8d2a25a797102c3ce21bc029c200076f",
    "2c85efc7f24ee4573d2b81a6ec66cee209b2dcbd09d8eddc51e0215b0b68e416",
    "eaebabb2383351fd31d703840b32e9e2",
    "7ac45cfe7722ee6c7ba84fbc2d5bd61b45cb2fe5eb65aa78",
    "4fa1a8bc3e6d80ee1316050e862c1812031493212b7ec3f3bb1b08f168cabeef",
    "18ab19a9f54a9274f03e5209a2ac8a91",
    "18a2e1d81b8ecfb2a333adcb0c17a5b9eb76cc5d05db91a4",
    "15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419"
  ]

mss :: [Mnemonic]
mss =
  [ "abandon abandon abandon abandon abandon abandon abandon abandon abandon\
    \ abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank\
    \ yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice\
    \ cage above",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon\
    \ abandon abandon abandon abandon abandon abandon abandon abandon agent",
    "legal winner thank year wave sausage worth useful legal winner thank\
    \ year wave sausage worth useful legal will",
    "letter advice cage absurd amount doctor acoustic avoid letter advice\
    \ cage absurd amount doctor acoustic avoid letter always",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo\
    \ when",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon\
    \ abandon abandon abandon abandon abandon abandon abandon abandon abandon\
    \ abandon abandon abandon abandon abandon art",
    "legal winner thank year wave sausage worth useful legal winner thank\
    \ year wave sausage worth useful legal winner thank year wave sausage\
    \ worth title",
    "letter advice cage absurd amount doctor acoustic avoid letter advice\
    \ cage absurd amount doctor acoustic avoid letter advice cage absurd\
    \ amount doctor acoustic bless",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo\
    \ zoo zoo zoo zoo zoo vote",
    "jelly better achieve collect unaware mountain thought cargo oxygen act\
    \ hood bridge",
    "renew stay biology evidence goat welcome casual join adapt armor shuffle\
    \ fault little machine walk stumble urge swap",
    "dignity pass list indicate nasty swamp pool script soccer toe leaf photo\
    \ multiply desk host tomato cradle drill spread actor shine dismiss\
    \ champion exotic",
    "afford alter spike radar gate glance object seek swamp infant panel\
    \ yellow",
    "indicate race push merry suffer human cruise dwarf pole review arch keep\
    \ canvas theme poem divorce alter left",
    "clutch control vehicle tonight unusual clog visa ice plunge glimpse\
    \ recipe series open hour vintage deposit universe tip job dress radar\
    \ refuse motion taste",
    "turtle front uncle idea crush write shrug there lottery flower risk\
    \ shell",
    "kiss carry display unusual confirm curtain upgrade antique rotate hello\
    \ void custom frequent obey nut hole price segment",
    "exile ask congress lamp submit jacket era scheme attend cousin alcohol\
    \ catch course end lucky hurt sentence oven short ball bird grab wing top",
    "board flee heavy tunnel powder denial science ski answer betray cargo\
    \ cat",
    "board blade invite damage undo sun mimic interest slam gaze truly\
    \ inherit resist great inject rocket museum chief",
    "beyond stage sleep clip because twist token leaf atom beauty genius food\
    \ business side grid unable middle armed observe pair crouch tonight away\
    \ coconut"
  ]

seeds :: [Text]
seeds =
  [ "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a69\
    \87599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1\
    \296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f1\
    \2eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a133325729\
    \17f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9\
    \a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
    "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c3\
    \92d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
    "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913f\
    \fb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
    "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43\
    \348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
    "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4\
    \d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146a\
    \d717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
    "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61a\
    \f0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
    "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0\
    \a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
    "b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f6\
    \72a290aae502472cf2d602c051f3e6f18055e84e4c43897fc4e51a6ff",
    "9248d83e06f4cd98debf5b6f010542760df925ce46cf38a1bdb4e4de7d21f5c39366941\
    \c69e1bdbf2966e0f6e6dbece898a0e2f0a4c2b3e640953dfe8b7bbdc5",
    "ff7f3184df8696d8bef94b6c03114dbee0ef89ff938712301d27ed8336ca89ef9635da2\
    \0af07d4175f2bf5f3de130f39c9d9e8dd0472489c19b1a020a940da67",
    "65f93a9f36b6c85cbe634ffc1f99f2b82cbb10b31edc7f087b4f6cb9e976e9faf76ff41\
    \f8f27c99afdf38f7a303ba1136ee48a4c1e7fcd3dba7aa876113a36e4",
    "3bbf9daa0dfad8229786ace5ddb4e00fa98a044ae4c4975ffd5e094dba9e0bb289349db\
    \e2091761f30f382d4e35c4a670ee8ab50758d2c55881be69e327117ba",
    "fe908f96f46668b2d5b37d82f558c77ed0d69dd0e7e043a5b0511c48c2f1064694a956f\
    \86360c93dd04052a8899497ce9e985ebe0c8c52b955e6ae86d4ff4449",
    "bdfb76a0759f301b0b899a1e3985227e53b3f51e67e3f2a65363caedf3e32fde42a66c4\
    \04f18d7b05818c95ef3ca1e5146646856c461c073169467511680876c",
    "ed56ff6c833c07982eb7119a8f48fd363c4a9b1601cd2de736b01045c5eb8ab4f57b079\
    \403485d1c4924f0790dc10a971763337cb9f9c62226f64fff26397c79",
    "095ee6f817b4c2cb30a5a797360a81a40ab0f9a4e25ecd672a3f58a0b5ba0687c096a6b\
    \14d2c0deb3bdefce4f61d01ae07417d502429352e27695163f7447a8c",
    "6eff1bb21562918509c73cb990260db07c0ce34ff0e3cc4a8cb3276129fbcb300bddfe0\
    \05831350efd633909f476c45c88253276d9fd0df6ef48609e8bb7dca8",
    "f84521c777a13b61564234bf8f8b62b3afce27fc4062b51bb5e62bdfecb23864ee6ecf0\
    \7c1d5a97c0834307c5c852d8ceb88e7c97923c0a3b496bedd4e5f88a9",
    "b15509eaa2d09d3efd3e006ef42151b30367dc6e3aa5e44caba3fe4d3e352e65101fbdb\
    \86a96776b91946ff06f8eac594dc6ee1d3e82a42dfe1b40fef6bcc3fd"
  ]

invalidMss :: [Mnemonic]
invalidMss =
  [ "abandon abandon abandon abandon abandon abandon abandon abandon abandon\
    \ abandon abandon abandon",
    "legal winner thank year wave sausage worth useful legal winner thank\
    \ thank",
    "letter advice cage absurd amount doctor acoustic avoid letter advice\
    \ cage sausage",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon\
    \ abandon abandon abandon abandon abandon abandon abandon abandon abandon",
    "legal winner thank year wave sausage worth useful legal winner thank\
    \ year wave sausage worth useful legal letter",
    "letter advice cage absurd amount doctor acoustic avoid letter advice\
    \ cage absurd amount doctor acoustic avoid letter abandon",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo\
    \ zoo",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon\
    \ abandon abandon abandon abandon abandon abandon abandon abandon abandon\
    \ abandon abandon abandon abandon abandon abandon",
    "legal winner thank year wave sausage worth useful legal winner thank\
    \ year wave sausage worth useful legal winner thank year wave sausage\
    \ worth letter",
    "letter advice cage absurd amount doctor acoustic avoid letter advice\
    \ cage absurd amount doctor acoustic avoid letter advice cage absurd\
    \ amount doctor acoustic letter",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo\
    \ zoo zoo zoo zoo zoo zoo",
    "jelly better achieve collect unaware mountain thought cargo oxygen act\
    \ hood zoo",
    "renew stay biology evidence goat welcome casual join adapt armor shuffle\
    \ fault little machine walk stumble urge zoo",
    "dignity pass list indicate nasty swamp pool script soccer toe leaf photo\
    \ multiply desk host tomato cradle drill spread actor shine dismiss\
    \ champion zoo",
    "afford alter spike radar gate glance object seek swamp infant panel\
    \ zoo",
    "indicate race push merry suffer human cruise dwarf pole review arch keep\
    \ canvas theme poem divorce alter zoo",
    "clutch control vehicle tonight unusual clog visa ice plunge glimpse\
    \ recipe series open hour vintage deposit universe tip job dress radar\
    \ refuse motion zoo",
    "turtle front uncle idea crush write shrug there lottery flower risk\
    \ zoo",
    "kiss carry display unusual confirm curtain upgrade antique rotate hello\
    \ void custom frequent obey nut hole price zoo",
    "exile ask congress lamp submit jacket era scheme attend cousin alcohol\
    \ catch course end lucky hurt sentence oven short ball bird grab wing zoo",
    "board flee heavy tunnel powder denial science ski answer betray cargo\
    \ zoo",
    "board blade invite damage undo sun mimic interest slam gaze truly\
    \ inherit resist great inject rocket museum zoo",
    "beyond stage sleep clip because twist token leaf atom beauty genius food\
    \ business side grid unable middle armed observe pair crouch tonight away\
    \ zoo"
  ]

-- | Entropy, sentence, seed with the passphrase "TREZOR" and master key for
-- 20 and 28 bytes of entropy, which the published vectors do not cover.
fifteenAndTwentyOneWordVectors :: [(Text, Mnemonic, Text, Text)]
fifteenAndTwentyOneWordVectors =
  [ ( "0000000000000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
      "fa08713f46bf5cb48728ceb70e3aae1bc53c5cb7b4e29c5610261d1cbb7be3bed4d805256fec515754d2be35974fc5da678168e9d9bb0cb70948026923b0def3",
      "xprv9s21ZrQH143K2nE8x21M7hF4msPN7WC7b6yCn1usVKBA9myCGie4yQCqsw479qmbjXeeRZgMjnNwvWweSCbBeUSPADo2aZbfpkTvJ8de1Qi"
    ),
    ( "ffffffffffffffffffffffffffffffffffffffff",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrist",
      "bfee6f9d2bcfa1331bd6482a24abca521e5f7e769498b9a0146672194c7356e4e409be22bc379c8b64fee2aa24b54d3ec20d10a083eaa5d1d6b4b365941ad37c",
      "xprv9s21ZrQH143K4YQcGfMEpbEoWtj4dJ8aSkUPCXEbg3kWsR8kcdcmhGK3y4swwdjUpyGBfWT9bpizzQJrznSRuFx9K4FKeoNEYT45rLY11Hc"
    ),
    ( "00000000000000000000000000000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
      "e7dadc189d2e8d07ac278d9ec98a1d2d327e4a6b7df494c00cbf2cbf2d3543dac7000fc72d4ada8d9997dc8db388ff22c6d79f604a7455f2df5534a28eee04c6",
      "xprv9s21ZrQH143K3CXWs34yKD87zsm1AVExnEEUnH8rKWqWVguXRprSz8bFFZDbKY7oai19nPTZ68HnW8xX62HFr8WxsNL4CEYmGLcTxAyKNHd"
    ),
    ( "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo veteran",
      "4aa0af4ca02ef1d9fa675cd02aa06d318425564e7fadd3d51b6165cc56d77398f28d8522073cd036c2a4a24a83e919211c84500d96cb120084e613ff5fcd96c1",
      "xprv9s21ZrQH143K4DvgrFvRv4J7m2qehW4MCdmLfRrpAJQFzgVFGi8L9QaapqJPQLyX9SAeGWATu6vXNYmo542LR8yMf4W7DMF1Xgsp96RYWDy"
    )
  ]

-- Vectors from https://github.com/trezor/python-mnemonic/blob/master/vectors.json
trezorVectors :: [(Text, Mnemonic, Text, Text)]
trezorVectors =
  [ ( "00000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
      "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
    ),
    ( "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
      "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
      "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq"
    ),
    ( "80808080808080808080808080808080",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
      "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
      "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq"
    ),
    ( "ffffffffffffffffffffffffffffffff",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
      "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
      "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
    ),
    ( "000000000000000000000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
      "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
      "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU"
    ),
    ( "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
      "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
      "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
      "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7"
    ),
    ( "808080808080808080808080808080808080808080808080",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
      "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
      "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae"
    ),
    ( "ffffffffffffffffffffffffffffffffffffffffffffffff",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
      "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
      "xprv9s21ZrQH143K36Ao5jHRVhFGDbLP6FCx8BEEmpru77ef3bmA928BxsqvVM27WnvvyfWywiFN8K6yToqMaGYfzS6Db1EHAXT5TuyCLBXUfdm"
    ),
    ( "0000000000000000000000000000000000000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
      "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
      "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM"
    ),
    ( "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
      "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
      "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
      "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU"
    ),
    ( "8080808080808080808080808080808080808080808080808080808080808080",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
      "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
      "xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo"
    ),
    ( "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
      "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
      "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB"
    ),
    ( "9e885d952ad362caeb4efe34a8e91bd2",
      "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
      "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
      "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH"
    ),
    ( "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
      "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
      "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
      "xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK"
    ),
    ( "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
      "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
      "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
      "xprv9s21ZrQH143K2XTAhys3pMNcGn261Fi5Ta2Pw8PwaVPhg3D8DWkzWQwjTJfskj8ofb81i9NP2cUNKxwjueJHHMQAnxtivTA75uUFqPFeWzk"
    ),
    ( "c0ba5a8e914111210f2bd131f3d5e08d",
      "scheme spot photo card baby mountain device kick cradle pact join borrow",
      "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
      "xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6"
    ),
    ( "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
      "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
      "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
      "xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt"
    ),
    ( "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
      "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
      "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
      "xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems"
    ),
    ( "23db8160a31d3e0dca3688ed941adbf3",
      "cat swing flag economy stadium alone churn speed unique patch report train",
      "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
      "xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ"
    ),
    ( "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
      "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
      "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
      "xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh"
    ),
    ( "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
      "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
      "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
      "xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm"
    ),
    ( "f30f8c1da665478f49b001d94c5fc452",
      "vessel ladder alter error federal sibling chat ability sun glass valve picture",
      "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
      "xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps"
    ),
    ( "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
      "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
      "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
      "xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYaPUZJhJx8S5j6puX"
    ),
    ( "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
      "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
      "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
      "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"
    )
  ]

binWordsToBS :: (Serialize a) => [a] -> BS.ByteString
binWordsToBS = foldr f BS.empty
  where
    f b a = a `BS.append` encode b

{- Encode mnemonic -}

toMnemonic128 :: (Word64, Word64) -> Bool
toMnemonic128 (a, b) = l == 12
  where
    bs = encode a `BS.append` encode b
    l =
      length
        . T.words
        . fromRight (error "Could not decode mnemonic senttence")
        $ toMnemonic bs

toMnemonic160 :: (Word32, Word64, Word64) -> Bool
toMnemonic160 (a, b, c) = l == 15
  where
    bs = BS.concat [encode a, encode b, encode c]
    l =
      length
        . T.words
        . fromRight (error "Could not decode mnemonic sentence")
        $ toMnemonic bs

toMnemonic256 :: (Word64, Word64, Word64, Word64) -> Bool
toMnemonic256 (a, b, c, d) = l == 24
  where
    bs = BS.concat [encode a, encode b, encode c, encode d]
    l =
      length
        . T.words
        . fromRight (error "Could not decode mnemonic sentence")
        $ toMnemonic bs

-- 64 bytes of entropy are above the 32 bytes BIP39 allows.
toMnemonic512 ::
  ((Word64, Word64, Word64, Word64), (Word64, Word64, Word64, Word64)) -> Bool
toMnemonic512 ((a, b, c, d), (e, f, g, h)) =
  toMnemonic bs == Left "toMnemonic: maximum entropy is 32 bytes (256 bits)"
  where
    bs =
      BS.concat
        [ encode a,
          encode b,
          encode c,
          encode d,
          encode e,
          encode f,
          encode g,
          encode h
        ]

-- Fewer than 4 words of 32 bits are below the 16 bytes BIP39 allows.
toMnemonicTooShort :: Property
toMnemonicTooShort =
  forAll (choose (0, 3) >>= \n -> vectorOf n (arbitrary :: Gen Word32)) $ \ls ->
    toMnemonic (binWordsToBS ls)
      == Left "toMnemonic: minimum entropy is 16 bytes (128 bits)"

-- | Entropy of 16 to 32 bytes in steps of 4 bytes, the sizes BIP39 allows.
allowedEntropy :: Gen BS.ByteString
allowedEntropy = do
  n <- choose (4, 8)
  binWordsToBS <$> vectorOf n (arbitrary :: Gen Word32)

-- Every 32 bits of entropy add one checksum bit, and every 11 bits give a word.
toMnemonicVar :: Property
toMnemonicVar = forAll allowedEntropy $ \bs ->
  let bl = BS.length bs
      wc = (bl * 8 + bl `div` 4) `div` 11
      l =
        length
          . T.words
          . fromRight (error "Could not decode mnemonic sentence")
          $ toMnemonic bs
   in l == wc

{- Encode/Decode -}

fromToMnemonic128 :: (Word64, Word64) -> Bool
fromToMnemonic128 (a, b) = bs == bs'
  where
    bs = encode a `BS.append` encode b
    bs' =
      fromRight
        (error "Could not decode mnemonic entropy")
        (fromMnemonic =<< toMnemonic bs)

fromToMnemonic160 :: (Word32, Word64, Word64) -> Bool
fromToMnemonic160 (a, b, c) = bs == bs'
  where
    bs = BS.concat [encode a, encode b, encode c]
    bs' =
      fromRight
        (error "Could not decode mnemonic entropy")
        (fromMnemonic =<< toMnemonic bs)

fromToMnemonic256 :: (Word64, Word64, Word64, Word64) -> Bool
fromToMnemonic256 (a, b, c, d) = bs == bs'
  where
    bs = BS.concat [encode a, encode b, encode c, encode d]
    bs' =
      fromRight
        (error "Could not decode mnemonic entropy")
        (fromMnemonic =<< toMnemonic bs)

fromToMnemonicVar :: Property
fromToMnemonicVar = forAll allowedEntropy $ \bs ->
  fromRight
    (error "Could not decode mnemonic entropy")
    (fromMnemonic =<< toMnemonic bs)
    == bs

{- Mnemonic to seed -}

mnemonicToSeed128 :: (Word64, Word64) -> Bool
mnemonicToSeed128 (a, b) = l == 64
  where
    bs = encode a `BS.append` encode b
    seed =
      fromRight
        (error "Could not decode mnemonic seed")
        (mnemonicToSeed "" =<< toMnemonic bs)
    l = BS.length seed

mnemonicToSeed160 :: (Word32, Word64, Word64) -> Bool
mnemonicToSeed160 (a, b, c) = l == 64
  where
    bs = BS.concat [encode a, encode b, encode c]
    seed =
      fromRight
        (error "Could not decode mnemonic seed")
        (mnemonicToSeed "" =<< toMnemonic bs)
    l = BS.length seed

mnemonicToSeed256 :: (Word64, Word64, Word64, Word64) -> Bool
mnemonicToSeed256 (a, b, c, d) = l == 64
  where
    bs = BS.concat [encode a, encode b, encode c, encode d]
    seed =
      fromRight
        (error "Could not decode mnemonic seed")
        (mnemonicToSeed "" =<< toMnemonic bs)
    l = BS.length seed

mnemonicToSeedVar :: Property
mnemonicToSeedVar = forAll allowedEntropy $ \bs ->
  BS.length
    ( fromRight
        (error "Could not decode mnemonic seed")
        (mnemonicToSeed "" =<< toMnemonic bs)
    )
    == 64

{- Get bits from ByteString -}

data ByteCountGen = ByteCountGen BS.ByteString Int deriving (Show)

instance Arbitrary ByteCountGen where
  arbitrary = do
    bs <- arbitraryBS
    i <- choose (0, BS.length bs * 8)
    return $ ByteCountGen bs i

getBitsByteCount :: ByteCountGen -> Bool
getBitsByteCount (ByteCountGen bs i) = BS.length bits == l
  where
    (q, r) = i `quotRem` 8
    bits = getBits i bs
    l = if r == 0 then q else q + 1

getBitsEndBits :: ByteCountGen -> Bool
getBitsEndBits (ByteCountGen bs i) =
  (r == 0) || (BS.last bits .&. (0xff `shiftR` r) == 0x00)
  where
    r = i `mod` 8
    bits = getBits i bs
