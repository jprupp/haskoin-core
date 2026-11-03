{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

module Haskoin.Crypto.HashSpec (spec) where

import Control.Exception (evaluate)
import Crypto.Hash (hashFinalize, hashUpdate)
import Data.Bits
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString.Builder
import Data.ByteString.Char8 qualified as Char8
import Data.ByteString.Lazy qualified as Lazy
import Data.ByteString.Short qualified as Short
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Default (def)
import Data.Maybe (fromJust)
import Data.String (fromString)
import Data.String.Conversions
import Data.Text (Text)
import Data.Word
import Haskoin.Block
import Haskoin.Crypto
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.HUnit
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Text.Read (readMaybe)

identityTests :: IdentityTests
identityTests =
  def
    { readTests =
        [ ReadBox arbitraryHash160,
          ReadBox arbitraryHash256,
          ReadBox arbitraryHash512,
          ReadBox arbitraryCheckSum32
        ],
      serialTests =
        [ SerialBox arbitraryHash160,
          SerialBox arbitraryHash256,
          SerialBox arbitraryHash512,
          SerialBox arbitraryCheckSum32
        ]
    }

spec :: Spec
spec =
  describe "Hash" $ do
    testIdentity identityTests
    describe "Property Tests" $ do
      prop "join512( split512(h) ) == h" $
        forAll arbitraryHash256 $
          forAll arbitraryHash256 . joinSplit512
      prop "decodeCompact . encodeCompact i == i" decEncCompact
      prop "from string Hash512" $
        forAll arbitraryHash512 $ \h ->
          fromString (cs $ encodeHex $ runPutS $ serialize h) == h
      prop "from string Hash256" $
        forAll arbitraryHash256 $ \h ->
          fromString (cs $ encodeHex $ runPutS $ serialize h) == h
      prop "from string Hash160" $
        forAll arbitraryHash160 $ \h ->
          fromString (cs $ encodeHex $ runPutS $ serialize h) == h
    describe "Test Vectors" $ do
      it "Passes RIPEMD160 test vectors" $
        mapM_ (testVector ripemd160 (.get)) ripemd160Vectors
      it "Passes SHA1 test vectors" $
        mapM_ (testVector sha1 (.get)) sha1Vectors
      it "Passes SHA256 test vectors" $
        mapM_ (testVector sha256 (.get)) sha256Vectors
      it "Passes SHA512 test vectors" $
        mapM_ (testVector sha512 (.get)) sha512Vectors
      it "Passes HMAC_SHA256 test vectors" $
        mapM_ (testHMACVector hmac256 (.get)) hmacSha256Vectors
      it "Passes HMAC_SHA512 test vectors" $
        mapM_ (testHMACVector hmac512 (.get)) hmacSha512Vectors
    describe "Composite hashes" $ do
      it "double SHA-256 hashes the SHA-256 of the input again" $ do
        -- sha256(sha256("")) and sha256(sha256("abc"))
        doubleSHA256 ("" :: ByteString)
          `shouldBe` "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        doubleSHA256 ("abc" :: ByteString)
          `shouldBe` "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
      it "address hash is the RIPEMD-160 of the SHA-256 of the input" $ do
        addressHash ("" :: ByteString)
          `shouldBe` "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
        addressHash ("abc" :: ByteString)
          `shouldBe` "bb1be98c142444d7a56aa3981c3942a978e4dc33"
      it "32-bit checksum is the first four bytes of the double SHA-256" $
        -- double SHA-256 of "" starts with 5d f6 e0 e2
        (checkSum32 ("" :: ByteString)).get `shouldBe` 0x5df6e0e2
      it "tagged hash is SHA-256 of the hashed tag twice and the message" $ do
        -- sha256(sha256("TapLeaf") || sha256("TapLeaf") || msg), as in BIP340
        taggedHex "TapLeaf" ""
          `shouldBe` "5212c288a377d1f8164962a5a13429f9ba6a7b84e59776a52c6637df2106facb"
        taggedHex "TapLeaf" "abc"
          `shouldBe` "83a56308a9c56f467e8df293da5ae5fdbc85b871952a83c4bf0575ee948ec230"
      it "split512 gives the two halves of a 512-bit hash" $
        -- SHA-512 of "" is cf83e135…d36ce9ce followed by 47d0d13c…f927da3e
        split512 (sha512 ("" :: ByteString))
          `shouldBe` ( "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
                       "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                     )
      it "join512 puts the two halves back together" $
        join512
          ( "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
          )
          `shouldBe` "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                     \47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    describe "Hash text forms" $ do
      it "reads a hash from its hex string" $
        readMaybe "\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\""
          `shouldBe` Just ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" :: Hash256)
      it "refuses to read a hash of the wrong length" $ do
        readMaybe "\"abcd\"" `shouldBe` (Nothing :: Maybe Hash160)
        readMaybe "\"abcd\"" `shouldBe` (Nothing :: Maybe Hash256)
        readMaybe "\"abcd\"" `shouldBe` (Nothing :: Maybe Hash512)
      it "refuses to read a hash that is not hex" $
        readMaybe "\"zz\"" `shouldBe` (Nothing :: Maybe Hash256)
      it "refuses a hash literal of the wrong length" $ do
        evaluate ("abcd" :: Hash160) `shouldThrow` anyErrorCall
        evaluate ("abcd" :: Hash256) `shouldThrow` anyErrorCall
        evaluate ("abcd" :: Hash512) `shouldThrow` anyErrorCall

-- | Hex of the BIP340 tagged hash of a message.
taggedHex :: ByteString -> ByteString -> Text
taggedHex tag msg =
  encodeHex (BA.convert (hashFinalize (hashUpdate (initTaggedHash tag) msg)))

joinSplit512 :: Hash256 -> Hash256 -> Bool
joinSplit512 a b = split512 (join512 (a, b)) == (a, b)

-- After encoding and decoding, we may loose precision so the new result is >=
-- to the old one.
decEncCompact :: Integer -> Bool
decEncCompact i
  -- Integer completely fits inside the mantisse
  | abs i <= 0x007fffff = decodeCompact (encodeCompact i) == (i, False)
  -- Otherwise precision will be lost and the decoded result will
  -- be smaller than the original number
  | i >= 0 = fst (decodeCompact (encodeCompact i)) < i
  | otherwise = fst (decodeCompact (encodeCompact i)) > i

-- Test vectors from:
-- https://github.com/bitcoin/bitcoin/blob/master/src/test/crypto_tests.cpp

testVector ::
  (ByteString -> a) ->
  (a -> Short.ShortByteString) ->
  (ByteString, Text) ->
  Assertion
testVector f1 f2 (i, res) =
  assertEqual "Hash matches" res (encodeHex (Short.fromShort $ f2 $ f1 i))

testHMACVector ::
  (ByteString -> ByteString -> a) ->
  (a -> Short.ShortByteString) ->
  (Text, Text, Text) ->
  Assertion
testHMACVector f1 f2 (k, m, res) =
  assertEqual "Hash matches" res (encodeHex (Short.fromShort $ f2 $ f1 bsK bsM))
  where
    bsK = fromJust $ decodeHex k
    bsM = fromJust $ decodeHex m

longTestString :: ByteString
longTestString =
  Lazy.toStrict $! toLazyByteString $! go [0 .. 199999]
  where
    go :: [Word32] -> Builder
    go [] = mempty
    go (i : is) =
      let i1 = fromIntegral $! i
          i2 = fromIntegral $! i `shiftR` 4
          i3 = fromIntegral $! i `shiftR` 8
          i4 = fromIntegral $! i `shiftR` 12
          i5 = fromIntegral $! i `shiftR` 16
       in word8 i1 <> word8 i2 <> word8 i3 <> word8 i4 <> word8 i5 <> go is

ripemd160Vectors :: [(ByteString, Text)]
ripemd160Vectors =
  [ ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    ("secure hash algorithm", "20397528223b6a5f4cbc2808aba0464e645544f9"),
    ( "RIPEMD160 is considered to be safe",
      "a7d78608c7af8a8e728778e81576870734122b66"
    ),
    ( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "12a053384a9c0c88e405a06c27dcf49ada62eb2b"
    ),
    ( "For this sample, this 63-byte string will be used as input data",
      "de90dbfee14b63fb5abf27c2ad4a82aaa5f27a11"
    ),
    ( "This is exactly 64 bytes long, not counting the terminating byte",
      "eda31d51d3a623b81e19eb02e24ff65d27d67b37"
    ),
    (Char8.replicate 1000000 'a', "52783243c1697bdbe16d37f97f68f08325dc1528"),
    (longTestString, "464243587bd146ea835cdf57bdae582f25ec45f1")
  ]

sha1Vectors :: [(ByteString, Text)]
sha1Vectors =
  [ ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    ("message digest", "c12252ceda8be8994d5fa0290a47231c1d16aae3"),
    ("secure hash algorithm", "d4d6d2f0ebe317513bbd8d967d89bac5819c2f60"),
    ( "SHA1 is considered to be safe",
      "f2b6650569ad3a8720348dd6ea6c497dee3a842a"
    ),
    ( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    ),
    ( "For this sample, this 63-byte string will be used as input data",
      "4f0ea5cd0585a23d028abdc1a6684e5a8094dc49"
    ),
    ( "This is exactly 64 bytes long, not counting the terminating byte",
      "fb679f23e7d1ce053313e66e127ab1b444397057"
    ),
    (Char8.replicate 1000000 'a', "34aa973cd4c4daa4f61eeb2bdbad27316534016f"),
    (longTestString, "b7755760681cbfd971451668f32af5774f4656b5")
  ]

sha256Vectors :: [(ByteString, Text)]
sha256Vectors =
  [ ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ( "abc",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    ),
    ( "message digest",
      "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"
    ),
    ( "secure hash algorithm",
      "f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d"
    ),
    ( "SHA256 is considered to be safe",
      "6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630"
    ),
    ( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    ),
    ( "For this sample, this 63-byte string will be used as input data",
      "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342"
    ),
    ( "This is exactly 64 bytes long, not counting the terminating byte",
      "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8"
    ),
    ( "As Bitcoin relies on 80 byte header hashes, we want to have an example for that.",
      "7406e8de7d6e4fffc573daef05aefb8806e7790f55eab5576f31349743cca743"
    ),
    ( Char8.replicate 1000000 'a',
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    ),
    ( longTestString,
      "a316d55510b49662420f49d145d42fb83f31ef8dc016aa4e32df049991a91e26"
    )
  ]

sha512Vectors :: [(ByteString, Text)]
sha512Vectors =
  [ ( "",
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d1\
      \3c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    ),
    ( "abc",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a219299\
      \2a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    ),
    ( "message digest",
      "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e164\
      \55ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c"
    ),
    ( "secure hash algorithm",
      "7746d91f3de30c68cec0dd693120a7e8b04d8073cb699bdce1a3f64127bca7a3d5db50\
      \2e814bb63c063a7a5043b2df87c61133395f4ad1edca7fcf4b30c3236e"
    ),
    ( "SHA512 is considered to be safe",
      "099e6468d889e1c79092a89ae925a9499b5408e01b66cb5b0a3bd0dfa51a99646b4a39\
      \01caab1318189f74cd8cf2e941829012f2449df52067d3dd5b978456c2"
    ),
    ( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15\
      \c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
    ),
    ( "For this sample, this 63-byte string will be used as input data",
      "b3de4afbc516d2478fe9b518d063bda6c8dd65fc38402dd81d1eb7364e72fb6e6663cf\
      \6d2771c8f5a6da09601712fb3d2a36c6ffea3e28b0818b05b0a8660766"
    ),
    ( "This is exactly 64 bytes long, not counting the terminating byte",
      "70aefeaa0e7ac4f8fe17532d7185a289bee3b428d950c14fa8b713ca09814a387d2458\
      \70e007a80ad97c369d193e41701aa07f3221d15f0e65a1ff970cedf030"
    ),
    ( "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmn\
      \opjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d28\
      \9e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    ),
    ( Char8.replicate 1000000 'a',
      "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff2\
      \44877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    ),
    ( longTestString,
      "40cac46c147e6131c5193dd5f34e9d8bb4951395f27b08c558c65ff4ba2de59437de8c\
      \3ef5459d76a52cedc02dc499a3c9ed9dedbfb3281afd9653b8a112fafc"
    )
  ]

-- test cases 1, 2, 3, 4, 6 and 7 of RFC 4231
hmacSha256Vectors :: [(Text, Text, Text)]
hmacSha256Vectors =
  [ ( "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "4869205468657265",
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    ),
    ( "4a656665",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    ),
    ( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
      \dddddddddddddddddddddddddddddd",
      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    ),
    ( "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
      \cdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
    ),
    ( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b\
      \6579202d2048617368204b6579204669727374",
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    ),
    ( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "5468697320697320612074657374207573696e672061206c6172676572207468616e20\
      \626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c\
      \6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520\
      \686173686564206265666f7265206265696e6720757365642062792074686520484d41\
      \4320616c676f726974686d2e",
      "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    ),
    -- Test case with key length 63 bytes.

    ( "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566\
      \654a6566654a6566654a6566654a6566654a6566654a6566654a6566",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "9de4b546756c83516720a4ad7fe7bdbeac4298c6fdd82b15f895a6d10b0769a6"
    ),
    -- Test case with key length 64 bytes.

    ( "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566\
      \654a6566654a6566654a6566654a6566654a6566654a6566654a656665",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "528c609a4c9254c274585334946b7c2661bad8f1fc406b20f6892478d19163dd"
    ),
    -- Test case with key length 65 bytes.

    ( "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566\
      \654a6566654a6566654a6566654a6566654a6566654a6566654a6566654a",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "d06af337f359a2330deffb8e3cbe4b5b7aa8ca1f208528cdbd245d5dc63c4483"
    )
  ]

-- test cases 1, 2, 3, 4, 6 and 7 of RFC 4231
hmacSha512Vectors :: [(Text, Text, Text)]
hmacSha512Vectors =
  [ ( "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "4869205468657265",
      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
      \daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    ),
    ( "4a656665",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
      \9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
    ),
    ( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
      \dddddddddddddddddddddddddddddddddddd",
      "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
      \bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
    ),
    ( "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
      \cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
      \a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
    ),
    ( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaa",
      "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a\
      \65204b6579202d2048617368204b6579204669727374",
      "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
      \6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
    ),
    ( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
      \aaaaaa",
      "5468697320697320612074657374207573696e672061206c6172676572207468\
      \616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074\
      \68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565\
      \647320746f20626520686173686564206265666f7265206265696e6720757365\
      \642062792074686520484d414320616c676f726974686d2e",
      "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
      \b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
    ),
    -- Test case with key length 127 bytes.

    ( "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665\
      \4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665\
      \4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665\
      \4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "267424dfb8eeb999f3e5ec39a4fe9fd14c923e6187e0897063e5c9e02b2e624a\
      \c04413e762977df71a9fb5d562b37f89dfdfb930fce2ed1fa783bbc2a203d80e"
    ),
    -- Test case with key length 128 bytes.

    ( "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665\
      \4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665\
      \4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665\
      \4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "43aaac07bb1dd97c82c04df921f83b16a68d76815cd1a30d3455ad43a3d80484\
      \2bb35462be42cc2e4b5902de4d204c1c66d93b47d1383e3e13a3788687d61258"
    ),
    -- Test case with key length 129 bytes.

    ( "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665\
      \4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665\
      \4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665\
      \4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665\
      \4a",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "0b273325191cfc1b4b71d5075c8fcad67696309d292b1dad2cd23983a35feb8e\
      \fb29795e79f2ef27f68cb1e16d76178c307a67beaad9456fac5fdffeadb16e2c"
    )
  ]
