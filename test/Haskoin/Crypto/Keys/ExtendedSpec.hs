{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

module Haskoin.Crypto.Keys.ExtendedSpec (spec) where

import Control.Exception (evaluate)
import Control.Monad (forM_)
import Data.Aeson as A
import Data.Bits ((.&.))
import Data.ByteString qualified as B
import Data.ByteString.Lazy.Char8 qualified as B8
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Default (def)
import Data.Either (isLeft)
import Data.Maybe (fromJust, isJust, isNothing)
import Data.Ord (comparing)
import Data.String (fromString)
import Data.String.Conversions (cs)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Word (Word32)
import Haskoin.Address
import Haskoin.Crypto
import Haskoin.Network.Constants
import Haskoin.Script
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.HUnit
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck hiding ((.&.))
import Text.Read (readMaybe)

identityTests :: Ctx -> IdentityTests
identityTests ctx =
  def
    { readTests =
        [ ReadBox (arbitraryXPubKey ctx),
          ReadBox arbitraryDerivPath,
          ReadBox arbitraryHardPath,
          ReadBox arbitrarySoftPath,
          ReadBox arbitraryParsedPath,
          ReadBox arbitraryBip32PathIndex
        ],
      jsonTests =
        [ JsonBox arbitraryDerivPath,
          JsonBox arbitraryHardPath,
          JsonBox arbitrarySoftPath,
          JsonBox arbitraryParsedPath
        ],
      marshalJsonTests =
        [ MarshalJsonBox $ (,) <$> arbitraryNetwork <*> arbitraryXPrvKey,
          MarshalJsonBox $
            (,) <$> ((,ctx) <$> arbitraryNetwork) <*> arbitraryXPubKey ctx
        ],
      serialTests =
        [ SerialBox arbitraryDerivPath,
          SerialBox arbitraryHardPath,
          SerialBox arbitrarySoftPath
        ],
      marshalTests =
        [ MarshalBox $ (,) <$> arbitraryNetwork <*> arbitraryXPrvKey,
          MarshalBox $
            (,) <$> ((,ctx) <$> arbitraryNetwork) <*> arbitraryXPubKey ctx
        ]
    }

spec :: Spec
spec = prepareContext $ \ctx -> do
  testIdentity $ identityTests ctx
  describe "Custom identity tests" $ do
    prop "encodes and decodes extended private key" $
      forAll arbitraryNetwork $ \net ->
        forAll arbitraryXPrvKey $
          customCerealID (marshalGet net) (marshalPut net)
    prop "encodes and decodes extended public key" $
      forAll arbitraryNetwork $ \net ->
        forAll (arbitraryXPubKey ctx) $
          customCerealID (marshalGet (net, ctx)) (marshalPut (net, ctx))
  describe "bip32 subkey derivation vector 1" $ vectorSpec ctx m1 vector1
  describe "bip32 subkey derivation vector 2" $ vectorSpec ctx m2 vector2
  describe "bip32 subkey derivation vector 3" $ vectorSpec ctx m3 vector3
  describe "bip32 test vector 4: private keys with leading zeros" $
    forM_ vector4 $ \(path, xpubText, xprvText) ->
      it ("chain " <> path) $ do
        let m = makeXPrvKey (fromJust (decodeHex m4))
            k = derivePath ctx ((.get) (fromJust (parsePath path))) m
        xPrvExport btc k `shouldBe` xprvText
        xPubExport btc ctx (deriveXPubKey ctx k) `shouldBe` xpubText
  describe "bip32 test vector 5: invalid extended keys" $
    forM_ vector5 $ \(key, reason) ->
      it ("refuses " <> reason) $ do
        xPrvImport btc key `shouldBe` Nothing
        xPubImport btc ctx key `shouldBe` Nothing
  describe "Extended key import" $ do
    it "refuses an xpub with trailing bytes" $
      -- the 78 bytes of the vector 1 master xpub followed by de ad be ef
      xPubImport btc ctx "7JJikZQ2NUXjSAnAF2v9rxutS1j84JbPJspH9roCjFfNvxFfhmgTczN53frJ4RaYoKmwYCj5r1qRsGbLz2fiUE4Aw7LqCR9NYxR72w6AThhWJsB43ZrGA"
        `shouldBe` Nothing
    it "refuses an xprv with trailing bytes" $
      xPrvImport btc "7JJRGiiVuW9DCAkyM2PaXqVx51tHCM3s2Wbq9SnmstZD4r8Ryf4i7Dbe2YQyz9mUF9oZEcdkyzU96dsBwJz3Uvu6PzVTC5k53mBrVHWxZMPdSBtmunEjn"
        `shouldBe` Nothing
    it "refuses an xpub carrying an uncompressed public key" $
      -- 110 bytes: the vector 1 master xpub with its key in the 65-byte form
      xPubImport btc ctx "HarqLWPftSVzTwufEPMMMdZS33daVnF1pMQCFXEQoWwsd7tK1oCwB34reM1xTwhKvY11Pfgite2BcpvEDscYTtuZYL3pZAwQzAoZRLA1xCjK2F28jNBa3muZtLmsqfWHzwSGk2RRAd1e52SvdFecN97hmfA"
        `shouldBe` Nothing
    it "refuses a string longer than any extended key" $ do
      xPrvImport btc (T.replicate 113 "z") `shouldBe` Nothing
      xPubImport btc ctx (T.replicate 113 "z") `shouldBe` Nothing
    it "refuses an extended key of another network" $ do
      xPrvImport btcTest xprv1Text `shouldBe` Nothing
      xPrvImport btc tprv1Text `shouldBe` Nothing
      xPubImport btcTest ctx xpub1Text `shouldBe` Nothing
      xPubImport btc ctx tpub1Text `shouldBe` Nothing
    it "imports the testnet form of a key on testnet" $ do
      fmap (.key) (xPrvImport btcTest tprv1Text) `shouldBe` Just (xprv1 ctx).key
      fmap (.key) (xPubImport btcTest ctx tpub1Text) `shouldBe` Just (xpub1 ctx).key
    it "refuses an xpub given to the private key importer, and the reverse" $ do
      xPrvImport btc xpub1Text `shouldBe` Nothing
      xPubImport btc ctx xprv1Text `shouldBe` Nothing
    it "fails the JSON parse of an invalid extended key" $
      -- BIP32 test vector 5: private key 0
      (unmarshalJSON btc "\"xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx\"" :: Maybe XPrvKey)
        `shouldBe` Nothing
  describe "Master key" $
    it "has depth 0, no parent and index 0" $ do
      let m = makeXPrvKey (fromJust (decodeHex m1))
      m.depth `shouldBe` 0
      m.parent `shouldBe` "00000000"
      m.index `shouldBe` 0
  describe "Showing an extended private key" $
    -- The master key of vector 1 has fingerprint 3442193e; its hardened
    -- child 7 has index 2^31 + 7 = 2147483655
    it "shows the depth, parent and index but not the chain code or the key" $ do
      let m = makeXPrvKey (fromJust (decodeHex m1))
      show m `shouldBe` "XPrvKey {depth = 0, parent = \"00000000\", index = 0, chain = <redacted>, key = <redacted>}"
      show (hardSubKey ctx m 7) `shouldBe` "XPrvKey {depth = 1, parent = \"3442193e\", index = 2147483655, chain = <redacted>, key = <redacted>}"
      show (Just m) `shouldBe` "Just (XPrvKey {depth = 0, parent = \"00000000\", index = 0, chain = <redacted>, key = <redacted>})"
  describe "Derivation depth" $ do
    let m = makeXPrvKey (fromJust (decodeHex m1))
        atDepth255 = XPrvKey 255 m.parent m.index m.chain m.key
        tooDeep = DerivationException "Maximum derivation depth exceeded"
        hardIndex = DerivationException "Invalid child derivation index"
    it "a child is one level deeper than its parent" $ do
      (prvSubKey ctx m 0).depth `shouldBe` 1
      (hardSubKey ctx m 0).depth `shouldBe` 1
      (pubSubKey ctx (deriveXPubKey ctx m) 0).depth `shouldBe` 1
      (derivePath ctx (Deriv :| 0 :/ 1 :/ 2 :: DerivPath) m).depth `shouldBe` 3
    it "refuses to derive a child of a key at depth 255" $ do
      evaluate (prvSubKey ctx atDepth255 0) `shouldThrow` (== tooDeep)
      evaluate (hardSubKey ctx atDepth255 0) `shouldThrow` (== tooDeep)
      evaluate (pubSubKey ctx (deriveXPubKey ctx atDepth255) 0) `shouldThrow` (== tooDeep)
    it "refuses a child index with the hard bit set with a DerivationException" $ do
      evaluate (prvSubKey ctx m 0x80000000) `shouldThrow` (== hardIndex)
      evaluate (hardSubKey ctx m 0x80000000) `shouldThrow` (== hardIndex)
      evaluate (pubSubKey ctx (deriveXPubKey ctx m) 0x80000000) `shouldThrow` (== hardIndex)
  describe "Child index" $ do
    let m = makeXPrvKey (fromJust (decodeHex m1))
    it "a hardened child stores its index with the hard bit set" $ do
      let k = hardSubKey ctx m 7
      k.index `shouldBe` 0x80000007
      xPrvChild k `shouldBe` 7
      xPrvIsHard k `shouldBe` True
      xPubChild (deriveXPubKey ctx k) `shouldBe` 7
      xPubIsHard (deriveXPubKey ctx k) `shouldBe` True
    it "a soft child stores its index as given" $ do
      let k = prvSubKey ctx m 7
      k.index `shouldBe` 7
      xPrvChild k `shouldBe` 7
      xPrvIsHard k `shouldBe` False
      xPubChild (deriveXPubKey ctx k) `shouldBe` 7
      xPubIsHard (deriveXPubKey ctx k) `shouldBe` False
  describe "Addresses of an extended public key" $ do
    -- BIP32 vector 1 master public key 0339a360…85c2 has HASH160 3442193e…f811
    it "pay to public key hash" $
      addrToText btc (xPubAddr ctx (xpub1 ctx)) `shouldBe` Just "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"
    it "pay to witness public key hash" $
      addrToText btc (xPubWitnessAddr ctx (xpub1 ctx)) `shouldBe` Just "bc1qx3ppj0smkuy3d6g525sh9n2w9k7fm7q3x30rtg"
    it "pay to script hash wrapping a witness public key hash" $
      addrToText btc (xPubCompatWitnessAddr ctx (xpub1 ctx)) `shouldBe` Just "3PpgpssV7mcAGpZRWiCWhodUTnjpoSZg7a"
  describe "Address derivation helpers" $ do
    -- BIP32 vector 2: child 0 of the master key has public key 02fc9e5a…12ea
    it "deriveAddr gives the address and the public key of the child" $ do
      let (addr, key) = deriveAddr ctx (xpub2 ctx) 0
      addrToText btc addr `shouldBe` Just "19EuDJdgfRkwCmRzbzVBHZWQG9QNWhftbZ"
      encodeHex (exportPubKey ctx True key)
        `shouldBe` "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
    it "deriveWitnessAddr gives the witness address of the child" $
      addrToText btc (fst (deriveWitnessAddr ctx (xpub2 ctx) 0))
        `shouldBe` Just "bc1qtfsllr4h4t9rqyxmjl4a5asjzcgt0qykp3q3we"
    it "deriveCompatWitnessAddr gives the wrapped witness address of the child" $
      addrToText btc (fst (deriveCompatWitnessAddr ctx (xpub2 ctx) 0))
        `shouldBe` Just "39cFMGtVaEw6AfksMcaLpu8frZxmqngh8c"
    it "deriveAddrs lists children from the start index and wraps around" $ do
      map lst3 (take 3 (deriveAddrs ctx (xpub2 ctx) 0x7ffffffe))
        `shouldBe` [0x7ffffffe, 0x7fffffff, 0]
      map addressAndIndex (take 1 (deriveAddrs ctx (xpub2 ctx) 5))
        `shouldBe` [(Just "16KmCWXw8kPgr9nnvETXoqzmsYcvscXfGL", 5)]
    it "deriveWitnessAddrs lists witness addresses with their index" $
      map addressAndIndex (take 1 (deriveWitnessAddrs ctx (xpub2 ctx) 5))
        `shouldBe` [(Just "bc1q8fjs9hakl9489q0fem0gya4m8yqr4gl32dhjr9", 5)]
    it "deriveCompatWitnessAddrs lists wrapped witness addresses with their index" $
      map addressAndIndex (take 1 (deriveCompatWitnessAddrs ctx (xpub2 ctx) 5))
        `shouldBe` [(Just "3FzrsDTC8KiEsBeBTrhDnJoJYvkDpWaWR6", 5)]
    it "prvSubKeys, pubSubKeys and hardSubKeys list children with their index" $ do
      let m = makeXPrvKey (fromJust (decodeHex m1))
      map snd (take 3 (prvSubKeys ctx m 0x7ffffffe)) `shouldBe` [0x7ffffffe, 0x7fffffff, 0]
      map snd (take 2 (hardSubKeys ctx m 0)) `shouldBe` [0, 1]
      map ((.index) . fst) (take 1 (hardSubKeys ctx m 1)) `shouldBe` [0x80000001]
      map (\(k, i) -> (addrToText btc (xPubAddr ctx k), i)) (take 1 (pubSubKeys ctx (xpub2 ctx) 0))
        `shouldBe` [(Just "19EuDJdgfRkwCmRzbzVBHZWQG9QNWhftbZ", 0)]
    it "cycleIndex runs through the soft indices from the start and wraps around" $ do
      take 3 (cycleIndex 0x7ffffffe) `shouldBe` [0x7ffffffe, 0x7fffffff, 0]
      take 2 (cycleIndex 0) `shouldBe` [0, 1]
      evaluate (cycleIndex 0x80000000) `shouldThrow` (== DerivationException "cycleIndex: invalid index 2147483648")
  describe "Multisig derivation" $ do
    -- 2-of-2 of child 0 of vectors 1 and 2; sorted keys 027c4b09… then 02fc9e5a…
    it "deriveMSAddr gives the P2SH address of the sorted multisig script" $ do
      let (addr, rdm) = deriveMSAddr ctx [xpub2 ctx, xpub1 ctx] 2 0
      addrToText btc addr `shouldBe` Just "3ARSZ47cqQBb9y6QhTk6UoWHMwpruUryZp"
      encodeHex (marshal ctx rdm)
        `shouldBe` "5221027c4b09ffb985c298afe7e5813266cbfcb7780b480ac294b0b43dc21f2be3d13c\
                   \2102fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea52ae"
    it "deriveMSAddrs lists multisig addresses with their index" $ do
      map lst3 (take 2 (deriveMSAddrs ctx [xpub1 ctx, xpub2 ctx] 2 0)) `shouldBe` [0, 1]
      -- 2-of-2 of child 1 of vectors 1 and 2
      map addressAndIndex (take 1 (deriveMSAddrs ctx [xpub1 ctx, xpub2 ctx] 2 1))
        `shouldBe` [(Just "3Pp8RkaJc8eNreFuTTTJ92QfXECQMXDEoE", 1)]
  describe "Address derivation below a path" $ do
    -- vector 2: m/0/0 has public key 0205c889…ef8c
    it "derivePathAddr derives the address of a child below a soft path" $ do
      let (addr, key) = derivePathAddr ctx (xpub2 ctx) (Deriv :/ 0) 0
      addrToText btc addr `shouldBe` Just "1NyMg76BQxDvV6vRsQugNS4ED2hpZCJtwK"
      encodeHex (exportPubKey ctx True key)
        `shouldBe` "0205c8897fd0ff5644adba4545a84020cd6aa94d90e1e0a56bb4b8eb7522e3ef8c"
    it "derivePathAddrs lists children below the path with their index" $
      map addressAndIndex (take 1 (derivePathAddrs ctx (xpub2 ctx) (Deriv :/ 0) 0))
        `shouldBe` [(Just "1NyMg76BQxDvV6vRsQugNS4ED2hpZCJtwK", 0)]
    it "derivePathMSAddr derives a multisig address below a soft path" $ do
      -- 2-of-2 of m/1/0 of vectors 1 and 2
      let (addr, _) = derivePathMSAddr ctx [xpub1 ctx, xpub2 ctx] (Deriv :/ 1) 2 0
      addrToText btc addr `shouldBe` Just "39HHTbxsnt5SrM4h2BtUgVRFzGYcavJ8M4"
    it "derivePathMSAddrs lists multisig addresses below the path with their index" $
      map addressAndIndex (take 1 (derivePathMSAddrs ctx [xpub1 ctx, xpub2 ctx] (Deriv :/ 1) 2 0))
        `shouldBe` [(Just "39HHTbxsnt5SrM4h2BtUgVRFzGYcavJ8M4", 0)]
  describe "Path operations" $ do
    it "++/ appends two paths into a mixed path" $ do
      let p = (Deriv :| 44 :| 0 :: HardPath) ++/ (Deriv :/ 0 :/ 5 :: SoftPath)
      p `shouldBe` (Deriv :| 44 :| 0 :/ 0 :/ 5)
      pathToStr p `shouldBe` "/44'/0'/0/5"
    it "toHard keeps a path only when every segment is hardened" $ do
      toHard (Deriv :| 1 :| 2 :: DerivPath) `shouldBe` Just (Deriv :| 1 :| 2)
      toHard (Deriv :| 1 :/ 2 :: DerivPath) `shouldBe` Nothing
    it "toSoft keeps a path only when no segment is hardened" $ do
      toSoft (Deriv :/ 1 :/ 2 :: DerivPath) `shouldBe` Just (Deriv :/ 1 :/ 2)
      toSoft (Deriv :| 1 :/ 2 :: DerivPath) `shouldBe` Nothing
    it "toGeneric keeps every segment" $ do
      toGeneric (Deriv :| 1 :| 2 :: HardPath) `shouldBe` (Deriv :| 1 :| 2)
      toGeneric (Deriv :/ 1 :/ 2 :: SoftPath) `shouldBe` (Deriv :/ 1 :/ 2)
    it "writes hardened segments with an apostrophe" $ do
      pathToStr (Deriv :| 44 :/ 0 :: DerivPath) `shouldBe` "/44'/0"
      show (ParsedPrv (Deriv :| 44 :/ 0)) `shouldBe` "ParsedPath \"m/44'/0\""
      show (ParsedPub (Deriv :| 44 :/ 0)) `shouldBe` "ParsedPath \"M/44'/0\""
    it "pathToList sets the hard bit on hardened segments" $
      pathToList (Deriv :| 1 :/ 2 :: DerivPath) `shouldBe` [0x80000001, 2]
    it "listToPath reads the hard bit back" $
      listToPath [0x80000001, 2] `shouldBe` (Deriv :| 1 :/ 2)
    it "serializes a path as a count and its indices with the hard bit" $
      runPutS (serialize (Deriv :| 1 :/ 2 :: DerivPath))
        `shouldBe` hex "0000000000000002" <> hex "80000001" <> hex "00000002"
    it "binary hard path refuses a soft segment" $
      (runGetS deserialize (hex "0000000000000001" <> hex "00000001") :: Either String HardPath)
        `shouldSatisfy` isLeft
    it "binary soft path refuses a hardened segment" $
      (runGetS deserialize (hex "0000000000000001" <> hex "80000001") :: Either String SoftPath)
        `shouldSatisfy` isLeft
    it "sorts a shorter path first, then by segment, soft before hard" $ do
      (Deriv :/ 9 :: DerivPath) < (Deriv :/ 0 :/ 1) `shouldBe` True
      (Deriv :/ 5 :: DerivPath) < (Deriv :| 0) `shouldBe` True
      (Deriv :/ 1 :: DerivPath) < (Deriv :/ 2) `shouldBe` True
    prop "ordering agrees with the shortlex order of the index lists" $
      forAll arbitraryDerivPath $ \a ->
        forAll arbitraryDerivPath $ \b ->
          compare a b == comparing (\p -> (length (pathToList p), pathToList p)) a b
  describe "Path parsing" $ do
    it "accepts the apostrophe, h and H as hardened markers" $ do
      parsePath "m/44h/0H/1'" `shouldBe` Just (ParsedPrv (Deriv :| 44 :| 0 :| 1))
      parseHard "m/44h/0H" `shouldBe` Just (Deriv :| 44 :| 0)
      (fromString "m/44h/0H/1" :: DerivPath) `shouldBe` (Deriv :| 44 :| 0 :/ 1)
    it "accepts the largest index, 2^31 - 1" $
      parsePath "m/2147483647'" `shouldBe` Just (ParsedPrv (Deriv :| 2147483647))
    it "refuses an index that does not fit in 31 bits instead of wrapping it" $ do
      parsePath "m/2147483648" `shouldBe` Nothing
      parsePath "m/4294967296" `shouldBe` Nothing -- 2^32, would wrap to 0
      parsePath "m/4294967297'" `shouldBe` Nothing -- 2^32 + 1, would wrap to 1
      parsePath "m/-4294967295" `shouldBe` Nothing -- would wrap to 1
      parsePath "m/18446744073709551617" `shouldBe` Nothing -- 2^64 + 1
    it "refuses anything but decimal digits in an index" $ do
      parsePath "m/0x10" `shouldBe` Nothing
      parsePath "m/(7)" `shouldBe` Nothing
      parsePath "m/+1" `shouldBe` Nothing
      parsePath "m/1e3" `shouldBe` Nothing
      parsePath "m/ 1" `shouldBe` Nothing
      parsePath "m/1 " `shouldBe` Nothing
      parsePath "m/1''" `shouldBe` Nothing
      parsePath "m/'" `shouldBe` Nothing
    it "refuses empty segments" $ do
      parsePath "m/" `shouldBe` Nothing
      parsePath "m//1" `shouldBe` Nothing
      parsePath "m/1/" `shouldBe` Nothing
    it "fails the JSON parse of an out-of-range index" $
      (A.decode "[\"m/4294967296\"]" :: Maybe [DerivPath]) `shouldBe` Nothing
    it "refuses to read a path index that does not fit in 31 bits" $
      readMaybe "Bip32SoftIndex 4294967296" `shouldBe` (Nothing :: Maybe Bip32PathIndex)
  describe "Fingerprint text" $ do
    -- the identifier of the vector 1 master key starts with 3442193e
    it "writes eight hex digits" $
      fingerprintToText (xPubFP ctx (xpub1 ctx)) `shouldBe` "3442193e"
    it "reads eight hex digits" $
      textToFingerprint "3442193e" `shouldBe` Right (xPubFP ctx (xpub1 ctx))
    it "refuses more or fewer than four bytes" $ do
      textToFingerprint "0011223344" `shouldSatisfy` isLeft
      textToFingerprint "001122" `shouldSatisfy` isLeft
      textToFingerprint "" `shouldSatisfy` isLeft
    it "refuses text that is not hex" $
      textToFingerprint "zzzzzzzz" `shouldSatisfy` isLeft
    it "parses from JSON and refuses the wrong length" $ do
      A.decode "\"3442193e\"" `shouldBe` Just (xPubFP ctx (xpub1 ctx))
      (A.decode "\"0011223344\"" :: Maybe Fingerprint) `shouldBe` Nothing
    it "refuses to read the wrong length" $
      readMaybe "\"0011223344\"" `shouldBe` (Nothing :: Maybe Fingerprint)
    it "refuses a literal of the wrong length" $
      evaluate ("0011223344" :: Fingerprint) `shouldThrow` anyErrorCall
  describe "bip32 subkey derivation using string path" $ do
    it "either derivations" $ testApplyPath ctx
    it "either derivations" $ testBadApplyPath ctx
    it "dublic derivations" $ testDerivePubPath ctx
    it "private derivations" $ testDerivePrvPath ctx
    it "path parsing" testParsePath
    it "from json" testFromJsonPath
    it "to json" testToJsonPath
  describe "Derivation Paths" $ do
    prop "from string derivation path" $
      forAll arbitraryDerivPath $
        \p -> fromString (cs $ pathToStr p) == p
    prop "from string hard derivation path" $
      forAll arbitraryHardPath $
        \p -> fromString (cs $ pathToStr p) == p
    prop "from string soft derivation path" $
      forAll arbitrarySoftPath $
        \p -> fromString (cs $ pathToStr p) == p
    prop "from and to lists of derivation paths" $
      forAll arbitraryDerivPath $
        \p -> listToPath (pathToList p) == p
    prop "from and to lists of hard derivation paths" $
      forAll arbitraryHardPath $ \p ->
        toHard (listToPath $ pathToList p) == Just p
    prop "from and to lists of soft derivation paths" $
      forAll arbitrarySoftPath $ \p ->
        toSoft (listToPath $ pathToList p) == Just p
  describe "Extended Keys" $ do
    let net = btc
    prop "computes pubkey of a subkey is subkey of the pubkey" $
      -- a key at depth 255 cannot have children
      forAll (arbitraryXPrvKey `suchThat` ((< 255) . (.depth))) $
        pubKeyOfSubKeyIsSubKeyOfPubKey ctx
    prop "exports and imports extended private key" $
      forAll arbitraryXPrvKey $ \k ->
        xPrvImport net (xPrvExport net k) == Just k
    prop "exports and imports extended public key" $
      forAll (arbitraryXPubKey ctx) $ \k ->
        xPubImport net ctx (xPubExport net ctx k) == Just k

hex :: Text -> B.ByteString
hex = fromJust . decodeHex

-- | The address text and the index of an entry of a derivation list.
addressAndIndex :: (Address, a, KeyIndex) -> (Maybe Text, KeyIndex)
addressAndIndex (addr, _, i) = (addrToText btc addr, i)

-- | Master keys of BIP32 test vectors 1 and 2, and the testnet form of the
-- first.
xpub1Text, xprv1Text, tpub1Text, tprv1Text, xpub2Text :: Text
xpub1Text = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
xprv1Text = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
tpub1Text = "tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp"
tprv1Text = "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWSFhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m"
xpub2Text = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

xpub1, xpub2 :: Ctx -> XPubKey
xpub1 ctx = fromJust (xPubImport btc ctx xpub1Text)
xpub2 ctx = fromJust (xPubImport btc ctx xpub2Text)

xprv1 :: Ctx -> XPrvKey
xprv1 _ = fromJust (xPrvImport btc xprv1Text)

pubKeyOfSubKeyIsSubKeyOfPubKey :: Ctx -> XPrvKey -> Word32 -> Bool
pubKeyOfSubKeyIsSubKeyOfPubKey ctx k i =
  deriveXPubKey ctx (prvSubKey ctx k i') == pubSubKey ctx (deriveXPubKey ctx k) i'
  where
    i' = fromIntegral $ i .&. 0x7fffffff -- make it a public derivation

testFromJsonPath :: Assertion
testFromJsonPath =
  sequence_ $ do
    path <- jsonPathVectors
    return $
      assertEqual
        path
        (Just [fromString path :: DerivPath])
        (A.decode $ B8.pack $ "[\"" ++ path ++ "\"]")

testToJsonPath :: Assertion
testToJsonPath =
  sequence_ $ do
    path <- jsonPathVectors
    return $
      assertEqual
        path
        (B8.pack $ "[\"" ++ path ++ "\"]")
        (A.encode [fromString path :: ParsedPath])

jsonPathVectors :: [String]
jsonPathVectors =
  [ "m",
    "m/0",
    "m/0'",
    "M/0'",
    "m/2147483647",
    "M/2147483647",
    "m/1/2/3/4/5/6/7/8",
    "M/1/2/3/4/5/6/7/8",
    "m/1'/2'/3/4",
    "M/1'/2'/3/4"
  ]

testParsePath :: Assertion
testParsePath =
  sequence_ $ do
    (path, t) <- parsePathVectors
    return $ assertBool path (t $ parsePath path)

parsePathVectors :: [(String, Maybe ParsedPath -> Bool)]
parsePathVectors =
  [ ("m", isJust),
    ("m/0'", isJust),
    ("M/0'", isJust),
    ("m/2147483648", isNothing),
    ("m/2147483647", isJust),
    ("M/2147483648", isNothing),
    ("M/2147483647", isJust),
    ("M/-1", isNothing),
    ("M/-2147483648", isNothing),
    ("m/1/2/3/4/5/6/7/8", isJust),
    ("M/1/2/3/4/5/6/7/8", isJust),
    ("m/1'/2'/3/4", isJust),
    ("M/1'/2'/3/4", isJust),
    ("m/1/2'/3/4'", isJust),
    ("M/1/2'/3/4'", isJust),
    ("meh", isNothing),
    ("infinity", isNothing),
    ("NaN", isNothing)
  ]

testApplyPath :: Ctx -> Assertion
testApplyPath ctx =
  sequence_ $ do
    (key, path, final) <- applyPathVectors ctx
    return $
      assertEqual path final $
        applyPath ctx (fromJust $ parsePath path) key

testBadApplyPath :: Ctx -> Assertion
testBadApplyPath ctx =
  sequence_ $ do
    (key, path) <- badApplyPathVectors ctx
    return $
      assertBool path $
        isLeft $
          applyPath ctx (fromJust $ parsePath path) key

testDerivePubPath :: Ctx -> Assertion
testDerivePubPath ctx =
  sequence_ $ do
    (key, path, final) <- derivePubPathVectors ctx
    return $
      assertEqual path final $
        derivePubPath ctx (fromString path :: SoftPath) key

testDerivePrvPath :: Ctx -> Assertion
testDerivePrvPath ctx =
  sequence_ $ do
    (key, path, final) <- derivePrvPathVectors ctx
    return $
      assertEqual path final $
        derivePath ctx (fromString path :: DerivPath) key

derivePubPathVectors :: Ctx -> [(XPubKey, String, XPubKey)]
derivePubPathVectors ctx =
  [ (xpub, "M", xpub),
    (xpub, "M/8", pubSubKey ctx xpub 8),
    (xpub, "M/8/30/1", foldl (pubSubKey ctx) xpub [8, 30, 1])
  ]
  where
    xprv =
      fromJust $
        xPrvImport
          btc
          "xprv9s21ZrQH143K46iDVRSyFfGfMgQjzC4BV3ZUfNbG7PHQrJjE53ofAn5gYkp6KQ\
          \WzGmb8oageSRxBY8s4rjr9VXPVp2HQDbwPt4H31Gg4LpB"
    xpub = deriveXPubKey ctx xprv

derivePrvPathVectors :: Ctx -> [(XPrvKey, String, XPrvKey)]
derivePrvPathVectors ctx =
  [ (xprv, "m", xprv),
    (xprv, "M", xprv),
    (xprv, "m/8'", hardSubKey ctx xprv 8),
    (xprv, "M/8'", hardSubKey ctx xprv 8),
    ( xprv,
      "m/8'/30/1",
      foldl (prvSubKey ctx) (hardSubKey ctx xprv 8) [30, 1]
    ),
    ( xprv,
      "M/8'/30/1",
      foldl (prvSubKey ctx) (hardSubKey ctx xprv 8) [30, 1]
    ),
    ( xprv,
      "m/3/20",
      foldl (prvSubKey ctx) xprv [3, 20]
    ),
    ( xprv,
      "M/3/20",
      foldl (prvSubKey ctx) xprv [3, 20]
    )
  ]
  where
    xprv =
      fromJust $
        xPrvImport
          btc
          "xprv9s21ZrQH143K46iDVRSyFfGfMgQjzC4BV3ZUfNbG7PHQrJjE53ofAn5gYkp6KQ\
          \WzGmb8oageSRxBY8s4rjr9VXPVp2HQDbwPt4H31Gg4LpB"

applyPathVectors :: Ctx -> [(XKey, String, Either String XKey)]
applyPathVectors ctx =
  [ (XPrv xprv btc, "m", Right (XPrv xprv btc)),
    (XPrv xprv btc, "M", Right (XPub xpub btc)),
    (XPrv xprv btc, "m/8'", Right (XPrv (hardSubKey ctx xprv 8) btc)),
    ( XPrv xprv btc,
      "M/8'",
      Right (XPub (deriveXPubKey ctx (hardSubKey ctx xprv 8)) btc)
    ),
    ( XPrv xprv btc,
      "m/8'/30/1",
      Right (XPrv (foldl (prvSubKey ctx) (hardSubKey ctx xprv 8) [30, 1]) btc)
    ),
    ( XPrv xprv btc,
      "M/8'/30/1",
      Right
        ( XPub
            (deriveXPubKey ctx (foldl (prvSubKey ctx) (hardSubKey ctx xprv 8) [30, 1]))
            btc
        )
    ),
    (XPrv xprv btc, "m/3/20", Right (XPrv (foldl (prvSubKey ctx) xprv [3, 20]) btc)),
    ( XPrv xprv btc,
      "M/3/20",
      Right (XPub (deriveXPubKey ctx (foldl (prvSubKey ctx) xprv [3, 20])) btc)
    ),
    ( XPub xpub btc,
      "M/3/20",
      Right (XPub (deriveXPubKey ctx (foldl (prvSubKey ctx) xprv [3, 20])) btc)
    )
  ]
  where
    xprv =
      fromJust $
        xPrvImport
          btc
          "xprv9s21ZrQH143K46iDVRSyFfGfMgQjzC4BV3ZUfNbG7PHQrJjE53ofAn5gYkp6KQ\
          \WzGmb8oageSRxBY8s4rjr9VXPVp2HQDbwPt4H31Gg4LpB"
    xpub = deriveXPubKey ctx xprv

badApplyPathVectors :: Ctx -> [(XKey, String)]
badApplyPathVectors ctx =
  [ (XPub xpub btc, "m/8'"),
    (XPub xpub btc, "M/8'"),
    (XPub xpub btc, "M/1/2/3'/4/5")
  ]
  where
    xprv =
      fromJust $
        xPrvImport
          btc
          "xprv9s21ZrQH143K46iDVRSyFfGfMgQjzC4BV3ZUfNbG7PHQrJjE53ofAn5gYkp6KQ\
          \WzGmb8oageSRxBY8s4rjr9VXPVp2HQDbwPt4H31Gg4LpB"
    xpub = deriveXPubKey ctx xprv

-- BIP 0032 Test Vectors
-- https://en.bitcoin.it/wiki/BIP_0032_TestVectors

bip44Addr :: DerivPath
bip44Addr = Deriv :| 44 :| 0 :| 0 :/ 0 :/ 0

vectorSpec :: Ctx -> TestKey -> [TestVector] -> Spec
vectorSpec ctx mTxt vecTxt =
  forM_ (parseVector ctx mTxt vecTxt) $ \(d, m, v) ->
    it ("chain " <> cs d) $ runVector ctx m v

runVector :: Ctx -> XPrvKey -> TestVector -> Assertion
runVector ctx m v = do
  assertBool "xPrvID" $ encodeHex ((runPutS . serialize) (xPrvID ctx m)) == head v
  assertBool "xPrvFP" $ encodeHex ((runPutS . serialize) (xPrvFP ctx m)) == v !! 1
  assertBool "xPrvAddr" $
    addrToText btc (xPubAddr ctx $ deriveXPubKey ctx m) == Just (v !! 2)
  assertBool "bip44Addr" $
    addrToText btc (xPubAddr ctx $ deriveXPubKey ctx $ derivePath ctx bip44Addr m)
      == Just (v !! 3)
  assertBool "prvKey" $ encodeHex m.key.get == v !! 4
  assertBool "xPrvWIF" $ xPrvWif btc m == v !! 5
  assertBool "pubKey" $
    encodeHex (exportPubKey ctx True (deriveXPubKey ctx m).key) == v !! 6
  assertBool "chain code" $ encodeHex (runPutS (serialize m.chain)) == v !! 7
  assertBool "Hex PubKey" $
    encodeHex (marshal (btc, ctx) (deriveXPubKey ctx m)) == v !! 8
  assertBool "Hex PrvKey" $ encodeHex (marshal btc m) == v !! 9
  assertBool "Base58 PubKey" $ xPubExport btc ctx (deriveXPubKey ctx m) == v !! 10
  assertBool "Base58 PrvKey" $ xPrvExport btc m == v !! 11

-- This function was used to generate addition data for the test vectors
genVector :: Ctx -> XPrvKey -> [(Text, Text)]
genVector ctx m =
  [ ("xPrvID", encodeHex (runPutS . serialize $ xPrvID ctx m)),
    ("xPrvFP", encodeHex (runPutS . serialize $ xPrvFP ctx m)),
    ("xPrvAddr", fromJust $ addrToText btc (xPubAddr ctx $ deriveXPubKey ctx m)),
    ( "bip44Addr",
      fromJust $
        addrToText btc (xPubAddr ctx $ deriveXPubKey ctx $ derivePath ctx bip44Addr m)
    ),
    ("prvKey", encodeHex m.key.get),
    ("xPrvWIF", xPrvWif btc m),
    ("pubKey", encodeHex (exportPubKey ctx True (deriveXPubKey ctx m).key)),
    ("chain code", encodeHex ((runPutS . serialize) m.chain)),
    ("Hex PubKey", encodeHex (marshal (btc, ctx) (deriveXPubKey ctx m))),
    ("Hex PrvKey", encodeHex (marshal btc m))
  ]

parseVector :: Ctx -> TestKey -> [TestVector] -> [(Text, XPrvKey, TestVector)]
parseVector ctx mTxt vs =
  go <$> vs
  where
    mast = makeXPrvKey $ fromJust $ decodeHex mTxt
    go (d : vec) =
      let deriv = ((.get) . fromJust . parsePath) (cs d)
       in (d, derivePath ctx deriv mast, vec)
    go _ = undefined

type TestVector = [Text]

type TestKey = Text

m1 :: TestKey
m1 = "000102030405060708090a0b0c0d0e0f"

vector1 :: [TestVector]
vector1 =
  [ [ "m",
      "3442193e1bb70916e914552172cd4e2dbc9df811",
      "3442193e",
      "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma",
      "1NQpH6Nf8QtR2HphLRcvuVqfhXBXsiWn8r",
      "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
      "L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW",
      "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
      "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
      "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
      "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    ],
    [ "m/0'",
      "5c1bd648ed23aa5fd50ba52b2457c11e9e80a6a7",
      "5c1bd648",
      "19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh",
      "1DDVw6BRKUv9U8Hzg5rGsia13nDrgJQpBd",
      "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
      "L5BmPijJjrKbiUfG4zbiFKNqkvuJ8usooJmzuD7Z8dkRoTThYnAT",
      "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
      "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
      "0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
      "0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
      "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    ],
    [ "m/0'/1",
      "bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe",
      "bef5a2f9",
      "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj",
      "1KMg6dRggXSkpz9fFyU76ru83TUSwPePEZ",
      "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
      "KyFAjQ5rgrKvhXvNMtFB5PCSKUYD1yyPEe3xr3T34TZSUHycXtMM",
      "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
      "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
      "0488b21e025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c1903501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
      "0488ade4025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
      "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
      "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    ],
    [ "m/0'/1/2'",
      "ee7ab90cde56a8c0e2bb086ac49748b8db9dce72",
      "ee7ab90c",
      "1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x",
      "1WykKhR25y7VDT21nZEwUUKSKDz9pENJh",
      "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
      "L43t3od1Gh7Lj55Bzjj1xDAgJDcL7YFo2nEcNaMGiyRZS1CidBVU",
      "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
      "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
      "0488b21e03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
      "0488ade403bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
      "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
    ],
    [ "m/0'/1/2'/2",
      "d880d7d893848509a62d8fb74e32148dac68412f",
      "d880d7d8",
      "1LjmJcdPnDHhNTUgrWyhLGnRDKxQjoxAgt",
      "1asQ3smHhv2nv5R6hPpiUfkEorJpsdwwx",
      "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
      "KwjQsVuMjbCP2Zmr3VaFaStav7NvevwjvvkqrWd5Qmh1XVnCteBR",
      "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
      "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
      "0488b21e04ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
      "0488ade404ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd000f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
      "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
      "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
    ],
    [ "m/0'/1/2'/2/1000000000",
      "d69aa102255fed74378278c7812701ea641fdf32",
      "d69aa102",
      "1LZiqrop2HGR4qrH1ULZPyBpU6AUP49Uam",
      "1HXJog342VFdc68AB9Cb6LwVmCjvcLMiwm",
      "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
      "Kybw8izYevo5xMh1TK7aUr7jHFCxXS1zv8p3oqFz3o2zFbhRXHYs",
      "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
      "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
      "0488b21e05d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
      "0488ade405d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
      "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
      "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
    ]
  ]

m2 :: TestKey
m2 = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

vector2 :: [TestVector]
vector2 =
  [ [ "m",
      "bd16bee53961a47d6ad888e29545434a89bdfe95",
      "bd16bee5",
      "1JEoxevbLLG8cVqeoGKQiAwoWbNYSUyYjg",
      "148CGtv7bwcC933EHtcDfzDQVneur1R8Y1",
      "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
      "KyjXhyHF9wTphBkfpxjL8hkDXDUSbE3tKANT94kXSyh6vn6nKaoy",
      "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
      "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
      "0488b21e00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968903cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
      "0488ade400000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689004b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
      "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
      "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
    ],
    [ "m/0",
      "5a61ff8eb7aaca3010db97ebda76121610b78096",
      "5a61ff8e",
      "19EuDJdgfRkwCmRzbzVBHZWQG9QNWhftbZ",
      "1KVyTSpsBGYs7NdyZmArEpVTfWJQSgiDCx",
      "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
      "L2ysLrR6KMSAtx7uPqmYpoTeiRzydXBattRXjXz5GDFPrdfPzKbj",
      "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
      "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
      "0488b21e01bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
      "0488ade401bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
      "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
      "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
    ],
    [ "m/0/2147483647'",
      "d8ab493736da02f11ed682f88339e720fb0379d1",
      "d8ab4937",
      "1Lke9bXGhn5VPrBuXgN12uGUphrttUErmk",
      "14MFLsfx1nc4RKiaH9khqDTNL9CRz3q347",
      "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
      "L1m5VpbXmMp57P3knskwhoMTLdhAAaXiHvnGLMribbfwzVRpz2Sr",
      "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
      "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
      "0488b21e025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d903c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
      "0488ade4025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d900877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
      "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
      "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
    ],
    [ "m/0/2147483647'/1",
      "78412e3a2296a40de124307b6485bd19833e2e34",
      "78412e3a",
      "1BxrAr2pHpeBheusmd6fHDP2tSLAUa3qsW",
      "19ou31MGyGW9VFx7woKBqwLe5JHhQBYaDD",
      "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
      "KzyzXnznxSv249b4KuNkBwowaN3akiNeEHy5FWoPCJpStZbEKXN2",
      "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
      "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
      "0488b21e03d8ab493700000001f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
      "0488ade403d8ab493700000001f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb00704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
      "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
      "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
    ],
    [ "m/0/2147483647'/1/2147483646'",
      "31a507b815593dfc51ffc7245ae7e5aee304246e",
      "31a507b8",
      "15XVotxCAV7sRx1PSCkQNsGw3W9jT9A94R",
      "18GYmRm4nyjk8ydvoVXFxMWQvxhksEFDZR",
      "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
      "L5KhaMvPYRW1ZoFmRjUtxxPypQ94m6BcDrPhqArhggdaTbbAFJEF",
      "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
      "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
      "0488b21e0478412e3afffffffe637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2902d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
      "0488ade40478412e3afffffffe637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2900f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
      "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
      "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
    ],
    [ "m/0/2147483647'/1/2147483646'/2",
      "26132fdbe7bf89cbc64cf8dafa3f9f88b8666220",
      "26132fdb",
      "14UKfRV9ZPUp6ZC9PLhqbRtxdihW9em3xt",
      "1758mgwNZhyzpRLe4u7FjqpJtqKpaGhXh7",
      "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
      "L3WAYNAZPxx1fr7KCz7GN9nD5qMBnNiqEJNJMU1z9MMaannAt4aK",
      "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
      "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
      "0488b21e0531a507b8000000029452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
      "0488ade40531a507b8000000029452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed27100bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
      "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
      "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
    ]
  ]

m3 :: TestKey
m3 = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"

-- Test vector 4 checks that private keys with leading zero bytes are kept at
-- 32 bytes. Each entry is the path, the extended public key and the extended
-- private key.
m4 :: TestKey
m4 = "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678"

vector4 :: [(String, Text, Text)]
vector4 =
  [ ( "m",
      "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
      "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
    ),
    ( "m/0'",
      "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
      "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"
    ),
    ( "m/0'/1'",
      "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
      "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
    )
  ]

-- Test vector 5 lists extended keys that must be refused, with the reason.
vector5 :: [(Text, String)]
vector5 =
  [ ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm", "pubkey version / prvkey mismatch"),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH", "prvkey version / pubkey mismatch"),
    ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn", "invalid pubkey prefix 04"),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ", "invalid prvkey prefix 04"),
    ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4", "invalid pubkey prefix 01"),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J", "invalid prvkey prefix 01"),
    ("xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv", "zero depth with non-zero parent fingerprint (xprv)"),
    ("xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ", "zero depth with non-zero parent fingerprint (xpub)"),
    ("xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN", "zero depth with non-zero index (xprv)"),
    ("xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8", "zero depth with non-zero index (xpub)"),
    ("DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4", "unknown extended key version (first)"),
    ("DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9", "unknown extended key version (second)"),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx", "private key 0 not in 1..n-1"),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G", "private key n not in 1..n-1"),
    ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY", "invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007"),
    ("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL", "invalid checksum")
  ]

vector3 :: [TestVector]
vector3 =
  [ [ "m",
      "41d63b50d8dd5e730cdf4c79a56fc929a757c548",
      "41d63b50",
      "1717ZYpXhZW5CqAbWSjDJbCey3FyKUmCSf",
      "17rxURoF96VhmkcEGCj5LNQkmN9HVhWb7F",
      "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
      "KwFPqAq9SKx1sPg15Qk56mqkHwrfGPuywtLUxoWPkiTSBoxCs8am",
      "03683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e5669",
      "01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f",
      "0488b21e00000000000000000001d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f03683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e5669",
      "0488ade400000000000000000001d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f0000ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
      "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
      "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
    ],
    [ "m/0'",
      "c61368bb50e066acd95bd04a0b23d3837fb75698",
      "c61368bb",
      "1K4L3YxEwg8HkSEapM4iSiGuR6HeQ53KPX",
      "13QeQVJNNakdUU55P1fc8xPMkkeYVzn4o6",
      "491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef",
      "KyfrPaeirL5yYAoZvfzyoKXSdszeLqg5vb6dNy9ymvjzZrMZY8GW",
      "026557fdda1d5d43d79611f784780471f086d58e8126b8c40acb82272a7712e7f2",
      "e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd",
      "0488b21e0141d63b5080000000e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd026557fdda1d5d43d79611f784780471f086d58e8126b8c40acb82272a7712e7f2",
      "0488ade40141d63b5080000000e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd00491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef",
      "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
      "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
    ]
  ]
