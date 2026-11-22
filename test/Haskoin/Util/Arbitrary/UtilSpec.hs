{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-- | 'testIdentity' of "Haskoin.Util.Arbitrary.Util" and the five tests it
-- makes. Every other spec, here and in the programs built on this library,
-- trusts them to fail for a type whose written form does not come back as
-- the value. Nothing else checks that they can fail: a helper that
-- compared nothing would leave every identity test green.
--
-- So the helpers are run here on types made for them: one whose five forms
-- are right, which must pass, and types with one fault each, which must
-- fail in the example of that fault and in no other. The identity tests of
-- such a type are run apart from the suite ('outcomes'), and each test
-- states which of their examples passed and which failed.
module Haskoin.Util.Arbitrary.UtilSpec (spec) where

import Data.Aeson (FromJSON (..), ToJSON (..))
import Data.Bytes.Get (getBytes, getWord8)
import Data.Bytes.Put (putWord8)
import Data.Bytes.Serial (Serial (..))
import Data.Default (def)
import Data.List (intercalate)
import Data.Word (Word8)
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Test.Hspec
import Test.Hspec.Runner
import Test.QuickCheck (Gen, sized)

spec :: Spec
spec = do
  describe "testIdentity" $ do
    it "makes one group for each form, and names each example after the form and the type" $
      def
        { readTests = [ReadBox (pure (Sound 3))],
          jsonTests = [JsonBox (pure (Sound 3))],
          marshalJsonTests = [MarshalJsonBox (pure ((), Sound 3))],
          serialTests = [SerialBox (pure (Sound 3))],
          marshalTests = [MarshalBox (pure ((), Sound 3))]
        }
        `gives` [ Passed "Read/Show Encoding" "read/show identity for Sound",
                  Passed "Data.Aeson Encoding" "Data.Aeson toJSON/fromJSON identity for Sound",
                  Passed "Data.Aeson Encoding" "Data.Aeson toEncoding/fromJSON identity for Sound",
                  Passed "MarshalJSON Encoding" "MarshalJSON marshalValue/unmarshalValue identity for Sound",
                  Passed "MarshalJSON Encoding" "MarshalJSON marshalEncoding/unmarshalValue identity for Sound",
                  Passed "Binary Encoding" "Binary encoding/decoding identity for Sound",
                  Passed "Marshal Encoding" "Marshal marshalPut/marshalGet identity for Sound"
                ]
    it "sees in every form a fault that only the larger half of the sizes shows" $
      def
        { readTests = [ReadBox (WrongText <$> largeOnly)],
          jsonTests = [JsonBox (WrongParse <$> largeOnly)],
          marshalJsonTests = [MarshalJsonBox ((,) () . WrongParse <$> largeOnly)],
          serialTests = [SerialBox (WrongRead <$> largeOnly)],
          marshalTests = [MarshalBox ((,) () . WrongRead <$> largeOnly)]
        }
        `gives` [ Failed "Read/Show Encoding" "read/show identity for WrongText",
                  Failed "Data.Aeson Encoding" "Data.Aeson toJSON/fromJSON identity for WrongParse",
                  Failed "Data.Aeson Encoding" "Data.Aeson toEncoding/fromJSON identity for WrongParse",
                  Failed "MarshalJSON Encoding" "MarshalJSON marshalValue/unmarshalValue identity for WrongParse",
                  Failed "MarshalJSON Encoding" "MarshalJSON marshalEncoding/unmarshalValue identity for WrongParse",
                  Failed "Binary Encoding" "Binary encoding/decoding identity for WrongRead",
                  Failed "Marshal Encoding" "Marshal marshalPut/marshalGet identity for WrongRead"
                ]

  describe "a ReadBox" $ do
    it "fails for a type whose text reads as another value" $
      def {readTests = [ReadBox (pure (WrongText 3))]}
        `gives` [Failed "Read/Show Encoding" "read/show identity for WrongText"]
    it "fails for a type whose text does not read" $
      def {readTests = [ReadBox (pure (NoText 3))]}
        `gives` [Failed "Read/Show Encoding" "read/show identity for NoText"]

  describe "a SerialBox" $ do
    it "fails for a codec that reads another value than the one written" $
      def {serialTests = [SerialBox (pure (WrongRead 3))]}
        `gives` [Failed "Binary Encoding" "Binary encoding/decoding identity for WrongRead"]
    it "fails for a codec that reads a byte more than it writes" $
      def {serialTests = [SerialBox (pure (ByteShort 3))]}
        `gives` [Failed "Binary Encoding" "Binary encoding/decoding identity for ByteShort"]
    it "fails for a codec that writes a byte more than it reads" $
      def {serialTests = [SerialBox (pure (ByteLeft 3))]}
        `gives` [Failed "Binary Encoding" "Binary encoding/decoding identity for ByteLeft"]
    it "fails for a codec that the strict reader alone refuses" $
      def {serialTests = [SerialBox (pure (StrictRefuses 3))]}
        `gives` [Failed "Binary Encoding" "Binary encoding/decoding identity for StrictRefuses"]

  describe "a JsonBox" $ do
    it "fails both examples for a type whose parser gives another value" $
      def {jsonTests = [JsonBox (pure (WrongParse 3))]}
        `gives` [ Failed "Data.Aeson Encoding" "Data.Aeson toJSON/fromJSON identity for WrongParse",
                  Failed "Data.Aeson Encoding" "Data.Aeson toEncoding/fromJSON identity for WrongParse"
                ]
    it "fails the toEncoding example alone for a type whose toEncoding writes another value" $
      def {jsonTests = [JsonBox (pure (WrongEncoding 3))]}
        `gives` [ Passed "Data.Aeson Encoding" "Data.Aeson toJSON/fromJSON identity for WrongEncoding",
                  Failed "Data.Aeson Encoding" "Data.Aeson toEncoding/fromJSON identity for WrongEncoding"
                ]

  describe "a MarshalBox" $ do
    it "fails for a codec that reads another value than the one written" $
      def {marshalTests = [MarshalBox (pure ((), WrongRead 3))]}
        `gives` [Failed "Marshal Encoding" "Marshal marshalPut/marshalGet identity for WrongRead"]
    it "fails for a codec that writes a byte more than it reads" $
      def {marshalTests = [MarshalBox (pure ((), ByteLeft 3))]}
        `gives` [Failed "Marshal Encoding" "Marshal marshalPut/marshalGet identity for ByteLeft"]

  describe "a MarshalJsonBox" $ do
    it "fails both examples for a type whose parser gives another value" $
      def {marshalJsonTests = [MarshalJsonBox (pure ((), WrongParse 3))]}
        `gives` [ Failed "MarshalJSON Encoding" "MarshalJSON marshalValue/unmarshalValue identity for WrongParse",
                  Failed "MarshalJSON Encoding" "MarshalJSON marshalEncoding/unmarshalValue identity for WrongParse"
                ]
    it "fails the marshalEncoding example alone for a type whose marshalEncoding writes another value" $
      def {marshalJsonTests = [MarshalJsonBox (pure ((), WrongEncoding 3))]}
        `gives` [ Passed "MarshalJSON Encoding" "MarshalJSON marshalValue/unmarshalValue identity for WrongEncoding",
                  Failed "MarshalJSON Encoding" "MarshalJSON marshalEncoding/unmarshalValue identity for WrongEncoding"
                ]

-- | What one example of the identity tests did: its group, its name, and
-- whether it passed.
data Outcome
  = Passed String String
  | Failed String String
  deriving (Eq, Show)

-- | The identity tests must give these outcomes, one for each example, in
-- the order of the run.
gives :: IdentityTests -> [Outcome] -> Expectation
gives tests expected = outcomes tests `shouldReturn` expected

-- | Run identity tests apart from the suite and give the outcome of each
-- example. The run prints nothing, and takes nothing from the command line
-- of the suite: a @--match@ given to the suite would leave it without an
-- example.
outcomes :: IdentityTests -> IO [Outcome]
outcomes tests = do
  (config, examples) <- evalSpec silent (testIdentity tests)
  map outcome . specResultItems <$> runSpecForest examples config
  where
    silent = defaultConfig {configFormat = Just (\_ -> return (\_ -> return ()))}
    outcome item = verdict item (intercalate "/" groups) name
      where
        (groups, name) = resultItemPath item
    verdict item
      | resultItemIsFailure item = Failed
      | otherwise = Passed

-- The types that the helpers are run on. Each holds one byte. A fault
-- shows on the byte 3 only, unless the type says otherwise: a helper sees
-- it only when it tests the value that it is given.

-- | A byte with five right forms
newtype Sound = Sound Word8
  deriving stock (Eq, Show, Read)
  deriving newtype (ToJSON, FromJSON)

instance Serial Sound where
  serialize (Sound byte) = putWord8 byte
  deserialize = Sound <$> getWord8

instance Marshal () Sound where
  marshalPut () = serialize
  marshalGet () = deserialize

instance MarshalJSON () Sound where
  marshalValue () = toJSON
  unmarshalValue () = parseJSON

-- | The fault of a form that gives another value: 4 where the byte is 3
threeAsFour :: Word8 -> Word8
threeAsFour 3 = 4
threeAsFour byte = byte

-- | The byte 3, which shows a fault, at the sizes of 50 and more, and the
-- byte 0 below them. Of the 100 cases of a property, the first 50 are
-- below: a helper that ran one case, or small values only, would pass.
largeOnly :: Gen Word8
largeOnly = sized $ \size -> pure (if size >= 50 then 3 else 0)

-- | Its text for the byte 3 is the text of the byte 4
newtype WrongText = WrongText Word8
  deriving stock (Eq, Read)

instance Show WrongText where
  show (WrongText byte) = "WrongText " <> show (threeAsFour byte)

-- | Its text for the byte 3 is no text that 'read' takes
newtype NoText = NoText Word8
  deriving stock (Eq, Read)

instance Show NoText where
  show (NoText 3) = "three"
  show (NoText byte) = "NoText " <> show byte

-- | Its binary readers give 4 where the byte 3 was written
newtype WrongRead = WrongRead Word8
  deriving stock (Eq, Show)

instance Serial WrongRead where
  serialize (WrongRead byte) = putWord8 byte
  deserialize = WrongRead . threeAsFour <$> getWord8

instance Marshal () WrongRead where
  marshalPut () = serialize
  marshalGet () = deserialize

-- | Its binary readers read two bytes where one was written, for every
-- value
newtype ByteShort = ByteShort Word8
  deriving stock (Eq, Show)

instance Serial ByteShort where
  serialize (ByteShort byte) = putWord8 byte
  deserialize = ByteShort <$> getWord8 <* getWord8

-- | Its binary writers write a zero byte after the value, which its
-- readers leave unread, for every value
newtype ByteLeft = ByteLeft Word8
  deriving stock (Eq, Show)

instance Serial ByteLeft where
  serialize (ByteLeft byte) = putWord8 byte >> putWord8 0
  deserialize = ByteLeft <$> getWord8

instance Marshal () ByteLeft where
  marshalPut () = serialize
  marshalGet () = deserialize

-- | Its binary readers ask for a negative number of bytes before the
-- value, for every value. The strict reader, which is that of cereal,
-- refuses that. The lazy reader, which is that of binary, reads nothing
-- and goes on, so the value comes back.
newtype StrictRefuses = StrictRefuses Word8
  deriving stock (Eq, Show)

instance Serial StrictRefuses where
  serialize (StrictRefuses byte) = putWord8 byte
  deserialize = getBytes (-1) >> StrictRefuses <$> getWord8

-- | Its JSON parsers give 4 where the byte 3 was written
newtype WrongParse = WrongParse Word8
  deriving stock (Eq, Show)
  deriving newtype (ToJSON)

instance FromJSON WrongParse where
  parseJSON = fmap (WrongParse . threeAsFour) . parseJSON

instance MarshalJSON () WrongParse where
  marshalValue () = toJSON
  unmarshalValue () = parseJSON

-- | Its JSON encodings write 4 for the byte 3. The JSON values that
-- 'toJSON' and 'marshalValue' make are right.
newtype WrongEncoding = WrongEncoding Word8
  deriving stock (Eq, Show)
  deriving newtype (FromJSON)

instance ToJSON WrongEncoding where
  toJSON (WrongEncoding byte) = toJSON byte
  toEncoding (WrongEncoding byte) = toEncoding (threeAsFour byte)

instance MarshalJSON () WrongEncoding where
  marshalValue () = toJSON
  marshalEncoding () = toEncoding
  unmarshalValue () = parseJSON
