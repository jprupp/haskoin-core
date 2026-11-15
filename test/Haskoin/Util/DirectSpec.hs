{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | "Haskoin.Util.Direct" promises that its functions give what cereal
-- gives, only faster. The serializers of transactions, blocks, hashes and
-- addresses go through them, so these tests are what shows that no byte
-- and no error changed when they did.
--
-- The reference is always the same serializer run in the monad of cereal
-- with 'runPutS' or 'runGetS', which is the code that the library ran
-- before and that nothing here replaced. The first half checks the three
-- monads operation by operation, on programs made of every method of
-- 'MonadPut' and 'MonadGet'. The second half checks the types: that
-- cereal, binary, 'Serial', 'encodeSerial' and 'decodeSerial' agree on the
-- bytes, read them back, and report the same error for bytes that are cut
-- short, changed or followed by others.
module Haskoin.Util.DirectSpec (spec) where

import Control.Monad (replicateM, unless)
import Crypto.Hash (SHA256 (..), hashWith)
import Data.Binary qualified as Binary
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as L
import Data.ByteString.Short (ShortByteString, fromShort, toShort)
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial (Serial (..))
import Data.Serialize qualified as Cereal
import Data.Typeable (Proxy (..), Typeable, typeRep)
import Data.Word (Word16, Word32, Word64, Word8)
import Haskoin.Block
import Haskoin.Crypto
import Haskoin.Transaction
import Haskoin.Util
import Haskoin.Util.Arbitrary
import Haskoin.Util.Direct
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

spec :: Spec
spec = do
  describe "Haskoin.Util.Direct" $ do
    describe "writing" $ do
      prop "encodeDirect gives the bytes of runPutS" $
        forAll (listOf arbitraryOp) $ \ops ->
          encodeDirect (mapM_ write ops) === runPutS (mapM_ write ops)
      prop "sizeDirect gives their length" $
        forAll (listOf arbitraryOp) $ \ops ->
          sizeDirect (mapM_ write ops) === B.length (runPutS (mapM_ write ops))
      prop "putDirect writes them in the middle of a cereal serializer" $
        forAll (listOf arbitraryOp) $ \ops ->
          Cereal.runPut (Cereal.putWord8 1 >> putDirect (mapM_ write ops) >> Cereal.putWord8 2)
            === Cereal.runPut (Cereal.putWord8 1 >> mapM_ write ops >> Cereal.putWord8 2)
      prop "putShortBytes writes the bytes of a short byte string in every monad" $
        forAll arbitraryBSS $ \s -> do
          runPutS (putShortBytes s) `shouldBe` fromShort s
          L.toStrict (runPutL (putShortBytes s)) `shouldBe` fromShort s
          encodeDirect (putShortBytes s) `shouldBe` fromShort s
          sizeDirect (putShortBytes s) `shouldBe` B.length (fromShort s)
    describe "reading" $ do
      prop "decodeDirect gives the result of runGetS on the bytes that were written" $
        forAll arbitraryProgram $ \(steps, bytes) ->
          decodeDirect (mapM look steps) bytes === runGetS (mapM look steps) bytes
      prop "decodeDirect gives the result of runGetS on any bytes, errors included" $
        forAll arbitraryProgram $ \(steps, _) -> forAll arbitraryBS $ \bytes ->
          decodeDirect (mapM look steps) bytes === runGetS (mapM look steps) bytes
      prop "decodeDirect gives the result of runGetS on bytes cut short" $
        forAll arbitraryProgram $ \(steps, bytes) -> forAll (choose (0, B.length bytes)) $ \n ->
          decodeDirect (mapM look steps) (B.take n bytes) === runGetS (mapM look steps) (B.take n bytes)
      prop "getDirect reads what the parser reads in cereal, and leaves the same input" $
        forAll arbitraryProgram $ \(steps, bytes) -> forAll arbitraryBS $ \more ->
          Cereal.runGetState (getDirect (mapM look steps)) (bytes <> more) 0
            === Cereal.runGetState (mapM look steps) (bytes <> more) 0
      prop "getDirect reads input that arrives in pieces as cereal does" $
        forAll arbitraryProgram $ \(steps, bytes) -> forAll (pieces bytes) $ \chunks ->
          feed (getDirect (mapM look steps)) chunks === feed (mapM look steps) chunks
      prop "getShortBytes reads what getByteString reads" $
        forAll arbitraryBS $ \bytes -> forAll (choose (-1, B.length bytes + 1)) $ \n -> do
          runGetS (getShortBytes n) bytes `shouldBe` toShort <$> runGetS (getByteString n) bytes
          decodeDirect (getShortBytes n) bytes `shouldBe` toShort <$> runGetS (getByteString n) bytes
  describe "Encodings of the types that go through Haskoin.Util.Direct" $
    mapM_
      codec
      [ Box arbitraryTxHash,
        Box arbitraryBlockHash,
        Box arbitraryHash160,
        Box arbitraryHash256,
        Box arbitraryHash512,
        Box arbitraryVarInt,
        Box arbitraryOutPoint,
        Box (arbitraryTxIn =<< arbitraryNetwork),
        Box (arbitraryTxOut =<< arbitraryNetwork),
        Box (arbitraryTx =<< arbitraryNetwork),
        Box arbitraryBlockHeader,
        Box (arbitraryBlock =<< arbitraryNetwork),
        Box (arbitraryAddress =<< arbitraryNetwork)
      ]
  describe "Functions that write a value to hash or to measure it" $ do
    prop "encodeSerial and decodeSerial of a transaction, compiled for it" $
      forAll (arbitraryTx =<< arbitraryNetwork) $ \tx -> do
        encodeSerial tx `shouldBe` runPutS (serialize tx)
        decodeSerial (runPutS (serialize tx)) `shouldBe` Right tx
        decodeTx (runPutS (serialize tx)) `shouldBe` Right tx
        decodeTx (runPutS (serialize tx) <> B.singleton 0) `shouldBe` Left trailing
    prop "encodeSerial and decodeSerial of an outpoint, compiled for it" $
      forAll arbitraryOutPoint $ \o -> do
        encodeSerial o `shouldBe` runPutS (serialize o)
        decodeSerial (runPutS (serialize o)) `shouldBe` Right o
    prop "txHash is the double SHA-256 of the transaction without its witness" $
      forAll (arbitraryTx =<< arbitraryNetwork) $ \tx ->
        txHash tx === TxHash (reference (runPutS (serialize (stripped tx))))
    prop "txWitnessHash is the double SHA-256 of the whole transaction" $
      forAll (arbitraryTx =<< arbitraryNetwork) $ \tx ->
        txWitnessHash tx === TxHash (reference (runPutS (serialize tx)))
    prop "txWeight is three times the size without the witness plus the size with it" $
      forAll (arbitraryTx =<< arbitraryNetwork) $ \tx ->
        txWeight tx
          === 3 * B.length (runPutS (serialize (stripped tx))) + B.length (runPutS (serialize tx))
    prop "headerHash is the double SHA-256 of the header" $
      forAll arbitraryBlockHeader $ \h ->
        headerHash h === BlockHash (reference (runPutS (serialize h)))
    prop "sha256 and doubleSHA256 give the digests of crypton for bytes of any length" $
      forAll (choose (0, 300)) $ \n -> forAll (arbitraryBSn n) $ \bytes -> do
        (sha256 bytes).get `shouldBe` toShort (BA.convert (hashWith SHA256 bytes))
        (doubleSHA256 bytes).get `shouldBe` (reference bytes).get
        -- a kind of bytes other than the one the functions are compiled for
        (sha256 (BA.convert bytes :: BA.Bytes)).get `shouldBe` (sha256 bytes).get
        (doubleSHA256 (BA.convert bytes :: BA.Bytes)).get `shouldBe` (doubleSHA256 bytes).get
  where
    trailing = "Failed reading: Trailing bytes after transaction\nEmpty call stack\n"
    stripped :: Tx -> Tx
    stripped (Tx v i o _ l) = Tx v i o [] l

-- | Two rounds of SHA-256 through the pure interface of crypton, as
-- 'doubleSHA256' was written before it called the C code itself.
reference :: ByteString -> Hash256
reference bytes =
  either error id . runGetS deserialize . BA.convert $ hashWith SHA256 (hashWith SHA256 bytes)

-- Programs

-- | One method of 'MonadPut', with what it writes.
data Op
  = W8 Word8
  | W16le Word16
  | W16be Word16
  | W16host Word16
  | W32le Word32
  | W32be Word32
  | W32host Word32
  | W64le Word64
  | W64be Word64
  | W64host Word64
  | Whost Word
  | Bytes ByteString
  | Lazy [ByteString]
  | Short ShortByteString
  | Flush
  deriving (Eq, Show)

arbitraryOp :: Gen Op
arbitraryOp =
  oneof
    [ W8 <$> arbitrary,
      W16le <$> arbitrary,
      W16be <$> arbitrary,
      W16host <$> arbitrary,
      W32le <$> arbitrary,
      W32be <$> arbitrary,
      W32host <$> arbitrary,
      W64le <$> arbitrary,
      W64be <$> arbitrary,
      W64host <$> arbitrary,
      Whost <$> arbitrary,
      Bytes <$> arbitraryBS,
      Lazy <$> listOf arbitraryBS,
      Short <$> arbitraryBSS,
      pure Flush
    ]

write :: (MonadPut m) => Op -> m ()
write op = case op of
  W8 w -> putWord8 w
  W16le w -> putWord16le w
  W16be w -> putWord16be w
  W16host w -> putWord16host w
  W32le w -> putWord32le w
  W32be w -> putWord32be w
  W32host w -> putWord32host w
  W64le w -> putWord64le w
  W64be w -> putWord64be w
  W64host w -> putWord64host w
  Whost w -> putWordhost w
  Bytes b -> putByteString b
  Lazy bs -> putLazyByteString (L.fromChunks bs)
  Short s -> putShortBytes s
  Flush -> flush

-- | One step of a parser: a method of 'MonadGet', or a few of them inside
-- one of the methods that look ahead.
data Step
  = -- | read back what the operation wrote
    Back Op
  | Slice Int
  | Copy Int
  | Skip Int
  | Ahead [Step]
  | -- | look ahead, and keep the input or not
    AheadM Bool [Step]
  | AheadE Bool [Step]
  | Empty
  | Remaining
  | Ensure Int
  | LazyBytes Int
  | Fail
  deriving (Eq, Show)

-- | What a step saw.
data Seen
  = Number Integer
  | Chunk ByteString
  | Flag Bool
  | Many [Seen]
  deriving (Eq, Show)

look :: (MonadGet m) => Step -> m Seen
look step = case step of
  Back op -> case op of
    W8 _ -> number <$> getWord8
    W16le _ -> number <$> getWord16le
    W16be _ -> number <$> getWord16be
    W16host _ -> number <$> getWord16host
    W32le _ -> number <$> getWord32le
    W32be _ -> number <$> getWord32be
    W32host _ -> number <$> getWord32host
    W64le _ -> number <$> getWord64le
    W64be _ -> number <$> getWord64be
    W64host _ -> number <$> getWord64host
    Whost _ -> number <$> getWordhost
    Bytes b -> Chunk <$> getByteString (B.length b)
    Lazy bs -> Chunk <$> getBytes (sum (map B.length bs))
    Short s -> Chunk . fromShort <$> getShortBytes (B.length (fromShort s))
    Flush -> pure (Many [])
  Slice n -> Chunk <$> getBytes n
  Copy n -> Chunk <$> getByteString n
  Skip n -> Many [] <$ skip n
  Ahead steps -> Many <$> lookAhead (mapM look steps)
  AheadM keep steps ->
    maybe (Flag False) Many <$> lookAheadM ((if keep then Just else const Nothing) <$> mapM look steps)
  AheadE keep steps ->
    either Many Many <$> lookAheadE ((if keep then Right else Left) <$> mapM look steps)
  Empty -> Flag <$> isEmpty
  Remaining -> number <$> remaining
  Ensure n -> number . B.length <$> ensure n
  LazyBytes n -> Chunk . L.toStrict <$> getLazyByteString (fromIntegral n)
  Fail -> fail "a step that fails"
  where
    number :: (Integral a) => a -> Seen
    number = Number . toInteger

-- | A parser and bytes that it reads to the end, unless one of its steps
-- fails: the steps that read back what a list of operations wrote, with
-- steps that read nothing put between them.
arbitraryProgram :: Gen ([Step], ByteString)
arbitraryProgram = do
  ops <- listOf arbitraryOp
  steps <- concat <$> mapM around ops
  return (steps, runPutS (mapM_ write ops))
  where
    around op = do
      extra <- frequency [(3, pure []), (1, pure <$> idle)]
      return (Back op : extra)
    -- steps that leave the position where it is, most of the time
    idle =
      oneof
        [ Slice <$> choose (-1, 2),
          Copy <$> choose (-1, 2),
          Skip <$> choose (-1, 2),
          Ahead <$> some,
          AheadM <$> arbitrary <*> some,
          AheadE <$> arbitrary <*> some,
          pure Empty,
          pure Remaining,
          Ensure <$> choose (0, 3),
          LazyBytes <$> choose (0, 2),
          frequency [(1, pure Fail), (5, pure Empty)]
        ]
    some = do
      n <- choose (0, 3)
      replicateM n (oneof [Back <$> arbitraryOp, Slice <$> choose (0, 3), pure Empty, pure Remaining])

-- | The bytes cut into pieces at random places.
pieces :: ByteString -> Gen [ByteString]
pieces bytes
  | B.null bytes = pure []
  | otherwise = do
      n <- choose (1, B.length bytes)
      (B.take n bytes :) <$> pieces (B.drop n bytes)

-- | Run a cereal parser on input that arrives in pieces and then ends. The
-- result is the value with the input left over, or the error.
feed :: Cereal.Get a -> [ByteString] -> Either String (a, ByteString)
feed parser = go (Cereal.runGetPartial parser)
  where
    go continue chunks = case continue (headOr chunks) of
      Cereal.Done a rest -> Right (a, rest <> mconcat (drop 1 chunks))
      Cereal.Fail message _ -> Left message
      Cereal.Partial more
        | null chunks -> Left "the parser wants input after the end"
        | otherwise -> go more (drop 1 chunks)
    headOr = foldr const B.empty

-- Types

data Box
  = forall a.
    (Show a, Eq a, Typeable a, Serial a, Cereal.Serialize a, Binary.Binary a) =>
    Box (Gen a)

-- | Bytes that are not what was written: cut short, with a byte changed,
-- or with bytes after them.
damaged :: ByteString -> Gen ByteString
damaged bytes =
  oneof
    [ (`B.take` bytes) <$> choose (0, B.length bytes),
      change <$> choose (0, max 0 (B.length bytes - 1)) <*> arbitrary,
      (bytes <>) <$> arbitraryBS1,
      arbitraryBS
    ]
  where
    change i w = B.take i bytes <> B.pack [w | i < B.length bytes] <> B.drop (i + 1) bytes

codec :: Box -> Spec
codec (Box (gen :: Gen a)) = describe (show (typeRep (Proxy :: Proxy a))) $ do
  prop "cereal, binary, Serial and encodeSerial give the same bytes" $
    forAll gen $ \x -> do
      let bytes = runPutS (serialize x)
      Cereal.encode x `shouldBe` bytes
      L.toStrict (Binary.encode x) `shouldBe` bytes
      L.toStrict (runPutL (serialize x)) `shouldBe` bytes
      encodeSerial x `shouldBe` bytes
      encodeDirect (serialize x) `shouldBe` bytes
      sizeDirect (serialize x) `shouldBe` B.length bytes
  prop "cereal, binary, Serial and decodeSerial read them back" $
    forAll gen $ \x -> do
      let bytes = runPutS (serialize x)
      Cereal.decode bytes `shouldBe` Right x
      Binary.decode (L.fromStrict bytes) `shouldBe` x
      runGetS deserialize bytes `shouldBe` Right x
      runGetL deserialize (L.fromStrict bytes) `shouldBe` x
      decodeSerial bytes `shouldBe` Right x
      decodeDirect deserialize bytes `shouldBe` Right x
  prop "cereal and decodeSerial give the result of the Serial parser on damaged bytes" $
    forAll gen $ \x -> forAll (damaged (runPutS (serialize x))) $ \bytes -> do
      Cereal.decode bytes `shouldBe` (runGetS deserialize bytes :: Either String a)
      decodeDirect deserialize bytes `shouldBe` (runGetS deserialize bytes :: Either String a)
      decodeSerial bytes `shouldBe` (runGetS whole bytes :: Either String a)
  prop "cereal reads the value from input that arrives in pieces" $
    forAll gen $ \x -> forAll arbitraryBS $ \more -> forAll (pieces (runPutS (serialize x) <> more)) $
      \chunks -> do
        feed Cereal.get chunks `shouldBe` Right (x, more)
        feed deserialize chunks `shouldBe` Right (x, more)
  prop "cereal reads damaged input that arrives in pieces as the Serial parser does" $
    forAll gen $ \x -> forAll (damaged (runPutS (serialize x)) >>= pieces) $ \chunks ->
      feed Cereal.get chunks `shouldBe` (feed deserialize chunks :: Either String (a, ByteString))
  where
    -- what decodeSerial was before it read the bytes directly
    whole :: (Serial b) => Cereal.Get b
    whole = do
      value <- deserialize
      done <- isEmpty
      unless done $ fail "decodeSerial: bytes left over after the value"
      return value
