{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-- |
-- Module      : Haskoin.Util
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- This module defines various utility functions used across the library.
module Haskoin.Util.Helpers
  ( -- * ByteString Helpers
    bsToInteger,
    integerToBS,
    hexEncoding,
    hexBuilder,
    encodeHex,
    encodeHexBytes,
    encodeHexLazy,
    encodeHexReversed,
    hexEncodingReversed,
    decodeHex,
    decodeHexLazy,
    getBits,

    -- * Maybe & Either Helpers
    eitherToMaybe,
    maybeToEither,
    liftEither,
    liftMaybe,

    -- * Other Helpers
    updateIndex,
    matchTemplate,
    convertBits,

    -- * Triples
    fst3,
    snd3,
    lst3,

    -- * JSON Utilities
    dropFieldLabel,
    dropSumLabels,

    -- * Serialization Helpers
    putList,
    getList,
    putMaybe,
    getMaybe,
    putLengthBytes,
    getLengthBytes,
    putInteger,
    getInteger,
    putInt32be,
    getInt32be,
    putInt64be,
    getInt64be,
    getIntMap,
    putIntMap,
    getTwo,
    putTwo,

    -- * Test Helpers
    customCerealID,
    readTestFile,
    readTestFileParser,
  )
where

import Control.Monad
import Control.Monad.Except (ExceptT (..), liftEither)
import Crypto.Secp256k1
import Data.Aeson (eitherDecodeFileStrict)
import Data.Aeson.Encoding
import Data.Aeson.Types
import Data.Base16.Types
import Data.Bits
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Base16
import Data.ByteString.Builder
import Data.ByteString.Builder.Prim qualified as BP
import Data.ByteString.Builder.Prim.Internal qualified as BPI
import Data.ByteString.Internal qualified as BI
import Data.ByteString.Lazy qualified as LB
import Data.ByteString.Lazy.Base16 qualified as LB16
import Data.ByteString.Short (ShortByteString)
import Data.ByteString.Short qualified as SBS
import Data.ByteString.Unsafe qualified as BU
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Char (toLower)
import Data.Int
import Data.IntMap (IntMap)
import Data.IntMap qualified as IntMap
import Data.List
import Data.Serialize qualified as S
import Data.Text (Text)
import Data.Text.Encoding qualified as T
import Data.Text.Lazy qualified as LT
import Data.Text.Lazy.Encoding qualified as LT
import Data.Word
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import Test.Hspec

-- ByteString helpers

-- | Decode a big endian 'Integer' from a 'ByteString'.
bsToInteger :: ByteString -> Integer
bsToInteger = B.foldr f 0 . B.reverse
  where
    f w n = toInteger w .|. shiftL n 8

-- | Encode an 'Integer' to a 'ByteString' as big endian.
integerToBS :: Integer -> ByteString
integerToBS 0 = B.pack [0]
integerToBS i
  | i > 0 = B.reverse $ B.unfoldr f i
  | otherwise = error "integerToBS not defined for negative values"
  where
    f 0 = Nothing
    f x = Just (fromInteger x :: Word8, x `shiftR` 8)

-- Hexadecimal
--
-- Two ways of writing hex are used here, each where it measured fastest.
--
-- Inside a builder, the hex is the builder's own, 'lazyByteStringHex' of
-- bytestring. It looks up the two digits of each byte in a table and writes
-- them straight into the output buffer, so it allocates nothing of its own.
-- Version 1.6.4 replaced it with a loop that made a strict string first and
-- copied it in, and that was slower at every size, at @-O1@ and at @-O2@.
--
-- Outside a builder, the result is a strict string or text of a known
-- length, so the bytes are allocated once and filled by a loop over the
-- input that writes each pair of digits with 'BP.word8HexFixed', the same
-- table lookup that the builder uses. On a transaction of 250 bytes that
-- takes less than half the time of base16, which 'encodeHex' used until
-- 1.6.3, and it costs less than running a builder for a short string.
--
-- The loop of 1.6.4 kept a table of its own in a 'ByteString'. GHC found
-- where that table was once, before the loop, only at @-O2@, where its
-- liberate-case pass runs. At @-O1@, the level this package is built at
-- unless the user asks otherwise, it looked again for every byte, and
-- 'encodeHex' was slower than the base16 it had replaced. The table of
-- bytestring is a literal with a fixed address, so the loop below is as
-- fast at @-O1@ as at @-O2@, and no option of the compiler is needed to
-- get its speed.
--
-- The benchmark of this package measures every function below at both
-- levels, next to what version 1.6.0 did. The README says how to run it.

-- | JSON string of the hex of bytes, in lowercase.
--
-- This is 'hexBuilder' between two quotes. Hex has no character that JSON
-- escapes, so nothing else is needed. Use it to write a script, a
-- transaction or a block as one field of a JSON object without building the
-- text first.
hexEncoding :: LB.ByteString -> Encoding
hexEncoding b =
  unsafeToEncoding $
    char7 '"' <> hexBuilder b <> char7 '"'

-- | Hex of bytes, in lowercase, to append to other output.
--
-- This is 'lazyByteStringHex' of bytestring, which writes the digits into
-- the buffer of the builder. Version 1.6.4 used a loop of its own for chunks
-- of 256 bytes and more. On a megabyte that took 1.5 times as long at @-O2@
-- and five times as long at @-O1@, so version 2.0.0 went back. Use this
-- function when the hex goes into a response or a file. For hex that you
-- keep as a value, 'encodeHex' and 'encodeHexBytes' cost less than running
-- a builder.
hexBuilder :: LB.ByteString -> Builder
hexBuilder = lazyByteStringHex

-- | Hex of bytes, in lowercase.
--
-- The text is the digits of 'encodeHexBytes', which are ASCII.
encodeHex :: ByteString -> Text
encodeHex = T.decodeLatin1 . encodeHexBytes

-- | Hex of bytes, in lowercase, as the bytes of its ASCII digits.
--
-- The result is allocated once, at twice the length of the input, and
-- filled in one pass.
encodeHexBytes :: ByteString -> ByteString
encodeHexBytes bs =
  BI.unsafeCreate (2 * n) $ \out ->
    BU.unsafeUseAsCString bs $ \inp ->
      let go !i
            | i >= n = return ()
            | otherwise = do
                w <- peekByteOff inp i
                pokeHex (out `plusPtr` (2 * i)) w
                go (i + 1)
       in go 0
  where
    n = B.length bs

-- | Hex of lazy bytes, in lowercase, as lazy text with a chunk for each
-- chunk of the input.
encodeHexLazy :: LB.ByteString -> LT.Text
encodeHexLazy = LT.fromChunks . map encodeHex . LB.toChunks

-- | Hex of bytes in reverse order, as hashes are shown, in lowercase.
--
-- The hash of a block or of a transaction is kept in the order of its bytes
-- on the wire and shown in the opposite order. Reading the bytes backwards
-- while writing the digits saves serializing the hash and reversing it,
-- which is what showing a hash cost until 1.6.3.
encodeHexReversed :: ShortByteString -> Text
encodeHexReversed h =
  T.decodeLatin1 . BI.unsafeCreate (2 * n) $ \out ->
    let go !i
          | i >= n = return ()
          | otherwise = pokeHex (out `plusPtr` (2 * i)) (SBS.index h (n - 1 - i)) >> go (i + 1)
     in go 0
  where
    n = SBS.length h

-- | JSON string of the hex of bytes in reverse order, as hashes are shown.
--
-- A hash of 32 bytes, the size of the hashes of blocks and transactions, is
-- written in one step of 66 bytes, straight from its bytes into the buffer
-- of the encoder. Any other length is reversed and given to 'hexEncoding'.
hexEncodingReversed :: ShortByteString -> Encoding
hexEncodingReversed h
  | SBS.length h == 32 = unsafeToEncoding (BP.primFixed quotedHash h)
  | otherwise = hexEncoding (LB.fromStrict (B.reverse (SBS.fromShort h)))
  where
    quotedHash = BPI.fixedPrim 66 $ \x p -> do
      pokeByteOff p 0 quote
      let go !i
            | i >= 32 = return ()
            | otherwise = pokeHex (p `plusPtr` (1 + 2 * i)) (SBS.index x (31 - i)) >> go (i + 1)
      go 0
      pokeByteOff p 65 quote
    quote = 0x22 :: Word8

-- | Write the two lowercase hex digits of a byte at an address. The digits
-- come from the table of bytestring, through the primitive that its builder
-- writes hex with.
pokeHex :: Ptr Word8 -> Word8 -> IO ()
pokeHex out w = BPI.runF BP.word8HexFixed w out
{-# INLINE pokeHex #-}

-- | Bytes from their hex, in lowercase or uppercase. 'Nothing' for text that
-- is not hex, or that has an odd number of digits.
decodeHex :: Text -> Maybe ByteString
decodeHex t =
  case parseBase16 u8 of
    Right b16 -> Just $ decodeBase16 b16
    Left _ -> Nothing
  where
    u8 = T.encodeUtf8 t

-- | Decode string of human-readable hex characters.
decodeHexLazy :: LT.Text -> Maybe LB.ByteString
decodeHexLazy t =
  case LB16.parseBase16 u8 of
    Right b16 -> Just $ LB16.decodeBase16 b16
    Left _ -> Nothing
  where
    u8 = LT.encodeUtf8 t

-- | Obtain 'Int' bits from beginning of 'ByteString'. Resulting 'ByteString'
-- will be smallest required to hold that many bits, padded with zeroes to the
-- right. Raises an error when the 'ByteString' does not hold that many
-- bits, instead of returning fewer bits than asked.
getBits :: Int -> ByteString -> ByteString
getBits b bs
  | b < 0 || b > 8 * B.length bs =
      error ("getBits: " <> show b <> " bits asked of " <> show (B.length bs) <> " bytes")
  | r == 0 = B.take q bs
  | otherwise = i `B.snoc` l
  where
    (q, r) = b `quotRem` 8
    s = B.take (q + 1) bs
    i = B.init s
    l = B.last s .&. (0xff `shiftL` (8 - r)) -- zero unneeded bits

-- Maybe and Either monad helpers

-- | Transform an 'Either' value into a 'Maybe' value. 'Right' is mapped to
-- 'Just' and 'Left' is mapped to 'Nothing'. The value inside 'Left' is lost.
eitherToMaybe :: Either a b -> Maybe b
eitherToMaybe (Right b) = Just b
eitherToMaybe _ = Nothing

-- | Transform a 'Maybe' value into an 'Either' value. 'Just' is mapped to
-- 'Right' and 'Nothing' is mapped to 'Left'. Default 'Left' required.
maybeToEither :: b -> Maybe a -> Either b a
maybeToEither err = maybe (Left err) Right

-- | Lift a 'Maybe' computation into the 'ExceptT' monad.
liftMaybe :: (Monad m) => b -> Maybe a -> ExceptT b m a
liftMaybe err = liftEither . maybeToEither err

-- Various helpers

-- | Applies a function to only one element of a list defined by its index.  If
-- the index is out of the bounds of the list, the original list is returned.
updateIndex ::
  -- | index of the element to change
  Int ->
  -- | list of elements
  [a] ->
  -- | function to apply
  (a -> a) ->
  -- | result with one element changed
  [a]
updateIndex i xs f
  | i < 0 || i >= length xs = xs
  | otherwise = l ++ (f h : r)
  where
    (l, h : r) = splitAt i xs

-- | Use the list @[b]@ as a template and try to match the elements of @[a]@
-- against it. For each element of @[b]@ return the (first) matching element of
-- @[a]@, or 'Nothing'. Output list has same size as @[b]@ and contains results
-- in same order. Elements of @[a]@ can only appear once.
matchTemplate ::
  -- | input list
  [a] ->
  -- | list to serve as a template
  [b] ->
  -- | comparison function
  (a -> b -> Bool) ->
  [Maybe a]
matchTemplate [] bs _ = replicate (length bs) Nothing
matchTemplate _ [] _ = []
matchTemplate as (b : bs) f = case break (`f` b) as of
  (l, r : rs) -> Just r : matchTemplate (l ++ rs) bs f
  _ -> Nothing : matchTemplate as bs f

-- | Returns the first value of a triple.
fst3 :: (a, b, c) -> a
fst3 (a, _, _) = a

-- | Returns the second value of a triple.
snd3 :: (a, b, c) -> b
snd3 (_, b, _) = b

-- | Returns the last value of a triple.
lst3 :: (a, b, c) -> c
lst3 (_, _, c) = c

-- | Field label goes lowercase and first @n@ characters get removed.
dropFieldLabel :: Int -> Options
dropFieldLabel n =
  defaultOptions
    { fieldLabelModifier = map toLower . drop n
    }

-- | Transformation from 'dropFieldLabel' is applied with argument @f@, plus
-- constructor tags are lowercased and first @c@ characters removed. @tag@ is
-- used as the name of the object field name that will hold the transformed
-- constructor tag as its value.
dropSumLabels :: Int -> Int -> String -> Options
dropSumLabels c f tag =
  (dropFieldLabel f)
    { constructorTagModifier = map toLower . drop c,
      sumEncoding = defaultTaggedObject {tagFieldName = tag}
    }

-- | Convert from one power-of-two base to another, as long as it fits in a
-- 'Word'. With padding, leftover bits fill one more output digit. Without
-- padding, the conversion fails when the leftover bits could hold a whole
-- input digit, or when they are not all zero. That is the rule Bitcoin Core
-- applies. It rejects strings that are not the canonical encoding of their
-- payload.
--
-- The conversion also fails for a digit that does not fit the width it is
-- converted from, as the reference code of BIP 173 does, and for widths that
-- are not positive or whose sum is above the 64 bits of a 'Word'.
convertBits :: Bool -> Int -> Int -> [Word] -> Maybe [Word]
convertBits pad frombits tobits i
  | frombits < 1 || tobits < 1 || frombits + tobits > 64 = Nothing
  | any (>= 1 `shiftL` frombits) i = Nothing
  | pad = Just . reverse $ if xbits == 0 then xout else leftover : xout
  | xbits >= frombits = Nothing
  | leftover /= 0 = Nothing
  | otherwise = Just (reverse xout)
  where
    (xacc, xbits, xout) = foldl' outer (0, 0, []) i
    -- The leftover bits, moved to the top of one output digit.
    leftover = (xacc `shiftL` (tobits - xbits)) .&. maxv
    maxv = 1 `shiftL` tobits - 1
    -- Only this many bits of the accumulator are ever read. Masking to them
    -- keeps the accumulator from overflowing on long inputs.
    maxAcc = 1 `shiftL` (frombits + tobits - 1) - 1
    outer (acc, bits, out) it =
      let acc' = ((acc `shiftL` frombits) .|. it) .&. maxAcc
          bits' = bits + frombits
          (out', bits'') = inner acc' out bits'
       in (acc', bits'', out')
    inner acc out bits
      | bits >= tobits =
          let bits' = bits - tobits
              out' = ((acc `shiftR` bits') .&. maxv) : out
           in inner acc out' bits'
      | otherwise = (out, bits)

--
-- Serialization helpers
--

putInt32be :: (MonadPut m) => Int32 -> m ()
putInt32be n
  | n < 0 = putWord32be (complement (fromIntegral (abs n)) + 1)
  | otherwise = putWord32be (fromIntegral (abs n))
{-# INLINEABLE putInt32be #-}

getInt32be :: (MonadGet m) => m Int32
getInt32be = do
  n <- getWord32be
  if testBit n 31
    then return (negate (complement (fromIntegral n) + 1))
    else return (fromIntegral n)
{-# INLINEABLE getInt32be #-}

putInt64be :: (MonadPut m) => Int64 -> m ()
putInt64be n
  | n < 0 = putWord64be (complement (fromIntegral (abs n)) + 1)
  | otherwise = putWord64be (fromIntegral (abs n))
{-# INLINEABLE putInt64be #-}

getInt64be :: (MonadGet m) => m Int64
getInt64be = do
  n <- getWord64be
  if testBit n 63
    then return (negate (complement (fromIntegral n) + 1))
    else return (fromIntegral n)
{-# INLINEABLE getInt64be #-}

putInteger :: (MonadPut m) => Integer -> m ()
putInteger n
  | n >= lo && n <= hi = do
      putWord8 0x00
      putInt32be (fromIntegral n)
  | otherwise = do
      putWord8 0x01
      putWord8 (fromIntegral (signum n))
      let len = (nrBits (abs n) + 7) `div` 8
      putWord64be (fromIntegral len)
      mapM_ putWord8 (unroll (abs n))
  where
    lo = fromIntegral (minBound :: Int32)
    hi = fromIntegral (maxBound :: Int32)
{-# INLINEABLE putInteger #-}

-- | Read an 'Integer' that 'putInteger' wrote. A number has one encoding, and
-- any other way to write it is refused:
--
-- * the tag byte is 0x00 for a number that fits 32 bits, and 0x01 otherwise
-- * the sign byte of the wide form is 0x01, or 0xff for a negative number
-- * the bytes of the wide form are the shortest that hold the number, so the
--   last one is not zero
--
-- This is the encoding that 'putInteger' has always written, so stored data
-- reads as before. The bytes are read in one piece and turned into a number
-- in close to linear time, so a long number cannot stall the reader.
getInteger :: (MonadGet m) => m Integer
getInteger =
  getWord8 >>= \case
    0x00 -> fromIntegral <$> getInt32be
    0x01 -> do
      sign <-
        getWord8 >>= \case
          0x01 -> return 1
          0xff -> return (-1)
          _ -> fail "getInteger: the sign byte is not 0x01 or 0xff"
      bytes <- getLengthBytes
      let n = sign * littleEndianToInteger bytes
      when (B.null bytes || B.last bytes == 0x00 || fitsInt32 n) $
        fail "getInteger: the number is not in its shortest form"
      return n
    _ -> fail "getInteger: the tag byte is not 0x00 or 0x01"
  where
    fitsInt32 n =
      n >= fromIntegral (minBound :: Int32) && n <= fromIntegral (maxBound :: Int32)
{-# INLINEABLE getInteger #-}

-- | The number that a string of bytes spells, least significant byte first.
-- The string is split in halves and the two numbers are joined. Adding one
-- byte at a time would move the whole number at every step, which takes time
-- that grows with the square of the length.
littleEndianToInteger :: ByteString -> Integer
littleEndianToInteger bs
  | B.length bs <= 8 = B.foldr (\byte n -> n `shiftL` 8 .|. toInteger byte) 0 bs
  | otherwise = low .|. (high `shiftL` (8 * B.length lowBytes))
  where
    (lowBytes, highBytes) = B.splitAt (B.length bs `div` 2) bs
    low = littleEndianToInteger lowBytes
    high = littleEndianToInteger highBytes

putMaybe :: (MonadPut m) => (a -> m ()) -> Maybe a -> m ()
putMaybe f Nothing = putWord8 0x00
putMaybe f (Just x) = putWord8 0x01 >> f x
{-# INLINEABLE putMaybe #-}

getMaybe :: (MonadGet m) => m a -> m (Maybe a)
getMaybe f =
  getWord8 >>= \case
    0x00 -> return Nothing
    0x01 -> Just <$> f
    _ -> fail "Not a Maybe"
{-# INLINEABLE getMaybe #-}

putLengthBytes :: (MonadPut m) => ByteString -> m ()
putLengthBytes bs = do
  putWord64be (fromIntegral (B.length bs))
  putByteString bs
{-# INLINEABLE putLengthBytes #-}

getLengthBytes :: (MonadGet m) => m ByteString
getLengthBytes = getByteString =<< getCount
{-# INLINEABLE getLengthBytes #-}

-- | A 64-bit count that must fit an 'Int'. A larger one fails the parse
-- instead of wrapping around to a negative number.
getCount :: (MonadGet m) => m Int
getCount = do
  n <- getWord64be
  when (n > fromIntegral (maxBound :: Int)) $
    fail ("Count too large: " <> show n)
  return (fromIntegral n)
{-# INLINEABLE getCount #-}

--
-- Fold and unfold an Integer to and from a list of its bytes
--
unroll :: (Integral a, Bits a) => a -> [Word8]
unroll = unfoldr step
  where
    step 0 = Nothing
    step i = Just (fromIntegral i, i `shiftR` 8)

nrBits :: (Ord a, Integral a) => a -> Int
nrBits k =
  let expMax = until (\e -> 2 ^ e > k) (* 2) 1
      findNr :: Int -> Int -> Int
      findNr lo hi
        | mid == lo = hi
        | 2 ^ mid <= k = findNr mid hi
        | 2 ^ mid > k = findNr lo mid
        where
          mid = (lo + hi) `div` 2
   in findNr (expMax `div` 2) expMax

-- | Read a map as a count and that many pairs of key and element. The keys
-- must come in ascending order, each one once, which is how 'putIntMap'
-- writes them. A key given twice is refused. It used to be read, and the
-- second element silently replaced the first.
getIntMap :: (MonadGet m) => m Int -> m a -> m (IntMap a)
getIntMap i m = do
  pairs <- getList (getTwo i m)
  let keys = map fst pairs
  unless (and (zipWith (<) keys (drop 1 keys))) $
    fail "getIntMap: the keys are not in ascending order"
  return (IntMap.fromDistinctAscList pairs)
{-# INLINEABLE getIntMap #-}

putIntMap :: (MonadPut m) => (Int -> m ()) -> (a -> m ()) -> IntMap a -> m ()
putIntMap f g = putList (putTwo f g) . IntMap.toAscList
{-# INLINEABLE putIntMap #-}

putTwo :: (MonadPut m) => (a -> m ()) -> (b -> m ()) -> (a, b) -> m ()
putTwo f g (x, y) = f x >> g y
{-# INLINEABLE putTwo #-}

getTwo :: (MonadGet m) => m a -> m b -> m (a, b)
getTwo f g = (,) <$> f <*> g
{-# INLINEABLE getTwo #-}

putList :: (MonadPut m) => (a -> m ()) -> [a] -> m ()
putList f ls = do
  putWord64be (fromIntegral (length ls))
  mapM_ f ls
{-# INLINEABLE putList #-}

getList :: (MonadGet m) => m a -> m [a]
getList f = do
  l <- getCount
  replicateM l f
{-# INLINEABLE getList #-}

--
-- Test Helpers
--

customCerealID :: (Eq a) => S.Get a -> S.Putter a -> a -> Bool
customCerealID g p a = (S.runGet g . S.runPut . p) a == Right a

readTestFile :: (FromJSON a) => FilePath -> IO a
readTestFile fp =
  eitherDecodeFileStrict ("data/" <> fp) >>= either (error . message) return
  where
    message aesonErr = "Could not read test file " <> fp <> ": " <> aesonErr

readTestFileParser :: (Value -> Parser a) -> FilePath -> IO a
readTestFileParser p fp = do
  v <- readTestFile fp
  case parse p v of
    Error s -> error s
    Success x -> return x
