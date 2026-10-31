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
    encodeHexLazy,
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
    prepareContext,
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
import Data.ByteString.Lazy qualified as LB
import Data.ByteString.Lazy.Base16 qualified as LB16
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

hexEncoding :: LB.ByteString -> Encoding
hexEncoding b =
  unsafeToEncoding $
    char7 '"' <> hexBuilder b <> char7 '"'

hexBuilder :: LB.ByteString -> Builder
hexBuilder = lazyByteStringHex

encodeHex :: ByteString -> Text
encodeHex = extractBase16 . encodeBase16

-- | Encode as string of human-readable hex characters.
encodeHexLazy :: LB.ByteString -> LT.Text
encodeHexLazy = extractBase16 . LB16.encodeBase16

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
-- right.
getBits :: Int -> ByteString -> ByteString
getBits b bs
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
-- 'Word'.
convertBits :: Bool -> Int -> Int -> [Word] -> ([Word], Bool)
convertBits pad frombits tobits i = (reverse yout, rem')
  where
    (xacc, xbits, xout) = foldl' outer (0, 0, []) i
    (yout, rem')
      | pad && xbits /= 0 =
          let xout' = (xacc `shiftL` (tobits - xbits)) .&. maxv : xout
           in (xout', False)
      | pad = (xout, False)
      | xbits /= 0 = (xout, True)
      | otherwise = (xout, False)
    maxv = 1 `shiftL` tobits - 1
    max_acc = 1 `shiftL` (frombits + tobits - 1) - 1
    outer (acc, bits, out) it =
      let acc' = ((acc `shiftL` frombits) .|. it) .&. max_acc
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

getInt32be :: (MonadGet m) => m Int32
getInt32be = do
  n <- getWord32be
  if testBit n 31
    then return (negate (complement (fromIntegral n) + 1))
    else return (fromIntegral n)

putInt64be :: (MonadPut m) => Int64 -> m ()
putInt64be n
  | n < 0 = putWord64be (complement (fromIntegral (abs n)) + 1)
  | otherwise = putWord64be (fromIntegral (abs n))

getInt64be :: (MonadGet m) => m Int64
getInt64be = do
  n <- getWord64be
  if testBit n 63
    then return (negate (complement (fromIntegral n) + 1))
    else return (fromIntegral n)

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

getInteger :: (MonadGet m) => m Integer
getInteger =
  getWord8 >>= \case
    0 -> fromIntegral <$> getInt32be
    _ -> do
      sign <- getWord8
      bytes <- getList getWord8
      let v = roll bytes
      return $! if sign == 0x01 then v else -v

putMaybe :: (MonadPut m) => (a -> m ()) -> Maybe a -> m ()
putMaybe f Nothing = putWord8 0x00
putMaybe f (Just x) = putWord8 0x01 >> f x

getMaybe :: (MonadGet m) => m a -> m (Maybe a)
getMaybe f =
  getWord8 >>= \case
    0x00 -> return Nothing
    0x01 -> Just <$> f
    _ -> fail "Not a Maybe"

putLengthBytes :: (MonadPut m) => ByteString -> m ()
putLengthBytes bs = do
  putWord64be (fromIntegral (B.length bs))
  putByteString bs

getLengthBytes :: (MonadGet m) => m ByteString
getLengthBytes = do
  len <- fromIntegral <$> getWord64be
  getByteString len

--
-- Fold and unfold an Integer to and from a list of its bytes
--
unroll :: (Integral a, Bits a) => a -> [Word8]
unroll = unfoldr step
  where
    step 0 = Nothing
    step i = Just (fromIntegral i, i `shiftR` 8)

roll :: (Integral a, Bits a) => [Word8] -> a
roll = foldr unstep 0
  where
    unstep b a = a `shiftL` 8 .|. fromIntegral b

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

-- | Read as a list of pairs of int and element.
getIntMap :: (MonadGet m) => m Int -> m a -> m (IntMap a)
getIntMap i m = IntMap.fromList <$> getList (getTwo i m)

putIntMap :: (MonadPut m) => (Int -> m ()) -> (a -> m ()) -> IntMap a -> m ()
putIntMap f g = putList (putTwo f g) . IntMap.toAscList

putTwo :: (MonadPut m) => (a -> m ()) -> (b -> m ()) -> (a, b) -> m ()
putTwo f g (x, y) = f x >> g y

getTwo :: (MonadGet m) => m a -> m b -> m (a, b)
getTwo f g = (,) <$> f <*> g

putList :: (MonadPut m) => (a -> m ()) -> [a] -> m ()
putList f ls = do
  putWord64be (fromIntegral (length ls))
  mapM_ f ls

getList :: (MonadGet m) => m a -> m [a]
getList f = do
  l <- fromIntegral <$> getWord64be
  replicateM l f

--
-- Test Helpers
--

prepareContext :: (Ctx -> SpecWith a) -> SpecWith a
prepareContext go = go =<< runIO createContext
  

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
