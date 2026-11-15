{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UnboxedSums #-}
{-# LANGUAGE UnboxedTuples #-}

-- |
-- Module      : Haskoin.Util.Direct
-- Description : Run a serializer straight on a buffer
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- The serializers of this library are written once, for any monad of the
-- 'MonadPut' and 'MonadGet' classes, so that the same code gives the bytes
-- through cereal, through binary and through anything else. The monads of
-- cereal and binary are general: they write through a
-- 'Data.ByteString.Builder.Builder', which does not know how long its output
-- will be, and read through continuations, which can stop anywhere and ask
-- for more input. That generality is paid for in every field. Writing a
-- transaction of 387 bytes through cereal allocated 11 kB and took 1.6
-- microseconds, and reading it back allocated 7 kB and took a microsecond,
-- most of it spent on closures that describe the work instead of on the
-- work. Here the same transaction is written in 0.18 microseconds and 0.5
-- kB, and read in 0.4 microseconds at @-O2@, or 0.5 at @-O1@, and 2 kB,
-- which is the transaction itself.
--
-- A program that already holds the whole value, or the whole input, needs
-- none of that. This module has three small monads for that case, and four
-- functions that run a serializer in them:
--
-- * 'encodeDirect' runs a serializer twice: once in t'Size', which only adds
--   up the lengths, and once in t'Poke', which writes the bytes one after the
--   other into a buffer of exactly that length. Nothing else is allocated.
-- * 'decodeDirect' runs a parser in t'Peek', which reads from the bytes at a
--   position that it moves forward, and gives up at the first difficulty.
-- * 'putDirect' and 'getDirect' do the same from inside a cereal serializer,
--   for the @put@ and @get@ of a 'Data.Serialize.Serialize' instance.
--
-- Each of the four gives the result that the same serializer gives through
-- cereal, in every case: the serializer is the same code, and when t'Peek'
-- gives up, for bytes that do not parse or for an operation that it does
-- not have, the parser runs again through cereal from where it started. So
-- the error of a bad input is the one cereal reports, and input that
-- arrives in pieces is read as before. Only the speed differs.
--
-- The serializer is taken as a value that works in any monad, with a
-- @forall@. To be fast, GHC must compile a copy of it for each monad here,
-- which it does when the function called and the serializer given are both
-- known where they meet: the four functions are inlined for that, and the
-- 'Data.Bytes.Serial.Serial' instances of this library carry @INLINABLE@
-- pragmas. A serializer reached through a dictionary that GHC cannot see
-- through still works, at the speed of a function call per field.
--
-- Use these functions for values that are written or read whole and often:
-- keys and records of a database, hashes of transactions. Do not use them
-- to write a value so large that a second pass over it, or a buffer of its
-- whole length, costs more than a builder, nor to read from a stream.
-- The @Haskoin@ module does not re-export this one.
module Haskoin.Util.Direct
  ( -- * Writing
    encodeDirect,
    sizeDirect,
    putDirect,
    putShortBytes,

    -- * Reading
    decodeDirect,
    getDirect,
    getShortBytes,

    -- * Monads
    Size,
    Poke,
    Peek,
  )
where

import Control.Monad.Fail qualified as Fail
import Data.Binary.Put qualified as Binary
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Internal (ByteString (BS), accursedUnutterablePerformIO, unsafeCreate)
import Data.ByteString.Lazy qualified as L
import Data.ByteString.Short (ShortByteString, fromShort, toShort)
import Data.ByteString.Short qualified as Short
import Data.ByteString.Short.Internal qualified as Short (copyToPtr)
import Data.Bytes.Get (MonadGet (..), runGetS)
import Data.Bytes.Put (MonadPut (..))
import Data.Serialize.Get qualified as Cereal
import Data.Serialize.Put qualified as Cereal
import Foreign.ForeignPtr (plusForeignPtr)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (sizeOf)
import GHC.ByteOrder (ByteOrder (..), targetByteOrder)
import GHC.Exts
import GHC.ForeignPtr (unsafeWithForeignPtr)
import GHC.IO (IO (IO))
import GHC.Word (Word16 (W16#), Word32 (W32#), Word64 (W64#), Word8 (W8#), byteSwap16, byteSwap32, byteSwap64)

-- Byte order

-- | A word as its bytes are in memory for a little-endian value.
le16 :: Word16 -> Word16
le16 = case targetByteOrder of
  LittleEndian -> id
  BigEndian -> byteSwap16
{-# INLINE le16 #-}

le32 :: Word32 -> Word32
le32 = case targetByteOrder of
  LittleEndian -> id
  BigEndian -> byteSwap32
{-# INLINE le32 #-}

le64 :: Word64 -> Word64
le64 = case targetByteOrder of
  LittleEndian -> id
  BigEndian -> byteSwap64
{-# INLINE le64 #-}

-- | A word as its bytes are in memory for a big-endian value.
be16 :: Word16 -> Word16
be16 = case targetByteOrder of
  LittleEndian -> byteSwap16
  BigEndian -> id
{-# INLINE be16 #-}

be32 :: Word32 -> Word32
be32 = case targetByteOrder of
  LittleEndian -> byteSwap32
  BigEndian -> id
{-# INLINE be32 #-}

be64 :: Word64 -> Word64
be64 = case targetByteOrder of
  LittleEndian -> byteSwap64
  BigEndian -> id
{-# INLINE be64 #-}

-- | The size of a machine word in bytes.
wordSize :: Int
wordSize = sizeOf (0 :: Word)
{-# INLINE wordSize #-}

-- Size

-- | The monad that measures: every write adds the number of its bytes to a
-- count and does nothing else. 'encodeDirect' runs a serializer in it first,
-- to learn how long a buffer to allocate.
newtype Size a = Size (Int# -> (# Int#, a #))

instance Functor Size where
  fmap f (Size g) = Size (oneShot (\n -> case g n of (# n', a #) -> (# n', f a #)))
  {-# INLINE fmap #-}

instance Applicative Size where
  pure a = Size (oneShot (\n -> (# n, a #)))
  {-# INLINE pure #-}
  Size f <*> Size g =
    Size (oneShot (\n -> case f n of (# n1, h #) -> case g n1 of (# n2, a #) -> (# n2, h a #)))
  {-# INLINE (<*>) #-}
  Size f *> Size g = Size (oneShot (\n -> case f n of (# n1, _ #) -> g n1))
  {-# INLINE (*>) #-}

instance Monad Size where
  Size g >>= f = Size (oneShot (\n -> case g n of (# n1, a #) -> case f a of Size h -> h n1))
  {-# INLINE (>>=) #-}
  (>>) = (*>)
  {-# INLINE (>>) #-}

-- | Count that many bytes.
count :: Int -> Size ()
count (I# k) = Size (oneShot (\n -> (# n +# k, () #)))
{-# INLINE count #-}

instance MonadPut Size where
  putWord8 _ = count 1
  {-# INLINE putWord8 #-}
  putByteString b = count (B.length b)
  {-# INLINE putByteString #-}
  putLazyByteString b = count (fromIntegral (L.length b))
  {-# INLINE putLazyByteString #-}
  flush = pure ()
  {-# INLINE flush #-}
  putWord16le _ = count 2
  {-# INLINE putWord16le #-}
  putWord16be _ = count 2
  {-# INLINE putWord16be #-}
  putWord16host _ = count 2
  {-# INLINE putWord16host #-}
  putWord32le _ = count 4
  {-# INLINE putWord32le #-}
  putWord32be _ = count 4
  {-# INLINE putWord32be #-}
  putWord32host _ = count 4
  {-# INLINE putWord32host #-}
  putWord64le _ = count 8
  {-# INLINE putWord64le #-}
  putWord64be _ = count 8
  {-# INLINE putWord64be #-}
  putWord64host _ = count 8
  {-# INLINE putWord64host #-}
  putWordhost _ = count wordSize
  {-# INLINE putWordhost #-}

-- Poke

-- | The monad that writes: every write stores its bytes at an address and
-- moves the address past them. It checks nothing, because 'encodeDirect'
-- runs it on a buffer that t'Size' measured for the same serializer.
newtype Poke a = Poke (Addr# -> State# RealWorld -> (# State# RealWorld, Addr#, a #))

instance Functor Poke where
  fmap f (Poke g) =
    Poke (oneShot (\p -> oneShot (\s -> case g p s of (# s1, p1, a #) -> (# s1, p1, f a #))))
  {-# INLINE fmap #-}

instance Applicative Poke where
  pure a = Poke (oneShot (\p -> oneShot (\s -> (# s, p, a #))))
  {-# INLINE pure #-}
  Poke f <*> Poke g =
    Poke . oneShot $ \p -> oneShot $ \s ->
      case f p s of
        (# s1, p1, h #) -> case g p1 s1 of
          (# s2, p2, a #) -> (# s2, p2, h a #)
  {-# INLINE (<*>) #-}
  Poke f *> Poke g = Poke (oneShot (\p -> oneShot (\s -> case f p s of (# s1, p1, _ #) -> g p1 s1)))
  {-# INLINE (*>) #-}

instance Monad Poke where
  Poke g >>= f =
    Poke (oneShot (\p -> oneShot (\s -> case g p s of (# s1, p1, a #) -> case f a of Poke h -> h p1 s1)))
  {-# INLINE (>>=) #-}
  (>>) = (*>)
  {-# INLINE (>>) #-}

-- | Write that many bytes with the given action, which gets the address to
-- write them at.
store :: Int -> (Ptr Word8 -> IO ()) -> Poke ()
store (I# k) f =
  Poke . oneShot $ \p -> oneShot $ \s ->
    case f (Ptr p) of
      IO io -> case io s of
        (# s1, _ #) -> (# s1, plusAddr# p k, () #)
{-# INLINE store #-}

-- The stores below write a whole word at an address that need not be
-- aligned, which the primitives that they call allow on every machine.

store8 :: Word8 -> Ptr Word8 -> IO ()
store8 (W8# w) (Ptr p) = IO (\s -> (# writeWord8OffAddr# p 0# w s, () #))
{-# INLINE store8 #-}

store16 :: Word16 -> Ptr Word8 -> IO ()
store16 (W16# w) (Ptr p) = IO (\s -> (# writeWord8OffAddrAsWord16# p 0# w s, () #))
{-# INLINE store16 #-}

store32 :: Word32 -> Ptr Word8 -> IO ()
store32 (W32# w) (Ptr p) = IO (\s -> (# writeWord8OffAddrAsWord32# p 0# w s, () #))
{-# INLINE store32 #-}

store64 :: Word64 -> Ptr Word8 -> IO ()
store64 (W64# w) (Ptr p) = IO (\s -> (# writeWord8OffAddrAsWord64# p 0# w s, () #))
{-# INLINE store64 #-}

storeWord :: Word -> Ptr Word8 -> IO ()
storeWord (W# w) (Ptr p) = IO (\s -> (# writeWord8OffAddrAsWord# p 0# w s, () #))
{-# INLINE storeWord #-}

storeBytes :: ByteString -> Poke ()
storeBytes (BS fp n) = store n (\p -> unsafeWithForeignPtr fp (\q -> copyBytes p q n))
{-# INLINE storeBytes #-}

instance MonadPut Poke where
  putWord8 w = store 1 (store8 w)
  {-# INLINE putWord8 #-}
  putByteString = storeBytes
  {-# INLINE putByteString #-}
  putLazyByteString = L.foldrChunks (\chunk rest -> storeBytes chunk *> rest) (pure ())
  {-# INLINE putLazyByteString #-}
  flush = pure ()
  {-# INLINE flush #-}
  putWord16le w = store 2 (store16 (le16 w))
  {-# INLINE putWord16le #-}
  putWord16be w = store 2 (store16 (be16 w))
  {-# INLINE putWord16be #-}
  putWord16host w = store 2 (store16 w)
  {-# INLINE putWord16host #-}
  putWord32le w = store 4 (store32 (le32 w))
  {-# INLINE putWord32le #-}
  putWord32be w = store 4 (store32 (be32 w))
  {-# INLINE putWord32be #-}
  putWord32host w = store 4 (store32 w)
  {-# INLINE putWord32host #-}
  putWord64le w = store 8 (store64 (le64 w))
  {-# INLINE putWord64le #-}
  putWord64be w = store 8 (store64 (be64 w))
  {-# INLINE putWord64be #-}
  putWord64host w = store 8 (store64 w)
  {-# INLINE putWord64host #-}
  putWordhost w = store wordSize (storeWord w)
  {-# INLINE putWordhost #-}

-- | The bytes that a serializer writes: the same as
-- @'Data.Bytes.Put.runPutS' p@, without the builder. The serializer runs
-- twice, to measure and then to write into one buffer of the exact length,
-- so the cost of a small value is that of its bytes, where a builder first
-- allocates a buffer of 4 kB for any value and then copies what it wrote.
--
-- Give it a serializer that GHC can see, such as
-- @'Data.Bytes.Serial.serialize' x@ for a type that is known where this is
-- called. See the notes of this module.
encodeDirect :: (forall m. (MonadPut m) => m ()) -> ByteString
encodeDirect p =
  case p of
    Size measure -> case measure 0# of
      (# n, _ #) -> unsafeCreate (I# n) $ \(Ptr start) ->
        IO $ \s -> case p of
          Poke write -> case write start s of
            (# s1, end, _ #)
              | isTrue# (minusAddr# end start ==# n) -> (# s1, () #)
              | otherwise -> errorWithoutStackTrace "encodeDirect: the serializer wrote a different length"
{-# INLINE encodeDirect #-}

-- | The number of bytes that a serializer writes, without writing them:
-- the same as the length of @'Data.Bytes.Put.runPutS' p@. Use it for the
-- size of a transaction or of a block, which is asked for more often than
-- its bytes.
sizeDirect :: (forall m. (MonadPut m) => m ()) -> Int
sizeDirect p =
  case p of
    Size measure -> case measure 0# of
      (# n, _ #) -> I# n
{-# INLINE sizeDirect #-}

-- | Write in cereal what a serializer writes, built with 'encodeDirect' and
-- added to the output in one piece. It is the same as the serializer run
-- in cereal, and is meant for the @put@ of a 'Data.Serialize.Serialize'
-- instance:
--
-- > instance Serialize TxOut where
-- >   put x = putDirect (serialize x)
putDirect :: (forall m. (MonadPut m) => m ()) -> Cereal.Put
putDirect p = Cereal.putByteString (encodeDirect p)
{-# INLINE putDirect #-}

-- | Write the bytes of a short byte string. 'MonadPut' has no method for
-- one, so a serializer would have to copy it into a 'ByteString' first, only
-- to copy that again. This function does so in a monad that it does not
-- know, and writes the bytes straight from where they are in the monads of
-- this module, of cereal and of binary, through the rewrite rules below.
-- The hashes of this library are short byte strings.
putShortBytes :: (MonadPut m) => ShortByteString -> m ()
putShortBytes s = putByteString (fromShort s)
{-# INLINE [1] putShortBytes #-}

{-# RULES
"putShortBytes/Size" putShortBytes = countShort
"putShortBytes/Poke" putShortBytes = storeShort
"putShortBytes/cereal" putShortBytes = Cereal.putShortByteString
"putShortBytes/binary" putShortBytes = Binary.putShortByteString
  #-}

countShort :: ShortByteString -> Size ()
countShort s = count (Short.length s)
{-# INLINE countShort #-}

storeShort :: ShortByteString -> Poke ()
storeShort s = store n (\p -> Short.copyToPtr s 0 p n)
  where
    n = Short.length s
{-# INLINE storeShort #-}

-- Peek

-- | What t'Peek' reads from: the bytes, and whether they are the whole input
-- or only what has arrived of it so far.
data Input = Input {-# UNPACK #-} !ByteString !Bool

-- | The monad that reads: every read checks that its bytes are there, takes
-- them at a position and moves the position past them. Its result is the
-- new position and the value, or nothing.
--
-- It has no error messages and cannot wait for more input. Where a parser
-- fails, or asks for something that depends on input that is not there
-- yet, t'Peek' gives up, and the function that ran it runs the parser again
-- through cereal, which reports the error or waits. It gives up on 'fail',
-- on a read past the end, on a negative length, on 'ensure' and on
-- 'getLazyByteString', and on 'isEmpty' and 'remaining' at the end of bytes
-- that are not the whole input.
newtype Peek a = Peek (Input -> Int# -> (# (# #) | (# Int#, a #) #))

instance Functor Peek where
  fmap f (Peek g) =
    Peek . oneShot $ \i -> oneShot $ \o ->
      case g i o of
        (# | (# o1, a #) #) -> (# | (# o1, f a #) #)
        (# (# #) | #) -> (# (# #) | #)
  {-# INLINE fmap #-}

instance Applicative Peek where
  pure a = Peek (oneShot (\_ -> oneShot (\o -> (# | (# o, a #) #))))
  {-# INLINE pure #-}
  Peek f <*> Peek g =
    Peek . oneShot $ \i -> oneShot $ \o ->
      case f i o of
        (# | (# o1, h #) #) -> case g i o1 of
          (# | (# o2, a #) #) -> (# | (# o2, h a #) #)
          (# (# #) | #) -> (# (# #) | #)
        (# (# #) | #) -> (# (# #) | #)
  {-# INLINE (<*>) #-}
  Peek f *> Peek g =
    Peek . oneShot $ \i -> oneShot $ \o ->
      case f i o of
        (# | (# o1, _ #) #) -> g i o1
        (# (# #) | #) -> (# (# #) | #)
  {-# INLINE (*>) #-}

instance Monad Peek where
  Peek g >>= f =
    Peek . oneShot $ \i -> oneShot $ \o ->
      case g i o of
        (# | (# o1, a #) #) -> case f a of Peek h -> h i o1
        (# (# #) | #) -> (# (# #) | #)
  {-# INLINE (>>=) #-}
  (>>) = (*>)
  {-# INLINE (>>) #-}

instance Fail.MonadFail Peek where
  fail _ = giveUp
  {-# INLINE fail #-}

giveUp :: Peek a
giveUp = Peek (\_ _ -> (# (# #) | #))
{-# INLINE giveUp #-}

-- | Read that many bytes with the given action, which gets their address.
-- The number must not be negative.
load :: Int -> (Ptr Word8 -> IO a) -> Peek a
load (I# k) f =
  Peek . oneShot $ \(Input (BS fp (I# len)) _) -> oneShot $ \o ->
    if isTrue# (k <=# (len -# o))
      then case accursedUnutterablePerformIO (unsafeWithForeignPtr fp (\p -> f (p `plusPtr` I# o))) of
        !a -> (# | (# o +# k, a #) #)
      else (# (# #) | #)
{-# INLINE load #-}

-- The loads below read a whole word at an address that need not be aligned.

load8 :: Ptr Word8 -> IO Word8
load8 (Ptr p) = IO (\s -> case readWord8OffAddr# p 0# s of (# s1, w #) -> (# s1, W8# w #))
{-# INLINE load8 #-}

load16 :: Ptr Word8 -> IO Word16
load16 (Ptr p) = IO (\s -> case readWord8OffAddrAsWord16# p 0# s of (# s1, w #) -> (# s1, W16# w #))
{-# INLINE load16 #-}

load32 :: Ptr Word8 -> IO Word32
load32 (Ptr p) = IO (\s -> case readWord8OffAddrAsWord32# p 0# s of (# s1, w #) -> (# s1, W32# w #))
{-# INLINE load32 #-}

load64 :: Ptr Word8 -> IO Word64
load64 (Ptr p) = IO (\s -> case readWord8OffAddrAsWord64# p 0# s of (# s1, w #) -> (# s1, W64# w #))
{-# INLINE load64 #-}

loadWord :: Ptr Word8 -> IO Word
loadWord (Ptr p) = IO (\s -> case readWord8OffAddrAsWord# p 0# s of (# s1, w #) -> (# s1, W# w #))
{-# INLINE loadWord #-}

-- | That many bytes of the input, not copied, or nothing for a negative
-- number.
slice :: Int -> Peek ByteString
slice n@(I# k) =
  Peek . oneShot $ \(Input (BS fp (I# len)) _) -> oneShot $ \o ->
    if isTrue# (k >=# 0#) && isTrue# (k <=# (len -# o))
      then (# | (# o +# k, BS (fp `plusForeignPtr` I# o) n #) #)
      else (# (# #) | #)
{-# INLINE slice #-}

instance MonadGet Peek where
  type Remaining Peek = Int
  type Bytes Peek = ByteString
  skip n = () <$ slice n
  {-# INLINE skip #-}

  -- how much of the input this returns differs from one monad to the next
  ensure _ = giveUp
  {-# INLINE ensure #-}
  lookAhead (Peek g) =
    Peek . oneShot $ \i -> oneShot $ \o ->
      case g i o of
        (# | (# _, a #) #) -> (# | (# o, a #) #)
        (# (# #) | #) -> (# (# #) | #)
  {-# INLINE lookAhead #-}
  lookAheadM (Peek g) =
    Peek . oneShot $ \i -> oneShot $ \o ->
      case g i o of
        (# | (# o1, a #) #) -> case a of
          Nothing -> (# | (# o, a #) #)
          Just _ -> (# | (# o1, a #) #)
        (# (# #) | #) -> (# (# #) | #)
  {-# INLINE lookAheadM #-}
  lookAheadE (Peek g) =
    Peek . oneShot $ \i -> oneShot $ \o ->
      case g i o of
        (# | (# o1, a #) #) -> case a of
          Left _ -> (# | (# o, a #) #)
          Right _ -> (# | (# o1, a #) #)
        (# (# #) | #) -> (# (# #) | #)
  {-# INLINE lookAheadE #-}
  getBytes = slice
  {-# INLINE getBytes #-}

  -- At the end of bytes that are only a part of the input, whether more
  -- follows is not known here.
  remaining =
    Peek $ \(Input (BS _ (I# len)) whole) o ->
      if whole then (# | (# o, I# (len -# o) #) #) else (# (# #) | #)
  {-# INLINE remaining #-}
  isEmpty =
    Peek $ \(Input (BS _ (I# len)) whole) o ->
      if isTrue# (o <# len)
        then (# | (# o, False #) #)
        else if whole then (# | (# o, True #) #) else (# (# #) | #)
  {-# INLINE isEmpty #-}
  getWord8 = load 1 load8
  {-# INLINE getWord8 #-}

  -- a copy, as in cereal, so that the value does not keep the input alive
  getByteString n = slice n >>= \b -> let !c = B.copy b in pure c
  {-# INLINE getByteString #-}
  getLazyByteString _ = giveUp
  {-# INLINE getLazyByteString #-}
  getWord16be = be16 <$> load 2 load16
  {-# INLINE getWord16be #-}
  getWord16le = le16 <$> load 2 load16
  {-# INLINE getWord16le #-}
  getWord16host = load 2 load16
  {-# INLINE getWord16host #-}
  getWord32be = be32 <$> load 4 load32
  {-# INLINE getWord32be #-}
  getWord32le = le32 <$> load 4 load32
  {-# INLINE getWord32le #-}
  getWord32host = load 4 load32
  {-# INLINE getWord32host #-}
  getWord64be = be64 <$> load 8 load64
  {-# INLINE getWord64be #-}
  getWord64le = le64 <$> load 8 load64
  {-# INLINE getWord64le #-}
  getWord64host = load 8 load64
  {-# INLINE getWord64host #-}
  getWordhost = load wordSize loadWord
  {-# INLINE getWordhost #-}

-- | Run a parser on bytes that are the whole input: the same as
-- @'runGetS' p@, without the continuations of cereal when the bytes parse.
-- Like 'runGetS', it does not mind bytes left over after the value; a
-- parser that must end with the input says so with 'isEmpty', as
-- 'Haskoin.Util.Marshal.decodeSerial' does.
--
-- When the bytes do not parse, the parser runs again through cereal to
-- report why, so a failure costs a little more than it did. Do not use this
-- where most inputs are expected to fail.
decodeDirect :: (forall m. (MonadGet m) => m a) -> ByteString -> Either String a
decodeDirect p bytes =
  case p of
    Peek peek -> case peek (Input bytes True) 0# of
      (# | (# _, a #) #) -> Right a
      (# (# #) | #) -> runGetS p bytes
{-# INLINE decodeDirect #-}

-- | Read in cereal what a parser reads, from the input that cereal has at
-- hand when that holds the whole value, and through cereal otherwise. It is
-- the same as the parser run in cereal, and is meant for the @get@ of a
-- 'Data.Serialize.Serialize' instance:
--
-- > instance Serialize TxOut where
-- >   get = getDirect deserialize
getDirect :: (forall m. (MonadGet m) => m a) -> Cereal.Get a
getDirect p = do
  bytes <- Cereal.ensure 0
  left <- Cereal.remaining
  -- cereal takes the input for whole when it knows of nothing after it
  case p of
    Peek peek -> case peek (Input bytes (left == B.length bytes)) 0# of
      (# | (# n, a #) #) -> a <$ Cereal.uncheckedSkip (I# n)
      (# (# #) | #) -> p
{-# INLINE getDirect #-}

-- | Read that many bytes as a short byte string, copied once from the
-- input. The value is built before the parser goes on, so that it does not
-- keep the input alive as an unevaluated copy would.
getShortBytes :: (MonadGet m) => Int -> m ShortByteString
getShortBytes n = getBytes n >>= \b -> let !s = toShort b in pure s
{-# INLINE getShortBytes #-}
