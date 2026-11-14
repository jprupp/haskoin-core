{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Address.Bech32
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Support for Bitcoin SegWit (BTC) Bech32 addresses. This module is a modified
-- version of Marko Bencun's reference implementation.
module Haskoin.Address.Bech32
  ( -- * Bech32
    HRP,
    Bech32,
    Bech32Encoding (..),
    bech32Const,
    Data,
    bech32Encode,
    bech32Decode,
    toBase32,
    toBase256,
    segwitEncode,
    segwitDecode,
    Word5 (..),
    word5,
    fromWord5,
  )
where

import Control.Monad (guard)
import Data.Array
  ( Array,
    assocs,
    bounds,
    listArray,
    (!),
    (//),
  )
import Data.Bits
  ( Bits,
    shiftL,
    shiftR,
    testBit,
    unsafeShiftL,
    unsafeShiftR,
    xor,
    (.&.),
    (.|.),
  )
import Data.ByteString qualified as B
import Data.ByteString.Unsafe qualified as BU
import Data.Foldable (foldl')
import Data.Functor.Identity (Identity, runIdentity)
import Data.Ix (Ix (..))
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as E
import Data.Word (Word8)

data Bech32Encoding = Bech32 | Bech32m
  deriving (Eq, Show, Ord, Enum)

-- | Bech32 human-readable string.
type Bech32 = Text

-- | Human-readable part of 'Bech32' address.
type HRP = Text

-- | Data part of 'Bech32' address.
type Data = [Word8]

(.>>.), (.<<.) :: (Bits a) => a -> Int -> a
(.>>.) = unsafeShiftR
(.<<.) = unsafeShiftL

-- | Five-bit word for Bech32.
newtype Word5
  = UnsafeWord5 Word8
  deriving (Eq, Ord)

instance Ix Word5 where
  range (UnsafeWord5 m, UnsafeWord5 n) = map UnsafeWord5 $ range (m, n)
  index (UnsafeWord5 m, UnsafeWord5 n) (UnsafeWord5 i) = index (m, n) i
  inRange (m, n) i = m <= i && i <= n

-- | Convert an integer number into a five-bit word.
word5 :: (Integral a) => a -> Word5
word5 x = UnsafeWord5 (fromIntegral x .&. 31)
{-# INLINE word5 #-}
{-# SPECIALIZE INLINE word5 :: Word8 -> Word5 #-}

-- | Convert a five-bit word into a number.
fromWord5 :: (Num a) => Word5 -> a
fromWord5 (UnsafeWord5 x) = fromIntegral x
{-# INLINE fromWord5 #-}
{-# SPECIALIZE INLINE fromWord5 :: Word5 -> Word8 #-}

-- | 'Bech32' character map as array of five-bit integers to character.
charset :: Array Word5 Char
charset =
  listArray (UnsafeWord5 0, UnsafeWord5 31) "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

-- | 'charset' as bytes, for writing: looked up without bounds or boxes.
charsetBytes :: B.ByteString
charsetBytes = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

-- | Inverse of 'charset'. Only the lowercase characters are present. The
-- decoder checks that the string is ASCII and not mixed case, then lowercases
-- it, before looking characters up here. No character from another alphabet
-- can therefore stand in for a 'Bech32' character.
charsetInverse :: Array Char (Maybe Word5)
charsetInverse =
  listArray ('0', 'z') (repeat Nothing) // map swap (assocs charset)
  where
    swap (w, c) = (c, Just w)

-- | Convert a lowercase character to its five-bit value from 'charset'.
charsetMap :: Char -> Maybe Word5
charsetMap c
  | inRange (bounds charsetInverse) c = charsetInverse ! c
  | otherwise = Nothing

-- | Calculate or validate 'Bech32' checksum.
bech32Polymod :: [Word5] -> Word
bech32Polymod values = foldl' go 1 values .&. 0x3fffffff
  where
    -- the five generators, each where its bit of the top of the accumulator
    -- is set, written out: a list of them for each character made the
    -- checksum the most of the cost of an address
    go !chk value =
      g 29 0x2a1462b3 . g 28 0x3d4233dd . g 27 0x1ea119fa . g 26 0x26508e6d $ g 25 0x3b6a57b2 chk'
      where
        -- Keep only the low 25 bits before shifting, as the reference
        -- implementation does, so the accumulator never grows past 30 bits.
        chk' = ((chk .&. 0x1ffffff) .<<. 5) `xor` fromWord5 value
        g :: Int -> Word -> Word -> Word
        g i gen c
          | testBit chk i = c `xor` gen
          | otherwise = c

-- | Convert human-readable part of 'Bech32' string into a list of five-bit
-- words.
bech32HRPExpand :: HRP -> [Word5]
bech32HRPExpand hrp =
  map (word5 . (.>>. 5)) hrpBytes
    ++ [word5 (0 :: Word8)]
    ++ map word5 hrpBytes
  where
    hrpBytes = B.unpack $ E.encodeUtf8 hrp

bech32Const :: Bech32Encoding -> Word
bech32Const Bech32 = 0x00000001
bech32Const Bech32m = 0x2bc830a3

-- | Calculate Bech32 checksum for a string of five-bit words.
bech32CreateChecksum :: Bech32Encoding -> HRP -> [Word5] -> [Word5]
bech32CreateChecksum enc hrp dat = [word5 (polymod .>>. i) | i <- [25, 20 .. 0]]
  where
    values = bech32HRPExpand hrp ++ dat
    w5 = values ++ map UnsafeWord5 [0, 0, 0, 0, 0, 0]
    polymod = bech32Polymod w5 `xor` bech32Const enc

-- | Verify Bech32 checksum for a human-readable part and string of five-bit words.
bech32VerifyChecksum :: HRP -> [Word5] -> Maybe Bech32Encoding
bech32VerifyChecksum hrp dat =
  let poly = bech32Polymod (bech32HRPExpand hrp ++ dat)
   in if
        | poly == bech32Const Bech32 -> Just Bech32
        | poly == bech32Const Bech32m -> Just Bech32m
        | otherwise -> Nothing

-- | Maximum length of a Bech32 result.
maxBech32Length :: Int
maxBech32Length = 90

-- | Number of five-bit words in a Bech32 checksum.
checksumLength :: Int
checksumLength = 6

-- | Encode string of five-bit words into 'Bech32' using a provided
-- human-readable part. Can fail if 'HRP' is invalid or result would be longer
-- than 90 characters.
bech32Encode :: Bech32Encoding -> HRP -> [Word5] -> Maybe Bech32
bech32Encode enc hrp dat = do
  guard $ checkHRP hrp
  -- The constructor of 'Word5' can hold any byte, and only 0 to 31 have a
  -- character.
  guard $ all (\(UnsafeWord5 w) -> w <= 31) dat
  let dat' = dat ++ bech32CreateChecksum enc (T.toLower hrp) dat
      rest = map (\(UnsafeWord5 w) -> BU.unsafeIndex charsetBytes (fromIntegral w)) dat'
      result = T.concat [T.toLower hrp, T.pack "1", E.decodeLatin1 (B.pack rest)]
  guard $ T.length result <= maxBech32Length
  return result

-- | BIP-173 allows only US-ASCII characters in the range 33 to 126 anywhere
-- in a 'Bech32' string.
isBech32Char :: Char -> Bool
isBech32Char c = c >= '\x21' && c <= '\x7e'

-- | Check that human-readable part is valid for a 'Bech32' string.
checkHRP :: HRP -> Bool
checkHRP hrp = not (T.null hrp) && T.all isBech32Char hrp

-- | Decode human-readable 'Bech32' string into a human-readable part and a
-- string of five-bit words.
bech32Decode :: Bech32 -> Maybe (Bech32Encoding, HRP, [Word5])
bech32Decode bech32 = do
  guard $ T.length bech32 <= maxBech32Length
  guard $ T.all isBech32Char bech32
  -- The string must be all uppercase or all lowercase, never a mix.
  guard $ T.toUpper bech32 == bech32 || lowerBech32 == bech32
  let (hrp, dat) = T.breakOnEnd "1" lowerBech32
  guard $ T.length dat >= checksumLength
  hrp' <- T.stripSuffix "1" hrp
  guard $ checkHRP hrp'
  dat' <- mapM charsetMap $ T.unpack dat
  enc <- bech32VerifyChecksum hrp' dat'
  return (enc, hrp', take (T.length dat - checksumLength) dat')
  where
    lowerBech32 = T.toLower bech32

type Pad f = Int -> Int -> Word -> [[Word]] -> f [[Word]]

yesPadding :: Pad Identity
yesPadding _ 0 _ result = return result
yesPadding _ _ padValue result = return $ [padValue] : result
{-# INLINE yesPadding #-}

noPadding :: Pad Maybe
noPadding frombits bits padValue result = do
  guard $ bits < frombits && padValue == 0
  return result
{-# INLINE noPadding #-}

-- | Big endian conversion of a bytestring from base \(2^{frombits}\) to base
-- \(2^{tobits}\). {frombits} and {twobits} must be positive and
-- \(2^{frombits}\) and \(2^{tobits}\) must be smaller than the size of Word.
-- Every value in 'dat' must be strictly smaller than \(2^{frombits}\).
convertBits :: (Functor f) => [Word] -> Int -> Int -> Pad f -> f [Word]
convertBits dat frombits tobits pad = concat . reverse <$> go dat 0 0 []
  where
    go [] acc bits result =
      let padValue = (acc .<<. (tobits - bits)) .&. maxv
       in pad frombits bits padValue result
    go (value : dat') acc bits result =
      go dat' acc' (bits' `rem` tobits) (result' : result)
      where
        -- Only the low (frombits + tobits - 1) bits of the accumulator are
        -- ever read, so masking to them keeps it from overflowing on long
        -- inputs.
        acc' = ((acc .<<. frombits) .|. fromIntegral value) .&. maxAcc
        bits' = bits + frombits
        result' =
          [ (acc' .>>. b) .&. maxv
          | b <- [bits' - tobits, bits' - 2 * tobits .. 0]
          ]
    maxv = (1 .<<. tobits) - 1
    maxAcc = (1 .<<. (frombits + tobits - 1)) - 1
{-# INLINE convertBits #-}

-- | Convert from eight-bit to five-bit word string, adding padding as required.
--
-- Each five bits are read from the two bytes that hold them, as
-- "Haskoin.Address.CashAddr" does, rather than through 'convertBits', whose
-- lists made this most of the cost of writing a SegWit address. The tests
-- hold it to 'convertBits'.
toBase32 :: [Word8] -> [Word5]
toBase32 dat = map UnsafeWord5 (B.unpack (fst (B.unfoldrN groups group 0)))
  where
    bs = B.pack dat
    groups = (B.length bs * 8 + 4) `div` 5
    byte :: Int -> Word
    byte i
      | i < B.length bs = fromIntegral (BU.unsafeIndex bs i)
      | otherwise = 0
    -- the five bits that start this many bits into the input, padded with
    -- zeros after its end
    group bit =
      let i = bit `shiftR` 3
          two = byte i `shiftL` 8 .|. byte (i + 1)
       in Just (fromIntegral ((two `shiftR` (11 - (bit .&. 7))) .&. 0x1f), bit + 5)

-- | Convert from five-bit word string to eight-bit word string. Fails if the
-- padding bits are not zero, or if there are enough of them to hold a whole
-- five-bit word, because the input is then not a canonical encoding.
toBase256 :: [Word5] -> Maybe [Word8]
toBase256 dat =
  map fromIntegral <$> convertBits (map fromWord5 dat) 5 8 noPadding

-- | Check if witness version and program are valid.
segwitCheck :: Bech32Encoding -> Word8 -> Data -> Bool
segwitCheck enc witver witprog =
  witver <= 16
    && if witver == 0
      then enc == Bech32 && (length witprog == 20 || length witprog == 32)
      else enc == Bech32m && (length witprog >= 2 && length witprog <= 40)

-- | Decode SegWit 'Bech32' address from a string and expected human-readable part.
segwitDecode :: HRP -> Bech32 -> Maybe (Word8, Data)
segwitDecode hrp addr = do
  (enc, hrp', dat) <- bech32Decode addr
  guard $ hrp == hrp'
  (witver, datBase32) <- case dat of
    [] -> Nothing
    (v : rest) -> Just (fromWord5 v, rest)
  decoded <- toBase256 datBase32
  guard $ segwitCheck enc witver decoded
  return (witver, decoded)

-- | Encode 'Data' as a SegWit 'Bech32' address. Needs human-readable part and
-- witness program version.
segwitEncode :: HRP -> Word8 -> Data -> Maybe Text
segwitEncode hrp witver witprog = do
  guard $ segwitCheck enc witver witprog
  bech32Encode enc hrp $ word5 witver : toBase32 witprog
  where
    enc = if witver == 0 then Bech32 else Bech32m
