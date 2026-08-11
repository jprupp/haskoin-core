{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Address.Base58
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
    testBit,
    unsafeShiftL,
    unsafeShiftR,
    xor,
    (.&.),
    (.|.),
  )
import Data.ByteString qualified as B
import Data.Char (toUpper)
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

-- | Convert a character to its five-bit value from 'Bech32' 'charset'.
charsetMap :: Char -> Maybe Word5
charsetMap c
  | inRange (bounds inv) upperC = inv ! upperC
  | otherwise = Nothing
  where
    upperC = toUpper c
    inv = listArray ('0', 'Z') (repeat Nothing) // map swap (assocs charset)
    swap (a, b) = (toUpper b, Just a)

-- | Calculate or validate 'Bech32' checksum.
bech32Polymod :: [Word5] -> Word
bech32Polymod values = foldl' go 1 values .&. 0x3fffffff
  where
    go chk value =
      foldl' xor chk' [g | (g, i) <- zip generator [25 ..], testBit chk i]
      where
        generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk' = chk .<<. 5 `xor` fromWord5 value

-- | Convert human-readable part of 'Bech32' string into a list of five-bit
-- words.
bech32HRPExpand :: HRP -> [Word5]
bech32HRPExpand hrp =
  map (UnsafeWord5 . (.>>. 5)) hrpBytes
    ++ [UnsafeWord5 0]
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

-- | Encode string of five-bit words into 'Bech32' using a provided
-- human-readable part. Can fail if 'HRP' is invalid or result would be longer
-- than 90 characters.
bech32Encode :: Bech32Encoding -> HRP -> [Word5] -> Maybe Bech32
bech32Encode enc hrp dat = do
  guard $ checkHRP hrp
  let dat' = dat ++ bech32CreateChecksum enc (T.toLower hrp) dat
      rest = map (charset !) dat'
      result = T.concat [T.toLower hrp, T.pack "1", T.pack rest]
  guard $ T.length result <= maxBech32Length
  return result

-- | Check that human-readable part is valid for a 'Bech32' string.
checkHRP :: HRP -> Bool
checkHRP hrp =
  not (T.null hrp)
    && T.all (\char -> char >= '\x21' && char <= '\x7e') hrp

-- | Decode human-readable 'Bech32' string into a human-readable part and a
-- string of five-bit words.
bech32Decode :: Bech32 -> Maybe (Bech32Encoding, HRP, [Word5])
bech32Decode bech32 = do
  guard $ T.length bech32 <= maxBech32Length
  guard $ T.toUpper bech32 == bech32 || lowerBech32 == bech32
  let (hrp, dat) = T.breakOnEnd "1" lowerBech32
  guard $ T.length dat >= 6
  hrp' <- T.stripSuffix "1" hrp
  guard $ checkHRP hrp'
  dat' <- mapM charsetMap $ T.unpack dat
  enc <- bech32VerifyChecksum hrp' dat'
  return (enc, hrp', take (T.length dat - 6) dat')
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
        acc' = (acc .<<. frombits) .|. fromIntegral value
        bits' = bits + frombits
        result' =
          [ (acc' .>>. b) .&. maxv
          | b <- [bits' - tobits, bits' - 2 * tobits .. 0]
          ]
    maxv = (1 .<<. tobits) - 1
{-# INLINE convertBits #-}

-- | Convert from eight-bit to five-bit word string, adding padding as required.
toBase32 :: [Word8] -> [Word5]
toBase32 dat =
  map word5 $ runIdentity $ convertBits (map fromIntegral dat) 8 5 yesPadding

-- | Convert from five-bit word string to eight-bit word string, ignoring padding.
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
  guard $ (hrp == hrp') && not (null dat)
  let (UnsafeWord5 witver : datBase32) = dat
  decoded <- toBase256 datBase32
  guard $ segwitCheck enc witver decoded
  return (witver, decoded)

-- | Encode 'Data' as a SegWit 'Bech32' address. Needs human-readable part and
-- witness program version.
segwitEncode :: HRP -> Word8 -> Data -> Maybe Text
segwitEncode hrp witver witprog = do
  guard $ segwitCheck enc witver witprog
  bech32Encode enc hrp $ UnsafeWord5 witver : toBase32 witprog
  where
    enc = if witver == 0 then Bech32 else Bech32m
