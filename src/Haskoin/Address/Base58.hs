{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ImportQualifiedPost #-}
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
-- Support for legacy 'Base58' addresses. Superseded by Bech32 for Bitcoin SegWit
-- (BTC) and CashAddr for Bitcoin Cash (BCH).
module Haskoin.Address.Base58
  ( -- * Base58
    Base58,
    encodeBase58,
    decodeBase58,
    encodeBase58Check,
    decodeBase58Check,
  )
where

import Control.Monad (guard)
import Data.Array (Array, assocs, listArray, (!), (//))
import Data.Bits (shiftL, (.|.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Unsafe qualified as BU
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (Serial (serialize))
import Data.Text (Text)
import Data.Text.Encoding qualified as E
import Data.Word (Word64, Word8)
import Haskoin.Crypto.Hash (checkSum32)
import Haskoin.Util.Helpers (integerToBS)

-- | 'Base58' classic Bitcoin address format.
type Base58 = Text

-- | Symbols for Base58 encoding.
b58Data :: ByteString
b58Data = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

b58Array :: Array Int Word8
b58Array = listArray (0, 57) (B.unpack b58Data)

-- | Value of each byte as a Base58 digit. Bytes outside the alphabet map to
-- 'Nothing'. Every byte of a multi-byte UTF-8 character is outside the
-- alphabet, so no non-ASCII character can ever be read as a digit.
b58InvArray :: Array Word8 (Maybe Int)
b58InvArray =
  listArray
    (minBound, maxBound)
    (repeat Nothing)
    // map swap (assocs b58Array)
  where
    swap (i, c) = (c, Just i)

-- | Convert a number less than 58 into a 'Base58' character.
b58 :: Int -> Word8
b58 = BU.unsafeIndex b58Data

-- | Convert a 'Base58' character into the number it represents.
b58' :: Word8 -> Maybe Int
b58' = (b58InvArray !)

-- | Decode the UTF-8 bytes of a 'Base58' string into an 'Integer'. Fails on
-- the first byte that is not a 'Base58' digit.
decodeBase58I :: ByteString -> Maybe Integer
decodeBase58I = B.foldl' step (Just 0)
  where
    step acc w = do
      n <- acc
      d <- b58' w
      return (n * 58 + toInteger d)

-- | Encode an arbitrary 'ByteString' into its 'Base58' representation,
-- preserving leading zeroes.
--
-- The bytes are read as one number, and the number is divided by 58^10
-- (430,804,206,899,405,824), the largest power of 58 that fits in a machine
-- word: each division of the big number gives ten digits, which are then
-- taken apart in machine words. Version 1.6.0 divided the big number by 58
-- for every digit, ten times as many divisions. Versions 1.6.3 and 1.6.4
-- kept the number as a list of limbs of 32 bits and divided it by 58^5,
-- which was quicker than 1.6.0 for an address and slower from about 500
-- bytes up. This way is quicker than both at every length, by the benchmark
-- of this package, at @-O1@ as at @-O2@: about three times as fast as 1.6.0
-- for an address of 25 bytes, and about twelve times for 20,000 bytes.
--
-- The time still grows with the square of the length, as for
-- 'decodeBase58'. That does not matter for anything in Bitcoin, where the
-- longest input is an extended key of 82 bytes, but Base58 is not a format
-- for large data.
encodeBase58 :: ByteString -> Base58
encodeBase58 bs =
  E.decodeLatin1 (B.replicate (B.length z) (b58 0) <> B.pack (map b58 (dropWhile (== 0) (groups (number b) []))))
  where
    (z, b) = B.span (== 0) bs
    -- the bytes as a number, most significant first: the two halves are
    -- read on their own and joined, so that the big numbers are few
    number :: ByteString -> Integer
    number bytes
      | B.length bytes <= 8 = toInteger (B.foldl' (\acc w -> acc `shiftL` 8 .|. fromIntegral w) (0 :: Word64) bytes)
      | otherwise =
          let (h, l) = B.splitAt (B.length bytes `div` 2) bytes
           in number h `shiftL` (8 * B.length l) .|. number l
    -- the digits, most significant first, ten for each division; the
    -- first group starts with zeroes that are not digits of the number
    groups :: Integer -> [Int] -> [Int]
    groups 0 acc = acc
    groups n !acc = let (q, r) = n `quotRem` chunk in groups q (ten (10 :: Int) (fromInteger r) acc)
    chunk = 430804206899405824 :: Integer
    ten :: Int -> Word64 -> [Int] -> [Int]
    ten 0 _ acc = acc
    ten k !w acc = let !d = fromIntegral (w `rem` 58) in ten (k - 1) (w `quot` 58) (d : acc)

-- | Decode a 'Base58'-encoded 'Text' to a 'ByteString'. Returns 'Nothing' if
-- the input contains any character outside the 'Base58' alphabet.
--
-- The time this takes grows with the square of the length of the input,
-- since the digits are accumulated into one big number. Bound the length
-- before decoding text from an untrusted source. No Bitcoin address is
-- longer than 35 characters and no extended key longer than 112;
-- 'Haskoin.Address.textToAddr', 'Haskoin.Crypto.Keys.fromWif' and
-- 'Haskoin.Crypto.Keys.xPrvImport' apply those bounds themselves.
decodeBase58 :: Base58 -> Maybe ByteString
decodeBase58 t =
  B.append prefix <$> r
  where
    (z, b) = B.span (== b58 0) (E.encodeUtf8 t)
    prefix = B.replicate (B.length z) 0 -- preserve leading 1's
    r
      | B.null b = Just B.empty
      | otherwise = integerToBS <$> decodeBase58I b

-- | Computes a checksum for the input 'ByteString' and encodes the input and
-- the checksum as 'Base58'.
encodeBase58Check :: ByteString -> Base58
encodeBase58Check bs = encodeBase58 (bs <> runPutS (serialize (checkSum32 bs)))

-- | Decode a 'Base58'-encoded string that contains a checksum. This function
-- returns 'Nothing' if the input string contains invalid 'Base58' characters,
-- if it is too short to hold a checksum, or if the checksum fails. The cost
-- grows with the square of the length, as for 'decodeBase58': bound the
-- length of untrusted input first.
decodeBase58Check :: Base58 -> Maybe ByteString
decodeBase58Check t = do
  rs <- decodeBase58 t
  guard $ B.length rs >= checkSumLength
  let (res, chk) = B.splitAt (B.length rs - checkSumLength) rs
  guard $ chk == (runPutS . serialize . checkSum32) res
  return res
  where
    checkSumLength = 4
