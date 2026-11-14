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
-- The bytes are read as one number in limbs of 32 bits, and divided by 58^5
-- (656,356,768) in machine words: each pass over the limbs gives five digits. An address
-- of 25 bytes takes seven passes over seven limbs. Building an 'Integer'
-- and dividing that, as this did until 1.6.2, took about five times as long,
-- and a server writes an address for every input and output it shows.
encodeBase58 :: ByteString -> Base58
encodeBase58 bs =
  E.decodeLatin1 (B.replicate (B.length z) (b58 0) <> B.pack (map b58 (dropWhile (== 0) (groups (limbs b) []))))
  where
    (z, b) = B.span (== 0) bs
    -- the number, most significant limb first, each limb under 2^32
    limbs bytes =
      let padded = B.replicate ((4 - B.length bytes `mod` 4) `mod` 4) 0 <> bytes
       in [ B.foldl' (\acc w -> acc `shiftL` 8 .|. fromIntegral w) 0 (BU.unsafeTake 4 (BU.unsafeDrop k padded))
          | k <- [0, 4 .. B.length padded - 4]
          ]
    -- the digits, most significant first, five for each division
    groups ls !acc = case dropWhile (== 0) ls of
      [] -> acc
      live -> let (q, r) = divide live in groups q (five (5 :: Int) r acc)
    -- the number divided by 58^5, with the remainder; a remainder is under
    -- 2^30, so with a limb after it it fits in 64 bits
    divide = go 0 []
      where
        go !r qs [] = (reverse qs, r)
        go !r qs (x : xs) =
          let !cur = r `shiftL` 32 .|. x
              !q = cur `quot` chunk
           in go (cur `rem` chunk) (q : qs) xs
    chunk = 656356768 :: Word64
    five :: Int -> Word64 -> [Int] -> [Int]
    five 0 _ acc = acc
    five k !w acc = let !d = fromIntegral (w `rem` 58) in five (k - 1) (w `quot` 58) (d : acc)

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
