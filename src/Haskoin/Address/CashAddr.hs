{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Address.CashAddr
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Support for Bitcoin Cash (BCH) CashAddr format.
module Haskoin.Address.CashAddr
  ( -- * CashAddr
    CashPrefix,
    CashVersion,
    CashAddr,
    Cash32,
    cashAddrDecode,
    cashAddrEncode,
    cash32decodeType,
    cash32encodeType,
    cash32decode,
    cash32encode,
    decodeVersionByte,
    encodeVersionByte,
  )
where

import Control.Monad (guard)
import Data.Bits
  ( Bits
      ( shiftL,
        shiftR,
        testBit,
        xor,
        (.&.),
        (.|.)
      ),
  )
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Char8 qualified as C
import Data.Char (isAscii, isAsciiLower, isAsciiUpper, ord)
import Data.List (elemIndex, foldl')
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding (decodeLatin1, decodeUtf8, encodeUtf8)
import Data.Word (Word64, Word8)
import Haskoin.Network.Data (Network (cashAddrPrefix))
import Haskoin.Util.Helpers (convertBits)

-- | 'CashAddr' prefix, usually shown before the colon in addresses, but sometimes
-- omitted. It is used in the checksum calculation to avoid parsing an address
-- from the wrong network.
type CashPrefix = Text

-- | 'CashAddr' type. Zero is P2PKH and one is P2SH. Two and three are their
-- token-aware forms, introduced with CashTokens.
type CashVersion = Word8

-- | High level 'CashAddr' human-reabale string, with explicit or implicit prefix.
type CashAddr = Text

-- | Low level 'Cash32' is the human-readable low-level encoding used by 'CashAddr'.
-- It need not encode a valid address but any binary data.
type Cash32 = Text

-- | Symbols for encoding 'Cash32' data in human-readable strings.
charset :: String
charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

-- | Number of five-bit characters in a 'Cash32' checksum.
checkSumLength :: Int
checkSumLength = 8

-- | An ASCII letter of either case.
isAsciiLetter :: Char -> Bool
isAsciiLetter c = isAsciiLower c || isAsciiUpper c

-- | The longest data part of a 'CashAddr', in characters, checksum included.
-- The largest hash is 64 bytes. With the version byte that is 65 bytes, or
-- 520 bits, which take 104 characters of five bits. The checksum adds
-- 'checkSumLength' characters: 104 + 8 = 112.
maxCashAddrDataLength :: Int
maxCashAddrDataLength = 112

-- | The value of each byte as a 'Cash32' character, or 0xff for a byte that
-- is not one. Only lowercase letters and digits are in the table.
base32table :: ByteString
base32table =
  B.pack [maybe 0xff fromIntegral (elemIndex (toEnum i) charset) | i <- [0 .. 255]]

-- | Turn lowercase 'Cash32' characters into their five-bit values. Fails if
-- a byte is not a 'Cash32' character.
base32values :: ByteString -> Maybe ByteString
base32values dat = do
  let values = B.map (B.index base32table . fromIntegral) dat
  guard (B.all (/= 0xff) values)
  return values

-- | A 'CashAddr' string must be all lowercase or all uppercase. A mix of both
-- must be rejected. Only ASCII is allowed, so no character from another
-- alphabet can stand in for a letter.
singleCase :: Text -> Bool
singleCase t = T.all isAscii t && (T.toUpper t == t || T.toLower t == t)

-- | High-Level: decode 'CashAddr' string if it is valid for the
-- provided 'Network'. Prefix may be omitted from the string.
--
-- A string longer than the prefix of the network, the colon and
-- 'maxCashAddrDataLength' characters is refused before any other work. No
-- valid address is longer, since the largest hash the format has is 64 bytes.
cashAddrDecode :: Network -> CashAddr -> Maybe (CashVersion, ByteString)
cashAddrDecode net ca = do
  epfx <- net.cashAddrPrefix
  guard (T.length ca <= T.length epfx + 1 + maxCashAddrDataLength)
  guard (singleCase ca)
  let (cpfx, cdat) = T.breakOnEnd ":" (T.toLower ca)
  guard (T.null cpfx || T.init cpfx == epfx)
  (dpfx, ver, bs) <- cash32decodeType (epfx <> ":" <> cdat)
  guard (dpfx == epfx)
  return (ver, bs)

-- | High-Level: encode 'CashAddr' string for the provided network and hash.
-- Fails if the 'CashVersion' or length of hash 'ByteString' is invalid.
cashAddrEncode :: Network -> CashVersion -> ByteString -> Maybe CashAddr
cashAddrEncode net cv bs = do
  pfx <- net.cashAddrPrefix
  cash32encodeType pfx cv bs

-- | Mid-Level: decode 'CashAddr' string containing arbitrary prefix, plus a
-- version byte before the 'ByteString' that encodes type and length. The
-- string must be the canonical encoding of its payload: padding bits must be
-- zero and there must be fewer than five of them.
cash32decodeType :: Cash32 -> Maybe (CashPrefix, CashVersion, ByteString)
cash32decodeType ca = do
  (dpfx, groups) <- cash32decodeGroups ca
  bs <- toBase256 groups
  (vb, pay) <- B.uncons bs
  (ver, len) <- decodeVersionByte vb
  guard (B.length pay == len)
  return (dpfx, ver, pay)

-- | Mid-Level: encode 'CashAddr' string containing arbitrary prefix and
-- 'CashVersion'. Length must be among those allowed by the standard.
cash32encodeType :: CashPrefix -> CashVersion -> ByteString -> Maybe Cash32
cash32encodeType pfx cv bs = do
  let len = B.length bs
  vb <- encodeVersionByte cv len
  let pl = vb `B.cons` bs
  cash32encode pfx pl

-- | Low-Level: decode 'Cash32' string. 'CashPrefix' must be part of the string.
-- No version or hash length validation is performed. The data may be any
-- sequence of five-bit groups, so bits left over after the last whole byte
-- are dropped. 'cash32decodeType' is the layer that enforces canonical
-- padding.
--
-- The prefix must be one or more letters, and the string has one colon, as
-- in the decoder of Bitcoin Cash Node. There is no limit on the length here,
-- since the data is arbitrary. The time and the memory grow in proportion to
-- the length.
cash32decode :: Cash32 -> Maybe (CashPrefix, ByteString)
cash32decode text = do
  (pfx, groups) <- cash32decodeGroups text
  return (pfx, wholeBytes groups)

-- | Check the checksum of a 'Cash32' string and return its prefix and its
-- data as five-bit groups, one per byte, without the checksum.
cash32decodeGroups :: Cash32 -> Maybe (CashPrefix, ByteString)
cash32decodeGroups text = do
  guard (singleCase text)
  let bs = encodeUtf8 (T.toLower text)
      (pfx', dat) = C.breakEnd (== ':') bs
  pfx <-
    if B.null pfx' || pfx' == C.singleton ':'
      then Nothing
      else Just (B.init pfx')
  -- Letters only: no digit and no second colon. The text is lowercase here.
  guard (C.all isAsciiLower pfx)
  b32 <- base32values dat
  guard (B.length b32 >= checkSumLength)
  let px = B.map (.&. 0x1f) pfx
      pd = px <> B.singleton 0 <> b32
      cs = cash32Polymod pd
  guard (verifyCash32Polymod cs)
  return (decodeUtf8 pfx, B.take (B.length b32 - checkSumLength) b32)

-- | Low-Level: encode 'Cash32' string for 'CashPrefix' provided. Can encode
-- arbitrary data, of any length.
--
-- The prefix must be one or more ASCII letters, which is what 'cash32decode'
-- and Bitcoin Cash Node read back. It is written in lowercase, so that the
-- string is never of mixed case. Any other prefix fails.
cash32encode :: CashPrefix -> ByteString -> Maybe Cash32
cash32encode prefix bs = do
  guard (not (T.null prefix) && T.all isAsciiLetter prefix)
  let pfx = T.toLower prefix
  let b32 = toBase32 bs
      px = B.map (.&. 0x1f) (encodeUtf8 pfx)
      pd = px <> B.singleton 0 <> b32 <> B.replicate checkSumLength 0
      cs = cash32Polymod pd
      c32 = B.map (B.index charsetBytes . fromIntegral) (b32 <> cs)
  return (pfx <> ":" <> decodeLatin1 c32)

-- | 'charset' as bytes, to look up characters in constant time.
charsetBytes :: ByteString
charsetBytes = C.pack charset

-- | Convert base of 'ByteString' from eight bits per byte to five bits per
-- byte, adding padding as necessary.
toBase32 :: ByteString -> ByteString
toBase32 bs = fst $ B.unfoldrN groups group 0
  where
    groups = (B.length bs * 8 + 4) `div` 5
    byte i
      | i < B.length bs = fromIntegral (B.index bs i) :: Word
      | otherwise = 0
    -- the five bits that start this many bits into the input, from the two
    -- bytes that hold them, padded with zeros after the end
    group bit =
      let i = bit `shiftR` 3
          pair = (byte i `shiftL` 8) .|. byte (i + 1)
       in Just (fromIntegral ((pair `shiftR` (11 - (bit .&. 7))) .&. 0x1f), bit + 5)

-- | Convert five-bit groups to the bytes they fill completely, dropping any
-- bits left over at the end.
wholeBytes :: ByteString -> ByteString
wholeBytes groups =
  B.take (5 * B.length groups `div` 8) . B.pack . map fromIntegral . fromMaybe [] $
    convertBits True 5 8 (map fromIntegral (B.unpack groups))

-- | Convert base of 'ByteString' from five to eight bits per byte. Fails if
-- the padding bits are not zero, or if there are enough of them to hold a
-- whole five-bit group, because the input is then not the canonical encoding
-- of its payload.
toBase256 :: ByteString -> Maybe ByteString
toBase256 =
  fmap (B.pack . map fromIntegral)
    . convertBits False 5 8
    . map fromIntegral
    . B.unpack

-- | Obtain 'CashVersion' and payload length from 'CashAddr' version byte.
decodeVersionByte :: Word8 -> Maybe (CashVersion, Int)
decodeVersionByte vb = do
  guard (vb .&. 0x80 == 0)
  return (ver, len)
  where
    ver = vb `shiftR` 3
    len = ls !! fromIntegral (vb .&. 0x07)
    ls = [20, 24, 28, 32, 40, 48, 56, 64]

-- | Encode 'CashVersion' and length into version byte. Fail if version is
-- larger than four bits, or length incorrect, since that is invalid.
encodeVersionByte :: CashVersion -> Int -> Maybe Word8
encodeVersionByte ver len = do
  guard (ver == ver .&. 0x0f)
  l <- case len of
    20 -> Just 0
    24 -> Just 1
    28 -> Just 2
    32 -> Just 3
    40 -> Just 4
    48 -> Just 5
    56 -> Just 6
    64 -> Just 7
    _ -> Nothing
  return ((ver `shiftL` 3) .|. l)

-- | Calculate or validate checksum from base32 'ByteString' (excluding prefix).
cash32Polymod :: ByteString -> ByteString
cash32Polymod v =
  B.pack
    [fromIntegral (polymod `shiftR` (5 * (7 - i))) .&. 0x1f | i <- [0 .. 7 :: Int]]
  where
    polymod = B.foldl' outer (1 :: Word64) v `xor` 1
    outer c d =
      let c0 = c `shiftR` 35
          c' = ((c .&. 0x07ffffffff) `shiftL` 5) `xor` fromIntegral d
       in g 4 0x1e4f43e470 c0
            . g 3 0xae2eabe2a8 c0
            . g 2 0xf33e5fb3c4 c0
            . g 1 0x79b76d99e2 c0
            $ g 0 0x98f2bc8e61 c0 c'
    g :: Int -> Word64 -> Word64 -> Word64 -> Word64
    g b gen c0 c
      | c0 `testBit` b = c `xor` gen
      | otherwise = c

-- | Validate that polymod 'ByteString' (eight bytes) is equal to zero.
verifyCash32Polymod :: ByteString -> Bool
verifyCash32Polymod = (== B.replicate checkSumLength 0)
