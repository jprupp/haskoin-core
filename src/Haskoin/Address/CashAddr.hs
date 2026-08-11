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
import Data.Char (ord, toLower, toUpper)
import Data.List (elemIndex, foldl')
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Word (Word64, Word8)
import Haskoin.Network.Data (Network (cashAddrPrefix))
import Haskoin.Util.Helpers (convertBits)

-- | 'CashAddr' prefix, usually shown before the colon in addresses, but sometimes
-- omitted. It is used in the checksum calculation to avoid parsing an address
-- from the wrong network.
type CashPrefix = Text

-- | 'CashAddr' version, until new address schemes appear it will be zero.
type CashVersion = Word8

-- | High level 'CashAddr' human-reabale string, with explicit or implicit prefix.
type CashAddr = Text

-- | Low level 'Cash32' is the human-readable low-level encoding used by 'CashAddr'.
-- It need not encode a valid address but any binary data.
type Cash32 = Text

-- | Symbols for encoding 'Cash32' data in human-readable strings.
charset :: String
charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

-- | Get the 32-bit number associated with this 'Cash32' character.
base32char :: Char -> Maybe Word8
base32char = fmap fromIntegral . (`elemIndex` charset)

-- | High-Level: decode 'CashAddr' string if it is valid for the
-- provided 'Network'. Prefix may be omitted from the string.
cashAddrDecode :: Network -> CashAddr -> Maybe (CashVersion, ByteString)
cashAddrDecode net ca = do
  epfx <- net.cashAddrPrefix
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
-- version byte before the 'ByteString' that encodes type and length.
cash32decodeType :: Cash32 -> Maybe (CashPrefix, CashVersion, ByteString)
cash32decodeType ca' = do
  guard (T.toUpper ca' == ca' || ca == ca')
  (dpfx, bs) <- cash32decode ca
  guard (not (B.null bs))
  let vb = B.head bs
      pay = B.tail bs
  (ver, len) <- decodeVersionByte vb
  guard (B.length pay == len)
  return (dpfx, ver, pay)
  where
    ca = T.toLower ca'

-- | Mid-Level: encode 'CashAddr' string containing arbitrary prefix and
-- 'CashVersion'. Length must be among those allowed by the standard.
cash32encodeType :: CashPrefix -> CashVersion -> ByteString -> Maybe Cash32
cash32encodeType pfx cv bs = do
  let len = B.length bs
  vb <- encodeVersionByte cv len
  let pl = vb `B.cons` bs
  return (cash32encode pfx pl)

-- | Low-Level: decode 'Cash32' string. 'CashPrefix' must be part of the string.
-- No version or hash length validation is performed.
cash32decode :: Cash32 -> Maybe (CashPrefix, ByteString)
cash32decode text = do
  let bs = C.map toLower bs'
  guard (C.map toUpper bs' == bs' || bs == bs')
  let (pfx', dat) = C.breakEnd (== ':') bs
  pfx <-
    if B.null pfx' || pfx' == C.singleton ':'
      then Nothing
      else Just (B.init pfx')
  b32 <- B.pack <$> mapM base32char (C.unpack dat)
  let px = B.map (.&. 0x1f) pfx
      pd = px <> B.singleton 0 <> b32
      cs = cash32Polymod pd
      bb = B.take (B.length b32 - 8) b32
  guard (verifyCash32Polymod cs)
  let out = toBase256 bb
  return (decodeUtf8 pfx, out)
  where
    bs' = encodeUtf8 text

-- | Low-Level: encode 'Cash32' string for 'CashPrefix' provided. Can encode
-- arbitrary data. No prefix or length validation is performed.
cash32encode :: CashPrefix -> ByteString -> Cash32
cash32encode pfx bs =
  let b32 = toBase32 bs
      px = B.map (.&. 0x1f) (encodeUtf8 pfx)
      pd = px <> B.singleton 0 <> b32 <> B.replicate 8 0
      cs = cash32Polymod pd
      c32 = B.map f (b32 <> cs)
      f = fromIntegral . ord . (charset !!) . fromIntegral
   in pfx <> ":" <> decodeUtf8 c32

-- | Convert base of 'ByteString' from eight bits per byte to five bits per
-- byte, adding padding as necessary.
toBase32 :: ByteString -> ByteString
toBase32 =
  B.pack
    . map fromIntegral
    . fst
    . convertBits True 8 5
    . map fromIntegral
    . B.unpack

-- | Convert base of 'ByteString' from five to eight bits per byte. Ignore
-- padding to be symmetric with respect to 'toBase32' function.
toBase256 :: ByteString -> ByteString
toBase256 =
  B.pack
    . map fromIntegral
    . fst
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
-- larger than five bits, or length incorrect, since that is invalid.
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
    [fromIntegral (polymod `shiftR` (5 * (7 - i))) .&. 0x1f | i <- [0 .. 7]]
  where
    polymod = B.foldl' outer (1 :: Word64) v `xor` 1
    outer c d =
      let c0 = (fromIntegral (c `shiftR` 35) :: Word8)
          c' = ((c .&. 0x07ffffffff) `shiftL` 5) `xor` fromIntegral d
       in foldl' (inner c0) c' (zip [0 ..] generator)
    generator =
      [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]
    inner c0 c (b, g)
      | c0 `testBit` b = c `xor` g
      | otherwise = c

-- | Validate that polymod 'ByteString' (eight bytes) is equal to zero.
verifyCash32Polymod :: ByteString -> Bool
verifyCash32Polymod = (== B.replicate 8 0)
