{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Haskoin.Crypto.Signature
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- ECDSA signatures using secp256k1 curve. Uses functions from upstream secp256k1
-- library.
module Haskoin.Crypto.Signature
  ( -- * Signatures
    signHash,
    hashToMsg,
    verifyHashSig,
    isCanonicalHalfOrder,
    decodeStrictSig,
    exportSig,
  )
where

import Control.Monad (guard, unless, when)
import Crypto.Secp256k1
import Data.Aeson
import Data.Aeson.Encoding
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as L
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Maybe (fromMaybe)
import Data.Serialize (Serialize (..))
import Data.Text qualified as T
import Haskoin.Crypto.Hash
import Haskoin.Util.Helpers
import Haskoin.Util.Marshal
import Numeric (showHex)

-- | Convert 256-bit hash into a 'Msg' for signing or verification.
hashToMsg :: Hash256 -> Msg
hashToMsg =
  fromMaybe e . msg . runPutS . serialize
  where
    e = error "Could not convert 32-byte hash to secp256k1 message"

-- | Sign a 256-bit hash using secp256k1 elliptic curve.
signHash :: Ctx -> SecKey -> Hash256 -> Sig
signHash ctx k = signMsg ctx k . hashToMsg

-- | Verify an ECDSA signature for a 256-bit hash.
verifyHashSig :: Ctx -> Hash256 -> Sig -> PubKey -> Bool
verifyHashSig ctx h s p = verifySig ctx p (normalizeSig ctx s) (hashToMsg h)

instance Marshal Ctx Sig where
  marshalGet ctx = do
    l <- lookAhead $ do
      t <- getWord8
      -- 0x30 is DER sequence type
      unless (t == 0x30) $
        fail $
          "Bad DER identifier byte 0x" ++ showHex t ". Expecting 0x30"
      l <- getWord8
      when (l == 0x00) $ fail "Indeterminate form unsupported"
      when (l >= 0x80) $ fail "Multi-octect length not supported"
      return $ fromIntegral l
    bs <- getByteString $ l + 2
    case decodeStrictSig ctx bs of
      Just s -> return s
      Nothing -> fail "Invalid signature"

  marshalPut ctx s = putByteString $ exportSig ctx s

instance MarshalJSON Ctx Sig where
  marshalValue ctx = String . encodeHex . exportSig ctx
  marshalEncoding ctx = hexEncoding . L.fromStrict . exportSig ctx
  -- Decoding is as strict as the binary form: low-S and non-zero components.
  unmarshalValue ctx =
    withText "Sig" $ \t ->
      case decodeHex t >>= decodeStrictSig ctx of
        Nothing -> fail $ "Could not decode signature: " <> T.unpack t
        Just s -> return s

-- | Is canonical half order: the s component is not above half the curve
-- order, the only form 'verifySig' accepts.
isCanonicalHalfOrder :: Ctx -> Sig -> Bool
isCanonicalHalfOrder = isLowS

-- | Decode signature strictly.
decodeStrictSig :: Ctx -> ByteString -> Maybe Sig
decodeStrictSig ctx bs = do
  g <- importSig ctx bs
  -- <http://www.secg.org/sec1-v2.pdf Section 4.1.4>
  -- 4.1.4.1 (r and s can not be zero)
  let compact = exportCompactSig ctx g
  let zero = B.replicate 32 0
  guard $ B.take 32 compact.get /= zero
  guard $ (B.take 32 . B.drop 32) compact.get /= zero
  guard $ isCanonicalHalfOrder ctx g
  return g
