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

import Control.Monad (unless, when)
import Crypto.Secp256k1
import Data.Aeson
import Data.Aeson.Encoding
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.ByteString.Lazy qualified as L
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Maybe (fromMaybe)
import Data.Serialize (Serialize (..))
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
  -- Decoding applies the same rules as the binary form, 'decodeStrictSig'.
  -- The error message does not repeat the text. The text comes from outside
  -- and can be of any length.
  unmarshalValue ctx =
    withText "Sig" $ \t ->
      case decodeHex t >>= decodeStrictSig ctx of
        Nothing -> fail "Could not decode signature"
        Just s -> return s

-- | Is the s component at most half the curve order? This is the low-S rule
-- that Bitcoin Core applies to the transactions it relays:
-- @SCRIPT_VERIFY_LOW_S@ is one of its standard flags. It is not a consensus
-- rule, so a block may hold a signature with a high s. The decoders of this
-- module do not apply it. Check it with this function where the relay rules
-- matter. 'signHash' always makes a signature that passes.
isCanonicalHalfOrder :: Ctx -> Sig -> Bool
isCanonicalHalfOrder = isLowS

-- | Decode a signature from its strict DER encoding, the encoding that BIP 66
-- made a consensus rule (@IsValidSignatureEncoding@ in Bitcoin Core, without
-- the hash type byte).
--
-- A signature whose r or s is zero, or not below the curve order, is refused
-- as well. BIP 66 allows such an encoding, but the signature can never
-- verify. 'importSig' applies both rules.
--
-- A high s is accepted, since BIP 66 allows it and such signatures are in the
-- block chain. Use 'isCanonicalHalfOrder' for the low-S relay rule.
decodeStrictSig :: Ctx -> ByteString -> Maybe Sig
decodeStrictSig = importSig
