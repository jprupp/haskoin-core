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

    -- * Schnorr signatures of Bitcoin Cash
    verifyCashSchnorr,
  )
where

import Control.Monad (unless, when)
import Crypto.Secp256k1
import Data.Aeson
import Data.Aeson.Encoding
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as L
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Maybe (catMaybes, fromMaybe)
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

-- | Verify a Schnorr signature of Bitcoin Cash: 64 bytes, @r@ then @s@,
-- of a public key over a 32-byte digest.
--
-- Bitcoin Cash has had these in @OP_CHECKSIG@ since May 2019, where a
-- signature of 64 bytes and the hash type byte is one, and most of its
-- wallets make them. They are not the Schnorr signatures of BIP 340,
-- which Taproot uses: the key is a full public key and not its x
-- coordinate, the challenge is a plain SHA-256 of @r@, the compressed
-- key and the digest, and @R@ is told from its negation by its y
-- coordinate being a square. libsecp256k1 has no function for them, so
-- this builds the check out of the operations it has on points:
--
-- > e = SHA-256(r || compressed P || m) mod n
-- > R = s*G - e*P
-- > valid when R is not at infinity, x(R) = r, and y(R) is a square mod p
--
-- This is the check of @secp256k1_schnorr_sig_verify@ in Bitcoin Cash
-- Node, and the tests hold it to the test vectors of that code. It only
-- verifies: nothing here is secret, so it is not written to run in
-- constant time.
verifyCashSchnorr :: Ctx -> PubKey -> ByteString -> Hash256 -> Bool
verifyCashSchnorr ctx pub sig h
  | BS.length sig /= 64 = False
  | r >= fieldP || s >= orderN = False
  | otherwise = case combined of
      Nothing -> False
      Just point ->
        let (x, y) = BS.splitAt 32 (BS.drop 1 (exportPubKey ctx False point))
         in bsToInteger x == r && isSquare (bsToInteger y)
  where
    (rBytes, sBytes) = BS.splitAt 32 sig
    r = bsToInteger rBytes
    s = bsToInteger sBytes
    digest = runPutS (serialize h)
    e = bsToInteger (runPutS (serialize (sha256 (rBytes <> exportPubKey ctx True pub <> digest)))) `mod` orderN
    -- s*G, when s is not zero
    sG = derivePubKey ctx <$> secKey (word256 s)
    -- -e*P, when e is not zero
    eP = tweak (word256 ((orderN - e) `mod` orderN)) >>= tweakMulPubKey ctx pub
    -- their sum, which is nothing when it is the point at infinity
    combined = case catMaybes [sG, eP] of
      [] -> Nothing
      points -> combinePubKeys ctx points
    -- Euler's criterion
    isSquare y = powMod y ((fieldP - 1) `div` 2) fieldP == 1
    word256 n = let b = integerToBS n in BS.replicate (32 - BS.length b) 0 <> b
    fieldP = 2 ^ (256 :: Int) - 2 ^ (32 :: Int) - 977 :: Integer
    orderN = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 :: Integer
    powMod _ 0 _ = 1
    powMod b k m
      | even k = let half = powMod b (k `div` 2) m in half * half `mod` m
      | otherwise = b * powMod b (k - 1) m `mod` m
