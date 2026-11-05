-- |
-- Module      : Haskoin.Test.Keys
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
module Haskoin.Util.Arbitrary.Keys where

import Crypto.Secp256k1
import Data.Bits (clearBit)
import Data.Coerce (coerce)
import Data.List (foldl')
import Data.Word (Word32)
import Haskoin.Crypto.Hash
import Haskoin.Crypto.Keys.Common
import Haskoin.Crypto.Keys.Extended
import Haskoin.Crypto.Keys.Extended.Internal (Fingerprint (..))
import Haskoin.Crypto.Signature
import Haskoin.Util.Arbitrary.Crypto
import Test.QuickCheck

-- | Arbitrary private key with arbitrary compressed flag.
arbitraryPrivateKey :: Gen PrivateKey
arbitraryPrivateKey = wrapSecKey <$> arbitrary <*> arbitrary

-- | Arbitrary public key, either compressed or not.
arbitraryPublicKey :: Ctx -> Gen PublicKey
arbitraryPublicKey ctx = snd <$> arbitraryKeyPair ctx

-- | Arbitrary keypair, both either compressed or not.
arbitraryKeyPair :: Ctx -> Gen (PrivateKey, PublicKey)
arbitraryKeyPair ctx = do
  k <- arbitraryPrivateKey
  return (k, derivePublicKey ctx k)

-- | Arbitrary private key with its public key, both in compressed form: the
-- only form of key that a SegWit version 0 input is signed with
arbitraryKeyPairC :: Ctx -> Gen (PrivateKey, PublicKey)
arbitraryKeyPairC ctx = do
  k <- wrapSecKey True <$> arbitrary
  return (k, derivePublicKey ctx k)

arbitraryFingerprint :: Gen Fingerprint
arbitraryFingerprint = Fingerprint <$> arbitrary

-- | Arbitrary extended private key. A key at depth 0 is a master key, and
-- BIP32 requires it to have a zero parent fingerprint and index.
arbitraryXPrvKey :: Gen XPrvKey
arbitraryXPrvKey = do
  depth <- arbitrary
  parent <- if depth == 0 then pure (Fingerprint 0) else arbitraryFingerprint
  index <- if depth == 0 then pure 0 else arbitrary
  XPrvKey depth parent index <$> arbitraryHash256 <*> arbitrary

-- | Arbitrary extended public key.
arbitraryXPubKey :: Ctx -> Gen XPubKey
arbitraryXPubKey ctx = snd <$> arbitraryXKeyPair ctx

-- | Arbitrary extended public key with its corresponding private key.
arbitraryXKeyPair :: Ctx -> Gen (XPrvKey, XPubKey)
arbitraryXKeyPair ctx = (\k -> (k, deriveXPubKey ctx k)) <$> arbitraryXPrvKey

{- Custom derivations -}

-- | Arbitrary derivation index with last bit unset.
genIndex :: Gen Word32
genIndex = (`clearBit` 31) <$> arbitrary

-- | Arbitrary BIP-32 path index. Can be hardened or not.
arbitraryBip32PathIndex :: Gen Bip32PathIndex
arbitraryBip32PathIndex =
  oneof
    [ Bip32SoftIndex <$> genIndex,
      Bip32HardIndex <$> genIndex
    ]

-- | Arbitrary BIP-32 derivation path composed of only hardened derivations.
arbitraryHardPath :: Gen HardPath
arbitraryHardPath = foldl' (:|) Deriv <$> listOf genIndex

-- | Arbitrary BIP-32 derivation path composed of only non-hardened derivations.
arbitrarySoftPath :: Gen SoftPath
arbitrarySoftPath = foldl' (:/) Deriv <$> listOf genIndex

-- | Arbitrary derivation path composed of hardened and non-hardened derivations.
arbitraryDerivPath :: Gen DerivPath
arbitraryDerivPath = concatBip32Segments <$> listOf arbitraryBip32PathIndex

-- | Arbitrary parsed derivation path. Can contain 'ParsedPrv', 'ParsedPub' or
-- 'ParsedEmpty' elements.
arbitraryParsedPath :: Gen ParsedPath
arbitraryParsedPath =
  oneof
    [ ParsedPrv <$> arbitraryDerivPath,
      ParsedPub <$> arbitraryDerivPath,
      ParsedEmpty <$> arbitraryDerivPath
    ]

-- | Arbitrary message hash, private key, nonce and corresponding signature. The
-- signature is generated with a random message, random private key and a random
-- nonce.
arbitrarySignature :: Ctx -> Gen (Hash256, SecKey, Sig)
arbitrarySignature ctx = do
  m <- arbitraryHash256
  key <- arbitrary
  let sig = signHash ctx key m
  return (m, key, sig)
