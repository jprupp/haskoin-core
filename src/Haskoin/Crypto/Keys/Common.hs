{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- |
-- Module      : Haskoin.Keys.Common
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- ECDSA private and public key functions.
module Haskoin.Crypto.Keys.Common
  ( -- * Bitcoin Public & Private Keys
    PublicKey (..),
    PrivateKey (..),
    wrapPubKey,
    decodePubKey,
    derivePublicKey,
    wrapSecKey,
    decodeSecKey,
    fromMiniKey,
    tweakPubKey,
    tweakSecKey,

    -- ** Private Key Wallet Import Format (WIF)
    fromWif,
    toWif,
  )
where

import Control.DeepSeq
import Control.Monad (guard, mzero, unless, (<=<))
import Crypto.Secp256k1
import Data.Aeson
  ( Encoding,
    FromJSON,
    ToJSON (..),
    Value (String),
    object,
    parseJSON,
    withText,
  )
import Data.Aeson.Encoding (text, unsafeToEncoding)
import Data.Aeson.Types (Parser)
import Data.Binary (Binary (..))
import Data.Bool (bool)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Builder (char7)
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Hashable
import Data.Maybe (fromMaybe)
import Data.Serialize (Serialize (..))
import Data.String (IsString, fromString)
import Data.String.Conversions (cs)
import Data.Text qualified as T
import GHC.Generics (Generic)
import Haskoin.Address.Base58
import Haskoin.Crypto.Hash
import Haskoin.Network.Data
import Haskoin.Util

-- | Elliptic curve public key type with expected serialized compression flag.
data PublicKey = PublicKey
  { point :: !PubKey,
    compress :: !Bool
  }
  deriving (Generic, Show, Read, Hashable, Eq, NFData)

instance MarshalJSON Ctx PublicKey where
  marshalValue ctx = String . encodeHex . runPutS . marshalPut ctx

  marshalEncoding ctx = hexEncoding . runPutL . marshalPut ctx

  unmarshalValue ctx =
    withText "PublicKey" $ \t -> do
      bs <- maybe (fail "Expected hex public key") return $ decodeHex t
      either fail return $ decodePubKey ctx bs

instance Marshal Ctx PublicKey where
  marshalGet ctx = do
    c <-
      lookAhead $
        getWord8 >>= \case
          0x02 -> return True
          0x03 -> return True
          0x04 -> return False
          _ -> fail "Not a public key"
    bs <- getByteString $ if c then 33 else 65
    case importPubKey ctx bs of
      Nothing -> fail "Could not decode public key"
      Just k -> return $ PublicKey k c

  marshalPut ctx pk =
    putByteString $ exportPubKey ctx pk.compress pk.point

-- | Wrap a public key from secp256k1 library adding information about compression.
wrapPubKey :: Bool -> PubKey -> PublicKey
wrapPubKey c p = PublicKey p c

-- | Decode a public key from bytes that must hold the key and nothing else:
-- 33 bytes starting with 0x02 or 0x03, or 65 bytes starting with 0x04. The
-- 'Marshal' instance reads a key from a longer stream and leaves the rest, so
-- it would accept trailing bytes here. A key pushed in a script, a witness or
-- a PSBT record is the whole item, so use this function for those.
decodePubKey :: Ctx -> ByteString -> Either String PublicKey
decodePubKey ctx = runGetS $ do
  k <- marshalGet ctx
  done <- isEmpty
  unless done $ fail "Trailing bytes after public key"
  return k

-- | Derives a public key from a private key. This function will preserve
-- compression flag.
derivePublicKey :: Ctx -> PrivateKey -> PublicKey
derivePublicKey ctx (PrivateKey d c) = PublicKey (derivePubKey ctx d) c

-- | Tweak a public key.
tweakPubKey :: Ctx -> PubKey -> Hash256 -> Maybe PubKey
tweakPubKey ctx p =
  tweakAddPubKey ctx p <=< tweak . runPutS . serialize

-- | Elliptic curve private key type with expected public key compression
-- information. Compression information is stored in private key WIF formats and
-- needs to be preserved to generate the correct address from the corresponding
-- public key.
data PrivateKey = PrivateKey
  { key :: !SecKey,
    compress :: !Bool
  }
  deriving (Eq, Show, Read, Generic, NFData)

instance Serial PrivateKey where
  serialize p = do
    putByteString p.key.get
    serialize p.compress
  deserialize = do
    bs <- getByteString 32
    c <- deserialize
    case decodeSecKey bs of
      Nothing -> fail "Secret key is zero or not below the curve order"
      Just k -> return PrivateKey {key = k, compress = c}

instance MarshalJSON Network PrivateKey where
  marshalValue net = String . toWif net
  marshalEncoding net = text . toWif net
  unmarshalValue net =
    withText "PrivateKey" $
      maybe (fail "Could not decode WIF") return . fromWif net

-- | Wrap private key with corresponding public key compression flag.
wrapSecKey :: Bool -> SecKey -> PrivateKey
wrapSecKey c d = PrivateKey d c

-- | Order of the secp256k1 group. A secret key is a number in @[1, n-1]@.
curveOrder :: Integer
curveOrder = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

-- | Build a secret key from its 32 big-endian bytes. Fails when the value is
-- zero or not below the curve order. 'Crypto.Secp256k1.secKey' only checks the
-- length, and such a key would make 'derivePubKey' and 'signMsg' crash.
decodeSecKey :: ByteString -> Maybe SecKey
decodeSecKey bs = do
  guard (BS.length bs == 32)
  let n = bsToInteger bs
  guard (n >= 1 && n < curveOrder)
  secKey bs

-- | Tweak a private key.
tweakSecKey :: Ctx -> SecKey -> Hash256 -> Maybe SecKey
tweakSecKey ctx k =
  tweakAddSecKey ctx k <=< tweak . runPutS . serialize

-- | Decode Casascius mini private keys (22 or 30 characters).
fromMiniKey :: ByteString -> Maybe PrivateKey
fromMiniKey bs = do
  guard checkShortKey
  wrapSecKey False <$> (decodeSecKey . runPutS . serialize . sha256) bs
  where
    checkHash = runPutS $ serialize $ sha256 $ bs `BS.append` "?"
    checkShortKey = BS.length bs `elem` [22, 30] && BS.head checkHash == 0x00

-- | Longest Base58 string a WIF can take. A WIF holds at most 38 bytes with
-- its checksum, which never need more than 52 digits because 58^52 is larger
-- than 256^38. Longer strings are rejected before decoding, since the time to
-- decode Base58 grows with the square of the length.
maxWifLength :: Int
maxWifLength = 52

-- | Decode private key from WIF (wallet import format) string. Fails on a
-- string of another network, of the wrong length, or holding a key that is
-- zero or not below the curve order.
fromWif :: Network -> Base58 -> Maybe PrivateKey
fromWif net wif = do
  guard (T.length wif <= maxWifLength)
  bs <- decodeBase58Check wif
  (prefix, rest) <- BS.uncons bs
  -- Check that this is a private key
  guard (prefix == net.secretPrefix)
  case BS.length rest of
    -- Uncompressed format
    32 -> wrapSecKey False <$> decodeSecKey rest
    -- Compressed format: the key is followed by a 0x01 flag byte
    33 -> do
      guard $ BS.last rest == 0x01
      wrapSecKey True <$> decodeSecKey (BS.init rest)
    -- Bad length
    _ -> Nothing

-- | Encode private key into a WIF string.
toWif :: Network -> PrivateKey -> Base58
toWif net (PrivateKey k c) =
  encodeBase58Check . BS.cons net.secretPrefix $
    if c then k.get `BS.snoc` 0x01 else k.get
