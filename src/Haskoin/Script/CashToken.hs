{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Script.CashToken
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Tokens of Bitcoin Cash (CashTokens, CHIP-2022-02), as an output carries
-- them.
--
-- Since May 2023 an output of Bitcoin Cash may hold tokens. They have no
-- field of their own in the transaction: they are written at the front of
-- the script field of the output, before the script that locks the coin.
-- That is the token prefix:
--
-- @
-- 0xef | category (32 bytes) | flags (1 byte)
--      | [commitment length and commitment, if flag 0x40]
--      | [fungible amount, if flag 0x10]
--      | locking script
-- @
--
-- The lengths and the amount are compact sizes, in their shortest form only.
-- Of the flags, 0x80 is reserved and must be zero, 0x40 says there is a
-- commitment, 0x20 that there is a non-fungible token, 0x10 that there is a
-- fungible amount. The low four bits are the capability of the non-fungible
-- token: 0 none, 1 mutable, 2 minting.
--
-- Software that does not know about the prefix sees a script that starts
-- with an undefined opcode and matches no template, so a coin with tokens
-- seems to have no address. 'splitTokenData' takes the prefix off and reads
-- it, so that the rest can be decoded as any other script.
-- 'Haskoin.Address.scriptToAddressBS' does that on the Bitcoin Cash
-- networks.
--
-- The byte 0xef is only a prefix on Bitcoin Cash. On Bitcoin it is an
-- undefined opcode like any other, and nothing in this module should be
-- applied to a script of that chain.
--
-- t'TokenData' is the decoded prefix, in a form that cannot be written in two
-- ways: an empty commitment and an amount of zero are what an absent
-- commitment and an absent amount mean, because the prefix may not encode a
-- commitment of length zero nor an amount of zero. So 'encodeTokenPrefix'
-- and 'splitTokenData' are inverses, and two equal values have the same
-- bytes.
--
-- What is not checked here: the rules that depend on the transaction, such
-- as the category being the id of an input being spent, or the amounts of
-- the inputs and the outputs adding up, and the limit on the length of a
-- commitment. That limit is a rule of transaction validation, not of the
-- prefix, and it has changed between network upgrades, so a commitment of
-- any length parses.
module Haskoin.Script.CashToken
  ( -- * Tokens
    TokenData (..),
    NFToken (..),
    TokenCapability (..),
    validTokenData,
    maxTokenAmount,

    -- * Token prefix
    tokenPrefixByte,
    hasTokenPrefix,
    splitTokenData,
    encodeTokenPrefix,
  )
where

import Control.DeepSeq (NFData)
import Control.Monad (unless, when)
import Data.Aeson
  ( FromJSON (parseJSON),
    ToJSON (toEncoding, toJSON),
    Value (Number, String),
    object,
    pairs,
    withObject,
    withText,
    (.:),
    (.:?),
    (.=),
  )
import Data.Aeson.Types (Parser)
import Data.Binary (Binary (..))
import Data.Bits ((.&.), (.|.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get (MonadGet (getByteString, getWord8, remaining))
import Data.Bytes.Put (MonadPut (putByteString, putWord8), runPutS)
import Data.Bytes.Serial (Serial (..))
import Data.Hashable (Hashable)
import Data.Maybe (isJust)
import Data.Scientific (floatingOrInteger)
import Data.Serialize (Serialize (..))
import Data.Serialize qualified as S
import Data.Text qualified as T
import Data.Word (Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Network.Common (VarInt (VarInt), putVarInt)
import Haskoin.Transaction.Common (TxHash, txHashToHex)
import Haskoin.Util.Helpers (decodeHex, encodeHex)
import Text.Read (readMaybe)

-- | What a non-fungible token allows its holder to do, besides spending it.
data TokenCapability
  = -- | An immutable token: its commitment can never change.
    NoCapability
  | -- | The holder can replace the commitment, in one new token.
    MutableCapability
  | -- | The holder can create any number of new tokens of the category.
    MintingCapability
  deriving (Eq, Ord, Show, Read, Enum, Bounded, Generic, Hashable, NFData)

-- | The non-fungible token of an output. An output holds at most one.
data NFToken = NFToken
  { capability :: !TokenCapability,
    -- | Data the token commits to. Empty when there is none.
    commitment :: !ByteString
  }
  deriving (Eq, Ord, Show, Read, Generic, Hashable, NFData)

-- | The tokens that one output holds: all of one category, a fungible
-- amount, a non-fungible token, or both.
--
-- A value is only valid with at least one token and an amount no larger than
-- 'maxTokenAmount'. The type does not enforce it, so that a record can be
-- built and taken apart freely. 'validTokenData' checks it, and the JSON
-- parser, 'splitTokenData' and 'encodeTokenPrefix' only accept or give
-- valid values.
data TokenData = TokenData
  { -- | The category, the id of the transaction whose first input created
    -- it. It is shown in reverse byte order, as a transaction id.
    category :: !TxHash,
    -- | Fungible tokens. Zero when there are none.
    amount :: !Word64,
    -- | Non-fungible token, if any.
    nft :: !(Maybe NFToken)
  }
  deriving (Eq, Ord, Show, Read, Generic, Hashable, NFData)

-- | The largest fungible amount an output can hold, the largest signed
-- 64-bit integer. It is also the largest supply a category can have.
maxTokenAmount :: Word64
maxTokenAmount = 0x7fffffffffffffff

-- | A t'TokenData' holds at least one token, and no more than
-- 'maxTokenAmount' fungible ones.
validTokenData :: TokenData -> Bool
validTokenData t =
  t.amount <= maxTokenAmount && (t.amount > 0 || isJust t.nft)

-- | The first byte of the script field of an output that holds tokens,
-- @PREFIX_TOKEN@ in the specification.
tokenPrefixByte :: Word8
tokenPrefixByte = 0xef

-- | The script field starts with 'tokenPrefixByte'. It says nothing about
-- the rest being a valid prefix: 'splitTokenData' does.
hasTokenPrefix :: ByteString -> Bool
hasTokenPrefix bytes = case B.uncons bytes of
  Just (b, _) -> b == tokenPrefixByte
  Nothing -> False

-- | Split the script field of an output of Bitcoin Cash into the tokens it
-- holds and the locking script after them. A field that does not start with
-- 'tokenPrefixByte' holds no tokens and is all locking script. A field that
-- starts with it and has no valid prefix after it is an error: consensus
-- does not let such an output into the chain.
--
-- The locking script is returned as bytes, not parsed, since it may be any
-- bytes at all, and so it can go to
-- 'Haskoin.Address.scriptToAddressBS' or 'Haskoin.Util.decodeSerial'.
splitTokenData :: ByteString -> Either String (Maybe TokenData, ByteString)
splitTokenData bytes
  | hasTokenPrefix bytes = do
      (t, rest) <- S.runGetState deserialize bytes 0
      return (Just t, rest)
  | otherwise = Right (Nothing, bytes)

-- | The token prefix of an output that holds these tokens, 'tokenPrefixByte'
-- included. Put the locking script after it to get the script field of the
-- output. 'Nothing' for a value that 'validTokenData' refuses, since it has
-- no valid prefix.
encodeTokenPrefix :: TokenData -> Maybe ByteString
encodeTokenPrefix t
  | validTokenData t = Just (runPutS (serialize t))
  | otherwise = Nothing

-- | Flag bits of the prefix.
reservedBit, commitmentBit, nftBit, amountBit :: Word8
reservedBit = 0x80
commitmentBit = 0x40
nftBit = 0x20
amountBit = 0x10

-- | The binary form is the token prefix, 'tokenPrefixByte' included, as it
-- is on the wire. Writing a value that 'validTokenData' refuses gives bytes
-- that do not read back: use 'encodeTokenPrefix' to be told.
instance Serial TokenData where
  serialize t = do
    putWord8 tokenPrefixByte
    serialize t.category
    putWord8 flags
    unless (B.null commitment) $ do
      putVarInt (B.length commitment)
      putByteString commitment
    when (t.amount > 0) $ putVarInt t.amount
    where
      commitment = maybe B.empty (.commitment) t.nft
      flags =
        bit (not (B.null commitment)) commitmentBit
          .|. bit (isJust t.nft) nftBit
          .|. bit (t.amount > 0) amountBit
          .|. maybe 0 (fromIntegral . fromEnum . (.capability)) t.nft
      bit c b = if c then b else 0

  deserialize = do
    b <- getWord8
    unless (b == tokenPrefixByte) $ invalid "does not start with 0xef"
    category <- deserialize
    flags <- getWord8
    let hasCommitment = flags .&. commitmentBit /= 0
        hasNft = flags .&. nftBit /= 0
        hasAmount = flags .&. amountBit /= 0
        cap = flags .&. 0x0f
    when (flags .&. reservedBit /= 0) $ invalid "reserved bit is set"
    unless (hasNft || hasAmount) $ invalid "must encode at least one token"
    when (cap > 2) $ invalid "capability must be none, mutable or minting"
    when (not hasNft && cap /= 0) $ invalid "capability requires an NFT"
    when (not hasNft && hasCommitment) $ invalid "commitment requires an NFT"
    commitment <-
      if hasCommitment
        then do
          VarInt n <- deserialize
          when (n == 0) $ invalid "commitment length must be greater than 0"
          left <- remaining
          when (n > fromIntegral left) $ invalid "commitment is too short"
          getByteString (fromIntegral n)
        else return B.empty
    amount <-
      if hasAmount
        then do
          VarInt n <- deserialize
          when (n == 0) $ invalid "amount must be greater than 0"
          when (n > maxTokenAmount) $ invalid "amount is too large"
          return n
        else return 0
    let nft
          | hasNft = Just NFToken {capability = toEnum (fromIntegral cap), commitment}
          | otherwise = Nothing
    return TokenData {category, amount, nft}
    where
      invalid msg = fail ("Invalid token prefix: " <> msg)

instance Serialize TokenData where
  put = serialize
  get = deserialize

instance Binary TokenData where
  put = serialize
  get = deserialize

-- | The names of the CashTokens specification and of the RPC of Bitcoin Cash
-- Node: @none@, @mutable@, @minting@.
instance ToJSON TokenCapability where
  toJSON = String . capabilityName

instance FromJSON TokenCapability where
  parseJSON = withText "capability" $ \case
    "none" -> return NoCapability
    "mutable" -> return MutableCapability
    "minting" -> return MintingCapability
    t -> fail ("Unknown token capability: " <> T.unpack t)

capabilityName :: TokenCapability -> T.Text
capabilityName = \case
  NoCapability -> "none"
  MutableCapability -> "mutable"
  MintingCapability -> "minting"

-- | @{"capability": "none", "commitment": "<hex>"}@.
instance ToJSON NFToken where
  toJSON n =
    object ["capability" .= n.capability, "commitment" .= encodeHex n.commitment]
  toEncoding n =
    pairs ("capability" .= n.capability <> "commitment" .= encodeHex n.commitment)

instance FromJSON NFToken where
  parseJSON = withObject "nft" $ \o -> do
    capability <- o .: "capability"
    hex <- o .: "commitment"
    commitment <- maybe (fail "Commitment is not hex") return (decodeHex hex)
    return NFToken {capability, commitment}

-- | The form of the CashTokens test vectors and of the RPC of Bitcoin Cash
-- Node:
--
-- @
-- {"category": "<txid>", "amount": "1000", "nft": {...}}
-- @
--
-- The amount is a string, since it may be larger than a JavaScript number
-- can hold exactly. The parser also takes a number. @nft@ is absent when
-- there is no non-fungible token. The parser refuses a value that
-- 'validTokenData' refuses.
instance ToJSON TokenData where
  toJSON t =
    object $
      [ "category" .= txHashToHex t.category,
        "amount" .= show t.amount
      ]
        <> maybe [] (\n -> ["nft" .= n]) t.nft
  toEncoding t =
    pairs $
      "category" .= txHashToHex t.category
        <> "amount" .= show t.amount
        <> maybe mempty ("nft" .=) t.nft

instance FromJSON TokenData where
  parseJSON = withObject "token data" $ \o -> do
    category <- o .: "category"
    amount <- parseAmount =<< o .: "amount"
    nft <- o .:? "nft"
    let t = TokenData {category, amount, nft}
    unless (validTokenData t) $ fail "Invalid token data"
    return t
    where
      parseAmount :: Value -> Parser Word64
      parseAmount = \case
        String s | Just n <- readMaybe (T.unpack s) -> integral n
        Number n | Right i <- (floatingOrInteger n :: Either Double Integer) -> integral i
        _ -> fail "Token amount is not an integer"
      integral :: Integer -> Parser Word64
      integral n
        | n < 0 || n > fromIntegral maxTokenAmount = fail "Token amount out of range"
        | otherwise = return (fromIntegral n)
