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

-- |
-- Module      : Haskoin.Address
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Base58, CashAddr, Bech32 address and WIF private key serialization support.
module Haskoin.Address
  ( -- * Addresses
    Address,
    isPubKeyAddress,
    isScriptAddress,
    isWitnessAddress,
    isWitnessPubKeyAddress,
    isWitnessScriptAddress,
    isScript32Address,
    isCashAddress,
    pubKeyAddress,
    scriptAddress,
    witnessAddress,
    witnessPubKeyAddress,
    witnessScriptAddress,
    script32Address,
    cashAddress,
    addressHash160,
    addressHash256,
    addressVersion,
    addressBytes,
    addrToText,
    textToAddr,
    bech32ToAddr,
    cashToAddr,
    base58ToAddr,
    pubKeyAddr,
    pubKeyWitnessAddr,
    pubKeyCompatWitnessAddr,
    p2pkhAddr,
    p2wpkhAddr,
    p2shAddr,
    p2wshAddr,
    inputAddress,
    outputAddress,
    addressToScript,
    addressToScriptBS,
    addressToOutput,
    payToScriptAddress,
    payToWitnessScriptAddress,
    payToNestedScriptAddress,
    scriptToAddress,
    scriptToAddressBS,
    module Haskoin.Address.Base58,
    module Haskoin.Address.Bech32,
    module Haskoin.Address.CashAddr,
  )
where

import Control.Applicative (Alternative ((<|>)))
import Control.Arrow (second)
import Control.DeepSeq (NFData)
import Control.Monad (guard, (<=<))
import Crypto.Secp256k1
import Data.Aeson (ToJSON (toJSON), Value, withText)
import Data.Aeson.Encoding (Encoding, null_, text)
import Data.Aeson.Types (Encoding, Parser, ToJSON (toJSON), Value, withText)
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get (MonadGet (getByteString, getWord64be, getWord8), isEmpty, runGetS)
import Data.Bytes.Put (MonadPut (putByteString, putWord64be, putWord8), runPutS)
import Data.Bytes.Serial (Serial (..))
import Data.Hashable (Hashable)
import Data.Maybe (isNothing)
import Data.Serialize (Serialize (..))
import Data.Text (Text)
import Data.Text qualified as T
import Data.Word (Word8)
import GHC.Generics (Generic)
import Haskoin.Address.Base58
import Haskoin.Address.Bech32
import Haskoin.Address.CashAddr
import Haskoin.Crypto.Hash
import Haskoin.Crypto.Keys.Common
import Haskoin.Network.Data
import Haskoin.Script.Common
import Haskoin.Script.Standard
import Haskoin.Util

-- | Address format for Bitcoin and Bitcoin Cash.
data Address
  = -- | pay to public key hash (regular)
    PubKeyAddress
      { -- | RIPEMD160 hash of public key's SHA256 hash
        hash160 :: !Hash160
      }
  | -- | pay to script hash (160-bit)
    ScriptAddress
      { -- | RIPEMD160 hash of script's SHA256 hash
        hash160 :: !Hash160
      }
  | -- | pay to witness public key hash
    WitnessPubKeyAddress
      { -- | RIPEMD160 hash of public key's SHA256 hash
        hash160 :: !Hash160
      }
  | -- | pay to witness script hash
    WitnessScriptAddress
      { -- | HASH256 hash of script
        hash256 :: !Hash256
      }
  | -- | other witness address
    WitnessAddress
      { version :: !Word8,
        bytes :: !ByteString
      }
  | -- | pay to script hash (256-bit)
    Script32Address
      { -- | HAS256 hash of script
        hash256 :: !Hash256
      }
  | -- | other CashAddr
    CashAddress
      { version :: !Word8,
        bytes :: !ByteString
      }
  deriving
    (Eq, Ord, Generic, Show, Read, Hashable, NFData)

-- | Binary serialization for 'Address' type is not standard.
-- Do not expect other other software to understand these.
-- Use text format or output scripts for exchange.
instance Serial Address where
  serialize (PubKeyAddress k) = do
    putWord8 0x00
    serialize k
  serialize (ScriptAddress s) = do
    putWord8 0x01
    serialize s
  serialize (WitnessPubKeyAddress h) = do
    putWord8 0x02
    serialize h
  serialize (WitnessScriptAddress s) = do
    putWord8 0x03
    serialize s
  serialize (WitnessAddress v d) = do
    putWord8 0x04
    putWord8 v
    putWord64be (fromIntegral (B.length d))
    putByteString d
  serialize (Script32Address s) = do
    putWord8 0x05
    serialize s
  serialize (CashAddress v d) = do
    putWord8 0x06
    putWord8 v
    putWord64be (fromIntegral (B.length d))
    putByteString d

  deserialize =
    getWord8 >>= \case
      0x00 -> PubKeyAddress <$> deserialize
      0x01 -> ScriptAddress <$> deserialize
      0x02 -> WitnessPubKeyAddress <$> deserialize
      0x03 -> WitnessScriptAddress <$> deserialize
      0x04 ->
        WitnessAddress
          <$> getWord8
          <*> (getByteString . fromIntegral =<< getWord64be)
      0x05 -> Script32Address <$> deserialize
      0x06 -> do
        CashAddress
          <$> getWord8
          <*> (getByteString . fromIntegral =<< getWord64be)
      b ->
        fail . T.unpack $
          "Could not decode address type byte: "
            <> encodeHex (B.singleton b)

instance Serialize Address where
  put = serialize
  get = deserialize

instance Binary Address where
  put = serialize
  get = deserialize

-- | 'Address' pays to a public key hash.
isPubKeyAddress :: Address -> Bool
isPubKeyAddress PubKeyAddress {} = True
isPubKeyAddress _ = False

-- | 'Address' pays to a 160-bit script hash.
isScriptAddress :: Address -> Bool
isScriptAddress ScriptAddress {} = True
isScriptAddress _ = False

-- | 'Address' pays to a witness public key hash. Only valid for SegWit
-- networks.
isWitnessPubKeyAddress :: Address -> Bool
isWitnessPubKeyAddress WitnessPubKeyAddress {} = True
isWitnessPubKeyAddress _ = False

-- | 'Address' pays to witness script hash. SegWit only.
isWitnessScriptAddress :: Address -> Bool
isWitnessScriptAddress WitnessScriptAddress {} = True
isWitnessScriptAddress _ = False

-- | 'Address' is another type of SegWit address, not covered above.
isWitnessAddress :: Address -> Bool
isWitnessAddress WitnessAddress {} = True
isWitnessAddress _ = False

-- | 'Address' pays to a 256-bit script hash.
isScript32Address :: Address -> Bool
isScript32Address Script32Address {} = True
isScript32Address _ = False

-- | 'Address' is another type of CashAddr, not covered above.
isCashAddress :: Address -> Bool
isCashAddress CashAddress {} = True
isCashAddress _ = False

-- | Smart constructor for P2PKH address.
pubKeyAddress :: Hash160 -> Address
pubKeyAddress = PubKeyAddress

-- | Smart constructor for P2SH address.
scriptAddress :: Hash160 -> Address
scriptAddress = ScriptAddress

-- | Smart constructor for P2WPKH address.
witnessPubKeyAddress :: Hash160 -> Address
witnessPubKeyAddress = WitnessPubKeyAddress

-- | Smart constructor for P2WSH address.
witnessScriptAddress :: Hash256 -> Address
witnessScriptAddress = WitnessScriptAddress

-- | Smart constructor for other SegWit address.
witnessAddress :: Word8 -> ByteString -> Maybe Address
witnessAddress v bs = do
  guard $ v <= 16
  guard $ B.length bs >= 2 && B.length bs <= 40
  case v of
    0 -> case B.length bs of
      20 -> do
        h <- eitherToMaybe $ runGetS deserialize bs
        return $ WitnessPubKeyAddress h
      32 -> do
        h <- eitherToMaybe $ runGetS deserialize bs
        return $ WitnessScriptAddress h
      _ -> Nothing
    _ -> return $ WitnessAddress v bs

-- | Smart constructor for P2SH32 address.
script32Address :: Hash256 -> Address
script32Address = Script32Address

-- | Smart constructor for CashAddr.
cashAddress :: Word8 -> ByteString -> Maybe Address
cashAddress v b = do
  guard $ v < 16
  guard $ B.length b `elem` [20, 24, 28, 32, 40, 48, 56, 64]
  case v of
    0 -> case B.length b of
      20 -> do
        h <- eitherToMaybe $ runGetS deserialize b
        return $ pubKeyAddress h
      _ -> return $ CashAddress v b
    1 -> case B.length b of
      20 -> do
        h <- eitherToMaybe $ runGetS deserialize b
        return $ scriptAddress h
      32 -> do
        h <- eitherToMaybe $ runGetS deserialize b
        return $ script32Address h
      _ -> return $ CashAddress v b
    _ -> return $ CashAddress v b

addressHash160 :: Address -> Maybe Hash160
addressHash160 (PubKeyAddress h) = Just h
addressHash160 (ScriptAddress h) = Just h
addressHash160 (WitnessPubKeyAddress h) = Just h
addressHash160 _ = Nothing

addressHash256 :: Address -> Maybe Hash256
addressHash256 (WitnessScriptAddress h) = Just h
addressHash256 (Script32Address h) = Just h
addressHash256 _ = Nothing

addressVersion :: Address -> Word8
addressVersion (PubKeyAddress _) = 0
addressVersion (ScriptAddress _) = 1
addressVersion (WitnessPubKeyAddress _) = 0
addressVersion (WitnessScriptAddress _) = 0
addressVersion (WitnessAddress v _) = v
addressVersion (Script32Address _) = 1
addressVersion (CashAddress v _) = v

addressBytes :: Address -> ByteString
addressBytes (PubKeyAddress h) = runPutS (serialize h)
addressBytes (ScriptAddress h) = runPutS (serialize h)
addressBytes (WitnessPubKeyAddress h) = runPutS (serialize h)
addressBytes (WitnessScriptAddress h) = runPutS (serialize h)
addressBytes (WitnessAddress _ b) = b
addressBytes (Script32Address h) = runPutS (serialize h)
addressBytes (CashAddress _ b) = runPutS (serialize b)

instance MarshalJSON Network Address where
  marshalValue net a = toJSON (addrToText net a)
  marshalEncoding net = maybe null_ text . addrToText net
  unmarshalValue net =
    withText "address" $ \t ->
      case textToAddr net t of
        Nothing -> fail "could not decode address"
        Just x -> return x

-- | Convert address to human-readable string. Uses 'Base58', 'Bech32', or
-- 'CashAddr' depending on network.
addrToText :: Network -> Address -> Maybe Text
addrToText net a@PubKeyAddress {hash160 = h}
  | isNothing net.cashAddrPrefix =
      Just . encodeBase58Check . runPutS $ base58put net a
  | otherwise = cashAddrEncode net 0 (runPutS $ serialize h)
addrToText net a@ScriptAddress {hash160 = h}
  | isNothing net.cashAddrPrefix =
      Just . encodeBase58Check . runPutS $ base58put net a
  | otherwise =
      cashAddrEncode net 1 (runPutS $ serialize h)
addrToText net WitnessPubKeyAddress {hash160 = h} = do
  hrp <- net.bech32Prefix
  segwitEncode hrp 0 (B.unpack (runPutS $ serialize h))
addrToText net WitnessScriptAddress {hash256 = h} = do
  hrp <- net.bech32Prefix
  segwitEncode hrp 0 (B.unpack (runPutS $ serialize h))
addrToText net WitnessAddress {version = v, bytes = d} = do
  hrp <- net.bech32Prefix
  segwitEncode hrp v (B.unpack d)
addrToText net Script32Address {hash256 = h}
  | isNothing net.cashAddrPrefix =
      Nothing
  | otherwise =
      cashAddrEncode net 1 (runPutS $ serialize h)
addrToText net CashAddress {version = v, bytes = h}
  | isNothing net.cashAddrPrefix =
      Nothing
  | otherwise =
      cashAddrEncode net v h

-- | Parse 'Base58', 'Bech32' or 'CashAddr' address, depending on network.
textToAddr :: Network -> Text -> Maybe Address
textToAddr net txt =
  cashToAddr net txt <|> bech32ToAddr net txt <|> base58ToAddr net txt

cashToAddr :: Network -> Text -> Maybe Address
cashToAddr net txt = do
  (ver, bs) <- cashAddrDecode net txt
  case ver of
    0 -> case B.length bs of
      20 -> PubKeyAddress <$> eitherToMaybe (runGetS deserialize bs)
      _ -> return $ CashAddress ver bs
    1 -> case B.length bs of
      20 -> ScriptAddress <$> eitherToMaybe (runGetS deserialize bs)
      32 -> Script32Address <$> eitherToMaybe (runGetS deserialize bs)
      _ -> return $ CashAddress ver bs
    _ -> return $ CashAddress ver bs

bech32ToAddr :: Network -> Text -> Maybe Address
bech32ToAddr net txt = do
  hrp <- net.bech32Prefix
  (ver, bs) <- second B.pack <$> segwitDecode hrp txt
  case ver of
    0 -> case B.length bs of
      20 -> WitnessPubKeyAddress <$> eitherToMaybe (runGetS deserialize bs)
      32 -> WitnessScriptAddress <$> eitherToMaybe (runGetS deserialize bs)
      _ -> Nothing
    _ -> Just $ WitnessAddress ver bs

base58ToAddr :: Network -> Text -> Maybe Address
base58ToAddr net txt =
  eitherToMaybe . runGetS (base58get net) =<< decodeBase58Check txt

base58get :: (MonadGet m) => Network -> m Address
base58get net = do
  pfx <- getWord8
  addr <- deserialize
  isEmpty >>= \case
    True -> f pfx addr
    False -> fail "Address too long"
  where
    f x a
      | x == net.addrPrefix = return $ PubKeyAddress a
      | x == net.scriptPrefix = return $ ScriptAddress a
      | otherwise = fail "Does not recognize address prefix"

base58put :: (MonadPut m) => Network -> Address -> m ()
base58put net (PubKeyAddress h) = do
  putWord8 net.addrPrefix
  serialize h
base58put net (ScriptAddress h) = do
  putWord8 net.scriptPrefix
  serialize h
base58put _ _ = error "Cannot serialize this address as Base58"

-- | Obtain a standard pay-to-public-key-hash address from a public key.
pubKeyAddr :: Ctx -> PublicKey -> Address
pubKeyAddr ctx = PubKeyAddress . addressHash . marshal ctx

-- | Obtain a standard pay-to-public-key-hash (P2PKH) address from a 'Hash160'.
p2pkhAddr :: Hash160 -> Address
p2pkhAddr = PubKeyAddress

-- | Obtain a SegWit pay-to-witness-public-key-hash (P2WPKH) address from a
-- public key.
pubKeyWitnessAddr :: Ctx -> PublicKey -> Address
pubKeyWitnessAddr ctx =
  WitnessPubKeyAddress . addressHash . marshal ctx

-- | Obtain a backwards-compatible SegWit P2SH-P2WPKH address from a public key.
pubKeyCompatWitnessAddr :: Ctx -> PublicKey -> Address
pubKeyCompatWitnessAddr ctx =
  p2shAddr
    . addressHash
    . marshal ctx
    . PayWitnessPKHash
    . addressHash
    . marshal ctx

-- | Obtain a SegWit pay-to-witness-public-key-hash (P2WPKH) address from a
-- 'Hash160'.
p2wpkhAddr :: Hash160 -> Address
p2wpkhAddr = WitnessPubKeyAddress

-- | Obtain a standard pay-to-script-hash (P2SH) address from a 'Hash160'.
p2shAddr :: Hash160 -> Address
p2shAddr = ScriptAddress

-- | Obtain a SegWit pay-to-witness-script-hash (P2WSH) address from a 'Hash256'
p2wshAddr :: Hash256 -> Address
p2wshAddr = WitnessScriptAddress

-- | Compute a standard pay-to-script-hash (P2SH) address for an output script.
payToScriptAddress :: Ctx -> ScriptOutput -> Address
payToScriptAddress ctx = p2shAddr . addressHash . marshal ctx

-- | Compute a SegWit pay-to-witness-script-hash (P2WSH) address for an output
-- script.
payToWitnessScriptAddress :: Ctx -> ScriptOutput -> Address
payToWitnessScriptAddress ctx = p2wshAddr . sha256 . marshal ctx

-- | Compute a backwards-compatible SegWit P2SH-P2WSH address.
payToNestedScriptAddress :: Ctx -> ScriptOutput -> Address
payToNestedScriptAddress ctx =
  p2shAddr . addressHash . marshal ctx . toP2WSH . encodeOutput ctx

-- | Encode an output script from an address. Will fail if using a
-- pay-to-witness address on a non-SegWit network.
addressToOutput :: Address -> Maybe ScriptOutput
addressToOutput =
  \case
    PubKeyAddress h -> Just (PayPKHash h)
    ScriptAddress h -> Just (PayScriptHash h)
    WitnessPubKeyAddress h -> Just (PayWitnessPKHash h)
    WitnessScriptAddress h -> Just (PayWitnessScriptHash h)
    WitnessAddress v d -> Just (PayWitness v d)
    Script32Address h -> Just (PayScript32Hash h)
    CashAddress v a -> Nothing

-- | Get output script AST for an 'Address'.
addressToScript :: Ctx -> Address -> Maybe Script
addressToScript ctx addr = encodeOutput ctx <$> addressToOutput addr

-- | Encode address as output script in 'ByteString' form.
addressToScriptBS :: Ctx -> Address -> Maybe ByteString
addressToScriptBS ctx addr = (runPutS . serialize) <$> addressToScript ctx addr

-- | Decode an output script into an 'Address' if it has such representation.
scriptToAddress :: Ctx -> Script -> Either String Address
scriptToAddress ctx =
  maybeToEither e . outputAddress ctx <=< decodeOutput ctx
  where
    e = "Could not decode address"

-- | Decode a serialized script into an 'Address'.
scriptToAddressBS :: Ctx -> ByteString -> Either String Address
scriptToAddressBS ctx =
  maybeToEither e . outputAddress ctx <=< unmarshal ctx
  where
    e = "Could not decode address"

-- | Get the 'Address' of a 'ScriptOutput'.
outputAddress :: Ctx -> ScriptOutput -> Maybe Address
outputAddress ctx =
  \case
    PayPKHash h -> Just $ PubKeyAddress h
    PayScriptHash h -> Just $ ScriptAddress h
    PayPK k -> Just $ pubKeyAddr ctx k
    PayWitnessPKHash h -> Just $ WitnessPubKeyAddress h
    PayWitnessScriptHash h -> Just $ WitnessScriptAddress h
    PayWitness v d -> Just $ WitnessAddress v d
    PayScript32Hash h -> Just $ Script32Address h
    _ -> Nothing

-- | Infer the 'Address' of a 'ScriptInput'.
inputAddress :: Ctx -> ScriptInput -> Maybe Address
inputAddress ctx =
  \case
    (RegularInput (SpendPKHash _ key)) -> Just $ pubKeyAddr ctx key
    (ScriptHashInput _ rdm) -> Just $ payToScriptAddress ctx rdm
    _ -> Nothing
