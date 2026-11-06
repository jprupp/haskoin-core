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
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Address
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Base58, CashAddr and Bech32 address serialization support.
module Haskoin.Address
  ( -- * Addresses
    Address
      ( PubKeyAddress,
        ScriptAddress,
        WitnessPubKeyAddress,
        WitnessScriptAddress,
        WitnessAddress,
        Script32Address,
        CashAddress
      ),
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
    addrToBase58,
    addrToBech32,
    addrToCash,
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
    p2shP2wpkhAddr,
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
import Control.DeepSeq (NFData)
import Control.Monad (guard, mfilter, when, (<=<))
import Crypto.Secp256k1
import Data.Aeson (ToJSON (toJSON), withText)
import Data.Aeson.Encoding (text)
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get (MonadGet (getByteString, getWord64be, getWord8), isEmpty, runGetS)
import Data.Bytes.Put (MonadPut (putByteString, putWord64be, putWord8), runPutS)
import Data.Bytes.Serial (Serial (..))
import Data.Hashable (Hashable)
import Data.Maybe (fromMaybe, isJust)
import Data.Serialize (Serialize (..))
import Data.Text (Text)
import Data.Text qualified as T
import Data.Word (Word8)
import GHC.Generics (Generic)
import GHC.Read (expectP)
import Haskoin.Address.Base58
import Haskoin.Address.Bech32
import Haskoin.Address.CashAddr
import Haskoin.Crypto.Hash
import Haskoin.Crypto.Keys.Common
import Haskoin.Network.Data
import Haskoin.Script.Common
import Haskoin.Script.Standard
import Haskoin.Util
import Text.Read
  ( Lexeme (Ident, Punc),
    Read (readListPrec, readPrec),
    ReadPrec,
    lexP,
    parens,
    pfail,
    prec,
    readListPrecDefault,
    reset,
  )

-- | Address format for Bitcoin and Bitcoin Cash.
--
-- The 'WitnessAddress' and 'CashAddress' patterns can only be used to match.
-- Build those addresses with 'witnessAddress' and 'cashAddress', which check
-- the version and the payload length, and which return the dedicated
-- constructor when one exists. This keeps every address with a single
-- representation, so two addresses with the same text are always equal.
--
-- Two different addresses can still pay the same script. A token-aware
-- CashAddr (type 2 or 3) locks coins with the script of its plain form (type
-- 0 or 1), and the two are not equal. To find what an address was paid, look
-- it up by the script of 'addressToOutput', not by the address.
--
-- A value does not know its network. 'textToAddr' and the JSON parser only
-- return addresses of the network they are given. The constructors, 'Read'
-- and the binary form do not check that, so a value from one of those can be
-- of a kind its chain does not have. 'addrToText' gives 'Nothing' for such a
-- value.
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
  | -- | SegWit address with a witness version other than zero, such as
    -- Taproot. The version is between 1 and 16 and the program is between 2
    -- and 40 bytes long.
    OtherWitnessAddress
      { version :: !Word8,
        bytes :: !ByteString
      }
  | -- | pay to script hash (256-bit)
    Script32Address
      { -- | HASH256 hash of script
        hash256 :: !Hash256
      }
  | -- | CashAddr with a type or hash size that has no dedicated constructor.
    -- Token-aware addresses have type 2 (P2PKH) or 3 (P2SH). The type is
    -- below 16 and the hash has one of the sizes the standard allows.
    OtherCashAddress
      { version :: !Word8,
        bytes :: !ByteString
      }
  deriving
    (Eq, Ord, Generic, Show, Hashable, NFData)

-- | Reads the text that 'Show' writes. The two generic kinds go through
-- 'witnessAddress' and 'cashAddress', so a version or a length that those
-- refuse does not read, and neither does a value that has a dedicated
-- constructor.
instance Read Address where
  readPrec =
    parens . prec 11 $ do
      Ident name <- lexP
      expectP (Punc "{")
      addr <- case name of
        "PubKeyAddress" -> PubKeyAddress <$> field "hash160"
        "ScriptAddress" -> ScriptAddress <$> field "hash160"
        "WitnessPubKeyAddress" -> WitnessPubKeyAddress <$> field "hash160"
        "WitnessScriptAddress" -> WitnessScriptAddress <$> field "hash256"
        "Script32Address" -> Script32Address <$> field "hash256"
        "OtherWitnessAddress" -> generic isWitnessAddress witnessAddress
        "OtherCashAddress" -> generic isCashAddress cashAddress
        _ -> pfail
      expectP (Punc "}")
      return addr
    where
      field :: (Read a) => String -> ReadPrec a
      field name = do
        expectP (Ident name)
        expectP (Punc "=")
        reset readPrec
      generic isKind build = do
        v <- field "version"
        expectP (Punc ",")
        b <- field "bytes"
        maybe pfail return (mfilter isKind (build v b))
  readListPrec = readListPrecDefault

-- | Match a SegWit address with a witness version other than zero. Use
-- 'witnessAddress' to build one.
pattern WitnessAddress :: Word8 -> ByteString -> Address
pattern WitnessAddress v d <- OtherWitnessAddress v d

-- | Match a CashAddr that has no dedicated constructor, such as a token-aware
-- address. Use 'cashAddress' to build one.
pattern CashAddress :: Word8 -> ByteString -> Address
pattern CashAddress v d <- OtherCashAddress v d

{-# COMPLETE
  PubKeyAddress,
  ScriptAddress,
  WitnessPubKeyAddress,
  WitnessScriptAddress,
  WitnessAddress,
  Script32Address,
  CashAddress
  #-}

-- | Highest witness version defined by BIP-141.
maxWitnessVersion :: Word8
maxWitnessVersion = 16

-- | Witness program length limits from BIP-141.
minWitnessProgramLength, maxWitnessProgramLength :: Int
minWitnessProgramLength = 2
maxWitnessProgramLength = 40

-- | Highest CashAddr type. The type byte holds the type in four bits.
maxCashAddrType :: Word8
maxCashAddrType = 15

-- | Hash sizes that the CashAddr version byte can describe.
cashAddrHashLengths :: [Int]
cashAddrHashLengths = [20, 24, 28, 32, 40, 48, 56, 64]

-- | CashAddr types for token-aware addresses, introduced with CashTokens.
-- They lock coins with the same script as the plain P2PKH and P2SH types.
-- The type only tells the sender that the receiver can handle tokens.
tokenPubKeyType, tokenScriptType :: Word8
tokenPubKeyType = 2
tokenScriptType = 3

-- | Binary serialization for 'Address' type is not standard.
-- Do not expect other other software to understand these.
-- Use text format or output scripts for exchange.
instance Serial Address where
  serialize = \case
    PubKeyAddress k -> do
      putWord8 0x00
      serialize k
    ScriptAddress s -> do
      putWord8 0x01
      serialize s
    WitnessPubKeyAddress h -> do
      putWord8 0x02
      serialize h
    WitnessScriptAddress s -> do
      putWord8 0x03
      serialize s
    OtherWitnessAddress v d -> do
      putWord8 0x04
      putWord8 v
      putSized d
    Script32Address s -> do
      putWord8 0x05
      serialize s
    OtherCashAddress v d -> do
      putWord8 0x06
      putWord8 v
      putSized d

  deserialize =
    getWord8 >>= \case
      0x00 -> PubKeyAddress <$> deserialize
      0x01 -> ScriptAddress <$> deserialize
      0x02 -> WitnessPubKeyAddress <$> deserialize
      0x03 -> WitnessScriptAddress <$> deserialize
      0x04 -> do
        v <- getWord8
        d <- getSized maxWitnessProgramLength
        checked "SegWit" (witnessAddress v d)
      0x05 -> Script32Address <$> deserialize
      0x06 -> do
        v <- getWord8
        d <- getSized (maximum cashAddrHashLengths)
        checked "CashAddr" (cashAddress v d)
      b ->
        fail . T.unpack $
          "Could not decode address type byte: "
            <> encodeHex (B.singleton b)
    where
      checked kind = maybe (fail ("Invalid " <> kind <> " address")) return

-- | Write bytes behind their length. The length is a 64-bit word to stay
-- compatible with data serialized by earlier versions.
putSized :: (MonadPut m) => ByteString -> m ()
putSized d = do
  putWord64be (fromIntegral (B.length d))
  putByteString d

-- | Read bytes written by 'putSized'. The length is checked against a maximum
-- while it is still a 64-bit word, so a corrupt or hostile length can neither
-- overflow an 'Int' nor ask for a huge allocation.
getSized :: (MonadGet m) => Int -> m ByteString
getSized maxLen = do
  n <- getWord64be
  when (n > fromIntegral maxLen) $ fail "Address payload too long"
  getByteString (fromIntegral n)

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
isWitnessAddress OtherWitnessAddress {} = True
isWitnessAddress _ = False

-- | 'Address' pays to a 256-bit script hash.
isScript32Address :: Address -> Bool
isScript32Address Script32Address {} = True
isScript32Address _ = False

-- | 'Address' is another type of CashAddr, not covered above.
isCashAddress :: Address -> Bool
isCashAddress OtherCashAddress {} = True
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

-- | Smart constructor for a SegWit address from its witness version and
-- program. Version zero programs must be 20 or 32 bytes long and become
-- 'WitnessPubKeyAddress' or 'WitnessScriptAddress'. Other versions keep the
-- program as it is, as long as it is between 2 and 40 bytes long.
witnessAddress :: Word8 -> ByteString -> Maybe Address
witnessAddress v bs = do
  guard $ v <= maxWitnessVersion
  guard $ B.length bs >= minWitnessProgramLength
  guard $ B.length bs <= maxWitnessProgramLength
  if v == 0
    then case B.length bs of
      20 -> WitnessPubKeyAddress <$> decodeHash bs
      32 -> WitnessScriptAddress <$> decodeHash bs
      _ -> Nothing
    else return $ OtherWitnessAddress v bs

-- | Smart constructor for P2SH32 address.
script32Address :: Hash256 -> Address
script32Address = Script32Address

-- | Smart constructor for a CashAddr from its type and hash. P2PKH and P2SH
-- types with a 20-byte hash become 'PubKeyAddress' and 'ScriptAddress', and
-- the P2SH type with a 32-byte hash becomes 'Script32Address'. Every other
-- combination that the standard allows is kept as it is.
cashAddress :: Word8 -> ByteString -> Maybe Address
cashAddress v b = do
  guard $ v <= maxCashAddrType
  guard $ B.length b `elem` cashAddrHashLengths
  case (v, B.length b) of
    (0, 20) -> PubKeyAddress <$> decodeHash b
    (1, 20) -> ScriptAddress <$> decodeHash b
    (1, 32) -> Script32Address <$> decodeHash b
    _ -> return $ OtherCashAddress v b

-- | Read a hash from bytes of the right length.
decodeHash :: (Serial a) => ByteString -> Maybe a
decodeHash = eitherToMaybe . runGetS deserialize

-- | The 160-bit hash an address pays to, if it pays to one. Token-aware
-- CashAddr addresses pay to the same hash as their plain counterparts.
addressHash160 :: Address -> Maybe Hash160
addressHash160 = \case
  PubKeyAddress h -> Just h
  ScriptAddress h -> Just h
  WitnessPubKeyAddress h -> Just h
  OtherCashAddress v b
    | (v == tokenPubKeyType || v == tokenScriptType) && B.length b == 20 ->
        decodeHash b
  _ -> Nothing

-- | The 256-bit hash an address pays to, if it pays to one. Token-aware
-- CashAddr addresses pay to the same hash as their plain counterparts.
addressHash256 :: Address -> Maybe Hash256
addressHash256 = \case
  WitnessScriptAddress h -> Just h
  Script32Address h -> Just h
  OtherCashAddress v b
    | v == tokenScriptType && B.length b == 32 ->
        decodeHash b
  _ -> Nothing

-- | The witness version of a SegWit address, or the CashAddr type of any
-- other address.
addressVersion :: Address -> Word8
addressVersion = \case
  PubKeyAddress _ -> 0
  ScriptAddress _ -> 1
  WitnessPubKeyAddress _ -> 0
  WitnessScriptAddress _ -> 0
  OtherWitnessAddress v _ -> v
  Script32Address _ -> 1
  OtherCashAddress v _ -> v

-- | The hash or witness program of an address, without any prefix.
addressBytes :: Address -> ByteString
addressBytes = \case
  PubKeyAddress h -> hashBytes h
  ScriptAddress h -> hashBytes h
  WitnessPubKeyAddress h -> hashBytes h
  WitnessScriptAddress h -> hashBytes h
  OtherWitnessAddress _ b -> b
  Script32Address h -> hashBytes h
  OtherCashAddress _ b -> b

-- | Raw bytes of a hash.
hashBytes :: (Serial a) => a -> ByteString
hashBytes = runPutS . serialize

-- | JSON encoding uses the text form of the address. Encoding an address that
-- has no text form on the network, such as a SegWit address on Bitcoin Cash,
-- is a programming error and throws an 'error'. A loud failure is better than
-- a silent @null@ in the output.
--
-- An address from 'outputAddress', 'scriptToAddress', 'scriptToAddressBS',
-- 'textToAddr' or the JSON parser of the same network always has a text form
-- there. One from a constructor or from the binary form may not. Check such
-- a value with 'addrToText' before encoding it.
instance MarshalJSON Network Address where
  marshalValue net = toJSON . addrTextOrError net
  marshalEncoding net = text . addrTextOrError net
  unmarshalValue net =
    withText "address" $ \t ->
      case textToAddr net t of
        Nothing -> fail "could not decode address"
        Just x -> return x

addrTextOrError :: Network -> Address -> Text
addrTextOrError net a = fromMaybe (error msg) (addrToText net a)
  where
    msg =
      "Address " <> show a <> " has no text form on network " <> net.name

-- | Convert address to human-readable string. Uses 'CashAddr' on Bitcoin Cash
-- networks, and 'Base58' or 'Bech32' on Bitcoin networks.
addrToText :: Network -> Address -> Maybe Text
addrToText net a
  | isJust net.cashAddrPrefix = addrToCash net a
  | otherwise = addrToBase58 net a <|> addrToBech32 net a

-- | Encode a P2PKH or P2SH address in the legacy 'Base58' format of the
-- network. Works on Bitcoin Cash networks too, for software that still needs
-- the legacy format there. Other address kinds have no 'Base58' form.
addrToBase58 :: Network -> Address -> Maybe Base58
addrToBase58 net = \case
  PubKeyAddress h -> Just $ base58 net.addrPrefix h
  ScriptAddress h -> Just $ base58 net.scriptPrefix h
  _ -> Nothing
  where
    base58 pfx h = encodeBase58Check . runPutS $ putWord8 pfx >> serialize h

-- | Encode a SegWit address in the 'Bech32' or 'Bech32m' format of the
-- network. Fails on networks without SegWit and for other address kinds.
addrToBech32 :: Network -> Address -> Maybe Bech32
addrToBech32 net a = do
  hrp <- net.bech32Prefix
  case a of
    WitnessPubKeyAddress h -> segwitEncode hrp 0 (B.unpack (hashBytes h))
    WitnessScriptAddress h -> segwitEncode hrp 0 (B.unpack (hashBytes h))
    OtherWitnessAddress v d -> segwitEncode hrp v (B.unpack d)
    _ -> Nothing

-- | Encode an address in the 'CashAddr' format of the network. Fails on
-- networks without CashAddr and for SegWit addresses.
addrToCash :: Network -> Address -> Maybe CashAddr
addrToCash net = \case
  PubKeyAddress h -> cashAddrEncode net 0 (hashBytes h)
  ScriptAddress h -> cashAddrEncode net 1 (hashBytes h)
  Script32Address h -> cashAddrEncode net 1 (hashBytes h)
  OtherCashAddress v b -> cashAddrEncode net v b
  _ -> Nothing

-- | Parse 'Base58', 'Bech32' or 'CashAddr' address, depending on network.
--
-- The text must be the address and nothing else. White space around it is
-- refused, where Bitcoin Core skips it around a 'Base58' address, so trim
-- text that comes from a user.
--
-- A result is a well-formed address of the network. It is not always one
-- that can be paid. A CashAddr of a type above 3, or with a hash that is not
-- 20 or 32 bytes long, decodes to an address that has no output script, and
-- Bitcoin Cash Node refuses it as a destination. 'addressToOutput' tells:
-- it gives 'Nothing' for those.
textToAddr :: Network -> Text -> Maybe Address
textToAddr net txt =
  cashToAddr net txt <|> bech32ToAddr net txt <|> base58ToAddr net txt

cashToAddr :: Network -> Text -> Maybe Address
cashToAddr net txt = uncurry cashAddress =<< cashAddrDecode net txt

bech32ToAddr :: Network -> Text -> Maybe Address
bech32ToAddr net txt = do
  hrp <- net.bech32Prefix
  (ver, prog) <- segwitDecode hrp txt
  witnessAddress ver (B.pack prog)

base58ToAddr :: Network -> Text -> Maybe Address
base58ToAddr net txt = do
  guard $ T.length txt <= maxBase58AddressLength
  bs <- decodeBase58Check txt
  eitherToMaybe $ runGetS (base58get net) bs

-- | A 'Base58' address holds 25 bytes: a version byte, a 20-byte hash and a
-- 4-byte checksum. That never takes more than 35 digits, because 58^35 is
-- larger than 256^25. Longer strings are rejected before any decoding, since
-- the time to decode grows with the square of the length.
maxBase58AddressLength :: Int
maxBase58AddressLength = 35

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

-- | HASH160 of a public key in its serialized form.
pubKeyHash :: Ctx -> PublicKey -> Hash160
pubKeyHash ctx = addressHash . marshal ctx

-- | Obtain a standard pay-to-public-key-hash address from a public key.
pubKeyAddr :: Ctx -> PublicKey -> Address
pubKeyAddr ctx = p2pkhAddr . pubKeyHash ctx

-- | Obtain a SegWit pay-to-witness-public-key-hash (P2WPKH) address from a
-- public key. Returns 'Nothing' for an uncompressed key. BIP-143 makes witness
-- spends with uncompressed keys non-standard, so coins sent to such an address
-- could not be spent through the normal network.
pubKeyWitnessAddr :: Ctx -> PublicKey -> Maybe Address
pubKeyWitnessAddr ctx pk = do
  guard pk.compress
  return . p2wpkhAddr $ pubKeyHash ctx pk

-- | Obtain a backwards-compatible SegWit P2SH-P2WPKH address from a public key.
-- Returns 'Nothing' for an uncompressed key, for the same reason as
-- 'pubKeyWitnessAddr'.
pubKeyCompatWitnessAddr :: Ctx -> PublicKey -> Maybe Address
pubKeyCompatWitnessAddr ctx pk = do
  guard pk.compress
  return . p2shP2wpkhAddr $ pubKeyHash ctx pk

-- | Obtain a standard pay-to-public-key-hash (P2PKH) address from a 'Hash160'.
p2pkhAddr :: Hash160 -> Address
p2pkhAddr = PubKeyAddress

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

-- | Obtain the backwards-compatible SegWit P2SH-P2WPKH address of the
-- 'Hash160' of a compressed public key. It is the pay-to-script-hash address
-- of the witness program @OP_0@ followed by the push of the 20-byte hash,
-- which is 22 bytes long.
p2shP2wpkhAddr :: Hash160 -> Address
p2shP2wpkhAddr h =
  p2shAddr . addressHash $ B.pack [0x00, 0x14] <> hashBytes h

-- | Compute a standard pay-to-script-hash (P2SH) address for an output script.
--
-- Fails when the redeem script is longer than 'maxRedeemScriptSize' (520)
-- bytes. Consensus limits a push to that size, and the redeem script is a
-- push of the spending input, so coins sent to such an address could never be
-- spent. A multisig of compressed keys fits up to 15 keys. Use
-- 'payToWitnessScriptAddress' or 'payToNestedScriptAddress' for more.
--
-- Also fails for a value that 'encodeOutput' cannot write, such as a multisig
-- that requires more signatures than it has keys.
payToScriptAddress :: Ctx -> ScriptOutput -> Either String Address
payToScriptAddress ctx =
  fmap p2shAddr . p2shScriptHash <=< encodeOutput ctx

-- | Compute a SegWit pay-to-witness-script-hash (P2WSH) address for an output
-- script.
--
-- Fails when the witness script is longer than 'maxWitnessScriptSize'
-- (10,000) bytes, which consensus could never execute, and for a value that
-- 'encodeOutput' cannot write. The relay policy of Bitcoin Core is stricter
-- than consensus: it does not relay the spend of a witness script above 3,600
-- bytes, nor one with an uncompressed key. This function does not check
-- either.
payToWitnessScriptAddress :: Ctx -> ScriptOutput -> Either String Address
payToWitnessScriptAddress ctx =
  fmap p2wshAddr . p2wshScriptHash <=< encodeOutput ctx

-- | Compute a backwards-compatible SegWit P2SH-P2WSH address: the
-- pay-to-script-hash address of the witness program of the script. Fails as
-- 'payToWitnessScriptAddress' does.
payToNestedScriptAddress :: Ctx -> ScriptOutput -> Either String Address
payToNestedScriptAddress ctx out = do
  h <- p2wshScriptHash =<< encodeOutput ctx out
  payToScriptAddress ctx (PayWitnessScriptHash h)

-- | Get the output script that locks coins sent to an address. Token-aware
-- CashAddr addresses use the same script as their plain counterparts. Other
-- CashAddr kinds have no known script, so the result is 'Nothing'.
--
-- The function does not know the network. It gives the script of a SegWit
-- address or of a 256-bit script hash address whatever chain the caller
-- works on. An address read with 'textToAddr' or from JSON always belongs to
-- its network. An address built with a constructor, or read from its binary
-- form, may not: check it with 'addrToText' of the network before paying it.
-- On Bitcoin, anyone who sees the redeem script can spend the script of a
-- 'Script32Address', and Bitcoin Cash does not have SegWit.
addressToOutput :: Address -> Maybe ScriptOutput
addressToOutput =
  \case
    PubKeyAddress h -> Just (PayPKHash h)
    ScriptAddress h -> Just (PayScriptHash h)
    WitnessPubKeyAddress h -> Just (PayWitnessPKHash h)
    WitnessScriptAddress h -> Just (PayWitnessScriptHash h)
    OtherWitnessAddress v d -> Just (PayWitness v d)
    Script32Address h -> Just (PayScript32Hash h)
    OtherCashAddress v b -> cashAddressOutput v b

-- | Output script for a CashAddr kind without a dedicated constructor.
cashAddressOutput :: Word8 -> ByteString -> Maybe ScriptOutput
cashAddressOutput v b
  | v == tokenPubKeyType && len == 20 = PayPKHash <$> decodeHash b
  | v == tokenScriptType && len == 20 = PayScriptHash <$> decodeHash b
  | v == tokenScriptType && len == 32 = PayScript32Hash <$> decodeHash b
  | otherwise = Nothing
  where
    len = B.length b

-- | Get output script AST for an 'Address'.
addressToScript :: Ctx -> Address -> Maybe Script
addressToScript ctx addr =
  addressToOutput addr >>= eitherToMaybe . encodeOutput ctx

-- | Encode address as output script in 'ByteString' form.
addressToScriptBS :: Ctx -> Address -> Maybe ByteString
addressToScriptBS ctx addr = (runPutS . serialize) <$> addressToScript ctx addr

-- | Decode an output script into the 'Address' it has on a network, if it
-- has one there. See 'outputAddress'.
scriptToAddress :: Network -> Ctx -> Script -> Either String Address
scriptToAddress net ctx =
  maybeToEither e . outputAddress net ctx <=< decodeOutput ctx
  where
    e = "Could not decode address"

-- | Decode a serialized script into the 'Address' it has on a network, if it
-- has one there. See 'outputAddress'.
scriptToAddressBS :: Network -> Ctx -> ByteString -> Either String Address
scriptToAddressBS net ctx =
  maybeToEither e . outputAddress net ctx <=< unmarshal ctx
  where
    e = "Could not decode address"

-- | Get the 'Address' that a 'ScriptOutput' has on a network.
--
-- A pay-to-public-key output has no address. Its coins are not spendable with
-- the input script of the P2PKH address of the same key, so reporting that
-- address would mislead.
--
-- An output only has an address on a network that defines its kind. A
-- witness program has none on a network without SegWit, such as Bitcoin
-- Cash. A 256-bit script hash (@OP_HASH256@, a push of 32 bytes, @OP_EQUAL@)
-- has one on the Bitcoin Cash networks only. On Bitcoin that script is a
-- plain hash lock, which Bitcoin Core reports as non-standard. Every address
-- this function returns has a text form on the network, so 'addrToText' and
-- the JSON encoder succeed for it.
outputAddress :: Network -> Ctx -> ScriptOutput -> Maybe Address
outputAddress net _ =
  \case
    PayPKHash h -> Just $ PubKeyAddress h
    PayScriptHash h -> Just $ ScriptAddress h
    PayWitnessPKHash h -> witness $ Just (WitnessPubKeyAddress h)
    PayWitnessScriptHash h -> witness $ Just (WitnessScriptAddress h)
    PayWitness v d -> witness $ witnessAddress v d
    PayScript32Hash h -> script32 $ Just (Script32Address h)
    _ -> Nothing
  where
    -- SegWit addresses exist where the network has a Bech32 prefix.
    witness a = guard (isJust net.bech32Prefix) >> a
    -- Pay-to-script-hash with a 256-bit hash exists where the network has
    -- CashAddr.
    script32 a = guard (isJust net.cashAddrPrefix) >> a

-- | Infer the 'Address' that a 'ScriptInput' spends from. It is the address
-- of the public key or of the redeem script that the input carries.
--
-- 'decodeInput' only returns a redeem script in the form 'encodeOutput'
-- writes, so for a decoded input this is the hash of the redeem script bytes
-- of the input. There is no address for a redeem script above
-- 'maxRedeemScriptSize' bytes, since no valid input can carry one. The
-- function does not look at the output being spent, so it is a guess that a
-- caller should confirm against that output when it has it.
inputAddress :: Ctx -> ScriptInput -> Maybe Address
inputAddress ctx =
  \case
    (RegularInput (SpendPKHash _ key)) -> Just $ pubKeyAddr ctx key
    (ScriptHashInput _ rdm) -> eitherToMaybe $ payToScriptAddress ctx rdm
    (NestedWitnessInput rdm) -> eitherToMaybe $ payToScriptAddress ctx rdm
    _ -> Nothing
