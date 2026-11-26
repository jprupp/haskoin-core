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
    tokenAwareAddress,
    plainAddress,
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
import Control.Monad (guard, mfilter, unless, when, (<=<))
import Crypto.Secp256k1
import Data.Aeson (ToJSON (toJSON), withText)
import Data.Aeson.Encoding (text)
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Unsafe qualified as BU
import Data.Bytes.Get (MonadGet (getByteString, getWord64be, getWord8), runGetS)
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
import Haskoin.Script.CashToken (hasTokenPrefix, splitTokenData)
import Haskoin.Script.Common
import Haskoin.Script.Standard
import Haskoin.Util
import Haskoin.Util.Direct (getDirect)
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
  {-# INLINEABLE serialize #-}

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
  {-# INLINEABLE deserialize #-}

-- | Write bytes behind their length. The length is a 64-bit word to stay
-- compatible with data serialized by earlier versions.
putSized :: (MonadPut m) => ByteString -> m ()
putSized d = do
  putWord64be (fromIntegral (B.length d))
  putByteString d
{-# INLINEABLE putSized #-}

-- | Read bytes written by 'putSized'. The length is checked against a maximum
-- while it is still a 64-bit word, so a corrupt or hostile length can neither
-- overflow an 'Int' nor ask for a huge allocation.
getSized :: (MonadGet m) => Int -> m ByteString
getSized maxLen = do
  n <- getWord64be
  when (n > fromIntegral maxLen) $ fail "Address payload too long"
  getByteString (fromIntegral n)
{-# INLINEABLE getSized #-}

-- | Through cereal an address is read on a buffer directly, with
-- 'getDirect': an index of the chain has an address in the key of every
-- output and of every balance. It is written through the builder of cereal,
-- which costs less for a tag and a hash than a buffer of their own.
instance Serialize Address where
  put = serialize
  get = getDirect deserialize

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

-- | The token-aware form of an address of Bitcoin Cash: CashAddr type 2 for
-- a P2PKH address, type 3 for a P2SH or P2SH32 address. A token-aware
-- address is its own token-aware form. 'Nothing' for any other address,
-- which has no such form.
--
-- CashTokens added these types so that a wallet can tell a sender that it
-- knows about tokens: software that does not would burn tokens sent to it,
-- by spending the coins without carrying the tokens over. Both forms lock
-- coins with the same script, so the token-aware form changes nothing on the
-- chain, only what a sender is told it may send.
--
-- Use it to show the address of an output that holds tokens, or to give a
-- token wallet an address to receive at. 'scriptToAddressBS' returns the
-- plain form for every output, with or without tokens; see there why.
--
-- Bitcoin has no token-aware addresses: 'addrToText' of the result is
-- 'Nothing' on a Bitcoin network, and on Bitcoin Cash it starts with @z@
-- for type 2 and @r@ for type 3 with a 32-byte hash.
tokenAwareAddress :: Address -> Maybe Address
tokenAwareAddress = \case
  PubKeyAddress h -> cashAddress tokenPubKeyType (hashBytes h)
  ScriptAddress h -> cashAddress tokenScriptType (hashBytes h)
  Script32Address h -> cashAddress tokenScriptType (hashBytes h)
  a@(OtherCashAddress v b)
    | isJust (cashAddressOutput v b) -> Just a
  _ -> Nothing

-- | The plain form of a token-aware address: the inverse of
-- 'tokenAwareAddress'. Every other address is returned as it is.
--
-- Two addresses that lock coins with the same script are different values,
-- so @plainAddress@ is how to put a token-aware address that a user gives
-- next to the addresses that 'scriptToAddressBS' returns, for instance to
-- look up its balance.
plainAddress :: Address -> Address
plainAddress = \case
  a@(OtherCashAddress v b)
    | v == tokenPubKeyType && len == 20 -> maybe a PubKeyAddress (decodeHash b)
    | v == tokenScriptType && len == 20 -> maybe a ScriptAddress (decodeHash b)
    | v == tokenScriptType && len == 32 -> maybe a Script32Address (decodeHash b)
    where
      len = B.length b
  a -> a

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

-- | Encode an address in the legacy 'Base58' format of the network: a P2PKH
-- or a P2SH address on every network, and a P2SH32 address on the Bitcoin
-- Cash networks. Other address kinds have no 'Base58' form.
--
-- The format works on the Bitcoin Cash networks for software that still
-- needs it there. Prefer 'addrToCash' where there is a choice: CashAddr is
-- the format of the specification.
--
-- No specification gives a legacy form to a P2SH32 address. The one written
-- here is that of Bitcoin Cash Node, which writes it with @-usecashaddr=0@
-- and reads it: the version byte of a script address, then the 32 bytes of
-- the hash. The text has 50 or 51 characters, where the other legacy
-- addresses have at most 35. Software that knows only those refuses it.
-- Bitcoin has no P2SH32 address, so on a Bitcoin network there is no form
-- to write.
addrToBase58 :: Network -> Address -> Maybe Base58
addrToBase58 net = \case
  PubKeyAddress h -> Just $ base58 net.addrPrefix h
  ScriptAddress h -> Just $ base58 net.scriptPrefix h
  Script32Address h | hasScript32 net -> Just $ base58 net.scriptPrefix h
  _ -> Nothing
  where
    base58 :: (Serial h) => Word8 -> h -> Base58
    base58 pfx h = encodeBase58Check . runPutS $ putWord8 pfx >> serialize h

-- | Pay-to-script-hash with a 256-bit hash (P2SH32) exists where the network
-- has CashAddr: on the Bitcoin Cash networks.
hasScript32 :: Network -> Bool
hasScript32 net = isJust net.cashAddrPrefix

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
-- A Bitcoin Cash network reads CashAddr and the legacy 'Base58' form, that
-- of a P2SH32 address included ('addrToBase58').
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

-- | Parse an address in the legacy 'Base58' format of the network: what
-- 'addrToBase58' writes there. That is a P2PKH or a P2SH address on every
-- network, and a P2SH32 address on the Bitcoin Cash networks, in the form
-- that Bitcoin Cash Node reads.
base58ToAddr :: Network -> Text -> Maybe Address
base58ToAddr net txt = do
  guard $ T.length txt <= maxBase58AddressLength
  (version, hash) <- B.uncons =<< decodeBase58Check txt
  legacyAddress net version hash

-- | The longest 'Base58' address. Longer strings are rejected before any
-- decoding, since the time to decode grows with the square of the length.
--
-- The longest address is a P2SH32 address of Bitcoin Cash. It holds 37
-- bytes: a version byte, a 32-byte hash and a 4-byte checksum. That never
-- takes more than 51 digits, because 58^51 is larger than 256^37. The other
-- addresses hold 25 bytes, which take at most 35 digits.
--
-- This is a bound on the work, the same on every network, and not a rule
-- of what an address is: 'legacyAddress' decides that from the bytes.
maxBase58AddressLength :: Int
maxBase58AddressLength = 51

-- | The address of a legacy version byte and the hash that follows it. A key
-- hash has 20 bytes. A script hash has 20 bytes, or 32 on a network with
-- P2SH32. Any other length is refused, so no byte is left unread.
legacyAddress :: Network -> Word8 -> ByteString -> Maybe Address
legacyAddress net version hash =
  case B.length hash of
    20
      | version == net.addrPrefix -> PubKeyAddress <$> decodeHash hash
      | version == net.scriptPrefix -> ScriptAddress <$> decodeHash hash
    32
      | version == net.scriptPrefix, hasScript32 net -> Script32Address <$> decodeHash hash
    _ -> Nothing

-- | HASH160 of a public key in its serialized form.
pubKeyHash :: PublicKey -> Hash160
pubKeyHash = addressHash . encodeSerial

-- | Obtain a standard pay-to-public-key-hash address from a public key.
pubKeyAddr :: PublicKey -> Address
pubKeyAddr = p2pkhAddr . pubKeyHash

-- | Obtain a SegWit pay-to-witness-public-key-hash (P2WPKH) address from a
-- public key. Returns 'Nothing' for an uncompressed key. BIP-143 makes witness
-- spends with uncompressed keys non-standard, so coins sent to such an address
-- could not be spent through the normal network.
pubKeyWitnessAddr :: PublicKey -> Maybe Address
pubKeyWitnessAddr pk = do
  guard pk.compress
  return . p2wpkhAddr $ pubKeyHash pk

-- | Obtain a backwards-compatible SegWit P2SH-P2WPKH address from a public key.
-- Returns 'Nothing' for an uncompressed key, for the same reason as
-- 'pubKeyWitnessAddr', and on a network without SegWit, for the reason that
-- 'p2shP2wpkhAddr' gives.
pubKeyCompatWitnessAddr :: Network -> PublicKey -> Maybe Address
pubKeyCompatWitnessAddr net pk = do
  guard pk.compress
  p2shP2wpkhAddr net (pubKeyHash pk)

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
--
-- Returns 'Nothing' on a network without SegWit, such as Bitcoin Cash. The
-- address is an ordinary pay-to-script-hash address, so it has a text there
-- and a payer can send coins to it. But only a witness holds the signature
-- that protects those coins, and such a network has no witness. On Bitcoin
-- Cash a block may spend them with the witness program alone as the input
-- script, without any signature (the SegWit recovery rule of May 2019), so
-- any miner can take them, and nodes do not relay that spend, so the owner
-- cannot make it without a miner. This is why the function takes the
-- network: a wallet must not show such an address there.
p2shP2wpkhAddr :: Network -> Hash160 -> Maybe Address
p2shP2wpkhAddr net h = do
  guard net.segWit
  return . p2shAddr . addressHash $ B.pack [0x00, 0x14] <> hashBytes h

-- | Compute a standard pay-to-script-hash (P2SH) address for an output script.
--
-- Fails when the redeem script is longer than 'maxRedeemScriptSize' (520)
-- bytes. On Bitcoin, consensus limits a push to that size, and the redeem
-- script is a push of the spending input, so coins sent to such an address
-- could never be spent. A multisig of compressed keys fits up to 15 keys. Use
-- 'payToWitnessScriptAddress' or 'payToNestedScriptAddress' for more.
--
-- The function takes no network, and the limit is the same on all of them.
-- On Bitcoin Cash it is stricter than the network, which spends a redeem
-- script of up to 9,997 bytes since May 2025: the library gives no address
-- for a multisig of 16 to 20 keys there. 'maxRedeemScriptSize' has the
-- reason.
--
-- Also fails for a value that 'encodeOutput' cannot write, such as a multisig
-- that requires more signatures than it has keys.
payToScriptAddress :: ScriptOutput -> Either String Address
payToScriptAddress =
  fmap p2shAddr . p2shScriptHash <=< encodeOutput

-- | Compute a SegWit pay-to-witness-script-hash (P2WSH) address for an output
-- script.
--
-- Fails when the witness script is longer than 'maxWitnessScriptSize'
-- (10,000) bytes, which consensus could never execute, and for a value that
-- 'encodeOutput' cannot write. The relay policy of Bitcoin Core is stricter
-- than consensus: it does not relay the spend of a witness script above 3,600
-- bytes, nor one with an uncompressed key. This function does not check
-- either.
payToWitnessScriptAddress :: ScriptOutput -> Either String Address
payToWitnessScriptAddress =
  fmap p2wshAddr . p2wshScriptHash <=< encodeOutput

-- | Compute a backwards-compatible SegWit P2SH-P2WSH address: the
-- pay-to-script-hash address of the witness program of the script. Fails as
-- 'payToWitnessScriptAddress' does.
--
-- Also fails on a network without SegWit, such as Bitcoin Cash, where any
-- miner can take coins sent to such an address: see 'p2shP2wpkhAddr'.
payToNestedScriptAddress :: Network -> ScriptOutput -> Either String Address
payToNestedScriptAddress net out = do
  unless net.segWit . Left $
    "The network "
      <> net.name
      <> " has no SegWit, so any miner can take coins sent to a nested SegWit address"
  h <- p2wshScriptHash =<< encodeOutput out
  payToScriptAddress (PayWitnessScriptHash h)

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
addressToScript :: Address -> Maybe Script
addressToScript addr =
  addressToOutput addr >>= eitherToMaybe . encodeOutput

-- | Encode address as output script in 'ByteString' form.
addressToScriptBS :: Address -> Maybe ByteString
addressToScriptBS addr = (runPutS . serialize) <$> addressToScript addr

-- | Decode an output script into the 'Address' it has on a network, if it
-- has one there. See 'outputAddress'.
--
-- On the Bitcoin Cash networks, a script that starts with the token prefix
-- byte 0xef, which parses as @OP_INVALIDOPCODE 0xef@, is the script field of
-- an output that holds tokens. It is handled as 'scriptToAddressBS' handles
-- it. Most such fields do not parse as a t'Script' at all: give their bytes to
-- 'scriptToAddressBS'.
scriptToAddress :: Network -> Script -> Either String Address
scriptToAddress net script
  | isJust net.cashAddrPrefix,
    OP_INVALIDOPCODE 0xef : _ <- script.ops =
      scriptToAddressBS net (encodeSerial script)
  | otherwise =
      maybeToEither e . outputAddress net =<< decodeOutput script
  where
    e = "Could not decode address"

-- | Decode a serialized script into the 'Address' it has on a network, if it
-- has one there. See 'outputAddress'.
--
-- The four kinds of output that most transactions pay to are told by their
-- bytes, without parsing the script: a key hash, a script hash, and on a
-- network with SegWit a witness key hash and a witness script hash. A server
-- reads the address of every input and output that it shows, and parsing
-- took most of that time.
--
-- Any other script is parsed with 'decodeSerial', and gives what the parser
-- gives, with the same text in a 'Left'; the tests hold both ways to the
-- same answers. That covers Taproot and the other witness versions, the
-- 256-bit script hash of Bitcoin Cash, and the scripts that have no address:
-- data carriers, bare public keys and multisig, and everything that is not
-- standard. A script with public keys in it costs the most, because each
-- key is checked to be a point of the curve before the answer is no.
--
-- By the benchmark of this package, at @-O1@ as at @-O2@, one of the four
-- kinds takes a twelfth or less of the time it took in version 1.6.0, which
-- parsed every script, and a Taproot output or a data carrier takes about a
-- fifth. Versions 1.6.3 and 1.6.4 were as fast for the four kinds, and
-- nearly twice as slow as 1.6.0 for every script they parsed.
--
-- On the Bitcoin Cash networks, the script field of an output that holds
-- tokens (CashTokens) starts with a token prefix, which
-- 'Haskoin.Script.CashToken.splitTokenData' takes off. The address is the
-- one of the locking script after it, and is in its plain form: a P2PKH,
-- P2SH or P2SH32 address of CashAddr type 0 or 1, as for an output without
-- tokens. A field with a prefix that is not valid has no address, and gives
-- the error of the prefix in a 'Left'. On Bitcoin the byte 0xef is no
-- prefix, and such a script has no address.
--
-- The plain form is the one an output has whatever it holds. Bitcoin Cash
-- Node shows the same, with the tokens apart. It keeps all the coins of a
-- key or a script under one address, as an index of addresses should: a
-- wallet receives coins with and without tokens at the same script, and the
-- token-aware form would split its history and its balance in two. Read the
-- tokens with 'splitTokenData', and show the token-aware form with
-- 'tokenAwareAddress' where a user wants it.
--
-- So nothing in the address says that an output holds tokens. A program that
-- serves the unspent outputs of an address must also give the tokens of each
-- one, from 'splitTokenData'. A wallet that spent such an output as a plain
-- coin would burn its tokens, or sign a digest without the token prefix and
-- see the transaction refused: see 'Haskoin.Script.SigHash.txSigHashCashToken'.
-- This is the mistake that token-aware addresses exist to prevent, and the
-- server has to prevent it by other means.
--
-- Before version 3.0.0 these outputs had no address. An index of addresses
-- built with an older version left them out, and must be built again, or have
-- them added, before it runs with this one: otherwise it takes away from a
-- balance an output that it never added when that output is spent.
scriptToAddressBS :: Network -> ByteString -> Either String Address
scriptToAddressBS net bytes
  | isJust net.cashAddrPrefix,
    hasTokenPrefix bytes =
      scriptToAddressBS' net . snd =<< splitTokenData bytes
  | otherwise = scriptToAddressBS' net bytes

-- | 'scriptToAddressBS' for a script without a token prefix.
scriptToAddressBS' :: Network -> ByteString -> Either String Address
scriptToAddressBS' net bytes
  | Just a <- standard = Right a
  | otherwise = maybeToEither e . outputAddress net =<< decodeSerial bytes
  where
    e = "Could not decode address"
    n = B.length bytes
    at = BU.unsafeIndex bytes
    segwit = isJust net.bech32Prefix
    hash :: (Serial h) => Int -> Int -> Maybe h
    hash from size = eitherToMaybe (runGetS deserialize (B.take size (B.drop from bytes)))
    standard
      -- OP_DUP OP_HASH160, a push of 20 bytes, OP_EQUALVERIFY OP_CHECKSIG
      | n == 25,
        at 0 == 0x76,
        at 1 == 0xa9,
        at 2 == 0x14,
        at 23 == 0x88,
        at 24 == 0xac =
          PubKeyAddress <$> hash 3 20
      -- OP_HASH160, a push of 20 bytes, OP_EQUAL
      | n == 23, at 0 == 0xa9, at 1 == 0x14, at 22 == 0x87 = ScriptAddress <$> hash 2 20
      -- OP_0 and a push of 20 bytes, or of 32
      | segwit, n == 22, at 0 == 0x00, at 1 == 0x14 = WitnessPubKeyAddress <$> hash 2 20
      | segwit, n == 34, at 0 == 0x00, at 1 == 0x20 = WitnessScriptAddress <$> hash 2 32
      | otherwise = Nothing

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
outputAddress :: Network -> ScriptOutput -> Maybe Address
outputAddress net =
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
    script32 a = guard (hasScript32 net) >> a

-- | Infer the 'Address' that a 'ScriptInput' spends from. It is the address
-- of the public key or of the redeem script that the input carries.
--
-- 'decodeInput' only returns a redeem script in the form 'encodeOutput'
-- writes, so for a decoded input this is the hash of the redeem script bytes
-- of the input. There is no address for a redeem script above
-- 'maxRedeemScriptSize' bytes. On Bitcoin no valid input can carry one. On
-- Bitcoin Cash a valid input can, since May 2025, and this function still
-- gives no address for it: the library keeps one limit on every network.
-- The function does not look at the output being spent, so it is a guess
-- that a caller should confirm against that output when it has it.
inputAddress :: ScriptInput -> Maybe Address
inputAddress =
  \case
    (RegularInput (SpendPKHash _ key)) -> Just $ pubKeyAddr key
    (ScriptHashInput _ rdm) -> eitherToMaybe $ payToScriptAddress rdm
    (NestedWitnessInput rdm) -> eitherToMaybe $ payToScriptAddress rdm
    _ -> Nothing
