{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Keys.Extended
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- BIP-32 extended keys.
module Haskoin.Crypto.Keys.Extended
  ( -- * Extended Keys
    XPubKey (..),
    XPrvKey (..),
    ChainCode,
    KeyIndex,
    Fingerprint,
    fingerprintToText,
    textToFingerprint,
    DerivationException (..),
    makeXPrvKey,
    deriveXPubKey,
    prvSubKey,
    pubSubKey,
    hardSubKey,
    xPrvIsHard,
    xPubIsHard,
    xPrvChild,
    xPubChild,
    xPubID,
    xPrvID,
    xPubFP,
    xPrvFP,
    xPubAddr,
    xPubWitnessAddr,
    xPubCompatWitnessAddr,
    xPubExport,
    xPrvExport,
    xPubImport,
    xPrvImport,
    xPrvWif,

    -- ** Helper Functions
    prvSubKeys,
    pubSubKeys,
    hardSubKeys,
    deriveAddr,
    deriveWitnessAddr,
    deriveCompatWitnessAddr,
    deriveAddrs,
    deriveWitnessAddrs,
    deriveCompatWitnessAddrs,
    deriveMSAddr,
    deriveMSAddrs,
    cycleIndex,

    -- ** Derivation Paths
    DerivPathI (..),
    AnyDeriv,
    HardDeriv,
    SoftDeriv,
    HardOrAny,
    AnyOrSoft,
    DerivPath,
    HardPath,
    SoftPath,
    Bip32PathIndex (..),
    derivePath,
    derivePubPath,
    toHard,
    toSoft,
    toGeneric,
    (++/),
    pathToStr,
    listToPath,
    pathToList,

    -- *** Derivation Path Parser
    XKey (..),
    ParsedPath (..),
    parsePath,
    parseHard,
    parseSoft,
    applyPath,
    derivePathAddr,
    derivePathAddrs,
    derivePathMSAddr,
    derivePathMSAddrs,
    concatBip32Segments,
  )
where

import Control.Applicative
import Control.DeepSeq
import Control.Exception (Exception, throw)
import Control.Monad (guard, mzero, unless, (<=<))
import Crypto.Secp256k1
import Data.Aeson as Aeson
  ( FromJSON,
    ToJSON (..),
    Value (String),
    parseJSON,
    toJSON,
    withText,
  )
import Data.Aeson.Encoding (Encoding, string, text)
import Data.Aeson.Types (Parser)
import Data.Binary (Binary (get, put))
import Data.Bits (clearBit, setBit, testBit)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get
  ( MonadGet
      ( getByteString,
        getWord32be,
        getWord8
      ),
    runGetS,
  )
import Data.Bytes.Put
  ( MonadPut
      ( putByteString,
        putWord32be,
        putWord8
      ),
    runPutS,
  )
import Data.Bytes.Serial (Serial (..))
import Data.Either (fromRight)
import Data.Hashable (Hashable)
import Data.List (foldl')
import Data.List.Split (splitOn)
import Data.Maybe (fromMaybe)
import Data.Serialize (Serialize (..))
import Data.Serialize qualified as S
import Data.String (IsString, fromString)
import Data.String.Conversions (cs)
import Data.Text qualified as Text
import Data.Typeable (Typeable)
import Data.Word (Word32, Word8)
import GHC.Generics (Generic)
import Haskoin.Address
import Haskoin.Crypto.Hash
import Haskoin.Crypto.Keys.Common
import Haskoin.Crypto.Keys.Extended.Internal
import Haskoin.Network.Data
import Haskoin.Script.Standard
import Haskoin.Util
import Text.Read as Read
  ( Lexeme (Ident, Number, String),
    Read (readPrec),
    lexP,
    parens,
    pfail,
  )
import Text.Read.Lex (numberToInteger)

-- | A derivation exception is thrown in the very unlikely event that a
-- derivation is invalid.
newtype DerivationException = DerivationException String
  deriving (Eq, Read, Show, Typeable, Generic)
  deriving newtype (NFData)

instance Exception DerivationException

-- | Chain code as specified in BIP-32.
type ChainCode = Hash256

-- | Index of key as specified in BIP-32.
type KeyIndex = Word32

-- | Data type representing an extended BIP32 private key. An extended key
-- is a node in a tree of key derivations. It has a depth in the tree, a
-- parent node and an index to differentiate it from other siblings.
data XPrvKey = XPrvKey
  { -- | depth in the tree
    depth :: !Word8,
    -- | fingerprint of parent
    parent :: !Fingerprint,
    -- | derivation index
    index :: !KeyIndex,
    -- | chain code
    chain :: !ChainCode,
    -- | private key of this node
    key :: !SecKey
  }
  deriving (Generic, Eq, Show, Read, NFData, Hashable)

instance Marshal Network XPrvKey where
  marshalGet net = do
    ver <- getWord32be
    unless (ver == net.xPrvPrefix) $
      fail "Get: Invalid version for extended private key"
    XPrvKey
      <$> getWord8
      <*> deserialize
      <*> getWord32be
      <*> deserialize
      <*> getPadPrvKey

  marshalPut net k = do
    putWord32be net.xPrvPrefix
    putWord8 k.depth
    serialize k.parent
    putWord32be k.index
    serialize $ k.chain
    putPadPrvKey k.key

instance MarshalJSON Network XPrvKey where
  marshalValue net = Aeson.String . xPrvExport net

  marshalEncoding net = text . xPrvExport net

  unmarshalValue net =
    withText "XPrvKey" $ \t ->
      case xPrvImport net t of
        Nothing -> fail "could not read xprv"
        Just x -> return x

-- | Data type representing an extended BIP32 public key.
data XPubKey = XPubKey
  { -- | depth in the tree
    depth :: !Word8,
    -- | fingerprint of parent
    parent :: !Fingerprint,
    -- | derivation index
    index :: !KeyIndex,
    -- | chain code
    chain :: !ChainCode,
    -- | public key of this node
    key :: !PubKey
  }
  deriving (Generic, Eq, Show, Read, Hashable, NFData)

instance Marshal (Network, Ctx) XPubKey where
  marshalGet (net, ctx) = do
    ver <- getWord32be
    unless (ver == net.xPubPrefix) $
      fail "Get: Invalid version for extended public key"
    XPubKey
      <$> getWord8
      <*> deserialize
      <*> getWord32be
      <*> deserialize
      <*> ((\PublicKey {point} -> point) <$> marshalGet ctx)

  marshalPut (net, ctx) k = do
    putWord32be net.xPubPrefix
    putWord8 k.depth
    serialize k.parent
    putWord32be k.index
    serialize k.chain
    marshalPut ctx $ wrapPubKey True k.key

instance MarshalJSON (Network, Ctx) XPubKey where
  unmarshalValue (net, ctx) =
    withText "XPubKey" $ \t ->
      case xPubImport net ctx t of
        Nothing -> fail "could not read xpub"
        Just x -> return x

  marshalValue (net, ctx) = Aeson.String . xPubExport net ctx

  marshalEncoding (net, ctx) = text . xPubExport net ctx

-- | Build a BIP32 compatible extended private key from a bytestring. This will
-- produce a root node (@depth=0@ and @parent=0@).
makeXPrvKey :: ByteString -> XPrvKey
makeXPrvKey bs =
  XPrvKey 0 (Fingerprint 0) 0 c k
  where
    (p, c) = split512 $ hmac512 "Bitcoin seed" bs
    k = fromMaybe err (secKey (runPutS (serialize p)))
    err = throw $ DerivationException "Invalid seed"

-- | Derive an extended public key from an extended private key. This function
-- will preserve the depth, parent, index and chaincode fields of the extended
-- private keys.
deriveXPubKey :: Ctx -> XPrvKey -> XPubKey
deriveXPubKey ctx (XPrvKey d p i c k) = XPubKey d p i c (derivePubKey ctx k)

-- | Compute a private, soft child key derivation. A private soft derivation
-- will allow the equivalent extended public key to derive the public key for
-- this child. Given a parent key /m/ and a derivation index /i/, this function
-- will compute /m\/i/.
--
-- Soft derivations allow for more flexibility such as read-only wallets.
-- However, care must be taken not the leak both the parent extended public key
-- and one of the extended child private keys as this would compromise the
-- extended parent private key.
prvSubKey ::
  Ctx ->
  -- | extended parent private key
  XPrvKey ->
  -- | child derivation index
  KeyIndex ->
  -- | extended child private key
  XPrvKey
prvSubKey ctx xkey child
  | child >= 0 && child < 0x80000000 =
      XPrvKey (xkey.depth + 1) (xPrvFP ctx xkey) child c k
  | otherwise = error "Invalid child derivation index"
  where
    pK = (deriveXPubKey ctx xkey).key
    m = B.append (exportPubKey ctx True pK) (runPutS (serialize child))
    (a, c) = split512 $ hmac512 (runPutS $ serialize xkey.chain) m
    k = fromMaybe err $ tweakSecKey ctx xkey.key a
    err = throw $ DerivationException "Invalid prvSubKey derivation"

-- | Compute a public, soft child key derivation. Given a parent key /M/
-- and a derivation index /i/, this function will compute /M\/i/.
pubSubKey ::
  Ctx ->
  -- | extended parent public key
  XPubKey ->
  -- | child derivation index
  KeyIndex ->
  -- | extended child public key
  XPubKey
pubSubKey ctx xKey child
  | child >= 0 && child < 0x80000000 =
      XPubKey (xKey.depth + 1) (xPubFP ctx xKey) child c pK
  | otherwise = error "Invalid child derivation index"
  where
    m = B.append (exportPubKey ctx True xKey.key) (runPutS $ serialize child)
    (a, c) = split512 $ hmac512 (runPutS $ serialize xKey.chain) m
    pK = fromMaybe err $ tweakPubKey ctx xKey.key a
    err = throw $ DerivationException "Invalid pubSubKey derivation"

-- | Compute a hard child key derivation. Hard derivations can only be computed
-- for private keys. Hard derivations do not allow the parent public key to
-- derive the child public keys. However, they are safer as a breach of the
-- parent public key and child private keys does not lead to a breach of the
-- parent private key. Given a parent key /m/ and a derivation index /i/, this
-- function will compute /m\/i'/.
hardSubKey ::
  Ctx ->
  -- | extended parent private key
  XPrvKey ->
  -- | child derivation index
  KeyIndex ->
  -- | extended child private key
  XPrvKey
hardSubKey ctx xkey child
  | child >= 0 && child < 0x80000000 =
      XPrvKey (xkey.depth + 1) (xPrvFP ctx xkey) i c k
  | otherwise = error "Invalid child derivation index"
  where
    i = setBit child 31
    m = B.append (bsPadPrvKey xkey.key) (runPutS $ serialize i)
    (a, c) = split512 $ hmac512 (runPutS $ serialize xkey.chain) m
    k = fromMaybe err $ tweakSecKey ctx xkey.key a
    err = throw $ DerivationException "Invalid hardSubKey derivation"

-- | Returns true if the extended private key was derived through a hard
-- derivation.
xPrvIsHard :: XPrvKey -> Bool
xPrvIsHard k = testBit k.index 31

-- | Returns true if the extended public key was derived through a hard
-- derivation.
xPubIsHard :: XPubKey -> Bool
xPubIsHard k = testBit k.index 31

-- | Returns the derivation index of this extended private key without the hard
-- bit set.
xPrvChild :: XPrvKey -> KeyIndex
xPrvChild k = clearBit k.index 31

-- | Returns the derivation index of this extended public key without the hard
-- bit set.
xPubChild :: XPubKey -> KeyIndex
xPubChild k = clearBit k.index 31

-- | Computes the key identifier of an extended private key.
xPrvID :: Ctx -> XPrvKey -> Hash160
xPrvID ctx = xPubID ctx . deriveXPubKey ctx

-- | Computes the key identifier of an extended public key.
xPubID :: Ctx -> XPubKey -> Hash160
xPubID ctx =
  ripemd160
    . runPutS
    . serialize
    . sha256
    . exportPubKey ctx True
    . (.key)

-- | Computes the key fingerprint of an extended private key.
xPrvFP :: Ctx -> XPrvKey -> Fingerprint
xPrvFP ctx =
  fromRight err
    . runGetS deserialize
    . B.take 4
    . runPutS
    . serialize
    . xPrvID ctx
  where
    err = error "Could not decode xPrvFP"

-- | Computes the key fingerprint of an extended public key.
xPubFP :: Ctx -> XPubKey -> Fingerprint
xPubFP ctx =
  fromRight err
    . runGetS deserialize
    . B.take 4
    . runPutS
    . serialize
    . xPubID ctx
  where
    err = error "Could not decode xPubFP"

-- | Compute a standard P2PKH address for an extended public key.
xPubAddr :: Ctx -> XPubKey -> Address
xPubAddr ctx xkey = pubKeyAddr ctx (wrapPubKey True xkey.key)

-- | Compute a SegWit P2WPKH address for an extended public key. Extended
-- public keys are always compressed, so the address always exists.
xPubWitnessAddr :: Ctx -> XPubKey -> Address
xPubWitnessAddr ctx xkey = p2wpkhAddr (xPubKeyHash ctx xkey)

-- | Compute a backwards-compatible SegWit P2SH-P2WPKH address for an extended
-- public key. Extended public keys are always compressed, so the address
-- always exists.
xPubCompatWitnessAddr :: Ctx -> XPubKey -> Address
xPubCompatWitnessAddr ctx xkey =
  payToScriptAddress ctx (PayWitnessPKHash (xPubKeyHash ctx xkey))

-- | HASH160 of the compressed public key of an extended public key.
xPubKeyHash :: Ctx -> XPubKey -> Hash160
xPubKeyHash ctx xkey = addressHash (marshal ctx (wrapPubKey True xkey.key))

-- | Exports an extended private key to the BIP32 key export format ('Base58').
xPrvExport :: Network -> XPrvKey -> Base58
xPrvExport net = encodeBase58Check . marshal net

-- | Exports an extended public key to the BIP32 key export format ('Base58').
xPubExport :: Network -> Ctx -> XPubKey -> Base58
xPubExport net ctx = encodeBase58Check . marshal (net, ctx)

-- | Decodes a BIP32 encoded extended private key. This function will fail if
-- invalid base 58 characters are detected or if the checksum fails.
xPrvImport :: Network -> Base58 -> Maybe XPrvKey
xPrvImport net =
  eitherToMaybe . unmarshal net <=< decodeBase58Check

-- | Decodes a BIP32 encoded extended public key. This function will fail if
-- invalid base 58 characters are detected or if the checksum fails.
xPubImport :: Network -> Ctx -> Base58 -> Maybe XPubKey
xPubImport net ctx =
  eitherToMaybe . unmarshal (net, ctx) <=< decodeBase58Check

-- | Export an extended private key to WIF (Wallet Import Format).
xPrvWif :: Network -> XPrvKey -> Base58
xPrvWif net xkey = toWif net (wrapSecKey True xkey.key)

{- Derivation helpers -}

-- | Cyclic list of all private soft child key derivations of a parent key
-- starting from an offset index.
prvSubKeys :: Ctx -> XPrvKey -> KeyIndex -> [(XPrvKey, KeyIndex)]
prvSubKeys ctx k = map (\i -> (prvSubKey ctx k i, i)) . cycleIndex

-- | Cyclic list of all public soft child key derivations of a parent key
-- starting from an offset index.
pubSubKeys :: Ctx -> XPubKey -> KeyIndex -> [(XPubKey, KeyIndex)]
pubSubKeys ctx k = map (\i -> (pubSubKey ctx k i, i)) . cycleIndex

-- | Cyclic list of all hard child key derivations of a parent key starting
-- from an offset index.
hardSubKeys :: Ctx -> XPrvKey -> KeyIndex -> [(XPrvKey, KeyIndex)]
hardSubKeys ctx k = map (\i -> (hardSubKey ctx k i, i)) . cycleIndex

-- | Derive a standard address from an extended public key and an index.
deriveAddr :: Ctx -> XPubKey -> KeyIndex -> (Address, PubKey)
deriveAddr ctx k i =
  (xPubAddr ctx key, key.key)
  where
    key = pubSubKey ctx k i

-- | Derive a SegWit P2WPKH address from an extended public key and an index.
deriveWitnessAddr :: Ctx -> XPubKey -> KeyIndex -> (Address, PubKey)
deriveWitnessAddr ctx k i =
  (xPubWitnessAddr ctx key, key.key)
  where
    key = pubSubKey ctx k i

-- | Derive a backwards-compatible SegWit P2SH-P2WPKH address from an extended
-- public key and an index.
deriveCompatWitnessAddr :: Ctx -> XPubKey -> KeyIndex -> (Address, PubKey)
deriveCompatWitnessAddr ctx k i =
  (xPubCompatWitnessAddr ctx key, key.key)
  where
    key = pubSubKey ctx k i

-- | Cyclic list of all addresses derived from a public key starting from an
-- offset index.
deriveAddrs :: Ctx -> XPubKey -> KeyIndex -> [(Address, PubKey, KeyIndex)]
deriveAddrs ctx k =
  map f . cycleIndex
  where
    f i = let (a, key) = deriveAddr ctx k i in (a, key, i)

-- | Cyclic list of all SegWit P2WPKH addresses derived from a public key
-- starting from an offset index.
deriveWitnessAddrs ::
  Ctx -> XPubKey -> KeyIndex -> [(Address, PubKey, KeyIndex)]
deriveWitnessAddrs ctx k =
  map f . cycleIndex
  where
    f i = let (a, key) = deriveWitnessAddr ctx k i in (a, key, i)

-- | Cyclic list of all backwards-compatible SegWit P2SH-P2WPKH addresses
-- derived from a public key starting from an offset index.
deriveCompatWitnessAddrs ::
  Ctx -> XPubKey -> KeyIndex -> [(Address, PubKey, KeyIndex)]
deriveCompatWitnessAddrs ctx k =
  map f . cycleIndex
  where
    f i = let (a, key) = deriveCompatWitnessAddr ctx k i in (a, key, i)

-- | Derive a multisig address from a list of public keys, the number of
-- required signatures /m/ and a derivation index. The derivation type is a
-- public, soft derivation.
deriveMSAddr ::
  Ctx -> [XPubKey] -> Int -> KeyIndex -> (Address, RedeemScript)
deriveMSAddr ctx keys m i = (payToScriptAddress ctx rdm, rdm)
  where
    rdm = sortMulSig ctx $ PayMulSig k m
    k = map (wrapPubKey True . (.key) . flip (pubSubKey ctx) i) keys

-- | Cyclic list of all multisig addresses derived from a list of public keys,
-- a number of required signatures /m/ and starting from an offset index. The
-- derivation type is a public, soft derivation.
deriveMSAddrs ::
  Ctx ->
  [XPubKey] ->
  Int ->
  KeyIndex ->
  [(Address, RedeemScript, KeyIndex)]
deriveMSAddrs ctx keys m = map f . cycleIndex
  where
    f i =
      let (a, rdm) = deriveMSAddr ctx keys m i
       in (a, rdm, i)

-- | Helper function to go through derivation indices.
cycleIndex :: KeyIndex -> [KeyIndex]
cycleIndex i
  | i == 0 = cycle [0 .. 0x7fffffff]
  | i < 0x80000000 = cycle $ [i .. 0x7fffffff] ++ [0 .. (i - 1)]
  | otherwise = error $ "cycleIndex: invalid index " ++ show i

{- Derivation Paths -}

-- | Phantom type signaling a hardened derivation path that can only be computed
-- from private extended key.
data HardDeriv deriving (Generic, NFData)

-- | Phantom type signaling no knowledge about derivation path: can be hardened or not.
data AnyDeriv deriving (Generic, NFData)

-- | Phantom type signaling derivation path including only non-hardened paths
-- that can be computed from an extended public key.
data SoftDeriv deriving (Generic, NFData)

-- | Hardened derivation path. Can be computed from extended private key only.
type HardPath = DerivPathI HardDeriv

-- | Any derivation path.
type DerivPath = DerivPathI AnyDeriv

-- | Non-hardened derivation path can be computed from extended public key.
type SoftPath = DerivPathI SoftDeriv

-- | Helper class to perform validations on a hardened derivation path.
class HardOrAny a

instance HardOrAny HardDeriv

instance HardOrAny AnyDeriv

-- | Helper class to perform validations on a non-hardened derivation path.
class AnyOrSoft a

instance AnyOrSoft AnyDeriv

instance AnyOrSoft SoftDeriv

-- | Data type representing a derivation path. Two constructors are provided
-- for specifying soft or hard derivations. The path /\/0\/1'\/2/ for example can be
-- expressed as @'Deriv' :\/ 0 :| 1 :\/ 2@. The 'HardOrAny' and 'AnyOrSoft' type
-- classes are used to constrain the valid values for the phantom type /t/. If
-- you mix hard '(:|)' and soft '(:\/)' paths, the only valid type for /t/ is 'AnyDeriv'.
-- Otherwise, /t/ can be 'HardDeriv' if you only have hard derivation or 'SoftDeriv'
-- if you only have soft derivations.
--
-- Using this type is as easy as writing the required derivation like in these
-- example:
--
-- > Deriv :/ 0 :/ 1 :/ 2 :: SoftPath
-- > Deriv :| 0 :| 1 :| 2 :: HardPath
-- > Deriv :| 0 :/ 1 :/ 2 :: DerivPath
data DerivPathI t where
  (:|) :: (HardOrAny t) => !(DerivPathI t) -> !KeyIndex -> DerivPathI t
  (:/) :: (AnyOrSoft t) => !(DerivPathI t) -> !KeyIndex -> DerivPathI t
  Deriv :: DerivPathI t

instance NFData (DerivPathI t) where
  rnf (a :| b) = rnf a `seq` rnf b
  rnf (a :/ b) = rnf a `seq` rnf b
  rnf Deriv = ()

instance Eq (DerivPathI t) where
  (nextA :| iA) == (nextB :| iB) = iA == iB && nextA == nextB
  (nextA :/ iA) == (nextB :/ iB) = iA == iB && nextA == nextB
  Deriv == Deriv = True
  _ == _ = False

instance Ord (DerivPathI t) where
  -- Same hardness on each side
  (nextA :| iA) `compare` (nextB :| iB) =
    if nextA == nextB then iA `compare` iB else nextA `compare` nextB
  (nextA :/ iA) `compare` (nextB :/ iB) =
    if nextA == nextB then iA `compare` iB else nextA `compare` nextB
  -- Different hardness: hard paths are LT soft paths
  (nextA :/ _iA) `compare` (nextB :| _iB) =
    if nextA == nextB then LT else nextA `compare` nextB
  (nextA :| _iA) `compare` (nextB :/ _iB) =
    if nextA == nextB then GT else nextA `compare` nextB
  Deriv `compare` Deriv = EQ
  Deriv `compare` _ = LT
  _ `compare` Deriv = GT

instance Serial DerivPath where
  deserialize = listToPath <$> getList getWord32be
  serialize = putList putWord32be . pathToList

instance Serialize DerivPath where
  put = serialize
  get = deserialize

instance Binary DerivPath where
  put = serialize
  get = deserialize

instance Serial HardPath where
  deserialize =
    maybe
      (fail "Could not decode hard path")
      return
      . toHard
      . listToPath
      =<< getList getWord32be
  serialize = putList putWord32be . pathToList

instance Serialize HardPath where
  put = serialize
  get = deserialize

instance Binary HardPath where
  put = serialize
  get = deserialize

instance Serial SoftPath where
  deserialize =
    maybe
      (fail "Could not decode soft path")
      return
      . toSoft
      . listToPath
      =<< getList getWord32be
  serialize = putList putWord32be . pathToList

instance Serialize SoftPath where
  put = serialize
  get = deserialize

instance Binary SoftPath where
  put = serialize
  get = deserialize

-- | Get a list of derivation indices from a derivation path.
pathToList :: DerivPathI t -> [KeyIndex]
pathToList =
  reverse . go
  where
    go (next :| i) = setBit i 31 : go next
    go (next :/ i) = i : go next
    go _ = []

-- | Convert a list of derivation indices to a derivation path.
listToPath :: [KeyIndex] -> DerivPath
listToPath =
  go . reverse
  where
    go (i : is)
      | testBit i 31 = go is :| clearBit i 31
      | otherwise = go is :/ i
    go [] = Deriv

-- | Convert a derivation path to a human-readable string.
pathToStr :: DerivPathI t -> String
pathToStr p =
  case p of
    next :| i -> concat [pathToStr next, "/", show i, "'"]
    next :/ i -> concat [pathToStr next, "/", show i]
    Deriv -> ""

-- | Turn a derivation path into a hard derivation path. Will fail if the path
-- contains soft derivations.
toHard :: DerivPathI t -> Maybe HardPath
toHard p = case p of
  next :| i -> (:| i) <$> toHard next
  Deriv -> Just Deriv
  _ -> Nothing

-- | Turn a derivation path into a soft derivation path. Will fail if the path
-- has hard derivations.
toSoft :: DerivPathI t -> Maybe SoftPath
toSoft p = case p of
  next :/ i -> (:/ i) <$> toSoft next
  Deriv -> Just Deriv
  _ -> Nothing

-- | Make a derivation path generic.
toGeneric :: DerivPathI t -> DerivPath
toGeneric p = case p of
  next :/ i -> toGeneric next :/ i
  next :| i -> toGeneric next :| i
  Deriv -> Deriv

-- | Append two derivation paths together. The result will be a mixed
-- derivation path.
(++/) :: DerivPathI t1 -> DerivPathI t2 -> DerivPath
(++/) p1 p2 =
  go id (toGeneric p2) $ toGeneric p1
  where
    go f p = case p of
      next :/ i -> go (f . (:/ i)) $ toGeneric next
      next :| i -> go (f . (:| i)) $ toGeneric next
      _ -> f

-- | Derive a private key from a derivation path
derivePath :: Ctx -> DerivPathI t -> XPrvKey -> XPrvKey
derivePath ctx = go id
  where
    -- Build the full derivation function starting from the end
    go f p = case p of
      next :| i -> go (f . flip (hardSubKey ctx) i) next
      next :/ i -> go (f . flip (prvSubKey ctx) i) next
      _ -> f

-- | Derive a public key from a soft derivation path
derivePubPath :: Ctx -> SoftPath -> XPubKey -> XPubKey
derivePubPath ctx = go id
  where
    -- Build the full derivation function starting from the end
    go f p = case p of
      next :/ i -> go (f . flip (pubSubKey ctx) i) next
      _ -> f

instance Show DerivPath where
  showsPrec d p =
    showParen (d > 10) $
      showString "DerivPath " . shows (pathToStr p)

instance Read DerivPath where
  readPrec = parens $ do
    Ident "DerivPath" <- lexP
    Read.String str <- lexP
    maybe pfail (return . (.get)) (parsePath str)

instance Show HardPath where
  showsPrec d p =
    showParen (d > 10) $
      showString "HardPath " . shows (pathToStr p)

instance Read HardPath where
  readPrec = parens $ do
    Ident "HardPath" <- lexP
    Read.String str <- lexP
    maybe pfail return $ parseHard str

instance Show SoftPath where
  showsPrec d p =
    showParen (d > 10) $
      showString "SoftPath " . shows (pathToStr p)

instance Read SoftPath where
  readPrec = parens $ do
    Ident "SoftPath" <- lexP
    Read.String str <- lexP
    maybe pfail return $ parseSoft str

instance IsString ParsedPath where
  fromString =
    fromMaybe e . parsePath
    where
      e = error "Could not parse derivation path"

instance IsString DerivPath where
  fromString =
    (.get) . fromMaybe e . parsePath
    where
      e = error "Could not parse derivation path"

instance IsString HardPath where
  fromString =
    fromMaybe e . parseHard
    where
      e = error "Could not parse hard derivation path"

instance IsString SoftPath where
  fromString =
    fromMaybe e . parseSoft
    where
      e = error "Could not parse soft derivation path"

instance FromJSON ParsedPath where
  parseJSON = withText "ParsedPath" $ \str -> case parsePath $ cs str of
    Just p -> return p
    _ -> mzero

instance FromJSON DerivPath where
  parseJSON = withText "DerivPath" $ \str -> case parsePath $ cs str of
    Just p -> return p.get
    _ -> mzero

instance FromJSON HardPath where
  parseJSON = withText "HardPath" $ \str -> case parseHard $ cs str of
    Just p -> return p
    _ -> mzero

instance FromJSON SoftPath where
  parseJSON = withText "SoftPath" $ \str -> case parseSoft $ cs str of
    Just p -> return p
    _ -> mzero

instance ToJSON (DerivPathI t) where
  toJSON = Aeson.String . cs . pathToStr
  toEncoding = string . pathToStr

instance ToJSON ParsedPath where
  toJSON (ParsedPrv p) = Aeson.String . cs . ("m" ++) . pathToStr $ p
  toJSON (ParsedPub p) = Aeson.String . cs . ("M" ++) . pathToStr $ p
  toJSON (ParsedEmpty p) = Aeson.String . cs . ("" ++) . pathToStr $ p
  toEncoding (ParsedPrv p) = text . cs . ("m" ++) . pathToStr $ p
  toEncoding (ParsedPub p) = text . cs . ("M" ++) . pathToStr $ p
  toEncoding (ParsedEmpty p) = text . cs . ("" ++) . pathToStr $ p

{- Parsing derivation paths of the form m/1/2'/3 or M/1/2'/3 -}

-- | Type for parsing derivation paths of the form /m\/1\/2'\/3/ or
-- /M\/1\/2'\/3/.
data ParsedPath
  = ParsedPrv {get :: !DerivPath}
  | ParsedPub {get :: !DerivPath}
  | ParsedEmpty {get :: !DerivPath}
  deriving (Eq, Generic, NFData)

instance Show ParsedPath where
  showsPrec d p = showParen (d > 10) $ showString "ParsedPath " . shows f
    where
      f =
        case p of
          ParsedPrv d' -> "m" <> pathToStr d'
          ParsedPub d' -> "M" <> pathToStr d'
          ParsedEmpty d' -> pathToStr d'

instance Read ParsedPath where
  readPrec = parens $ do
    Ident "ParsedPath" <- lexP
    Read.String str <- lexP
    maybe pfail return $ parsePath str

-- | Parse derivation path string for extended key.
-- Forms: /m\/0'\/2/, /M\/2\/3\/4/.
parsePath :: String -> Maybe ParsedPath
parsePath str = do
  res <- concatBip32Segments <$> mapM parseBip32PathIndex xs
  case x of
    "m" -> Just $ ParsedPrv res
    "M" -> Just $ ParsedPub res
    "" -> Just $ ParsedEmpty res
    _ -> Nothing
  where
    (x : xs) = splitOn "/" str

-- | Concatenate derivation path indices into a derivation path.
concatBip32Segments :: [Bip32PathIndex] -> DerivPath
concatBip32Segments = foldl' appendBip32Segment Deriv

-- | Append an extra derivation path index element into an existing path.
appendBip32Segment :: DerivPath -> Bip32PathIndex -> DerivPath
appendBip32Segment d (Bip32SoftIndex i) = d :/ i
appendBip32Segment d (Bip32HardIndex i) = d :| i

-- | Parse a BIP32 derivation path index element from a string.
parseBip32PathIndex :: String -> Maybe Bip32PathIndex
parseBip32PathIndex segment = case reads segment of
  [(i, "")] -> guard (is31Bit i) >> return (Bip32SoftIndex i)
  [(i, "'")] -> guard (is31Bit i) >> return (Bip32HardIndex i)
  _ -> Nothing

-- | Type for BIP32 path index element.
data Bip32PathIndex
  = Bip32HardIndex KeyIndex
  | Bip32SoftIndex KeyIndex
  deriving (Eq, Generic, NFData)

instance Show Bip32PathIndex where
  showsPrec d (Bip32HardIndex i) =
    showParen (d > 10) $
      showString "Bip32HardIndex " . shows i
  showsPrec d (Bip32SoftIndex i) =
    showParen (d > 10) $
      showString "Bip32SoftIndex " . shows i

instance Read Bip32PathIndex where
  readPrec = h <|> s
    where
      h =
        parens $ do
          Ident "Bip32HardIndex" <- lexP
          Number n <- lexP
          maybe
            pfail
            (return . Bip32HardIndex . fromIntegral)
            (numberToInteger n)
      s =
        parens $ do
          Ident "Bip32SoftIndex" <- lexP
          Number n <- lexP
          maybe
            pfail
            (return . Bip32SoftIndex . fromIntegral)
            (numberToInteger n)

-- | Test whether the number could be a valid BIP32 derivation index.
is31Bit :: (Integral a) => a -> Bool
is31Bit i = i >= 0 && i < 0x80000000

-- | Helper function to parse a hard path.
parseHard :: String -> Maybe HardPath
parseHard = toHard . (.get) <=< parsePath

-- | Helper function to parse a soft path.
parseSoft :: String -> Maybe SoftPath
parseSoft = toSoft . (.get) <=< parsePath

-- | Data type representing a private or public key with its respective network.
data XKey
  = XPrv
      { xprv :: !XPrvKey,
        net :: !Network
      }
  | XPub
      { xpub :: !XPubKey,
        net :: !Network
      }
  deriving (Show, Read, Eq, Generic, NFData)

-- | Apply a parsed path to an extended key to derive the new key defined in the
-- path. If the path starts with /m/, a private key will be returned and if the
-- path starts with /M/, a public key will be returned. Private derivations on a
-- public key, and public derivations with a hard segment, return an error
-- value.
applyPath :: Ctx -> ParsedPath -> XKey -> Either String XKey
applyPath ctx path key =
  case (path, key) of
    (ParsedPrv _, XPrv k n) -> return $ XPrv (derivPrvF k) n
    (ParsedPrv _, XPub {}) -> Left "applyPath: Invalid public key"
    (ParsedPub _, XPrv k n) -> return $ XPub (deriveXPubKey ctx (derivPrvF k)) n
    (ParsedPub _, XPub k n) -> derivPubFE >>= \f -> return $ XPub (f k) n
    -- For empty parsed paths, we take a hint from the provided key
    (ParsedEmpty _, XPrv k n) -> return $ XPrv (derivPrvF k) n
    (ParsedEmpty _, XPub k n) -> derivPubFE >>= \f -> return $ XPub (f k) n
  where
    derivPrvF = goPrv id path.get
    derivPubFE = goPubE id path.get
    -- Build the full private derivation function starting from the end
    goPrv f p =
      case p of
        next :| i -> goPrv (f . flip (hardSubKey ctx) i) next
        next :/ i -> goPrv (f . flip (prvSubKey ctx) i) next
        Deriv -> f
    -- Build the full public derivation function starting from the end
    goPubE f p =
      case p of
        next :/ i -> goPubE (f . flip (pubSubKey ctx) i) next
        Deriv -> Right f
        _ -> Left "applyPath: Invalid hard derivation"

{- Helpers for derivation paths and addresses -}

-- | Derive an address from a given parent path.
derivePathAddr :: Ctx -> XPubKey -> SoftPath -> KeyIndex -> (Address, PubKey)
derivePathAddr ctx key path = deriveAddr ctx (derivePubPath ctx path key)

-- | Cyclic list of all addresses derived from a given parent path and starting
-- from the given offset index.
derivePathAddrs ::
  Ctx -> XPubKey -> SoftPath -> KeyIndex -> [(Address, PubKey, KeyIndex)]
derivePathAddrs ctx key path = deriveAddrs ctx (derivePubPath ctx path key)

-- | Derive a multisig address from a given parent path. The number of required
-- signatures (m in m of n) is also needed.
derivePathMSAddr ::
  Ctx ->
  [XPubKey] ->
  SoftPath ->
  Int ->
  KeyIndex ->
  (Address, RedeemScript)
derivePathMSAddr ctx keys path =
  deriveMSAddr ctx $ map (derivePubPath ctx path) keys

-- | Cyclic list of all multisig addresses derived from a given parent path and
-- starting from the given offset index. The number of required signatures
-- (m in m of n) is also needed.
derivePathMSAddrs ::
  Ctx ->
  [XPubKey] ->
  SoftPath ->
  Int ->
  KeyIndex ->
  [(Address, RedeemScript, KeyIndex)]
derivePathMSAddrs ctx keys path =
  deriveMSAddrs ctx $ map (derivePubPath ctx path) keys

{- Utilities for extended keys -}

-- | De-serialize HDW-specific private key.
getPadPrvKey :: (MonadGet m) => m SecKey
getPadPrvKey = do
  pad <- getWord8
  unless (pad == 0x00) $ fail "Private key must be padded with 0x00"
  bs <- getByteString 32
  case secKey bs of
    Nothing -> fail $ "Could not decode secret key: " ++ cs (encodeHex bs)
    Just x -> return x

-- | Serialize HDW-specific private key.
putPadPrvKey :: (MonadPut m) => SecKey -> m ()
putPadPrvKey p = putWord8 0x00 >> putByteString p.get

bsPadPrvKey :: SecKey -> ByteString
bsPadPrvKey = runPutS . putPadPrvKey
