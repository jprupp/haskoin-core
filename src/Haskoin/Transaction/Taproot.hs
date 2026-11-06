{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Transaction.Taproot
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Taproot outputs, witnesses and signatures: the script trees and output
-- keys of BIP 341, the witness of a key path or script path spend, the
-- control block, and the digest a Taproot signature signs. For reference
-- see BIPs 340, 341 and 342.
module Haskoin.Transaction.Taproot
  ( -- * Keys
    XOnlyPubKey (..),
    keyParity,

    -- * Script trees
    TapLeafVersion,
    tapscriptLeafVersion,
    MAST (..),
    mastCommitment,
    getMerkleProofs,
    leafHash,
    leafHashBytes,
    checkTapTree,
    TapLeaf (..),
    tapTreeLeaves,
    tapTreeFromLeaves,

    -- * Outputs
    TaprootOutput (..),
    taprootOutputKey,
    taprootOutputSecKey,
    taprootScriptOutput,

    -- * Witnesses
    TaprootWitness (..),
    ScriptPathData (..),
    scriptPathScriptBytes,
    viewTaprootWitness,
    encodeTaprootWitness,
    verifyScriptPathData,
    maxControlBlockNodes,
    encodeControlBlock,
    decodeControlBlock,

    -- * Signatures
    TaprootSignature,
    pattern TaprootSignature,
    taprootSignature,
    isTaprootSigHash,
    taprootSigHash,
    encodeTaprootSig,
    decodeTaprootSig,
  )
where

import Control.Monad (forM_, unless, when, (<=<))
import Crypto.Hash
  ( Digest,
    SHA256,
    digestFromByteString,
    hashFinalize,
    hashUpdate,
    hashUpdates,
  )
import Crypto.Secp256k1
import Data.Aeson
  ( FromJSON (parseJSON),
    ToJSON (toJSON),
    Value (String),
    withText,
  )
import Data.Aeson.Types (Parser, Value)
import Data.Bits ((.&.), (.|.))
import Data.Bool (bool)
import Data.ByteArray qualified as BA
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Bytes.Get (MonadGet, getBytes, runGetS)
import Data.Bytes.Put (MonadPut, putByteString, putWord32le, putWord64le, putWord8, runPutL, runPutS)
import Data.Bytes.Serial (Serial (..), deserialize, serialize)
import Data.Foldable (foldl')
import Data.Maybe (fromMaybe, maybeToList)
import Data.Word (Word32, Word8)
import GHC.Records (HasField (..))
import Haskoin.Crypto.Hash
import Haskoin.Crypto.Keys.Common
import Haskoin.Network.Common (putVarIntBytes)
import Haskoin.Script.Common
import Haskoin.Script.SigHash
import Haskoin.Script.Standard
import Haskoin.Transaction.Common
import Haskoin.Util

{- Keys -}

-- | An x-only pubkey corresponds to the keys @(x,y)@ and @(x, -y)@.  The
-- equality test only checks the x-coordinate.  An x-only pubkey serializes to 32
-- bytes, and reads back as the point with the even y coordinate, as BIP 340
-- defines.
--
-- @since 0.21.0
newtype XOnlyPubKey = XOnlyPubKey {point :: PubKey}
  deriving (Read, Show)

instance Eq XOnlyPubKey where
  XOnlyPubKey k1 == XOnlyPubKey k2 = f k1 == f k2
    where
      f = BS.take 32 . (.get)

instance Marshal Ctx XOnlyPubKey where
  marshalPut ctx (XOnlyPubKey pk) =
    putByteString (exportXOnlyPubKey ctx pk)

  marshalGet ctx =
    maybe (fail "Not an x-only public key") (pure . XOnlyPubKey)
      . importXOnlyPubKey ctx
      =<< getBytes 32

instance MarshalJSON Ctx XOnlyPubKey where
  -- The hex must hold the 32 bytes of the key and nothing else. A longer
  -- value, such as a 33-byte compressed key, is another kind of key.
  unmarshalValue ctx =
    withText "XOnlyPubKey" $ either fail pure . (unmarshal ctx <=< hex)
    where
      hex = maybe (Left "Unable to decode hex") Right . decodeHex

  marshalValue ctx =
    String . encodeHex . marshal ctx

  marshalEncoding ctx =
    hexEncoding . runPutL . marshalPut ctx

-- | The parity of the y coordinate of a key: 0 when it is even, 1 when it
-- is odd. It is the parity bit of a control block.
keyParity :: Ctx -> PubKey -> Word8
keyParity ctx key =
  case BS.unpack . marshal ctx $ PublicKey key True of
    0x02 : _ -> 0x00
    _ -> 0x01

{- Script trees -}

-- | @since 0.21.0
type TapLeafVersion = Word8

-- | The leaf version of a Tapscript, @0xc0@, the only one BIP 342 defines.
tapscriptLeafVersion :: TapLeafVersion
tapscriptLeafVersion = 0xc0

-- | Merklized Abstract Syntax Tree.  This type can represent trees where only a
-- subset of the leaves are known.  Note that the tree is invariant under swapping
-- branches at an internal node.
--
-- A leaf holds its script as opcodes. For a leaf whose bytes are not a list
-- of opcodes, put its hash in the tree: @MASTCommitment (leafHashBytes
-- version bytes)@. 'checkTapTree' tells whether every leaf of a tree can be
-- spent.
--
-- @since 0.21.0
data MAST
  = MASTBranch MAST MAST
  | MASTLeaf TapLeafVersion Script
  | MASTCommitment (Digest SHA256)
  deriving (Eq, Show)

-- | The inclusion proof of every leaf of the tree, depth first: the leaf
-- version, the script, and the hashes of the siblings on the way from the
-- leaf up to the root. This is the order a control block holds them in, the
-- one of @taproot_tree_helper@ in BIP 341 and of @TaprootBuilder::Combine@
-- in Bitcoin Core. A leaf at depth @d@ has a proof of @d@ hashes.
--
-- A proof of more than 'maxControlBlockNodes' hashes cannot be used: no
-- control block may hold it. 'checkTapTree' tells whether a tree has such
-- a leaf.
--
-- @since 0.21.0
getMerkleProofs :: MAST -> [(TapLeafVersion, Script, [Digest SHA256])]
getMerkleProofs = snd . go
  where
    -- The commitment of a subtree with the proofs of its leaves inside
    -- that subtree. Joining two subtrees adds the hash of the sibling at
    -- the end of every proof.
    go = \case
      MASTBranch left right ->
        let (hashL, proofsL) = go left
            (hashR, proofsR) = go right
         in ( hashBranch hashL hashR,
              [(v, s, proof <> [hashR]) | (v, s, proof) <- proofsL]
                <> [(v, s, proof <> [hashL]) | (v, s, proof) <- proofsR]
            )
      MASTLeaf v s -> (leafHash v s, [(v, s, [])])
      MASTCommitment commitment -> (commitment, [])

-- | Calculate the root hash for this tree.
--
-- @since 0.21.0
mastCommitment :: MAST -> Digest SHA256
mastCommitment = \case
  MASTBranch leftBranch rightBranch ->
    hashBranch (mastCommitment leftBranch) (mastCommitment rightBranch)
  MASTLeaf leafVersion leafScript -> leafHash leafVersion leafScript
  MASTCommitment theCommitment -> theCommitment

hashBranch :: Digest SHA256 -> Digest SHA256 -> Digest SHA256
hashBranch hashA hashB =
  hashFinalize $
    hashUpdates
      (initTaggedHash "TapBranch")
      [ min hashA hashB,
        max hashA hashB
      ]

-- | The hash of a leaf of the tree, the tapleaf hash of BIP 341:
-- @hash_TapLeaf(v || compact_size(size of s) || s)@, the tagged hash of the
-- leaf version and the script with its length as a CompactSize.
--
-- Versions up to 1.5.1 wrote the length as a base-128 varint, which is the
-- same byte below 128 only. For a script of 128 bytes or more they gave a
-- leaf hash, and so an output key and an address, that no other software
-- derives. The changelog of the release after 1.5.1 says how to move coins
-- that sit at such an address.
leafHash :: TapLeafVersion -> Script -> Digest SHA256
leafHash leafVersion = leafHashBytes leafVersion . runPutS . serialize

-- | The tapleaf hash of a script given as its bytes, as it is in the
-- witness of a script path spend. Use this for a script that is not a list
-- of opcodes, which a 'Script' cannot hold.
leafHashBytes :: TapLeafVersion -> ByteString -> Digest SHA256
leafHashBytes leafVersion scriptBytes =
  hashFinalize
    . hashUpdate (initTaggedHash "TapLeaf")
    . runPutS
    $ do
      putWord8 leafVersion
      putVarIntBytes scriptBytes

-- | Whether every leaf of a tree can be spent by its script path, as far as
-- the shape of the tree tells. It fails, with the reason, when:
--
-- * a node is deeper than 'maxControlBlockNodes' (128). The control block
--   of a leaf holds one hash per level, and BIP 341 allows at most 128.
--   Bitcoin Core's @TaprootBuilder@ refuses such a tree.
-- * a leaf version is odd or is @0x50@. A control block carries the leaf
--   version in the bits @0xfe@ of its first byte, so an odd version cannot
--   be expressed, and @0x50@ would read as an annex.
--
-- 'taprootOutputKey' and 'taprootScriptOutput' do not make this check: the
-- output of such a tree is well defined, and its other leaves and its key
-- path can still be spent. Check a tree with this function before you give
-- out its address, since a leaf it refuses can never be spent.
checkTapTree :: MAST -> Either String ()
checkTapTree = go (0 :: Int)
  where
    go depth node
      | depth > maxControlBlockNodes =
          Left ("checkTapTree: a node is deeper than " <> show maxControlBlockNodes)
      | otherwise = case node of
          MASTBranch left right -> go (depth + 1) left >> go (depth + 1) right
          MASTLeaf version _
            | odd version -> Left ("checkTapTree: the leaf version " <> show version <> " is odd")
            | version == 0x50 -> Left "checkTapTree: the leaf version 0x50 would read as an annex"
            | otherwise -> Right ()
          MASTCommitment _ -> Right ()

-- | A leaf of a script tree with its depth, as the field
-- @PSBT_OUT_TAP_TREE@ of BIP 371 lists the leaves, depth first
data TapLeaf = TapLeaf
  { depth :: !Word8,
    version :: !TapLeafVersion,
    script :: !Script
  }
  deriving (Eq, Show)

-- | The leaves of a tree, depth first, with their depth. 'Nothing' when a
-- branch of the tree is only known by its commitment, since its leaves are
-- not known, and when a leaf is deeper than 'maxControlBlockNodes' (128):
-- such a leaf can never be spent, @PSBT_OUT_TAP_TREE@ cannot hold it, and
-- 'tapTreeFromLeaves' refuses it.
tapTreeLeaves :: MAST -> Maybe [TapLeaf]
tapTreeLeaves = go (0 :: Int)
  where
    go depth = \case
      MASTBranch l r -> (<>) <$> go (depth + 1) l <*> go (depth + 1) r
      MASTLeaf v s
        | depth > maxControlBlockNodes -> Nothing
        | otherwise -> Just [TapLeaf (fromIntegral depth) v s]
      MASTCommitment _ -> Nothing

-- | The tree whose leaves these are, depth first with their depth, built
-- as @TaprootBuilder@ builds it in Bitcoin Core: two nodes at the same
-- depth join into their parent. 'Nothing' when the leaves do not make one
-- whole tree, or when a depth is above 128.
tapTreeFromLeaves :: [TapLeaf] -> Maybe MAST
tapTreeFromLeaves = go []
  where
    go :: [(Word8, MAST)] -> [TapLeaf] -> Maybe MAST
    go [(0, tree)] [] = Just tree
    go _ [] = Nothing
    go stack (leaf : rest)
      | leaf.depth > 128 = Nothing
      | otherwise = go (merge ((leaf.depth, MASTLeaf leaf.version leaf.script) : stack)) rest
    -- The newest node is first. Two nodes at the same depth become a
    -- branch at the depth above, the older one on the left.
    merge :: [(Word8, MAST)] -> [(Word8, MAST)]
    merge ((d1, right) : (d2, left) : more)
      | d1 == d2 && d1 > 0 = merge ((d1 - 1, MASTBranch left right) : more)
    merge stack = stack

{- Outputs -}

-- | Representation of a full taproot output: the internal key and the
-- script tree, if there is one. Only the x coordinate of the internal key
-- matters, as BIP 341 defines the output from the x-only internal key: a
-- key and its negation give the same output.
--
-- @since 0.21.0
data TaprootOutput = TaprootOutput
  { internalKey :: PubKey,
    mast :: Maybe MAST
  }

-- | The output key of BIP 341: the x-only internal key tweaked with the
-- hash of the internal key and the root of the tree. The parity of its y
-- coordinate is the one a control block of a script path spend carries.
--
-- Two things this function does not do:
--
-- * It does not look at the shape of the tree. A leaf deeper than 128, or
--   with a leaf version a control block cannot carry, gets an output like
--   any other and can never be spent. Run 'checkTapTree' on the tree first.
-- * It calls 'error' when the tweak is not below the order of the curve or
--   gives the point at infinity, which BIP 341 defines as a failure. The
--   tweak is a SHA256 output, so this happens for about one tree in 2^128,
--   and no input is known that reaches it. 'taprootOutputSecKey' returns
--   'Nothing' in the same case.
--
-- @since 0.21.0
taprootOutputKey :: Ctx -> TaprootOutput -> PubKey
taprootOutputKey ctx TaprootOutput {..} =
  fromMaybe keyFail $
    tweak commitment >>= tweakAddXOnlyPubKey ctx internalKey
  where
    commitment =
      taprootCommitment ctx internalKey $
        mastCommitment <$> mast
    keyFail = error "haskoin-core taprootOutputKey: key derivation failed"

-- | The secret key that signs a key path spend of the output of the secret
-- key given: the secret key, negated when its public key has an odd y
-- coordinate, plus the tweak of 'taprootOutputKey'. 'Nothing' in the
-- negligible case where the tweak gives no key.
taprootOutputSecKey :: Ctx -> SecKey -> Maybe MAST -> Maybe SecKey
taprootOutputSecKey ctx secret mast =
  tweak commitment >>= tweakAddXOnlySecKey ctx secret
  where
    commitment =
      taprootCommitment ctx (derivePubKey ctx secret) $
        mastCommitment <$> mast

taprootCommitment :: Ctx -> PubKey -> Maybe (Digest SHA256) -> ByteString
taprootCommitment ctx internalKey merkleRoot =
  BA.convert
    . hashFinalize
    . maybe id (flip hashUpdate) merkleRoot
    . (`hashUpdate` exportXOnlyPubKey ctx internalKey)
    $ initTaggedHash "TapTweak"

-- | The output script of a Taproot output: witness version 1 and the
-- x-only output key of 'taprootOutputKey', whose two caveats apply here
-- too. Check a script tree with 'checkTapTree' before you pay to it.
--
-- @since 0.21.0
taprootScriptOutput :: Ctx -> TaprootOutput -> ScriptOutput
taprootScriptOutput ctx =
  PayWitness 0x01
    . runPutS
    . marshalPut ctx
    . XOnlyPubKey
    . taprootOutputKey ctx

{- Witnesses -}

-- | Comprehension of taproot witness data
--
-- @since 0.21.0
data TaprootWitness
  = -- | A key path spend: the signature, and the annex if there is one
    KeyPathSpend ByteString (Maybe ByteString)
  | ScriptPathSpend ScriptPathData
  deriving (Eq, Show)

-- | A script path spend: the items the script runs on, the script, and
-- the control block that commits the script to the output key.
--
-- @since 0.21.0
data ScriptPathData = ScriptPathData
  { annex :: Maybe ByteString,
    stack :: [ByteString],
    -- | the script as opcodes. It is the empty script when 'opaqueScript'
    -- holds the bytes of a script that is not a list of opcodes.
    script :: Script,
    -- | the parity of the y coordinate of the output key
    extIsOdd :: Bool,
    -- | This value is masked by 0xFE
    leafVersion :: Word8,
    internalKey :: PubKey,
    -- | the Merkle proof of the leaf, leaf to root
    control :: [Digest SHA256],
    -- | the bytes of the script, when they are not the serialization of a
    -- 'Script'. A script path spend can be valid with such bytes: a
    -- Tapscript that holds an @OP_SUCCESSx@ opcode succeeds even if later
    -- bytes do not decode, and a leaf of a version other than @0xc0@ is not
    -- looked at. 'Nothing' for every script that is a list of opcodes, in
    -- which case 'script' holds it.
    opaqueScript :: Maybe ByteString
  }
  deriving (Eq, Show)

-- | The bytes of the script of a script path spend, as they are in the
-- witness: 'opaqueScript' when there is one, the serialization of 'script'
-- otherwise. The leaf hash is taken on these bytes.
scriptPathScriptBytes :: ScriptPathData -> ByteString
scriptPathScriptBytes d = fromMaybe (runPutS (serialize d.script)) d.opaqueScript

-- | The number of nodes a control block may hold at most, the depth of the
-- deepest leaf BIP 341 allows
maxControlBlockNodes :: Int
maxControlBlockNodes = 128

-- | The control block of a script path spend: the leaf version with the
-- parity bit of the output key, the x-only internal key, and the proof
-- of the leaf
encodeControlBlock :: Ctx -> Word8 -> PubKey -> [Digest SHA256] -> ByteString
encodeControlBlock ctx versionAndParity internalKey proof =
  BS.concat (BS.singleton versionAndParity : exportXOnlyPubKey ctx internalKey : map BA.convert proof)

-- | The parts of a control block, which must be 33 bytes plus 32 per node
-- of the proof, with at most 'maxControlBlockNodes' nodes, as BIP 341
-- requires
decodeControlBlock :: Ctx -> ByteString -> Either String (Word8, PubKey, [Digest SHA256])
decodeControlBlock ctx bytes
  | len < 33 || (len - 33) `mod` 32 /= 0 =
      Left ("decodeControlBlock: a control block is 33 bytes plus 32 per node, not " <> show len)
  | nodeCount > maxControlBlockNodes =
      Left ("decodeControlBlock: more than " <> show maxControlBlockNodes <> " nodes")
  | otherwise = do
      internalKey <- maybe (Left "decodeControlBlock: the internal key is not an x-only public key") Right $ importXOnlyPubKey ctx (BS.take 32 (BS.drop 1 bytes))
      proof <- traverse node (chunks (BS.drop 33 bytes))
      return (BS.head bytes, internalKey, proof)
  where
    len = BS.length bytes
    nodeCount = (len - 33) `div` 32
    chunks b
      | BS.null b = []
      | otherwise = BS.take 32 b : chunks (BS.drop 32 b)
    node = maybe (Left "decodeControlBlock: not a hash") Right . digestFromByteString @SHA256

-- | Try to interpret a 'WitnessStack' as taproot witness data, as BIP 341
-- reads it: the last item is the annex when there are at least two items
-- and it starts with @0x50@; then one item left is a key path signature,
-- and more are the stack, the script and the control block. The script is
-- read whatever its bytes are, see 'opaqueScript'. 'Nothing' for an empty
-- witness and for a control block that 'decodeControlBlock' refuses.
--
-- @since 0.21.0
viewTaprootWitness :: Ctx -> WitnessStack -> Maybe TaprootWitness
viewTaprootWitness ctx witnessStack =
  case reverse items of
    [sig] -> Just (KeyPathSpend sig annex)
    controlBytes : scriptBytes : reversedStack -> do
      (v, internalKey, control) <- eitherToMaybe $ decodeControlBlock ctx controlBytes
      -- The script is kept as opcodes when the bytes are exactly the
      -- serialization of a list of opcodes, and as bytes otherwise, so
      -- that the leaf hash is always the hash of the witness bytes.
      let (script, opaqueScript) = case runGetS deserialize scriptBytes of
            Right parsed | runPutS (serialize parsed) == scriptBytes -> (parsed, Nothing)
            _ -> (Script [], Just scriptBytes)
      pure $
        ScriptPathSpend
          ScriptPathData
            { annex,
              stack = reverse reversedStack,
              script,
              extIsOdd = odd v,
              leafVersion = v .&. 0xfe,
              internalKey,
              control,
              opaqueScript
            }
    [] -> Nothing
  where
    (annex, items) = case reverse witnessStack of
      a : rest
        | not (null rest), isAnnex a -> (Just a, reverse rest)
      _ -> (Nothing, witnessStack)

-- | The witness stack of a Taproot spend, in the order of BIP 341: the
-- signature of a key path spend, or the stack, the script and the control
-- block of a script path spend, and then the annex when there is one.
--
-- It fails for a witness that no node reads back as the same spend:
--
-- * an annex that is empty or does not start with @0x50@, which would be
--   read as a signature, a script or a control block;
-- * a proof of more than 'maxControlBlockNodes' hashes;
-- * a leaf version that is odd or is @0x50@, which a control block cannot
--   carry.
--
-- @since 0.21.0
encodeTaprootWitness :: Ctx -> TaprootWitness -> Either String WitnessStack
encodeTaprootWitness ctx = \case
  KeyPathSpend signature annex -> do
    mapM_ checkAnnex annex
    return (signature : maybeToList annex)
  ScriptPathSpend d -> do
    mapM_ checkAnnex d.annex
    when (length d.control > maxControlBlockNodes) $
      Left ("encodeTaprootWitness: a control block holds at most " <> show maxControlBlockNodes <> " nodes")
    when (odd d.leafVersion || d.leafVersion == annexTag) $
      Left ("encodeTaprootWitness: a control block cannot carry the leaf version " <> show d.leafVersion)
    return $
      d.stack
        <> [ scriptPathScriptBytes d,
             encodeControlBlock ctx (d.leafVersion .|. bool 0 1 d.extIsOdd) d.internalKey d.control
           ]
        <> maybeToList d.annex
  where
    checkAnnex annex =
      unless (isAnnex annex) $ Left "encodeTaprootWitness: an annex starts with 0x50"

-- | The first byte of an annex, @ANNEX_TAG@ in Bitcoin Core
annexTag :: Word8
annexTag = 0x50

-- | Whether bytes can be an annex: BIP 341 defines the annex as a last
-- witness item whose first byte is @0x50@
isAnnex :: ByteString -> Bool
isAnnex bytes = case BS.uncons bytes of
  Just (first, _) -> first == annexTag
  Nothing -> False

-- | Verify that the script path spend is valid, except for script execution:
-- the leaf and its proof commit to the output key, with the parity the
-- control block says, and the proof has at most 'maxControlBlockNodes'
-- hashes. The leaf hash is taken on 'scriptPathScriptBytes'.
--
-- @since 0.21.0
verifyScriptPathData ::
  Ctx ->
  -- | Output key
  PubKey ->
  ScriptPathData ->
  Bool
verifyScriptPathData ctx outkey spd = fromMaybe False $ do
  if length spd.control > maxControlBlockNodes
    then Nothing
    else
      tweak commitment
        >>= fmap onComputedKey
          . tweakAddXOnlyPubKey ctx spd.internalKey
  where
    onComputedKey computedKey =
      XOnlyPubKey outkey == XOnlyPubKey computedKey
        && expectedParity == keyParity ctx computedKey
    commitment =
      taprootCommitment ctx spd.internalKey (Just merkleRoot)
    merkleRoot = foldl' hashBranch theLeafHash spd.control
    theLeafHash = leafHashBytes (spd.leafVersion .&. 0xfe) (scriptPathScriptBytes spd)
    expectedParity = bool 0 1 spd.extIsOdd

{- Signatures -}

-- | A Schnorr signature with the hash type it signs: 64 bytes, then the
-- hash type byte unless it is 'sigHashDefault'.
--
-- The hash type is always one that 'isTaprootSigHash' accepts. Build a
-- value with 'taprootSignature' or 'decodeTaprootSig', which check it, and
-- take it apart with the pattern 'TaprootSignature' or with the fields
-- @sig@ and @hash@, as in @signature.hash@. The fields cannot be updated.
data TaprootSignature = MkTaprootSignature !SchnorrSig !SigHash
  deriving (Eq)

instance Show TaprootSignature where
  showsPrec d (MkTaprootSignature s h) =
    showParen (d > 10) $
      showString "TaprootSignature {sig = "
        . shows s
        . showString ", hash = "
        . shows h
        . showString "}"

instance HasField "sig" TaprootSignature SchnorrSig where
  getField (MkTaprootSignature s _) = s

instance HasField "hash" TaprootSignature SigHash where
  getField (MkTaprootSignature _ h) = h

-- | The signature and the hash type of a 'TaprootSignature'. This pattern
-- only matches. 'taprootSignature' builds a value.
pattern TaprootSignature :: SchnorrSig -> SigHash -> TaprootSignature
pattern TaprootSignature s h <- MkTaprootSignature s h

{-# COMPLETE TaprootSignature #-}

-- | A Taproot signature from a Schnorr signature and its hash type. Fails
-- for a hash type that 'isTaprootSigHash' refuses, such as @0x04@,
-- @0x41@ or a value above one byte: every node refuses such a signature,
-- and its bytes could not say the hash type it was made with.
taprootSignature :: SchnorrSig -> SigHash -> Either String TaprootSignature
taprootSignature s h
  | isTaprootSigHash h = Right (MkTaprootSignature s h)
  | otherwise = Left ("taprootSignature: invalid hash type " <> show (fromIntegral h :: Word32))

-- | Whether a hash type is one a Taproot signature may use: the default,
-- @ALL@, @NONE@ and @SINGLE@, the last three with or without
-- @ANYONECANPAY@. Bitcoin Core refuses every other value in
-- @SignatureHashSchnorr@.
isTaprootSigHash :: SigHash -> Bool
isTaprootSigHash sh = sh `elem` [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83]

-- | The bytes of a Taproot signature as they go in a witness: the 64 bytes
-- of the signature, then the hash type byte unless it is 'sigHashDefault'.
-- 'decodeTaprootSig' reads these bytes back to the same value, since a
-- 'TaprootSignature' only holds a hash type that Taproot defines.
encodeTaprootSig :: TaprootSignature -> ByteString
encodeTaprootSig (MkTaprootSignature s h)
  | h == sigHashDefault = s.get
  | otherwise = s.get <> BS.singleton (fromIntegral h)

-- | A Taproot signature from its bytes: 64 bytes sign with
-- 'sigHashDefault', 65 end with a hash type byte that must be one
-- 'isTaprootSigHash' accepts and not zero, as BIP 341 requires
decodeTaprootSig :: ByteString -> Either String TaprootSignature
decodeTaprootSig bytes
  | BS.length bytes == 64 = (`MkTaprootSignature` sigHashDefault) <$> sigOf bytes
  | BS.length bytes == 65 = do
      let sh = fromIntegral (BS.last bytes)
      unless (isTaprootSigHash sh && sh /= sigHashDefault) $
        Left ("decodeTaprootSig: invalid hash type byte " <> show (BS.last bytes))
      (`MkTaprootSignature` sh) <$> sigOf (BS.init bytes)
  | otherwise = Left ("decodeTaprootSig: a signature is 64 or 65 bytes, not " <> show (BS.length bytes))
  where
    sigOf = maybe (Left "decodeTaprootSig: not a Schnorr signature") Right . schnorrSig

-- | The digest a Taproot signature signs, as BIP 341 and BIP 342 define it:
-- the tagged hash of the signature message, which commits to the whole
-- transaction and to the output every input spends, and, for a script path
-- spend, to the leaf. Fails when the hash type is not one of
-- 'isTaprootSigHash', when the input index is out of range, when the
-- spent outputs do not match the inputs, with @SIGHASH_SINGLE@ and no
-- output at the index of the input, or when the annex is empty or does not
-- start with @0x50@: no node takes such an item for an annex, so no node
-- computes that digest.
taprootSigHash ::
  -- | transaction to sign
  Tx ->
  -- | outputs spent, one per input of the transaction, in order
  [TxOut] ->
  -- | index of input being signed
  Int ->
  -- | what to sign
  SigHash ->
  -- | annex of the input, if there is one, with its @0x50@ prefix
  Maybe ByteString ->
  -- | for a script path spend: the leaf hash, and the position of the last
  -- @OP_CODESEPARATOR@ executed, @0xffffffff@ for none
  Maybe (Digest SHA256, Word32) ->
  Either String Hash256
taprootSigHash tx spent i sh annexM leafM = do
  unless (i >= 0 && i < length tx.inputs) $
    Left "taprootSigHash: input index out of range"
  unless (length spent == length tx.inputs) $
    Left "taprootSigHash: one spent output per input is required"
  unless (isTaprootSigHash sh) $
    Left ("taprootSigHash: invalid hash type " <> show (fromIntegral sh :: Word32))
  when (isSigHashSingle sh && i >= length tx.outputs) $
    Left "taprootSigHash: SIGHASH_SINGLE without an output at the input index"
  forM_ annexM $ \annex ->
    unless (isAnnex annex) $ Left "taprootSigHash: an annex starts with 0x50"
  return . taggedHash "TapSighash" . runPutS $ do
    putWord8 0x00 -- the epoch
    putWord8 (fromIntegral sh)
    putWord32le tx.version
    putWord32le tx.locktime
    unless (anyoneCanPay sh) $ do
      serialize $ sha256 (runPutS (mapM_ (serialize . (.outpoint)) tx.inputs))
      serialize $ sha256 (runPutS (mapM_ (putWord64le . (.value)) spent))
      serialize $ sha256 (runPutS (mapM_ (putVarIntBytes . (.script)) spent))
      serialize $ sha256 (runPutS (mapM_ (putWord32le . (.sequence)) tx.inputs))
    unless (isSigHashNone sh || isSigHashSingle sh) $
      serialize $ sha256 (runPutS (mapM_ serialize tx.outputs))
    putWord8 (bool 0 2 (isJust' leafM) .|. bool 0 1 (isJust' annexM))
    if anyoneCanPay sh
      then do
        serialize input.outpoint
        putWord64le coin.value
        putVarIntBytes coin.script
        putWord32le input.sequence
      else putWord32le (fromIntegral i)
    forM_ annexM $ \annex ->
      serialize $ sha256 (runPutS (putVarIntBytes annex))
    when (isSigHashSingle sh) $
      serialize $ sha256 (runPutS (serialize (tx.outputs !! i)))
    forM_ leafM $ \(leaf, codeSeparatorPosition) -> do
      putByteString (BA.convert leaf)
      putWord8 0x00 -- the key version
      putWord32le codeSeparatorPosition
  where
    input = tx.inputs !! i
    coin = spent !! i
    isJust' = maybe False (const True)

-- | The tagged hash of BIP 340: SHA256 of the hash of the tag twice, then
-- the message
taggedHash :: ByteString -> ByteString -> Hash256
taggedHash tag message = sha256 (tagHash <> tagHash <> message)
  where
    tagHash = runPutS (serialize (sha256 tag))
