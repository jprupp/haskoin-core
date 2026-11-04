{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
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
    viewTaprootWitness,
    encodeTaprootWitness,
    verifyScriptPathData,
    maxControlBlockNodes,
    encodeControlBlock,
    decodeControlBlock,

    -- * Signatures
    TaprootSignature (..),
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
import Data.Bytes.VarInt (VarInt (VarInt))
import Data.Foldable (foldl')
import Data.Maybe (fromMaybe, maybeToList)
import Data.Word (Word32, Word8)
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
  unmarshalValue ctx =
    withText "XOnlyPubKey" $ either fail pure . (des <=< hex)
    where
      hex = maybe (Left "Unable to decode hex") Right . decodeHex
      des = runGetS $ marshalGet ctx

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
-- @since 0.21.0
data MAST
  = MASTBranch MAST MAST
  | MASTLeaf TapLeafVersion Script
  | MASTCommitment (Digest SHA256)
  deriving (Eq, Show)

-- | Get the inclusion proofs for the leaves in the tree.  The proof is ordered
-- leaf-to-root.
--
-- @since 0.21.0
getMerkleProofs :: MAST -> [(TapLeafVersion, Script, [Digest SHA256])]
getMerkleProofs = getProofs mempty
  where
    getProofs proof = \case
      MASTBranch branchL branchR ->
        (updateProof proof (mastCommitment branchR) <$> getMerkleProofs branchL)
          <> (updateProof proof (mastCommitment branchL) <$> getMerkleProofs branchR)
      MASTLeaf v s -> [(v, s, proof)]
      MASTCommitment {} -> mempty
    updateProof proofInit branchCommitment (v, s, proofTail) =
      (v, s, reverse $ proofInit <> (branchCommitment : proofTail))

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

-- | The hash of a leaf of the tree, @TapLeaf@ of BIP 341: the tagged hash
-- of the leaf version and the script with its length.
leafHash :: TapLeafVersion -> Script -> Digest SHA256
leafHash leafVersion leafScript =
  hashFinalize
    . hashUpdate (initTaggedHash "TapLeaf")
    . runPutS
    $ do
      serialize leafVersion
      serialize $ VarInt (BS.length scriptBytes)
      putByteString scriptBytes
  where
    scriptBytes = runPutS $ serialize leafScript

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
-- not known.
tapTreeLeaves :: MAST -> Maybe [TapLeaf]
tapTreeLeaves = go 0
  where
    go d = \case
      MASTBranch l r -> (<>) <$> go (d + 1) l <*> go (d + 1) r
      MASTLeaf v s -> Just [TapLeaf d v s]
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

-- | Generate the output script for a taproot output
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
    script :: Script,
    -- | the parity of the y coordinate of the output key
    extIsOdd :: Bool,
    -- | This value is masked by 0xFE
    leafVersion :: Word8,
    internalKey :: PubKey,
    -- | the Merkle proof of the leaf, leaf to root
    control :: [Digest SHA256]
  }
  deriving (Eq, Show)

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
-- and more are the stack, the script and the control block.
--
-- @since 0.21.0
viewTaprootWitness :: Ctx -> WitnessStack -> Maybe TaprootWitness
viewTaprootWitness ctx witnessStack =
  case reverse items of
    [sig] -> Just (KeyPathSpend sig annex)
    controlBytes : scriptBytes : reversedStack -> do
      script <- eitherToMaybe $ runGetS deserialize scriptBytes
      (v, internalKey, control) <- eitherToMaybe $ decodeControlBlock ctx controlBytes
      pure $
        ScriptPathSpend
          ScriptPathData
            { annex,
              stack = reverse reversedStack,
              script,
              extIsOdd = odd v,
              leafVersion = v .&. 0xfe,
              internalKey,
              control
            }
    [] -> Nothing
  where
    (annex, items) = case reverse witnessStack of
      a : rest
        | not (null rest),
          Just (0x50, _) <- BS.uncons a ->
            (Just a, reverse rest)
      _ -> (Nothing, witnessStack)

-- | Transform the high-level representation of taproot witness data into a witness stack
--
-- @since 0.21.0
encodeTaprootWitness :: Ctx -> TaprootWitness -> WitnessStack
encodeTaprootWitness ctx = \case
  KeyPathSpend signature annex -> signature : maybeToList annex
  ScriptPathSpend d ->
    d.stack
      <> [ runPutS (serialize d.script),
           encodeControlBlock ctx (d.leafVersion .|. bool 0 1 d.extIsOdd) d.internalKey d.control
         ]
      <> maybeToList d.annex

-- | Verify that the script path spend is valid, except for script execution:
-- the leaf and its proof commit to the output key, with the parity the
-- control block says.
--
-- @since 0.21.0
verifyScriptPathData ::
  Ctx ->
  -- | Output key
  PubKey ->
  ScriptPathData ->
  Bool
verifyScriptPathData ctx outkey spd = fromMaybe False $ do
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
    theLeafHash = leafHash (spd.leafVersion .&. 0xfe) spd.script
    expectedParity = bool 0 1 spd.extIsOdd

{- Signatures -}

-- | A Schnorr signature with the hash type it signs: 64 bytes, then the
-- hash type byte unless it is 'sigHashDefault'
data TaprootSignature = TaprootSignature
  { sig :: !SchnorrSig,
    hash :: !SigHash
  }
  deriving (Eq, Show)

-- | Whether a hash type is one a Taproot signature may use: the default,
-- @ALL@, @NONE@ and @SINGLE@, the last three with or without
-- @ANYONECANPAY@. Bitcoin Core refuses every other value in
-- @SignatureHashSchnorr@.
isTaprootSigHash :: SigHash -> Bool
isTaprootSigHash sh = sh `elem` [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83]

-- | The bytes of a Taproot signature as they go in a witness: the 64 bytes
-- of the signature, then the hash type byte unless it is 'sigHashDefault'
encodeTaprootSig :: TaprootSignature -> ByteString
encodeTaprootSig s
  | s.hash == sigHashDefault = s.sig.get
  | otherwise = s.sig.get <> BS.singleton (fromIntegral s.hash)

-- | A Taproot signature from its bytes: 64 bytes sign with
-- 'sigHashDefault', 65 end with a hash type byte that must be one
-- 'isTaprootSigHash' accepts and not zero, as BIP 341 requires
decodeTaprootSig :: ByteString -> Either String TaprootSignature
decodeTaprootSig bytes
  | BS.length bytes == 64 = (`TaprootSignature` sigHashDefault) <$> sigOf bytes
  | BS.length bytes == 65 = do
      let sh = fromIntegral (BS.last bytes)
      unless (isTaprootSigHash sh && sh /= sigHashDefault) $
        Left ("decodeTaprootSig: invalid hash type byte " <> show (BS.last bytes))
      (`TaprootSignature` sh) <$> sigOf (BS.init bytes)
  | otherwise = Left ("decodeTaprootSig: a signature is 64 or 65 bytes, not " <> show (BS.length bytes))
  where
    sigOf = maybe (Left "decodeTaprootSig: not a Schnorr signature") Right . schnorrSig

-- | The digest a Taproot signature signs, as BIP 341 and BIP 342 define it:
-- the tagged hash of the signature message, which commits to the whole
-- transaction and to the output every input spends, and, for a script path
-- spend, to the leaf. Fails when the hash type is not one of
-- 'isTaprootSigHash', when the input index is out of range, when the
-- spent outputs do not match the inputs, or with @SIGHASH_SINGLE@ and no
-- output at the index of the input.
taprootSigHash ::
  -- | transaction to sign
  Tx ->
  -- | outputs spent, one per input of the transaction, in order
  [TxOut] ->
  -- | index of input being signed
  Int ->
  -- | what to sign
  SigHash ->
  -- | annex of the input, if there is one
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
