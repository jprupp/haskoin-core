{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Util.Arbitrary.Spelling
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Signed transactions with one input written in another way than a signer
-- writes it, to test a verifier.
--
-- The other generators of this library hand a verifier what 'signTx'
-- writes: every push the shortest one, every S low, every key compressed
-- or uncompressed, every script the one 'encodeOutput' writes. A verifier
-- that is wrong about any other form passes all the tests made from them.
-- The same spend can be written in other bytes with every signature still
-- good, and what a node does with it then depends on the form and on the
-- network: it relays it, it takes it in a block only, or no block can hold
-- it. Anyone can make most of these forms from a spend seen on the
-- network, without a key. So a verifier that looks at the signatures alone
-- says yes to a transaction that a node refuses, and a node of Bitcoin
-- Cash drops the peer that sends one.
--
-- 'arbitraryRespelled' makes such a transaction for one 'Spelling'. Each
-- constructor says what the nodes of each network do with it, which is
-- what a test expects of the verifier. Every signature in the transaction
-- is good: a verifier never has a reason to call an input forged.
--
-- These are not all the forms that a node refuses. A size limit, such as
-- the 999 keys of a Taproot multisig, is not a spelling, and has tests of
-- its own.
module Haskoin.Util.Arbitrary.Spelling
  ( Spelling (..),
    Respelled (..),
    arbitraryRespelled,
  )
where

import Control.Applicative ((<|>))
import Crypto.Secp256k1
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get (runGetS)
import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (deserialize, serialize)
import Data.Maybe (fromMaybe)
import Haskoin.Crypto.Hash (addressHash)
import Haskoin.Crypto.Keys.Common
import Haskoin.Crypto.Signature (decodeStrictSig)
import Haskoin.Network.Data
import Haskoin.Script
import Haskoin.Transaction.Builder.Sign
import Haskoin.Transaction.Common
import Haskoin.Transaction.Segwit (isSegwit)
import Haskoin.Util
import Haskoin.Util.Arbitrary.Keys
import Haskoin.Util.Arbitrary.Transaction
import Test.QuickCheck

-- | A way to write an input other than the way of 'signTx', with every
-- signature still good.
--
-- On Bitcoin three of the rules below belong to the relay policy: a block
-- may hold the input, and nodes do not relay it. Bitcoin Cash applies the
-- same three to every block (@MANDATORY_SCRIPT_VERIFY_FLAGS@ of Bitcoin
-- Cash Node).
data Spelling
  = -- | An item of the input script is pushed by @OP_PUSHDATA1@, @2@ or
    -- @4@ where a shorter push holds it. The coin is not a witness program.
    -- This is the @MINIMALDATA@ rule: relay policy on Bitcoin, every block
    -- on Bitcoin Cash.
    LongPush
  | -- | The witness program of a SegWit input nested in a script hash is
    -- pushed by @OP_PUSHDATA1@, @2@ or @4@. No block holds it: BIP 141
    -- wants the input script to be exactly the push of the program. Only a
    -- network with SegWit has this spelling.
    LongProgramPush
  | -- | An ECDSA signature has the order of the curve less S in place of
    -- S. Both verify. This is the @LOW_S@ rule: relay policy on Bitcoin,
    -- every block on Bitcoin Cash.
    HighS
  | -- | The coin is locked to the hash of a key in the hybrid form, 65
    -- bytes that start with 0x06 or 0x07, and the input shows that key. The
    -- coin is a key hash or, on a network with SegWit, a witness key hash.
    -- This is the @STRICTENC@ rule: relay policy on Bitcoin, every block on
    -- Bitcoin Cash.
    HybridKey
  | -- | A SegWit version 0 coin is locked to the hash of an uncompressed
    -- key, and the input shows that key. A block may hold it, and nodes do
    -- not relay it (@WITNESS_PUBKEYTYPE@). 'signTx' refuses to make it.
    -- Only a network with SegWit has this spelling.
    UncompressedKey
  | -- | The input shows its redeem script or its witness script with a
    -- longer push in it: the same keys in other bytes, with another hash
    -- than the one that the coin holds. No block holds it (BIP 16, BIP
    -- 141).
    UncommittedScript
  | -- | The coin is locked to a script with a longer push in it, a key, a
    -- key hash or a multisig, and not to the hash of one. The signatures
    -- cover the script with the shortest pushes, which is what a decoder
    -- that forgets the form of a push hands to a verifier. No block holds
    -- it: a signature covers the bytes of the script of its coin.
    UnsignedScript
  deriving (Eq, Show, Enum, Bounded)

-- | A signed transaction with one input in another spelling. The other
-- inputs are as 'signTx' wrote them: a node takes each of them.
data Respelled = Respelled
  { -- | the transaction
    tx :: Tx,
    -- | the output that each input spends, in order
    coins :: [TxOut],
    -- | which input is in the other spelling
    index :: Int
  }
  deriving (Eq, Show)

-- | Arbitrary signed transaction of one to four inputs, one of them in the
-- spelling asked for, with the outputs that it spends. A SegWit input is
-- native or nested in a script hash. The outputs of the transaction spend
-- no more than its coins hold.
--
-- The call is an error for a spelling that the network does not have: see
-- 'Spelling'.
arbitraryRespelled :: Network -> Spelling -> Gen Respelled
arbitraryRespelled net spelling = do
  made <- recipe net spelling
  others <- resize 3 (listOf other)
  (unsigned, sigis, keys) <- arbitrarySigningDataOf net (made.coin : others)
  nestings <- vectorOf (length sigis) arbitrary
  let goal = (fst made.coin).outpoint
      spent =
        [ (s, isSegwit s.script && (if s.outpoint == goal then made.nested else n))
        | (s, n) <- zip sigis nestings
        ]
      signed = orError (signTx net unsigned spent (map (.key) keys))
      outputs = [(s.outpoint, spentOutput s n) | (s, n) <- spent]
      coins = [coin | input <- signed.inputs, Just coin <- [lookup input.outpoint outputs]]
      index = length (takeWhile ((/= goal) . (.outpoint)) signed.inputs)
  made.change Respelled {tx = signed, coins, index}
  where
    -- A Taproot signature covers the script of every coin spent, so it
    -- would not stand a coin whose script changes after the signing
    other
      | spelling == UnsignedScript = arbitrarySigInput net `suchThat` (not . isTaprootKey . (.script) . fst)
      | otherwise = arbitrarySigInput net
    isTaprootKey = \case
      PayWitness 1 _ -> True
      _ -> False

-- | The output that a coin of the signer is on the chain: a nested SegWit
-- program is locked to the hash of the program.
spentOutput :: SigInput -> Bool -> TxOut
spentOutput s nested
  | nested = TxOut s.value (encodeSerial (orError (toP2SH =<< encodeOutput s.script)))
  | otherwise = TxOut s.value (encodeSerial s.script)

-- | How a spelling is made.
data Recipe = Recipe
  { -- | the coin to respell, with the keys that 'signTx' gets for it: none
    -- for a coin that 'signTx' does not sign, which the change signs
    coin :: (SigInput, [PrivateKey]),
    -- | whether a SegWit coin is nested in a script hash
    nested :: Bool,
    -- | what to change in the transaction once 'signTx' has signed it
    change :: Respelled -> Gen Respelled
  }

recipe :: Network -> Spelling -> Gen Recipe
recipe net = \case
  LongPush ->
    Recipe <$> arbitraryLegacySigInput net <*> pure False <*> pure (onInputScript longerPush)
  LongProgramPush ->
    Recipe <$> witness <*> pure True <*> pure (onInputScript longerPush)
  HighS ->
    Recipe <$> oneof (arbitraryLegacySigInput net : [witness | net.segWit]) <*> arbitrary <*> pure (return . withHighS)
  HybridKey -> do
    secret <- arbitraryPrivateKey
    let shown = hybridKey (derivePubKey secret.key)
    coin <- keyHashCoin (PayPKHash (addressHash shown) : [PayWitnessPKHash (addressHash shown) | net.segWit])
    return (Recipe (coin, []) False (return . signedShowing net coin secret shown))
  UncompressedKey -> do
    secret <- (\k -> wrapSecKey False k.key) <$> arbitraryPrivateKey
    coin <- keyHashCoin [PayWitnessPKHash (addressHash (encodeSerial (derivePublicKey secret))) | net.segWit]
    nested <- arbitrary
    return (Recipe (coin, []) nested (return . signedBy net (coin, nested) secret))
  UncommittedScript ->
    Recipe
      <$> oneof (arbitrarySHSigInput net : [arbitraryWSHSigInput net | net.segWit])
      <*> arbitrary
      <*> pure (onShownScript longerPush)
  UnsignedScript ->
    Recipe
      <$> oneof [wrapKey <$> arbitraryPKSigInput net, wrapKey <$> arbitraryPKHashSigInput net, bareMultisig]
      <*> pure False
      <*> pure (onCoinScript longerPush)
  where
    bareMultisig = arbitraryMSSigInput net
    witness
      | net.segWit = arbitraryWitnessSigInput net
      | otherwise = error "arbitraryRespelled: this network has no SegWit"
    keyHashCoin [] = error "arbitraryRespelled: this network has no SegWit"
    keyHashCoin scripts = do
      script <- elements scripts
      (value, outpoint, sighash) <- arbitraryInputStuff net
      return SigInput {script, value, outpoint, sighash, redeem = Nothing}

-- | The script with one of its pushes of data written by a longer opcode
-- than the data needs: @OP_PUSHDATA1@, @2@ or @4@ for a direct push, and so
-- on.
longerPush :: ByteString -> Gen ByteString
longerPush script = do
  (n, op) <- elements [(n, OP_PUSHDATA d longer) | (n, OP_PUSHDATA d t) <- zip [0 ..] ops, longer <- longerThan t]
  return (scriptBytes (updateIndex n ops (const op)))
  where
    ops = scriptOps script
    longerThan = \case
      OPCODE -> [OPDATA1, OPDATA2, OPDATA4]
      OPDATA1 -> [OPDATA2, OPDATA4]
      OPDATA2 -> [OPDATA4]
      OPDATA4 -> []

-- | An ECDSA signature and its hash type byte, with the order of the curve
-- less S in place of S. Nothing for an item that is not such a signature.
highS :: ByteString -> Maybe ByteString
highS item = do
  (der, hashType) <- B.unsnoc item
  (r, s) <- B.splitAt 32 . (.get) . exportCompactSig <$> decodeStrictSig der
  let order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 :: Integer
      other = integerToBS (order - bsToInteger s)
  flipped <- importCompactSig =<< compactSig (r <> B.replicate (32 - B.length other) 0 <> other)
  return (exportSig flipped `B.snoc` hashType)

-- | The input with a high S in its first signature, which is in its input
-- script or in its witness. The signature is pushed by the shortest push.
withHighS :: Respelled -> Respelled
withHighS r = fromMaybe (error "arbitraryRespelled: no ECDSA signature") (inScript <|> inWitness)
  where
    inScript = (\ops -> withInputScript (scriptBytes ops) r) <$> changeFirst pushed (scriptOps (inputScript r))
    inWitness = (`withWitness` r) <$> changeFirst highS (witnessOf r)
    pushed = \case
      OP_PUSHDATA d _ -> opPushData <$> highS d
      _ -> Nothing

-- | The 65 bytes of a key in the hybrid form: both coordinates, after 0x06
-- when y is even and 0x07 when it is odd.
hybridKey :: PubKey -> ByteString
hybridKey point = B.cons (if even (B.last full) then 0x06 else 0x07) (B.drop 1 full)
  where
    full = exportPubKey False point

-- | The input signed by a key, and showing these bytes as that key. The
-- coin is a key hash or a witness key hash.
signedShowing :: Network -> SigInput -> PrivateKey -> ByteString -> Respelled -> Respelled
signedShowing net coin secret shown r
  | isSegwit coin.script = withWitness [signature, shown] r
  | otherwise = withInputScript (scriptBytes (map opPushData [signature, shown])) r
  where
    signature = encodeTxSig net (orError (makeSignature net r.tx r.index coin secret))

-- | The input signed by 'signInput', which signs with the key in the form
-- that it is given.
signedBy :: Network -> (SigInput, Bool) -> PrivateKey -> Respelled -> Respelled
signedBy net coin secret r = r {tx = orError (signInput net r.tx r.index coin secret)}

-- | Change the first element that the function changes.
changeFirst :: (a -> Maybe a) -> [a] -> Maybe [a]
changeFirst change = \case
  [] -> Nothing
  x : xs -> ((: xs) <$> change x) <|> ((x :) <$> changeFirst change xs)

-- | Change the input script of the respelled input.
onInputScript :: (ByteString -> Gen ByteString) -> Respelled -> Gen Respelled
onInputScript change r = (`withInputScript` r) <$> change (inputScript r)

-- | Change the script that the respelled input shows: its witness script,
-- the last item of its witness, or else its redeem script, the last push of
-- its input script. The redeem script is pushed by the shortest push.
onShownScript :: (ByteString -> Gen ByteString) -> Respelled -> Gen Respelled
onShownScript change r = case (reverse (witnessOf r), reverse (scriptOps (inputScript r))) of
  (script : below, _) ->
    (\s -> withWitness (reverse (s : below)) r) <$> change script
  ([], OP_PUSHDATA script _ : below) ->
    (\s -> withInputScript (scriptBytes (reverse (opPushData s : below))) r) <$> change script
  _ -> error "arbitraryRespelled: the input shows no script"

-- | Change the script of the coin that the respelled input spends.
onCoinScript :: (ByteString -> Gen ByteString) -> Respelled -> Gen Respelled
onCoinScript change r = do
  script <- change (r.coins !! r.index).script
  return (r {coins = updateIndex r.index r.coins (\coin -> TxOut coin.value script)} :: Respelled)

inputScript :: Respelled -> ByteString
inputScript r = (r.tx.inputs !! r.index).script

withInputScript :: ByteString -> Respelled -> Respelled
withInputScript script r = r {tx = r.tx {inputs = updateIndex r.index r.tx.inputs change}}
  where
    change :: TxIn -> TxIn
    change input = TxIn input.outpoint script input.sequence

-- | The witness of the respelled input: no item when it has none.
witnessOf :: Respelled -> WitnessStack
witnessOf r = concat (take 1 (drop r.index r.tx.witness))

withWitness :: WitnessStack -> Respelled -> Respelled
withWitness items r = r {tx = r.tx {witness = updateIndex r.index stacks (const items)}}
  where
    -- A transaction without a witness has no stack at all
    stacks
      | null r.tx.witness = map (const []) r.tx.inputs
      | otherwise = r.tx.witness

scriptOps :: ByteString -> [ScriptOp]
scriptOps bytes = (orError (runGetS deserialize bytes) :: Script).ops

scriptBytes :: [ScriptOp] -> ByteString
scriptBytes = runPutS . serialize . Script

-- | The generators only take apart what the signer just made.
orError :: Either String a -> a
orError = either (error . ("arbitraryRespelled: " <>)) id
