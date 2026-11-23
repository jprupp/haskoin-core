{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Transaction.Judge
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- What a program that is no full node can say of a transaction: whether a
-- node would take it, as far as that can be told without running a script.
--
-- = The problem
--
-- A full node checks a transaction by running the script of every coin
-- that it spends. This library has no interpreter of scripts. But most of
-- what makes a transaction bad needs none: a coin that is not there, more
-- paid than is held, a lock time that has not passed, tokens made from
-- nothing, and the signature of a coin that is locked to one key, which
-- is most coins. A program that indexes the chain, relays transactions or
-- builds them can check all of that, and say of the rest that it does not
-- know.
--
-- = Two questions
--
-- * 'judge': somebody wants to __publish__ this transaction. Would a node
--   relay it? This holds the transaction to the rules of the chain and to
--   the rules of relay that have not changed in years, since handing a
--   node a transaction that it refuses can cost the connection to it.
--
-- * 'judgeRelayed': a peer __sent__ this transaction, as one that its
--   node took. Could a node have taken it? This holds it only to what no
--   node can take whatever its policy, since the policy of a node is its
--   own, and a transaction that some node relays must not be refused for
--   breaking the policy of another.
--
-- Both answer in three ways: refused, with the reason ('Refusal'); good,
-- with every signature verified; or good as far as can be told, with the
-- first input that could not be judged. The third is not a polite refusal:
-- a spend of a coin locked by a script is a normal transaction, and only a
-- full node can say whether it is good. What to do with it is for the
-- caller to decide, and depends on who vouches for the transaction.
--
-- = What this is not
--
-- Not validation. A transaction that passes may still be one that no node
-- takes: a script that fails, a fee too low, a conflict with another
-- transaction. And nothing here looks at a mempool.
--
-- The names of this module are not exported by "Haskoin" or by
-- "Haskoin.Transaction": @Coin@ is already the name of a class there
-- ("Haskoin.Transaction.Builder"), and names as short as 'Spent' and
-- 'Missing' are best imported on purpose.
module Haskoin.Transaction.Judge
  ( -- * A transaction to publish
    judge,
    Rules (..),
    rulesAt,
    Coin (..),

    -- * A transaction that a peer sent
    judgeRelayed,

    -- * Why not
    Refusal (..),

    -- * The rules of relay
    maxTxSize,
    maxStandardSize,
    isDust,

    -- * The tokens of Bitcoin Cash
    tokenRules,
  )
where

import Control.Monad (forM_, unless, when)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.HashMap.Strict qualified as HashMap
import Data.List (partition)
import Data.Maybe (isJust, listToMaybe)
import Data.Serialize (decode, encode)
import Data.String.Conversions (cs)
import Data.Word (Word32, Word64, Word8)
import Haskoin.Block.Common (BlockHeight)
import Haskoin.Network.Data (Network (..))
import Haskoin.Script.CashToken (NFToken (..), TokenData (..), splitTokenData)
import Haskoin.Script.Common (Script (..), isMinimalPush, isPushOp)
import Haskoin.Transaction.Builder (InputVerdict (..), judgeInputs)
import Haskoin.Transaction.Common
  ( OutPoint (..),
    Tx (..),
    TxHash,
    TxIn (..),
    TxOut (..),
    nullOutPoint,
    txHashToHex,
  )

-- | An output that a transaction spends, as whoever judges it knows it.
data Coin
  = -- | it is there to spend, or only an unconfirmed transaction spends
    -- it
    Coin
      { -- | the output, as it is in the transaction that made it
        output :: !TxOut,
        -- | the height of the block that confirmed it, if one did
        mined :: !(Maybe BlockHeight),
        -- | whether a coinbase made it
        coinbase :: !Bool
      }
  | -- | a confirmed transaction has spent it
    Spent !TxHash
  | -- | it is not known
    Missing
  deriving (Eq, Show)

-- | Why a transaction is refused. What 'show' says of each is written for
-- the one who made the transaction.
data Refusal
  = TooLarge !Int
  | NoInputs
  | NoOutputs
  | IsCoinbase
  | DuplicateInput !OutPoint
  | UnknownOutput !OutPoint
  | SpentOutput !OutPoint !TxHash
  | Overspent
  | Immature !OutPoint
  | NotFinal !Word32
  | TooHeavy !Int
  | Dust !Int
  | Forged !Int
  | BadVersion !Word32
  | NotPushOnly !Int
  | NotMinimal !Int
  | BadTokens !Int
  | TokensUnbacked !String
  deriving (Eq)

instance Show Refusal where
  show (TooLarge n) = "The transaction is too large: " <> show n <> " bytes"
  show NoInputs = "The transaction has no inputs"
  show NoOutputs = "The transaction has no outputs"
  show IsCoinbase = "A coinbase transaction cannot be published"
  show (DuplicateInput o) = "The transaction spends the same output twice: " <> showOutPoint o
  show (UnknownOutput o) = "The transaction spends an output that this server does not know: " <> showOutPoint o
  show (SpentOutput o by) =
    "The transaction spends an output that a confirmed transaction has spent: "
      <> showOutPoint o
      <> " by "
      <> cs (txHashToHex by)
  show Overspent = "The outputs of the transaction are worth more than its inputs"
  show (Immature o) = "The transaction spends a coinbase that is not a hundred blocks old: " <> showOutPoint o
  show (NotFinal lock) = "The lock time of the transaction has not passed: " <> show lock
  show (TooHeavy n) = "The transaction is larger than nodes relay: " <> show n
  show (Dust i) = "Output " <> show i <> " is worth less than it costs to spend, and nodes do not relay it"
  show (Forged i) = "The signature of input " <> show i <> " does not verify"
  show (BadVersion v) = "Nodes do not take a transaction of version " <> show v
  show (NotPushOnly i) = "The script of input " <> show i <> " does more than push data"
  show (NotMinimal i) = "The script of input " <> show i <> " pushes data in a longer form than it needs"
  show (BadTokens i) = "The tokens of output " <> show i <> " are not written as tokens are"
  show (TokensUnbacked c) = "The transaction gives tokens of category " <> c <> " that its inputs do not hold"

showOutPoint :: OutPoint -> String
showOutPoint o = cs (txHashToHex o.hash) <> ":" <> show o.index

-- | The largest transaction that a block of the network can hold, in
-- bytes. With SegWit a block weighs four million units at most, and a byte
-- of witness weighs one, so a transaction that is nearly all witness comes
-- close to four million bytes. Without it, the rule of Bitcoin Cash is a
-- million bytes for a transaction.
--
-- Nodes relay far smaller ones only, a hundred thousand bytes or so. That
-- rule is theirs to change ('maxStandardSize'): this is the
-- size past which no node can take the transaction.
maxTxSize :: Network -> Int
maxTxSize net
  | net.segWit = 4000000
  | otherwise = 1000000

-- | What is known of the chain and the network when a transaction is
-- looked at.
data Rules = Rules
  { net :: !Network,
    -- | what can be said of the signature of each input, given the
    -- outputs they spend: 'judgeInputs', as 'rulesAt' sets it. A field,
    -- so that a test can say what the verdicts are.
    inputs :: !(Tx -> [TxOut] -> [InputVerdict]),
    -- | height of the best block
    height :: !BlockHeight,
    -- | median of the times of the last eleven blocks, which is the time
    -- that lock times are held to (BIP 113)
    medianTime :: !Word64
  }

-- | What can be said of a transaction that somebody wants to publish,
-- without a full node: given the coin of each input, in order.
--
-- Every check here is one whose answer a node would give too, and that
-- does not depend on what else is in a mempool:
--
-- * __What makes it no transaction__: no inputs or outputs, an input
--   twice, a coinbase, longer than a block can hold ('maxTxSize').
-- * __The coins__: each input spends an output that is known, that
--   no confirmed transaction has spent, and a coinbase only after a
--   hundred blocks. The outputs are not worth more than the inputs.
-- * __The lock time__ has passed, by height or by the median time, unless
--   every input waives it.
-- * __What nodes do not relay__: more than 'maxStandardSize', and an
--   output so small that spending it costs more than it holds ('isDust').
--   These are rules of relay and not of the chain; they are the ones that
--   have not changed in years.
-- * __Input scripts__ only push data, each push in its shortest form. On
--   Bitcoin Cash that is a rule of the chain, and a node drops every
--   connection of a peer that sends a transaction that breaks it.
-- * __The version__: 1 or 2 on Bitcoin Cash, a rule of the chain there; 1
--   to 3 on Bitcoin, which nodes relay.
-- * __Tokens__ of Bitcoin Cash ('tokenRules'): written as tokens are, and
--   given only as the inputs hold them. A node drops every connection of a
--   peer that sends a transaction that breaks them.
-- * __Signatures__, where there is no script to run: an input that spends
--   a coin locked to one key with a signature that does not verify
--   ('judgeInputs'). An input that is a script, or that cannot be read,
--   is left to a node.
--
-- A conflict with an unconfirmed transaction is not a reason to refuse:
-- whether one may replace the other is for the node to say, and the
-- mempool of the caller may hold what the network has dropped. The fee is
-- not checked either: what a node asks for changes with its mempool.
--
-- The answer for a transaction that passes says whether every signature
-- was verified, or names the first input that could not be judged: a
-- script, a hash type other than all. Such a transaction may be good, and
-- only a full node can say.
judge :: Rules -> Tx -> [Coin] -> Either Refusal (Maybe Int)
judge rules tx coins = do
  when (size > maxTxSize rules.net) $ Left (TooLarge size)
  when (null tx.inputs) $ Left NoInputs
  when (null tx.outputs) $ Left NoOutputs
  when (any ((== nullOutPoint) . (.outpoint)) tx.inputs) $ Left IsCoinbase
  mapM_ (Left . DuplicateInput) (firstDuplicate (map (.outpoint) tx.inputs))
  unless (tx.version `elem` versions) $ Left (BadVersion tx.version)
  mapM_ pushes (zip [0 ..] tx.inputs)
  spent <- mapM known (zip (map (.outpoint) tx.inputs) coins)
  when cash $ tokenRules tx spent
  -- sums of 64-bit values: compared as integers, which do not wrap
  unless (sum (map (toInteger . (.value)) spent) >= sum (map (toInteger . (.value)) tx.outputs)) $ Left Overspent
  mapM_ mature (zip (map (.outpoint) tx.inputs) coins)
  unless final $ Left (NotFinal tx.locktime)
  when (heavy > maxStandardSize rules.net) $ Left (TooHeavy heavy)
  mapM_ (Left . Dust) (take 1 [i | (i, o) <- zip [0 ..] tx.outputs, isDust rules.net o])
  let verdicts = zip [0 ..] (rules.inputs tx spent)
  mapM_ (Left . Forged) (take 1 [i | (i, InputForged) <- verdicts])
  return (listToMaybe [i | (i, InputUndecided) <- verdicts])
  where
    cash = isJust rules.net.sigHashForkId
    -- Bitcoin Cash takes versions 1 and 2 only, by its rules since May
    -- 2023; Bitcoin Core relays those and version 3
    versions
      | cash = [1, 2]
      | otherwise = [1, 2, 3]
    -- an input script that only pushes data, each push in its shortest
    -- form: rules of Bitcoin Cash, relay rules of Bitcoin Core
    pushes :: (Int, TxIn) -> Either Refusal ()
    pushes (i, input) = case decode input.script of
      Right (Script ops)
        | not (all isPushOp ops) -> Left (NotPushOnly i)
        | not (all isMinimalPush ops) -> Left (NotMinimal i)
        | otherwise -> Right ()
      Left _ -> Left (NotPushOnly i)
    size = B.length (encode tx)
    -- what the limit of relay counts: weight with SegWit, bytes without
    heavy
      | rules.net.segWit = 3 * B.length (encode (tx {witness = []} :: Tx)) + size
      | otherwise = size
    known (_, Coin {output}) = Right output
    known (o, Spent by) = Left (SpentOutput o by)
    known (o, Missing) = Left (UnknownOutput o)
    -- a coinbase can be spent in the hundredth block after its own
    mature (o, Coin {coinbase = True, mined = Just h})
      | rules.height + 1 < h + 100 = Left (Immature o)
    mature _ = Right ()
    -- IsFinalTx of Bitcoin Core, for the block after the best one
    final
      | tx.locktime == 0 = True
      | tx.locktime < 500000000 = tx.locktime < rules.height + 1 || waived
      | otherwise = fromIntegral tx.locktime < rules.medianTime || waived
    waived = all ((== maxBound) . (.sequence)) tx.inputs

-- | The rules at a height and a median time, with the signatures judged
-- by 'judgeInputs'.
rulesAt :: Network -> BlockHeight -> Word64 -> Rules
rulesAt net height medianTime =
  Rules {net, inputs = \tx -> judgeInputs net tx . map Just, height, medianTime}

-- | What can be said of a transaction that a peer sent as one that its
-- node took, given the outputs that it spends, in order.
--
-- A node relays what its own policy lets it, and the policies of nodes
-- differ and change: the smallest output, the largest transaction, the
-- versions. A transaction that breaks one of those rules may be one that
-- most of the network relays. So this refuses only what no node takes,
-- whatever its policy, because no block could hold it:
--
-- * it has no inputs or no outputs, spends an output twice, or is a
--   coinbase, which no node relays;
-- * its outputs are worth more than its inputs;
-- * on Bitcoin Cash, it breaks the rules of the tokens ('tokenRules');
-- * the signature of a coin locked to one key does not verify
--   ('judgeInputs').
--
-- The lock time is left out though a node holds a transaction to it: it
-- is held to the block that the node is at, which is not always the one
-- that the caller is at.
--
-- It answers as 'judge' does: for a transaction that passes, whether
-- every signature was verified, or the first input that could not be
-- judged. Whether to take such a transaction depends on who sent it: from
-- a node of one's own it is as good as any, and from a stranger it is a
-- claim that nothing here supports.
--
-- The outputs must be those that the inputs spend, all of them: what the
-- caller does not have is not something to judge yet.
judgeRelayed :: Network -> Tx -> [TxOut] -> Either Refusal (Maybe Int)
judgeRelayed net tx spent = do
  when (null tx.inputs) $ Left NoInputs
  when (null tx.outputs) $ Left NoOutputs
  when (any ((== nullOutPoint) . (.outpoint)) tx.inputs) $ Left IsCoinbase
  mapM_ (Left . DuplicateInput) (firstDuplicate (map (.outpoint) tx.inputs))
  when (isJust net.sigHashForkId) $ tokenRules tx spent
  unless (sum (map (toInteger . (.value)) spent) >= sum (map (toInteger . (.value)) tx.outputs)) $ Left Overspent
  let verdicts = zip [0 ..] (judgeInputs net tx (map Just spent))
  mapM_ (Left . Forged) (take 1 [i | (i, InputForged) <- verdicts])
  return (listToMaybe [i | (i, InputUndecided) <- verdicts])

-- | The first of some outpoints that comes twice.
firstDuplicate :: [OutPoint] -> Maybe OutPoint
firstDuplicate = go HashMap.empty
  where
    go _ [] = Nothing
    go seen (o : os)
      | HashMap.member o seen = Just o
      | otherwise = go (HashMap.insert o () seen) os

-- | The most that nodes relay: 400,000 units of weight with SegWit, which
-- is 100,000 bytes of a transaction without witness, and 100,000 bytes on
-- Bitcoin Cash.
maxStandardSize :: Network -> Int
maxStandardSize net
  | net.segWit = 400000
  | otherwise = 100000

-- | Whether an output is dust: worth less than three times what it costs,
-- at the lowest fee nodes relay, to make it and to spend it. Nodes do not
-- relay a transaction with one. This is @IsDust@ of Bitcoin Core at its
-- default of 3,000 satoshi a kilobyte, and of Bitcoin Cash Node: 546
-- satoshi for an output to a key hash, 294 to a witness key hash.
--
-- An output that cannot be spent, which starts with @OP_RETURN@, holds
-- data and may hold no value.
isDust :: Network -> TxOut -> Bool
isDust net o
  | unspendable = False
  | otherwise = toInteger o.value < 3 * toInteger (made + spent)
  where
    s = o.script
    unspendable = (not (B.null s) && B.head s == 0x6a) || B.length s > 10000
    made = 8 + lengthOfLength + B.length s
    lengthOfLength
      | B.length s < 0xfd = 1
      | B.length s <= 0xffff = 3
      | otherwise = 5
    -- what an input that spends it adds: less when its signature is in
    -- the witness
    spent
      | net.segWit && witnessProgram = 67
      | otherwise = 148
    witnessProgram =
      B.length s >= 4
        && B.length s <= 42
        && (B.head s == 0 || (B.head s >= 0x51 && B.head s <= 0x60))
        && fromIntegral (B.index s 1) == B.length s - 2

-- | The tokens that an output holds: their category, a non-fungible token
-- with its capability and commitment, and an amount of fungible ones.
data Tokens = Tokens
  { category :: !ByteString,
    nft :: !(Maybe (Word8, ByteString)),
    amount :: !Word64
  }

-- | The tokens at the front of the script of an output, if it has any, or
-- 'Left' if they are not written as tokens are ('splitTokenData'). The category is in the order of its bytes in the
-- transaction, as the rules compare it with the outpoints of the inputs.
readTokens :: ByteString -> Either () (Maybe Tokens)
readTokens script = case splitTokenData script of
  Left _ -> Left ()
  Right (Nothing, _) -> Right Nothing
  Right (Just t, _) ->
    Right . Just $
      Tokens
        { category = encode t.category,
          -- capabilities: 0 none, 1 mutable, 2 minting, in the order of
          -- the constructors
          nft = (\n -> (fromIntegral (fromEnum n.capability), n.commitment)) <$> t.nft,
          amount = t.amount
        }

-- | The rules of the tokens of Bitcoin Cash (CashTokens, since May 2023),
-- given the outputs that the inputs spend, in order. A node drops every
-- connection of a peer that sends it a transaction that breaks them, and
-- no block holds one.
--
-- * The tokens of every output are written as tokens are.
-- * A category is new when it is the id of a transaction whose first
--   output an input spends: its tokens may be made at will.
-- * Of any other category, the outputs hold no more fungible tokens than
--   the inputs, and no more than the largest amount, in all.
-- * And its non-fungible tokens come from the inputs: any, when an input
--   holds one that can mint; else each output's equals one of an input
--   that cannot be changed, or takes the place of one that can be changed,
--   and none can mint.
tokenRules :: Tx -> [TxOut] -> Either Refusal ()
tokenRules tx spent = do
  outs <- mapM readOut (zip [0 ..] tx.outputs)
  let ins = [t | Right (Just t) <- map (readTokens . (.script)) spent] :: [Tokens]
      made = [t | Just t <- outs] :: [Tokens]
      new = [encode i.outpoint.hash | i <- tx.inputs, i.outpoint.index == 0]
      categories = HashMap.keys (HashMap.fromList [(t.category, ()) | t <- made])
  forM_ categories $ \c -> do
    let given = [t | t <- made, t.category == c] :: [Tokens]
        held = [t | t <- ins, t.category == c] :: [Tokens]
        total = sum (map (toInteger . (.amount)) given)
    when (total > 0x7fffffffffffffff) $ Left (TokensUnbacked (named c))
    unless (c `elem` new) $ do
      when (total > sum (map (toInteger . (.amount)) held)) $ Left (TokensUnbacked (named c))
      unless (nftsBacked [n | Just n <- map (.nft) given] [n | Just n <- map (.nft) held]) $
        Left (TokensUnbacked (named c))
  where
    readOut :: (Int, TxOut) -> Either Refusal (Maybe Tokens)
    readOut (i, o) = either (const (Left (BadTokens i))) Right (readTokens o.script)
    -- the id of a category as people write it: the bytes reversed
    named = concatMap hex . B.unpack . B.reverse
    hex w = [digits !! fromIntegral (w `div` 16), digits !! fromIntegral (w `mod` 16)]
    digits = "0123456789abcdef"
    -- capabilities: 0 none, 1 mutable, 2 minting
    nftsBacked given held
      | any ((== 2) . fst) held = True
      | any ((== 2) . fst) given = False
      | otherwise =
          let (fixed, changing) = partition ((== 0) . fst) given
              left = foldl matched ([n | n <- held, fst n == 0], []) fixed
              mutable = length (filter ((== 1) . fst) held)
           in length (snd left) + length changing <= mutable
    -- an immutable token given takes an equal one held, or waits for a
    -- mutable one
    matched (pool, unmatched) n = case break (== n) pool of
      (before, _ : after) -> (before <> after, unmatched)
      _ -> (pool, n : unmatched)
