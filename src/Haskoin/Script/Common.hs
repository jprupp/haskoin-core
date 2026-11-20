{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Script.Common
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Common script-related functions and data types.
module Haskoin.Script.Common
  ( -- * Scripts
    ScriptOp (..),
    pattern OP_CHECKSIGADD,
    pattern OP_BEGIN,
    pattern OP_UNTIL,
    pattern OP_SPLIT,
    pattern OP_NUM2BIN,
    pattern OP_BIN2NUM,
    pattern OP_DEFINE,
    pattern OP_INVOKE,
    pattern OP_LSHIFTNUM,
    pattern OP_RSHIFTNUM,
    pattern OP_LSHIFTBIN,
    pattern OP_RSHIFTBIN,
    opName,
    Script (..),
    PushDataType (..),
    isPushOp,
    pushOpData,
    isMinimalPush,
    opPushData,
    intToScriptOp,
    scriptOpToInt,
  )
where

import Control.DeepSeq
import Control.Monad
import Data.Aeson
import Data.Aeson.Encoding
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.ByteString.Builder (char7)
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Hashable
import Data.Maybe (fromMaybe, isJust)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Serialize (Serialize (..))
import Data.Word (Word8)
import GHC.Generics (Generic)
import Haskoin.Network.Data (Network (..))
import Haskoin.Util (hexBuilder)
import Haskoin.Util.Helpers (decodeHex, encodeHex, hexEncoding)

-- | Data type representing a transaction script. Scripts are defined as lists
-- of script operators 'ScriptOp'. Scripts are used to:
--
-- * Define the spending conditions in the output of a transaction.
-- * Provide signatures in the input of a transaction (except SegWit).
--
-- SigWit only: the segregated witness data structure, and not the input script,
-- contains signatures and redeem script for pay-to-witness-script and
-- pay-to-witness-public-key-hash transactions.
newtype Script = Script
  { -- | script operators defining this script
    ops :: [ScriptOp]
  }
  deriving (Eq, Show, Read, Generic)
  deriving newtype (Hashable, NFData)

instance FromJSON Script where
  parseJSON = withText "script" $ \t -> do
    bs <- maybe mzero return (decodeHex t)
    either fail return (runGetS deserialize bs)

instance ToJSON Script where
  toJSON = String . encodeHex . runPutS . serialize
  toEncoding = hexEncoding . runPutL . serialize

instance Serial Script where
  {-# INLINEABLE serialize #-}
  {-# INLINEABLE deserialize #-}
  deserialize =
    Script <$> getScriptOps
    where
      getScriptOps = do
        empty <- isEmpty
        if empty
          then return []
          else (:) <$> deserialize <*> getScriptOps

  serialize (Script ops) = forM_ ops serialize

instance Binary Script where
  put = serialize
  get = deserialize

instance Serialize Script where
  put = serialize
  get = deserialize

-- | Data type representing the type of an OP_PUSHDATA opcode.
data PushDataType
  = -- | next opcode bytes is data to be pushed
    OPCODE
  | -- | next byte contains number of bytes of data to be pushed
    OPDATA1
  | -- | next two bytes contains number of bytes to be pushed
    OPDATA2
  | -- | next four bytes contains the number of bytes to be pushed
    OPDATA4
  deriving (Show, Read, Eq, Generic, Hashable, NFData)

-- | Data type representing an operator allowed inside a 'Script'.
--
-- One type serves both chains, with one constructor for each byte. Bitcoin
-- and Bitcoin Cash split a script into opcodes in the same way: the same
-- bytes, the same pushes, the same lengths. They differ in the names of
-- twelve bytes and in what some bytes do when a script runs, which matters
-- to an interpreter and not to a parser. So a script parses and serializes
-- without a network, and the chains share every type built on it:
-- addresses, PSBTs, signature hashes.
--
-- * The constructors of those twelve bytes carry the Bitcoin name, but for
--   0xba, which carries the Bitcoin Cash name 'OP_CHECKDATASIG'. Each has a
--   pattern synonym for the name of the other chain, such as 'OP_SPLIT' for
--   'OP_SUBSTR' and 'OP_CHECKSIGADD' for 'OP_CHECKDATASIG': both names build
--   and match the same value.
-- * The opcodes that only Bitcoin Cash defines, from 0xbb to 0xd5, have
--   constructors of their own: their bytes have no name on Bitcoin.
-- * 'opName' gives the name that the reference node of a network prints.
--
-- Separate types for each chain were rejected: they would add a network to
-- every parse of a script, for names alone. Which opcodes a chain enables, at
-- which height, and the bytes that make a Tapscript succeed at once belong to
-- an interpreter, which this library does not have.
--
-- An 'OP_PUSHDATA' must carry a payload that fits its 'PushDataType': at most
-- 75 bytes for 'OPCODE', 255 for 'OPDATA1', 65535 for 'OPDATA2'. Serializing
-- a push that breaks this invariant fails with an 'error' call, because no
-- byte sequence can represent it. Build pushes with 'opPushData' to get the
-- minimal encoding.
--
-- 'OP_INVALIDOPCODE' holds a byte that has no opcode of its own. The parser
-- only builds it for such a byte. Built by hand with the byte of a defined
-- opcode, such as 0xac, it is a second value for that opcode: it is not equal
-- to 'OP_CHECKSIG', it serializes to the same byte, and it reads back as
-- 'OP_CHECKSIG'. Code that looks for an opcode, such as the removal of
-- 'OP_CODESEPARATOR' in 'Haskoin.Script.SigHash.txSigHash', does not see it.
-- Do not build one for a byte that has a constructor.
data ScriptOp
  = -- Pushing Data
    OP_PUSHDATA
      !ByteString
      !PushDataType
  | OP_0
  | OP_1NEGATE
  | OP_RESERVED
  | OP_1
  | OP_2
  | OP_3
  | OP_4
  | OP_5
  | OP_6
  | OP_7
  | OP_8
  | OP_9
  | OP_10
  | OP_11
  | OP_12
  | OP_13
  | OP_14
  | OP_15
  | OP_16
  | -- Flow control
    OP_NOP
  | OP_VER -- reserved
  | OP_IF
  | OP_NOTIF
  | OP_VERIF -- resreved
  | OP_VERNOTIF -- reserved
  | OP_ELSE
  | OP_ENDIF
  | OP_VERIFY
  | OP_RETURN
  | -- Stack operations
    OP_TOALTSTACK
  | OP_FROMALTSTACK
  | OP_IFDUP
  | OP_DEPTH
  | OP_DROP
  | OP_DUP
  | OP_NIP
  | OP_OVER
  | OP_PICK
  | OP_ROLL
  | OP_ROT
  | OP_SWAP
  | OP_TUCK
  | OP_2DROP
  | OP_2DUP
  | OP_3DUP
  | OP_2OVER
  | OP_2ROT
  | OP_2SWAP
  | -- Splice
    OP_CAT
  | OP_SUBSTR
  | OP_LEFT
  | OP_RIGHT
  | OP_SIZE
  | -- Bitwise logic
    OP_INVERT
  | OP_AND
  | OP_OR
  | OP_XOR
  | OP_EQUAL
  | OP_EQUALVERIFY
  | OP_RESERVED1
  | OP_RESERVED2
  | -- Arithmetic
    OP_1ADD
  | OP_1SUB
  | OP_2MUL
  | OP_2DIV
  | OP_NEGATE
  | OP_ABS
  | OP_NOT
  | OP_0NOTEQUAL
  | OP_ADD
  | OP_SUB
  | OP_MUL
  | OP_DIV
  | OP_MOD
  | OP_LSHIFT
  | OP_RSHIFT
  | OP_BOOLAND
  | OP_BOOLOR
  | OP_NUMEQUAL
  | OP_NUMEQUALVERIFY
  | OP_NUMNOTEQUAL
  | OP_LESSTHAN
  | OP_GREATERTHAN
  | OP_LESSTHANOREQUAL
  | OP_GREATERTHANOREQUAL
  | OP_MIN
  | OP_MAX
  | OP_WITHIN
  | -- Crypto
    OP_RIPEMD160
  | OP_SHA1
  | OP_SHA256
  | OP_HASH160
  | OP_HASH256
  | OP_CODESEPARATOR
  | OP_CHECKSIG
  | OP_CHECKSIGVERIFY
  | OP_CHECKMULTISIG
  | OP_CHECKMULTISIGVERIFY
  | -- Expansion
    OP_NOP1
  | OP_CHECKLOCKTIMEVERIFY
  | OP_CHECKSEQUENCEVERIFY
  | OP_NOP4
  | OP_NOP5
  | OP_NOP6
  | OP_NOP7
  | OP_NOP8
  | OP_NOP9
  | OP_NOP10
  | -- Bitcoin Cash Nov 2018 hard fork. Opcode 0xba is 'OP_CHECKSIGADD' in
    -- Tapscript (BIP 342), see the pattern synonym of that name.
    OP_CHECKDATASIG
  | OP_CHECKDATASIGVERIFY
  | -- Bitcoin Cash May 2020 hard fork
    OP_REVERSEBYTES
  | -- Bitcoin Cash May 2022 hard fork: native introspection, 0xc0 to 0xcd
    OP_INPUTINDEX
  | OP_ACTIVEBYTECODE
  | OP_TXVERSION
  | OP_TXINPUTCOUNT
  | OP_TXOUTPUTCOUNT
  | OP_TXLOCKTIME
  | OP_UTXOVALUE
  | OP_UTXOBYTECODE
  | OP_OUTPOINTTXHASH
  | OP_OUTPOINTINDEX
  | OP_INPUTBYTECODE
  | OP_INPUTSEQUENCENUMBER
  | OP_OUTPUTVALUE
  | OP_OUTPUTBYTECODE
  | -- Bitcoin Cash May 2023 hard fork: introspection of tokens, 0xce to 0xd3
    OP_UTXOTOKENCATEGORY
  | OP_UTXOTOKENCOMMITMENT
  | OP_UTXOTOKENAMOUNT
  | OP_OUTPUTTOKENCATEGORY
  | OP_OUTPUTTOKENCOMMITMENT
  | OP_OUTPUTTOKENAMOUNT
  | -- Reserved by Bitcoin Cash Node, 0xd4 and 0xd5
    OP_RESERVED3
  | OP_RESERVED4
  | -- Other
    OP_PUBKEYHASH
  | OP_PUBKEY
  | OP_INVALIDOPCODE !Word8
  deriving (Show, Read, Eq, Generic, Hashable, NFData)

-- | Opcode 0xba as Tapscript (BIP 342) names it. It is the same opcode as
-- 'OP_CHECKDATASIG' of Bitcoin Cash, so a value built with either name is
-- equal to the other and serializes to the same byte. 'Show' prints the
-- Bitcoin Cash name.
pattern OP_CHECKSIGADD :: ScriptOp
pattern OP_CHECKSIGADD = OP_CHECKDATASIG

-- | Opcode 0x65 as Bitcoin Cash names it: starts a loop (May 2026). It is
-- 'OP_VERIF' of Bitcoin, the same value.
pattern OP_BEGIN :: ScriptOp
pattern OP_BEGIN = OP_VERIF

-- | Opcode 0x66 as Bitcoin Cash names it: ends a loop (May 2026). It is
-- 'OP_VERNOTIF' of Bitcoin, the same value.
pattern OP_UNTIL :: ScriptOp
pattern OP_UNTIL = OP_VERNOTIF

-- | Opcode 0x7f as Bitcoin Cash names it: splits a byte string in two (May 2018). It is
-- 'OP_SUBSTR' of Bitcoin, the same value.
pattern OP_SPLIT :: ScriptOp
pattern OP_SPLIT = OP_SUBSTR

-- | Opcode 0x80 as Bitcoin Cash names it: pads a number to a size (May 2018). It is
-- 'OP_LEFT' of Bitcoin, the same value.
pattern OP_NUM2BIN :: ScriptOp
pattern OP_NUM2BIN = OP_LEFT

-- | Opcode 0x81 as Bitcoin Cash names it: reads a byte string as a minimal number (May 2018). It is
-- 'OP_RIGHT' of Bitcoin, the same value.
pattern OP_BIN2NUM :: ScriptOp
pattern OP_BIN2NUM = OP_RIGHT

-- | Opcode 0x89 as Bitcoin Cash names it: defines a function (May 2026). It is
-- 'OP_RESERVED1' of Bitcoin, the same value.
pattern OP_DEFINE :: ScriptOp
pattern OP_DEFINE = OP_RESERVED1

-- | Opcode 0x8a as Bitcoin Cash names it: calls a function (May 2026). It is
-- 'OP_RESERVED2' of Bitcoin, the same value.
pattern OP_INVOKE :: ScriptOp
pattern OP_INVOKE = OP_RESERVED2

-- | Opcode 0x8d as Bitcoin Cash names it: shifts a number left (May 2026). It is
-- 'OP_2MUL' of Bitcoin, the same value.
pattern OP_LSHIFTNUM :: ScriptOp
pattern OP_LSHIFTNUM = OP_2MUL

-- | Opcode 0x8e as Bitcoin Cash names it: shifts a number right (May 2026). It is
-- 'OP_2DIV' of Bitcoin, the same value.
pattern OP_RSHIFTNUM :: ScriptOp
pattern OP_RSHIFTNUM = OP_2DIV

-- | Opcode 0x98 as Bitcoin Cash names it: shifts a byte string left (May 2026). It is
-- 'OP_LSHIFT' of Bitcoin, the same value.
pattern OP_LSHIFTBIN :: ScriptOp
pattern OP_LSHIFTBIN = OP_LSHIFT

-- | Opcode 0x99 as Bitcoin Cash names it: shifts a byte string right (May 2026). It is
-- 'OP_RSHIFT' of Bitcoin, the same value.
pattern OP_RSHIFTBIN :: ScriptOp
pattern OP_RSHIFTBIN = OP_RSHIFT

-- | The name that the reference node of a network gives an opcode, as its
-- @GetOpName@ does in @src\/script\/script.cpp@: Bitcoin Core 32.1 on the
-- Bitcoin networks, Bitcoin Cash Node 29.2.0 on the Bitcoin Cash networks. A
-- network and its testnets share their names. These are the names that the
-- @asm@ of a decoded script shows in the RPC of each node, so a program that
-- prints scripts for one chain prints them as that chain does.
--
-- The twelve bytes that the chains name differently get the name of the
-- chain: 0x7f is @OP_SUBSTR@ on Bitcoin and @OP_SPLIT@ on Bitcoin Cash, and
-- 0xba is @OP_CHECKSIGADD@ on Bitcoin and @OP_CHECKDATASIG@ on Bitcoin Cash.
-- A byte that the node does not name is @OP_UNKNOWN@: on Bitcoin, the
-- opcodes that only Bitcoin Cash defines, and on both chains a direct push
-- of 1 to 75 bytes and the template bytes 'OP_PUBKEYHASH' and 'OP_PUBKEY'.
-- As upstream does, 'OP_0', 'OP_1NEGATE' and 'OP_1' to 'OP_16' are named by
-- their numbers, @0@, @-1@ and @1@ to @16@; 0xff is @OP_INVALIDOPCODE@ on
-- Bitcoin, and 0xef, the prefix of tokens, is @SPECIAL_TOKEN_PREFIX@ on
-- Bitcoin Cash.
--
-- 'Show' cannot depend on the network, so it prints the name of the
-- constructor, which is the Bitcoin name for the twelve bytes but 0xba. Use
-- this function to show an opcode to a user.
opName :: Network -> ScriptOp -> Text
opName net op = case op of
  OP_PUSHDATA _ OPCODE -> "OP_UNKNOWN"
  OP_PUSHDATA _ OPDATA1 -> "OP_PUSHDATA1"
  OP_PUSHDATA _ OPDATA2 -> "OP_PUSHDATA2"
  OP_PUSHDATA _ OPDATA4 -> "OP_PUSHDATA4"
  OP_0 -> "0"
  OP_1NEGATE -> "-1"
  OP_PUBKEYHASH -> "OP_UNKNOWN"
  OP_PUBKEY -> "OP_UNKNOWN"
  OP_INVALIDOPCODE b -> invalid b
  _
    | Right n <- scriptOpToInt op -> T.pack (show n)
    | bitcoinCash -> fromMaybe (T.pack (show op)) (lookup op bitcoinCashNames)
    | op == OP_CHECKDATASIG -> "OP_CHECKSIGADD"
    | bitcoinCashOnly -> "OP_UNKNOWN"
    | otherwise -> T.pack (show op)
  where
    bitcoinCash = isJust net.sigHashForkId
    bitcoinCashNames =
      [ (OP_BEGIN, "OP_BEGIN"),
        (OP_UNTIL, "OP_UNTIL"),
        (OP_SPLIT, "OP_SPLIT"),
        (OP_NUM2BIN, "OP_NUM2BIN"),
        (OP_BIN2NUM, "OP_BIN2NUM"),
        (OP_DEFINE, "OP_DEFINE"),
        (OP_INVOKE, "OP_INVOKE"),
        (OP_LSHIFTNUM, "OP_LSHIFTNUM"),
        (OP_RSHIFTNUM, "OP_RSHIFTNUM"),
        (OP_LSHIFTBIN, "OP_LSHIFTBIN"),
        (OP_RSHIFTBIN, "OP_RSHIFTBIN")
      ]
    -- The opcodes from 0xbb on, which Bitcoin Core does not define.
    bitcoinCashOnly = B.head (runPutS (serialize op)) >= 0xbb
    -- A byte without a constructor. One built by hand for a byte that has
    -- a constructor is named as that constructor.
    invalid b
      | b == 0x00 = "0"
      | b <= 0x4b = "OP_UNKNOWN"
      | b == 0x4c = "OP_PUSHDATA1"
      | b == 0x4d = "OP_PUSHDATA2"
      | b == 0x4e = "OP_PUSHDATA4"
      | b == 0xff, not bitcoinCash = "OP_INVALIDOPCODE"
      | b == 0xef, bitcoinCash = "SPECIAL_TOKEN_PREFIX"
      | Right named <- runGetS deserialize (B.singleton b),
        named /= OP_INVALIDOPCODE b =
          opName net named
      | otherwise = "OP_UNKNOWN"

instance Serial ScriptOp where
  {-# INLINEABLE serialize #-}
  {-# INLINEABLE deserialize #-}
  deserialize = go . fromIntegral =<< getWord8
    where
      go op
        | op == 0x00 = return OP_0
        | op <= 0x4b = do
            payload <- getByteString (fromIntegral op)
            return $ OP_PUSHDATA payload OPCODE
        | op == 0x4c = do
            len <- getWord8
            payload <- getByteString (fromIntegral len)
            return $ OP_PUSHDATA payload OPDATA1
        | op == 0x4d = do
            len <- getWord16le
            payload <- getByteString (fromIntegral len)
            return $ OP_PUSHDATA payload OPDATA2
        | op == 0x4e = do
            len <- getWord32le
            payload <- getByteString (fromIntegral len)
            return $ OP_PUSHDATA payload OPDATA4
        | op == 0x4f = return OP_1NEGATE
        | op == 0x50 = return OP_RESERVED
        | op == 0x51 = return OP_1
        | op == 0x52 = return OP_2
        | op == 0x53 = return OP_3
        | op == 0x54 = return OP_4
        | op == 0x55 = return OP_5
        | op == 0x56 = return OP_6
        | op == 0x57 = return OP_7
        | op == 0x58 = return OP_8
        | op == 0x59 = return OP_9
        | op == 0x5a = return OP_10
        | op == 0x5b = return OP_11
        | op == 0x5c = return OP_12
        | op == 0x5d = return OP_13
        | op == 0x5e = return OP_14
        | op == 0x5f = return OP_15
        | op == 0x60 = return OP_16
        -- Flow control
        | op == 0x61 = return OP_NOP
        | op == 0x62 = return OP_VER -- reserved
        | op == 0x63 = return OP_IF
        | op == 0x64 = return OP_NOTIF
        | op == 0x65 = return OP_VERIF -- reserved
        | op == 0x66 = return OP_VERNOTIF -- reserved
        | op == 0x67 = return OP_ELSE
        | op == 0x68 = return OP_ENDIF
        | op == 0x69 = return OP_VERIFY
        | op == 0x6a = return OP_RETURN
        -- Stack
        | op == 0x6b = return OP_TOALTSTACK
        | op == 0x6c = return OP_FROMALTSTACK
        | op == 0x6d = return OP_2DROP
        | op == 0x6e = return OP_2DUP
        | op == 0x6f = return OP_3DUP
        | op == 0x70 = return OP_2OVER
        | op == 0x71 = return OP_2ROT
        | op == 0x72 = return OP_2SWAP
        | op == 0x73 = return OP_IFDUP
        | op == 0x74 = return OP_DEPTH
        | op == 0x75 = return OP_DROP
        | op == 0x76 = return OP_DUP
        | op == 0x77 = return OP_NIP
        | op == 0x78 = return OP_OVER
        | op == 0x79 = return OP_PICK
        | op == 0x7a = return OP_ROLL
        | op == 0x7b = return OP_ROT
        | op == 0x7c = return OP_SWAP
        | op == 0x7d = return OP_TUCK
        -- Splice
        | op == 0x7e = return OP_CAT
        | op == 0x7f = return OP_SUBSTR
        | op == 0x80 = return OP_LEFT
        | op == 0x81 = return OP_RIGHT
        | op == 0x82 = return OP_SIZE
        -- Bitwise logic
        | op == 0x83 = return OP_INVERT
        | op == 0x84 = return OP_AND
        | op == 0x85 = return OP_OR
        | op == 0x86 = return OP_XOR
        | op == 0x87 = return OP_EQUAL
        | op == 0x88 = return OP_EQUALVERIFY
        | op == 0x89 = return OP_RESERVED1
        | op == 0x8a = return OP_RESERVED2
        -- Arithmetic
        | op == 0x8b = return OP_1ADD
        | op == 0x8c = return OP_1SUB
        | op == 0x8d = return OP_2MUL
        | op == 0x8e = return OP_2DIV
        | op == 0x8f = return OP_NEGATE
        | op == 0x90 = return OP_ABS
        | op == 0x91 = return OP_NOT
        | op == 0x92 = return OP_0NOTEQUAL
        | op == 0x93 = return OP_ADD
        | op == 0x94 = return OP_SUB
        | op == 0x95 = return OP_MUL
        | op == 0x96 = return OP_DIV
        | op == 0x97 = return OP_MOD
        | op == 0x98 = return OP_LSHIFT
        | op == 0x99 = return OP_RSHIFT
        | op == 0x9a = return OP_BOOLAND
        | op == 0x9b = return OP_BOOLOR
        | op == 0x9c = return OP_NUMEQUAL
        | op == 0x9d = return OP_NUMEQUALVERIFY
        | op == 0x9e = return OP_NUMNOTEQUAL
        | op == 0x9f = return OP_LESSTHAN
        | op == 0xa0 = return OP_GREATERTHAN
        | op == 0xa1 = return OP_LESSTHANOREQUAL
        | op == 0xa2 = return OP_GREATERTHANOREQUAL
        | op == 0xa3 = return OP_MIN
        | op == 0xa4 = return OP_MAX
        | op == 0xa5 = return OP_WITHIN
        -- Crypto
        | op == 0xa6 = return OP_RIPEMD160
        | op == 0xa7 = return OP_SHA1
        | op == 0xa8 = return OP_SHA256
        | op == 0xa9 = return OP_HASH160
        | op == 0xaa = return OP_HASH256
        | op == 0xab = return OP_CODESEPARATOR
        | op == 0xac = return OP_CHECKSIG
        | op == 0xad = return OP_CHECKSIGVERIFY
        | op == 0xae = return OP_CHECKMULTISIG
        | op == 0xaf = return OP_CHECKMULTISIGVERIFY
        -- More NOPs
        | op == 0xb0 = return OP_NOP1
        | op == 0xb1 = return OP_CHECKLOCKTIMEVERIFY
        | op == 0xb2 = return OP_CHECKSEQUENCEVERIFY
        | op == 0xb3 = return OP_NOP4
        | op == 0xb4 = return OP_NOP5
        | op == 0xb5 = return OP_NOP6
        | op == 0xb6 = return OP_NOP7
        | op == 0xb7 = return OP_NOP8
        | op == 0xb8 = return OP_NOP9
        | op == 0xb9 = return OP_NOP10
        -- Bitcoin Cash Nov 2018 hard fork
        | op == 0xba = return OP_CHECKDATASIG
        | op == 0xbb = return OP_CHECKDATASIGVERIFY
        -- Bitcoin Cash May 2020 hard fork
        | op == 0xbc = return OP_REVERSEBYTES
        -- Bitcoin Cash May 2022 and May 2023 hard forks
        | op == 0xc0 = return OP_INPUTINDEX
        | op == 0xc1 = return OP_ACTIVEBYTECODE
        | op == 0xc2 = return OP_TXVERSION
        | op == 0xc3 = return OP_TXINPUTCOUNT
        | op == 0xc4 = return OP_TXOUTPUTCOUNT
        | op == 0xc5 = return OP_TXLOCKTIME
        | op == 0xc6 = return OP_UTXOVALUE
        | op == 0xc7 = return OP_UTXOBYTECODE
        | op == 0xc8 = return OP_OUTPOINTTXHASH
        | op == 0xc9 = return OP_OUTPOINTINDEX
        | op == 0xca = return OP_INPUTBYTECODE
        | op == 0xcb = return OP_INPUTSEQUENCENUMBER
        | op == 0xcc = return OP_OUTPUTVALUE
        | op == 0xcd = return OP_OUTPUTBYTECODE
        | op == 0xce = return OP_UTXOTOKENCATEGORY
        | op == 0xcf = return OP_UTXOTOKENCOMMITMENT
        | op == 0xd0 = return OP_UTXOTOKENAMOUNT
        | op == 0xd1 = return OP_OUTPUTTOKENCATEGORY
        | op == 0xd2 = return OP_OUTPUTTOKENCOMMITMENT
        | op == 0xd3 = return OP_OUTPUTTOKENAMOUNT
        | op == 0xd4 = return OP_RESERVED3
        | op == 0xd5 = return OP_RESERVED4
        -- Constants
        | op == 0xfd = return OP_PUBKEYHASH
        | op == 0xfe = return OP_PUBKEY
        | otherwise = return $ OP_INVALIDOPCODE op

  serialize op = case op of
    (OP_PUSHDATA payload optype) -> do
      let len = B.length payload
      case optype of
        OPCODE -> do
          unless (len <= 0x4b) $
            error "OP_PUSHDATA OPCODE: Payload size too big"
          putWord8 $ fromIntegral len
        OPDATA1 -> do
          unless (len <= 0xff) $
            error "OP_PUSHDATA OPDATA1: Payload size too big"
          putWord8 0x4c
          putWord8 $ fromIntegral len
        OPDATA2 -> do
          unless (len <= 0xffff) $
            error "OP_PUSHDATA OPDATA2: Payload size too big"
          putWord8 0x4d
          putWord16le $ fromIntegral len
        OPDATA4 -> do
          unless (len <= 0xffffffff) $
            error "OP_PUSHDATA OPDATA4: Payload size too big"
          putWord8 0x4e
          putWord32le $ fromIntegral len
      putByteString payload

    -- Constants
    OP_0 -> putWord8 0x00
    OP_1NEGATE -> putWord8 0x4f
    OP_RESERVED -> putWord8 0x50
    OP_1 -> putWord8 0x51
    OP_2 -> putWord8 0x52
    OP_3 -> putWord8 0x53
    OP_4 -> putWord8 0x54
    OP_5 -> putWord8 0x55
    OP_6 -> putWord8 0x56
    OP_7 -> putWord8 0x57
    OP_8 -> putWord8 0x58
    OP_9 -> putWord8 0x59
    OP_10 -> putWord8 0x5a
    OP_11 -> putWord8 0x5b
    OP_12 -> putWord8 0x5c
    OP_13 -> putWord8 0x5d
    OP_14 -> putWord8 0x5e
    OP_15 -> putWord8 0x5f
    OP_16 -> putWord8 0x60
    -- Crypto Constants
    OP_PUBKEY -> putWord8 0xfe
    OP_PUBKEYHASH -> putWord8 0xfd
    -- Invalid Opcodes
    (OP_INVALIDOPCODE x) -> putWord8 x
    -- Flow Control
    OP_NOP -> putWord8 0x61
    OP_VER -> putWord8 0x62
    OP_IF -> putWord8 0x63
    OP_NOTIF -> putWord8 0x64
    OP_VERIF -> putWord8 0x65
    OP_VERNOTIF -> putWord8 0x66
    OP_ELSE -> putWord8 0x67
    OP_ENDIF -> putWord8 0x68
    OP_VERIFY -> putWord8 0x69
    OP_RETURN -> putWord8 0x6a
    -- Stack Operations
    OP_TOALTSTACK -> putWord8 0x6b
    OP_FROMALTSTACK -> putWord8 0x6c
    OP_2DROP -> putWord8 0x6d
    OP_2DUP -> putWord8 0x6e
    OP_3DUP -> putWord8 0x6f
    OP_2OVER -> putWord8 0x70
    OP_2ROT -> putWord8 0x71
    OP_2SWAP -> putWord8 0x72
    OP_IFDUP -> putWord8 0x73
    OP_DEPTH -> putWord8 0x74
    OP_DROP -> putWord8 0x75
    OP_DUP -> putWord8 0x76
    OP_NIP -> putWord8 0x77
    OP_OVER -> putWord8 0x78
    OP_PICK -> putWord8 0x79
    OP_ROLL -> putWord8 0x7a
    OP_ROT -> putWord8 0x7b
    OP_SWAP -> putWord8 0x7c
    OP_TUCK -> putWord8 0x7d
    -- Splice
    OP_CAT -> putWord8 0x7e
    OP_SUBSTR -> putWord8 0x7f
    OP_LEFT -> putWord8 0x80
    OP_RIGHT -> putWord8 0x81
    OP_SIZE -> putWord8 0x82
    -- Bitwise Logic
    OP_INVERT -> putWord8 0x83
    OP_AND -> putWord8 0x84
    OP_OR -> putWord8 0x85
    OP_XOR -> putWord8 0x86
    OP_EQUAL -> putWord8 0x87
    OP_EQUALVERIFY -> putWord8 0x88
    OP_RESERVED1 -> putWord8 0x89
    OP_RESERVED2 -> putWord8 0x8a
    -- Arithmetic
    OP_1ADD -> putWord8 0x8b
    OP_1SUB -> putWord8 0x8c
    OP_2MUL -> putWord8 0x8d
    OP_2DIV -> putWord8 0x8e
    OP_NEGATE -> putWord8 0x8f
    OP_ABS -> putWord8 0x90
    OP_NOT -> putWord8 0x91
    OP_0NOTEQUAL -> putWord8 0x92
    OP_ADD -> putWord8 0x93
    OP_SUB -> putWord8 0x94
    OP_MUL -> putWord8 0x95
    OP_DIV -> putWord8 0x96
    OP_MOD -> putWord8 0x97
    OP_LSHIFT -> putWord8 0x98
    OP_RSHIFT -> putWord8 0x99
    OP_BOOLAND -> putWord8 0x9a
    OP_BOOLOR -> putWord8 0x9b
    OP_NUMEQUAL -> putWord8 0x9c
    OP_NUMEQUALVERIFY -> putWord8 0x9d
    OP_NUMNOTEQUAL -> putWord8 0x9e
    OP_LESSTHAN -> putWord8 0x9f
    OP_GREATERTHAN -> putWord8 0xa0
    OP_LESSTHANOREQUAL -> putWord8 0xa1
    OP_GREATERTHANOREQUAL -> putWord8 0xa2
    OP_MIN -> putWord8 0xa3
    OP_MAX -> putWord8 0xa4
    OP_WITHIN -> putWord8 0xa5
    -- Crypto
    OP_RIPEMD160 -> putWord8 0xa6
    OP_SHA1 -> putWord8 0xa7
    OP_SHA256 -> putWord8 0xa8
    OP_HASH160 -> putWord8 0xa9
    OP_HASH256 -> putWord8 0xaa
    OP_CODESEPARATOR -> putWord8 0xab
    OP_CHECKSIG -> putWord8 0xac
    OP_CHECKSIGVERIFY -> putWord8 0xad
    OP_CHECKMULTISIG -> putWord8 0xae
    OP_CHECKMULTISIGVERIFY -> putWord8 0xaf
    -- More NOPs
    OP_NOP1 -> putWord8 0xb0
    OP_CHECKLOCKTIMEVERIFY -> putWord8 0xb1
    OP_CHECKSEQUENCEVERIFY -> putWord8 0xb2
    OP_NOP4 -> putWord8 0xb3
    OP_NOP5 -> putWord8 0xb4
    OP_NOP6 -> putWord8 0xb5
    OP_NOP7 -> putWord8 0xb6
    OP_NOP8 -> putWord8 0xb7
    OP_NOP9 -> putWord8 0xb8
    OP_NOP10 -> putWord8 0xb9
    -- Bitcoin Cash Nov 2018 hard fork
    OP_CHECKDATASIG -> putWord8 0xba
    OP_CHECKDATASIGVERIFY -> putWord8 0xbb
    -- Bitcoin Cash May 2020 hard fork
    OP_REVERSEBYTES -> putWord8 0xbc
    -- Bitcoin Cash May 2022 and May 2023 hard forks
    OP_INPUTINDEX -> putWord8 0xc0
    OP_ACTIVEBYTECODE -> putWord8 0xc1
    OP_TXVERSION -> putWord8 0xc2
    OP_TXINPUTCOUNT -> putWord8 0xc3
    OP_TXOUTPUTCOUNT -> putWord8 0xc4
    OP_TXLOCKTIME -> putWord8 0xc5
    OP_UTXOVALUE -> putWord8 0xc6
    OP_UTXOBYTECODE -> putWord8 0xc7
    OP_OUTPOINTTXHASH -> putWord8 0xc8
    OP_OUTPOINTINDEX -> putWord8 0xc9
    OP_INPUTBYTECODE -> putWord8 0xca
    OP_INPUTSEQUENCENUMBER -> putWord8 0xcb
    OP_OUTPUTVALUE -> putWord8 0xcc
    OP_OUTPUTBYTECODE -> putWord8 0xcd
    OP_UTXOTOKENCATEGORY -> putWord8 0xce
    OP_UTXOTOKENCOMMITMENT -> putWord8 0xcf
    OP_UTXOTOKENAMOUNT -> putWord8 0xd0
    OP_OUTPUTTOKENCATEGORY -> putWord8 0xd1
    OP_OUTPUTTOKENCOMMITMENT -> putWord8 0xd2
    OP_OUTPUTTOKENAMOUNT -> putWord8 0xd3
    OP_RESERVED3 -> putWord8 0xd4
    OP_RESERVED4 -> putWord8 0xd5

instance Binary ScriptOp where
  put = serialize
  get = deserialize

instance Serialize ScriptOp where
  put = serialize
  get = deserialize

-- | Check whether opcode is only data: 'OP_PUSHDATA', 'OP_0', 'OP_1NEGATE' or
-- one of 'OP_1' to 'OP_16'.
isPushOp :: ScriptOp -> Bool
isPushOp = isJust . pushOpData

-- | The data that a push opcode puts on the stack. 'OP_0' pushes the empty
-- string, 'OP_1' to 'OP_16' push one byte with that value, 'OP_1NEGATE'
-- pushes the byte 0x81, and 'OP_PUSHDATA' pushes its payload. Other opcodes
-- push nothing and give 'Nothing'.
pushOpData :: ScriptOp -> Maybe ByteString
pushOpData op = case op of
  OP_PUSHDATA bs _ -> Just bs
  OP_0 -> Just B.empty
  OP_1NEGATE -> Just (B.singleton 0x81)
  _ -> B.singleton . fromIntegral <$> either (const Nothing) Just (scriptOpToInt op)

-- | Is the opcode a push in its shortest encoding? This is the rule of
-- @CheckMinimalPush@ in Bitcoin Core, which the @MINIMALDATA@ policy flag
-- enforces: the empty string is 'OP_0', one byte from 1 to 16 is the matching
-- 'OP_1' to 'OP_16', the byte 0x81 is 'OP_1NEGATE', and other data uses the
-- smallest 'PushDataType' that holds it. An opcode that pushes nothing is not
-- a minimal push.
isMinimalPush :: ScriptOp -> Bool
isMinimalPush op = maybe False (\bs -> opPushData bs == op) (pushOpData op)

-- | Encode data as the push opcode of its minimal encoding, see
-- 'isMinimalPush'.
opPushData :: ByteString -> ScriptOp
opPushData bs
  | len == 0 = OP_0
  | len == 1, Right op <- intToScriptOp (fromIntegral (B.head bs)) = op
  | bs == B.singleton 0x81 = OP_1NEGATE
  | len <= 0x4b = OP_PUSHDATA bs OPCODE
  | len <= 0xff = OP_PUSHDATA bs OPDATA1
  | len <= 0xffff = OP_PUSHDATA bs OPDATA2
  | len <= 0xffffffff = OP_PUSHDATA bs OPDATA4
  | otherwise = error "opPushData: payload size too big"
  where
    len = B.length bs

-- | Transforms integers @[1 .. 16]@ to 'ScriptOp' @[OP_1 .. OP_16]@. Other
-- integers give a 'Left'.
intToScriptOp :: Int -> Either String ScriptOp
intToScriptOp i = case i of
  1 -> Right OP_1
  2 -> Right OP_2
  3 -> Right OP_3
  4 -> Right OP_4
  5 -> Right OP_5
  6 -> Right OP_6
  7 -> Right OP_7
  8 -> Right OP_8
  9 -> Right OP_9
  10 -> Right OP_10
  11 -> Right OP_11
  12 -> Right OP_12
  13 -> Right OP_13
  14 -> Right OP_14
  15 -> Right OP_15
  16 -> Right OP_16
  _ -> Left $ "intToScriptOp: invalid integer " ++ show i

-- | Decode 'ScriptOp' @[OP_1 .. OP_16]@ to integers @[1 .. 16]@. Other
-- opcodes give a 'Left'.
scriptOpToInt :: ScriptOp -> Either String Int
scriptOpToInt op = case op of
  OP_1 -> Right 1
  OP_2 -> Right 2
  OP_3 -> Right 3
  OP_4 -> Right 4
  OP_5 -> Right 5
  OP_6 -> Right 6
  OP_7 -> Right 7
  OP_8 -> Right 8
  OP_9 -> Right 9
  OP_10 -> Right 10
  OP_11 -> Right 11
  OP_12 -> Right 12
  OP_13 -> Right 13
  OP_14 -> Right 14
  OP_15 -> Right 15
  OP_16 -> Right 16
  _ -> Left $ "scriptOpToInt: invalid opcode " ++ show op
