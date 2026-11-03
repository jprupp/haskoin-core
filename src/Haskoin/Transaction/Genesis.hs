{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Haskoin.Transaction.Genesis
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Coinbase transactions of the genesis blocks.
module Haskoin.Transaction.Genesis
  ( mainnetGenesisTx,
    testnet4GenesisTx,
    genesisCoinbase,
  )
where

import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Haskoin.Transaction.Common
import Haskoin.Util.Helpers (decodeHex)

-- | Build a genesis coinbase the way Bitcoin Core's @CreateGenesisBlock@
-- does: version 1, one input that spends nothing, one output of 50 BTC and a
-- lock time of zero.
genesisCoinbase ::
  -- | input script: the bits, the number 4 and the message
  ByteString ->
  -- | output script
  ByteString ->
  Tx
genesisCoinbase inputScript outputScript =
  Tx 1 [TxIn (OutPoint nullHash maxBound) inputScript maxBound] [TxOut 5000000000 outputScript] [] 0
  where
    nullHash = "0000000000000000000000000000000000000000000000000000000000000000"

-- | Coinbase of the Bitcoin genesis block. Every network except Bitcoin
-- testnet4 reuses it. Its hash is
-- @4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b@.
mainnetGenesisTx :: Tx
mainnetGenesisTx =
  genesisCoinbase
    ( hex
        "04ffff001d0104455468652054696d65732030332f4a616e2f323030392043686\
        \16e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f\
        \757420666f722062616e6b73"
    )
    ( hex
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61d\
        \eb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d\
        \5fac"
    )

-- | Coinbase of the Bitcoin testnet4 genesis block. The message is
-- @03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e@
-- and the output pays to a public key of 33 zero bytes. Its hash is
-- @7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e@.
testnet4GenesisTx :: Tx
testnet4GenesisTx =
  genesisCoinbase
    ( hex
        "04ffff001d01044c4c30332f4d61792f32303234203030303030303030303030\
        \3030303030303030303165626435386332343439373062336161396437383362\
        \623030313031316662653865613865393865303065"
    )
    (hex "21000000000000000000000000000000000000000000000000000000000000000000ac")

hex :: Text -> ByteString
hex = fromMaybe (error "genesis script is not valid hex") . decodeHex
