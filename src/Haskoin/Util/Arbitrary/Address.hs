{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE TupleSections #-}

-- |
-- Module      : Haskoin.Test.Address
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
module Haskoin.Util.Arbitrary.Address where

import qualified Data.ByteString as B
import Data.Maybe (isJust)
import Haskoin.Address
import Haskoin.Network.Constants
import Haskoin.Network.Data
import Haskoin.Util.Arbitrary.Crypto
import Haskoin.Util.Arbitrary.Util
import Test.QuickCheck

-- | Arbitrary address of a Bitcoin Cash network: pay-to-public-key-hash,
-- pay-to-script-hash with either hash size, a token-aware address, or any
-- other CashAddr kind.
arbitraryBitcoinCashAddress :: Gen Address
arbitraryBitcoinCashAddress =
  oneof
    [ arbitraryPubKeyAddress,
      arbitraryScriptAddress,
      arbitraryScript32Address,
      arbitraryTokenAddress,
      arbitraryCashAddress
    ]

-- | Arbitrary address of a Bitcoin network, including pay-to-witness and
-- Taproot.
arbitraryBitcoinAddress :: Gen Address
arbitraryBitcoinAddress =
  oneof
    [ arbitraryPubKeyAddress,
      arbitraryScriptAddress,
      arbitraryWitnessPubKeyAddress,
      arbitraryWitnessScriptAddress,
      arbitraryTaprootAddress,
      arbitraryWitnessAddress
    ]

arbitraryAddress :: Network -> Gen Address
arbitraryAddress net =
  if isJust net.cashAddrPrefix
    then arbitraryBitcoinCashAddress
    else arbitraryBitcoinAddress

-- | Arbitrary valid combination of (Network, Address)
arbitraryNetAddress :: Gen (Network, Address)
arbitraryNetAddress = do
  net <- arbitraryNetwork
  addr <- arbitraryAddress net
  return (net, addr)

-- | Arbitrary pay-to-public-key-hash address.
arbitraryPubKeyAddress :: Gen Address
arbitraryPubKeyAddress = pubKeyAddress <$> arbitraryHash160

-- | Arbitrary pay-to-script-hash address.
arbitraryScriptAddress :: Gen Address
arbitraryScriptAddress = scriptAddress <$> arbitraryHash160

-- | Arbitrary pay-to-witness public key hash
arbitraryWitnessPubKeyAddress :: Gen Address
arbitraryWitnessPubKeyAddress = witnessPubKeyAddress <$> arbitraryHash160

-- | Arbitrary pay-to-witness script hash
arbitraryWitnessScriptAddress :: Gen Address
arbitraryWitnessScriptAddress = witnessScriptAddress <$> arbitraryHash256

arbitraryWitnessAddress :: Gen Address
arbitraryWitnessAddress = do
  ver <- choose (1, 16)
  len <- choose (2, 40)
  ws <- vectorOf len arbitrary
  let bs = B.pack ws
  case witnessAddress ver bs of
    Just a -> return a
    Nothing -> error "Error generating arbitrary WitnessAddress"

-- | Arbitrary Taproot address: witness version 1 with a 32-byte program.
-- 'arbitraryWitnessAddress' almost never draws that combination.
arbitraryTaprootAddress :: Gen Address
arbitraryTaprootAddress = do
  bs <- B.pack <$> vectorOf 32 arbitrary
  case witnessAddress 1 bs of
    Just a -> return a
    Nothing -> error "Error generating arbitrary Taproot address"

arbitraryScript32Address :: Gen Address
arbitraryScript32Address = script32Address <$> arbitraryHash256

-- | Arbitrary token-aware CashAddr that can be paid: type 2 with a 20-byte
-- hash, or type 3 with a 20-byte or a 32-byte hash.
arbitraryTokenAddress :: Gen Address
arbitraryTokenAddress = do
  (ver, len) <- elements [(2, 20), (3, 20), (3, 32)]
  bs <- B.pack <$> vectorOf len arbitrary
  case cashAddress ver bs of
    Just a -> return a
    Nothing -> error "Error generating arbitrary token-aware address"

arbitraryCashAddress :: Gen Address
arbitraryCashAddress = do
  ver <- choose (0, 15)
  len <- choose (0, 7)
  let lbs = [20, 24, 28, 32, 40, 48, 56, 64] !! len
  ws <- vectorOf lbs arbitrary
  let bs = B.pack ws
  case cashAddress ver bs of
    Just a -> return a
    Nothing -> error "Error generating arbitrary CashAddress"
