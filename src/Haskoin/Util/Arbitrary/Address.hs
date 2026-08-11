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

-- | Arbitrary pay-to-public-key-hash or pay-to-script-hash address.
arbitraryBitcoinCashAddress :: Gen Address
arbitraryBitcoinCashAddress =
  oneof
    [ arbitraryPubKeyAddress,
      arbitraryScriptAddress,
      arbitraryScript32Address,
      arbitraryCashAddress
    ]

-- | Arbitrary address including pay-to-witness
arbitraryBitcoinAddress :: Gen Address
arbitraryBitcoinAddress =
  oneof
    [ arbitraryPubKeyAddress,
      arbitraryScriptAddress,
      arbitraryWitnessPubKeyAddress,
      arbitraryWitnessScriptAddress,
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
arbitraryWitnessScriptAddress = witnessPubKeyAddress <$> arbitraryHash160

arbitraryWitnessAddress :: Gen Address
arbitraryWitnessAddress = do
  ver <- choose (1, 16)
  len <- choose (2, 40)
  ws <- vectorOf len arbitrary
  let bs = B.pack ws
  case witnessAddress ver bs of
    Just a -> return a
    Nothing -> error "Error generating arbitrary WitnessAddress"

arbitraryScript32Address :: Gen Address
arbitraryScript32Address = script32Address <$> arbitraryHash256

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
