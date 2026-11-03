{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module      : Haskoin.Test.Network
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
module Haskoin.Util.Arbitrary.Network where

import Data.Bits (shiftL)
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as C8
import Data.Sequence qualified as Seq
import Data.Word (Word16, Word32)
import Haskoin.Network
import Haskoin.Util.Arbitrary.Crypto
import Haskoin.Util.Arbitrary.Util
import Network.Socket (SockAddr (..))
import Test.QuickCheck

-- | Arbitrary 'VarInt'.
arbitraryVarInt :: Gen VarInt
arbitraryVarInt = VarInt <$> arbitrary

-- | Arbitrary 'VarString'.
arbitraryVarString :: Gen VarString
arbitraryVarString = VarString <$> arbitraryBS

-- | Arbitrary 'NetworkAddress'.
arbitraryNetworkAddress :: Gen NetworkAddress
arbitraryNetworkAddress = do
  s <- arbitrary
  a <- arbitrary
  p <- arbitrary
  d <-
    oneof
      [ do
          b <- arbitrary
          c <- arbitrary
          d <- arbitrary
          return $ SockAddrInet6 (fromIntegral p) 0 (a, b, c, d) 0,
        return $ SockAddrInet (fromIntegral (p :: Word16)) a
      ]
  let n = sockToHostAddress d
  return $ NetworkAddress s n

-- | Arbitrary 'NetworkAddressTime'.
arbitraryNetworkAddressTime :: Gen (Word32, NetworkAddress)
arbitraryNetworkAddressTime = (,) <$> arbitrary <*> arbitraryNetworkAddress

-- | Arbitrary 'AddressNetwork', known or unknown.
arbitraryAddressNetwork :: Gen AddressNetwork
arbitraryAddressNetwork =
  frequency
    [ (7, elements [AddrIPv4, AddrIPv6, AddrTorV2, AddrTorV3, AddrI2P, AddrCJDNS, AddrYggdrasil]),
      (1, AddrUnknown <$> choose (8, 255))
    ]

-- | Arbitrary 'NetworkAddressV2' with as many address bytes as its network
-- requires. An unknown network gets up to 'maxAddrV2Size' bytes.
arbitraryNetworkAddressV2 :: Gen NetworkAddressV2
arbitraryNetworkAddressV2 = do
  network <- arbitraryAddressNetwork
  len <- maybe (choose (0, fromIntegral maxAddrV2Size)) return (addressNetworkLength network)
  NetworkAddressV2
    <$> arbitrary
    <*> arbitrary
    <*> pure network
    <*> arbitraryBSn len
    <*> arbitrary

-- | Arbitrary 'AddrV2'.
arbitraryAddrV2 :: Gen AddrV2
arbitraryAddrV2 = AddrV2 <$> listOf arbitraryNetworkAddressV2

-- | Arbitrary 'InvType', including unknown types.
arbitraryInvType :: Gen InvType
arbitraryInvType =
  frequency
    [ ( 9,
        elements
          [ InvError,
            InvTx,
            InvBlock,
            InvMerkleBlock,
            InvCompactBlock,
            InvWTx,
            InvWitnessTx,
            InvWitnessBlock,
            InvWitnessMerkleBlock
          ]
      ),
      -- Types between the last plain one and the witness flag are unknown.
      (1, InvType <$> choose (6, 1 `shiftL` 30))
    ]

-- | Arbitrary 'InvVector'.
arbitraryInvVector :: Gen InvVector
arbitraryInvVector = InvVector <$> arbitraryInvType <*> arbitraryHash256

-- | Arbitrary non-empty 'Inv'.
arbitraryInv1 :: Gen Inv
arbitraryInv1 = Inv <$> listOf1 arbitraryInvVector

-- | Arbitrary 'Version' with a user agent that fits 'maxUserAgentLength'.
arbitraryVersion :: Gen Version
arbitraryVersion =
  Version
    <$> arbitrary
    <*> arbitrary
    <*> arbitrary
    <*> arbitraryNetworkAddress
    <*> arbitraryNetworkAddress
    <*> arbitrary
    <*> (VarString <$> (arbitraryBSn =<< choose (0, maxUserAgentLength)))
    <*> arbitrary
    <*> arbitrary

-- | Arbitrary non-empty 'Addr'.
arbitraryAddr1 :: Gen Addr
arbitraryAddr1 = Addr <$> listOf1 arbitraryNetworkAddressTime

-- | Arbitrary 'Alert' with random payload and signature. Signature is not
-- valid.
arbitraryAlert :: Gen Alert
arbitraryAlert = Alert <$> arbitraryVarString <*> arbitraryVarString

-- | Arbitrary 'FeeFilter'.
arbitraryFeeFilter :: Gen FeeFilter
arbitraryFeeFilter = FeeFilter <$> arbitrary

-- | Arbitrary 'SendTxRcncl'.
arbitrarySendTxRcncl :: Gen SendTxRcncl
arbitrarySendTxRcncl = SendTxRcncl <$> arbitrary <*> arbitrary

-- | Arbitrary 'Reject'.
arbitraryReject :: Gen Reject
arbitraryReject =
  Reject
    <$> arbitraryMessageCommand
    <*> arbitraryRejectCode
    <*> arbitraryVarString
    <*> arbitraryMaybe arbitraryHash256

-- | Arbitrary 'RejectCode', any of the eight.
arbitraryRejectCode :: Gen RejectCode
arbitraryRejectCode =
  elements
    [ RejectMalformed,
      RejectInvalid,
      RejectObsolete,
      RejectDuplicate,
      RejectNonStandard,
      RejectDust,
      RejectInsufficientFee,
      RejectCheckpoint
    ]

-- | Arbitrary non-empty 'GetData'.
arbitraryGetData :: Gen GetData
arbitraryGetData = GetData <$> listOf1 arbitraryInvVector

-- | Arbitrary 'NotFound'.
arbitraryNotFound :: Gen NotFound
arbitraryNotFound = NotFound <$> listOf1 arbitraryInvVector

-- | Arbitrary 'Ping'.
arbitraryPing :: Gen Ping
arbitraryPing = Ping <$> arbitrary

-- | Arbitrary 'Pong'.
arbitraryPong :: Gen Pong
arbitraryPong = Pong <$> arbitrary

-- | Arbitrary bloom filter flags.
arbitraryBloomFlags :: Gen BloomFlags
arbitraryBloomFlags =
  elements
    [ BloomUpdateNone,
      BloomUpdateAll,
      BloomUpdateP2PubKeyOnly
    ]

-- | Arbitrary bloom filter with random bits, within the limits a peer
-- accepts.
arbitraryBloomFilter :: Gen BloomFilter
arbitraryBloomFilter = do
  len <- choose (0, 1000)
  bytes <- vectorOf len arbitrary
  BloomFilter (Seq.fromList bytes)
    <$> choose (0, maxHashFuncs)
    <*> arbitrary
    <*> arbitraryBloomFlags

-- | Arbitrary 'FilterLoad'.
arbitraryFilterLoad :: Gen FilterLoad
arbitraryFilterLoad = FilterLoad <$> arbitraryBloomFilter

-- | Arbitrary 'FilterAdd' that fits 'maxFilterAddSize'.
arbitraryFilterAdd :: Gen FilterAdd
arbitraryFilterAdd = FilterAdd <$> (arbitraryBSn =<< choose (0, maxFilterAddSize))

-- | Arbitrary 'MessageCommand', known or not. An unknown command has one to
-- twelve printable ASCII characters and is not the name of a known one.
arbitraryMessageCommand :: Gen MessageCommand
arbitraryMessageCommand =
  frequency
    [ (36, elements knownCommands),
      (4, MCOther <$> arbitraryOtherCommand)
    ]
  where
    knownCommands =
      [ MCVersion,
        MCVerAck,
        MCAddr,
        MCAddrV2,
        MCSendAddrV2,
        MCInv,
        MCGetData,
        MCNotFound,
        MCGetBlocks,
        MCGetHeaders,
        MCTx,
        MCBlock,
        MCMerkleBlock,
        MCHeaders,
        MCGetAddr,
        MCFilterLoad,
        MCFilterAdd,
        MCFilterClear,
        MCPing,
        MCPong,
        MCAlert,
        MCMempool,
        MCReject,
        MCSendHeaders,
        MCFeeFilter,
        MCSendCmpct,
        MCCmpctBlock,
        MCGetBlockTxn,
        MCBlockTxn,
        MCGetCFilters,
        MCCFilter,
        MCGetCFHeaders,
        MCCFHeaders,
        MCGetCFCheckpt,
        MCCFCheckpt,
        MCWtxidRelay,
        MCSendTxRcncl
      ]

-- | Arbitrary command name that no known command uses: one to twelve
-- printable ASCII characters.
arbitraryOtherCommand :: Gen BS.ByteString
arbitraryOtherCommand = name `suchThat` unknown
  where
    name = do
      n <- choose (1, 12)
      C8.pack <$> vectorOf n (choose (' ', '~'))
    unknown s = case stringToCommand s of
      MCOther _ -> True
      _ -> False
