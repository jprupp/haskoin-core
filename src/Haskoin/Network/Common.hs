{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Common
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Common functions and data types related to peer-to-peer network.
module Haskoin.Network.Common
  ( -- * Network Data Types
    Addr (..),
    NetworkAddressTime,
    AddrV2 (..),
    NetworkAddressV2 (..),
    AddressNetwork (..),
    addressNetworkId,
    addressNetworkLength,
    maxAddrV2Size,
    toNetworkAddressV2,
    fromNetworkAddressV2,
    Alert (..),
    FeeFilter (..),
    GetData (..),
    Inv (..),
    InvVector (..),
    InvType (..),
    HostAddress,
    hostToSockAddr,
    sockToHostAddress,
    NetworkAddress (..),
    NotFound (..),
    Ping (..),
    Pong (..),
    Reject (..),
    RejectCode (..),
    SendTxRcncl (..),
    VarInt (..),
    VarString (..),
    Version (..),
    maxUserAgentLength,
    MessageCommand (..),
    reject,
    nodeNone,
    nodeNetwork,
    nodeGetUTXO,
    nodeBloom,
    nodeWitness,
    nodeXThin,
    nodeCompactFilters,
    nodeNetworkLimited,
    nodeP2PV2,
    commandToString,
    stringToCommand,
    putVarInt,
    getVarIntList,
    putVarIntList,
    getVarIntBytes,
    putVarIntBytes,
    maxListSize,
  )
where

import Control.DeepSeq
import Control.Monad (forM_, liftM2, replicateM, unless, when)
import Data.Binary (Binary (..))
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Serialize (Serialize (..))
import Data.String
import Data.String.Conversions (cs)
import Data.Word (Word16, Word32, Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Crypto.Hash
import Network.Socket (SockAddr (..))
import Text.Read as R

-- | Network address with a timestamp.
type NetworkAddressTime = (Word32, NetworkAddress)

-- | Provides information about known nodes in the bitcoin network. An 'Addr'
-- type is sent inside a 'Message' as a response to a 'GetAddr' message.
newtype Addr = Addr
  { -- List of addresses of other nodes on the network with timestamps.
    list :: [NetworkAddressTime]
  }
  deriving (Eq, Show, Generic)
  deriving newtype (NFData)

instance Serial Addr where
  deserialize = Addr <$> getVarIntList action
    where
      action = liftM2 (,) getWord32le deserialize

  serialize (Addr xs) = do
    putVarInt $ length xs
    forM_ xs $ \(a, b) -> putWord32le a >> serialize b

instance Binary Addr where
  get = deserialize
  put = serialize

instance Serialize Addr where
  get = deserialize
  put = serialize

-- | Network that an 'addrv2' address belongs to (BIP 155).
data AddressNetwork
  = -- | IPv4, 4 address bytes
    AddrIPv4
  | -- | IPv6, 16 address bytes
    AddrIPv6
  | -- | Tor v2, 10 address bytes. No longer in use.
    AddrTorV2
  | -- | Tor v3, 32 address bytes
    AddrTorV3
  | -- | I2P, 32 address bytes
    AddrI2P
  | -- | CJDNS, 16 address bytes
    AddrCJDNS
  | -- | Yggdrasil, 16 address bytes
    AddrYggdrasil
  | -- | a network identifier this library does not know
    AddrUnknown Word8
  deriving (Eq, Show, Read, Generic, NFData)

-- | Network identifier byte of BIP 155.
addressNetworkId :: AddressNetwork -> Word8
addressNetworkId AddrIPv4 = 1
addressNetworkId AddrIPv6 = 2
addressNetworkId AddrTorV2 = 3
addressNetworkId AddrTorV3 = 4
addressNetworkId AddrI2P = 5
addressNetworkId AddrCJDNS = 6
addressNetworkId AddrYggdrasil = 7
addressNetworkId (AddrUnknown w) = w

-- | Network of a BIP 155 identifier byte.
addressNetwork :: Word8 -> AddressNetwork
addressNetwork 1 = AddrIPv4
addressNetwork 2 = AddrIPv6
addressNetwork 3 = AddrTorV2
addressNetwork 4 = AddrTorV3
addressNetwork 5 = AddrI2P
addressNetwork 6 = AddrCJDNS
addressNetwork 7 = AddrYggdrasil
addressNetwork w = AddrUnknown w

-- | Number of address bytes that BIP 155 requires for a network, if known.
addressNetworkLength :: AddressNetwork -> Maybe Int
addressNetworkLength AddrIPv4 = Just 4
addressNetworkLength AddrIPv6 = Just 16
addressNetworkLength AddrTorV2 = Just 10
addressNetworkLength AddrTorV3 = Just 32
addressNetworkLength AddrI2P = Just 32
addressNetworkLength AddrCJDNS = Just 16
addressNetworkLength AddrYggdrasil = Just 16
addressNetworkLength (AddrUnknown _) = Nothing

-- | Longest address that an 'addrv2' entry may carry, in bytes (BIP 155).
maxAddrV2Size :: Word64
maxAddrV2Size = 512

-- | An entry of an 'addrv2' message (BIP 155).
data NetworkAddressV2 = NetworkAddressV2
  { -- | time this node was last seen
    time :: !Word32,
    -- | bitmask of services available for this address
    services :: !Word64,
    -- | network the address belongs to
    network :: !AddressNetwork,
    -- | address bytes, as many as the network requires
    address :: !ByteString,
    -- | port, or 0 when the network has none
    port :: !Word16
  }
  deriving (Eq, Show, Read, Generic, NFData)

-- | An entry fails to parse when its address is longer than 'maxAddrV2Size'
-- or does not have the length its network requires. Entries of unknown
-- networks are kept with their bytes.
instance Serial NetworkAddressV2 where
  deserialize = do
    time <- getWord32le
    VarInt services <- deserialize
    network <- addressNetwork <$> getWord8
    VarInt len <- deserialize
    when (len > maxAddrV2Size) $
      fail ("addrv2 address too long: " ++ show len)
    address <- getByteString (fromIntegral len)
    forM_ (addressNetworkLength network) $ \expected ->
      unless (B.length address == expected) $
        fail $
          unwords
            [ "addrv2 address of",
              show (B.length address),
              "bytes for",
              show network,
              "(should be",
              show expected ++ ")"
            ]
    port <- getWord16be
    return NetworkAddressV2 {time, services, network, address, port}

  serialize a = do
    putWord32le a.time
    putVarInt a.services
    putWord8 (addressNetworkId a.network)
    putVarIntBytes a.address
    putWord16be a.port

instance Binary NetworkAddressV2 where
  get = deserialize
  put = serialize

instance Serialize NetworkAddressV2 where
  get = deserialize
  put = serialize

-- | The 'addrv2' message (BIP 155). It replaces 'Addr' once both peers have
-- sent @sendaddrv2@, and can carry Tor, I2P and CJDNS addresses.
newtype AddrV2 = AddrV2
  { list :: [NetworkAddressV2]
  }
  deriving (Eq, Show, Generic)
  deriving newtype (NFData)

instance Serial AddrV2 where
  deserialize = AddrV2 <$> getVarIntList deserialize
  serialize (AddrV2 xs) = putVarIntList serialize xs

instance Binary AddrV2 where
  get = deserialize
  put = serialize

instance Serialize AddrV2 where
  get = deserialize
  put = serialize

-- | Prefix of an IPv4-mapped IPv6 address.
ipv4Prefix :: ByteString
ipv4Prefix = B.replicate 10 0 <> B.pack [0xff, 0xff]

-- | The 'addrv2' form of an 'addr' entry. An IPv4-mapped address becomes an
-- 'AddrIPv4' entry with four address bytes. Any other address is IPv6.
toNetworkAddressV2 :: NetworkAddressTime -> NetworkAddressV2
toNetworkAddressV2 (t, NetworkAddress s (HostAddress bs)) =
  NetworkAddressV2 {time = t, services = s, network, address, port}
  where
    ip = B.take 16 bs
    port =
      (fromIntegral (B.index bs 16) `shiftL` 8)
        .|. fromIntegral (B.index bs 17)
    (network, address)
      | B.take 12 ip == ipv4Prefix = (AddrIPv4, B.drop 12 ip)
      | otherwise = (AddrIPv6, ip)

-- | The 'addr' form of an 'addrv2' entry. Only IPv4 and IPv6 entries have
-- one. Tor, I2P and CJDNS addresses do not fit the 'addr' message.
fromNetworkAddressV2 :: NetworkAddressV2 -> Maybe NetworkAddressTime
fromNetworkAddressV2 a =
  case a.network of
    AddrIPv4 -> Just (entry (ipv4Prefix <> a.address))
    AddrIPv6 -> Just (entry a.address)
    _ -> Nothing
  where
    entry ip = (a.time, NetworkAddress a.services (HostAddress (ip <> portBytes)))
    portBytes = B.pack [fromIntegral (a.port `shiftR` 8), fromIntegral a.port]

-- | Data type describing signed messages that can be sent between bitcoin
-- nodes to display important notifications to end users about the health of
-- the network.
data Alert = Alert
  { -- | Alert payload.
    payload :: !VarString,
    -- | ECDSA signature of the payload
    signature :: !VarString
  }
  deriving (Eq, Show, Read, Generic, NFData)

instance Serial Alert where
  deserialize = Alert <$> deserialize <*> deserialize
  serialize (Alert p s) = serialize p >> serialize s

instance Binary Alert where
  put = serialize
  get = deserialize

instance Serialize Alert where
  put = serialize
  get = deserialize

-- | The 'feefilter' message (BIP 133). The peer asks not to be sent
-- transactions that pay less than this fee rate.
newtype FeeFilter = FeeFilter
  { -- | minimum fee rate in satoshi per 1000 bytes
    feeRate :: Word64
  }
  deriving (Eq, Show, Read, Generic)
  deriving newtype (NFData)

instance Serial FeeFilter where
  deserialize = FeeFilter <$> getWord64le
  serialize (FeeFilter r) = putWord64le r

instance Binary FeeFilter where
  put = serialize
  get = deserialize

instance Serialize FeeFilter where
  put = serialize
  get = deserialize

-- | The 'GetData' type is used to retrieve information on a specific object
-- ('Block' or 'Tx') identified by the objects hash. The payload of a 'GetData'
-- request is a list of 'InvVector' which represent all the hashes of objects
-- that a node wants. The response to a 'GetBlock' message will be either a
-- 'Block' or a 'Tx' message depending on the type of the object referenced by
-- the hash. Usually, 'GetData' messages are sent after a node receives an 'Inv'
-- message that contains unknown object hashes.
newtype GetData = GetData
  { -- | list of object hashes
    list :: [InvVector]
  }
  deriving (Eq, Show, Generic)
  deriving newtype (NFData)

instance Serial GetData where
  deserialize = GetData <$> getVarIntList deserialize

  serialize (GetData xs) = do
    putVarInt $ length xs
    forM_ xs serialize

instance Binary GetData where
  get = deserialize
  put = serialize

instance Serialize GetData where
  get = deserialize
  put = serialize

-- | 'Inv' messages are used by nodes to advertise their knowledge of new
-- objects by publishing a list of hashes to a peer. 'Inv' messages can be sent
-- unsolicited or in response to a 'GetBlocks' message.
newtype Inv = Inv
  { -- | inventory
    list :: [InvVector]
  }
  deriving (Eq, Show, Generic)
  deriving newtype (NFData)

instance Serial Inv where
  deserialize = Inv <$> getVarIntList deserialize

  serialize (Inv xs) = do
    putVarInt $ length xs
    forM_ xs serialize

instance Binary Inv where
  get = deserialize
  put = serialize

instance Serialize Inv where
  get = deserialize
  put = serialize

-- | Data type identifying the type of an inventory vector. SegWit types are
-- only used in 'GetData' messages, not 'Inv'.
data InvType
  = -- | error
    InvError
  | -- | transaction
    InvTx
  | -- | block
    InvBlock
  | -- | filtered block
    InvMerkleBlock
  | -- | compact block (BIP 152)
    InvCompactBlock
  | -- | transaction identified by its witness transaction id (BIP 339)
    InvWTx
  | -- | segwit transaction
    InvWitnessTx
  | -- | segwit block
    InvWitnessBlock
  | -- | segwit filtered block
    InvWitnessMerkleBlock
  | -- | unknown inv type
    InvType Word32
  deriving (Eq, Show, Read, Generic, NFData)

instance Serial InvType where
  deserialize = go =<< getWord32le
    where
      go x =
        case x of
          0 -> return InvError
          1 -> return InvTx
          2 -> return InvBlock
          3 -> return InvMerkleBlock
          4 -> return InvCompactBlock
          5 -> return InvWTx
          _
            | x == 1 `shiftL` 30 + 1 -> return InvWitnessTx
            | x == 1 `shiftL` 30 + 2 -> return InvWitnessBlock
            | x == 1 `shiftL` 30 + 3 -> return InvWitnessMerkleBlock
            | otherwise -> return (InvType x)
  serialize x =
    putWord32le $
      case x of
        InvError -> 0
        InvTx -> 1
        InvBlock -> 2
        InvMerkleBlock -> 3
        InvCompactBlock -> 4
        InvWTx -> 5
        InvWitnessTx -> 1 `shiftL` 30 + 1
        InvWitnessBlock -> 1 `shiftL` 30 + 2
        InvWitnessMerkleBlock -> 1 `shiftL` 30 + 3
        InvType w -> w

instance Binary InvType where
  get = deserialize
  put = serialize

instance Serialize InvType where
  get = deserialize
  put = serialize

-- | Invectory vectors represent hashes identifying objects such as a 'Block' or
-- a 'Tx'. They notify other peers about new data or data they have otherwise
-- requested.
data InvVector = InvVector
  { -- | type of object
    invType :: !InvType,
    -- | 256-bit hash of object
    invHash :: !Hash256
  }
  deriving (Eq, Show, Generic, NFData)

instance Serial InvVector where
  deserialize = InvVector <$> deserialize <*> deserialize
  serialize (InvVector t h) = serialize t >> serialize h

instance Binary InvVector where
  get = deserialize
  put = serialize

instance Serialize InvVector where
  get = deserialize
  put = serialize

-- | Sixteen address bytes followed by a big-endian port, the 18-byte address
-- of the 'addr' and 'version' messages.
newtype HostAddress
  = HostAddress ByteString
  deriving (Eq, Show, Ord, Generic)
  deriving newtype (NFData)

instance Serial HostAddress where
  serialize (HostAddress bs) = putByteString bs
  deserialize = HostAddress <$> getByteString 18

instance Binary HostAddress where
  get = deserialize
  put = serialize

instance Serialize HostAddress where
  get = deserialize
  put = serialize

-- | Data type describing a bitcoin network address. Addresses are stored in
-- IPv6 format. IPv4 addresses are mapped to IPv6 using IPv4 mapped IPv6
-- addresses: <http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses>.
data NetworkAddress = NetworkAddress
  { -- | bitmask of services available for this address
    services :: !Word64,
    -- | address and port information
    address :: !HostAddress
  }
  deriving (Eq, Show, Generic, NFData)

hostToSockAddr :: HostAddress -> SockAddr
hostToSockAddr (HostAddress bs) =
  case runGetS getSockAddr bs of
    Left e -> error e
    Right x -> x

sockToHostAddress :: SockAddr -> HostAddress
sockToHostAddress = HostAddress . runPutS . putSockAddr

putSockAddr :: (MonadPut m) => SockAddr -> m ()
putSockAddr (SockAddrInet6 p _ (a, b, c, d) _) = do
  putWord32be a
  putWord32be b
  putWord32be c
  putWord32be d
  putWord16be (fromIntegral p)
putSockAddr (SockAddrInet p a) = do
  putWord32be 0x00000000
  putWord32be 0x00000000
  putWord32be 0x0000ffff
  putWord32host a
  putWord16be (fromIntegral p)
putSockAddr _ = error "Invalid address type"

getSockAddr :: (MonadGet m) => m SockAddr
getSockAddr = do
  a <- getWord32be
  b <- getWord32be
  c <- getWord32be
  if a == 0x00000000 && b == 0x00000000 && c == 0x0000ffff
    then do
      d <- getWord32host
      p <- getWord16be
      return $ SockAddrInet (fromIntegral p) d
    else do
      d <- getWord32be
      p <- getWord16be
      return $ SockAddrInet6 (fromIntegral p) 0 (a, b, c, d) 0

instance Serial NetworkAddress where
  deserialize = NetworkAddress <$> getWord64le <*> deserialize
  serialize (NetworkAddress s a) = putWord64le s >> serialize a

instance Binary NetworkAddress where
  get = deserialize
  put = serialize

instance Serialize NetworkAddress where
  get = deserialize
  put = serialize

-- | A 'NotFound' message is returned as a response to a 'GetData' message
-- whe one of the requested objects could not be retrieved. This could happen,
-- for example, if a tranasaction was requested and was not available in the
-- memory pool of the receiving node.
newtype NotFound = NotFound
  { -- | Inventory vectors related to this request
    list :: [InvVector]
  }
  deriving (Eq, Show, Generic)
  deriving newtype (NFData)

instance Serial NotFound where
  deserialize = NotFound <$> getVarIntList deserialize

  serialize (NotFound xs) = do
    putVarInt $ length xs
    forM_ xs serialize

instance Binary NotFound where
  get = deserialize
  put = serialize

instance Serialize NotFound where
  get = deserialize
  put = serialize

-- | A 'Ping' message is sent to bitcoin peers to check if a connection is still
-- open.
newtype Ping = Ping
  { -- | A random nonce used to identify the recipient of the ping
    -- request once a Pong response is received.
    nonce :: Word64
  }
  deriving (Eq, Show, Read, Generic)
  deriving newtype (NFData)

-- | A Pong message is sent as a response to a ping message.
newtype Pong = Pong
  { -- | nonce from corresponding 'Ping'
    nonce :: Word64
  }
  deriving (Eq, Show, Read, Generic)
  deriving newtype (NFData)

instance Serial Ping where
  deserialize = Ping <$> getWord64le
  serialize (Ping n) = putWord64le n

instance Serial Pong where
  deserialize = Pong <$> getWord64le
  serialize (Pong n) = putWord64le n

instance Binary Ping where
  get = deserialize
  put = serialize

instance Binary Pong where
  get = deserialize
  put = serialize

instance Serialize Ping where
  get = deserialize
  put = serialize

instance Serialize Pong where
  get = deserialize
  put = serialize

-- | The 'Reject' message is sent when messages are rejected by a peer.
data Reject = Reject
  { -- | type of message rejected
    message :: !MessageCommand,
    -- | rejection code
    code :: !RejectCode,
    -- | text reason for rejection
    reason :: !VarString,
    -- | hash of the rejected block or transaction, when the peer gives one
    extra :: !(Maybe Hash256)
  }
  deriving (Eq, Show, Read, Generic, NFData)

-- | Rejection code associated to the 'Reject' message.
data RejectCode
  = RejectMalformed
  | RejectInvalid
  | RejectObsolete
  | RejectDuplicate
  | RejectNonStandard
  | RejectDust
  | RejectInsufficientFee
  | RejectCheckpoint
  deriving (Eq, Show, Read, Generic, NFData)

instance Serial RejectCode where
  deserialize =
    getWord8 >>= \code -> case code of
      0x01 -> return RejectMalformed
      0x10 -> return RejectInvalid
      0x11 -> return RejectObsolete
      0x12 -> return RejectDuplicate
      0x40 -> return RejectNonStandard
      0x41 -> return RejectDust
      0x42 -> return RejectInsufficientFee
      0x43 -> return RejectCheckpoint
      _ ->
        fail $
          unwords
            [ "Reject get: Invalid code",
              show code
            ]

  serialize code = putWord8 $ case code of
    RejectMalformed -> 0x01
    RejectInvalid -> 0x10
    RejectObsolete -> 0x11
    RejectDuplicate -> 0x12
    RejectNonStandard -> 0x40
    RejectDust -> 0x41
    RejectInsufficientFee -> 0x42
    RejectCheckpoint -> 0x43

instance Binary RejectCode where
  put = serialize
  get = deserialize

instance Serialize RejectCode where
  put = serialize
  get = deserialize

-- | Convenience function to build a 'Reject' message without a hash.
reject :: MessageCommand -> RejectCode -> ByteString -> Reject
reject cmd code reason =
  Reject cmd code (VarString reason) Nothing

instance Serial Reject where
  deserialize =
    deserialize >>= \(VarString bs) ->
      Reject (stringToCommand bs)
        <$> deserialize
        <*> deserialize
        <*> maybeHash
    where
      maybeHash =
        isEmpty >>= \done ->
          if done
            then return Nothing
            else Just <$> deserialize
  serialize (Reject cmd code reason extra) = do
    serialize $ VarString $ commandToString cmd
    serialize code
    serialize reason
    forM_ extra serialize

instance Binary Reject where
  put = serialize
  get = deserialize

instance Serialize Reject where
  put = serialize
  get = deserialize

-- | The 'sendtxrcncl' message (BIP 330). It announces support for
-- transaction reconciliation.
data SendTxRcncl = SendTxRcncl
  { -- | reconciliation protocol version
    version :: !Word32,
    -- | salt for the short transaction identifiers
    salt :: !Word64
  }
  deriving (Eq, Show, Read, Generic, NFData)

instance Serial SendTxRcncl where
  deserialize = SendTxRcncl <$> getWord32le <*> getWord64le
  serialize (SendTxRcncl v s) = putWord32le v >> putWord64le s

instance Binary SendTxRcncl where
  put = serialize
  get = deserialize

instance Serialize SendTxRcncl where
  put = serialize
  get = deserialize

-- | Data type representing a variable-length integer. The 'VarInt' type
-- usually precedes an array or a string that can vary in length.
newtype VarInt = VarInt {get :: Word64}
  deriving (Eq, Show, Read, Generic)
  deriving newtype (NFData)

-- | Only the shortest encoding of a value is accepted, as in the
-- @ReadCompactSize@ function of Bitcoin Core. A value below 253 must use one
-- byte, below 0x10000 three bytes, and below 0x100000000 five bytes.
instance Serial VarInt where
  deserialize = VarInt <$> (getWord8 >>= go)
    where
      go 0xff = do
        x <- getWord64le
        when (x < 0x100000000) $ nonCanonical 9 x
        return x
      go 0xfe = do
        x <- getWord32le
        when (x < 0x10000) $ nonCanonical 5 x
        return $ fromIntegral x
      go 0xfd = do
        x <- getWord16le
        when (x < 0xfd) $ nonCanonical 3 x
        return $ fromIntegral x
      go x = return $ fromIntegral x
      nonCanonical :: (MonadGet m, Show a) => Int -> a -> m ()
      nonCanonical n x =
        fail $
          unwords
            [ "VarInt: non-canonical",
              show n ++ "-byte encoding of",
              show x
            ]

  serialize (VarInt x)
    | x < 0xfd =
        putWord8 $ fromIntegral x
    | x <= 0xffff = do
        putWord8 0xfd
        putWord16le $ fromIntegral x
    | x <= 0xffffffff = do
        putWord8 0xfe
        putWord32le $ fromIntegral x
    | otherwise = do
        putWord8 0xff
        putWord64le x

instance Binary VarInt where
  put = serialize
  get = deserialize

instance Serialize VarInt where
  put = serialize
  get = deserialize

putVarInt :: (MonadPut m, Integral a) => a -> m ()
putVarInt = serialize . VarInt . fromIntegral

-- | Largest number of elements that a serialized list may announce, and
-- largest number of bytes that a serialized string may announce. Bitcoin Core
-- refuses larger counts when it reads a compact size (@MAX_SIZE@).
maxListSize :: Word64
maxListSize = 0x02000000

-- | Read a list that starts with its element count as a 'VarInt'. A count
-- above 'maxListSize' fails the parse. Without this check a huge count would
-- wrap around to a negative 'Int' and read as an empty list.
getVarIntList :: (MonadGet m) => m a -> m [a]
getVarIntList element = do
  VarInt count <- deserialize
  when (count > maxListSize) $
    fail ("List count too large: " ++ show count)
  replicateM (fromIntegral count) element

-- | Write a list with its element count as a 'VarInt' in front.
putVarIntList :: (MonadPut m) => (a -> m ()) -> [a] -> m ()
putVarIntList element xs = do
  putVarInt (length xs)
  mapM_ element xs

-- | Read bytes that start with their count as a 'VarInt'. A count above
-- 'maxListSize' fails the parse.
getVarIntBytes :: (MonadGet m) => m ByteString
getVarIntBytes = do
  VarInt count <- deserialize
  when (count > maxListSize) $
    fail ("Byte count too large: " ++ show count)
  getByteString (fromIntegral count)

-- | Write bytes with their count as a 'VarInt' in front.
putVarIntBytes :: (MonadPut m) => ByteString -> m ()
putVarIntBytes bs = do
  putVarInt (B.length bs)
  putByteString bs

-- | Data type for serialization of variable-length strings.
newtype VarString = VarString {get :: ByteString}
  deriving (Eq, Show, Read, Generic)
  deriving newtype (NFData)

instance Serial VarString where
  deserialize = VarString <$> getVarIntBytes
  serialize (VarString bs) = putVarIntBytes bs

instance Binary VarString where
  put = serialize
  get = deserialize

instance Serialize VarString where
  put = serialize
  get = deserialize

-- | Longest user agent that a 'Version' message may carry, in bytes. Bitcoin
-- Core disconnects a peer that sends a longer one (@MAX_SUBVERSION_LENGTH@).
maxUserAgentLength :: Int
maxUserAgentLength = 256

-- | When a bitcoin node creates an outgoing connection to another node,
-- the first message it will send is a 'Version' message. The other node
-- will similarly respond with it's own 'Version' message.
data Version = Version
  { -- | protocol version
    version :: !Word32,
    -- | features supported by this connection
    services :: !Word64,
    -- | unix timestamp
    timestamp :: !Word64,
    -- | network address of remote node
    addrRecv :: !NetworkAddress,
    -- | network address of sending node
    addrSend :: !NetworkAddress,
    -- | random nonce to detect connection to self
    nonce :: !Word64,
    -- | user agent string
    userAgent :: !VarString,
    -- | height of the last block in sending node
    startHeight :: !Word32,
    -- | relay transactions flag (BIP-37)
    relay :: !Bool
  }
  deriving (Eq, Show, Generic, NFData)

-- | A user agent longer than 'maxUserAgentLength' fails the parse. The relay
-- flag is 'True' when the message ends before it, as for peers that predate
-- BIP 37.
instance Serial Version where
  deserialize =
    Version
      <$> getWord32le
      <*> getWord64le
      <*> getWord64le
      <*> deserialize
      <*> deserialize
      <*> getWord64le
      <*> userAgent
      <*> getWord32le
      <*> (go =<< isEmpty)
    where
      go True = return True
      go False = getBool
      userAgent = do
        ua@(VarString bs) <- deserialize
        when (B.length bs > maxUserAgentLength) $
          fail ("Version: user agent of " ++ show (B.length bs) ++ " bytes is too long")
        return ua

  serialize (Version v s t ar as n ua sh r) = do
    putWord32le v
    putWord64le s
    putWord64le t
    serialize ar
    serialize as
    putWord64le n
    serialize ua
    putWord32le sh
    putBool r

instance Binary Version where
  put = serialize
  get = deserialize

instance Serialize Version where
  put = serialize
  get = deserialize

-- | 0x00 is 'False', anything else is 'True'.
getBool :: (MonadGet m) => m Bool
getBool = go =<< getWord8
  where
    go 0 = return False
    go _ = return True

putBool :: (MonadPut m) => Bool -> m ()
putBool True = putWord8 1
putBool False = putWord8 0

-- | A 'MessageCommand' is included in a 'MessageHeader' in order to identify
-- the type of message present in the payload. This allows the message
-- de-serialization code to know how to decode a particular message payload.
-- Every valid 'Message' constructor has a corresponding 'MessageCommand'
-- constructor.
data MessageCommand
  = MCVersion
  | MCVerAck
  | MCAddr
  | MCAddrV2
  | MCSendAddrV2
  | MCInv
  | MCGetData
  | MCNotFound
  | MCGetBlocks
  | MCGetHeaders
  | MCTx
  | MCBlock
  | MCMerkleBlock
  | MCHeaders
  | MCGetAddr
  | MCFilterLoad
  | MCFilterAdd
  | MCFilterClear
  | MCPing
  | MCPong
  | MCAlert
  | MCMempool
  | MCReject
  | MCSendHeaders
  | MCFeeFilter
  | MCSendCmpct
  | MCCmpctBlock
  | MCGetBlockTxn
  | MCBlockTxn
  | MCGetCFilters
  | MCCFilter
  | MCGetCFHeaders
  | MCCFHeaders
  | MCGetCFCheckpt
  | MCCFCheckpt
  | MCWtxidRelay
  | MCSendTxRcncl
  | MCOther ByteString
  deriving (Eq, Generic, NFData)

instance Show MessageCommand where
  showsPrec _ = shows . commandToString

instance Read MessageCommand where
  readPrec = do
    String str <- lexP
    return (stringToCommand (cs str))

-- | A command is twelve bytes on the wire: its name in printable ASCII, then
-- NUL bytes. The parse fails for a byte outside printable ASCII in the name or
-- a byte other than NUL after it, as @IsMessageTypeValid@ does in Bitcoin
-- Core. Serializing a name longer than twelve bytes, or with a byte outside
-- printable ASCII, is an error.
instance Serial MessageCommand where
  deserialize = do
    bs <- getByteString 12
    either fail (return . stringToCommand) (unpackCommand bs)
  serialize mc = putByteString $ packCommand $ commandToString mc

instance Binary MessageCommand where
  put = serialize
  get = deserialize

instance Serialize MessageCommand where
  put = serialize
  get = deserialize

instance IsString MessageCommand where
  fromString str = stringToCommand (cs str)

-- | Read a 'MessageCommand' from its string representation.
stringToCommand :: ByteString -> MessageCommand
stringToCommand str = case str of
  "version" -> MCVersion
  "verack" -> MCVerAck
  "addr" -> MCAddr
  "addrv2" -> MCAddrV2
  "sendaddrv2" -> MCSendAddrV2
  "inv" -> MCInv
  "getdata" -> MCGetData
  "notfound" -> MCNotFound
  "getblocks" -> MCGetBlocks
  "getheaders" -> MCGetHeaders
  "tx" -> MCTx
  "block" -> MCBlock
  "merkleblock" -> MCMerkleBlock
  "headers" -> MCHeaders
  "getaddr" -> MCGetAddr
  "filterload" -> MCFilterLoad
  "filteradd" -> MCFilterAdd
  "filterclear" -> MCFilterClear
  "ping" -> MCPing
  "pong" -> MCPong
  "alert" -> MCAlert
  "mempool" -> MCMempool
  "reject" -> MCReject
  "sendheaders" -> MCSendHeaders
  "feefilter" -> MCFeeFilter
  "sendcmpct" -> MCSendCmpct
  "cmpctblock" -> MCCmpctBlock
  "getblocktxn" -> MCGetBlockTxn
  "blocktxn" -> MCBlockTxn
  "getcfilters" -> MCGetCFilters
  "cfilter" -> MCCFilter
  "getcfheaders" -> MCGetCFHeaders
  "cfheaders" -> MCCFHeaders
  "getcfcheckpt" -> MCGetCFCheckpt
  "cfcheckpt" -> MCCFCheckpt
  "wtxidrelay" -> MCWtxidRelay
  "sendtxrcncl" -> MCSendTxRcncl
  _ -> MCOther str

-- | Convert a 'MessageCommand' to its string representation.
commandToString :: MessageCommand -> ByteString
commandToString mc = case mc of
  MCVersion -> "version"
  MCVerAck -> "verack"
  MCAddr -> "addr"
  MCAddrV2 -> "addrv2"
  MCSendAddrV2 -> "sendaddrv2"
  MCInv -> "inv"
  MCGetData -> "getdata"
  MCNotFound -> "notfound"
  MCGetBlocks -> "getblocks"
  MCGetHeaders -> "getheaders"
  MCTx -> "tx"
  MCBlock -> "block"
  MCMerkleBlock -> "merkleblock"
  MCHeaders -> "headers"
  MCGetAddr -> "getaddr"
  MCFilterLoad -> "filterload"
  MCFilterAdd -> "filteradd"
  MCFilterClear -> "filterclear"
  MCPing -> "ping"
  MCPong -> "pong"
  MCAlert -> "alert"
  MCMempool -> "mempool"
  MCReject -> "reject"
  MCSendHeaders -> "sendheaders"
  MCFeeFilter -> "feefilter"
  MCSendCmpct -> "sendcmpct"
  MCCmpctBlock -> "cmpctblock"
  MCGetBlockTxn -> "getblocktxn"
  MCBlockTxn -> "blocktxn"
  MCGetCFilters -> "getcfilters"
  MCCFilter -> "cfilter"
  MCGetCFHeaders -> "getcfheaders"
  MCCFHeaders -> "cfheaders"
  MCGetCFCheckpt -> "getcfcheckpt"
  MCCFCheckpt -> "cfcheckpt"
  MCWtxidRelay -> "wtxidrelay"
  MCSendTxRcncl -> "sendtxrcncl"
  MCOther c -> c

-- | Length of a command on the wire.
commandSize :: Int
commandSize = 12

-- | Is this byte printable ASCII? Command names are made of these.
printable :: Word8 -> Bool
printable w = w >= 0x20 && w <= 0x7e

-- | Pack a command name so that it is exactly 12 bytes long. A name that
-- does not fit, or has a byte outside printable ASCII, is an error. Bitcoin
-- Core asserts the same when it builds a header.
packCommand :: ByteString -> ByteString
packCommand s
  | B.length s > commandSize =
      error ("Message command longer than 12 bytes: " ++ show s)
  | not (B.all printable s) =
      error ("Message command with a byte outside printable ASCII: " ++ show s)
  | otherwise = s <> B.replicate (commandSize - B.length s) 0

-- | Undo packing done by 'packCommand'. Fails for a name with a byte outside
-- printable ASCII, or for a byte other than NUL after the name.
unpackCommand :: ByteString -> Either String ByteString
unpackCommand bs
  | not (B.all (== 0) padding) =
      Left ("Message command with bytes after its NUL terminator: " ++ show bs)
  | not (B.all printable name) =
      Left ("Message command with a byte outside printable ASCII: " ++ show bs)
  | otherwise = Right name
  where
    (name, padding) = B.break (== 0) bs

-- | Node offers no services.
nodeNone :: Word64
nodeNone = 0

-- | Services indicate node is a full node that can serve full blocks.
nodeNetwork :: Word64
nodeNetwork = 1

-- | Services indicate node allows to request 'UTXO' set.
nodeGetUTXO :: Word64
nodeGetUTXO = 1 `shiftL` 1

-- | Services indicate node accepts bloom filters.
nodeBloom :: Word64
nodeBloom = 1 `shiftL` 2

-- | Services indicate SegWit-capable node.
nodeWitness :: Word64
nodeWitness = 1 `shiftL` 3

-- | Services indicate Xtreme Thinblocks compatibility.
nodeXThin :: Word64
nodeXThin = 1 `shiftL` 4

-- | Services indicate node serves compact block filters (BIP 157).
nodeCompactFilters :: Word64
nodeCompactFilters = 1 `shiftL` 6

-- | Services indicate node serves only the last 288 blocks (BIP 159). Pruned
-- nodes advertise this instead of 'nodeNetwork'.
nodeNetworkLimited :: Word64
nodeNetworkLimited = 1 `shiftL` 10

-- | Services indicate node supports the version 2 encrypted transport
-- (BIP 324).
nodeP2PV2 :: Word64
nodeP2PV2 = 1 `shiftL` 11
