{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ImportQualifiedPost #-}
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
    Alert (..),
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
    VarInt (..),
    VarString (..),
    Version (..),
    MessageCommand (..),
    reject,
    nodeNone,
    nodeNetwork,
    nodeGetUTXO,
    nodeBloom,
    nodeWitness,
    nodeXThin,
    commandToString,
    stringToCommand,
    putVarInt,
    getVarIntList,
    putVarIntList,
    maxListSize,
  )
where

import Control.DeepSeq
import Control.Monad (forM_, liftM2, replicateM, unless, when)
import Data.Binary (Binary (..))
import Data.Bits (shiftL)
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.ByteString.Char8 as C (replicate)
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Serialize (Serialize (..))
import Data.String
import Data.String.Conversions (cs)
import Data.Word (Word32, Word64)
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
    -- | extra data such as block or tx hash
    extra :: !ByteString
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

-- | Convenience function to build a 'Reject' message.
reject :: MessageCommand -> RejectCode -> ByteString -> Reject
reject cmd code reason =
  Reject cmd code (VarString reason) B.empty

instance Serial Reject where
  deserialize =
    deserialize >>= \(VarString bs) ->
      Reject (stringToCommand bs)
        <$> deserialize
        <*> deserialize
        <*> maybeData
    where
      maybeData =
        isEmpty >>= \done ->
          if done
            then return B.empty
            else getByteString 32
  serialize (Reject cmd code reason dat) = do
    serialize $ VarString $ commandToString cmd
    serialize code
    serialize reason
    unless (B.null dat) $ putByteString dat

instance Binary Reject where
  put = serialize
  get = deserialize

instance Serialize Reject where
  put = serialize
  get = deserialize

-- | Data type representing a variable-length integer. The 'VarInt' type
-- usually precedes an array or a string that can vary in length.
newtype VarInt = VarInt {get :: Word64}
  deriving (Eq, Show, Read, Generic)
  deriving newtype (NFData)

instance Serial VarInt where
  deserialize = VarInt <$> (getWord8 >>= go)
    where
      go 0xff = getWord64le
      go 0xfe = fromIntegral <$> getWord32le
      go 0xfd = fromIntegral <$> getWord16le
      go x = return $ fromIntegral x

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

-- | Largest number of elements that a serialized list may announce. Bitcoin
-- Core refuses larger counts when it reads a compact size (@MAX_SIZE@).
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

-- | Data type for serialization of variable-length strings.
newtype VarString = VarString {get :: ByteString}
  deriving (Eq, Show, Read, Generic)
  deriving newtype (NFData)

instance Serial VarString where
  deserialize = VarString <$> (readBS =<< deserialize)
    where
      readBS (VarInt len) = getByteString (fromIntegral len)

  serialize (VarString bs) = do
    putVarInt $ B.length bs
    putByteString bs

instance Binary VarString where
  put = serialize
  get = deserialize

instance Serialize VarString where
  put = serialize
  get = deserialize

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

instance Serial Version where
  deserialize =
    Version
      <$> getWord32le
      <*> getWord64le
      <*> getWord64le
      <*> deserialize
      <*> deserialize
      <*> getWord64le
      <*> deserialize
      <*> getWord32le
      <*> (go =<< isEmpty)
    where
      go True = return True
      go False = getBool

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
  | MCOther ByteString
  deriving (Eq, Generic, NFData)

instance Show MessageCommand where
  showsPrec _ = shows . commandToString

instance Read MessageCommand where
  readPrec = do
    String str <- lexP
    return (stringToCommand (cs str))

instance Serial MessageCommand where
  deserialize = go <$> getByteString 12
    where
      go bs =
        let str = unpackCommand bs
         in stringToCommand str
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
  _ -> MCOther str

-- | Convert a 'MessageCommand' to its string representation.
commandToString :: MessageCommand -> ByteString
commandToString mc = case mc of
  MCVersion -> "version"
  MCVerAck -> "verack"
  MCAddr -> "addr"
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
  MCOther c -> c

-- | Pack a string 'MessageCommand' so that it is exactly 12-bytes long.
packCommand :: ByteString -> ByteString
packCommand s =
  B.take 12 $
    s `mappend` C.replicate 12 '\NUL'

-- | Undo packing done by 'packCommand'.
unpackCommand :: ByteString -> ByteString
unpackCommand = B.takeWhile (/= 0)

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
