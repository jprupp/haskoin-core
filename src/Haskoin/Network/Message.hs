{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Message
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Peer-to-peer network message serialization.
module Haskoin.Network.Message
  ( -- * Network Message
    Message (..),
    MessageHeader (..),
    msgType,
    putMessage,
    getMessage,
    maxPayloadSize,
  )
where

import Control.DeepSeq
import Control.Monad (unless, when)
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.ByteString qualified as B
import Data.Bytes.Get
import Data.Bytes.Put
import Data.Bytes.Serial
import Data.Serialize (Serialize (..))
import Data.Word (Word32)
import GHC.Generics (Generic)
import Haskoin.Block.Common
import Haskoin.Block.Merkle
import Haskoin.Crypto.Hash
import Haskoin.Network.BlockFilter
import Haskoin.Network.Bloom
import Haskoin.Network.Common
import Haskoin.Network.CompactBlock
import Haskoin.Network.Data
import Haskoin.Transaction.Common

-- | Data type representing the header of a 'Message'. All messages sent between
-- nodes contain a message header.
data MessageHeader = MessageHeader
  { -- | magic bytes identify network
    magic :: !Word32,
    -- | message type
    cmd :: !MessageCommand,
    -- | length of payload
    size :: !Word32,
    -- | checksum of payload
    checksum :: !CheckSum32
  }
  deriving (Eq, Show, Generic, NFData)

instance Serial MessageHeader where
  deserialize =
    MessageHeader
      <$> getWord32be
      <*> deserialize
      <*> getWord32le
      <*> deserialize

  serialize (MessageHeader m c l chk) = do
    putWord32be m
    serialize c
    putWord32le l
    serialize chk

instance Binary MessageHeader where
  put = serialize
  get = deserialize

instance Serialize MessageHeader where
  put = serialize
  get = deserialize

-- | The 'Message' type is used to identify all the valid messages that can be
-- sent between bitcoin peers. Only values of type 'Message' will be accepted
-- by other bitcoin peers as bitcoin protocol messages need to be correctly
-- serialized with message headers. Serializing a 'Message' value will
-- include the 'MessageHeader' with the correct checksum value automatically.
-- No need to add the 'MessageHeader' separately.
data Message
  = MVersion !Version
  | MVerAck
  | MAddr !Addr
  | MAddrV2 !AddrV2
  | MSendAddrV2
  | MInv !Inv
  | MGetData !GetData
  | MNotFound !NotFound
  | MGetBlocks !GetBlocks
  | MGetHeaders !GetHeaders
  | MTx !Tx
  | MBlock !Block
  | MMerkleBlock !MerkleBlock
  | MHeaders !Headers
  | MGetAddr
  | MFilterLoad !FilterLoad
  | MFilterAdd !FilterAdd
  | MFilterClear
  | MPing !Ping
  | MPong !Pong
  | MAlert !Alert
  | MMempool
  | MReject !Reject
  | MSendHeaders
  | MFeeFilter !FeeFilter
  | MSendCompact !SendCompact
  | MCompactBlock !CompactBlock
  | MGetBlockTxn !GetBlockTxn
  | MBlockTxn !BlockTxn
  | MGetCFilters !GetCFilters
  | MCFilter !CFilter
  | MGetCFHeaders !GetCFHeaders
  | MCFHeaders !CFHeaders
  | MGetCFCheckpt !GetCFCheckpt
  | MCFCheckpt !CFCheckpt
  | MWtxidRelay
  | MSendTxRcncl !SendTxRcncl
  | -- | a message of a command this library does not know, with its payload
    MOther !ByteString !ByteString
  deriving (Eq, Show, Generic, NFData)

-- | Get 'MessageCommand' assocated with a message.
msgType :: Message -> MessageCommand
msgType (MVersion _) = MCVersion
msgType MVerAck = MCVerAck
msgType (MAddr _) = MCAddr
msgType (MAddrV2 _) = MCAddrV2
msgType MSendAddrV2 = MCSendAddrV2
msgType (MInv _) = MCInv
msgType (MGetData _) = MCGetData
msgType (MNotFound _) = MCNotFound
msgType (MGetBlocks _) = MCGetBlocks
msgType (MGetHeaders _) = MCGetHeaders
msgType (MTx _) = MCTx
msgType (MBlock _) = MCBlock
msgType (MMerkleBlock _) = MCMerkleBlock
msgType (MHeaders _) = MCHeaders
msgType MGetAddr = MCGetAddr
msgType (MFilterLoad _) = MCFilterLoad
msgType (MFilterAdd _) = MCFilterAdd
msgType MFilterClear = MCFilterClear
msgType (MPing _) = MCPing
msgType (MPong _) = MCPong
msgType (MAlert _) = MCAlert
msgType MMempool = MCMempool
msgType (MReject _) = MCReject
msgType MSendHeaders = MCSendHeaders
msgType (MFeeFilter _) = MCFeeFilter
msgType (MSendCompact _) = MCSendCmpct
msgType (MCompactBlock _) = MCCmpctBlock
msgType (MGetBlockTxn _) = MCGetBlockTxn
msgType (MBlockTxn _) = MCBlockTxn
msgType (MGetCFilters _) = MCGetCFilters
msgType (MCFilter _) = MCCFilter
msgType (MGetCFHeaders _) = MCGetCFHeaders
msgType (MCFHeaders _) = MCCFHeaders
msgType (MGetCFCheckpt _) = MCGetCFCheckpt
msgType (MCFCheckpt _) = MCCFCheckpt
msgType MWtxidRelay = MCWtxidRelay
msgType (MSendTxRcncl _) = MCSendTxRcncl
msgType (MOther c _) = MCOther c

-- | Largest payload that a message of this command may have on a network.
-- On Bitcoin every message is limited to 4,000,000 bytes, as in Bitcoin Core.
-- On Bitcoin Cash a message is limited to 2 MiB, unless it carries block
-- content: @block@, @cmpctblock@ and @blocktxn@ may be twice the block size.
-- This is @CMessageHeader::IsOversized@ in Bitcoin Cash Node. A node should
-- check the length of a message header against this limit before it buffers
-- the payload.
maxPayloadSize :: Network -> MessageCommand -> Word32
maxPayloadSize net cmd
  | carriesBlock = net.maxMessageSize
  | otherwise = min net.maxMessageSize net.maxProtocolMessageSize
  where
    carriesBlock = cmd `elem` [MCBlock, MCCmpctBlock, MCBlockTxn]

-- | Read one message of a network. The checks come in this order: the magic
-- bytes, the command name, the length against 'maxPayloadSize' of the
-- command, then the payload is read and its checksum compared. The payload
-- parser sees the declared bytes only. Any failure fails the parse. Bitcoin
-- Core drops a message with a wrong checksum or an invalid command name and
-- keeps the connection, which a caller can do by reading the header itself.
--
-- Transactions, in @tx@, @block@, @cmpctblock@ and @blocktxn@ messages, are
-- read with 'getNetworkTx', and compact block positions are limited as the
-- network requires, see 'getCompactBlock' and 'getGetBlockTxn'.
getMessage :: (MonadGet m) => Network -> m Message
getMessage net = do
  -- The magic is checked before the rest of the header is looked at.
  mgc <- lookAhead getWord32be
  unless
    (mgc == net.magic)
    (fail $ "get: Invalid network magic bytes: " ++ show mgc)
  (MessageHeader _ cmd len chk) <- deserialize
  let limit = maxPayloadSize net cmd
  when (len > limit) $
    fail $
      "get: Message of "
        ++ show len
        ++ " bytes is larger than the limit of "
        ++ show limit
  payload <- getByteString (fromIntegral len)
  unless
    (checkSum32 payload == chk)
    (fail $ "get: Invalid message checksum: " ++ show chk)
  either fail return (runGetS (getPayload net cmd len) payload)

getPayload :: (MonadGet m) => Network -> MessageCommand -> Word32 -> m Message
getPayload net cmd len =
  case cmd of
    MCVersion -> MVersion <$> deserialize
    MCVerAck -> return MVerAck
    MCAddr -> MAddr <$> deserialize
    MCAddrV2 -> MAddrV2 <$> deserialize
    MCSendAddrV2 -> return MSendAddrV2
    MCInv -> MInv <$> deserialize
    MCGetData -> MGetData <$> deserialize
    MCNotFound -> MNotFound <$> deserialize
    MCGetBlocks -> MGetBlocks <$> deserialize
    MCGetHeaders -> MGetHeaders <$> deserialize
    MCTx -> MTx <$> getNetworkTx net
    MCBlock -> MBlock <$> (Block <$> deserialize <*> getVarIntList (getNetworkTx net))
    MCMerkleBlock -> MMerkleBlock <$> deserialize
    MCHeaders -> MHeaders <$> deserialize
    MCGetAddr -> return MGetAddr
    MCFilterLoad -> MFilterLoad <$> deserialize
    MCFilterAdd -> MFilterAdd <$> deserialize
    MCFilterClear -> return MFilterClear
    MCPing -> MPing <$> deserialize
    MCPong -> MPong <$> deserialize
    MCAlert -> MAlert <$> deserialize
    MCMempool -> return MMempool
    MCReject -> MReject <$> deserialize
    MCSendHeaders -> return MSendHeaders
    MCFeeFilter -> MFeeFilter <$> deserialize
    MCSendCmpct -> MSendCompact <$> deserialize
    MCCmpctBlock -> MCompactBlock <$> getCompactBlock net
    MCGetBlockTxn -> MGetBlockTxn <$> getGetBlockTxn net
    MCBlockTxn -> MBlockTxn <$> getBlockTxn net
    MCGetCFilters -> MGetCFilters <$> deserialize
    MCCFilter -> MCFilter <$> deserialize
    MCGetCFHeaders -> MGetCFHeaders <$> deserialize
    MCCFHeaders -> MCFHeaders <$> deserialize
    MCGetCFCheckpt -> MGetCFCheckpt <$> deserialize
    MCCFCheckpt -> MCFCheckpt <$> deserialize
    MCWtxidRelay -> return MWtxidRelay
    MCSendTxRcncl -> MSendTxRcncl <$> deserialize
    MCOther c -> MOther c <$> getByteString (fromIntegral len)

-- | Serializer for network messages.
putMessage :: (MonadPut m) => Network -> Message -> m ()
putMessage net msg = do
  let (cmd, payload) =
        case msg of
          MVersion m -> (MCVersion, runPutS $ serialize m)
          MVerAck -> (MCVerAck, B.empty)
          MAddr m -> (MCAddr, runPutS $ serialize m)
          MAddrV2 m -> (MCAddrV2, runPutS $ serialize m)
          MSendAddrV2 -> (MCSendAddrV2, B.empty)
          MInv m -> (MCInv, runPutS $ serialize m)
          MGetData m -> (MCGetData, runPutS $ serialize m)
          MNotFound m -> (MCNotFound, runPutS $ serialize m)
          MGetBlocks m -> (MCGetBlocks, runPutS $ serialize m)
          MGetHeaders m -> (MCGetHeaders, runPutS $ serialize m)
          MTx m -> (MCTx, runPutS $ serialize m)
          MBlock m -> (MCBlock, runPutS $ serialize m)
          MMerkleBlock m -> (MCMerkleBlock, runPutS $ serialize m)
          MHeaders m -> (MCHeaders, runPutS $ serialize m)
          MGetAddr -> (MCGetAddr, B.empty)
          MFilterLoad m -> (MCFilterLoad, runPutS $ serialize m)
          MFilterAdd m -> (MCFilterAdd, runPutS $ serialize m)
          MFilterClear -> (MCFilterClear, B.empty)
          MPing m -> (MCPing, runPutS $ serialize m)
          MPong m -> (MCPong, runPutS $ serialize m)
          MAlert m -> (MCAlert, runPutS $ serialize m)
          MMempool -> (MCMempool, B.empty)
          MReject m -> (MCReject, runPutS $ serialize m)
          MSendHeaders -> (MCSendHeaders, B.empty)
          MFeeFilter m -> (MCFeeFilter, runPutS $ serialize m)
          MSendCompact m -> (MCSendCmpct, runPutS $ serialize m)
          MCompactBlock m -> (MCCmpctBlock, runPutS $ serialize m)
          MGetBlockTxn m -> (MCGetBlockTxn, runPutS $ serialize m)
          MBlockTxn m -> (MCBlockTxn, runPutS $ serialize m)
          MGetCFilters m -> (MCGetCFilters, runPutS $ serialize m)
          MCFilter m -> (MCCFilter, runPutS $ serialize m)
          MGetCFHeaders m -> (MCGetCFHeaders, runPutS $ serialize m)
          MCFHeaders m -> (MCCFHeaders, runPutS $ serialize m)
          MGetCFCheckpt m -> (MCGetCFCheckpt, runPutS $ serialize m)
          MCFCheckpt m -> (MCCFCheckpt, runPutS $ serialize m)
          MWtxidRelay -> (MCWtxidRelay, B.empty)
          MSendTxRcncl m -> (MCSendTxRcncl, runPutS $ serialize m)
          MOther c p -> (MCOther c, p)
      chk = checkSum32 payload
      len = fromIntegral $ B.length payload
      header = MessageHeader net.magic cmd len chk
  serialize header
  putByteString payload
