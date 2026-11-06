{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE NoFieldSelectors #-}

module Haskoin.Network.Data
  ( Network (..),
    getNetworkTx,
  )
where

import Control.DeepSeq
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.Bytes.Get (MonadGet)
import Data.Bytes.Serial (deserialize)
import Data.Serialize (Serialize (..))
import Data.Text (Text)
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Block.Common
import Haskoin.Transaction.Common (Tx, parseLegacyTx)

-- | Network definition.
data Network = Network
  { -- | lowercase alphanumeric and dashes
    name :: !String,
    -- | prefix for 'Base58' P2PKH addresses
    addrPrefix :: !Word8,
    -- | prefix for 'Base58' P2SH addresses
    scriptPrefix :: !Word8,
    -- | prefix for WIF private key
    secretPrefix :: !Word8,
    -- | prefix for extended public key
    xPubPrefix :: !Word32,
    -- | prefix for extended private key
    xPrvPrefix :: !Word32,
    -- | network magic
    magic :: !Word32,
    -- | genesis block header
    genesisHeader :: !BlockHeader,
    -- | coinbase transaction of the genesis block
    genesisTx :: !Tx,
    -- | maximum block size in bytes
    maxBlockSize :: !Int,
    -- | largest P2P message of any kind, in bytes. A message that carries
    -- block content (@block@, @cmpctblock@ or @blocktxn@) may be this large.
    -- Bitcoin Core refuses any message over 4,000,000 bytes
    -- (@MAX_PROTOCOL_MESSAGE_LENGTH@). Bitcoin Cash Node refuses those three
    -- messages over twice the block size. Use
    -- 'Haskoin.Network.Message.maxPayloadSize' for the limit of one command.
    maxMessageSize :: !Word32,
    -- | largest P2P message that carries no block content, in bytes. This is
    -- @MAX_PROTOCOL_MESSAGE_LENGTH@ of the reference node: 4,000,000 on
    -- Bitcoin, where it is the limit of every message, and 2 MiB on Bitcoin
    -- Cash, where @CMessageHeader::IsOversized@ applies it to every message
    -- but @block@, @cmpctblock@ and @blocktxn@.
    maxProtocolMessageSize :: !Word32,
    -- | largest transaction position that a compact block message may name.
    -- BIP 152 and Bitcoin Core use 16 bits (65535). Bitcoin Cash Node uses 32.
    maxCompactBlockIndex :: !Word32,
    -- | maximum amount of satoshi
    maxSatoshi :: !Word64,
    -- | user agent string
    userAgent :: !ByteString,
    -- | default port for P2P connections
    defaultPort :: !Int,
    -- | allow min difficulty blocks (testnet)
    minDiffBlocks :: !Bool,
    -- | do not retarget difficulty (regtest)
    powNoRetarget :: !Bool,
    -- | enforce BIP94 block storm and time warp rules (testnet4)
    bip94 :: !Bool,
    -- | proof-of-work target higest possible value
    powLimit :: !Integer,
    -- | height at which BIP34 activates
    bip34Height :: !BlockHeight,
    -- | hash of the block at 'bip34Height', when the chain pins one. Bitcoin
    -- Core pins none on regtest.
    bip34Hash :: !(Maybe BlockHash),
    -- | block at which BIP65 activates
    bip65Height :: !BlockHeight,
    -- | block at which BIP66 activates
    bip66Height :: !BlockHeight,
    -- | time between difficulty retargets
    targetTimespan :: !Word32,
    -- | time between blocks
    targetSpacing :: !Word32,
    -- | checkpoints
    checkpoints :: ![(BlockHeight, BlockHash)],
    -- | work that the best chain is known to have, @nMinimumChainWork@ of the
    -- reference node. Once the best block has this much work,
    -- 'Haskoin.Block.Headers.connectBlocks' refuses a new header with less,
    -- which can only be a fork from far below the tip. Zero on regtest.
    minimumChainWork :: !Integer,
    -- | BIP44 derivation path root
    bip44Coin :: !Word32,
    -- | peer-to-peer network seeds
    seeds :: ![String],
    -- | fork id for replay protection
    sigHashForkId :: !(Maybe Word32),
    -- | height of the first block that uses the EDA
    -- (one above @uahfHeight@ in Bitcoin Cash Node)
    edaHeight :: !(Maybe Word32),
    -- | height of the first block that uses the DAA
    -- (one above @daaHeight@ in Bitcoin Cash Node)
    daaHeight :: !(Maybe Word32),
    -- | asert3-2d algorithm activation time
    -- TODO: Replace with block height after fork
    asertActivationTime :: !(Maybe Word32),
    -- | asert3-2d algorithm halflife (not used for non-BCH networks)
    asertHalfLife :: !Integer,
    -- | segregated witness active
    segWit :: !Bool,
    -- | 'CashAddr' prefix (for Bitcoin Cash)
    cashAddrPrefix :: !(Maybe Text),
    -- | 'Bech32' prefix (for SegWit network)
    bech32Prefix :: !(Maybe Text),
    -- | Replace-By-Fee (BIP-125)
    replaceByFee :: !Bool,
    -- | Subsidy halving interval
    halvingInterval :: !Word32
  }
  deriving (Eq, Show, Read, Generic, NFData)

-- | Read a transaction as the reference node of the network reads one that
-- a peer sends. On a network with SegWit this is the extended format of BIP
-- 144, with its marker, flag and witness. On a network without SegWit it is
-- the old format only: Bitcoin Cash Node has no witness format, so it reads
-- the marker byte as an input count of zero. Reading the old format there
-- also means that a peer cannot make a Bitcoin Cash node build witness
-- stacks.
getNetworkTx :: (MonadGet m) => Network -> m Tx
getNetworkTx net
  | net.segWit = deserialize
  | otherwise = parseLegacyTx

