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
    --
    -- On Bitcoin Cash this is a fixed number, twice a block size of 32 MB,
    -- where the node works the limit out from a block size limit that
    -- grows when blocks fill up (the adaptive limit, active since 2024). The
    -- library does not follow that growth: it would need the sizes of the
    -- blocks of the chain, which a reader of messages does not have. No block
    -- is near the limit today. When the limit of the chain rises, a caller
    -- sets a larger number in its copy of the network, and 'maxBlockSize'
    -- with it.
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
    -- | blocks that the chain must hold at these heights, as the reference
    -- node pins them. 'Haskoin.Block.Headers.connectBlocks' refuses a header
    -- at such a height with another hash, and a fork below the last
    -- checkpoint the chain has reached. Bitcoin Core 32.1 has none, so the
    -- Bitcoin networks have none either; Bitcoin Cash Node keeps them.
    checkpoints :: ![(BlockHeight, BlockHash)],
    -- | work that the best chain is known to have, @nMinimumChainWork@ of the
    -- reference node. Once the best block has this much work,
    -- 'Haskoin.Block.Headers.connectBlocks' refuses a new header with less,
    -- which can only be a fork from far below the tip. Zero on regtest.
    minimumChainWork :: !Integer,
    -- | BIP44 derivation path root
    bip44Coin :: !Word32,
    -- | DNS seeds of the network, as the reference node lists them. On
    -- regtest they are a placeholder that does not resolve (Bitcoin Core) or
    -- none (Bitcoin Cash Node).
    seeds :: ![String],
    -- | fork id for replay protection
    sigHashForkId :: !(Maybe Word32),
    -- | height of the first block that uses the EDA, the emergency difficulty
    -- rule of Bitcoin Cash (one above @uahfHeight@ in Bitcoin Cash Node).
    --
    -- Below this height the retarget rule of Bitcoin applies. The UAHF
    -- specification makes the EDA a rule of the fork block and of the blocks
    -- after it, and the blocks below were mined under the rule of Bitcoin.
    -- Bitcoin Cash Node has no such height: it applies the EDA to every
    -- block below the DAA. Both accept the real chains. They differ only on
    -- a made-up chain that leaves the real one below this height. There the
    -- library is the stricter side: the EDA only ever asks for less work.
    -- Set this field to @Just 1@ on a network of your own to get the rule of
    -- the node at every height.
    edaHeight :: !(Maybe Word32),
    -- | height of the first block that uses the DAA
    -- (one above @daaHeight@ in Bitcoin Cash Node)
    daaHeight :: !(Maybe Word32),
    -- | asert3-2d algorithm activation time
    -- TODO: Replace with block height after fork
    asertActivationTime :: !(Maybe Word32),
    -- | asert3-2d algorithm halflife (not used for non-BCH networks)
    asertHalfLife :: !Integer,
    -- | height and hash of the aserti3-2d anchor block, where it is known.
    -- The anchor is the first block whose median time past reached the
    -- activation time, and every later difficulty depends on it. Without this
    -- constant 'Haskoin.Block.Headers.asertAnchor' finds the anchor with a
    -- binary search down the chain, about 1,500 reads of the store at height
    -- 100,000. With it, one walk to the ancestor at that height is enough,
    -- about 80 reads, and the search is still used for a chain that does not
    -- hold this block.
    --
    -- The block must be the first whose median time past reaches the
    -- activation time. When the chain holds it, it is taken as the anchor
    -- without looking at its median time past, so a wrong block gives every
    -- block above it another difficulty, with no error. Set it only from a
    -- trusted source, such as the constants of the reference node.
    -- Bitcoin Cash Node keeps the same constant (@asertAnchorParams@). It is
    -- 'Nothing' on regtest, where every chain has its own anchor, and on
    -- testnet3, whose anchor block could not be checked against a second
    -- source when it was added.
    asertAnchorBlock :: !(Maybe (BlockHeight, BlockHash)),
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
{-# INLINE getNetworkTx #-}
