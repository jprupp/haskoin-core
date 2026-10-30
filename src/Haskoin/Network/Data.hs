{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NoFieldSelectors #-}

module Haskoin.Network.Data
  ( Network (..),
  )
where

import Control.DeepSeq
import Data.Binary (Binary (..))
import Data.ByteString (ByteString)
import Data.Serialize (Serialize (..))
import Data.Text (Text)
import Data.Word (Word32, Word64, Word8)
import GHC.Generics (Generic)
import Haskoin.Block.Common

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
    -- | maximum block size in bytes
    maxBlockSize :: !Int,
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
    -- | block at which BIP34 activates
    bip34Block :: !(BlockHeight, BlockHash),
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
    -- | BIP44 derivation path root
    bip44Coin :: !Word32,
    -- | peer-to-peer network seeds
    seeds :: ![String],
    -- | fork id for replay protection
    sigHashForkId :: !(Maybe Word32),
    -- | EDA start block height
    edaHeight :: !(Maybe Word32),
    -- | DAA start block height
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
