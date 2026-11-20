{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}

-- |
-- Module      : Haskoin.Network.Protocol
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- Pure state machines that model how the reference node of each supported
-- network treats one peer: Bitcoin Core 32.1 for the Bitcoin networks, and
-- Bitcoin Cash Node 29.2.0 for the Bitcoin Cash networks.
--
-- The problem they solve: the peer-to-peer protocol is defined by what these
-- nodes do, not by a specification. The BIPs leave out most of what decides
-- whether a connection lives: which messages are dropped before the
-- handshake, which ones count as misbehaviour, when the node pings and how
-- long it waits, what a whitelisted peer may do that others may not. A
-- program that talks to these nodes, such as haskoin-node, needs that map to
-- behave correctly, and its tests need an oracle to compare against. Each
-- machine is a translation of the upstream source, with a t'Cite' of the file
-- and line behind every t'Effect', so the map can be checked against the code
-- and brought forward to a new release.
--
-- Pick a machine for a network with 'machine', open a 'Connection' with
-- 'start', and feed it 'Input's with 'step':
--
-- > let m = machine btc
-- >     c0 = start m setup
-- >     (c1, effects) = step env c0 (Receive (MVersion ver))
--
-- The vocabulary is in "Haskoin.Network.Protocol.Types". The rules of each
-- node, with the options it reads, are in
-- "Haskoin.Network.Protocol.BitcoinCore" and
-- "Haskoin.Network.Protocol.BitcoinCashNode". The report
-- @doc\/protocol\/README.md@ of the repository describes the protocol of both
-- nodes in prose, with the same references, and is kept in step with these
-- modules.
--
-- What the machines leave out, and why:
--
-- * Validation of blocks and transactions, and the state of the chain and the
--   mempool. A machine asks the t'Env' for verdicts instead. Translating
--   consensus is a different job, and a verdict is all that the protocol
--   needs.
-- * Decisions that span peers, such as which peer to download a block from or
--   which inbound peer to evict. Where one of them changes what a peer sees,
--   it comes in as a 'Notification'.
-- * Bytes. A machine sees whole messages, and framing errors as 'FrameError'.
module Haskoin.Network.Protocol
  ( -- * Machines
    Machine (..),
    machine,
    upstreamOf,
    networkOf,

    -- * Connections
    Connection (..),
    start,
    step,

    -- * Vocabulary
    module Haskoin.Network.Protocol.Types,
  )
where

import Control.DeepSeq (NFData)
import GHC.Generics (Generic)
import Haskoin.Network.Data (Network (..))
import Haskoin.Network.Protocol.BitcoinCashNode qualified as BCHN
import Haskoin.Network.Protocol.BitcoinCore qualified as Core
import Haskoin.Network.Protocol.Types

-- | The rules of one node on one network, with its options.
data Machine
  = -- | Bitcoin Core, which serves the Bitcoin networks
    BitcoinCore !Core.Options
  | -- | Bitcoin Cash Node, which serves the Bitcoin Cash networks
    BitcoinCashNode !BCHN.Options
  deriving (Eq, Show, Generic, NFData)

-- | The machine of the reference node of a network, with the options that
-- node has when started with none. A network with a fork id is a Bitcoin Cash
-- network.
machine :: Network -> Machine
machine net = case net.sigHashForkId of
  Just _ -> BitcoinCashNode (BCHN.defaultOptions net)
  Nothing -> BitcoinCore (Core.defaultOptions net)

-- | The upstream release that a machine translates.
upstreamOf :: Machine -> Upstream
upstreamOf (BitcoinCore _) = Core.upstream
upstreamOf (BitcoinCashNode _) = BCHN.upstream

-- | The network of a machine.
networkOf :: Machine -> Network
networkOf (BitcoinCore o) = o.network
networkOf (BitcoinCashNode o) = o.network

-- | One connection as a node sees it: the rules and the state it keeps about
-- the peer. The two travel together so that a state can never be stepped by
-- the rules of the other node.
data Connection
  = CoreConnection !Core.Options !Core.State
  | BchnConnection !BCHN.Options !BCHN.State
  deriving (Eq, Show, Generic, NFData)

-- | Open a connection.
start :: Machine -> Setup -> Connection
start (BitcoinCore o) s = CoreConnection o (Core.start o s)
start (BitcoinCashNode o) s = BchnConnection o (BCHN.start o s)

-- | Feed one input to a connection: the new connection and what the node did,
-- in the order it did it.
step :: Env -> Connection -> Input -> (Connection, [Effect])
step env (CoreConnection o s) i =
  let (s', es) = Core.step o env s i
   in (CoreConnection o s', es)
step env (BchnConnection o s) i =
  let (s', es) = BCHN.step o env s i
   in (BchnConnection o s', es)
