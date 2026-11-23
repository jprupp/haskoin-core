{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Haskoin.Network.Protocol.BitcoinCore.Machine
-- Copyright   : No rights reserved
-- License     : MIT
-- Maintainer  : jprupp@protonmail.ch
-- Stability   : experimental
-- Portability : POSIX
--
-- The small state monad in which the handlers of
-- "Haskoin.Network.Protocol.BitcoinCore" are written, and the primitives
-- that every handler uses: send a message, drop one, disconnect, flag
-- misbehaviour, draw randomness.
--
-- The handlers are translations of C++ functions that mutate the state of
-- a peer and push messages as they go, and stop early with @return@. A
-- state monad that collects t'Effect's in order keeps the translation close
-- to that shape, so that a reader can follow both side by side. The
-- alternative, threading a state and a list of effects through every
-- function by hand, made the handlers twice as long and hid the order of the
-- decisions, which is what the machine is for.
--
-- A handler stops early with 'stop', as the C++ function returns; 'scoped'
-- runs a sub-handler whose early return ends only that sub-handler.
--
-- 'send' applies the one filter of the transport that a peer can observe:
-- on a private broadcast connection, the node sends only @version@,
-- @verack@, @inv@, @tx@ and @ping@ (@CConnman::PushMessage@,
-- @src\/net.cpp@).
module Haskoin.Network.Protocol.BitcoinCore.Machine
  ( M,
    Run (..),
    runM,
    stop,
    scoped,
    opts,
    env,
    now,
    getS,
    putS,
    modifyS,
    modifyBlocks,
    modifyTxRelay,
    emit,
    send,
    ignore,
    process,
    disconnect,
    misbehaving,
    random,
    isConn,
    isInbound,
    isPrivateBroadcast,
    whenM,
    unlessM,
  )
where

import Control.Monad (unless, when)
import Control.Monad.Except (ExceptT, catchError, runExceptT, throwError)
import Control.Monad.State.Strict qualified as S
import Data.Text (Text)
import Haskoin.Network.Message (Message (..))
import Haskoin.Network.Protocol.BitcoinCore.State
import Haskoin.Network.Protocol.Types

-- | What a step works on: the options and the environment, which do not
-- change, the state of the peer, and the effects so far, newest first.
data Run = Run
  { options :: !Options,
    environment :: Env,
    state :: !State,
    effects :: ![Effect]
  }

-- | The monad of the handlers: a state, and an early exit.
type M = ExceptT () (S.State Run)

-- | Run a handler: the new state and the effects in the order they
-- happened.
runM :: Options -> Env -> State -> M () -> (State, [Effect])
runM o e s m =
  let r = S.execState (runExceptT (scoped m)) (Run o e s [])
   in (r.state, reverse r.effects)

-- | Return from the handler now, keeping what it did so far.
stop :: M a
stop = throwError ()

-- | Run a sub-handler; its 'stop' returns to here.
scoped :: M () -> M ()
scoped m = catchError m (\() -> return ())

-- | The options of the node.
opts :: M Options
opts = S.gets (.options)

-- | The environment of this step.
env :: M Env
env = S.gets (.environment)

-- | The time of this step.
now :: M Micros
now = S.gets (.environment.now)

-- | The state of the peer.
getS :: M State
getS = S.gets (.state)

-- | Replace the state of the peer.
putS :: State -> M ()
putS s = S.modify' $ \r -> r {state = s}

-- | Change the state of the peer.
modifyS :: (State -> State) -> M ()
modifyS f = S.modify' $ \r -> r {state = f r.state}

-- | Change the block download state.
modifyBlocks :: (BlockState -> BlockState) -> M ()
modifyBlocks f = modifyS $ \s -> s {blocks = f s.blocks}

-- | Change the transaction relay state, if there is one.
modifyTxRelay :: (TxRelay -> TxRelay) -> M ()
modifyTxRelay f = modifyS $ \s -> s {txRelay = f <$> s.txRelay}

-- | Record an effect.
emit :: Action -> Cite -> M ()
emit a c = S.modify' $ \r -> r {effects = Effect a c : r.effects}

-- | Send a message, and note the time of the last send for the inactivity
-- checks. On a private broadcast connection, only the messages that
-- @CConnman::PushMessage@ lets through are sent; the others are dropped
-- without a trace, as upstream does.
send :: Message -> Cite -> M ()
send m c = do
  pb <- isPrivateBroadcast
  unless (pb && not (allowed m)) $ do
    t <- now
    modifyS $ \s -> s {lastSend = Just t}
    emit (Send m) c
  where
    allowed (MVersion _) = True
    allowed MVerAck = True
    allowed (MInv _) = True
    allowed (MTx _) = True
    allowed (MPing _) = True
    allowed _ = False

-- | Drop the message without an answer.
ignore :: Cite -> M ()
ignore = emit Ignore

-- | An effect on the rest of the node that the peer does not see.
process :: Text -> Cite -> M ()
process t = emit (Process t)

-- | Close the connection (@fDisconnect = true@). Nothing more is processed
-- for the peer after this.
disconnect :: DisconnectReason -> Cite -> M ()
disconnect r c = do
  modifyS $ \s -> s {disconnected = True}
  emit (Disconnect r) c

-- | @Misbehaving@: flag the peer for discouragement, which
-- @MaybeDiscourageAndDisconnect@ acts on before the node sends anything
-- more. There is no score in Bitcoin Core 32.1: one call is enough. The
-- t'Cite' is kept to explain the 'Discourage' effect when it comes.
misbehaving :: Cite -> M ()
misbehaving c = modifyS $ \s -> s {shouldDiscourage = Just c}

-- | Draw from the randomness of the node.
random :: (Rng -> (a, Rng)) -> M a
random f = do
  s <- getS
  let (a, g) = f s.rng
  putS s {rng = g}
  return a

-- | The connection is of this type.
isConn :: ConnectionType -> M Bool
isConn t = (== t) . (.connectionType) <$> getS

-- | The peer connected to the node.
isInbound :: M Bool
isInbound = isConn Inbound

-- | A private broadcast connection.
isPrivateBroadcast :: M Bool
isPrivateBroadcast = isConn PrivateBroadcast

-- | Run an action if a condition holds.
whenM :: M Bool -> M () -> M ()
whenM c a = c >>= \b -> when b a

-- | Run an action unless a condition holds.
unlessM :: M Bool -> M () -> M ()
unlessM c a = c >>= \b -> unless b a
