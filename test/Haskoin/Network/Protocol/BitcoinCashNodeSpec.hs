{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}
{-# OPTIONS_GHC -Wno-deprecations #-}

module Haskoin.Network.Protocol.BitcoinCashNodeSpec (spec) where

import Data.ByteString qualified as B
import Data.Int (Int32, Int64)
import Data.List (foldl')
import Data.Maybe (isJust, isNothing)
import Data.Sequence qualified as S
import Data.Set qualified as Set
import Data.Word (Word64)
import Haskoin.Block
import Haskoin.Network
import Haskoin.Network.Protocol.BitcoinCashNode qualified as BCHN
import Haskoin.Network.Protocol.Types
import Haskoin.Transaction
import Network.Socket (SockAddr (..))
import Test.Hspec

-- Helpers -------------------------------------------------------------------

-- | The time of the tests, in seconds.
t0 :: Micros
t0 = seconds 1700000000

-- | What the node knows of the genesis block of a network.
genesisInfo :: Network -> BlockInfo
genesisInfo net =
  BlockInfo
    { hash = headerHash net.genesisHeader,
      height = 0,
      status = HaveData,
      inActiveChain = True,
      work = 1,
      time = net.genesisHeader.timestamp
    }

-- | A node out of initial block download with only the genesis block, at
-- some seconds after 't0'.
envAt :: Network -> Micros -> Env
envAt net dt =
  (defaultEnv (genesisInfo net) (genesisBlock net) (t0 + dt))
    { initialBlockDownload = False
    }

-- | A connection of a type, with permissions.
setupOf :: ConnectionType -> [Permission] -> Setup
setupOf ct ps =
  Setup
    { connectionType = ct,
      permissions = Set.fromList ps,
      peerNetwork = AddrIPv4,
      peerIsLocal = False,
      transport = TransportV1,
      openedAt = t0,
      seed = 7
    }

-- | The null address of a @version@.
nullAddress :: NetworkAddress
nullAddress = NetworkAddress 0 (sockToHostAddress (SockAddrInet6 0 0 (0, 0, 0, 0) 0))

-- | The @version@ of a peer of protocol 70016 that serves the chain.
peerVersion :: Version
peerVersion =
  Version
    { version = 70016,
      services = 1 + 32,
      timestamp = 1700000000,
      addrRecv = nullAddress,
      addrSend = nullAddress,
      nonce = 42,
      userAgent = VarString "/test:1.0/",
      startHeight = 0,
      relay = True
    }

-- | 'peerVersion' with another protocol version.
versionOf :: Int32 -> Version
versionOf n = let Version _ s t a b o u h r = peerVersion in Version n s t a b o u h r

-- | 'peerVersion' with other services.
withServices :: Word64 -> Version
withServices x = let Version n _ t a b o u h r = peerVersion in Version n x t a b o u h r

-- | 'peerVersion' with another time.
withTime :: Int64 -> Version
withTime x = let Version n s _ a b o u h r = peerVersion in Version n s x a b o u h r

-- | 'peerVersion' with another relay flag.
withRelay :: Bool -> Version
withRelay x = let Version n s t a b o u h _ = peerVersion in Version n s t a b o u h x

-- | A machine on a network with its options, and the state of a connection.
data Peer = Peer
  { net :: Network,
    opts :: BCHN.Options,
    st :: BCHN.State
  }

-- | Open a connection.
open :: Network -> (BCHN.Options -> BCHN.Options) -> ConnectionType -> [Permission] -> Peer
open n f ct ps =
  let o = f (BCHN.defaultOptions n)
   in Peer n o (BCHN.start o (setupOf ct ps))

-- | Feed an input at some seconds after 't0', with a change to the
-- environment.
feedWith :: (Env -> Env) -> Micros -> Input -> Peer -> (Peer, [Effect])
feedWith f dt i p =
  let (s', es) = BCHN.step p.opts (f (envAt p.net dt)) p.st i
   in (p {st = s'}, es)

-- | Feed an input at some seconds after 't0'.
feed :: Micros -> Input -> Peer -> (Peer, [Effect])
feed = feedWith id

-- | Feed inputs in order, keeping only the last effects.
feeds :: Micros -> [Input] -> Peer -> (Peer, [Effect])
feeds dt is p = foldl' (\(q, _) i -> feed dt i q) (p, []) is

-- | The actions of some effects.
actions :: [Effect] -> [Action]
actions = map (.action)

-- | The messages sent.
sent :: [Effect] -> [Message]
sent es = [m | Send m <- actions es]

-- | The commands of the messages sent.
sentCommands :: [Effect] -> [MessageCommand]
sentCommands = map msgType . sent

-- | The nonce of the ping sent, or 0.
pingNonce :: [Effect] -> Word64
pingNonce es = case [x | MPing (Ping x) <- sent es] of
  (x : _) -> x
  [] -> 0

-- | Some effect is a disconnect.
disconnects :: [Effect] -> Bool
disconnects es = not (null [() | Disconnect _ <- actions es])

-- | Some effect discourages the peer.
discourages :: [Effect] -> Bool
discourages = elem Discourage . actions

-- | The scores added.
scores :: [Effect] -> [Int]
scores es = [n | Misbehave n <- actions es]

-- | An inbound peer past the handshake.
inboundReady :: Network -> [Permission] -> Peer
inboundReady n ps =
  fst (feeds 1 [Receive (MVersion peerVersion), Receive MVerAck] (open n id Inbound ps))

-- | An outbound peer past the handshake.
outboundReady :: Network -> Peer
outboundReady n =
  fst (feeds 1 [Receive (MVersion peerVersion), Receive MVerAck] (open n id OutboundFullRelay []))

-- | A @reject@ with this code was sent.
rejects :: RejectCode -> [Effect] -> Bool
rejects c es = not (null [() | MReject r <- sent es, r.code == c])

-- | Every effect cites a line of the upstream source.
allCited :: [Effect] -> Bool
allCited = all (\e -> e.because.line > 0 && not (null e.because.file))

-- | A transaction with one input and one output.
someTx :: Tx
someTx =
  Tx
    { version = 1,
      inputs = [TxIn (OutPoint "0000000000000000000000000000000000000000000000000000000000000001" 0) "" 0],
      outputs = [TxOut 1000 "\x51"],
      witness = [],
      locktime = 0
    }

-- Spec ----------------------------------------------------------------------

spec :: Spec
spec = describe "Haskoin.Network.Protocol.BitcoinCashNode" $ do
  handshakeSpec
  orderSpec
  pingSpec
  timeoutSpec
  misbehaviourSpec
  framingSpec
  permissionSpec
  networkSpec
  blockSpec
  relaySpec

handshakeSpec :: Spec
handshakeSpec = describe "handshake" $ do
  it "answers the version of an inbound peer with version, sendaddrv2 and verack" $ do
    let (_, es) = feed 1 (Receive (MVersion peerVersion)) (open bch id Inbound [])
    sentCommands es `shouldBe` [MCVersion, MCSendAddrV2, MCVerAck]
    allCited es `shouldBe` True
  it "sends no sendaddrv2 to a peer older than 70016" $ do
    let v = versionOf 70015
        (_, es) = feed 1 (Receive (MVersion v)) (open bch id Inbound [])
    sentCommands es `shouldBe` [MCVersion, MCVerAck]
  it "sends sendheaders and sendcmpct on the peer's verack" $ do
    let p = fst (feed 1 (Receive (MVersion peerVersion)) (open bch id Inbound []))
        (p', es) = feed 1 (Receive MVerAck) p
    sentCommands es `shouldBe` [MCSendHeaders, MCSendCmpct]
    sent es `shouldContain` [MSendCompact (SendCompact False 1)]
    BCHN.handshakeComplete p'.st `shouldBe` True
  it "sends its version first to an outbound peer, then verack and getaddr" $ do
    let p = open bch id OutboundFullRelay []
        (p1, es1) = feed 0 Tick p
        (_, es2) = feed 1 (Receive (MVersion peerVersion)) p1
    sentCommands es1 `shouldBe` [MCVersion]
    sentCommands es2 `shouldBe` [MCSendAddrV2, MCVerAck, MCGetAddr]
  it "says relay false in its version in blocks-only mode" $ do
    let p = open bch (\o -> o {BCHN.blocksOnly = True}) OutboundFullRelay []
        (_, es) = feed 0 Tick p
    [v.relay | MVersion v <- sent es] `shouldBe` [False]
  it "refuses an outbound peer without the services it wants" $ do
    let v = withServices (32)
        (_, es) = feed 1 (Receive (MVersion v)) (open bch id OutboundFullRelay [])
    rejects RejectNonStandard es `shouldBe` True
    disconnects es `shouldBe` True
  it "takes NODE_NETWORK_LIMITED from an outbound peer out of IBD" $ do
    let v = withServices (1024 + 32)
        (_, es) = feed 1 (Receive (MVersion v)) (open bch id OutboundFullRelay [])
    disconnects es `shouldBe` False
  it "refuses a version older than 31800" $ do
    let v = versionOf 31799
        (_, es) = feed 1 (Receive (MVersion v)) (open bch id Inbound [])
    rejects RejectObsolete es `shouldBe` True
    disconnects es `shouldBe` True
    sentCommands es `shouldNotContain` [MCVersion]
  it "disconnects a connection to itself" $ do
    let (_, es) =
          feedWith (\e -> e {ownNonce = (== 42)}) 1 (Receive (MVersion peerVersion)) (open bch id Inbound [])
    disconnects es `shouldBe` True
    sent es `shouldBe` []
  it "disconnects a feeler after version" $ do
    let (_, es) = feeds 1 [Tick, Receive (MVersion peerVersion)] (open bch id Feeler [])
    disconnects es `shouldBe` True
    sentCommands es `shouldContain` [MCVerAck]
  it "disconnects a peer of a rejected sub-version, but not a manual one" $ do
    let f o = o {BCHN.rejectSubVersions = ["test"]}
        (_, es) = feed 1 (Receive (MVersion peerVersion)) (open bch f Inbound [])
        (_, es') = feeds 1 [Tick, Receive (MVersion peerVersion)] (open bch f Manual [])
    disconnects es `shouldBe` True
    disconnects es' `shouldBe` False
  it "uses extversion when both sides offer it" $ do
    let f o = o {BCHN.useExtVersion = True}
        v = withServices (1 + 32 + 2048)
        p = open bch f Inbound []
        (p1, es1) = feed 1 (Receive (MVersion v)) p
        (p2, es2) = feed 1 (Receive (MOther "extversion" (B.pack [1, 0, 1, 100]))) p1
    sentCommands es1 `shouldBe` [MCVersion, MCOther "extversion"]
    sentCommands es2 `shouldBe` [MCSendAddrV2, MCVerAck]
    BCHN.negotiatedExtVersion p2.st `shouldBe` True
  it "answers verack with verack when the peer ignored extversion" $ do
    let f o = o {BCHN.useExtVersion = True}
        v = withServices (1 + 32 + 2048)
        (_, es) = feeds 1 [Receive (MVersion v), Receive MVerAck] (open bch f Inbound [])
    sentCommands es `shouldBe` [MCSendAddrV2, MCVerAck, MCSendHeaders, MCSendCmpct]
  it "disconnects extversion after verack" $ do
    let (_, es) = feed 2 (Receive (MOther "extversion" (B.pack [0]))) (inboundReady bch [])
    disconnects es `shouldBe` True
  it "takes sendaddrv2 before verack and disconnects it after" $ do
    let p = fst (feed 1 (Receive (MVersion peerVersion)) (open bch id Inbound []))
        (p1, _) = feed 1 (Receive MSendAddrV2) p
        (_, es) = feed 1 (Receive MSendAddrV2) (fst (feed 1 (Receive MVerAck) p1))
    BCHN.negotiatedAddrV2 p1.st `shouldBe` True
    disconnects es `shouldBe` True

orderSpec :: Spec
orderSpec = describe "messages out of order" $ do
  it "scores 10 for a message before version" $ do
    let (_, es) = feed 1 (Receive (MPing (Ping 1))) (open bch id Inbound [])
    scores es `shouldBe` [10]
  it "only logs a reject before version" $ do
    let r = Reject MCTx RejectInvalid (VarString "x") Nothing
        (_, es) = feed 1 (Receive (MReject r)) (open bch id Inbound [])
    actions es `shouldBe` [Ignore]
  it "drops a ping between version and verack without a pong" $ do
    let p = fst (feed 1 (Receive (MVersion peerVersion)) (open bch id Inbound []))
        (_, es) = feed 1 (Receive (MPing (Ping 1))) p
    actions es `shouldBe` [Ignore]
  it "answers a second version with a reject and a score of 1" $ do
    let (_, es) = feed 2 (Receive (MVersion peerVersion)) (inboundReady bch [])
    rejects RejectDuplicate es `shouldBe` True
    scores es `shouldBe` [1]
  it "sends sendheaders again on a second verack" $ do
    let (_, es) = feed 2 (Receive MVerAck) (inboundReady bch [])
    sentCommands es `shouldBe` [MCSendHeaders, MCSendCmpct]
  it "drops an unknown command after the handshake" $ do
    let (_, es) = feed 2 (Receive (MOther "foo" "")) (inboundReady bch [])
    actions es `shouldBe` [Ignore]
  it "drops the messages of Bitcoin Core it does not know" $ do
    let p = inboundReady bch []
    actions (snd (feed 2 (Receive MWtxidRelay) p)) `shouldBe` [Ignore]
    actions (snd (feed 2 (Receive (MSendTxRcncl (SendTxRcncl 1 2))) p)) `shouldBe` [Ignore]
    actions (snd (feed 2 (Receive (MAlert (Alert (VarString "") (VarString "")))) p)) `shouldBe` [Ignore]

pingSpec :: Spec
pingSpec = describe "ping and pong" $ do
  it "answers a ping with a pong after the handshake" $ do
    let (_, es) = feed 2 (Receive (MPing (Ping 99))) (inboundReady bch [])
    sent es `shouldBe` [MPong (Pong 99)]
  it "pings at the first pass after the handshake" $ do
    let (p, es) = feed 2 Tick (inboundReady bch [])
    sentCommands es `shouldContain` [MCPing]
    BCHN.pingOutstanding p.st `shouldSatisfy` isJust
  it "ends the ping on the matching pong" $ do
    let (p, es) = feed 2 Tick (inboundReady bch [])
        n = pingNonce es
        (p', _) = feed 3 (Receive (MPong (Pong n))) p
    BCHN.pingOutstanding p'.st `shouldSatisfy` isNothing
  it "keeps the ping on a pong of another nonce" $ do
    let (p, es) = feed 2 Tick (inboundReady bch [])
        n = pingNonce es
        (p', _) = feed 3 (Receive (MPong (Pong (n + 1)))) p
    BCHN.pingOutstanding p'.st `shouldBe` Just n
  it "disconnects when the pong does not come in 20 minutes" $ do
    let p = fst (feed 2 Tick (inboundReady bch []))
        -- the peer keeps the connection busy with pings of its own
        p' = fst (feed (seconds 1000) (Receive (MPing (Ping 5))) p)
        (_, es) = feed (seconds 1203) Tick p'
    [c.line | Effect (Disconnect Timeout) c <- es] `shouldBe` [1296]

timeoutSpec :: Spec
timeoutSpec = describe "timeouts" $ do
  it "disconnects a peer that sends nothing in the first minute" $ do
    let (_, es) = feed (seconds 61) Tick (open bch id Inbound [])
    [c.line | Effect (Disconnect Timeout) c <- es] `shouldBe` [1280]
  it "does nothing before the first minute" $ do
    let (_, es) = feed (seconds 60) Tick (open bch id Inbound [])
    es `shouldBe` []
  it "disconnects a peer that does not finish the handshake in a minute" $ do
    let p = fst (feed 1 (Receive (MVersion peerVersion)) (open bch id Inbound []))
        (_, es) = feed (seconds 62) Tick p
    [c.line | Effect (Disconnect Timeout) c <- es] `shouldBe` [1300]
  it "follows -peertimeout" $ do
    let p = open bch (\o -> o {BCHN.peerTimeout = 120}) Inbound []
    snd (feed (seconds 100) Tick p) `shouldBe` []

misbehaviourSpec :: Spec
misbehaviourSpec = describe "misbehaviour" $ do
  let early = Receive (MPing (Ping 1))
  it "discourages and disconnects at a score of 100" $ do
    let (p, es) = feeds 1 (replicate 10 early) (open bch id Inbound [])
    discourages es `shouldBe` True
    disconnects es `shouldBe` True
    BCHN.banScoreOf p.st `shouldBe` 100
  it "does not act below the threshold" $ do
    let (_, es) = feeds 1 (replicate 9 early) (open bch id Inbound [])
    discourages es `shouldBe` False
  it "follows -banscore" $ do
    let (_, es) = feeds 1 (replicate 5 early) (open bch (\o -> o {BCHN.banScore = 50}) Inbound [])
    discourages es `shouldBe` True
  it "processes nothing after the decision to disconnect" $ do
    let (p, _) = feeds 1 (replicate 10 early) (open bch id Inbound [])
        (_, es) = feed 1 (Receive (MVersion peerVersion)) p
    actions es `shouldBe` [Ignore]
  it "never punishes a noban peer" $ do
    let (p, es) = feeds 1 (replicate 20 early) (open bch id Inbound [PermNoBan])
    discourages es `shouldBe` False
    disconnects es `shouldBe` False
    BCHN.banScoreOf p.st `shouldBe` 200
  it "never punishes a manual peer" $ do
    let (_, es) = feeds 1 (Tick : replicate 10 early) (open bch id Manual [])
    disconnects es `shouldBe` False
  it "disconnects a local peer without discouraging it" $ do
    let s = (setupOf Inbound []) {peerIsLocal = True}
        o = BCHN.defaultOptions bch
        p = Peer bch o (BCHN.start o s)
        (_, es) = feeds 1 (replicate 10 early) p
    disconnects es `shouldBe` True
    discourages es `shouldBe` False
  it "acts on a penalty from the rest of the node at the next pass" $ do
    let p = inboundReady bch []
        (p1, es1) = feed 2 (Notify (Penalty 100 "bad-dsproof")) p
        (_, es2) = feed 2 Tick p1
    scores es1 `shouldBe` [100]
    discourages es2 `shouldBe` True

framingSpec :: Spec
framingSpec = describe "framing" $ do
  it "discourages a peer for the wrong magic, even with noban" $ do
    let (_, es) = feed 1 (BadFrame (WrongMagic 0)) (open bch id Inbound [PermNoBan])
    discourages es `shouldBe` True
    disconnects es `shouldBe` True
  it "discourages a peer for a bad checksum" $ do
    let (_, es) = feed 1 (BadFrame (BadChecksum "ping")) (open bch id Inbound [])
    discourages es `shouldBe` True
  it "drops a message with a bad command" $ do
    let (_, es) = feed 1 (BadFrame (BadCommand "\1")) (open bch id Inbound [])
    actions es `shouldBe` [Ignore]
  it "disconnects an oversized message without discouraging" $ do
    let (_, es) = feed 1 (BadFrame (Oversized "tx" 3000000)) (open bch id Inbound [])
    disconnects es `shouldBe` True
    discourages es `shouldBe` False
  it "answers a payload that does not parse with a malformed reject" $ do
    let (_, es) = feed 2 (BadFrame (BadPayload "inv")) (inboundReady bch [])
    rejects RejectMalformed es `shouldBe` True
    scores es `shouldBe` []
  it "scores a bad payload before version as a missing version" $ do
    let (_, es) = feed 1 (BadFrame (BadPayload "inv")) (open bch id Inbound [])
    scores es `shouldBe` [10]
  it "rejects a version that does not parse" $ do
    let (_, es) = feed 1 (BadFrame (BadPayload "version")) (open bch id Inbound [])
    rejects RejectMalformed es `shouldBe` True
  it "ends the ping on a short pong" $ do
    let (p, _) = feed 2 Tick (inboundReady bch [])
        (p', _) = feed 3 (BadFrame (BadPayload "pong")) p
    BCHN.pingOutstanding p'.st `shouldSatisfy` isNothing

permissionSpec :: Spec
permissionSpec = describe "permissions" $ do
  it "expands a bare whitelist to noban, mempool and relay" $ do
    let p = open bch id Inbound [PermImplicit]
    BCHN.permissionsOf p.st `shouldBe` Set.fromList [PermNoBan, PermMempool, PermRelay]
  it "drops relay from a bare whitelist in blocks-only mode" $ do
    let p = open bch (\o -> o {BCHN.blocksOnly = True}) Inbound [PermImplicit]
    BCHN.permissionsOf p.st `shouldBe` Set.fromList [PermNoBan, PermMempool]
  it "gives no permission to an outbound peer" $ do
    let p = open bch id Manual [PermNoBan]
    BCHN.permissionsOf p.st `shouldBe` Set.empty
  it "offers NODE_BLOOM to a peer with the bloomfilter permission" $ do
    let f o = o {BCHN.peerBloomFilters = False}
    BCHN.servicesOffered (open bch f Inbound []).st `shouldBe` (1 + 32 + 1024)
    BCHN.servicesOffered (open bch f Inbound [PermBloomFilter]).st `shouldBe` (1 + 4 + 32 + 1024)
  it "drops transactions in blocks-only mode unless the peer has relay" $ do
    let f o = o {BCHN.blocksOnly = True}
        ready ps = fst (feeds 1 [Receive (MVersion peerVersion), Receive MVerAck] (open bch f Inbound ps))
        (_, es1) = feed 2 (Receive (MTx someTx)) (ready [])
        (_, es2) = feed 2 (Receive (MTx someTx)) (ready [PermRelay])
    actions es1 `shouldBe` [Ignore]
    actions es2 `shouldNotBe` [Ignore]
  it "answers getheaders in IBD only to a noban peer" $ do
    let gh = MGetHeaders (GetHeaders 70016 [] (headerHash bch.genesisHeader))
        ibd e = e {initialBlockDownload = True}
        (_, es1) = feedWith ibd 2 (Receive gh) (inboundReady bch [])
        (_, es2) = feedWith ibd 2 (Receive gh) (inboundReady bch [PermNoBan])
    actions es1 `shouldBe` [Ignore]
    sentCommands es2 `shouldBe` [MCHeaders]
  it "disconnects a mempool request without bloom filters, but not from noban" $ do
    let f o = o {BCHN.peerBloomFilters = False}
        ready ps = fst (feeds 1 [Receive (MVersion peerVersion), Receive MVerAck] (open bch f Inbound ps))
    disconnects (snd (feed 2 (Receive MMempool) (ready []))) `shouldBe` True
    actions (snd (feed 2 (Receive MMempool) (ready [PermNoBan]))) `shouldBe` [Ignore]

networkSpec :: Spec
networkSpec = describe "networks" $ do
  it "has the default block size of each network" $ do
    map (\n -> (BCHN.defaultOptions n).defaultBlockSize) [bch, bchTest3, bchTest4, bchRegTest]
      `shouldBe` [32000000, 32000000, 2000000, 32000000]
  it "has the same timeouts and scores on every network" $
    mapM_
      (\n -> (BCHN.defaultOptions n).banScore `shouldBe` 100)
      [bch, bchTest3, bchTest4, bchRegTest]
  it "scores a version older than the genesis block of the network" $ do
    let v = withTime 1296688601
        score n = scores (snd (feed 1 (Receive (MVersion v)) (open n id Inbound [])))
    score bch `shouldBe` []
    score bchTest3 `shouldBe` [20]
    score bchTest4 `shouldBe` [20]
    score bchRegTest `shouldBe` [20]
  it "never finds too little work in headers on regtest" $ do
    let p = outboundReady bchRegTest
    (BCHN.defaultOptions bchRegTest).network.minimumChainWork `shouldBe` 0
    BCHN.isClosing p.st `shouldBe` False

blockSpec :: Spec
blockSpec = describe "blocks" $ do
  let g = headerHash bch.genesisHeader
      gh = bch.genesisHeader
      child = BlockHeader gh.version g gh.merkle 1700000000 gh.bits gh.nonce
      childHash = headerHash child
  it "answers getheaders with headers" $ do
    let (_, es) = feed 2 (Receive (MGetHeaders (GetHeaders 70016 [g] childHash))) (inboundReady bch [])
    sentCommands es `shouldBe` [MCHeaders]
  it "disconnects a getheaders with a locator of more than 101" $ do
    let gh = GetHeaders 70016 (replicate 102 g) g
    disconnects (snd (feed 2 (Receive (MGetHeaders gh)) (inboundReady bch []))) `shouldBe` True
  it "announces getblocks results by inv at the next pass" $ do
    let p = inboundReady bch []
        (p1, es1) = feed 2 (Receive (MGetBlocks (GetBlocks 70016 [] g))) p
        (_, es2) = feed 2 Tick p1
    sentCommands es1 `shouldBe` []
    -- only the genesis block is known, so nothing follows the fork
    sentCommands es2 `shouldNotContain` [MCInv]
  it "scores more than 2000 headers" $ do
    let hs = Headers (replicate 2001 (child, VarInt 0))
    scores (snd (feed 2 (Receive (MHeaders hs)) (inboundReady bch []))) `shouldBe` [20]
  it "asks for headers when a header does not connect" $ do
    let lone = child {prev = childHash}
        (_, es) = feed 2 (Receive (MHeaders (Headers [(lone, VarInt 0)]))) (inboundReady bch [])
    sentCommands es `shouldBe` [MCGetHeaders]
  it "scores every tenth header that does not connect" $ do
    let lone = child {prev = childHash}
        m = Receive (MHeaders (Headers [(lone, VarInt 0)]))
        (_, es) = feeds 2 (replicate 10 m) (inboundReady bch [])
    scores es `shouldBe` [20]
  it "scores headers that do not follow one another" $ do
    let hs = Headers [(child, VarInt 0), (child, VarInt 0)]
    scores (snd (feed 2 (Receive (MHeaders hs)) (inboundReady bch []))) `shouldBe` [20]
  it "scores invalid headers as validation says" $ do
    let hs = Headers [(child, VarInt 0)]
        (_, es) =
          feedWith (\e -> e {checkHeaders = const (HeadersRejected 50 "high-hash")}) 2 (Receive (MHeaders hs)) $
            inboundReady bch []
    scores es `shouldBe` [50]
  it "asks for headers after an inv of an unknown block" $ do
    let iv = InvVector InvBlock childHash.get
        (_, es) = feed 2 (Receive (MInv (Inv [iv]))) (inboundReady bch [])
    sentCommands es `shouldBe` [MCGetHeaders]
  it "serves a block it has" $ do
    let iv = InvVector InvBlock g.get
        (_, es) = feed 2 (Receive (MGetData (GetData [iv]))) (inboundReady bch [])
    sent es `shouldBe` [MBlock (genesisBlock bch)]
  it "sends nothing for an unknown block" $ do
    let iv = InvVector InvBlock childHash.get
        (_, es) = feed 2 (Receive (MGetData (GetData [iv]))) (inboundReady bch [])
    sent es `shouldBe` []
  it "rejects and scores an invalid block" $ do
    let blk = Block child []
        f e = e {checkBlock = const (BlockRejected 0x10 100 "bad-txnmrklroot")}
        (_, es) = feedWith f 2 (Receive (MBlock blk)) (inboundReady bch [])
    rejects RejectInvalid es `shouldBe` True
    scores es `shouldBe` [100]
    discourages es `shouldBe` True
  it "does not punish a noban peer for an invalid block" $ do
    let blk = Block child []
        f e = e {checkBlock = const (BlockRejected 0x10 100 "bad-txnmrklroot")}
        (_, es) = feedWith f 2 (Receive (MBlock blk)) (inboundReady bch [PermNoBan])
    discourages es `shouldBe` False
  it "asks for headers when a compact block does not connect" $ do
    let cb = CompactBlock (child {prev = childHash}) 0 [] []
        (_, es) = feed 2 (Receive (MCompactBlock cb)) (inboundReady bch [])
    sentCommands es `shouldBe` [MCGetHeaders]
  it "drops a blocktxn it did not ask for" $ do
    let (_, es) = feed 2 (Receive (MBlockTxn (BlockTxn childHash []))) (inboundReady bch [])
    actions es `shouldBe` [Ignore]
  it "disconnects a getblocktxn without indexes" $ do
    let (_, es) = feed 2 (Receive (MGetBlockTxn (GetBlockTxn g []))) (inboundReady bch [])
    disconnects es `shouldBe` True
  it "takes sendcmpct of version 1 and ignores others" $ do
    let p = inboundReady bch []
        (p1, _) = feed 2 (Receive (MSendCompact (SendCompact True 1))) p
        (_, es) = feed 2 (Receive (MSendCompact (SendCompact True 2))) p
    BCHN.highBandwidthFrom p1.st `shouldBe` True
    actions es `shouldBe` [Ignore]
  it "announces a new block with headers to a peer that sent sendheaders" $ do
    let info = BlockInfo childHash 1 HaveData True 2 1700000000
        f e =
          e
            { lookupBlock = \h -> if h == childHash then Just info else e.lookupBlock h,
              headerOf = \h -> if h == childHash then Just child else e.headerOf h,
              tip = info
            }
        known = Receive (MInv (Inv [InvVector InvBlock g.get]))
        p = fst (feeds 2 [Tick, known] (inboundReady bch []))
        p1 = fst (feed 2 (Receive MSendHeaders) p)
        p2 = fst (feedWith f 3 (Notify (NewTip [child])) p1)
        (_, es) = feedWith f 3 Tick p2
    BCHN.prefersHeaders p1.st `shouldBe` True
    sent es `shouldContain` [MHeaders (Headers [(child, VarInt 0)])]
  it "announces a new block with inv to a peer that did not" $ do
    let info = BlockInfo childHash 1 HaveData True 2 1700000000
        f e =
          e
            { lookupBlock = \h -> if h == childHash then Just info else e.lookupBlock h,
              headerOf = \h -> if h == childHash then Just child else e.headerOf h,
              tip = info
            }
        p = fst (feed 2 Tick (inboundReady bch []))
        p1 = fst (feedWith f 3 (Notify (NewTip [child])) p)
        (_, es) = feedWith f 3 Tick p1
    sent es `shouldContain` [MInv (Inv [InvVector InvBlock childHash.get])]
  it "requests a block the node asks for at the next pass" $ do
    let p = fst (feed 2 Tick (outboundReady bch))
        p1 = fst (feed 3 (Notify (RequestBlock childHash)) p)
        (p2, es) = feed 3 Tick p1
    sent es `shouldContain` [MGetData (GetData [InvVector InvBlock childHash.get])]
    BCHN.blocksInFlight p2.st `shouldBe` [childHash]
  it "sends sendcmpct when the node picks the peer for high bandwidth" $ do
    let p = fst (feed 2 (Receive (MSendCompact (SendCompact False 1))) (inboundReady bch []))
        (p1, es1) = feed 3 (Notify (HighBandwidth True)) p
        (_, es2) = feed 4 (Notify (HighBandwidth False)) p1
    sent es1 `shouldBe` [MSendCompact (SendCompact True 1)]
    sent es2 `shouldBe` [MSendCompact (SendCompact False 1)]
  it "disconnects on the operator's request and on eviction" $ do
    disconnects (snd (feed 2 (Notify OperatorDisconnect) (inboundReady bch []))) `shouldBe` True
    disconnects (snd (feed 2 (Notify Evict) (inboundReady bch []))) `shouldBe` True
  it "disconnects a peer that stalls the download for 2 seconds" $ do
    let p = fst (feed 2 Tick (inboundReady bch []))
        p1 = fst (feed (seconds 3) (Notify MarkStalling) p)
        (_, es) = feed (seconds 6) Tick p1
    [c.line | Effect (Disconnect Timeout) c <- es] `shouldBe` [4665]

relaySpec :: Spec
relaySpec = describe "relay" $ do
  let txid = txHash someTx
  it "sends feefilter at the first pass" $ do
    let (_, es) = feed 2 Tick (inboundReady bch [])
        -- the rounding moves the fee to the bucket below two times in three
        values = [r | MFeeFilter (FeeFilter r) <- sent es]
    values `shouldSatisfy` (`elem` [[1000], [1071]])
  it "sends no feefilter to a forcerelay peer" $ do
    let (_, es) = feed 2 Tick (inboundReady bch [PermForceRelay])
    sentCommands es `shouldNotContain` [MCFeeFilter]
  it "requests an announced transaction" $ do
    let p = outboundReady bch
        p1 = fst (feed 2 (Receive (MInv (Inv [InvVector InvTx txid.get]))) p)
        (p2, es) = feed 2 Tick p1
    sent es `shouldContain` [MGetData (GetData [InvVector InvTx txid.get])]
    BCHN.txsInFlight p2.st `shouldBe` [txid]
  it "waits 2 seconds more for a transaction from an inbound peer" $ do
    let p = inboundReady bch []
        p1 = fst (feed (seconds 1) (Receive (MInv (Inv [InvVector InvTx txid.get]))) p)
        (p2, es1) = feed (seconds 2) Tick p1
        (_, es2) = feed (seconds 4) Tick p2
    sentCommands es1 `shouldNotContain` [MCGetData]
    sentCommands es2 `shouldContain` [MCGetData]
  it "scores an inv of more than 50000" $ do
    let ivs = replicate 50001 (InvVector InvTx txid.get)
    scores (snd (feed 2 (Receive (MInv (Inv ivs))) (inboundReady bch []))) `shouldBe` [20]
  it "scores a getdata of more than 50000" $ do
    let ivs = replicate 50001 (InvVector InvTx txid.get)
    scores (snd (feed 2 (Receive (MGetData (GetData ivs))) (inboundReady bch []))) `shouldBe` [20]
  it "answers notfound for a transaction it does not have" $ do
    let iv = InvVector InvTx txid.get
        (_, es) = feed 2 (Receive (MGetData (GetData [iv]))) (inboundReady bch [])
    sent es `shouldBe` [MNotFound (NotFound [iv])]
  it "serves a transaction it announced recently" $ do
    let iv = InvVector InvTx txid.get
        f e = e {relayedTx = \h -> if h == txid then Just someTx else Nothing}
        (_, es) = feedWith f 2 (Receive (MGetData (GetData [iv]))) (inboundReady bch [])
    sent es `shouldBe` [MTx someTx]
  it "rejects and scores an invalid transaction" $ do
    let f e = e {checkTx = const (TxRejected 0x10 100 "bad-txns-vin-empty")}
        (_, es) = feedWith f 2 (Receive (MTx someTx)) (inboundReady bch [])
    rejects RejectInvalid es `shouldBe` True
    scores es `shouldBe` [100]
  it "rejects a transaction refused by policy without a score" $ do
    let f e = e {checkTx = const (TxPolicyReject "dust")}
        (_, es) = feedWith f 2 (Receive (MTx someTx)) (inboundReady bch [])
    rejects RejectNonStandard es `shouldBe` True
    scores es `shouldBe` []
  it "relays an accepted transaction" $ do
    let f e = e {checkTx = const TxAcceptedToMempool}
        (_, es) = feedWith f 2 (Receive (MTx someTx)) (inboundReady bch [])
    [() | Process _ <- actions es] `shouldBe` [()]
  it "announces a transaction from the mempool when the trickle fires" $ do
    let f e = e {mempoolTx = \h -> if h == txid then Just someTx else Nothing}
        p = fst (feed 2 Tick (inboundReady bch [PermNoBan]))
        p1 = fst (feedWith f 3 (Notify (TxAccepted someTx)) p)
        (_, es) = feedWith f 3 Tick p1
    sent es `shouldContain` [MInv (Inv [InvVector InvTx txid.get])]
  it "ends the request of a transaction on notfound" $ do
    let p = outboundReady bch
        p1 = fst (feed 2 (Receive (MInv (Inv [InvVector InvTx txid.get]))) p)
        p2 = fst (feed 2 Tick p1)
        (p3, _) = feed 3 (Receive (MNotFound (NotFound [InvVector InvTx txid.get]))) p2
    BCHN.txsInFlight p3.st `shouldBe` []
  it "scores an invalid double-spend proof, but not from noban" $ do
    let m = Receive (MOther "dsproof-beta" "x")
    scores (snd (feed 2 m (inboundReady bch []))) `shouldBe` [10]
    scores (snd (feed 2 m (inboundReady bch [PermNoBan]))) `shouldBe` []
  it "keeps the feefilter of the peer and ignores a bad one" $ do
    let (_, es1) = feed 2 (Receive (MFeeFilter (FeeFilter 5000))) (inboundReady bch [])
        (_, es2) = feed 2 (Receive (MFeeFilter (FeeFilter maxBound))) (inboundReady bch [])
    es1 `shouldBe` []
    actions es2 `shouldBe` [Ignore]
  it "scores an oversized filterload" $ do
    let f = BloomFilter (S.replicate 36001 0) 1 0 BloomUpdateNone
    scores (snd (feed 2 (Receive (MFilterLoad (FilterLoad f))) (inboundReady bch []))) `shouldBe` [100]
  it "disconnects a filterload before version when it offers no bloom" $ do
    let f = BloomFilter (S.replicate 10 0) 1 0 BloomUpdateNone
        p = open bch (\o -> o {BCHN.peerBloomFilters = False}) Inbound []
        (_, es) = feed 1 (Receive (MFilterLoad (FilterLoad f))) p
    disconnects es `shouldBe` True
    scores es `shouldBe` []
  it "scores a filterload after version when it offers no bloom" $ do
    let f = BloomFilter (S.replicate 10 0) 1 0 BloomUpdateNone
        noBloom o = o {BCHN.peerBloomFilters = False}
        p = fst (feed 1 (Receive (MVersion peerVersion)) (open bch noBloom Inbound []))
        (_, es) = feed 1 (Receive (MFilterLoad (FilterLoad f))) p
    scores es `shouldBe` [100]
  it "scores an oversized filteradd" $ do
    let m = Receive (MFilterAdd (FilterAdd (B.replicate 521 0)))
    scores (snd (feed 2 m (inboundReady bch []))) `shouldBe` [100]
  it "turns on transaction relay with filterclear" $ do
    let v = withRelay False
        p = fst (feeds 1 [Receive (MVersion v), Receive MVerAck] (open bch id Inbound []))
        (p1, _) = feed 2 (Receive MFilterClear) p
    BCHN.relaysTransactions p.st `shouldBe` False
    BCHN.relaysTransactions p1.st `shouldBe` True
  it "scores an addr of more than 1000" $ do
    let a = (1700000000, NetworkAddress 1 (sockToHostAddress (SockAddrInet 8333 0x01020304)))
        m = Receive (MAddr (Addr (replicate 1001 a)))
    scores (snd (feed 2 m (inboundReady bch []))) `shouldBe` [20]
  it "takes addrv2 and disconnects an address fetch after it" $ do
    let a = NetworkAddressV2 1700000000 1 AddrIPv4 (B.pack [1, 2, 3, 4]) 8333
        p = fst (feeds 1 [Tick, Receive (MVersion peerVersion), Receive MVerAck] (open bch id AddrFetch []))
        (_, es) = feed 2 (Receive (MAddrV2 (AddrV2 [a]))) p
    disconnects es `shouldBe` True
  it "answers getaddr once, and only from an inbound peer" $ do
    let a = NetworkAddressV2 1700000000 1 AddrIPv4 (B.pack [1, 2, 3, 4]) 8333
        f e = e {addressesForPeer = const [a]}
        p = fst (feed 2 Tick (inboundReady bch []))
        (p1, _) = feedWith f 3 (Receive MGetAddr) p
        (_, es1) = feedWith f (seconds 1000) Tick p1
        (_, es2) = feedWith f 4 (Receive MGetAddr) p1
        (_, es3) = feedWith f 3 (Receive MGetAddr) (outboundReady bch)
    sentCommands es1 `shouldContain` [MCAddr]
    actions es2 `shouldBe` [Ignore]
    actions es3 `shouldBe` [Ignore]
