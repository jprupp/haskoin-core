{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoFieldSelectors #-}
{-# OPTIONS_GHC -Wno-deprecations #-}

-- | Scenario tests of the protocol machine of Bitcoin Core 32.1: each one
-- drives the machine through 'step' and checks the effects, and where it
-- matters the upstream line that decided them.
module Haskoin.Network.Protocol.BitcoinCoreSpec (spec) where

import Data.ByteString qualified as B
import Data.Bytes.Get (runGetS)
import Data.Bytes.Put (runPutS)
import Data.Int (Int32)
import Data.List (foldl')
import Data.Maybe (isJust, isNothing)
import Data.Sequence qualified as Seq
import Data.Set qualified as Set
import Data.String (IsString, fromString)
import Data.Word (Word32, Word64, Word8)
import Haskoin.Block
import Haskoin.Block.Headers (headerWork)
import Haskoin.Network
import Haskoin.Network.Protocol.BitcoinCore
import Haskoin.Network.Protocol.Types
import Haskoin.Transaction
import Network.Socket (SockAddr (..))
import Test.Hspec

-- * Fixtures

t0 :: Micros
t0 = seconds 1700000000

genesisInfo :: Network -> BlockInfo
genesisInfo net =
  BlockInfo
    { hash = headerHash net.genesisHeader,
      height = 0,
      status = HaveData,
      inActiveChain = True,
      work = headerWork net.genesisHeader,
      time = net.genesisHeader.timestamp
    }

mkEnv :: Network -> Env
mkEnv net =
  let gi = genesisInfo net
      e = defaultEnv gi (Block net.genesisHeader [net.genesisTx]) t0
   in e {headerOf = \h -> if h == gi.hash then Just net.genesisHeader else Nothing}

at :: Micros -> Env -> Env
at t e = e {now = t}

setup :: ConnectionType -> [Permission] -> Setup
setup ct ps =
  Setup
    { connectionType = ct,
      permissions = Set.fromList ps,
      peerNetwork = AddrIPv4,
      peerIsLocal = False,
      transport = TransportV1,
      openedAt = t0,
      seed = 7
    }

zeroAddr :: NetworkAddress
zeroAddr = NetworkAddress 0 (sockToHostAddress (SockAddrInet6 0 0 (0, 0, 0, 0) 0))

fullServices :: Word64
fullServices = nodeNetwork + nodeWitness

ver :: Int32 -> Word64 -> Bool -> Version
ver v svc r =
  Version
    { version = v,
      services = svc,
      timestamp = 0,
      addrRecv = zeroAddr,
      addrSend = zeroAddr,
      nonce = 42,
      userAgent = VarString "/test/",
      startHeight = 0,
      relay = r
    }

peerVer :: Version
peerVer = ver 70017 fullServices True

-- | A header like the genesis header of a network, with another parent and
-- nonce.
headerAfter :: Network -> BlockHash -> Word32 -> BlockHeader
headerAfter net p n =
  let g = net.genesisHeader
   in BlockHeader g.version p g.merkle g.timestamp g.bits n

zero :: BlockHash
zero = hashN 0

-- | A made-up hash that ends in a digit.
hashN :: (IsString a) => Int -> a
hashN n = fromString (replicate 63 '0' ++ show (n `mod` 10))

-- | A public IPv4 address that offers full services.
ipv4 :: [Word8] -> NetworkAddressV2
ipv4 bs =
  NetworkAddressV2
    { time = 0,
      services = fullServices,
      network = AddrIPv4,
      address = B.pack bs,
      port = 8333
    }

-- | Feed inputs one after another, collecting all effects.
run :: Options -> Env -> State -> [Input] -> (State, [Effect])
run o e s0 = foldl' go (s0, [])
  where
    go (s, acc) i = let (s', es) = step o e s i in (s', acc ++ es)

sent :: [Effect] -> [Message]
sent es = [m | Effect (Send m) _ <- es]

actions :: [Effect] -> [Action]
actions = map (.action)

lines' :: [Effect] -> [Int]
lines' = map (.because.line)

isDisc :: Action -> Bool
isDisc (Disconnect _) = True
isDisc _ = False

commands :: [Message] -> [MessageCommand]
commands = map msgType

-- | An inbound connection with the handshake done.
inboundReady :: Options -> Env -> [Permission] -> State
inboundReady o e ps =
  fst $ run o e (start o (setup Inbound ps)) [Receive (MVersion peerVer), Receive MVerAck]

-- | An outbound full relay connection with the handshake done.
outboundReady :: Options -> Env -> State
outboundReady o e =
  fst $
    run
      o
      e
      (start o (setup OutboundFullRelay []))
      [Tick, Receive (MVersion peerVer), Receive MVerAck]

btcO :: Options
btcO = defaultOptions btc

btcE :: Env
btcE = mkEnv btc

-- | The payload of a @sendcmpct@ with the announce byte 2 and the version 2.
announceTwo :: B.ByteString
announceTwo = B.pack [2, 2, 0, 0, 0, 0, 0, 0, 0]

hugeInv :: Message
hugeInv = MInv (Inv (replicate 50001 (InvVector InvBlock (hashN 1))))

aTx :: Tx
aTx = btc.genesisTx

spec :: Spec
spec = do
  handshakeSpec
  pingSpec
  timeoutSpec
  misbehaviourSpec
  permissionSpec
  networkSpec
  messageSpec
  notificationSpec

handshakeSpec :: Spec
handshakeSpec = describe "handshake" $ do
  it "answers an inbound version in upstream order" $ do
    let s0 = start btcO (setup Inbound [])
        (s1, es) = step btcO btcE s0 (Receive (MVersion peerVer))
    commands (sent es) `shouldBe` [MCVersion, MCWtxidRelay, MCSendAddrV2, MCVerAck]
    versionReceived s1 `shouldBe` True
    handshakeComplete s1 `shouldBe` False
    let (s2, es2) = step btcO btcE s1 (Receive MVerAck)
    commands (sent es2) `shouldBe` [MCSendCmpct]
    handshakeComplete s2 `shouldBe` True
  it "sends its version first on an outbound connection" $ do
    let s0 = start btcO (setup OutboundFullRelay [])
        (s1, es) = step btcO btcE s0 Tick
    commands (sent es) `shouldBe` [MCVersion]
    let (_, es2) = step btcO btcE s1 (Receive (MVersion peerVer))
    commands (sent es2) `shouldBe` [MCWtxidRelay, MCSendAddrV2, MCVerAck, MCGetAddr]
  it "sends its version before processing an early outbound message" $ do
    let s0 = start btcO (setup OutboundFullRelay [])
        (_, es) = step btcO btcE s0 (Receive (MVersion peerVer))
    take 1 (commands (sent es)) `shouldBe` [MCVersion]
  it "drops any message before version" $ do
    let (_, es) = step btcO btcE (start btcO (setup Inbound [])) (Receive (MPing (Ping 1)))
    actions es `shouldBe` [Ignore]
    lines' es `shouldBe` [4076]
  it "drops a ping between version and verack" $ do
    let (s1, _) = step btcO btcE (start btcO (setup Inbound [])) (Receive (MVersion peerVer))
        (_, es) = step btcO btcE s1 (Receive (MPing (Ping 1)))
    lines' es `shouldBe` [4321]
  it "ignores a second version and a second verack" $ do
    let s = inboundReady btcO btcE []
        (_, es1) = step btcO btcE s (Receive (MVersion peerVer))
        (_, es2) = step btcO btcE s (Receive MVerAck)
    lines' es1 `shouldBe` [3839]
    lines' es2 `shouldBe` [4082]
  it "disconnects an obsolete version" $ do
    let (s, es) = step btcO btcE (start btcO (setup Inbound [])) (Receive (MVersion (ver 31799 fullServices True)))
    actions es `shouldBe` [Disconnect ProtocolViolation]
    isDisconnected s `shouldBe` True
  it "disconnects an outbound peer without the expected services" $ do
    let s0 = start btcO (setup OutboundFullRelay [])
        (_, es) = run btcO btcE s0 [Tick, Receive (MVersion (ver 70017 nodeWitness True))]
    lines' (filter (isDisc . (.action)) es) `shouldBe` [3871]
  it "accepts a manual peer without services" $ do
    let s0 = start btcO (setup Manual [])
        (s, _) = run btcO btcE s0 [Tick, Receive (MVersion (ver 70017 0 True))]
    isDisconnected s `shouldBe` False
  it "disconnects a connection to itself" $ do
    let e = btcE {ownNonce = (== 42)}
        (_, es) = step btcO e (start btcO (setup Inbound [])) (Receive (MVersion peerVer))
    lines' es `shouldBe` [3904]
  it "ends a feeler after the version" $ do
    let s0 = start btcO (setup Feeler [])
        (s, es) = run btcO btcE s0 [Tick, Receive (MVersion peerVer)]
    last (actions es) `shouldBe` Disconnect Done
    isDisconnected s `shouldBe` True
  it "sends no getaddr and relay off to a block-relay-only peer" $ do
    let s0 = start btcO (setup BlockRelayOnly [])
        (_, es) = run btcO btcE s0 [Tick, Receive (MVersion peerVer)]
    [v.relay | MVersion v <- sent es] `shouldBe` [False]
    MCGetAddr `elem` commands (sent es) `shouldBe` False
  it "sends the final alert to an old peer and no BIP 155 or 339 messages" $ do
    let (_, es) = step btcO btcE (start btcO (setup Inbound [])) (Receive (MVersion (ver 70012 fullServices True)))
    commands (sent es) `shouldBe` [MCVersion, MCVerAck, MCAlert]
  it "closes the connection on wtxidrelay or sendaddrv2 after verack" $ do
    let s = inboundReady btcO btcE []
    lines' (snd (step btcO btcE s (Receive MWtxidRelay))) `shouldBe` [4196]
    lines' (snd (step btcO btcE s (Receive MSendAddrV2))) `shouldBe` [4218]
  it "records wtxidrelay and sendaddrv2 before verack" $ do
    let (s1, _) = step btcO btcE (start btcO (setup Inbound [])) (Receive (MVersion peerVer))
        (s2, _) = run btcO btcE s1 [Receive MWtxidRelay, Receive MSendAddrV2]
        (_, es) = step btcO btcE s2 (Receive MWtxidRelay)
    wtxidRelayOf s2 `shouldBe` True
    wantsAddrV2Of s2 `shouldBe` True
    lines' es `shouldBe` [4204]
  it "checks the feature message" $ do
    let (s1, _) = step btcO btcE (start btcO (setup Inbound [])) (Receive (MVersion peerVer))
        good = B.concat [B.singleton 4, "abcd", B.singleton 0]
        bad = B.concat [B.singleton 2, "ab", B.singleton 0]
    lines' (snd (step btcO btcE s1 (Receive (MOther "feature" good)))) `shouldBe` [4260]
    lines' (snd (step btcO btcE s1 (Receive (MOther "feature" bad)))) `shouldBe` [4250]
    let s = inboundReady btcO btcE []
    lines' (snd (step btcO btcE s (Receive (MOther "feature" good)))) `shouldBe` [4229]
  it "negotiates Erlay only when enabled" $ do
    let (s1, _) = step btcO btcE (start btcO (setup Inbound [])) (Receive (MVersion peerVer))
    lines' (snd (step btcO btcE s1 (Receive (MSendTxRcncl (SendTxRcncl 1 5))))) `shouldBe` [4269]
    let o = btcO {txReconciliation = True}
        (r1, es1) = step o btcE (start o (setup Inbound [])) (Receive (MVersion peerVer))
    MCSendTxRcncl `elem` commands (sent es1) `shouldBe` True
    let (r2, es2) = step o btcE r1 (Receive (MSendTxRcncl (SendTxRcncl 1 5)))
        (_, es3) = step o btcE r2 (Receive (MSendTxRcncl (SendTxRcncl 1 5)))
    es2 `shouldBe` []
    lines' es3 `shouldBe` [4310]
  it "handles a private broadcast connection" $ do
    let s0 = start btcO (setup PrivateBroadcast [])
        (_, esNo) = run btcO btcE s0 [Tick, Receive (MVersion (ver 70017 fullServices False))]
    lines' (filter (isDisc . (.action)) esNo) `shouldBe` [3961]
    let e = btcE {privateBroadcastTx = Just aTx}
        (s1, es) = run btcO e s0 [Tick, Receive (MVersion peerVer), Receive MVerAck]
    commands (sent es) `shouldBe` [MCVersion, MCVerAck, MCInv]
    [v.version | MVersion v <- sent es] `shouldBe` [70016]
    let (_, es2) = step btcO e s1 (Receive (MGetData (GetData [InvVector InvTx (txHash aTx).get])))
    commands (sent es2) `shouldBe` [MCTx, MCPing]
    let (_, es3) = step btcO e s1 (Receive (MPing (Ping 3)))
    lines' es3 `shouldBe` [4327]

pingSpec :: Spec
pingSpec = describe "ping" $ do
  it "pings after the handshake and accepts the pong" $ do
    let s = inboundReady btcO btcE []
        (s1, es) = step btcO btcE s Tick
        nonces = [n | MPing (Ping n) <- sent es]
    isJust (pingOutstanding s1) `shouldBe` True
    case nonces of
      [n] -> do
        let (s2, _) = step btcO btcE s1 (Receive (MPong (Pong n)))
        pingOutstanding s2 `shouldBe` Nothing
      _ -> expectationFailure "expected one ping"

  it "answers a ping with a pong of the same nonce" $ do
    let s = inboundReady btcO btcE []
    sent (snd (step btcO btcE s (Receive (MPing (Ping 99))))) `shouldBe` [MPong (Pong 99)]
  it "handles wrong pongs as upstream does" $ do
    let s = inboundReady btcO btcE []
        (s1, _) = step btcO btcE s Tick
    lines' (snd (step btcO btcE s (Receive (MPong (Pong 5))))) `shouldBe` [5929]
    let (s2, es2) = step btcO btcE s1 (Receive (MPong (Pong 12345)))
    lines' es2 `shouldBe` [5921]
    isJust (pingOutstanding s2) `shouldBe` True
    let (s3, es3) = step btcO btcE s1 (Receive (MPong (Pong 0)))
    lines' es3 `shouldBe` [5925]
    pingOutstanding s3 `shouldBe` Nothing
  it "disconnects after 20 minutes without a pong" $ do
    let s = inboundReady btcO btcE []
        (s1, _) = step btcO btcE s Tick
        later = at (t0 + seconds (21 * 60)) btcE
        (s2, es) = step btcO later s1 (Receive (MPing (Ping 1)))
        (_, es2) = step btcO later s2 Tick
    lines' (es ++ es2) `shouldContain` [5706]

timeoutSpec :: Spec
timeoutSpec = describe "timers" $ do
  it "closes a handshake that takes more than 60 seconds" $ do
    let (s1, _) = step btcO btcE (start btcO (setup Inbound [])) (Receive (MVersion peerVer))
        (_, es) = step btcO (at (t0 + seconds 61) btcE) s1 Tick
    lines' es `shouldBe` [2101]
  it "closes a silent connection after the peer timeout" $ do
    let (_, es) = step btcO (at (t0 + seconds 61) btcE) (start btcO (setup Inbound [])) Tick
    lines' es `shouldBe` [2067]
  it "keeps a quiet connection within the peer timeout" $ do
    let (_, es) = step btcO (at (t0 + seconds 59) btcE) (start btcO (setup Inbound [])) Tick
    es `shouldBe` []
  it "ends an address fetch connection after 300 seconds" $ do
    let s0 = start btcO (setup AddrFetch [])
        (s1, _) = run btcO btcE s0 [Tick, Receive (MVersion peerVer), Receive MVerAck]
        (_, es) = step btcO (at (t0 + seconds 301) btcE) (s1 {- recent traffic -}) (Receive (MPing (Ping 1)))
        (_, es2) = step btcO (at (t0 + seconds 301) btcE) s1 Tick
    length es `shouldSatisfy` (> 0)
    lines' (filter (isDisc . (.action)) es2) `shouldBe` [6100]

misbehaviourSpec :: Spec
misbehaviourSpec = describe "misbehaviour" $ do
  it "discourages a peer that sends an oversized inv" $ do
    let s = inboundReady btcO btcE []
        (s1, es) = step btcO btcE s (Receive hugeInv)
    actions es `shouldBe` [Ignore, Discourage, Disconnect Misbehaviour]
    (.because.line) (es !! 1) `shouldBe` 4352
    isDisconnected s1 `shouldBe` True
  it "never punishes a noban peer" $ do
    let s = inboundReady btcO btcE [PermNoBan]
        (s1, es) = step btcO btcE s (Receive hugeInv)
    actions es `shouldBe` [Ignore]
    isDisconnected s1 `shouldBe` False
  it "never punishes a manual connection" $ do
    let s0 = start btcO (setup Manual [])
        (s, _) = run btcO btcE s0 [Tick, Receive (MVersion peerVer), Receive MVerAck]
        (s1, _) = step btcO btcE s (Receive hugeInv)
    isDisconnected s1 `shouldBe` False
  it "disconnects a local or inbound Tor peer without discouraging it" $ do
    let local = (setup Inbound []) {peerIsLocal = True}
        tor = (setup Inbound []) {peerNetwork = AddrTorV3}
    mapM_
      ( \su -> do
          let (s, _) = run btcO btcE (start btcO su) [Receive (MVersion peerVer), Receive MVerAck]
              (_, es) = step btcO btcE s (Receive hugeInv)
          actions es `shouldBe` [Ignore, Disconnect Misbehaviour]
      )
      [local, tor]
  it "discourages oversized headers" $ do
    let s = inboundReady btcO btcE []
        hdr = (btc.genesisHeader, VarInt 0)
        (_, es) = step btcO btcE s (Receive (MHeaders (Headers (replicate 2001 hdr))))
    Discourage `elem` actions es `shouldBe` True
  -- The parser refuses a sendcmpct with an announce byte above 1 on Bitcoin,
  -- so the machine has it as a payload that did not parse, with its bytes.
  -- Bitcoin Core: "invalid sendcmpct announce field" (net_processing.cpp).
  it "discourages an announce byte above 1 in a sendcmpct that did not parse, even before verack" $ do
    let (s1, _) = step btcO btcE (start btcO (setup Inbound [])) (Receive (MVersion peerVer))
        (_, es) = step btcO btcE s1 (BadFrame (BadPayload "sendcmpct" announceTwo))
    actions es `shouldBe` [Ignore, Discourage, Disconnect Misbehaviour]
  it "gives the answer of the node for the bytes of a sendcmpct with the announce byte 2" $ do
    -- the frame as a peer sends it, read as a caller reads it
    let (s1, _) = step btcO btcE (start btcO (setup Inbound [])) (Receive (MVersion peerVer))
        bytes = runPutS (putMessage btc (MOther "sendcmpct" announceTwo))
        input = either (const (BadFrame (BadPayload "sendcmpct" announceTwo))) Receive (runGetS (getMessage btc) bytes)
    input `shouldBe` BadFrame (BadPayload "sendcmpct" announceTwo)
    actions (snd (step btcO btcE s1 input)) `shouldBe` [Ignore, Discourage, Disconnect Misbehaviour]
  it "drops a sendcmpct with an announce byte above 1 before version, as any message" $ do
    let (_, es) = step btcO btcE (start btcO (setup Inbound [])) (BadFrame (BadPayload "sendcmpct" announceTwo))
    actions es `shouldBe` [Ignore]
    -- "non-version message before version handshake"
    lines' es `shouldBe` [4076]
  it "drops a sendcmpct that is cut short, whatever its announce byte" $ do
    let (s1, _) = step btcO btcE (start btcO (setup Inbound [])) (Receive (MVersion peerVer))
        (_, es) = step btcO btcE s1 (BadFrame (BadPayload "sendcmpct" (B.pack [2, 2, 0, 0])))
    actions es `shouldBe` [Ignore]
    -- "Exception caught"
    lines' es `shouldBe` [5493]

permissionSpec :: Spec
permissionSpec = describe "permissions and blocks-only" $ do
  it "expands a bare whitelist" $ do
    expandPermissions btcO (Set.fromList [PermImplicit])
      `shouldBe` Set.fromList [PermNoBan, PermDownload, PermMempool, PermRelay]
    let o = btcO {blocksOnly = True}
    expandPermissions o (Set.fromList [PermImplicit])
      `shouldBe` Set.fromList [PermNoBan, PermDownload, PermMempool]
    let f = btcO {whitelistForceRelay = True}
    expandPermissions f (Set.fromList [PermImplicit])
      `shouldBe` Set.fromList [PermNoBan, PermDownload, PermMempool, PermRelay, PermForceRelay]
  it "gives noban the download permission" $
    expandPermissions btcO (Set.fromList [PermNoBan]) `shouldBe` Set.fromList [PermNoBan, PermDownload]
  it "tells peers not to relay in blocks-only mode, unless they have relay" $ do
    let o = btcO {blocksOnly = True}
        relayOf ps =
          let (_, es) = step o btcE (start o (setup Inbound ps)) (Receive (MVersion peerVer))
           in [v.relay | MVersion v <- sent es]
    relayOf [] `shouldBe` [False]
    relayOf [PermRelay] `shouldBe` [True]
  it "disconnects a peer that sends a transaction in blocks-only mode" $ do
    let o = btcO {blocksOnly = True}
        e = btcE {initialBlockDownload = False}
        s = inboundReady o e []
    lines' (snd (step o e s (Receive (MTx aTx)))) `shouldBe` [4711]
    let r = inboundReady o e [PermRelay]
    isDisconnected (fst (step o e r (Receive (MTx aTx)))) `shouldBe` False
  it "offers NODE_BLOOM to a peer with the bloomfilter permission" $ do
    let s = start btcO (setup Inbound [PermBloomFilter])
    ourServicesOf s `shouldSatisfy` (\x -> x `div` nodeBloom `mod` 2 == 1)

networkSpec :: Spec
networkSpec = describe "networks" $ do
  it "takes the minimum chain work of each network" $
    mapM_
      (\n -> (defaultOptions n).minimumChainWork `shouldBe` n.minimumChainWork)
      [btc, btcTest, btcTest4, btcRegTest]
  it "has the same defaults on the four networks otherwise" $
    mapM_
      ( \n -> do
          let o = defaultOptions n
          (o.blocksOnly, o.peerBloomFilters, o.txReconciliation, o.listen, o.peerTimeout)
            `shouldBe` (False, False, False, True, seconds 60)
      )
      [btc, btcTest, btcTest4, btcRegTest]
  it "sends empty headers while the tip has too little work, except on regtest" $ do
    let check n expected = do
          let o = defaultOptions n
              e = mkEnv n
              s = inboundReady o e []
              gh' = GetHeaders 70016 [headerHash n.genesisHeader] zero
          lines' (snd (step o e s (Receive (MGetHeaders gh')))) `shouldBe` [expected]
    check btc 4655
    check btcTest 4655
    check btcTest4 4655
    check btcRegTest 4704
  it "lets a download peer have headers while the tip has too little work" $ do
    let s = inboundReady btcO btcE [PermDownload]
        gh = GetHeaders 70016 [headerHash btc.genesisHeader] zero
    lines' (snd (step btcO btcE s (Receive (MGetHeaders gh)))) `shouldBe` [4704]

messageSpec :: Spec
messageSpec = describe "messages" $ do
  let s = inboundReady btcO btcE []
      reg = defaultOptions btcRegTest
      regE = mkEnv btcRegTest
  it "drops a bad checksum and closes on a wrong magic" $ do
    lines' (snd (step btcO btcE s (BadFrame (BadChecksum "ping")))) `shouldBe` [836]
    actions (snd (step btcO btcE s (BadFrame (WrongMagic 1)))) `shouldBe` [Disconnect ProtocolViolation]
    actions (snd (step btcO btcE s (BadFrame (Oversized "block" 5000000)))) `shouldBe` [Disconnect ProtocolViolation]
    lines' (snd (step btcO btcE s (BadFrame (BadPayload "inv" "")))) `shouldBe` [5493]
  it "ignores unknown and retired messages" $ do
    lines' (snd (step btcO btcE s (Receive (MOther "dsproof-beta" "x")))) `shouldBe` [5360]
    let rej = MReject (Reject MCTx RejectInvalid (VarString "") Nothing)
    lines' (snd (step btcO btcE s (Receive rej))) `shouldBe` [5360]
  it "records sendheaders" $
    prefersHeadersOf (fst (step btcO btcE s (Receive MSendHeaders))) `shouldBe` True
  it "records sendcmpct of version 2 only" $ do
    compactBlocksOf (fst (step btcO btcE s (Receive (MSendCompact (SendCompact True 2)))))
      `shouldBe` (True, True, False)
    lines' (snd (step btcO btcE s (Receive (MSendCompact (SendCompact True 1))))) `shouldBe` [4178]
  it "takes a sendcmpct that did not parse and has a valid announce byte as the message" $
    -- announce 1, version 2
    compactBlocksOf (fst (step btcO btcE s (BadFrame (BadPayload "sendcmpct" (B.pack [1, 2, 0, 0, 0, 0, 0, 0, 0])))))
      `shouldBe` (True, True, False)
  it "takes a sendcmpct under an unknown command name for an unknown message" $
    -- the bytes of a refused sendcmpct come as a BadPayload, and only so
    lines' (snd (step btcO btcE s (Receive (MOther "sendcmpct" announceTwo)))) `shouldBe` [5360]
  it "closes on a getheaders locator over 101 entries" $ do
    let gh = GetHeaders 70016 (replicate 102 (hashN 1)) zero
    lines' (snd (step btcO btcE s (Receive (MGetHeaders gh)))) `shouldBe` [4636]
  it "asks for headers when a header does not connect" $ do
    let r = inboundReady reg regE []
        hdr = headerAfter btcRegTest (hashN 9) 1
        (_, es) = step reg regE r (Receive (MHeaders (Headers [(hdr, VarInt 0)])))
    lines' es `shouldBe` [2903]
  it "takes an empty headers message silently" $
    snd (step btcO btcE s (Receive (MHeaders (Headers [])))) `shouldBe` []
  it "answers getblocks with an inv at the next pass" $ do
    let e = regE {blockAtHeight = \n -> if n == 0 then Just (genesisInfo btcRegTest) else Nothing}
        r = inboundReady reg e []
        (r1, es) = step reg e r (Receive (MGetBlocks (GetBlocks 70016 [] zero)))
    es `shouldBe` []
    isDisconnected r1 `shouldBe` False
  it "serves a transaction or a notfound" $ do
    let e = btcE {mempoolTx = \h -> if h == txHash aTx then Just aTx else Nothing}
        r = inboundReady btcO e []
        have = InvVector InvTx (txHash aTx).get
        lack = InvVector InvTx (hashN 2)
        (_, es) = step btcO e r (Receive (MGetData (GetData [have, lack])))
    commands (sent es) `shouldBe` [MCTx, MCNotFound]
  it "serves a block" $ do
    let r = inboundReady btcO btcE []
        iv = InvVector InvWitnessBlock (headerHash btc.genesisHeader).get
    commands (sent (snd (step btcO btcE r (Receive (MGetData (GetData [iv])))))) `shouldBe` [MCBlock]
  it "discourages a mutated block" $ do
    let e = btcE {checkBlock = const BlockMutated}
        r = inboundReady btcO e []
        blk = Block (headerAfter btc (headerHash btc.genesisHeader) 1) []
    Discourage `elem` actions (snd (step btcO e r (Receive (MBlock blk)))) `shouldBe` True
  it "punishes an invalid block but not a duplicate" $ do
    let bad = btcE {checkBlock = const (BlockInvalid True "bad-txns")}
        dup = btcE {checkBlock = const BlockDuplicate}
        blk = Block btc.genesisHeader []
    Discourage `elem` actions (snd (step btcO bad (inboundReady btcO bad []) (Receive (MBlock blk)))) `shouldBe` True
    Discourage `elem` actions (snd (step btcO dup (inboundReady btcO dup []) (Receive (MBlock blk)))) `shouldBe` False
  it "ignores a cmpctblock from a peer that did not offer compact blocks" $ do
    let cb = CompactBlock btc.genesisHeader 0 [] []
    lines' (snd (step btcO btcE s (Receive (MCompactBlock cb)))) `shouldBe` [4799]
  it "closes on an empty getblocktxn and ignores an unexpected blocktxn" $ do
    let h = headerHash btc.genesisHeader
    lines' (snd (step btcO btcE s (Receive (MGetBlockTxn (GetBlockTxn h []))))) `shouldBe` [4567]
    lines' (snd (step btcO btcE s (Receive (MBlockTxn (BlockTxn h []))))) `shouldBe` [3721]
  it "closes on BIP 157 requests without -peerblockfilters" $ do
    let h = headerHash btc.genesisHeader
    lines' (snd (step btcO btcE s (Receive (MGetCFilters (GetCFilters 0 0 h))))) `shouldBe` [3530]
    lines' (snd (step btcO btcE s (Receive (MGetCFHeaders (GetCFHeaders 0 0 h))))) `shouldBe` [3530]
    lines' (snd (step btcO btcE s (Receive (MGetCFCheckpt (GetCFCheckpt 0 h))))) `shouldBe` [3530]
  it "drops transactions during initial block download" $
    lines' (snd (step btcO btcE s (Receive (MTx aTx)))) `shouldBe` [4718]
  it "hands a valid transaction to the node" $ do
    let e = btcE {initialBlockDownload = False, checkTx = const TxAcceptedToMempool}
    actions (snd (step btcO e (inboundReady btcO e []) (Receive (MTx aTx))))
      `shouldBe` [Process "transaction accepted"]
  it "passes notfound to the transaction download" $ do
    let nf = NotFound [InvVector InvTx (txHash aTx).get]
    lines' (snd (step btcO btcE s (Receive (MNotFound nf)))) `shouldBe` [5355]
  it "refuses mempool without bloom filters, quietly for noban" $ do
    lines' (snd (step btcO btcE s (Receive MMempool))) `shouldBe` [5195]
    let nb = inboundReady btcO btcE [PermNoBan]
    lines' (snd (step btcO btcE nb (Receive MMempool))) `shouldBe` [5197]
    let mp = inboundReady btcO btcE [PermMempool]
    snd (step btcO btcE mp (Receive MMempool)) `shouldBe` []
  it "records a fee filter" $
    feeFilterOf (fst (step btcO btcE s (Receive (MFeeFilter (FeeFilter 2000))))) `shouldBe` Just 2000
  it "checks the Bloom filter messages" $ do
    let bf = bloomCreate 10 0.001 0 BloomUpdateNone
    lines' (snd (step btcO btcE s (Receive (MFilterLoad (FilterLoad bf))))) `shouldBe` [5245]
    lines' (snd (step btcO btcE s (Receive (MFilterAdd (FilterAdd "abc"))))) `shouldBe` [5271]
    lines' (snd (step btcO btcE s (Receive MFilterClear))) `shouldBe` [5299]
    let o = btcO {peerBloomFilters = True}
        b = inboundReady o btcE []
        big = BloomFilter (Seq.replicate 36001 0) 1 0 BloomUpdateNone
    take 1 (lines' (snd (step o btcE b (Receive (MFilterLoad (FilterLoad big)))))) `shouldBe` [5254]
    take 1 (lines' (snd (step o btcE b (Receive (MFilterAdd (FilterAdd "abc")))))) `shouldBe` [5291]
    let (b1, es1) = step o btcE b (Receive (MFilterLoad (FilterLoad bf)))
    es1 `shouldBe` []
    txRelayEnabled b1 `shouldBe` True
    snd (step o btcE b1 (Receive (MFilterAdd (FilterAdd "abc")))) `shouldBe` []
    snd (step o btcE b1 (Receive MFilterClear)) `shouldBe` []
  it "rate-limits and checks addresses" $ do
    let a = ipv4 [8, 8, 8, 8]
        (_, es) = step btcO btcE s (Receive (MAddrV2 (AddrV2 (replicate 1001 a))))
    take 1 (lines' es) `shouldBe` [5984]
    Discourage `elem` actions es `shouldBe` True
    let s0 = start btcO (setup BlockRelayOnly [])
        (br, _) = run btcO btcE s0 [Tick, Receive (MVersion peerVer), Receive MVerAck]
    lines' (snd (step btcO btcE br (Receive (MAddrV2 (AddrV2 [a]))))) `shouldBe` [5978]
    let f0 = start btcO (setup AddrFetch [])
        (af, _) = run btcO btcE f0 [Tick, Receive (MVersion peerVer), Receive MVerAck]
        a2 = ipv4 [8, 8, 4, 4]
        (af1, es2) = step btcO btcE af (Receive (MAddrV2 (AddrV2 [a, a2])))
    last (lines' es2) `shouldBe` 6055
    isDisconnected af1 `shouldBe` True
  it "answers getaddr once, from inbound peers only" $ do
    let a = ipv4 [8, 8, 8, 8]
        e = btcE {addressesForPeer = const [a]}
        r = inboundReady btcO e []
        (r1, es1) = step btcO e r (Receive MGetAddr)
    es1 `shouldBe` []
    addrRelayEnabled r1 `shouldBe` True
    commands (sent (snd (step btcO e r1 Tick))) `shouldContain` [MCAddr]
    lines' (snd (step btcO e r1 (Receive MGetAddr))) `shouldBe` [5169]
    let ob = outboundReady btcO e
    lines' (snd (step btcO e ob (Receive MGetAddr))) `shouldBe` [5158]
  it "disconnects a transaction inv on a block-relay-only connection" $ do
    let s0 = start btcO (setup BlockRelayOnly [])
        (br, _) = run btcO btcE s0 [Tick, Receive (MVersion peerVer), Receive MVerAck]
        inv = MInv (Inv [InvVector InvTx (txHash aTx).get])
    lines' (snd (step btcO btcE br (Receive inv))) `shouldBe` [4394]
  it "asks for headers after a block inv" $ do
    let inv = MInv (Inv [InvVector InvBlock (hashN 5)])
    commands (sent (snd (step btcO btcE s (Receive inv)))) `shouldBe` [MCGetHeaders]

notificationSpec :: Spec
notificationSpec = describe "sending and notifications" $ do
  it "sends a fee filter and starts the headers sync on the first pass" $ do
    let s = inboundReady btcO btcE []
        cmds = commands (sent (snd (step btcO btcE s Tick)))
    cmds `shouldContain` [MCPing]
    cmds `shouldContain` [MCGetHeaders]
    cmds `shouldContain` [MCFeeFilter]
  it "sends no fee filter in blocks-only mode or on block-relay-only connections" $ do
    let o = btcO {blocksOnly = True}
        s = inboundReady o btcE []
    commands (sent (snd (step o btcE s Tick))) `shouldNotContain` [MCFeeFilter]
  it "requests a block from the peer with the witness flag" $ do
    let s = inboundReady btcO btcE []
        h = (hashN 7)
        (s1, es) = step btcO btcE s (Notify (RequestBlock h))
    sent es `shouldBe` [MGetData (GetData [InvVector InvWitnessBlock h.get])]
    blocksInFlight s1 `shouldBe` [h]
  it "disconnects a peer that holds a block too long" $ do
    let s = inboundReady btcO btcE []
        h = (hashN 7)
        (s1, _) = step btcO btcE s (Notify (RequestBlock h))
        later = at (t0 + seconds 601) btcE
        (s2, _) = step btcO later s1 (Receive (MPing (Ping 1)))
        (_, es) = step btcO later s2 Tick
    lines' es `shouldContain` [6465]
  it "disconnects a staller after 2 seconds" $ do
    let s = inboundReady btcO btcE []
        h = (hashN 7)
        (s1, _) = run btcO btcE s [Notify (RequestBlock h), Notify MarkStalling]
        (_, es) = step btcO (at (t0 + seconds 3) btcE) s1 Tick
    lines' es `shouldContain` [6446]
  it "announces an accepted transaction at the next trickle" $ do
    let inPool h = if h `elem` [txHash aTx, txWitnessHash aTx] then Just aTx else Nothing
        e = btcE {initialBlockDownload = False, mempoolTx = inPool}
        s = inboundReady btcO e []
        (s1, _) = step btcO e s Tick
        (s2, _) = step btcO e s1 (Notify (TxAccepted aTx))
        (_, es) = step btcO (at (t0 + seconds 600) e) s2 Tick
    [length l | MInv (Inv l) <- sent es] `shouldBe` [1]
  it "queues new blocks and announces them by inv to a plain peer" $ do
    let gi = genesisInfo btc
        hdr = headerAfter btc gi.hash 1
        h = headerHash hdr
        bi =
          BlockInfo
            { hash = h,
              height = 1,
              status = HaveData,
              inActiveChain = True,
              work = gi.work * 2,
              time = gi.time
            }
        e =
          btcE
            { initialBlockDownload = False,
              lookupBlock = \x -> if x == h then Just bi else if x == gi.hash then Just gi else Nothing,
              headerOf = \x -> if x == h then Just hdr else Nothing
            }
        s = inboundReady btcO e []
        (s1, _) = step btcO e s Tick
        (s2, _) = step btcO e s1 (Notify (NewTip [hdr]))
        (_, es) = step btcO e s2 Tick
    [l | MInv (Inv l) <- sent es] `shouldBe` [[InvVector InvBlock h.get]]
  it "closes the connection when the operator asks" $ do
    let s = inboundReady btcO btcE []
        (s1, es) = step btcO btcE s (Notify OperatorDisconnect)
    actions es `shouldBe` [Disconnect Resources]
    snd (step btcO btcE s1 Tick) `shouldBe` []
  it "pings at once when asked" $ do
    let s = inboundReady btcO btcE []
        (s1, _) = step btcO btcE s Tick
        (s2, _) = step btcO btcE s1 (Receive (MPing (Ping 1)))
        (s3, _) = step btcO btcE s2 (Notify PingRequested)
    commands (sent (snd (step btcO btcE s3 Tick))) `shouldContain` [MCPing]
  it "has no ping outstanding before the handshake" $
    isNothing (pingOutstanding (start btcO (setup Inbound []))) `shouldBe` True
