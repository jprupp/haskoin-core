# The peer-to-peer protocol of the reference nodes

The peer-to-peer protocol of Bitcoin and Bitcoin Cash is defined by what the
reference nodes do, not by a specification. The BIPs describe the messages.
They leave out most of what decides whether a connection lives: which messages
a node drops before the handshake, which ones it counts as misbehaviour, when
it pings and how long it waits, what a whitelisted peer may do that others may
not, and how all of this changes from one connection type to another. A
program that talks to these nodes, such as
[haskoin-node](https://github.com/jprupp/haskoin-node), needs that map to
behave correctly, and its tests need something to check against.

This directory holds the map, in prose, for the two upstream releases that
haskoin-core follows. The same rules are translated into pure Haskell state
machines in `src/Haskoin/Network/Protocol`, one per supported network. Every
rule in the reports and every effect of the machines names the upstream file
and line that decides it.

| Report                                           | Upstream            | Haskell module                             |
| ------------------------------------------------ | ------------------- | ------------------------------------------ |
| [Bitcoin Core 32.1](bitcoin-core.md)             | tag `v32.1`         | `Haskoin.Network.Protocol.BitcoinCore`     |
| [Bitcoin Cash Node 29.2.0](bitcoin-cash-node.md) | tag `v29.2.0`       | `Haskoin.Network.Protocol.BitcoinCashNode` |

The commits in full: Bitcoin Core `f0de87f040621468b956f01f526a43a010310501`,
Bitcoin Cash Node `07576013c91ff4a3a74acd85f189c69121cdad1b`. These are the
releases that the regtest image of haskoin-node runs.

## One machine per network

`Haskoin.Network.Protocol.machine` picks the machine of a network: the rules of
its reference node, with the options that node has when started with none on
that network.

| Network      | Value        | Node              | Magic      | Port  |
| ------------ | ------------ | ----------------- | ---------- | ----- |
| Bitcoin      | `btc`        | Bitcoin Core      | `f9beb4d9` | 8333  |
| testnet3     | `btcTest`    | Bitcoin Core      | `0b110907` | 18333 |
| testnet4     | `btcTest4`   | Bitcoin Core      | `1c163f28` | 48333 |
| regtest      | `btcRegTest` | Bitcoin Core      | `fabfb5da` | 18444 |
| Bitcoin Cash | `bch`        | Bitcoin Cash Node | `e3e1f3e8` | 8333  |
| testnet3     | `bchTest3`   | Bitcoin Cash Node | `f4e5f3f4` | 18333 |
| testnet4     | `bchTest4`   | Bitcoin Cash Node | `e2b7daaf` | 28333 |
| regtest      | `bchRegTest` | Bitcoin Cash Node | `dab5bffa` | 18444 |

On each node the rules are the same on its four chains. What changes is the
data the rules read: the magic, the minimum chain work (zero on regtest, which
changes when `getheaders` is answered and when `sendheaders` is sent), and on
Bitcoin Cash the block size, which bounds the messages that carry blocks and
the number of transactions announced at a time. Each report has a section
"Differences by network" with the details and the upstream lines.

```haskell
import Haskoin.Network.Constants (btc)
import Haskoin.Network.Protocol

-- The node is Bitcoin Core on mainnet; the peer connected to it.
let conn0 = start (machine btc) setup
    (conn1, effects) = step env conn0 (Receive (MVersion ourVersion))
-- effects: the node's version, wtxidrelay, sendaddrv2, verack, each with
-- the Cite of the upstream line that sends it.
```

`setup` says who opened the connection, the permissions of the peer and its
address network. `env` answers what the rest of the node would: the time, the
tip, whether a header connects, what the mempool holds. The module headers in
`Haskoin.Network.Protocol` and `Haskoin.Network.Protocol.Types` explain the
design and its trade-offs.

## Where the two nodes differ

Bitcoin Cash Node forked from Bitcoin Core in 2017 and the two have drifted
apart since. These are the differences that a peer is most likely to run
into. The reports give each with its upstream lines.

- **Misbehaviour.** Bitcoin Core: no score: one offence marks the peer to be
  discouraged and dropped. Bitcoin Cash Node: a ban score per peer; at
  `-banscore` (100) discouraged and dropped.
- **Messages before `version`.** Bitcoin Core: dropped without a penalty.
  Bitcoin Cash Node: 10 points each: ten of them get the peer discouraged.
- **Wrong magic.** Bitcoin Core: the connection closes. Bitcoin Cash Node: the
  address is discouraged and every connection from it closes.
- **Wrong checksum.** Bitcoin Core: the message is dropped; the connection
  stays. Bitcoin Cash Node: the address is discouraged and every connection
  from it closes.
- **Transport.** Bitcoin Core: BIP 324 offered; a v1 peer must send `version`
  as its first message. Bitcoin Cash Node: the original framing only.
- **Handshake extras.** Bitcoin Core: `wtxidrelay`, `sendaddrv2`, `sendtxrcncl`
  (off by default), `feature`. Bitcoin Cash Node: `extversion` (off by
  default), `sendaddrv2`.
- **`reject` (BIP 61).** Bitcoin Core: never sent; received ones are ignored.
  Bitcoin Cash Node: sent by default.
- **Low-work headers.** Bitcoin Core: presync and redownload before any header
  is stored. Bitcoin Cash Node: stored as soon as they are valid; a counter of
  unconnecting headers.
- **Compact blocks.** Bitcoin Core: version 2 (wtxid), 16-bit indexes. Bitcoin
  Cash Node: version 1, 32-bit indexes, a block in flight from up to 3 peers.
- **Compact filters (BIP 157).** Bitcoin Core: served with `-peerblockfilters`
  (off by default). Bitcoin Cash Node: not implemented.
- **Double-spend proofs.** Bitcoin Core: none. Bitcoin Cash Node:
  `dsproof-beta`.
- **Transaction announcements.** Bitcoin Core: two token buckets shared by all
  inbound and all outbound peers. Bitcoin Cash Node: a trickle per peer, its
  size set by the block size.
- **Permissions.** Bitcoin Core: `download` exists; `noban` includes it.
  Bitcoin Cash Node: no `download`; only inbound peers get permissions.
- **Block-relay-only connections.** Bitcoin Core: two are opened. Bitcoin Cash
  Node: defined, never opened.
- **Private broadcast connections.** Bitcoin Core: a short connection that
  sends one of the node's own transactions. Bitcoin Cash Node: none.

Both nodes ignore an unknown message after the handshake, and both drop
everything but the handshake messages between `version` and `verack`.

## Whitelisted peers

Both nodes grant permissions to a peer that matches `-whitelist` or
`-whitebind`. A bare entry, with no list of flags, gives `noban` and `mempool`,
`relay` unless `-blocksonly` is set or `-whitelistrelay` is off, and
`forcerelay` with `-whitelistforcerelay`. On Bitcoin Core `noban` brings
`download` too. What each permission changes, rule by rule, is in the section
"Permissions" and the closing section "Differences by permission and
connection type" of each report. In the machines, `Setup.permissions` takes
the flags as configured, and `start` expands them as the node does.

## Keeping the reports and the machines in sync

The reports and the modules describe the same rules and change together: a
change to a rule changes the function, its `Cite`, its Haddock, its test and
the paragraph of the report in the same commit. Each report begins with the
steps to bring it, and its machine, to a new upstream release: diff the
upstream files between the two tags, find the rules whose cited lines fall in
the changed hunks, and update the rule, the line, the test and the report.
The tests check the cited lines of many effects, so a line that moves fails a
test until both are updated.

The citations of a machine can be printed next to the upstream lines they
point at, from a checkout of the upstream tag:

```sh
scripts/protocol-cites.sh core ../bitcoin
scripts/protocol-cites.sh bchn ../bitcoin-cash-node
```

## What is not here yet

The reports are read from the source. They have not yet been checked against
running nodes. The next steps are to drive regtest nodes of both releases
with raw peers that check each rule, and to record what the nodes send on the
wire, so that each rule can be marked as confirmed on a release.
