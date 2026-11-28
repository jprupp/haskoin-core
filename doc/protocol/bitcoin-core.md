# The peer-to-peer protocol of Bitcoin Core 32.1

This report describes how Bitcoin Core 32.1 (tag `v32.1`, commit
`f0de87f040621468b956f01f526a43a010310501`) treats one peer: what it sends, what it
drops, what closes the connection and what gets the peer's address discouraged. It
is the prose companion of the module `Haskoin.Network.Protocol.BitcoinCore` and its
submodules, which translate the same rules into a pure state machine. Every rule
names the upstream line that decides it, as a link to the source at the commit,
and the Haskell function that implements it.

Links name the file by a short key and the line: `np` is `src/net_processing.cpp`,
`net` is `src/net.cpp`, `nh` is `src/net.h`, `perm` is `src/net_permissions.h`, `pv` is
`src/node/protocol_version.h`, `hs` is `src/headerssync.cpp`, `tr` is
`src/node/txreconciliation.cpp`, `fee` is `src/policy/fees/block_policy_estimator.cpp`,
`init` is `src/init.cpp` and `cp` is `src/kernel/chainparams.cpp`.

<!-- The link references stay on one line each: Markdown cannot continue a URL
     on the next line. -->

## Keeping this report in sync

The report and the modules under `src/Haskoin/Network/Protocol/BitcoinCore` change
together: a change to a rule changes the function, its `Cite`, its Haddock and the
paragraph here in the same commit. The tests in
`test/Haskoin/Network/Protocol/BitcoinCoreSpec.hs` assert the cited lines of many
effects, so a `Cite` that changes changes its test too.

To bring both to a new upstream release:

1. Check out the new tag and note its commit. Change `upstream` in
   `BitcoinCore/Constants.hs` and the commit in the links of this report.
2. Diff `src/net_processing.cpp`, `src/net.cpp`, `src/net.h`,
   `src/net_permissions.h`, `src/node/protocol_version.h`, `src/headerssync.cpp`
   and `src/kernel/chainparams.cpp` between the two tags.
3. For each hunk, find the handlers whose `Cite` falls in it (`grep` the line
   numbers in the submodules), and update the rule, the line and this report.
   Lines that only moved still need their numbers changed: a script that prints
   the upstream line behind every `Cite` makes this quick.
4. Check the constants in `BitcoinCore/Constants.hs` against their definitions.
5. Run `haskell-dev test Protocol`.

## How the machine maps onto the upstream code

Upstream handles a peer in three places: the socket thread reads bytes and runs
the inactivity checks ([net 2267]), the message thread runs `ProcessMessages`, which
handles one message with `ProcessMessage` ([np 5479]), and then `SendMessages` for
the same peer ([np 6059]). The machine has one input for each:

- `Receive`: `ProcessMessage`, then the punishment check that opens `SendMessages`.
  Haskell: `step`, `processMessage`, `maybeDiscourageAndDisconnect`.
- `BadFrame`: `V1Transport`, `V2Transport` and the exception handler of
  `ProcessMessages`. Haskell: `badFrame`.
- `Tick`: `InactivityCheck`, then `SendMessages`. Haskell: `inactivityCheck`,
  `sendMessages`.
- `Notify`: the rest of the node: validation signals, the download scheduler, RPC.
  Haskell: `notify`.

Validation, the mempool, the address manager and every decision that spans peers
are answers of the `Env` or come as a `Notification`. Once the node decides to
close a connection (`fDisconnect`), nothing more is processed for it
([net 3249]); `step` returns no effect for a closed connection.

[net 2267]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L2267
[np 5479]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5479
[np 6059]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6059
[net 3249]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L3249

## Framing

| Rule | Upstream | Haskell |
|---|---|---|
| A V1 header with another network's magic is a transport error: the socket closes. | [net 763] | `badFrame` |
| A V1 payload over 4,000,000 bytes closes the socket, before the payload is read. | [net 771] | `badFrame` |
| A wrong checksum drops the message; the connection stays. | [net 830] | `badFrame` |
| A command that is not printable ASCII padded with zeros drops the message. | [net 837] | `badFrame` |
| A V2 responder that sees `version` after another magic disconnects. | [net 1140] | `badFrame` |
| A V2 packet over the size limit closes the socket. | [net 1228] | `badFrame` |
| A payload that does not parse throws; `ProcessMessages` catches it and drops the message. | [np 5492] | `badFrame` |

What changed before the parse failed stays changed upstream; the machine sees only
whole messages, so a `BadPayload` is a plain drop. Some library parsers fail where
Bitcoin Core would parse and then punish (a locator over 101 entries, more than
2,000 headers, an inventory over 50,000 entries): to see the punishment, hand the
machine the decoded message.

[net 763]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L763
[net 771]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L771
[net 830]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L830
[net 837]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L837
[net 1140]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L1140
[net 1228]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L1228
[np 5492]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5492

## Connection types and permissions

### Permissions

`start` expands the configured permissions as `AddWhitelistPermissionFlags` does
([net 586]): a bare `-whitelist` or `-whitebind` (implicit) gives `noban`, `mempool`,
`relay` when `-whitelistrelay` is on, and `forcerelay` with `-whitelistforcerelay`,
and the implicit flag is cleared. `-blocksonly` soft-sets `-whitelistrelay` off
([init 851]) and `-whitelistforcerelay` soft-sets it on ([init 861]). The bit masks
of `src/net_permissions.h` make `forcerelay` include `relay` ([perm 33]) and `noban`
include `download` ([perm 37]). Haskell: `expandPermissions`.

What each permission changes:

- `noban`: never discouraged or disconnected for misbehaviour ([np 5375]); the
  trickle fires at every pass ([np 6330]); a refused `mempool` is dropped quietly
  ([np 5192]); the headers sync timeout starts over instead of disconnecting
  ([np 6480]); an inbound peer becomes a preferred download peer ([np 4009]); its
  headers skip the anti-DoS work check ([np 3315]).
- `download`: gets headers while the tip has less than the minimum chain work
  ([np 4651]); ignores the upload target for historical blocks ([np 2622]).
- `relay`: may send transactions in blocks-only mode ([np 5886]), and the node's
  `version` then says relay ([np 1672]).
- `forcerelay`: a transaction the node has is relayed again ([np 4739]); the node
  sends it no `feefilter` ([np 5843]).
- `mempool`: may send `mempool` without Bloom filters ([np 5190]) and past the upload
  target ([np 5200]).
- `bloomfilter`: the node offers `NODE_BLOOM` to this peer only ([np 1713]).
- `addr`: no rate limit on the addresses it sends ([np 6001]); its `getaddr` is
  answered without the cache ([np 5176]).

### Local peers

A peer whose address is local, or an inbound Tor peer, whose address is that of the
local proxy, is disconnected but not discouraged when it misbehaves ([np 5393]):
discouraging the proxy's address would discourage every Tor peer. The `Setup` says
whether the peer is local (`peerIsLocal`); an inbound connection on a Tor address
network counts as local too. Haskell: `start`, `maybeDiscourageAndDisconnect`.

### Connection types

- Inbound: no services required. The node's relay flag is off only in blocks-only
  mode without `relay`. Address relay starts with the peer's `addr`, `addrv2` or
  `getaddr`. Subject to the self-connection check and the tx-relay slots.
- Outbound full relay: requires `NODE_NETWORK` (or `NODE_NETWORK_LIMITED` near the
  tip) and `NODE_WITNESS`. Relay flag as inbound. The node sends `getaddr` at
  `version`. Chain sync eviction applies; four caught-up peers are protected from it.
- Manual: no services required; relay flag as inbound; `getaddr` at `version`;
  never punished.
- Feeler: no services required; relay off; no address relay; disconnected right
  after `version`.
- Block-relay-only: services as outbound; relay off; no address relay; a
  transaction closes the connection; chain sync eviction applies.
- Address fetch: services as outbound; relay flag as inbound; `getaddr` at
  `version`; done after an `addr` of more than one address, or after 300 seconds.
- Private broadcast: services as outbound; relay off, version 70016 and an anonymous
  `version`; no address relay; sends only `version`, `verack`, `inv`, `tx` and
  `ping`; lives 3 minutes.

Upstream: services [np 3865] and `ExpectServicesFromConn` ([nh 851]); relay flag
[np 5880]; address relay [np 5950] and [np 4016]; feeler [np 4067]; address fetch
[np 6053] and [np 6098]; private broadcast [np 1656], [net 4170] and [np 6089].
Haskell: `handleVersion`, `rejectIncomingTxs`, `setupAddressRelay`, `send`,
`sendMessages`.

[net 586]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L586
[init 851]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/init.cpp#L851
[init 861]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/init.cpp#L861
[perm 33]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_permissions.h#L33
[perm 37]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_permissions.h#L37
[np 5375]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5375
[np 6330]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6330
[np 5192]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5192
[np 6480]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6480
[np 4009]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4009
[np 3315]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3315
[np 4651]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4651
[np 2622]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2622
[np 5886]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5886
[np 1672]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L1672
[np 4739]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4739
[np 5843]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5843
[np 5190]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5190
[np 5200]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5200
[np 1713]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L1713
[np 6001]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6001
[np 5176]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5176
[np 5393]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5393
[np 3865]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3865
[nh 851]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.h#L851
[np 5880]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5880
[np 5950]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5950
[np 4016]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4016
[np 4067]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4067
[np 6053]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6053
[np 6098]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6098
[np 1656]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L1656
[net 4170]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L4170
[np 6089]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6089

## Handshake

### The node's `version`

An outbound connection sends the node's `version` on its first `SendMessages`
([np 6074]); an inbound one answers the peer's `version` ([np 3915]). It carries
version 70017 ([pv 12]), the services offered to this peer, the time, the nonce of
the connection, the user agent, the height of the tip and the relay flag
([np 1675]). A private broadcast connection sends version 70016, no services, time
0, height 0, the user agent `/pynode:0.0.1/` and no relay ([np 1656]). Haskell:
`pushNodeVersion`. The machine leaves `addr_recv` empty: it does not know the peer's
address.

If an outbound peer's message arrives before the node's first pass, upstream keeps
the message until the `version` is sent ([np 5430]); the machine sends the
`version` first and then processes the message (`step`).

### `version`

In order ([np 3837] onwards; Haskell `handleVersion`):

1. A second `version` is dropped ([np 3839]).
2. A connection type that expects services disconnects a peer without them
   ([np 3865]). The desirable services are `NODE_NETWORK | NODE_WITNESS`, or
   `NODE_NETWORK_LIMITED | NODE_WITNESS` from a limited peer when the tip is less
   than 144 block intervals old by the clock ([np 1867]). Haskell:
   `desirableServices`.
3. A version below 31800 disconnects ([np 3875]).
4. An inbound peer whose nonce is that of one of the node's own outbound
   connections is the node itself: disconnect ([np 3901]). Env: `ownNonce`.
5. Inbound: the node sends its `version` ([np 3915]).
6. The common version is the smaller of the two ([np 3920]). Transaction relay is
   set up unless the connection is block-relay-only or a feeler, if the peer asked
   for transactions or the node offers it Bloom filters ([np 3938]).
7. Private broadcast: `verack` if the peer relays, otherwise disconnect ([np 3955]).
8. Common version 70016 or more: `wtxidrelay` ([np 3966]) and `sendaddrv2`
   ([np 3971]).
9. With `-txreconciliation`, a peer that relays, not an address fetch, outside
   blocks-only: `sendtxrcncl` with a fresh salt ([np 3979]).
10. An inbound peer that relays transactions takes a tx-relay slot; when they are
    full and no other peer can be evicted, it is dropped before `verack`
    ([np 4002], [np 5409]). Env: `txRelayInboundFull`.
11. `verack` ([np 4003]).
12. Preferred download peer: outbound or `noban`, not address fetch, and the peer
    serves blocks ([np 4009]).
13. Outbound, not block-relay-only or feeler: address relay starts and the node sends
    `getaddr`, with 1,000 more address tokens ([np 4016]).
14. Common version 70012 or less: the final `alert` ([np 4061]).
15. A feeler disconnects ([np 4067]).

So an inbound peer sees `version`, `wtxidrelay`, `sendaddrv2`, (`sendtxrcncl`),
`verack`; an outbound full relay peer sees `wtxidrelay`, `sendaddrv2`, `verack`,
`getaddr` after the node's earlier `version`.

### Before `version` and before `verack`

Any message before an accepted `version` is dropped ([np 4074]). Between
`version` and `verack`, `verack`, `sendheaders`, `sendcmpct`, `wtxidrelay`,
`sendaddrv2`, `feature` and `sendtxrcncl` are handled, and every other message is
dropped ([np 4320]). Haskell: `processMessage`.

### `verack`

A second `verack` is dropped ([np 4081]). On a private broadcast connection the
handshake ends and the node announces its transaction with `inv`, or disconnects if
it has none ([np 4117], [np 3813]; Env `privateBroadcastTx`). Otherwise, with a
common version of 70014 or more, the node sends `sendcmpct(0, 2)` ([np 4128]),
forgets an Erlay registration that did not complete ([np 4137]), and the handshake
is done ([np 4156]). Haskell: `handleVerAck`.

### `wtxidrelay`, `sendaddrv2`, `feature`, `sendtxrcncl`

- `wtxidrelay` after `verack` disconnects; before it, it counts with a common version of
  70016 or more; a second one is dropped. Upstream: [np 4193], [np 4199], [np 4204];
  Haskell: `handleWtxidRelay`.
- `sendaddrv2` after `verack` disconnects; before it, any version. Upstream: [np 4215],
  [np 4221]; Haskell: `handleSendAddrV2`.
- `feature` after `verack`, or with a common version below 70017, disconnects; a payload
  that is not an id of 4 to 80 bytes and data of at most 512 bytes, with nothing after,
  disconnects; a good one is unknown and ignored. Upstream: [np 4226], [np 4231],
  [np 4248], [np 4260]; Haskell: `handleFeature`.
- `sendtxrcncl` without `-txreconciliation` is ignored, even after `verack`. Upstream:
  [np 4268]; Haskell: `handleSendTxRcncl`.
- `sendtxrcncl` after `verack`, to a peer told not to relay, or from a peer that does
  not relay, disconnects. Upstream: [np 4273], [np 4280], [np 4290]; Haskell:
  `handleSendTxRcncl`.
- `sendtxrcncl` without ours is ignored; a second one, or version 0, disconnects.
  Upstream: [np 4303], [np 4308], [np 4312], [tr 118]; Haskell: `handleSendTxRcncl`.

The library does not know `feature`: it arrives as `MOther "feature"`.

[np 6074]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6074
[np 3915]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3915
[pv 12]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/node/protocol_version.h#L12
[np 1675]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L1675
[np 1656]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L1656
[np 5430]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5430
[np 3837]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3837
[np 3839]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3839
[np 3865]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3865
[np 1867]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L1867
[np 3875]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3875
[np 3901]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3901
[np 3920]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3920
[np 3938]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3938
[np 3955]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3955
[np 3966]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3966
[np 3971]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3971
[np 3979]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3979
[np 4002]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4002
[np 5409]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5409
[np 4003]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4003
[np 4009]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4009
[np 4016]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4016
[np 4061]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4061
[np 4067]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4067
[np 4074]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4074
[np 4320]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4320
[np 4081]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4081
[np 4117]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4117
[np 3813]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3813
[np 4128]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4128
[np 4137]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4137
[np 4156]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4156
[np 4193]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4193
[np 4199]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4199
[np 4204]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4204
[np 4215]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4215
[np 4221]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4221
[np 4226]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4226
[np 4231]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4231
[np 4248]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4248
[np 4260]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4260
[np 4268]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4268
[np 4273]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4273
[np 4280]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4280
[np 4290]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4290
[np 4303]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4303
[np 4308]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4308
[np 4312]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4312
[tr 118]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/node/txreconciliation.cpp#L118

## Ping

- A ping waiting more than 20 minutes, once the connection is past `-peertimeout`,
  disconnects. Upstream: [np 5699]; Haskell: `maybeSendPing`.
- The node pings when asked (`PingRequested`), or when none is waiting and the last was
  more than 2 minutes ago; the first goes out at the first pass after the handshake.
  Upstream: [np 5712], [np 5717]; Haskell: `maybeSendPing`.
- Above version 60000 the ping has a random non-zero nonce; otherwise it is empty and no
  pong is expected. Upstream: [np 5729]; Haskell: `maybeSendPing`.
- A `ping` gets a `pong` with its nonce above version 60000, nothing otherwise.
  Upstream: [np 5218]; Haskell: `handlePing`.
- A matching `pong` ends the ping; on a private broadcast connection it confirms
  delivery and disconnects. Upstream: [np 5902], [np 5909]; Haskell: `handlePong`.
- A `pong` with nonce 0 cancels the ping; another wrong nonce leaves it waiting; one
  without a ping is ignored; none is punished. Upstream: [np 5922], [np 5921],
  [np 5929]; Haskell: `handlePong`.

[np 5699]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5699
[np 5712]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5712
[np 5717]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5717
[np 5729]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5729
[np 5218]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5218
[np 5902]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5902
[np 5909]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5909
[np 5922]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5922
[np 5921]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5921
[np 5929]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5929

## Blocks

### Announcements the peer makes

- `sendheaders`, before or after `verack`: announce blocks to this peer with headers.
  Upstream: [np 4160]; Haskell: `handleSendHeaders`.
- `sendcmpct` with announce above 1 is misbehaviour, even before `verack`. Upstream:
  [np 4172]; Haskell: `rawSendCmpct`.
- `sendcmpct` of a version other than 2 is ignored; version 2 records whether the peer
  wants blocks pushed. Upstream: [np 4178], [np 4182]; Haskell: `handleSendCmpct`.
- A block `inv` updates what the peer has; the last unknown one triggers a `getheaders`
  from a syncing peer, or from one more peer per new block. Upstream: [np 4381],
  [np 4424]; Haskell: `blockInvs`.

`getMessage` refuses a `sendcmpct` with an announce byte above 1 on a Bitcoin
network, so a caller that parses bytes has a `BadPayload` for it, which the machine
drops. The rule on announce values above 1 is checked only for a raw
`MOther "sendcmpct"`.

### `getheaders`

A locator over 101 entries disconnects ([np 4634]). While reindexing, the request is
ignored ([np 4640]). While the tip has less than the minimum chain work, a peer
without `download` gets an empty `headers` ([np 4650]). An empty locator asks for
the one header of the stop hash, if it may be served ([np 4661]); otherwise the
answer is up to 2,000 headers of the active chain after the first locator entry on
it, stopping after the stop hash ([np 4676], [np 4685]). The best header sent
becomes the last one sent ([np 4703]). Haskell: `handleGetHeaders`, `forkHeight`.

A block may be served if it is on the active chain, or valid and at most 30 days
older than the best header ([np 2077]); the machine checks the time only, not the
equivalent work. Haskell: `blockRequestAllowed`.

### `headers`

In order (Haskell `handleHeaders`, `processHeaders`):

1. While reindexing, ignored ([np 5066]). More than 2,000 headers is misbehaviour
   ([np 5075]).
2. An empty message ends a low-work sync and clears the `getheaders` timer
   ([np 3222]).
3. A header with bad proof of work ([np 2867]), or a sequence that does not chain
   ([np 2873]), is misbehaviour.
4. A running low-work sync takes the headers ([np 3265]): a full message asks for
   more ([np 2944]); a short one ends the sync and the headers are dropped
   ([hs 103]).
5. Headers whose first parent is unknown get a `getheaders` from the best header,
   and their last hash is remembered ([np 3288], [np 2903]). No penalty.
6. Headers not already known to lead to enough work, from a peer without `noban`,
   whose claimed work is below the anti-DoS threshold, start a low-work sync if the
   message is full, and are ignored otherwise ([np 3322], [np 3026], [np 3056]).
7. Validation ([np 3339]): an invalid header is misbehaviour ([np 2063]); one already
   known invalid only from an outbound peer ([np 2056]); one from the future is
   not punished ([np 2069]).
8. A full message asks for more ([np 3362]).
9. The peer's best block moves; a new header with more work than the tip marks a
   block announcement ([np 3171], [np 3177]). In initial block download, an outbound
   full relay or block-relay-only peer whose chain still has less than the minimum
   chain work, and has no more headers, is disconnected ([np 3183]). A caught-up
   outbound full relay peer may be protected from chain sync eviction ([np 3207]).
10. When the tip is recent, up to 16 missing blocks toward the new headers are
    requested at once; a lone one as a compact block when nothing else is in
    flight ([np 3104], [np 3146]). A walk that does not reach the active chain is a
    large reorganisation and fetches nothing ([np 3122]). Haskell:
    `headersDirectFetch`.

The machine does not keep the commitments of the low-work sync
(`HeadersSyncState`): it follows the sync while `checkHeaders` says the headers have
too little work, and treats any other verdict as its end.

### `getblocks`

A locator over 101 entries disconnects ([np 4499]). Up to 500 hashes after the fork
point are queued for an `inv` at the next pass; a pruned node stops at blocks it may
not have; the 500th becomes the continuation block, whose request is followed by an
`inv` of the tip ([np 4534], [np 4549], [np 2728]). Haskell: `handleGetBlocks`,
`getBlockData`.

### `getdata` of blocks

`ProcessGetBlockData` ([np 2564]; Haskell `getBlockData`):

1. A filtered block without `NODE_BLOOM` offered disconnects ([np 2568]).
2. An unknown block, or one that may not be served, gets no answer ([np 2612],
   [np 2615]).
3. Past the upload target, a block more than a week older than the best header, or
   any filtered block, disconnects a peer without `download` ([np 2620]).
4. A pruned node disconnects a peer without `noban` that asks for a block more than
   290 deep ([np 2630]).
5. A block without data gets no answer ([np 2640]).
6. `MSG_BLOCK` gets the block without witnesses, `MSG_WITNESS_BLOCK` with them
   ([np 2681], [np 2683]); `MSG_FILTERED_BLOCK` gets `merkleblock` and the matching
   transactions if a filter is loaded ([np 2694]); `MSG_CMPCT_BLOCK` gets
   `cmpctblock` within 5 blocks of a recent tip, the block otherwise ([np 2712]).

A block that cannot be served never gets `notfound` ([np 2816]).

### `block`

While reindexing, ignored ([np 5107]). A block whose parent is known and that does
not match its merkle root or witness commitment is misbehaviour ([np 5120]).
Otherwise the request is cleared and the block goes to validation ([np 5147]). The
verdict comes back through `BlockChecked` ([np 2328]) and `MaybePunishNodeForBlock`
([np 2032]): invalid by consensus or mutated is misbehaviour unless the block came
from a compact block ([np 2047]); known invalid only for an outbound peer
([np 2056]); a missing parent always ([np 2067]). Haskell: `handleBlock`,
`processBlock`.

### Compact blocks

`cmpctblock` ([np 4784]; Haskell `handleCmpctBlock`): ignored while reindexing, in
blocks-only mode, and from a peer that never sent `sendcmpct` ([np 4787],
[np 4798]). A block whose parent is unknown gets a `getheaders` outside initial
block download ([np 4814]); one of too little work is ignored ([np 4820]). An
invalid header is misbehaviour, judged as from a compact block ([np 4835]). A block
the node did not ask for is taken only from a peer it chose for high bandwidth
([np 4887]). Near the tip, the node rebuilds the block from its mempool
([np 4926]): a malformed compact block is misbehaviour ([np 4929]); a failed
rebuild asks for the whole block if this is the first request ([np 4932]); missing
transactions are asked with `getblocktxn` ([np 4951]). Far ahead, a requested block
is asked whole and an unrequested one counts as a header announcement ([np 4991]).
Env: `initCompact`.

`getblocktxn` ([np 4560]; Haskell `handleGetBlockTxn`): an empty list disconnects
([np 4565]); a block the node lacks gets no answer ([np 4594]); within 10 blocks of
the tip the transactions are sent, and a position past the end is misbehaviour
([np 2848]); deeper, the whole block is served as for `getdata` ([np 4623]).

`blocktxn` ([np 3697]; Haskell `handleBlockTxn`): for a block not being completed
from this peer, ignored ([np 3720]); a second one for the same block is
misbehaviour ([np 3727]); transactions that do not fit are misbehaviour
([np 3741]); a failed rebuild asks for the whole block if this is the first
request ([np 3745]). Env: `fillCompact`.

The node chooses up to three high-bandwidth peers across all its peers; the machine
gets the choice as `HighBandwidth` and sends `sendcmpct(1, 2)` or `sendcmpct(0, 2)`
([np 1412], [np 1422]). Haskell: `highBandwidth`.

### BIP 157

`getcfilters`, `getcfheaders`, `getcfcheckpt` ([np 3518]; Haskell
`prepareFilterRequest` and the three handlers): a filter type other than 0, or no
`NODE_COMPACT_FILTERS` offered, disconnects ([np 3524]); an unknown or unservable
stop hash disconnects ([np 3536]); a start above the stop disconnects ([np 3548]);
more than 1,000 filters or 2,000 headers disconnects ([np 3555]). A missing index
entry gets no answer. None of these discourages.

### Announcements the node makes

At each pass after the handshake (Haskell `sendBlockAnnouncements`):

- New blocks queued by `NewTip` (up to 8, only outside initial block download,
  [np 2295]) go out as one `cmpctblock` to a peer that wants them pushed, as
  `headers` to a peer that sent `sendheaders`, and otherwise as an `inv` of the
  newest ([np 6188], [np 6242], [np 6265], [np 6280]).
- Hashes queued by `getblocks` go out as `inv`, before the transactions
  ([np 6317]).
- `NewPoWValidBlock`: a new block that extends the tip goes at once as
  `cmpctblock` to a peer that wants them pushed, has the parent and not the block,
  with a common version of 70015 or more ([np 2268], [np 2274]). Haskell:
  `newPoWValidBlock`.
- `sendheaders` once the peer is known to have a block with more than the minimum
  chain work ([np 5823]). Haskell: `maybeSendSendHeaders`.
- The initial `getheaders` goes to the first peer to sync from, or to every peer once
  the best header is less than a day old; it starts the headers sync timeout
  ([np 6146]). Haskell: `initialGetHeaders`, `syncFromPeer`.
- A `getheaders` goes out at most once per 2 minutes while unanswered ([np 3086]).
  Haskell: `maybeSendGetHeaders`.

### Block download

Which block to fetch from which peer (`FindNextBlocksToDownload`, [np 6511]) spans
peers: the node sends `RequestBlock`, and the machine sends `getdata` with the
witness flag when the peer offers `NODE_WITNESS` ([np 6534], [np 2835]), at most 16
in flight. Haskell: `requestBlock`.

[np 4160]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4160
[np 4172]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4172
[np 4178]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4178
[np 4182]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4182
[np 4381]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4381
[np 4424]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4424
[np 4634]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4634
[np 4640]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4640
[np 4650]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4650
[np 4661]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4661
[np 4676]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4676
[np 4685]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4685
[np 4703]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4703
[np 2077]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2077
[np 5066]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5066
[np 5075]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5075
[np 3222]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3222
[np 2867]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2867
[np 2873]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2873
[np 3265]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3265
[np 2944]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2944
[hs 103]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/headerssync.cpp#L103
[np 3288]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3288
[np 2903]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2903
[np 3322]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3322
[np 3026]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3026
[np 3056]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3056
[np 3339]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3339
[np 2063]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2063
[np 2056]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2056
[np 2069]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2069
[np 3362]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3362
[np 3171]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3171
[np 3177]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3177
[np 3183]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3183
[np 3207]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3207
[np 3104]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3104
[np 3146]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3146
[np 3122]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3122
[np 4499]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4499
[np 4534]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4534
[np 4549]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4549
[np 2728]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2728
[np 2564]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2564
[np 2568]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2568
[np 2612]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2612
[np 2615]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2615
[np 2620]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2620
[np 2630]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2630
[np 2640]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2640
[np 2681]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2681
[np 2683]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2683
[np 2694]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2694
[np 2712]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2712
[np 2816]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2816
[np 5107]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5107
[np 5120]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5120
[np 5147]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5147
[np 2328]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2328
[np 2032]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2032
[np 2047]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2047
[np 2067]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2067
[np 4784]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4784
[np 4787]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4787
[np 4798]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4798
[np 4814]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4814
[np 4820]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4820
[np 4835]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4835
[np 4887]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4887
[np 4926]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4926
[np 4929]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4929
[np 4932]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4932
[np 4951]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4951
[np 4991]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4991
[np 4560]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4560
[np 4565]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4565
[np 4594]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4594
[np 2848]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2848
[np 4623]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4623
[np 3697]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3697
[np 3720]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3720
[np 3727]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3727
[np 3741]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3741
[np 3745]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3745
[np 1412]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L1412
[np 1422]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L1422
[np 3518]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3518
[np 3524]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3524
[np 3536]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3536
[np 3548]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3548
[np 3555]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3555
[np 2295]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2295
[np 6188]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6188
[np 6242]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6242
[np 6265]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6265
[np 6280]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6280
[np 6317]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6317
[np 2268]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2268
[np 2274]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2274
[np 5823]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5823
[np 6146]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6146
[np 3086]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3086
[np 6511]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6511
[np 6534]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6534
[np 2835]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2835

## Transactions

- `inv` of more than 50,000 entries is misbehaviour. Upstream: [np 4350]; Haskell:
  `handleInv`.
- Entries of the hash type the peer does not use (txid or wtxid) are skipped. Upstream:
  [np 4371]; Haskell: `handleInv`.
- A transaction entry from a peer told not to send transactions disconnects at once.
  Upstream: [np 4392]; Haskell: `handleInv`.
- Other transaction entries go to the transaction download, outside initial block
  download. Upstream: [np 4403]; Haskell: `handleInv`.
- An unknown inventory type is logged. Upstream: [np 4407]; Haskell: `handleInv`.
- `getdata` of more than 50,000 entries is misbehaviour. Upstream: [np 4446]; Haskell:
  `handleGetData`.
- On a private broadcast connection, `getdata` must ask exactly for the announced
  transaction, which is sent with a ping. Upstream: [np 4458], [np 4471]; Haskell:
  `privateGetData`.
- Transactions are served from the mempool, without witnesses for `MSG_TX`; a peer
  without transaction relay gets nothing; missing ones get one `notfound`. Upstream:
  [np 2784], [np 2790], [np 2816]; Haskell: `handleGetData`.
- `tx` from a peer told not to send transactions disconnects. Upstream: [np 4709];
  Haskell: `handleTx`.
- `tx` in initial block download is dropped. Upstream: [np 4718]; Haskell: `handleTx`.
- A known transaction from a `forcerelay` peer is relayed again if in the mempool.
  Upstream: [np 4739]; Haskell: `handleTx`.
- No transaction verdict is ever punished. Upstream: [np 4765], [np 4772]; Haskell:
  `handleTx`.
- `notfound` marks the requests as failed; never punished. Upstream: [np 5347],
  [np 5355]; Haskell: `handleNotFound`.
- `mempool` without Bloom filters offered or `mempool`, or past the upload target,
  disconnects; silent for `noban`. Upstream: [np 5190], [np 5200]; Haskell:
  `handleMempool`.
- `feefilter` of a valid amount is kept. Upstream: [np 5319]; Haskell:
  `handleFeeFilter`.
- `filterload`, `filteradd`, `filterclear` without `NODE_BLOOM` offered disconnect, even
  for `noban`. Upstream: [np 5243], [np 5269], [np 5297]; Haskell: `handleFilterLoad`,
  `handleFilterAdd`, `handleFilterClear`.
- A filter over 36,000 bytes or 50 hash functions is misbehaviour. Upstream: [np 5251];
  Haskell: `handleFilterLoad`.
- `filteradd` over 520 bytes, or with no filter loaded, is misbehaviour. Upstream:
  [np 5280]; Haskell: `handleFilterAdd`.
- A loaded or cleared filter turns transaction relay on and takes a tx-relay slot.
  Upstream: [np 5259], [np 5308], [np 5263]; Haskell: `handleFilterLoad`,
  `handleFilterClear`.

The trickle (Haskell `sendTxTrickle`): a timer per outbound peer, with a mean of
2 seconds, and a timer shared by inbound peers, with a mean of 5 seconds
([np 6331]); a `noban` peer gets every pass ([np 6330]). When it fires, the answer
to `mempool` ([np 6347]) and the queued transactions go out, less those under the
peer's fee filter, those it knows and those its Bloom filter rejects ([np 6385]).
Upstream paces announcements with two token buckets shared by all peers; the
machine leaves that to the node, which queues a transaction for this peer with
`TxAccepted` (Haskell `txAccepted`), only after the first pass that followed the
handshake ([np 2468]). The node's transaction download asks the peer for a
transaction with `RequestTx` ([np 6553]; Haskell `requestTx`).

The fee filter (Haskell `maybeSendFeeFilter`, `roundFeeFilter`): not in blocks-only
mode, nor below version 70013, nor to `forcerelay` peers or block-relay-only
connections ([np 5840]); the mempool minimum, or the maximum in initial block
download ([np 5850]), rounded to a bucket, two times in three the one below
([fee 1142]), never below `-minrelaytxfee`; sent when it changes, about every 10
minutes, sooner after a large change ([np 5862], [np 5874]).

[np 4350]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4350
[np 4371]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4371
[np 4392]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4392
[np 4403]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4403
[np 4407]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4407
[np 4446]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4446
[np 4458]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4458
[np 4471]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4471
[np 2784]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2784
[np 2790]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2790
[np 2816]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2816
[np 4709]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4709
[np 4718]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4718
[np 4739]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4739
[np 4765]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4765
[np 4772]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4772
[np 5347]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5347
[np 5355]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5355
[np 5190]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5190
[np 5200]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5200
[np 5319]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5319
[np 5243]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5243
[np 5269]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5269
[np 5297]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5297
[np 5251]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5251
[np 5280]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5280
[np 5259]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5259
[np 5308]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5308
[np 5263]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5263
[np 6331]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6331
[np 6330]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6330
[np 6347]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6347
[np 6385]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6385
[np 2468]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2468
[np 6553]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6553
[np 5840]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5840
[np 5850]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5850
[fee 1142]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/policy/fees/block_policy_estimator.cpp#L1142
[np 5862]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5862
[np 5874]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5874

## Addresses

- No address relay with block-relay-only or feeler connections: `addr` is ignored.
  Upstream: [np 5977]; Haskell: `handleAddrs`.
- More than 1,000 addresses is misbehaviour. Upstream: [np 5982]; Haskell:
  `handleAddrs`.
- A token bucket, refilled at 0.1 a second up to 1,000, limits the addresses processed,
  unless `addr`. Upstream: [np 5993], [np 6011]; Haskell: `handleAddrs`.
- An address fetch connection is done after an `addr` of more than one address.
  Upstream: [np 6053]; Haskell: `handleAddrs`.
- `getaddr` from an outbound peer is ignored; a second one is ignored. Upstream:
  [np 5157], [np 5168]; Haskell: `handleGetAddr`.
- The `getaddr` answer comes from the cache, fresh for `addr` peers, and goes out with
  the next send. Upstream: [np 5176]; Haskell: `handleGetAddr`.
- The node's own address about once a day, at once the first time; the queue about every
  30 seconds; `addrv2` to peers that sent `sendaddrv2`. Upstream: [np 5747], [np 5781],
  [np 5804]; Haskell: `maybeSendAddr`.

Which peers relay an address (`RelayAddress`) is chosen across peers; the machine
queues an address when the node sends `RelayAddress` (Haskell `relayAddress`), and
hands received addresses to the node with a `Process` effect.

[np 5977]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5977
[np 5982]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5982
[np 5993]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5993
[np 6011]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6011
[np 6053]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6053
[np 5157]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5157
[np 5168]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5168
[np 5176]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5176
[np 5747]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5747
[np 5781]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5781
[np 5804]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5804

## Unknown and retired messages

After `verack`, a command with no handler is logged and ignored ([np 5360]). This
covers `alert`, `reject`, and the messages that only Bitcoin Core sends:
`merkleblock`, `cfilter`, `cfheaders`, `cfcheckpt`. Haskell: `processMessage`.

[np 5360]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5360

## Timers

| Timer | Value | Upstream | Haskell |
|---|---|---|---|
| Nothing received or sent after `-peertimeout` | 60 s | [net 2057] | `inactivityCheck` |
| Nothing sent, or nothing received | 20 min | [net 2070], [net 2078] | `inactivityCheck` |
| Handshake not done after `-peertimeout` | 60 s | [net 2097] | `inactivityCheck` |
| Ping without pong | 20 min | [np 5699] | `maybeSendPing` |
| Ping interval | 2 min | [np 5717] | `maybeSendPing` |
| Address fetch lifetime | 300 s | [np 6098] | `sendMessages` |
| Private broadcast lifetime | 3 min | [np 6090] | `sendMessages` |
| Block stalling | 2 s after `MarkStalling` | [np 6442] | `blockTimeouts` |
| Block download | 600 s, plus 300 s for each other downloading peer | [np 6464] | `blockTimeouts` |
| Headers sync (only syncing peer, another preferred one) | 15 min + 1 ms per header | [np 6474] | `blockTimeouts` |
| Chain sync of outbound peers | 20 min, then `getheaders` and 2 min | [np 5521], [np 5531] | `considerEviction` |
| Trickle | exponential, mean 5 s inbound, 2 s outbound | [np 6334], [np 6336] | `sendTxTrickle` |
| Address send | exponential, mean 30 s | [np 5783] | `maybeSendAddr` |
| Self-announcement | exponential, mean 24 h | [np 5777] | `maybeSendAddr` |
| Fee filter | exponential, mean 10 min | [np 5870] | `maybeSendFeeFilter` |

Upstream doubles the stalling timeout, up to 64 s, each time it disconnects a staller,
and lets it decay as blocks connect ([np 6450]); that is state of the whole node,
and the machine keeps 2 s. Extra outbound peers, stale tips and inbound eviction are
decided across peers: the node sends `Evict` (Haskell `notify`).

[net 2057]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L2057
[net 2070]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L2070
[net 2078]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L2078
[net 2097]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net.cpp#L2097
[np 5699]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5699
[np 5717]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5717
[np 6098]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6098
[np 6090]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6090
[np 6442]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6442
[np 6464]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6464
[np 6474]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6474
[np 5521]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5521
[np 5531]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5531
[np 6334]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6334
[np 6336]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6336
[np 5783]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5783
[np 5777]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5777
[np 5870]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5870
[np 6450]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L6450

## Misbehaviour

Bitcoin Core 32.1 has no ban score and no `-banscore` option: one `Misbehaving` call
flags the peer ([np 2019]), and `MaybeDiscourageAndDisconnect`, the first step of
the next `SendMessages`, acts on it ([np 5364]):

1. `noban`: nothing ([np 5375]).
2. Manual connection: nothing ([np 5381]).
3. Private broadcast: disconnect ([np 5387]).
4. Local address, or inbound Tor: disconnect ([np 5393]).
5. Otherwise: discourage the address and disconnect every connection from it
   ([np 5404]).

The machine emits `Discourage` with the `Cite` of the `Misbehaving` call, then
`Disconnect Misbehaviour`. A discouraged address is not banned: it is the first to
be evicted when inbound slots run out, and the node does not connect to it. Bans
come only from the `setban` RPC.

The calls to `Misbehaving`, all handled by the machine:

| Reason | Upstream |
|---|---|
| `invalid sendcmpct announce field` | [np 4173] |
| `inv message size = N` | [np 4352] |
| `getdata message size = N` | [np 4448] |
| `headers message size = N` | [np 5076] |
| `header with invalid proof of work` | [np 2867] |
| `non-continuous headers sequence` | [np 2873] |
| invalid header or block (`MaybePunishNodeForBlock`) | [np 2047], [np 2056], [np 2063], [np 2067] |
| `mutated block` | [np 5123] |
| `invalid compact block` | [np 4929] |
| `previous compact block reconstruction attempt failed` | [np 3732] |
| `invalid compact block/non-matching block transactions` | [np 3743] |
| `getblocktxn with out-of-bounds tx indices` | [np 2849] |
| `addr message size = N`, `addrv2 message size = N` | [np 5984] |
| `too-large bloom filter` | [np 5254] |
| `bad filteradd message` | [np 5291] |

Every other violation is a plain disconnect or a silent drop.

[np 2019]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2019
[np 5364]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5364
[np 5375]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5375
[np 5381]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5381
[np 5387]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5387
[np 5393]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5393
[np 5404]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5404
[np 4173]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4173
[np 4352]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4352
[np 4448]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4448
[np 5076]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5076
[np 2867]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2867
[np 2873]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2873
[np 2047]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2047
[np 2056]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2056
[np 2063]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2063
[np 2067]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2067
[np 5123]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5123
[np 4929]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4929
[np 3732]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3732
[np 3743]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L3743
[np 2849]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L2849
[np 5984]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5984
[np 5254]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5254
[np 5291]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L5291

## Differences by network

| | main (`btc`) | testnet3 (`btcTest`) | testnet4 (`btcTest4`) | regtest (`btcRegTest`) |
|---|---|---|---|---|
| Magic | `f9beb4d9` ([cp 149]) | `0b110907` ([cp 274]) | `1c163f28` ([cp 381]) | `fabfb5da` ([cp 620]) |
| Minimum chain work | `0x0145ec036acc5ba740052af1a0` | `0x17f49f702147f10c0eb6` | `0x0e346a558455ade8eca9` | 0 |
| Its line | [cp 141] | [cp 271] | [cp 378] | [cp 617] |
| Min-difficulty blocks | no | yes ([cp 259]) | yes ([cp 365]) | yes ([cp 606]) |
| BIP 94 | no | no | yes ([cp 366]) | with `-enforcebip94` |

What the minimum chain work changes in the machine: `getheaders` gets an empty
answer below it unless `download` (`handleGetHeaders`); `sendheaders` waits for the
peer to pass it (`maybeSendSendHeaders`); the anti-DoS threshold of headers
(`antiDoSThreshold`); the insufficient-work disconnect in initial block download
(`processHeaders`). On regtest it is 0, so `getheaders` is always answered and
`sendheaders` goes out as soon as the peer is known to have any block. Upstream
skips the difficulty transition check of the low-work sync on the test chains and
enforces BIP 94 in header validation; both are answers of `checkHeaders`. Every
timer, limit, protocol version and default option is the same on the four chains,
and so is the block interval of 600 seconds. Haskell: `defaultOptions`.

[cp 149]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L149
[cp 274]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L274
[cp 381]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L381
[cp 620]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L620
[cp 141]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L141
[cp 271]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L271
[cp 378]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L378
[cp 617]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L617
[cp 259]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L259
[cp 365]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L365
[cp 606]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L606
[cp 366]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/kernel/chainparams.cpp#L366

## Options

| Option | Default | Field of `Options` |
|---|---|---|
| `-blocksonly` | off | `blocksOnly` |
| `-peerbloomfilters` | off | `peerBloomFilters` |
| `-peerblockfilters` | off | `peerBlockFilters` |
| `-txreconciliation` | off | `txReconciliation` |
| `-maxuploadtarget` | 0, none | `maxUploadTarget` |
| `-listen` | on | `listen` |
| `-prune` | off | `prune` |
| `-v2transport` | on | `v2Transport` |
| `-whitelistrelay` | on, off with `-blocksonly` | `whitelistRelay` |
| `-whitelistforcerelay` | off | `whitelistForceRelay` |
| `-peertimeout` | 60 s | `peerTimeout` |
| `-minimumchainwork` | per chain | `minimumChainWork` |
| `-minrelaytxfee` | 100 sat/kvB | `minRelayTxFee` |

The services the node offers follow from them ([init 893]; Haskell
`localServices`): `NODE_NETWORK_LIMITED | NODE_WITNESS` always, `NODE_NETWORK` unless
pruned, `NODE_P2P_V2`, `NODE_COMPACT_FILTERS` and `NODE_BLOOM` with their options.

[init 893]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/init.cpp#L893

## Differences by permission and connection type

- Whitelisted peers (implicit permissions) are never punished, get headers below the
  minimum chain work, may send `mempool`, and in default mode may relay in
  blocks-only mode only if `-whitelistrelay` stays on, which `-blocksonly` turns off.
- Inbound peers are the only ones subject to the self-connection check and the
  tx-relay slots; their `getaddr` is answered once; they are preferred for download
  only with `noban`.
- Outbound full relay and block-relay-only peers are evicted when their chain falls
  behind (`considerEviction`), and dropped in initial block download when it has too
  little work.
- Block-relay-only and feeler connections relay no transactions and no addresses,
  and get no fee filter.
- Manual connections need no services and are never punished.
- Private broadcast connections accept only `pong` and `getdata` after `verack`
  ([np 4325]) and send only five message types.

[np 4325]: https://github.com/bitcoin/bitcoin/blob/f0de87f040621468b956f01f526a43a010310501/src/net_processing.cpp#L4325
