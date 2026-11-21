# The protocol of Bitcoin Cash Node 29.2.0

This report describes how Bitcoin Cash Node 29.2.0 (tag `v29.2.0`, commit
`07576013c91ff4a3a74acd85f189c69121cdad1b`) treats one peer on the Bitcoin
Cash networks: what it answers, what it drops, what costs ban score, when it
disconnects, and what it sends on its own. Every rule names the upstream line
that decides it and the Haskell function of
`Haskoin.Network.Protocol.BitcoinCashNode` that implements it. Upstream paths
are relative to the root of the Bitcoin Cash Node repository; Haskell modules
are named without the prefix `Haskoin.Network.Protocol.BitcoinCashNode.`.

Links to the upstream source are written `name:line`, with these names:

- `np`: `src/net_processing.cpp`
- `net`: `src/net.cpp`
- `nh`: `src/net.h`
- `pc`: `src/protocol.cpp`
- `init`: `src/init.cpp`
- `cv`: `src/clientversion.cpp`
- `ext`: `src/extversion.h`
- `val`: `src/validation.h`
- `nph`: `src/net_processing.h`
- `cp`: `src/chainparams.cpp`

<!-- The link references stay on one line each: Markdown cannot continue a URL
     on the next line. -->

## Keeping this report in sync

This report and the modules under `src/Haskoin/Network/Protocol/BitcoinCashNode`
describe the same rules and change together, in the same commit. A change of a
rule, a constant or a cited line in the code is not finished until this report
says the same, and the other way round.

To bring both to a new upstream release:

1. Change the commit in `upstream` (module `Haskoin.Network.Protocol.BitcoinCashNode`)
   and in the links of this report.
2. Diff `src/net_processing.cpp`, `src/net.cpp`, `src/net.h`, `src/protocol.cpp`,
   `src/version.h`, `src/validation.h`, `src/net_processing.h`,
   `src/extversion.h` and `src/chainparams.cpp` between the two commits.
3. For each changed rule, change the handler and its test, then this report.
4. Every `Cite` carries a line number: check each one against the new source.
   The cites are the second arguments of `netProcessing`, `netCpp`, `netH` and
   `protocolCpp`; a one-line script that prints the upstream line next to
   each cite finds those that moved.
5. Check the constants of module `Constants` against their definitions.
6. Run `haskell-dev test Protocol`.

## The machine

`step :: Options -> Env -> State -> Input -> (State, [Effect])` is a pure
function. The `Env` gives the chain, the mempool and the rest of the node at
the time of the step; the `State` is what the node keeps about the peer
(`CNode` in `src/net.h` and `CNodeState` in [np:269-385]); each `Effect` has
an action and a `Cite`. The modules follow the upstream code:

- `Handshake` (`ProcessMessages`, the start of `ProcessMessage`,
  `InactivityCheck`): framing, handshake, ping, ban score, timeouts.
- `Blocks` (the block handlers, `SendMessages` block part): headers, blocks,
  compact blocks, announcements.
- `Relay` (the relay handlers, `SendMessages` inventory part): transactions,
  proofs, filters, addresses.
- `Options` (`src/init.cpp`, `src/net.cpp` `AcceptConnection`): options,
  permissions, services.
- `State` (`CNode`, `CNodeState`): the state and the helpers of the handlers.
- `Constants` (headers): the constants with their lines.

An outbound connection sends our `version` with its first input, since the
machine has no effect at `start` (`Handshake.initializeNode`, [np:799-801]).

[np:269-385]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L269-385
[np:799-801]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L799-801

## Framing

The socket thread reads the 24-byte header and checks only the size; the
message thread checks the magic, the command and the checksum after the whole
message arrived.

- `Oversized`: closes the connection as soon as the header arrives; no score
  ([net:689], `Handshake.frameError`).
- `WrongMagic`: discourages the address and disconnects every connection from
  it, whatever the permissions ([np:3876-3888], `Handshake.frameError`).
- `BadCommand`: drops the message, keeps the connection ([np:3892-3896],
  `Handshake.frameError`).
- `BadChecksum`: discourages the address and disconnects, whatever the
  permissions ([np:3902-3914], `Handshake.frameError`).
- `BadPayload`: the handler of the command throws: `reject` with code
  `REJECT_MALFORMED` and reason "error parsing message", no score
  ([np:3927-3934], `badPayload`, `Handshake.parseError`).

The size limit is 2 MiB (`MAX_PROTOCOL_MESSAGE_LENGTH`) for every command but
`block`, `cmpctblock` and `blocktxn`, which may be twice the expected block
size ([pc:166-182]). The caller checks it and reports `Oversized`.

A bad payload goes through the same gates as a message (see "Order of
processing"): before `version` it costs 10, between `version` and `verack` it
is dropped. `verack`, `sendaddrv2`, `sendheaders`, `getaddr`, `mempool` and
`filterclear` do not read their payload upstream, so they are handled as if it
were empty; a short `pong` ends the ping ([np:3593-3598]); a bad
`dsproof-beta` costs 10 ([np:3726-3736]); a bad `reject` is only logged
([np:2044-2048]).

Upstream reads some payloads that the library's parser refuses: a `version`
without the optional fields, an `inv` or `getdata` of more than 50000
entries, an `addr` of more than 1000, `headers` of more than 2000, a locator
of more than 101. The machine has the upstream rules for the messages when
they are built directly, but a caller that parses bytes gets `BadPayload` for
them, which the machine treats as a payload that does not parse.

[net:689]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.cpp#L689
[np:3876-3888]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3876-3888
[np:3892-3896]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3892-3896
[np:3902-3914]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3902-3914
[pc:166-182]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/protocol.cpp#L166-182
[np:3593-3598]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3593-3598
[np:3726-3736]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3726-3736
[np:2044-2048]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2044-2048

## Order of processing

`ProcessMessages` takes one message at a time ([np:3858-3869]) and
`ProcessMessage` checks it in this order ([np:2000-3769]), which decides what
any message does in any state (`dispatch`, `handle`):

1. After the decision to disconnect, nothing is processed ([np:3836]).
2. `filterload` and `filteradd` when the node does not offer `NODE_BLOOM` to
   this peer: score 100 ("no-bloom-version") from a peer of version 70011 or
   later, else a plain disconnect, even before `version` ([np:2012-2023],
   `Handshake.bloomPrologue`).
3. `reject`: logged, never answered, in any state ([np:2025-2051],
   `Handshake.receiveReject`).
4. `version` ([np:2053-2306]).
5. Anything else before `version`: score 10, "missing-version" ([np:2308-2313],
   `Handshake.missingVersion`). Ten such messages reach the threshold.
6. `extversion`, `verack`, `sendaddrv2`.
7. Anything else before the peer's `verack`: dropped, no score
   ([np:2404-2408], `Handshake.priorToVerAck`). This includes `ping`, and the
   `wtxidrelay` and `sendtxrcncl` of Bitcoin Core.
8. The handler of the command. An unknown command is dropped ([np:3765-3768],
   `Handshake.unknownCommand`): `wtxidrelay`, `sendtxrcncl`, `merkleblock`,
   `alert` and the BIP 157 messages are unknown to Bitcoin Cash Node.
9. After the message: the `reject`s of invalid blocks are sent, and a crossed
   ban score is acted on ([np:3945-3946],
   `Handshake.sendRejectsAndCheckIfShouldDiscourage`).

Upstream does not read a peer's next message while its `getdata` queue is not
empty ([np:3824-3851]); the machine answers the whole queue in one step, in
the upstream order (see `getdata`).

[np:3858-3869]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3858-3869
[np:2000-3769]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2000-3769
[np:3836]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3836
[np:2012-2023]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2012-2023
[np:2025-2051]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2025-2051
[np:2053-2306]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2053-2306
[np:2308-2313]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2308-2313
[np:2404-2408]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2404-2408
[np:3765-3768]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3765-3768
[np:3945-3946]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3945-3946
[np:3824-3851]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3824-3851

## Connection types and permissions

### Permissions

Only inbound peers have permissions: `-whitelist` and `-whitebind` are read
only in `CConnman::AcceptConnection` ([net:1036-1052], [net:1130]). An entry
without flags becomes `noban` and `mempool`, with `relay` if
`-whitelistrelay` (default true, soft-set false by `-blocksonly`, soft-set
true again by `-whitelistforcerelay`, [init:1504-1520]) and `forcerelay` if
`-whitelistforcerelay` (default false). `forcerelay` implies `relay`. There is
no `download` permission (`Options.effectivePermissions`,
`Options.whitelistRelayEffective`).

- `noban`: never discouraged or disconnected for its score; exempt from
  `-rejectsubversion`; preferred for downloads when inbound; served
  `getheaders` in initial block download; transactions announced at every
  pass; not disconnected for the upload target, the pruned depth or a disk
  error; unrequested blocks forced out of IBD; invalid proofs not charged;
  headers sync timeout resets instead of disconnecting ([np:3789], [np:2141],
  [np:404], [np:2791], [np:4507], [np:1291], [np:1303], [np:3447], [np:3694],
  [np:4706]).
- `relay`: transactions taken in blocks-only mode; no cap of 100000
  announcements, no overload delay ([np:2554], [np:2860], [np:1961], [np:1976]).
- `forcerelay`: a rejected transaction that is not invalid is relayed again;
  no `feefilter` sent ([np:2959-2979], [np:4819]).
- `mempool`: `mempool` allowed without `NODE_BLOOM` and past the upload target
  ([np:3501-3502], [np:3513-3514]).
- `bloomfilter`: the node offers `NODE_BLOOM` to this peer even with
  `-peerbloomfilters=0` ([net:1123-1126]).
- `addr`: addresses not rate-limited; `getaddr` answered with a fresh sample
  ([np:2445], [np:3487]).

A local address (`127.0.0.0/8`, `::1`) has no permission but is disconnected
without being discouraged when its score crosses the threshold ([np:3795-3799]).

### Connection types

| Behaviour | Inbound | Outbound full relay | Manual | Feeler | Address fetch |
|---|---|---|---|---|---|
| Who sends `version` first | peer | node | node | node | node |
| Must offer the desirable services | no | yes | no | no | yes |
| Checked for connecting to itself | yes | no | no | no | no |
| Gets our address and `getaddr` after `version` | no | yes | yes | yes | yes |
| Disconnected after | | | | `version` | first `addr` |
| Punished for its score | unless `noban` | yes | no | yes | yes |
| Exempt from `-rejectsubversion` | if `noban` | no | yes | no | no |
| Preferred for downloads | if `noban` | yes | yes | yes | no |
| Chain-sync check and insufficient-work disconnect | no | yes | no | no | no |
| Answered on `getaddr` | yes | no | no | no | no |

Block-relay-only connections exist in the code but are never opened
(`nMaxOutboundBlockRelay = 0`, [nh:213]); the code treats them as outbound.
Upstream refs: [nh:1057-1090], [np:2086-2106], [np:2133-2153], [np:2161-2167],
[np:2233-2272], [np:2302-2304], [np:2507-2509], [np:3787-3806].

### Services

The node offers `NODE_NETWORK | NODE_NETWORK_LIMITED | NODE_BITCOIN_CASH`
([init:1568], [init:2012]), without `NODE_NETWORK` when pruned, with
`NODE_BLOOM` if `-peerbloomfilters` (default true) or the `bloomfilter`
permission, and `NODE_EXTVERSION` if `-useextversion` (default false)
(`Options.localServices`). An outbound peer must offer `NODE_NETWORK`, or
`NODE_NETWORK_LIMITED` once the node is out of initial block download
(`GetDesirableServiceFlags`, [pc:184-190], `Handshake.hasAllDesirableServices`).

[net:1036-1052]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.cpp#L1036-1052
[net:1130]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.cpp#L1130
[init:1504-1520]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/init.cpp#L1504-1520
[np:3789]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3789
[np:2141]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2141
[np:404]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L404
[np:2791]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2791
[np:4507]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4507
[np:1291]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1291
[np:1303]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1303
[np:3447]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3447
[np:3694]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3694
[np:4706]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4706
[np:2554]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2554
[np:2860]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2860
[np:1961]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1961
[np:2959-2979]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2959-2979
[np:4819]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4819
[np:3501-3502]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3501-3502
[np:3513-3514]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3513-3514
[net:1123-1126]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.cpp#L1123-1126
[np:2445]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2445
[np:3487]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3487
[np:3795-3799]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3795-3799
[nh:213]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.h#L213
[nh:1057-1090]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.h#L1057-1090
[np:2086-2106]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2086-2106
[np:2133-2153]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2133-2153
[np:2161-2167]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2161-2167
[np:2233-2272]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2233-2272
[np:2302-2304]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2302-2304
[np:2507-2509]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2507-2509
[np:3787-3806]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3787-3806
[init:1568]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/init.cpp#L1568
[init:2012]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/init.cpp#L2012
[pc:184-190]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/protocol.cpp#L184-190

## Handshake

### Our `version`

`PushNodeVersion` ([np:761-785], `Handshake.pushNodeVersion`): protocol
70016, the services offered to this peer, the time, the peer's address (the
null address in the machine, which does not know it), our null address with
our services, our nonce, the user agent `/Bitcoin Cash Node:29.2.0/` with the
`-uacomment`s in parentheses ([cv:103-118], `Options.subVersion`), our
height, and relay false in blocks-only mode. Outbound connections send it at
once ([np:799-801]); inbound ones after the peer's `version` ([np:2175]).

### `version`

`Handshake.receiveVersion`, in upstream order ([np:2053-2306]):

1. A second `version`: `reject` with `REJECT_DUPLICATE` and score 1
   ([np:2054-2066], `Handshake.duplicateVersion`).
2. A negative time counts as 0 ([np:2081-2083]).
3. An outbound full-relay or address-fetch peer without the desirable
   services: `reject` "Expected to offer services %08x" with
   `REJECT_NONSTANDARD`, then disconnect ([np:2089-2106]).
4. Version below 31800: `reject` "Version must be 31800 or greater" with
   `REJECT_OBSOLETE`, then disconnect ([np:2108-2123]). An inbound peer gets
   only the `reject`, since our `version` is not sent yet.
5. A user agent that contains a `-rejectsubversion` string before its first
   `(`: disconnect without `reject`, unless the peer is manual or `noban`
   ([np:2133-2153]).
6. An inbound peer with the nonce of one of our own connections: disconnect
   ([np:2161-2167], `Env.ownNonce`).
7. Inbound: our `version` ([np:2175]).
8. If both sides offer `NODE_EXTVERSION`, `extversion` and wait for the
   peer's; otherwise `sendaddrv2` to peers of version 70016 or later and
   `verack` ([np:2182-2198], `PushVerACK` [np:1890-1902]).
9. Note the peer's services, user agent, height, relay flag; a peer that
   serves neither the whole chain nor its recent part is a client
   ([np:2200-2225]).
10. Preferred for downloads: outbound or `noban`, not address fetch, not a
    client ([np:399-408]).
11. Outbound (not block-relay-only): our address if the node listens and is
    out of initial block download, then `getaddr` once our `verack` is out
    ([np:2233-2272], `PushGetAddrOnceIfAfterVerAck` [np:1870-1883]).
12. A time before the genesis block of the network: score 20, "Ignoring
    invalid timestamp in version message" ([np:2289-2294]).
13. A feeler is disconnected ([np:2301-2304]).

On the wire: outbound `version` … `sendaddrv2`, `verack`, `getaddr` … then on
the peer's `verack`, `sendheaders` and `sendcmpct(false, 1)`; inbound
`version`, `sendaddrv2`, `verack` … `sendheaders`, `sendcmpct`.

### `extversion`

Used only when both sides offer `NODE_EXTVERSION` (`-useextversion`, default
false). `Handshake.receiveExtVersion` ([np:2315-2341]):

1. The expectation flag is cleared first, before any check ([np:2317]).
2. After the peer's `verack`: disconnect, no score ([np:2318-2321]).
3. A payload of more than 100000 bytes, more than 8192 keys, or a key 0 whose
   value is not a compact size throws: malformed `reject`, no score
   ([np:2324], [ext:155-182]). The node then never sends its `verack` on
   that connection, since the flag is already clear.
4. Otherwise: `sendaddrv2` (70016 or later), `verack`, and `getaddr` for an
   outbound peer ([np:2334-2338]). This is not gated on the node having
   offered `extversion`: a peer that sends it unasked gets a second
   `sendaddrv2` and `verack`.

Our `extversion` is the map {0: 100}, version 0.1.0 ([ext:50-52], [ext:75]).

### `verack`

`Handshake.receiveVerAck` ([np:2346-2391]): if the node sent `extversion`
and the peer answered with `verack`, the node sends `sendaddrv2`, `verack`
and `getaddr` then ([np:2362-2369]); `sendheaders` to peers of 70012 or
later ([np:2371-2377]); `sendcmpct(false, 1)` to peers of 70014 or later
([np:2378-2388]); the handshake is complete ([np:2389]). A second `verack` is
not checked: it sends `sendheaders` and `sendcmpct` again.

### `sendaddrv2`

`Handshake.receiveSendAddrV2` ([np:2393-2402]): allowed between `version` and
`verack`; after `verack`, a disconnect without score. The payload is not read.

### `ping` and `pong`

`Handshake.receivePing` ([np:3530-3551]): a `pong` with the nonce for peers
above version 60000; nothing for older ones; a short payload draws a malformed
`reject`. No rate limit.

`Handshake.receivePong` ([np:3553-3610]): ends the ping on the matching
nonce (and notes the round trip if positive), on nonce 0 and on a short
payload; a different nonce leaves it outstanding; a `pong` without a ping is
logged. Never a score.

The node pings at the first pass of `SendMessages` after the handshake, then
two minutes after the last ping once it is answered, and when an operator
asks (`PingNow`); peers of version 60000 or less get a `ping` without nonce
and are not expected to answer ([np:4161-4190], `Handshake.sendPing`).

[np:761-785]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L761-785
[cv:103-118]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/clientversion.cpp#L103-118
[np:2175]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2175
[np:2054-2066]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2054-2066
[np:2081-2083]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2081-2083
[np:2089-2106]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2089-2106
[np:2108-2123]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2108-2123
[np:2182-2198]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2182-2198
[np:1890-1902]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1890-1902
[np:2200-2225]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2200-2225
[np:399-408]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L399-408
[np:1870-1883]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1870-1883
[np:2289-2294]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2289-2294
[np:2301-2304]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2301-2304
[np:2315-2341]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2315-2341
[np:2317]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2317
[np:2318-2321]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2318-2321
[np:2324]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2324
[ext:155-182]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/extversion.h#L155-182
[np:2334-2338]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2334-2338
[ext:50-52]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/extversion.h#L50-52
[ext:75]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/extversion.h#L75
[np:2346-2391]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2346-2391
[np:2362-2369]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2362-2369
[np:2371-2377]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2371-2377
[np:2378-2388]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2378-2388
[np:2389]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2389
[np:2393-2402]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2393-2402
[np:3530-3551]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3530-3551
[np:3553-3610]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3553-3610
[np:4161-4190]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4161-4190

## Timers and inactivity

`CConnman::InactivityCheck` runs at every loop of the socket thread for every
peer ([net:1272-1303], `Handshake.inactivityCheck`). Nothing is checked until
the connection is older than `-peertimeout` (60 s); then the first rule that
holds disconnects:

1. Nothing received or nothing sent yet ([net:1275-1280]).
2. Nothing sent for 20 minutes ([net:1281-1284]).
3. Nothing received for 20 minutes, or 90 minutes for peers of version 60000
   or less ([net:1285-1290]).
4. A ping unanswered for 20 minutes ([net:1291-1296]).
5. The handshake not finished ([net:1297-1301]): the peer's `verack` must
   arrive within `-peertimeout`.

These values are the same on every network. The timers of `SendMessages`
(`tick`, `sendMessages`, [np:4143-4848]), in their order:

- ping: see above ([np:4161-4190], `Handshake.sendPing`).
- our address: out of IBD, from the first pass, then every 24 h on average
  ([np:4203-4207], `Relay.advertiseLocal`).
- addresses: every 30 s on average, `addrv2` if the peer sent `sendaddrv2`
  ([np:4212-4247], `Relay.sendAddresses`).
- first `getheaders`: one peer in IBD, every peer that serves blocks once the
  best header is a day old ([np:4249-4293], `Blocks.initialGetHeaders`).
- block announcements: see "Announcements" ([np:4307-4458],
  `Blocks.blockAnnouncements`).
- transactions: 500 ms on average inbound, 250 ms outbound, every pass for
  `noban` ([np:4507-4516], `Relay.sendInventory`).
- stalling: 2 s after another peer found this one holding the window ([np:4656-4667], `Blocks.downloadTimers`).
- block download: 600 s × (1 + 0.5 × other peers with validated downloads)
  ([np:4668-4691], `Blocks.downloadTimers`).
- headers sync: 15 min + 1 ms per expected header, while the best header is
  old, if this is the only sync peer and another preferred peer exists; resets
  for `noban` ([np:4693-4730], `Blocks.downloadTimers`).
- chain sync: outbound full relay: 20 min to reach our tip's work, then
  `getheaders` and 2 min ([np:3951-4035], `Blocks.considerEviction`).
- `getdata`: blocks, then proofs, then transactions, 1000 per message ([np:4738-4812], `sendMessages`).
- `feefilter`: to 70013 or later without `forcerelay`, every 10 min on
  average, sooner after a change of a third ([np:4815-4846],
  `Relay.sendFeeFilter`).

Nothing of `SendMessages` runs before the peer's `verack` ([np:4148-4151]).

[net:1272-1303]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.cpp#L1272-1303
[net:1275-1280]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.cpp#L1275-1280
[net:1281-1284]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.cpp#L1281-1284
[net:1285-1290]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.cpp#L1285-1290
[net:1291-1296]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.cpp#L1291-1296
[net:1297-1301]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.cpp#L1297-1301
[np:4143-4848]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4143-4848
[np:4203-4207]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4203-4207
[np:4212-4247]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4212-4247
[np:4249-4293]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4249-4293
[np:4307-4458]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4307-4458
[np:4507-4516]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4507-4516
[np:4668-4691]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4668-4691
[np:4693-4730]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4693-4730
[np:3951-4035]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3951-4035
[np:4815-4846]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4815-4846
[np:4148-4151]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4148-4151

## Misbehaviour

`Misbehaving` ([np:894-919], `State.misbehaving`) adds to the score; a score
of 0 does nothing. When the score crosses `-banscore` (old below, new at or
above; default 100), the node acts after the message or at the next pass of
`SendMessages` ([np:3771-3810], `Handshake.sendRejectsAndCheckIfShouldDiscourage`):

- `noban` peer: a warning only;
- manual peer: a warning only;
- local address: disconnect, no discouragement;
- otherwise: discourage the address and disconnect every connection from it.

The score never decays, so the threshold is crossed at most once per
connection. Discouragement is not a ban: inbound connections from the address
are still accepted unless the slots are nearly full, and the node does not
connect to it. Scores are counted for exempt peers too.

| Score | Reason | Trigger | Upstream |
|---|---|---|---|
| 1 | multiple-version | second `version` | [np:2064] |
| 10 | missing-version | message before `version` | [np:2311] |
| 20 | Ignoring invalid timestamp in version message | `version` older than genesis | [np:2293] |
| 100 | no-bloom-version | `filterload`/`filteradd` without `NODE_BLOOM`, version ≥ 70011 | [np:2017] |
| 20 | oversized-addr | more than 1000 addresses | [np:2425] |
| 20 | oversized-inv | `inv` of more than 50000 | [np:2546] |
| 20 | too-many-inv | `getdata` of more than 50000 | [np:2629] |
| 20 | too-many-headers | more than 2000 headers | [np:3409] |
| 20 | too-many-unconnected-headers | every 10th short `headers` that does not connect | [np:1655] |
| 20 | disconnected-header | headers that do not follow one another | [np:1665] |
| n | validation's reason | invalid header in `headers` or `cmpctblock` | [np:1686], [np:3067] |
| n | validation's reason | invalid block from a `block` message, reject code 1 to 0xff | [np:1114] |
| n | validation's reason | invalid transaction | [np:3016] |
| 100 | invalid-cmpctblk | malformed compact block | [np:3170] |
| 100 | invalid-cmpctblk-txns | `blocktxn` of the wrong count | [np:3332] |
| 100 | out-of-bound-tx-index | `getblocktxn` index out of range | [np:1592] |
| 100 | oversized-bloom-filter | filter over 36000 bytes or 50 functions | [np:3619] |
| 100 | invalid-filteradd | item over 520 bytes | [np:3652] |
| 10 | bad-dsproof | invalid or unparsable proof, not from `noban` | [np:4870] |

Scores charged from outside the peer's messages (an orphan transaction found
invalid, an orphan proof found invalid or expired with score 1,
`src/dsproof/storage_cleanup.cpp`) come as the `Penalty` notification.

Disconnections without score: oversized message, wrong magic and bad checksum
(with discouragement), locator over 101, `getblocktxn` without indexes,
`sendaddrv2` or `extversion` after `verack`, the refusals of `version`,
`filterload`/`filteradd` without `NODE_BLOOM` from a peer older than 70011,
`mempool` refusals, a known invalid header from an outbound peer that is not
manual, the upload target and pruned depth on `getdata`, and the timers.

[np:894-919]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L894-919
[np:3771-3810]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3771-3810
[np:2064]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2064
[np:2311]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2311
[np:2293]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2293
[np:2017]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2017
[np:2425]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2425
[np:2546]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2546
[np:2629]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2629
[np:3409]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3409
[np:1655]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1655
[np:1665]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1665
[np:1686]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1686
[np:3067]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3067
[np:1114]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1114
[np:3016]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3016
[np:3170]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3170
[np:3332]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3332
[np:1592]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1592
[np:3619]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3619
[np:3652]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3652
[np:4870]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4870

## Blocks

### `sendheaders` and `sendcmpct`

`sendheaders` asks for announcements by `headers`, for good ([np:2513-2517],
`Blocks.receiveSendHeaders`). `sendcmpct` of version 1 notes that the peer
takes compact blocks and whether it wants high bandwidth; a later one
overrides the flag; other versions are ignored ([np:2520-2535],
`Blocks.receiveSendCmpct`).

### `inv` of blocks

Each `MSG_BLOCK` entry updates the best block the peer has; the last unknown
block that is not in flight anywhere gets one `getheaders` up to it after the
loop ([np:2573-2579], [np:2616-2619], `Blocks.receiveBlockInv`,
`Blocks.afterInv`). No `getdata` follows a block `inv` directly. Other entry
types that are not transactions or proofs count as known and are ignored
([np:1184-1185]).

### `getheaders`

`Blocks.receiveGetHeaders` ([np:2777-2853]): a locator of more than 101 is a
disconnect; in initial block download only `noban` peers are answered; an
empty locator names one block by its stop hash, which must be known and
servable (on the active chain, or validated and less than 30 days older than
the best header, `BlockRequestAllowed` [np:936-950]); otherwise the answer
starts after the first locator hash on the active chain, at block 1 if none
is. Up to 2000 headers, including the stop hash; the answer is sent even when
empty.

### `headers`

`Blocks.receiveHeaders` and `processHeaders` (`ProcessHeadersMessage`,
[np:1606-1865]):

1. More than 2000: score 20 ([np:3406-3411]).
2. None: nothing ([np:1613-1616]).
3. Fewer than 8 whose first does not connect: `getheaders` from the best
   header, the peer's best block noted, and every 10th such message costs 20
   ([np:1632-1658]).
4. Headers that do not follow one another: score 20 ([np:1661-1669]).
5. Validation fails: its score; a known invalid header from an outbound peer
   that is not manual is also a disconnect ([np:1680-1724]).
6. Accepted: the streak of unconnected headers resets, the peer's best block
   moves, a new header with more work than our tip notes the time of the
   announcement ([np:1727-1747]).
7. Exactly 2000: `getheaders` from the last ([np:1749-1763]).
8. Direct fetch: if the tip is younger than 200 minutes and the headers have
   at least the work of the tip, the missing blocks back to the active chain
   are requested, at most 16 in flight, as `MSG_CMPCT_BLOCK` when there is
   one and the peer takes compact blocks; a reorganisation deeper than 17
   blocks is not fetched ([np:1765-1825]).
9. In initial block download, an outbound full-relay peer whose complete
   headers chain has less work than the minimum chain work of the network is
   disconnected ([np:1828-1849]).
10. An outbound full-relay peer whose best block has our tip's work is
    protected from the chain-sync check, up to four peers ([np:1851-1861]).

Bitcoin Cash Node has no anti-DoS headers pre-sync: low-work headers are
stored once they validate.

### `getblocks`

`Blocks.receiveGetBlocks` ([np:2649-2727]): a locator of more than 101 is a
disconnect; up to 500 hashes after the fork, without the stop hash, announced
by `inv` at the next pass; a pruned node stops at blocks it may not have; the
500th is remembered so that serving it sends an `inv` of the tip. Nothing is
sent when nothing follows the fork.

### `getdata` of blocks

`Blocks.getBlockData` (`ProcessGetBlockData`, [np:1235-1476]): nothing for an
unknown or unservable block; disconnect (unless `noban`) when the historical
upload target is reached and the block is a week older than the best header
or a filtered block is asked; disconnect (unless `noban`) when a pruned node
is asked for a block deeper than 290; nothing for a block not on disk;
otherwise `block`, or `merkleblock` and the matched transactions against the
peer's filter (an empty filter matches everything, and there is always one),
or `cmpctblock` for a block within 5 of the tip while the tip is recent and
`block` otherwise. A `notfound` is never sent for blocks.

### `block`

`Blocks.receiveBlock` and `processNewBlock` ([np:3427-3461],
`ProcessBlockFromNode` [np:1983-1998], `BlockChecked` [np:1094-1130]): a block
is processed with force when it was requested from this peer, or comes from a
`noban` peer out of initial block download. An invalid block with a reject
code from 1 to 0xff queues a `reject` and costs its score; "prev-blk-not-found",
"duplicate" and "bad-header-finalization" (code 0x103) give neither. A valid
block that was the only one in flight makes the node ask its source for
high-bandwidth compact blocks (`MaybeSetPeerAsAnnouncingHeaderAndIDs`
[np:560-610]).

### `cmpctblock`, `getblocktxn`, `blocktxn`

`Blocks.receiveCmpctBlock` ([np:3022-3298]): a compact block that does not
connect draws `getheaders` out of IBD and no score; an invalid header costs
its score; a block already stored or of less work than the tip is dropped (or
requested whole if it was in flight from this peer); within two blocks of the
tip, when it is in flight from fewer than 3 peers and this one has fewer
than 16, the node rebuilds it from the mempool (`Env.checkCompactBlock`):
malformed costs 100, a collision falls back to `getdata`, missing
transactions draw `getblocktxn`; further ahead, the header is processed as a
`headers` message without the duplicate-invalid disconnect. Positions are
32-bit in Bitcoin Cash Node.

`Blocks.receiveGetBlockTxn` ([np:2730-2775]): no index is a disconnect; the
most recent block is answered with `blocktxn` (an index out of range costs
100); another block the node has is sent whole; nothing otherwise.

`Blocks.receiveBlockTxn` ([np:3300-3391]): only for a compact block in flight
from this peer; the wrong count costs 100; a merkle mismatch falls back to
`getdata`; an invalid block rebuilt this way is never punished.

### `notfound`

Block entries are ignored; the request stays in flight until the timers
([np:3750-3763]).

### Announcements

`Blocks.updatedBlockTip` (`UpdatedBlockTip`, [np:1051-1088]): out of initial
block download, up to 8 new blocks are queued for each peer whose start
height is less than 2000 above the new tip. At the next pass
(`Blocks.blockAnnouncements`, [np:4307-4458]): `cmpctblock` for one block to a
high-bandwidth peer, `headers` (up to 8) to a peer that sent `sendheaders`,
when the first new block the peer lacks has a parent it has; otherwise an
`inv` of the last block, sent with the other `inv`s of the pass without
trickle ([np:4486-4494]). `Blocks.newPoWValidBlock` (`NewPoWValidBlock`,
[np:1002-1045]) sends `cmpctblock` before full validation to high-bandwidth
peers of version 70015 or later that have the parent.

[np:2513-2517]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2513-2517
[np:2520-2535]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2520-2535
[np:2573-2579]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2573-2579
[np:2616-2619]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2616-2619
[np:1184-1185]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1184-1185
[np:2777-2853]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2777-2853
[np:936-950]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L936-950
[np:1606-1865]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1606-1865
[np:3406-3411]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3406-3411
[np:1613-1616]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1613-1616
[np:1632-1658]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1632-1658
[np:1661-1669]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1661-1669
[np:1680-1724]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1680-1724
[np:1727-1747]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1727-1747
[np:1749-1763]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1749-1763
[np:1765-1825]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1765-1825
[np:1828-1849]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1828-1849
[np:1851-1861]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1851-1861
[np:2649-2727]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2649-2727
[np:1235-1476]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1235-1476
[np:3427-3461]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3427-3461
[np:1983-1998]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1983-1998
[np:1094-1130]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1094-1130
[np:560-610]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L560-610
[np:3022-3298]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3022-3298
[np:2730-2775]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2730-2775
[np:3300-3391]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3300-3391
[np:3750-3763]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3750-3763
[np:1051-1088]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1051-1088
[np:4486-4494]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4486-4494
[np:1002-1045]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1002-1045

## Relay

### `inv` of transactions and proofs

`Relay.receiveInv` and `otherEntry` ([np:2537-2622]): more than 50000 costs
20. Each entry is noted as known to the peer. In blocks-only mode, from a
peer without `relay`, a transaction or proof `inv` is logged and ignored. A
new transaction is announced to the request tracker (`AddTxAnnouncement`
[np:1958-1980]: +2 s for a non-preferred peer, +2 s with 100 requests in
flight, at most 100000 announcements, without `relay`); a new proof is queued
for `getdata`, at most 5000. Nothing happens in initial block download.
Witness inventory types count as known.

### `getdata` of transactions and proofs

`Relay.receiveGetData` ([np:2624-2645], `ProcessGetData` [np:1478-1585]):
more than 50000 costs 20. A run of transactions and proofs is answered first:
a transaction announced to any peer in the last 15 minutes (`mapRelay`), or
from the mempool if it was there at the last answer to this peer's `mempool`;
a stored proof, orphans included. Then one block entry is served, or an entry
of another type is dropped; then one `notfound` for the run. The machine
repeats this until the queue is empty.

### `tx`

`Relay.receiveTx` ([np:2856-3020]): in blocks-only mode, from a peer without
`relay`, dropped before parsing. Otherwise known to the peer, its request
ends, and if the node does not have it, the mempool decides: accepted →
relayed to the other peers; missing inputs → the parents are requested and
the transaction kept as an orphan, unless a parent was recently rejected;
refused → a `reject` with its code (if from 1 to 0xff) and its score; a
`forcerelay` peer gets it relayed again when it is not invalid. Unsolicited
transactions are treated the same.

### `dsproof-beta`

`Relay.receiveDsProof` ([np:3680-3748]): ignored with `-doublespendproof=0`;
processed even unsolicited and in blocks-only mode; a proof for an outpoint
that has one is ignored; valid → stored and announced to peers that relay
transactions and whose filter matches; missing coin or spender → orphan;
invalid or unparsable → marked rejected and score 10 unless `noban`
([np:4865-4872]).

### `mempool`, `feefilter`

`Relay.receiveMempool` ([np:3500-3528]): refused (disconnect, or nothing for
`noban`) without `NODE_BLOOM` and the `mempool` permission, or past the
upload target without `mempool`; otherwise answered at the next trickle with
every mempool transaction that pays the peer's fee filter and matches its
filter, not capped.

`Relay.receiveFeeFilter` ([np:3666-3678]): kept if a valid amount, ignored
otherwise.

### BIP 37 filters

`Relay.receiveFilterLoad` ([np:3612-3626]): over 36000 bytes or 50 functions
costs 100; otherwise the filter is replaced and transaction relay turns on.
`Relay.receiveFilterAdd` ([np:3628-3655]): over 520 bytes costs 100; there is
always a filter, so `filteradd` without `filterload` adds to the empty one.
`Relay.receiveFilterClear` ([np:3657-3664]): no `NODE_BLOOM` check; resets the
filter only when the node offers Bloom filters, and turns on transaction
relay in any case.

### `addr`, `addrv2`, `getaddr`

`Relay.receiveAddr` ([np:2410-2511]): more than 1000 costs 20. A token bucket
of 0.1 per second, capped at 1000 and opened by 1000 when the node sends
`getaddr`, limits how many are taken unless the peer has `addr`. Addresses
without useful services are skipped; a time far in the future or before 1973
becomes five days ago; up to 10 fresh routable addresses are relayed to two
peers; an address-fetch connection ends after the first message.

`Relay.receiveGetAddr` ([np:3463-3498]): only from an inbound peer, once per
connection; a fresh sample for `addr`, the cached answer otherwise; sent with
the next `addr`.

### Announcing transactions

`Relay.sendInventory` ([np:4461-4654]): block hashes and proof ids go out at
every pass; transactions when the trickle fires: the answer to `mempool`
first, then up to `ceil(txbroadcastrate × block size in MB × interval in
s)` transactions (112 with 32 MB blocks, 7 with 2 MB), each only if the peer
wants transactions, does not know it, it is still in the mempool, pays the
peer's fee filter and matches its filter.

[np:2537-2622]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2537-2622
[np:1958-1980]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1958-1980
[np:2624-2645]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2624-2645
[np:1478-1585]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1478-1585
[np:2856-3020]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2856-3020
[np:3680-3748]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3680-3748
[np:4865-4872]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4865-4872
[np:3500-3528]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3500-3528
[np:3666-3678]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3666-3678
[np:3612-3626]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3612-3626
[np:3628-3655]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3628-3655
[np:3657-3664]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3657-3664
[np:2410-2511]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L2410-2511
[np:3463-3498]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3463-3498
[np:4461-4654]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4461-4654

## Options

| Option | Default | Field of `Options` | Upstream |
|---|---|---|---|
| `-enablebip61` | true | `enableBip61` | [nph:58] |
| `-banscore` | 100 | `banScore` | [val:150] |
| `-peertimeout` | 60 s | `peerTimeout` | [nh:104] |
| `-blocksonly` | false | `blocksOnly` | [nh:102] |
| `-peerbloomfilters` | true | `peerBloomFilters` | [val:166] |
| `-useextversion` | false | `useExtVersion` | `src/extversion.h` |
| `-whitelistrelay` | true, soft-set | `whitelistRelay` | [nh:51], [init:1504-1520] |
| `-whitelistforcerelay` | false | `whitelistForceRelay` | [nh:53] |
| `-rejectsubversion` | none | `rejectSubVersions` | [np:2133-2153] |
| `-uacomment` | none | `uaComments` | [cv:103-118] |
| `-listen` | true | `listen` | [nh:94] |
| `-feefilter` | true | `feeFilter` | [val:155] |
| `-minrelaytxfee` | 1000 sat/kB | `minRelayTxFee` | [val:68] |
| `-txbroadcastinterval` | 500 ms | `txBroadcastInterval` | [nph:32] |
| `-txbroadcastrate` | 7 | `txBroadcastRate` | [nph:38] |
| `-doublespendproof` | true | `doubleSpendProof` | `src/dsproof/dsproof.cpp` |
| `-prune` | off | `prune` | [init:2806-2807] |
| chain block size | per network | `defaultBlockSize` | [cp:158], [cp:417], [cp:642], [cp:1181] |

`-maxuploadtarget` reaches the machine as `Env.uploadTargetReached` and
`Env.historicalUploadTargetReached`; validation options
(`-finalizeheaders`, `-maxreorgdepth`, `-checkpoints`) through the verdicts of
the `Env`.

[nph:58]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.h#L58
[val:150]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/validation.h#L150
[nh:104]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.h#L104
[nh:102]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.h#L102
[val:166]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/validation.h#L166
[nh:51]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.h#L51
[nh:53]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.h#L53
[nh:94]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net.h#L94
[val:155]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/validation.h#L155
[val:68]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/validation.h#L68
[nph:32]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.h#L32
[nph:38]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.h#L38
[init:2806-2807]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/init.cpp#L2806-2807
[cp:158]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/chainparams.cpp#L158
[cp:417]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/chainparams.cpp#L417
[cp:642]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/chainparams.cpp#L642
[cp:1181]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/chainparams.cpp#L1181

## Differences by network

The rules are the same on the four networks of this library; `defaultOptions`
of each network makes one machine per network.

| | main (`bch`) | testnet3 (`bchTest3`) | testnet4 (`bchTest4`) | regtest (`bchRegTest`) |
|---|---|---|---|---|
| Magic | e3e1f3e8 | f4e5f3f4 | e2b7daaf | dab5bffa |
| Genesis time (floor of a `version` time) | 1231006505 | 1296688602 | 1597811185 | 1296688602 |
| Default block size | 32 MB, ABLA | 32 MB, fixed | 2 MB, fixed | 32 MB, ABLA |
| Transactions per announcement | 112 | 112 | 7 | 112 |
| Limit of block messages | ≥ 64 MB | 64 MB | 4 MB | ≥ 64 MB |
| Minimum chain work | network's | network's | network's | 0 |

Upstream: [cp:190-199], [cp:444-454], [cp:669-678], [cp:1201-1210] (magic and
genesis), [cp:158], [cp:417], [cp:642], [cp:1181] (block size). On regtest a
headers chain never has too little work, and `-peerratelimit` would apply to
`noban`, manual and local peers too ([np:804-806]; no rule by default, not
modelled). The target spacing is 600 s on all four, so every timer of block
download is the same. The magic and the size limit of block messages are
checked by the caller, which reports `WrongMagic` and `Oversized`; the next
block size, which ABLA can raise on main and regtest, comes from
`Env.nextBlockSizeLimit`.

[cp:190-199]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/chainparams.cpp#L190-199
[cp:444-454]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/chainparams.cpp#L444-454
[cp:669-678]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/chainparams.cpp#L669-678
[cp:1201-1210]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/chainparams.cpp#L1201-1210
[np:804-806]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L804-806

## What the machine simplifies

- Decisions across peers come as notifications: which block to download from
  whom (`RequestBlock`; the direct fetch after `headers` is modelled), the
  stalling of the download window (`Stalling`), eviction (`Evict`), the
  high-bandwidth choice (`HighBandwidth`), the peers an address is relayed
  to, scores charged from outside (`Penalty`).
- The transaction request tracker is global; the machine requests this
  peer's announcements as if it were the only one, and `RequestTx` forces a
  request.
- The rolling Bloom filters of known inventory and addresses are exact sets.
- Transactions to announce keep their order of arrival, not the order of the
  mempool.
- Ancestry is found by walking `headerOf` back at most 2016 steps; the
  locator of a block off the active chain joins it by height; the
  proof-equivalent time of `BlockRequestAllowed` is left out.
- A header accepted by validation but unknown to `lookupBlock` is assumed to
  have one unit of work per block above the tip.
- The count of protected outbound peers (at most 4) is global; the machine
  assumes there is room.
- The shared trickle timer of inbound peers is a timer of each peer with the
  same mean, and the shuffle of large `addr` messages is left out.
- Addresses are routable when their bytes are not all zero; Tor v2 addresses
  are not sent in `addr`, although Bitcoin Cash Node still counts them as
  `addr`-compatible.
- `-peerratelimit` and `-dropmessagestest` have no default and are not
  modelled.

[np:3927-3934]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L3927-L3934
[np:1976]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L1976
[np:4656-4667]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4656-L4667
[np:4738-4812]: https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/07576013c91ff4a3a74acd85f189c69121cdad1b/src/net_processing.cpp#L4738-L4812
