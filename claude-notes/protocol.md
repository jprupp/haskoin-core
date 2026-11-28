# Protocol machines

The state machines of `src/Haskoin/Network/Protocol` (Bitcoin Core and Bitcoin
Cash Node), their specs, the report in `doc/protocol/` and
`scripts/protocol-cites.sh`.

## Layout

- `Types.hs` is shared: `Setup`, `Input`, `Effect`, `Env`, the verdicts.
  Each node has its own `Options`, `State` and submodules; `Protocol.hs` only
  dispatches. A field of `Env` used by both nodes has one name: look for an
  existing field before adding one (both had added `bestHeader`,
  `inFlightElsewhere` and the address and compact block answers).
- `uploadTargetReached` is `OutboundTargetReached(false)` and
  `historicalUploadTargetReached` is `OutboundTargetReached(true)`.
- The citation helpers (`netProcessing`, `netCpp`, ...) are in each node's
  `Constants.hs`, or in `BitcoinCashNode.hs` for its `upstream`.

## Upstream source

- Clone at the tags to read and to check citations:
  `git clone --depth 1 --branch v32.1 https://github.com/bitcoin/bitcoin.git`
  and `--branch v29.2.0 https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node.git`.
- `scripts/protocol-cites.sh core|bchn CHECKOUT` prints every citation next to
  its upstream line; an empty upstream line means the number is past the end.

## Tests and examples

- `haskell-dev test Protocol` runs both specs. hspec hides what a test
  prints: to check a README example, put it in a temporary spec with
  `shouldBe`, then delete the spec and run `stack build --dry-run`.
- The library's parser refuses some payloads that a node handles itself (a
  `sendcmpct` announce byte above 1 on Bitcoin, a short `version`): the specs
  send them as `MOther` or `BadFrame (BadPayload ...)`.
