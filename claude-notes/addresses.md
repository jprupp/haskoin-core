# Addresses

`Haskoin.Address` and the address functions of `Crypto/Keys/Extended.hs`:
what exists on which network, the legacy and nested forms, the limit of a
P2SH redeem script, and their tests.

## What exists on which network

- Three tests of a network, not to mix: `net.segWit` (the consensus has a
  witness: nested SegWit addresses), `isJust net.bech32Prefix` (a SegWit
  address has a text), `hasScript32` (P2SH32, where the network has
  CashAddr).
- A function that makes a nested SegWit address takes the network and
  refuses without `segWit`: the address is a plain `ScriptAddress`, so
  `addrToText` cannot refuse it later. A new function of that kind goes
  through `p2shP2wpkhAddr` or `payToNestedScriptAddress`.
- The native SegWit functions take no network: their address has no text
  without a Bech32 prefix. `addressToOutput` still gives its script.

## Reading bytes

- `decodeHash` does not fail on bytes left over: 32 bytes read as a
  `Hash160` give the first 20. Check the length before it, as
  `legacyAddress`, `cashAddress` and `witnessAddress` do.
- `maxBase58AddressLength` (51) bounds the work only, on every network.
  `legacyAddress` decides what an address is.

## The limit of a P2SH redeem script

- 520 bytes on every network, kept on purpose (Haddock of
  `maxRedeemScriptSize`). The check is `p2shScriptHash`: `toP2SH`,
  `payToScriptAddress`, `inputAddress`, `deriveMSAddr`, `makeSignature`,
  the P2SH branch of `verifyStdInput`, and `toP2SH` in `Psbt.hs`.
- Bitcoin Cash Node 29.2.0 spends a redeem script of 9,997 bytes and
  refuses 9,998 (`scriptsig-size`): the input script holds 10,000 at most.
- A limit by network also needs the relay rule on signature checks of
  Bitcoin Cash Node (`SCRIPT_VERIFY_INPUT_SIGCHECKS`): an input script has
  43 bytes for each check, less 60, and an ECDSA multisig counts one check
  for each key. An ECDSA 1-of-16 has 624 bytes and needs 628: not relayed.
- `judgeInputs` has no size check in `cashMultisig`: a Schnorr multisig
  spend of a longer redeem script is `InputVerified` on Bitcoin Cash.

## Tests

- A literal address text of a node, with no node running: the offline
  `bitcoin-tx` of Bitcoin Core or Bitcoin Cash Node, `-json -create
  "outscript=0.001:HASH256 0x20 0x<hash> EQUAL"`, and `outaddr=0.001:<text>`
  to read one back. `-usecashaddr=0` gives the legacy form.
- A test of a function that gives an endless list: compare `isNothing` or
  `take n` of it. `shouldBe` on the list prints it without end when it
  fails.
