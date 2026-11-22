# The PSBT signer and finalizer

`signPsbt` and `finalizePsbt` of `Haskoin.Transaction.Psbt`, the readers of
the fields that they use, and their tests in `PsbtSpec.hs`.

## What is refused, and when

- A change of a refusal: the rule is in `CLAUDE.md`, "General". The Taproot
  signer refuses a sighash type only, and leaves any input that it cannot
  sign. The ECDSA signer still refuses an input that it holds a key for
  (`heldKeys` first), which Bitcoin Core leaves.
- What Bitcoin Core does with a PSBT: read `SignPSBTInput` (`psbt.cpp`) and
  `SignTaproot` (`script/sign.cpp`). Its finalizer refuses nothing: an input
  that fails is left not final. `finalizePsbt` still refuses some.
- A Taproot entry that `decodePsbt` reads (`checkMap` checks lengths only) and
  a reader refuses: 32 bytes that are no point, a leaf script that is not a
  list of opcodes. Read such entries one by one: `tapLeafScriptEntries`,
  `tapScriptSigsByKeyData`. The ECDSA fields are checked whole by `checkMap`.
- A key of 32 bytes that is no point, for a test: the x coordinate 5.

## Cost

- A change of `heldTaprootKeys` or `finalTaprootScripts`: the records and the
  signatures are found by a lookup in a map by the bytes of the key, and the
  leaves of a record are a `Set` built once. `taprootCostSpec` fails within
  three seconds per test when a lookup becomes a walk.

## Tests

- Fixtures of the spec: `spendingPsbt` (one coin), `spendingTwo` (two coins of
  one previous transaction), `spendingTree` (a Taproot coin with many
  leaves), `onInputs`, and in `taprootChecksSpec` the coin `withTree` with
  `treeFields` and `leafOfVersion`. Own input in the tests: key 1, P2PKH.
- To see a test fail on a changed `Psbt.hs`: `haskell-dev test Psbt` builds
  and runs it in about a minute. Do not edit the file while such a run goes.
