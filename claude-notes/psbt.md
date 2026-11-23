# The PSBT decoder, signer and finalizer

`decodePsbt`, `signPsbt` and `finalizePsbt` of `Haskoin.Transaction.Psbt`,
the readers of the fields that they use, and their tests in `PsbtSpec.hs`.

## What is refused, and when

- A change of a refusal, or of what an input gets: the rule is in
  `CLAUDE.md`, "General". `signPsbt` refuses a PSBT for a sighash type only
  (`checkSigHash`, `acceptsSigHash`, `signaturesUse`). To leave an input,
  `signEcdsa`, `signTaproot`, `finalEcdsa` and `finalTaproot` give `Nothing`.
- Before "aligning" a behaviour with Bitcoin Core: the Haddock of `signPsbt`,
  `finalizePsbt`, `decodePsbt`, `combinePsbt` and `psbtTransaction` name each
  place where the module does not do as Bitcoin Core, with the reason (a BIP
  sentence, a problem of Bitcoin Core, or a limit of the library).
- What Bitcoin Core does with a PSBT: `SignPSBTInput` and `FinalizePSBT`
  (`psbt.cpp`), `ProduceSignature`, `SignStep`, `CreateSig` and `SignTaproot`
  (`script/sign.cpp`), `FillPSBT` (`wallet/scriptpubkeyman.cpp`), and the
  `Unserialize` of `PSBTInput` (`psbt.h`) for what its decoder refuses.
- A field that `decodePsbt` reads as bytes and its accessor refuses: a script
  that is no list of opcodes, 32 bytes that are no point, a Taproot signature
  of 65 bytes with a last byte that is no sighash type. The signer and the
  finalizer read the bytes of the map, not the accessors (`singleKeyLeaves`,
  `signaturesUse`, `smallestSignedLeaf`).
- A new field for the decoder: its type constant, its `Field` with a
  `KeyShape` in `inputFields` or `outputFields`, and for an input its type in
  `clearedTypes` of `finalizePsbt`, which a final input loses.
- A P2SH coin with a redeem script over 520 bytes gets no signature:
  `inputSpend` matches with `toP2SH`, and `makeSignature` refuses that size
  too. Bitcoin Core signs it. To sign it, both would change.
- A key of 32 bytes that is no point, for a test: the x coordinate 5.

## Comparing with a node

- Bitcoin Core counts as signed an input whose coin verifies with empty
  final scripts, such as the script `OP_1` (`PSBTInputSignedAndVerified`
  comes first in `SignPSBTInput`), and then checks no sighash type on it.
- The wallet of Bitcoin Core knows descriptors: it signs a `tr(KEY)` coin
  without the internal key field, and a P2SH-P2WPKH coin without its redeem
  script. It takes a previous transaction from its own transactions. A
  comparison must give the library those fields in the PSBT.
- Bitcoin Core writes a witness output into an input that it signed with a
  witness signature, and writes its keys in another order. Compare the
  signatures and the final scripts, not the bytes.

## Cost

- A change of `heldTaprootKeys`, `singleKeyLeaves` or `smallestSignedLeaf`:
  the records and the signatures are found by a lookup in a map by the bytes
  of the key, and each leaf script is asked for once, whatever its number of
  entries. `taprootCostSpec` fails within three seconds per test when a
  lookup becomes a walk.
- A new Taproot digest in the signer or the finalizer: `taprootSigHashWith`
  on the hashes of `taprootHashes`, never `taprootSigHash`, which hashes the
  whole transaction. The tests of 5000 inputs are in `sharedHashesCostSpec`
  of `TaprootSpec.hs`, with the other callers of the digest.

## Tests

- Fixtures of the spec: `spendingPsbt` (one coin), `spendingTwo` (two coins of
  one previous transaction), `spendingTree` (a Taproot coin with many
  leaves), `onInputs`, and in `taprootChecksSpec` the coin `withTree` with
  `treeFields` and `leafOfVersion`. Own input in the tests: key 1, P2PKH.
- `inputByInputSpec` has one test for each rule of the signer and the
  finalizer that was compared with Bitcoin Core: `treeUnder` (a leaf of key
  1 under an internal key), `twoDepths` (two signed leaves), `leftAlone`.
- A decoder case: `tinyPsbt GLOBAL INPUT OUTPUT`, each an entry in hex: the
  length of the key, the key (type first), the length of the value, the
  value. The vectors of BIP 373 are read with the type `Vectors371`.
- A new file under `data/`: `stack build --dry-run` adds it to
  `haskoin-core.cabal`, as for a new module.
- To see a test fail on a changed `Psbt.hs`: `haskell-dev test Psbt` builds
  and runs it in about two minutes. Do not edit the file while such a run
  goes.
