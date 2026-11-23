# Signing and verifying transactions

The signer and the verifier of whole transactions: `signTx`, `signInput`,
`verifyStdTx`, `judgeInputs` (`Haskoin.Transaction.Builder` and
`Builder.Sign`) and the digests they use (`Haskoin.Script.SigHash`,
`Haskoin.Transaction.Taproot`). The PSBT code has its own file.

## Cost

- A new digest for an input: the function that ends in `With`, on the hashes
  that the inputs share: `spent.sigHashes` and `spent.taproot` of
  `SpentCoins` in the verifier and `judgeInputs`, `sigHashes` and
  `taprootCoins` in `signTx`. A function that takes the `Tx` hashes it whole.
- A new read of an input by its index in `verifyInput` or `judge`: the
  vectors `spent.coins` and `spent.spends`. `!!` or `length` on a list of
  the transaction, for each input, takes time by the square of the inputs.
- `signTx` signs each input on its input script and witness stack
  (`signSpend`, `spendInput`, `taprootKeyWitness`) and puts the transaction
  together once. `signInput`, `buildInput` and `signTaprootInput` run the
  same code for one input. A wrong number of stacks is told last, as before.
- The timed tests, 5000 inputs in under three seconds for each caller:
  `sharedHashesCostSpec` of `TaprootSpec.hs` (Taproot) and of
  `TransactionSpec.hs` (SegWit version 0 and Bitcoin Cash, with 8000
  outputs so that the old code is 5 times over the limit).
- `mergeTxs` merges each input on its input scripts (`mergeScripts`, with
  `txSigHashes` of the first transaction) and puts the transaction together
  once. `mergeTxInput` runs `mergeScripts` for one input. Its timed test is
  on Bitcoin Cash: on Bitcoin the legacy digest is the square by design.
- A loop over the inputs whose work calls libsecp256k1 many times for each
  input: a left fold (`foldM`, as in `mergeTxs`), not `mapM` of `Either`.
  The bindings use `safe` foreign calls, which take longer on a deep stack:
  `mergeTxs` of ten transactions of 2000 inputs took 1.07 s, and now 0.40.
- Not done: a legacy multisig computes its digest again for each key that a
  signature is tried against (`countMulSig'`, `spendInput`, `mergeScripts`).
  Bitcoin Core keeps it by hash type (`SigHashCache`). `countMulSig` is for
  one input.
- Not done: `matchTemplate` (in `findInputIndex` and `mergeTxs`) looks for
  the coin of each input from the start of the list. It is fast only when
  the coins or the signing parameters come in the order of the inputs.
