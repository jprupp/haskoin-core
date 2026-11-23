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
- Not done: `mergeTxs` and `mergeTxInput` walk the lists and call
  `txSigHash` for each input. `countMulSig` is for one input.
