# SLIP-39

The module `Haskoin.Crypto.Keys.Slip39`, its spec `Slip39Spec.hs`, the data
files `data/slip39_*` and the verifier
`test/Haskoin/Crypto/Keys/slip39_verify.py`.

## Tests

- A new literal (a ciphertext, a mnemonic, shares): take it from the
  verifier. A script outside the repository can import it and call `encrypt`,
  `decrypt`, `encode_share` and `generate_shares`. Run that script with
  `python3 -B`, or the import leaves a `__pycache__` folder under `test/`.
- A test at a high iteration exponent: the cipher takes 45 ms at 4 and 90 ms
  at 5 in the spec, and minutes at 15. State the count with `roundIterations`
  and do not run the cipher above 5.
- A test of what `generateSharesFrom` draws: `scripted` of the spec is a
  source that gives a fixed stream of bytes, and `drawnBytes` is the stream
  of a case of `data/slip39_split.json`. A 1-of-1 scheme draws the two bytes
  of the identifier and nothing more.
- "Two of the random values are equal" in a test with fixed random values:
  `generateSharesWith` and `splitSecret` refuse a value given twice
  (`checkDrawnOnce`). Give each split its own bytes. `recordedZeros` only
  works on a scheme that draws one value of each length, such as 3-of-5.
- A test of `combineShares` on a long list: more than 256 shares are refused
  by their number first, so no test can time the grouping of the shares.
- To see a test fail on a changed `Slip39.hs`: `haskell-dev test Slip39`
  builds and runs it in 25 seconds, and no other spec imports the module.
