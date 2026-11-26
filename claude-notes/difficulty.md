# Difficulty

The work a new header must show, in `src/Haskoin/Block/Headers.hs`: the
retarget of Bitcoin, and the EDA, DAA and aserti3-2d rules of Bitcoin Cash.

## aserti3-2d

- A change to `nextAsertWorkRequired`: the vectors of
  `data/test_vectors_aserti3-2d_run*.txt` do not check it. `testAsertBits` in
  `test/Haskoin/BlockSpec.hs` gives them to `computeAsertBits` only. They pass
  whatever time and height the wrapper takes.
- The wrapper takes the time and the height of the parent, not of the new
  block: its comment says why. Compare a change with `GetNextASERTWorkRequired`
  of Bitcoin Cash Node, and check it in `asertSpec`, which calls the wrapper
  through `nextWorkRequired` and `connectBlocks`.

## Tests of a rule

- The top of `test/Haskoin/BlockSpec.hs` has a network for each rule
  (`retargetNet`, `edaNet`, `daaNet`, `asertNet`) and the helpers to use.
  `storeChain` stores headers from a list of (timestamp, bits) with no proof
  of work, and `requiredAfter` gives the bits asked of the next block.
- A test that must connect a header with every rule checked mines it:
  `mineOn`, `mineChain`, then `connectHeight` or `connectAll`.
- A test of a header that `isValidPOW` must refuse for its bits: `mineBlock`
  and `mineOn` cannot make it, since they look for a nonce with `isValidPOW`.
  Take a literal header and state its hash, as the test of the limit in
  `proofOfWorkSpec`. The hash comes from a SHA-256 of the 80 bytes in Python.
- A test of the upper limit of a result: the bits must differ without the
  limit. At `0x207fffff` a block has 2 of work, and a DAA window of blocks
  every ten minutes gives `0x207fffff` with or without the limit. Every
  twenty minutes it gives `0x2100ffff` without it.

## A rule with no answer

- A new place where a rule cannot answer (too few blocks below, a division):
  return `Left` through `nextWorkRequiredWith`, never `error`. A header is
  given its required bits before its proof of work is checked, so on a
  network made by hand a peer chooses the case. Tests: `requiredOrRefusal`.
- A DAA test at the regtest limit: the work of the window is 288 over 144
  blocks, and `computeTarget` gives `Left` once the window is shorter. Use
  `0x1f7fffff` (512 of work) unless the test is about that refusal.
