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
