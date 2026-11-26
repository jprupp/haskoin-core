# Bloom filters

`Haskoin.Network.Bloom`: the filter of a BIP 37 client, the match of a
transaction and of a block against it on each chain, and their tests.

## Where the two nodes differ

- Bitcoin Cash Node does not match as Bitcoin Core, in three places, all
  behind `cashRules`: two passes over a block (`bloomRelevantBlock`), the
  token prefix taken off an output (`lockingScript`), and a multisig of 16
  keys at most, each a direct push (`paysToKeys`).
- Before a change of the match, read both nodes: `CMerkleBlock` in
  `merkleblock.cpp`, `IsRelevantAndUpdate` in `bloom.cpp`, and `Solver` in
  `script/solver.cpp` (Bitcoin Core) and `script/standard.cpp` (Bitcoin
  Cash Node). The same names hide other rules.
- Two folds of `bloomRelevantUpdate` are not the two passes of the node: the
  second tests the outputs again. The halves are `matchOutputs` and
  `matchInputs`.
- The callers in the library: `filtered` in
  `Protocol/BitcoinCashNode/Blocks.hs`, and both `Relay.hs`. The Bitcoin
  Core machine takes its filtered block from `Env.filteredBlock`.

## bloomCreate

- A guard comes before every conversion. `truncate` of an infinite or
  not-a-number `Double` to `Int` gives 0 without optimisation and `minBound`
  with `-O1`, and a negative size makes `S.replicate` throw when the filter
  is used.

## Tests

- To see what outpoint a node inserted in a filter, without a spend to
  sign: a later transaction that pushes the 36 bytes of the outpoint after
  `OP_RETURN` matches exactly when the outpoint is in the filter. Ask for
  the two blocks on one connection.
- `cashBlock` of `NetworkSpec.hs` is a regtest block of Bitcoin Cash Node
  with spenders before their parent, and the expected matches are the
  answers of the node. On Bitcoin Cash the node gives no block in a chosen
  order: make blocks until a spender stands first.
- A filtered block of the node needs `-acceptnonstdtxn=1` for the odd
  output scripts, and a token genesis spends an output of index 0: the
  category is the id of that output's transaction.
