# Instructions for Claude

## How this file is kept

This file is loaded into every session, so each line costs tokens every time.
It has three parts:

- **The rules**: everything above `## Feature notes`. Only the maintainer
  changes them. If a change makes a rule out of date, say so in your report
  and leave the rule alone.
- **The feature notes**: the index of the files of `claude-notes/`, one file
  for each kind of feature. A file costs tokens only in the sessions that
  work on its feature.
- **The working notes**: the last section. It holds only what applies to
  every session, whatever the feature.

Claude owns the working notes, the files of `claude-notes/` and their index,
and keeps them without asking, by the rules below.

### Rules for the notes

The notes save the next session the research this session paid for.

- **Before the work.** Read each file of `claude-notes/` that the index names
  for the task, before you read the code.
- **When to add.** Something about this repository took real effort to find
  out (several searches, a failed build or test run, a wrong first approach),
  and it would take that effort again. At the end of a task, ask what would
  have saved the most effort, and write that down, or nothing.
- **Where it goes.** What helps on one kind of feature goes to the file of
  that feature. What helps whatever the feature goes to the working notes:
  the build, the tests, the layout of the code, a trap that any change can
  fall into. A fact has one home: another file points to it.
- **A new file.** When no file fits, create one, named after the feature. Add
  its line to the index in the same change: the file, then when to read it,
  in one or two lines. A file starts with a title and what it covers. Delete
  a file, and its line, when nothing is left in it.
- **What to leave out.** What one `grep` or the module names show. The story
  of a task. What matters to one task only. The maintainer's decisions and
  preferences, which go to memory. What the rules, the README or a module
  header already say: point to it instead. When a note covers what a memory
  says about the repository, trim that memory to what is left.
- **Only what was checked.** An entry states what this session saw in the
  code or in a run. Never a guess.
- **Form.** The task or the symptom first, then what to do. Name files and
  functions, never line numbers. An entry of the working notes is one or two
  lines. An entry of a feature file is four lines at most. Put it under the
  heading it fits, and add a heading only when none fits.
- **Upkeep.** Update an entry instead of adding a second one. Fix or delete
  an entry in the same change that makes it wrong, and at once when you find
  one wrong.
- **Size.** 80 lines at most for the working notes, and 120 lines at most for
  a file of `claude-notes/`. When one is full, merge entries or drop the
  least useful one before adding. A feature file that stays full is split in
  two, by the parts of its feature.
- **Report.** Name each change to the notes in one line of your report.

## Build and test

- Build: `haskell-dev build`
- All tests: `haskell-dev test`
- One spec: `haskell-dev test Psbt` (a word of the module name;
  `--match "/Haskoin.Block/asert/"` narrows it)
- Documentation: `haskell-dev docs`
- `haskell-dev` is a script of [jprupp/tools](https://github.com/jprupp/tools),
  shared with the other packages, and not a file of this repository. It must
  be on the `PATH`. Its settings for this package are in `haskell-dev.toml`.
  A change to the script itself is a change to jprupp/tools.
- `stack build`, `stack test`, `stack haddock` and `stack bench` are the
  release build. Do not mix them with `haskell-dev` in one session. With no
  source changed, a switch builds nothing and keeps the objects of the other
  flags; after a change, it compiles everything again.
- `haskell-dev` builds without optimisation. Never time the library with it:
  the benchmarks run with `stack bench`, as the README says.

## Keep the documentation up to date with every change

Every change to this repository must update all the documentation it affects,
in the same commit or pull request. A change is not finished until its
documentation is. Before you finish, check each of these and update what the
change touches:

- `README.md`: features, installation steps, examples, configuration,
  tutorials, module overview and caveats. Code examples must still compile
  against the new code, and version numbers in examples must name the current
  release.
- `CHANGELOG.md`: describe the change under the next version.
- Haddock in `src`.
- Module headers and declaration comments: add Haddock for every new
  declaration, and fix comments that the change made wrong.

If a change needs no documentation update, say so explicitly when you report
the change, with the reason.

## How to write documentation here

Documentation explains the purpose and spirit of the code, not only its
behaviour. For every module and every significant type or function, say what
problem it solves and why it is designed the way it is, including the trade-offs
and the alternatives it rejects. A reader should come away knowing when to use
it and when not to. Keep to the structure the README already has, and put new
material in the section where a reader would look for it.

## Line length

Every line of code must be shorter than 120 columns. This covers Haskell
source, tests, `package.yaml` and cabal files, CI workflows, scripts, and the
code examples in the documentation. Break long expressions, type signatures
and import lists over several lines rather than letting them run on.

- **Long strings:** split them over several lines in the least cluttered way
  that works. Pick the form that leaves the fewest quotes, backslashes and
  operators on the page:
  - `unwords [...]` or `unlines [...]` for messages and prose, one piece per
    line;
  - string gaps for text that has to stay a single literal, with a backslash
    at the end of one line and another at the start of the next:

    ```haskell
    msg =
      "The first part of a long message, \
      \and the rest of it."
    ```

  - `<>` only when neither of those reads better.
- **Long constants:** split them too, even when they have no natural break,
  such as hexadecimal test vectors, keys, hashes and base64 data. Cut them into
  pieces of equal width so that they line up, and join them with string gaps
  or `mconcat`.
- **Exceptions:** sometimes a line cannot be split because of a limitation of
  the language or of a tool, for example a generated file such as
  `stack.yaml.lock`, a URL or other value that a tool reads only on one line,
  or a format with no way to continue a line. Leave such lines long, but keep
  them rare, and add a comment explaining why where the format allows one.

## Embedded scripts

Put multi-line scripts in their own files whenever possible, rather than
embedding them in other files: for example, move a long `run:` block of a
GitHub Actions workflow into a script under `scripts/` and call it from the
workflow. A script in its own file can be read, linted and run on its own.

When a script has to stay embedded, lay it out to be read: one command per
line, indentation that shows its structure, a comment for any step that is not
obvious, and no long chains of commands joined with `&&` or `;` on one line.

## Checks

Build the documentation with `haskell-dev docs` and make sure it has no
warnings about broken markup. The command ends with a check of the comments:
a change must add nothing to what that check reports. CI builds the
documentation too, with `stack haddock`, both with the OS libraries and with
`stack --nix`.

List the lines of 120 columns or more with
`git ls-files '*.hs' '*.yaml' '*.cabal' '*.md' | xargs grep -n '.\{120,\}'`,
and fix every one that is code and is not one of the exceptions above.

## General

All features in haskoin-core must follow the Bitcoin specification or BIPs
exactly. If the specification or the BIPs are imprecise, then haskoin-core
must follow the bitcoin-core implementation exactly. You can ask the user
about a feature choice only if you have a strong case that there is a real
problem in the bitcoin-core implementation. In case of doubt, we want to
implement the most conservative and safest option for the end users. We
generally want to follow the bitcoin-core relay rules rather than block
validation rules.

## Feature notes

Read a file before any work on what its line names.

- `claude-notes/addresses.md`: `Haskoin.Address` and the address functions
  of extended keys: what exists on which network, the legacy and nested
  forms, the limit of a P2SH redeem script, and their tests.
- `claude-notes/bloom.md`: Bloom filters (`Haskoin.Network.Bloom`): the match
  of a transaction and of a block on each chain, `bloomCreate`, their tests.
- `claude-notes/difficulty.md`: the work a new header must show, on Bitcoin
  or on Bitcoin Cash (EDA, DAA, aserti3-2d), and the tests of those rules.
- `claude-notes/protocol.md`: the protocol machines of the reference nodes
  (`Haskoin.Network.Protocol`), their report in `doc/protocol/` and citations.
- `claude-notes/psbt.md`: the PSBT decoder, signer and finalizer
  (`decodePsbt`, `signPsbt`, `finalizePsbt`): what they refuse and when,
  where they differ from Bitcoin Core, their cost and their tests.
- `claude-notes/signing.md`: the signer and the verifier of whole
  transactions (`signTx`, `signInput`, `verifyStdTx`, `judgeInputs`) and
  the digests they share between inputs: their cost and its tests.
- `claude-notes/slip39.md`: SLIP-39 shares (`Haskoin.Crypto.Keys.Slip39`),
  their tests and where the literal values of the tests come from.
- `claude-notes/test-helpers.md`: `testIdentity` and the five identity tests
  (`Haskoin.Util.Arbitrary.Util`), their spec, and a test of any helper that
  makes a `Spec`.

## Working notes

### Where things are

- The helpers that the specs share are in the library, not in `test/`:
  `src/Haskoin/Util/Arbitrary/` holds the generators, and its `Util.hs` holds
  `testIdentity`, `testSerial` and `testJson`. A change there is a change of
  the public API. The helpers of one spec are at the top of its file.
- `==` and `shouldBe` on a `Tx` or a `MerkleBlock` do not see how the witness
  list or the flags are written (`txContent`, `merkleBlockContent`). A test
  of that form compares the field `witness` or `flags`.
- A function that calls `decodeDirect` (or `wholeTx`) without its bytes
  argument, and is not `INLINE`, is nine times slower on the release build,
  as `decodeTx` was. Write `f bytes = ... bytes`.
- A new refusal of `signTx` or `signInput`: the generators of
  `Util/Arbitrary/Transaction.hs` and `Spelling.hs` sign with them, and the
  property tests then fail with an `ErrorCall`. Make the generators avoid it.
- `test/BitcoinCore.hs` is the one helper module of the test suite: it needs
  podman-test, which the library must not. It runs Bitcoin Core for `PsbtSpec`.
- Calls to Bitcoin Core in the tests are positional: check the order in the
  RPC `help METHOD`. `walletcreatefundedpsbt` takes a lock time before options.
- A new module: `stack build --dry-run` writes `haskoin-core.cabal` again in
  under a second, without a build. The file is tracked, so it is part of the
  change.
- A change of a function that a README example calls: nothing compiles
  the README. Copy the example into a `main` and build it with
  `stack exec -- ghc -O0`, then run it for the `-- =>` lines.
- "Non type-variable argument in the constraint: HasField": a local function
  without a signature uses `x.field` on its argument. Give it a signature, or
  write the expression where it is used.

### Running the checks

- A type and a constructor of the same name: write `t'Name'` in Haddock, or
  the check of `haskell-dev docs` counts it as ambiguous.
- The check of `haskell-dev docs` reports 144 problems, all older than the
  script: 93 ambiguous names, 27 names out of scope, 19 slashes and 5
  links. Keep the lines after `Documentation check` in a file before the
  change, and `diff` after it without the line numbers, which an edit
  moves. The count is the same on each run.
- A spec that becomes the longest share of `haskell-dev test`: add its module
  to `slow-specs` in `haskell-dev.toml`, and each top `describe` of it runs
  in a process of its own. Split a long `describe` to spread it further.
- A probe with `stack exec -- runghc` or `ghc` uses the library as last
  built. After a build of changed source, such as a reverted fix to see a
  test fail, build the real source again before the probe.
- "Could not load module Haskoin ... unusable due to missing dependencies",
  in a probe with `stack exec`: run `haskell-dev build` first, then the probe.
- "haskell-dev: not in a git repository", in a copy of the tree made with
  `git archive`: run `git init` in the copy. No commit is needed.
- A run under a memory limit: a clean `haskell-dev build` needs 1.2 GB for
  GHC, and each of the eight test processes about 100 MB.
- A test of a cost: `timeout` around `evaluate`, as `taprootCostSpec` of
  `PsbtSpec.hs`. Size it so that the old code, timed first, is 4 times over.
  Time both with the built `spec` and nothing else running: a mutant run
  beside it made a test of 1 s miss a limit of 3 s.
- A test of the order of a type that defines `compare` only: with this GHC
  `a < b` calls `compare b a`. State the order with `compare` in both
  directions, as `sortsBefore` of `ExtendedSpec.hs`.
- `--match "/Module/name/"` runs nothing unless `name` is the whole name of
  a `describe`. Without slashes, a part of the name is enough.
- The seconds that `haskell-dev test` prints change with the load of the
  machine: 3 to 9 for one spec. To time examples, run the built `spec` of
  `.stack-work/dist` with `--match "/Module/" --times`.
- The long-line check prints about 1450 lines, most of them test vectors,
  `doc/protocol/` and `CHANGELOG.md`. With `grep -c` in place of `grep -n`
  it counts them for each file: compare the counts before and after the
  change.
