# The identity helpers and their spec

`testIdentity` and the five tests it makes (`src/Haskoin/Util/Arbitrary/Util.hs`),
which every spec calls with its boxes, and the spec that defends them
(`test/Haskoin/Util/Arbitrary/UtilSpec.hs`).

## A test of a helper that makes a `Spec`

- Run the `Spec` inside a test: `evalSpec` then `runSpecForest`, of
  `Test.Hspec.Runner` (hspec 2.10 or later), as `outcomes` of the spec does.
  The run takes nothing from the command line: with `--match` given to the
  suite, its examples still run. `specResultItems` gives each example with
  its groups, its name and whether it failed.
- A new rule of a helper: add a type with that one fault to the spec, and
  state which example fails. The types there hold one byte, and a fault
  shows on the byte 3 only, so the generator decides whether it shows.
- A property under `prop` runs 100 cases at the sizes 0 to 99, in order. A
  generator made with `sized` therefore gives the same values on each run:
  `largeOnly` of the spec uses this to show a fault at the sizes above 49.
- `deriving newtype (Serial)` does not compile ("Couldn't match representation
  of type: m Word8"): write the two methods.

## What a changed helper can show

- The strict reader (`runGetS`, cereal) and the lazy reader (`runGetL`,
  binary) differ on one request only, of those probed: a negative number of
  bytes (`getBytes (-1)`). The strict one fails, the lazy one reads nothing.
  The type `StrictRefuses` of the spec uses it. Probed and the same in both:
  `remaining`, `isEmpty`, `skip`, `ensure`, `lookAhead`, a read past the end.
- So no test fails when `testSerial` loses its two lazy lines, nor when
  `testMarshal` loses one of its two lines: `unmarshalLazy` is `unmarshal`
  on the strict bytes. Do not look for such a test again.
- To see that a test of the spec can fail, change one line of a helper and
  run `haskell-dev test Arbitrary`: it runs this spec alone, in about 20
  seconds with the build.
