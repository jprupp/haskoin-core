# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-08-11

### Changed

- Make script and address parsing more strict.
- Use smart constructors for addresses to avoid inconsistent or incorrect represtentations.

### Fixed

- Support Bitcoin Cash 256-bit pay-to-script-hash scripts and addresses.
- Make addresses of incorrect length invalid.
- Avoid decoding scripts as standard when hash or public key length incorrect.

## [1.2.2] - 2025-05-08

### Changed

- Standardize author name and correct README link.

## [1.2.1] - 2025-05-08

### Changed

- New home in github.com/jprupp rather than github.com/haskoin.

## [1.2.0] - 2023-07-23

### Changed

- Move from `cryptonite` to `crypton` for now.

## [1.1.0] - 2023-03-14

### Changed

- Update upstream dependencies & LTS Haskell.

## [1.0.4] - 2023-10-09

### Changed

- Export the BIP39 word list
- Add new BIP39 test vectors

## [1.0.3] - 2023-09-02

### Changed

- New dependency on data-default
- Renamed some arbitrary (test) functions for clarity
- Reworked the identity testing tool to include Marshal and MarshalJSON classes

## [1.0.2] - 2023-08-04

### Fixed

- Text files needed for testing now in tarball.

## [1.0.1] - 2023-08-03

### Changed

- Do not use alternative monad for Either String values.

## [1.0.0] - 2023-07-28

### Changed

- Shorten all field names allow duplicates, using DuplicateRecordFields extension.
- Use OverloadedRecordDot language extension and syntax.
- Use explicit context object from secp256k1-haskell library.
- Unify serialization into custom Marhsal and MarshalJSON classes.
- Use ormolu for formatting.
- Simplify module organisation.
- Strongly break backwards compatibility.

## [0.22.0] - 2023-06-28

### Changed

- Upgrade to lastest secp256k1 and base16 packages.

## [0.21.2] - 2022-04-13

### Changed

- Serialisation test now works for both strict and lazy bytestrings.

## [0.21.1] - 2021-12-13

### Changed

- Make Base58 faster.

## [0.21.0] - 2022-11-23

### Added

- BCH Testnet4 support.

### Changed

- Fix inconsistent serialization/deserialization issues.

### Fixed

- Makes `finalScriptWitness` field encoding conform to bitcoin core.
- Fixes bug in `finalizeTransaction`

### Added

- Signing support for PSBTs
- Helper function for merging PSBTs
- More PSBT tests
- Partial support for taproot

## [0.20.5] - 2021-09-13

### Added

- Support Bech32m address format for Taproot.

## [0.20.4] - 2021-06-08

### Fixed

- Add missing case for witness version.

## [0.20.3] - 2021-05-17

### Fixed

- Allow unknown inv types.

## [0.20.2] - 2021-05-17

### Fixed

- Allow unknown messages of zero length.

## [0.20.1] - 2021-05-14

### Fixed

- Correct case where binary search returned the wrong element.

## [0.20.0] - 2021-02-22

### Chaged

- Use bytes instead of binary or cereal.

## [0.19.0] - 2021-01-25

### Added

- Hashable instances for extended keys.

### Changed

- Mnemonic passphrases now `Text` instead of `ByteString`.

### Fixed

- Tests now pass for witness addresses.

## [0.18.0] - 2020-12-10

### Added

- Support SegWit addresses with version other than 0.

## [0.17.6] - 2020-12-07

### Added

- Serialize instances for `XPubKey` and `XPrvKey`.

## [0.17.5] - 2020-12-03

### Fixed

- Handle special case in block header binary search function.

## [0.17.4] - 2020-12-03

### Fixed

- Bounds check too restrictive in block header binary search function.

## [0.17.3] - 2020-11-17

### Changed

- Reduce minimum version of text package dependency.

## [0.17.2] - 2020-11-17

### Changed

- Update lists of seeds for all networks.

## [0.17.1] - 2020-11-02

### Changed

- Use the C-preprocessor to handle versions of `base16-bytestring`

## [0.17.0] - 2020-10-21

### Added

- Support for Bitcoin Cash November 2020 hard fork.
- Functions to find block headers matching arbitrary sorted attributes.

### Removed

- GenesisNode constructor for BlockNode type.

## [0.15.0] - 2020-07-23

### Added

- Add more test vectors

### Changed

- stringToAddr renamed to textToAddr
- Move ScriptOutput to Standard.hs
- Move WIF encoding/decoding to Keys.hs
- (breaking) rename `OP_NOP2` and `OP_NOP3` to `OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY` resp.
- Update to latest secp256k1 bindings.

## [0.14.1] - 2020-06-14

### Fixed

- Correct some Bitcoin Cash Testnet3 seeds.
- Add helpers for writing Data.Serialize and Data.Aeson identity tests

## [0.14.0] - 2020-06-14

### Changed

- Expose all modules for tests.
- Tests depend on library instead of having access to its source code.
- Use MIT license.
- Update seeds.
- Bump secp256k1-haskell dependency.

## [0.13.6] - 2020-06-05

### Changed

- Expose the Arbitrary test instances under Haskoin.Util.Arbitrary

## [0.13.5] - 2020-05-16

### Changed

- Provide meaningful JSON instances for most types.

## [0.13.4] - 2020-05-14

### Added

- Support for Bitcoin Cash May 2020 hard fork.

## [0.13.3] - 2020-05-08

### Changed

- Improve code and documentation organisation.

## [0.13.2] - 2020-05-08

### Changed

- Move all packages from Network.Haskoin namespace to Haskoin namespace.
- Expose all top-level modules directly.

## [0.13.1] - 2020-05-06

### Changed

- Faster JSON serialization.

## [0.13.0] - 2020-05-06

### Changed

- Consolidate all modules in Haskoin module.

### Removed

- Deprecate Network.Haskoin namespace.
- Hide QuickCheck generators in test suite.

## [0.12.0] - 2020-04-10

### Added

- Support for signing segwit transactions.
- High-level representation of segwit v0 data and auxilliary functions.

### Changed

- Adds handling of segwit signing parameters to transaction signing code.

## [0.10.1] - 2020-02-08

### Added

- Lower bound versions for some dependencies.

## [0.10.0] - 2020-01-15

### Added

- DeepSeq instances for all data types.

### Changed

- There is no `SockAddr` inside `NetworkAddress` anymore.

## [0.9.8] - 2020-01-01

### Added

- Ord instance for `DerivPathI`

## [0.9.7] - 2019-12-04

### Added

- JSON encoding/decoding for blocks.

### Fixed

- Fix lowercase HRP test for Bech32.

## [0.9.6] - 2019-10-29

### Added

- `bloomRelevantUpdate` implementation for Bloom filters (thanks to @IlyasRidhuan).

### Fixed

- Fix for Bech32 encoding (thanks to @pavel-main).

## [0.9.5] - 2019-10-23

### Added

- Expose functions added in 0.9.4.

## [0.9.4] - 2019-10-23

### Added

- Support for (P2SH-)P2WPKH addresses derived from extended keys.

### Changed

- Change names of backwards-compatible P2SH-P2WPKH functions from 0.9.3.

## [0.9.3] - 2019-10-22

### Added

- Some support for P2WPKH-over-P2SH addresses.

## [0.9.2] - 2019-10-09

### Removed

- Disable unnecessary `-O2` optimisation added in previous version.

### Added

- Allow decoding unknown P2P messages.

## [0.9.1] - 2019-10-02

### Added

- Add a function to produce a structured signature over a transaction.
- Enable `-O2` optimisations.

## [0.9.0] - 2019-04-12

### Changed

- Address conversion to string now defined for all inputs.

## [0.8.4] - 2018-12-05

### Added

- Add reward computation to block functions.
- Add PSBT BIP-174 types and functions.

## [0.8.3] - 2018-12-04

### Added

- Add reward halving interval parameter to network constants.

## [0.8.2] - 2018-11-06

### Added

- Recognize `OP_CHECKDATASIG` and `OP_CHECKDATASIGVERIFY` opcodes.

## [0.8.1] - 2018-10-13

### Added

- Add instances of `Hashable` and `Generic` where possible.

## [0.8.0] - 2018-10-13

### Removed

- Remove `deepseq` dependency.
- Remove network constant reference from address and extended keys.

## [0.7.0] - 2018-10-13

### Added

- Add `Serialize` instance for network constants.
- Add `Serialize` instance for addresses that includes network constants.

### Changed

- Move functions related to addresses from `Script` to `Address` module.

## [0.6.1] - 2018-10-09

### Added

- Compatibility with latest GHC and base.

### Changed

- Update minimum base to 4.9.

## [0.6.0] - 2018-10-08

### Changed

- Force initialization of addresses through smart constructor.
- Assume addresses are always valid when instantiated in code.
- Allow to provide unwrapped private keys to transaction signing functions.

## [0.5.2] - 2018-09-10

### Changed

- Make dependencies more specific.

## [0.5.1] - 2018-09-10

### Changed

- Remove some unneeded dependencies from `stack.yaml`.
- Change `secp256k1` dependency to `secp256k1-haskell`.

## [0.5.0] - 2018-09-09

### Added

- Support for Bitcoin Cash network block sychronization.
- Support for Bitcoin Cash signatures.
- Initial work on SegWit support.
- New version of `secp256k1` bindings.
- Block header validation.
- Support for RegTest networks on Bitcoin and Bitcoin Cash.
- Support for Bitcoin Cash Testnet3 Network.
- Support for new Haskoin Wallet.
- Minikey decoding for Casascius coins.
- New tests for various networks and new features.
- Added `CHANGELOG.md` file.
- Support for SegWit addresses.
- Support for CashAddr addresses.

### Changed

- Use of hpack `package.yaml` file to auto-generate Cabal file.
- Removal of dependency version limits, relying on `stack.yaml` instead.
- Tests moved to `hspec`.
- New documentation.
- Updated `.gitignore`.
- Renamed network constants to use same style for BTC and BCH.
- Network constants must be passed explicitly.
- Target LTS Haskell 12.9.

### Removed

- Removed `.stylish-haskell.yaml` files.
- Removed old `haskoin-node` and `haskoin-wallet` packages from main repository.
- Removed support for non-strict signatures and related tests.
- Removed script evaluator and related tests.
