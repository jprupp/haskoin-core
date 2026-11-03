# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-11-03

### Added

- `connectBlock` and `connectBlocks` now check that a header carries the difficulty bits the chain requires, as `ContextualCheckBlockHeader` does in Bitcoin Core. `validBlock` takes the required bits as a new argument. Without this check a chain of headers mined at the minimum difficulty was accepted.
- `asertAnchor` finds the anchor block of the aserti3-2d algorithm for the chain that ends at a given block. `mtp` is now the median time past of the block itself, as in Bitcoin Core, instead of its parent's.
- `getVarIntList` and `putVarIntList` in `Haskoin.Network.Common` read and write lists with their `VarInt` count. A count above `maxListSize` (32 MiB, the `MAX_SIZE` of Bitcoin Core) fails the parse instead of wrapping around and reading an empty list. Blocks, Merkle blocks, `getblocks`, `getheaders`, `headers`, `inv`, `getdata`, `notfound` and `addr` messages use them.
- `genesisTx` in `Network` holds the coinbase transaction of the genesis block. `Haskoin.Transaction.Genesis` exports `mainnetGenesisTx`, `testnet4GenesisTx` and `genesisCoinbase`.
- `skipHeight` and `medianTime` are exported from `Haskoin.Block.Headers`.
- Tests for every function of the `Haskoin.Block` modules, with vectors from Bitcoin Core and from mainnet block 100000.

- PSBT version 2 (BIP 370) in `Haskoin.Transaction.Psbt`: a PSBT of version 2 is read and written as its maps, with the unsigned transaction its fields describe and the lock time they determine. The roles take both versions, and version 2 has its constructor (`addInput`, `addOutput`), its updater (`setInputSequence`), the flags of `PSBT_GLOBAL_TX_MODIFIABLE`, which the signer and the combiner keep as the spec and Bitcoin Core do, and conversion between the versions (`withVersion`). The test vectors of BIP 370 and files of Bitcoin Core 32.1 check it.
- `addrToBase58`, `addrToBech32` and `addrToCash` encode an address in one chosen format. `addrToBase58` gives the legacy form of a Bitcoin Cash address.
- Token-aware CashAddr addresses (types 2 and 3) can be paid. `addressToOutput`, `addressHash160` and `addressHash256` treat them like their plain P2PKH, P2SH and P2SH32 counterparts.
- `decodeSecKey` in `Haskoin.Crypto.Keys.Common` builds a secret key from 32 bytes and refuses zero and values at or above the curve order. `fromWif`, `fromMiniKey`, `xPrvImport`, `makeXPrvKey` and the binary form of `PrivateKey` use it. The `secKey` of secp256k1-haskell 1.7.0 only checks the length, so such keys used to import and then crash `derivePubKey` and `signMsg` with an error call.
- Derivation paths accept `h` and `H` as hardened markers, as Bitcoin Core does, so `m/84h/0h/0h` parses.
- Tests for BIP32 test vectors 4 and 5, for a BIP39 passphrase with accented letters, and for every function of the `Haskoin.Crypto` modules.
- The P2P messages added since 2016: `addrv2` and `sendaddrv2` (BIP 155) with `AddrV2`, `NetworkAddressV2` and conversions from and to `addr` entries; `feefilter` (BIP 133); `sendcmpct`, `cmpctblock`, `getblocktxn` and `blocktxn` (BIP 152) in `Haskoin.Network.CompactBlock`; `getcfilters`, `cfilter`, `getcfheaders`, `cfheaders`, `getcfcheckpt` and `cfcheckpt` (BIP 157) in `Haskoin.Network.BlockFilter`; `wtxidrelay` (BIP 339) and `sendtxrcncl` (BIP 330). The inventory types `InvCompactBlock` and `InvWTx`, and the service bits `nodeCompactFilters`, `nodeNetworkLimited` and `nodeP2PV2`.
- `maxMessageSize` in `Network` bounds the payload `getMessage` reads: 4,000,000 bytes on Bitcoin, as in Bitcoin Core, and twice the block size on Bitcoin Cash.
- `scriptPushData` lists the data elements a script pushes, as `GetOp` does in Bitcoin Core.
- `getVarIntBytes` and `putVarIntBytes` read and write bytes with their count, under the same limit as lists.
- Tests with fixed wire bytes for every message type, the sample `version`, `verack` and `addr` messages of the protocol documentation, and every function of the `Haskoin.Network` modules.

### Changed

- `buildMerkleRoot` returns `Either String MerkleRoot`. It fails for an empty list, which used to crash, and for a mutated tree in which two sibling nodes are identical (CVE-2012-2459). `extractMatches` rejects such a tree too, as `CPartialMerkleTree::TraverseAndExtract` does in Bitcoin Core, and reports why a partial tree is malformed.
- `buildMerkleRoot`, `buildPartialMerkle` and `calcHash` build the tree in linear time instead of quadratic. `decodeMerkleFlags` is linear too; it took a minute for 100 KB of flags, which a peer could send in a `merkleblock` message.
- `genesisBlock` no longer takes a `Ctx` and returns the right coinbase for every network. Bitcoin testnet4 has its own genesis coinbase, so `genesisBlock btcTest4` used to return a block whose transactions did not match its header.
- The `merkleroot` field of the JSON form of `BlockHeader` is in display order, like `prevblock` and the `getblockheader` RPC call of Bitcoin Core. It was in internal byte order.
- `hexToBlockHash` and the JSON parser of `BlockHeader` reject a hash that is not exactly 32 bytes. They used to accept longer input and drop the leading bytes.
- `computeAsertBits` takes the proof-of-work limit of the network as its first argument instead of using the mainnet limit.
- `connectBlocks` adds each header to the store as it passes, so a batch with a bad header keeps the headers before it and makes the last of them the best block when it has the most work.
- `Ord BlockNode` compares the height and then the header, so that it agrees with `Eq`, which compares the header.
- `appendBlocks` dates every block one target spacing after its parent, so the chains it mines pass the median time past rule.
- `blockLocatorNodes` steps back like `LocatorEntries` in Bitcoin Core and lists the genesis block once.
- `encodeCompact` raises an error for a number wider than 255 bytes instead of wrapping the exponent.
- `traverseAndBuild` and `traverseAndExtract` are no longer exported.
- `getMessage` consumes exactly one message. It used to leave the payload in the stream and let the payload parser read past the declared length, so bytes outside the checksum could end up in a message. It now checks the magic before reading the payload, refuses a payload above `maxMessageSize`, and accepts a payload on message types that carry none, as Bitcoin Core does.
- `VarInt` refuses an encoding longer than the value needs, as `ReadCompactSize` does in Bitcoin Core. A transaction with such an encoding used to parse and re-serialize to different bytes. `VarString` refuses a count above `maxListSize`.
- `MessageCommand` refuses a name with a byte outside printable ASCII or with a byte other than NUL after it, as Bitcoin Core does, and serializing a name longer than twelve bytes is an error instead of a silent truncation.
- The `extra` field of `Reject` is a `Maybe Hash256`. It was a `ByteString` that only round-tripped when empty or 32 bytes long.
- `Version` refuses a user agent longer than 256 bytes, as Bitcoin Core does.
- `BloomFilter` refuses a filter above 36000 bytes or 50 hash functions when parsing, as Bitcoin Core refuses such a `filterload`, and reads its bytes in one go instead of one at a time. `FilterAdd` refuses an element above 520 bytes. `BloomFlags` reads only the two low bits of its byte, as Bitcoin Core does.
- `bloomRelevantUpdate` matches the data pushed by every output script, standard or not, and inserts outpoints according to the flags, as `IsRelevantAndUpdate` does in Bitcoin Core. It used to raise an error for any transaction with a non-standard output, and for a matching output that was not pay-to-pubkey or pay-to-multisig under `BloomUpdateP2PubKeyOnly`. It returns `Just` the filter whenever an output matches, unchanged under `BloomUpdateNone`.
- `bloomInsert` and `bloomContains` treat a filter with zero hash functions as matching everything, as Bitcoin Core does. `bloomInsert` used to loop over 2^32 hash functions and `bloomContains` used to answer `False`. `bloomCreate` gives zero hash functions for zero elements.
- `bip34Block` in `Network` is split into `bip34Height` and `bip34Hash`, the hash being optional. `btcRegTest` activates BIP34, BIP65 and BIP66 at height 1, as Bitcoin Core regtest does; it had the heights of Bitcoin Cash Node regtest. `bchRegTest` has the 32 MB block size of Bitcoin Cash Node.
- `arbitraryBloomFilter` generates a `BloomFilter` with random bits instead of a tuple.
- Replace the PSBT module with `Haskoin.Transaction.Psbt`, which keeps every field of a PSBT, known or not, writes maps with their keys in order as Bitcoin Core does, refuses what breaks BIP 174 (duplicate keys, keys out of shape, bytes after the last map, other versions), and reads and writes the global xpub and proprietary fields. It still creates, combines, signs, finalizes and extracts. The `Haskoin.Transaction.Partial` module and its types are gone.
- `pubKeyWitnessAddr` and `pubKeyCompatWitnessAddr` now return `Maybe Address` and refuse uncompressed keys. BIP 143 makes witness spends with uncompressed keys non-standard, so coins sent to such an address could not be spent through the normal network.
- The `WitnessAddress` and `CashAddress` constructors are now patterns that can only match. Build these addresses with `witnessAddress` and `cashAddress`, which validate the version and payload and return the dedicated constructor when one exists. Every address now has a single representation, so equal addresses compare equal.
- `outputAddress` and `scriptToAddress` no longer report the P2PKH address of the key for a pay-to-public-key output. Such coins cannot be spent with the P2PKH input script, so the address was misleading.
- `convertBits` in `Haskoin.Util.Helpers` returns `Maybe [Word]` and fails on padding bits that are not zero, or that are wide enough to hold a whole input digit, when padding is not allowed.
- JSON encoding of an address that has no text form on the given network now fails with an error instead of writing `null`.
- `mnemonicToSeed` NFKD-normalises the sentence and the passphrase, as BIP39 requires and as Trezor, Electrum, python-mnemonic and bitcoinjs do. A passphrase with accented letters used to give a seed that no other wallet derives, so the funds could not be restored elsewhere. `fromMnemonic` normalises the sentence before looking up its words. This adds a dependency on `unicode-transforms`.
- `toMnemonic` accepts 16 to 32 bytes of entropy and `fromMnemonic` accepts sentences of 12, 15, 18, 21 or 24 words, the sizes BIP39 allows. Entropy of 4 to 12 bytes and of 36 to 64 bytes, and sentences of 3 to 9 and 27 to 48 words, were accepted before, and no other wallet reads them. A word that is not in the list is reported with the `fromMnemonic:` prefix.
- `xPrvImport` and `xPubImport` require a payload of exactly 78 bytes, as Bitcoin Core does. Trailing bytes and an uncompressed public key used to be accepted. They also refuse a key at depth 0 whose parent fingerprint or index is not zero, as BIP32 test vector 5 requires.
- `fromWif` refuses strings longer than 52 characters, and `xPrvImport` and `xPubImport` strings longer than 112, before decoding them. No valid key is longer, and the time to decode Base58 grows with the square of the length.
- `prvSubKey`, `pubSubKey` and `hardSubKey` throw `DerivationException` when the parent is at depth 255. The depth of the child used to wrap around to 0.
- Parsing a derivation path reads each index as an unbounded integer and accepts decimal digits only. `m/4294967296` used to wrap around to `m/0`, and hex, parenthesised and signed numbers were accepted.
- The JSON form of `Sig` is decoded with `decodeStrictSig`, like the binary form, so a high-S signature is refused by both.
- The `Read` instances of `Hash160`, `Hash256` and `Hash512`, and `textToFingerprint`, refuse hex of the wrong length, as the string literal instances already did. A two-byte hash could be read and then crash `signHash`.

### Fixed

- A block whose timestamp equals the median time past of its parent is rejected, as in Bitcoin Core. It used to be accepted.
- `connectBlocks` keeps the block that was seen first as the best block when a competing block has the same work and height, as `connectBlock` and Bitcoin Core do. It used to switch the best block to every competitor.
- `calcNextWork` and `computeTarget` measure the time span of a retarget period as a signed number. A period whose last block is dated before its first block used to wrap around to four times the target timespan instead of being limited to a quarter.
- `headerWork` returns zero for bits that are negative, overflow or encode a zero target, like `GetBlockProof` in Bitcoin Core. It used to divide by zero for bits `0x03800001`.
- The block version is compared as a signed number, as in Bitcoin Core, so versions with the top bit set are rejected once BIP34 is active.
- The Bitcoin Cash difficulty algorithms follow Bitcoin Cash Node: the minimum-difficulty rule of test networks applies to the ASERT algorithm and no longer applies to the EDA and DAA algorithms on mainnet, the EDA returns the bits of the last block without minimum difficulty on test networks, `getSuitableBlock` picks the same block as Bitcoin Cash Node when timestamps are equal, `computeTarget` no longer overshoots by one, the ASERT anchor is the first block whose own median time past reaches the activation time, and regtest never retargets.
- A PSBT of another version is refused by its version. The unsigned transaction was looked for first, and a PSBT of version 2 holds none.
- `addressBytes` returned a length-prefixed value for a generic CashAddr instead of the raw hash.
- Base58, Bech32 and CashAddr decoders accepted non-ASCII look-alike characters. Base58 truncated code points to one byte and Bech32 used Unicode case folding. All three now accept ASCII only, as the specifications require.
- `cashAddrDecode` accepted mixed-case strings, which the CashAddr specification rejects.
- CashAddr decoding accepted non-canonical strings whose padding bits were not zero, or that carried an extra group of padding, so several strings could stand for the same address.
- `textToAddr` decoded Base58 input of any length, with a cost growing with the square of the length. Strings longer than any valid address are now rejected first.
- Binary deserialization of an address now validates the witness version, the CashAddr type and the payload length, and checks the length prefix before converting it to an `Int`. Previously an invalid value could be read and later crash `addressToScript`.
- The Bech32 and bit conversion accumulators are masked so that they cannot overflow on long inputs.
- `encodeOutput` had no case for `PayScript32Hash` and crashed on it, so a P2SH32 address could not be turned into a script.
- The P2WSH test generator produced P2WPKH addresses.
- `fromWif` threw an exception on a Base58Check string with an empty payload, such as `3QJmnh`, also through the JSON parser of `PrivateKey`. It returns `Nothing` now.
- The JSON parser of `PublicKey` accepted bytes after the key.

## [1.4.0] - 2026-10-31

### Added

- Bitcoin testnet4 network (`btctest4`) with the BIP94 block storm and time warp rules.

### Changed

- Update DNS seeds to match Bitcoin Core and Bitcoin Cash Node. Drop the Bitcoin ABC seeds, which now serve eCash.
- This package now requires base16 2.0 and secp256k1-haskell 0.7.

### Fixed

- Compute the difficulty retarget in `nextPowWorkRequired` and `nextEdaWorkRequired`, which never reached their retarget branches.
- Fix the Bitcoin Cash DAA activation height, which had a typo (404031 instead of 504032).
- Start the DAA one block later on Bitcoin Cash testnet and testnet4, to match Bitcoin Cash Node.
- Fix the Bitcoin Cash ASERT half-life, which must be two days.

## [1.3.0] - 2026-08-12

### Changed

- Make script and address parsing more strict.
- Use smart constructors for addresses to avoid inconsistent or incorrect represtentations.

### Fixed

- Support Bitcoin Cash 256-bit pay-to-script-hash scripts and addresses.
- Make addresses of incorrect length invalid.
- Avoid decoding scripts as standard when hash or public key length incorrect.
- Fix secp256 library function names.

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
