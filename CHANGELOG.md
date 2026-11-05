# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Haskoin.Crypto.Keys.Slip39`: Shamir's secret-sharing for mnemonic codes, SLIP-0039, as a standalone module. `generateMnemonics` splits a master secret, encrypted with a passphrase, into share mnemonics under a two-level scheme of groups and members, and `combineMnemonics` rebuilds it from a threshold of them; `generateSharesWith` takes the identifier and the random values as arguments, so that a split can be reproduced. `encodeShare` and `decodeShare` read and write one share, with its checksum, padding and ranges checked as the specification requires; `encryptMasterSecret` and `decryptMasterSecret` are the passphrase step; `splitSecret`, `recoverSecret` and `interpolate` are the sharing over GF(256), and `rs1024Checksum` the checksum. The 45 vectors of the reference implementation, a share set of Sparrow's library, and split cases with fixed random values made by an independent Python implementation of the specification, `test/Haskoin/Crypto/Keys/slip39_verify.py`, check it. The word list is `data/slip39_wordlist.txt`, the file of the specification, and its SHA-256 is checked.

## [1.5.1] - 2026-11-04

### Fixed

- `nextAsertWorkRequired` evaluates the aserti3-2d formula at the parent of the new block, with the parent's timestamp and height, as `GetNextASERTWorkRequired` does in Bitcoin Cash Node. It used the new block's own timestamp and height, so the bits it required were wrong for every block that did not come exactly ten minutes after its parent. The bits check that 1.5.0 added to `connectBlocks` turned this into a rejected block on Bitcoin Cash mainnet at height 975899.

## [1.5.0] - 2026-11-03

### Added

- Taproot signing and verification, BIP 341 and BIP 342: `taprootSigHash` computes the digest a Taproot signature signs, for the key path and for a leaf of a script path; `taprootOutputSecKey` tweaks a secret key as `taprootOutputKey` tweaks its public key; `signTx` signs a `SigInput` of a Taproot output by its key path, with a key whose x-only public key is the output key or whose tweak without a script tree is, as a BIP 86 wallet spends, and `signTaprootInput` signs one input; `verifyStdTx` verifies key path spends, and script path spends whose leaf is a single key check. `TaprootSignature`, `encodeTaprootSig` and `decodeTaprootSig` are a Schnorr signature with its hash type, `isTaprootSigHash` tells the hash types a Taproot signature may use, and `sigHashDefault` is the default one. The key path vectors of BIP 341 and the BIP 86 vectors check them.
- The Taproot fields of PSBTs, BIP 371, in `Haskoin.Transaction.Psbt`: `tapKeySig`, `tapScriptSigs`, `tapLeafScripts`, `inputTapDerivations`, `inputTapInternalKey`, `inputTapMerkleRoot`, `outputTapInternalKey`, `outputTapTree` and `outputTapDerivations`, with their inserts. They are checked against the spec when a PSBT is read. `signPsbt` signs a Taproot coin by its key path when the input has its internal key, and by each leaf script that is a single key check; `finalizePsbt` finalizes both. The test vectors of BIP 371 check them.
- `tapTreeLeaves` and `tapTreeFromLeaves` in `Haskoin.Transaction.Taproot` convert a script tree to and from its leaves with their depth, the form of `PSBT_OUT_TAP_TREE`. `encodeControlBlock` and `decodeControlBlock` build and read a control block, which must be 33 bytes plus 32 per node with at most `maxControlBlockNodes` (128) nodes. `leafHash`, `keyParity` and `tapscriptLeafVersion` are exported.
- `txWitnessHash` in `Haskoin.Transaction.Common` is the witness transaction id of BIP 141. `txWeight` and `txVirtualSize` give the weight and the virtual size of a transaction, and `hasWitness` tells whether it has a witness.
- `InputKind` and `OutputKind` in `Haskoin.Transaction.Builder` name the kinds of inputs and outputs: pay-to-public-key, pay-to-public-key-hash with a compressed or an uncompressed key, pay-to-script-hash multisig, the native and nested SegWit kinds, Taproot, pay-to-script-hash of a 256-bit hash, and any other output script by its size. `guessTxWeight`, `guessTxSize` and `guessTxFee` estimate the weight, the virtual size and the fee of a transaction of those kinds, with `inputWeight` and `outputSize` per kind. The guess is an upper bound: it counts 72 bytes per signature, the one-byte empty witness stack of a legacy input in a transaction with a witness, and two bytes for each count of a multisig script above 16.
- `Signer` in `Haskoin.Transaction.Psbt` is a record: `keyOfRecord` gives the key a derivation record names, as before, and `keyOfHash` the key of a public key hash, so that `signPsbt` signs the coins whose keys it holds when the input has no derivation record. `keySigner` provides both, `xPrvSigner` the first.
- Tests for every function of the `Haskoin.Transaction` and `Haskoin.Util` modules, with the key path vectors of BIP 341, the vectors of BIP 86 and BIP 371, and literal sizes, ids and fee estimates.
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
- `pushOpData` gives the data that a push opcode puts on the stack, and `isMinimalPush` tells whether a push is in its shortest encoding, the rule of `CheckMinimalPush` in Bitcoin Core.
- `OP_CHECKSIGADD` is a pattern synonym for opcode 0xba, which `OP_CHECKDATASIG` also names, so a Tapscript can be written with the name of BIP 342.
- `NestedWitnessInput` is the input script of a P2SH-P2WPKH or P2SH-P2WSH output: a push of the witness output script. `decodeInput`, `encodeInput`, `inputAddress` and the signer use it, and `isNestedWitnessInput` tests for it. Such an input used to fail to decode.
- `maxMultisigKeys` is 20, the `MAX_PUBKEYS_PER_MULTISIG` of Bitcoin Core. `decodeOutput` reads a multisig output with 17 to 20 keys, whose counts are one-byte pushes, and `encodeOutput` writes one. Only 16 keys used to be supported.
- `decodePubKey` in `Haskoin.Crypto.Keys.Common` reads a public key from bytes that must hold the key and nothing else.
- Tests for every function of the `Haskoin.Script` modules, with literal vectors from BIP 67, BIP 143, BIP 173 and BIP 341.

### Changed

- `makeSignature`, and with it `signTx`, `signInput` and `signPsbt`, refuse to sign a legacy input with `SIGHASH_SINGLE` when the input has no output at its index. The digest of that case is the constant 1, which commits to nothing, so the signature would spend any other coin of the key wherever the same case comes up. `txSigHash` still computes that digest, as a node must to verify such signatures, and `verifyStdInput` still accepts them. A SegWit input is signed in that case, since the BIP 143 digest commits to the coin.
- `Signer` has a new field, `acceptedSigHashes`: the sighash types it signs with. `keySigner` and `xPrvSigner` set it to `defaultSigHashes`, which are `SIGHASH_DEFAULT` and `SIGHASH_ALL`. `signPsbt` refuses an input that asks for another type, as BIP 174 asks of a signer: the other types leave part of the transaction unsigned, and the PSBT comes from someone else. A PSBT asking for `SIGHASH_NONE` or `SIGHASH_SINGLE` used to be signed as asked. The fork id flag is not compared, since the network decides it.
- `PrivateKey` and `XPrvKey` show their secret as `<redacted>`, and no longer have a `Read` instance; nor does `XKey`. The derived instances printed the key, and for `XPrvKey` the chain code, so a value in a log or an error message gave the coins away. `toWif` and `xPrvExport` write a key out.
- `prvSubKey`, `pubSubKey`, `hardSubKey` and `cycleIndex` throw `DerivationException` for a child index with the hard bit set, like every other failure of a derivation. They used to call `error`.
- A transaction with no inputs whose next byte, the flags of BIP 144, is neither 0x00 nor 0x01 fails to parse with "Unknown transaction optional data", as in Bitcoin Core. Such bytes used to parse as a legacy transaction with no inputs that did not serialize back to the same bytes. A `Tx` string literal must hold the transaction and nothing else, as `DecodeHexTx` requires in Bitcoin Core.
- The documentation of `decodeBase58` and `decodeBase58Check` says that their cost grows with the square of the length and that callers must bound untrusted input. The decoders of the library bound it already.
- `taprootOutputKey` and `taprootScriptOutput` tweak the x-only internal key, as BIP 341 defines the output key. An internal key with an odd y coordinate used to be tweaked as a full point, which gave an output key and an address no other wallet derives from that key, and that a BIP 341 signer could not spend.
- `viewTaprootWitness` reads a witness in the order of BIP 341: the annex last, then the control block, then the script, then the stack. It used to read the control block and the script in the other order, and so decoded no real script path witness. `encodeTaprootWitness` writes the annex only when there is one; it used to append an empty item, which made the witness invalid. The control block of a `ScriptPathData` is a list of digests, and a control block of a wrong length is refused. `KeyPathSpend` carries the annex of a key path spend.
- `signPsbt` applies the checks of the BIP 174 signer. A coin known from `PSBT_IN_WITNESS_UTXO` alone is signed only with a witness signature, since the legacy digest does not commit to the amount; the previous transaction is used first, and a witness output that is not its output is refused. A sighash type no node accepts, or whose fork id flag does not fit the network, is refused instead of signed. A redeem script that does not hash to the coin, or a witness script that does not hash to the witness program, is refused. An input whose coin script is not standard is left alone instead of failing the PSBT.
- `finalizePsbt` takes the `Network` and verifies every signature it uses, against the digest of the coin and the sighash type of the input when it has one, as `PSBTInputSignedAndVerified` does in Bitcoin Core. A signature that does not verify, is not a signature, or uses another sighash type is refused. It used to finalize any bytes stored as a signature.
- `mergeTxs` leaves an input that no transaction signed as it is. It used to crash with `Prelude.head: empty list`.
- `chooseCoins` takes the kinds of the outputs and a fee rate per virtual byte, and estimates the fee from the `coinInputKind` of each coin, a new method of `Coin`. `chooseMSCoins`, `chooseMSCoinsSink`, `guessMSTxFee` and `guessMSSize` are gone, since the kind of input lives on the coin. The old estimate counted every input as pay-to-public-key-hash and charged bytes rather than virtual bytes, so a SegWit wallet overpaid fees by about 60 %.
- `hexToTxHash`, and the `Read`, string and JSON forms of `TxHash` and `OutPoint`, refuse hex that is not exactly 32 bytes. Longer hex used to be accepted with its leading bytes dropped.
- Transaction parsing bounds the counts of inputs, outputs, witness stacks and witness items by `maxListSize`, as `ReadCompactSize` does in Bitcoin Core; a count of 2^64 - 1 used to wrap around and read as zero. A transaction with the witness marker but no witness item is refused ("Superfluous witness record"), as Bitcoin Core refuses it. A transaction whose witness stacks are all empty is serialized without the marker, and `hasWitness` is false for it.
- `verifyStdTx` and `verifyStdInput` take the coins of every input, matched by outpoint, so that Taproot inputs can be verified. A witness on an input whose coin is not a witness program is refused, as `VerifyScript` refuses it in Bitcoin Core, and `verifyStdTx` refuses outputs that spend more than the coins hold.
- `nosigTxHash` removes the witness as well as the input scripts, so that it is the same before and after signing a SegWit input.
- `getBits` raises an error for input shorter than the bits asked, `getList` and `getLengthBytes` refuse a count that does not fit an `Int`, and `unmarshalLazy` returns `Either String a` instead of throwing.
- `setInputSequence` refuses to change the sequence of an input that is signed, since every signature commits to it.
- `WitnessProgram`, `WitnessProgramPKH`, `MAST`, `TaprootWitness` and `ScriptPathData` have `Show` and `Eq` instances.
- The package requires secp256k1-haskell 2.0.0, whose `normalizeSig` is total. `verifyHashSig` normalises the signature with it, and `isCanonicalHalfOrder` is its `isLowS`.
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
- `encodeOutput` returns `Either String Script`. It fails for a `PayMulSig` whose required count is not between 1 and its number of keys or that has more than 20 keys, and for a `PayWitness` whose version is 0 or above 16 or whose program is not 2 to 40 bytes long. Those values used to crash with an `error` call. `marshalPut` still fails with an `error` call for them, since it cannot report a failure.
- `txSigHash` and `txSigHashForkId` return `Either String Hash256`. They fail for an input index the transaction does not have. With `SIGHASH_ALL`, `txSigHash` used to return a digest over the transaction without any script code for such an index, and crash for the other hash types. `makeSignature` and `makeSigHash` return `Either` too.
- On a network with a fork id, `txSigHash` requires the `SIGHASH_FORKID` flag and `decodeTxSig` rejects a signature without it. `makeSignature` sets the flag, so `signTx bch` with a plain `sigHashAll` produces a signature the network accepts. It used to sign the legacy digest, which Bitcoin Cash has rejected since 2017.
- `isSigHashUnknown` is the test of `IsDefinedHashtypeSignature` in Bitcoin Core: after masking the `SIGHASH_ANYONECANPAY` and `SIGHASH_FORKID` bits, the hash type byte must be 1, 2 or 3. A byte such as 0x21 used to pass and be signed, although every node rejects it under `STRICTENC`.
- `opPushData` gives the minimal encoding of BIP 62: `OP_0` for the empty string, `OP_1` to `OP_16` for one byte from 1 to 16 and `OP_1NEGATE` for the byte 0x81. The empty push used to be an `OP_PUSHDATA` that serialized to the byte of `OP_0` but was not equal to it.
- `DataCarrier` holds the data of every push after `OP_RETURN`, as a list, since `TxoutType::NULL_DATA` of Bitcoin Core is `OP_RETURN` followed by any pushes. A bare `OP_RETURN`, several pushes and an empty push used to be "Non-standard output".
- `intToScriptOp` returns `Either String ScriptOp` instead of crashing outside 1 to 16. `scriptOpToInt` no longer serializes its argument, so it cannot crash on an `OP_PUSHDATA` whose payload does not fit its type.
- `sortMulSig` returns any output that is not a multisig unchanged instead of crashing.
- `decodeInput` reads the input of a pay-to-script-hash output as its redeem script requires. A multisig template with the redeem script and no signature yet, `OP_0 <redeem>`, is a `SpendMulSig []`, which `mergeTxs` used to reject. An input that does not fit its redeem script fails.
- The generators of `Haskoin.Util.Arbitrary.Script` produce pushes of every `PushDataType`, pushes that are not minimal, multisig outputs of up to 20 keys, data carriers with any number of pushes, nested witness inputs, and, on networks with a fork id, only hash types with the flag.

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
- `decodeOutput` matches the output templates on their exact bytes, as Bitcoin Core does. A script that wrote the hash of a P2PKH, P2SH, P2SH32 or witness output with `OP_PUSHDATA1` or a longer push used to decode as that output and give its address. By consensus such a script is not a P2SH or witness output at all, and anyone can spend it, so a wallet could credit a payment to its address that was not one.
- A public key pushed in a script or a witness must fill its push. A 65-byte item that starts with 0x02 or 0x03 used to parse as the 33-byte key it starts with, so `decodeOutput`, `decodeInput` and the witness decoders reported a key the script did not hold, and `verifyStdTx` accepted a P2PKH or P2WPKH spend whose key item carried 32 extra bytes, which no node accepts.
- `verifyStdInput` returns `False` for an input index the transaction does not have, and `parseExistingSigs` reads no witness signatures when the witness list is shorter than the input index. Both used to crash.

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
