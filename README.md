# Haskoin Core

[![CI](https://github.com/jprupp/haskoin-core/actions/workflows/ci.yml/badge.svg)](https://github.com/jprupp/haskoin-core/actions/workflows/ci.yml)
[![Hackage](https://img.shields.io/hackage/v/haskoin-core.svg)](https://hackage.haskell.org/package/haskoin-core)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jprupp/haskoin-core/blob/master/LICENSE)

Haskoin Core is a Bitcoin and Bitcoin Cash library for Haskell. It covers keys,
addresses, scripts, transactions, PSBTs, block headers and the peer-to-peer
message format.

It does no I/O of its own. It never opens a socket or writes a file. You can use
it in a wallet, a block explorer or a node, and bring your own networking and
storage.

- [API documentation](https://hackage.haskell.org/package/haskoin-core)
- [Changelog](https://github.com/jprupp/haskoin-core/blob/master/CHANGELOG.md)
- [Report a bug](https://github.com/jprupp/haskoin-core/issues)

## Contents

- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Concepts](#concepts)
- [Usage guide](#usage-guide)
- [Module overview](#module-overview)
- [Security notes](#security-notes)
- [Development](#development)
- [Related projects](#related-projects)
- [License](#license)

## Features

| Area         | What you get                                                                                                         |
| ------------ | -------------------------------------------------------------------------------------------------------------------- |
| Networks     | Bitcoin and Bitcoin Cash: mainnet, testnet3, testnet4 and regtest; Bitcoin testnet3 is deprecated                    |
| Keys         | secp256k1 keys, WIF, BIP-32 extended keys and paths, BIP-39 mnemonics, SLIP-39 Shamir shares                         |
| Signatures   | Deterministic ECDSA (RFC 6979) and BIP-340 Schnorr                                                                   |
| Addresses    | Base58, Bech32, Bech32m and CashAddr, including P2SH32 and the token-aware CashAddr types                            |
| Scripts      | Script parsing and serialization, standard templates, BIP-67 sorted multisig, the CashTokens prefix                  |
| Transactions | Building, signing and verifying P2PK, P2PKH, P2SH, multisig, P2WPKH, P2WSH, nested SegWit and Taproot key path spends |
| Wallet tools | Coin selection, and weight, size and fee estimates                                                                   |
| PSBT         | Versions 0 and 2, with the Taproot fields (BIP-174, BIP-370, BIP-371)                                                |
| Taproot      | Script trees, output keys, witnesses, control blocks and signature hashes (BIP-341, BIP-342)                         |
| Blocks       | Header validation, proof of work, the difficulty rules of both chains, Merkle trees and an in-memory header chain    |
| Peer-to-peer | Message encoding, including `addrv2`, compact blocks and compact filter messages, and BIP-37 Bloom filters           |
| Protocol     | State machines of how Bitcoin Core and Bitcoin Cash Node treat a peer, one per network                               |
| Testing      | QuickCheck generators for the library's types                                                                        |

### What is not included

- **Peer connections and chain sync.** Use
  [haskoin-node](https://github.com/jprupp/haskoin-node).
- **Address and transaction indexing.** Use
  [haskoin-store](https://github.com/jprupp/haskoin-store).
- **A script interpreter.** `verifyStdTx` recognises the standard templates. It
  is not a consensus check.
- **Signet, output descriptors, Miniscript and MuSig2.**
- **Signing with Schnorr signatures, `SIGHASH_UTXOS` and token outputs of
  Bitcoin Cash.** `judgeInputs` verifies a Schnorr signature, of one key
  or in a multisig, and the spend of a coin that holds tokens.
  Nothing here signs them, and `verifyStdTx` does not read them. The tokens
  of an output and its address are read: see [Bitcoin Cash](#bitcoin-cash).
- **The adaptive block size limit of Bitcoin Cash.** Bitcoin Cash Node raises
  its block size limit when blocks fill up, and takes a block message of twice
  that limit. The library has fixed numbers for a block of 32 MB:
  `maxBlockSize`, and `maxMessageSize` of 64,000,000 bytes. No block is near
  them today. When the limit of the chain rises, set larger numbers in your
  copy of the network: see [Peer-to-peer messages](#peer-to-peer-messages).
- **BIP-324 encrypted transport.**
- **BIP-39 word lists other than English.**

## Installation

### System library

Haskoin Core needs [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
0.2.0 or later, and `pkg-config` to find it.

```sh
# Debian and Ubuntu
sudo apt-get install libsecp256k1-dev pkg-config

# macOS with Homebrew
brew install secp256k1 pkg-config

# Nix
nix-shell -p secp256k1 pkg-config
```

Check what you have with `pkg-config --modversion libsecp256k1`. Debian 11 and
other older systems ship a version below 0.2.0. On those, build the library from
source and enable its recovery module with `./configure --enable-module-recovery`.

### Compiler

The library is tested with GHC 9.10 and 9.12. It cannot build below GHC 9.2,
because it uses `OverloadedRecordDot`.

### With Cabal

Add the packages to your `.cabal` file:

```cabal
build-depends:
    base
  , bytes
  , haskoin-core
  , text
```

You need `bytes` to serialize values with `runPutS` and `serialize`.

Run `cabal update` first. Haskoin Core needs a recent secp256k1-haskell, and a
stale package index makes the build fail with a dependency error.

### With Stack

Haskoin Core is not in Stackage, so add it to `stack.yaml` as an extra
dependency. Use the [latest version from Hackage](https://hackage.haskell.org/package/haskoin-core).

```yaml
resolver: nightly-2026-10-28
extra-deps:
  - haskoin-core-3.0.0
  - base16-2.0
  - secp256k1-haskell-3.0.0
```

## Quick start

This program turns a mnemonic into the first receiving address of a BIP-84
wallet.

```haskell
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Data.Text (Text)
import Haskoin

-- This is the public BIP-39 test mnemonic. Never send coins to it.
mnemonic :: Text
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

main :: IO ()
main = do
  seed <- either fail pure (mnemonicToSeed "" mnemonic)
  let master = makeXPrvKey seed
      -- Hardened steps need the private key.
      account = derivePath ("m/84'/0'/0'" :: HardPath) master
      accountPub = deriveXPubKey account
      -- The remaining steps only need the public key.
      receiving = derivePubPath ("m/0" :: SoftPath) accountPub
      (address, _publicKey) = deriveWitnessAddr receiving 0
  print (addrToText btc address)
  -- => Just "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
```

The address is the one that [BIP-84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)
publishes for this mnemonic.

## Concepts

A few conventions apply across the whole library. Reading this section first
will save you time.

### No context to pass

Signing, verifying and deriving keys are pure functions that take only their
data. The secp256k1 context that libsecp256k1 needs is created and randomized
once, inside secp256k1-haskell, the first time a function uses it, and is
shared by every thread. Up to version 1.6 most functions took that context as
an argument. From 2.0.0 none does, and there is nothing to create or pass around.

### Networks

A `Network` is a record of the parameters of one chain. Functions that depend on
the chain take one as their first argument.

| Value        | Chain                 | Name for `netByName` |
| ------------ | --------------------- | -------------------- |
| `btc`        | Bitcoin mainnet       | `btc`                |
| `btcTest`    | Bitcoin testnet3      | `btctest`            |
| `btcTest4`   | Bitcoin testnet4      | `btctest4`           |
| `btcRegTest` | Bitcoin regtest       | `btcreg`             |
| `bch`        | Bitcoin Cash mainnet  | `bch`                |
| `bchTest3`   | Bitcoin Cash testnet3 | `bchtest3`           |
| `bchTest4`   | Bitcoin Cash testnet4 | `bchtest4`           |
| `bchRegTest` | Bitcoin Cash regtest  | `bchreg`             |

`btcTest`, Bitcoin testnet3, is deprecated: using it gives a warning when you
compile. Bitcoin Core has deprecated testnet3 in favour of testnet4, whose BIP94
rules stop the storms of minimum-difficulty blocks that made testnet3 hard to
use, and will remove it. Use `btcTest4` instead. `btcTest` is still in `allNets`
and `netByName` still finds it, so that code reading old testnet3 data keeps
working; a later major version will remove it. `bchTest3` is not deprecated:
Bitcoin Cash Node still supports testnet3.

The Bitcoin Cash testnet3 carries its number, `bchTest3` and `bchtest3`, as
testnet4 does, so that neither looks like the default test network of Bitcoin
Cash. Before 3.0.0 it was `bchTest` and `bchtest`. Its CashAddr prefix is still
`bchtest`, which every Bitcoin Cash test network shares.

The constants of each network are those of the reference node: Bitcoin Core
32.1 for Bitcoin and Bitcoin Cash Node 29.2.0 for Bitcoin Cash. Bitcoin Core
has no checkpoints, so the Bitcoin networks have none either.

### Record fields

The library is built with `NoFieldSelectors`, so record fields are not functions.
Turn on `OverloadedRecordDot` in your modules and read fields with a dot.

```haskell
print btc.defaultPort
-- => 8333
print (map (.value) btc.genesisTx.outputs)
-- => [5000000000]
```

Many records share field names. `Tx` and `Psbt` both have `inputs`, for example.
To update such a field, import the module qualified and name the field through
it, as the [PSBT example](#psbt) does.

### Errors

Functions that can fail return `Maybe` or `Either String`. The examples below
turn those into `IO` failures with `either fail pure`.

Hashes, paths and public keys have `IsString` instances, so you can write them as
literals. Those instances call `error` on bad input. For input you do not control,
use `hexToTxHash`, `hexToBlockHash`, `parsePath` and `textToAddr`.

### Amounts

Amounts are satoshi, as `Word64`.

### Serialization

Most types have `Serial` instances, from the
[bytes](https://hackage.haskell.org/package/bytes) package, and also `Binary` and
`Serialize` instances, and `ToJSON` and `FromJSON` instances for JSON. Public
keys, signatures and output scripts are among them. The encoding of some types
depends on the network, so they have `Marshal` or `MarshalJSON` instances
instead, which take the `Network` as their first argument. `XPrvKey`,
`XPubKey`, `PrivateKey`, `Address`, `TxSignature` and `ScriptInput` are those.

| Task                | Encode                     | Decode                       |
| ------------------- | -------------------------- | ---------------------------- |
| Binary              | `runPutS (serialize x)`    | `runGetS deserialize bytes`  |
| Binary, whole input | `encodeSerial x`           | `decodeSerial bytes`         |
| Binary with network | `marshal net x`            | `unmarshal net bytes`        |
| Hexadecimal         | `encodeHex bytes`          | `decodeHex text`             |
| JSON                | `toJSON x`                 | `parseJSON value`            |
| JSON with network   | `marshalJSON net x`        | `unmarshalJSON net json`     |

`decodeSerial` and `unmarshal` fail when bytes are left over after the value,
and `decodeTx` does the same for a transaction. `runGetS deserialize` reads a
value from the start of the bytes and ignores the rest. `encodeSerial x` gives
the bytes of `runPutS (serialize x)`.

**Which one is fast.** All of these give the same bytes, but not at the same
price. `encodeSerial` and `decodeSerial` are the cheapest: they write into one
buffer of the exact length and read the bytes where they are. `decode` of
cereal reads the same way for transactions, their inputs and outputs,
outpoints, block headers, blocks and addresses, and `encode` writes the same
way for transactions, inputs, headers and blocks. But `encode` first allocates
a buffer of 4 kB whatever the value, which is most of the cost of a value of a
few bytes. `runPutS (serialize x)` and `runGetS deserialize` go through the
builder and the continuations of cereal one field at a time, and are several
times slower on a transaction: keep them for a value that is part of a longer
stream.

The module `Haskoin.Util.Direct` has the functions behind this, for your own
types: give `encodeDirect`, `decodeDirect` or `sizeDirect` a serializer written
for any `MonadPut` or `MonadGet`, or write the `put` and `get` of a cereal
instance with `putDirect` and `getDirect`. They give what cereal gives, errors
included.

```haskell
instance Serialize Record where
  put record = putDirect (serialize record)
  get = getDirect deserialize
```

Mark the `serialize` and `deserialize` of such a type `INLINEABLE`, so that GHC
can compile them for the monads of that module.

### Hash byte order

`TxHash` and `BlockHash` show as hexadecimal in reversed byte order. This is the
form that Bitcoin Core and block explorers display, so you can paste those values
straight in. The serialized bytes keep the internal order.

## Usage guide

The examples below are fragments of `main` in this program. Paste one in place of
the comment to run it. If an example starts with `import` lines, add them to the
top of the file. A `-- =>` comment shows what the line above it prints.

```haskell
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Data.Bytes.Put (runPutS)
import Data.Bytes.Serial (serialize)
import Haskoin

main :: IO ()
main = do
  -- This is the public BIP-39 test mnemonic. Never send coins to it.
  seed <-
    either fail pure $
      mnemonicToSeed "" "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  let master = makeXPrvKey seed
  -- Paste an example here.
  pure ()
```

### Mnemonics

Generate entropy with a cryptographic source. This example uses the
[entropy](https://hackage.haskell.org/package/entropy) package.

```haskell
import qualified Data.ByteString as B
import System.Entropy (getEntropy)

-- 16 bytes of entropy give 12 words. 32 bytes give 24 words.
entropy <- getEntropy 16
words12 <- either fail pure (toMnemonic entropy)

-- The passphrase is optional. Use "" for none.
newSeed <- either fail pure (mnemonicToSeed "my passphrase" words12)
print (B.length newSeed)
-- => 64
```

`mnemonicToSeed` checks the words and the checksum. `fromMnemonic` gives the
entropy back.

### Keys and signatures

```haskell
-- A secret key is 32 bytes. decodeSecKey refuses zero and values at or above
-- the curve order.
bytes <- maybe (fail "bad hex") pure (decodeHex "0000000000000000000000000000000000000000000000000000000000000001")
secret <- maybe (fail "bad key") pure (decodeSecKey bytes)

-- True asks for the compressed form of the public key.
let private = wrapSecKey True secret
    public = derivePublicKey private

print private
-- => PrivateKey {key = <redacted>, compress = True}
print (toWif btc private)
-- => "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
print (encodeHex (encodeSerial public))
-- => "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
print (addrToText btc (pubKeyAddr public))
-- => Just "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

-- Sign and verify a hash.
let digest = doubleSHA256 bytes
    signature = signHash secret digest
print (verifyHashSig digest signature public.point)
-- => True
```

`fromWif btc text` reads a WIF key back. `Haskoin` also re-exports the
[secp256k1-haskell](https://hackage.haskell.org/package/secp256k1-haskell) API,
which has the Schnorr functions such as `signSchnorr` and `verifySchnorr`.

### Extended keys

Paths have three types. A `HardPath` has only hardened steps. A `SoftPath` has
only normal steps, which a public key can derive. A `DerivPath` can mix both.
Hardened steps can be written `'`, `h` or `H`.

```haskell
let account = derivePath ("m/84'/0'/0'" :: HardPath) master
    accountPub = deriveXPubKey account

print (xPubExport btc accountPub)
-- => "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"

-- The account's public key derives all its receiving addresses.
let receiving = derivePubPath ("m/0" :: SoftPath) accountPub
    addresses = [address | (address, _, _) <- deriveWitnessAddrs receiving 0]
print (map (addrToText btc) (take 2 addresses))
-- => [Just "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",Just "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"]
```

Pick the address function that matches the wallet standard:

| Standard | Address type        | Path          | One address               | Endless list               |
| -------- | ------------------- | ------------- | ------------------------- | -------------------------- |
| BIP-44   | P2PKH               | `m/44'/0'/0'` | `deriveAddr`              | `deriveAddrs`              |
| BIP-49   | P2WPKH nested in P2SH | `m/49'/0'/0'` | `deriveCompatWitnessAddr` | `deriveCompatWitnessAddrs` |
| BIP-84   | P2WPKH              | `m/84'/0'/0'` | `deriveWitnessAddr`       | `deriveWitnessAddrs`       |
| BIP-86   | Taproot             | `m/86'/0'/0'` | See [Taproot](#taproot)   |                            |

The two functions of BIP-49 take the network first, and return `Nothing` on a
network without SegWit: `deriveCompatWitnessAddr btc account 0`. A nested
SegWit address is an ordinary P2SH address, so it has a text on Bitcoin Cash
too, and there any miner can take the coins sent to it. See
[Bitcoin Cash](#bitcoin-cash).

`xPrvExport` and `xPubExport` write the standard `xprv` and `xpub` forms.
`xPrvImport` and `xPubImport` read them back. The `ypub` and `zpub` prefixes are
not supported.

`parsePath` reads a path at run time. It returns a `ParsedPath`, which
`applyPath` applies to a private or a public key.

### Addresses

```haskell
let text = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

print (textToAddr btc text)
-- => Just (WitnessPubKeyAddress {hash160 = "c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2"})

-- An address of another network is refused.
print (textToAddr bch text)
-- => Nothing

-- The output script an address pays to.
print (encodeHex <$> (addressToScriptBS =<< textToAddr btc text))
-- => Just "0014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2"
```

`textToAddr` and `addrToText` handle every address format of a network.
`addrToBase58`, `addrToBech32` and `addrToCash` each write one chosen format.

### Scripts

`ScriptOutput` is a standard output script. Its constructors are `PayPK`,
`PayPKHash`, `PayMulSig`, `PayScriptHash`, `PayWitnessPKHash`,
`PayWitnessScriptHash`, `PayWitness`, `PayScript32Hash` and `DataCarrier`.

```haskell
let keyA = wrapPubKey True "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8"
    keyB = wrapPubKey True "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f"
    -- BIP-67 sorts the keys, so that all signers build the same script.
    multisig = sortMulSig (PayMulSig [keyA, keyB] 2)

-- The address can fail, because a P2SH redeem script holds at most 520 bytes.
print (addrToText btc <$> payToScriptAddress multisig)
-- => Right (Just "39bgKC7RFbpoCRbtD5KEdkYKtNyhpsNa3Z")

-- OP_RETURN is 6a, then the push of 5 bytes, then "hello".
print (encodeHex (encodeSerial (DataCarrier ["hello"])))
-- => "6a0568656c6c6f"

-- Read the same bytes back.
script <- maybe (fail "bad hex") pure (decodeHex "6a0568656c6c6f")
print (decodeSerial script :: Either String ScriptOutput)
-- => Right (DataCarrier {pushes = ["hello"]})
```

Decoding a `ScriptOutput` fails for a script that matches no template. A `Script`
holds any script, as a list of `ScriptOp` values, so use that type for the others.
`encodeOutput` and `decodeOutput` convert between `ScriptOutput` and `Script`.

The templates are matched on their exact bytes: every hash and key is a direct
push. A multisig script whose keys are pushed with `OP_PUSHDATA1` is therefore
not a `PayMulSig`, although Bitcoin Core calls it `multisig`. A signature covers
the bytes of the script of its coin, and a `ScriptOutput` does not keep them, so
a `PayMulSig` must stand for one script only. The library does not sign or
verify the spend of such a coin. Nodes of Bitcoin do not relay that spend, and
on Bitcoin Cash no block holds it.

#### Opcodes on the two chains

Bitcoin and Bitcoin Cash split a script into opcodes in the same way, so one
`ScriptOp` type serves both, with one constructor per byte, and a script parses
without a network. The chains name twelve bytes differently. Their constructors
carry the Bitcoin name, but 0xba carries the Bitcoin Cash name
`OP_CHECKDATASIG`, and each has a pattern synonym for the other name:

| Byte       | Bitcoin                            | Bitcoin Cash                           |
| ---------- | ---------------------------------- | -------------------------------------- |
| 0x65, 0x66 | `OP_VERIF`, `OP_VERNOTIF`          | `OP_BEGIN`, `OP_UNTIL`                 |
| 0x7f–0x81  | `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT` | `OP_SPLIT`, `OP_NUM2BIN`, `OP_BIN2NUM` |
| 0x89, 0x8a | `OP_RESERVED1`, `OP_RESERVED2`     | `OP_DEFINE`, `OP_INVOKE`               |
| 0x8d, 0x8e | `OP_2MUL`, `OP_2DIV`               | `OP_LSHIFTNUM`, `OP_RSHIFTNUM`         |
| 0x98, 0x99 | `OP_LSHIFT`, `OP_RSHIFT`           | `OP_LSHIFTBIN`, `OP_RSHIFTBIN`         |
| 0xba       | `OP_CHECKSIGADD`                   | `OP_CHECKDATASIG`                      |

Both names build and match the same value: `OP_SPLIT == OP_SUBSTR`. The
opcodes that only Bitcoin Cash defines have constructors of their own:
`OP_CHECKDATASIGVERIFY` and `OP_REVERSEBYTES`, the introspection opcodes from
`OP_INPUTINDEX` (0xc0) to `OP_OUTPUTBYTECODE` (0xcd), the token opcodes from
`OP_UTXOTOKENCATEGORY` (0xce) to `OP_OUTPUTTOKENAMOUNT` (0xd3), and the
reserved `OP_RESERVED3` and `OP_RESERVED4`.

`Show` prints the constructor. To show an opcode as a chain names it, use
`opName`, which gives the name that the reference node of the network prints:

```haskell
print (opName btc OP_SUBSTR, opName bch OP_SUBSTR)
-- => ("OP_SUBSTR","OP_SPLIT")
```

Which opcodes a chain enables, and from which block, is a matter for a script
interpreter, which this library does not have.

`payToWitnessScriptAddress` and `payToNestedScriptAddress` give the P2WSH and
P2SH-P2WSH addresses of a script. `payToNestedScriptAddress` takes the network
first, and fails on a network without SegWit.

The three functions return `Either`. A P2SH redeem script holds at most 520
bytes, which is a multisig of 15 compressed keys. On Bitcoin, coins sent to a
longer script could never be spent, so `payToScriptAddress` refuses it. A P2WSH
script holds up to 10,000 bytes, so a multisig of 16 to 20 keys needs P2WSH.
The limit of 520 bytes is the same on Bitcoin Cash, where it is stricter than
the network: see [Bitcoin Cash](#bitcoin-cash).

### Building and signing a transaction

```haskell
-- The key at m/84'/0'/0'/0/0 and its address.
let key = derivePath ("m/84'/0'/0'/0/0" :: DerivPath) master
    address = xPubWitnessAddr (deriveXPubKey key)

-- The coin to spend, and the transaction that paid it. Both are made up.
-- The coin holds 100,000 satoshi.
coinScript <- maybe (fail "no output script") pure (addressToOutput address)
let amount = 100000
    fundingInput = TxIn (OutPoint "1111111111111111111111111111111111111111111111111111111111111111" 0) "" 0xffffffff
    funding = Tx 2 [fundingInput] [TxOut amount (encodeSerial coinScript)] [] 0
    coin = OutPoint (txHash funding) 0

-- Pay 99,000 satoshi. The 1,000 satoshi left over are the fee.
unsigned <-
  either fail pure $
    buildAddrTx btc [coin] [("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", 99000)]

-- SigInput describes the coin. The last argument is the redeem script.
signed <-
  either fail pure $
    signTx btc unsigned [SigInput coinScript amount coin sigHashAll Nothing] [key.key]

print (verifyStdTx btc signed [(coinScript, amount, coin)])
-- => True
print (txVirtualSize signed)
-- => 110
print (txHash signed)
-- => "9a079e6b7939909415b7b027a19e093bc539dac5a2ed50df8beb0942ec821848"

-- This hexadecimal form is what you broadcast.
print (encodeHex (runPutS (serialize signed)))
-- => "01000000000101..."
```

`buildAddrTx` adds no change output. Whatever the outputs do not spend goes to the
miners as a fee, so list your change output along with the payments.

Fill in `SigInput` and pick the signing function by the type of the coin:

| Coin             | `script`               | `redeem`                 | Function              |
| ---------------- | ---------------------- | ------------------------ | --------------------- |
| P2PKH            | `PayPKHash`            | `Nothing`                | `signTx`              |
| P2SH multisig    | `PayScriptHash`        | `Just (PayMulSig ks m)`  | `signTx`              |
| P2WPKH           | `PayWitnessPKHash`     | `Nothing`                | `signTx`              |
| P2WSH            | `PayWitnessScriptHash` | `Just script`            | `signTx`              |
| P2SH-P2WPKH      | `PayWitnessPKHash`     | `Nothing`                | `signNestedWitnessTx` |
| P2SH-P2WSH       | `PayWitnessScriptHash` | `Just script`            | `signNestedWitnessTx` |
| Taproot key path | `PayWitness 1 key`     | `Nothing`                | `signTx`              |

For multisig, each signer can call `signTx` with their own keys. `mergeTxs`
combines the results for legacy inputs. For SegWit multisig, use a [PSBT](#psbt).

The digest of a SegWit version 0 input, and of every input on Bitcoin Cash, is
the one of BIP 143. It holds three hashes over all the inputs and all the
outputs of the transaction, which are the same for every input. `signTx`,
`mergeTxs`, `verifyStdTx`, `judgeInputs`, `signPsbt` and `finalizePsbt` compute
them once for a transaction. Code that computes the digests itself does the same:
`txSigHashes` takes the transaction once, and `txSigHashForkIdWith` gives the
digest of one input. `txSigHashForkId` computes the three hashes at each call,
so it is the function for one digest.

```haskell
-- The hashes that the digests of the inputs share, computed once.
let hashes = txSigHashes unsigned

print $ do
  -- The script code of a P2WPKH coin is the P2PKH script of its key.
  code <- case coinScript of
    PayWitnessPKHash keyHash -> encodeOutput (PayPKHash keyHash)
    _ -> Left "not a P2WPKH coin"
  mapM (\i -> txSigHashForkIdWith btc hashes code amount i sigHashAll) [0 .. length unsigned.inputs - 1]
-- => Right ["06c4ab89d1c30437a3f32fb31384d908bc9902f09a294dffd54a820942d8152d"]
```

`makeSignatureWith` signs one input from the same hashes. The legacy digest of
Bitcoin shares nothing between the inputs: it hashes a copy of the whole
transaction for each of them, by its design.

### Judging a transaction without a node

A full node checks a transaction by running the script of every coin that
it spends. This library runs no scripts. But most of what makes a
transaction bad needs none, and `Haskoin.Transaction.Judge`, a separate
import, checks that: a coin that is not there, more paid than is held, a
lock time that has not passed, tokens of Bitcoin Cash made from nothing,
and the signature of a coin locked to one key, which is most coins.

It answers two questions:

| Function | The question | What it holds the transaction to |
| --- | --- | --- |
| `judge` | Somebody wants to publish it: would a node relay it? | The rules of the chain, and the rules of relay that have not changed in years |
| `judgeRelayed` | A peer sent it: could a node have taken it? | Only what no node takes, whatever its policy |

Both give a `Refusal` with the reason, or `Nothing` when every signature
was verified, or the first input that could not be judged:

```haskell
import Haskoin
import Haskoin.Transaction.Judge (Refusal, judgeRelayed)

-- The outputs that the inputs of the transaction spend, in order.
relayed :: Tx -> [TxOut] -> Either Refusal (Maybe Int)
relayed = judgeRelayed btc
```

An input that could not be judged is no reason to refuse. It spends a coin
locked by a script, which is a normal thing to do, and only a full node can
say whether it is good. What to do with such a transaction depends on who
vouches for it: from a node of your own it is as good as any, and from a
stranger it is a claim that nothing here supports.

This is not validation. A transaction that passes may still be one that no
node takes: a script that fails, a fee too low, a conflict with another
transaction.

### Coin selection and fees

Make your coin type an instance of `Coin`. The library then picks coins and
estimates the fee from the kinds of the inputs and outputs. This example is a
complete program.

```haskell
{-# LANGUAGE OverloadedRecordDot #-}

module Main (main) where

import Data.Word (Word64)
import Haskoin

newtype Utxo = Utxo {amount :: Word64}

instance Coin Utxo where
  coinValue utxo = utxo.amount
  coinInputKind _ = InputWitnessPKHash

main :: IO ()
main = do
  let outputs = [OutputWitnessPKHash, OutputWitnessPKHash]
      coins = [Utxo 50000, Utxo 120000, Utxo 300000]
      target = 150000
      feeRate = 5

  -- The size is in virtual bytes, and the fee rate in satoshi per virtual byte.
  print (guessTxSize [InputWitnessPKHash] outputs)
  -- => 141
  print (guessTxFee feeRate [InputWitnessPKHash] outputs)
  -- => Right 705

  -- The result is the chosen coins and the change to send back to yourself.
  -- True keeps searching the rest of the list for a smaller solution.
  case chooseCoins target feeRate outputs True coins of
    Left err -> putStrLn err
    Right (chosen, change) -> print (map (.amount) chosen, change)
  -- => ([120000,50000],18955)
```

The change here is 170,000 - 150,000 - 1,045, where 1,045 is the fee for two
inputs and two outputs.

`chooseCoins` takes the coins in the order of the list, so sort them the way you
prefer first. The output list must include the change output.

The change can be smaller than the `dustThreshold` of its output kind, down to
one satoshi. Nodes do not relay such an output, so leave that change to the fee.
`chooseCoins` refuses a selection above `maxStandardTxWeight`, which nodes do not
relay either.

The estimates are upper bounds, because they count 72 bytes per signature. The
kinds include `InputPKHash`, `InputWitnessPKHash` and `InputTaproot`. See
`InputKind` and `OutputKind` in `Haskoin.Transaction.Builder` for all of them.

### PSBT

Use a PSBT when several parties or devices sign a transaction. This example
continues the one in [Building and signing](#building-and-signing-a-transaction).

```haskell
-- Continues the example above.
import qualified Haskoin.Transaction.Psbt as Psbt

-- Creator: start from the unsigned transaction.
let created = psbtOf unsigned

-- Updater: attach the transaction that paid each coin. The signer checks the
-- amount of the coin against it.
    updated = created {Psbt.inputs = map (insertNonWitnessUtxo funding) created.inputs}

-- This base64 text is what you pass to the signers.
let shared = encodePsbtBase64 updated

-- Signer: read the text, and sign every input the keys can sign.
received <- either fail pure (decodePsbtBase64 shared)
signedPsbt <- either fail pure (signPsbt btc (keySigner key.key) received)

-- Finalizer and extractor: check the signatures and build the transaction.
finalized <- either fail pure (finalizePsbt btc signedPsbt)
extracted <- either fail pure (psbtTransaction finalized)

-- RFC 6979 signatures are deterministic, so this is the same transaction.
print (extracted == signed)
-- => True
```

Some other useful functions:

- `xPrvSigner` signs from an extended private key, following the derivation
  records of the inputs.
- `combinePsbt` merges the copies that different signers return.
- `signPsbt` and `finalizePsbt` take one input at a time, as BIP 174 and Bitcoin
  Core do. `signPsbt` signs the inputs that the signer holds a key for. It leaves
  as it is an input that it cannot or may not sign, so each party can sign before
  the others have added their coins and scripts. It keeps the signatures that an
  input already has. To see what was signed, compare the inputs before and after.
- `signPsbt` refuses a whole PSBT for a sighash type only: a type that the signer
  does not accept, as BIP 174 asks, or a signature already on an input that is of
  another type than the one the input is signed with, as in Bitcoin Core.
- A Taproot signature commits to the coin of every input, so `signPsbt` leaves
  every Taproot input unsigned until each input has its coin, as Bitcoin Core
  does.
- `finalizePsbt` finalizes the inputs that are ready and leaves the others as
  they are. It builds the one final script that Bitcoin Core would build, and
  verifies the signatures that this script uses.
- `decodePsbt` checks the fields of BIP 174, BIP 370, BIP 371 and BIP 373. It
  keeps the hash preimages and the MuSig2 fields, and nothing here signs with
  them. A PSBT written here and the same PSBT written by Bitcoin Core can differ
  in the order of their keys, which BIP 174 leaves open: each side reads the
  other.
- `insertWitnessUtxo` attaches a coin without the transaction that paid it. That
  is enough for a Taproot coin. For a SegWit version 0 coin, the amount is then a
  claim that the signature does not cover for the other inputs, and a signer can
  be led to burn coins as fee (CVE-2020-14199). `keySigner` and `xPrvSigner`
  therefore leave such a coin unsigned. Set `requirePreviousTx = False` on the
  `Signer` to sign it.
- `psbtFee` and `inputCoins` give the fee and the coins as the signer checks
  them. Show those to the user, not amounts read from the fields yourself.
- `psbtTransaction` refuses a PSBT whose inputs are not all final.
  `psbtPartialTransaction` gives the transaction of a PSBT that is still being
  signed.
- `insertInputRedeemScript` and `insertInputWitnessScript` attach the scripts of
  P2SH and P2WSH coins.
- `withVersion Version2` converts a PSBT to version 2. `addInput` and `addOutput`
  then extend it.

### Taproot

```haskell
let key = derivePath ("m/86'/0'/0'/0/0" :: DerivPath) master
    internalKey = (deriveXPubKey key).key

-- Nothing means that the output has no script tree.
output <- either fail pure (taprootScriptOutput (TaprootOutput internalKey Nothing))

print (addrToText btc =<< outputAddress btc output)
-- => Just "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"

-- Spend a made-up coin of 100,000 satoshi by its key path.
let coin = OutPoint "1111111111111111111111111111111111111111111111111111111111111111" 0
    unsigned = buildTx [coin] [(output, 99000)]

signed <-
  either fail pure $
    signTx btc unsigned [SigInput output 100000 coin sigHashDefault Nothing] [key.key]

print (verifyStdTx btc signed [(output, 100000, coin)])
-- => True
```

The signature commits to every coin the transaction spends. `signTx` therefore
needs a `SigInput` for every input of a Taproot transaction.

To commit to scripts, pass a `MAST` in place of `Nothing`. `signTx` only signs key
path spends. `signPsbt` also signs a script path when the leaf is a single key
check, `<key> OP_CHECKSIG`. For other scripts, build the witness yourself with
`taprootSigHash` and `encodeTaprootWitness`.

`taprootSigHash` hashes every input and every output of the transaction, so it
is the function for one digest. For the digest of each input, or for several
digests of one input, take the hashes that they share once with
`taprootTxHashes`, and each digest with `taprootSigHashWith`:

```haskell
-- The outputs that the inputs spend, one for each input and in their order.
let spent = [TxOut 100000 (encodeSerial output)]

print $ do
  hashes <- taprootTxHashes unsigned spent
  mapM (\i -> taprootSigHashWith hashes i sigHashDefault Nothing Nothing) [0 .. length spent - 1]
-- => Right ["bc2a6f20493e9377e4214f713ff3168c3eec0e8d07c1c18f3d9756df8602ef6c"]
```

`signTx`, `verifyStdTx`, `judgeInputs`, `signPsbt` and `finalizePsbt` do this
themselves: they hash the inputs and the outputs of a transaction once for all
its Taproot inputs.

`checkTapTree` tells whether every leaf of a tree can be spent. A leaf can be at
most 128 levels deep, and its version must be one that BIP 341 allows.
`taprootOutputKey` and `taprootScriptOutput` give `Left` for a tree that it
refuses, so that no address is made for a leaf that can never be spent. Bitcoin
Core builds no output for a tree deeper than 128 either.

### SLIP-39 secret sharing

[SLIP-39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) splits a
secret into mnemonic shares, and a threshold of shares rebuilds it. It is
available from version 1.6.0. The `Haskoin` module does not re-export it, so
import it yourself.

```haskell
import qualified Haskoin.Crypto.Keys.Slip39 as Slip39

-- One group of 3 members, of which 2 rebuild the secret.
let scheme = Slip39.Scheme 1 [(2, 3)]
    -- A secret has at least 16 bytes, and an even number of them.
    -- Use random bytes in practice.
    secret = "0123456789abcdef"

-- True makes the shares extendable. 1 sets the cost of the encryption.
groups <- either fail pure =<< Slip39.generateMnemonics scheme True 1 "passphrase" secret
let shares = concat groups

print (length shares)
-- => 3
print (Slip39.combineMnemonics "passphrase" (take 2 shares))
-- => Right "0123456789abcdef"
print (Slip39.combineMnemonics "passphrase" (take 1 shares))
-- => Left "Group 0 has 1 share, but its member threshold is 2"
```

A wrong passphrase is not an error. It returns a different secret, as the
specification requires. The passphrase must be printable ASCII, which the
specification requires too. A SLIP-39 share is not a BIP-39 mnemonic, and one
cannot be converted into the other.

`Scheme` can also describe two levels. For example, `Scheme 2 [(1, 1), (2, 3),
(3, 5)]` needs two of the three groups, each with its own member threshold.

### Bitcoin Cash

Pass `bch` wherever the examples above pass `btc`. A few things differ.

```haskell
-- The BIP-44 coin type of Bitcoin Cash is 145.
let key = derivePath ("m/44'/145'/0'/0/0" :: DerivPath) master
    address = xPubAddr (deriveXPubKey key)

-- addrToText writes CashAddr on Bitcoin Cash.
print (addrToText bch address)
-- => Just "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6"
print (addrToBase58 bch address)
-- => Just "1mW6fDEMjKrDHvLvoEsaeLxSCzZBf3Bfg"

-- textToAddr reads both forms.
print ((== Just address) (textToAddr bch "1mW6fDEMjKrDHvLvoEsaeLxSCzZBf3Bfg"))
-- => True

-- SegWit addresses do not exist on Bitcoin Cash.
print (addrToText bch (xPubWitnessAddr (deriveXPubKey key)))
-- => Nothing

-- Nor do the nested ones, which the library refuses to make there.
print (xPubCompatWitnessAddr bch (deriveXPubKey key))
-- => Nothing
```

A nested SegWit address (P2SH-P2WPKH or P2SH-P2WSH) is an ordinary P2SH
address, so it has a valid text on Bitcoin Cash, and a payer can send coins to
it. Bitcoin Cash has no witness. A block there may spend such coins with the
witness program alone, without a signature, and nodes do not relay that spend:
any miner can take the coins, and the owner cannot spend them without a miner.
This is why `pubKeyCompatWitnessAddr`, `p2shP2wpkhAddr`,
`payToNestedScriptAddress`, `xPubCompatWitnessAddr`, `deriveCompatWitnessAddr`
and `deriveCompatWitnessAddrs` take the network, and give no address where it
has no SegWit.

`addrToBase58` writes the legacy form of a P2SH32 address too, and `textToAddr`
reads it, as Bitcoin Cash Node does: the version byte of a script address and
the 32 bytes of the hash, 50 or 51 characters. Software that knows only the
legacy addresses of 20 bytes refuses that text. Prefer CashAddr.

A P2SH redeem script holds at most 520 bytes in this library, on every network.
Bitcoin Cash spends a redeem script of up to 9,997 bytes since May 2025, so the
library is stricter than the network there: `payToScriptAddress`, `toP2SH` and
`deriveMSAddr` give no address for a longer script, such as a multisig of 16 to
20 keys, `signTx` and `signPsbt` do not sign its coins, and `verifyStdTx` does
not verify a spend of them. The refusal loses no coins: it is the safe side of
one limit for every chain.

`signTx` sets the fork id flag of the signature hash when the network needs it.
Pass `sigHashAll` as usual.

Bitcoin Cash applies to every block three rules of encoding that Bitcoin
applies only to the transactions it relays: the S of an ECDSA signature is low,
a key is compressed or uncompressed, and an input script pushes each item by
the shortest push that holds it. A node of Bitcoin Cash drops the peer that
sends it a transaction that breaks one. `verifyStdTx` and `judgeInputs` verify
no input that breaks one, on any network. `decodeStrictSig`,
`verifyHashSig` and `importPubKey` follow the consensus of Bitcoin, and take
more than a block of Bitcoin Cash can hold: to verify a signature of Bitcoin
Cash with them, check `isCanonicalHalfOrder` too, and read the key with
`decodePubKey`.

On Bitcoin Cash a signature of 64 bytes before its hash type byte is a Schnorr
signature, also when its bytes are the DER form of an ECDSA signature that
verifies. Such a signature is rare by accident, and a computer makes one on
purpose in a minute. `decodeTxSig` refuses that length on the Bitcoin Cash
networks, so `decodeInput` and `verifyStdTx` do not take it for an ECDSA
signature, and `judgeInputs` reads it as a Schnorr signature. `decodeStrictSig`
reads it: with that function, check `isCashSchnorrLength` too. `signTx` does
not hand out such a signature. When one comes out, which the specification of
Bitcoin Cash gives one chance in 2^49, it fails and says to change the
transaction and sign again.

#### CashTokens

An output of Bitcoin Cash can hold tokens (CHIP-2022-02). They are written at
the front of the script field of the output, before the locking script, as a
token prefix that starts with the byte `0xef`. `splitTokenData` reads the
prefix into a `TokenData`, with the category, the fungible amount and the
non-fungible token, and gives back the locking script after it.
`encodeTokenPrefix` writes the prefix. `scriptToAddressBS` takes the prefix off
by itself on the Bitcoin Cash networks; on Bitcoin `0xef` is no prefix, and
such a script has no address.

```haskell
-- Output 4 of transaction e3abdbdc…f5a809 holds 110,830 tokens on a P2PKH script.
field <-
  maybe (fail "bad hex") pure . decodeHex $
    "ef2c06f3b2565d0818a8e41f58beff5918d5dbdc64b11ee8ad474e499751cde07f10feeeb00100\
    \76a9146e0810ceea13412b73feb41566a3d2d0ce54e10188ac"

-- The address is that of the locking script, in its plain form.
let address = either error id (scriptToAddressBS bch field)
print (addrToText bch address)
-- => Just "bitcoincash:qphqsyxwagf5z2mnl66p2e4r6tgvu48pqyhmvay0uy"

-- The token-aware form of the same address, for a wallet that handles tokens.
print (addrToText bch =<< tokenAwareAddress address)
-- => Just "bitcoincash:zphqsyxwagf5z2mnl66p2e4r6tgvu48pqys3lr2frh"

-- The tokens.
let tokens = either error fst (splitTokenData field)
print (fmap (.amount) tokens)
-- => Just 110830
print (fmap (.category) tokens)
-- => Just "7fe0cd5197494e47ade81eb164dcdbd51859ffbe581fe4a818085d56b2f3062c"
```

Why the plain form: a token-aware CashAddr (type 2 for P2PKH, 3 for P2SH and
P2SH32) locks coins with the same script as the plain one. It only tells a
sender that the receiver will not burn tokens by spending them as plain coins.
A wallet receives coins with and without tokens at the same script, so an index
that used the token-aware form for outputs with tokens would split the history
and the balance of one address in two. Bitcoin Cash Node shows the plain form
too, with the tokens beside it. Use `tokenAwareAddress` to show or hand out the
token-aware form, and `plainAddress` to turn a token-aware address that a user
gives back into the address that `scriptToAddressBS` returns.

The other side of that choice: nothing in the address says that an output
holds tokens. A server that lists the unspent outputs of an address must give
the tokens of each one too, from `splitTokenData`, so that a wallet can leave
them out. A wallet that spends such an output as a plain coin burns its tokens,
or signs without the token prefix and has the transaction refused. Nothing in
this library signs these outputs.

Before 3.0.0 these outputs had no address. An index of addresses built with an
older version left them out, and must be rebuilt, or have them added, before it
runs with 3.0.0. Otherwise spending one of them takes from a balance an amount
that was never added to it.

What is not checked: the rules that need the whole transaction, such as the
category being an input of it and the amounts adding up, and the limit on the
length of a commitment, which is a validation rule that has changed between
network upgrades.

### Blocks and headers

```haskell
print (headerHash btc.genesisHeader)
-- => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
print (isValidPOW btc btc.genesisHeader)
-- => True

-- 3.125 BTC since the halving at this height.
print (computeSubsidy btc 840000)
-- => 312500000
```

`connectBlocks` validates headers and adds them to a chain. This covers proof of
work, difficulty, timestamps, versions and checkpoints. It runs in any monad with
a `BlockHeaders` instance. `StateT HeaderMemory` is the in-memory one: it keeps
every header under its block hash, in about 300 bytes each on a main network.
Write your own instance to keep headers in a database, and key it by the whole
hash too. A key made of a part of the hash lets a peer replace a stored header
with another one, where proof of work is cheap.

Give `connectBlocks` all the headers of a `headers` message at once rather than
one by one with `connectBlock`. On Bitcoin Cash the difficulty depends on an
anchor block far down the chain. On mainnet and testnet4 the `Network` record
holds that block (`asertAnchorBlock`), as Bitcoin Cash Node does, and finding
it is a walk down the chain: about 80 reads at height 100,000, and about 75 on
mainnet today. On other networks, such as regtest, it is a binary search of
about 1,500 reads at height 100,000.
`connectBlocks` finds it once for the whole run, so either way it pays this
cost once rather than for each header.

The emergency difficulty rule of Bitcoin Cash (EDA) starts at `edaHeight`, the
block of the fork of August 2017, and the retarget rule of Bitcoin applies
below it. This is what the UAHF specification says, and it is the rule under
which those blocks were mined. Bitcoin Cash Node applies the EDA to every block
below the DAA. Both accept the real chains. They differ only on a made-up chain
that leaves the real one below the fork, where the library asks for more work,
since the EDA only ever asks for less. A `Network` of your own with
`edaHeight = Just 1` follows the node at every height.

On such a network a rule of Bitcoin Cash can have no answer for a header: the
DAA needs a parent at or above the retarget interval and at height 147 at
least (`daaFirstParent`), and the EDA needs six blocks below the parent.
Bitcoin Cash Node stops on an assertion there. `connectBlocks` refuses the
header with the reason, as `Left`. The eight networks of the library never
reach those cases.

Once the best block has the `minimumChainWork` of the network, a fork with less
work is refused. Below that work nothing bounds the side chains a peer can send,
so a node that is still syncing should not keep headers from a peer it does not
trust.

This example needs the [mtl](https://hackage.haskell.org/package/mtl) package.

```haskell
import Control.Monad.State.Strict (runStateT)

-- Mine three regtest headers on top of the genesis block.
let net = btcRegTest
    headers = appendBlocks net 7 net.genesisHeader 3
    now = net.genesisHeader.timestamp + 3600

(result, chain) <- runStateT (connectBlocks net now headers) (initialChain net)
nodes <- either fail pure result

-- The nodes come back with the highest one first.
print (map (.height) nodes)
-- => [3,2,1]
print chain.best.height
-- => 3
```

`buildMerkleRoot` and `buildPartialMerkle` compute Merkle trees.
`extractMatches` checks a partial tree from a `merkleblock` message against its
Merkle root. The header and the number of transactions are claims of the sender,
which the caller must check.

### Peer-to-peer messages

The library encodes and decodes messages. Moving the bytes is up to you.

```haskell
import Data.Bytes.Get (runGetS)

let bytes = runPutS (putMessage btc MVerAck)

print (encodeHex bytes)
-- => "f9beb4d976657261636b000000000000000000005df6e0e2"
print (runGetS (getMessage btc) bytes)
-- => Right MVerAck
```

`getMessage` checks the network magic and the checksum, and bounds the payload by
the `maxPayloadSize` of its command. Read the 24-byte `MessageHeader` first to
learn how many more bytes to take from the socket, and refuse a length above
`maxPayloadSize net command` before you read them.

Where the two reference nodes read a message in different ways, `getMessage`
reads it as the node of the network does:

- A `sendcmpct` whose first byte is neither 0 nor 1 fails on Bitcoin. BIP 152
  allows only those two values, and Bitcoin Core disconnects the peer that
  sends another one. On Bitcoin Cash any byte but 0 means "announce", as in
  Bitcoin Cash Node.
- A position in a compact block message has 16 bits on Bitcoin and 32 bits on
  Bitcoin Cash.
- A message that carries a block may have 4,000,000 bytes on Bitcoin and
  64,000,000 on Bitcoin Cash. The second number is fixed in the library, and
  the node works it out from a block size limit that can grow. To read larger
  blocks, pass your own copy of the network:

  ```haskell
  let larger = bch {maxMessageSize = 128000000, maxBlockSize = 64000000}
  ```

A `reject` is read whatever its code. `RejectCode` holds the byte, and the
eight codes that BIP 61 names are patterns, such as `RejectDust`. A match on
them needs a last case for the other bytes:

```haskell
let why code = case code of
      RejectDust -> "an output is too small"
      RejectInsufficientFee -> "the fee is too low"
      _ -> "refused: " <> show code

print (map why [RejectDust, RejectCode 0x44])
-- => ["an output is too small","refused: RejectCode 68"]
```

`Message` has a constructor for each message type. `bloomCreate`, `bloomInsert`
and `bloomContains` build BIP-37 filters for `filterload`.

A node that serves such a client tests a transaction that it relays with
`bloomRelevantUpdate`, and the transactions of a block with
`bloomRelevantBlock`. The second gives one flag for each transaction, and the
filter as the block left it, which the node keeps for the peer.

```haskell
-- The key that the first block of Bitcoin pays to.
let key =
      fromJust . decodeHex $
        "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61de\
        \b649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
    wanted = bloomInsert (bloomCreate 10 0.0001 0 BloomUpdateP2PubKeyOnly) key
    block = genesisBlock btc
    (flags, after) = bloomRelevantBlock btc wanted block.txs

print flags
-- => [True]
-- The filter now holds the outpoint of the output that pays to the key, so
-- the transaction that spends it will match too.
print (after == wanted)
-- => False
-- A merkleblock message is built from the flags.
print (fst (buildPartialMerkle (zip (map txHash block.txs) flags)))
-- => [True]
```

Both functions take the network, because Bitcoin Cash Node does not match as
Bitcoin Core does. A block of Bitcoin Cash holds its transactions in the order
of their ids, so a transaction may stand before the one it spends. The node
reads the outputs of the whole block first and the inputs after, and
`bloomRelevantBlock` does the same. A fold of `bloomRelevantUpdate` over such a
block misses that transaction: use it for one transaction, not for a block. On
Bitcoin Cash the tokens that an output carries in front of its locking script
are not matched, and the bare multisig that `BloomUpdateP2PubKeyOnly` follows
has at most 16 keys, each a direct push, where Bitcoin takes 20 keys pushed in
any way.

`bloomCreate` is total. A count of 0 or less, or a rate of 1 or more, gives the
filter of no bytes, which matches everything. A rate of 0 or less gives the
largest filter.

### Protocol machines

The messages are half of the protocol. The other half is what a node does with
them: which messages it drops before the handshake, which ones cost the peer
its connection or its address, when it pings and how long it waits, what a
whitelisted peer may do. No BIP says it; the code of the reference nodes does.
`Haskoin.Network.Protocol` translates that code into pure state machines, one
per network: Bitcoin Core 32.1 for the Bitcoin networks and Bitcoin Cash Node
29.2.0 for the Bitcoin Cash networks. A program that talks to these nodes can
use them to know what the node will do, and its tests can use them as an
oracle.

A machine models how the node treats one peer. `start` opens a connection from
a `Setup` (who opened it, the peer's permissions, its address network), and
`step` feeds it one input: a message, a framing error, a tick of the clock, or
news from the rest of the node. It returns what the node did, and each
`Effect` carries a `Cite` of the upstream file and line that decides it. The
machine reads nothing on its own: an `Env` gives the time and the answers about
the chain and the mempool.

```haskell
import qualified Data.Set as Set
import Haskoin
import Haskoin.Network.Protocol

let -- A peer that connects to the node, with no permissions.
    setup =
      Setup
        { connectionType = Inbound,
          permissions = Set.empty,
          peerNetwork = AddrIPv4,
          peerIsLocal = False,
          transport = TransportV1,
          openedAt = seconds 1700000000,
          seed = 42
        }
    -- A node that has only the genesis block of its network.
    envOf net =
      let info =
            BlockInfo
              { hash = headerHash net.genesisHeader,
                height = 0,
                status = HaveData,
                inActiveChain = True,
                work = 0,
                time = net.genesisHeader.timestamp
              }
       in defaultEnv info (genesisBlock net) (seconds 1700000001)
    -- The peer sends verack before version.
    tryIt net =
      snd (step (envOf net) (start (machine net) setup) (Receive MVerAck))

print (map (.action) (tryIt btc))
-- => [Ignore]
print (map (.action) (tryIt bch))
-- => [Misbehave 10]
print (map (.because) (tryIt bch))
-- => [Cite {file = "src/net_processing.cpp", line = 2311, reason = "missing-version"}]
```

Bitcoin Core drops the early `verack`; Bitcoin Cash Node adds 10 to the peer's
ban score, so ten such messages get its address discouraged. The report in
[`doc/protocol`](doc/protocol/README.md) describes the protocol of both nodes
in prose, with the same references, and lists where they differ. It changes
with the machines: `scripts/protocol-cites.sh` prints every citation next to
the upstream line it names, which is how both are brought to a new release.

What the machines leave out: validation, the chain and the mempool, which come
from the `Env`; decisions that span peers, such as which peer to download a
block from, which come in as notifications; and bytes, since a machine sees
whole messages.

When `getMessage` refuses the payload of a message, pass the machine
`BadFrame (BadPayload command payload)`. A node reads some payloads that the
parser refuses, and the bytes let a machine answer as its node does. The
Bitcoin Core machine does this for a `sendcmpct` whose first byte is neither 0
nor 1: Bitcoin Core discourages the address of the peer and disconnects, where
it only drops another message that it cannot read.

## Module overview

`import Haskoin` brings in everything below except the modules marked as
separate. It exports many short names, so you may prefer to import only the
modules you need, or to import it qualified.

| Module                        | Contents                                                             |
| ----------------------------- | -------------------------------------------------------------------- |
| `Haskoin.Address`             | Address types and Base58, Bech32 and CashAddr encoding               |
| `Haskoin.Block`               | Block types, header chain, validation, difficulty and Merkle trees   |
| `Haskoin.Crypto`              | Hashes, keys, signatures and the `Crypto.Secp256k1` API              |
| `Haskoin.Crypto.Keys.Slip39`  | SLIP-39 secret sharing (separate import)                             |
| `Haskoin.Network`             | Network constants, P2P messages, Bloom filters                       |
| `Haskoin.Network.Protocol`    | State machines of the reference nodes' protocol (separate import)    |
| `Haskoin.Script`              | Scripts, standard templates, signature hashes and CashTokens         |
| `Haskoin.Transaction`         | Transaction types, builder, signing, SegWit, Taproot and PSBT        |
| `Haskoin.Transaction.Judge`   | What can be said of a transaction without a node (separate import)   |
| `Haskoin.Util`                | Hexadecimal helpers, `Marshal` and small utilities                   |
| `Haskoin.Util.Direct`         | Serializers run straight on a buffer (separate import)               |
| `Haskoin.Util.Arbitrary`      | QuickCheck generators such as `arbitraryTx` (separate import)        |

## Security notes

Bugs in code that handles keys can lose money. Try your program on regtest or a
test network before you use it on mainnet.

- **Randomness.** Create keys and mnemonics with a cryptographic source, such as
  `getEntropy` from the entropy package. Never use `System.Random`.
- **Secrets in logs.** `PrivateKey` and `XPrvKey` show as `<redacted>` and have no
  `Read` instance. `toWif` and `xPrvExport` write a key out on purpose. A bare
  `SecKey`, such as the `key` field of a `PrivateKey`, shows as
  `SecKey <redacted>` too, since secp256k1-haskell 3.0.0. The
  errors of `fromMnemonic` and `mnemonicToSeed` name the position of a bad word,
  never the word.
- **Secrets in memory.** Keys live in the GHC heap. The library cannot wipe them,
  and the garbage collector can copy them.
- **Review before you sign.** `signPsbt` checks that a PSBT is sound, but not that
  it pays who you expect. Show the outputs and `psbtFee` to the user first. By
  default the signer wants the previous transaction of every SegWit version 0
  coin, because an amount in a witness output alone is a claim.
- **Signature hash types.** By default `signPsbt` signs only `SIGHASH_ALL` and
  `SIGHASH_DEFAULT`, because the other types leave part of the transaction
  unsigned. To accept others, set `acceptedSigHashes` on the `Signer`.
- **Verification.** `verifyStdTx` checks the signatures of the standard templates,
  and that outputs do not exceed inputs. It is not a script interpreter and does
  not apply every consensus rule. It answers `True` only for inputs in a form
  that Bitcoin Core relays. It answers `False` for a script that it does not
  read, and for an input that a block may hold and that nodes do not relay: a
  signature with a high S, a key in the hybrid form, an input script with a
  push longer than its data needs, a SegWit input signed with an uncompressed
  key and a Taproot input with an annex. `True` is still no promise that nodes
  relay the transaction: the rules on the whole transaction, such as its size,
  its fee and its outputs, are not looked at. `judgeInputs` tells a forged
  input from one that is left to a node.
- **Untrusted text.** The cost of `decodeBase58` and `decodeBase58Check` grows
  with the square of the input length. Limit the length of input you pass to them
  directly. The address and key decoders of the library already do.
  `cash32decode` reads data of any length by design, and holds hundreds of
  bytes for each character: limit its input too.

## Development

```sh
git clone https://github.com/jprupp/haskoin-core.git
cd haskoin-core

stack build                                         # build the library
stack test                                          # run all the tests
stack test --test-arguments='--match "Slip39"'      # run the tests of one module
stack haddock --no-haddock-deps                     # build the API documentation
```

`cabal build` and `cabal test` work too. On NixOS, or with `stack --nix`, the
`nix` section of `stack.yaml` provides libsecp256k1.

These commands build the library as it is released, with optimisation, which
takes minutes. For the time between two commits there is a faster loop:
`haskell-dev`, a script of [jprupp/tools](https://github.com/jprupp/tools).
Clone that repository once and put its folder on your `PATH`, for example in
`~/.bashrc`; a terminal opened before the change needs `source ~/.bashrc`.

```sh
git clone https://github.com/jprupp/tools.git ~/Source/tools
echo 'export PATH="$HOME/Source/tools:$PATH"' >> ~/.bashrc
```

Then run it from the top folder of haskoin-core:

```sh
haskell-dev test                                # build, then run all the tests
haskell-dev test Psbt                           # the specs with Psbt in their module name
haskell-dev test Psbt Block                     # the specs of several modules
haskell-dev test --match "/Haskoin.Block/asert/"  # one path, in one process
haskell-dev test --seed 12345                   # run a failure again
haskell-dev test --jobs 4                       # fewer processes, to save memory
haskell-dev build                               # build without optimisation
haskell-dev docs                                # build the documentation and check its comments
```

`test` builds first, so a separate `build` is not needed. A clean build takes
about 30 seconds, and a run of all the tests 5 to 10, against minutes for
`stack test`. The tests run in several processes at once, and
`haskell-dev.toml` tells the script which spec modules are slow, so that it
shares them between the processes. When a test fails, the output gives the
seed: run the test again alone with `--seed` and `--match` on its path, which
prints the usual output of hspec.

Do not mix the two kinds of build in one
folder. When no source has changed, Stack does not see that the flags have,
and keeps the objects of the other build: a plain `stack build` right after
`haskell-dev build` gives a library without optimisation. Only what runs from
this folder uses it, such as the tests: a package that depends on haskoin-core
builds its own copy. After the next change to a source, everything compiles
again. Never time the library with `haskell-dev`: see [Benchmarks](#benchmarks).

`package.yaml` is the source of the package description. Change it rather than
`haskoin-core.cabal`, which [hpack](https://github.com/sol/hpack) generates. Stack
regenerates the file whenever it builds.

The tests are in `test/` and use [hspec](https://hspec.github.io/). The test
vectors from the BIPs, Bitcoin Core and other implementations are in `data/`.

Some tests check the library against a node of Bitcoin Core 32.1 on regtest:
the library signs the PSBTs that Bitcoin Core makes, for every kind of coin,
and Bitcoin Core accepts the transactions; twelve wallets sign a PSBT of nine
coins, and the library must combine, finalize and extract it as Bitcoin Core
does. They need rootless [Podman](https://podman.io/) on Linux: each group of
these tests starts a node of its own in a container, through
[podman-test](https://github.com/jprupp/podman-test), so test processes that
run at once share nothing. The first run builds the image of the node, which
downloads Ubuntu and Bitcoin Core and takes a minute or two; after that a node
starts in a few seconds. Without Podman these tests are pending, and say why;
set `PODMAN_TEST_SKIP` to leave them out on purpose. The image and the RPC
client are in `test/BitcoinCore.hs`.

`data/psbt_complex_core32.json` comes from such a node. To make a new one, run
the tests with the path of the file in `HASKOIN_COMPLEX_PSBT`, and format it
with `jq .` as the other files of `data/` are:

```sh
HASKOIN_COMPLEX_PSBT=/tmp/complex.json haskell-dev test --match "sign as the tests run"
```

### Benchmarks

The benchmarks are in `bench/Bench.hs` and use
[tasty-bench](https://hackage.haskell.org/package/tasty-bench). They time the
functions that a server calls for every input and output it shows: hex,
`scriptToAddressBS`, the text of an address, the JSON of a transaction, and
Base58. The group `serial` times the binary encoding of hashes, outpoints,
transactions, headers, blocks and addresses, written and read through cereal,
through `runPutS` and `runGetS`, and through `encodeSerial` and `decodeSerial`,
and the hashing of transactions and headers. The group `headers` times
`connectBlocks` on a batch of 2,000 headers, the most that a `headers` message
holds, on top of a Bitcoin Cash chain of 100,000 that uses the aserti3-2d
difficulty rule, the case where a node syncing headers spends its time.

```sh
stack bench                                                 # at -O1, as the package builds by default
stack bench --ghc-options -O2                               # at -O2
stack bench --benchmark-arguments '-p hexBuilder'           # one group
stack bench --benchmark-arguments '-p /All.serial/'         # the binary encodings
stack bench --benchmark-arguments '--csv before.csv'        # keep the timings
stack bench --benchmark-arguments '--baseline before.csv'   # compare with them
```

Each line shows the memory allocated next to the time. The time of an encoder
of a few bytes is mostly the time it takes to allocate, and the memory does
not move from one run to the next as the time does, so compare that first.

Run them at both levels. Most users build this package at `-O1`, so a change
that is only faster at `-O2` is not faster for them. Stack does not always
rebuild when only `--ghc-options` changes: add `--force-dirty` if the numbers
of the two levels look the same.

Most functions are timed next to a copy of what haskoin-core 1.6.0 did, kept
in the benchmark as a reference. The reference is the line `as in 1.6.0`, and
the function of the library is the line `now`, which ends with its time as a
multiple of the reference:

```
encodeHex
  250 B
    as in 1.6.0:                                           OK
      680  ns ±  55 ns
    now:                                                   OK
      310  ns ±  20 ns, 0.46x
```

Below `1.00x` the library is faster than the reference. `hexBuilder` and
`hexEncoding` are the same code as their reference, so their lines show how
much the timings move by themselves on your machine: about a tenth either way
on a desktop with other programs open. A line that stays above `1.00x` by
more than that, at either level, is a regression: fix it, or say in the
changelog why it is worth it.

Quote a timing in the changelog or in the documentation only with the level it
was measured at, and only after running it here. The entries of 1.6.3 and
1.6.4 in the changelog quoted timings that did not hold at `-O1`, and one that
did not hold at either level, which is why this suite exists.

A reference is a copy of the old code compiled into the benchmark, not the old
library. To time an old release itself, check out its tag, copy `bench/` and
the `benchmarks` section of `package.yaml` into it, and give
`scriptToAddressBS` and the functions around it the `Ctx` argument that
releases before 2.0.0 take.

### Contributing

Pull requests are welcome.

- Format the code with [Ormolu](https://github.com/tweag/ormolu).
  `haskell-format`, from [jprupp/tools](https://github.com/jprupp/tools),
  does this for every Haskell file in the repository.
- Add tests for the behaviour you change.
- Describe the change under `[Unreleased]` in `CHANGELOG.md`. The file follows
  [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and versions follow
  [Semantic Versioning](https://semver.org/).

## Related projects

- [haskoin-node](https://github.com/jprupp/haskoin-node) connects to peers and
  syncs headers and blocks.
- [haskoin-store](https://github.com/jprupp/haskoin-store) indexes the block chain
  and serves it over a REST API.
- [secp256k1-haskell](https://github.com/jprupp/secp256k1-haskell) is the binding
  to libsecp256k1 that this library uses.

## License

Haskoin Core is released under the
[MIT License](https://github.com/jprupp/haskoin-core/blob/master/LICENSE).
