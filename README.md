# Haskoin Core

Haskoin Core is a library of Bitcoin and Bitcoin Cash functions written in Haskell featuring:

- Hashing functions (SHA-256, RIPEMD-160)
- Base58 support
- CashAddr support
- Bech32 suport
- BIP32 extended key derivation and parsing (m/1'/2/3)
- BIP39 mnemonic keys
- SLIP39 Shamir secret-sharing of a master secret in mnemonic shares
- ECDSA secp256k1 cryptographic primitives
- Script parsing
- Building and signing of standard transactions (regular, multisig, p2sh, segwit)
- Parsing and manipulation of all Bitcoin and Bitcoin Cash protocol messages
- Bloom filters and partial merkle trees (used in SPV wallets)
- Comprehensive test suite

## Contributing

All code is formatted with [Ormolu](https://github.com/tweag/ormolu).
Convenience formatting script available at [scripts/format](scripts/format)
