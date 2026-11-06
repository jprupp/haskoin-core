#!/usr/bin/env python3
"""An independent check of the SLIP-39 test data, written from the
specification alone, without the reference implementation or the Haskell
module. Run it from the root of haskoin-core:

    python3 -I test/Haskoin/Crypto/Keys/slip39_verify.py

It checks that:

- data/slip39_wordlist.txt is the word list of the specification: 1024
  words, the SHA-256 of the file as published, sorted, 4 to 8 letters,
  distinct four-letter prefixes.
- Every case of data/slip39_vectors.json, the vectors of the reference
  implementation, gives the master secret stated, or is refused when none is
  stated, and that the master secret derives the BIP-32 key stated.
- Every case of data/slip39_split.json gives the shares stated when split
  with the random values stated, and that every threshold of those shares
  rebuilds the master secret. With --write, the file is written from the
  cases defined below instead; the Haskell tests take their literal shares
  from it.

With --reference, the reference implementation (the shamir_mnemonic package)
is also run over the split cases, with its source of random bytes replaying
the values of the case, and over the vectors.

The field arithmetic here multiplies by shifting and reducing, and the
mnemonic is packed as a string of bits, so that neither shares its method
with the Haskell module, which uses logarithm tables and integers.
"""

import hashlib
import hmac
import itertools
import json
import os
import sys

DATA = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "data")

WORDLIST_SHA256 = "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"


class Refused(Exception):
    """A mnemonic or a set of shares the specification refuses."""


# --- The field GF(256), bytes as polynomials modulo x^8 + x^4 + x^3 + x + 1 ---


def gf_mul(a, b):
    product = 0
    while b:
        if b & 1:
            product ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return product


def gf_pow(a, n):
    result = 1
    for _ in range(n):
        result = gf_mul(result, a)
    return result


def gf_inv(a):
    # Every non-zero element satisfies a^255 = 1, so a^254 is its inverse
    assert a != 0
    return gf_pow(a, 254)


def interpolate(x, points):
    """f(x) of the polynomials through the points, one per byte."""
    xs = [xi for xi, _ in points]
    assert len(set(xs)) == len(xs), "distinct indices"
    length = len(points[0][1])
    assert all(len(y) == length for _, y in points), "one length"
    result = bytearray(length)
    for xi, yi in points:
        weight = 1
        for xj in xs:
            if xj != xi:
                weight = gf_mul(weight, gf_mul(x ^ xj, gf_inv(xi ^ xj)))
        for k in range(length):
            result[k] ^= gf_mul(yi[k], weight)
    return bytes(result)


# --- Sharing a secret ---


def digest_of(random_part, secret):
    return hmac.new(random_part, secret, "sha256").digest()[:4]


def split_secret(threshold, count, secret, random_shares, random_part):
    assert 0 < threshold <= count <= 16
    assert len(secret) >= 16 and len(secret) % 2 == 0
    if threshold == 1:
        assert random_shares == [] and random_part == b""
        return [(i, secret) for i in range(count)]
    assert len(random_shares) == threshold - 2
    assert all(len(r) == len(secret) for r in random_shares)
    assert len(random_part) == len(secret) - 4
    base = [(i, r) for i, r in enumerate(random_shares)]
    base += [(254, digest_of(random_part, secret) + random_part), (255, secret)]
    shares = [(i, r) for i, r in enumerate(random_shares)]
    for i in range(threshold - 2, count):
        shares.append((i, interpolate(i, base)))
    return shares


def recover_secret(threshold, shares):
    if threshold == 1:
        return shares[0][1]
    secret = interpolate(255, shares)
    digest_share = interpolate(254, shares)
    if digest_share[:4] != digest_of(digest_share[4:], secret):
        raise Refused("digest")
    return secret


# --- The checksum, as the specification gives it ---


def rs1024_polymod(values):
    GEN = [0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009,
           0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120]
    chk = 1
    for v in values:
        b = chk >> 20
        chk = (chk & 0xFFFFF) << 10 ^ v
        for i in range(10):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def rs1024_verify_checksum(cs, data):
    return rs1024_polymod([ord(x) for x in cs] + data) == 1


def rs1024_create_checksum(cs, data):
    values = [ord(x) for x in cs] + data
    polymod = rs1024_polymod(values + [0, 0, 0]) ^ 1
    return [(polymod >> 10 * (2 - i)) & 1023 for i in range(3)]


def customization(extendable):
    return "shamir_extendable" if extendable else "shamir"


# --- Share mnemonics, packed as bit strings ---


def load_wordlist():
    with open(os.path.join(DATA, "slip39_wordlist.txt"), "rb") as f:
        raw = f.read()
    words = raw.decode("ascii").split("\n")
    assert words[-1] == ""
    return raw, words[:-1]


WORDLIST_RAW, WORDS = load_wordlist()
WORD_INDEX = {w: i for i, w in enumerate(WORDS)}


def bits(value, width):
    return format(value, "b").zfill(width)


def encode_share(share):
    """The mnemonic of a share given as a dict of its fields."""
    data = (
        bits(share["identifier"], 15)
        + bits(int(share["extendable"]), 1)
        + bits(share["iterationExponent"], 4)
        + bits(share["groupIndex"], 4)
        + bits(share["groupThreshold"] - 1, 4)
        + bits(share["groupCount"] - 1, 4)
        + bits(share["memberIndex"], 4)
        + bits(share["memberThreshold"] - 1, 4)
    )
    value_bits = "".join(bits(b, 8) for b in share["value"])
    padding = (-len(value_bits)) % 10
    data += "0" * padding + value_bits
    assert len(data) % 10 == 0
    indices = [int(data[i:i + 10], 2) for i in range(0, len(data), 10)]
    indices += rs1024_create_checksum(customization(share["extendable"]), indices)
    return " ".join(WORDS[i] for i in indices)


def decode_share(mnemonic):
    indices = []
    for word in mnemonic.split():
        if word.lower() not in WORD_INDEX:
            raise Refused("word")
        indices.append(WORD_INDEX[word.lower()])
    if len(indices) < 20:
        raise Refused("too short")
    value_words = len(indices) - 7
    padding = (10 * value_words) % 16
    if padding > 8:
        raise Refused("length")
    data = "".join(bits(i, 10) for i in indices[:-3])
    extendable = data[15] == "1"
    if not rs1024_verify_checksum(customization(extendable), indices):
        raise Refused("checksum")
    share = {
        "identifier": int(data[0:15], 2),
        "extendable": extendable,
        "iterationExponent": int(data[16:20], 2),
        "groupIndex": int(data[20:24], 2),
        "groupThreshold": int(data[24:28], 2) + 1,
        "groupCount": int(data[28:32], 2) + 1,
        "memberIndex": int(data[32:36], 2),
        "memberThreshold": int(data[36:40], 2) + 1,
    }
    if share["groupThreshold"] > share["groupCount"]:
        raise Refused("group threshold")
    value_bits = data[40:]
    if value_bits[:padding] != "0" * padding:
        raise Refused("padding")
    value_bits = value_bits[padding:]
    share["value"] = bytes(int(value_bits[i:i + 8], 2) for i in range(0, len(value_bits), 8))
    return share


# --- The passphrase ---


def feistel(rounds, identifier, extendable, exponent, passphrase, secret):
    half = len(secret) // 2
    left, right = secret[:half], secret[half:]
    salt_prefix = b"" if extendable else b"shamir" + identifier.to_bytes(2, "big")
    for i in rounds:
        f = hashlib.pbkdf2_hmac("sha256", bytes([i]) + passphrase, salt_prefix + right,
                                2500 << exponent, dklen=half)
        left, right = right, bytes(a ^ b for a, b in zip(left, f))
    return right + left


def encrypt(identifier, extendable, exponent, passphrase, secret):
    assert all(32 <= c <= 126 for c in passphrase)
    return feistel([0, 1, 2, 3], identifier, extendable, exponent, passphrase, secret)


def decrypt(identifier, extendable, exponent, passphrase, ciphertext):
    return feistel([3, 2, 1, 0], identifier, extendable, exponent, passphrase, ciphertext)


# --- Generating and combining ---


def generate_shares(scheme, identifier, extendable, exponent, passphrase, secret, randoms):
    """The mnemonics of the master secret under the scheme, one list per
    group, with the random values given: one (shares, digest part) pair for
    the group split, then one per group."""
    group_threshold, groups = scheme["groupThreshold"], scheme["groups"]
    ems = encrypt(identifier, extendable, exponent, passphrase, secret)
    group_shares = split_secret(group_threshold, len(groups), ems, *randoms[0])
    result = []
    for (threshold, count), (gi, group_secret), random in zip(groups, group_shares, randoms[1:]):
        members = split_secret(threshold, count, group_secret, *random)
        result.append([
            encode_share({
                "identifier": identifier, "extendable": extendable,
                "iterationExponent": exponent, "groupIndex": gi,
                "groupThreshold": group_threshold, "groupCount": len(groups),
                "memberIndex": mi, "memberThreshold": threshold, "value": v,
            })
            for mi, v in members
        ])
    return result


def combine(mnemonics, passphrase):
    if not mnemonics:
        raise Refused("empty")
    shares = [decode_share(m) for m in mnemonics]
    common = [(s["identifier"], s["extendable"], s["iterationExponent"],
               s["groupThreshold"], s["groupCount"], len(s["value"])) for s in shares]
    if len(set(common)) != 1:
        raise Refused("common parameters")
    identifier, extendable, exponent, group_threshold, _, _ = common[0]
    groups = {}
    for s in shares:
        groups.setdefault(s["groupIndex"], []).append(s)
    if len(groups) != group_threshold:
        raise Refused("group count")
    group_points = []
    for gi, members in groups.items():
        thresholds = {m["memberThreshold"] for m in members}
        if len(thresholds) != 1:
            raise Refused("member threshold")
        threshold = thresholds.pop()
        indices = [m["memberIndex"] for m in members]
        if len(set(indices)) != len(indices):
            raise Refused("duplicate member")
        if len(members) != threshold:
            raise Refused("member count")
        group_points.append((gi, recover_secret(threshold, [(m["memberIndex"], m["value"]) for m in members])))
    ems = recover_secret(group_threshold, group_points)
    return decrypt(identifier, extendable, exponent, passphrase, ems)


# --- BIP-32 master key of a seed, for the fourth element of the vectors ---


def base58check(payload):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def xprv_of_seed(seed):
    i = hmac.new(b"Bitcoin seed", seed, "sha512").digest()
    key, chain = i[:32], i[32:]
    return base58check(bytes.fromhex("0488ADE4") + b"\0" * 9 + chain + b"\0" + key)


# --- The split cases of data/slip39_split.json ---


def fixed_bytes(label, length):
    """Bytes that stand in for random ones, fixed by a label: SHA-256 of the
    label, repeated as needed. They make the cases reproducible; they are
    not random, and no secret is made from them."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(label.encode() + bytes([counter])).digest()
        counter += 1
    return out[:length]


def split_random(label, threshold, secret_length):
    if threshold == 1:
        return [], b""
    shares = [fixed_bytes(f"{label} share {i}", secret_length) for i in range(threshold - 2)]
    return shares, fixed_bytes(f"{label} digest", secret_length - 4)


SPLIT_CASES = [
    # description, group threshold, groups, identifier, extendable, exponent, passphrase, master secret
    ("1-of-1, 128 bits, no passphrase", 1, [(1, 1)], 7945, True, 0, "", "ABCDEFGHIJKLMNOP"),
    ("2-of-3, 128 bits, passphrase TREZOR", 1, [(2, 3)], 42, True, 1, "TREZOR", "ABCDEFGHIJKLMNOP"),
    ("3-of-5, 128 bits, not extendable", 1, [(3, 5)], 42, False, 1, "TREZOR", "ABCDEFGHIJKLMNOP"),
    ("3-of-5, 256 bits, exponent 2", 1, [(3, 5)], 32767, True, 2, "pass phrase", "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
    ("2-of-2, 160 bits", 1, [(2, 2)], 0, True, 0, "", "ABCDEFGHIJKLMNOPQRST"),
    ("2 of 3 groups: 1-of-1, 2-of-3, 3-of-5, 128 bits", 2, [(1, 1), (2, 3), (3, 5)], 12345, True, 0, "TREZOR", "ABCDEFGHIJKLMNOP"),
    ("1 of 2 groups: 2-of-3 and 2-of-3, 256 bits, not extendable", 1, [(2, 3), (2, 3)], 1, False, 1, "", "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
    ("4-of-4, 128 bits: two random shares", 1, [(4, 4)], 100, True, 0, "", "0123456789abcdef"),
]


def split_case(description, group_threshold, groups, identifier, extendable, exponent, passphrase, secret_text):
    secret = secret_text.encode()
    thresholds = [group_threshold] + [t for t, _ in groups]
    randoms = [split_random(f"{description} split {k}", t, len(secret)) for k, t in enumerate(thresholds)]
    scheme = {"groupThreshold": group_threshold, "groups": [list(g) for g in groups]}
    mnemonics = generate_shares(scheme, identifier, extendable, exponent, passphrase.encode(), secret, randoms)
    return {
        "description": description,
        "scheme": scheme,
        "identifier": identifier,
        "extendable": extendable,
        "iterationExponent": exponent,
        "passphrase": passphrase,
        "masterSecret": secret.hex(),
        "random": [{"shares": [s.hex() for s in shares], "digest": digest.hex()} for shares, digest in randoms],
        "mnemonics": mnemonics,
    }


def threshold_subsets(case):
    """Every set of mnemonics that meets the scheme: for each choice of
    enough groups, each choice of enough members of those groups."""
    scheme, groups = case["scheme"], case["mnemonics"]
    thresholds = [t for t, _ in scheme["groups"]]
    for chosen in itertools.combinations(range(len(groups)), scheme["groupThreshold"]):
        per_group = [list(itertools.combinations(groups[g], thresholds[g])) for g in chosen]
        for pick in itertools.product(*per_group):
            yield [m for members in pick for m in members]


# --- Checks ---


def check(condition, message):
    if not condition:
        print("FAILED:", message)
        sys.exit(1)


def check_wordlist():
    check(hashlib.sha256(WORDLIST_RAW).hexdigest() == WORDLIST_SHA256, "word list hash")
    check(len(WORDS) == 1024, "1024 words")
    check(WORDS == sorted(WORDS), "sorted")
    check(all(4 <= len(w) <= 8 for w in WORDS), "4 to 8 letters")
    check(len({w[:4] for w in WORDS}) == 1024, "distinct prefixes")
    print("word list: ok")


# Why each invalid vector is refused, by its number, from its description.
# Vectors 21 to 35 are vectors 2 to 16 with 256-bit secrets.
REFUSALS = {
    2: "checksum",            # invalid checksum
    3: "padding",             # invalid padding
    5: "member count",        # one share of a 2-of-3 split
    6: "common parameters",   # different identifiers
    7: "common parameters",   # different iteration exponents
    8: "common parameters",   # mismatching group thresholds
    9: "common parameters",   # mismatching group counts
    10: "group threshold",    # group threshold greater than the group count
    11: "duplicate member",   # duplicate member indices
    12: "member threshold",   # mismatching member thresholds
    13: "digest",             # invalid digest
    14: "group count",        # insufficient number of groups, case 1
    15: "group count",        # insufficient number of groups, case 2
    16: "member count",       # enough groups, too few members in one
    39: "too short",          # insufficient length
    40: "length",             # invalid master secret length
}
REFUSALS.update({number + 19: reason for number, reason in list(REFUSALS.items()) if number <= 16})


def check_vectors():
    with open(os.path.join(DATA, "slip39_vectors.json")) as f:
        vectors = json.load(f)
    for description, mnemonics, secret_hex, xprv in vectors:
        if secret_hex:
            secret = combine(mnemonics, b"TREZOR")
            check(secret.hex() == secret_hex, description)
            check(xprv_of_seed(secret) == xprv, description + " (xprv)")
        else:
            number = int(description.split(".")[0])
            try:
                combine(mnemonics, b"TREZOR")
            except Refused as refusal:
                # A vector must be refused for the reason its description
                # gives, not for any reason
                check(str(refusal) == REFUSALS[number],
                      f"{description} (refused for '{refusal}', not for '{REFUSALS[number]}')")
                continue
            check(False, description + " (not refused)")
    # A share made by an early reference version with a passphrase outside
    # printable ASCII still decrypts with it, as UTF-8
    cafe = ("acid fawn academic academic company fridge picture cage pecan glance "
            "privacy carpet should public pharmacy eclipse percent python together flavor")
    check(combine([cafe], "café".encode()) == b"ABCDEFGHIJKLMNOP", "café passphrase")
    # From the tests of Sparrow's library: five of eight groups of one member,
    # and the value of the fifth share starts with a zero byte
    sparrow = [
        "budget surprise agency romp clay quiet spew favorite purchase thumb observe sympathy acrobat presence unfold focus already tricycle diagnose muscle",
        "budget surprise birthday romp breathe scroll intend humidity aspect plains isolate crystal blimp dragon garbage both kind dance human craft",
        "budget surprise cleanup romp early remove uncover hearing lamp firefly ounce species submit snake phrase genuine tactics mustang desire artist",
        "budget surprise desert romp deny easy senior arena smirk average single smart fatal lecture threaten eyebrow lunar carve indicate romantic",
        "budget surprise email romp academic anxiety sister nylon fake makeup spine breathe window true recall desktop shelter divorce luck screw",
    ]
    check(decode_share(sparrow[4])["value"].hex() == "000bf319a1478ab5418bedeb2de34f26", "zero byte kept")
    check(combine(sparrow, b"").hex() == "609d9cf21c065a88e9f5b97c0e6928c6", "Sparrow's groups")
    print(f"vectors: {len(vectors)} ok")


def check_split(write):
    path = os.path.join(DATA, "slip39_split.json")
    cases = [split_case(*c) for c in SPLIT_CASES]
    if write:
        with open(path, "w") as f:
            json.dump(cases, f, indent=1)
            f.write("\n")
        print(f"wrote {len(cases)} split cases to {path}")
    with open(path) as f:
        stored = json.load(f)
    check(stored == cases, "the split cases match the file")
    for case in cases:
        secret = bytes.fromhex(case["masterSecret"])
        subsets = 0
        for subset in threshold_subsets(case):
            check(combine(subset, case["passphrase"].encode()) == secret, case["description"])
            subsets += 1
        check(subsets > 0, case["description"] + " has subsets")
    print(f"split cases: {len(cases)} ok")


def check_reference():
    """The reference implementation over the same data, with its random
    bytes replaying the values of each split case."""
    import shamir_mnemonic
    from shamir_mnemonic import shamir

    with open(os.path.join(DATA, "slip39_split.json")) as f:
        cases = json.load(f)
    for case in cases:
        secret = bytes.fromhex(case["masterSecret"])
        for subset in threshold_subsets(case):
            check(shamir_mnemonic.combine_mnemonics(subset, case["passphrase"].encode()) == secret,
                  "reference combines " + case["description"])
        stream = []
        for r in case["random"]:
            stream += [bytes.fromhex(s) for s in r["shares"]] + [bytes.fromhex(r["digest"])]
        stream = [b for b in stream if b != b""]
        queue = list(stream)

        def replay(n):
            value = queue.pop(0)
            assert len(value) == n, "the reference draws as the case was made"
            return value

        saved = shamir.RANDOM_BYTES
        shamir.RANDOM_BYTES = replay
        try:
            ems = shamir.EncryptedMasterSecret.from_master_secret(
                secret, case["passphrase"].encode(), case["identifier"],
                case["extendable"], case["iterationExponent"])
            groups = shamir.split_ems(case["scheme"]["groupThreshold"],
                                      [tuple(g) for g in case["scheme"]["groups"]], ems)
        finally:
            shamir.RANDOM_BYTES = saved
        check(queue == [], "the reference drew every value of " + case["description"])
        mnemonics = [[s.mnemonic() for s in group] for group in groups]
        check(mnemonics == case["mnemonics"], "reference splits " + case["description"])
    with open(os.path.join(DATA, "slip39_vectors.json")) as f:
        vectors = json.load(f)
    for description, mnemonics, secret_hex, _ in vectors:
        if secret_hex:
            check(shamir_mnemonic.combine_mnemonics(mnemonics, b"TREZOR").hex() == secret_hex,
                  "reference " + description)
    print(f"reference implementation: {len(cases)} split cases and the vectors ok")


def main():
    check_wordlist()
    check_vectors()
    check_split("--write" in sys.argv)
    if "--reference" in sys.argv:
        check_reference()


if __name__ == "__main__":
    main()
