#!/usr/bin/env python3
"""
Generate signed DNS fixtures for src/dnssec's end-to-end tests.

The captured fixtures in `fixtures_test.odin` are real traffic, which is the
right thing to validate the ordinary path against: a canonicalisation bug
cannot agree with itself and still pass. What they cannot supply is a zone
nobody operates on purpose - a delegation whose every DS names an algorithm we
do not implement, a key published with the revoke bit set, an opt-out span
standing in for a proof. Those are generated here.

Ed25519 throughout (algorithm 15, RFC 8080): the signatures are short, the keys
are 32 bytes, and there is no per-signature randomness, so a regenerated fixture
is byte-identical. The root is replaced by a trust anchor of this file's own
making, printed alongside each scenario.

Usage: python3 sign_fixtures.py            # every scenario
       python3 sign_fixtures.py <name>     # just one
"""

import hashlib
import struct
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Signatures are pinned to the window the Odin tests use for FIXTURE_TIME.
FIXTURE_TIME = 1785664800  # must match FIXTURE_TIME in src/dnssec/dnssec_test.odin
INCEPTION = FIXTURE_TIME - 86400 * 30
EXPIRATION = FIXTURE_TIME + 86400 * 3650

ALG_ED25519 = 15
DIGEST_SHA256 = 2
CLASS_IN = 1

A, NS, SOA, CNAME, MX, TXT = 1, 2, 6, 5, 15, 16
DS, RRSIG, NSEC, DNSKEY, NSEC3 = 43, 46, 47, 48, 50


def wire_name(name):
    if name in (".", ""):
        return b"\x00"
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode()
        assert len(raw) <= 63, label
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def canonical_name(name):
    return wire_name(name.lower())


class Key:
    """One Ed25519 zone key, used as both KSK and ZSK."""

    def __init__(self, zone, seed, flags=257, protocol=3, algorithm=ALG_ED25519):
        self.zone = zone
        self.priv = ed25519.Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(seed.encode()).digest()
        )
        self.pub = self.priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.flags = flags
        self.protocol = protocol
        self.algorithm = algorithm

    @property
    def rdata(self):
        return struct.pack("!HBB", self.flags, self.protocol, self.algorithm) + self.pub

    @property
    def tag(self):
        acc = 0
        for i, b in enumerate(self.rdata):
            acc += (b << 8) if i % 2 == 0 else b
        acc += (acc >> 16) & 0xFFFF
        return acc & 0xFFFF

    def ds(self, digest_type=DIGEST_SHA256):
        data = canonical_name(self.zone) + self.rdata
        digest = hashlib.sha256(data).digest()
        return struct.pack("!HBB", self.tag, self.algorithm, digest_type) + digest

    def ds_text(self):
        return "%s IN DS %d %d %d %s" % (
            self.zone,
            self.tag,
            self.algorithm,
            DIGEST_SHA256,
            self.ds()[4:].hex().upper(),
        )


class RR:
    def __init__(self, name, rtype, rdata, ttl=3600):
        self.name, self.type, self.rdata, self.ttl = name, rtype, rdata, ttl

    def wire(self):
        return (
            wire_name(self.name)
            + struct.pack("!HHI", self.type, CLASS_IN, self.ttl)
            + struct.pack("!H", len(self.rdata))
            + self.rdata
        )


def sign(rrset, key, signer=None, labels=None, ttl=3600, original_ttl=3600,
         inception=INCEPTION, expiration=EXPIRATION, key_tag=None, algorithm=None):
    """An RRSIG over `rrset`, which must be one owner name and one type."""
    signer = signer if signer is not None else key.zone
    owner = rrset[0].name
    rtype = rrset[0].type
    if labels is None:
        stripped = owner.rstrip(".")
        labels = len([l for l in stripped.split(".") if l and l != "*"])
    algorithm = algorithm if algorithm is not None else key.algorithm
    key_tag = key_tag if key_tag is not None else key.tag

    prefix = (
        struct.pack("!HBBI", rtype, algorithm, labels, original_ttl)
        + struct.pack("!II", expiration, inception)
        + struct.pack("!H", key_tag)
        + canonical_name(signer)
    )

    # RFC 4034 section 6.3: the RRset in canonical order, duplicates dropped.
    # A wildcard expansion is signed under the wildcard the zone holds.
    sign_owner = owner
    owner_labels = len([l for l in owner.rstrip(".").split(".") if l])
    if labels < owner_labels and not owner.startswith("*."):
        sign_owner = "*." + ".".join(owner.rstrip(".").split(".")[owner_labels - labels:]) + "."

    body = b""
    for rdata in sorted({rr.rdata for rr in rrset}):
        body += (
            canonical_name(sign_owner)
            + struct.pack("!HHI", rtype, CLASS_IN, original_ttl)
            + struct.pack("!H", len(rdata))
            + rdata
        )

    signature = key.priv.sign(prefix + body)
    return RR(owner, RRSIG, prefix + signature, ttl)


def nsec3_hash(name, salt, iterations):
    h = hashlib.sha1(canonical_name(name) + salt).digest()
    for _ in range(iterations):
        h = hashlib.sha1(h + salt).digest()
    return h


B32HEX = "0123456789abcdefghijklmnopqrstuv"


def b32hex(data):
    out, acc, bits = "", 0, 0
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out += B32HEX[(acc >> bits) & 31]
    if bits:
        out += B32HEX[(acc << (5 - bits)) & 31]
    return out


def type_bitmap(types):
    out = b""
    for window in sorted({t >> 8 for t in types}):
        bits = bytearray(32)
        high = 0
        for t in types:
            if t >> 8 != window:
                continue
            bits[(t & 0xFF) // 8] |= 0x80 >> ((t & 0xFF) % 8)
            high = max(high, (t & 0xFF) // 8 + 1)
        out += bytes([window, high]) + bytes(bits[:high])
    return out


def nsec_rdata(next_name, types):
    return wire_name(next_name) + type_bitmap(types)


def nsec3_rdata(next_hash, types, salt=b"", iterations=0, flags=0):
    return (
        bytes([1, flags])
        + struct.pack("!H", iterations)
        + bytes([len(salt)])
        + salt
        + bytes([len(next_hash)])
        + next_hash
        + type_bitmap(types)
    )


def nsec3_rr(zone, owner, next_hash, types, salt=b"", iterations=0, flags=0, ttl=3600):
    name = b32hex(nsec3_hash(owner, salt, iterations)) + "." + zone
    return RR(name, NSEC3, nsec3_rdata(next_hash, types, salt, iterations, flags), ttl)


def message(qname, qtype, answer=(), authority=(), additional=(), rcode=0, qid=0x1234):
    flags = 0x8580 | rcode  # QR, AA, RD, RA
    out = struct.pack(
        "!HHHHHH", qid, flags, 1, len(answer), len(authority), len(additional)
    )
    out += wire_name(qname) + struct.pack("!HH", qtype, CLASS_IN)
    for section in (answer, authority, additional):
        for rr in section:
            out += rr.wire()
    return out


def emit(key, name, rtype, wire, rcode=0):
    text = wire.hex()
    lines = [text[i:i + 96] for i in range(0, len(text), 96)]
    body = '" +\n\t\t\t"'.join(lines)
    print("\t{")
    print('\t\tkey   = "%s",' % key)
    print('\t\tname  = "%s",' % name)
    print("\t\ttype  = .%s," % rtype)
    print("\t\trcode = %d," % rcode)
    print('\t\twire  = "%s",' % body)
    print("\t},")


SCENARIOS = {}


def scenario(fn):
    SCENARIOS[fn.__name__] = fn
    return fn


@scenario
def algorithm_downgrade():
    """
    A delegation whose DS set names two algorithms, one of them unknown here.

    RFC 6840 section 5.11: a validator needs one DS it can follow, and the
    presence of a DS for an algorithm it does not implement neither breaks the
    delegation nor excuses it from checking the one it does. Getting this wrong
    in either direction is a downgrade: refuse the whole set and a zone mid
    rollover goes dark, accept the unknown one as sufficient and an attacker who
    can strip the usable DS turns a signed zone insecure.
    """
    root = Key(".", "downgrade-root")
    child = Key("dgtest.", "downgrade-child")

    # The real DS, plus one naming algorithm 253 - private use, and nothing this
    # build implements.
    unknown = struct.pack("!HBB", child.tag, 253, DIGEST_SHA256) + hashlib.sha256(b"nope").digest()

    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("dg_root_dnskey", ".", "DNSKEY", message(".", DNSKEY, root_keys + [sign(root_keys, root)]))

    ds_set = [RR("dgtest.", DS, unknown), RR("dgtest.", DS, child.ds())]
    emit("dg_ds", "dgtest.", "DS", message("dgtest.", DS, ds_set + [sign(ds_set, root)]))

    child_keys = [RR("dgtest.", DNSKEY, child.rdata)]
    emit("dg_dnskey", "dgtest.", "DNSKEY",
         message("dgtest.", DNSKEY, child_keys + [sign(child_keys, child)]))

    answer = [RR("www.dgtest.", A, bytes([192, 0, 2, 1]))]
    emit("dg_answer", "www.dgtest.", "A",
         message("www.dgtest.", A, answer + [sign(answer, child)]))


@scenario
def unsupported_algorithm_only():
    """
    The same delegation with only the unknown-algorithm DS left.

    Nothing in the chain can be followed past this point, and RFC 6840 section
    5.2 makes that an insecure delegation rather than a broken one: the answer
    is served without the AD bit rather than refused.
    """
    root = Key(".", "unsupported-root")
    child = Key("uatest.", "unsupported-child")
    unknown = struct.pack("!HBB", child.tag, 253, DIGEST_SHA256) + hashlib.sha256(b"nope").digest()

    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("ua_root_dnskey", ".", "DNSKEY", message(".", DNSKEY, root_keys + [sign(root_keys, root)]))

    ds_set = [RR("uatest.", DS, unknown)]
    emit("ua_ds", "uatest.", "DS", message("uatest.", DS, ds_set + [sign(ds_set, root)]))

    child_keys = [RR("uatest.", DNSKEY, child.rdata)]
    emit("ua_dnskey", "uatest.", "DNSKEY",
         message("uatest.", DNSKEY, child_keys + [sign(child_keys, child)]))

    answer = [RR("www.uatest.", A, bytes([192, 0, 2, 1]))]
    emit("ua_answer", "www.uatest.", "A",
         message("www.uatest.", A, answer + [sign(answer, child)]))


@scenario
def unsupported_digest_only():
    """
    A DS whose algorithm we implement but whose digest type we do not.

    Same outcome as an unknown algorithm, by the same section, and worth its own
    fixture because the two fields are checked separately and only one of them
    being consulted is an easy mistake to make.
    """
    root = Key(".", "digest-root")
    child = Key("udtest.", "digest-child")
    # Digest type 3 is GOST R 34.11-94, withdrawn by RFC 6986.
    gost = struct.pack("!HBB", child.tag, ALG_ED25519, 3) + hashlib.sha256(b"gost").digest()[:32]

    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("ud_root_dnskey", ".", "DNSKEY", message(".", DNSKEY, root_keys + [sign(root_keys, root)]))

    ds_set = [RR("udtest.", DS, gost)]
    emit("ud_ds", "udtest.", "DS", message("udtest.", DS, ds_set + [sign(ds_set, root)]))

    child_keys = [RR("udtest.", DNSKEY, child.rdata)]
    emit("ud_dnskey", "udtest.", "DNSKEY",
         message("udtest.", DNSKEY, child_keys + [sign(child_keys, child)]))

    answer = [RR("www.udtest.", A, bytes([192, 0, 2, 1]))]
    emit("ud_answer", "www.udtest.", "A",
         message("www.udtest.", A, answer + [sign(answer, child)]))


@scenario
def revoked_key():
    """
    A zone whose apex key is published with the revoke bit set (RFC 5011).

    The key still hashes to the DS the parent published - revoking changes the
    flags, which changes the key tag, but an attacker replaying an old DS would
    not care. A validator that ignores the bit would keep trusting a key its
    owner has publicly withdrawn, which is the entire point of revoking one.
    """
    root = Key(".", "revoked-root")
    child = Key("rvtest.", "revoked-child")

    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("rv_root_dnskey", ".", "DNSKEY", message(".", DNSKEY, root_keys + [sign(root_keys, root)]))

    # The DS is computed over the revoked key exactly as published, so the
    # binding to the parent is sound and only the revoke bit is in the way.
    child.flags = 257 | 0x0080
    ds_set = [RR("rvtest.", DS, child.ds())]
    emit("rv_ds", "rvtest.", "DS", message("rvtest.", DS, ds_set + [sign(ds_set, root)]))

    child_keys = [RR("rvtest.", DNSKEY, child.rdata)]
    emit("rv_dnskey", "rvtest.", "DNSKEY",
         message("rvtest.", DNSKEY, child_keys + [sign(child_keys, child)]))

    answer = [RR("www.rvtest.", A, bytes([192, 0, 2, 1]))]
    emit("rv_answer", "www.rvtest.", "A",
         message("www.rvtest.", A, answer + [sign(answer, child)]))


@scenario
def unfollowable_ds_beside_unsupported():
    """
    A DS set holding one record we could follow and one we cannot understand,
    where the followable one matches no published key.

    This is the case that tells the two layers of the check apart. `zone_step`
    refuses a DS set with nothing usable in it before spending a DNSKEY lookup;
    `fetch_keys` reaches the same verdict again after the lookup, for the set
    that got past. Both must hold on their own, or a change to either goes
    unnoticed because the other still produces the right answer.

    Here the Ed25519 DS is usable enough to get past the first check and then
    matches nothing, while the algorithm-253 DS remains unevaluatable. A DS we
    cannot check may yet be the right one, so the delegation is insecure rather
    than bogus - the same conclusion, reached in the second place.
    """
    root = Key(".", "unfollowable-root")
    child = Key("uftest.", "unfollowable-child")

    # Right algorithm, right digest type, right key tag - and a digest that is
    # not this key's.
    mismatched = struct.pack("!HBB", child.tag, ALG_ED25519, DIGEST_SHA256) + hashlib.sha256(b"not this key").digest()
    unknown = struct.pack("!HBB", child.tag, 253, DIGEST_SHA256) + hashlib.sha256(b"nope").digest()

    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("uf_root_dnskey", ".", "DNSKEY", message(".", DNSKEY, root_keys + [sign(root_keys, root)]))

    ds_set = [RR("uftest.", DS, mismatched), RR("uftest.", DS, unknown)]
    emit("uf_ds", "uftest.", "DS", message("uftest.", DS, ds_set + [sign(ds_set, root)]))

    child_keys = [RR("uftest.", DNSKEY, child.rdata)]
    emit("uf_dnskey", "uftest.", "DNSKEY",
         message("uftest.", DNSKEY, child_keys + [sign(child_keys, child)]))

    answer = [RR("www.uftest.", A, bytes([192, 0, 2, 1]))]
    emit("uf_answer", "www.uftest.", "A",
         message("www.uftest.", A, answer + [sign(answer, child)]))


if __name__ == "__main__":
    wanted = sys.argv[1:] or list(SCENARIOS)
    for name in wanted:
        print("\n// ==== %s ====" % name)
        print("// " + (SCENARIOS[name].__doc__ or "").strip().replace("\n", "\n// "))
        SCENARIOS[name]()
