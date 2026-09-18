#!/usr/bin/env python3
"""Generate signed DNS fixtures for src/dnssec's end-to-end tests."""

# The captured fixtures in `fixtures_test.odin` are real traffic, which is the
# right thing to validate the ordinary path against: a canonicalisation bug
# cannot agree with itself and still pass. What they cannot supply is a zone
# nobody operates on purpose - a delegation whose every DS names an algorithm we
# do not implement, a key published with the revoke bit set, an opt-out span
# standing in for a proof. Those are generated here.
#
# Ed25519 throughout (algorithm 15, RFC 8080): the signatures are short, the keys
# are 32 bytes, and there is no per-signature randomness, so a regenerated fixture
# is byte-identical. The root is replaced by a trust anchor of this file's own
# making, printed alongside each scenario.
#
# Usage:
#     python3 sign_fixtures.py           # every scenario
#     python3 sign_fixtures.py <name>    # just one

import hashlib
import struct
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Signatures are pinned to the window the Odin tests use for FIXTURE_TIME.
FIXTURE_TIME = 1785664800  # must match FIXTURE_TIME in src/dnssec/dnssec_test.odin
INCEPTION = FIXTURE_TIME - 86400 * 30
EXPIRATION = FIXTURE_TIME + 86400 * 3650

TTL = 3600
# A fixture reply is authoritative NOERROR with the query id the Odin harness
# expects: QR, AA, RD and RA set.
QID = 0x1234
FLAGS = 0x8580

ALG_ED25519 = 15
DIGEST_SHA256 = 2
CLASS_IN = 1

A, NS, SOA, CNAME, MX, TXT = 1, 2, 6, 5, 15, 16
AAAA, SRV, SVCB, HTTPS = 28, 33, 64, 65
DNAME = 39
DS, RRSIG, NSEC, DNSKEY, NSEC3 = 43, 46, 47, 48, 50
NSEC3PARAM = 51


def wire_name(name):
    """A presentation-form name as length-prefixed labels, case preserved."""
    if name in (".", ""):
        return b"\x00"
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode()
        assert len(raw) <= 63, label
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def canonical_name(name):
    """The same, lowercased: the form RFC 4034 section 6.2 signs over."""
    return wire_name(name.lower())


class Key:
    """One Ed25519 zone key, used as both KSK and ZSK."""

    def __init__(self, zone, seed):
        """Derive the key deterministically, so a regenerated fixture matches."""
        self.zone = zone
        self.priv = ed25519.Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(seed.encode()).digest()
        )
        self.pub = self.priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        # A single key per zone, acting as both KSK and ZSK. A scenario that
        # needs a different shape sets these after construction.
        self.flags = 257
        self.protocol = 3
        self.algorithm = ALG_ED25519

    @property
    def rdata(self):
        """The DNSKEY RDATA, which both the key tag and the DS digest run over."""
        return struct.pack("!HBB", self.flags, self.protocol, self.algorithm) + self.pub

    @property
    def tag(self):
        """The key tag of RFC 4034 appendix B."""
        acc = 0
        for i, b in enumerate(self.rdata):
            acc += (b << 8) if i % 2 == 0 else b
        acc += (acc >> 16) & 0xFFFF
        return acc & 0xFFFF

    def ds(self, digest_type=DIGEST_SHA256):
        """The DS RDATA for this key, as its parent would publish it."""
        data = canonical_name(self.zone) + self.rdata
        digest = hashlib.sha256(data).digest()
        return struct.pack("!HBB", self.tag, self.algorithm, digest_type) + digest

    def ds_text(self):
        """The same DS in presentation form, for a trust anchor in the tests."""
        return "%s IN DS %d %d %d %s" % (
            self.zone,
            self.tag,
            self.algorithm,
            DIGEST_SHA256,
            self.ds()[4:].hex().upper(),
        )


class RR:
    """One resource record, carrying its RDATA already encoded."""

    def __init__(self, name, rtype, rdata, ttl=3600):
        """Hold one record; `rdata` is already in wire form."""
        self.name, self.type, self.rdata, self.ttl = name, rtype, rdata, ttl

    def wire(self):
        """The record as it goes in a message section."""
        return (
            wire_name(self.name)
            + struct.pack("!HHI", self.type, CLASS_IN, self.ttl)
            + struct.pack("!H", len(self.rdata))
            + self.rdata
        )


def labels_of(name):
    """The labels of a presentation-form name, root and empties dropped."""
    return [label for label in name.rstrip(".").split(".") if label]


def signed_label_count(owner):
    """The Labels field an honest signature over `owner` carries."""
    # RFC 4034 section 3.1.3 counts the owner name's labels without a leading
    # asterisk, so a zone's own `*.example.com.` counts two rather than three.
    return len([label for label in labels_of(owner) if label != "*"])


def signing_owner(owner, labels):
    """The name a signature is computed under, which is `owner` unless it expands."""
    # A Labels field short of the owner's own count says a wildcard answered, and
    # RFC 4035 section 5.3.2 has the signature computed over that wildcard rather
    # than over the name it was expanded to.
    parts = labels_of(owner)
    if labels >= len(parts) or owner.startswith("*."):
        return owner
    return "*." + ".".join(parts[len(parts) - labels:]) + "."


def sign(rrset, key, signer=None, labels=None):
    """Build an RRSIG over `rrset`, which is one owner name and one type."""
    # The validity window and the TTLs come from the module constants: no scenario
    # has needed to vary them, and a signature outside the window is a case the
    # Odin tests reach by moving the clock rather than by signing differently.
    #
    # `signer` and `labels` default to the truthful values and are overridable
    # because two tests need a signature that is internally consistent with an
    # untruthful one - see `check_signature_test.odin`.
    signer = signer if signer is not None else key.zone
    owner = rrset[0].name
    rtype = rrset[0].type
    if labels is None:
        labels = signed_label_count(owner)
    prefix = (
        struct.pack("!HBBI", rtype, key.algorithm, labels, TTL)
        + struct.pack("!II", EXPIRATION, INCEPTION)
        + struct.pack("!H", key.tag)
        + canonical_name(signer)
    )

    # RFC 4034 section 6.3: the RRset in canonical order, duplicates dropped.
    sign_owner = signing_owner(owner, labels)

    body = b""
    for rdata in sorted({rr.rdata for rr in rrset}):
        body += (
            canonical_name(sign_owner)
            + struct.pack("!HHI", rtype, CLASS_IN, TTL)
            + struct.pack("!H", len(rdata))
            + rdata
        )

    signature = key.priv.sign(prefix + body)
    return RR(owner, RRSIG, prefix + signature, TTL)


def type_bitmap(types):
    """The NSEC type bit maps of RFC 4034 section 4.1.2."""
    windows = {}
    for rtype in types:
        window, bit = rtype >> 8, rtype & 0xFF
        windows.setdefault(window, bytearray(32))[bit // 8] |= 0x80 >> (bit % 8)
    out = b""
    for window in sorted(windows):
        bitmap = windows[window]
        length = max(i for i, byte in enumerate(bitmap) if byte) + 1
        out += bytes([window, length]) + bytes(bitmap[:length])
    return out


def nsec_rdata(next_name, types):
    """The next owner name and the types present at this one."""
    return wire_name(next_name) + type_bitmap(types)


B32HEX = "0123456789abcdefghijklmnopqrstuv"


def base32hex(raw):
    """Base 32 with the extended hex alphabet, which is how NSEC3 owners read."""
    bits = "".join(format(byte, "08b") for byte in raw)
    assert len(bits) % 40 == 0, "an SHA-1 hash is 20 bytes, so this always divides"
    return "".join(B32HEX[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def nsec3_hash(name, salt, iterations):
    """RFC 5155 section 5: SHA-1 over the canonical name, salted and iterated."""
    # SHA-1 is not a choice here. It is the only hash algorithm NSEC3 has ever
    # been assigned (RFC 5155 appendix A.1, value 1), so a fixture hashed with
    # anything else is a record no validator would match. Nothing is being
    # authenticated by it either: what makes these records trustworthy is the
    # Ed25519 RRSIG over them.
    digest = hashlib.sha1(canonical_name(name) + salt).digest()  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    return digest


def nsec3_rdata(next_hash, types, salt, iterations, flags=0):
    """The NSEC3 RDATA of RFC 5155 section 3.2."""
    return (
        struct.pack("!BBH", 1, flags, iterations)
        + bytes([len(salt)]) + salt
        + bytes([len(next_hash)]) + next_hash
        + type_bitmap(types)
    )


def nsec3_chain(zone, nodes, salt, iterations):
    """One NSEC3 record per name, in hash order, the last wrapping to the first."""
    # Keyed by the name each record speaks for, so a scenario can pick the one
    # its message needs without depending on where in the chain it landed.
    hashed = sorted(
        ((nsec3_hash(name, salt, iterations), name, types) for name, types in nodes),
        key=lambda entry: entry[0],
    )
    out = {}
    for i, (digest, name, types) in enumerate(hashed):
        owner = base32hex(digest) + "." + zone
        next_hash = hashed[(i + 1) % len(hashed)][0]
        out[name] = RR(owner, NSEC3, nsec3_rdata(next_hash, types, salt, iterations))
    return out


def message(qname, qtype, answer, authority=(), additional=(), rcode=0):
    """One authoritative reply, as the fixture query callback returns it."""
    header = struct.pack(
        "!HHHHHH", QID, FLAGS | rcode, 1, len(answer), len(authority), len(additional)
    )
    out = header + wire_name(qname) + struct.pack("!HH", qtype, CLASS_IN)
    for section in (answer, authority, additional):
        for rr in section:
            out += rr.wire()
    return out


def emit(key, name, rtype, wire, rcode=0):
    """Print one `Fixture` literal, wrapped the way the Odin files are written."""
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
    """Register a scenario so it can be generated by name."""
    SCENARIOS[fn.__name__] = fn
    return fn


@scenario
def algorithm_downgrade():
    """Cover a delegation naming two DS algorithms, one of them unknown here."""
    # RFC 6840 section 5.11: a validator needs one DS it can follow, and the
    # presence of a DS for an algorithm it does not implement neither breaks the
    # delegation nor excuses it from checking the one it does. Getting this wrong
    # in either direction is a downgrade: refuse the whole set and a zone mid
    # rollover goes dark, accept the unknown one as sufficient and an attacker who
    # can strip the usable DS turns a signed zone insecure.
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
    """Cover the same delegation with only the unknown-algorithm DS left."""
    # Nothing in the chain can be followed past this point, and RFC 6840 section
    # 5.2 makes that an insecure delegation rather than a broken one: the answer
    # is served without the AD bit rather than refused.
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
    """Cover a DS we can follow by algorithm but not by digest type."""
    # Same outcome as an unknown algorithm, by the same section, and worth its own
    # fixture because the two fields are checked separately and only one of them
    # being consulted is an easy mistake to make.
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
    """Cover a zone whose apex key is published revoked (RFC 5011)."""
    # The key still hashes to the DS the parent published - revoking changes the
    # flags, which changes the key tag, but an attacker replaying an old DS would
    # not care. A validator that ignores the bit would keep trusting a key its
    # owner has publicly withdrawn, which is the entire point of revoking one.
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
    """Cover a followable DS matching no key, beside one we cannot read."""
    # This is the case that tells the two layers of the check apart. `zone_step`
    # refuses a DS set with nothing usable in it before spending a DNSKEY lookup;
    # `fetch_keys` reaches the same verdict again after the lookup, for the set
    # that got past. Both must hold on their own, or a change to either goes
    # unnoticed because the other still produces the right answer.
    #
    # Here the Ed25519 DS is usable enough to get past the first check and then
    # matches nothing, while the algorithm-253 DS remains unevaluatable. A DS we
    # cannot check may yet be the right one, so the delegation is insecure rather
    # than bogus - the same conclusion, reached in the second place.
    root = Key(".", "unfollowable-root")
    child = Key("uftest.", "unfollowable-child")

    # Right algorithm, right digest type, right key tag - and a digest that is
    # not this key's.
    mismatched = (
        struct.pack("!HBB", child.tag, ALG_ED25519, DIGEST_SHA256)
        + hashlib.sha256(b"not this key").digest()
    )
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


def a_rr(name, addr):
    """One A record, from a dotted-quad."""
    return RR(name, A, bytes(int(part) for part in addr.split(".")))


def aaaa_rr(name, addr):
    """One AAAA record, from the 16 bytes written as hex."""
    return RR(name, AAAA, bytes.fromhex(addr))


def srv_rr(name, target):
    """An SRV record at priority 0, weight 0, port 443."""
    return RR(name, SRV, struct.pack("!HHH", 0, 0, 443) + wire_name(target))


def https_rr(name, target, priority=1):
    """An HTTPS record with no parameters; priority 0 is AliasMode."""
    return RR(name, HTTPS, struct.pack("!H", priority) + wire_name(target))


def mx_rr(name, target, preference=10):
    """One MX record."""
    return RR(name, MX, struct.pack("!H", preference) + wire_name(target))


def soa_rr(zone):
    """The apex SOA, which a denial carries so the negative TTL has a source."""
    rdata = (
        wire_name("ns." + zone)
        + wire_name("hostmaster." + zone)
        + struct.pack("!IIIII", 1, 3600, 900, 604800, 300)
    )
    return RR(zone, SOA, rdata)


def hint_chain(root, children):
    """Emit the trust anchor and each signed zone the hint fixtures answer from."""
    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("sh_root_dnskey", ".", "DNSKEY", message(".", DNSKEY, root_keys + [sign(root_keys, root)]))
    for child in children:
        ds_set = [RR(child.zone, DS, child.ds())]
        emit("sh_%s_ds" % child.zone.rstrip("."), child.zone, "DS",
             message(child.zone, DS, ds_set + [sign(ds_set, root)]))
        keys = [RR(child.zone, DNSKEY, child.rdata)]
        emit("sh_%s_dnskey" % child.zone.rstrip("."), child.zone, "DNSKEY",
             message(child.zone, DNSKEY, keys + [sign(keys, child)]))


def hints_that_hold_up(zone, other):
    """Emit the responses whose address hints a validator may keep."""
    # A target inside the zone the answer already established: the common case,
    # and the one that costs no lookup at all because the keys are in hand.
    answer = [srv_rr("_svc._tcp.hinttest.", "svc.hinttest.")]
    hints = [a_rr("svc.hinttest.", "192.0.2.10"),
             aaaa_rr("svc.hinttest.", "20010db8000000000000000000000010")]
    emit("sh_srv_same_zone", "_svc._tcp.hinttest.", "SRV",
         message("_svc._tcp.hinttest.", SRV, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints[:1], zone), sign(hints[1:], zone)]))

    # A target in a second signed zone. Keeping this one means walking a chain
    # the answer never needed.
    answer = [https_rr("alt.hinttest.", "edge.other.")]
    hints = [a_rr("edge.other.", "198.51.100.20"),
             aaaa_rr("edge.other.", "20010db8000000000000000000000020")]
    emit("sh_https_cross_zone", "alt.hinttest.", "HTTPS",
         message("alt.hinttest.", HTTPS, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints[:1], other), sign(hints[1:], other)]))

    # A ServiceMode TargetName of "." stands for the owner name (RFC 9460
    # section 2.5), so the hints to keep are the ones at the answer's own name.
    answer = [https_rr("hinttest.", ".")]
    hints = [a_rr("hinttest.", "192.0.2.1")]
    emit("sh_https_service_form", "hinttest.", "HTTPS",
         message("hinttest.", HTTPS, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints, zone)]))


def hints_that_must_not(zone, other, nowhere):
    """Emit the responses whose address hints must not survive the prune."""
    # One MX answer carrying every kind of record that must not survive it: the
    # exchange's AAAA with no signature at all, a validly signed address for a
    # name the answer never named, and an attacker's unsigned glue.
    answer = [mx_rr("hinttest.", "mail.hinttest.")]
    signed = [a_rr("mail.hinttest.", "192.0.2.30")]
    bystander = [a_rr("bystander.hinttest.", "192.0.2.31")]
    additional = (
        signed + [sign(signed, zone)]
        + [aaaa_rr("mail.hinttest.", "20010db8000000000000000000000030")]
        + bystander + [sign(bystander, zone)]
        + [a_rr("ns.attacker.example.", "203.0.113.66")]
    )
    emit("sh_mx_mixed", "hinttest.", "MX",
         message("hinttest.", MX, answer + [sign(answer, zone)], additional=additional))

    # The signature is the zone's and covers this owner and type - over an
    # address that is not the one in the record beside it.
    answer = [srv_rr("_svc._tcp.hinttest.", "svc.hinttest.")]
    genuine = [a_rr("svc.hinttest.", "192.0.2.10")]
    emit("sh_forged_hint", "_svc._tcp.hinttest.", "SRV",
         message("_svc._tcp.hinttest.", SRV, answer + [sign(answer, zone)],
                 additional=[a_rr("svc.hinttest.", "203.0.113.99"), sign(genuine, zone)]))

    # AliasMode - priority zero - is a redirection the client follows by name
    # (RFC 9460 section 2.4.2), so its target names no hint to keep even when a
    # perfectly good signed address for it is sitting in the section.
    answer = [https_rr("alias.hinttest.", "edge.other.", priority=0)]
    hints = [a_rr("edge.other.", "198.51.100.20")]
    emit("sh_alias_mode", "alias.hinttest.", "HTTPS",
         message("alias.hinttest.", HTTPS, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints, other)]))

    # A hint that verifies against a wildcard. Nothing in the message proves the
    # name had no records of its own, and that proof lives in a section this
    # server never validated - so the signature holding up is not enough.
    answer = [https_rr("alt2.hinttest.", "wild.hinttest.")]
    hints = [a_rr("wild.hinttest.", "192.0.2.40")]
    emit("sh_wildcard_hint", "alt2.hinttest.", "HTTPS",
         message("alt2.hinttest.", HTTPS, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints, zone, labels=1)]))

    # A target in a zone nothing delegates to. The signature is real and the
    # chain cannot be built, which is the same as no signature at all here.
    answer = [https_rr("alt3.hinttest.", "edge.nosuch.")]
    hints = [a_rr("edge.nosuch.", "192.0.2.50")]
    emit("sh_unreachable_zone", "alt3.hinttest.", "HTTPS",
         message("alt3.hinttest.", HTTPS, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints, nowhere)]))

    # Forty exchanges in forty zones, none of them reachable. What is being
    # counted is how many of them provoke a chain walk: a response naming more
    # targets than `MAX_HINT_TARGETS` must not buy a walk apiece, and must not
    # cost the answer its own verdict.
    answer = [mx_rr("hinttest.", "mx%d.z%d." % (i, i), preference=i) for i in range(40)]
    additional = [a_rr("mx%d.z%d." % (i, i), "192.0.2.%d" % (100 + i)) for i in range(40)]
    emit("sh_many_targets", "hinttest.", "MX",
         message("hinttest.", MX, answer + [sign(answer, zone)], additional=additional))


@scenario
def signed_address_hints():
    """Cover the address records that ride beside an HTTPS, SVCB, SRV or MX answer."""
    # RFC 9460 section 5 has an authoritative server put A and AAAA for the
    # target in the additional section so a client can connect without asking
    # again. Those are not glue - they are ordinary signed zone data - so a
    # resolver setting AD can keep the ones it authenticates, and must drop the
    # rest. Every shape that decision has to tell apart is here: a target inside
    # the zone the answer established, one in a second zone that needs a chain
    # walk of its own, one in a zone that cannot be reached at all, an unsigned
    # record, a forged one, a validly signed record for a name the answer never
    # named, and a wildcard expansion whose proof is nowhere in the message.
    root = Key(".", "hints-root")
    zone = Key("hinttest.", "hints-zone")
    other = Key("other.", "hints-other")
    # A zone with no delegation anywhere in these fixtures, so a hint signed by
    # it is a hint whose chain of trust cannot be built.
    nowhere = Key("nosuch.", "hints-nowhere")

    hint_chain(root, (zone, other))
    hints_that_hold_up(zone, other)
    hints_that_must_not(zone, other, nowhere)

@scenario
def zone_cut_under_empty_non_terminal():
    """Cover a signed zone whose apex sits two labels below its signed parent."""
    # `deep.mid.entest.` is a zone of its own, and `mid.entest.` between it and
    # `entest.` is an empty non-terminal: no NS, no DS, nothing but the names
    # under it. A chain walk that reads "no delegation here" as "nothing below
    # here is delegated either" stops at `entest.` and never reaches the keys
    # that signed the answer, which reaches the client as a forgery. The shape
    # is not exotic - `seed.btc.petertodd.net.` and `seed.bitcoin.sprovoost.nl.`
    # are both this, under an empty non-terminal their operators never named.
    root = Key(".", "ent-root")
    parent = Key("entest.", "ent-parent")
    child = Key("deep.mid.entest.", "ent-child")

    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("en_root_dnskey", ".", "DNSKEY", message(".", DNSKEY, root_keys + [sign(root_keys, root)]))

    ds_set = [RR("entest.", DS, parent.ds())]
    emit("en_ds", "entest.", "DS", message("entest.", DS, ds_set + [sign(ds_set, root)]))

    parent_keys = [RR("entest.", DNSKEY, parent.rdata)]
    emit("en_dnskey", "entest.", "DNSKEY",
         message("entest.", DNSKEY, parent_keys + [sign(parent_keys, parent)]))

    # The empty non-terminal: it exists because something below it does, and it
    # holds nothing itself. NS absent is what makes it not a zone cut.
    mid_nsec = [RR("mid.entest.", NSEC, nsec_rdata("deep.mid.entest.", [RRSIG, NSEC]))]
    emit("en_mid_ds", "mid.entest.", "DS",
         message("mid.entest.", DS, [], mid_nsec + [sign(mid_nsec, parent)]))

    child_ds = [RR("deep.mid.entest.", DS, child.ds())]
    emit("en_deep_ds", "deep.mid.entest.", "DS",
         message("deep.mid.entest.", DS, child_ds + [sign(child_ds, parent)]))

    child_keys = [RR("deep.mid.entest.", DNSKEY, child.rdata)]
    emit("en_deep_dnskey", "deep.mid.entest.", "DNSKEY",
         message("deep.mid.entest.", DNSKEY, child_keys + [sign(child_keys, child)]))

    answer = [RR("deep.mid.entest.", A, bytes([192, 0, 2, 1]))]
    emit("en_answer", "deep.mid.entest.", "A",
         message("deep.mid.entest.", A, answer + [sign(answer, child)]))

    # One NSEC does both halves of an NXDOMAIN proof here: the span from the
    # apex to `zz.` swallows `nx.deep.mid.entest.` and the wildcard that would
    # otherwise have answered for it.
    apex_nsec = [
        RR("deep.mid.entest.", NSEC,
           nsec_rdata("zz.deep.mid.entest.", [A, NS, SOA, RRSIG, NSEC, DNSKEY])),
    ]
    denial = apex_nsec + [sign(apex_nsec, child)]
    emit("en_nx", "nx.deep.mid.entest.", "A",
         message("nx.deep.mid.entest.", A, [], denial, rcode=3), rcode=3)
    # The walk asks about the queried name itself before it settles on a zone,
    # so the denial has to answer a DS lookup too.
    emit("en_nx_ds", "nx.deep.mid.entest.", "DS",
         message("nx.deep.mid.entest.", DS, [], denial, rcode=3), rcode=3)


@scenario
def ds_denial_from_child_apex():
    """Cover a DS denial carried by the child's own apex record."""
    # A DS lives in the parent zone and nowhere else, so the record a child
    # signs at its own apex never lists the type - and a validator that reads
    # the missing bit as a denial can be handed the zone's genuine, published
    # apex NSEC and told the delegation is unsigned. Nothing is forged: the
    # records are copied verbatim and verify against the child's own keys, which
    # this server fetched by following the very DS it is then told is absent.
    #
    # Both zones below are signed and both have a real DS. `www` under each is
    # an ordinary name that is not a zone cut, which is the shape a legitimate
    # DS NODATA really has, and it is here so that refusing the apex cannot be
    # mistaken for refusing every DS denial.
    root = Key(".", "dsapex-root")
    child = Key("dstest.", "dsapex-child")
    child3 = Key("dstest3.", "dsapex-child3")
    # A third zone whose signer answers NODATA the way RFC 4470 allows, with an
    # NSEC minted for the question rather than one taken from the chain. Its bit
    # map holds only what that name really has to offer a validator, so neither
    # SOA nor NS appears on it, and reading the record alone cannot tell which
    # side of the cut it came from.
    blind = Key("bltest.", "dsapex-blind")

    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("da_root_dnskey", ".", "DNSKEY", message(".", DNSKEY, root_keys + [sign(root_keys, root)]))

    # The genuine delegations. These are what make each zone come back Secure,
    # so that the denial below is read against the child's own keys.
    for tag, zone in (("da", child), ("da3", child3), ("bl", blind)):
        ds_set = [RR(zone.zone, DS, zone.ds())]
        emit("%s_ds" % tag, zone.zone, "DS", message(zone.zone, DS, ds_set + [sign(ds_set, root)]))
        keys = [RR(zone.zone, DNSKEY, zone.rdata)]
        emit("%s_dnskey" % tag, zone.zone, "DNSKEY", message(zone.zone, DNSKEY, keys + [sign(keys, zone)]))

    # NSEC. The apex record of `dstest.` exactly as the zone publishes it, in a
    # NODATA reply to `dstest. DS`.
    apex_nsec = [RR("dstest.", NSEC, nsec_rdata("www.dstest.", [A, NS, SOA, RRSIG, NSEC, DNSKEY]))]
    emit("da_apex_nodata", "dstest.", "DS",
         message("dstest.", DS, [], apex_nsec + [sign(apex_nsec, child)]))

    # The honest shape: `www.dstest.` is a name in the zone, not a cut, so no
    # NS and no SOA, and its NSEC really does settle that there is no DS there.
    www_nsec = [RR("www.dstest.", NSEC, nsec_rdata("dstest.", [A, RRSIG, NSEC]))]
    emit("da_www_nodata", "www.dstest.", "DS",
         message("www.dstest.", DS, [], www_nsec + [sign(www_nsec, child)]))

    # NSEC3, salt and iterations kept small: what is under test is which bits
    # the bit map carries, not how expensive the hash was to compute.
    salt = bytes.fromhex("0a0b")
    chain = nsec3_chain(
        "dstest3.",
        [
            ("dstest3.", [A, NS, SOA, RRSIG, DNSKEY, NSEC3PARAM]),
            ("www.dstest3.", [A, RRSIG]),
        ],
        salt,
        0,
    )

    apex_nsec3 = [chain["dstest3."]]
    emit("da3_apex_nodata", "dstest3.", "DS",
         message("dstest3.", DS, [], apex_nsec3 + [sign(apex_nsec3, child3)]))

    www_nsec3 = [chain["www.dstest3."]]
    emit("da3_www_nodata", "www.dstest3.", "DS",
         message("www.dstest3.", DS, [], www_nsec3 + [sign(www_nsec3, child3)]))

    # The minimally covering NSEC, at the apex of a zone that plainly has a DS.
    # RFC 4470 puts the next name one step past the owner - `\000.bltest.` as a
    # real zone would write it - but nothing here reads a span, because the
    # record matches the owner exactly, so an ordinary name says the same thing
    # without teaching this generator to escape a NUL. What matters is the bit
    # map: no DS, and nothing else naming whose side of the cut this came from.
    blind_nsec = [RR("bltest.", NSEC, nsec_rdata("a.bltest.", [RRSIG, NSEC]))]
    emit("bl_apex_nodata", "bltest.", "DS",
         message("bltest.", DS, [], blind_nsec + [sign(blind_nsec, blind)]))


@scenario
def relocated_wildcard_denial():
    """Cover a wildcard's own NSEC and RRSIG re-owned to some other name."""
    # RFC 4034 section 3.1.3 lets an RRSIG carry a Labels field shorter than its
    # owner name, and that is how a wildcard answer is signed: the signature is
    # computed over `*.<encloser>`, not over the name the asterisk stood in for.
    # Nothing in the signature names the owner it was published under, so the
    # zone's genuine `*.wctest. NSEC` and its genuine RRSIG - both public, both
    # fetchable with one harmless query - verify just as well after the owner
    # field has been rewritten to any other name in the zone.
    #
    # Rewritten once, the wildcard's bit map becomes a NODATA proof for a name
    # that really has the type. Rewritten twice with chosen owners, the two
    # spans cover a qname and the wildcard, and the pair proves NXDOMAIN for a
    # name the zone answers for. RFC 4592 section 4.7 is the reason this is
    # never legitimate: a wildcard owns an NSEC, but "synthesis of these records
    # will only occur when the query exactly matches the record", so a denial
    # record whose signature expanded is a denial record that was moved.
    #
    # `wdtest.` carries the same mistake on the other side of the same routine:
    # a DS RRset whose signature expanded. The digest binds the child's name, so
    # a plain replay of some other DS does not survive `ds_matches` - the one
    # here is what a signer that expanded a wildcard DS would emit, and the
    # chain walk must still refuse to take a zone cut from it.
    root = Key(".", "wcard-root")
    wc = Key("wctest.", "wcard-zone")

    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("wc_root_dnskey", ".", "DNSKEY", message(".", DNSKEY, root_keys + [sign(root_keys, root)]))

    wc_ds = [RR(wc.zone, DS, wc.ds())]
    emit("wc_ds", wc.zone, "DS", message(wc.zone, DS, wc_ds + [sign(wc_ds, root)]))
    wc_keys = [RR(wc.zone, DNSKEY, wc.rdata)]
    emit("wc_dnskey", wc.zone, "DNSKEY", message(wc.zone, DNSKEY, wc_keys + [sign(wc_keys, wc)]))

    # The zone as it really is: an apex, a wildcard holding an A, and one
    # ordinary name holding an A and a TXT. Canonical order puts `*` before `r`,
    # so the chain is wctest. -> *.wctest. -> real.wctest. -> wctest.
    wc_soa = [soa_rr("wctest.")]
    wc_soa_sig = sign(wc_soa, wc)
    wild_rdata = nsec_rdata("real.wctest.", [A, RRSIG, NSEC])
    wild_nsec = [RR("*.wctest.", NSEC, wild_rdata)]
    # Labels 1, because RFC 4034 section 3.1.3 does not count the asterisk. This
    # is the signature the attack below reuses unchanged.
    wild_sig = sign(wild_nsec, wc)
    real_nsec = [RR("real.wctest.", NSEC, nsec_rdata("wctest.", [A, TXT, RRSIG, NSEC]))]
    real_sig = sign(real_nsec, wc)

    # The chain walk asks for a DS at each name on the way down. `real.wctest.`
    # is an ordinary name, so its own NSEC answers; `www.wctest.` does not exist,
    # so the wildcard's NSEC matches and `real.wctest.`'s covers it.
    emit("wc_real_ds", "real.wctest.", "DS",
         message("real.wctest.", DS, [], real_nsec + [real_sig] + wc_soa + [wc_soa_sig]))
    emit("wc_www_ds", "www.wctest.", "DS",
         message("www.wctest.", DS, [],
                 real_nsec + [real_sig] + wild_nsec + [wild_sig] + wc_soa + [wc_soa_sig]))

    # The attack. The wildcard's NSEC RDATA and its RRSIG, both verbatim, under
    # a rewritten owner: NODATA for `real.wctest. TXT`, which the zone really
    # holds and the wildcard's bit map does not list.
    relocated = [RR("real.wctest.", NSEC, wild_rdata), RR("real.wctest.", RRSIG, wild_sig.rdata)]
    emit("wc_relocated_nodata", "real.wctest.", "TXT",
         message("real.wctest.", TXT, [], relocated + wc_soa + [wc_soa_sig]))

    # The same two records again, under two owners chosen so that the spans
    # cover both what an NXDOMAIN has to deny: `s.wctest. -> real.wctest.` wraps
    # and so covers `www.wctest.`, and `!.wctest. -> real.wctest.` covers the
    # wildcard itself, since `!` sorts before `*`.
    relocated_nx = [
        RR("s.wctest.", NSEC, wild_rdata), RR("s.wctest.", RRSIG, wild_sig.rdata),
        RR("!.wctest.", NSEC, wild_rdata), RR("!.wctest.", RRSIG, wild_sig.rdata),
    ]
    emit("wc_relocated_nxdomain", "www.wctest.", "A",
         message("www.wctest.", A, [], relocated_nx + wc_soa + [wc_soa_sig], rcode=3), rcode=3)

    # The control, and the reason the refusal cannot simply be "the signature
    # expanded": a wildcard has an NSEC of its own, published under `*.wctest.`,
    # and it is what proves NODATA for a type the wildcard does not hold. Its
    # Labels field is not short - the asterisk is a label the name really has -
    # so this one has to keep working.
    emit("wc_wildcard_nodata", "www.wctest.", "TXT",
         message("www.wctest.", TXT, [],
                 wild_nsec + [wild_sig] + real_nsec + [real_sig] + wc_soa + [wc_soa_sig]))

    # The same relocation one section over. An answer-section NSEC is not a
    # proof of anything here, so this one is not an NXDOMAIN forged - it is an
    # authenticated statement about `nx.wctest.` that the zone never made,
    # carrying a chosen next-name and a chosen type bit map, going out at AD=1
    # and into the cache for whatever reads it there.
    #
    # The authority section is the genuine `*.wctest. NSEC`, unmodified, which
    # really does cover `nx.wctest.` - so the RFC 4035 section 5.3.4 proof the
    # answer's short Labels field calls for is one an attacker can make. That
    # the proof succeeds is the point: the expansion is provable and the record
    # is still forged, because RFC 4592 section 4.7 has an NSEC synthesised
    # only for a query that matches it exactly.
    moved_nsec = [RR("nx.wctest.", NSEC, wild_rdata), RR("nx.wctest.", RRSIG, wild_sig.rdata)]
    emit("wc_relocated_answer_nsec", "nx.wctest.", "NSEC",
         message("nx.wctest.", NSEC, moved_nsec,
                 wild_nsec + [wild_sig] + wc_soa + [wc_soa_sig]))
    # The chain walk asks for a DS at `nx.wctest.` on the way to that answer.
    # The wildcard matches the name and its NSEC denies the type; `real.wctest.`
    # is what proves no closer name exists.
    emit("wc_nx_ds", "nx.wctest.", "DS",
         message("nx.wctest.", DS, [],
                 wild_nsec + [wild_sig] + real_nsec + [real_sig] + wc_soa + [wc_soa_sig]))

    # The same refusal is owed to the other types that are never synthesised
    # from a wildcard, and these two do not come from rewriting an owner: a
    # relocated DS or SOA changes the signing input and the signature dies.
    # They are what a signer that wildcard signed a DS or an apex SOA emits,
    # which is the shape `wdtest.` already models for the chain walk - the
    # answer section is the one place left that took them.
    #
    # RFC 4592 section 4.6 has a DS at a wildcard "meaningless and harmless",
    # and section 4.1 has a wildcard owning an SOA be the apex, which cannot be
    # a source of synthesis. Neither expansion is a thing a zone can mean.
    nx = Key("nx.wctest.", "wcard-nxchild")
    nx_ds = [RR("nx.wctest.", DS, nx.ds())]
    emit("wc_expanded_ds_answer", "nx.wctest.", "DS",
         message("nx.wctest.", DS, nx_ds + [sign(nx_ds, wc, labels=1)],
                 wild_nsec + [wild_sig] + wc_soa + [wc_soa_sig]))
    nx_soa = [soa_rr("nx.wctest.")]
    emit("wc_expanded_soa_answer", "nx.wctest.", "SOA",
         message("nx.wctest.", SOA, nx_soa + [sign(nx_soa, wc, labels=1)],
                 wild_nsec + [wild_sig] + wc_soa + [wc_soa_sig]))
    wildcard_expanded_ds(root)
    wildcard_dname(root)


def wildcard_expanded_ds(root):
    """Emit `wdtest.`, whose DS at one child was signed as a wildcard expansion."""
    wd = Key("wdtest.", "wcard-dszone")
    ev = Key("evil.wdtest.", "wcard-evil")
    fi = Key("fine.wdtest.", "wcard-fine")

    ds_set = [RR(wd.zone, DS, wd.ds())]
    emit("wd_ds", wd.zone, "DS", message(wd.zone, DS, ds_set + [sign(ds_set, root)]))
    keys = [RR(wd.zone, DNSKEY, wd.rdata)]
    emit("wd_dnskey", wd.zone, "DNSKEY", message(wd.zone, DNSKEY, keys + [sign(keys, wd)]))

    # A DS set at `evil.wdtest.` whose digest names that child, so it
    # matches the key served below, but whose signature was computed over
    # `*.wdtest.`. Taking the cut means the walk moves to keys the parent never
    # attested under this name.
    evil_ds = [RR("evil.wdtest.", DS, ev.ds())]
    emit("wd_evil_ds", "evil.wdtest.", "DS",
         message("evil.wdtest.", DS, evil_ds + [sign(evil_ds, wd, labels=1)]))
    evil_keys = [RR("evil.wdtest.", DNSKEY, ev.rdata)]
    emit("wd_evil_dnskey", "evil.wdtest.", "DNSKEY",
         message("evil.wdtest.", DNSKEY, evil_keys + [sign(evil_keys, ev)]))
    evil_a = [a_rr("evil.wdtest.", "192.0.2.66")]
    emit("wd_evil_answer", "evil.wdtest.", "A",
         message("evil.wdtest.", A, evil_a + [sign(evil_a, ev)]))

    # The control for that one: the same delegation shape a label over, with the
    # DS signed at its own name. Everything else about the two is identical, so
    # a chain that came apart here fails this one too rather than passing the
    # refusal off as a verdict about the Labels field.
    fine_ds = [RR("fine.wdtest.", DS, fi.ds())]
    emit("wd_fine_ds", "fine.wdtest.", "DS",
         message("fine.wdtest.", DS, fine_ds + [sign(fine_ds, wd)]))
    fine_keys = [RR("fine.wdtest.", DNSKEY, fi.rdata)]
    emit("wd_fine_dnskey", "fine.wdtest.", "DNSKEY",
         message("fine.wdtest.", DNSKEY, fine_keys + [sign(fine_keys, fi)]))
    fine_a = [a_rr("fine.wdtest.", "192.0.2.67")]
    emit("wd_fine_answer", "fine.wdtest.", "A",
         message("fine.wdtest.", A, fine_a + [sign(fine_a, fi)]))


def wildcard_dname(root):
    """Emit `dwtest.`, which holds a wildcard DNAME and one ordinary name."""
    # The third caller of the same routine. `dname_covered` asks
    # `validate_rrset` about the DNAME and reads only the status, so on its own
    # it would vouch for an unsigned CNAME under a DNAME re-owned to a name the
    # wildcard does not stand for. What stops that is not there: the DNAME sits
    # in the answer section, so `validate_answer`'s own loop validates the same
    # RRset, records the expansion, and makes the RFC 4035 section 5.3.4 proof
    # a condition of the whole message.
    #
    # Both fixtures are here so that stays true, and so that the guard this
    # scenario is about is not copied to a site where it would refuse the
    # legitimate one: a DNAME may sit at a wildcard like any other type, and
    # then every redirection it makes carries an RRSIG one label short.
    dw = Key("dwtest.", "wcard-dname")
    ds_set = [RR(dw.zone, DS, dw.ds())]
    emit("dw_ds", dw.zone, "DS", message(dw.zone, DS, ds_set + [sign(ds_set, root)]))
    keys = [RR(dw.zone, DNSKEY, dw.rdata)]
    emit("dw_dnskey", dw.zone, "DNSKEY", message(dw.zone, DNSKEY, keys + [sign(keys, dw)]))

    soa = [soa_rr("dwtest.")]
    soa_sig = sign(soa, dw)
    # dwtest. -> *.dwtest. -> real.dwtest. -> dwtest. `real.dwtest.` is what
    # makes the relocation below a forgery rather than an expansion: the
    # wildcard does not stand for a name the zone already holds.
    wild_nsec = [RR("*.dwtest.", NSEC, nsec_rdata("real.dwtest.", [DNAME, RRSIG, NSEC]))]
    wild_nsec_sig = sign(wild_nsec, dw)
    real_nsec = [RR("real.dwtest.", NSEC, nsec_rdata("dwtest.", [A, RRSIG, NSEC]))]
    real_nsec_sig = sign(real_nsec, dw)
    denial = wild_nsec + [wild_nsec_sig] + real_nsec + [real_nsec_sig] + soa + [soa_sig]

    # The chain walk asks for a DS at each name on the way down, and none of
    # these four is a zone cut. `real.dwtest.`'s NSEC covers everything after
    # it, its own name included, so one denial answers all of them.
    for tag, name in (("y", "y.dwtest."), ("xy", "x.y.dwtest."),
                      ("real", "real.dwtest."), ("xreal", "x.real.dwtest.")):
        emit("dw_%s_ds" % tag, name, "DS", message(name, DS, [], denial))

    # The redirection as a server sends it: the DNAME under the name the
    # wildcard was expanded to, its RRSIG still counting one label, and the
    # CNAME synthesised from it, unsigned per RFC 6672 section 3.4.1. The
    # authority section carries the proof that `y.dwtest.` is not in the zone,
    # and no SOA, because nothing here is being denied.
    dname_rr = [RR("y.dwtest.", DNAME, wire_name("t.example."))]
    dname_sig = sign(dname_rr, dw, labels=1)
    cname = [RR("x.y.dwtest.", CNAME, wire_name("x.t.example."))]
    emit("dw_wildcard_dname", "x.y.dwtest.", "A",
         message("x.y.dwtest.", A, dname_rr + [dname_sig] + cname,
                 real_nsec + [real_nsec_sig]))

    # The same two records with the DNAME's owner rewritten to `real.dwtest.`,
    # which the zone holds and the wildcard therefore never stands for. The
    # proof that would have to accompany it is a denial of a name that exists,
    # so there is none to send.
    moved = [RR("real.dwtest.", DNAME, wire_name("t.example.")),
             RR("real.dwtest.", RRSIG, dname_sig.rdata)]
    moved_cname = [RR("x.real.dwtest.", CNAME, wire_name("x.t.example."))]
    emit("dw_relocated_dname", "x.real.dwtest.", "A",
         message("x.real.dwtest.", A, moved + moved_cname))


@scenario
def nsec3_name_error():
    """Cover a name error proven with NSEC3 in a zone whose chain holds up."""
    # Every other NSEC3 fixture here is a DS denial, where the walk down to the
    # name settles the question before the answer's own proof is read - under
    # opt-out the name comes back as an unsigned delegation, and without it the
    # step answers from a record on the name itself. Neither reaches
    # `validate_denial`'s NSEC3 proof, which is the one that hashes a closest
    # encloser, a next closer name and a wildcard.
    #
    # `n3test.` is that shape: signed, no opt-out, and asked about a name two
    # labels below its apex so the proof has to walk. The same three records
    # answer the DS lookup the chain walk makes on the way down, because they
    # are the denial that zone really sends for anything under `deep.n3test.`.
    root = Key(".", "n3err-root")
    zone = Key("n3test.", "n3err-zone")

    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("n3_root_dnskey", ".", "DNSKEY",
         message(".", DNSKEY, root_keys + [sign(root_keys, root)]))

    ds_set = [RR(zone.zone, DS, zone.ds())]
    emit("n3_ds", zone.zone, "DS", message(zone.zone, DS, ds_set + [sign(ds_set, root)]))
    keys = [RR(zone.zone, DNSKEY, zone.rdata)]
    emit("n3_dnskey", zone.zone, "DNSKEY", message(zone.zone, DNSKEY, keys + [sign(keys, zone)]))

    # Two names, so the chain is two spans and everything the zone does not hold
    # falls inside one of them. A two-byte salt and twelve iterations: what is
    # under test is how much hashing the proof asks for rather than how dear one
    # hash is, but the count is not zero, so a validator whose ceiling is below
    # it has something to refuse and the ceiling is carried from the
    # configuration to the proof by the test rather than by assertion.
    salt = bytes.fromhex("0e0f")
    chain = nsec3_chain(
        "n3test.",
        [
            ("n3test.", [A, NS, SOA, RRSIG, DNSKEY, NSEC3PARAM]),
            ("a.n3test.", [A, RRSIG]),
        ],
        salt,
        12,
    )

    # Each NSEC3 is its own owner name and so its own RRset, with a signature of
    # its own - a validator that verified one and read all of them would be
    # taking the rest on trust.
    authority = []
    for record in (chain["n3test."], chain["a.n3test."]):
        authority += [record, sign([record], zone)]

    # The reply under test, and the DS denial the walk reads on its way to it.
    emit("n3_nx", "nx.deep.n3test.", "A",
         message("nx.deep.n3test.", A, [], authority, rcode=3), rcode=3)
    emit("n3_deep_ds", "deep.n3test.", "DS",
         message("deep.n3test.", DS, [], authority, rcode=3), rcode=3)


@scenario
def deep_run_of_empty_non_terminals():
    """Cover a zone that answers every DS below its apex with a minted NSEC."""
    # RFC 4470 lets a zone answer a name it does not hold with an NSEC minted
    # for the question, and such a record says the name is there and carries no
    # NS - which is exactly an empty non-terminal. A zone serving those answers
    # every label of every name that way, so a client asking for a name eight
    # labels deep has the chain walk descend all eight, one blocking DS lookup
    # apiece, for one question. Nothing here is forged: every record verifies
    # against the zone's own key, which is what makes the cost real.
    #
    # `drtest.` is that zone, and `l1.l2.l3.l4.l5.l6.l7.l8.drtest.` the name.
    root = Key(".", "deeprun-root")
    zone = Key("drtest.", "deeprun-zone")

    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("dr_root_dnskey", ".", "DNSKEY", message(".", DNSKEY, root_keys + [sign(root_keys, root)]))

    ds_set = [RR("drtest.", DS, zone.ds())]
    emit("dr_ds", "drtest.", "DS", message("drtest.", DS, ds_set + [sign(ds_set, root)]))

    zone_keys = [RR("drtest.", DNSKEY, zone.rdata)]
    emit("dr_dnskey", "drtest.", "DNSKEY",
         message("drtest.", DNSKEY, zone_keys + [sign(zone_keys, zone)]))

    # One DS denial per label of the name, each minted for the name asked about.
    # No NS bit, so none of them is a delegation, and the walk has to keep going
    # past every one of them.
    # The next name is the epsilon successor RFC 4470 section 3.1 asks for - the
    # queried name with a leading zero-octet label - and not something like
    # `zz.<name>`. The span of an NSEC denies everything strictly inside it, so a
    # next name any further along would have these records denying real names
    # below them, `sub.` among them.
    labels = ["l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8"]
    for i, label in enumerate(labels):
        name = ".".join(labels[i:]) + ".drtest."
        minted = [RR(name, NSEC, nsec_rdata("\x00." + name, [RRSIG, NSEC]))]
        emit("dr_ds_%s" % label, name, "DS",
             message(name, DS, [], minted + [sign(minted, zone)]))

    # And the question itself: NODATA at the deepest name, denied the same way.
    qname = ".".join(labels) + ".drtest."
    minted = [RR(qname, NSEC, nsec_rdata("\x00." + qname, [RRSIG, NSEC]))]
    emit("dr_nodata", qname, "A", message(qname, A, [], minted + [sign(minted, zone)]))

    # A real zone cut at the bottom of the run, so that "the walk may skip the
    # descent" can never quietly become "the walk may stop descending". Its DS
    # is signed by `drtest.`, which is the closest zone above it - everything in
    # between being no cut at all.
    sub = Key("sub." + qname, "deeprun-sub")
    sub_ds = [RR(sub.zone, DS, sub.ds())]
    emit("dr_sub_ds", sub.zone, "DS", message(sub.zone, DS, sub_ds + [sign(sub_ds, zone)]))

    sub_keys = [RR(sub.zone, DNSKEY, sub.rdata)]
    emit("dr_sub_dnskey", sub.zone, "DNSKEY",
         message(sub.zone, DNSKEY, sub_keys + [sign(sub_keys, sub)]))

    sub_answer = [RR(sub.zone, A, bytes([192, 0, 2, 1]))]
    emit("dr_sub_answer", sub.zone, "A",
         message(sub.zone, A, sub_answer + [sign(sub_answer, sub)]))

    # A DS answer whose denial verifies but speaks for some other name, which is
    # what a step reads as broken. It stands in for the one way a remembered
    # non-cut turns harmful: the name it names stops existing, the walk skips it
    # on the memo's word, and the denial that comes back is for a name one label
    # too far down - under NSEC3 that is neither matched nor covered. The walk
    # has to forget the name above rather than keep reading it for an hour.
    stray = [RR("zzz.drtest.", NSEC, nsec_rdata("\x00.zzz.drtest.", [RRSIG, NSEC]))]
    emit("dr_stray_denial", "b.c.drtest.", "DS",
         message("b.c.drtest.", DS, [], stray + [sign(stray, zone)]))

    # And the same step broken the other way: a DS answer with nothing in it to
    # read. That is what a delegation appearing at a remembered non-cut looks
    # like from here - the question lands inside the new child zone, and what it
    # signs is not the parent's to verify, so the denial is dropped and both
    # slices come back empty.
    emit("dr_bare_ds", "e.f.drtest.", "DS", message("e.f.drtest.", DS, []))

    # A NODATA from the zone below the run, for the denial path's own version of
    # the heal: the answer path reaches `validate_rrset`, a denial reaches
    # `validate_denial`, and each has to give back a name the walk could not
    # reach on its own account.
    sub_nodata = [RR(sub.zone, NSEC,
                     nsec_rdata("zz." + sub.zone, [A, NS, SOA, RRSIG, NSEC, DNSKEY]))]
    emit("dr_sub_nodata", sub.zone, "AAAA",
         message(sub.zone, AAAA, [], sub_nodata + [sign(sub_nodata, sub)]))

    # The parent's own record at the zone cut: NS set, SOA clear, which is what
    # a delegation NSEC looks like. Its span swallows everything under `sub.`,
    # the wildcard included - but RFC 6840 section 4.1 says a record from the
    # parent side of a cut speaks for nothing below it, so it must not be
    # allowed to deny a name inside the child. Signed by `drtest.`, because the
    # parent is who publishes it.
    deleg = [RR(sub.zone, NSEC, nsec_rdata("zz." + sub.zone, [NS, RRSIG, NSEC]))]
    emit("dr_delegation_nsec", "www." + sub.zone, "A",
         message("www." + sub.zone, A, [], deleg + [sign(deleg, zone)], rcode=3), rcode=3)
    # The same record answering the DS the walk asks on its way down, which is
    # what lets the walk settle on the parent and read the denial above against
    # the parent's keys. Whoever can put the one in front of the validator can
    # put the other.
    emit("dr_www_ds", "www." + sub.zone, "DS",
         message("www." + sub.zone, DS, [], deleg + [sign(deleg, zone)], rcode=3), rcode=3)


if __name__ == "__main__":
    wanted = sys.argv[1:] or list(SCENARIOS)
    for name in wanted:
        print("\n// ==== %s ====" % name)
        print("// " + (SCENARIOS[name].__doc__ or "").strip().replace("\n", "\n// "))
        SCENARIOS[name]()
