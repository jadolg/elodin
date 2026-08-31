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
DS, RRSIG, NSEC, DNSKEY, NSEC3 = 43, 46, 47, 48, 50


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


def message(qname, qtype, answer, authority=(), additional=()):
    """One authoritative NOERROR reply, as the fixture query callback returns it."""
    header = struct.pack(
        "!HHHHHH", QID, FLAGS, 1, len(answer), len(authority), len(additional)
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

    root_keys = [RR(".", DNSKEY, root.rdata)]
    print("// anchor: %s" % root.ds_text())
    emit("sh_root_dnskey", ".", "DNSKEY", message(".", DNSKEY, root_keys + [sign(root_keys, root)]))

    for child in (zone, other):
        ds_set = [RR(child.zone, DS, child.ds())]
        emit("sh_%s_ds" % child.zone.rstrip("."), child.zone, "DS",
             message(child.zone, DS, ds_set + [sign(ds_set, root)]))
        keys = [RR(child.zone, DNSKEY, child.rdata)]
        emit("sh_%s_dnskey" % child.zone.rstrip("."), child.zone, "DNSKEY",
             message(child.zone, DNSKEY, keys + [sign(keys, child)]))

    def a(name, addr):
        """One A record, from a dotted-quad."""
        return RR(name, A, bytes(int(part) for part in addr.split(".")))

    def aaaa(name, addr):
        """One AAAA record, from the 16 bytes written as hex."""
        return RR(name, AAAA, bytes.fromhex(addr))

    def srv(name, target):
        """An SRV record at priority 0, weight 0, port 443."""
        return RR(name, SRV, struct.pack("!HHH", 0, 0, 443) + wire_name(target))

    def https(name, target):
        """A ServiceMode HTTPS record with no parameters."""
        return RR(name, HTTPS, struct.pack("!H", 1) + wire_name(target))

    def mx(name, target, preference=10):
        """One MX record."""
        return RR(name, MX, struct.pack("!H", preference) + wire_name(target))

    # A target inside the zone the answer already established: the common case,
    # and the one that costs no lookup at all because the zone's keys are in hand.
    answer = [srv("_svc._tcp.hinttest.", "svc.hinttest.")]
    hints = [a("svc.hinttest.", "192.0.2.10"), aaaa("svc.hinttest.", "20010db8000000000000000000000010")]
    emit("sh_srv_same_zone", "_svc._tcp.hinttest.", "SRV",
         message("_svc._tcp.hinttest.", SRV, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints[:1], zone), sign(hints[1:], zone)]))

    # A target in a second signed zone. Keeping this one means walking a chain
    # the answer never needed.
    answer = [https("alt.hinttest.", "edge.other.")]
    hints = [a("edge.other.", "198.51.100.20"), aaaa("edge.other.", "20010db8000000000000000000000020")]
    emit("sh_https_cross_zone", "alt.hinttest.", "HTTPS",
         message("alt.hinttest.", HTTPS, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints[:1], other), sign(hints[1:], other)]))

    # A ServiceMode TargetName of "." stands for the owner name (RFC 9460
    # section 2.5), so the hints to keep are the ones at the answer's own name.
    answer = [https("hinttest.", ".")]
    hints = [a("hinttest.", "192.0.2.1")]
    emit("sh_https_service_form", "hinttest.", "HTTPS",
         message("hinttest.", HTTPS, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints, zone)]))

    # One MX answer carrying every kind of record that must not survive it: the
    # exchange's AAAA with no signature at all, a validly signed address for a
    # name the answer never named, and an attacker's unsigned glue.
    answer = [mx("hinttest.", "mail.hinttest.")]
    signed = [a("mail.hinttest.", "192.0.2.30")]
    bystander = [a("bystander.hinttest.", "192.0.2.31")]
    additional = (
        signed + [sign(signed, zone)]
        + [aaaa("mail.hinttest.", "20010db8000000000000000000000030")]
        + bystander + [sign(bystander, zone)]
        + [a("ns.attacker.example.", "203.0.113.66")]
    )
    emit("sh_mx_mixed", "hinttest.", "MX",
         message("hinttest.", MX, answer + [sign(answer, zone)], additional=additional))

    # The signature is the zone's and covers this owner and type - over an
    # address that is not the one in the record beside it.
    answer = [srv("_svc._tcp.hinttest.", "svc.hinttest.")]
    genuine = [a("svc.hinttest.", "192.0.2.10")]
    emit("sh_forged_hint", "_svc._tcp.hinttest.", "SRV",
         message("_svc._tcp.hinttest.", SRV, answer + [sign(answer, zone)],
                 additional=[a("svc.hinttest.", "203.0.113.99"), sign(genuine, zone)]))

    # AliasMode - priority zero - is a redirection the client follows by name
    # (RFC 9460 section 2.4.2), so its target names no hint to keep even when a
    # perfectly good signed address for it is sitting in the section.
    answer = [RR("alias.hinttest.", HTTPS, struct.pack("!H", 0) + wire_name("edge.other."))]
    hints = [a("edge.other.", "198.51.100.20")]
    emit("sh_alias_mode", "alias.hinttest.", "HTTPS",
         message("alias.hinttest.", HTTPS, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints, other)]))

    # A hint that verifies against a wildcard. Nothing in the message proves the
    # name had no records of its own, and that proof lives in a section this
    # server never validated - so the signature holding up is not enough.
    answer = [https("alt2.hinttest.", "wild.hinttest.")]
    hints = [a("wild.hinttest.", "192.0.2.40")]
    emit("sh_wildcard_hint", "alt2.hinttest.", "HTTPS",
         message("alt2.hinttest.", HTTPS, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints, zone, labels=1)]))

    # A target in a zone nothing delegates to. The signature is real and the
    # chain cannot be built, which is the same as no signature at all here.
    answer = [https("alt3.hinttest.", "edge.nosuch.")]
    hints = [a("edge.nosuch.", "192.0.2.50")]
    emit("sh_unreachable_zone", "alt3.hinttest.", "HTTPS",
         message("alt3.hinttest.", HTTPS, answer + [sign(answer, zone)],
                 additional=hints + [sign(hints, nowhere)]))

    # Forty exchanges in forty zones, none of them reachable. What is being
    # counted is how many of them provoke a chain walk: a response naming more
    # targets than `MAX_HINT_TARGETS` must not buy a walk apiece, and must not
    # cost the answer its own verdict.
    answer = [mx("hinttest.", "mx%d.z%d." % (i, i), preference=i) for i in range(40)]
    additional = [a("mx%d.z%d." % (i, i), "192.0.2.%d" % (100 + i)) for i in range(40)]
    emit("sh_many_targets", "hinttest.", "MX",
         message("hinttest.", MX, answer + [sign(answer, zone)], additional=additional))


if __name__ == "__main__":
    wanted = sys.argv[1:] or list(SCENARIOS)
    for name in wanted:
        print("\n// ==== %s ====" % name)
        print("// " + (SCENARIOS[name].__doc__ or "").strip().replace("\n", "\n// "))
        SCENARIOS[name]()
