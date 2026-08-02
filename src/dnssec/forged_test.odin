package dnssec

/*
A zone built for one purpose: two DNSKEY records whose RDATA folds to the same
key tag, 37443, both Ed25519.

The parent's DS attests exactly one of them. `HONEST_DNSKEY` is the set signed
by that key, which must validate. `FORGED_DNSKEY` is the same set signed by the
other key of the same tag, which must not - a key tag is a 16-bit fold, not an
identity, and an attacker able to publish a second key under one is exactly what
binds the DS to nothing if the verifier picks its key by tag.

Generated rather than captured, because no real zone would publish this. The
honest half is what makes the forged half meaningful: it fails too if the
canonical form here ever stops matching the validator's.
*/

FORGED_ZONE :: "test."
FORGED_KEY_TAG :: 37443
FORGED_DS_DIGEST :: "31d327c36bc808bbb222c0b8dd4d5fd706ec84bf570e9b652dfaca99283b9e4e"

HONEST_DNSKEY :: "123481800001000300000000047465737400003000010474657374000030000100000e1000240101030fc6a8381fe38ec1312ec459b655ab771ee63b6d66c5b4ecd721212cbcd91368460474657374000030000100000e1000240101030faaef025859fe7c779e26b74e0ba52841eb2e7434b12041ae7f7b9195e2c13b15047465737400002e000100000e10005800300f0100000e10832156005f5e100092430474657374003293cd6274c8d7d8e368a871765270163da48ac507eadd4cad13ed86aa8a06bf0dc1e539547085fae06bbc26b8828b7e39631c749bd0c92b44dda5a54f8ae40e"

FORGED_DNSKEY :: "123481800001000300000000047465737400003000010474657374000030000100000e1000240101030fc6a8381fe38ec1312ec459b655ab771ee63b6d66c5b4ecd721212cbcd91368460474657374000030000100000e1000240101030faaef025859fe7c779e26b74e0ba52841eb2e7434b12041ae7f7b9195e2c13b15047465737400002e000100000e10005800300f0100000e10832156005f5e100092430474657374005187825eb630ae8e90b7f7eeb382ba5370426dc38933a6cf3d97b3b084d1e6910e1d51c791de2cdd172cd014276e62dfb291e7116830ac7e7b2933eaad383c06"

