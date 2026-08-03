# elodin DNSSEC survey

Measured on AMD Ryzen 7 PRO 6850U with Radeon Graphics (16 logical cores, 31 GB RAM, Linux 7.0.14-201.fc44.x86_64), elodin 0.1.0.

129 names asked through elodin with validation on, and asked again of 9.9.9.9:53.

| | |
|---|---|
| names agreeing on rcode and AD | 120 |
| names differing | 5 |
| authenticated here / by the reference | 66 / 71 |
| deliberately broken, refused | 4 |
| deliberately broken, served anyway | 0 |
| unanswered by one side or the other | 0 |

Where they differ:

| name | elodin | reference |
|---|---|---|
| cmu.edu | noerror | noerror + AD |
| comcast.net | noerror | noerror + AD |
| pir.org | noerror | noerror + AD |
| afilias.info | noerror | noerror + AD |
| kisa.or.kr | noerror | noerror + AD |

Every one of the five is signed with DNSSEC algorithm 5 or 7 — RSA/SHA-1 —
which this machine's OpenSSL refuses to compute at all under the Fedora and
RHEL crypto policy (`rh-allow-sha1-signatures = no`):

| name | DNSKEY algorithms |
|---|---|
| cmu.edu | 7 |
| comcast.net | 13, 5 |
| pir.org | 5 |
| afilias.info | 5 |
| kisa.or.kr | 7 |

So they come back served but unauthenticated rather than refused, which is the
safe direction and is what the DNSSEC section of the README describes. It is
still a silent downgrade, and it is a fact about the machine rather than about
the zone: the same names carry AD on a host whose OpenSSL will do SHA-1.

No false failure: every name that resolves at the reference resolver resolves
here, and all four deliberately broken zones are refused.
