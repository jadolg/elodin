package server

import "core:sys/posix"

/*
The server tests stand up real loopback listeners (TCP, UDP, DoT, DoH2) and
drive them with clients that hang up mid-exchange - a connection refused past
`max_connections`, a peer that closes while the server still has bytes to push.
The follow-up write then raises SIGPIPE, whose default disposition kills the
process; the live server ignores it (see main.odin) but the test runner does
not, so an ordinary teardown race turned into an intermittent exit-141 failure.

Ignore it once for the whole test binary, matching main. The write still fails
through the normal EPIPE path, so nothing that relies on the error is masked.
The sibling socket suites do the same per test (upstream_test.odin,
tlsx_test.odin); this package has too many network tests to guard one at a time.
*/
@(init)
ignore_sigpipe_in_tests :: proc "contextless" () {
	posix.sigignore(.SIGPIPE)
}
