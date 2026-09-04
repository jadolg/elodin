package server

import "core:net"
import "core:sync"
import "core:testing"
import "core:time"

/*
The connection limit is `len(threads) - permanent`, so `permanent` has to keep
meaning what it says for as long as the manager runs.

Then how that limit is shared out. `max_connections` is one budget for the whole
server and nothing else counts connections per client - the rate limiter charges
queries, so connections opened and left idle are free - so without a per-prefix
share one client may hold every slot there is.
*/

@(private = "file")
returns_immediately :: proc(data: rawptr) {}

@(private = "file")
Held :: struct {
	go: bool,
}

@(private = "file")
holds_until_released :: proc(data: rawptr) {
	h := cast(^Held)data
	for !sync.atomic_load(&h.go) {
		time.sleep(time.Millisecond)
	}
}

@(private = "file")
wait_for_reap :: proc(cm: ^Conn_Manager, want: int) -> int {
	deadline := time.time_add(time.now(), 2 * time.Second)
	got := active_connections(cm)
	for got != want && time.diff(time.now(), deadline) > 0 {
		time.sleep(time.Millisecond)
		got = active_connections(cm)
	}
	return got
}

/*
Reaping a listener loop must take it off the permanent tally too.

The loops are excluded from the connection limit by being counted separately
and subtracted. `reap_locked` removed a finished thread from the list without
touching that count, so once a loop had been reaped the subtraction was against
a number that no longer described anything: the total goes negative, and the
limit stops holding for as many connections as there were loops.
*/
@(test)
test_reaping_a_permanent_thread_keeps_the_count_honest :: proc(t: ^testing.T) {
	cm: Conn_Manager
	// No per-prefix share, which is this case's subject: the total limit alone.
	conn_manager_init(&cm, 1, 0)
	defer conn_manager_shutdown(&cm)

	// A listener loop, as `start_udp` and `start_stream_listener` register one,
	// that then finishes - which is what shutdown does to all of them.
	testing.expect_value(t, conn_spawn(&cm, nil, returns_immediately, counted = false), Spawn_Result.Started)
	testing.expect_value(t, wait_for_reap(&cm, 0), 0)

	// With the tally corrected, the one slot the limit allows is still one slot.
	held := Held{}
	defer sync.atomic_store(&held.go, true)
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released), Spawn_Result.Started)
	testing.expect_value(t, active_connections(&cm), 1)
	/*
	And the refusal says which of the two it was.

	`Limit_Reached` and `Thread_Failed` ask an operator for opposite things -
	raise the limit, or find out what stopped the OS giving this process a
	thread - so the accept loop counts and reports them apart. A boolean could
	not tell them apart, and named `max_connections` for both.
	*/
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released), Spawn_Result.Limit_Reached)
}

/*
One client must not be able to hold every slot in the table.

This is the whole of the finding: `max_connections` bounded how many connections
existed and nothing bounded whose they were, so 512 of them from one source
address were 512 the rest of the network could not have. The limiter does not
reach it either - what it charges is opening a connection and the queries asked
over it, both of them rates a client can stay inside while never letting go - so a
client that opens connections slowly and sits there is, to every counter this
server keeps, several well-behaved clients.

Two slots each out of four, so the case can tell a share being full from the
table being full: the third connection from the flooded /24 is refused with half
the table still free, and the bystander in the next /24 along is served out of
it. A cap that had been checked against the total instead would let the third one
through, and one that had refused everybody past two would fail the last line.
*/
@(test)
test_one_prefix_cannot_hold_every_slot :: proc(t: ^testing.T) {
	cm: Conn_Manager
	conn_manager_init(&cm, 4, 2)
	defer conn_manager_shutdown(&cm)

	held := Held{}
	defer sync.atomic_store(&held.go, true)

	// Two addresses in one /24 and one in the next, which is the granularity
	// `client_prefix` reads a client at - so the first two are the same client
	// here however different they look.
	flood := client_prefix(net.IP4_Address{192, 0, 2, 1})
	flood_again := client_prefix(net.IP4_Address{192, 0, 2, 200})
	bystander := client_prefix(net.IP4_Address{192, 0, 3, 1})

	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released, flood), Spawn_Result.Started)
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released, flood_again), Spawn_Result.Started)
	testing.expect_value(
		t,
		conn_spawn(&cm, &held, holds_until_released, flood),
		Spawn_Result.Prefix_Limit_Reached,
	)
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released, bystander), Spawn_Result.Started)
	// Three of four taken, so the refusal above was not the table running out.
	testing.expect_value(t, active_connections(&cm), 3)
}

/*
The same for IPv6, where the client is a /64.

Worth its own case rather than trusting the v4 one: the two arms of
`client_prefix` are separate code, and a /64 read as a /128 would make every
address in a client's own network a client of its own - which is the granularity
an attacker with a routed prefix picks addresses within, and so the granularity
at which a cap is not a cap.
*/
@(test)
test_the_prefix_share_holds_for_v6_too :: proc(t: ^testing.T) {
	cm: Conn_Manager
	conn_manager_init(&cm, 4, 1)
	defer conn_manager_shutdown(&cm)

	held := Held{}
	defer sync.atomic_store(&held.go, true)

	// 2001:db8::1 and 2001:db8::dead:beef, which differ below the /64 and are
	// therefore one client; then 2001:db8:0:1::1, which is the next /64 along.
	client := client_prefix(net.IP6_Address{0x2001, 0x0db8, 0, 0, 0, 0, 0, 1})
	same_64 := client_prefix(net.IP6_Address{0x2001, 0x0db8, 0, 0, 0, 0, 0xdead, 0xbeef})
	next_64 := client_prefix(net.IP6_Address{0x2001, 0x0db8, 0, 1, 0, 0, 0, 1})

	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released, client), Spawn_Result.Started)
	testing.expect_value(
		t,
		conn_spawn(&cm, &held, holds_until_released, same_64),
		Spawn_Result.Prefix_Limit_Reached,
	)
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released, next_64), Spawn_Result.Started)
}

/*
A connection that ends gives its client's share back.

The share is counted off the thread list rather than kept in a table beside it,
which is what makes this true by construction: the same `reap_locked` that
returns the slot returns the share, and there is no second place for the two to
disagree. A count that was incremented on accept and decremented at the far end
of a connection handler would be one refusal away from leaking a share
permanently - and a leaked share is a client this server refuses for the rest of
its uptime, on the strength of connections that ended.
*/
@(test)
test_a_finished_connection_gives_its_share_back :: proc(t: ^testing.T) {
	cm: Conn_Manager
	conn_manager_init(&cm, 4, 1)
	defer conn_manager_shutdown(&cm)

	client := client_prefix(net.IP4_Address{192, 0, 2, 1})
	testing.expect_value(t, conn_spawn(&cm, nil, returns_immediately, client), Spawn_Result.Started)
	testing.expect_value(t, wait_for_reap(&cm, 0), 0)

	held := Held{}
	defer sync.atomic_store(&held.go, true)
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released, client), Spawn_Result.Started)
}

/*
A full table is reported as a full table, whoever filled it.

Both refusals can be true of the same connection - the table is full, and this
prefix was not entitled to the slot it wanted anyway - and the two send an
operator to different settings. The total is the one to name there: it is a fact
about the server rather than about the client, and it is what would have to be
raised before the next connection from *anywhere* could be served. Reported the
other way round, an operator would raise the per-prefix share and watch nothing
change.
*/
@(test)
test_a_full_table_is_not_blamed_on_the_client :: proc(t: ^testing.T) {
	cm: Conn_Manager
	conn_manager_init(&cm, 2, 2)
	defer conn_manager_shutdown(&cm)

	held := Held{}
	defer sync.atomic_store(&held.go, true)

	client := client_prefix(net.IP4_Address{192, 0, 2, 1})
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released, client), Spawn_Result.Started)
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released, client), Spawn_Result.Started)
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released, client), Spawn_Result.Limit_Reached)
}

/*
No share configured is the behaviour this server had before there was one.

`max_connections_per_prefix` at or above `max_connections` is stored as no cap,
which an operator asks for by saying so - a resolver serving one large NAT, where
every client is one prefix, and where a share would be the outage rather than the
defence. It has to keep working: one client taking the whole table is a bad
default, not a state to make unreachable.
*/
@(test)
test_no_share_lets_one_client_have_the_table :: proc(t: ^testing.T) {
	cm: Conn_Manager
	conn_manager_init(&cm, 3, 0)
	defer conn_manager_shutdown(&cm)

	held := Held{}
	defer sync.atomic_store(&held.go, true)

	client := client_prefix(net.IP4_Address{192, 0, 2, 1})
	for i in 0 ..< 3 {
		testing.expectf(
			t,
			conn_spawn(&cm, &held, holds_until_released, client) == .Started,
			"connection %d from one prefix was refused with no share configured",
			i + 1,
		)
	}
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released, client), Spawn_Result.Limit_Reached)
}

/*
The server's own loops are nobody's client.

They are already outside the total - `permanent` is subtracted from it - and they
have to be outside the shares too. Counted as a client, the accept loops and the
UDP reader would spend the share of whichever prefix the zero value collides
with, which is every client whose address neither arm of `client_prefix`
recognises: a share of one would then be spent before the first connection
arrived.
*/
@(test)
test_the_listener_loops_spend_nobodys_share :: proc(t: ^testing.T) {
	cm: Conn_Manager
	conn_manager_init(&cm, 4, 1)
	defer conn_manager_shutdown(&cm)

	held := Held{}
	defer sync.atomic_store(&held.go, true)

	testing.expect_value(
		t,
		conn_spawn(&cm, &held, holds_until_released, counted = false),
		Spawn_Result.Started,
	)
	client := client_prefix(net.IP4_Address{192, 0, 2, 1})
	testing.expect_value(t, conn_spawn(&cm, &held, holds_until_released, client), Spawn_Result.Started)
}
