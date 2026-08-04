package dns

import "core:testing"

/*
What can be checked about a random transaction ID from inside the process.

Not that it is unpredictable - a test cannot establish that - but that it is
drawn rather than derived: a constant, a counter, or a value that only moves
every so often all fail here, and those are the shapes the mistake takes.
*/
@(test)
test_random_id_is_drawn_fresh :: proc(t: ^testing.T) {
	DRAWS :: 4096

	seen: map[u16]bool
	defer delete(seen)

	sequential := 0
	previous := random_id()
	seen[previous] = true

	for _ in 1 ..< DRAWS {
		id := random_id()
		if id == previous + 1 {
			sequential += 1
		}
		seen[id] = true
		previous = id
	}

	/*
	4096 draws from 16 bits collide about 120 times by the birthday bound, so
	the count lands near 3970 and the floor sits well below that while still
	being far above anything a small or repeating set of values could reach.
	*/
	testing.expectf(t, len(seen) > 3800, "only %d distinct ids in %d draws", len(seen), DRAWS)

	// A counter increments every time. Chance alone does it about once in 65536
	// draws, so a handful here would already be remarkable.
	testing.expectf(t, sequential < 8, "%d of %d ids were the previous one plus one", sequential, DRAWS)

	// Both halves have to come from somewhere: a generator that filled only one
	// of the two bytes would pass the count above on a large enough sample.
	high, low: map[u8]bool
	defer delete(high)
	defer delete(low)
	for id in seen {
		high[u8(id >> 8)] = true
		low[u8(id)] = true
	}
	testing.expectf(t, len(high) == 256, "only %d distinct high bytes", len(high))
	testing.expectf(t, len(low) == 256, "only %d distinct low bytes", len(low))
}
