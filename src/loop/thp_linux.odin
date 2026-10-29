#+build linux
package loop

import "core:sys/linux"

@(private)
PR_SET_THP_DISABLE :: 41

/*
Keep transparent huge pages off every mapping this process makes (#526).
`main` calls it before its first thread.

glibc gives each thread that allocates at once a heap of its own, up to eight
per core, and `spawn` maps each thread's scratch arena itself. Under THP
`always`, or `madvise` with glibc's heaps advised, the kernel backs those with
2 MB pages - fully resident once a single page in one is touched, so 200
connections at once left 64 MB behind. A process-wide flag rather than advice
per mapping or `GLIBC_TUNABLES`: it covers glibc's heaps and elodin's own
mappings alike, however the process was started. Nothing here is large and hot
enough for a huge page to pay for itself. Advice only: a kernel without THP
refuses it, and nothing changes.
*/
disable_huge_pages :: proc() {
	_ = linux.prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0)
}
