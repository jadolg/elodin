#+build !linux
package loop

// Transparent huge pages are a Linux feature; see thp_linux.odin.
disable_huge_pages :: proc() {}
