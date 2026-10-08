// Package clean makes strings that came from a workload safe to print.
package clean

import (
	"strings"
	"unicode"
)

// String drops control characters (which carry terminal escape sequences)
// and bidirectional overrides (which make text display differently from what
// it contains), and caps the result at max runes.
func String(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || isBidi(r) || r == unicode.ReplacementChar {
			continue
		}
		if n == max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// Name is for short identifiers such as package names and versions.
func Name(s string) string { return String(s, 128) }

// Message is for error text and other free-form output.
func Message(s string) string { return String(s, 512) }

func isBidi(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}
