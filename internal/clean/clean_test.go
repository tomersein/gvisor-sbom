package clean

import "testing"

func TestString(t *testing.T) {
	tests := []struct {
		name, in, want string
		max            int
	}{
		{"plain", "requests", "requests", 128},
		{"ansi escape", "evil\x1b[2K\x1b[1Arequests", "evil[2K[1Arequests", 128},
		{"newline injection", "pkg\n  + fake-package 1.0", "pkg  + fake-package 1.0", 128},
		{"bidi override", "admin‮gnp.exe", "admingnp.exe", 128},
		{"invalid utf8", "a\xffb", "ab", 128},
		{"truncated", "abcdef", "abc…", 3},
		{"unicode kept", "naïve-pkg", "naïve-pkg", 128},
	}
	for _, tt := range tests {
		if got := String(tt.in, tt.max); got != tt.want {
			t.Errorf("%s: String(%q) = %q, want %q", tt.name, tt.in, got, tt.want)
		}
	}
}
