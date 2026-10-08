package rootfs

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type entry struct {
	name, body, link string
	typ              byte
	mode             int64
}

func archive(t *testing.T, entries ...entry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: mode, Linkname: e.link, Size: int64(len(e.body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

var testLimits = Limits{MaxBytes: 1 << 20, MaxEntries: 1000}

func TestExtractRegularTree(t *testing.T) {
	dir := t.TempDir()
	st, err := Extract(archive(t,
		entry{name: "./", typ: tar.TypeDir},
		entry{name: "./usr/bin/", typ: tar.TypeDir},
		entry{name: "./usr/bin/tool", typ: tar.TypeReg, body: "bin", mode: 0o4755},
		entry{name: "./etc/os-release", typ: tar.TypeReg, body: "ID=debian"},
		entry{name: "./bin", typ: tar.TypeSymlink, link: "usr/bin"},
		entry{name: "./etc/os-release.bak", typ: tar.TypeLink, link: "./etc/os-release"},
		entry{name: "./run/fifo", typ: tar.TypeFifo},
	), dir, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	if st.Files != 2 || st.Symlinks != 1 || st.Links != 1 || st.Skipped != 1 {
		t.Fatalf("unexpected stats: %+v", st)
	}
	info, err := os.Stat(filepath.Join(dir, "usr/bin/tool"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 || info.Mode()&os.ModeSetuid != 0 {
		t.Fatalf("copy must not be executable or setuid, got %v", info.Mode())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "bin/tool")); string(b) != "bin" {
		t.Fatalf("symlink inside root not usable, got %q", b)
	}
}

func TestExtractCannotEscapeRoot(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "rootfs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Extract(archive(t,
		entry{name: "../../escape-dotdot", typ: tar.TypeReg, body: "x"},
		entry{name: "/abs-escape", typ: tar.TypeReg, body: "x"},
		entry{name: "./link", typ: tar.TypeSymlink, link: outside},
		entry{name: "./link/through-symlink", typ: tar.TypeReg, body: "x"},
		entry{name: "./rel", typ: tar.TypeSymlink, link: "../outside"},
		entry{name: "./rel/through-relative", typ: tar.TypeReg, body: "x"},
		entry{name: "./hard", typ: tar.TypeLink, link: "../../etc/passwd"},
	), dir, testLimits)
	if err != nil {
		t.Fatal(err)
	}

	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("archive wrote outside the root: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(parent, "escape-dotdot")); err == nil {
		t.Fatal("dot-dot entry escaped the root")
	}
	if _, err := os.Stat(filepath.Join(dir, "escape-dotdot")); err != nil {
		t.Fatal("dot-dot entry should be clamped inside the root")
	}
	if _, err := os.Stat(filepath.Join(dir, "abs-escape")); err != nil {
		t.Fatal("absolute entry should be clamped inside the root")
	}
}

func TestExtractExcludesNeverTouchDisk(t *testing.T) {
	dir := t.TempDir()
	st, err := Extract(archive(t,
		entry{name: "./run/secrets/kubernetes.io/serviceaccount/", typ: tar.TypeDir},
		entry{name: "./run/secrets/kubernetes.io/serviceaccount/token", typ: tar.TypeReg, body: "eyJhbGciOi"},
		entry{name: "./run/secrets-not-a-mount", typ: tar.TypeReg, body: "keep"},
		entry{name: "./usr/lib/app.py", typ: tar.TypeReg, body: "keep"},
	), dir, Limits{MaxBytes: 1 << 20, MaxEntries: 100, Exclude: []string{"run/secrets/kubernetes.io/serviceaccount"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Excluded != 2 || st.Files != 2 {
		t.Fatalf("unexpected stats: %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dir, "run/secrets/kubernetes.io")); err == nil {
		t.Fatal("excluded mount left a directory behind")
	}
}

func TestExtractSizeLimit(t *testing.T) {
	_, err := Extract(archive(t,
		entry{name: "a", typ: tar.TypeReg, body: "12345"},
		entry{name: "b", typ: tar.TypeReg, body: "67890"},
	), t.TempDir(), Limits{MaxBytes: 8, MaxEntries: 100})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}

func TestExtractEntryLimit(t *testing.T) {
	var entries []entry
	for i := range 20 {
		entries = append(entries, entry{name: fmt.Sprintf("./empty-%d", i), typ: tar.TypeReg})
	}
	_, err := Extract(archive(t, entries...), t.TempDir(), Limits{MaxBytes: 1 << 20, MaxEntries: 10})
	if !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("expected ErrTooManyEntries, got %v", err)
	}
}

func TestExtractRecordsWhiteouts(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range []*tar.Header{
		{Name: "./usr/lib/python3/site-packages/old-1.0.dist-info", Typeflag: tar.TypeChar, Mode: 0},
		{Name: "./usr/lib/python3/site-packages/pip-25.0.1.dist-info", Typeflag: tar.TypeLink, Linkname: "./usr/lib/python3/site-packages/old-1.0.dist-info"},
		{Name: "./etc/.wh.removed.conf", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "./opt/app/.wh..wh..opq", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "./var/cache/", Typeflag: tar.TypeDir, Mode: 0o755, PAXRecords: map[string]string{"SCHILY.xattr.trusted.overlay.opaque": "y"}},
		{Name: "./dev/real-device", Typeflag: tar.TypeChar, Mode: 0o600, Devmajor: 1, Devminor: 3},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()

	dir := t.TempDir()
	st, err := Extract(&buf, dir, testLimits)
	if err != nil {
		t.Fatal(err)
	}
	wantWhiteouts := []string{"usr/lib/python3/site-packages/old-1.0.dist-info", "usr/lib/python3/site-packages/pip-25.0.1.dist-info", "etc/removed.conf"}
	wantOpaque := []string{"opt/app", "var/cache"}
	if !reflect.DeepEqual(st.Whiteouts, wantWhiteouts) || !reflect.DeepEqual(st.Opaque, wantOpaque) {
		t.Fatalf("whiteouts %v opaque %v", st.Whiteouts, st.Opaque)
	}
	if st.Skipped != 1 {
		t.Fatalf("a real device should still be skipped: %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dir, "etc/.wh.removed.conf")); err == nil {
		t.Fatal("whiteout marker written to disk")
	}
	if fi, err := os.Stat(filepath.Join(dir, "var/cache")); err != nil || !fi.IsDir() {
		t.Fatal("opaque directory should still be created")
	}
}
