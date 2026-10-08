// Package rootfs unpacks a container filesystem streamed out of a pod.
package rootfs

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

var (
	ErrTooLarge       = errors.New("container filesystem exceeds the size limit")
	ErrTooManyEntries = errors.New("container filesystem exceeds the entry limit")
)

type Limits struct {
	MaxBytes   int64
	MaxEntries int
	// Exclude lists paths, relative to the root, that are dropped with
	// everything below them.
	Exclude []string
}

type Stats struct {
	Files    int
	Dirs     int
	Symlinks int
	Links    int
	Skipped  int
	Excluded int
	Entries  int
	Bytes    int64

	// Whiteouts and Opaque describe deletions when the archive is an overlay
	// upper layer: paths removed from the layers below, and directories whose
	// lower contents are hidden entirely.
	Whiteouts []string `json:"-"`
	Opaque    []string `json:"-"`
	Deleted   int
}

// Extract unpacks a tar stream into dir. The stream comes from a sandboxed,
// untrusted workload, so all writes go through os.Root: no entry, symlink or
// hard link can reach outside dir. Nothing in the copy is executable, device
// files are dropped, and excluded entries never touch disk.
func Extract(r io.Reader, dir string, lim Limits) (Stats, error) {
	var st Stats
	root, err := os.OpenRoot(dir)
	if err != nil {
		return st, err
	}
	defer root.Close()

	whiteouts := map[string]bool{}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return st, nil
		}
		if err != nil {
			return st, fmt.Errorf("reading tar stream: %w", err)
		}
		name, ok := cleanName(hdr.Name)
		if !ok {
			continue
		}
		if excluded(name, lim.Exclude) {
			st.Excluded++
			continue
		}
		st.Entries++
		if st.Entries > lim.MaxEntries {
			return st, ErrTooManyEntries
		}
		whiteout, opaque, ok := deletion(name, hdr)
		// runsc writes the first whiteout as a 0:0 device and every later one
		// as a hard link to it.
		if target, _ := cleanName(hdr.Linkname); hdr.Typeflag == tar.TypeLink && whiteouts[target] {
			whiteout, ok = name, true
		}
		if ok {
			if whiteout != "" {
				st.Whiteouts = append(st.Whiteouts, whiteout)
				whiteouts[whiteout] = true
			}
			if opaque != "" {
				st.Opaque = append(st.Opaque, opaque)
			}
			st.Deleted++
			if hdr.Typeflag != tar.TypeDir {
				continue
			}
		}
		if parent := path.Dir(name); parent != "." {
			if err := root.MkdirAll(parent, 0o755); err != nil {
				st.Skipped++
				continue
			}
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o755); err != nil {
				st.Skipped++
				continue
			}
			st.Dirs++
		case tar.TypeReg:
			if st.Bytes+hdr.Size > lim.MaxBytes {
				return st, ErrTooLarge
			}
			n, err := writeFile(root, name, hdr, tr)
			st.Bytes += n
			if errors.Is(err, errSkip) {
				st.Skipped++
				continue
			}
			if err != nil {
				return st, err
			}
			st.Files++
		case tar.TypeSymlink:
			_ = root.Remove(name)
			if err := root.Symlink(hdr.Linkname, name); err != nil {
				st.Skipped++
				continue
			}
			st.Symlinks++
		case tar.TypeLink:
			target, ok := cleanName(hdr.Linkname)
			if !ok {
				st.Skipped++
				continue
			}
			_ = root.Remove(name)
			if err := root.Link(target, name); err != nil {
				st.Skipped++
				continue
			}
			st.Links++
		default:
			st.Skipped++
		}
	}
}

var errSkip = errors.New("skip entry")

// deletion recognises the overlay whiteout conventions: a 0:0 character
// device (overlayfs, and what runsc writes), ".wh.<name>" and ".wh..wh..opq"
// files (OCI layers), and the opaque-directory xattr.
func deletion(name string, hdr *tar.Header) (whiteout, opaque string, ok bool) {
	dir, base := path.Split(name)
	dir = strings.TrimSuffix(dir, "/")
	switch {
	case hdr.Typeflag == tar.TypeChar && hdr.Devmajor == 0 && hdr.Devminor == 0:
		return name, "", true
	case base == ".wh..wh..opq":
		return "", dir, dir != ""
	case strings.HasPrefix(base, ".wh."):
		return path.Join(dir, strings.TrimPrefix(base, ".wh.")), "", true
	case hdr.Typeflag == tar.TypeDir && (hdr.PAXRecords["SCHILY.xattr.trusted.overlay.opaque"] == "y" ||
		hdr.PAXRecords["SCHILY.xattr.user.overlay.opaque"] == "y"):
		return "", name, true
	}
	return "", "", false
}

// Every file is written 0644: syft recognises binaries by content, so the copy
// never needs to be executable.
func writeFile(root *os.Root, name string, hdr *tar.Header, r io.Reader) (int64, error) {
	_ = root.Remove(name)
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, errSkip
	}
	n, err := io.Copy(f, io.LimitReader(r, hdr.Size))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, fmt.Errorf("writing %s: %w", name, err)
	}
	return n, nil
}

// cleanName turns an archive path into one relative to the extraction root.
// Leading slashes and ".." are clamped to the root rather than rejected.
func cleanName(name string) (string, bool) {
	clean := path.Clean("/" + name)[1:]
	return clean, clean != ""
}

func excluded(name string, exclude []string) bool {
	for _, e := range exclude {
		if name == e || strings.HasPrefix(name, e+"/") {
			return true
		}
	}
	return false
}
