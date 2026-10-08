package scanner

import (
	"errors"
	"testing"

	utilexec "k8s.io/client-go/util/exec"
)

func TestClassifyExecError(t *testing.T) {
	gvisor := errors.New(`OCI runtime exec failed: executing processes for container: executing command "tar cf - -C / ." in sandbox: error finding executable "tar" in PATH [/usr/bin /bin]: no such file or directory`)
	runc := errors.New(`OCI runtime exec failed: exec failed: unable to start container process: exec: "tar": executable file not found in $PATH: unknown`)

	for name, err := range map[string]error{"gvisor": gvisor, "runc": runc, "exit 127": utilexec.CodeExitError{Err: errors.New("x"), Code: 127}} {
		if _, got := classifyExecError(err, ""); !errors.Is(got, ErrNoTar) {
			t.Errorf("%s: expected ErrNoTar, got %v", name, got)
		}
	}

	warning, err := classifyExecError(utilexec.CodeExitError{Err: errors.New("x"), Code: 1}, "tar: ./tmp/x: file changed as we read it\n")
	if err != nil || warning == "" {
		t.Errorf("exit 1 should be a warning, got warning=%q err=%v", warning, err)
	}

	if _, err := classifyExecError(utilexec.CodeExitError{Err: errors.New("x"), Code: 2}, "tar: fatal"); err == nil || errors.Is(err, ErrNoTar) {
		t.Errorf("exit 2 should be a hard error, got %v", err)
	}
}
