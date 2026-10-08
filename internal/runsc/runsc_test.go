package runsc

import "testing"

func TestContainerID(t *testing.T) {
	const id = "e3af44813d8d001e91f9d80cfd2cdfcdea4f37ae704b6095ea93003a45de9cae"
	got, err := ContainerID("containerd://" + id)
	if err != nil || got != id {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{
		id,
		"docker://" + id,
		"containerd://" + id[:12],
		"containerd://--root=/tmp " + id,
	} {
		if _, err := ContainerID(bad); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
}
