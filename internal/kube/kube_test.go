package kube

import "testing"

func TestImageRef(t *testing.T) {
	const digest = "sha256:ddb0207ae1f0356c2b724d740769b0c5f5f51cc54a0525178f721825f78fe74c"
	tests := []struct {
		image, imageID, want string
	}{
		{"python:3.12-slim", "docker.io/library/python@" + digest, "docker.io/library/python@" + digest},
		{"python:3.12-slim", "docker-pullable://python@" + digest, "python@" + digest},
		{"python:3.12-slim", digest, "python@" + digest},
		{"registry.local:5000/team/app:v1", digest, "registry.local:5000/team/app@" + digest},
		{"registry.local:5000/team/app", digest, "registry.local:5000/team/app@" + digest},
	}
	for _, tt := range tests {
		got, err := ImageRef(tt.image, tt.imageID)
		if err != nil {
			t.Fatalf("ImageRef(%q, %q): %v", tt.image, tt.imageID, err)
		}
		if got != tt.want {
			t.Errorf("ImageRef(%q, %q) = %q, want %q", tt.image, tt.imageID, got, tt.want)
		}
	}

	if _, err := ImageRef("", "abc"); err == nil {
		t.Error("expected an error for an imageID without a digest")
	}
}
