VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build build-linux test lint e2e-lima clean

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/gvsbom .

# Node mode runs on Linux nodes.
build-linux:
	GOOS=linux GOARCH=$(or $(ARCH),amd64) go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/gvsbom-linux-$(or $(ARCH),amd64) .

test:
	go test ./...

# End-to-end test inside the Lima lab VM (k3s + gVisor), see README.
e2e-lima:
	$(MAKE) build-linux ARCH=arm64
	limactl shell $(or $(LIMA_VM),gvisor-lab) sudo env BIN=$(CURDIR)/bin/gvsbom-linux-arm64 KUBECONFIG=/etc/rancher/k3s/k3s.yaml $(CURDIR)/test/e2e/run.sh

lint:
	gofmt -l . | (! grep .)
	go vet ./...

clean:
	rm -rf bin sbom-output
