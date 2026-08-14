BINDIR := dist
LDFLAGS := -s -w
VERSION ?= 0.0.0-dev

GOIMAGE ?= golang:1.25

.PHONY: build test vet fmt package clean integration smoke

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/tripwired ./cmd/tripwired
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/tripwire  ./cmd/tripwire

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

package: build
	VERSION=$(VERSION) nfpm package -f packaging/nfpm.yaml -p deb -t $(BINDIR)/
	VERSION=$(VERSION) nfpm package -f packaging/nfpm.yaml -p rpm -t $(BINDIR)/

# fanotify permission events need CAP_SYS_ADMIN, so the syscall-level tests run
# in a privileged container.
integration:
	docker run --rm --privileged -v "$(PWD)":/src -w /src $(GOIMAGE) \
		go test -tags integration ./test/integration/ -v -timeout 120s

# Installs the built packages across distros and asserts the decoys end up owned
# by no package. Run `make package` first.
smoke:
	test/smoke/install_smoke.sh $(BINDIR)/tripwire_$(VERSION)_amd64.deb \
		$(BINDIR)/tripwire-$(VERSION)-1.x86_64.rpm

clean:
	rm -rf $(BINDIR)
