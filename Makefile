BINDIR := dist
LDFLAGS := -s -w
VERSION ?= 0.0.0-dev

.PHONY: build test vet fmt package clean

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

clean:
	rm -rf $(BINDIR)
