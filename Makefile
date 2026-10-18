VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet fmt install clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/go-guard ./cmd/go-guard

test:
	go test -race ./...

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

fmt:
	gofmt -w .

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/go-guard

clean:
	rm -rf bin dist
