BIN     := awg3panel
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOENV   := GOOS=linux GOARCH=amd64 CGO_ENABLED=0

.PHONY: test vet build build-readonly bundle vendor clean all

all: test build

# Private portable Linux bundle; Docker runs only on the trusted build host.
bundle:
	docker build --build-arg VERSION="$(VERSION)" -f deploy/Dockerfile.build --target artifact --output type=local,dest=dist .

test:
	go test ./... -count=1
	go test -tags readonly ./... -count=1

vet:
	go vet ./...
	go vet -tags readonly ./...

# Полная сборка: умеет и читать, и писать.
build:
	$(GOENV) go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN) ./cmd/awg3panel

# Сборка этапа A: обработчиков мутаций в бинаре физически нет.
build-readonly:
	$(GOENV) go build -trimpath -tags readonly -ldflags "$(LDFLAGS)" \
		-o dist/$(BIN)-readonly ./cmd/awg3panel

vendor:
	go mod tidy
	go mod vendor

clean:
	rm -rf dist
