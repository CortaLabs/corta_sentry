.PHONY: bootstrap generate fmt lint test test-race frontend-typecheck frontend-test frontend-build build demo smoke install
GOCACHE ?= /tmp/cortasentry-go-cache
GOENV = GOCACHE=$(GOCACHE)

bootstrap:
	$(GOENV) go mod download
	cd web && npm ci --ignore-scripts

generate: frontend-build

fmt:
	gofmt -w cmd internal migrations web/embed.go

lint: frontend-typecheck
	$(GOENV) go vet ./...

test: frontend-test
	$(GOENV) go test ./...

test-race:
	$(GOENV) go test -race ./...

frontend-typecheck:
	cd web && npm run typecheck

frontend-test:
	cd web && npm test

frontend-build:
	cd web && npm run build

build: frontend-build
	mkdir -p bin
	$(GOENV) CGO_ENABLED=0 go build -trimpath -o bin/cortasentry ./cmd/cortasentry
	$(GOENV) CGO_ENABLED=0 go build -trimpath -o bin/cortasentry-fixtures ./cmd/cortasentry-fixtures
	$(GOENV) CGO_ENABLED=0 go build -trimpath -o bin/cortasentry-sensor ./cmd/cortasentry-sensor

demo: build
	./scripts/smoke-test.sh

smoke: build
	./scripts/smoke-test.sh

install:
	./install.sh
