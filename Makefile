.PHONY: test lint build

PKGS := $(shell go list ./... 2>/dev/null)

test:
ifneq ($(PKGS),)
	go test -race ./...
endif

lint:
ifneq ($(PKGS),)
	golangci-lint run ./...
endif

build:
ifneq ($(PKGS),)
	go build ./...
endif
