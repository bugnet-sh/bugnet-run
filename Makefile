.PHONY: test lint build

ARCHS := amd64 arm64

test:
	go test -race ./...

lint:
	golangci-lint run ./...

build:
	go build ./...
	for arch in $(ARCHS); do \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
			-o dist/bugnet-run-linux-$$arch ./cmd/bugnet-run || exit 1; \
	done
