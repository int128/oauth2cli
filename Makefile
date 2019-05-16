.PHONY: check

check:
	golangci-lint run
	go test -v -race ./...
