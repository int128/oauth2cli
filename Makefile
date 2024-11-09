.PHONY: all
all:

.PHONY: lint
lint:
	$(MAKE) -C tools
	go mod tidy
	./tools/bin/golangci-lint run
