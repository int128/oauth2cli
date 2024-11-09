.PHONY: all
all:

.PHONY: lint
lint:
	$(MAKE) -C tools
	./tools/bin/golangci-lint run
