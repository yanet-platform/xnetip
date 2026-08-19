# Developer entry points for the gates described in AGENTS.md.
#
# The lint binaries (gofumpt, golangci-lint, gocommentlint, benchstat) are
# installed with `go install` into $GOPATH/bin, which is prepended to PATH
# here so the targets work even when that directory is not on the caller's
# PATH.

export PATH := $(shell go env GOPATH)/bin:$(PATH)

.PHONY: test test-short lint lint-comments bench bench-run hooks

# The full test gate, same flags as CI.
test:
	go test -race ./...

# Property tests at one fifth of the checks (rapid divides -rapid.checks
# by five under -short).
test-short:
	go test -short ./...

# The static gate: formatting, vet, golangci-lint, then the comment shape
# of the staged diff.
lint:
	@unformatted="$$(gofumpt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofumpt: files need formatting (run 'gofumpt -w .'):"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	go vet ./...
	golangci-lint run ./...
	gocommentlint

# Comment-shape gate on the staged diff, the same binary the pre-commit
# hook runs.
lint-comments:
	gocommentlint

# Compile and smoke-run every benchmark once.
bench:
	go test -run xxx -bench . -benchtime 1x ./...

# The measurement run, feed the output to benchstat.
bench-run:
	go test -run xxx -bench . -benchmem -count 10 ./...

# Once per clone: route git hooks to the versioned .githooks directory.
hooks:
	git config core.hooksPath .githooks
