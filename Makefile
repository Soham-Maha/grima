BINARY  := grima
CMD     := ./cmd/grima
DIST    := dist

ifeq ($(OS),Windows_NT)
  EXE := .exe
else
  EXE :=
endif

PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/arm64

# Set per target rather than globally, and as a make variable rather than a
# `NAME=value` prefix on the recipe line. A make on Windows (chocolatey's, for
# instance) runs recipes through cmd.exe, where that prefix is a syntax error —
# and `make build` failing on the first command a Windows user types is a poor
# introduction. Target-specific export reaches the recipe's environment under
# cmd, sh and PowerShell alike, and leaves `race` alone: `go test -race` needs
# cgo, so a global CGO_ENABLED=0 breaks it.

# Evaluated when make starts, so the check itself needs no shell beyond running
# gofmt, which ships with Go.
FMT_BAD := $(shell gofmt -l .)

.PHONY: all build test race vet fmt fmt-check lint cross run clean

all: build

build: export CGO_ENABLED := 0
build:
	go build -trimpath -o $(BINARY)$(EXE) $(CMD)

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

fmt-check:
ifneq ($(FMT_BAD),)
	@echo "not gofmt-clean:"
	@echo "$(FMT_BAD)"
	@exit 1
endif
	@echo "gofmt clean"

lint: fmt-check vet

# POSIX shell only: the loop and the variable expansion below are sh syntax.
# On Windows run it from Git Bash, or use the direct go commands in the README.
cross: export CGO_ENABLED := 0
cross:
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=$(DIST)/$(BINARY)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then out=$$out.exe; fi; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "-s -w" -o $$out $(CMD) || exit 1; \
	done

# Resolved by make, not by a shell test, so this works under cmd as well as sh.
CFG := $(if $(wildcard grima.toml),grima.toml,configs/grima.example.toml)

run: build
	@echo "running with $(CFG)"
	./$(BINARY)$(EXE) --config $(CFG)

# POSIX shell only: `rm -rf`. On Windows delete the binary and dist/ directly.
clean:
	rm -rf $(BINARY)$(EXE) $(DIST)
