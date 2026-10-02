BINARY  := grima
CMD     := ./cmd/grima
DIST    := dist

ifeq ($(OS),Windows_NT)
  EXE := .exe
else
  EXE :=
endif

PLATFORMS := linux/amd64 linux/arm64 windows/amd64 darwin/arm64

.PHONY: all build test race vet fmt fmt-check lint cross run clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -o $(BINARY)$(EXE) $(CMD)

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

lint: fmt-check vet

cross:
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=$(DIST)/$(BINARY)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then out=$$out.exe; fi; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "-s -w" -o $$out $(CMD) || exit 1; \
	done

run: build
	@cfg=grima.toml; [ -f $$cfg ] || cfg=configs/grima.example.toml; \
	echo "running with $$cfg"; ./$(BINARY)$(EXE) --config $$cfg

clean:
	rm -rf $(BINARY)$(EXE) $(DIST)
