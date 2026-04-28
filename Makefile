.PHONY: wasm clean

# Reproducible WASM build flags. Anyone running `make wasm` with the same
# Go version should produce a byte-identical vpmail.wasm.
GO_BUILD_FLAGS := -trimpath -buildvcs=false -ldflags="-s -w -buildid="

wasm:
	cd web/wasm && GOOS=js GOARCH=wasm go build $(GO_BUILD_FLAGS) -o ../../vpmail.wasm .
	@echo
	@echo "Built vpmail.wasm:"
	@shasum -a 256 vpmail.wasm

clean:
	rm -f vpmail.wasm
