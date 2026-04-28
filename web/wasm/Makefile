.PHONY: build size clean

WASM_OUT := ../public/crypto.wasm
EXEC_JS  := ../public/wasm_exec.js

build: $(WASM_OUT) $(EXEC_JS)

$(WASM_OUT): main.go go.mod go.sum
	GOOS=js GOARCH=wasm go build -o $@ .

$(EXEC_JS):
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" $@

size: $(WASM_OUT)
	@printf "Uncompressed: "; ls -lh $(WASM_OUT) | awk '{print $$5}'
	@printf "Gzipped:      "; gzip -c $(WASM_OUT) | wc -c | awk '{printf "%.1fMB\n", $$1/1048576}'

clean:
	rm -f $(WASM_OUT) $(EXEC_JS)
