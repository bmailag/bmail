# bmail crypto (verifiable WASM)

This repository contains the cryptographic code that runs in your browser when
you use [bmail.ag](https://bmail.ag). It is the source of `vpmail.wasm`, the
WebAssembly module that handles every encryption, decryption, signing, key
derivation, OPAQUE login, and key transparency check on the client side.

The point of publishing it is to let anyone reproduce the exact `vpmail.wasm`
that bmail.ag serves to your browser. Build it locally, hash it, compare to the
hash in the latest release. If they match, you have proof that the binary
running in your browser is built from this source.

## Build it yourself

You need Go 1.26.1 on Linux. The byte output of `GOOS=js GOARCH=wasm` builds
depends on the build host, so a macOS or Windows build will not match the
published Linux hash. To reproduce on a non-Linux machine, use Docker:

```
git clone https://github.com/bmailag/bmail.git
cd bmail
docker run --rm -v "$PWD":/src -w /src golang:1.26.1 make wasm
```

On Linux, the Docker step is unnecessary:

```
git clone https://github.com/bmailag/bmail.git
cd bmail
make wasm
```

This produces `vpmail.wasm` in the repo root and prints its SHA-256 hash. The
hash should match the one shown on the corresponding release at
[github.com/bmailag/bmail/releases](https://github.com/bmailag/bmail/releases).

The build is reproducible because it uses these flags:

```
GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o vpmail.wasm .
```

`-trimpath` removes filesystem path prefixes from the binary, `-buildvcs=false`
omits the VCS revision and timestamp, `-s -w` strips the symbol table and
DWARF info, and `-buildid=` clears Go's internal build identifier. With
identical source and the same Go version, the resulting WASM bytes are
deterministic and reproducible across machines.

## What is in here

```
internal/crypto/   The Go package that implements every primitive used by the
                   client: X25519 + ML-KEM-768 hybrid encryption, Ed25519
                   signing, XChaCha20-Poly1305 AEAD, HKDF, BIP-39 recovery
                   mnemonics, OpenPGP interop, RSA blind signatures.

web/wasm/          The thin WASM glue layer that registers JavaScript-callable
                   functions on the global `vpCrypto` object. Each file
                   covers one area: keys, messages, signing, recovery, files,
                   attachments, KT proofs, PGP, OPAQUE, password validation,
                   AES-GCM share helpers, blind-signature primitives.
```

## Verifying what your browser ran

bmail.ag embeds the expected SHA-256 of `vpmail.wasm` in the served HTML, and
the loader hashes the bytes it received before instantiating the module. If
the hash does not match, the loader refuses to run the WASM and shows an
error. You can inspect this in your browser's network tab.

## Running the tests

The Go tests in `internal/crypto/` cover encryption round-trips, hybrid KEM
construction, recovery flows, blind signatures, and PGP interop:

```
go test ./internal/crypto/...
```

## License

MIT. See [LICENSE](LICENSE).

## Main project

The bmail product, infrastructure, and full source live elsewhere. This
repository is the verifiable client-side crypto subset.
