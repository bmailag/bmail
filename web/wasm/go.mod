module github.com/bmailag/bmail/web/wasm

go 1.26.1

replace github.com/bmailag/bmail => ../..

require (
	github.com/bmailag/bmail v0.0.0-00010101000000-000000000000
	github.com/bytemare/opaque v0.10.0
	golang.org/x/crypto v0.48.0
)

require (
	filippo.io/edwards25519 v1.0.0 // indirect
	filippo.io/nistec v0.0.2 // indirect
	github.com/ProtonMail/go-crypto v1.3.0 // indirect
	github.com/ProtonMail/gopenpgp/v3 v3.3.0 // indirect
	github.com/bytemare/crypto v0.4.3 // indirect
	github.com/bytemare/hash v0.1.5 // indirect
	github.com/bytemare/hash2curve v0.1.3 // indirect
	github.com/bytemare/ksf v0.1.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/gtank/ristretto255 v0.1.2 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
)
