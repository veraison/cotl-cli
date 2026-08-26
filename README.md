# cotl-cli

Go command-line tool for working with **Concise Tag Lists (CoTLs)** and
**Concise Reference Integrity Manifests (CoRIMs)** per
[draft-ietf-rats-corim-11](https://datatracker.ietf.org/doc/draft-ietf-rats-corim/).

Built on [veraison/corim](https://github.com/veraison/corim),
[veraison/go-cose](https://github.com/veraison/go-cose), and the sibling
[veraison/cotl](../cotl) library.

A Rust implementation of the same tool exists at [`../cotlme`](../cotlme); the
two are byte-compatible and continuously cross-verified by interop tests.

## Install

```sh
go build -o cotl-cli .
```

## Usage

```sh
# 1. Generate a signing keypair
cotl-cli keygen --curve p256 --private-out signing-key.pem --public-out signing-pub.pem

# 2. Create a CoTL activating some tags
cotl-cli cotl create -i my-cotl \
    -t 123e4567-e89b-12d3-a456-426614174000 \
    -t component-fw \
    --not-after "2100-01-01T00:00:00Z" \
    -o my.cotl

# 3. Inspect / validate
cotl-cli cotl show my.cotl
cotl-cli cotl validate --now "2030-01-01T00:00:00Z" my.cotl

# 4. Wrap in an unsigned CoRIM (#6.501)
cotl-cli rim wrap --cotl my.cotl -i rim-1 --profile "tag:example.com,2025/p" -o unsigned.corim

# 5. Sign (COSE_Sign1 #6.18, ES256/384/512)
cotl-cli rim sign --input unsigned.corim --key signing-key.pem \
    --signer-name "ACME" --not-after "2100-01-01T00:00:00Z" -o signed.corim

# 6. Verify / inspect
cotl-cli rim verify --key signing-pub.pem signed.corim
cotl-cli rim show signed.corim
```

Run `cotl-cli` with no arguments for the interactive wizard.

Notes:
* Timestamps accept RFC 3339 or Unix seconds.
* Because Go's `flag` package stops parsing at the first positional argument,
  flags always come before file arguments.
* `--kid` is currently a no-op: veraison/corim v1.1.2 does not expose COSE
  key-id embedding (git HEAD does; a warning is printed if set).
* Validity windows are inclusive of both bounds (RFC 5280 convention), and
  activation lists are atomic per Section 6 of the draft.

## Testing

```sh
GOTMPDIR=$HOME/.gotmp go test -race ./...
```

Includes end-to-end tests through the real binary (all three curves,
tamper/wrong-key rejection, expiry windows, duplicate warnings, wizard flow)
and cross-language interoperability tests that parse and verify files
produced by the Rust `cotlme` implementation — automatically skipped when the
Rust binary is absent.

## Layout

```
main.go          entrypoint + usage
commands.go      cotl/rim subcommands
keygen.go        ECDSA key generation (PKCS#8 PEM)
interactive.go   no-args wizard
cli_test.go      end-to-end integration tests
interop_test.go  cross-implementation tests vs Rust cotlme
```

## License

Apache-2.0 (matches veraison/corim)
