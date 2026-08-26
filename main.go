// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Command cotl-cli is a stupid-simple, extremely powerful tool for working
// with Concise Tag Lists (CoTLs) and Concise Reference Integrity Manifests
// (CoRIMs), per draft-ietf-rats-corim-11.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return runInteractive()
	}

	switch args[0] {
	case "keygen":
		return cmdKeygen(args[1:])
	case "cotl":
		return cmdCotl(args[1:])
	case "rim":
		return cmdRim(args[1:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	default:
		usage(os.Stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `cotl-cli — CoTL/CoRIM tool (draft-ietf-rats-corim-11)

usage:
  cotl-cli keygen --curve p256 --private-out k.pem --public-out k.pub.pem
  cotl-cli cotl create -i ID -t TAG [-t TAG...] [--not-before TS] --not-after TS -o FILE
  cotl-cli cotl show FILE
  cotl-cli cotl validate [--now TS] FILE
  cotl-cli rim wrap --cotl FILE -i ID [--profile URI] -o FILE
  cotl-cli rim sign --input FILE --key PEM [--alg es256] [--signer-name NAME]
                  --not-after TS -o FILE
  cotl-cli rim verify FILE --key PUB.pem
  cotl-cli rim show FILE

Run with no arguments for the interactive wizard.
Timestamps accept RFC 3339 ("2100-01-01T00:00:00Z") or Unix seconds.
`)
}
