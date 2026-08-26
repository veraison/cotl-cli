// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// runInteractive drives a simple stdin-based wizard, offered when the tool is
// invoked without arguments.
func runInteractive() error {
	fmt.Println("cotl-cli — CoTL/CoRIM tool (draft-ietf-rats-corim-11)")
	fmt.Println()

	choices := []string{
		"Create a CoTL",
		"Inspect / validate a file",
		"Wrap + sign a CoTL into a signed CoRIM",
		"Verify a signed CoRIM",
		"Generate a signing keypair",
		"Quit",
	}

	pick, err := choose("What do you want to do", choices)
	if err != nil {
		return err
	}

	switch pick {
	case 0:
		return wizCreateCotl()
	case 1:
		return wizInspect()
	case 2:
		return wizWrapSign()
	case 3:
		return wizVerify()
	case 4:
		return wizKeygen()
	default:
		return nil
	}
}

var stdin *bufio.Reader

func reader() *bufio.Reader {
	if stdin == nil {
		stdin = bufio.NewReader(os.Stdin)
	}

	return stdin
}

func prompt(label, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}

	line, err := reader().ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}

	line = strings.TrimSpace(line)
	if line == "" {
		line = def
	}

	return line, nil
}

func choose(label string, choices []string) (int, error) {
	fmt.Println(label)

	for i, c := range choices {
		fmt.Printf("  %d) %s\n", i+1, c)
	}

	for {
		line, err := prompt("choice", "1")
		if err != nil {
			return 0, err
		}

		n, err := strconv.Atoi(line)
		if err == nil && n >= 1 && n <= len(choices) {
			return n - 1, nil
		}

		fmt.Printf("please enter a number between 1 and %d\n", len(choices))
	}
}

func wizCreateCotl() error {
	id, err := prompt("CoTL id (UUID or text)", "")
	if err != nil {
		return err
	}

	tagsRaw, err := prompt("Tag ids to activate (comma-separated)", "")
	if err != nil {
		return err
	}

	notAfter, err := prompt("Valid until (RFC 3339 or Unix seconds)", "2100-01-01T00:00:00Z")
	if err != nil {
		return err
	}

	out, err := prompt("Output file", "out.cotl")
	if err != nil {
		return err
	}

	var args []string
	args = append(args, "-i", id, "--not-after", notAfter, "-o", out)
	for _, t := range strings.Split(tagsRaw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			args = append(args, "-t", t)
		}
	}

	return cotlCreate(args)
}

func wizInspect() error {
	path, err := prompt("File to inspect", "")
	if err != nil {
		return err
	}

	if _, err := loadCotl(path); err == nil {
		if err := cotlShow([]string{path}); err != nil {
			return err
		}
		return cotlValidate([]string{path})
	}

	return rimShow([]string{path})
}

func wizWrapSign() error {
	cotlPath, err := prompt("CoTL file", "")
	if err != nil {
		return err
	}

	corimID, err := prompt("CoRIM id", "")
	if err != nil {
		return err
	}

	keyPath, err := prompt("PEM private key", "signing-key.pem")
	if err != nil {
		return err
	}

	signerName, err := prompt("Signer name", "cotl-cli signer")
	if err != nil {
		return err
	}

	out, err := prompt("Output file", "signed.corim")
	if err != nil {
		return err
	}

	unsigned := "unsigned-" + out

	if err := rimWrap([]string{
		"--cotl", cotlPath, "-i", corimID, "-o", unsigned,
	}); err != nil {
		return err
	}

	return rimSign([]string{
		"--input", unsigned, "--key", keyPath,
		"--signer-name", signerName,
		"--not-after", "2100-01-01T00:00:00Z",
		"-o", out,
	})
}

func wizVerify() error {
	file, err := prompt("Signed CoRIM file", "")
	if err != nil {
		return err
	}

	key, err := prompt("PEM public key", "")
	if err != nil {
		return err
	}

	return rimVerify([]string{"--key", key, file})
}

func wizKeygen() error {
	curveIdx, err := choose("Curve", []string{"p256", "p384", "p521"})
	if err != nil {
		return err
	}

	privOut, err := prompt("Private key path", "signing-key.pem")
	if err != nil {
		return err
	}

	pubOut, err := prompt("Public key path", "signing-pub.pem")
	if err != nil {
		return err
	}

	curves := []string{"p256", "p384", "p521"}

	return cmdKeygen([]string{
		"--curve", curves[curveIdx],
		"--private-out", privOut,
		"--public-out", pubOut,
	})
}
