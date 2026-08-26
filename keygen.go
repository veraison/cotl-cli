// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
)

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	curve := fs.String("curve", "p256", "elliptic curve: p256, p384 or p521")
	privOut := fs.String("private-out", "signing-key.pem", "output path for the PEM private key")
	pubOut := fs.String("public-out", "signing-pub.pem", "output path for the PEM public key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var ecCurve elliptic.Curve
	switch strings.ToLower(*curve) {
	case "p256", "prime256v1":
		ecCurve = elliptic.P256()
	case "p384":
		ecCurve = elliptic.P384()
	case "p521":
		ecCurve = elliptic.P521()
	default:
		return fmt.Errorf("unsupported curve %q (want p256, p384 or p521)", *curve)
	}

	key, err := ecdsa.GenerateKey(ecCurve, rand.Reader)
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("private key marshaling failed: %w", err)
	}

	if err := writePEM(*privOut, "PRIVATE KEY", der); err != nil {
		return err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("public key marshaling failed: %w", err)
	}

	if err := writePEM(*pubOut, "PUBLIC KEY", pubDER); err != nil {
		return err
	}

	fmt.Printf("private key: %s\npublic key:  %s\n", *privOut, *pubOut)

	return nil
}

func loadECDSAPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}

	generic, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	key, ok := generic.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA private key (%T)", path, generic)
	}

	return key, nil
}

func loadECDSPublicKey(path string) (*ecdsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}

	generic, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	key, ok := generic.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA public key (%T)", path, generic)
	}

	return key, nil
}
