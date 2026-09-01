// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/veraison/corim/corim"
	"github.com/veraison/corim/cotl"
	cose "github.com/veraison/go-cose"
	"github.com/veraison/swid"
)

func cmdCotl(args []string) error {
	if len(args) == 0 {
		usage(os.Stderr)
		return errors.New("cotl requires a subcommand (create, show or validate)")
	}

	switch args[0] {
	case "create":
		return cotlCreate(args[1:])
	case "show":
		return cotlShow(args[1:])
	case "validate":
		return cotlValidate(args[1:])
	default:
		return fmt.Errorf("unknown cotl subcommand %q", args[0])
	}
}

func cotlCreate(args []string) error {
	fs := flag.NewFlagSet("cotl create", flag.ExitOnError)
	id := fs.String("i", "", "CoTL id (UUID or text)")
	version := fs.Uint("version", 0, "optional tag version")
	notBefore := fs.String("not-before", "", "validity start (RFC 3339 or Unix seconds)")
	notAfter := fs.String("not-after", "", "validity end (RFC 3339 or Unix seconds)")
	out := fs.String("o", "out.cotl", "output file")
	tags := multiFlag(fs, "t", "tag activated by this list (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *id == "" {
		return errors.New("-i/--id is required")
	}
	if len(tags.values) == 0 {
		return errors.New("at least one -t/--tag is required")
	}

	identity, err := cotl.NewTagIdentityMap(*id)
	if err != nil {
		return err
	}
	if *version > 0 {
		identity.TagVersion = version
	}

	list := make([]cotl.TagIdentityMap, 0, len(tags.values))
	for _, t := range tags.values {
		tm, err := cotl.NewTagIdentityMap(t)
		if err != nil {
			return fmt.Errorf("invalid tag %q: %w", t, err)
		}
		list = append(list, *tm)
	}

	if *notAfter == "" {
		return errors.New("--not-after is required")
	}
	na, err := parseTime(*notAfter)
	if err != nil {
		return err
	}

	validity := corim.Validity{NotAfter: na}
	if *notBefore != "" {
		nb, err := parseTime(*notBefore)
		if err != nil {
			return err
		}
		validity.NotBefore = &nb
	}

	tag := cotl.ConciseTlTag{
		TagIdentity: *identity,
		TagsList:    list,
		TlValidity:  validity,
	}

	buf, err := tag.ToCBOR()
	if err != nil {
		return err
	}

	if err := os.WriteFile(*out, buf, 0o600); err != nil {
		return fmt.Errorf("writing %s failed: %w", *out, err)
	}

	fmt.Printf("wrote CoTL %s (%d)\n", *out, len(buf))

	return nil
}

func cotlShow(args []string) error {
	fs := flag.NewFlagSet("cotl show", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: cotl show FILE")
	}

	tag, err := loadCotl(fs.Arg(0))
	if err != nil {
		return err
	}

	printCotlSummary(tag)

	return nil
}

func cotlValidate(args []string) error {
	fs := flag.NewFlagSet("cotl validate", flag.ExitOnError)
	nowStr := fs.String("now", "", "check as-of time (defaults to now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: cotl validate [--now TS] FILE")
	}

	tag, err := loadCotl(fs.Arg(0))
	if err != nil {
		return err
	}

	now := time.Now()
	if *nowStr != "" {
		ts, err := parseTime(*nowStr)
		if err != nil {
			return err
		}
		now = ts
	}

	report := tag.ValidateAt(now)

	for _, w := range report.Warnings {
		fmt.Printf("warning: %s\n", w)
	}

	for _, e := range report.Errors {
		fmt.Fprintf(os.Stderr, "error: %s\n", e)
	}

	if !report.Valid() {
		return errors.New("CoTL is invalid")
	}

	fmt.Println("valid")

	return nil
}

func loadCotl(path string) (*cotl.ConciseTlTag, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return cotl.NewConciseTlTagFromCBOR(buf)
}

func printCotlSummary(tag *cotl.ConciseTlTag) {
	fmt.Printf("tag-id:       %s\n", tag.TagIdentity.String())

	if tag.TlValidity.NotBefore != nil {
		fmt.Printf("not-before:   %s\n", tag.TlValidity.NotBefore.UTC().Format(time.RFC3339))
	}

	fmt.Printf("not-after:    %s\n", tag.TlValidity.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("tags-list:    %d tag(s)\n", len(tag.TagsList))

	for _, t := range tag.TagsList {
		fmt.Printf("  - %s\n", t.String())
	}
}

// rim -----------------------------------------------------------------------

func cmdRim(args []string) error {
	if len(args) == 0 {
		usage(os.Stderr)
		return errors.New("rim requires a subcommand (wrap, sign, verify or show)")
	}

	switch args[0] {
	case "wrap":
		return rimWrap(args[1:])
	case "sign":
		return rimSign(args[1:])
	case "verify":
		return rimVerify(args[1:])
	case "show":
		return rimShow(args[1:])
	default:
		return fmt.Errorf("unknown rim subcommand %q", args[0])
	}
}

func rimWrap(args []string) error {
	fs := flag.NewFlagSet("rim wrap", flag.ExitOnError)
	cotlPath := fs.String("cotl", "", "CoTL file to embed")
	id := fs.String("i", "", "CoRIM id (UUID or text)")
	profile := fs.String("profile", "", "optional profile URI")
	out := fs.String("o", "unsigned.corim", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *id == "" {
		return errors.New("-i/--id is required")
	}

	tag, err := loadCotl(*cotlPath)
	if err != nil {
		return err
	}

	tagCBOR, err := tag.ToCBOR()
	if err != nil {
		return err
	}

	var corimTag corim.Tag
	if err := corimTag.UnmarshalCBOR(tagCBOR); err != nil {
		return fmt.Errorf("wrapping CoTL tag failed: %w", err)
	}

	unsigned := corim.UnsignedCorim{
		ID:   *swid.NewTagID(*id),
		Tags: []corim.Tag{corimTag},
	}

	if *profile != "" {
		unsigned.SetProfile(*profile)
	}

	buf, err := unsigned.ToCBOR()
	if err != nil {
		return fmt.Errorf("CoRIM encoding failed: %w", err)
	}

	if err := os.WriteFile(*out, buf, 0o600); err != nil {
		return err
	}

	fmt.Printf("wrote unsigned CoRIM %s (%d)\n", *out, len(buf))

	return nil
}

func rimSign(args []string) error {
	fs := flag.NewFlagSet("rim sign", flag.ExitOnError)
	input := fs.String("input", "", "unsigned CoRIM to sign")
	keyPath := fs.String("key", "", "PEM private key")
	alg := fs.String("alg", "es256", "signature algorithm: es256, es384 or es512")
	kid := fs.String("kid", "cotl-cli", "key identifier")
	signerName := fs.String("signer-name", "cotl-cli signer", "signer name recorded in corim-meta")
	notAfter := fs.String("not-after", "", "signature validity end (RFC 3339 or Unix seconds)")
	out := fs.String("o", "signed.corim", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	key, err := loadECDSAPrivateKey(*keyPath)
	if err != nil {
		return err
	}

	algID, err := coseAlg(*alg)
	if err != nil {
		return err
	}

	signer, err := cose.NewSigner(algID, key)
	if err != nil {
		return fmt.Errorf("signer creation failed: %w", err)
	}

	na, err := parseTime(*notAfter)
	if err != nil {
		return err
	}

	unsignedBuf, err := os.ReadFile(*input)
	if err != nil {
		return err
	}

	sc := &corim.SignedCorim{}
	if err := sc.UnsignedCorim.FromCBOR(unsignedBuf); err != nil {
		return fmt.Errorf("%s is not an unsigned CoRIM: %w", *input, err)
	}
	sc.Meta = *corim.NewMeta().SetSigner(*signerName, nil).SetValidity(na, ptrTime(time.Now()))
	if *kid != "" && *kid != "cotl-cli" {
		fmt.Fprintln(os.Stderr,
			"warning: corim v1.1.2 does not support embedding kid in the signed CoRIM header; ignoring")
	}

	signedBuf, err := sc.Sign(signer)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	if err := os.WriteFile(*out, signedBuf, 0o600); err != nil {
		return err
	}

	fmt.Printf("wrote signed CoRIM %s (%d)\n", *out, len(signedBuf))

	return nil
}

func rimVerify(args []string) error {
	fs := flag.NewFlagSet("rim verify", flag.ExitOnError)
	keyPath := fs.String("key", "", "PEM public key of the signer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *keyPath == "" {
		return errors.New("usage: rim verify --key PUB.pem FILE")
	}

	pub, err := loadECDSPublicKey(*keyPath)
	if err != nil {
		return err
	}

	buf, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}

	sc := &corim.SignedCorim{}
	if err := sc.FromCOSE(buf); err != nil {
		return fmt.Errorf("%s is not a signed CoRIM: %w", fs.Arg(0), err)
	}

	if err := sc.Verify(pub); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Println("signature valid")

	return nil
}

func rimShow(args []string) error {
	fs := flag.NewFlagSet("rim show", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: rim show FILE")
	}

	buf, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}

	// Signed form first, then unsigned.
	sc := &corim.SignedCorim{}
	if err := sc.FromCOSE(buf); err == nil {
		fmt.Println("form:      signed (COSE_Sign1 #6.18)")

		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(buf); err == nil {
			if alg, err := msg.Headers.Protected.Algorithm(); err == nil {
				fmt.Printf("algorithm: %s\n", alg)
			}
		}

		fmt.Printf("signer:    %s\n", sc.Meta.Signer.Name)
		return nil
	}

	var unsigned corim.UnsignedCorim
	if err := unsigned.FromCBOR(buf); err != nil {
		return fmt.Errorf("%s is neither a signed nor unsigned CoRIM: %w", fs.Arg(0), err)
	}

	fmt.Println("form:      unsigned (#6.501)")
	fmt.Printf("id:        %s\n", unsigned.ID.String())
	fmt.Printf("tags:      %d\n", len(unsigned.Tags))

	for i, t := range unsigned.Tags {
		if t.Number != cotl.CotlTag {
			fmt.Printf("  [tag %d] (%d bytes, not a CoTL)\n", i, len(t.Content))
			continue
		}

		tag, err := cotl.NewConciseTlTagFromCBOR(t.Content)
		if err != nil {
			fmt.Printf("  [tag %d] (%d bytes, not a CoTL)\n", i, len(t.Content))
			continue
		}
		fmt.Println("  [CoTL]")
		printCotlSummary(tag)
	}

	return nil
}

// helpers --------------------------------------------------------------------

type multiValue struct {
	values []string
}

func multiFlag(fs *flag.FlagSet, name, usage string) *multiValue {
	mv := &multiValue{}
	fs.Var(mv, name, usage)

	return mv
}

func (m *multiValue) String() string { return strings.Join(m.values, ",") }

func (m *multiValue) Set(v string) error {
	m.values = append(m.values, v)

	return nil
}

func parseTime(s string) (time.Time, error) {
	if secs, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
		return time.Unix(secs, 0).UTC(), nil
	}

	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp %q: %w", s, err)
	}

	return ts, nil
}

func ptrTime(ts time.Time) *time.Time { return &ts }

func writePEM(path, blockType string, der []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func coseAlg(alg string) (cose.Algorithm, error) {
	switch strings.ToLower(alg) {
	case "es256":
		return cose.AlgorithmES256, nil
	case "es384":
		return cose.AlgorithmES384, nil
	case "es512":
		return cose.AlgorithmES512, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm %q (want es256, es384 or es512)", alg)
	}
}
