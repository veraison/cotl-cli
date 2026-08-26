// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const farFuture = "2100-01-01T00:00:00Z"

// bin builds the cotl-cli binary once per test run and returns its path.
func bin(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "cotl-cli")

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine source location")
	}

	cmd := exec.Command("go", "build", "-o", path, ".")
	cmd.Dir = filepath.Dir(thisFile)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building cotl-cli failed: %v\n%s", err, out)
	}

	return path
}

type result struct {
	stdout string
	stderr string
	ok     bool
}

func runCLI(t *testing.T, args ...string) result {
	t.Helper()

	b := bin(t)

	cmd := exec.Command(b, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, isExit := err.(*exec.ExitError); !isExit {
			t.Fatalf("running %v: %v", args, err)
		}
	}

	return result{stdout: string(out), stderr: string(out), ok: err == nil}
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()

	r := runCLI(t, args...)
	if !r.ok {
		t.Fatalf("command %v failed: %s", args, r.stdout+r.stderr)
	}

	return r.stdout
}

// lifecycle ------------------------------------------------------------------

func TestKeygenProducesUsablePEMPair(t *testing.T) {
	dir := t.TempDir()
	k := filepath.Join(dir, "k.pem")
	kp := filepath.Join(dir, "k.pub.pem")

	for _, curve := range []string{"p256", "p384", "p521"} {
		out := mustRun(t, "keygen", "--curve", curve,
			"--private-out", k, "--public-out", kp)
		if !strings.Contains(out, curve) && !strings.Contains(out, "private key") {
			t.Errorf("unexpected output: %s", out)
		}

		priv, err := os.ReadFile(k)
		if err != nil || !contains(string(priv), "BEGIN PRIVATE KEY") {
			t.Errorf("%s: bad private PEM", curve)
		}

		pub, err := os.ReadFile(kp)
		if err != nil || !contains(string(pub), "BEGIN PUBLIC KEY") {
			t.Errorf("%s: bad public PEM", curve)
		}
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}

func TestCotlCreateShowValidateLifecycle(t *testing.T) {
	dir := t.TempDir()
	cotlPath := filepath.Join(dir, "t.cotl")

	mustRun(t, "cotl", "create", "-i", "it-cotl",
		"-t", "123e4567-e89b-12d3-a456-426614174000",
		"-t", "component-fw",
		"--not-after", farFuture, "-o", cotlPath)

	show := mustRun(t, "cotl", "show", cotlPath)
	if !contains(show, "it-cotl") || !contains(show, "2 tag(s)") {
		t.Errorf("show output incomplete:\n%s", show)
	}

	valid := mustRun(t, "cotl", "validate", cotlPath)
	if !contains(valid, "valid") {
		t.Errorf("validate output = %q", valid)
	}
}

func TestCotlValidateDetectsExpiryViaAsOfTime(t *testing.T) {
	dir := t.TempDir()
	cotlPath := filepath.Join(dir, "t.cotl")

	mustRun(t, "cotl", "create", "-i", "x", "-t", "tag",
		"--not-after", "1000000000", "-o", cotlPath)

	r := runCLI(t, "cotl", "validate", "--now", "999000000", cotlPath)
	if !r.ok || !contains(r.stdout, "valid") {
		t.Errorf("expected valid as-of 2001: %+v", r)
	}

	r = runCLI(t, "cotl", "validate", cotlPath)
	if r.ok || !contains(r.stderr, "expired") {
		t.Errorf("expected expiry failure: %+v", r)
	}
}

func TestCotlCreateRejectsMissingTagsAndBadTime(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "nope.cotl")

	r := runCLI(t, "cotl", "create", "-i", "x", "--not-after", farFuture, "-o", out)
	if r.ok || !contains(r.stderr, "at least one -t/--tag") {
		t.Errorf("missing tags accepted: %+v", r)
	}

	r = runCLI(t, "cotl", "create", "-i", "x", "-t", "t",
		"--not-after", "not-a-time", "-o", out)
	if r.ok || !contains(r.stderr, "invalid timestamp") {
		t.Errorf("bad timestamp accepted: %+v", r)
	}

	r = runCLI(t, "cotl", "create", "--not-after", farFuture, "-t", "t", "-o", out)
	if r.ok || !contains(r.stderr, "-i/--id is required") {
		t.Errorf("missing id accepted: %+v", r)
	}
}

func TestNotBeforeWindowReportedViaValidate(t *testing.T) {
	dir := t.TempDir()
	cotlPath := filepath.Join(dir, "t.cotl")

	mustRun(t, "cotl", "create", "-i", "future", "-t", "tag",
		"--not-before", "4102444800", "--not-after", "4202444800",
		"-o", cotlPath)

	out := mustRun(t, "cotl", "validate", cotlPath)
	if !contains(out, "not yet valid") || !contains(out, "valid") {
		t.Errorf("expected not-yet-valid warning + valid:\n%s", out)
	}
}

func TestVersionFlagRoundTripsThroughCLI(t *testing.T) {
	dir := t.TempDir()
	cotlPath := filepath.Join(dir, "t.cotl")

	mustRun(t, "cotl", "create", "-i", "v", "--version", "42",
		"-t", "tag", "--not-after", farFuture, "-o", cotlPath)

	out := mustRun(t, "cotl", "show", cotlPath)
	if !contains(out, "(version 42)") {
		t.Errorf("version lost:\n%s", out)
	}
}

func TestDuplicateTagsWarnThroughCLIValidate(t *testing.T) {
	dir := t.TempDir()
	cotlPath := filepath.Join(dir, "t.cotl")

	mustRun(t, "cotl", "create", "-i", "d", "-t", "same", "-t", "same",
		"--not-after", farFuture, "-o", cotlPath)

	out := mustRun(t, "cotl", "validate", cotlPath)
	if !contains(out, "duplicate") {
		t.Errorf("duplicate warning missing:\n%s", out)
	}
}

// signing round-trips ----------------------------------------------------------

func TestFullSigningRoundTripAndTamperDetectionAllCurves(t *testing.T) {
	for _, curve := range []string{"p256", "p384", "p521"} {
		t.Run(curve, func(t *testing.T) {
			dir := t.TempDir()
			k := filepath.Join(dir, "k.pem")
			kp := filepath.Join(dir, "k.pub.pem")
			cotlPath := filepath.Join(dir, "t.cotl")
			unsigned := filepath.Join(dir, "u.corim")
			signed := filepath.Join(dir, "s.corim")

			mustRun(t, "keygen", "--curve", curve, "--private-out", k, "--public-out", kp)
			mustRun(t, "cotl", "create", "-i", "id", "-t", "a", "-t", "b",
				"--not-after", farFuture, "-o", cotlPath)
			mustRun(t, "rim", "wrap", "--cotl", cotlPath, "-i", "rim-id", "-o", unsigned)
			mustRun(t, "rim", "sign", "--input", unsigned, "--key", k,
				"--signer-name", "ACME", "--not-after", farFuture, "-o", signed)

			out := mustRun(t, "rim", "verify", "--key", kp, signed)
			if !contains(out, "signature valid") {
				t.Errorf("verify output = %q", out)
			}

			raw, err := os.ReadFile(signed)
			if err != nil {
				t.Fatalf("read signed: %v", err)
			}
			raw[len(raw)-3] ^= 0xAA
			if err := os.WriteFile(signed, raw, 0o600); err != nil {
				t.Fatalf("rewrite signed: %v", err)
			}

			if r := runCLI(t, "rim", "verify", "--key", kp, signed); r.ok {
				t.Error("tampered payload still verified")
			}
		})
	}
}

func TestRimVerifyRejectsWrongKey(t *testing.T) {
	dir := t.TempDir()
	k1 := filepath.Join(dir, "k1.pem")
	k1p := filepath.Join(dir, "k1.pub.pem")
	k2p := filepath.Join(dir, "k2.pub.pem")
	cotlPath := filepath.Join(dir, "t.cotl")
	unsigned := filepath.Join(dir, "u.corim")
	signed := filepath.Join(dir, "s.corim")

	mustRun(t, "keygen", "--private-out", k1, "--public-out", k1p)
	mustRun(t, "keygen", "--private-out", filepath.Join(dir, "k2.pem"), "--public-out", k2p)
	mustRun(t, "cotl", "create", "-i", "i", "-t", "t", "--not-after", farFuture, "-o", cotlPath)
	mustRun(t, "rim", "wrap", "--cotl", cotlPath, "-i", "r", "-o", unsigned)
	mustRun(t, "rim", "sign", "--input", unsigned, "--key", k1, "--not-after", farFuture, "-o", signed)

	if r := runCLI(t, "rim", "verify", "--key", k2p, signed); r.ok {
		t.Error("wrong key accepted")
	}
}

func TestRimSignRejectsAlreadySignedInput(t *testing.T) {
	dir := t.TempDir()
	k := filepath.Join(dir, "k.pem")
	kp := filepath.Join(dir, "k.pub.pem")
	cotlPath := filepath.Join(dir, "t.cotl")
	unsigned := filepath.Join(dir, "u.corim")
	signed := filepath.Join(dir, "s.corim")

	mustRun(t, "keygen", "--private-out", k, "--public-out", kp)
	mustRun(t, "cotl", "create", "-i", "i", "-t", "t", "--not-after", farFuture, "-o", cotlPath)
	mustRun(t, "rim", "wrap", "--cotl", cotlPath, "-i", "r", "-o", unsigned)
	mustRun(t, "rim", "sign", "--input", unsigned, "--key", k, "--not-after", farFuture, "-o", signed)

	r := runCLI(t, "rim", "sign", "--input", signed, "--key", k,
		"--not-after", farFuture, "-o", filepath.Join(dir, "again.corim"))
	if r.ok || !contains(r.stderr, "not an unsigned CoRIM") {
		t.Errorf("re-signing accepted: %+v", r)
	}
}

func TestRimShowReportsBothForms(t *testing.T) {
	dir := t.TempDir()
	k := filepath.Join(dir, "k.pem")
	kp := filepath.Join(dir, "k.pub.pem")
	cotlPath := filepath.Join(dir, "t.cotl")
	unsigned := filepath.Join(dir, "u.corim")
	signed := filepath.Join(dir, "s.corim")

	mustRun(t, "keygen", "--private-out", k, "--public-out", kp)
	mustRun(t, "cotl", "create", "-i", "list-id", "-t", "tag",
		"--not-after", farFuture, "-o", cotlPath)
	mustRun(t, "rim", "wrap", "--cotl", cotlPath, "-i", "rim-id", "-o", unsigned)

	out := mustRun(t, "rim", "show", unsigned)
	if !contains(out, "unsigned (#6.501)") || !contains(out, "[CoTL]") ||
		!contains(out, "list-id") {
		t.Errorf("unsigned show incomplete:\n%s", out)
	}

	mustRun(t, "rim", "sign", "--input", unsigned, "--key", k,
		"--signer-name", "Zeta Corp", "--not-after", farFuture, "-o", signed)

	out = mustRun(t, "rim", "show", signed)
	if !contains(out, "COSE_Sign1 #6.18") || !contains(out, "ES256") ||
		!contains(out, "Zeta Corp") {
		t.Errorf("signed show incomplete:\n%s", out)
	}
}

// failure paths -----------------------------------------------------------------

func TestMissingInputFilesFailCleanly(t *testing.T) {
	dir := t.TempDir()
	nope := filepath.Join(dir, "nope")

	for _, args := range [][]string{
		{"cotl", "show", nope},
		{"cotl", "validate", nope},
		{"rim", "verify", "--key", kp(t), nope},
		{"rim", "wrap", "--cotl", nope, "-i", "x", "-o", filepath.Join(dir, "o")},
	} {
		if r := runCLI(t, args...); r.ok || !contains(r.stderr, "error:") {
			t.Errorf("%v: expected clean failure, got %+v", args, r)
		}
	}
}

func kp(t *testing.T) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), "any.pem")
	if err := os.WriteFile(p, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}

	return p
}

func TestGarbageFilesFailCleanly(t *testing.T) {
	dir := t.TempDir()
	g := filepath.Join(dir, "g.bin")
	if err := os.WriteFile(g, []byte("this is not cbor"), 0o600); err != nil {
		t.Fatal(err)
	}

	if r := runCLI(t, "cotl", "show", g); r.ok {
		t.Error("garbage CoTL accepted")
	}

	if r := runCLI(t, "rim", "show", g); r.ok {
		t.Error("garbage CoRIM accepted")
	}
}

func TestSignWithMissingKeyFailsCleanly(t *testing.T) {
	dir := t.TempDir()
	unsigned := filepath.Join(dir, "u.corim")
	k := filepath.Join(dir, "k.pem")
	kp := filepath.Join(dir, "k.pub.pem")
	cotlPath := filepath.Join(dir, "t.cotl")

	mustRun(t, "keygen", "--private-out", k, "--public-out", kp)
	mustRun(t, "cotl", "create", "-i", "i", "-t", "t", "--not-after", farFuture, "-o", cotlPath)
	mustRun(t, "rim", "wrap", "--cotl", cotlPath, "-i", "r", "-o", unsigned)

	r := runCLI(t, "rim", "sign", "--input", unsigned,
		"--key", filepath.Join(dir, "gone.pem"),
		"--not-after", farFuture, "-o", filepath.Join(dir, "s.corim"))
	if r.ok || !contains(r.stderr, "error:") {
		t.Errorf("missing key accepted: %+v", r)
	}
}

// interactive wizard -------------------------------------------------------------

func TestInteractiveWizardCreateFlow(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "wiz.cotl")

	input := fmt.Sprintf(
		"1\nwizard-list\ntag-a, tag-b\n%s\n%s\n6\n",
		farFuture, out,
	)

	cmd := exec.Command(bin(t))
	cmd.Stdin = strings.NewReader(input)
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wizard failed: %v\n%s", err, outBytes)
	}

	show := mustRun(t, "cotl", "show", out)
	if !contains(show, "wizard-list") || !contains(show, "2 tag(s)") {
		t.Errorf("wizard-produced CoTL wrong:\n%s", show)
	}
}
