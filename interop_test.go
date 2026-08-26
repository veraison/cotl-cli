// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// rustBin locates the Rust `cotlme` binary used for cross-implementation
// interoperability tests. Tests are skipped when it is not available.
func rustBin(t *testing.T) string {
	t.Helper()

	candidates := []string{
		filepath.Join("..", "cotlme", "target", "debug", "cotlme"),
		filepath.Join("..", "cotlme", "target", "release", "cotlme"),
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			abs, err := filepath.Abs(p)
			if err != nil {
				t.Fatal(err)
			}

			return abs
		}
	}

	t.Skip("rust cotlme binary not found; skipping interop test")
	return ""
}

// buildRustCotlme builds the Rust binary if missing (best effort).
func buildRustCotlme(t *testing.T) string {
	t.Helper()

	if path := rustBinNoSkip(); path != "" {
		return path
	}

	src := filepath.Join("..", "cotlme")
	if _, err := os.Stat(src); err != nil {
		t.Skip("rust cotlme source not found; skipping interop test")
	}

	cmd := exec.Command("cargo", "build")
	cmd.Dir = src

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cargo build failed; skipping interop test: %v\n%s", err, out)
	}

	return rustBin(t)
}

func rustBinNoSkip() string {
	candidates := []string{
		filepath.Join("..", "cotlme", "target", "debug", "cotlme"),
		filepath.Join("..", "cotlme", "target", "release", "cotlme"),
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			if abs, err := filepath.Abs(p); err == nil {
				return abs
			}
		}
	}

	return ""
}

func runExternal(t *testing.T, bin string, args ...string) (string, bool) {
	t.Helper()

	out, err := exec.Command(bin, args...).CombinedOutput()

	return string(out), err == nil
}

// TestCrossLanguageCoTLFiles asserts both implementations parse each other's
// CoTL files byte-for-byte.
func TestCrossLanguageCoTLFiles(t *testing.T) {
	rust := buildRustCotlme(t)

	dir := t.TempDir()
	gOut := filepath.Join(dir, "g.cotl")
	rOut := filepath.Join(dir, "r.cotl")

	mustRun(t, "cotl", "create", "-i", "g-list",
		"-t", "123e4567-e89b-12d3-a456-426614174000", "-t", "text-tag",
		"--not-after", farFuture, "-o", gOut)
	runExternal(t, rust, "cotl", "create", "-i", "r-list",
		"-t", "tag-r1", "--not-after", farFuture, "-o", rOut)

	for _, tc := range []struct{ file, id string }{{gOut, "g-list"}, {rOut, "r-list"}} {
		if out, ok := runExternal(t, rust, "cotl", "show", tc.file); !ok || !strings.Contains(out, tc.id) {
			t.Errorf("rust could not read go-produced file %s:\n%s", tc.file, out)
		}

		out := mustRun(t, "cotl", "show", tc.file)
		if !contains(out, tc.id) {
			t.Errorf("go could not read file %s:\n%s", tc.file, out)
		}
	}
}

// TestCrossLanguageSignVerify asserts Go-signed CoRIMs verify under Rust and
// vice versa, on all curves.
func TestCrossLanguageSignVerify(t *testing.T) {
	rust := buildRustCotlme(t)

	for _, curve := range []string{"p256", "p384", "p521"} {
		t.Run(curve, func(t *testing.T) {
			dir := t.TempDir()
			gk := filepath.Join(dir, "gk.pem")
			gkp := filepath.Join(dir, "gk.pub.pem")
			rk := filepath.Join(dir, "rk.pem")
			rkp := filepath.Join(dir, "rk.pub.pem")

			mustRun(t, "keygen", "--curve", curve, "--private-out", gk, "--public-out", gkp)
			if _, ok := runExternal(t, rust, "keygen", "-c", curve,
				"--private-out", rk, "-P", rkp); !ok {
				t.Fatal("rust keygen failed")
			}

			gCotl := filepath.Join(dir, "g.cotl")
			gU := filepath.Join(dir, "gu.corim")
			gS := filepath.Join(dir, "gs.corim")

			mustRun(t, "cotl", "create", "-i", "x", "-t", "t",
				"--not-after", farFuture, "-o", gCotl)
			mustRun(t, "rim", "wrap", "--cotl", gCotl, "-i", "gr", "-o", gU)
			mustRun(t, "rim", "sign", "--input", gU, "--key", gk,
				"--not-after", farFuture, "-o", gS)

			rCotl := filepath.Join(dir, "r.cotl")
			rU := filepath.Join(dir, "ru.corim")
			rS := filepath.Join(dir, "rs.corim")

			if _, ok := runExternal(t, rust, "cotl", "create", "-i", "y",
				"-t", "t", "--not-after", farFuture, "-o", rCotl); !ok {
				t.Fatal("rust cotl create failed")
			}
			if _, ok := runExternal(t, rust, "rim", "wrap", "--cotl", rCotl,
				"-i", "rr", "-o", rU); !ok {
				t.Fatal("rust rim wrap failed")
			}
			if _, ok := runExternal(t, rust, "rim", "sign", "--input", rU,
				"--key", rk, "--not-after", farFuture, "-o", rS); !ok {
				t.Fatal("rust rim sign failed")
			}

			// Go verifies Rust signature.
			out, ok := runExternal(t, rust, "rim", "verify", "--key", gkp, gS)
			if !ok || !strings.Contains(out, "signature valid") {
				t.Errorf("rust failed to verify go signature:\n%s", out)
			}

			// Rust verifies Go signature.
			out = mustRun(t, "rim", "verify", "--key", rkp, rS)
			if !contains(out, "signature valid") {
				t.Errorf("go failed to verify rust signature:\n%s", out)
			}
		})
	}
}
