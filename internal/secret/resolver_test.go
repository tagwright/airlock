// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSecretFile drops name -> content under dir and returns dir. Helper
// for the file-source cases.
func writeSecretFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write secret file %q: %v", name, err)
	}
}

// TestFileEnvResolver_FileTakesPrecedenceOverEnv proves the documented
// resolution order: when both a secrets-directory file and the fallback env
// var are present, the file wins.
func TestFileEnvResolver_FileTakesPrecedenceOverEnv(t *testing.T) {
	dir := t.TempDir()
	writeSecretFile(t, dir, "ntfy-token", "from-file")
	t.Setenv("AIRLOCK_SECRET_NTFY_TOKEN", "from-env")

	got, err := FileEnvResolver(dir)("ntfy-token")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-file" {
		t.Errorf("value = %q, want %q (file must win over env)", got, "from-file")
	}
}

// TestFileEnvResolver_EnvFallbackWhenNoFile proves that with no file for the
// name, resolution falls back to AIRLOCK_SECRET_<NAME>.
func TestFileEnvResolver_EnvFallbackWhenNoFile(t *testing.T) {
	dir := t.TempDir() // empty: no file for the name
	t.Setenv("AIRLOCK_SECRET_NTFY_TOKEN", "from-env")

	got, err := FileEnvResolver(dir)("ntfy-token")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-env" {
		t.Errorf("value = %q, want %q (env fallback)", got, "from-env")
	}
}

// TestFileEnvResolver_NotFoundErrors proves the not-found path: neither a
// file nor an env var, so the resolver returns an error naming the secret
// (so a channel send fails loudly rather than sending an empty credential),
// never an empty value with a nil error.
func TestFileEnvResolver_NotFoundErrors(t *testing.T) {
	dir := t.TempDir()
	// Guard against a leaked env var from the ambient environment.
	os.Unsetenv("AIRLOCK_SECRET_MISSING_TOKEN")

	got, err := FileEnvResolver(dir)("missing-token")
	if err == nil {
		t.Fatalf("resolve of an absent secret returned nil error and value %q, want an error", got)
	}
	if got != "" {
		t.Errorf("value on not-found = %q, want empty", got)
	}
	if !strings.Contains(err.Error(), "missing-token") {
		t.Errorf("not-found error %q does not name the secret", err)
	}
}

// TestFileEnvResolver_Trimming proves surrounding whitespace is stripped
// identically whichever source supplied the value, so a token pasted with a
// stray trailing newline behaves the same from a file or an env var.
func TestFileEnvResolver_Trimming(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		dir := t.TempDir()
		writeSecretFile(t, dir, "tok", "\t secret-value \r\n")
		got, err := FileEnvResolver(dir)("tok")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got != "secret-value" {
			t.Errorf("file value = %q, want %q", got, "secret-value")
		}
	})

	t.Run("env", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("AIRLOCK_SECRET_TOK", "  secret-value\n")
		got, err := FileEnvResolver(dir)("tok")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got != "secret-value" {
			t.Errorf("env value = %q, want %q", got, "secret-value")
		}
	})
}

// TestFileEnvResolver_EmptyNameErrors proves an empty secret name is
// rejected before any lookup.
func TestFileEnvResolver_EmptyNameErrors(t *testing.T) {
	if _, err := FileEnvResolver("")(""); err == nil {
		t.Fatalf("empty name returned nil error, want an error")
	}
}

// TestFileEnvResolver_EmptySecretsDirDefaults proves an empty secretsDir
// falls back to DefaultSecretsDir: with no file present there, the env
// fallback still resolves, and the not-found error names the default dir.
func TestFileEnvResolver_EmptySecretsDirDefaults(t *testing.T) {
	t.Setenv("AIRLOCK_SECRET_DEFAULTDIR_TOKEN", "v")
	got, err := FileEnvResolver("")("defaultdir-token")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "v" {
		t.Errorf("value = %q, want %q", got, "v")
	}

	os.Unsetenv("AIRLOCK_SECRET_DEFAULTDIR_TOKEN")
	_, err = FileEnvResolver("")("defaultdir-token")
	if err == nil || !strings.Contains(err.Error(), DefaultSecretsDir) {
		t.Errorf("not-found error = %v, want it to name the default secrets dir %q", err, DefaultSecretsDir)
	}
}

// TestEnvVarName proves the secret-name -> env-var mapping: uppercase,
// hyphens to underscores, AIRLOCK_SECRET_ prefix.
func TestEnvVarName(t *testing.T) {
	cases := map[string]string{
		"ntfy-token":       "AIRLOCK_SECRET_NTFY_TOKEN",
		"discord-webhook":  "AIRLOCK_SECRET_DISCORD_WEBHOOK",
		"gatus-push-token": "AIRLOCK_SECRET_GATUS_PUSH_TOKEN",
		"plain":            "AIRLOCK_SECRET_PLAIN",
	}
	for in, want := range cases {
		if got := envVarName(in); got != want {
			t.Errorf("envVarName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTrimSecret proves trimSecret strips exactly the documented set of
// surrounding whitespace (spaces, tabs, CR, LF) and leaves interior
// characters untouched.
func TestTrimSecret(t *testing.T) {
	cases := map[string]string{
		"  value  ":         "value",
		"\t\r\nvalue\n\r\t": "value",
		"no-trim":           "no-trim",
		"inner space kept":  "inner space kept",
		"":                  "",
	}
	for in, want := range cases {
		if got := trimSecret(in); got != want {
			t.Errorf("trimSecret(%q) = %q, want %q", in, got, want)
		}
	}
}
