// SPDX-License-Identifier: GPL-3.0-or-later

// Package secret resolves the named-secret references airlock's own
// notification and telemetry channels carry (an ntfy token, a Discord
// webhook URL, a Gatus push token, and so on). It is airlock's ONLY secret
// domain: unlike ballast (repository credentials) or bilgeline (exporter
// destination secrets, kept out of this process entirely), airlock's
// grammar has no secret-shaped field at all -- see internal/config's
// package doc -- so the only credentials this process ever resolves are
// the alerting channel's own.
//
// Nothing in this package holds a secret value longer than it has to, and
// no secret value is ever logged.
package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultSecretsDir is airlock's default alerting-secrets directory, used
// when neither config.Config.SecretsDir nor AIRLOCK_SECRETS_DIR is set. It
// mirrors ballast's and bilgeline's /run/<tool>/secrets convention: a
// tmpfs mount the operator drops alerting-credential files into (e.g. via
// SOPS at deploy time).
const DefaultSecretsDir = "/run/airlock/secrets"

// Resolver resolves a named secret to its value. Its signature
// intentionally matches beacon.SecretResolver so internal/alert can hand
// it straight to beacon.New: channels and sinks name secrets, they never
// contain them.
type Resolver func(name string) (string, error)

// FileEnvResolver returns a Resolver that looks up name first as a file
// under secretsDir, then as an environment variable.
//
// Resolution order:
//  1. File filepath.Join(secretsDir, name).
//  2. Env var AIRLOCK_SECRET_<NAME>, where NAME is name uppercased with
//     "-" replaced by "_".
//  3. Neither found: an error naming the secret, so a channel's send fails
//     loudly (and is logged) rather than sending with an empty credential.
//
// Whichever source a value comes from, it is trimmed the same way: leading
// and trailing whitespace (spaces, tabs, CR, LF) is stripped before it is
// returned, so a token pasted into an env var with a stray trailing
// newline behaves exactly like one read from a file.
//
// secretsDir defaults to DefaultSecretsDir when empty.
func FileEnvResolver(secretsDir string) Resolver {
	if secretsDir == "" {
		secretsDir = DefaultSecretsDir
	}

	return func(name string) (string, error) {
		if name == "" {
			return "", fmt.Errorf("secret: empty secret name")
		}

		path := filepath.Join(secretsDir, name)
		if data, err := os.ReadFile(path); err == nil {
			return trimSecret(string(data)), nil
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("secret: read %s: %w", path, err)
		}

		envName := envVarName(name)
		if v, ok := os.LookupEnv(envName); ok {
			return trimSecret(v), nil
		}

		return "", fmt.Errorf("secret: %q not found in %s or %s", name, path, envName)
	}
}

// trimSecret strips leading and trailing whitespace (spaces, tabs, CR, LF)
// from a resolved secret value. It is applied uniformly to every source a
// Resolver can pull from, so the resolved value never depends on which
// source supplied it.
func trimSecret(v string) string {
	return strings.Trim(v, "\r\n \t")
}

// envVarName maps a secret name to the AIRLOCK_SECRET_<NAME> env var the
// resolver falls back to when no secrets-directory file exists for it.
func envVarName(name string) string {
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	return "AIRLOCK_SECRET_" + upper
}
