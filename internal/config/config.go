// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package config loads airlock's configuration from airlock.yml: the named
// policy sets a container's airlock.policy label references (Fork 5), the
// group-scoped policies that arm a whole class of containers without a
// per-container label (Fork 8), the fleet-wide defaults that mirror the
// AIRLOCK_* environment globals, the notification and telemetry channels
// internal/alert builds a beacon notifier from, and the (not yet wired up)
// observation-backend section.
//
// The file is optional. The surviving AIRLOCK_* environment variables
// overlay onto it -- env wins over the file -- so env-only operation with
// no file at all is valid, exactly like bilgeline's BILGELINE_* overlay.
//
// This package parses and validates airlock.yml's STRUCTURE only. It reuses
// internal/policy's parsers (ParseEntry, ParseMode, ParseScope) to check
// every allow/deny entry and every mode/scope value at load time, because
// airlock.yml is static config: a malformed entry here is a loud
// config-load failure, never the sticky per-container runtime warning a
// bad LABEL produces (that per-container, skip-and-alert behavior belongs
// to the label-reading layer built on top of this package, not here).
// Merging a container's own labels with the policy sets and groups that
// apply to it -- the runtime resolution the frozen grammar's specificity
// ladder describes -- is also that later layer's job; this package only
// validates that airlock.yml itself is internally consistent.
//
// See "Airlock Label Grammar (Draft)" (ratified 2026-08-27) for the frozen
// contract this package implements.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tagwright/airlock/internal/policy"
	"gopkg.in/yaml.v3"
)

// Config is airlock's daemon configuration, loaded from airlock.yml.
type Config struct {
	// Policies is the named, reusable policy-set map (Fork 5), keyed by
	// name. A container's airlock.policy label, or a group's Policy
	// field, references entries here by name.
	Policies map[string]PolicySet `yaml:"policies,omitempty"`

	// Groups is the ordered list of group-scoped policy rules (Fork 8).
	// Order has no evaluation meaning -- the specificity ladder, not
	// list position, resolves multi-group membership -- but it is
	// preserved for stable diagnostics and stable rewrites of the file.
	Groups []Group `yaml:"groups,omitempty"`

	// Defaults holds the fleet-wide tunables that mirror the AIRLOCK_*
	// environment globals. Setting one here is equivalent to setting
	// the matching env var, except the env var always wins when both
	// are present -- the same file-then-env layering bilgeline uses.
	Defaults Defaults `yaml:"defaults,omitempty"`

	// Notifications is airlock's alert-channel configuration for
	// delivery through beacon (the digest, sticky validation-error
	// reports, and flood-breaker summaries).
	Notifications Notifications `yaml:"notifications,omitempty"`

	// Telemetry is the list of health/status push sinks (e.g. a Gatus
	// external endpoint), separate from the alert channels above. It
	// mirrors ballast's and bilgeline's Config.Telemetry field-for-field.
	Telemetry []TelemetryConfig `yaml:"telemetry,omitempty"`

	// SecretsDir is the directory internal/alert's secret resolver reads
	// named-secret files from, for the credentials Notifications and
	// Telemetry settings name (never hold literally). Overridable by
	// AIRLOCK_SECRETS_DIR. Defaults to secret.DefaultSecretsDir when
	// unset. This is airlock's OWN alerting-secrets directory: it has
	// nothing to do with any credential a container's own workload
	// might use, and nothing here is ever a container label.
	SecretsDir string `yaml:"secrets_dir,omitempty"`

	// Observe is the observation backend's configuration, mirroring
	// internal/observe/ig.Options field-for-field where practical (ig
	// binary path, per-gadget image pins, runtimes, docker socket
	// path).
	//
	// TODO(observe-wiring chunk): this section is parsed and given
	// light structural validation here only. Converting it into an
	// actual ig.Options and constructing the backend is a later
	// chunk's job; nothing here starts or contacts ig.
	Observe ObserveConfig `yaml:"observe,omitempty"`

	// Warnings collects non-fatal issues Validate found: declared but
	// practically inert configuration (a scope=all-only token used
	// without scope=all, an allow: "*" policy with no deny rules to
	// carve anything back out). These are not config-load errors --
	// Load still succeeds -- but a caller should surface them the same
	// way the frozen grammar's own "validation warning" language
	// intends: loud, not silent. Populated fresh on every Validate
	// call, never accumulated across calls.
	Warnings []string `yaml:"-"`
}

// Defaults are the fleet-wide tunables mirroring the AIRLOCK_* environment
// globals documented in the frozen grammar's "Global defaults" section.
// Field names follow the env var names (snake_case, minus the AIRLOCK_
// prefix), not the per-container label names, because these mirror an env
// var, not a label -- unlike PolicySet.AlertWindow and Group.AlertWindow,
// which deliberately DO mirror the label name (airlock.alert.window)
// one-to-one per the frozen grammar's explicit "identical field names"
// instruction for group body fields.
//
// Deliberately absent: fleet-wide Allow/Deny fields. The frozen grammar is
// explicit that per-container policy keys have no global env form -- a
// fleet-wide allow is what ImplicitAllow is for (small and named as a
// baseline extension), and a fleet-wide deny would let policy hide in env
// while labels claim the whole story, making docker inspect lie about what
// alerts. Fleet-wide policy that needs real structure is a Group, not a
// default.
type Defaults struct {
	// Observe is the observation scope: "all" (default, fleet-wide
	// regardless of arming) or "enabled" (only containers with a
	// policy evaluated at all). AIRLOCK_OBSERVE overlays this.
	Observe string `yaml:"observe,omitempty"`

	// DefaultMode is the fleet-wide default for airlock.mode /
	// groups[].mode when a container or group leaves it unset:
	// "alert" (default) or "audit". Never "block" in v1.
	// AIRLOCK_DEFAULT_MODE overlays this.
	DefaultMode string `yaml:"default_mode,omitempty"`

	// DefaultScope is the fleet-wide default for airlock.scope /
	// groups[].scope: "external" (default) or "all".
	// AIRLOCK_DEFAULT_SCOPE overlays this.
	DefaultScope string `yaml:"default_scope,omitempty"`

	// AlertWindow is the fleet-wide default dedup window (a Go
	// duration string) when a container or group leaves
	// airlock.alert.window unset. Default "1h". AIRLOCK_ALERT_WINDOW
	// overlays this.
	AlertWindow string `yaml:"alert_window,omitempty"`

	// AlertFlood is the distinct-identity alert count per container per
	// hour before the global flood breaker collapses that container to
	// a single "flooding" alert. Default 30. AIRLOCK_ALERT_FLOOD
	// overlays this.
	AlertFlood int `yaml:"alert_flood,omitempty"`

	// DigestSchedule is the plain cron schedule for the one digest per
	// period. Default "0 0 * * *" (daily at midnight).
	// AIRLOCK_DIGEST_SCHEDULE overlays this.
	DigestSchedule string `yaml:"digest_schedule,omitempty"`

	// ImplicitAllow extends the fixed resolver-on-port-53 baseline with
	// additional entries, or is the literal "none" to disable even the
	// resolver baseline for a hardened fleet. Empty means the baseline
	// only, unmodified. AIRLOCK_IMPLICIT_ALLOW overlays this (a csv
	// value, or "none").
	ImplicitAllow EntryList `yaml:"implicit_allow,omitempty"`

	// UnpoliciedDigest opts in to the first-seen-destination-per-day
	// digest summary for containers with no declared policy at all.
	// Default false. AIRLOCK_UNPOLICIED_DIGEST overlays this.
	UnpoliciedDigest bool `yaml:"unpolicied_digest,omitempty"`
}

// Notifications is airlock.yml's alert-channel configuration. Its shape
// mirrors bilgeline's ChannelConfig (a backend type, a minimum severity,
// and a backend-specific settings map of secret NAMES, never literal
// tokens) since that is the suite's established shape for exactly this
// concern: delivery through the beacon notifier that runs inside the
// daemon's own process.
//
// This shape is FINAL as of the alert chunk (internal/alert.New consumes
// it directly): only Type is structurally validated here (must be
// non-empty). The valid backend-type enum is beacon's own registry
// (internal/alert imports the beacon package, which self-registers every
// backend it ships via init()), so hardcoding that list here would risk
// drifting out of sync with it; an unknown Type surfaces as an error from
// beacon.New instead, at alert-construction time.
type Notifications struct {
	Channels []NotificationChannel `yaml:"channels,omitempty"`
}

// NotificationChannel is one alert channel airlock reports through.
type NotificationChannel struct {
	// Type selects the backend, e.g. "ntfy", "discord", "smtp",
	// "webhook". Required. Passed straight through to
	// beacon.ChannelConfig.Type.
	Type string `yaml:"type"`

	// Name is an optional human label for this channel, distinct from
	// Type, so a fleet with two channels of the same Type (say, two ntfy
	// topics) can still be told apart in airlock's own error messages
	// and logs. It plays no role in beacon itself (beacon.ChannelConfig
	// has no name field); it defaults to Type when empty.
	Name string `yaml:"name,omitempty"`

	// MinLevel is the minimum severity this channel fires on. Empty
	// means "receive everything". Passed through parseLevel to a
	// beacon.Level.
	MinLevel string `yaml:"min_level,omitempty"`

	// Settings carries backend-specific config, passed straight through
	// to beacon.ChannelConfig.Settings. Credential values are secret
	// NAMES resolved at send time by the backend itself (via the
	// resolver internal/alert builds from SecretsDir), never literal
	// tokens, per the suite-wide secrets rule -- this grammar has no
	// separate "secret ref" field because beacon's own contract is that
	// ANY settings value naming a secret is resolved this way; which
	// keys are secret names is a property of the backend, not of this
	// struct.
	Settings map[string]string `yaml:"settings,omitempty"`
}

// TelemetryConfig is one telemetry sink airlock pushes health/status to
// (e.g. a Gatus external endpoint for the dead-man's-switch heartbeat).
// Mirrors NotificationChannel's non-import, secret-naming shape and
// ballast's/bilgeline's TelemetryConfig field-for-field.
type TelemetryConfig struct {
	// Type selects the sink, e.g. "gatus". Required.
	Type string `yaml:"type"`

	// Settings carries sink-specific config. Values that are secrets are
	// named, never literal, same rule as NotificationChannel.Settings.
	Settings map[string]string `yaml:"settings,omitempty"`
}

// ObserveConfig is airlock.yml's observation-backend configuration. It
// mirrors internal/observe/ig.Options field-for-field where practical, so
// converting one into the other is a mechanical, obvious mapping for the
// chunk that owns wiring it up.
//
// TODO(observe-wiring chunk): only light structural checks run here
// (Images keys must name a gadget this backend knows about). Applying
// ig.Options' own defaults, and constructing the actual backend, belongs
// to that later chunk.
type ObserveConfig struct {
	// IGPath is the path to (or name of) the ig binary. Mirrors
	// ig.Options.IGPath. Empty defers to ig's own default ("ig",
	// resolved via PATH).
	IGPath string `yaml:"ig_path,omitempty"`

	// Images maps gadget name ("trace_tcp", "trace_dns", "trace_sni")
	// to a pinned OCI image reference, for digest pinning in
	// production. Mirrors ig.Options.Images.
	Images map[string]string `yaml:"images,omitempty"`

	// Runtimes is passed as ig run's -r/--runtimes flag. Mirrors
	// ig.Options.Runtimes. Empty defers to ig's own default.
	Runtimes string `yaml:"runtimes,omitempty"`

	// DockerSocketPath is passed as ig run's --docker-socketpath flag
	// when non-empty. Mirrors ig.Options.DockerSocketPath.
	DockerSocketPath string `yaml:"docker_socketpath,omitempty"`
}

// knownGadgets are the gadget names ObserveConfig.Images may key by. This
// intentionally duplicates the gadget name strings documented (but left
// unexported) on internal/observe/ig.Options.Images -- config does not
// import the ig package's private constants, and ig does not currently
// export a name list for config to import instead. If a gadget is ever
// added or renamed there, this list needs the matching update; the
// observe-wiring chunk is a natural point to instead have ig export its
// own name list and delete this duplication.
var knownGadgets = []string{"trace_tcp", "trace_dns", "trace_sni"}

// Defaults applied to any Config field left unset after the file and env
// passes, matching the frozen grammar's documented defaults exactly.
const (
	defaultObserve        = "all"
	defaultMode           = "alert"
	defaultScope          = "external"
	defaultAlertWindow    = "1h"
	defaultAlertFlood     = 30
	defaultDigestSchedule = "0 0 * * *"

	// defaultSecretsDir mirrors ballast's and bilgeline's
	// /run/<tool>/secrets convention: a tmpfs mount the operator drops
	// alerting-credential files into (e.g. via SOPS at deploy time).
	// internal/secret.DefaultSecretsDir carries this same value; it is
	// restated here rather than imported so internal/config does not
	// need to depend on internal/secret just for one constant.
	defaultSecretsDir = "/run/airlock/secrets"
)

// noneSentinel is the reserved "explicitly nothing" value, shared by
// airlock.allow/deny and AIRLOCK_IMPLICIT_ALLOW.
const noneSentinel = "none"

// Load reads the YAML config at path, overlays the surviving AIRLOCK_*
// environment variables (env wins over the file), applies built-in
// defaults, and validates the result. A valid *Config is returned only
// when Validate passes; a non-fatal issue is instead recorded on the
// returned Config's Warnings.
//
// path is optional: an empty path, or a path that does not exist, is not
// an error -- Load returns a defaulted, validated Config in that case, so
// env-only operation with no file at all works, exactly like bilgeline.
func Load(path string) (*Config, error) {
	cfg := &Config{}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("config: read %s: %w", path, err)
			}
		} else if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}

	overlayEnv(cfg)
	applyDefaults(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// overlayEnv applies the surviving AIRLOCK_* globals. Any variable that is
// set wins over the file (or the zero value). There is deliberately no
// env form for a fleet-wide allow/deny -- see Defaults' doc comment.
func overlayEnv(cfg *Config) {
	if v, ok := os.LookupEnv("AIRLOCK_OBSERVE"); ok {
		cfg.Defaults.Observe = v
	}
	if v, ok := os.LookupEnv("AIRLOCK_DEFAULT_MODE"); ok {
		cfg.Defaults.DefaultMode = v
	}
	if v, ok := os.LookupEnv("AIRLOCK_DEFAULT_SCOPE"); ok {
		cfg.Defaults.DefaultScope = v
	}
	if v, ok := os.LookupEnv("AIRLOCK_ALERT_WINDOW"); ok {
		cfg.Defaults.AlertWindow = v
	}
	if v, ok := os.LookupEnv("AIRLOCK_ALERT_FLOOD"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			cfg.Defaults.AlertFlood = n
		} else {
			// Left as-is; Validate reports a clear error for a
			// non-numeric value rather than silently ignoring it.
			cfg.Defaults.AlertFlood = -1
		}
	}
	if v, ok := os.LookupEnv("AIRLOCK_DIGEST_SCHEDULE"); ok {
		cfg.Defaults.DigestSchedule = v
	}
	if v, ok := os.LookupEnv("AIRLOCK_IMPLICIT_ALLOW"); ok {
		cfg.Defaults.ImplicitAllow = parseEntryListEnv(v)
	}
	if v, ok := os.LookupEnv("AIRLOCK_UNPOLICIED_DIGEST"); ok {
		cfg.Defaults.UnpoliciedDigest = strings.EqualFold(strings.TrimSpace(v), "true")
	}
	if v, ok := os.LookupEnv("AIRLOCK_SECRETS_DIR"); ok {
		cfg.SecretsDir = v
	}
}

// parseEntryListEnv parses an AIRLOCK_IMPLICIT_ALLOW-shaped env value: the
// literal "none", or a csv of entries.
func parseEntryListEnv(v string) EntryList {
	v = strings.TrimSpace(v)
	if v == noneSentinel {
		return EntryList{None: true}
	}
	return EntryList{Entries: splitCSV(v)}
}

// applyDefaults fills sane defaults for anything left unset after the
// file and env passes.
func applyDefaults(cfg *Config) {
	if cfg.Defaults.Observe == "" {
		cfg.Defaults.Observe = defaultObserve
	}
	if cfg.Defaults.DefaultMode == "" {
		cfg.Defaults.DefaultMode = defaultMode
	}
	if cfg.Defaults.DefaultScope == "" {
		cfg.Defaults.DefaultScope = defaultScope
	}
	if cfg.Defaults.AlertWindow == "" {
		cfg.Defaults.AlertWindow = defaultAlertWindow
	}
	if cfg.Defaults.AlertFlood == 0 {
		cfg.Defaults.AlertFlood = defaultAlertFlood
	}
	if cfg.Defaults.DigestSchedule == "" {
		cfg.Defaults.DigestSchedule = defaultDigestSchedule
	}
	if cfg.SecretsDir == "" {
		cfg.SecretsDir = defaultSecretsDir
	}
}

// cronFieldsRE is a light structural check for "plain cron": five
// whitespace-separated fields. This package does not own schedule
// evaluation (a later chunk does), so it deliberately does not validate
// field ranges or step/list syntax, only that the value has the right
// shape to be a cron expression at all, so an obviously-wrong value (an
// empty string, a duration, a single word) fails fast at config load
// rather than at the first missed digest.
var cronFieldsRE = regexp.MustCompile(`^\S+(\s+\S+){4}$`)

// Validate checks the config for internal consistency, aggregating every
// problem it finds into one error so a bad airlock.yml surfaces all its
// faults at once rather than one per run. Non-fatal issues are recorded on
// c.Warnings instead of returned as an error; c.Warnings is reset at the
// start of every call.
func (c *Config) Validate() error {
	var errs []error
	var warns []string
	c.Warnings = nil

	policyNames := make(map[string]struct{}, len(c.Policies))
	for name := range c.Policies {
		policyNames[name] = struct{}{}
	}

	for name, ps := range c.Policies {
		ps.validate(name, &errs, &warns)
	}

	seenGroupNames := make(map[string]int, len(c.Groups))
	for i := range c.Groups {
		c.Groups[i].validate(i, policyNames, &errs, &warns)
		name := c.Groups[i].Name
		if name != "" {
			if prev, ok := seenGroupNames[name]; ok {
				errs = append(errs, fmt.Errorf("groups[%d] and groups[%d]: duplicate group name %q", prev, i, name))
			} else {
				seenGroupNames[name] = i
			}
		}
	}

	checkAllowNoneContradiction(c.Groups, c.Policies, &errs)

	validateDefaults(c.Defaults, &errs)

	for i, ch := range c.Notifications.Channels {
		if ch.Type == "" {
			errs = append(errs, fmt.Errorf("notifications.channels[%d]: missing type", i))
		}
	}

	for i, t := range c.Telemetry {
		if t.Type == "" {
			errs = append(errs, fmt.Errorf("telemetry[%d]: missing type", i))
		}
	}

	for gadget := range c.Observe.Images {
		if !contains(knownGadgets, gadget) {
			errs = append(errs, fmt.Errorf("observe.images: unknown gadget %q, want one of %s", gadget, strings.Join(knownGadgets, ", ")))
		}
	}

	c.Warnings = warns

	return errors.Join(errs...)
}

// checkAllowNoneContradiction enforces the Fork 5 rule that
// airlock.allow=none (the zero-egress sentinel) combined with a policy
// reference whose sets contain allow entries is contradictory, applied
// here to groups: a group declaring allow: "none" while also referencing
// a policy set that itself allows something is the same contradiction the
// frozen grammar names for per-container labels, and Validate is the
// natural place to catch it for groups too since both fields live in
// airlock.yml.
func checkAllowNoneContradiction(groups []Group, policies map[string]PolicySet, errs *[]error) {
	for i, g := range groups {
		if !g.Allow.None {
			continue
		}
		for _, name := range g.Policy {
			ps, ok := policies[name]
			if !ok {
				continue // already reported as an unknown reference
			}
			if !ps.Allow.None && len(ps.Allow.Entries) > 0 {
				label := fmt.Sprintf("groups[%d]", i)
				if g.Name != "" {
					label = fmt.Sprintf("groups[%q]", g.Name)
				}
				*errs = append(*errs, fmt.Errorf(`%s: allow: "none" declares zero egress, but it also references policy set %q, which allows %d destination(s) -- "none" is a declaration, not a filter, so this is contradictory, not a suppression`, label, name, len(ps.Allow.Entries)))
			}
		}
	}
}

// validateDefaults checks the Defaults section.
func validateDefaults(d Defaults, errs *[]error) {
	if d.Observe != "all" && d.Observe != "enabled" {
		*errs = append(*errs, fmt.Errorf("defaults.observe: invalid value %q: must be one of all, enabled", d.Observe))
	}
	if _, err := policy.ParseMode(d.DefaultMode); err != nil {
		*errs = append(*errs, fmt.Errorf("defaults.default_mode: %w", err))
	}
	if _, err := policy.ParseScope(d.DefaultScope); err != nil {
		*errs = append(*errs, fmt.Errorf("defaults.default_scope: %w", err))
	}
	if _, err := time.ParseDuration(d.AlertWindow); err != nil {
		*errs = append(*errs, fmt.Errorf("defaults.alert_window: invalid duration %q: %w", d.AlertWindow, err))
	}
	if d.AlertFlood <= 0 {
		*errs = append(*errs, fmt.Errorf("defaults.alert_flood: invalid value %d: must be a positive integer (from AIRLOCK_ALERT_FLOOD if set)", d.AlertFlood))
	}
	if !cronFieldsRE.MatchString(strings.TrimSpace(d.DigestSchedule)) {
		*errs = append(*errs, fmt.Errorf("defaults.digest_schedule: %q does not look like a 5-field plain cron expression", d.DigestSchedule))
	}
	validateEntryList("defaults.implicit_allow", d.ImplicitAllow, errs)
}

// contains reports whether s is in list.
func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
