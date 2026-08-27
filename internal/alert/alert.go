// SPDX-License-Identifier: GPL-3.0-or-later

// Package alert turns engine violations and discovery diagnostics into
// notifications delivered through the beacon library, implementing the
// alert-volume contract Fork 6 of the frozen "Airlock Label Grammar
// (Draft)" defines:
//
//   - Alert identity is (service, destination, port, class). The FIRST
//     occurrence of a new identity in Alert mode alerts immediately, never
//     delayed.
//   - Repeats of the same identity within its window (the resolved
//     policy's AlertWindow, else the fleet-wide default) are suppressed
//     and counted, not sent. The count surfaces in the next digest, and in
//     the next immediate alert for that identity once the window rolls.
//   - Audit-mode violations never alert immediately; they are tallied for
//     the digest only.
//   - A global flood breaker collapses a container to a single "flooding"
//     alert once its DISTINCT-identity immediate alerts exceed the flood
//     cap within a rolling hour, resuming normal alerting once the rate
//     falls.
//   - One digest per period carries suppressed counts, audit tallies,
//     sticky validation diagnostics, flood episodes, and (if fed) an
//     unpolicied first-seen summary.
//
// See "Airlock Label Grammar (Draft)" (ratified 2026-08-27), Fork 6, for
// the full contract.
//
// # Concurrency
//
// The daemon's serialized reconcile/event loop is expected to call
// Violation and Diagnostic (bracketed by StartReconcile / EndReconcile once
// per reconcile pass) from a single goroutine, never concurrently with
// itself. Digest and Report are called from the daemon's own timer
// goroutines -- the cron ticker and the telemetry heartbeat both live in
// the daemon, not here -- and DO run concurrently with the event loop's
// calls and with each other. All of an Alerter's mutable state is
// therefore behind one mutex, held only for the duration of the state
// touch itself; the (potentially slow, network-bound) beacon.Notify /
// beacon.Report calls happen outside the lock.
package alert

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tagwright/beacon"

	"github.com/tagwright/airlock/internal/config"
	"github.com/tagwright/airlock/internal/discovery"
	"github.com/tagwright/airlock/internal/engine"
	"github.com/tagwright/airlock/internal/policy"
	"github.com/tagwright/airlock/internal/secret"
)

// Bounds on the state this package tracks, so a hostile flood (unbounded
// distinct identities, an unbounded number of misbehaving containers, or
// an unbounded number of broken policies) cannot grow memory without
// limit. Eviction is FIFO by insertion order, not a true LRU: a full scan
// to find the single oldest entry is cheap at these sizes and this is a
// backstop behind the flood breaker (which is the REAL defense against
// unbounded distinct identities), not expected to trigger on a sane fleet.
const (
	// maxIdentityStates bounds the per-identity dedup map.
	maxIdentityStates = 20000

	// maxContainerStates bounds the per-container flood-breaker map.
	maxContainerStates = 4000

	// maxStickyDiagnostics bounds the sticky-diagnostic set the digest
	// re-lists every period.
	maxStickyDiagnostics = 4000

	// defaultFloodWindow is the flood breaker's per-container window.
	//
	// JUDGMENT CALL (flagged for doc reconciliation): the frozen doc
	// calls this a "rolling hour". This package implements a TUMBLING
	// (fixed, reset-on-elapse) hour instead of a true sliding window over
	// individual timestamps. A true rolling window that still only counts
	// DISTINCT identities would need to remember which identities have
	// already been counted this hour to avoid a window-rolled repeat of
	// an already-counted identity inflating the tally again -- exactly
	// the unbounded-memory shape (remembering every distinct identity)
	// the flood breaker exists to defend against. A tumbling hour is O(1)
	// per container and differs from a true rolling hour only at the
	// reset boundary (a burst straddling the boundary can count against
	// two consecutive windows). See countFlood's doc comment for the
	// companion judgment call: only a brand-new identity's first-ever
	// alert increments the tally at all, which is what makes "distinct"
	// free to compute without storing the identity set.
	defaultFloodWindow = time.Hour
)

// identityState is the per-identity dedup bookkeeping for one alert
// identity (service, destination, port, class).
type identityState struct {
	order int // insertion sequence, for FIFO eviction

	windowStart time.Time

	// suppressedForAlert counts repeats suppressed since the last
	// immediate alert for this identity (first-hit or window-rolled). It
	// is reported as "N since last alert" on the NEXT immediate alert,
	// then reset to 0.
	suppressedForAlert int

	// suppressedForDigest counts repeats suppressed since the last
	// Digest call. It is independent of suppressedForAlert: the digest
	// and the next per-identity immediate alert are two different
	// readers of "how many repeats happened", each with its own reset
	// point, so one reporting a count never erases the other's view of
	// the same underlying suppressions.
	suppressedForDigest int
}

// containerFloodState is the per-container flood-breaker bookkeeping.
type containerFloodState struct {
	order int

	windowStart   time.Time
	distinctCount int
	notified      bool // whether the collapse alert has already fired this window
	lastTally     int  // distinctCount at the moment notified was last set true
}

// stickyDiag is one sticky discovery.Diagnostic the digest re-lists every
// period, keyed by (containerID, message).
type stickyDiag struct {
	order int

	level         discovery.DiagLevel
	message       string
	containerID   string
	containerName string
	alerted       bool // whether the one-shot Error immediate alert already fired
}

// Alerter routes engine.Violations and discovery.Diagnostics through a
// beacon.Beacon per the Fork 6 alert-volume contract. Build one with New
// and reuse it for the process's lifetime.
type Alerter struct {
	mu sync.Mutex

	b *beacon.Beacon

	defaultWindow time.Duration
	floodCap      int

	now func() time.Time

	// windows holds the per-service AlertWindow override fed by
	// SetWindow, keyed by service name (the same key Identity.Service
	// uses, since replicas sharing a service name share one window).
	windows map[string]time.Duration

	identities   map[engine.Identity]*identityState
	identitySeq  int
	containers   map[string]*containerFloodState
	containerSeq int
	sticky       map[string]*stickyDiag
	stickySeq    int

	// reconcileSeen, when non-nil, marks the sticky keys fed since the
	// last StartReconcile. nil outside a StartReconcile/EndReconcile
	// bracket, so Diagnostic calls outside a bracket never age anything
	// out on their own.
	reconcileSeen map[string]bool

	// auditTally counts audit-mode violations per identity since the
	// last Digest.
	auditTally map[engine.Identity]int

	// unpolicied holds the next digest's unpolicied first-seen summary,
	// fed by FeedUnpoliciedSummary and consumed (cleared) by Digest.
	unpolicied []string
}

// Option configures an Alerter at construction time.
type Option func(*Alerter)

// WithClock overrides an Alerter's time source. Meant for tests: the
// window and flood-breaker logic is otherwise driven by time.Now, which
// makes an hour-scale flood window impractical to exercise directly.
func WithClock(now func() time.Time) Option {
	return func(a *Alerter) { a.now = now }
}

// New builds an Alerter from cfg's notification and telemetry
// configuration, resolving named channel/sink secrets through resolver
// (typically secret.FileEnvResolver(cfg.SecretsDir); nil is accepted and
// treated as beacon does -- every secret lookup then fails, which only
// matters to a backend whose settings actually name one).
//
// beacon's built-in "log" backend is ALWAYS wired ahead of any configured
// channel, mirroring bilgeline's stricter convention (ballast wires it
// only as a fallback when zero channels are configured): airlock is a
// security tool, and this suite's house rule that an unprotected
// container must never go silent extends naturally to "an alert must
// never go silent" too.
//
// cfg.Defaults.AlertWindow and cfg.Defaults.AlertFlood supply the
// fleet-wide default dedup window and the flood cap; both are expected to
// already be defaulted and validated (config.Load does this). Per-
// container window overrides come later, via SetWindow, not through New:
// a resolved policy.Policy is a per-container, per-reconcile fact, not
// something available once at construction time.
func New(cfg *config.Config, resolver secret.Resolver, opts ...Option) (*Alerter, error) {
	channels := make([]beacon.ChannelConfig, 0, len(cfg.Notifications.Channels)+1)
	channels = append(channels, beacon.ChannelConfig{Type: "log", MinLevel: beacon.LevelInfo})
	for i, c := range cfg.Notifications.Channels {
		level, err := parseLevel(c.MinLevel)
		if err != nil {
			label := c.Name
			if label == "" {
				label = c.Type
			}
			return nil, fmt.Errorf("alert: notifications.channels[%d] (%s): %w", i, label, err)
		}
		channels = append(channels, beacon.ChannelConfig{
			Type:     c.Type,
			MinLevel: level,
			Settings: c.Settings,
		})
	}

	telemetry := make([]beacon.TelemetryConfig, 0, len(cfg.Telemetry))
	for _, t := range cfg.Telemetry {
		telemetry = append(telemetry, beacon.TelemetryConfig{Type: t.Type, Settings: t.Settings})
	}

	var resolve beacon.SecretResolver
	if resolver != nil {
		resolve = beacon.SecretResolver(resolver)
	}

	b, err := beacon.New(beacon.Config{Channels: channels, Telemetry: telemetry}, resolve)
	if err != nil {
		return nil, fmt.Errorf("alert: building beacon: %w", err)
	}

	window, err := time.ParseDuration(cfg.Defaults.AlertWindow)
	if err != nil {
		return nil, fmt.Errorf("alert: defaults.alert_window %q: %w", cfg.Defaults.AlertWindow, err)
	}
	floodCap := cfg.Defaults.AlertFlood
	if floodCap <= 0 {
		floodCap = 30
	}

	a := &Alerter{
		b:             b,
		defaultWindow: window,
		floodCap:      floodCap,
		now:           time.Now,
		windows:       make(map[string]time.Duration),
		identities:    make(map[engine.Identity]*identityState),
		containers:    make(map[string]*containerFloodState),
		sticky:        make(map[string]*stickyDiag),
		auditTally:    make(map[engine.Identity]int),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// parseLevel maps a config.NotificationChannel.MinLevel string onto a
// beacon.Level. An empty value means "receive everything" (LevelInfo).
// Mirrors ballast's and bilgeline's daemon.parseLevel exactly, the suite's
// established shape for this concern.
func parseLevel(s string) (beacon.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return beacon.LevelInfo, nil
	case "warn", "warning":
		return beacon.LevelWarning, nil
	case "error":
		return beacon.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown notification level %q", s)
	}
}

// SetWindow records service's resolved per-container alert.window
// (resolve.Resolved.Policy.AlertWindow, already defaulted by resolve.
// Resolve). The daemon calls this once per armed container per reconcile
// pass, before feeding that pass' violations, so a label or config change
// to the window takes effect on the very next violation for that service.
// Replicas sharing one service name share one window, matching the frozen
// doc's identity tuple, which keys dedup on service, never on container
// id.
func (a *Alerter) SetWindow(service string, window time.Duration) {
	if window <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.windows[service] = window
}

// windowFor returns service's resolved window, falling back to the
// fleet-wide default when SetWindow was never called for it (e.g. before
// the first reconcile pass, or for a service the daemon does not track
// per-container windows for). Caller must hold a.mu.
func (a *Alerter) windowFor(service string) time.Duration {
	if w, ok := a.windows[service]; ok {
		return w
	}
	return a.defaultWindow
}

// classLevel maps a violation Class to a beacon.Level.
//
// ClassDeny and ClassUnresolvedIP both map to LevelError: a deny is an
// explicit, deliberate policy statement being violated right now, and an
// unresolved-ip connection is the frozen doc's named exfiltration shape
// (a bare IP with no DNS or SNI evidence at all) -- both are sharp,
// actionable signals that warrant attention immediately, not "worth a
// look eventually". ClassNoMatch maps to LevelWarning: it is simply an
// undeclared destination, the natural noise of early onboarding or a
// legitimate destination nobody got around to allowlisting yet -- worth
// surfacing, but it does not carry the same "something is deliberately
// wrong or actively hiding" charge the other two classes do.
func classLevel(c engine.Class) beacon.Level {
	switch c {
	case engine.ClassDeny, engine.ClassUnresolvedIP:
		return beacon.LevelError
	default:
		return beacon.LevelWarning
	}
}

// Violation routes one engine.Violation per the Fork 6 alert-volume
// contract. Called from the daemon's serialized event loop, once per
// evaluated connection.
func (a *Alerter) Violation(ctx context.Context, v engine.Violation) error {
	if v.Mode == policy.Audit {
		// Audit mode routes everything to the digest, per Fork 2: the
		// policy is evaluated identically, but a would-be violation
		// never alerts immediately while the operator is still onboarding
		// this container.
		a.mu.Lock()
		a.auditTally[v.Identity()]++
		a.mu.Unlock()
		return nil
	}

	id := v.Identity()
	now := a.now()

	a.mu.Lock()
	st, exists := a.identities[id]
	if !exists {
		if len(a.identities) >= maxIdentityStates {
			a.evictOldestIdentityLocked()
		}
		st = &identityState{order: a.identitySeq}
		a.identitySeq++
		a.identities[id] = st
	}

	window := a.windowFor(v.Service)

	var sinceLastAlert int
	send := !exists
	if exists {
		if now.Sub(st.windowStart) >= window {
			sinceLastAlert = st.suppressedForAlert
			send = true
		} else {
			st.suppressedForAlert++
			st.suppressedForDigest++
		}
	}
	if send {
		st.windowStart = now
		st.suppressedForAlert = 0
	}
	a.mu.Unlock()

	if !send {
		return nil
	}

	// The flood breaker only gates a BRAND-NEW identity's first-ever
	// alert. A window-rolled re-alert of an identity we already know
	// about is not a new DISTINCT identity, so it never counts toward
	// (or gets gated by) the flood tally -- per-identity dedup already
	// caps how often that specific, finite identity can alert; the flood
	// breaker's whole job is capping an UNBOUNDED stream of never-seen-
	// before identities, which by construction can only ever be a
	// !exists occurrence.
	if !exists {
		flooding, notify := a.countFlood(v.ContainerID, now)
		if flooding {
			a.mu.Lock()
			if fst, ok := a.identities[id]; ok {
				fst.suppressedForDigest++
			}
			a.mu.Unlock()
			if notify {
				return a.sendFlood(ctx, v)
			}
			return nil
		}
	}

	return a.b.Notify(ctx, violationNotification(v, sinceLastAlert))
}

// countFlood updates containerID's tumbling-hour distinct-identity tally
// and reports whether it is currently over the flood cap (flooding), and
// if so whether THIS call is the one that should emit the collapse notice
// (the first crossing this window) as opposed to a later one that should
// be absorbed silently until the window rolls or the tally falls.
func (a *Alerter) countFlood(containerID string, now time.Time) (flooding, notify bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	cs, ok := a.containers[containerID]
	if !ok {
		if len(a.containers) >= maxContainerStates {
			a.evictOldestContainerLocked()
		}
		cs = &containerFloodState{order: a.containerSeq, windowStart: now}
		a.containerSeq++
		a.containers[containerID] = cs
	}
	if now.Sub(cs.windowStart) >= defaultFloodWindow {
		cs.windowStart = now
		cs.distinctCount = 0
		cs.notified = false
	}
	cs.distinctCount++

	if cs.distinctCount <= a.floodCap {
		return false, false
	}
	cs.lastTally = cs.distinctCount
	if !cs.notified {
		cs.notified = true
		return true, true
	}
	return true, false
}

func (a *Alerter) sendFlood(ctx context.Context, v engine.Violation) error {
	label := containerLabel(v)
	return a.b.Notify(ctx, beacon.Notification{
		Title: fmt.Sprintf("airlock: %s flooding", label),
		Body: fmt.Sprintf(
			"%s has exceeded %d distinct violation identities in the last hour and is being collapsed to this single alert; individual violations are absorbed into the next digest until the rate falls.",
			label, a.floodCap,
		),
		Level: beacon.LevelError,
		Tags:  []string{"airlock", "flood"},
		Fields: map[string]string{
			"service":        v.Service,
			"container_id":   v.ContainerID,
			"container_name": v.ContainerName,
		},
	})
}

// Diagnostic routes one discovery.Diagnostic about containerID /
// containerName. Called from the daemon's serialized event loop, once per
// diagnostic produced by a discovery/resolve pass for that container.
//
// An Error-level diagnostic alerts immediately (beacon.LevelError) the
// FIRST time this exact (container, message) pair is seen; a re-feed of
// the identical diagnostic on a later reconcile pass does not re-alert, it
// only refreshes the sticky bookkeeping so the digest keeps listing it. A
// Sticky diagnostic (of either level) is retained in the set the digest
// re-lists every period until a full StartReconcile/EndReconcile bracket
// passes without it being fed again, at which point it ages out (see
// StartReconcile).
//
// A non-Sticky diagnostic is never persisted: it either alerts once (if
// Error) with no memory of having done so, or does nothing at all (if
// Warning). Nothing airlock's discovery package currently produces is
// non-sticky -- see discovery's package doc -- so this path is a defensive
// default, not an exercised one.
func (a *Alerter) Diagnostic(ctx context.Context, containerID, containerName string, d discovery.Diagnostic) error {
	shouldAlert := d.Level == discovery.Error

	if d.Sticky {
		key := stickyKey(containerID, d.Message)

		a.mu.Lock()
		sd, exists := a.sticky[key]
		if !exists {
			if len(a.sticky) >= maxStickyDiagnostics {
				a.evictOldestStickyLocked()
			}
			sd = &stickyDiag{order: a.stickySeq}
			a.stickySeq++
			a.sticky[key] = sd
		}
		sd.level = d.Level
		sd.message = d.Message
		sd.containerID = containerID
		sd.containerName = containerName

		if a.reconcileSeen != nil {
			a.reconcileSeen[key] = true
		}

		if shouldAlert && sd.alerted {
			shouldAlert = false
		} else if shouldAlert {
			sd.alerted = true
		}
		a.mu.Unlock()
	}

	if !shouldAlert {
		return nil
	}
	return a.b.Notify(ctx, diagnosticNotification(containerID, containerName, d))
}

// StartReconcile begins a diagnostic re-feed pass: call it once before
// feeding this reconcile pass' current diagnostics to Diagnostic, then
// call EndReconcile once after the last one. Any sticky diagnostic not
// re-fed between the two calls is treated as resolved and ages out of the
// digest's sticky set, per the frozen doc's "a diagnostic no longer
// present should age out" requirement.
//
// Calling Diagnostic outside a StartReconcile/EndReconcile bracket still
// records and (for a first-seen Error) alerts normally; it just never
// ages anything out on its own, since aging out requires knowing a full
// pass completed without a sticky being mentioned.
func (a *Alerter) StartReconcile() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reconcileSeen = make(map[string]bool)
}

// EndReconcile closes the bracket StartReconcile opened, dropping any
// sticky diagnostic that was not re-fed during it.
func (a *Alerter) EndReconcile() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reconcileSeen == nil {
		return
	}
	for key := range a.sticky {
		if !a.reconcileSeen[key] {
			delete(a.sticky, key)
		}
	}
	a.reconcileSeen = nil
}

// FeedUnpoliciedSummary hands the next Digest a ready-made unpolicied
// first-seen summary (one line per entry) for containers with no declared
// policy at all, gated fleet-wide by AIRLOCK_UNPOLICIED_DIGEST. This
// package only carries the text through to the next Digest call and then
// clears it; building the summary (per-container first-seen destinations
// per day) is the daemon's own bookkeeping, not this package's concern.
// Calling it again before the next Digest replaces, rather than
// accumulates, the pending lines.
func (a *Alerter) FeedUnpoliciedSummary(lines []string) {
	cp := append([]string(nil), lines...)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.unpolicied = cp
}

// Report pushes a health heartbeat through beacon's configured telemetry
// sinks (e.g. a Gatus external endpoint), for the dead-man's-switch leg.
// The daemon calls this periodically; no timer lives in this package. A
// nil telemetry configuration makes this a no-op success (beacon.Report
// fans out to zero sinks and returns nil).
func (a *Alerter) Report(ctx context.Context, healthy bool) error {
	msg := "ok"
	if !healthy {
		msg = "unhealthy"
	}
	return a.b.Report(ctx, beacon.Health{Name: "airlock", OK: healthy, Message: msg})
}

// Digest assembles and sends ONE beacon notification summarizing
// everything accumulated since the last Digest call: suppressed per-
// identity counts, audit-mode tallies, flood episodes, the current sticky
// validation diagnostics, and the unpolicied first-seen summary if fed.
// Every per-period counter is reset after assembly (sticky diagnostics
// that are still active are KEPT -- only their already-reported tallies
// are period-scoped, the sticky entries themselves persist until they age
// out via StartReconcile/EndReconcile, per the frozen doc's "re-fires in
// every digest until fixed").
//
// The daemon owns the cron ticker (AIRLOCK_DIGEST_SCHEDULE) and calls this
// once per period; no timer lives in this package.
func (a *Alerter) Digest(ctx context.Context) error {
	a.mu.Lock()

	suppressed := a.drainSuppressedLocked()
	audit := a.drainAuditLocked()
	floods := a.drainFloodsLocked()
	stickies := a.snapshotStickyLocked()
	unpolicied := a.unpolicied
	a.unpolicied = nil

	a.mu.Unlock()

	n := digestNotification(suppressed, audit, floods, stickies, unpolicied)
	return a.b.Notify(ctx, n)
}

type identityCount struct {
	id    engine.Identity
	count int
}

type floodEpisode struct {
	containerID string
	count       int
}

type stickyRow struct {
	containerID   string
	containerName string
	message       string
	level         discovery.DiagLevel
}

// drainSuppressedLocked collects and resets every identity's
// digest-scoped suppressed count. Caller must hold a.mu.
func (a *Alerter) drainSuppressedLocked() []identityCount {
	var out []identityCount
	for id, st := range a.identities {
		if st.suppressedForDigest > 0 {
			out = append(out, identityCount{id, st.suppressedForDigest})
			st.suppressedForDigest = 0
		}
	}
	sortIdentityCounts(out)
	return out
}

// drainAuditLocked collects and clears the audit-mode tally map. Caller
// must hold a.mu.
func (a *Alerter) drainAuditLocked() []identityCount {
	var out []identityCount
	for id, n := range a.auditTally {
		out = append(out, identityCount{id, n})
	}
	a.auditTally = make(map[engine.Identity]int)
	sortIdentityCounts(out)
	return out
}

// drainFloodsLocked collects every container currently in a notified
// flood episode. Unlike identity/audit tallies, flood state itself is NOT
// reset here: a container mid-flood-episode is still mid-episode after
// this digest, and will keep reporting (a growing) tally in each
// subsequent digest until its tumbling hour rolls over and the rate
// falls, per "resumes normal alerting when the rate drops." Caller must
// hold a.mu.
func (a *Alerter) drainFloodsLocked() []floodEpisode {
	var out []floodEpisode
	for id, cs := range a.containers {
		if cs.notified {
			out = append(out, floodEpisode{id, cs.lastTally})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].containerID < out[j].containerID })
	return out
}

// snapshotStickyLocked copies the current sticky set for the digest. It
// does not modify or clear anything: sticky entries persist across
// digests until StartReconcile/EndReconcile ages them out. Caller must
// hold a.mu.
func (a *Alerter) snapshotStickyLocked() []stickyRow {
	var out []stickyRow
	for _, sd := range a.sticky {
		out = append(out, stickyRow{sd.containerID, sd.containerName, sd.message, sd.level})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].containerName != out[j].containerName {
			return out[i].containerName < out[j].containerName
		}
		return out[i].message < out[j].message
	})
	return out
}

func sortIdentityCounts(rows []identityCount) {
	sort.Slice(rows, func(i, j int) bool { return identityKey(rows[i].id) < identityKey(rows[j].id) })
}

func identityKey(id engine.Identity) string {
	return fmt.Sprintf("%s|%s|%05d|%d", id.Service, id.Destination, id.Port, id.Class)
}

func stickyKey(containerID, message string) string {
	return containerID + "\x00" + message
}

// evictOldestIdentityLocked drops the identity state with the smallest
// insertion order. Caller must hold a.mu and know len(a.identities) is at
// capacity.
func (a *Alerter) evictOldestIdentityLocked() {
	var oldestKey engine.Identity
	oldest := -1
	for k, st := range a.identities {
		if oldest == -1 || st.order < oldest {
			oldest = st.order
			oldestKey = k
		}
	}
	if oldest != -1 {
		delete(a.identities, oldestKey)
	}
}

func (a *Alerter) evictOldestContainerLocked() {
	var oldestKey string
	oldest := -1
	for k, cs := range a.containers {
		if oldest == -1 || cs.order < oldest {
			oldest = cs.order
			oldestKey = k
		}
	}
	if oldest != -1 {
		delete(a.containers, oldestKey)
	}
}

func (a *Alerter) evictOldestStickyLocked() {
	var oldestKey string
	oldest := -1
	for k, sd := range a.sticky {
		if oldest == -1 || sd.order < oldest {
			oldest = sd.order
			oldestKey = k
		}
	}
	if oldest != -1 {
		delete(a.sticky, oldestKey)
	}
}

// containerLabel renders a human-readable container identifier: "name
// (short-id)" when both are known, whichever one is known alone otherwise.
func containerLabel(v engine.Violation) string {
	name := v.ContainerName
	id := shortID(v.ContainerID)
	switch {
	case name != "" && id != "":
		return fmt.Sprintf("%s (%s)", name, id)
	case name != "":
		return name
	default:
		return id
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// destinationLabel renders the best available identity for where a
// connection went, per Fork 6: the winning name evidence, else the raw
// destination IP.
func destinationLabel(v engine.Violation) string {
	if v.Destination != "" {
		return v.Destination
	}
	return v.DstIP.String()
}

// violationNotification builds the beacon.Notification for one immediate
// alert, per the frozen doc's "a clear human-readable message: service,
// destination ... port, class, container name/id, and both DNS and SNI
// evidence when present" requirement. sinceLastAlert is 0 for a first-hit
// alert, and the suppressed-repeat count for a window-rolled re-alert.
func violationNotification(v engine.Violation, sinceLastAlert int) beacon.Notification {
	dest := destinationLabel(v)

	var body strings.Builder
	fmt.Fprintf(&body, "%s reached %s", v.Service, dest)
	if v.Port != 0 {
		fmt.Fprintf(&body, ":%d", v.Port)
	}
	fmt.Fprintf(&body, " (%s) via %s.", v.Class, containerLabel(v))

	if v.Class == engine.ClassUnresolvedIP {
		body.WriteString(" Connected to a bare IP with no DNS or SNI evidence at all.")
	}

	if v.DNSName != "" || v.SNIName != "" {
		body.WriteString(" Evidence:")
		if v.DNSName != "" {
			fmt.Fprintf(&body, " dns=%s", v.DNSName)
		}
		if v.SNIName != "" {
			fmt.Fprintf(&body, " sni=%s", v.SNIName)
		}
		if v.DNSName != "" && v.SNIName != "" && !strings.EqualFold(v.DNSName, v.SNIName) {
			body.WriteString(" (disagree: SNI wins for matching)")
		}
	}

	if sinceLastAlert > 0 {
		fmt.Fprintf(&body, " %d suppressed since the last alert for this identity.", sinceLastAlert)
	}

	fields := map[string]string{
		"service":        v.Service,
		"destination":    v.Destination,
		"port":           strconv.Itoa(int(v.Port)),
		"class":          v.Class.String(),
		"container_id":   v.ContainerID,
		"container_name": v.ContainerName,
	}
	if v.DNSName != "" {
		fields["dns"] = v.DNSName
	}
	if v.SNIName != "" {
		fields["sni"] = v.SNIName
	}
	if sinceLastAlert > 0 {
		fields["since_last_alert"] = strconv.Itoa(sinceLastAlert)
	}

	return beacon.Notification{
		Title:  fmt.Sprintf("airlock: %s violation (%s)", v.Class, v.Service),
		Body:   body.String(),
		Level:  classLevel(v.Class),
		Tags:   []string{"airlock", v.Class.String()},
		Fields: fields,
	}
}

func diagnosticNotification(containerID, containerName string, d discovery.Diagnostic) beacon.Notification {
	label := containerName
	if label == "" {
		label = shortID(containerID)
	}
	return beacon.Notification{
		Title: fmt.Sprintf("airlock: validation error (%s)", label),
		Body:  d.Message,
		Level: beacon.LevelError,
		Tags:  []string{"airlock", "validation"},
		Fields: map[string]string{
			"container_id":   containerID,
			"container_name": containerName,
		},
	}
}

// digestNotification assembles the single periodic digest notification.
func digestNotification(suppressed, audit []identityCount, floods []floodEpisode, stickies []stickyRow, unpolicied []string) beacon.Notification {
	if len(suppressed) == 0 && len(audit) == 0 && len(floods) == 0 && len(stickies) == 0 && len(unpolicied) == 0 {
		return beacon.Notification{
			Title: "airlock: digest",
			Body:  "Nothing to report this period.",
			Level: beacon.LevelInfo,
			Tags:  []string{"airlock", "digest"},
		}
	}

	var b strings.Builder
	if len(suppressed) > 0 {
		fmt.Fprintf(&b, "Suppressed repeats (%d identities):\n", len(suppressed))
		for _, r := range suppressed {
			fmt.Fprintf(&b, "  - %s -> %s:%d (%s): %d suppressed\n", r.id.Service, r.id.Destination, r.id.Port, r.id.Class, r.count)
		}
	}
	if len(audit) > 0 {
		fmt.Fprintf(&b, "Audit-mode tallies (%d identities):\n", len(audit))
		for _, r := range audit {
			fmt.Fprintf(&b, "  - %s -> %s:%d (%s): %d\n", r.id.Service, r.id.Destination, r.id.Port, r.id.Class, r.count)
		}
	}
	if len(floods) > 0 {
		fmt.Fprintf(&b, "Flood episodes (%d containers):\n", len(floods))
		for _, r := range floods {
			fmt.Fprintf(&b, "  - %s: %d distinct violations this hour\n", r.containerID, r.count)
		}
	}
	if len(stickies) > 0 {
		fmt.Fprintf(&b, "Sticky validation diagnostics (%d):\n", len(stickies))
		for _, s := range stickies {
			label := s.containerName
			if label == "" {
				label = shortID(s.containerID)
			}
			fmt.Fprintf(&b, "  - [%s] %s: %s\n", s.level, label, s.message)
		}
	}
	if len(unpolicied) > 0 {
		b.WriteString("Unpolicied first-seen summary:\n")
		for _, line := range unpolicied {
			fmt.Fprintf(&b, "  - %s\n", line)
		}
	}

	return beacon.Notification{
		Title: "airlock: digest",
		Body:  b.String(),
		Level: beacon.LevelInfo,
		Tags:  []string{"airlock", "digest"},
		Fields: map[string]string{
			"suppressed_identities": strconv.Itoa(len(suppressed)),
			"audit_identities":      strconv.Itoa(len(audit)),
			"flood_episodes":        strconv.Itoa(len(floods)),
			"sticky_diagnostics":    strconv.Itoa(len(stickies)),
		},
	}
}
