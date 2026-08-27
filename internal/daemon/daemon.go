// SPDX-License-Identifier: GPL-3.0-or-later

// Package daemon is airlock's wiring hub: the long-running process that
// turns every other package (internal/observe, internal/engine,
// internal/resolve, internal/discovery, internal/alert, and
// github.com/tagwright/core's runtime abstraction) into one running
// program. It builds the container runtime and the observation backend,
// keeps a live World snapshot (world.go) the policy engine reads, runs the
// event loop that turns observed egress into alerts, and periodically
// writes the JSON state snapshot (state.go) that is the file-based
// CLI<->daemon contract behind `airlock status` and `airlock suggest` --
// see state.go's package-level DESIGN comment for why a file rather than
// an IPC server.
//
// # Concurrency
//
// Exactly one goroutine -- the one running Daemon.Run's select loop --
// ever calls engine.Process, engine.Flush, or reconcile (which mutates
// the World snapshot those two read). This is the architecture's
// documented "simplest correct design": no snapshot lock is needed
// because there is never a second goroutine touching it. Every
// timer/source that runs on its own goroutine is explicitly documented,
// everywhere it appears, to touch ONLY thread-safe read/write-sides: the
// digest cron (github.com/robfig/cron/v3, its own internal goroutine)
// touches d.alerter and d.unpolicied (fed from d.engine.ObservedSnapshot,
// itself thread-safe -- see observed.go's own concurrency doc comment);
// the state-snapshot writer (state.go's runStateWriter, this package's own
// goroutine) touches d.engine.ObservedSnapshot, d.alerter.SuppressedByService,
// d.health, d.violations, and d.armedMeta (an atomic.Pointer written once
// per reconcile by the main goroutine). Nothing on either of those
// goroutines ever touches d.world directly. The observe backend's own
// channels and the runtime's own Watch channel are both consumed
// synchronously inside Run's select loop, never fanned out to a second
// goroutine of this package's own making.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/tagwright/airlock/internal/alert"
	"github.com/tagwright/airlock/internal/config"
	"github.com/tagwright/airlock/internal/engine"
	"github.com/tagwright/airlock/internal/observe"
	"github.com/tagwright/airlock/internal/observe/ig"
	"github.com/tagwright/airlock/internal/secret"
	"github.com/tagwright/core/runtime"
)

// Tunables with no config.Config field of their own. AIRLOCK_* env
// overrides exist for every one that plausibly needs adjusting in the
// field; none of them are policy-shaped, which is why they live here as
// daemon-owned operational knobs rather than in airlock.yml (mirrors
// bilgeline's BILGELINE_RUNTIME/BILGELINE_SOCKET/BILGELINE_SELF_ID split:
// runtime selection and self-identification are deployment concerns, not
// fleet policy).
const (
	// defaultDockerSocket is used when the selected runtime is Docker
	// and neither AIRLOCK_SOCKET nor DOCKER_HOST names a socket path.
	defaultDockerSocket = "/var/run/docker.sock"

	// reconcileDebounce is the quiet window applied to runtime lifecycle
	// churn before a reconcile runs, coalescing a burst of start/stop
	// events (a compose up, a crash loop) into one pass. JUDGMENT CALL:
	// airlock's config carries no debounce field (unlike bilgeline's
	// BILGELINE_DEBOUNCE), so this mirrors bilgeline's own default
	// value (2s) as a package constant rather than exposing new config
	// surface for a single fixed value nothing else in this chunk's
	// brief asked to make tunable.
	reconcileDebounce = 2 * time.Second

	// flushInterval is how often Daemon.Run calls engine.Flush to
	// surface deferred verdicts. The engine's own doc comment
	// recommends "a few hundred milliseconds ... comfortably finer than
	// sniWindow"; this picks the middle of that range.
	flushInterval = 300 * time.Millisecond

	// defaultHeartbeatInterval is how often Daemon.Run pushes a healthy
	// alert.Report for the Gatus dead-man's-switch leg, absent
	// AIRLOCK_HEARTBEAT_INTERVAL. JUDGMENT CALL: not specified by the
	// frozen doc or this chunk's brief; five minutes is a conventional
	// heartbeat cadence for this suite's telemetry push pattern
	// (frequent enough that a missed window is noticed promptly, rare
	// enough to cost nothing).
	defaultHeartbeatInterval = 5 * time.Minute

	// backendRestartMax bounds how many times Run will restart a
	// terminally-failed observe.Backend before giving up and returning
	// an error (a clean-shutdown signal to the caller). In practice
	// IGBackend supervises its own gadget subprocesses internally and
	// only closes its errs channel (without ever sending on it) when
	// ctx is cancelled, so this path is defensive: it exists for a
	// future backend (or a future IGBackend change) that CAN report a
	// real terminal error, per observe.Backend's documented contract
	// ("errs carries at most one terminal error").
	backendRestartMax = 5

	backendRestartBackoffMin = 1 * time.Second
	backendRestartBackoffMax = 30 * time.Second
)

// Daemon wires every airlock package together. Build one with New and
// drive it with Run.
type Daemon struct {
	cfg    *config.Config
	logger *slog.Logger

	rt      runtime.Runtime
	netInsp runtime.NetworkInspector
	backend observe.Backend
	alerter *alert.Alerter
	engine  *engine.Engine
	world   *world

	// health, violations, and unpolicied are this package's own small
	// thread-safe read/write-sides for the state-snapshot writer and the
	// digest cron, both of which run on their own goroutines -- see the
	// package doc comment's concurrency section. armedMeta is written
	// once per reconcile (the main goroutine) and read with no lock at
	// all by the state-snapshot writer, via atomic.Pointer.
	health     *backendHealthTracker
	violations *violationTally
	unpolicied *unpoliciedTracker
	armedMeta  atomic.Pointer[[]armedContainerMeta]

	selfID string

	heartbeatInterval time.Duration
	flushInterval     time.Duration
	debounce          time.Duration
	resolvConfPath    string
	statePath         string
	stateInterval     time.Duration
}

// New constructs a Daemon from cfg: it selects and constructs the
// container runtime, builds the IG observation backend, and builds the
// beacon-backed alerter. It does not touch the runtime's socket or start
// observing; that is Run's job. ctx is used only to resolve airlock's own
// self-id (an Inspect call against the runtime), never retained.
func New(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Daemon, error) {
	if logger == nil {
		logger = slog.Default()
	}

	rt, err := buildRuntime(cfg)
	if err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}

	netInsp, ok := rt.(runtime.NetworkInspector)
	if !ok {
		_ = rt.Close()
		return nil, fmt.Errorf("daemon: runtime %T does not implement runtime.NetworkInspector (ListNetworks), which airlock's scope classification and net:<name> resolution both require", rt)
	}

	backend := buildObserveBackend(cfg)

	resolver := secret.FileEnvResolver(cfg.SecretsDir)
	alerter, err := alert.New(cfg, resolver)
	if err != nil {
		_ = rt.Close()
		return nil, fmt.Errorf("daemon: build alerter: %w", err)
	}

	w := newWorld()

	d := &Daemon{
		cfg:               cfg,
		logger:            logger,
		rt:                rt,
		netInsp:           netInsp,
		backend:           backend,
		alerter:           alerter,
		engine:            engine.New(w),
		world:             w,
		health:            newBackendHealthTracker(backend.Name()),
		violations:        newViolationTally(),
		unpolicied:        newUnpoliciedTracker(),
		heartbeatInterval: heartbeatInterval(),
		flushInterval:     flushInterval,
		debounce:          reconcileDebounce,
		resolvConfPath:    resolvConfPath(),
		statePath:         StatePath(),
		stateInterval:     resolveStateInterval(),
	}
	d.selfID = resolveSelfID(ctx, rt, logger)

	return d, nil
}

// buildRuntime selects and constructs the container runtime.
// AIRLOCK_RUNTIME picks docker (the default) or podman; AIRLOCK_SOCKET
// overrides the socket path for either. JUDGMENT CALL: unlike ballast,
// airlock's config.Config carries no Runtime/Socket field of its own
// (config.go's schema is otherwise frozen by the config chunk), so this
// mirrors bilgeline's env-only selection exactly rather than adding new
// config surface this chunk does not own.
func buildRuntime(cfg *config.Config) (runtime.Runtime, error) {
	_ = cfg // reserved: no config-file runtime selector exists (see doc comment above)
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AIRLOCK_RUNTIME"))) {
	case "", "docker":
		return runtime.NewDocker(dockerSocket()), nil
	case "podman":
		return runtime.NewPodman(podmanSocket()), nil
	default:
		return nil, fmt.Errorf("unknown runtime %q, want \"docker\" or \"podman\" (set via AIRLOCK_RUNTIME)", os.Getenv("AIRLOCK_RUNTIME"))
	}
}

// resolvedRuntimeName mirrors buildRuntime's own AIRLOCK_RUNTIME switch,
// normalized to exactly the name ig's -r/--runtimes flag wants for that
// same runtime ("docker" or "podman"), for buildObserveBackend to use.
// It deliberately does not error on an unrecognized value the way
// buildRuntime does -- buildRuntime is always called first and already
// fails startup on that same input, so by the time this runs the value
// (or its "" default) is known good.
func resolvedRuntimeName() string {
	if strings.ToLower(strings.TrimSpace(os.Getenv("AIRLOCK_RUNTIME"))) == "podman" {
		return "podman"
	}
	return "docker"
}

// dockerSocket resolves the Docker API socket path: AIRLOCK_SOCKET if
// set, otherwise DOCKER_HOST (with a "unix://" scheme prefix stripped,
// since NewDocker wants a bare path), otherwise the conventional default.
func dockerSocket() string {
	if v := os.Getenv("AIRLOCK_SOCKET"); v != "" {
		return v
	}
	if v := os.Getenv("DOCKER_HOST"); v != "" {
		return strings.TrimPrefix(v, "unix://")
	}
	return defaultDockerSocket
}

// podmanSocket resolves the Podman API socket path: AIRLOCK_SOCKET if
// set, otherwise CONTAINER_HOST (with a "unix://" scheme prefix
// stripped), otherwise empty, which tells runtime.NewPodman to fall back
// to its own rootless/rootful default-socket resolution.
func podmanSocket() string {
	if v := os.Getenv("AIRLOCK_SOCKET"); v != "" {
		return v
	}
	if v := os.Getenv("CONTAINER_HOST"); v != "" {
		return strings.TrimPrefix(v, "unix://")
	}
	return ""
}

// buildObserveBackend constructs the IG observation backend from cfg's
// (currently lightly-validated, see config.ObserveConfig's own doc
// comment) Observe section. v1 has exactly one backend; a future
// bathyscaphe adapter selects here on its own config knob without
// changing anything downstream of the observe.Backend interface.
func buildObserveBackend(cfg *config.Config) observe.Backend {
	return ig.NewIGBackend(ig.Options{
		IGPath:           cfg.Observe.IGPath,
		Images:           cfg.Observe.Images,
		Runtimes:         observeRuntimes(cfg),
		DockerSocketPath: cfg.Observe.DockerSocketPath,
	})
}

// observeRuntimes resolves ig run's -r/--runtimes value: cfg.Observe.Runtimes
// verbatim when the operator set one explicitly in airlock.yml, otherwise
// the single runtime name resolvedRuntimeName derives from AIRLOCK_RUNTIME
// -- the same env var buildRuntime reads to pick airlock's own container
// runtime.
//
// BUG FIX (this integration pass): this used to leave Runtimes empty
// whenever airlock.yml left observe.runtimes unset, deferring entirely to
// ig.Options' own DefaultRuntimes. That constant used to be ig's own
// documented multi-runtime default (docker,containerd,cri-o,podman) --
// see ig.DefaultRuntimes' doc comment for the real, confirmed-against-a-
// live-ig-run failure mode that made that fatal on a plain-Docker-only
// host. Even with that constant now fixed to a safe single "docker", this
// function additionally makes the ig runtime scope track AIRLOCK_RUNTIME:
// a fleet actually running Podman (AIRLOCK_RUNTIME=podman) needs ig scoped
// to "podman", not the package default's "docker", or every gadget would
// run against a runtime with no live containers to attribute anything to.
func observeRuntimes(cfg *config.Config) string {
	if cfg.Observe.Runtimes != "" {
		return cfg.Observe.Runtimes
	}
	return resolvedRuntimeName()
}

// heartbeatInterval resolves the Gatus dead-man's-switch push cadence:
// AIRLOCK_HEARTBEAT_INTERVAL (a Go duration string) if set and valid,
// otherwise defaultHeartbeatInterval.
func heartbeatInterval() time.Duration {
	if v := strings.TrimSpace(os.Getenv("AIRLOCK_HEARTBEAT_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultHeartbeatInterval
}

// resolvConfPath resolves where ResolverIPs' best-effort host-resolver
// scan reads from: AIRLOCK_RESOLV_CONF if set, otherwise
// defaultResolvConfPath.
func resolvConfPath() string {
	if v := strings.TrimSpace(os.Getenv("AIRLOCK_RESOLV_CONF")); v != "" {
		return v
	}
	return defaultResolvConfPath
}

// containerIDPattern matches a full 64-hex container id anywhere in a
// line, the shape Docker and Podman both write into /proc/self/cgroup and
// mountinfo. Mirrors bilgeline's identical pattern and reasoning.
var containerIDPattern = regexp.MustCompile(`[0-9a-f]{64}`)

// resolveSelfID determines airlock's OWN container id, purely for status
// and logging: per the frozen architecture, airlock holds NO
// self-exclusion exemption (it is observed and policy-judged like any
// other container), so unlike bilgeline's identically-shaped
// ResolveSelfID this value never gates anything downstream of it. A
// best-effort resolution failure is logged, not fatal, and Run continues
// with an empty self-id.
func resolveSelfID(ctx context.Context, rt runtime.Runtime, logger *slog.Logger) string {
	hint := selfIDHint()
	if hint == "" {
		logger.Warn("daemon: could not determine airlock's own container id (status/logging only, no self-exclusion exists in this architecture)")
		return ""
	}

	if c, err := rt.Inspect(ctx, hint); err == nil && c.ID != "" {
		return c.ID
	}
	if len(hint) == 64 && containerIDPattern.MatchString(hint) {
		return hint
	}
	logger.Warn("daemon: could not normalize self id to a full container id", "hint", hint)
	return hint
}

// selfIDHint gathers the best available hint for airlock's own container
// id without touching the socket: the env override, else a 64-hex id from
// the process's cgroup or mountinfo, else the hostname.
func selfIDHint() string {
	if v := strings.TrimSpace(os.Getenv("AIRLOCK_SELF_ID")); v != "" {
		return v
	}
	for _, path := range []string{"/proc/self/cgroup", "/proc/self/mountinfo"} {
		if id := containerIDFromFile(path); id != "" {
			return id
		}
	}
	if h, err := os.Hostname(); err == nil {
		return strings.TrimSpace(h)
	}
	return ""
}

func containerIDFromFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return containerIDPattern.FindString(string(data))
}

// Run drives the daemon until ctx is cancelled: an initial full reconcile,
// then the event loop described in the package doc comment. It always
// closes the runtime and stops every timer before returning, including on
// error.
func (d *Daemon) Run(ctx context.Context) error {
	defer func() {
		if err := d.rt.Close(); err != nil {
			d.logger.Warn("daemon: close runtime", "error", err)
		}
	}()

	d.logger.Info("daemon: starting",
		"backend", d.backend.Name(),
		"self_id", d.selfID,
		"digest_schedule", d.cfg.Defaults.DigestSchedule,
		"heartbeat_interval", d.heartbeatInterval.String())

	if err := d.reconcile(ctx); err != nil {
		return fmt.Errorf("daemon: initial reconcile: %w", err)
	}

	events, stats, errs := d.backend.Run(ctx)
	rtEvents, rtErrs := d.rt.Watch(ctx)

	cronRunner := cron.New()
	if _, err := cronRunner.AddFunc(d.cfg.Defaults.DigestSchedule, func() { d.runDigest(ctx) }); err != nil {
		return fmt.Errorf("daemon: digest schedule %q: %w", d.cfg.Defaults.DigestSchedule, err)
	}
	cronRunner.Start()
	defer func() { <-cronRunner.Stop().Done() }()

	stateDone := make(chan struct{})
	go func() {
		defer close(stateDone)
		d.runStateWriter(ctx)
	}()
	defer func() { <-stateDone }()

	heartbeat := time.NewTicker(d.heartbeatInterval)
	defer heartbeat.Stop()

	flush := time.NewTicker(d.flushInterval)
	defer flush.Stop()

	debounceTimer := time.NewTimer(d.debounce)
	if !debounceTimer.Stop() {
		<-debounceTimer.C
	}
	debounceArmed := false
	defer debounceTimer.Stop()

	backendRestarts := 0

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			d.handleObserveEvent(ctx, ev)

		case st, ok := <-stats:
			if !ok {
				stats = nil
				continue
			}
			d.handleStat(st)

		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			if err == nil {
				continue
			}
			d.logger.Error("daemon: observe backend terminal error", "backend", d.backend.Name(), "error", err)
			if ctx.Err() != nil {
				continue
			}
			backendRestarts++
			if backendRestarts > backendRestartMax {
				return fmt.Errorf("daemon: observe backend %s failed %d times, giving up: %w", d.backend.Name(), backendRestarts, err)
			}
			backoff := backendRestartBackoffMin * time.Duration(1<<uint(backendRestarts-1))
			if backoff > backendRestartBackoffMax || backoff <= 0 {
				backoff = backendRestartBackoffMax
			}
			d.logger.Warn("daemon: restarting observe backend", "attempt", backendRestarts, "backoff", backoff.String())
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			events, stats, errs = d.backend.Run(ctx)

		case rev, ok := <-rtEvents:
			if !ok {
				rtEvents = nil
				continue
			}
			if d.handleRuntimeEvent(rev) {
				if debounceArmed && !debounceTimer.Stop() {
					select {
					case <-debounceTimer.C:
					default:
					}
				}
				debounceTimer.Reset(d.debounce)
				debounceArmed = true
			}

		case err, ok := <-rtErrs:
			if !ok {
				rtErrs = nil
				continue
			}
			if err != nil {
				d.logger.Error("daemon: runtime watch error", "error", err)
			}

		case <-debounceTimer.C:
			debounceArmed = false
			if err := d.reconcile(ctx); err != nil {
				d.logger.Error("daemon: reconcile failed", "error", err)
			}

		case now := <-flush.C:
			for _, v := range d.engine.Flush(now) {
				d.recordAndAlertViolation(ctx, v, "flush")
			}

		case <-heartbeat.C:
			if err := d.alerter.Report(ctx, true); err != nil {
				d.logger.Error("daemon: heartbeat report", "error", err)
			}
		}
	}
}

// handleObserveEvent feeds one observe.Event through the engine and routes
// any resulting Violations to the alerter, tallying each by container and
// class along the way (violationTally, see tally.go) for `airlock
// status`'s per-container violation counts. It also stamps the backend
// health tracker's last-event time, since an event actually reaching this
// method is the liveness signal `airlock status`'s "events flowing" reads.
// The engine's own observed-egress recorder (internal/engine/observed.go)
// records unpolicied and suggest data directly inside Process/
// evaluateConnection, so there is nothing left for this method to do for
// an unarmed container's connection beyond what Process already did.
// Called only from Run's own goroutine.
func (d *Daemon) handleObserveEvent(ctx context.Context, ev observe.Event) {
	d.health.RecordEvent(time.Now())

	for _, v := range d.engine.Process(ev) {
		d.recordAndAlertViolation(ctx, v, "process")
	}
}

// recordAndAlertViolation tallies v by container and class
// (violationTally, see tally.go -- the source for `airlock status`'s
// per-container violation counts) and routes it through the alerter. It
// is the single choke point both of Run's two Violation sources funnel
// through: handleObserveEvent, for engine.Process's immediate verdicts,
// and Run's flush case, for engine.Flush's deferred ones.
//
// BUG FIX (this integration pass): before this helper existed, Run's
// flush case alerted a deferred Violation without ever tallying it, so
// `airlock status`'s per-container violation counts silently
// undercounted -- often all the way to zero -- every violation that went
// through the deferred/SNI-window path. That path is not a rare corner:
// deferral is gated only on the policy having ANY domain-based allow
// entry (hasNameBasedAllow), so it is the common case for a realistic
// policy, not an edge case. Confirmed live against a real daemon: a
// connection with no name evidence at all (always deferred, since any
// name-based allow entry qualifies for deferral) alerted correctly but
// never appeared in state.json's violations_by_class until this fix.
// sourceLabel distinguishes the two call sites in the error log only; it
// has no bearing on tallying or alerting.
func (d *Daemon) recordAndAlertViolation(ctx context.Context, v engine.Violation, sourceLabel string) {
	d.violations.Record(v.ContainerID, v.Class.String())
	if err := d.alerter.Violation(ctx, v); err != nil {
		d.logger.Error("daemon: alert violation", "source", sourceLabel, "error", err)
	}
}

// handleStat logs an observe.Stat as the operational signal it is, and
// folds it into the backend health tracker (health.go) for `airlock
// status`. A nonzero DroppedEvents is treated as the tamper/loss signal the
// frozen architecture calls out (logged at Error, since it means airlock
// may have missed connections without anyone otherwise knowing); a bare
// restart with no reported loss is logged at Warn, since sustained
// restarts under load are the same ring-buffer-flooding shape even when a
// specific backend cannot yet count the drops itself (see
// internal/observe/ig's package-level TODO on this exact gap).
func (d *Daemon) handleStat(st observe.Stat) {
	d.health.RecordStat(st)

	if st.DroppedEvents > 0 {
		d.logger.Error("daemon: observe backend reported dropped events (possible tamper or ring-buffer overflow)",
			"source", st.Source, "dropped_events", st.DroppedEvents, "restarts", st.Restarts, "message", st.Message)
		return
	}
	if st.Restarts > 0 {
		d.logger.Warn("daemon: observe backend source restarted",
			"source", st.Source, "restarts", st.Restarts, "message", st.Message)
	}
}

// handleRuntimeEvent applies one runtime.Event: a die or destroy
// immediately releases the container's engine correlation state
// (engine.Forget), independent of and ahead of the next debounced
// reconcile, since there is no reason to hold DNS/SNI cache state for a
// container already gone. It returns whether ev should (re)arm the
// reconcile debounce timer.
func (d *Daemon) handleRuntimeEvent(ev runtime.Event) (armDebounce bool) {
	switch ev.Type {
	case runtime.EventDie, runtime.EventDestroy:
		d.engine.Forget(ev.ID)
	}
	return relevantRuntimeEvent(ev.Type)
}

// relevantRuntimeEvent reports whether a lifecycle event should trigger a
// reconcile: every documented transition can change what the fleet's
// armed policies or network inventory look like, so all of them arm the
// debounce. Reconcile itself is cheap relative to a real gadget restart,
// so no hash-diffing (unlike bilgeline's reconciler) guards the rebuild
// here.
func relevantRuntimeEvent(t runtime.EventType) bool {
	switch t {
	case runtime.EventStart, runtime.EventStop, runtime.EventDie, runtime.EventDestroy:
		return true
	default:
		return false
	}
}

// runDigest feeds the pending unpolicied-first-seen summary (gated by
// cfg.Defaults.UnpoliciedDigest) and fires the periodic digest. Called from
// the cron library's own goroutine -- see the package doc comment's
// concurrency section -- it touches only d.alerter, d.unpolicied, and
// d.engine.ObservedSnapshot, all independently thread-safe, never d.world.
func (d *Daemon) runDigest(ctx context.Context) {
	if d.cfg.Defaults.UnpoliciedDigest {
		d.alerter.FeedUnpoliciedSummary(d.unpolicied.NewSince(d.engine.ObservedSnapshot()))
	}
	if err := d.alerter.Digest(ctx); err != nil {
		d.logger.Error("daemon: digest failed", "error", err)
	}
}

// reconcile runs one full pass: list the fleet and the network inventory,
// resolve every container's policy, rebuild the World snapshot in place
// (world.replace, preserving the engine's reference to it -- see
// world.go's type doc comment), and route every diagnostic and per-service
// alert window produced along the way through the alerter. Called from
// Run's own goroutine only, both at startup and on every debounced
// runtime event.
func (d *Daemon) reconcile(ctx context.Context) error {
	containers, err := d.rt.List(ctx)
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	networks, err := d.netInsp.ListNetworks(ctx)
	if err != nil {
		return fmt.Errorf("list networks: %w", err)
	}
	resolverBase := parseResolvConf(d.resolvConfPath)

	result := buildWorld(containers, networks, d.cfg, resolverBase)

	d.alerter.StartReconcile()
	for _, cd := range result.diagnostics {
		if err := d.alerter.Diagnostic(ctx, cd.containerID, cd.containerName, cd.diag); err != nil {
			d.logger.Error("daemon: alert diagnostic", "container", cd.containerName, "error", err)
		}
	}
	d.alerter.EndReconcile()

	for service, window := range result.windows {
		d.alerter.SetWindow(service, window)
	}

	d.world.replace(result.world)
	d.armedMeta.Store(&result.armed)

	d.logger.Debug("daemon: reconcile complete",
		"containers", len(containers),
		"armed", len(result.world.policies),
		"networks", len(networks),
		"diagnostics", len(result.diagnostics),
		"resolver_ips", len(result.world.resolverIPs))

	return nil
}
