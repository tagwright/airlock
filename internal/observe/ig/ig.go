// SPDX-License-Identifier: GPL-3.0-or-later

// Package ig implements observe.Backend on top of Inspektor Gadget (IG),
// airlock's first observation backend.
//
// Per the operational research this adapter was built against, IG's
// image-based gadgets are consumed by spawning "ig run <image> -o json" as
// a subprocess per gadget and reading newline-delimited JSON off its
// stdout -- not the ig gRPC daemon, and not IG's Go packages embedded
// in-process. That choice buys a real OS process boundary (a crashed or
// wedged gadget is just a child process this package restarts, never a
// fault in airlock's own process) and keeps this package's dependency
// surface to the ig CLI's flags and each gadget's documented JSON schema,
// both far more stable contracts than IG's pre-1.0 Go API or its
// currently-plaintext-by-default gRPC transport.
//
// Every IG-specific type, JSON shape, and CLI flag is unexported and
// confined to this package; IGBackend is the only exported symbol, and it
// speaks observe.Event/observe.Stat like any other observe.Backend.
//
// TODO(digest pinning): Options.Images defaults to ":latest" tags for
// development convenience. Because each gadget's JSON schema can change
// independently of the ig binary's own version, production deployments
// should pin every image by digest
// (ghcr.io/inspektor-gadget/gadget/trace_tcp@sha256:...) resolved at
// packaging time, and pass that pinned map in via Options.Images. This
// package deliberately does not fabricate or hardcode a digest here.
//
// TODO(dropped events): IG's documented per-gadget JSON schemas (as of
// v0.55.1) do not expose a field for the gadget's own ring-buffer
// drop/loss counter, so this adapter cannot currently surface true
// mid-stream event loss into observe.Stat.DroppedEvents. Until such a
// field is confirmed and wired up, this adapter's only loss/health signal
// is a Stat emitted on every subprocess restart (see superviseSource
// below), which airlock should still treat as a visibility-gap signal:
// sustained restarts under load are exactly the ring-buffer-flooding
// scenario this TODO is tracking.
package ig

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/tagwright/airlock/internal/observe"
)

// Default image references for the three gadgets this backend drives.
// These are ":latest" tags, not pinned digests -- see the package-level
// digest-pinning TODO above.
const (
	DefaultTraceTCPImage = "ghcr.io/inspektor-gadget/gadget/trace_tcp:latest"
	DefaultTraceDNSImage = "ghcr.io/inspektor-gadget/gadget/trace_dns:latest"
	DefaultTraceSNIImage = "ghcr.io/inspektor-gadget/gadget/trace_sni:latest"

	// DefaultRuntimes is the -r/--runtimes value used when neither
	// Options.Runtimes nor a caller-supplied override names one.
	//
	// This is deliberately just "docker", NOT the ig CLI's own
	// documented multi-runtime default ("docker,containerd,cri-o,podman")
	// this constant originally mirrored. Confirmed against a real
	// v0.55.1 `ig run` on a plain-Docker-only host (no containerd/cri-o/
	// podman API socket present -- the exact target deployment this
	// project is built for): ig does not skip a listed runtime whose
	// socket is missing, it fails the ENTIRE invocation at startup
	// ("pre-starting operator \"LocalManager\": container-collection
	// isn't available") the moment any one of them, other than docker,
	// has no live socket. Passing the old multi-runtime default meant
	// every gadget subprocess this backend supervises would crash-loop
	// forever, at construction time, before ever emitting a single
	// event, on the documented turnkey single-runtime deployment --
	// silent total observation loss, not a degraded mode. Callers
	// running against Podman instead of Docker must pass "podman"
	// explicitly via Options.Runtimes (see internal/daemon's
	// buildObserveBackend, which does this from AIRLOCK_RUNTIME); ig
	// has no default that is safe across an unknown mix of runtimes.
	DefaultRuntimes = "docker"

	defaultBackoffMin = 500 * time.Millisecond
	defaultBackoffMax = 30 * time.Second
)

// gadget names, used as map keys in Options.Images and as Stat.Source
// values.
const (
	gadgetTraceTCP = "trace_tcp"
	gadgetTraceDNS = "trace_dns"
	gadgetTraceSNI = "trace_sni"
)

func defaultImages() map[string]string {
	return map[string]string{
		gadgetTraceTCP: DefaultTraceTCPImage,
		gadgetTraceDNS: DefaultTraceDNSImage,
		gadgetTraceSNI: DefaultTraceSNIImage,
	}
}

// Options configures an IGBackend.
type Options struct {
	// IGPath is the path to (or name of) the ig binary. Defaults to "ig"
	// (resolved via PATH).
	IGPath string

	// Images maps gadget name ("trace_tcp", "trace_dns", "trace_sni") to
	// the OCI image reference to run for it. Any gadget missing from this
	// map falls back to its Default*Image constant. Production
	// deployments should populate this with digest-pinned references --
	// see the package-level TODO.
	Images map[string]string

	// Runtimes is passed as ig run's -r/--runtimes flag. Defaults to
	// DefaultRuntimes.
	Runtimes string

	// DockerSocketPath is passed as ig run's --docker-socketpath flag
	// when non-empty. Left empty, ig's own default applies.
	DockerSocketPath string

	// BackoffMin and BackoffMax bound the exponential backoff applied
	// between restarts of a crashed gadget subprocess. Default to 500ms
	// and 30s respectively.
	BackoffMin time.Duration
	BackoffMax time.Duration

	// newCommand builds the *exec.Cmd used to run one gadget source. It
	// exists so tests can substitute a fake command in place of the real
	// ig binary; production callers should leave it nil to get
	// defaultCommandBuilder.
	newCommand func(ctx context.Context, s source, opts Options) *exec.Cmd
}

// withDefaults returns a copy of o with every unset field filled in.
func (o Options) withDefaults() Options {
	if o.IGPath == "" {
		o.IGPath = "ig"
	}
	images := defaultImages()
	for k, v := range o.Images {
		images[k] = v
	}
	o.Images = images
	if o.Runtimes == "" {
		o.Runtimes = DefaultRuntimes
	}
	if o.BackoffMin <= 0 {
		o.BackoffMin = defaultBackoffMin
	}
	if o.BackoffMax <= 0 {
		o.BackoffMax = defaultBackoffMax
	}
	if o.BackoffMax < o.BackoffMin {
		o.BackoffMax = o.BackoffMin
	}
	if o.newCommand == nil {
		o.newCommand = defaultCommandBuilder
	}
	return o
}

// DefaultOptions returns the Options an IGBackend uses when constructed
// with a zero Options value; it is exposed so callers can start from the
// defaults and override individual fields (most commonly Images, to pin
// digests).
func DefaultOptions() Options {
	return Options{}.withDefaults()
}

// source is one gadget this backend supervises: a name (used for logging
// and Stat.Source), the image to run, and the function that turns one
// NDJSON line from it into a normalized observe.Event.
type source struct {
	name  string
	image string
	parse func(line []byte) (observe.Event, bool)
}

// defaultCommandBuilder builds the real "ig run <image> -o json ..."
// subprocess command for a source.
//
// --auto-mount-filesystems is always passed. BUG FIX (this integration
// pass): confirmed against a real v0.55.1 `ig run` inside airlock's own
// packaged image (Dockerfile's debian:stable-slim final stage, the raw
// release binary with no wrapper around it, run --privileged/--pid=host/
// with the docker-compose.yml-documented mounts): without this flag, ig
// fails its entire startup with "filesystems debugfs, tracefs not
// mounted" every time, because nothing in that image's own startup
// mounts them (unlike, apparently, upstream's own ghcr.io/inspektor-
// gadget/ig container image, which this adapter was validated against
// directly and does not hit this -- its own entrypoint evidently handles
// this already). Airlock always runs ig as a dedicated, already-
// privileged subprocess whose only job is loading eBPF, so there is no
// deployment shape where letting ig mount its own bpffs/debugfs/tracefs
// is undesirable; this is not made an Options field because no caller
// has a reason to turn it off.
func defaultCommandBuilder(ctx context.Context, s source, opts Options) *exec.Cmd {
	args := []string{"run", s.image, "-o", "json", "--auto-mount-filesystems"}
	if opts.Runtimes != "" {
		args = append(args, "-r", opts.Runtimes)
	}
	if opts.DockerSocketPath != "" {
		args = append(args, "--docker-socketpath", opts.DockerSocketPath)
	}
	return exec.CommandContext(ctx, opts.IGPath, args...)
}

// IGBackend implements observe.Backend on top of Inspektor Gadget. See the
// package doc for the overall design.
type IGBackend struct {
	opts Options
}

// NewIGBackend constructs an IGBackend. A zero Options value is valid and
// yields the defaults described on each Options field.
func NewIGBackend(opts Options) *IGBackend {
	return &IGBackend{opts: opts.withDefaults()}
}

// Name implements observe.Backend.
func (b *IGBackend) Name() string { return "inspektor-gadget" }

// sources returns the fixed set of gadget sources this backend supervises.
func (b *IGBackend) sources() []source {
	return []source{
		{name: gadgetTraceTCP, image: b.opts.Images[gadgetTraceTCP], parse: parseTCPLine},
		{name: gadgetTraceDNS, image: b.opts.Images[gadgetTraceDNS], parse: parseDNSLine},
		{name: gadgetTraceSNI, image: b.opts.Images[gadgetTraceSNI], parse: parseSNILine},
	}
}

// Run implements observe.Backend. It starts one supervised subprocess per
// gadget and returns immediately; the returned channels are closed once
// every source's supervision loop has exited following ctx cancellation.
func (b *IGBackend) Run(ctx context.Context) (<-chan observe.Event, <-chan observe.Stat, <-chan error) {
	events := make(chan observe.Event)
	stats := make(chan observe.Stat)
	errs := make(chan error, 1)

	var wg sync.WaitGroup
	for _, s := range b.sources() {
		wg.Add(1)
		go func(s source) {
			defer wg.Done()
			b.superviseSource(ctx, s, events, stats)
		}(s)
	}

	go func() {
		wg.Wait()
		close(events)
		close(stats)
		close(errs)
	}()

	return events, stats, errs
}

// superviseSource runs one source's subprocess repeatedly, applying capped
// exponential backoff between restarts, until ctx is cancelled. Every
// restart (including the first failure that triggers one) emits a Stat so
// consumers can see source churn as it happens.
func (b *IGBackend) superviseSource(ctx context.Context, s source, events chan<- observe.Event, stats chan<- observe.Stat) {
	backoff := b.opts.BackoffMin
	var restarts uint64

	for {
		if ctx.Err() != nil {
			return
		}

		runErr := b.runSource(ctx, s, events, stats)

		if ctx.Err() != nil {
			return
		}

		restarts++
		msg := fmt.Sprintf("source %s exited (%v), restarting (attempt %d) in %s", s.name, runErr, restarts, backoff)
		log.Printf("airlock/observe/ig: %s", msg)

		select {
		case stats <- observe.Stat{Source: s.name, Time: time.Now(), Restarts: restarts, Message: msg}:
		case <-ctx.Done():
			return
		}

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}

		backoff *= 2
		if backoff > b.opts.BackoffMax {
			backoff = b.opts.BackoffMax
		}
	}
}

// runSource runs one instance of the source's subprocess to completion (or
// until ctx is cancelled), streaming parsed events as it goes. It returns
// the reason the subprocess stopped so the caller can log it; a nil return
// paired with ctx.Err() != nil means the caller asked us to stop, not that
// anything went wrong.
func (b *IGBackend) runSource(ctx context.Context, s source, events chan<- observe.Event, _ chan<- observe.Stat) error {
	// The stats parameter is reserved for a per-line loss/health signal
	// once IG exposes one (see the package-level dropped-events TODO);
	// today the only Stat this backend emits comes from
	// superviseSource on restart.

	cmdCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := b.opts.newCommand(cmdCtx, s, b.opts)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	scanDone := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			ev, ok := s.parse(line)
			if !ok {
				continue
			}
			select {
			case events <- ev:
			case <-cmdCtx.Done():
				scanDone <- cmdCtx.Err()
				return
			}
		}
		scanDone <- scanner.Err()
	}()

	select {
	case <-ctx.Done():
		cancel()
		<-scanDone
		_ = cmd.Wait()
		return ctx.Err()
	case scanErr := <-scanDone:
		waitErr := cmd.Wait()
		if scanErr != nil {
			return scanErr
		}
		return waitErr
	}
}
