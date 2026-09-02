// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package ig

import (
	"context"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/observe"
)

// TestDefaultCommandBuilder_AlwaysAutoMountsFilesystems pins the exact
// argument list defaultCommandBuilder produces, most importantly that
// --auto-mount-filesystems is always present. This is a regression test
// for a real bug this integration pass found: confirmed against a live
// v0.55.1 `ig run` inside airlock's own packaged image, without this flag
// ig fails its ENTIRE startup ("filesystems debugfs, tracefs not
// mounted") on every gadget, every time, because nothing else in that
// image's startup mounts them. See defaultCommandBuilder's doc comment.
func TestDefaultCommandBuilder_AlwaysAutoMountsFilesystems(t *testing.T) {
	opts := Options{IGPath: "ig", Runtimes: "docker", DockerSocketPath: "/run/docker.sock"}.withDefaults()
	s := source{name: gadgetTraceTCP, image: DefaultTraceTCPImage, parse: parseTCPLine}

	cmd := defaultCommandBuilder(context.Background(), s, opts)

	want := []string{
		"ig", "run", DefaultTraceTCPImage, "-o", "json", "--auto-mount-filesystems",
		"-r", "docker", "--docker-socketpath", "/run/docker.sock",
	}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("defaultCommandBuilder args = %v, want %v", cmd.Args, want)
	}
}

// TestDefaultCommandBuilder_MinimalOptions confirms the bare-minimum
// invocation (no Runtimes, no DockerSocketPath set) still always carries
// -o json and --auto-mount-filesystems, and omits the two optional flags
// entirely rather than passing them empty.
func TestDefaultCommandBuilder_MinimalOptions(t *testing.T) {
	s := source{name: gadgetTraceDNS, image: DefaultTraceDNSImage, parse: parseDNSLine}
	cmd := defaultCommandBuilder(context.Background(), s, Options{IGPath: "ig"})

	want := []string{"ig", "run", DefaultTraceDNSImage, "-o", "json", "--auto-mount-filesystems"}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("defaultCommandBuilder args = %v, want %v", cmd.Args, want)
	}
}

// fakeIGScript is a stand-in for the real ig binary. Each invocation
// increments a counter file (so successive restarts are distinguishable)
// and prints two trace_tcp-shaped NDJSON lines before exiting cleanly,
// simulating a gadget subprocess that runs for a while and then just
// stops -- the case superviseSource must recover from by restarting it.
const fakeIGScript = `
count=0
if [ -f "$COUNTER_FILE" ]; then
  count=$(cat "$COUNTER_FILE")
fi
count=$((count+1))
echo "$count" > "$COUNTER_FILE"
echo "{\"type\":\"connect\",\"dst\":{\"addr\":\"10.0.0.1\",\"port\":$count},\"runtime\":{\"containerId\":\"c1\",\"containerName\":\"web\"}}"
echo "{\"type\":\"connect\",\"dst\":{\"addr\":\"10.0.0.2\",\"port\":$count},\"runtime\":{\"containerId\":\"c1\",\"containerName\":\"web\"}}"
exit 0
`

func fakeCommandBuilder(counterFile string) func(ctx context.Context, s source, opts Options) *exec.Cmd {
	return func(ctx context.Context, s source, opts Options) *exec.Cmd {
		cmd := exec.CommandContext(ctx, "sh", "-c", fakeIGScript)
		cmd.Env = append(cmd.Env, "COUNTER_FILE="+counterFile)
		return cmd
	}
}

// TestSuperviseSourceRestartsAndStops drives IGBackend.superviseSource
// directly against a fake "ig" command (no real Inspektor Gadget or
// Docker socket involved): the fake process prints a couple of JSON lines
// and exits every time it's run. This asserts the supervisor (a) keeps
// streaming normalized events across restarts, (b) reports each restart
// as a Stat, and (c) stops cleanly and promptly once its context is
// cancelled.
func TestSuperviseSourceRestartsAndStops(t *testing.T) {
	counterFile := filepath.Join(t.TempDir(), "count")

	opts := Options{
		BackoffMin: 5 * time.Millisecond,
		BackoffMax: 20 * time.Millisecond,
		newCommand: fakeCommandBuilder(counterFile),
	}.withDefaults()

	b := NewIGBackend(opts)

	src := source{name: "fake", image: "n/a", parse: parseTCPLine}

	events := make(chan observe.Event)
	stats := make(chan observe.Stat, 64)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		b.superviseSource(ctx, src, events, stats)
		close(done)
	}()

	// Each subprocess run emits exactly two events. Collect events across
	// at least two runs (i.e. at least one restart) to prove the
	// supervisor keeps going after the first process exits.
	const wantEvents = 5
	seen := 0
	for seen < wantEvents {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatalf("events channel closed early after %d events", seen)
			}
			seen++
			if ev.Kind != observe.Connection {
				t.Fatalf("event %d: Kind = %v, want Connection", seen, ev.Kind)
			}
			if ev.ContainerID != "c1" || ev.ContainerName != "web" {
				t.Fatalf("event %d: container attribution = %q/%q, want c1/web", seen, ev.ContainerID, ev.ContainerName)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for events, saw %d of %d", seen, wantEvents)
		}
	}

	// At least one restart must have been reported by now.
	select {
	case st := <-stats:
		if st.Source != "fake" {
			t.Errorf("Stat.Source = %q, want fake", st.Source)
		}
		if st.Restarts == 0 {
			t.Errorf("Stat.Restarts = 0, want > 0")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a restart Stat")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("superviseSource did not stop promptly after ctx cancellation")
	}
}

// TestIGBackendRunStopsOnCancel exercises the full Backend.Run wiring
// (all three sources, real channel lifecycle) against the same fake
// command, and asserts every channel closes after ctx cancellation, as
// the observe.Backend contract requires.
func TestIGBackendRunStopsOnCancel(t *testing.T) {
	counterFile := filepath.Join(t.TempDir(), "count")

	opts := Options{
		BackoffMin: 5 * time.Millisecond,
		BackoffMax: 20 * time.Millisecond,
		newCommand: fakeCommandBuilder(counterFile),
	}

	b := NewIGBackend(opts)
	if b.Name() != "inspektor-gadget" {
		t.Fatalf("Name() = %q, want inspektor-gadget", b.Name())
	}

	ctx, cancel := context.WithCancel(context.Background())
	events, stats, errs := b.Run(ctx)

	// Drain until we've seen at least one event, then cancel.
	select {
	case <-events:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the first event")
	}

	cancel()

	drainUntilClosed := func(name string, done <-chan struct{}) {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s did not close within timeout", name)
		}
	}

	// Keep draining events/stats (other goroutines may still be mid-send)
	// while waiting for all three channels to close.
	eventsClosed := make(chan struct{})
	go func() {
		for range events {
		}
		close(eventsClosed)
	}()
	statsClosed := make(chan struct{})
	go func() {
		for range stats {
		}
		close(statsClosed)
	}()
	errsClosed := make(chan struct{})
	go func() {
		for range errs {
		}
		close(errsClosed)
	}()

	drainUntilClosed("events", eventsClosed)
	drainUntilClosed("stats", statsClosed)
	drainUntilClosed("errs", errsClosed)
}
