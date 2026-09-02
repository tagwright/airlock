// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"errors"
	"io"

	"github.com/tagwright/core/runtime"
)

// fakeRuntime is an in-memory runtime.Runtime + runtime.NetworkInspector
// for tests: no socket, canned List/Inspect/ListNetworks/Watch. Only the
// methods this chunk's tests exercise do anything interesting; the rest
// return ErrNotImplemented or a zero value, which is fine since nothing
// here calls them.
type fakeRuntime struct {
	containers []runtime.Container
	networks   []runtime.Network

	listErr         error
	listNetworksErr error
}

func (f *fakeRuntime) List(ctx context.Context) ([]runtime.Container, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.containers, nil
}

func (f *fakeRuntime) Inspect(ctx context.Context, id string) (runtime.Container, error) {
	for _, c := range f.containers {
		if c.ID == id || c.Name == id {
			return c, nil
		}
	}
	return runtime.Container{}, errors.New("fakeRuntime: not found")
}

func (f *fakeRuntime) Watch(ctx context.Context) (<-chan runtime.Event, <-chan error) {
	events := make(chan runtime.Event)
	errs := make(chan error)
	close(events)
	close(errs)
	return events, errs
}

func (f *fakeRuntime) Exec(ctx context.Context, id string, spec runtime.ExecSpec) (*runtime.ExecHandle, error) {
	return nil, runtime.ErrNotImplemented
}

func (f *fakeRuntime) Stop(ctx context.Context, id string, timeoutSeconds int) error {
	return runtime.ErrNotImplemented
}

func (f *fakeRuntime) Start(ctx context.Context, id string) error { return runtime.ErrNotImplemented }

func (f *fakeRuntime) Kill(ctx context.Context, id string, signal string) error {
	return runtime.ErrNotImplemented
}

func (f *fakeRuntime) Restart(ctx context.Context, id string) error {
	return runtime.ErrNotImplemented
}

func (f *fakeRuntime) Close() error { return nil }

func (f *fakeRuntime) ListNetworks(ctx context.Context) ([]runtime.Network, error) {
	if f.listNetworksErr != nil {
		return nil, f.listNetworksErr
	}
	return f.networks, nil
}

var _ runtime.Runtime = (*fakeRuntime)(nil)
var _ runtime.NetworkInspector = (*fakeRuntime)(nil)
var _ io.Closer = (*fakeRuntime)(nil)
