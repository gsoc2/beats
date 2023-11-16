// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"sync"

	"github.com/elastic/ebpfevents"
)

type EventMask uint64

type Client struct {
	name   string
	mask   EventMask
	events chan ebpfevents.Event
	errors chan error
}

type Watcher interface {
	Subscribe(string, EventMask) (<-chan ebpfevents.Event, <-chan error)
	Unsubscribe(string)
	Close() error
}

type watcher struct {
	sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	loader  *ebpfevents.Loader
	clients map[string]Client
}

var watcherOnce struct {
	sync.Once
	w   *watcher
	err error
}

func GetWatcher() (Watcher, error) {
	watcherOnce.Do(func() {
		loader, err := ebpfevents.NewLoader()
		if err != nil {
			watcherOnce.err = fmt.Errorf("new ebpf loader: %w", err)
			return
		}

		watcherOnce.w = &watcher{
			loader:  loader,
			clients: make(map[string]Client),
		}

		events := make(chan ebpfevents.Event)
		errors := make(chan error)
		watcherOnce.w.ctx, watcherOnce.w.cancel = context.WithCancel(context.Background())

		go watcherOnce.w.loader.EventLoop(watcherOnce.w.ctx, events, errors)
		go func() {
			for {
				select {
				case err := <-errors:
					for _, client := range watcherOnce.w.clients {
						client.errors <- err
					}
					continue
				case ev := <-events:
					for _, client := range watcherOnce.w.clients {
						if client.mask&EventMask(ev.Type) != 0 {
							client.events <- ev
						}
					}
					continue
				case <-watcherOnce.w.ctx.Done():
					return
				}
			}
		}()
	})

	return watcherOnce.w, watcherOnce.err
}

func (w *watcher) Subscribe(name string, events EventMask) (<-chan ebpfevents.Event, <-chan error) {
	w.Lock()
	defer w.Unlock()

	w.clients[name] = Client{
		name:   name,
		mask:   events,
		events: make(chan ebpfevents.Event),
		errors: make(chan error),
	}

	return w.clients[name].events, w.clients[name].errors
}

func (w *watcher) Unsubscribe(name string) {
	w.Lock()
	defer w.Unlock()
	delete(w.clients, name)
}

func (w *watcher) Close() error {
	w.Lock()
	defer w.Unlock()

	if w.cancel != nil {
		w.cancel()
	}

	if w.loader != nil {
		_ = w.loader.Close()
	}

	for _, cl := range w.clients {
		close(cl.events)
		close(cl.errors)
	}

	return nil
}
