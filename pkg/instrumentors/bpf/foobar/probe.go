// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package foobar

import (
	"go.opentelemetry.io/auto/pkg/instrumentors/bpffs"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/auto/pkg/inject"
	"go.opentelemetry.io/auto/pkg/instrumentors/context"
	"go.opentelemetry.io/auto/pkg/instrumentors/events"
	"go.opentelemetry.io/auto/pkg/log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags $CFLAGS bpf ./bpf/probe.bpf.c

type Instrumentor struct {
	bpfObjects *bpfObjects
	uprobes    []link.Link
}

func New() *Instrumentor {
	return &Instrumentor{}
}

func (f *Instrumentor) LibraryName() string {
	return "foobar"
}

func (f *Instrumentor) FuncNames() []string {
	return []string{"main.foobar"}
}

func (f *Instrumentor) Load(ctx *context.InstrumentorContext) error {
	spec, err := ctx.Injector.Inject(loadBpf, f.LibraryName(), ctx.TargetDetails.GoVersion.Original(), []*inject.StructField{}, false)

	if err != nil {
		return err
	}

	f.bpfObjects = &bpfObjects{}
	err = spec.LoadAndAssign(f.bpfObjects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpffs.BPFFsPath,
		},
	})
	if err != nil {
		return err
	}

	for _, funcName := range f.FuncNames() {
		f.registerProbes(ctx, funcName)
	}

	return nil
}

func (f *Instrumentor) registerProbes(ctx *context.InstrumentorContext, funcName string) {
	logger := log.Logger.WithName("foobar-instrumentor").WithValues("function", funcName)
	offset, err := ctx.TargetDetails.GetFunctionOffset(funcName)
	if err != nil {
		logger.Error(err, "could not find function start offset. Skipping")
		return
	}

	up, err := ctx.Executable.Uprobe("", f.bpfObjects.UprobeFoobar, &link.UprobeOptions{
		Address: offset,
	})
	if err != nil {
		logger.V(1).Info("could not insert start uprobe. Skipping",
			"error", err.Error())
		return
	}

	f.uprobes = append(f.uprobes, up)
}

func (f *Instrumentor) Run(eventsChan chan<- *events.Event) {
	// noop
}

func (f *Instrumentor) Close() {
	log.Logger.V(0).Info("closing foobar instrumentor")

	for _, r := range f.uprobes {
		r.Close()
	}

	if f.bpfObjects != nil {
		f.bpfObjects.Close()
	}
}
