// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package native // import "go.opentelemetry.io/ebpf-profiler/interpreter/native"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

// Config controls opt-in native symbolization via ELF symbol tables.
type Config struct {
	Enabled bool `mapstructure:"enabled" json:"enabled,omitempty"`
}

var _ interpreter.Config = Config{}

func (c Config) IsDisabled() bool { return !c.Enabled }
