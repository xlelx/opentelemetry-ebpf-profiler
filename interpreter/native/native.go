// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package native implements opt-in on-host symbolization of native frames
// using ELF symbol tables (.symtab/.dynsym). It is intentionally disabled by
// default because retaining symbol table metadata can add significant per-ELF
// memory overhead.
//
// Symbol names are resolved lazily: only the address range and string table
// offset are kept per symbol. The actual name is read from the mmap-backed
// string table on first lookup and cached in an LRU to amortize demangling.
package native // import "go.opentelemetry.io/ebpf-profiler/interpreter/native"

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync/atomic"
	"unsafe"

	lru "github.com/elastic/go-freelru"
	"github.com/ianlancetaylor/demangle"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfbufio"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/successfailurecounter"
)

var (
	_ interpreter.Data     = &nativeData{}
	_ interpreter.Instance = &nativeInstance{}
)

const nameCacheSize = 1024

// symbolEntry represents a single function symbol with its address range.
type symbolEntry struct {
	address uint32
	size    uint32
	nameOff uint32 // offset into string table
}

// nativeData holds the parsed symbol table for a single ELF.
type nativeData struct {
	fileID host.FileID
	// symbols is indexed by the upper 32 bits of the symbol address. Each
	// bucket is sorted by the lower 32 bits for binary search.
	symbols map[uint32][]symbolEntry
	numSyms int
	// strtab is the raw string table bytes (mmap-backed).
	strtab []byte
	// nameCache caches demangled symbol names by strtab offset.
	nameCache *lru.SyncedLRU[uint32, string]
	// elfFile owns the mmap backing strtab; closed on Unload to munmap.
	elfFile *pfelf.File
}

type nativeInstance struct {
	interpreter.InstanceStubs

	successCount atomic.Uint64
	failCount    atomic.Uint64

	d *nativeData
}

// Loader is the interpreter.Loader for native symbol resolution.
// It loads function symbols from .symtab, falling back to .dynsym, and
// finally trying a .gnu_debuglink-referenced ELF if neither is present.
// Go binaries are skipped since they are handled by the Go-specific symbolizer.
func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Skip Go binaries because the Go symbolizer handles their Go frames. CGO
	// symbols would be useful here, but separating them from Go runtime symbols
	// needs a more precise filter than plain ELF symbol table scanning.
	if ef.IsGolang() {
		return nil, nil
	}

	symbols, strtab, elfFile := loadSymbols(ef, info.FileName())
	if len(symbols) == 0 {
		return nil, nil
	}

	nameCache, err := lru.NewSynced[uint32, string](nameCacheSize, hash.Uint32)
	if err != nil {
		if elfFile != nil {
			elfFile.Close()
		}
		return nil, fmt.Errorf("failed to create name cache: %w", err)
	}

	d := &nativeData{
		fileID:    info.FileID(),
		symbols:   symbols,
		numSyms:   countSymbols(symbols),
		strtab:    strtab,
		nameCache: nameCache,
		elfFile:   elfFile,
	}
	return d, nil
}

// loadSymbols extracts FUNC symbols from the ELF's .symtab, falling back to
// .dynsym, and if neither is present, trying the debug-linked ELF's .symtab.
// It returns the symbol entries, the raw string table, and the ELF file that
// must be kept open to back the strtab mmap.
//
// The returned *pfelf.File owns the mmap that backs strtab. The caller must
// keep it open for the lifetime of the strtab slice and close it on Unload.
func loadSymbols(ef *pfelf.File, elfPath string) (map[uint32][]symbolEntry, []byte, *pfelf.File) {
	// Check if the primary ELF has symbols (using the Reference's cached file
	// just for the check). If it does, open our own copy so we own the mmap.
	if syms, _ := collectSymbolOffsets(ef, ".symtab"); len(syms) > 0 {
		return openOwnedELF(elfPath, ".symtab")
	}
	if syms, _ := collectSymbolOffsets(ef, ".dynsym"); len(syms) > 0 {
		return openOwnedELF(elfPath, ".dynsym")
	}

	// Try debug-linked ELF.
	debugELF, _ := ef.OpenDebugLink(elfPath, pfelf.SystemOpener)
	if debugELF == nil {
		return nil, nil, nil
	}

	if syms, strtab := collectSymbolOffsets(debugELF, ".symtab"); len(syms) > 0 {
		return syms, strtab, debugELF
	}
	debugELF.Close()
	return nil, nil, nil
}

// openOwnedELF opens an independent copy of the ELF file and extracts symbols
// from the given section. The returned *pfelf.File owns the mmap backing strtab.
func openOwnedELF(elfPath, section string) (map[uint32][]symbolEntry, []byte, *pfelf.File) {
	owned, err := pfelf.Open(elfPath)
	if err != nil {
		return nil, nil, nil
	}
	syms, strtab := collectSymbolOffsets(owned, section)
	if len(syms) == 0 {
		owned.Close()
		return nil, nil, nil
	}
	return syms, strtab, owned
}

// collectSymbolOffsets reads a symbol table section and returns entries with
// raw string table offsets (no name resolution or demangling at this stage).
func collectSymbolOffsets(ef *pfelf.File, sectionName string) (map[uint32][]symbolEntry, []byte) {
	symTab := ef.Section(sectionName)
	if symTab == nil {
		return nil, nil
	}

	if symTab.Link == 0 || symTab.Link >= uint32(len(ef.Sections)) {
		return nil, nil
	}

	strTab := ef.Sections[symTab.Link]
	// Returns a sub-slice of the mmap when available (zero-copy); maxSize
	// only caps the fallback heap allocation for non-mmap readers.
	strtab, err := strTab.Data(16 * 1024 * 1024)
	if err != nil {
		return nil, nil
	}

	rdr := pfbufio.NewReader(symTab, 0, int64(symTab.FileSize))
	defer pfbufio.PutReader(rdr)

	symSz := int(unsafe.Sizeof(elf.Sym64{}))
	symBytes := make([]byte, symSz)
	symbols := make(map[uint32][]symbolEntry)

	for {
		if _, err := io.ReadFull(rdr, symBytes); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, nil
		}
		sym := (*elf.Sym64)(unsafe.Pointer(&symBytes[0]))
		if sym.Value == 0 || sym.Size == 0 {
			continue
		}
		if !libpf.SymbolType(elf.ST_TYPE(sym.Info)).IsFunction() {
			continue
		}
		if sym.Size > uint64(^uint32(0)) {
			continue
		}
		// Verify the name offset is valid and non-empty.
		nameOff := sym.Name
		if int(nameOff) >= len(strtab) || strtab[nameOff] == 0 {
			continue
		}
		high := uint32(sym.Value >> 32)
		symbols[high] = append(symbols[high], symbolEntry{
			address: uint32(sym.Value),
			size:    uint32(sym.Size),
			nameOff: nameOff,
		})
	}
	if len(symbols) == 0 {
		return nil, nil
	}
	for high := range symbols {
		sort.Slice(symbols[high], func(i, j int) bool {
			return symbols[high][i].address < symbols[high][j].address
		})
	}
	return symbols, strtab
}

// demangleSymbol attempts to demangle C++ and Rust mangled symbol names.
func demangleSymbol(name string) string {
	if strings.HasPrefix(name, "_Z") || strings.HasPrefix(name, "_R") {
		if demangled, err := demangle.ToString(name); err == nil {
			return demangled
		}
	}
	return name
}

// resolveSymbolName reads a symbol name from the string table and demangles it.
func (d *nativeData) resolveSymbolName(nameOff uint32) string {
	if name, ok := d.nameCache.Get(nameOff); ok {
		return name
	}

	start := int(nameOff)
	if start >= len(d.strtab) {
		return ""
	}

	end := bytes.IndexByte(d.strtab[start:], 0)
	if end < 0 {
		return ""
	}
	raw := string(d.strtab[start : start+end])
	name := demangleSymbol(raw)

	d.nameCache.Add(nameOff, name)
	return name
}

// lookupSymbol performs a binary search to find the function containing addr.
func (d *nativeData) lookupSymbol(addr uint64) (string, bool) {
	symbols := d.symbols[uint32(addr>>32)]
	lowAddr := uint32(addr)
	i := sort.Search(len(symbols), func(i int) bool {
		return symbols[i].address > lowAddr
	}) - 1

	if i < 0 {
		return "", false
	}
	sym := &symbols[i]
	offset := lowAddr - sym.address
	if offset < sym.size {
		return d.resolveSymbolName(sym.nameOff), true
	}
	return "", false
}

func (d *nativeData) String() string {
	return fmt.Sprintf("Native symbolizer (%d symbols)", d.numSyms)
}

func countSymbols(symbols map[uint32][]symbolEntry) int {
	count := 0
	for _, bucket := range symbols {
		count += len(bucket)
	}
	return count
}

func (d *nativeData) Attach(_ interpreter.EbpfHandler, _ libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	return &nativeInstance{d: d}, nil
}

func (d *nativeData) Unload(_ interpreter.EbpfHandler) {
	if d.elfFile != nil {
		d.elfFile.Close()
		d.elfFile = nil
	}
}

func (inst *nativeInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	return []metrics.Metric{
		{
			ID:    metrics.IDNativeSymbolizationSuccess,
			Value: metrics.MetricValue(inst.successCount.Swap(0)),
		},
		{
			ID:    metrics.IDNativeSymbolizationFailure,
			Value: metrics.MetricValue(inst.failCount.Swap(0)),
		},
	}, nil
}

func (inst *nativeInstance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	return nil
}

func (inst *nativeInstance) Symbolize(ef libpf.EbpfFrame, frames *libpf.Frames,
	mapping libpf.FrameMapping) error {
	if !ef.Type().IsInterpType(libpf.Native) {
		return interpreter.ErrMismatchInterpreterType
	}
	if host.FileID(ef.Variable(0)) != inst.d.fileID {
		return interpreter.ErrMismatchInterpreterType
	}

	sfCounter := successfailurecounter.New(&inst.successCount, &inst.failCount)
	defer sfCounter.DefaultToFailure()

	address := ef.Data()
	name, ok := inst.d.lookupSymbol(address)
	if !ok {
		return fmt.Errorf("no symbol for 0x%x", address)
	}

	if ef.Flags().ReturnAddress() {
		address--
	}
	frames.Append(&libpf.Frame{
		Type:            ef.Type(),
		AddressOrLineno: libpf.AddressOrLineno(address),
		Mapping:         mapping,
		FunctionName:    libpf.Intern(name),
	})
	sfCounter.ReportSuccess()
	return nil
}

func (inst *nativeInstance) ReleaseResources() error {
	return nil
}
