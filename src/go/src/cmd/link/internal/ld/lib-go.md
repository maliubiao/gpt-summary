Response:
The user has provided a snippet of Go code from `go/src/cmd/link/internal/ld/lib.go` and is asking for a breakdown of its functionality.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Purpose:**  The file `lib.go` within the `cmd/link/internal/ld` package strongly suggests it deals with library loading and linking functionalities within the Go linker. The comments at the beginning mentioning `asm.c` and `l.h` from Inferno hint at the historical roots of some concepts.

2. **Analyze Imports:** The import statements provide a good overview of the areas the code interacts with. Key imports include:
    * Standard library packages (`bytes`, `debug/elf`, `debug/macho`, `encoding/...`, `fmt`, `io`, `log`, `os`, `os/exec`, `path/filepath`, `runtime`, `slices`, `sort`, `strings`, `sync`, `time`). This indicates general utility functions, interaction with the operating system, and handling of file formats like ELF and Mach-O.
    * Internal Go packages (`internal/buildcfg`, `cmd/internal/bio`, `cmd/internal/goobj`, `cmd/internal/hash`, `cmd/internal/objabi`, `cmd/internal/sys`). These point to Go-specific build configurations, buffered I/O, Go object file handling, hashing, object ABI definitions, and system architecture information.
    * Internal linker packages (`cmd/link/internal/loadelf`, `cmd/link/internal/loader`, `cmd/link/internal/loadmacho`, `cmd/link/internal/loadpe`, `cmd/link/internal/loadxcoff`, `cmd/link/internal/sym`). These are the core linker components for loading different executable formats (ELF, Mach-O, PE, XCOFF), managing symbols, and other linker-specific tasks.

3. **Examine Key Data Structures:**
    * `ArchSyms`:  Clearly holds architecture-specific symbols required during the linking process. The names like `.got`, `.plt`, `.dynamic` are standard linker terms, especially for ELF. The functions `mkArchSym` and `setArchSyms` are responsible for populating this structure.
    * `Arch`: This struct encapsulates architecture-specific details and functions that the linker needs to operate correctly for different targets. Fields like `Funcalign`, `Maxalign`, `TrampLimit`, and function pointers like `Adddynrel`, `Archreloc`, `Trampoline`, `Asmb`, `Asmb2`, `Extreloc` are crucial for the linking process.
    * Global variables like `thearch`, segment definitions (`Segtext`, `Segrodata`, etc.), and `ctxt *Link` all point to global linker state and settings.

4. **Identify Key Functions and their Roles:**
    * `libinit`: Initializes library loading, sets up output file, and determines the entry point symbol.
    * `loadinternal`: Loads internal Go packages (like `runtime`).
    * `loadlib`: The main function for loading object files (both Go and potentially host objects). It manages the `ctxt.Library` list.
    * `loadobjfile`:  Handles loading a single object file (or archive of object files). It distinguishes between regular files and archive files.
    * `ldhostobj`: Registers a host object file for later processing.
    * `hostobjs`: Processes the registered host object files.
    * `hostlinksetup`:  Prepares for external linking by setting up a temporary directory.
    * `hostlink`:  Orchestrates the external linking process by invoking the external linker (like `gcc` or `clang`).
    * `archive`:  Creates a static library archive.
    * `linksetup`:  Sets up various flags and special symbols based on the build mode.
    * `mangleTypeSym`, `typeSymbolMangle`:  Shorten the names of Go type symbols, especially relevant for shared libraries or plugins.
    * Functions related to archive processing (`nextar`).

5. **Infer Functionality from Code Snippets:**
    * The `setArchSyms` function initializes `ArchSyms` with specific symbol names. This indicates that the linker needs these symbols for relocation and dynamic linking purposes. The conditional logic for PPC64 and ELF/Darwin suggests architecture-specific handling.
    * The `Arch` struct's fields and function pointers reveal the linker's architecture-aware nature. It needs to handle function alignment, relocation, trampoline generation, assembly, and external relocation formats.
    * The functions within `loadlib` show the process of loading both internal Go packages and potentially external (host) objects. The distinction between `LinkInternal` and `LinkExternal` modes is apparent.
    * The `hostlink` function clearly demonstrates how the Go linker invokes an external linker to perform the final linking step when `-linkmode=external` is used or when host objects are involved that necessitate external linking.

6. **Relate to Go Features:**  The code clearly relates to the compilation and linking process of Go programs. It handles:
    * **Static and Dynamic Linking:** The code distinguishes between internal and external linking, and supports building shared libraries and plugins.
    * **Cross-Compilation:** The architecture-specific `Arch` struct and the handling of different object file formats (ELF, Mach-O, PE, XCOFF) are crucial for cross-compilation.
    * **Cgo:** The handling of host objects and the interaction with external linkers are essential for `cgo`.
    * **Build Modes:** The `ctxt.BuildMode` variable and the conditional logic based on it demonstrate support for different build modes (executable, PIE, shared library, plugin, C archive, C shared).

7. **Consider User Mistakes:** Based on the complexity and the number of command-line flags involved, potential user errors could include:
    * Incorrectly specifying `-linkmode`.
    * Providing incompatible linker flags via `-ldflags`.
    * Issues with the external toolchain setup (e.g., missing `gcc` or `clang`).

8. **Structure the Response:** Organize the findings into clear sections: overall functionality, explanation of Go features, code examples (where applicable and inferrable), command-line parameter handling, and potential user errors.

By following these steps, one can effectively analyze the provided code snippet and derive a comprehensive understanding of its role and functionalities within the Go linker.
```go
// Inferno utils/8l/asm.c
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/8l/asm.c
//
//	Copyright © 1994-1999 Lucent Technologies Inc. All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
//	Portions Copyright © 2009 The Go Authors. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of this software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package ld

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"internal/buildcfg"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"cmd/internal/bio"
	"cmd/internal/goobj"
	"cmd/internal/hash"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/loadelf"
	"cmd/link/internal/loader"
	"cmd/link/internal/loadmacho"
	"cmd/link/internal/loadpe"
	"cmd/link/internal/loadxcoff"
	"cmd/link/internal/sym"
)

// Data layout and relocation.

// Derived from Inferno utils/6l/l.h
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/6l/l.h
//
//	Copyright © 1994-1999 Lucent Technologies Inc. All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
//	Portions Copyright © 2009 The Go Authors. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// ArchSyms holds a number of architecture specific symbols used during
// relocation. Rather than allowing them universal access to all symbols,
// we keep a subset for relocation application.
type ArchSyms struct {
	Rel     loader.Sym
	Rela    loader.Sym
	RelPLT  loader.Sym
	RelaPLT loader.Sym

	LinkEditGOT loader.Sym
	LinkEditPLT loader.Sym

	TOC    loader.Sym
	DotTOC []loader.Sym // for each version

	GOT    loader.Sym
	PLT    loader.Sym
	GOTPLT loader.Sym

	Tlsg      loader.Sym
	Tlsoffset int

	Dynamic loader.Sym
	DynSym  loader.Sym
	DynStr  loader.Sym

	unreachableMethod loader.Sym

	// Symbol containing a list of all the inittasks that need
	// to be run at startup.
	mainInittasks loader.Sym
}

// mkArchSym is a helper for setArchSyms, to set up a special symbol.
func (ctxt *Link) mkArchSym(name string, ver int, ls *loader.Sym) {
	*ls = ctxt.loader.LookupOrCreateSym(name, ver)
	ctxt.loader.SetAttrReachable(*ls, true)
}

// mkArchSymVec is similar to  setArchSyms, but operates on elements within
// a slice, where each element corresponds to some symbol version.
func (ctxt *Link) mkArchSymVec(name string, ver int, ls []loader.Sym) {
	ls[ver] = ctxt.loader.LookupOrCreateSym(name, ver)
	ctxt.loader.SetAttrReachable(ls[ver], true)
}

// setArchSyms sets up the ArchSyms structure, and must be called before
// relocations are applied.
func (ctxt *Link) setArchSyms() {
	ctxt.mkArchSym(".got", 0, &ctxt.GOT)
	ctxt.mkArchSym(".plt", 0, &ctxt.PLT)
	ctxt.mkArchSym(".got.plt", 0, &ctxt.GOTPLT)
	ctxt.mkArchSym(".dynamic", 0, &ctxt.Dynamic)
	ctxt.mkArchSym(".dynsym", 0, &ctxt.DynSym)
	ctxt.mkArchSym(".dynstr", 0, &ctxt.DynStr)
	ctxt.mkArchSym("runtime.unreachableMethod", abiInternalVer, &ctxt.unreachableMethod)

	if ctxt.IsPPC64() {
		ctxt.mkArchSym("TOC", 0, &ctxt.TOC)

		ctxt.DotTOC = make([]loader.Sym, ctxt.MaxVersion()+1)
		for i := 0; i <= ctxt.MaxVersion(); i++ {
			if i >= sym.SymVerABICount && i < sym.SymVerStatic { // these versions are not used currently
				continue
			}
			ctxt.mkArchSymVec(".TOC.", i, ctxt.DotTOC)
		}
	}
	if ctxt.IsElf() {
		ctxt.mkArchSym(".rel", 0, &ctxt.Rel)
		ctxt.mkArchSym(".rela", 0, &ctxt.Rela)
		ctxt.mkArchSym(".rel.plt", 0, &ctxt.RelPLT)
		ctxt.mkArchSym(".rela.plt", 0, &ctxt.RelaPLT)
	}
	if ctxt.IsDarwin() {
		ctxt.mkArchSym(".linkedit.got", 0, &ctxt.LinkEditGOT)
		ctxt.mkArchSym(".linkedit.plt", 0, &ctxt.LinkEditPLT)
	}
}

type Arch struct {
	Funcalign  int
	Maxalign   int
	Minalign   int
	Dwarfregsp int
	Dwarfreglr int

	// Threshold of total text size, used for trampoline insertion. If the total
	// text size is smaller than TrampLimit, we won't need to insert trampolines.
	// It is pretty close to the offset range of a direct CALL machine instruction.
	// We leave some room for extra stuff like PLT stubs.
	TrampLimit uint64

	// Empty spaces between codeblocks will be padded with this value.
	// For example an architecture might want to pad with a trap instruction to
	// catch wayward programs. Architectures that do not define a padding value
	// are padded with zeros.
	CodePad []byte

	// Plan 9 variables.
	Plan9Magic  uint32
	Plan9_64Bit bool

	Adddynrel func(*Target, *loader.Loader, *ArchSyms, loader.Sym, loader.Reloc, int) bool
	Archinit  func(*Link)
	// Archreloc is an arch-specific hook that assists in relocation processing
	// (invoked by 'relocsym'); it handles target-specific relocation tasks.
	// Here "rel" is the current relocation being examined, "sym" is the symbol
	// containing the chunk of data to which the relocation applies, and "off"
	// is the contents of the to-be-relocated data item (from sym.P). Return
	// value is the appropriately relocated value (to be written back to the
	// same spot in sym.P), number of external _host_ relocations needed (i.e.
	// ELF/Mach-O/etc. relocations, not Go relocations, this must match ELF.Reloc1,
	// etc.), and a boolean indicating success/failure (a failing value indicates
	// a fatal error).
	Archreloc func(*Target, *loader.Loader, *ArchSyms, loader.Reloc, loader.Sym,
		int64) (relocatedOffset int64, nExtReloc int, ok bool)
	// Archrelocvariant is a second arch-specific hook used for
	// relocation processing; it handles relocations where r.Type is
	// insufficient to describe the relocation (r.Variant !=
	// sym.RV_NONE). Here "rel" is the relocation being applied, "sym"
	// is the symbol containing the chunk of data to which the
	// relocation applies, and "off" is the contents of the
	// to-be-relocated data item (from sym.P). Return is an updated
	// offset value.
	Archrelocvariant func(target *Target, ldr *loader.Loader, rel loader.Reloc,
		rv sym.RelocVariant, sym loader.Sym, offset int64, data []byte) (relocatedOffset int64)

	// Generate a trampoline for a call from s to rs if necessary. ri is
	// index of the relocation.
	Trampoline func(ctxt *Link, ldr *loader.Loader, ri int, rs, s loader.Sym)

	// Assembling the binary breaks into two phases, writing the code/data/
	// dwarf information (which is rather generic), and some more architecture
	// specific work like setting up the elf headers/dynamic relocations, etc.
	// The phases are called "Asmb" and "Asmb2". Asmb2 needs to be defined for
	// every architecture, but only if architecture has an Asmb function will
	// it be used for assembly. Otherwise a generic assembly Asmb function is
	// used.
	Asmb  func(*Link, *loader.Loader)
	Asmb2 func(*Link, *loader.Loader)

	// Extreloc is an arch-specific hook that converts a Go relocation to an
	// external relocation. Return the external relocation and whether it is
	// needed.
	Extreloc func(*Target, *loader.Loader, loader.Reloc, loader.Sym) (loader.ExtReloc, bool)

	Gentext        func(*Link, *loader.Loader) // Generate text before addressing has been performed.
	Machoreloc1    func(*sys.Arch, *OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool
	MachorelocSize uint32 // size of an Mach-O relocation record, must match Machoreloc1.
	PEreloc1       func(*sys.Arch, *OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool
	Xcoffreloc1    func(*sys.Arch, *OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool

	// Generate additional symbols for the native symbol table just prior to
	// code generation.
	GenSymsLate func(*Link, *loader.Loader)

	// TLSIEtoLE converts a TLS Initial Executable relocation to
	// a TLS Local Executable relocation.
	//
	// This is possible when a TLS IE relocation refers to a local
	// symbol in an executable, which is typical when internally
	// linking PIE binaries.
	TLSIEtoLE func(P []byte, off, size int)

	// optional override for assignAddress
	AssignAddress func(ldr *loader.Loader, sect *sym.Section, n int, s loader.Sym, va uint64, isTramp bool) (*sym.Section, int, uint64)

	// ELF specific information.
	ELF ELFArch
}

var (
	thearch Arch
	lcSize  int32
	rpath   Rpath
	spSize  int32
	symSize int32
)

// Symbol version of ABIInternal symbols. It is sym.SymVerABIInternal if ABI wrappers
// are used, 0 otherwise.
var abiInternalVer = sym.SymVerABIInternal

// DynlinkingGo reports whether we are producing Go code that can live
// in separate shared libraries linked together at runtime.
func (ctxt *Link) DynlinkingGo() bool {
	if !ctxt.Loaded {
		panic("DynlinkingGo called before all symbols loaded")
	}
	return ctxt.BuildMode == BuildModeShared || ctxt.linkShared || ctxt.BuildMode == BuildModePlugin || ctxt.canUsePlugins
}

// CanUsePlugins reports whether a plugins can be used
func (ctxt *Link) CanUsePlugins() bool {
	if !ctxt.Loaded {
		panic("CanUsePlugins called before all symbols loaded")
	}
	return ctxt.canUsePlugins
}

// NeedCodeSign reports whether we need to code-sign the output binary.
func (ctxt *Link) NeedCodeSign() bool {
	return ctxt.IsDarwin() && ctxt.IsARM64()
}

var (
	dynlib          []string
	ldflag          []string
	havedynamic     int
	Funcalign       int
	iscgo           bool
	elfglobalsymndx int
	interpreter     string

	debug_s bool // backup old value of debug['s']
	HEADR   int32

	nerrors  int
	liveness int64 // size of liveness data (funcdata), printed if -v

	// See -strictdups command line flag.
	checkStrictDups   int // 0=off 1=warning 2=error
	strictDupMsgCount int
)

var (
	Segtext      sym.Segment
	Segrodata    sym.Segment
	Segrelrodata sym.Segment
	Segdata      sym.Segment
	Segdwarf     sym.Segment
	Segpdata     sym.Segment // windows-only
	Segxdata     sym.Segment // windows-only

	Segments = []*sym.Segment{&Segtext, &Segrodata, &Segrelrodata, &Segdata, &Segdwarf, &Segpdata, &Segxdata}
)

const pkgdef = "__.PKGDEF"

var (
	// externalobj is set to true if we see an object compiled by
	// the host compiler that is not from a package that is known
	// to support internal linking mode.
	externalobj = false

	// dynimportfail is a list of packages for which generating
	// the dynimport file, _cgo_import.go, failed. If there are
	// any of these objects, we must link externally. Issue 52863.
	dynimportfail []string

	// preferlinkext is a list of packages for which the Go command
	// noticed use of peculiar C flags. If we see any of these,
	// default to linking externally unless overridden by the
	// user. See issues #58619, #58620, and #58848.
	preferlinkext []string

	// unknownObjFormat is set to true if we see an object whose
	// format we don't recognize.
	unknownObjFormat = false

	theline string
)

func Lflag(ctxt *Link, arg string) {
	ctxt.Libdir = append(ctxt.Libdir, arg)
}

/*
 * Unix doesn't like it when we write to a running (or, sometimes,
 * recently run) binary, so remove the output file before writing it.
 * On Windows 7, remove() can force a subsequent create() to fail.
 * S_ISREG() does not exist on Plan 9.
 */
func mayberemoveoutfile() {
	if fi, err := os.Lstat(*flagOutfile); err == nil && !fi.Mode().IsRegular() {
		return
	}
	os.Remove(*flagOutfile)
}

func libinit(ctxt *Link) {
	Funcalign = thearch.Funcalign

	// add goroot to the end of the libdir list.
	suffix := ""

	suffixsep := ""
	if *flagInstallSuffix != "" {
		suffixsep = "_"
		suffix = *flagInstallSuffix
	} else if *flagRace {
		suffixsep = "_"
		suffix = "race"
	} else if *flagMsan {
		suffixsep = "_"
		suffix = "msan"
	} else if *flagAsan {
		suffixsep = "_"
		suffix = "asan"
	}

	if buildcfg.GOROOT != "" {
		Lflag(ctxt, filepath.Join(buildcfg.GOROOT, "pkg", fmt.Sprintf("%s_%s%s%s", buildcfg.GOOS, buildcfg.GOARCH, suffixsep, suffix)))
	}

	mayberemoveoutfile()

	if err := ctxt.Out.Open(*flagOutfile); err != nil {
		Exitf("cannot create %s: %v", *flagOutfile, err)
	}

	if *flagEntrySymbol == "" {
		switch ctxt.BuildMode {
		case BuildModeCShared, BuildModeCArchive:
			*flagEntrySymbol = fmt.Sprintf("_rt0_%s_%s_lib", buildcfg.GOARCH, buildcfg.GOOS)
		case BuildModeExe, BuildModePIE:
			*flagEntrySymbol = fmt.Sprintf("_rt0_%s_%s", buildcfg.GOARCH, buildcfg.GOOS)
		case BuildModeShared, BuildModePlugin:
			// No *flagEntrySymbol for -buildmode=shared and plugin
		default:
			Errorf("unknown *flagEntrySymbol for buildmode %v", ctxt.BuildMode)
		}
	}
}

func exitIfErrors() {
	if nerrors != 0 || checkStrictDups > 1 && strictDupMsgCount > 0 {
		mayberemoveoutfile()
		Exit(2)
	}

}

func errorexit() {
	exitIfErrors()
	Exit(0)
}

func loadinternal(ctxt *Link, name string) *sym.Library {
	zerofp := goobj.FingerprintType{}
	if ctxt.linkShared && ctxt.PackageShlib != nil {
		if shlib := ctxt.PackageShlib[name]; shlib != "" {
			return addlibpath(ctxt, "internal", "internal", "", name, shlib, zerofp)
		}
	}
	if ctxt.PackageFile != nil {
		if pname := ctxt.PackageFile[name]; pname != "" {
			return addlibpath(ctxt, "internal", "internal", pname, name, "", zerofp)
		}
		ctxt.Logf("loadinternal: cannot find %s\n", name)
		return nil
	}

	for _, libdir := range ctxt.Libdir {
		if ctxt.linkShared {
			shlibname := filepath.Join(libdir, name+".shlibname")
			if ctxt.Debugvlog != 0 {
				ctxt.Logf("searching for %s.a in %s\n", name, shlibname)
			}
			if _, err := os.Stat(shlibname); err == nil {
				return addlibpath(ctxt, "internal", "internal", "", name, shlibname, zerofp)
			}
		}
		pname := filepath.Join(libdir, name+".a")
		if ctxt.Debugvlog != 0 {
			ctxt.Logf("searching for %s.a in %s\n", name, pname)
		}
		if _, err := os.Stat(pname); err == nil {
			return addlibpath(ctxt, "internal", "internal", pname, name, "", zerofp)
		}
	}

	if name == "runtime" {
		Exitf("error: unable to find runtime.a")
	}
	ctxt.Logf("warning: unable to find %s.a\n", name)
	return nil
}

// extld returns the current external linker.
func (ctxt *Link) extld() []string {
	if len(flagExtld) == 0 {
		// Return the default external linker for the platform.
		// This only matters when link tool is called directly without explicit -extld,
		// go tool already passes the correct linker in other cases.
		switch buildcfg.GOOS {
		case "darwin", "freebsd", "openbsd":
			flagExtld = []string{"clang"}
		default:
			flagExtld = []string{"gcc"}
		}
	}
	return flagExtld
}

// findLibPathCmd uses cmd command to find gcc library libname.
// It returns library full path if found, or "none" if not found.
func (ctxt *Link) findLibPathCmd(cmd, libname string) string {
	extld := ctxt.extld()
	name, args := extld[0], extld[1:]
	args = append(args, hostlinkArchArgs(ctxt.Arch)...)
	args = append(args, cmd)
	if ctxt.Debugvlog != 0 {
		ctxt.Logf("%s %v\n", extld, args)
	}
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		if ctxt.Debugvlog != 0 {
			ctxt.Logf("not using a %s file because compiler failed\n%v\n%s\n", libname, err, out)
		}
		return "none"
	}
	return strings.TrimSpace(string(out))
}

// findLibPath searches for library libname.
// It returns library full path if found, or "none" if not found.
func (ctxt *Link) findLibPath(libname string) string {
	return ctxt.findLibPathCmd("--print-file-name="+libname, libname)
}

func (ctxt *Link) loadlib() {
	var flags uint32
	if *flagCheckLinkname {
		flags |= loader.FlagCheckLinkname
	}
	switch *FlagStrictDups {
	case 0:
		// nothing to do
	case 1, 2:
		flags |= loader.FlagStrictDups
	default:
		log.Fatalf("invalid -strictdups flag value %d", *FlagStrictDups)
	}
	ctxt.loader = loader.NewLoader(flags, &ctxt.ErrorReporter.ErrorReporter)
	ctxt.ErrorReporter.SymName = func(s loader.Sym) string {
		return ctxt.loader.SymName(s)
	}

	// ctxt.Library grows during the loop, so not a range loop.
	i := 0
	for ; i < len(ctxt.Library); i++ {
		lib := ctxt.Library[i]
		if lib.Shlib == "" {
			if ctxt.Debugvlog > 1 {
				ctxt.Logf("autolib: %s (from %s)\n", lib.File, lib.Objref)
			}
			loadobjfile(ctxt, lib)
		}
	}

	// load internal packages, if not already
	if *flagRace {
		loadinternal(ctxt, "runtime/race")
	}
	if *flagMsan {
		loadinternal(ctxt, "runtime/msan")
	}
	if *flagAsan {
		loadinternal(ctxt, "runtime/asan")
	}
	loadinternal(ctxt, "runtime")
	for ; i < len(ctxt.Library); i++ {
		lib := ctxt.Library[i]
		if lib.Shlib == "" {
			loadobjfile(ctxt, lib)
		}
	}
	// At this point, the Go objects are "preloaded". Not all the symbols are
	// added to the symbol table (only defined package symbols are). Looking
	// up symbol by name may not get expected result.

	iscgo = ctxt.LibraryByPkg["runtime/cgo"] != nil

	// Plugins a require cgo support to function. Similarly, plugins may require additional
	// internal linker support on some platforms which may not be implemented.
	ctxt.canUsePlugins = ctxt.LibraryByPkg["plugin"] != nil && iscgo

	// We now have enough information to determine the link mode.
	determineLinkMode(ctxt)

	if ctxt.LinkMode == LinkExternal && !iscgo && !(buildcfg.GOOS == "darwin" && ctxt.BuildMode != BuildModePlugin && ctxt.Arch.Family == sys.AMD64) {
		// This indicates a user requested -linkmode=external.
		// The startup code uses an import of runtime/cgo to decide
		// whether to initialize the TLS. So give it one. This could
		// be handled differently but it's an unusual case.
		if lib := loadinternal(ctxt, "runtime/cgo"); lib != nil && lib.Shlib == "" {
			if ctxt.BuildMode == BuildModeShared || ctxt.linkShared {
				Exitf("cannot implicitly include runtime/cgo in a shared library")
			}
			for ; i < len(ctxt.Library); i++ {
				lib := ctxt.Library[i]
				if lib.Shlib == "" {
					loadobjfile(ctxt, lib)
				}
			}
		}
	}

	// Add non-package symbols and references of externally defined symbols.
	ctxt.loader.LoadSyms(ctxt.Arch)

	// Load symbols from shared libraries, after all Go object symbols are loaded.
	for _, lib := range ctxt.Library {
		if lib.Shlib != "" {
			if ctxt.Debugvlog > 1 {
				ctxt.Logf("autolib: %s (from %s)\n", lib.Shlib, lib.Objref)
			}
			ldshlibsyms(ctxt, lib.Shlib)
		}
	}

	// Process cgo directives (has to be done before host object loading).
	ctxt.loadcgodirectives()

	// Conditionally load host objects, or setup for external linking.
	hostobjs(ctxt)
	hostlinksetup(ctxt)

	if ctxt.LinkMode == LinkInternal && len(hostobj) != 0 {
		// If we have any undefined symbols in external
		// objects, try to read them from the libgcc file.
		any := false
		undefs, froms := ctxt.loader.UndefinedRel
Prompt: 
```
这是路径为go/src/cmd/link/internal/ld/lib.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能

"""
// Inferno utils/8l/asm.c
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/8l/asm.c
//
//	Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
//	Portions Copyright © 2009 The Go Authors. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package ld

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"internal/buildcfg"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"cmd/internal/bio"
	"cmd/internal/goobj"
	"cmd/internal/hash"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/loadelf"
	"cmd/link/internal/loader"
	"cmd/link/internal/loadmacho"
	"cmd/link/internal/loadpe"
	"cmd/link/internal/loadxcoff"
	"cmd/link/internal/sym"
)

// Data layout and relocation.

// Derived from Inferno utils/6l/l.h
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/6l/l.h
//
//	Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
//	Portions Copyright © 2009 The Go Authors. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// ArchSyms holds a number of architecture specific symbols used during
// relocation.  Rather than allowing them universal access to all symbols,
// we keep a subset for relocation application.
type ArchSyms struct {
	Rel     loader.Sym
	Rela    loader.Sym
	RelPLT  loader.Sym
	RelaPLT loader.Sym

	LinkEditGOT loader.Sym
	LinkEditPLT loader.Sym

	TOC    loader.Sym
	DotTOC []loader.Sym // for each version

	GOT    loader.Sym
	PLT    loader.Sym
	GOTPLT loader.Sym

	Tlsg      loader.Sym
	Tlsoffset int

	Dynamic loader.Sym
	DynSym  loader.Sym
	DynStr  loader.Sym

	unreachableMethod loader.Sym

	// Symbol containing a list of all the inittasks that need
	// to be run at startup.
	mainInittasks loader.Sym
}

// mkArchSym is a helper for setArchSyms, to set up a special symbol.
func (ctxt *Link) mkArchSym(name string, ver int, ls *loader.Sym) {
	*ls = ctxt.loader.LookupOrCreateSym(name, ver)
	ctxt.loader.SetAttrReachable(*ls, true)
}

// mkArchSymVec is similar to  setArchSyms, but operates on elements within
// a slice, where each element corresponds to some symbol version.
func (ctxt *Link) mkArchSymVec(name string, ver int, ls []loader.Sym) {
	ls[ver] = ctxt.loader.LookupOrCreateSym(name, ver)
	ctxt.loader.SetAttrReachable(ls[ver], true)
}

// setArchSyms sets up the ArchSyms structure, and must be called before
// relocations are applied.
func (ctxt *Link) setArchSyms() {
	ctxt.mkArchSym(".got", 0, &ctxt.GOT)
	ctxt.mkArchSym(".plt", 0, &ctxt.PLT)
	ctxt.mkArchSym(".got.plt", 0, &ctxt.GOTPLT)
	ctxt.mkArchSym(".dynamic", 0, &ctxt.Dynamic)
	ctxt.mkArchSym(".dynsym", 0, &ctxt.DynSym)
	ctxt.mkArchSym(".dynstr", 0, &ctxt.DynStr)
	ctxt.mkArchSym("runtime.unreachableMethod", abiInternalVer, &ctxt.unreachableMethod)

	if ctxt.IsPPC64() {
		ctxt.mkArchSym("TOC", 0, &ctxt.TOC)

		ctxt.DotTOC = make([]loader.Sym, ctxt.MaxVersion()+1)
		for i := 0; i <= ctxt.MaxVersion(); i++ {
			if i >= sym.SymVerABICount && i < sym.SymVerStatic { // these versions are not used currently
				continue
			}
			ctxt.mkArchSymVec(".TOC.", i, ctxt.DotTOC)
		}
	}
	if ctxt.IsElf() {
		ctxt.mkArchSym(".rel", 0, &ctxt.Rel)
		ctxt.mkArchSym(".rela", 0, &ctxt.Rela)
		ctxt.mkArchSym(".rel.plt", 0, &ctxt.RelPLT)
		ctxt.mkArchSym(".rela.plt", 0, &ctxt.RelaPLT)
	}
	if ctxt.IsDarwin() {
		ctxt.mkArchSym(".linkedit.got", 0, &ctxt.LinkEditGOT)
		ctxt.mkArchSym(".linkedit.plt", 0, &ctxt.LinkEditPLT)
	}
}

type Arch struct {
	Funcalign  int
	Maxalign   int
	Minalign   int
	Dwarfregsp int
	Dwarfreglr int

	// Threshold of total text size, used for trampoline insertion. If the total
	// text size is smaller than TrampLimit, we won't need to insert trampolines.
	// It is pretty close to the offset range of a direct CALL machine instruction.
	// We leave some room for extra stuff like PLT stubs.
	TrampLimit uint64

	// Empty spaces between codeblocks will be padded with this value.
	// For example an architecture might want to pad with a trap instruction to
	// catch wayward programs. Architectures that do not define a padding value
	// are padded with zeros.
	CodePad []byte

	// Plan 9 variables.
	Plan9Magic  uint32
	Plan9_64Bit bool

	Adddynrel func(*Target, *loader.Loader, *ArchSyms, loader.Sym, loader.Reloc, int) bool
	Archinit  func(*Link)
	// Archreloc is an arch-specific hook that assists in relocation processing
	// (invoked by 'relocsym'); it handles target-specific relocation tasks.
	// Here "rel" is the current relocation being examined, "sym" is the symbol
	// containing the chunk of data to which the relocation applies, and "off"
	// is the contents of the to-be-relocated data item (from sym.P). Return
	// value is the appropriately relocated value (to be written back to the
	// same spot in sym.P), number of external _host_ relocations needed (i.e.
	// ELF/Mach-O/etc. relocations, not Go relocations, this must match ELF.Reloc1,
	// etc.), and a boolean indicating success/failure (a failing value indicates
	// a fatal error).
	Archreloc func(*Target, *loader.Loader, *ArchSyms, loader.Reloc, loader.Sym,
		int64) (relocatedOffset int64, nExtReloc int, ok bool)
	// Archrelocvariant is a second arch-specific hook used for
	// relocation processing; it handles relocations where r.Type is
	// insufficient to describe the relocation (r.Variant !=
	// sym.RV_NONE). Here "rel" is the relocation being applied, "sym"
	// is the symbol containing the chunk of data to which the
	// relocation applies, and "off" is the contents of the
	// to-be-relocated data item (from sym.P). Return is an updated
	// offset value.
	Archrelocvariant func(target *Target, ldr *loader.Loader, rel loader.Reloc,
		rv sym.RelocVariant, sym loader.Sym, offset int64, data []byte) (relocatedOffset int64)

	// Generate a trampoline for a call from s to rs if necessary. ri is
	// index of the relocation.
	Trampoline func(ctxt *Link, ldr *loader.Loader, ri int, rs, s loader.Sym)

	// Assembling the binary breaks into two phases, writing the code/data/
	// dwarf information (which is rather generic), and some more architecture
	// specific work like setting up the elf headers/dynamic relocations, etc.
	// The phases are called "Asmb" and "Asmb2". Asmb2 needs to be defined for
	// every architecture, but only if architecture has an Asmb function will
	// it be used for assembly.  Otherwise a generic assembly Asmb function is
	// used.
	Asmb  func(*Link, *loader.Loader)
	Asmb2 func(*Link, *loader.Loader)

	// Extreloc is an arch-specific hook that converts a Go relocation to an
	// external relocation. Return the external relocation and whether it is
	// needed.
	Extreloc func(*Target, *loader.Loader, loader.Reloc, loader.Sym) (loader.ExtReloc, bool)

	Gentext        func(*Link, *loader.Loader) // Generate text before addressing has been performed.
	Machoreloc1    func(*sys.Arch, *OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool
	MachorelocSize uint32 // size of an Mach-O relocation record, must match Machoreloc1.
	PEreloc1       func(*sys.Arch, *OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool
	Xcoffreloc1    func(*sys.Arch, *OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool

	// Generate additional symbols for the native symbol table just prior to
	// code generation.
	GenSymsLate func(*Link, *loader.Loader)

	// TLSIEtoLE converts a TLS Initial Executable relocation to
	// a TLS Local Executable relocation.
	//
	// This is possible when a TLS IE relocation refers to a local
	// symbol in an executable, which is typical when internally
	// linking PIE binaries.
	TLSIEtoLE func(P []byte, off, size int)

	// optional override for assignAddress
	AssignAddress func(ldr *loader.Loader, sect *sym.Section, n int, s loader.Sym, va uint64, isTramp bool) (*sym.Section, int, uint64)

	// ELF specific information.
	ELF ELFArch
}

var (
	thearch Arch
	lcSize  int32
	rpath   Rpath
	spSize  int32
	symSize int32
)

// Symbol version of ABIInternal symbols. It is sym.SymVerABIInternal if ABI wrappers
// are used, 0 otherwise.
var abiInternalVer = sym.SymVerABIInternal

// DynlinkingGo reports whether we are producing Go code that can live
// in separate shared libraries linked together at runtime.
func (ctxt *Link) DynlinkingGo() bool {
	if !ctxt.Loaded {
		panic("DynlinkingGo called before all symbols loaded")
	}
	return ctxt.BuildMode == BuildModeShared || ctxt.linkShared || ctxt.BuildMode == BuildModePlugin || ctxt.canUsePlugins
}

// CanUsePlugins reports whether a plugins can be used
func (ctxt *Link) CanUsePlugins() bool {
	if !ctxt.Loaded {
		panic("CanUsePlugins called before all symbols loaded")
	}
	return ctxt.canUsePlugins
}

// NeedCodeSign reports whether we need to code-sign the output binary.
func (ctxt *Link) NeedCodeSign() bool {
	return ctxt.IsDarwin() && ctxt.IsARM64()
}

var (
	dynlib          []string
	ldflag          []string
	havedynamic     int
	Funcalign       int
	iscgo           bool
	elfglobalsymndx int
	interpreter     string

	debug_s bool // backup old value of debug['s']
	HEADR   int32

	nerrors  int
	liveness int64 // size of liveness data (funcdata), printed if -v

	// See -strictdups command line flag.
	checkStrictDups   int // 0=off 1=warning 2=error
	strictDupMsgCount int
)

var (
	Segtext      sym.Segment
	Segrodata    sym.Segment
	Segrelrodata sym.Segment
	Segdata      sym.Segment
	Segdwarf     sym.Segment
	Segpdata     sym.Segment // windows-only
	Segxdata     sym.Segment // windows-only

	Segments = []*sym.Segment{&Segtext, &Segrodata, &Segrelrodata, &Segdata, &Segdwarf, &Segpdata, &Segxdata}
)

const pkgdef = "__.PKGDEF"

var (
	// externalobj is set to true if we see an object compiled by
	// the host compiler that is not from a package that is known
	// to support internal linking mode.
	externalobj = false

	// dynimportfail is a list of packages for which generating
	// the dynimport file, _cgo_import.go, failed. If there are
	// any of these objects, we must link externally. Issue 52863.
	dynimportfail []string

	// preferlinkext is a list of packages for which the Go command
	// noticed use of peculiar C flags. If we see any of these,
	// default to linking externally unless overridden by the
	// user. See issues #58619, #58620, and #58848.
	preferlinkext []string

	// unknownObjFormat is set to true if we see an object whose
	// format we don't recognize.
	unknownObjFormat = false

	theline string
)

func Lflag(ctxt *Link, arg string) {
	ctxt.Libdir = append(ctxt.Libdir, arg)
}

/*
 * Unix doesn't like it when we write to a running (or, sometimes,
 * recently run) binary, so remove the output file before writing it.
 * On Windows 7, remove() can force a subsequent create() to fail.
 * S_ISREG() does not exist on Plan 9.
 */
func mayberemoveoutfile() {
	if fi, err := os.Lstat(*flagOutfile); err == nil && !fi.Mode().IsRegular() {
		return
	}
	os.Remove(*flagOutfile)
}

func libinit(ctxt *Link) {
	Funcalign = thearch.Funcalign

	// add goroot to the end of the libdir list.
	suffix := ""

	suffixsep := ""
	if *flagInstallSuffix != "" {
		suffixsep = "_"
		suffix = *flagInstallSuffix
	} else if *flagRace {
		suffixsep = "_"
		suffix = "race"
	} else if *flagMsan {
		suffixsep = "_"
		suffix = "msan"
	} else if *flagAsan {
		suffixsep = "_"
		suffix = "asan"
	}

	if buildcfg.GOROOT != "" {
		Lflag(ctxt, filepath.Join(buildcfg.GOROOT, "pkg", fmt.Sprintf("%s_%s%s%s", buildcfg.GOOS, buildcfg.GOARCH, suffixsep, suffix)))
	}

	mayberemoveoutfile()

	if err := ctxt.Out.Open(*flagOutfile); err != nil {
		Exitf("cannot create %s: %v", *flagOutfile, err)
	}

	if *flagEntrySymbol == "" {
		switch ctxt.BuildMode {
		case BuildModeCShared, BuildModeCArchive:
			*flagEntrySymbol = fmt.Sprintf("_rt0_%s_%s_lib", buildcfg.GOARCH, buildcfg.GOOS)
		case BuildModeExe, BuildModePIE:
			*flagEntrySymbol = fmt.Sprintf("_rt0_%s_%s", buildcfg.GOARCH, buildcfg.GOOS)
		case BuildModeShared, BuildModePlugin:
			// No *flagEntrySymbol for -buildmode=shared and plugin
		default:
			Errorf("unknown *flagEntrySymbol for buildmode %v", ctxt.BuildMode)
		}
	}
}

func exitIfErrors() {
	if nerrors != 0 || checkStrictDups > 1 && strictDupMsgCount > 0 {
		mayberemoveoutfile()
		Exit(2)
	}

}

func errorexit() {
	exitIfErrors()
	Exit(0)
}

func loadinternal(ctxt *Link, name string) *sym.Library {
	zerofp := goobj.FingerprintType{}
	if ctxt.linkShared && ctxt.PackageShlib != nil {
		if shlib := ctxt.PackageShlib[name]; shlib != "" {
			return addlibpath(ctxt, "internal", "internal", "", name, shlib, zerofp)
		}
	}
	if ctxt.PackageFile != nil {
		if pname := ctxt.PackageFile[name]; pname != "" {
			return addlibpath(ctxt, "internal", "internal", pname, name, "", zerofp)
		}
		ctxt.Logf("loadinternal: cannot find %s\n", name)
		return nil
	}

	for _, libdir := range ctxt.Libdir {
		if ctxt.linkShared {
			shlibname := filepath.Join(libdir, name+".shlibname")
			if ctxt.Debugvlog != 0 {
				ctxt.Logf("searching for %s.a in %s\n", name, shlibname)
			}
			if _, err := os.Stat(shlibname); err == nil {
				return addlibpath(ctxt, "internal", "internal", "", name, shlibname, zerofp)
			}
		}
		pname := filepath.Join(libdir, name+".a")
		if ctxt.Debugvlog != 0 {
			ctxt.Logf("searching for %s.a in %s\n", name, pname)
		}
		if _, err := os.Stat(pname); err == nil {
			return addlibpath(ctxt, "internal", "internal", pname, name, "", zerofp)
		}
	}

	if name == "runtime" {
		Exitf("error: unable to find runtime.a")
	}
	ctxt.Logf("warning: unable to find %s.a\n", name)
	return nil
}

// extld returns the current external linker.
func (ctxt *Link) extld() []string {
	if len(flagExtld) == 0 {
		// Return the default external linker for the platform.
		// This only matters when link tool is called directly without explicit -extld,
		// go tool already passes the correct linker in other cases.
		switch buildcfg.GOOS {
		case "darwin", "freebsd", "openbsd":
			flagExtld = []string{"clang"}
		default:
			flagExtld = []string{"gcc"}
		}
	}
	return flagExtld
}

// findLibPathCmd uses cmd command to find gcc library libname.
// It returns library full path if found, or "none" if not found.
func (ctxt *Link) findLibPathCmd(cmd, libname string) string {
	extld := ctxt.extld()
	name, args := extld[0], extld[1:]
	args = append(args, hostlinkArchArgs(ctxt.Arch)...)
	args = append(args, cmd)
	if ctxt.Debugvlog != 0 {
		ctxt.Logf("%s %v\n", extld, args)
	}
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		if ctxt.Debugvlog != 0 {
			ctxt.Logf("not using a %s file because compiler failed\n%v\n%s\n", libname, err, out)
		}
		return "none"
	}
	return strings.TrimSpace(string(out))
}

// findLibPath searches for library libname.
// It returns library full path if found, or "none" if not found.
func (ctxt *Link) findLibPath(libname string) string {
	return ctxt.findLibPathCmd("--print-file-name="+libname, libname)
}

func (ctxt *Link) loadlib() {
	var flags uint32
	if *flagCheckLinkname {
		flags |= loader.FlagCheckLinkname
	}
	switch *FlagStrictDups {
	case 0:
		// nothing to do
	case 1, 2:
		flags |= loader.FlagStrictDups
	default:
		log.Fatalf("invalid -strictdups flag value %d", *FlagStrictDups)
	}
	ctxt.loader = loader.NewLoader(flags, &ctxt.ErrorReporter.ErrorReporter)
	ctxt.ErrorReporter.SymName = func(s loader.Sym) string {
		return ctxt.loader.SymName(s)
	}

	// ctxt.Library grows during the loop, so not a range loop.
	i := 0
	for ; i < len(ctxt.Library); i++ {
		lib := ctxt.Library[i]
		if lib.Shlib == "" {
			if ctxt.Debugvlog > 1 {
				ctxt.Logf("autolib: %s (from %s)\n", lib.File, lib.Objref)
			}
			loadobjfile(ctxt, lib)
		}
	}

	// load internal packages, if not already
	if *flagRace {
		loadinternal(ctxt, "runtime/race")
	}
	if *flagMsan {
		loadinternal(ctxt, "runtime/msan")
	}
	if *flagAsan {
		loadinternal(ctxt, "runtime/asan")
	}
	loadinternal(ctxt, "runtime")
	for ; i < len(ctxt.Library); i++ {
		lib := ctxt.Library[i]
		if lib.Shlib == "" {
			loadobjfile(ctxt, lib)
		}
	}
	// At this point, the Go objects are "preloaded". Not all the symbols are
	// added to the symbol table (only defined package symbols are). Looking
	// up symbol by name may not get expected result.

	iscgo = ctxt.LibraryByPkg["runtime/cgo"] != nil

	// Plugins a require cgo support to function. Similarly, plugins may require additional
	// internal linker support on some platforms which may not be implemented.
	ctxt.canUsePlugins = ctxt.LibraryByPkg["plugin"] != nil && iscgo

	// We now have enough information to determine the link mode.
	determineLinkMode(ctxt)

	if ctxt.LinkMode == LinkExternal && !iscgo && !(buildcfg.GOOS == "darwin" && ctxt.BuildMode != BuildModePlugin && ctxt.Arch.Family == sys.AMD64) {
		// This indicates a user requested -linkmode=external.
		// The startup code uses an import of runtime/cgo to decide
		// whether to initialize the TLS.  So give it one. This could
		// be handled differently but it's an unusual case.
		if lib := loadinternal(ctxt, "runtime/cgo"); lib != nil && lib.Shlib == "" {
			if ctxt.BuildMode == BuildModeShared || ctxt.linkShared {
				Exitf("cannot implicitly include runtime/cgo in a shared library")
			}
			for ; i < len(ctxt.Library); i++ {
				lib := ctxt.Library[i]
				if lib.Shlib == "" {
					loadobjfile(ctxt, lib)
				}
			}
		}
	}

	// Add non-package symbols and references of externally defined symbols.
	ctxt.loader.LoadSyms(ctxt.Arch)

	// Load symbols from shared libraries, after all Go object symbols are loaded.
	for _, lib := range ctxt.Library {
		if lib.Shlib != "" {
			if ctxt.Debugvlog > 1 {
				ctxt.Logf("autolib: %s (from %s)\n", lib.Shlib, lib.Objref)
			}
			ldshlibsyms(ctxt, lib.Shlib)
		}
	}

	// Process cgo directives (has to be done before host object loading).
	ctxt.loadcgodirectives()

	// Conditionally load host objects, or setup for external linking.
	hostobjs(ctxt)
	hostlinksetup(ctxt)

	if ctxt.LinkMode == LinkInternal && len(hostobj) != 0 {
		// If we have any undefined symbols in external
		// objects, try to read them from the libgcc file.
		any := false
		undefs, froms := ctxt.loader.UndefinedRelocTargets(1)
		if len(undefs) > 0 {
			any = true
			if ctxt.Debugvlog > 1 {
				ctxt.Logf("loadlib: first unresolved is %s [%d] from %s [%d]\n",
					ctxt.loader.SymName(undefs[0]), undefs[0],
					ctxt.loader.SymName(froms[0]), froms[0])
			}
		}
		if any {
			if *flagLibGCC == "" {
				*flagLibGCC = ctxt.findLibPathCmd("--print-libgcc-file-name", "libgcc")
			}
			if runtime.GOOS == "freebsd" && strings.HasPrefix(filepath.Base(*flagLibGCC), "libclang_rt.builtins") {
				// On newer versions of FreeBSD, libgcc is returned as something like
				// /usr/lib/clang/18/lib/freebsd/libclang_rt.builtins-x86_64.a.
				// Unfortunately this ends up missing a bunch of symbols we need from
				// libcompiler_rt.
				*flagLibGCC = ctxt.findLibPathCmd("--print-file-name=libcompiler_rt.a", "libcompiler_rt")
			}
			if runtime.GOOS == "openbsd" && *flagLibGCC == "libgcc.a" {
				// On OpenBSD `clang --print-libgcc-file-name` returns "libgcc.a".
				// In this case we fail to load libgcc.a and can encounter link
				// errors - see if we can find libcompiler_rt.a instead.
				*flagLibGCC = ctxt.findLibPathCmd("--print-file-name=libcompiler_rt.a", "libcompiler_rt")
			}
			if ctxt.HeadType == objabi.Hwindows {
				loadWindowsHostArchives(ctxt)
			}
			if *flagLibGCC != "none" {
				hostArchive(ctxt, *flagLibGCC)
			}
			// For glibc systems, the linker setup used by GCC
			// looks like
			//
			//  GROUP ( /lib/x86_64-linux-gnu/libc.so.6
			//      /usr/lib/x86_64-linux-gnu/libc_nonshared.a
			//      AS_NEEDED ( /lib64/ld-linux-x86-64.so.2 ) )
			//
			// where libc_nonshared.a contains a small set of
			// symbols including "__stack_chk_fail_local" and a
			// few others. Thus if we are doing internal linking
			// and "__stack_chk_fail_local" is unresolved (most
			// likely due to the use of -fstack-protector), try
			// loading libc_nonshared.a to resolve it.
			//
			// On Alpine Linux (musl-based), the library providing
			// this symbol is called libssp_nonshared.a.
			isunresolved := symbolsAreUnresolved(ctxt, []string{"__stack_chk_fail_local"})
			if isunresolved[0] {
				if p := ctxt.findLibPath("libc_nonshared.a"); p != "none" {
					hostArchive(ctxt, p)
				}
				if p := ctxt.findLibPath("libssp_nonshared.a"); p != "none" {
					hostArchive(ctxt, p)
				}
			}
		}
	}

	loadfips(ctxt)

	// We've loaded all the code now.
	ctxt.Loaded = true

	strictDupMsgCount = ctxt.loader.NStrictDupMsgs()
}

// loadWindowsHostArchives loads in host archives and objects when
// doing internal linking on windows. Older toolchains seem to require
// just a single pass through the various archives, but some modern
// toolchains when linking a C program with mingw pass library paths
// multiple times to the linker, e.g. "... -lmingwex -lmingw32 ...
// -lmingwex -lmingw32 ...". To accommodate this behavior, we make two
// passes over the host archives below.
func loadWindowsHostArchives(ctxt *Link) {
	any := true
	for i := 0; any && i < 2; i++ {
		// Link crt2.o (if present) to resolve "atexit" when
		// using LLVM-based compilers.
		isunresolved := symbolsAreUnresolved(ctxt, []string{"atexit"})
		if isunresolved[0] {
			if p := ctxt.findLibPath("crt2.o"); p != "none" {
				hostObject(ctxt, "crt2", p)
			}
		}
		if *flagRace {
			if p := ctxt.findLibPath("libsynchronization.a"); p != "none" {
				hostArchive(ctxt, p)
			}
		}
		if p := ctxt.findLibPath("libmingwex.a"); p != "none" {
			hostArchive(ctxt, p)
		}
		if p := ctxt.findLibPath("libmingw32.a"); p != "none" {
			hostArchive(ctxt, p)
		}
		// Link libmsvcrt.a to resolve '__acrt_iob_func' symbol
		// (see https://golang.org/issue/23649 for details).
		if p := ctxt.findLibPath("libmsvcrt.a"); p != "none" {
			hostArchive(ctxt, p)
		}
		any = false
		undefs, froms := ctxt.loader.UndefinedRelocTargets(1)
		if len(undefs) > 0 {
			any = true
			if ctxt.Debugvlog > 1 {
				ctxt.Logf("loadWindowsHostArchives: remaining unresolved is %s [%d] from %s [%d]\n",
					ctxt.loader.SymName(undefs[0]), undefs[0],
					ctxt.loader.SymName(froms[0]), froms[0])
			}
		}
	}
	// If needed, create the __CTOR_LIST__ and __DTOR_LIST__
	// symbols (referenced by some of the mingw support library
	// routines). Creation of these symbols is normally done by the
	// linker if not already present.
	want := []string{"__CTOR_LIST__", "__DTOR_LIST__"}
	isunresolved := symbolsAreUnresolved(ctxt, want)
	for k, w := range want {
		if isunresolved[k] {
			sb := ctxt.loader.CreateSymForUpdate(w, 0)
			sb.SetType(sym.SDATA)
			sb.AddUint64(ctxt.Arch, 0)
			sb.SetReachable(true)
			ctxt.loader.SetAttrSpecial(sb.Sym(), true)
		}
	}

	// Fix up references to DLL import symbols now that we're done
	// pulling in new objects.
	if err := loadpe.PostProcessImports(); err != nil {
		Errorf("%v", err)
	}

	// TODO: maybe do something similar to peimporteddlls to collect
	// all lib names and try link them all to final exe just like
	// libmingwex.a and libmingw32.a:
	/*
		for:
		#cgo windows LDFLAGS: -lmsvcrt -lm
		import:
		libmsvcrt.a libm.a
	*/
}

// loadcgodirectives reads the previously discovered cgo directives, creating
// symbols in preparation for host object loading or use later in the link.
func (ctxt *Link) loadcgodirectives() {
	l := ctxt.loader
	hostObjSyms := make(map[loader.Sym]struct{})
	for _, d := range ctxt.cgodata {
		setCgoAttr(ctxt, d.file, d.pkg, d.directives, hostObjSyms)
	}
	ctxt.cgodata = nil

	if ctxt.LinkMode == LinkInternal {
		// Drop all the cgo_import_static declarations.
		// Turns out we won't be needing them.
		for symIdx := range hostObjSyms {
			if l.SymType(symIdx) == sym.SHOSTOBJ {
				// If a symbol was marked both
				// cgo_import_static and cgo_import_dynamic,
				// then we want to make it cgo_import_dynamic
				// now.
				su := l.MakeSymbolUpdater(symIdx)
				if l.SymExtname(symIdx) != "" && l.SymDynimplib(symIdx) != "" && !(l.AttrCgoExportStatic(symIdx) || l.AttrCgoExportDynamic(symIdx)) {
					su.SetType(sym.SDYNIMPORT)
				} else {
					su.SetType(0)
				}
			}
		}
	}
}

// Set up flags and special symbols depending on the platform build mode.
// This version works with loader.Loader.
func (ctxt *Link) linksetup() {
	switch ctxt.BuildMode {
	case BuildModeCShared, BuildModePlugin:
		symIdx := ctxt.loader.LookupOrCreateSym("runtime.islibrary", 0)
		sb := ctxt.loader.MakeSymbolUpdater(symIdx)
		sb.SetType(sym.SNOPTRDATA)
		sb.AddUint8(1)
	case BuildModeCArchive:
		symIdx := ctxt.loader.LookupOrCreateSym("runtime.isarchive", 0)
		sb := ctxt.loader.MakeSymbolUpdater(symIdx)
		sb.SetType(sym.SNOPTRDATA)
		sb.AddUint8(1)
	}

	// Recalculate pe parameters now that we have ctxt.LinkMode set.
	if ctxt.HeadType == objabi.Hwindows {
		Peinit(ctxt)
	}

	if ctxt.LinkMode == LinkExternal {
		// When external linking, we are creating an object file. The
		// absolute address is irrelevant.
		*FlagTextAddr = 0
	}

	// If there are no dynamic libraries needed, gcc disables dynamic linking.
	// Because of this, glibc's dynamic ELF loader occasionally (like in version 2.13)
	// assumes that a dynamic binary always refers to at least one dynamic library.
	// Rather than be a source of test cases for glibc, disable dynamic linking
	// the same way that gcc would.
	//
	// Exception: on OS X, programs such as Shark only work with dynamic
	// binaries, so leave it enabled on OS X (Mach-O) binaries.
	// Also leave it enabled on Solaris which doesn't support
	// statically linked binaries.
	if ctxt.BuildMode == BuildModeExe {
		if havedynamic == 0 && ctxt.HeadType != objabi.Hdarwin && ctxt.HeadType != objabi.Hsolaris {
			*FlagD = true
		}
	}

	if ctxt.LinkMode == LinkExternal && ctxt.Arch.Family == sys.PPC64 && buildcfg.GOOS != "aix" {
		toc := ctxt.loader.LookupOrCreateSym(".TOC.", 0)
		sb := ctxt.loader.MakeSymbolUpdater(toc)
		sb.SetType(sym.SDYNIMPORT)
	}

	// The Android Q linker started to complain about underalignment of the our TLS
	// section. We don't actually use the section on android, so don't
	// generate it.
	if buildcfg.GOOS != "android" {
		tlsg := ctxt.loader.LookupOrCreateSym("runtime.tlsg", 0)
		sb := ctxt.loader.MakeSymbolUpdater(tlsg)

		// runtime.tlsg is used for external linking on platforms that do not define
		// a variable to hold g in assembly (currently only intel).
		if sb.Type() == 0 {
			sb.SetType(sym.STLSBSS)
			sb.SetSize(int64(ctxt.Arch.PtrSize))
		} else if sb.Type() != sym.SDYNIMPORT {
			Errorf("runtime declared tlsg variable %v", sb.Type())
		}
		ctxt.loader.SetAttrReachable(tlsg, true)
		ctxt.Tlsg = tlsg
	}

	var moduledata loader.Sym
	var mdsb *loader.SymbolBuilder
	if ctxt.BuildMode == BuildModePlugin {
		moduledata = ctxt.loader.LookupOrCreateSym("local.pluginmoduledata", 0)
		mdsb = ctxt.loader.MakeSymbolUpdater(moduledata)
		ctxt.loader.SetAttrLocal(moduledata, true)
	} else {
		moduledata = ctxt.loader.LookupOrCreateSym("runtime.firstmoduledata", 0)
		mdsb = ctxt.loader.MakeSymbolUpdater(moduledata)
	}
	if mdsb.Type() != 0 && mdsb.Type() != sym.SDYNIMPORT {
		// If the module (toolchain-speak for "executable or shared
		// library") we are linking contains the runtime package, it
		// will define the runtime.firstmoduledata symbol and we
		// truncate it back to 0 bytes so we can define its entire
		// contents in symtab.go:symtab().
		mdsb.SetSize(0)

		// In addition, on ARM, the runtime depends on the linker
		// recording the value of GOARM.
		if ctxt.Arch.Family == sys.ARM {
			goarm := ctxt.loader.LookupOrCreateSym("runtime.goarm", 0)
			sb := ctxt.loader.MakeSymbolUpdater(goarm)
			sb.SetType(sym.SNOPTRDATA)
			sb.SetSize(0)
			sb.AddUint8(uint8(buildcfg.GOARM.Version))

			goarmsoftfp := ctxt.loader.LookupOrCreateSym("runtime.goarmsoftfp", 0)
			sb2 := ctxt.loader.MakeSymbolUpdater(goarmsoftfp)
			sb2.SetType(sym.SNOPTRDATA)
			sb2.SetSize(0)
			if buildcfg.GOARM.SoftFloat {
				sb2.AddUint8(1)
			} else {
				sb2.AddUint8(0)
			}
		}

		// Set runtime.disableMemoryProfiling bool if
		// runtime.memProfileInternal is not retained in the binary after
		// deadcode (and we're not dynamically linking).
		memProfile := ctxt.loader.Lookup("runtime.memProfileInternal", abiInternalVer)
		if memProfile != 0 && !ctxt.loader.AttrReachable(memProfile) && !ctxt.DynlinkingGo() {
			memProfSym := ctxt.loader.LookupOrCreateSym("runtime.disableMemoryProfiling", 0)
			sb := ctxt.loader.MakeSymbolUpdater(memProfSym)
			sb.SetType(sym.SNOPTRDATA)
			sb.SetSize(0)
			sb.AddUint8(1) // true bool
		}
	} else {
		// If OTOH the module does not contain the runtime package,
		// create a local symbol for the moduledata.
		moduledata = ctxt.loader.LookupOrCreateSym("local.moduledata", 0)
		mdsb = ctxt.loader.MakeSymbolUpdater(moduledata)
		ctxt.loader.SetAttrLocal(moduledata, true)
	}
	// In all cases way we mark the moduledata as noptrdata to hide it from
	// the GC.
	mdsb.SetType(sym.SNOPTRDATA)
	ctxt.loader.SetAttrReachable(moduledata, true)
	ctxt.Moduledata = moduledata

	if ctxt.Arch == sys.Arch386 && ctxt.HeadType != objabi.Hwindows {
		if (ctxt.BuildMode == BuildModeCArchive && ctxt.IsELF) || ctxt.BuildMode == BuildModeCShared || ctxt.BuildMode == BuildModePIE || ctxt.DynlinkingGo() {
			got := ctxt.loader.LookupOrCreateSym("_GLOBAL_OFFSET_TABLE_", 0)
			sb := ctxt.loader.MakeSymbolUpdater(got)
			sb.SetType(sym.SDYNIMPORT)
			ctxt.loader.SetAttrReachable(got, true)
		}
	}

	// DWARF-gen and other phases require that the unit Textp slices
	// be populated, so that it can walk the functions in each unit.
	// Call into the loader to do this (requires that we collect the
	// set of internal libraries first). NB: might be simpler if we
	// moved isRuntimeDepPkg to cmd/internal and then did the test in
	// loader.AssignTextSymbolOrder.
	ctxt.Library = postorder(ctxt.Library)
	intlibs := []bool{}
	for _, lib := range ctxt.Library {
		intlibs = append(intlibs, isRuntimeDepPkg(lib.Pkg))
	}
	ctxt.Textp = ctxt.loader.AssignTextSymbolOrder(ctxt.Library, intlibs, ctxt.Textp)
}

// mangleTypeSym shortens the names of symbols that represent Go types
// if they are visible in the symbol table.
//
// As the names of these symbols are derived from the string of
// the type, they can run to many kilobytes long. So we shorten
// them using a SHA-1 when the name appears in the final binary.
// This also removes characters that upset external linkers.
//
// These are the symbols that begin with the prefix 'type.' and
// contain run-time type information used by the runtime and reflect
// packages. All Go binaries contain these symbols, but only
// those programs loaded dynamically in multiple parts need these
// symbols to have entries in the symbol table.
func (ctxt *Link) mangleTypeSym() {
	if ctxt.BuildMode != BuildModeShared && !ctxt.linkShared && ctxt.BuildMode != BuildModePlugin && !ctxt.CanUsePlugins() {
		return
	}

	ldr := ctxt.loader
	for s := loader.Sym(1); s < loader.Sym(ldr.NSym()); s++ {
		if !ldr.AttrReachable(s) && !ctxt.linkShared {
			// If -linkshared, the gc mask generation code may need to reach
			// out to the shared library for the type descriptor's data, even
			// the type descriptor itself is not actually needed at run time
			// (therefore not reachable). We still need to mangle its name,
			// so it is consistent with the one stored in the shared library.
			continue
		}
		name := ldr.SymName(s)
		newName := typeSymbolMangle(name)
		if newName != name {
			ldr.SetSymExtname(s, newName)

			// When linking against a shared library, the Go object file may
			// have reference to the original symbol name whereas the shared
			// library provides a symbol with the mangled name. We need to
			// copy the payload of mangled to original.
			// XXX maybe there is a better way to do this.
			dup := ldr.Lookup(newName, ldr.SymVersion(s))
			if dup != 0 {
				st := ldr.SymType(s)
				dt := ldr.SymType(dup)
				if st == sym.Sxxx && dt != sym.Sxxx {
					ldr.CopySym(dup, s)
				}
			}
		}
	}
}

// typeSymbolMangle mangles the given symbol name into something shorter.
//
// Keep the type:. prefix, which parts of the linker (like the
// DWARF generator) know means the symbol is not decodable.
// Leave type:runtime. symbols alone, because other parts of
// the linker manipulates them.
func typeSymbolMangle(name string) string {
	isType := strings.HasPrefix(name, "type:")
	if !isType && !strings.Contains(name, "@") {
		// Issue 58800: instantiated symbols may include a type name, which may contain "@"
		return name
	}
	if strings.HasPrefix(name, "type:runtime.") {
		return name
	}
	if strings.HasPrefix(name, "go:string.") {
		// String symbols will be grouped to a single go:string.* symbol.
		// No need to mangle individual symbol names.
		return name
	}
	if len(name) <= 14 && !strings.Contains(name, "@") { // Issue 19529
		return name
	}
	if isType {
		hb := hash.Sum20([]byte(name[5:]))
		prefix := "type:"
		if name[5] == '.' {
			prefix = "type:."
		}
		return prefix + base64.StdEncoding.EncodeToString(hb[:6])
	}
	// instantiated symbol, replace type name in []
	i := strings.IndexByte(name, '[')
	j := strings.LastIndexByte(name, ']')
	if j == -1 || j <= i {
		j = len(name)
	}
	hb := hash.Sum20([]byte(name[i+1 : j]))
	return name[:i+1] + base64.StdEncoding.EncodeToString(hb[:6]) + name[j:]
}

/*
 * look for the next file in an archive.
 * adapted from libmach.
 */
func nextar(bp *bio.Reader, off int64, a *ArHdr) int64 {
	if off&1 != 0 {
		off++
	}
	bp.MustSeek(off, 0)
	var buf [SAR_HDR]byte
	if n, err := io.ReadFull(bp, buf[:]); err != nil {
		if n == 0 && err != io.EOF {
			return -1
		}
		return 0
	}

	a.name = artrim(buf[0:16])
	a.date = artrim(buf[16:28])
	a.uid = artrim(buf[28:34])
	a.gid = artrim(buf[34:40])
	a.mode = artrim(buf[40:48])
	a.size = artrim(buf[48:58])
	a.fmag = artrim(buf[58:60])

	arsize := atolwhex(a.size)
	if arsize&1 != 0 {
		arsize++
	}
	return arsize + SAR_HDR
}

func loadobjfile(ctxt *Link, lib *sym.Library) {
	pkg := objabi.PathToPrefix(lib.Pkg)

	if ctxt.Debugvlog > 1 {
		ctxt.Logf("ldobj: %s (%s)\n", lib.File, pkg)
	}
	f, err := bio.Open(lib.File)
	if err != nil {
		Exitf("cannot open file %s: %v", lib.File, err)
	}
	defer f.Close()
	defer func() {
		if pkg == "main" && !lib.Main {
			Exitf("%s: not package main", lib.File)
		}
	}()

	for i := 0; i < len(ARMAG); i++ {
		if c, err := f.ReadByte(); err == nil && c == ARMAG[i] {
			continue
		}

		/* load it as a regular file */
		l := f.MustSeek(0, 2)
		f.MustSeek(0, 0)
		ldobj(ctxt, f, lib, l, lib.File, lib.File)
		return
	}

	/*
	 * load all the object files from the archive now.
	 * this gives us sequential file access and keeps us
	 * from needing to come back later to pick up more
	 * objects.  it breaks the usual C archive model, but
	 * this is Go, not C.  the common case in Go is that
	 * we need to load all the objects, and then we throw away
	 * the individual symbols that are unused.
	 *
	 * loading every object will also make it possible to
	 * load foreign objects not referenced by __.PKGDEF.
	 */
	var arhdr ArHdr
	off := f.Offset()
	for {
		l := nextar(f, off, &arhdr)
		if l == 0 {
			break
		}
		if l < 0 {
			Exitf("%s: malformed archive", lib.File)
		}
		off += l

		// __.PKGDEF isn't a real Go object file, and it's
		// absent in -linkobj builds anyway. Skipping it
		// ensures consistency between -linkobj and normal
		// build modes.
		if arhdr.name == pkgdef {
			continue
		}

		if arhdr.name == "dynimportfail" {
			dynimportfail = append(dynimportfail, lib.Pkg)
		}
		if arhdr.name == "preferlinkext" {
			// Ignore this directive if -linkmode has been
			// set explicitly.
			if ctxt.LinkMode == LinkAuto {
				preferlinkext = append(preferlinkext, lib.Pkg)
			}
		}

		// Skip other special (non-object-file) sections that
		// build tools may have added. Such sections must have
		// short names so that the suffix is not truncated.
		if len(arhdr.name) < 16 {
			if ext := filepath.Ext(arhdr.name); ext != ".o" && ext != ".syso" {
				continue
			}
		}

		pname := fmt.Sprintf("%s(%s)", lib.File, arhdr.name)
		l = atolwhex(arhdr.size)
		ldobj(ctxt, f, lib, l, pname, lib.File)
	}
}

type Hostobj struct {
	ld     func(*Link, *bio.Reader, string, int64, string)
	pkg    string
	pn     string
	file   string
	off    int64
	length int64
}

var hostobj []Hostobj

// These packages can use internal linking mode.
// Others trigger external mode.
var internalpkg = []string{
	"crypto/internal/boring",
	"crypto/internal/boring/syso",
	"crypto/x509",
	"net",
	"os/user",
	"runtime/cgo",
	"runtime/race",
	"runtime/race/internal/amd64v1",
	"runtime/race/internal/amd64v3",
	"runtime/msan",
	"runtime/asan",
}

func ldhostobj(ld func(*Link, *bio.Reader, string, int64, string), headType objabi.HeadType, f *bio.Reader, pkg string, length int64, pn string, file string) *Hostobj {
	isinternal := false
	for _, intpkg := range internalpkg {
		if pkg == intpkg {
			isinternal = true
			break
		}
	}

	// DragonFly declares errno with __thread, which results in a symbol
	// type of R_386_TLS_GD or R_X86_64_TLSGD. The Go linker does not
	// currently know how to handle TLS relocations, hence we have to
	// force external linking for any libraries that link in code that
	// uses errno. This can be removed if the Go linker ever supports
	// these relocation types.
	if headType == objabi.Hdragonfly {
		if pkg == "net" || pkg == "os/user" {
			isinternal = false
		}
	}

	if !isinternal {
		externalobj = true
	}

	hostobj = append(hostobj, Hostobj{})
	h := &hostobj[len(hostobj)-1]
	h.ld = ld
	h.pkg = pkg
	h.pn = pn
	h.file = file
	h.off = f.Offset()
	h.length = length
	return h
}

func hostobjs(ctxt *Link) {
	if ctxt.LinkMode != LinkInternal {
		return
	}
	var h *Hostobj

	for i := 0; i < len(hostobj); i++ {
		h = &hostobj[i]
		f, err := bio.Open(h.file)
		if err != nil {
			Exitf("cannot reopen %s: %v", h.pn, err)
		}
		f.MustSeek(h.off, 0)
		if h.ld == nil {
			Errorf("%s: unrecognized object file format", h.pn)
			continue
		}
		h.ld(ctxt, f, h.pkg, h.length, h.pn)
		if *flagCaptureHostObjs != "" {
			captureHostObj(h)
		}
		f.Close()
	}
}

func hostlinksetup(ctxt *Link) {
	if ctxt.LinkMode != LinkExternal {
		return
	}

	// For external link, record that we need to tell the external linker -s,
	// and turn off -s internally: the external linker needs the symbol
	// information for its final link.
	debug_s = *FlagS
	*FlagS = false

	// create temporary directory and arrange cleanup
	if *flagTmpdir == "" {
		dir, err := os.MkdirTemp("", "go-link-")
		if err != nil {
			log.Fatal(err)
		}
		*flagTmpdir = dir
		ownTmpDir = true
		AtExit(func() {
			os.RemoveAll(*flagTmpdir)
		})
	}

	// change our output to temporary object file
	if err := ctxt.Out.Close(); err != nil {
		Exitf("error closing output file")
	}
	mayberemoveoutfile()

	p := filepath.Join(*flagTmpdir, "go.o")
	if err := ctxt.Out.Open(p); err != nil {
		Exitf("cannot create %s: %v", p, err)
	}
}

// cleanTimeStamps resets the timestamps for the specified list of
// existing files to the Unix epoch (1970-01-01 00:00:00 +0000 UTC).
// We take this step in order to help preserve reproducible builds;
// this seems to be primarily needed for external linking on Darwin
// with later versions of xcode, which (unfortunately) seem to want to
// incorporate object file times into the final output file's build
// ID. See issue 64947 for the unpleasant details.
func cleanTimeStamps(files []string) {
	epocht := time.Unix(0, 0)
	for _, f := range files {
		if err := os.Chtimes(f, epocht, epocht); err != nil {
			Exitf("cannot chtimes %s: %v", f, err)
		}
	}
}

// hostobjCopy creates a copy of the object files in hostobj in a
// temporary directory.
func (ctxt *Link) hostobjCopy() (paths []string) {
	var wg sync.WaitGroup
	sema := make(chan struct{}, runtime.NumCPU()) // limit open file descriptors
	for i, h := range hostobj {
		h := h
		dst := filepath.Join(*flagTmpdir, fmt.Sprintf("%06d.o", i))
		paths = append(paths, dst)
		if ctxt.Debugvlog != 0 {
			ctxt.Logf("host obj copy: %s from pkg %s -> %s\n", h.pn, h.pkg, dst)
		}

		wg.Add(1)
		go func() {
			sema <- struct{}{}
			defer func() {
				<-sema
				wg.Done()
			}()
			f, err := os.Open(h.file)
			if err != nil {
				Exitf("cannot reopen %s: %v", h.pn, err)
			}
			defer f.Close()
			if _, err := f.Seek(h.off, 0); err != nil {
				Exitf("cannot seek %s: %v", h.pn, err)
			}

			w, err := os.Create(dst)
			if err != nil {
				Exitf("cannot create %s: %v", dst, err)
			}
			if _, err := io.CopyN(w, f, h.length); err != nil {
				Exitf("cannot write %s: %v", dst, err)
			}
			if err := w.Close(); err != nil {
				Exitf("cannot close %s: %v", dst, err)
			}
		}()
	}
	wg.Wait()
	return paths
}

// writeGDBLinkerScript creates gcc linker script file in temp
// directory. writeGDBLinkerScript returns created file path.
// The script is used to work around gcc bug
// (see https://golang.org/issue/20183 for details).
func writeGDBLinkerScript() string {
	name := "fix_debug_gdb_scripts.ld"
	path := filepath.Join(*flagTmpdir, name)
	src := `SECTIONS
{
  .debug_gdb_scripts BLOCK(__section_alignment__) (NOLOAD) :
  {
    *(.debug_gdb_scripts)
  }
}
INSERT AFTER .debug_types;
`
	err := os.WriteFile(path, []byte(src), 0666)
	if err != nil {
		Errorf("WriteFile %s failed: %v", name, err)
	}
	return path
}

type machoUpdateFunc func(ctxt *Link, exef *os.File, exem *macho.File, outexe string) error

// archive builds a .a archive from the hostobj object files.
func (ctxt *Link) archive() {
	if ctxt.BuildMode != BuildModeCArchive {
		return
	}

	exitIfErrors()

	if *flagExtar == "" {
		const printProgName = "--print-prog-name=ar"
		cc := ctxt.extld()
		*flagExtar = "ar"
		if linkerFlagSupported(ctxt.Arch, cc[0], "", printProgName) {
			*flagExtar = ctxt.findExtLinkTool("ar")
		}
	}

	mayberemoveoutfile()

	// Force the buffer to flush here so that external
	// tools will see a complete file.
	if err := ctxt.Out.Close(); err != nil {
		Exitf("error closing %v", *flagOutfile)
	}

	argv := []string{*flagExtar, "-q", "-c", "-s"}
	if ctxt.HeadType == objabi.Haix {
		argv = append(argv, "-X64")
	}
	godotopath := filepath.Join(*flagTmpdir, "go.o")
	cleanTimeStamps([]string{godotopath})
	hostObjCopyPaths := ctxt.hostobjCopy()
	cleanTimeStamps(hostObjCopyPaths)

	argv = append(argv, *flagOutfile)
	argv = append(argv, godotopath)
	argv = append(argv, hostObjCopyPaths...)

	if ctxt.Debugvlog != 0 {
		ctxt.Logf("archive: %s\n", strings.Join(argv, " "))
	}

	// If supported, use syscall.Exec() to invoke the archive command,
	// which should be the final remaining step needed for the link.
	// This will reduce peak RSS for the link (and speed up linking of
	// large applications), since when the archive command runs we
	// won't be holding onto all of the linker's live memory.
	if syscallExecSupported && !ownTmpDir {
		runAtExitFuncs()
		ctxt.execArchive(argv)
		panic("should not get here")
	}

	// Otherwise invoke 'ar' in the usual way (fork + exec).
	if out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput(); err != nil {
		Exitf("running %s failed: %v\n%s", argv[0], err, out)
	}
}

func (ctxt *Link) hostlink() {
	if ctxt.LinkMode != LinkExternal || nerrors > 0 {
		return
	}
	if ctxt.BuildMode == BuildModeCArchive {
		return
	}

	var argv []string
	argv = append(argv, ctxt.extld()...)
	argv = append(argv, hostlinkArchArgs(ctxt.Arch)...)

	if *FlagS || debug_s {
		if ctxt.HeadType == objabi.Hdarwin {
			// Recent versions of macOS print
			//	ld: warning: option -s is obsolete and being ignored
			// so do not pass any arguments (but we strip symbols below).
		} else {
			argv = append(argv, "-s")
		}
	}

	// On darwin, whether to combine DWARF into executable.
	// Only macOS supports unmapped segments such as our __DWARF segment.
	combineDwarf := ctxt.IsDarwin() && !*FlagW && machoPlatform == PLATFORM_MACOS

	switch ctxt.HeadType {
	case objabi.Hdarwin:
		if combineDwarf {
			// Leave room for DWARF combining.
			// -headerpad is incompatible with -fembed-bitcode.
			argv = append(argv, "-Wl,-headerpad,1144")
		}
		if ctxt.DynlinkingGo() && buildcfg.GOOS != "ios" {
			// -flat_namespace is deprecated on iOS.
			// It is useful for supporting plugins. We don't support plugins on iOS.
			// -flat_namespace may cause the dynamic linker to hang at forkExec when
			// resolving a lazy binding. See issue 38824.
			// Force eager resolution to work around.
			argv = append(argv, "-Wl,-flat_namespace", "-Wl,-bind_at_load")
		}
		if !combineDwarf {
			argv = append(argv, "-Wl,-S") // suppress STAB (symbolic debugging) symbols
			if debug_s {
				// We are generating a binary with symbol table suppressed.
				// Suppress local symbols. We need to keep dynamically exported
				// and referenced symbols so the dynamic linker can resolve them.
				argv = append(argv, "-Wl,-x")
			}
		}
		if *flagHostBuildid == "none" {
			argv = append(argv, "-Wl,-no_uuid")
		}
	case objabi.Hopenbsd:
		argv = append(argv, "-pthread")
		if ctxt.BuildMode != BuildModePIE {
			argv = append(argv, "-Wl,-nopie")
		}
		if linkerFlagSupported(ctxt.Arch, argv[0], "", "-Wl,-z,nobtcfi") {
			// -Wl,-z,nobtcfi is only supported on OpenBSD 7.4+, remove guard
			// when OpenBSD 7.5 is released and 7.3 is no longer supported.
			argv = append(argv, "-Wl,-z,nobtcfi")
		}
		if ctxt.Arch.InFamily(sys.ARM64) {
			// Disable execute-only on openbsd/arm64 - the Go arm64 assembler
			// currently stores constants in the text section rather than in rodata.
			// See issue #59615.
			argv = append(argv, "-Wl,--no-execute-only")
		}
	case objabi.Hwindows:
		if windowsgui {
			argv = append(argv, "-mwindows")
		} else {
			argv = append(argv, "-mconsole")
		}
		// Mark as having awareness of terminal services, to avoid
		// ancient compatibility hacks.
		argv = append(argv, "-Wl,--tsaware")

		// Enable DEP
		argv = append(argv, "-Wl,--nxcompat")

		argv = append(argv, fmt.Sprintf("-Wl,--major-os-version=%d", PeMinimumTargetMajorVersion))
		argv = append(argv, fmt.Sprintf("-Wl,--minor-os-version=%d", PeMinimumTargetMinorVersion))
		argv = append(argv, fmt.Sprintf("-Wl,--major-subsystem-version=%d", PeMinimumTargetMajorVersion))
		argv = append(argv, fmt.Sprintf("-Wl,--minor-subsystem-version=%d", PeMinimumTargetMinorVersion))
	case objabi.Haix:
		argv = append(argv, "-pthread")
		// prevent ld to reorder .text functions to keep the same
		// first/last functions for moduledata.
		argv = append(argv, "-Wl,-bnoobjreorder")
		// mcmodel=large is needed for every gcc generated files, but
		// ld still need -bbigtoc in order to allow larger TOC.
		argv = append(argv, "-mcmodel=large")
		argv = append(argv, "-Wl,-bbigtoc")
	}

	// On PPC64, verify the external toolchain supports Power10. This is needed when
	// PC relative relocations might be generated by Go. Only targets compiling ELF
	// binaries might generate these relocations.
	if ctxt.IsPPC64() && ctxt.IsElf() && buildcfg.GOPPC64 >= 10 {
		if !linkerFlagSupported(ctxt.Arch, argv[0], "", "-mcpu=power10") {
			Exitf("The external toolchain does not support -mcpu=power10. " +
				" This is required to externally link GOPPC64 >= power10")
		}
	}

	// Enable/disable ASLR on Windows.
	addASLRargs := func(argv []string, val bool) []string {
		// Old/ancient versions of GCC support "--dynamicbase" and
		// "--high-entropy-va" but don't enable it by default. In
		// addition, they don't accept "--disable-dynamicbase" or
		// "--no-dynamicbase", so the only way to disable ASLR is to
		// not pass any flags at all.
		//
		// More modern versions of GCC (and also clang) enable ASLR
		// by default. With these compilers, however you can turn it
		// off if you want using "--disable-dynamicbase" or
		// "--no-dynamicbase".
		//
		// The strategy below is to try using "--disable-dynamicbase";
		// if this succeeds, then assume we're working with more
		// modern compilers and act accordingly. If it fails, assume
		// an ancient compiler with ancient defaults.
		var dbopt string
		var heopt string
		dbon := "--dynamicbase"
		heon := "--high-entropy-va"
		dboff := "--disable-dynamicbase"
		heoff := "--disable-high-entropy-va"
		if val {
			dbopt = dbon
			heopt = heon
		} else {
			// Test to see whether "--disable-dynamicbase" works.
			newer := linkerFlagSupported(ctxt.Arch, argv[0], "", "-Wl,"+dboff)
			if newer {
				// Newer compiler, which supports both on/off options.
				dbopt = dboff
				heopt = heoff
			} else {
				// older toolchain: we have to say nothing in order to
				// get a no-ASLR binary.
				dbopt = ""
				heopt = ""
			}
		}
		if dbopt != "" {
			argv = append(argv, "-Wl,"+dbopt)
		}
		// enable high-entropy ASLR on 64-bit.
		if ctxt.Arch.PtrSize >= 8 && heopt != "" {
			argv = append(argv, "-Wl,"+heopt)
		}
		return argv
	}

	switch ctxt.BuildMode {
	case BuildModeExe:
		if ctxt.HeadType == objabi.Hdarwin {
			if machoPlatform == PLATFORM_MACOS && ctxt.IsAMD64() {
				argv = append(argv, "-Wl,-no_pie")
			}
		}
		if *flagRace && ctxt.HeadType == objabi.Hwindows {
			// Current windows/amd64 race detector tsan support
			// library can't handle PIE mode (see #53539 for more details).
			// For now, explicitly disable PIE (since some compilers
			// default to it) if -race is in effect.
			argv = addASLRargs(argv, false)
		}
	case BuildModePIE:
		switch ctxt.HeadType {
		case objabi.Hdarwin, objabi.Haix:
		case objabi.Hwindows:
			if *flagAslr && *flagRace {
				// Current windows/amd64 race detector tsan support
				// library can't handle PIE mode (see #53539 for more details).
				// Disable alsr if -race in effect.
				*flagAslr = false
			}
			argv = addASLRargs(argv, *flagAslr)
		default:
			// ELF.
			if ctxt.UseRelro() {
				argv = append(argv, "-Wl,-z,relro")
			}
			argv = append(argv, "-pie")
		}
	case BuildModeCShared:
		if ctxt.HeadType == objabi.Hdarwin {
			argv = append(argv, "-dynamiclib")
		} else {
			if ctxt.UseRelro() {
				argv = append(argv, "-Wl,-z,relro")
			}
			argv = append(argv, "-shared")
			if ctxt.HeadType == objabi.Hwindows {
				argv = addASLRargs(argv, *flagAslr)
			} else {
				// Pass -z nodelete to mark the shared library as
				// non-closeable: a dlclose will do nothing.
				argv = append(argv, "-Wl,-z,nodelete")
				// Only pass Bsymbolic on non-Windows.
				argv = append(argv, "-Wl,-Bsymbolic")
			}
		}
	case BuildModeShared:
		if ctxt.UseRelro() {
			argv = append(argv, "-Wl,-z,relro")
		}
		argv = append(argv, "-shared")
	case BuildModePlugin:
		if ctxt.HeadType == objabi.Hdarwin {
			argv = append(argv, "-dynamiclib")
		} else {
			if ctxt.UseRelro() {
				argv = append(argv, "-Wl,-z,relro")
			}
			argv = append(argv, "-shared")
		}
	}

	var altLinker string
	if ctxt.IsELF && (ctxt.DynlinkingGo() || *flagBindNow) {
		// For ELF targets, when producing dynamically linked Go code
		// or when immediate binding is explicitly requested,
		// we force all symbol resolution to be done at program startup
		// because lazy PLT resolution can use large amounts of stack at
		// times we cannot allow it to do so.
		argv = append(argv, "-Wl,-z,now")
	}

	if ctxt.IsELF && ctxt.DynlinkingGo() {
		// Do not let the host linker generate COPY relocations. These
		// can move symbols out of sections that rely on stable offsets
		// from the beginning of the section (like sym.STYPE).
		argv = append(argv, "-Wl,-z,nocopyreloc")

		if buildcfg.GOOS == "android" {
			// Use lld to avoid errors from default linker (issue #38838)
			altLinker = "lld"
		}

		if ctxt.Arch.InFamily(sys.ARM64) && buildcfg.GOOS == "linux" {
			// On ARM64, the GNU linker will fail with
			// -znocopyreloc if it thinks a COPY relocation is
			// required. Switch to gold.
			// https://sourceware.org/bugzilla/show_bug.cgi?id=19962
			// https://go.dev/issue/22040
			altLinker = "gold"

			// If gold is not installed, gcc will silently switch
			// back to ld.bfd. So we parse the version information
			// and provide a useful error if gold is missing.
			name, args := flagExtld[0], flagExtld[1:]
			args = append(args, "-fuse-ld=gold", "-Wl,--version")
			cmd := exec.Command(name, args...)
			if out, err := cmd.CombinedOutput(); err == nil {
				if !bytes.Contains(out, []byte("GNU gold")) {
					log.Fatalf("ARM64 external linker must be gold (issue #15696, 22040), but is not: %s", out)
				}
			}
		}
	}
	if ctxt.Arch.Family == sys.ARM64 && buildcfg.GOOS == "freebsd" {
		// Switch to ld.bfd on freebsd/arm64.
		altLinker = "bfd"

		// Provide a useful error if ld.bfd is missing.
		name, args := flagExtld[0], flagExtld[1:]
		args = append(args, "-fuse-ld=bfd", "-Wl,--version")
		cmd := exec.Command(name, args...)
		if out, err := cmd.CombinedOutput(); err == nil {
			if !bytes.Contains(out, []byte("GNU ld")) {
				log.Fatalf("ARM64 external linker must be ld.bfd (issue #35197), please install devel/binutils")
			}
		}
	}
	if altLinker != "" {
		argv = append(argv, "-fuse-ld="+altLinker)
	}

	if ctxt.IsELF && linkerFlagSupported(ctxt.Arch, argv[0], "", "-Wl,--build-id=0x1234567890abcdef") { // Solaris ld doesn't support --build-id.
		if len(buildinfo) > 0 {
			argv = append(argv, fmt.Sprintf("-Wl,--build-id=0x%x", buildinfo))
		} else if *flagHostBuildid == "none" {
			argv = append(argv, "-Wl,--build-id=none")
		}
	}

	// On Windows, given -o foo, GCC will append ".exe" to produce
	// "foo.exe".  We have decided that we want to honor the -o
	// option. To make this work, we append a '.' so that GCC
	// will decide that the file already has an extension. We
	// only want to do this when producing a Windows output file
	// on a Windows host.
	outopt := *flagOutfile
	if buildcfg.GOOS == "windows" && runtime.GOOS == "windows" && filepath.Ext(outopt) == "" {
		outopt += "."
	}
	argv = append(argv, "-o")
	argv = append(argv, outopt)

	if rpath.val != "" {
		argv = append(argv, fmt.Sprintf("-Wl,-rpath,%s", rpath.val))
	}

	if *flagInterpreter != "" {
		// Many linkers support both -I and the --dynamic-linker flags
		// to set the ELF interpreter, but lld only supports
		// --dynamic-linker so prefer that (ld on very old Solaris only
		// supports -I but that seems less important).
		argv = append(argv, fmt.Sprintf("-Wl,--dynamic-linker,%s", *flagInterpreter))
	}

	// Force global symbols to be exported for dlopen, etc.
	if ctxt.IsELF {
		if ctxt.DynlinkingGo() || ctxt.BuildMode == BuildModeCShared || !linkerFlagSupported(ctxt.Arch, argv[0], altLinker, "-Wl,--export-dynamic-symbol=main") {
			argv = append(argv, "-rdynamic")
		} else {
			var exports []string
			ctxt.loader.ForAllCgoExportDynamic(func(s loader.Sym) {
				exports = append(exports, "-Wl,--export-dynamic-symbol="+ctxt.loader.SymExtname(s))
			})
			sort.Strings(exports)
			argv = append(argv, exports...)
		}
	}
	if ctxt.HeadType == objabi.Haix {
		fileName := xcoffCreateExportFile(ctxt)
		argv = append(argv, "-Wl,-bE:"+fileName)
	}

	const unusedArguments = "-Qunused-arguments"
	if linkerFlagSupported(ctxt.Arch, argv[0], altLinker, unusedArguments) {
		argv = append(argv, unusedArguments)
	}

	if ctxt.IsWindows() {
		// Suppress generation of the PE file header timestamp,
		// so as to avoid spurious build ID differences between
		// linked binaries that are otherwise identical other than
		// the date/time they were linked.
		const noTimeStamp = "-Wl,--no-insert-timestamp"
		if linkerFlagSupported(ctxt.Arch, argv[0], altLinker, noTimeStamp) {
			argv = append(argv, noTimeStamp)
		}
	}

	const compressDWARF = "-Wl,--compress-debug-sections=zlib"
	if ctxt.compressDWARF && linkerFlagSupported(ctxt.Arch, argv[0], altLinker, compressDWARF) {
		argv = append(argv, compressDWARF)
	}

	hostObjCopyPaths := ctxt.hostobjCopy()
	cleanTimeStamps(hostObjCopyPaths)
	godotopath := filepath.Join(*flagTmpdir, "go.o")
	cleanTimeStamps([]string{godotopath})

	argv = append(argv, godotopath)
	argv = append(argv, hostObjCopyPaths...)
	if ctxt.HeadType == objabi.Haix {
		// We want to have C files after Go files to remove
		// trampolines csects made by ld.
		argv = append(argv, "-nostartfiles")
		argv = append(argv, "/lib/crt0_64.o")

		extld := ctxt.extld()
		name, args := extld[0], extld[1:]
		// Get starting files.
		getPathFile := func(file string) string {
			args := append(args, "-maix64", "--print-file-name="+file)
			out, err := exec.Command(name, args...).CombinedOutput()
			if err != nil {
				log.Fatalf("running %s failed: %v\n%s", extld, err, out)
			}
			return strings.Trim(string(out), "\n")
		}
		// Since GCC version 11, the 64-bit version of GCC starting files
		// are now suffixed by "_64". Even under "-maix64" multilib directory
		// "crtcxa.o" is 32-bit.
		crtcxa := getPathFile("crtcxa_64.o")
		if !filepath.IsAbs(crtcxa) {
			crtcxa = getPathFile("crtcxa.o")
		}
		crtdbase := getPathFile("crtdbase_64.o")
		if !filepath.IsAbs(crtdbase) {
			crtdbase = getPathFile("crtdbase.o")
		}
		argv = append(argv, crtcxa)
		argv = append(argv, crtdbase)
	}

	if ctxt.linkShared {
		seenDirs := make(map[string]bool)
		seenLibs := make(map[string]bool)
		addshlib := func(path string) {
			dir, base := filepath.Split(path)
			if !seenDirs[dir] {
				argv = append(argv, "-L"+dir)
				if !rpath.set {
					argv = append(argv, "-Wl,-rpath="+dir)
				}
				seenDirs[dir] = true
			}
			base = strings.TrimSuffix(base, ".so")
			base = strings.TrimPrefix(base, "lib")
			if !seenLibs[base] {
				argv = append(argv, "-l"+base)
				seenLibs[base] = true
			}
		}
		for _, shlib := range ctxt.Shlibs {
			addshlib(shlib.Path)
			for _, dep := range shlib.Deps {
				if dep == "" {
					continue
				}
				libpath := findshlib(ctxt, dep)
				if libpath != "" {
					addshlib(libpath)
				}
			}
		}
	}

	// clang, unlike GCC, passes -rdynamic to the linker
	// even when linking with -static, causing a linker
	// error when using GNU ld. So take out -rdynamic if
	// we added it. We do it in this order, rather than
	// only adding -rdynamic later, so that -extldflags
	// can override -rdynamic without using -static.
	// Similarly for -Wl,--dynamic-linker.
	checkStatic := func(arg string) {
		if ctxt.IsELF && arg == "-static" {
			for i := range argv {
				if argv[i] == "-rdynamic" || strings.HasPrefix(argv[i], "-Wl,--dynamic-linker,") {
					argv[i] = "-static"
				}
			}
		}
	}

	for _, p := range ldflag {
		argv = append(argv, p)
		checkStatic(p)
	}

	// When building a program with the default -buildmode=exe the
	// gc compiler generates code requires DT_TEXTREL in a
	// position independent executable (PIE). On systems where the
	// toolchain creates PIEs by default, and where DT_TEXTREL
	// does not work, the resulting programs will not run. See
	// issue #17847. To avoid this problem pass -no-pie to the
	// toolchain if it is supported.
	if ctxt.BuildMode == BuildModeExe && !ctxt.linkShared && !(ctxt.IsDarwin() && ctxt.IsARM64()) {
		// GCC uses -no-pie, clang uses -nopie.
		for _, nopie := range []string{"-no-pie", "-nopie"} {
			if linkerFlagSupported(ctxt.Arch, argv[0], altLinker, nopie) {
				argv = append(argv, nopie)
				break
			}
		}
	}

	for _, p := range flagExtldflags {
		argv = append(argv, p)
		checkStatic(p)
	}
	if ctxt.HeadType == objabi.Hwindows {
		// Determine which linker we're using. Add in the extldflags in
		// case used has specified "-fuse-ld=...".
		extld := ctxt.extld()
		name, args := extld[0], extld[1:]
		args = append(args, trimLinkerArgv(flagExtldflags)...)
		args = append(args, "-Wl,--version")
		cmd := exec.Command(name, args...)
		usingLLD := false
		if out, err := cmd.CombinedOutput(); err == nil {
			if bytes.Contains(out, []byte("LLD ")) {
				usingLLD = true
			}
		}

		// use gcc linker script to work around gcc bug
		// (see https://golang.org/issue/20183 for details).
		if !usingLLD {
			p := writeGDBLinkerScript()
			argv = append(argv, "-Wl,-T,"+p)
		}
		if *flagRace {
			if p := ctxt.findLibPath("libsynchronization.a"); p != "libsynchronization.a" {
				argv = append(argv, "-lsynchronization")
			}
		}
		// libmingw32 and libmingwex have some inter-dependencies,
		// so must use linker groups.
		argv = append(argv, "-Wl,--start-group", "-lmingwex", "-lmingw32", "-Wl,--end-group")
		argv = append(argv, peimporteddlls()...)
	}

	argv = ctxt.passLongArgsInResponseFile(argv, altLinker)

	if ctxt.Debugvlog != 0 {
		ctxt.Logf("host link:")
		for _, v := range argv {
			ctxt.Logf(" %q", v)
		}
		ctxt.Logf("\n")
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		Exitf("running %s failed: %v\n%s\n%s", argv[0], err, cmd, out)
	}

	// Filter out useless linker warnings caused by bugs outside Go.
	// See also cmd/go/internal/work/exec.go's gccld method.
	var save [][]byte
	var skipLines int
	for _, line := range bytes.SplitAfter(out, []byte("\n")) {
		// golang.org/issue/26073 - Apple Xcode bug
		if bytes.Contains(line, []byte("ld: warning: text-based stub file")) {
			continue
		}

		if skipLines > 0 {
			skipLines--
			continue
		}

		// Remove TOC overflow warning on AIX.
		if bytes.Contains(line, []byte("ld: 0711-783")) {
			skipLines = 2
			continue
		}

		save = append(save, line)
	}
	out = bytes.Join(save, nil)

	if len(out) > 0 {
		// always print external output even if the command is successful, so that we don't
		// swallow linker warnings (see https://golang.org/issue/17935).
		if ctxt.IsDarwin() && ctxt.IsAMD64() {
			const noPieWarning = "ld: warning: -no_pie is deprecated when targeting new OS versions\n"
			if i := bytes.Index(out, []byte(noPieWarning)); i >= 0 {
				// swallow -no_pie deprecation warning, issue 54482
				out = append(out[:i], out[i+len(noPieWarning):]...)
			}
		}
		if ctxt.IsDarwin() {
			const bindAtLoadWarning = "ld: warning: -bind_at_load is deprecated on macOS\n"
			if i := bytes.Index(out, []byte(bindAtLoadWarning)); i >= 0 {
				// -bind_at_load is deprecated with ld-prime, but needed for
				// correctness with older versions of ld64. Swallow the warning.
				// TODO: maybe pass -bind_at_load conditionally based on C
				// linker version.
				out = append(out[:i], out[i+len(bindAtLoadWarning):]...)
			}
		}
		ctxt.Logf("%s", out)
	}

	// Helper for updating a Macho binary in some way (shared between
	// dwarf combining and UUID update).
	updateMachoOutFile := func(op string, updateFunc machoUpdateFunc) {
		// For os.Rename to work reliably, must be in same directory as outfile.
		rewrittenOutput := *flagOutfile + "~"
		exef, err := os.Open(*flagOutfile)
		if err != nil {
			Exitf("%s: %s failed: %v", os.Args[0], op, err)
		}
		defer exef.Close()
		exem, err := macho.NewFile(exef)
		if err != nil {
			Exitf("%s: parsing Mach-O header failed: %v", os.
"""




```