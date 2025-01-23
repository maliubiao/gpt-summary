Response: The user wants to understand the functionality of the Go code snippet provided. The code is a part of the Go compiler, specifically the SSA generation phase.

Here's a plan to address the request:

1. **Identify the main purpose of the code:**  The code is responsible for converting the Go intermediate representation (IR) into Static Single Assignment (SSA) form.

2. **Break down the functionalities:**  List the key functions and data structures and describe their roles in the SSA generation process.

3. **Infer Go language features:** Based on the operations performed (e.g., handling defers, goroutines, type assertions), try to connect them to corresponding Go language features.

4. **Provide code examples:** If a Go language feature is identified, illustrate its usage with a simple Go code snippet and explain how the SSA generation might handle it (with hypothetical input and output).

5. **Analyze command-line parameters:**  Identify any code related to processing environment variables or flags that affect the SSA generation process.

6. **Highlight potential pitfalls:** Point out any common errors that users might make when dealing with the aspects of Go compilation that this code touches upon (if applicable).

7. **Summarize the functionality:**  Provide a concise summary of the code's overall purpose.

**Thinking through the code:**

* **`package ssagen`:** Clearly indicates this is the SSA generation package within the Go compiler.
* **Imports:** The imports suggest interaction with various compiler components (IR, types, ABI, SSA representation) and runtime elements.
* **Global variables (`ssaConfig`, `ssaCaches`, `ssaDump`, etc.):** These seem to control the SSA generation process, including debugging and configuration.
* **`InitEnv()` and `InitConfig()`:** These functions initialize the environment and configuration for SSA generation, potentially based on environment variables and compiler flags.
* **`buildssa(fn *ir.Func, worker int, isPgoHot bool) *ssa.Func`:** This function seems to be the core of the SSA generation for a given function.
* **`state` struct:**  This likely holds the context and state during the SSA conversion of a single function.
* **Methods on `state` (e.g., `stmtList`, `stmt`, `expr`, `assign`, `call`, `load`, `store`):** These methods likely implement the conversion of different Go language constructs into SSA form.
* **Handling of `defer`, `go`, type assertions, returns, etc.:**  The code includes logic for these language features, suggesting its role in their compilation.
* **Instrumentation (`instrumentMemory`, `instrumentEnterExit`):**  Indicates support for tools like race detectors and memory sanitizers.

**Potential Go features and their SSA representation:**

* **Function calls:**  `callResult`, `callDefer`, `callGo` suggest handling different types of function calls.
* **`defer`:** `openDeferInfo`, `emitOpenDeferInfo` suggest specific handling of deferred function calls.
* **`go` (goroutines):** The `callGo` function likely deals with the creation of new goroutines.
* **Type assertions:** `dottype`, `dynamicDottype` point to the implementation of type assertion logic.
* **Assignments:** `assign`, `assignWhichMayOverlap` handle different kinds of assignments.
* **Control flow (`if`, `for`, `goto`, `break`, `continue`):**  The code includes logic for translating these control flow statements into SSA blocks and edges.

**Command-line parameters:**

* `GOSSAFUNC`: Controls SSA dumping for specific functions.
* `GOSSADIR`: Specifies the directory for SSA dump files.
* `-N 0`:  Disables optimizations, affecting certain SSA generation decisions.
* `-race`: Enables race detector instrumentation.
* `-msan`: Enables memory sanitizer instrumentation.
* `-asan`: Enables address sanitizer instrumentation.

**Potential pitfalls:**

* Incorrectly interpreting SSA output without understanding the different phases.
* Misunderstanding the impact of optimization flags on the generated SSA.

Now, let's formulate the response based on this analysis.
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssagen

import (
	"bufio"
	"bytes"
	"fmt"
	"go/constant"
	"html"
	"internal/buildcfg"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"cmd/compile/internal/abi"
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/liveness"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/reflectdata"
	"cmd/compile/internal/rttype"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/staticdata"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/src"
	"cmd/internal/sys"

	rtabi "internal/abi"
)

var ssaConfig *ssa.Config
var ssaCaches []ssa.Cache

var ssaDump string     // early copy of $GOSSAFUNC; the func name to dump output for
var ssaDir string      // optional destination for ssa dump file
var ssaDumpStdout bool // whether to dump to stdout
var ssaDumpCFG string  // generate CFGs for these phases
const ssaDumpFile = "ssa.html"

// ssaDumpInlined holds all inlined functions when ssaDump contains a function name.
var ssaDumpInlined []*ir.Func

func DumpInline(fn *ir.Func) {
	if ssaDump != "" && ssaDump == ir.FuncName(fn) {
		ssaDumpInlined = append(ssaDumpInlined, fn)
	}
}

func InitEnv() {
	ssaDump = os.Getenv("GOSSAFUNC")
	ssaDir = os.Getenv("GOSSADIR")
	if ssaDump != "" {
		if strings.HasSuffix(ssaDump, "+") {
			ssaDump = ssaDump[:len(ssaDump)-1]
			ssaDumpStdout = true
		}
		spl := strings.Split(ssaDump, ":")
		if len(spl) > 1 {
			ssaDump = spl[0]
			ssaDumpCFG = spl[1]
		}
	}
}

func InitConfig() {
	types_ := ssa.NewTypes()

	if Arch.SoftFloat {
		softfloatInit()
	}

	// Generate a few pointer types that are uncommon in the frontend but common in the backend.
	// Caching is disabled in the backend, so generating these here avoids allocations.
	_ = types.NewPtr(types.Types[types.TINTER])                             // *interface{}
	_ = types.NewPtr(types.NewPtr(types.Types[types.TSTRING]))              // **string
	_ = types.NewPtr(types.NewSlice(types.Types[types.TINTER]))             // *[]interface{}
	_ = types.NewPtr(types.NewPtr(types.ByteType))                          // **byte
	_ = types.NewPtr(types.NewSlice(types.ByteType))                        // *[]byte
	_ = types.NewPtr(types.NewSlice(types.Types[types.TSTRING]))            // *[]string
	_ = types.NewPtr(types.NewPtr(types.NewPtr(types.Types[types.TUINT8]))) // ***uint8
	_ = types.NewPtr(types.Types[types.TINT16])                             // *int16
	_ = types.NewPtr(types.Types[types.TINT64])                             // *int64
	_ = types.NewPtr(types.ErrorType)                                       // *error
	if buildcfg.Experiment.SwissMap {
		_ = types.NewPtr(reflectdata.SwissMapType()) // *internal/runtime/maps.Map
	} else {
		_ = types.NewPtr(reflectdata.OldMapType()) // *runtime.hmap
	}
	_ = types.NewPtr(deferstruct()) // *runtime._defer
	types.NewPtrCacheEnabled = false
	ssaConfig = ssa.NewConfig(base.Ctxt.Arch.Name, *types_, base.Ctxt, base.Flag.N == 0, Arch.SoftFloat)
	ssaConfig.Race = base.Flag.Race
	ssaCaches = make([]ssa.Cache, base.Flag.LowerC)

	// Set up some runtime functions we'll need to call.
	ir.Syms.AssertE2I = typecheck.LookupRuntimeFunc("assertE2I")
	ir.Syms.AssertE2I2 = typecheck.LookupRuntimeFunc("assertE2I2")
	ir.Syms.CgoCheckMemmove = typecheck.LookupRuntimeFunc("cgoCheckMemmove")
	ir.Syms.CgoCheckPtrWrite = typecheck.LookupRuntimeFunc("cgoCheckPtrWrite")
	ir.Syms.CheckPtrAlignment = typecheck.LookupRuntimeFunc("checkptrAlignment")
	ir.Syms.Deferproc = typecheck.LookupRuntimeFunc("deferproc")
	ir.Syms.Deferprocat = typecheck.LookupRuntimeFunc("deferprocat")
	ir.Syms.DeferprocStack = typecheck.LookupRuntimeFunc("deferprocStack")
	ir.Syms.Deferreturn = typecheck.LookupRuntimeFunc("deferreturn")
	ir.Syms.Duffcopy = typecheck.LookupRuntimeFunc("duffcopy")
	ir.Syms.Duffzero = typecheck.LookupRuntimeFunc("duffzero")
	ir.Syms.GCWriteBarrier[0] = typecheck.LookupRuntimeFunc("gcWriteBarrier1")
	ir.Syms.GCWriteBarrier[1] = typecheck.LookupRuntimeFunc("gcWriteBarrier2")
	ir.Syms.GCWriteBarrier[2] = typecheck.LookupRuntimeFunc("gcWriteBarrier3")
	ir.Syms.GCWriteBarrier[3] = typecheck.LookupRuntimeFunc("gcWriteBarrier4")
	ir.Syms.GCWriteBarrier[4] = typecheck.LookupRuntimeFunc("gcWriteBarrier5")
	ir.Syms.GCWriteBarrier[5] = typecheck.LookupRuntimeFunc("gcWriteBarrier6")
	ir.Syms.GCWriteBarrier[6] = typecheck.LookupRuntimeFunc("gcWriteBarrier7")
	ir.Syms.GCWriteBarrier[7] = typecheck.LookupRuntimeFunc("gcWriteBarrier8")
	ir.Syms.Goschedguarded = typecheck.LookupRuntimeFunc("goschedguarded")
	ir.Syms.Growslice = typecheck.LookupRuntimeFunc("growslice")
	ir.Syms.InterfaceSwitch = typecheck.LookupRuntimeFunc("interfaceSwitch")
	ir.Syms.Memmove = typecheck.LookupRuntimeFunc("memmove")
	ir.Syms.Msanread = typecheck.LookupRuntimeFunc("msanread")
	ir.Syms.Msanwrite = typecheck.LookupRuntimeFunc("msanwrite")
	ir.Syms.Msanmove = typecheck.LookupRuntimeFunc("msanmove")
	ir.Syms.Asanread = typecheck.LookupRuntimeFunc("asanread")
	ir.Syms.Asanwrite = typecheck.LookupRuntimeFunc("asanwrite")
	ir.Syms.Newobject = typecheck.LookupRuntimeFunc("newobject")
	ir.Syms.Newproc = typecheck.LookupRuntimeFunc("newproc")
	ir.Syms.Panicdivide = typecheck.LookupRuntimeFunc("panicdivide")
	ir.Syms.PanicdottypeE = typecheck.LookupRuntimeFunc("panicdottypeE")
	ir.Syms.PanicdottypeI = typecheck.LookupRuntimeFunc("panicdottypeI")
	ir.Syms.Panicnildottype = typecheck.LookupRuntimeFunc("panicnildottype")
	ir.Syms.Panicoverflow = typecheck.LookupRuntimeFunc("panicoverflow")
	ir.Syms.Panicshift = typecheck.LookupRuntimeFunc("panicshift")
	ir.Syms.Racefuncenter = typecheck.LookupRuntimeFunc("racefuncenter")
	ir.Syms.Racefuncexit = typecheck.LookupRuntimeFunc("racefuncexit")
	ir.Syms.Raceread = typecheck.LookupRuntimeFunc("raceread")
	ir.Syms.Racereadrange = typecheck.LookupRuntimeFunc("racereadrange")
	ir.Syms.Racewrite = typecheck.LookupRuntimeFunc("racewrite")
	ir.Syms.Racewriterange = typecheck.LookupRuntimeFunc("racewriterange")
	ir.Syms.TypeAssert = typecheck.LookupRuntimeFunc("typeAssert")
	ir.Syms.WBZero = typecheck.LookupRuntimeFunc("wbZero")
	ir.Syms.WBMove = typecheck.LookupRuntimeFunc("wbMove")
	ir.Syms.X86HasPOPCNT = typecheck.LookupRuntimeVar("x86HasPOPCNT")         // bool
	ir.Syms.X86HasSSE41 = typecheck.LookupRuntimeVar("x86HasSSE41")           // bool
	ir.Syms.X86HasFMA = typecheck.LookupRuntimeVar("x86HasFMA")               // bool
	ir.Syms.ARMHasVFPv4 = typecheck.LookupRuntimeVar("armHasVFPv4")           // bool
	ir.Syms.ARM64HasATOMICS = typecheck.LookupRuntimeVar("arm64HasATOMICS")   // bool
	ir.Syms.Loong64HasLAMCAS = typecheck.LookupRuntimeVar("loong64HasLAMCAS") // bool
	ir.Syms.Loong64HasLAM_BH = typecheck.LookupRuntimeVar("loong64HasLAM_BH") // bool
	ir.Syms.Loong64HasLSX = typecheck.LookupRuntimeVar("loong64HasLSX")       // bool
	ir.Syms.Staticuint64s = typecheck.LookupRuntimeVar("staticuint64s")
	ir.Syms.Typedmemmove = typecheck.LookupRuntimeFunc("typedmemmove")
	ir.Syms.Udiv = typecheck.LookupRuntimeVar("udiv")                 // asm func with special ABI
	ir.Syms.WriteBarrier = typecheck.LookupRuntimeVar("writeBarrier") // struct { bool; ... }
	ir.Syms.Zerobase = typecheck.LookupRuntimeVar("zerobase")

	if Arch.LinkArch.Family == sys.Wasm {
		BoundsCheckFunc[ssa.BoundsIndex] = typecheck.LookupRuntimeFunc("goPanicIndex")
		BoundsCheckFunc[ssa.BoundsIndexU] = typecheck.LookupRuntimeFunc("goPanicIndexU")
		BoundsCheckFunc[ssa.BoundsSliceAlen] = typecheck.LookupRuntimeFunc("goPanicSliceAlen")
		BoundsCheckFunc[ssa.BoundsSliceAlenU] = typecheck.LookupRuntimeFunc("goPanicSliceAlenU")
		BoundsCheckFunc[ssa.BoundsSliceAcap] = typecheck.LookupRuntimeFunc("goPanicSliceAcap")
		BoundsCheckFunc[ssa.BoundsSliceAcapU] = typecheck.LookupRuntimeFunc("goPanicSliceAcapU")
		BoundsCheckFunc[ssa.BoundsSliceB] = typecheck.LookupRuntimeFunc("goPanicSliceB")
		BoundsCheckFunc[ssa.BoundsSliceBU] = typecheck.LookupRuntimeFunc("goPanicSliceBU")
		BoundsCheckFunc[ssa.BoundsSlice3Alen] = typecheck.LookupRuntimeFunc("goPanicSlice3Alen")
		BoundsCheckFunc[ssa.BoundsSlice3AlenU] = typecheck.LookupRuntimeFunc("goPanicSlice3AlenU")
		BoundsCheckFunc[ssa.BoundsSlice3Acap] = typecheck.LookupRuntimeFunc("goPanicSlice3Acap")
		BoundsCheckFunc[ssa.BoundsSlice3AcapU] = typecheck.LookupRuntimeFunc("goPanicSlice3AcapU")
		BoundsCheckFunc[ssa.BoundsSlice3B] = typecheck.LookupRuntimeFunc("goPanicSlice3B")
		BoundsCheckFunc[ssa.BoundsSlice3BU] = typecheck.LookupRuntimeFunc("goPanicSlice3BU")
		BoundsCheckFunc[ssa.BoundsSlice3C] = typecheck.LookupRuntimeFunc("goPanicSlice3C")
		BoundsCheckFunc[ssa.BoundsSlice3CU] = typecheck.LookupRuntimeFunc("goPanicSlice3CU")
		BoundsCheckFunc[ssa.BoundsConvert] = typecheck.LookupRuntimeFunc("goPanicSliceConvert")
	} else {
		BoundsCheckFunc[ssa.BoundsIndex] = typecheck.LookupRuntimeFunc("panicIndex")
		BoundsCheckFunc[ssa.BoundsIndexU] = typecheck.LookupRuntimeFunc("panicIndexU")
		BoundsCheckFunc[ssa.BoundsSliceAlen] = typecheck.LookupRuntimeFunc("panicSliceAlen")
		BoundsCheckFunc[ssa.BoundsSliceAlenU] = typecheck.LookupRuntimeFunc("panicSliceAlenU")
		BoundsCheckFunc[ssa.BoundsSliceAcap] = typecheck.LookupRuntimeFunc("panicSliceAcap")
		BoundsCheckFunc[ssa.BoundsSliceAcapU] = typecheck.LookupRuntimeFunc("panicSliceAcapU")
		BoundsCheckFunc[ssa.BoundsSliceB] = typecheck.LookupRuntimeFunc("panicSliceB")
		BoundsCheckFunc[ssa.BoundsSliceBU] = typecheck.LookupRuntimeFunc("panicSliceBU")
		BoundsCheckFunc[ssa.BoundsSlice3Alen] = typecheck.LookupRuntimeFunc("panicSlice3Alen")
		BoundsCheckFunc[ssa.BoundsSlice3AlenU] = typecheck.LookupRuntimeFunc("panicSlice3AlenU")
		BoundsCheckFunc[ssa.BoundsSlice3Acap] = typecheck.LookupRuntimeFunc("panicSlice3Acap")
		BoundsCheckFunc[ssa.BoundsSlice3AcapU] = typecheck.LookupRuntimeFunc("panicSlice3AcapU")
		BoundsCheckFunc[ssa.BoundsSlice3B] = typecheck.LookupRuntimeFunc("panicSlice3B")
		BoundsCheckFunc[ssa.BoundsSlice3BU] = typecheck.LookupRuntimeFunc("panicSlice3BU")
		BoundsCheckFunc[ssa.BoundsSlice3C] = typecheck.LookupRuntimeFunc("panicSlice3C")
		BoundsCheckFunc[ssa.BoundsSlice3CU] = typecheck.LookupRuntimeFunc("panicSlice3CU")
		BoundsCheckFunc[ssa.BoundsConvert] = typecheck.LookupRuntimeFunc("panicSliceConvert")
	}
	if Arch.LinkArch.PtrSize == 4 {
		ExtendCheckFunc[ssa.BoundsIndex] = typecheck.LookupRuntimeVar("panicExtendIndex")
		ExtendCheckFunc[ssa.BoundsIndexU] = typecheck.LookupRuntimeVar("panicExtendIndexU")
		ExtendCheckFunc[ssa.BoundsSliceAlen] = typecheck.LookupRuntimeVar("panicExtendSliceAlen")
		ExtendCheckFunc[ssa.BoundsSliceAlenU] = typecheck.LookupRuntimeVar("panicExtendSliceAlenU")
		ExtendCheckFunc[ssa.BoundsSliceAcap] = typecheck.LookupRuntimeVar("panicExtendSliceAcap")
		ExtendCheckFunc[ssa.BoundsSliceAcapU] = typecheck.LookupRuntimeVar("panicExtendSliceAcapU")
		ExtendCheckFunc[ssa.BoundsSliceB] = typecheck.LookupRuntimeVar("panicExtendSliceB")
		ExtendCheckFunc[ssa.BoundsSliceBU] = typecheck.LookupRuntimeVar("panicExtendSliceBU")
		ExtendCheckFunc[ssa.BoundsSlice3Alen] = typecheck.LookupRuntimeVar("panicExtendSlice3Alen")
		ExtendCheckFunc[ssa.BoundsSlice3AlenU] = typecheck.LookupRuntimeVar("panicExtendSlice3AlenU")
		ExtendCheckFunc[ssa.BoundsSlice3Acap] = typecheck.LookupRuntimeVar("panicExtendSlice3Acap")
		ExtendCheckFunc[ssa.BoundsSlice3AcapU] = typecheck.LookupRuntimeVar("panicExtendSlice3AcapU")
		ExtendCheckFunc[ssa.BoundsSlice3B] = typecheck.LookupRuntimeVar("panicExtendSlice3B")
		ExtendCheckFunc[ssa.BoundsSlice3BU] = typecheck.LookupRuntimeVar("panicExtendSlice3BU")
		ExtendCheckFunc[ssa.BoundsSlice3C] = typecheck.LookupRuntimeVar("panicExtendSlice3C")
		ExtendCheckFunc[ssa.BoundsSlice3CU] = typecheck.LookupRuntimeVar("panicExtendSlice3CU")
	}

	// Wasm (all asm funcs with special ABIs)
	ir.Syms.WasmDiv = typecheck.LookupRuntimeVar("wasmDiv")
	ir.Syms.WasmTruncS = typecheck.LookupRuntimeVar("wasmTruncS")
	ir.Syms.WasmTruncU = typecheck.LookupRuntimeVar("wasmTruncU")
	ir.Syms.SigPanic = typecheck.LookupRuntimeFunc("sigpanic")
}

func InitTables() {
	initIntrinsics(nil)
}

// AbiForBodylessFuncStackMap returns the ABI for a bodyless function's stack map.
// This is not necessarily the ABI used to call it.
// Currently (1.17 dev) such a stack map is always ABI0;
// any ABI wrapper that is present is nosplit, hence a precise
// stack map is not needed there (the parameters survive only long
// enough to call the wrapped assembly function).
// This always returns a freshly copied ABI.
func AbiForBodylessFuncStackMap(fn *ir.Func) *abi.ABIConfig {
	return ssaConfig.ABI0.Copy() // No idea what races will result, be safe
}

// abiForFunc implements ABI policy for a function, but does not return a copy of the ABI.
// Passing a nil function returns the default ABI based on experiment configuration.
func abiForFunc(fn *ir.Func, abi0, abi1 *abi.ABIConfig) *abi.ABIConfig {
	if buildcfg.Experiment.RegabiArgs {
		// Select the ABI based on the function's defining ABI.
		if fn == nil {
			return abi1
		}
		switch fn.ABI {
		case obj.ABI0:
			return abi0
		case obj.ABIInternal:
			// TODO(austin): Clean up the nomenclature here.
			// It's not clear that "abi1" is ABIInternal.
			return abi1
		}
		base.Fatalf("function %v has unknown ABI %v", fn, fn.ABI)
		panic("not reachable")
	}

	a := abi0
	if fn != nil {
		if fn.Pragma&ir.RegisterParams != 0 { // TODO(register args) remove after register abi is working
			a = abi1
		}
	}
	return a
}

// emitOpenDeferInfo emits FUNCDATA information about the defers in a function
// that is using open-coded defers. This funcdata is used to determine the active
// defers in a function and execute those defers during panic processing.
//
// The funcdata is all encoded in varints (since values will almost always be less than
// 128, but stack offsets could potentially be up to 2Gbyte). All "locations" (offsets)
// for stack variables are specified as the number of bytes below varp (pointer to the
// top of the local variables) for their starting address. The format is:
//
//   - Offset of the deferBits variable
//   - Offset of the first closure slot (the rest are laid out consecutively).
func (s *state) emitOpenDeferInfo() {
	firstOffset := s.openDefers[0].closureNode.FrameOffset()

	// Verify that cmpstackvarlt laid out the slots in order.
	for i, r := range s.openDefers {
		have := r.closureNode.FrameOffset()
		want := firstOffset + int64(i)*int64(types.PtrSize)
		if have != want {
			base.FatalfAt(s.curfn.Pos(), "unexpected frame offset for open-coded defer slot #%v: have %v, want %v", i, have, want)
		}
	}

	x := base.Ctxt.Lookup(s.curfn.LSym.Name + ".opendefer")
	x.Set(obj.AttrContentAddressable, true)
	s.curfn.LSym.Func().OpenCodedDeferInfo = x

	off := 0
	off = objw.Uvarint(x, off, uint64(-s.deferBitsTemp.FrameOffset()))
	off = objw.Uvarint(x, off, uint64(-firstOffset))
}

// buildssa builds an SSA function for fn.
// worker indicates which of the backend workers is doing the processing.
func buildssa(fn *ir.Func, worker int, isPgoHot bool) *ssa.Func {
	name := ir.FuncName(fn)

	abiSelf := abiForFunc(fn, ssaConfig.ABI0, ssaConfig.ABI1)

	printssa := false
	// match either a simple name e.g. "(*Reader).Reset", package.name e.g. "compress/gzip.(*Reader).Reset", or subpackage name "gzip.(*Reader).Reset"
	// optionally allows an ABI suffix specification in the GOSSAHASH, e.g. "(*Reader).Reset<0>" etc
	if strings.Contains(ssaDump, name) { // in all the cases the function name is entirely contained within the GOSSAFUNC string.
		nameOptABI := name
		if strings.Contains(ssaDump, ",") { // ABI specification
			nameOptABI = ssa.FuncNameABI(name, abiSelf.Which())
		} else if strings.HasSuffix(ssaDump, ">") { // if they use the linker syntax instead....
			l := len(ssaDump)
			if l >= 3 && ssaDump[l-3] == '<' {
				nameOptABI = ssa.FuncNameABI(name, abiSelf.Which())
				ssaDump = ssaDump[:l-3] + "," + ssaDump[l-2:l-1]
			}
		}
		pkgDotName := base.Ctxt.Pkgpath + "." + nameOptABI
		printssa = nameOptABI == ssaDump || // "(*Reader).Reset"
			pkgDotName == ssaDump || // "compress/gzip.(*Reader).Reset"
			strings.HasSuffix(pkgDotName, ssaDump) && strings.HasSuffix(pkgDotName, "/"+ssaDump) // "gzip.(*Reader).Reset"
	}

	var astBuf *bytes.Buffer
	if printssa {
		astBuf = &bytes.Buffer{}
		ir.FDumpList(astBuf, "buildssa-body", fn.Body)
		if ssaDumpStdout {
			fmt.Println("generating SSA for", name)
			fmt.Print(astBuf.String())
		}
	}

	var s state
	s.pushLine(fn.Pos())
	defer s.popLine()

	s.hasdefer = fn.HasDefer()
	if fn.Pragma&ir.CgoUnsafeArgs != 0 {
		s.cgoUnsafeArgs = true
	}
	s.checkPtrEnabled = ir.ShouldCheckPtr(fn, 1)

	if base.Flag.Cfg.Instrumenting && fn.Pragma&ir.Norace == 0 && !fn.Linksym().ABIWrapper() {
		if !base.Flag.Race || !objabi.LookupPkgSpecial(fn.Sym().Pkg.Path).NoRaceFunc {
			s.instrumentMemory = true
		}
		if base.Flag.Race {
			s.instrumentEnterExit = true
		}
	}

	fe := ssafn{
		curfn: fn,
		log:   printssa && ssaDumpStdout,
	}
	s.curfn = fn

	cache := &ssaCaches[worker]
	cache.Reset()

	s.f = ssaConfig.NewFunc(&fe, cache)
	s.config = ssaConfig
	s.f.Type = fn.Type()
	s.f.Name = name
	s.f.PrintOrHtmlSSA = printssa
	if fn.Pragma&ir.Nosplit != 0 {
		s.f.NoSplit = true
	}
	s.f.ABI0 = ssaConfig.ABI0
	s.f.ABI1 = ssaConfig.ABI1
	s.f.ABIDefault = abiForFunc(nil, ssaConfig.ABI0, ssaConfig.ABI1)
	s.f.ABISelf = abiSelf

	s.panics = map[funcLine]*ssa.Block{}
	s.softFloat = s.config.SoftFloat

	// Allocate starting block
	s.f.Entry = s.f.NewBlock(ssa.BlockPlain)
	s.f.Entry.Pos = fn.Pos()
	s.f.IsPgoHot = isPgoHot

	if printssa {
		ssaDF := ssaDumpFile
		if ssaDir != "" {
			ssaDF = filepath.Join(ssaDir, base.Ctxt.Pkgpath+"."+s.f.NameABI()+".html")
			ssaD := filepath.Dir(ssaDF)
			os.MkdirAll(ssaD, 0755)
		}
		s.f.HTMLWriter = ssa.NewHTMLWriter(ssaDF, s.f, ssaDumpCFG)
		// TODO: generate and print a mapping from nodes to values and blocks
		dumpSourcesColumn(s.f.HTMLWriter, fn)
		s.f.HTMLWriter.WriteAST("AST", astBuf)
	}

	// Allocate starting values
	s.labels = map[string]*ssaLabel{}
	s.fwdVars = map[ir.Node]*ssa.Value{}
	s.startmem = s.entryNewValue0(ssa.OpInitMem, types.TypeMem)

	s.hasOpenDefers = base.Flag.N == 0 && s.hasdefer && !s.curfn.OpenCodedDeferDisallowed()
	switch {
	case base.Debug.NoOpenDefer != 0:
		s.hasOpenDefers = false
	case s.hasOpenDefers && (base.Ctxt.Flag_shared || base.Ctxt.Flag_dynlink) && base.Ctxt.Arch.Name == "386":
		// Don't support open-coded defers for 386 ONLY when using shared
		// libraries, because there is extra code (added by rewriteToUseGot())
		// preceding the deferreturn/ret code that we don't track correctly.
		s.hasOpenDefers = false
	}
	if s.hasOpenDefers && s.instrumentEnterExit {
		// Skip doing open defers if we need to instrument function
		// returns for the race detector, since we will not generate that
		// code in the case of the extra deferreturn/ret segment.
		s.hasOpenDefers = false
	}
	if s.hasOpenDefers {
		// Similarly, skip if there are any heap-allocated result
		// parameters that need to be copied back to their stack slots.
		for _, f := range s.curfn.Type().Results() {
			if !f.Nname.(*ir.Name).OnStack() {
				s.hasOpenDefers = false
				break
			}
		}
	}
	if s.hasOpenDefers &&
		s.curfn.NumReturns*s.curfn.NumDefers > 15 {
		// Since we are generating defer calls at every exit for
		// open-coded defers, skip doing open-coded defers if there are
		// too many returns (especially if there are multiple defers).
		// Open-coded defers are most important for improving performance
		// for smaller functions (which don't have many returns).
		s.hasOpenDefers = false
	}

	s.sp = s.entryNewValue0(ssa.OpSP, types.Types[types.TUINTPTR]) // TODO: use generic pointer type (unsafe.Pointer?) instead
	s.sb = s.entryNewValue0(ssa.OpSB, types.Types[types.TUINTPTR])

	s.startBlock(s.f.Entry)
	s.vars[memVar] = s.startmem
	if s.hasOpenDefers {
		// Create the deferBits variable and stack slot. deferBits is a
		// bitmask showing which of the open-coded defers in this function
		// have been activated.
		deferBitsTemp := typecheck.TempAt(src.NoXPos, s.curfn, types.Types[types.TUINT8])
		deferBitsTemp.SetAddrtaken(true)
		s.deferBitsTemp = deferBitsTemp
		// For this value, AuxInt is initialized to zero by default
		startDeferBits := s.entryNewValue0(ssa.OpConst8, types.Types[types.TUINT8])
		s.vars[deferBitsVar] = startDeferBits
		s.deferBitsAddr = s.addr(deferBitsTemp)
		s.store(types.Types[types.TUINT8], s.deferBitsAddr, startDeferBits)
		// Make sure that the deferBits stack slot is kept alive (for use
		// by panics) and stores to deferBits are not eliminated, even if
		// all checking code on deferBits in the function exit can be
		// eliminated, because the defer statements were all
		// unconditional.
		s.vars[memVar] = s.newValue1Apos(ssa.OpVarLive, types.TypeMem, deferBitsTemp, s.mem(), false)
	}

	var params *abi.ABIParamResultInfo
	params = s.f.ABISelf.ABIAnalyze(fn.Type(), true)

	// The backend's stackframe pass prunes away entries from the fn's
	// Dcl list, including PARAMOUT nodes that correspond to output
	// params passed in registers. Walk the Dcl list and capture these
	// nodes to a side list, so that we'll have them available during
	// DWARF-gen later on. See issue 48573 for more details.
	var debugInfo ssa.FuncDebug
	for _, n := range fn.Dcl {
		if n.Class == ir.PPARAMOUT && n.IsOutputParamInRegisters() {
			debugInfo.RegOutputParams = append(debugInfo.RegOutputParams, n)
		}
	}
	fn.DebugInfo = &debugInfo

	// Generate addresses of local declarations
	s.decladdrs = map[*ir.Name]*ssa.Value{}
	for _, n := range fn.Dcl {
		switch n.Class {
		case ir.PPARAM:
			// Be aware that blank and unnamed input parameters will not appear here, but do appear in the type
			s.decladdrs[n] = s.entry
### 提示词
```
这是路径为go/src/cmd/compile/internal/ssagen/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssagen

import (
	"bufio"
	"bytes"
	"fmt"
	"go/constant"
	"html"
	"internal/buildcfg"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"cmd/compile/internal/abi"
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/liveness"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/reflectdata"
	"cmd/compile/internal/rttype"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/staticdata"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/src"
	"cmd/internal/sys"

	rtabi "internal/abi"
)

var ssaConfig *ssa.Config
var ssaCaches []ssa.Cache

var ssaDump string     // early copy of $GOSSAFUNC; the func name to dump output for
var ssaDir string      // optional destination for ssa dump file
var ssaDumpStdout bool // whether to dump to stdout
var ssaDumpCFG string  // generate CFGs for these phases
const ssaDumpFile = "ssa.html"

// ssaDumpInlined holds all inlined functions when ssaDump contains a function name.
var ssaDumpInlined []*ir.Func

func DumpInline(fn *ir.Func) {
	if ssaDump != "" && ssaDump == ir.FuncName(fn) {
		ssaDumpInlined = append(ssaDumpInlined, fn)
	}
}

func InitEnv() {
	ssaDump = os.Getenv("GOSSAFUNC")
	ssaDir = os.Getenv("GOSSADIR")
	if ssaDump != "" {
		if strings.HasSuffix(ssaDump, "+") {
			ssaDump = ssaDump[:len(ssaDump)-1]
			ssaDumpStdout = true
		}
		spl := strings.Split(ssaDump, ":")
		if len(spl) > 1 {
			ssaDump = spl[0]
			ssaDumpCFG = spl[1]
		}
	}
}

func InitConfig() {
	types_ := ssa.NewTypes()

	if Arch.SoftFloat {
		softfloatInit()
	}

	// Generate a few pointer types that are uncommon in the frontend but common in the backend.
	// Caching is disabled in the backend, so generating these here avoids allocations.
	_ = types.NewPtr(types.Types[types.TINTER])                             // *interface{}
	_ = types.NewPtr(types.NewPtr(types.Types[types.TSTRING]))              // **string
	_ = types.NewPtr(types.NewSlice(types.Types[types.TINTER]))             // *[]interface{}
	_ = types.NewPtr(types.NewPtr(types.ByteType))                          // **byte
	_ = types.NewPtr(types.NewSlice(types.ByteType))                        // *[]byte
	_ = types.NewPtr(types.NewSlice(types.Types[types.TSTRING]))            // *[]string
	_ = types.NewPtr(types.NewPtr(types.NewPtr(types.Types[types.TUINT8]))) // ***uint8
	_ = types.NewPtr(types.Types[types.TINT16])                             // *int16
	_ = types.NewPtr(types.Types[types.TINT64])                             // *int64
	_ = types.NewPtr(types.ErrorType)                                       // *error
	if buildcfg.Experiment.SwissMap {
		_ = types.NewPtr(reflectdata.SwissMapType()) // *internal/runtime/maps.Map
	} else {
		_ = types.NewPtr(reflectdata.OldMapType()) // *runtime.hmap
	}
	_ = types.NewPtr(deferstruct()) // *runtime._defer
	types.NewPtrCacheEnabled = false
	ssaConfig = ssa.NewConfig(base.Ctxt.Arch.Name, *types_, base.Ctxt, base.Flag.N == 0, Arch.SoftFloat)
	ssaConfig.Race = base.Flag.Race
	ssaCaches = make([]ssa.Cache, base.Flag.LowerC)

	// Set up some runtime functions we'll need to call.
	ir.Syms.AssertE2I = typecheck.LookupRuntimeFunc("assertE2I")
	ir.Syms.AssertE2I2 = typecheck.LookupRuntimeFunc("assertE2I2")
	ir.Syms.CgoCheckMemmove = typecheck.LookupRuntimeFunc("cgoCheckMemmove")
	ir.Syms.CgoCheckPtrWrite = typecheck.LookupRuntimeFunc("cgoCheckPtrWrite")
	ir.Syms.CheckPtrAlignment = typecheck.LookupRuntimeFunc("checkptrAlignment")
	ir.Syms.Deferproc = typecheck.LookupRuntimeFunc("deferproc")
	ir.Syms.Deferprocat = typecheck.LookupRuntimeFunc("deferprocat")
	ir.Syms.DeferprocStack = typecheck.LookupRuntimeFunc("deferprocStack")
	ir.Syms.Deferreturn = typecheck.LookupRuntimeFunc("deferreturn")
	ir.Syms.Duffcopy = typecheck.LookupRuntimeFunc("duffcopy")
	ir.Syms.Duffzero = typecheck.LookupRuntimeFunc("duffzero")
	ir.Syms.GCWriteBarrier[0] = typecheck.LookupRuntimeFunc("gcWriteBarrier1")
	ir.Syms.GCWriteBarrier[1] = typecheck.LookupRuntimeFunc("gcWriteBarrier2")
	ir.Syms.GCWriteBarrier[2] = typecheck.LookupRuntimeFunc("gcWriteBarrier3")
	ir.Syms.GCWriteBarrier[3] = typecheck.LookupRuntimeFunc("gcWriteBarrier4")
	ir.Syms.GCWriteBarrier[4] = typecheck.LookupRuntimeFunc("gcWriteBarrier5")
	ir.Syms.GCWriteBarrier[5] = typecheck.LookupRuntimeFunc("gcWriteBarrier6")
	ir.Syms.GCWriteBarrier[6] = typecheck.LookupRuntimeFunc("gcWriteBarrier7")
	ir.Syms.GCWriteBarrier[7] = typecheck.LookupRuntimeFunc("gcWriteBarrier8")
	ir.Syms.Goschedguarded = typecheck.LookupRuntimeFunc("goschedguarded")
	ir.Syms.Growslice = typecheck.LookupRuntimeFunc("growslice")
	ir.Syms.InterfaceSwitch = typecheck.LookupRuntimeFunc("interfaceSwitch")
	ir.Syms.Memmove = typecheck.LookupRuntimeFunc("memmove")
	ir.Syms.Msanread = typecheck.LookupRuntimeFunc("msanread")
	ir.Syms.Msanwrite = typecheck.LookupRuntimeFunc("msanwrite")
	ir.Syms.Msanmove = typecheck.LookupRuntimeFunc("msanmove")
	ir.Syms.Asanread = typecheck.LookupRuntimeFunc("asanread")
	ir.Syms.Asanwrite = typecheck.LookupRuntimeFunc("asanwrite")
	ir.Syms.Newobject = typecheck.LookupRuntimeFunc("newobject")
	ir.Syms.Newproc = typecheck.LookupRuntimeFunc("newproc")
	ir.Syms.Panicdivide = typecheck.LookupRuntimeFunc("panicdivide")
	ir.Syms.PanicdottypeE = typecheck.LookupRuntimeFunc("panicdottypeE")
	ir.Syms.PanicdottypeI = typecheck.LookupRuntimeFunc("panicdottypeI")
	ir.Syms.Panicnildottype = typecheck.LookupRuntimeFunc("panicnildottype")
	ir.Syms.Panicoverflow = typecheck.LookupRuntimeFunc("panicoverflow")
	ir.Syms.Panicshift = typecheck.LookupRuntimeFunc("panicshift")
	ir.Syms.Racefuncenter = typecheck.LookupRuntimeFunc("racefuncenter")
	ir.Syms.Racefuncexit = typecheck.LookupRuntimeFunc("racefuncexit")
	ir.Syms.Raceread = typecheck.LookupRuntimeFunc("raceread")
	ir.Syms.Racereadrange = typecheck.LookupRuntimeFunc("racereadrange")
	ir.Syms.Racewrite = typecheck.LookupRuntimeFunc("racewrite")
	ir.Syms.Racewriterange = typecheck.LookupRuntimeFunc("racewriterange")
	ir.Syms.TypeAssert = typecheck.LookupRuntimeFunc("typeAssert")
	ir.Syms.WBZero = typecheck.LookupRuntimeFunc("wbZero")
	ir.Syms.WBMove = typecheck.LookupRuntimeFunc("wbMove")
	ir.Syms.X86HasPOPCNT = typecheck.LookupRuntimeVar("x86HasPOPCNT")         // bool
	ir.Syms.X86HasSSE41 = typecheck.LookupRuntimeVar("x86HasSSE41")           // bool
	ir.Syms.X86HasFMA = typecheck.LookupRuntimeVar("x86HasFMA")               // bool
	ir.Syms.ARMHasVFPv4 = typecheck.LookupRuntimeVar("armHasVFPv4")           // bool
	ir.Syms.ARM64HasATOMICS = typecheck.LookupRuntimeVar("arm64HasATOMICS")   // bool
	ir.Syms.Loong64HasLAMCAS = typecheck.LookupRuntimeVar("loong64HasLAMCAS") // bool
	ir.Syms.Loong64HasLAM_BH = typecheck.LookupRuntimeVar("loong64HasLAM_BH") // bool
	ir.Syms.Loong64HasLSX = typecheck.LookupRuntimeVar("loong64HasLSX")       // bool
	ir.Syms.Staticuint64s = typecheck.LookupRuntimeVar("staticuint64s")
	ir.Syms.Typedmemmove = typecheck.LookupRuntimeFunc("typedmemmove")
	ir.Syms.Udiv = typecheck.LookupRuntimeVar("udiv")                 // asm func with special ABI
	ir.Syms.WriteBarrier = typecheck.LookupRuntimeVar("writeBarrier") // struct { bool; ... }
	ir.Syms.Zerobase = typecheck.LookupRuntimeVar("zerobase")

	if Arch.LinkArch.Family == sys.Wasm {
		BoundsCheckFunc[ssa.BoundsIndex] = typecheck.LookupRuntimeFunc("goPanicIndex")
		BoundsCheckFunc[ssa.BoundsIndexU] = typecheck.LookupRuntimeFunc("goPanicIndexU")
		BoundsCheckFunc[ssa.BoundsSliceAlen] = typecheck.LookupRuntimeFunc("goPanicSliceAlen")
		BoundsCheckFunc[ssa.BoundsSliceAlenU] = typecheck.LookupRuntimeFunc("goPanicSliceAlenU")
		BoundsCheckFunc[ssa.BoundsSliceAcap] = typecheck.LookupRuntimeFunc("goPanicSliceAcap")
		BoundsCheckFunc[ssa.BoundsSliceAcapU] = typecheck.LookupRuntimeFunc("goPanicSliceAcapU")
		BoundsCheckFunc[ssa.BoundsSliceB] = typecheck.LookupRuntimeFunc("goPanicSliceB")
		BoundsCheckFunc[ssa.BoundsSliceBU] = typecheck.LookupRuntimeFunc("goPanicSliceBU")
		BoundsCheckFunc[ssa.BoundsSlice3Alen] = typecheck.LookupRuntimeFunc("goPanicSlice3Alen")
		BoundsCheckFunc[ssa.BoundsSlice3AlenU] = typecheck.LookupRuntimeFunc("goPanicSlice3AlenU")
		BoundsCheckFunc[ssa.BoundsSlice3Acap] = typecheck.LookupRuntimeFunc("goPanicSlice3Acap")
		BoundsCheckFunc[ssa.BoundsSlice3AcapU] = typecheck.LookupRuntimeFunc("goPanicSlice3AcapU")
		BoundsCheckFunc[ssa.BoundsSlice3B] = typecheck.LookupRuntimeFunc("goPanicSlice3B")
		BoundsCheckFunc[ssa.BoundsSlice3BU] = typecheck.LookupRuntimeFunc("goPanicSlice3BU")
		BoundsCheckFunc[ssa.BoundsSlice3C] = typecheck.LookupRuntimeFunc("goPanicSlice3C")
		BoundsCheckFunc[ssa.BoundsSlice3CU] = typecheck.LookupRuntimeFunc("goPanicSlice3CU")
		BoundsCheckFunc[ssa.BoundsConvert] = typecheck.LookupRuntimeFunc("goPanicSliceConvert")
	} else {
		BoundsCheckFunc[ssa.BoundsIndex] = typecheck.LookupRuntimeFunc("panicIndex")
		BoundsCheckFunc[ssa.BoundsIndexU] = typecheck.LookupRuntimeFunc("panicIndexU")
		BoundsCheckFunc[ssa.BoundsSliceAlen] = typecheck.LookupRuntimeFunc("panicSliceAlen")
		BoundsCheckFunc[ssa.BoundsSliceAlenU] = typecheck.LookupRuntimeFunc("panicSliceAlenU")
		BoundsCheckFunc[ssa.BoundsSliceAcap] = typecheck.LookupRuntimeFunc("panicSliceAcap")
		BoundsCheckFunc[ssa.BoundsSliceAcapU] = typecheck.LookupRuntimeFunc("panicSliceAcapU")
		BoundsCheckFunc[ssa.BoundsSliceB] = typecheck.LookupRuntimeFunc("panicSliceB")
		BoundsCheckFunc[ssa.BoundsSliceBU] = typecheck.LookupRuntimeFunc("panicSliceBU")
		BoundsCheckFunc[ssa.BoundsSlice3Alen] = typecheck.LookupRuntimeFunc("panicSlice3Alen")
		BoundsCheckFunc[ssa.BoundsSlice3AlenU] = typecheck.LookupRuntimeFunc("panicSlice3AlenU")
		BoundsCheckFunc[ssa.BoundsSlice3Acap] = typecheck.LookupRuntimeFunc("panicSlice3Acap")
		BoundsCheckFunc[ssa.BoundsSlice3AcapU] = typecheck.LookupRuntimeFunc("panicSlice3AcapU")
		BoundsCheckFunc[ssa.BoundsSlice3B] = typecheck.LookupRuntimeFunc("panicSlice3B")
		BoundsCheckFunc[ssa.BoundsSlice3BU] = typecheck.LookupRuntimeFunc("panicSlice3BU")
		BoundsCheckFunc[ssa.BoundsSlice3C] = typecheck.LookupRuntimeFunc("panicSlice3C")
		BoundsCheckFunc[ssa.BoundsSlice3CU] = typecheck.LookupRuntimeFunc("panicSlice3CU")
		BoundsCheckFunc[ssa.BoundsConvert] = typecheck.LookupRuntimeFunc("panicSliceConvert")
	}
	if Arch.LinkArch.PtrSize == 4 {
		ExtendCheckFunc[ssa.BoundsIndex] = typecheck.LookupRuntimeVar("panicExtendIndex")
		ExtendCheckFunc[ssa.BoundsIndexU] = typecheck.LookupRuntimeVar("panicExtendIndexU")
		ExtendCheckFunc[ssa.BoundsSliceAlen] = typecheck.LookupRuntimeVar("panicExtendSliceAlen")
		ExtendCheckFunc[ssa.BoundsSliceAlenU] = typecheck.LookupRuntimeVar("panicExtendSliceAlenU")
		ExtendCheckFunc[ssa.BoundsSliceAcap] = typecheck.LookupRuntimeVar("panicExtendSliceAcap")
		ExtendCheckFunc[ssa.BoundsSliceAcapU] = typecheck.LookupRuntimeVar("panicExtendSliceAcapU")
		ExtendCheckFunc[ssa.BoundsSliceB] = typecheck.LookupRuntimeVar("panicExtendSliceB")
		ExtendCheckFunc[ssa.BoundsSliceBU] = typecheck.LookupRuntimeVar("panicExtendSliceBU")
		ExtendCheckFunc[ssa.BoundsSlice3Alen] = typecheck.LookupRuntimeVar("panicExtendSlice3Alen")
		ExtendCheckFunc[ssa.BoundsSlice3AlenU] = typecheck.LookupRuntimeVar("panicExtendSlice3AlenU")
		ExtendCheckFunc[ssa.BoundsSlice3Acap] = typecheck.LookupRuntimeVar("panicExtendSlice3Acap")
		ExtendCheckFunc[ssa.BoundsSlice3AcapU] = typecheck.LookupRuntimeVar("panicExtendSlice3AcapU")
		ExtendCheckFunc[ssa.BoundsSlice3B] = typecheck.LookupRuntimeVar("panicExtendSlice3B")
		ExtendCheckFunc[ssa.BoundsSlice3BU] = typecheck.LookupRuntimeVar("panicExtendSlice3BU")
		ExtendCheckFunc[ssa.BoundsSlice3C] = typecheck.LookupRuntimeVar("panicExtendSlice3C")
		ExtendCheckFunc[ssa.BoundsSlice3CU] = typecheck.LookupRuntimeVar("panicExtendSlice3CU")
	}

	// Wasm (all asm funcs with special ABIs)
	ir.Syms.WasmDiv = typecheck.LookupRuntimeVar("wasmDiv")
	ir.Syms.WasmTruncS = typecheck.LookupRuntimeVar("wasmTruncS")
	ir.Syms.WasmTruncU = typecheck.LookupRuntimeVar("wasmTruncU")
	ir.Syms.SigPanic = typecheck.LookupRuntimeFunc("sigpanic")
}

func InitTables() {
	initIntrinsics(nil)
}

// AbiForBodylessFuncStackMap returns the ABI for a bodyless function's stack map.
// This is not necessarily the ABI used to call it.
// Currently (1.17 dev) such a stack map is always ABI0;
// any ABI wrapper that is present is nosplit, hence a precise
// stack map is not needed there (the parameters survive only long
// enough to call the wrapped assembly function).
// This always returns a freshly copied ABI.
func AbiForBodylessFuncStackMap(fn *ir.Func) *abi.ABIConfig {
	return ssaConfig.ABI0.Copy() // No idea what races will result, be safe
}

// abiForFunc implements ABI policy for a function, but does not return a copy of the ABI.
// Passing a nil function returns the default ABI based on experiment configuration.
func abiForFunc(fn *ir.Func, abi0, abi1 *abi.ABIConfig) *abi.ABIConfig {
	if buildcfg.Experiment.RegabiArgs {
		// Select the ABI based on the function's defining ABI.
		if fn == nil {
			return abi1
		}
		switch fn.ABI {
		case obj.ABI0:
			return abi0
		case obj.ABIInternal:
			// TODO(austin): Clean up the nomenclature here.
			// It's not clear that "abi1" is ABIInternal.
			return abi1
		}
		base.Fatalf("function %v has unknown ABI %v", fn, fn.ABI)
		panic("not reachable")
	}

	a := abi0
	if fn != nil {
		if fn.Pragma&ir.RegisterParams != 0 { // TODO(register args) remove after register abi is working
			a = abi1
		}
	}
	return a
}

// emitOpenDeferInfo emits FUNCDATA information about the defers in a function
// that is using open-coded defers.  This funcdata is used to determine the active
// defers in a function and execute those defers during panic processing.
//
// The funcdata is all encoded in varints (since values will almost always be less than
// 128, but stack offsets could potentially be up to 2Gbyte). All "locations" (offsets)
// for stack variables are specified as the number of bytes below varp (pointer to the
// top of the local variables) for their starting address. The format is:
//
//   - Offset of the deferBits variable
//   - Offset of the first closure slot (the rest are laid out consecutively).
func (s *state) emitOpenDeferInfo() {
	firstOffset := s.openDefers[0].closureNode.FrameOffset()

	// Verify that cmpstackvarlt laid out the slots in order.
	for i, r := range s.openDefers {
		have := r.closureNode.FrameOffset()
		want := firstOffset + int64(i)*int64(types.PtrSize)
		if have != want {
			base.FatalfAt(s.curfn.Pos(), "unexpected frame offset for open-coded defer slot #%v: have %v, want %v", i, have, want)
		}
	}

	x := base.Ctxt.Lookup(s.curfn.LSym.Name + ".opendefer")
	x.Set(obj.AttrContentAddressable, true)
	s.curfn.LSym.Func().OpenCodedDeferInfo = x

	off := 0
	off = objw.Uvarint(x, off, uint64(-s.deferBitsTemp.FrameOffset()))
	off = objw.Uvarint(x, off, uint64(-firstOffset))
}

// buildssa builds an SSA function for fn.
// worker indicates which of the backend workers is doing the processing.
func buildssa(fn *ir.Func, worker int, isPgoHot bool) *ssa.Func {
	name := ir.FuncName(fn)

	abiSelf := abiForFunc(fn, ssaConfig.ABI0, ssaConfig.ABI1)

	printssa := false
	// match either a simple name e.g. "(*Reader).Reset", package.name e.g. "compress/gzip.(*Reader).Reset", or subpackage name "gzip.(*Reader).Reset"
	// optionally allows an ABI suffix specification in the GOSSAHASH, e.g. "(*Reader).Reset<0>" etc
	if strings.Contains(ssaDump, name) { // in all the cases the function name is entirely contained within the GOSSAFUNC string.
		nameOptABI := name
		if strings.Contains(ssaDump, ",") { // ABI specification
			nameOptABI = ssa.FuncNameABI(name, abiSelf.Which())
		} else if strings.HasSuffix(ssaDump, ">") { // if they use the linker syntax instead....
			l := len(ssaDump)
			if l >= 3 && ssaDump[l-3] == '<' {
				nameOptABI = ssa.FuncNameABI(name, abiSelf.Which())
				ssaDump = ssaDump[:l-3] + "," + ssaDump[l-2:l-1]
			}
		}
		pkgDotName := base.Ctxt.Pkgpath + "." + nameOptABI
		printssa = nameOptABI == ssaDump || // "(*Reader).Reset"
			pkgDotName == ssaDump || // "compress/gzip.(*Reader).Reset"
			strings.HasSuffix(pkgDotName, ssaDump) && strings.HasSuffix(pkgDotName, "/"+ssaDump) // "gzip.(*Reader).Reset"
	}

	var astBuf *bytes.Buffer
	if printssa {
		astBuf = &bytes.Buffer{}
		ir.FDumpList(astBuf, "buildssa-body", fn.Body)
		if ssaDumpStdout {
			fmt.Println("generating SSA for", name)
			fmt.Print(astBuf.String())
		}
	}

	var s state
	s.pushLine(fn.Pos())
	defer s.popLine()

	s.hasdefer = fn.HasDefer()
	if fn.Pragma&ir.CgoUnsafeArgs != 0 {
		s.cgoUnsafeArgs = true
	}
	s.checkPtrEnabled = ir.ShouldCheckPtr(fn, 1)

	if base.Flag.Cfg.Instrumenting && fn.Pragma&ir.Norace == 0 && !fn.Linksym().ABIWrapper() {
		if !base.Flag.Race || !objabi.LookupPkgSpecial(fn.Sym().Pkg.Path).NoRaceFunc {
			s.instrumentMemory = true
		}
		if base.Flag.Race {
			s.instrumentEnterExit = true
		}
	}

	fe := ssafn{
		curfn: fn,
		log:   printssa && ssaDumpStdout,
	}
	s.curfn = fn

	cache := &ssaCaches[worker]
	cache.Reset()

	s.f = ssaConfig.NewFunc(&fe, cache)
	s.config = ssaConfig
	s.f.Type = fn.Type()
	s.f.Name = name
	s.f.PrintOrHtmlSSA = printssa
	if fn.Pragma&ir.Nosplit != 0 {
		s.f.NoSplit = true
	}
	s.f.ABI0 = ssaConfig.ABI0
	s.f.ABI1 = ssaConfig.ABI1
	s.f.ABIDefault = abiForFunc(nil, ssaConfig.ABI0, ssaConfig.ABI1)
	s.f.ABISelf = abiSelf

	s.panics = map[funcLine]*ssa.Block{}
	s.softFloat = s.config.SoftFloat

	// Allocate starting block
	s.f.Entry = s.f.NewBlock(ssa.BlockPlain)
	s.f.Entry.Pos = fn.Pos()
	s.f.IsPgoHot = isPgoHot

	if printssa {
		ssaDF := ssaDumpFile
		if ssaDir != "" {
			ssaDF = filepath.Join(ssaDir, base.Ctxt.Pkgpath+"."+s.f.NameABI()+".html")
			ssaD := filepath.Dir(ssaDF)
			os.MkdirAll(ssaD, 0755)
		}
		s.f.HTMLWriter = ssa.NewHTMLWriter(ssaDF, s.f, ssaDumpCFG)
		// TODO: generate and print a mapping from nodes to values and blocks
		dumpSourcesColumn(s.f.HTMLWriter, fn)
		s.f.HTMLWriter.WriteAST("AST", astBuf)
	}

	// Allocate starting values
	s.labels = map[string]*ssaLabel{}
	s.fwdVars = map[ir.Node]*ssa.Value{}
	s.startmem = s.entryNewValue0(ssa.OpInitMem, types.TypeMem)

	s.hasOpenDefers = base.Flag.N == 0 && s.hasdefer && !s.curfn.OpenCodedDeferDisallowed()
	switch {
	case base.Debug.NoOpenDefer != 0:
		s.hasOpenDefers = false
	case s.hasOpenDefers && (base.Ctxt.Flag_shared || base.Ctxt.Flag_dynlink) && base.Ctxt.Arch.Name == "386":
		// Don't support open-coded defers for 386 ONLY when using shared
		// libraries, because there is extra code (added by rewriteToUseGot())
		// preceding the deferreturn/ret code that we don't track correctly.
		s.hasOpenDefers = false
	}
	if s.hasOpenDefers && s.instrumentEnterExit {
		// Skip doing open defers if we need to instrument function
		// returns for the race detector, since we will not generate that
		// code in the case of the extra deferreturn/ret segment.
		s.hasOpenDefers = false
	}
	if s.hasOpenDefers {
		// Similarly, skip if there are any heap-allocated result
		// parameters that need to be copied back to their stack slots.
		for _, f := range s.curfn.Type().Results() {
			if !f.Nname.(*ir.Name).OnStack() {
				s.hasOpenDefers = false
				break
			}
		}
	}
	if s.hasOpenDefers &&
		s.curfn.NumReturns*s.curfn.NumDefers > 15 {
		// Since we are generating defer calls at every exit for
		// open-coded defers, skip doing open-coded defers if there are
		// too many returns (especially if there are multiple defers).
		// Open-coded defers are most important for improving performance
		// for smaller functions (which don't have many returns).
		s.hasOpenDefers = false
	}

	s.sp = s.entryNewValue0(ssa.OpSP, types.Types[types.TUINTPTR]) // TODO: use generic pointer type (unsafe.Pointer?) instead
	s.sb = s.entryNewValue0(ssa.OpSB, types.Types[types.TUINTPTR])

	s.startBlock(s.f.Entry)
	s.vars[memVar] = s.startmem
	if s.hasOpenDefers {
		// Create the deferBits variable and stack slot.  deferBits is a
		// bitmask showing which of the open-coded defers in this function
		// have been activated.
		deferBitsTemp := typecheck.TempAt(src.NoXPos, s.curfn, types.Types[types.TUINT8])
		deferBitsTemp.SetAddrtaken(true)
		s.deferBitsTemp = deferBitsTemp
		// For this value, AuxInt is initialized to zero by default
		startDeferBits := s.entryNewValue0(ssa.OpConst8, types.Types[types.TUINT8])
		s.vars[deferBitsVar] = startDeferBits
		s.deferBitsAddr = s.addr(deferBitsTemp)
		s.store(types.Types[types.TUINT8], s.deferBitsAddr, startDeferBits)
		// Make sure that the deferBits stack slot is kept alive (for use
		// by panics) and stores to deferBits are not eliminated, even if
		// all checking code on deferBits in the function exit can be
		// eliminated, because the defer statements were all
		// unconditional.
		s.vars[memVar] = s.newValue1Apos(ssa.OpVarLive, types.TypeMem, deferBitsTemp, s.mem(), false)
	}

	var params *abi.ABIParamResultInfo
	params = s.f.ABISelf.ABIAnalyze(fn.Type(), true)

	// The backend's stackframe pass prunes away entries from the fn's
	// Dcl list, including PARAMOUT nodes that correspond to output
	// params passed in registers. Walk the Dcl list and capture these
	// nodes to a side list, so that we'll have them available during
	// DWARF-gen later on. See issue 48573 for more details.
	var debugInfo ssa.FuncDebug
	for _, n := range fn.Dcl {
		if n.Class == ir.PPARAMOUT && n.IsOutputParamInRegisters() {
			debugInfo.RegOutputParams = append(debugInfo.RegOutputParams, n)
		}
	}
	fn.DebugInfo = &debugInfo

	// Generate addresses of local declarations
	s.decladdrs = map[*ir.Name]*ssa.Value{}
	for _, n := range fn.Dcl {
		switch n.Class {
		case ir.PPARAM:
			// Be aware that blank and unnamed input parameters will not appear here, but do appear in the type
			s.decladdrs[n] = s.entryNewValue2A(ssa.OpLocalAddr, types.NewPtr(n.Type()), n, s.sp, s.startmem)
		case ir.PPARAMOUT:
			s.decladdrs[n] = s.entryNewValue2A(ssa.OpLocalAddr, types.NewPtr(n.Type()), n, s.sp, s.startmem)
		case ir.PAUTO:
			// processed at each use, to prevent Addr coming
			// before the decl.
		default:
			s.Fatalf("local variable with class %v unimplemented", n.Class)
		}
	}

	s.f.OwnAux = ssa.OwnAuxCall(fn.LSym, params)

	// Populate SSAable arguments.
	for _, n := range fn.Dcl {
		if n.Class == ir.PPARAM {
			if s.canSSA(n) {
				v := s.newValue0A(ssa.OpArg, n.Type(), n)
				s.vars[n] = v
				s.addNamedValue(n, v) // This helps with debugging information, not needed for compilation itself.
			} else { // address was taken AND/OR too large for SSA
				paramAssignment := ssa.ParamAssignmentForArgName(s.f, n)
				if len(paramAssignment.Registers) > 0 {
					if ssa.CanSSA(n.Type()) { // SSA-able type, so address was taken -- receive value in OpArg, DO NOT bind to var, store immediately to memory.
						v := s.newValue0A(ssa.OpArg, n.Type(), n)
						s.store(n.Type(), s.decladdrs[n], v)
					} else { // Too big for SSA.
						// Brute force, and early, do a bunch of stores from registers
						// Note that expand calls knows about this and doesn't trouble itself with larger-than-SSA-able Args in registers.
						s.storeParameterRegsToStack(s.f.ABISelf, paramAssignment, n, s.decladdrs[n], false)
					}
				}
			}
		}
	}

	// Populate closure variables.
	if fn.Needctxt() {
		clo := s.entryNewValue0(ssa.OpGetClosurePtr, s.f.Config.Types.BytePtr)
		if fn.RangeParent != nil && base.Flag.N != 0 {
			// For a range body closure, keep its closure pointer live on the
			// stack with a special name, so the debugger can look for it and
			// find the parent frame.
			sym := &types.Sym{Name: ".closureptr", Pkg: types.LocalPkg}
			cloSlot := s.curfn.NewLocal(src.NoXPos, sym, s.f.Config.Types.BytePtr)
			cloSlot.SetUsed(true)
			cloSlot.SetEsc(ir.EscNever)
			cloSlot.SetAddrtaken(true)
			s.f.CloSlot = cloSlot
			s.vars[memVar] = s.newValue1Apos(ssa.OpVarDef, types.TypeMem, cloSlot, s.mem(), false)
			addr := s.addr(cloSlot)
			s.store(s.f.Config.Types.BytePtr, addr, clo)
			// Keep it from being dead-store eliminated.
			s.vars[memVar] = s.newValue1Apos(ssa.OpVarLive, types.TypeMem, cloSlot, s.mem(), false)
		}
		csiter := typecheck.NewClosureStructIter(fn.ClosureVars)
		for {
			n, typ, offset := csiter.Next()
			if n == nil {
				break
			}

			ptr := s.newValue1I(ssa.OpOffPtr, types.NewPtr(typ), offset, clo)

			// If n is a small variable captured by value, promote
			// it to PAUTO so it can be converted to SSA.
			//
			// Note: While we never capture a variable by value if
			// the user took its address, we may have generated
			// runtime calls that did (#43701). Since we don't
			// convert Addrtaken variables to SSA anyway, no point
			// in promoting them either.
			if n.Byval() && !n.Addrtaken() && ssa.CanSSA(n.Type()) {
				n.Class = ir.PAUTO
				fn.Dcl = append(fn.Dcl, n)
				s.assign(n, s.load(n.Type(), ptr), false, 0)
				continue
			}

			if !n.Byval() {
				ptr = s.load(typ, ptr)
			}
			s.setHeapaddr(fn.Pos(), n, ptr)
		}
	}

	// Convert the AST-based IR to the SSA-based IR
	if s.instrumentEnterExit {
		s.rtcall(ir.Syms.Racefuncenter, true, nil, s.newValue0(ssa.OpGetCallerPC, types.Types[types.TUINTPTR]))
	}
	s.zeroResults()
	s.paramsToHeap()
	s.stmtList(fn.Body)

	// fallthrough to exit
	if s.curBlock != nil {
		s.pushLine(fn.Endlineno)
		s.exit()
		s.popLine()
	}

	for _, b := range s.f.Blocks {
		if b.Pos != src.NoXPos {
			s.updateUnsetPredPos(b)
		}
	}

	s.f.HTMLWriter.WritePhase("before insert phis", "before insert phis")

	s.insertPhis()

	// Main call to ssa package to compile function
	ssa.Compile(s.f)

	fe.AllocFrame(s.f)

	if len(s.openDefers) != 0 {
		s.emitOpenDeferInfo()
	}

	// Record incoming parameter spill information for morestack calls emitted in the assembler.
	// This is done here, using all the parameters (used, partially used, and unused) because
	// it mimics the behavior of the former ABI (everything stored) and because it's not 100%
	// clear if naming conventions are respected in autogenerated code.
	// TODO figure out exactly what's unused, don't spill it. Make liveness fine-grained, also.
	for _, p := range params.InParams() {
		typs, offs := p.RegisterTypesAndOffsets()
		for i, t := range typs {
			o := offs[i]                // offset within parameter
			fo := p.FrameOffset(params) // offset of parameter in frame
			reg := ssa.ObjRegForAbiReg(p.Registers[i], s.f.Config)
			s.f.RegArgs = append(s.f.RegArgs, ssa.Spill{Reg: reg, Offset: fo + o, Type: t})
		}
	}

	return s.f
}

func (s *state) storeParameterRegsToStack(abi *abi.ABIConfig, paramAssignment *abi.ABIParamAssignment, n *ir.Name, addr *ssa.Value, pointersOnly bool) {
	typs, offs := paramAssignment.RegisterTypesAndOffsets()
	for i, t := range typs {
		if pointersOnly && !t.IsPtrShaped() {
			continue
		}
		r := paramAssignment.Registers[i]
		o := offs[i]
		op, reg := ssa.ArgOpAndRegisterFor(r, abi)
		aux := &ssa.AuxNameOffset{Name: n, Offset: o}
		v := s.newValue0I(op, t, reg)
		v.Aux = aux
		p := s.newValue1I(ssa.OpOffPtr, types.NewPtr(t), o, addr)
		s.store(t, p, v)
	}
}

// zeroResults zeros the return values at the start of the function.
// We need to do this very early in the function.  Defer might stop a
// panic and show the return values as they exist at the time of
// panic.  For precise stacks, the garbage collector assumes results
// are always live, so we need to zero them before any allocations,
// even allocations to move params/results to the heap.
func (s *state) zeroResults() {
	for _, f := range s.curfn.Type().Results() {
		n := f.Nname.(*ir.Name)
		if !n.OnStack() {
			// The local which points to the return value is the
			// thing that needs zeroing. This is already handled
			// by a Needzero annotation in plive.go:(*liveness).epilogue.
			continue
		}
		// Zero the stack location containing f.
		if typ := n.Type(); ssa.CanSSA(typ) {
			s.assign(n, s.zeroVal(typ), false, 0)
		} else {
			if typ.HasPointers() || ssa.IsMergeCandidate(n) {
				s.vars[memVar] = s.newValue1A(ssa.OpVarDef, types.TypeMem, n, s.mem())
			}
			s.zero(n.Type(), s.decladdrs[n])
		}
	}
}

// paramsToHeap produces code to allocate memory for heap-escaped parameters
// and to copy non-result parameters' values from the stack.
func (s *state) paramsToHeap() {
	do := func(params []*types.Field) {
		for _, f := range params {
			if f.Nname == nil {
				continue // anonymous or blank parameter
			}
			n := f.Nname.(*ir.Name)
			if ir.IsBlank(n) || n.OnStack() {
				continue
			}
			s.newHeapaddr(n)
			if n.Class == ir.PPARAM {
				s.move(n.Type(), s.expr(n.Heapaddr), s.decladdrs[n])
			}
		}
	}

	typ := s.curfn.Type()
	do(typ.Recvs())
	do(typ.Params())
	do(typ.Results())
}

// newHeapaddr allocates heap memory for n and sets its heap address.
func (s *state) newHeapaddr(n *ir.Name) {
	s.setHeapaddr(n.Pos(), n, s.newObject(n.Type(), nil))
}

// setHeapaddr allocates a new PAUTO variable to store ptr (which must be non-nil)
// and then sets it as n's heap address.
func (s *state) setHeapaddr(pos src.XPos, n *ir.Name, ptr *ssa.Value) {
	if !ptr.Type.IsPtr() || !types.Identical(n.Type(), ptr.Type.Elem()) {
		base.FatalfAt(n.Pos(), "setHeapaddr %L with type %v", n, ptr.Type)
	}

	// Declare variable to hold address.
	sym := &types.Sym{Name: "&" + n.Sym().Name, Pkg: types.LocalPkg}
	addr := s.curfn.NewLocal(pos, sym, types.NewPtr(n.Type()))
	addr.SetUsed(true)
	types.CalcSize(addr.Type())

	if n.Class == ir.PPARAMOUT {
		addr.SetIsOutputParamHeapAddr(true)
	}

	n.Heapaddr = addr
	s.assign(addr, ptr, false, 0)
}

// newObject returns an SSA value denoting new(typ).
func (s *state) newObject(typ *types.Type, rtype *ssa.Value) *ssa.Value {
	if typ.Size() == 0 {
		return s.newValue1A(ssa.OpAddr, types.NewPtr(typ), ir.Syms.Zerobase, s.sb)
	}
	if rtype == nil {
		rtype = s.reflectType(typ)
	}
	return s.rtcall(ir.Syms.Newobject, true, []*types.Type{types.NewPtr(typ)}, rtype)[0]
}

func (s *state) checkPtrAlignment(n *ir.ConvExpr, v *ssa.Value, count *ssa.Value) {
	if !n.Type().IsPtr() {
		s.Fatalf("expected pointer type: %v", n.Type())
	}
	elem, rtypeExpr := n.Type().Elem(), n.ElemRType
	if count != nil {
		if !elem.IsArray() {
			s.Fatalf("expected array type: %v", elem)
		}
		elem, rtypeExpr = elem.Elem(), n.ElemElemRType
	}
	size := elem.Size()
	// Casting from larger type to smaller one is ok, so for smallest type, do nothing.
	if elem.Alignment() == 1 && (size == 0 || size == 1 || count == nil) {
		return
	}
	if count == nil {
		count = s.constInt(types.Types[types.TUINTPTR], 1)
	}
	if count.Type.Size() != s.config.PtrSize {
		s.Fatalf("expected count fit to a uintptr size, have: %d, want: %d", count.Type.Size(), s.config.PtrSize)
	}
	var rtype *ssa.Value
	if rtypeExpr != nil {
		rtype = s.expr(rtypeExpr)
	} else {
		rtype = s.reflectType(elem)
	}
	s.rtcall(ir.Syms.CheckPtrAlignment, true, nil, v, rtype, count)
}

// reflectType returns an SSA value representing a pointer to typ's
// reflection type descriptor.
func (s *state) reflectType(typ *types.Type) *ssa.Value {
	// TODO(mdempsky): Make this Fatalf under Unified IR; frontend needs
	// to supply RType expressions.
	lsym := reflectdata.TypeLinksym(typ)
	return s.entryNewValue1A(ssa.OpAddr, types.NewPtr(types.Types[types.TUINT8]), lsym, s.sb)
}

func dumpSourcesColumn(writer *ssa.HTMLWriter, fn *ir.Func) {
	// Read sources of target function fn.
	fname := base.Ctxt.PosTable.Pos(fn.Pos()).Filename()
	targetFn, err := readFuncLines(fname, fn.Pos().Line(), fn.Endlineno.Line())
	if err != nil {
		writer.Logf("cannot read sources for function %v: %v", fn, err)
	}

	// Read sources of inlined functions.
	var inlFns []*ssa.FuncLines
	for _, fi := range ssaDumpInlined {
		elno := fi.Endlineno
		fname := base.Ctxt.PosTable.Pos(fi.Pos()).Filename()
		fnLines, err := readFuncLines(fname, fi.Pos().Line(), elno.Line())
		if err != nil {
			writer.Logf("cannot read sources for inlined function %v: %v", fi, err)
			continue
		}
		inlFns = append(inlFns, fnLines)
	}

	slices.SortFunc(inlFns, ssa.ByTopoCmp)
	if targetFn != nil {
		inlFns = append([]*ssa.FuncLines{targetFn}, inlFns...)
	}

	writer.WriteSources("sources", inlFns)
}

func readFuncLines(file string, start, end uint) (*ssa.FuncLines, error) {
	f, err := os.Open(os.ExpandEnv(file))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	ln := uint(1)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() && ln <= end {
		if ln >= start {
			lines = append(lines, scanner.Text())
		}
		ln++
	}
	return &ssa.FuncLines{Filename: file, StartLineno: start, Lines: lines}, nil
}

// updateUnsetPredPos propagates the earliest-value position information for b
// towards all of b's predecessors that need a position, and recurs on that
// predecessor if its position is updated. B should have a non-empty position.
func (s *state) updateUnsetPredPos(b *ssa.Block) {
	if b.Pos == src.NoXPos {
		s.Fatalf("Block %s should have a position", b)
	}
	bestPos := src.NoXPos
	for _, e := range b.Preds {
		p := e.Block()
		if !p.LackingPos() {
			continue
		}
		if bestPos == src.NoXPos {
			bestPos = b.Pos
			for _, v := range b.Values {
				if v.LackingPos() {
					continue
				}
				if v.Pos != src.NoXPos {
					// Assume values are still in roughly textual order;
					// TODO: could also seek minimum position?
					bestPos = v.Pos
					break
				}
			}
		}
		p.Pos = bestPos
		s.updateUnsetPredPos(p) // We do not expect long chains of these, thus recursion is okay.
	}
}

// Information about each open-coded defer.
type openDeferInfo struct {
	// The node representing the call of the defer
	n *ir.CallExpr
	// If defer call is closure call, the address of the argtmp where the
	// closure is stored.
	closure *ssa.Value
	// The node representing the argtmp where the closure is stored - used for
	// function, method, or interface call, to store a closure that panic
	// processing can use for this defer.
	closureNode *ir.Name
}

type state struct {
	// configuration (arch) information
	config *ssa.Config

	// function we're building
	f *ssa.Func

	// Node for function
	curfn *ir.Func

	// labels in f
	labels map[string]*ssaLabel

	// unlabeled break and continue statement tracking
	breakTo    *ssa.Block // current target for plain break statement
	continueTo *ssa.Block // current target for plain continue statement

	// current location where we're interpreting the AST
	curBlock *ssa.Block

	// variable assignments in the current block (map from variable symbol to ssa value)
	// *Node is the unique identifier (an ONAME Node) for the variable.
	// TODO: keep a single varnum map, then make all of these maps slices instead?
	vars map[ir.Node]*ssa.Value

	// fwdVars are variables that are used before they are defined in the current block.
	// This map exists just to coalesce multiple references into a single FwdRef op.
	// *Node is the unique identifier (an ONAME Node) for the variable.
	fwdVars map[ir.Node]*ssa.Value

	// all defined variables at the end of each block. Indexed by block ID.
	defvars []map[ir.Node]*ssa.Value

	// addresses of PPARAM and PPARAMOUT variables on the stack.
	decladdrs map[*ir.Name]*ssa.Value

	// starting values. Memory, stack pointer, and globals pointer
	startmem *ssa.Value
	sp       *ssa.Value
	sb       *ssa.Value
	// value representing address of where deferBits autotmp is stored
	deferBitsAddr *ssa.Value
	deferBitsTemp *ir.Name

	// line number stack. The current line number is top of stack
	line []src.XPos
	// the last line number processed; it may have been popped
	lastPos src.XPos

	// list of panic calls by function name and line number.
	// Used to deduplicate panic calls.
	panics map[funcLine]*ssa.Block

	cgoUnsafeArgs       bool
	hasdefer            bool // whether the function contains a defer statement
	softFloat           bool
	hasOpenDefers       bool // whether we are doing open-coded defers
	checkPtrEnabled     bool // whether to insert checkptr instrumentation
	instrumentEnterExit bool // whether to instrument function enter/exit
	instrumentMemory    bool // whether to instrument memory operations

	// If doing open-coded defers, list of info about the defer calls in
	// scanning order. Hence, at exit we should run these defers in reverse
	// order of this list
	openDefers []*openDeferInfo
	// For open-coded defers, this is the beginning and end blocks of the last
	// defer exit code that we have generated so far. We use these to share
	// code between exits if the shareDeferExits option (disabled by default)
	// is on.
	lastDeferExit       *ssa.Block // Entry block of last defer exit code we generated
	lastDeferFinalBlock *ssa.Block // Final block of last defer exit code we generated
	lastDeferCount      int        // Number of defers encountered at that point

	prevCall *ssa.Value // the previous call; use this to tie results to the call op.
}

type funcLine struct {
	f    *obj.LSym
	base *src.PosBase
	line uint
}

type ssaLabel struct {
	target         *ssa.Block // block identified by this label
	breakTarget    *ssa.Block // block to break to in control flow node identified by this label
	continueTarget *ssa.Block // block to continue to in control flow node identified by this label
}

// label returns the label associated with sym, creating it if necessary.
func (s *state) label(sym *types.Sym) *ssaLabel {
	lab := s.labels[sym.Name]
	if lab == nil {
		lab = new(ssaLabel)
		s.labels[sym.Name] = lab
	}
	return lab
}

func (s *state) Logf(msg string, args ...interface{}) { s.f.Logf(msg, args...) }
func (s *state) Log() bool                            { return s.f.Log() }
func (s *state) Fatalf(msg string, args ...interface{}) {
	s.f.Frontend().Fatalf(s.peekPos(), msg, args...)
}
func (s *state) Warnl(pos src.XPos, msg string, args ...interface{}) { s.f.Warnl(pos, msg, args...) }
func (s *state) Debug_checknil() bool                                { return s.f.Frontend().Debug_checknil() }

func ssaMarker(name string) *ir.Name {
	return ir.NewNameAt(base.Pos, &types.Sym{Name: name}, nil)
}

var (
	// marker node for the memory variable
	memVar = ssaMarker("mem")

	// marker nodes for temporary variables
	ptrVar       = ssaMarker("ptr")
	lenVar       = ssaMarker("len")
	capVar       = ssaMarker("cap")
	typVar       = ssaMarker("typ")
	okVar        = ssaMarker("ok")
	deferBitsVar = ssaMarker("deferBits")
	hashVar      = ssaMarker("hash")
)

// startBlock sets the current block we're generating code in to b.
func (s *state) startBlock(b *ssa.Block) {
	if s.curBlock != nil {
		s.Fatalf("starting block %v when block %v has not ended", b, s.curBlock)
	}
	s.curBlock = b
	s.vars = map[ir.Node]*ssa.Value{}
	clear(s.fwdVars)
}

// endBlock marks the end of generating code for the current block.
// Returns the (former) current block. Returns nil if there is no current
// block, i.e. if no code flows to the current execution point.
func (s *state) endBlock() *ssa.Block {
	b := s.curBlock
	if b == nil {
		return nil
	}
	for len(s.defvars) <= int(b.ID) {
		s.defvars = append(s.defvars, nil)
	}
	s.defvars[b.ID] = s.vars
	s.curBlock = nil
	s.vars = nil
	if b.LackingPos() {
		// Empty plain blocks get the line of their successor (handled after all blocks created),
		// except for increment blocks in For statements (handled in ssa conversion of OFOR),
		// and for blocks ending in GOTO/BREAK/CONTINUE.
		b.Pos = src.NoXPos
	} else {
		b.Pos = s.lastPos
	}
	return b
}

// pushLine pushes a line number on the line number stack.
func (s *state) pushLine(line src.XPos) {
	if !line.IsKnown() {
		// the frontend may emit node with line number missing,
		// use the parent line number in this case.
		line = s.peekPos()
		if base.Flag.K != 0 {
			base.Warn("buildssa: unknown position (line 0)")
		}
	} else {
		s.lastPos = line
	}

	s.line = append(s.line, line)
}

// popLine pops the top of the line number stack.
func (s *state) popLine() {
	s.line = s.line[:len(s.line)-1]
}

// peekPos peeks the top of the line number stack.
func (s *state) peekPos() src.XPos {
	return s.line[len(s.line)-1]
}

// newValue0 adds a new value with no arguments to the current block.
func (s *state) newValue0(op ssa.Op, t *types.Type) *ssa.Value {
	return s.curBlock.NewValue0(s.peekPos(), op, t)
}

// newValue0A adds a new value with no arguments and an aux value to the current block.
func (s *state) newValue0A(op ssa.Op, t *types.Type, aux ssa.Aux) *ssa.Value {
	return s.curBlock.NewValue0A(s.peekPos(), op, t, aux)
}

// newValue0I adds a new value with no arguments and an auxint value to the current block.
func (s *state) newValue0I(op ssa.Op, t *types.Type, auxint int64) *ssa.Value {
	return s.curBlock.NewValue0I(s.peekPos(), op, t, auxint)
}

// newValue1 adds a new value with one argument to the current block.
func (s *state) newValue1(op ssa.Op, t *types.Type, arg *ssa.Value) *ssa.Value {
	return s.curBlock.NewValue1(s.peekPos(), op, t, arg)
}

// newValue1A adds a new value with one argument and an aux value to the current block.
func (s *state) newValue1A(op ssa.Op, t *types.Type, aux ssa.Aux, arg *ssa.Value) *ssa.Value {
	return s.curBlock.NewValue1A(s.peekPos(), op, t, aux, arg)
}

// newValue1Apos adds a new value with one argument and an aux value to the current block.
// isStmt determines whether the created values may be a statement or not
// (i.e., false means never, yes means maybe).
func (s *state) newValue1Apos(op ssa.Op, t *types.Type, aux ssa.Aux, arg *ssa.Value, isStmt bool) *ssa.Value {
	if isStmt {
		return s.curBlock.NewValue1A(s.peekPos(), op, t, aux, arg)
	}
	return s.curBlock.NewValue1A(s.peekPos().WithNotStmt(), op, t, aux, arg)
}

// newValue1I adds a new value with one argument and an auxint value to the current block.
func (s *state) newValue1I(op ssa.Op, t *types.Type, aux int64, arg *ssa.Value) *ssa.Value {
	return s.curBlock.NewValue1I(s.peekPos(), op, t, aux, arg)
}

// newValue2 adds a new value with two arguments to the current block.
func (s *state) newValue2(op ssa.Op, t *types.Type, arg0, arg1 *ssa.Value) *ssa.Value {
	return s.curBlock.NewValue2(s.peekPos(), op, t, arg0, arg1)
}

// newValue2A adds a new value with two arguments and an aux value to the current block.
func (s *state) newValue2A(op ssa.Op, t *types.Type, aux ssa.Aux, arg0, arg1 *ssa.Value) *ssa.Value {
	return s.curBlock.NewValue2A(s.peekPos(), op, t, aux, arg0, arg1)
}

// newValue2Apos adds a new value with two arguments and an aux value to the current block.
// isStmt determines whether the created values may be a statement or not
// (i.e., false means never, yes means maybe).
func (s *state) newValue2Apos(op ssa.Op, t *types.Type, aux ssa.Aux, arg0, arg1 *ssa.Value, isStmt bool) *ssa.Value {
	if isStmt {
		return s.curBlock.NewValue2A(s.peekPos(), op, t, aux, arg0, arg1)
	}
	return s.curBlock.NewValue2A(s.peekPos().WithNotStmt(), op, t, aux, arg0, arg1)
}

// newValue2I adds a new value with two arguments and an auxint value to the current block.
func (s *state) newValue2I(op ssa.Op, t *types.Type, aux int64, arg0, arg1 *ssa.Value) *ssa.Value {
	return s.curBlock.NewValue2I(s.peekPos(), op, t, aux, arg0, arg1)
}

// newValue3 adds a new value with three arguments to the current block.
func (s *state) newValue3(op ssa.Op, t *types.Type, arg0, arg1, arg2 *ssa.Value) *ssa.Value {
	return s.curBlock.NewValue3(s.peekPos(), op, t, arg0, arg1, arg2)
}

// newValue3I adds a new value with three arguments and an auxint value to the current block.
func (s *state) newValue3I(op ssa.Op, t *types.Type, aux int64, arg0, arg1, arg2 *ssa.Value) *ssa.Value {
	return s.curBlock.NewValue3I(s.peekPos(), op, t, aux, arg0, arg1, arg2)
}

// newValue3A adds a new value with three arguments and an aux value to the current block.
func (s *state) newValue3A(op ssa.Op, t *types.Type, aux ssa.Aux, arg0, arg1, arg2 *ssa.Value) *ssa.Value {
	return s.curBlock.NewValue3A(s.peekPos(), op, t, aux, arg0, arg1, arg2)
}

// newValue3Apos adds a new value with three arguments and an aux value to the current block.
// isStmt determines whether the created values may be a statement or not
// (i.e., false means never, yes means maybe).
func (s *state) newValue3Apos(op ssa.Op, t *types.Type, aux ssa.Aux, arg0, arg1, arg2 *ssa.Value, isStmt bool) *ssa.Value {
	if isStmt {
		return s.curBlock.NewValue3A(s.peekPos(), op, t, aux, arg0, arg1, arg2)
	}
	return s.curBlock.NewValue3A(s.peekPos().WithNotStmt(), op, t, aux, arg0, arg1, arg2)
}

// newValue4 adds a new value with four arguments to the current block.
func (s *state) newValue4(op ssa.Op, t *types.Type, arg0, arg1, arg2, arg3 *ssa.Value) *ssa.Value {
	return s.curBlock.NewValue4(s.peekPos(), op, t, arg0, arg1, arg2, arg3)
}

// newValue4I adds a new value with four arguments and an auxint value to the current block.
func (s *state) newValue4I(op ssa.Op, t *types.Type, aux int64, arg0, arg1, arg2, arg3 *ssa.Value) *ssa.Value {
	return s.curBlock.NewValue4I(s.peekPos(), op, t, aux, arg0, arg1, arg2, arg3)
}

func (s *state) entryBlock() *ssa.Block {
	b := s.f.Entry
	if base.Flag.N > 0 && s.curBlock != nil {
		// If optimizations are off, allocate in current block instead. Since with -N
		// we're not doing the CSE or tighten passes, putting lots of stuff in the
		// entry block leads to O(n^2) entries in the live value map during regalloc.
		// See issue 45897.
		b = s.curBlock
	}
	return b
}

// entryNewValue0 adds a new value with no arguments to the entry block.
func (s *state) entryNewValue0(op ssa.Op, t *types.Type) *ssa.Value {
	return s.entryBlock().NewValue0(src.NoXPos, op, t)
}

// entryNewValue0A adds a new value with no arguments and an aux value to the entry block.
func (s *state) entryNewValue0A(op ssa.Op, t *types.Type, aux ssa.Aux) *ssa.Value {
	return s.entryBlock().NewValue0A(src.NoXPos, op, t, aux)
}

// entryNewValue1 adds a new value with one argument to the entry block.
func (s *state) entryNewValue1(op ssa.Op, t *types.Type, arg *ssa.Value) *ssa.Value {
	return s.entryBlock().NewValue1(src.NoXPos, op, t, arg)
}

// entryNewValue1I adds a new value with one argument and an auxint value to the entry block.
func (s *state) entryNewValue1I(op ssa.Op, t *types.Type, auxint int64, arg *ssa.Value) *ssa.Value {
	return s.entryBlock().NewValue1I(src.NoXPos, op, t, auxint, arg)
}

// entryNewValue1A adds a new value with one argument and an aux value to the entry block.
func (s *state) entryNewValue1A(op ssa.Op, t *types.Type, aux ssa.Aux, arg *ssa.Value) *ssa.Value {
	return s.entryBlock().NewValue1A(src.NoXPos, op, t, aux, arg)
}

// entryNewValue2 adds a new value with two arguments to the entry block.
func (s *state) entryNewValue2(op ssa.Op, t *types.Type, arg0, arg1 *ssa.Value) *ssa.Value {
	return s.entryBlock().NewValue2(src.NoXPos, op, t, arg0, arg1)
}

// entryNewValue2A adds a new value with two arguments and an aux value to the entry block.
func (s *state) entryNewValue2A(op ssa.Op, t *types.Type, aux ssa.Aux, arg0, arg1 *ssa.Value) *ssa.Value {
	return s.entryBlock().NewValue2A(src.NoXPos, op, t, aux, arg0, arg1)
}

// const* routines add a new const value to the entry block.
func (s *state) constSlice(t *types.Type) *ssa.Value {
	return s.f.ConstSlice(t)
}
func (s *state) constInterface(t *types.Type) *ssa.Value {
	return s.f.ConstInterface(t)
}
func (s *state) constNil(t *types.Type) *ssa.Value { return s.f.ConstNil(t) }
func (s *state) constEmptyString(t *types.Type) *ssa.Value {
	return s.f.ConstEmptyString(t)
}
func (s *state) constBool(c bool) *ssa.Value {
	return s.f.ConstBool(types.Types[types.TBOOL], c)
}
func (s *state) constInt8(t *types.Type, c int8) *ssa.Value {
	return s.f.ConstInt8(t, c)
}
func (s *state) constInt16(t *types.Type, c int16) *ssa.Value {
	return s.f.ConstInt16(t, c)
}
func (s *state) constInt32(t *types.Type, c int32) *ssa.Value {
	return s.f.ConstInt32(t, c)
}
func (s *state) constInt64(t *types.Type, c int64) *ssa.Value {
	return s.f.ConstInt64(t, c)
}
func (s *state) constFloat32(t *types.Type, c float64) *ssa.Value {
	return s.f.ConstFloat32(t, c)
}
func (s *state) constFloat64(t *types.Type, c float64) *ssa.Value {
	return s.f.ConstFloat64(t, c)
}
func (s *state) constInt(t *types.Type, c int64) *ssa.Value {
	if s.config.PtrSize == 8 {
		return s.constInt64(t, c)
	}
	if int64(int32(c)) != c {
		s.Fatalf("integer constant too big %d", c)
	}
	return s.constInt32(t, int32(c))
}
func (s *state) constOffPtrSP(t *types.Type, c int64) *ssa.Value {
	return s.f.ConstOffPtrSP(t, c, s.sp)
}

// newValueOrSfCall* are wrappers around newValue*, which may create a call to a
// soft-float runtime function instead (when emitting soft-float code).
func (s *state) newValueOrSfCall1(op ssa.Op, t *types.Type, arg *ssa.Value) *ssa.Value {
	if s.softFloat {
		if c, ok := s.sfcall(op, arg); ok {
			return c
		}
	}
	return s.newValue1(op, t, arg)
}
func (s *state) newValueOrSfCall2(op ssa.Op, t *types.Type, arg0, arg1 *ssa.Value) *ssa.Value {
	if s.softFloat {
		if c, ok := s.sfcall(op, arg0, arg1); ok {
			return c
		}
	}
	return s.newValue2(op, t, arg0, arg1)
}

type instrumentKind uint8

const (
	instrumentRead = iota
	instrumentWrite
	instrumentMove
)

func (s *state) instrument(t *types.Type, addr *ssa.Value, kind instrumentKind) {
	s.instrument2(t, addr, nil, kind)
}

// instrumentFields instruments a read/write operation on addr.
// If it is instrumenting for MSAN or ASAN and t is a struct type, it instruments
// operation for each field, instead of for the whole struct.
func (s *state) instrumentFields(t *types.Type, addr *ssa.Value, kind instrumentKind) {
	if !(base.Flag.MSan || base.Flag.ASan) || !t.IsStruct() {
		s.instrument(t, addr, kind)
		return
	}
	for _, f := range t.Fields() {
		if f.Sym.IsBlank() {
			continue
		}
		offptr := s.newValue1I(ssa.OpOffPtr, types.NewPtr(f.Type), f.Offset, addr)
		s.instrumentFields(f.Type, offptr, kind)
	}
}

func (s *state) instrumentMove(t *types.Type, dst, src *ssa.Value) {
	if base.Flag.MSan {
		s.instrument2(t, dst, src, instrumentMove)
	} else {
		s.instrument(t, src, instrumentRead)
		s.instrument(t, dst, instrumentWrite)
	}
}

func (s *state) instrument2(t *types.Type, addr, addr2 *ssa.Value, kind instrumentKind) {
	if !s.instrumentMemory {
		return
	}

	w := t.Size()
	if w == 0 {
		return // can't race on zero-sized things
	}

	if ssa.IsSanitizerSafeAddr(addr) {
		return
	}

	var fn *obj.LSym
	needWidth := false

	if addr2 != nil && kind != instrumentMove {
		panic("instrument2: non-nil addr2 for non-move instrumentation")
	}

	if base.Flag.MSan {
		switch kind {
		case instrumentRead:
			fn = ir.Syms.Msanread
		case instrumentWrite:
			fn = ir.Syms.Msanwrite
		case instrumentMove:
			fn = ir.Syms.Msanmove
		default:
			panic("unreachable")
		}
		needWidth = true
	} else if base.Flag.Race && t.NumComponents(types.CountBlankFields) > 1 {
		// for composite objects we have to write every address
		// because a write might happen to any subobject.
		// composites with only one element don't have subobjects, though.
		switch kind {
		case instrumentRead:
			fn = ir.Syms.Racereadrange
		case instrumentWrite:
			fn = ir.Syms.Racewriterange
		default:
			panic("unreachable")
		}
		needWidth = true
	} else if base.Flag.Race {
		// for non-composite objects we can write just the start
		// address, as any write must write the first byte.
		switch kind {
		case instrumentRead:
			fn = ir.Syms.Raceread
		case instrumentWrite:
			fn = ir.Syms.Racewrite
		default:
			panic("unreachable")
		}
	} else if base.Flag.ASan {
		switch kind {
		case instrumentRead:
			fn = ir.Syms.Asanread
		case instrumentWrite:
			fn = ir.Syms.Asanwrite
		default:
			panic("unreachable")
		}
		needWidth = true
	} else {
		panic("unreachable")
	}

	args := []*ssa.Value{addr}
	if addr2 != nil {
		args = append(args, addr2)
	}
	if needWidth {
		args = append(args, s.constInt(types.Types[types.TUINTPTR], w))
	}
	s.rtcall(fn, true, nil, args...)
}

func (s *state) load(t *types.Type, src *ssa.Value) *ssa.Value {
	s.instrumentFields(t, src, instrumentRead)
	return s.rawLoad(t, src)
}

func (s *state) rawLoad(t *types.Type, src *ssa.Value) *ssa.Value {
	return s.newValue2(ssa.OpLoad, t, src, s.mem())
}

func (s *state) store(t *types.Type, dst, val *ssa.Value) {
	s.vars[memVar] = s.newValue3A(ssa.OpStore, types.TypeMem, t, dst, val, s.mem())
}

func (s *state) zero(t *types.Type, dst *ssa.Value) {
	s.instrument(t, dst, instrumentWrite)
	store := s.newValue2I(ssa.OpZero, types.TypeMem, t.Size(), dst, s.mem())
	store.Aux = t
	s.vars[memVar] = store
}

func (s *state) move(t *types.Type, dst, src *ssa.Value) {
	s.moveWhichMayOverlap(t, dst, src, false)
}
func (s *state) moveWhichMayOverlap(t *types.Type, dst, src *ssa.Value, mayOverlap bool) {
	s.instrumentMove(t, dst, src)
	if mayOverlap && t.IsArray() && t.NumElem() > 1 && !ssa.IsInlinableMemmove(dst, src, t.Size(), s.f.Config) {
		// Normally, when moving Go values of type T from one location to another,
		// we don't need to worry about partial overlaps. The two Ts must either be
		// in disjoint (nonoverlapping) memory or in exactly the same location.
		// There are 2 cases where this isn't true:
		//  1) Using unsafe you can arrange partial overlaps.
		//  2) Since Go 1.17, you can use a cast from a slice to a ptr-to-array.
		//     https://go.dev/ref/spec#Conversions_from_slice_to_array_pointer
		//     This feature can be used to construct partial overlaps of array types.
		//       var a [3]int
		//       p := (*[2]int)(a[:])
		//       q := (*[2]int)(a[1:])
		//       *p = *q
		// We don't care about solving 1. Or at least, we haven't historically
		// and no one has complained.
		// For 2, we need to ensure that if there might be partial overlap,
		// then we can't use OpMove; we must use memmove instead.
		// (memmove handles partial overlap by copying in the correct
		// direction. OpMove does not.)
		//
		// Note that we have to be careful here not to introduce a call when
		// we're marshaling arguments to a call or unmarshaling results from a call.
		// Cases where this is happening must pass mayOverlap to false.
		// (Currently this only happens when unmarshaling results of a call.)
		if t.HasPointers() {
			s.rtcall(ir.Syms.Typedmemmove, true, nil, s.reflectType(t), dst, src)
			// We would have otherwise implemented this move with straightline code,
			// including a write barrier. Pretend we issue a write barrier here,
			// so that the write barrier tests work. (Otherwise they'd need to know
			// the details of IsInlineableMemmove.)
			s.curfn.SetWBPos(s.peekPos())
		} else {
			s.rtcall(ir.Syms.Memmove, true, nil, dst, src, s.constInt(types.Types[types.TUINTPTR], t.Size()))
		}
		ssa.LogLargeCopy(s.f.Name, s.peekPos(), t.Size())
		return
	}
	store := s.newValue3I(ssa.OpMove, types.TypeMem, t.Size(), dst, src, s.mem())
	store.Aux = t
	s.vars[memVar] = store
}

// stmtList converts the statement list n to SSA and adds it to s.
func (s *state) stmtList(l ir.Nodes) {
	for _, n := range l {
		s.stmt(n)
	}
}

// stmt converts the statement n to SSA and adds it to s.
func (s *state) stmt(n ir.Node) {
	s.pushLine(n.Pos())
	defer s.popLine()

	// If s.curBlock is nil, and n isn't a label (which might have an associated goto somewhere),
	// then this code is dead. Stop here.
	if s.curBlock == nil && n.Op() != ir.OLABEL {
		return
	}

	s.stmtList(n.Init())
	switch n.Op() {

	case ir.OBLOCK:
		n := n.(*ir.BlockStmt)
		s.stmtList(n.List)

	case ir.OFALL: // no-op

	// Expression statements
	case ir.OCALLFUNC:
		n := n.(*ir.CallExpr)
		if ir.IsIntrinsicCall(n) {
			s.intrinsicCall(n)
			return
		}
		fallthrough

	case ir.OCALLINTER:
		n := n.(*ir.CallExpr)
		s.callResult(n, callNormal)
		if n.Op() == ir.OCALLFUNC && n.Fun.Op() == ir.ONAME && n.Fun.(*ir.Name).Class == ir.PFUNC {
			if fn := n.Fun.Sym().Name; base.Flag.CompilingRuntime && fn == "throw" ||
				n.Fun.Sym().Pkg == ir.Pkgs.Runtime &&
					(fn == "throwinit" || fn == "gopanic" || fn == "panicwrap" || fn == "block" ||
						fn == "panicmakeslicelen" || fn == "panicmakeslicecap" || fn == "panicunsafeslicelen" ||
						fn == "panicunsafeslicenilptr" || fn == "panicunsafestringlen" || fn == "panicunsafestringnilptr" ||
						fn == "panicrangestate") {
				m := s.mem()
				b := s.endBlock()
				b.Kind = ssa.BlockExit
				b.SetControl(m)
				// TODO: never rewrite OPANIC to OCALLFUNC in the
				// first place. Need to wait until all backends
				// go through SSA.
			}
		}
	case ir.ODEFER:
		n := n.(*ir.GoDeferStmt)
		if base.Debug.Defer > 0 {
			var defertype string
			if s.hasOpenDefers {
				defertype = "open-coded"
			} else if n.Esc() == ir.EscNever {
				defertype = "stack-allocated"
			} else {
				defertype = "heap-allocated"
			}
			base.WarnfAt(n.Pos(), "%s defer", defertype)
		}
		if s.hasOpenDefers {
			s.openDeferRecord(n.Call.(*ir.CallExpr))
		} else {
			d := callDefer
			if n.Esc() == ir.EscNever && n.DeferAt == nil {
				d = callDeferStack
			}
			s.call(n.Call.(*ir.CallExpr), d, false, n.DeferAt)
		}
	case ir.OGO:
		n := n.(*ir.GoDeferStmt)
		s.callResult(n.Call.(*ir.CallExpr), callGo)

	case ir.OAS2DOTTYPE:
		n := n.(*ir.AssignListStmt)
		var res, resok *ssa.Value
		if n.Rhs[0].Op() == ir.ODOTTYPE2 {
			res, resok = s.dottype(n.Rhs[0].(*ir.TypeAssertExpr), true)
		} else {
			res, resok = s.dynamicDottype(n.Rhs[0].(*ir.DynamicTypeAssertExpr), true)
		}
		deref := false
		if !ssa.CanSSA(n.Rhs[0].Type()) {
			if res.Op != ssa.OpLoad {
				s.Fatalf("dottype of non-load")
			}
			mem := s.mem()
			if res.Args[1] != mem {
				s.Fatalf("memory no longer live from 2-result dottype load")
			}
			deref = true
			res = res.Args[0]
		}
		s.assign(n.Lhs[0], res, deref, 0)
		s.assign(n.Lhs[1], resok, false, 0)
		return

	case ir.OAS2FUNC:
		// We come here only when it is an intrinsic call returning two values.
		n := n.(*ir.AssignListStmt)
		call := n.Rhs[0].(*ir.CallExpr)
		if !ir.IsIntrinsicCall(call) {
			s.Fatalf("non-intrinsic AS2FUNC not expanded %v", call)
		}
		v := s.intrinsicCall(call)
		v1 := s.newValue1(ssa.OpSelect0, n.Lhs[0].Type(), v)
		v2 := s.newValue1(ssa.OpSelect1, n.Lhs[1].Type(), v)
		s.assign(n.Lhs[0], v1, false, 0)
		s.assign(n.Lhs[1], v2, false, 0)
		return

	case ir.ODCL:
		n := n.(*ir.Decl)
		if v := n.X; v.Esc() == ir.EscHeap {
			s.newHeapaddr(v)
		}

	case ir.OLABEL:
		n := n.(*ir.LabelStmt)
		sym := n.Label
		if sym.IsBlank() {
			// Nothing to do because the label isn't targetable. See issue 52278.
			break
		}
		lab := s.label(sym)

		// The label might already have a target block via a goto.
		if lab.target == nil {
			lab.target = s.f.NewBlock(ssa.BlockPlain)
		}

		// Go to that label.
		// (We pretend "label:" is preceded by "goto label", unless the predecessor is unreachable.)
		if s.curBlock != nil {
			b := s.endBlock()
			b.AddEdgeTo(lab.target)
		}
		s.startBlock(lab.target)

	case ir.OGOTO:
		n := n.(*ir.BranchStmt)
		sym := n.Label

		lab := s.label(sym)
		if lab.target == nil {
			lab.target = s.f.NewBlock(ssa.BlockPlain)
		}

		b := s.endBlock()
		b.Pos = s.lastPos.WithIsStmt() // Do this even if b is an empty block.
		b.AddEdgeTo(lab.target)

	case ir.OAS:
		n := n.(*ir.AssignStmt)
		if n.X == n.Y && n.X.Op() == ir.ONAME {
			// An x=x assignment. No point in doing anything
			// here. In addition, skipping this assignment
			// prevents generating:
			//   VARDEF x
			//   COPY x -> x
			// which is bad because x is incorrectly considered
			// dead before the vardef. See issue #14904.
			return
		}

		// mayOverlap keeps track of whether the LHS and RHS might
		// refer to partially overlapping memory. Partial overlapping can
		// only happen for arrays, see the comment in moveWhichMayOverlap.
		//
		// If both sides of the assignment are not dereferences, then partial
		// overlap can't happen. Partial overlap can only occur only when the
		// arrays referenced are strictly smaller parts of the same base array.
		// If one side of the assignment is a full array, then partial overlap
		// can't happen. (The arrays are either disjoint or identical.)
		mayOverlap := n.X.Op() == ir.ODEREF && (n.Y != nil && n.Y.Op() == ir.ODEREF)
		if n.Y != nil && n.Y.Op() == ir.ODEREF {
			p := n.Y.(*ir.StarExpr).X
			for p.Op() == ir.OCONVNOP {
				p = p.(*ir.ConvExpr).X
			}
			if p.Op() == ir.OSPTR && p.(*ir.UnaryExpr).X.Type().IsString() {
				// Pointer fields of strings point to unmodifiable memory.
				// That memory can't overlap with the memory being written.
				mayOverlap = false
			}
		}

		// Evaluate RHS.
		rhs := n.Y
		if rhs != nil {
			switch rhs.Op() {
			case ir.OSTRUCTLIT, ir.OARRAYLIT, ir.OSLICELIT:
				// All literals with nonzero fields have already been
				// rewritten during walk. Any that remain are just T{}
				// or equivalents. Use the zero value.
				if !ir.IsZero(rhs) {
					s.Fatalf("literal with nonzero value in SSA: %v", rhs)
				}
				rhs = nil
			case ir.OAPPEND:
				rhs := rhs.(*ir.CallExpr)
				// Check whether we're writing the result of an append back to the same slice.
				// If so, we handle it specially to avoid write barriers on the fast
				// (non-growth) path.
				if !ir.SameSafeExpr(n.X, rhs.Args[0]) || base.Flag.N != 0 {
					break
				}
				// If the slice can be SSA'd, it'll be on the stack,
				// so there will be no write barriers,
				// so there's no need to attempt to prevent them.
				if s.canSSA(n.X) {
					if base.Debug.Append > 0 { // replicating old diagnostic message
						base.WarnfAt(n.Pos(), "append: len-only update (in local slice)")
					}
					break
				}
				if base.Debug.Append > 0 {
					base.WarnfAt(n.Pos(), "append: len-only update")
				}
				s.append(rhs, true)
				return
			}
		}

		if ir.IsBlank(n.X) {
			// _ = rhs
			// Just evaluate rhs for side-effects.
			if rhs != nil {
				s.expr(rhs)
			}
			return
		}

		var t *types.Type
		if n.Y != nil {
			t = n.Y.Type()
		} else {
			t = n.X.Type()
		}

		var r *ssa.Value
		deref := !ssa.CanSSA(t)
		if deref {
			if rhs == nil {
				r = nil // Signal assign to use OpZero.
			} else {
				r = s.addr(rhs)
			}
		} else {
			if rhs == nil {
				r = s.zeroVal(t)
			} else {
				r = s.expr(rhs)
			}
		}

		var skip skipMask
		if rhs != nil && (rhs.Op() == ir.OSLICE || rhs.Op() == ir.OSLICE3 || rhs.Op() == ir.OSLICESTR) && ir.SameSafeExpr(rhs.(*ir.SliceExpr).X, n.X) {
			// We're assigning a slicing operation back to its source.
			// Don't write back fields we aren't changing. See issue #14855.
			rhs := rhs.(*ir.SliceExpr)
			i, j, k := rhs.Low, rhs.High, rhs.Max
			if i != nil && (i.Op() == ir.OLITERAL && i.Val().Kind() == constant.Int && ir.Int64Val(i) == 0) {
				// [0:...] is the same as [:...]
				i = nil
			}
			// TODO: detect defaults for len/cap also.
			// Currently doesn't really work because (*p)[:len(*p)] appears here as:
			//    tmp = len(*p)
			//    (*p)[:tmp]
			// if j != nil && (j.Op == OLEN && SameSafeExpr(j.Left, n.Left)) {
			//      j = nil
			// }
			// if k != nil && (k.Op == OCAP && SameSafeExpr(k.Left, n.Left)) {
			//      k = nil
			// }
			if i == nil {
				skip |= skipPtr
				if j == nil {
					skip |= skipLen
				}
				if k == nil {
					skip |= skipCap
				}
			}
		}

		s.assignWhichMayOverlap(n.X, r, deref, skip, mayOverlap)

	case ir.OIF:
		n := n.(*ir.IfStmt)
		if ir.IsConst(n.Cond, constant.Bool) {
			s.stmtList(n.Cond.Init())
			if ir.BoolVal(n.Cond) {
				s.stmtList(n.Body)
			} else {
				s.stmtList(n.Else)
			}
			break
		}

		bEnd := s.f.NewBlock(ssa.BlockPlain)
		var likely int8
		if n.Likely {
			likely = 1
		}
		var bThen *ssa.Block
		if len(n.Body) != 0 {
			bThen = s.f.NewBlock(ssa.BlockPlain)
		} else {
			bThen = bEnd
		}
		var bElse *ssa.Block
		if len(n.Else) != 0 {
			bElse = s.f.NewBlock(ssa.BlockPlain)
		} else {
			bElse = bEnd
		}
		s.condBranch(n.Cond, bThen, bElse, likely)

		if len(n.Body) != 0 {
			s.startBlock(bThen)
			s.stmtList(n.Body)
			if b := s.endBlock(); b != nil {
				b.AddEdgeTo(bEnd)
			}
		}
		if len(n.Else) != 0 {
			s.startBlock(bElse)
			s.stmtList(n.Else)
			if b := s.endBlock(); b != nil {
				b.AddEdgeTo(bEnd)
			}
		}
		s.startBlock(bEnd)

	case ir.ORETURN:
		n := n.(*ir.ReturnStmt)
		s.stmtList(n.Results)
		b := s.exit()
		b.Pos = s.lastPos.WithIsStmt()

	case ir.OTAILCALL:
		n := n.(*ir.TailCallStmt)
		s.callResult(n.Call, callTail)
		call := s.mem()
		b := s.endBlock()
		b.Kind = ssa.BlockRetJmp // could use BlockExit. BlockRetJmp is mostly for clarity.
		b.SetControl(call)

	case ir.OCONTINUE, ir.OBREAK:
		n := n.(*ir.BranchStmt)
		var to *ssa.Block
		if n.Label == nil {
			// plain break/continue
			switch n.Op() {
			case ir.OCONTINUE:
				to = s.continueTo
			case ir.OBREAK:
				to = s.breakTo
			}
		} else {
			// labeled break/continue; look up the target
			sym := n.Label
			lab := s.label(sym)
			switch n.Op() {
			case ir.OCONTINUE:
				to = lab.continueTarget
			case ir.OBREAK:
				to = lab.breakTarget
			}
		}

		b := s.endBlock()
		b.Pos = s.lastPos.WithIsStmt() // Do this even if b is an empty block.
		b.AddEdgeTo(to)

	case ir.OFOR:
		// OFOR: for Ninit; Left; Right { Nbody }
		// cond (Left); body (Nbody); incr (Right)
		n := n.(*ir.ForStmt)
		base.Assert(!n.DistinctVars) // Should all be rewritten before escape analysis
		bCond := s.f.NewBlock(ssa.BlockPlain)
		bBody := s.f.NewBlock(ssa.BlockPlain)
		bIncr := s.f.NewBlock(ssa.BlockPlain)
		bEnd := s.f.NewBlock(ssa.BlockPlain)

		// ensure empty for loops have correct position; issue #30167
		bBody.Pos = n.Pos()

		// first, jump to condition test
		b := s.endBlock()
		b.
```