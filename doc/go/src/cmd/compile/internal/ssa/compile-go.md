Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Initial Understanding of the Context:** The comment at the top clearly states this is a part of the Go compiler, specifically within the SSA (Static Single Assignment) package, and the file `compile.go`. This immediately tells us we're dealing with the core optimization and code generation pipeline of the Go compiler.

2. **Identifying the Core Function:** The most prominent function is `Compile(f *Func)`. The comment block preceding it is crucial. It states the main goals of this function:
    * Transform SSA values to 0 or 1 assembly instructions.
    * Order blocks for emission.
    * Order values within blocks for emission.
    * Ensure a non-nil `regAlloc` field, indicating register allocation has been performed.

3. **Analyzing the Function's Structure:**  The `Compile` function follows a clear pattern:
    * **Initialization:** Logging, random seed generation (for testing), and a `defer` block to handle panics and provide debug information.
    * **Pass Execution Loop:** A `for` loop iterates through a slice called `passes`. This is a strong indicator of a multi-stage compilation process.
    * **Pass-Specific Actions:** Inside the loop, each pass has a `fn` field, which is a function that modifies the `*Func`. There's also logging, timing, and conditional dumping based on flags.
    * **Finalization:** Handling rule matches and resetting the `phaseName` for the `defer` function.

4. **Deconstructing the Pass Structure:** The `pass` struct is defined, revealing the attributes of each compilation phase: `name`, `fn`, `required`, `disabled`, `time`, `mem`, `stats`, `debug`, `test`, and `dump`. This provides insight into the different types of operations performed during compilation. The `addDump` and `String` methods are helper functions for this struct.

5. **Understanding the `PhaseOption` Function:** This function is responsible for handling command-line flags related to SSA compilation phases. Its logic involves parsing the phase name and flag, then modifying the corresponding `pass` structure. The detailed help message within this function is very informative.

6. **Identifying Key Data Structures:**
    * `Func`:  Represents the function being compiled in SSA form. It's the central object modified by the passes.
    * `Block`: Represents a basic block in the control flow graph.
    * `Value`: Represents an operation or a value in SSA form.
    * `passes`:  The slice of `pass` structs, defining the sequence of compilation phases.

7. **Inferring Functionality based on Pass Names:**  The names of the passes in the `passes` slice are very telling: "deadcode", "cse", "phiopt", "nilcheckelim", "prove", "fuse", "lower", "regalloc", "schedule", etc. These are standard compiler optimization and code generation techniques.

8. **Inferring the Overall Compilation Process:**  Based on the passes, the general flow is:
    * **Initial Setup:** Numbering lines, basic cleanup.
    * **High-Level Optimizations:**  Dead code elimination, common subexpression elimination, phi node optimization, nil check elimination, loop invariant code motion (implied by "prove").
    * **Lowering to Target Architecture:** Expanding calls, decomposing builtins, handling floating-point operations, address mode selection, register allocation.
    * **Scheduling and Layout:** Ordering instructions and basic blocks for efficient execution.
    * **Final Cleanup:** Removing empty blocks.

9. **Connecting to Go Language Features:**  The optimizations and transformations performed in these passes are essential for efficiently compiling various Go language features. For instance:
    * **`nilcheckelim`:** Directly related to the safety of pointer dereferences in Go.
    * **`expand calls`:** Handles inlining and other call-related optimizations.
    * **`softfloat`:**  Might be relevant for architectures without native floating-point support.
    * **`writebarrier`:**  Crucial for the Go garbage collector.
    * **`insert resched checks`:**  Related to goroutine preemption.

10. **Considering Error Points and Usage:** The `PhaseOption` function, with its complex parsing and numerous flags, is a likely source of user errors. For example, typos in phase or flag names, or incorrect value specifications. The help message attempts to mitigate this.

11. **Formulating Examples:**  Based on the pass names and the `PhaseOption` documentation, we can construct example Go code and demonstrate how certain passes might affect it. The examples focusing on nil checks and loop optimizations are relevant given the presence of `nilcheckelim` and `insert resched checks`.

12. **Review and Refine:**  After drafting the initial analysis, it's important to review the code snippet again, paying attention to details like the `checkEnabled` flag, the `HTMLWriter`, and the `dumpFile` functionality. This helps in providing a more complete and accurate picture. The `passOrder` constraints are also an important detail to note.

This systematic approach, starting from high-level understanding and gradually drilling down into details, helps in effectively analyzing and explaining the functionality of a complex piece of code like the provided Go compiler snippet.这段代码是 Go 语言编译器中 SSA（Static Single Assignment）中间表示的编译过程的核心部分。它定义了编译的主要入口点 `Compile` 函数，以及一系列用于组织和执行编译优化的“pass”。

**功能列举:**

1. **SSA 编译主入口:** `Compile(f *Func)` 是将 Go 函数的 SSA 表示形式转换为目标架构机器指令的关键函数。
2. **编译阶段组织:**  通过 `passes` 变量定义了一系列编译阶段（pass），每个阶段都执行特定的优化或转换。
3. **编译阶段执行:** `Compile` 函数遍历 `passes`，依次执行每个编译阶段的 `fn` 函数。
4. **编译阶段控制:**  通过 `PhaseOption` 函数可以控制各个编译阶段的开启、关闭、调试信息输出等行为，这通常通过命令行参数 `-d=ssa/...` 实现。
5. **性能分析:**  可以记录每个编译阶段的执行时间和内存分配情况（通过 `time` 和 `mem` 字段）。
6. **调试支持:**  支持在每个阶段前后 dump (输出) SSA 中间表示，方便调试和理解编译器的行为。
7. **一致性检查:**  在每个编译阶段后可以进行一致性检查 (`checkEnabled`)，以确保 SSA 表示的正确性。
8. **随机化测试:**  在测试模式下，可以随机化基本块中值的顺序，以发现编译器对值顺序的依赖性问题。
9. **错误处理:**  包含 `defer` 机制来捕获编译过程中的 panic，并输出详细的错误信息，包括当前的编译阶段和堆栈信息。
10. **生成 HTML 报告:** 可以将每个编译阶段的中间结果输出到 HTML 文件，用于可视化编译过程。

**推断的 Go 语言功能实现 (结合代码推理和假设):**

这段代码的核心目标是优化 Go 代码的性能，并将其转换为可执行的机器码。它涵盖了许多经典的编译器优化技术。我们可以推断出一些它可能涉及的 Go 语言特性，并用代码示例说明。

**假设输入:**  一个简单的 Go 函数，例如：

```go
package main

func add(a int, b int) int {
	sum := a + b
	return sum
}

func main() {
	x := 10
	y := 20
	z := add(x, y)
	println(z)
}
```

**编译过程推断 (部分):**

1. **`number lines`:**  为 SSA 中的值和块分配行号，方便调试和错误报告。
2. **`early phielim and copyelim`:**  消除早期的 phi 函数和复制操作。如果 `add` 函数被内联到 `main` 中，可能会有临时的赋值操作，这个阶段会清理它们。
3. **`early deadcode`:** 移除未使用的代码。如果 `add` 函数没有被使用，这个阶段可能会移除它。
4. **`opt`:**  执行各种通用优化，例如常量折叠。如果 `x` 和 `y` 是常量，`a + b` 可能会在编译时计算出来。
5. **`generic cse`:**  进行通用公共子表达式消除。如果在多个地方计算了相同的表达式，这个阶段会将其合并。
6. **`nilcheckelim`:**  消除不必要的 nil 指针检查。
7. **`expand calls`:**  展开函数调用，例如内联。 如果 `add` 函数被认为足够小且适合内联，这个阶段会将其内联到 `main` 函数中。
8. **`lower`:**  将高层次的 SSA 操作转换为更接近目标机器的操作。例如，将加法操作转换为目标架构的加法指令。
9. **`regalloc`:**  进行寄存器分配，将 SSA 中的值分配到目标机器的寄存器中。
10. **`schedule`:**  安排指令的执行顺序，以提高流水线效率。

**Go 代码示例 (展示 `nilcheckelim` 的潜在影响):**

```go
package main

func mightBeNil() *int {
	return nil // 假设在某些情况下返回 nil
}

func main() {
	p := mightBeNil()
	if p != nil {
		println(*p)
	}
}
```

**假设输入:** 上面的 `main` 函数。

**`nilcheckelim` 的可能操作:**  如果编译器通过静态分析能够确定 `p` 在 `println(*p)` 处不可能为 `nil` (例如，`mightBeNil` 函数的实现总是返回非 nil 值，或者有更复杂的控制流分析)，那么 `nilcheckelim` 阶段可能会移除 `if p != nil` 的检查，直接生成 `println(*p)` 的代码。

**可能输出 (优化后，`nilcheckelim` 移除检查):**

```assembly
// ... (其他指令)
MOVQ    "".p+8(SP), AX // 将 p 的值加载到 AX 寄存器
// 假设编译器确定 p 不会是 nil，则可能直接访问 *p
MOVQ    (AX), BX       // 将 AX 指向的值加载到 BX 寄存器
// ... (打印 BX 的指令)
```

**命令行参数的具体处理 (`PhaseOption` 函数):**

`PhaseOption` 函数负责解析和应用与 SSA 编译阶段相关的命令行参数，这些参数通常通过 `go tool compile -d=ssa/...` 的形式传递。

**参数格式:** `-d=ssa/<phase>/<flag>[=<value>|<function_name>]`

* **`<phase>`:**  指定要操作的编译阶段的名称，例如 `opt`, `nilcheckelim`, `regalloc` 等。可以使用 `check`, `all`, `build`, `intrinsics`, `genssa` 等特殊值来影响多个阶段或特定模块。
* **`<flag>`:**  指定要设置的标志，常见的有：
    * `on`: 启用该阶段 (`val != 0`)。
    * `off`: 禁用该阶段 (`val == 0`)。
    * `time`: 报告该阶段的执行时间。
    * `mem`: 报告该阶段的内存使用情况。
    * `debug`: 设置该阶段的调试级别 (`val`)。
    * `stats`:  启用该阶段的统计信息输出。
    * `test`: 启用该阶段的特定测试功能。
    * `dump`:  在该阶段之后 dump 指定的函数 (`function_name`) 的 SSA 表示。
    * `seed`: 为检查阶段设置随机种子。
* **`<value>`:**  某些标志（如 `debug`, `seed`) 需要一个整数值。如果省略，则默认为 1。
* **`<function_name>`:**  `dump` 标志需要指定要 dump 的函数名称。

**示例:**

* `-d=ssa/opt/on`: 启用 `opt` 优化阶段。
* `-d=ssa/nilcheckelim/off`: 禁用 `nilcheckelim` 阶段。
* `-d=ssa/regalloc/time`: 报告 `regalloc` 阶段的执行时间。
* `-d=ssa/prove/debug=2`: 将 `prove` 阶段的调试级别设置为 2。
* `-d=ssa/all/time`: 报告所有编译阶段的执行时间。
* `-d=ssa/lower/dump=main.add`: 在 `lower` 阶段之后 dump `main` 包中的 `add` 函数的 SSA 表示。
* `-d=ssa/check/on`: 启用所有编译阶段后的一致性检查。

**使用者易犯错的点:**

1. **拼写错误:**  阶段名称或标志名称拼写错误会导致参数无效，编译器可能不会报错或者给出难以理解的错误信息。
    * **错误示例:** `-d=ssa/optt/on` (错误的阶段名 `optt`)
2. **标志和阶段不匹配:**  某些标志只对特定的阶段有效，对其他阶段使用可能没有效果或者导致错误。
    * **错误示例:** `-d=ssa/layout/debug=2` (可能 `layout` 阶段没有 `debug` 标志)
3. **缺少必要的值:**  对于需要值的标志，忘记提供值会导致解析错误。
    * **错误示例:** `-d=ssa/prove/debug` (缺少调试级别的值)
4. **`dump` 标志不指定函数名:** 使用 `dump` 标志时必须指定要 dump 的函数名称。
    * **错误示例:** `-d=ssa/lower/dump`
5. **正则表达式错误:** 在使用 `~` 开头的正则表达式匹配阶段名称时，如果正则表达式本身存在语法错误，会导致参数解析失败。
    * **错误示例:** `-d='ssa/~(*scc$/off'` (正则表达式语法错误)
6. **误解 `all` 阶段的作用域:**  `ssa/all/time` 等选项会影响 *所有* 的 SSA 编译阶段，可能会产生大量的输出。
7. **不理解阶段的依赖关系:**  随意开启或关闭某些阶段可能会导致编译错误或生成非最优的代码，因为某些阶段依赖于其他阶段的输出。

这段代码是 Go 编译器优化的核心，理解它的功能和配置对于深入了解 Go 编译过程和进行性能调优非常有帮助。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/compile.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/internal/src"
	"fmt"
	"hash/crc32"
	"internal/buildcfg"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Compile is the main entry point for this package.
// Compile modifies f so that on return:
//   - all Values in f map to 0 or 1 assembly instructions of the target architecture
//   - the order of f.Blocks is the order to emit the Blocks
//   - the order of b.Values is the order to emit the Values in each Block
//   - f has a non-nil regAlloc field
func Compile(f *Func) {
	// TODO: debugging - set flags to control verbosity of compiler,
	// which phases to dump IR before/after, etc.
	if f.Log() {
		f.Logf("compiling %s\n", f.Name)
	}

	var rnd *rand.Rand
	if checkEnabled {
		seed := int64(crc32.ChecksumIEEE(([]byte)(f.Name))) ^ int64(checkRandSeed)
		rnd = rand.New(rand.NewSource(seed))
	}

	// hook to print function & phase if panic happens
	phaseName := "init"
	defer func() {
		if phaseName != "" {
			err := recover()
			stack := make([]byte, 16384)
			n := runtime.Stack(stack, false)
			stack = stack[:n]
			if f.HTMLWriter != nil {
				f.HTMLWriter.flushPhases()
			}
			f.Fatalf("panic during %s while compiling %s:\n\n%v\n\n%s\n", phaseName, f.Name, err, stack)
		}
	}()

	// Run all the passes
	if f.Log() {
		printFunc(f)
	}
	f.HTMLWriter.WritePhase("start", "start")
	if BuildDump[f.Name] {
		f.dumpFile("build")
	}
	if checkEnabled {
		checkFunc(f)
	}
	const logMemStats = false
	for _, p := range passes {
		if !f.Config.optimize && !p.required || p.disabled {
			continue
		}
		f.pass = &p
		phaseName = p.name
		if f.Log() {
			f.Logf("  pass %s begin\n", p.name)
		}
		// TODO: capture logging during this pass, add it to the HTML
		var mStart runtime.MemStats
		if logMemStats || p.mem {
			runtime.ReadMemStats(&mStart)
		}

		if checkEnabled && !f.scheduled {
			// Test that we don't depend on the value order, by randomizing
			// the order of values in each block. See issue 18169.
			for _, b := range f.Blocks {
				for i := 0; i < len(b.Values)-1; i++ {
					j := i + rnd.Intn(len(b.Values)-i)
					b.Values[i], b.Values[j] = b.Values[j], b.Values[i]
				}
			}
		}

		tStart := time.Now()
		p.fn(f)
		tEnd := time.Now()

		// Need something less crude than "Log the whole intermediate result".
		if f.Log() || f.HTMLWriter != nil {
			time := tEnd.Sub(tStart).Nanoseconds()
			var stats string
			if logMemStats {
				var mEnd runtime.MemStats
				runtime.ReadMemStats(&mEnd)
				nBytes := mEnd.TotalAlloc - mStart.TotalAlloc
				nAllocs := mEnd.Mallocs - mStart.Mallocs
				stats = fmt.Sprintf("[%d ns %d allocs %d bytes]", time, nAllocs, nBytes)
			} else {
				stats = fmt.Sprintf("[%d ns]", time)
			}

			if f.Log() {
				f.Logf("  pass %s end %s\n", p.name, stats)
				printFunc(f)
			}
			f.HTMLWriter.WritePhase(phaseName, fmt.Sprintf("%s <span class=\"stats\">%s</span>", phaseName, stats))
		}
		if p.time || p.mem {
			// Surround timing information w/ enough context to allow comparisons.
			time := tEnd.Sub(tStart).Nanoseconds()
			if p.time {
				f.LogStat("TIME(ns)", time)
			}
			if p.mem {
				var mEnd runtime.MemStats
				runtime.ReadMemStats(&mEnd)
				nBytes := mEnd.TotalAlloc - mStart.TotalAlloc
				nAllocs := mEnd.Mallocs - mStart.Mallocs
				f.LogStat("TIME(ns):BYTES:ALLOCS", time, nBytes, nAllocs)
			}
		}
		if p.dump != nil && p.dump[f.Name] {
			// Dump function to appropriately named file
			f.dumpFile(phaseName)
		}
		if checkEnabled {
			checkFunc(f)
		}
	}

	if f.HTMLWriter != nil {
		// Ensure we write any pending phases to the html
		f.HTMLWriter.flushPhases()
	}

	if f.ruleMatches != nil {
		var keys []string
		for key := range f.ruleMatches {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf := new(strings.Builder)
		fmt.Fprintf(buf, "%s: ", f.Name)
		for _, key := range keys {
			fmt.Fprintf(buf, "%s=%d ", key, f.ruleMatches[key])
		}
		fmt.Fprint(buf, "\n")
		fmt.Print(buf.String())
	}

	// Squash error printing defer
	phaseName = ""
}

// DumpFileForPhase creates a file from the function name and phase name,
// warning and returning nil if this is not possible.
func (f *Func) DumpFileForPhase(phaseName string) io.WriteCloser {
	f.dumpFileSeq++
	fname := fmt.Sprintf("%s_%02d__%s.dump", f.Name, int(f.dumpFileSeq), phaseName)
	fname = strings.Replace(fname, " ", "_", -1)
	fname = strings.Replace(fname, "/", "_", -1)
	fname = strings.Replace(fname, ":", "_", -1)

	if ssaDir := os.Getenv("GOSSADIR"); ssaDir != "" {
		fname = filepath.Join(ssaDir, fname)
	}

	fi, err := os.Create(fname)
	if err != nil {
		f.Warnl(src.NoXPos, "Unable to create after-phase dump file %s", fname)
		return nil
	}
	return fi
}

// dumpFile creates a file from the phase name and function name
// Dumping is done to files to avoid buffering huge strings before
// output.
func (f *Func) dumpFile(phaseName string) {
	fi := f.DumpFileForPhase(phaseName)
	if fi != nil {
		p := stringFuncPrinter{w: fi}
		fprintFunc(p, f)
		fi.Close()
	}
}

type pass struct {
	name     string
	fn       func(*Func)
	required bool
	disabled bool
	time     bool            // report time to run pass
	mem      bool            // report mem stats to run pass
	stats    int             // pass reports own "stats" (e.g., branches removed)
	debug    int             // pass performs some debugging. =1 should be in error-testing-friendly Warnl format.
	test     int             // pass-specific ad-hoc option, perhaps useful in development
	dump     map[string]bool // dump if function name matches
}

func (p *pass) addDump(s string) {
	if p.dump == nil {
		p.dump = make(map[string]bool)
	}
	p.dump[s] = true
}

func (p *pass) String() string {
	if p == nil {
		return "nil pass"
	}
	return p.name
}

// Run consistency checker between each phase
var (
	checkEnabled  = false
	checkRandSeed = 0
)

// Debug output
var IntrinsicsDebug int
var IntrinsicsDisable bool

var BuildDebug int
var BuildTest int
var BuildStats int
var BuildDump map[string]bool = make(map[string]bool) // names of functions to dump after initial build of ssa

var GenssaDump map[string]bool = make(map[string]bool) // names of functions to dump after ssa has been converted to asm

// PhaseOption sets the specified flag in the specified ssa phase,
// returning empty string if this was successful or a string explaining
// the error if it was not.
// A version of the phase name with "_" replaced by " " is also checked for a match.
// If the phase name begins a '~' then the rest of the underscores-replaced-with-blanks
// version is used as a regular expression to match the phase name(s).
//
// Special cases that have turned out to be useful:
//   - ssa/check/on enables checking after each phase
//   - ssa/all/time enables time reporting for all phases
//
// See gc/lex.go for dissection of the option string.
// Example uses:
//
// GO_GCFLAGS=-d=ssa/generic_cse/time,ssa/generic_cse/stats,ssa/generic_cse/debug=3 ./make.bash
//
// BOOT_GO_GCFLAGS=-d='ssa/~^.*scc$/off' GO_GCFLAGS='-d=ssa/~^.*scc$/off' ./make.bash
func PhaseOption(phase, flag string, val int, valString string) string {
	switch phase {
	case "", "help":
		lastcr := 0
		phasenames := "    check, all, build, intrinsics, genssa"
		for _, p := range passes {
			pn := strings.Replace(p.name, " ", "_", -1)
			if len(pn)+len(phasenames)-lastcr > 70 {
				phasenames += "\n    "
				lastcr = len(phasenames)
				phasenames += pn
			} else {
				phasenames += ", " + pn
			}
		}
		return `PhaseOptions usage:

    go tool compile -d=ssa/<phase>/<flag>[=<value>|<function_name>]

where:

- <phase> is one of:
` + phasenames + `

- <flag> is one of:
    on, off, debug, mem, time, test, stats, dump, seed

- <value> defaults to 1

- <function_name> is required for the "dump" flag, and specifies the
  name of function to dump after <phase>

Phase "all" supports flags "time", "mem", and "dump".
Phase "intrinsics" supports flags "on", "off", and "debug".
Phase "genssa" (assembly generation) supports the flag "dump".

If the "dump" flag is specified, the output is written on a file named
<phase>__<function_name>_<seq>.dump; otherwise it is directed to stdout.

Examples:

    -d=ssa/check/on
enables checking after each phase

	-d=ssa/check/seed=1234
enables checking after each phase, using 1234 to seed the PRNG
used for value order randomization

    -d=ssa/all/time
enables time reporting for all phases

    -d=ssa/prove/debug=2
sets debugging level to 2 in the prove pass

Be aware that when "/debug=X" is applied to a pass, some passes
will emit debug output for all functions, and other passes will
only emit debug output for functions that match the current
GOSSAFUNC value.

Multiple flags can be passed at once, by separating them with
commas. For example:

    -d=ssa/check/on,ssa/all/time
`
	}

	if phase == "check" {
		switch flag {
		case "on":
			checkEnabled = val != 0
			debugPoset = checkEnabled // also turn on advanced self-checking in prove's data structure
			return ""
		case "off":
			checkEnabled = val == 0
			debugPoset = checkEnabled
			return ""
		case "seed":
			checkEnabled = true
			checkRandSeed = val
			debugPoset = checkEnabled
			return ""
		}
	}

	alltime := false
	allmem := false
	alldump := false
	if phase == "all" {
		switch flag {
		case "time":
			alltime = val != 0
		case "mem":
			allmem = val != 0
		case "dump":
			alldump = val != 0
			if alldump {
				BuildDump[valString] = true
				GenssaDump[valString] = true
			}
		default:
			return fmt.Sprintf("Did not find a flag matching %s in -d=ssa/%s debug option (expected ssa/all/{time,mem,dump=function_name})", flag, phase)
		}
	}

	if phase == "intrinsics" {
		switch flag {
		case "on":
			IntrinsicsDisable = val == 0
		case "off":
			IntrinsicsDisable = val != 0
		case "debug":
			IntrinsicsDebug = val
		default:
			return fmt.Sprintf("Did not find a flag matching %s in -d=ssa/%s debug option (expected ssa/intrinsics/{on,off,debug})", flag, phase)
		}
		return ""
	}
	if phase == "build" {
		switch flag {
		case "debug":
			BuildDebug = val
		case "test":
			BuildTest = val
		case "stats":
			BuildStats = val
		case "dump":
			BuildDump[valString] = true
		default:
			return fmt.Sprintf("Did not find a flag matching %s in -d=ssa/%s debug option (expected ssa/build/{debug,test,stats,dump=function_name})", flag, phase)
		}
		return ""
	}
	if phase == "genssa" {
		switch flag {
		case "dump":
			GenssaDump[valString] = true
		default:
			return fmt.Sprintf("Did not find a flag matching %s in -d=ssa/%s debug option (expected ssa/genssa/dump=function_name)", flag, phase)
		}
		return ""
	}

	underphase := strings.Replace(phase, "_", " ", -1)
	var re *regexp.Regexp
	if phase[0] == '~' {
		r, ok := regexp.Compile(underphase[1:])
		if ok != nil {
			return fmt.Sprintf("Error %s in regexp for phase %s, flag %s", ok.Error(), phase, flag)
		}
		re = r
	}
	matchedOne := false
	for i, p := range passes {
		if phase == "all" {
			p.time = alltime
			p.mem = allmem
			if alldump {
				p.addDump(valString)
			}
			passes[i] = p
			matchedOne = true
		} else if p.name == phase || p.name == underphase || re != nil && re.MatchString(p.name) {
			switch flag {
			case "on":
				p.disabled = val == 0
			case "off":
				p.disabled = val != 0
			case "time":
				p.time = val != 0
			case "mem":
				p.mem = val != 0
			case "debug":
				p.debug = val
			case "stats":
				p.stats = val
			case "test":
				p.test = val
			case "dump":
				p.addDump(valString)
			default:
				return fmt.Sprintf("Did not find a flag matching %s in -d=ssa/%s debug option", flag, phase)
			}
			if p.disabled && p.required {
				return fmt.Sprintf("Cannot disable required SSA phase %s using -d=ssa/%s debug option", phase, phase)
			}
			passes[i] = p
			matchedOne = true
		}
	}
	if matchedOne {
		return ""
	}
	return fmt.Sprintf("Did not find a phase matching %s in -d=ssa/... debug option", phase)
}

// list of passes for the compiler
var passes = [...]pass{
	{name: "number lines", fn: numberLines, required: true},
	{name: "early phielim and copyelim", fn: copyelim},
	{name: "early deadcode", fn: deadcode}, // remove generated dead code to avoid doing pointless work during opt
	{name: "short circuit", fn: shortcircuit},
	{name: "decompose user", fn: decomposeUser, required: true},
	{name: "pre-opt deadcode", fn: deadcode},
	{name: "opt", fn: opt, required: true},               // NB: some generic rules know the name of the opt pass. TODO: split required rules and optimizing rules
	{name: "zero arg cse", fn: zcse, required: true},     // required to merge OpSB values
	{name: "opt deadcode", fn: deadcode, required: true}, // remove any blocks orphaned during opt
	{name: "generic cse", fn: cse},
	{name: "phiopt", fn: phiopt},
	{name: "gcse deadcode", fn: deadcode, required: true}, // clean out after cse and phiopt
	{name: "nilcheckelim", fn: nilcheckelim},
	{name: "prove", fn: prove},
	{name: "early fuse", fn: fuseEarly},
	{name: "expand calls", fn: expandCalls, required: true},
	{name: "decompose builtin", fn: postExpandCallsDecompose, required: true},
	{name: "softfloat", fn: softfloat, required: true},
	{name: "late opt", fn: opt, required: true}, // TODO: split required rules and optimizing rules
	{name: "dead auto elim", fn: elimDeadAutosGeneric},
	{name: "sccp", fn: sccp},
	{name: "generic deadcode", fn: deadcode, required: true}, // remove dead stores, which otherwise mess up store chain
	{name: "branchelim", fn: branchelim},
	{name: "late fuse", fn: fuseLate},
	{name: "check bce", fn: checkbce},
	{name: "dse", fn: dse},
	{name: "memcombine", fn: memcombine},
	{name: "writebarrier", fn: writebarrier, required: true}, // expand write barrier ops
	{name: "insert resched checks", fn: insertLoopReschedChecks,
		disabled: !buildcfg.Experiment.PreemptibleLoops}, // insert resched checks in loops.
	{name: "lower", fn: lower, required: true},
	{name: "addressing modes", fn: addressingModes, required: false},
	{name: "late lower", fn: lateLower, required: true},
	{name: "lowered deadcode for cse", fn: deadcode}, // deadcode immediately before CSE avoids CSE making dead values live again
	{name: "lowered cse", fn: cse},
	{name: "elim unread autos", fn: elimUnreadAutos},
	{name: "tighten tuple selectors", fn: tightenTupleSelectors, required: true},
	{name: "lowered deadcode", fn: deadcode, required: true},
	{name: "checkLower", fn: checkLower, required: true},
	{name: "late phielim and copyelim", fn: copyelim},
	{name: "tighten", fn: tighten, required: true}, // move values closer to their uses
	{name: "late deadcode", fn: deadcode},
	{name: "critical", fn: critical, required: true}, // remove critical edges
	{name: "phi tighten", fn: phiTighten},            // place rematerializable phi args near uses to reduce value lifetimes
	{name: "likelyadjust", fn: likelyadjust},
	{name: "layout", fn: layout, required: true},     // schedule blocks
	{name: "schedule", fn: schedule, required: true}, // schedule values
	{name: "late nilcheck", fn: nilcheckelim2},
	{name: "flagalloc", fn: flagalloc, required: true}, // allocate flags register
	{name: "regalloc", fn: regalloc, required: true},   // allocate int & float registers + stack slots
	{name: "loop rotate", fn: loopRotate},
	{name: "trim", fn: trim}, // remove empty blocks
}

// Double-check phase ordering constraints.
// This code is intended to document the ordering requirements
// between different phases. It does not override the passes
// list above.
type constraint struct {
	a, b string // a must come before b
}

var passOrder = [...]constraint{
	// "insert resched checks" uses mem, better to clean out stores first.
	{"dse", "insert resched checks"},
	// insert resched checks adds new blocks containing generic instructions
	{"insert resched checks", "lower"},
	{"insert resched checks", "tighten"},

	// prove relies on common-subexpression elimination for maximum benefits.
	{"generic cse", "prove"},
	// deadcode after prove to eliminate all new dead blocks.
	{"prove", "generic deadcode"},
	// common-subexpression before dead-store elim, so that we recognize
	// when two address expressions are the same.
	{"generic cse", "dse"},
	// cse substantially improves nilcheckelim efficacy
	{"generic cse", "nilcheckelim"},
	// allow deadcode to clean up after nilcheckelim
	{"nilcheckelim", "generic deadcode"},
	// nilcheckelim generates sequences of plain basic blocks
	{"nilcheckelim", "late fuse"},
	// nilcheckelim relies on opt to rewrite user nil checks
	{"opt", "nilcheckelim"},
	// tighten will be most effective when as many values have been removed as possible
	{"generic deadcode", "tighten"},
	{"generic cse", "tighten"},
	// checkbce needs the values removed
	{"generic deadcode", "check bce"},
	// decompose builtin now also cleans up after expand calls
	{"expand calls", "decompose builtin"},
	// don't run optimization pass until we've decomposed builtin objects
	{"decompose builtin", "late opt"},
	// decompose builtin is the last pass that may introduce new float ops, so run softfloat after it
	{"decompose builtin", "softfloat"},
	// tuple selectors must be tightened to generators and de-duplicated before scheduling
	{"tighten tuple selectors", "schedule"},
	// remove critical edges before phi tighten, so that phi args get better placement
	{"critical", "phi tighten"},
	// don't layout blocks until critical edges have been removed
	{"critical", "layout"},
	// regalloc requires the removal of all critical edges
	{"critical", "regalloc"},
	// regalloc requires all the values in a block to be scheduled
	{"schedule", "regalloc"},
	// the rules in late lower run after the general rules.
	{"lower", "late lower"},
	// late lower may generate some values that need to be CSEed.
	{"late lower", "lowered cse"},
	// checkLower must run after lowering & subsequent dead code elim
	{"lower", "checkLower"},
	{"lowered deadcode", "checkLower"},
	{"late lower", "checkLower"},
	// late nilcheck needs instructions to be scheduled.
	{"schedule", "late nilcheck"},
	// flagalloc needs instructions to be scheduled.
	{"schedule", "flagalloc"},
	// regalloc needs flags to be allocated first.
	{"flagalloc", "regalloc"},
	// loopRotate will confuse regalloc.
	{"regalloc", "loop rotate"},
	// trim needs regalloc to be done first.
	{"regalloc", "trim"},
	// memcombine works better if fuse happens first, to help merge stores.
	{"late fuse", "memcombine"},
	// memcombine is a arch-independent pass.
	{"memcombine", "lower"},
}

func init() {
	for _, c := range passOrder {
		a, b := c.a, c.b
		i := -1
		j := -1
		for k, p := range passes {
			if p.name == a {
				i = k
			}
			if p.name == b {
				j = k
			}
		}
		if i < 0 {
			log.Panicf("pass %s not found", a)
		}
		if j < 0 {
			log.Panicf("pass %s not found", b)
		}
		if i >= j {
			log.Panicf("passes %s and %s out of order", a, b)
		}
	}
}
```