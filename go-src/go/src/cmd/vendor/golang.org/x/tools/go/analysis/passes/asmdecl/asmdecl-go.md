Response:
Let's break down the thought process for analyzing this Go code snippet and generating the requested information.

**1. Understanding the Core Task:**

The core purpose of this code is stated clearly in the package documentation: "report mismatches between assembly files and Go declarations."  This immediately tells us it's an analysis tool that checks consistency between `.go` and `.s` files.

**2. Identifying Key Data Structures and Functions:**

I started by looking for the main entry point and central data structures.

* **`Analyzer`:**  This is the standard structure for Go analysis tools. Its `Run` function (`run`) is the heart of the analysis.
* **`asmArch`:**  This structure clearly represents architecture-specific information, which is crucial for assembly language. The numerous predefined `asmArch` variables (e.g., `asmArchAmd64`) reinforce this.
* **`asmFunc`:**  This likely represents the assembly-level view of a Go function, holding information about arguments and local variables.
* **`asmVar`:**  This represents a single variable (argument, return value, or part of a composite type) as seen in assembly.
* **`run(pass *analysis.Pass)`:** This is the core analysis function. I scanned its code to understand the flow.

**3. Deconstructing the `run` Function:**

I went through the `run` function step by step:

* **File Handling:** It iterates through `pass.OtherFiles` to find `.s` files.
* **Declaration Gathering:** It iterates through `pass.Files` to find Go function declarations without bodies (which are the ones with corresponding assembly implementations). It stores these in `knownFunc`. The function `asmParseDecl` is clearly responsible for extracting assembly-level information from Go declarations.
* **Assembly File Processing:** It reads each assembly file line by line.
* **Architecture Detection:** It attempts to determine the architecture from the filename or `+build` tags.
* **`TEXT` Directive Handling:**  The `asmTEXT` regular expression is a key indicator of the start of an assembly function. The code extracts the function name and size information.
* **Argument Size Check:** It compares the declared argument size in the Go code with the size specified in the assembly `TEXT` directive.
* **Local Variable Size Calculation:** It calculates the expected size of the local variable frame.
* **Stack Pointer Usage (`SP`):** It checks for explicit manipulation of the stack pointer, which can affect the frame layout.
* **Return Value Handling (`RET`):** It tracks `RET` instructions and checks if return values are written to (especially important for ABIInternal).
* **Frame Pointer Usage (`FP`):** It analyzes accesses to memory relative to the frame pointer, both named and unnamed arguments. The `asmNamedFP` and `asmUnnamedFP` regular expressions are crucial here.
* **Variable Checking (`asmCheckVar`):** This function appears to do the detailed checking of individual variable accesses, comparing the assembly usage with the information extracted from the Go declaration.

**4. Understanding `asmParseDecl`:**

This function is crucial for linking Go declarations to their assembly counterparts. I examined its logic:

* **Iterating Through Architectures:** It generates `asmFunc` structures for each supported architecture.
* **`addParams` Function:** This helper function processes function parameters (both input and output). It uses `componentsOfType` to break down complex types into their addressable parts.
* **`componentsOfType` and Recursive Breakdown:** This function is the most complex part of `asmParseDecl`. It recursively decomposes Go types (structs, arrays, strings, slices, interfaces) into their individual components as they would be laid out in memory. This is essential for understanding how to access members in assembly.

**5. Understanding `asmCheckVar`:**

This function checks if an assembly instruction's access to a variable is consistent with the Go declaration. It looks at:

* **Opcode Analysis:**  It tries to infer the size of the operands based on the assembly instruction.
* **Offset Verification:**  It checks if the offset used in the assembly matches the expected offset of the variable.
* **Type Size Consistency:** It verifies that the size implied by the assembly instruction is compatible with the size of the Go variable's type.

**6. Inferring the Go Language Feature:**

Based on the analysis, it's clear that this code helps implement the feature of writing assembly implementations for Go functions. This is often needed for performance-critical sections or when interacting directly with hardware.

**7. Generating Examples:**

With the understanding of the tool's purpose and the functions involved, I could construct illustrative examples showing how it detects mismatches between Go and assembly.

**8. Identifying Error-Prone Areas:**

By understanding the checks performed by the analyzer, I could identify common mistakes developers might make when writing assembly code for Go, such as incorrect argument sizes, incorrect offsets, and forgetting to handle return values.

**9. Handling Command-Line Arguments:**

The code itself doesn't explicitly parse command-line arguments. However, it's part of the `go vet` tooling. Therefore, the command-line usage is inherited from `go vet`.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps this is just about checking the *existence* of assembly files.
* **Correction:** The focus on offsets, sizes, and type breakdowns indicates a much deeper level of analysis, checking the *correctness* of the assembly implementation.
* **Initial thought:** The architecture detection might be more complex.
* **Refinement:** While it checks `+build` tags, it primarily relies on filename suffixes, simplifying the logic.
* **Initial thought:**  The `asmCheckVar` function might be simpler.
* **Refinement:** The logic within `asmCheckVar` for inferring operand sizes based on opcodes and handling different architectures shows its complexity and importance.

By following this structured approach, combining code reading with understanding the overall goal, I was able to extract the requested information and generate helpful examples.
这段代码是 Go 语言分析工具 `golang.org/x/tools/go/analysis` 中的一个 `pass`，名为 `asmdecl`。它的主要功能是**报告 Go 语言声明和对应的汇编文件之间存在的差异**。

更具体地说，`asmdecl` 检查以下几个方面的一致性：

1. **函数签名匹配:**  确保 Go 语言中声明的函数（没有函数体）在汇编文件中存在对应的实现，并且参数和返回值的大小与 Go 声明一致。
2. **函数参数和局部变量的布局:**  检查汇编代码中对函数参数和局部变量的访问是否与 Go 语言的内存布局相符，包括正确的偏移量和大小。
3. **返回值的处理:** 验证汇编代码是否正确地设置了函数的返回值。

**它是什么 Go 语言功能的实现？**

`asmdecl` 工具是为了支持 Go 语言中编写汇编代码的功能而存在的。Go 允许开发者为特定的平台和架构编写汇编代码以提高性能或进行底层操作。这些汇编文件通常与 Go 源代码一起编译。`asmdecl` 确保了这些汇编代码与 Go 语言的声明保持同步，避免由于声明和实现不匹配而导致的运行时错误。

**Go 代码举例说明:**

假设我们有以下 Go 代码 `mymath.go`:

```go
package mymath

//go:noinline
func Add(a, b int) int
```

以及对应的汇编代码 `mymath_amd64.s`:

```assembly
#include "textflag.h"

// func Add(a, b int) int
TEXT ·Add(SB), NOSPLIT, $0-24
  MOVQ  a+0(FP), AX
  ADDQ  b+8(FP), AX
  MOVQ  AX, ret+16(FP)
  RET
```

**假设的输入与输出:**

* **输入 (Go 代码):** `mymath.go`
* **输入 (汇编代码):** `mymath_amd64.s`
* **预期输出 (没有错误):** `asmdecl` 分析后不会报告任何错误，因为汇编代码正确地实现了 `Add` 函数，参数和返回值的大小和偏移量都与 Go 声明一致。

**假设的输入与输出 (存在错误):**

假设我们修改了汇编代码，错误地访问了 `b` 参数：

```assembly
#include "textflag.h"

// func Add(a, b int) int
TEXT ·Add(SB), NOSPLIT, $0-24
  MOVQ  a+0(FP), AX
  ADDQ  b+16(FP), AX  // 错误：访问了错误的偏移量
  MOVQ  AX, ret+16(FP)
  RET
```

* **输入 (Go 代码):** `mymath.go`
* **输入 (汇编代码):** 修改后的 `mymath_amd64.s`
* **预期输出 (报告错误):** `asmdecl` 会报告一个错误，指出在访问 `b` 参数时使用了错误的偏移量。例如：`mymath_amd64.s:5: [amd64] Add: use of b+16(FP) points beyond argument frame` 或者类似的错误信息。

**代码推理:**

`asmdecl` 的 `run` 函数主要流程如下：

1. **查找汇编文件:**  遍历 `pass.OtherFiles` 找到以 `.s` 结尾的文件。
2. **解析 Go 声明:** 遍历 `pass.Files`，找到没有函数体的函数声明，这些通常对应着汇编实现。`asmParseDecl` 函数负责解析这些声明，提取函数的参数和返回值信息，以及它们在内存中的布局（偏移量和大小）。
3. **解析汇编文件:**  逐行读取汇编文件，使用正则表达式（如 `asmTEXT`）匹配函数定义。
4. **匹配 Go 声明和汇编函数:**  根据函数名和架构匹配 Go 声明和汇编实现。
5. **检查参数大小:**  比较汇编文件中 `TEXT` 指令中声明的参数大小与 Go 声明计算出的参数大小是否一致。
6. **检查局部变量大小:** 分析汇编代码中栈指针的移动，推断局部变量的大小。
7. **检查参数和局部变量的访问:**  使用正则表达式（如 `asmNamedFP` 和 `asmUnnamedFP`）匹配汇编代码中对参数和局部变量的访问，并与 `asmParseDecl` 中计算出的偏移量进行比较。`asmCheckVar` 函数负责具体的检查逻辑，包括验证偏移量和操作数的大小是否匹配。
8. **检查返回值:**  检查汇编代码中是否有将结果写入返回值位置的操作。

**命令行参数的具体处理:**

`asmdecl` 本身作为一个 `analysis.Analyzer`，并没有直接处理命令行参数。它被集成到 `go vet` 工具中。因此，其行为受到 `go vet` 的命令行参数影响。

例如：

* `go vet ./...`:  会对当前目录及其子目录下的所有 Go 包进行静态分析，包括运行 `asmdecl` 检查。
* `go vet -v ./mypackage`:  会显示更详细的 `go vet` 输出，包括 `asmdecl` 的分析结果。
* `go vet -check=asmdecl ./mypackage`:  可以明确指定只运行 `asmdecl` 这个分析器。

**使用者易犯错的点:**

1. **参数或返回值大小不匹配:**  在 Go 声明中修改了参数或返回值的类型，但忘记更新对应的汇编代码中的栈偏移量和 `TEXT` 指令中的大小。

   **例子:**

   Go 代码:
   ```go
   func Process(data int64)
   ```

   汇编代码 (错误地假设 `int` 大小):
   ```assembly
   TEXT ·Process(SB), NOSPLIT, $0-8 // 错误：假设参数大小为 8 字节
       // ... 使用 data+0(FP) ...
       RET
   ```
   `asmdecl` 会报告参数大小不匹配的错误。

2. **错误的栈偏移量:**  在汇编代码中访问参数或局部变量时使用了错误的偏移量。

   **例子:**

   Go 代码:
   ```go
   func Calculate(a int, b int) int
   ```

   汇编代码 (错误地计算 `b` 的偏移量):
   ```assembly
   TEXT ·Calculate(SB), NOSPLIT, $0-24
       MOVQ a+0(FP), AX
       ADDQ b+4(FP), AX  // 错误：b 的偏移量应该是 8
       MOVQ AX, ret+16(FP)
       RET
   ```
   `asmdecl` 会报告访问 `b` 时使用了错误的偏移量。

3. **忘记处理返回值:**  对于有返回值的函数，汇编代码中忘记将计算结果写入正确的返回值位置。

   **例子:**

   Go 代码:
   ```go
   func Double(x int) int
   ```

   汇编代码 (忘记写入返回值):
   ```assembly
   TEXT ·Double(SB), NOSPLIT, $0-16
       MOVQ x+0(FP), AX
       ADDQ AX, AX
       RET // 错误：没有将 AX 的值写入 ret+8(FP)
   ```
   `asmdecl` 会报告 `RET` 指令之前没有写入返回值。

4. **架构特定的错误:**  在跨平台项目中，汇编代码可能是特定于架构的。如果 Go 代码和汇编代码的架构标签不匹配，`asmdecl` 可能会报告错误。

总而言之，`asmdecl` 是一个非常有用的静态分析工具，可以帮助 Go 开发者在编写和维护汇编代码时避免常见的错误，确保 Go 代码和汇编实现的正确性和一致性。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/tools/go/analysis/passes/asmdecl/asmdecl.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package asmdecl defines an Analyzer that reports mismatches between
// assembly files and Go declarations.
package asmdecl

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/token"
	"go/types"
	"log"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/internal/analysisutil"
)

const Doc = "report mismatches between assembly files and Go declarations"

var Analyzer = &analysis.Analyzer{
	Name: "asmdecl",
	Doc:  Doc,
	URL:  "https://pkg.go.dev/golang.org/x/tools/go/analysis/passes/asmdecl",
	Run:  run,
}

// 'kind' is a kind of assembly variable.
// The kinds 1, 2, 4, 8 stand for values of that size.
type asmKind int

// These special kinds are not valid sizes.
const (
	asmString asmKind = 100 + iota
	asmSlice
	asmArray
	asmInterface
	asmEmptyInterface
	asmStruct
	asmComplex
)

// An asmArch describes assembly parameters for an architecture
type asmArch struct {
	name      string
	bigEndian bool
	stack     string
	lr        bool
	// retRegs is a list of registers for return value in register ABI (ABIInternal).
	// For now, as we only check whether we write to any result, here we only need to
	// include the first integer register and first floating-point register. Accessing
	// any of them counts as writing to result.
	retRegs []string
	// writeResult is a list of instructions that will change result register implicity.
	writeResult []string
	// calculated during initialization
	sizes    types.Sizes
	intSize  int
	ptrSize  int
	maxAlign int
}

// An asmFunc describes the expected variables for a function on a given architecture.
type asmFunc struct {
	arch        *asmArch
	size        int // size of all arguments
	vars        map[string]*asmVar
	varByOffset map[int]*asmVar
}

// An asmVar describes a single assembly variable.
type asmVar struct {
	name  string
	kind  asmKind
	typ   string
	off   int
	size  int
	inner []*asmVar
}

var (
	asmArch386      = asmArch{name: "386", bigEndian: false, stack: "SP", lr: false}
	asmArchArm      = asmArch{name: "arm", bigEndian: false, stack: "R13", lr: true}
	asmArchArm64    = asmArch{name: "arm64", bigEndian: false, stack: "RSP", lr: true, retRegs: []string{"R0", "F0"}, writeResult: []string{"SVC"}}
	asmArchAmd64    = asmArch{name: "amd64", bigEndian: false, stack: "SP", lr: false, retRegs: []string{"AX", "X0"}, writeResult: []string{"SYSCALL"}}
	asmArchMips     = asmArch{name: "mips", bigEndian: true, stack: "R29", lr: true}
	asmArchMipsLE   = asmArch{name: "mipsle", bigEndian: false, stack: "R29", lr: true}
	asmArchMips64   = asmArch{name: "mips64", bigEndian: true, stack: "R29", lr: true}
	asmArchMips64LE = asmArch{name: "mips64le", bigEndian: false, stack: "R29", lr: true}
	asmArchPpc64    = asmArch{name: "ppc64", bigEndian: true, stack: "R1", lr: true, retRegs: []string{"R3", "F1"}, writeResult: []string{"SYSCALL"}}
	asmArchPpc64LE  = asmArch{name: "ppc64le", bigEndian: false, stack: "R1", lr: true, retRegs: []string{"R3", "F1"}, writeResult: []string{"SYSCALL"}}
	asmArchRISCV64  = asmArch{name: "riscv64", bigEndian: false, stack: "SP", lr: true, retRegs: []string{"X10", "F10"}, writeResult: []string{"ECALL"}}
	asmArchS390X    = asmArch{name: "s390x", bigEndian: true, stack: "R15", lr: true}
	asmArchWasm     = asmArch{name: "wasm", bigEndian: false, stack: "SP", lr: false}
	asmArchLoong64  = asmArch{name: "loong64", bigEndian: false, stack: "R3", lr: true, retRegs: []string{"R4", "F0"}, writeResult: []string{"SYSCALL"}}

	arches = []*asmArch{
		&asmArch386,
		&asmArchArm,
		&asmArchArm64,
		&asmArchAmd64,
		&asmArchMips,
		&asmArchMipsLE,
		&asmArchMips64,
		&asmArchMips64LE,
		&asmArchPpc64,
		&asmArchPpc64LE,
		&asmArchRISCV64,
		&asmArchS390X,
		&asmArchWasm,
		&asmArchLoong64,
	}
)

func init() {
	for _, arch := range arches {
		arch.sizes = types.SizesFor("gc", arch.name)
		if arch.sizes == nil {
			// TODO(adonovan): fix: now that asmdecl is not in the standard
			// library we cannot assume types.SizesFor is consistent with arches.
			// For now, assume 64-bit norms and print a warning.
			// But this warning should really be deferred until we attempt to use
			// arch, which is very unlikely. Better would be
			// to defer size computation until we have Pass.TypesSizes.
			arch.sizes = types.SizesFor("gc", "amd64")
			log.Printf("unknown architecture %s", arch.name)
		}
		arch.intSize = int(arch.sizes.Sizeof(types.Typ[types.Int]))
		arch.ptrSize = int(arch.sizes.Sizeof(types.Typ[types.UnsafePointer]))
		arch.maxAlign = int(arch.sizes.Alignof(types.Typ[types.Int64]))
	}
}

var (
	re           = regexp.MustCompile
	asmPlusBuild = re(`//\s+\+build\s+([^\n]+)`)
	asmTEXT      = re(`\bTEXT\b(.*)·([^\(]+)\(SB\)(?:\s*,\s*([0-9A-Z|+()]+))?(?:\s*,\s*\$(-?[0-9]+)(?:-([0-9]+))?)?`)
	asmDATA      = re(`\b(DATA|GLOBL)\b`)
	asmNamedFP   = re(`\$?([a-zA-Z0-9_\xFF-\x{10FFFF}]+)(?:\+([0-9]+))\(FP\)`)
	asmUnnamedFP = re(`[^+\-0-9](([0-9]+)\(FP\))`)
	asmSP        = re(`[^+\-0-9](([0-9]+)\(([A-Z0-9]+)\))`)
	asmOpcode    = re(`^\s*(?:[A-Z0-9a-z_]+:)?\s*([A-Z]+)\s*([^,]*)(?:,\s*(.*))?`)
	ppc64Suff    = re(`([BHWD])(ZU|Z|U|BR)?$`)
	abiSuff      = re(`^(.+)<(ABI.+)>$`)
)

func run(pass *analysis.Pass) (interface{}, error) {
	// No work if no assembly files.
	var sfiles []string
	for _, fname := range pass.OtherFiles {
		if strings.HasSuffix(fname, ".s") {
			sfiles = append(sfiles, fname)
		}
	}
	if sfiles == nil {
		return nil, nil
	}

	// Gather declarations. knownFunc[name][arch] is func description.
	knownFunc := make(map[string]map[string]*asmFunc)

	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			if decl, ok := decl.(*ast.FuncDecl); ok && decl.Body == nil {
				knownFunc[decl.Name.Name] = asmParseDecl(pass, decl)
			}
		}
	}

Files:
	for _, fname := range sfiles {
		content, tf, err := analysisutil.ReadFile(pass, fname)
		if err != nil {
			return nil, err
		}

		// Determine architecture from file name if possible.
		var arch string
		var archDef *asmArch
		for _, a := range arches {
			if strings.HasSuffix(fname, "_"+a.name+".s") {
				arch = a.name
				archDef = a
				break
			}
		}

		lines := strings.SplitAfter(string(content), "\n")
		var (
			fn                 *asmFunc
			fnName             string
			abi                string
			localSize, argSize int
			wroteSP            bool
			noframe            bool
			haveRetArg         bool
			retLine            []int
		)

		flushRet := func() {
			if fn != nil && fn.vars["ret"] != nil && !haveRetArg && len(retLine) > 0 {
				v := fn.vars["ret"]
				resultStr := fmt.Sprintf("%d-byte ret+%d(FP)", v.size, v.off)
				if abi == "ABIInternal" {
					resultStr = "result register"
				}
				for _, line := range retLine {
					pass.Reportf(analysisutil.LineStart(tf, line), "[%s] %s: RET without writing to %s", arch, fnName, resultStr)
				}
			}
			retLine = nil
		}
		trimABI := func(fnName string) (string, string) {
			m := abiSuff.FindStringSubmatch(fnName)
			if m != nil {
				return m[1], m[2]
			}
			return fnName, ""
		}
		for lineno, line := range lines {
			lineno++

			badf := func(format string, args ...interface{}) {
				pass.Reportf(analysisutil.LineStart(tf, lineno), "[%s] %s: %s", arch, fnName, fmt.Sprintf(format, args...))
			}

			if arch == "" {
				// Determine architecture from +build line if possible.
				if m := asmPlusBuild.FindStringSubmatch(line); m != nil {
					// There can be multiple architectures in a single +build line,
					// so accumulate them all and then prefer the one that
					// matches build.Default.GOARCH.
					var archCandidates []*asmArch
					for _, fld := range strings.Fields(m[1]) {
						for _, a := range arches {
							if a.name == fld {
								archCandidates = append(archCandidates, a)
							}
						}
					}
					for _, a := range archCandidates {
						if a.name == build.Default.GOARCH {
							archCandidates = []*asmArch{a}
							break
						}
					}
					if len(archCandidates) > 0 {
						arch = archCandidates[0].name
						archDef = archCandidates[0]
					}
				}
			}

			// Ignore comments and commented-out code.
			if i := strings.Index(line, "//"); i >= 0 {
				line = line[:i]
			}

			if m := asmTEXT.FindStringSubmatch(line); m != nil {
				flushRet()
				if arch == "" {
					// Arch not specified by filename or build tags.
					// Fall back to build.Default.GOARCH.
					for _, a := range arches {
						if a.name == build.Default.GOARCH {
							arch = a.name
							archDef = a
							break
						}
					}
					if arch == "" {
						log.Printf("%s: cannot determine architecture for assembly file", fname)
						continue Files
					}
				}
				fnName = m[2]
				if pkgPath := strings.TrimSpace(m[1]); pkgPath != "" {
					// The assembler uses Unicode division slash within
					// identifiers to represent the directory separator.
					pkgPath = strings.Replace(pkgPath, "∕", "/", -1)
					if pkgPath != pass.Pkg.Path() {
						// log.Printf("%s:%d: [%s] cannot check cross-package assembly function: %s is in package %s", fname, lineno, arch, fnName, pkgPath)
						fn = nil
						fnName = ""
						abi = ""
						continue
					}
				}
				// Trim off optional ABI selector.
				fnName, abi = trimABI(fnName)
				flag := m[3]
				fn = knownFunc[fnName][arch]
				if fn != nil {
					size, _ := strconv.Atoi(m[5])
					if size != fn.size && (flag != "7" && !strings.Contains(flag, "NOSPLIT") || size != 0) {
						badf("wrong argument size %d; expected $...-%d", size, fn.size)
					}
				}
				localSize, _ = strconv.Atoi(m[4])
				localSize += archDef.intSize
				if archDef.lr && !strings.Contains(flag, "NOFRAME") {
					// Account for caller's saved LR
					localSize += archDef.intSize
				}
				argSize, _ = strconv.Atoi(m[5])
				noframe = strings.Contains(flag, "NOFRAME")
				if fn == nil && !strings.Contains(fnName, "<>") && !noframe {
					badf("function %s missing Go declaration", fnName)
				}
				wroteSP = false
				haveRetArg = false
				continue
			} else if strings.Contains(line, "TEXT") && strings.Contains(line, "SB") {
				// function, but not visible from Go (didn't match asmTEXT), so stop checking
				flushRet()
				fn = nil
				fnName = ""
				abi = ""
				continue
			}

			if strings.Contains(line, "RET") && !strings.Contains(line, "(SB)") {
				// RET f(SB) is a tail call. It is okay to not write the results.
				retLine = append(retLine, lineno)
			}

			if fnName == "" {
				continue
			}

			if asmDATA.FindStringSubmatch(line) != nil {
				fn = nil
			}

			if archDef == nil {
				continue
			}

			if strings.Contains(line, ", "+archDef.stack) || strings.Contains(line, ",\t"+archDef.stack) || strings.Contains(line, "NOP "+archDef.stack) || strings.Contains(line, "NOP\t"+archDef.stack) {
				wroteSP = true
				continue
			}

			if arch == "wasm" && strings.Contains(line, "CallImport") {
				// CallImport is a call out to magic that can write the result.
				haveRetArg = true
			}

			if abi == "ABIInternal" && !haveRetArg {
				for _, ins := range archDef.writeResult {
					if strings.Contains(line, ins) {
						haveRetArg = true
						break
					}
				}
				for _, reg := range archDef.retRegs {
					if strings.Contains(line, reg) {
						haveRetArg = true
						break
					}
				}
			}

			for _, m := range asmSP.FindAllStringSubmatch(line, -1) {
				if m[3] != archDef.stack || wroteSP || noframe {
					continue
				}
				off := 0
				if m[1] != "" {
					off, _ = strconv.Atoi(m[2])
				}
				if off >= localSize {
					if fn != nil {
						v := fn.varByOffset[off-localSize]
						if v != nil {
							badf("%s should be %s+%d(FP)", m[1], v.name, off-localSize)
							continue
						}
					}
					if off >= localSize+argSize {
						badf("use of %s points beyond argument frame", m[1])
						continue
					}
					badf("use of %s to access argument frame", m[1])
				}
			}

			if fn == nil {
				continue
			}

			for _, m := range asmUnnamedFP.FindAllStringSubmatch(line, -1) {
				off, _ := strconv.Atoi(m[2])
				v := fn.varByOffset[off]
				if v != nil {
					badf("use of unnamed argument %s; offset %d is %s+%d(FP)", m[1], off, v.name, v.off)
				} else {
					badf("use of unnamed argument %s", m[1])
				}
			}

			for _, m := range asmNamedFP.FindAllStringSubmatch(line, -1) {
				name := m[1]
				off := 0
				if m[2] != "" {
					off, _ = strconv.Atoi(m[2])
				}
				if name == "ret" || strings.HasPrefix(name, "ret_") {
					haveRetArg = true
				}
				v := fn.vars[name]
				if v == nil {
					// Allow argframe+0(FP).
					if name == "argframe" && off == 0 {
						continue
					}
					v = fn.varByOffset[off]
					if v != nil {
						badf("unknown variable %s; offset %d is %s+%d(FP)", name, off, v.name, v.off)
					} else {
						badf("unknown variable %s", name)
					}
					continue
				}
				asmCheckVar(badf, fn, line, m[0], off, v, archDef)
			}
		}
		flushRet()
	}
	return nil, nil
}

func asmKindForType(t types.Type, size int) asmKind {
	switch t := t.Underlying().(type) {
	case *types.Basic:
		switch t.Kind() {
		case types.String:
			return asmString
		case types.Complex64, types.Complex128:
			return asmComplex
		}
		return asmKind(size)
	case *types.Pointer, *types.Chan, *types.Map, *types.Signature:
		return asmKind(size)
	case *types.Struct:
		return asmStruct
	case *types.Interface:
		if t.Empty() {
			return asmEmptyInterface
		}
		return asmInterface
	case *types.Array:
		return asmArray
	case *types.Slice:
		return asmSlice
	}
	panic("unreachable")
}

// A component is an assembly-addressable component of a composite type,
// or a composite type itself.
type component struct {
	size   int
	offset int
	kind   asmKind
	typ    string
	suffix string // Such as _base for string base, _0_lo for lo half of first element of [1]uint64 on 32 bit machine.
	outer  string // The suffix for immediately containing composite type.
}

func newComponent(suffix string, kind asmKind, typ string, offset, size int, outer string) component {
	return component{suffix: suffix, kind: kind, typ: typ, offset: offset, size: size, outer: outer}
}

// componentsOfType generates a list of components of type t.
// For example, given string, the components are the string itself, the base, and the length.
func componentsOfType(arch *asmArch, t types.Type) []component {
	return appendComponentsRecursive(arch, t, nil, "", 0)
}

// appendComponentsRecursive implements componentsOfType.
// Recursion is required to correct handle structs and arrays,
// which can contain arbitrary other types.
func appendComponentsRecursive(arch *asmArch, t types.Type, cc []component, suffix string, off int) []component {
	s := t.String()
	size := int(arch.sizes.Sizeof(t))
	kind := asmKindForType(t, size)
	cc = append(cc, newComponent(suffix, kind, s, off, size, suffix))

	switch kind {
	case 8:
		if arch.ptrSize == 4 {
			w1, w2 := "lo", "hi"
			if arch.bigEndian {
				w1, w2 = w2, w1
			}
			cc = append(cc, newComponent(suffix+"_"+w1, 4, "half "+s, off, 4, suffix))
			cc = append(cc, newComponent(suffix+"_"+w2, 4, "half "+s, off+4, 4, suffix))
		}

	case asmEmptyInterface:
		cc = append(cc, newComponent(suffix+"_type", asmKind(arch.ptrSize), "interface type", off, arch.ptrSize, suffix))
		cc = append(cc, newComponent(suffix+"_data", asmKind(arch.ptrSize), "interface data", off+arch.ptrSize, arch.ptrSize, suffix))

	case asmInterface:
		cc = append(cc, newComponent(suffix+"_itable", asmKind(arch.ptrSize), "interface itable", off, arch.ptrSize, suffix))
		cc = append(cc, newComponent(suffix+"_data", asmKind(arch.ptrSize), "interface data", off+arch.ptrSize, arch.ptrSize, suffix))

	case asmSlice:
		cc = append(cc, newComponent(suffix+"_base", asmKind(arch.ptrSize), "slice base", off, arch.ptrSize, suffix))
		cc = append(cc, newComponent(suffix+"_len", asmKind(arch.intSize), "slice len", off+arch.ptrSize, arch.intSize, suffix))
		cc = append(cc, newComponent(suffix+"_cap", asmKind(arch.intSize), "slice cap", off+arch.ptrSize+arch.intSize, arch.intSize, suffix))

	case asmString:
		cc = append(cc, newComponent(suffix+"_base", asmKind(arch.ptrSize), "string base", off, arch.ptrSize, suffix))
		cc = append(cc, newComponent(suffix+"_len", asmKind(arch.intSize), "string len", off+arch.ptrSize, arch.intSize, suffix))

	case asmComplex:
		fsize := size / 2
		cc = append(cc, newComponent(suffix+"_real", asmKind(fsize), fmt.Sprintf("real(complex%d)", size*8), off, fsize, suffix))
		cc = append(cc, newComponent(suffix+"_imag", asmKind(fsize), fmt.Sprintf("imag(complex%d)", size*8), off+fsize, fsize, suffix))

	case asmStruct:
		tu := t.Underlying().(*types.Struct)
		fields := make([]*types.Var, tu.NumFields())
		for i := 0; i < tu.NumFields(); i++ {
			fields[i] = tu.Field(i)
		}
		offsets := arch.sizes.Offsetsof(fields)
		for i, f := range fields {
			cc = appendComponentsRecursive(arch, f.Type(), cc, suffix+"_"+f.Name(), off+int(offsets[i]))
		}

	case asmArray:
		tu := t.Underlying().(*types.Array)
		elem := tu.Elem()
		// Calculate offset of each element array.
		fields := []*types.Var{
			types.NewVar(token.NoPos, nil, "fake0", elem),
			types.NewVar(token.NoPos, nil, "fake1", elem),
		}
		offsets := arch.sizes.Offsetsof(fields)
		elemoff := int(offsets[1])
		for i := 0; i < int(tu.Len()); i++ {
			cc = appendComponentsRecursive(arch, elem, cc, suffix+"_"+strconv.Itoa(i), off+i*elemoff)
		}
	}

	return cc
}

// asmParseDecl parses a function decl for expected assembly variables.
func asmParseDecl(pass *analysis.Pass, decl *ast.FuncDecl) map[string]*asmFunc {
	var (
		arch   *asmArch
		fn     *asmFunc
		offset int
	)

	// addParams adds asmVars for each of the parameters in list.
	// isret indicates whether the list are the arguments or the return values.
	// TODO(adonovan): simplify by passing (*types.Signature).{Params,Results}
	// instead of list.
	addParams := func(list []*ast.Field, isret bool) {
		argnum := 0
		for _, fld := range list {
			t := pass.TypesInfo.Types[fld.Type].Type

			// Work around https://golang.org/issue/28277.
			if t == nil {
				if ell, ok := fld.Type.(*ast.Ellipsis); ok {
					t = types.NewSlice(pass.TypesInfo.Types[ell.Elt].Type)
				}
			}

			align := int(arch.sizes.Alignof(t))
			size := int(arch.sizes.Sizeof(t))
			offset += -offset & (align - 1)
			cc := componentsOfType(arch, t)

			// names is the list of names with this type.
			names := fld.Names
			if len(names) == 0 {
				// Anonymous args will be called arg, arg1, arg2, ...
				// Similarly so for return values: ret, ret1, ret2, ...
				name := "arg"
				if isret {
					name = "ret"
				}
				if argnum > 0 {
					name += strconv.Itoa(argnum)
				}
				names = []*ast.Ident{ast.NewIdent(name)}
			}
			argnum += len(names)

			// Create variable for each name.
			for _, id := range names {
				name := id.Name
				for _, c := range cc {
					outer := name + c.outer
					v := asmVar{
						name: name + c.suffix,
						kind: c.kind,
						typ:  c.typ,
						off:  offset + c.offset,
						size: c.size,
					}
					if vo := fn.vars[outer]; vo != nil {
						vo.inner = append(vo.inner, &v)
					}
					fn.vars[v.name] = &v
					for i := 0; i < v.size; i++ {
						fn.varByOffset[v.off+i] = &v
					}
				}
				offset += size
			}
		}
	}

	m := make(map[string]*asmFunc)
	for _, arch = range arches {
		fn = &asmFunc{
			arch:        arch,
			vars:        make(map[string]*asmVar),
			varByOffset: make(map[int]*asmVar),
		}
		offset = 0
		addParams(decl.Type.Params.List, false)
		if decl.Type.Results != nil && len(decl.Type.Results.List) > 0 {
			offset += -offset & (arch.maxAlign - 1)
			addParams(decl.Type.Results.List, true)
		}
		fn.size = offset
		m[arch.name] = fn
	}

	return m
}

// asmCheckVar checks a single variable reference.
func asmCheckVar(badf func(string, ...interface{}), fn *asmFunc, line, expr string, off int, v *asmVar, archDef *asmArch) {
	m := asmOpcode.FindStringSubmatch(line)
	if m == nil {
		if !strings.HasPrefix(strings.TrimSpace(line), "//") {
			badf("cannot find assembly opcode")
		}
		return
	}

	addr := strings.HasPrefix(expr, "$")

	// Determine operand sizes from instruction.
	// Typically the suffix suffices, but there are exceptions.
	var src, dst, kind asmKind
	op := m[1]
	switch fn.arch.name + "." + op {
	case "386.FMOVLP":
		src, dst = 8, 4
	case "arm.MOVD":
		src = 8
	case "arm.MOVW":
		src = 4
	case "arm.MOVH", "arm.MOVHU":
		src = 2
	case "arm.MOVB", "arm.MOVBU":
		src = 1
	// LEA* opcodes don't really read the second arg.
	// They just take the address of it.
	case "386.LEAL":
		dst = 4
		addr = true
	case "amd64.LEAQ":
		dst = 8
		addr = true
	default:
		switch fn.arch.name {
		case "386", "amd64":
			if strings.HasPrefix(op, "F") && (strings.HasSuffix(op, "D") || strings.HasSuffix(op, "DP")) {
				// FMOVDP, FXCHD, etc
				src = 8
				break
			}
			if strings.HasPrefix(op, "P") && strings.HasSuffix(op, "RD") {
				// PINSRD, PEXTRD, etc
				src = 4
				break
			}
			if strings.HasPrefix(op, "F") && (strings.HasSuffix(op, "F") || strings.HasSuffix(op, "FP")) {
				// FMOVFP, FXCHF, etc
				src = 4
				break
			}
			if strings.HasSuffix(op, "SD") {
				// MOVSD, SQRTSD, etc
				src = 8
				break
			}
			if strings.HasSuffix(op, "SS") {
				// MOVSS, SQRTSS, etc
				src = 4
				break
			}
			if op == "MOVO" || op == "MOVOU" {
				src = 16
				break
			}
			if strings.HasPrefix(op, "SET") {
				// SETEQ, etc
				src = 1
				break
			}
			switch op[len(op)-1] {
			case 'B':
				src = 1
			case 'W':
				src = 2
			case 'L':
				src = 4
			case 'D', 'Q':
				src = 8
			}
		case "ppc64", "ppc64le":
			// Strip standard suffixes to reveal size letter.
			m := ppc64Suff.FindStringSubmatch(op)
			if m != nil {
				switch m[1][0] {
				case 'B':
					src = 1
				case 'H':
					src = 2
				case 'W':
					src = 4
				case 'D':
					src = 8
				}
			}
		case "loong64", "mips", "mipsle", "mips64", "mips64le":
			switch op {
			case "MOVB", "MOVBU":
				src = 1
			case "MOVH", "MOVHU":
				src = 2
			case "MOVW", "MOVWU", "MOVF":
				src = 4
			case "MOVV", "MOVD":
				src = 8
			}
		case "s390x":
			switch op {
			case "MOVB", "MOVBZ":
				src = 1
			case "MOVH", "MOVHZ":
				src = 2
			case "MOVW", "MOVWZ", "FMOVS":
				src = 4
			case "MOVD", "FMOVD":
				src = 8
			}
		}
	}
	if dst == 0 {
		dst = src
	}

	// Determine whether the match we're holding
	// is the first or second argument.
	if strings.Index(line, expr) > strings.Index(line, ",") {
		kind = dst
	} else {
		kind = src
	}

	vk := v.kind
	vs := v.size
	vt := v.typ
	switch vk {
	case asmInterface, asmEmptyInterface, asmString, asmSlice:
		// allow reference to first word (pointer)
		vk = v.inner[0].kind
		vs = v.inner[0].size
		vt = v.inner[0].typ
	case asmComplex:
		// Allow a single instruction to load both parts of a complex.
		if int(kind) == vs {
			kind = asmComplex
		}
	}
	if addr {
		vk = asmKind(archDef.ptrSize)
		vs = archDef.ptrSize
		vt = "address"
	}

	if off != v.off {
		var inner bytes.Buffer
		for i, vi := range v.inner {
			if len(v.inner) > 1 {
				fmt.Fprintf(&inner, ",")
			}
			fmt.Fprintf(&inner, " ")
			if i == len(v.inner)-1 {
				fmt.Fprintf(&inner, "or ")
			}
			fmt.Fprintf(&inner, "%s+%d(FP)", vi.name, vi.off)
		}
		badf("invalid offset %s; expected %s+%d(FP)%s", expr, v.name, v.off, inner.String())
		return
	}
	if kind != 0 && kind != vk {
		var inner bytes.Buffer
		if len(v.inner) > 0 {
			fmt.Fprintf(&inner, " containing")
			for i, vi := range v.inner {
				if i > 0 && len(v.inner) > 2 {
					fmt.Fprintf(&inner, ",")
				}
				fmt.Fprintf(&inner, " ")
				if i > 0 && i == len(v.inner)-1 {
					fmt.Fprintf(&inner, "and ")
				}
				fmt.Fprintf(&inner, "%s+%d(FP)", vi.name, vi.off)
			}
		}
		badf("invalid %s of %s; %s is %d-byte value%s", op, expr, vt, vs, inner.String())
	}
}

"""



```