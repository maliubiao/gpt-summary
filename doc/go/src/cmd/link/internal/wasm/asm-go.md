Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - Context and Purpose:**

* **File Path:** `go/src/cmd/link/internal/wasm/asm.go` immediately tells us this code is part of the Go linker, specifically dealing with WebAssembly. The `asm` suggests assembly or binary generation.
* **Package:** `package wasm` reinforces the WebAssembly focus.
* **Copyright and License:** Standard Go boilerplate, confirming it's part of the Go project.
* **Imports:**  These are crucial for understanding dependencies and capabilities:
    * `cmd/internal/obj`, `cmd/internal/obj/wasm`, `cmd/internal/objabi`: Low-level object file representation and architecture-specific details, especially for WebAssembly.
    * `cmd/link/internal/ld`, `cmd/link/internal/loader`, `cmd/link/internal/sym`: Core linker components for handling linking, loading, and symbols.
    * `fmt`, `bytes`, `io`, `regexp`: Standard Go libraries for formatting, byte manipulation, input/output, and regular expressions.
    * `internal/abi`, `internal/buildcfg`: Internal Go packages for ABI details and build configuration.

**2. High-Level Functionality Identification (Scanning for Key Functions and Structures):**

* **Constants:**  `I32`, `I64`, `F32`, `F64` clearly represent WebAssembly data types. `sectionCustom`, `sectionType`, etc., define the different sections of a WebAssembly module.
* **`gentext` function:** Empty. This might be a placeholder or have functionality elsewhere in the linker.
* **`wasmFunc` and `wasmFuncType` structs:**  These are key data structures for representing WebAssembly functions and their type signatures (parameters and results).
* **`readWasmImport` function:**  Handles reading information about imported WebAssembly functions.
* **`wasmFuncTypes` map:** A hardcoded mapping of Go function names to their WebAssembly type signatures. This suggests these are special runtime or helper functions.
* **`assignAddress` function:**  Deals with assigning addresses to symbols, but with a WebAssembly-specific twist related to function indices and the `funcValueOffset`.
* **`wasmDataSect` struct and `dataSects` variable:** Likely used to manage data sections within the WebAssembly module.
* **`asmb` function:** Seems to prepare data sections for the final output.
* **`asmb2` function:** This looks like the core function responsible for generating the WebAssembly binary itself. The extensive code within it, the writing of magic numbers, version, and different sections strongly suggests this.
* **Helper functions like `lookupType`, `writeSecHeader`, `writeSecSize`, `writeBuildID`, `writeTypeSec`, etc.:** These are clearly modular components for writing different parts of the WebAssembly binary format.
* **Helper functions for writing constants (`writeI32Const`, `writeI64Const`), names (`writeName`), and LEB128 encoding (`writeUleb128`, `writeSleb128`):**  Essential for writing the binary format correctly.
* **`fieldsToTypes` function:** Converts Go's internal representation of types to WebAssembly type bytes.

**3. Detailed Analysis and Function-Specific Breakdown:**

* **`asmb2` is the core:** Focus on the order of operations within `asmb2`. It:
    * Initializes `types`.
    * Collects `hostImports` by scanning relocations of type `objabi.R_WASMIMPORT`. This links Go code to external WebAssembly functions.
    * Collects `fns` (native Go functions compiled to WebAssembly) and handles relocations within their code. Crucially, it handles `objabi.R_ADDR`, `objabi.R_CALL`, and `objabi.R_WASMIMPORT` relocations, showing how Go symbols are translated into WebAssembly instructions and function indices.
    * Writes the WebAssembly module header (magic number and version).
    * Writes various sections in the correct order: Type, Import, Function, Table, Memory, Global, Export, Element, Code, Data, Producer, and optionally Name. The order matters for WebAssembly validity.

* **Relocation Handling:**  Pay close attention to the relocation handling within the loop in `asmb2`. The `switch r.Type()` block is critical.
    * `objabi.R_ADDR`: Writes the address of a symbol (likely for data).
    * `objabi.R_CALL`: Writes the WebAssembly function index for a call. The offset calculation `int64(len(hostImports))+ldr.SymValue(rs)>>16-funcValueOffset` is important. The `>>16` and `funcValueOffset` relate back to the `assignAddress` function.
    * `objabi.R_WASMIMPORT`: Writes the pre-calculated index of an imported function.

* **Section Writing Functions:** Each `write...Sec` function corresponds to a specific WebAssembly section. Understanding the data being written to each section (function types, imports, function indices, memory details, exports, etc.) is crucial.

* **LEB128 Encoding:** Recognize the purpose of `writeUleb128` and `writeSleb128` for encoding variable-length integers as required by the WebAssembly binary format.

**4. Inferring Go Feature Implementation:**

* **Calling External WebAssembly:** The handling of `objabi.R_WASMIMPORT` and the `hostImports` collection clearly indicates the implementation of the ability for Go code to call functions defined in external WebAssembly modules (like JavaScript environments or WASI).

* **Exporting Go Functions to WebAssembly:** The `writeExportSec` function, particularly how it handles `ldr.WasmExports`, reveals how Go functions can be exposed for consumption by the WebAssembly host. The different logic for "js" and "wasip1" GOOS highlights platform-specific export mechanisms.

**5. Code Example Construction (Based on Inferences):**

Based on the understanding of import and export handling, the example code focuses on demonstrating the Go side of defining an import and an export.

**6. Command-Line Arguments and Potential Errors:**

* **Command-Line Arguments:** The code itself doesn't explicitly parse command-line arguments. However, its role within the `cmd/link` package suggests it's influenced by linker flags. The `-buildmode` flag is evident in the `writeExportSec` function's logic for different GOOS values.
* **Common Mistakes:**  The potential errors revolve around mismatches between Go function signatures and the declared WebAssembly types, incorrect import/export declarations, and forgetting necessary imports or exports.

**7. Iterative Refinement:**

Throughout this process, it's important to go back and forth between different parts of the code. For example, understanding `assignAddress` helps clarify the relocation logic in `asmb2`. Seeing how `wasmFuncTypes` is used clarifies its purpose.

By systematically analyzing the code structure, function roles, and data flow, along with understanding the WebAssembly binary format, we can arrive at a comprehensive understanding of the code's functionality.
这段代码是 Go 语言链接器 `cmd/link` 中 `wasm` 包的一部分，主要负责将 Go 代码链接成 WebAssembly 模块。以下是其主要功能：

**1. 定义 WebAssembly 常量和数据结构:**

*   定义了 WebAssembly 的基本数据类型常量，如 `I32`, `I64`, `F32`, `F64`。
*   定义了 WebAssembly 模块的段 (section) 类型常量，如 `sectionCustom`, `sectionType`, `sectionImport` 等。
*   定义了 `funcValueOffset` 常量，用于调整 Go 函数在 WebAssembly 中的地址，以避免与内存地址冲突。
*   定义了 `wasmFunc` 结构体，用于表示一个 WebAssembly 函数，包含模块名、函数名、类型索引和代码。
*   定义了 `wasmFuncType` 结构体，用于表示 WebAssembly 函数的类型签名，包含参数类型列表和返回值类型列表。

**2. 读取 WebAssembly 导入信息:**

*   `readWasmImport` 函数用于从链接器加载器 `loader.Loader` 中读取 WebAssembly 导入符号 (类型为 `obj.WasmImport`) 的信息。

**3. 预定义的 WebAssembly 函数类型:**

*   `wasmFuncTypes` 变量是一个 `map`，存储了一些 Go 运行时或特殊用途的函数及其对应的 WebAssembly 函数类型签名。例如：
    *   `_rt0_wasm_js`, `_rt0_wasm_wasip1`, `_rt0_wasm_wasip1_lib`: WebAssembly 启动函数，无参数。
    *   `wasm_export_run`, `wasm_export_resume`, `wasm_export_getsp`:  用于与 JavaScript 或 WASI 宿主环境交互的导出函数。
    *   `runtime.wasmDiv`, `runtime.wasmTruncS`, `runtime.wasmTruncU`:  Go 运行时提供的 WebAssembly 数学运算辅助函数。
    *   `gcWriteBarrier`:  Go 垃圾回收相关的写屏障函数。
    *   `cmpbody`, `memeqbody`, `memcmp`, `memchr`:  内存比较和查找相关的函数。

**4. 分配 WebAssembly 函数地址:**

*   `assignAddress` 函数用于为 Go 函数在 WebAssembly 模块中分配地址。
*   WebAssembly 函数不使用线性内存地址，而是使用索引。
*   导入的函数索引从 0 开始，本地函数索引从 `n+1` 开始。
*   Go 函数的 "PC" (程序计数器) 被编码为 `PC_F<<16 + PC_B`，其中 `PC_F` 与 WebAssembly 函数索引有关，`PC_B` 是函数内部的偏移量（恢复点）。
*   `funcValueOffset` 被添加到函数索引中以生成 `PC_F`，以避免与 Go 运行时对函数地址的假设冲突。

**5. 处理数据段:**

*   `wasmDataSect` 结构体用于表示一个数据段及其内容。
*   `dataSects` 变量是一个切片，存储了 Go 程序中各个数据段的信息（如只读数据、类型信息、符号表等）。
*   `asmb` 函数用于收集 Go 程序中的数据段，并将它们的起始地址和长度信息存储到 `dataSects` 中。

**6. 生成 WebAssembly 模块二进制代码 (核心功能):**

*   `asmb2` 函数是生成最终 WebAssembly 模块二进制代码的核心函数。它按照 WebAssembly 的二进制格式规范，将 Go 代码编译和链接成的各种信息写入输出流。
*   **收集类型信息:**  收集所有用到的函数类型，并去重。初始包含一个默认的函数类型 `([]I32) -> []I32`，用于表示一般的 Go 函数（参数是 PC_B，返回值表示是否需要栈回溯）。
*   **收集宿主导入 (Host Imports):** 遍历所有文本段 (函数)，查找 `R_WASMIMPORT` 类型的重定位，这些重定位指向需要从宿主环境（如 JavaScript）导入的函数。将导入函数的模块名、函数名和类型信息添加到 `hostImports` 列表中。
*   **收集本地函数 (Functions with WebAssembly Body):** 遍历所有文本段，对于每个函数，将其编译后的 WebAssembly 代码写入 `wfn` (`bytes.Buffer`)。在写入代码的过程中，处理各种类型的重定位：
    *   `R_ADDR`:  写入符号的地址。
    *   `R_CALL`:  写入被调用函数的 WebAssembly 索引（需要考虑导入函数的数量和 `funcValueOffset`）。
    *   `R_WASMIMPORT`: 写入导入函数的索引。
*   **写入 WebAssembly 模块的各个段:**  按照 WebAssembly 的二进制格式顺序写入各个段：
    *   **Magic Number 和 Version:**  模块的起始标识。
    *   **Custom Section (可选):**  可以包含自定义信息，例如 `go:buildid` (构建 ID)。
    *   **Type Section:**  声明所有用到的函数类型。
    *   **Import Section:**  列出所有从宿主环境导入的函数。
    *   **Function Section:**  声明所有本地函数的类型索引。
    *   **Table Section:**  声明表 (Table)，目前只声明一个用于 `call_indirect` 指令的表。
    *   **Memory Section:**  声明线性内存，设置初始大小。
    *   **Global Section:**  声明全局变量，例如 Go 运行时的 SP, CTXT, g 等寄存器。
    *   **Export Section:**  声明需要导出的函数和内存，以便宿主环境可以访问。导出的内容取决于目标操作系统 (`GOOS`) 和构建模式 (`BuildMode`)。例如，对于 `js` 目标，会导出 `run`, `resume`, `getsp` 等函数和 `mem` 内存。对于 `wasip1` 目标，会导出 `_start` 或 `_initialize` 等入口函数。
    *   **Element Section:**  初始化表的内容，将函数索引写入表中。
    *   **Code Section:**  包含本地函数的代码。
    *   **Data Section:**  包含初始化线性内存的数据。为了减小 wasm 文件大小，会跳过连续的零字节。
    *   **Producer Section (可选):**  记录生成 wasm 文件的工具和版本信息。
    *   **Name Section (可选):**  包含函数名，用于调试和反编译。

**7. 辅助函数:**

*   `lookupType`:  在已有的函数类型列表中查找给定的类型签名，如果不存在则添加并返回索引。
*   `writeSecHeader`, `writeSecSize`:  用于写入 WebAssembly 段的头部信息（段 ID 和大小）。
*   `writeBuildID`, `writeTypeSec`, `writeImportSec`, `writeFunctionSec`, `writeTableSec`, `writeMemorySec`, `writeGlobalSec`, `writeExportSec`, `writeElementSec`, `writeCodeSec`, `writeDataSec`, `writeProducerSec`, `writeNameSec`:  分别用于写入不同类型的 WebAssembly 段。
*   `writeI32Const`, `writeI64Const`:  写入 i32 和 i64 类型的常量指令。
*   `writeName`:  写入 UTF-8 编码的名称。
*   `writeUleb128`, `writeUleb128FixedLength`, `writeSleb128`:  写入 LEB128 编码的无符号和有符号整数。
*   `fieldsToTypes`:  将 `obj.WasmField` 切片转换为 WebAssembly 类型字节切片。

**它可以推理出这是 Go 语言链接器中用于生成 WebAssembly 模块的功能实现。**

**Go 代码举例说明 (导出 Go 函数到 WebAssembly):**

假设我们有以下 Go 代码想要编译成 WebAssembly 并导出一个函数：

```go
package main

import "fmt"

//export add
func add(x, y int) int {
	return x + y
}

func main() {
	fmt.Println(add(5, 3))
}
```

在这个例子中，我们使用了 `//export add` 注释来标记 `add` 函数需要被导出到 WebAssembly 模块。

**假设的输入与输出:**

*   **输入:** 上述的 `main.go` 文件。
*   **链接器处理:** 当 Go 链接器 (通过 `go build -o output.wasm`) 处理这个文件时，`asm.go` 中的代码会被调用。
*   **`asmb2` 函数处理:**
    *   `wasmFuncTypes` 中可能没有 `add` 函数的类型信息，但会根据 `add` 函数的签名 (两个 `int` 参数，一个 `int` 返回值) 推断出其 WebAssembly 类型签名（可能是 `[]byte{I32, I32}`, `[]byte{I32}`）。
    *   `add` 函数的代码会被编译成 WebAssembly 指令，并存储在 `fns` 中。
    *   在 `writeExportSec` 函数中，由于 `add` 函数带有 `//export` 注释，链接器会将 `add` 函数的信息写入到 Export Section 中，以便宿主环境可以通过名称 "add" 调用这个函数。
*   **输出:**  最终生成的 `output.wasm` 文件将会包含 Export Section，其中会定义一个名为 "add" 的导出项，其类型为 function，索引指向 `add` 函数在 Function Section 中的位置。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。然而，作为 `cmd/link` 的一部分，它的行为会受到链接器命令行参数的影响。一些相关的参数可能包括：

*   **`-o <outfile>`:**  指定输出的 WebAssembly 文件名。
*   **`-buildmode=wasm`:**  指定构建模式为 WebAssembly。
*   **`-ldflags`:**  可以传递链接器标志，这些标志可能会影响链接过程，但不会直接被这段代码解析。
*   **`-trimpath`:**  可能会影响生成的文件路径信息。

链接器会解析命令行参数，并根据这些参数配置链接过程，例如选择目标架构 (wasm)，设置输出文件等。`asm.go` 中的代码会根据链接器的配置信息来生成 WebAssembly 模块。

**使用者易犯错的点:**

虽然这段代码是链接器内部实现，普通 Go 开发者不会直接接触，但在使用 `//export` 注释将 Go 函数导出到 WebAssembly 时，容易犯以下错误：

1. **导出的函数签名不被 WebAssembly 支持:** WebAssembly 目前只支持有限的数据类型。如果在导出的 Go 函数中使用了 WebAssembly 不支持的类型（例如 Go 的切片、map、interface 等），链接器可能会报错，或者生成的 WebAssembly 代码无法正确运行。需要将这些复杂类型转换为 WebAssembly 支持的基本类型（如 i32, i64, f32, f64）。

    ```go
    // 错误示例：导出的函数使用了切片
    //export processData
    func processData(data []int) int {
        return len(data)
    }
    ```

2. **没有在 `main` 包中导出函数:**  `//export` 注释只能用于 `main` 包中的函数。尝试在其他包中导出函数会导致链接错误。

3. **导出的函数名与已有的导出项冲突:** 如果导出的函数名与 WebAssembly 模块中已有的导出项（例如运行时提供的导出项）冲突，链接器会报错。

4. **忘记导入必要的包:** 如果导出的函数依赖于其他包的功能，需要确保正确导入这些包。

总而言之，`go/src/cmd/link/internal/wasm/asm.go` 是 Go 语言链接器中至关重要的组成部分，它负责将 Go 代码转换和组装成符合 WebAssembly 规范的二进制模块，是 Go 语言支持 WebAssembly 目标平台的核心实现之一。

Prompt: 
```
这是路径为go/src/cmd/link/internal/wasm/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wasm

import (
	"bytes"
	"cmd/internal/obj"
	"cmd/internal/obj/wasm"
	"cmd/internal/objabi"
	"cmd/link/internal/ld"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"fmt"
	"internal/abi"
	"internal/buildcfg"
	"io"
	"regexp"
)

const (
	I32 = 0x7F
	I64 = 0x7E
	F32 = 0x7D
	F64 = 0x7C
)

const (
	sectionCustom   = 0
	sectionType     = 1
	sectionImport   = 2
	sectionFunction = 3
	sectionTable    = 4
	sectionMemory   = 5
	sectionGlobal   = 6
	sectionExport   = 7
	sectionStart    = 8
	sectionElement  = 9
	sectionCode     = 10
	sectionData     = 11
)

// funcValueOffset is the offset between the PC_F value of a function and the index of the function in WebAssembly
const funcValueOffset = 0x1000 // TODO(neelance): make function addresses play nice with heap addresses

func gentext(ctxt *ld.Link, ldr *loader.Loader) {
}

type wasmFunc struct {
	Module string
	Name   string
	Type   uint32
	Code   []byte
}

type wasmFuncType struct {
	Params  []byte
	Results []byte
}

func readWasmImport(ldr *loader.Loader, s loader.Sym) obj.WasmImport {
	var wi obj.WasmImport
	wi.Read(ldr.Data(s))
	return wi
}

var wasmFuncTypes = map[string]*wasmFuncType{
	"_rt0_wasm_js":            {Params: []byte{}},                                         //
	"_rt0_wasm_wasip1":        {Params: []byte{}},                                         //
	"_rt0_wasm_wasip1_lib":    {Params: []byte{}},                                         //
	"wasm_export__start":      {},                                                         //
	"wasm_export_run":         {Params: []byte{I32, I32}},                                 // argc, argv
	"wasm_export_resume":      {Params: []byte{}},                                         //
	"wasm_export_getsp":       {Results: []byte{I32}},                                     // sp
	"wasm_pc_f_loop":          {Params: []byte{}},                                         //
	"wasm_pc_f_loop_export":   {Params: []byte{I32}},                                      // pc_f
	"runtime.wasmDiv":         {Params: []byte{I64, I64}, Results: []byte{I64}},           // x, y -> x/y
	"runtime.wasmTruncS":      {Params: []byte{F64}, Results: []byte{I64}},                // x -> int(x)
	"runtime.wasmTruncU":      {Params: []byte{F64}, Results: []byte{I64}},                // x -> uint(x)
	"gcWriteBarrier":          {Params: []byte{I64}, Results: []byte{I64}},                // #bytes -> bufptr
	"runtime.gcWriteBarrier1": {Results: []byte{I64}},                                     // -> bufptr
	"runtime.gcWriteBarrier2": {Results: []byte{I64}},                                     // -> bufptr
	"runtime.gcWriteBarrier3": {Results: []byte{I64}},                                     // -> bufptr
	"runtime.gcWriteBarrier4": {Results: []byte{I64}},                                     // -> bufptr
	"runtime.gcWriteBarrier5": {Results: []byte{I64}},                                     // -> bufptr
	"runtime.gcWriteBarrier6": {Results: []byte{I64}},                                     // -> bufptr
	"runtime.gcWriteBarrier7": {Results: []byte{I64}},                                     // -> bufptr
	"runtime.gcWriteBarrier8": {Results: []byte{I64}},                                     // -> bufptr
	"cmpbody":                 {Params: []byte{I64, I64, I64, I64}, Results: []byte{I64}}, // a, alen, b, blen -> -1/0/1
	"memeqbody":               {Params: []byte{I64, I64, I64}, Results: []byte{I64}},      // a, b, len -> 0/1
	"memcmp":                  {Params: []byte{I32, I32, I32}, Results: []byte{I32}},      // a, b, len -> <0/0/>0
	"memchr":                  {Params: []byte{I32, I32, I32}, Results: []byte{I32}},      // s, c, len -> index
}

func assignAddress(ldr *loader.Loader, sect *sym.Section, n int, s loader.Sym, va uint64, isTramp bool) (*sym.Section, int, uint64) {
	// WebAssembly functions do not live in the same address space as the linear memory.
	// Instead, WebAssembly automatically assigns indices. Imported functions (section "import")
	// have indices 0 to n. They are followed by native functions (sections "function" and "code")
	// with indices n+1 and following.
	//
	// The following rules describe how wasm handles function indices and addresses:
	//   PC_F = funcValueOffset + WebAssembly function index (not including the imports)
	//   s.Value = PC = PC_F<<16 + PC_B
	//
	// The funcValueOffset is necessary to avoid conflicts with expectations
	// that the Go runtime has about function addresses.
	// The field "s.Value" corresponds to the concept of PC at runtime.
	// However, there is no PC register, only PC_F and PC_B. PC_F denotes the function,
	// PC_B the resume point inside of that function. The entry of the function has PC_B = 0.
	ldr.SetSymSect(s, sect)
	ldr.SetSymValue(s, int64(funcValueOffset+va/abi.MINFUNC)<<16) // va starts at zero
	va += uint64(abi.MINFUNC)
	return sect, n, va
}

type wasmDataSect struct {
	sect *sym.Section
	data []byte
}

var dataSects []wasmDataSect

func asmb(ctxt *ld.Link, ldr *loader.Loader) {
	sections := []*sym.Section{
		ldr.SymSect(ldr.Lookup("runtime.rodata", 0)),
		ldr.SymSect(ldr.Lookup("runtime.typelink", 0)),
		ldr.SymSect(ldr.Lookup("runtime.itablink", 0)),
		ldr.SymSect(ldr.Lookup("runtime.symtab", 0)),
		ldr.SymSect(ldr.Lookup("runtime.pclntab", 0)),
		ldr.SymSect(ldr.Lookup("runtime.noptrdata", 0)),
		ldr.SymSect(ldr.Lookup("runtime.data", 0)),
	}

	dataSects = make([]wasmDataSect, len(sections))
	for i, sect := range sections {
		data := ld.DatblkBytes(ctxt, int64(sect.Vaddr), int64(sect.Length))
		dataSects[i] = wasmDataSect{sect, data}
	}
}

// asmb writes the final WebAssembly module binary.
// Spec: https://webassembly.github.io/spec/core/binary/modules.html
func asmb2(ctxt *ld.Link, ldr *loader.Loader) {
	types := []*wasmFuncType{
		// For normal Go functions, the single parameter is PC_B,
		// the return value is
		// 0 if the function returned normally or
		// 1 if the stack needs to be unwound.
		{Params: []byte{I32}, Results: []byte{I32}},
	}

	// collect host imports (functions that get imported from the WebAssembly host, usually JavaScript)
	// we store the import index of each imported function, so the R_WASMIMPORT relocation
	// can write the correct index after a "call" instruction
	// these are added as import statements to the top of the WebAssembly binary
	var hostImports []*wasmFunc
	hostImportMap := make(map[loader.Sym]int64)
	for _, fn := range ctxt.Textp {
		relocs := ldr.Relocs(fn)
		for ri := 0; ri < relocs.Count(); ri++ {
			r := relocs.At(ri)
			if r.Type() == objabi.R_WASMIMPORT {
				if wsym := ldr.WasmImportSym(fn); wsym != 0 {
					wi := readWasmImport(ldr, wsym)
					hostImportMap[fn] = int64(len(hostImports))
					hostImports = append(hostImports, &wasmFunc{
						Module: wi.Module,
						Name:   wi.Name,
						Type: lookupType(&wasmFuncType{
							Params:  fieldsToTypes(wi.Params),
							Results: fieldsToTypes(wi.Results),
						}, &types),
					})
				} else {
					panic(fmt.Sprintf("missing wasm symbol for %s", ldr.SymName(r.Sym())))
				}
			}
		}
	}

	// collect functions with WebAssembly body
	var buildid []byte
	fns := make([]*wasmFunc, len(ctxt.Textp))
	for i, fn := range ctxt.Textp {
		wfn := new(bytes.Buffer)
		if ldr.SymName(fn) == "go:buildid" {
			writeUleb128(wfn, 0) // number of sets of locals
			writeI32Const(wfn, 0)
			wfn.WriteByte(0x0b) // end
			buildid = ldr.Data(fn)
		} else {
			// Relocations have variable length, handle them here.
			relocs := ldr.Relocs(fn)
			P := ldr.Data(fn)
			off := int32(0)
			for ri := 0; ri < relocs.Count(); ri++ {
				r := relocs.At(ri)
				if r.Siz() == 0 {
					continue // skip marker relocations
				}
				wfn.Write(P[off:r.Off()])
				off = r.Off()
				rs := r.Sym()
				switch r.Type() {
				case objabi.R_ADDR:
					writeSleb128(wfn, ldr.SymValue(rs)+r.Add())
				case objabi.R_CALL:
					writeSleb128(wfn, int64(len(hostImports))+ldr.SymValue(rs)>>16-funcValueOffset)
				case objabi.R_WASMIMPORT:
					writeSleb128(wfn, hostImportMap[rs])
				default:
					ldr.Errorf(fn, "bad reloc type %d (%s)", r.Type(), sym.RelocName(ctxt.Arch, r.Type()))
					continue
				}
			}
			wfn.Write(P[off:])
		}

		typ := uint32(0)
		if sig, ok := wasmFuncTypes[ldr.SymName(fn)]; ok {
			typ = lookupType(sig, &types)
		}
		if s := ldr.WasmTypeSym(fn); s != 0 {
			var o obj.WasmFuncType
			o.Read(ldr.Data(s))
			t := &wasmFuncType{
				Params:  fieldsToTypes(o.Params),
				Results: fieldsToTypes(o.Results),
			}
			typ = lookupType(t, &types)
		}

		name := nameRegexp.ReplaceAllString(ldr.SymName(fn), "_")
		fns[i] = &wasmFunc{Name: name, Type: typ, Code: wfn.Bytes()}
	}

	ctxt.Out.Write([]byte{0x00, 0x61, 0x73, 0x6d}) // magic
	ctxt.Out.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version

	// Add any buildid early in the binary:
	if len(buildid) != 0 {
		writeBuildID(ctxt, buildid)
	}

	writeTypeSec(ctxt, types)
	writeImportSec(ctxt, hostImports)
	writeFunctionSec(ctxt, fns)
	writeTableSec(ctxt, fns)
	writeMemorySec(ctxt, ldr)
	writeGlobalSec(ctxt)
	writeExportSec(ctxt, ldr, len(hostImports))
	writeElementSec(ctxt, uint64(len(hostImports)), uint64(len(fns)))
	writeCodeSec(ctxt, fns)
	writeDataSec(ctxt)
	writeProducerSec(ctxt)
	if !*ld.FlagS {
		writeNameSec(ctxt, len(hostImports), fns)
	}
}

func lookupType(sig *wasmFuncType, types *[]*wasmFuncType) uint32 {
	for i, t := range *types {
		if bytes.Equal(sig.Params, t.Params) && bytes.Equal(sig.Results, t.Results) {
			return uint32(i)
		}
	}
	*types = append(*types, sig)
	return uint32(len(*types) - 1)
}

func writeSecHeader(ctxt *ld.Link, id uint8) int64 {
	ctxt.Out.WriteByte(id)
	sizeOffset := ctxt.Out.Offset()
	ctxt.Out.Write(make([]byte, 5)) // placeholder for length
	return sizeOffset
}

func writeSecSize(ctxt *ld.Link, sizeOffset int64) {
	endOffset := ctxt.Out.Offset()
	ctxt.Out.SeekSet(sizeOffset)
	writeUleb128FixedLength(ctxt.Out, uint64(endOffset-sizeOffset-5), 5)
	ctxt.Out.SeekSet(endOffset)
}

func writeBuildID(ctxt *ld.Link, buildid []byte) {
	sizeOffset := writeSecHeader(ctxt, sectionCustom)
	writeName(ctxt.Out, "go:buildid")
	ctxt.Out.Write(buildid)
	writeSecSize(ctxt, sizeOffset)
}

// writeTypeSec writes the section that declares all function types
// so they can be referenced by index.
func writeTypeSec(ctxt *ld.Link, types []*wasmFuncType) {
	sizeOffset := writeSecHeader(ctxt, sectionType)

	writeUleb128(ctxt.Out, uint64(len(types)))

	for _, t := range types {
		ctxt.Out.WriteByte(0x60) // functype
		writeUleb128(ctxt.Out, uint64(len(t.Params)))
		for _, v := range t.Params {
			ctxt.Out.WriteByte(byte(v))
		}
		writeUleb128(ctxt.Out, uint64(len(t.Results)))
		for _, v := range t.Results {
			ctxt.Out.WriteByte(byte(v))
		}
	}

	writeSecSize(ctxt, sizeOffset)
}

// writeImportSec writes the section that lists the functions that get
// imported from the WebAssembly host, usually JavaScript.
func writeImportSec(ctxt *ld.Link, hostImports []*wasmFunc) {
	sizeOffset := writeSecHeader(ctxt, sectionImport)

	writeUleb128(ctxt.Out, uint64(len(hostImports))) // number of imports
	for _, fn := range hostImports {
		if fn.Module != "" {
			writeName(ctxt.Out, fn.Module)
		} else {
			writeName(ctxt.Out, wasm.GojsModule) // provided by the import object in wasm_exec.js
		}
		writeName(ctxt.Out, fn.Name)
		ctxt.Out.WriteByte(0x00) // func import
		writeUleb128(ctxt.Out, uint64(fn.Type))
	}

	writeSecSize(ctxt, sizeOffset)
}

// writeFunctionSec writes the section that declares the types of functions.
// The bodies of these functions will later be provided in the "code" section.
func writeFunctionSec(ctxt *ld.Link, fns []*wasmFunc) {
	sizeOffset := writeSecHeader(ctxt, sectionFunction)

	writeUleb128(ctxt.Out, uint64(len(fns)))
	for _, fn := range fns {
		writeUleb128(ctxt.Out, uint64(fn.Type))
	}

	writeSecSize(ctxt, sizeOffset)
}

// writeTableSec writes the section that declares tables. Currently there is only a single table
// that is used by the CallIndirect operation to dynamically call any function.
// The contents of the table get initialized by the "element" section.
func writeTableSec(ctxt *ld.Link, fns []*wasmFunc) {
	sizeOffset := writeSecHeader(ctxt, sectionTable)

	numElements := uint64(funcValueOffset + len(fns))
	writeUleb128(ctxt.Out, 1)           // number of tables
	ctxt.Out.WriteByte(0x70)            // type: anyfunc
	ctxt.Out.WriteByte(0x00)            // no max
	writeUleb128(ctxt.Out, numElements) // min

	writeSecSize(ctxt, sizeOffset)
}

// writeMemorySec writes the section that declares linear memories. Currently one linear memory is being used.
// Linear memory always starts at address zero. More memory can be requested with the GrowMemory instruction.
func writeMemorySec(ctxt *ld.Link, ldr *loader.Loader) {
	sizeOffset := writeSecHeader(ctxt, sectionMemory)

	dataEnd := uint64(ldr.SymValue(ldr.Lookup("runtime.end", 0)))
	var initialSize = dataEnd + 1<<20 // 1 MB, for runtime init allocating a few pages

	const wasmPageSize = 64 << 10 // 64KB

	writeUleb128(ctxt.Out, 1)                        // number of memories
	ctxt.Out.WriteByte(0x00)                         // no maximum memory size
	writeUleb128(ctxt.Out, initialSize/wasmPageSize) // minimum (initial) memory size

	writeSecSize(ctxt, sizeOffset)
}

// writeGlobalSec writes the section that declares global variables.
func writeGlobalSec(ctxt *ld.Link) {
	sizeOffset := writeSecHeader(ctxt, sectionGlobal)

	globalRegs := []byte{
		I32, // 0: SP
		I64, // 1: CTXT
		I64, // 2: g
		I64, // 3: RET0
		I64, // 4: RET1
		I64, // 5: RET2
		I64, // 6: RET3
		I32, // 7: PAUSE
	}

	writeUleb128(ctxt.Out, uint64(len(globalRegs))) // number of globals

	for _, typ := range globalRegs {
		ctxt.Out.WriteByte(typ)
		ctxt.Out.WriteByte(0x01) // var
		switch typ {
		case I32:
			writeI32Const(ctxt.Out, 0)
		case I64:
			writeI64Const(ctxt.Out, 0)
		}
		ctxt.Out.WriteByte(0x0b) // end
	}

	writeSecSize(ctxt, sizeOffset)
}

// writeExportSec writes the section that declares exports.
// Exports can be accessed by the WebAssembly host, usually JavaScript.
// The wasm_export_* functions and the linear memory get exported.
func writeExportSec(ctxt *ld.Link, ldr *loader.Loader, lenHostImports int) {
	sizeOffset := writeSecHeader(ctxt, sectionExport)

	switch buildcfg.GOOS {
	case "wasip1":
		writeUleb128(ctxt.Out, uint64(2+len(ldr.WasmExports))) // number of exports
		var entry, entryExpName string
		switch ctxt.BuildMode {
		case ld.BuildModeExe:
			entry = "_rt0_wasm_wasip1"
			entryExpName = "_start"
		case ld.BuildModeCShared:
			entry = "_rt0_wasm_wasip1_lib"
			entryExpName = "_initialize"
		}
		s := ldr.Lookup(entry, 0)
		if s == 0 {
			ld.Errorf("export symbol %s not defined", entry)
		}
		idx := uint32(lenHostImports) + uint32(ldr.SymValue(s)>>16) - funcValueOffset
		writeName(ctxt.Out, entryExpName)   // the wasi entrypoint
		ctxt.Out.WriteByte(0x00)            // func export
		writeUleb128(ctxt.Out, uint64(idx)) // funcidx
		for _, s := range ldr.WasmExports {
			idx := uint32(lenHostImports) + uint32(ldr.SymValue(s)>>16) - funcValueOffset
			writeName(ctxt.Out, ldr.SymName(s))
			ctxt.Out.WriteByte(0x00)            // func export
			writeUleb128(ctxt.Out, uint64(idx)) // funcidx
		}
		writeName(ctxt.Out, "memory") // memory in wasi
		ctxt.Out.WriteByte(0x02)      // mem export
		writeUleb128(ctxt.Out, 0)     // memidx
	case "js":
		writeUleb128(ctxt.Out, uint64(4+len(ldr.WasmExports))) // number of exports
		for _, name := range []string{"run", "resume", "getsp"} {
			s := ldr.Lookup("wasm_export_"+name, 0)
			if s == 0 {
				ld.Errorf("export symbol %s not defined", "wasm_export_"+name)
			}
			idx := uint32(lenHostImports) + uint32(ldr.SymValue(s)>>16) - funcValueOffset
			writeName(ctxt.Out, name)           // inst.exports.run/resume/getsp in wasm_exec.js
			ctxt.Out.WriteByte(0x00)            // func export
			writeUleb128(ctxt.Out, uint64(idx)) // funcidx
		}
		for _, s := range ldr.WasmExports {
			idx := uint32(lenHostImports) + uint32(ldr.SymValue(s)>>16) - funcValueOffset
			writeName(ctxt.Out, ldr.SymName(s))
			ctxt.Out.WriteByte(0x00)            // func export
			writeUleb128(ctxt.Out, uint64(idx)) // funcidx
		}
		writeName(ctxt.Out, "mem") // inst.exports.mem in wasm_exec.js
		ctxt.Out.WriteByte(0x02)   // mem export
		writeUleb128(ctxt.Out, 0)  // memidx
	default:
		ld.Exitf("internal error: writeExportSec: unrecognized GOOS %s", buildcfg.GOOS)
	}

	writeSecSize(ctxt, sizeOffset)
}

// writeElementSec writes the section that initializes the tables declared by the "table" section.
// The table for CallIndirect gets initialized in a very simple way so that each table index (PC_F value)
// maps linearly to the function index (numImports + PC_F).
func writeElementSec(ctxt *ld.Link, numImports, numFns uint64) {
	sizeOffset := writeSecHeader(ctxt, sectionElement)

	writeUleb128(ctxt.Out, 1) // number of element segments

	writeUleb128(ctxt.Out, 0) // tableidx
	writeI32Const(ctxt.Out, funcValueOffset)
	ctxt.Out.WriteByte(0x0b) // end

	writeUleb128(ctxt.Out, numFns) // number of entries
	for i := uint64(0); i < numFns; i++ {
		writeUleb128(ctxt.Out, numImports+i)
	}

	writeSecSize(ctxt, sizeOffset)
}

// writeCodeSec writes the section that provides the function bodies for the functions
// declared by the "func" section.
func writeCodeSec(ctxt *ld.Link, fns []*wasmFunc) {
	sizeOffset := writeSecHeader(ctxt, sectionCode)

	writeUleb128(ctxt.Out, uint64(len(fns))) // number of code entries
	for _, fn := range fns {
		writeUleb128(ctxt.Out, uint64(len(fn.Code)))
		ctxt.Out.Write(fn.Code)
	}

	writeSecSize(ctxt, sizeOffset)
}

// writeDataSec writes the section that provides data that will be used to initialize the linear memory.
func writeDataSec(ctxt *ld.Link) {
	sizeOffset := writeSecHeader(ctxt, sectionData)

	type dataSegment struct {
		offset int32
		data   []byte
	}

	// Omit blocks of zeroes and instead emit data segments with offsets skipping the zeroes.
	// This reduces the size of the WebAssembly binary. We use 8 bytes as an estimate for the
	// overhead of adding a new segment (same as wasm-opt's memory-packing optimization uses).
	const segmentOverhead = 8

	// Generate at most this many segments. A higher number of segments gets rejected by some WebAssembly runtimes.
	const maxNumSegments = 100000

	var segments []*dataSegment
	for secIndex, ds := range dataSects {
		data := ds.data
		offset := int32(ds.sect.Vaddr)

		// skip leading zeroes
		for len(data) > 0 && data[0] == 0 {
			data = data[1:]
			offset++
		}

		for len(data) > 0 {
			dataLen := int32(len(data))
			var segmentEnd, zeroEnd int32
			if len(segments)+(len(dataSects)-secIndex) == maxNumSegments {
				segmentEnd = dataLen
				zeroEnd = dataLen
			} else {
				for {
					// look for beginning of zeroes
					for segmentEnd < dataLen && data[segmentEnd] != 0 {
						segmentEnd++
					}
					// look for end of zeroes
					zeroEnd = segmentEnd
					for zeroEnd < dataLen && data[zeroEnd] == 0 {
						zeroEnd++
					}
					// emit segment if omitting zeroes reduces the output size
					if zeroEnd-segmentEnd >= segmentOverhead || zeroEnd == dataLen {
						break
					}
					segmentEnd = zeroEnd
				}
			}

			segments = append(segments, &dataSegment{
				offset: offset,
				data:   data[:segmentEnd],
			})
			data = data[zeroEnd:]
			offset += zeroEnd
		}
	}

	writeUleb128(ctxt.Out, uint64(len(segments))) // number of data entries
	for _, seg := range segments {
		writeUleb128(ctxt.Out, 0) // memidx
		writeI32Const(ctxt.Out, seg.offset)
		ctxt.Out.WriteByte(0x0b) // end
		writeUleb128(ctxt.Out, uint64(len(seg.data)))
		ctxt.Out.Write(seg.data)
	}

	writeSecSize(ctxt, sizeOffset)
}

// writeProducerSec writes an optional section that reports the source language and compiler version.
func writeProducerSec(ctxt *ld.Link) {
	sizeOffset := writeSecHeader(ctxt, sectionCustom)
	writeName(ctxt.Out, "producers")

	writeUleb128(ctxt.Out, 2) // number of fields

	writeName(ctxt.Out, "language")       // field name
	writeUleb128(ctxt.Out, 1)             // number of values
	writeName(ctxt.Out, "Go")             // value: name
	writeName(ctxt.Out, buildcfg.Version) // value: version

	writeName(ctxt.Out, "processed-by")   // field name
	writeUleb128(ctxt.Out, 1)             // number of values
	writeName(ctxt.Out, "Go cmd/compile") // value: name
	writeName(ctxt.Out, buildcfg.Version) // value: version

	writeSecSize(ctxt, sizeOffset)
}

var nameRegexp = regexp.MustCompile(`[^\w.]`)

// writeNameSec writes an optional section that assigns names to the functions declared by the "func" section.
// The names are only used by WebAssembly stack traces, debuggers and decompilers.
// TODO(neelance): add symbol table of DATA symbols
func writeNameSec(ctxt *ld.Link, firstFnIndex int, fns []*wasmFunc) {
	sizeOffset := writeSecHeader(ctxt, sectionCustom)
	writeName(ctxt.Out, "name")

	sizeOffset2 := writeSecHeader(ctxt, 0x01) // function names
	writeUleb128(ctxt.Out, uint64(len(fns)))
	for i, fn := range fns {
		writeUleb128(ctxt.Out, uint64(firstFnIndex+i))
		writeName(ctxt.Out, fn.Name)
	}
	writeSecSize(ctxt, sizeOffset2)

	writeSecSize(ctxt, sizeOffset)
}

type nameWriter interface {
	io.ByteWriter
	io.Writer
}

func writeI32Const(w io.ByteWriter, v int32) {
	w.WriteByte(0x41) // i32.const
	writeSleb128(w, int64(v))
}

func writeI64Const(w io.ByteWriter, v int64) {
	w.WriteByte(0x42) // i64.const
	writeSleb128(w, v)
}

func writeName(w nameWriter, name string) {
	writeUleb128(w, uint64(len(name)))
	w.Write([]byte(name))
}

func writeUleb128(w io.ByteWriter, v uint64) {
	if v < 128 {
		w.WriteByte(uint8(v))
		return
	}
	more := true
	for more {
		c := uint8(v & 0x7f)
		v >>= 7
		more = v != 0
		if more {
			c |= 0x80
		}
		w.WriteByte(c)
	}
}

func writeUleb128FixedLength(w io.ByteWriter, v uint64, length int) {
	for i := 0; i < length; i++ {
		c := uint8(v & 0x7f)
		v >>= 7
		if i < length-1 {
			c |= 0x80
		}
		w.WriteByte(c)
	}
	if v != 0 {
		panic("writeUleb128FixedLength: length too small")
	}
}

func writeSleb128(w io.ByteWriter, v int64) {
	more := true
	for more {
		c := uint8(v & 0x7f)
		s := uint8(v & 0x40)
		v >>= 7
		more = !((v == 0 && s == 0) || (v == -1 && s != 0))
		if more {
			c |= 0x80
		}
		w.WriteByte(c)
	}
}

func fieldsToTypes(fields []obj.WasmField) []byte {
	b := make([]byte, len(fields))
	for i, f := range fields {
		switch f.Type {
		case obj.WasmI32, obj.WasmPtr, obj.WasmBool:
			b[i] = I32
		case obj.WasmI64:
			b[i] = I64
		case obj.WasmF32:
			b[i] = F32
		case obj.WasmF64:
			b[i] = F64
		default:
			panic(fmt.Sprintf("fieldsToTypes: unknown field type: %d", f.Type))
		}
	}
	return b
}

"""



```