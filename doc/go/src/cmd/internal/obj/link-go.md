Response: My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for the functionality of the provided Go code snippet, which is part of `go/src/cmd/internal/obj/link.go`. It also asks for examples, potential errors, and command-line handling, if applicable.

2. **Identify the Core Purpose:** The package name `obj` and the file name `link.go` strongly suggest this code is related to the *object linking* process in the Go compiler toolchain. The comment at the beginning reinforces this by mentioning derivation from Inferno's linker.

3. **Break Down the Code:** I'll scan the code for key data structures and functions to understand the underlying mechanisms.

    * **`Addr` struct:**  This clearly represents operands to machine instructions. The comments meticulously describe various addressing modes and their encodings. This is fundamental to representing instructions.

    * **`Prog` struct:** This represents a single machine instruction. It contains fields for opcode (`As`), operands (`From`, `To`, `RestArgs`), control flow (`Link`, `Forwd`, `Rel`), and source information (`Pos`). This is the core representation of executable code during linking.

    * **`LSym` struct:** This represents a symbol in the object file. It has a name, type, size, data, relocations, and extra information. Symbols are the building blocks of linked programs (functions, variables, etc.).

    * **`FuncInfo`, `VarInfo`, `FileInfo`, `TypeInfo`, `WasmImport`, `WasmExport`:** These structs associated with `LSym` provide additional metadata for different kinds of symbols (functions, variables, file-backed data, types, WebAssembly imports/exports).

    * **`Link` struct:** This holds the overall context for the linking process, including the target architecture, debugging flags, symbol tables, and lists of text and data symbols. This is the central orchestrating structure.

    * **`As` type:** This represents assembler opcodes. The constants define portable opcodes and a mechanism for architecture-specific opcodes.

4. **Infer High-Level Functionality:** Based on the identified structures, I can infer the main functionalities of this code:

    * **Representing Machine Instructions:** The `Addr` and `Prog` structs are designed to hold all the information needed to represent a machine instruction in various architectures. This includes operands with different addressing modes, opcodes, and control flow information.

    * **Representing Symbols:** The `LSym` struct is used to represent symbols, which are essential for linking different parts of a program together. It stores the symbol's name, type, data, and attributes.

    * **Managing Symbol Metadata:** The various `*Info` structs attached to `LSym` allow storing specific metadata for different types of symbols. This is crucial for tasks like debugging, garbage collection, and interaction with other languages (like WebAssembly).

    * **Providing a Linking Context:** The `Link` struct provides the overall context for the linking process. It manages symbol tables, tracks defined and referenced symbols, and handles architecture-specific details.

5. **Connect to Go Language Features:** Now I need to relate these internal structures to visible Go language features:

    * **Functions and Variables:** `LSym` with `FuncInfo` represents Go functions. `LSym` with `VarInfo` represents Go variables.
    * **Types:** `LSym` with `TypeInfo` represents Go types.
    * **Assembly Code (`//go:noescape`, `TEXT`, etc.):** The `Addr` and `Prog` structs are directly used when processing assembly code within Go programs. The `TEXT` directive creates `LSym` with `FuncInfo`, and instructions within it are represented by `Prog`.
    * **External Linking (Cgo, WASM):**  `LSym` with `WasmImport` and `WasmExport` relates to the `//go:wasmimport` and `//go:wasmexport` directives for interacting with WebAssembly. Cgo would involve `AttrCFunc`.
    * **Internal Linking:** The whole process of compiling and linking Go packages relies on these structures.

6. **Develop Code Examples:**  I'll create simple Go examples to illustrate how these internal structures relate to user-visible code:

    * **Function:** A simple Go function will be represented by an `LSym` of type `STEXT` and have a corresponding `FuncInfo`. The instructions within the function will be `Prog` instances.
    * **Global Variable:** A global variable will be represented by an `LSym` of type `SDATA` or `SBSS`.
    * **Assembly Function:** A Go function implemented in assembly will directly use the `TEXT` directive, and its instructions will be represented by `Prog` with `Addr` operands.
    * **WASM Import:**  An example using `//go:wasmimport` will create an `LSym` with `WasmImport`.

7. **Consider Command-Line Arguments:** The `Link` struct contains fields like `Debugasm`, `Debugvlog`, `Flag_shared`, etc. These correspond to command-line flags passed to the `go build` or `go link` commands. I need to identify a few relevant ones and explain their impact.

8. **Identify Potential Errors:**  Based on my understanding, I can think of common errors:

    * **Incorrect Addressing Modes in Assembly:**  Manually writing assembly can lead to errors in specifying operands using the `Addr` structure's encoding.
    * **Mismatched Types in WASM Imports/Exports:**  Incorrectly specifying the types in `//go:wasmimport` or `//go:wasmexport` directives will cause errors.
    * **Incorrect Use of Linker Directives:** Misusing directives like `//go:linkname` can lead to unexpected linking behavior.

9. **Structure the Answer:**  Finally, I'll organize the information into the requested sections: functionalities, examples, command-line arguments, and common errors. I will use code blocks for examples and format the command-line explanations clearly.

By following these steps, I can systematically analyze the code, infer its purpose, connect it to user-level Go features, and generate a comprehensive answer to the request. The key is to start with the core data structures and work outwards, connecting the internal representations to the observable behavior of the Go language.
`go/src/cmd/internal/obj/link.go` 是 Go 语言工具链中负责链接阶段的核心代码。它定义了用于表示目标代码、符号和链接上下文的数据结构。以下是它的一些主要功能：

**1. 定义了表示机器指令的数据结构 (`Prog`, `Addr`):**

   - **`Addr`**:  表示指令的操作数（参数），可以表达各种寻址模式，如寄存器、立即数、内存地址（带偏移、寄存器、索引等）。它详细定义了各种操作数类型的编码方式。
   - **`Prog`**: 表示单个机器指令，包含操作码 (`As`)，源操作数 (`From`)，目的操作数 (`To`)，以及其他辅助信息（如源文件位置、栈调整大小等）。

**2. 定义了表示符号的数据结构 (`LSym`):**

   - **`LSym`**: 表示链接器处理的符号，可以是函数、变量、常量等。它包含符号的名称、类型、大小、数据、重定位信息等。
   - 符号可以有额外的元数据，通过 `LSym.Extra` 指针指向不同的信息结构体，例如：
     - **`FuncInfo`**: 存储函数符号的额外信息，如参数大小、局部变量大小、调试信息相关的符号等。
     - **`VarInfo`**: 存储变量符号的额外信息。
     - **`FileInfo`**: 存储由文件支持的数据符号的信息。
     - **`TypeInfo`**: 存储包含 `runtime._type` 的符号的信息。
     - **`WasmImport`, `WasmExport`**: 存储 WebAssembly 导入和导出函数的信息。

**3. 定义了链接上下文的数据结构 (`Link`):**

   - **`Link`**: 存储链接过程中的全局上下文信息，包括目标架构、调试选项、符号表、导入的包信息等。它是链接过程的核心管理结构。

**4. 定义了汇编器操作码 (`As`):**

   - **`As`**:  枚举类型，定义了通用的汇编器操作码，以及为不同架构预留的操作码空间。

**5. 定义了符号属性 (`Attribute`):**

   - **`Attribute`**:  位掩码，用于表示符号的各种属性，例如是否允许重复、是否是 C 函数、是否需要上下文指针等。

**6. 定义了重定位信息的数据结构 (`Reloc`):**

   - **`Reloc`**:  表示需要链接器处理的重定位项，包含重定位的偏移、大小、类型、附加值和目标符号。

**它可以推理出是什么 Go 语言功能的实现：**

这个文件是 Go 语言链接器的核心数据结构定义。它为链接器提供了操作和管理目标代码和符号的基础设施。具体来说，它参与了以下 Go 语言功能的实现：

* **编译和链接 Go 代码:**  当使用 `go build` 或 `go run` 编译 Go 代码时，`cmd/compile` 生成的目标文件会使用这里定义的数据结构来表示代码和数据。`cmd/link` 读取这些目标文件，解析其中的 `LSym` 和 `Prog`，进行符号解析和地址分配，最终生成可执行文件或共享库。
* **支持汇编代码:** Go 允许在程序中使用汇编代码。在汇编代码中定义的符号和指令也会被表示成 `LSym` 和 `Prog` 结构。
* **Cgo 互操作:**  当 Go 代码调用 C 代码 (使用 Cgo) 时，C 代码中的符号需要与 Go 代码中的符号链接在一起。`AttrCFunc` 等属性以及 `LSym` 的机制支持这种跨语言的链接。
* **WebAssembly 支持:** Go 可以编译成 WebAssembly。`WasmImport` 和 `WasmExport` 结构体以及相关的字段支持与 WebAssembly 模块进行符号级别的互操作。
* **调试信息生成 (DWARF):** `FuncInfo` 中包含与 DWARF 调试信息相关的符号，链接器会根据这些信息生成调试数据。
* **内联优化:** `InlMark` 结构体用于记录内联发生的位置，以便在调试或错误追踪时能够正确回溯。

**Go 代码举例说明 (假设的输入与输出):**

假设我们有以下简单的 Go 代码 `main.go`:

```go
package main

import "fmt"

var globalVar int = 10

func add(a, b int) int {
	return a + b
}

func main() {
	result := add(globalVar, 5)
	fmt.Println(result)
}
```

当使用 `go tool compile -o main.o main.go` 编译后，生成的 `main.o` 文件（这是一个简化的概念，实际的目标文件格式更复杂）会包含类似以下信息的表示 (内部表示会更加底层):

* **`LSym` for `main.globalVar`:**
    - `Name`: "main.globalVar"
    - `Type`: `SDATA` (initialized data)
    - `Size`: 8 (假设 int 是 64 位)
    - `P`:  包含 `10` 的字节数组

* **`LSym` for `main.add`:**
    - `Name`: "main.add"
    - `Type`: `STEXT` (text, executable code)
    - `FuncInfo`: 包含 `add` 函数的元数据
    - 指向 `Prog` 链表的指针，表示 `add` 函数的指令序列，例如：
        - `Prog`: `MOVQ arg0, AX` (将参数 a 移动到 AX 寄存器)
        - `Prog`: `ADDQ arg1, AX` (将参数 b 加到 AX 寄存器)
        - `Prog`: `MOVQ AX, ret`  (将 AX 寄存器的值移动到返回值位置)
        - `Prog`: `RET`

* **`LSym` for `main.main`:**
    - `Name`: "main.main"
    - `Type`: `STEXT`
    - `FuncInfo`: 包含 `main` 函数的元数据
    - 指向 `Prog` 链表的指针，表示 `main` 函数的指令序列，例如：
        - `Prog`: `CALL main.add` (调用 `add` 函数，这里会有重定位信息指向 `main.add`)
        - `Prog`: `CALL fmt.Println` (调用 `fmt.Println` 函数，这里会有重定位信息指向 `fmt.Println`)

在链接阶段 (`go tool link main.o`)，`link.go` 中的数据结构会被用来：

1. **加载目标文件:** 读取 `main.o` 中的 `LSym` 和 `Prog` 信息。
2. **符号解析:** 找到 `main.main` 中 `CALL main.add` 和 `CALL fmt.Println` 指令引用的符号 `main.add` 和 `fmt.Println` 的定义。对于 `fmt.Println`，链接器可能需要查找标准库的 `.a` 文件。
3. **地址分配:** 为所有的符号 (函数、变量) 分配最终的内存地址。
4. **重定位:** 根据分配的地址，修改 `CALL` 指令中的目标地址。例如，如果 `main.add` 被分配到地址 `0x1000`，则 `CALL main.add` 指令会被修改为 `CALL 0x1000`。
5. **生成最终的可执行文件:**  将代码和数据按照分配的地址排列，生成可执行文件。

**命令行参数的具体处理:**

`go/src/cmd/internal/obj/link.go` 本身主要是数据结构的定义，具体的命令行参数处理逻辑通常在 `cmd/link/internal/ld` 包中。但是，`link.go` 中的 `Link` 结构体包含了一些与命令行参数相关的字段，这些字段会在链接过程的早期被 `cmd/link` 包填充。

一些相关的 `Link` 结构体字段以及它们可能对应的命令行参数或链接选项：

* **`Headtype`**:  目标操作系统和架构 (`-H` 命令行参数会影响)。
* **`Arch`**: 目标架构的具体信息。
* **`Debugasm`**: 是否输出汇编调试信息 (通常通过 `-v` 或特定的调试选项启用)。
* **`Flag_shared`**: 是否构建共享库 (`-buildmode=shared`)。
* **`Flag_dynlink`**:  是否使用动态链接。
* **`Flag_optimize`**: 是否启用优化 (`-gcflags -N` 可以禁用优化)。
* **`Retpoline`**:  是否使用 retpoline 来缓解幽灵漏洞 (`-spectre=ret` 或 `-spectre=auto`)。
* **`Pkgpath`**: 当前正在链接的包的导入路径。

**使用者易犯错的点 (主要在汇编代码中使用 `obj` 包时):**

虽然 `obj` 包主要是内部使用，但在编写 Go 汇编代码时，开发者实际上是在使用 `obj` 包定义的数据结构。以下是一些容易犯错的点：

* **`Addr` 寻址模式的错误使用:**  在汇编代码中指定操作数时，需要正确理解 `Addr` 结构体中 `Type`, `Name`, `Reg`, `Offset`, `Sym` 等字段的含义和组合方式。例如，错误地指定寄存器或偏移量会导致汇编错误或运行时崩溃。
    * **示例:** 假设想要访问全局变量 `globalVar`，错误的写法可能直接使用变量名，而正确的写法需要使用符号类型和名称，例如 `globalVar(SB)`。

* **`Prog` 指令的错误定义:**  在某些需要手动构建 `Prog` 链表的情况下（非常少见，通常由编译器完成），需要确保 `As` 操作码和操作数的类型匹配，否则链接器会报错。

* **不理解符号类型和属性:**  在汇编代码中引用符号时，需要了解符号的类型（如 `SB`, `SP`, `FP`）和属性，例如是否是外部符号、静态符号等。错误的符号引用会导致链接错误。
    * **示例:** 尝试直接访问另一个包的私有变量，即使使用了 `//go:linkname`，也可能因为符号属性不匹配而失败。

**总结:**

`go/src/cmd/internal/obj/link.go` 是 Go 链接器的蓝图，定义了构建链接器的基本元素。理解这些数据结构有助于深入理解 Go 的编译和链接过程，特别是在涉及汇编代码、Cgo 互操作或 WebAssembly 集成时。普通 Go 开发者通常不需要直接操作这些结构，但了解它们的存在可以帮助理解 Go 工具链的底层工作原理。

### 提示词
```
这是路径为go/src/cmd/internal/obj/link.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Derived from Inferno utils/6l/l.h and related files.
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

package obj

import (
	"bufio"
	"bytes"
	"cmd/internal/dwarf"
	"cmd/internal/goobj"
	"cmd/internal/objabi"
	"cmd/internal/src"
	"cmd/internal/sys"
	"encoding/binary"
	"fmt"
	"internal/abi"
	"sync"
	"sync/atomic"
)

// An Addr is an argument to an instruction.
// The general forms and their encodings are:
//
//	sym±offset(symkind)(reg)(index*scale)
//		Memory reference at address &sym(symkind) + offset + reg + index*scale.
//		Any of sym(symkind), ±offset, (reg), (index*scale), and *scale can be omitted.
//		If (reg) and *scale are both omitted, the resulting expression (index) is parsed as (reg).
//		To force a parsing as index*scale, write (index*1).
//		Encoding:
//			type = TYPE_MEM
//			name = symkind (NAME_AUTO, ...) or 0 (NAME_NONE)
//			sym = sym
//			offset = ±offset
//			reg = reg (REG_*)
//			index = index (REG_*)
//			scale = scale (1, 2, 4, 8)
//
//	$<mem>
//		Effective address of memory reference <mem>, defined above.
//		Encoding: same as memory reference, but type = TYPE_ADDR.
//
//	$<±integer value>
//		This is a special case of $<mem>, in which only ±offset is present.
//		It has a separate type for easy recognition.
//		Encoding:
//			type = TYPE_CONST
//			offset = ±integer value
//
//	*<mem>
//		Indirect reference through memory reference <mem>, defined above.
//		Only used on x86 for CALL/JMP *sym(SB), which calls/jumps to a function
//		pointer stored in the data word sym(SB), not a function named sym(SB).
//		Encoding: same as above, but type = TYPE_INDIR.
//
//	$*$<mem>
//		No longer used.
//		On machines with actual SB registers, $*$<mem> forced the
//		instruction encoding to use a full 32-bit constant, never a
//		reference relative to SB.
//
//	$<floating point literal>
//		Floating point constant value.
//		Encoding:
//			type = TYPE_FCONST
//			val = floating point value
//
//	$<string literal, up to 8 chars>
//		String literal value (raw bytes used for DATA instruction).
//		Encoding:
//			type = TYPE_SCONST
//			val = string
//
//	<symbolic constant name>
//		Special symbolic constants for ARM64, such as conditional flags, tlbi_op and so on.
//		Encoding:
//			type = TYPE_SPECIAL
//			offset = The constant value corresponding to this symbol
//
//	<register name>
//		Any register: integer, floating point, control, segment, and so on.
//		If looking for specific register kind, must check type and reg value range.
//		Encoding:
//			type = TYPE_REG
//			reg = reg (REG_*)
//
//	x(PC)
//		Encoding:
//			type = TYPE_BRANCH
//			val = Prog* reference OR ELSE offset = target pc (branch takes priority)
//
//	$±x-±y
//		Final argument to TEXT, specifying local frame size x and argument size y.
//		In this form, x and y are integer literals only, not arbitrary expressions.
//		This avoids parsing ambiguities due to the use of - as a separator.
//		The ± are optional.
//		If the final argument to TEXT omits the -±y, the encoding should still
//		use TYPE_TEXTSIZE (not TYPE_CONST), with u.argsize = ArgsSizeUnknown.
//		Encoding:
//			type = TYPE_TEXTSIZE
//			offset = x
//			val = int32(y)
//
//	reg<<shift, reg>>shift, reg->shift, reg@>shift
//		Shifted register value, for ARM and ARM64.
//		In this form, reg must be a register and shift can be a register or an integer constant.
//		Encoding:
//			type = TYPE_SHIFT
//		On ARM:
//			offset = (reg&15) | shifttype<<5 | count
//			shifttype = 0, 1, 2, 3 for <<, >>, ->, @>
//			count = (reg&15)<<8 | 1<<4 for a register shift count, (n&31)<<7 for an integer constant.
//		On ARM64:
//			offset = (reg&31)<<16 | shifttype<<22 | (count&63)<<10
//			shifttype = 0, 1, 2 for <<, >>, ->
//
//	(reg, reg)
//		A destination register pair. When used as the last argument of an instruction,
//		this form makes clear that both registers are destinations.
//		Encoding:
//			type = TYPE_REGREG
//			reg = first register
//			offset = second register
//
//	[reg, reg, reg-reg]
//		Register list for ARM, ARM64, 386/AMD64.
//		Encoding:
//			type = TYPE_REGLIST
//		On ARM:
//			offset = bit mask of registers in list; R0 is low bit.
//		On ARM64:
//			offset = register count (Q:size) | arrangement (opcode) | first register
//		On 386/AMD64:
//			reg = range low register
//			offset = 2 packed registers + kind tag (see x86.EncodeRegisterRange)
//
//	reg, reg
//		Register pair for ARM.
//		TYPE_REGREG2
//
//	(reg+reg)
//		Register pair for PPC64.
//		Encoding:
//			type = TYPE_MEM
//			reg = first register
//			index = second register
//			scale = 1
//
//	reg.[US]XT[BHWX]
//		Register extension for ARM64
//		Encoding:
//			type = TYPE_REG
//			reg = REG_[US]XT[BHWX] + register + shift amount
//			offset = ((reg&31) << 16) | (exttype << 13) | (amount<<10)
//
//	reg.<T>
//		Register arrangement for ARM64 and Loong64 SIMD register
//		e.g.:
//			On ARM64: V1.S4, V2.S2, V7.D2, V2.H4, V6.B16
//			On Loong64: X1.B32, X1.H16, X1.W8, X2.V4, X1.Q1, V1.B16, V1.H8, V1.W4, V1.V2
//		Encoding:
//			type = TYPE_REG
//			reg = REG_ARNG + register + arrangement
//
//	reg.<T>[index]
//		Register element for ARM64 and Loong64
//		Encoding:
//			type = TYPE_REG
//			reg = REG_ELEM + register + arrangement
//			index = element index

type Addr struct {
	Reg    int16
	Index  int16
	Scale  int16 // Sometimes holds a register.
	Type   AddrType
	Name   AddrName
	Class  int8
	Offset int64
	Sym    *LSym

	// argument value:
	//	for TYPE_SCONST, a string
	//	for TYPE_FCONST, a float64
	//	for TYPE_BRANCH, a *Prog (optional)
	//	for TYPE_TEXTSIZE, an int32 (optional)
	Val interface{}
}

type AddrName int8

const (
	NAME_NONE AddrName = iota
	NAME_EXTERN
	NAME_STATIC
	NAME_AUTO
	NAME_PARAM
	// A reference to name@GOT(SB) is a reference to the entry in the global offset
	// table for 'name'.
	NAME_GOTREF
	// Indicates that this is a reference to a TOC anchor.
	NAME_TOCREF
)

//go:generate stringer -type AddrType

type AddrType uint8

const (
	TYPE_NONE AddrType = iota
	TYPE_BRANCH
	TYPE_TEXTSIZE
	TYPE_MEM
	TYPE_CONST
	TYPE_FCONST
	TYPE_SCONST
	TYPE_REG
	TYPE_ADDR
	TYPE_SHIFT
	TYPE_REGREG
	TYPE_REGREG2
	TYPE_INDIR
	TYPE_REGLIST
	TYPE_SPECIAL
)

func (a *Addr) Target() *Prog {
	if a.Type == TYPE_BRANCH && a.Val != nil {
		return a.Val.(*Prog)
	}
	return nil
}
func (a *Addr) SetTarget(t *Prog) {
	if a.Type != TYPE_BRANCH {
		panic("setting branch target when type is not TYPE_BRANCH")
	}
	a.Val = t
}

func (a *Addr) SetConst(v int64) {
	a.Sym = nil
	a.Type = TYPE_CONST
	a.Offset = v
}

// Prog describes a single machine instruction.
//
// The general instruction form is:
//
//	(1) As.Scond From [, ...RestArgs], To
//	(2) As.Scond From, Reg [, ...RestArgs], To, RegTo2
//
// where As is an opcode and the others are arguments:
// From, Reg are sources, and To, RegTo2 are destinations.
// RestArgs can hold additional sources and destinations.
// Usually, not all arguments are present.
// For example, MOVL R1, R2 encodes using only As=MOVL, From=R1, To=R2.
// The Scond field holds additional condition bits for systems (like arm)
// that have generalized conditional execution.
// (2) form is present for compatibility with older code,
// to avoid too much changes in a single swing.
// (1) scheme is enough to express any kind of operand combination.
//
// Jump instructions use the To.Val field to point to the target *Prog,
// which must be in the same linked list as the jump instruction.
//
// The Progs for a given function are arranged in a list linked through the Link field.
//
// Each Prog is charged to a specific source line in the debug information,
// specified by Pos.Line().
// Every Prog has a Ctxt field that defines its context.
// For performance reasons, Progs are usually bulk allocated, cached, and reused;
// those bulk allocators should always be used, rather than new(Prog).
//
// The other fields not yet mentioned are for use by the back ends and should
// be left zeroed by creators of Prog lists.
type Prog struct {
	Ctxt     *Link     // linker context
	Link     *Prog     // next Prog in linked list
	From     Addr      // first source operand
	RestArgs []AddrPos // can pack any operands that not fit into {Prog.From, Prog.To}, same kinds of operands are saved in order
	To       Addr      // destination operand (second is RegTo2 below)
	Pool     *Prog     // constant pool entry, for arm,arm64 back ends
	Forwd    *Prog     // for x86 back end
	Rel      *Prog     // for x86, arm back ends
	Pc       int64     // for back ends or assembler: virtual or actual program counter, depending on phase
	Pos      src.XPos  // source position of this instruction
	Spadj    int32     // effect of instruction on stack pointer (increment or decrement amount)
	As       As        // assembler opcode
	Reg      int16     // 2nd source operand
	RegTo2   int16     // 2nd destination operand
	Mark     uint16    // bitmask of arch-specific items
	Optab    uint16    // arch-specific opcode index
	Scond    uint8     // bits that describe instruction suffixes (e.g. ARM conditions, RISCV Rounding Mode)
	Back     uint8     // for x86 back end: backwards branch state
	Ft       uint8     // for x86 back end: type index of Prog.From
	Tt       uint8     // for x86 back end: type index of Prog.To
	Isize    uint8     // for x86 back end: size of the instruction in bytes
}

// AddrPos indicates whether the operand is the source or the destination.
type AddrPos struct {
	Addr
	Pos OperandPos
}

type OperandPos int8

const (
	Source OperandPos = iota
	Destination
)

// From3Type returns p.GetFrom3().Type, or TYPE_NONE when
// p.GetFrom3() returns nil.
func (p *Prog) From3Type() AddrType {
	from3 := p.GetFrom3()
	if from3 == nil {
		return TYPE_NONE
	}
	return from3.Type
}

// GetFrom3 returns second source operand (the first is Prog.From).
// The same kinds of operands are saved in order so GetFrom3 actually
// return the first source operand in p.RestArgs.
// In combination with Prog.From and Prog.To it makes common 3 operand
// case easier to use.
func (p *Prog) GetFrom3() *Addr {
	for i := range p.RestArgs {
		if p.RestArgs[i].Pos == Source {
			return &p.RestArgs[i].Addr
		}
	}
	return nil
}

// AddRestSource assigns []Args{{a, Source}} to p.RestArgs.
func (p *Prog) AddRestSource(a Addr) {
	p.RestArgs = append(p.RestArgs, AddrPos{a, Source})
}

// AddRestSourceReg calls p.AddRestSource with a register Addr containing reg.
func (p *Prog) AddRestSourceReg(reg int16) {
	p.AddRestSource(Addr{Type: TYPE_REG, Reg: reg})
}

// AddRestSourceConst calls p.AddRestSource with a const Addr containing off.
func (p *Prog) AddRestSourceConst(off int64) {
	p.AddRestSource(Addr{Type: TYPE_CONST, Offset: off})
}

// AddRestDest assigns []Args{{a, Destination}} to p.RestArgs when the second destination
// operand does not fit into prog.RegTo2.
func (p *Prog) AddRestDest(a Addr) {
	p.RestArgs = append(p.RestArgs, AddrPos{a, Destination})
}

// GetTo2 returns the second destination operand.
// The same kinds of operands are saved in order so GetTo2 actually
// return the first destination operand in Prog.RestArgs[]
func (p *Prog) GetTo2() *Addr {
	for i := range p.RestArgs {
		if p.RestArgs[i].Pos == Destination {
			return &p.RestArgs[i].Addr
		}
	}
	return nil
}

// AddRestSourceArgs assigns more than one source operands to p.RestArgs.
func (p *Prog) AddRestSourceArgs(args []Addr) {
	for i := range args {
		p.RestArgs = append(p.RestArgs, AddrPos{args[i], Source})
	}
}

// An As denotes an assembler opcode.
// There are some portable opcodes, declared here in package obj,
// that are common to all architectures.
// However, the majority of opcodes are arch-specific
// and are declared in their respective architecture's subpackage.
type As int16

// These are the portable opcodes.
const (
	AXXX As = iota
	ACALL
	ADUFFCOPY
	ADUFFZERO
	AEND
	AFUNCDATA
	AJMP
	ANOP
	APCALIGN
	APCALIGNMAX // currently x86, amd64 and arm64
	APCDATA
	ARET
	AGETCALLERPC
	ATEXT
	AUNDEF
	A_ARCHSPECIFIC
)

// Each architecture is allotted a distinct subspace of opcode values
// for declaring its arch-specific opcodes.
// Within this subspace, the first arch-specific opcode should be
// at offset A_ARCHSPECIFIC.
//
// Subspaces are aligned to a power of two so opcodes can be masked
// with AMask and used as compact array indices.
const (
	ABase386 = (1 + iota) << 11
	ABaseARM
	ABaseAMD64
	ABasePPC64
	ABaseARM64
	ABaseMIPS
	ABaseLoong64
	ABaseRISCV
	ABaseS390X
	ABaseWasm

	AllowedOpCodes = 1 << 11            // The number of opcodes available for any given architecture.
	AMask          = AllowedOpCodes - 1 // AND with this to use the opcode as an array index.
)

// An LSym is the sort of symbol that is written to an object file.
// It represents Go symbols in a flat pkg+"."+name namespace.
type LSym struct {
	Name string
	Type objabi.SymKind
	Attribute

	Size   int64
	Gotype *LSym
	P      []byte
	R      []Reloc

	Extra *interface{} // *FuncInfo, *VarInfo, *FileInfo, or *TypeInfo, if present

	Pkg    string
	PkgIdx int32
	SymIdx int32
}

// A FuncInfo contains extra fields for STEXT symbols.
type FuncInfo struct {
	Args      int32
	Locals    int32
	Align     int32
	FuncID    abi.FuncID
	FuncFlag  abi.FuncFlag
	StartLine int32
	Text      *Prog
	Autot     map[*LSym]struct{}
	Pcln      Pcln
	InlMarks  []InlMark
	spills    []RegSpill

	dwarfInfoSym       *LSym
	dwarfLocSym        *LSym
	dwarfRangesSym     *LSym
	dwarfAbsFnSym      *LSym
	dwarfDebugLinesSym *LSym

	GCArgs             *LSym
	GCLocals           *LSym
	StackObjects       *LSym
	OpenCodedDeferInfo *LSym
	ArgInfo            *LSym // argument info for traceback
	ArgLiveInfo        *LSym // argument liveness info for traceback
	WrapInfo           *LSym // for wrapper, info of wrapped function
	JumpTables         []JumpTable

	FuncInfoSym *LSym

	WasmImport *WasmImport
	WasmExport *WasmExport

	sehUnwindInfoSym *LSym
}

// JumpTable represents a table used for implementing multi-way
// computed branching, used typically for implementing switches.
// Sym is the table itself, and Targets is a list of target
// instructions to go to for the computed branch index.
type JumpTable struct {
	Sym     *LSym
	Targets []*Prog
}

// NewFuncInfo allocates and returns a FuncInfo for LSym.
func (s *LSym) NewFuncInfo() *FuncInfo {
	if s.Extra != nil {
		panic(fmt.Sprintf("invalid use of LSym - NewFuncInfo with Extra of type %T", *s.Extra))
	}
	f := new(FuncInfo)
	s.Extra = new(interface{})
	*s.Extra = f
	return f
}

// Func returns the *FuncInfo associated with s, or else nil.
func (s *LSym) Func() *FuncInfo {
	if s.Extra == nil {
		return nil
	}
	f, _ := (*s.Extra).(*FuncInfo)
	return f
}

type VarInfo struct {
	dwarfInfoSym *LSym
}

// NewVarInfo allocates and returns a VarInfo for LSym.
func (s *LSym) NewVarInfo() *VarInfo {
	if s.Extra != nil {
		panic(fmt.Sprintf("invalid use of LSym - NewVarInfo with Extra of type %T", *s.Extra))
	}
	f := new(VarInfo)
	s.Extra = new(interface{})
	*s.Extra = f
	return f
}

// VarInfo returns the *VarInfo associated with s, or else nil.
func (s *LSym) VarInfo() *VarInfo {
	if s.Extra == nil {
		return nil
	}
	f, _ := (*s.Extra).(*VarInfo)
	return f
}

// A FileInfo contains extra fields for SDATA symbols backed by files.
// (If LSym.Extra is a *FileInfo, LSym.P == nil.)
type FileInfo struct {
	Name string // name of file to read into object file
	Size int64  // length of file
}

// NewFileInfo allocates and returns a FileInfo for LSym.
func (s *LSym) NewFileInfo() *FileInfo {
	if s.Extra != nil {
		panic(fmt.Sprintf("invalid use of LSym - NewFileInfo with Extra of type %T", *s.Extra))
	}
	f := new(FileInfo)
	s.Extra = new(interface{})
	*s.Extra = f
	return f
}

// File returns the *FileInfo associated with s, or else nil.
func (s *LSym) File() *FileInfo {
	if s.Extra == nil {
		return nil
	}
	f, _ := (*s.Extra).(*FileInfo)
	return f
}

// A TypeInfo contains information for a symbol
// that contains a runtime._type.
type TypeInfo struct {
	Type interface{} // a *cmd/compile/internal/types.Type
}

func (s *LSym) NewTypeInfo() *TypeInfo {
	if s.Extra != nil {
		panic(fmt.Sprintf("invalid use of LSym - NewTypeInfo with Extra of type %T", *s.Extra))
	}
	t := new(TypeInfo)
	s.Extra = new(interface{})
	*s.Extra = t
	return t
}

// WasmImport represents a WebAssembly (WASM) imported function with
// parameters and results translated into WASM types based on the Go function
// declaration.
type WasmImport struct {
	// Module holds the WASM module name specified by the //go:wasmimport
	// directive.
	Module string
	// Name holds the WASM imported function name specified by the
	// //go:wasmimport directive.
	Name string

	WasmFuncType // type of the imported function

	// aux symbol to pass metadata to the linker, serialization of
	// the fields above.
	AuxSym *LSym
}

func (wi *WasmImport) CreateAuxSym() {
	var b bytes.Buffer
	wi.Write(&b)
	p := b.Bytes()
	wi.AuxSym = &LSym{
		Type: objabi.SDATA, // doesn't really matter
		P:    append([]byte(nil), p...),
		Size: int64(len(p)),
	}
}

func (wi *WasmImport) Write(w *bytes.Buffer) {
	var b [8]byte
	writeUint32 := func(x uint32) {
		binary.LittleEndian.PutUint32(b[:], x)
		w.Write(b[:4])
	}
	writeString := func(s string) {
		writeUint32(uint32(len(s)))
		w.WriteString(s)
	}
	writeString(wi.Module)
	writeString(wi.Name)
	wi.WasmFuncType.Write(w)
}

func (wi *WasmImport) Read(b []byte) {
	readUint32 := func() uint32 {
		x := binary.LittleEndian.Uint32(b)
		b = b[4:]
		return x
	}
	readString := func() string {
		n := readUint32()
		s := string(b[:n])
		b = b[n:]
		return s
	}
	wi.Module = readString()
	wi.Name = readString()
	wi.WasmFuncType.Read(b)
}

// WasmFuncType represents a WebAssembly (WASM) function type with
// parameters and results translated into WASM types based on the Go function
// declaration.
type WasmFuncType struct {
	// Params holds the function parameter fields.
	Params []WasmField
	// Results holds the function result fields.
	Results []WasmField
}

func (ft *WasmFuncType) Write(w *bytes.Buffer) {
	var b [8]byte
	writeByte := func(x byte) {
		w.WriteByte(x)
	}
	writeUint32 := func(x uint32) {
		binary.LittleEndian.PutUint32(b[:], x)
		w.Write(b[:4])
	}
	writeInt64 := func(x int64) {
		binary.LittleEndian.PutUint64(b[:], uint64(x))
		w.Write(b[:])
	}
	writeUint32(uint32(len(ft.Params)))
	for _, f := range ft.Params {
		writeByte(byte(f.Type))
		writeInt64(f.Offset)
	}
	writeUint32(uint32(len(ft.Results)))
	for _, f := range ft.Results {
		writeByte(byte(f.Type))
		writeInt64(f.Offset)
	}
}

func (ft *WasmFuncType) Read(b []byte) {
	readByte := func() byte {
		x := b[0]
		b = b[1:]
		return x
	}
	readUint32 := func() uint32 {
		x := binary.LittleEndian.Uint32(b)
		b = b[4:]
		return x
	}
	readInt64 := func() int64 {
		x := binary.LittleEndian.Uint64(b)
		b = b[8:]
		return int64(x)
	}
	ft.Params = make([]WasmField, readUint32())
	for i := range ft.Params {
		ft.Params[i].Type = WasmFieldType(readByte())
		ft.Params[i].Offset = int64(readInt64())
	}
	ft.Results = make([]WasmField, readUint32())
	for i := range ft.Results {
		ft.Results[i].Type = WasmFieldType(readByte())
		ft.Results[i].Offset = int64(readInt64())
	}
}

// WasmExport represents a WebAssembly (WASM) exported function with
// parameters and results translated into WASM types based on the Go function
// declaration.
type WasmExport struct {
	WasmFuncType

	WrappedSym *LSym // the wrapped Go function
	AuxSym     *LSym // aux symbol to pass metadata to the linker
}

func (we *WasmExport) CreateAuxSym() {
	var b bytes.Buffer
	we.WasmFuncType.Write(&b)
	p := b.Bytes()
	we.AuxSym = &LSym{
		Type: objabi.SDATA, // doesn't really matter
		P:    append([]byte(nil), p...),
		Size: int64(len(p)),
	}
}

type WasmField struct {
	Type WasmFieldType
	// Offset holds the frame-pointer-relative locations for Go's stack-based
	// ABI. This is used by the src/cmd/internal/wasm package to map WASM
	// import parameters to the Go stack in a wrapper function.
	Offset int64
}

type WasmFieldType byte

const (
	WasmI32 WasmFieldType = iota
	WasmI64
	WasmF32
	WasmF64
	WasmPtr

	// bool is not really a wasm type, but we allow it on wasmimport/wasmexport
	// function parameters/results. 32-bit on Wasm side, 8-bit on Go side.
	WasmBool
)

type InlMark struct {
	// When unwinding from an instruction in an inlined body, mark
	// where we should unwind to.
	// id records the global inlining id of the inlined body.
	// p records the location of an instruction in the parent (inliner) frame.
	p  *Prog
	id int32
}

// Mark p as the instruction to set as the pc when
// "unwinding" the inlining global frame id. Usually it should be
// instruction with a file:line at the callsite, and occur
// just before the body of the inlined function.
func (fi *FuncInfo) AddInlMark(p *Prog, id int32) {
	fi.InlMarks = append(fi.InlMarks, InlMark{p: p, id: id})
}

// AddSpill appends a spill record to the list for FuncInfo fi
func (fi *FuncInfo) AddSpill(s RegSpill) {
	fi.spills = append(fi.spills, s)
}

// Record the type symbol for an auto variable so that the linker
// an emit DWARF type information for the type.
func (fi *FuncInfo) RecordAutoType(gotype *LSym) {
	if fi.Autot == nil {
		fi.Autot = make(map[*LSym]struct{})
	}
	fi.Autot[gotype] = struct{}{}
}

//go:generate stringer -type ABI

// ABI is the calling convention of a text symbol.
type ABI uint8

const (
	// ABI0 is the stable stack-based ABI. It's important that the
	// value of this is "0": we can't distinguish between
	// references to data and ABI0 text symbols in assembly code,
	// and hence this doesn't distinguish between symbols without
	// an ABI and text symbols with ABI0.
	ABI0 ABI = iota

	// ABIInternal is the internal ABI that may change between Go
	// versions. All Go functions use the internal ABI and the
	// compiler generates wrappers for calls to and from other
	// ABIs.
	ABIInternal

	ABICount
)

// ParseABI converts from a string representation in 'abistr' to the
// corresponding ABI value. Second return value is TRUE if the
// abi string is recognized, FALSE otherwise.
func ParseABI(abistr string) (ABI, bool) {
	switch abistr {
	default:
		return ABI0, false
	case "ABI0":
		return ABI0, true
	case "ABIInternal":
		return ABIInternal, true
	}
}

// ABISet is a bit set of ABI values.
type ABISet uint8

const (
	// ABISetCallable is the set of all ABIs any function could
	// potentially be called using.
	ABISetCallable ABISet = (1 << ABI0) | (1 << ABIInternal)
)

// Ensure ABISet is big enough to hold all ABIs.
var _ ABISet = 1 << (ABICount - 1)

func ABISetOf(abi ABI) ABISet {
	return 1 << abi
}

func (a *ABISet) Set(abi ABI, value bool) {
	if value {
		*a |= 1 << abi
	} else {
		*a &^= 1 << abi
	}
}

func (a *ABISet) Get(abi ABI) bool {
	return (*a>>abi)&1 != 0
}

func (a ABISet) String() string {
	s := "{"
	for i := ABI(0); a != 0; i++ {
		if a&(1<<i) != 0 {
			if s != "{" {
				s += ","
			}
			s += i.String()
			a &^= 1 << i
		}
	}
	return s + "}"
}

// Attribute is a set of symbol attributes.
type Attribute uint32

const (
	AttrDuplicateOK Attribute = 1 << iota
	AttrCFunc
	AttrNoSplit
	AttrLeaf
	AttrWrapper
	AttrNeedCtxt
	AttrNoFrame
	AttrOnList
	AttrStatic

	// MakeTypelink means that the type should have an entry in the typelink table.
	AttrMakeTypelink

	// ReflectMethod means the function may call reflect.Type.Method or
	// reflect.Type.MethodByName. Matching is imprecise (as reflect.Type
	// can be used through a custom interface), so ReflectMethod may be
	// set in some cases when the reflect package is not called.
	//
	// Used by the linker to determine what methods can be pruned.
	AttrReflectMethod

	// Local means make the symbol local even when compiling Go code to reference Go
	// symbols in other shared libraries, as in this mode symbols are global by
	// default. "local" here means in the sense of the dynamic linker, i.e. not
	// visible outside of the module (shared library or executable) that contains its
	// definition. (When not compiling to support Go shared libraries, all symbols are
	// local in this sense unless there is a cgo_export_* directive).
	AttrLocal

	// For function symbols; indicates that the specified function was the
	// target of an inline during compilation
	AttrWasInlined

	// Indexed indicates this symbol has been assigned with an index (when using the
	// new object file format).
	AttrIndexed

	// Only applied on type descriptor symbols, UsedInIface indicates this type is
	// converted to an interface.
	//
	// Used by the linker to determine what methods can be pruned.
	AttrUsedInIface

	// ContentAddressable indicates this is a content-addressable symbol.
	AttrContentAddressable

	// ABI wrapper is set for compiler-generated text symbols that
	// convert between ABI0 and ABIInternal calling conventions.
	AttrABIWrapper

	// IsPcdata indicates this is a pcdata symbol.
	AttrPcdata

	// PkgInit indicates this is a compiler-generated package init func.
	AttrPkgInit

	// Linkname indicates this is a go:linkname'd symbol.
	AttrLinkname

	// attrABIBase is the value at which the ABI is encoded in
	// Attribute. This must be last; all bits after this are
	// assumed to be an ABI value.
	//
	// MUST BE LAST since all bits above this comprise the ABI.
	attrABIBase
)

func (a *Attribute) load() Attribute { return Attribute(atomic.LoadUint32((*uint32)(a))) }

func (a *Attribute) DuplicateOK() bool        { return a.load()&AttrDuplicateOK != 0 }
func (a *Attribute) MakeTypelink() bool       { return a.load()&AttrMakeTypelink != 0 }
func (a *Attribute) CFunc() bool              { return a.load()&AttrCFunc != 0 }
func (a *Attribute) NoSplit() bool            { return a.load()&AttrNoSplit != 0 }
func (a *Attribute) Leaf() bool               { return a.load()&AttrLeaf != 0 }
func (a *Attribute) OnList() bool             { return a.load()&AttrOnList != 0 }
func (a *Attribute) ReflectMethod() bool      { return a.load()&AttrReflectMethod != 0 }
func (a *Attribute) Local() bool              { return a.load()&AttrLocal != 0 }
func (a *Attribute) Wrapper() bool            { return a.load()&AttrWrapper != 0 }
func (a *Attribute) NeedCtxt() bool           { return a.load()&AttrNeedCtxt != 0 }
func (a *Attribute) NoFrame() bool            { return a.load()&AttrNoFrame != 0 }
func (a *Attribute) Static() bool             { return a.load()&AttrStatic != 0 }
func (a *Attribute) WasInlined() bool         { return a.load()&AttrWasInlined != 0 }
func (a *Attribute) Indexed() bool            { return a.load()&AttrIndexed != 0 }
func (a *Attribute) UsedInIface() bool        { return a.load()&AttrUsedInIface != 0 }
func (a *Attribute) ContentAddressable() bool { return a.load()&AttrContentAddressable != 0 }
func (a *Attribute) ABIWrapper() bool         { return a.load()&AttrABIWrapper != 0 }
func (a *Attribute) IsPcdata() bool           { return a.load()&AttrPcdata != 0 }
func (a *Attribute) IsPkgInit() bool          { return a.load()&AttrPkgInit != 0 }
func (a *Attribute) IsLinkname() bool         { return a.load()&AttrLinkname != 0 }

func (a *Attribute) Set(flag Attribute, value bool) {
	for {
		v0 := a.load()
		v := v0
		if value {
			v |= flag
		} else {
			v &^= flag
		}
		if atomic.CompareAndSwapUint32((*uint32)(a), uint32(v0), uint32(v)) {
			break
		}
	}
}

func (a *Attribute) ABI() ABI { return ABI(a.load() / attrABIBase) }
func (a *Attribute) SetABI(abi ABI) {
	const mask = 1 // Only one ABI bit for now.
	for {
		v0 := a.load()
		v := (v0 &^ (mask * attrABIBase)) | Attribute(abi)*attrABIBase
		if atomic.CompareAndSwapUint32((*uint32)(a), uint32(v0), uint32(v)) {
			break
		}
	}
}

var textAttrStrings = [...]struct {
	bit Attribute
	s   string
}{
	{bit: AttrDuplicateOK, s: "DUPOK"},
	{bit: AttrMakeTypelink, s: ""},
	{bit: AttrCFunc, s: "CFUNC"},
	{bit: AttrNoSplit, s: "NOSPLIT"},
	{bit: AttrLeaf, s: "LEAF"},
	{bit: AttrOnList, s: ""},
	{bit: AttrReflectMethod, s: "REFLECTMETHOD"},
	{bit: AttrLocal, s: "LOCAL"},
	{bit: AttrWrapper, s: "WRAPPER"},
	{bit: AttrNeedCtxt, s: "NEEDCTXT"},
	{bit: AttrNoFrame, s: "NOFRAME"},
	{bit: AttrStatic, s: "STATIC"},
	{bit: AttrWasInlined, s: ""},
	{bit: AttrIndexed, s: ""},
	{bit: AttrContentAddressable, s: ""},
	{bit: AttrABIWrapper, s: "ABIWRAPPER"},
	{bit: AttrPkgInit, s: "PKGINIT"},
	{bit: AttrLinkname, s: "LINKNAME"},
}

// String formats a for printing in as part of a TEXT prog.
func (a Attribute) String() string {
	var s string
	for _, x := range textAttrStrings {
		if a&x.bit != 0 {
			if x.s != "" {
				s += x.s + "|"
			}
			a &^= x.bit
		}
	}
	switch a.ABI() {
	case ABI0:
	case ABIInternal:
		s += "ABIInternal|"
		a.SetABI(0) // Clear ABI so we don't print below.
	}
	if a != 0 {
		s += fmt.Sprintf("UnknownAttribute(%d)|", a)
	}
	// Chop off trailing |, if present.
	if len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

// TextAttrString formats the symbol attributes for printing in as part of a TEXT prog.
func (s *LSym) TextAttrString() string {
	attr := s.Attribute.String()
	if s.Func().FuncFlag&abi.FuncFlagTopFrame != 0 {
		if attr != "" {
			attr += "|"
		}
		attr += "TOPFRAME"
	}
	return attr
}

func (s *LSym) String() string {
	return s.Name
}

// The compiler needs *LSym to be assignable to cmd/compile/internal/ssa.Sym.
func (*LSym) CanBeAnSSASym() {}
func (*LSym) CanBeAnSSAAux() {}

type Pcln struct {
	// Aux symbols for pcln
	Pcsp      *LSym
	Pcfile    *LSym
	Pcline    *LSym
	Pcinline  *LSym
	Pcdata    []*LSym
	Funcdata  []*LSym
	UsedFiles map[goobj.CUFileIndex]struct{} // file indices used while generating pcfile
	InlTree   InlTree                        // per-function inlining tree extracted from the global tree
}

type Reloc struct {
	Off  int32
	Siz  uint8
	Type objabi.RelocType
	Add  int64
	Sym  *LSym
}

type Auto struct {
	Asym    *LSym
	Aoffset int32
	Name    AddrName
	Gotype  *LSym
}

// RegSpill provides spill/fill information for a register-resident argument
// to a function.  These need spilling/filling in the safepoint/stackgrowth case.
// At the time of fill/spill, the offset must be adjusted by the architecture-dependent
// adjustment to hardware SP that occurs in a call instruction.  E.g., for AMD64,
// at Offset+8 because the return address was pushed.
type RegSpill struct {
	Addr           Addr
	Reg            int16
	Reg2           int16 // If not 0, a second register to spill at Addr+regSize. Only for some archs.
	Spill, Unspill As
}

// A Func represents a Go function. If non-nil, it must be a *ir.Func.
type Func interface {
	Pos() src.XPos
}

// Link holds the context for writing object code from a compiler
// to be linker input or for reading that input into the linker.
type Link struct {
	Headtype           objabi.HeadType
	Arch               *LinkArch
	Debugasm           int
	Debugvlog          bool
	Debugpcln          string
	Flag_shared        bool
	Flag_dynlink       bool
	Flag_linkshared    bool
	Flag_optimize      bool
	Flag_locationlists bool
	Flag_noRefName     bool   // do not include referenced symbol names in object file
	Retpoline          bool   // emit use of retpoline stubs for indirect jmp/call
	Flag_maymorestack  string // If not "", call this function before stack checks
	Bso                *bufio.Writer
	Pathname           string
	Pkgpath            string           // the current package's import path
	hashmu             sync.Mutex       // protects hash, funchash
	hash               map[string]*LSym // name -> sym mapping
	funchash           map[string]*LSym // name -> sym mapping for ABIInternal syms
	statichash         map[string]*LSym // name -> sym mapping for static syms
	PosTable           src.PosTable
	InlTree            InlTree // global inlining tree used by gc/inl.go
	DwFixups           *DwarfFixupTable
	Imports            []goobj.ImportedPkg
	DiagFunc           func(string, ...interface{})
	DiagFlush          func()
	DebugInfo          func(ctxt *Link, fn *LSym, info *LSym, curfn Func) ([]dwarf.Scope, dwarf.InlCalls)
	GenAbstractFunc    func(fn *LSym)
	Errors             int

	InParallel    bool // parallel backend phase in effect
	UseBASEntries bool // use Base Address Selection Entries in location lists and PC ranges
	IsAsm         bool // is the source assembly language, which may contain surprising idioms (e.g., call tables)
	Std           bool // is standard library package

	// state for writing objects
	Text []*LSym
	Data []*LSym

	// Constant symbols (e.g. $i64.*) are data symbols created late
	// in the concurrent phase. To ensure a deterministic order, we
	// add them to a separate list, sort at the end, and append it
	// to Data.
	constSyms []*LSym

	// Windows SEH symbols are also data symbols that can be created
	// concurrently.
	SEHSyms []*LSym

	// pkgIdx maps package path to index. The index is used for
	// symbol reference in the object file.
	pkgIdx map[string]int32

	defs         []*LSym // list of defined symbols in the current package
	hashed64defs []*LSym // list of defined short (64-bit or less) hashed (content-addressable) symbols
	hasheddefs   []*LSym // list of defined hashed (content-addressable) symbols
	nonpkgdefs   []*LSym // list of defined non-package symbols
	nonpkgrefs   []*LSym // list of referenced non-package symbols

	Fingerprint goobj.FingerprintType // fingerprint of symbol indices, to catch index mismatch
}

func (ctxt *Link) Diag(format string, args ...interface{}) {
	ctxt.Errors++
	ctxt.DiagFunc(format, args...)
}

func (ctxt *Link) Logf(format string, args ...interface{}) {
	fmt.Fprintf(ctxt.Bso, format, args...)
	ctxt.Bso.Flush()
}

// SpillRegisterArgs emits the code to spill register args into whatever
// locations the spill records specify.
func (fi *FuncInfo) SpillRegisterArgs(last *Prog, pa ProgAlloc) *Prog {
	// Spill register args.
	for _, ra := range fi.spills {
		spill := Appendp(last, pa)
		spill.As = ra.Spill
		spill.From.Type = TYPE_REG
		spill.From.Reg = ra.Reg
		if ra.Reg2 != 0 {
			spill.From.Type = TYPE_REGREG
			spill.From.Offset = int64(ra.Reg2)
		}
		spill.To = ra.Addr
		last = spill
	}
	return last
}

// UnspillRegisterArgs emits the code to restore register args from whatever
// locations the spill records specify.
func (fi *FuncInfo) UnspillRegisterArgs(last *Prog, pa ProgAlloc) *Prog {
	// Unspill any spilled register args
	for _, ra := range fi.spills {
		unspill := Appendp(last, pa)
		unspill.As = ra.Unspill
		unspill.From = ra.Addr
		unspill.To.Type = TYPE_REG
		unspill.To.Reg = ra.Reg
		if ra.Reg2 != 0 {
			unspill.To.Type = TYPE_REGREG
			unspill.To.Offset = int64(ra.Reg2)
		}
		last = unspill
	}
	return last
}

// LinkArch is the definition of a single architecture.
type LinkArch struct {
	*sys.Arch
	Init           func(*Link)
	ErrorCheck     func(*Link, *LSym)
	Preprocess     func(*Link, *LSym, ProgAlloc)
	Assemble       func(*Link, *LSym, ProgAlloc)
	Progedit       func(*Link, *Prog, ProgAlloc)
	SEH            func(*Link, *LSym) *LSym
	UnaryDst       map[As]bool // Instruction takes one operand, a destination.
	DWARFRegisters map[int16]int16
}
```