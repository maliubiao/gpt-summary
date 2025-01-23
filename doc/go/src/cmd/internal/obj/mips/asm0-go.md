Response: My thinking process to analyze the provided Go code snippet went through several stages:

1. **Identify the Purpose:** The initial lines clearly indicate that this file (`asm0.go`) is part of the Go assembler for the MIPS architecture. The comments mentioning `cmd/9l/optab.c` and `cmd/9l/asmout.c` from Plan 9 ("Vita Nuova") strongly suggest that this code is responsible for instruction encoding and layout.

2. **Core Data Structures:** I immediately focused on the key data structures defined in the code:
    * `ctxt0`:  This structure holds per-function assembly state. The comments explicitly state its purpose: to enable concurrent assembly of multiple functions. The fields within (`ctxt`, `newprog`, `cursym`, `autosize`, `instoffset`, `pc`) provide clues about its role in managing the assembly process.
    * `Optab`: This looks like an "opcode table." The fields (`as`, `a1`, `a2`, `a3`, `type_`, `size`, `param`, `family`, `flag`) strongly suggest it's defining the structure of MIPS instructions and their operands. The `family` field indicates support for both MIPS and MIPS64.
    * `optab`: This is a *variable* of type `[]Optab`, making it the actual opcode table containing the specific MIPS instructions the assembler knows.

3. **Analyzing `Optab` Entries:** I examined several entries in the `optab` variable. The values assigned to the fields gave me concrete information:
    * `obj.ATEXT`:  Likely represents the "TEXT" directive marking the start of a function. The operand types (`C_LEXT`, `C_NONE`, `C_TEXTSIZE`) provide information about how this directive is used.
    * Instructions like `AMOVW`, `AMOVV`, `ASUB`, `AADD`, etc., are clearly MIPS assembly instructions. The `C_REG`, `C_NONE`, `C_SEXT`, `C_SAUTO`, etc., are operand type constants. The `size` field indicates the instruction's size in bytes. The `family` field restricts some instructions to MIPS or MIPS64.

4. **Key Functions:** I scanned for important function definitions:
    * `span0`: The comment "holds state while assembling a single function" and the fields in `ctxt0` confirmed this function's purpose. The logic within the function, especially the loops iterating through `cursym.Func().Text.Link`, and the calls to `oplook` and `asmout`, indicate its role in:
        * Calculating function size.
        * Handling large branch instructions.
        * Laying out the code in memory.
        * Emitting machine code.
        * Managing relocations.
        * Marking unsafe preemption points.
    * `oplook`: The name suggests this function "looks up" opcode information. The logic for determining operand classes (`aclass`) and then searching the `oprange` table reinforces this idea.
    * `aclass`:  This function determines the "class" of an operand based on its type (`obj.TYPE_REG`, `obj.TYPE_MEM`, etc.) and other properties (like register names, memory offsets, symbol types). This is crucial for matching instructions to the `optab`.
    * `buildop`:  The comment "build the opcode table" confirmed its role in initializing the `oprange` variable. The sorting of `optab` and the logic for populating `oprange` based on instruction mnemonics are key here.
    * `asmout`:  This function is responsible for generating the actual machine code for a given instruction. The `switch` statement based on `o.type_` and the calls to functions like `OP_RRR`, `OP_IRR`, etc., which seem to be instruction encoding helpers, solidify this understanding.

5. **Inferring Go Functionality:** Based on the identified functions and data structures, I could start inferring the Go functionality being implemented:
    * **MIPS Assembly:** The primary function is clearly assembling Go code for the MIPS and MIPS64 architectures.
    * **Instruction Encoding:** The `Optab` structure, `oplook`, `asmout`, and the `OP_*` helper functions are all directly involved in translating Go assembly instructions into their binary representations.
    * **Function Layout:** `span0` handles the process of determining the size of a function and laying out the instructions in memory.
    * **Relocations:** The calls to `cursym.AddRel` within `asmout` indicate the handling of relocations, necessary for addressing data and functions outside the current code segment.
    * **Concurrency (Potentially):** The `ctxt0` structure and the comment about safe concurrent assembly suggest that this assembler is designed to potentially assemble different functions in parallel.
    * **Stack Management:** The mentions of `REGSP`, `autosize`, and the calculations within `aclass` for `NAME_AUTO` and `NAME_PARAM` indicate involvement in managing the function's stack frame.
    * **TLS Support:** The checks for `objabi.STLSBSS` and the code in `asmout` for handling TLS variables indicate support for thread-local storage.

6. **Code Examples and Assumptions:** To illustrate the functionality, I chose representative examples:
    * A simple register-to-register move (`AMOVW R1, R2`) to demonstrate the basic instruction encoding.
    * Loading a constant into a register (`AMOVW $10, R1`) to show how immediate values are handled.
    * A function call (`CALL myFunc`) to demonstrate relocation handling.
    * Accessing a local variable on the stack (`AMOVW localvar, R1`) to showcase stack frame management.

7. **Command-Line Arguments (Absence):** I noted that the code snippet itself didn't show any explicit command-line argument parsing. This is expected, as this is a lower-level component of the Go toolchain. The command-line argument processing would likely occur in the higher-level compiler or assembler driver.

8. **Common Mistakes:**  I considered potential pitfalls based on my understanding of assembly and the code:
    * **Incorrect Operand Types:**  The strict type checking in `oplook` suggests that providing incorrect operand types would be a common mistake.
    * **Out-of-Range Immediate Values:** The code handling constant values and the generation of multiple instructions for larger constants suggest that using immediates outside the supported ranges could lead to errors.
    * **Misunderstanding Stack Offsets:** Incorrectly calculating or specifying stack offsets when accessing local variables or parameters would be a common error.

By following these steps, I could systematically analyze the code, understand its purpose, identify its key components, infer the Go features it implements, and provide relevant examples and potential pitfalls.
这是 `go/src/cmd/internal/obj/mips/asm0.go` 文件的部分代码，它是 Go 语言工具链中 MIPS 架构的汇编器实现的一部分。其主要功能可以概括为：

**1. 指令操作码表 (Opcode Table) 定义和管理:**

* **`Optab` 结构体:** 定义了 MIPS 指令的结构，包括汇编指令类型 (`as`)，操作数类型 (`a1`, `a2`, `a3`)，指令类型 (`type_`)，指令大小 (`size`)，参数 (`param`)，支持的架构族 (`family`) 和标志位 (`flag`)。
* **`optab` 变量:**  是一个 `Optab` 结构体的切片，包含了 MIPS 架构支持的各种汇编指令及其属性。这个表是汇编器进行指令匹配和编码的核心数据结构。
* **`oprange` 变量:**  用于优化指令查找的二级索引。它是一个切片数组，以汇编指令类型为索引，存储该指令类型对应的 `Optab` 条目切片。
* **`xcmp` 变量:**  一个二维布尔数组，用于快速比较操作数类型是否兼容。例如，`xcmp[C_LCON][C_SCON]` 为 true 表示一个长常量可以匹配一个短常量的操作数类型。
* **`buildop` 函数:**  负责初始化 `oprange` 和 `xcmp` 两个表。它会遍历 `optab`，根据指令类型对其进行排序，并将相同指令类型的 `Optab` 条目存储到 `oprange` 的相应位置。同时，它也会填充 `xcmp` 数组，定义操作数类型之间的兼容关系。
* **`oplook` 函数:**  给定一个汇编指令 `obj.Prog`，这个函数会在 `oprange` 中查找匹配的 `Optab` 条目。它首先获取操作数的类型，然后使用这些类型在 `oprange` 中进行搜索。

**2. 函数汇编过程中的状态管理:**

* **`ctxt0` 结构体:**  用于在汇编单个函数时保存状态。每个函数都会创建一个新的 `ctxt0` 实例，这使得可以安全地并发汇编多个函数。它包含以下字段：
    * `ctxt`: 指向全局链接器的指针。
    * `newprog`: 用于分配新的汇编指令的函数。
    * `cursym`: 当前正在汇编的符号 (函数)。
    * `autosize`: 当前函数的自动变量大小。
    * `instoffset`:  用于计算内存操作数偏移量的临时变量。
    * `pc`: 当前汇编到的程序计数器值。

**3. 指令跨度计算和代码布局:**

* **`span0` 函数:**  负责计算函数的代码大小，并在必要时插入额外的跳转指令来处理超出短跳转范围的情况。它会遍历函数中的每条指令，调用 `oplook` 获取指令大小，并更新程序计数器。
* **处理大跳转:** 如果条件分支指令的目标距离太远，`span0` 会插入无条件跳转指令来绕过范围限制。

**4. 指令编码 (Machine Code Generation):**

* **`asmout` 函数:**  将汇编指令编码成机器码。它接收一个汇编指令 `obj.Prog` 和对应的 `Optab` 条目，根据 `Optab` 中定义的指令类型和操作数类型，生成对应的 32 位或 64 位机器码。
* **`OP_RRR`, `OP_IRR`, `OP_JMP` 等函数:**  是一些辅助函数，用于构建不同指令格式的机器码。它们根据操作码和寄存器/立即数等信息，按照 MIPS 的指令编码格式生成机器码。
* **处理重定位:** `asmout` 函数还会处理需要重定位的指令，例如访问外部符号或全局变量的指令，通过调用 `cursym.AddRel` 添加重定位信息。

**5. 非抢占点标记:**

* **`isUnsafePoint` 函数:**  判断当前指令是否是不安全的抢占点。如果指令显式使用了 `REGTMP` 寄存器，则认为是 unsafe。
* **`isRestartable` 函数:** 判断当前指令是否是多指令序列，如果被抢占可以重启。

**推理 Go 语言功能的实现:**

这段代码是 Go 语言 **汇编器 (Assembler)** 的一部分，特别是针对 **MIPS 架构** 的实现。汇编器的主要任务是将人类可读的汇编语言代码转换为机器可以直接执行的二进制代码。

**Go 代码举例说明:**

假设有以下简单的 Go 函数：

```go
package main

func add(a, b int) int {
	return a + b
}
```

当 Go 编译器编译这个函数时，会生成 MIPS 汇编代码。`asm0.go` 中的代码就负责将这些汇编指令转换为最终的机器码。

**假设的汇编指令输入 (简化)：**

```assembly
TEXT ·add(SB),NOSPLIT,$0-24
  MOVW  a+8(FP), R1 // Load argument 'a'
  MOVW  b+16(FP), R2 // Load argument 'b'
  ADD   R1, R2, R3   // Add 'a' and 'b'
  MOVW  R3, ret+0(FP) // Store the result
  RET
```

**`asm0.go` 的处理过程 (简化)：**

1. **`span0`:** 会遍历这些指令，根据 `oplook` 获取每条指令的大小，计算出 `add` 函数的代码大小。
2. **`oplook`:**  对于 `MOVW a+8(FP), R1`，`oplook` 会识别出 `MOVW` 指令，并且操作数分别是内存地址和寄存器。它会查找 `optab` 表，找到匹配的 `Optab` 条目。
3. **`asmout`:**  对于 `ADD R1, R2, R3`，`asmout` 会根据 `Optab` 中 `ADD` 指令的类型 (type 2) 和操作数类型，调用 `OP_RRR(c.oprrr(p.As), p.From.Reg, r, p.To.Reg)` 生成对应的 MIPS 加法指令机器码。
4. **重定位:**  对于访问函数参数 (`a+8(FP)`, `b+16(FP)`) 和返回值地址 (`ret+0(FP)`) 的 `MOVW` 指令，`asmout` 会添加相应的重定位信息，以便链接器在最终生成可执行文件时填充正确的地址。

**假设的机器码输出 (仅 `ADD` 指令，实际会更复杂):**

假设 `ADD` 指令的 `oprrr` 返回的操作码是 `0x00000020`，寄存器 `R1`, `R2`, `R3` 分别对应编号 `1`, `2`, `3`。那么 `asmout` 生成的机器码可能是：

```
00421820  // (十六进制)  对应的二进制为 00000000 01000010 00011000 00100000
```

**命令行参数的具体处理:**

`asm0.go` 文件本身 **不直接处理命令行参数**。 命令行参数的处理发生在更上层的 Go 工具链组件中，例如 `cmd/compile` (编译器) 和 `cmd/link` (链接器)。 这些组件会解析命令行参数，然后调用汇编器来处理汇编代码。

**使用者易犯错的点:**

由于 `asm0.go` 是 Go 工具链的内部实现，**普通 Go 开发者不会直接与这个文件交互**。 易犯错的点主要存在于 **Go 汇编语言的编写** 方面，这些错误可能会导致 `asm0.go` 在处理汇编代码时出错：

* **操作数类型不匹配:** 在汇编代码中使用的操作数类型与指令要求的类型不符。例如，将立即数用作需要寄存器的操作数。`oplook` 函数会检查这些类型匹配。
  ```assembly
  // 错误示例：ADD $10, $20, R1  // ADD 指令通常需要寄存器作为源操作数
  ```
* **使用了架构不支持的指令:**  尝试使用 MIPS 架构不支持的指令。`oplook` 函数会找不到对应的 `Optab` 条目。
* **立即数超出范围:**  某些指令的立即数有范围限制。
  ```assembly
  // 错误示例：ADDI R1, $0xFFFFFFFF, R2 // 立即数可能超出 ADDI 的范围
  ```
* **栈帧布局错误:**  在手写汇编代码时，错误地管理栈指针 (`SP`) 或帧指针 (`FP`)，导致访问局部变量或参数时出错。这会在 `aclass` 计算内存操作数偏移量时暴露出来。
* **重定位错误:**  在需要使用重定位的情况下，没有正确指定符号名称或偏移量。这会在 `asmout` 调用 `cursym.AddRel` 时出现问题。

**总结:**

`go/src/cmd/internal/obj/mips/asm0.go` 是 Go 语言 MIPS 架构汇编器的核心部分，负责将汇编指令转换为机器码。它定义了指令集、管理汇编状态、计算代码布局以及执行指令编码和重定位。普通 Go 开发者不会直接使用它，但理解其功能有助于理解 Go 语言的底层编译过程。

### 提示词
```
这是路径为go/src/cmd/internal/obj/mips/asm0.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// cmd/9l/optab.c, cmd/9l/asmout.c from Vita Nuova.
//
//	Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2008 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2008 Lucent Technologies Inc. and others
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

package mips

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"fmt"
	"log"
	"slices"
)

// ctxt0 holds state while assembling a single function.
// Each function gets a fresh ctxt0.
// This allows for multiple functions to be safely concurrently assembled.
type ctxt0 struct {
	ctxt       *obj.Link
	newprog    obj.ProgAlloc
	cursym     *obj.LSym
	autosize   int32
	instoffset int64
	pc         int64
}

// Instruction layout.

const (
	mips64FuncAlign = 8
)

const (
	r0iszero = 1
)

type Optab struct {
	as     obj.As
	a1     uint8
	a2     uint8
	a3     uint8
	type_  int8
	size   int8
	param  int16
	family sys.ArchFamily // 0 means both sys.MIPS and sys.MIPS64
	flag   uint8
}

const (
	// Optab.flag
	NOTUSETMP = 1 << iota // p expands to multiple instructions, but does NOT use REGTMP
)

var optab = []Optab{
	{obj.ATEXT, C_LEXT, C_NONE, C_TEXTSIZE, 0, 0, 0, sys.MIPS64, 0},
	{obj.ATEXT, C_ADDR, C_NONE, C_TEXTSIZE, 0, 0, 0, 0, 0},

	{AMOVW, C_REG, C_NONE, C_REG, 1, 4, 0, 0, 0},
	{AMOVV, C_REG, C_NONE, C_REG, 1, 4, 0, sys.MIPS64, 0},
	{AMOVB, C_REG, C_NONE, C_REG, 12, 8, 0, 0, NOTUSETMP},
	{AMOVBU, C_REG, C_NONE, C_REG, 13, 4, 0, 0, 0},
	{AMOVWU, C_REG, C_NONE, C_REG, 14, 8, 0, sys.MIPS64, NOTUSETMP},

	{ASUB, C_REG, C_REG, C_REG, 2, 4, 0, 0, 0},
	{ASUBV, C_REG, C_REG, C_REG, 2, 4, 0, sys.MIPS64, 0},
	{AADD, C_REG, C_REG, C_REG, 2, 4, 0, 0, 0},
	{AADDV, C_REG, C_REG, C_REG, 2, 4, 0, sys.MIPS64, 0},
	{AAND, C_REG, C_REG, C_REG, 2, 4, 0, 0, 0},
	{ASUB, C_REG, C_NONE, C_REG, 2, 4, 0, 0, 0},
	{ASUBV, C_REG, C_NONE, C_REG, 2, 4, 0, sys.MIPS64, 0},
	{AADD, C_REG, C_NONE, C_REG, 2, 4, 0, 0, 0},
	{AADDV, C_REG, C_NONE, C_REG, 2, 4, 0, sys.MIPS64, 0},
	{AAND, C_REG, C_NONE, C_REG, 2, 4, 0, 0, 0},
	{ACMOVN, C_REG, C_REG, C_REG, 2, 4, 0, 0, 0},
	{ANEGW, C_REG, C_NONE, C_REG, 2, 4, 0, 0, 0},
	{ANEGV, C_REG, C_NONE, C_REG, 2, 4, 0, sys.MIPS64, 0},

	{ASLL, C_REG, C_NONE, C_REG, 9, 4, 0, 0, 0},
	{ASLL, C_REG, C_REG, C_REG, 9, 4, 0, 0, 0},
	{ASLLV, C_REG, C_NONE, C_REG, 9, 4, 0, sys.MIPS64, 0},
	{ASLLV, C_REG, C_REG, C_REG, 9, 4, 0, sys.MIPS64, 0},
	{ACLO, C_REG, C_NONE, C_REG, 9, 4, 0, 0, 0},

	{AADDF, C_FREG, C_NONE, C_FREG, 32, 4, 0, 0, 0},
	{AADDF, C_FREG, C_REG, C_FREG, 32, 4, 0, 0, 0},
	{ACMPEQF, C_FREG, C_REG, C_NONE, 32, 4, 0, 0, 0},
	{AABSF, C_FREG, C_NONE, C_FREG, 33, 4, 0, 0, 0},
	{AMOVVF, C_FREG, C_NONE, C_FREG, 33, 4, 0, sys.MIPS64, 0},
	{AMOVF, C_FREG, C_NONE, C_FREG, 33, 4, 0, 0, 0},
	{AMOVD, C_FREG, C_NONE, C_FREG, 33, 4, 0, 0, 0},

	{AMOVW, C_REG, C_NONE, C_SEXT, 7, 4, REGSB, sys.MIPS64, 0},
	{AMOVWU, C_REG, C_NONE, C_SEXT, 7, 4, REGSB, sys.MIPS64, 0},
	{AMOVV, C_REG, C_NONE, C_SEXT, 7, 4, REGSB, sys.MIPS64, 0},
	{AMOVB, C_REG, C_NONE, C_SEXT, 7, 4, REGSB, sys.MIPS64, 0},
	{AMOVBU, C_REG, C_NONE, C_SEXT, 7, 4, REGSB, sys.MIPS64, 0},
	{AMOVWL, C_REG, C_NONE, C_SEXT, 7, 4, REGSB, sys.MIPS64, 0},
	{AMOVVL, C_REG, C_NONE, C_SEXT, 7, 4, REGSB, sys.MIPS64, 0},
	{AMOVW, C_REG, C_NONE, C_SAUTO, 7, 4, REGSP, 0, 0},
	{AMOVWU, C_REG, C_NONE, C_SAUTO, 7, 4, REGSP, sys.MIPS64, 0},
	{AMOVV, C_REG, C_NONE, C_SAUTO, 7, 4, REGSP, sys.MIPS64, 0},
	{AMOVB, C_REG, C_NONE, C_SAUTO, 7, 4, REGSP, 0, 0},
	{AMOVBU, C_REG, C_NONE, C_SAUTO, 7, 4, REGSP, 0, 0},
	{AMOVWL, C_REG, C_NONE, C_SAUTO, 7, 4, REGSP, 0, 0},
	{AMOVVL, C_REG, C_NONE, C_SAUTO, 7, 4, REGSP, sys.MIPS64, 0},
	{AMOVW, C_REG, C_NONE, C_SOREG, 7, 4, REGZERO, 0, 0},
	{AMOVWU, C_REG, C_NONE, C_SOREG, 7, 4, REGZERO, sys.MIPS64, 0},
	{AMOVV, C_REG, C_NONE, C_SOREG, 7, 4, REGZERO, sys.MIPS64, 0},
	{AMOVB, C_REG, C_NONE, C_SOREG, 7, 4, REGZERO, 0, 0},
	{AMOVBU, C_REG, C_NONE, C_SOREG, 7, 4, REGZERO, 0, 0},
	{AMOVWL, C_REG, C_NONE, C_SOREG, 7, 4, REGZERO, 0, 0},
	{AMOVVL, C_REG, C_NONE, C_SOREG, 7, 4, REGZERO, sys.MIPS64, 0},
	{ASC, C_REG, C_NONE, C_SOREG, 7, 4, REGZERO, 0, 0},
	{ASCV, C_REG, C_NONE, C_SOREG, 7, 4, REGZERO, sys.MIPS64, 0},

	{AMOVW, C_SEXT, C_NONE, C_REG, 8, 4, REGSB, sys.MIPS64, 0},
	{AMOVWU, C_SEXT, C_NONE, C_REG, 8, 4, REGSB, sys.MIPS64, 0},
	{AMOVV, C_SEXT, C_NONE, C_REG, 8, 4, REGSB, sys.MIPS64, 0},
	{AMOVB, C_SEXT, C_NONE, C_REG, 8, 4, REGSB, sys.MIPS64, 0},
	{AMOVBU, C_SEXT, C_NONE, C_REG, 8, 4, REGSB, sys.MIPS64, 0},
	{AMOVWL, C_SEXT, C_NONE, C_REG, 8, 4, REGSB, sys.MIPS64, 0},
	{AMOVVL, C_SEXT, C_NONE, C_REG, 8, 4, REGSB, sys.MIPS64, 0},
	{AMOVW, C_SAUTO, C_NONE, C_REG, 8, 4, REGSP, 0, 0},
	{AMOVWU, C_SAUTO, C_NONE, C_REG, 8, 4, REGSP, sys.MIPS64, 0},
	{AMOVV, C_SAUTO, C_NONE, C_REG, 8, 4, REGSP, sys.MIPS64, 0},
	{AMOVB, C_SAUTO, C_NONE, C_REG, 8, 4, REGSP, 0, 0},
	{AMOVBU, C_SAUTO, C_NONE, C_REG, 8, 4, REGSP, 0, 0},
	{AMOVWL, C_SAUTO, C_NONE, C_REG, 8, 4, REGSP, 0, 0},
	{AMOVVL, C_SAUTO, C_NONE, C_REG, 8, 4, REGSP, sys.MIPS64, 0},
	{AMOVW, C_SOREG, C_NONE, C_REG, 8, 4, REGZERO, 0, 0},
	{AMOVWU, C_SOREG, C_NONE, C_REG, 8, 4, REGZERO, sys.MIPS64, 0},
	{AMOVV, C_SOREG, C_NONE, C_REG, 8, 4, REGZERO, sys.MIPS64, 0},
	{AMOVB, C_SOREG, C_NONE, C_REG, 8, 4, REGZERO, 0, 0},
	{AMOVBU, C_SOREG, C_NONE, C_REG, 8, 4, REGZERO, 0, 0},
	{AMOVWL, C_SOREG, C_NONE, C_REG, 8, 4, REGZERO, 0, 0},
	{AMOVVL, C_SOREG, C_NONE, C_REG, 8, 4, REGZERO, sys.MIPS64, 0},
	{ALL, C_SOREG, C_NONE, C_REG, 8, 4, REGZERO, 0, 0},
	{ALLV, C_SOREG, C_NONE, C_REG, 8, 4, REGZERO, sys.MIPS64, 0},

	{AMOVW, C_REG, C_NONE, C_LEXT, 35, 12, REGSB, sys.MIPS64, 0},
	{AMOVWU, C_REG, C_NONE, C_LEXT, 35, 12, REGSB, sys.MIPS64, 0},
	{AMOVV, C_REG, C_NONE, C_LEXT, 35, 12, REGSB, sys.MIPS64, 0},
	{AMOVB, C_REG, C_NONE, C_LEXT, 35, 12, REGSB, sys.MIPS64, 0},
	{AMOVBU, C_REG, C_NONE, C_LEXT, 35, 12, REGSB, sys.MIPS64, 0},
	{AMOVW, C_REG, C_NONE, C_LAUTO, 35, 12, REGSP, 0, 0},
	{AMOVWU, C_REG, C_NONE, C_LAUTO, 35, 12, REGSP, sys.MIPS64, 0},
	{AMOVV, C_REG, C_NONE, C_LAUTO, 35, 12, REGSP, sys.MIPS64, 0},
	{AMOVB, C_REG, C_NONE, C_LAUTO, 35, 12, REGSP, 0, 0},
	{AMOVBU, C_REG, C_NONE, C_LAUTO, 35, 12, REGSP, 0, 0},
	{AMOVW, C_REG, C_NONE, C_LOREG, 35, 12, REGZERO, 0, 0},
	{AMOVWU, C_REG, C_NONE, C_LOREG, 35, 12, REGZERO, sys.MIPS64, 0},
	{AMOVV, C_REG, C_NONE, C_LOREG, 35, 12, REGZERO, sys.MIPS64, 0},
	{AMOVB, C_REG, C_NONE, C_LOREG, 35, 12, REGZERO, 0, 0},
	{AMOVBU, C_REG, C_NONE, C_LOREG, 35, 12, REGZERO, 0, 0},
	{ASC, C_REG, C_NONE, C_LOREG, 35, 12, REGZERO, 0, 0},
	{AMOVW, C_REG, C_NONE, C_ADDR, 50, 8, 0, sys.MIPS, 0},
	{AMOVW, C_REG, C_NONE, C_ADDR, 50, 12, 0, sys.MIPS64, 0},
	{AMOVWU, C_REG, C_NONE, C_ADDR, 50, 12, 0, sys.MIPS64, 0},
	{AMOVV, C_REG, C_NONE, C_ADDR, 50, 12, 0, sys.MIPS64, 0},
	{AMOVB, C_REG, C_NONE, C_ADDR, 50, 8, 0, sys.MIPS, 0},
	{AMOVB, C_REG, C_NONE, C_ADDR, 50, 12, 0, sys.MIPS64, 0},
	{AMOVBU, C_REG, C_NONE, C_ADDR, 50, 8, 0, sys.MIPS, 0},
	{AMOVBU, C_REG, C_NONE, C_ADDR, 50, 12, 0, sys.MIPS64, 0},
	{AMOVW, C_REG, C_NONE, C_TLS, 53, 8, 0, 0, NOTUSETMP},
	{AMOVWU, C_REG, C_NONE, C_TLS, 53, 8, 0, sys.MIPS64, NOTUSETMP},
	{AMOVV, C_REG, C_NONE, C_TLS, 53, 8, 0, sys.MIPS64, NOTUSETMP},
	{AMOVB, C_REG, C_NONE, C_TLS, 53, 8, 0, 0, NOTUSETMP},
	{AMOVBU, C_REG, C_NONE, C_TLS, 53, 8, 0, 0, NOTUSETMP},

	{AMOVW, C_LEXT, C_NONE, C_REG, 36, 12, REGSB, sys.MIPS64, 0},
	{AMOVWU, C_LEXT, C_NONE, C_REG, 36, 12, REGSB, sys.MIPS64, 0},
	{AMOVV, C_LEXT, C_NONE, C_REG, 36, 12, REGSB, sys.MIPS64, 0},
	{AMOVB, C_LEXT, C_NONE, C_REG, 36, 12, REGSB, sys.MIPS64, 0},
	{AMOVBU, C_LEXT, C_NONE, C_REG, 36, 12, REGSB, sys.MIPS64, 0},
	{AMOVW, C_LAUTO, C_NONE, C_REG, 36, 12, REGSP, 0, 0},
	{AMOVWU, C_LAUTO, C_NONE, C_REG, 36, 12, REGSP, sys.MIPS64, 0},
	{AMOVV, C_LAUTO, C_NONE, C_REG, 36, 12, REGSP, sys.MIPS64, 0},
	{AMOVB, C_LAUTO, C_NONE, C_REG, 36, 12, REGSP, 0, 0},
	{AMOVBU, C_LAUTO, C_NONE, C_REG, 36, 12, REGSP, 0, 0},
	{AMOVW, C_LOREG, C_NONE, C_REG, 36, 12, REGZERO, 0, 0},
	{AMOVWU, C_LOREG, C_NONE, C_REG, 36, 12, REGZERO, sys.MIPS64, 0},
	{AMOVV, C_LOREG, C_NONE, C_REG, 36, 12, REGZERO, sys.MIPS64, 0},
	{AMOVB, C_LOREG, C_NONE, C_REG, 36, 12, REGZERO, 0, 0},
	{AMOVBU, C_LOREG, C_NONE, C_REG, 36, 12, REGZERO, 0, 0},
	{AMOVW, C_ADDR, C_NONE, C_REG, 51, 8, 0, sys.MIPS, 0},
	{AMOVW, C_ADDR, C_NONE, C_REG, 51, 12, 0, sys.MIPS64, 0},
	{AMOVWU, C_ADDR, C_NONE, C_REG, 51, 12, 0, sys.MIPS64, 0},
	{AMOVV, C_ADDR, C_NONE, C_REG, 51, 12, 0, sys.MIPS64, 0},
	{AMOVB, C_ADDR, C_NONE, C_REG, 51, 8, 0, sys.MIPS, 0},
	{AMOVB, C_ADDR, C_NONE, C_REG, 51, 12, 0, sys.MIPS64, 0},
	{AMOVBU, C_ADDR, C_NONE, C_REG, 51, 8, 0, sys.MIPS, 0},
	{AMOVBU, C_ADDR, C_NONE, C_REG, 51, 12, 0, sys.MIPS64, 0},
	{AMOVW, C_TLS, C_NONE, C_REG, 54, 8, 0, 0, NOTUSETMP},
	{AMOVWU, C_TLS, C_NONE, C_REG, 54, 8, 0, sys.MIPS64, NOTUSETMP},
	{AMOVV, C_TLS, C_NONE, C_REG, 54, 8, 0, sys.MIPS64, NOTUSETMP},
	{AMOVB, C_TLS, C_NONE, C_REG, 54, 8, 0, 0, NOTUSETMP},
	{AMOVBU, C_TLS, C_NONE, C_REG, 54, 8, 0, 0, NOTUSETMP},

	{AMOVW, C_SECON, C_NONE, C_REG, 3, 4, REGSB, sys.MIPS64, 0},
	{AMOVV, C_SECON, C_NONE, C_REG, 3, 4, REGSB, sys.MIPS64, 0},
	{AMOVW, C_SACON, C_NONE, C_REG, 3, 4, REGSP, 0, 0},
	{AMOVV, C_SACON, C_NONE, C_REG, 3, 4, REGSP, sys.MIPS64, 0},
	{AMOVW, C_LECON, C_NONE, C_REG, 52, 8, REGSB, sys.MIPS, NOTUSETMP},
	{AMOVW, C_LECON, C_NONE, C_REG, 52, 12, REGSB, sys.MIPS64, NOTUSETMP},
	{AMOVV, C_LECON, C_NONE, C_REG, 52, 12, REGSB, sys.MIPS64, NOTUSETMP},

	{AMOVW, C_LACON, C_NONE, C_REG, 26, 12, REGSP, 0, 0},
	{AMOVV, C_LACON, C_NONE, C_REG, 26, 12, REGSP, sys.MIPS64, 0},
	{AMOVW, C_ADDCON, C_NONE, C_REG, 3, 4, REGZERO, 0, 0},
	{AMOVV, C_ADDCON, C_NONE, C_REG, 3, 4, REGZERO, sys.MIPS64, 0},
	{AMOVW, C_ANDCON, C_NONE, C_REG, 3, 4, REGZERO, 0, 0},
	{AMOVV, C_ANDCON, C_NONE, C_REG, 3, 4, REGZERO, sys.MIPS64, 0},
	{AMOVW, C_STCON, C_NONE, C_REG, 55, 8, 0, 0, NOTUSETMP},
	{AMOVV, C_STCON, C_NONE, C_REG, 55, 8, 0, sys.MIPS64, NOTUSETMP},

	{AMOVW, C_UCON, C_NONE, C_REG, 24, 4, 0, 0, 0},
	{AMOVV, C_UCON, C_NONE, C_REG, 24, 4, 0, sys.MIPS64, 0},
	{AMOVW, C_LCON, C_NONE, C_REG, 19, 8, 0, 0, NOTUSETMP},
	{AMOVV, C_LCON, C_NONE, C_REG, 19, 8, 0, sys.MIPS64, NOTUSETMP},

	{AMOVW, C_HI, C_NONE, C_REG, 20, 4, 0, 0, 0},
	{AMOVV, C_HI, C_NONE, C_REG, 20, 4, 0, sys.MIPS64, 0},
	{AMOVW, C_LO, C_NONE, C_REG, 20, 4, 0, 0, 0},
	{AMOVV, C_LO, C_NONE, C_REG, 20, 4, 0, sys.MIPS64, 0},
	{AMOVW, C_REG, C_NONE, C_HI, 21, 4, 0, 0, 0},
	{AMOVV, C_REG, C_NONE, C_HI, 21, 4, 0, sys.MIPS64, 0},
	{AMOVW, C_REG, C_NONE, C_LO, 21, 4, 0, 0, 0},
	{AMOVV, C_REG, C_NONE, C_LO, 21, 4, 0, sys.MIPS64, 0},

	{AMUL, C_REG, C_REG, C_NONE, 22, 4, 0, 0, 0},
	{AMUL, C_REG, C_REG, C_REG, 22, 4, 0, 0, 0},
	{AMULV, C_REG, C_REG, C_NONE, 22, 4, 0, sys.MIPS64, 0},

	{AADD, C_ADD0CON, C_REG, C_REG, 4, 4, 0, 0, 0},
	{AADD, C_ADD0CON, C_NONE, C_REG, 4, 4, 0, 0, 0},
	{AADD, C_ANDCON, C_REG, C_REG, 10, 8, 0, 0, 0},
	{AADD, C_ANDCON, C_NONE, C_REG, 10, 8, 0, 0, 0},

	{AADDV, C_ADD0CON, C_REG, C_REG, 4, 4, 0, sys.MIPS64, 0},
	{AADDV, C_ADD0CON, C_NONE, C_REG, 4, 4, 0, sys.MIPS64, 0},
	{AADDV, C_ANDCON, C_REG, C_REG, 10, 8, 0, sys.MIPS64, 0},
	{AADDV, C_ANDCON, C_NONE, C_REG, 10, 8, 0, sys.MIPS64, 0},

	{AAND, C_AND0CON, C_REG, C_REG, 4, 4, 0, 0, 0},
	{AAND, C_AND0CON, C_NONE, C_REG, 4, 4, 0, 0, 0},
	{AAND, C_ADDCON, C_REG, C_REG, 10, 8, 0, 0, 0},
	{AAND, C_ADDCON, C_NONE, C_REG, 10, 8, 0, 0, 0},

	{AADD, C_UCON, C_REG, C_REG, 25, 8, 0, 0, 0},
	{AADD, C_UCON, C_NONE, C_REG, 25, 8, 0, 0, 0},
	{AADDV, C_UCON, C_REG, C_REG, 25, 8, 0, sys.MIPS64, 0},
	{AADDV, C_UCON, C_NONE, C_REG, 25, 8, 0, sys.MIPS64, 0},
	{AAND, C_UCON, C_REG, C_REG, 25, 8, 0, 0, 0},
	{AAND, C_UCON, C_NONE, C_REG, 25, 8, 0, 0, 0},

	{AADD, C_LCON, C_NONE, C_REG, 23, 12, 0, 0, 0},
	{AADDV, C_LCON, C_NONE, C_REG, 23, 12, 0, sys.MIPS64, 0},
	{AAND, C_LCON, C_NONE, C_REG, 23, 12, 0, 0, 0},
	{AADD, C_LCON, C_REG, C_REG, 23, 12, 0, 0, 0},
	{AADDV, C_LCON, C_REG, C_REG, 23, 12, 0, sys.MIPS64, 0},
	{AAND, C_LCON, C_REG, C_REG, 23, 12, 0, 0, 0},

	{ASLL, C_SCON, C_REG, C_REG, 16, 4, 0, 0, 0},
	{ASLL, C_SCON, C_NONE, C_REG, 16, 4, 0, 0, 0},

	{ASLLV, C_SCON, C_REG, C_REG, 16, 4, 0, sys.MIPS64, 0},
	{ASLLV, C_SCON, C_NONE, C_REG, 16, 4, 0, sys.MIPS64, 0},

	{ASYSCALL, C_NONE, C_NONE, C_NONE, 5, 4, 0, 0, 0},

	{ABEQ, C_REG, C_REG, C_SBRA, 6, 4, 0, 0, 0},
	{ABEQ, C_REG, C_NONE, C_SBRA, 6, 4, 0, 0, 0},
	{ABLEZ, C_REG, C_NONE, C_SBRA, 6, 4, 0, 0, 0},
	{ABFPT, C_NONE, C_NONE, C_SBRA, 6, 8, 0, 0, NOTUSETMP},

	{AJMP, C_NONE, C_NONE, C_LBRA, 11, 4, 0, 0, 0},
	{AJAL, C_NONE, C_NONE, C_LBRA, 11, 4, 0, 0, 0},

	{AJMP, C_NONE, C_NONE, C_ZOREG, 18, 4, REGZERO, 0, 0},
	{AJAL, C_NONE, C_NONE, C_ZOREG, 18, 4, REGLINK, 0, 0},

	{AMOVW, C_SEXT, C_NONE, C_FREG, 27, 4, REGSB, sys.MIPS64, 0},
	{AMOVF, C_SEXT, C_NONE, C_FREG, 27, 4, REGSB, sys.MIPS64, 0},
	{AMOVD, C_SEXT, C_NONE, C_FREG, 27, 4, REGSB, sys.MIPS64, 0},
	{AMOVW, C_SAUTO, C_NONE, C_FREG, 27, 4, REGSP, sys.MIPS64, 0},
	{AMOVF, C_SAUTO, C_NONE, C_FREG, 27, 4, REGSP, 0, 0},
	{AMOVD, C_SAUTO, C_NONE, C_FREG, 27, 4, REGSP, 0, 0},
	{AMOVW, C_SOREG, C_NONE, C_FREG, 27, 4, REGZERO, sys.MIPS64, 0},
	{AMOVF, C_SOREG, C_NONE, C_FREG, 27, 4, REGZERO, 0, 0},
	{AMOVD, C_SOREG, C_NONE, C_FREG, 27, 4, REGZERO, 0, 0},

	{AMOVW, C_LEXT, C_NONE, C_FREG, 27, 12, REGSB, sys.MIPS64, 0},
	{AMOVF, C_LEXT, C_NONE, C_FREG, 27, 12, REGSB, sys.MIPS64, 0},
	{AMOVD, C_LEXT, C_NONE, C_FREG, 27, 12, REGSB, sys.MIPS64, 0},
	{AMOVW, C_LAUTO, C_NONE, C_FREG, 27, 12, REGSP, sys.MIPS64, 0},
	{AMOVF, C_LAUTO, C_NONE, C_FREG, 27, 12, REGSP, 0, 0},
	{AMOVD, C_LAUTO, C_NONE, C_FREG, 27, 12, REGSP, 0, 0},
	{AMOVW, C_LOREG, C_NONE, C_FREG, 27, 12, REGZERO, sys.MIPS64, 0},
	{AMOVF, C_LOREG, C_NONE, C_FREG, 27, 12, REGZERO, 0, 0},
	{AMOVD, C_LOREG, C_NONE, C_FREG, 27, 12, REGZERO, 0, 0},
	{AMOVF, C_ADDR, C_NONE, C_FREG, 51, 8, 0, sys.MIPS, 0},
	{AMOVF, C_ADDR, C_NONE, C_FREG, 51, 12, 0, sys.MIPS64, 0},
	{AMOVD, C_ADDR, C_NONE, C_FREG, 51, 8, 0, sys.MIPS, 0},
	{AMOVD, C_ADDR, C_NONE, C_FREG, 51, 12, 0, sys.MIPS64, 0},

	{AMOVW, C_FREG, C_NONE, C_SEXT, 28, 4, REGSB, sys.MIPS64, 0},
	{AMOVF, C_FREG, C_NONE, C_SEXT, 28, 4, REGSB, sys.MIPS64, 0},
	{AMOVD, C_FREG, C_NONE, C_SEXT, 28, 4, REGSB, sys.MIPS64, 0},
	{AMOVW, C_FREG, C_NONE, C_SAUTO, 28, 4, REGSP, sys.MIPS64, 0},
	{AMOVF, C_FREG, C_NONE, C_SAUTO, 28, 4, REGSP, 0, 0},
	{AMOVD, C_FREG, C_NONE, C_SAUTO, 28, 4, REGSP, 0, 0},
	{AMOVW, C_FREG, C_NONE, C_SOREG, 28, 4, REGZERO, sys.MIPS64, 0},
	{AMOVF, C_FREG, C_NONE, C_SOREG, 28, 4, REGZERO, 0, 0},
	{AMOVD, C_FREG, C_NONE, C_SOREG, 28, 4, REGZERO, 0, 0},

	{AMOVW, C_FREG, C_NONE, C_LEXT, 28, 12, REGSB, sys.MIPS64, 0},
	{AMOVF, C_FREG, C_NONE, C_LEXT, 28, 12, REGSB, sys.MIPS64, 0},
	{AMOVD, C_FREG, C_NONE, C_LEXT, 28, 12, REGSB, sys.MIPS64, 0},
	{AMOVW, C_FREG, C_NONE, C_LAUTO, 28, 12, REGSP, sys.MIPS64, 0},
	{AMOVF, C_FREG, C_NONE, C_LAUTO, 28, 12, REGSP, 0, 0},
	{AMOVD, C_FREG, C_NONE, C_LAUTO, 28, 12, REGSP, 0, 0},
	{AMOVW, C_FREG, C_NONE, C_LOREG, 28, 12, REGZERO, sys.MIPS64, 0},
	{AMOVF, C_FREG, C_NONE, C_LOREG, 28, 12, REGZERO, 0, 0},
	{AMOVD, C_FREG, C_NONE, C_LOREG, 28, 12, REGZERO, 0, 0},
	{AMOVF, C_FREG, C_NONE, C_ADDR, 50, 8, 0, sys.MIPS, 0},
	{AMOVF, C_FREG, C_NONE, C_ADDR, 50, 12, 0, sys.MIPS64, 0},
	{AMOVD, C_FREG, C_NONE, C_ADDR, 50, 8, 0, sys.MIPS, 0},
	{AMOVD, C_FREG, C_NONE, C_ADDR, 50, 12, 0, sys.MIPS64, 0},

	{AMOVW, C_REG, C_NONE, C_FREG, 30, 4, 0, 0, 0},
	{AMOVW, C_FREG, C_NONE, C_REG, 31, 4, 0, 0, 0},
	{AMOVV, C_REG, C_NONE, C_FREG, 47, 4, 0, sys.MIPS64, 0},
	{AMOVV, C_FREG, C_NONE, C_REG, 48, 4, 0, sys.MIPS64, 0},

	{AMOVW, C_ADDCON, C_NONE, C_FREG, 34, 8, 0, sys.MIPS64, 0},
	{AMOVW, C_ANDCON, C_NONE, C_FREG, 34, 8, 0, sys.MIPS64, 0},

	{AMOVW, C_REG, C_NONE, C_MREG, 37, 4, 0, 0, 0},
	{AMOVV, C_REG, C_NONE, C_MREG, 37, 4, 0, sys.MIPS64, 0},
	{AMOVW, C_MREG, C_NONE, C_REG, 38, 4, 0, 0, 0},
	{AMOVV, C_MREG, C_NONE, C_REG, 38, 4, 0, sys.MIPS64, 0},

	{AWORD, C_LCON, C_NONE, C_NONE, 40, 4, 0, 0, 0},

	{AMOVW, C_REG, C_NONE, C_FCREG, 41, 4, 0, 0, 0},
	{AMOVV, C_REG, C_NONE, C_FCREG, 41, 4, 0, sys.MIPS64, 0},
	{AMOVW, C_FCREG, C_NONE, C_REG, 42, 4, 0, 0, 0},
	{AMOVV, C_FCREG, C_NONE, C_REG, 42, 4, 0, sys.MIPS64, 0},

	{ATEQ, C_SCON, C_REG, C_REG, 15, 4, 0, 0, 0},
	{ATEQ, C_SCON, C_NONE, C_REG, 15, 4, 0, 0, 0},
	{ACMOVT, C_REG, C_NONE, C_REG, 17, 4, 0, 0, 0},

	{AVMOVB, C_SCON, C_NONE, C_WREG, 56, 4, 0, sys.MIPS64, 0},
	{AVMOVB, C_ADDCON, C_NONE, C_WREG, 56, 4, 0, sys.MIPS64, 0},
	{AVMOVB, C_SOREG, C_NONE, C_WREG, 57, 4, 0, sys.MIPS64, 0},
	{AVMOVB, C_WREG, C_NONE, C_SOREG, 58, 4, 0, sys.MIPS64, 0},

	{AWSBH, C_REG, C_NONE, C_REG, 59, 4, 0, 0, 0},
	{ADSBH, C_REG, C_NONE, C_REG, 59, 4, 0, sys.MIPS64, 0},

	{ABREAK, C_REG, C_NONE, C_SEXT, 7, 4, REGSB, sys.MIPS64, 0}, /* really CACHE instruction */
	{ABREAK, C_REG, C_NONE, C_SAUTO, 7, 4, REGSP, sys.MIPS64, 0},
	{ABREAK, C_REG, C_NONE, C_SOREG, 7, 4, REGZERO, sys.MIPS64, 0},
	{ABREAK, C_NONE, C_NONE, C_NONE, 5, 4, 0, 0, 0},

	{obj.AUNDEF, C_NONE, C_NONE, C_NONE, 49, 4, 0, 0, 0},
	{obj.APCDATA, C_LCON, C_NONE, C_LCON, 0, 0, 0, 0, 0},
	{obj.AFUNCDATA, C_SCON, C_NONE, C_ADDR, 0, 0, 0, 0, 0},
	{obj.ANOP, C_NONE, C_NONE, C_NONE, 0, 0, 0, 0, 0},
	{obj.ANOP, C_LCON, C_NONE, C_NONE, 0, 0, 0, 0, 0}, // nop variants, see #40689
	{obj.ANOP, C_REG, C_NONE, C_NONE, 0, 0, 0, 0, 0},
	{obj.ANOP, C_FREG, C_NONE, C_NONE, 0, 0, 0, 0, 0},
	{obj.ADUFFZERO, C_NONE, C_NONE, C_LBRA, 11, 4, 0, 0, 0}, // same as AJMP
	{obj.ADUFFCOPY, C_NONE, C_NONE, C_LBRA, 11, 4, 0, 0, 0}, // same as AJMP

	{obj.AXXX, C_NONE, C_NONE, C_NONE, 0, 4, 0, 0, 0},
}

var oprange [ALAST & obj.AMask][]Optab

var xcmp [C_NCLASS][C_NCLASS]bool

func span0(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc) {
	if ctxt.Retpoline {
		ctxt.Diag("-spectre=ret not supported on mips")
		ctxt.Retpoline = false // don't keep printing
	}

	p := cursym.Func().Text
	if p == nil || p.Link == nil { // handle external functions and ELF section symbols
		return
	}

	c := ctxt0{ctxt: ctxt, newprog: newprog, cursym: cursym, autosize: int32(p.To.Offset + ctxt.Arch.FixedFrameSize)}

	if oprange[AOR&obj.AMask] == nil {
		c.ctxt.Diag("mips ops not initialized, call mips.buildop first")
	}

	pc := int64(0)
	p.Pc = pc

	var m int
	var o *Optab
	for p = p.Link; p != nil; p = p.Link {
		p.Pc = pc
		o = c.oplook(p)
		m = int(o.size)
		if m == 0 {
			if p.As != obj.ANOP && p.As != obj.AFUNCDATA && p.As != obj.APCDATA {
				c.ctxt.Diag("zero-width instruction\n%v", p)
			}
			continue
		}

		pc += int64(m)
	}

	c.cursym.Size = pc

	/*
	 * if any procedure is large enough to
	 * generate a large SBRA branch, then
	 * generate extra passes putting branches
	 * around jmps to fix. this is rare.
	 */
	bflag := 1

	var otxt int64
	var q *obj.Prog
	for bflag != 0 {
		bflag = 0
		pc = 0
		for p = c.cursym.Func().Text.Link; p != nil; p = p.Link {
			p.Pc = pc
			o = c.oplook(p)

			// very large conditional branches
			if o.type_ == 6 && p.To.Target() != nil {
				otxt = p.To.Target().Pc - pc
				if otxt < -(1<<17)+10 || otxt >= (1<<17)-10 {
					q = c.newprog()
					q.Link = p.Link
					p.Link = q
					q.As = AJMP
					q.Pos = p.Pos
					q.To.Type = obj.TYPE_BRANCH
					q.To.SetTarget(p.To.Target())
					p.To.SetTarget(q)
					q = c.newprog()
					q.Link = p.Link
					p.Link = q
					q.As = AJMP
					q.Pos = p.Pos
					q.To.Type = obj.TYPE_BRANCH
					q.To.SetTarget(q.Link.Link)

					c.addnop(p.Link)
					c.addnop(p)
					bflag = 1
				}
			}

			m = int(o.size)
			if m == 0 {
				if p.As != obj.ANOP && p.As != obj.AFUNCDATA && p.As != obj.APCDATA {
					c.ctxt.Diag("zero-width instruction\n%v", p)
				}
				continue
			}

			pc += int64(m)
		}

		c.cursym.Size = pc
	}
	if c.ctxt.Arch.Family == sys.MIPS64 {
		pc += -pc & (mips64FuncAlign - 1)
	}
	c.cursym.Size = pc

	/*
	 * lay out the code, emitting code and data relocations.
	 */

	c.cursym.Grow(c.cursym.Size)

	bp := c.cursym.P
	var i int32
	var out [4]uint32
	for p := c.cursym.Func().Text.Link; p != nil; p = p.Link {
		c.pc = p.Pc
		o = c.oplook(p)
		if int(o.size) > 4*len(out) {
			log.Fatalf("out array in span0 is too small, need at least %d for %v", o.size/4, p)
		}
		c.asmout(p, o, out[:])
		for i = 0; i < int32(o.size/4); i++ {
			c.ctxt.Arch.ByteOrder.PutUint32(bp, out[i])
			bp = bp[4:]
		}
	}

	// Mark nonpreemptible instruction sequences.
	// We use REGTMP as a scratch register during call injection,
	// so instruction sequences that use REGTMP are unsafe to
	// preempt asynchronously.
	obj.MarkUnsafePoints(c.ctxt, c.cursym.Func().Text, c.newprog, c.isUnsafePoint, c.isRestartable)
}

// isUnsafePoint returns whether p is an unsafe point.
func (c *ctxt0) isUnsafePoint(p *obj.Prog) bool {
	// If p explicitly uses REGTMP, it's unsafe to preempt, because the
	// preemption sequence clobbers REGTMP.
	return p.From.Reg == REGTMP || p.To.Reg == REGTMP || p.Reg == REGTMP
}

// isRestartable returns whether p is a multi-instruction sequence that,
// if preempted, can be restarted.
func (c *ctxt0) isRestartable(p *obj.Prog) bool {
	if c.isUnsafePoint(p) {
		return false
	}
	// If p is a multi-instruction sequence with uses REGTMP inserted by
	// the assembler in order to materialize a large constant/offset, we
	// can restart p (at the start of the instruction sequence), recompute
	// the content of REGTMP, upon async preemption. Currently, all cases
	// of assembler-inserted REGTMP fall into this category.
	// If p doesn't use REGTMP, it can be simply preempted, so we don't
	// mark it.
	o := c.oplook(p)
	return o.size > 4 && o.flag&NOTUSETMP == 0
}

func isint32(v int64) bool {
	return int64(int32(v)) == v
}

func isuint32(v uint64) bool {
	return uint64(uint32(v)) == v
}

func (c *ctxt0) aclass(a *obj.Addr) int {
	switch a.Type {
	case obj.TYPE_NONE:
		return C_NONE

	case obj.TYPE_REG:
		if REG_R0 <= a.Reg && a.Reg <= REG_R31 {
			return C_REG
		}
		if REG_F0 <= a.Reg && a.Reg <= REG_F31 {
			return C_FREG
		}
		if REG_M0 <= a.Reg && a.Reg <= REG_M31 {
			return C_MREG
		}
		if REG_FCR0 <= a.Reg && a.Reg <= REG_FCR31 {
			return C_FCREG
		}
		if REG_W0 <= a.Reg && a.Reg <= REG_W31 {
			return C_WREG
		}
		if a.Reg == REG_LO {
			return C_LO
		}
		if a.Reg == REG_HI {
			return C_HI
		}
		return C_GOK

	case obj.TYPE_MEM:
		switch a.Name {
		case obj.NAME_EXTERN,
			obj.NAME_STATIC:
			if a.Sym == nil {
				break
			}
			c.instoffset = a.Offset
			if a.Sym != nil { // use relocation
				if a.Sym.Type == objabi.STLSBSS {
					return C_TLS
				}
				return C_ADDR
			}
			return C_LEXT

		case obj.NAME_AUTO:
			if a.Reg == REGSP {
				// unset base register for better printing, since
				// a.Offset is still relative to pseudo-SP.
				a.Reg = obj.REG_NONE
			}
			c.instoffset = int64(c.autosize) + a.Offset
			if c.instoffset >= -BIG && c.instoffset < BIG {
				return C_SAUTO
			}
			return C_LAUTO

		case obj.NAME_PARAM:
			if a.Reg == REGSP {
				// unset base register for better printing, since
				// a.Offset is still relative to pseudo-FP.
				a.Reg = obj.REG_NONE
			}
			c.instoffset = int64(c.autosize) + a.Offset + c.ctxt.Arch.FixedFrameSize
			if c.instoffset >= -BIG && c.instoffset < BIG {
				return C_SAUTO
			}
			return C_LAUTO

		case obj.NAME_NONE:
			c.instoffset = a.Offset
			if c.instoffset == 0 {
				return C_ZOREG
			}
			if c.instoffset >= -BIG && c.instoffset < BIG {
				return C_SOREG
			}
			return C_LOREG
		}

		return C_GOK

	case obj.TYPE_TEXTSIZE:
		return C_TEXTSIZE

	case obj.TYPE_CONST,
		obj.TYPE_ADDR:
		switch a.Name {
		case obj.NAME_NONE:
			c.instoffset = a.Offset
			if a.Reg != obj.REG_NONE {
				if -BIG <= c.instoffset && c.instoffset <= BIG {
					return C_SACON
				}
				if isint32(c.instoffset) {
					return C_LACON
				}
				return C_DACON
			}

		case obj.NAME_EXTERN,
			obj.NAME_STATIC:
			s := a.Sym
			if s == nil {
				return C_GOK
			}

			c.instoffset = a.Offset
			if s.Type == objabi.STLSBSS {
				return C_STCON // address of TLS variable
			}
			return C_LECON

		case obj.NAME_AUTO:
			if a.Reg == REGSP {
				// unset base register for better printing, since
				// a.Offset is still relative to pseudo-SP.
				a.Reg = obj.REG_NONE
			}
			c.instoffset = int64(c.autosize) + a.Offset
			if c.instoffset >= -BIG && c.instoffset < BIG {
				return C_SACON
			}
			return C_LACON

		case obj.NAME_PARAM:
			if a.Reg == REGSP {
				// unset base register for better printing, since
				// a.Offset is still relative to pseudo-FP.
				a.Reg = obj.REG_NONE
			}
			c.instoffset = int64(c.autosize) + a.Offset + c.ctxt.Arch.FixedFrameSize
			if c.instoffset >= -BIG && c.instoffset < BIG {
				return C_SACON
			}
			return C_LACON

		default:
			return C_GOK
		}

		if c.instoffset >= 0 {
			if c.instoffset == 0 {
				return C_ZCON
			}
			if c.instoffset <= 0x7fff {
				return C_SCON
			}
			if c.instoffset <= 0xffff {
				return C_ANDCON
			}
			if c.instoffset&0xffff == 0 && isuint32(uint64(c.instoffset)) { /* && ((instoffset & (1<<31)) == 0) */
				return C_UCON
			}
			if isint32(c.instoffset) || isuint32(uint64(c.instoffset)) {
				return C_LCON
			}
			return C_LCON // C_DCON
		}

		if c.instoffset >= -0x8000 {
			return C_ADDCON
		}
		if c.instoffset&0xffff == 0 && isint32(c.instoffset) {
			return C_UCON
		}
		if isint32(c.instoffset) {
			return C_LCON
		}
		return C_LCON // C_DCON

	case obj.TYPE_BRANCH:
		return C_SBRA
	}

	return C_GOK
}

func prasm(p *obj.Prog) {
	fmt.Printf("%v\n", p)
}

func (c *ctxt0) oplook(p *obj.Prog) *Optab {
	if oprange[AOR&obj.AMask] == nil {
		c.ctxt.Diag("mips ops not initialized, call mips.buildop first")
	}

	a1 := int(p.Optab)
	if a1 != 0 {
		return &optab[a1-1]
	}
	a1 = int(p.From.Class)
	if a1 == 0 {
		a1 = c.aclass(&p.From) + 1
		p.From.Class = int8(a1)
	}

	a1--
	a3 := int(p.To.Class)
	if a3 == 0 {
		a3 = c.aclass(&p.To) + 1
		p.To.Class = int8(a3)
	}

	a3--
	a2 := C_NONE
	if p.Reg != obj.REG_NONE {
		a2 = C_REG
	}

	ops := oprange[p.As&obj.AMask]
	c1 := &xcmp[a1]
	c3 := &xcmp[a3]
	for i := range ops {
		op := &ops[i]
		if int(op.a2) == a2 && c1[op.a1] && c3[op.a3] && (op.family == 0 || c.ctxt.Arch.Family == op.family) {
			p.Optab = uint16(cap(optab) - cap(ops) + i + 1)
			return op
		}
	}

	c.ctxt.Diag("illegal combination %v %v %v %v", p.As, DRconv(a1), DRconv(a2), DRconv(a3))
	prasm(p)
	// Turn illegal instruction into an UNDEF, avoid crashing in asmout.
	return &Optab{obj.AUNDEF, C_NONE, C_NONE, C_NONE, 49, 4, 0, 0, 0}
}

func cmp(a int, b int) bool {
	if a == b {
		return true
	}
	switch a {
	case C_LCON:
		if b == C_ZCON || b == C_SCON || b == C_UCON || b == C_ADDCON || b == C_ANDCON {
			return true
		}

	case C_ADD0CON:
		if b == C_ADDCON {
			return true
		}
		fallthrough

	case C_ADDCON:
		if b == C_ZCON || b == C_SCON {
			return true
		}

	case C_AND0CON:
		if b == C_ANDCON {
			return true
		}
		fallthrough

	case C_ANDCON:
		if b == C_ZCON || b == C_SCON {
			return true
		}

	case C_UCON:
		if b == C_ZCON {
			return true
		}

	case C_SCON:
		if b == C_ZCON {
			return true
		}

	case C_LACON:
		if b == C_SACON {
			return true
		}

	case C_LBRA:
		if b == C_SBRA {
			return true
		}

	case C_LEXT:
		if b == C_SEXT {
			return true
		}

	case C_LAUTO:
		if b == C_SAUTO {
			return true
		}

	case C_REG:
		if b == C_ZCON {
			return r0iszero != 0 /*TypeKind(100016)*/
		}

	case C_LOREG:
		if b == C_ZOREG || b == C_SOREG {
			return true
		}

	case C_SOREG:
		if b == C_ZOREG {
			return true
		}
	}

	return false
}

func ocmp(p1, p2 Optab) int {
	if p1.as != p2.as {
		return int(p1.as) - int(p2.as)
	}
	if p1.a1 != p2.a1 {
		return int(p1.a1) - int(p2.a1)
	}
	if p1.a2 != p2.a2 {
		return int(p1.a2) - int(p2.a2)
	}
	if p1.a3 != p2.a3 {
		return int(p1.a3) - int(p2.a3)
	}
	return 0
}

func opset(a, b0 obj.As) {
	oprange[a&obj.AMask] = oprange[b0]
}

func buildop(ctxt *obj.Link) {
	if oprange[AOR&obj.AMask] != nil {
		// Already initialized; stop now.
		// This happens in the cmd/asm tests,
		// each of which re-initializes the arch.
		return
	}

	var n int

	for i := 0; i < C_NCLASS; i++ {
		for n = 0; n < C_NCLASS; n++ {
			if cmp(n, i) {
				xcmp[i][n] = true
			}
		}
	}
	for n = 0; optab[n].as != obj.AXXX; n++ {
	}
	slices.SortFunc(optab[:n], ocmp)
	for i := 0; i < n; i++ {
		r := optab[i].as
		r0 := r & obj.AMask
		start := i
		for optab[i].as == r {
			i++
		}
		oprange[r0] = optab[start:i]
		i--

		switch r {
		default:
			ctxt.Diag("unknown op in build: %v", r)
			ctxt.DiagFlush()
			log.Fatalf("bad code")

		case AABSF:
			opset(AMOVFD, r0)
			opset(AMOVDF, r0)
			opset(AMOVWF, r0)
			opset(AMOVFW, r0)
			opset(AMOVWD, r0)
			opset(AMOVDW, r0)
			opset(ANEGF, r0)
			opset(ANEGD, r0)
			opset(AABSD, r0)
			opset(ATRUNCDW, r0)
			opset(ATRUNCFW, r0)
			opset(ASQRTF, r0)
			opset(ASQRTD, r0)

		case AMOVVF:
			opset(AMOVVD, r0)
			opset(AMOVFV, r0)
			opset(AMOVDV, r0)
			opset(ATRUNCDV, r0)
			opset(ATRUNCFV, r0)

		case AADD:
			opset(ASGT, r0)
			opset(ASGTU, r0)
			opset(AADDU, r0)

		case AADDV:
			opset(AADDVU, r0)

		case AADDF:
			opset(ADIVF, r0)
			opset(ADIVD, r0)
			opset(AMULF, r0)
			opset(AMULD, r0)
			opset(ASUBF, r0)
			opset(ASUBD, r0)
			opset(AADDD, r0)

		case AAND:
			opset(AOR, r0)
			opset(AXOR, r0)

		case ABEQ:
			opset(ABNE, r0)

		case ABLEZ:
			opset(ABGEZ, r0)
			opset(ABGEZAL, r0)
			opset(ABLTZ, r0)
			opset(ABLTZAL, r0)
			opset(ABGTZ, r0)

		case AMOVB:
			opset(AMOVH, r0)

		case AMOVBU:
			opset(AMOVHU, r0)

		case AMUL:
			opset(AREM, r0)
			opset(AREMU, r0)
			opset(ADIVU, r0)
			opset(AMULU, r0)
			opset(ADIV, r0)
			opset(AMADD, r0)
			opset(AMSUB, r0)

		case AMULV:
			opset(ADIVV, r0)
			opset(ADIVVU, r0)
			opset(AMULVU, r0)
			opset(AREMV, r0)
			opset(AREMVU, r0)

		case ASLL:
			opset(ASRL, r0)
			opset(ASRA, r0)
			opset(AROTR, r0)

		case ASLLV:
			opset(ASRAV, r0)
			opset(ASRLV, r0)
			opset(AROTRV, r0)

		case ASUB:
			opset(ASUBU, r0)
			opset(ANOR, r0)

		case ASUBV:
			opset(ASUBVU, r0)

		case ASYSCALL:
			opset(ASYNC, r0)
			opset(ANOOP, r0)
			opset(ATLBP, r0)
			opset(ATLBR, r0)
			opset(ATLBWI, r0)
			opset(ATLBWR, r0)

		case ACMPEQF:
			opset(ACMPGTF, r0)
			opset(ACMPGTD, r0)
			opset(ACMPGEF, r0)
			opset(ACMPGED, r0)
			opset(ACMPEQD, r0)

		case ABFPT:
			opset(ABFPF, r0)

		case AMOVWL:
			opset(AMOVWR, r0)

		case AMOVVL:
			opset(AMOVVR, r0)

		case AVMOVB:
			opset(AVMOVH, r0)
			opset(AVMOVW, r0)
			opset(AVMOVD, r0)

		case AMOVW,
			AMOVD,
			AMOVF,
			AMOVV,
			ABREAK,
			ARFE,
			AJAL,
			AJMP,
			AMOVWU,
			ALL,
			ALLV,
			ASC,
			ASCV,
			ANEGW,
			ANEGV,
			AWORD,
			obj.ANOP,
			obj.ATEXT,
			obj.AUNDEF,
			obj.AFUNCDATA,
			obj.APCDATA,
			obj.ADUFFZERO,
			obj.ADUFFCOPY:
			break

		case ACMOVN:
			opset(ACMOVZ, r0)

		case ACMOVT:
			opset(ACMOVF, r0)

		case ACLO:
			opset(ACLZ, r0)

		case ATEQ:
			opset(ATNE, r0)

		case AWSBH:
			opset(ASEB, r0)
			opset(ASEH, r0)

		case ADSBH:
			opset(ADSHD, r0)
		}
	}
}

func OP(x uint32, y uint32) uint32 {
	return x<<3 | y<<0
}

func SP(x uint32, y uint32) uint32 {
	return x<<29 | y<<26
}

func BCOND(x uint32, y uint32) uint32 {
	return x<<19 | y<<16
}

func MMU(x uint32, y uint32) uint32 {
	return SP(2, 0) | 16<<21 | x<<3 | y<<0
}

func FPF(x uint32, y uint32) uint32 {
	return SP(2, 1) | 16<<21 | x<<3 | y<<0
}

func FPD(x uint32, y uint32) uint32 {
	return SP(2, 1) | 17<<21 | x<<3 | y<<0
}

func FPW(x uint32, y uint32) uint32 {
	return SP(2, 1) | 20<<21 | x<<3 | y<<0
}

func FPV(x uint32, y uint32) uint32 {
	return SP(2, 1) | 21<<21 | x<<3 | y<<0
}

func OP_RRR(op uint32, r1 int16, r2 int16, r3 int16) uint32 {
	return op | uint32(r1&31)<<16 | uint32(r2&31)<<21 | uint32(r3&31)<<11
}

func OP_IRR(op uint32, i uint32, r2 int16, r3 int16) uint32 {
	return op | i&0xFFFF | uint32(r2&31)<<21 | uint32(r3&31)<<16
}

func OP_SRR(op uint32, s uint32, r2 int16, r3 int16) uint32 {
	return op | (s&31)<<6 | uint32(r2&31)<<16 | uint32(r3&31)<<11
}

func OP_FRRR(op uint32, r1 int16, r2 int16, r3 int16) uint32 {
	return op | uint32(r1&31)<<16 | uint32(r2&31)<<11 | uint32(r3&31)<<6
}

func OP_JMP(op uint32, i uint32) uint32 {
	return op | i&0x3FFFFFF
}

func OP_VI10(op uint32, df uint32, s10 int32, wd uint32, minor uint32) uint32 {
	return 0x1e<<26 | (op&7)<<23 | (df&3)<<21 | uint32(s10&0x3FF)<<11 | (wd&31)<<6 | minor&0x3F
}

func OP_VMI10(s10 int32, rs uint32, wd uint32, minor uint32, df uint32) uint32 {
	return 0x1e<<26 | uint32(s10&0x3FF)<<16 | (rs&31)<<11 | (wd&31)<<6 | (minor&15)<<2 | df&3
}

func (c *ctxt0) asmout(p *obj.Prog, o *Optab, out []uint32) {
	o1 := uint32(0)
	o2 := uint32(0)
	o3 := uint32(0)
	o4 := uint32(0)

	add := AADDU

	if c.ctxt.Arch.Family == sys.MIPS64 {
		add = AADDVU
	}
	switch o.type_ {
	default:
		c.ctxt.Diag("unknown type %d %v", o.type_)
		prasm(p)

	case 0: /* pseudo ops */
		break

	case 1: /* mov r1,r2 ==> OR r1,r0,r2 */
		a := AOR
		if p.As == AMOVW && c.ctxt.Arch.Family == sys.MIPS64 {
			// on MIPS64, most of the 32-bit instructions have unpredictable behavior,
			// but SLL is special that the result is always sign-extended to 64-bit.
			a = ASLL
		}
		o1 = OP_RRR(c.oprrr(a), p.From.Reg, REGZERO, p.To.Reg)

	case 2: /* add/sub r1,[r2],r3 */
		r := p.Reg
		if p.As == ANEGW || p.As == ANEGV {
			r = REGZERO
		}
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o1 = OP_RRR(c.oprrr(p.As), p.From.Reg, r, p.To.Reg)

	case 3: /* mov $soreg, r ==> or/add $i,o,r */
		a := add
		if o.a1 == C_ANDCON {
			a = AOR
		}
		r := p.From.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(a), uint32(v), r, p.To.Reg)

	case 4: /* add $scon,[r1],r2 */
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(p.As), uint32(v), r, p.To.Reg)

	case 5: /* syscall */
		o1 = c.oprrr(p.As)

	case 6: /* beq r1,[r2],sbra */
		v := int32(0)
		if p.To.Target() == nil {
			v = int32(-4) >> 2
		} else {
			v = int32(p.To.Target().Pc-p.Pc-4) >> 2
		}
		if (v<<16)>>16 != v {
			c.ctxt.Diag("short branch too far\n%v", p)
		}
		o1 = OP_IRR(c.opirr(p.As), uint32(v), p.From.Reg, p.Reg)
		// for ABFPT and ABFPF only: always fill delay slot with 0
		// see comments in func preprocess for details.
		o2 = 0

	case 7: /* mov r, soreg ==> sw o(r) */
		r := p.To.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.To)
		o1 = OP_IRR(c.opirr(p.As), uint32(v), r, p.From.Reg)

	case 8: /* mov soreg, r ==> lw o(r) */
		r := p.From.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(-p.As), uint32(v), r, p.To.Reg)

	case 9: /* sll r1,[r2],r3 */
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o1 = OP_RRR(c.oprrr(p.As), r, p.From.Reg, p.To.Reg)

	case 10: /* add $con,[r1],r2 ==> mov $con, t; add t,[r1],r2 */
		v := c.regoff(&p.From)
		a := AOR
		if v < 0 {
			a = AADDU
		}
		o1 = OP_IRR(c.opirr(a), uint32(v), obj.REG_NONE, REGTMP)
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o2 = OP_RRR(c.oprrr(p.As), REGTMP, r, p.To.Reg)

	case 11: /* jmp lbra */
		v := int32(0)
		if c.aclass(&p.To) == C_SBRA && p.To.Sym == nil && p.As == AJMP {
			// use PC-relative branch for short branches
			// BEQ	R0, R0, sbra
			if p.To.Target() == nil {
				v = int32(-4) >> 2
			} else {
				v = int32(p.To.Target().Pc-p.Pc-4) >> 2
			}
			if (v<<16)>>16 == v {
				o1 = OP_IRR(c.opirr(ABEQ), uint32(v), REGZERO, REGZERO)
				break
			}
		}
		if p.To.Target() == nil {
			v = int32(p.Pc) >> 2
		} else {
			v = int32(p.To.Target().Pc) >> 2
		}
		o1 = OP_JMP(c.opirr(p.As), uint32(v))
		if p.To.Sym == nil {
			p.To.Sym = c.cursym.Func().Text.From.Sym
			p.To.Offset = p.To.Target().Pc
		}
		typ := objabi.R_JMPMIPS
		if p.As == AJAL {
			typ = objabi.R_CALLMIPS
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: typ,
			Off:  int32(c.pc),
			Siz:  4,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})

	case 12: /* movbs r,r */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		v := 16
		if p.As == AMOVB {
			v = 24
		}
		o1 = OP_SRR(c.opirr(ASLL), uint32(v), p.From.Reg, p.To.Reg)
		o2 = OP_SRR(c.opirr(ASRA), uint32(v), p.To.Reg, p.To.Reg)

	case 13: /* movbu r,r */
		if p.As == AMOVBU {
			o1 = OP_IRR(c.opirr(AAND), uint32(0xff), p.From.Reg, p.To.Reg)
		} else {
			o1 = OP_IRR(c.opirr(AAND), uint32(0xffff), p.From.Reg, p.To.Reg)
		}

	case 14: /* movwu r,r */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		o1 = OP_SRR(c.opirr(-ASLLV), 0, p.From.Reg, p.To.Reg)
		o2 = OP_SRR(c.opirr(-ASRLV), 0, p.To.Reg, p.To.Reg)

	case 15: /* teq $c r,r */
		r := p.Reg
		if r == obj.REG_NONE {
			r = REGZERO
		}
		v := c.regoff(&p.From)
		/* only use 10 bits of trap code */
		o1 = OP_IRR(c.opirr(p.As), (uint32(v)&0x3FF)<<6, r, p.To.Reg)

	case 16: /* sll $c,[r1],r2 */
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		v := c.regoff(&p.From)

		/* OP_SRR will use only the low 5 bits of the shift value */
		if v >= 32 && vshift(p.As) {
			o1 = OP_SRR(c.opirr(-p.As), uint32(v-32), r, p.To.Reg)
		} else {
			o1 = OP_SRR(c.opirr(p.As), uint32(v), r, p.To.Reg)
		}

	case 17:
		o1 = OP_RRR(c.oprrr(p.As), REGZERO, p.From.Reg, p.To.Reg)

	case 18: /* jmp [r1],0(r2) */
		r := p.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		o1 = OP_RRR(c.oprrr(p.As), obj.REG_NONE, p.To.Reg, r)
		if p.As == obj.ACALL {
			c.cursym.AddRel(c.ctxt, obj.Reloc{
				Type: objabi.R_CALLIND,
				Off:  int32(c.pc),
			})
		}

	case 19: /* mov $lcon,r ==> lu+or */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32(v>>16), REGZERO, p.To.Reg)
		o2 = OP_IRR(c.opirr(AOR), uint32(v), p.To.Reg, p.To.Reg)

	case 20: /* mov lo/hi,r */
		a := OP(2, 0) /* mfhi */
		if p.From.Reg == REG_LO {
			a = OP(2, 2) /* mflo */
		}
		o1 = OP_RRR(a, REGZERO, REGZERO, p.To.Reg)

	case 21: /* mov r,lo/hi */
		a := OP(2, 1) /* mthi */
		if p.To.Reg == REG_LO {
			a = OP(2, 3) /* mtlo */
		}
		o1 = OP_RRR(a, REGZERO, p.From.Reg, REGZERO)

	case 22: /* mul r1,r2 [r3]*/
		if p.To.Reg != obj.REG_NONE {
			r := p.Reg
			if r == obj.REG_NONE {
				r = p.To.Reg
			}
			a := SP(3, 4) | 2 /* mul */
			o1 = OP_RRR(a, p.From.Reg, r, p.To.Reg)
		} else {
			o1 = OP_RRR(c.oprrr(p.As), p.From.Reg, p.Reg, REGZERO)
		}

	case 23: /* add $lcon,r1,r2 ==> lu+or+add */
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32(v>>16), REGZERO, REGTMP)
		o2 = OP_IRR(c.opirr(AOR), uint32(v), REGTMP, REGTMP)
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o3 = OP_RRR(c.oprrr(p.As), REGTMP, r, p.To.Reg)

	case 24: /* mov $ucon,r ==> lu r */
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32(v>>16), REGZERO, p.To.Reg)

	case 25: /* add/and $ucon,[r1],r2 ==> lu $con,t; add t,[r1],r2 */
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32(v>>16), REGZERO, REGTMP)
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o2 = OP_RRR(c.oprrr(p.As), REGTMP, r, p.To.Reg)

	case 26: /* mov $lsext/auto/oreg,r ==> lu+or+add */
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32(v>>16), REGZERO, REGTMP)
		o2 = OP_IRR(c.opirr(AOR), uint32(v), REGTMP, REGTMP)
		r := p.From.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		o3 = OP_RRR(c.oprrr(add), REGTMP, r, p.To.Reg)

	case 27: /* mov [sl]ext/auto/oreg,fr ==> lwc1 o(r) */
		a := -AMOVF
		if p.As == AMOVD {
			a = -AMOVD
		}
		r := p.From.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.From)
		switch o.size {
		case 12:
			o1 = OP_IRR(c.opirr(ALUI), uint32((v+1<<15)>>16), REGZERO, REGTMP)
			o2 = OP_RRR(c.oprrr(add), r, REGTMP, REGTMP)
			o3 = OP_IRR(c.opirr(a), uint32(v), REGTMP, p.To.Reg)

		case 4:
			o1 = OP_IRR(c.opirr(a), uint32(v), r, p.To.Reg)
		}

	case 28: /* mov fr,[sl]ext/auto/oreg ==> swc1 o(r) */
		a := AMOVF
		if p.As == AMOVD {
			a = AMOVD
		}
		r := p.To.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.To)
		switch o.size {
		case 12:
			o1 = OP_IRR(c.opirr(ALUI), uint32((v+1<<15)>>16), REGZERO, REGTMP)
			o2 = OP_RRR(c.oprrr(add), r, REGTMP, REGTMP)
			o3 = OP_IRR(c.opirr(a), uint32(v), REGTMP, p.From.Reg)

		case 4:
			o1 = OP_IRR(c.opirr(a), uint32(v), r, p.From.Reg)
		}

	case 30: /* movw r,fr */
		a := SP(2, 1) | (4 << 21) /* mtc1 */
		o1 = OP_RRR(a, p.From.Reg, obj.REG_NONE, p.To.Reg)

	case 31: /* movw fr,r */
		a := SP(2, 1) | (0 << 21) /* mtc1 */
		o1 = OP_RRR(a, p.To.Reg, obj.REG_NONE, p.From.Reg)

	case 32: /* fadd fr1,[fr2],fr3 */
		r := p.Reg
		if r == obj.REG_NONE {
			r = p.To.Reg
		}
		o1 = OP_FRRR(c.oprrr(p.As), p.From.Reg, r, p.To.Reg)

	case 33: /* fabs fr1, fr3 */
		o1 = OP_FRRR(c.oprrr(p.As), obj.REG_NONE, p.From.Reg, p.To.Reg)

	case 34: /* mov $con,fr ==> or/add $i,t; mov t,fr */
		a := AADDU
		if o.a1 == C_ANDCON {
			a = AOR
		}
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(a), uint32(v), obj.REG_NONE, REGTMP)
		o2 = OP_RRR(SP(2, 1)|(4<<21), REGTMP, obj.REG_NONE, p.To.Reg) /* mtc1 */

	case 35: /* mov r,lext/auto/oreg ==> sw o(REGTMP) */
		r := p.To.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.To)
		o1 = OP_IRR(c.opirr(ALUI), uint32((v+1<<15)>>16), REGZERO, REGTMP)
		o2 = OP_RRR(c.oprrr(add), r, REGTMP, REGTMP)
		o3 = OP_IRR(c.opirr(p.As), uint32(v), REGTMP, p.From.Reg)

	case 36: /* mov lext/auto/oreg,r ==> lw o(REGTMP) */
		r := p.From.Reg
		if r == obj.REG_NONE {
			r = o.param
		}
		v := c.regoff(&p.From)
		o1 = OP_IRR(c.opirr(ALUI), uint32((v+1<<15)>>16), REGZERO, REGTMP)
		o2 = OP_RRR(c.oprrr(add), r, REGTMP, REGTMP)
		o3 = OP_IRR(c.opirr(-p.As), uint32(v), REGTMP, p.To.Reg)

	case 37: /* movw r,mr */
		a := SP(2, 0) | (4 << 21) /* mtc0 */
		if p.As == AMOVV {
			a = SP(2, 0) | (5 << 21) /* dmtc0 */
		}
		o1 = OP_RRR(a, p.From.Reg, obj.REG_NONE, p.To.Reg)

	case 38: /* movw mr,r */
		a := SP(2, 0) | (0 << 21) /* mfc0 */
		if p.As == AMOVV {
			a = SP(2, 0) | (1 << 21) /* dmfc0 */
		}
		o1 = OP_RRR(a, p.To.Reg, obj.REG_NONE, p.From.Reg)

	case 40: /* word */
		o1 = uint32(c.regoff(&p.From))

	case 41: /* movw f,fcr */
		o1 = OP_RRR(SP(2, 1)|(6<<21), p.From.Reg, obj.REG_NONE, p.To.Reg) /* mtcc1 */

	case 42: /* movw fcr,r */
		o1 = OP_RRR(SP(2, 1)|(2<<21), p.To.Reg, obj.REG_NONE, p.From.Reg) /* mfcc1 */

	case 47: /* movv r,fr */
		a := SP(2, 1) | (5 << 21) /* dmtc1 */
		o1 = OP_RRR(a, p.From.Reg, obj.REG_NONE, p.To.Reg)

	case 48: /* movv fr,r */
		a := SP(2, 1) | (1 << 21) /* dmtc1 */
		o1 = OP_RRR(a, p.To.Reg, obj.REG_NONE, p.From.Reg)

	case 49: /* undef */
		o1 = 52 /* trap -- teq r0, r0 */

	/* relocation operations */
	case 50: /* mov r,addr ==> lu + add REGSB, REGTMP + sw o(REGTMP) */
		o1 = OP_IRR(c.opirr(ALUI), 0, REGZERO, REGTMP)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSU,
			Off:  int32(c.pc),
			Siz:  4,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})

		o2 = OP_IRR(c.opirr(p.As), 0, REGTMP, p.From.Reg)
		off := int32(c.pc + 4)
		if o.size == 12 {
			o3 = o2
			o2 = OP_RRR(c.oprrr(AADDVU), REGSB, REGTMP, REGTMP)
			off += 4
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPS,
			Off:  off,
			Siz:  4,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})

	case 51: /* mov addr,r ==> lu + add REGSB, REGTMP + lw o(REGTMP) */
		o1 = OP_IRR(c.opirr(ALUI), 0, REGZERO, REGTMP)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSU,
			Off:  int32(c.pc),
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

		o2 = OP_IRR(c.opirr(-p.As), 0, REGTMP, p.To.Reg)
		off := int32(c.pc + 4)
		if o.size == 12 {
			o3 = o2
			o2 = OP_RRR(c.oprrr(AADDVU), REGSB, REGTMP, REGTMP)
			off += 4
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPS,
			Off:  off,
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 52: /* mov $lext, r ==> lu + add REGSB, r + add */
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		o1 = OP_IRR(c.opirr(ALUI), 0, REGZERO, p.To.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSU,
			Off:  int32(c.pc),
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

		o2 = OP_IRR(c.opirr(add), 0, p.To.Reg, p.To.Reg)
		off := int32(c.pc + 4)
		if o.size == 12 {
			o3 = o2
			o2 = OP_RRR(c.oprrr(AADDVU), REGSB, p.To.Reg, p.To.Reg)
			off += 4
		}
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPS,
			Off:  off,
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 53: /* mov r, tlsvar ==> rdhwr + sw o(r3) */
		// clobbers R3 !
		// load thread pointer with RDHWR, R3 is used for fast kernel emulation on Linux
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		o1 = (037<<26 + 073) | (29 << 11) | (3 << 16) // rdhwr $29, r3
		o2 = OP_IRR(c.opirr(p.As), 0, REG_R3, p.From.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSTLS,
			Off:  int32(c.pc + 4),
			Siz:  4,
			Sym:  p.To.Sym,
			Add:  p.To.Offset,
		})

	case 54: /* mov tlsvar, r ==> rdhwr + lw o(r3) */
		// clobbers R3 !
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		o1 = (037<<26 + 073) | (29 << 11) | (3 << 16) // rdhwr $29, r3
		o2 = OP_IRR(c.opirr(-p.As), 0, REG_R3, p.To.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSTLS,
			Off:  int32(c.pc + 4),
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 55: /* mov $tlsvar, r ==> rdhwr + add */
		// clobbers R3 !
		// NOTE: this case does not use REGTMP. If it ever does,
		// remove the NOTUSETMP flag in optab.
		o1 = (037<<26 + 073) | (29 << 11) | (3 << 16) // rdhwr $29, r3
		o2 = OP_IRR(c.opirr(add), 0, REG_R3, p.To.Reg)
		c.cursym.AddRel(c.ctxt, obj.Reloc{
			Type: objabi.R_ADDRMIPSTLS,
			Off:  int32(c.pc + 4),
			Siz:  4,
			Sym:  p.From.Sym,
			Add:  p.From.Offset,
		})

	case 56: /* vmov{b,h,w,d} $scon, wr */

		v := c.regoff(&p.From)
		o1 = OP_VI10(110, c.twobitdf(p.As), v, uint32(p.To.Reg), 7)

	case 57: /* vld $soreg, wr */
		v := c.lsoffset(p.As, c.regoff(&p.From))
		o1 = OP_VMI10(v, uint32(p.From.Reg), uint32(p.To.Reg), 8, c.twobitdf(p.As))

	case 58: /* vst wr, $soreg */
		v := c.lsoffset(p.As, c.regoff(&p.To))
		o1 = OP_VMI10(v, uint32(p.To.Reg), uint32(p.From.Reg), 9, c.twobitdf(p.As))

	case 59:
		o1 = OP_RRR(c.oprrr(p.As), p.From.Reg, REGZERO, p.To.Reg)
	}

	out[0] = o1
	out[1] = o2
	out[2] = o3
	out[3] = o4
}

func (c *ctxt0) vregoff(a *obj.Addr) int64 {
	c.instoffset = 0
	c.aclass(a)
	return c.instoffset
}

func (c *ctxt0) regoff(a *obj.Addr) int32 {
	return int32(c.vregoff(a))
}

func (c *ctxt0) oprrr(a obj.As) uint32 {
	switch a {
	case AADD:
		return OP(4, 0)
	case AADDU:
		return OP(4, 1)
	case ASGT:
		return OP(5, 2)
	case ASGTU:
		return OP(5, 3)
	case AAND:
		return OP(4, 4)
	case AOR:
		return OP(4, 5)
	case AXOR:
		return OP(4, 6)
	case ASUB:
		return OP(4, 2)
	case ASUBU, ANEGW:
		return OP(4, 3)
	case ANOR:
		return OP(4, 7)
	case ASLL:
		return OP(0, 4)
	case ASRL:
		return OP(0, 6)
	case ASRA:
		return OP(0, 7)
	case AROTR:
		return OP(8, 6)
	case ASLLV:
		return OP(2, 4)
	case ASRLV:
		return OP(2, 6)
	case ASRAV:
		return OP(2, 7)
	case AROTRV:
		return OP(10, 6)
	case AADDV:
		return OP(5, 4)
	case AADDVU:
		return OP(5, 5)
	case ASUBV:
		return OP(5, 6)
	case ASUBVU, ANEGV:
		return OP(5, 7)
	case AREM,
		ADIV:
		return OP(3, 2)
	case AREMU,
		ADIVU:
		return OP(3, 3)
	case AMUL:
		return OP(3, 0)
	case AMULU:
		return OP(3, 1)
	case AREMV,
		ADIVV:
		return OP(3, 6)
	case AREMVU,
		ADIVVU:
		return OP(3, 7)
	case AMULV:
		return OP(3, 4)
	case AMULVU:
		return OP(3, 5)

	case AJMP:
		return OP(1, 0)
	case AJAL:
		return OP(1, 1)

	case ABREAK:
		return OP(1, 5)
	case ASYSCALL:
		return OP(1, 4)
	case ATLBP:
		return MMU(1, 0)
	case ATLBR:
		return MMU(0, 1)
	case ATLBWI:
		return MMU(0, 2)
	case ATLBWR:
		return MMU(0, 6)
	case ARFE:
		return MMU(2, 0)

	case ADIVF:
		return FPF(0, 3)
	case ADIVD:
		return FPD(0, 3)
	case AMULF:
		return FPF(0, 2)
	case AMULD:
		return FPD(0, 2)
	case ASUBF:
		return FPF(0, 1)
	case ASUBD:
		return FPD(0, 1)
	case AADDF:
		return FPF(0, 0)
	case AADDD:
		return FPD(0, 0)
	case ATRUNCFV:
		return FPF(1, 1)
	case ATRUNCDV:
		return FPD(1, 1)
	case ATRUNCFW:
		return FPF(1, 5)
	case ATRUNCDW:
		return FPD(1, 5)
	case AMOVFV:
		return FPF(4, 5)
	case AMOVDV:
		return FPD(4, 5)
	case AMOVVF:
		return FPV(4, 0)
	case AMOVVD:
		return FPV(4, 1)
	case AMOVFW:
		return FPF(4, 4)
	case AMOVDW:
		return FPD(4, 4)
	case AMOVWF:
		return FPW(4, 0)
	case AMOVDF:
		return FPD(4, 0)
	case AMOVWD:
		return FPW(4, 1)
	case AMOVFD:
		return FPF(4, 1)
	case AABSF:
		return FPF(0, 5)
	case AABSD:
		return FPD(0, 5)
	case AMOVF:
		return FPF(0, 6)
	case AMOVD:
		return FPD(0, 6)
	case ANEGF:
		return FPF(0, 7)
	case ANEGD:
		return FPD(0, 7)
	case ACMPEQF:
		return FPF(6, 2)
	case ACMPEQD:
		return FPD(6, 2)
	case ACMPGTF:
		return FPF(7, 4)
	case ACMPGTD:
		return FPD(7, 4)
	case ACMPGEF:
		return FPF(7, 6)
	case ACMPGED:
		return FPD(7, 6)

	case ASQRTF:
		return FPF(0, 4)
	case ASQRTD:
		return FPD(0, 4)

	case ASYNC:
		return OP(1, 7)
	case ANOOP:
		return 0

	case ACMOVN:
		return OP(1, 3)
	case ACMOVZ:
		return OP(1, 2)
	case ACMOVT:
		return OP(0, 1) | (1 << 16)
	case ACMOVF:
		return OP(0, 1) | (0 << 16)
	case ACLO:
		return SP(3, 4) | OP(4, 1)
	case ACLZ:
		return SP(3, 4) | OP(4, 0)
	case AMADD:
		return SP(3, 4) | OP(0, 0)
	case AMSUB:
		return SP(3, 4) | OP(0, 4)
	case AWSBH:
		return SP(3, 7) | OP(20, 0)
	case ADSBH:
		return SP(3, 7) | OP(20, 4)
	case ADSHD:
		return SP(3, 7) | OP(44, 4)
	case ASEB:
		return SP(3, 7) | OP(132, 0)
	case ASEH:
		return SP(3, 7) | OP(196, 0)
	}

	if a < 0 {
		c.ctxt.Diag("bad rrr opcode -%v", -a)
	} else {
		c.ctxt.Diag("bad rrr opcode %v", a)
	}
	return 0
}

func (c *ctxt0) opirr(a obj.As) uint32 {
	switch a {
	case AADD:
		return SP(1, 0)
	case AADDU:
		return SP(1, 1)
	case ASGT:
		return SP(1, 2)
	case ASGTU:
		return SP(1, 3)
	case AAND:
		return SP(1, 4)
	case AOR:
		return SP(1, 5)
	case AXOR:
		return SP(1, 6)
	case ALUI:
		return SP(1, 7)
	case ASLL:
		return OP(0, 0)
	case ASRL:
		return OP(0, 2)
	case ASRA:
		return OP(0, 3)
	case AROTR:
		return OP(0, 2) | 1<<21
	case AADDV:
		return SP(3, 0)
	case AADDVU:
		return SP(3, 1)

	case AJMP:
		return SP(0, 2)
	case AJAL,
		obj.ADUFFZERO,
		obj.ADUFFCOPY:
		return SP(0, 3)
	case ABEQ:
		return SP(0, 4)
	case -ABEQ:
		return SP(2, 4) /* likely */
	case ABNE:
		return SP(0, 5)
	case -ABNE:
		return SP(2, 5) /* likely */
	case ABGEZ:
		return SP(0, 1) | BCOND(0, 1)
	case -ABGEZ:
		return SP(0, 1) | BCOND(0, 3) /* likely */
	case ABGEZAL:
		return SP(0, 1) | BCOND(2, 1)
	case -ABGEZAL:
		return SP(0, 1) | BCOND(2, 3) /* likely */
	case ABGTZ:
		return SP(0, 7)
	case -ABGTZ:
		return SP(2, 7) /* likely */
	case ABLEZ:
		return SP(0, 6)
	case -ABLEZ:
		return SP(2, 6) /* likely */
	case ABLTZ:
		return SP(0, 1) | BCOND(0, 0)
	case -ABLTZ:
		return SP(0, 1) | BCOND(0, 2) /* likely */
	case ABLTZAL:
		return SP(0, 1) | BCOND(2, 0)
	case -ABLTZAL:
		return SP(0, 1) | BCOND(2, 2) /* likely */
	case ABFPT:
		return SP(2, 1) | (257 << 16)
	case -ABFPT:
		return SP(2, 1) | (259 << 16) /* likely */
	case ABFPF:
		return SP(2, 1) | (256 << 16)
	case -ABFPF:
		return SP(2, 1) | (258 << 16) /* likely */

	case AMOVB,
		AMOVBU:
		return SP(5, 0)
	case AMOVH,
		AMOVHU:
		return SP(5, 1)
	case AMOVW,
		AMOVWU:
		return SP(5, 3)
	case AMOVV:
		return SP(7, 7)
	case AMOVF:
		return SP(7, 1)
	case AMOVD:
		return SP(7, 5)
	case AMOVWL:
		return SP(5, 2)
	case AMOVWR:
		return SP(5, 6)
	case AMOVVL:
		return SP(5, 4)
	case AMOVVR:
		return SP(5, 5)

	case ABREAK:
		return SP(5, 7)

	case -AMOVWL:
		return SP(4, 2)
	case -AMOVWR:
		return SP(4, 6)
	case -AMOVVL:
		return SP(3, 2)
	case -AMOVVR:
		return SP(3, 3)
	case -AMOVB:
		return SP(4, 0)
	case -AMOVBU:
		return SP(4, 4)
	case -AMOVH:
		return SP(4, 1)
	case -AMOVHU:
		return SP(4, 5)
	case -AMOVW:
		return SP(4, 3)
	case -AMOVWU:
		return SP(4, 7)
	case -AMOVV:
		return SP(6, 7)
	case -AMOVF:
		return SP(6, 1)
	case -AMOVD:
		return SP(6, 5)

	case ASLLV:
		return OP(7, 0)
	case ASRLV:
		return OP(7, 2)
	case ASRAV:
		return OP(7, 3)
	case AROTRV:
		return OP(7, 2) | 1<<21
	case -ASLLV:
		return OP(7, 4)
	case -ASRLV:
		return OP(7, 6)
	case -ASRAV:
		return OP(7, 7)
	case -AROTRV:
		return OP(7, 6) | 1<<21

	case ATEQ:
		return OP(6, 4)
	case ATNE:
		return OP(6, 6)
	case -ALL:
		return SP(6, 0)
	case -ALLV:
		return SP(6, 4)
	case ASC:
		return SP(7, 0)
	case ASCV:
		return SP(7, 4)
	}

	if a < 0 {
		c.ctxt.Diag("bad irr opcode -%v", -a)
	} else {
		c.ctxt.Diag("bad irr opcode %v", a)
	}
	return 0
}

func vshift(a obj.As) bool {
	switch a {
	case ASLLV,
		ASRLV,
		ASRAV,
		AROTRV:
		return true
	}
	return false
}

// MSA Two-bit Data Format Field Encoding
func (c *ctxt0) twobitdf(a obj.As) uint32 {
	switch a {
	case AVMOVB:
		return 0
	case AVMOVH:
		return 1
	case AVMOVW:
		return 2
	case AVMOVD:
		return 3
	default:
		c.ctxt.Diag("unsupported data format %v", a)
	}
	return 0
}

// MSA Load/Store offset have to be multiple of size of data format
func (c *ctxt0) lsoffset(a obj.As, o int32) int32 {
	var mod int32
	switch a {
	case AVMOVB:
		mod = 1
	case AVMOVH:
		mod = 2
	case AVMOVW:
		mod = 4
	case AVMOVD:
		mod = 8
	default:
		c.ctxt.Diag("unsupported instruction:%v", a)
	}

	if o%mod != 0 {
		c.ctxt.Diag("invalid offset for %v: %d is not a multiple of %d", a, o, mod)
	}

	return o / mod
}
```