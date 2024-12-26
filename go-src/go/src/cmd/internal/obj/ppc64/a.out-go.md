Response: The user wants to understand the functionality of the Go source code located at `go/src/cmd/internal/obj/ppc64/a.out.go`. The file seems to define constants and data structures related to the PowerPC 64 architecture, specifically for the Go assembler and linker.

Here's a breakdown of how to approach the request:

1. **Identify Core Functionality:** Look for key data structures and constants that reveal the purpose of the file. The presence of register definitions, instruction opcodes, and DWARF register mappings strongly suggests this file is about architecture-specific details for code generation.

2. **Infer Go Feature Implementation:** Connect the identified functionalities to the broader Go compilation and linking process. The file likely plays a crucial role in translating Go code into machine code for the PPC64 architecture.

3. **Provide Go Code Examples:**  Illustrate how these definitions might be used in practice. Since this file is part of the internal compiler toolchain, direct user-level Go code examples might be limited. However, demonstrating the *concept* of register usage and assembly generation is possible.

4. **Handle Code Inference:** When making inferences, clearly state the assumptions. For example, assuming the constants define registers and opcodes is a reasonable starting point.

5. **Explain Command-Line Arguments (If Applicable):** Scan the code for any command-line flag parsing or processing. In this case, the code snippet itself doesn't seem to directly handle command-line arguments. The `//go:generate` directive hints at code generation, but not direct command-line parsing within this file.

6. **Identify Common Mistakes:** Consider potential pitfalls users might encounter when working with architecture-specific details. Incorrect register usage or misunderstanding assembly instructions are common areas for errors.

**Pre-computation/Pre-analysis:**

* **Copyright Notice:** Acknowledge the historical context and licensing.
* **Package Declaration:** Note the `ppc64` package name, indicating its specific focus.
* **Import Statement:**  Recognize the dependency on `cmd/internal/obj`, suggesting it's part of the Go object file manipulation tools.
* **`//go:generate` Directive:** Understand that this line triggers the `stringer` tool to generate code for converting constants to strings.
* **Constant Definitions:**  Categorize the constants:
    * **Basic Architecture Limits:** `NSNAME`, `NSYM`, `NREG`, `NFREG`.
    * **Register Definitions:** `REG_R0` through `REG_VS63`, `REG_CR0` through `REG_CR7`, etc. Notice the naming conventions and the use of `iota`.
    * **Special Purpose Registers:** `REG_MSR`, `REG_FPSCR`, `REG_CR`, `REG_XER`, `REG_LR`, `REG_CTR`.
    * **Register Aliases:** `REGZERO`, `REGSP`, `REGSB`, etc. These provide semantic meaning to specific registers.
    * **DWARF Register Mappings:** The `PPC64DWARFRegisters` map is crucial for debugging and stack unwinding.
* **Flag Constants:** `LABEL`, `LEAF`, `FLOAT`, etc., are likely used to mark properties of instructions or code blocks.
* **Branch Instruction Constants:** `BI_CR0` through `BI_FU`, `BO_ALWAYS` through `BO_NOTBCR`.
* **Condition Code Constants:** `C_COND_LT`, `C_COND_GT`, `C_COND_EQ`, `C_COND_SO`.
* **Operand Class Constants:** `C_NONE` through `C_TEXTSIZE`. These define the types of operands instructions can take.
* **Instruction Opcodes:** `AADD`, `AAND`, `ABC`, etc. The `obj.ABasePPC64` and `obj.A_ARCHSPECIFIC` suggest these are architecture-specific opcodes building upon a base set.

By carefully examining these elements, the core functionality and likely purpose of the file become clear.
这是路径为 `go/src/cmd/internal/obj/ppc64/a.out.go` 的 Go 语言实现的一部分，它定义了 PowerPC 64 位架构（ppc64）的汇编器和链接器所使用的常量、数据结构以及初始化代码。

**功能列表:**

1. **定义了 PowerPC 64 位架构的常量:**
   - `NSNAME`, `NSYM`, `NREG`, `NFREG`: 定义了符号名称长度、符号数量、通用寄存器数量和浮点寄存器数量等基本架构参数。
2. **定义了通用寄存器 (General Purpose Registers) 的编号:**
   - `REG_R0` 到 `REG_R31`:  枚举了 32 个通用寄存器的常量，并基于 `obj.RBasePPC64` 进行偏移。
3. **定义了条件寄存器 (Condition Register) 位的编号:**
   - `REG_CR0LT` 到 `REG_CR7SO`: 枚举了条件寄存器中各个位的常量，用于分支指令的判断。
4. **定义了浮点寄存器 (Floating Point Registers) 的编号:**
   - `REG_F0` 到 `REG_F31`: 枚举了 32 个浮点寄存器的常量。
5. **定义了向量寄存器 (Vector Registers) 的编号:**
   - `REG_V0` 到 `REG_V31`: 枚举了 32 个向量寄存器的常量。
6. **定义了向量标量寄存器 (Vector Scalar Registers, VSX) 的编号:**
   - `REG_VS0` 到 `REG_VS63`: 枚举了 64 个向量标量寄存器的常量，并说明了它们与浮点寄存器和向量寄存器的重叠关系。
7. **定义了条件寄存器 (Condition Register) 的编号:**
   - `REG_CR0` 到 `REG_CR7`: 枚举了 8 个条件寄存器的常量。
8. **定义了 MMA (Matrix-Multiply Accumulator) 累加寄存器的编号:**
   - `REG_A0` 到 `REG_A7`: 枚举了 MMA 累加寄存器的常量，并说明了它们与向量标量寄存器的关联。
9. **定义了特殊寄存器 (Special Purpose Registers) 的编号:**
   - `REG_MSR`, `REG_FPSCR`, `REG_CR`, `REG_XER`, `REG_LR`, `REG_CTR`: 定义了机器状态寄存器、浮点状态和控制寄存器、条件寄存器、定点异常寄存器、链接寄存器和计数寄存器的常量。
10. **定义了特殊的通用寄存器别名:**
    - `REGZERO`, `REGSP`, `REGSB`, `REGRET`, `REGARG`, `REGRT1`, `REGRT2`, `REGMIN`, `REGCTXT`, `REGTLS`, `REGMAX`, `REGEXT`, `REGG`, `REGTMP`:  为一些常用的通用寄存器赋予了更具语义的别名，方便编译器和汇编器使用。
11. **定义了特殊的浮点寄存器别名:**
    - `FREGRET`, `FREGMIN`, `FREGMAX`, `FREGEXT`: 为一些常用的浮点寄存器赋予了别名。
12. **定义了 DWARF 调试信息的寄存器映射:**
    - `PPC64DWARFRegisters`:  一个 `map[int16]int16`，用于将内部寄存器编号映射到 DWARF 标准中定义的寄存器编号，方便调试器进行调试。
13. **定义了指令标记 (Mark Flags):**
    - `LABEL`, `LEAF`, `FLOAT`, `BRANCH` 等常量用于标记指令的特性，供编译器和汇编器使用。
14. **定义了分支指令 `BC` 的操作数常量:**
    - `BI_CR0` 到 `BI_FU`: 定义了 `BC` 指令中用于指定条件寄存器位和分支类型的常量。
    - `BO_ALWAYS` 到 `BO_NOTBCR`: 定义了 `BC` 指令中用于指定分支条件的常量。
15. **定义了条件码 (Condition Code) 的位设置:**
    - `C_COND_LT`, `C_COND_GT`, `C_COND_EQ`, `C_COND_SO`: 定义了条件寄存器中各位的含义。
16. **定义了操作数类型常量 (Operand Class Constants):**
    - `C_NONE` 到 `C_TEXTSIZE`:  定义了各种操作数的类型，例如寄存器、常量、内存地址等，用于指令的匹配和编码。
17. **定义了 PowerPC 64 位架构的指令操作码 (Opcodes):**
    - `AADD`, `AAND`, `ABC`, ..., `ALASTAOUT`: 定义了 ppc64 架构的各种指令的操作码常量，例如加法、逻辑运算、分支、数据移动等。 这些常量基于 `obj.ABasePPC64` 和 `obj.A_ARCHSPECIFIC` 进行偏移。
18. **定义了指令操作码的别名:**
    - `ABR` (branch) 是 `obj.AJMP` 的别名， `ABL` (branch and link) 是 `obj.ACALL` 的别名。
19. **初始化 DWARF 寄存器映射:**
    - `init()` 函数初始化了 `PPC64DWARFRegisters` 映射，将内部的寄存器编号映射到 DWARF 标准的编号。

**推理：这是 Go 语言编译器中 PowerPC 64 位架构的后端实现的关键部分。**

该文件为 Go 编译器（例如 `gc`）和链接器（例如 `link`) 提供了关于 ppc64 架构的底层细节信息。编译器在将 Go 代码翻译成汇编代码时，会使用这些常量来生成正确的指令和操作数。链接器在将多个目标文件链接成可执行文件时，也会使用这些信息进行符号解析和重定位。

**Go 代码举例说明 (概念性):**

虽然这个文件本身不包含直接被用户 Go 代码调用的函数，但可以理解为 Go 编译器在背后使用这些定义来处理针对 ppc64 架构的代码。

假设我们有以下简单的 Go 代码：

```go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	result := add(5, 10)
	println(result)
}
```

Go 编译器在将这段代码编译为 ppc64 汇编代码时，可能会使用 `a.out.go` 中定义的常量，例如：

```assembly
// 假设的 ppc64 汇编代码 (简化)
MOVD R3, 5  // 将常量 5 移动到寄存器 R3 (可能对应 REGRET)
MOVD R4, 10 // 将常量 10 移动到寄存器 R4 (可能对应 REGARG 的下一个)
ADD  R3, R4, R5 // 将 R3 和 R4 的值相加，结果存入 R5 (使用 AADD 操作码)
MOVD R5, R3  // 将 R5 的值移动到返回寄存器 (可能对应 REGRET)
BL   runtime.println // 调用 println 函数 (使用 ABL 操作码)
```

在这个例子中，`MOVD` 和 `ADD` 对应了 `a.out.go` 中定义的指令操作码常量（尽管实际的指令名称可能有所不同），而 `R3`、`R4`、`R5` 则对应了定义的通用寄存器常量。

**代码推理与假设的输入与输出:**

`a.out.go` 中的大部分代码是常量定义，并没有直接的逻辑处理需要输入和输出。 `init()` 函数的功能是初始化 `PPC64DWARFRegisters`。

**假设的 `init()` 函数执行:**

* **输入:**  程序启动，执行 `init()` 函数。
* **处理:**  `init()` 函数调用 `f` 函数多次，使用不同的寄存器范围和基址，将内部寄存器编号映射到 DWARF 寄存器编号，并将这些映射关系存储到 `PPC64DWARFRegisters` map 中。
* **输出:** `PPC64DWARFRegisters` map 被填充，例如 `PPC64DWARFRegisters[REG_R0]` 的值将是 `0`，`PPC64DWARFRegisters[REG_F0]` 的值将是 `32`，等等。

**命令行参数的具体处理:**

`a.out.go` 文件本身**不直接处理命令行参数**。它主要提供常量定义和初始化逻辑。命令行参数的处理通常发生在 Go 编译器的其他部分，例如 `cmd/compile/internal/gc` 包。

**使用者易犯错的点:**

由于 `a.out.go` 是 Go 编译器内部使用的文件，普通 Go 开发者**不会直接与其交互，因此不容易犯错**。

然而，对于**Go 编译器或汇编器的开发者**来说，以下是一些可能犯错的点：

1. **错误地使用寄存器常量:**  在编写汇编代码生成逻辑时，可能会错误地使用寄存器常量，导致生成错误的指令。例如，错误地将一个操作数放入了错误的寄存器。
   ```go
   // 错误的假设：将源操作数放在目标寄存器
   // 假设要生成 "MOVD R3, R4" (将 R4 的值移动到 R3)
   // 错误的代码可能尝试直接使用 REG_R4 作为目标
   // ... 生成指令时使用了错误的目标寄存器 ...
   ```

2. **错误地使用指令操作码:**  可能会错误地选择了指令操作码，导致生成了错误的指令。例如，本来应该使用加法指令，却使用了减法指令。
   ```go
   // 错误的假设：使用减法指令代替加法
   // 假设要生成 "ADD R3, R4, R5"
   // 错误的代码可能使用了 ASUB (减法) 操作码
   // ... 生成指令时使用了错误的 ASUB 操作码 ...
   ```

3. **误解操作数类型:**  可能会错误地理解了指令支持的操作数类型，导致生成了无效的指令。例如，尝试将一个立即数直接赋值给一个不支持立即数操作的寄存器。
   ```go
   // 错误的假设：直接将一个大立即数赋值给寄存器
   // 假设要生成 "MOVD R3, 0xFFFFFFFFFFFFFFFF"
   // 如果 MOVD 指令不支持 64 位立即数，则会出错
   ```

总而言之，`go/src/cmd/internal/obj/ppc64/a.out.go` 是 Go 语言工具链中关于 PowerPC 64 位架构的重要基础，它为编译和链接过程提供了必要的架构信息。普通 Go 开发者无需直接关注此文件，但理解其作用有助于更深入地了解 Go 的底层实现。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/ppc64/a.out.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// cmd/9c/9.out.h from Vita Nuova.
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

package ppc64

import "cmd/internal/obj"

//go:generate go run ../stringer.go -i $GOFILE -o anames.go -p ppc64

/*
 * powerpc 64
 */
const (
	NSNAME = 8
	NSYM   = 50
	NREG   = 32 /* number of general registers */
	NFREG  = 32 /* number of floating point registers */
)

const (
	/* RBasePPC64 = 4096 */
	/* R0=4096 ... R31=4127 */
	REG_R0 = obj.RBasePPC64 + iota
	REG_R1
	REG_R2
	REG_R3
	REG_R4
	REG_R5
	REG_R6
	REG_R7
	REG_R8
	REG_R9
	REG_R10
	REG_R11
	REG_R12
	REG_R13
	REG_R14
	REG_R15
	REG_R16
	REG_R17
	REG_R18
	REG_R19
	REG_R20
	REG_R21
	REG_R22
	REG_R23
	REG_R24
	REG_R25
	REG_R26
	REG_R27
	REG_R28
	REG_R29
	REG_R30
	REG_R31

	// CR bits. Use Book 1, chapter 2 naming for bits. Keep aligned to 32
	REG_CR0LT
	REG_CR0GT
	REG_CR0EQ
	REG_CR0SO
	REG_CR1LT
	REG_CR1GT
	REG_CR1EQ
	REG_CR1SO
	REG_CR2LT
	REG_CR2GT
	REG_CR2EQ
	REG_CR2SO
	REG_CR3LT
	REG_CR3GT
	REG_CR3EQ
	REG_CR3SO
	REG_CR4LT
	REG_CR4GT
	REG_CR4EQ
	REG_CR4SO
	REG_CR5LT
	REG_CR5GT
	REG_CR5EQ
	REG_CR5SO
	REG_CR6LT
	REG_CR6GT
	REG_CR6EQ
	REG_CR6SO
	REG_CR7LT
	REG_CR7GT
	REG_CR7EQ
	REG_CR7SO

	/* Align FPR and VSR vectors such that when masked with 0x3F they produce
	   an equivalent VSX register. */
	/* F0=4160 ... F31=4191 */
	REG_F0
	REG_F1
	REG_F2
	REG_F3
	REG_F4
	REG_F5
	REG_F6
	REG_F7
	REG_F8
	REG_F9
	REG_F10
	REG_F11
	REG_F12
	REG_F13
	REG_F14
	REG_F15
	REG_F16
	REG_F17
	REG_F18
	REG_F19
	REG_F20
	REG_F21
	REG_F22
	REG_F23
	REG_F24
	REG_F25
	REG_F26
	REG_F27
	REG_F28
	REG_F29
	REG_F30
	REG_F31

	/* V0=4192 ... V31=4223 */
	REG_V0
	REG_V1
	REG_V2
	REG_V3
	REG_V4
	REG_V5
	REG_V6
	REG_V7
	REG_V8
	REG_V9
	REG_V10
	REG_V11
	REG_V12
	REG_V13
	REG_V14
	REG_V15
	REG_V16
	REG_V17
	REG_V18
	REG_V19
	REG_V20
	REG_V21
	REG_V22
	REG_V23
	REG_V24
	REG_V25
	REG_V26
	REG_V27
	REG_V28
	REG_V29
	REG_V30
	REG_V31

	/* VS0=4224 ... VS63=4287 */
	REG_VS0
	REG_VS1
	REG_VS2
	REG_VS3
	REG_VS4
	REG_VS5
	REG_VS6
	REG_VS7
	REG_VS8
	REG_VS9
	REG_VS10
	REG_VS11
	REG_VS12
	REG_VS13
	REG_VS14
	REG_VS15
	REG_VS16
	REG_VS17
	REG_VS18
	REG_VS19
	REG_VS20
	REG_VS21
	REG_VS22
	REG_VS23
	REG_VS24
	REG_VS25
	REG_VS26
	REG_VS27
	REG_VS28
	REG_VS29
	REG_VS30
	REG_VS31
	REG_VS32
	REG_VS33
	REG_VS34
	REG_VS35
	REG_VS36
	REG_VS37
	REG_VS38
	REG_VS39
	REG_VS40
	REG_VS41
	REG_VS42
	REG_VS43
	REG_VS44
	REG_VS45
	REG_VS46
	REG_VS47
	REG_VS48
	REG_VS49
	REG_VS50
	REG_VS51
	REG_VS52
	REG_VS53
	REG_VS54
	REG_VS55
	REG_VS56
	REG_VS57
	REG_VS58
	REG_VS59
	REG_VS60
	REG_VS61
	REG_VS62
	REG_VS63

	REG_CR0
	REG_CR1
	REG_CR2
	REG_CR3
	REG_CR4
	REG_CR5
	REG_CR6
	REG_CR7

	// MMA accumulator registers, these shadow VSR 0-31
	// e.g MMAx shadows VSRx*4-VSRx*4+3 or
	//     MMA0 shadows VSR0-VSR3
	REG_A0
	REG_A1
	REG_A2
	REG_A3
	REG_A4
	REG_A5
	REG_A6
	REG_A7

	REG_MSR
	REG_FPSCR
	REG_CR

	REG_SPECIAL = REG_CR0

	REG_CRBIT0 = REG_CR0LT // An alias for a Condition Register bit 0

	REG_SPR0 = obj.RBasePPC64 + 1024 // first of 1024 registers

	REG_XER = REG_SPR0 + 1
	REG_LR  = REG_SPR0 + 8
	REG_CTR = REG_SPR0 + 9

	REGZERO = REG_R0 /* set to zero */
	REGSP   = REG_R1
	REGSB   = REG_R2
	REGRET  = REG_R3
	REGARG  = -1      /* -1 disables passing the first argument in register */
	REGRT1  = REG_R20 /* reserved for runtime, duffzero and duffcopy */
	REGRT2  = REG_R21 /* reserved for runtime, duffcopy */
	REGMIN  = REG_R7  /* register variables allocated from here to REGMAX */
	REGCTXT = REG_R11 /* context for closures */
	REGTLS  = REG_R13 /* C ABI TLS base pointer */
	REGMAX  = REG_R27
	REGEXT  = REG_R30 /* external registers allocated from here down */
	REGG    = REG_R30 /* G */
	REGTMP  = REG_R31 /* used by the linker */
	FREGRET = REG_F0
	FREGMIN = REG_F17 /* first register variable */
	FREGMAX = REG_F26 /* last register variable for 9g only */
	FREGEXT = REG_F26 /* first external register */
)

// OpenPOWER ABI for Linux Supplement Power Architecture 64-Bit ELF V2 ABI
// https://openpowerfoundation.org/?resource_lib=64-bit-elf-v2-abi-specification-power-architecture
var PPC64DWARFRegisters = map[int16]int16{}

func init() {
	// f assigns dwarfregister[from:to] = (base):(to-from+base)
	f := func(from, to, base int16) {
		for r := int16(from); r <= to; r++ {
			PPC64DWARFRegisters[r] = r - from + base
		}
	}
	f(REG_R0, REG_R31, 0)
	f(REG_F0, REG_F31, 32)
	f(REG_V0, REG_V31, 77)
	f(REG_CR0, REG_CR7, 68)

	f(REG_VS0, REG_VS31, 32)  // overlaps F0-F31
	f(REG_VS32, REG_VS63, 77) // overlaps V0-V31
	PPC64DWARFRegisters[REG_LR] = 65
	PPC64DWARFRegisters[REG_CTR] = 66
	PPC64DWARFRegisters[REG_XER] = 76
}

/*
 * GENERAL:
 *
 * compiler allocates R3 up as temps
 * compiler allocates register variables R7-R27
 * compiler allocates external registers R30 down
 *
 * compiler allocates register variables F17-F26
 * compiler allocates external registers F26 down
 */
const (
	BIG = 32768 - 8
)

const (
	/* mark flags */
	LABEL    = 1 << 0
	LEAF     = 1 << 1
	FLOAT    = 1 << 2
	BRANCH   = 1 << 3
	LOAD     = 1 << 4
	FCMP     = 1 << 5
	SYNC     = 1 << 6
	LIST     = 1 << 7
	FOLL     = 1 << 8
	NOSCHED  = 1 << 9
	PFX_X64B = 1 << 10 // A prefixed instruction crossing a 64B boundary
)

// Values for use in branch instruction BC
// BC B0,BI,label
// BO is type of branch + likely bits described below
// BI is CR value + branch type
// ex: BEQ CR2,label is BC 12,10,label
//   12 = BO_BCR
//   10 = BI_CR2 + BI_EQ

const (
	BI_CR0 = 0
	BI_CR1 = 4
	BI_CR2 = 8
	BI_CR3 = 12
	BI_CR4 = 16
	BI_CR5 = 20
	BI_CR6 = 24
	BI_CR7 = 28
	BI_LT  = 0
	BI_GT  = 1
	BI_EQ  = 2
	BI_FU  = 3
)

// Common values for the BO field.

const (
	BO_ALWAYS  = 20 // branch unconditionally
	BO_BCTR    = 16 // decrement ctr, branch on ctr != 0
	BO_NOTBCTR = 18 // decrement ctr, branch on ctr == 0
	BO_BCR     = 12 // branch on cr value
	BO_BCRBCTR = 8  // decrement ctr, branch on ctr != 0 and cr value
	BO_NOTBCR  = 4  // branch on not cr value
)

// Bit settings from the CR

const (
	C_COND_LT = iota // 0 result is negative
	C_COND_GT        // 1 result is positive
	C_COND_EQ        // 2 result is zero
	C_COND_SO        // 3 summary overflow or FP compare w/ NaN
)

//go:generate go run ../mkcnames.go -i a.out.go -o anames9.go -p ppc64
const (
	C_NONE     = iota
	C_REGP     /* An even numbered gpr which can be used a gpr pair argument */
	C_REG      /* Any gpr register */
	C_FREGP    /* An even numbered fpr which can be used a fpr pair argument */
	C_FREG     /* Any fpr register */
	C_VREG     /* Any vector register */
	C_VSREGP   /* An even numbered vsx register which can be used as a vsx register pair argument */
	C_VSREG    /* Any vector-scalar register */
	C_CREG     /* The condition registor (CR) */
	C_CRBIT    /* A single bit of the CR register (0-31) */
	C_SPR      /* special processor register */
	C_AREG     /* MMA accumulator register */
	C_ZCON     /* The constant zero */
	C_U1CON    /* 1 bit unsigned constant */
	C_U2CON    /* 2 bit unsigned constant */
	C_U3CON    /* 3 bit unsigned constant */
	C_U4CON    /* 4 bit unsigned constant */
	C_U5CON    /* 5 bit unsigned constant */
	C_U8CON    /* 8 bit unsigned constant */
	C_U15CON   /* 15 bit unsigned constant */
	C_S16CON   /* 16 bit signed constant */
	C_U16CON   /* 16 bit unsigned constant */
	C_16CON    /* Any constant which fits into 16 bits. Can be signed or unsigned */
	C_U31CON   /* 31 bit unsigned constant */
	C_S32CON   /* 32 bit signed constant */
	C_U32CON   /* 32 bit unsigned constant */
	C_32CON    /* Any constant which fits into 32 bits. Can be signed or unsigned */
	C_S34CON   /* 34 bit signed constant */
	C_64CON    /* Any constant which fits into 64 bits. Can be signed or unsigned */
	C_SACON    /* $n(REG) where n <= int16 */
	C_LACON    /* $n(REG) where n <= int32 */
	C_DACON    /* $n(REG) where n <= int64 */
	C_BRA      /* A short offset argument to a branching instruction */
	C_BRAPIC   /* Like C_BRA, but requires an extra NOP for potential TOC restore by the linker. */
	C_ZOREG    /* An $0+reg memory op */
	C_SOREG    /* An $n+reg memory arg where n is a 16 bit signed offset */
	C_LOREG    /* An $n+reg memory arg where n is a 32 bit signed offset */
	C_XOREG    /* An reg+reg memory arg */
	C_FPSCR    /* The fpscr register */
	C_LR       /* The link register */
	C_CTR      /* The count register */
	C_ANY      /* Any argument */
	C_GOK      /* A non-matched argument */
	C_ADDR     /* A symbolic memory location */
	C_TLS_LE   /* A thread local, local-exec, type memory arg */
	C_TLS_IE   /* A thread local, initial-exec, type memory arg */
	C_TEXTSIZE /* An argument with Type obj.TYPE_TEXTSIZE */

	C_NCLASS /* must be the last */
)

const (
	AADD = obj.ABasePPC64 + obj.A_ARCHSPECIFIC + iota
	AADDCC
	AADDIS
	AADDV
	AADDVCC
	AADDC
	AADDCCC
	AADDCV
	AADDCVCC
	AADDME
	AADDMECC
	AADDMEVCC
	AADDMEV
	AADDE
	AADDECC
	AADDEVCC
	AADDEV
	AADDZE
	AADDZECC
	AADDZEVCC
	AADDZEV
	AADDEX
	AAND
	AANDCC
	AANDN
	AANDNCC
	AANDISCC
	ABC
	ABCL
	ABEQ
	ABGE // not LT = G/E/U
	ABGT
	ABLE // not GT = L/E/U
	ABLT
	ABNE  // not EQ = L/G/U
	ABVC  // Branch if float not unordered (also branch on not summary overflow)
	ABVS  // Branch if float unordered (also branch on summary overflow)
	ABDNZ // Decrement CTR, and branch if CTR != 0
	ABDZ  // Decrement CTR, and branch if CTR == 0
	ACMP
	ACMPU
	ACMPEQB
	ACNTLZW
	ACNTLZWCC
	ACRAND
	ACRANDN
	ACREQV
	ACRNAND
	ACRNOR
	ACROR
	ACRORN
	ACRXOR
	ADADD
	ADADDQ
	ADCMPO
	ADCMPOQ
	ADCMPU
	ADCMPUQ
	ADDIV
	ADDIVQ
	ADIVW
	ADIVWCC
	ADIVWVCC
	ADIVWV
	ADIVWU
	ADIVWUCC
	ADIVWUVCC
	ADIVWUV
	ADMUL
	ADMULQ
	ADSUB
	ADSUBQ
	AMODUD
	AMODUW
	AMODSD
	AMODSW
	AEQV
	AEQVCC
	AEXTSB
	AEXTSBCC
	AEXTSH
	AEXTSHCC
	AFABS
	AFABSCC
	AFADD
	AFADDCC
	AFADDS
	AFADDSCC
	AFCMPO
	AFCMPU
	AFCTIW
	AFCTIWCC
	AFCTIWZ
	AFCTIWZCC
	AFDIV
	AFDIVCC
	AFDIVS
	AFDIVSCC
	AFMADD
	AFMADDCC
	AFMADDS
	AFMADDSCC
	AFMOVD
	AFMOVDCC
	AFMOVDU
	AFMOVS
	AFMOVSU
	AFMOVSX
	AFMOVSZ
	AFMSUB
	AFMSUBCC
	AFMSUBS
	AFMSUBSCC
	AFMUL
	AFMULCC
	AFMULS
	AFMULSCC
	AFNABS
	AFNABSCC
	AFNEG
	AFNEGCC
	AFNMADD
	AFNMADDCC
	AFNMADDS
	AFNMADDSCC
	AFNMSUB
	AFNMSUBCC
	AFNMSUBS
	AFNMSUBSCC
	AFRSP
	AFRSPCC
	AFSUB
	AFSUBCC
	AFSUBS
	AFSUBSCC
	AISEL
	AMOVMW
	ALBAR
	ALHAR
	ALSW
	ALWAR
	ALWSYNC
	AMOVDBR
	AMOVWBR
	AMOVB
	AMOVBU
	AMOVBZ
	AMOVBZU
	AMOVH
	AMOVHBR
	AMOVHU
	AMOVHZ
	AMOVHZU
	AMOVW
	AMOVWU
	AMOVFL
	AMOVCRFS
	AMTFSB0
	AMTFSB0CC
	AMTFSB1
	AMTFSB1CC
	AMULHW
	AMULHWCC
	AMULHWU
	AMULHWUCC
	AMULLW
	AMULLWCC
	AMULLWVCC
	AMULLWV
	ANAND
	ANANDCC
	ANEG
	ANEGCC
	ANEGVCC
	ANEGV
	ANOR
	ANORCC
	AOR
	AORCC
	AORN
	AORNCC
	AORIS
	AREM
	AREMU
	ARFI
	ARLWMI
	ARLWMICC
	ARLWNM
	ARLWNMCC
	ACLRLSLWI
	ASLW
	ASLWCC
	ASRW
	ASRAW
	ASRAWCC
	ASRWCC
	ASTBCCC
	ASTHCCC
	ASTSW
	ASTWCCC
	ASUB
	ASUBCC
	ASUBVCC
	ASUBC
	ASUBCCC
	ASUBCV
	ASUBCVCC
	ASUBME
	ASUBMECC
	ASUBMEVCC
	ASUBMEV
	ASUBV
	ASUBE
	ASUBECC
	ASUBEV
	ASUBEVCC
	ASUBZE
	ASUBZECC
	ASUBZEVCC
	ASUBZEV
	ASYNC
	AXOR
	AXORCC
	AXORIS

	ADCBF
	ADCBI
	ADCBST
	ADCBT
	ADCBTST
	ADCBZ
	AEIEIO
	AICBI
	AISYNC
	APTESYNC
	ATLBIE
	ATLBIEL
	ATLBSYNC
	ATW

	ASYSCALL
	AWORD

	ARFCI

	AFCPSGN
	AFCPSGNCC
	/* optional on 32-bit */
	AFRES
	AFRESCC
	AFRIM
	AFRIMCC
	AFRIP
	AFRIPCC
	AFRIZ
	AFRIZCC
	AFRIN
	AFRINCC
	AFRSQRTE
	AFRSQRTECC
	AFSEL
	AFSELCC
	AFSQRT
	AFSQRTCC
	AFSQRTS
	AFSQRTSCC

	/* 64-bit */

	ACNTLZD
	ACNTLZDCC
	ACMPW /* CMP with L=0 */
	ACMPWU
	ACMPB
	AFTDIV
	AFTSQRT
	ADIVD
	ADIVDCC
	ADIVDE
	ADIVDECC
	ADIVDEU
	ADIVDEUCC
	ADIVDVCC
	ADIVDV
	ADIVDU
	ADIVDUCC
	ADIVDUVCC
	ADIVDUV
	AEXTSW
	AEXTSWCC
	/* AFCFIW; AFCFIWCC */
	AFCFID
	AFCFIDCC
	AFCFIDU
	AFCFIDUCC
	AFCFIDS
	AFCFIDSCC
	AFCTID
	AFCTIDCC
	AFCTIDZ
	AFCTIDZCC
	ALDAR
	AMOVD
	AMOVDU
	AMOVWZ
	AMOVWZU
	AMULHD
	AMULHDCC
	AMULHDU
	AMULHDUCC
	AMULLD
	AMULLDCC
	AMULLDVCC
	AMULLDV
	ARFID
	ARLDMI
	ARLDMICC
	ARLDIMI
	ARLDIMICC
	ARLDC
	ARLDCCC
	ARLDCR
	ARLDCRCC
	ARLDICR
	ARLDICRCC
	ARLDCL
	ARLDCLCC
	ARLDICL
	ARLDICLCC
	ARLDIC
	ARLDICCC
	ACLRLSLDI
	AROTL
	AROTLW
	ASLBIA
	ASLBIE
	ASLBMFEE
	ASLBMFEV
	ASLBMTE
	ASLD
	ASLDCC
	ASRD
	ASRAD
	ASRADCC
	ASRDCC
	AEXTSWSLI
	AEXTSWSLICC
	ASTDCCC
	ATD
	ASETB

	/* 64-bit pseudo operation */
	ADWORD
	AREMD
	AREMDU

	/* more 64-bit operations */
	AHRFID
	APOPCNTD
	APOPCNTW
	APOPCNTB
	ACNTTZW
	ACNTTZWCC
	ACNTTZD
	ACNTTZDCC
	ACOPY
	APASTECC
	ADARN
	AMADDHD
	AMADDHDU
	AMADDLD

	/* Vector */
	ALVEBX
	ALVEHX
	ALVEWX
	ALVX
	ALVXL
	ALVSL
	ALVSR
	ASTVEBX
	ASTVEHX
	ASTVEWX
	ASTVX
	ASTVXL
	AVAND
	AVANDC
	AVNAND
	AVOR
	AVORC
	AVNOR
	AVXOR
	AVEQV
	AVADDUM
	AVADDUBM
	AVADDUHM
	AVADDUWM
	AVADDUDM
	AVADDUQM
	AVADDCU
	AVADDCUQ
	AVADDCUW
	AVADDUS
	AVADDUBS
	AVADDUHS
	AVADDUWS
	AVADDSS
	AVADDSBS
	AVADDSHS
	AVADDSWS
	AVADDE
	AVADDEUQM
	AVADDECUQ
	AVSUBUM
	AVSUBUBM
	AVSUBUHM
	AVSUBUWM
	AVSUBUDM
	AVSUBUQM
	AVSUBCU
	AVSUBCUQ
	AVSUBCUW
	AVSUBUS
	AVSUBUBS
	AVSUBUHS
	AVSUBUWS
	AVSUBSS
	AVSUBSBS
	AVSUBSHS
	AVSUBSWS
	AVSUBE
	AVSUBEUQM
	AVSUBECUQ
	AVMULESB
	AVMULOSB
	AVMULEUB
	AVMULOUB
	AVMULESH
	AVMULOSH
	AVMULEUH
	AVMULOUH
	AVMULESW
	AVMULOSW
	AVMULEUW
	AVMULOUW
	AVMULUWM
	AVPMSUM
	AVPMSUMB
	AVPMSUMH
	AVPMSUMW
	AVPMSUMD
	AVMSUMUDM
	AVR
	AVRLB
	AVRLH
	AVRLW
	AVRLD
	AVS
	AVSLB
	AVSLH
	AVSLW
	AVSL
	AVSLO
	AVSRB
	AVSRH
	AVSRW
	AVSR
	AVSRO
	AVSLD
	AVSRD
	AVSA
	AVSRAB
	AVSRAH
	AVSRAW
	AVSRAD
	AVSOI
	AVSLDOI
	AVCLZ
	AVCLZB
	AVCLZH
	AVCLZW
	AVCLZD
	AVPOPCNT
	AVPOPCNTB
	AVPOPCNTH
	AVPOPCNTW
	AVPOPCNTD
	AVCMPEQ
	AVCMPEQUB
	AVCMPEQUBCC
	AVCMPEQUH
	AVCMPEQUHCC
	AVCMPEQUW
	AVCMPEQUWCC
	AVCMPEQUD
	AVCMPEQUDCC
	AVCMPGT
	AVCMPGTUB
	AVCMPGTUBCC
	AVCMPGTUH
	AVCMPGTUHCC
	AVCMPGTUW
	AVCMPGTUWCC
	AVCMPGTUD
	AVCMPGTUDCC
	AVCMPGTSB
	AVCMPGTSBCC
	AVCMPGTSH
	AVCMPGTSHCC
	AVCMPGTSW
	AVCMPGTSWCC
	AVCMPGTSD
	AVCMPGTSDCC
	AVCMPNEZB
	AVCMPNEZBCC
	AVCMPNEB
	AVCMPNEBCC
	AVCMPNEH
	AVCMPNEHCC
	AVCMPNEW
	AVCMPNEWCC
	AVPERM
	AVPERMXOR
	AVPERMR
	AVBPERMQ
	AVBPERMD
	AVSEL
	AVSPLTB
	AVSPLTH
	AVSPLTW
	AVSPLTISB
	AVSPLTISH
	AVSPLTISW
	AVCIPH
	AVCIPHER
	AVCIPHERLAST
	AVNCIPH
	AVNCIPHER
	AVNCIPHERLAST
	AVSBOX
	AVSHASIGMA
	AVSHASIGMAW
	AVSHASIGMAD
	AVMRGEW
	AVMRGOW
	AVCLZLSBB
	AVCTZLSBB

	/* VSX */
	ALXV
	ALXVL
	ALXVLL
	ALXVD2X
	ALXVW4X
	ALXVH8X
	ALXVB16X
	ALXVX
	ALXVDSX
	ASTXV
	ASTXVL
	ASTXVLL
	ASTXVD2X
	ASTXVW4X
	ASTXVH8X
	ASTXVB16X
	ASTXVX
	ALXSDX
	ASTXSDX
	ALXSIWAX
	ALXSIWZX
	ASTXSIWX
	AMFVSRD
	AMFFPRD
	AMFVRD
	AMFVSRWZ
	AMFVSRLD
	AMTVSRD
	AMTFPRD
	AMTVRD
	AMTVSRWA
	AMTVSRWZ
	AMTVSRDD
	AMTVSRWS
	AXXLAND
	AXXLANDC
	AXXLEQV
	AXXLNAND
	AXXLOR
	AXXLORC
	AXXLNOR
	AXXLORQ
	AXXLXOR
	AXXSEL
	AXXMRGHW
	AXXMRGLW
	AXXSPLTW
	AXXSPLTIB
	AXXPERM
	AXXPERMDI
	AXXSLDWI
	AXXBRQ
	AXXBRD
	AXXBRW
	AXXBRH
	AXSCVDPSP
	AXSCVSPDP
	AXSCVDPSPN
	AXSCVSPDPN
	AXVCVDPSP
	AXVCVSPDP
	AXSCVDPSXDS
	AXSCVDPSXWS
	AXSCVDPUXDS
	AXSCVDPUXWS
	AXSCVSXDDP
	AXSCVUXDDP
	AXSCVSXDSP
	AXSCVUXDSP
	AXVCVDPSXDS
	AXVCVDPSXWS
	AXVCVDPUXDS
	AXVCVDPUXWS
	AXVCVSPSXDS
	AXVCVSPSXWS
	AXVCVSPUXDS
	AXVCVSPUXWS
	AXVCVSXDDP
	AXVCVSXWDP
	AXVCVUXDDP
	AXVCVUXWDP
	AXVCVSXDSP
	AXVCVSXWSP
	AXVCVUXDSP
	AXVCVUXWSP
	AXSMAXJDP
	AXSMINJDP
	ALASTAOUT // The last instruction in this list. Also the first opcode generated by ppc64map.

	// aliases
	ABR   = obj.AJMP
	ABL   = obj.ACALL
	ALAST = ALASTGEN // The final enumerated instruction value + 1. This is used to size the oprange table.
)

"""



```