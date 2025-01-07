Response: Let's break down the thought process for analyzing the given Go code snippet.

**1. Initial Understanding of the Context:**

The first line `// cmd/7c/7.out.h  from Vita Nuova.` is a crucial starting point. It immediately tells us this code has historical roots and is likely related to a compiler or assembler toolchain. The "Vita Nuova" reference and the copyright notices spanning from the 90s reinforce this. The path `go/src/cmd/internal/obj/arm64/a.out.go` confirms it's part of the Go toolchain, specifically for the ARM64 architecture, and within the `obj` package, which deals with object file manipulation. The filename `a.out.go` is a classic name for assembler output, further suggesting its role in the compilation/assembly process.

**2. Identifying Key Areas and Functionality:**

Scanning the code reveals several key sections:

* **Copyright and License:** Standard boilerplate, not directly related to functionality.
* **`package arm64`:**  Confirms the target architecture.
* **`import "cmd/internal/obj"`:** This import is vital. It indicates this code relies on the `obj` package, which likely provides core data structures and functions for representing assembly instructions and operands.
* **Constants:** A large block of `const` declarations. These are likely definitions for registers, sizes, flags, and instruction operand classes.
* **Register Definitions (`REG_R0`, `REG_F0`, `REG_V0` etc.):** These clearly define the ARM64 register set, including general-purpose, floating-point, and SIMD registers. The `obj.RBaseARM64 + iota` pattern suggests these are based on a common base value defined in the `obj` package.
* **Extended Register and Special Register Definitions:**  The `REG_LSL`, `REG_EXT`, and `REG_SPECIAL` constants point to mechanisms for encoding more complex register operations or accessing special system registers.
* **Register Assignments:**  Comments like "compiler allocates R0 up as temps" provide insight into how the Go compiler utilizes these registers.
* **`ARM64DWARFRegisters`:**  This map clearly relates to debugging information (DWARF) and how Go's internal register names map to the standard DWARF register numbers.
* **`BIG` constant:** A seemingly arbitrary numerical constant, likely related to buffer sizes or similar.
* **Mark Flags (`LABEL`, `LEAF`, etc.):** These are bit flags used to mark properties of instructions or code blocks.
* **`//go:generate go run ../mkcnames.go ...`:** This directive signals code generation for constants related to instruction names.
* **Operand Classes (`C_NONE`, `C_REG`, `C_ZCON`, etc.):** This is a significant part. These constants define different classes of operands that ARM64 instructions can take. The detailed naming convention (e.g., `C_NSAUTO_16`) suggests encoding of addressing modes and constant ranges.
* **Instruction Definitions (`AADC`, `AADD`, `AB`, `ABL`, etc.):**  These `const` definitions, starting with `obj.ABaseARM64`, represent the ARM64 instruction set as understood by the Go toolchain.
* **Shift Types (`SHIFT_LL`, `SHIFT_LR`, etc.):**  Constants for different bit shift operations.
* **Arrangement Types (`ARNG_8B`, `ARNG_16B`, etc.):** Constants relevant to SIMD (NEON) instruction operand layout.
* **`SpecialOperand` enum:** This defines special operands used with certain instructions, like `PRFM` (prefetch) and `TLBI` (TLB invalidate). The `SPOP_EQ`, `SPOP_NE`, etc. are condition codes.

**3. Reasoning about Functionality:**

Based on the identified areas, we can infer the following functions:

* **Architecture Definition:** The primary function is to define the specifics of the ARM64 architecture for the Go compiler and assembler. This includes the register set, instruction set, addressing modes, and operand types.
* **Internal Representation:**  It provides the internal constants and data structures needed to represent ARM64 assembly instructions and operands within the Go toolchain.
* **Operand Classification:** The `C_*` constants are crucial for classifying instruction operands, which is essential for instruction encoding and code generation. The detailed categories suggest a sophisticated understanding of the ARM64 instruction set's intricacies.
* **Debugging Information Support:** The `ARM64DWARFRegisters` map shows that this code contributes to generating debugging information that conforms to the DWARF standard.
* **Instruction Encoding (Implicit):** Although the code doesn't directly encode instructions, the defined constants (especially the instruction opcodes) are foundational for the encoding process. Other parts of the toolchain would use these constants to map assembly instructions to their binary representations.

**4. Connecting to Go Language Features (Hypothesis and Example):**

Given its location in the `cmd/internal/obj` package, this code is *not* directly used by typical Go programmers writing application code. Instead, it's a low-level component of the Go toolchain itself. It's used when the Go compiler translates Go source code into ARM64 machine code.

Therefore, the connection to Go language features is through the *compilation process*. When you compile a Go program targeting ARM64, the compiler internally uses these definitions to generate the correct assembly instructions.

**Example (Illustrative):**

Suppose you have a simple Go function:

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

When the Go compiler compiles this for ARM64, it will generate ARM64 assembly instructions. The constants defined in `a.out.go` are used during this process. For instance, the `ADD` operation might be represented internally using the `AADD` constant, and the registers `a` and `b` might be assigned to specific ARM64 registers like `REG_R0` and `REG_R1`. The return value might be placed in a designated register like `REG_R0`.

**5. Command-Line Arguments and User Mistakes:**

This specific file (`a.out.go`) doesn't directly handle command-line arguments. The command-line arguments for compiling Go code (like `go build`, `go run`) are handled by other parts of the Go toolchain (e.g., `cmd/go`).

User mistakes are unlikely to occur *directly* with this file because it's an internal part of the toolchain. However, incorrect Go code can lead to the compiler generating invalid or inefficient ARM64 assembly based on the rules defined here.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file is directly involved in reading or writing `.o` (object) files.
* **Correction:**  While related to object files (due to the `obj` package), the content suggests it's more about *defining* the architecture for the assembler/compiler than directly handling file I/O. The constants and register definitions point to internal representation.
* **Initial thought:** How do users interact with this?
* **Correction:** Users don't directly interact with this file. It's an internal implementation detail of the Go toolchain. The interaction is indirect, through the compilation process of their Go code.

By following this systematic approach of examining the code structure, identifying key elements, reasoning about functionality, and connecting it back to the broader context of the Go toolchain, we can arrive at a comprehensive understanding of the purpose of `a.out.go`.
这个Go语言文件 `go/src/cmd/internal/obj/arm64/a.out.go` 是Go语言工具链中用于处理ARM64架构的汇编器和链接器 (`cmd/internal/obj`) 的一部分。它定义了ARM64架构特定的常量、数据结构和指令集，为Go编译器将Go代码转换为ARM64汇编代码，以及链接器将这些汇编代码组合成可执行文件提供了基础。

以下是它的主要功能：

1. **定义ARM64架构的常量:**
   - `NSNAME`, `NSYM`, `NREG`, `NFREG`:  定义了符号名称的最大长度、符号表的大小、通用寄存器和浮点寄存器的数量。
   - `REG_R0` 到 `REG_R31`: 定义了ARM64的通用寄存器。
   - `REG_F0` 到 `REG_F31`: 定义了ARM64的浮点寄存器。
   - `REG_V0` 到 `REG_V31`: 定义了ARM64的SIMD寄存器 (NEON)。
   - `REG_RSP`:  定义了栈指针寄存器。
   - `REG_ARNG`, `REG_ELEM`:  定义了SIMD寄存器的排列方式和元素访问方式相关的常量。
   - `REG_LSL`, `REG_EXT`, `REG_UXTB` 等: 定义了寄存器扩展和移位操作相关的常量。
   - `REG_SPECIAL`: 定义了特殊寄存器的基址。
   - `REGMIN`, `REGMAX`, `REGCTXT`, `REGTMP`, `REGG`, `REGFP`, `REGLINK`, `REGZERO`, `REGSP`, `FREGRET`, `FREGMIN`, `FREGMAX`, `FREGEXT`:  定义了编译器进行寄存器分配时使用的范围和特定用途的寄存器。
   - `BIG`: 一个常量，可能用于表示大的偏移量或大小。

2. **定义ARM64 DWARF寄存器映射:**
   - `ARM64DWARFRegisters`:  一个 `map`，将Go内部的寄存器表示映射到DWARF调试信息标准中定义的寄存器编号。这对于调试器正确理解程序状态至关重要。

3. **定义指令标记 (Mark Flags):**
   - `LABEL`, `LEAF`, `FLOAT`, `BRANCH` 等常量: 这些是用于标记指令属性的位标志，例如指令是否为标签、叶子函数、浮点运算、分支指令等。这些标记在编译和链接过程中被使用。

4. **定义指令操作数类型 (Operand Classes):**
   - `C_NONE`, `C_REG`, `C_ZCON`, `C_ADDCON`, `C_ZAUTO`, `C_ZOREG` 等大量的 `C_` 开头的常量: 这些定义了ARM64指令可以使用的各种操作数类型，包括寄存器、立即数、内存地址 (基于寄存器、偏移量、自动变量等)。 这些分类非常详细，涵盖了ARM64架构的各种寻址模式和立即数格式。

5. **定义ARM64指令集:**
   - `AADC`, `AADD`, `AB`, `ABL` 等大量的 `A` 开头的常量:  这些定义了ARM64架构的指令集。每个常量代表一个ARM64指令，例如 `AADD` 代表加法指令，`ABL` 代表带链接的分支指令 (函数调用)。这些指令常量基于 `obj.ABaseARM64` 进行偏移。

6. **定义移位类型:**
   - `SHIFT_LL`, `SHIFT_LR`, `SHIFT_AR`, `SHIFT_ROR`: 定义了移位操作的类型 (逻辑左移、逻辑右移、算术右移、循环右移)。

7. **定义SIMD排列方式 (Arrangement):**
   - `ARNG_8B`, `ARNG_16B`, `ARNG_1D` 等: 定义了SIMD指令操作数的排列方式，例如8个字节、16个字节、一个双字等。

8. **定义特殊操作数 (Special Operand):**
   - `SpecialOperand` 类型和 `SPOP_PLDL1KEEP`, `SPOP_VMALLE1IS`, `SPOP_EQ` 等常量:  定义了某些指令特有的特殊操作数，例如 `PRFM` 指令的预取操作类型，`TLBI` 指令的TLB失效操作类型，以及条件码。

**推断的Go语言功能实现:**

这个文件是Go语言编译器将Go代码编译成ARM64机器码的关键部分。它定义了目标架构的指令集和寄存器，使得编译器能够：

- **理解ARM64架构:**  编译器需要知道ARM64有哪些寄存器、支持哪些指令以及各种指令的操作数格式。
- **生成ARM64汇编代码:**  在将Go代码翻译成机器码的过程中，编译器会根据这里定义的常量选择合适的ARM64指令，并正确地编码操作数 (寄存器、立即数、内存地址等)。
- **支持调试:**  `ARM64DWARFRegisters` 映射使得调试器能够将Go程序中的变量和状态与生成的ARM64机器码对应起来。

**Go代码举例说明 (假设的编译器内部使用):**

虽然我们不能直接在Go代码中使用这些常量，但可以假设编译器内部会使用类似的方式来生成汇编代码。

```go
// 假设这是编译器内部的代码片段
package compiler

import "cmd/internal/obj/arm64"
import "cmd/internal/obj"

func compileAddInt(asm *obj.Prog, dst, src obj.Addr) {
	// ... 一些逻辑，确定使用哪个寄存器 ...
	r0 := arm64.REG_R0 // 假设将结果放到 R0 寄存器
	r1 := arm64.REG_R1 // 假设第一个操作数在 R1 寄存器
	r2 := arm64.REG_R2 // 假设第二个操作数在 R2 寄存器

	p := asm.NewProg()
	p.As = arm64.AADD  // 设置指令为 ADD
	p.Reg = r1        // 第一个源操作数
	p.From = obj.Addr{Type: obj.TYPE_REG, Reg: r2} // 第二个源操作数
	p.To = obj.Addr{Type: obj.TYPE_REG, Reg: r0}   // 目标操作数 (结果)
	// ... 其他设置 ...
}

// ... 其他编译器的逻辑 ...
```

**假设的输入与输出:**

**输入 (Go代码):**

```go
package main

func main() {
	a := 10
	b := 20
	c := a + b
	println(c)
}
```

**输出 (假设的编译器生成的ARM64汇编指令 -  这只是一个简化的例子，实际可能更复杂):**

```assembly
MOV  R1, #10  // 将立即数 10 移动到 R1
MOV  R2, #20  // 将立即数 20 移动到 R2
ADD  R0, R1, R2 // 将 R1 和 R2 的值相加，结果存到 R0
// ... 将 R0 的值传递给 println 函数 ...
```

在这个过程中，编译器内部会使用 `arm64.AADD` 来表示 `ADD` 指令，并使用 `arm64.REG_R0`, `arm64.REG_R1`, `arm64.REG_R2` 等常量来指定寄存器。

**命令行参数的具体处理:**

这个 `a.out.go` 文件本身**不处理命令行参数**。命令行参数的处理发生在 Go 工具链的其他部分，例如 `cmd/go` 包。 `cmd/go` 会解析命令行参数 (例如 `-arch=arm64`)，然后调用相应的架构特定的编译器和链接器。这个 `a.out.go` 文件会被 ARM64 架构的编译器和链接器使用。

**使用者易犯错的点:**

作为 Go 语言的普通开发者，**你不会直接使用或修改这个文件**。它是 Go 工具链的内部实现细节。 因此，普通开发者不太可能因为这个文件而犯错。

然而，如果你是 Go 语言工具链的开发者，或者正在进行与 Go 编译器相关的底层开发，那么理解这个文件至关重要。 可能会犯的错误包括：

- **错误地理解或使用指令常量:**  例如，错误地使用了某个指令的常量，导致生成了错误的机器码。
- **错误地定义寄存器或操作数类型:**  如果对寄存器或操作数类型的定义有误，可能会导致编译器无法正确地生成或理解汇编代码。
- **不符合ARM64架构规范:**  对ARM64架构的理解有偏差，导致定义的常量或指令不符合实际的ARM64规范。

总而言之，`go/src/cmd/internal/obj/arm64/a.out.go` 是 Go 语言工具链中关于 ARM64 架构的核心定义文件，它为 Go 编译器生成正确的 ARM64 机器码提供了基础。普通 Go 开发者无需关心这个文件，但它是理解 Go 编译过程的重要组成部分。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/arm64/a.out.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// cmd/7c/7.out.h  from Vita Nuova.
// https://bitbucket.org/plan9-from-bell-labs/9-cc/src/master/src/cmd/7c/7.out.h
//
// 	Copyright © 1994-1999 Lucent Technologies Inc. All rights reserved.
// 	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
// 	Portions Copyright © 1997-1999 Vita Nuova Limited
// 	Portions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com)
// 	Portions Copyright © 2004,2006 Bruce Ellis
// 	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
// 	Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
// 	Portions Copyright © 2009 The Go Authors. All rights reserved.
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

package arm64

import "cmd/internal/obj"

const (
	NSNAME = 8
	NSYM   = 50
	NREG   = 32 /* number of general registers */
	NFREG  = 32 /* number of floating point registers */
)

// General purpose registers, kept in the low bits of Prog.Reg.
const (
	// integer
	REG_R0 = obj.RBaseARM64 + iota
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

	// scalar floating point
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

	// SIMD
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

	REG_RSP = REG_V31 + 32 // to differentiate ZR/SP, REG_RSP&0x1f = 31
)

// bits 0-4 indicates register: Vn
// bits 5-8 indicates arrangement: <T>
const (
	REG_ARNG = obj.RBaseARM64 + 1<<10 + iota<<9 // Vn.<T>
	REG_ELEM                                    // Vn.<T>[index]
	REG_ELEM_END
)

// Not registers, but flags that can be combined with regular register
// constants to indicate extended register conversion. When checking,
// you should subtract obj.RBaseARM64 first. From this difference, bit 11
// indicates extended register, bits 8-10 select the conversion mode.
// REG_LSL is the index shift specifier, bit 9 indicates shifted offset register.
const REG_LSL = obj.RBaseARM64 + 1<<9
const REG_EXT = obj.RBaseARM64 + 1<<11

const (
	REG_UXTB = REG_EXT + iota<<8
	REG_UXTH
	REG_UXTW
	REG_UXTX
	REG_SXTB
	REG_SXTH
	REG_SXTW
	REG_SXTX
)

// Special registers, after subtracting obj.RBaseARM64, bit 12 indicates
// a special register and the low bits select the register.
// SYSREG_END is the last item in the automatically generated system register
// declaration, and it is defined in the sysRegEnc.go file.
// Define the special register after REG_SPECIAL, the first value of it should be
// REG_{name} = SYSREG_END + iota.
const (
	REG_SPECIAL = obj.RBaseARM64 + 1<<12
)

// Register assignments:
//
// compiler allocates R0 up as temps
// compiler allocates register variables R7-R25
// compiler allocates external registers R26 down
//
// compiler allocates register variables F7-F26
// compiler allocates external registers F26 down
const (
	REGMIN = REG_R7  // register variables allocated from here to REGMAX
	REGRT1 = REG_R16 // ARM64 IP0, external linker may use as a scratch register in trampoline
	REGRT2 = REG_R17 // ARM64 IP1, external linker may use as a scratch register in trampoline
	REGPR  = REG_R18 // ARM64 platform register, unused in the Go toolchain
	REGMAX = REG_R25

	REGCTXT = REG_R26 // environment for closures
	REGTMP  = REG_R27 // reserved for liblink
	REGG    = REG_R28 // G
	REGFP   = REG_R29 // frame pointer
	REGLINK = REG_R30

	// ARM64 uses R31 as both stack pointer and zero register,
	// depending on the instruction. To differentiate RSP from ZR,
	// we use a different numeric value for REGZERO and REGSP.
	REGZERO = REG_R31
	REGSP   = REG_RSP

	FREGRET = REG_F0
	FREGMIN = REG_F7  // first register variable
	FREGMAX = REG_F26 // last register variable for 7g only
	FREGEXT = REG_F26 // first external register
)

// http://infocenter.arm.com/help/topic/com.arm.doc.ecm0665627/abi_sve_aadwarf_100985_0000_00_en.pdf
var ARM64DWARFRegisters = map[int16]int16{
	REG_R0:  0,
	REG_R1:  1,
	REG_R2:  2,
	REG_R3:  3,
	REG_R4:  4,
	REG_R5:  5,
	REG_R6:  6,
	REG_R7:  7,
	REG_R8:  8,
	REG_R9:  9,
	REG_R10: 10,
	REG_R11: 11,
	REG_R12: 12,
	REG_R13: 13,
	REG_R14: 14,
	REG_R15: 15,
	REG_R16: 16,
	REG_R17: 17,
	REG_R18: 18,
	REG_R19: 19,
	REG_R20: 20,
	REG_R21: 21,
	REG_R22: 22,
	REG_R23: 23,
	REG_R24: 24,
	REG_R25: 25,
	REG_R26: 26,
	REG_R27: 27,
	REG_R28: 28,
	REG_R29: 29,
	REG_R30: 30,

	// floating point
	REG_F0:  64,
	REG_F1:  65,
	REG_F2:  66,
	REG_F3:  67,
	REG_F4:  68,
	REG_F5:  69,
	REG_F6:  70,
	REG_F7:  71,
	REG_F8:  72,
	REG_F9:  73,
	REG_F10: 74,
	REG_F11: 75,
	REG_F12: 76,
	REG_F13: 77,
	REG_F14: 78,
	REG_F15: 79,
	REG_F16: 80,
	REG_F17: 81,
	REG_F18: 82,
	REG_F19: 83,
	REG_F20: 84,
	REG_F21: 85,
	REG_F22: 86,
	REG_F23: 87,
	REG_F24: 88,
	REG_F25: 89,
	REG_F26: 90,
	REG_F27: 91,
	REG_F28: 92,
	REG_F29: 93,
	REG_F30: 94,
	REG_F31: 95,

	// SIMD
	REG_V0:  64,
	REG_V1:  65,
	REG_V2:  66,
	REG_V3:  67,
	REG_V4:  68,
	REG_V5:  69,
	REG_V6:  70,
	REG_V7:  71,
	REG_V8:  72,
	REG_V9:  73,
	REG_V10: 74,
	REG_V11: 75,
	REG_V12: 76,
	REG_V13: 77,
	REG_V14: 78,
	REG_V15: 79,
	REG_V16: 80,
	REG_V17: 81,
	REG_V18: 82,
	REG_V19: 83,
	REG_V20: 84,
	REG_V21: 85,
	REG_V22: 86,
	REG_V23: 87,
	REG_V24: 88,
	REG_V25: 89,
	REG_V26: 90,
	REG_V27: 91,
	REG_V28: 92,
	REG_V29: 93,
	REG_V30: 94,
	REG_V31: 95,
}

const (
	BIG = 2048 - 8
)

const (
	/* mark flags */
	LABEL = 1 << iota
	LEAF
	FLOAT
	BRANCH
	LOAD
	FCMP
	SYNC
	LIST
	FOLL
	NOSCHED
)

//go:generate go run ../mkcnames.go -i a.out.go -o anames7.go -p arm64
const (
	// optab is sorted based on the order of these constants
	// and the first match is chosen.
	// The more specific class needs to come earlier.
	C_NONE   = iota + 1 // starting from 1, leave unclassified Addr's class as 0
	C_REG               // R0..R30
	C_ZREG              // R0..R30, ZR
	C_RSP               // R0..R30, RSP
	C_FREG              // F0..F31
	C_VREG              // V0..V31
	C_PAIR              // (Rn, Rm)
	C_SHIFT             // Rn<<2
	C_EXTREG            // Rn.UXTB[<<3]
	C_SPR               // REG_NZCV
	C_COND              // condition code, EQ, NE, etc.
	C_SPOP              // special operand, PLDL1KEEP, VMALLE1IS, etc.
	C_ARNG              // Vn.<T>
	C_ELEM              // Vn.<T>[index]
	C_LIST              // [V1, V2, V3]

	C_ZCON     // $0
	C_ABCON0   // could be C_ADDCON0 or C_BITCON
	C_ADDCON0  // 12-bit unsigned, unshifted
	C_ABCON    // could be C_ADDCON or C_BITCON
	C_AMCON    // could be C_ADDCON or C_MOVCON
	C_ADDCON   // 12-bit unsigned, shifted left by 0 or 12
	C_MBCON    // could be C_MOVCON or C_BITCON
	C_MOVCON   // generated by a 16-bit constant, optionally inverted and/or shifted by multiple of 16
	C_BITCON   // bitfield and logical immediate masks
	C_ADDCON2  // 24-bit constant
	C_LCON     // 32-bit constant
	C_MOVCON2  // a constant that can be loaded with one MOVZ/MOVN and one MOVK
	C_MOVCON3  // a constant that can be loaded with one MOVZ/MOVN and two MOVKs
	C_VCON     // 64-bit constant
	C_FCON     // floating-point constant
	C_VCONADDR // 64-bit memory address

	C_AACON  // ADDCON offset in auto constant $a(FP)
	C_AACON2 // 24-bit offset in auto constant $a(FP)
	C_LACON  // 32-bit offset in auto constant $a(FP)
	C_AECON  // ADDCON offset in extern constant $e(SB)

	// TODO(aram): only one branch class should be enough
	C_SBRA // for TYPE_BRANCH
	C_LBRA

	C_ZAUTO       // 0(RSP)
	C_NSAUTO_16   // -256 <= x < 0, 0 mod 16
	C_NSAUTO_8    // -256 <= x < 0, 0 mod 8
	C_NSAUTO_4    // -256 <= x < 0, 0 mod 4
	C_NSAUTO      // -256 <= x < 0
	C_NPAUTO_16   // -512 <= x < 0, 0 mod 16
	C_NPAUTO      // -512 <= x < 0, 0 mod 8
	C_NQAUTO_16   // -1024 <= x < 0, 0 mod 16
	C_NAUTO4K     // -4095 <= x < 0
	C_PSAUTO_16   // 0 to 255, 0 mod 16
	C_PSAUTO_8    // 0 to 255, 0 mod 8
	C_PSAUTO_4    // 0 to 255, 0 mod 4
	C_PSAUTO      // 0 to 255
	C_PPAUTO_16   // 0 to 504, 0 mod 16
	C_PPAUTO      // 0 to 504, 0 mod 8
	C_PQAUTO_16   // 0 to 1008, 0 mod 16
	C_UAUTO4K_16  // 0 to 4095, 0 mod 16
	C_UAUTO4K_8   // 0 to 4095, 0 mod 8
	C_UAUTO4K_4   // 0 to 4095, 0 mod 4
	C_UAUTO4K_2   // 0 to 4095, 0 mod 2
	C_UAUTO4K     // 0 to 4095
	C_UAUTO8K_16  // 0 to 8190, 0 mod 16
	C_UAUTO8K_8   // 0 to 8190, 0 mod 8
	C_UAUTO8K_4   // 0 to 8190, 0 mod 4
	C_UAUTO8K     // 0 to 8190, 0 mod 2  + C_PSAUTO
	C_UAUTO16K_16 // 0 to 16380, 0 mod 16
	C_UAUTO16K_8  // 0 to 16380, 0 mod 8
	C_UAUTO16K    // 0 to 16380, 0 mod 4 + C_PSAUTO
	C_UAUTO32K_16 // 0 to 32760, 0 mod 16 + C_PSAUTO
	C_UAUTO32K    // 0 to 32760, 0 mod 8 + C_PSAUTO
	C_UAUTO64K    // 0 to 65520, 0 mod 16 + C_PSAUTO
	C_LAUTOPOOL   // any other constant up to 64 bits (needs pool literal)
	C_LAUTO       // any other constant up to 64 bits

	C_SEXT1  // 0 to 4095, direct
	C_SEXT2  // 0 to 8190
	C_SEXT4  // 0 to 16380
	C_SEXT8  // 0 to 32760
	C_SEXT16 // 0 to 65520
	C_LEXT

	C_ZOREG     // 0(R)
	C_NSOREG_16 // must mirror C_NSAUTO_16, etc
	C_NSOREG_8
	C_NSOREG_4
	C_NSOREG
	C_NPOREG_16
	C_NPOREG
	C_NQOREG_16
	C_NOREG4K
	C_PSOREG_16
	C_PSOREG_8
	C_PSOREG_4
	C_PSOREG
	C_PPOREG_16
	C_PPOREG
	C_PQOREG_16
	C_UOREG4K_16
	C_UOREG4K_8
	C_UOREG4K_4
	C_UOREG4K_2
	C_UOREG4K
	C_UOREG8K_16
	C_UOREG8K_8
	C_UOREG8K_4
	C_UOREG8K
	C_UOREG16K_16
	C_UOREG16K_8
	C_UOREG16K
	C_UOREG32K_16
	C_UOREG32K
	C_UOREG64K
	C_LOREGPOOL
	C_LOREG

	C_ADDR // TODO(aram): explain difference from C_VCONADDR

	// The GOT slot for a symbol in -dynlink mode.
	C_GOTADDR

	// TLS "var" in local exec mode: will become a constant offset from
	// thread local base that is ultimately chosen by the program linker.
	C_TLS_LE

	// TLS "var" in initial exec mode: will become a memory address (chosen
	// by the program linker) that the dynamic linker will fill with the
	// offset from the thread local base.
	C_TLS_IE

	C_ROFF // register offset (including register extended)

	C_GOK
	C_TEXTSIZE
	C_NCLASS // must be last
)

const (
	C_XPRE  = 1 << 6 // match arm.C_WBIT, so Prog.String know how to print it
	C_XPOST = 1 << 5 // match arm.C_PBIT, so Prog.String know how to print it
)

//go:generate go run ../stringer.go -i $GOFILE -o anames.go -p arm64

const (
	AADC = obj.ABaseARM64 + obj.A_ARCHSPECIFIC + iota
	AADCS
	AADCSW
	AADCW
	AADD
	AADDS
	AADDSW
	AADDW
	AADR
	AADRP
	AAESD
	AAESE
	AAESIMC
	AAESMC
	AAND
	AANDS
	AANDSW
	AANDW
	AASR
	AASRW
	AAT
	ABCC
	ABCS
	ABEQ
	ABFI
	ABFIW
	ABFM
	ABFMW
	ABFXIL
	ABFXILW
	ABGE
	ABGT
	ABHI
	ABHS
	ABIC
	ABICS
	ABICSW
	ABICW
	ABLE
	ABLO
	ABLS
	ABLT
	ABMI
	ABNE
	ABPL
	ABRK
	ABVC
	ABVS
	ACASAD
	ACASALB
	ACASALD
	ACASALH
	ACASALW
	ACASAW
	ACASB
	ACASD
	ACASH
	ACASLD
	ACASLW
	ACASPD
	ACASPW
	ACASW
	ACBNZ
	ACBNZW
	ACBZ
	ACBZW
	ACCMN
	ACCMNW
	ACCMP
	ACCMPW
	ACINC
	ACINCW
	ACINV
	ACINVW
	ACLREX
	ACLS
	ACLSW
	ACLZ
	ACLZW
	ACMN
	ACMNW
	ACMP
	ACMPW
	ACNEG
	ACNEGW
	ACRC32B
	ACRC32CB
	ACRC32CH
	ACRC32CW
	ACRC32CX
	ACRC32H
	ACRC32W
	ACRC32X
	ACSEL
	ACSELW
	ACSET
	ACSETM
	ACSETMW
	ACSETW
	ACSINC
	ACSINCW
	ACSINV
	ACSINVW
	ACSNEG
	ACSNEGW
	ADC
	ADCPS1
	ADCPS2
	ADCPS3
	ADMB
	ADRPS
	ADSB
	ADWORD
	AEON
	AEONW
	AEOR
	AEORW
	AERET
	AEXTR
	AEXTRW
	AFABSD
	AFABSS
	AFADDD
	AFADDS
	AFCCMPD
	AFCCMPED
	AFCCMPES
	AFCCMPS
	AFCMPD
	AFCMPED
	AFCMPES
	AFCMPS
	AFCSELD
	AFCSELS
	AFCVTDH
	AFCVTDS
	AFCVTHD
	AFCVTHS
	AFCVTSD
	AFCVTSH
	AFCVTZSD
	AFCVTZSDW
	AFCVTZSS
	AFCVTZSSW
	AFCVTZUD
	AFCVTZUDW
	AFCVTZUS
	AFCVTZUSW
	AFDIVD
	AFDIVS
	AFLDPD
	AFLDPQ
	AFLDPS
	AFMADDD
	AFMADDS
	AFMAXD
	AFMAXNMD
	AFMAXNMS
	AFMAXS
	AFMIND
	AFMINNMD
	AFMINNMS
	AFMINS
	AFMOVD
	AFMOVQ
	AFMOVS
	AFMSUBD
	AFMSUBS
	AFMULD
	AFMULS
	AFNEGD
	AFNEGS
	AFNMADDD
	AFNMADDS
	AFNMSUBD
	AFNMSUBS
	AFNMULD
	AFNMULS
	AFRINTAD
	AFRINTAS
	AFRINTID
	AFRINTIS
	AFRINTMD
	AFRINTMS
	AFRINTND
	AFRINTNS
	AFRINTPD
	AFRINTPS
	AFRINTXD
	AFRINTXS
	AFRINTZD
	AFRINTZS
	AFSQRTD
	AFSQRTS
	AFSTPD
	AFSTPQ
	AFSTPS
	AFSUBD
	AFSUBS
	AHINT
	AHLT
	AHVC
	AIC
	AISB
	ALDADDAB
	ALDADDAD
	ALDADDAH
	ALDADDALB
	ALDADDALD
	ALDADDALH
	ALDADDALW
	ALDADDAW
	ALDADDB
	ALDADDD
	ALDADDH
	ALDADDLB
	ALDADDLD
	ALDADDLH
	ALDADDLW
	ALDADDW
	ALDAR
	ALDARB
	ALDARH
	ALDARW
	ALDAXP
	ALDAXPW
	ALDAXR
	ALDAXRB
	ALDAXRH
	ALDAXRW
	ALDCLRAB
	ALDCLRAD
	ALDCLRAH
	ALDCLRALB
	ALDCLRALD
	ALDCLRALH
	ALDCLRALW
	ALDCLRAW
	ALDCLRB
	ALDCLRD
	ALDCLRH
	ALDCLRLB
	ALDCLRLD
	ALDCLRLH
	ALDCLRLW
	ALDCLRW
	ALDEORAB
	ALDEORAD
	ALDEORAH
	ALDEORALB
	ALDEORALD
	ALDEORALH
	ALDEORALW
	ALDEORAW
	ALDEORB
	ALDEORD
	ALDEORH
	ALDEORLB
	ALDEORLD
	ALDEORLH
	ALDEORLW
	ALDEORW
	ALDORAB
	ALDORAD
	ALDORAH
	ALDORALB
	ALDORALD
	ALDORALH
	ALDORALW
	ALDORAW
	ALDORB
	ALDORD
	ALDORH
	ALDORLB
	ALDORLD
	ALDORLH
	ALDORLW
	ALDORW
	ALDP
	ALDPSW
	ALDPW
	ALDXP
	ALDXPW
	ALDXR
	ALDXRB
	ALDXRH
	ALDXRW
	ALSL
	ALSLW
	ALSR
	ALSRW
	AMADD
	AMADDW
	AMNEG
	AMNEGW
	AMOVB
	AMOVBU
	AMOVD
	AMOVH
	AMOVHU
	AMOVK
	AMOVKW
	AMOVN
	AMOVNW
	AMOVP
	AMOVPD
	AMOVPQ
	AMOVPS
	AMOVPSW
	AMOVPW
	AMOVW
	AMOVWU
	AMOVZ
	AMOVZW
	AMRS
	AMSR
	AMSUB
	AMSUBW
	AMUL
	AMULW
	AMVN
	AMVNW
	ANEG
	ANEGS
	ANEGSW
	ANEGW
	ANGC
	ANGCS
	ANGCSW
	ANGCW
	ANOOP
	AORN
	AORNW
	AORR
	AORRW
	APRFM
	APRFUM
	ARBIT
	ARBITW
	AREM
	AREMW
	AREV
	AREV16
	AREV16W
	AREV32
	AREVW
	AROR
	ARORW
	ASBC
	ASBCS
	ASBCSW
	ASBCW
	ASBFIZ
	ASBFIZW
	ASBFM
	ASBFMW
	ASBFX
	ASBFXW
	ASCVTFD
	ASCVTFS
	ASCVTFWD
	ASCVTFWS
	ASDIV
	ASDIVW
	ASEV
	ASEVL
	ASHA1C
	ASHA1H
	ASHA1M
	ASHA1P
	ASHA1SU0
	ASHA1SU1
	ASHA256H
	ASHA256H2
	ASHA256SU0
	ASHA256SU1
	ASHA512H
	ASHA512H2
	ASHA512SU0
	ASHA512SU1
	ASMADDL
	ASMC
	ASMNEGL
	ASMSUBL
	ASMULH
	ASMULL
	ASTLR
	ASTLRB
	ASTLRH
	ASTLRW
	ASTLXP
	ASTLXPW
	ASTLXR
	ASTLXRB
	ASTLXRH
	ASTLXRW
	ASTP
	ASTPW
	ASTXP
	ASTXPW
	ASTXR
	ASTXRB
	ASTXRH
	ASTXRW
	ASUB
	ASUBS
	ASUBSW
	ASUBW
	ASVC
	ASWPAB
	ASWPAD
	ASWPAH
	ASWPALB
	ASWPALD
	ASWPALH
	ASWPALW
	ASWPAW
	ASWPB
	ASWPD
	ASWPH
	ASWPLB
	ASWPLD
	ASWPLH
	ASWPLW
	ASWPW
	ASXTB
	ASXTBW
	ASXTH
	ASXTHW
	ASXTW
	ASYS
	ASYSL
	ATBNZ
	ATBZ
	ATLBI
	ATST
	ATSTW
	AUBFIZ
	AUBFIZW
	AUBFM
	AUBFMW
	AUBFX
	AUBFXW
	AUCVTFD
	AUCVTFS
	AUCVTFWD
	AUCVTFWS
	AUDIV
	AUDIVW
	AUMADDL
	AUMNEGL
	AUMSUBL
	AUMULH
	AUMULL
	AUREM
	AUREMW
	AUXTB
	AUXTBW
	AUXTH
	AUXTHW
	AUXTW
	AVADD
	AVADDP
	AVADDV
	AVAND
	AVBCAX
	AVBIF
	AVBIT
	AVBSL
	AVCMEQ
	AVCMTST
	AVCNT
	AVDUP
	AVEOR
	AVEOR3
	AVEXT
	AVFMLA
	AVFMLS
	AVLD1
	AVLD1R
	AVLD2
	AVLD2R
	AVLD3
	AVLD3R
	AVLD4
	AVLD4R
	AVMOV
	AVMOVD
	AVMOVI
	AVMOVQ
	AVMOVS
	AVORR
	AVPMULL
	AVPMULL2
	AVRAX1
	AVRBIT
	AVREV16
	AVREV32
	AVREV64
	AVSHL
	AVSLI
	AVSRI
	AVST1
	AVST2
	AVST3
	AVST4
	AVSUB
	AVTBL
	AVTBX
	AVTRN1
	AVTRN2
	AVUADDLV
	AVUADDW
	AVUADDW2
	AVUMAX
	AVUMIN
	AVUSHLL
	AVUSHLL2
	AVUSHR
	AVUSRA
	AVUXTL
	AVUXTL2
	AVUZP1
	AVUZP2
	AVXAR
	AVZIP1
	AVZIP2
	AWFE
	AWFI
	AWORD
	AYIELD
	ALAST
	AB  = obj.AJMP
	ABL = obj.ACALL
)

const (
	// shift types
	SHIFT_LL  = 0 << 22
	SHIFT_LR  = 1 << 22
	SHIFT_AR  = 2 << 22
	SHIFT_ROR = 3 << 22
)

// Arrangement for ARM64 SIMD instructions
const (
	// arrangement types
	ARNG_8B = iota
	ARNG_16B
	ARNG_1D
	ARNG_4H
	ARNG_8H
	ARNG_2S
	ARNG_4S
	ARNG_2D
	ARNG_1Q
	ARNG_B
	ARNG_H
	ARNG_S
	ARNG_D
)

//go:generate stringer -type SpecialOperand -trimprefix SPOP_
type SpecialOperand int

const (
	// PRFM
	SPOP_PLDL1KEEP SpecialOperand = iota     // must be the first one
	SPOP_BEGIN     SpecialOperand = iota - 1 // set as the lower bound
	SPOP_PLDL1STRM
	SPOP_PLDL2KEEP
	SPOP_PLDL2STRM
	SPOP_PLDL3KEEP
	SPOP_PLDL3STRM
	SPOP_PLIL1KEEP
	SPOP_PLIL1STRM
	SPOP_PLIL2KEEP
	SPOP_PLIL2STRM
	SPOP_PLIL3KEEP
	SPOP_PLIL3STRM
	SPOP_PSTL1KEEP
	SPOP_PSTL1STRM
	SPOP_PSTL2KEEP
	SPOP_PSTL2STRM
	SPOP_PSTL3KEEP
	SPOP_PSTL3STRM

	// TLBI
	SPOP_VMALLE1IS
	SPOP_VAE1IS
	SPOP_ASIDE1IS
	SPOP_VAAE1IS
	SPOP_VALE1IS
	SPOP_VAALE1IS
	SPOP_VMALLE1
	SPOP_VAE1
	SPOP_ASIDE1
	SPOP_VAAE1
	SPOP_VALE1
	SPOP_VAALE1
	SPOP_IPAS2E1IS
	SPOP_IPAS2LE1IS
	SPOP_ALLE2IS
	SPOP_VAE2IS
	SPOP_ALLE1IS
	SPOP_VALE2IS
	SPOP_VMALLS12E1IS
	SPOP_IPAS2E1
	SPOP_IPAS2LE1
	SPOP_ALLE2
	SPOP_VAE2
	SPOP_ALLE1
	SPOP_VALE2
	SPOP_VMALLS12E1
	SPOP_ALLE3IS
	SPOP_VAE3IS
	SPOP_VALE3IS
	SPOP_ALLE3
	SPOP_VAE3
	SPOP_VALE3
	SPOP_VMALLE1OS
	SPOP_VAE1OS
	SPOP_ASIDE1OS
	SPOP_VAAE1OS
	SPOP_VALE1OS
	SPOP_VAALE1OS
	SPOP_RVAE1IS
	SPOP_RVAAE1IS
	SPOP_RVALE1IS
	SPOP_RVAALE1IS
	SPOP_RVAE1OS
	SPOP_RVAAE1OS
	SPOP_RVALE1OS
	SPOP_RVAALE1OS
	SPOP_RVAE1
	SPOP_RVAAE1
	SPOP_RVALE1
	SPOP_RVAALE1
	SPOP_RIPAS2E1IS
	SPOP_RIPAS2LE1IS
	SPOP_ALLE2OS
	SPOP_VAE2OS
	SPOP_ALLE1OS
	SPOP_VALE2OS
	SPOP_VMALLS12E1OS
	SPOP_RVAE2IS
	SPOP_RVALE2IS
	SPOP_IPAS2E1OS
	SPOP_RIPAS2E1
	SPOP_RIPAS2E1OS
	SPOP_IPAS2LE1OS
	SPOP_RIPAS2LE1
	SPOP_RIPAS2LE1OS
	SPOP_RVAE2OS
	SPOP_RVALE2OS
	SPOP_RVAE2
	SPOP_RVALE2
	SPOP_ALLE3OS
	SPOP_VAE3OS
	SPOP_VALE3OS
	SPOP_RVAE3IS
	SPOP_RVALE3IS
	SPOP_RVAE3OS
	SPOP_RVALE3OS
	SPOP_RVAE3
	SPOP_RVALE3

	// DC
	SPOP_IVAC
	SPOP_ISW
	SPOP_CSW
	SPOP_CISW
	SPOP_ZVA
	SPOP_CVAC
	SPOP_CVAU
	SPOP_CIVAC
	SPOP_IGVAC
	SPOP_IGSW
	SPOP_IGDVAC
	SPOP_IGDSW
	SPOP_CGSW
	SPOP_CGDSW
	SPOP_CIGSW
	SPOP_CIGDSW
	SPOP_GVA
	SPOP_GZVA
	SPOP_CGVAC
	SPOP_CGDVAC
	SPOP_CGVAP
	SPOP_CGDVAP
	SPOP_CGVADP
	SPOP_CGDVADP
	SPOP_CIGVAC
	SPOP_CIGDVAC
	SPOP_CVAP
	SPOP_CVADP

	// PSTATE fields
	SPOP_DAIFSet
	SPOP_DAIFClr

	// Condition code, EQ, NE, etc. Their relative order to EQ is matter.
	SPOP_EQ
	SPOP_NE
	SPOP_HS
	SPOP_LO
	SPOP_MI
	SPOP_PL
	SPOP_VS
	SPOP_VC
	SPOP_HI
	SPOP_LS
	SPOP_GE
	SPOP_LT
	SPOP_GT
	SPOP_LE
	SPOP_AL
	SPOP_NV
	// Condition code end.

	SPOP_END
)

"""



```