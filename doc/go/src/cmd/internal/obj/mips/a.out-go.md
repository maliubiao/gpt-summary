Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding and Context:**

* **File Path:** The path `go/src/cmd/internal/obj/mips/a.out.go` immediately tells us this code is part of the Go compiler toolchain (`cmd`), specifically within the object code handling (`internal/obj`) for the MIPS architecture (`mips`). The `a.out.go` naming convention often relates to the output format of the linker/assembler.
* **Copyright Notice:** This is boilerplate and provides historical context about the code's origins. It's good to acknowledge but not crucial for understanding the core functionality *right now*.
* **`package mips`:**  Confirms this code is specific to the MIPS architecture.
* **`import "cmd/internal/obj"`:**  This is a key import. It means this code relies on the internal object representation structures and constants defined in the `cmd/internal/obj` package. This is the foundation for how the Go compiler manipulates assembly instructions and data.
* **`//go:generate go run ../stringer.go ...`:** This is a directive for the `go generate` tool. It indicates that the `stringer` tool is used to automatically generate a `String()` method for some type defined in this file. The `-type` likely refers to the instruction opcodes (`A...` constants). This suggests the code deals with defining MIPS assembly instructions.

**2. Deconstructing the Constants:**

* **Architecture-Specific Constants:** `NSNAME`, `NSYM`, `NREG`, `NFREG`, `NWREG`. These clearly define fundamental aspects of the MIPS architecture in the context of the Go toolchain: name length, number of symbols, general-purpose registers, floating-point registers, and MSA registers. The comments "mips 64" reinforce that this is for the 64-bit MIPS variant.
* **Register Definitions:** The `REG_R0` to `REG_R31`, `REG_F0` to `REG_F31`, etc., are enumerations of the MIPS registers. The `iota` keyword is used for sequential numbering, and the comments "must be a multiple of 32" are a bit cryptic at this stage but might relate to internal indexing or alignment. The grouping (general, floating-point, co-processor, FPU control, MSA) is important for understanding the different register classes.
* **Special Registers:** `REG_HI`, `REG_LO`, `REGZERO`, `REGSP`, etc., are definitions of commonly used or architecturally significant registers with symbolic names. The comments explain their typical roles (stack pointer, link register, etc.).
* **DWARF Registers:** The `MIPSDWARFRegisters` map and the `init()` function that populates it are related to debugging information. DWARF is a standard debugging format. This suggests a mapping between the Go-internal register representation and the register numbers used in DWARF debugging information.
* **Mark Flags:** `FOLL`, `LABEL`, `LEAF`, etc., seem to be flags used internally during the compilation process, likely for marking properties of instructions or code blocks.
* **Instruction Classes (C_...):** `C_NONE`, `C_REG`, `C_FREG`, etc. These constants likely classify the *types* of operands an instruction can take (register, immediate value, memory address, etc.).
* **Assembly Opcodes (A...):** The `AABSD`, `AABSF`, `AADD`, `ABEQ`, etc., are the core of this file. They represent the different MIPS assembly instructions. The `obj.ABaseMIPS + obj.A_ARCHSPECIFIC + iota` pattern shows they are built upon a base value and an offset, likely related to how instructions are represented internally. The comments like "hardware nop" are helpful. The sections for "64-bit" and "MSA" instructions indicate specific extensions or features of the MIPS architecture being handled.
* **Aliases:** `AJMP`, `AJAL`, `ARET` are aliases for other instruction opcodes, providing more readable names for common operations.

**3. Inferring Functionality:**

Based on the constants, the file's location, and the imports, it's highly probable that `a.out.go` is responsible for:

* **Defining the MIPS instruction set:** The `A...` constants are the core instruction opcodes.
* **Defining register names and their mappings:** The `REG_...` constants provide symbolic names for registers, and `MIPSDWARFRegisters` maps them for debugging.
* **Defining operand types:** The `C_...` constants classify the types of operands instructions can use.
* **Providing architecture-specific constants:**  `NREG`, `NFREG`, etc., define the architectural limits.

**4. Developing Go Code Examples (Hypothetical):**

Since this file is part of the compiler's internal representation, direct usage in user Go code isn't expected. The examples would be about how the *compiler* might use these definitions.

* **Instruction Representation:** Imagine a data structure used by the compiler to represent a MIPS instruction. It might use the `A...` constants as an enum.
* **Register Handling:** When compiling, the compiler needs to know the registers available for allocation. The `REG_...` constants provide this information.
* **Operand Encoding:** The `C_...` constants could guide how the compiler encodes the operands of an instruction into the machine code.

**5. Considering Command-Line Arguments (Indirect):**

This specific file likely doesn't directly process command-line arguments. However, it's *part* of the compilation process. The `go build` command (or `go run`) will trigger the compiler, which *will* have command-line flags. These flags (like `-arch=mips64`) influence *which* architecture's `a.out.go` file gets used.

**6. Identifying Common Mistakes (Compiler Internals):**

Since this is compiler-internal code, the "users" are primarily Go compiler developers. Potential mistakes include:

* **Incorrectly defining register numbers:**  A mismatch between the `REG_...` constants and the actual hardware register encoding would lead to incorrect code generation. The `init()` function with the modulo check is a safeguard against this.
* **Missing or incorrect instruction definitions:**  If an `A...` constant is missing or has the wrong value, the compiler won't be able to generate that instruction.
* **Incorrect operand type classification:**  Misclassifying an operand type (`C_...`) could lead to incorrect instruction encoding.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** "This looks like low-level assembly stuff."  **Refinement:** "Yes, it's *for* the assembler/linker, defining the instruction set and register mappings."
* **Initial thought:** "How is this used in Go code?" **Refinement:** "Directly, it's probably not. It's part of the *compiler's* internal representation. Examples should focus on how the compiler *uses* these definitions."
* **Initial thought:** "Command-line arguments? Maybe for the assembler?" **Refinement:** "While not directly handling arguments, this file is crucial for compiling *for* the MIPS architecture, which is specified via command-line flags."

By following these steps, combining code analysis with domain knowledge (compiler internals, assembly language concepts), and iteratively refining understanding, we can arrive at a comprehensive explanation of the code's purpose.
`go/src/cmd/internal/obj/mips/a.out.go` 是 Go 语言编译器工具链中，专门用于处理 MIPS 架构的目标文件（object file）和汇编代码生成的部分。它定义了 MIPS 架构相关的常量、寄存器、指令以及操作数的表示方式。

以下是它的主要功能：

1. **定义 MIPS 架构特定的常量:**
   - `NSNAME`, `NSYM`:  符号名称和符号数量的限制。
   - `NREG`, `NFREG`, `NWREG`: 通用寄存器、浮点寄存器和 MSA 寄存器的数量。

2. **定义 MIPS 架构的寄存器:**
   - `REG_R0` 到 `REG_R31`: 定义了 MIPS 的 32 个通用寄存器，并赋予了它们在 Go 编译器内部使用的常量名。例如，`REGZERO` 代表 R0 寄存器（通常为零寄存器），`REGSP` 代表栈指针寄存器。
   - `REG_F0` 到 `REG_F31`: 定义了 32 个浮点寄存器。
   - `REG_M0` 到 `REG_M31`: 定义了协处理器 0 的控制寄存器。
   - `REG_FCR0` 到 `REG_FCR31`: 定义了浮点单元的控制寄存器。
   - `REG_W0` 到 `REG_W31`: 定义了 MSA (MIPS SIMD Architecture) 寄存器。
   - `REG_HI`, `REG_LO`: 定义了乘法和除法指令使用的特殊寄存器。
   - `REG_SPECIAL`, `REGZERO`, `REGSP`, `REGSB`, `REGLINK`, `REGRET`, `REGARG`, `REGRT1`, `REGRT2`, `REGCTXT`, `REGG`, `REGTMP`, `FREGRET`:  定义了一些具有特殊用途的寄存器的别名。

3. **定义 DWARF 调试信息相关的寄存器映射:**
   - `MIPSDWARFRegisters`:  一个 map，用于将 Go 编译器内部的寄存器表示映射到 DWARF 调试信息中使用的寄存器编号。这对于调试器理解程序状态至关重要。

4. **定义指令标记 (Mark Flags):**
   - `FOLL`, `LABEL`, `LEAF`, `SYNC`, `BRANCH`, `LOAD`, `FCMP`, `NOSCHED`: 这些常量是用于标记指令属性的标志，例如是否是分支指令、是否是叶子函数等，供编译器优化和代码生成阶段使用。

5. **定义操作数类型 (Operand Classes):**
   - `C_NONE`, `C_REG`, `C_FREG`, `C_SCON`, `C_LCON`, `C_SAUTO`, `C_LAUTO` 等: 这些常量定义了汇编指令操作数的类型，例如寄存器、立即数、内存地址等。这有助于编译器正确解析和编码指令。

6. **定义 MIPS 汇编指令 (Opcodes):**
   - `AABSD`, `AADD`, `ABEQ`, `AMOVW`, `ASYSCALL` 等:  这些常量定义了 MIPS 架构的各种汇编指令。`obj.ABaseMIPS + obj.A_ARCHSPECIFIC + iota` 这种模式表明这些指令代码是在 `cmd/internal/obj` 包中定义的通用汇编指令基础上，添加了 MIPS 特有的指令。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言编译器中 **汇编器（assembler）** 和 **链接器（linker）** 的一部分实现，特别是针对 MIPS 架构。它负责：

* **将 Go 源代码编译成 MIPS 汇编代码:** 编译器在生成目标代码时，会使用这里定义的常量和指令来表示 MIPS 汇编指令。
* **处理 MIPS 架构的汇编代码:**  汇编器会解析包含这些指令的汇编文件，并将其转换为机器码。
* **生成 MIPS 架构的目标文件:**  这些定义有助于生成符合 MIPS 目标文件格式的代码和数据。
* **支持 MIPS 架构的调试:**  `MIPSDWARFRegisters` 用于生成包含调试信息的 ELF 文件。

**Go 代码举例说明:**

虽然 `a.out.go` 本身不是用户直接编写的 Go 代码，但它可以被 Go 编译器在编译用户代码时使用。例如，当编译包含 MIPS 特有操作的汇编代码时，这些常量就会被用到。

假设有一个包含 MIPS 汇编指令的 Go 文件（使用 `//go:nosplit` 和 `//go:noescape` 等指令，通常用于 runtime 包或底层操作）：

```go
package main

import "unsafe"

//go:nosplit
func add(a, b int32) int32 {
	// This is a highly simplified example and might not be directly compilable
	// without further context and setup for inline assembly.
	// It's meant to illustrate the concept.
	res := a + b
	return res
}

// 在实际的 Go 代码中，你不会直接这样写 MIPS 汇编，
// 而是通过 `asm` 功能（在某些情况下）或 Go 编译器自动生成。
// 以下是一个概念性的例子，说明编译器如何使用 a.out.go 中的定义。
//
// TEXT ·add(SB),$0-16
//  MOVW 8(SP), R1 // Load argument a from stack
//  MOVW 12(SP), R2 // Load argument b from stack
//  ADD R1, R2, R0  // Add R1 and R2, store result in R0
//  MOVW R0, 16(SP) // Store result back to stack for return
//  RET

func main() {
	x := int32(5)
	y := int32(10)
	sum := add(x, y)
	println(sum)
}
```

在这个例子中，虽然 `add` 函数是用 Go 语法写的，但当 Go 编译器为 MIPS 架构编译这段代码时，它内部会将 `a + b` 的操作转换为对应的 MIPS 汇编指令，例如 `ADD` 指令，而 `a.out.go` 中定义的 `AADD` 常量就代表了这个指令。编译器还会使用 `REG_R0`、`REG_R1` 等常量来表示 MIPS 寄存器。

**代码推理和假设的输入与输出:**

由于 `a.out.go` 主要定义常量，直接的代码推理不太适用。但可以理解其定义如何影响汇编代码的生成。

**假设的输入:**  Go 编译器需要将 `a + b` 这个简单的加法操作编译成 MIPS 汇编代码。

**编译器内部的处理:**

1. 编译器识别出 `+` 操作需要进行加法运算。
2. 针对 MIPS 架构，编译器会查找对应的 MIPS 加法指令，即 `AADD`。
3. 编译器需要将变量 `a` 和 `b` 分配到 MIPS 寄存器中，例如 `REG_R1` 和 `REG_R2`。
4. 编译器生成汇编指令，类似于：`ADD R1, R2, R0` （将 R1 和 R2 的值相加，结果存入 R0）。
5. 编译器可能还会生成加载指令，将 `a` 和 `b` 的值从内存加载到寄存器，以及存储指令将结果写回内存或寄存器。

**输出:**  最终生成的目标文件中的 MIPS 机器码会包含与 `ADD` 指令对应的编码。

**命令行参数的具体处理:**

`a.out.go` 本身不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的更高层。但是，编译器接收的架构相关的参数（例如 `-arch=mips64`）会决定是否使用 `mips/a.out.go` 中的定义。

例如，当使用 `go build -arch=mips64 myprogram.go` 命令时，编译器会选择 MIPS 64 位架构的后端，并使用 `go/src/cmd/internal/obj/mips/a.out.go` 中定义的常量和指令集来生成目标代码。

**使用者易犯错的点:**

由于 `a.out.go` 是 Go 编译器内部的实现，普通 Go 语言开发者不会直接修改或使用它。因此，直接使用 `a.out.go` 导致的错误不太可能发生。

然而，如果开发者编写内联汇编代码（通常在 `runtime` 包或进行底层操作时），可能会因为对 MIPS 架构的指令、寄存器理解不透彻，导致内联汇编代码错误。

**举例说明内联汇编的常见错误（概念性）：**

假设开发者想使用内联汇编手动进行加法操作，可能会犯以下错误：

1. **使用了不存在的寄存器名称:**  例如，误写成 `ADD R33, R1, R0`，因为 MIPS 只有 R0 到 R31 这 32 个通用寄存器。
2. **使用了错误的指令:** 例如，想进行加法，却使用了乘法指令。
3. **没有正确处理函数调用约定:**  在内联汇编中调用其他函数时，如果没有按照 MIPS 的 ABI (Application Binary Interface) 保存和恢复寄存器，可能会导致程序崩溃。
4. **对立即数的范围理解错误:**  某些 MIPS 指令对立即数的大小有限制，如果使用的立即数超出范围，会导致汇编错误。

总而言之，`go/src/cmd/internal/obj/mips/a.out.go` 是 Go 语言编译器中至关重要的组成部分，它为 MIPS 架构的代码生成提供了基础的定义和支持。理解它的功能有助于深入了解 Go 语言的编译过程以及目标代码的生成机制。

### 提示词
```
这是路径为go/src/cmd/internal/obj/mips/a.out.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
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

package mips

import (
	"cmd/internal/obj"
)

//go:generate go run ../stringer.go -i $GOFILE -o anames.go -p mips

/*
 * mips 64
 */
const (
	NSNAME = 8
	NSYM   = 50
	NREG   = 32 /* number of general registers */
	NFREG  = 32 /* number of floating point registers */
	NWREG  = 32 /* number of MSA registers */
)

const (
	REG_R0 = obj.RBaseMIPS + iota // must be a multiple of 32
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

	REG_F0 // must be a multiple of 32
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

	// co-processor 0 control registers
	REG_M0 // must be a multiple of 32
	REG_M1
	REG_M2
	REG_M3
	REG_M4
	REG_M5
	REG_M6
	REG_M7
	REG_M8
	REG_M9
	REG_M10
	REG_M11
	REG_M12
	REG_M13
	REG_M14
	REG_M15
	REG_M16
	REG_M17
	REG_M18
	REG_M19
	REG_M20
	REG_M21
	REG_M22
	REG_M23
	REG_M24
	REG_M25
	REG_M26
	REG_M27
	REG_M28
	REG_M29
	REG_M30
	REG_M31

	// FPU control registers
	REG_FCR0 // must be a multiple of 32
	REG_FCR1
	REG_FCR2
	REG_FCR3
	REG_FCR4
	REG_FCR5
	REG_FCR6
	REG_FCR7
	REG_FCR8
	REG_FCR9
	REG_FCR10
	REG_FCR11
	REG_FCR12
	REG_FCR13
	REG_FCR14
	REG_FCR15
	REG_FCR16
	REG_FCR17
	REG_FCR18
	REG_FCR19
	REG_FCR20
	REG_FCR21
	REG_FCR22
	REG_FCR23
	REG_FCR24
	REG_FCR25
	REG_FCR26
	REG_FCR27
	REG_FCR28
	REG_FCR29
	REG_FCR30
	REG_FCR31

	// MSA registers
	// The lower bits of W registers are alias to F registers
	REG_W0 // must be a multiple of 32
	REG_W1
	REG_W2
	REG_W3
	REG_W4
	REG_W5
	REG_W6
	REG_W7
	REG_W8
	REG_W9
	REG_W10
	REG_W11
	REG_W12
	REG_W13
	REG_W14
	REG_W15
	REG_W16
	REG_W17
	REG_W18
	REG_W19
	REG_W20
	REG_W21
	REG_W22
	REG_W23
	REG_W24
	REG_W25
	REG_W26
	REG_W27
	REG_W28
	REG_W29
	REG_W30
	REG_W31

	REG_HI
	REG_LO

	REG_LAST = REG_LO // the last defined register

	REG_SPECIAL = REG_M0

	REGZERO = REG_R0 /* set to zero */
	REGSP   = REG_R29
	REGSB   = REG_R28
	REGLINK = REG_R31
	REGRET  = REG_R1
	REGARG  = -1      /* -1 disables passing the first argument in register */
	REGRT1  = REG_R1  /* reserved for runtime, duffzero and duffcopy */
	REGRT2  = REG_R2  /* reserved for runtime, duffcopy */
	REGCTXT = REG_R22 /* context for closures */
	REGG    = REG_R30 /* G */
	REGTMP  = REG_R23 /* used by the linker */
	FREGRET = REG_F0
)

// https://llvm.org/svn/llvm-project/llvm/trunk/lib/Target/Mips/MipsRegisterInfo.td search for DwarfRegNum
// https://gcc.gnu.org/viewcvs/gcc/trunk/gcc/config/mips/mips.c?view=co&revision=258099&content-type=text%2Fplain search for mips_dwarf_regno
// For now, this is adequate for both 32 and 64 bit.
var MIPSDWARFRegisters = map[int16]int16{}

func init() {
	// f assigns dwarfregisters[from:to] = (base):(to-from+base)
	f := func(from, to, base int16) {
		for r := int16(from); r <= to; r++ {
			MIPSDWARFRegisters[r] = (r - from) + base
		}
	}
	f(REG_R0, REG_R31, 0)
	f(REG_F0, REG_F31, 32) // For 32-bit MIPS, compiler only uses even numbered registers --  see cmd/compile/internal/ssa/gen/MIPSOps.go
	MIPSDWARFRegisters[REG_HI] = 64
	MIPSDWARFRegisters[REG_LO] = 65
	// The lower bits of W registers are alias to F registers
	f(REG_W0, REG_W31, 32)
}

const (
	BIG = 32766
)

const (
	/* mark flags */
	FOLL    = 1 << 0
	LABEL   = 1 << 1
	LEAF    = 1 << 2
	SYNC    = 1 << 3
	BRANCH  = 1 << 4
	LOAD    = 1 << 5
	FCMP    = 1 << 6
	NOSCHED = 1 << 7

	NSCHED = 20
)

//go:generate go run ../mkcnames.go -i a.out.go -o anames0.go -p mips
const (
	C_NONE = iota
	C_REG
	C_FREG
	C_FCREG
	C_MREG /* special processor register */
	C_WREG /* MSA registers */
	C_HI
	C_LO
	C_ZCON
	C_SCON /* 16 bit signed */
	C_UCON /* 32 bit signed, low 16 bits 0 */
	C_ADD0CON
	C_AND0CON
	C_ADDCON /* -0x8000 <= v < 0 */
	C_ANDCON /* 0 < v <= 0xFFFF */
	C_LCON   /* other 32 */
	C_DCON   /* other 64 (could subdivide further) */
	C_SACON  /* $n(REG) where n <= int16 */
	C_SECON
	C_LACON /* $n(REG) where int16 < n <= int32 */
	C_LECON
	C_DACON /* $n(REG) where int32 < n */
	C_STCON /* $tlsvar */
	C_SBRA
	C_LBRA
	C_SAUTO
	C_LAUTO
	C_SEXT
	C_LEXT
	C_ZOREG
	C_SOREG
	C_LOREG
	C_GOK
	C_ADDR
	C_TLS
	C_TEXTSIZE

	C_NCLASS /* must be the last */
)

const (
	AABSD = obj.ABaseMIPS + obj.A_ARCHSPECIFIC + iota
	AABSF
	AABSW
	AADD
	AADDD
	AADDF
	AADDU
	AADDW
	AAND
	ABEQ
	ABFPF
	ABFPT
	ABGEZ
	ABGEZAL
	ABGTZ
	ABLEZ
	ABLTZ
	ABLTZAL
	ABNE
	ABREAK
	ACLO
	ACLZ
	ACMOVF
	ACMOVN
	ACMOVT
	ACMOVZ
	ACMPEQD
	ACMPEQF
	ACMPGED
	ACMPGEF
	ACMPGTD
	ACMPGTF
	ADIV
	ADIVD
	ADIVF
	ADIVU
	ADIVW
	AGOK
	ALL
	ALLV
	ALUI
	AMADD
	AMOVB
	AMOVBU
	AMOVD
	AMOVDF
	AMOVDW
	AMOVF
	AMOVFD
	AMOVFW
	AMOVH
	AMOVHU
	AMOVW
	AMOVWD
	AMOVWF
	AMOVWL
	AMOVWR
	AMSUB
	AMUL
	AMULD
	AMULF
	AMULU
	AMULW
	ANEGD
	ANEGF
	ANEGW
	ANEGV
	ANOOP // hardware nop
	ANOR
	AOR
	AREM
	AREMU
	ARFE
	AROTR
	AROTRV
	ASC
	ASCV
	ASEB
	ASEH
	ASGT
	ASGTU
	ASLL
	ASQRTD
	ASQRTF
	ASRA
	ASRL
	ASUB
	ASUBD
	ASUBF
	ASUBU
	ASUBW
	ASYNC
	ASYSCALL
	ATEQ
	ATLBP
	ATLBR
	ATLBWI
	ATLBWR
	ATNE
	AWORD
	AWSBH
	AXOR

	/* 64-bit */
	AMOVV
	AMOVVL
	AMOVVR
	ASLLV
	ASRAV
	ASRLV
	ADIVV
	ADIVVU
	AREMV
	AREMVU
	AMULV
	AMULVU
	AADDV
	AADDVU
	ASUBV
	ASUBVU
	ADSBH
	ADSHD

	/* 64-bit FP */
	ATRUNCFV
	ATRUNCDV
	ATRUNCFW
	ATRUNCDW
	AMOVWU
	AMOVFV
	AMOVDV
	AMOVVF
	AMOVVD

	/* MSA */
	AVMOVB
	AVMOVH
	AVMOVW
	AVMOVD

	ALAST

	// aliases
	AJMP = obj.AJMP
	AJAL = obj.ACALL
	ARET = obj.ARET
)

func init() {
	// The asm encoder generally assumes that the lowest 5 bits of the
	// REG_XX constants match the machine instruction encoding, i.e.
	// the lowest 5 bits is the register number.
	// Check this here.
	if REG_R0%32 != 0 {
		panic("REG_R0 is not a multiple of 32")
	}
	if REG_F0%32 != 0 {
		panic("REG_F0 is not a multiple of 32")
	}
	if REG_M0%32 != 0 {
		panic("REG_M0 is not a multiple of 32")
	}
	if REG_FCR0%32 != 0 {
		panic("REG_FCR0 is not a multiple of 32")
	}
	if REG_W0%32 != 0 {
		panic("REG_W0 is not a multiple of 32")
	}
}
```