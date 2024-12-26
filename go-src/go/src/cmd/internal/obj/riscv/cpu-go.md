Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Initial Understanding:** The first step is to recognize this is a Go source file related to the RISC-V architecture within the Go compiler (`cmd/internal/obj`). The `package riscv` declaration confirms this. The copyright header indicates it's part of the Go project.

2. **Identify Core Purpose:** Scanning the code, especially the `const` block, reveals a central theme: defining constants related to RISC-V architecture elements. The names like `REG_X0`, `REG_F0`, `REG_V0`, `REG_ZERO`, `REG_SP`, etc., strongly suggest it's about register definitions.

3. **Categorize the Content:**  As I go through the code, I can start categorizing the information:

    * **Register Definitions:**  The largest section defines integer, floating-point, and vector registers with numerical assignments. It also maps common ABI names (like `REG_SP` for stack pointer) to the base register names. Runtime-specific registers (`REG_CTXT`, `REG_G`) are also defined.

    * **DWARF Register Mapping:** The `RISCV64DWARFRegisters` map explicitly connects Go's internal register representation to DWARF debugging information. This is crucial for debuggers to understand the register context.

    * **Instruction Flags:** The `Prog.Mark` constants (`USES_REG_TMP`, `NEED_JAL_RELOC`, etc.) point towards flags used during the assembly/linking process. These flags likely signal specific requirements for instruction processing.

    * **Instruction Mnemonics:** The massive `const` block defining `AADDI`, `ASLTI`, `AJAL`, etc., clearly lists RISC-V instruction mnemonics. The comments mention "opcodes" and "opcodes-pseudo," confirming this.

    * **Rounding Mode Handling:**  The `rmSuffixSet`, `rmSuffixEncode`, and `rmSuffixString` functions indicate support for handling floating-point rounding modes.

    * **Unary Destination Instructions:** The `unaryDst` map lists instructions that write to their operands. This is a semantic detail needed for correct parsing.

    * **Instruction Encoding Masks:** The `BTypeImmMask`, `ITypeImmMask`, etc., constants define bitmasks used to extract specific parts of instruction encodings, particularly immediate values.

4. **Infer Functionality:** Based on the identified categories, I can infer the following functionalities:

    * **Register Management:** Defining and mapping registers is fundamental for any compiler targeting a specific architecture. This allows the compiler to refer to registers using meaningful names.

    * **Debugging Support:** The DWARF mapping is essential for generating debug information that allows developers to inspect program state.

    * **Code Generation and Linking:** The instruction flags suggest that this file plays a role in the code generation pipeline, specifically in determining when relocations are needed. Relocations are necessary to resolve addresses at link time.

    * **Assembly Parsing:** The instruction mnemonics and the `unaryDst` map are critical for the assembler to parse RISC-V assembly code correctly.

    * **Floating-Point Support:** The rounding mode handling demonstrates support for floating-point operations according to the RISC-V specification.

    * **Instruction Encoding/Decoding:** The masks imply operations related to encoding or decoding RISC-V instructions at the binary level.

5. **Consider Go Language Features:**  I look for specific Go features being used:

    * **Constants (`const`):** Heavily used for defining numerical values and strings.
    * **`iota`:** Used for automatically incrementing integer constants, making register definitions concise.
    * **Maps (`map`):** Used for mapping register names to DWARF numbers and for storing rounding mode suffixes.
    * **Stringer (`//go:generate`):** The comment indicates that the `stringer` tool is used to generate code (likely for converting instruction opcodes to strings), showing integration with Go's code generation features.
    * **Packages (`package` and `import`):** Demonstrates Go's modularity. The import of `cmd/internal/obj` is crucial, showing its role within the Go compiler toolchain.

6. **Develop Examples (if applicable):**  For the register definitions, it's straightforward to illustrate how these constants might be used within the compiler. Showing how a register like `REG_SP` is used in assembly or how the DWARF mapping could be accessed in a debugger would be relevant.

7. **Command-Line Arguments (if applicable):**  In this particular snippet, there's no direct handling of command-line arguments. However, it's important to note that the broader Go compiler toolchain (of which this is a part) *does* use command-line arguments. This distinction is important.

8. **Common Mistakes (if applicable):**  While not explicitly present in the code, I could consider potential errors related to *using* these definitions. For example, incorrectly using register numbers directly instead of the defined constants could be a mistake.

9. **Structure the Output:** Finally, I organize the findings into logical sections (Functionality, Go Feature Implementation, Code Inference, Command-line Args, Common Mistakes) to present a clear and comprehensive analysis.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Might have initially focused too much on the specific instruction mnemonics.
* **Correction:** Realized the broader context is about *defining* these elements for the compiler, not necessarily *implementing* their behavior.
* **Initial thought:** Perhaps overlooked the significance of the DWARF mapping.
* **Correction:** Recognized its importance for debugging and integrated it into the analysis.
* **Initial thought:** Considered if this file *directly* executes code.
* **Correction:** Understood it's primarily a data definition file used by other parts of the compiler.

By following this structured approach, I can systematically analyze the code snippet and extract meaningful information about its functionality and role within the Go compiler.
这是路径为 `go/src/cmd/internal/obj/riscv/cpu.go` 的 Go 语言实现的一部分，它主要定义了 RISC-V 架构相关的常量和数据结构，用于 Go 语言的 RISC-V 架构支持。

**功能列举：**

1. **定义 RISC-V 寄存器常量：**
   - 定义了通用寄存器 (X0-X31) 的常量，并为其分配了在 Go 内部表示中使用的数值。
   - 定义了浮点寄存器 (F0-F31) 的常量。
   - 定义了向量寄存器 (V0-V31) 的常量。
   - 定义了通用寄存器的 ABI (Application Binary Interface) 名称，例如 `REG_ZERO`，`REG_SP`，`REG_RA` 等，方便在汇编代码中使用。
   - 定义了 Go 运行时使用的特殊寄存器，例如 `REG_CTXT` (上下文指针)，`REG_G` (goroutine 指针)。
   - 定义了浮点寄存器的 ABI 名称，例如 `REG_FT0`，`REG_FS0` 等。
   - 定义了 SSA (Static Single Assignment) 编译器使用的寄存器名称，例如 `REGSP`，`REGG`。

2. **定义 RISC-V DWARF 调试信息寄存器映射：**
   - `RISCV64DWARFRegisters` 映射表将 Go 内部使用的寄存器常量映射到 DWARF 调试信息标准中 RISC-V 架构的寄存器编号。这对于调试器正确理解程序状态至关重要。

3. **定义 `Prog.Mark` 标志位常量：**
   - 定义了用于标记 `obj.Prog` 结构体的标志位，这些标志位用于在汇编和链接过程中指示指令的特殊需求，例如是否使用了临时寄存器、是否需要特定的重定位类型。

4. **定义 RISC-V 指令助记符常量：**
   - 定义了大量 RISC-V 指令集的助记符常量，包括基础指令、扩展指令（如乘除法、原子操作、浮点运算、向量运算）以及伪指令。这些常量用于表示 RISC-V 的各种机器指令。

5. **定义浮点舍入模式相关常量和函数：**
   - `rmSuffixSet` 存储了浮点舍入模式的字符串表示和对应的编码值。
   - `rmSuffixEncode` 函数将舍入模式字符串编码为数值。
   - `rmSuffixString` 函数将数值解码为舍入模式字符串。
   - 定义了具体的舍入模式常量，例如 `RM_RNE` (Round to Nearest, ties to Even)。

6. **定义一元目标指令集合：**
   - `unaryDst` 映射表存储了那些将结果写入其操作数的一元指令的助记符。这在汇编解析时用于正确构建抽象语法树 (AST)。

7. **定义指令编码掩码常量：**
   - 定义了不同指令格式 (B-type, CB-type, CJ-type, I-type, J-type, S-type, U-type) 的立即数字段掩码。这些掩码用于在指令编码和解码过程中提取立即数部分。

**推理 Go 语言功能实现：**

这个文件是 Go 编译器中 RISC-V 后端实现的关键部分，它定义了 RISC-V 架构的各种抽象，使得 Go 编译器能够生成针对 RISC-V 架构的机器码。

**Go 代码举例说明 (寄存器使用):**

假设我们有一个简单的 Go 函数，需要在 RISC-V 架构上执行，它会将两个整数相加：

```go
package main

func add(a, b int64) int64 {
	return a + b
}

func main() {
	result := add(5, 10)
	println(result)
}
```

在编译这个 Go 程序时，`cmd/internal/obj/riscv/cpu.go` 中定义的寄存器常量会被用来生成汇编代码。例如，参数 `a` 和 `b` 可能会被加载到 `REG_A0` 和 `REG_A1` 寄存器（根据 RISC-V 的调用约定），加法指令可能会使用这些寄存器，结果可能会存储回某个寄存器。虽然我们看不到直接使用这些常量的 Go 代码，但在编译器的内部实现中，它们会被大量使用。

**代码推理 (DWARF 寄存器映射):**

假设调试器需要知道当前程序中 `REG_X5` 寄存器的值。

**假设输入：** 调试器请求获取 DWARF 寄存器编号为 `5` 的寄存器的值。

**代码推理：** 调试器会查阅 `RISCV64DWARFRegisters` 映射表。根据定义：

```go
var RISCV64DWARFRegisters = map[int16]int16{
	// ...
	REG_X5:  5,
	// ...
}
```

调试器会发现 DWARF 寄存器编号 `5` 对应于 Go 内部的 `REG_X5` 常量。然后，调试器会进一步查找 Go 运行时中 `REG_X5` 对应的物理寄存器的值。

**输出：** 调试器显示 `REG_X5` 寄存器的当前值。

**命令行参数的具体处理：**

这个 `cpu.go` 文件本身不直接处理命令行参数。它作为 Go 编译器的一部分，其行为受到 Go 编译器 `compile` 命令的控制。例如，当使用 `go build` 或 `go run` 命令时，编译器会根据目标架构（通过 `GOARCH=riscv64` 等环境变量指定）加载相应的架构特定文件，包括 `cpu.go`。

具体的命令行参数处理发生在 Go 编译器的其他部分，例如 `cmd/compile/internal/gc` 包。这些参数会影响编译过程的各个方面，例如优化级别、是否生成调试信息等。

**使用者易犯错的点：**

普通 Go 开发者通常不会直接与 `cmd/internal/obj/riscv/cpu.go` 文件交互。这个文件是 Go 编译器内部实现的一部分。

但是，对于那些深入研究 Go 编译器或者编写汇编代码的开发者，可能会遇到以下易犯错的点：

1. **直接使用魔术数字而不是寄存器常量：**  在编写 RISC-V 汇编代码时，应该使用 `cpu.go` 中定义的寄存器常量 (例如 `REG_SP`) 而不是直接使用其数值 (例如 `2`)。这样可以提高代码的可读性和可维护性。如果未来寄存器的分配发生变化，只需要修改 `cpu.go` 中的定义，而不需要修改所有使用了该寄存器的汇编代码。

   **错误示例 (假设直接写汇编):**
   ```assembly
   // 错误：直接使用数字 2 代表 SP
   MOV 2, ...
   ```

   **正确示例 (假设使用 Go 的汇编特性):**
   ```go
   // 正确：使用常量 REG_SP
   // 在实际的 Go 汇编中，会使用如 `SP` 这样的符号，
   // 但其底层映射关系由 cpu.go 定义
   ```

2. **混淆 ABI 名称和基础寄存器名称：** 了解 ABI 名称（如 `REG_SP`）和其对应的基础寄存器名称（如 `REG_X2`）之间的关系很重要。在不同的上下文，可能需要使用不同的名称。

总而言之，`go/src/cmd/internal/obj/riscv/cpu.go` 是 Go 语言 RISC-V 架构支持的核心数据定义文件，它为编译器的后续步骤提供了必要的架构信息。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/riscv/cpu.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
//	Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2008 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2008 Lucent Technologies Inc. and others
//	Portions Copyright © 2009 The Go Authors.  All rights reserved.
//	Portions Copyright © 2019 The Go Authors.  All rights reserved.
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

package riscv

import (
	"errors"
	"fmt"

	"cmd/internal/obj"
)

//go:generate go run ../stringer.go -i $GOFILE -o anames.go -p riscv

const (
	// Base register numberings.
	REG_X0 = obj.RBaseRISCV + iota
	REG_X1
	REG_X2
	REG_X3
	REG_X4
	REG_X5
	REG_X6
	REG_X7
	REG_X8
	REG_X9
	REG_X10
	REG_X11
	REG_X12
	REG_X13
	REG_X14
	REG_X15
	REG_X16
	REG_X17
	REG_X18
	REG_X19
	REG_X20
	REG_X21
	REG_X22
	REG_X23
	REG_X24
	REG_X25
	REG_X26
	REG_X27
	REG_X28
	REG_X29
	REG_X30
	REG_X31

	// Floating Point register numberings.
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

	// Vector register numberings.
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

	// This marks the end of the register numbering.
	REG_END

	// General registers reassigned to ABI names.
	REG_ZERO = REG_X0
	REG_RA   = REG_X1 // aka REG_LR
	REG_SP   = REG_X2
	REG_GP   = REG_X3 // aka REG_SB
	REG_TP   = REG_X4
	REG_T0   = REG_X5
	REG_T1   = REG_X6
	REG_T2   = REG_X7
	REG_S0   = REG_X8
	REG_S1   = REG_X9
	REG_A0   = REG_X10
	REG_A1   = REG_X11
	REG_A2   = REG_X12
	REG_A3   = REG_X13
	REG_A4   = REG_X14
	REG_A5   = REG_X15
	REG_A6   = REG_X16
	REG_A7   = REG_X17
	REG_S2   = REG_X18
	REG_S3   = REG_X19
	REG_S4   = REG_X20
	REG_S5   = REG_X21
	REG_S6   = REG_X22
	REG_S7   = REG_X23
	REG_S8   = REG_X24
	REG_S9   = REG_X25
	REG_S10  = REG_X26 // aka REG_CTXT
	REG_S11  = REG_X27 // aka REG_G
	REG_T3   = REG_X28
	REG_T4   = REG_X29
	REG_T5   = REG_X30
	REG_T6   = REG_X31 // aka REG_TMP

	// Go runtime register names.
	REG_CTXT = REG_S10 // Context for closures.
	REG_G    = REG_S11 // G pointer.
	REG_LR   = REG_RA  // Link register.
	REG_TMP  = REG_T6  // Reserved for assembler use.

	// ABI names for floating point registers.
	REG_FT0  = REG_F0
	REG_FT1  = REG_F1
	REG_FT2  = REG_F2
	REG_FT3  = REG_F3
	REG_FT4  = REG_F4
	REG_FT5  = REG_F5
	REG_FT6  = REG_F6
	REG_FT7  = REG_F7
	REG_FS0  = REG_F8
	REG_FS1  = REG_F9
	REG_FA0  = REG_F10
	REG_FA1  = REG_F11
	REG_FA2  = REG_F12
	REG_FA3  = REG_F13
	REG_FA4  = REG_F14
	REG_FA5  = REG_F15
	REG_FA6  = REG_F16
	REG_FA7  = REG_F17
	REG_FS2  = REG_F18
	REG_FS3  = REG_F19
	REG_FS4  = REG_F20
	REG_FS5  = REG_F21
	REG_FS6  = REG_F22
	REG_FS7  = REG_F23
	REG_FS8  = REG_F24
	REG_FS9  = REG_F25
	REG_FS10 = REG_F26
	REG_FS11 = REG_F27
	REG_FT8  = REG_F28
	REG_FT9  = REG_F29
	REG_FT10 = REG_F30
	REG_FT11 = REG_F31

	// Names generated by the SSA compiler.
	REGSP = REG_SP
	REGG  = REG_G
)

// https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-dwarf.adoc#dwarf-register-numbers
var RISCV64DWARFRegisters = map[int16]int16{
	// Integer Registers.
	REG_X0:  0,
	REG_X1:  1,
	REG_X2:  2,
	REG_X3:  3,
	REG_X4:  4,
	REG_X5:  5,
	REG_X6:  6,
	REG_X7:  7,
	REG_X8:  8,
	REG_X9:  9,
	REG_X10: 10,
	REG_X11: 11,
	REG_X12: 12,
	REG_X13: 13,
	REG_X14: 14,
	REG_X15: 15,
	REG_X16: 16,
	REG_X17: 17,
	REG_X18: 18,
	REG_X19: 19,
	REG_X20: 20,
	REG_X21: 21,
	REG_X22: 22,
	REG_X23: 23,
	REG_X24: 24,
	REG_X25: 25,
	REG_X26: 26,
	REG_X27: 27,
	REG_X28: 28,
	REG_X29: 29,
	REG_X30: 30,
	REG_X31: 31,

	// Floating-Point Registers.
	REG_F0:  32,
	REG_F1:  33,
	REG_F2:  34,
	REG_F3:  35,
	REG_F4:  36,
	REG_F5:  37,
	REG_F6:  38,
	REG_F7:  39,
	REG_F8:  40,
	REG_F9:  41,
	REG_F10: 42,
	REG_F11: 43,
	REG_F12: 44,
	REG_F13: 45,
	REG_F14: 46,
	REG_F15: 47,
	REG_F16: 48,
	REG_F17: 49,
	REG_F18: 50,
	REG_F19: 51,
	REG_F20: 52,
	REG_F21: 53,
	REG_F22: 54,
	REG_F23: 55,
	REG_F24: 56,
	REG_F25: 57,
	REG_F26: 58,
	REG_F27: 59,
	REG_F28: 60,
	REG_F29: 61,
	REG_F30: 62,
	REG_F31: 63,
}

// Prog.Mark flags.
const (
	// USES_REG_TMP indicates that a machine instruction generated from the
	// corresponding *obj.Prog uses the temporary register.
	USES_REG_TMP = 1 << iota

	// NEED_JAL_RELOC is set on JAL instructions to indicate that a
	// R_RISCV_JAL relocation is needed.
	NEED_JAL_RELOC

	// NEED_CALL_RELOC is set on an AUIPC instruction to indicate that it
	// is the first instruction in an AUIPC + JAL pair that needs a
	// R_RISCV_CALL relocation.
	NEED_CALL_RELOC

	// NEED_PCREL_ITYPE_RELOC is set on AUIPC instructions to indicate that
	// it is the first instruction in an AUIPC + I-type pair that needs a
	// R_RISCV_PCREL_ITYPE relocation.
	NEED_PCREL_ITYPE_RELOC

	// NEED_PCREL_STYPE_RELOC is set on AUIPC instructions to indicate that
	// it is the first instruction in an AUIPC + S-type pair that needs a
	// R_RISCV_PCREL_STYPE relocation.
	NEED_PCREL_STYPE_RELOC
)

// RISC-V mnemonics, as defined in the "opcodes" and "opcodes-pseudo" files
// at https://github.com/riscv/riscv-opcodes.
//
// As well as some pseudo-mnemonics (e.g. MOV) used only in the assembler.
//
// See also "The RISC-V Instruction Set Manual" at https://riscv.org/technical/specifications/.
//
// If you modify this table, you MUST run 'go generate' to regenerate anames.go!
const (
	//
	// Unprivileged ISA (version 20240411)
	//

	// 2.4: Integer Computational Instructions
	AADDI = obj.ABaseRISCV + obj.A_ARCHSPECIFIC + iota
	ASLTI
	ASLTIU
	AANDI
	AORI
	AXORI
	ASLLI
	ASRLI
	ASRAI
	ALUI
	AAUIPC
	AADD
	ASLT
	ASLTU
	AAND
	AOR
	AXOR
	ASLL
	ASRL
	ASUB
	ASRA

	// 2.5: Control Transfer Instructions
	AJAL
	AJALR
	ABEQ
	ABNE
	ABLT
	ABLTU
	ABGE
	ABGEU

	// 2.6: Load and Store Instructions
	ALW
	ALWU
	ALH
	ALHU
	ALB
	ALBU
	ASW
	ASH
	ASB

	// 2.7: Memory Ordering Instructions
	AFENCE

	// 4.2: Integer Computational Instructions (RV64I)
	AADDIW
	ASLLIW
	ASRLIW
	ASRAIW
	AADDW
	ASLLW
	ASRLW
	ASUBW
	ASRAW

	// 4.3: Load and Store Instructions (RV64I)
	ALD
	ASD

	// 7.1: CSR Instructions (Zicsr)
	ACSRRW
	ACSRRS
	ACSRRC
	ACSRRWI
	ACSRRSI
	ACSRRCI

	// 13.1: Multiplication Operations
	AMUL
	AMULH
	AMULHU
	AMULHSU
	AMULW

	// 13.2: Division Operations
	ADIV
	ADIVU
	AREM
	AREMU
	ADIVW
	ADIVUW
	AREMW
	AREMUW

	// 14.2: Load-Reserved/Store-Conditional Instructions (Zalrsc)
	ALRD
	ASCD
	ALRW
	ASCW

	// 14.4: Atomic Memory Operations (Zaamo)
	AAMOSWAPD
	AAMOADDD
	AAMOANDD
	AAMOORD
	AAMOXORD
	AAMOMAXD
	AAMOMAXUD
	AAMOMIND
	AAMOMINUD
	AAMOSWAPW
	AAMOADDW
	AAMOANDW
	AAMOORW
	AAMOXORW
	AAMOMAXW
	AAMOMAXUW
	AAMOMINW
	AAMOMINUW

	// 20.5: Single-Precision Load and Store Instructions
	AFLW
	AFSW

	// 20.6: Single-Precision Floating-Point Computational Instructions
	AFADDS
	AFSUBS
	AFMULS
	AFDIVS
	AFMINS
	AFMAXS
	AFSQRTS
	AFMADDS
	AFMSUBS
	AFNMADDS
	AFNMSUBS

	// 20.7: Single-Precision Floating-Point Conversion and Move Instructions
	AFCVTWS
	AFCVTLS
	AFCVTSW
	AFCVTSL
	AFCVTWUS
	AFCVTLUS
	AFCVTSWU
	AFCVTSLU
	AFSGNJS
	AFSGNJNS
	AFSGNJXS
	AFMVXS
	AFMVSX
	AFMVXW
	AFMVWX

	// 20.8: Single-Precision Floating-Point Compare Instructions
	AFEQS
	AFLTS
	AFLES

	// 20.9: Single-Precision Floating-Point Classify Instruction
	AFCLASSS

	// 21.3: Double-Precision Load and Store Instructions
	AFLD
	AFSD

	// 21.4: Double-Precision Floating-Point Computational Instructions
	AFADDD
	AFSUBD
	AFMULD
	AFDIVD
	AFMIND
	AFMAXD
	AFSQRTD
	AFMADDD
	AFMSUBD
	AFNMADDD
	AFNMSUBD

	// 21.5: Double-Precision Floating-Point Conversion and Move Instructions
	AFCVTWD
	AFCVTLD
	AFCVTDW
	AFCVTDL
	AFCVTWUD
	AFCVTLUD
	AFCVTDWU
	AFCVTDLU
	AFCVTSD
	AFCVTDS
	AFSGNJD
	AFSGNJND
	AFSGNJXD
	AFMVXD
	AFMVDX

	// 21.6: Double-Precision Floating-Point Compare Instructions
	AFEQD
	AFLTD
	AFLED

	// 21.7: Double-Precision Floating-Point Classify Instruction
	AFCLASSD

	// 22.1 Quad-Precision Load and Store Instructions
	AFLQ
	AFSQ

	// 22.2: Quad-Precision Computational Instructions
	AFADDQ
	AFSUBQ
	AFMULQ
	AFDIVQ
	AFMINQ
	AFMAXQ
	AFSQRTQ
	AFMADDQ
	AFMSUBQ
	AFNMADDQ
	AFNMSUBQ

	// 22.3 Quad-Precision Convert and Move Instructions
	AFCVTWQ
	AFCVTLQ
	AFCVTSQ
	AFCVTDQ
	AFCVTQW
	AFCVTQL
	AFCVTQS
	AFCVTQD
	AFCVTWUQ
	AFCVTLUQ
	AFCVTQWU
	AFCVTQLU
	AFSGNJQ
	AFSGNJNQ
	AFSGNJXQ

	// 22.4 Quad-Precision Floating-Point Compare Instructions
	AFEQQ
	AFLEQ
	AFLTQ

	// 22.5 Quad-Precision Floating-Point Classify Instruction
	AFCLASSQ

	// 28.4.1: Address Generation Instructions (Zba)
	AADDUW
	ASH1ADD
	ASH1ADDUW
	ASH2ADD
	ASH2ADDUW
	ASH3ADD
	ASH3ADDUW
	ASLLIUW

	// 28.4.2: Basic Bit Manipulation (Zbb)
	AANDN
	AORN
	AXNOR
	ACLZ
	ACLZW
	ACTZ
	ACTZW
	ACPOP
	ACPOPW
	AMAX
	AMAXU
	AMIN
	AMINU
	ASEXTB
	ASEXTH
	AZEXTH

	// 28.4.3: Bitwise Rotation (Zbb)
	AROL
	AROLW
	AROR
	ARORI
	ARORIW
	ARORW
	AORCB
	AREV8

	// 28.4.4: Single-bit Instructions (Zbs)
	ABCLR
	ABCLRI
	ABEXT
	ABEXTI
	ABINV
	ABINVI
	ABSET
	ABSETI

	//
	// RISC-V Vector ISA-extension (1.0) (Unprivileged 20240411)
	//

	// 31.6. Configuration-Setting Instructions
	AVSETVLI
	AVSETIVLI
	AVSETVL

	// 31.7.4. Vector Unit-Stride Instructions
	AVLE8V
	AVLE16V
	AVLE32V
	AVLE64V
	AVSE8V
	AVSE16V
	AVSE32V
	AVSE64V
	AVLMV
	AVSMV

	// 31.7.5. Vector Strided Instructions
	AVLSE8V
	AVLSE16V
	AVLSE32V
	AVLSE64V
	AVSSE8V
	AVSSE16V
	AVSSE32V
	AVSSE64V

	// 31.7.6. Vector Indexed Instructions
	AVLUXEI8V
	AVLUXEI16V
	AVLUXEI32V
	AVLUXEI64V
	AVLOXEI8V
	AVLOXEI16V
	AVLOXEI32V
	AVLOXEI64V
	AVSUXEI8V
	AVSUXEI16V
	AVSUXEI32V
	AVSUXEI64V
	AVSOXEI8V
	AVSOXEI16V
	AVSOXEI32V
	AVSOXEI64V

	// 31.7.7. Unit-stride Fault-Only-First Loads
	AVLE8FFV
	AVLE16FFV
	AVLE32FFV
	AVLE64FFV

	// 31.7.9. Vector Load/Store Whole Register Instructions
	AVL1RE8V
	AVL1RE16V
	AVL1RE32V
	AVL1RE64V
	AVL2RE8V
	AVL2RE16V
	AVL2RE32V
	AVL2RE64V
	AVL4RE8V
	AVL4RE16V
	AVL4RE32V
	AVL4RE64V
	AVL8RE8V
	AVL8RE16V
	AVL8RE32V
	AVL8RE64V
	AVS1RV
	AVS2RV
	AVS4RV
	AVS8RV

	// 31.11.1. Vector Single-Width Integer Add and Subtract
	AVADDVV
	AVADDVX
	AVADDVI
	AVSUBVV
	AVSUBVX
	AVRSUBVX
	AVRSUBVI

	// 31.11.2. Vector Widening Integer Add/Subtract
	AVWADDUVV
	AVWADDUVX
	AVWSUBUVV
	AVWSUBUVX
	AVWADDVV
	AVWADDVX
	AVWSUBVV
	AVWSUBVX
	AVWADDUWV
	AVWADDUWX
	AVWSUBUWV
	AVWSUBUWX
	AVWADDWV
	AVWADDWX
	AVWSUBWV
	AVWSUBWX

	// 31.11.3. Vector Integer Extension
	AVZEXTVF2
	AVSEXTVF2
	AVZEXTVF4
	AVSEXTVF4
	AVZEXTVF8
	AVSEXTVF8

	// 31.11.4. Vector Integer Add-with-Carry / Subtract-with-Borrow Instructions
	AVADCVVM
	AVADCVXM
	AVADCVIM
	AVMADCVVM
	AVMADCVXM
	AVMADCVIM
	AVMADCVV
	AVMADCVX
	AVMADCVI
	AVSBCVVM
	AVSBCVXM
	AVMSBCVVM
	AVMSBCVXM
	AVMSBCVV
	AVMSBCVX

	// 31.11.5. Vector Bitwise Logical Instructions
	AVANDVV
	AVANDVX
	AVANDVI
	AVORVV
	AVORVX
	AVORVI
	AVXORVV
	AVXORVX
	AVXORVI

	// 31.11.6. Vector Single-Width Shift Instructions
	AVSLLVV
	AVSLLVX
	AVSLLVI
	AVSRLVV
	AVSRLVX
	AVSRLVI
	AVSRAVV
	AVSRAVX
	AVSRAVI

	// 31.11.7. Vector Narrowing Integer Right Shift Instructions
	AVNSRLWV
	AVNSRLWX
	AVNSRLWI
	AVNSRAWV
	AVNSRAWX
	AVNSRAWI

	// 31.11.8. Vector Integer Compare Instructions
	AVMSEQVV
	AVMSEQVX
	AVMSEQVI
	AVMSNEVV
	AVMSNEVX
	AVMSNEVI
	AVMSLTUVV
	AVMSLTUVX
	AVMSLTVV
	AVMSLTVX
	AVMSLEUVV
	AVMSLEUVX
	AVMSLEUVI
	AVMSLEVV
	AVMSLEVX
	AVMSLEVI
	AVMSGTUVX
	AVMSGTUVI
	AVMSGTVX
	AVMSGTVI

	// 31.11.9. Vector Integer Min/Max Instructions
	AVMINUVV
	AVMINUVX
	AVMINVV
	AVMINVX
	AVMAXUVV
	AVMAXUVX
	AVMAXVV
	AVMAXVX

	// 31.11.10. Vector Single-Width Integer Multiply Instructions
	AVMULVV
	AVMULVX
	AVMULHVV
	AVMULHVX
	AVMULHUVV
	AVMULHUVX
	AVMULHSUVV
	AVMULHSUVX

	// 31.11.11. Vector Integer Divide Instructions
	AVDIVUVV
	AVDIVUVX
	AVDIVVV
	AVDIVVX
	AVREMUVV
	AVREMUVX
	AVREMVV
	AVREMVX

	// 31.11.12. Vector Widening Integer Multiply Instructions
	AVWMULVV
	AVWMULVX
	AVWMULUVV
	AVWMULUVX
	AVWMULSUVV
	AVWMULSUVX

	// 31.11.13. Vector Single-Width Integer Multiply-Add Instructions
	AVMACCVV
	AVMACCVX
	AVNMSACVV
	AVNMSACVX
	AVMADDVV
	AVMADDVX
	AVNMSUBVV
	AVNMSUBVX

	// 31.11.14. Vector Widening Integer Multiply-Add Instructions
	AVWMACCUVV
	AVWMACCUVX
	AVWMACCVV
	AVWMACCVX
	AVWMACCSUVV
	AVWMACCSUVX
	AVWMACCUSVX

	// 31.11.15. Vector Integer Merge Instructions
	AVMERGEVVM
	AVMERGEVXM
	AVMERGEVIM

	// 31.11.16. Vector Integer Move Instructions
	AVMVVV
	AVMVVX
	AVMVVI

	// 31.12.1. Vector Single-Width Saturating Add and Subtract
	AVSADDUVV
	AVSADDUVX
	AVSADDUVI
	AVSADDVV
	AVSADDVX
	AVSADDVI
	AVSSUBUVV
	AVSSUBUVX
	AVSSUBVV
	AVSSUBVX

	// 31.12.2. Vector Single-Width Averaging Add and Subtract
	AVAADDUVV
	AVAADDUVX
	AVAADDVV
	AVAADDVX
	AVASUBUVV
	AVASUBUVX
	AVASUBVV
	AVASUBVX

	// 31.12.3. Vector Single-Width Fractional Multiply with Rounding and Saturation
	AVSMULVV
	AVSMULVX

	// 31.12.4. Vector Single-Width Scaling Shift Instructions
	AVSSRLVV
	AVSSRLVX
	AVSSRLVI
	AVSSRAVV
	AVSSRAVX
	AVSSRAVI

	// 31.12.5. Vector Narrowing Fixed-Point Clip Instructions
	AVNCLIPUWV
	AVNCLIPUWX
	AVNCLIPUWI
	AVNCLIPWV
	AVNCLIPWX
	AVNCLIPWI

	// 31.13.2. Vector Single-Width Floating-Point Add/Subtract Instructions
	AVFADDVV
	AVFADDVF
	AVFSUBVV
	AVFSUBVF
	AVFRSUBVF

	// 31.13.3. Vector Widening Floating-Point Add/Subtract Instructions
	AVFWADDVV
	AVFWADDVF
	AVFWSUBVV
	AVFWSUBVF
	AVFWADDWV
	AVFWADDWF
	AVFWSUBWV
	AVFWSUBWF

	// 31.13.4. Vector Single-Width Floating-Point Multiply/Divide Instructions
	AVFMULVV
	AVFMULVF
	AVFDIVVV
	AVFDIVVF
	AVFRDIVVF

	// 31.13.5. Vector Widening Floating-Point Multiply
	AVFWMULVV
	AVFWMULVF

	// 31.13.6. Vector Single-Width Floating-Point Fused Multiply-Add Instructions
	AVFMACCVV
	AVFMACCVF
	AVFNMACCVV
	AVFNMACCVF
	AVFMSACVV
	AVFMSACVF
	AVFNMSACVV
	AVFNMSACVF
	AVFMADDVV
	AVFMADDVF
	AVFNMADDVV
	AVFNMADDVF
	AVFMSUBVV
	AVFMSUBVF
	AVFNMSUBVV
	AVFNMSUBVF

	// 31.13.7. Vector Widening Floating-Point Fused Multiply-Add Instructions
	AVFWMACCVV
	AVFWMACCVF
	AVFWNMACCVV
	AVFWNMACCVF
	AVFWMSACVV
	AVFWMSACVF
	AVFWNMSACVV
	AVFWNMSACVF

	// 31.13.8. Vector Floating-Point Square-Root Instruction
	AVFSQRTV

	// 31.13.9. Vector Floating-Point Reciprocal Square-Root Estimate Instruction
	AVFRSQRT7V

	// 31.13.10. Vector Floating-Point Reciprocal Estimate Instruction
	AVFREC7V

	// 31.13.11. Vector Floating-Point MIN/MAX Instructions
	AVFMINVV
	AVFMINVF
	AVFMAXVV
	AVFMAXVF

	// 31.13.12. Vector Floating-Point Sign-Injection Instructions
	AVFSGNJVV
	AVFSGNJVF
	AVFSGNJNVV
	AVFSGNJNVF
	AVFSGNJXVV
	AVFSGNJXVF

	// 31.13.13. Vector Floating-Point Compare Instructions
	AVMFEQVV
	AVMFEQVF
	AVMFNEVV
	AVMFNEVF
	AVMFLTVV
	AVMFLTVF
	AVMFLEVV
	AVMFLEVF
	AVMFGTVF
	AVMFGEVF

	// 31.13.14. Vector Floating-Point Classify Instruction
	AVFCLASSV

	// 31.13.15. Vector Floating-Point Merge Instruction
	AVFMERGEVFM

	// 31.13.16. Vector Floating-Point Move Instruction
	AVFMVVF

	// 31.13.17. Single-Width Floating-Point/Integer Type-Convert Instructions
	AVFCVTXUFV
	AVFCVTXFV
	AVFCVTRTZXUFV
	AVFCVTRTZXFV
	AVFCVTFXUV
	AVFCVTFXV

	// 31.13.18. Widening Floating-Point/Integer Type-Convert Instructions
	AVFWCVTXUFV
	AVFWCVTXFV
	AVFWCVTRTZXUFV
	AVFWCVTRTZXFV
	AVFWCVTFXUV
	AVFWCVTFXV
	AVFWCVTFFV

	// 31.13.19. Narrowing Floating-Point/Integer Type-Convert Instructions
	AVFNCVTXUFW
	AVFNCVTXFW
	AVFNCVTRTZXUFW
	AVFNCVTRTZXFW
	AVFNCVTFXUW
	AVFNCVTFXW
	AVFNCVTFFW
	AVFNCVTRODFFW

	// 31.14.1. Vector Single-Width Integer Reduction Instructions
	AVREDSUMVS
	AVREDMAXUVS
	AVREDMAXVS
	AVREDMINUVS
	AVREDMINVS
	AVREDANDVS
	AVREDORVS
	AVREDXORVS

	// 31.14.2. Vector Widening Integer Reduction Instructions
	AVWREDSUMUVS
	AVWREDSUMVS

	// 31.14.3. Vector Single-Width Floating-Point Reduction Instructions
	AVFREDOSUMVS
	AVFREDUSUMVS
	AVFREDMAXVS
	AVFREDMINVS

	// 31.14.4. Vector Widening Floating-Point Reduction Instructions
	AVFWREDOSUMVS
	AVFWREDUSUMVS

	// 31.15. Vector Mask Instructions
	AVMANDMM
	AVMNANDMM
	AVMANDNMM
	AVMXORMM
	AVMORMM
	AVMNORMM
	AVMORNMM
	AVMXNORMM
	AVCPOPM
	AVFIRSTM
	AVMSBFM
	AVMSIFM
	AVMSOFM
	AVIOTAM
	AVIDV

	// 31.16.1. Integer Scalar Move Instructions
	AVMVXS
	AVMVSX

	// 31.16.2. Floating-Point Scalar Move Instructions
	AVFMVFS
	AVFMVSF

	// 31.16.3. Vector Slide Instructions
	AVSLIDEUPVX
	AVSLIDEUPVI
	AVSLIDEDOWNVX
	AVSLIDEDOWNVI
	AVSLIDE1UPVX
	AVFSLIDE1UPVF
	AVSLIDE1DOWNVX
	AVFSLIDE1DOWNVF

	// 31.16.4. Vector Register Gather Instructions
	AVRGATHERVV
	AVRGATHEREI16VV
	AVRGATHERVX
	AVRGATHERVI

	// 31.16.5. Vector Compress Instruction
	AVCOMPRESSVM

	// 31.16.6. Whole Vector Register Move
	AVMV1RV
	AVMV2RV
	AVMV4RV
	AVMV8RV

	//
	// Privileged ISA (version 20240411)
	//

	// 3.3.1: Environment Call and Breakpoint
	AECALL
	ASCALL
	AEBREAK
	ASBREAK

	// 3.3.2: Trap-Return Instructions
	AMRET
	ASRET
	ADRET

	// 3.3.3: Wait for Interrupt
	AWFI

	// 10.2: Supervisor Memory-Management Fence Instruction
	ASFENCEVMA

	// The escape hatch. Inserts a single 32-bit word.
	AWORD

	// Pseudo-instructions.  These get translated by the assembler into other
	// instructions, based on their operands.
	ABEQZ
	ABGEZ
	ABGT
	ABGTU
	ABGTZ
	ABLE
	ABLEU
	ABLEZ
	ABLTZ
	ABNEZ
	AFABSD
	AFABSS
	AFNED
	AFNEGD
	AFNEGS
	AFNES
	AMOV
	AMOVB
	AMOVBU
	AMOVD
	AMOVF
	AMOVH
	AMOVHU
	AMOVW
	AMOVWU
	ANEG
	ANEGW
	ANOT
	ARDCYCLE
	ARDINSTRET
	ARDTIME
	ASEQZ
	ASNEZ

	// End marker
	ALAST
)

// opSuffix encoding to uint8 which fit into p.Scond
var rmSuffixSet = map[string]uint8{
	"RNE": RM_RNE,
	"RTZ": RM_RTZ,
	"RDN": RM_RDN,
	"RUP": RM_RUP,
	"RMM": RM_RMM,
}

const rmSuffixBit uint8 = 1 << 7

func rmSuffixEncode(s string) (uint8, error) {
	if s == "" {
		return 0, errors.New("empty suffix")
	}
	enc, ok := rmSuffixSet[s]
	if !ok {
		return 0, fmt.Errorf("invalid encoding for unknown suffix:%q", s)
	}
	return enc | rmSuffixBit, nil
}

func rmSuffixString(u uint8) (string, error) {
	if u&rmSuffixBit == 0 {
		return "", fmt.Errorf("invalid suffix, require round mode bit:%x", u)
	}

	u &^= rmSuffixBit
	for k, v := range rmSuffixSet {
		if v == u {
			return k, nil
		}
	}
	return "", fmt.Errorf("unknown suffix:%x", u)
}

const (
	RM_RNE uint8 = iota // Round to Nearest, ties to Even
	RM_RTZ              // Round towards Zero
	RM_RDN              // Round Down
	RM_RUP              // Round Up
	RM_RMM              // Round to Nearest, ties to Max Magnitude
)

// All unary instructions which write to their arguments (as opposed to reading
// from them) go here. The assembly parser uses this information to populate
// its AST in a semantically reasonable way.
//
// Any instructions not listed here are assumed to either be non-unary or to read
// from its argument.
var unaryDst = map[obj.As]bool{
	ARDCYCLE:   true,
	ARDTIME:    true,
	ARDINSTRET: true,
}

// Instruction encoding masks.
const (
	// BTypeImmMask is a mask including only the immediate portion of
	// B-type instructions.
	BTypeImmMask = 0xfe000f80

	// CBTypeImmMask is a mask including only the immediate portion of
	// CB-type instructions.
	CBTypeImmMask = 0x1c7c

	// CJTypeImmMask is a mask including only the immediate portion of
	// CJ-type instructions.
	CJTypeImmMask = 0x1f7c

	// ITypeImmMask is a mask including only the immediate portion of
	// I-type instructions.
	ITypeImmMask = 0xfff00000

	// JTypeImmMask is a mask including only the immediate portion of
	// J-type instructions.
	JTypeImmMask = 0xfffff000

	// STypeImmMask is a mask including only the immediate portion of
	// S-type instructions.
	STypeImmMask = 0xfe000f80

	// UTypeImmMask is a mask including only the immediate portion of
	// U-type instructions.
	UTypeImmMask = 0xfffff000
)

"""



```