Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Assessment & Context:**

* **File Path:** `go/src/cmd/internal/obj/arm/a.out.go`. This immediately suggests it's part of the Go compiler toolchain, specifically the assembler/linker (`obj`) for the ARM architecture. The `a.out.go` naming convention often indicates architecture-specific definitions.
* **Copyright Notice:**  A lengthy copyright notice with various contributors indicates this is likely historical code with roots in Plan 9/Inferno. It's probably well-established and potentially influential.
* **Package Declaration:** `package arm`. Confirms the ARM architecture focus.
* **Import:** `import "cmd/internal/obj"`. This confirms the code interacts with the internal Go object representation.

**2. Deconstructing the Content - Top-Down:**

* **Comments:** The initial comment block referencing Inferno's `5.out.h` is a strong hint that this Go code is mirroring or translating concepts from a historical ARM assembler/linker definition file. This provides valuable context for understanding the constants.
* **`//go:generate go run ../stringer.go ...`:**  This is a standard Go directive. It tells the `go generate` tool to run a program to automatically generate a `anames.go` file, likely containing string representations of the constants defined in this file (opcodes, registers, etc.).
* **Constants:** The majority of the code consists of `const` declarations. This is where the core functionality lies. I'd categorize them:
    * **General Constants (`NSNAME`, `NSYM`, `NREG`, `REGARG`):** These look like general size or limit definitions within the assembler/linker. `REGARG` with a value of -1 suggests a disabling flag.
    * **Register Definitions (`REG_R0`, `REG_F0`, `REG_FPSR`, etc.):**  These are crucial. They define the ARM registers, both general-purpose and floating-point. The `iota` and the comments "must be 16-aligned," etc., are important details related to memory alignment requirements for these registers.
    * **Special Registers (`REG_SPECIAL`, `REG_MB_SY`, etc.):**  These seem to represent specialized control or memory barrier registers. The comment about "bit 9 indicates a special register" suggests a particular encoding scheme.
    * **Constant Types (`C_NONE`, `C_REG`, `C_REGREG`, etc.):**  These are likely operand types used in ARM instructions. The names themselves are quite descriptive (e.g., `C_REGREG` suggests an instruction with two register operands, `C_LCON` a large constant).
    * **Opcodes (`AAND`, `AEOR`, `ASUB`, etc.):**  This is the heart of the ARM instruction set definition. The prefixes (`A` likely for "ARM") and the mnemonic-like names clearly represent ARM instructions. The comment about conditional branches is important for understanding how branching instructions are handled.
    * **Condition Codes (`C_SCOND_EQ`, `C_SCOND_NE`, etc.):** These are standard ARM condition codes used for conditional execution of instructions. The `C_SCOND_XOR` comment suggests a specific encoding or representation.
    * **Shift Types (`SHIFT_LL`, `SHIFT_LR`, etc.):** These define the different types of bit shifts available in ARM instructions.
* **Global Variable:** `var ARMDWARFRegisters map[int16]int16{}`. This hints at DWARF debugging information generation. It's a mapping between internal register representations and their DWARF equivalents.
* **`init()` Function:** This function initializes the `ARMDWARFRegisters` map. The `f` helper function simplifies populating the map for ranges of registers, with base and step values. This confirms the DWARF register mapping functionality.

**3. Inferring Functionality and Providing Examples:**

* **Core Functionality:** The primary function is clearly to define the ARM instruction set, register names, operand types, and related constants necessary for assembling and linking ARM Go programs. The DWARF register mapping is a secondary but important function for debugging.
* **Go Code Example (Register Usage):**  To illustrate register usage, I'd create a simple Go function that might involve register manipulation (though the direct manipulation happens at a lower level). Focusing on *how* the *names* are used is key.
* **Go Code Example (Instruction Types):**  Showing how the constant types (`C_REG`, `C_LCON`, etc.) *could* conceptually be used in a compiler's internal representation of an instruction is valuable, even though the user wouldn't directly interact with these constants.
* **Command-Line Arguments:** This file doesn't directly handle command-line arguments. It's a data definition file. The command-line argument handling would occur in other parts of the `cmd/compile` or `cmd/link` packages.

**4. Identifying Potential Pitfalls:**

* **Incorrect Register Usage:** Emphasize the importance of adhering to calling conventions and register allocation strategies. Provide examples of how using "reserved" registers incorrectly can lead to issues.
* **Misunderstanding Instruction Syntax:** Highlight that the constants represent *internal* representations and don't directly translate to assembly syntax. Show how incorrect assembly syntax would be a user error.

**5. Review and Refine:**

After drafting the explanation, I would review it for clarity, accuracy, and completeness. Ensure that the examples are relevant and easy to understand. Double-check the assumptions made during the analysis. For instance, initially, I might have thought `REGARG` related to function arguments, but realizing it's -1 and commented as disabling makes it clearer. Similarly, understanding the DWARF mapping helps clarify the purpose of that section.

This systematic approach of examining the file path, imports, comments, constants, and functions, combined with the contextual knowledge of compiler internals, allows for a comprehensive understanding of the code's purpose.
这段Go语言代码是Go编译器工具链中，针对ARM架构的一部分，主要用于定义ARM汇编指令的助记符、操作数类型以及寄存器等常量。它在将Go源代码编译成ARM机器码的过程中扮演着核心的数据定义角色。

以下是它的具体功能：

1. **定义ARM架构的寄存器:**
   - 定义了通用寄存器 `R0` 到 `R15`，以及它们的别名，例如 `REGRET` (返回寄存器，通常是 `R0`)，`REGSP` (栈指针，`R13`)，`REGLINK` (链接寄存器，`R14`)，`REGPC` (程序计数器，`R15`) 等。
   - 定义了浮点寄存器 `F0` 到 `F15`，以及它们的别名，例如 `FREGRET` (浮点返回寄存器，`F0`)， `FREGTMP` (浮点临时寄存器，`F15`) 等。
   - 定义了特殊寄存器，例如 `FPSR` (浮点状态寄存器)，`FPCR` (浮点控制寄存器)，`CPSR` (当前程序状态寄存器)，`SPSR` (保存的程序状态寄存器) 以及内存屏障相关的寄存器 `REG_MB_SY` 等。
   - `obj.RBaseARM` 是一个基址，用于区分ARM架构的寄存器与其他架构的寄存器。

2. **定义ARM汇编指令的操作数类型 (Classes):**
   - 定义了各种操作数的类型，例如：
     - `C_NONE`: 没有操作数
     - `C_REG`:  通用寄存器
     - `C_FREG`: 浮点寄存器
     - `C_LCON`:  大的立即数
     - `C_SCON`:  小的立即数
     - `C_LCONADDR`:  内存地址形式的大的立即数
     - `C_SAUTO`, `C_LAUTO`: 栈上的偏移地址 (自动变量)
     - `C_LOREG`:  通过寄存器偏移的内存地址
     - `C_PC`: 程序计数器
     - `C_SP`: 栈指针
     - `C_ADDR`: 需要重定位的地址
     - `C_TLS_LE`, `C_TLS_IE`:  线程局部存储相关的操作数类型
   - 这些操作数类型用于描述ARM指令的参数形式，例如 `MOV R0, #10` 中，`R0` 是 `C_REG` 类型，`#10` 可以是 `C_SCON` 类型。

3. **定义ARM汇编指令的助记符 (Opcodes):**
   - 定义了各种ARM汇编指令的助记符，例如：
     - 数据处理指令: `AAND` (逻辑与), `AEOR` (逻辑异或), `AADD` (加法), `ASUB` (减法), `ACMP` (比较) 等。
     - 分支指令: `ABEQ` (等于时跳转), `ABNE` (不等于时跳转), `ABL` (带链接的跳转，用于函数调用) 等，以及别名 `AB` (无条件跳转), `ABL` (函数调用)。
     - 浮点指令: `AADDF` (浮点加法), `ASUBF` (浮点减法), `AMULF` (浮点乘法), `ADIVF` (浮点除法) 等。
     - 加载/存储指令: `AMOVB` (移动字节), `AMOVW` (移动字), `AMOVM` (移动多个寄存器) 等。
     - 其他指令: `ASWI` (软中断), `ADMB` (数据内存屏障) 等。
   - 这些助记符是程序员编写ARM汇编代码时使用的指令名称。

4. **定义条件码 (Condition Codes):**
   - 定义了ARM指令可以附加的条件码，例如 `C_SCOND_EQ` (等于), `C_SCOND_NE` (不等于), `C_SCOND_HS` (无符号大于等于), `C_SCOND_LT` (有符号小于) 等。
   - 条件码允许指令在满足特定条件时才执行，实现条件分支和条件执行。

5. **定义移位操作类型 (Shift Types):**
   - 定义了ARM指令中可以使用的移位操作类型，例如 `SHIFT_LL` (逻辑左移), `SHIFT_LR` (逻辑右移), `SHIFT_AR` (算术右移), `SHIFT_RR` (循环右移)。

6. **定义Dwarf调试信息的寄存器映射:**
   - `ARMDWARFRegisters` 是一个映射表，用于将Go编译器内部使用的寄存器编号映射到Dwarf调试信息标准中定义的寄存器编号。这对于调试器理解程序执行时的寄存器状态至关重要。

**它是什么Go语言功能的实现？**

这个文件是Go编译器中**架构特定的汇编器 (assembler)** 的一部分。当Go编译器将Go源代码编译成机器码时，它会经过以下步骤：

1. **词法分析和语法分析:** 将Go源代码解析成抽象语法树 (AST)。
2. **类型检查:** 检查代码的类型正确性。
3. **中间代码生成:** 将AST转换为一种中间表示形式 (例如，静态单赋值形式，SSA)。
4. **机器码生成 (汇编):**  根据目标架构 (这里是ARM)，将中间代码转换为汇编指令。`a.out.go` 中定义的常量在这个阶段被用来表示ARM的指令、寄存器和操作数。
5. **汇编和链接:** 将生成的汇编代码汇编成机器码，并与必要的库进行链接，生成最终的可执行文件。

**Go代码举例说明:**

虽然 `a.out.go` 本身不是可执行的Go代码，它定义了编译过程中的常量。我们可以想象编译器内部是如何使用这些常量的。例如，当编译器遇到一个Go的加法操作时，它可能会生成类似以下的内部表示：

```go
// 假设的编译器内部结构
type Instruction struct {
    Opcode int
    Args   []Operand
}

type Operand struct {
    Type  int
    Value interface{}
}

// ... 在编译过程中 ...

// 假设要编译 x := a + b，其中 a 和 b 是 int 类型，并且分配到了 R1 和 R2
instruction := Instruction{
    Opcode: AADD, // 加法指令
    Args: []Operand{
        {Type: C_REG, Value: REG_R0}, // 目标寄存器，假设分配到 R0
        {Type: C_REG, Value: REG_R1}, // 源操作数 1 (a)
        {Type: C_REG, Value: REG_R2}, // 源操作数 2 (b)
    },
}

// 编译器后续会根据这个 Instruction 结构生成实际的 ARM 汇编代码:
// ADD R0, R1, R2
```

**代码推理与假设的输入与输出:**

`a.out.go` 主要定义常量，没有直接的输入和输出。但我们可以推断编译器使用这些常量的方式。

**假设输入:** 一个简单的Go函数，执行加法操作。

```go
package main

func add(a, b int) int {
	return a + b
}
```

**编译器内部处理 (部分):**

当编译器处理 `a + b` 时，会查找 `AADD` 常量作为加法指令的操作码。如果 `a` 和 `b` 被分配到寄存器 `REG_R1` 和 `REG_R2`，并且结果要放到 `REG_R0`，编译器会构建一个内部表示，其中使用了 `C_REG` 和对应的寄存器常量。

**输出 (最终生成的ARM汇编代码):**

```assembly
// (简化的汇编，实际可能更复杂)
MOV R1, [sp, #offset_a]  // 将 a 从栈加载到 R1
MOV R2, [sp, #offset_b]  // 将 b 从栈加载到 R2
ADD R0, R1, R2          // 执行加法，结果存入 R0
// ... 其他代码 ...
```

**命令行参数的具体处理:**

`a.out.go` 文件本身不处理命令行参数。处理命令行参数的是 Go 编译器的入口程序，例如 `go build` 命令会调用 `cmd/compile/internal/gc` 包中的代码。这些代码会解析命令行参数，例如目标架构 (`GOARCH=arm`)，然后加载相应的架构特定的定义，包括 `a.out.go` 中的内容。

**使用者易犯错的点:**

普通Go程序员通常不会直接接触或修改 `a.out.go` 文件。这个文件是编译器内部使用的。

**但是，理解这些常量对于以下开发者可能有所帮助，从而避免潜在的错误：**

1. **编写内联汇编的Go开发者:**  如果需要在Go代码中嵌入汇编代码，需要正确使用ARM的寄存器名称和指令助记符，而 `a.out.go` 中定义的常量提供了这些信息的权威来源。  **易犯错点:** 错误地使用了寄存器编号或指令名称，导致汇编器报错或生成错误的机器码。

   ```go
   package main

   import "unsafe"

   func main() {
       var a int32 = 10
       var b int32 = 20
       var result int32

       //go:noinline // 避免函数内联，方便查看生成的汇编
       inlineAdd(&a, &b, &result)

       println(result)
   }

   //go:nosplit
   func inlineAdd(a, b, result *int32)

   // 在另一个 .s 文件中定义 inlineAdd (假设文件名是 inline.s)
   // TEXT ·inlineAdd(SB),$0-24
   //  MOV  R0, 4(R13)   // 获取参数 a 的地址
   //  LDR  R1, (R0)    // 加载 a 的值到 R1
   //  MOV  R0, 8(R13)   // 获取参数 b 的地址
   //  LDR  R2, (R0)    // 加载 b 的值到 R2
   //  ADD  R3, R1, R2    // 将 R1 和 R2 的值相加，结果放入 R3
   //  MOV  R0, 12(R13)  // 获取参数 result 的地址
   //  STR  R3, (R0)    // 将 R3 的值存储到 result 指向的内存
   //  RET

   // 易犯错点：如果开发者在 inline.s 中错误地使用了寄存器名称，例如使用了 "r0" 而不是 "R0" (虽然汇编器可能不区分大小写，但最好保持一致)，或者使用了错误的寄存器编号，就会导致问题。
   ```

2. **Go编译器或工具链的开发者:** 如果需要修改或扩展Go编译器对ARM架构的支持，理解这些常量的含义和用法是必不可少的。 **易犯错点:**  在修改编译器代码时，错误地修改了这些常量的值或含义，导致生成的机器码不正确。

总而言之，`go/src/cmd/internal/obj/arm/a.out.go` 是Go编译器中关于ARM架构的重要数据定义文件，它为汇编器提供了必要的指令、寄存器和操作数信息，是Go语言能够编译成ARM机器码的基础。普通Go开发者无需直接修改它，但理解其内容有助于编写更底层的代码或深入理解Go的编译过程。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/arm/a.out.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Inferno utils/5c/5.out.h
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/5c/5.out.h
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

package arm

import "cmd/internal/obj"

//go:generate go run ../stringer.go -i $GOFILE -o anames.go -p arm

const (
	NSNAME = 8
	NSYM   = 50
	NREG   = 16
)

/* -1 disables use of REGARG */
const (
	REGARG = -1
)

const (
	REG_R0 = obj.RBaseARM + iota // must be 16-aligned
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

	REG_F0 // must be 16-aligned
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

	REG_FPSR // must be 2-aligned
	REG_FPCR

	REG_CPSR // must be 2-aligned
	REG_SPSR

	REGRET = REG_R0
	/* compiler allocates R1 up as temps */
	/* compiler allocates register variables R3 up */
	/* compiler allocates external registers R10 down */
	REGEXT = REG_R10
	/* these two registers are declared in runtime.h */
	REGG = REGEXT - 0
	REGM = REGEXT - 1

	REGCTXT = REG_R7
	REGTMP  = REG_R11
	REGSP   = REG_R13
	REGLINK = REG_R14
	REGPC   = REG_R15

	NFREG = 16
	/* compiler allocates register variables F0 up */
	/* compiler allocates external registers F7 down */
	FREGRET = REG_F0
	FREGEXT = REG_F7
	FREGTMP = REG_F15
)

// http://infocenter.arm.com/help/topic/com.arm.doc.ihi0040b/IHI0040B_aadwarf.pdf
var ARMDWARFRegisters = map[int16]int16{}

func init() {
	// f assigns dwarfregisters[from:to] = (base):(step*(to-from)+base)
	f := func(from, to, base, step int16) {
		for r := int16(from); r <= to; r++ {
			ARMDWARFRegisters[r] = step*(r-from) + base
		}
	}
	f(REG_R0, REG_R15, 0, 1)
	f(REG_F0, REG_F15, 64, 2) // Use d0 through D15, aka S0, S2, ..., S30
}

// Special registers, after subtracting obj.RBaseARM, bit 9 indicates
// a special register and the low bits select the register.
const (
	REG_SPECIAL = obj.RBaseARM + 1<<9 + iota
	REG_MB_SY
	REG_MB_ST
	REG_MB_ISH
	REG_MB_ISHST
	REG_MB_NSH
	REG_MB_NSHST
	REG_MB_OSH
	REG_MB_OSHST

	MAXREG
)

const (
	C_NONE = iota
	C_REG
	C_REGREG
	C_REGREG2
	C_REGLIST
	C_SHIFT     /* register shift R>>x */
	C_SHIFTADDR /* memory address with shifted offset R>>x(R) */
	C_FREG
	C_PSR
	C_FCR
	C_SPR /* REG_MB_SY */

	C_RCON   /* 0xff rotated */
	C_NCON   /* ~RCON */
	C_RCON2A /* OR of two disjoint C_RCON constants */
	C_RCON2S /* subtraction of two disjoint C_RCON constants */
	C_SCON   /* 0xffff */
	C_LCON
	C_LCONADDR
	C_ZFCON
	C_SFCON
	C_LFCON

	C_RACON /* <=0xff rotated constant offset from auto */
	C_LACON /* Large Auto CONstant, i.e. large offset from SP */

	C_SBRA
	C_LBRA

	C_HAUTO  /* halfword insn offset (-0xff to 0xff) */
	C_FAUTO  /* float insn offset (0 to 0x3fc, word aligned) */
	C_HFAUTO /* both H and F */
	C_SAUTO  /* -0xfff to 0xfff */
	C_LAUTO

	C_HOREG
	C_FOREG
	C_HFOREG
	C_SOREG
	C_ROREG
	C_SROREG /* both nil and R */
	C_LOREG

	C_PC
	C_SP
	C_HREG

	C_ADDR /* reference to relocatable address */

	// TLS "var" in local exec mode: will become a constant offset from
	// thread local base that is ultimately chosen by the program linker.
	C_TLS_LE

	// TLS "var" in initial exec mode: will become a memory address (chosen
	// by the program linker) that the dynamic linker will fill with the
	// offset from the thread local base.
	C_TLS_IE

	C_TEXTSIZE

	C_GOK

	C_NCLASS /* must be the last */
)

const (
	AAND = obj.ABaseARM + obj.A_ARCHSPECIFIC + iota
	AEOR
	ASUB
	ARSB
	AADD
	AADC
	ASBC
	ARSC
	ATST
	ATEQ
	ACMP
	ACMN
	AORR
	ABIC

	AMVN

	/*
	 * Do not reorder or fragment the conditional branch
	 * opcodes, or the predication code will break
	 */
	ABEQ
	ABNE
	ABCS
	ABHS
	ABCC
	ABLO
	ABMI
	ABPL
	ABVS
	ABVC
	ABHI
	ABLS
	ABGE
	ABLT
	ABGT
	ABLE

	AMOVWD
	AMOVWF
	AMOVDW
	AMOVFW
	AMOVFD
	AMOVDF
	AMOVF
	AMOVD

	ACMPF
	ACMPD
	AADDF
	AADDD
	ASUBF
	ASUBD
	AMULF
	AMULD
	ANMULF
	ANMULD
	AMULAF
	AMULAD
	ANMULAF
	ANMULAD
	AMULSF
	AMULSD
	ANMULSF
	ANMULSD
	AFMULAF
	AFMULAD
	AFNMULAF
	AFNMULAD
	AFMULSF
	AFMULSD
	AFNMULSF
	AFNMULSD
	ADIVF
	ADIVD
	ASQRTF
	ASQRTD
	AABSF
	AABSD
	ANEGF
	ANEGD

	ASRL
	ASRA
	ASLL
	AMULU
	ADIVU
	AMUL
	AMMUL
	ADIV
	AMOD
	AMODU
	ADIVHW
	ADIVUHW

	AMOVB
	AMOVBS
	AMOVBU
	AMOVH
	AMOVHS
	AMOVHU
	AMOVW
	AMOVM
	ASWPBU
	ASWPW

	ARFE
	ASWI
	AMULA
	AMULS
	AMMULA
	AMMULS

	AWORD

	AMULL
	AMULAL
	AMULLU
	AMULALU

	ABX
	ABXRET
	ADWORD

	ALDREX
	ASTREX
	ALDREXD
	ALDREXB
	ASTREXD
	ASTREXB

	ADMB

	APLD

	ACLZ
	AREV
	AREV16
	AREVSH
	ARBIT

	AXTAB
	AXTAH
	AXTABU
	AXTAHU

	ABFX
	ABFXU
	ABFC
	ABFI

	AMULWT
	AMULWB
	AMULBB
	AMULAWT
	AMULAWB
	AMULABB

	AMRC // MRC/MCR

	ALAST

	// aliases
	AB  = obj.AJMP
	ABL = obj.ACALL
)

/* scond byte */
const (
	C_SCOND = (1 << 4) - 1
	C_SBIT  = 1 << 4
	C_PBIT  = 1 << 5
	C_WBIT  = 1 << 6
	C_FBIT  = 1 << 7 /* psr flags-only */
	C_UBIT  = 1 << 7 /* up bit, unsigned bit */

	// These constants are the ARM condition codes encodings,
	// XORed with 14 so that C_SCOND_NONE has value 0,
	// so that a zeroed Prog.scond means "always execute".
	C_SCOND_XOR = 14

	C_SCOND_EQ   = 0 ^ C_SCOND_XOR
	C_SCOND_NE   = 1 ^ C_SCOND_XOR
	C_SCOND_HS   = 2 ^ C_SCOND_XOR
	C_SCOND_LO   = 3 ^ C_SCOND_XOR
	C_SCOND_MI   = 4 ^ C_SCOND_XOR
	C_SCOND_PL   = 5 ^ C_SCOND_XOR
	C_SCOND_VS   = 6 ^ C_SCOND_XOR
	C_SCOND_VC   = 7 ^ C_SCOND_XOR
	C_SCOND_HI   = 8 ^ C_SCOND_XOR
	C_SCOND_LS   = 9 ^ C_SCOND_XOR
	C_SCOND_GE   = 10 ^ C_SCOND_XOR
	C_SCOND_LT   = 11 ^ C_SCOND_XOR
	C_SCOND_GT   = 12 ^ C_SCOND_XOR
	C_SCOND_LE   = 13 ^ C_SCOND_XOR
	C_SCOND_NONE = 14 ^ C_SCOND_XOR
	C_SCOND_NV   = 15 ^ C_SCOND_XOR

	/* D_SHIFT type */
	SHIFT_LL = 0 << 5
	SHIFT_LR = 1 << 5
	SHIFT_AR = 2 << 5
	SHIFT_RR = 3 << 5
)

"""



```