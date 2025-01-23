Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The first clue is the package name: `s390x`. This immediately suggests it's related to the s390x architecture, likely for Go's compiler toolchain (`cmd/internal/obj`). The file name `a.out.go` further hints at object file manipulation or assembly generation for this architecture. The copyright notices mentioning "Lucent Technologies Inc." and "The Go Authors" reinforce this as part of the Go project's internal tooling.

2. **Examine the Imports:**  The import `cmd/internal/obj` is crucial. This confirms that this code interacts with Go's internal object representation and likely defines architecture-specific details for the s390x target.

3. **Analyze the Constants:**
    * `NSNAME`, `NSYM`, `NREG`, `NFREG`: These numeric constants likely define limits or sizes related to symbols, registers, etc., within the s390x architecture's context in the Go compiler. `NREG` and `NFREG` are particularly clear, indicating the number of general-purpose and floating-point registers.
    * `REG_R0` through `REGSP`:  The `iota` keyword strongly suggests this is an enumeration defining the general-purpose registers (GPRs) of the s390x architecture. The comments clearly label them. Similarly, `REG_F0` through `REG_F15` are the floating-point registers (FPRs).
    * `REG_V0` through `REG_V31`:  These are clearly labeled as vector registers (VRs), with a note about aliasing with FPRs. This is a crucial architectural detail.
    * `REG_AR0` through `REG_AR15`: These are access registers (ARs), and the comment about the thread pointer is significant for understanding their use.
    * `REG_RESERVED`: This signifies the end of the allocated register space.
    * `REGARG`, `REGRT1`, `REGRT2`, `REGTMP`, `REGTMP2`, `REGCTXT`, `REGG`, `REG_LR`, `REGSP`: These are special-purpose registers with descriptive names, important for the calling convention, stack management, and other internal compiler operations.

4. **Investigate the `S390XDWARFRegisters` Map and `init()` Function:**
    * The map `S390XDWARFRegisters` with `int16` keys and values strongly suggests a mapping between the Go-internal register representation and DWARF register numbers. DWARF is a standard debugging information format.
    * The `init()` function initializes this map using a helper function `f`. The pattern in `f` and the calls to it (e.g., `f(REG_R0, 1, REG_R15, 0)`) clearly establish the mapping for different register types with specific base values and strides. This is critical for generating debug information.

5. **Examine `BIG`, `DISP12`, `DISP16`, `DISP20`:** These constants likely represent size limits for displacements or offsets used in instructions, reflecting the s390x instruction set's addressing modes.

6. **Analyze `LEAF`, `BRANCH`, `USETMP`:** These are bit flags. Their names suggest they are used to mark properties of code blocks or instructions during compilation (e.g., whether a function is a leaf function, whether it contains branches, or whether it uses a temporary register).

7. **Scrutinize the Instruction Constants (Starting with `C_NONE` and `AADD`):**
    * The `C_` constants (`C_NONE`, `C_REG`, etc.) appear to define operand classes or types for s390x instructions. The comments "comments from func aclass in asmz.go" are a valuable pointer to where these are used in the assembler.
    * The `A` constants (`AADD`, `AADDC`, etc.) strongly resemble s390x assembly instruction mnemonics. The prefix 'A' likely stands for "assembler."  The organization into categories like "integer arithmetic," "integer moves," "floating point," "branch," etc., further confirms this. The comments within these sections are also very helpful.

8. **Formulate Hypotheses and Connect the Dots:**
    * **Core Function:** This file provides architecture-specific definitions and constants for the s390x architecture within the Go compiler. It's used during the assembly and linking phases.
    * **Register Definitions:** It defines Go-internal names for all the s390x registers (GPRs, FPRs, VRs, ARs) and assigns them numerical values.
    * **DWARF Mapping:** It establishes the mapping between Go's register names and DWARF register numbers for debugging.
    * **Instruction Set Representation:**  It defines constants representing s390x instructions and operand types, essential for the assembler to generate machine code.
    * **Internal Flags:** It defines flags used during the compilation process for optimization or code generation decisions.

9. **Consider Examples:** Think about how these definitions would be used.
    * **Assembly Generation:** When the Go compiler needs to generate an "add" instruction on s390x, it would use the `AADD` constant. When it needs to refer to register R5, it would use `REG_R5`.
    * **Debugging Information:** When generating DWARF information, the compiler would use the `S390XDWARFRegisters` map to translate Go's register representation to the DWARF standard.

10. **Identify Potential Pitfalls:** Based on the content, consider common mistakes a user *of the Go compiler* might make related to s390x. This is a bit more abstract, but thinking about cross-compilation or architecture-specific optimizations might yield some ideas. However, since this is *internal* code, direct user errors are less likely in this specific file's context. The focus is more on ensuring the *Go compiler itself* uses these definitions correctly.

By following these steps, analyzing the code structure, keywords, comments, and naming conventions, we can arrive at a comprehensive understanding of the purpose and functionality of the given Go code snippet. The process involves both direct observation and logical deduction based on the context of the Go compiler and the s390x architecture.
这是Go语言编译器（`cmd/compile`）中用于处理S390X架构目标代码生成的一部分。具体来说，它定义了S390X架构的特定常量、寄存器、指令集以及相关的辅助功能。

**功能列表:**

1. **定义S390X架构的寄存器:**  定义了通用寄存器 (GPRs, `REG_R0` - `REG_R15`)、浮点寄存器 (FPRs, `REG_F0` - `REG_F15`)、向量寄存器 (VRs, `REG_V0` - `REG_V31`) 和访问寄存器 (ARs, `REG_AR0` - `REG_AR15`) 的枚举常量。这些常量在编译过程中用于表示和操作S390X的硬件寄存器。
2. **定义特殊的寄存器别名:**  定义了一些具有特定用途的寄存器别名，如 `REGARG` (函数参数寄存器，目前禁用)、`REGRT1`/`REGRT2` (用于栈清零)、`REGTMP`/`REGTMP2` (汇编器和链接器使用的临时寄存器)、`REGCTXT` (闭包上下文寄存器)、`REGG` (指向G的寄存器，用于goroutine的本地存储)、`REG_LR` (链接寄存器) 和 `REGSP` (栈指针)。
3. **定义Dwarf调试信息的寄存器映射:**  `S390XDWARFRegisters` 存储了 Go 内部的寄存器编号到 DWARF 调试信息中使用的寄存器编号的映射。这对于生成可用于调试的二进制文件至关重要。`init()` 函数负责初始化这个映射。
4. **定义常量用于表示地址偏移量和大小:**  定义了 `BIG`, `DISP12`, `DISP16`, `DISP20` 等常量，可能用于限制或表示指令中使用的位移量的大小。
5. **定义代码标记标志:**  定义了 `LEAF`, `BRANCH`, `USETMP` 等常量，用于标记代码块的属性，例如是否为叶子函数、是否包含分支、是否使用了临时寄存器。这些标志在编译优化和代码生成过程中可能会被用到。
6. **定义S390X指令集:**  定义了大量的常量，以 `A` 开头，表示S390X架构的各种指令，例如算术运算指令 (`AADD`, `ASUB`)、数据移动指令 (`AMOVW`, `AMOVD`)、浮点运算指令 (`AFADD`, `AFMUL`)、分支指令 (`ABC`, `ABR`)、以及向量指令 (`AVA`, `AVADD` 等)。这些常量在编译器的汇编阶段用于生成实际的机器码。
7. **定义指令操作数的类别:** 定义了以 `C_` 开头的常量，用于表示S390X指令操作数的类型，例如寄存器 (`C_REG`, `C_FREG`, `C_VREG`, `C_AREG`)、立即数 (`C_ZCON`, `C_SCON`, `C_LCON`, `C_DCON`)、内存地址 (`C_ZOREG`, `C_SOREG`, `C_LOREG`, `C_SAUTO`, `C_LAUTO`)、分支目标 (`C_SBRA`, `C_LBRA`) 以及 TLS 相关的地址 (`C_TLS_LE`, `C_TLS_IE`) 等。

**它是什么Go语言功能的实现 (推断):**

这个文件是Go语言编译器中 **目标代码生成器 (code generator)** 的一部分，专门负责将中间表示 (IR) 的 Go 代码转换为 S390X 架构的汇编代码。具体来说，它提供了生成 S390X 汇编代码所需的各种定义和常量。

**Go代码举例说明:**

虽然这个文件本身不包含可执行的 Go 代码，但它的定义在编译器的内部使用。 假设编译器需要生成将寄存器 R1 的值加到寄存器 R2 的代码，它可能会使用这个文件中定义的常量：

```go
// 假设在编译器的某个阶段
import "./s390x"
import "cmd/internal/obj"

// ...

// 生成 ADD R2, R1 指令
func generateAddInstruction(p *obj.Prog) {
	p.As = s390x.AADD
	p.From.Type = obj.TYPE_REG
	p.From.Reg = s390x.REG_R1
	p.To.Type = obj.TYPE_REG
	p.To.Reg = s390x.REG_R2
}

// ...
```

**假设的输入与输出:**

在这个例子中，输入是编译器的内部表示 `obj.Prog` 结构体，它描述了要生成的指令。输出是修改后的 `obj.Prog` 结构体，其中 `As` 字段被设置为 `s390x.AADD`，`From` 和 `To` 字段被设置为相应的寄存器。最终，汇编器会根据这些信息生成实际的机器码。

**命令行参数的具体处理:**

这个文件本身不直接处理命令行参数。命令行参数的处理发生在 `cmd/compile/internal/gc` 包和更上层的 `cmd/go` 工具中。 当用户使用 `go build` 或 `go run` 并指定了 S390X 架构作为目标时（例如，通过设置 `GOOS` 和 `GOARCH` 环境变量），编译器会加载并使用这个文件中的定义来生成针对 S390X 的代码。

例如，使用以下命令构建针对 S390X 的程序：

```bash
GOOS=linux GOARCH=s390x go build myprogram.go
```

在这个过程中，`cmd/compile` 会读取 `GOARCH` 环境变量的值 (`s390x`)，并加载 `go/src/cmd/internal/obj/s390x/a.out.go` 文件中的定义来指导代码生成。

**使用者易犯错的点:**

这个文件是 Go 编译器内部的实现细节，**直接的使用者（Go 程序员）通常不会直接与其交互，因此不容易犯错。**  常见的错误更多发生在 Go 编译器的开发人员在修改或添加新的 S390X 指令时，需要确保这个文件中的定义与实际的硬件指令集保持一致。

例如，如果 S390X 架构引入了一条新的指令，而这个文件没有及时更新，那么 Go 编译器就无法生成这条新指令的代码。

**总结:**

`go/src/cmd/internal/obj/s390x/a.out.go` 是 Go 编译器中至关重要的组成部分，它为 S390X 架构的目标代码生成提供了基础的定义和常量，使得 Go 语言能够在该架构上编译和运行。它定义了寄存器、指令集、调试信息映射等关键信息，是连接 Go 语言抽象和 S390X 硬件的桥梁。

### 提示词
```
这是路径为go/src/cmd/internal/obj/s390x/a.out.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Based on cmd/internal/obj/ppc64/a.out.go.
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

package s390x

import "cmd/internal/obj"

//go:generate go run ../stringer.go -i $GOFILE -o anames.go -p s390x

const (
	NSNAME = 8
	NSYM   = 50
	NREG   = 16 // number of general purpose registers
	NFREG  = 16 // number of floating point registers
)

const (
	// General purpose registers (GPRs).
	REG_R0 = obj.RBaseS390X + iota
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

	// Floating point registers (FPRs).
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

	// Vector registers (VRs) - only available when the vector
	// facility is installed.
	// V0-V15 are aliases for F0-F15.
	// We keep them in a separate space to make printing etc. easier
	// If the code generator ever emits vector instructions it will
	// need to take into account the aliasing.
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

	// Access registers (ARs).
	// The thread pointer is typically stored in the register pair
	// AR0 and AR1.
	REG_AR0
	REG_AR1
	REG_AR2
	REG_AR3
	REG_AR4
	REG_AR5
	REG_AR6
	REG_AR7
	REG_AR8
	REG_AR9
	REG_AR10
	REG_AR11
	REG_AR12
	REG_AR13
	REG_AR14
	REG_AR15

	REG_RESERVED // end of allocated registers

	REGARG  = -1      // -1 disables passing the first argument in register
	REGRT1  = REG_R3  // used during zeroing of the stack - not reserved
	REGRT2  = REG_R4  // used during zeroing of the stack - not reserved
	REGTMP  = REG_R10 // scratch register used in the assembler and linker
	REGTMP2 = REG_R11 // scratch register used in the assembler and linker
	REGCTXT = REG_R12 // context for closures
	REGG    = REG_R13 // G
	REG_LR  = REG_R14 // link register
	REGSP   = REG_R15 // stack pointer
)

// LINUX for zSeries ELF Application Binary Interface Supplement
// https://refspecs.linuxfoundation.org/ELF/zSeries/lzsabi0_zSeries/x1472.html
var S390XDWARFRegisters = map[int16]int16{}

func init() {
	// f assigns dwarfregisters[from:to by step] = (base):((to-from)/step+base)
	f := func(from, step, to, base int16) {
		for r := int16(from); r <= to; r += step {
			S390XDWARFRegisters[r] = (r-from)/step + base
		}
	}
	f(REG_R0, 1, REG_R15, 0)

	f(REG_F0, 2, REG_F6, 16)
	f(REG_F1, 2, REG_F7, 20)
	f(REG_F8, 2, REG_F14, 24)
	f(REG_F9, 2, REG_F15, 28)

	f(REG_V0, 2, REG_V6, 16) // V0:15 aliased to F0:15
	f(REG_V1, 2, REG_V7, 20) // TODO what about V16:31?
	f(REG_V8, 2, REG_V14, 24)
	f(REG_V9, 2, REG_V15, 28)

	f(REG_AR0, 1, REG_AR15, 48)
}

const (
	BIG    = 32768 - 8
	DISP12 = 4096
	DISP16 = 65536
	DISP20 = 1048576
)

const (
	// mark flags
	LEAF = 1 << iota
	BRANCH
	USETMP // generated code of this Prog uses REGTMP
)

//go:generate go run ../mkcnames.go -i a.out.go -o anamesz.go -p s390x
const ( // comments from func aclass in asmz.go
	C_NONE     = iota
	C_REG      // general-purpose register (64-bit)
	C_FREG     // floating-point register (64-bit)
	C_VREG     // vector register (128-bit)
	C_AREG     // access register (32-bit)
	C_ZCON     // constant == 0
	C_SCON     // 0 <= constant <= 0x7fff (positive int16)
	C_UCON     // constant & 0xffff == 0 (int16 or uint16)
	C_ADDCON   // 0 > constant >= -0x8000 (negative int16)
	C_ANDCON   // constant <= 0xffff
	C_LCON     // constant (int32 or uint32)
	C_DCON     // constant (int64 or uint64)
	C_SACON    // computed address, 16-bit displacement, possibly SP-relative
	C_LACON    // computed address, 32-bit displacement, possibly SP-relative
	C_DACON    // computed address, 64-bit displacement?
	C_SBRA     // short branch
	C_LBRA     // long branch
	C_SAUTO    // short auto
	C_LAUTO    // long auto
	C_ZOREG    // heap address, register-based, displacement == 0
	C_SOREG    // heap address, register-based, int16 displacement
	C_LOREG    // heap address, register-based, int32 displacement
	C_TLS_LE   // TLS - local exec model (for executables)
	C_TLS_IE   // TLS - initial exec model (for shared libraries loaded at program startup)
	C_GOK      // general address
	C_ADDR     // relocation for extern or static symbols (loads and stores)
	C_SYMADDR  // relocation for extern or static symbols (address taking)
	C_GOTADDR  // GOT slot for a symbol in -dynlink mode
	C_TEXTSIZE // text size
	C_ANY
	C_NCLASS // must be the last
)

const (
	// integer arithmetic
	AADD = obj.ABaseS390X + obj.A_ARCHSPECIFIC + iota
	AADDC
	AADDE
	AADDW
	ADIVW
	ADIVWU
	ADIVD
	ADIVDU
	AMODW
	AMODWU
	AMODD
	AMODDU
	AMULLW
	AMULLD
	AMULHD
	AMULHDU
	AMLGR
	ASUB
	ASUBC
	ASUBV
	ASUBE
	ASUBW
	ANEG
	ANEGW

	// integer moves
	AMOVWBR
	AMOVB
	AMOVBZ
	AMOVH
	AMOVHBR
	AMOVHZ
	AMOVW
	AMOVWZ
	AMOVD
	AMOVDBR

	// conditional moves
	AMOVDEQ
	AMOVDGE
	AMOVDGT
	AMOVDLE
	AMOVDLT
	AMOVDNE
	ALOCR
	ALOCGR

	// find leftmost one
	AFLOGR

	// population count
	APOPCNT

	// integer bitwise
	AAND
	AANDW
	AOR
	AORW
	AXOR
	AXORW
	ASLW
	ASLD
	ASRW
	ASRAW
	ASRD
	ASRAD
	ARLL
	ARLLG
	ARNSBG
	ARXSBG
	AROSBG
	ARNSBGT
	ARXSBGT
	AROSBGT
	ARISBG
	ARISBGN
	ARISBGZ
	ARISBGNZ
	ARISBHG
	ARISBLG
	ARISBHGZ
	ARISBLGZ

	// floating point
	AFABS
	AFADD
	AFADDS
	AFCMPO
	AFCMPU
	ACEBR
	AFDIV
	AFDIVS
	AFMADD
	AFMADDS
	AFMOVD
	AFMOVS
	AFMSUB
	AFMSUBS
	AFMUL
	AFMULS
	AFNABS
	AFNEG
	AFNEGS
	ALEDBR
	ALDEBR
	ALPDFR
	ALNDFR
	AFSUB
	AFSUBS
	AFSQRT
	AFSQRTS
	AFIEBR
	AFIDBR
	ACPSDR
	ALTEBR
	ALTDBR
	ATCEB
	ATCDB

	// move from GPR to FPR and vice versa
	ALDGR
	ALGDR

	// convert from int32/int64 to float/float64
	ACEFBRA
	ACDFBRA
	ACEGBRA
	ACDGBRA

	// convert from float/float64 to int32/int64
	ACFEBRA
	ACFDBRA
	ACGEBRA
	ACGDBRA

	// convert from uint32/uint64 to float/float64
	ACELFBR
	ACDLFBR
	ACELGBR
	ACDLGBR

	// convert from float/float64 to uint32/uint64
	ACLFEBR
	ACLFDBR
	ACLGEBR
	ACLGDBR

	// compare
	ACMP
	ACMPU
	ACMPW
	ACMPWU

	// test under mask
	ATMHH
	ATMHL
	ATMLH
	ATMLL

	// insert program mask
	AIPM

	// set program mask
	ASPM

	// compare and swap
	ACS
	ACSG

	// serialize
	ASYNC

	// branch
	ABC
	ABCL
	ABRC
	ABEQ
	ABGE
	ABGT
	ABLE
	ABLT
	ABLEU
	ABLTU
	ABNE
	ABVC
	ABVS
	ASYSCALL

	// branch on count
	ABRCT
	ABRCTG

	// compare and branch
	ACRJ
	ACGRJ
	ACLRJ
	ACLGRJ
	ACIJ
	ACGIJ
	ACLIJ
	ACLGIJ
	ACMPBEQ
	ACMPBGE
	ACMPBGT
	ACMPBLE
	ACMPBLT
	ACMPBNE
	ACMPUBEQ
	ACMPUBGE
	ACMPUBGT
	ACMPUBLE
	ACMPUBLT
	ACMPUBNE

	// storage-and-storage
	AMVC
	AMVCIN
	ACLC
	AXC
	AOC
	ANC

	// load
	AEXRL
	ALARL
	ALA
	ALAY

	// interlocked load and op
	ALAA
	ALAAG
	ALAAL
	ALAALG
	ALAN
	ALANG
	ALAX
	ALAXG
	ALAO
	ALAOG

	// load/store multiple
	ALMY
	ALMG
	ASTMY
	ASTMG

	// store clock
	ASTCK
	ASTCKC
	ASTCKE
	ASTCKF

	// macros
	ACLEAR

	// crypto
	AKM
	AKMC
	AKLMD
	AKIMD
	AKDSA
	AKMA
	AKMCTR

	// vector
	AVA
	AVAB
	AVAH
	AVAF
	AVAG
	AVAQ
	AVACC
	AVACCB
	AVACCH
	AVACCF
	AVACCG
	AVACCQ
	AVAC
	AVACQ
	AVACCC
	AVACCCQ
	AVN
	AVNC
	AVAVG
	AVAVGB
	AVAVGH
	AVAVGF
	AVAVGG
	AVAVGL
	AVAVGLB
	AVAVGLH
	AVAVGLF
	AVAVGLG
	AVCKSM
	AVCEQ
	AVCEQB
	AVCEQH
	AVCEQF
	AVCEQG
	AVCEQBS
	AVCEQHS
	AVCEQFS
	AVCEQGS
	AVCH
	AVCHB
	AVCHH
	AVCHF
	AVCHG
	AVCHBS
	AVCHHS
	AVCHFS
	AVCHGS
	AVCHL
	AVCHLB
	AVCHLH
	AVCHLF
	AVCHLG
	AVCHLBS
	AVCHLHS
	AVCHLFS
	AVCHLGS
	AVCLZ
	AVCLZB
	AVCLZH
	AVCLZF
	AVCLZG
	AVCTZ
	AVCTZB
	AVCTZH
	AVCTZF
	AVCTZG
	AVEC
	AVECB
	AVECH
	AVECF
	AVECG
	AVECL
	AVECLB
	AVECLH
	AVECLF
	AVECLG
	AVERIM
	AVERIMB
	AVERIMH
	AVERIMF
	AVERIMG
	AVERLL
	AVERLLB
	AVERLLH
	AVERLLF
	AVERLLG
	AVERLLV
	AVERLLVB
	AVERLLVH
	AVERLLVF
	AVERLLVG
	AVESLV
	AVESLVB
	AVESLVH
	AVESLVF
	AVESLVG
	AVESL
	AVESLB
	AVESLH
	AVESLF
	AVESLG
	AVESRA
	AVESRAB
	AVESRAH
	AVESRAF
	AVESRAG
	AVESRAV
	AVESRAVB
	AVESRAVH
	AVESRAVF
	AVESRAVG
	AVESRL
	AVESRLB
	AVESRLH
	AVESRLF
	AVESRLG
	AVESRLV
	AVESRLVB
	AVESRLVH
	AVESRLVF
	AVESRLVG
	AVX
	AVFAE
	AVFAEB
	AVFAEH
	AVFAEF
	AVFAEBS
	AVFAEHS
	AVFAEFS
	AVFAEZB
	AVFAEZH
	AVFAEZF
	AVFAEZBS
	AVFAEZHS
	AVFAEZFS
	AVFEE
	AVFEEB
	AVFEEH
	AVFEEF
	AVFEEBS
	AVFEEHS
	AVFEEFS
	AVFEEZB
	AVFEEZH
	AVFEEZF
	AVFEEZBS
	AVFEEZHS
	AVFEEZFS
	AVFENE
	AVFENEB
	AVFENEH
	AVFENEF
	AVFENEBS
	AVFENEHS
	AVFENEFS
	AVFENEZB
	AVFENEZH
	AVFENEZF
	AVFENEZBS
	AVFENEZHS
	AVFENEZFS
	AVFA
	AVFADB
	AWFADB
	AWFK
	AWFKDB
	AVFCE
	AVFCEDB
	AVFCEDBS
	AWFCEDB
	AWFCEDBS
	AVFCH
	AVFCHDB
	AVFCHDBS
	AWFCHDB
	AWFCHDBS
	AVFCHE
	AVFCHEDB
	AVFCHEDBS
	AWFCHEDB
	AWFCHEDBS
	AWFC
	AWFCDB
	AVCDG
	AVCDGB
	AWCDGB
	AVCDLG
	AVCDLGB
	AWCDLGB
	AVCGD
	AVCGDB
	AWCGDB
	AVCLGD
	AVCLGDB
	AWCLGDB
	AVFD
	AVFDDB
	AWFDDB
	AVLDE
	AVLDEB
	AWLDEB
	AVLED
	AVLEDB
	AWLEDB
	AVFM
	AVFMDB
	AWFMDB
	AVFMA
	AVFMADB
	AWFMADB
	AVFMS
	AVFMSDB
	AWFMSDB
	AVFPSO
	AVFPSODB
	AWFPSODB
	AVFLCDB
	AWFLCDB
	AVFLNDB
	AWFLNDB
	AVFLPDB
	AWFLPDB
	AVFSQ
	AVFSQDB
	AWFSQDB
	AVFS
	AVFSDB
	AWFSDB
	AVFTCI
	AVFTCIDB
	AWFTCIDB
	AVGFM
	AVGFMB
	AVGFMH
	AVGFMF
	AVGFMG
	AVGFMA
	AVGFMAB
	AVGFMAH
	AVGFMAF
	AVGFMAG
	AVGEF
	AVGEG
	AVGBM
	AVZERO
	AVONE
	AVGM
	AVGMB
	AVGMH
	AVGMF
	AVGMG
	AVISTR
	AVISTRB
	AVISTRH
	AVISTRF
	AVISTRBS
	AVISTRHS
	AVISTRFS
	AVL
	AVLR
	AVLREP
	AVLREPB
	AVLREPH
	AVLREPF
	AVLREPG
	AVLC
	AVLCB
	AVLCH
	AVLCF
	AVLCG
	AVLEH
	AVLEF
	AVLEG
	AVLEB
	AVLEIH
	AVLEIF
	AVLEIG
	AVLEIB
	AVFI
	AVFIDB
	AWFIDB
	AVLGV
	AVLGVB
	AVLGVH
	AVLGVF
	AVLGVG
	AVLLEZ
	AVLLEZB
	AVLLEZH
	AVLLEZF
	AVLLEZG
	AVLM
	AVLP
	AVLPB
	AVLPH
	AVLPF
	AVLPG
	AVLBB
	AVLVG
	AVLVGB
	AVLVGH
	AVLVGF
	AVLVGG
	AVLVGP
	AVLL
	AVMX
	AVMXB
	AVMXH
	AVMXF
	AVMXG
	AVMXL
	AVMXLB
	AVMXLH
	AVMXLF
	AVMXLG
	AVMRH
	AVMRHB
	AVMRHH
	AVMRHF
	AVMRHG
	AVMRL
	AVMRLB
	AVMRLH
	AVMRLF
	AVMRLG
	AVMN
	AVMNB
	AVMNH
	AVMNF
	AVMNG
	AVMNL
	AVMNLB
	AVMNLH
	AVMNLF
	AVMNLG
	AVMAE
	AVMAEB
	AVMAEH
	AVMAEF
	AVMAH
	AVMAHB
	AVMAHH
	AVMAHF
	AVMALE
	AVMALEB
	AVMALEH
	AVMALEF
	AVMALH
	AVMALHB
	AVMALHH
	AVMALHF
	AVMALO
	AVMALOB
	AVMALOH
	AVMALOF
	AVMAL
	AVMALB
	AVMALHW
	AVMALF
	AVMAO
	AVMAOB
	AVMAOH
	AVMAOF
	AVME
	AVMEB
	AVMEH
	AVMEF
	AVMH
	AVMHB
	AVMHH
	AVMHF
	AVMLE
	AVMLEB
	AVMLEH
	AVMLEF
	AVMLH
	AVMLHB
	AVMLHH
	AVMLHF
	AVMLO
	AVMLOB
	AVMLOH
	AVMLOF
	AVML
	AVMLB
	AVMLHW
	AVMLF
	AVMO
	AVMOB
	AVMOH
	AVMOF
	AVNO
	AVNOT
	AVO
	AVPK
	AVPKH
	AVPKF
	AVPKG
	AVPKLS
	AVPKLSH
	AVPKLSF
	AVPKLSG
	AVPKLSHS
	AVPKLSFS
	AVPKLSGS
	AVPKS
	AVPKSH
	AVPKSF
	AVPKSG
	AVPKSHS
	AVPKSFS
	AVPKSGS
	AVPERM
	AVPDI
	AVPOPCT
	AVREP
	AVREPB
	AVREPH
	AVREPF
	AVREPG
	AVREPI
	AVREPIB
	AVREPIH
	AVREPIF
	AVREPIG
	AVSCEF
	AVSCEG
	AVSEL
	AVSL
	AVSLB
	AVSLDB
	AVSRA
	AVSRAB
	AVSRL
	AVSRLB
	AVSEG
	AVSEGB
	AVSEGH
	AVSEGF
	AVST
	AVSTEH
	AVSTEF
	AVSTEG
	AVSTEB
	AVSTM
	AVSTL
	AVSTRC
	AVSTRCB
	AVSTRCH
	AVSTRCF
	AVSTRCBS
	AVSTRCHS
	AVSTRCFS
	AVSTRCZB
	AVSTRCZH
	AVSTRCZF
	AVSTRCZBS
	AVSTRCZHS
	AVSTRCZFS
	AVS
	AVSB
	AVSH
	AVSF
	AVSG
	AVSQ
	AVSCBI
	AVSCBIB
	AVSCBIH
	AVSCBIF
	AVSCBIG
	AVSCBIQ
	AVSBCBI
	AVSBCBIQ
	AVSBI
	AVSBIQ
	AVSUMG
	AVSUMGH
	AVSUMGF
	AVSUMQ
	AVSUMQF
	AVSUMQG
	AVSUM
	AVSUMB
	AVSUMH
	AVTM
	AVUPH
	AVUPHB
	AVUPHH
	AVUPHF
	AVUPLH
	AVUPLHB
	AVUPLHH
	AVUPLHF
	AVUPLL
	AVUPLLB
	AVUPLLH
	AVUPLLF
	AVUPL
	AVUPLB
	AVUPLHW
	AVUPLF
	AVMSLG
	AVMSLEG
	AVMSLOG
	AVMSLEOG

	ANOPH // NOP

	// binary
	ABYTE
	AWORD
	ADWORD

	// Breakpoint
	ABRRK

	// end marker
	ALAST

	// aliases
	ABR = obj.AJMP
	ABL = obj.ACALL
)
```