Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The first line, `package arm`, and the file name `ssa.go` immediately suggest this code is related to the ARM architecture within the Go compiler's SSA (Static Single Assignment) backend. The `ssa.go` part strongly hints at code generation or manipulation at a lower level than the abstract syntax tree.

2. **Scan for Key Data Structures and Functions:**  Look for prominent data types, functions, and constants. This involves a quick skim through the code:
    * `loadByType`, `storeByType`:  These clearly relate to loading and storing data of different types.
    * `shift`: This custom type seems to handle shifted register operands, a common ARM feature.
    * `makeshift`, `genshift`, `makeregshift`, `genregshift`: These function names strongly suggest they are involved in constructing or encoding shifted register instructions.
    * `getBFC`: This function name, along with the comment about "BFC", points towards the ARM Bitfield Clear (BFC) instruction.
    * `ssaGenValue`:  The name is very telling. It likely handles the code generation for individual SSA values (operations). The large `switch` statement confirms this.
    * `condBits`: This map likely stores condition codes for conditional instructions.
    * `blockJump`, `leJumps`, `gtJumps`: These seem to handle branching logic for different SSA block types.
    * `ssaGenBlock`:  Likely responsible for generating code for SSA basic blocks.

3. **Analyze Key Functions in Detail:** Focus on the functions that appear most central to the code's purpose.

    * **`loadByType` and `storeByType`:**  These are straightforward. They map Go types to the corresponding ARM load/store instructions. Pay attention to the handling of signed/unsigned integers and floating-point numbers.

    * **Shift-related functions:**  Recognize the importance of shifted registers in ARM. Understand that `shift` is a custom type for encoding this. Note the distinction between shifting by a constant (`makeshift`, `genshift`) and shifting by a register (`makeregshift`, `genregshift`). The `String()` method on `shift` is useful for debugging or understanding the encoded value.

    * **`getBFC`:** The comments are very helpful here. Understand the purpose of the BFC instruction and the limitations on its applicability.

    * **`ssaGenValue`:** This is the workhorse. Systematically go through each `case` in the `switch` statement.
        * **Identify the SSA operation (e.g., `ssa.OpCopy`, `ssa.OpARMADD`).**
        * **Understand the corresponding ARM instruction (e.g., `arm.AMOVW`, `arm.AADD`).**
        * **Analyze how the operands are mapped from SSA values to ARM instruction operands.** Pay attention to register allocation (`v.Reg()`, `v.Args[0].Reg()`), constant handling (`v.AuxInt`), memory access (`ssagen.AddrAuto`), and special cases like shifts.
        * **Look for specific optimizations (like the BFC optimization for `ssa.OpARMANDconst` and `ssa.OpARMBICconst`).**
        * **Note the handling of function calls (`ssa.OpARMCALLstatic`, etc.) and lowered operations (`ssa.OpARMLoweredWB`, `ssa.OpARMLoweredZero`, etc.).** These indicate interactions with the Go runtime or compiler intrinsics.
        * **Recognize how comparison operations (`ssa.OpARMCMP`, etc.) set flags and how those flags are used for conditional moves (`ssa.OpARMEqual`, etc.).**

    * **`ssaGenBlock`:** Understand how different SSA block types are translated into ARM control flow instructions (jumps, conditional branches). Pay attention to how successor blocks are handled and the logic for conditional jumps.

4. **Infer Go Feature Implementations:** Based on the operations handled in `ssaGenValue`, try to connect them back to higher-level Go language features.
    * Arithmetic and logical operations (`ADD`, `SUB`, `AND`, `OR`, `XOR`, shifts) are fundamental.
    * Load and store operations (`MOV`) are essential for memory access.
    * Comparisons (`CMP`) are used in `if` statements, loops, and other control flow constructs.
    * Function calls (`CALL`) are how Go functions are invoked.
    * Lowered operations (like `Zero`, `Move`, `WB`) are compiler-generated implementations for runtime tasks.
    * The handling of `defer` is explicit.
    * The conditional moves for boolean values directly implement the results of comparisons.

5. **Construct Examples:**  Once you have an idea of the Go features being implemented, create simple Go code examples that would likely generate the corresponding ARM instructions. This helps solidify your understanding.

6. **Consider Command-line Arguments (if applicable):** In this case, the code refers to `buildcfg.GOARM.Version`. This indicates that the code generation might be influenced by the target ARM architecture version, which is often set through command-line flags during the Go build process (e.g., `-gcflags=-V=7`).

7. **Identify Potential Pitfalls:**  Think about common mistakes developers might make that would lead to incorrect or inefficient code generation. In this snippet, a key point is the interaction between SSA operations and the underlying ARM instructions, especially regarding register usage and the reversed operand order in some ARM instructions (like `CMP`).

8. **Review and Refine:** Go back through your analysis, ensuring consistency and accuracy. Check for any assumptions you made and whether they are supported by the code. For example, the comment about "Special layout in ARM assembly" for `CMP` is crucial.

This detailed thought process, moving from high-level understanding to specific code analysis and then back to connecting with Go features, is crucial for deciphering code like this. The process is iterative, and you might need to revisit earlier steps as you learn more about the code.
这段Go语言代码是Go编译器中用于将中间表示（SSA，Static Single Assignment）转换为ARM汇编指令的一部分。它专注于ARM架构的特定代码生成。

以下是代码的功能列表：

**核心功能：将SSA操作转换为ARM汇编指令**

* **加载和存储指令生成 (`loadByType`, `storeByType`):**  根据Go语言变量的类型 (`types.Type`) 生成相应的ARM加载 (`AMOVB`, `AMOVBU`, `AMOVH`, `AMOVHU`, `AMOVW`, `AMOVF`, `AMOVD`) 和存储指令。例如，`int32` 类型会生成 `AMOVW` 指令。
* **移位操作处理 (`shift`, `makeshift`, `genshift`, `makeregshift`, `genregshift`):**  处理ARM架构中的移位操作，包括常量移位和寄存器移位。它定义了一个 `shift` 类型来编码移位操作，并提供了辅助函数来生成带有移位操作的汇编指令。
* **位域清除 (BFC) 指令优化 (`getBFC`):**  尝试将某些常量的 `AND` 和 `BIC` 操作优化为 ARMv7 上的 `BFC` (Bit Field Clear) 指令，以提高代码效率。
* **SSA Value 到汇编指令的转换 (`ssaGenValue`):**  这是核心函数，负责将各种SSA操作 (`ssa.Op`) 转换为对应的ARM汇编指令。它包含了大量的 `switch` 分支，处理了算术运算、逻辑运算、加载存储、比较、函数调用、类型转换等各种操作。

**具体实现的Go语言功能 (推断):**

基于 `ssaGenValue` 函数中的 `case` 分支，可以推断出它实现了以下Go语言功能的代码生成：

* **基本数据类型的操作:**
    * **赋值 (`ssa.OpCopy`, `ssa.OpARMMOVWreg`):** 将一个寄存器的值复制到另一个寄存器。
    * **加载 (`ssa.OpLoadReg`, `ssa.OpARMMOVWload`, etc.):** 从内存中加载数据到寄存器。
    * **存储 (`ssa.OpStoreReg`, `ssa.OpARMMOVWstore`, etc.):** 将寄存器的值存储到内存中。
    * **常量加载 (`ssa.OpARMMOVWconst`, `ssa.OpARMMOVFconst`, `ssa.OpARMMOVDconst`):** 将常量值加载到寄存器。
* **算术和逻辑运算:**
    * **加减法 (`ssa.OpARMADD`, `ssa.OpARMSUB`, `ssa.OpARMADC`, `ssa.OpARMSBC`, `ssa.OpARMRSB`, `ssa.OpARMSUBS`, `ssa.OpARMADDS`):**  包括带进位的加减法和设置标志位的加减法。
    * **乘法 (`ssa.OpARMMUL`, `ssa.OpARMMULA`, `ssa.OpARMMULS`, `ssa.OpARMHMUL`, `ssa.OpARMHMULU`, `ssa.OpARMMULLU`):**  各种类型的乘法运算，包括 32 位乘法、带累加的乘法、高位乘法等。
    * **除法 (`ssa.OpARMDIVF`, `ssa.OpARMDIVD`, `ssa.OpARMCALLudiv`):** 浮点数除法和无符号整数除法（通过调用运行时函数）。
    * **位运算 (`ssa.OpARMAND`, `ssa.OpARMOR`, `ssa.OpARMXOR`, `ssa.OpARMBIC`, `ssa.OpARMNVN`):**  按位与、或、异或、位清除、位取反。
    * **移位操作 (`ssa.OpARMSLL`, `ssa.OpARMSRL`, `ssa.OpARMSRA`, `ssa.OpARMSRR`, 以及各种带移位的指令):**  逻辑左移、逻辑右移、算术右移、循环右移。
* **浮点数运算:**
    * **加减乘除 (`ssa.OpARMADDF`, `ssa.OpARMADDD`, `ssa.OpARMSUBF`, `ssa.OpARMSUBD`, `ssa.OpARMMULF`, `ssa.OpARMMULD`, `ssa.OpARMNMULF`, `ssa.OpARMNMULD`, `ssa.OpARMDIVF`, `ssa.OpARMDIVD`):** 浮点数的算术运算。
    * **绝对值、取反、平方根 (`ssa.OpARMABSD`, `ssa.OpARMNEGF`, `ssa.OpARMNEGD`, `ssa.OpARMSQRTF`, `ssa.OpARMSQRTD`):**  常见的浮点数操作。
    * **类型转换 (`ssa.OpARMMOVWF`, `ssa.OpARMMOVWD`, `ssa.OpARMMOVFW`, `ssa.OpARMMOVDW`, `ssa.OpARMMOVFD`, `ssa.OpARMMOVDF`, `ssa.OpARMMOVWUF`, `ssa.OpARMMOVWUD`, `ssa.OpARMMOVFWU`, `ssa.OpARMMOVDWU`):**  整数和浮点数之间的类型转换。
* **比较操作:**
    * **整数比较 (`ssa.OpARMCMP`, `ssa.OpARMCMN`, `ssa.OpARMTST`, `ssa.OpARMTEQ`, `ssa.OpARMCMPconst`, etc.):**  比较两个整数或整数与常量，设置标志位。
    * **浮点数比较 (`ssa.OpARMCMPF`, `ssa.OpARMCMPD`, `ssa.OpARMCMPF0`, `ssa.OpARMCMPD0`):** 比较两个浮点数或浮点数与零。
    * **条件移动 (`ssa.OpARMCMOVWHSconst`, `ssa.OpARMCMOVWLSconst`):**  根据条件标志位进行数据移动。
* **控制流:**
    * **函数调用 (`ssa.OpARMCALLstatic`, `ssa.OpARMCALLclosure`, `ssa.OpARMCALLinter`, `ssa.OpARMCALLtail`):**  静态调用、闭包调用、接口调用、尾调用。
    * **跳转 (`ssaGenBlock`):**  根据SSA块的类型生成不同的跳转指令（有条件跳转、无条件跳转）。
    * **Defer机制 (`ssaGenBlock` 中 `ssa.BlockDefer` 的处理):**  处理 `defer` 语句的执行流程。
    * **Panic和边界检查 (`ssa.OpARMLoweredPanicBoundsA`, `ssa.OpARMLoweredPanicExtendA`):** 生成调用运行时 panic 函数的指令。
* **内存操作:**
    * **加载地址 (`ssa.OpARMMOVWaddr`):**  将变量的地址加载到寄存器。
    * **Nil检查 (`ssa.OpARMLoweredNilCheck`):**  通过尝试加载内存来触发空指针异常。
    * **Zeroing内存 (`ssa.OpARMLoweredZero`, `ssa.OpARMDUFFZERO`):**  将一块内存区域置零，可以使用循环或者 `DUFFZERO` 优化。
    * **移动内存 (`ssa.OpARMLoweredMove`, `ssa.OpARMDUFFCOPY`):**  将一块内存区域的内容复制到另一块，可以使用循环或者 `DUFFCOPY` 优化。
    * **写屏障 (`ssa.OpARMLoweredWB`):**  在垃圾回收时使用的写屏障机制。
* **获取运行时信息:**
    * **获取闭包指针 (`ssa.OpARMLoweredGetClosurePtr`):**  获取当前函数的闭包指针。
    * **获取调用者SP/PC (`ssa.OpARMLoweredGetCallerSP`, `ssa.OpARMLoweredGetCallerPC`):**  用于栈回溯等功能。
* **布尔值生成 (`ssa.OpARMEqual`, `ssa.OpARMNotEqual`, etc.):**  将比较结果转换为布尔值 (0 或 1)。

**Go代码举例说明:**

```go
package main

func add(a, b int32) int32 {
	return a + b
}

func main() {
	x := 10
	y := 20
	sum := add(int32(x), int32(y))
	println(sum)
}
```

**推断的汇编指令 (假设的输入与输出):**

对于 `add` 函数中的 `a + b` 操作，`ssaGenValue` 中 `ssa.OpARMADD` 的分支会被触发，假设 `a` 在寄存器 `R0`，`b` 在寄存器 `R1`，返回值存入 `R2`，则可能生成如下汇编指令：

```assembly
ADD R2, R0, R1  // R2 = R0 + R1
```

对于 `main` 函数中的 `x := 10`，`ssaGenValue` 中 `ssa.OpARMMOVWconst` 的分支会被触发，假设 `x` 对应的寄存器是 `R3`，则可能生成：

```assembly
MOVW R3, $10  // R3 = 10
```

**命令行参数的具体处理:**

代码中涉及 `buildcfg.GOARM.Version`，这通常是通过编译Go程序时传递的 `-gcflags` 命令行参数来设置的。例如：

```bash
go build -gcflags="-V=7" main.go
```

这个命令会告诉Go编译器为ARMv7架构生成代码。`ssaGenValue` 中的 `getBFC` 函数会根据 `buildcfg.GOARM.Version` 的值来决定是否尝试优化为 `BFC` 指令，因为 `BFC` 指令只在 ARMv7 及以上版本可用。

**使用者易犯错的点:**

这段代码是Go编译器内部的代码生成部分，普通Go语言开发者不会直接接触到它，因此不存在使用者易犯错的点。 开发者需要关注的是Go语言本身的语法和语义。

**总结:**

`go/src/cmd/compile/internal/arm/ssa.go` 文件是Go编译器中针对ARM架构的关键代码生成模块。它将高级的SSA中间表示转换为底层的ARM汇编指令，实现了Go语言在ARM架构上的运行。它处理了各种Go语言构造，包括基本类型操作、算术逻辑运算、控制流、内存管理以及与Go运行时的交互。其内部的逻辑复杂且与ARM架构的特性紧密相关。

### 提示词
```
这是路径为go/src/cmd/compile/internal/arm/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"fmt"
	"internal/buildcfg"
	"math"
	"math/bits"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/ssagen"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/obj/arm"
)

// loadByType returns the load instruction of the given type.
func loadByType(t *types.Type) obj.As {
	if t.IsFloat() {
		switch t.Size() {
		case 4:
			return arm.AMOVF
		case 8:
			return arm.AMOVD
		}
	} else {
		switch t.Size() {
		case 1:
			if t.IsSigned() {
				return arm.AMOVB
			} else {
				return arm.AMOVBU
			}
		case 2:
			if t.IsSigned() {
				return arm.AMOVH
			} else {
				return arm.AMOVHU
			}
		case 4:
			return arm.AMOVW
		}
	}
	panic("bad load type")
}

// storeByType returns the store instruction of the given type.
func storeByType(t *types.Type) obj.As {
	if t.IsFloat() {
		switch t.Size() {
		case 4:
			return arm.AMOVF
		case 8:
			return arm.AMOVD
		}
	} else {
		switch t.Size() {
		case 1:
			return arm.AMOVB
		case 2:
			return arm.AMOVH
		case 4:
			return arm.AMOVW
		}
	}
	panic("bad store type")
}

// shift type is used as Offset in obj.TYPE_SHIFT operands to encode shifted register operands.
type shift int64

// copied from ../../../internal/obj/util.go:/TYPE_SHIFT
func (v shift) String() string {
	op := "<<>>->@>"[((v>>5)&3)<<1:]
	if v&(1<<4) != 0 {
		// register shift
		return fmt.Sprintf("R%d%c%cR%d", v&15, op[0], op[1], (v>>8)&15)
	} else {
		// constant shift
		return fmt.Sprintf("R%d%c%c%d", v&15, op[0], op[1], (v>>7)&31)
	}
}

// makeshift encodes a register shifted by a constant.
func makeshift(v *ssa.Value, reg int16, typ int64, s int64) shift {
	if s < 0 || s >= 32 {
		v.Fatalf("shift out of range: %d", s)
	}
	return shift(int64(reg&0xf) | typ | (s&31)<<7)
}

// genshift generates a Prog for r = r0 op (r1 shifted by n).
func genshift(s *ssagen.State, v *ssa.Value, as obj.As, r0, r1, r int16, typ int64, n int64) *obj.Prog {
	p := s.Prog(as)
	p.From.Type = obj.TYPE_SHIFT
	p.From.Offset = int64(makeshift(v, r1, typ, n))
	p.Reg = r0
	if r != 0 {
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	}
	return p
}

// makeregshift encodes a register shifted by a register.
func makeregshift(r1 int16, typ int64, r2 int16) shift {
	return shift(int64(r1&0xf) | typ | int64(r2&0xf)<<8 | 1<<4)
}

// genregshift generates a Prog for r = r0 op (r1 shifted by r2).
func genregshift(s *ssagen.State, as obj.As, r0, r1, r2, r int16, typ int64) *obj.Prog {
	p := s.Prog(as)
	p.From.Type = obj.TYPE_SHIFT
	p.From.Offset = int64(makeregshift(r1, typ, r2))
	p.Reg = r0
	if r != 0 {
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	}
	return p
}

// find a (lsb, width) pair for BFC
// lsb must be in [0, 31], width must be in [1, 32 - lsb]
// return (0xffffffff, 0) if v is not a binary like 0...01...10...0
func getBFC(v uint32) (uint32, uint32) {
	var m, l uint32
	// BFC is not applicable with zero
	if v == 0 {
		return 0xffffffff, 0
	}
	// find the lowest set bit, for example l=2 for 0x3ffffffc
	l = uint32(bits.TrailingZeros32(v))
	// m-1 represents the highest set bit index, for example m=30 for 0x3ffffffc
	m = 32 - uint32(bits.LeadingZeros32(v))
	// check if v is a binary like 0...01...10...0
	if (1<<m)-(1<<l) == v {
		// it must be m > l for non-zero v
		return l, m - l
	}
	// invalid
	return 0xffffffff, 0
}

func ssaGenValue(s *ssagen.State, v *ssa.Value) {
	switch v.Op {
	case ssa.OpCopy, ssa.OpARMMOVWreg:
		if v.Type.IsMemory() {
			return
		}
		x := v.Args[0].Reg()
		y := v.Reg()
		if x == y {
			return
		}
		as := arm.AMOVW
		if v.Type.IsFloat() {
			switch v.Type.Size() {
			case 4:
				as = arm.AMOVF
			case 8:
				as = arm.AMOVD
			default:
				panic("bad float size")
			}
		}
		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = x
		p.To.Type = obj.TYPE_REG
		p.To.Reg = y
	case ssa.OpARMMOVWnop:
		// nothing to do
	case ssa.OpLoadReg:
		if v.Type.IsFlags() {
			v.Fatalf("load flags not implemented: %v", v.LongString())
			return
		}
		p := s.Prog(loadByType(v.Type))
		ssagen.AddrAuto(&p.From, v.Args[0])
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpStoreReg:
		if v.Type.IsFlags() {
			v.Fatalf("store flags not implemented: %v", v.LongString())
			return
		}
		p := s.Prog(storeByType(v.Type))
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddrAuto(&p.To, v)
	case ssa.OpARMADD,
		ssa.OpARMADC,
		ssa.OpARMSUB,
		ssa.OpARMSBC,
		ssa.OpARMRSB,
		ssa.OpARMAND,
		ssa.OpARMOR,
		ssa.OpARMXOR,
		ssa.OpARMBIC,
		ssa.OpARMMUL,
		ssa.OpARMADDF,
		ssa.OpARMADDD,
		ssa.OpARMSUBF,
		ssa.OpARMSUBD,
		ssa.OpARMSLL,
		ssa.OpARMSRL,
		ssa.OpARMSRA,
		ssa.OpARMMULF,
		ssa.OpARMMULD,
		ssa.OpARMNMULF,
		ssa.OpARMNMULD,
		ssa.OpARMDIVF,
		ssa.OpARMDIVD:
		r := v.Reg()
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r2
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	case ssa.OpARMSRR:
		genregshift(s, arm.AMOVW, 0, v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm.SHIFT_RR)
	case ssa.OpARMMULAF, ssa.OpARMMULAD, ssa.OpARMMULSF, ssa.OpARMMULSD, ssa.OpARMFMULAD:
		r := v.Reg()
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		r2 := v.Args[2].Reg()
		if r != r0 {
			v.Fatalf("result and addend are not in the same register: %v", v.LongString())
		}
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r2
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	case ssa.OpARMADDS,
		ssa.OpARMSUBS:
		r := v.Reg0()
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		p := s.Prog(v.Op.Asm())
		p.Scond = arm.C_SBIT
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r2
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	case ssa.OpARMSRAcond:
		// ARM shift instructions uses only the low-order byte of the shift amount
		// generate conditional instructions to deal with large shifts
		// flag is already set
		// SRA.HS	$31, Rarg0, Rdst // shift 31 bits to get the sign bit
		// SRA.LO	Rarg1, Rarg0, Rdst
		r := v.Reg()
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		p := s.Prog(arm.ASRA)
		p.Scond = arm.C_SCOND_HS
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 31
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
		p = s.Prog(arm.ASRA)
		p.Scond = arm.C_SCOND_LO
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r2
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	case ssa.OpARMBFX, ssa.OpARMBFXU:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt >> 8
		p.AddRestSourceConst(v.AuxInt & 0xff)
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMANDconst, ssa.OpARMBICconst:
		// try to optimize ANDconst and BICconst to BFC, which saves bytes and ticks
		// BFC is only available on ARMv7, and its result and source are in the same register
		if buildcfg.GOARM.Version == 7 && v.Reg() == v.Args[0].Reg() {
			var val uint32
			if v.Op == ssa.OpARMANDconst {
				val = ^uint32(v.AuxInt)
			} else { // BICconst
				val = uint32(v.AuxInt)
			}
			lsb, width := getBFC(val)
			// omit BFC for ARM's imm12
			if 8 < width && width < 24 {
				p := s.Prog(arm.ABFC)
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = int64(width)
				p.AddRestSourceConst(int64(lsb))
				p.To.Type = obj.TYPE_REG
				p.To.Reg = v.Reg()
				break
			}
		}
		// fall back to ordinary form
		fallthrough
	case ssa.OpARMADDconst,
		ssa.OpARMADCconst,
		ssa.OpARMSUBconst,
		ssa.OpARMSBCconst,
		ssa.OpARMRSBconst,
		ssa.OpARMRSCconst,
		ssa.OpARMORconst,
		ssa.OpARMXORconst,
		ssa.OpARMSLLconst,
		ssa.OpARMSRLconst,
		ssa.OpARMSRAconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMADDSconst,
		ssa.OpARMSUBSconst,
		ssa.OpARMRSBSconst:
		p := s.Prog(v.Op.Asm())
		p.Scond = arm.C_SBIT
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
	case ssa.OpARMSRRconst:
		genshift(s, v, arm.AMOVW, 0, v.Args[0].Reg(), v.Reg(), arm.SHIFT_RR, v.AuxInt)
	case ssa.OpARMADDshiftLL,
		ssa.OpARMADCshiftLL,
		ssa.OpARMSUBshiftLL,
		ssa.OpARMSBCshiftLL,
		ssa.OpARMRSBshiftLL,
		ssa.OpARMRSCshiftLL,
		ssa.OpARMANDshiftLL,
		ssa.OpARMORshiftLL,
		ssa.OpARMXORshiftLL,
		ssa.OpARMBICshiftLL:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm.SHIFT_LL, v.AuxInt)
	case ssa.OpARMADDSshiftLL,
		ssa.OpARMSUBSshiftLL,
		ssa.OpARMRSBSshiftLL:
		p := genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Reg0(), arm.SHIFT_LL, v.AuxInt)
		p.Scond = arm.C_SBIT
	case ssa.OpARMADDshiftRL,
		ssa.OpARMADCshiftRL,
		ssa.OpARMSUBshiftRL,
		ssa.OpARMSBCshiftRL,
		ssa.OpARMRSBshiftRL,
		ssa.OpARMRSCshiftRL,
		ssa.OpARMANDshiftRL,
		ssa.OpARMORshiftRL,
		ssa.OpARMXORshiftRL,
		ssa.OpARMBICshiftRL:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm.SHIFT_LR, v.AuxInt)
	case ssa.OpARMADDSshiftRL,
		ssa.OpARMSUBSshiftRL,
		ssa.OpARMRSBSshiftRL:
		p := genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Reg0(), arm.SHIFT_LR, v.AuxInt)
		p.Scond = arm.C_SBIT
	case ssa.OpARMADDshiftRA,
		ssa.OpARMADCshiftRA,
		ssa.OpARMSUBshiftRA,
		ssa.OpARMSBCshiftRA,
		ssa.OpARMRSBshiftRA,
		ssa.OpARMRSCshiftRA,
		ssa.OpARMANDshiftRA,
		ssa.OpARMORshiftRA,
		ssa.OpARMXORshiftRA,
		ssa.OpARMBICshiftRA:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm.SHIFT_AR, v.AuxInt)
	case ssa.OpARMADDSshiftRA,
		ssa.OpARMSUBSshiftRA,
		ssa.OpARMRSBSshiftRA:
		p := genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Reg0(), arm.SHIFT_AR, v.AuxInt)
		p.Scond = arm.C_SBIT
	case ssa.OpARMXORshiftRR:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm.SHIFT_RR, v.AuxInt)
	case ssa.OpARMMVNshiftLL:
		genshift(s, v, v.Op.Asm(), 0, v.Args[0].Reg(), v.Reg(), arm.SHIFT_LL, v.AuxInt)
	case ssa.OpARMMVNshiftRL:
		genshift(s, v, v.Op.Asm(), 0, v.Args[0].Reg(), v.Reg(), arm.SHIFT_LR, v.AuxInt)
	case ssa.OpARMMVNshiftRA:
		genshift(s, v, v.Op.Asm(), 0, v.Args[0].Reg(), v.Reg(), arm.SHIFT_AR, v.AuxInt)
	case ssa.OpARMMVNshiftLLreg:
		genregshift(s, v.Op.Asm(), 0, v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm.SHIFT_LL)
	case ssa.OpARMMVNshiftRLreg:
		genregshift(s, v.Op.Asm(), 0, v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm.SHIFT_LR)
	case ssa.OpARMMVNshiftRAreg:
		genregshift(s, v.Op.Asm(), 0, v.Args[0].Reg(), v.Args[1].Reg(), v.Reg(), arm.SHIFT_AR)
	case ssa.OpARMADDshiftLLreg,
		ssa.OpARMADCshiftLLreg,
		ssa.OpARMSUBshiftLLreg,
		ssa.OpARMSBCshiftLLreg,
		ssa.OpARMRSBshiftLLreg,
		ssa.OpARMRSCshiftLLreg,
		ssa.OpARMANDshiftLLreg,
		ssa.OpARMORshiftLLreg,
		ssa.OpARMXORshiftLLreg,
		ssa.OpARMBICshiftLLreg:
		genregshift(s, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Args[2].Reg(), v.Reg(), arm.SHIFT_LL)
	case ssa.OpARMADDSshiftLLreg,
		ssa.OpARMSUBSshiftLLreg,
		ssa.OpARMRSBSshiftLLreg:
		p := genregshift(s, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Args[2].Reg(), v.Reg0(), arm.SHIFT_LL)
		p.Scond = arm.C_SBIT
	case ssa.OpARMADDshiftRLreg,
		ssa.OpARMADCshiftRLreg,
		ssa.OpARMSUBshiftRLreg,
		ssa.OpARMSBCshiftRLreg,
		ssa.OpARMRSBshiftRLreg,
		ssa.OpARMRSCshiftRLreg,
		ssa.OpARMANDshiftRLreg,
		ssa.OpARMORshiftRLreg,
		ssa.OpARMXORshiftRLreg,
		ssa.OpARMBICshiftRLreg:
		genregshift(s, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Args[2].Reg(), v.Reg(), arm.SHIFT_LR)
	case ssa.OpARMADDSshiftRLreg,
		ssa.OpARMSUBSshiftRLreg,
		ssa.OpARMRSBSshiftRLreg:
		p := genregshift(s, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Args[2].Reg(), v.Reg0(), arm.SHIFT_LR)
		p.Scond = arm.C_SBIT
	case ssa.OpARMADDshiftRAreg,
		ssa.OpARMADCshiftRAreg,
		ssa.OpARMSUBshiftRAreg,
		ssa.OpARMSBCshiftRAreg,
		ssa.OpARMRSBshiftRAreg,
		ssa.OpARMRSCshiftRAreg,
		ssa.OpARMANDshiftRAreg,
		ssa.OpARMORshiftRAreg,
		ssa.OpARMXORshiftRAreg,
		ssa.OpARMBICshiftRAreg:
		genregshift(s, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Args[2].Reg(), v.Reg(), arm.SHIFT_AR)
	case ssa.OpARMADDSshiftRAreg,
		ssa.OpARMSUBSshiftRAreg,
		ssa.OpARMRSBSshiftRAreg:
		p := genregshift(s, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Args[2].Reg(), v.Reg0(), arm.SHIFT_AR)
		p.Scond = arm.C_SBIT
	case ssa.OpARMHMUL,
		ssa.OpARMHMULU:
		// 32-bit high multiplication
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REGREG
		p.To.Reg = v.Reg()
		p.To.Offset = arm.REGTMP // throw away low 32-bit into tmp register
	case ssa.OpARMMULLU:
		// 32-bit multiplication, results 64-bit, high 32-bit in out0, low 32-bit in out1
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REGREG
		p.To.Reg = v.Reg0()           // high 32-bit
		p.To.Offset = int64(v.Reg1()) // low 32-bit
	case ssa.OpARMMULA, ssa.OpARMMULS:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REGREG2
		p.To.Reg = v.Reg()                   // result
		p.To.Offset = int64(v.Args[2].Reg()) // addend
	case ssa.OpARMMOVWconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMMOVFconst,
		ssa.OpARMMOVDconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_FCONST
		p.From.Val = math.Float64frombits(uint64(v.AuxInt))
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMCMP,
		ssa.OpARMCMN,
		ssa.OpARMTST,
		ssa.OpARMTEQ,
		ssa.OpARMCMPF,
		ssa.OpARMCMPD:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		// Special layout in ARM assembly
		// Comparing to x86, the operands of ARM's CMP are reversed.
		p.From.Reg = v.Args[1].Reg()
		p.Reg = v.Args[0].Reg()
	case ssa.OpARMCMPconst,
		ssa.OpARMCMNconst,
		ssa.OpARMTSTconst,
		ssa.OpARMTEQconst:
		// Special layout in ARM assembly
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.Reg = v.Args[0].Reg()
	case ssa.OpARMCMPF0,
		ssa.OpARMCMPD0:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
	case ssa.OpARMCMPshiftLL, ssa.OpARMCMNshiftLL, ssa.OpARMTSTshiftLL, ssa.OpARMTEQshiftLL:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), 0, arm.SHIFT_LL, v.AuxInt)
	case ssa.OpARMCMPshiftRL, ssa.OpARMCMNshiftRL, ssa.OpARMTSTshiftRL, ssa.OpARMTEQshiftRL:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), 0, arm.SHIFT_LR, v.AuxInt)
	case ssa.OpARMCMPshiftRA, ssa.OpARMCMNshiftRA, ssa.OpARMTSTshiftRA, ssa.OpARMTEQshiftRA:
		genshift(s, v, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), 0, arm.SHIFT_AR, v.AuxInt)
	case ssa.OpARMCMPshiftLLreg, ssa.OpARMCMNshiftLLreg, ssa.OpARMTSTshiftLLreg, ssa.OpARMTEQshiftLLreg:
		genregshift(s, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Args[2].Reg(), 0, arm.SHIFT_LL)
	case ssa.OpARMCMPshiftRLreg, ssa.OpARMCMNshiftRLreg, ssa.OpARMTSTshiftRLreg, ssa.OpARMTEQshiftRLreg:
		genregshift(s, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Args[2].Reg(), 0, arm.SHIFT_LR)
	case ssa.OpARMCMPshiftRAreg, ssa.OpARMCMNshiftRAreg, ssa.OpARMTSTshiftRAreg, ssa.OpARMTEQshiftRAreg:
		genregshift(s, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg(), v.Args[2].Reg(), 0, arm.SHIFT_AR)
	case ssa.OpARMMOVWaddr:
		p := s.Prog(arm.AMOVW)
		p.From.Type = obj.TYPE_ADDR
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

		var wantreg string
		// MOVW $sym+off(base), R
		// the assembler expands it as the following:
		// - base is SP: add constant offset to SP (R13)
		//               when constant is large, tmp register (R11) may be used
		// - base is SB: load external address from constant pool (use relocation)
		switch v.Aux.(type) {
		default:
			v.Fatalf("aux is of unknown type %T", v.Aux)
		case *obj.LSym:
			wantreg = "SB"
			ssagen.AddAux(&p.From, v)
		case *ir.Name:
			wantreg = "SP"
			ssagen.AddAux(&p.From, v)
		case nil:
			// No sym, just MOVW $off(SP), R
			wantreg = "SP"
			p.From.Offset = v.AuxInt
		}
		if reg := v.Args[0].RegName(); reg != wantreg {
			v.Fatalf("bad reg %s for symbol type %T, want %s", reg, v.Aux, wantreg)
		}

	case ssa.OpARMMOVBload,
		ssa.OpARMMOVBUload,
		ssa.OpARMMOVHload,
		ssa.OpARMMOVHUload,
		ssa.OpARMMOVWload,
		ssa.OpARMMOVFload,
		ssa.OpARMMOVDload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMMOVBstore,
		ssa.OpARMMOVHstore,
		ssa.OpARMMOVWstore,
		ssa.OpARMMOVFstore,
		ssa.OpARMMOVDstore:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpARMMOVWloadidx, ssa.OpARMMOVBUloadidx, ssa.OpARMMOVBloadidx, ssa.OpARMMOVHUloadidx, ssa.OpARMMOVHloadidx:
		// this is just shift 0 bits
		fallthrough
	case ssa.OpARMMOVWloadshiftLL:
		p := genshift(s, v, v.Op.Asm(), 0, v.Args[1].Reg(), v.Reg(), arm.SHIFT_LL, v.AuxInt)
		p.From.Reg = v.Args[0].Reg()
	case ssa.OpARMMOVWloadshiftRL:
		p := genshift(s, v, v.Op.Asm(), 0, v.Args[1].Reg(), v.Reg(), arm.SHIFT_LR, v.AuxInt)
		p.From.Reg = v.Args[0].Reg()
	case ssa.OpARMMOVWloadshiftRA:
		p := genshift(s, v, v.Op.Asm(), 0, v.Args[1].Reg(), v.Reg(), arm.SHIFT_AR, v.AuxInt)
		p.From.Reg = v.Args[0].Reg()
	case ssa.OpARMMOVWstoreidx, ssa.OpARMMOVBstoreidx, ssa.OpARMMOVHstoreidx:
		// this is just shift 0 bits
		fallthrough
	case ssa.OpARMMOVWstoreshiftLL:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[2].Reg()
		p.To.Type = obj.TYPE_SHIFT
		p.To.Reg = v.Args[0].Reg()
		p.To.Offset = int64(makeshift(v, v.Args[1].Reg(), arm.SHIFT_LL, v.AuxInt))
	case ssa.OpARMMOVWstoreshiftRL:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[2].Reg()
		p.To.Type = obj.TYPE_SHIFT
		p.To.Reg = v.Args[0].Reg()
		p.To.Offset = int64(makeshift(v, v.Args[1].Reg(), arm.SHIFT_LR, v.AuxInt))
	case ssa.OpARMMOVWstoreshiftRA:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[2].Reg()
		p.To.Type = obj.TYPE_SHIFT
		p.To.Reg = v.Args[0].Reg()
		p.To.Offset = int64(makeshift(v, v.Args[1].Reg(), arm.SHIFT_AR, v.AuxInt))
	case ssa.OpARMMOVBreg,
		ssa.OpARMMOVBUreg,
		ssa.OpARMMOVHreg,
		ssa.OpARMMOVHUreg:
		a := v.Args[0]
		for a.Op == ssa.OpCopy || a.Op == ssa.OpARMMOVWreg || a.Op == ssa.OpARMMOVWnop {
			a = a.Args[0]
		}
		if a.Op == ssa.OpLoadReg {
			t := a.Type
			switch {
			case v.Op == ssa.OpARMMOVBreg && t.Size() == 1 && t.IsSigned(),
				v.Op == ssa.OpARMMOVBUreg && t.Size() == 1 && !t.IsSigned(),
				v.Op == ssa.OpARMMOVHreg && t.Size() == 2 && t.IsSigned(),
				v.Op == ssa.OpARMMOVHUreg && t.Size() == 2 && !t.IsSigned():
				// arg is a proper-typed load, already zero/sign-extended, don't extend again
				if v.Reg() == v.Args[0].Reg() {
					return
				}
				p := s.Prog(arm.AMOVW)
				p.From.Type = obj.TYPE_REG
				p.From.Reg = v.Args[0].Reg()
				p.To.Type = obj.TYPE_REG
				p.To.Reg = v.Reg()
				return
			default:
			}
		}
		if buildcfg.GOARM.Version >= 6 {
			// generate more efficient "MOVB/MOVBU/MOVH/MOVHU Reg@>0, Reg" on ARMv6 & ARMv7
			genshift(s, v, v.Op.Asm(), 0, v.Args[0].Reg(), v.Reg(), arm.SHIFT_RR, 0)
			return
		}
		fallthrough
	case ssa.OpARMMVN,
		ssa.OpARMCLZ,
		ssa.OpARMREV,
		ssa.OpARMREV16,
		ssa.OpARMRBIT,
		ssa.OpARMSQRTF,
		ssa.OpARMSQRTD,
		ssa.OpARMNEGF,
		ssa.OpARMNEGD,
		ssa.OpARMABSD,
		ssa.OpARMMOVWF,
		ssa.OpARMMOVWD,
		ssa.OpARMMOVFW,
		ssa.OpARMMOVDW,
		ssa.OpARMMOVFD,
		ssa.OpARMMOVDF:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMMOVWUF,
		ssa.OpARMMOVWUD,
		ssa.OpARMMOVFWU,
		ssa.OpARMMOVDWU:
		p := s.Prog(v.Op.Asm())
		p.Scond = arm.C_UBIT
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMCMOVWHSconst:
		p := s.Prog(arm.AMOVW)
		p.Scond = arm.C_SCOND_HS
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMCMOVWLSconst:
		p := s.Prog(arm.AMOVW)
		p.Scond = arm.C_SCOND_LS
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMCALLstatic, ssa.OpARMCALLclosure, ssa.OpARMCALLinter:
		s.Call(v)
	case ssa.OpARMCALLtail:
		s.TailCall(v)
	case ssa.OpARMCALLudiv:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Udiv
	case ssa.OpARMLoweredWB:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		// AuxInt encodes how many buffer entries we need.
		p.To.Sym = ir.Syms.GCWriteBarrier[v.AuxInt-1]
	case ssa.OpARMLoweredPanicBoundsA, ssa.OpARMLoweredPanicBoundsB, ssa.OpARMLoweredPanicBoundsC:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ssagen.BoundsCheckFunc[v.AuxInt]
		s.UseArgs(8) // space used in callee args area by assembly stubs
	case ssa.OpARMLoweredPanicExtendA, ssa.OpARMLoweredPanicExtendB, ssa.OpARMLoweredPanicExtendC:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ssagen.ExtendCheckFunc[v.AuxInt]
		s.UseArgs(12) // space used in callee args area by assembly stubs
	case ssa.OpARMDUFFZERO:
		p := s.Prog(obj.ADUFFZERO)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Duffzero
		p.To.Offset = v.AuxInt
	case ssa.OpARMDUFFCOPY:
		p := s.Prog(obj.ADUFFCOPY)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Duffcopy
		p.To.Offset = v.AuxInt
	case ssa.OpARMLoweredNilCheck:
		// Issue a load which will fault if arg is nil.
		p := s.Prog(arm.AMOVB)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = arm.REGTMP
		if logopt.Enabled() {
			logopt.LogOpt(v.Pos, "nilcheck", "genssa", v.Block.Func.Name)
		}
		if base.Debug.Nil != 0 && v.Pos.Line() > 1 { // v.Pos.Line()==1 in generated wrappers
			base.WarnfAt(v.Pos, "generated nil check")
		}
	case ssa.OpARMLoweredZero:
		// MOVW.P	Rarg2, 4(R1)
		// CMP	Rarg1, R1
		// BLE	-2(PC)
		// arg1 is the address of the last element to zero
		// arg2 is known to be zero
		// auxint is alignment
		var sz int64
		var mov obj.As
		switch {
		case v.AuxInt%4 == 0:
			sz = 4
			mov = arm.AMOVW
		case v.AuxInt%2 == 0:
			sz = 2
			mov = arm.AMOVH
		default:
			sz = 1
			mov = arm.AMOVB
		}
		p := s.Prog(mov)
		p.Scond = arm.C_PBIT
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[2].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = arm.REG_R1
		p.To.Offset = sz
		p2 := s.Prog(arm.ACMP)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = v.Args[1].Reg()
		p2.Reg = arm.REG_R1
		p3 := s.Prog(arm.ABLE)
		p3.To.Type = obj.TYPE_BRANCH
		p3.To.SetTarget(p)
	case ssa.OpARMLoweredMove:
		// MOVW.P	4(R1), Rtmp
		// MOVW.P	Rtmp, 4(R2)
		// CMP	Rarg2, R1
		// BLE	-3(PC)
		// arg2 is the address of the last element of src
		// auxint is alignment
		var sz int64
		var mov obj.As
		switch {
		case v.AuxInt%4 == 0:
			sz = 4
			mov = arm.AMOVW
		case v.AuxInt%2 == 0:
			sz = 2
			mov = arm.AMOVH
		default:
			sz = 1
			mov = arm.AMOVB
		}
		p := s.Prog(mov)
		p.Scond = arm.C_PBIT
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = arm.REG_R1
		p.From.Offset = sz
		p.To.Type = obj.TYPE_REG
		p.To.Reg = arm.REGTMP
		p2 := s.Prog(mov)
		p2.Scond = arm.C_PBIT
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = arm.REGTMP
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = arm.REG_R2
		p2.To.Offset = sz
		p3 := s.Prog(arm.ACMP)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = v.Args[2].Reg()
		p3.Reg = arm.REG_R1
		p4 := s.Prog(arm.ABLE)
		p4.To.Type = obj.TYPE_BRANCH
		p4.To.SetTarget(p)
	case ssa.OpARMEqual,
		ssa.OpARMNotEqual,
		ssa.OpARMLessThan,
		ssa.OpARMLessEqual,
		ssa.OpARMGreaterThan,
		ssa.OpARMGreaterEqual,
		ssa.OpARMLessThanU,
		ssa.OpARMLessEqualU,
		ssa.OpARMGreaterThanU,
		ssa.OpARMGreaterEqualU:
		// generate boolean values
		// use conditional move
		p := s.Prog(arm.AMOVW)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
		p = s.Prog(arm.AMOVW)
		p.Scond = condBits[v.Op]
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMLoweredGetClosurePtr:
		// Closure pointer is R7 (arm.REGCTXT).
		ssagen.CheckLoweredGetClosurePtr(v)
	case ssa.OpARMLoweredGetCallerSP:
		// caller's SP is FixedFrameSize below the address of the first arg
		p := s.Prog(arm.AMOVW)
		p.From.Type = obj.TYPE_ADDR
		p.From.Offset = -base.Ctxt.Arch.FixedFrameSize
		p.From.Name = obj.NAME_PARAM
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMLoweredGetCallerPC:
		p := s.Prog(obj.AGETCALLERPC)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARMFlagConstant:
		v.Fatalf("FlagConstant op should never make it to codegen %v", v.LongString())
	case ssa.OpARMInvertFlags:
		v.Fatalf("InvertFlags should never make it to codegen %v", v.LongString())
	case ssa.OpClobber, ssa.OpClobberReg:
		// TODO: implement for clobberdead experiment. Nop is ok for now.
	default:
		v.Fatalf("genValue not implemented: %s", v.LongString())
	}
}

var condBits = map[ssa.Op]uint8{
	ssa.OpARMEqual:         arm.C_SCOND_EQ,
	ssa.OpARMNotEqual:      arm.C_SCOND_NE,
	ssa.OpARMLessThan:      arm.C_SCOND_LT,
	ssa.OpARMLessThanU:     arm.C_SCOND_LO,
	ssa.OpARMLessEqual:     arm.C_SCOND_LE,
	ssa.OpARMLessEqualU:    arm.C_SCOND_LS,
	ssa.OpARMGreaterThan:   arm.C_SCOND_GT,
	ssa.OpARMGreaterThanU:  arm.C_SCOND_HI,
	ssa.OpARMGreaterEqual:  arm.C_SCOND_GE,
	ssa.OpARMGreaterEqualU: arm.C_SCOND_HS,
}

var blockJump = map[ssa.BlockKind]struct {
	asm, invasm obj.As
}{
	ssa.BlockARMEQ:     {arm.ABEQ, arm.ABNE},
	ssa.BlockARMNE:     {arm.ABNE, arm.ABEQ},
	ssa.BlockARMLT:     {arm.ABLT, arm.ABGE},
	ssa.BlockARMGE:     {arm.ABGE, arm.ABLT},
	ssa.BlockARMLE:     {arm.ABLE, arm.ABGT},
	ssa.BlockARMGT:     {arm.ABGT, arm.ABLE},
	ssa.BlockARMULT:    {arm.ABLO, arm.ABHS},
	ssa.BlockARMUGE:    {arm.ABHS, arm.ABLO},
	ssa.BlockARMUGT:    {arm.ABHI, arm.ABLS},
	ssa.BlockARMULE:    {arm.ABLS, arm.ABHI},
	ssa.BlockARMLTnoov: {arm.ABMI, arm.ABPL},
	ssa.BlockARMGEnoov: {arm.ABPL, arm.ABMI},
}

// To model a 'LEnoov' ('<=' without overflow checking) branching.
var leJumps = [2][2]ssagen.IndexJump{
	{{Jump: arm.ABEQ, Index: 0}, {Jump: arm.ABPL, Index: 1}}, // next == b.Succs[0]
	{{Jump: arm.ABMI, Index: 0}, {Jump: arm.ABEQ, Index: 0}}, // next == b.Succs[1]
}

// To model a 'GTnoov' ('>' without overflow checking) branching.
var gtJumps = [2][2]ssagen.IndexJump{
	{{Jump: arm.ABMI, Index: 1}, {Jump: arm.ABEQ, Index: 1}}, // next == b.Succs[0]
	{{Jump: arm.ABEQ, Index: 1}, {Jump: arm.ABPL, Index: 0}}, // next == b.Succs[1]
}

func ssaGenBlock(s *ssagen.State, b, next *ssa.Block) {
	switch b.Kind {
	case ssa.BlockPlain:
		if b.Succs[0].Block() != next {
			p := s.Prog(obj.AJMP)
			p.To.Type = obj.TYPE_BRANCH
			s.Branches = append(s.Branches, ssagen.Branch{P: p, B: b.Succs[0].Block()})
		}

	case ssa.BlockDefer:
		// defer returns in R0:
		// 0 if we should continue executing
		// 1 if we should jump to deferreturn call
		p := s.Prog(arm.ACMP)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 0
		p.Reg = arm.REG_R0
		p = s.Prog(arm.ABNE)
		p.To.Type = obj.TYPE_BRANCH
		s.Branches = append(s.Branches, ssagen.Branch{P: p, B: b.Succs[1].Block()})
		if b.Succs[0].Block() != next {
			p := s.Prog(obj.AJMP)
			p.To.Type = obj.TYPE_BRANCH
			s.Branches = append(s.Branches, ssagen.Branch{P: p, B: b.Succs[0].Block()})
		}

	case ssa.BlockExit, ssa.BlockRetJmp:

	case ssa.BlockRet:
		s.Prog(obj.ARET)

	case ssa.BlockARMEQ, ssa.BlockARMNE,
		ssa.BlockARMLT, ssa.BlockARMGE,
		ssa.BlockARMLE, ssa.BlockARMGT,
		ssa.BlockARMULT, ssa.BlockARMUGT,
		ssa.BlockARMULE, ssa.BlockARMUGE,
		ssa.BlockARMLTnoov, ssa.BlockARMGEnoov:
		jmp := blockJump[b.Kind]
		switch next {
		case b.Succs[0].Block():
			s.Br(jmp.invasm, b.Succs[1].Block())
		case b.Succs[1].Block():
			s.Br(jmp.asm, b.Succs[0].Block())
		default:
			if b.Likely != ssa.BranchUnlikely {
				s.Br(jmp.asm, b.Succs[0].Block())
				s.Br(obj.AJMP, b.Succs[1].Block())
			} else {
				s.Br(jmp.invasm, b.Succs[1].Block())
				s.Br(obj.AJMP, b.Succs[0].Block())
			}
		}

	case ssa.BlockARMLEnoov:
		s.CombJump(b, next, &leJumps)

	case ssa.BlockARMGTnoov:
		s.CombJump(b, next, &gtJumps)

	default:
		b.Fatalf("branch not implemented: %s", b.LongString())
	}
}
```