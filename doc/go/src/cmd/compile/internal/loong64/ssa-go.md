Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the code, potential Go features it implements, illustrative Go code examples, details on command-line argument handling (if any), and common pitfalls for users. The context is a specific Go compiler file for the loong64 architecture.

2. **High-Level Overview:** The file `ssa.go` within the `loong64` directory of the Go compiler strongly suggests that this code is part of the back-end responsible for generating machine code for the LoongArch 64-bit architecture. Specifically, it's likely involved in the instruction selection and register allocation phases within the SSA (Static Single Assignment) framework used by the Go compiler.

3. **Function-by-Function Analysis:**  The best approach is to examine each function in the code and deduce its purpose.

    * **`isFPreg(r int16) bool`:**  This is a straightforward helper function. It checks if a given register `r` is a floating-point register based on the LoongArch register naming conventions (likely `loong64.REG_F0` to `loong64.REG_F31`).

    * **`loadByType(t *types.Type, r int16) obj.As`:** This function determines the appropriate *load* instruction based on the data type `t` and the destination register `r`. It handles integer and floating-point types of different sizes (1, 2, 4, 8 bytes). The `IsSigned()` check is crucial for selecting signed vs. unsigned load instructions for integers. The `panic()` indicates an error condition if the type size is not handled.

    * **`storeByType(t *types.Type, r int16) obj.As`:** Similar to `loadByType`, this function selects the correct *store* instruction based on the data type and source register. It also handles integer and floating-point types.

    * **`largestMove(alignment int64) (obj.As, int64)`:** This function aims to optimize memory moves. Given an alignment requirement, it returns the largest possible move instruction (e.g., `MOVV` for 8-byte aligned) and its size. This avoids unnecessary smaller moves.

    * **`ssaGenValue(s *ssagen.State, v *ssa.Value)`:** This is the core function. The name `ssaGenValue` strongly implies that it's responsible for generating machine code instructions for individual SSA values (`ssa.Value`). The `switch v.Op` structure indicates that it handles a wide range of SSA operations (`ssa.Op`). By examining the cases, we can infer the corresponding LoongArch instructions being generated. For example, `ssa.OpCopy` translates to `loong64.AMOVV`, arithmetic operations like `ssa.OpLOONG64ADDV` map to their corresponding assembly instructions, and memory access operations like `ssa.OpLoadReg` and `ssa.OpStoreReg` utilize `loadByType` and `storeByType`. There are also cases for constants, function calls, atomic operations, and control flow.

    * **`ssaGenBlock(s *ssagen.State, b, next *ssa.Block)`:** This function generates the necessary assembly code for the *control flow* aspects of the SSA representation (the `ssa.Block`s). It handles different block kinds like plain jumps, conditional branches (based on comparisons and floating-point flags), function returns, and defer statements. The `blockJump` map likely stores the corresponding assembly instructions for different block kinds.

    * **`loadRegResult(s *ssagen.State, f *ssa.Func, t *types.Type, reg int16, n *ir.Name, off int64) *obj.Prog`:** This function appears to be involved in loading function return values from the stack into registers.

    * **`spillArgReg(pp *objw.Progs, p *obj.Prog, f *ssa.Func, t *types.Type, reg int16, n *ir.Name, off int64) *obj.Prog`:**  This function seems to handle spilling function arguments from registers to the stack, likely as part of function call setup or register allocation.

4. **Identify Key Functionality:**  Based on the function analysis, the primary functionality of this code is:

    * **Instruction Selection:** Mapping high-level SSA operations to specific LoongArch assembly instructions.
    * **Register Allocation (Implicit):** While not explicitly performing register allocation, the code works with register assignments provided by the SSA framework and handles moving data between registers and memory.
    * **Memory Access Generation:**  Generating load and store instructions, including handling different data sizes and signedness.
    * **Control Flow Generation:** Implementing jumps and conditional branches based on SSA block types.
    * **Function Call Support:** Generating code for static calls, closure calls, and tail calls.
    * **Atomic Operation Support:** Handling atomic loads, stores, exchanges, additions, and compare-and-swap operations.
    * **Special Instructions:**  Generating code for intrinsics like `duffzero` and `duffcopy`, and nil checks.

5. **Infer Go Feature Implementation:** The code snippet provides strong hints about the Go features being implemented for the LoongArch architecture:

    * **Basic Data Types:**  The handling of different integer and floating-point sizes (`int8`, `int16`, `int32`, `int64`, `float32`, `float64`, and their unsigned counterparts).
    * **Memory Operations:** Loading and storing values from memory.
    * **Arithmetic and Logical Operations:** Implementing the standard set of arithmetic and logical operations.
    * **Function Calls:** Supporting various types of function calls.
    * **Control Flow:** Implementing `if`, `for`, `switch` statements.
    * **Atomic Operations:**  Supporting concurrent programming primitives.
    * **`defer`:** The `BlockDefer` case in `ssaGenBlock` indicates support for the `defer` keyword.
    * **Nil Checks:** The `ssa.OpLOONG64LoweredNilCheck` case explicitly handles nil pointer checks.

6. **Construct Go Code Examples:** Based on the inferred feature implementations, create simple Go code snippets that would exercise the generated assembly code. Focus on examples that directly correspond to the operations seen in `ssaGenValue`.

7. **Command-Line Arguments:** Carefully examine the code for any explicit handling of command-line flags. In this snippet, there's no direct parsing of `os.Args` or use of the `flag` package. However, the code *is* part of the Go compiler, and the compiler itself takes numerous command-line arguments. Mention the *indirect* relationship – this code is used when compiling for the loong64 architecture, which is selected through compiler flags like `GOARCH=loong64`.

8. **Common Pitfalls:**  Think about the potential issues developers might face when writing Go code that relies on these low-level implementations. Since this is backend code, direct user errors related to *this specific file* are unlikely. Instead, focus on the *implications* of the code:

    * **Incorrect Type Handling:**  While the compiler prevents many type errors, understanding how different types are handled at the assembly level can be helpful for debugging.
    * **Performance Considerations:** Awareness of the generated assembly can sometimes help in optimizing performance-critical sections of code (though the compiler does a lot of this automatically).
    * **Concurrency Issues:** Misunderstanding how atomic operations work can lead to bugs in concurrent programs.

9. **Review and Refine:** Read through the entire analysis to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that need further explanation. For instance, explicitly mentioning the role of SSA in the compilation process adds context.

This detailed thought process combines code analysis, contextual understanding of the Go compiler, and reasoning about the relationship between high-level Go code and low-level assembly instructions.
好的，我们来分析一下 `go/src/cmd/compile/internal/loong64/ssa.go` 这个 Go 语言源文件片段的功能。

**功能概览**

这段代码是 Go 语言编译器针对 LoongArch 64 位架构 (`loong64`) 的一部分，它主要负责将中间表示（SSA，Static Single Assignment）形式的 Go 代码转换为 LoongArch 汇编指令。更具体地说，它包含了以下核心功能：

1. **辅助函数：** 提供了一些辅助函数，用于判断寄存器类型（浮点寄存器），以及根据 Go 语言的类型选择合适的加载和存储指令。
2. **`ssaGenValue` 函数：** 这是核心函数，它接收一个 SSA 值 (`ssa.Value`)，并根据其操作码 (`v.Op`) 生成相应的 LoongArch 汇编指令。这个函数处理了各种各样的操作，包括：
    * **数据移动：**  寄存器到寄存器、常量到寄存器、内存加载和存储。
    * **算术和逻辑运算：** 加法、减法、与、或、异或、移位、旋转等。
    * **浮点运算：** 加法、减法、乘法、除法、最小值、最大值、乘加、类型转换等。
    * **比较运算：** 整数和浮点数的比较，并设置条件标志。
    * **函数调用：** 静态调用、闭包调用、接口调用、尾调用。
    * **原子操作：**  加载、存储、交换、加法、与、或、CAS 等原子操作。
    * **特殊操作：**  零初始化、内存拷贝、nil 检查、获取闭包指针、获取调用者 SP/PC 等。
3. **`ssaGenBlock` 函数：**  负责根据 SSA 基本块 (`ssa.Block`) 的类型生成相应的控制流汇编指令，例如跳转（无条件和条件跳转）、函数返回等。
4. **辅助的加载和存储函数：** `loadRegResult` 和 `spillArgReg` 看起来是用于处理函数参数和返回值的加载和存储，可能涉及到栈操作。

**它是什么 Go 语言功能的实现？**

这段代码实际上是 Go 语言编译器将各种 Go 语言构造翻译成底层机器码的关键部分。 几乎所有的 Go 语言功能最终都会通过类似的 `ssaGenValue` 和 `ssaGenBlock` 函数转换成目标架构的指令。  以下是一些具体的例子：

* **基本数据类型的操作：**  例如，对 `int`, `float64`, `bool` 等变量的赋值、算术运算、比较运算等。
* **函数调用和返回：**  无论是普通函数还是方法调用，都会涉及到参数传递、执行函数体、返回值处理等，这些都需要生成相应的汇编指令。
* **控制流语句：** `if`, `for`, `switch` 等语句最终会转换成条件跳转和无条件跳转指令。
* **并发和同步：** `sync/atomic` 包中的原子操作需要底层的原子指令支持，这段代码中可以看到对 LoongArch 原子指令的生成。
* **内存管理：**  虽然这段代码本身不直接负责垃圾回收，但它生成的加载和存储指令是内存操作的基础。`DUFFZERO` 和 `DUFFCOPY` 可能是对大块内存进行零初始化和拷贝的优化实现。
* **`defer` 语句：** `ssaGenBlock` 中对 `ssa.BlockDefer` 的处理表明了对 `defer` 语句的支持。

**Go 代码举例说明**

以下是一些 Go 代码示例，并尝试推断 `ssa.go` 中可能生成的汇编指令（简化版本）：

```go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	x := 10
	y := 20
	z := add(x, y)
	println(z)
}
```

**假设的输入与输出 (针对 `add` 函数中的加法 `a + b`)：**

* **假设输入 SSA 值 `v` 的操作码 `v.Op` 是 `ssa.OpLOONG64ADDV`。**
* **假设 `a` 存储在寄存器 `R10`，`b` 存储在寄存器 `R11`，`z` 应该存储在寄存器 `R12`。**

**`ssaGenValue` 函数中 `ssa.OpLOONG64ADDV` 的处理逻辑会生成类似以下的汇编指令：**

```assembly
  ADDV R11, R10, R12  //  R12 = R10 + R11
```

**另一个例子：**

```go
package main

func main() {
	var flag bool = true
	if flag {
		println("true")
	}
}
```

**假设的输入与输出 (针对 `if flag` 语句)：**

* **假设输入 SSA 基本块 `b` 的类型 `b.Kind` 是 `ssa.BlockLOONG64BEQ` (如果 `flag` 为 false 则跳转)。**
* **假设 `flag` 的值存储在寄存器 `R13` (0 表示 false, 1 表示 true)。**
* **假设 `if` 块的下一个基本块是 `block2`，`else` 块（如果存在）的下一个基本块是 `block3`。**

**`ssaGenBlock` 函数中 `ssa.BlockLOONG64BEQ` 的处理逻辑可能会生成类似以下的汇编指令：**

```assembly
  BEQ  RZERO, R13, block3_label  // 如果 R13 等于 0 (false)，跳转到 block3
  // ... 执行 "true" 的代码 (block2) ...
block3_label:
  // ...
```

**命令行参数的具体处理**

这段代码本身并不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的更上层。当使用 `go build` 或 `go run` 等命令时，编译器会根据指定的参数（例如 `GOARCH=loong64` 来选择目标架构）来调用相应的代码生成模块，其中包括 `loong64/ssa.go`。

因此，命令行参数的影响是间接的：

* **`GOARCH=loong64`:** 这个环境变量或构建标记会指示编译器使用 `loong64` 架构的代码生成器，从而调用这段 `ssa.go` 中的函数。
* **优化相关的参数（例如 `-O` 标志）：**  这些参数会影响 SSA 的生成和优化过程，进而影响 `ssaGenValue` 和 `ssaGenBlock` 如何生成汇编指令。例如，开启优化可能会导致更多的指令合并、常量折叠等。

**使用者易犯错的点**

作为编译器内部的代码，普通 Go 语言开发者不会直接与这段代码交互。然而，理解这段代码的功能可以帮助开发者更好地理解 Go 语言的底层行为，从而避免一些潜在的性能陷阱或错误。

一些与代码生成相关的常见误解或容易犯错的点包括：

1. **不理解不同数据类型的汇编指令差异：** 例如，加载有符号和无符号整数会使用不同的汇编指令 (`AMOVB` vs. `AMOVBU`)。不了解这些差异可能导致对某些类型转换或位操作的理解偏差。
2. **忽略函数调用的开销：** 函数调用涉及到参数传递、栈帧管理等操作，理解 `ssaGenValue` 中对 `CALLstatic` 等操作的处理，可以帮助开发者意识到函数调用的成本。
3. **对原子操作的误用：** 原子操作是实现并发安全的关键，但如果使用不当（例如，过度使用或没有正确理解其内存序语义），可能会导致性能下降或死锁。`ssaGenValue` 中对 `LoweredAtomic...` 系列操作的处理体现了原子操作的底层实现。
4. **不了解 `defer` 的执行机制：** `ssaGenBlock` 中对 `BlockDefer` 的处理揭示了 `defer` 语句在控制流上的影响，理解这一点有助于避免在使用 `defer` 时出现意外的行为。

**总结**

`go/src/cmd/compile/internal/loong64/ssa.go` 是 Go 语言编译器中一个至关重要的组成部分，它负责将平台无关的 SSA 中间表示转换为 LoongArch 64 位架构的机器码。理解这段代码的功能可以帮助我们更深入地了解 Go 语言的编译过程以及各种 Go 语言特性的底层实现方式。虽然普通开发者不会直接修改这段代码，但了解其背后的原理对于编写高效和正确的 Go 代码是有益的。

### 提示词
```
这是路径为go/src/cmd/compile/internal/loong64/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package loong64

import (
	"math"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/ssagen"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/obj/loong64"
)

// isFPreg reports whether r is an FP register.
func isFPreg(r int16) bool {
	return loong64.REG_F0 <= r && r <= loong64.REG_F31
}

// loadByType returns the load instruction of the given type.
func loadByType(t *types.Type, r int16) obj.As {
	if isFPreg(r) {
		if t.Size() == 4 {
			return loong64.AMOVF
		} else {
			return loong64.AMOVD
		}
	} else {
		switch t.Size() {
		case 1:
			if t.IsSigned() {
				return loong64.AMOVB
			} else {
				return loong64.AMOVBU
			}
		case 2:
			if t.IsSigned() {
				return loong64.AMOVH
			} else {
				return loong64.AMOVHU
			}
		case 4:
			if t.IsSigned() {
				return loong64.AMOVW
			} else {
				return loong64.AMOVWU
			}
		case 8:
			return loong64.AMOVV
		}
	}
	panic("bad load type")
}

// storeByType returns the store instruction of the given type.
func storeByType(t *types.Type, r int16) obj.As {
	if isFPreg(r) {
		if t.Size() == 4 {
			return loong64.AMOVF
		} else {
			return loong64.AMOVD
		}
	} else {
		switch t.Size() {
		case 1:
			return loong64.AMOVB
		case 2:
			return loong64.AMOVH
		case 4:
			return loong64.AMOVW
		case 8:
			return loong64.AMOVV
		}
	}
	panic("bad store type")
}

// largestMove returns the largest move instruction possible and its size,
// given the alignment of the total size of the move.
//
// e.g., a 16-byte move may use MOVV, but an 11-byte move must use MOVB.
//
// Note that the moves may not be on naturally aligned addresses depending on
// the source and destination.
//
// This matches the calculation in ssa.moveSize.
func largestMove(alignment int64) (obj.As, int64) {
	switch {
	case alignment%8 == 0:
		return loong64.AMOVV, 8
	case alignment%4 == 0:
		return loong64.AMOVW, 4
	case alignment%2 == 0:
		return loong64.AMOVH, 2
	default:
		return loong64.AMOVB, 1
	}
}

func ssaGenValue(s *ssagen.State, v *ssa.Value) {
	switch v.Op {
	case ssa.OpCopy, ssa.OpLOONG64MOVVreg:
		if v.Type.IsMemory() {
			return
		}
		x := v.Args[0].Reg()
		y := v.Reg()
		if x == y {
			return
		}
		as := loong64.AMOVV
		if isFPreg(x) && isFPreg(y) {
			as = loong64.AMOVD
		}
		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = x
		p.To.Type = obj.TYPE_REG
		p.To.Reg = y
	case ssa.OpLOONG64MOVVnop,
		ssa.OpLOONG64LoweredRound32F,
		ssa.OpLOONG64LoweredRound64F:
		// nothing to do
	case ssa.OpLoadReg:
		if v.Type.IsFlags() {
			v.Fatalf("load flags not implemented: %v", v.LongString())
			return
		}
		r := v.Reg()
		p := s.Prog(loadByType(v.Type, r))
		ssagen.AddrAuto(&p.From, v.Args[0])
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	case ssa.OpStoreReg:
		if v.Type.IsFlags() {
			v.Fatalf("store flags not implemented: %v", v.LongString())
			return
		}
		r := v.Args[0].Reg()
		p := s.Prog(storeByType(v.Type, r))
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r
		ssagen.AddrAuto(&p.To, v)
	case ssa.OpArgIntReg, ssa.OpArgFloatReg:
		// The assembler needs to wrap the entry safepoint/stack growth code with spill/unspill
		// The loop only runs once.
		for _, a := range v.Block.Func.RegArgs {
			// Pass the spill/unspill information along to the assembler, offset by size of
			// the saved LR slot.
			addr := ssagen.SpillSlotAddr(a, loong64.REGSP, base.Ctxt.Arch.FixedFrameSize)
			s.FuncInfo().AddSpill(
				obj.RegSpill{Reg: a.Reg, Addr: addr, Unspill: loadByType(a.Type, a.Reg), Spill: storeByType(a.Type, a.Reg)})
		}
		v.Block.Func.RegArgs = nil
		ssagen.CheckArgReg(v)
	case ssa.OpLOONG64ADDV,
		ssa.OpLOONG64SUBV,
		ssa.OpLOONG64AND,
		ssa.OpLOONG64OR,
		ssa.OpLOONG64XOR,
		ssa.OpLOONG64NOR,
		ssa.OpLOONG64SLLV,
		ssa.OpLOONG64SRLV,
		ssa.OpLOONG64SRAV,
		ssa.OpLOONG64ROTR,
		ssa.OpLOONG64ROTRV,
		ssa.OpLOONG64ADDF,
		ssa.OpLOONG64ADDD,
		ssa.OpLOONG64SUBF,
		ssa.OpLOONG64SUBD,
		ssa.OpLOONG64MULF,
		ssa.OpLOONG64MULD,
		ssa.OpLOONG64DIVF,
		ssa.OpLOONG64DIVD,
		ssa.OpLOONG64MULV, ssa.OpLOONG64MULHV, ssa.OpLOONG64MULHVU,
		ssa.OpLOONG64DIVV, ssa.OpLOONG64REMV, ssa.OpLOONG64DIVVU, ssa.OpLOONG64REMVU,
		ssa.OpLOONG64FCOPYSGD:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpLOONG64BSTRPICKV,
		ssa.OpLOONG64BSTRPICKW:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		if v.Op == ssa.OpLOONG64BSTRPICKW {
			p.From.Offset = v.AuxInt >> 5
			p.AddRestSourceConst(v.AuxInt & 0x1f)
		} else {
			p.From.Offset = v.AuxInt >> 6
			p.AddRestSourceConst(v.AuxInt & 0x3f)
		}
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpLOONG64FMINF,
		ssa.OpLOONG64FMIND,
		ssa.OpLOONG64FMAXF,
		ssa.OpLOONG64FMAXD:
		// ADDD Rarg0, Rarg1, Rout
		// CMPEQD Rarg0, Rarg0, FCC0
		// bceqz FCC0, end
		// CMPEQD Rarg1, Rarg1, FCC0
		// bceqz FCC0, end
		// F(MIN|MAX)(F|D)

		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg()
		add, fcmp := loong64.AADDD, loong64.ACMPEQD
		if v.Op == ssa.OpLOONG64FMINF || v.Op == ssa.OpLOONG64FMAXF {
			add = loong64.AADDF
			fcmp = loong64.ACMPEQF
		}
		p1 := s.Prog(add)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r0
		p1.Reg = r1
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = out

		p2 := s.Prog(fcmp)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = r0
		p2.Reg = r0
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = loong64.REG_FCC0

		p3 := s.Prog(loong64.ABFPF)
		p3.To.Type = obj.TYPE_BRANCH

		p4 := s.Prog(fcmp)
		p4.From.Type = obj.TYPE_REG
		p4.From.Reg = r1
		p4.Reg = r1
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = loong64.REG_FCC0

		p5 := s.Prog(loong64.ABFPF)
		p5.To.Type = obj.TYPE_BRANCH

		p6 := s.Prog(v.Op.Asm())
		p6.From.Type = obj.TYPE_REG
		p6.From.Reg = r1
		p6.Reg = r0
		p6.To.Type = obj.TYPE_REG
		p6.To.Reg = out

		nop := s.Prog(obj.ANOP)
		p3.To.SetTarget(nop)
		p5.To.SetTarget(nop)

	case ssa.OpLOONG64SGT,
		ssa.OpLOONG64SGTU:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpLOONG64ADDVconst,
		ssa.OpLOONG64SUBVconst,
		ssa.OpLOONG64ANDconst,
		ssa.OpLOONG64ORconst,
		ssa.OpLOONG64XORconst,
		ssa.OpLOONG64NORconst,
		ssa.OpLOONG64SLLVconst,
		ssa.OpLOONG64SRLVconst,
		ssa.OpLOONG64SRAVconst,
		ssa.OpLOONG64ROTRconst,
		ssa.OpLOONG64ROTRVconst,
		ssa.OpLOONG64SGTconst,
		ssa.OpLOONG64SGTUconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpLOONG64MOVVconst:
		r := v.Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
		if isFPreg(r) {
			// cannot move into FP or special registers, use TMP as intermediate
			p.To.Reg = loong64.REGTMP
			p = s.Prog(loong64.AMOVV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = loong64.REGTMP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = r
		}
	case ssa.OpLOONG64MOVFconst,
		ssa.OpLOONG64MOVDconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_FCONST
		p.From.Val = math.Float64frombits(uint64(v.AuxInt))
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpLOONG64CMPEQF,
		ssa.OpLOONG64CMPEQD,
		ssa.OpLOONG64CMPGEF,
		ssa.OpLOONG64CMPGED,
		ssa.OpLOONG64CMPGTF,
		ssa.OpLOONG64CMPGTD:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = loong64.REG_FCC0

	case ssa.OpLOONG64FMADDF,
		ssa.OpLOONG64FMADDD,
		ssa.OpLOONG64FMSUBF,
		ssa.OpLOONG64FMSUBD,
		ssa.OpLOONG64FNMADDF,
		ssa.OpLOONG64FNMADDD,
		ssa.OpLOONG64FNMSUBF,
		ssa.OpLOONG64FNMSUBD:
		p := s.Prog(v.Op.Asm())
		// r=(FMA x y z) -> FMADDD z, y, x, r
		// the SSA operand order is for taking advantage of
		// commutativity (that only applies for the first two operands)
		r := v.Reg()
		x := v.Args[0].Reg()
		y := v.Args[1].Reg()
		z := v.Args[2].Reg()
		p.From.Type = obj.TYPE_REG
		p.From.Reg = z
		p.Reg = y
		p.AddRestSourceReg(x)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r

	case ssa.OpLOONG64MOVVaddr:
		p := s.Prog(loong64.AMOVV)
		p.From.Type = obj.TYPE_ADDR
		p.From.Reg = v.Args[0].Reg()
		var wantreg string
		// MOVV $sym+off(base), R
		// the assembler expands it as the following:
		// - base is SP: add constant offset to SP (R3)
		// when constant is large, tmp register (R30) may be used
		// - base is SB: load external address with relocation
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
			// No sym, just MOVV $off(SP), R
			wantreg = "SP"
			p.From.Offset = v.AuxInt
		}
		if reg := v.Args[0].RegName(); reg != wantreg {
			v.Fatalf("bad reg %s for symbol type %T, want %s", reg, v.Aux, wantreg)
		}
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpLOONG64MOVBloadidx,
		ssa.OpLOONG64MOVBUloadidx,
		ssa.OpLOONG64MOVHloadidx,
		ssa.OpLOONG64MOVHUloadidx,
		ssa.OpLOONG64MOVWloadidx,
		ssa.OpLOONG64MOVWUloadidx,
		ssa.OpLOONG64MOVVloadidx,
		ssa.OpLOONG64MOVFloadidx,
		ssa.OpLOONG64MOVDloadidx:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Name = obj.NAME_NONE
		p.From.Reg = v.Args[0].Reg()
		p.From.Index = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpLOONG64MOVBstoreidx,
		ssa.OpLOONG64MOVHstoreidx,
		ssa.OpLOONG64MOVWstoreidx,
		ssa.OpLOONG64MOVVstoreidx,
		ssa.OpLOONG64MOVFstoreidx,
		ssa.OpLOONG64MOVDstoreidx:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[2].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_NONE
		p.To.Reg = v.Args[0].Reg()
		p.To.Index = v.Args[1].Reg()

	case ssa.OpLOONG64MOVBstorezeroidx,
		ssa.OpLOONG64MOVHstorezeroidx,
		ssa.OpLOONG64MOVWstorezeroidx,
		ssa.OpLOONG64MOVVstorezeroidx:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = loong64.REGZERO
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_NONE
		p.To.Reg = v.Args[0].Reg()
		p.To.Index = v.Args[1].Reg()

	case ssa.OpLOONG64MOVBload,
		ssa.OpLOONG64MOVBUload,
		ssa.OpLOONG64MOVHload,
		ssa.OpLOONG64MOVHUload,
		ssa.OpLOONG64MOVWload,
		ssa.OpLOONG64MOVWUload,
		ssa.OpLOONG64MOVVload,
		ssa.OpLOONG64MOVFload,
		ssa.OpLOONG64MOVDload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpLOONG64MOVBstore,
		ssa.OpLOONG64MOVHstore,
		ssa.OpLOONG64MOVWstore,
		ssa.OpLOONG64MOVVstore,
		ssa.OpLOONG64MOVFstore,
		ssa.OpLOONG64MOVDstore:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpLOONG64MOVBstorezero,
		ssa.OpLOONG64MOVHstorezero,
		ssa.OpLOONG64MOVWstorezero,
		ssa.OpLOONG64MOVVstorezero:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = loong64.REGZERO
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpLOONG64MOVBreg,
		ssa.OpLOONG64MOVBUreg,
		ssa.OpLOONG64MOVHreg,
		ssa.OpLOONG64MOVHUreg,
		ssa.OpLOONG64MOVWreg,
		ssa.OpLOONG64MOVWUreg:
		a := v.Args[0]
		for a.Op == ssa.OpCopy || a.Op == ssa.OpLOONG64MOVVreg {
			a = a.Args[0]
		}
		if a.Op == ssa.OpLoadReg && loong64.REG_R0 <= a.Reg() && a.Reg() <= loong64.REG_R31 {
			// LoadReg from a narrower type does an extension, except loading
			// to a floating point register. So only eliminate the extension
			// if it is loaded to an integer register.

			t := a.Type
			switch {
			case v.Op == ssa.OpLOONG64MOVBreg && t.Size() == 1 && t.IsSigned(),
				v.Op == ssa.OpLOONG64MOVBUreg && t.Size() == 1 && !t.IsSigned(),
				v.Op == ssa.OpLOONG64MOVHreg && t.Size() == 2 && t.IsSigned(),
				v.Op == ssa.OpLOONG64MOVHUreg && t.Size() == 2 && !t.IsSigned(),
				v.Op == ssa.OpLOONG64MOVWreg && t.Size() == 4 && t.IsSigned(),
				v.Op == ssa.OpLOONG64MOVWUreg && t.Size() == 4 && !t.IsSigned():
				// arg is a proper-typed load, already zero/sign-extended, don't extend again
				if v.Reg() == v.Args[0].Reg() {
					return
				}
				p := s.Prog(loong64.AMOVV)
				p.From.Type = obj.TYPE_REG
				p.From.Reg = v.Args[0].Reg()
				p.To.Type = obj.TYPE_REG
				p.To.Reg = v.Reg()
				return
			default:
			}
		}
		fallthrough

	case ssa.OpLOONG64MOVWF,
		ssa.OpLOONG64MOVWD,
		ssa.OpLOONG64TRUNCFW,
		ssa.OpLOONG64TRUNCDW,
		ssa.OpLOONG64MOVVF,
		ssa.OpLOONG64MOVVD,
		ssa.OpLOONG64TRUNCFV,
		ssa.OpLOONG64TRUNCDV,
		ssa.OpLOONG64MOVFD,
		ssa.OpLOONG64MOVDF,
		ssa.OpLOONG64MOVWfpgp,
		ssa.OpLOONG64MOVWgpfp,
		ssa.OpLOONG64MOVVfpgp,
		ssa.OpLOONG64MOVVgpfp,
		ssa.OpLOONG64NEGF,
		ssa.OpLOONG64NEGD,
		ssa.OpLOONG64CLZW,
		ssa.OpLOONG64CLZV,
		ssa.OpLOONG64CTZW,
		ssa.OpLOONG64CTZV,
		ssa.OpLOONG64SQRTD,
		ssa.OpLOONG64SQRTF,
		ssa.OpLOONG64REVB2H,
		ssa.OpLOONG64REVB2W,
		ssa.OpLOONG64REVBV,
		ssa.OpLOONG64BITREV4B,
		ssa.OpLOONG64BITREVW,
		ssa.OpLOONG64BITREVV,
		ssa.OpLOONG64ABSD:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpLOONG64VPCNT64,
		ssa.OpLOONG64VPCNT32,
		ssa.OpLOONG64VPCNT16:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = ((v.Args[0].Reg() - loong64.REG_F0) & 31) + loong64.REG_V0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = ((v.Reg() - loong64.REG_F0) & 31) + loong64.REG_V0

	case ssa.OpLOONG64NEGV:
		// SUB from REGZERO
		p := s.Prog(loong64.ASUBVU)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = loong64.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpLOONG64DUFFZERO:
		// runtime.duffzero expects start address in R20
		p := s.Prog(obj.ADUFFZERO)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Duffzero
		p.To.Offset = v.AuxInt
	case ssa.OpLOONG64LoweredZero:
		// MOVx	R0, (Rarg0)
		// ADDV	$sz, Rarg0
		// BGEU	Rarg1, Rarg0, -2(PC)
		mov, sz := largestMove(v.AuxInt)
		p := s.Prog(mov)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = loong64.REGZERO
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()

		p2 := s.Prog(loong64.AADDVU)
		p2.From.Type = obj.TYPE_CONST
		p2.From.Offset = sz
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = v.Args[0].Reg()

		p3 := s.Prog(loong64.ABGEU)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = v.Args[1].Reg()
		p3.Reg = v.Args[0].Reg()
		p3.To.Type = obj.TYPE_BRANCH
		p3.To.SetTarget(p)

	case ssa.OpLOONG64DUFFCOPY:
		p := s.Prog(obj.ADUFFCOPY)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Duffcopy
		p.To.Offset = v.AuxInt
	case ssa.OpLOONG64LoweredMove:
		// MOVx	(Rarg1), Rtmp
		// MOVx	Rtmp, (Rarg0)
		// ADDV	$sz, Rarg1
		// ADDV	$sz, Rarg0
		// BGEU	Rarg2, Rarg0, -4(PC)
		mov, sz := largestMove(v.AuxInt)
		p := s.Prog(mov)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = loong64.REGTMP

		p2 := s.Prog(mov)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = loong64.REGTMP
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = v.Args[0].Reg()

		p3 := s.Prog(loong64.AADDVU)
		p3.From.Type = obj.TYPE_CONST
		p3.From.Offset = sz
		p3.To.Type = obj.TYPE_REG
		p3.To.Reg = v.Args[1].Reg()

		p4 := s.Prog(loong64.AADDVU)
		p4.From.Type = obj.TYPE_CONST
		p4.From.Offset = sz
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = v.Args[0].Reg()

		p5 := s.Prog(loong64.ABGEU)
		p5.From.Type = obj.TYPE_REG
		p5.From.Reg = v.Args[2].Reg()
		p5.Reg = v.Args[1].Reg()
		p5.To.Type = obj.TYPE_BRANCH
		p5.To.SetTarget(p)

	case ssa.OpLOONG64CALLstatic, ssa.OpLOONG64CALLclosure, ssa.OpLOONG64CALLinter:
		s.Call(v)
	case ssa.OpLOONG64CALLtail:
		s.TailCall(v)
	case ssa.OpLOONG64LoweredWB:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		// AuxInt encodes how many buffer entries we need.
		p.To.Sym = ir.Syms.GCWriteBarrier[v.AuxInt-1]

	case ssa.OpLOONG64LoweredPubBarrier:
		// DBAR 0x1A
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 0x1A

	case ssa.OpLOONG64LoweredPanicBoundsA, ssa.OpLOONG64LoweredPanicBoundsB, ssa.OpLOONG64LoweredPanicBoundsC:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ssagen.BoundsCheckFunc[v.AuxInt]
		s.UseArgs(16) // space used in callee args area by assembly stubs
	case ssa.OpLOONG64LoweredAtomicLoad8, ssa.OpLOONG64LoweredAtomicLoad32, ssa.OpLOONG64LoweredAtomicLoad64:
		// MOVB	(Rarg0), Rout
		// DBAR	0x14
		as := loong64.AMOVV
		switch v.Op {
		case ssa.OpLOONG64LoweredAtomicLoad8:
			as = loong64.AMOVB
		case ssa.OpLOONG64LoweredAtomicLoad32:
			as = loong64.AMOVW
		}
		p := s.Prog(as)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
		p1 := s.Prog(loong64.ADBAR)
		p1.From.Type = obj.TYPE_CONST
		p1.From.Offset = 0x14

	case ssa.OpLOONG64LoweredAtomicStore8,
		ssa.OpLOONG64LoweredAtomicStore32,
		ssa.OpLOONG64LoweredAtomicStore64:
		// DBAR 0x12
		// MOVx (Rarg1), Rout
		// DBAR 0x18
		movx := loong64.AMOVV
		switch v.Op {
		case ssa.OpLOONG64LoweredAtomicStore8:
			movx = loong64.AMOVB
		case ssa.OpLOONG64LoweredAtomicStore32:
			movx = loong64.AMOVW
		}
		p := s.Prog(loong64.ADBAR)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 0x12

		p1 := s.Prog(movx)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = v.Args[1].Reg()
		p1.To.Type = obj.TYPE_MEM
		p1.To.Reg = v.Args[0].Reg()

		p2 := s.Prog(loong64.ADBAR)
		p2.From.Type = obj.TYPE_CONST
		p2.From.Offset = 0x18

	case ssa.OpLOONG64LoweredAtomicStore8Variant,
		ssa.OpLOONG64LoweredAtomicStore32Variant,
		ssa.OpLOONG64LoweredAtomicStore64Variant:
		//AMSWAPx  Rarg1, (Rarg0), Rout
		amswapx := loong64.AAMSWAPDBV
		switch v.Op {
		case ssa.OpLOONG64LoweredAtomicStore32Variant:
			amswapx = loong64.AAMSWAPDBW
		case ssa.OpLOONG64LoweredAtomicStore8Variant:
			amswapx = loong64.AAMSWAPDBB
		}
		p := s.Prog(amswapx)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		p.RegTo2 = loong64.REGZERO

	case ssa.OpLOONG64LoweredAtomicExchange32, ssa.OpLOONG64LoweredAtomicExchange64:
		// AMSWAPx	Rarg1, (Rarg0), Rout
		amswapx := loong64.AAMSWAPDBV
		if v.Op == ssa.OpLOONG64LoweredAtomicExchange32 {
			amswapx = loong64.AAMSWAPDBW
		}
		p := s.Prog(amswapx)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		p.RegTo2 = v.Reg0()

	case ssa.OpLOONG64LoweredAtomicExchange8Variant:
		// AMSWAPDBB	Rarg1, (Rarg0), Rout
		p := s.Prog(loong64.AAMSWAPDBB)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		p.RegTo2 = v.Reg0()

	case ssa.OpLOONG64LoweredAtomicAdd32, ssa.OpLOONG64LoweredAtomicAdd64:
		// AMADDx  Rarg1, (Rarg0), Rout
		// ADDV    Rarg1, Rout, Rout
		amaddx := loong64.AAMADDDBV
		addx := loong64.AADDV
		if v.Op == ssa.OpLOONG64LoweredAtomicAdd32 {
			amaddx = loong64.AAMADDDBW
		}
		p := s.Prog(amaddx)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		p.RegTo2 = v.Reg0()

		p1 := s.Prog(addx)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = v.Args[1].Reg()
		p1.Reg = v.Reg0()
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = v.Reg0()

	case ssa.OpLOONG64LoweredAtomicCas32, ssa.OpLOONG64LoweredAtomicCas64:
		// MOVV $0, Rout
		// DBAR 0x14
		// LL	(Rarg0), Rtmp
		// BNE	Rtmp, Rarg1, 4(PC)
		// MOVV Rarg2, Rout
		// SC	Rout, (Rarg0)
		// BEQ	Rout, -4(PC)
		// DBAR 0x12
		ll := loong64.ALLV
		sc := loong64.ASCV
		if v.Op == ssa.OpLOONG64LoweredAtomicCas32 {
			ll = loong64.ALL
			sc = loong64.ASC
		}

		p := s.Prog(loong64.AMOVV)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = loong64.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

		p1 := s.Prog(loong64.ADBAR)
		p1.From.Type = obj.TYPE_CONST
		p1.From.Offset = 0x14

		p2 := s.Prog(ll)
		p2.From.Type = obj.TYPE_MEM
		p2.From.Reg = v.Args[0].Reg()
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = loong64.REGTMP

		p3 := s.Prog(loong64.ABNE)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = v.Args[1].Reg()
		p3.Reg = loong64.REGTMP
		p3.To.Type = obj.TYPE_BRANCH

		p4 := s.Prog(loong64.AMOVV)
		p4.From.Type = obj.TYPE_REG
		p4.From.Reg = v.Args[2].Reg()
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = v.Reg0()

		p5 := s.Prog(sc)
		p5.From.Type = obj.TYPE_REG
		p5.From.Reg = v.Reg0()
		p5.To.Type = obj.TYPE_MEM
		p5.To.Reg = v.Args[0].Reg()

		p6 := s.Prog(loong64.ABEQ)
		p6.From.Type = obj.TYPE_REG
		p6.From.Reg = v.Reg0()
		p6.To.Type = obj.TYPE_BRANCH
		p6.To.SetTarget(p2)

		p7 := s.Prog(loong64.ADBAR)
		p7.From.Type = obj.TYPE_CONST
		p7.From.Offset = 0x12
		p3.To.SetTarget(p7)

	case ssa.OpLOONG64LoweredAtomicAnd32,
		ssa.OpLOONG64LoweredAtomicOr32:
		// AM{AND,OR}DBx  Rarg1, (Rarg0), RegZero
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		p.RegTo2 = loong64.REGZERO

	case ssa.OpLOONG64LoweredAtomicAnd32value,
		ssa.OpLOONG64LoweredAtomicAnd64value,
		ssa.OpLOONG64LoweredAtomicOr64value,
		ssa.OpLOONG64LoweredAtomicOr32value:
		// AM{AND,OR}DBx  Rarg1, (Rarg0), Rout
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		p.RegTo2 = v.Reg0()

	case ssa.OpLOONG64LoweredAtomicCas64Variant, ssa.OpLOONG64LoweredAtomicCas32Variant:
		// MOVV         $0, Rout
		// MOVV         Rarg1, Rtmp
		// AMCASDBx     Rarg2, (Rarg0), Rtmp
		// BNE          Rarg1, Rtmp, 2(PC)
		// MOVV         $1, Rout
		// NOP

		amcasx := loong64.AAMCASDBV
		if v.Op == ssa.OpLOONG64LoweredAtomicCas32Variant {
			amcasx = loong64.AAMCASDBW
		}

		p := s.Prog(loong64.AMOVV)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = loong64.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

		p1 := s.Prog(loong64.AMOVV)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = v.Args[1].Reg()
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = loong64.REGTMP

		p2 := s.Prog(amcasx)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = v.Args[2].Reg()
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = v.Args[0].Reg()
		p2.RegTo2 = loong64.REGTMP

		p3 := s.Prog(loong64.ABNE)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = v.Args[1].Reg()
		p3.Reg = loong64.REGTMP
		p3.To.Type = obj.TYPE_BRANCH

		p4 := s.Prog(loong64.AMOVV)
		p4.From.Type = obj.TYPE_CONST
		p4.From.Offset = 0x1
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = v.Reg0()

		p5 := s.Prog(obj.ANOP)
		p3.To.SetTarget(p5)

	case ssa.OpLOONG64LoweredNilCheck:
		// Issue a load which will fault if arg is nil.
		p := s.Prog(loong64.AMOVB)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = loong64.REGTMP
		if logopt.Enabled() {
			logopt.LogOpt(v.Pos, "nilcheck", "genssa", v.Block.Func.Name)
		}
		if base.Debug.Nil != 0 && v.Pos.Line() > 1 { // v.Pos.Line()==1 in generated wrappers
			base.WarnfAt(v.Pos, "generated nil check")
		}
	case ssa.OpLOONG64FPFlagTrue,
		ssa.OpLOONG64FPFlagFalse:
		// MOVV	$0, r
		// BFPF	2(PC)
		// MOVV	$1, r
		branch := loong64.ABFPF
		if v.Op == ssa.OpLOONG64FPFlagFalse {
			branch = loong64.ABFPT
		}
		p := s.Prog(loong64.AMOVV)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = loong64.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
		p2 := s.Prog(branch)
		p2.To.Type = obj.TYPE_BRANCH
		p3 := s.Prog(loong64.AMOVV)
		p3.From.Type = obj.TYPE_CONST
		p3.From.Offset = 1
		p3.To.Type = obj.TYPE_REG
		p3.To.Reg = v.Reg()
		p4 := s.Prog(obj.ANOP) // not a machine instruction, for branch to land
		p2.To.SetTarget(p4)
	case ssa.OpLOONG64LoweredGetClosurePtr:
		// Closure pointer is R22 (loong64.REGCTXT).
		ssagen.CheckLoweredGetClosurePtr(v)
	case ssa.OpLOONG64LoweredGetCallerSP:
		// caller's SP is FixedFrameSize below the address of the first arg
		p := s.Prog(loong64.AMOVV)
		p.From.Type = obj.TYPE_ADDR
		p.From.Offset = -base.Ctxt.Arch.FixedFrameSize
		p.From.Name = obj.NAME_PARAM
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpLOONG64LoweredGetCallerPC:
		p := s.Prog(obj.AGETCALLERPC)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpLOONG64MASKEQZ, ssa.OpLOONG64MASKNEZ:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpClobber, ssa.OpClobberReg:
		// TODO: implement for clobberdead experiment. Nop is ok for now.
	default:
		v.Fatalf("genValue not implemented: %s", v.LongString())
	}
}

var blockJump = map[ssa.BlockKind]struct {
	asm, invasm obj.As
}{
	ssa.BlockLOONG64EQ:   {loong64.ABEQ, loong64.ABNE},
	ssa.BlockLOONG64NE:   {loong64.ABNE, loong64.ABEQ},
	ssa.BlockLOONG64LTZ:  {loong64.ABLTZ, loong64.ABGEZ},
	ssa.BlockLOONG64GEZ:  {loong64.ABGEZ, loong64.ABLTZ},
	ssa.BlockLOONG64LEZ:  {loong64.ABLEZ, loong64.ABGTZ},
	ssa.BlockLOONG64GTZ:  {loong64.ABGTZ, loong64.ABLEZ},
	ssa.BlockLOONG64FPT:  {loong64.ABFPT, loong64.ABFPF},
	ssa.BlockLOONG64FPF:  {loong64.ABFPF, loong64.ABFPT},
	ssa.BlockLOONG64BEQ:  {loong64.ABEQ, loong64.ABNE},
	ssa.BlockLOONG64BNE:  {loong64.ABNE, loong64.ABEQ},
	ssa.BlockLOONG64BGE:  {loong64.ABGE, loong64.ABLT},
	ssa.BlockLOONG64BLT:  {loong64.ABLT, loong64.ABGE},
	ssa.BlockLOONG64BLTU: {loong64.ABLTU, loong64.ABGEU},
	ssa.BlockLOONG64BGEU: {loong64.ABGEU, loong64.ABLTU},
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
		// defer returns in R19:
		// 0 if we should continue executing
		// 1 if we should jump to deferreturn call
		p := s.Prog(loong64.ABNE)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = loong64.REGZERO
		p.Reg = loong64.REG_R19
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
	case ssa.BlockLOONG64EQ, ssa.BlockLOONG64NE,
		ssa.BlockLOONG64LTZ, ssa.BlockLOONG64GEZ,
		ssa.BlockLOONG64LEZ, ssa.BlockLOONG64GTZ,
		ssa.BlockLOONG64BEQ, ssa.BlockLOONG64BNE,
		ssa.BlockLOONG64BLT, ssa.BlockLOONG64BGE,
		ssa.BlockLOONG64BLTU, ssa.BlockLOONG64BGEU,
		ssa.BlockLOONG64FPT, ssa.BlockLOONG64FPF:
		jmp := blockJump[b.Kind]
		var p *obj.Prog
		switch next {
		case b.Succs[0].Block():
			p = s.Br(jmp.invasm, b.Succs[1].Block())
		case b.Succs[1].Block():
			p = s.Br(jmp.asm, b.Succs[0].Block())
		default:
			if b.Likely != ssa.BranchUnlikely {
				p = s.Br(jmp.asm, b.Succs[0].Block())
				s.Br(obj.AJMP, b.Succs[1].Block())
			} else {
				p = s.Br(jmp.invasm, b.Succs[1].Block())
				s.Br(obj.AJMP, b.Succs[0].Block())
			}
		}
		switch b.Kind {
		case ssa.BlockLOONG64BEQ, ssa.BlockLOONG64BNE,
			ssa.BlockLOONG64BGE, ssa.BlockLOONG64BLT,
			ssa.BlockLOONG64BGEU, ssa.BlockLOONG64BLTU:
			p.From.Type = obj.TYPE_REG
			p.From.Reg = b.Controls[0].Reg()
			p.Reg = b.Controls[1].Reg()
		case ssa.BlockLOONG64EQ, ssa.BlockLOONG64NE,
			ssa.BlockLOONG64LTZ, ssa.BlockLOONG64GEZ,
			ssa.BlockLOONG64LEZ, ssa.BlockLOONG64GTZ,
			ssa.BlockLOONG64FPT, ssa.BlockLOONG64FPF:
			if !b.Controls[0].Type.IsFlags() {
				p.From.Type = obj.TYPE_REG
				p.From.Reg = b.Controls[0].Reg()
			}
		}
	default:
		b.Fatalf("branch not implemented: %s", b.LongString())
	}
}

func loadRegResult(s *ssagen.State, f *ssa.Func, t *types.Type, reg int16, n *ir.Name, off int64) *obj.Prog {
	p := s.Prog(loadByType(t, reg))
	p.From.Type = obj.TYPE_MEM
	p.From.Name = obj.NAME_AUTO
	p.From.Sym = n.Linksym()
	p.From.Offset = n.FrameOffset() + off
	p.To.Type = obj.TYPE_REG
	p.To.Reg = reg
	return p
}

func spillArgReg(pp *objw.Progs, p *obj.Prog, f *ssa.Func, t *types.Type, reg int16, n *ir.Name, off int64) *obj.Prog {
	p = pp.Append(p, storeByType(t, reg), obj.TYPE_REG, reg, 0, obj.TYPE_MEM, 0, n.FrameOffset()+off)
	p.To.Name = obj.NAME_PARAM
	p.To.Sym = n.Linksym()
	p.Pos = p.Pos.WithNotStmt()
	return p
}
```