Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding and Context:**

The first step is to recognize the file path: `go/src/cmd/compile/internal/mips64/ssa.go`. This immediately tells us:

* **`go/src`:** This is part of the Go standard library source code.
* **`cmd/compile`:** This relates to the Go compiler.
* **`internal`:** This package is for internal use within the compiler.
* **`mips64`:** This code is specific to the MIPS64 architecture.
* **`ssa.go`:**  This strongly suggests that the file deals with the Static Single Assignment (SSA) form, an intermediate representation used by the compiler for optimization.

Therefore, the code's purpose is to generate machine code (specifically for MIPS64) from the SSA representation of Go programs.

**2. High-Level Functionality Identification:**

Skimming through the code reveals several key function names and patterns:

* `isFPreg`, `isHILO`:  These clearly deal with identifying specific types of registers (floating-point and HI/LO).
* `loadByType`, `storeByType`: These functions determine the correct MIPS instruction for loading and storing data based on the Go type. This is a core function in code generation.
* `ssaGenValue`: This is a central function, and the `switch v.Op` suggests it handles different SSA operations (like copying, loading, storing, arithmetic, etc.). This is the heart of the code generation for individual SSA values.
* `ssaGenBlock`: This function seems to handle the generation of code for control flow blocks (like conditional jumps, function returns).
* `blockJump`: This map associates SSA block kinds with corresponding MIPS jump instructions.

From this initial scan, we can infer the primary function: **This code translates Go's SSA representation into MIPS64 assembly instructions.**

**3. Deeper Dive into Key Functions:**

Now, let's examine the core functions in more detail:

* **`loadByType`, `storeByType`:**  Notice the logic based on `t.Size()` and `t.IsSigned()`. This directly maps Go's type system to MIPS load/store instructions (e.g., `AMOVB` for signed byte, `AMOVBU` for unsigned byte). This reinforces the code generation purpose.

* **`ssaGenValue`:** This is the most complex. The `switch v.Op` is crucial. Analyze a few cases:
    * `ssa.OpCopy`, `ssa.OpMIPS64MOVVreg`: Handles moving data between registers, with special handling for floating-point and HI/LO registers. This highlights the architecture-specific nature of the code.
    * `ssa.OpLoadReg`, `ssa.OpStoreReg`: Generates load and store instructions, calling `loadByType` and `storeByType`. The handling of HI/LO registers further emphasizes MIPS specifics.
    * Arithmetic operations (`ssa.OpMIPS64ADDV`, etc.): Directly translates SSA ops to corresponding MIPS assembly instructions.
    * Constant operations (`ssa.OpMIPS64ADDVconst`, etc.):  Handles operations with immediate values.
    * Memory access (`ssa.OpMIPS64MOVBload`, `ssa.OpMIPS64MOVBstore`, etc.): Generates load and store instructions from/to memory locations. The use of `ssagen.AddrAuto` and `ssagen.AddAux` suggests interaction with other parts of the compiler for address calculation.
    * Function calls (`ssa.OpMIPS64CALLstatic`, etc.):  Indicates handling of function call conventions.
    * Atomic operations (`ssa.OpMIPS64LoweredAtomicLoad8`, etc.): Shows support for atomic operations, using MIPS's load-linked/store-conditional instructions.

* **`ssaGenBlock`:**  The `switch b.Kind` handles different control flow structures:
    * `ssa.BlockPlain`: Simple unconditional jump.
    * `ssa.BlockDefer`:  Handles the logic for `defer` statements.
    * `ssa.BlockRet`: Generates the `ARET` (return) instruction.
    * Conditional blocks (`ssa.BlockMIPS64EQ`, etc.): Uses the `blockJump` map to generate conditional branch instructions.

**4. Connecting to Go Features and Examples:**

Based on the identified functionalities, we can connect them back to specific Go language features:

* **Basic Data Types and Operations:** The `loadByType`, `storeByType`, and the various arithmetic/logical operations in `ssaGenValue` directly implement how Go's basic types (int, float, bool, etc.) and their operations are translated to MIPS.
* **Pointers and Memory Access:**  The load and store operations (`ssa.OpLoadReg`, `ssa.OpStoreReg`, `ssa.OpMIPS64MOVBload`, etc.) are crucial for handling pointers and accessing memory.
* **Function Calls:** The `ssa.OpMIPS64CALLstatic`, `ssa.OpMIPS64CALLclosure`, `ssa.OpMIPS64CALLinter` cases handle different types of function calls in Go.
* **`defer` Statements:** The `ssaGenBlock`'s `ssa.BlockDefer` case directly implements the behavior of `defer`.
* **Atomic Operations:** The `ssa.OpMIPS64LoweredAtomic*` operations correspond to Go's `sync/atomic` package.
* **Nil Checks:**  `ssa.OpMIPS64LoweredNilCheck` implements the runtime checks for nil pointers.

This allows us to create illustrative Go examples.

**5. Identifying Potential Issues and Assumptions:**

* **Register Conventions:** The code makes assumptions about which registers are used for specific purposes (e.g., `mips.REGCTXT` for the closure pointer). This is architecture-specific and could be a point of error if not handled consistently.
* **Function Call ABI:** The way function arguments and return values are handled is dependent on the Application Binary Interface (ABI) for MIPS64. Mistakes in adhering to the ABI would lead to incorrect code.
* **Atomic Operation Correctness:**  The implementation of atomic operations needs to be precisely correct to guarantee atomicity and avoid race conditions. The use of `SYNC`, `LL`, and `SC` instructions is crucial here.
* **Optimization Levels:**  The generated code might vary depending on the compiler's optimization level. This code snippet likely represents a stage in the compilation process before more aggressive optimizations are applied.

**6. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, covering:

* **Overall Functionality:** Start with a concise summary.
* **Detailed Functionality:**  Elaborate on the key functions and their roles.
* **Go Feature Implementation:** Connect the code to specific Go language features with illustrative examples.
* **Code Reasoning (with Assumptions, Inputs, and Outputs):** For more complex parts (like atomic operations or `defer`), provide a step-by-step explanation with hypothetical scenarios.
* **Command-Line Parameters:**  If applicable (though not explicitly present in this snippet), explain how relevant compiler flags might affect this code.
* **Common Mistakes:**  Highlight potential pitfalls for developers working with this type of low-level code.

By following these steps, we can effectively analyze and understand the purpose and functionality of the given Go code snippet. The iterative process of identifying high-level functions, diving deeper into key components, and connecting them to the larger context of the Go compiler and language features is essential for a comprehensive understanding.
这段代码是 Go 语言编译器的一部分，位于 `go/src/cmd/compile/internal/mips64/ssa.go`，它的主要功能是 **将 Go 语言的 SSA (Static Single Assignment) 中间表示形式转换为 MIPS64 架构的机器码指令**。

更具体地说，它定义了一些辅助函数和核心的 `ssaGenValue` 和 `ssaGenBlock` 函数，用于遍历 SSA 图并生成相应的 MIPS64 汇编指令。

以下是它的主要功能点：

1. **类型相关的辅助函数:**
   - `isFPreg(r int16) bool`: 判断给定的寄存器 `r` 是否为浮点寄存器。
   - `isHILO(r int16) bool`: 判断给定的寄存器 `r` 是否为 `HI` 或 `LO` 特殊寄存器（用于乘法和除法结果）。
   - `loadByType(t *types.Type, r int16) obj.As`:  根据 Go 语言的类型 `t` 和目标寄存器 `r`，返回合适的 MIPS64 加载指令。它会区分浮点和整数类型，以及不同大小和符号的整数类型。
   - `storeByType(t *types.Type, r int16) obj.As`: 根据 Go 语言的类型 `t` 和源寄存器 `r`，返回合适的 MIPS64 存储指令。同样会区分浮点和整数类型。

2. **核心的 SSA 值生成函数 `ssaGenValue(s *ssagen.State, v *ssa.Value)`:**
   - 遍历 SSA 图中的每个 `ssa.Value` (代表一个操作或值)。
   - 根据 `v.Op` (操作码) 的不同，生成相应的 MIPS64 汇编指令。
   - 支持各种 SSA 操作，包括：
     - 数据移动 (`ssa.OpCopy`, `ssa.OpMIPS64MOVVreg`)
     - 常数加载 (`ssa.OpMIPS64MOVVconst`, `ssa.OpMIPS64MOVFconst`, `ssa.OpMIPS64MOVDconst`)
     - 寄存器加载和存储 (`ssa.OpLoadReg`, `ssa.OpStoreReg`)
     - 算术和逻辑运算 (`ssa.OpMIPS64ADDV`, `ssa.OpMIPS64SUBV`, `ssa.OpMIPS64AND`, 等等)
     - 比较运算 (`ssa.OpMIPS64SGT`, `ssa.OpMIPS64SGTU`, `ssa.OpMIPS64CMPEQF`, 等等)
     - 地址加载 (`ssa.OpMIPS64MOVVaddr`)
     - 内存加载和存储 (`ssa.OpMIPS64MOVBload`, `ssa.OpMIPS64MOVHstore`, 等等)
     - 类型转换 (`ssa.OpMIPS64MOVBreg`, `ssa.OpMIPS64MOVWF`, 等等)
     - 函数调用 (`ssa.OpMIPS64CALLstatic`, `ssa.OpMIPS64CALLclosure`, `ssa.OpMIPS64CALLinter`, `ssa.OpMIPS64CALLtail`)
     - 内置函数 (`ssa.OpMIPS64DUFFZERO`, `ssa.OpMIPS64DUFFCOPY`)
     - 原子操作 (`ssa.OpMIPS64LoweredAtomicLoad8`, `ssa.OpMIPS64LoweredAtomicStore32`, 等等)
     - Nil 检查 (`ssa.OpMIPS64LoweredNilCheck`)
     - 获取闭包指针、调用者 SP/PC (`ssa.OpMIPS64LoweredGetClosurePtr`, `ssa.OpMIPS64LoweredGetCallerSP`, `ssa.OpMIPS64LoweredGetCallerPC`)

3. **核心的 SSA 块生成函数 `ssaGenBlock(s *ssagen.State, b, next *ssa.Block)`:**
   - 遍历 SSA 图中的每个 `ssa.Block` (代表一个代码块)。
   - 根据 `b.Kind` (块的类型，例如 `ssa.BlockPlain`, `ssa.BlockIf`, `ssa.BlockRet` 等) 生成相应的控制流指令（例如跳转指令）。
   - 处理不同类型的块，包括：
     - 普通块 (`ssa.BlockPlain`)
     - `defer` 块 (`ssa.BlockDefer`)
     - 退出块和跳转返回块 (`ssa.BlockExit`, `ssa.BlockRetJmp`)
     - 返回块 (`ssa.BlockRet`)
     - 条件分支块 (`ssa.BlockMIPS64EQ`, `ssa.BlockMIPS64NE`, 等等)

4. **块跳转映射 `blockJump`:**
   - 定义了一个映射，将 SSA 的块类型映射到对应的 MIPS64 条件跳转指令和其反向指令。

**它可以推理出这是 Go 语言编译器中，MIPS64 架构的代码生成后端实现。** 它负责将 Go 语言的高级抽象转换为可以在 MIPS64 处理器上执行的低级指令。

**Go 代码示例 (推理):**

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

在编译这个代码时，编译器会将其转换为 SSA 形式，然后 `ssaGenValue` 函数会处理 `add` 函数中的加法操作。

**假设的 SSA 输入 (简化版):**

```
b1:
  v1 = Param <int> {a}
  v2 = Param <int> {b}
  v3 = AddInt <int> v1 v2
  Return v3
```

**`ssaGenValue` 的处理 (假设):**

当 `ssaGenValue` 处理 `v3 = AddInt <int> v1 v2` 时，它会执行以下操作（假设 `v1` 在寄存器 `R3`，`v2` 在寄存器 `R4`，并且结果需要放到寄存器 `R5`）：

```go
case ssa.OpAddInt: // 实际上在 MIPS64 架构下可能是 OpMIPS64ADDV
	p := s.Prog(mips.AADDV) // 生成 ADDV 指令
	p.From.Type = obj.TYPE_REG
	p.From.Reg = v.Args[1].Reg() // v2 的寄存器 (R4)
	p.Reg = v.Args[0].Reg()    // v1 的寄存器 (R3)
	p.To.Type = obj.TYPE_REG
	p.To.Reg = v.Reg()       // v3 的寄存器 (R5)
```

**生成的 MIPS64 汇编指令 (可能类似):**

```assembly
ADDV R4, R3, R5  // R5 = R3 + R4
```

**假设的输入与输出 (针对 `loadByType`):**

假设我们有以下 Go 代码，并且需要加载一个 `int32` 类型的变量到寄存器：

```go
var x int32 = 10

func main() {
	var y int32
	y = x
	println(y)
}
```

在 SSA 生成阶段，加载 `x` 的操作可能对应一个 `ssa.OpLoadReg`。

**假设的 SSA 输入 (简化版):**

```
b1:
  v1 = LoadReg <int32> {&x}
```

**`ssaGenValue` 的处理 (假设 `v1` 需要加载到寄存器 `R6`):**

```go
case ssa.OpLoadReg:
	r := v.Reg() // R6
	p := s.Prog(loadByType(v.Type, r)) // 调用 loadByType
	// 假设 loadByType(int32, R6) 返回 mips.AMOVW (Move Word)
	// 并且 v.Args[0] 代表 &x 的地址
	ssagen.AddrAuto(&p.From, v.Args[0]) // 设置加载地址
	p.To.Type = obj.TYPE_REG
	p.To.Reg = r // R6
```

**生成的 MIPS64 汇编指令 (可能类似):**

```assembly
MOVW x, R6  // 将地址 x 处的一个 word (32位) 加载到 R6
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的其他部分，例如 `cmd/compile/internal/gc` 包。但是，编译器的命令行参数会影响到 SSA 的生成和优化，进而影响到这段代码最终生成的机器码。

例如，`-gcflags` 可以传递参数来控制编译器的行为，包括优化级别。更高的优化级别可能会导致 SSA 图更复杂，从而影响 `ssaGenValue` 和 `ssaGenBlock` 的执行路径和生成的指令。

**使用者易犯错的点:**

作为 Go 语言的使用者，一般不会直接接触到这部分代码。这部分是编译器内部的实现细节。  但是，理解编译器的工作原理可以帮助我们避免一些性能陷阱。

一个潜在的、与代码生成相关的易错点（虽然不是直接由这段代码引起，但与编译器行为有关）是 **对齐问题**。  MIPS64 架构对内存访问的对齐有要求。如果 Go 代码中存在不安全的指针操作，导致未对齐的内存访问，可能会导致程序崩溃或性能下降。虽然编译器会尽量处理对齐问题，但在某些极端情况下，开发者仍然需要注意。

例如，使用 `unsafe` 包进行指针操作时，如果开发者不理解内存布局和对齐规则，可能会导致生成非法的或低效的机器码。

**总结:**

这段 `ssa.go` 文件是 Go 语言编译器中 MIPS64 架构代码生成的核心部分。它负责将 Go 语言的 SSA 中间表示转换为可以在 MIPS64 处理器上执行的机器码指令。理解这部分代码有助于深入了解 Go 语言的编译过程和底层机制。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/mips64/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mips64

import (
	"math"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/ssagen"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/obj/mips"
)

// isFPreg reports whether r is an FP register.
func isFPreg(r int16) bool {
	return mips.REG_F0 <= r && r <= mips.REG_F31
}

// isHILO reports whether r is HI or LO register.
func isHILO(r int16) bool {
	return r == mips.REG_HI || r == mips.REG_LO
}

// loadByType returns the load instruction of the given type.
func loadByType(t *types.Type, r int16) obj.As {
	if isFPreg(r) {
		if t.Size() == 4 { // float32 or int32
			return mips.AMOVF
		} else { // float64 or int64
			return mips.AMOVD
		}
	} else {
		switch t.Size() {
		case 1:
			if t.IsSigned() {
				return mips.AMOVB
			} else {
				return mips.AMOVBU
			}
		case 2:
			if t.IsSigned() {
				return mips.AMOVH
			} else {
				return mips.AMOVHU
			}
		case 4:
			if t.IsSigned() {
				return mips.AMOVW
			} else {
				return mips.AMOVWU
			}
		case 8:
			return mips.AMOVV
		}
	}
	panic("bad load type")
}

// storeByType returns the store instruction of the given type.
func storeByType(t *types.Type, r int16) obj.As {
	if isFPreg(r) {
		if t.Size() == 4 { // float32 or int32
			return mips.AMOVF
		} else { // float64 or int64
			return mips.AMOVD
		}
	} else {
		switch t.Size() {
		case 1:
			return mips.AMOVB
		case 2:
			return mips.AMOVH
		case 4:
			return mips.AMOVW
		case 8:
			return mips.AMOVV
		}
	}
	panic("bad store type")
}

func ssaGenValue(s *ssagen.State, v *ssa.Value) {
	switch v.Op {
	case ssa.OpCopy, ssa.OpMIPS64MOVVreg:
		if v.Type.IsMemory() {
			return
		}
		x := v.Args[0].Reg()
		y := v.Reg()
		if x == y {
			return
		}
		as := mips.AMOVV
		if isFPreg(x) && isFPreg(y) {
			as = mips.AMOVD
		}
		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = x
		p.To.Type = obj.TYPE_REG
		p.To.Reg = y
		if isHILO(x) && isHILO(y) || isHILO(x) && isFPreg(y) || isFPreg(x) && isHILO(y) {
			// cannot move between special registers, use TMP as intermediate
			p.To.Reg = mips.REGTMP
			p = s.Prog(mips.AMOVV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = mips.REGTMP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = y
		}
	case ssa.OpMIPS64MOVVnop:
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
		if isHILO(r) {
			// cannot directly load, load to TMP and move
			p.To.Reg = mips.REGTMP
			p = s.Prog(mips.AMOVV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = mips.REGTMP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = r
		}
	case ssa.OpStoreReg:
		if v.Type.IsFlags() {
			v.Fatalf("store flags not implemented: %v", v.LongString())
			return
		}
		r := v.Args[0].Reg()
		if isHILO(r) {
			// cannot directly store, move to TMP and store
			p := s.Prog(mips.AMOVV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = r
			p.To.Type = obj.TYPE_REG
			p.To.Reg = mips.REGTMP
			r = mips.REGTMP
		}
		p := s.Prog(storeByType(v.Type, r))
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r
		ssagen.AddrAuto(&p.To, v)
	case ssa.OpMIPS64ADDV,
		ssa.OpMIPS64SUBV,
		ssa.OpMIPS64AND,
		ssa.OpMIPS64OR,
		ssa.OpMIPS64XOR,
		ssa.OpMIPS64NOR,
		ssa.OpMIPS64SLLV,
		ssa.OpMIPS64SRLV,
		ssa.OpMIPS64SRAV,
		ssa.OpMIPS64ADDF,
		ssa.OpMIPS64ADDD,
		ssa.OpMIPS64SUBF,
		ssa.OpMIPS64SUBD,
		ssa.OpMIPS64MULF,
		ssa.OpMIPS64MULD,
		ssa.OpMIPS64DIVF,
		ssa.OpMIPS64DIVD:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPS64SGT,
		ssa.OpMIPS64SGTU:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPS64ADDVconst,
		ssa.OpMIPS64SUBVconst,
		ssa.OpMIPS64ANDconst,
		ssa.OpMIPS64ORconst,
		ssa.OpMIPS64XORconst,
		ssa.OpMIPS64NORconst,
		ssa.OpMIPS64SLLVconst,
		ssa.OpMIPS64SRLVconst,
		ssa.OpMIPS64SRAVconst,
		ssa.OpMIPS64SGTconst,
		ssa.OpMIPS64SGTUconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPS64MULV,
		ssa.OpMIPS64MULVU,
		ssa.OpMIPS64DIVV,
		ssa.OpMIPS64DIVVU:
		// result in hi,lo
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.Reg = v.Args[0].Reg()
	case ssa.OpMIPS64MOVVconst:
		r := v.Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
		if isFPreg(r) || isHILO(r) {
			// cannot move into FP or special registers, use TMP as intermediate
			p.To.Reg = mips.REGTMP
			p = s.Prog(mips.AMOVV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = mips.REGTMP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = r
		}
	case ssa.OpMIPS64MOVFconst,
		ssa.OpMIPS64MOVDconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_FCONST
		p.From.Val = math.Float64frombits(uint64(v.AuxInt))
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPS64CMPEQF,
		ssa.OpMIPS64CMPEQD,
		ssa.OpMIPS64CMPGEF,
		ssa.OpMIPS64CMPGED,
		ssa.OpMIPS64CMPGTF,
		ssa.OpMIPS64CMPGTD:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = v.Args[1].Reg()
	case ssa.OpMIPS64MOVVaddr:
		p := s.Prog(mips.AMOVV)
		p.From.Type = obj.TYPE_ADDR
		p.From.Reg = v.Args[0].Reg()
		var wantreg string
		// MOVV $sym+off(base), R
		// the assembler expands it as the following:
		// - base is SP: add constant offset to SP (R29)
		//               when constant is large, tmp register (R23) may be used
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
	case ssa.OpMIPS64MOVBload,
		ssa.OpMIPS64MOVBUload,
		ssa.OpMIPS64MOVHload,
		ssa.OpMIPS64MOVHUload,
		ssa.OpMIPS64MOVWload,
		ssa.OpMIPS64MOVWUload,
		ssa.OpMIPS64MOVVload,
		ssa.OpMIPS64MOVFload,
		ssa.OpMIPS64MOVDload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPS64MOVBstore,
		ssa.OpMIPS64MOVHstore,
		ssa.OpMIPS64MOVWstore,
		ssa.OpMIPS64MOVVstore,
		ssa.OpMIPS64MOVFstore,
		ssa.OpMIPS64MOVDstore:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpMIPS64MOVBstorezero,
		ssa.OpMIPS64MOVHstorezero,
		ssa.OpMIPS64MOVWstorezero,
		ssa.OpMIPS64MOVVstorezero:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = mips.REGZERO
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpMIPS64MOVBreg,
		ssa.OpMIPS64MOVBUreg,
		ssa.OpMIPS64MOVHreg,
		ssa.OpMIPS64MOVHUreg,
		ssa.OpMIPS64MOVWreg,
		ssa.OpMIPS64MOVWUreg:
		a := v.Args[0]
		for a.Op == ssa.OpCopy || a.Op == ssa.OpMIPS64MOVVreg {
			a = a.Args[0]
		}
		if a.Op == ssa.OpLoadReg && mips.REG_R0 <= a.Reg() && a.Reg() <= mips.REG_R31 {
			// LoadReg from a narrower type does an extension, except loading
			// to a floating point register. So only eliminate the extension
			// if it is loaded to an integer register.
			t := a.Type
			switch {
			case v.Op == ssa.OpMIPS64MOVBreg && t.Size() == 1 && t.IsSigned(),
				v.Op == ssa.OpMIPS64MOVBUreg && t.Size() == 1 && !t.IsSigned(),
				v.Op == ssa.OpMIPS64MOVHreg && t.Size() == 2 && t.IsSigned(),
				v.Op == ssa.OpMIPS64MOVHUreg && t.Size() == 2 && !t.IsSigned(),
				v.Op == ssa.OpMIPS64MOVWreg && t.Size() == 4 && t.IsSigned(),
				v.Op == ssa.OpMIPS64MOVWUreg && t.Size() == 4 && !t.IsSigned():
				// arg is a proper-typed load, already zero/sign-extended, don't extend again
				if v.Reg() == v.Args[0].Reg() {
					return
				}
				p := s.Prog(mips.AMOVV)
				p.From.Type = obj.TYPE_REG
				p.From.Reg = v.Args[0].Reg()
				p.To.Type = obj.TYPE_REG
				p.To.Reg = v.Reg()
				return
			default:
			}
		}
		fallthrough
	case ssa.OpMIPS64MOVWF,
		ssa.OpMIPS64MOVWD,
		ssa.OpMIPS64TRUNCFW,
		ssa.OpMIPS64TRUNCDW,
		ssa.OpMIPS64MOVVF,
		ssa.OpMIPS64MOVVD,
		ssa.OpMIPS64TRUNCFV,
		ssa.OpMIPS64TRUNCDV,
		ssa.OpMIPS64MOVFD,
		ssa.OpMIPS64MOVDF,
		ssa.OpMIPS64MOVWfpgp,
		ssa.OpMIPS64MOVWgpfp,
		ssa.OpMIPS64MOVVfpgp,
		ssa.OpMIPS64MOVVgpfp,
		ssa.OpMIPS64NEGF,
		ssa.OpMIPS64NEGD,
		ssa.OpMIPS64ABSD,
		ssa.OpMIPS64SQRTF,
		ssa.OpMIPS64SQRTD:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPS64NEGV:
		// SUB from REGZERO
		p := s.Prog(mips.ASUBVU)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = mips.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPS64DUFFZERO:
		// runtime.duffzero expects start address - 8 in R1
		p := s.Prog(mips.ASUBVU)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 8
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = mips.REG_R1
		p = s.Prog(obj.ADUFFZERO)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Duffzero
		p.To.Offset = v.AuxInt
	case ssa.OpMIPS64LoweredZero:
		// SUBV	$8, R1
		// MOVV	R0, 8(R1)
		// ADDV	$8, R1
		// BNE	Rarg1, R1, -2(PC)
		// arg1 is the address of the last element to zero
		var sz int64
		var mov obj.As
		switch {
		case v.AuxInt%8 == 0:
			sz = 8
			mov = mips.AMOVV
		case v.AuxInt%4 == 0:
			sz = 4
			mov = mips.AMOVW
		case v.AuxInt%2 == 0:
			sz = 2
			mov = mips.AMOVH
		default:
			sz = 1
			mov = mips.AMOVB
		}
		p := s.Prog(mips.ASUBVU)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = sz
		p.To.Type = obj.TYPE_REG
		p.To.Reg = mips.REG_R1
		p2 := s.Prog(mov)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = mips.REGZERO
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = mips.REG_R1
		p2.To.Offset = sz
		p3 := s.Prog(mips.AADDVU)
		p3.From.Type = obj.TYPE_CONST
		p3.From.Offset = sz
		p3.To.Type = obj.TYPE_REG
		p3.To.Reg = mips.REG_R1
		p4 := s.Prog(mips.ABNE)
		p4.From.Type = obj.TYPE_REG
		p4.From.Reg = v.Args[1].Reg()
		p4.Reg = mips.REG_R1
		p4.To.Type = obj.TYPE_BRANCH
		p4.To.SetTarget(p2)
	case ssa.OpMIPS64DUFFCOPY:
		p := s.Prog(obj.ADUFFCOPY)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Duffcopy
		p.To.Offset = v.AuxInt
	case ssa.OpMIPS64LoweredMove:
		// SUBV	$8, R1
		// MOVV	8(R1), Rtmp
		// MOVV	Rtmp, (R2)
		// ADDV	$8, R1
		// ADDV	$8, R2
		// BNE	Rarg2, R1, -4(PC)
		// arg2 is the address of the last element of src
		var sz int64
		var mov obj.As
		switch {
		case v.AuxInt%8 == 0:
			sz = 8
			mov = mips.AMOVV
		case v.AuxInt%4 == 0:
			sz = 4
			mov = mips.AMOVW
		case v.AuxInt%2 == 0:
			sz = 2
			mov = mips.AMOVH
		default:
			sz = 1
			mov = mips.AMOVB
		}
		p := s.Prog(mips.ASUBVU)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = sz
		p.To.Type = obj.TYPE_REG
		p.To.Reg = mips.REG_R1
		p2 := s.Prog(mov)
		p2.From.Type = obj.TYPE_MEM
		p2.From.Reg = mips.REG_R1
		p2.From.Offset = sz
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = mips.REGTMP
		p3 := s.Prog(mov)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = mips.REGTMP
		p3.To.Type = obj.TYPE_MEM
		p3.To.Reg = mips.REG_R2
		p4 := s.Prog(mips.AADDVU)
		p4.From.Type = obj.TYPE_CONST
		p4.From.Offset = sz
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = mips.REG_R1
		p5 := s.Prog(mips.AADDVU)
		p5.From.Type = obj.TYPE_CONST
		p5.From.Offset = sz
		p5.To.Type = obj.TYPE_REG
		p5.To.Reg = mips.REG_R2
		p6 := s.Prog(mips.ABNE)
		p6.From.Type = obj.TYPE_REG
		p6.From.Reg = v.Args[2].Reg()
		p6.Reg = mips.REG_R1
		p6.To.Type = obj.TYPE_BRANCH
		p6.To.SetTarget(p2)
	case ssa.OpMIPS64CALLstatic, ssa.OpMIPS64CALLclosure, ssa.OpMIPS64CALLinter:
		s.Call(v)
	case ssa.OpMIPS64CALLtail:
		s.TailCall(v)
	case ssa.OpMIPS64LoweredWB:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		// AuxInt encodes how many buffer entries we need.
		p.To.Sym = ir.Syms.GCWriteBarrier[v.AuxInt-1]
	case ssa.OpMIPS64LoweredPanicBoundsA, ssa.OpMIPS64LoweredPanicBoundsB, ssa.OpMIPS64LoweredPanicBoundsC:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ssagen.BoundsCheckFunc[v.AuxInt]
		s.UseArgs(16) // space used in callee args area by assembly stubs
	case ssa.OpMIPS64LoweredAtomicLoad8, ssa.OpMIPS64LoweredAtomicLoad32, ssa.OpMIPS64LoweredAtomicLoad64:
		as := mips.AMOVV
		switch v.Op {
		case ssa.OpMIPS64LoweredAtomicLoad8:
			as = mips.AMOVB
		case ssa.OpMIPS64LoweredAtomicLoad32:
			as = mips.AMOVW
		}
		s.Prog(mips.ASYNC)
		p := s.Prog(as)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
		s.Prog(mips.ASYNC)
	case ssa.OpMIPS64LoweredAtomicStore8, ssa.OpMIPS64LoweredAtomicStore32, ssa.OpMIPS64LoweredAtomicStore64:
		as := mips.AMOVV
		switch v.Op {
		case ssa.OpMIPS64LoweredAtomicStore8:
			as = mips.AMOVB
		case ssa.OpMIPS64LoweredAtomicStore32:
			as = mips.AMOVW
		}
		s.Prog(mips.ASYNC)
		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		s.Prog(mips.ASYNC)
	case ssa.OpMIPS64LoweredAtomicStorezero32, ssa.OpMIPS64LoweredAtomicStorezero64:
		as := mips.AMOVV
		if v.Op == ssa.OpMIPS64LoweredAtomicStorezero32 {
			as = mips.AMOVW
		}
		s.Prog(mips.ASYNC)
		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = mips.REGZERO
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		s.Prog(mips.ASYNC)
	case ssa.OpMIPS64LoweredAtomicExchange32, ssa.OpMIPS64LoweredAtomicExchange64:
		// SYNC
		// MOVV	Rarg1, Rtmp
		// LL	(Rarg0), Rout
		// SC	Rtmp, (Rarg0)
		// BEQ	Rtmp, -3(PC)
		// SYNC
		ll := mips.ALLV
		sc := mips.ASCV
		if v.Op == ssa.OpMIPS64LoweredAtomicExchange32 {
			ll = mips.ALL
			sc = mips.ASC
		}
		s.Prog(mips.ASYNC)
		p := s.Prog(mips.AMOVV)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = mips.REGTMP
		p1 := s.Prog(ll)
		p1.From.Type = obj.TYPE_MEM
		p1.From.Reg = v.Args[0].Reg()
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = v.Reg0()
		p2 := s.Prog(sc)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = mips.REGTMP
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = v.Args[0].Reg()
		p3 := s.Prog(mips.ABEQ)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = mips.REGTMP
		p3.To.Type = obj.TYPE_BRANCH
		p3.To.SetTarget(p)
		s.Prog(mips.ASYNC)
	case ssa.OpMIPS64LoweredAtomicAdd32, ssa.OpMIPS64LoweredAtomicAdd64:
		// SYNC
		// LL	(Rarg0), Rout
		// ADDV Rarg1, Rout, Rtmp
		// SC	Rtmp, (Rarg0)
		// BEQ	Rtmp, -3(PC)
		// SYNC
		// ADDV Rarg1, Rout
		ll := mips.ALLV
		sc := mips.ASCV
		if v.Op == ssa.OpMIPS64LoweredAtomicAdd32 {
			ll = mips.ALL
			sc = mips.ASC
		}
		s.Prog(mips.ASYNC)
		p := s.Prog(ll)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
		p1 := s.Prog(mips.AADDVU)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = v.Args[1].Reg()
		p1.Reg = v.Reg0()
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = mips.REGTMP
		p2 := s.Prog(sc)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = mips.REGTMP
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = v.Args[0].Reg()
		p3 := s.Prog(mips.ABEQ)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = mips.REGTMP
		p3.To.Type = obj.TYPE_BRANCH
		p3.To.SetTarget(p)
		s.Prog(mips.ASYNC)
		p4 := s.Prog(mips.AADDVU)
		p4.From.Type = obj.TYPE_REG
		p4.From.Reg = v.Args[1].Reg()
		p4.Reg = v.Reg0()
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = v.Reg0()
	case ssa.OpMIPS64LoweredAtomicAddconst32, ssa.OpMIPS64LoweredAtomicAddconst64:
		// SYNC
		// LL	(Rarg0), Rout
		// ADDV $auxint, Rout, Rtmp
		// SC	Rtmp, (Rarg0)
		// BEQ	Rtmp, -3(PC)
		// SYNC
		// ADDV $auxint, Rout
		ll := mips.ALLV
		sc := mips.ASCV
		if v.Op == ssa.OpMIPS64LoweredAtomicAddconst32 {
			ll = mips.ALL
			sc = mips.ASC
		}
		s.Prog(mips.ASYNC)
		p := s.Prog(ll)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
		p1 := s.Prog(mips.AADDVU)
		p1.From.Type = obj.TYPE_CONST
		p1.From.Offset = v.AuxInt
		p1.Reg = v.Reg0()
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = mips.REGTMP
		p2 := s.Prog(sc)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = mips.REGTMP
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = v.Args[0].Reg()
		p3 := s.Prog(mips.ABEQ)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = mips.REGTMP
		p3.To.Type = obj.TYPE_BRANCH
		p3.To.SetTarget(p)
		s.Prog(mips.ASYNC)
		p4 := s.Prog(mips.AADDVU)
		p4.From.Type = obj.TYPE_CONST
		p4.From.Offset = v.AuxInt
		p4.Reg = v.Reg0()
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = v.Reg0()
	case ssa.OpMIPS64LoweredAtomicAnd32,
		ssa.OpMIPS64LoweredAtomicOr32:
		// SYNC
		// LL	(Rarg0), Rtmp
		// AND/OR	Rarg1, Rtmp
		// SC	Rtmp, (Rarg0)
		// BEQ	Rtmp, -3(PC)
		// SYNC
		s.Prog(mips.ASYNC)

		p := s.Prog(mips.ALL)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = mips.REGTMP

		p1 := s.Prog(v.Op.Asm())
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = v.Args[1].Reg()
		p1.Reg = mips.REGTMP
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = mips.REGTMP

		p2 := s.Prog(mips.ASC)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = mips.REGTMP
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = v.Args[0].Reg()

		p3 := s.Prog(mips.ABEQ)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = mips.REGTMP
		p3.To.Type = obj.TYPE_BRANCH
		p3.To.SetTarget(p)

		s.Prog(mips.ASYNC)

	case ssa.OpMIPS64LoweredAtomicCas32, ssa.OpMIPS64LoweredAtomicCas64:
		// MOVV $0, Rout
		// SYNC
		// LL	(Rarg0), Rtmp
		// BNE	Rtmp, Rarg1, 4(PC)
		// MOVV Rarg2, Rout
		// SC	Rout, (Rarg0)
		// BEQ	Rout, -4(PC)
		// SYNC
		ll := mips.ALLV
		sc := mips.ASCV
		if v.Op == ssa.OpMIPS64LoweredAtomicCas32 {
			ll = mips.ALL
			sc = mips.ASC
		}
		p := s.Prog(mips.AMOVV)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = mips.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
		s.Prog(mips.ASYNC)
		p1 := s.Prog(ll)
		p1.From.Type = obj.TYPE_MEM
		p1.From.Reg = v.Args[0].Reg()
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = mips.REGTMP
		p2 := s.Prog(mips.ABNE)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = v.Args[1].Reg()
		p2.Reg = mips.REGTMP
		p2.To.Type = obj.TYPE_BRANCH
		p3 := s.Prog(mips.AMOVV)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = v.Args[2].Reg()
		p3.To.Type = obj.TYPE_REG
		p3.To.Reg = v.Reg0()
		p4 := s.Prog(sc)
		p4.From.Type = obj.TYPE_REG
		p4.From.Reg = v.Reg0()
		p4.To.Type = obj.TYPE_MEM
		p4.To.Reg = v.Args[0].Reg()
		p5 := s.Prog(mips.ABEQ)
		p5.From.Type = obj.TYPE_REG
		p5.From.Reg = v.Reg0()
		p5.To.Type = obj.TYPE_BRANCH
		p5.To.SetTarget(p1)
		p6 := s.Prog(mips.ASYNC)
		p2.To.SetTarget(p6)
	case ssa.OpMIPS64LoweredNilCheck:
		// Issue a load which will fault if arg is nil.
		p := s.Prog(mips.AMOVB)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = mips.REGTMP
		if logopt.Enabled() {
			logopt.LogOpt(v.Pos, "nilcheck", "genssa", v.Block.Func.Name)
		}
		if base.Debug.Nil != 0 && v.Pos.Line() > 1 { // v.Pos.Line()==1 in generated wrappers
			base.WarnfAt(v.Pos, "generated nil check")
		}
	case ssa.OpMIPS64FPFlagTrue,
		ssa.OpMIPS64FPFlagFalse:
		// MOVV	$0, r
		// BFPF	2(PC)
		// MOVV	$1, r
		branch := mips.ABFPF
		if v.Op == ssa.OpMIPS64FPFlagFalse {
			branch = mips.ABFPT
		}
		p := s.Prog(mips.AMOVV)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = mips.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
		p2 := s.Prog(branch)
		p2.To.Type = obj.TYPE_BRANCH
		p3 := s.Prog(mips.AMOVV)
		p3.From.Type = obj.TYPE_CONST
		p3.From.Offset = 1
		p3.To.Type = obj.TYPE_REG
		p3.To.Reg = v.Reg()
		p4 := s.Prog(obj.ANOP) // not a machine instruction, for branch to land
		p2.To.SetTarget(p4)
	case ssa.OpMIPS64LoweredGetClosurePtr:
		// Closure pointer is R22 (mips.REGCTXT).
		ssagen.CheckLoweredGetClosurePtr(v)
	case ssa.OpMIPS64LoweredGetCallerSP:
		// caller's SP is FixedFrameSize below the address of the first arg
		p := s.Prog(mips.AMOVV)
		p.From.Type = obj.TYPE_ADDR
		p.From.Offset = -base.Ctxt.Arch.FixedFrameSize
		p.From.Name = obj.NAME_PARAM
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPS64LoweredGetCallerPC:
		p := s.Prog(obj.AGETCALLERPC)
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
	ssa.BlockMIPS64EQ:  {mips.ABEQ, mips.ABNE},
	ssa.BlockMIPS64NE:  {mips.ABNE, mips.ABEQ},
	ssa.BlockMIPS64LTZ: {mips.ABLTZ, mips.ABGEZ},
	ssa.BlockMIPS64GEZ: {mips.ABGEZ, mips.ABLTZ},
	ssa.BlockMIPS64LEZ: {mips.ABLEZ, mips.ABGTZ},
	ssa.BlockMIPS64GTZ: {mips.ABGTZ, mips.ABLEZ},
	ssa.BlockMIPS64FPT: {mips.ABFPT, mips.ABFPF},
	ssa.BlockMIPS64FPF: {mips.ABFPF, mips.ABFPT},
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
		// defer returns in R1:
		// 0 if we should continue executing
		// 1 if we should jump to deferreturn call
		p := s.Prog(mips.ABNE)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = mips.REGZERO
		p.Reg = mips.REG_R1
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
	case ssa.BlockMIPS64EQ, ssa.BlockMIPS64NE,
		ssa.BlockMIPS64LTZ, ssa.BlockMIPS64GEZ,
		ssa.BlockMIPS64LEZ, ssa.BlockMIPS64GTZ,
		ssa.BlockMIPS64FPT, ssa.BlockMIPS64FPF:
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
		if !b.Controls[0].Type.IsFlags() {
			p.From.Type = obj.TYPE_REG
			p.From.Reg = b.Controls[0].Reg()
		}
	default:
		b.Fatalf("branch not implemented: %s", b.LongString())
	}
}

"""



```