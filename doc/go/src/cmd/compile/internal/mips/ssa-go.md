Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding & Scope:**

The first step is to recognize the file path: `go/src/cmd/compile/internal/mips/ssa.go`. This immediately tells us we're dealing with the Go compiler's internals, specifically the code generation phase for the MIPS architecture. The `ssa` in the name strongly suggests it deals with Static Single Assignment form, a common intermediate representation in compilers.

**2. High-Level Functionality - Initial Scan:**

Read through the code, identifying the main functions and their purposes. Keywords like `loadByType`, `storeByType`, `ssaGenValue`, and `ssaGenBlock` stand out. The names themselves offer significant clues:

* `loadByType`, `storeByType`: Likely related to generating instructions for loading and storing data of different types.
* `ssaGenValue`:  This looks like the core function for translating SSA values (representing operations) into MIPS assembly instructions.
* `ssaGenBlock`:  This seems to handle the generation of control flow structures (blocks of code) in MIPS assembly.

**3. Deeper Dive into Key Functions:**

Now, examine the logic within each key function:

* **`isFPreg`, `isHILO`:**  Simple helper functions to identify floating-point and special (HI/LO) registers. This indicates architecture-specific handling.
* **`loadByType`, `storeByType`:**  These use `switch` statements based on `t.Size()` (data size) and `t.IsSigned()`. They return MIPS assembly mnemonics (like `AMOVF`, `AMOVW`, `AMOVBU`). This confirms they are about generating type-specific load/store instructions.
* **`ssaGenValue`:** This is the most complex. The large `switch` statement based on `v.Op` (the SSA operation) is crucial. Each case corresponds to a specific SSA operation being translated into MIPS assembly. Notice the use of `s.Prog(asm)` to create assembly instructions, `p.From`, `p.To`, `p.Reg` to set operands, and references to MIPS register constants (like `mips.REGZERO`, `mips.REGTMP`). The handling of `ssa.OpCopy`, `ssa.OpLoadReg`, `ssa.OpStoreReg`, arithmetic operations, constants, memory access, function calls, atomic operations, and nil checks all become apparent. The conditional logic for special registers (HI/LO, FP) suggests constraints in the MIPS architecture.
* **`ssaGenBlock`:** This function deals with control flow. The `switch` on `b.Kind` (block type) shows how different control flow constructs (plain jumps, conditional branches, returns, defer) are translated into MIPS branch instructions. The `blockJump` map is a good clue about how SSA block kinds map to MIPS branch instructions.

**4. Inferring Go Feature Implementations:**

Based on the identified functionalities, start connecting them back to Go features:

* **Type System:** `loadByType` and `storeByType` directly relate to Go's type system and how different types are handled in memory.
* **Basic Operations:** The numerous `ssa.OpMIPS...` cases in `ssaGenValue` covering arithmetic, logical, and comparison operations clearly implement Go's corresponding operators.
* **Constants:** `ssa.OpMIPSMOVWconst`, `ssa.OpMIPSMOVFconst`, `ssa.OpMIPSMOVDconst` show how Go constants are loaded into registers.
* **Memory Access:** `ssa.OpLoadReg`, `ssa.OpStoreReg`, `ssa.OpMIPSMOVWaddr`, and the various `ssa.OpMIPS...load/store` operations demonstrate how Go accesses memory (variables, fields, etc.).
* **Function Calls:** `ssa.OpMIPSCALLstatic`, `ssa.OpMIPSCALLclosure`, `ssa.OpMIPSCALLinter`, and `ssa.OpMIPSCALLtail` obviously handle different kinds of function calls in Go.
* **Defer:** The `ssa.BlockDefer` case in `ssaGenBlock` explicitly deals with the `defer` keyword.
* **Panic/Recover (Implicit):** The `ssa.OpMIPSLoweredPanicBounds...` and `ssa.OpMIPSLoweredPanicExtend...` suggest the implementation of runtime panic handling for array bounds and slice extensions.
* **Atomic Operations:** The `ssa.OpMIPSLoweredAtomic...` operations clearly implement Go's `sync/atomic` package.
* **Nil Checks:** `ssa.OpMIPSLoweredNilCheck` directly implements Go's automatic nil pointer checks.
* **Closures:**  `ssa.OpMIPSLoweredGetClosurePtr` relates to how closures capture variables.
* **Goroutines/Stack Management (Implicit):** `ssa.OpMIPSLoweredGetCallerSP` and `ssa.OpMIPSLoweredGetCallerPC` are related to stack management and obtaining information about the call stack, which is fundamental for goroutines.

**5. Code Examples and Assumptions:**

Once the features are identified, construct simple Go code examples that would likely trigger the code paths observed in the `ssa.go` file. This involves thinking about what kinds of Go code would lead to specific SSA operations.

* For loading/storing, declare variables of different types.
* For arithmetic, perform basic arithmetic operations.
* For function calls, call regular functions, closures, and methods.
* For `defer`, use the `defer` keyword.
* For atomic operations, use functions from the `sync/atomic` package.
* For nil checks, dereference a potentially nil pointer.

**6. Command-Line Arguments (Compiler Flags):**

Consider if any parts of the code suggest compiler flags. The `base.Debug.Nil != 0` in `ssa.OpMIPSLoweredNilCheck` is a direct indication of a debug flag (`-N` or similar in the Go compiler).

**7. Common Mistakes:**

Think about potential pitfalls related to the MIPS architecture, particularly based on the code's handling of special registers and the need for temporary registers in certain moves. This leads to identifying the constraint of direct moves between HI/LO and FP registers.

**8. Review and Refine:**

Finally, review the entire analysis for clarity, accuracy, and completeness. Ensure that the explanations are well-structured and easy to understand. Double-check the code examples and the reasoning behind them.

This systematic approach, starting with a high-level overview and gradually drilling down into details, combined with knowledge of compiler concepts and the Go language, allows for a comprehensive understanding of the provided code snippet.
这段代码是 Go 编译器中针对 MIPS 架构生成 SSA（Static Single Assignment）中间表示代码的一部分。它负责将 Go 语言的各种操作和控制流结构转换为 MIPS 汇编指令。

以下是其主要功能列表：

1. **判断寄存器类型:**
   - `isFPreg(r int16) bool`: 判断给定的寄存器 `r` 是否为浮点寄存器。
   - `isHILO(r int16) bool`: 判断给定的寄存器 `r` 是否为 HI 或 LO 特殊寄存器 (用于乘法和除法结果)。

2. **根据类型选择加载/存储指令:**
   - `loadByType(t *types.Type, r int16) obj.As`:  根据 Go 语言类型 `t` 和目标寄存器 `r` (用于判断是否为浮点寄存器) 返回合适的 MIPS 加载指令 (例如 `AMOVW`, `AMOVF`, `AMOVD`, `AMOVB`, `AMOVBU`, `AMOVH`, `AMOVHU`)。
   - `storeByType(t *types.Type, r int16) obj.As`: 根据 Go 语言类型 `t` 和源寄存器 `r` (用于判断是否为浮点寄存器) 返回合适的 MIPS 存储指令 (例如 `AMOVW`, `AMOVF`, `AMOVD`, `AMOVB`, `AMOVH`)。

3. **生成 SSA Value 的汇编代码 (`ssaGenValue`):**
   - 这是核心函数，根据 SSA `Value` 的操作类型 (`v.Op`) 生成相应的 MIPS 汇编指令。
   - 它处理各种 Go 语言的底层操作，例如：
     - **数据移动:** `OpCopy`, `OpMIPSMOVWreg`, `OpLoadReg`, `OpStoreReg`, `OpMIPSMOVWconst`, `OpMIPSMOVFconst`, `OpMIPSMOVDconst`, `OpMIPSMOVWaddr` 等。
     - **算术运算:** `OpMIPSADD`, `OpMIPSSUB`, `OpMIPSMUL`, `OpMIPSDIV`, `OpMIPSADDconst`, `OpMIPSSUBconst` 等。
     - **位运算:** `OpMIPSAND`, `OpMIPSOR`, `OpMIPSXOR`, `OpMIPSNOR`, `OpMIPSSLL`, `OpMIPSSRL`, `OpMIPSSRA`, `OpMIPSANDconst` 等。
     - **浮点运算:** `OpMIPSADDF`, `OpMIPSADDD`, `OpMIPSSUBF`, `OpMIPSSUBD`, `OpMIPSMULF`, `OpMIPSMULD`, `OpMIPSDIVF`, `OpMIPSDIVD`, `OpMIPSNEGF`, `OpMIPSNEGD` 等。
     - **比较运算:** `OpMIPSSGT`, `OpMIPSSGTU`, `OpMIPSSGTzero`, `OpMIPSSGTUzero`, `OpMIPSCMPEQF`, `OpMIPSCMPEQD`, `OpMIPSCMPGEF` 等。
     - **条件移动:** `OpMIPSCMOVZ`, `OpMIPSCMOVZzero`.
     - **内存加载和存储:** `OpMIPSMOVBload`, `OpMIPSMOVBUload`, `OpMIPSMOVHload`, `OpMIPSMOVHUload`, `OpMIPSMOVWload`, `OpMIPSMOVFload`, `OpMIPSMOVDload`, `OpMIPSMOVBstore`, `OpMIPSMOVHstore`, `OpMIPSMOVWstore` 等。
     - **类型转换:** `OpMIPSMOVWF`, `OpMIPSMOVWD`, `OpMIPSTRUNCFW`, `OpMIPSTRUNCDW`, `OpMIPSMOVFD`, `OpMIPSMOVDF`.
     - **函数调用:** `OpMIPSCALLstatic`, `OpMIPSCALLclosure`, `OpMIPSCALLinter`, `OpMIPSCALLtail`.
     - **内置函数和运行时支持:** `OpMIPSLoweredZero` (清零内存), `OpMIPSLoweredMove` (内存拷贝), `OpMIPSLoweredWB` (写屏障), `OpMIPSLoweredPanicBoundsA/B/C` (数组越界 panic), `OpMIPSLoweredAtomicLoad8/32`, `OpMIPSLoweredAtomicStore8/32/zero`, `OpMIPSLoweredAtomicExchange`, `OpMIPSLoweredAtomicAdd/const`, `OpMIPSLoweredAtomicAnd/Or`, `OpMIPSLoweredAtomicCas` (原子操作)。
     - **Nil 检查:** `OpMIPSLoweredNilCheck`.
     - **获取闭包指针和调用者信息:** `OpMIPSLoweredGetClosurePtr`, `OpMIPSLoweredGetCallerSP`, `OpMIPSLoweredGetCallerPC`.
     - **条件标志:** `OpMIPSFPFlagTrue`, `OpMIPSFPFlagFalse`.
     - **No-op:** `OpMIPSMOVWnop`.

4. **生成 SSA Block 的汇编代码 (`ssaGenBlock`):**
   - 负责根据 SSA `Block` 的类型 (`b.Kind`) 生成相应的控制流 MIPS 汇编指令。
   - 处理各种控制流结构，例如：
     - **顺序执行:** `ssa.BlockPlain`.
     - **延迟调用:** `ssa.BlockDefer`.
     - **退出和返回:** `ssa.BlockExit`, `ssa.BlockRet`, `ssa.BlockRetJmp`.
     - **条件跳转:** `ssa.BlockMIPSEQ`, `ssa.BlockMIPSNE`, `ssa.BlockMIPSLTZ`, `ssa.BlockMIPSGEZ`, `ssa.BlockMIPSLEZ`, `ssa.BlockMIPSGTZ`, `ssa.BlockMIPSFPT`, `ssa.BlockMIPSFPF`.
   - 使用 `blockJump` map 将 SSA 的 Block 类型映射到 MIPS 的条件跳转指令及其反向指令。

**推断的 Go 语言功能实现和代码示例:**

基于代码内容，可以推断出它实现了 Go 语言的以下功能：

1. **基本数据类型的操作:**  整数、浮点数的算术、位运算、比较等。
2. **类型转换:**  不同数值类型之间的转换。
3. **内存操作:**  变量的加载和存储。
4. **函数调用:**  包括普通函数、闭包和接口方法的调用。
5. **`defer` 语句:**  实现 `defer` 关键字的功能。
6. **`panic` 和 `recover`:**  通过 `OpMIPSLoweredPanicBounds...` 等操作实现 `panic` 的触发。 `recover` 的实现可能在其他相关文件中。
7. **原子操作:**  通过 `sync/atomic` 包提供的原子操作，例如 `atomic.LoadInt32`, `atomic.StoreInt32`, `atomic.AddInt32`, `atomic.CompareAndSwapInt32` 等。
8. **切片和数组:**  通过边界检查 (`OpMIPSLoweredPanicBounds...`) 实现对切片和数组的安全访问。
9. **Nil 指针检查:**  自动插入 nil 指针检查 (`OpMIPSLoweredNilCheck`)，当访问 nil 指针时会触发 panic。
10. **闭包:**  通过 `OpMIPSLoweredGetClosurePtr` 获取闭包所需的上下文信息。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"sync/atomic"
)

func main() {
	// 基本数据类型操作
	a := 10
	b := 5
	sum := a + b
	fmt.Println("Sum:", sum)

	// 类型转换
	f := float32(a)
	fmt.Println("Float:", f)

	// 内存操作
	var x int
	y := &x
	*y = 20
	fmt.Println("Value at y:", *y)

	// 函数调用
	greet("Go")

	// defer 语句
	defer fmt.Println("Deferred message")

	// 原子操作
	var count int32
	atomic.AddInt32(&count, 1)
	fmt.Println("Atomic count:", atomic.LoadInt32(&count))

	// 切片
	s := []int{1, 2, 3}
	// 触发边界检查 (如果编译器没有优化掉)
	// _ = s[3]

	// Nil 指针检查
	var ptr *int
	// 下面的代码会导致 panic
	// if ptr != nil {
	// 	_ = *ptr
	// }
}

func greet(name string) {
	fmt.Println("Hello,", name)
}
```

**假设的输入与输出 (针对 `ssaGenValue` 中的 `ssa.OpMIPSADD`):**

假设有一个 SSA `Value` `v` 代表整数加法 `a + b`，其中：

- `v.Op` 为 `ssa.OpMIPSADD`
- `v.Args[0]` 代表 `a`，已分配到 MIPS 寄存器 `R3`
- `v.Args[1]` 代表 `b`，已分配到 MIPS 寄存器 `R4`
- `v.Reg()` (加法结果的目标寄存器) 为 `R5`

**生成的 MIPS 汇编代码:**

```assembly
  ADD R4, R3, R5
```

**解释:**

- `ADD` 是 MIPS 的加法指令。
- `R4` 是源寄存器。
- `R3` 是另一个源寄存器。
- `R5` 是目标寄存器，存储加法的结果。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的前端和主流程中。但是，这段代码中的一些行为可能受到编译选项的影响，例如：

- **优化级别:** 不同的优化级别可能导致生成的 SSA 中操作的组合和形式有所不同，从而影响 `ssaGenValue` 生成的汇编代码。
- **调试信息:** 调试相关的编译选项可能会影响 nil 检查的插入 (`base.Debug.Nil != 0`)。

**使用者易犯错的点 (针对 Go 语言开发者):**

这段代码是编译器内部实现，Go 语言开发者通常不会直接与之交互。但是，了解其背后的原理可以帮助开发者避免一些性能陷阱或理解某些行为：

- **不必要的类型转换:**  过多的类型转换可能会导致编译器生成额外的指令。
- **频繁的小对象分配:**  可能导致更频繁的写屏障操作 (`OpMIPSLoweredWB`)。
- **过度使用原子操作:**  虽然原子操作保证了并发安全，但它们的性能开销通常比非原子操作大，需要谨慎使用。
- **在循环中进行可能导致边界检查的操作:**  编译器有时无法完全消除循环内的边界检查，这可能会影响性能。

总而言之，`go/src/cmd/compile/internal/mips/ssa.go` 是 Go 编译器中至关重要的组成部分，它负责将高级的 Go 语言结构翻译成底层的 MIPS 汇编指令，使得程序能够在 MIPS 架构的处理器上运行。理解这段代码的功能有助于深入了解 Go 语言的编译过程和底层实现。

### 提示词
```
这是路径为go/src/cmd/compile/internal/mips/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package mips

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
			return mips.AMOVW
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
		}
	}
	panic("bad store type")
}

func ssaGenValue(s *ssagen.State, v *ssa.Value) {
	switch v.Op {
	case ssa.OpCopy, ssa.OpMIPSMOVWreg:
		t := v.Type
		if t.IsMemory() {
			return
		}
		x := v.Args[0].Reg()
		y := v.Reg()
		if x == y {
			return
		}
		as := mips.AMOVW
		if isFPreg(x) && isFPreg(y) {
			as = mips.AMOVF
			if t.Size() == 8 {
				as = mips.AMOVD
			}
		}

		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = x
		p.To.Type = obj.TYPE_REG
		p.To.Reg = y
		if isHILO(x) && isHILO(y) || isHILO(x) && isFPreg(y) || isFPreg(x) && isHILO(y) {
			// cannot move between special registers, use TMP as intermediate
			p.To.Reg = mips.REGTMP
			p = s.Prog(mips.AMOVW)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = mips.REGTMP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = y
		}
	case ssa.OpMIPSMOVWnop:
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
			p = s.Prog(mips.AMOVW)
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
			p := s.Prog(mips.AMOVW)
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
	case ssa.OpMIPSADD,
		ssa.OpMIPSSUB,
		ssa.OpMIPSAND,
		ssa.OpMIPSOR,
		ssa.OpMIPSXOR,
		ssa.OpMIPSNOR,
		ssa.OpMIPSSLL,
		ssa.OpMIPSSRL,
		ssa.OpMIPSSRA,
		ssa.OpMIPSADDF,
		ssa.OpMIPSADDD,
		ssa.OpMIPSSUBF,
		ssa.OpMIPSSUBD,
		ssa.OpMIPSMULF,
		ssa.OpMIPSMULD,
		ssa.OpMIPSDIVF,
		ssa.OpMIPSDIVD,
		ssa.OpMIPSMUL:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSSGT,
		ssa.OpMIPSSGTU:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSSGTzero,
		ssa.OpMIPSSGTUzero:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = mips.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSADDconst,
		ssa.OpMIPSSUBconst,
		ssa.OpMIPSANDconst,
		ssa.OpMIPSORconst,
		ssa.OpMIPSXORconst,
		ssa.OpMIPSNORconst,
		ssa.OpMIPSSLLconst,
		ssa.OpMIPSSRLconst,
		ssa.OpMIPSSRAconst,
		ssa.OpMIPSSGTconst,
		ssa.OpMIPSSGTUconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSMULT,
		ssa.OpMIPSMULTU,
		ssa.OpMIPSDIV,
		ssa.OpMIPSDIVU:
		// result in hi,lo
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.Reg = v.Args[0].Reg()
	case ssa.OpMIPSMOVWconst:
		r := v.Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
		if isFPreg(r) || isHILO(r) {
			// cannot move into FP or special registers, use TMP as intermediate
			p.To.Reg = mips.REGTMP
			p = s.Prog(mips.AMOVW)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = mips.REGTMP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = r
		}
	case ssa.OpMIPSMOVFconst,
		ssa.OpMIPSMOVDconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_FCONST
		p.From.Val = math.Float64frombits(uint64(v.AuxInt))
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSCMOVZ:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[2].Reg()
		p.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSCMOVZzero:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.Reg = mips.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSCMPEQF,
		ssa.OpMIPSCMPEQD,
		ssa.OpMIPSCMPGEF,
		ssa.OpMIPSCMPGED,
		ssa.OpMIPSCMPGTF,
		ssa.OpMIPSCMPGTD:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = v.Args[1].Reg()
	case ssa.OpMIPSMOVWaddr:
		p := s.Prog(mips.AMOVW)
		p.From.Type = obj.TYPE_ADDR
		p.From.Reg = v.Args[0].Reg()
		var wantreg string
		// MOVW $sym+off(base), R
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
			// No sym, just MOVW $off(SP), R
			wantreg = "SP"
			p.From.Offset = v.AuxInt
		}
		if reg := v.Args[0].RegName(); reg != wantreg {
			v.Fatalf("bad reg %s for symbol type %T, want %s", reg, v.Aux, wantreg)
		}
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSMOVBload,
		ssa.OpMIPSMOVBUload,
		ssa.OpMIPSMOVHload,
		ssa.OpMIPSMOVHUload,
		ssa.OpMIPSMOVWload,
		ssa.OpMIPSMOVFload,
		ssa.OpMIPSMOVDload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSMOVBstore,
		ssa.OpMIPSMOVHstore,
		ssa.OpMIPSMOVWstore,
		ssa.OpMIPSMOVFstore,
		ssa.OpMIPSMOVDstore:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpMIPSMOVBstorezero,
		ssa.OpMIPSMOVHstorezero,
		ssa.OpMIPSMOVWstorezero:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = mips.REGZERO
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpMIPSMOVBreg,
		ssa.OpMIPSMOVBUreg,
		ssa.OpMIPSMOVHreg,
		ssa.OpMIPSMOVHUreg:
		a := v.Args[0]
		for a.Op == ssa.OpCopy || a.Op == ssa.OpMIPSMOVWreg || a.Op == ssa.OpMIPSMOVWnop {
			a = a.Args[0]
		}
		if a.Op == ssa.OpLoadReg {
			t := a.Type
			switch {
			case v.Op == ssa.OpMIPSMOVBreg && t.Size() == 1 && t.IsSigned(),
				v.Op == ssa.OpMIPSMOVBUreg && t.Size() == 1 && !t.IsSigned(),
				v.Op == ssa.OpMIPSMOVHreg && t.Size() == 2 && t.IsSigned(),
				v.Op == ssa.OpMIPSMOVHUreg && t.Size() == 2 && !t.IsSigned():
				// arg is a proper-typed load, already zero/sign-extended, don't extend again
				if v.Reg() == v.Args[0].Reg() {
					return
				}
				p := s.Prog(mips.AMOVW)
				p.From.Type = obj.TYPE_REG
				p.From.Reg = v.Args[0].Reg()
				p.To.Type = obj.TYPE_REG
				p.To.Reg = v.Reg()
				return
			default:
			}
		}
		fallthrough
	case ssa.OpMIPSMOVWF,
		ssa.OpMIPSMOVWD,
		ssa.OpMIPSTRUNCFW,
		ssa.OpMIPSTRUNCDW,
		ssa.OpMIPSMOVFD,
		ssa.OpMIPSMOVDF,
		ssa.OpMIPSMOVWfpgp,
		ssa.OpMIPSMOVWgpfp,
		ssa.OpMIPSNEGF,
		ssa.OpMIPSNEGD,
		ssa.OpMIPSABSD,
		ssa.OpMIPSSQRTF,
		ssa.OpMIPSSQRTD,
		ssa.OpMIPSCLZ:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSNEG:
		// SUB from REGZERO
		p := s.Prog(mips.ASUBU)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.Reg = mips.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSLoweredZero:
		// SUBU	$4, R1
		// MOVW	R0, 4(R1)
		// ADDU	$4, R1
		// BNE	Rarg1, R1, -2(PC)
		// arg1 is the address of the last element to zero
		var sz int64
		var mov obj.As
		switch {
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
		p := s.Prog(mips.ASUBU)
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
		p3 := s.Prog(mips.AADDU)
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
	case ssa.OpMIPSLoweredMove:
		// SUBU	$4, R1
		// MOVW	4(R1), Rtmp
		// MOVW	Rtmp, (R2)
		// ADDU	$4, R1
		// ADDU	$4, R2
		// BNE	Rarg2, R1, -4(PC)
		// arg2 is the address of the last element of src
		var sz int64
		var mov obj.As
		switch {
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
		p := s.Prog(mips.ASUBU)
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
		p4 := s.Prog(mips.AADDU)
		p4.From.Type = obj.TYPE_CONST
		p4.From.Offset = sz
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = mips.REG_R1
		p5 := s.Prog(mips.AADDU)
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
	case ssa.OpMIPSCALLstatic, ssa.OpMIPSCALLclosure, ssa.OpMIPSCALLinter:
		s.Call(v)
	case ssa.OpMIPSCALLtail:
		s.TailCall(v)
	case ssa.OpMIPSLoweredWB:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		// AuxInt encodes how many buffer entries we need.
		p.To.Sym = ir.Syms.GCWriteBarrier[v.AuxInt-1]
	case ssa.OpMIPSLoweredPanicBoundsA, ssa.OpMIPSLoweredPanicBoundsB, ssa.OpMIPSLoweredPanicBoundsC:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ssagen.BoundsCheckFunc[v.AuxInt]
		s.UseArgs(8) // space used in callee args area by assembly stubs
	case ssa.OpMIPSLoweredPanicExtendA, ssa.OpMIPSLoweredPanicExtendB, ssa.OpMIPSLoweredPanicExtendC:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ssagen.ExtendCheckFunc[v.AuxInt]
		s.UseArgs(12) // space used in callee args area by assembly stubs
	case ssa.OpMIPSLoweredAtomicLoad8,
		ssa.OpMIPSLoweredAtomicLoad32:
		s.Prog(mips.ASYNC)

		var op obj.As
		switch v.Op {
		case ssa.OpMIPSLoweredAtomicLoad8:
			op = mips.AMOVB
		case ssa.OpMIPSLoweredAtomicLoad32:
			op = mips.AMOVW
		}
		p := s.Prog(op)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

		s.Prog(mips.ASYNC)
	case ssa.OpMIPSLoweredAtomicStore8,
		ssa.OpMIPSLoweredAtomicStore32:
		s.Prog(mips.ASYNC)

		var op obj.As
		switch v.Op {
		case ssa.OpMIPSLoweredAtomicStore8:
			op = mips.AMOVB
		case ssa.OpMIPSLoweredAtomicStore32:
			op = mips.AMOVW
		}
		p := s.Prog(op)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()

		s.Prog(mips.ASYNC)
	case ssa.OpMIPSLoweredAtomicStorezero:
		s.Prog(mips.ASYNC)

		p := s.Prog(mips.AMOVW)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = mips.REGZERO
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()

		s.Prog(mips.ASYNC)
	case ssa.OpMIPSLoweredAtomicExchange:
		// SYNC
		// MOVW Rarg1, Rtmp
		// LL	(Rarg0), Rout
		// SC	Rtmp, (Rarg0)
		// BEQ	Rtmp, -3(PC)
		// SYNC
		s.Prog(mips.ASYNC)

		p := s.Prog(mips.AMOVW)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = mips.REGTMP

		p1 := s.Prog(mips.ALL)
		p1.From.Type = obj.TYPE_MEM
		p1.From.Reg = v.Args[0].Reg()
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = v.Reg0()

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
	case ssa.OpMIPSLoweredAtomicAdd:
		// SYNC
		// LL	(Rarg0), Rout
		// ADDU Rarg1, Rout, Rtmp
		// SC	Rtmp, (Rarg0)
		// BEQ	Rtmp, -3(PC)
		// SYNC
		// ADDU Rarg1, Rout
		s.Prog(mips.ASYNC)

		p := s.Prog(mips.ALL)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

		p1 := s.Prog(mips.AADDU)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = v.Args[1].Reg()
		p1.Reg = v.Reg0()
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

		p4 := s.Prog(mips.AADDU)
		p4.From.Type = obj.TYPE_REG
		p4.From.Reg = v.Args[1].Reg()
		p4.Reg = v.Reg0()
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = v.Reg0()

	case ssa.OpMIPSLoweredAtomicAddconst:
		// SYNC
		// LL	(Rarg0), Rout
		// ADDU $auxInt, Rout, Rtmp
		// SC	Rtmp, (Rarg0)
		// BEQ	Rtmp, -3(PC)
		// SYNC
		// ADDU $auxInt, Rout
		s.Prog(mips.ASYNC)

		p := s.Prog(mips.ALL)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

		p1 := s.Prog(mips.AADDU)
		p1.From.Type = obj.TYPE_CONST
		p1.From.Offset = v.AuxInt
		p1.Reg = v.Reg0()
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

		p4 := s.Prog(mips.AADDU)
		p4.From.Type = obj.TYPE_CONST
		p4.From.Offset = v.AuxInt
		p4.Reg = v.Reg0()
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = v.Reg0()

	case ssa.OpMIPSLoweredAtomicAnd,
		ssa.OpMIPSLoweredAtomicOr:
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

	case ssa.OpMIPSLoweredAtomicCas:
		// MOVW $0, Rout
		// SYNC
		// LL	(Rarg0), Rtmp
		// BNE	Rtmp, Rarg1, 4(PC)
		// MOVW Rarg2, Rout
		// SC	Rout, (Rarg0)
		// BEQ	Rout, -4(PC)
		// SYNC
		p := s.Prog(mips.AMOVW)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = mips.REGZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

		s.Prog(mips.ASYNC)

		p1 := s.Prog(mips.ALL)
		p1.From.Type = obj.TYPE_MEM
		p1.From.Reg = v.Args[0].Reg()
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = mips.REGTMP

		p2 := s.Prog(mips.ABNE)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = v.Args[1].Reg()
		p2.Reg = mips.REGTMP
		p2.To.Type = obj.TYPE_BRANCH

		p3 := s.Prog(mips.AMOVW)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = v.Args[2].Reg()
		p3.To.Type = obj.TYPE_REG
		p3.To.Reg = v.Reg0()

		p4 := s.Prog(mips.ASC)
		p4.From.Type = obj.TYPE_REG
		p4.From.Reg = v.Reg0()
		p4.To.Type = obj.TYPE_MEM
		p4.To.Reg = v.Args[0].Reg()

		p5 := s.Prog(mips.ABEQ)
		p5.From.Type = obj.TYPE_REG
		p5.From.Reg = v.Reg0()
		p5.To.Type = obj.TYPE_BRANCH
		p5.To.SetTarget(p1)

		s.Prog(mips.ASYNC)

		p6 := s.Prog(obj.ANOP)
		p2.To.SetTarget(p6)

	case ssa.OpMIPSLoweredNilCheck:
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
	case ssa.OpMIPSFPFlagTrue,
		ssa.OpMIPSFPFlagFalse:
		// MOVW		$1, r
		// CMOVF	R0, r

		cmov := mips.ACMOVF
		if v.Op == ssa.OpMIPSFPFlagFalse {
			cmov = mips.ACMOVT
		}
		p := s.Prog(mips.AMOVW)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
		p1 := s.Prog(cmov)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = mips.REGZERO
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = v.Reg()

	case ssa.OpMIPSLoweredGetClosurePtr:
		// Closure pointer is R22 (mips.REGCTXT).
		ssagen.CheckLoweredGetClosurePtr(v)
	case ssa.OpMIPSLoweredGetCallerSP:
		// caller's SP is FixedFrameSize below the address of the first arg
		p := s.Prog(mips.AMOVW)
		p.From.Type = obj.TYPE_ADDR
		p.From.Offset = -base.Ctxt.Arch.FixedFrameSize
		p.From.Name = obj.NAME_PARAM
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpMIPSLoweredGetCallerPC:
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
	ssa.BlockMIPSEQ:  {mips.ABEQ, mips.ABNE},
	ssa.BlockMIPSNE:  {mips.ABNE, mips.ABEQ},
	ssa.BlockMIPSLTZ: {mips.ABLTZ, mips.ABGEZ},
	ssa.BlockMIPSGEZ: {mips.ABGEZ, mips.ABLTZ},
	ssa.BlockMIPSLEZ: {mips.ABLEZ, mips.ABGTZ},
	ssa.BlockMIPSGTZ: {mips.ABGTZ, mips.ABLEZ},
	ssa.BlockMIPSFPT: {mips.ABFPT, mips.ABFPF},
	ssa.BlockMIPSFPF: {mips.ABFPF, mips.ABFPT},
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
	case ssa.BlockMIPSEQ, ssa.BlockMIPSNE,
		ssa.BlockMIPSLTZ, ssa.BlockMIPSGEZ,
		ssa.BlockMIPSLEZ, ssa.BlockMIPSGTZ,
		ssa.BlockMIPSFPT, ssa.BlockMIPSFPF:
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
```