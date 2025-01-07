Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding & Purpose:**

The first step is to recognize the file path: `go/src/cmd/compile/internal/riscv64/ssa.go`. This immediately tells us this code is part of the Go compiler, specifically for the RISC-V 64-bit architecture, and it's dealing with Static Single Assignment (SSA) form. SSA is an intermediate representation used by compilers to perform optimizations. The `ssa.go` suffix strongly suggests this file is responsible for translating Go's SSA representation into RISC-V 64 assembly instructions.

**2. High-Level Functionality Identification:**

A quick scan reveals key functions and data structures:

* `ssaRegToReg`:  A map from SSA register numbers to actual RISC-V register numbers. This is crucial for the translation process.
* `loadByType` and `storeByType`: Functions that determine the correct RISC-V load and store instructions based on the Go type's size and signedness.
* `largestMove`:  A function to find the largest possible move instruction based on memory alignment. This hints at optimization efforts to use efficient move instructions.
* `ssaMarkMoves`:  A no-op for RISC-V, indicating a specific optimization not needed for this architecture.
* `ssaGenValue`: The core function. The `switch` statement on `v.Op` (SSA operation) suggests this function generates assembly code for each SSA operation.
* `ssaGenBlock`: Handles the generation of assembly for different types of control flow blocks (like conditional branches, jumps, returns).
* `loadRegResult` and `spillArgReg`:  Helper functions related to loading and storing register values, possibly for function calls or argument passing.

**3. Deeper Dive into Key Functions:**

* **`ssaRegToReg`:**  Examine the mapping. Notice the skip for `riscv.REG_X1` (LR). This likely means the link register is handled specially. The presence of both integer registers (X0-X31) and floating-point registers (F0-F31) confirms it's dealing with a complete register set.

* **`loadByType` and `storeByType`:**  Analyze the `switch` statements based on `t.Size()` and `t.IsFloat()`/`t.IsSigned()`. This reveals how different Go data types (integers of various sizes, floats) are loaded and stored using the appropriate RISC-V instructions (e.g., `AMOVB`, `AMOVBU`, `AMOVW`, `AMOVD`, `AMOVF`).

* **`largestMove`:** Understand the logic. It prioritizes larger moves for efficiency, respecting alignment constraints.

* **`ssaGenValue`:** This is the most complex part. Go through the `switch` cases. For each case:
    * **Identify the SSA Operation:**  Understand what the Go operation represents (e.g., `ssa.OpCopy`, `ssa.OpAdd`, `ssa.OpLoadReg`, `ssa.OpStoreReg`, `ssa.OpCallStatic`).
    * **Trace the Assembly Generation:** See how the SSA operation is translated into RISC-V assembly instructions using `s.Prog()`. Pay attention to how operands are accessed (`v.Args[0].Reg()`, `v.Reg()`, `v.AuxInt`, `v.Aux`).
    * **Look for Specific Patterns:**  Notice patterns like loading/storing with offsets using `ssagen.AddrAuto()`, handling function calls with `s.Call()` and `s.TailCall()`, and special handling for atomic operations and memory barriers.
    * **Focus on Notable Cases:** Spend more time on complex operations like `ssa.OpRISCV64LoweredFMAXD/S` and `ssa.OpRISCV64LoweredMuluhilo`, where multiple assembly instructions are generated to achieve the desired functionality. The NaN handling in the floating-point max/min is a key detail.

* **`ssaGenBlock`:** Analyze how different control flow block kinds are translated into RISC-V branch instructions. Note how the `next` block is used to optimize away unnecessary jumps.

**4. Inferring Go Feature Implementation:**

Based on the `ssaGenValue` cases, start connecting the generated assembly to higher-level Go features:

* **Basic Arithmetic:** `ssa.OpRISCV64ADD`, `ssa.OpRISCV64SUB`, `ssa.OpRISCV64MUL`, etc., directly correspond to Go's arithmetic operators.
* **Memory Access:** `ssa.OpLoadReg`, `ssa.OpStoreReg`, `ssa.OpRISCV64MOVBload`, `ssa.OpRISCV64MOVBstore` are used for accessing memory, representing Go's variable access, field access in structs, and array element access.
* **Function Calls:** `ssa.OpRISCV64CALLstatic`, `ssa.OpRISCV64CALLclosure`, `ssa.OpRISCV64CALLinter` handle different types of function calls in Go.
* **Control Flow:** `ssaGenBlock` shows how `if` statements, `for` loops, and `switch` statements are implemented using conditional and unconditional jumps.
* **Concurrency:**  The presence of atomic operations (`ssa.OpRISCV64LoweredAtomicLoad...`, `ssa.OpRISCV64LoweredAtomicStore...`, `ssa.OpRISCV64LoweredAtomicCas...`) points to the implementation of Go's synchronization primitives.
* **Defer:** `ssa.BlockDefer` indicates the implementation of Go's `defer` statement.
* **Panic/Recover:** `ssa.OpRISCV64LoweredPanicBounds...` suggests the handling of out-of-bounds access, leading to panics.
* **Nil Checks:** `ssa.OpRISCV64LoweredNilCheck` shows how the compiler inserts checks for nil pointers.
* **String/Slice Operations:**  `ssa.OpRISCV64LoweredMove` and `ssa.OpRISCV64LoweredZero` are used for moving and zeroing out blocks of memory, which is crucial for string and slice manipulation.

**5. Code Examples and Assumptions:**

Once you've identified the functionalities, create simple Go code examples that would likely trigger the generation of the assembly code you've seen. For example, a simple addition would use `ssa.OpRISCV64ADD`, a memory load would use `ssa.OpRISCV64MOVWload`, and a function call would use one of the `ssa.OpRISCV64CALL...` operations. Make reasonable assumptions about register allocation based on common compiler practices.

**6. Command-Line Arguments and Error-Prone Areas:**

While the code itself doesn't directly parse command-line arguments, remember its context within the Go compiler. Think about compiler flags that might influence the code generation process (e.g., optimization levels, debugging flags).

For error-prone areas, consider:

* **Incorrect Type Handling:**  Mistakes in `loadByType` or `storeByType` could lead to incorrect memory access sizes or signedness.
* **Register Allocation Issues:** While this code doesn't do register allocation, understanding how registers are used is crucial. Incorrect assumptions could lead to issues when the code interacts with the register allocator.
* **Branching Logic:** Errors in `ssaGenBlock` could lead to incorrect control flow.

**7. Refinement and Organization:**

Finally, organize your findings into a clear and structured answer, addressing each part of the prompt. Use clear headings and bullet points. Provide specific code examples and explain the corresponding assembly instructions.

By following this structured approach, you can effectively analyze and understand even complex compiler code like the provided snippet. The key is to start with the big picture and gradually drill down into the details, making connections between the assembly code and the higher-level language features.
好的，让我们来分析一下 `go/src/cmd/compile/internal/riscv64/ssa.go` 这个 Go 语言编译器的部分代码。

**功能列举:**

这个文件主要负责将 Go 语言的中间表示形式（SSA，Static Single Assignment）转换为 RISC-V 64 位架构的机器码指令。具体功能包括：

1. **SSA 寄存器到 RISC-V 寄存器的映射:** `ssaRegToReg` 变量定义了 SSA 逻辑寄存器编号到 RISC-V 物理寄存器编号的映射关系。这使得编译器可以将 SSA 操作中的抽象寄存器对应到实际的硬件寄存器。

2. **根据类型选择加载和存储指令:** `loadByType` 和 `storeByType` 函数根据 Go 语言变量的类型（大小、是否为浮点数、是否有符号）选择合适的 RISC-V 加载（`AMOVB`, `AMOVBU`, `AMOVH`, `AMOVHU`, `AMOVW`, `AMOVWU`, `AMOV`, `AMOVF`, `AMOVD`）和存储指令。

3. **确定最大移动指令:** `largestMove` 函数根据内存对齐方式，选择能够使用的最大字节数的移动指令 (`AMOV`, `AMOVW`, `AMOVH`, `AMOVB`)，用于优化内存拷贝操作。

4. **生成 SSA 值的代码:** `ssaGenValue` 函数是核心，它根据不同的 SSA 操作码 (`v.Op`)，生成对应的 RISC-V 汇编指令。涵盖了算术运算、逻辑运算、内存加载/存储、常量加载、函数调用、原子操作、内存拷贝和清零等多种操作。

5. **生成 SSA 代码块的代码:** `ssaGenBlock` 函数负责根据 SSA 代码块的类型 (`b.Kind`) 生成相应的控制流指令，如跳转 (`AJMP`)、条件分支 (`ABEQ`, `ABNE`, `ABLT` 等) 和返回 (`ARET`)。

6. **辅助函数:**  `loadRegResult` 和 `spillArgReg` 是辅助函数，用于处理函数返回值加载和函数参数溢出到栈的操作。

**Go 语言功能实现推理与代码示例:**

基于代码内容，可以推断出 `ssa.go` 实现了 Go 语言的以下功能：

* **基本数据类型的操作:**  `ssaGenValue` 中大量的 `ssa.OpRISCV64...` 开头的操作码，如 `ADD`, `SUB`, `MUL`, `AND`, `OR` 等，对应了 Go 语言的基本算术和逻辑运算。

  ```go
  package main

  func add(a, b int) int {
      return a + b
  }

  func main() {
      result := add(5, 3)
      println(result)
  }
  ```

  **假设输入:**  编译器编译上述 `add` 函数。

  **可能的输出 (对应 `ssa.OpRISCV64ADD`):**

  ```assembly
  // ... 其他指令 ...
  MOV x10, a0  // 将参数 a 放入寄存器 x10 (假设)
  MOV x11, a1  // 将参数 b 放入寄存器 x11 (假设)
  ADD x10, x11, a0 // 执行加法，结果放入寄存器 a0
  // ... 其他指令 ...
  RET
  ```

* **内存加载和存储:** `ssa.OpLoadReg` 和 `ssa.OpStoreReg` 以及 `ssa.OpRISCV64MOVBload`, `ssa.OpRISCV64MOVBstore` 等操作码，实现了 Go 语言中变量的读写操作。

  ```go
  package main

  func loadAndStore(x *int, value int) {
      *x = value
      _ = *x
  }

  func main() {
      num := 10
      loadAndStore(&num, 20)
  }
  ```

  **假设输入:** 编译器编译上述 `loadAndStore` 函数。

  **可能的输出 (对应 `ssa.OpRISCV64MOVWstore` 和 `ssa.OpRISCV64MOVWload`):**

  ```assembly
  // ... 其他指令 ...
  MOV a0, a0  //  指针 x 在寄存器 a0 (假设)
  MOV a1, a1  //  value 在寄存器 a1 (假设)
  SW a1, 0(a0) // 存储 value 到 x 指向的内存地址
  LW a2, 0(a0) // 从 x 指向的内存地址加载值到 a2
  // ... 其他指令 ...
  RET
  ```

* **函数调用:** `ssa.OpRISCV64CALLstatic`, `ssa.OpRISCV64CALLclosure`, `ssa.OpRISCV64CALLinter` 对应了 Go 语言中不同类型的函数调用。

  ```go
  package main

  import "fmt"

  func greet(name string) {
      fmt.Println("Hello,", name)
  }

  func main() {
      greet("World")
  }
  ```

  **假设输入:** 编译器编译包含 `greet` 函数调用的 `main` 函数。

  **可能的输出 (对应 `ssa.OpRISCV64CALLstatic`):**

  ```assembly
  // ... 其他指令 ...
  LA gp, runtime.gocall // 加载 runtime.gocall 函数地址 (可能需要设置 G 寄存器)
  MOV a0, ...        // 设置 greet 函数的参数 (字符串 "World")
  CALL greet           // 调用 greet 函数
  // ... 其他指令 ...
  ```

* **控制流语句:** `ssaGenBlock` 中处理的 `ssa.BlockRISCV64BEQ`, `ssa.BlockRISCV64BNE` 等，对应了 Go 语言的 `if`、`for`、`switch` 等控制流语句。

  ```go
  package main

  func isPositive(n int) bool {
      if n > 0 {
          return true
      }
      return false
  }

  func main() {
      println(isPositive(5))
  }
  ```

  **假设输入:** 编译器编译 `isPositive` 函数。

  **可能的输出 (对应 `ssa.BlockRISCV64BGEZ`):**

  ```assembly
  // ... 其他指令 ...
  MOV a0, a0  // 参数 n 在寄存器 a0 (假设)
  BGEZ a0, L1  // 如果 n 大于等于 0，跳转到 L1
  MOV a0, zero // 否则，将 false (0) 放入返回值寄存器 a0
  JMP L2       // 跳转到 L2
  L1:
  LI a0, 1    // 将 true (1) 放入返回值寄存器 a0
  L2:
  RET
  ```

* **原子操作:** `ssa.OpRISCV64LoweredAtomicLoad...` 和 `ssa.OpRISCV64LoweredAtomicStore...` 等操作码，实现了 Go 语言中的原子操作，用于并发编程中的数据同步。

  ```go
  package main

  import "sync/atomic"

  var counter int64

  func increment() {
      atomic.AddInt64(&counter, 1)
  }

  func main() {
      increment()
  }
  ```

  **假设输入:** 编译器编译 `increment` 函数。

  **可能的输出 (对应 `ssa.OpRISCV64LoweredAtomicAdd64`):**

  ```assembly
  // ... 其他指令 ...
  MOV a0, a0  // &counter 的地址在寄存器 a0 (假设)
  LI a1, 1    // 要增加的值 1 在寄存器 a1
  amoadd.d a1, a1, (a0) // 原子地将 a1 的值加到 a0 指向的内存地址
  // ... 其他指令 ...
  RET
  ```

* **内存清零和拷贝:** `ssa.OpRISCV64LoweredZero` 和 `ssa.OpRISCV64LoweredMove` 用于实现 Go 语言中对内存块的清零（例如，初始化变量）和拷贝（例如，复制切片或字符串）。

* **defer 语句:** `ssaGenBlock` 中对 `ssa.BlockDefer` 的处理，表明了对 Go 语言 `defer` 语句的支持。

* **panic 和 recover:** `ssa.OpRISCV64LoweredPanicBoundsA` 等操作码暗示了 Go 语言中 `panic` 机制的实现，例如数组越界检查。

* **nil 检查:** `ssa.OpRISCV64LoweredNilCheck` 用于在必要时插入空指针检查。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理发生在 Go 编译器的更上层。然而，编译器的命令行参数（例如 `-gcflags` 用于传递额外的编译器标志）会影响到 SSA 生成和最终代码的生成。例如，优化级别的设置可能会导致编译器生成不同的 SSA 代码，从而影响 `ssaGenValue` 和 `ssaGenBlock` 的行为。

**使用者易犯错的点:**

作为编译器开发者，在使用或修改这类代码时，容易犯以下错误：

1. **寄存器映射错误:**  错误地修改 `ssaRegToReg` 中的映射关系，会导致 SSA 逻辑寄存器对应到错误的物理寄存器，从而产生不可预测的行为。

2. **指令选择错误:** 在 `loadByType` 或 `storeByType` 中选择了错误的加载/存储指令，可能导致数据被错误地截断、符号扩展或大小不匹配。

3. **SSA 操作码处理不完整:**  如果 `ssaGenValue` 中缺少对某个 SSA 操作码的处理，或者处理逻辑有误，会导致编译出的程序行为不正确。

4. **控制流逻辑错误:** `ssaGenBlock` 中的分支跳转逻辑错误，会导致程序执行流程混乱。

5. **对特定指令的副作用理解不透彻:** 例如，某些原子操作指令可能对内存排序有特定的影响，如果理解不正确，可能导致并发程序出现问题。

**示例说明 `ssaGenValue` 中 `ssa.OpRISCV64LoweredFMAXD` 的代码:**

```go
	case ssa.OpRISCV64LoweredFMAXD, ssa.OpRISCV64LoweredFMIND, ssa.OpRISCV64LoweredFMAXS, ssa.OpRISCV64LoweredFMINS:
		// Most of FMIN/FMAX result match Go's required behaviour, unless one of the
		// inputs is a NaN. As such, we need to explicitly test for NaN
		// before using FMIN/FMAX.

		// FADD Rarg0, Rarg1, Rout // FADD is used to propagate a NaN to the result in these cases.
		// FEQ  Rarg0, Rarg0, Rtmp
		// BEQZ Rtmp, end
		// FEQ  Rarg1, Rarg1, Rtmp
		// BEQZ Rtmp, end
		// F(MIN | MAX)

		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg()
		add, feq := riscv.AFADDD, riscv.AFEQD
		if v.Op == ssa.OpRISCV64LoweredFMAXS || v.Op == ssa.OpRISCV64LoweredFMINS {
			add = riscv.AFADDS
			feq = riscv.AFEQS
		}

		p1 := s.Prog(add)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r0
		p1.Reg = r1
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = out

		p2 := s.Prog(feq)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = r0
		p2.Reg = r0
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = riscv.REG_TMP

		p3 := s.Prog(riscv.ABEQ)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = riscv.REG_ZERO
		p3.Reg = riscv.REG_TMP
		p3.To.Type = obj.TYPE_BRANCH

		p4 := s.Prog(feq)
		p4.From.Type = obj.TYPE_REG
		p4.From.Reg = r1
		p4.Reg = r1
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = riscv.REG_TMP

		p5 := s.Prog(riscv.ABEQ)
		p5.From.Type = obj.TYPE_REG
		p5.From.Reg = riscv.REG_ZERO
		p5.Reg = riscv.REG_TMP
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
```

**假设输入:** 编译器遇到如下 Go 代码：

```go
package main

func floatMax(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func main() {
	result := floatMax(3.14, 2.71)
	println(result)
}
```

**代码推理:**  `ssa.OpRISCV64LoweredFMAXD` 对应 `floatMax` 函数中的 `>` 比较和 `return` 语句，特别是当需要处理 NaN (Not a Number) 的情况时。RISC-V 的 `FMAX.d` 指令的行为与 Go 的 `math.Max` 在处理 NaN 上有所不同。Go 规定如果其中一个参数是 NaN，则返回 NaN。因此，需要额外的代码来显式检查 NaN。

**生成的汇编代码解释:**

1. **`FADD Rarg0, Rarg1, Rout`**:  使用浮点加法来将 NaN 传播到结果寄存器 (`out`)。如果 `r0` 或 `r1` 是 NaN，则 `out` 也会是 NaN。
2. **`FEQ Rarg0, Rarg0, Rtmp`**:  比较 `r0` 和自身。如果 `r0` 是 NaN，则比较结果为 false (因为 NaN 不等于任何值，包括自身)。结果存储在临时寄存器 `Rtmp` 中。
3. **`BEQZ Rtmp, end`**: 如果 `Rtmp` 为零（表示 `r0` 不是 NaN），则跳转到 `end` 标签。
4. **`FEQ Rarg1, Rarg1, Rtmp`**:  类似地，检查 `r1` 是否为 NaN。
5. **`BEQZ Rtmp, end`**: 如果 `Rtmp` 为零（表示 `r1` 也不是 NaN），则跳转到 `end` 标签。
6. **`F(MIN | MAX)`**:  如果两个操作数都不是 NaN，则执行实际的浮点最大值/最小值指令。
7. **`nop`**:  `end` 标签指向 `nop` 指令，作为跳转目标。

这段代码确保了即使输入包含 NaN，`floatMax` 函数也能按照 Go 语言的语义返回 NaN。

希望以上分析能够帮助你理解 `go/src/cmd/compile/internal/riscv64/ssa.go` 文件的功能和实现细节。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/riscv64/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package riscv64

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/ssagen"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/obj/riscv"
)

// ssaRegToReg maps ssa register numbers to obj register numbers.
var ssaRegToReg = []int16{
	riscv.REG_X0,
	// X1 (LR): unused
	riscv.REG_X2,
	riscv.REG_X3,
	riscv.REG_X4,
	riscv.REG_X5,
	riscv.REG_X6,
	riscv.REG_X7,
	riscv.REG_X8,
	riscv.REG_X9,
	riscv.REG_X10,
	riscv.REG_X11,
	riscv.REG_X12,
	riscv.REG_X13,
	riscv.REG_X14,
	riscv.REG_X15,
	riscv.REG_X16,
	riscv.REG_X17,
	riscv.REG_X18,
	riscv.REG_X19,
	riscv.REG_X20,
	riscv.REG_X21,
	riscv.REG_X22,
	riscv.REG_X23,
	riscv.REG_X24,
	riscv.REG_X25,
	riscv.REG_X26,
	riscv.REG_X27,
	riscv.REG_X28,
	riscv.REG_X29,
	riscv.REG_X30,
	riscv.REG_X31,
	riscv.REG_F0,
	riscv.REG_F1,
	riscv.REG_F2,
	riscv.REG_F3,
	riscv.REG_F4,
	riscv.REG_F5,
	riscv.REG_F6,
	riscv.REG_F7,
	riscv.REG_F8,
	riscv.REG_F9,
	riscv.REG_F10,
	riscv.REG_F11,
	riscv.REG_F12,
	riscv.REG_F13,
	riscv.REG_F14,
	riscv.REG_F15,
	riscv.REG_F16,
	riscv.REG_F17,
	riscv.REG_F18,
	riscv.REG_F19,
	riscv.REG_F20,
	riscv.REG_F21,
	riscv.REG_F22,
	riscv.REG_F23,
	riscv.REG_F24,
	riscv.REG_F25,
	riscv.REG_F26,
	riscv.REG_F27,
	riscv.REG_F28,
	riscv.REG_F29,
	riscv.REG_F30,
	riscv.REG_F31,
	0, // SB isn't a real register.  We fill an Addr.Reg field with 0 in this case.
}

func loadByType(t *types.Type) obj.As {
	width := t.Size()

	if t.IsFloat() {
		switch width {
		case 4:
			return riscv.AMOVF
		case 8:
			return riscv.AMOVD
		default:
			base.Fatalf("unknown float width for load %d in type %v", width, t)
			return 0
		}
	}

	switch width {
	case 1:
		if t.IsSigned() {
			return riscv.AMOVB
		} else {
			return riscv.AMOVBU
		}
	case 2:
		if t.IsSigned() {
			return riscv.AMOVH
		} else {
			return riscv.AMOVHU
		}
	case 4:
		if t.IsSigned() {
			return riscv.AMOVW
		} else {
			return riscv.AMOVWU
		}
	case 8:
		return riscv.AMOV
	default:
		base.Fatalf("unknown width for load %d in type %v", width, t)
		return 0
	}
}

// storeByType returns the store instruction of the given type.
func storeByType(t *types.Type) obj.As {
	width := t.Size()

	if t.IsFloat() {
		switch width {
		case 4:
			return riscv.AMOVF
		case 8:
			return riscv.AMOVD
		default:
			base.Fatalf("unknown float width for store %d in type %v", width, t)
			return 0
		}
	}

	switch width {
	case 1:
		return riscv.AMOVB
	case 2:
		return riscv.AMOVH
	case 4:
		return riscv.AMOVW
	case 8:
		return riscv.AMOV
	default:
		base.Fatalf("unknown width for store %d in type %v", width, t)
		return 0
	}
}

// largestMove returns the largest move instruction possible and its size,
// given the alignment of the total size of the move.
//
// e.g., a 16-byte move may use MOV, but an 11-byte move must use MOVB.
//
// Note that the moves may not be on naturally aligned addresses depending on
// the source and destination.
//
// This matches the calculation in ssa.moveSize.
func largestMove(alignment int64) (obj.As, int64) {
	switch {
	case alignment%8 == 0:
		return riscv.AMOV, 8
	case alignment%4 == 0:
		return riscv.AMOVW, 4
	case alignment%2 == 0:
		return riscv.AMOVH, 2
	default:
		return riscv.AMOVB, 1
	}
}

// ssaMarkMoves marks any MOVXconst ops that need to avoid clobbering flags.
// RISC-V has no flags, so this is a no-op.
func ssaMarkMoves(s *ssagen.State, b *ssa.Block) {}

func ssaGenValue(s *ssagen.State, v *ssa.Value) {
	s.SetPos(v.Pos)

	switch v.Op {
	case ssa.OpInitMem:
		// memory arg needs no code
	case ssa.OpArg:
		// input args need no code
	case ssa.OpPhi:
		ssagen.CheckLoweredPhi(v)
	case ssa.OpCopy, ssa.OpRISCV64MOVDreg:
		if v.Type.IsMemory() {
			return
		}
		rs := v.Args[0].Reg()
		rd := v.Reg()
		if rs == rd {
			return
		}
		as := riscv.AMOV
		if v.Type.IsFloat() {
			as = riscv.AMOVD
		}
		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = rs
		p.To.Type = obj.TYPE_REG
		p.To.Reg = rd
	case ssa.OpRISCV64MOVDnop:
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
	case ssa.OpArgIntReg, ssa.OpArgFloatReg:
		// The assembler needs to wrap the entry safepoint/stack growth code with spill/unspill
		// The loop only runs once.
		for _, a := range v.Block.Func.RegArgs {
			// Pass the spill/unspill information along to the assembler, offset by size of
			// the saved LR slot.
			addr := ssagen.SpillSlotAddr(a, riscv.REG_SP, base.Ctxt.Arch.FixedFrameSize)
			s.FuncInfo().AddSpill(
				obj.RegSpill{Reg: a.Reg, Addr: addr, Unspill: loadByType(a.Type), Spill: storeByType(a.Type)})
		}
		v.Block.Func.RegArgs = nil

		ssagen.CheckArgReg(v)
	case ssa.OpSP, ssa.OpSB, ssa.OpGetG:
		// nothing to do
	case ssa.OpRISCV64MOVBreg, ssa.OpRISCV64MOVHreg, ssa.OpRISCV64MOVWreg,
		ssa.OpRISCV64MOVBUreg, ssa.OpRISCV64MOVHUreg, ssa.OpRISCV64MOVWUreg:
		a := v.Args[0]
		for a.Op == ssa.OpCopy || a.Op == ssa.OpRISCV64MOVDreg {
			a = a.Args[0]
		}
		as := v.Op.Asm()
		rs := v.Args[0].Reg()
		rd := v.Reg()
		if a.Op == ssa.OpLoadReg {
			t := a.Type
			switch {
			case v.Op == ssa.OpRISCV64MOVBreg && t.Size() == 1 && t.IsSigned(),
				v.Op == ssa.OpRISCV64MOVHreg && t.Size() == 2 && t.IsSigned(),
				v.Op == ssa.OpRISCV64MOVWreg && t.Size() == 4 && t.IsSigned(),
				v.Op == ssa.OpRISCV64MOVBUreg && t.Size() == 1 && !t.IsSigned(),
				v.Op == ssa.OpRISCV64MOVHUreg && t.Size() == 2 && !t.IsSigned(),
				v.Op == ssa.OpRISCV64MOVWUreg && t.Size() == 4 && !t.IsSigned():
				// arg is a proper-typed load and already sign/zero-extended
				if rs == rd {
					return
				}
				as = riscv.AMOV
			default:
			}
		}
		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = rs
		p.To.Type = obj.TYPE_REG
		p.To.Reg = rd
	case ssa.OpRISCV64ADD, ssa.OpRISCV64SUB, ssa.OpRISCV64SUBW, ssa.OpRISCV64XNOR, ssa.OpRISCV64XOR,
		ssa.OpRISCV64OR, ssa.OpRISCV64ORN, ssa.OpRISCV64AND, ssa.OpRISCV64ANDN,
		ssa.OpRISCV64SLL, ssa.OpRISCV64SLLW, ssa.OpRISCV64SRA, ssa.OpRISCV64SRAW, ssa.OpRISCV64SRL, ssa.OpRISCV64SRLW,
		ssa.OpRISCV64SLT, ssa.OpRISCV64SLTU, ssa.OpRISCV64MUL, ssa.OpRISCV64MULW, ssa.OpRISCV64MULH,
		ssa.OpRISCV64MULHU, ssa.OpRISCV64DIV, ssa.OpRISCV64DIVU, ssa.OpRISCV64DIVW,
		ssa.OpRISCV64DIVUW, ssa.OpRISCV64REM, ssa.OpRISCV64REMU, ssa.OpRISCV64REMW,
		ssa.OpRISCV64REMUW,
		ssa.OpRISCV64ROL, ssa.OpRISCV64ROLW, ssa.OpRISCV64ROR, ssa.OpRISCV64RORW,
		ssa.OpRISCV64FADDS, ssa.OpRISCV64FSUBS, ssa.OpRISCV64FMULS, ssa.OpRISCV64FDIVS,
		ssa.OpRISCV64FEQS, ssa.OpRISCV64FNES, ssa.OpRISCV64FLTS, ssa.OpRISCV64FLES,
		ssa.OpRISCV64FADDD, ssa.OpRISCV64FSUBD, ssa.OpRISCV64FMULD, ssa.OpRISCV64FDIVD,
		ssa.OpRISCV64FEQD, ssa.OpRISCV64FNED, ssa.OpRISCV64FLTD, ssa.OpRISCV64FLED, ssa.OpRISCV64FSGNJD,
		ssa.OpRISCV64MIN, ssa.OpRISCV64MAX, ssa.OpRISCV64MINU, ssa.OpRISCV64MAXU,
		ssa.OpRISCV64SH1ADD, ssa.OpRISCV64SH2ADD, ssa.OpRISCV64SH3ADD:
		r := v.Reg()
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r2
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r

	case ssa.OpRISCV64LoweredFMAXD, ssa.OpRISCV64LoweredFMIND, ssa.OpRISCV64LoweredFMAXS, ssa.OpRISCV64LoweredFMINS:
		// Most of FMIN/FMAX result match Go's required behaviour, unless one of the
		// inputs is a NaN. As such, we need to explicitly test for NaN
		// before using FMIN/FMAX.

		// FADD Rarg0, Rarg1, Rout // FADD is used to propagate a NaN to the result in these cases.
		// FEQ  Rarg0, Rarg0, Rtmp
		// BEQZ Rtmp, end
		// FEQ  Rarg1, Rarg1, Rtmp
		// BEQZ Rtmp, end
		// F(MIN | MAX)

		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg()
		add, feq := riscv.AFADDD, riscv.AFEQD
		if v.Op == ssa.OpRISCV64LoweredFMAXS || v.Op == ssa.OpRISCV64LoweredFMINS {
			add = riscv.AFADDS
			feq = riscv.AFEQS
		}

		p1 := s.Prog(add)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r0
		p1.Reg = r1
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = out

		p2 := s.Prog(feq)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = r0
		p2.Reg = r0
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = riscv.REG_TMP

		p3 := s.Prog(riscv.ABEQ)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = riscv.REG_ZERO
		p3.Reg = riscv.REG_TMP
		p3.To.Type = obj.TYPE_BRANCH

		p4 := s.Prog(feq)
		p4.From.Type = obj.TYPE_REG
		p4.From.Reg = r1
		p4.Reg = r1
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = riscv.REG_TMP

		p5 := s.Prog(riscv.ABEQ)
		p5.From.Type = obj.TYPE_REG
		p5.From.Reg = riscv.REG_ZERO
		p5.Reg = riscv.REG_TMP
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

	case ssa.OpRISCV64LoweredMuluhilo:
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		p := s.Prog(riscv.AMULHU)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.Reg = r0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
		p1 := s.Prog(riscv.AMUL)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r1
		p1.Reg = r0
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = v.Reg1()
	case ssa.OpRISCV64LoweredMuluover:
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		p := s.Prog(riscv.AMULHU)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.Reg = r0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg1()
		p1 := s.Prog(riscv.AMUL)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r1
		p1.Reg = r0
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = v.Reg0()
		p2 := s.Prog(riscv.ASNEZ)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = v.Reg1()
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = v.Reg1()
	case ssa.OpRISCV64FMADDD, ssa.OpRISCV64FMSUBD, ssa.OpRISCV64FNMADDD, ssa.OpRISCV64FNMSUBD,
		ssa.OpRISCV64FMADDS, ssa.OpRISCV64FMSUBS, ssa.OpRISCV64FNMADDS, ssa.OpRISCV64FNMSUBS:
		r := v.Reg()
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		r3 := v.Args[2].Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r2
		p.Reg = r1
		p.AddRestSource(obj.Addr{Type: obj.TYPE_REG, Reg: r3})
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	case ssa.OpRISCV64FSQRTS, ssa.OpRISCV64FNEGS, ssa.OpRISCV64FABSD, ssa.OpRISCV64FSQRTD, ssa.OpRISCV64FNEGD,
		ssa.OpRISCV64FMVSX, ssa.OpRISCV64FMVDX,
		ssa.OpRISCV64FCVTSW, ssa.OpRISCV64FCVTSL, ssa.OpRISCV64FCVTWS, ssa.OpRISCV64FCVTLS,
		ssa.OpRISCV64FCVTDW, ssa.OpRISCV64FCVTDL, ssa.OpRISCV64FCVTWD, ssa.OpRISCV64FCVTLD, ssa.OpRISCV64FCVTDS, ssa.OpRISCV64FCVTSD,
		ssa.OpRISCV64NOT, ssa.OpRISCV64NEG, ssa.OpRISCV64NEGW:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpRISCV64ADDI, ssa.OpRISCV64ADDIW, ssa.OpRISCV64XORI, ssa.OpRISCV64ORI, ssa.OpRISCV64ANDI,
		ssa.OpRISCV64SLLI, ssa.OpRISCV64SLLIW, ssa.OpRISCV64SRAI, ssa.OpRISCV64SRAIW,
		ssa.OpRISCV64SRLI, ssa.OpRISCV64SRLIW, ssa.OpRISCV64SLTI, ssa.OpRISCV64SLTIU,
		ssa.OpRISCV64RORI, ssa.OpRISCV64RORIW:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpRISCV64MOVDconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpRISCV64MOVaddr:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_ADDR
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

		var wantreg string
		// MOVW $sym+off(base), R
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
			p.From.Reg = riscv.REG_SP
			p.From.Offset = v.AuxInt
		}
		if reg := v.Args[0].RegName(); reg != wantreg {
			v.Fatalf("bad reg %s for symbol type %T, want %s", reg, v.Aux, wantreg)
		}
	case ssa.OpRISCV64MOVBload, ssa.OpRISCV64MOVHload, ssa.OpRISCV64MOVWload, ssa.OpRISCV64MOVDload,
		ssa.OpRISCV64MOVBUload, ssa.OpRISCV64MOVHUload, ssa.OpRISCV64MOVWUload,
		ssa.OpRISCV64FMOVWload, ssa.OpRISCV64FMOVDload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpRISCV64MOVBstore, ssa.OpRISCV64MOVHstore, ssa.OpRISCV64MOVWstore, ssa.OpRISCV64MOVDstore,
		ssa.OpRISCV64FMOVWstore, ssa.OpRISCV64FMOVDstore:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpRISCV64MOVBstorezero, ssa.OpRISCV64MOVHstorezero, ssa.OpRISCV64MOVWstorezero, ssa.OpRISCV64MOVDstorezero:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = riscv.REG_ZERO
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpRISCV64SEQZ, ssa.OpRISCV64SNEZ:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpRISCV64CALLstatic, ssa.OpRISCV64CALLclosure, ssa.OpRISCV64CALLinter:
		s.Call(v)
	case ssa.OpRISCV64CALLtail:
		s.TailCall(v)
	case ssa.OpRISCV64LoweredWB:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		// AuxInt encodes how many buffer entries we need.
		p.To.Sym = ir.Syms.GCWriteBarrier[v.AuxInt-1]
	case ssa.OpRISCV64LoweredPanicBoundsA, ssa.OpRISCV64LoweredPanicBoundsB, ssa.OpRISCV64LoweredPanicBoundsC:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ssagen.BoundsCheckFunc[v.AuxInt]
		s.UseArgs(16) // space used in callee args area by assembly stubs

	case ssa.OpRISCV64LoweredAtomicLoad8:
		s.Prog(riscv.AFENCE)
		p := s.Prog(riscv.AMOVBU)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
		s.Prog(riscv.AFENCE)

	case ssa.OpRISCV64LoweredAtomicLoad32, ssa.OpRISCV64LoweredAtomicLoad64:
		as := riscv.ALRW
		if v.Op == ssa.OpRISCV64LoweredAtomicLoad64 {
			as = riscv.ALRD
		}
		p := s.Prog(as)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

	case ssa.OpRISCV64LoweredAtomicStore8:
		s.Prog(riscv.AFENCE)
		p := s.Prog(riscv.AMOVB)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		s.Prog(riscv.AFENCE)

	case ssa.OpRISCV64LoweredAtomicStore32, ssa.OpRISCV64LoweredAtomicStore64:
		as := riscv.AAMOSWAPW
		if v.Op == ssa.OpRISCV64LoweredAtomicStore64 {
			as = riscv.AAMOSWAPD
		}
		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		p.RegTo2 = riscv.REG_ZERO

	case ssa.OpRISCV64LoweredAtomicAdd32, ssa.OpRISCV64LoweredAtomicAdd64:
		as := riscv.AAMOADDW
		if v.Op == ssa.OpRISCV64LoweredAtomicAdd64 {
			as = riscv.AAMOADDD
		}
		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		p.RegTo2 = riscv.REG_TMP

		p2 := s.Prog(riscv.AADD)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = riscv.REG_TMP
		p2.Reg = v.Args[1].Reg()
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = v.Reg0()

	case ssa.OpRISCV64LoweredAtomicExchange32, ssa.OpRISCV64LoweredAtomicExchange64:
		as := riscv.AAMOSWAPW
		if v.Op == ssa.OpRISCV64LoweredAtomicExchange64 {
			as = riscv.AAMOSWAPD
		}
		p := s.Prog(as)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		p.RegTo2 = v.Reg0()

	case ssa.OpRISCV64LoweredAtomicCas32, ssa.OpRISCV64LoweredAtomicCas64:
		// MOV  ZERO, Rout
		// LR	(Rarg0), Rtmp
		// BNE	Rtmp, Rarg1, 3(PC)
		// SC	Rarg2, (Rarg0), Rtmp
		// BNE	Rtmp, ZERO, -3(PC)
		// MOV	$1, Rout

		lr := riscv.ALRW
		sc := riscv.ASCW
		if v.Op == ssa.OpRISCV64LoweredAtomicCas64 {
			lr = riscv.ALRD
			sc = riscv.ASCD
		}

		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		r2 := v.Args[2].Reg()
		out := v.Reg0()

		p := s.Prog(riscv.AMOV)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = riscv.REG_ZERO
		p.To.Type = obj.TYPE_REG
		p.To.Reg = out

		p1 := s.Prog(lr)
		p1.From.Type = obj.TYPE_MEM
		p1.From.Reg = r0
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = riscv.REG_TMP

		p2 := s.Prog(riscv.ABNE)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = r1
		p2.Reg = riscv.REG_TMP
		p2.To.Type = obj.TYPE_BRANCH

		p3 := s.Prog(sc)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = r2
		p3.To.Type = obj.TYPE_MEM
		p3.To.Reg = r0
		p3.RegTo2 = riscv.REG_TMP

		p4 := s.Prog(riscv.ABNE)
		p4.From.Type = obj.TYPE_REG
		p4.From.Reg = riscv.REG_TMP
		p4.Reg = riscv.REG_ZERO
		p4.To.Type = obj.TYPE_BRANCH
		p4.To.SetTarget(p1)

		p5 := s.Prog(riscv.AMOV)
		p5.From.Type = obj.TYPE_CONST
		p5.From.Offset = 1
		p5.To.Type = obj.TYPE_REG
		p5.To.Reg = out

		p6 := s.Prog(obj.ANOP)
		p2.To.SetTarget(p6)

	case ssa.OpRISCV64LoweredAtomicAnd32, ssa.OpRISCV64LoweredAtomicOr32:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		p.RegTo2 = riscv.REG_ZERO

	case ssa.OpRISCV64LoweredZero:
		mov, sz := largestMove(v.AuxInt)

		//	mov	ZERO, (Rarg0)
		//	ADD	$sz, Rarg0
		//	BGEU	Rarg1, Rarg0, -2(PC)

		p := s.Prog(mov)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = riscv.REG_ZERO
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()

		p2 := s.Prog(riscv.AADD)
		p2.From.Type = obj.TYPE_CONST
		p2.From.Offset = sz
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = v.Args[0].Reg()

		p3 := s.Prog(riscv.ABGEU)
		p3.To.Type = obj.TYPE_BRANCH
		p3.Reg = v.Args[0].Reg()
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = v.Args[1].Reg()
		p3.To.SetTarget(p)

	case ssa.OpRISCV64LoweredMove:
		mov, sz := largestMove(v.AuxInt)

		//	mov	(Rarg1), T2
		//	mov	T2, (Rarg0)
		//	ADD	$sz, Rarg0
		//	ADD	$sz, Rarg1
		//	BGEU	Rarg2, Rarg0, -4(PC)

		p := s.Prog(mov)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = riscv.REG_T2

		p2 := s.Prog(mov)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = riscv.REG_T2
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = v.Args[0].Reg()

		p3 := s.Prog(riscv.AADD)
		p3.From.Type = obj.TYPE_CONST
		p3.From.Offset = sz
		p3.To.Type = obj.TYPE_REG
		p3.To.Reg = v.Args[0].Reg()

		p4 := s.Prog(riscv.AADD)
		p4.From.Type = obj.TYPE_CONST
		p4.From.Offset = sz
		p4.To.Type = obj.TYPE_REG
		p4.To.Reg = v.Args[1].Reg()

		p5 := s.Prog(riscv.ABGEU)
		p5.To.Type = obj.TYPE_BRANCH
		p5.Reg = v.Args[1].Reg()
		p5.From.Type = obj.TYPE_REG
		p5.From.Reg = v.Args[2].Reg()
		p5.To.SetTarget(p)

	case ssa.OpRISCV64LoweredNilCheck:
		// Issue a load which will fault if arg is nil.
		p := s.Prog(riscv.AMOVB)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = riscv.REG_ZERO
		if logopt.Enabled() {
			logopt.LogOpt(v.Pos, "nilcheck", "genssa", v.Block.Func.Name)
		}
		if base.Debug.Nil != 0 && v.Pos.Line() > 1 { // v.Pos == 1 in generated wrappers
			base.WarnfAt(v.Pos, "generated nil check")
		}

	case ssa.OpRISCV64LoweredGetClosurePtr:
		// Closure pointer is S10 (riscv.REG_CTXT).
		ssagen.CheckLoweredGetClosurePtr(v)

	case ssa.OpRISCV64LoweredGetCallerSP:
		// caller's SP is FixedFrameSize below the address of the first arg
		p := s.Prog(riscv.AMOV)
		p.From.Type = obj.TYPE_ADDR
		p.From.Offset = -base.Ctxt.Arch.FixedFrameSize
		p.From.Name = obj.NAME_PARAM
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpRISCV64LoweredGetCallerPC:
		p := s.Prog(obj.AGETCALLERPC)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpRISCV64DUFFZERO:
		p := s.Prog(obj.ADUFFZERO)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Duffzero
		p.To.Offset = v.AuxInt

	case ssa.OpRISCV64DUFFCOPY:
		p := s.Prog(obj.ADUFFCOPY)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Duffcopy
		p.To.Offset = v.AuxInt

	case ssa.OpRISCV64LoweredPubBarrier:
		// FENCE
		s.Prog(v.Op.Asm())

	case ssa.OpRISCV64LoweredRound32F, ssa.OpRISCV64LoweredRound64F:
		// input is already rounded

	case ssa.OpClobber, ssa.OpClobberReg:
		// TODO: implement for clobberdead experiment. Nop is ok for now.

	default:
		v.Fatalf("Unhandled op %v", v.Op)
	}
}

var blockBranch = [...]obj.As{
	ssa.BlockRISCV64BEQ:  riscv.ABEQ,
	ssa.BlockRISCV64BEQZ: riscv.ABEQZ,
	ssa.BlockRISCV64BGE:  riscv.ABGE,
	ssa.BlockRISCV64BGEU: riscv.ABGEU,
	ssa.BlockRISCV64BGEZ: riscv.ABGEZ,
	ssa.BlockRISCV64BGTZ: riscv.ABGTZ,
	ssa.BlockRISCV64BLEZ: riscv.ABLEZ,
	ssa.BlockRISCV64BLT:  riscv.ABLT,
	ssa.BlockRISCV64BLTU: riscv.ABLTU,
	ssa.BlockRISCV64BLTZ: riscv.ABLTZ,
	ssa.BlockRISCV64BNE:  riscv.ABNE,
	ssa.BlockRISCV64BNEZ: riscv.ABNEZ,
}

func ssaGenBlock(s *ssagen.State, b, next *ssa.Block) {
	s.SetPos(b.Pos)

	switch b.Kind {
	case ssa.BlockDefer:
		// defer returns in A0:
		// 0 if we should continue executing
		// 1 if we should jump to deferreturn call
		p := s.Prog(riscv.ABNE)
		p.To.Type = obj.TYPE_BRANCH
		p.From.Type = obj.TYPE_REG
		p.From.Reg = riscv.REG_ZERO
		p.Reg = riscv.REG_A0
		s.Branches = append(s.Branches, ssagen.Branch{P: p, B: b.Succs[1].Block()})
		if b.Succs[0].Block() != next {
			p := s.Prog(obj.AJMP)
			p.To.Type = obj.TYPE_BRANCH
			s.Branches = append(s.Branches, ssagen.Branch{P: p, B: b.Succs[0].Block()})
		}
	case ssa.BlockPlain:
		if b.Succs[0].Block() != next {
			p := s.Prog(obj.AJMP)
			p.To.Type = obj.TYPE_BRANCH
			s.Branches = append(s.Branches, ssagen.Branch{P: p, B: b.Succs[0].Block()})
		}
	case ssa.BlockExit, ssa.BlockRetJmp:
	case ssa.BlockRet:
		s.Prog(obj.ARET)
	case ssa.BlockRISCV64BEQ, ssa.BlockRISCV64BEQZ, ssa.BlockRISCV64BNE, ssa.BlockRISCV64BNEZ,
		ssa.BlockRISCV64BLT, ssa.BlockRISCV64BLEZ, ssa.BlockRISCV64BGE, ssa.BlockRISCV64BGEZ,
		ssa.BlockRISCV64BLTZ, ssa.BlockRISCV64BGTZ, ssa.BlockRISCV64BLTU, ssa.BlockRISCV64BGEU:

		as := blockBranch[b.Kind]
		invAs := riscv.InvertBranch(as)

		var p *obj.Prog
		switch next {
		case b.Succs[0].Block():
			p = s.Br(invAs, b.Succs[1].Block())
		case b.Succs[1].Block():
			p = s.Br(as, b.Succs[0].Block())
		default:
			if b.Likely != ssa.BranchUnlikely {
				p = s.Br(as, b.Succs[0].Block())
				s.Br(obj.AJMP, b.Succs[1].Block())
			} else {
				p = s.Br(invAs, b.Succs[1].Block())
				s.Br(obj.AJMP, b.Succs[0].Block())
			}
		}

		p.From.Type = obj.TYPE_REG
		switch b.Kind {
		case ssa.BlockRISCV64BEQ, ssa.BlockRISCV64BNE, ssa.BlockRISCV64BLT, ssa.BlockRISCV64BGE, ssa.BlockRISCV64BLTU, ssa.BlockRISCV64BGEU:
			if b.NumControls() != 2 {
				b.Fatalf("Unexpected number of controls (%d != 2): %s", b.NumControls(), b.LongString())
			}
			p.From.Reg = b.Controls[0].Reg()
			p.Reg = b.Controls[1].Reg()

		case ssa.BlockRISCV64BEQZ, ssa.BlockRISCV64BNEZ, ssa.BlockRISCV64BGEZ, ssa.BlockRISCV64BLEZ, ssa.BlockRISCV64BLTZ, ssa.BlockRISCV64BGTZ:
			if b.NumControls() != 1 {
				b.Fatalf("Unexpected number of controls (%d != 1): %s", b.NumControls(), b.LongString())
			}
			p.From.Reg = b.Controls[0].Reg()
		}

	default:
		b.Fatalf("Unhandled block: %s", b.LongString())
	}
}

func loadRegResult(s *ssagen.State, f *ssa.Func, t *types.Type, reg int16, n *ir.Name, off int64) *obj.Prog {
	p := s.Prog(loadByType(t))
	p.From.Type = obj.TYPE_MEM
	p.From.Name = obj.NAME_AUTO
	p.From.Sym = n.Linksym()
	p.From.Offset = n.FrameOffset() + off
	p.To.Type = obj.TYPE_REG
	p.To.Reg = reg
	return p
}

func spillArgReg(pp *objw.Progs, p *obj.Prog, f *ssa.Func, t *types.Type, reg int16, n *ir.Name, off int64) *obj.Prog {
	p = pp.Append(p, storeByType(t), obj.TYPE_REG, reg, 0, obj.TYPE_MEM, 0, n.FrameOffset()+off)
	p.To.Name = obj.NAME_PARAM
	p.To.Sym = n.Linksym()
	p.Pos = p.Pos.WithNotStmt()
	return p
}

"""



```