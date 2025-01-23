Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - Context is Key:**

The first thing I noticed is the file path: `go/src/cmd/compile/internal/amd64/ssa.go`. This immediately tells me it's part of the Go compiler, specifically the code generation phase for the AMD64 architecture. The `ssa` part indicates it deals with Static Single Assignment form, a key intermediate representation in compilers.

**2. Core Functionality -  Generating Machine Code:**

Given the context, the primary function of this code is to translate SSA instructions into actual AMD64 assembly instructions. This means it's responsible for tasks like:

* **Instruction Selection:** Choosing the correct AMD64 instruction for a given SSA operation.
* **Operand Handling:**  Determining how to represent the operands of those instructions (registers, memory addresses, constants).
* **Register Allocation (Implicit):** While not explicitly doing register allocation *here*, this code makes decisions that impact how registers are used. For instance, using specific registers for certain operations (like AX for division).
* **Flag Management:** Handling CPU flags, as seen in the `ssaMarkMoves` function.
* **Special Case Handling:** Dealing with architecture-specific optimizations and instructions (like `DUFFZERO`).

**3. Dissecting Key Functions:**

I started by examining the most prominent functions and their names:

* **`ssaMarkMoves`:**  The name suggests it's about marking `MOV` instructions. The code confirms this, focusing on `MOV` instructions that might affect flags. This hints at the importance of flag preservation for conditional operations.
* **`loadByType`, `storeByType`, `moveByType`:** These are clearly utility functions for selecting the appropriate `MOV` instruction based on the data type's size and whether it's a float. This highlights the type-aware nature of code generation.
* **`opregreg`:**  A helper to generate two-operand instructions where both operands are registers. This is a common pattern in assembly.
* **`memIdx`:**  Another helper, specifically for constructing memory addresses with an index register. This relates to array access and pointer arithmetic.
* **`duffStart`, `duffAdj`, `duff`:**  The name "duff" is a strong indicator of the Duff's device optimization for `memset`-like operations.
* **`getgFromTLS`:**  This function clearly retrieves the Go runtime's `g` (goroutine) structure pointer from thread-local storage (TLS). This is crucial for Go's concurrency model.
* **`ssaGenValue`:** This is the *main* function for generating code for individual SSA values (instructions). The massive `switch` statement confirms this, handling a wide variety of SSA opcodes.
* **`ssaGenBlock`:** This function generates code for SSA blocks, primarily handling control flow (jumps, branches).

**4. Inferring Go Features:**

By looking at the handled SSA opcodes in `ssaGenValue`, I could infer the Go language features being implemented:

* **Basic Arithmetic:** `ADD`, `SUB`, `MUL`, `DIV`, `AND`, `OR`, `XOR`, shifts, rotates.
* **Comparisons:** `CMP`, `TEST`, and the various `SETcc` instructions.
* **Floating-Point Operations:** `ADDSS`, `ADDSD`, `MULSS`, `MULSD`, `DIVSS`, `DIVSD`, `SQRT`, conversions.
* **Memory Access:** `MOV` instructions (load and store).
* **Constants:** `MOV $constant, reg`.
* **Control Flow:** Conditional jumps based on flags.
* **Function Calls:** `CALLstatic`, `CALLclosure`, `CALLinter`, tail calls.
* **Concurrency:**  `getgFromTLS`, write barriers (`LoweredWB`).
* **Atomic Operations:** `XCHG`, `XADD`, `CMPXCHG`, atomic AND/OR.
* **String/Memory Operations:**  `REP STOSQ`, `REP MOVSQ`, `DUFFZERO`, `DUFFCOPY`.
* **Bounds Checking:** `LoweredPanicBoundsA`, `LoweredPanicBoundsB`, `LoweredPanicBoundsC`.
* **Nil Checks:** `LoweredNilCheck`.
* **CPU Feature Detection:** `LoweredHasCPUFeature`.

**5. Code Examples and Reasoning:**

For each key function or logical block, I tried to construct a simple Go code example that would likely result in those SSA operations being generated. I then mentally traced how the provided code would translate that SSA into assembly.

* **`ssaMarkMoves`:** Focused on a conditional statement where flags are used.
* **`loadByType`, `storeByType`:** Showed basic variable declarations of different types.
* **`opregreg`:**  Demonstrated simple register-to-register operations.
* **`memIdx`:** Used array indexing to exemplify the need for indexed memory access.
* **`duff`:**  Showed a `for` loop setting elements of a large slice to zero, a typical use case for `DUFFZERO`.
* **`getgFromTLS`:**  While not directly generating code for this, I explained its role in the runtime.
* **`ssaGenValue`:**  This required breaking down the `switch` statement and providing examples for various operation categories (arithmetic, memory access, comparisons, etc.). The division example was chosen because it showcases specific register usage (AX, DX).
* **`ssaGenBlock`:**  Focused on `if` statements and `switch` statements to illustrate how different control flow structures are handled.

**6. Command-Line Arguments and Common Mistakes:**

I scanned the code for any explicit handling of command-line arguments. Since this is low-level code generation, it doesn't directly parse user-provided flags. However, it *uses* information derived from command-line flags (via `base.Ctxt`, `buildcfg`). I highlighted the TLS instruction selection as an example of this.

For common mistakes, I considered scenarios where developers might misunderstand how the compiler works or make assumptions about code generation:

* **Incorrect assumptions about flag preservation.**
* **Not understanding the limitations of `DUFFZERO` (size constraints).**
* **Being unaware of the specific register requirements for certain operations (like division).**

**7. Refinement and Organization:**

After the initial analysis, I organized the information logically, grouping related functionalities together. I used headings, bullet points, and code blocks to improve readability and clarity. I also double-checked my examples and explanations for accuracy.

This iterative process of understanding the context, dissecting the code, inferring functionality, creating examples, and refining the presentation allowed for a comprehensive analysis of the provided Go code snippet.
这段代码是Go编译器中AMD64架构的代码生成部分，它负责将静态单赋值(SSA)形式的中间代码转换为AMD64汇编指令。以下是它的功能分解：

**1. 标记需要避免覆盖标志位的MOV指令 (`ssaMarkMoves`)**

   - **功能:** 遍历SSA块中的指令，标记那些在标志位仍然活跃的情况下执行的`MOV`常量指令 (`MOVQconst`, `MOVLconst`)。
   - **原理:**  某些`MOV`指令会影响CPU的标志位（例如，零标志位、符号标志位）。如果后续指令依赖这些标志位进行条件判断，那么执行`MOV`指令时不应覆盖这些标志位。
   - **标记方式:**  通过给`Value`的 `Aux` 字段设置一个非空的特殊值 (`ssa.AuxMark`) 来标记这些需要注意的 `MOV` 指令。
   - **使用场景:**  例如，在一个if语句中，比较指令设置了标志位，紧接着的`MOV`常量指令如果会修改标志位，就需要被标记。

   ```go
   // 假设的SSA代码块
   // b0:
   //   v1 = CMPQconst [10] rsi
   //   If v1 goto b1 else b2
   // b1:
   //   v2 = MOVQconst [0]  // 如果标志位对b1很重要，这个MOVQconst需要被标记
   //   ...
   ```

**2. 根据类型返回加载指令 (`loadByType`)**

   - **功能:**  根据给定的Go类型 `t`，返回相应的AMD64加载汇编指令。
   - **原理:**  不同的数据类型在内存中的大小不同，需要使用不同的加载指令。例如，加载一个字节用 `MOVBLZX`，加载一个字用 `MOVWLZX`。
   - **特殊处理:**  为了避免部分寄存器写入的问题，对于非浮点类型且大小为1或2字节的情况，会使用带零扩展的加载指令 (`MOVBLZX`, `MOVWLZX`)。
   - **默认情况:**  对于其他情况，会调用 `storeByType` 返回存储指令，因为对于这些情况，加载和存储操作码没有区别。

   ```go
   // 例如，加载一个int8类型的变量
   var x int8
   y := x  // 对应 SSA 中的 Load 操作，会调用 loadByType(typeOf(x)) 返回 x86.AMOVBLZX
   ```

**3. 根据类型返回存储指令 (`storeByType`)**

   - **功能:**  根据给定的Go类型 `t`，返回相应的AMD64存储汇编指令。
   - **原理:**  与 `loadByType` 类似，根据数据类型的大小选择合适的存储指令。
   - **支持类型:**  支持浮点数 (`MOVSS`, `MOVSD`) 和整数 (`MOVB`, `MOVW`, `MOVL`, `MOVQ`, `MOVUPS`)。
   - **异常处理:**  如果遇到不支持的类型，会触发 `panic`。

   ```go
   // 例如，存储一个float64类型的值
   var x float64 = 3.14
   y := x
   // ... 对 y 进行修改
   x = y  // 对应 SSA 中的 Store 操作，会调用 storeByType(typeOf(x)) 返回 x86.AMOVSD
   ```

**4. 根据类型返回寄存器到寄存器的移动指令 (`moveByType`)**

   - **功能:**  根据给定的Go类型 `t`，返回相应的AMD64寄存器到寄存器的移动汇编指令。
   - **原理:**  与加载和存储类似，但主要用于寄存器之间的拷贝。
   - **优化:**  对于浮点数，直接移动整个SSE2寄存器 (`MOVUPS`)，因为这样比只移动低位部分更快。
   - **避免部分写入:**  对于1字节的整数，使用 `MOVL` 避免部分寄存器写入。
   - **支持类型:**  支持浮点数 (`MOVUPS`) 和整数 (`MOVL`, `MOVQ`, `MOVUPS` 用于 int128)。
   - **异常处理:**  如果遇到不支持的整数大小，会触发 `panic`。

   ```go
   // 例如，将一个int类型的寄存器值拷贝到另一个寄存器
   var x int
   var y int
   // ... 将 x 的值加载到寄存器 R1
   // ... 将 y 的值加载到寄存器 R2
   y = x // 对应 SSA 中的 Copy 操作，如果 R1 != R2，会调用 moveByType(typeOf(x)) 返回 x86.AMOVL，生成 MOVL R1, R2
   ```

**5. 生成 `dest := dest op src` 形式的指令 (`opregreg`)**

   - **功能:**  生成一个AMD64汇编指令，其操作是 `dest = dest op src`，其中 `dest` 和 `src` 都是寄存器。
   - **返回:**  返回创建的 `obj.Prog` 结构体，方便后续调整（例如，添加偏移量）。
   - **用途:**  用于实现双操作数指令，例如加法、减法、位运算等。

   ```go
   // 例如，实现 r1 += r2
   // 假设 r1 对应寄存器 AX，r2 对应寄存器 BX
   p := opregreg(s, x86.AADDL, x86.REG_AX, x86.REG_BX) // 生成 ADDL BX, AX
   ```

**6. 填充索引内存引用 (`memIdx`)**

   - **功能:**  为给定的SSA值 `v` 填充一个索引内存引用到 `obj.Addr` 结构体 `a` 中。
   - **假设:**  假设基址寄存器和索引寄存器分别是 `v.Args[0].Reg()` 和 `v.Args[1].Reg()`。
   - **处理:**  设置 `a.Type` 为 `obj.TYPE_MEM`，设置 `a.Scale` 为操作码的缩放因子 (`v.Op.Scale()`)。
   - **`SP` 寄存器优化:**  如果索引寄存器是 `SP` (栈指针)，则交换基址寄存器和索引寄存器，这是一种常见的优化。
   - **注意:**  调用者需要使用 `gc.AddAux` 或 `gc.AddAux2` 来处理 `v.Aux` 中可能存在的偏移量或符号信息。

   ```go
   // 例如，访问数组 arr[i]，其中 arr 的地址在寄存器 R10，i 的值在寄存器 R11
   // 假设对应的 SSA Value 是 v，v.Args[0] 是指向 arr 的指针，v.Args[1] 是索引 i
   var addr obj.Addr
   memIdx(&addr, v) // addr 会被设置为 TYPE_MEM, Reg: R10, Index: R11, Scale: ... (取决于数组元素大小)
   ```

**7. Duff's Device 相关函数 (`duffStart`, `duffAdj`, `duff`)**

   - **功能:**  用于实现 Duff's Device 优化，这是一种用于快速清零或拷贝大块内存的技巧。
   - **原理:**  Duff's Device 通过展开循环来减少循环开销。
   - **`duff` 函数:**  计算使用 Duff's Device 清零给定大小内存块所需的偏移量和指针调整量。
   - **`duffStart` 和 `duffAdj`:**  分别返回偏移量和调整量。
   - **限制:**  Duff's Device 通常对大小有限制（代码中是 32 到 1024 字节，且必须是特定步长的倍数）。

   ```go
   // 例如，将一个大小为 128 字节的切片清零
   data := make([]byte, 128)
   // 在 SSA 代码生成阶段，如果检测到这样的清零操作，可能会使用 DUFFZERO 指令
   // duffStart(128) 和 duffAdj(128) 会计算出相应的偏移量和调整量
   ```

**8. 从 TLS 获取 g 结构体指针 (`getgFromTLS`)**

   - **功能:**  生成从线程本地存储 (TLS) 获取当前 goroutine 的 `g` 结构体指针的汇编指令。
   - **原理:**  每个 goroutine 都有一个关联的 `g` 结构体，包含了 goroutine 的状态信息。TLS 是一种每个线程独有的存储机制，可以高效地访问当前线程的特定数据。
   - **指令选择:**  根据目标平台的 `CanUse1InsnTLS` 函数的返回值，选择使用单条指令或多条指令来获取 `g` 指针。
   - **重要性:**  `g` 指针是 Go 运行时系统管理 goroutine 的关键。

   ```go
   // 在函数入口或某些需要访问 goroutine 信息的地方，会调用 getgFromTLS
   // 例如，在 runtime 包中的某些函数中
   ```

**9. 生成 SSA 值对应的汇编指令 (`ssaGenValue`)**

   - **功能:**  这是代码生成的核心函数，根据给定的 SSA `Value` (代表一个操作或指令) 生成相应的AMD64汇编指令。
   - **实现方式:**  使用一个巨大的 `switch` 语句来处理各种不同的 SSA 操作码 (`v.Op`)。
   - **详细处理:**  针对每种操作码，生成相应的汇编指令，并设置其源操作数、目标操作数、常量、内存地址等信息。
   - **示例:**
     - `ssa.OpAMD64ADDQ`: 生成加法指令 `ADDQ`。
     - `ssa.OpAMD64MOVQconst`: 生成移动常量到寄存器的指令 `MOVQ $constant, reg`。
     - `ssa.OpAMD64CALLstatic`: 生成静态函数调用指令 `CALL function`。
     - `ssa.OpAMD64LoweredNilCheck`: 生成空指针检查指令 `TESTB AX, (reg)`。
   - **特殊情况处理:**  代码中包含了大量的针对特定指令和优化策略的处理，例如：
     - 常量加法的优化 (`INC`, `DEC` 指令)。
     - 除法指令的溢出处理。
     - 条件移动指令 (`CMOVcc`).
     - 原子操作指令 (`LOCK`, `XCHG`, `CMPXCHG`).
     - Duff's Device 的使用 (`DUFFZERO`, `DUFFCOPY`).
     - 调用约定和参数传递的处理 (`OpArgIntReg`, `OpArgFloatReg`).
     - 获取调用者信息 (`LoweredGetCallerPC`, `LoweredGetCallerSP`).

**10. 生成 SSA 块的汇编指令 (`ssaGenBlock`)**

    - **功能:**  根据给定的SSA块 `b` 和下一个要执行的块 `next`，生成相应的控制流汇编指令。
    - **处理不同类型的块:**
        - **`ssa.BlockPlain`:**  生成无条件跳转指令 (`JMP`)，如果下一个块不是紧随其后的块。
        - **`ssa.BlockDefer`:**  处理 `defer` 语句的返回逻辑，检查返回值并决定是否跳转到 `deferreturn` 调用。
        - **`ssa.BlockExit`, `ssa.BlockRetJmp`:**  不生成代码，表示函数退出或尾调用跳转。
        - **`ssa.BlockRet`:**  生成函数返回指令 (`RET`).
        - **`ssa.BlockAMD64EQF`, `ssa.BlockAMD64NEF`:** 处理浮点数比较后的条件跳转，可能需要组合多个跳转指令来正确处理 NaN 的情况。
        - **`ssa.BlockAMD64EQ` 等条件跳转块:**  根据不同的条件码生成相应的条件跳转指令 (`JE`, `JNE`, `JL`, etc.)。会根据 `b.Likely` 提示进行分支预测优化。
        - **`ssa.BlockAMD64JUMPTABLE`:**  生成跳转表，用于实现 `switch` 语句。
    - **分支目标:**  将生成的跳转指令与目标块关联起来，以便后续链接器可以正确填充跳转地址。

**11. 加载寄存器结果 (`loadRegResult`)**

    - **功能:**  生成将存储在栈上的函数返回值加载到寄存器的汇编指令。
    - **参数:**  包括 SSA 状态、函数信息、返回值类型、目标寄存器、返回值对应的 `ir.Name` 和偏移量。
    - **生成指令:**  使用 `loadByType` 获取加载指令，并设置内存地址和目标寄存器。

**12. 溢出参数到栈 (`spillArgReg`)**

    - **功能:**  生成将寄存器中的参数值溢出到栈上的汇编指令。
    - **场景:**  当寄存器数量不足以容纳所有参数时，需要将部分参数存储到栈上。
    - **参数:**  包括程序列表、当前指令、函数信息、参数类型、寄存器、参数对应的 `ir.Name` 和偏移量。
    - **生成指令:**  使用 `storeByType` 获取存储指令，并设置源寄存器和栈上的内存地址。

**总结来说，`go/src/cmd/compile/internal/amd64/ssa.go` 的核心功能是将 Go 语言的 SSA 中间表示转换为 AMD64 架构的汇编指令，它涵盖了算术运算、逻辑运算、内存访问、控制流、函数调用、原子操作等多种 Go 语言特性的底层实现。**

**Go 代码示例 (及其对应的假设 SSA 和汇编输出):**

**示例 1: 简单的加法**

```go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	add(10, 20)
}
```

**假设的 SSA (简化):**

```
// 函数 add
b0:
    v1 = LocalSlot {int} // a
    v2 = LocalSlot {int} // b
    v3 = ArgIntReg a
    v4 = ArgIntReg b
    Store v3 v1
    Store v4 v2
    Goto b1
b1:
    v5 = Load v1
    v6 = Load v2
    v7 = ADDL v5 v6
    Return v7
```

**`ssaGenValue` 生成的汇编 (部分):**

```assembly
// ... 函数 add 的入口 ...
// 加载 a 到寄存器 (假设是 AX)
MOVL (SP+offset_a), AX
// 加载 b 到寄存器 (假设是 BX)
MOVL (SP+offset_b), BX
// 执行加法
ADDL BX, AX
// ... 返回 AX 中的结果 ...
```

**示例 2:  `if` 语句**

```go
package main

func compare(a int) bool {
	if a > 10 {
		return true
	}
	return false
}

func main() {
	compare(15)
}
```

**假设的 SSA (简化):**

```
// 函数 compare
b0:
    v1 = LocalSlot {int} // a
    v2 = ArgIntReg a
    Store v2 v1
    Goto b1
b1:
    v3 = Load v1
    v4 = CMPLconst [10] v3
    IfGT v4 goto b2 else b3
b2:
    v5 = MOVQconst [1] // true
    Return v5
b3:
    v6 = MOVQconst [0] // false
    Return v6
```

**`ssaGenValue` 和 `ssaGenBlock` 生成的汇编 (部分):**

```assembly
// ... 函数 compare 的入口 ...
// 加载 a 到寄存器 (假设是 AX)
MOVL (SP+offset_a), AX
// 比较 a 和 10
CMPL $0xa, AX
// 条件跳转
JLE  label_b3  // 如果小于等于，跳转到 b3
// ... b2 的代码 (返回 true) ...
MOVQ $0x1, AX
RET
label_b3:
// ... b3 的代码 (返回 false) ...
MOVQ $0x0, AX
RET
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它属于编译器的内部代码生成阶段，依赖于编译器前端和中间阶段的处理结果。但是，编译器在处理命令行参数时，会影响到代码生成的行为，例如：

- **`-gcflags`:**  传递给编译器的标志可能会影响优化级别、内联策略等，从而影响生成的 SSA 和最终的汇编代码。
- **`-N` (禁用优化):**  禁用优化会生成更直接、更少优化的汇编代码。
- **`-l` (禁用内联):**  禁用内联会阻止函数调用被替换为函数体，从而影响调用指令的生成。
- **目标架构 (`GOARCH`)**:  编译器会根据目标架构选择不同的代码生成后端 (例如，amd64, arm64)。

**使用者易犯错的点 (对于阅读和理解这段代码的人):**

1. **对 SSA 的理解不足:**  要理解代码生成的过程，需要先了解 SSA 的概念和特性。
2. **对 AMD64 汇编不熟悉:**  代码中涉及到大量的 AMD64 汇编指令，不熟悉这些指令的功能和操作数格式会难以理解代码的意图。
3. **忽略上下文:**  这段代码是编译器的一部分，它的行为受到编译器其他阶段的影响，例如类型检查、逃逸分析等。孤立地理解这段代码可能会导致误解。
4. **过度关注细节而忽略整体流程:**  `ssaGenValue` 函数非常庞大，包含了很多细节。在理解其功能时，先把握整体流程，再深入到具体的操作码处理可能更有效。
5. **假设代码总是按照直观的方式生成:**  编译器会进行各种优化，生成的汇编代码可能与手写的代码有很大差异，需要理解编译器的优化策略。

总而言之，这段代码是 Go 编译器中非常底层和复杂的组成部分，理解它需要一定的编译原理、体系结构和汇编语言的知识。

### 提示词
```
这是路径为go/src/cmd/compile/internal/amd64/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package amd64

import (
	"fmt"
	"internal/buildcfg"
	"math"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/ssagen"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/obj/x86"
)

// ssaMarkMoves marks any MOVXconst ops that need to avoid clobbering flags.
func ssaMarkMoves(s *ssagen.State, b *ssa.Block) {
	flive := b.FlagsLiveAtEnd
	for _, c := range b.ControlValues() {
		flive = c.Type.IsFlags() || flive
	}
	for i := len(b.Values) - 1; i >= 0; i-- {
		v := b.Values[i]
		if flive && (v.Op == ssa.OpAMD64MOVLconst || v.Op == ssa.OpAMD64MOVQconst) {
			// The "mark" is any non-nil Aux value.
			v.Aux = ssa.AuxMark
		}
		if v.Type.IsFlags() {
			flive = false
		}
		for _, a := range v.Args {
			if a.Type.IsFlags() {
				flive = true
			}
		}
	}
}

// loadByType returns the load instruction of the given type.
func loadByType(t *types.Type) obj.As {
	// Avoid partial register write
	if !t.IsFloat() {
		switch t.Size() {
		case 1:
			return x86.AMOVBLZX
		case 2:
			return x86.AMOVWLZX
		}
	}
	// Otherwise, there's no difference between load and store opcodes.
	return storeByType(t)
}

// storeByType returns the store instruction of the given type.
func storeByType(t *types.Type) obj.As {
	width := t.Size()
	if t.IsFloat() {
		switch width {
		case 4:
			return x86.AMOVSS
		case 8:
			return x86.AMOVSD
		}
	} else {
		switch width {
		case 1:
			return x86.AMOVB
		case 2:
			return x86.AMOVW
		case 4:
			return x86.AMOVL
		case 8:
			return x86.AMOVQ
		case 16:
			return x86.AMOVUPS
		}
	}
	panic(fmt.Sprintf("bad store type %v", t))
}

// moveByType returns the reg->reg move instruction of the given type.
func moveByType(t *types.Type) obj.As {
	if t.IsFloat() {
		// Moving the whole sse2 register is faster
		// than moving just the correct low portion of it.
		// There is no xmm->xmm move with 1 byte opcode,
		// so use movups, which has 2 byte opcode.
		return x86.AMOVUPS
	} else {
		switch t.Size() {
		case 1:
			// Avoids partial register write
			return x86.AMOVL
		case 2:
			return x86.AMOVL
		case 4:
			return x86.AMOVL
		case 8:
			return x86.AMOVQ
		case 16:
			return x86.AMOVUPS // int128s are in SSE registers
		default:
			panic(fmt.Sprintf("bad int register width %d:%v", t.Size(), t))
		}
	}
}

// opregreg emits instructions for
//
//	dest := dest(To) op src(From)
//
// and also returns the created obj.Prog so it
// may be further adjusted (offset, scale, etc).
func opregreg(s *ssagen.State, op obj.As, dest, src int16) *obj.Prog {
	p := s.Prog(op)
	p.From.Type = obj.TYPE_REG
	p.To.Type = obj.TYPE_REG
	p.To.Reg = dest
	p.From.Reg = src
	return p
}

// memIdx fills out a as an indexed memory reference for v.
// It assumes that the base register and the index register
// are v.Args[0].Reg() and v.Args[1].Reg(), respectively.
// The caller must still use gc.AddAux/gc.AddAux2 to handle v.Aux as necessary.
func memIdx(a *obj.Addr, v *ssa.Value) {
	r, i := v.Args[0].Reg(), v.Args[1].Reg()
	a.Type = obj.TYPE_MEM
	a.Scale = v.Op.Scale()
	if a.Scale == 1 && i == x86.REG_SP {
		r, i = i, r
	}
	a.Reg = r
	a.Index = i
}

// DUFFZERO consists of repeated blocks of 4 MOVUPSs + LEAQ,
// See runtime/mkduff.go.
func duffStart(size int64) int64 {
	x, _ := duff(size)
	return x
}
func duffAdj(size int64) int64 {
	_, x := duff(size)
	return x
}

// duff returns the offset (from duffzero, in bytes) and pointer adjust (in bytes)
// required to use the duffzero mechanism for a block of the given size.
func duff(size int64) (int64, int64) {
	if size < 32 || size > 1024 || size%dzClearStep != 0 {
		panic("bad duffzero size")
	}
	steps := size / dzClearStep
	blocks := steps / dzBlockLen
	steps %= dzBlockLen
	off := dzBlockSize * (dzBlocks - blocks)
	var adj int64
	if steps != 0 {
		off -= dzLeaqSize
		off -= dzMovSize * steps
		adj -= dzClearStep * (dzBlockLen - steps)
	}
	return off, adj
}

func getgFromTLS(s *ssagen.State, r int16) {
	// See the comments in cmd/internal/obj/x86/obj6.go
	// near CanUse1InsnTLS for a detailed explanation of these instructions.
	if x86.CanUse1InsnTLS(base.Ctxt) {
		// MOVQ (TLS), r
		p := s.Prog(x86.AMOVQ)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = x86.REG_TLS
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	} else {
		// MOVQ TLS, r
		// MOVQ (r)(TLS*1), r
		p := s.Prog(x86.AMOVQ)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = x86.REG_TLS
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
		q := s.Prog(x86.AMOVQ)
		q.From.Type = obj.TYPE_MEM
		q.From.Reg = r
		q.From.Index = x86.REG_TLS
		q.From.Scale = 1
		q.To.Type = obj.TYPE_REG
		q.To.Reg = r
	}
}

func ssaGenValue(s *ssagen.State, v *ssa.Value) {
	switch v.Op {
	case ssa.OpAMD64VFMADD231SD:
		p := s.Prog(v.Op.Asm())
		p.From = obj.Addr{Type: obj.TYPE_REG, Reg: v.Args[2].Reg()}
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: v.Reg()}
		p.AddRestSourceReg(v.Args[1].Reg())
	case ssa.OpAMD64ADDQ, ssa.OpAMD64ADDL:
		r := v.Reg()
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		switch {
		case r == r1:
			p := s.Prog(v.Op.Asm())
			p.From.Type = obj.TYPE_REG
			p.From.Reg = r2
			p.To.Type = obj.TYPE_REG
			p.To.Reg = r
		case r == r2:
			p := s.Prog(v.Op.Asm())
			p.From.Type = obj.TYPE_REG
			p.From.Reg = r1
			p.To.Type = obj.TYPE_REG
			p.To.Reg = r
		default:
			var asm obj.As
			if v.Op == ssa.OpAMD64ADDQ {
				asm = x86.ALEAQ
			} else {
				asm = x86.ALEAL
			}
			p := s.Prog(asm)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = r1
			p.From.Scale = 1
			p.From.Index = r2
			p.To.Type = obj.TYPE_REG
			p.To.Reg = r
		}
	// 2-address opcode arithmetic
	case ssa.OpAMD64SUBQ, ssa.OpAMD64SUBL,
		ssa.OpAMD64MULQ, ssa.OpAMD64MULL,
		ssa.OpAMD64ANDQ, ssa.OpAMD64ANDL,
		ssa.OpAMD64ORQ, ssa.OpAMD64ORL,
		ssa.OpAMD64XORQ, ssa.OpAMD64XORL,
		ssa.OpAMD64SHLQ, ssa.OpAMD64SHLL,
		ssa.OpAMD64SHRQ, ssa.OpAMD64SHRL, ssa.OpAMD64SHRW, ssa.OpAMD64SHRB,
		ssa.OpAMD64SARQ, ssa.OpAMD64SARL, ssa.OpAMD64SARW, ssa.OpAMD64SARB,
		ssa.OpAMD64ROLQ, ssa.OpAMD64ROLL, ssa.OpAMD64ROLW, ssa.OpAMD64ROLB,
		ssa.OpAMD64RORQ, ssa.OpAMD64RORL, ssa.OpAMD64RORW, ssa.OpAMD64RORB,
		ssa.OpAMD64ADDSS, ssa.OpAMD64ADDSD, ssa.OpAMD64SUBSS, ssa.OpAMD64SUBSD,
		ssa.OpAMD64MULSS, ssa.OpAMD64MULSD, ssa.OpAMD64DIVSS, ssa.OpAMD64DIVSD,
		ssa.OpAMD64MINSS, ssa.OpAMD64MINSD,
		ssa.OpAMD64POR, ssa.OpAMD64PXOR,
		ssa.OpAMD64BTSL, ssa.OpAMD64BTSQ,
		ssa.OpAMD64BTCL, ssa.OpAMD64BTCQ,
		ssa.OpAMD64BTRL, ssa.OpAMD64BTRQ,
		ssa.OpAMD64PCMPEQB, ssa.OpAMD64PSIGNB,
		ssa.OpAMD64PUNPCKLBW:
		opregreg(s, v.Op.Asm(), v.Reg(), v.Args[1].Reg())

	case ssa.OpAMD64PSHUFLW:
		p := s.Prog(v.Op.Asm())
		imm := v.AuxInt
		if imm < 0 || imm > 255 {
			v.Fatalf("Invalid source selection immediate")
		}
		p.From.Offset = imm
		p.From.Type = obj.TYPE_CONST
		p.AddRestSourceReg(v.Args[0].Reg())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpAMD64PSHUFBbroadcast:
		// PSHUFB with a control mask of zero copies byte 0 to all
		// bytes in the register.
		//
		// X15 is always zero with ABIInternal.
		if s.ABI != obj.ABIInternal {
			// zero X15 manually
			opregreg(s, x86.AXORPS, x86.REG_X15, x86.REG_X15)
		}

		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
		p.From.Reg = x86.REG_X15

	case ssa.OpAMD64SHRDQ, ssa.OpAMD64SHLDQ:
		p := s.Prog(v.Op.Asm())
		lo, hi, bits := v.Args[0].Reg(), v.Args[1].Reg(), v.Args[2].Reg()
		p.From.Type = obj.TYPE_REG
		p.From.Reg = bits
		p.To.Type = obj.TYPE_REG
		p.To.Reg = lo
		p.AddRestSourceReg(hi)

	case ssa.OpAMD64BLSIQ, ssa.OpAMD64BLSIL,
		ssa.OpAMD64BLSMSKQ, ssa.OpAMD64BLSMSKL,
		ssa.OpAMD64BLSRQ, ssa.OpAMD64BLSRL:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		switch v.Op {
		case ssa.OpAMD64BLSRQ, ssa.OpAMD64BLSRL:
			p.To.Reg = v.Reg0()
		default:
			p.To.Reg = v.Reg()
		}

	case ssa.OpAMD64ANDNQ, ssa.OpAMD64ANDNL:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
		p.AddRestSourceReg(v.Args[1].Reg())

	case ssa.OpAMD64SARXL, ssa.OpAMD64SARXQ,
		ssa.OpAMD64SHLXL, ssa.OpAMD64SHLXQ,
		ssa.OpAMD64SHRXL, ssa.OpAMD64SHRXQ:
		p := opregreg(s, v.Op.Asm(), v.Reg(), v.Args[1].Reg())
		p.AddRestSourceReg(v.Args[0].Reg())

	case ssa.OpAMD64SHLXLload, ssa.OpAMD64SHLXQload,
		ssa.OpAMD64SHRXLload, ssa.OpAMD64SHRXQload,
		ssa.OpAMD64SARXLload, ssa.OpAMD64SARXQload:
		p := opregreg(s, v.Op.Asm(), v.Reg(), v.Args[1].Reg())
		m := obj.Addr{Type: obj.TYPE_MEM, Reg: v.Args[0].Reg()}
		ssagen.AddAux(&m, v)
		p.AddRestSource(m)

	case ssa.OpAMD64SHLXLloadidx1, ssa.OpAMD64SHLXLloadidx4, ssa.OpAMD64SHLXLloadidx8,
		ssa.OpAMD64SHRXLloadidx1, ssa.OpAMD64SHRXLloadidx4, ssa.OpAMD64SHRXLloadidx8,
		ssa.OpAMD64SARXLloadidx1, ssa.OpAMD64SARXLloadidx4, ssa.OpAMD64SARXLloadidx8,
		ssa.OpAMD64SHLXQloadidx1, ssa.OpAMD64SHLXQloadidx8,
		ssa.OpAMD64SHRXQloadidx1, ssa.OpAMD64SHRXQloadidx8,
		ssa.OpAMD64SARXQloadidx1, ssa.OpAMD64SARXQloadidx8:
		p := opregreg(s, v.Op.Asm(), v.Reg(), v.Args[2].Reg())
		m := obj.Addr{Type: obj.TYPE_MEM}
		memIdx(&m, v)
		ssagen.AddAux(&m, v)
		p.AddRestSource(m)

	case ssa.OpAMD64DIVQU, ssa.OpAMD64DIVLU, ssa.OpAMD64DIVWU:
		// Arg[0] (the dividend) is in AX.
		// Arg[1] (the divisor) can be in any other register.
		// Result[0] (the quotient) is in AX.
		// Result[1] (the remainder) is in DX.
		r := v.Args[1].Reg()

		// Zero extend dividend.
		opregreg(s, x86.AXORL, x86.REG_DX, x86.REG_DX)

		// Issue divide.
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r

	case ssa.OpAMD64DIVQ, ssa.OpAMD64DIVL, ssa.OpAMD64DIVW:
		// Arg[0] (the dividend) is in AX.
		// Arg[1] (the divisor) can be in any other register.
		// Result[0] (the quotient) is in AX.
		// Result[1] (the remainder) is in DX.
		r := v.Args[1].Reg()

		var opCMP, opNEG, opSXD obj.As
		switch v.Op {
		case ssa.OpAMD64DIVQ:
			opCMP, opNEG, opSXD = x86.ACMPQ, x86.ANEGQ, x86.ACQO
		case ssa.OpAMD64DIVL:
			opCMP, opNEG, opSXD = x86.ACMPL, x86.ANEGL, x86.ACDQ
		case ssa.OpAMD64DIVW:
			opCMP, opNEG, opSXD = x86.ACMPW, x86.ANEGW, x86.ACWD
		}

		// CPU faults upon signed overflow, which occurs when the most
		// negative int is divided by -1. Handle divide by -1 as a special case.
		var j1, j2 *obj.Prog
		if ssa.DivisionNeedsFixUp(v) {
			c := s.Prog(opCMP)
			c.From.Type = obj.TYPE_REG
			c.From.Reg = r
			c.To.Type = obj.TYPE_CONST
			c.To.Offset = -1

			// Divisor is not -1, proceed with normal division.
			j1 = s.Prog(x86.AJNE)
			j1.To.Type = obj.TYPE_BRANCH

			// Divisor is -1, manually compute quotient and remainder via fixup code.
			// n / -1 = -n
			n1 := s.Prog(opNEG)
			n1.To.Type = obj.TYPE_REG
			n1.To.Reg = x86.REG_AX

			// n % -1 == 0
			opregreg(s, x86.AXORL, x86.REG_DX, x86.REG_DX)

			// TODO(khr): issue only the -1 fixup code we need.
			// For instance, if only the quotient is used, no point in zeroing the remainder.

			// Skip over normal division.
			j2 = s.Prog(obj.AJMP)
			j2.To.Type = obj.TYPE_BRANCH
		}

		// Sign extend dividend and perform division.
		p := s.Prog(opSXD)
		if j1 != nil {
			j1.To.SetTarget(p)
		}
		p = s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r

		if j2 != nil {
			j2.To.SetTarget(s.Pc())
		}

	case ssa.OpAMD64HMULQ, ssa.OpAMD64HMULL, ssa.OpAMD64HMULQU, ssa.OpAMD64HMULLU:
		// the frontend rewrites constant division by 8/16/32 bit integers into
		// HMUL by a constant
		// SSA rewrites generate the 64 bit versions

		// Arg[0] is already in AX as it's the only register we allow
		// and DX is the only output we care about (the high bits)
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()

		// IMULB puts the high portion in AH instead of DL,
		// so move it to DL for consistency
		if v.Type.Size() == 1 {
			m := s.Prog(x86.AMOVB)
			m.From.Type = obj.TYPE_REG
			m.From.Reg = x86.REG_AH
			m.To.Type = obj.TYPE_REG
			m.To.Reg = x86.REG_DX
		}

	case ssa.OpAMD64MULQU, ssa.OpAMD64MULLU:
		// Arg[0] is already in AX as it's the only register we allow
		// results lo in AX
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()

	case ssa.OpAMD64MULQU2:
		// Arg[0] is already in AX as it's the only register we allow
		// results hi in DX, lo in AX
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()

	case ssa.OpAMD64DIVQU2:
		// Arg[0], Arg[1] are already in Dx, AX, as they're the only registers we allow
		// results q in AX, r in DX
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[2].Reg()

	case ssa.OpAMD64AVGQU:
		// compute (x+y)/2 unsigned.
		// Do a 64-bit add, the overflow goes into the carry.
		// Shift right once and pull the carry back into the 63rd bit.
		p := s.Prog(x86.AADDQ)
		p.From.Type = obj.TYPE_REG
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
		p.From.Reg = v.Args[1].Reg()
		p = s.Prog(x86.ARCRQ)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpAMD64ADDQcarry, ssa.OpAMD64ADCQ:
		r := v.Reg0()
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		switch r {
		case r0:
			p := s.Prog(v.Op.Asm())
			p.From.Type = obj.TYPE_REG
			p.From.Reg = r1
			p.To.Type = obj.TYPE_REG
			p.To.Reg = r
		case r1:
			p := s.Prog(v.Op.Asm())
			p.From.Type = obj.TYPE_REG
			p.From.Reg = r0
			p.To.Type = obj.TYPE_REG
			p.To.Reg = r
		default:
			v.Fatalf("output not in same register as an input %s", v.LongString())
		}

	case ssa.OpAMD64SUBQborrow, ssa.OpAMD64SBBQ:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

	case ssa.OpAMD64ADDQconstcarry, ssa.OpAMD64ADCQconst, ssa.OpAMD64SUBQconstborrow, ssa.OpAMD64SBBQconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

	case ssa.OpAMD64ADDQconst, ssa.OpAMD64ADDLconst:
		r := v.Reg()
		a := v.Args[0].Reg()
		if r == a {
			switch v.AuxInt {
			case 1:
				var asm obj.As
				// Software optimization manual recommends add $1,reg.
				// But inc/dec is 1 byte smaller. ICC always uses inc
				// Clang/GCC choose depending on flags, but prefer add.
				// Experiments show that inc/dec is both a little faster
				// and make a binary a little smaller.
				if v.Op == ssa.OpAMD64ADDQconst {
					asm = x86.AINCQ
				} else {
					asm = x86.AINCL
				}
				p := s.Prog(asm)
				p.To.Type = obj.TYPE_REG
				p.To.Reg = r
				return
			case -1:
				var asm obj.As
				if v.Op == ssa.OpAMD64ADDQconst {
					asm = x86.ADECQ
				} else {
					asm = x86.ADECL
				}
				p := s.Prog(asm)
				p.To.Type = obj.TYPE_REG
				p.To.Reg = r
				return
			case 0x80:
				// 'SUBQ $-0x80, r' is shorter to encode than
				// and functionally equivalent to 'ADDQ $0x80, r'.
				asm := x86.ASUBL
				if v.Op == ssa.OpAMD64ADDQconst {
					asm = x86.ASUBQ
				}
				p := s.Prog(asm)
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = -0x80
				p.To.Type = obj.TYPE_REG
				p.To.Reg = r
				return

			}
			p := s.Prog(v.Op.Asm())
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = v.AuxInt
			p.To.Type = obj.TYPE_REG
			p.To.Reg = r
			return
		}
		var asm obj.As
		if v.Op == ssa.OpAMD64ADDQconst {
			asm = x86.ALEAQ
		} else {
			asm = x86.ALEAL
		}
		p := s.Prog(asm)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = a
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r

	case ssa.OpAMD64CMOVQEQ, ssa.OpAMD64CMOVLEQ, ssa.OpAMD64CMOVWEQ,
		ssa.OpAMD64CMOVQLT, ssa.OpAMD64CMOVLLT, ssa.OpAMD64CMOVWLT,
		ssa.OpAMD64CMOVQNE, ssa.OpAMD64CMOVLNE, ssa.OpAMD64CMOVWNE,
		ssa.OpAMD64CMOVQGT, ssa.OpAMD64CMOVLGT, ssa.OpAMD64CMOVWGT,
		ssa.OpAMD64CMOVQLE, ssa.OpAMD64CMOVLLE, ssa.OpAMD64CMOVWLE,
		ssa.OpAMD64CMOVQGE, ssa.OpAMD64CMOVLGE, ssa.OpAMD64CMOVWGE,
		ssa.OpAMD64CMOVQHI, ssa.OpAMD64CMOVLHI, ssa.OpAMD64CMOVWHI,
		ssa.OpAMD64CMOVQLS, ssa.OpAMD64CMOVLLS, ssa.OpAMD64CMOVWLS,
		ssa.OpAMD64CMOVQCC, ssa.OpAMD64CMOVLCC, ssa.OpAMD64CMOVWCC,
		ssa.OpAMD64CMOVQCS, ssa.OpAMD64CMOVLCS, ssa.OpAMD64CMOVWCS,
		ssa.OpAMD64CMOVQGTF, ssa.OpAMD64CMOVLGTF, ssa.OpAMD64CMOVWGTF,
		ssa.OpAMD64CMOVQGEF, ssa.OpAMD64CMOVLGEF, ssa.OpAMD64CMOVWGEF:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpAMD64CMOVQNEF, ssa.OpAMD64CMOVLNEF, ssa.OpAMD64CMOVWNEF:
		// Flag condition: ^ZERO || PARITY
		// Generate:
		//   CMOV*NE  SRC,DST
		//   CMOV*PS  SRC,DST
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
		var q *obj.Prog
		if v.Op == ssa.OpAMD64CMOVQNEF {
			q = s.Prog(x86.ACMOVQPS)
		} else if v.Op == ssa.OpAMD64CMOVLNEF {
			q = s.Prog(x86.ACMOVLPS)
		} else {
			q = s.Prog(x86.ACMOVWPS)
		}
		q.From.Type = obj.TYPE_REG
		q.From.Reg = v.Args[1].Reg()
		q.To.Type = obj.TYPE_REG
		q.To.Reg = v.Reg()

	case ssa.OpAMD64CMOVQEQF, ssa.OpAMD64CMOVLEQF, ssa.OpAMD64CMOVWEQF:
		// Flag condition: ZERO && !PARITY
		// Generate:
		//   MOV      SRC,TMP
		//   CMOV*NE  DST,TMP
		//   CMOV*PC  TMP,DST
		//
		// TODO(rasky): we could generate:
		//   CMOV*NE  DST,SRC
		//   CMOV*PC  SRC,DST
		// But this requires a way for regalloc to know that SRC might be
		// clobbered by this instruction.
		t := v.RegTmp()
		opregreg(s, moveByType(v.Type), t, v.Args[1].Reg())

		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = t
		var q *obj.Prog
		if v.Op == ssa.OpAMD64CMOVQEQF {
			q = s.Prog(x86.ACMOVQPC)
		} else if v.Op == ssa.OpAMD64CMOVLEQF {
			q = s.Prog(x86.ACMOVLPC)
		} else {
			q = s.Prog(x86.ACMOVWPC)
		}
		q.From.Type = obj.TYPE_REG
		q.From.Reg = t
		q.To.Type = obj.TYPE_REG
		q.To.Reg = v.Reg()

	case ssa.OpAMD64MULQconst, ssa.OpAMD64MULLconst:
		r := v.Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
		p.AddRestSourceReg(v.Args[0].Reg())

	case ssa.OpAMD64ANDQconst:
		asm := v.Op.Asm()
		// If the constant is positive and fits into 32 bits, use ANDL.
		// This saves a few bytes of encoding.
		if 0 <= v.AuxInt && v.AuxInt <= (1<<32-1) {
			asm = x86.AANDL
		}
		p := s.Prog(asm)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpAMD64SUBQconst, ssa.OpAMD64SUBLconst,
		ssa.OpAMD64ANDLconst,
		ssa.OpAMD64ORQconst, ssa.OpAMD64ORLconst,
		ssa.OpAMD64XORQconst, ssa.OpAMD64XORLconst,
		ssa.OpAMD64SHLQconst, ssa.OpAMD64SHLLconst,
		ssa.OpAMD64SHRQconst, ssa.OpAMD64SHRLconst, ssa.OpAMD64SHRWconst, ssa.OpAMD64SHRBconst,
		ssa.OpAMD64SARQconst, ssa.OpAMD64SARLconst, ssa.OpAMD64SARWconst, ssa.OpAMD64SARBconst,
		ssa.OpAMD64ROLQconst, ssa.OpAMD64ROLLconst, ssa.OpAMD64ROLWconst, ssa.OpAMD64ROLBconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpAMD64SBBQcarrymask, ssa.OpAMD64SBBLcarrymask:
		r := v.Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
	case ssa.OpAMD64LEAQ1, ssa.OpAMD64LEAQ2, ssa.OpAMD64LEAQ4, ssa.OpAMD64LEAQ8,
		ssa.OpAMD64LEAL1, ssa.OpAMD64LEAL2, ssa.OpAMD64LEAL4, ssa.OpAMD64LEAL8,
		ssa.OpAMD64LEAW1, ssa.OpAMD64LEAW2, ssa.OpAMD64LEAW4, ssa.OpAMD64LEAW8:
		p := s.Prog(v.Op.Asm())
		memIdx(&p.From, v)
		o := v.Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = o
		if v.AuxInt != 0 && v.Aux == nil {
			// Emit an additional LEA to add the displacement instead of creating a slow 3 operand LEA.
			switch v.Op {
			case ssa.OpAMD64LEAQ1, ssa.OpAMD64LEAQ2, ssa.OpAMD64LEAQ4, ssa.OpAMD64LEAQ8:
				p = s.Prog(x86.ALEAQ)
			case ssa.OpAMD64LEAL1, ssa.OpAMD64LEAL2, ssa.OpAMD64LEAL4, ssa.OpAMD64LEAL8:
				p = s.Prog(x86.ALEAL)
			case ssa.OpAMD64LEAW1, ssa.OpAMD64LEAW2, ssa.OpAMD64LEAW4, ssa.OpAMD64LEAW8:
				p = s.Prog(x86.ALEAW)
			}
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = o
			p.To.Type = obj.TYPE_REG
			p.To.Reg = o
		}
		ssagen.AddAux(&p.From, v)
	case ssa.OpAMD64LEAQ, ssa.OpAMD64LEAL, ssa.OpAMD64LEAW:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpAMD64CMPQ, ssa.OpAMD64CMPL, ssa.OpAMD64CMPW, ssa.OpAMD64CMPB,
		ssa.OpAMD64TESTQ, ssa.OpAMD64TESTL, ssa.OpAMD64TESTW, ssa.OpAMD64TESTB,
		ssa.OpAMD64BTL, ssa.OpAMD64BTQ:
		opregreg(s, v.Op.Asm(), v.Args[1].Reg(), v.Args[0].Reg())
	case ssa.OpAMD64UCOMISS, ssa.OpAMD64UCOMISD:
		// Go assembler has swapped operands for UCOMISx relative to CMP,
		// must account for that right here.
		opregreg(s, v.Op.Asm(), v.Args[0].Reg(), v.Args[1].Reg())
	case ssa.OpAMD64CMPQconst, ssa.OpAMD64CMPLconst, ssa.OpAMD64CMPWconst, ssa.OpAMD64CMPBconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_CONST
		p.To.Offset = v.AuxInt
	case ssa.OpAMD64BTLconst, ssa.OpAMD64BTQconst,
		ssa.OpAMD64TESTQconst, ssa.OpAMD64TESTLconst, ssa.OpAMD64TESTWconst, ssa.OpAMD64TESTBconst,
		ssa.OpAMD64BTSQconst,
		ssa.OpAMD64BTCQconst,
		ssa.OpAMD64BTRQconst:
		op := v.Op
		if op == ssa.OpAMD64BTQconst && v.AuxInt < 32 {
			// Emit 32-bit version because it's shorter
			op = ssa.OpAMD64BTLconst
		}
		p := s.Prog(op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Args[0].Reg()
	case ssa.OpAMD64CMPQload, ssa.OpAMD64CMPLload, ssa.OpAMD64CMPWload, ssa.OpAMD64CMPBload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Args[1].Reg()
	case ssa.OpAMD64CMPQconstload, ssa.OpAMD64CMPLconstload, ssa.OpAMD64CMPWconstload, ssa.OpAMD64CMPBconstload:
		sc := v.AuxValAndOff()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux2(&p.From, v, sc.Off64())
		p.To.Type = obj.TYPE_CONST
		p.To.Offset = sc.Val64()
	case ssa.OpAMD64CMPQloadidx8, ssa.OpAMD64CMPQloadidx1, ssa.OpAMD64CMPLloadidx4, ssa.OpAMD64CMPLloadidx1, ssa.OpAMD64CMPWloadidx2, ssa.OpAMD64CMPWloadidx1, ssa.OpAMD64CMPBloadidx1:
		p := s.Prog(v.Op.Asm())
		memIdx(&p.From, v)
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Args[2].Reg()
	case ssa.OpAMD64CMPQconstloadidx8, ssa.OpAMD64CMPQconstloadidx1, ssa.OpAMD64CMPLconstloadidx4, ssa.OpAMD64CMPLconstloadidx1, ssa.OpAMD64CMPWconstloadidx2, ssa.OpAMD64CMPWconstloadidx1, ssa.OpAMD64CMPBconstloadidx1:
		sc := v.AuxValAndOff()
		p := s.Prog(v.Op.Asm())
		memIdx(&p.From, v)
		ssagen.AddAux2(&p.From, v, sc.Off64())
		p.To.Type = obj.TYPE_CONST
		p.To.Offset = sc.Val64()
	case ssa.OpAMD64MOVLconst, ssa.OpAMD64MOVQconst:
		x := v.Reg()

		// If flags aren't live (indicated by v.Aux == nil),
		// then we can rewrite MOV $0, AX into XOR AX, AX.
		if v.AuxInt == 0 && v.Aux == nil {
			opregreg(s, x86.AXORL, x, x)
			break
		}

		asm := v.Op.Asm()
		// Use MOVL to move a small constant into a register
		// when the constant is positive and fits into 32 bits.
		if 0 <= v.AuxInt && v.AuxInt <= (1<<32-1) {
			// The upper 32bit are zeroed automatically when using MOVL.
			asm = x86.AMOVL
		}
		p := s.Prog(asm)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = x
	case ssa.OpAMD64MOVSSconst, ssa.OpAMD64MOVSDconst:
		x := v.Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_FCONST
		p.From.Val = math.Float64frombits(uint64(v.AuxInt))
		p.To.Type = obj.TYPE_REG
		p.To.Reg = x
	case ssa.OpAMD64MOVQload, ssa.OpAMD64MOVLload, ssa.OpAMD64MOVWload, ssa.OpAMD64MOVBload, ssa.OpAMD64MOVOload,
		ssa.OpAMD64MOVSSload, ssa.OpAMD64MOVSDload, ssa.OpAMD64MOVBQSXload, ssa.OpAMD64MOVWQSXload, ssa.OpAMD64MOVLQSXload,
		ssa.OpAMD64MOVBEQload, ssa.OpAMD64MOVBELload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpAMD64MOVBloadidx1, ssa.OpAMD64MOVWloadidx1, ssa.OpAMD64MOVLloadidx1, ssa.OpAMD64MOVQloadidx1, ssa.OpAMD64MOVSSloadidx1, ssa.OpAMD64MOVSDloadidx1,
		ssa.OpAMD64MOVQloadidx8, ssa.OpAMD64MOVSDloadidx8, ssa.OpAMD64MOVLloadidx8, ssa.OpAMD64MOVLloadidx4, ssa.OpAMD64MOVSSloadidx4, ssa.OpAMD64MOVWloadidx2,
		ssa.OpAMD64MOVBELloadidx1, ssa.OpAMD64MOVBELloadidx4, ssa.OpAMD64MOVBELloadidx8, ssa.OpAMD64MOVBEQloadidx1, ssa.OpAMD64MOVBEQloadidx8:
		p := s.Prog(v.Op.Asm())
		memIdx(&p.From, v)
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpAMD64MOVQstore, ssa.OpAMD64MOVSSstore, ssa.OpAMD64MOVSDstore, ssa.OpAMD64MOVLstore, ssa.OpAMD64MOVWstore, ssa.OpAMD64MOVBstore, ssa.OpAMD64MOVOstore,
		ssa.OpAMD64ADDQmodify, ssa.OpAMD64SUBQmodify, ssa.OpAMD64ANDQmodify, ssa.OpAMD64ORQmodify, ssa.OpAMD64XORQmodify,
		ssa.OpAMD64ADDLmodify, ssa.OpAMD64SUBLmodify, ssa.OpAMD64ANDLmodify, ssa.OpAMD64ORLmodify, ssa.OpAMD64XORLmodify,
		ssa.OpAMD64MOVBEQstore, ssa.OpAMD64MOVBELstore, ssa.OpAMD64MOVBEWstore:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpAMD64MOVBstoreidx1, ssa.OpAMD64MOVWstoreidx1, ssa.OpAMD64MOVLstoreidx1, ssa.OpAMD64MOVQstoreidx1, ssa.OpAMD64MOVSSstoreidx1, ssa.OpAMD64MOVSDstoreidx1,
		ssa.OpAMD64MOVQstoreidx8, ssa.OpAMD64MOVSDstoreidx8, ssa.OpAMD64MOVLstoreidx8, ssa.OpAMD64MOVSSstoreidx4, ssa.OpAMD64MOVLstoreidx4, ssa.OpAMD64MOVWstoreidx2,
		ssa.OpAMD64ADDLmodifyidx1, ssa.OpAMD64ADDLmodifyidx4, ssa.OpAMD64ADDLmodifyidx8, ssa.OpAMD64ADDQmodifyidx1, ssa.OpAMD64ADDQmodifyidx8,
		ssa.OpAMD64SUBLmodifyidx1, ssa.OpAMD64SUBLmodifyidx4, ssa.OpAMD64SUBLmodifyidx8, ssa.OpAMD64SUBQmodifyidx1, ssa.OpAMD64SUBQmodifyidx8,
		ssa.OpAMD64ANDLmodifyidx1, ssa.OpAMD64ANDLmodifyidx4, ssa.OpAMD64ANDLmodifyidx8, ssa.OpAMD64ANDQmodifyidx1, ssa.OpAMD64ANDQmodifyidx8,
		ssa.OpAMD64ORLmodifyidx1, ssa.OpAMD64ORLmodifyidx4, ssa.OpAMD64ORLmodifyidx8, ssa.OpAMD64ORQmodifyidx1, ssa.OpAMD64ORQmodifyidx8,
		ssa.OpAMD64XORLmodifyidx1, ssa.OpAMD64XORLmodifyidx4, ssa.OpAMD64XORLmodifyidx8, ssa.OpAMD64XORQmodifyidx1, ssa.OpAMD64XORQmodifyidx8,
		ssa.OpAMD64MOVBEWstoreidx1, ssa.OpAMD64MOVBEWstoreidx2, ssa.OpAMD64MOVBELstoreidx1, ssa.OpAMD64MOVBELstoreidx4, ssa.OpAMD64MOVBELstoreidx8, ssa.OpAMD64MOVBEQstoreidx1, ssa.OpAMD64MOVBEQstoreidx8:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[2].Reg()
		memIdx(&p.To, v)
		ssagen.AddAux(&p.To, v)
	case ssa.OpAMD64ADDQconstmodify, ssa.OpAMD64ADDLconstmodify:
		sc := v.AuxValAndOff()
		off := sc.Off64()
		val := sc.Val()
		if val == 1 || val == -1 {
			var asm obj.As
			if v.Op == ssa.OpAMD64ADDQconstmodify {
				if val == 1 {
					asm = x86.AINCQ
				} else {
					asm = x86.ADECQ
				}
			} else {
				if val == 1 {
					asm = x86.AINCL
				} else {
					asm = x86.ADECL
				}
			}
			p := s.Prog(asm)
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()
			ssagen.AddAux2(&p.To, v, off)
			break
		}
		fallthrough
	case ssa.OpAMD64ANDQconstmodify, ssa.OpAMD64ANDLconstmodify, ssa.OpAMD64ORQconstmodify, ssa.OpAMD64ORLconstmodify,
		ssa.OpAMD64XORQconstmodify, ssa.OpAMD64XORLconstmodify,
		ssa.OpAMD64BTSQconstmodify, ssa.OpAMD64BTRQconstmodify, ssa.OpAMD64BTCQconstmodify:
		sc := v.AuxValAndOff()
		off := sc.Off64()
		val := sc.Val64()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = val
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux2(&p.To, v, off)

	case ssa.OpAMD64MOVQstoreconst, ssa.OpAMD64MOVLstoreconst, ssa.OpAMD64MOVWstoreconst, ssa.OpAMD64MOVBstoreconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		sc := v.AuxValAndOff()
		p.From.Offset = sc.Val64()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux2(&p.To, v, sc.Off64())
	case ssa.OpAMD64MOVOstoreconst:
		sc := v.AuxValAndOff()
		if sc.Val() != 0 {
			v.Fatalf("MOVO for non zero constants not implemented: %s", v.LongString())
		}

		if s.ABI != obj.ABIInternal {
			// zero X15 manually
			opregreg(s, x86.AXORPS, x86.REG_X15, x86.REG_X15)
		}
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = x86.REG_X15
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux2(&p.To, v, sc.Off64())

	case ssa.OpAMD64MOVQstoreconstidx1, ssa.OpAMD64MOVQstoreconstidx8, ssa.OpAMD64MOVLstoreconstidx1, ssa.OpAMD64MOVLstoreconstidx4, ssa.OpAMD64MOVWstoreconstidx1, ssa.OpAMD64MOVWstoreconstidx2, ssa.OpAMD64MOVBstoreconstidx1,
		ssa.OpAMD64ADDLconstmodifyidx1, ssa.OpAMD64ADDLconstmodifyidx4, ssa.OpAMD64ADDLconstmodifyidx8, ssa.OpAMD64ADDQconstmodifyidx1, ssa.OpAMD64ADDQconstmodifyidx8,
		ssa.OpAMD64ANDLconstmodifyidx1, ssa.OpAMD64ANDLconstmodifyidx4, ssa.OpAMD64ANDLconstmodifyidx8, ssa.OpAMD64ANDQconstmodifyidx1, ssa.OpAMD64ANDQconstmodifyidx8,
		ssa.OpAMD64ORLconstmodifyidx1, ssa.OpAMD64ORLconstmodifyidx4, ssa.OpAMD64ORLconstmodifyidx8, ssa.OpAMD64ORQconstmodifyidx1, ssa.OpAMD64ORQconstmodifyidx8,
		ssa.OpAMD64XORLconstmodifyidx1, ssa.OpAMD64XORLconstmodifyidx4, ssa.OpAMD64XORLconstmodifyidx8, ssa.OpAMD64XORQconstmodifyidx1, ssa.OpAMD64XORQconstmodifyidx8:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		sc := v.AuxValAndOff()
		p.From.Offset = sc.Val64()
		switch {
		case p.As == x86.AADDQ && p.From.Offset == 1:
			p.As = x86.AINCQ
			p.From.Type = obj.TYPE_NONE
		case p.As == x86.AADDQ && p.From.Offset == -1:
			p.As = x86.ADECQ
			p.From.Type = obj.TYPE_NONE
		case p.As == x86.AADDL && p.From.Offset == 1:
			p.As = x86.AINCL
			p.From.Type = obj.TYPE_NONE
		case p.As == x86.AADDL && p.From.Offset == -1:
			p.As = x86.ADECL
			p.From.Type = obj.TYPE_NONE
		}
		memIdx(&p.To, v)
		ssagen.AddAux2(&p.To, v, sc.Off64())
	case ssa.OpAMD64MOVLQSX, ssa.OpAMD64MOVWQSX, ssa.OpAMD64MOVBQSX, ssa.OpAMD64MOVLQZX, ssa.OpAMD64MOVWQZX, ssa.OpAMD64MOVBQZX,
		ssa.OpAMD64CVTTSS2SL, ssa.OpAMD64CVTTSD2SL, ssa.OpAMD64CVTTSS2SQ, ssa.OpAMD64CVTTSD2SQ,
		ssa.OpAMD64CVTSS2SD, ssa.OpAMD64CVTSD2SS, ssa.OpAMD64VPBROADCASTB, ssa.OpAMD64PMOVMSKB:
		opregreg(s, v.Op.Asm(), v.Reg(), v.Args[0].Reg())
	case ssa.OpAMD64CVTSL2SD, ssa.OpAMD64CVTSQ2SD, ssa.OpAMD64CVTSQ2SS, ssa.OpAMD64CVTSL2SS:
		r := v.Reg()
		// Break false dependency on destination register.
		opregreg(s, x86.AXORPS, r, r)
		opregreg(s, v.Op.Asm(), r, v.Args[0].Reg())
	case ssa.OpAMD64MOVQi2f, ssa.OpAMD64MOVQf2i, ssa.OpAMD64MOVLi2f, ssa.OpAMD64MOVLf2i:
		var p *obj.Prog
		switch v.Op {
		case ssa.OpAMD64MOVQi2f, ssa.OpAMD64MOVQf2i:
			p = s.Prog(x86.AMOVQ)
		case ssa.OpAMD64MOVLi2f, ssa.OpAMD64MOVLf2i:
			p = s.Prog(x86.AMOVL)
		}
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpAMD64ADDQload, ssa.OpAMD64ADDLload, ssa.OpAMD64SUBQload, ssa.OpAMD64SUBLload,
		ssa.OpAMD64ANDQload, ssa.OpAMD64ANDLload, ssa.OpAMD64ORQload, ssa.OpAMD64ORLload,
		ssa.OpAMD64XORQload, ssa.OpAMD64XORLload, ssa.OpAMD64ADDSDload, ssa.OpAMD64ADDSSload,
		ssa.OpAMD64SUBSDload, ssa.OpAMD64SUBSSload, ssa.OpAMD64MULSDload, ssa.OpAMD64MULSSload,
		ssa.OpAMD64DIVSDload, ssa.OpAMD64DIVSSload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[1].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpAMD64ADDLloadidx1, ssa.OpAMD64ADDLloadidx4, ssa.OpAMD64ADDLloadidx8, ssa.OpAMD64ADDQloadidx1, ssa.OpAMD64ADDQloadidx8,
		ssa.OpAMD64SUBLloadidx1, ssa.OpAMD64SUBLloadidx4, ssa.OpAMD64SUBLloadidx8, ssa.OpAMD64SUBQloadidx1, ssa.OpAMD64SUBQloadidx8,
		ssa.OpAMD64ANDLloadidx1, ssa.OpAMD64ANDLloadidx4, ssa.OpAMD64ANDLloadidx8, ssa.OpAMD64ANDQloadidx1, ssa.OpAMD64ANDQloadidx8,
		ssa.OpAMD64ORLloadidx1, ssa.OpAMD64ORLloadidx4, ssa.OpAMD64ORLloadidx8, ssa.OpAMD64ORQloadidx1, ssa.OpAMD64ORQloadidx8,
		ssa.OpAMD64XORLloadidx1, ssa.OpAMD64XORLloadidx4, ssa.OpAMD64XORLloadidx8, ssa.OpAMD64XORQloadidx1, ssa.OpAMD64XORQloadidx8,
		ssa.OpAMD64ADDSSloadidx1, ssa.OpAMD64ADDSSloadidx4, ssa.OpAMD64ADDSDloadidx1, ssa.OpAMD64ADDSDloadidx8,
		ssa.OpAMD64SUBSSloadidx1, ssa.OpAMD64SUBSSloadidx4, ssa.OpAMD64SUBSDloadidx1, ssa.OpAMD64SUBSDloadidx8,
		ssa.OpAMD64MULSSloadidx1, ssa.OpAMD64MULSSloadidx4, ssa.OpAMD64MULSDloadidx1, ssa.OpAMD64MULSDloadidx8,
		ssa.OpAMD64DIVSSloadidx1, ssa.OpAMD64DIVSSloadidx4, ssa.OpAMD64DIVSDloadidx1, ssa.OpAMD64DIVSDloadidx8:
		p := s.Prog(v.Op.Asm())

		r, i := v.Args[1].Reg(), v.Args[2].Reg()
		p.From.Type = obj.TYPE_MEM
		p.From.Scale = v.Op.Scale()
		if p.From.Scale == 1 && i == x86.REG_SP {
			r, i = i, r
		}
		p.From.Reg = r
		p.From.Index = i

		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpAMD64DUFFZERO:
		if s.ABI != obj.ABIInternal {
			// zero X15 manually
			opregreg(s, x86.AXORPS, x86.REG_X15, x86.REG_X15)
		}
		off := duffStart(v.AuxInt)
		adj := duffAdj(v.AuxInt)
		var p *obj.Prog
		if adj != 0 {
			p = s.Prog(x86.ALEAQ)
			p.From.Type = obj.TYPE_MEM
			p.From.Offset = adj
			p.From.Reg = x86.REG_DI
			p.To.Type = obj.TYPE_REG
			p.To.Reg = x86.REG_DI
		}
		p = s.Prog(obj.ADUFFZERO)
		p.To.Type = obj.TYPE_ADDR
		p.To.Sym = ir.Syms.Duffzero
		p.To.Offset = off
	case ssa.OpAMD64DUFFCOPY:
		p := s.Prog(obj.ADUFFCOPY)
		p.To.Type = obj.TYPE_ADDR
		p.To.Sym = ir.Syms.Duffcopy
		if v.AuxInt%16 != 0 {
			v.Fatalf("bad DUFFCOPY AuxInt %v", v.AuxInt)
		}
		p.To.Offset = 14 * (64 - v.AuxInt/16)
		// 14 and 64 are magic constants.  14 is the number of bytes to encode:
		//	MOVUPS	(SI), X0
		//	ADDQ	$16, SI
		//	MOVUPS	X0, (DI)
		//	ADDQ	$16, DI
		// and 64 is the number of such blocks. See src/runtime/duff_amd64.s:duffcopy.

	case ssa.OpCopy: // TODO: use MOVQreg for reg->reg copies instead of OpCopy?
		if v.Type.IsMemory() {
			return
		}
		x := v.Args[0].Reg()
		y := v.Reg()
		if x != y {
			opregreg(s, moveByType(v.Type), y, x)
		}
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
	case ssa.OpAMD64LoweredHasCPUFeature:
		p := s.Prog(x86.AMOVBLZX)
		p.From.Type = obj.TYPE_MEM
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpArgIntReg, ssa.OpArgFloatReg:
		// The assembler needs to wrap the entry safepoint/stack growth code with spill/unspill
		// The loop only runs once.
		for _, ap := range v.Block.Func.RegArgs {
			// Pass the spill/unspill information along to the assembler, offset by size of return PC pushed on stack.
			addr := ssagen.SpillSlotAddr(ap, x86.REG_SP, v.Block.Func.Config.PtrSize)
			s.FuncInfo().AddSpill(
				obj.RegSpill{Reg: ap.Reg, Addr: addr, Unspill: loadByType(ap.Type), Spill: storeByType(ap.Type)})
		}
		v.Block.Func.RegArgs = nil
		ssagen.CheckArgReg(v)
	case ssa.OpAMD64LoweredGetClosurePtr:
		// Closure pointer is DX.
		ssagen.CheckLoweredGetClosurePtr(v)
	case ssa.OpAMD64LoweredGetG:
		if s.ABI == obj.ABIInternal {
			v.Fatalf("LoweredGetG should not appear in ABIInternal")
		}
		r := v.Reg()
		getgFromTLS(s, r)
	case ssa.OpAMD64CALLstatic, ssa.OpAMD64CALLtail:
		if s.ABI == obj.ABI0 && v.Aux.(*ssa.AuxCall).Fn.ABI() == obj.ABIInternal {
			// zeroing X15 when entering ABIInternal from ABI0
			if buildcfg.GOOS != "plan9" { // do not use SSE on Plan 9
				opregreg(s, x86.AXORPS, x86.REG_X15, x86.REG_X15)
			}
			// set G register from TLS
			getgFromTLS(s, x86.REG_R14)
		}
		if v.Op == ssa.OpAMD64CALLtail {
			s.TailCall(v)
			break
		}
		s.Call(v)
		if s.ABI == obj.ABIInternal && v.Aux.(*ssa.AuxCall).Fn.ABI() == obj.ABI0 {
			// zeroing X15 when entering ABIInternal from ABI0
			if buildcfg.GOOS != "plan9" { // do not use SSE on Plan 9
				opregreg(s, x86.AXORPS, x86.REG_X15, x86.REG_X15)
			}
			// set G register from TLS
			getgFromTLS(s, x86.REG_R14)
		}
	case ssa.OpAMD64CALLclosure, ssa.OpAMD64CALLinter:
		s.Call(v)

	case ssa.OpAMD64LoweredGetCallerPC:
		p := s.Prog(x86.AMOVQ)
		p.From.Type = obj.TYPE_MEM
		p.From.Offset = -8 // PC is stored 8 bytes below first parameter.
		p.From.Name = obj.NAME_PARAM
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpAMD64LoweredGetCallerSP:
		// caller's SP is the address of the first arg
		mov := x86.AMOVQ
		if types.PtrSize == 4 {
			mov = x86.AMOVL
		}
		p := s.Prog(mov)
		p.From.Type = obj.TYPE_ADDR
		p.From.Offset = -base.Ctxt.Arch.FixedFrameSize // 0 on amd64, just to be consistent with other architectures
		p.From.Name = obj.NAME_PARAM
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpAMD64LoweredWB:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		// AuxInt encodes how many buffer entries we need.
		p.To.Sym = ir.Syms.GCWriteBarrier[v.AuxInt-1]

	case ssa.OpAMD64LoweredPanicBoundsA, ssa.OpAMD64LoweredPanicBoundsB, ssa.OpAMD64LoweredPanicBoundsC:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ssagen.BoundsCheckFunc[v.AuxInt]
		s.UseArgs(int64(2 * types.PtrSize)) // space used in callee args area by assembly stubs

	case ssa.OpAMD64NEGQ, ssa.OpAMD64NEGL,
		ssa.OpAMD64BSWAPQ, ssa.OpAMD64BSWAPL,
		ssa.OpAMD64NOTQ, ssa.OpAMD64NOTL:
		p := s.Prog(v.Op.Asm())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpAMD64NEGLflags:
		p := s.Prog(v.Op.Asm())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

	case ssa.OpAMD64BSFQ, ssa.OpAMD64BSRQ, ssa.OpAMD64BSFL, ssa.OpAMD64BSRL, ssa.OpAMD64SQRTSD, ssa.OpAMD64SQRTSS:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		switch v.Op {
		case ssa.OpAMD64BSFQ, ssa.OpAMD64BSRQ:
			p.To.Reg = v.Reg0()
		case ssa.OpAMD64BSFL, ssa.OpAMD64BSRL, ssa.OpAMD64SQRTSD, ssa.OpAMD64SQRTSS:
			p.To.Reg = v.Reg()
		}
	case ssa.OpAMD64ROUNDSD:
		p := s.Prog(v.Op.Asm())
		val := v.AuxInt
		// 0 means math.RoundToEven, 1 Floor, 2 Ceil, 3 Trunc
		if val < 0 || val > 3 {
			v.Fatalf("Invalid rounding mode")
		}
		p.From.Offset = val
		p.From.Type = obj.TYPE_CONST
		p.AddRestSourceReg(v.Args[0].Reg())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpAMD64POPCNTQ, ssa.OpAMD64POPCNTL,
		ssa.OpAMD64TZCNTQ, ssa.OpAMD64TZCNTL,
		ssa.OpAMD64LZCNTQ, ssa.OpAMD64LZCNTL:
		if v.Args[0].Reg() != v.Reg() {
			// POPCNT/TZCNT/LZCNT have a false dependency on the destination register on Intel cpus.
			// TZCNT/LZCNT problem affects pre-Skylake models. See discussion at https://gcc.gnu.org/bugzilla/show_bug.cgi?id=62011#c7.
			// Xor register with itself to break the dependency.
			opregreg(s, x86.AXORL, v.Reg(), v.Reg())
		}
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpAMD64SETEQ, ssa.OpAMD64SETNE,
		ssa.OpAMD64SETL, ssa.OpAMD64SETLE,
		ssa.OpAMD64SETG, ssa.OpAMD64SETGE,
		ssa.OpAMD64SETGF, ssa.OpAMD64SETGEF,
		ssa.OpAMD64SETB, ssa.OpAMD64SETBE,
		ssa.OpAMD64SETORD, ssa.OpAMD64SETNAN,
		ssa.OpAMD64SETA, ssa.OpAMD64SETAE,
		ssa.OpAMD64SETO:
		p := s.Prog(v.Op.Asm())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpAMD64SETEQstore, ssa.OpAMD64SETNEstore,
		ssa.OpAMD64SETLstore, ssa.OpAMD64SETLEstore,
		ssa.OpAMD64SETGstore, ssa.OpAMD64SETGEstore,
		ssa.OpAMD64SETBstore, ssa.OpAMD64SETBEstore,
		ssa.OpAMD64SETAstore, ssa.OpAMD64SETAEstore:
		p := s.Prog(v.Op.Asm())
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)

	case ssa.OpAMD64SETEQstoreidx1, ssa.OpAMD64SETNEstoreidx1,
		ssa.OpAMD64SETLstoreidx1, ssa.OpAMD64SETLEstoreidx1,
		ssa.OpAMD64SETGstoreidx1, ssa.OpAMD64SETGEstoreidx1,
		ssa.OpAMD64SETBstoreidx1, ssa.OpAMD64SETBEstoreidx1,
		ssa.OpAMD64SETAstoreidx1, ssa.OpAMD64SETAEstoreidx1:
		p := s.Prog(v.Op.Asm())
		memIdx(&p.To, v)
		ssagen.AddAux(&p.To, v)

	case ssa.OpAMD64SETNEF:
		t := v.RegTmp()
		p := s.Prog(v.Op.Asm())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
		q := s.Prog(x86.ASETPS)
		q.To.Type = obj.TYPE_REG
		q.To.Reg = t
		// ORL avoids partial register write and is smaller than ORQ, used by old compiler
		opregreg(s, x86.AORL, v.Reg(), t)

	case ssa.OpAMD64SETEQF:
		t := v.RegTmp()
		p := s.Prog(v.Op.Asm())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
		q := s.Prog(x86.ASETPC)
		q.To.Type = obj.TYPE_REG
		q.To.Reg = t
		// ANDL avoids partial register write and is smaller than ANDQ, used by old compiler
		opregreg(s, x86.AANDL, v.Reg(), t)

	case ssa.OpAMD64InvertFlags:
		v.Fatalf("InvertFlags should never make it to codegen %v", v.LongString())
	case ssa.OpAMD64FlagEQ, ssa.OpAMD64FlagLT_ULT, ssa.OpAMD64FlagLT_UGT, ssa.OpAMD64FlagGT_ULT, ssa.OpAMD64FlagGT_UGT:
		v.Fatalf("Flag* ops should never make it to codegen %v", v.LongString())
	case ssa.OpAMD64AddTupleFirst32, ssa.OpAMD64AddTupleFirst64:
		v.Fatalf("AddTupleFirst* should never make it to codegen %v", v.LongString())
	case ssa.OpAMD64REPSTOSQ:
		s.Prog(x86.AREP)
		s.Prog(x86.ASTOSQ)
	case ssa.OpAMD64REPMOVSQ:
		s.Prog(x86.AREP)
		s.Prog(x86.AMOVSQ)
	case ssa.OpAMD64LoweredNilCheck:
		// Issue a load which will fault if the input is nil.
		// TODO: We currently use the 2-byte instruction TESTB AX, (reg).
		// Should we use the 3-byte TESTB $0, (reg) instead? It is larger
		// but it doesn't have false dependency on AX.
		// Or maybe allocate an output register and use MOVL (reg),reg2 ?
		// That trades clobbering flags for clobbering a register.
		p := s.Prog(x86.ATESTB)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = x86.REG_AX
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		if logopt.Enabled() {
			logopt.LogOpt(v.Pos, "nilcheck", "genssa", v.Block.Func.Name)
		}
		if base.Debug.Nil != 0 && v.Pos.Line() > 1 { // v.Pos.Line()==1 in generated wrappers
			base.WarnfAt(v.Pos, "generated nil check")
		}
	case ssa.OpAMD64MOVBatomicload, ssa.OpAMD64MOVLatomicload, ssa.OpAMD64MOVQatomicload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
	case ssa.OpAMD64XCHGB, ssa.OpAMD64XCHGL, ssa.OpAMD64XCHGQ:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Reg0()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[1].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpAMD64XADDLlock, ssa.OpAMD64XADDQlock:
		s.Prog(x86.ALOCK)
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Reg0()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[1].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpAMD64CMPXCHGLlock, ssa.OpAMD64CMPXCHGQlock:
		if v.Args[1].Reg() != x86.REG_AX {
			v.Fatalf("input[1] not in AX %s", v.LongString())
		}
		s.Prog(x86.ALOCK)
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[2].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
		p = s.Prog(x86.ASETEQ)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
	case ssa.OpAMD64ANDBlock, ssa.OpAMD64ANDLlock, ssa.OpAMD64ANDQlock, ssa.OpAMD64ORBlock, ssa.OpAMD64ORLlock, ssa.OpAMD64ORQlock:
		// Atomic memory operations that don't need to return the old value.
		s.Prog(x86.ALOCK)
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)
	case ssa.OpAMD64LoweredAtomicAnd64, ssa.OpAMD64LoweredAtomicOr64, ssa.OpAMD64LoweredAtomicAnd32, ssa.OpAMD64LoweredAtomicOr32:
		// Atomic memory operations that need to return the old value.
		// We need to do these with compare-and-exchange to get access to the old value.
		// loop:
		// MOVQ mask, tmp
		// MOVQ (addr), AX
		// ANDQ AX, tmp
		// LOCK CMPXCHGQ tmp, (addr) : note that AX is implicit old value to compare against
		// JNE loop
		// : result in AX
		mov := x86.AMOVQ
		op := x86.AANDQ
		cmpxchg := x86.ACMPXCHGQ
		switch v.Op {
		case ssa.OpAMD64LoweredAtomicOr64:
			op = x86.AORQ
		case ssa.OpAMD64LoweredAtomicAnd32:
			mov = x86.AMOVL
			op = x86.AANDL
			cmpxchg = x86.ACMPXCHGL
		case ssa.OpAMD64LoweredAtomicOr32:
			mov = x86.AMOVL
			op = x86.AORL
			cmpxchg = x86.ACMPXCHGL
		}
		addr := v.Args[0].Reg()
		mask := v.Args[1].Reg()
		tmp := v.RegTmp()
		p1 := s.Prog(mov)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = mask
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = tmp
		p2 := s.Prog(mov)
		p2.From.Type = obj.TYPE_MEM
		p2.From.Reg = addr
		ssagen.AddAux(&p2.From, v)
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = x86.REG_AX
		p3 := s.Prog(op)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = x86.REG_AX
		p3.To.Type = obj.TYPE_REG
		p3.To.Reg = tmp
		s.Prog(x86.ALOCK)
		p5 := s.Prog(cmpxchg)
		p5.From.Type = obj.TYPE_REG
		p5.From.Reg = tmp
		p5.To.Type = obj.TYPE_MEM
		p5.To.Reg = addr
		ssagen.AddAux(&p5.To, v)
		p6 := s.Prog(x86.AJNE)
		p6.To.Type = obj.TYPE_BRANCH
		p6.To.SetTarget(p1)
	case ssa.OpAMD64PrefetchT0, ssa.OpAMD64PrefetchNTA:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
	case ssa.OpClobber:
		p := s.Prog(x86.AMOVL)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 0xdeaddead
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = x86.REG_SP
		ssagen.AddAux(&p.To, v)
		p = s.Prog(x86.AMOVL)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 0xdeaddead
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = x86.REG_SP
		ssagen.AddAux(&p.To, v)
		p.To.Offset += 4
	case ssa.OpClobberReg:
		x := uint64(0xdeaddeaddeaddead)
		p := s.Prog(x86.AMOVQ)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = int64(x)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	default:
		v.Fatalf("genValue not implemented: %s", v.LongString())
	}
}

var blockJump = [...]struct {
	asm, invasm obj.As
}{
	ssa.BlockAMD64EQ:  {x86.AJEQ, x86.AJNE},
	ssa.BlockAMD64NE:  {x86.AJNE, x86.AJEQ},
	ssa.BlockAMD64LT:  {x86.AJLT, x86.AJGE},
	ssa.BlockAMD64GE:  {x86.AJGE, x86.AJLT},
	ssa.BlockAMD64LE:  {x86.AJLE, x86.AJGT},
	ssa.BlockAMD64GT:  {x86.AJGT, x86.AJLE},
	ssa.BlockAMD64OS:  {x86.AJOS, x86.AJOC},
	ssa.BlockAMD64OC:  {x86.AJOC, x86.AJOS},
	ssa.BlockAMD64ULT: {x86.AJCS, x86.AJCC},
	ssa.BlockAMD64UGE: {x86.AJCC, x86.AJCS},
	ssa.BlockAMD64UGT: {x86.AJHI, x86.AJLS},
	ssa.BlockAMD64ULE: {x86.AJLS, x86.AJHI},
	ssa.BlockAMD64ORD: {x86.AJPC, x86.AJPS},
	ssa.BlockAMD64NAN: {x86.AJPS, x86.AJPC},
}

var eqfJumps = [2][2]ssagen.IndexJump{
	{{Jump: x86.AJNE, Index: 1}, {Jump: x86.AJPS, Index: 1}}, // next == b.Succs[0]
	{{Jump: x86.AJNE, Index: 1}, {Jump: x86.AJPC, Index: 0}}, // next == b.Succs[1]
}
var nefJumps = [2][2]ssagen.IndexJump{
	{{Jump: x86.AJNE, Index: 0}, {Jump: x86.AJPC, Index: 1}}, // next == b.Succs[0]
	{{Jump: x86.AJNE, Index: 0}, {Jump: x86.AJPS, Index: 0}}, // next == b.Succs[1]
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
		// defer returns in rax:
		// 0 if we should continue executing
		// 1 if we should jump to deferreturn call
		p := s.Prog(x86.ATESTL)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = x86.REG_AX
		p.To.Type = obj.TYPE_REG
		p.To.Reg = x86.REG_AX
		p = s.Prog(x86.AJNE)
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

	case ssa.BlockAMD64EQF:
		s.CombJump(b, next, &eqfJumps)

	case ssa.BlockAMD64NEF:
		s.CombJump(b, next, &nefJumps)

	case ssa.BlockAMD64EQ, ssa.BlockAMD64NE,
		ssa.BlockAMD64LT, ssa.BlockAMD64GE,
		ssa.BlockAMD64LE, ssa.BlockAMD64GT,
		ssa.BlockAMD64OS, ssa.BlockAMD64OC,
		ssa.BlockAMD64ULT, ssa.BlockAMD64UGT,
		ssa.BlockAMD64ULE, ssa.BlockAMD64UGE:
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

	case ssa.BlockAMD64JUMPTABLE:
		// JMP      *(TABLE)(INDEX*8)
		p := s.Prog(obj.AJMP)
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = b.Controls[1].Reg()
		p.To.Index = b.Controls[0].Reg()
		p.To.Scale = 8
		// Save jump tables for later resolution of the target blocks.
		s.JumpTables = append(s.JumpTables, b)

	default:
		b.Fatalf("branch not implemented: %s", b.LongString())
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
```