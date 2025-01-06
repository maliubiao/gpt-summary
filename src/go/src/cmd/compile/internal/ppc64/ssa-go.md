Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - The Context:**

The first line `// go/src/cmd/compile/internal/ppc64/ssa.go` immediately tells us this code is part of the Go compiler, specifically for the PowerPC 64-bit architecture (`ppc64`). The `ssa.go` filename strongly suggests it's involved in the Static Single Assignment (SSA) intermediate representation used during compilation.

**2. High-Level Structure Scan:**

I'd quickly scan the file for key elements:

* **Package Declaration:** `package ppc64` confirms the architecture.
* **Imports:**  These hint at the functionalities. I see `cmd/compile/internal/ssa` (SSA representation), `cmd/compile/internal/ssagen` (SSA code generation), `cmd/internal/obj/ppc64` (PPC64 assembly instructions), `cmd/compile/internal/types` (Go type system). This reinforces the code generation aspect.
* **Function Definitions:** I'd list them out: `ssaMarkMoves`, `loadByType`, `storeByType`, `ssaGenValue`, `ssaGenBlock`, `loadRegResult`, `spillArgReg`. This gives a good overview of the modules within the file.

**3. Analyzing Individual Functions - Core Logic:**

Now, I'd go through each function, trying to understand its purpose:

* **`ssaMarkMoves`:** The name and the comment about `MOVXconst` and "clobbering flags" suggest this function identifies move constant operations that might interfere with CPU flags. The commented-out code hints at a previous implementation or alternative approach.
* **`loadByType`:**  The name and the `switch` statement on `t.Size()` and `t.IsFloat()` clearly indicate this function returns the correct assembly load instruction (`obj.As`) based on the Go type.
* **`storeByType`:** Similar to `loadByType`, but for store instructions.
* **`ssaGenValue`:** This looks like the heart of the code generation. The `switch` statement on `v.Op` (SSA operation) and the generation of assembly instructions using `s.Prog()` confirm this. I'd examine some key cases:
    * **`ssa.OpCopy`:** Simple register-to-register move.
    * **Atomic Operations (`LoweredAtomic...`)**:  The assembly sequences (LWSYNC, LDAR/LWAR, STBCCC/STWCCC, BNE) strongly suggest implementations of atomic operations using compare-and-swap loops.
    * **`LoweredGetClosurePtr`, `LoweredGetCallerSP`, `LoweredGetCallerPC`:**  These handle accessing runtime information.
    * **Arithmetic/Logical Operations (`OpPPC64ADD`, `OpPPC64AND`, etc.):** Straightforward mapping of SSA ops to PPC64 assembly.
    * **Memory Access (`MOVDload`, `MOVDstore`):**  The comments about alignment and the temporary register usage are important.
    * **Control Flow (`CALLstatic`, `CALLclosure`, `CALLinter`):**  How function calls are translated.
    * **Special Operations (`LoweredWB`, `LoweredPanicBounds`, `LoweredNilCheck`):** Interaction with the Go runtime.
* **`ssaGenBlock`:** This deals with generating assembly for control flow within SSA blocks (jumps, conditional branches, returns). The `blockJump` array is key here.
* **`loadRegResult`:**  Loads a value from the stack (auto frame) into a register, likely for function returns.
* **`spillArgReg`:** Stores a value from a register onto the stack, probably for function arguments or register spilling.

**4. Inferring Go Functionality (Connecting the Dots):**

Based on the functions and their assembly generation logic, I could infer:

* **Basic Arithmetic and Logic:**  The numerous `OpPPC64ADD`, `OpPPC64SUB`, `OpPPC64AND`, etc. cases indicate support for standard integer and floating-point operations.
* **Memory Operations:** `MOVDload`, `MOVDstore`, etc., represent loading and storing values from memory.
* **Function Calls:** `CALLstatic`, `CALLclosure`, `CALLinter` handle different types of function calls.
* **Atomic Operations:** The `LoweredAtomic...` cases show the implementation of atomic primitives needed for concurrency.
* **Runtime Interaction:** `LoweredWB` (write barrier), `LoweredPanicBounds` (bounds checking), `LoweredNilCheck` (nil pointer checks) demonstrate interaction with the Go runtime for garbage collection, safety, and error handling.
* **Control Flow:** `ssaGenBlock` shows how `if`, `else`, `for`, and other control structures are translated into branches.
* **Register Allocation and Spilling:** `spillArgReg` suggests register allocation and the need to spill registers to memory when they are exhausted.

**5. Code Examples and Assumptions:**

To provide concrete examples, I'd choose simple scenarios that map directly to the observed code:

* **Basic Arithmetic:**  `x + y` example translating to `ADD`.
* **Memory Load/Store:** Accessing an array element translating to `MOVDload` and `MOVDstore`.
* **Function Call:** A simple function call translating to `CALLstatic`.
* **Atomic Operation:** An example of incrementing a shared counter translating to the atomic add sequence.

When constructing examples, I'd make clear assumptions about input values and expected outputs to illustrate the code's behavior.

**6. Command-Line Arguments and Error Points:**

Since the code is part of the compiler's internal workings, it doesn't directly process command-line arguments in the typical sense. However, compiler flags (like optimization levels or architecture-specific settings) *indirectly* influence the SSA generation process and thus the code generated by these functions. I would explain this indirect influence.

For common mistakes, I'd focus on potential issues related to the compiler's internal logic that might be exposed to developers in more subtle ways (e.g., performance implications of unaligned memory access, the cost of atomic operations). Direct misuse of this low-level code is unlikely for most Go developers.

**7. Review and Refine:**

Finally, I'd review my analysis for clarity, accuracy, and completeness, ensuring that the explanations are easy to understand and supported by the code.

This structured approach, moving from high-level understanding to detailed analysis and then connecting the pieces to infer functionality and provide examples, helps in effectively dissecting and explaining complex compiler code like this.
这段代码是Go语言编译器的一部分，位于 `go/src/cmd/compile/internal/ppc64/ssa.go`，它专门负责将 Go 语言的 **静态单赋值 (SSA)** 中间表示转换为 **PowerPC 64位 (ppc64)** 架构的机器码指令。

让我们逐个功能进行列举和解释：

**1. `ssaMarkMoves(s *ssagen.State, b *ssa.Block)`:**

* **功能:**  这个函数用于标记那些需要避免影响 **标志位 (flags)** 的 `MOVXconst` 操作（即移动常量到寄存器的操作）。
* **原理:** 在某些情况下，紧随 `MOVXconst` 之后的操作可能依赖于之前指令设置的标志位。如果 `MOVXconst` 操作会修改这些标志位，就会导致错误。这个函数遍历基本块中的指令，如果发现一个 `MOVDconst` 指令并且当前的标志位是活跃的，它会将该指令的 `Aux` 字段设置为自身，作为一种标记。
* **为什么需要？**  PPC64 架构的某些指令会隐式地设置或使用条件码寄存器中的标志位。如果一个移动常量的操作不小心覆盖了这些标志位，可能会导致后续的条件跳转或条件选择指令的行为异常。
* **代码示例 (推断):** 假设有以下 SSA 代码：
   ```
   v1 = MOVDconst <int64> 10
   v2 = CMP <flags> v1, R0
   If v2 goto block2 else block3
   ```
   如果 `MOVDconst` 会影响标志位，那么 `CMP` 的结果可能不正确。`ssaMarkMoves` 的作用就是标记这样的 `MOVDconst`，以便在后续的指令生成阶段采取措施（例如，使用不会影响标志位的指令或插入额外的指令来保存和恢复标志位）。

**2. `loadByType(t *types.Type) obj.As`:**

* **功能:**  根据给定的 Go 语言类型 `t`，返回对应的 **PPC64 加载指令 (assembly instruction)**。
* **原理:**  通过 `switch` 语句判断类型 `t` 的大小和是否为浮点数或有符号数，返回相应的 PPC64 加载指令助记符（例如 `ppc64.AMOVB`, `ppc64.AMOVD`, `ppc64.AFMOVS` 等）。
* **代码示例:**
   ```go
   package main

   import (
       "fmt"
       "cmd/compile/internal/types"
       "cmd/internal/obj/ppc64"
   )

   func main() {
       intType := types.Types[types.TINT]
       float32Type := types.Types[types.TFLOAT32]

       fmt.Println(loadByType(intType) == ppc64.AMOVD)      // Output: true (假设 int 是 64 位)
       fmt.Println(loadByType(float32Type) == ppc64.AFMOVS) // Output: true
   }
   ```

**3. `storeByType(t *types.Type) obj.As`:**

* **功能:**  与 `loadByType` 类似，根据给定的 Go 语言类型 `t`，返回对应的 **PPC64 存储指令**。
* **原理:**  同样使用 `switch` 语句判断类型特性，返回相应的 PPC64 存储指令助记符。
* **代码示例:**
   ```go
   package main

   import (
       "fmt"
       "cmd/compile/internal/types"
       "cmd/internal/obj/ppc64"
   )

   func main() {
       boolType := types.Types[types.TBOOL]
       float64Type := types.Types[types.TFLOAT64]

       fmt.Println(storeByType(boolType) == ppc64.AMOVB)     // Output: true (假设 bool 是 1 字节)
       fmt.Println(storeByType(float64Type) == ppc64.AFMOVD) // Output: true
   }
   ```

**4. `ssaGenValue(s *ssagen.State, v *ssa.Value)`:**

* **功能:**  这是核心函数，负责将单个 SSA **值 (value)** `v` 转换为对应的 **PPC64 汇编指令序列**。
* **原理:**  使用一个巨大的 `switch` 语句，根据 SSA 值的操作码 `v.Op`，生成不同的汇编指令。每种操作码对应着不同的 PPC64 指令或指令序列。
* **涉及的 Go 语言功能实现 (通过 `ssaGenValue` 的 case 推断):**
    * **基本运算:**  加法 (`ssa.OpPPC64ADD`), 减法 (`ssa.OpPPC64SUB`), 乘法 (`ssa.OpPPC64MULLD`), 除法 (`ssa.OpPPC64DIVD`), 位运算 (`ssa.OpPPC64AND`, `ssa.OpPPC64OR`, `ssa.OpPPC64XOR`), 移位 (`ssa.OpPPC64SLD`, `ssa.OpPPC64SRD`) 等。
    * **常量加载:** (`ssa.OpPPC64MOVDconst`, `ssa.OpPPC64FMOVDconst`)
    * **内存加载和存储:** (`ssa.OpPPC64MOVDload`, `ssa.OpPPC64MOVDstore`)，包括不同大小和类型的加载存储。
    * **类型转换:** (`ssa.OpPPC64FCTIDZ`, `ssa.OpPPC64FCTIWZ`)
    * **函数调用:**  静态调用 (`ssa.OpPPC64CALLstatic`), 闭包调用 (`ssa.OpPPC64CALLclosure`), 接口调用 (`ssa.OpPPC64CALLinter`), 尾调用 (`ssa.OpPPC64CALLtail`)。
    * **原子操作:**  原子加 (`ssa.OpPPC64LoweredAtomicAdd32`, `ssa.OpPPC64LoweredAtomicAdd64`), 原子与/或 (`ssa.OpPPC64LoweredAtomicAnd8`, `ssa.OpPPC64LoweredAtomicOr32`), 原子交换 (`ssa.OpPPC64LoweredAtomicExchange8`), 原子加载/存储 (`ssa.OpPPC64LoweredAtomicLoad8`, `ssa.OpPPC64LoweredAtomicStore32`), 原子比较并交换 (`ssa.OpPPC64LoweredAtomicCas64`)。
    * **Goroutine 相关:** 获取 closure 指针 (`ssa.OpPPC64LoweredGetClosurePtr`), 获取调用者 SP/PC (`ssa.OpPPC64LoweredGetCallerSP`, `ssa.OpPPC64LoweredGetCallerPC`)。
    * **内存清零:** (`ssa.OpPPC64LoweredZero`, `ssa.OpPPC64LoweredQuadZero`)
    * **内存拷贝:** (`ssa.OpPPC64LoweredMove`, `ssa.OpPPC64LoweredQuadMove`)
    * **写屏障:** (`ssa.OpPPC64LoweredWB`)，用于垃圾回收。
    * **边界检查和 nil 检查:** (`ssa.OpPPC64LoweredPanicBoundsA`, `ssa.OpPPC64LoweredNilCheck`)。
    * **条件选择 (类似三元运算符):** (`ssa.OpPPC64ISEL`, `ssa.OpPPC64ISELZ`)
    * **设置条件码寄存器位:** (`ssa.OpPPC64SETBC`, `ssa.OpPPC64SETBCR`)
* **代码示例 (基于 `ssaGenValue` 中的 `ssa.OpPPC64ADD`):**
   假设有以下 SSA 值：
   ```
   v1 = Reg <int> R1
   v2 = Reg <int> R2
   v3 = Add <int> v1 v2
   ```
   `ssaGenValue` 会生成以下 PPC64 汇编指令：
   ```assembly
   ADD R2, R1, v3(R)  // 将 R1 + R2 的结果存入 v3 寄存器
   ```
   * **假设输入:** `v.Op == ssa.OpPPC64ADD`, `v.Args[0].Reg() == R1`, `v.Args[1].Reg() == R2`, `v.Reg() == v3`.
   * **输出 (生成的汇编指令):**  如上所示。

* **代码示例 (基于 `ssaGenValue` 中的 `ssa.OpPPC64MOVDload`):**
   假设有以下 SSA 值：
   ```
   p  = Reg <*int> R10
   v  = MOVDload <int> p+8
   ```
   `ssaGenValue` 会生成以下 PPC64 汇编指令：
   ```assembly
   MOVD 8(R10), v(R) // 从 R10 + 8 地址加载一个 64 位值到 v 寄存器
   ```
   * **假设输入:** `v.Op == ssa.OpPPC64MOVDload`, `v.Args[0].Reg() == R10`, `v.AuxInt == 8`, `v.Reg() == v`.
   * **输出 (生成的汇编指令):** 如上所示。

* **命令行参数:**  这个文件中的代码本身不直接处理命令行参数。它属于编译器的内部逻辑，由编译器的其他部分驱动。然而，编译器的命令行参数（例如 `-gcflags`, `-asmflags`）会影响整个编译过程，间接地影响到 SSA 的生成和这里的代码生成。例如，优化级别的不同可能会导致生成不同的 SSA 和不同的汇编指令。

* **使用者易犯错的点:**  普通 Go 开发者不会直接与这个文件中的代码交互。这是编译器内部实现细节。但是，理解编译器如何处理不同的 Go 语言结构，可以帮助开发者写出更高效的代码。例如，了解原子操作的实现方式可以帮助开发者更好地使用同步原语。对于编译器开发者来说，在添加新的 SSA 操作或修改现有操作的代码生成逻辑时，需要非常小心，确保生成的汇编代码的正确性和效率。例如，错误地处理标志位可能会导致难以调试的错误。

**5. `ssaGenBlock(s *ssagen.State, b, next *ssa.Block)`:**

* **功能:**  负责将 SSA **基本块 (block)** `b` 的控制流转换为 PPC64 的 **跳转指令**。
* **原理:**  根据基本块的类型 `b.Kind` (例如 `ssa.BlockPlain`, `ssa.BlockIf`, `ssa.BlockRet`)，生成相应的跳转指令。例如，`ssa.BlockPPC64EQ` 对应于条件相等跳转。
* **代码示例 (基于 `ssaGenBlock` 中的 `ssa.BlockPPC64EQ`):**
   假设一个基本块 `b` 的类型是 `ssa.BlockPPC64EQ`，它的后继块是 `succ0` 和 `succ1`。如果 `next` 是 `succ0`，那么会生成一个不等跳转指令到 `succ1`。

**6. `loadRegResult(s *ssagen.State, f *ssa.Func, t *types.Type, reg int16, n *ir.Name, off int64)`:**

* **功能:**  生成从 **自动变量 (栈上分配的局部变量)** 加载结果到寄存器的指令。通常用于函数返回值。
* **原理:**  根据类型 `t` 使用 `loadByType` 获取加载指令，并指定内存地址（基于栈帧偏移）。

**7. `spillArgReg(pp *objw.Progs, p *obj.Prog, f *ssa.Func, t *types.Type, reg int16, n *ir.Name, off int64)`:**

* **功能:**  生成将寄存器中的参数值 **溢出 (spill)** 到栈上的指令。
* **原理:**  根据类型 `t` 使用 `storeByType` 获取存储指令，并指定内存地址（基于参数的栈帧偏移）。

**总结:**

`go/src/cmd/compile/internal/ppc64/ssa.go` 文件是 Go 语言编译器中至关重要的一部分，它定义了如何将高级的、与架构无关的 SSA 中间表示转换为底层的、特定于 PPC64 架构的机器指令。理解这个文件的功能有助于深入了解 Go 语言的编译过程和目标架构的特性。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ppc64/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ppc64

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/ssagen"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/obj/ppc64"
	"internal/buildcfg"
	"math"
	"strings"
)

// ssaMarkMoves marks any MOVXconst ops that need to avoid clobbering flags.
func ssaMarkMoves(s *ssagen.State, b *ssa.Block) {
	//	flive := b.FlagsLiveAtEnd
	//	if b.Control != nil && b.Control.Type.IsFlags() {
	//		flive = true
	//	}
	//	for i := len(b.Values) - 1; i >= 0; i-- {
	//		v := b.Values[i]
	//		if flive && (v.Op == v.Op == ssa.OpPPC64MOVDconst) {
	//			// The "mark" is any non-nil Aux value.
	//			v.Aux = v
	//		}
	//		if v.Type.IsFlags() {
	//			flive = false
	//		}
	//		for _, a := range v.Args {
	//			if a.Type.IsFlags() {
	//				flive = true
	//			}
	//		}
	//	}
}

// loadByType returns the load instruction of the given type.
func loadByType(t *types.Type) obj.As {
	if t.IsFloat() {
		switch t.Size() {
		case 4:
			return ppc64.AFMOVS
		case 8:
			return ppc64.AFMOVD
		}
	} else {
		switch t.Size() {
		case 1:
			if t.IsSigned() {
				return ppc64.AMOVB
			} else {
				return ppc64.AMOVBZ
			}
		case 2:
			if t.IsSigned() {
				return ppc64.AMOVH
			} else {
				return ppc64.AMOVHZ
			}
		case 4:
			if t.IsSigned() {
				return ppc64.AMOVW
			} else {
				return ppc64.AMOVWZ
			}
		case 8:
			return ppc64.AMOVD
		}
	}
	panic("bad load type")
}

// storeByType returns the store instruction of the given type.
func storeByType(t *types.Type) obj.As {
	if t.IsFloat() {
		switch t.Size() {
		case 4:
			return ppc64.AFMOVS
		case 8:
			return ppc64.AFMOVD
		}
	} else {
		switch t.Size() {
		case 1:
			return ppc64.AMOVB
		case 2:
			return ppc64.AMOVH
		case 4:
			return ppc64.AMOVW
		case 8:
			return ppc64.AMOVD
		}
	}
	panic("bad store type")
}

func ssaGenValue(s *ssagen.State, v *ssa.Value) {
	switch v.Op {
	case ssa.OpCopy:
		t := v.Type
		if t.IsMemory() {
			return
		}
		x := v.Args[0].Reg()
		y := v.Reg()
		if x != y {
			rt := obj.TYPE_REG
			op := ppc64.AMOVD

			if t.IsFloat() {
				op = ppc64.AFMOVD
			}
			p := s.Prog(op)
			p.From.Type = rt
			p.From.Reg = x
			p.To.Type = rt
			p.To.Reg = y
		}

	case ssa.OpPPC64LoweredAtomicAnd8,
		ssa.OpPPC64LoweredAtomicAnd32,
		ssa.OpPPC64LoweredAtomicOr8,
		ssa.OpPPC64LoweredAtomicOr32:
		// LWSYNC
		// LBAR/LWAR	(Rarg0), Rtmp
		// AND/OR	Rarg1, Rtmp
		// STBCCC/STWCCC Rtmp, (Rarg0)
		// BNE		-3(PC)
		ld := ppc64.ALBAR
		st := ppc64.ASTBCCC
		if v.Op == ssa.OpPPC64LoweredAtomicAnd32 || v.Op == ssa.OpPPC64LoweredAtomicOr32 {
			ld = ppc64.ALWAR
			st = ppc64.ASTWCCC
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		// LWSYNC - Assuming shared data not write-through-required nor
		// caching-inhibited. See Appendix B.2.2.2 in the ISA 2.07b.
		plwsync := s.Prog(ppc64.ALWSYNC)
		plwsync.To.Type = obj.TYPE_NONE
		// LBAR or LWAR
		p := s.Prog(ld)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = r0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = ppc64.REGTMP
		// AND/OR reg1,out
		p1 := s.Prog(v.Op.Asm())
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r1
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = ppc64.REGTMP
		// STBCCC or STWCCC
		p2 := s.Prog(st)
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = ppc64.REGTMP
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = r0
		p2.RegTo2 = ppc64.REGTMP
		// BNE retry
		p3 := s.Prog(ppc64.ABNE)
		p3.To.Type = obj.TYPE_BRANCH
		p3.To.SetTarget(p)

	case ssa.OpPPC64LoweredAtomicAdd32,
		ssa.OpPPC64LoweredAtomicAdd64:
		// LWSYNC
		// LDAR/LWAR    (Rarg0), Rout
		// ADD		Rarg1, Rout
		// STDCCC/STWCCC Rout, (Rarg0)
		// BNE         -3(PC)
		// MOVW		Rout,Rout (if Add32)
		ld := ppc64.ALDAR
		st := ppc64.ASTDCCC
		if v.Op == ssa.OpPPC64LoweredAtomicAdd32 {
			ld = ppc64.ALWAR
			st = ppc64.ASTWCCC
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg0()
		// LWSYNC - Assuming shared data not write-through-required nor
		// caching-inhibited. See Appendix B.2.2.2 in the ISA 2.07b.
		plwsync := s.Prog(ppc64.ALWSYNC)
		plwsync.To.Type = obj.TYPE_NONE
		// LDAR or LWAR
		p := s.Prog(ld)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = r0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = out
		// ADD reg1,out
		p1 := s.Prog(ppc64.AADD)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r1
		p1.To.Reg = out
		p1.To.Type = obj.TYPE_REG
		// STDCCC or STWCCC
		p3 := s.Prog(st)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = out
		p3.To.Type = obj.TYPE_MEM
		p3.To.Reg = r0
		// BNE retry
		p4 := s.Prog(ppc64.ABNE)
		p4.To.Type = obj.TYPE_BRANCH
		p4.To.SetTarget(p)

		// Ensure a 32 bit result
		if v.Op == ssa.OpPPC64LoweredAtomicAdd32 {
			p5 := s.Prog(ppc64.AMOVWZ)
			p5.To.Type = obj.TYPE_REG
			p5.To.Reg = out
			p5.From.Type = obj.TYPE_REG
			p5.From.Reg = out
		}

	case ssa.OpPPC64LoweredAtomicExchange8,
		ssa.OpPPC64LoweredAtomicExchange32,
		ssa.OpPPC64LoweredAtomicExchange64:
		// LWSYNC
		// LDAR/LWAR/LBAR        (Rarg0), Rout
		// STDCCC/STWCCC/STBWCCC Rout, (Rarg0)
		// BNE         -2(PC)
		// ISYNC
		ld := ppc64.ALDAR
		st := ppc64.ASTDCCC
		switch v.Op {
		case ssa.OpPPC64LoweredAtomicExchange8:
			ld = ppc64.ALBAR
			st = ppc64.ASTBCCC
		case ssa.OpPPC64LoweredAtomicExchange32:
			ld = ppc64.ALWAR
			st = ppc64.ASTWCCC
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		out := v.Reg0()
		// LWSYNC - Assuming shared data not write-through-required nor
		// caching-inhibited. See Appendix B.2.2.2 in the ISA 2.07b.
		plwsync := s.Prog(ppc64.ALWSYNC)
		plwsync.To.Type = obj.TYPE_NONE
		// L[B|W|D]AR
		p := s.Prog(ld)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = r0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = out
		// ST[B|W|D]CCC
		p1 := s.Prog(st)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r1
		p1.To.Type = obj.TYPE_MEM
		p1.To.Reg = r0
		// BNE retry
		p2 := s.Prog(ppc64.ABNE)
		p2.To.Type = obj.TYPE_BRANCH
		p2.To.SetTarget(p)
		// ISYNC
		pisync := s.Prog(ppc64.AISYNC)
		pisync.To.Type = obj.TYPE_NONE

	case ssa.OpPPC64LoweredAtomicLoad8,
		ssa.OpPPC64LoweredAtomicLoad32,
		ssa.OpPPC64LoweredAtomicLoad64,
		ssa.OpPPC64LoweredAtomicLoadPtr:
		// SYNC
		// MOVB/MOVD/MOVW (Rarg0), Rout
		// CMP Rout,Rout
		// BNE 1(PC)
		// ISYNC
		ld := ppc64.AMOVD
		cmp := ppc64.ACMP
		switch v.Op {
		case ssa.OpPPC64LoweredAtomicLoad8:
			ld = ppc64.AMOVBZ
		case ssa.OpPPC64LoweredAtomicLoad32:
			ld = ppc64.AMOVWZ
			cmp = ppc64.ACMPW
		}
		arg0 := v.Args[0].Reg()
		out := v.Reg0()
		// SYNC when AuxInt == 1; otherwise, load-acquire
		if v.AuxInt == 1 {
			psync := s.Prog(ppc64.ASYNC)
			psync.To.Type = obj.TYPE_NONE
		}
		// Load
		p := s.Prog(ld)
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = arg0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = out
		// CMP
		p1 := s.Prog(cmp)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = out
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = out
		// BNE
		p2 := s.Prog(ppc64.ABNE)
		p2.To.Type = obj.TYPE_BRANCH
		// ISYNC
		pisync := s.Prog(ppc64.AISYNC)
		pisync.To.Type = obj.TYPE_NONE
		p2.To.SetTarget(pisync)

	case ssa.OpPPC64LoweredAtomicStore8,
		ssa.OpPPC64LoweredAtomicStore32,
		ssa.OpPPC64LoweredAtomicStore64:
		// SYNC or LWSYNC
		// MOVB/MOVW/MOVD arg1,(arg0)
		st := ppc64.AMOVD
		switch v.Op {
		case ssa.OpPPC64LoweredAtomicStore8:
			st = ppc64.AMOVB
		case ssa.OpPPC64LoweredAtomicStore32:
			st = ppc64.AMOVW
		}
		arg0 := v.Args[0].Reg()
		arg1 := v.Args[1].Reg()
		// If AuxInt == 0, LWSYNC (Store-Release), else SYNC
		// SYNC
		syncOp := ppc64.ASYNC
		if v.AuxInt == 0 {
			syncOp = ppc64.ALWSYNC
		}
		psync := s.Prog(syncOp)
		psync.To.Type = obj.TYPE_NONE
		// Store
		p := s.Prog(st)
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = arg0
		p.From.Type = obj.TYPE_REG
		p.From.Reg = arg1

	case ssa.OpPPC64LoweredAtomicCas64,
		ssa.OpPPC64LoweredAtomicCas32:
		// MOVD        $0, Rout
		// LWSYNC
		// loop:
		// LDAR        (Rarg0), MutexHint, Rtmp
		// CMP         Rarg1, Rtmp
		// BNE         end
		// STDCCC      Rarg2, (Rarg0)
		// BNE         loop
		// MOVD        $1, Rout
		// end:
		// LWSYNC      // Only for sequential consistency; not required in CasRel.
		ld := ppc64.ALDAR
		st := ppc64.ASTDCCC
		cmp := ppc64.ACMP
		if v.Op == ssa.OpPPC64LoweredAtomicCas32 {
			ld = ppc64.ALWAR
			st = ppc64.ASTWCCC
			cmp = ppc64.ACMPW
		}
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()
		r2 := v.Args[2].Reg()
		out := v.Reg0()
		// Initialize return value to false
		p := s.Prog(ppc64.AMOVD)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = out
		// LWSYNC - Assuming shared data not write-through-required nor
		// caching-inhibited. See Appendix B.2.2.2 in the ISA 2.07b.
		plwsync1 := s.Prog(ppc64.ALWSYNC)
		plwsync1.To.Type = obj.TYPE_NONE
		// LDAR or LWAR
		p0 := s.Prog(ld)
		p0.From.Type = obj.TYPE_MEM
		p0.From.Reg = r0
		p0.To.Type = obj.TYPE_REG
		p0.To.Reg = ppc64.REGTMP
		// If it is a Compare-and-Swap-Release operation, set the EH field with
		// the release hint.
		if v.AuxInt == 0 {
			p0.AddRestSourceConst(0)
		}
		// CMP reg1,reg2
		p1 := s.Prog(cmp)
		p1.From.Type = obj.TYPE_REG
		p1.From.Reg = r1
		p1.To.Reg = ppc64.REGTMP
		p1.To.Type = obj.TYPE_REG
		// BNE done with return value = false
		p2 := s.Prog(ppc64.ABNE)
		p2.To.Type = obj.TYPE_BRANCH
		// STDCCC or STWCCC
		p3 := s.Prog(st)
		p3.From.Type = obj.TYPE_REG
		p3.From.Reg = r2
		p3.To.Type = obj.TYPE_MEM
		p3.To.Reg = r0
		// BNE retry
		p4 := s.Prog(ppc64.ABNE)
		p4.To.Type = obj.TYPE_BRANCH
		p4.To.SetTarget(p0)
		// return value true
		p5 := s.Prog(ppc64.AMOVD)
		p5.From.Type = obj.TYPE_CONST
		p5.From.Offset = 1
		p5.To.Type = obj.TYPE_REG
		p5.To.Reg = out
		// LWSYNC - Assuming shared data not write-through-required nor
		// caching-inhibited. See Appendix B.2.1.1 in the ISA 2.07b.
		// If the operation is a CAS-Release, then synchronization is not necessary.
		if v.AuxInt != 0 {
			plwsync2 := s.Prog(ppc64.ALWSYNC)
			plwsync2.To.Type = obj.TYPE_NONE
			p2.To.SetTarget(plwsync2)
		} else {
			// done (label)
			p6 := s.Prog(obj.ANOP)
			p2.To.SetTarget(p6)
		}

	case ssa.OpPPC64LoweredPubBarrier:
		// LWSYNC
		s.Prog(v.Op.Asm())

	case ssa.OpPPC64LoweredGetClosurePtr:
		// Closure pointer is R11 (already)
		ssagen.CheckLoweredGetClosurePtr(v)

	case ssa.OpPPC64LoweredGetCallerSP:
		// caller's SP is FixedFrameSize below the address of the first arg
		p := s.Prog(ppc64.AMOVD)
		p.From.Type = obj.TYPE_ADDR
		p.From.Offset = -base.Ctxt.Arch.FixedFrameSize
		p.From.Name = obj.NAME_PARAM
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpPPC64LoweredGetCallerPC:
		p := s.Prog(obj.AGETCALLERPC)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpPPC64LoweredRound32F, ssa.OpPPC64LoweredRound64F:
		// input is already rounded

	case ssa.OpLoadReg:
		loadOp := loadByType(v.Type)
		p := s.Prog(loadOp)
		ssagen.AddrAuto(&p.From, v.Args[0])
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpStoreReg:
		storeOp := storeByType(v.Type)
		p := s.Prog(storeOp)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddrAuto(&p.To, v)

	case ssa.OpArgIntReg, ssa.OpArgFloatReg:
		// The assembler needs to wrap the entry safepoint/stack growth code with spill/unspill
		// The loop only runs once.
		for _, a := range v.Block.Func.RegArgs {
			// Pass the spill/unspill information along to the assembler, offset by size of
			// the saved LR slot.
			addr := ssagen.SpillSlotAddr(a, ppc64.REGSP, base.Ctxt.Arch.FixedFrameSize)
			s.FuncInfo().AddSpill(
				obj.RegSpill{Reg: a.Reg, Addr: addr, Unspill: loadByType(a.Type), Spill: storeByType(a.Type)})
		}
		v.Block.Func.RegArgs = nil

		ssagen.CheckArgReg(v)

	case ssa.OpPPC64DIVD:
		// For now,
		//
		// cmp arg1, -1
		// be  ahead
		// v = arg0 / arg1
		// b over
		// ahead: v = - arg0
		// over: nop
		r := v.Reg()
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()

		p := s.Prog(ppc64.ACMP)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.To.Type = obj.TYPE_CONST
		p.To.Offset = -1

		pbahead := s.Prog(ppc64.ABEQ)
		pbahead.To.Type = obj.TYPE_BRANCH

		p = s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.Reg = r0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r

		pbover := s.Prog(obj.AJMP)
		pbover.To.Type = obj.TYPE_BRANCH

		p = s.Prog(ppc64.ANEG)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r0
		pbahead.To.SetTarget(p)

		p = s.Prog(obj.ANOP)
		pbover.To.SetTarget(p)

	case ssa.OpPPC64DIVW:
		// word-width version of above
		r := v.Reg()
		r0 := v.Args[0].Reg()
		r1 := v.Args[1].Reg()

		p := s.Prog(ppc64.ACMPW)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.To.Type = obj.TYPE_CONST
		p.To.Offset = -1

		pbahead := s.Prog(ppc64.ABEQ)
		pbahead.To.Type = obj.TYPE_BRANCH

		p = s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.Reg = r0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r

		pbover := s.Prog(obj.AJMP)
		pbover.To.Type = obj.TYPE_BRANCH

		p = s.Prog(ppc64.ANEG)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r0
		pbahead.To.SetTarget(p)

		p = s.Prog(obj.ANOP)
		pbover.To.SetTarget(p)

	case ssa.OpPPC64CLRLSLWI:
		r := v.Reg()
		r1 := v.Args[0].Reg()
		shifts := v.AuxInt
		p := s.Prog(v.Op.Asm())
		// clrlslwi ra,rs,mb,sh will become rlwinm ra,rs,sh,mb-sh,31-sh as described in ISA
		p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: ssa.GetPPC64Shiftmb(shifts)}
		p.AddRestSourceConst(ssa.GetPPC64Shiftsh(shifts))
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r

	case ssa.OpPPC64CLRLSLDI:
		r := v.Reg()
		r1 := v.Args[0].Reg()
		shifts := v.AuxInt
		p := s.Prog(v.Op.Asm())
		// clrlsldi ra,rs,mb,sh will become rldic ra,rs,sh,mb-sh
		p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: ssa.GetPPC64Shiftmb(shifts)}
		p.AddRestSourceConst(ssa.GetPPC64Shiftsh(shifts))
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r

	case ssa.OpPPC64ADD, ssa.OpPPC64FADD, ssa.OpPPC64FADDS, ssa.OpPPC64SUB, ssa.OpPPC64FSUB, ssa.OpPPC64FSUBS,
		ssa.OpPPC64MULLD, ssa.OpPPC64MULLW, ssa.OpPPC64DIVDU, ssa.OpPPC64DIVWU,
		ssa.OpPPC64SRAD, ssa.OpPPC64SRAW, ssa.OpPPC64SRD, ssa.OpPPC64SRW, ssa.OpPPC64SLD, ssa.OpPPC64SLW,
		ssa.OpPPC64ROTL, ssa.OpPPC64ROTLW,
		ssa.OpPPC64MULHD, ssa.OpPPC64MULHW, ssa.OpPPC64MULHDU, ssa.OpPPC64MULHWU,
		ssa.OpPPC64FMUL, ssa.OpPPC64FMULS, ssa.OpPPC64FDIV, ssa.OpPPC64FDIVS, ssa.OpPPC64FCPSGN,
		ssa.OpPPC64AND, ssa.OpPPC64OR, ssa.OpPPC64ANDN, ssa.OpPPC64ORN, ssa.OpPPC64NOR, ssa.OpPPC64XOR, ssa.OpPPC64EQV,
		ssa.OpPPC64MODUD, ssa.OpPPC64MODSD, ssa.OpPPC64MODUW, ssa.OpPPC64MODSW, ssa.OpPPC64XSMINJDP, ssa.OpPPC64XSMAXJDP:
		r := v.Reg()
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r2
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r

	case ssa.OpPPC64ADDCC, ssa.OpPPC64ANDCC, ssa.OpPPC64SUBCC, ssa.OpPPC64ORCC, ssa.OpPPC64XORCC, ssa.OpPPC64NORCC,
		ssa.OpPPC64ANDNCC, ssa.OpPPC64MULHDUCC:
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r2
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

	case ssa.OpPPC64NEGCC, ssa.OpPPC64CNTLZDCC:
		p := s.Prog(v.Op.Asm())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()

	case ssa.OpPPC64ROTLconst, ssa.OpPPC64ROTLWconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

		// Auxint holds encoded rotate + mask
	case ssa.OpPPC64RLWINM, ssa.OpPPC64RLWMI:
		sh, mb, me, _ := ssa.DecodePPC64RotateMask(v.AuxInt)
		p := s.Prog(v.Op.Asm())
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: v.Reg()}
		p.Reg = v.Args[0].Reg()
		p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: int64(sh)}
		p.AddRestSourceArgs([]obj.Addr{{Type: obj.TYPE_CONST, Offset: mb}, {Type: obj.TYPE_CONST, Offset: me}})
		// Auxint holds mask

	case ssa.OpPPC64RLDICL, ssa.OpPPC64RLDICLCC, ssa.OpPPC64RLDICR:
		sh, mb, me, _ := ssa.DecodePPC64RotateMask(v.AuxInt)
		p := s.Prog(v.Op.Asm())
		p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: sh}
		switch v.Op {
		case ssa.OpPPC64RLDICL, ssa.OpPPC64RLDICLCC:
			p.AddRestSourceConst(mb)
		case ssa.OpPPC64RLDICR:
			p.AddRestSourceConst(me)
		}
		p.Reg = v.Args[0].Reg()
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: v.ResultReg()}

	case ssa.OpPPC64RLWNM:
		_, mb, me, _ := ssa.DecodePPC64RotateMask(v.AuxInt)
		p := s.Prog(v.Op.Asm())
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: v.Reg()}
		p.Reg = v.Args[0].Reg()
		p.From = obj.Addr{Type: obj.TYPE_REG, Reg: v.Args[1].Reg()}
		p.AddRestSourceArgs([]obj.Addr{{Type: obj.TYPE_CONST, Offset: mb}, {Type: obj.TYPE_CONST, Offset: me}})

	case ssa.OpPPC64MADDLD:
		r := v.Reg()
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		r3 := v.Args[2].Reg()
		// r = r1*r2 ± r3
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.Reg = r2
		p.AddRestSourceReg(r3)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r

	case ssa.OpPPC64FMADD, ssa.OpPPC64FMADDS, ssa.OpPPC64FMSUB, ssa.OpPPC64FMSUBS:
		r := v.Reg()
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		r3 := v.Args[2].Reg()
		// r = r1*r2 ± r3
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r1
		p.Reg = r3
		p.AddRestSourceReg(r2)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r

	case ssa.OpPPC64NEG, ssa.OpPPC64FNEG, ssa.OpPPC64FSQRT, ssa.OpPPC64FSQRTS, ssa.OpPPC64FFLOOR, ssa.OpPPC64FTRUNC, ssa.OpPPC64FCEIL,
		ssa.OpPPC64FCTIDZ, ssa.OpPPC64FCTIWZ, ssa.OpPPC64FCFID, ssa.OpPPC64FCFIDS, ssa.OpPPC64FRSP, ssa.OpPPC64CNTLZD, ssa.OpPPC64CNTLZW,
		ssa.OpPPC64POPCNTD, ssa.OpPPC64POPCNTW, ssa.OpPPC64POPCNTB, ssa.OpPPC64MFVSRD, ssa.OpPPC64MTVSRD, ssa.OpPPC64FABS, ssa.OpPPC64FNABS,
		ssa.OpPPC64FROUND, ssa.OpPPC64CNTTZW, ssa.OpPPC64CNTTZD, ssa.OpPPC64BRH, ssa.OpPPC64BRW, ssa.OpPPC64BRD:
		r := v.Reg()
		p := s.Prog(v.Op.Asm())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()

	case ssa.OpPPC64ADDconst, ssa.OpPPC64ORconst, ssa.OpPPC64XORconst,
		ssa.OpPPC64SRADconst, ssa.OpPPC64SRAWconst, ssa.OpPPC64SRDconst, ssa.OpPPC64SRWconst,
		ssa.OpPPC64SLDconst, ssa.OpPPC64SLWconst, ssa.OpPPC64EXTSWSLconst, ssa.OpPPC64MULLWconst, ssa.OpPPC64MULLDconst,
		ssa.OpPPC64ANDconst:
		p := s.Prog(v.Op.Asm())
		p.Reg = v.Args[0].Reg()
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpPPC64ADDC, ssa.OpPPC64ADDE, ssa.OpPPC64SUBC, ssa.OpPPC64SUBE:
		r := v.Reg0() // CA is the first, implied argument.
		r1 := v.Args[0].Reg()
		r2 := v.Args[1].Reg()
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = r2
		p.Reg = r1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = r

	case ssa.OpPPC64ADDZE:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

	case ssa.OpPPC64ADDZEzero, ssa.OpPPC64SUBZEzero:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = ppc64.REG_R0
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpPPC64ADDCconst:
		p := s.Prog(v.Op.Asm())
		p.Reg = v.Args[0].Reg()
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		// Output is a pair, the second is the CA, which is implied.
		p.To.Reg = v.Reg0()

	case ssa.OpPPC64SUBCconst:
		p := s.Prog(v.Op.Asm())
		p.AddRestSourceConst(v.AuxInt)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

	case ssa.OpPPC64SUBFCconst:
		p := s.Prog(v.Op.Asm())
		p.AddRestSourceConst(v.AuxInt)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpPPC64ADDCCconst, ssa.OpPPC64ANDCCconst:
		p := s.Prog(v.Op.Asm())
		p.Reg = v.Args[0].Reg()
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg0()

	case ssa.OpPPC64MOVDaddr:
		switch v.Aux.(type) {
		default:
			v.Fatalf("aux in MOVDaddr is of unknown type %T", v.Aux)
		case nil:
			// If aux offset and aux int are both 0, and the same
			// input and output regs are used, no instruction
			// needs to be generated, since it would just be
			// addi rx, rx, 0.
			if v.AuxInt != 0 || v.Args[0].Reg() != v.Reg() {
				p := s.Prog(ppc64.AMOVD)
				p.From.Type = obj.TYPE_ADDR
				p.From.Reg = v.Args[0].Reg()
				p.From.Offset = v.AuxInt
				p.To.Type = obj.TYPE_REG
				p.To.Reg = v.Reg()
			}

		case *obj.LSym, ir.Node:
			p := s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_ADDR
			p.From.Reg = v.Args[0].Reg()
			p.To.Type = obj.TYPE_REG
			p.To.Reg = v.Reg()
			ssagen.AddAux(&p.From, v)

		}

	case ssa.OpPPC64MOVDconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpPPC64FMOVDconst, ssa.OpPPC64FMOVSconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_FCONST
		p.From.Val = math.Float64frombits(uint64(v.AuxInt))
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpPPC64FCMPU, ssa.OpPPC64CMP, ssa.OpPPC64CMPW, ssa.OpPPC64CMPU, ssa.OpPPC64CMPWU:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Args[1].Reg()

	case ssa.OpPPC64CMPconst, ssa.OpPPC64CMPUconst, ssa.OpPPC64CMPWconst, ssa.OpPPC64CMPWUconst:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_CONST
		p.To.Offset = v.AuxInt

	case ssa.OpPPC64MOVBreg, ssa.OpPPC64MOVBZreg, ssa.OpPPC64MOVHreg, ssa.OpPPC64MOVHZreg, ssa.OpPPC64MOVWreg, ssa.OpPPC64MOVWZreg:
		// Shift in register to required size
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Reg = v.Reg()
		p.To.Type = obj.TYPE_REG

	case ssa.OpPPC64MOVDload, ssa.OpPPC64MOVWload:

		// MOVDload and MOVWload are DS form instructions that are restricted to
		// offsets that are a multiple of 4. If the offset is not a multiple of 4,
		// then the address of the symbol to be loaded is computed (base + offset)
		// and used as the new base register and the offset field in the instruction
		// can be set to zero.

		// This same problem can happen with gostrings since the final offset is not
		// known yet, but could be unaligned after the relocation is resolved.
		// So gostrings are handled the same way.

		// This allows the MOVDload and MOVWload to be generated in more cases and
		// eliminates some offset and alignment checking in the rules file.

		fromAddr := obj.Addr{Type: obj.TYPE_MEM, Reg: v.Args[0].Reg()}
		ssagen.AddAux(&fromAddr, v)

		genAddr := false

		switch fromAddr.Name {
		case obj.NAME_EXTERN, obj.NAME_STATIC:
			// Special case for a rule combines the bytes of gostring.
			// The v alignment might seem OK, but we don't want to load it
			// using an offset because relocation comes later.
			genAddr = strings.HasPrefix(fromAddr.Sym.Name, "go:string") || v.Type.Alignment()%4 != 0 || fromAddr.Offset%4 != 0
		default:
			genAddr = fromAddr.Offset%4 != 0
		}
		if genAddr {
			// Load full address into the temp register.
			p := s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_ADDR
			p.From.Reg = v.Args[0].Reg()
			ssagen.AddAux(&p.From, v)
			// Load target using temp as base register
			// and offset zero. Setting NAME_NONE
			// prevents any extra offsets from being
			// added.
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REGTMP
			fromAddr.Reg = ppc64.REGTMP
			// Clear the offset field and other
			// information that might be used
			// by the assembler to add to the
			// final offset value.
			fromAddr.Offset = 0
			fromAddr.Name = obj.NAME_NONE
			fromAddr.Sym = nil
		}
		p := s.Prog(v.Op.Asm())
		p.From = fromAddr
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpPPC64MOVHload, ssa.OpPPC64MOVWZload, ssa.OpPPC64MOVBZload, ssa.OpPPC64MOVHZload, ssa.OpPPC64FMOVDload, ssa.OpPPC64FMOVSload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.From, v)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpPPC64MOVDBRload, ssa.OpPPC64MOVWBRload, ssa.OpPPC64MOVHBRload:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpPPC64MOVDBRstore, ssa.OpPPC64MOVWBRstore, ssa.OpPPC64MOVHBRstore:
		p := s.Prog(v.Op.Asm())
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()

	case ssa.OpPPC64MOVDloadidx, ssa.OpPPC64MOVWloadidx, ssa.OpPPC64MOVHloadidx, ssa.OpPPC64MOVWZloadidx,
		ssa.OpPPC64MOVBZloadidx, ssa.OpPPC64MOVHZloadidx, ssa.OpPPC64FMOVDloadidx, ssa.OpPPC64FMOVSloadidx,
		ssa.OpPPC64MOVDBRloadidx, ssa.OpPPC64MOVWBRloadidx, ssa.OpPPC64MOVHBRloadidx:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.From.Index = v.Args[1].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()

	case ssa.OpPPC64DCBT:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_CONST
		p.To.Offset = v.AuxInt

	case ssa.OpPPC64MOVWstorezero, ssa.OpPPC64MOVHstorezero, ssa.OpPPC64MOVBstorezero:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = ppc64.REGZERO
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)

	case ssa.OpPPC64MOVDstore, ssa.OpPPC64MOVDstorezero:

		// MOVDstore and MOVDstorezero become DS form instructions that are restricted
		// to offset values that are a multiple of 4. If the offset field is not a
		// multiple of 4, then the full address of the store target is computed (base +
		// offset) and used as the new base register and the offset in the instruction
		// is set to 0.

		// This allows the MOVDstore and MOVDstorezero to be generated in more cases,
		// and prevents checking of the offset value and alignment in the rules.

		toAddr := obj.Addr{Type: obj.TYPE_MEM, Reg: v.Args[0].Reg()}
		ssagen.AddAux(&toAddr, v)

		if toAddr.Offset%4 != 0 {
			p := s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_ADDR
			p.From.Reg = v.Args[0].Reg()
			ssagen.AddAux(&p.From, v)
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REGTMP
			toAddr.Reg = ppc64.REGTMP
			// Clear the offset field and other
			// information that might be used
			// by the assembler to add to the
			// final offset value.
			toAddr.Offset = 0
			toAddr.Name = obj.NAME_NONE
			toAddr.Sym = nil
		}
		p := s.Prog(v.Op.Asm())
		p.To = toAddr
		p.From.Type = obj.TYPE_REG
		if v.Op == ssa.OpPPC64MOVDstorezero {
			p.From.Reg = ppc64.REGZERO
		} else {
			p.From.Reg = v.Args[1].Reg()
		}

	case ssa.OpPPC64MOVWstore, ssa.OpPPC64MOVHstore, ssa.OpPPC64MOVBstore, ssa.OpPPC64FMOVDstore, ssa.OpPPC64FMOVSstore:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()
		ssagen.AddAux(&p.To, v)

	case ssa.OpPPC64MOVDstoreidx, ssa.OpPPC64MOVWstoreidx, ssa.OpPPC64MOVHstoreidx, ssa.OpPPC64MOVBstoreidx,
		ssa.OpPPC64FMOVDstoreidx, ssa.OpPPC64FMOVSstoreidx, ssa.OpPPC64MOVDBRstoreidx, ssa.OpPPC64MOVWBRstoreidx,
		ssa.OpPPC64MOVHBRstoreidx:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[2].Reg()
		p.To.Index = v.Args[1].Reg()
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = v.Args[0].Reg()

	case ssa.OpPPC64ISEL, ssa.OpPPC64ISELZ:
		// ISEL  AuxInt ? arg0 : arg1
		// ISELZ is a special case of ISEL where arg1 is implicitly $0.
		//
		// AuxInt value indicates conditions 0=LT 1=GT 2=EQ 3=SO 4=GE 5=LE 6=NE 7=NSO.
		// ISEL accepts a CR bit argument, not a condition as expressed by AuxInt.
		// Convert the condition to a CR bit argument by the following conversion:
		//
		// AuxInt&3 ? arg0 : arg1 for conditions LT, GT, EQ, SO
		// AuxInt&3 ? arg1 : arg0 for conditions GE, LE, NE, NSO
		p := s.Prog(v.Op.Asm())
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: v.Reg()}
		p.Reg = v.Args[0].Reg()
		if v.Op == ssa.OpPPC64ISEL {
			p.AddRestSourceReg(v.Args[1].Reg())
		} else {
			p.AddRestSourceReg(ppc64.REG_R0)
		}
		// AuxInt values 4,5,6 implemented with reverse operand order from 0,1,2
		if v.AuxInt > 3 {
			p.Reg, p.GetFrom3().Reg = p.GetFrom3().Reg, p.Reg
		}
		p.From.SetConst(v.AuxInt & 3)

	case ssa.OpPPC64SETBC, ssa.OpPPC64SETBCR:
		p := s.Prog(v.Op.Asm())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
		p.From.Type = obj.TYPE_REG
		p.From.Reg = int16(ppc64.REG_CR0LT + v.AuxInt)

	case ssa.OpPPC64LoweredQuadZero, ssa.OpPPC64LoweredQuadZeroShort:
		// The LoweredQuad code generation
		// generates STXV instructions on
		// power9. The Short variation is used
		// if no loop is generated.

		// sizes >= 64 generate a loop as follows:

		// Set up loop counter in CTR, used by BC
		// XXLXOR clears VS32
		//       XXLXOR VS32,VS32,VS32
		//       MOVD len/64,REG_TMP
		//       MOVD REG_TMP,CTR
		//       loop:
		//       STXV VS32,0(R20)
		//       STXV VS32,16(R20)
		//       STXV VS32,32(R20)
		//       STXV VS32,48(R20)
		//       ADD  $64,R20
		//       BC   16, 0, loop

		// Bytes per iteration
		ctr := v.AuxInt / 64

		// Remainder bytes
		rem := v.AuxInt % 64

		// Only generate a loop if there is more
		// than 1 iteration.
		if ctr > 1 {
			// Set up VS32 (V0) to hold 0s
			p := s.Prog(ppc64.AXXLXOR)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS32
			p.Reg = ppc64.REG_VS32

			// Set up CTR loop counter
			p = s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = ctr
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REGTMP

			p = s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REGTMP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_CTR

			// Don't generate padding for
			// loops with few iterations.
			if ctr > 3 {
				p = s.Prog(obj.APCALIGN)
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = 16
			}

			// generate 4 STXVs to zero 64 bytes
			var top *obj.Prog

			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()

			//  Save the top of loop
			if top == nil {
				top = p
			}
			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()
			p.To.Offset = 16

			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()
			p.To.Offset = 32

			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()
			p.To.Offset = 48

			// Increment address for the
			// 64 bytes just zeroed.
			p = s.Prog(ppc64.AADD)
			p.Reg = v.Args[0].Reg()
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = 64
			p.To.Type = obj.TYPE_REG
			p.To.Reg = v.Args[0].Reg()

			// Branch back to top of loop
			// based on CTR
			// BC with BO_BCTR generates bdnz
			p = s.Prog(ppc64.ABC)
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = ppc64.BO_BCTR
			p.Reg = ppc64.REG_CR0LT
			p.To.Type = obj.TYPE_BRANCH
			p.To.SetTarget(top)
		}
		// When ctr == 1 the loop was not generated but
		// there are at least 64 bytes to clear, so add
		// that to the remainder to generate the code
		// to clear those doublewords
		if ctr == 1 {
			rem += 64
		}

		// Clear the remainder starting at offset zero
		offset := int64(0)

		if rem >= 16 && ctr <= 1 {
			// If the XXLXOR hasn't already been
			// generated, do it here to initialize
			// VS32 (V0) to 0.
			p := s.Prog(ppc64.AXXLXOR)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS32
			p.Reg = ppc64.REG_VS32
		}
		// Generate STXV for 32 or 64
		// bytes.
		for rem >= 32 {
			p := s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()
			p.To.Offset = offset

			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()
			p.To.Offset = offset + 16
			offset += 32
			rem -= 32
		}
		// Generate 16 bytes
		if rem >= 16 {
			p := s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()
			p.To.Offset = offset
			offset += 16
			rem -= 16
		}

		// first clear as many doublewords as possible
		// then clear remaining sizes as available
		for rem > 0 {
			op, size := ppc64.AMOVB, int64(1)
			switch {
			case rem >= 8:
				op, size = ppc64.AMOVD, 8
			case rem >= 4:
				op, size = ppc64.AMOVW, 4
			case rem >= 2:
				op, size = ppc64.AMOVH, 2
			}
			p := s.Prog(op)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_R0
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()
			p.To.Offset = offset
			rem -= size
			offset += size
		}

	case ssa.OpPPC64LoweredZero, ssa.OpPPC64LoweredZeroShort:

		// Unaligned data doesn't hurt performance
		// for these instructions on power8.

		// For sizes >= 64 generate a loop as follows:

		// Set up loop counter in CTR, used by BC
		//       XXLXOR VS32,VS32,VS32
		//	 MOVD len/32,REG_TMP
		//	 MOVD REG_TMP,CTR
		//       MOVD $16,REG_TMP
		//	 loop:
		//	 STXVD2X VS32,(R0)(R20)
		//	 STXVD2X VS32,(R31)(R20)
		//	 ADD  $32,R20
		//	 BC   16, 0, loop
		//
		// any remainder is done as described below

		// for sizes < 64 bytes, first clear as many doublewords as possible,
		// then handle the remainder
		//	MOVD R0,(R20)
		//	MOVD R0,8(R20)
		// .... etc.
		//
		// the remainder bytes are cleared using one or more
		// of the following instructions with the appropriate
		// offsets depending which instructions are needed
		//
		//	MOVW R0,n1(R20)	4 bytes
		//	MOVH R0,n2(R20)	2 bytes
		//	MOVB R0,n3(R20)	1 byte
		//
		// 7 bytes: MOVW, MOVH, MOVB
		// 6 bytes: MOVW, MOVH
		// 5 bytes: MOVW, MOVB
		// 3 bytes: MOVH, MOVB

		// each loop iteration does 32 bytes
		ctr := v.AuxInt / 32

		// remainder bytes
		rem := v.AuxInt % 32

		// only generate a loop if there is more
		// than 1 iteration.
		if ctr > 1 {
			// Set up VS32 (V0) to hold 0s
			p := s.Prog(ppc64.AXXLXOR)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS32
			p.Reg = ppc64.REG_VS32

			// Set up CTR loop counter
			p = s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = ctr
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REGTMP

			p = s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REGTMP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_CTR

			// Set up R31 to hold index value 16
			p = s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = 16
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REGTMP

			// Don't add padding for alignment
			// with few loop iterations.
			if ctr > 3 {
				p = s.Prog(obj.APCALIGN)
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = 16
			}

			// generate 2 STXVD2Xs to store 16 bytes
			// when this is a loop then the top must be saved
			var top *obj.Prog
			// This is the top of loop

			p = s.Prog(ppc64.ASTXVD2X)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()
			p.To.Index = ppc64.REGZERO
			// Save the top of loop
			if top == nil {
				top = p
			}
			p = s.Prog(ppc64.ASTXVD2X)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()
			p.To.Index = ppc64.REGTMP

			// Increment address for the
			// 4 doublewords just zeroed.
			p = s.Prog(ppc64.AADD)
			p.Reg = v.Args[0].Reg()
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = 32
			p.To.Type = obj.TYPE_REG
			p.To.Reg = v.Args[0].Reg()

			// Branch back to top of loop
			// based on CTR
			// BC with BO_BCTR generates bdnz
			p = s.Prog(ppc64.ABC)
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = ppc64.BO_BCTR
			p.Reg = ppc64.REG_CR0LT
			p.To.Type = obj.TYPE_BRANCH
			p.To.SetTarget(top)
		}

		// when ctr == 1 the loop was not generated but
		// there are at least 32 bytes to clear, so add
		// that to the remainder to generate the code
		// to clear those doublewords
		if ctr == 1 {
			rem += 32
		}

		// clear the remainder starting at offset zero
		offset := int64(0)

		// first clear as many doublewords as possible
		// then clear remaining sizes as available
		for rem > 0 {
			op, size := ppc64.AMOVB, int64(1)
			switch {
			case rem >= 8:
				op, size = ppc64.AMOVD, 8
			case rem >= 4:
				op, size = ppc64.AMOVW, 4
			case rem >= 2:
				op, size = ppc64.AMOVH, 2
			}
			p := s.Prog(op)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_R0
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = v.Args[0].Reg()
			p.To.Offset = offset
			rem -= size
			offset += size
		}

	case ssa.OpPPC64LoweredMove, ssa.OpPPC64LoweredMoveShort:

		bytesPerLoop := int64(32)
		// This will be used when moving more
		// than 8 bytes.  Moves start with
		// as many 8 byte moves as possible, then
		// 4, 2, or 1 byte(s) as remaining.  This will
		// work and be efficient for power8 or later.
		// If there are 64 or more bytes, then a
		// loop is generated to move 32 bytes and
		// update the src and dst addresses on each
		// iteration. When < 64 bytes, the appropriate
		// number of moves are generated based on the
		// size.
		// When moving >= 64 bytes a loop is used
		//	MOVD len/32,REG_TMP
		//	MOVD REG_TMP,CTR
		//	MOVD $16,REG_TMP
		// top:
		//	LXVD2X (R0)(R21),VS32
		//	LXVD2X (R31)(R21),VS33
		//	ADD $32,R21
		//	STXVD2X VS32,(R0)(R20)
		//	STXVD2X VS33,(R31)(R20)
		//	ADD $32,R20
		//	BC 16,0,top
		// Bytes not moved by this loop are moved
		// with a combination of the following instructions,
		// starting with the largest sizes and generating as
		// many as needed, using the appropriate offset value.
		//	MOVD  n(R21),R31
		//	MOVD  R31,n(R20)
		//	MOVW  n1(R21),R31
		//	MOVW  R31,n1(R20)
		//	MOVH  n2(R21),R31
		//	MOVH  R31,n2(R20)
		//	MOVB  n3(R21),R31
		//	MOVB  R31,n3(R20)

		// Each loop iteration moves 32 bytes
		ctr := v.AuxInt / bytesPerLoop

		// Remainder after the loop
		rem := v.AuxInt % bytesPerLoop

		dstReg := v.Args[0].Reg()
		srcReg := v.Args[1].Reg()

		// The set of registers used here, must match the clobbered reg list
		// in PPC64Ops.go.
		offset := int64(0)

		// top of the loop
		var top *obj.Prog
		// Only generate looping code when loop counter is > 1 for >= 64 bytes
		if ctr > 1 {
			// Set up the CTR
			p := s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = ctr
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REGTMP

			p = s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REGTMP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_CTR

			// Use REGTMP as index reg
			p = s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = 16
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REGTMP

			// Don't adding padding for
			// alignment with small iteration
			// counts.
			if ctr > 3 {
				p = s.Prog(obj.APCALIGN)
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = 16
			}

			// Generate 16 byte loads and stores.
			// Use temp register for index (16)
			// on the second one.

			p = s.Prog(ppc64.ALXVD2X)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.From.Index = ppc64.REGZERO
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS32
			if top == nil {
				top = p
			}
			p = s.Prog(ppc64.ALXVD2X)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.From.Index = ppc64.REGTMP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS33

			// increment the src reg for next iteration
			p = s.Prog(ppc64.AADD)
			p.Reg = srcReg
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = bytesPerLoop
			p.To.Type = obj.TYPE_REG
			p.To.Reg = srcReg

			// generate 16 byte stores
			p = s.Prog(ppc64.ASTXVD2X)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg
			p.To.Index = ppc64.REGZERO

			p = s.Prog(ppc64.ASTXVD2X)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS33
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg
			p.To.Index = ppc64.REGTMP

			// increment the dst reg for next iteration
			p = s.Prog(ppc64.AADD)
			p.Reg = dstReg
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = bytesPerLoop
			p.To.Type = obj.TYPE_REG
			p.To.Reg = dstReg

			// BC with BO_BCTR generates bdnz to branch on nonzero CTR
			// to loop top.
			p = s.Prog(ppc64.ABC)
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = ppc64.BO_BCTR
			p.Reg = ppc64.REG_CR0LT
			p.To.Type = obj.TYPE_BRANCH
			p.To.SetTarget(top)

			// srcReg and dstReg were incremented in the loop, so
			// later instructions start with offset 0.
			offset = int64(0)
		}

		// No loop was generated for one iteration, so
		// add 32 bytes to the remainder to move those bytes.
		if ctr == 1 {
			rem += bytesPerLoop
		}

		if rem >= 16 {
			// Generate 16 byte loads and stores.
			// Use temp register for index (value 16)
			// on the second one.
			p := s.Prog(ppc64.ALXVD2X)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.From.Index = ppc64.REGZERO
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS32

			p = s.Prog(ppc64.ASTXVD2X)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg
			p.To.Index = ppc64.REGZERO

			offset = 16
			rem -= 16

			if rem >= 16 {
				// Use REGTMP as index reg
				p := s.Prog(ppc64.AMOVD)
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = 16
				p.To.Type = obj.TYPE_REG
				p.To.Reg = ppc64.REGTMP

				p = s.Prog(ppc64.ALXVD2X)
				p.From.Type = obj.TYPE_MEM
				p.From.Reg = srcReg
				p.From.Index = ppc64.REGTMP
				p.To.Type = obj.TYPE_REG
				p.To.Reg = ppc64.REG_VS32

				p = s.Prog(ppc64.ASTXVD2X)
				p.From.Type = obj.TYPE_REG
				p.From.Reg = ppc64.REG_VS32
				p.To.Type = obj.TYPE_MEM
				p.To.Reg = dstReg
				p.To.Index = ppc64.REGTMP

				offset = 32
				rem -= 16
			}
		}

		// Generate all the remaining load and store pairs, starting with
		// as many 8 byte moves as possible, then 4, 2, 1.
		for rem > 0 {
			op, size := ppc64.AMOVB, int64(1)
			switch {
			case rem >= 8:
				op, size = ppc64.AMOVD, 8
			case rem >= 4:
				op, size = ppc64.AMOVWZ, 4
			case rem >= 2:
				op, size = ppc64.AMOVH, 2
			}
			// Load
			p := s.Prog(op)
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REGTMP
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.From.Offset = offset

			// Store
			p = s.Prog(op)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REGTMP
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg
			p.To.Offset = offset
			rem -= size
			offset += size
		}

	case ssa.OpPPC64LoweredQuadMove, ssa.OpPPC64LoweredQuadMoveShort:
		bytesPerLoop := int64(64)
		// This is used when moving more
		// than 8 bytes on power9.  Moves start with
		// as many 8 byte moves as possible, then
		// 4, 2, or 1 byte(s) as remaining.  This will
		// work and be efficient for power8 or later.
		// If there are 64 or more bytes, then a
		// loop is generated to move 32 bytes and
		// update the src and dst addresses on each
		// iteration. When < 64 bytes, the appropriate
		// number of moves are generated based on the
		// size.
		// When moving >= 64 bytes a loop is used
		//      MOVD len/32,REG_TMP
		//      MOVD REG_TMP,CTR
		// top:
		//      LXV 0(R21),VS32
		//      LXV 16(R21),VS33
		//      ADD $32,R21
		//      STXV VS32,0(R20)
		//      STXV VS33,16(R20)
		//      ADD $32,R20
		//      BC 16,0,top
		// Bytes not moved by this loop are moved
		// with a combination of the following instructions,
		// starting with the largest sizes and generating as
		// many as needed, using the appropriate offset value.
		//      MOVD  n(R21),R31
		//      MOVD  R31,n(R20)
		//      MOVW  n1(R21),R31
		//      MOVW  R31,n1(R20)
		//      MOVH  n2(R21),R31
		//      MOVH  R31,n2(R20)
		//      MOVB  n3(R21),R31
		//      MOVB  R31,n3(R20)

		// Each loop iteration moves 32 bytes
		ctr := v.AuxInt / bytesPerLoop

		// Remainder after the loop
		rem := v.AuxInt % bytesPerLoop

		dstReg := v.Args[0].Reg()
		srcReg := v.Args[1].Reg()

		offset := int64(0)

		// top of the loop
		var top *obj.Prog

		// Only generate looping code when loop counter is > 1 for >= 64 bytes
		if ctr > 1 {
			// Set up the CTR
			p := s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = ctr
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REGTMP

			p = s.Prog(ppc64.AMOVD)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REGTMP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_CTR

			p = s.Prog(obj.APCALIGN)
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = 16

			// Generate 16 byte loads and stores.
			p = s.Prog(ppc64.ALXV)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.From.Offset = offset
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS32
			if top == nil {
				top = p
			}
			p = s.Prog(ppc64.ALXV)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.From.Offset = offset + 16
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS33

			// generate 16 byte stores
			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg
			p.To.Offset = offset

			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS33
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg
			p.To.Offset = offset + 16

			// Generate 16 byte loads and stores.
			p = s.Prog(ppc64.ALXV)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.From.Offset = offset + 32
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS32

			p = s.Prog(ppc64.ALXV)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.From.Offset = offset + 48
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS33

			// generate 16 byte stores
			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg
			p.To.Offset = offset + 32

			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS33
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg
			p.To.Offset = offset + 48

			// increment the src reg for next iteration
			p = s.Prog(ppc64.AADD)
			p.Reg = srcReg
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = bytesPerLoop
			p.To.Type = obj.TYPE_REG
			p.To.Reg = srcReg

			// increment the dst reg for next iteration
			p = s.Prog(ppc64.AADD)
			p.Reg = dstReg
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = bytesPerLoop
			p.To.Type = obj.TYPE_REG
			p.To.Reg = dstReg

			// BC with BO_BCTR generates bdnz to branch on nonzero CTR
			// to loop top.
			p = s.Prog(ppc64.ABC)
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = ppc64.BO_BCTR
			p.Reg = ppc64.REG_CR0LT
			p.To.Type = obj.TYPE_BRANCH
			p.To.SetTarget(top)

			// srcReg and dstReg were incremented in the loop, so
			// later instructions start with offset 0.
			offset = int64(0)
		}

		// No loop was generated for one iteration, so
		// add 32 bytes to the remainder to move those bytes.
		if ctr == 1 {
			rem += bytesPerLoop
		}
		if rem >= 32 {
			p := s.Prog(ppc64.ALXV)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS32

			p = s.Prog(ppc64.ALXV)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.From.Offset = 16
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS33

			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg

			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS33
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg
			p.To.Offset = 16

			offset = 32
			rem -= 32
		}

		if rem >= 16 {
			// Generate 16 byte loads and stores.
			p := s.Prog(ppc64.ALXV)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.From.Offset = offset
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REG_VS32

			p = s.Prog(ppc64.ASTXV)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_VS32
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg
			p.To.Offset = offset

			offset += 16
			rem -= 16

			if rem >= 16 {
				p := s.Prog(ppc64.ALXV)
				p.From.Type = obj.TYPE_MEM
				p.From.Reg = srcReg
				p.From.Offset = offset
				p.To.Type = obj.TYPE_REG
				p.To.Reg = ppc64.REG_VS32

				p = s.Prog(ppc64.ASTXV)
				p.From.Type = obj.TYPE_REG
				p.From.Reg = ppc64.REG_VS32
				p.To.Type = obj.TYPE_MEM
				p.To.Reg = dstReg
				p.To.Offset = offset

				offset += 16
				rem -= 16
			}
		}
		// Generate all the remaining load and store pairs, starting with
		// as many 8 byte moves as possible, then 4, 2, 1.
		for rem > 0 {
			op, size := ppc64.AMOVB, int64(1)
			switch {
			case rem >= 8:
				op, size = ppc64.AMOVD, 8
			case rem >= 4:
				op, size = ppc64.AMOVWZ, 4
			case rem >= 2:
				op, size = ppc64.AMOVH, 2
			}
			// Load
			p := s.Prog(op)
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REGTMP
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = srcReg
			p.From.Offset = offset

			// Store
			p = s.Prog(op)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REGTMP
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = dstReg
			p.To.Offset = offset
			rem -= size
			offset += size
		}

	case ssa.OpPPC64CALLstatic:
		s.Call(v)

	case ssa.OpPPC64CALLtail:
		s.TailCall(v)

	case ssa.OpPPC64CALLclosure, ssa.OpPPC64CALLinter:
		p := s.Prog(ppc64.AMOVD)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = v.Args[0].Reg()
		p.To.Type = obj.TYPE_REG
		p.To.Reg = ppc64.REG_LR

		if v.Args[0].Reg() != ppc64.REG_R12 {
			v.Fatalf("Function address for %v should be in R12 %d but is in %d", v.LongString(), ppc64.REG_R12, p.From.Reg)
		}

		pp := s.Call(v)

		// Convert the call into a blrl with hint this is not a subroutine return.
		// The full bclrl opcode must be specified when passing a hint.
		pp.As = ppc64.ABCL
		pp.From.Type = obj.TYPE_CONST
		pp.From.Offset = ppc64.BO_ALWAYS
		pp.Reg = ppc64.REG_CR0LT // The preferred value if BI is ignored.
		pp.To.Reg = ppc64.REG_LR
		pp.AddRestSourceConst(1)

		if ppc64.NeedTOCpointer(base.Ctxt) {
			// When compiling Go into PIC, the function we just
			// called via pointer might have been implemented in
			// a separate module and so overwritten the TOC
			// pointer in R2; reload it.
			q := s.Prog(ppc64.AMOVD)
			q.From.Type = obj.TYPE_MEM
			q.From.Offset = 24
			q.From.Reg = ppc64.REGSP
			q.To.Type = obj.TYPE_REG
			q.To.Reg = ppc64.REG_R2
		}

	case ssa.OpPPC64LoweredWB:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		// AuxInt encodes how many buffer entries we need.
		p.To.Sym = ir.Syms.GCWriteBarrier[v.AuxInt-1]

	case ssa.OpPPC64LoweredPanicBoundsA, ssa.OpPPC64LoweredPanicBoundsB, ssa.OpPPC64LoweredPanicBoundsC:
		p := s.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ssagen.BoundsCheckFunc[v.AuxInt]
		s.UseArgs(16) // space used in callee args area by assembly stubs

	case ssa.OpPPC64LoweredNilCheck:
		if buildcfg.GOOS == "aix" {
			// CMP Rarg0, $0
			// BNE 2(PC)
			// STW R0, 0(R0)
			// NOP (so the BNE has somewhere to land)

			// CMP Rarg0, $0
			p := s.Prog(ppc64.ACMP)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = v.Args[0].Reg()
			p.To.Type = obj.TYPE_CONST
			p.To.Offset = 0

			// BNE 2(PC)
			p2 := s.Prog(ppc64.ABNE)
			p2.To.Type = obj.TYPE_BRANCH

			// STW R0, 0(R0)
			// Write at 0 is forbidden and will trigger a SIGSEGV
			p = s.Prog(ppc64.AMOVW)
			p.From.Type = obj.TYPE_REG
			p.From.Reg = ppc64.REG_R0
			p.To.Type = obj.TYPE_MEM
			p.To.Reg = ppc64.REG_R0

			// NOP (so the BNE has somewhere to land)
			nop := s.Prog(obj.ANOP)
			p2.To.SetTarget(nop)

		} else {
			// Issue a load which will fault if arg is nil.
			p := s.Prog(ppc64.AMOVBZ)
			p.From.Type = obj.TYPE_MEM
			p.From.Reg = v.Args[0].Reg()
			ssagen.AddAux(&p.From, v)
			p.To.Type = obj.TYPE_REG
			p.To.Reg = ppc64.REGTMP
		}
		if logopt.Enabled() {
			logopt.LogOpt(v.Pos, "nilcheck", "genssa", v.Block.Func.Name)
		}
		if base.Debug.Nil != 0 && v.Pos.Line() > 1 { // v.Pos.Line()==1 in generated wrappers
			base.WarnfAt(v.Pos, "generated nil check")
		}

	// These should be resolved by rules and not make it here.
	case ssa.OpPPC64Equal, ssa.OpPPC64NotEqual, ssa.OpPPC64LessThan, ssa.OpPPC64FLessThan,
		ssa.OpPPC64LessEqual, ssa.OpPPC64GreaterThan, ssa.OpPPC64FGreaterThan, ssa.OpPPC64GreaterEqual,
		ssa.OpPPC64FLessEqual, ssa.OpPPC64FGreaterEqual:
		v.Fatalf("Pseudo-op should not make it to codegen: %s ###\n", v.LongString())
	case ssa.OpPPC64InvertFlags:
		v.Fatalf("InvertFlags should never make it to codegen %v", v.LongString())
	case ssa.OpPPC64FlagEQ, ssa.OpPPC64FlagLT, ssa.OpPPC64FlagGT:
		v.Fatalf("Flag* ops should never make it to codegen %v", v.LongString())
	case ssa.OpClobber, ssa.OpClobberReg:
		// TODO: implement for clobberdead experiment. Nop is ok for now.
	default:
		v.Fatalf("genValue not implemented: %s", v.LongString())
	}
}

var blockJump = [...]struct {
	asm, invasm     obj.As
	asmeq, invasmun bool
}{
	ssa.BlockPPC64EQ: {ppc64.ABEQ, ppc64.ABNE, false, false},
	ssa.BlockPPC64NE: {ppc64.ABNE, ppc64.ABEQ, false, false},

	ssa.BlockPPC64LT: {ppc64.ABLT, ppc64.ABGE, false, false},
	ssa.BlockPPC64GE: {ppc64.ABGE, ppc64.ABLT, false, false},
	ssa.BlockPPC64LE: {ppc64.ABLE, ppc64.ABGT, false, false},
	ssa.BlockPPC64GT: {ppc64.ABGT, ppc64.ABLE, false, false},

	// TODO: need to work FP comparisons into block jumps
	ssa.BlockPPC64FLT: {ppc64.ABLT, ppc64.ABGE, false, false},
	ssa.BlockPPC64FGE: {ppc64.ABGT, ppc64.ABLT, true, true}, // GE = GT or EQ; !GE = LT or UN
	ssa.BlockPPC64FLE: {ppc64.ABLT, ppc64.ABGT, true, true}, // LE = LT or EQ; !LE = GT or UN
	ssa.BlockPPC64FGT: {ppc64.ABGT, ppc64.ABLE, false, false},
}

func ssaGenBlock(s *ssagen.State, b, next *ssa.Block) {
	switch b.Kind {
	case ssa.BlockDefer:
		// defer returns in R3:
		// 0 if we should continue executing
		// 1 if we should jump to deferreturn call
		p := s.Prog(ppc64.ACMP)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = ppc64.REG_R3
		p.To.Type = obj.TYPE_CONST
		p.To.Offset = 0

		p = s.Prog(ppc64.ABNE)
		p.To.Type = obj.TYPE_BRANCH
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

	case ssa.BlockPPC64EQ, ssa.BlockPPC64NE,
		ssa.BlockPPC64LT, ssa.BlockPPC64GE,
		ssa.BlockPPC64LE, ssa.BlockPPC64GT,
		ssa.BlockPPC64FLT, ssa.BlockPPC64FGE,
		ssa.BlockPPC64FLE, ssa.BlockPPC64FGT:
		jmp := blockJump[b.Kind]
		switch next {
		case b.Succs[0].Block():
			s.Br(jmp.invasm, b.Succs[1].Block())
			if jmp.invasmun {
				// TODO: The second branch is probably predict-not-taken since it is for FP unordered
				s.Br(ppc64.ABVS, b.Succs[1].Block())
			}
		case b.Succs[1].Block():
			s.Br(jmp.asm, b.Succs[0].Block())
			if jmp.asmeq {
				s.Br(ppc64.ABEQ, b.Succs[0].Block())
			}
		default:
			if b.Likely != ssa.BranchUnlikely {
				s.Br(jmp.asm, b.Succs[0].Block())
				if jmp.asmeq {
					s.Br(ppc64.ABEQ, b.Succs[0].Block())
				}
				s.Br(obj.AJMP, b.Succs[1].Block())
			} else {
				s.Br(jmp.invasm, b.Succs[1].Block())
				if jmp.invasmun {
					// TODO: The second branch is probably predict-not-taken since it is for FP unordered
					s.Br(ppc64.ABVS, b.Succs[1].Block())
				}
				s.Br(obj.AJMP, b.Succs[0].Block())
			}
		}
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

"""



```