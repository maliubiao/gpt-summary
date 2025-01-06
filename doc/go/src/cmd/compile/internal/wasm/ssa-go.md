Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a functional summary of the `ssa.go` file within the `cmd/compile/internal/wasm` package, its purpose, examples, command-line arguments, and potential pitfalls. This points to an analysis focusing on code generation for the WebAssembly target.

2. **Initial Scan and Package Context:** The `package wasm` immediately tells us this code is specific to the WebAssembly port of the Go compiler. The imports provide crucial context:
    * `cmd/compile/internal/base`, `ir`, `logopt`, `objw`, `ssa`, `ssagen`, `types`:  These are all core Go compiler components, indicating this file is deeply involved in the compilation process, specifically the Static Single Assignment (SSA) phase for code generation.
    * `cmd/internal/obj`, `cmd/internal/obj/wasm`: These are related to the object file format and the WebAssembly-specific instruction set.
    * `internal/buildcfg`: This suggests configuration options might influence the generated code.

3. **Core Data Structures and Functions:** Looking at the top-level functions and data structures provides a high-level overview:
    * `Init(arch *ssagen.ArchInfo)`:  This function likely initializes the WebAssembly-specific architecture information within the SSA framework.
    * `zeroRange`, `ginsnop`: These look like utility functions for generating specific WebAssembly instructions or sequences. `zeroRange` hints at memory manipulation.
    * `ssaMarkMoves`, `ssaGenValue`, `ssaGenBlock`: These are clearly the core functions responsible for generating WebAssembly code based on the SSA representation of Go code. The "ssa" prefix reinforces this.

4. **Analyzing the Comments:** The extensive multi-line comment at the beginning is incredibly valuable. It details the key differences and challenges in implementing Go for WebAssembly:
    * **PCs:**  Wasm doesn't have traditional program counters, so they are simulated using function and block IDs. This leads to the `F<<16+B` encoding.
    * **Threads:** Wasm's lack of threads requires simulating them through stack management and goroutine switching. This explains the "exit immediately flag" and the saving/restoring of return addresses on the Go stack.
    * **Stack Pointer:** The global stack pointer and its caching are explained.
    * **Calling Convention:**  The description of how arguments, return values, and "resume addresses" are handled on the Go stack is crucial. The `(i32)->i32` Wasm function type is important.
    * **Callsite and Prologue/Epilogue:**  These sections provide the concrete steps involved in function calls and returns, revealing how the stack and registers are manipulated.
    * **Global Variables:** The description of globals 0, 1, and 2 as SP, CTXT, and GP is vital for understanding register usage.

5. **Deep Dive into `ssaGenValue` and `ssaGenBlock`:** These functions are the heart of the code generation process. Analyzing their `switch` statements reveals how different Go SSA operations are translated into WebAssembly instructions.
    * **`ssaGenBlock`:**  Handles control flow: `BlockPlain` (jumps), `BlockIf` (conditional branches), `BlockRet` (returns), `BlockDefer` (defer statements). The `ARESUMEPOINT` instruction is noteworthy.
    * **`ssaGenValue`:**  Handles various operations:
        * **Calls:** `OpWasmLoweredStaticCall`, `OpWasmLoweredClosureCall`, `OpWasmLoweredInterCall`, `OpWasmLoweredTailCall` demonstrate how function calls (static, closure, interface, tail) are translated. The use of `ACALL`, `ARET`, and the handling of `deferreturn` are significant.
        * **Memory Operations:** `OpWasmLoweredMove`, `OpWasmLoweredZero`, `OpWasmI64Store*`, `OpLoadReg`, `OpStoreReg` show how memory is accessed and manipulated.
        * **Nil Checks:** `OpWasmLoweredNilCheck` shows how null pointer checks are implemented.
        * **Write Barriers:** `OpWasmLoweredWB` relates to garbage collection.
        * **Constants and Conversions:** Various `OpWasm*Const` and `OpWasmLoweredConvert` operations.
        * **Arithmetic and Logical Operations:**  A wide range of `OpWasmI64*` and `OpWasmF*` operations.
        * **Special Operations:** `OpWasmLoweredGetClosurePtr`, `OpWasmLoweredGetCallerPC`, `OpWasmLoweredGetCallerSP`, `OpWasmLoweredAddr`.

6. **Inferring Go Features and Examples:**  Based on the analysis of `ssaGenValue` and the comments, we can infer the Go features being implemented:
    * **Function Calls:** The various call operations clearly implement Go function calls.
    * **Goroutines and Defer:** The handling of the stack, return addresses, and the `BlockDefer` case directly relate to goroutines and the `defer` keyword.
    * **Pointers and Memory Access:** The load/store operations and nil checks implement Go's pointer semantics.
    * **Data Types:**  The handling of different integer (`I64`, `I32`), float (`F32`, `F64`), and boolean types is evident.
    * **Closures:** `OpWasmLoweredClosureCall` and `OpWasmLoweredGetClosurePtr` indicate support for closures.
    * **Interfaces:** `OpWasmLoweredInterCall` suggests interface calls are supported.
    * **Garbage Collection:** The write barrier operation (`OpWasmLoweredWB`) shows integration with the Go runtime's garbage collector.

7. **Command-Line Arguments and Potential Pitfalls:**  The code itself doesn't directly process command-line arguments. However, the import of `internal/buildcfg` hints that build-time flags might influence the generated code (e.g., the `buildcfg.GOWASM.SatConv` check). The comments about simulating threads and the unusual calling convention point to potential complexities and areas where developers unfamiliar with the Wasm port might make mistakes. The "OnWasmStack" logic and the need to carefully manage the Go stack also suggest potential pitfalls.

8. **Structuring the Answer:**  Organize the findings into the requested categories: functionality, Go feature implementation (with examples), code reasoning (including assumptions), command-line arguments, and common mistakes. Use clear and concise language. Provide concrete Go examples to illustrate the inferred features. Highlight the key assumptions made during the code analysis.

9. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check if the examples are correct and the explanations are easy to understand.

This detailed breakdown exemplifies the systematic approach needed to understand complex code like a compiler backend. It involves understanding the overall context, identifying key components, analyzing specific functionalities, and drawing logical inferences based on the code and its comments.
这是 `go/src/cmd/compile/internal/wasm/ssa.go` 文件的一部分，它属于 Go 编译器针对 WebAssembly 目标的后端实现。  这个文件的主要功能是**将 Go 语言的 SSA 中间表示转换为 WebAssembly 的指令序列**。

更具体地说，它实现了 Go 编译器 SSA 阶段的特定于 WebAssembly 架构的部分，负责生成实际的 WebAssembly 代码。

以下是其功能的详细列举：

**核心功能：**

1. **架构初始化 (`Init` 函数):**
   - 设置 WebAssembly 的链接架构 (`arch.LinkArch = &wasm.Linkwasm`).
   - 定义 WebAssembly 架构的寄存器，例如栈指针 (`arch.REGSP = wasm.REG_SP`).
   - 设置最大宽度 (`arch.MAXWIDTH = 1 << 50`).
   - 关联用于生成特定 WebAssembly 指令的函数，例如 `zeroRange`, `ginsnop`, `ssaMarkMoves`, `ssaGenValue`, `ssaGenBlock`.

2. **生成 WebAssembly 指令的辅助函数:**
   - `zeroRange`: 生成将指定内存范围清零为 0 的 WebAssembly 指令序列。
   - `ginsnop`: 生成 WebAssembly 的 `nop` 指令。

3. **SSA 到 WebAssembly 的转换核心函数:**
   - `ssaMarkMoves`: (目前为空)  可能用于标记需要在寄存器之间移动的数据，但在当前的 WebAssembly 实现中可能不需要显式的寄存器分配。
   - `ssaGenValue`:  **核心函数，负责根据 SSA 的 `Value` (操作) 生成相应的 WebAssembly 指令。** 它处理各种 Go 语言的操作，例如函数调用、内存操作、算术运算、比较等，并将它们转换为 WebAssembly 的指令。
   - `ssaGenBlock`: **负责根据 SSA 的 `Block` (控制流块) 生成相应的 WebAssembly 指令。** 它处理不同类型的控制流，例如顺序执行、条件分支、返回、defer 等。

**可以推理出的 Go 语言功能实现以及 Go 代码示例：**

基于代码中的 `ssaGenValue` 和 `ssaGenBlock` 函数，我们可以推断出它正在实现以下 Go 语言功能：

1. **函数调用 (包括普通调用、闭包调用、接口调用、尾调用):**
   - 代码中处理了 `ssa.OpWasmLoweredStaticCall`, `ssa.OpWasmLoweredClosureCall`, `ssa.OpWasmLoweredInterCall`, `ssa.OpWasmLoweredTailCall` 等操作码。
   - 它涉及到将参数压入 Go 栈，调用 WebAssembly 函数，以及处理返回值。

   ```go
   package main

   func add(a, b int32) int32 {
       return a + b
   }

   func main() {
       result := add(10, 20)
       println(result)
   }
   ```

   **假设的输入 SSA (简化):**  对于 `add(10, 20)` 这个调用，可能会有类似的 SSA 表示：

   ```
   v1 = Const32 <int32> 10
   v2 = Const32 <int32> 20
   v3 = StaticCall <int32> "main.add"(v1, v2)
   // ... 后续处理 v3
   ```

   **假设的输出 WebAssembly (简化):** `ssaGenValue` 对于 `StaticCall` 可能会生成如下指令：

   ```wasm
   ;; 将参数压入 Go 栈 (此处简化)
   i32.const 10
   i32.const 20
   ;; 调用 main.add 函数
   call $main.add
   ;; 从 Go 栈获取返回值 (此处简化)
   ```

2. **内存操作 (读、写、清零、拷贝):**
   - 代码中处理了 `ssa.OpWasmI64Store*`, `ssa.OpWasmF*Store`, `ssa.OpWasmI64Load*`, `ssa.OpWasmF*Load`, `ssa.OpWasmLoweredMove`, `ssa.OpWasmLoweredZero` 等操作码。

   ```go
   package main

   func main() {
       var x int64 = 100
       var y int64
       y = x
       println(y)
   }
   ```

   **假设的输入 SSA (简化):** 对于 `y = x` 这个操作：

   ```
   v1 = LocalAddr <*int64> {y}
   v2 = LocalAddr <*int64> {x}
   v3 = Load <int64> v2
   Store v1, v3
   ```

   **假设的输出 WebAssembly (简化):** `ssaGenValue` 对于 `Load` 和 `Store` 可能会生成如下指令：

   ```wasm
   ;; 获取 x 的地址 (简化)
   local.get $x_addr
   ;; 从 x 的地址加载值
   i64.load
   ;; 获取 y 的地址 (简化)
   local.get $y_addr
   ;; 将加载的值存储到 y 的地址
   i64.store
   ```

3. **算术和逻辑运算:**
   - 代码中处理了 `ssa.OpWasmI64Add`, `ssa.OpWasmI64Sub`, `ssa.OpWasmI64Mul`, `ssa.OpWasmI64Div*`, `ssa.OpWasmI64And`, `ssa.OpWasmI64Or`, `ssa.OpWasmI64Xor` 以及浮点运算等。

   ```go
   package main

   func main() {
       a := 5
       b := 3
       c := a * b
       println(c)
   }
   ```

   **假设的输入 SSA (简化):** 对于 `c := a * b`：

   ```
   v1 = LocalAddr <*int> {a}
   v2 = Load <int> v1
   v3 = LocalAddr <*int> {b}
   v4 = Load <int> v3
   v5 = Mul <int> v2, v4
   v6 = LocalAddr <*int> {c}
   Store v6, v5
   ```

   **假设的输出 WebAssembly (简化):**  `ssaGenValue` 对于 `Mul` 可能会生成：

   ```wasm
   ;; 加载 a 的值
   local.get $a
   ;; 加载 b 的值
   local.get $b
   ;; 执行乘法
   i32.mul
   ;; ... 后续存储到 c
   ```

4. **比较运算:**
   - 代码中处理了 `ssa.OpWasmI64Eq`, `ssa.OpWasmI64Ne`, `ssa.OpWasmI64LtS`, `ssa.OpWasmI64GtU` 等比较操作。

   ```go
   package main

   func main() {
       a := 10
       b := 5
       if a > b {
           println("a is greater than b")
       }
   }
   ```

   **假设的输入 SSA (简化):** 对于 `a > b`：

   ```
   v1 = LocalAddr <*int> {a}
   v2 = Load <int> v1
   v3 = LocalAddr <*int> {b}
   v4 = Load <int> v3
   v5 = GtS <bool> v2, v4  // 有符号大于
   // ... 后续的条件分支基于 v5
   ```

   **假设的输出 WebAssembly (简化):** `ssaGenValue` 对于 `GtS` 可能会生成：

   ```wasm
   ;; 加载 a 的值
   local.get $a
   ;; 加载 b 的值
   local.get $b
   ;; 执行有符号大于比较
   i32.gt_s
   ;; ... 后续的条件分支
   ```

5. **控制流 (if, return, defer):**
   - `ssaGenBlock` 函数处理了 `ssa.BlockPlain` (简单跳转), `ssa.BlockIf` (条件分支), `ssa.BlockRet` (返回), `ssa.BlockDefer` (defer 语句)。

   ```go
   package main

   func example(x int) {
       defer println("cleanup")
       if x > 0 {
           println("positive")
           return
       }
       println("non-positive")
   }
   ```

   `ssaGenBlock` 会为 `if` 语句生成条件分支指令，为 `return` 生成返回指令，为 `defer` 语句生成在函数返回前执行的代码。

**命令行参数的具体处理：**

这个代码片段本身并不直接处理命令行参数。命令行参数的处理通常发生在 `cmd/compile/internal/gc` 包或其他更上层的编译器组件中。  但是，编译器的某些命令行选项可能会影响到 SSA 的生成和优化，进而影响到 `wasm/ssa.go` 中生成的 WebAssembly 代码。例如，优化级别可能会影响生成的代码量和性能。

**使用者易犯错的点 (针对 WebAssembly 目标的 Go 开发)：**

1. **对 WebAssembly 的执行模型不熟悉:**  WebAssembly 不是一个传统的机器架构，它的内存模型、调用约定、以及缺少线程等特性与传统的系统有很大不同。开发者需要理解这些差异，例如：
   - Go 的 goroutine 在 WebAssembly 中是被模拟的，性能开销可能较高。
   - 直接操作内存需要特别注意，因为 WebAssembly 的内存是线性的。

2. **依赖于某些在 WebAssembly 中不可用的 Go 标准库功能:**  并非所有的 Go 标准库功能都能在 WebAssembly 中完美运行或得到支持。  例如，涉及系统调用的功能可能需要特殊的实现或不可用。

3. **对 Go 的 wasm 特有类型和 API 不熟悉:**  Go 提供了 `syscall/js` 包用于与 JavaScript 环境交互。开发者需要了解如何使用这些 API 来与 WebAssembly 容器进行通信。

4. **误解 WebAssembly 的性能特性:**  虽然 WebAssembly 旨在提供接近原生的性能，但在某些场景下，由于模拟或其他开销，其性能可能不如原生代码。

**举例说明使用者易犯的错误：**

```go
package main

import "time"

func main() {
    // 错误示例：直接使用 time.Sleep，可能导致在 WebAssembly 环境中阻塞整个执行
    time.Sleep(time.Second)
    println("Done sleeping")
}
```

在 WebAssembly 环境中，直接使用 `time.Sleep` 可能会导致问题，因为它依赖于操作系统级别的线程阻塞。由于 WebAssembly 通常是单线程的（或者模拟多线程），这种阻塞可能会影响整个应用程序的运行。  正确的做法可能是使用基于事件的异步机制，或者与 JavaScript 环境进行交互来实现延时。

总之，`go/src/cmd/compile/internal/wasm/ssa.go` 是 Go 编译器 WebAssembly 后端的核心组成部分，负责将 Go 代码的中间表示转换为可在 WebAssembly 虚拟机上执行的指令。理解其功能有助于深入了解 Go 如何在 WebAssembly 环境中运行。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/wasm/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wasm

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/ssagen"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/obj/wasm"
	"internal/buildcfg"
)

/*

   Wasm implementation
   -------------------

   Wasm is a strange Go port because the machine isn't
   a register-based machine, threads are different, code paths
   are different, etc. We outline those differences here.

   See the design doc for some additional info on this topic.
   https://docs.google.com/document/d/131vjr4DH6JFnb-blm_uRdaC0_Nv3OUwjEY5qVCxCup4/edit#heading=h.mjo1bish3xni

   PCs:

   Wasm doesn't have PCs in the normal sense that you can jump
   to or call to. Instead, we simulate these PCs using our own construct.

   A PC in the Wasm implementation is the combination of a function
   ID and a block ID within that function. The function ID is an index
   into a function table which transfers control to the start of the
   function in question, and the block ID is a sequential integer
   indicating where in the function we are.

   Every function starts with a branch table which transfers control
   to the place in the function indicated by the block ID. The block
   ID is provided to the function as the sole Wasm argument.

   Block IDs do not encode every possible PC. They only encode places
   in the function where it might be suspended. Typically these places
   are call sites.

   Sometimes we encode the function ID and block ID separately. When
   recorded together as a single integer, we use the value F<<16+B.

   Threads:

   Wasm doesn't (yet) have threads. We have to simulate threads by
   keeping goroutine stacks in linear memory and unwinding
   the Wasm stack each time we want to switch goroutines.

   To support unwinding a stack, each function call returns on the Wasm
   stack a boolean that tells the function whether it should return
   immediately or not. When returning immediately, a return address
   is left on the top of the Go stack indicating where the goroutine
   should be resumed.

   Stack pointer:

   There is a single global stack pointer which records the stack pointer
   used by the currently active goroutine. This is just an address in
   linear memory where the Go runtime is maintaining the stack for that
   goroutine.

   Functions cache the global stack pointer in a local variable for
   faster access, but any changes must be spilled to the global variable
   before any call and restored from the global variable after any call.

   Calling convention:

   All Go arguments and return values are passed on the Go stack, not
   the wasm stack. In addition, return addresses are pushed on the
   Go stack at every call point. Return addresses are not used during
   normal execution, they are used only when resuming goroutines.
   (So they are not really a "return address", they are a "resume address".)

   All Go functions have the Wasm type (i32)->i32. The argument
   is the block ID and the return value is the exit immediately flag.

   Callsite:
    - write arguments to the Go stack (starting at SP+0)
    - push return address to Go stack (8 bytes)
    - write local SP to global SP
    - push 0 (type i32) to Wasm stack
    - issue Call
    - restore local SP from global SP
    - pop int32 from top of Wasm stack. If nonzero, exit function immediately.
    - use results from Go stack (starting at SP+sizeof(args))
       - note that the callee will have popped the return address

   Prologue:
    - initialize local SP from global SP
    - jump to the location indicated by the block ID argument
      (which appears in local variable 0)
    - at block 0
      - check for Go stack overflow, call morestack if needed
      - subtract frame size from SP
      - note that arguments now start at SP+framesize+8

   Normal epilogue:
    - pop frame from Go stack
    - pop return address from Go stack
    - push 0 (type i32) on the Wasm stack
    - return
   Exit immediately epilogue:
    - push 1 (type i32) on the Wasm stack
    - return
    - note that the return address and stack frame are left on the Go stack

   The main loop that executes goroutines is wasm_pc_f_loop, in
   runtime/rt0_js_wasm.s. It grabs the saved return address from
   the top of the Go stack (actually SP-8?), splits it up into F
   and B parts, then calls F with its Wasm argument set to B.

   Note that when resuming a goroutine, only the most recent function
   invocation of that goroutine appears on the Wasm stack. When that
   Wasm function returns normally, the next most recent frame will
   then be started up by wasm_pc_f_loop.

   Global 0 is SP (stack pointer)
   Global 1 is CTXT (closure pointer)
   Global 2 is GP (goroutine pointer)
*/

func Init(arch *ssagen.ArchInfo) {
	arch.LinkArch = &wasm.Linkwasm
	arch.REGSP = wasm.REG_SP
	arch.MAXWIDTH = 1 << 50

	arch.ZeroRange = zeroRange
	arch.Ginsnop = ginsnop

	arch.SSAMarkMoves = ssaMarkMoves
	arch.SSAGenValue = ssaGenValue
	arch.SSAGenBlock = ssaGenBlock
}

func zeroRange(pp *objw.Progs, p *obj.Prog, off, cnt int64, state *uint32) *obj.Prog {
	if cnt == 0 {
		return p
	}
	if cnt%8 != 0 {
		base.Fatalf("zerorange count not a multiple of widthptr %d", cnt)
	}

	for i := int64(0); i < cnt; i += 8 {
		p = pp.Append(p, wasm.AGet, obj.TYPE_REG, wasm.REG_SP, 0, 0, 0, 0)
		p = pp.Append(p, wasm.AI64Const, obj.TYPE_CONST, 0, 0, 0, 0, 0)
		p = pp.Append(p, wasm.AI64Store, 0, 0, 0, obj.TYPE_CONST, 0, off+i)
	}

	return p
}

func ginsnop(pp *objw.Progs) *obj.Prog {
	return pp.Prog(wasm.ANop)
}

func ssaMarkMoves(s *ssagen.State, b *ssa.Block) {
}

func ssaGenBlock(s *ssagen.State, b, next *ssa.Block) {
	switch b.Kind {
	case ssa.BlockPlain:
		if next != b.Succs[0].Block() {
			s.Br(obj.AJMP, b.Succs[0].Block())
		}

	case ssa.BlockIf:
		switch next {
		case b.Succs[0].Block():
			// if false, jump to b.Succs[1]
			getValue32(s, b.Controls[0])
			s.Prog(wasm.AI32Eqz)
			s.Prog(wasm.AIf)
			s.Br(obj.AJMP, b.Succs[1].Block())
			s.Prog(wasm.AEnd)
		case b.Succs[1].Block():
			// if true, jump to b.Succs[0]
			getValue32(s, b.Controls[0])
			s.Prog(wasm.AIf)
			s.Br(obj.AJMP, b.Succs[0].Block())
			s.Prog(wasm.AEnd)
		default:
			// if true, jump to b.Succs[0], else jump to b.Succs[1]
			getValue32(s, b.Controls[0])
			s.Prog(wasm.AIf)
			s.Br(obj.AJMP, b.Succs[0].Block())
			s.Prog(wasm.AEnd)
			s.Br(obj.AJMP, b.Succs[1].Block())
		}

	case ssa.BlockRet:
		s.Prog(obj.ARET)

	case ssa.BlockExit, ssa.BlockRetJmp:

	case ssa.BlockDefer:
		p := s.Prog(wasm.AGet)
		p.From = obj.Addr{Type: obj.TYPE_REG, Reg: wasm.REG_RET0}
		s.Prog(wasm.AI64Eqz)
		s.Prog(wasm.AI32Eqz)
		s.Prog(wasm.AIf)
		s.Br(obj.AJMP, b.Succs[1].Block())
		s.Prog(wasm.AEnd)
		if next != b.Succs[0].Block() {
			s.Br(obj.AJMP, b.Succs[0].Block())
		}

	default:
		panic("unexpected block")
	}

	// Entry point for the next block. Used by the JMP in goToBlock.
	s.Prog(wasm.ARESUMEPOINT)

	if s.OnWasmStackSkipped != 0 {
		panic("wasm: bad stack")
	}
}

func ssaGenValue(s *ssagen.State, v *ssa.Value) {
	switch v.Op {
	case ssa.OpWasmLoweredStaticCall, ssa.OpWasmLoweredClosureCall, ssa.OpWasmLoweredInterCall, ssa.OpWasmLoweredTailCall:
		s.PrepareCall(v)
		if call, ok := v.Aux.(*ssa.AuxCall); ok && call.Fn == ir.Syms.Deferreturn {
			// The runtime needs to inject jumps to
			// deferreturn calls using the address in
			// _func.deferreturn. Hence, the call to
			// deferreturn must itself be a resumption
			// point so it gets a target PC.
			s.Prog(wasm.ARESUMEPOINT)
		}
		if v.Op == ssa.OpWasmLoweredClosureCall {
			getValue64(s, v.Args[1])
			setReg(s, wasm.REG_CTXT)
		}
		if call, ok := v.Aux.(*ssa.AuxCall); ok && call.Fn != nil {
			sym := call.Fn
			p := s.Prog(obj.ACALL)
			p.To = obj.Addr{Type: obj.TYPE_MEM, Name: obj.NAME_EXTERN, Sym: sym}
			p.Pos = v.Pos
			if v.Op == ssa.OpWasmLoweredTailCall {
				p.As = obj.ARET
			}
		} else {
			getValue64(s, v.Args[0])
			p := s.Prog(obj.ACALL)
			p.To = obj.Addr{Type: obj.TYPE_NONE}
			p.Pos = v.Pos
		}

	case ssa.OpWasmLoweredMove:
		getValue32(s, v.Args[0])
		getValue32(s, v.Args[1])
		i32Const(s, int32(v.AuxInt))
		s.Prog(wasm.AMemoryCopy)

	case ssa.OpWasmLoweredZero:
		getValue32(s, v.Args[0])
		i32Const(s, 0)
		i32Const(s, int32(v.AuxInt))
		s.Prog(wasm.AMemoryFill)

	case ssa.OpWasmLoweredNilCheck:
		getValue64(s, v.Args[0])
		s.Prog(wasm.AI64Eqz)
		s.Prog(wasm.AIf)
		p := s.Prog(wasm.ACALLNORESUME)
		p.To = obj.Addr{Type: obj.TYPE_MEM, Name: obj.NAME_EXTERN, Sym: ir.Syms.SigPanic}
		s.Prog(wasm.AEnd)
		if logopt.Enabled() {
			logopt.LogOpt(v.Pos, "nilcheck", "genssa", v.Block.Func.Name)
		}
		if base.Debug.Nil != 0 && v.Pos.Line() > 1 { // v.Pos.Line()==1 in generated wrappers
			base.WarnfAt(v.Pos, "generated nil check")
		}

	case ssa.OpWasmLoweredWB:
		p := s.Prog(wasm.ACall)
		// AuxInt encodes how many buffer entries we need.
		p.To = obj.Addr{Type: obj.TYPE_MEM, Name: obj.NAME_EXTERN, Sym: ir.Syms.GCWriteBarrier[v.AuxInt-1]}
		setReg(s, v.Reg0()) // move result from wasm stack to register local

	case ssa.OpWasmI64Store8, ssa.OpWasmI64Store16, ssa.OpWasmI64Store32, ssa.OpWasmI64Store, ssa.OpWasmF32Store, ssa.OpWasmF64Store:
		getValue32(s, v.Args[0])
		getValue64(s, v.Args[1])
		p := s.Prog(v.Op.Asm())
		p.To = obj.Addr{Type: obj.TYPE_CONST, Offset: v.AuxInt}

	case ssa.OpStoreReg:
		getReg(s, wasm.REG_SP)
		getValue64(s, v.Args[0])
		p := s.Prog(storeOp(v.Type))
		ssagen.AddrAuto(&p.To, v)

	case ssa.OpClobber, ssa.OpClobberReg:
		// TODO: implement for clobberdead experiment. Nop is ok for now.

	default:
		if v.Type.IsMemory() {
			return
		}
		if v.OnWasmStack {
			s.OnWasmStackSkipped++
			// If a Value is marked OnWasmStack, we don't generate the value and store it to a register now.
			// Instead, we delay the generation to when the value is used and then directly generate it on the WebAssembly stack.
			return
		}
		ssaGenValueOnStack(s, v, true)
		if s.OnWasmStackSkipped != 0 {
			panic("wasm: bad stack")
		}
		setReg(s, v.Reg())
	}
}

func ssaGenValueOnStack(s *ssagen.State, v *ssa.Value, extend bool) {
	switch v.Op {
	case ssa.OpWasmLoweredGetClosurePtr:
		getReg(s, wasm.REG_CTXT)

	case ssa.OpWasmLoweredGetCallerPC:
		p := s.Prog(wasm.AI64Load)
		// Caller PC is stored 8 bytes below first parameter.
		p.From = obj.Addr{
			Type:   obj.TYPE_MEM,
			Name:   obj.NAME_PARAM,
			Offset: -8,
		}

	case ssa.OpWasmLoweredGetCallerSP:
		p := s.Prog(wasm.AGet)
		// Caller SP is the address of the first parameter.
		p.From = obj.Addr{
			Type:   obj.TYPE_ADDR,
			Name:   obj.NAME_PARAM,
			Reg:    wasm.REG_SP,
			Offset: 0,
		}

	case ssa.OpWasmLoweredAddr:
		if v.Aux == nil { // address of off(SP), no symbol
			getValue64(s, v.Args[0])
			i64Const(s, v.AuxInt)
			s.Prog(wasm.AI64Add)
			break
		}
		p := s.Prog(wasm.AGet)
		p.From.Type = obj.TYPE_ADDR
		switch v.Aux.(type) {
		case *obj.LSym:
			ssagen.AddAux(&p.From, v)
		case *ir.Name:
			p.From.Reg = v.Args[0].Reg()
			ssagen.AddAux(&p.From, v)
		default:
			panic("wasm: bad LoweredAddr")
		}

	case ssa.OpWasmLoweredConvert:
		getValue64(s, v.Args[0])

	case ssa.OpWasmSelect:
		getValue64(s, v.Args[0])
		getValue64(s, v.Args[1])
		getValue32(s, v.Args[2])
		s.Prog(v.Op.Asm())

	case ssa.OpWasmI64AddConst:
		getValue64(s, v.Args[0])
		i64Const(s, v.AuxInt)
		s.Prog(v.Op.Asm())

	case ssa.OpWasmI64Const:
		i64Const(s, v.AuxInt)

	case ssa.OpWasmF32Const:
		f32Const(s, v.AuxFloat())

	case ssa.OpWasmF64Const:
		f64Const(s, v.AuxFloat())

	case ssa.OpWasmI64Load8U, ssa.OpWasmI64Load8S, ssa.OpWasmI64Load16U, ssa.OpWasmI64Load16S, ssa.OpWasmI64Load32U, ssa.OpWasmI64Load32S, ssa.OpWasmI64Load, ssa.OpWasmF32Load, ssa.OpWasmF64Load:
		getValue32(s, v.Args[0])
		p := s.Prog(v.Op.Asm())
		p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: v.AuxInt}

	case ssa.OpWasmI64Eqz:
		getValue64(s, v.Args[0])
		s.Prog(v.Op.Asm())
		if extend {
			s.Prog(wasm.AI64ExtendI32U)
		}

	case ssa.OpWasmI64Eq, ssa.OpWasmI64Ne, ssa.OpWasmI64LtS, ssa.OpWasmI64LtU, ssa.OpWasmI64GtS, ssa.OpWasmI64GtU, ssa.OpWasmI64LeS, ssa.OpWasmI64LeU, ssa.OpWasmI64GeS, ssa.OpWasmI64GeU,
		ssa.OpWasmF32Eq, ssa.OpWasmF32Ne, ssa.OpWasmF32Lt, ssa.OpWasmF32Gt, ssa.OpWasmF32Le, ssa.OpWasmF32Ge,
		ssa.OpWasmF64Eq, ssa.OpWasmF64Ne, ssa.OpWasmF64Lt, ssa.OpWasmF64Gt, ssa.OpWasmF64Le, ssa.OpWasmF64Ge:
		getValue64(s, v.Args[0])
		getValue64(s, v.Args[1])
		s.Prog(v.Op.Asm())
		if extend {
			s.Prog(wasm.AI64ExtendI32U)
		}

	case ssa.OpWasmI64Add, ssa.OpWasmI64Sub, ssa.OpWasmI64Mul, ssa.OpWasmI64DivU, ssa.OpWasmI64RemS, ssa.OpWasmI64RemU, ssa.OpWasmI64And, ssa.OpWasmI64Or, ssa.OpWasmI64Xor, ssa.OpWasmI64Shl, ssa.OpWasmI64ShrS, ssa.OpWasmI64ShrU, ssa.OpWasmI64Rotl,
		ssa.OpWasmF32Add, ssa.OpWasmF32Sub, ssa.OpWasmF32Mul, ssa.OpWasmF32Div, ssa.OpWasmF32Copysign,
		ssa.OpWasmF64Add, ssa.OpWasmF64Sub, ssa.OpWasmF64Mul, ssa.OpWasmF64Div, ssa.OpWasmF64Copysign:
		getValue64(s, v.Args[0])
		getValue64(s, v.Args[1])
		s.Prog(v.Op.Asm())

	case ssa.OpWasmI32Rotl:
		getValue32(s, v.Args[0])
		getValue32(s, v.Args[1])
		s.Prog(wasm.AI32Rotl)
		s.Prog(wasm.AI64ExtendI32U)

	case ssa.OpWasmI64DivS:
		getValue64(s, v.Args[0])
		getValue64(s, v.Args[1])
		if v.Type.Size() == 8 {
			// Division of int64 needs helper function wasmDiv to handle the MinInt64 / -1 case.
			p := s.Prog(wasm.ACall)
			p.To = obj.Addr{Type: obj.TYPE_MEM, Name: obj.NAME_EXTERN, Sym: ir.Syms.WasmDiv}
			break
		}
		s.Prog(wasm.AI64DivS)

	case ssa.OpWasmI64TruncSatF32S, ssa.OpWasmI64TruncSatF64S:
		getValue64(s, v.Args[0])
		if buildcfg.GOWASM.SatConv {
			s.Prog(v.Op.Asm())
		} else {
			if v.Op == ssa.OpWasmI64TruncSatF32S {
				s.Prog(wasm.AF64PromoteF32)
			}
			p := s.Prog(wasm.ACall)
			p.To = obj.Addr{Type: obj.TYPE_MEM, Name: obj.NAME_EXTERN, Sym: ir.Syms.WasmTruncS}
		}

	case ssa.OpWasmI64TruncSatF32U, ssa.OpWasmI64TruncSatF64U:
		getValue64(s, v.Args[0])
		if buildcfg.GOWASM.SatConv {
			s.Prog(v.Op.Asm())
		} else {
			if v.Op == ssa.OpWasmI64TruncSatF32U {
				s.Prog(wasm.AF64PromoteF32)
			}
			p := s.Prog(wasm.ACall)
			p.To = obj.Addr{Type: obj.TYPE_MEM, Name: obj.NAME_EXTERN, Sym: ir.Syms.WasmTruncU}
		}

	case ssa.OpWasmF32DemoteF64:
		getValue64(s, v.Args[0])
		s.Prog(v.Op.Asm())

	case ssa.OpWasmF64PromoteF32:
		getValue64(s, v.Args[0])
		s.Prog(v.Op.Asm())

	case ssa.OpWasmF32ConvertI64S, ssa.OpWasmF32ConvertI64U,
		ssa.OpWasmF64ConvertI64S, ssa.OpWasmF64ConvertI64U,
		ssa.OpWasmI64Extend8S, ssa.OpWasmI64Extend16S, ssa.OpWasmI64Extend32S,
		ssa.OpWasmF32Neg, ssa.OpWasmF32Sqrt, ssa.OpWasmF32Trunc, ssa.OpWasmF32Ceil, ssa.OpWasmF32Floor, ssa.OpWasmF32Nearest, ssa.OpWasmF32Abs,
		ssa.OpWasmF64Neg, ssa.OpWasmF64Sqrt, ssa.OpWasmF64Trunc, ssa.OpWasmF64Ceil, ssa.OpWasmF64Floor, ssa.OpWasmF64Nearest, ssa.OpWasmF64Abs,
		ssa.OpWasmI64Ctz, ssa.OpWasmI64Clz, ssa.OpWasmI64Popcnt:
		getValue64(s, v.Args[0])
		s.Prog(v.Op.Asm())

	case ssa.OpLoadReg:
		p := s.Prog(loadOp(v.Type))
		ssagen.AddrAuto(&p.From, v.Args[0])

	case ssa.OpCopy:
		getValue64(s, v.Args[0])

	default:
		v.Fatalf("unexpected op: %s", v.Op)

	}
}

func isCmp(v *ssa.Value) bool {
	switch v.Op {
	case ssa.OpWasmI64Eqz, ssa.OpWasmI64Eq, ssa.OpWasmI64Ne, ssa.OpWasmI64LtS, ssa.OpWasmI64LtU, ssa.OpWasmI64GtS, ssa.OpWasmI64GtU, ssa.OpWasmI64LeS, ssa.OpWasmI64LeU, ssa.OpWasmI64GeS, ssa.OpWasmI64GeU,
		ssa.OpWasmF32Eq, ssa.OpWasmF32Ne, ssa.OpWasmF32Lt, ssa.OpWasmF32Gt, ssa.OpWasmF32Le, ssa.OpWasmF32Ge,
		ssa.OpWasmF64Eq, ssa.OpWasmF64Ne, ssa.OpWasmF64Lt, ssa.OpWasmF64Gt, ssa.OpWasmF64Le, ssa.OpWasmF64Ge:
		return true
	default:
		return false
	}
}

func getValue32(s *ssagen.State, v *ssa.Value) {
	if v.OnWasmStack {
		s.OnWasmStackSkipped--
		ssaGenValueOnStack(s, v, false)
		if !isCmp(v) {
			s.Prog(wasm.AI32WrapI64)
		}
		return
	}

	reg := v.Reg()
	getReg(s, reg)
	if reg != wasm.REG_SP {
		s.Prog(wasm.AI32WrapI64)
	}
}

func getValue64(s *ssagen.State, v *ssa.Value) {
	if v.OnWasmStack {
		s.OnWasmStackSkipped--
		ssaGenValueOnStack(s, v, true)
		return
	}

	reg := v.Reg()
	getReg(s, reg)
	if reg == wasm.REG_SP {
		s.Prog(wasm.AI64ExtendI32U)
	}
}

func i32Const(s *ssagen.State, val int32) {
	p := s.Prog(wasm.AI32Const)
	p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: int64(val)}
}

func i64Const(s *ssagen.State, val int64) {
	p := s.Prog(wasm.AI64Const)
	p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: val}
}

func f32Const(s *ssagen.State, val float64) {
	p := s.Prog(wasm.AF32Const)
	p.From = obj.Addr{Type: obj.TYPE_FCONST, Val: val}
}

func f64Const(s *ssagen.State, val float64) {
	p := s.Prog(wasm.AF64Const)
	p.From = obj.Addr{Type: obj.TYPE_FCONST, Val: val}
}

func getReg(s *ssagen.State, reg int16) {
	p := s.Prog(wasm.AGet)
	p.From = obj.Addr{Type: obj.TYPE_REG, Reg: reg}
}

func setReg(s *ssagen.State, reg int16) {
	p := s.Prog(wasm.ASet)
	p.To = obj.Addr{Type: obj.TYPE_REG, Reg: reg}
}

func loadOp(t *types.Type) obj.As {
	if t.IsFloat() {
		switch t.Size() {
		case 4:
			return wasm.AF32Load
		case 8:
			return wasm.AF64Load
		default:
			panic("bad load type")
		}
	}

	switch t.Size() {
	case 1:
		if t.IsSigned() {
			return wasm.AI64Load8S
		}
		return wasm.AI64Load8U
	case 2:
		if t.IsSigned() {
			return wasm.AI64Load16S
		}
		return wasm.AI64Load16U
	case 4:
		if t.IsSigned() {
			return wasm.AI64Load32S
		}
		return wasm.AI64Load32U
	case 8:
		return wasm.AI64Load
	default:
		panic("bad load type")
	}
}

func storeOp(t *types.Type) obj.As {
	if t.IsFloat() {
		switch t.Size() {
		case 4:
			return wasm.AF32Store
		case 8:
			return wasm.AF64Store
		default:
			panic("bad store type")
		}
	}

	switch t.Size() {
	case 1:
		return wasm.AI64Store8
	case 2:
		return wasm.AI64Store16
	case 4:
		return wasm.AI64Store32
	case 8:
		return wasm.AI64Store
	default:
		panic("bad store type")
	}
}

"""



```