Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding and Context:**

The first step is to recognize the file path: `go/src/cmd/internal/obj/mips/obj0.go`. This immediately tells us this code is part of the Go compiler toolchain, specifically the assembler (`obj`) for the MIPS architecture. The `internal` package indicates it's not meant for direct external use. The `obj0.go` naming convention within the `cmd/internal/obj` directory often signifies the first pass or initial stages of processing assembly code.

**2. High-Level Overview of Functionality (Reading Comments and Function Signatures):**

Next, scan the code for comments and function names. The initial comment block mentions several `.c` files and copyright information, suggesting this code was ported from an older assembler. The key functions are `progedit` and `preprocess`. Their names suggest their primary responsibilities:

*   `progedit`:  Likely modifies or rewrites individual assembly program instructions (`obj.Prog`).
*   `preprocess`:  Operates on a symbol (`obj.LSym`) representing a function, performing actions before the main assembly phase.

**3. Deep Dive into `progedit`:**

Focus on the `progedit` function. Analyze its actions step-by-step:

*   **Initialization:** Creates a `ctxt0` struct, which seems to hold context information. Resets `From.Class` and `To.Class` of the instruction.
*   **Branch Rewriting:**  Looks for jump/call instructions (`AJMP`, `AJAL`, `ARET`, etc.) and if the target is a symbol, sets the `To.Type` to `obj.TYPE_BRANCH`. This is a crucial optimization for the assembler to correctly handle jumps to symbolic labels.
*   **Floating-Point Constant Handling:**  If a `AMOVF` or `AMOVD` instruction has a floating-point constant as the source (`TYPE_FCONST`), it checks if the value is zero. If so, it rewrites the instruction to move zero from a register (likely for efficiency). Otherwise, it replaces the constant with a memory reference to a pre-defined symbol representing that constant. This is a common technique to avoid embedding floating-point literals directly in the instruction stream. The MIPS64 zero-double handling is a specific optimization.
*   **Large Constant Handling (64-bit):** For `AMOVV` (move 64-bit value), if the source is a large constant that doesn't fit in an immediate field, it's moved to memory, and the instruction is rewritten to load from that memory location. Similar to floating-point constants.
*   **Subtraction to Addition:**  A clever optimization:  `ASUB` instructions with constant operands are transformed into `AADD` with the negated constant. This simplifies the instruction set and potentially the instruction encoding.

**4. Deep Dive into `preprocess`:**

Now analyze the `preprocess` function:

*   **Initialization:**  Creates a `ctxt0`, checks for a valid function body.
*   **Frame Size Handling:**  Determines the stack frame size, handling the `NOFRAME` attribute.
*   **Leaf Function Detection:**  Identifies leaf functions (functions that don't call other functions).
*   **Instruction Marking:**  Iterates through the instructions, marking them with flags (`LABEL`, `LEAF`, `SYNC`, `BRANCH`). These marks are crucial for later optimization and code generation phases. Special handling for `ABFPT`/`ABFPF` is noted with the kernel bug workaround.
*   **RET Expansion:**  Handles `ARET` instructions, potentially inserting code to adjust the stack pointer and jump back to the caller. The handling of `retjmp` (returning to a specific address) is also present.
*   **Stack Management (Function Prologue):**  For non-leaf functions, it generates code to:
    *   Allocate stack space.
    *   Save the link register (return address).
    *   Potentially handle stack overflow checks (`stacksplit`).
    *   Potentially handle panic wrappers.
*   **`stacksplit` Function:** This is a separate function called by `preprocess`. It implements the logic for checking if there's enough stack space and calling `runtime.morestack` if needed. This is essential for Go's goroutine stack management.
*   **Instruction Scheduling (Conditional):**  Includes logic for instruction scheduling (reordering instructions to improve performance), but it's conditionally disabled by `nosched`. When enabled, it uses a `sched` function and a data structure to track dependencies between instructions.
*   **MOVD to MOVF Rewrite (32-bit):**  In 32-bit mode, `AMOVD` instructions are rewritten into two `AMOVF` instructions to avoid potential alignment issues.
*   **NOP Insertion:**  If instruction scheduling is disabled, it inserts NOP (no-operation) instructions after branch instructions. This is a simple way to fill delay slots on MIPS.

**5. Inference of Go Language Features:**

Based on the code, we can infer the following Go language features being implemented:

*   **Function Calls and Returns:** The handling of `AJAL` (jump and link), `ARET` (return), and the saving/restoring of the link register are directly related to function calls.
*   **Stack Management:** The `preprocess` and `stacksplit` functions deal extensively with stack frame allocation, stack overflow checks, and the `runtime.morestack` mechanism, which are fundamental to Go's goroutines.
*   **Floating-Point Numbers:** The handling of `TYPE_FCONST`, `AMOVF`, and `AMOVD` demonstrates support for floating-point constants and operations.
*   **Large Constants:**  The handling of `AMOVV` with large `TYPE_CONST` values shows how the compiler handles constants that don't fit directly into instructions.
*   **Function Wrappers:**  The code that checks for `cursym.Func().Text.From.Sym.Wrapper()` indicates support for function wrappers, likely used for features like `go:linkname`.
*   **Noframe Functions:** The `obj.AttrNoFrame` attribute and the associated handling show support for functions that don't have a traditional stack frame (e.g., leaf functions).
*   **Stack Probes/Splitting:** The `stacksplit` logic with `runtime.morestack` is a core part of Go's dynamic stack growth mechanism.
*   **Instruction Scheduling (Optimization):** Although conditionally disabled, the presence of the `sched` function indicates an attempt to optimize instruction order.

**6. Code Examples and Assumptions:**

Constructing code examples involves making assumptions about the intended behavior based on the code analysis. The examples for floating-point constants, large constants, and `ARET` expansion are relatively straightforward.

**7. Command-Line Parameters:**

The code mentions `ctxt.Flag_maymorestack`. This clearly indicates the handling of a command-line flag related to alternative stack growth mechanisms. The example explains how this flag might be used.

**8. Common Mistakes:**

Identify potential pitfalls based on the code:

*   Incorrect frame sizes for `NOFRAME` functions.
*   Attempting to use `BECOME` (tail calls) which are noted as unsupported.

**Self-Correction/Refinement during the thought process:**

*   **Initial thought:** The code might be directly generating machine code.
*   **Correction:** Realized it's operating on an intermediate representation (`obj.Prog`) within the assembler. The actual machine code generation happens later.
*   **Initial thought:** Instruction scheduling is always active.
*   **Correction:** Noticed the `nosched` variable and the conditional execution of the scheduling logic.
*   **Initial thought:**  `ctxt0` is just a simple context.
*   **Refinement:** Understood it holds crucial information like the current symbol, link context, and potentially other assembler state.

By following this structured approach, combining code reading, comment analysis, and inference, we can effectively understand the functionality of the provided Go code snippet.
好的，让我们来分析一下 `go/src/cmd/internal/obj/mips/obj0.go` 文件的部分代码。

**功能列举:**

1. **指令预处理 (`progedit` 函数):**
    *   将跳转/调用指令 (`JMP`, `JAL`, `RET`, `DUFFZERO`, `DUFFCOPY`) 目标为符号的情况，将其目标类型设置为 `obj.TYPE_BRANCH`，这有助于后续的链接和代码生成。
    *   将浮点数常量 (`TYPE_FCONST`) 转换为内存引用。如果浮点数常量为 0，则将其转换为 `MOV` 指令从 `REGZERO` 寄存器移动。否则，创建一个指向该浮点数常量的符号，并将指令的操作数类型改为内存引用。
    *   对于大于 32 位的常量，将其存储在内存中，并将 `MOV` 指令的操作数类型改为从内存加载。
    *   将减法指令 (`SUB`, `SUBU`, `SUBV`, `SUBVU`) 且源操作数为常量的情况，转换为加法指令 (`ADD`, `ADDU`, `ADDV`, `ADDVU`)，并将常量取反。这是一种常见的编译器优化手段。

2. **函数预处理 (`preprocess` 函数):**
    *   处理函数的栈帧大小，包括对 `NOFRAME` 属性的处理。
    *   识别叶子函数 (不调用其他函数的函数)。
    *   展开 `RET` 指令，根据是否为叶子函数以及栈帧大小，生成不同的指令序列，包括调整栈指针和跳转到返回地址。
    *   展开 `BECOME` 伪指令（已注释，表示不支持）。
    *   在函数入口处插入栈溢出检测代码 (`stacksplit` 函数)，调用 `runtime.morestack` 来扩展栈空间。
    *   对于 wrapper 函数，插入特定的代码来检查和更新 `g->panic->argp` 的值。
    *   可选的指令调度 (默认关闭，由 `nosched` 变量控制)。如果启用，则尝试重新排列指令以提高执行效率。
    *   在 MIPS 32 位模式下，将 `MOVD` 指令（双字移动）拆分为两个 `MOVF` 指令（单字浮点移动），以避免未对齐的内存访问。
    *   如果未启用指令调度，则在每个分支指令后添加 `NOP` 指令。

3. **栈溢出检测 (`stacksplit` 函数):**
    *   生成代码来检查当前栈指针是否接近栈底。
    *   如果栈空间不足，则调用 `runtime.morestack` 函数来扩展栈空间。
    *   在调用 `runtime.morestack` 前后，可能会保存和恢复链接寄存器 (`REGLINK`) 和上下文寄存器 (`REGCTXT`)。
    *   根据栈帧大小选择不同的栈溢出检测策略。

4. **添加 NOP 指令 (`addnop` 函数):**
    *   在指定的指令后插入一条 `ANOOP` 指令。

5. **指令调度相关 (`sched`, `markregused`, `depend`, `conflict`, `compound` 等函数和结构体):**
    *   定义了用于指令调度的结构体 (`Sch`, `Dep`)，用于跟踪指令的寄存器使用和设置情况。
    *   `markregused` 函数分析指令并标记其使用的和设置的寄存器。
    *   `depend` 函数判断两个指令之间是否存在依赖关系，从而确定是否可以安全地交换位置。
    *   `conflict` 函数判断两个相邻的指令之间是否存在冲突，可能导致流水线停顿。
    *   `sched` 函数实现具体的指令调度算法，尝试将非依赖的指令移动到分支指令的延迟槽中。

**推理 Go 语言功能的实现:**

这个文件是 Go 编译器中 MIPS 架构的汇编器的一部分，负责将 Go 代码编译成 MIPS 汇编指令。它涉及到以下 Go 语言功能的实现：

*   **函数调用约定:** `progedit` 和 `preprocess` 中对 `JAL`、`RET` 等指令的处理，以及栈帧的设置和链接寄存器的保存恢复，都与 Go 的函数调用约定密切相关。
*   **栈管理:** `preprocess` 和 `stacksplit` 函数实现了 Go 的动态栈增长机制，确保 goroutine 在运行时拥有足够的栈空间。
*   **浮点数支持:** `progedit` 中对 `TYPE_FCONST` 和 `AMOVF/AMOVD` 指令的处理，体现了 Go 对浮点数的支持。
*   **常量处理:** 对不同大小的常量进行处理，确保它们能被正确加载和使用。
*   **内联函数和叶子函数优化:**  对叶子函数的特殊处理 (例如不保存链接寄存器) 是一种常见的编译器优化。
*   **函数 Wrapper:**  对于使用了 `//go:linkname` 等机制的函数 wrapper，需要进行额外的处理来确保 panic 信息的正确性。

**Go 代码举例说明:**

以下是一些基于代码推理的 Go 代码示例，展示了 `obj0.go` 中处理的一些情况：

**示例 1: 浮点数常量**

```go
package main

func main() {
	var f float32 = 3.14
	_ = f
}
```

**假设的汇编指令 (MIPS 32-bit):**

```assembly
TEXT main.main(SB), $0-8
  // ... 其他指令 ...
  MOVW $go.string."3.14"(SB), R1 // 假设 "3.14" 常量存储在 .rodata 段
  MOVF (R1), F0
  // ... 其他指令 ...
  RET
```

**`progedit` 的可能处理:**  当遇到 `var f float32 = 3.14` 对应的 `AMOVF` 指令时，如果源操作数是 `TYPE_FCONST`，`progedit` 会将其转换为从内存加载，指向存储 `3.14` 的符号。

**示例 2: 大于 32 位的常量 (MIPS 64-bit)**

```go
package main

func main() {
	var i int64 = 0x1234567890abcdef
	_ = i
}
```

**假设的汇编指令 (MIPS 64-bit):**

```assembly
TEXT main.main(SB), $0-8
  // ... 其他指令 ...
  MOVV $go.int64.0x1234567890abcdef(SB), R1 // 假设常量存储在 .rodata 段
  // ... 其他指令 ...
  RET
```

**`progedit` 的可能处理:** 当遇到 `var i int64 = 0x1234567890abcdef` 对应的 `AMOVV` 指令时，由于常量太大，`progedit` 会将其转换为从内存加载，指向存储该 64 位常量的符号。

**示例 3: 函数调用和返回**

```go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	sum := add(1, 2)
	_ = sum
}
```

**假设的汇编指令 (MIPS):**

```assembly
TEXT main.add(SB), NOSPLIT, $0-16
  ADD R4, R5, R3 // a + b
  MOV R3, 16(SP) // 将返回值存储到栈上
  RET

TEXT main.main(SB), $0-8
  // ... 其他指令 ...
  MOVW $1, R4
  MOVW $2, R5
  JAL main.add(SB)
  MOVW 16(SP), R6 // 获取返回值
  // ... 其他指令 ...
  RET
```

**`progedit` 和 `preprocess` 的可能处理:**

*   **`progedit`:**  会将 `JAL main.add(SB)` 的目标类型设置为 `obj.TYPE_BRANCH`。
*   **`preprocess`:** 会处理 `main.add` 和 `main.main` 的栈帧设置，并在 `main.add` 的 `RET` 指令处生成相应的返回指令序列。

**命令行参数的具体处理:**

在 `stacksplit` 函数中，可以看到对 `c.ctxt.Flag_maymorestack` 的判断：

```go
if c.ctxt.Flag_maymorestack != "" {
    // ... 生成调用 maymorestack 的代码 ...
}
```

这表明可以通过命令行参数 `-maymorestack` 来指定一个自定义的栈扩展函数。例如，在编译时可以使用以下命令：

```bash
go tool compile -maymorestack=mypackage.mymorestack mypackage/myfile.go
```

在这种情况下，当需要扩展栈时，生成的汇编代码会调用 `mypackage.mymorestack` 而不是默认的 `runtime.morestack`。 这通常用于一些特殊场景，例如需要自定义栈扩展逻辑或与特定的运行时环境集成。

**使用者易犯错的点:**

1. **手动编写汇编代码时的栈帧管理错误:**  如果用户尝试手动编写 MIPS 汇编代码并与 Go 代码混合使用，很容易在栈帧的设置、链接寄存器的保存和恢复等方面出错，导致程序崩溃或行为异常。`preprocess` 函数中的栈帧处理逻辑较为复杂，需要仔细理解。

2. **错误地使用 `NOFRAME` 属性:**  如果将一个需要栈帧（例如，调用了其他函数或有局部变量）的函数标记为 `NOFRAME`，会导致栈指针混乱，引发严重错误。`preprocess` 函数会检查 `NOFRAME` 函数的栈帧大小是否为 0，但用户仍然可能在其他地方引入错误。

3. **假设指令调度的行为:**  由于指令调度是可选的，并且具体的调度算法可能随 Go 版本变化，因此不应假设指令会以特定的顺序执行。手动编写汇编时，应避免依赖于特定的指令执行顺序。

4. **不理解 `runtime.morestack` 的调用时机:**  `stacksplit` 函数在函数入口处插入栈检查代码，如果用户手动修改或绕过这些检查，可能会导致栈溢出，进而引发安全问题。

**总结:**

`go/src/cmd/internal/obj/mips/obj0.go` 是 Go 编译器中 MIPS 架构汇编器的核心部分，负责指令和函数的预处理，包括常量转换、跳转目标处理、栈帧管理、栈溢出检测和可选的指令调度。理解这个文件的功能有助于深入了解 Go 的底层实现以及 MIPS 架构的特性。  用户在使用 Go 进行开发时，通常不需要直接与这个文件交互，但了解其背后的机制可以帮助避免一些潜在的错误。

### 提示词
```
这是路径为go/src/cmd/internal/obj/mips/obj0.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// cmd/9l/noop.c, cmd/9l/pass.c, cmd/9l/span.c from Vita Nuova.
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

package mips

import (
	"cmd/internal/obj"
	"cmd/internal/sys"
	"encoding/binary"
	"fmt"
	"internal/abi"
	"log"
	"math"
)

func progedit(ctxt *obj.Link, p *obj.Prog, newprog obj.ProgAlloc) {
	c := ctxt0{ctxt: ctxt}

	p.From.Class = 0
	p.To.Class = 0

	// Rewrite JMP/JAL to symbol as TYPE_BRANCH.
	switch p.As {
	case AJMP,
		AJAL,
		ARET,
		obj.ADUFFZERO,
		obj.ADUFFCOPY:
		if p.To.Sym != nil {
			p.To.Type = obj.TYPE_BRANCH
		}
	}

	// Rewrite float constants to values stored in memory.
	switch p.As {
	case AMOVF:
		if p.From.Type == obj.TYPE_FCONST {
			f32 := float32(p.From.Val.(float64))
			if math.Float32bits(f32) == 0 {
				p.As = AMOVW
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGZERO
				break
			}
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = ctxt.Float32Sym(f32)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}

	case AMOVD:
		if p.From.Type == obj.TYPE_FCONST {
			f64 := p.From.Val.(float64)
			if math.Float64bits(f64) == 0 && c.ctxt.Arch.Family == sys.MIPS64 {
				p.As = AMOVV
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGZERO
				break
			}
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = ctxt.Float64Sym(f64)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}

		// Put >32-bit constants in memory and load them
	case AMOVV:
		if p.From.Type == obj.TYPE_CONST && p.From.Name == obj.NAME_NONE && p.From.Reg == 0 && int64(int32(p.From.Offset)) != p.From.Offset {
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = ctxt.Int64Sym(p.From.Offset)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}
	}

	// Rewrite SUB constants into ADD.
	switch p.As {
	case ASUB:
		if p.From.Type == obj.TYPE_CONST {
			p.From.Offset = -p.From.Offset
			p.As = AADD
		}

	case ASUBU:
		if p.From.Type == obj.TYPE_CONST {
			p.From.Offset = -p.From.Offset
			p.As = AADDU
		}

	case ASUBV:
		if p.From.Type == obj.TYPE_CONST {
			p.From.Offset = -p.From.Offset
			p.As = AADDV
		}

	case ASUBVU:
		if p.From.Type == obj.TYPE_CONST {
			p.From.Offset = -p.From.Offset
			p.As = AADDVU
		}
	}
}

func preprocess(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc) {
	// TODO(minux): add morestack short-cuts with small fixed frame-size.
	c := ctxt0{ctxt: ctxt, newprog: newprog, cursym: cursym}

	// a switch for enabling/disabling instruction scheduling
	nosched := true

	if c.cursym.Func().Text == nil || c.cursym.Func().Text.Link == nil {
		return
	}

	p := c.cursym.Func().Text
	textstksiz := p.To.Offset
	if textstksiz == -ctxt.Arch.FixedFrameSize {
		// Historical way to mark NOFRAME.
		p.From.Sym.Set(obj.AttrNoFrame, true)
		textstksiz = 0
	}
	if textstksiz < 0 {
		c.ctxt.Diag("negative frame size %d - did you mean NOFRAME?", textstksiz)
	}
	if p.From.Sym.NoFrame() {
		if textstksiz != 0 {
			c.ctxt.Diag("NOFRAME functions must have a frame size of 0, not %d", textstksiz)
		}
	}

	c.cursym.Func().Args = p.To.Val.(int32)
	c.cursym.Func().Locals = int32(textstksiz)

	/*
	 * find leaf subroutines
	 * expand RET
	 * expand BECOME pseudo
	 */

	for p := c.cursym.Func().Text; p != nil; p = p.Link {
		switch p.As {
		/* too hard, just leave alone */
		case obj.ATEXT:
			p.Mark |= LABEL | LEAF | SYNC
			if p.Link != nil {
				p.Link.Mark |= LABEL
			}

		/* too hard, just leave alone */
		case AMOVW,
			AMOVV:
			if p.To.Type == obj.TYPE_REG && p.To.Reg >= REG_SPECIAL {
				p.Mark |= LABEL | SYNC
				break
			}
			if p.From.Type == obj.TYPE_REG && p.From.Reg >= REG_SPECIAL {
				p.Mark |= LABEL | SYNC
			}

		/* too hard, just leave alone */
		case ASYSCALL,
			AWORD,
			ATLBWR,
			ATLBWI,
			ATLBP,
			ATLBR:
			p.Mark |= LABEL | SYNC

		case ANOR:
			if p.To.Type == obj.TYPE_REG {
				if p.To.Reg == REGZERO {
					p.Mark |= LABEL | SYNC
				}
			}

		case ABGEZAL,
			ABLTZAL,
			AJAL,
			obj.ADUFFZERO,
			obj.ADUFFCOPY:
			c.cursym.Func().Text.Mark &^= LEAF
			fallthrough

		case AJMP,
			ABEQ,
			ABGEZ,
			ABGTZ,
			ABLEZ,
			ABLTZ,
			ABNE,
			ABFPT, ABFPF:
			if p.As == ABFPT || p.As == ABFPF {
				// We don't treat ABFPT and ABFPF as branches here,
				// so that we will always fill nop (0x0) in their
				// delay slot during assembly.
				// This is to workaround a kernel FPU emulator bug
				// where it uses the user stack to simulate the
				// instruction in the delay slot if it's not 0x0,
				// and somehow that leads to SIGSEGV when the kernel
				// jump to the stack.
				p.Mark |= SYNC
			} else {
				p.Mark |= BRANCH
			}
			q1 := p.To.Target()
			if q1 != nil {
				for q1.As == obj.ANOP {
					q1 = q1.Link
					p.To.SetTarget(q1)
				}

				if q1.Mark&LEAF == 0 {
					q1.Mark |= LABEL
				}
			}
			//else {
			//	p.Mark |= LABEL
			//}
			q1 = p.Link
			if q1 != nil {
				q1.Mark |= LABEL
			}

		case ARET:
			if p.Link != nil {
				p.Link.Mark |= LABEL
			}
		}
	}

	var mov, add obj.As
	if c.ctxt.Arch.Family == sys.MIPS64 {
		add = AADDV
		mov = AMOVV
	} else {
		add = AADDU
		mov = AMOVW
	}

	var q *obj.Prog
	var q1 *obj.Prog
	autosize := int32(0)
	var p1 *obj.Prog
	var p2 *obj.Prog
	for p := c.cursym.Func().Text; p != nil; p = p.Link {
		o := p.As
		switch o {
		case obj.ATEXT:
			autosize = int32(textstksiz)

			if p.Mark&LEAF != 0 && autosize == 0 {
				// A leaf function with no locals has no frame.
				p.From.Sym.Set(obj.AttrNoFrame, true)
			}

			if !p.From.Sym.NoFrame() {
				// If there is a stack frame at all, it includes
				// space to save the LR.
				autosize += int32(c.ctxt.Arch.FixedFrameSize)
			}

			if autosize&4 != 0 && c.ctxt.Arch.Family == sys.MIPS64 {
				autosize += 4
			}

			if autosize == 0 && c.cursym.Func().Text.Mark&LEAF == 0 {
				if c.cursym.Func().Text.From.Sym.NoSplit() {
					if ctxt.Debugvlog {
						ctxt.Logf("save suppressed in: %s\n", c.cursym.Name)
					}

					c.cursym.Func().Text.Mark |= LEAF
				}
			}

			p.To.Offset = int64(autosize) - ctxt.Arch.FixedFrameSize

			if c.cursym.Func().Text.Mark&LEAF != 0 {
				c.cursym.Set(obj.AttrLeaf, true)
				if p.From.Sym.NoFrame() {
					break
				}
			}

			if !p.From.Sym.NoSplit() {
				p = c.stacksplit(p, autosize) // emit split check
			}

			q = p

			if autosize != 0 {
				// Make sure to save link register for non-empty frame, even if
				// it is a leaf function, so that traceback works.
				// Store link register before decrement SP, so if a signal comes
				// during the execution of the function prologue, the traceback
				// code will not see a half-updated stack frame.
				// This sequence is not async preemptible, as if we open a frame
				// at the current SP, it will clobber the saved LR.
				q = c.ctxt.StartUnsafePoint(q, c.newprog)

				q = obj.Appendp(q, newprog)
				q.As = mov
				q.Pos = p.Pos
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REGLINK
				q.To.Type = obj.TYPE_MEM
				q.To.Offset = int64(-autosize)
				q.To.Reg = REGSP

				q = obj.Appendp(q, newprog)
				q.As = add
				q.Pos = p.Pos
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = int64(-autosize)
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REGSP
				q.Spadj = +autosize

				q = c.ctxt.EndUnsafePoint(q, c.newprog, -1)

				// On Linux, in a cgo binary we may get a SIGSETXID signal early on
				// before the signal stack is set, as glibc doesn't allow us to block
				// SIGSETXID. So a signal may land on the current stack and clobber
				// the content below the SP. We store the LR again after the SP is
				// decremented.
				q = obj.Appendp(q, newprog)
				q.As = mov
				q.Pos = p.Pos
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REGLINK
				q.To.Type = obj.TYPE_MEM
				q.To.Offset = 0
				q.To.Reg = REGSP
			}

			if c.cursym.Func().Text.From.Sym.Wrapper() && c.cursym.Func().Text.Mark&LEAF == 0 {
				// if(g->panic != nil && g->panic->argp == FP) g->panic->argp = bottom-of-frame
				//
				//	MOV	g_panic(g), R1
				//	BEQ	R1, end
				//	MOV	panic_argp(R1), R2
				//	ADD	$(autosize+FIXED_FRAME), R29, R3
				//	BNE	R2, R3, end
				//	ADD	$FIXED_FRAME, R29, R2
				//	MOV	R2, panic_argp(R1)
				// end:
				//	NOP
				//
				// The NOP is needed to give the jumps somewhere to land.
				// It is a liblink NOP, not an mips NOP: it encodes to 0 instruction bytes.
				//
				// We don't generate this for leafs because that means the wrapped
				// function was inlined into the wrapper.

				q = obj.Appendp(q, newprog)

				q.As = mov
				q.From.Type = obj.TYPE_MEM
				q.From.Reg = REGG
				q.From.Offset = 4 * int64(c.ctxt.Arch.PtrSize) // G.panic
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R1

				q = obj.Appendp(q, newprog)
				q.As = ABEQ
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R1
				q.To.Type = obj.TYPE_BRANCH
				q.Mark |= BRANCH
				p1 = q

				q = obj.Appendp(q, newprog)
				q.As = mov
				q.From.Type = obj.TYPE_MEM
				q.From.Reg = REG_R1
				q.From.Offset = 0 // Panic.argp
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R2

				q = obj.Appendp(q, newprog)
				q.As = add
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = int64(autosize) + ctxt.Arch.FixedFrameSize
				q.Reg = REGSP
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R3

				q = obj.Appendp(q, newprog)
				q.As = ABNE
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R2
				q.Reg = REG_R3
				q.To.Type = obj.TYPE_BRANCH
				q.Mark |= BRANCH
				p2 = q

				q = obj.Appendp(q, newprog)
				q.As = add
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = ctxt.Arch.FixedFrameSize
				q.Reg = REGSP
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R2

				q = obj.Appendp(q, newprog)
				q.As = mov
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R2
				q.To.Type = obj.TYPE_MEM
				q.To.Reg = REG_R1
				q.To.Offset = 0 // Panic.argp

				q = obj.Appendp(q, newprog)

				q.As = obj.ANOP
				p1.To.SetTarget(q)
				p2.To.SetTarget(q)
			}

		case ARET:
			if p.From.Type == obj.TYPE_CONST {
				ctxt.Diag("using BECOME (%v) is not supported!", p)
				break
			}

			retSym := p.To.Sym
			p.To.Name = obj.NAME_NONE // clear fields as we may modify p to other instruction
			p.To.Sym = nil

			if c.cursym.Func().Text.Mark&LEAF != 0 {
				if autosize == 0 {
					p.As = AJMP
					p.From = obj.Addr{}
					if retSym != nil { // retjmp
						p.To.Type = obj.TYPE_BRANCH
						p.To.Name = obj.NAME_EXTERN
						p.To.Sym = retSym
					} else {
						p.To.Type = obj.TYPE_MEM
						p.To.Reg = REGLINK
						p.To.Offset = 0
					}
					p.Mark |= BRANCH
					break
				}

				p.As = add
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = int64(autosize)
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REGSP
				p.Spadj = -autosize

				q = c.newprog()
				q.As = AJMP
				q.Pos = p.Pos
				if retSym != nil { // retjmp
					q.To.Type = obj.TYPE_BRANCH
					q.To.Name = obj.NAME_EXTERN
					q.To.Sym = retSym
				} else {
					q.To.Type = obj.TYPE_MEM
					q.To.Reg = REGLINK
					q.To.Offset = 0
				}
				q.Mark |= BRANCH
				q.Spadj = +autosize

				q.Link = p.Link
				p.Link = q
				break
			}

			p.As = mov
			p.From.Type = obj.TYPE_MEM
			p.From.Offset = 0
			p.From.Reg = REGSP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = REGLINK

			if autosize != 0 {
				q = c.newprog()
				q.As = add
				q.Pos = p.Pos
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = int64(autosize)
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REGSP
				q.Spadj = -autosize

				q.Link = p.Link
				p.Link = q
			}

			q1 = c.newprog()
			q1.As = AJMP
			q1.Pos = p.Pos
			if retSym != nil { // retjmp
				q1.To.Type = obj.TYPE_BRANCH
				q1.To.Name = obj.NAME_EXTERN
				q1.To.Sym = retSym
			} else {
				q1.To.Type = obj.TYPE_MEM
				q1.To.Offset = 0
				q1.To.Reg = REGLINK
			}
			q1.Mark |= BRANCH
			q1.Spadj = +autosize

			q1.Link = q.Link
			q.Link = q1

		case AADD,
			AADDU,
			AADDV,
			AADDVU:
			if p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP && p.From.Type == obj.TYPE_CONST {
				p.Spadj = int32(-p.From.Offset)
			}

		case obj.AGETCALLERPC:
			if cursym.Leaf() {
				/* MOV LR, Rd */
				p.As = mov
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGLINK
			} else {
				/* MOV (RSP), Rd */
				p.As = mov
				p.From.Type = obj.TYPE_MEM
				p.From.Reg = REGSP
			}
		}

		if p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP && p.Spadj == 0 {
			f := c.cursym.Func()
			if f.FuncFlag&abi.FuncFlagSPWrite == 0 {
				c.cursym.Func().FuncFlag |= abi.FuncFlagSPWrite
				if ctxt.Debugvlog || !ctxt.IsAsm {
					ctxt.Logf("auto-SPWRITE: %s %v\n", c.cursym.Name, p)
					if !ctxt.IsAsm {
						ctxt.Diag("invalid auto-SPWRITE in non-assembly")
						ctxt.DiagFlush()
						log.Fatalf("bad SPWRITE")
					}
				}
			}
		}
	}

	if c.ctxt.Arch.Family == sys.MIPS {
		// rewrite MOVD into two MOVF in 32-bit mode to avoid unaligned memory access
		for p = c.cursym.Func().Text; p != nil; p = p1 {
			p1 = p.Link

			if p.As != AMOVD {
				continue
			}
			if p.From.Type != obj.TYPE_MEM && p.To.Type != obj.TYPE_MEM {
				continue
			}

			p.As = AMOVF
			q = c.newprog()
			*q = *p
			q.Link = p.Link
			p.Link = q
			p1 = q.Link

			var addrOff int64
			if c.ctxt.Arch.ByteOrder == binary.BigEndian {
				addrOff = 4 // swap load/save order
			}
			if p.From.Type == obj.TYPE_MEM {
				reg := REG_F0 + (p.To.Reg-REG_F0)&^1
				p.To.Reg = reg
				q.To.Reg = reg + 1
				p.From.Offset += addrOff
				q.From.Offset += 4 - addrOff
			} else if p.To.Type == obj.TYPE_MEM {
				reg := REG_F0 + (p.From.Reg-REG_F0)&^1
				p.From.Reg = reg
				q.From.Reg = reg + 1
				p.To.Offset += addrOff
				q.To.Offset += 4 - addrOff
			}
		}
	}

	if nosched {
		// if we don't do instruction scheduling, simply add
		// NOP after each branch instruction.
		for p = c.cursym.Func().Text; p != nil; p = p.Link {
			if p.Mark&BRANCH != 0 {
				c.addnop(p)
			}
		}
		return
	}

	// instruction scheduling
	q = nil                   // p - 1
	q1 = c.cursym.Func().Text // top of block
	o := 0                    // count of instructions
	for p = c.cursym.Func().Text; p != nil; p = p1 {
		p1 = p.Link
		o++
		if p.Mark&NOSCHED != 0 {
			if q1 != p {
				c.sched(q1, q)
			}
			for ; p != nil; p = p.Link {
				if p.Mark&NOSCHED == 0 {
					break
				}
				q = p
			}
			p1 = p
			q1 = p
			o = 0
			continue
		}
		if p.Mark&(LABEL|SYNC) != 0 {
			if q1 != p {
				c.sched(q1, q)
			}
			q1 = p
			o = 1
		}
		if p.Mark&(BRANCH|SYNC) != 0 {
			c.sched(q1, p)
			q1 = p1
			o = 0
		}
		if o >= NSCHED {
			c.sched(q1, p)
			q1 = p1
			o = 0
		}
		q = p
	}
}

func (c *ctxt0) stacksplit(p *obj.Prog, framesize int32) *obj.Prog {
	var mov, add obj.As

	if c.ctxt.Arch.Family == sys.MIPS64 {
		add = AADDV
		mov = AMOVV
	} else {
		add = AADDU
		mov = AMOVW
	}

	if c.ctxt.Flag_maymorestack != "" {
		// Save LR and REGCTXT.
		frameSize := 2 * c.ctxt.Arch.PtrSize

		p = c.ctxt.StartUnsafePoint(p, c.newprog)

		// MOV	REGLINK, -8/-16(SP)
		p = obj.Appendp(p, c.newprog)
		p.As = mov
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGLINK
		p.To.Type = obj.TYPE_MEM
		p.To.Offset = int64(-frameSize)
		p.To.Reg = REGSP

		// MOV	REGCTXT, -4/-8(SP)
		p = obj.Appendp(p, c.newprog)
		p.As = mov
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGCTXT
		p.To.Type = obj.TYPE_MEM
		p.To.Offset = -int64(c.ctxt.Arch.PtrSize)
		p.To.Reg = REGSP

		// ADD	$-8/$-16, SP
		p = obj.Appendp(p, c.newprog)
		p.As = add
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = int64(-frameSize)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGSP
		p.Spadj = int32(frameSize)

		// JAL	maymorestack
		p = obj.Appendp(p, c.newprog)
		p.As = AJAL
		p.To.Type = obj.TYPE_BRANCH
		// See ../x86/obj6.go
		p.To.Sym = c.ctxt.LookupABI(c.ctxt.Flag_maymorestack, c.cursym.ABI())
		p.Mark |= BRANCH

		// Restore LR and REGCTXT.

		// MOV	0(SP), REGLINK
		p = obj.Appendp(p, c.newprog)
		p.As = mov
		p.From.Type = obj.TYPE_MEM
		p.From.Offset = 0
		p.From.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGLINK

		// MOV	4/8(SP), REGCTXT
		p = obj.Appendp(p, c.newprog)
		p.As = mov
		p.From.Type = obj.TYPE_MEM
		p.From.Offset = int64(c.ctxt.Arch.PtrSize)
		p.From.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGCTXT

		// ADD	$8/$16, SP
		p = obj.Appendp(p, c.newprog)
		p.As = add
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = int64(frameSize)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGSP
		p.Spadj = int32(-frameSize)

		p = c.ctxt.EndUnsafePoint(p, c.newprog, -1)
	}

	// Jump back to here after morestack returns.
	startPred := p

	// MOV	g_stackguard(g), R1
	p = obj.Appendp(p, c.newprog)

	p.As = mov
	p.From.Type = obj.TYPE_MEM
	p.From.Reg = REGG
	p.From.Offset = 2 * int64(c.ctxt.Arch.PtrSize) // G.stackguard0
	if c.cursym.CFunc() {
		p.From.Offset = 3 * int64(c.ctxt.Arch.PtrSize) // G.stackguard1
	}
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REG_R1

	// Mark the stack bound check and morestack call async nonpreemptible.
	// If we get preempted here, when resumed the preemption request is
	// cleared, but we'll still call morestack, which will double the stack
	// unnecessarily. See issue #35470.
	p = c.ctxt.StartUnsafePoint(p, c.newprog)

	var q *obj.Prog
	if framesize <= abi.StackSmall {
		// small stack: SP < stackguard
		//	AGTU	SP, stackguard, R1
		p = obj.Appendp(p, c.newprog)

		p.As = ASGTU
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGSP
		p.Reg = REG_R1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R1
	} else {
		// large stack: SP-framesize < stackguard-StackSmall
		offset := int64(framesize) - abi.StackSmall
		if framesize > abi.StackBig {
			// Such a large stack we need to protect against underflow.
			// The runtime guarantees SP > objabi.StackBig, but
			// framesize is large enough that SP-framesize may
			// underflow, causing a direct comparison with the
			// stack guard to incorrectly succeed. We explicitly
			// guard against underflow.
			//
			//	SGTU	$(framesize-StackSmall), SP, R2
			//	BNE	R2, label-of-call-to-morestack

			p = obj.Appendp(p, c.newprog)
			p.As = ASGTU
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = offset
			p.Reg = REGSP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = REG_R2

			p = obj.Appendp(p, c.newprog)
			q = p
			p.As = ABNE
			p.From.Type = obj.TYPE_REG
			p.From.Reg = REG_R2
			p.To.Type = obj.TYPE_BRANCH
			p.Mark |= BRANCH
		}

		// Check against the stack guard. We've ensured this won't underflow.
		//	ADD	$-(framesize-StackSmall), SP, R2
		//	SGTU	R2, stackguard, R1
		p = obj.Appendp(p, c.newprog)

		p.As = add
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = -offset
		p.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R2

		p = obj.Appendp(p, c.newprog)
		p.As = ASGTU
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_R2
		p.Reg = REG_R1
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R1
	}

	// q1: BNE	R1, done
	p = obj.Appendp(p, c.newprog)
	q1 := p

	p.As = ABNE
	p.From.Type = obj.TYPE_REG
	p.From.Reg = REG_R1
	p.To.Type = obj.TYPE_BRANCH
	p.Mark |= BRANCH

	// MOV	LINK, R3
	p = obj.Appendp(p, c.newprog)

	p.As = mov
	p.From.Type = obj.TYPE_REG
	p.From.Reg = REGLINK
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REG_R3
	if q != nil {
		q.To.SetTarget(p)
		p.Mark |= LABEL
	}

	p = c.ctxt.EmitEntryStackMap(c.cursym, p, c.newprog)

	// JAL	runtime.morestack(SB)
	p = obj.Appendp(p, c.newprog)

	p.As = AJAL
	p.To.Type = obj.TYPE_BRANCH
	if c.cursym.CFunc() {
		p.To.Sym = c.ctxt.Lookup("runtime.morestackc")
	} else if !c.cursym.Func().Text.From.Sym.NeedCtxt() {
		p.To.Sym = c.ctxt.Lookup("runtime.morestack_noctxt")
	} else {
		p.To.Sym = c.ctxt.Lookup("runtime.morestack")
	}
	p.Mark |= BRANCH

	p = c.ctxt.EndUnsafePoint(p, c.newprog, -1)

	// JMP	start
	p = obj.Appendp(p, c.newprog)

	p.As = AJMP
	p.To.Type = obj.TYPE_BRANCH
	p.To.SetTarget(startPred.Link)
	startPred.Link.Mark |= LABEL
	p.Mark |= BRANCH

	// placeholder for q1's jump target
	p = obj.Appendp(p, c.newprog)

	p.As = obj.ANOP // zero-width place holder
	q1.To.SetTarget(p)

	return p
}

func (c *ctxt0) addnop(p *obj.Prog) {
	q := c.newprog()
	q.As = ANOOP
	q.Pos = p.Pos
	q.Link = p.Link
	p.Link = q
}

const (
	E_HILO  = 1 << 0
	E_FCR   = 1 << 1
	E_MCR   = 1 << 2
	E_MEM   = 1 << 3
	E_MEMSP = 1 << 4 /* uses offset and size */
	E_MEMSB = 1 << 5 /* uses offset and size */
	ANYMEM  = E_MEM | E_MEMSP | E_MEMSB
	//DELAY = LOAD|BRANCH|FCMP
	DELAY = BRANCH /* only schedule branch */
)

type Dep struct {
	ireg uint32
	freg uint32
	cc   uint32
}

type Sch struct {
	p       obj.Prog
	set     Dep
	used    Dep
	soffset int32
	size    uint8
	nop     uint8
	comp    bool
}

func (c *ctxt0) sched(p0, pe *obj.Prog) {
	var sch [NSCHED]Sch

	/*
	 * build side structure
	 */
	s := sch[:]
	for p := p0; ; p = p.Link {
		s[0].p = *p
		c.markregused(&s[0])
		if p == pe {
			break
		}
		s = s[1:]
	}
	se := s

	for i := cap(sch) - cap(se); i >= 0; i-- {
		s = sch[i:]
		if s[0].p.Mark&DELAY == 0 {
			continue
		}
		if -cap(s) < -cap(se) {
			if !conflict(&s[0], &s[1]) {
				continue
			}
		}

		var t []Sch
		var j int
		for j = cap(sch) - cap(s) - 1; j >= 0; j-- {
			t = sch[j:]
			if t[0].comp {
				if s[0].p.Mark&BRANCH != 0 {
					continue
				}
			}
			if t[0].p.Mark&DELAY != 0 {
				if -cap(s) >= -cap(se) || conflict(&t[0], &s[1]) {
					continue
				}
			}
			for u := t[1:]; -cap(u) <= -cap(s); u = u[1:] {
				if c.depend(&u[0], &t[0]) {
					continue
				}
			}
			goto out2
		}

		if s[0].p.Mark&BRANCH != 0 {
			s[0].nop = 1
		}
		continue

	out2:
		// t[0] is the instruction being moved to fill the delay
		stmp := t[0]
		copy(t[:i-j], t[1:i-j+1])
		s[0] = stmp

		if t[i-j-1].p.Mark&BRANCH != 0 {
			// t[i-j] is being put into a branch delay slot
			// combine its Spadj with the branch instruction
			t[i-j-1].p.Spadj += t[i-j].p.Spadj
			t[i-j].p.Spadj = 0
		}

		i--
	}

	/*
	 * put it all back
	 */
	var p *obj.Prog
	var q *obj.Prog
	for s, p = sch[:], p0; -cap(s) <= -cap(se); s, p = s[1:], q {
		q = p.Link
		if q != s[0].p.Link {
			*p = s[0].p
			p.Link = q
		}
		for s[0].nop != 0 {
			s[0].nop--
			c.addnop(p)
		}
	}
}

func (c *ctxt0) markregused(s *Sch) {
	p := &s.p
	s.comp = c.compound(p)
	s.nop = 0
	if s.comp {
		s.set.ireg |= 1 << (REGTMP - REG_R0)
		s.used.ireg |= 1 << (REGTMP - REG_R0)
	}

	ar := 0  /* dest is really reference */
	ad := 0  /* source/dest is really address */
	ld := 0  /* opcode is load instruction */
	sz := 20 /* size of load/store for overlap computation */

	/*
	 * flags based on opcode
	 */
	switch p.As {
	case obj.ATEXT:
		c.autosize = int32(p.To.Offset + 8)
		ad = 1

	case AJAL:
		r := p.Reg
		if r == 0 {
			r = REGLINK
		}
		s.set.ireg |= 1 << uint(r-REG_R0)
		ar = 1
		ad = 1

	case ABGEZAL,
		ABLTZAL:
		s.set.ireg |= 1 << (REGLINK - REG_R0)
		fallthrough
	case ABEQ,
		ABGEZ,
		ABGTZ,
		ABLEZ,
		ABLTZ,
		ABNE:
		ar = 1
		ad = 1

	case ABFPT,
		ABFPF:
		ad = 1
		s.used.cc |= E_FCR

	case ACMPEQD,
		ACMPEQF,
		ACMPGED,
		ACMPGEF,
		ACMPGTD,
		ACMPGTF:
		ar = 1
		s.set.cc |= E_FCR
		p.Mark |= FCMP

	case AJMP:
		ar = 1
		ad = 1

	case AMOVB,
		AMOVBU:
		sz = 1
		ld = 1

	case AMOVH,
		AMOVHU:
		sz = 2
		ld = 1

	case AMOVF,
		AMOVW,
		AMOVWL,
		AMOVWR:
		sz = 4
		ld = 1

	case AMOVD,
		AMOVV,
		AMOVVL,
		AMOVVR:
		sz = 8
		ld = 1

	case ADIV,
		ADIVU,
		AMUL,
		AMULU,
		AREM,
		AREMU,
		ADIVV,
		ADIVVU,
		AMULV,
		AMULVU,
		AREMV,
		AREMVU:
		s.set.cc = E_HILO
		fallthrough
	case AADD,
		AADDU,
		AADDV,
		AADDVU,
		AAND,
		ANOR,
		AOR,
		ASGT,
		ASGTU,
		ASLL,
		ASRA,
		ASRL,
		ASLLV,
		ASRAV,
		ASRLV,
		ASUB,
		ASUBU,
		ASUBV,
		ASUBVU,
		AXOR,

		AADDD,
		AADDF,
		AADDW,
		ASUBD,
		ASUBF,
		ASUBW,
		AMULF,
		AMULD,
		AMULW,
		ADIVF,
		ADIVD,
		ADIVW:
		if p.Reg == 0 {
			if p.To.Type == obj.TYPE_REG {
				p.Reg = p.To.Reg
			}
			//if(p->reg == NREG)
			//	print("botch %P\n", p);
		}
	}

	/*
	 * flags based on 'to' field
	 */
	cls := int(p.To.Class)
	if cls == 0 {
		cls = c.aclass(&p.To) + 1
		p.To.Class = int8(cls)
	}
	cls--
	switch cls {
	default:
		fmt.Printf("unknown class %d %v\n", cls, p)

	case C_ZCON,
		C_SCON,
		C_ADD0CON,
		C_AND0CON,
		C_ADDCON,
		C_ANDCON,
		C_UCON,
		C_LCON,
		C_NONE,
		C_SBRA,
		C_LBRA,
		C_ADDR,
		C_TEXTSIZE:
		break

	case C_HI,
		C_LO:
		s.set.cc |= E_HILO

	case C_FCREG:
		s.set.cc |= E_FCR

	case C_MREG:
		s.set.cc |= E_MCR

	case C_ZOREG,
		C_SOREG,
		C_LOREG:
		cls = int(p.To.Reg)
		s.used.ireg |= 1 << uint(cls-REG_R0)
		if ad != 0 {
			break
		}
		s.size = uint8(sz)
		s.soffset = c.regoff(&p.To)

		m := uint32(ANYMEM)
		if cls == REGSB {
			m = E_MEMSB
		}
		if cls == REGSP {
			m = E_MEMSP
		}

		if ar != 0 {
			s.used.cc |= m
		} else {
			s.set.cc |= m
		}

	case C_SACON,
		C_LACON:
		s.used.ireg |= 1 << (REGSP - REG_R0)

	case C_SECON,
		C_LECON:
		s.used.ireg |= 1 << (REGSB - REG_R0)

	case C_REG:
		if ar != 0 {
			s.used.ireg |= 1 << uint(p.To.Reg-REG_R0)
		} else {
			s.set.ireg |= 1 << uint(p.To.Reg-REG_R0)
		}

	case C_FREG:
		if ar != 0 {
			s.used.freg |= 1 << uint(p.To.Reg-REG_F0)
		} else {
			s.set.freg |= 1 << uint(p.To.Reg-REG_F0)
		}
		if ld != 0 && p.From.Type == obj.TYPE_REG {
			p.Mark |= LOAD
		}

	case C_SAUTO,
		C_LAUTO:
		s.used.ireg |= 1 << (REGSP - REG_R0)
		if ad != 0 {
			break
		}
		s.size = uint8(sz)
		s.soffset = c.regoff(&p.To)

		if ar != 0 {
			s.used.cc |= E_MEMSP
		} else {
			s.set.cc |= E_MEMSP
		}

	case C_SEXT,
		C_LEXT:
		s.used.ireg |= 1 << (REGSB - REG_R0)
		if ad != 0 {
			break
		}
		s.size = uint8(sz)
		s.soffset = c.regoff(&p.To)

		if ar != 0 {
			s.used.cc |= E_MEMSB
		} else {
			s.set.cc |= E_MEMSB
		}
	}

	/*
	 * flags based on 'from' field
	 */
	cls = int(p.From.Class)
	if cls == 0 {
		cls = c.aclass(&p.From) + 1
		p.From.Class = int8(cls)
	}
	cls--
	switch cls {
	default:
		fmt.Printf("unknown class %d %v\n", cls, p)

	case C_ZCON,
		C_SCON,
		C_ADD0CON,
		C_AND0CON,
		C_ADDCON,
		C_ANDCON,
		C_UCON,
		C_LCON,
		C_NONE,
		C_SBRA,
		C_LBRA,
		C_ADDR,
		C_TEXTSIZE:
		break

	case C_HI,
		C_LO:
		s.used.cc |= E_HILO

	case C_FCREG:
		s.used.cc |= E_FCR

	case C_MREG:
		s.used.cc |= E_MCR

	case C_ZOREG,
		C_SOREG,
		C_LOREG:
		cls = int(p.From.Reg)
		s.used.ireg |= 1 << uint(cls-REG_R0)
		if ld != 0 {
			p.Mark |= LOAD
		}
		s.size = uint8(sz)
		s.soffset = c.regoff(&p.From)

		m := uint32(ANYMEM)
		if cls == REGSB {
			m = E_MEMSB
		}
		if cls == REGSP {
			m = E_MEMSP
		}

		s.used.cc |= m

	case C_SACON,
		C_LACON:
		cls = int(p.From.Reg)
		if cls == 0 {
			cls = REGSP
		}
		s.used.ireg |= 1 << uint(cls-REG_R0)

	case C_SECON,
		C_LECON:
		s.used.ireg |= 1 << (REGSB - REG_R0)

	case C_REG:
		s.used.ireg |= 1 << uint(p.From.Reg-REG_R0)

	case C_FREG:
		s.used.freg |= 1 << uint(p.From.Reg-REG_F0)
		if ld != 0 && p.To.Type == obj.TYPE_REG {
			p.Mark |= LOAD
		}

	case C_SAUTO,
		C_LAUTO:
		s.used.ireg |= 1 << (REGSP - REG_R0)
		if ld != 0 {
			p.Mark |= LOAD
		}
		if ad != 0 {
			break
		}
		s.size = uint8(sz)
		s.soffset = c.regoff(&p.From)

		s.used.cc |= E_MEMSP

	case C_SEXT:
	case C_LEXT:
		s.used.ireg |= 1 << (REGSB - REG_R0)
		if ld != 0 {
			p.Mark |= LOAD
		}
		if ad != 0 {
			break
		}
		s.size = uint8(sz)
		s.soffset = c.regoff(&p.From)

		s.used.cc |= E_MEMSB
	}

	cls = int(p.Reg)
	if cls != 0 {
		if REG_F0 <= cls && cls <= REG_F31 {
			s.used.freg |= 1 << uint(cls-REG_F0)
		} else {
			s.used.ireg |= 1 << uint(cls-REG_R0)
		}
	}
	s.set.ireg &^= (1 << (REGZERO - REG_R0)) /* R0 can't be set */
}

/*
 * test to see if two instructions can be
 * interchanged without changing semantics
 */
func (c *ctxt0) depend(sa, sb *Sch) bool {
	if sa.set.ireg&(sb.set.ireg|sb.used.ireg) != 0 {
		return true
	}
	if sb.set.ireg&sa.used.ireg != 0 {
		return true
	}

	if sa.set.freg&(sb.set.freg|sb.used.freg) != 0 {
		return true
	}
	if sb.set.freg&sa.used.freg != 0 {
		return true
	}

	/*
	 * special case.
	 * loads from same address cannot pass.
	 * this is for hardware fifo's and the like
	 */
	if sa.used.cc&sb.used.cc&E_MEM != 0 {
		if sa.p.Reg == sb.p.Reg {
			if c.regoff(&sa.p.From) == c.regoff(&sb.p.From) {
				return true
			}
		}
	}

	x := (sa.set.cc & (sb.set.cc | sb.used.cc)) | (sb.set.cc & sa.used.cc)
	if x != 0 {
		/*
		 * allow SB and SP to pass each other.
		 * allow SB to pass SB iff doffsets are ok
		 * anything else conflicts
		 */
		if x != E_MEMSP && x != E_MEMSB {
			return true
		}
		x = sa.set.cc | sb.set.cc | sa.used.cc | sb.used.cc
		if x&E_MEM != 0 {
			return true
		}
		if offoverlap(sa, sb) {
			return true
		}
	}

	return false
}

func offoverlap(sa, sb *Sch) bool {
	if sa.soffset < sb.soffset {
		if sa.soffset+int32(sa.size) > sb.soffset {
			return true
		}
		return false
	}
	if sb.soffset+int32(sb.size) > sa.soffset {
		return true
	}
	return false
}

/*
 * test 2 adjacent instructions
 * and find out if inserted instructions
 * are desired to prevent stalls.
 */
func conflict(sa, sb *Sch) bool {
	if sa.set.ireg&sb.used.ireg != 0 {
		return true
	}
	if sa.set.freg&sb.used.freg != 0 {
		return true
	}
	if sa.set.cc&sb.used.cc != 0 {
		return true
	}
	return false
}

func (c *ctxt0) compound(p *obj.Prog) bool {
	o := c.oplook(p)
	if o.size != 4 {
		return true
	}
	if p.To.Type == obj.TYPE_REG && p.To.Reg == REGSB {
		return true
	}
	return false
}

var Linkmips64 = obj.LinkArch{
	Arch:           sys.ArchMIPS64,
	Init:           buildop,
	Preprocess:     preprocess,
	Assemble:       span0,
	Progedit:       progedit,
	DWARFRegisters: MIPSDWARFRegisters,
}

var Linkmips64le = obj.LinkArch{
	Arch:           sys.ArchMIPS64LE,
	Init:           buildop,
	Preprocess:     preprocess,
	Assemble:       span0,
	Progedit:       progedit,
	DWARFRegisters: MIPSDWARFRegisters,
}

var Linkmips = obj.LinkArch{
	Arch:           sys.ArchMIPS,
	Init:           buildop,
	Preprocess:     preprocess,
	Assemble:       span0,
	Progedit:       progedit,
	DWARFRegisters: MIPSDWARFRegisters,
}

var Linkmipsle = obj.LinkArch{
	Arch:           sys.ArchMIPSLE,
	Init:           buildop,
	Preprocess:     preprocess,
	Assemble:       span0,
	Progedit:       progedit,
	DWARFRegisters: MIPSDWARFRegisters,
}
```