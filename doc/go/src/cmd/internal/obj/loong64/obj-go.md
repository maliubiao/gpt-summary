Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The file path `go/src/cmd/internal/obj/loong64/obj.go` immediately tells us this code is part of the Go compiler toolchain, specifically the assembler/linker for the `loong64` architecture. The `cmd/internal/obj` package is a key component for handling object code manipulation.

2. **Identify Key Functions:**  Scanning the code reveals the following top-level functions: `progedit`, `rewriteToUseGot`, `preprocess`, and the `Linkloong64` variable initialization. These are the primary units of functionality to examine.

3. **Analyze `progedit`:**  The name suggests this function edits a program instruction (`obj.Prog`). The comments and the `switch` statements within provide clues about specific instruction rewrites:
    * **Branch Handling:**  Rewrites `JMP`, `JAL`, `ARET`, `DUFFZERO`, `DUFFCOPY` with symbol targets to `TYPE_BRANCH`. This suggests handling control flow instructions targeting symbols.
    * **Floating-Point Constant Handling:** Converts floating-point constants in `AMOVF` and `AMOVD` instructions to memory references to pre-defined constant symbols. This is likely an optimization or a requirement of the architecture's instruction set. The zero-value optimization is also important.
    * **SUB to ADD Conversion:**  Transforms `SUB` instructions with constant operands into `ADD` instructions with the negated constant. This is a common compiler optimization.
    * **Dynamic Linking:**  Calls `rewriteToUseGot` if dynamic linking is enabled. This clearly indicates handling of external symbols in shared libraries.

4. **Analyze `rewriteToUseGot`:**  The name strongly hints at interaction with the Global Offset Table (GOT), a crucial component in dynamic linking. The code confirms this:
    * **`DUFF` Instructions:**  Rewrites `ADUFFCOPY` and `ADUFFZERO` to load the GOT address of the corresponding runtime functions into a temporary register and then jump to it. This is a typical pattern for calling external functions in dynamically linked environments.
    * **Global Data Access:** Handles `MOVV $sym, Rx` by loading the address of `sym` from the GOT. The code also handles offsets. The comments highlight the focus on `NAME_EXTERN` and `!p.From.Sym.Local()`, confirming it deals with external, non-local symbols.
    * **Symmetric External Access:** Rewrites `MOVx sym, Ry` and `MOVx Ry, sym` to use the GOT for accessing external symbols on either side of the instruction. This ensures all accesses to external data go through the GOT.

5. **Analyze `preprocess`:** This function seems to perform initial processing on the function's instructions. Key observations:
    * **Stack Size and NOFRAME:** Checks and enforces rules about stack frame size for functions marked `NOFRAME`.
    * **Argument and Local Sizes:** Extracts argument and local variable sizes from the `TEXT` instruction.
    * **Leaf Function Identification:**  Identifies leaf functions (those that don't call other functions) using instruction analysis.
    * **RET Expansion:** Expands `RET` instructions, potentially inserting code for stack adjustments and jumps. It handles both regular returns and tail calls (`retjmp`).
    * **Stack Split Check:** Calls `c.stacksplit` to insert code that checks for stack overflow and calls `morestack` if necessary.
    * **Function Prologue and Epilogue:** Inserts instructions to save/restore the link register and manage the stack pointer in the function prologue and epilogue.
    * **Wrapper Function Handling:**  Includes logic for wrapper functions, potentially adjusting the `panic.argp` pointer.
    * **`GETCALLERPC` Handling:** Implements `GETCALLERPC` differently for leaf and non-leaf functions.

6. **Analyze `stacksplit`:**  This function is clearly responsible for implementing the stack growth mechanism.
    * **`maymorestack` Handling:** Optionally calls a `maymorestack` function before the standard stack check, likely for more sophisticated stack management.
    * **Stack Guard Check:** Implements the logic to compare the current stack pointer (or stack pointer minus frame size) against the stack guard value.
    * **`morestack` Call:**  Calls the appropriate `runtime.morestack` function when a stack overflow is detected.
    * **Register Spilling and Unspilling:** Spills and unspills registers around the `morestack` call to preserve their values.

7. **Analyze `Linkloong64`:** This is the entry point that registers this architecture-specific code with the overall Go linking process. It specifies the architecture (`sys.ArchLoong64`) and assigns the functions analyzed above to their corresponding linking stages (`Init`, `Preprocess`, `Assemble`, `Progedit`).

8. **Infer Go Feature Implementation:** Based on the function analysis:
    * **Function Calls and Returns:**  The handling of `JAL`, `AJMP`, `ARET`, and link register manipulation points to the implementation of function calls and returns.
    * **Stack Management:**  The `preprocess` and `stacksplit` functions directly implement stack frame setup, stack growth, and stack overflow checks.
    * **Dynamic Linking:** `rewriteToUseGot` clearly implements the dynamic linking mechanism using the GOT.
    * **Floating-Point Constants:** The handling of `AMOVF` and `AMOVD` with `TYPE_FCONST` shows how floating-point constants are loaded.
    * **Compiler Optimizations:** The `SUB` to `ADD` conversion is a basic compiler optimization.

9. **Code Examples:** Constructing Go code examples that would trigger these behaviors involves writing functions that:
    * Call other functions (to demonstrate branch handling and stack management).
    * Use floating-point constants.
    * Are potentially subject to stack overflow.
    * Are part of a dynamically linked program (though this is harder to directly demonstrate in a simple example without the build process).

10. **Command-Line Arguments:** The code references `ctxt.Flag_dynlink` and `ctxt.Flag_maymorestack`. These correspond to compiler/linker flags like `-shared` (for dynamic linking) and potentially a flag to specify a custom `morestack` function.

11. **Common Mistakes:**  Think about potential pitfalls for users interacting with this functionality *indirectly* through the Go compiler:
    * Incorrect `NOFRAME` usage.
    * Assumptions about stack frame layout.
    * Issues related to dynamic linking if not properly configured.

By following these steps, we can systematically analyze the provided Go code snippet and understand its role in the Go compiler for the LoongArch 64-bit architecture. The key is to look for patterns, keywords related to compilation and linking concepts, and understand the purpose of each function within the overall process.
这段代码是 Go 语言编译器 `cmd/compile/internal/gc` 包中，针对 `loong64` (龙芯 64 位) 架构的代码生成和链接过程的一部分。它主要负责对中间代码进行架构特定的优化和转换，以便生成最终的可执行文件。

以下是它的主要功能：

1. **程序编辑 (`progedit`)**:
   - **重写跳转指令**: 将以符号为目标的 `JMP`、`JAL`、`ARET` 以及 `DUFFZERO`、`DUFFCOPY` 指令的目标类型设置为 `TYPE_BRANCH`，这有助于后续的链接器处理。
   - **处理浮点数常量**: 将浮点数常量（`TYPE_FCONST`）加载指令 `AMOVF` 和 `AMOVD` 转换为从内存中加载。
     - 如果常量是 0.0，则将其替换为从零寄存器加载，以提高效率。
     - 否则，将浮点数常量存储在一个特殊的符号表中 (`ctxt.Float32Sym`, `ctxt.Float64Sym`)，并将加载指令的目标修改为从该符号地址加载。
   - **将减法指令转换为加法指令**: 将立即数减法指令 `ASUB`、`ASUBU`、`ASUBV`、`ASUBVU` 转换为相应的加法指令 `AADD`、`AADDU`、`AADDV`、`AADDVU`，并将立即数取反。这是一种常见的编译器优化。
   - **处理动态链接**: 如果启用了动态链接 (`ctxt.Flag_dynlink`)，则调用 `rewriteToUseGot` 函数。

2. **重写以使用 GOT (`rewriteToUseGot`)**:
   - **处理 `DUFFCOPY` 和 `DUFFZERO`**:  对于 `ADUFFCOPY` 和 `ADUFFZERO` 指令，将其重写为通过 GOT (Global Offset Table) 表来调用 `runtime.duffcopy` 或 `runtime.duffzero` 函数。
     - 将原指令替换为加载 GOT 表中对应函数地址到临时寄存器的 `MOVV` 指令。
     - 添加一个将偏移量加到临时寄存器的 `ADDV` 指令。
     - 添加一个通过临时寄存器跳转的 `JAL` 指令。
   - **处理全局数据访问**: 当指令访问全局变量（`NAME_EXTERN`）时，将其重写为通过 GOT 表访问。
     - 对于 `MOVV $sym, Rx` 类型的指令，将其转换为 `MOVV sym@GOT, Rx`。
     - 如果存在偏移量，则在加载 GOT 表地址后，再添加一个 `ADDV` 指令加上偏移量。
   - **处理对称的全局数据访问**: 对于 `MOVx sym, Ry` 和 `MOVx Ry, sym` 这样的指令，如果 `sym` 是全局变量，也会将其重写为通过 GOT 表访问。
     - 先将 GOT 表中符号的地址加载到临时寄存器。
     - 然后使用临时寄存器作为地址进行数据的移动。

3. **预处理 (`preprocess`)**:
   - **设置函数参数和局部变量大小**: 从 `TEXT` 指令中获取函数参数和局部变量的大小。
   - **识别叶子函数**: 标记不调用其他函数的叶子函数。
   - **展开 `RET` 指令**: 将 `RET` 指令展开成更具体的操作，例如加载返回地址、调整栈指针等。针对叶子函数和非叶子函数有不同的处理方式。
   - **插入栈溢出检查 (`stacksplit`)**: 在函数入口处插入检查栈是否溢出的代码，如果可能溢出，则调用 `runtime.morestack` 来扩展栈空间。
   - **处理 `GETCALLERPC`**: 根据当前函数是否为叶子函数，将 `GETCALLERPC` 指令替换为不同的操作来获取调用者的 PC 值。
   - **标记同步点**:  在某些指令处标记 `SYNC`，用于垃圾回收的安全点。

4. **链接架构 (`Linkloong64`)**:
   - 定义了 `loong64` 架构的链接信息，包括架构名称、初始化函数、预处理函数、汇编函数、程序编辑函数以及 DWARF 寄存器信息。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码主要实现了 Go 语言中以下功能在 `loong64` 架构上的底层支持：

- **函数调用和返回**: `progedit` 中对 `JAL` 和 `ARET` 的处理，以及 `preprocess` 中对 `RET` 指令的展开和栈帧的管理，都与函数调用和返回机制密切相关。
- **栈管理**: `preprocess` 中的栈溢出检查 (`stacksplit`) 以及对栈指针的调整，是 Go 语言栈管理的核心部分。
- **动态链接**: `rewriteToUseGot` 函数明显是在处理动态链接相关的符号引用，通过 GOT 表来实现对外部符号的访问。
- **浮点数处理**: `progedit` 中对浮点数常量的处理，确保了浮点数在 `loong64` 架构上的正确加载和使用。
- **垃圾回收安全点**: `preprocess` 中标记的 `SYNC` 点用于支持垃圾回收器的安全操作。
- **`getcallerpc` 内建函数**: `preprocess` 中对 `obj.AGETCALLERPC` 的处理实现了获取调用者 PC 的功能。

**Go 代码举例说明 (`progedit` 和浮点数常量处理):**

```go
package main

import "fmt"

func main() {
	var f float32 = 3.14
	var d float64 = 2.71828
	var zeroF float32 = 0.0
	var zeroD float64 = 0.0

	fmt.Println(f, d, zeroF, zeroD)
}
```

**假设的输入与输出 (`progedit` 和浮点数常量处理):**

假设编译器在处理上述代码时，遇到了以下中间代码指令（简化表示）：

```
// ...
AMOVF $3.14, R1  // 将浮点数常量 3.14 移动到寄存器 R1
AMOVD $2.71828, R2 // 将浮点数常量 2.71828 移动到寄存器 R2
AMOVF $0.0, R3    // 将浮点数常量 0.0 移动到寄存器 R3
AMOVD $0.0, R4    // 将浮点数常量 0.0 移动到寄存器 R4
// ...
```

经过 `progedit` 处理后，输出可能变为（同样是简化表示）：

```
// ...
// 假设 ctxt.Float32Sym(3.14) 返回一个指向存储 3.14 的内存地址的符号 .f32.1
// 假设 ctxt.Float64Sym(2.71828) 返回一个指向存储 2.71828 的内存地址的符号 .f64.1
AMOVW (.f32.1), R1 // 从内存地址 .f32.1 加载 32 位浮点数到 R1
AMOVV (.f64.1), R2 // 从内存地址 .f64.1 加载 64 位浮点数到 R2
AMOVW REGZERO, R3   // 将零寄存器的值移动到 R3 (优化)
AMOVV REGZERO, R4   // 将零寄存器的值移动到 R4 (优化)
// ...
```

**Go 代码举例说明 (`rewriteToUseGot` 和动态链接):**

假设有一个外部函数 `externalFunc` 定义在共享库中，Go 代码中调用了它：

```go
package main

// #cgo LDFLAGS: -lexternal
// void externalFunc();
import "C"

func main() {
	C.externalFunc()
}
```

在编译这个使用了 cgo 和外部链接的程序时，如果启用了动态链接，`rewriteToUseGot` 可能会将对 `externalFunc` 的调用指令进行如下转换（简化表示）：

```
// 原始调用指令
AJAL externalFunc

// 转换后的指令
MOVV externalFunc@GOT, REGTMP // 将 externalFunc 在 GOT 表中的地址加载到临时寄存器 REGTMP
AJAL (REGTMP)              // 通过临时寄存器跳转到 externalFunc 的实际地址
```

**命令行参数的具体处理：**

- `ctxt.Flag_dynlink`:  这个标志通常对应编译器的 `-shared` 或 `-linkshared` 参数，用于指示是否生成可以与其他共享库链接的可执行文件或共享库本身。当设置了这个标志时，`rewriteToUseGot` 函数会被调用，处理与动态链接相关的指令重写。

- `ctxt.Flag_maymorestack`: 这个标志可能对应一个非标准的或实验性的选项，用于指定一个自定义的函数来执行更复杂的栈扩展逻辑。如果设置了这个标志，`stacksplit` 函数会生成调用该函数的代码。

**使用者易犯错的点 (与 `preprocess` 和栈管理相关):**

- **错误地使用 `//go:noinline` 和 `//go:nosplit`**:  开发者可能会错误地使用这些编译指示来阻止函数内联或栈溢出检查，这可能会导致程序崩溃或难以调试的问题，尤其是在对底层机制不熟悉的情况下。例如：

```go
//go:nosplit
func recursiveFunc() {
	recursiveFunc() // 如果没有栈溢出检查，可能会无限递归导致崩溃
}
```

- **手动操作栈指针**:  在 Go 中，栈管理是自动的。开发者不应该尝试手动修改栈指针 (SP) 的值，除非他们非常清楚自己在做什么，并且理解 Go 的栈模型。错误地操作 SP 会导致严重的运行时错误。虽然这段代码是在编译器内部，但理解其背后的原理有助于避免在汇编或其他底层编程中犯类似的错误。

总而言之，这段代码是 Go 语言在 `loong64` 架构上实现其核心功能（如函数调用、栈管理、动态链接等）的关键组成部分，它负责将高级的 Go 代码转换为能在该架构上高效执行的机器指令。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/loong64/obj.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package loong64

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/src"
	"cmd/internal/sys"
	"internal/abi"
	"log"
	"math"
)

func progedit(ctxt *obj.Link, p *obj.Prog, newprog obj.ProgAlloc) {
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
			if math.Float64bits(f64) == 0 {
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

	if ctxt.Flag_dynlink {
		rewriteToUseGot(ctxt, p, newprog)
	}
}

func rewriteToUseGot(ctxt *obj.Link, p *obj.Prog, newprog obj.ProgAlloc) {
	//     ADUFFxxx $offset
	// becomes
	//     MOVV runtime.duffxxx@GOT, REGTMP
	//     ADD $offset, REGTMP
	//     JAL REGTMP
	if p.As == obj.ADUFFCOPY || p.As == obj.ADUFFZERO {
		var sym *obj.LSym
		if p.As == obj.ADUFFZERO {
			sym = ctxt.LookupABI("runtime.duffzero", obj.ABIInternal)
		} else {
			sym = ctxt.LookupABI("runtime.duffcopy", obj.ABIInternal)
		}
		offset := p.To.Offset
		p.As = AMOVV
		p.From.Type = obj.TYPE_MEM
		p.From.Sym = sym
		p.From.Name = obj.NAME_GOTREF
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGTMP
		p.To.Name = obj.NAME_NONE
		p.To.Offset = 0
		p.To.Sym = nil
		p1 := obj.Appendp(p, newprog)
		p1.As = AADDV
		p1.From.Type = obj.TYPE_CONST
		p1.From.Offset = offset
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = REGTMP
		p2 := obj.Appendp(p1, newprog)
		p2.As = AJAL
		p2.To.Type = obj.TYPE_MEM
		p2.To.Reg = REGTMP
	}

	// We only care about global data: NAME_EXTERN means a global
	// symbol in the Go sense, and p.Sym.Local is true for a few
	// internally defined symbols.
	if p.From.Type == obj.TYPE_ADDR && p.From.Name == obj.NAME_EXTERN && !p.From.Sym.Local() {
		// MOVV $sym, Rx becomes MOVV sym@GOT, Rx
		// MOVV $sym+<off>, Rx becomes MOVV sym@GOT, Rx; ADD <off>, Rx
		if p.As != AMOVV {
			ctxt.Diag("do not know how to handle TYPE_ADDR in %v with -shared", p)
		}
		if p.To.Type != obj.TYPE_REG {
			ctxt.Diag("do not know how to handle LEAQ-type insn to non-register in %v with -shared", p)
		}
		p.From.Type = obj.TYPE_MEM
		p.From.Name = obj.NAME_GOTREF
		if p.From.Offset != 0 {
			q := obj.Appendp(p, newprog)
			q.As = AADDV
			q.From.Type = obj.TYPE_CONST
			q.From.Offset = p.From.Offset
			q.To = p.To
			p.From.Offset = 0
		}
	}
	if p.GetFrom3() != nil && p.GetFrom3().Name == obj.NAME_EXTERN {
		ctxt.Diag("don't know how to handle %v with -shared", p)
	}

	var source *obj.Addr
	// MOVx sym, Ry becomes MOVV sym@GOT, REGTMP; MOVx (REGTMP), Ry
	// MOVx Ry, sym becomes MOVV sym@GOT, REGTMP; MOVx Ry, (REGTMP)
	// An addition may be inserted between the two MOVs if there is an offset.
	if p.From.Name == obj.NAME_EXTERN && !p.From.Sym.Local() {
		if p.To.Name == obj.NAME_EXTERN && !p.To.Sym.Local() {
			ctxt.Diag("cannot handle NAME_EXTERN on both sides in %v with -shared", p)
		}
		source = &p.From
	} else if p.To.Name == obj.NAME_EXTERN && !p.To.Sym.Local() {
		source = &p.To
	} else {
		return
	}
	if p.As == obj.ATEXT || p.As == obj.AFUNCDATA || p.As == obj.ACALL || p.As == obj.ARET || p.As == obj.AJMP {
		return
	}
	if source.Sym.Type == objabi.STLSBSS {
		return
	}
	if source.Type != obj.TYPE_MEM {
		ctxt.Diag("don't know how to handle %v with -shared", p)
	}
	p1 := obj.Appendp(p, newprog)
	p2 := obj.Appendp(p1, newprog)
	p1.As = AMOVV
	p1.From.Type = obj.TYPE_MEM
	p1.From.Sym = source.Sym
	p1.From.Name = obj.NAME_GOTREF
	p1.To.Type = obj.TYPE_REG
	p1.To.Reg = REGTMP

	p2.As = p.As
	p2.From = p.From
	p2.To = p.To
	if p.From.Name == obj.NAME_EXTERN {
		p2.From.Reg = REGTMP
		p2.From.Name = obj.NAME_NONE
		p2.From.Sym = nil
	} else if p.To.Name == obj.NAME_EXTERN {
		p2.To.Reg = REGTMP
		p2.To.Name = obj.NAME_NONE
		p2.To.Sym = nil
	} else {
		return
	}

	obj.Nopout(p)
}

func preprocess(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc) {
	c := ctxt0{ctxt: ctxt, newprog: newprog, cursym: cursym}

	p := c.cursym.Func().Text
	textstksiz := p.To.Offset

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
	 */

	for p := c.cursym.Func().Text; p != nil; p = p.Link {
		switch p.As {
		case obj.ATEXT:
			p.Mark |= LABEL | LEAF | SYNC
			if p.Link != nil {
				p.Link.Mark |= LABEL
			}

		case AMOVW,
			AMOVV:
			if p.To.Type == obj.TYPE_REG && p.To.Reg >= REG_SPECIAL {
				p.Mark |= LABEL | SYNC
				break
			}
			if p.From.Type == obj.TYPE_REG && p.From.Reg >= REG_SPECIAL {
				p.Mark |= LABEL | SYNC
			}

		case ASYSCALL,
			AWORD:
			p.Mark |= LABEL | SYNC

		case ANOR:
			if p.To.Type == obj.TYPE_REG {
				if p.To.Reg == REGZERO {
					p.Mark |= LABEL | SYNC
				}
			}

		case AJAL,
			obj.ADUFFZERO,
			obj.ADUFFCOPY:
			c.cursym.Func().Text.Mark &^= LEAF
			fallthrough

		case AJMP,
			ABEQ,
			ABGEU,
			ABLTU,
			ABLTZ,
			ABNE,
			ABFPT, ABFPF:
			p.Mark |= BRANCH
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

	add = AADDV
	mov = AMOVV

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

			if p.Mark&LEAF != 0 && autosize < abi.StackSmall {
				// A leaf function with a small stack can be marked
				// NOSPLIT, avoiding a stack check.
				p.From.Sym.Set(obj.AttrNoSplit, true)
			}

			if autosize&4 != 0 {
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
				q.Pos = q.Pos.WithXlogue(src.PosPrologueEnd)
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
				//	MOV	g_panic(g), R20
				//	BEQ	R20, end
				//	MOV	panic_argp(R20), R24
				//	ADD	$(autosize+FIXED_FRAME), R3, R30
				//	BNE	R24, R30, end
				//	ADD	$FIXED_FRAME, R3, R24
				//	MOV	R24, panic_argp(R20)
				// end:
				//	NOP
				//
				// The NOP is needed to give the jumps somewhere to land.
				// It is a liblink NOP, not a hardware NOP: it encodes to 0 instruction bytes.
				//
				// We don't generate this for leaves because that means the wrapped
				// function was inlined into the wrapper.

				q = obj.Appendp(q, newprog)

				q.As = mov
				q.From.Type = obj.TYPE_MEM
				q.From.Reg = REGG
				q.From.Offset = 4 * int64(c.ctxt.Arch.PtrSize) // G.panic
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R20

				q = obj.Appendp(q, newprog)
				q.As = ABEQ
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R20
				q.To.Type = obj.TYPE_BRANCH
				q.Mark |= BRANCH
				p1 = q

				q = obj.Appendp(q, newprog)
				q.As = mov
				q.From.Type = obj.TYPE_MEM
				q.From.Reg = REG_R20
				q.From.Offset = 0 // Panic.argp
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R24

				q = obj.Appendp(q, newprog)
				q.As = add
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = int64(autosize) + ctxt.Arch.FixedFrameSize
				q.Reg = REGSP
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R30

				q = obj.Appendp(q, newprog)
				q.As = ABNE
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R24
				q.Reg = REG_R30
				q.To.Type = obj.TYPE_BRANCH
				q.Mark |= BRANCH
				p2 = q

				q = obj.Appendp(q, newprog)
				q.As = add
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = ctxt.Arch.FixedFrameSize
				q.Reg = REGSP
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R24

				q = obj.Appendp(q, newprog)
				q.As = mov
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R24
				q.To.Type = obj.TYPE_MEM
				q.To.Reg = REG_R20
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
					q.To.Offset = 0
					q.To.Reg = REGLINK
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
				// MOV LR, Rd
				p.As = mov
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGLINK
			} else {
				// MOV (RSP), Rd
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
}

func (c *ctxt0) stacksplit(p *obj.Prog, framesize int32) *obj.Prog {
	var mov, add obj.As

	add = AADDV
	mov = AMOVV
	if c.ctxt.Flag_maymorestack != "" {
		// Save LR and REGCTXT.
		frameSize := 2 * c.ctxt.Arch.PtrSize

		p = c.ctxt.StartUnsafePoint(p, c.newprog)

		// Spill Arguments. This has to happen before we open
		// any more frame space.
		p = c.cursym.Func().SpillRegisterArgs(p, c.newprog)

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

		// Unspill arguments
		p = c.cursym.Func().UnspillRegisterArgs(p, c.newprog)
		p = c.ctxt.EndUnsafePoint(p, c.newprog, -1)
	}

	// Jump back to here after morestack returns.
	startPred := p

	// MOV	g_stackguard(g), R20
	p = obj.Appendp(p, c.newprog)

	p.As = mov
	p.From.Type = obj.TYPE_MEM
	p.From.Reg = REGG
	p.From.Offset = 2 * int64(c.ctxt.Arch.PtrSize) // G.stackguard0
	if c.cursym.CFunc() {
		p.From.Offset = 3 * int64(c.ctxt.Arch.PtrSize) // G.stackguard1
	}
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REG_R20

	// Mark the stack bound check and morestack call async nonpreemptible.
	// If we get preempted here, when resumed the preemption request is
	// cleared, but we'll still call morestack, which will double the stack
	// unnecessarily. See issue #35470.
	p = c.ctxt.StartUnsafePoint(p, c.newprog)

	var q *obj.Prog
	if framesize <= abi.StackSmall {
		// small stack: SP < stackguard
		//	SGTU	SP, stackguard, R20
		p = obj.Appendp(p, c.newprog)

		p.As = ASGTU
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGSP
		p.Reg = REG_R20
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R20
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
			//      SGTU    $(framesize-StackSmall), SP, R24
			//      BNE     R24, label-of-call-to-morestack

			p = obj.Appendp(p, c.newprog)
			p.As = ASGTU
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = offset
			p.Reg = REGSP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = REG_R24

			p = obj.Appendp(p, c.newprog)
			q = p
			p.As = ABNE
			p.From.Type = obj.TYPE_REG
			p.From.Reg = REG_R24
			p.To.Type = obj.TYPE_BRANCH
			p.Mark |= BRANCH
		}

		p = obj.Appendp(p, c.newprog)

		p.As = add
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = -offset
		p.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R24

		p = obj.Appendp(p, c.newprog)
		p.As = ASGTU
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_R24
		p.Reg = REG_R20
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R20
	}

	// q1: BEQ	R20, morestack
	p = obj.Appendp(p, c.newprog)
	q1 := p

	p.As = ABEQ
	p.From.Type = obj.TYPE_REG
	p.From.Reg = REG_R20
	p.To.Type = obj.TYPE_BRANCH
	p.Mark |= BRANCH

	end := c.ctxt.EndUnsafePoint(p, c.newprog, -1)

	var last *obj.Prog
	for last = c.cursym.Func().Text; last.Link != nil; last = last.Link {
	}

	// Now we are at the end of the function, but logically
	// we are still in function prologue. We need to fix the
	// SP data and PCDATA.
	spfix := obj.Appendp(last, c.newprog)
	spfix.As = obj.ANOP
	spfix.Spadj = -framesize

	pcdata := c.ctxt.EmitEntryStackMap(c.cursym, spfix, c.newprog)
	pcdata = c.ctxt.StartUnsafePoint(pcdata, c.newprog)

	if q != nil {
		q.To.SetTarget(pcdata)
	}
	q1.To.SetTarget(pcdata)

	p = c.cursym.Func().SpillRegisterArgs(pcdata, c.newprog)

	// MOV  LINK, R31
	p = obj.Appendp(p, c.newprog)
	p.As = mov
	p.From.Type = obj.TYPE_REG
	p.From.Reg = REGLINK
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REG_R31
	if q != nil {
		q.To.SetTarget(p)
		p.Mark |= LABEL
	}

	// JAL runtime.morestack(SB)
	call := obj.Appendp(p, c.newprog)
	call.As = AJAL
	call.To.Type = obj.TYPE_BRANCH

	if c.cursym.CFunc() {
		call.To.Sym = c.ctxt.Lookup("runtime.morestackc")
	} else if !c.cursym.Func().Text.From.Sym.NeedCtxt() {
		call.To.Sym = c.ctxt.Lookup("runtime.morestack_noctxt")
	} else {
		call.To.Sym = c.ctxt.Lookup("runtime.morestack")
	}
	call.Mark |= BRANCH

	// The instructions which unspill regs should be preemptible.
	pcdata = c.ctxt.EndUnsafePoint(call, c.newprog, -1)
	unspill := c.cursym.Func().UnspillRegisterArgs(pcdata, c.newprog)

	// JMP start
	jmp := obj.Appendp(unspill, c.newprog)
	jmp.As = AJMP
	jmp.To.Type = obj.TYPE_BRANCH
	jmp.To.SetTarget(startPred.Link)
	jmp.Spadj = +framesize

	return end
}

func (c *ctxt0) addnop(p *obj.Prog) {
	q := c.newprog()
	q.As = ANOOP
	q.Pos = p.Pos
	q.Link = p.Link
	p.Link = q
}

var Linkloong64 = obj.LinkArch{
	Arch:           sys.ArchLoong64,
	Init:           buildop,
	Preprocess:     preprocess,
	Assemble:       span0,
	Progedit:       progedit,
	DWARFRegisters: LOONG64DWARFRegisters,
}

"""



```