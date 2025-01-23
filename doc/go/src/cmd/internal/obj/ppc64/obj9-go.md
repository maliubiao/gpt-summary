Response: Let's break down the thought process for analyzing the `obj9.go` file.

1. **Understand the Goal:** The request asks for the functionality of the given Go code snippet. Specifically, it wants to know what Go language features this code helps implement, with examples, command-line parameter handling, and common mistakes.

2. **Identify the File's Role:**  The path `go/src/cmd/internal/obj/ppc64/obj9.go` is a crucial starting point. It tells us:
    * `cmd`: This is part of the Go toolchain.
    * `internal`: This package is not meant for public use.
    * `obj`: This likely deals with object file manipulation or assembly.
    * `ppc64`: This is specific to the PowerPC 64-bit architecture.
    * `obj9.go`: The "9" suggests this is related to the 9th assembler for this architecture (though historically the numbering might be more complex). The `.go` extension confirms it's Go source code.

3. **Examine the Imports:** The imported packages provide clues about the file's responsibilities:
    * `cmd/internal/obj`: Core object file structures and utilities.
    * `cmd/internal/objabi`: Definitions for object file formats and ABIs.
    * `cmd/internal/src`: Source code position information.
    * `cmd/internal/sys`: System architecture information.
    * `internal/abi`:  Internal ABI definitions.
    * `internal/buildcfg`: Build configuration details.
    * `log`: Logging for debugging or informational messages.
    * `math`, `math/bits`: Mathematical operations, particularly bit manipulation.
    * `strings`: String manipulation.

4. **Analyze Top-Level Functions:**  Start by reading through the function definitions and their comments:
    * `isPPC64DoublewordRotateMask`: Checks if a 64-bit value can be represented by a specific PowerPC rotate mask. This suggests instruction encoding or optimization related to bitwise operations.
    * `encodePPC64RLDCMask`: Encodes a doubleword rotate mask into its `mb` and `me` (mask begin/end) components. This directly supports the previous function, indicating mask-related instruction generation.
    * `isNOTOCfunc`: Checks if a function name should *not* have a TOC (Table of Contents) prologue generated. This points to handling of function calls in position-independent code (PIC) environments, likely on AIX.
    * `convertFMOVtoXXSPLTIDP`: Attempts to convert floating-point move instructions into a vector instruction (`XXSPLTIDP`). This indicates an optimization pass for floating-point operations, potentially for newer PowerPC architectures.
    * `progedit`: This is a crucial function. The name suggests it edits or modifies `obj.Prog` (program/instruction) structures. It's the heart of instruction rewriting and optimization.
    * `rewriteToUseTOC`:  Rewrites instructions to use the TOC for accessing symbols. Strong indication of AIX-specific PIC handling.
    * `rewriteToUseGot`: Rewrites instructions to use the GOT (Global Offset Table) for accessing global data. This is for general dynamic linking.
    * `preprocess`:  Performs pre-processing steps on a function's instructions. This involves tasks like identifying leaf functions, expanding `RET` instructions, and handling stack management.
    * `stacksplit`: Generates code for stack overflow checks and calls to `runtime.morestack`. This is fundamental to Go's dynamic stack growth.

5. **Deep Dive into Key Functions (progedit):**  `progedit` is the most complex. Break down its `switch` statements:
    * **Branch Rewriting:** Converts symbolic branches to `TYPE_BRANCH`.
    * **Floating-Point Constants:**  Moves floating-point constants to memory (data section). The `convertFMOVtoXXSPLTIDP` call is within this block, showing an optimization within constant loading.
    * **Integer Constants (AMOVW, AMOVWZ, AMOVD):**  Significant logic for optimizing integer constant loads. It tries to use efficient instructions like `ADDIS`, `ORIS`, and even converts to shift-and-load sequences or mask operations where possible. This demonstrates a key role in code generation efficiency.
    * **SUB to ADD Conversion:** Rewrites subtraction with constants as addition with the negated constant.
    * **ADD/OR/XOR/ANDCC Optimizations:**  Attempts to use immediate instructions (`ADDIS`, `ORIS`, etc.) for constant operands.
    * **Argument Ordering Rewrite:**  Handles potentially incorrect argument ordering in some instructions for backward compatibility.

6. **Analyze `rewriteToUseTOC` and `rewriteToUseGot`:** These functions are clearly about handling external symbols in different linking scenarios. `rewriteToUseTOC` is specific to AIX and the TOC, while `rewriteToUseGot` is for general dynamic linking using the GOT. The code manipulates instruction operands to reference symbols indirectly through these tables.

7. **Analyze `preprocess`:** This function does several things:
    * **Leaf Function Detection:** Identifies functions that don't call other functions, allowing for stack frame optimizations.
    * **RET Expansion:**  Expands `RET` instructions to handle stack unwinding and potential function epilogues.
    * **Stack Frame Setup:** Inserts instructions to allocate and manage the stack frame, including saving the link register.
    * **Stack Overflow Checks:** Calls `stacksplit`.

8. **Analyze `stacksplit`:**  This function generates the code to check if the current stack has enough space. If not, it calls `runtime.morestack` to grow the stack. This is core to Go's memory management model.

9. **Identify Go Language Features:**  Based on the code analysis, connect the functionality to Go features:
    * **Function Calls (especially in PIC on AIX and dynamic linking):** `rewriteToUseTOC`, `rewriteToUseGot`, TOC prologue insertion in `preprocess`.
    * **Floating-Point Operations:** `convertFMOVtoXXSPLTIDP`, handling of floating-point constants in `progedit`.
    * **Integer Operations:** Constant optimization in `progedit`, rotate mask handling.
    * **Stack Management:** `preprocess` (frame setup), `stacksplit` (stack growth).
    * **Function Prologues and Epilogues:**  Code inserted in `preprocess` for saving/restoring registers, adjusting the stack pointer.
    * **Dynamic Linking:** `rewriteToUseGot`.

10. **Construct Examples:** Create simple Go code snippets that would trigger the functionalities observed in the code. Think about function calls, using floating-point numbers, integer constants, etc.

11. **Consider Command-Line Parameters:** Look for references to `ctxt.Flag_...` variables. These indicate command-line flags that influence the behavior of the assembler/linker. `-dynlink` and `-shared` are prominent examples.

12. **Identify Common Mistakes:** Think about scenarios where developers might make errors related to the optimizations or transformations performed by this code. For example, assuming a direct memory access when the code might be using the GOT, or making assumptions about stack frame layout.

13. **Structure the Output:** Organize the findings into clear sections covering functionality, Go language feature implementation, code examples, command-line parameters, and potential mistakes. Use clear and concise language.

By following this structured analysis, we can systematically understand the purpose and functionality of the `obj9.go` file and effectively address all aspects of the request.
这是 Go 语言编译器 `cmd/compile` 中 PowerPC 64 位架构（ppc64）的汇编器部分代码。它负责将中间表示（IR）的 Go 代码转换为目标机器的汇编指令。

下面列举一下 `obj9.go` 的主要功能：

1. **指令级别的优化和转换:**
   - **常量加载优化:**  将常量加载指令优化为更高效的指令序列，例如将 `MOVD $const, Rx` 转换为 `ADDIS/ORIS` 等更小的指令，或者使用位移和掩码操作来生成常量。
   - **浮点数常量处理:** 将浮点数常量存储到只读数据段，并通过内存访问指令加载。对于特定的单精度浮点数，会尝试转换为 `XXSPLTIDP` 向量指令进行优化。
   - **分支指令处理:** 将分支指令的目标转换为 `TYPE_BRANCH` 类型。
   - **SUB 指令优化:** 将常量减法 `SUBC $const, ...` 转换为加法 `ADDC $-const, ...`。
   - **特殊指令的调整:**  对于某些指令（如 `VSHASIGMAW`, `AADDEX` 等），调整操作数顺序以适应汇编器的处理。
   - **针对 AIX 和动态链接的代码重写:**  在 AIX 系统上，会将全局符号的访问重写为通过 TOC (Table of Contents) 进行；在动态链接的情况下，会将全局符号的访问重写为通过 GOT (Global Offset Table) 进行。

2. **函数序言（Prologue）和结语（Epilogue）处理:**
   - **栈帧管理:** 计算函数所需的栈帧大小，并在函数序言中分配栈空间，保存链接寄存器 (LR)。
   - **栈溢出检测:**  插入栈溢出检测代码，如果栈空间不足，则调用 `runtime.morestack` 函数进行栈扩展。
   - **叶子函数优化:**  对于没有调用其他 Go 函数的叶子函数，可以省略栈帧的创建。
   - **`NOSPLIT` 优化:**  对于栈帧较小的叶子函数，可以标记为 `NOSPLIT`，避免栈检查。
   - **包装函数处理:** 对于包装函数，会插入代码来检查和更新 `g.panic->argp`。

3. **指令调度 (注释部分):**  虽然代码中被注释掉了，但可以看出原本有指令调度的功能，旨在优化指令执行顺序。

**它是什么 Go 语言功能的实现？**

`obj9.go` 是 Go 语言编译器实现的重要组成部分，它直接参与了以下 Go 语言功能的实现：

* **函数调用:**  通过处理函数序言和结语，以及对 AIX 和动态链接的支持，确保函数能够正确地被调用和返回。
* **变量访问:**  通过处理全局变量的访问方式（TOC/GOT），使得程序能够正确地访问全局变量。
* **常量使用:**  通过优化常量加载，提高代码执行效率。
* **栈管理:**  通过插入栈溢出检测和管理栈帧，保证程序的稳定运行和内存安全。
* **内联汇编 (间接体现):**  虽然 `obj9.go` 本身不直接处理内联汇编，但它生成的指令是内联汇编的基础。
* **运行时支持:**  通过调用 `runtime.morestack` 等运行时函数，与 Go 运行时系统协同工作。

**Go 代码举例说明:**

```go
package main

import "fmt"

var globalVar int = 10

func add(a, b int) int {
	const localConst int = 5
	return a + b + localConst + globalVar
}

func main() {
	result := add(2, 3)
	fmt.Println(result)
}
```

**假设的输入与输出（针对 `progedit` 函数的常量优化部分）:**

**假设输入（`p *obj.Prog`）:**

```
As: AMOVD
From: {Type: obj.TYPE_CONST, Offset: 65536, Name: obj.NAME_NONE, Reg: 0}
To: {Type: obj.TYPE_REG, Reg: REG_R3}
```

这表示一个将常量 65536 (0x10000) 加载到寄存器 R3 的指令。

**输出（修改后的 `p *obj.Prog`）:**

```
As: AADDIS
From: {Type: obj.TYPE_CONST, Offset: 1, Name: obj.NAME_NONE, Reg: 0}
Reg: REG_R0
To: {Type: obj.TYPE_REG, Reg: REG_R3}
```

`AMOVD $65536, R3` 被转换为 `AADDIS $1, R0, R3`。这是因为 65536 可以通过 `ADDIS` 指令高效地加载（65536 >> 16 = 1）。这里假设 `REG_R0` 是零寄存器。

**涉及命令行参数的具体处理:**

`obj9.go` 中会检查 `ctxt.Flag_dynlink` 和 `ctxt.Flag_shared` 等标志，这些标志通常由 `go build` 或 `go tool compile` 命令传递。

* **`-dynlink`:**  指示编译器生成可以动态链接的代码。这会导致 `rewriteToUseGot` 函数被调用，将全局符号的访问重写为通过 GOT 进行。例如，如果使用 `-dynlink` 编译上面的示例代码，访问 `globalVar` 的指令可能会被修改为从 GOT 表中加载地址。
* **`-shared`:**  指示编译器生成共享库。这也会影响全局符号的处理方式。
* **`-maymorestack`:**  允许更激进的栈增长策略，会影响 `stacksplit` 函数的实现。

**使用者易犯错的点（与此文件相关的间接错误）：**

由于 `obj9.go` 是编译器内部的代码，普通 Go 开发者不会直接与之交互。但编译器行为的改变可能会间接影响开发者，例如：

* **假设全局变量的访问方式:**  在不同的编译模式下（例如，是否使用 `-dynlink`），全局变量的访问方式可能会有所不同。如果开发者编写了与特定访问方式相关的底层代码（通常是 C 代码通过 `cgo` 调用），则可能在不同的编译模式下出现问题。
* **对栈帧布局的假设:**  编译器会根据优化策略调整栈帧布局。如果 C 代码通过 `cgo` 与 Go 代码交互，并且对 Go 函数的栈帧布局有硬编码的假设，则可能会因为编译器的优化而导致错误。
* **内联汇编的兼容性:**  虽然 `obj9.go` 不直接处理内联汇编，但其生成的指令是内联汇编的基础。如果内联汇编代码依赖于特定的指令序列或寄存器使用方式，而编译器的优化策略发生了变化，则可能会导致内联汇编代码失效。

**总结:**

`go/src/cmd/internal/obj/ppc64/obj9.go` 是 Go 语言编译器中针对 PowerPC 64 位架构的关键组成部分，负责将 Go 代码转换为高效的机器码，并处理与特定操作系统（如 AIX）和链接模式相关的细节。它涉及到指令优化、函数调用约定、栈管理等核心功能，是 Go 语言编译过程中的重要一环。

### 提示词
```
这是路径为go/src/cmd/internal/obj/ppc64/obj9.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package ppc64

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/src"
	"cmd/internal/sys"
	"internal/abi"
	"internal/buildcfg"
	"log"
	"math"
	"math/bits"
	"strings"
)

// Test if this value can encoded as a mask for
// li -1, rx; rlic rx,rx,sh,mb.
// Masks can also extend from the msb and wrap to
// the lsb too. That is, the valid masks are 32 bit strings
// of the form: 0..01..10..0 or 1..10..01..1 or 1...1
func isPPC64DoublewordRotateMask(v64 int64) bool {
	// Isolate rightmost 1 (if none 0) and add.
	v := uint64(v64)
	vp := (v & -v) + v
	// Likewise, for the wrapping case.
	vn := ^v
	vpn := (vn & -vn) + vn
	return (v&vp == 0 || vn&vpn == 0) && v != 0
}

// Encode a doubleword rotate mask into mb (mask begin) and
// me (mask end, inclusive). Note, POWER ISA labels bits in
// big endian order.
func encodePPC64RLDCMask(mask int64) (mb, me int) {
	// Determine boundaries and then decode them
	mb = bits.LeadingZeros64(uint64(mask))
	me = 64 - bits.TrailingZeros64(uint64(mask))
	mbn := bits.LeadingZeros64(^uint64(mask))
	men := 64 - bits.TrailingZeros64(^uint64(mask))
	// Check for a wrapping mask (e.g bits at 0 and 63)
	if mb == 0 && me == 64 {
		// swap the inverted values
		mb, me = men, mbn
	}
	// Note, me is inclusive.
	return mb, me - 1
}

// Is this a symbol which should never have a TOC prologue generated?
// These are special functions which should not have a TOC regeneration
// prologue.
func isNOTOCfunc(name string) bool {
	switch {
	case name == "runtime.duffzero":
		return true
	case name == "runtime.duffcopy":
		return true
	case strings.HasPrefix(name, "runtime.elf_"):
		return true
	default:
		return false
	}
}

// Try converting FMOVD/FMOVS to XXSPLTIDP. If it is converted,
// return true.
func convertFMOVtoXXSPLTIDP(p *obj.Prog) bool {
	if p.From.Type != obj.TYPE_FCONST || buildcfg.GOPPC64 < 10 {
		return false
	}
	v := p.From.Val.(float64)
	if float64(float32(v)) != v {
		return false
	}
	// Secondly, is this value a normal value?
	ival := int64(math.Float32bits(float32(v)))
	isDenorm := ival&0x7F800000 == 0 && ival&0x007FFFFF != 0
	if !isDenorm {
		p.As = AXXSPLTIDP
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = ival
		// Convert REG_Fx into equivalent REG_VSx
		p.To.Reg = REG_VS0 + (p.To.Reg & 31)
	}
	return !isDenorm
}

func progedit(ctxt *obj.Link, p *obj.Prog, newprog obj.ProgAlloc) {
	p.From.Class = 0
	p.To.Class = 0

	c := ctxt9{ctxt: ctxt, newprog: newprog}

	// Rewrite BR/BL to symbol as TYPE_BRANCH.
	switch p.As {
	case ABR,
		ABL,
		obj.ARET,
		obj.ADUFFZERO,
		obj.ADUFFCOPY:
		if p.To.Sym != nil {
			p.To.Type = obj.TYPE_BRANCH
		}
	}

	// Rewrite float constants to values stored in memory.
	switch p.As {
	case AFMOVS:
		if p.From.Type == obj.TYPE_FCONST && !convertFMOVtoXXSPLTIDP(p) {
			f32 := float32(p.From.Val.(float64))
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = ctxt.Float32Sym(f32)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}

	case AFMOVD:
		if p.From.Type == obj.TYPE_FCONST {
			f64 := p.From.Val.(float64)
			// Constant not needed in memory for float +/- 0
			if f64 != 0 && !convertFMOVtoXXSPLTIDP(p) {
				p.From.Type = obj.TYPE_MEM
				p.From.Sym = ctxt.Float64Sym(f64)
				p.From.Name = obj.NAME_EXTERN
				p.From.Offset = 0
			}
		}

	case AMOVW, AMOVWZ:
		// Note, for backwards compatibility, MOVW $const, Rx and MOVWZ $const, Rx are identical.
		if p.From.Type == obj.TYPE_CONST && p.From.Offset != 0 && p.From.Offset&0xFFFF == 0 {
			// This is a constant shifted 16 bits to the left, convert it to ADDIS/ORIS $const,...
			p.As = AADDIS
			// Use ORIS for large constants which should not be sign extended.
			if p.From.Offset >= 0x80000000 {
				p.As = AORIS
			}
			p.Reg = REG_R0
			p.From.Offset >>= 16
		}

	case AMOVD:
		// Skip this opcode if it is not a constant load.
		if p.From.Type != obj.TYPE_CONST || p.From.Name != obj.NAME_NONE || p.From.Reg != 0 {
			break
		}

		// 32b constants (signed and unsigned) can be generated via 1 or 2 instructions. They can be assembled directly.
		isS32 := int64(int32(p.From.Offset)) == p.From.Offset
		isU32 := uint64(uint32(p.From.Offset)) == uint64(p.From.Offset)
		// If prefixed instructions are supported, a 34b signed constant can be generated by one pli instruction.
		isS34 := pfxEnabled && (p.From.Offset<<30)>>30 == p.From.Offset

		// Try converting MOVD $const,Rx into ADDIS/ORIS $s32>>16,R0,Rx
		switch {
		case isS32 && p.From.Offset&0xFFFF == 0 && p.From.Offset != 0:
			p.As = AADDIS
			p.From.Offset >>= 16
			p.Reg = REG_R0

		case isU32 && p.From.Offset&0xFFFF == 0 && p.From.Offset != 0:
			p.As = AORIS
			p.From.Offset >>= 16
			p.Reg = REG_R0

		case isS32 || isU32 || isS34:
			// The assembler can generate this opcode in 1 (on Power10) or 2 opcodes.

		// Otherwise, see if the large constant can be generated with 2 instructions. If not, load it from memory.
		default:
			// Is this a shifted 16b constant? If so, rewrite it to avoid a creating and loading a constant.
			val := p.From.Offset
			shift := bits.TrailingZeros64(uint64(val))
			mask := int64(0xFFFF) << shift
			if val&mask == val || (val>>(shift+16) == -1 && (val>>shift)<<shift == val) {
				// Rewrite this value into MOVD $const>>shift, Rto; SLD $shift, Rto
				q := obj.Appendp(p, c.newprog)
				q.As = ASLD
				q.From.SetConst(int64(shift))
				q.To = p.To
				p.From.Offset >>= shift
				p = q
			} else if isPPC64DoublewordRotateMask(val) {
				// This constant is a mask value, generate MOVD $-1, Rto; RLDIC Rto, ^me, mb, Rto
				mb, me := encodePPC64RLDCMask(val)
				q := obj.Appendp(p, c.newprog)
				q.As = ARLDC
				q.AddRestSourceConst((^int64(me)) & 0x3F)
				q.AddRestSourceConst(int64(mb))
				q.From = p.To
				q.To = p.To
				p.From.Offset = -1
				p = q
			} else {
				// Load the constant from memory.
				p.From.Type = obj.TYPE_MEM
				p.From.Sym = ctxt.Int64Sym(p.From.Offset)
				p.From.Name = obj.NAME_EXTERN
				p.From.Offset = 0
			}
		}
	}

	switch p.As {
	// Rewrite SUB constants into ADD.
	case ASUBC:
		if p.From.Type == obj.TYPE_CONST {
			p.From.Offset = -p.From.Offset
			p.As = AADDC
		}

	case ASUBCCC:
		if p.From.Type == obj.TYPE_CONST {
			p.From.Offset = -p.From.Offset
			p.As = AADDCCC
		}

	case ASUB:
		if p.From.Type != obj.TYPE_CONST {
			break
		}
		// Rewrite SUB $const,... into ADD $-const,...
		p.From.Offset = -p.From.Offset
		p.As = AADD
		// This is now an ADD opcode, try simplifying it below.
		fallthrough

	// Rewrite ADD/OR/XOR/ANDCC $const,... forms into ADDIS/ORIS/XORIS/ANDISCC
	case AADD:
		// Don't rewrite if this is not adding a constant value, or is not an int32
		if p.From.Type != obj.TYPE_CONST || p.From.Offset == 0 || int64(int32(p.From.Offset)) != p.From.Offset {
			break
		}
		if p.From.Offset&0xFFFF == 0 {
			// The constant can be added using ADDIS
			p.As = AADDIS
			p.From.Offset >>= 16
		} else if buildcfg.GOPPC64 >= 10 {
			// Let the assembler generate paddi for large constants.
			break
		} else if (p.From.Offset < -0x8000 && int64(int32(p.From.Offset)) == p.From.Offset) || (p.From.Offset > 0xFFFF && p.From.Offset < 0x7FFF8000) {
			// For a constant x, 0xFFFF (UINT16_MAX) < x < 0x7FFF8000 or -0x80000000 (INT32_MIN) <= x < -0x8000 (INT16_MIN)
			// This is not done for 0x7FFF < x < 0x10000; the assembler will generate a slightly faster instruction sequence.
			//
			// The constant x can be rewritten as ADDIS + ADD as follows:
			//     ADDIS $x>>16 + (x>>15)&1, rX, rY
			//     ADD   $int64(int16(x)), rY, rY
			// The range is slightly asymmetric as 0x7FFF8000 and above overflow the sign bit, whereas for
			// negative values, this would happen with constant values between -1 and -32768 which can
			// assemble into a single addi.
			is := p.From.Offset>>16 + (p.From.Offset>>15)&1
			i := int64(int16(p.From.Offset))
			p.As = AADDIS
			p.From.Offset = is
			q := obj.Appendp(p, c.newprog)
			q.As = AADD
			q.From.SetConst(i)
			q.Reg = p.To.Reg
			q.To = p.To
			p = q
		}
	case AOR:
		if p.From.Type == obj.TYPE_CONST && uint64(p.From.Offset)&0xFFFFFFFF0000FFFF == 0 && p.From.Offset != 0 {
			p.As = AORIS
			p.From.Offset >>= 16
		}
	case AXOR:
		if p.From.Type == obj.TYPE_CONST && uint64(p.From.Offset)&0xFFFFFFFF0000FFFF == 0 && p.From.Offset != 0 {
			p.As = AXORIS
			p.From.Offset >>= 16
		}
	case AANDCC:
		if p.From.Type == obj.TYPE_CONST && uint64(p.From.Offset)&0xFFFFFFFF0000FFFF == 0 && p.From.Offset != 0 {
			p.As = AANDISCC
			p.From.Offset >>= 16
		}

	// To maintain backwards compatibility, we accept some 4 argument usage of
	// several opcodes which was likely not intended, but did work. These are not
	// added to optab to avoid the chance this behavior might be used with newer
	// instructions.
	//
	// Rewrite argument ordering like "ADDEX R3, $3, R4, R5" into
	//                                "ADDEX R3, R4, $3, R5"
	case AVSHASIGMAW, AVSHASIGMAD, AADDEX, AXXSLDWI, AXXPERMDI:
		if len(p.RestArgs) == 2 && p.Reg == 0 && p.RestArgs[0].Addr.Type == obj.TYPE_CONST && p.RestArgs[1].Addr.Type == obj.TYPE_REG {
			p.Reg = p.RestArgs[1].Addr.Reg
			p.RestArgs = p.RestArgs[:1]
		}
	}

	if c.ctxt.Headtype == objabi.Haix {
		c.rewriteToUseTOC(p)
	} else if c.ctxt.Flag_dynlink {
		c.rewriteToUseGot(p)
	}
}

// Rewrite p, if necessary, to access a symbol using its TOC anchor.
// This code is for AIX only.
func (c *ctxt9) rewriteToUseTOC(p *obj.Prog) {
	if p.As == obj.ATEXT || p.As == obj.AFUNCDATA || p.As == obj.ACALL || p.As == obj.ARET || p.As == obj.AJMP {
		return
	}

	if p.As == obj.ADUFFCOPY || p.As == obj.ADUFFZERO {
		// ADUFFZERO/ADUFFCOPY is considered as an ABL except in dynamic
		// link where it should be an indirect call.
		if !c.ctxt.Flag_dynlink {
			return
		}
		//     ADUFFxxx $offset
		// becomes
		//     MOVD runtime.duffxxx@TOC, R12
		//     ADD $offset, R12
		//     MOVD R12, LR
		//     BL (LR)
		var sym *obj.LSym
		if p.As == obj.ADUFFZERO {
			sym = c.ctxt.Lookup("runtime.duffzero")
		} else {
			sym = c.ctxt.Lookup("runtime.duffcopy")
		}
		// Retrieve or create the TOC anchor.
		symtoc := c.ctxt.LookupInit("TOC."+sym.Name, func(s *obj.LSym) {
			s.Type = objabi.SDATA
			s.Set(obj.AttrDuplicateOK, true)
			s.Set(obj.AttrStatic, true)
			c.ctxt.Data = append(c.ctxt.Data, s)
			s.WriteAddr(c.ctxt, 0, 8, sym, 0)
		})

		offset := p.To.Offset
		p.As = AMOVD
		p.From.Type = obj.TYPE_MEM
		p.From.Name = obj.NAME_TOCREF
		p.From.Sym = symtoc
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R12
		p.To.Name = obj.NAME_NONE
		p.To.Offset = 0
		p.To.Sym = nil
		p1 := obj.Appendp(p, c.newprog)
		p1.As = AADD
		p1.From.Type = obj.TYPE_CONST
		p1.From.Offset = offset
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = REG_R12
		p2 := obj.Appendp(p1, c.newprog)
		p2.As = AMOVD
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = REG_R12
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = REG_LR
		p3 := obj.Appendp(p2, c.newprog)
		p3.As = obj.ACALL
		p3.To.Type = obj.TYPE_REG
		p3.To.Reg = REG_LR
	}

	var source *obj.Addr
	if p.From.Name == obj.NAME_EXTERN || p.From.Name == obj.NAME_STATIC {
		if p.From.Type == obj.TYPE_ADDR {
			if p.As == ADWORD {
				// ADWORD $sym doesn't need TOC anchor
				return
			}
			if p.As != AMOVD {
				c.ctxt.Diag("do not know how to handle TYPE_ADDR in %v", p)
				return
			}
			if p.To.Type != obj.TYPE_REG {
				c.ctxt.Diag("do not know how to handle LEAQ-type insn to non-register in %v", p)
				return
			}
		} else if p.From.Type != obj.TYPE_MEM {
			c.ctxt.Diag("do not know how to handle %v without TYPE_MEM", p)
			return
		}
		source = &p.From

	} else if p.To.Name == obj.NAME_EXTERN || p.To.Name == obj.NAME_STATIC {
		if p.To.Type != obj.TYPE_MEM {
			c.ctxt.Diag("do not know how to handle %v without TYPE_MEM", p)
			return
		}
		if source != nil {
			c.ctxt.Diag("cannot handle symbols on both sides in %v", p)
			return
		}
		source = &p.To
	} else {
		return

	}

	if source.Sym == nil {
		c.ctxt.Diag("do not know how to handle nil symbol in %v", p)
		return
	}

	if source.Sym.Type == objabi.STLSBSS {
		return
	}

	// Retrieve or create the TOC anchor.
	symtoc := c.ctxt.LookupInit("TOC."+source.Sym.Name, func(s *obj.LSym) {
		s.Type = objabi.SDATA
		s.Set(obj.AttrDuplicateOK, true)
		s.Set(obj.AttrStatic, true)
		c.ctxt.Data = append(c.ctxt.Data, s)
		s.WriteAddr(c.ctxt, 0, 8, source.Sym, 0)
	})

	if source.Type == obj.TYPE_ADDR {
		// MOVD $sym, Rx becomes MOVD symtoc, Rx
		// MOVD $sym+<off>, Rx becomes MOVD symtoc, Rx; ADD <off>, Rx
		p.From.Type = obj.TYPE_MEM
		p.From.Sym = symtoc
		p.From.Name = obj.NAME_TOCREF

		if p.From.Offset != 0 {
			q := obj.Appendp(p, c.newprog)
			q.As = AADD
			q.From.Type = obj.TYPE_CONST
			q.From.Offset = p.From.Offset
			p.From.Offset = 0
			q.To = p.To
		}
		return

	}

	// MOVx sym, Ry becomes MOVD symtoc, REGTMP; MOVx (REGTMP), Ry
	// MOVx Ry, sym becomes MOVD symtoc, REGTMP; MOVx Ry, (REGTMP)
	// An addition may be inserted between the two MOVs if there is an offset.

	q := obj.Appendp(p, c.newprog)
	q.As = AMOVD
	q.From.Type = obj.TYPE_MEM
	q.From.Sym = symtoc
	q.From.Name = obj.NAME_TOCREF
	q.To.Type = obj.TYPE_REG
	q.To.Reg = REGTMP

	q = obj.Appendp(q, c.newprog)
	q.As = p.As
	q.From = p.From
	q.To = p.To
	if p.From.Name != obj.NAME_NONE {
		q.From.Type = obj.TYPE_MEM
		q.From.Reg = REGTMP
		q.From.Name = obj.NAME_NONE
		q.From.Sym = nil
	} else if p.To.Name != obj.NAME_NONE {
		q.To.Type = obj.TYPE_MEM
		q.To.Reg = REGTMP
		q.To.Name = obj.NAME_NONE
		q.To.Sym = nil
	} else {
		c.ctxt.Diag("unreachable case in rewriteToUseTOC with %v", p)
	}

	obj.Nopout(p)
}

// Rewrite p, if necessary, to access global data via the global offset table.
func (c *ctxt9) rewriteToUseGot(p *obj.Prog) {
	if p.As == obj.ADUFFCOPY || p.As == obj.ADUFFZERO {
		//     ADUFFxxx $offset
		// becomes
		//     MOVD runtime.duffxxx@GOT, R12
		//     ADD $offset, R12
		//     MOVD R12, LR
		//     BL (LR)
		var sym *obj.LSym
		if p.As == obj.ADUFFZERO {
			sym = c.ctxt.LookupABI("runtime.duffzero", obj.ABIInternal)
		} else {
			sym = c.ctxt.LookupABI("runtime.duffcopy", obj.ABIInternal)
		}
		offset := p.To.Offset
		p.As = AMOVD
		p.From.Type = obj.TYPE_MEM
		p.From.Name = obj.NAME_GOTREF
		p.From.Sym = sym
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R12
		p.To.Name = obj.NAME_NONE
		p.To.Offset = 0
		p.To.Sym = nil
		p1 := obj.Appendp(p, c.newprog)
		p1.As = AADD
		p1.From.Type = obj.TYPE_CONST
		p1.From.Offset = offset
		p1.To.Type = obj.TYPE_REG
		p1.To.Reg = REG_R12
		p2 := obj.Appendp(p1, c.newprog)
		p2.As = AMOVD
		p2.From.Type = obj.TYPE_REG
		p2.From.Reg = REG_R12
		p2.To.Type = obj.TYPE_REG
		p2.To.Reg = REG_LR
		p3 := obj.Appendp(p2, c.newprog)
		p3.As = obj.ACALL
		p3.To.Type = obj.TYPE_REG
		p3.To.Reg = REG_LR
	}

	// We only care about global data: NAME_EXTERN means a global
	// symbol in the Go sense, and p.Sym.Local is true for a few
	// internally defined symbols.
	if p.From.Type == obj.TYPE_ADDR && p.From.Name == obj.NAME_EXTERN && !p.From.Sym.Local() {
		// MOVD $sym, Rx becomes MOVD sym@GOT, Rx
		// MOVD $sym+<off>, Rx becomes MOVD sym@GOT, Rx; ADD <off>, Rx
		if p.As != AMOVD {
			c.ctxt.Diag("do not know how to handle TYPE_ADDR in %v with -dynlink", p)
		}
		if p.To.Type != obj.TYPE_REG {
			c.ctxt.Diag("do not know how to handle LEAQ-type insn to non-register in %v with -dynlink", p)
		}
		p.From.Type = obj.TYPE_MEM
		p.From.Name = obj.NAME_GOTREF
		if p.From.Offset != 0 {
			q := obj.Appendp(p, c.newprog)
			q.As = AADD
			q.From.Type = obj.TYPE_CONST
			q.From.Offset = p.From.Offset
			q.To = p.To
			p.From.Offset = 0
		}
	}
	if p.GetFrom3() != nil && p.GetFrom3().Name == obj.NAME_EXTERN {
		c.ctxt.Diag("don't know how to handle %v with -dynlink", p)
	}
	var source *obj.Addr
	// MOVx sym, Ry becomes MOVD sym@GOT, REGTMP; MOVx (REGTMP), Ry
	// MOVx Ry, sym becomes MOVD sym@GOT, REGTMP; MOVx Ry, (REGTMP)
	// An addition may be inserted between the two MOVs if there is an offset.
	if p.From.Name == obj.NAME_EXTERN && !p.From.Sym.Local() {
		if p.To.Name == obj.NAME_EXTERN && !p.To.Sym.Local() {
			c.ctxt.Diag("cannot handle NAME_EXTERN on both sides in %v with -dynlink", p)
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
		c.ctxt.Diag("don't know how to handle %v with -dynlink", p)
	}
	p1 := obj.Appendp(p, c.newprog)
	p2 := obj.Appendp(p1, c.newprog)

	p1.As = AMOVD
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
	// TODO(minux): add morestack short-cuts with small fixed frame-size.
	if cursym.Func().Text == nil || cursym.Func().Text.Link == nil {
		return
	}

	c := ctxt9{ctxt: ctxt, cursym: cursym, newprog: newprog}

	p := c.cursym.Func().Text
	textstksiz := p.To.Offset
	if textstksiz == -8 {
		// Compatibility hack.
		p.From.Sym.Set(obj.AttrNoFrame, true)
		textstksiz = 0
	}
	if textstksiz%8 != 0 {
		c.ctxt.Diag("frame size %d not a multiple of 8", textstksiz)
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

	var q *obj.Prog
	var q1 *obj.Prog
	for p := c.cursym.Func().Text; p != nil; p = p.Link {
		switch p.As {
		/* too hard, just leave alone */
		case obj.ATEXT:
			q = p

			p.Mark |= LABEL | LEAF | SYNC
			if p.Link != nil {
				p.Link.Mark |= LABEL
			}

		case ANOR:
			q = p
			if p.To.Type == obj.TYPE_REG {
				if p.To.Reg == REGZERO {
					p.Mark |= LABEL | SYNC
				}
			}

		case ALWAR,
			ALBAR,
			ASTBCCC,
			ASTWCCC,
			AEIEIO,
			AICBI,
			AISYNC,
			ATLBIE,
			ATLBIEL,
			ASLBIA,
			ASLBIE,
			ASLBMFEE,
			ASLBMFEV,
			ASLBMTE,
			ADCBF,
			ADCBI,
			ADCBST,
			ADCBT,
			ADCBTST,
			ADCBZ,
			ASYNC,
			ATLBSYNC,
			APTESYNC,
			ALWSYNC,
			ATW,
			AWORD,
			ARFI,
			ARFCI,
			ARFID,
			AHRFID:
			q = p
			p.Mark |= LABEL | SYNC
			continue

		case AMOVW, AMOVWZ, AMOVD:
			q = p
			if p.From.Reg >= REG_SPECIAL || p.To.Reg >= REG_SPECIAL {
				p.Mark |= LABEL | SYNC
			}
			continue

		case AFABS,
			AFABSCC,
			AFADD,
			AFADDCC,
			AFCTIW,
			AFCTIWCC,
			AFCTIWZ,
			AFCTIWZCC,
			AFDIV,
			AFDIVCC,
			AFMADD,
			AFMADDCC,
			AFMOVD,
			AFMOVDU,
			/* case AFMOVDS: */
			AFMOVS,
			AFMOVSU,

			/* case AFMOVSD: */
			AFMSUB,
			AFMSUBCC,
			AFMUL,
			AFMULCC,
			AFNABS,
			AFNABSCC,
			AFNEG,
			AFNEGCC,
			AFNMADD,
			AFNMADDCC,
			AFNMSUB,
			AFNMSUBCC,
			AFRSP,
			AFRSPCC,
			AFSUB,
			AFSUBCC:
			q = p

			p.Mark |= FLOAT
			continue

		case ABL,
			ABCL,
			obj.ADUFFZERO,
			obj.ADUFFCOPY:
			c.cursym.Func().Text.Mark &^= LEAF
			fallthrough

		case ABC,
			ABEQ,
			ABGE,
			ABGT,
			ABLE,
			ABLT,
			ABNE,
			ABR,
			ABVC,
			ABVS:
			p.Mark |= BRANCH
			q = p
			q1 = p.To.Target()
			if q1 != nil {
				// NOPs are not removed due to #40689.

				if q1.Mark&LEAF == 0 {
					q1.Mark |= LABEL
				}
			} else {
				p.Mark |= LABEL
			}
			q1 = p.Link
			if q1 != nil {
				q1.Mark |= LABEL
			}
			continue

		case AFCMPO, AFCMPU:
			q = p
			p.Mark |= FCMP | FLOAT
			continue

		case obj.ARET:
			q = p
			if p.Link != nil {
				p.Link.Mark |= LABEL
			}
			continue

		case obj.ANOP:
			// NOPs are not removed due to
			// #40689
			continue

		default:
			q = p
			continue
		}
	}

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

			p.To.Offset = int64(autosize)

			q = p

			if NeedTOCpointer(c.ctxt) && !isNOTOCfunc(c.cursym.Name) {
				// When compiling Go into PIC, without PCrel support, all functions must start
				// with instructions to load the TOC pointer into r2:
				//
				//	addis r2, r12, .TOC.-func@ha
				//	addi r2, r2, .TOC.-func@l+4
				//
				// We could probably skip this prologue in some situations
				// but it's a bit subtle. However, it is both safe and
				// necessary to leave the prologue off duffzero and
				// duffcopy as we rely on being able to jump to a specific
				// instruction offset for them.
				//
				// These are AWORDS because there is no (afaict) way to
				// generate the addis instruction except as part of the
				// load of a large constant, and in that case there is no
				// way to use r12 as the source.
				//
				// Note that the same condition is tested in
				// putelfsym in cmd/link/internal/ld/symtab.go
				// where we set the st_other field to indicate
				// the presence of these instructions.
				q = obj.Appendp(q, c.newprog)
				q.As = AWORD
				q.Pos = p.Pos
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = 0x3c4c0000
				q = obj.Appendp(q, c.newprog)
				q.As = AWORD
				q.Pos = p.Pos
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = 0x38420000
				c.cursym.AddRel(c.ctxt, obj.Reloc{
					Type: objabi.R_ADDRPOWER_PCREL,
					Off:  0,
					Siz:  8,
					Sym:  c.ctxt.Lookup(".TOC."),
				})
			}

			if !c.cursym.Func().Text.From.Sym.NoSplit() {
				q = c.stacksplit(q, autosize) // emit split check
			}

			if autosize != 0 {
				var prologueEnd *obj.Prog
				// Save the link register and update the SP.  MOVDU is used unless
				// the frame size is too large.  The link register must be saved
				// even for non-empty leaf functions so that traceback works.
				if autosize >= -BIG && autosize <= BIG {
					// Use MOVDU to adjust R1 when saving R31, if autosize is small.
					q = obj.Appendp(q, c.newprog)
					q.As = AMOVD
					q.Pos = p.Pos
					q.From.Type = obj.TYPE_REG
					q.From.Reg = REG_LR
					q.To.Type = obj.TYPE_REG
					q.To.Reg = REGTMP
					prologueEnd = q

					q = obj.Appendp(q, c.newprog)
					q.As = AMOVDU
					q.Pos = p.Pos
					q.From.Type = obj.TYPE_REG
					q.From.Reg = REGTMP
					q.To.Type = obj.TYPE_MEM
					q.To.Offset = int64(-autosize)
					q.To.Reg = REGSP
					q.Spadj = autosize
				} else {
					// Frame size is too large for a MOVDU instruction.
					// Store link register before decrementing SP, so if a signal comes
					// during the execution of the function prologue, the traceback
					// code will not see a half-updated stack frame.
					// This sequence is not async preemptible, as if we open a frame
					// at the current SP, it will clobber the saved LR.
					q = obj.Appendp(q, c.newprog)
					q.As = AMOVD
					q.Pos = p.Pos
					q.From.Type = obj.TYPE_REG
					q.From.Reg = REG_LR
					q.To.Type = obj.TYPE_REG
					q.To.Reg = REG_R29 // REGTMP may be used to synthesize large offset in the next instruction

					q = c.ctxt.StartUnsafePoint(q, c.newprog)

					q = obj.Appendp(q, c.newprog)
					q.As = AMOVD
					q.Pos = p.Pos
					q.From.Type = obj.TYPE_REG
					q.From.Reg = REG_R29
					q.To.Type = obj.TYPE_MEM
					q.To.Offset = int64(-autosize)
					q.To.Reg = REGSP

					prologueEnd = q

					q = obj.Appendp(q, c.newprog)
					q.As = AADD
					q.Pos = p.Pos
					q.From.Type = obj.TYPE_CONST
					q.From.Offset = int64(-autosize)
					q.To.Type = obj.TYPE_REG
					q.To.Reg = REGSP
					q.Spadj = +autosize

					q = c.ctxt.EndUnsafePoint(q, c.newprog, -1)
				}
				prologueEnd.Pos = prologueEnd.Pos.WithXlogue(src.PosPrologueEnd)
			} else if c.cursym.Func().Text.Mark&LEAF == 0 {
				// A very few functions that do not return to their caller
				// (e.g. gogo) are not identified as leaves but still have
				// no frame.
				c.cursym.Func().Text.Mark |= LEAF
			}

			if c.cursym.Func().Text.Mark&LEAF != 0 {
				c.cursym.Set(obj.AttrLeaf, true)
				break
			}

			if NeedTOCpointer(c.ctxt) {
				q = obj.Appendp(q, c.newprog)
				q.As = AMOVD
				q.Pos = p.Pos
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R2
				q.To.Type = obj.TYPE_MEM
				q.To.Reg = REGSP
				q.To.Offset = 24
			}

			if c.cursym.Func().Text.From.Sym.Wrapper() {
				// if(g->panic != nil && g->panic->argp == FP) g->panic->argp = bottom-of-frame
				//
				//	MOVD g_panic(g), R22
				//	CMP R22, $0
				//	BEQ end
				//	MOVD panic_argp(R22), R23
				//	ADD $(autosize+8), R1, R24
				//	CMP R23, R24
				//	BNE end
				//	ADD $8, R1, R25
				//	MOVD R25, panic_argp(R22)
				// end:
				//	NOP
				//
				// The NOP is needed to give the jumps somewhere to land.
				// It is a liblink NOP, not a ppc64 NOP: it encodes to 0 instruction bytes.

				q = obj.Appendp(q, c.newprog)

				q.As = AMOVD
				q.From.Type = obj.TYPE_MEM
				q.From.Reg = REGG
				q.From.Offset = 4 * int64(c.ctxt.Arch.PtrSize) // G.panic
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R22

				q = obj.Appendp(q, c.newprog)
				q.As = ACMP
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R22
				q.To.Type = obj.TYPE_CONST
				q.To.Offset = 0

				q = obj.Appendp(q, c.newprog)
				q.As = ABEQ
				q.To.Type = obj.TYPE_BRANCH
				p1 = q

				q = obj.Appendp(q, c.newprog)
				q.As = AMOVD
				q.From.Type = obj.TYPE_MEM
				q.From.Reg = REG_R22
				q.From.Offset = 0 // Panic.argp
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R23

				q = obj.Appendp(q, c.newprog)
				q.As = AADD
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = int64(autosize) + c.ctxt.Arch.FixedFrameSize
				q.Reg = REGSP
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R24

				q = obj.Appendp(q, c.newprog)
				q.As = ACMP
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R23
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R24

				q = obj.Appendp(q, c.newprog)
				q.As = ABNE
				q.To.Type = obj.TYPE_BRANCH
				p2 = q

				q = obj.Appendp(q, c.newprog)
				q.As = AADD
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = c.ctxt.Arch.FixedFrameSize
				q.Reg = REGSP
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REG_R25

				q = obj.Appendp(q, c.newprog)
				q.As = AMOVD
				q.From.Type = obj.TYPE_REG
				q.From.Reg = REG_R25
				q.To.Type = obj.TYPE_MEM
				q.To.Reg = REG_R22
				q.To.Offset = 0 // Panic.argp

				q = obj.Appendp(q, c.newprog)

				q.As = obj.ANOP
				p1.To.SetTarget(q)
				p2.To.SetTarget(q)
			}

		case obj.ARET:
			if p.From.Type == obj.TYPE_CONST {
				c.ctxt.Diag("using BECOME (%v) is not supported!", p)
				break
			}

			retTarget := p.To.Sym

			if c.cursym.Func().Text.Mark&LEAF != 0 {
				if autosize == 0 {
					p.As = ABR
					p.From = obj.Addr{}
					if retTarget == nil {
						p.To.Type = obj.TYPE_REG
						p.To.Reg = REG_LR
					} else {
						p.To.Type = obj.TYPE_BRANCH
						p.To.Sym = retTarget
					}
					p.Mark |= BRANCH
					break
				}

				p.As = AADD
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = int64(autosize)
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REGSP
				p.Spadj = -autosize

				q = c.newprog()
				q.As = ABR
				q.Pos = p.Pos
				if retTarget == nil {
					q.To.Type = obj.TYPE_REG
					q.To.Reg = REG_LR
				} else {
					q.To.Type = obj.TYPE_BRANCH
					q.To.Sym = retTarget
				}
				q.Mark |= BRANCH
				q.Spadj = +autosize

				q.Link = p.Link
				p.Link = q
				break
			}

			p.As = AMOVD
			p.From.Type = obj.TYPE_MEM
			p.From.Offset = 0
			p.From.Reg = REGSP
			p.To.Type = obj.TYPE_REG
			p.To.Reg = REGTMP

			q = c.newprog()
			q.As = AMOVD
			q.Pos = p.Pos
			q.From.Type = obj.TYPE_REG
			q.From.Reg = REGTMP
			q.To.Type = obj.TYPE_REG
			q.To.Reg = REG_LR

			q.Link = p.Link
			p.Link = q
			p = q

			if false {
				// Debug bad returns
				q = c.newprog()

				q.As = AMOVD
				q.Pos = p.Pos
				q.From.Type = obj.TYPE_MEM
				q.From.Offset = 0
				q.From.Reg = REGTMP
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REGTMP

				q.Link = p.Link
				p.Link = q
				p = q
			}
			prev := p
			if autosize != 0 {
				q = c.newprog()
				q.As = AADD
				q.Pos = p.Pos
				q.From.Type = obj.TYPE_CONST
				q.From.Offset = int64(autosize)
				q.To.Type = obj.TYPE_REG
				q.To.Reg = REGSP
				q.Spadj = -autosize

				q.Link = p.Link
				prev.Link = q
				prev = q
			}

			q1 = c.newprog()
			q1.As = ABR
			q1.Pos = p.Pos
			if retTarget == nil {
				q1.To.Type = obj.TYPE_REG
				q1.To.Reg = REG_LR
			} else {
				q1.To.Type = obj.TYPE_BRANCH
				q1.To.Sym = retTarget
			}
			q1.Mark |= BRANCH
			q1.Spadj = +autosize

			q1.Link = q.Link
			prev.Link = q1
		case AADD:
			if p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP && p.From.Type == obj.TYPE_CONST {
				p.Spadj = int32(-p.From.Offset)
			}
		case AMOVDU:
			if p.To.Type == obj.TYPE_MEM && p.To.Reg == REGSP {
				p.Spadj = int32(-p.To.Offset)
			}
			if p.From.Type == obj.TYPE_MEM && p.From.Reg == REGSP {
				p.Spadj = int32(-p.From.Offset)
			}
		case obj.AGETCALLERPC:
			if cursym.Leaf() {
				/* MOVD LR, Rd */
				p.As = AMOVD
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REG_LR
			} else {
				/* MOVD (RSP), Rd */
				p.As = AMOVD
				p.From.Type = obj.TYPE_MEM
				p.From.Reg = REGSP
			}
		}

		if p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP && p.Spadj == 0 && p.As != ACMPU {
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

/*
// instruction scheduling

	if(debug['Q'] == 0)
		return;

	curtext = nil;
	q = nil;	// p - 1
	q1 = firstp;	// top of block
	o = 0;		// count of instructions
	for(p = firstp; p != nil; p = p1) {
		p1 = p->link;
		o++;
		if(p->mark & NOSCHED){
			if(q1 != p){
				sched(q1, q);
			}
			for(; p != nil; p = p->link){
				if(!(p->mark & NOSCHED))
					break;
				q = p;
			}
			p1 = p;
			q1 = p;
			o = 0;
			continue;
		}
		if(p->mark & (LABEL|SYNC)) {
			if(q1 != p)
				sched(q1, q);
			q1 = p;
			o = 1;
		}
		if(p->mark & (BRANCH|SYNC)) {
			sched(q1, p);
			q1 = p1;
			o = 0;
		}
		if(o >= NSCHED) {
			sched(q1, p);
			q1 = p1;
			o = 0;
		}
		q = p;
	}
*/
func (c *ctxt9) stacksplit(p *obj.Prog, framesize int32) *obj.Prog {
	if c.ctxt.Flag_maymorestack != "" {
		if c.ctxt.Flag_shared || c.ctxt.Flag_dynlink {
			// See the call to morestack for why these are
			// complicated to support.
			c.ctxt.Diag("maymorestack with -shared or -dynlink is not supported")
		}

		// Spill arguments. This has to happen before we open
		// any more frame space.
		p = c.cursym.Func().SpillRegisterArgs(p, c.newprog)

		// Save LR and REGCTXT
		frameSize := 8 + c.ctxt.Arch.FixedFrameSize

		// MOVD LR, REGTMP
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_LR
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGTMP
		// MOVDU REGTMP, -16(SP)
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVDU
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGTMP
		p.To.Type = obj.TYPE_MEM
		p.To.Offset = -frameSize
		p.To.Reg = REGSP
		p.Spadj = int32(frameSize)

		// MOVD REGCTXT, 8(SP)
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGCTXT
		p.To.Type = obj.TYPE_MEM
		p.To.Offset = 8
		p.To.Reg = REGSP

		// BL maymorestack
		p = obj.Appendp(p, c.newprog)
		p.As = ABL
		p.To.Type = obj.TYPE_BRANCH
		// See ../x86/obj6.go
		p.To.Sym = c.ctxt.LookupABI(c.ctxt.Flag_maymorestack, c.cursym.ABI())

		// Restore LR and REGCTXT

		// MOVD 8(SP), REGCTXT
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_MEM
		p.From.Offset = 8
		p.From.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGCTXT

		// MOVD 0(SP), REGTMP
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_MEM
		p.From.Offset = 0
		p.From.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGTMP

		// MOVD REGTMP, LR
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REGTMP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_LR

		// ADD $16, SP
		p = obj.Appendp(p, c.newprog)
		p.As = AADD
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = frameSize
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGSP
		p.Spadj = -int32(frameSize)

		// Unspill arguments.
		p = c.cursym.Func().UnspillRegisterArgs(p, c.newprog)
	}

	// save entry point, but skipping the two instructions setting R2 in shared mode and maymorestack
	startPred := p

	// MOVD	g_stackguard(g), R22
	p = obj.Appendp(p, c.newprog)

	p.As = AMOVD
	p.From.Type = obj.TYPE_MEM
	p.From.Reg = REGG
	p.From.Offset = 2 * int64(c.ctxt.Arch.PtrSize) // G.stackguard0
	if c.cursym.CFunc() {
		p.From.Offset = 3 * int64(c.ctxt.Arch.PtrSize) // G.stackguard1
	}
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REG_R22

	// Mark the stack bound check and morestack call async nonpreemptible.
	// If we get preempted here, when resumed the preemption request is
	// cleared, but we'll still call morestack, which will double the stack
	// unnecessarily. See issue #35470.
	p = c.ctxt.StartUnsafePoint(p, c.newprog)

	var q *obj.Prog
	if framesize <= abi.StackSmall {
		// small stack: SP < stackguard
		//	CMP	stackguard, SP
		p = obj.Appendp(p, c.newprog)

		p.As = ACMPU
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_R22
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REGSP
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
			//	CMPU	SP, $(framesize-StackSmall)
			//	BLT	label-of-call-to-morestack
			if offset <= 0xffff {
				p = obj.Appendp(p, c.newprog)
				p.As = ACMPU
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGSP
				p.To.Type = obj.TYPE_CONST
				p.To.Offset = offset
			} else {
				// Constant is too big for CMPU.
				p = obj.Appendp(p, c.newprog)
				p.As = AMOVD
				p.From.Type = obj.TYPE_CONST
				p.From.Offset = offset
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REG_R23

				p = obj.Appendp(p, c.newprog)
				p.As = ACMPU
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REGSP
				p.To.Type = obj.TYPE_REG
				p.To.Reg = REG_R23
			}

			p = obj.Appendp(p, c.newprog)
			q = p
			p.As = ABLT
			p.To.Type = obj.TYPE_BRANCH
		}

		// Check against the stack guard. We've ensured this won't underflow.
		//	ADD  $-(framesize-StackSmall), SP, R4
		//	CMPU stackguard, R4
		p = obj.Appendp(p, c.newprog)

		p.As = AADD
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = -offset
		p.Reg = REGSP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R23

		p = obj.Appendp(p, c.newprog)
		p.As = ACMPU
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_R22
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R23
	}

	// q1: BLT	done
	p = obj.Appendp(p, c.newprog)
	q1 := p

	p.As = ABLT
	p.To.Type = obj.TYPE_BRANCH

	p = obj.Appendp(p, c.newprog)
	p.As = obj.ANOP // zero-width place holder

	if q != nil {
		q.To.SetTarget(p)
	}

	// Spill the register args that could be clobbered by the
	// morestack code.

	spill := c.cursym.Func().SpillRegisterArgs(p, c.newprog)

	// MOVD LR, R5
	p = obj.Appendp(spill, c.newprog)
	p.As = AMOVD
	p.From.Type = obj.TYPE_REG
	p.From.Reg = REG_LR
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REG_R5

	p = c.ctxt.EmitEntryStackMap(c.cursym, p, c.newprog)

	var morestacksym *obj.LSym
	if c.cursym.CFunc() {
		morestacksym = c.ctxt.Lookup("runtime.morestackc")
	} else if !c.cursym.Func().Text.From.Sym.NeedCtxt() {
		morestacksym = c.ctxt.Lookup("runtime.morestack_noctxt")
	} else {
		morestacksym = c.ctxt.Lookup("runtime.morestack")
	}

	if NeedTOCpointer(c.ctxt) {
		// In PPC64 PIC code, R2 is used as TOC pointer derived from R12
		// which is the address of function entry point when entering
		// the function. We need to preserve R2 across call to morestack.
		// Fortunately, in shared mode, 8(SP) and 16(SP) are reserved in
		// the caller's frame, but not used (0(SP) is caller's saved LR,
		// 24(SP) is caller's saved R2). Use 8(SP) to save this function's R2.
		// MOVD R2, 8(SP)
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_R2
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = REGSP
		p.To.Offset = 8
	}

	if c.ctxt.Flag_dynlink {
		// Avoid calling morestack via a PLT when dynamically linking. The
		// PLT stubs generated by the system linker on ppc64le when "std r2,
		// 24(r1)" to save the TOC pointer in their callers stack
		// frame. Unfortunately (and necessarily) morestack is called before
		// the function that calls it sets up its frame and so the PLT ends
		// up smashing the saved TOC pointer for its caller's caller.
		//
		// According to the ABI documentation there is a mechanism to avoid
		// the TOC save that the PLT stub does (put a R_PPC64_TOCSAVE
		// relocation on the nop after the call to morestack) but at the time
		// of writing it is not supported at all by gold and my attempt to
		// use it with ld.bfd caused an internal linker error. So this hack
		// seems preferable.

		// MOVD $runtime.morestack(SB), R12
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_MEM
		p.From.Sym = morestacksym
		p.From.Name = obj.NAME_GOTREF
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R12

		// MOVD R12, LR
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_R12
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_LR

		// BL LR
		p = obj.Appendp(p, c.newprog)
		p.As = obj.ACALL
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_LR
	} else {
		// BL	runtime.morestack(SB)
		p = obj.Appendp(p, c.newprog)

		p.As = ABL
		p.To.Type = obj.TYPE_BRANCH
		p.To.Sym = morestacksym
	}

	if NeedTOCpointer(c.ctxt) {
		// MOVD 8(SP), R2
		p = obj.Appendp(p, c.newprog)
		p.As = AMOVD
		p.From.Type = obj.TYPE_MEM
		p.From.Reg = REGSP
		p.From.Offset = 8
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_R2
	}

	// The instructions which unspill regs should be preemptible.
	p = c.ctxt.EndUnsafePoint(p, c.newprog, -1)
	unspill := c.cursym.Func().UnspillRegisterArgs(p, c.newprog)

	// BR	start
	p = obj.Appendp(unspill, c.newprog)
	p.As = ABR
	p.To.Type = obj.TYPE_BRANCH
	p.To.SetTarget(startPred.Link)

	// placeholder for q1's jump target
	p = obj.Appendp(p, c.newprog)

	p.As = obj.ANOP // zero-width place holder
	q1.To.SetTarget(p)

	return p
}

// MMA accumulator to/from instructions are slightly ambiguous since
// the argument represents both source and destination, specified as
// an accumulator. It is treated as a unary destination to simplify
// the code generation in ppc64map.
var unaryDst = map[obj.As]bool{
	AXXSETACCZ: true,
	AXXMTACC:   true,
	AXXMFACC:   true,
}

var Linkppc64 = obj.LinkArch{
	Arch:           sys.ArchPPC64,
	Init:           buildop,
	Preprocess:     preprocess,
	Assemble:       span9,
	Progedit:       progedit,
	UnaryDst:       unaryDst,
	DWARFRegisters: PPC64DWARFRegisters,
}

var Linkppc64le = obj.LinkArch{
	Arch:           sys.ArchPPC64LE,
	Init:           buildop,
	Preprocess:     preprocess,
	Assemble:       span9,
	Progedit:       progedit,
	UnaryDst:       unaryDst,
	DWARFRegisters: PPC64DWARFRegisters,
}
```