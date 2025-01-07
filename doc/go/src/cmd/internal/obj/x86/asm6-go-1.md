Response: My thinking process to answer the request about `asm6.go`'s functionality goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of a specific Go file within the Go compiler toolchain. It also prompts for demonstrating the functionality with Go code examples and considering potential pitfalls. It explicitly states this is "part 2 of 3", implying a larger context of assembly generation.

2. **Initial Scan for Keywords and Patterns:** I quickly scanned the provided code for recurring keywords and function names that might indicate core functionalities. Some initial observations:

    * **`obj.Link`, `obj.LSym`, `obj.Prog`:** These suggest interactions with the Go object file format and the program representation within the assembler.
    * **`padJump`, `reAssemble`, `nopPad`:**  These strongly indicate handling of instruction sizes and potentially jump optimizations or padding.
    * **`requireAlignment`:**  Deals with ensuring proper memory alignment for instructions or data.
    * **`span6`:** This function seems central. The loop structure and calls to `asmins` suggest it's iterating through instructions and generating their byte representation.
    * **`instinit`:**  Likely handles the initialization of instruction tables or related data structures.
    * **`prefixof`:**  Suggests the handling of instruction prefixes.
    * **`oclass`, `oclassRegList`, `oclassVMem`:**  These appear to classify operands based on their types (registers, memory, etc.).
    * **`AsmBuf`, `Put1`, `PutInt32`, etc.:** This is a buffer for assembling the raw bytes of instructions.
    * **Instruction mnemonics (like `AADJSP`, `ACALL`, `AJMP`):** Indicate processing of specific assembly instructions.
    * **`ctxt.Diag`:**  Used for reporting errors and diagnostics.
    * **`Reloc`:** Indicates handling of relocations necessary for linking.

3. **Focus on `span6`:**  This function appears to be the core of the provided code. Its structure suggests a two-pass assembly process (or a loop that continues until convergence):

    * **First Pass (or initial part of the loop):**  It iterates through the program's instructions (`s.Func().Text`). It seems to:
        * Handle branch targets (`p.To.Target()`).
        * Special-case `AADJSP` for stack pointer adjustments.
        * Implement `retpoline` (Spectre mitigation) if enabled.
        * Initially assume short branches (`branchShort`).
    * **Looping/Re-assembly:** The `for {}` loop with the `reAssemble` flag suggests that the instruction sizes might change during assembly. If a jump needs a longer encoding than initially assumed, the code needs to re-layout.
    * **Instruction Encoding:**  The call to `ab.asmins(ctxt, s, p)` is the key part where the instruction is translated into bytes. `AsmBuf` then stores these bytes.
    * **Padding:**  The `pjc.padJump` function and the `nops` slice indicate the insertion of `NOP` instructions for alignment or optimization.
    * **Relocations:**  The handling of `s.R` (relocations) is important for external references and addresses that aren't fixed at assembly time.
    * **Jump Tables:**  The code also handles the generation of jump table entries.

4. **Infer High-Level Functionality:** Based on the keywords and the structure of `span6`, I can infer that this code is responsible for the *assembly* phase of the Go compilation process for the x86 architecture. This involves:

    * **Translating Go's intermediate representation (likely the `obj.Prog` structure) into actual machine code (bytes).**
    * **Handling instruction sizing and potentially optimizing branches (short vs. long jumps).**
    * **Inserting padding for alignment or performance.**
    * **Generating relocation information for the linker.**
    * **Implementing architecture-specific features like `retpoline`.**

5. **Address Specific Questions:**

    * **Functionality Listing:** I would list the key functionalities I identified in step 4, along with the more granular details like handling `AADJSP`, `retpoline`, and alignment.
    * **Go Code Example:**  I would create a simple Go function that, when compiled, would exercise some of the functionality in `asm6.go`. A function with a jump or a stack adjustment is a good candidate. I'd anticipate the compiled output would show the generated x86 assembly, including potential padding or `retpoline` calls.
    * **Code Inference (with Input/Output):** I'd focus on `padJump`. I'd provide an example of a jump instruction and the `pjc` value, then explain how `padJump` determines if padding is needed and how it calculates the amount. The output would be the updated `c` value after padding.
    * **Command-Line Arguments:**  I'd consider if any compiler flags directly influence the behavior of this code (like flags related to Spectre mitigation or architecture).
    * **User Mistakes:** I'd think about common assembly errors or misunderstandings related to instruction sizes or alignment. For example, assuming a jump will always be a short jump.

6. **Structure the Answer:** I would organize the answer logically, starting with the high-level summary, then providing specific details and examples. I would ensure to clearly label each part of the answer according to the prompt's requirements.

7. **Refine and Review:** I would reread the code and my answer to make sure it's accurate, complete, and easy to understand. I'd double-check that my Go code example is relevant and that my explanations of the code snippets are clear.

By following this process, I can systematically analyze the provided code and construct a comprehensive and accurate answer to the request. The key is to move from a general understanding to specific details, focusing on the core functionalities and how they relate to the larger compilation process.
这是 `go/src/cmd/internal/obj/x86/asm6.go` 文件的一部分，主要负责 **x86 架构下的汇编代码生成和布局优化**。更具体地说，它实现了将 Go 语言的中间表示 (intermediate representation, IR) 转换为实际的 x86 机器码的过程中的一些关键步骤。

以下是其功能的详细归纳：

**核心功能：**

1. **指令填充 (Padding Jumps):** `padJump` 函数负责在必要时向跳转指令前后添加 `NOP` 指令，以满足特定的代码对齐要求或优化需求。这对于提高指令缓存的效率或者满足某些微架构的约束可能很重要。

2. **指令重组 (Re-assembly):** `reAssemble` 函数判断是否需要重新汇编某个指令。当指令的大小在汇编过程中发生变化（例如，短跳转变为长跳转）时，就需要重新汇编以确保代码布局的正确性。

3. **函数对齐 (Require Alignment):** `requireAlignment` 函数确保函数的起始地址符合特定的对齐要求。这对于性能至关重要，尤其是在 x86 架构上，对齐的访问通常更快。

4. **跨度计算与指令编码 (Span Calculation and Instruction Encoding):** `span6` 函数是核心。它的主要职责是：
    * **处理分支目标:** 确保所有分支指令的目标都已正确设置。
    * **处理 `AADJSP` 指令:**  将 `AADJSP` 指令转换为实际的堆栈调整指令 (`ADDQ` 或 `SUBQ`)。
    * **处理 `retpoline` (Spectre 缓解):**  如果启用了 `retpoline` 机制，它会将直接调用或跳转指令替换为间接调用 `runtime.retpoline`，以缓解 Spectre 漏洞。
    * **初步估计指令长度:**  首次遍历指令链表时，假设使用短跳转。
    * **分配空间:** 为汇编后的机器码预先分配空间。
    * **循环汇编:**  进入一个循环，直到代码布局稳定。在循环中：
        * **计算指令偏移:** 计算每个指令在最终代码段中的偏移量 (`p.Pc`)。
        * **处理前向跳转:**  解决之前遇到的前向跳转指令，计算跳转偏移量并填充到指令中。如果发现短跳转不足以覆盖目标，则标记需要重新汇编。
        * **实际指令汇编:** 调用 `ab.asmins` 将 Go IR 指令转换为实际的 x86 机器码。
        * **检查指令大小变化:**  比较实际汇编后的指令大小与之前的估计，如果大小发生变化，并且该指令是跳转指令或宏融合跳转指令，则标记需要重新汇编。
        * **复制机器码:** 将汇编后的机器码复制到最终的代码段中。
        * **记录填充:** 如果在指令之间插入了填充 (`NOP`)，则记录下来。
    * **插入填充指令:**  在代码布局稳定后，将记录的填充指令实际插入到指令链表中。
    * **设置代码段大小:**  最终确定代码段的大小。
    * **生成跳转表条目:**  为函数中的跳转表生成相应的条目。
    * **标记不可抢占的代码序列:**  标记某些需要原子执行的代码序列（例如，TLS 访问）。

5. **指令初始化 (Instruction Initialization):** `instinit` 函数负责初始化 x86 架构相关的指令查找表 (`opindex`) 和其他辅助数据结构 (`ycover`)。

6. **前缀处理 (Prefix Handling):** `prefixof` 函数确定是否需要为给定的操作数添加段前缀（如 `CS:`, `DS:` 等）或 TLS 前缀 (`FS:`, `GS:`）。

7. **操作数分类 (Operand Classification):** `oclass`, `oclassRegList`, `oclassVMem` 等函数用于对指令的操作数进行分类，例如区分寄存器、内存地址、立即数等，并进一步区分不同类型的寄存器 (通用寄存器、浮点寄存器、向量寄存器等)。这些分类信息用于后续的指令编码。

8. **汇编缓冲区 (Assembly Buffer):** `AsmBuf` 结构体充当一个缓冲区，用于临时存储汇编后的机器码字节。它提供了一系列 `Put` 方法来添加不同大小的数据。

9. **指令编码辅助函数:**  `asmidx`, `relput4`, `vaddr`, `asmandsz`, `asmand`, `asmando` 等函数是汇编过程中用于编码不同类型操作数和指令的辅助函数。

10. **`mov` 指令特殊处理:** `ymovtab` 定义了 `mov` 指令的一些特殊情况，例如段寄存器之间的移动、控制寄存器和调试寄存器的访问等。

11. **媒体指令操作:** `mediaop` 函数处理类似 `Pm`, `Pe`, `Pf2`, `Pf3` 这样的媒体指令前缀。

12. **AVX/EVEX 指令编码:** `asmvex` 和 `asmevex` 函数负责编码 VEX 和 EVEX 编码的 AVX 指令。

**它是什么 Go 语言功能的实现？**

这部分代码是 Go 语言编译器 `cmd/compile/internal/gc` (或更准确地说是其底层的汇编器 `cmd/asm`) 将 Go 源代码编译成机器码的关键组成部分。具体来说，它负责 **将 Go 语言的函数转换为 x86 架构的汇编指令，并安排这些指令在内存中的布局**。

**Go 代码示例 (展示 `padJump` 的推断功能):**

假设我们有以下 Go 代码：

```go
package main

func main() {
	if true {
		goto target
	}
	// 一些代码
	println("not reached")
target:
	println("reached")
}
```

在编译过程中，`padJump` 可能会被调用来处理 `goto target` 这样的跳转指令。

**假设的输入和输出：**

* **输入:**
    * `ctxt`:  `obj.Link` 类型的链接上下文。
    * `s`:  `obj.LSym` 类型的当前函数符号。
    * `p`:  指向 `goto target` 指令的 `obj.Prog` 指针。假设该指令是短跳转，`p.Isize` 为 2 字节。
    * `c`: 当前代码的偏移量，例如 10。
    * `pjc`:  `padJumpsCtx`，假设为 32，表示一个 32 字节的对齐边界。

* **推理:**
    * `fusedJump(p)`: 假设 `goto` 不是宏融合跳转，返回 `false`, `0`。
    * `isJump(p)`:  `goto` 是跳转指令，返回 `true`。
    * `mask`: `pjc - 1` = 31。
    * `(c & mask) + int32(p.Isize)`: `(10 & 31) + 2` = 12。
    * `int32(pjc)`: 32。
    * 由于 `12 < 32`， 不需要填充。

* **输出:**
    * 返回 `c`，即 10。

**如果我们将 `pjc` 设置为一个较小的值，例如 8：**

* **推理:**
    * `mask`: `pjc - 1` = 7。
    * `(c & mask) + int32(p.Isize)`: `(10 & 7) + 2` = `2 + 2` = 4。
    * `int32(pjc)`: 8。
    * 由于 `4 < 8`, 不需要填充。

**如果 `goto target` 指令位于接近对齐边界的位置，例如 `c` 为 30，且 `pjc` 为 32：**

* **推理:**
    * `mask`: 31。
    * `(c & mask) + int32(p.Isize)`: `(30 & 31) + 2` = `30 + 2` = 32。
    * `int32(pjc)`: 32。
    * 由于 `32 >= 32`，`toPad` 将被计算为 `32 - (30 & 31)` = `32 - 30` = 2。
    * `noppad` 函数将被调用，插入 2 个字节的 `NOP` 指令。

* **输出:**
    * 返回 `noppad(ctxt, s, 30, 2)` 的结果，该结果将是填充后的新偏移量，可能是 32。

**命令行参数的具体处理:**

这部分代码本身不直接处理命令行参数。命令行参数的处理发生在更高级别的 Go 编译器代码中。但是，某些编译器标志会影响这部分代码的行为，例如：

* **`-spectre=ret`:** 启用 `retpoline` 机制，导致 `span6` 函数将调用和跳转指令替换为 `runtime.retpoline` 调用。
* **`-shared`:**  影响 TLS (线程本地存储) 前缀的处理方式 (`prefixof` 函数)。
* **目标架构 (例如 `GOARCH=386` 或 `GOARCH=amd64`)**: 决定了生成的指令和一些行为细节。

**使用者易犯错的点 (理论上，直接使用者是 Go 编译器本身):**

由于这部分代码是 Go 编译器内部的实现，普通 Go 开发者不会直接编写或修改它。然而，理解这些概念对于理解编译器的行为以及可能出现的性能问题是有帮助的。

* **假设跳转距离过短:**  编译器可能会首先假设使用短跳转，但在后续的布局中发现需要长跳转，导致重新汇编。这在某些性能敏感的代码中可能会有轻微的影响。
* **不理解代码对齐的重要性:** 代码对齐对于指令缓存的效率至关重要。不恰当的填充或对齐可能导致性能下降。
* **误解 `retpoline` 的影响:**  启用 `retpoline` 会带来一定的性能开销，理解其工作原理有助于权衡安全性和性能。

**归纳一下它的功能 (针对第2部分):**

这部分代码（第2部分）的核心功能是 **在 x86 架构下，对汇编指令进行布局优化和最终的机器码生成**。它包括：

* **确保代码满足特定的对齐要求，**通过插入 `NOP` 指令进行填充。
* **处理跳转指令，**包括短跳转和长跳转之间的转换。
* **实现 `retpoline` 等安全机制。**
* **生成实际的机器码字节流，**并处理相关的重定位信息。
* **对操作数进行分类，**以便正确编码指令。

它在 Go 编译器的汇编阶段扮演着至关重要的角色，确保最终生成的 x86 可执行代码的正确性和性能。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/x86/asm6.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共3部分，请归纳一下它的功能

"""
obj.Link, s *obj.LSym, p *obj.Prog, c int32) int32 {
	if pjc == 0 {
		return c
	}

	var toPad int32
	fj, fjSize := fusedJump(p)
	mask := int32(pjc - 1)
	if fj {
		if (c&mask)+int32(fjSize) >= int32(pjc) {
			toPad = int32(pjc) - (c & mask)
		}
	} else if isJump(p) {
		if (c&mask)+int32(p.Isize) >= int32(pjc) {
			toPad = int32(pjc) - (c & mask)
		}
	}
	if toPad <= 0 {
		return c
	}

	return noppad(ctxt, s, c, toPad)
}

// reAssemble is called if an instruction's size changes during assembly. If
// it does and the instruction is a standalone or a macro-fused jump we need to
// reassemble.
func (pjc padJumpsCtx) reAssemble(p *obj.Prog) bool {
	if pjc == 0 {
		return false
	}

	fj, _ := fusedJump(p)
	return fj || isJump(p)
}

type nopPad struct {
	p *obj.Prog // Instruction before the pad
	n int32     // Size of the pad
}

// requireAlignment ensures that the function alignment is at
// least as high as a, which should be a power of two
// and between 8 and 2048, inclusive.
//
// the boolean result indicates whether the alignment meets those constraints
func requireAlignment(a int64, ctxt *obj.Link, cursym *obj.LSym) bool {
	if !((a&(a-1) == 0) && 8 <= a && a <= 2048) {
		ctxt.Diag("alignment value of an instruction must be a power of two and in the range [8, 2048], got %d\n", a)
		return false
	}
	// By default function alignment is 32 bytes for amd64
	if cursym.Func().Align < int32(a) {
		cursym.Func().Align = int32(a)
	}
	return true
}

func span6(ctxt *obj.Link, s *obj.LSym, newprog obj.ProgAlloc) {
	if ctxt.Retpoline && ctxt.Arch.Family == sys.I386 {
		ctxt.Diag("-spectre=ret not supported on 386")
		ctxt.Retpoline = false // don't keep printing
	}

	pjc := makePjcCtx(ctxt)

	if s.P != nil {
		return
	}

	if ycover[0] == 0 {
		ctxt.Diag("x86 tables not initialized, call x86.instinit first")
	}

	for p := s.Func().Text; p != nil; p = p.Link {
		if p.To.Type == obj.TYPE_BRANCH && p.To.Target() == nil {
			p.To.SetTarget(p)
		}
		if p.As == AADJSP {
			p.To.Type = obj.TYPE_REG
			p.To.Reg = REG_SP
			// Generate 'ADDQ $x, SP' or 'SUBQ $x, SP', with x positive.
			// One exception: It is smaller to encode $-0x80 than $0x80.
			// For that case, flip the sign and the op:
			// Instead of 'ADDQ $0x80, SP', generate 'SUBQ $-0x80, SP'.
			switch v := p.From.Offset; {
			case v == 0:
				p.As = obj.ANOP
			case v == 0x80 || (v < 0 && v != -0x80):
				p.As = spadjop(ctxt, AADDL, AADDQ)
				p.From.Offset *= -1
			default:
				p.As = spadjop(ctxt, ASUBL, ASUBQ)
			}
		}
		if ctxt.Retpoline && (p.As == obj.ACALL || p.As == obj.AJMP) && (p.To.Type == obj.TYPE_REG || p.To.Type == obj.TYPE_MEM) {
			if p.To.Type != obj.TYPE_REG {
				ctxt.Diag("non-retpoline-compatible: %v", p)
				continue
			}
			p.To.Type = obj.TYPE_BRANCH
			p.To.Name = obj.NAME_EXTERN
			p.To.Sym = ctxt.Lookup("runtime.retpoline" + obj.Rconv(int(p.To.Reg)))
			p.To.Reg = 0
			p.To.Offset = 0
		}
	}

	var count int64 // rough count of number of instructions
	for p := s.Func().Text; p != nil; p = p.Link {
		count++
		p.Back = branchShort // use short branches first time through
		if q := p.To.Target(); q != nil && (q.Back&branchShort != 0) {
			p.Back |= branchBackwards
			q.Back |= branchLoopHead
		}
	}
	s.GrowCap(count * 5) // preallocate roughly 5 bytes per instruction

	var ab AsmBuf
	var n int
	var c int32
	errors := ctxt.Errors
	var nops []nopPad // Padding for a particular assembly (reuse slice storage if multiple assemblies)
	nrelocs0 := len(s.R)
	for {
		// This loop continues while there are reasons to re-assemble
		// whole block, like the presence of long forward jumps.
		reAssemble := false
		for i := range s.R[nrelocs0:] {
			s.R[nrelocs0+i] = obj.Reloc{}
		}
		s.R = s.R[:nrelocs0] // preserve marker relocations generated by the compiler
		s.P = s.P[:0]
		c = 0
		var pPrev *obj.Prog
		nops = nops[:0]
		for p := s.Func().Text; p != nil; p = p.Link {
			c0 := c
			c = pjc.padJump(ctxt, s, p, c)

			if p.As == obj.APCALIGN || p.As == obj.APCALIGNMAX {
				v := obj.AlignmentPadding(c, p, ctxt, s)
				if v > 0 {
					s.Grow(int64(c) + int64(v))
					fillnop(s.P[c:], int(v))
				}
				p.Pc = int64(c)
				c += int32(v)
				pPrev = p
				continue

			}

			if maxLoopPad > 0 && p.Back&branchLoopHead != 0 && c&(loopAlign-1) != 0 {
				// pad with NOPs
				v := -c & (loopAlign - 1)

				if v <= maxLoopPad {
					s.Grow(int64(c) + int64(v))
					fillnop(s.P[c:], int(v))
					c += v
				}
			}

			p.Pc = int64(c)

			// process forward jumps to p
			for q := p.Rel; q != nil; q = q.Forwd {
				v := int32(p.Pc - (q.Pc + int64(q.Isize)))
				if q.Back&branchShort != 0 {
					if v > 127 {
						reAssemble = true
						q.Back ^= branchShort
					}

					if q.As == AJCXZL || q.As == AXBEGIN {
						s.P[q.Pc+2] = byte(v)
					} else {
						s.P[q.Pc+1] = byte(v)
					}
				} else {
					binary.LittleEndian.PutUint32(s.P[q.Pc+int64(q.Isize)-4:], uint32(v))
				}
			}

			p.Rel = nil

			p.Pc = int64(c)
			ab.asmins(ctxt, s, p)
			m := ab.Len()
			if int(p.Isize) != m {
				p.Isize = uint8(m)
				if pjc.reAssemble(p) {
					// We need to re-assemble here to check for jumps and fused jumps
					// that span or end on 32 byte boundaries.
					reAssemble = true
				}
			}

			s.Grow(p.Pc + int64(m))
			copy(s.P[p.Pc:], ab.Bytes())
			// If there was padding, remember it.
			if pPrev != nil && !ctxt.IsAsm && c > c0 {
				nops = append(nops, nopPad{p: pPrev, n: c - c0})
			}
			c += int32(m)
			pPrev = p
		}

		n++
		if n > 1000 {
			ctxt.Diag("span must be looping")
			log.Fatalf("loop")
		}
		if !reAssemble {
			break
		}
		if ctxt.Errors > errors {
			return
		}
	}
	// splice padding nops into Progs
	for _, n := range nops {
		pp := n.p
		np := &obj.Prog{Link: pp.Link, Ctxt: pp.Ctxt, As: obj.ANOP, Pos: pp.Pos.WithNotStmt(), Pc: pp.Pc + int64(pp.Isize), Isize: uint8(n.n)}
		pp.Link = np
	}

	s.Size = int64(c)

	if false { /* debug['a'] > 1 */
		fmt.Printf("span1 %s %d (%d tries)\n %.6x", s.Name, s.Size, n, 0)
		var i int
		for i = 0; i < len(s.P); i++ {
			fmt.Printf(" %.2x", s.P[i])
			if i%16 == 15 {
				fmt.Printf("\n  %.6x", uint(i+1))
			}
		}

		if i%16 != 0 {
			fmt.Printf("\n")
		}

		for i := 0; i < len(s.R); i++ {
			r := &s.R[i]
			fmt.Printf(" rel %#.4x/%d %s%+d\n", uint32(r.Off), r.Siz, r.Sym.Name, r.Add)
		}
	}

	// Mark nonpreemptible instruction sequences.
	// The 2-instruction TLS access sequence
	//	MOVQ TLS, BX
	//	MOVQ 0(BX)(TLS*1), BX
	// is not async preemptible, as if it is preempted and resumed on
	// a different thread, the TLS address may become invalid.
	if !CanUse1InsnTLS(ctxt) {
		useTLS := func(p *obj.Prog) bool {
			// Only need to mark the second instruction, which has
			// REG_TLS as Index. (It is okay to interrupt and restart
			// the first instruction.)
			return p.From.Index == REG_TLS
		}
		obj.MarkUnsafePoints(ctxt, s.Func().Text, newprog, useTLS, nil)
	}

	// Now that we know byte offsets, we can generate jump table entries.
	// TODO: could this live in obj instead of obj/$ARCH?
	for _, jt := range s.Func().JumpTables {
		for i, p := range jt.Targets {
			// The ith jumptable entry points to the p.Pc'th
			// byte in the function symbol s.
			jt.Sym.WriteAddr(ctxt, int64(i)*8, 8, s, p.Pc)
		}
	}
}

func instinit(ctxt *obj.Link) {
	if ycover[0] != 0 {
		// Already initialized; stop now.
		// This happens in the cmd/asm tests,
		// each of which re-initializes the arch.
		return
	}

	switch ctxt.Headtype {
	case objabi.Hplan9:
		plan9privates = ctxt.Lookup("_privates")
	}

	for i := range avxOptab {
		c := avxOptab[i].as
		if opindex[c&obj.AMask] != nil {
			ctxt.Diag("phase error in avxOptab: %d (%v)", i, c)
		}
		opindex[c&obj.AMask] = &avxOptab[i]
	}
	for i := 1; optab[i].as != 0; i++ {
		c := optab[i].as
		if opindex[c&obj.AMask] != nil {
			ctxt.Diag("phase error in optab: %d (%v)", i, c)
		}
		opindex[c&obj.AMask] = &optab[i]
	}

	for i := 0; i < Ymax; i++ {
		ycover[i*Ymax+i] = 1
	}

	ycover[Yi0*Ymax+Yu2] = 1
	ycover[Yi1*Ymax+Yu2] = 1

	ycover[Yi0*Ymax+Yi8] = 1
	ycover[Yi1*Ymax+Yi8] = 1
	ycover[Yu2*Ymax+Yi8] = 1
	ycover[Yu7*Ymax+Yi8] = 1

	ycover[Yi0*Ymax+Yu7] = 1
	ycover[Yi1*Ymax+Yu7] = 1
	ycover[Yu2*Ymax+Yu7] = 1

	ycover[Yi0*Ymax+Yu8] = 1
	ycover[Yi1*Ymax+Yu8] = 1
	ycover[Yu2*Ymax+Yu8] = 1
	ycover[Yu7*Ymax+Yu8] = 1

	ycover[Yi0*Ymax+Ys32] = 1
	ycover[Yi1*Ymax+Ys32] = 1
	ycover[Yu2*Ymax+Ys32] = 1
	ycover[Yu7*Ymax+Ys32] = 1
	ycover[Yu8*Ymax+Ys32] = 1
	ycover[Yi8*Ymax+Ys32] = 1

	ycover[Yi0*Ymax+Yi32] = 1
	ycover[Yi1*Ymax+Yi32] = 1
	ycover[Yu2*Ymax+Yi32] = 1
	ycover[Yu7*Ymax+Yi32] = 1
	ycover[Yu8*Ymax+Yi32] = 1
	ycover[Yi8*Ymax+Yi32] = 1
	ycover[Ys32*Ymax+Yi32] = 1

	ycover[Yi0*Ymax+Yi64] = 1
	ycover[Yi1*Ymax+Yi64] = 1
	ycover[Yu7*Ymax+Yi64] = 1
	ycover[Yu2*Ymax+Yi64] = 1
	ycover[Yu8*Ymax+Yi64] = 1
	ycover[Yi8*Ymax+Yi64] = 1
	ycover[Ys32*Ymax+Yi64] = 1
	ycover[Yi32*Ymax+Yi64] = 1

	ycover[Yal*Ymax+Yrb] = 1
	ycover[Ycl*Ymax+Yrb] = 1
	ycover[Yax*Ymax+Yrb] = 1
	ycover[Ycx*Ymax+Yrb] = 1
	ycover[Yrx*Ymax+Yrb] = 1
	ycover[Yrl*Ymax+Yrb] = 1 // but not Yrl32

	ycover[Ycl*Ymax+Ycx] = 1

	ycover[Yax*Ymax+Yrx] = 1
	ycover[Ycx*Ymax+Yrx] = 1

	ycover[Yax*Ymax+Yrl] = 1
	ycover[Ycx*Ymax+Yrl] = 1
	ycover[Yrx*Ymax+Yrl] = 1
	ycover[Yrl32*Ymax+Yrl] = 1

	ycover[Yf0*Ymax+Yrf] = 1

	ycover[Yal*Ymax+Ymb] = 1
	ycover[Ycl*Ymax+Ymb] = 1
	ycover[Yax*Ymax+Ymb] = 1
	ycover[Ycx*Ymax+Ymb] = 1
	ycover[Yrx*Ymax+Ymb] = 1
	ycover[Yrb*Ymax+Ymb] = 1
	ycover[Yrl*Ymax+Ymb] = 1 // but not Yrl32
	ycover[Ym*Ymax+Ymb] = 1

	ycover[Yax*Ymax+Yml] = 1
	ycover[Ycx*Ymax+Yml] = 1
	ycover[Yrx*Ymax+Yml] = 1
	ycover[Yrl*Ymax+Yml] = 1
	ycover[Yrl32*Ymax+Yml] = 1
	ycover[Ym*Ymax+Yml] = 1

	ycover[Yax*Ymax+Ymm] = 1
	ycover[Ycx*Ymax+Ymm] = 1
	ycover[Yrx*Ymax+Ymm] = 1
	ycover[Yrl*Ymax+Ymm] = 1
	ycover[Yrl32*Ymax+Ymm] = 1
	ycover[Ym*Ymax+Ymm] = 1
	ycover[Ymr*Ymax+Ymm] = 1

	ycover[Yxr0*Ymax+Yxr] = 1

	ycover[Ym*Ymax+Yxm] = 1
	ycover[Yxr0*Ymax+Yxm] = 1
	ycover[Yxr*Ymax+Yxm] = 1

	ycover[Ym*Ymax+Yym] = 1
	ycover[Yyr*Ymax+Yym] = 1

	ycover[Yxr0*Ymax+YxrEvex] = 1
	ycover[Yxr*Ymax+YxrEvex] = 1

	ycover[Ym*Ymax+YxmEvex] = 1
	ycover[Yxr0*Ymax+YxmEvex] = 1
	ycover[Yxr*Ymax+YxmEvex] = 1
	ycover[YxrEvex*Ymax+YxmEvex] = 1

	ycover[Yyr*Ymax+YyrEvex] = 1

	ycover[Ym*Ymax+YymEvex] = 1
	ycover[Yyr*Ymax+YymEvex] = 1
	ycover[YyrEvex*Ymax+YymEvex] = 1

	ycover[Ym*Ymax+Yzm] = 1
	ycover[Yzr*Ymax+Yzm] = 1

	ycover[Yk0*Ymax+Yk] = 1
	ycover[Yknot0*Ymax+Yk] = 1

	ycover[Yk0*Ymax+Ykm] = 1
	ycover[Yknot0*Ymax+Ykm] = 1
	ycover[Yk*Ymax+Ykm] = 1
	ycover[Ym*Ymax+Ykm] = 1

	ycover[Yxvm*Ymax+YxvmEvex] = 1

	ycover[Yyvm*Ymax+YyvmEvex] = 1

	for i := 0; i < MAXREG; i++ {
		reg[i] = -1
		if i >= REG_AL && i <= REG_R15B {
			reg[i] = (i - REG_AL) & 7
			if i >= REG_SPB && i <= REG_DIB {
				regrex[i] = 0x40
			}
			if i >= REG_R8B && i <= REG_R15B {
				regrex[i] = Rxr | Rxx | Rxb
			}
		}

		if i >= REG_AH && i <= REG_BH {
			reg[i] = 4 + ((i - REG_AH) & 7)
		}
		if i >= REG_AX && i <= REG_R15 {
			reg[i] = (i - REG_AX) & 7
			if i >= REG_R8 {
				regrex[i] = Rxr | Rxx | Rxb
			}
		}

		if i >= REG_F0 && i <= REG_F0+7 {
			reg[i] = (i - REG_F0) & 7
		}
		if i >= REG_M0 && i <= REG_M0+7 {
			reg[i] = (i - REG_M0) & 7
		}
		if i >= REG_K0 && i <= REG_K0+7 {
			reg[i] = (i - REG_K0) & 7
		}
		if i >= REG_X0 && i <= REG_X0+15 {
			reg[i] = (i - REG_X0) & 7
			if i >= REG_X0+8 {
				regrex[i] = Rxr | Rxx | Rxb
			}
		}
		if i >= REG_X16 && i <= REG_X16+15 {
			reg[i] = (i - REG_X16) & 7
			if i >= REG_X16+8 {
				regrex[i] = Rxr | Rxx | Rxb | RxrEvex
			} else {
				regrex[i] = RxrEvex
			}
		}
		if i >= REG_Y0 && i <= REG_Y0+15 {
			reg[i] = (i - REG_Y0) & 7
			if i >= REG_Y0+8 {
				regrex[i] = Rxr | Rxx | Rxb
			}
		}
		if i >= REG_Y16 && i <= REG_Y16+15 {
			reg[i] = (i - REG_Y16) & 7
			if i >= REG_Y16+8 {
				regrex[i] = Rxr | Rxx | Rxb | RxrEvex
			} else {
				regrex[i] = RxrEvex
			}
		}
		if i >= REG_Z0 && i <= REG_Z0+15 {
			reg[i] = (i - REG_Z0) & 7
			if i > REG_Z0+7 {
				regrex[i] = Rxr | Rxx | Rxb
			}
		}
		if i >= REG_Z16 && i <= REG_Z16+15 {
			reg[i] = (i - REG_Z16) & 7
			if i >= REG_Z16+8 {
				regrex[i] = Rxr | Rxx | Rxb | RxrEvex
			} else {
				regrex[i] = RxrEvex
			}
		}

		if i >= REG_CR+8 && i <= REG_CR+15 {
			regrex[i] = Rxr
		}
	}
}

var isAndroid = buildcfg.GOOS == "android"

func prefixof(ctxt *obj.Link, a *obj.Addr) int {
	if a.Reg < REG_CS && a.Index < REG_CS { // fast path
		return 0
	}
	if a.Type == obj.TYPE_MEM && a.Name == obj.NAME_NONE {
		switch a.Reg {
		case REG_CS:
			return 0x2e

		case REG_DS:
			return 0x3e

		case REG_ES:
			return 0x26

		case REG_FS:
			return 0x64

		case REG_GS:
			return 0x65

		case REG_TLS:
			// NOTE: Systems listed here should be only systems that
			// support direct TLS references like 8(TLS) implemented as
			// direct references from FS or GS. Systems that require
			// the initial-exec model, where you load the TLS base into
			// a register and then index from that register, do not reach
			// this code and should not be listed.
			if ctxt.Arch.Family == sys.I386 {
				switch ctxt.Headtype {
				default:
					if isAndroid {
						return 0x65 // GS
					}
					log.Fatalf("unknown TLS base register for %v", ctxt.Headtype)

				case objabi.Hdarwin,
					objabi.Hdragonfly,
					objabi.Hfreebsd,
					objabi.Hnetbsd,
					objabi.Hopenbsd:
					return 0x65 // GS
				}
			}

			switch ctxt.Headtype {
			default:
				log.Fatalf("unknown TLS base register for %v", ctxt.Headtype)

			case objabi.Hlinux:
				if isAndroid {
					return 0x64 // FS
				}

				if ctxt.Flag_shared {
					log.Fatalf("unknown TLS base register for linux with -shared")
				} else {
					return 0x64 // FS
				}

			case objabi.Hdragonfly,
				objabi.Hfreebsd,
				objabi.Hnetbsd,
				objabi.Hopenbsd,
				objabi.Hsolaris:
				return 0x64 // FS

			case objabi.Hdarwin:
				return 0x65 // GS
			}
		}
	}

	switch a.Index {
	case REG_CS:
		return 0x2e

	case REG_DS:
		return 0x3e

	case REG_ES:
		return 0x26

	case REG_TLS:
		if ctxt.Flag_shared && ctxt.Headtype != objabi.Hwindows {
			// When building for inclusion into a shared library, an instruction of the form
			//     MOV off(CX)(TLS*1), AX
			// becomes
			//     mov %gs:off(%ecx), %eax // on i386
			//     mov %fs:off(%rcx), %rax // on amd64
			// which assumes that the correct TLS offset has been loaded into CX (today
			// there is only one TLS variable -- g -- so this is OK). When not building for
			// a shared library the instruction it becomes
			//     mov 0x0(%ecx), %eax // on i386
			//     mov 0x0(%rcx), %rax // on amd64
			// and a R_TLS_LE relocation, and so does not require a prefix.
			if ctxt.Arch.Family == sys.I386 {
				return 0x65 // GS
			}
			return 0x64 // FS
		}

	case REG_FS:
		return 0x64

	case REG_GS:
		return 0x65
	}

	return 0
}

// oclassRegList returns multisource operand class for addr.
func oclassRegList(ctxt *obj.Link, addr *obj.Addr) int {
	// TODO(quasilyte): when oclass register case is refactored into
	// lookup table, use it here to get register kind more easily.
	// Helper functions like regIsXmm should go away too (they will become redundant).

	regIsXmm := func(r int) bool { return r >= REG_X0 && r <= REG_X31 }
	regIsYmm := func(r int) bool { return r >= REG_Y0 && r <= REG_Y31 }
	regIsZmm := func(r int) bool { return r >= REG_Z0 && r <= REG_Z31 }

	reg0, reg1 := decodeRegisterRange(addr.Offset)
	low := regIndex(int16(reg0))
	high := regIndex(int16(reg1))

	if ctxt.Arch.Family == sys.I386 {
		if low >= 8 || high >= 8 {
			return Yxxx
		}
	}

	switch high - low {
	case 3:
		switch {
		case regIsXmm(reg0) && regIsXmm(reg1):
			return YxrEvexMulti4
		case regIsYmm(reg0) && regIsYmm(reg1):
			return YyrEvexMulti4
		case regIsZmm(reg0) && regIsZmm(reg1):
			return YzrMulti4
		default:
			return Yxxx
		}
	default:
		return Yxxx
	}
}

// oclassVMem returns V-mem (vector memory with VSIB) operand class.
// For addr that is not V-mem returns (Yxxx, false).
func oclassVMem(ctxt *obj.Link, addr *obj.Addr) (int, bool) {
	switch addr.Index {
	case REG_X0 + 0,
		REG_X0 + 1,
		REG_X0 + 2,
		REG_X0 + 3,
		REG_X0 + 4,
		REG_X0 + 5,
		REG_X0 + 6,
		REG_X0 + 7:
		return Yxvm, true
	case REG_X8 + 0,
		REG_X8 + 1,
		REG_X8 + 2,
		REG_X8 + 3,
		REG_X8 + 4,
		REG_X8 + 5,
		REG_X8 + 6,
		REG_X8 + 7:
		if ctxt.Arch.Family == sys.I386 {
			return Yxxx, true
		}
		return Yxvm, true
	case REG_X16 + 0,
		REG_X16 + 1,
		REG_X16 + 2,
		REG_X16 + 3,
		REG_X16 + 4,
		REG_X16 + 5,
		REG_X16 + 6,
		REG_X16 + 7,
		REG_X16 + 8,
		REG_X16 + 9,
		REG_X16 + 10,
		REG_X16 + 11,
		REG_X16 + 12,
		REG_X16 + 13,
		REG_X16 + 14,
		REG_X16 + 15:
		if ctxt.Arch.Family == sys.I386 {
			return Yxxx, true
		}
		return YxvmEvex, true

	case REG_Y0 + 0,
		REG_Y0 + 1,
		REG_Y0 + 2,
		REG_Y0 + 3,
		REG_Y0 + 4,
		REG_Y0 + 5,
		REG_Y0 + 6,
		REG_Y0 + 7:
		return Yyvm, true
	case REG_Y8 + 0,
		REG_Y8 + 1,
		REG_Y8 + 2,
		REG_Y8 + 3,
		REG_Y8 + 4,
		REG_Y8 + 5,
		REG_Y8 + 6,
		REG_Y8 + 7:
		if ctxt.Arch.Family == sys.I386 {
			return Yxxx, true
		}
		return Yyvm, true
	case REG_Y16 + 0,
		REG_Y16 + 1,
		REG_Y16 + 2,
		REG_Y16 + 3,
		REG_Y16 + 4,
		REG_Y16 + 5,
		REG_Y16 + 6,
		REG_Y16 + 7,
		REG_Y16 + 8,
		REG_Y16 + 9,
		REG_Y16 + 10,
		REG_Y16 + 11,
		REG_Y16 + 12,
		REG_Y16 + 13,
		REG_Y16 + 14,
		REG_Y16 + 15:
		if ctxt.Arch.Family == sys.I386 {
			return Yxxx, true
		}
		return YyvmEvex, true

	case REG_Z0 + 0,
		REG_Z0 + 1,
		REG_Z0 + 2,
		REG_Z0 + 3,
		REG_Z0 + 4,
		REG_Z0 + 5,
		REG_Z0 + 6,
		REG_Z0 + 7:
		return Yzvm, true
	case REG_Z8 + 0,
		REG_Z8 + 1,
		REG_Z8 + 2,
		REG_Z8 + 3,
		REG_Z8 + 4,
		REG_Z8 + 5,
		REG_Z8 + 6,
		REG_Z8 + 7,
		REG_Z8 + 8,
		REG_Z8 + 9,
		REG_Z8 + 10,
		REG_Z8 + 11,
		REG_Z8 + 12,
		REG_Z8 + 13,
		REG_Z8 + 14,
		REG_Z8 + 15,
		REG_Z8 + 16,
		REG_Z8 + 17,
		REG_Z8 + 18,
		REG_Z8 + 19,
		REG_Z8 + 20,
		REG_Z8 + 21,
		REG_Z8 + 22,
		REG_Z8 + 23:
		if ctxt.Arch.Family == sys.I386 {
			return Yxxx, true
		}
		return Yzvm, true
	}

	return Yxxx, false
}

func oclass(ctxt *obj.Link, p *obj.Prog, a *obj.Addr) int {
	switch a.Type {
	case obj.TYPE_REGLIST:
		return oclassRegList(ctxt, a)

	case obj.TYPE_NONE:
		return Ynone

	case obj.TYPE_BRANCH:
		return Ybr

	case obj.TYPE_INDIR:
		if a.Name != obj.NAME_NONE && a.Reg == REG_NONE && a.Index == REG_NONE && a.Scale == 0 {
			return Yindir
		}
		return Yxxx

	case obj.TYPE_MEM:
		// Pseudo registers have negative index, but SP is
		// not pseudo on x86, hence REG_SP check is not redundant.
		if a.Index == REG_SP || a.Index < 0 {
			// Can't use FP/SB/PC/SP as the index register.
			return Yxxx
		}

		if vmem, ok := oclassVMem(ctxt, a); ok {
			return vmem
		}

		if ctxt.Arch.Family == sys.AMD64 {
			switch a.Name {
			case obj.NAME_EXTERN, obj.NAME_STATIC, obj.NAME_GOTREF:
				// Global variables can't use index registers and their
				// base register is %rip (%rip is encoded as REG_NONE).
				if a.Reg != REG_NONE || a.Index != REG_NONE || a.Scale != 0 {
					return Yxxx
				}
			case obj.NAME_AUTO, obj.NAME_PARAM:
				// These names must have a base of SP.  The old compiler
				// uses 0 for the base register. SSA uses REG_SP.
				if a.Reg != REG_SP && a.Reg != 0 {
					return Yxxx
				}
			case obj.NAME_NONE:
				// everything is ok
			default:
				// unknown name
				return Yxxx
			}
		}
		return Ym

	case obj.TYPE_ADDR:
		switch a.Name {
		case obj.NAME_GOTREF:
			ctxt.Diag("unexpected TYPE_ADDR with NAME_GOTREF")
			return Yxxx

		case obj.NAME_EXTERN,
			obj.NAME_STATIC:
			if a.Sym != nil && useAbs(ctxt, a.Sym) {
				return Yi32
			}
			return Yiauto // use pc-relative addressing

		case obj.NAME_AUTO,
			obj.NAME_PARAM:
			return Yiauto
		}

		// TODO(rsc): DUFFZERO/DUFFCOPY encoding forgot to set a->index
		// and got Yi32 in an earlier version of this code.
		// Keep doing that until we fix yduff etc.
		if a.Sym != nil && strings.HasPrefix(a.Sym.Name, "runtime.duff") {
			return Yi32
		}

		if a.Sym != nil || a.Name != obj.NAME_NONE {
			ctxt.Diag("unexpected addr: %v", obj.Dconv(p, a))
		}
		fallthrough

	case obj.TYPE_CONST:
		if a.Sym != nil {
			ctxt.Diag("TYPE_CONST with symbol: %v", obj.Dconv(p, a))
		}

		v := a.Offset
		if ctxt.Arch.Family == sys.I386 {
			v = int64(int32(v))
		}
		switch {
		case v == 0:
			return Yi0
		case v == 1:
			return Yi1
		case v >= 0 && v <= 3:
			return Yu2
		case v >= 0 && v <= 127:
			return Yu7
		case v >= 0 && v <= 255:
			return Yu8
		case v >= -128 && v <= 127:
			return Yi8
		}
		if ctxt.Arch.Family == sys.I386 {
			return Yi32
		}
		l := int32(v)
		if int64(l) == v {
			return Ys32 // can sign extend
		}
		if v>>32 == 0 {
			return Yi32 // unsigned
		}
		return Yi64

	case obj.TYPE_TEXTSIZE:
		return Ytextsize
	}

	if a.Type != obj.TYPE_REG {
		ctxt.Diag("unexpected addr1: type=%d %v", a.Type, obj.Dconv(p, a))
		return Yxxx
	}

	switch a.Reg {
	case REG_AL:
		return Yal

	case REG_AX:
		return Yax

		/*
			case REG_SPB:
		*/
	case REG_BPB,
		REG_SIB,
		REG_DIB,
		REG_R8B,
		REG_R9B,
		REG_R10B,
		REG_R11B,
		REG_R12B,
		REG_R13B,
		REG_R14B,
		REG_R15B:
		if ctxt.Arch.Family == sys.I386 {
			return Yxxx
		}
		fallthrough

	case REG_DL,
		REG_BL,
		REG_AH,
		REG_CH,
		REG_DH,
		REG_BH:
		return Yrb

	case REG_CL:
		return Ycl

	case REG_CX:
		return Ycx

	case REG_DX, REG_BX:
		return Yrx

	case REG_R8, // not really Yrl
		REG_R9,
		REG_R10,
		REG_R11,
		REG_R12,
		REG_R13,
		REG_R14,
		REG_R15:
		if ctxt.Arch.Family == sys.I386 {
			return Yxxx
		}
		fallthrough

	case REG_SP, REG_BP, REG_SI, REG_DI:
		if ctxt.Arch.Family == sys.I386 {
			return Yrl32
		}
		return Yrl

	case REG_F0 + 0:
		return Yf0

	case REG_F0 + 1,
		REG_F0 + 2,
		REG_F0 + 3,
		REG_F0 + 4,
		REG_F0 + 5,
		REG_F0 + 6,
		REG_F0 + 7:
		return Yrf

	case REG_M0 + 0,
		REG_M0 + 1,
		REG_M0 + 2,
		REG_M0 + 3,
		REG_M0 + 4,
		REG_M0 + 5,
		REG_M0 + 6,
		REG_M0 + 7:
		return Ymr

	case REG_X0:
		return Yxr0

	case REG_X0 + 1,
		REG_X0 + 2,
		REG_X0 + 3,
		REG_X0 + 4,
		REG_X0 + 5,
		REG_X0 + 6,
		REG_X0 + 7,
		REG_X0 + 8,
		REG_X0 + 9,
		REG_X0 + 10,
		REG_X0 + 11,
		REG_X0 + 12,
		REG_X0 + 13,
		REG_X0 + 14,
		REG_X0 + 15:
		return Yxr

	case REG_X0 + 16,
		REG_X0 + 17,
		REG_X0 + 18,
		REG_X0 + 19,
		REG_X0 + 20,
		REG_X0 + 21,
		REG_X0 + 22,
		REG_X0 + 23,
		REG_X0 + 24,
		REG_X0 + 25,
		REG_X0 + 26,
		REG_X0 + 27,
		REG_X0 + 28,
		REG_X0 + 29,
		REG_X0 + 30,
		REG_X0 + 31:
		return YxrEvex

	case REG_Y0 + 0,
		REG_Y0 + 1,
		REG_Y0 + 2,
		REG_Y0 + 3,
		REG_Y0 + 4,
		REG_Y0 + 5,
		REG_Y0 + 6,
		REG_Y0 + 7,
		REG_Y0 + 8,
		REG_Y0 + 9,
		REG_Y0 + 10,
		REG_Y0 + 11,
		REG_Y0 + 12,
		REG_Y0 + 13,
		REG_Y0 + 14,
		REG_Y0 + 15:
		return Yyr

	case REG_Y0 + 16,
		REG_Y0 + 17,
		REG_Y0 + 18,
		REG_Y0 + 19,
		REG_Y0 + 20,
		REG_Y0 + 21,
		REG_Y0 + 22,
		REG_Y0 + 23,
		REG_Y0 + 24,
		REG_Y0 + 25,
		REG_Y0 + 26,
		REG_Y0 + 27,
		REG_Y0 + 28,
		REG_Y0 + 29,
		REG_Y0 + 30,
		REG_Y0 + 31:
		return YyrEvex

	case REG_Z0 + 0,
		REG_Z0 + 1,
		REG_Z0 + 2,
		REG_Z0 + 3,
		REG_Z0 + 4,
		REG_Z0 + 5,
		REG_Z0 + 6,
		REG_Z0 + 7:
		return Yzr

	case REG_Z0 + 8,
		REG_Z0 + 9,
		REG_Z0 + 10,
		REG_Z0 + 11,
		REG_Z0 + 12,
		REG_Z0 + 13,
		REG_Z0 + 14,
		REG_Z0 + 15,
		REG_Z0 + 16,
		REG_Z0 + 17,
		REG_Z0 + 18,
		REG_Z0 + 19,
		REG_Z0 + 20,
		REG_Z0 + 21,
		REG_Z0 + 22,
		REG_Z0 + 23,
		REG_Z0 + 24,
		REG_Z0 + 25,
		REG_Z0 + 26,
		REG_Z0 + 27,
		REG_Z0 + 28,
		REG_Z0 + 29,
		REG_Z0 + 30,
		REG_Z0 + 31:
		if ctxt.Arch.Family == sys.I386 {
			return Yxxx
		}
		return Yzr

	case REG_K0:
		return Yk0

	case REG_K0 + 1,
		REG_K0 + 2,
		REG_K0 + 3,
		REG_K0 + 4,
		REG_K0 + 5,
		REG_K0 + 6,
		REG_K0 + 7:
		return Yknot0

	case REG_CS:
		return Ycs
	case REG_SS:
		return Yss
	case REG_DS:
		return Yds
	case REG_ES:
		return Yes
	case REG_FS:
		return Yfs
	case REG_GS:
		return Ygs
	case REG_TLS:
		return Ytls

	case REG_GDTR:
		return Ygdtr
	case REG_IDTR:
		return Yidtr
	case REG_LDTR:
		return Yldtr
	case REG_MSW:
		return Ymsw
	case REG_TASK:
		return Ytask

	case REG_CR + 0:
		return Ycr0
	case REG_CR + 1:
		return Ycr1
	case REG_CR + 2:
		return Ycr2
	case REG_CR + 3:
		return Ycr3
	case REG_CR + 4:
		return Ycr4
	case REG_CR + 5:
		return Ycr5
	case REG_CR + 6:
		return Ycr6
	case REG_CR + 7:
		return Ycr7
	case REG_CR + 8:
		return Ycr8

	case REG_DR + 0:
		return Ydr0
	case REG_DR + 1:
		return Ydr1
	case REG_DR + 2:
		return Ydr2
	case REG_DR + 3:
		return Ydr3
	case REG_DR + 4:
		return Ydr4
	case REG_DR + 5:
		return Ydr5
	case REG_DR + 6:
		return Ydr6
	case REG_DR + 7:
		return Ydr7

	case REG_TR + 0:
		return Ytr0
	case REG_TR + 1:
		return Ytr1
	case REG_TR + 2:
		return Ytr2
	case REG_TR + 3:
		return Ytr3
	case REG_TR + 4:
		return Ytr4
	case REG_TR + 5:
		return Ytr5
	case REG_TR + 6:
		return Ytr6
	case REG_TR + 7:
		return Ytr7
	}

	return Yxxx
}

// AsmBuf is a simple buffer to assemble variable-length x86 instructions into
// and hold assembly state.
type AsmBuf struct {
	buf      [100]byte
	off      int
	rexflag  int
	vexflag  bool // Per inst: true for VEX-encoded
	evexflag bool // Per inst: true for EVEX-encoded
	rep      bool
	repn     bool
	lock     bool

	evex evexBits // Initialized when evexflag is true
}

// Put1 appends one byte to the end of the buffer.
func (ab *AsmBuf) Put1(x byte) {
	ab.buf[ab.off] = x
	ab.off++
}

// Put2 appends two bytes to the end of the buffer.
func (ab *AsmBuf) Put2(x, y byte) {
	ab.buf[ab.off+0] = x
	ab.buf[ab.off+1] = y
	ab.off += 2
}

// Put3 appends three bytes to the end of the buffer.
func (ab *AsmBuf) Put3(x, y, z byte) {
	ab.buf[ab.off+0] = x
	ab.buf[ab.off+1] = y
	ab.buf[ab.off+2] = z
	ab.off += 3
}

// Put4 appends four bytes to the end of the buffer.
func (ab *AsmBuf) Put4(x, y, z, w byte) {
	ab.buf[ab.off+0] = x
	ab.buf[ab.off+1] = y
	ab.buf[ab.off+2] = z
	ab.buf[ab.off+3] = w
	ab.off += 4
}

// PutInt16 writes v into the buffer using little-endian encoding.
func (ab *AsmBuf) PutInt16(v int16) {
	ab.buf[ab.off+0] = byte(v)
	ab.buf[ab.off+1] = byte(v >> 8)
	ab.off += 2
}

// PutInt32 writes v into the buffer using little-endian encoding.
func (ab *AsmBuf) PutInt32(v int32) {
	ab.buf[ab.off+0] = byte(v)
	ab.buf[ab.off+1] = byte(v >> 8)
	ab.buf[ab.off+2] = byte(v >> 16)
	ab.buf[ab.off+3] = byte(v >> 24)
	ab.off += 4
}

// PutInt64 writes v into the buffer using little-endian encoding.
func (ab *AsmBuf) PutInt64(v int64) {
	ab.buf[ab.off+0] = byte(v)
	ab.buf[ab.off+1] = byte(v >> 8)
	ab.buf[ab.off+2] = byte(v >> 16)
	ab.buf[ab.off+3] = byte(v >> 24)
	ab.buf[ab.off+4] = byte(v >> 32)
	ab.buf[ab.off+5] = byte(v >> 40)
	ab.buf[ab.off+6] = byte(v >> 48)
	ab.buf[ab.off+7] = byte(v >> 56)
	ab.off += 8
}

// Put copies b into the buffer.
func (ab *AsmBuf) Put(b []byte) {
	copy(ab.buf[ab.off:], b)
	ab.off += len(b)
}

// PutOpBytesLit writes zero terminated sequence of bytes from op,
// starting at specified offset (e.g. z counter value).
// Trailing 0 is not written.
//
// Intended to be used for literal Z cases.
// Literal Z cases usually have "Zlit" in their name (Zlit, Zlitr_m, Zlitm_r).
func (ab *AsmBuf) PutOpBytesLit(offset int, op *opBytes) {
	for int(op[offset]) != 0 {
		ab.Put1(byte(op[offset]))
		offset++
	}
}

// Insert inserts b at offset i.
func (ab *AsmBuf) Insert(i int, b byte) {
	ab.off++
	copy(ab.buf[i+1:ab.off], ab.buf[i:ab.off-1])
	ab.buf[i] = b
}

// Last returns the byte at the end of the buffer.
func (ab *AsmBuf) Last() byte { return ab.buf[ab.off-1] }

// Len returns the length of the buffer.
func (ab *AsmBuf) Len() int { return ab.off }

// Bytes returns the contents of the buffer.
func (ab *AsmBuf) Bytes() []byte { return ab.buf[:ab.off] }

// Reset empties the buffer.
func (ab *AsmBuf) Reset() { ab.off = 0 }

// At returns the byte at offset i.
func (ab *AsmBuf) At(i int) byte { return ab.buf[i] }

// asmidx emits SIB byte.
func (ab *AsmBuf) asmidx(ctxt *obj.Link, scale int, index int, base int) {
	var i int

	// X/Y index register is used in VSIB.
	switch index {
	default:
		goto bad

	case REG_NONE:
		i = 4 << 3
		goto bas

	case REG_R8,
		REG_R9,
		REG_R10,
		REG_R11,
		REG_R12,
		REG_R13,
		REG_R14,
		REG_R15,
		REG_X8,
		REG_X9,
		REG_X10,
		REG_X11,
		REG_X12,
		REG_X13,
		REG_X14,
		REG_X15,
		REG_X16,
		REG_X17,
		REG_X18,
		REG_X19,
		REG_X20,
		REG_X21,
		REG_X22,
		REG_X23,
		REG_X24,
		REG_X25,
		REG_X26,
		REG_X27,
		REG_X28,
		REG_X29,
		REG_X30,
		REG_X31,
		REG_Y8,
		REG_Y9,
		REG_Y10,
		REG_Y11,
		REG_Y12,
		REG_Y13,
		REG_Y14,
		REG_Y15,
		REG_Y16,
		REG_Y17,
		REG_Y18,
		REG_Y19,
		REG_Y20,
		REG_Y21,
		REG_Y22,
		REG_Y23,
		REG_Y24,
		REG_Y25,
		REG_Y26,
		REG_Y27,
		REG_Y28,
		REG_Y29,
		REG_Y30,
		REG_Y31,
		REG_Z8,
		REG_Z9,
		REG_Z10,
		REG_Z11,
		REG_Z12,
		REG_Z13,
		REG_Z14,
		REG_Z15,
		REG_Z16,
		REG_Z17,
		REG_Z18,
		REG_Z19,
		REG_Z20,
		REG_Z21,
		REG_Z22,
		REG_Z23,
		REG_Z24,
		REG_Z25,
		REG_Z26,
		REG_Z27,
		REG_Z28,
		REG_Z29,
		REG_Z30,
		REG_Z31:
		if ctxt.Arch.Family == sys.I386 {
			goto bad
		}
		fallthrough

	case REG_AX,
		REG_CX,
		REG_DX,
		REG_BX,
		REG_BP,
		REG_SI,
		REG_DI,
		REG_X0,
		REG_X1,
		REG_X2,
		REG_X3,
		REG_X4,
		REG_X5,
		REG_X6,
		REG_X7,
		REG_Y0,
		REG_Y1,
		REG_Y2,
		REG_Y3,
		REG_Y4,
		REG_Y5,
		REG_Y6,
		REG_Y7,
		REG_Z0,
		REG_Z1,
		REG_Z2,
		REG_Z3,
		REG_Z4,
		REG_Z5,
		REG_Z6,
		REG_Z7:
		i = reg[index] << 3
	}

	switch scale {
	default:
		goto bad

	case 1:
		break

	case 2:
		i |= 1 << 6

	case 4:
		i |= 2 << 6

	case 8:
		i |= 3 << 6
	}

bas:
	switch base {
	default:
		goto bad

	case REG_NONE: // must be mod=00
		i |= 5

	case REG_R8,
		REG_R9,
		REG_R10,
		REG_R11,
		REG_R12,
		REG_R13,
		REG_R14,
		REG_R15:
		if ctxt.Arch.Family == sys.I386 {
			goto bad
		}
		fallthrough

	case REG_AX,
		REG_CX,
		REG_DX,
		REG_BX,
		REG_SP,
		REG_BP,
		REG_SI,
		REG_DI:
		i |= reg[base]
	}

	ab.Put1(byte(i))
	return

bad:
	ctxt.Diag("asmidx: bad address %d/%s/%s", scale, rconv(index), rconv(base))
	ab.Put1(0)
}

func (ab *AsmBuf) relput4(ctxt *obj.Link, cursym *obj.LSym, p *obj.Prog, a *obj.Addr) {
	var rel obj.Reloc

	v := vaddr(ctxt, p, a, &rel)
	if rel.Siz != 0 {
		if rel.Siz != 4 {
			ctxt.Diag("bad reloc")
		}
		rel.Off = int32(p.Pc + int64(ab.Len()))
		cursym.AddRel(ctxt, rel)
	}

	ab.PutInt32(int32(v))
}

func vaddr(ctxt *obj.Link, p *obj.Prog, a *obj.Addr, r *obj.Reloc) int64 {
	if r != nil {
		*r = obj.Reloc{}
	}

	switch a.Name {
	case obj.NAME_STATIC,
		obj.NAME_GOTREF,
		obj.NAME_EXTERN:
		s := a.Sym
		if r == nil {
			ctxt.Diag("need reloc for %v", obj.Dconv(p, a))
			log.Fatalf("reloc")
		}

		if a.Name == obj.NAME_GOTREF {
			r.Siz = 4
			r.Type = objabi.R_GOTPCREL
		} else if useAbs(ctxt, s) {
			r.Siz = 4
			r.Type = objabi.R_ADDR
		} else {
			r.Siz = 4
			r.Type = objabi.R_PCREL
		}

		r.Off = -1 // caller must fill in
		r.Sym = s
		r.Add = a.Offset

		return 0
	}

	if (a.Type == obj.TYPE_MEM || a.Type == obj.TYPE_ADDR) && a.Reg == REG_TLS {
		if r == nil {
			ctxt.Diag("need reloc for %v", obj.Dconv(p, a))
			log.Fatalf("reloc")
		}

		if !ctxt.Flag_shared || isAndroid || ctxt.Headtype == objabi.Hdarwin {
			r.Type = objabi.R_TLS_LE
			r.Siz = 4
			r.Off = -1 // caller must fill in
			r.Add = a.Offset
		}
		return 0
	}

	return a.Offset
}

func (ab *AsmBuf) asmandsz(ctxt *obj.Link, cursym *obj.LSym, p *obj.Prog, a *obj.Addr, r int, rex int, m64 int) {
	var base int
	var rel obj.Reloc

	rex &= 0x40 | Rxr
	if a.Offset != int64(int32(a.Offset)) {
		// The rules are slightly different for 386 and AMD64,
		// mostly for historical reasons. We may unify them later,
		// but it must be discussed beforehand.
		//
		// For 64bit mode only LEAL is allowed to overflow.
		// It's how https://golang.org/cl/59630 made it.
		// crypto/sha1/sha1block_amd64.s depends on this feature.
		//
		// For 32bit mode rules are more permissive.
		// If offset fits uint32, it's permitted.
		// This is allowed for assembly that wants to use 32-bit hex
		// constants, e.g. LEAL 0x99999999(AX), AX.
		overflowOK := (ctxt.Arch.Family == sys.AMD64 && p.As == ALEAL) ||
			(ctxt.Arch.Family != sys.AMD64 &&
				int64(uint32(a.Offset)) == a.Offset &&
				ab.rexflag&Rxw == 0)
		if !overflowOK {
			ctxt.Diag("offset too large in %s", p)
		}
	}
	v := int32(a.Offset)
	rel.Siz = 0

	switch a.Type {
	case obj.TYPE_ADDR:
		if a.Name == obj.NAME_NONE {
			ctxt.Diag("unexpected TYPE_ADDR with NAME_NONE")
		}
		if a.Index == REG_TLS {
			ctxt.Diag("unexpected TYPE_ADDR with index==REG_TLS")
		}
		goto bad

	case obj.TYPE_REG:
		const regFirst = REG_AL
		const regLast = REG_Z31
		if a.Reg < regFirst || regLast < a.Reg {
			goto bad
		}
		if v != 0 {
			goto bad
		}
		ab.Put1(byte(3<<6 | reg[a.Reg]<<0 | r<<3))
		ab.rexflag |= regrex[a.Reg]&(0x40|Rxb) | rex
		return
	}

	if a.Type != obj.TYPE_MEM {
		goto bad
	}

	if a.Index != REG_NONE && a.Index != REG_TLS && !(REG_CS <= a.Index && a.Index <= REG_GS) {
		base := int(a.Reg)
		switch a.Name {
		case obj.NAME_EXTERN,
			obj.NAME_GOTREF,
			obj.NAME_STATIC:
			if !useAbs(ctxt, a.Sym) && ctxt.Arch.Family == sys.AMD64 {
				goto bad
			}
			if ctxt.Arch.Family == sys.I386 && ctxt.Flag_shared {
				// The base register has already been set. It holds the PC
				// of this instruction returned by a PC-reading thunk.
				// See obj6.go:rewriteToPcrel.
			} else {
				base = REG_NONE
			}
			v = int32(vaddr(ctxt, p, a, &rel))

		case obj.NAME_AUTO,
			obj.NAME_PARAM:
			base = REG_SP
		}

		ab.rexflag |= regrex[int(a.Index)]&Rxx | regrex[base]&Rxb | rex
		if base == REG_NONE {
			ab.Put1(byte(0<<6 | 4<<0 | r<<3))
			ab.asmidx(ctxt, int(a.Scale), int(a.Index), base)
			goto putrelv
		}

		if v == 0 && rel.Siz == 0 && base != REG_BP && base != REG_R13 {
			ab.Put1(byte(0<<6 | 4<<0 | r<<3))
			ab.asmidx(ctxt, int(a.Scale), int(a.Index), base)
			return
		}

		if disp8, ok := toDisp8(v, p, ab); ok && rel.Siz == 0 {
			ab.Put1(byte(1<<6 | 4<<0 | r<<3))
			ab.asmidx(ctxt, int(a.Scale), int(a.Index), base)
			ab.Put1(disp8)
			return
		}

		ab.Put1(byte(2<<6 | 4<<0 | r<<3))
		ab.asmidx(ctxt, int(a.Scale), int(a.Index), base)
		goto putrelv
	}

	base = int(a.Reg)
	switch a.Name {
	case obj.NAME_STATIC,
		obj.NAME_GOTREF,
		obj.NAME_EXTERN:
		if a.Sym == nil {
			ctxt.Diag("bad addr: %v", p)
		}
		if ctxt.Arch.Family == sys.I386 && ctxt.Flag_shared {
			// The base register has already been set. It holds the PC
			// of this instruction returned by a PC-reading thunk.
			// See obj6.go:rewriteToPcrel.
		} else {
			base = REG_NONE
		}
		v = int32(vaddr(ctxt, p, a, &rel))

	case obj.NAME_AUTO,
		obj.NAME_PARAM:
		base = REG_SP
	}

	if base == REG_TLS {
		v = int32(vaddr(ctxt, p, a, &rel))
	}

	ab.rexflag |= regrex[base]&Rxb | rex
	if base == REG_NONE || (REG_CS <= base && base <= REG_GS) || base == REG_TLS {
		if (a.Sym == nil || !useAbs(ctxt, a.Sym)) && base == REG_NONE && (a.Name == obj.NAME_STATIC || a.Name == obj.NAME_EXTERN || a.Name == obj.NAME_GOTREF) || ctxt.Arch.Family != sys.AMD64 {
			if a.Name == obj.NAME_GOTREF && (a.Offset != 0 || a.Index != 0 || a.Scale != 0) {
				ctxt.Diag("%v has offset against gotref", p)
			}
			ab.Put1(byte(0<<6 | 5<<0 | r<<3))
			goto putrelv
		}

		// temporary
		ab.Put2(
			byte(0<<6|4<<0|r<<3), // sib present
			0<<6|4<<3|5<<0,       // DS:d32
		)
		goto putrelv
	}

	if base == REG_SP || base == REG_R12 {
		if v == 0 {
			ab.Put1(byte(0<<6 | reg[base]<<0 | r<<3))
			ab.asmidx(ctxt, int(a.Scale), REG_NONE, base)
			return
		}

		if disp8, ok := toDisp8(v, p, ab); ok {
			ab.Put1(byte(1<<6 | reg[base]<<0 | r<<3))
			ab.asmidx(ctxt, int(a.Scale), REG_NONE, base)
			ab.Put1(disp8)
			return
		}

		ab.Put1(byte(2<<6 | reg[base]<<0 | r<<3))
		ab.asmidx(ctxt, int(a.Scale), REG_NONE, base)
		goto putrelv
	}

	if REG_AX <= base && base <= REG_R15 {
		if a.Index == REG_TLS && !ctxt.Flag_shared && !isAndroid &&
			ctxt.Headtype != objabi.Hwindows {
			rel = obj.Reloc{}
			rel.Type = objabi.R_TLS_LE
			rel.Siz = 4
			rel.Sym = nil
			rel.Add = int64(v)
			v = 0
		}

		if v == 0 && rel.Siz == 0 && base != REG_BP && base != REG_R13 {
			ab.Put1(byte(0<<6 | reg[base]<<0 | r<<3))
			return
		}

		if disp8, ok := toDisp8(v, p, ab); ok && rel.Siz == 0 {
			ab.Put2(byte(1<<6|reg[base]<<0|r<<3), disp8)
			return
		}

		ab.Put1(byte(2<<6 | reg[base]<<0 | r<<3))
		goto putrelv
	}

	goto bad

putrelv:
	if rel.Siz != 0 {
		if rel.Siz != 4 {
			ctxt.Diag("bad rel")
			goto bad
		}

		rel.Off = int32(p.Pc + int64(ab.Len()))
		cursym.AddRel(ctxt, rel)
	}

	ab.PutInt32(v)
	return

bad:
	ctxt.Diag("asmand: bad address %v", obj.Dconv(p, a))
}

func (ab *AsmBuf) asmand(ctxt *obj.Link, cursym *obj.LSym, p *obj.Prog, a *obj.Addr, ra *obj.Addr) {
	ab.asmandsz(ctxt, cursym, p, a, reg[ra.Reg], regrex[ra.Reg], 0)
}

func (ab *AsmBuf) asmando(ctxt *obj.Link, cursym *obj.LSym, p *obj.Prog, a *obj.Addr, o int) {
	ab.asmandsz(ctxt, cursym, p, a, o, 0, 0)
}

func bytereg(a *obj.Addr, t *uint8) {
	if a.Type == obj.TYPE_REG && a.Index == REG_NONE && (REG_AX <= a.Reg && a.Reg <= REG_R15) {
		a.Reg += REG_AL - REG_AX
		*t = 0
	}
}

func unbytereg(a *obj.Addr, t *uint8) {
	if a.Type == obj.TYPE_REG && a.Index == REG_NONE && (REG_AL <= a.Reg && a.Reg <= REG_R15B) {
		a.Reg += REG_AX - REG_AL
		*t = 0
	}
}

const (
	movLit uint8 = iota // Like Zlit
	movRegMem
	movMemReg
	movRegMem2op
	movMemReg2op
	movFullPtr // Load full pointer, trash heap (unsupported)
	movDoubleShift
	movTLSReg
)

var ymovtab = []movtab{
	// push
	{APUSHL, Ycs, Ynone, Ynone, movLit, [4]uint8{0x0e, 0}},
	{APUSHL, Yss, Ynone, Ynone, movLit, [4]uint8{0x16, 0}},
	{APUSHL, Yds, Ynone, Ynone, movLit, [4]uint8{0x1e, 0}},
	{APUSHL, Yes, Ynone, Ynone, movLit, [4]uint8{0x06, 0}},
	{APUSHL, Yfs, Ynone, Ynone, movLit, [4]uint8{0x0f, 0xa0, 0}},
	{APUSHL, Ygs, Ynone, Ynone, movLit, [4]uint8{0x0f, 0xa8, 0}},
	{APUSHQ, Yfs, Ynone, Ynone, movLit, [4]uint8{0x0f, 0xa0, 0}},
	{APUSHQ, Ygs, Ynone, Ynone, movLit, [4]uint8{0x0f, 0xa8, 0}},
	{APUSHW, Ycs, Ynone, Ynone, movLit, [4]uint8{Pe, 0x0e, 0}},
	{APUSHW, Yss, Ynone, Ynone, movLit, [4]uint8{Pe, 0x16, 0}},
	{APUSHW, Yds, Ynone, Ynone, movLit, [4]uint8{Pe, 0x1e, 0}},
	{APUSHW, Yes, Ynone, Ynone, movLit, [4]uint8{Pe, 0x06, 0}},
	{APUSHW, Yfs, Ynone, Ynone, movLit, [4]uint8{Pe, 0x0f, 0xa0, 0}},
	{APUSHW, Ygs, Ynone, Ynone, movLit, [4]uint8{Pe, 0x0f, 0xa8, 0}},

	// pop
	{APOPL, Ynone, Ynone, Yds, movLit, [4]uint8{0x1f, 0}},
	{APOPL, Ynone, Ynone, Yes, movLit, [4]uint8{0x07, 0}},
	{APOPL, Ynone, Ynone, Yss, movLit, [4]uint8{0x17, 0}},
	{APOPL, Ynone, Ynone, Yfs, movLit, [4]uint8{0x0f, 0xa1, 0}},
	{APOPL, Ynone, Ynone, Ygs, movLit, [4]uint8{0x0f, 0xa9, 0}},
	{APOPQ, Ynone, Ynone, Yfs, movLit, [4]uint8{0x0f, 0xa1, 0}},
	{APOPQ, Ynone, Ynone, Ygs, movLit, [4]uint8{0x0f, 0xa9, 0}},
	{APOPW, Ynone, Ynone, Yds, movLit, [4]uint8{Pe, 0x1f, 0}},
	{APOPW, Ynone, Ynone, Yes, movLit, [4]uint8{Pe, 0x07, 0}},
	{APOPW, Ynone, Ynone, Yss, movLit, [4]uint8{Pe, 0x17, 0}},
	{APOPW, Ynone, Ynone, Yfs, movLit, [4]uint8{Pe, 0x0f, 0xa1, 0}},
	{APOPW, Ynone, Ynone, Ygs, movLit, [4]uint8{Pe, 0x0f, 0xa9, 0}},

	// mov seg
	{AMOVW, Yes, Ynone, Yml, movRegMem, [4]uint8{0x8c, 0, 0, 0}},
	{AMOVW, Ycs, Ynone, Yml, movRegMem, [4]uint8{0x8c, 1, 0, 0}},
	{AMOVW, Yss, Ynone, Yml, movRegMem, [4]uint8{0x8c, 2, 0, 0}},
	{AMOVW, Yds, Ynone, Yml, movRegMem, [4]uint8{0x8c, 3, 0, 0}},
	{AMOVW, Yfs, Ynone, Yml, movRegMem, [4]uint8{0x8c, 4, 0, 0}},
	{AMOVW, Ygs, Ynone, Yml, movRegMem, [4]uint8{0x8c, 5, 0, 0}},
	{AMOVW, Yml, Ynone, Yes, movMemReg, [4]uint8{0x8e, 0, 0, 0}},
	{AMOVW, Yml, Ynone, Ycs, movMemReg, [4]uint8{0x8e, 1, 0, 0}},
	{AMOVW, Yml, Ynone, Yss, movMemReg, [4]uint8{0x8e, 2, 0, 0}},
	{AMOVW, Yml, Ynone, Yds, movMemReg, [4]uint8{0x8e, 3, 0, 0}},
	{AMOVW, Yml, Ynone, Yfs, movMemReg, [4]uint8{0x8e, 4, 0, 0}},
	{AMOVW, Yml, Ynone, Ygs, movMemReg, [4]uint8{0x8e, 5, 0, 0}},

	// mov cr
	{AMOVL, Ycr0, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 0, 0}},
	{AMOVL, Ycr2, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 2, 0}},
	{AMOVL, Ycr3, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 3, 0}},
	{AMOVL, Ycr4, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 4, 0}},
	{AMOVL, Ycr8, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 8, 0}},
	{AMOVQ, Ycr0, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 0, 0}},
	{AMOVQ, Ycr2, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 2, 0}},
	{AMOVQ, Ycr3, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 3, 0}},
	{AMOVQ, Ycr4, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 4, 0}},
	{AMOVQ, Ycr8, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x20, 8, 0}},
	{AMOVL, Yrl, Ynone, Ycr0, movMemReg2op, [4]uint8{0x0f, 0x22, 0, 0}},
	{AMOVL, Yrl, Ynone, Ycr2, movMemReg2op, [4]uint8{0x0f, 0x22, 2, 0}},
	{AMOVL, Yrl, Ynone, Ycr3, movMemReg2op, [4]uint8{0x0f, 0x22, 3, 0}},
	{AMOVL, Yrl, Ynone, Ycr4, movMemReg2op, [4]uint8{0x0f, 0x22, 4, 0}},
	{AMOVL, Yrl, Ynone, Ycr8, movMemReg2op, [4]uint8{0x0f, 0x22, 8, 0}},
	{AMOVQ, Yrl, Ynone, Ycr0, movMemReg2op, [4]uint8{0x0f, 0x22, 0, 0}},
	{AMOVQ, Yrl, Ynone, Ycr2, movMemReg2op, [4]uint8{0x0f, 0x22, 2, 0}},
	{AMOVQ, Yrl, Ynone, Ycr3, movMemReg2op, [4]uint8{0x0f, 0x22, 3, 0}},
	{AMOVQ, Yrl, Ynone, Ycr4, movMemReg2op, [4]uint8{0x0f, 0x22, 4, 0}},
	{AMOVQ, Yrl, Ynone, Ycr8, movMemReg2op, [4]uint8{0x0f, 0x22, 8, 0}},

	// mov dr
	{AMOVL, Ydr0, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 0, 0}},
	{AMOVL, Ydr6, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 6, 0}},
	{AMOVL, Ydr7, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 7, 0}},
	{AMOVQ, Ydr0, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 0, 0}},
	{AMOVQ, Ydr2, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 2, 0}},
	{AMOVQ, Ydr3, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 3, 0}},
	{AMOVQ, Ydr6, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 6, 0}},
	{AMOVQ, Ydr7, Ynone, Yrl, movRegMem2op, [4]uint8{0x0f, 0x21, 7, 0}},
	{AMOVL, Yrl, Ynone, Ydr0, movMemReg2op, [4]uint8{0x0f, 0x23, 0, 0}},
	{AMOVL, Yrl, Ynone, Ydr6, movMemReg2op, [4]uint8{0x0f, 0x23, 6, 0}},
	{AMOVL, Yrl, Ynone, Ydr7, movMemReg2op, [4]uint8{0x0f, 0x23, 7, 0}},
	{AMOVQ, Yrl, Ynone, Ydr0, movMemReg2op, [4]uint8{0x0f, 0x23, 0, 0}},
	{AMOVQ, Yrl, Ynone, Ydr2, movMemReg2op, [4]uint8{0x0f, 0x23, 2, 0}},
	{AMOVQ, Yrl, Ynone, Ydr3, movMemReg2op, [4]uint8{0x0f, 0x23, 3, 0}},
	{AMOVQ, Yrl, Ynone, Ydr6, movMemReg2op, [4]uint8{0x0f, 0x23, 6, 0}},
	{AMOVQ, Yrl, Ynone, Ydr7, movMemReg2op, [4]uint8{0x0f, 0x23, 7, 0}},

	// mov tr
	{AMOVL, Ytr6, Ynone, Yml, movRegMem2op, [4]uint8{0x0f, 0x24, 6, 0}},
	{AMOVL, Ytr7, Ynone, Yml, movRegMem2op, [4]uint8{0x0f, 0x24, 7, 0}},
	{AMOVL, Yml, Ynone, Ytr6, movMemReg2op, [4]uint8{0x0f, 0x26, 6, 0xff}},
	{AMOVL, Yml, Ynone, Ytr7, movMemReg2op, [4]uint8{0x0f, 0x26, 7, 0xff}},

	// lgdt, sgdt, lidt, sidt
	{AMOVL, Ym, Ynone, Ygdtr, movMemReg2op, [4]uint8{0x0f, 0x01, 2, 0}},
	{AMOVL, Ygdtr, Ynone, Ym, movRegMem2op, [4]uint8{0x0f, 0x01, 0, 0}},
	{AMOVL, Ym, Ynone, Yidtr, movMemReg2op, [4]uint8{0x0f, 0x01, 3, 0}},
	{AMOVL, Yidtr, Ynone, Ym, movRegMem2op, [4]uint8{0x0f, 0x01, 1, 0}},
	{AMOVQ, Ym, Ynone, Ygdtr, movMemReg2op, [4]uint8{0x0f, 0x01, 2, 0}},
	{AMOVQ, Ygdtr, Ynone, Ym, movRegMem2op, [4]uint8{0x0f, 0x01, 0, 0}},
	{AMOVQ, Ym, Ynone, Yidtr, movMemReg2op, [4]uint8{0x0f, 0x01, 3, 0}},
	{AMOVQ, Yidtr, Ynone, Ym, movRegMem2op, [4]uint8{0x0f, 0x01, 1, 0}},

	// lldt, sldt
	{AMOVW, Yml, Ynone, Yldtr, movMemReg2op, [4]uint8{0x0f, 0x00, 2, 0}},
	{AMOVW, Yldtr, Ynone, Yml, movRegMem2op, [4]uint8{0x0f, 0x00, 0, 0}},

	// lmsw, smsw
	{AMOVW, Yml, Ynone, Ymsw, movMemReg2op, [4]uint8{0x0f, 0x01, 6, 0}},
	{AMOVW, Ymsw, Ynone, Yml, movRegMem2op, [4]uint8{0x0f, 0x01, 4, 0}},

	// ltr, str
	{AMOVW, Yml, Ynone, Ytask, movMemReg2op, [4]uint8{0x0f, 0x00, 3, 0}},
	{AMOVW, Ytask, Ynone, Yml, movRegMem2op, [4]uint8{0x0f, 0x00, 1, 0}},

	/* load full pointer - unsupported
	{AMOVL, Yml, Ycol, movFullPtr, [4]uint8{0, 0, 0, 0}},
	{AMOVW, Yml, Ycol, movFullPtr, [4]uint8{Pe, 0, 0, 0}},
	*/

	// double shift
	{ASHLL, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{0xa4, 0xa5, 0, 0}},
	{ASHLL, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{0xa4, 0xa5, 0, 0}},
	{ASHLL, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{0xa4, 0xa5, 0, 0}},
	{ASHRL, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{0xac, 0xad, 0, 0}},
	{ASHRL, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{0xac, 0xad, 0, 0}},
	{ASHRL, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{0xac, 0xad, 0, 0}},
	{ASHLQ, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xa4, 0xa5, 0}},
	{ASHLQ, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xa4, 0xa5, 0}},
	{ASHLQ, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xa4, 0xa5, 0}},
	{ASHRQ, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xac, 0xad, 0}},
	{ASHRQ, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xac, 0xad, 0}},
	{ASHRQ, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{Pw, 0xac, 0xad, 0}},
	{ASHLW, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xa4, 0xa5, 0}},
	{ASHLW, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xa4, 0xa5, 0}},
	{ASHLW, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xa4, 0xa5, 0}},
	{ASHRW, Yi8, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xac, 0xad, 0}},
	{ASHRW, Ycl, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xac, 0xad, 0}},
	{ASHRW, Ycx, Yrl, Yml, movDoubleShift, [4]uint8{Pe, 0xac, 0xad, 0}},

	// load TLS base
	{AMOVL, Ytls, Ynone, Yrl, movTLSReg, [4]uint8{0, 0, 0, 0}},
	{AMOVQ, Ytls, Ynone, Yrl, movTLSReg, [4]uint8{0, 0, 0, 0}},
	{0, 0, 0, 0, 0, [4]uint8{}},
}

func isax(a *obj.Addr) bool {
	switch a.Reg {
	case REG_AX, REG_AL, REG_AH:
		return true
	}

	return a.Index == REG_AX
}

func subreg(p *obj.Prog, from int, to int) {
	if false { /* debug['Q'] */
		fmt.Printf("\n%v\ts/%v/%v/\n", p, rconv(from), rconv(to))
	}

	if int(p.From.Reg) == from {
		p.From.Reg = int16(to)
		p.Ft = 0
	}

	if int(p.To.Reg) == from {
		p.To.Reg = int16(to)
		p.Tt = 0
	}

	if int(p.From.Index) == from {
		p.From.Index = int16(to)
		p.Ft = 0
	}

	if int(p.To.Index) == from {
		p.To.Index = int16(to)
		p.Tt = 0
	}

	if false { /* debug['Q'] */
		fmt.Printf("%v\n", p)
	}
}

func (ab *AsmBuf) mediaop(ctxt *obj.Link, o *Optab, op int, osize int, z int) int {
	switch op {
	case Pm, Pe, Pf2, Pf3:
		if osize != 1 {
			if op != Pm {
				ab.Put1(byte(op))
			}
			ab.Put1(Pm)
			z++
			op = int(o.op[z])
			break
		}
		fallthrough

	default:
		if ab.Len() == 0 || ab.Last() != Pm {
			ab.Put1(Pm)
		}
	}

	ab.Put1(byte(op))
	return z
}

var bpduff1 = []byte{
	0x48, 0x89, 0x6c, 0x24, 0xf0, // MOVQ BP, -16(SP)
	0x48, 0x8d, 0x6c, 0x24, 0xf0, // LEAQ -16(SP), BP
}

var bpduff2 = []byte{
	0x48, 0x8b, 0x6d, 0x00, // MOVQ 0(BP), BP
}

// asmevex emits EVEX pregis and opcode byte.
// In addition to asmvex r/m, vvvv and reg fields also requires optional
// K-masking register.
//
// Expects asmbuf.evex to be properly initialized.
func (ab *AsmBuf) asmevex(ctxt *obj.Link, p *obj.Prog, rm, v, r, k *obj.Addr) {
	ab.evexflag = true
	evex := ab.evex

	rexR := byte(1)
	evexR := byte(1)
	rexX := byte(1)
	rexB := byte(1)
	if r != nil {
		if regrex[r.Reg]&Rxr != 0 {
			rexR = 0 // "ModR/M.reg" selector 4th bit.
		}
		if regrex[r.Reg]&RxrEvex != 0 {
			evexR = 0 // "ModR/M.reg" selector 5th bit.
		}
	}
	if rm != nil {
		if rm.Index == REG_NONE && regrex[rm.Reg]&RxrEvex != 0 {
			rexX = 0
		} else if regrex[rm.Index]&Rxx != 0 {
			rexX = 0
		}
		if regrex[rm.Reg]&Rxb != 0 {
			rexB = 0
		}
	}
	// P0 = [R][X][B][R'][00][mm]
	p0 := (rexR << 7) |
		(rexX << 6) |
		(rexB << 5) |
		(evexR << 4) |
		(0 << 2) |
		(evex.M() << 0)

	vexV := byte(0)
	if v != nil {
		// 4bit-wide reg index.
		vexV = byte(reg[v.Reg]|(regrex[v.Reg]&Rxr)<<1) & 0xF
	}
	vexV ^= 0x0F
	// P1 = [W][vvvv][1][pp]
	p1 := (evex.W() << 7) |
		(vexV << 3) |
		(1 << 2) |
		(evex.P() << 0)

	suffix := evexSuffixMap[p.Scond]
	evexZ := byte(0)
	evexLL := evex.L()
	evexB := byte(0)
	evexV := byte(1)
	evexA := byte(0)
	if suffix.zeroing {
		if !evex.ZeroingEnabled() {
			ctxt.Diag("unsupported zeroing: %v", p)
		}
		if k == nil {
			// When you request zeroing you must specify a mask register.
			// See issue 57952.
			ctxt.Diag("mask register must be specified for .Z instructions: %v", p)
		} else if k.Reg == REG_K0 {
			// The mask register must not be K0. That restriction is already
			// handled by the Yknot0 restriction in the opcode tables, so we
			// won't ever reach here. But put something sensible here just in case.
			ctxt.Diag("mask register must not be K0 for .Z instructions: %v", p)
		}
		evexZ = 1
	}
	switch {
	case suffix.rounding != rcUnset:
		if rm != nil && rm.Type == obj.TYPE_MEM {
			ctxt.Diag("illegal rounding with memory argument: %v", p)
		} else if !evex.RoundingEnabled() {
			ctxt.Diag("unsupported rounding: %v", p)
		}
		evexB = 1
		evexLL = suffix.rounding
	case suffix.broadcast:
		if rm == nil || rm.Type != obj.TYPE_MEM {
			ctxt.Diag("illegal broadcast without memory argument: %v", p)
		} else if !evex.BroadcastEnabled() {
			ctxt.Diag("unsupported broadcast: %v", p)
		}
		evexB = 1
	case suffix.sae:
		if rm != nil && rm.Type == obj.TYPE_MEM {
			ctxt.Diag("illegal SAE with memory argument: %v", p)
		} else if !evex.SaeEnabled() {
			ctxt.Diag("unsupported SAE: %v", p)
		}
		evexB = 1
	}
	if rm != nil && regrex[rm.Index]&RxrEvex != 0 {
		evexV = 0
	} else if v != nil && regrex[v.Reg]&RxrEvex != 0 {
		evexV = 0 // VSR selector 5th bit.
	}
	if k != nil {
		evexA = byte(reg[k.Reg])
	}
	// P2 = [z][L'L][b][V'][aaa]
	p2 := (evexZ << 7) |
		(evexLL << 5) |
		(evexB << 4) |
		(evexV << 3) |
		(evexA << 0)

	const evexEscapeByte = 0x62
	ab.Put4(evexEscapeByte, p0, p1, p2)
	ab.Put1(evex.opcode)
}

// Emit VEX prefix and opcode byte.
// The three addresses are the r/m, vvvv, and reg fields.
// The reg and rm arguments appear in the same order as the
// arguments to asmand, which typically follows the call to asmvex.
// The final two arguments are the VEX prefix (see encoding above)
// and the opcode byte.
// For details about vex prefix see:
// https://en.wikipedia.org/wiki/VEX_prefix#Technical_description
func (ab *AsmBuf) asmvex(ctxt *obj.Link, rm, v, r *obj.Addr, vex, opcode uint8) {
	ab.vexflag = true
	rexR := 0
	if r != nil {
		rexR = regrex[r.Reg] & Rxr
	}
	rexB := 0
	rexX := 0
	if rm != nil {
		rexB = regrex[rm.Reg] & Rxb
		rexX = regrex[rm.Index] & Rxx
	}
	vexM := (vex >> 3) & 0x7
	vexWLP := vex & 0x87
	vexV := byte(0)
	if v != nil {
		vexV = byte(reg[v.Reg]|(regrex[v.Reg]&Rxr)<<1) & 0xF
	}
	vexV ^= 0xF
	if vexM == 1 && (rexX|rexB) == 0 && vex&vexW1 == 0 {
		// Can use 2-byte encoding.
		ab.Put2(0xc5, byte(rexR<<5)^0x80|vexV<<3|vexWLP)
	} else {
		// Must use 3-byte encoding.
		ab.Put3(0xc4,
			(byte(rexR|rexX|rexB)<<5)^0xE0|vexM,
			vexV<<3|vexWLP,
		)
	}
	ab.Put1(opcode)
}

// regIndex returns register index that fits in 5 bits.
//
//	R         : 3 bit | legacy instructions     | N/A
//	[R/V]EX.R : 1 bit | REX / VEX extension bit | Rxr
//	EVEX.R    : 1 bit | EVEX extension bit      | RxrEvex
//
// Examples:
//
//	REG_Z30 => 30
//	REG_X15 => 15
//	REG_R9  => 9
//	REG_AX  => 0
func regIndex(r int16) int {
	lower3bits := reg[r]
	high4bit := regrex[r] & Rxr << 1
	high5bit := regrex[r] & RxrEvex << 0
	return lower3bits | high4bit | high5bit
}

// avx2gatherValid reports whether p satisfies AVX2 gather constraints.
// Reports errors via ctxt.
func avx2gatherValid(ctxt *obj.Link, p *obj.Prog) bool {
	// If any pair of the index, mask, or destination registers
	// are the same, illegal instruction trap (#UD) is triggered.
	index := regIndex(p.GetFrom3().Index)
	mask := regIndex(p.From.Reg)
	dest := regIndex(p.To.Reg)
	if dest == mask || dest == index || mask == index {
		ctxt.Diag("mask, index, and destination registers should be distinct: %v", p)
		return false
	}

	return true
}

// avx512gatherValid reports whether p satisfies AVX512 gather constraints.
// Reports errors via ctxt.
func avx512gatherValid(ctxt *obj.Link, p *obj.Prog) bool {
	// Illegal instruction trap (#UD) is triggered if the destination vector
	// register is the same as index vector in VSIB.
	index := regIndex(p.From.Index)
	dest := regIndex(p.To.Reg)
	if dest == index {
		ctxt.Diag("index and destination registers should be distinct: %v", p)
		return false
	}

	return true
}

func (ab *AsmBuf) doasm(ctxt *obj.Link, cursym *obj.LSym, p *obj.Prog) {
	o := opindex[p.As&obj.AMask]

	if o == nil {
		ctxt.Diag("asmins: missing op %v", p)
		return
	}

	if pre := prefixof(ctxt, &p.From); pre != 0 {
		ab.Put1(byte(pre))
	}
	if pre := prefixof(ctxt, &p.To); pre != 0 {
		ab.Put1(byte(pre))
	}

	// Checks to warn about instruction/arguments combinations that
	// will unconditionally trigger illegal instruction trap (#UD).
	switch p.As {
	case AVGATHERDPD,
		AVGATHERQPD,
		AVGATHERDPS,
		AVGATHERQPS,
		AVPGATHERDD,
		AVPGATHERQD,
		AVPGATHERDQ,
		AVPGATHERQQ:
		if p.GetFrom3() == nil {
			// gathers need a 3rd arg. See issue 58822.
			ctxt.Diag("need a third arg for gather instruction: %v", p)
			return
		}
		// AVX512 gather requires explicit K mask.
		if p.GetFrom3().Reg >= REG_K0 && p.GetFrom3().Reg <= REG_K7 {
			if !avx512gatherValid(ctxt, p) {
				return
			}
		} else {
			if !avx2gatherValid(ctxt, p) {
				return
			}
		}
	}

	if p.Ft == 0 {
		p.Ft = uint8(oclass(ctxt, p, &p.From))
	}
	if p.Tt == 0 {
		p.Tt = uint8(oclass(ctxt, p, &p.To))
	}

	ft := int(p.Ft) * Ymax
	tt := int(p.Tt) * Ymax

	xo := obj.Bool2int(o.op[0] == 0x0f)
	z := 0

	args := make([]int, 0, argListMax)
	if ft != Ynone*Ymax {
		args = append(args, ft)
	}
	for i := range p.RestArgs {
		args = append(args, oclass(ctxt, p, &p.RestArgs[i].Addr)*Ymax)
	}
	if tt != Ynone*Ymax {
		args = append(args, tt)
	}

	var f3t int
	for _, yt := range o.ytab {
		// ytab matching is purely args-based,
		// but AVX512 suffixes like "Z" or "RU_SAE" will
		// add EVEX-only filter that will reject non-EVEX matches.
		//
		// Consider "VADDPD.BCST 2032(DX), X0, X0".
		// Without this rule, operands will lead to VEX-encoded form
		// and produce "c5b15813" encoding.
		if !yt.match(args) {
			// "xo" is always zero for VEX/EVEX encoded insts.
			z += int(yt.zoffset) + xo
		} else {
			if p.Scond != 0 && !evexZcase(yt.zcase) {
				// Do not signal error and continue to search
				// for matching EVEX-encoded form.
				z += int(yt.zoffset)
				continue
			}

			switch o.prefix {
			case Px1: // first option valid only in 32-bit mode
				if ctxt.Arch.Family == sys.AMD64 && z == 0 {
					z += int(yt.zoffset) + xo
					continue
				}
			case Pq: // 16 bit escape and opcode escape
				ab.Put2(Pe, Pm)

			case Pq3: // 16 bit escape and opcode escape + REX.W
				ab.rexflag |= Pw
				ab.Put2(Pe, Pm)

			case Pq4: // 66 0F 38
				ab.Put3(0x66, 0x0F, 0x38)

			case Pq4w: // 66 0F 38 + REX.W
				ab.rexflag |= Pw
				ab.Put3(0x66, 0x0F, 0x38)

			case Pq5: // F3 0F 38
				ab.Put3(0xF3, 0x0F, 0x38)

			case Pq5w: //  F3 0F 38 + REX.W
				ab.rexflag |= Pw
				ab.Put3(0xF3, 0x0F, 0x38)

			case Pf2, // xmm opcode escape
				Pf3:
				ab.Put2(o.prefix, Pm)

			case Pef3:
				ab.Put3(Pe, Pf3, Pm)

			case Pfw: // xmm opcode escape + REX.W
				ab.rexflag |= Pw
				ab.Put2(Pf3, Pm)

			case Pm: // opcode escape
				ab.Put1(Pm)

			case Pe: // 16 bit escape
				ab.Put1(Pe)

			case Pw: // 64-bit escape
				if ctxt.Arch.Family != sys.AMD64 {
					ctxt.Diag("asmins: illegal 64: %v", p)
				}
				ab.rexflag |= Pw

			case Pw8: // 64-bit escape if z >= 8
				if z >= 8 {
					if ctxt.Arch.Family != sys.AMD64 {
						ctxt.Diag("asmins: illegal 64: %v", p)
					}
					ab.rexflag |= Pw
				}

			case Pb: // botch
				if ctxt.Arch.Family != sys.AMD64 && (isbadbyte(&p.From) || isbadbyte(&p.To)) {
					goto bad
				}
				// NOTE(rsc): This is probably safe to do always,
				// but when enabled it chooses different encodings
				// than the old cmd/internal/obj/i386 code did,
				// which breaks our "same bits out" checks.
				// In particular, CMPB AX, $0 encodes as 80 f8 00
				// in the original obj/i386, and it would encode
				// (using a valid, shorter form) as 3c 00 if we enabled
				// the call to bytereg here.
				if ctxt.Arch.Family == sys.AMD64 {
					bytereg(&p.From, &p.Ft)
					bytereg(&p.To, &p.Tt)
				}

			case P32: // 32 bit but illegal if 64-bit mode
				if ctxt.Arch.Family == sys.AMD64 {
					ctxt.Diag("asmins: illegal in 64-bit mode: %v", p)
				}

			case Py: // 64-bit only, no prefix
				if ctxt.Arch.Family != sys.AMD64 {
					ctxt.Diag("asmins: illegal in %d-bit mode: %v", ctxt.Arch.RegSize*8, p)
				}

			case Py1: // 64-bit only if z < 1, no prefix
				if z < 1 && ctxt.Arch.Family != sys.AMD64 {
					ctxt.Diag("asmins: illegal in %d-bit mode: %v", ctxt.Arch.RegSize*8, p)
				}

			case Py3: // 64-bit only if z < 3, no prefix
				if z < 3 && ctxt.Arch.Family != sys.AMD64 {
					ctxt.Diag("asmins: illegal in %d-bit mode: %v", ctxt.Arch.RegSize*8, p)
				}
			}

			if z >= len(o.op) {
				log.Fatalf("asmins bad table %v", p)
			}
			op := int(o.op[z])
			if op == 0x0f {
				ab.Put1(byte(op))
				z++
				op = int(o.op[z])
			}

			switch yt.zcase {
			default:
				ctxt.Diag("asmins: unknown z %d %v", yt.zcase, p)
				return

			case Zpseudo:
				break

			case Zlit:
				ab.PutOpBytesLit(z, &o.op)

			case Zlitr_m:
				ab.PutOpBytesLit(z, &o.op)
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zlitm_r:
				ab.PutOpBytesLit(z, &o.op)
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zlit_m_r:
				ab.PutOpBytesLit(z, &o.op)
				ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)

			case Zmb_r:
				bytereg(&p.From, &p.Ft)
				fallthrough

			case Zm_r:
				ab.Put1(byte(op))
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Z_m_r:
				ab.Put1(byte(op))
				ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)

			case Zm2_r:
				ab.Put2(byte(op), o.op[z+1])
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zm_r_xm:
				ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zm_r_xm_nr:
				ab.rexflag = 0
				ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zm_r_i_xm:
				ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmand(ctxt, cursym, p, &p.From, p.GetFrom3())
				ab.Put1(byte(p.To.Offset))

			case Zibm_r, Zibr_m:
				ab.PutOpBytesLit(z, &o.op)
				if yt.zcase == Zibr_m {
					ab.asmand(ctxt, cursym, p, &p.To, p.GetFrom3())
				} else {
					ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)
				}
				switch {
				default:
					ab.Put1(byte(p.From.Offset))
				case yt.args[0] == Yi32 && o.prefix == Pe:
					ab.PutInt16(int16(p.From.Offset))
				case yt.args[0] == Yi32:
					ab.PutInt32(int32(p.From.Offset))
				}

			case Zaut_r:
				ab.Put1(0x8d) // leal
				if p.From.Type != obj.TYPE_ADDR {
					ctxt.Diag("asmins: Zaut sb type ADDR")
				}
				p.From.Type = obj.TYPE_MEM
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)
				p.From.Type = obj.TYPE_ADDR

			case Zm_o:
				ab.Put1(byte(op))
				ab.asmando(ctxt, cursym, p, &p.From, int(o.op[z+1]))

			case Zr_m:
				ab.Put1(byte(op))
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zvex:
				ab.asmvex(ctxt, &p.From, p.GetFrom3(), &p.To, o.op[z], o.op[z+1])

			case Zvex_rm_v_r:
				ab.asmvex(ctxt, &p.From, p.GetFrom3(), &p.To, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zvex_rm_v_ro:
				ab.asmvex(ctxt, &p.From, p.GetFrom3(), &p.To, o.op[z], o.op[z+1])
				ab.asmando(ctxt, cursym, p, &p.From, int(o.op[z+2]))

			case Zvex_i_rm_vo:
				ab.asmvex(ctxt, p.GetFrom3(), &p.To, nil, o.op[z], o.op[z+1])
				ab.asmando(ctxt, cursym, p, p.GetFrom3(), int(o.op[z+2]))
				ab.Put1(byte(p.From.Offset))

			case Zvex_i_r_v:
				ab.asmvex(ctxt, p.GetFrom3(), &p.To, nil, o.op[z], o.op[z+1])
				regnum := byte(0x7)
				if p.GetFrom3().Reg >= REG_X0 && p.GetFrom3().Reg <= REG_X15 {
					regnum &= byte(p.GetFrom3().Reg - REG_X0)
				} else {
					regnum &= byte(p.GetFrom3().Reg - REG_Y0)
				}
				ab.Put1(o.op[z+2] | regnum)
				ab.Put1(byte(p.From.Offset))

			case Zvex_i_rm_v_r:
				imm, from, from3, to := unpackOps4(p)
				ab.asmvex(ctxt, from, from3, to, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, from, to)
				ab.Put1(byte(imm.Offset))

			case Zvex_i_rm_r:
				ab.asmvex(ctxt, p.GetFrom3(), nil, &p.To, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)
				ab.Put1(byte(p.From.Offset))

			case Zvex_v_rm_r:
				ab.asmvex(ctxt, p.GetFrom3(), &p.From, &p.To, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)

			case Zvex_r_v_rm:
				ab.asmvex(ctxt, &p.To, p.GetFrom3(), &p.From, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zvex_rm_r_vo:
				ab.asmvex(ctxt, &p.From, &p.To, p.GetFrom3(), o.op[z], o.op[z+1])
				ab.asmando(ctxt, cursym, p, &p.From, int(o.op[z+2]))

			case Zvex_i_r_rm:
				ab.asmvex(ctxt, &p.To, nil, p.GetFrom3(), o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, &p.To, p.GetFrom3())
				ab.Put1(byte(p.From.Offset))

			case Zvex_hr_rm_v_r:
				hr, from, from3, to := unpackOps4(p)
				ab.asmvex(ctxt, from, from3, to, o.op[z], o.op[z+1])
				ab.asmand(ctxt, cursym, p, from, to)
				ab.Put1(byte(regIndex(hr.Reg) << 4))

			case Zevex_k_rmo:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.To, nil, nil, &p.From)
				ab.asmando(ctxt, cursym, p, &p.To, int(o.op[z+3]))

			case Zevex_i_rm_vo:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, p.GetFrom3(), &p.To, nil, nil)
				ab.asmando(ctxt, cursym, p, p.GetFrom3(), int(o.op[z+3]))
				ab.Put1(byte(p.From.Offset))

			case Zevex_i_rm_k_vo:
				imm, from, kmask, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, from, to, nil, kmask)
				ab.asmando(ctxt, cursym, p, from, int(o.op[z+3]))
				ab.Put1(byte(imm.Offset))

			case Zevex_i_r_rm:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.To, nil, p.GetFrom3(), nil)
				ab.asmand(ctxt, cursym, p, &p.To, p.GetFrom3())
				ab.Put1(byte(p.From.Offset))

			case Zevex_i_r_k_rm:
				imm, from, kmask, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, to, nil, from, kmask)
				ab.asmand(ctxt, cursym, p, to, from)
				ab.Put1(byte(imm.Offset))

			case Zevex_i_rm_r:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, p.GetFrom3(), nil, &p.To, nil)
				ab.asmand(ctxt, cursym, p, p.GetFrom3(), &p.To)
				ab.Put1(byte(p.From.Offset))

			case Zevex_i_rm_k_r:
				imm, from, kmask, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, from, nil, to, kmask)
				ab.asmand(ctxt, cursym, p, from, to)
				ab.Put1(byte(imm.Offset))

			case Zevex_i_rm_v_r:
				imm, from, from3, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, from, from3, to, nil)
				ab.asmand(ctxt, cursym, p, from, to)
				ab.Put1(byte(imm.Offset))

			case Zevex_i_rm_v_k_r:
				imm, from, from3, kmask, to := unpackOps5(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, from, from3, to, kmask)
				ab.asmand(ctxt, cursym, p, from, to)
				ab.Put1(byte(imm.Offset))

			case Zevex_r_v_rm:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.To, p.GetFrom3(), &p.From, nil)
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zevex_rm_v_r:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.From, p.GetFrom3(), &p.To, nil)
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zevex_rm_k_r:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.From, nil, &p.To, p.GetFrom3())
				ab.asmand(ctxt, cursym, p, &p.From, &p.To)

			case Zevex_r_k_rm:
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, &p.To, nil, &p.From, p.GetFrom3())
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zevex_rm_v_k_r:
				from, from3, kmask, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, from, from3, to, kmask)
				ab.asmand(ctxt, cursym, p, from, to)

			case Zevex_r_v_k_rm:
				from, from3, kmask, to := unpackOps4(p)
				ab.evex = newEVEXBits(z, &o.op)
				ab.asmevex(ctxt, p, to, from3, from, kmask)
				ab.asmand(ctxt, cursym, p, to, from)

			case Zr_m_xm:
				ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zr_m_xm_nr:
				ab.rexflag = 0
				ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmand(ctxt, cursym, p, &p.To, &p.From)

			case Zo_m:
				ab.Put1(byte(op))
				ab.asmando(ctxt, cursym, p, &p.To, int(o.op[z+1]))

			case Zcallindreg:
				cursym.AddRel(ctxt, obj.Reloc{
					Type: objabi.R_CALLIND,
					Off:  int32(p.Pc),
				})
				fallthrough

			case Zo_m64:
				ab.Put1(byte(op))
				ab.asmandsz(ctxt, cursym, p, &p.To, int(o.op[z+1]), 0, 1)

			case Zm_ibo:
				ab.Put1(byte(op))
				ab.asmando(ctxt, cursym, p, &p.From, int(o.op[z+1]))
				ab.Put1(byte(vaddr(ctxt, p, &p.To, nil)))

			case Zibo_m:
				ab.Put1(byte(op))
				ab.asmando(ctxt, cursym, p, &p.To, int(o.op[z+1]))
				ab.Put1(byte(vaddr(ctxt, p, &p.From, nil)))

			case Zibo_m_xm:
				z = ab.mediaop(ctxt, o, op, int(yt.zoffset), z)
				ab.asmando(ctxt, cursym, p, &p.To, int(o.op[z+1]))
				ab.Put1(byte(vaddr(ctxt, p, &p.From, nil)))

			case Z_ib, Zib_:
				var a *obj.Addr
				if yt.zcase == Zib_ {
					a = &p.From
				} else {
					a = &p.To
				}
				ab.Put1(byte(op))
				if p.As == AXABORT {
					ab.Put1(o.op[z+1])
				}
				ab.Put1(byte(vaddr(ctxt, p, a, nil)))

			case Zib_rp:
				ab.rexflag |= regrex[p.To.Reg] & (Rxb | 0x40)
				ab.Put2(byte(op+reg[p.To.Reg]), byte(vaddr(ctxt, p, &p.From, nil)))

			case Zil_rp:
				ab.rexflag |= regrex[p.To.Reg] & Rxb
				ab.Put1(byte(op + reg[p.To.Reg]))
				if o.prefix == Pe {
					v := vaddr(ctxt, p, &p.From, nil)
					ab.PutInt16(int16(v))
				} else {
					ab.relput4(ctxt, cursym, p, &p.From)
				}

			case Zo_iw:
				ab.Put1(byte(op))
				if p.From.Type != obj.TYPE_NONE {
					v := vaddr(ctxt, p, &p.From, nil)
					ab.PutInt16(int16(v))
				}

			case Ziq_rp:
				var rel obj.Reloc
				v := vaddr(ctxt, p, &p.Fr
"""




```