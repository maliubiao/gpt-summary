Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code snippet, which is part of the PowerPC 64-bit architecture backend for the Go compiler. It's the second part of a two-part question, implying that the first part provided the initial context.

2. **Identify the Core Function:** The code is within the `ssaGenValue` function. This function, within the context of a compiler's Static Single Assignment (SSA) intermediate representation, is responsible for generating machine code instructions for specific SSA operations (`ssa.Op` values). The `ssaGenBlock` function handles generating code for control flow within the SSA graph.

3. **Break Down `ssaGenValue`:** I'll iterate through the `switch` statement in `ssaGenValue`, analyzing each `case`.

    * **Zeroing Memory (`ssa.OpPPC64LoweredZero`, `ssa.OpPPC64LoweredZeroShort`):**  This case clearly deals with setting blocks of memory to zero. The code uses different strategies based on the size of the memory region. Small regions are cleared with individual `MOV` instructions. Larger regions utilize loops with vector instructions (`STXVD2X`) for efficiency. The comments about unaligned data and Power8 are crucial hints about the target architecture's characteristics.

    * **Memory Copying (`ssa.OpPPC64LoweredMove`, `ssa.OpPPC64LoweredMoveShort`, `ssa.OpPPC64LoweredQuadMove`, `ssa.OpPPC64LoweredQuadMoveShort`):** These cases handle copying data from one memory location to another. Similar to zeroing, they employ different strategies based on size, using loops with vector loads and stores (`LXVD2X`, `STXVD2X`, `LXV`, `STXV`) for larger transfers and individual `MOV` instructions for smaller remainders. The `QuadMove` variants likely target newer PowerPC architectures (like Power9) with potentially more efficient quad-word (128-bit) operations.

    * **Function Calls (`ssa.OpPPC64CALLstatic`, `ssa.OpPPC64CALLtail`, `ssa.OpPPC64CALLclosure`, `ssa.OpPPC64CALLinter`):** These are straightforward. They generate code for different types of function calls: static calls, tail calls, closure calls, and interface method calls. The code related to `REG_LR` (link register) and TOC pointers is specific to the PowerPC calling convention and PIC (Position Independent Code).

    * **Write Barriers (`ssa.OpPPC64LoweredWB`):**  This deals with garbage collection. Write barriers are used to notify the garbage collector when a pointer in a managed heap object is updated. The `AuxInt` likely indicates the size class or some other parameter for the write barrier.

    * **Panic/Bounds Checks (`ssa.OpPPC64LoweredPanicBoundsA`, etc.):** These generate calls to runtime functions that handle array bounds checks and trigger panics if a violation occurs.

    * **Nil Checks (`ssa.OpPPC64LoweredNilCheck`):**  This generates code to check if a pointer is nil. The implementation differs slightly for AIX, but the core idea is to cause a fault if the pointer is zero.

    * **Unimplemented/Pseudo-ops:** The remaining `case` statements flag operations that should have been handled earlier in the compilation pipeline. These are errors if they reach this stage.

4. **Break Down `ssaGenBlock`:**  This function handles generating assembly for control flow blocks.

    * **Defer (`ssa.BlockDefer`):** Generates code to check the return value from a `defer` call to determine if the deferred function should be executed.
    * **Plain (`ssa.BlockPlain`):**  A simple unconditional jump.
    * **Exit/RetJmp (`ssa.BlockExit`, `ssa.BlockRetJmp`):** No explicit code generation is needed here. These represent the end of a function or a jump for tail calls.
    * **Return (`ssa.BlockRet`):** Generates the `ARET` (return) instruction.
    * **Conditional Jumps (`ssa.BlockPPC64EQ`, etc.):** This uses the `blockJump` array to map SSA block kinds to the appropriate PowerPC branch instructions. It optimizes for the "next" block in the control flow graph to avoid unnecessary jumps.

5. **Identify Key Functionality:** Based on the analysis, the core functionality of this code is:

    * **Memory Manipulation:** Efficiently zeroing and copying memory blocks, with optimizations specific to the PowerPC architecture (like using vector instructions).
    * **Function Calls:** Generating the correct calling conventions for different types of Go function calls.
    * **Runtime Support:** Integrating with the Go runtime for garbage collection (write barriers), panic handling (bounds checks), and nil checks.
    * **Control Flow:** Translating SSA control flow blocks into conditional and unconditional jumps.

6. **Synthesize the Summary:**  Combine the identified functionalities into a concise summary.

7. **Provide Code Examples (where possible):** The request asks for Go code examples. The most illustrative examples are for the memory manipulation functions (`copy` and setting to zero). Function calls are harder to demonstrate concisely without a larger program.

8. **Infer Go Language Features:** Connect the generated assembly patterns back to high-level Go language features. Zeroing memory relates to default values and initialization. Memory copying relates to assignments and data structures. Function calls are fundamental. Write barriers are for garbage collection. Panic/bounds checks are for array/slice access. Nil checks are for pointer safety.

9. **Address Potential Pitfalls (if any):** In this specific code snippet, there aren't obvious user-facing pitfalls. The complexities are internal to the compiler. So, I'd skip this if there weren't any clear examples.

10. **Structure the Answer:**  Organize the answer clearly with headings and bullet points for readability. Use Chinese as requested.

By following this structured thinking process, I can systematically analyze the provided code and generate a comprehensive and accurate answer to the request. The key is to break down the code into manageable parts, understand the purpose of each part, and then synthesize the findings into a coherent explanation.
这是路径为go/src/cmd/compile/internal/ppc64/ssa.go的go语言实现的一部分， 这是第2部分，共2部分。

基于提供的代码片段，我们可以归纳一下它的主要功能是：

**低级代码生成：将SSA中间表示转换为PowerPC 64位汇编指令。**

具体来说，这段代码是 `ssaGenValue` 函数的一部分，它负责针对不同的 SSA 操作码 (`ssa.Op`) 生成相应的 PowerPC64 汇编指令。  同时，`ssaGenBlock` 函数负责生成控制流相关的汇编指令。

以下是代码片段中主要功能的总结：

1. **内存清零 (Zeroing Memory):**
   - 针对 `ssa.OpPPC64LoweredZero` 和 `ssa.OpPPC64LoweredZeroShort` 操作，生成将指定内存区域清零的汇编代码。
   - 对于较大的内存区域，它会生成一个循环，使用 `STXVD2X` 指令一次清零 16 字节（或更多，取决于具体情况），提高效率。
   - 对于较小的内存区域，它会使用 `MOVD`, `MOVW`, `MOVH`, `MOVB` 等指令逐字节或按字/半字/双字清零。

2. **内存移动 (Memory Move):**
   - 针对 `ssa.OpPPC64LoweredMove`, `ssa.OpPPC64LoweredMoveShort`, `ssa.OpPPC64LoweredQuadMove`, `ssa.OpPPC64LoweredQuadMoveShort` 操作，生成将一块内存区域复制到另一块内存区域的汇编代码。
   - 对于较大的内存区域，它会生成一个循环，使用向量指令 `LXVD2X` 和 `STXVD2X` (或 `LXV` 和 `STXV`) 一次移动 32 字节或 64 字节，提升性能。
   - 对于较小的剩余部分，它会使用 `MOVD`, `MOVW`, `MOVH`, `MOVB` 等指令进行移动。
   - `LoweredQuadMove` 系列的操作可能是针对支持更宽向量操作的较新 PowerPC 架构 (如 Power9) 的优化。

3. **函数调用 (Function Call):**
   - 针对 `ssa.OpPPC64CALLstatic` (静态调用), `ssa.OpPPC64CALLtail` (尾调用), `ssa.OpPPC64CALLclosure` (闭包调用), `ssa.OpPPC64CALLinter` (接口调用) 操作，生成相应的函数调用汇编代码。
   - 它会将函数地址加载到 `LR` 寄存器 (链接寄存器)，然后使用 `BL` (或 `BCL` 对于间接调用) 指令进行调用。
   - 对于间接调用，需要将函数地址加载到 `R12` 寄存器。
   - 在 PIC (位置无关代码) 的场景下，还会处理 TOC (Table of Contents) 指针的恢复。

4. **写屏障 (Write Barrier):**
   - 针对 `ssa.OpPPC64LoweredWB` 操作，生成调用垃圾回收器写屏障函数的汇编代码。`AuxInt` 字段可能用于指定写屏障的类型或参数。

5. **边界检查 (Bounds Check):**
   - 针对 `ssa.OpPPC64LoweredPanicBoundsA`, `ssa.OpPPC64LoweredPanicBoundsB`, `ssa.OpPPC64LoweredPanicBoundsC` 操作，生成调用运行时边界检查函数的汇编代码，并在越界时触发 panic。

6. **空指针检查 (Nil Check):**
   - 针对 `ssa.OpPPC64LoweredNilCheck` 操作，生成检查指针是否为空的汇编代码。
   - 在 AIX 系统上，它会使用 `CMP` 和条件跳转，并在指针为空时尝试写入地址 0 来触发 SIGSEGV 信号。
   - 在其他系统上，它会尝试从指针指向的地址加载一个字节，如果指针为空则会触发内存访问错误。

7. **控制流生成 (Block Generation):**
   - `ssaGenBlock` 函数负责将 SSA 的控制流块 (`ssa.Block`) 转换为 PowerPC64 的跳转指令。
   - 针对不同的块类型 (`ssa.BlockDefer`, `ssa.BlockPlain`, `ssa.BlockRet`, 以及各种条件跳转块)，生成相应的 `JMP`, `BEQ`, `BNE`, `BLT`, `BGE` 等指令。
   - 它会根据后续块的位置优化跳转，避免不必要的跳转。

8. **其他操作:**
   - 代码中还处理了一些其他 SSA 操作，例如加载寄存器结果 (`loadRegResult`) 和存储参数寄存器 (`spillArgReg`)。
   - 对于一些不应该出现在代码生成阶段的伪操作 (如 `ssa.OpPPC64Equal`, `ssa.OpPPC64NotEqual` 等)，会直接调用 `v.Fatalf` 报错。

**总而言之，这段代码是 Go 编译器 PowerPC64 后端的核心组成部分，负责将高级的 SSA 中间表示转换为可以直接在 PowerPC64 架构上执行的机器码，包括处理内存操作、函数调用、运行时支持以及控制流。**

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ppc64/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
hen clear remaining sizes as available
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