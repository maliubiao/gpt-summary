Response:
Let's break down the thought process for summarizing the provided Go code snippet.

1. **Understand the Context:** The prompt clearly states this is part of `go/src/cmd/compile/internal/arm64/ssa.go`, and it's part 2 of 2. This immediately tells us we're dealing with the ARM64 architecture within the Go compiler's intermediate representation (SSA) to assembly code generation phase. Part 1 likely dealt with earlier stages of the process.

2. **Identify Key Functions:**  Scanning the code, the main functions that stand out are `genValue` and `ssaGenBlock`. These names strongly suggest their purposes:
    * `genValue`: Likely responsible for generating assembly instructions for individual SSA values (operations).
    * `ssaGenBlock`: Likely responsible for generating assembly instructions for SSA basic blocks (control flow structures).

3. **Analyze `genValue`:**  This function has a large `switch` statement based on `v.Op`. This is a common pattern for handling different SSA operations. For each case:
    * Observe the `ssa.OpARM64...` prefixes. This confirms we are dealing with ARM64-specific operations.
    * Note the assembly instructions being generated using `s.Prog(arm64.AMOV...)`, `s.Prog(obj.AGETCALLERPC)`, etc. This shows how SSA operations are translated into concrete ARM64 assembly.
    * Look for patterns or groups of operations. For example, several cases handle getting closure pointers, caller SP/PC, memory barriers (DMB), constant flags, and clobbering registers/memory.

4. **Analyze `ssaGenBlock`:**  This function also uses a `switch` statement, this time based on `b.Kind`, which represents the type of basic block.
    * Notice the different block kinds like `ssa.BlockPlain`, `ssa.BlockDefer`, `ssa.BlockRet`, and various conditional branch blocks (`ssa.BlockARM64EQ`, `ssa.BlockARM64LT`, etc.).
    * See how assembly instructions are generated for different control flow scenarios: unconditional jumps (`obj.AJMP`), conditional branches (`arm64.ABEQ`, `arm64.ABNE`, etc.), function returns (`obj.ARET`), and handling defer statements.
    * Pay attention to how conditional branches are implemented based on the block's control value (`b.Controls`).
    * Observe the handling of jump tables (`ssa.BlockARM64JUMPTABLE`).

5. **Identify Helper Data Structures:**  The code defines `condBits`, `blockJump`, `leJumps`, and `gtJumps`. These are lookup tables or data structures that map SSA concepts to ARM64 assembly instructions or logic.
    * `condBits`: Maps SSA condition code operations to ARM64 special operands for conditional execution.
    * `blockJump`: Maps SSA block kinds (conditional branches) to their corresponding ARM64 branch instructions and their inverses.
    * `leJumps`, `gtJumps`:  Appear to handle specific complex branching scenarios (likely related to overflow).

6. **Identify Supporting Functions:**  `loadRegResult` and `spillArgReg` seem to deal with loading values from memory into registers and storing register values back to memory, respectively. The "arg" in `spillArgReg` suggests it deals with function arguments.

7. **Synthesize and Summarize:** Based on the analysis, start formulating the summary points:
    * **Core Functionality:**  Code generation for ARM64 architecture.
    * **Key Functions:** `genValue` (handles SSA value translation) and `ssaGenBlock` (handles control flow translation).
    * **SSA Operation Mapping:** `genValue` translates individual SSA operations to ARM64 assembly. Provide examples of the types of operations handled (arithmetic, memory access, control flow related).
    * **Control Flow Generation:** `ssaGenBlock` translates SSA basic blocks into ARM64 branch instructions, handling different control flow constructs. Mention conditional branches, unconditional jumps, function returns, and defer statements.
    * **Lookup Tables:**  Highlight the purpose of `condBits`, `blockJump`, etc., in mapping SSA concepts to assembly.
    * **Helper Functions:** Briefly explain the purpose of `loadRegResult` and `spillArgReg`.
    * **Connection to Go Features:** Infer that this code is crucial for compiling Go code to native ARM64 assembly, enabling the execution of Go programs on ARM64 systems. Mention features like function calls, defer statements, and conditional logic that are implemented through this code.

8. **Refine and Organize:** Organize the summary points logically, using clear and concise language. Group related functionalities together. Use bullet points or numbered lists for readability. Ensure the summary addresses all the key aspects identified during the analysis.

This systematic approach, focusing on understanding the code's purpose, identifying key components, and then synthesizing the findings, leads to a comprehensive and accurate summary of the provided Go code snippet.
这是 `go/src/cmd/compile/internal/arm64/ssa.go` 文件的一部分，接续了之前代码的功能。它的主要功能仍然是 **将 SSA (Static Single Assignment) 形式的中间代码转换为 ARM64 汇编指令**。

让我们归纳一下这部分代码的功能：

**1. 生成特定 SSA Value 的汇编代码 (`genValue` 函数中的部分 case 分支):**

   * **`ssa.OpARM64LoweredZeroedCallMemory`:**  将调用所需的内存区域清零。它生成一个循环，每次写入 8 个字节的零，直到达到所需的大小。
   * **`ssa.OpARM64LoweredNilCheck`:**  生成空指针检查的代码。它将一个寄存器的值加载到另一个寄存器，如果地址是无效的，将会触发异常。
   * **`ssa.OpARM64Move`:**  生成寄存器之间移动数据的指令。
   * **`ssa.OpCopy`:**  生成将一个 SSA value 的值复制到另一个 SSA value 的目标寄存器的指令。
   * **`ssa.OpSP`:**  生成获取当前栈指针的指令。
   * **`ssa.OpSB`:**  生成获取静态基址寄存器的指令。
   * **`ssa.OpLB`，`ssa.OpLW`，`ssa.OpLD`，`ssa.OpLF`，`ssa.OpLDf`:** 生成从内存加载不同大小数据的指令 (字节、字、双字、单精度浮点、双精度浮点)。
   * **`ssa.OpSTB`，`ssa.OpSTW`，`ssa.OpSTD`，`ssa.OpSTF`，`ssa.OpSTDF`:** 生成将不同大小的数据存储到内存的指令。
   * **`ssa.OpARM64MOVDconst`:**  生成将常量值加载到寄存器的指令。
   * **`ssa.OpARM64ADDRconst`:**  生成将一个地址（常量偏移量）加载到寄存器的指令。
   * **`ssa.OpARM64LoweredGetClosurePtr`:**  处理获取闭包指针的操作。
   * **`ssa.OpARM64LoweredGetCallerSP`:**  生成获取调用者栈指针的指令。
   * **`ssa.OpARM64LoweredGetCallerPC`:**  生成获取调用者程序计数器的指令。
   * **`ssa.OpARM64DMB`:**  生成数据内存屏障指令。
   * **`ssa.OpARM64FlagConstant`，`ssa.OpARM64InvertFlags`:**  这两个操作不应该出现在代码生成阶段，如果出现会触发错误。
   * **`ssa.OpClobber`:**  生成代码来覆写一段内存，通常用于调试或安全目的。它会将指定的内存区域用特定的值（0xdeaddead）填充。
   * **`ssa.OpClobberReg`:** 生成代码来覆写一个寄存器的值，也通常用于调试或安全目的。它会将寄存器设置为 0xdeaddeaddeaddead。

**2. 定义条件码 (`condBits` 变量):**

   * `condBits` 是一个 `map`，将 SSA 中的条件操作符 (例如 `ssa.OpARM64Equal`, `ssa.OpARM64LessThan`) 映射到 ARM64 汇编中的特殊操作数，用于条件分支指令。这使得在生成条件跳转指令时能够方便地查找对应的条件码。

**3. 定义块跳转指令 (`blockJump` 变量):**

   * `blockJump` 是一个 `map`，将 SSA 中的块类型 (表示不同的条件分支) 映射到 ARM64 汇编中对应的跳转指令及其反向跳转指令。例如，`ssa.BlockARM64EQ` (等于时跳转) 对应 `arm64.ABEQ` 和 `arm64.ABNE` (不等于时跳转)。

**4. 定义特殊的跳转序列 (`leJumps` 和 `gtJumps` 变量):**

   * `leJumps` 和 `gtJumps` 定义了用于模拟 "小于等于且无溢出" (`LEnoov`) 和 "大于且无溢出" (`GTnoov`) 分支的跳转指令序列。这些是更复杂的条件分支情况，需要多个汇编指令来实现。

**5. 生成 SSA Block 的汇编代码 (`ssaGenBlock` 函数):**

   * 这个函数根据 SSA Block 的类型生成相应的 ARM64 汇编代码来控制程序的执行流程。
   * **`ssa.BlockPlain`:** 生成无条件跳转到下一个 Block 的指令。
   * **`ssa.BlockDefer`:**  处理 `defer` 语句。它检查返回值，如果返回值为 0 则继续执行，否则跳转到 defer 返回的地址。
   * **`ssa.BlockExit`, `ssa.BlockRetJmp`:**  这两种类型的 Block 不需要生成额外的跳转指令。
   * **`ssa.BlockRet`:** 生成函数返回指令 (`ARET`).
   * **`ssa.BlockARM64EQ` 等条件分支 Block:** 根据 `blockJump` 中定义的指令，生成条件跳转指令。它会根据下一个要执行的 Block 是哪个 successor 来选择正向或反向的跳转指令。还会处理 `Likely` 属性来优化分支预测。
   * **`ssa.BlockARM64TBZ`, `ssa.BlockARM64TBNZ`:** 生成测试位并根据结果跳转的指令。
   * **`ssa.BlockARM64LEnoov`, `ssa.BlockARM64GTnoov`:**  使用 `leJumps` 和 `gtJumps` 中定义的指令序列来生成对应的分支代码。
   * **`ssa.BlockARM64JUMPTABLE`:**  生成跳转表的代码。它会加载跳转目标地址到临时寄存器，然后执行间接跳转。

**6. 辅助函数:**

   * **`loadRegResult`:**  生成从栈帧加载数据到寄存器的指令。
   * **`spillArgReg`:** 生成将寄存器中的函数参数存储到栈帧的指令。

**总结这部分代码的功能:**

这部分代码是 Go 编译器中 ARM64 后端代码生成的核心部分。它负责将 SSA 中间表示的计算和控制流操作转换为实际的 ARM64 汇编指令。  它通过 `genValue` 处理单个 SSA value 的转换，并使用 `ssaGenBlock` 处理程序控制流的生成，包括各种类型的条件分支、无条件跳转、函数返回以及 `defer` 语句的实现。  `condBits` 和 `blockJump` 等数据结构提供了 SSA 操作到 ARM64 指令的映射，简化了代码生成的逻辑。

**可以推理出的 Go 语言功能实现 (举例):**

* **条件语句 (if/else):**  `ssaGenBlock` 中对 `ssa.BlockARM64EQ`, `ssa.BlockARM64NE` 等 Block 类型的处理，以及 `condBits` 中条件码的定义，正是用于实现 Go 语言中的 `if/else` 语句。

   ```go
   package main

   func compare(a, b int) bool {
       if a > b {
           return true
       } else {
           return false
       }
   }

   func main() {
       compare(10, 5)
   }
   ```

   **假设的 SSA 输入 (简化):** 可能会有类似比较 `a` 和 `b` 的 SSA 操作，然后根据比较结果生成一个条件分支 Block (例如 `ssa.BlockARM64GT`)。`ssaGenBlock` 会根据这个 Block 类型生成 `ABGT` (大于时跳转) 或其反向指令。

* **循环语句 (for):** 循环语句也会被翻译成带有条件分支的 SSA Block。例如，`for` 循环的退出条件会对应一个条件分支 Block。

   ```go
   package main

   func sum(n int) int {
       s := 0
       for i := 0; i < n; i++ {
           s += i
       }
       return s
   }

   func main() {
       sum(10)
   }
   ```

   **假设的 SSA 输入 (简化):**  循环的条件 `i < n` 会生成一个比较操作和一个条件分支 Block (例如 `ssa.BlockARM64LT`)，用于判断是否继续循环。

* **函数调用和 `defer`:**  `ssa.OpARM64LoweredGetClosurePtr`、`ssa.OpARM64LoweredGetCallerSP`、`ssa.OpARM64LoweredGetCallerPC` 以及 `ssaGenBlock` 中对 `ssa.BlockDefer` 的处理，都直接关联到函数调用和 `defer` 机制的实现。

   ```go
   package main

   import "fmt"

   func foo() {
       defer fmt.Println("清理工作")
       fmt.Println("foo 被调用")
   }

   func main() {
       foo()
   }
   ```

   **假设的 SSA 输入 (简化):**  调用 `fmt.Println("清理工作")` 的 `defer` 语句会生成一个 `ssa.BlockDefer` 类型的 Block。`ssaGenBlock` 会生成相应的代码来在函数返回前执行 `defer` 语句。

* **空指针检查:** `ssa.OpARM64LoweredNilCheck` 用于实现 Go 语言中的隐式空指针检查。

   ```go
   package main

   type MyStruct struct {
       Value int
   }

   func access(s *MyStruct) int {
       return s.Value // 如果 s 是 nil，这里会触发 panic
   }

   func main() {
       var ptr *MyStruct
       // access(ptr) // 取消注释会触发 panic
   }
   ```

   **假设的 SSA 输入 (简化):**  访问 `s.Value` 之前可能会插入一个 `ssa.OpARM64LoweredNilCheck` 操作，以确保 `s` 不是 `nil`。

**命令行参数的具体处理:** 这部分代码本身不直接处理命令行参数。命令行参数的处理发生在编译器的早期阶段。这部分代码是在 SSA 生成之后，负责将 SSA 转换为特定架构的汇编代码。

**使用者易犯错的点:**  作为编译器开发者，理解 SSA 的结构和 ARM64 架构的指令集是至关重要的。常见的错误可能包括：

* **错误的指令选择:** 为某个 SSA 操作选择了不正确的 ARM64 指令。
* **寄存器分配错误:**  没有正确地管理寄存器的使用，导致数据冲突或覆盖。
* **条件码使用错误:**  在生成条件分支指令时，使用了错误的条件码。
* **内存访问错误:**  在加载或存储数据时，计算了错误的内存地址。
* **忽略了架构特定的细节:**  没有考虑到 ARM64 架构的特性，例如对齐要求或特定的指令行为。

由于这段代码是 Go 编译器内部的一部分，普通 Go 语言使用者不会直接接触到它，因此不存在普通使用者易犯错的点。只有编译器开发者在修改或扩展编译器时才需要深入理解这部分代码。

### 提示词
```
这是路径为go/src/cmd/compile/internal/arm64/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
rgs[0].Reg()
		p.To.Type = obj.TYPE_CONST
		p.To.Offset = v.AuxInt
	case ssa.OpARM64LoweredGetClosurePtr:
		// Closure pointer is R26 (arm64.REGCTXT).
		ssagen.CheckLoweredGetClosurePtr(v)
	case ssa.OpARM64LoweredGetCallerSP:
		// caller's SP is FixedFrameSize below the address of the first arg
		p := s.Prog(arm64.AMOVD)
		p.From.Type = obj.TYPE_ADDR
		p.From.Offset = -base.Ctxt.Arch.FixedFrameSize
		p.From.Name = obj.NAME_PARAM
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64LoweredGetCallerPC:
		p := s.Prog(obj.AGETCALLERPC)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	case ssa.OpARM64DMB:
		p := s.Prog(v.Op.Asm())
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = v.AuxInt
	case ssa.OpARM64FlagConstant:
		v.Fatalf("FlagConstant op should never make it to codegen %v", v.LongString())
	case ssa.OpARM64InvertFlags:
		v.Fatalf("InvertFlags should never make it to codegen %v", v.LongString())
	case ssa.OpClobber:
		// MOVW	$0xdeaddead, REGTMP
		// MOVW	REGTMP, (slot)
		// MOVW	REGTMP, 4(slot)
		p := s.Prog(arm64.AMOVW)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 0xdeaddead
		p.To.Type = obj.TYPE_REG
		p.To.Reg = arm64.REGTMP
		p = s.Prog(arm64.AMOVW)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = arm64.REGTMP
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = arm64.REGSP
		ssagen.AddAux(&p.To, v)
		p = s.Prog(arm64.AMOVW)
		p.From.Type = obj.TYPE_REG
		p.From.Reg = arm64.REGTMP
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = arm64.REGSP
		ssagen.AddAux2(&p.To, v, v.AuxInt+4)
	case ssa.OpClobberReg:
		x := uint64(0xdeaddeaddeaddead)
		p := s.Prog(arm64.AMOVD)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = int64(x)
		p.To.Type = obj.TYPE_REG
		p.To.Reg = v.Reg()
	default:
		v.Fatalf("genValue not implemented: %s", v.LongString())
	}
}

var condBits = map[ssa.Op]arm64.SpecialOperand{
	ssa.OpARM64Equal:         arm64.SPOP_EQ,
	ssa.OpARM64NotEqual:      arm64.SPOP_NE,
	ssa.OpARM64LessThan:      arm64.SPOP_LT,
	ssa.OpARM64LessThanU:     arm64.SPOP_LO,
	ssa.OpARM64LessEqual:     arm64.SPOP_LE,
	ssa.OpARM64LessEqualU:    arm64.SPOP_LS,
	ssa.OpARM64GreaterThan:   arm64.SPOP_GT,
	ssa.OpARM64GreaterThanU:  arm64.SPOP_HI,
	ssa.OpARM64GreaterEqual:  arm64.SPOP_GE,
	ssa.OpARM64GreaterEqualU: arm64.SPOP_HS,
	ssa.OpARM64LessThanF:     arm64.SPOP_MI, // Less than
	ssa.OpARM64LessEqualF:    arm64.SPOP_LS, // Less than or equal to
	ssa.OpARM64GreaterThanF:  arm64.SPOP_GT, // Greater than
	ssa.OpARM64GreaterEqualF: arm64.SPOP_GE, // Greater than or equal to

	// The following condition codes have unordered to handle comparisons related to NaN.
	ssa.OpARM64NotLessThanF:     arm64.SPOP_PL, // Greater than, equal to, or unordered
	ssa.OpARM64NotLessEqualF:    arm64.SPOP_HI, // Greater than or unordered
	ssa.OpARM64NotGreaterThanF:  arm64.SPOP_LE, // Less than, equal to or unordered
	ssa.OpARM64NotGreaterEqualF: arm64.SPOP_LT, // Less than or unordered

	ssa.OpARM64LessThanNoov:     arm64.SPOP_MI, // Less than but without honoring overflow
	ssa.OpARM64GreaterEqualNoov: arm64.SPOP_PL, // Greater than or equal to but without honoring overflow
}

var blockJump = map[ssa.BlockKind]struct {
	asm, invasm obj.As
}{
	ssa.BlockARM64EQ:     {arm64.ABEQ, arm64.ABNE},
	ssa.BlockARM64NE:     {arm64.ABNE, arm64.ABEQ},
	ssa.BlockARM64LT:     {arm64.ABLT, arm64.ABGE},
	ssa.BlockARM64GE:     {arm64.ABGE, arm64.ABLT},
	ssa.BlockARM64LE:     {arm64.ABLE, arm64.ABGT},
	ssa.BlockARM64GT:     {arm64.ABGT, arm64.ABLE},
	ssa.BlockARM64ULT:    {arm64.ABLO, arm64.ABHS},
	ssa.BlockARM64UGE:    {arm64.ABHS, arm64.ABLO},
	ssa.BlockARM64UGT:    {arm64.ABHI, arm64.ABLS},
	ssa.BlockARM64ULE:    {arm64.ABLS, arm64.ABHI},
	ssa.BlockARM64Z:      {arm64.ACBZ, arm64.ACBNZ},
	ssa.BlockARM64NZ:     {arm64.ACBNZ, arm64.ACBZ},
	ssa.BlockARM64ZW:     {arm64.ACBZW, arm64.ACBNZW},
	ssa.BlockARM64NZW:    {arm64.ACBNZW, arm64.ACBZW},
	ssa.BlockARM64TBZ:    {arm64.ATBZ, arm64.ATBNZ},
	ssa.BlockARM64TBNZ:   {arm64.ATBNZ, arm64.ATBZ},
	ssa.BlockARM64FLT:    {arm64.ABMI, arm64.ABPL},
	ssa.BlockARM64FGE:    {arm64.ABGE, arm64.ABLT},
	ssa.BlockARM64FLE:    {arm64.ABLS, arm64.ABHI},
	ssa.BlockARM64FGT:    {arm64.ABGT, arm64.ABLE},
	ssa.BlockARM64LTnoov: {arm64.ABMI, arm64.ABPL},
	ssa.BlockARM64GEnoov: {arm64.ABPL, arm64.ABMI},
}

// To model a 'LEnoov' ('<=' without overflow checking) branching.
var leJumps = [2][2]ssagen.IndexJump{
	{{Jump: arm64.ABEQ, Index: 0}, {Jump: arm64.ABPL, Index: 1}}, // next == b.Succs[0]
	{{Jump: arm64.ABMI, Index: 0}, {Jump: arm64.ABEQ, Index: 0}}, // next == b.Succs[1]
}

// To model a 'GTnoov' ('>' without overflow checking) branching.
var gtJumps = [2][2]ssagen.IndexJump{
	{{Jump: arm64.ABMI, Index: 1}, {Jump: arm64.ABEQ, Index: 1}}, // next == b.Succs[0]
	{{Jump: arm64.ABEQ, Index: 1}, {Jump: arm64.ABPL, Index: 0}}, // next == b.Succs[1]
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
		// defer returns in R0:
		// 0 if we should continue executing
		// 1 if we should jump to deferreturn call
		p := s.Prog(arm64.ACMP)
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = 0
		p.Reg = arm64.REG_R0
		p = s.Prog(arm64.ABNE)
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

	case ssa.BlockARM64EQ, ssa.BlockARM64NE,
		ssa.BlockARM64LT, ssa.BlockARM64GE,
		ssa.BlockARM64LE, ssa.BlockARM64GT,
		ssa.BlockARM64ULT, ssa.BlockARM64UGT,
		ssa.BlockARM64ULE, ssa.BlockARM64UGE,
		ssa.BlockARM64Z, ssa.BlockARM64NZ,
		ssa.BlockARM64ZW, ssa.BlockARM64NZW,
		ssa.BlockARM64FLT, ssa.BlockARM64FGE,
		ssa.BlockARM64FLE, ssa.BlockARM64FGT,
		ssa.BlockARM64LTnoov, ssa.BlockARM64GEnoov:
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
	case ssa.BlockARM64TBZ, ssa.BlockARM64TBNZ:
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
		p.From.Offset = b.AuxInt
		p.From.Type = obj.TYPE_CONST
		p.Reg = b.Controls[0].Reg()

	case ssa.BlockARM64LEnoov:
		s.CombJump(b, next, &leJumps)
	case ssa.BlockARM64GTnoov:
		s.CombJump(b, next, &gtJumps)

	case ssa.BlockARM64JUMPTABLE:
		// MOVD	(TABLE)(IDX<<3), Rtmp
		// JMP	(Rtmp)
		p := s.Prog(arm64.AMOVD)
		p.From = genIndexedOperand(ssa.OpARM64MOVDloadidx8, b.Controls[1].Reg(), b.Controls[0].Reg())
		p.To.Type = obj.TYPE_REG
		p.To.Reg = arm64.REGTMP
		p = s.Prog(obj.AJMP)
		p.To.Type = obj.TYPE_MEM
		p.To.Reg = arm64.REGTMP
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