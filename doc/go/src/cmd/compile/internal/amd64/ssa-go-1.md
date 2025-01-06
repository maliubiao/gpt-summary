Response:
Let's break down the thought process to arrive at the summary of the provided Go code snippet.

1. **Initial Reading and Keyword Identification:** The first step is to read through the code and identify key functions, data structures, and operations. Words like `ssa`, `obj.Prog`, `x86`, `opregreg`, `ssagen`, `duffzero`, `duffcopy`, `CALL`, `MOV`, `CMP`, `JMP`, `atomic`, `prefetch`, and the various `ssa.OpAMD64...` and `ssa.BlockAMD64...` constants immediately jump out. These provide hints about the code's purpose.

2. **High-Level Goal Deduction:**  The file path `go/src/cmd/compile/internal/amd64/ssa.go` strongly suggests this code is part of the Go compiler, specifically dealing with the AMD64 architecture and Single Static Assignment (SSA) form. This implies the code is involved in translating SSA instructions into actual machine code instructions for AMD64 processors.

3. **Function-Specific Analysis:** Now, examine each function:

    * **`genValue(s *ssagen.State, v *ssa.Value)`:** This function takes an SSA value (`v`) and a state object (`s`). The `switch v.Op` statement suggests it's handling different types of SSA operations. The calls to `s.Prog()` to create `obj.Prog` instances (which represent assembly instructions) are a major clue. The different `case` blocks within the `switch` correspond to specific AMD64 instructions or higher-level SSA concepts.

    * **`ssaGenBlock(s *ssagen.State, b, next *ssa.Block)`:** This function deals with SSA blocks (`b`). The `switch b.Kind` suggests it's handling different control flow structures. The creation of jump instructions (`obj.AJMP`, `x86.AJEQ`, etc.) indicates it's responsible for generating code for branching and control flow.

    * **`loadRegResult(...)` and `spillArgReg(...)`:** These functions appear to be related to moving data between registers and memory (stack). `loadRegResult` loads from memory to a register, and `spillArgReg` stores from a register to memory. The context suggests these are used for handling function arguments and return values.

4. **Categorization of Operations:**  As you analyze `genValue`, group the operations by their apparent function:

    * **Data Movement:** `OpCopy`, `OpLoadReg`, `OpStoreReg`, various `MOV` instructions.
    * **Arithmetic/Logical:** `NEG`, `NOT`, `BSWAP`, `POPCNT`, `TZCNT`, `LZCNT`, etc.
    * **Comparisons/Conditional Sets:** `SETEQ`, `SETNE`, `SETL`, etc.
    * **Control Flow:** `DUFFZERO`, `DUFFCOPY`, `CALL`, `RET`.
    * **Atomic Operations:** `XCHG`, `XADD`, `CMPXCHG`, `ANDBlock`, `ORBlock`, `LoweredAtomicAnd/Or`.
    * **Special Operations:** `LoweredHasCPUFeature`, `LoweredGetClosurePtr`, `LoweredGetG`, `LoweredWB`, `LoweredPanicBounds`, `LoweredNilCheck`, `Prefetch`, `Clobber`, `ClobberReg`.

5. **Inferring Go Feature Implementations:** Based on the identified operations, try to connect them to higher-level Go features:

    * **`DUFFZERO`/`DUFFCOPY`:**  These are clearly optimized implementations for zeroing and copying memory, respectively, likely used for `make([]byte, size)` or `copy()` operations.
    * **`CALLstatic`/`CALLclosure`/`CALLinter`:** These are the different ways functions are called in Go (direct call, closure call, interface method call).
    * **`LoweredGetClosurePtr`:**  This is how a closure accesses its captured variables.
    * **`LoweredGetG`:** Accessing the Go runtime's `g` (goroutine) structure.
    * **`LoweredWB`:** Write barrier for the garbage collector.
    * **`LoweredPanicBounds`:** Implementing bounds checks for array/slice access.
    * **Atomic operations:** Implementing `sync/atomic` package functions.
    * **`LoweredNilCheck`:**  Automatic nil pointer checks.

6. **Analyzing `ssaGenBlock`:** This function directly translates SSA block kinds into jump instructions. The `blockJump` array maps SSA block types to their corresponding assembly jump instructions. This reinforces the idea that this part of the code is responsible for control flow.

7. **Synthesizing the Summary:**  Combine the observations into a concise summary. Start with the high-level purpose (code generation for AMD64). Then elaborate on the key responsibilities: translating SSA values and blocks into assembly instructions, handling different Go language features, and managing control flow. Mention the specific examples like function calls, memory operations, atomic operations, and runtime interactions.

8. **Refining the Language:** Ensure the summary is clear, accurate, and uses appropriate terminology (like "SSA," "assembly instructions," "code generation").

This systematic approach of reading, identifying keywords, analyzing functions, categorizing operations, and connecting them to Go features allows for a comprehensive understanding and summarization of the provided code snippet.
这是对Go编译器中AMD64架构的SSA代码生成部分（第2部分）的总结。

**总体功能归纳:**

这段代码是Go编译器将中间表示形式（SSA，静态单赋值）转换为AMD64汇编指令的关键部分。它定义了如何将各种SSA操作和控制流块翻译成具体的AMD64机器指令。

**具体功能分解:**

1. **处理SSA值 (genValue 函数):**
   - `genValue` 函数是核心，它根据 SSA `Value` 的操作码 (`v.Op`) 生成相应的AMD64汇编指令。
   - 它处理了大量的SSA操作码，涵盖了：
     - **数据移动:**  例如 `OpCopy` (寄存器到寄存器拷贝), `OpLoadReg` (从内存加载到寄存器), `OpStoreReg` (从寄存器存储到内存)。
     - **算术和逻辑运算:** 例如 `OpAMD64NEGQ` (取负), `OpAMD64NOTL` (按位取反), `OpAMD64ADDQ` (加法), `OpAMD64XORL` (异或) 等。
     - **比较和条件设置:** 例如 `OpAMD64SETEQ` (如果相等则设置字节), `OpAMD64SETNE` (如果不相等则设置字节) 等。
     - **函数调用:** 例如 `OpAMD64CALLstatic` (静态调用), `OpAMD64CALLclosure` (闭包调用), `OpAMD64CALLinter` (接口调用)。
     - **内存操作:** 例如 `OpAMD64MOVQstore` (存储), 以及 `DUFFZERO` 和 `DUFFCOPY` 优化的大块内存清零和拷贝。
     - **原子操作:**  例如 `OpAMD64XCHGB` (交换字节), `OpAMD64XADDLlock` (原子加), `OpAMD64CMPXCHGQlock` (原子比较并交换) 等。
     - **特殊操作:** 例如 `OpAMD64LoweredGetClosurePtr` (获取闭包指针), `OpAMD64LoweredGetG` (获取goroutine的g结构体指针), `OpAMD64LoweredNilCheck` (空指针检查),  `OpAMD64LoweredWB` (写屏障)。
     - **浮点数操作:** 例如 `OpAMD64SQRTSD` (平方根), `OpAMD64ROUNDSD` (舍入)。
     - **位操作:** 例如 `OpAMD64BSFQ` (位扫描正向), `OpAMD64POPCNTQ` (计算设置的位数)。

2. **处理SSA块 (ssaGenBlock 函数):**
   - `ssaGenBlock` 函数负责根据 SSA `Block` 的类型 (`b.Kind`) 生成控制流相关的汇编指令。
   - 它处理了各种控制流块，包括：
     - **普通块 (`ssa.BlockPlain`):** 生成无条件跳转。
     - **延迟块 (`ssa.BlockDefer`):** 生成检查defer返回值并跳转的指令。
     - **返回块 (`ssa.BlockRet`):** 生成 `RET` 指令。
     - **条件跳转块:** 例如 `ssa.BlockAMD64EQ` (相等跳转), `ssa.BlockAMD64NE` (不相等跳转), `ssa.BlockAMD64LT` (小于跳转) 等。它会根据目标块和下一个块的关系选择合适的跳转指令。
     - **跳转表块 (`ssa.BlockAMD64JUMPTABLE`):** 生成间接跳转指令，用于实现 `switch` 语句。

3. **辅助函数:**
   - `loadRegResult`: 生成从栈帧加载函数返回值到寄存器的指令。
   - `spillArgReg`: 生成将寄存器中的参数值存储到栈帧的指令。

**Go语言功能的实现推断和代码示例:**

基于代码中的操作码，可以推断出它实现了以下Go语言功能：

* **函数调用和返回:** `OpAMD64CALLstatic`, `OpAMD64CALLclosure`, `OpAMD64CALLinter`, `ssa.BlockRet` 明显与函数调用和返回相关。
  ```go
  package main

  func add(a, b int) int {
      return a + b
  }

  func main() {
      result := add(3, 5)
      println(result)
  }
  ```
  这段代码中的 `add(3, 5)` 调用会涉及到 `OpAMD64CALLstatic` 的代码生成。`return a + b` 会涉及到将返回值移动到指定寄存器的操作。

* **内存操作 (例如切片和映射):** `DUFFZERO` 和 `DUFFCOPY` 是优化的内存清零和拷贝，常用于切片的初始化和复制。
  ```go
  package main

  func main() {
      s := make([]byte, 1024) // 可能会使用 DUFFZERO 来清零
      t := make([]byte, len(s))
      copy(t, s) // 可能会使用 DUFFCOPY 来拷贝
      println(len(t))
  }
  ```

* **原子操作 (sync/atomic 包):** `OpAMD64XCHGB`, `OpAMD64XADDLlock`, `OpAMD64CMPXCHGQlock` 对应 `sync/atomic` 包提供的原子操作。
  ```go
  package main

  import "sync/atomic"

  func main() {
      var counter int64
      atomic.AddInt64(&counter, 1)
      println(atomic.LoadInt64(&counter))
  }
  ```
  `atomic.AddInt64` 可能会涉及到 `OpAMD64XADDQlock` 指令的生成。

* **闭包:** `OpAMD64LoweredGetClosurePtr` 用于获取闭包捕获的变量。
  ```go
  package main

  func makeAdder(x int) func(int) int {
      return func(y int) int {
          return x + y // 这里需要访问外部变量 x
      }
  }

  func main() {
      add5 := makeAdder(5)
      println(add5(3))
  }
  ```
  在 `return func(y int) int { ... }` 中访问 `x` 时，编译器可能会使用 `OpAMD64LoweredGetClosurePtr` 来获取包含 `x` 的闭包结构体的指针。

* **defer 语句:** `ssa.BlockDefer` 处理 `defer` 语句的实现。
  ```go
  package main

  import "fmt"

  func example() {
      defer fmt.Println("清理工作")
      fmt.Println("函数执行中")
  }

  func main() {
      example()
  }
  ```
  `defer fmt.Println("清理工作")` 会导致在函数返回前执行 `fmt.Println("清理工作")`，这由 `ssa.BlockDefer` 生成相应的指令来实现。

* **goroutine 的管理:** `OpAMD64LoweredGetG` 用于获取当前 goroutine 的 `g` 结构体，这是 Go 运行时管理 goroutine 的核心数据结构。

* **空指针检查:** `OpAMD64LoweredNilCheck` 用于实现自动的空指针检查。
  ```go
  package main

  func main() {
      var p *int
      // if p != nil { // 编译器可能会插入 nil check
      //    println(*p)
      // }
      _ = *p // 这里如果 p 是 nil，会触发 panic
  }
  ```
  访问 `*p` 时，编译器可能会在底层插入 `OpAMD64LoweredNilCheck` 相关的指令。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理发生在编译器的更上层。但是，编译器的某些命令行参数会影响代码生成过程。例如：

* **`-gcflags`:**  可以传递参数来控制编译器的行为，例如禁用某些优化，这可能会影响生成的汇编代码。
* **`-race`:** 启用竞态检测会引入额外的代码来监控内存访问，这会影响生成的汇编指令，例如会使用更严格的原子操作。
* **`-buildmode=...`:**  不同的构建模式（例如 `exe`, `shared`)  会影响最终生成的可执行文件或共享库的结构，间接影响代码生成的一些细节。

**使用者易犯错的点:**

由于这段代码是编译器内部实现，直接的 Go 语言使用者不会直接与之交互，因此不存在使用者易犯错的点。 开发者在修改编译器代码时需要非常小心，理解每个操作码和块的含义，避免引入错误的代码生成逻辑。

**总结第2部分的功能:**

作为 `go/src/cmd/compile/internal/amd64/ssa.go` 的第二部分，这段代码延续了将SSA中间表示转换为AMD64汇编指令的过程。它涵盖了更广泛的SSA操作码和控制流块，包括函数调用、内存操作（尤其是优化的 `DUFFZERO` 和 `DUFFCOPY`）、原子操作、闭包实现、goroutine 管理、空指针检查等关键的Go语言特性。结合第1部分，这两部分代码共同构成了AMD64架构下Go代码生成的核心逻辑。它保证了Go程序的高效执行，并为Go语言的各种高级特性提供了底层的机器指令实现。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/amd64/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
2].Reg()
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

"""




```