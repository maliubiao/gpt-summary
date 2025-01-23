Response:
Let's break down the thought process for analyzing this Go code snippet and fulfilling the request.

**1. Initial Understanding & Goal Identification:**

The request asks for the functionality of the provided Go code (`go/src/cmd/compile/internal/ssagen/ssa.go`). It also specifies focusing on a particular part (part 8 of 8). Key requirements are listing functionalities, inferring Go language features implemented, providing Go code examples (with input/output where relevant), explaining command-line argument handling, highlighting potential user errors, and summarizing the overall function.

**2. Deconstructing the Code - Identifying Key Functions and Data Structures:**

The first step is to read through the code and identify the main functions and data structures. I noticed:

* **`compileFunctions` (from surrounding context):**  The initial lines with `func compileFunctions` and the `for` loop iterating through `fns` suggest this code is part of a larger process that compiles multiple functions.
* **`compileSSA`:** This function is the core of the provided snippet. It takes a `State`, `ssafn`, and `ssa.Func` as arguments. This strongly indicates it's responsible for generating machine code (or assembly) from the SSA representation of a function.
* **`ssa.Func`:**  This is an SSA (Static Single Assignment) function representation, a common intermediate representation in compilers.
* **`State`:**  Seems to hold the overall state of the compilation process.
* **`ssafn`:** Appears to hold function-specific information needed during code generation.
* **`defframe`:**  Deals with setting up the function's stack frame.
* **`IndexJump`, `oneJump`, `CombJump`:** Related to generating jump instructions, possibly for complex control flow.
* **`AddAux`, `AddAux2`:**  Manipulating `obj.Addr` structures, likely for addressing memory locations.
* **`extendIndex`:** Handling index values, possibly for array/slice access and bounds checking.
* **`CheckLoweredPhi`, `CheckLoweredGetClosurePtr`, `CheckArgReg`:**  Assertion functions for verifying assumptions during code generation.
* **`AddrAuto`:** Creating an `obj.Addr` for local variables.
* **`Call`, `TailCall`, `PrepareCall`:**  Generating code for function calls.
* **`UseArgs`:**  Tracking the maximum argument size for a function call.
* **`fieldIdx`:**  Calculating the index of a struct field.
* **`StringData`:**  Managing string literals.
* **`SplitSlot`:**  Dealing with splitting stack slots.
* **`Logf`, `Log`, `Fatalf`, `Warnl`, `Debug_checknil`, `UseWriteBarrier`, `Syslook`, `Func`:**  Utility functions for logging, error reporting, and accessing compiler settings.
* **`clobberBase`:**  Simplifying expressions, likely for optimization.
* **`callTargetLSym`:** Determining the correct symbol to call a function.
* **`deferstruct`:**  Defining the structure of a `defer` object.
* **`SpillSlotAddr`:** Calculating the address of a spilled register.

**3. Inferring Go Features and Generating Examples:**

Based on the identified functions, I could infer the Go features being implemented:

* **Function Calls:**  `Call`, `TailCall`, `PrepareCall` are directly related to function calls.
* **Stack Management:** `defframe`, `SpillSlotAddr`, `SplitSlot` are involved in setting up and managing the function's stack frame.
* **String Literals:** `StringData` handles string constants.
* **Struct Field Access:** `fieldIdx` is used for accessing fields within structs.
* **`defer` Statements:** `deferstruct` indicates handling of `defer` statements.
* **Bounds Checking:** `extendIndex` and the presence of `BoundsCheckFunc` suggest implementation of array/slice bounds checking.
* **Control Flow (Jumps):** `IndexJump`, `oneJump`, `CombJump` are about generating jump instructions for `if`, `for`, and `switch` statements.
* **Closures:** `CheckLoweredGetClosurePtr` hints at support for closures.
* **Function Arguments:** `CheckArgReg` and the discussion in `defframe` about spilling argument registers show how function arguments are handled.

For each inferred feature, I tried to create a simple Go code example illustrating it. For instance, for function calls, a basic function calling another function suffices. For `defer`, a simple `defer` statement is enough. The goal was clarity and directness.

**4. Identifying Potential User Errors:**

I looked for patterns that might lead to programmer mistakes:

* **Incorrect `defer` Usage:**  The explanation around `deferstruct` and the potential for the compiler's internal structure to change led to the "incorrect assumptions about `defer` implementation" error.
* **Manual Stack Manipulation (Hypothetical):** While not directly in the code, the functions dealing with stack frames suggested the danger of manual stack manipulation in assembly, which is generally discouraged.

**5. Analyzing Command-Line Argument Handling:**

I scanned the code for references to `base.Flag`. This package likely handles command-line flags for the Go compiler. I then looked for specific flags used in the snippet:

* `base.Flag.N`:  Related to optimizations (disabling optimizations).
* `base.Flag.B`:  Related to bounds checking.
* `base.Flag.WB`:  Related to write barriers in the garbage collector.
* `base.Debug.Nil`:  Related to nil pointer checks.

I described how these flags influence the code generation process.

**6. Summarizing the Functionality:**

Finally, I synthesized the individual functionalities into a concise summary, highlighting the core role of this code in the SSA-to-machine-code translation within the Go compiler.

**7. Iteration and Refinement:**

Throughout the process, I would reread the code and my explanations to ensure accuracy and clarity. I might rephrase sentences or add more detail where needed. For example, initially, I might just say "handles function calls," but then refine it to mention the different types of calls (`CALL`, `TAILCALL`) and the `PrepareCall` step.

This systematic approach of deconstruction, inference, example generation, error analysis, command-line flag identification, and summarization helped in thoroughly understanding the provided Go code snippet and fulfilling the requirements of the request.
这是 `go/src/cmd/compile/internal/ssagen/ssa.go` 文件的第 8 部分，该文件负责将 Go 程序的 SSA (Static Single Assignment) 中间表示转换为目标机器的汇编代码。

**该部分的功能归纳:**

这部分代码主要包含了 `compileSSA` 函数的结尾部分以及一些辅助函数，这些函数负责完成以下任务：

1. **完成函数汇编的生成:** `compileSSA` 函数的结尾部分负责输出生成的汇编代码到文件，并进行一些清理工作。
2. **处理函数栈帧:** `defframe` 函数计算并设置函数的栈帧大小，并插入代码来清零可能包含垃圾回收需要扫描的指针的栈内存区域。
3. **生成复杂的跳转指令:** `IndexJump`, `oneJump`, `CombJump` 用于生成基于索引的跳转指令，可以模拟更复杂的条件分支行为。
4. **处理地址寻址:** `AddAux`, `AddAux2` 用于向 `obj.Addr` 结构体添加偏移量和符号信息，用于访问内存中的变量和函数。
5. **处理索引值扩展和边界检查:** `extendIndex` 函数用于将索引值扩展到合适的宽度，并插入必要的边界检查代码。
6. **进行代码正确性检查:** `CheckLoweredPhi`, `CheckLoweredGetClosurePtr`, `CheckArgReg` 等函数用于在编译过程中进行断言检查，确保代码生成的正确性。
7. **生成局部变量的地址:** `AddrAuto` 函数用于生成局部变量在栈上的地址。
8. **生成函数调用指令:** `Call`, `TailCall`, `PrepareCall` 函数用于生成函数调用指令，并处理与函数调用相关的簿记工作，例如记录栈映射信息。
9. **记录函数调用参数大小:** `UseArgs` 函数用于记录函数调用时需要的最大参数空间。
10. **计算结构体字段索引:** `fieldIdx` 函数用于查找结构体字段的索引。
11. **提供编译期间的辅助信息:** `ssafn` 结构体存储了函数相关的编译信息，并提供了一些工具函数，如获取字符串数据的符号、记录日志等。
12. **处理 `defer` 语句:** `deferstruct` 函数定义了 `defer` 结构体的类型。
13. **生成溢出槽的地址:** `SpillSlotAddr` 函数用于生成寄存器溢出到栈上的位置的地址。

**推理 Go 语言功能的实现并举例说明:**

通过分析代码，可以推断出这部分代码涉及到以下 Go 语言功能的实现：

1. **函数调用 (Function Calls):** `Call` 和 `TailCall` 明显用于生成普通函数调用和尾调用的汇编指令。
   ```go
   package main

   import "fmt"

   func add(a, b int) int {
       return a + b
   }

   func main() {
       result := add(5, 3) // 普通函数调用
       fmt.Println(result)
   }
   ```
   * **假设输入:** 上述 Go 代码。
   * **推理输出:** `compileSSA` 中 `s.Call(v)` 会被调用，`v` 代表 `add(5, 3)` 这个调用。生成的汇编代码会包含 `ACALL` 指令，指向 `add` 函数的符号地址。

2. **`defer` 语句 (Defer Statements):** `deferstruct` 函数定义了 `runtime._defer` 结构体的布局，这与 `defer` 语句的实现密切相关。
   ```go
   package main

   import "fmt"

   func exampleDefer() {
       defer fmt.Println("Deferred message")
       fmt.Println("Main function")
   }

   func main() {
       exampleDefer()
   }
   ```
   * **推理输出:** 编译器会创建 `_defer` 结构体实例，并将 `fmt.Println("Deferred message")` 的相关信息（函数地址等）存储到该结构体中。在 `exampleDefer` 函数返回前，会执行 `defer` 注册的函数。

3. **结构体字段访问 (Struct Field Access):** `fieldIdx` 函数用于计算结构体字段的偏移量。
   ```go
   package main

   import "fmt"

   type Point struct {
       X int
       Y int
   }

   func main() {
       p := Point{X: 10, Y: 20}
       fmt.Println(p.X) // 访问结构体字段 X
   }
   ```
   * **推理输出:** 当访问 `p.X` 时，编译器会调用 `fieldIdx` 来确定 `X` 字段在 `Point` 结构体中的偏移量，然后生成相应的汇编代码来访问该内存地址。

4. **局部变量 (Local Variables):** `AddrAuto` 函数用于获取局部变量在栈上的地址。
   ```go
   package main

   import "fmt"

   func main() {
       x := 5
       fmt.Println(x)
   }
   ```
   * **推理输出:** 编译器会将局部变量 `x` 分配到栈上，并使用 `AddrAuto` 生成访问 `x` 的内存地址。生成的汇编代码会使用栈指针 (SP) 加上一定的偏移量来访问 `x`。

5. **边界检查 (Bounds Checking):** `extendIndex` 函数处理索引值的扩展，并可能插入边界检查代码。
   ```go
   package main

   import "fmt"

   func main() {
       arr := [3]int{1, 2, 3}
       index := 2
       fmt.Println(arr[index])
   }
   ```
   * **假设输入:** 编译时启用了边界检查 (`-gcflags=-B`)。
   * **推理输出:** 当访问 `arr[index]` 时，`extendIndex` 可能会被调用来确保 `index` 在数组的有效范围内。如果启用了边界检查，则会生成额外的汇编代码来比较 `index` 和数组的长度，并在越界时触发 panic。

**命令行参数的具体处理:**

代码中提到了 `base.Flag` 和 `base.Debug`，这通常用于处理 Go 编译器的命令行参数。

* **`base.Flag.N == 0`:**  这个条件判断通常与禁用优化有关。当 `-N` 命令行参数被使用时，`base.Flag.N` 会被设置为非零值，从而跳过某些优化相关的代码，例如在 `defframe` 中对参数寄存器的溢出处理。
* **`base.Flag.B != 0`:** 这个条件判断通常与启用边界检查有关。当使用 `-gcflags=-B` 编译时，`base.Flag.B` 会被设置为非零值，导致 `extendIndex` 函数中生成更多的边界检查代码。
* **`base.Flag.WB`:**  这个标志可能与启用写屏障 (Write Barrier) 有关，写屏障是垃圾回收机制的一部分。
* **`base.Debug.Nil != 0`:** 这个条件判断可能与启用 nil 指针检查的调试模式有关。

**使用者易犯错的点:**

这部分代码是 Go 编译器内部的实现细节，普通 Go 开发者通常不会直接与之交互。但是，理解这些内部机制可以帮助开发者避免一些性能陷阱或理解某些行为的原因。

一个可能的 “易犯错的点” （更多是理解上的）：**对 `defer` 语句的实现细节的误解**。`deferstruct` 函数揭示了 `defer` 语句是通过创建 `_defer` 结构体并在函数返回时执行相关函数来实现的。如果开发者错误地认为 `defer` 是零成本的或具有其他实现方式，可能会影响他们对代码性能的预期。例如，在循环中使用大量的 `defer` 可能会导致性能问题，因为每个 `defer` 都会增加开销。

**总结 `compileSSA` 的功能 (结合所有 8 部分):**

`compileSSA` 函数是 Go 编译器中将 SSA 中间表示转换为目标机器汇编代码的核心函数。它遍历 SSA 函数中的每个基本块和值，根据操作类型生成相应的汇编指令。

**综合所有 8 部分来看，`compileSSA` 的主要功能包括:**

1. **初始化编译状态:** 设置编译所需的各种数据结构和上下文信息。
2. **处理函数序言:** 生成函数入口处的汇编代码，包括保存寄存器、分配栈帧等。
3. **遍历 SSA 基本块和值:** 按照控制流顺序处理函数中的每个基本块和其中的每个 SSA 值。
4. **为每个 SSA 值生成汇编代码:**  根据 SSA 值的操作类型 (例如，算术运算、内存访问、函数调用等) 生成对应的汇编指令。这涉及到选择合适的机器指令、分配寄存器、计算内存地址等。
5. **处理控制流:** 生成跳转指令 (包括条件跳转和无条件跳转) 来实现代码的控制流，例如 `if` 语句、循环、`switch` 语句等。
6. **处理函数调用:** 生成函数调用和返回的汇编代码，包括参数传递、保存返回地址等。
7. **处理特殊操作:** 生成与垃圾回收、`defer` 语句、`panic` 和 `recover` 等 Go 语言特性相关的汇编代码。
8. **进行代码优化:**  在生成汇编代码的过程中，可能会进行一些简单的优化，例如常量折叠、死代码消除等。
9. **输出汇编代码:** 将生成的汇编代码输出到文件。
10. **处理函数尾声:** 生成函数退出前的汇编代码，包括恢复寄存器、释放栈帧、执行 `defer` 语句等。

总而言之，`compileSSA` 函数是 Go 编译器代码生成阶段的关键组成部分，它负责将高级的、平台无关的 SSA 表示转换为可以直接在目标机器上执行的低级汇编代码。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssagen/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第8部分，共8部分，请归纳一下它的功能
```

### 源代码
```go
s = b.String()
				} else {
					s = "   " // most value and branch strings are 2-3 characters long
				}
				fmt.Fprintf(fi, " %-6s\t%.5d %s\t%s\n", s, p.Pc, ssa.StmtString(p.Pos), p.InstructionString())
			}
			fi.Close()
		}
	}

	defframe(&s, e, f)

	f.HTMLWriter.Close()
	f.HTMLWriter = nil
}

func defframe(s *State, e *ssafn, f *ssa.Func) {
	pp := s.pp

	s.maxarg = types.RoundUp(s.maxarg, e.stkalign)
	frame := s.maxarg + e.stksize
	if Arch.PadFrame != nil {
		frame = Arch.PadFrame(frame)
	}

	// Fill in argument and frame size.
	pp.Text.To.Type = obj.TYPE_TEXTSIZE
	pp.Text.To.Val = int32(types.RoundUp(f.OwnAux.ArgWidth(), int64(types.RegSize)))
	pp.Text.To.Offset = frame

	p := pp.Text

	// Insert code to spill argument registers if the named slot may be partially
	// live. That is, the named slot is considered live by liveness analysis,
	// (because a part of it is live), but we may not spill all parts into the
	// slot. This can only happen with aggregate-typed arguments that are SSA-able
	// and not address-taken (for non-SSA-able or address-taken arguments we always
	// spill upfront).
	// Note: spilling is unnecessary in the -N/no-optimize case, since all values
	// will be considered non-SSAable and spilled up front.
	// TODO(register args) Make liveness more fine-grained to that partial spilling is okay.
	if f.OwnAux.ABIInfo().InRegistersUsed() != 0 && base.Flag.N == 0 {
		// First, see if it is already spilled before it may be live. Look for a spill
		// in the entry block up to the first safepoint.
		type nameOff struct {
			n   *ir.Name
			off int64
		}
		partLiveArgsSpilled := make(map[nameOff]bool)
		for _, v := range f.Entry.Values {
			if v.Op.IsCall() {
				break
			}
			if v.Op != ssa.OpStoreReg || v.Args[0].Op != ssa.OpArgIntReg {
				continue
			}
			n, off := ssa.AutoVar(v)
			if n.Class != ir.PPARAM || n.Addrtaken() || !ssa.CanSSA(n.Type()) || !s.partLiveArgs[n] {
				continue
			}
			partLiveArgsSpilled[nameOff{n, off}] = true
		}

		// Then, insert code to spill registers if not already.
		for _, a := range f.OwnAux.ABIInfo().InParams() {
			n := a.Name
			if n == nil || n.Addrtaken() || !ssa.CanSSA(n.Type()) || !s.partLiveArgs[n] || len(a.Registers) <= 1 {
				continue
			}
			rts, offs := a.RegisterTypesAndOffsets()
			for i := range a.Registers {
				if !rts[i].HasPointers() {
					continue
				}
				if partLiveArgsSpilled[nameOff{n, offs[i]}] {
					continue // already spilled
				}
				reg := ssa.ObjRegForAbiReg(a.Registers[i], f.Config)
				p = Arch.SpillArgReg(pp, p, f, rts[i], reg, n, offs[i])
			}
		}
	}

	// Insert code to zero ambiguously live variables so that the
	// garbage collector only sees initialized values when it
	// looks for pointers.
	var lo, hi int64

	// Opaque state for backend to use. Current backends use it to
	// keep track of which helper registers have been zeroed.
	var state uint32

	// Iterate through declarations. Autos are sorted in decreasing
	// frame offset order.
	for _, n := range e.curfn.Dcl {
		if !n.Needzero() {
			continue
		}
		if n.Class != ir.PAUTO {
			e.Fatalf(n.Pos(), "needzero class %d", n.Class)
		}
		if n.Type().Size()%int64(types.PtrSize) != 0 || n.FrameOffset()%int64(types.PtrSize) != 0 || n.Type().Size() == 0 {
			e.Fatalf(n.Pos(), "var %L has size %d offset %d", n, n.Type().Size(), n.Offset_)
		}

		if lo != hi && n.FrameOffset()+n.Type().Size() >= lo-int64(2*types.RegSize) {
			// Merge with range we already have.
			lo = n.FrameOffset()
			continue
		}

		// Zero old range
		p = Arch.ZeroRange(pp, p, frame+lo, hi-lo, &state)

		// Set new range.
		lo = n.FrameOffset()
		hi = lo + n.Type().Size()
	}

	// Zero final range.
	Arch.ZeroRange(pp, p, frame+lo, hi-lo, &state)
}

// For generating consecutive jump instructions to model a specific branching
type IndexJump struct {
	Jump  obj.As
	Index int
}

func (s *State) oneJump(b *ssa.Block, jump *IndexJump) {
	p := s.Br(jump.Jump, b.Succs[jump.Index].Block())
	p.Pos = b.Pos
}

// CombJump generates combinational instructions (2 at present) for a block jump,
// thereby the behaviour of non-standard condition codes could be simulated
func (s *State) CombJump(b, next *ssa.Block, jumps *[2][2]IndexJump) {
	switch next {
	case b.Succs[0].Block():
		s.oneJump(b, &jumps[0][0])
		s.oneJump(b, &jumps[0][1])
	case b.Succs[1].Block():
		s.oneJump(b, &jumps[1][0])
		s.oneJump(b, &jumps[1][1])
	default:
		var q *obj.Prog
		if b.Likely != ssa.BranchUnlikely {
			s.oneJump(b, &jumps[1][0])
			s.oneJump(b, &jumps[1][1])
			q = s.Br(obj.AJMP, b.Succs[1].Block())
		} else {
			s.oneJump(b, &jumps[0][0])
			s.oneJump(b, &jumps[0][1])
			q = s.Br(obj.AJMP, b.Succs[0].Block())
		}
		q.Pos = b.Pos
	}
}

// AddAux adds the offset in the aux fields (AuxInt and Aux) of v to a.
func AddAux(a *obj.Addr, v *ssa.Value) {
	AddAux2(a, v, v.AuxInt)
}
func AddAux2(a *obj.Addr, v *ssa.Value, offset int64) {
	if a.Type != obj.TYPE_MEM && a.Type != obj.TYPE_ADDR {
		v.Fatalf("bad AddAux addr %v", a)
	}
	// add integer offset
	a.Offset += offset

	// If no additional symbol offset, we're done.
	if v.Aux == nil {
		return
	}
	// Add symbol's offset from its base register.
	switch n := v.Aux.(type) {
	case *ssa.AuxCall:
		a.Name = obj.NAME_EXTERN
		a.Sym = n.Fn
	case *obj.LSym:
		a.Name = obj.NAME_EXTERN
		a.Sym = n
	case *ir.Name:
		if n.Class == ir.PPARAM || (n.Class == ir.PPARAMOUT && !n.IsOutputParamInRegisters()) {
			a.Name = obj.NAME_PARAM
		} else {
			a.Name = obj.NAME_AUTO
		}
		a.Sym = n.Linksym()
		a.Offset += n.FrameOffset()
	default:
		v.Fatalf("aux in %s not implemented %#v", v, v.Aux)
	}
}

// extendIndex extends v to a full int width.
// panic with the given kind if v does not fit in an int (only on 32-bit archs).
func (s *state) extendIndex(idx, len *ssa.Value, kind ssa.BoundsKind, bounded bool) *ssa.Value {
	size := idx.Type.Size()
	if size == s.config.PtrSize {
		return idx
	}
	if size > s.config.PtrSize {
		// truncate 64-bit indexes on 32-bit pointer archs. Test the
		// high word and branch to out-of-bounds failure if it is not 0.
		var lo *ssa.Value
		if idx.Type.IsSigned() {
			lo = s.newValue1(ssa.OpInt64Lo, types.Types[types.TINT], idx)
		} else {
			lo = s.newValue1(ssa.OpInt64Lo, types.Types[types.TUINT], idx)
		}
		if bounded || base.Flag.B != 0 {
			return lo
		}
		bNext := s.f.NewBlock(ssa.BlockPlain)
		bPanic := s.f.NewBlock(ssa.BlockExit)
		hi := s.newValue1(ssa.OpInt64Hi, types.Types[types.TUINT32], idx)
		cmp := s.newValue2(ssa.OpEq32, types.Types[types.TBOOL], hi, s.constInt32(types.Types[types.TUINT32], 0))
		if !idx.Type.IsSigned() {
			switch kind {
			case ssa.BoundsIndex:
				kind = ssa.BoundsIndexU
			case ssa.BoundsSliceAlen:
				kind = ssa.BoundsSliceAlenU
			case ssa.BoundsSliceAcap:
				kind = ssa.BoundsSliceAcapU
			case ssa.BoundsSliceB:
				kind = ssa.BoundsSliceBU
			case ssa.BoundsSlice3Alen:
				kind = ssa.BoundsSlice3AlenU
			case ssa.BoundsSlice3Acap:
				kind = ssa.BoundsSlice3AcapU
			case ssa.BoundsSlice3B:
				kind = ssa.BoundsSlice3BU
			case ssa.BoundsSlice3C:
				kind = ssa.BoundsSlice3CU
			}
		}
		b := s.endBlock()
		b.Kind = ssa.BlockIf
		b.SetControl(cmp)
		b.Likely = ssa.BranchLikely
		b.AddEdgeTo(bNext)
		b.AddEdgeTo(bPanic)

		s.startBlock(bPanic)
		mem := s.newValue4I(ssa.OpPanicExtend, types.TypeMem, int64(kind), hi, lo, len, s.mem())
		s.endBlock().SetControl(mem)
		s.startBlock(bNext)

		return lo
	}

	// Extend value to the required size
	var op ssa.Op
	if idx.Type.IsSigned() {
		switch 10*size + s.config.PtrSize {
		case 14:
			op = ssa.OpSignExt8to32
		case 18:
			op = ssa.OpSignExt8to64
		case 24:
			op = ssa.OpSignExt16to32
		case 28:
			op = ssa.OpSignExt16to64
		case 48:
			op = ssa.OpSignExt32to64
		default:
			s.Fatalf("bad signed index extension %s", idx.Type)
		}
	} else {
		switch 10*size + s.config.PtrSize {
		case 14:
			op = ssa.OpZeroExt8to32
		case 18:
			op = ssa.OpZeroExt8to64
		case 24:
			op = ssa.OpZeroExt16to32
		case 28:
			op = ssa.OpZeroExt16to64
		case 48:
			op = ssa.OpZeroExt32to64
		default:
			s.Fatalf("bad unsigned index extension %s", idx.Type)
		}
	}
	return s.newValue1(op, types.Types[types.TINT], idx)
}

// CheckLoweredPhi checks that regalloc and stackalloc correctly handled phi values.
// Called during ssaGenValue.
func CheckLoweredPhi(v *ssa.Value) {
	if v.Op != ssa.OpPhi {
		v.Fatalf("CheckLoweredPhi called with non-phi value: %v", v.LongString())
	}
	if v.Type.IsMemory() {
		return
	}
	f := v.Block.Func
	loc := f.RegAlloc[v.ID]
	for _, a := range v.Args {
		if aloc := f.RegAlloc[a.ID]; aloc != loc { // TODO: .Equal() instead?
			v.Fatalf("phi arg at different location than phi: %v @ %s, but arg %v @ %s\n%s\n", v, loc, a, aloc, v.Block.Func)
		}
	}
}

// CheckLoweredGetClosurePtr checks that v is the first instruction in the function's entry block,
// except for incoming in-register arguments.
// The output of LoweredGetClosurePtr is generally hardwired to the correct register.
// That register contains the closure pointer on closure entry.
func CheckLoweredGetClosurePtr(v *ssa.Value) {
	entry := v.Block.Func.Entry
	if entry != v.Block {
		base.Fatalf("in %s, badly placed LoweredGetClosurePtr: %v %v", v.Block.Func.Name, v.Block, v)
	}
	for _, w := range entry.Values {
		if w == v {
			break
		}
		switch w.Op {
		case ssa.OpArgIntReg, ssa.OpArgFloatReg:
			// okay
		default:
			base.Fatalf("in %s, badly placed LoweredGetClosurePtr: %v %v", v.Block.Func.Name, v.Block, v)
		}
	}
}

// CheckArgReg ensures that v is in the function's entry block.
func CheckArgReg(v *ssa.Value) {
	entry := v.Block.Func.Entry
	if entry != v.Block {
		base.Fatalf("in %s, badly placed ArgIReg or ArgFReg: %v %v", v.Block.Func.Name, v.Block, v)
	}
}

func AddrAuto(a *obj.Addr, v *ssa.Value) {
	n, off := ssa.AutoVar(v)
	a.Type = obj.TYPE_MEM
	a.Sym = n.Linksym()
	a.Reg = int16(Arch.REGSP)
	a.Offset = n.FrameOffset() + off
	if n.Class == ir.PPARAM || (n.Class == ir.PPARAMOUT && !n.IsOutputParamInRegisters()) {
		a.Name = obj.NAME_PARAM
	} else {
		a.Name = obj.NAME_AUTO
	}
}

// Call returns a new CALL instruction for the SSA value v.
// It uses PrepareCall to prepare the call.
func (s *State) Call(v *ssa.Value) *obj.Prog {
	pPosIsStmt := s.pp.Pos.IsStmt() // The statement-ness fo the call comes from ssaGenState
	s.PrepareCall(v)

	p := s.Prog(obj.ACALL)
	if pPosIsStmt == src.PosIsStmt {
		p.Pos = v.Pos.WithIsStmt()
	} else {
		p.Pos = v.Pos.WithNotStmt()
	}
	if sym, ok := v.Aux.(*ssa.AuxCall); ok && sym.Fn != nil {
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = sym.Fn
	} else {
		// TODO(mdempsky): Can these differences be eliminated?
		switch Arch.LinkArch.Family {
		case sys.AMD64, sys.I386, sys.PPC64, sys.RISCV64, sys.S390X, sys.Wasm:
			p.To.Type = obj.TYPE_REG
		case sys.ARM, sys.ARM64, sys.Loong64, sys.MIPS, sys.MIPS64:
			p.To.Type = obj.TYPE_MEM
		default:
			base.Fatalf("unknown indirect call family")
		}
		p.To.Reg = v.Args[0].Reg()
	}
	return p
}

// TailCall returns a new tail call instruction for the SSA value v.
// It is like Call, but for a tail call.
func (s *State) TailCall(v *ssa.Value) *obj.Prog {
	p := s.Call(v)
	p.As = obj.ARET
	return p
}

// PrepareCall prepares to emit a CALL instruction for v and does call-related bookkeeping.
// It must be called immediately before emitting the actual CALL instruction,
// since it emits PCDATA for the stack map at the call (calls are safe points).
func (s *State) PrepareCall(v *ssa.Value) {
	idx := s.livenessMap.Get(v)
	if !idx.StackMapValid() {
		// See Liveness.hasStackMap.
		if sym, ok := v.Aux.(*ssa.AuxCall); !ok || !(sym.Fn == ir.Syms.WBZero || sym.Fn == ir.Syms.WBMove) {
			base.Fatalf("missing stack map index for %v", v.LongString())
		}
	}

	call, ok := v.Aux.(*ssa.AuxCall)

	if ok {
		// Record call graph information for nowritebarrierrec
		// analysis.
		if nowritebarrierrecCheck != nil {
			nowritebarrierrecCheck.recordCall(s.pp.CurFunc, call.Fn, v.Pos)
		}
	}

	if s.maxarg < v.AuxInt {
		s.maxarg = v.AuxInt
	}
}

// UseArgs records the fact that an instruction needs a certain amount of
// callee args space for its use.
func (s *State) UseArgs(n int64) {
	if s.maxarg < n {
		s.maxarg = n
	}
}

// fieldIdx finds the index of the field referred to by the ODOT node n.
func fieldIdx(n *ir.SelectorExpr) int {
	t := n.X.Type()
	if !t.IsStruct() {
		panic("ODOT's LHS is not a struct")
	}

	for i, f := range t.Fields() {
		if f.Sym == n.Sel {
			if f.Offset != n.Offset() {
				panic("field offset doesn't match")
			}
			return i
		}
	}
	panic(fmt.Sprintf("can't find field in expr %v\n", n))

	// TODO: keep the result of this function somewhere in the ODOT Node
	// so we don't have to recompute it each time we need it.
}

// ssafn holds frontend information about a function that the backend is processing.
// It also exports a bunch of compiler services for the ssa backend.
type ssafn struct {
	curfn      *ir.Func
	strings    map[string]*obj.LSym // map from constant string to data symbols
	stksize    int64                // stack size for current frame
	stkptrsize int64                // prefix of stack containing pointers

	// alignment for current frame.
	// NOTE: when stkalign > PtrSize, currently this only ensures the offsets of
	// objects in the stack frame are aligned. The stack pointer is still aligned
	// only PtrSize.
	stkalign int64

	log bool // print ssa debug to the stdout
}

// StringData returns a symbol which
// is the data component of a global string constant containing s.
func (e *ssafn) StringData(s string) *obj.LSym {
	if aux, ok := e.strings[s]; ok {
		return aux
	}
	if e.strings == nil {
		e.strings = make(map[string]*obj.LSym)
	}
	data := staticdata.StringSym(e.curfn.Pos(), s)
	e.strings[s] = data
	return data
}

// SplitSlot returns a slot representing the data of parent starting at offset.
func (e *ssafn) SplitSlot(parent *ssa.LocalSlot, suffix string, offset int64, t *types.Type) ssa.LocalSlot {
	node := parent.N

	if node.Class != ir.PAUTO || node.Addrtaken() {
		// addressed things and non-autos retain their parents (i.e., cannot truly be split)
		return ssa.LocalSlot{N: node, Type: t, Off: parent.Off + offset}
	}

	sym := &types.Sym{Name: node.Sym().Name + suffix, Pkg: types.LocalPkg}
	n := e.curfn.NewLocal(parent.N.Pos(), sym, t)
	n.SetUsed(true)
	n.SetEsc(ir.EscNever)
	types.CalcSize(t)
	return ssa.LocalSlot{N: n, Type: t, Off: 0, SplitOf: parent, SplitOffset: offset}
}

// Logf logs a message from the compiler.
func (e *ssafn) Logf(msg string, args ...interface{}) {
	if e.log {
		fmt.Printf(msg, args...)
	}
}

func (e *ssafn) Log() bool {
	return e.log
}

// Fatalf reports a compiler error and exits.
func (e *ssafn) Fatalf(pos src.XPos, msg string, args ...interface{}) {
	base.Pos = pos
	nargs := append([]interface{}{ir.FuncName(e.curfn)}, args...)
	base.Fatalf("'%s': "+msg, nargs...)
}

// Warnl reports a "warning", which is usually flag-triggered
// logging output for the benefit of tests.
func (e *ssafn) Warnl(pos src.XPos, fmt_ string, args ...interface{}) {
	base.WarnfAt(pos, fmt_, args...)
}

func (e *ssafn) Debug_checknil() bool {
	return base.Debug.Nil != 0
}

func (e *ssafn) UseWriteBarrier() bool {
	return base.Flag.WB
}

func (e *ssafn) Syslook(name string) *obj.LSym {
	switch name {
	case "goschedguarded":
		return ir.Syms.Goschedguarded
	case "writeBarrier":
		return ir.Syms.WriteBarrier
	case "wbZero":
		return ir.Syms.WBZero
	case "wbMove":
		return ir.Syms.WBMove
	case "cgoCheckMemmove":
		return ir.Syms.CgoCheckMemmove
	case "cgoCheckPtrWrite":
		return ir.Syms.CgoCheckPtrWrite
	}
	e.Fatalf(src.NoXPos, "unknown Syslook func %v", name)
	return nil
}

func (e *ssafn) Func() *ir.Func {
	return e.curfn
}

func clobberBase(n ir.Node) ir.Node {
	if n.Op() == ir.ODOT {
		n := n.(*ir.SelectorExpr)
		if n.X.Type().NumFields() == 1 {
			return clobberBase(n.X)
		}
	}
	if n.Op() == ir.OINDEX {
		n := n.(*ir.IndexExpr)
		if n.X.Type().IsArray() && n.X.Type().NumElem() == 1 {
			return clobberBase(n.X)
		}
	}
	return n
}

// callTargetLSym returns the correct LSym to call 'callee' using its ABI.
func callTargetLSym(callee *ir.Name) *obj.LSym {
	if callee.Func == nil {
		// TODO(austin): This happens in case of interface method I.M from imported package.
		// It's ABIInternal, and would be better if callee.Func was never nil and we didn't
		// need this case.
		return callee.Linksym()
	}

	return callee.LinksymABI(callee.Func.ABI)
}

// deferStructFnField is the field index of _defer.fn.
const deferStructFnField = 4

var deferType *types.Type

// deferstruct returns a type interchangeable with runtime._defer.
// Make sure this stays in sync with runtime/runtime2.go:_defer.
func deferstruct() *types.Type {
	if deferType != nil {
		return deferType
	}

	makefield := func(name string, t *types.Type) *types.Field {
		sym := (*types.Pkg)(nil).Lookup(name)
		return types.NewField(src.NoXPos, sym, t)
	}

	fields := []*types.Field{
		makefield("heap", types.Types[types.TBOOL]),
		makefield("rangefunc", types.Types[types.TBOOL]),
		makefield("sp", types.Types[types.TUINTPTR]),
		makefield("pc", types.Types[types.TUINTPTR]),
		// Note: the types here don't really matter. Defer structures
		// are always scanned explicitly during stack copying and GC,
		// so we make them uintptr type even though they are real pointers.
		makefield("fn", types.Types[types.TUINTPTR]),
		makefield("link", types.Types[types.TUINTPTR]),
		makefield("head", types.Types[types.TUINTPTR]),
	}
	if name := fields[deferStructFnField].Sym.Name; name != "fn" {
		base.Fatalf("deferStructFnField is %q, not fn", name)
	}

	n := ir.NewDeclNameAt(src.NoXPos, ir.OTYPE, ir.Pkgs.Runtime.Lookup("_defer"))
	typ := types.NewNamed(n)
	n.SetType(typ)
	n.SetTypecheck(1)

	// build struct holding the above fields
	typ.SetUnderlying(types.NewStruct(fields))
	types.CalcStructSize(typ)

	deferType = typ
	return typ
}

// SpillSlotAddr uses LocalSlot information to initialize an obj.Addr
// The resulting addr is used in a non-standard context -- in the prologue
// of a function, before the frame has been constructed, so the standard
// addressing for the parameters will be wrong.
func SpillSlotAddr(spill ssa.Spill, baseReg int16, extraOffset int64) obj.Addr {
	return obj.Addr{
		Name:   obj.NAME_NONE,
		Type:   obj.TYPE_MEM,
		Reg:    baseReg,
		Offset: spill.Offset + extraOffset,
	}
}

var (
	BoundsCheckFunc [ssa.BoundsKindCount]*obj.LSym
	ExtendCheckFunc [ssa.BoundsKindCount]*obj.LSym
)
```