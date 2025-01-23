Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for the functionality of the provided Go code snippet, which is part of the SSA code generation phase in the Go compiler. It also requests explanations, examples, and potential pitfalls. Crucially, it's the *seventh* part of an eight-part series, so I need to summarize the function's overall role within the broader context.

2. **Identify the Key Function:** The most prominent function in the provided snippet is `genssa`. The code within `genssa` is responsible for iterating through the SSA representation of a function and generating machine code instructions.

3. **Break Down `genssa` Functionality:** I'll go through the code within `genssa` and identify its major steps:

    * **Initialization:** Creating a `State` struct, gathering liveness information, emitting argument and wrapper function info.
    * **Block Iteration:**  Looping through the basic blocks of the SSA function.
    * **Value Iteration:**  Looping through the values (instructions) within each block.
    * **Instruction Generation:** Calling `Arch.SSAGenValue` to generate machine code for each SSA value. This is a critical part handled by the architecture-specific backend.
    * **Control Flow Generation:** Calling `Arch.SSAGenBlock` to generate branch instructions at the end of each block.
    * **Inline Mark Handling:** Processing inline markers to aid debugging.
    * **Location List Generation:**  Generating debugging information to map machine code back to source code.
    * **Branch and Jump Table Resolution:**  Fixing up branch targets and jump table entries.
    * **Outputting Generated Code:**  Optionally logging the generated assembly or writing it to an HTML file for debugging.

4. **Infer Overall Functionality:** Based on the breakdown, the primary function of `genssa` and the surrounding code is to translate the *architecture-independent* SSA representation into *architecture-specific* machine code instructions. This is a crucial step in the compilation process.

5. **Address Specific Requests:**

    * **List Functionalities:** I'll list the major steps identified in the breakdown above.
    * **Infer Go Language Feature:** The code extensively deals with interface type assertions and inlining. I'll choose type assertions as a concrete example.
    * **Go Code Example (Type Assertion):**  I'll provide a simple Go function with a type assertion.
    * **Code Reasoning (Type Assertion):** I'll explain how the provided snippet handles the `ssa.OpAssertI2I` and `ssa.OpAssertI2T` operations, highlighting the cache lookup for interface-to-interface assertions and the direct comparison for interface-to-concrete-type assertions. I'll include hypothetical input (an interface value and a target type) and the expected output (the asserted value and a boolean indicating success).
    * **Command-Line Parameters:** I'll mention the relevant `-d=ssa/gen=N` flag for debugging.
    * **Common Mistakes:** The snippet itself doesn't directly expose user-facing code, but potential compiler bugs could arise if the generated code is incorrect. I'll give an example of an incorrect type assertion.
    * **Summarize Functionality (Part 7 of 8):** I'll emphasize that this part focuses on the core translation of SSA to machine code, handling details like instruction generation, control flow, and debugging information.

6. **Structure the Answer:**  I'll organize the answer clearly with headings for each part of the request. I'll use code blocks for the Go example and ensure the language is precise and easy to understand.

7. **Refine and Review:** I'll reread my answer to ensure it accurately reflects the code's functionality, addresses all aspects of the request, and is well-organized and easy to follow. I'll check for any inconsistencies or areas where the explanation could be clearer. For instance, initially, I might focus too much on the low-level details of individual SSA operations. I'll refine it to explain the broader purpose. I'll also ensure the "part 7 of 8" summary provides the necessary context.
这是 `go/src/cmd/compile/internal/ssagen/ssa.go` 文件的一部分，主要负责将静态单赋值（SSA）形式的中间代码转换为目标机器的汇编代码。 这是第 7 部分，让我们来归纳一下这部分代码的主要功能：

**主要功能归纳:**

这部分代码是 `genssa` 函数的核心，负责遍历 SSA 函数中的每个基本块和每个值（指令），并将其转换为目标架构的汇编指令。  它做了以下关键的事情：

1. **初始化状态:**  初始化 `State` 结构体，其中包含了生成汇编代码所需的各种信息，例如 ABI 信息、程序计数器、分支信息、以及用于存储临时变量的映射。

2. **处理基本块:** 遍历 SSA 函数中的每个基本块。在每个基本块的开始，它会设置当前的代码位置，并根据需要插入对齐指令 (`APCALIGNMAX`)，尤其针对 PGO 优化的热点循环头部。

3. **处理 SSA 值 (指令):**  遍历每个基本块中的 SSA 值（指令）。
    * **跳过特定操作:** 对于一些不需要生成实际代码的 SSA 操作（例如 `OpInitMem`, `OpArg`, `OpSP`, `OpSB`, `OpSelect` 系列, `OpGetG`, `OpVarDef`, `OpVarLive`, `OpKeepAlive`, `OpWBend`, `OpPhi`, `OpConvert`），它会直接跳过。
    * **处理内联标记 (`OpInlMark`):**  对于内联标记，它会插入一个 NOP 指令，并记录内联信息，用于调试。它会尝试重用已有的指令作为内联标记，以减少生成的代码量。
    * **生成目标代码:**  对于其他需要生成代码的 SSA 操作，它会调用架构相关的 `Arch.SSAGenValue(&s, v)` 函数来生成对应的汇编指令。

4. **处理控制流:**  在每个基本块的末尾，它会调用架构相关的 `Arch.SSAGenBlock(&s, b, next)` 函数来生成控制流指令，例如跳转到下一个基本块或条件分支。

5. **处理函数尾声:** 对于以 `ssa.BlockExit` 结尾的函数，它会添加一个 NOP 指令，以确保 panic 调用的返回地址仍然在该函数内部。

6. **处理开放编码的 defer:** 如果函数使用了开放编码的 defer，它会生成一个对 `deferreturn` 函数的调用和一个 `RET` 指令，用于在 panic 恢复时返回到运行时。

7. **处理内联信息:**  在生成完所有指令后，它会处理收集到的内联标记信息，将它们添加到函数的内联树中。 对于无栈帧的叶子函数，它会确保第一个指令不是来自内联调用者，以保证 `runtime.FuncForPC` 的正确性。

8. **生成调试信息 (Location Lists):** 如果启用了位置列表功能，它会调用 `ssa.BuildFuncDebug` 或 `ssa.BuildFuncDebugNoOptimized` 来生成调试信息，将 SSA 的值和基本块映射到生成的汇编指令。

9. **解析分支和跳转表:**  解析之前记录的分支指令，将它们的跳转目标设置为对应基本块的起始地址。 对于跳转表，它会将目标基本块转换为目标汇编指令的地址。

10. **输出生成的代码 (可选):** 如果启用了日志记录或 HTML 输出，它会将生成的汇编代码以及对应的 SSA 值和基本块信息输出到控制台或 HTML 文件中，用于调试。

**推理 Go 语言功能的实现 (涉及代码推理):**

从代码中可以看出，这部分主要在处理将高级的控制流结构（例如 `if`, `for`, `switch`）和操作（例如类型断言）转换为底层的汇编指令。  让我们重点关注 **类型断言** 的实现：

在 `genssa` 函数中，可以看到对 `ssa.OpAssertI2I` 和 `ssa.OpAssertI2T` 的处理最终会调用 `s.assertE2I` 函数。 这部分代码实现了接口类型断言的功能。

**Go 代码示例 (类型断言):**

```go
package main

import "fmt"

type MyInterface interface {
	GetName() string
}

type MyStruct struct {
	Name string
}

func (m MyStruct) GetName() string {
	return m.Name
}

func main() {
	var i MyInterface = MyStruct{Name: "Hello"}

	// 接口到接口的类型断言
	if concreteI, ok := i.(interface{ GetName() string }); ok {
		fmt.Println("Interface assertion:", concreteI.GetName())
	}

	// 接口到具体类型的类型断言
	if concreteS, ok := i.(MyStruct); ok {
		fmt.Println("Concrete type assertion:", concreteS.Name)
	}
}
```

**代码推理 (类型断言):**

假设输入的 SSA 代码中包含一个类型断言操作，例如将一个接口类型的变量 `iface` 断言为 `MyStruct` 类型，并且带有 `comma-ok` 语法（即 `value, ok := iface.(MyStruct)`）。

**假设输入 (SSA):**

假设 `iface` 是一个接口类型的 SSA 值，`target` 是 `MyStruct` 类型的 SSA 值。

**`s.assertE2I` 函数中的关键逻辑 (简化):**

* **接口到接口 (`ssa.OpAssertI2I`):** 这部分代码会尝试从一个缓存中查找是否已经有相同的接口类型断言结果。 如果找到，则直接加载缓存的结果。 如果没有找到，则会调用运行时函数进行类型断言。
* **接口到具体类型 (`ssa.OpAssertI2T`):**  这部分代码会直接比较接口的类型信息 (`itab`) 和目标类型的类型信息 (`targetItab`)。 如果匹配，则从接口的数据部分加载数据。 如果不匹配，则根据是否使用了 `comma-ok` 语法，会发生 panic 或返回零值和 `false`。

**假设输出 (SSA):**

* 如果断言成功，则会生成一个表示 `MyStruct` 类型值的 SSA 值和一个表示 `true` 的 SSA 值。
* 如果断言失败且使用了 `comma-ok`，则会生成一个 `MyStruct` 类型的零值和一个表示 `false` 的 SSA 值。
* 如果断言失败且没有使用 `comma-ok`，则会生成一个调用 `panicdottype` 或 `panicdottypeE` 的 SSA 指令。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。 命令行参数的处理通常发生在编译器的前端和主流程中。  但是，代码中使用了 `base.Debug.TypeAssert > 0` 和 `ssa.GenssaDump[f.Name]` 这样的条件，这些标志很可能受到命令行参数的影响。

例如，使用 `-d=ssa/gen=函数名` 这样的命令行参数可能会启用 `ssa.GenssaDump`，从而使 `genssa` 函数输出生成的汇编代码。  `base.Debug.TypeAssert` 可能受到类似 `-d=typeassert=1` 这样的参数控制。

**使用者易犯错的点:**

作为编译器开发者，可能犯错的点包括：

* **生成的汇编代码不正确:**  例如，对于复杂的 SSA 操作，生成的汇编指令可能没有正确地实现其语义，导致运行时错误。
* **处理边界情况不当:**  例如，对于空接口的类型断言或 nil 接口的类型断言，可能没有正确处理。
* **生成的调试信息不准确:**  如果生成的调试信息（例如位置列表）不正确，会导致调试器无法正确地将汇编代码映射回源代码。
* **性能问题:**  生成的汇编代码效率不高，例如存在不必要的内存访问或寄存器溢出。

**总结 `genssa` 的功能 (针对第 7 部分):**

总的来说，这部分 `genssa` 函数的主要职责是将 SSA 中间表示的核心指令和控制流结构转换为目标架构的实际汇编代码。 它处理了各种 SSA 操作，包括类型断言、内存访问、算术运算等，并生成相应的机器指令。 同时，它还负责生成必要的调试信息，以便在调试时能够将生成的代码与源代码关联起来。 这是代码生成过程中的一个关键阶段。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssagen/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```go
sa.OpLoad, typs.Uintptr, cache, s.mem())
				// Jump to loop head.
				b := s.endBlock()
				b.AddEdgeTo(loopHead)

				// At loop head, get pointer to the cache entry.
				//   e := &cache.Entries[hash&mask]
				s.startBlock(loopHead)
				idx := s.newValue2(and, typs.Uintptr, s.variable(hashVar, typs.Uintptr), mask)
				idx = s.newValue2(mul, typs.Uintptr, idx, s.uintptrConstant(uint64(2*s.config.PtrSize)))
				idx = s.newValue2(add, typs.Uintptr, idx, s.uintptrConstant(uint64(s.config.PtrSize)))
				e := s.newValue2(ssa.OpAddPtr, typs.UintptrPtr, cache, idx)
				//   hash++
				s.vars[hashVar] = s.newValue2(add, typs.Uintptr, s.variable(hashVar, typs.Uintptr), s.uintptrConstant(1))

				// Look for a cache hit.
				//   if e.Typ == typ { goto hit }
				eTyp := s.newValue2(ssa.OpLoad, typs.Uintptr, e, s.mem())
				cmp1 := s.newValue2(ssa.OpEqPtr, typs.Bool, typ, eTyp)
				b = s.endBlock()
				b.Kind = ssa.BlockIf
				b.SetControl(cmp1)
				b.AddEdgeTo(cacheHit)
				b.AddEdgeTo(loopBody)

				// Look for an empty entry, the tombstone for this hash table.
				//   if e.Typ == nil { goto miss }
				s.startBlock(loopBody)
				cmp2 := s.newValue2(ssa.OpEqPtr, typs.Bool, eTyp, s.constNil(typs.BytePtr))
				b = s.endBlock()
				b.Kind = ssa.BlockIf
				b.SetControl(cmp2)
				b.AddEdgeTo(cacheMiss)
				b.AddEdgeTo(loopHead)

				// On a hit, load the data fields of the cache entry.
				//   Itab = e.Itab
				s.startBlock(cacheHit)
				eItab := s.newValue2(ssa.OpLoad, typs.BytePtr, s.newValue1I(ssa.OpOffPtr, typs.BytePtrPtr, s.config.PtrSize, e), s.mem())
				s.vars[typVar] = eItab
				b = s.endBlock()
				b.AddEdgeTo(bMerge)

				// On a miss, call into the runtime to get the answer.
				s.startBlock(cacheMiss)
			}
		}

		// Call into runtime to get itab for result.
		if descriptor != nil {
			itab = s.rtcall(ir.Syms.TypeAssert, true, []*types.Type{byteptr}, d, typ)[0]
		} else {
			var fn *obj.LSym
			if commaok {
				fn = ir.Syms.AssertE2I2
			} else {
				fn = ir.Syms.AssertE2I
			}
			itab = s.rtcall(fn, true, []*types.Type{byteptr}, target, typ)[0]
		}
		s.vars[typVar] = itab
		b = s.endBlock()
		b.AddEdgeTo(bMerge)

		// Build resulting interface.
		s.startBlock(bMerge)
		itab = s.variable(typVar, byteptr)
		var ok *ssa.Value
		if commaok {
			ok = s.newValue2(ssa.OpNeqPtr, types.Types[types.TBOOL], itab, s.constNil(byteptr))
		}
		return s.newValue2(ssa.OpIMake, dst, itab, data), ok
	}

	if base.Debug.TypeAssert > 0 {
		base.WarnfAt(pos, "type assertion inlined")
	}

	// Converting to a concrete type.
	direct := types.IsDirectIface(dst)
	itab := s.newValue1(ssa.OpITab, byteptr, iface) // type word of interface
	if base.Debug.TypeAssert > 0 {
		base.WarnfAt(pos, "type assertion inlined")
	}
	var wantedFirstWord *ssa.Value
	if src.IsEmptyInterface() {
		// Looking for pointer to target type.
		wantedFirstWord = target
	} else {
		// Looking for pointer to itab for target type and source interface.
		wantedFirstWord = targetItab
	}

	var tmp ir.Node     // temporary for use with large types
	var addr *ssa.Value // address of tmp
	if commaok && !ssa.CanSSA(dst) {
		// unSSAable type, use temporary.
		// TODO: get rid of some of these temporaries.
		tmp, addr = s.temp(pos, dst)
	}

	cond := s.newValue2(ssa.OpEqPtr, types.Types[types.TBOOL], itab, wantedFirstWord)
	b := s.endBlock()
	b.Kind = ssa.BlockIf
	b.SetControl(cond)
	b.Likely = ssa.BranchLikely

	bOk := s.f.NewBlock(ssa.BlockPlain)
	bFail := s.f.NewBlock(ssa.BlockPlain)
	b.AddEdgeTo(bOk)
	b.AddEdgeTo(bFail)

	if !commaok {
		// on failure, panic by calling panicdottype
		s.startBlock(bFail)
		taddr := source
		if taddr == nil {
			taddr = s.reflectType(src)
		}
		if src.IsEmptyInterface() {
			s.rtcall(ir.Syms.PanicdottypeE, false, nil, itab, target, taddr)
		} else {
			s.rtcall(ir.Syms.PanicdottypeI, false, nil, itab, target, taddr)
		}

		// on success, return data from interface
		s.startBlock(bOk)
		if direct {
			return s.newValue1(ssa.OpIData, dst, iface), nil
		}
		p := s.newValue1(ssa.OpIData, types.NewPtr(dst), iface)
		return s.load(dst, p), nil
	}

	// commaok is the more complicated case because we have
	// a control flow merge point.
	bEnd := s.f.NewBlock(ssa.BlockPlain)
	// Note that we need a new valVar each time (unlike okVar where we can
	// reuse the variable) because it might have a different type every time.
	valVar := ssaMarker("val")

	// type assertion succeeded
	s.startBlock(bOk)
	if tmp == nil {
		if direct {
			s.vars[valVar] = s.newValue1(ssa.OpIData, dst, iface)
		} else {
			p := s.newValue1(ssa.OpIData, types.NewPtr(dst), iface)
			s.vars[valVar] = s.load(dst, p)
		}
	} else {
		p := s.newValue1(ssa.OpIData, types.NewPtr(dst), iface)
		s.move(dst, addr, p)
	}
	s.vars[okVar] = s.constBool(true)
	s.endBlock()
	bOk.AddEdgeTo(bEnd)

	// type assertion failed
	s.startBlock(bFail)
	if tmp == nil {
		s.vars[valVar] = s.zeroVal(dst)
	} else {
		s.zero(dst, addr)
	}
	s.vars[okVar] = s.constBool(false)
	s.endBlock()
	bFail.AddEdgeTo(bEnd)

	// merge point
	s.startBlock(bEnd)
	if tmp == nil {
		res = s.variable(valVar, dst)
		delete(s.vars, valVar) // no practical effect, just to indicate typVar is no longer live.
	} else {
		res = s.load(dst, addr)
	}
	resok = s.variable(okVar, types.Types[types.TBOOL])
	delete(s.vars, okVar) // ditto
	return res, resok
}

// temp allocates a temp of type t at position pos
func (s *state) temp(pos src.XPos, t *types.Type) (*ir.Name, *ssa.Value) {
	tmp := typecheck.TempAt(pos, s.curfn, t)
	if t.HasPointers() || (ssa.IsMergeCandidate(tmp) && t != deferstruct()) {
		s.vars[memVar] = s.newValue1A(ssa.OpVarDef, types.TypeMem, tmp, s.mem())
	}
	addr := s.addr(tmp)
	return tmp, addr
}

// variable returns the value of a variable at the current location.
func (s *state) variable(n ir.Node, t *types.Type) *ssa.Value {
	v := s.vars[n]
	if v != nil {
		return v
	}
	v = s.fwdVars[n]
	if v != nil {
		return v
	}

	if s.curBlock == s.f.Entry {
		// No variable should be live at entry.
		s.f.Fatalf("value %v (%v) incorrectly live at entry", n, v)
	}
	// Make a FwdRef, which records a value that's live on block input.
	// We'll find the matching definition as part of insertPhis.
	v = s.newValue0A(ssa.OpFwdRef, t, fwdRefAux{N: n})
	s.fwdVars[n] = v
	if n.Op() == ir.ONAME {
		s.addNamedValue(n.(*ir.Name), v)
	}
	return v
}

func (s *state) mem() *ssa.Value {
	return s.variable(memVar, types.TypeMem)
}

func (s *state) addNamedValue(n *ir.Name, v *ssa.Value) {
	if n.Class == ir.Pxxx {
		// Don't track our marker nodes (memVar etc.).
		return
	}
	if ir.IsAutoTmp(n) {
		// Don't track temporary variables.
		return
	}
	if n.Class == ir.PPARAMOUT {
		// Don't track named output values.  This prevents return values
		// from being assigned too early. See #14591 and #14762. TODO: allow this.
		return
	}
	loc := ssa.LocalSlot{N: n, Type: n.Type(), Off: 0}
	values, ok := s.f.NamedValues[loc]
	if !ok {
		s.f.Names = append(s.f.Names, &loc)
		s.f.CanonicalLocalSlots[loc] = &loc
	}
	s.f.NamedValues[loc] = append(values, v)
}

// Branch is an unresolved branch.
type Branch struct {
	P *obj.Prog  // branch instruction
	B *ssa.Block // target
}

// State contains state needed during Prog generation.
type State struct {
	ABI obj.ABI

	pp *objw.Progs

	// Branches remembers all the branch instructions we've seen
	// and where they would like to go.
	Branches []Branch

	// JumpTables remembers all the jump tables we've seen.
	JumpTables []*ssa.Block

	// bstart remembers where each block starts (indexed by block ID)
	bstart []*obj.Prog

	maxarg int64 // largest frame size for arguments to calls made by the function

	// Map from GC safe points to liveness index, generated by
	// liveness analysis.
	livenessMap liveness.Map

	// partLiveArgs includes arguments that may be partially live, for which we
	// need to generate instructions that spill the argument registers.
	partLiveArgs map[*ir.Name]bool

	// lineRunStart records the beginning of the current run of instructions
	// within a single block sharing the same line number
	// Used to move statement marks to the beginning of such runs.
	lineRunStart *obj.Prog

	// wasm: The number of values on the WebAssembly stack. This is only used as a safeguard.
	OnWasmStackSkipped int
}

func (s *State) FuncInfo() *obj.FuncInfo {
	return s.pp.CurFunc.LSym.Func()
}

// Prog appends a new Prog.
func (s *State) Prog(as obj.As) *obj.Prog {
	p := s.pp.Prog(as)
	if objw.LosesStmtMark(as) {
		return p
	}
	// Float a statement start to the beginning of any same-line run.
	// lineRunStart is reset at block boundaries, which appears to work well.
	if s.lineRunStart == nil || s.lineRunStart.Pos.Line() != p.Pos.Line() {
		s.lineRunStart = p
	} else if p.Pos.IsStmt() == src.PosIsStmt {
		s.lineRunStart.Pos = s.lineRunStart.Pos.WithIsStmt()
		p.Pos = p.Pos.WithNotStmt()
	}
	return p
}

// Pc returns the current Prog.
func (s *State) Pc() *obj.Prog {
	return s.pp.Next
}

// SetPos sets the current source position.
func (s *State) SetPos(pos src.XPos) {
	s.pp.Pos = pos
}

// Br emits a single branch instruction and returns the instruction.
// Not all architectures need the returned instruction, but otherwise
// the boilerplate is common to all.
func (s *State) Br(op obj.As, target *ssa.Block) *obj.Prog {
	p := s.Prog(op)
	p.To.Type = obj.TYPE_BRANCH
	s.Branches = append(s.Branches, Branch{P: p, B: target})
	return p
}

// DebugFriendlySetPosFrom adjusts Pos.IsStmt subject to heuristics
// that reduce "jumpy" line number churn when debugging.
// Spill/fill/copy instructions from the register allocator,
// phi functions, and instructions with a no-pos position
// are examples of instructions that can cause churn.
func (s *State) DebugFriendlySetPosFrom(v *ssa.Value) {
	switch v.Op {
	case ssa.OpPhi, ssa.OpCopy, ssa.OpLoadReg, ssa.OpStoreReg:
		// These are not statements
		s.SetPos(v.Pos.WithNotStmt())
	default:
		p := v.Pos
		if p != src.NoXPos {
			// If the position is defined, update the position.
			// Also convert default IsStmt to NotStmt; only
			// explicit statement boundaries should appear
			// in the generated code.
			if p.IsStmt() != src.PosIsStmt {
				if s.pp.Pos.IsStmt() == src.PosIsStmt && s.pp.Pos.SameFileAndLine(p) {
					// If s.pp.Pos already has a statement mark, then it was set here (below) for
					// the previous value.  If an actual instruction had been emitted for that
					// value, then the statement mark would have been reset.  Since the statement
					// mark of s.pp.Pos was not reset, this position (file/line) still needs a
					// statement mark on an instruction.  If file and line for this value are
					// the same as the previous value, then the first instruction for this
					// value will work to take the statement mark.  Return early to avoid
					// resetting the statement mark.
					//
					// The reset of s.pp.Pos occurs in (*Progs).Prog() -- if it emits
					// an instruction, and the instruction's statement mark was set,
					// and it is not one of the LosesStmtMark instructions,
					// then Prog() resets the statement mark on the (*Progs).Pos.
					return
				}
				p = p.WithNotStmt()
				// Calls use the pos attached to v, but copy the statement mark from State
			}
			s.SetPos(p)
		} else {
			s.SetPos(s.pp.Pos.WithNotStmt())
		}
	}
}

// emit argument info (locations on stack) for traceback.
func emitArgInfo(e *ssafn, f *ssa.Func, pp *objw.Progs) {
	ft := e.curfn.Type()
	if ft.NumRecvs() == 0 && ft.NumParams() == 0 {
		return
	}

	x := EmitArgInfo(e.curfn, f.OwnAux.ABIInfo())
	x.Set(obj.AttrContentAddressable, true)
	e.curfn.LSym.Func().ArgInfo = x

	// Emit a funcdata pointing at the arg info data.
	p := pp.Prog(obj.AFUNCDATA)
	p.From.SetConst(rtabi.FUNCDATA_ArgInfo)
	p.To.Type = obj.TYPE_MEM
	p.To.Name = obj.NAME_EXTERN
	p.To.Sym = x
}

// emit argument info (locations on stack) of f for traceback.
func EmitArgInfo(f *ir.Func, abiInfo *abi.ABIParamResultInfo) *obj.LSym {
	x := base.Ctxt.Lookup(fmt.Sprintf("%s.arginfo%d", f.LSym.Name, f.ABI))
	// NOTE: do not set ContentAddressable here. This may be referenced from
	// assembly code by name (in this case f is a declaration).
	// Instead, set it in emitArgInfo above.

	PtrSize := int64(types.PtrSize)
	uintptrTyp := types.Types[types.TUINTPTR]

	isAggregate := func(t *types.Type) bool {
		return t.IsStruct() || t.IsArray() || t.IsComplex() || t.IsInterface() || t.IsString() || t.IsSlice()
	}

	wOff := 0
	n := 0
	writebyte := func(o uint8) { wOff = objw.Uint8(x, wOff, o) }

	// Write one non-aggregate arg/field/element.
	write1 := func(sz, offset int64) {
		if offset >= rtabi.TraceArgsSpecial {
			writebyte(rtabi.TraceArgsOffsetTooLarge)
		} else {
			writebyte(uint8(offset))
			writebyte(uint8(sz))
		}
		n++
	}

	// Visit t recursively and write it out.
	// Returns whether to continue visiting.
	var visitType func(baseOffset int64, t *types.Type, depth int) bool
	visitType = func(baseOffset int64, t *types.Type, depth int) bool {
		if n >= rtabi.TraceArgsLimit {
			writebyte(rtabi.TraceArgsDotdotdot)
			return false
		}
		if !isAggregate(t) {
			write1(t.Size(), baseOffset)
			return true
		}
		writebyte(rtabi.TraceArgsStartAgg)
		depth++
		if depth >= rtabi.TraceArgsMaxDepth {
			writebyte(rtabi.TraceArgsDotdotdot)
			writebyte(rtabi.TraceArgsEndAgg)
			n++
			return true
		}
		switch {
		case t.IsInterface(), t.IsString():
			_ = visitType(baseOffset, uintptrTyp, depth) &&
				visitType(baseOffset+PtrSize, uintptrTyp, depth)
		case t.IsSlice():
			_ = visitType(baseOffset, uintptrTyp, depth) &&
				visitType(baseOffset+PtrSize, uintptrTyp, depth) &&
				visitType(baseOffset+PtrSize*2, uintptrTyp, depth)
		case t.IsComplex():
			_ = visitType(baseOffset, types.FloatForComplex(t), depth) &&
				visitType(baseOffset+t.Size()/2, types.FloatForComplex(t), depth)
		case t.IsArray():
			if t.NumElem() == 0 {
				n++ // {} counts as a component
				break
			}
			for i := int64(0); i < t.NumElem(); i++ {
				if !visitType(baseOffset, t.Elem(), depth) {
					break
				}
				baseOffset += t.Elem().Size()
			}
		case t.IsStruct():
			if t.NumFields() == 0 {
				n++ // {} counts as a component
				break
			}
			for _, field := range t.Fields() {
				if !visitType(baseOffset+field.Offset, field.Type, depth) {
					break
				}
			}
		}
		writebyte(rtabi.TraceArgsEndAgg)
		return true
	}

	start := 0
	if strings.Contains(f.LSym.Name, "[") {
		// Skip the dictionary argument - it is implicit and the user doesn't need to see it.
		start = 1
	}

	for _, a := range abiInfo.InParams()[start:] {
		if !visitType(a.FrameOffset(abiInfo), a.Type, 0) {
			break
		}
	}
	writebyte(rtabi.TraceArgsEndSeq)
	if wOff > rtabi.TraceArgsMaxLen {
		base.Fatalf("ArgInfo too large")
	}

	return x
}

// for wrapper, emit info of wrapped function.
func emitWrappedFuncInfo(e *ssafn, pp *objw.Progs) {
	if base.Ctxt.Flag_linkshared {
		// Relative reference (SymPtrOff) to another shared object doesn't work.
		// Unfortunate.
		return
	}

	wfn := e.curfn.WrappedFunc
	if wfn == nil {
		return
	}

	wsym := wfn.Linksym()
	x := base.Ctxt.LookupInit(fmt.Sprintf("%s.wrapinfo", wsym.Name), func(x *obj.LSym) {
		objw.SymPtrOff(x, 0, wsym)
		x.Set(obj.AttrContentAddressable, true)
	})
	e.curfn.LSym.Func().WrapInfo = x

	// Emit a funcdata pointing at the wrap info data.
	p := pp.Prog(obj.AFUNCDATA)
	p.From.SetConst(rtabi.FUNCDATA_WrapInfo)
	p.To.Type = obj.TYPE_MEM
	p.To.Name = obj.NAME_EXTERN
	p.To.Sym = x
}

// genssa appends entries to pp for each instruction in f.
func genssa(f *ssa.Func, pp *objw.Progs) {
	var s State
	s.ABI = f.OwnAux.Fn.ABI()

	e := f.Frontend().(*ssafn)

	s.livenessMap, s.partLiveArgs = liveness.Compute(e.curfn, f, e.stkptrsize, pp)
	emitArgInfo(e, f, pp)
	argLiveBlockMap, argLiveValueMap := liveness.ArgLiveness(e.curfn, f, pp)

	openDeferInfo := e.curfn.LSym.Func().OpenCodedDeferInfo
	if openDeferInfo != nil {
		// This function uses open-coded defers -- write out the funcdata
		// info that we computed at the end of genssa.
		p := pp.Prog(obj.AFUNCDATA)
		p.From.SetConst(rtabi.FUNCDATA_OpenCodedDeferInfo)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = openDeferInfo
	}

	emitWrappedFuncInfo(e, pp)

	// Remember where each block starts.
	s.bstart = make([]*obj.Prog, f.NumBlocks())
	s.pp = pp
	var progToValue map[*obj.Prog]*ssa.Value
	var progToBlock map[*obj.Prog]*ssa.Block
	var valueToProgAfter []*obj.Prog // The first Prog following computation of a value v; v is visible at this point.
	gatherPrintInfo := f.PrintOrHtmlSSA || ssa.GenssaDump[f.Name]
	if gatherPrintInfo {
		progToValue = make(map[*obj.Prog]*ssa.Value, f.NumValues())
		progToBlock = make(map[*obj.Prog]*ssa.Block, f.NumBlocks())
		f.Logf("genssa %s\n", f.Name)
		progToBlock[s.pp.Next] = f.Blocks[0]
	}

	if base.Ctxt.Flag_locationlists {
		if cap(f.Cache.ValueToProgAfter) < f.NumValues() {
			f.Cache.ValueToProgAfter = make([]*obj.Prog, f.NumValues())
		}
		valueToProgAfter = f.Cache.ValueToProgAfter[:f.NumValues()]
		for i := range valueToProgAfter {
			valueToProgAfter[i] = nil
		}
	}

	// If the very first instruction is not tagged as a statement,
	// debuggers may attribute it to previous function in program.
	firstPos := src.NoXPos
	for _, v := range f.Entry.Values {
		if v.Pos.IsStmt() == src.PosIsStmt && v.Op != ssa.OpArg && v.Op != ssa.OpArgIntReg && v.Op != ssa.OpArgFloatReg && v.Op != ssa.OpLoadReg && v.Op != ssa.OpStoreReg {
			firstPos = v.Pos
			v.Pos = firstPos.WithDefaultStmt()
			break
		}
	}

	// inlMarks has an entry for each Prog that implements an inline mark.
	// It maps from that Prog to the global inlining id of the inlined body
	// which should unwind to this Prog's location.
	var inlMarks map[*obj.Prog]int32
	var inlMarkList []*obj.Prog

	// inlMarksByPos maps from a (column 1) source position to the set of
	// Progs that are in the set above and have that source position.
	var inlMarksByPos map[src.XPos][]*obj.Prog

	var argLiveIdx int = -1 // argument liveness info index

	// These control cache line alignment; if the required portion of
	// a cache line is not available, then pad to obtain cache line
	// alignment.  Not implemented on all architectures, may not be
	// useful on all architectures.
	var hotAlign, hotRequire int64

	if base.Debug.AlignHot > 0 {
		switch base.Ctxt.Arch.Name {
		// enable this on a case-by-case basis, with benchmarking.
		// currently shown:
		//   good for amd64
		//   not helpful for Apple Silicon
		//
		case "amd64", "386":
			// Align to 64 if 31 or fewer bytes remain in a cache line
			// benchmarks a little better than always aligning, and also
			// adds slightly less to the (PGO-compiled) binary size.
			hotAlign = 64
			hotRequire = 31
		}
	}

	// Emit basic blocks
	for i, b := range f.Blocks {

		s.lineRunStart = nil
		s.SetPos(s.pp.Pos.WithNotStmt()) // It needs a non-empty Pos, but cannot be a statement boundary (yet).

		if hotAlign > 0 && b.Hotness&ssa.HotPgoInitial == ssa.HotPgoInitial {
			// So far this has only been shown profitable for PGO-hot loop headers.
			// The Hotness values allows distinctions between initial blocks that are "hot" or not, and "flow-in" or not.
			// Currently only the initial blocks of loops are tagged in this way;
			// there are no blocks tagged "pgo-hot" that are not also tagged "initial".
			// TODO more heuristics, more architectures.
			p := s.pp.Prog(obj.APCALIGNMAX)
			p.From.SetConst(hotAlign)
			p.To.SetConst(hotRequire)
		}

		s.bstart[b.ID] = s.pp.Next

		if idx, ok := argLiveBlockMap[b.ID]; ok && idx != argLiveIdx {
			argLiveIdx = idx
			p := s.pp.Prog(obj.APCDATA)
			p.From.SetConst(rtabi.PCDATA_ArgLiveIndex)
			p.To.SetConst(int64(idx))
		}

		// Emit values in block
		Arch.SSAMarkMoves(&s, b)
		for _, v := range b.Values {
			x := s.pp.Next
			s.DebugFriendlySetPosFrom(v)

			if v.Op.ResultInArg0() && v.ResultReg() != v.Args[0].Reg() {
				v.Fatalf("input[0] and output not in same register %s", v.LongString())
			}

			switch v.Op {
			case ssa.OpInitMem:
				// memory arg needs no code
			case ssa.OpArg:
				// input args need no code
			case ssa.OpSP, ssa.OpSB:
				// nothing to do
			case ssa.OpSelect0, ssa.OpSelect1, ssa.OpSelectN, ssa.OpMakeResult:
				// nothing to do
			case ssa.OpGetG:
				// nothing to do when there's a g register,
				// and checkLower complains if there's not
			case ssa.OpVarDef, ssa.OpVarLive, ssa.OpKeepAlive, ssa.OpWBend:
				// nothing to do; already used by liveness
			case ssa.OpPhi:
				CheckLoweredPhi(v)
			case ssa.OpConvert:
				// nothing to do; no-op conversion for liveness
				if v.Args[0].Reg() != v.Reg() {
					v.Fatalf("OpConvert should be a no-op: %s; %s", v.Args[0].LongString(), v.LongString())
				}
			case ssa.OpInlMark:
				p := Arch.Ginsnop(s.pp)
				if inlMarks == nil {
					inlMarks = map[*obj.Prog]int32{}
					inlMarksByPos = map[src.XPos][]*obj.Prog{}
				}
				inlMarks[p] = v.AuxInt32()
				inlMarkList = append(inlMarkList, p)
				pos := v.Pos.AtColumn1()
				inlMarksByPos[pos] = append(inlMarksByPos[pos], p)
				firstPos = src.NoXPos

			default:
				// Special case for first line in function; move it to the start (which cannot be a register-valued instruction)
				if firstPos != src.NoXPos && v.Op != ssa.OpArgIntReg && v.Op != ssa.OpArgFloatReg && v.Op != ssa.OpLoadReg && v.Op != ssa.OpStoreReg {
					s.SetPos(firstPos)
					firstPos = src.NoXPos
				}
				// Attach this safe point to the next
				// instruction.
				s.pp.NextLive = s.livenessMap.Get(v)
				s.pp.NextUnsafe = s.livenessMap.GetUnsafe(v)

				// let the backend handle it
				Arch.SSAGenValue(&s, v)
			}

			if idx, ok := argLiveValueMap[v.ID]; ok && idx != argLiveIdx {
				argLiveIdx = idx
				p := s.pp.Prog(obj.APCDATA)
				p.From.SetConst(rtabi.PCDATA_ArgLiveIndex)
				p.To.SetConst(int64(idx))
			}

			if base.Ctxt.Flag_locationlists {
				valueToProgAfter[v.ID] = s.pp.Next
			}

			if gatherPrintInfo {
				for ; x != s.pp.Next; x = x.Link {
					progToValue[x] = v
				}
			}
		}
		// If this is an empty infinite loop, stick a hardware NOP in there so that debuggers are less confused.
		if s.bstart[b.ID] == s.pp.Next && len(b.Succs) == 1 && b.Succs[0].Block() == b {
			p := Arch.Ginsnop(s.pp)
			p.Pos = p.Pos.WithIsStmt()
			if b.Pos == src.NoXPos {
				b.Pos = p.Pos // It needs a file, otherwise a no-file non-zero line causes confusion.  See #35652.
				if b.Pos == src.NoXPos {
					b.Pos = s.pp.Text.Pos // Sometimes p.Pos is empty.  See #35695.
				}
			}
			b.Pos = b.Pos.WithBogusLine() // Debuggers are not good about infinite loops, force a change in line number
		}

		// Set unsafe mark for any end-of-block generated instructions
		// (normally, conditional or unconditional branches).
		// This is particularly important for empty blocks, as there
		// are no values to inherit the unsafe mark from.
		s.pp.NextUnsafe = s.livenessMap.GetUnsafeBlock(b)

		// Emit control flow instructions for block
		var next *ssa.Block
		if i < len(f.Blocks)-1 && base.Flag.N == 0 {
			// If -N, leave next==nil so every block with successors
			// ends in a JMP (except call blocks - plive doesn't like
			// select{send,recv} followed by a JMP call).  Helps keep
			// line numbers for otherwise empty blocks.
			next = f.Blocks[i+1]
		}
		x := s.pp.Next
		s.SetPos(b.Pos)
		Arch.SSAGenBlock(&s, b, next)
		if gatherPrintInfo {
			for ; x != s.pp.Next; x = x.Link {
				progToBlock[x] = b
			}
		}
	}
	if f.Blocks[len(f.Blocks)-1].Kind == ssa.BlockExit {
		// We need the return address of a panic call to
		// still be inside the function in question. So if
		// it ends in a call which doesn't return, add a
		// nop (which will never execute) after the call.
		Arch.Ginsnop(s.pp)
	}
	if openDeferInfo != nil {
		// When doing open-coded defers, generate a disconnected call to
		// deferreturn and a return. This will be used to during panic
		// recovery to unwind the stack and return back to the runtime.
		s.pp.NextLive = s.livenessMap.DeferReturn
		p := s.pp.Prog(obj.ACALL)
		p.To.Type = obj.TYPE_MEM
		p.To.Name = obj.NAME_EXTERN
		p.To.Sym = ir.Syms.Deferreturn

		// Load results into registers. So when a deferred function
		// recovers a panic, it will return to caller with right results.
		// The results are already in memory, because they are not SSA'd
		// when the function has defers (see canSSAName).
		for _, o := range f.OwnAux.ABIInfo().OutParams() {
			n := o.Name
			rts, offs := o.RegisterTypesAndOffsets()
			for i := range o.Registers {
				Arch.LoadRegResult(&s, f, rts[i], ssa.ObjRegForAbiReg(o.Registers[i], f.Config), n, offs[i])
			}
		}

		s.pp.Prog(obj.ARET)
	}

	if inlMarks != nil {
		hasCall := false

		// We have some inline marks. Try to find other instructions we're
		// going to emit anyway, and use those instructions instead of the
		// inline marks.
		for p := s.pp.Text; p != nil; p = p.Link {
			if p.As == obj.ANOP || p.As == obj.AFUNCDATA || p.As == obj.APCDATA || p.As == obj.ATEXT ||
				p.As == obj.APCALIGN || p.As == obj.APCALIGNMAX || Arch.LinkArch.Family == sys.Wasm {
				// Don't use 0-sized instructions as inline marks, because we need
				// to identify inline mark instructions by pc offset.
				// (Some of these instructions are sometimes zero-sized, sometimes not.
				// We must not use anything that even might be zero-sized.)
				// TODO: are there others?
				continue
			}
			if _, ok := inlMarks[p]; ok {
				// Don't use inline marks themselves. We don't know
				// whether they will be zero-sized or not yet.
				continue
			}
			if p.As == obj.ACALL || p.As == obj.ADUFFCOPY || p.As == obj.ADUFFZERO {
				hasCall = true
			}
			pos := p.Pos.AtColumn1()
			marks := inlMarksByPos[pos]
			if len(marks) == 0 {
				continue
			}
			for _, m := range marks {
				// We found an instruction with the same source position as
				// some of the inline marks.
				// Use this instruction instead.
				p.Pos = p.Pos.WithIsStmt() // promote position to a statement
				s.pp.CurFunc.LSym.Func().AddInlMark(p, inlMarks[m])
				// Make the inline mark a real nop, so it doesn't generate any code.
				m.As = obj.ANOP
				m.Pos = src.NoXPos
				m.From = obj.Addr{}
				m.To = obj.Addr{}
			}
			delete(inlMarksByPos, pos)
		}
		// Any unmatched inline marks now need to be added to the inlining tree (and will generate a nop instruction).
		for _, p := range inlMarkList {
			if p.As != obj.ANOP {
				s.pp.CurFunc.LSym.Func().AddInlMark(p, inlMarks[p])
			}
		}

		if e.stksize == 0 && !hasCall {
			// Frameless leaf function. It doesn't need any preamble,
			// so make sure its first instruction isn't from an inlined callee.
			// If it is, add a nop at the start of the function with a position
			// equal to the start of the function.
			// This ensures that runtime.FuncForPC(uintptr(reflect.ValueOf(fn).Pointer())).Name()
			// returns the right answer. See issue 58300.
			for p := s.pp.Text; p != nil; p = p.Link {
				if p.As == obj.AFUNCDATA || p.As == obj.APCDATA || p.As == obj.ATEXT || p.As == obj.ANOP {
					continue
				}
				if base.Ctxt.PosTable.Pos(p.Pos).Base().InliningIndex() >= 0 {
					// Make a real (not 0-sized) nop.
					nop := Arch.Ginsnop(s.pp)
					nop.Pos = e.curfn.Pos().WithIsStmt()

					// Unfortunately, Ginsnop puts the instruction at the
					// end of the list. Move it up to just before p.

					// Unlink from the current list.
					for x := s.pp.Text; x != nil; x = x.Link {
						if x.Link == nop {
							x.Link = nop.Link
							break
						}
					}
					// Splice in right before p.
					for x := s.pp.Text; x != nil; x = x.Link {
						if x.Link == p {
							nop.Link = p
							x.Link = nop
							break
						}
					}
				}
				break
			}
		}
	}

	if base.Ctxt.Flag_locationlists {
		var debugInfo *ssa.FuncDebug
		debugInfo = e.curfn.DebugInfo.(*ssa.FuncDebug)
		if e.curfn.ABI == obj.ABIInternal && base.Flag.N != 0 {
			ssa.BuildFuncDebugNoOptimized(base.Ctxt, f, base.Debug.LocationLists > 1, StackOffset, debugInfo)
		} else {
			ssa.BuildFuncDebug(base.Ctxt, f, base.Debug.LocationLists, StackOffset, debugInfo)
		}
		bstart := s.bstart
		idToIdx := make([]int, f.NumBlocks())
		for i, b := range f.Blocks {
			idToIdx[b.ID] = i
		}
		// Register a callback that will be used later to fill in PCs into location
		// lists. At the moment, Prog.Pc is a sequence number; it's not a real PC
		// until after assembly, so the translation needs to be deferred.
		debugInfo.GetPC = func(b, v ssa.ID) int64 {
			switch v {
			case ssa.BlockStart.ID:
				if b == f.Entry.ID {
					return 0 // Start at the very beginning, at the assembler-generated prologue.
					// this should only happen for function args (ssa.OpArg)
				}
				return bstart[b].Pc
			case ssa.BlockEnd.ID:
				blk := f.Blocks[idToIdx[b]]
				nv := len(blk.Values)
				return valueToProgAfter[blk.Values[nv-1].ID].Pc
			case ssa.FuncEnd.ID:
				return e.curfn.LSym.Size
			default:
				return valueToProgAfter[v].Pc
			}
		}
	}

	// Resolve branches, and relax DefaultStmt into NotStmt
	for _, br := range s.Branches {
		br.P.To.SetTarget(s.bstart[br.B.ID])
		if br.P.Pos.IsStmt() != src.PosIsStmt {
			br.P.Pos = br.P.Pos.WithNotStmt()
		} else if v0 := br.B.FirstPossibleStmtValue(); v0 != nil && v0.Pos.Line() == br.P.Pos.Line() && v0.Pos.IsStmt() == src.PosIsStmt {
			br.P.Pos = br.P.Pos.WithNotStmt()
		}

	}

	// Resolve jump table destinations.
	for _, jt := range s.JumpTables {
		// Convert from *Block targets to *Prog targets.
		targets := make([]*obj.Prog, len(jt.Succs))
		for i, e := range jt.Succs {
			targets[i] = s.bstart[e.Block().ID]
		}
		// Add to list of jump tables to be resolved at assembly time.
		// The assembler converts from *Prog entries to absolute addresses
		// once it knows instruction byte offsets.
		fi := s.pp.CurFunc.LSym.Func()
		fi.JumpTables = append(fi.JumpTables, obj.JumpTable{Sym: jt.Aux.(*obj.LSym), Targets: targets})
	}

	if e.log { // spew to stdout
		filename := ""
		for p := s.pp.Text; p != nil; p = p.Link {
			if p.Pos.IsKnown() && p.InnermostFilename() != filename {
				filename = p.InnermostFilename()
				f.Logf("# %s\n", filename)
			}

			var s string
			if v, ok := progToValue[p]; ok {
				s = v.String()
			} else if b, ok := progToBlock[p]; ok {
				s = b.String()
			} else {
				s = "   " // most value and branch strings are 2-3 characters long
			}
			f.Logf(" %-6s\t%.5d (%s)\t%s\n", s, p.Pc, p.InnermostLineNumber(), p.InstructionString())
		}
	}
	if f.HTMLWriter != nil { // spew to ssa.html
		var buf strings.Builder
		buf.WriteString("<code>")
		buf.WriteString("<dl class=\"ssa-gen\">")
		filename := ""
		for p := s.pp.Text; p != nil; p = p.Link {
			// Don't spam every line with the file name, which is often huge.
			// Only print changes, and "unknown" is not a change.
			if p.Pos.IsKnown() && p.InnermostFilename() != filename {
				filename = p.InnermostFilename()
				buf.WriteString("<dt class=\"ssa-prog-src\"></dt><dd class=\"ssa-prog\">")
				buf.WriteString(html.EscapeString("# " + filename))
				buf.WriteString("</dd>")
			}

			buf.WriteString("<dt class=\"ssa-prog-src\">")
			if v, ok := progToValue[p]; ok {
				buf.WriteString(v.HTML())
			} else if b, ok := progToBlock[p]; ok {
				buf.WriteString("<b>" + b.HTML() + "</b>")
			}
			buf.WriteString("</dt>")
			buf.WriteString("<dd class=\"ssa-prog\">")
			fmt.Fprintf(&buf, "%.5d <span class=\"l%v line-number\">(%s)</span> %s", p.Pc, p.InnermostLineNumber(), p.InnermostLineNumberHTML(), html.EscapeString(p.InstructionString()))
			buf.WriteString("</dd>")
		}
		buf.WriteString("</dl>")
		buf.WriteString("</code>")
		f.HTMLWriter.WriteColumn("genssa", "genssa", "ssa-prog", buf.String())
	}
	if ssa.GenssaDump[f.Name] {
		fi := f.DumpFileForPhase("genssa")
		if fi != nil {

			// inliningDiffers if any filename changes or if any line number except the innermost (last index) changes.
			inliningDiffers := func(a, b []src.Pos) bool {
				if len(a) != len(b) {
					return true
				}
				for i := range a {
					if a[i].Filename() != b[i].Filename() {
						return true
					}
					if i != len(a)-1 && a[i].Line() != b[i].Line() {
						return true
					}
				}
				return false
			}

			var allPosOld []src.Pos
			var allPos []src.Pos

			for p := s.pp.Text; p != nil; p = p.Link {
				if p.Pos.IsKnown() {
					allPos = allPos[:0]
					p.Ctxt.AllPos(p.Pos, func(pos src.Pos) { allPos = append(allPos, pos) })
					if inliningDiffers(allPos, allPosOld) {
						for _, pos := range allPos {
							fmt.Fprintf(fi, "# %s:%d\n", pos.Filename(), pos.Line())
						}
						allPos, allPosOld = allPosOld, allPos // swap, not copy, so that they do not share slice storage.
					}
				}

				var s string
				if v, ok := progToValue[p]; ok {
					s = v.String()
				} else if b, ok := progToBlock[p]; ok {
```