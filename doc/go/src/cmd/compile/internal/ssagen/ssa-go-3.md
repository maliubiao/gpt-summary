Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keywords:**

First, I'd quickly scan the code for recognizable keywords and structures. Things that immediately jump out are:

* `ssa`: This strongly suggests involvement with Static Single Assignment form, a compiler intermediate representation.
* `obj.Prog`, `objw.Progs`, `obj.LSym`, `obj.ABI`: These relate to the Go assembler and linker.
* `ir.Node`, `ir.Name`, `ir.Func`: These indicate interaction with the Go intermediate representation (likely before SSA).
* `types.Type`: This deals with Go's type system.
* `s.newValue`, `s.startBlock`, `s.endBlock`: These are functions within the `state` struct, indicating the construction of SSA control flow graphs.
* `rtcall`, `ir.Syms`:  These point to runtime function calls.
* `type assertion`:  A prominent operation being implemented.
* `cache`:  A caching mechanism for type assertions.
* `loop`: Explicit loop structures within the type assertion implementation.
* `panic`:  Handling failed type assertions.
* `commaok`:  The "comma ok" idiom in Go's type assertions.

**2. Identify the Core Functionality:**

The presence of the `type assertion` logic, particularly the part involving a `cache`, strongly suggests that this code is responsible for *efficiently implementing type assertions in Go*. The `iface`, `target`, `targetItab` variables reinforce this.

**3. Deconstruct the Type Assertion Logic:**

I would then focus on the code blocks related to type assertions:

* **Caching Logic:** The code using `cache`, `hash`, `mask`, `loopHead`, `cacheHit`, `cacheMiss`, and `bMerge` clearly implements a hash table-based cache for type assertion results. The steps within the loop (calculating the index, comparing types, checking for empty entries) are standard hash table operations.
* **Runtime Calls:** The `s.rtcall` calls with `ir.Syms.TypeAssert`, `ir.Syms.AssertE2I2`, and `ir.Syms.AssertE2I` indicate fallbacks to runtime functions when the cache misses. This is a common pattern for performance-critical operations.
* **Direct Type Conversions:** The section starting with "Converting to a concrete type" handles the simpler case of asserting to a concrete type. The comparison of `itab` with `wantedFirstWord` is the core of this check.
* **Comma Ok Handling:** The code with `commaok` explicitly deals with the two-result form of type assertions.
* **Panic on Failure:** The `s.rtcall(ir.Syms.PanicdottypeE, ...)` and `s.rtcall(ir.Syms.PanicdottypeI, ...)` calls demonstrate how failed non-"comma ok" assertions trigger panics.

**4. Infer the Larger Context:**

Knowing this is about type assertions within the compiler, I would deduce that this code resides within a part of the compiler responsible for generating machine code from the SSA representation. The path `go/src/cmd/compile/internal/ssagen/ssa.go` confirms this, as `ssagen` likely refers to SSA generation.

**5. Reason about Inputs and Outputs:**

For the caching part, the input is the interface value (`iface`), the target type (`typ`), and potentially a descriptor (`descriptor`). The output is the `itab` (interface table pointer) and, in the "comma ok" case, a boolean indicating success.

For the direct conversion, the input is the interface value and the target type. The output is the converted value and the success boolean (if "comma ok").

**6. Consider Command-Line Arguments:**

The presence of `base.Debug.TypeAssert` suggests a debug flag that controls whether the compiler inlines type assertions or relies on runtime calls. This is a typical way to enable/disable optimizations or gather debugging information.

**7. Identify Potential Pitfalls:**

The complexity of the caching logic, especially with the pointer arithmetic, presents opportunities for errors if not carefully implemented. Incorrect hash function, mask calculation, or pointer manipulation could lead to incorrect caching or even crashes.

**8. Synthesize the Summary:**

Finally, I would synthesize the information gathered into a concise summary, highlighting the core functionality (efficient type assertion implementation), key aspects (caching, runtime calls, handling different forms of assertions), and the broader context within the Go compiler.

**Self-Correction/Refinement during the process:**

* Initially, I might only focus on the caching part. However, noticing the "Converting to a concrete type" section would prompt me to realize that the code handles more than just cached assertions.
* Seeing `ir.Syms.PanicdottypeE` and `ir.Syms.PanicdottypeI` would clarify how type assertion failures are handled.
* The presence of `commaok` would lead me to understand the distinction between the single and dual-result forms of type assertions.
*  Realizing this is part 4 of 4 would push me to think about how this part fits into the overall SSA generation process.

By following this structured approach, combining code analysis with knowledge of Go's features and compiler concepts, I can effectively understand and summarize the functionality of the given code snippet.
这是 `go/src/cmd/compile/internal/ssagen/ssa.go` 文件的第 4 部分，主要关注 **将 SSA 中间表示转换为目标机器的汇编代码**。

**核心功能归纳：**

这部分代码的主要功能是负责将 SSA (Static Single Assignment) 形式的 Go 代码转换为目标架构的机器指令。 它涵盖了以下关键方面：

1. **类型断言的 SSA 代码生成:**  详细实现了类型断言 (`v.(T)`) 的 SSA 代码生成，包括以下策略：
    * **内联缓存优化:**  使用一个哈希表来缓存最近的类型断言结果，以提高性能。
    * **运行时调用:** 当缓存未命中或无法内联时，会调用 Go 运行时的函数 (`runtime.TypeAssert`, `runtime.AssertE2I`, `runtime.AssertE2I2`) 来完成类型断言。
    * **处理 "comma ok" 形式:**  支持带布尔返回值的类型断言。
    * **直接类型转换:**  处理将接口类型断言为具体类型的情况。
    * **失败时的 panic:**  对于不带 "comma ok" 的类型断言失败，会调用运行时 panic 函数。

2. **临时变量管理:**  提供了 `temp` 函数用于在需要时分配临时变量。

3. **变量访问:**  `variable` 函数用于获取变量在当前位置的值，并处理前向引用的情况。

4. **内存访问:**  `mem` 函数用于获取当前的内存状态。

5. **控制流图到汇编的转换:**
    * **基本块的生成:** 遍历 SSA 的基本块，为每个块生成相应的汇编代码。
    * **指令生成:**  为每个 SSA 指令调用架构特定的 `Arch.SSAGenValue` 函数来生成汇编代码。
    * **分支处理:**  记录所有分支指令及其目标，并在后续处理中解析。
    * **跳转表处理:**  记录跳转表信息，以便在汇编时生成正确的跳转指令。

6. **函数序言和尾声:**  生成函数的序言（设置栈帧）和尾声（恢复栈帧和返回）。

7. **参数和局部变量的栈分配:**  管理函数参数和局部变量在栈上的分配。

8. **内联处理:** 处理内联函数的标记和代码生成。

9. **调试信息生成:** 生成用于调试的元数据，例如行号信息和变量位置信息。

10. **延迟调用 (defer) 处理:**  插入与 `defer` 相关的运行时调用。

**它是什么 Go 语言功能的实现 (类型断言):**

这部分代码重点实现了 Go 语言的 **类型断言** 功能。

**Go 代码示例:**

```go
package main

import "fmt"

func assertType(i interface{}) {
	s, ok := i.(string) // 类型断言，带 "comma ok"
	if ok {
		fmt.Println("It's a string:", s)
	} else {
		fmt.Println("It's not a string")
	}

	n := i.(int) // 类型断言，不带 "comma ok"，如果失败会 panic
	fmt.Println("It's an integer:", n)
}

func main() {
	assertType("hello")
	assertType(123)
}
```

**代码推理 (类型断言的内联缓存):**

**假设输入:**

* `iface`: 一个包含字符串 "world" 的 `interface{}` 类型的值。
* `typ`: `string` 类型的类型信息。
* `cache`:  一个已经缓存了一些类型断言结果的哈希表，但没有 `("world", string)` 的条目。

**输出 (大致流程):**

1. **计算哈希值:** 根据 `iface` 的类型和 `typ` 计算哈希值。
2. **查找缓存:**  根据哈希值在 `cache` 中查找对应的条目，发现未命中。
3. **调用运行时:**  由于缓存未命中，调用 `runtime.TypeAssert` 或类似的运行时函数。
4. **运行时执行:** 运行时函数会检查 `iface` 的动态类型是否与 `typ` 匹配。
5. **更新缓存:**  如果匹配成功，将 `("world", string)` 和相应的 `itab` 存入 `cache` 中。
6. **返回结果:** 返回字符串 "world" 和 `true` (如果使用 "comma ok")。

**命令行参数的具体处理:**

这部分代码中涉及的命令行参数主要是通过 `base.Debug.TypeAssert` 来控制类型断言的内联行为。

* **`base.Debug.TypeAssert > 0`:**  表示启用类型断言的内联优化。编译器会尝试将类型断言的逻辑直接生成到代码中，利用缓存或其他优化手段。
* **`base.Debug.TypeAssert <= 0`:**  表示不启用类型断言的内联优化。编译器会直接调用运行时函数来执行类型断言。

**使用者易犯错的点 (没有直接体现在这段代码中，但与类型断言相关):**

虽然这段代码是编译器内部实现，但使用者在编写 Go 代码时容易犯与类型断言相关的错误：

* **类型断言失败时没有处理 panic:**  使用不带 "comma ok" 的类型断言，如果断言失败，程序会 panic。开发者需要确保类型断言的安全性，或者使用 "comma ok" 形式进行显式错误处理。
* **过度使用类型断言:**  频繁使用类型断言可能表明设计上存在问题，例如接口设计不合理。应该尽量使用更通用的接口或泛型 (Go 1.18+)。
* **忽略类型断言的性能影响:**  虽然编译器有内联缓存等优化，但类型断言仍然可能比直接类型操作开销更大。在高频调用的场景下需要注意性能。

**总结:**

这段 `ssa.go` 代码的第 4 部分是 Go 编译器中负责将 SSA 中间表示转换为机器代码的关键部分，它详细实现了类型断言的 SSA 代码生成，并涉及了临时变量管理、控制流转换、函数序言尾声、内联和调试信息生成等功能。理解这部分代码有助于深入了解 Go 语言的编译过程以及类型断言的实现原理。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssagen/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第4部分，共4部分，请归纳一下它的功能
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