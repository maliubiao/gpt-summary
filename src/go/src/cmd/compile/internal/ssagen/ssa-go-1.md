Response: My goal is to analyze the provided Go code snippet and extract its functionality. Here's my thinking process:

1. **Understand the Context:** The code is from `go/src/cmd/compile/internal/ssagen/ssa.go`. This immediately tells me it's part of the Go compiler, specifically the stage that transforms intermediate representation (IR) into static single assignment (SSA) form. SSA is a lower-level representation suitable for optimization and code generation.

2. **Identify the Core Function:** The primary function in this snippet is `(s *state) stmt(n ir.Node)`. The `s *state` indicates it's a method on a `state` receiver, likely holding the current compilation context. The `n ir.Node` argument suggests it processes individual statements from the IR.

3. **Analyze the `switch` Statement:** The core logic of `stmt` is a large `switch` statement based on the `n.Op()` (the operation code of the IR node). Each `case` handles a different type of Go statement or expression.

4. **Break Down Each `case`:** I'll go through each `case` and try to understand what Go language construct it corresponds to and what SSA operations it generates.

    * **`ir.OBLOCK`:** This is straightforward: it iterates through the statements within a block and recursively calls `s.stmt`.
    * **`ir.OEMPTY`:**  Does nothing, as expected for an empty statement.
    * **`ir.OBREAK`, `ir.OCONTINUE`, `ir.OGOTO`:**  These handle control flow within loops and functions. They set the current block's kind to `ssa.BlockJump` and add an edge to the appropriate target block (determined by labels or loop structures).
    * **`ir.ORETURN`:**  Generates the return sequence by calling `s.exit()`.
    * **`ir.OIF`:** Implements `if` statements. It generates conditional branches based on the condition, leading to the "then" or "else" blocks.
    * **`ir.OFOR`:** Handles `for` loops. This is more complex, involving blocks for the condition, body, increment, and exit. It also manages `continue` and `break` targets.
    * **`ir.OSWITCH`, `ir.OSELECT`:**  These handle `switch` and `select` statements. The code notes that the frontend mostly rewrites these, and the main task is handling `break` statements. The generated SSA involves an exit block.
    * **`ir.OJUMPTABLE`:**  Implements jump tables (efficiently handling multi-way branches based on an index). It generates code to check if the index is within bounds before using the jump table.
    * **`ir.OINTERFACESWITCH`:** Handles type switches on interfaces. It includes a sophisticated caching mechanism to speed up type assertions. This case demonstrates the generation of more complex SSA with loops and conditional logic.
    * **`ir.OCHECKNIL`:**  Generates a nil check for a pointer.
    * **`ir.OINLMARK`:** Marks an inline function call, likely for debugging or optimization purposes.
    * **`default`:** Handles unhandled statement types, throwing an error.

5. **Identify Associated Functions:**  The `stmt` function calls other methods of the `state` receiver. I'll note some of the key ones and their apparent purpose:
    * `s.startBlock()`, `s.endBlock()`: Manage the creation and linking of SSA blocks.
    * `s.condBranch()`: Handles conditional branching logic.
    * `s.label()`: Retrieves or creates SSA labels.
    * `s.stmtList()`: Processes a list of statements.
    * `s.expr()`: Converts expressions to SSA.
    * `s.rtcall()`: Generates calls to runtime functions.
    * `s.newValue*()`: Creates new SSA values.
    * `s.assign()`: Assigns values to variables.
    * `s.mem()`, `s.variable()`: Access memory and variable states.

6. **Infer Go Language Features:** By analyzing the `case` statements, I can infer the Go language features being implemented:
    * Basic control flow: `if`, `for`, `break`, `continue`, `goto`, `return`.
    * `switch` and `select` statements.
    * Jump tables (compiler optimization, not directly a Go keyword).
    * Interface type switches.
    * Nil checks.
    * Inline function calls.

7. **Provide Go Code Examples:** For some of the key features, I'll provide simple Go code examples that would trigger the corresponding `case` in the `stmt` function. This helps illustrate the connection between the Go source and the SSA generation.

8. **Infer Input and Output (Conceptual):** While the exact input is the IR and the output is SSA, I can describe the *conceptual* input and output for some cases. For example, for an `if` statement, the input is the `if` condition and the bodies of the `then` and `else` blocks. The output is the corresponding SSA block structure with conditional edges.

9. **Command-Line Parameters (If Applicable):**  The code mentions `base.Flag.Cfg.SpectreIndex` and `base.Flag.N`. This indicates the code might be influenced by compiler flags. I'll explain these briefly.

10. **Common Mistakes (If Applicable):** I'll look for patterns in the code that might suggest potential errors users could make that this code handles or prevents (though this section was explicitly stated as optional). For instance, the jump table case checks for index bounds, preventing out-of-bounds access.

11. **Synthesize the Functionality (for Part 2):** Finally, I'll summarize the overall functionality of the provided code snippet for Part 2 of the prompt.

By following these steps, I can systematically analyze the code and generate a comprehensive description of its functionality. The focus is on connecting the low-level SSA generation with the higher-level Go language constructs.
这段代码是Go语言编译器中将 Go 语言的抽象语法树 (AST) 转换为静态单赋值 (SSA) 中间表示的 `ssagen` 包的一部分。具体来说，这是 `state` 类型的 `stmt` 方法的实现，该方法负责处理各种 Go 语言语句，并将其转换为相应的 SSA 代码。

**归纳一下它的功能 (针对第 2 部分):**

这段代码实现了将 **循环语句 (`for`)、`switch` 语句、`select` 语句、`goto` 型的 `switch` 语句 (`JUMPTABLE`) 和接口类型的 `switch` 语句 (`INTERFACESWITCH`)** 转换成 SSA 代码的功能。它还处理了 **空指针检查 (`CHECKNIL`)** 和 **内联标记 (`INLMARK`)** 语句。

**更详细的功能分解：**

* **`case ir.OFOR` (For 循环):**
    * 创建用于循环条件判断 (`bCond`)、循环体 (`bBody`) 和循环后执行 (`bIncr`) 以及循环结束 (`bEnd`) 的 SSA 代码块。
    * 如果存在初始化语句 (`n.Init`)，则先处理初始化语句。
    * 生成测试循环条件的 SSA 代码。如果条件为空 (`n.Cond == nil`)，则表示无限循环。
    * 设置 `continue` 和 `break` 语句的目标代码块。
    * 生成循环体的 SSA 代码。
    * 生成循环后执行语句 (`n.Post`) 的 SSA 代码。
    * 将循环后执行代码块跳转回条件判断代码块，形成循环。

* **`case ir.OSWITCH, ir.OSELECT` (Switch 和 Select 语句):**
    * 创建用于 `switch` 或 `select` 语句结束的 SSA 代码块 (`bEnd`)。
    * 设置 `break` 语句的目标代码块。
    * 处理 `switch` 或 `select` 语句的 `case` 子句，这些子句已经被前端编译器重写到了 `Nbody` 字段中。
    * 如果在所有 `case` 子句执行完后仍然有当前代码块 (`s.curBlock != nil`)，则将其标记为不可达 (`ssa.BlockExit`)。

* **`case ir.OJUMPTABLE` (跳转表 Switch 语句):**
    * 创建跳转表代码块 (`jt`) 和结束代码块 (`bEnd`)。
    * 计算跳转索引的 SSA 值 (`idx`)。
    * 生成代码来判断索引是否在有效范围内，如果不在范围内，则跳转到 `bEnd`。
    * 构建跳转表代码块，根据索引值跳转到对应的 `case` 代码块。

* **`case ir.OINTERFACESWITCH` (接口类型 Switch 语句):**
    * 获取接口变量的运行时类型 (`t`) 和哈希值 (`h`)。
    * **实现了接口类型断言的缓存机制 (在 `base.Flag.N == 0` 且架构支持的情况下):**
        * 尝试从接口描述符中加载缓存指针，并利用原子操作确保加载到完整的缓存。
        * 进入循环，检查缓存中是否存在匹配的类型。
        * 如果找到匹配的类型 (缓存命中)，则加载缓存中的 `Case` 和 `Itab` 并跳转到合并代码块。
        * 如果在缓存中未找到匹配类型或空槽位 (缓存未命中)，则跳转到调用运行时函数的代码块。
    * 如果没有使用缓存或缓存未命中，则调用运行时函数 `runtime.iface.switchType` 来获取匹配的 `case` 索引和 `itab`。

* **`case ir.OCHECKNIL` (空指针检查):**
    * 生成检查指针是否为空的 SSA 代码，并可能触发 panic。

* **`case ir.OINLMARK` (内联标记):**
    * 生成一个内联标记的 SSA 操作，用于指示代码内联的位置，可能用于调试或性能分析。

**Go 代码举例说明：**

```go
package main

import "fmt"

func main() {
	// For 循环
	for i := 0; i < 10; i++ {
		fmt.Println(i)
	}

	// Switch 语句
	x := 2
	switch x {
	case 1:
		fmt.Println("one")
	case 2:
		fmt.Println("two")
	default:
		fmt.Println("other")
	}

	// Select 语句
	ch1 := make(chan int)
	ch2 := make(chan int)
	select {
	case <-ch1:
		fmt.Println("received from ch1")
	case <-ch2:
		fmt.Println("received from ch2")
	default:
		fmt.Println("no communication")
	}

	// 接口类型 Switch 语句
	var i interface{} = 10
	switch v := i.(type) {
	case int:
		fmt.Println("int", v)
	case string:
		fmt.Println("string", v)
	default:
		fmt.Println("unknown")
	}

	// 空指针检查 (通常由编译器隐式插入)
	var p *int
	// if p != nil { // 编译器可能会生成类似的检查
	// 	fmt.Println(*p)
	// }
	_ = p // 这里只是为了声明 p，实际使用可能会触发 CHECKNIL

	// 跳转表 Switch 语句 (Go 编译器可能会为某些优化的 switch 生成)
	// 示例：当 case 的值是连续的整数时
	y := 1
	switch y {
	case 0:
		fmt.Println("zero")
	case 1:
		fmt.Println("one")
	case 2:
		fmt.Println("two")
	}
}
```

**代码推理 (带假设的输入与输出):**

假设我们有如下 Go 代码片段：

```go
for i := 0; i < 3; i++ {
    println(i)
}
```

**假设的输入 (简化的 AST 节点):**

```
&ir.ForStmt{
    Cond: &ir.BinaryExpr{ // i < 3
        Op: ir.OLT,
        X:  &ir.Name{Name: "i", ...},
        Y:  &ir.ConstExpr{Val: 3, ...},
    },
    Post: &ir.AssignStmt{ // i++
        X:  &ir.Name{Name: "i", ...},
        Y:  &ir.BinaryExpr{Op: ir.OADD, ...},
    },
    Body: &ir.BlockStmt{ // println(i)
        List: []*ir.Node{
            &ir.CallExpr{Fun: &ir.Name{Name: "println", ...}, Args: []*ir.Node{&ir.Name{Name: "i", ...}}},
        },
    },
}
```

**假设的输出 (部分 SSA 代码，简化表示):**

```
// bCond:
v_i := ... // 获取 i 的值
v_3 := const 3
cond := v_i < v_3
if cond goto bBody else goto bEnd

// bBody:
call println(v_i)
goto bIncr

// bIncr:
v_i_old := ... // 获取 i 的旧值
v_1 := const 1
v_i_new := v_i_old + v_1
... // 更新 i 的值
goto bCond

// bEnd:
```

**命令行参数的具体处理：**

这段代码中提到了 `base.Flag.Cfg.SpectreIndex` 和 `base.Flag.N`。

* **`base.Flag.Cfg.SpectreIndex`**:  这是一个布尔类型的标志，用于指示是否启用针对 Spectre 漏洞的缓解措施。在 `OJUMPTABLE` 的 `case` 中，如果该标志为真，则会插入 `ssa.OpSpectreSliceIndex` 操作，这是一种用于缓解 Spectre 分支预测攻击的技术。该参数通常通过编译器的命令行参数 `-spectre=index` 来控制。

* **`base.Flag.N`**:  这是一个整数类型的标志，通常用于控制编译器的并行编译单元数量。在 `OINTERFACESWITCH` 的 `case` 中，`if base.Flag.N == 0`  判断是否禁用了并行编译。如果禁用了并行编译，并且架构支持接口类型断言缓存，则会尝试使用缓存来优化接口类型断言。

**使用者易犯错的点：**

这段代码是编译器内部实现，直接的用户不会与这段代码交互，因此不存在使用者易犯错的点。 这里的“使用者”是指 Go 语言的开发者，他们编写的 Go 代码会被这段代码处理。

希望以上解释能够帮助你理解这段代码的功能。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssagen/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共4部分，请归纳一下它的功能

"""
AddEdgeTo(bCond)

		// generate code to test condition
		s.startBlock(bCond)
		if n.Cond != nil {
			s.condBranch(n.Cond, bBody, bEnd, 1)
		} else {
			b := s.endBlock()
			b.Kind = ssa.BlockPlain
			b.AddEdgeTo(bBody)
		}

		// set up for continue/break in body
		prevContinue := s.continueTo
		prevBreak := s.breakTo
		s.continueTo = bIncr
		s.breakTo = bEnd
		var lab *ssaLabel
		if sym := n.Label; sym != nil {
			// labeled for loop
			lab = s.label(sym)
			lab.continueTarget = bIncr
			lab.breakTarget = bEnd
		}

		// generate body
		s.startBlock(bBody)
		s.stmtList(n.Body)

		// tear down continue/break
		s.continueTo = prevContinue
		s.breakTo = prevBreak
		if lab != nil {
			lab.continueTarget = nil
			lab.breakTarget = nil
		}

		// done with body, goto incr
		if b := s.endBlock(); b != nil {
			b.AddEdgeTo(bIncr)
		}

		// generate incr
		s.startBlock(bIncr)
		if n.Post != nil {
			s.stmt(n.Post)
		}
		if b := s.endBlock(); b != nil {
			b.AddEdgeTo(bCond)
			// It can happen that bIncr ends in a block containing only VARKILL,
			// and that muddles the debugging experience.
			if b.Pos == src.NoXPos {
				b.Pos = bCond.Pos
			}
		}

		s.startBlock(bEnd)

	case ir.OSWITCH, ir.OSELECT:
		// These have been mostly rewritten by the front end into their Nbody fields.
		// Our main task is to correctly hook up any break statements.
		bEnd := s.f.NewBlock(ssa.BlockPlain)

		prevBreak := s.breakTo
		s.breakTo = bEnd
		var sym *types.Sym
		var body ir.Nodes
		if n.Op() == ir.OSWITCH {
			n := n.(*ir.SwitchStmt)
			sym = n.Label
			body = n.Compiled
		} else {
			n := n.(*ir.SelectStmt)
			sym = n.Label
			body = n.Compiled
		}

		var lab *ssaLabel
		if sym != nil {
			// labeled
			lab = s.label(sym)
			lab.breakTarget = bEnd
		}

		// generate body code
		s.stmtList(body)

		s.breakTo = prevBreak
		if lab != nil {
			lab.breakTarget = nil
		}

		// walk adds explicit OBREAK nodes to the end of all reachable code paths.
		// If we still have a current block here, then mark it unreachable.
		if s.curBlock != nil {
			m := s.mem()
			b := s.endBlock()
			b.Kind = ssa.BlockExit
			b.SetControl(m)
		}
		s.startBlock(bEnd)

	case ir.OJUMPTABLE:
		n := n.(*ir.JumpTableStmt)

		// Make blocks we'll need.
		jt := s.f.NewBlock(ssa.BlockJumpTable)
		bEnd := s.f.NewBlock(ssa.BlockPlain)

		// The only thing that needs evaluating is the index we're looking up.
		idx := s.expr(n.Idx)
		unsigned := idx.Type.IsUnsigned()

		// Extend so we can do everything in uintptr arithmetic.
		t := types.Types[types.TUINTPTR]
		idx = s.conv(nil, idx, idx.Type, t)

		// The ending condition for the current block decides whether we'll use
		// the jump table at all.
		// We check that min <= idx <= max and jump around the jump table
		// if that test fails.
		// We implement min <= idx <= max with 0 <= idx-min <= max-min, because
		// we'll need idx-min anyway as the control value for the jump table.
		var min, max uint64
		if unsigned {
			min, _ = constant.Uint64Val(n.Cases[0])
			max, _ = constant.Uint64Val(n.Cases[len(n.Cases)-1])
		} else {
			mn, _ := constant.Int64Val(n.Cases[0])
			mx, _ := constant.Int64Val(n.Cases[len(n.Cases)-1])
			min = uint64(mn)
			max = uint64(mx)
		}
		// Compare idx-min with max-min, to see if we can use the jump table.
		idx = s.newValue2(s.ssaOp(ir.OSUB, t), t, idx, s.uintptrConstant(min))
		width := s.uintptrConstant(max - min)
		cmp := s.newValue2(s.ssaOp(ir.OLE, t), types.Types[types.TBOOL], idx, width)
		b := s.endBlock()
		b.Kind = ssa.BlockIf
		b.SetControl(cmp)
		b.AddEdgeTo(jt)             // in range - use jump table
		b.AddEdgeTo(bEnd)           // out of range - no case in the jump table will trigger
		b.Likely = ssa.BranchLikely // TODO: assumes missing the table entirely is unlikely. True?

		// Build jump table block.
		s.startBlock(jt)
		jt.Pos = n.Pos()
		if base.Flag.Cfg.SpectreIndex {
			idx = s.newValue2(ssa.OpSpectreSliceIndex, t, idx, width)
		}
		jt.SetControl(idx)

		// Figure out where we should go for each index in the table.
		table := make([]*ssa.Block, max-min+1)
		for i := range table {
			table[i] = bEnd // default target
		}
		for i := range n.Targets {
			c := n.Cases[i]
			lab := s.label(n.Targets[i])
			if lab.target == nil {
				lab.target = s.f.NewBlock(ssa.BlockPlain)
			}
			var val uint64
			if unsigned {
				val, _ = constant.Uint64Val(c)
			} else {
				vl, _ := constant.Int64Val(c)
				val = uint64(vl)
			}
			// Overwrite the default target.
			table[val-min] = lab.target
		}
		for _, t := range table {
			jt.AddEdgeTo(t)
		}
		s.endBlock()

		s.startBlock(bEnd)

	case ir.OINTERFACESWITCH:
		n := n.(*ir.InterfaceSwitchStmt)
		typs := s.f.Config.Types

		t := s.expr(n.RuntimeType)
		h := s.expr(n.Hash)
		d := s.newValue1A(ssa.OpAddr, typs.BytePtr, n.Descriptor, s.sb)

		// Check the cache first.
		var merge *ssa.Block
		if base.Flag.N == 0 && rtabi.UseInterfaceSwitchCache(Arch.LinkArch.Name) {
			// Note: we can only use the cache if we have the right atomic load instruction.
			// Double-check that here.
			if intrinsics.lookup(Arch.LinkArch.Arch, "internal/runtime/atomic", "Loadp") == nil {
				s.Fatalf("atomic load not available")
			}
			merge = s.f.NewBlock(ssa.BlockPlain)
			cacheHit := s.f.NewBlock(ssa.BlockPlain)
			cacheMiss := s.f.NewBlock(ssa.BlockPlain)
			loopHead := s.f.NewBlock(ssa.BlockPlain)
			loopBody := s.f.NewBlock(ssa.BlockPlain)

			// Pick right size ops.
			var mul, and, add, zext ssa.Op
			if s.config.PtrSize == 4 {
				mul = ssa.OpMul32
				and = ssa.OpAnd32
				add = ssa.OpAdd32
				zext = ssa.OpCopy
			} else {
				mul = ssa.OpMul64
				and = ssa.OpAnd64
				add = ssa.OpAdd64
				zext = ssa.OpZeroExt32to64
			}

			// Load cache pointer out of descriptor, with an atomic load so
			// we ensure that we see a fully written cache.
			atomicLoad := s.newValue2(ssa.OpAtomicLoadPtr, types.NewTuple(typs.BytePtr, types.TypeMem), d, s.mem())
			cache := s.newValue1(ssa.OpSelect0, typs.BytePtr, atomicLoad)
			s.vars[memVar] = s.newValue1(ssa.OpSelect1, types.TypeMem, atomicLoad)

			// Initialize hash variable.
			s.vars[hashVar] = s.newValue1(zext, typs.Uintptr, h)

			// Load mask from cache.
			mask := s.newValue2(ssa.OpLoad, typs.Uintptr, cache, s.mem())
			// Jump to loop head.
			b := s.endBlock()
			b.AddEdgeTo(loopHead)

			// At loop head, get pointer to the cache entry.
			//   e := &cache.Entries[hash&mask]
			s.startBlock(loopHead)
			entries := s.newValue2(ssa.OpAddPtr, typs.UintptrPtr, cache, s.uintptrConstant(uint64(s.config.PtrSize)))
			idx := s.newValue2(and, typs.Uintptr, s.variable(hashVar, typs.Uintptr), mask)
			idx = s.newValue2(mul, typs.Uintptr, idx, s.uintptrConstant(uint64(3*s.config.PtrSize)))
			e := s.newValue2(ssa.OpAddPtr, typs.UintptrPtr, entries, idx)
			//   hash++
			s.vars[hashVar] = s.newValue2(add, typs.Uintptr, s.variable(hashVar, typs.Uintptr), s.uintptrConstant(1))

			// Look for a cache hit.
			//   if e.Typ == t { goto hit }
			eTyp := s.newValue2(ssa.OpLoad, typs.Uintptr, e, s.mem())
			cmp1 := s.newValue2(ssa.OpEqPtr, typs.Bool, t, eTyp)
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
			//   Case = e.Case
			//   Itab = e.Itab
			s.startBlock(cacheHit)
			eCase := s.newValue2(ssa.OpLoad, typs.Int, s.newValue1I(ssa.OpOffPtr, typs.IntPtr, s.config.PtrSize, e), s.mem())
			eItab := s.newValue2(ssa.OpLoad, typs.BytePtr, s.newValue1I(ssa.OpOffPtr, typs.BytePtrPtr, 2*s.config.PtrSize, e), s.mem())
			s.assign(n.Case, eCase, false, 0)
			s.assign(n.Itab, eItab, false, 0)
			b = s.endBlock()
			b.AddEdgeTo(merge)

			// On a miss, call into the runtime to get the answer.
			s.startBlock(cacheMiss)
		}

		r := s.rtcall(ir.Syms.InterfaceSwitch, true, []*types.Type{typs.Int, typs.BytePtr}, d, t)
		s.assign(n.Case, r[0], false, 0)
		s.assign(n.Itab, r[1], false, 0)

		if merge != nil {
			// Cache hits merge in here.
			b := s.endBlock()
			b.Kind = ssa.BlockPlain
			b.AddEdgeTo(merge)
			s.startBlock(merge)
		}

	case ir.OCHECKNIL:
		n := n.(*ir.UnaryExpr)
		p := s.expr(n.X)
		_ = s.nilCheck(p)
		// TODO: check that throwing away the nilcheck result is ok.

	case ir.OINLMARK:
		n := n.(*ir.InlineMarkStmt)
		s.newValue1I(ssa.OpInlMark, types.TypeVoid, n.Index, s.mem())

	default:
		s.Fatalf("unhandled stmt %v", n.Op())
	}
}

// If true, share as many open-coded defer exits as possible (with the downside of
// worse line-number information)
const shareDeferExits = false

// exit processes any code that needs to be generated just before returning.
// It returns a BlockRet block that ends the control flow. Its control value
// will be set to the final memory state.
func (s *state) exit() *ssa.Block {
	if s.hasdefer {
		if s.hasOpenDefers {
			if shareDeferExits && s.lastDeferExit != nil && len(s.openDefers) == s.lastDeferCount {
				if s.curBlock.Kind != ssa.BlockPlain {
					panic("Block for an exit should be BlockPlain")
				}
				s.curBlock.AddEdgeTo(s.lastDeferExit)
				s.endBlock()
				return s.lastDeferFinalBlock
			}
			s.openDeferExit()
		} else {
			s.rtcall(ir.Syms.Deferreturn, true, nil)
		}
	}

	// Do actual return.
	// These currently turn into self-copies (in many cases).
	resultFields := s.curfn.Type().Results()
	results := make([]*ssa.Value, len(resultFields)+1, len(resultFields)+1)
	// Store SSAable and heap-escaped PPARAMOUT variables back to stack locations.
	for i, f := range resultFields {
		n := f.Nname.(*ir.Name)
		if s.canSSA(n) { // result is in some SSA variable
			if !n.IsOutputParamInRegisters() && n.Type().HasPointers() {
				// We are about to store to the result slot.
				s.vars[memVar] = s.newValue1A(ssa.OpVarDef, types.TypeMem, n, s.mem())
			}
			results[i] = s.variable(n, n.Type())
		} else if !n.OnStack() { // result is actually heap allocated
			// We are about to copy the in-heap result to the result slot.
			if n.Type().HasPointers() {
				s.vars[memVar] = s.newValue1A(ssa.OpVarDef, types.TypeMem, n, s.mem())
			}
			ha := s.expr(n.Heapaddr)
			s.instrumentFields(n.Type(), ha, instrumentRead)
			results[i] = s.newValue2(ssa.OpDereference, n.Type(), ha, s.mem())
		} else { // result is not SSA-able; not escaped, so not on heap, but too large for SSA.
			// Before register ABI this ought to be a self-move, home=dest,
			// With register ABI, it's still a self-move if parameter is on stack (i.e., too big or overflowed)
			// No VarDef, as the result slot is already holding live value.
			results[i] = s.newValue2(ssa.OpDereference, n.Type(), s.addr(n), s.mem())
		}
	}

	// In -race mode, we need to call racefuncexit.
	// Note: This has to happen after we load any heap-allocated results,
	// otherwise races will be attributed to the caller instead.
	if s.instrumentEnterExit {
		s.rtcall(ir.Syms.Racefuncexit, true, nil)
	}

	results[len(results)-1] = s.mem()
	m := s.newValue0(ssa.OpMakeResult, s.f.OwnAux.LateExpansionResultType())
	m.AddArgs(results...)

	b := s.endBlock()
	b.Kind = ssa.BlockRet
	b.SetControl(m)
	if s.hasdefer && s.hasOpenDefers {
		s.lastDeferFinalBlock = b
	}
	return b
}

type opAndType struct {
	op    ir.Op
	etype types.Kind
}

var opToSSA = map[opAndType]ssa.Op{
	{ir.OADD, types.TINT8}:    ssa.OpAdd8,
	{ir.OADD, types.TUINT8}:   ssa.OpAdd8,
	{ir.OADD, types.TINT16}:   ssa.OpAdd16,
	{ir.OADD, types.TUINT16}:  ssa.OpAdd16,
	{ir.OADD, types.TINT32}:   ssa.OpAdd32,
	{ir.OADD, types.TUINT32}:  ssa.OpAdd32,
	{ir.OADD, types.TINT64}:   ssa.OpAdd64,
	{ir.OADD, types.TUINT64}:  ssa.OpAdd64,
	{ir.OADD, types.TFLOAT32}: ssa.OpAdd32F,
	{ir.OADD, types.TFLOAT64}: ssa.OpAdd64F,

	{ir.OSUB, types.TINT8}:    ssa.OpSub8,
	{ir.OSUB, types.TUINT8}:   ssa.OpSub8,
	{ir.OSUB, types.TINT16}:   ssa.OpSub16,
	{ir.OSUB, types.TUINT16}:  ssa.OpSub16,
	{ir.OSUB, types.TINT32}:   ssa.OpSub32,
	{ir.OSUB, types.TUINT32}:  ssa.OpSub32,
	{ir.OSUB, types.TINT64}:   ssa.OpSub64,
	{ir.OSUB, types.TUINT64}:  ssa.OpSub64,
	{ir.OSUB, types.TFLOAT32}: ssa.OpSub32F,
	{ir.OSUB, types.TFLOAT64}: ssa.OpSub64F,

	{ir.ONOT, types.TBOOL}: ssa.OpNot,

	{ir.ONEG, types.TINT8}:    ssa.OpNeg8,
	{ir.ONEG, types.TUINT8}:   ssa.OpNeg8,
	{ir.ONEG, types.TINT16}:   ssa.OpNeg16,
	{ir.ONEG, types.TUINT16}:  ssa.OpNeg16,
	{ir.ONEG, types.TINT32}:   ssa.OpNeg32,
	{ir.ONEG, types.TUINT32}:  ssa.OpNeg32,
	{ir.ONEG, types.TINT64}:   ssa.OpNeg64,
	{ir.ONEG, types.TUINT64}:  ssa.OpNeg64,
	{ir.ONEG, types.TFLOAT32}: ssa.OpNeg32F,
	{ir.ONEG, types.TFLOAT64}: ssa.OpNeg64F,

	{ir.OBITNOT, types.TINT8}:   ssa.OpCom8,
	{ir.OBITNOT, types.TUINT8}:  ssa.OpCom8,
	{ir.OBITNOT, types.TINT16}:  ssa.OpCom16,
	{ir.OBITNOT, types.TUINT16}: ssa.OpCom16,
	{ir.OBITNOT, types.TINT32}:  ssa.OpCom32,
	{ir.OBITNOT, types.TUINT32}: ssa.OpCom32,
	{ir.OBITNOT, types.TINT64}:  ssa.OpCom64,
	{ir.OBITNOT, types.TUINT64}: ssa.OpCom64,

	{ir.OIMAG, types.TCOMPLEX64}:  ssa.OpComplexImag,
	{ir.OIMAG, types.TCOMPLEX128}: ssa.OpComplexImag,
	{ir.OREAL, types.TCOMPLEX64}:  ssa.OpComplexReal,
	{ir.OREAL, types.TCOMPLEX128}: ssa.OpComplexReal,

	{ir.OMUL, types.TINT8}:    ssa.OpMul8,
	{ir.OMUL, types.TUINT8}:   ssa.OpMul8,
	{ir.OMUL, types.TINT16}:   ssa.OpMul16,
	{ir.OMUL, types.TUINT16}:  ssa.OpMul16,
	{ir.OMUL, types.TINT32}:   ssa.OpMul32,
	{ir.OMUL, types.TUINT32}:  ssa.OpMul32,
	{ir.OMUL, types.TINT64}:   ssa.OpMul64,
	{ir.OMUL, types.TUINT64}:  ssa.OpMul64,
	{ir.OMUL, types.TFLOAT32}: ssa.OpMul32F,
	{ir.OMUL, types.TFLOAT64}: ssa.OpMul64F,

	{ir.ODIV, types.TFLOAT32}: ssa.OpDiv32F,
	{ir.ODIV, types.TFLOAT64}: ssa.OpDiv64F,

	{ir.ODIV, types.TINT8}:   ssa.OpDiv8,
	{ir.ODIV, types.TUINT8}:  ssa.OpDiv8u,
	{ir.ODIV, types.TINT16}:  ssa.OpDiv16,
	{ir.ODIV, types.TUINT16}: ssa.OpDiv16u,
	{ir.ODIV, types.TINT32}:  ssa.OpDiv32,
	{ir.ODIV, types.TUINT32}: ssa.OpDiv32u,
	{ir.ODIV, types.TINT64}:  ssa.OpDiv64,
	{ir.ODIV, types.TUINT64}: ssa.OpDiv64u,

	{ir.OMOD, types.TINT8}:   ssa.OpMod8,
	{ir.OMOD, types.TUINT8}:  ssa.OpMod8u,
	{ir.OMOD, types.TINT16}:  ssa.OpMod16,
	{ir.OMOD, types.TUINT16}: ssa.OpMod16u,
	{ir.OMOD, types.TINT32}:  ssa.OpMod32,
	{ir.OMOD, types.TUINT32}: ssa.OpMod32u,
	{ir.OMOD, types.TINT64}:  ssa.OpMod64,
	{ir.OMOD, types.TUINT64}: ssa.OpMod64u,

	{ir.OAND, types.TINT8}:   ssa.OpAnd8,
	{ir.OAND, types.TUINT8}:  ssa.OpAnd8,
	{ir.OAND, types.TINT16}:  ssa.OpAnd16,
	{ir.OAND, types.TUINT16}: ssa.OpAnd16,
	{ir.OAND, types.TINT32}:  ssa.OpAnd32,
	{ir.OAND, types.TUINT32}: ssa.OpAnd32,
	{ir.OAND, types.TINT64}:  ssa.OpAnd64,
	{ir.OAND, types.TUINT64}: ssa.OpAnd64,

	{ir.OOR, types.TINT8}:   ssa.OpOr8,
	{ir.OOR, types.TUINT8}:  ssa.OpOr8,
	{ir.OOR, types.TINT16}:  ssa.OpOr16,
	{ir.OOR, types.TUINT16}: ssa.OpOr16,
	{ir.OOR, types.TINT32}:  ssa.OpOr32,
	{ir.OOR, types.TUINT32}: ssa.OpOr32,
	{ir.OOR, types.TINT64}:  ssa.OpOr64,
	{ir.OOR, types.TUINT64}: ssa.OpOr64,

	{ir.OXOR, types.TINT8}:   ssa.OpXor8,
	{ir.OXOR, types.TUINT8}:  ssa.OpXor8,
	{ir.OXOR, types.TINT16}:  ssa.OpXor16,
	{ir.OXOR, types.TUINT16}: ssa.OpXor16,
	{ir.OXOR, types.TINT32}:  ssa.OpXor32,
	{ir.OXOR, types.TUINT32}: ssa.OpXor32,
	{ir.OXOR, types.TINT64}:  ssa.OpXor64,
	{ir.OXOR, types.TUINT64}: ssa.OpXor64,

	{ir.OEQ, types.TBOOL}:      ssa.OpEqB,
	{ir.OEQ, types.TINT8}:      ssa.OpEq8,
	{ir.OEQ, types.TUINT8}:     ssa.OpEq8,
	{ir.OEQ, types.TINT16}:     ssa.OpEq16,
	{ir.OEQ, types.TUINT16}:    ssa.OpEq16,
	{ir.OEQ, types.TINT32}:     ssa.OpEq32,
	{ir.OEQ, types.TUINT32}:    ssa.OpEq32,
	{ir.OEQ, types.TINT64}:     ssa.OpEq64,
	{ir.OEQ, types.TUINT64}:    ssa.OpEq64,
	{ir.OEQ, types.TINTER}:     ssa.OpEqInter,
	{ir.OEQ, types.TSLICE}:     ssa.OpEqSlice,
	{ir.OEQ, types.TFUNC}:      ssa.OpEqPtr,
	{ir.OEQ, types.TMAP}:       ssa.OpEqPtr,
	{ir.OEQ, types.TCHAN}:      ssa.OpEqPtr,
	{ir.OEQ, types.TPTR}:       ssa.OpEqPtr,
	{ir.OEQ, types.TUINTPTR}:   ssa.OpEqPtr,
	{ir.OEQ, types.TUNSAFEPTR}: ssa.OpEqPtr,
	{ir.OEQ, types.TFLOAT64}:   ssa.OpEq64F,
	{ir.OEQ, types.TFLOAT32}:   ssa.OpEq32F,

	{ir.ONE, types.TBOOL}:      ssa.OpNeqB,
	{ir.ONE, types.TINT8}:      ssa.OpNeq8,
	{ir.ONE, types.TUINT8}:     ssa.OpNeq8,
	{ir.ONE, types.TINT16}:     ssa.OpNeq16,
	{ir.ONE, types.TUINT16}:    ssa.OpNeq16,
	{ir.ONE, types.TINT32}:     ssa.OpNeq32,
	{ir.ONE, types.TUINT32}:    ssa.OpNeq32,
	{ir.ONE, types.TINT64}:     ssa.OpNeq64,
	{ir.ONE, types.TUINT64}:    ssa.OpNeq64,
	{ir.ONE, types.TINTER}:     ssa.OpNeqInter,
	{ir.ONE, types.TSLICE}:     ssa.OpNeqSlice,
	{ir.ONE, types.TFUNC}:      ssa.OpNeqPtr,
	{ir.ONE, types.TMAP}:       ssa.OpNeqPtr,
	{ir.ONE, types.TCHAN}:      ssa.OpNeqPtr,
	{ir.ONE, types.TPTR}:       ssa.OpNeqPtr,
	{ir.ONE, types.TUINTPTR}:   ssa.OpNeqPtr,
	{ir.ONE, types.TUNSAFEPTR}: ssa.OpNeqPtr,
	{ir.ONE, types.TFLOAT64}:   ssa.OpNeq64F,
	{ir.ONE, types.TFLOAT32}:   ssa.OpNeq32F,

	{ir.OLT, types.TINT8}:    ssa.OpLess8,
	{ir.OLT, types.TUINT8}:   ssa.OpLess8U,
	{ir.OLT, types.TINT16}:   ssa.OpLess16,
	{ir.OLT, types.TUINT16}:  ssa.OpLess16U,
	{ir.OLT, types.TINT32}:   ssa.OpLess32,
	{ir.OLT, types.TUINT32}:  ssa.OpLess32U,
	{ir.OLT, types.TINT64}:   ssa.OpLess64,
	{ir.OLT, types.TUINT64}:  ssa.OpLess64U,
	{ir.OLT, types.TFLOAT64}: ssa.OpLess64F,
	{ir.OLT, types.TFLOAT32}: ssa.OpLess32F,

	{ir.OLE, types.TINT8}:    ssa.OpLeq8,
	{ir.OLE, types.TUINT8}:   ssa.OpLeq8U,
	{ir.OLE, types.TINT16}:   ssa.OpLeq16,
	{ir.OLE, types.TUINT16}:  ssa.OpLeq16U,
	{ir.OLE, types.TINT32}:   ssa.OpLeq32,
	{ir.OLE, types.TUINT32}:  ssa.OpLeq32U,
	{ir.OLE, types.TINT64}:   ssa.OpLeq64,
	{ir.OLE, types.TUINT64}:  ssa.OpLeq64U,
	{ir.OLE, types.TFLOAT64}: ssa.OpLeq64F,
	{ir.OLE, types.TFLOAT32}: ssa.OpLeq32F,
}

func (s *state) concreteEtype(t *types.Type) types.Kind {
	e := t.Kind()
	switch e {
	default:
		return e
	case types.TINT:
		if s.config.PtrSize == 8 {
			return types.TINT64
		}
		return types.TINT32
	case types.TUINT:
		if s.config.PtrSize == 8 {
			return types.TUINT64
		}
		return types.TUINT32
	case types.TUINTPTR:
		if s.config.PtrSize == 8 {
			return types.TUINT64
		}
		return types.TUINT32
	}
}

func (s *state) ssaOp(op ir.Op, t *types.Type) ssa.Op {
	etype := s.concreteEtype(t)
	x, ok := opToSSA[opAndType{op, etype}]
	if !ok {
		s.Fatalf("unhandled binary op %v %s", op, etype)
	}
	return x
}

type opAndTwoTypes struct {
	op     ir.Op
	etype1 types.Kind
	etype2 types.Kind
}

type twoTypes struct {
	etype1 types.Kind
	etype2 types.Kind
}

type twoOpsAndType struct {
	op1              ssa.Op
	op2              ssa.Op
	intermediateType types.Kind
}

var fpConvOpToSSA = map[twoTypes]twoOpsAndType{

	{types.TINT8, types.TFLOAT32}:  {ssa.OpSignExt8to32, ssa.OpCvt32to32F, types.TINT32},
	{types.TINT16, types.TFLOAT32}: {ssa.OpSignExt16to32, ssa.OpCvt32to32F, types.TINT32},
	{types.TINT32, types.TFLOAT32}: {ssa.OpCopy, ssa.OpCvt32to32F, types.TINT32},
	{types.TINT64, types.TFLOAT32}: {ssa.OpCopy, ssa.OpCvt64to32F, types.TINT64},

	{types.TINT8, types.TFLOAT64}:  {ssa.OpSignExt8to32, ssa.OpCvt32to64F, types.TINT32},
	{types.TINT16, types.TFLOAT64}: {ssa.OpSignExt16to32, ssa.OpCvt32to64F, types.TINT32},
	{types.TINT32, types.TFLOAT64}: {ssa.OpCopy, ssa.OpCvt32to64F, types.TINT32},
	{types.TINT64, types.TFLOAT64}: {ssa.OpCopy, ssa.OpCvt64to64F, types.TINT64},

	{types.TFLOAT32, types.TINT8}:  {ssa.OpCvt32Fto32, ssa.OpTrunc32to8, types.TINT32},
	{types.TFLOAT32, types.TINT16}: {ssa.OpCvt32Fto32, ssa.OpTrunc32to16, types.TINT32},
	{types.TFLOAT32, types.TINT32}: {ssa.OpCvt32Fto32, ssa.OpCopy, types.TINT32},
	{types.TFLOAT32, types.TINT64}: {ssa.OpCvt32Fto64, ssa.OpCopy, types.TINT64},

	{types.TFLOAT64, types.TINT8}:  {ssa.OpCvt64Fto32, ssa.OpTrunc32to8, types.TINT32},
	{types.TFLOAT64, types.TINT16}: {ssa.OpCvt64Fto32, ssa.OpTrunc32to16, types.TINT32},
	{types.TFLOAT64, types.TINT32}: {ssa.OpCvt64Fto32, ssa.OpCopy, types.TINT32},
	{types.TFLOAT64, types.TINT64}: {ssa.OpCvt64Fto64, ssa.OpCopy, types.TINT64},
	// unsigned
	{types.TUINT8, types.TFLOAT32}:  {ssa.OpZeroExt8to32, ssa.OpCvt32to32F, types.TINT32},
	{types.TUINT16, types.TFLOAT32}: {ssa.OpZeroExt16to32, ssa.OpCvt32to32F, types.TINT32},
	{types.TUINT32, types.TFLOAT32}: {ssa.OpZeroExt32to64, ssa.OpCvt64to32F, types.TINT64}, // go wide to dodge unsigned
	{types.TUINT64, types.TFLOAT32}: {ssa.OpCopy, ssa.OpInvalid, types.TUINT64},            // Cvt64Uto32F, branchy code expansion instead

	{types.TUINT8, types.TFLOAT64}:  {ssa.OpZeroExt8to32, ssa.OpCvt32to64F, types.TINT32},
	{types.TUINT16, types.TFLOAT64}: {ssa.OpZeroExt16to32, ssa.OpCvt32to64F, types.TINT32},
	{types.TUINT32, types.TFLOAT64}: {ssa.OpZeroExt32to64, ssa.OpCvt64to64F, types.TINT64}, // go wide to dodge unsigned
	{types.TUINT64, types.TFLOAT64}: {ssa.OpCopy, ssa.OpInvalid, types.TUINT64},            // Cvt64Uto64F, branchy code expansion instead

	{types.TFLOAT32, types.TUINT8}:  {ssa.OpCvt32Fto32, ssa.OpTrunc32to8, types.TINT32},
	{types.TFLOAT32, types.TUINT16}: {ssa.OpCvt32Fto32, ssa.OpTrunc32to16, types.TINT32},
	{types.TFLOAT32, types.TUINT32}: {ssa.OpCvt32Fto64, ssa.OpTrunc64to32, types.TINT64}, // go wide to dodge unsigned
	{types.TFLOAT32, types.TUINT64}: {ssa.OpInvalid, ssa.OpCopy, types.TUINT64},          // Cvt32Fto64U, branchy code expansion instead

	{types.TFLOAT64, types.TUINT8}:  {ssa.OpCvt64Fto32, ssa.OpTrunc32to8, types.TINT32},
	{types.TFLOAT64, types.TUINT16}: {ssa.OpCvt64Fto32, ssa.OpTrunc32to16, types.TINT32},
	{types.TFLOAT64, types.TUINT32}: {ssa.OpCvt64Fto64, ssa.OpTrunc64to32, types.TINT64}, // go wide to dodge unsigned
	{types.TFLOAT64, types.TUINT64}: {ssa.OpInvalid, ssa.OpCopy, types.TUINT64},          // Cvt64Fto64U, branchy code expansion instead

	// float
	{types.TFLOAT64, types.TFLOAT32}: {ssa.OpCvt64Fto32F, ssa.OpCopy, types.TFLOAT32},
	{types.TFLOAT64, types.TFLOAT64}: {ssa.OpRound64F, ssa.OpCopy, types.TFLOAT64},
	{types.TFLOAT32, types.TFLOAT32}: {ssa.OpRound32F, ssa.OpCopy, types.TFLOAT32},
	{types.TFLOAT32, types.TFLOAT64}: {ssa.OpCvt32Fto64F, ssa.OpCopy, types.TFLOAT64},
}

// this map is used only for 32-bit arch, and only includes the difference
// on 32-bit arch, don't use int64<->float conversion for uint32
var fpConvOpToSSA32 = map[twoTypes]twoOpsAndType{
	{types.TUINT32, types.TFLOAT32}: {ssa.OpCopy, ssa.OpCvt32Uto32F, types.TUINT32},
	{types.TUINT32, types.TFLOAT64}: {ssa.OpCopy, ssa.OpCvt32Uto64F, types.TUINT32},
	{types.TFLOAT32, types.TUINT32}: {ssa.OpCvt32Fto32U, ssa.OpCopy, types.TUINT32},
	{types.TFLOAT64, types.TUINT32}: {ssa.OpCvt64Fto32U, ssa.OpCopy, types.TUINT32},
}

// uint64<->float conversions, only on machines that have instructions for that
var uint64fpConvOpToSSA = map[twoTypes]twoOpsAndType{
	{types.TUINT64, types.TFLOAT32}: {ssa.OpCopy, ssa.OpCvt64Uto32F, types.TUINT64},
	{types.TUINT64, types.TFLOAT64}: {ssa.OpCopy, ssa.OpCvt64Uto64F, types.TUINT64},
	{types.TFLOAT32, types.TUINT64}: {ssa.OpCvt32Fto64U, ssa.OpCopy, types.TUINT64},
	{types.TFLOAT64, types.TUINT64}: {ssa.OpCvt64Fto64U, ssa.OpCopy, types.TUINT64},
}

var shiftOpToSSA = map[opAndTwoTypes]ssa.Op{
	{ir.OLSH, types.TINT8, types.TUINT8}:   ssa.OpLsh8x8,
	{ir.OLSH, types.TUINT8, types.TUINT8}:  ssa.OpLsh8x8,
	{ir.OLSH, types.TINT8, types.TUINT16}:  ssa.OpLsh8x16,
	{ir.OLSH, types.TUINT8, types.TUINT16}: ssa.OpLsh8x16,
	{ir.OLSH, types.TINT8, types.TUINT32}:  ssa.OpLsh8x32,
	{ir.OLSH, types.TUINT8, types.TUINT32}: ssa.OpLsh8x32,
	{ir.OLSH, types.TINT8, types.TUINT64}:  ssa.OpLsh8x64,
	{ir.OLSH, types.TUINT8, types.TUINT64}: ssa.OpLsh8x64,

	{ir.OLSH, types.TINT16, types.TUINT8}:   ssa.OpLsh16x8,
	{ir.OLSH, types.TUINT16, types.TUINT8}:  ssa.OpLsh16x8,
	{ir.OLSH, types.TINT16, types.TUINT16}:  ssa.OpLsh16x16,
	{ir.OLSH, types.TUINT16, types.TUINT16}: ssa.OpLsh16x16,
	{ir.OLSH, types.TINT16, types.TUINT32}:  ssa.OpLsh16x32,
	{ir.OLSH, types.TUINT16, types.TUINT32}: ssa.OpLsh16x32,
	{ir.OLSH, types.TINT16, types.TUINT64}:  ssa.OpLsh16x64,
	{ir.OLSH, types.TUINT16, types.TUINT64}: ssa.OpLsh16x64,

	{ir.OLSH, types.TINT32, types.TUINT8}:   ssa.OpLsh32x8,
	{ir.OLSH, types.TUINT32, types.TUINT8}:  ssa.OpLsh32x8,
	{ir.OLSH, types.TINT32, types.TUINT16}:  ssa.OpLsh32x16,
	{ir.OLSH, types.TUINT32, types.TUINT16}: ssa.OpLsh32x16,
	{ir.OLSH, types.TINT32, types.TUINT32}:  ssa.OpLsh32x32,
	{ir.OLSH, types.TUINT32, types.TUINT32}: ssa.OpLsh32x32,
	{ir.OLSH, types.TINT32, types.TUINT64}:  ssa.OpLsh32x64,
	{ir.OLSH, types.TUINT32, types.TUINT64}: ssa.OpLsh32x64,

	{ir.OLSH, types.TINT64, types.TUINT8}:   ssa.OpLsh64x8,
	{ir.OLSH, types.TUINT64, types.TUINT8}:  ssa.OpLsh64x8,
	{ir.OLSH, types.TINT64, types.TUINT16}:  ssa.OpLsh64x16,
	{ir.OLSH, types.TUINT64, types.TUINT16}: ssa.OpLsh64x16,
	{ir.OLSH, types.TINT64, types.TUINT32}:  ssa.OpLsh64x32,
	{ir.OLSH, types.TUINT64, types.TUINT32}: ssa.OpLsh64x32,
	{ir.OLSH, types.TINT64, types.TUINT64}:  ssa.OpLsh64x64,
	{ir.OLSH, types.TUINT64, types.TUINT64}: ssa.OpLsh64x64,

	{ir.ORSH, types.TINT8, types.TUINT8}:   ssa.OpRsh8x8,
	{ir.ORSH, types.TUINT8, types.TUINT8}:  ssa.OpRsh8Ux8,
	{ir.ORSH, types.TINT8, types.TUINT16}:  ssa.OpRsh8x16,
	{ir.ORSH, types.TUINT8, types.TUINT16}: ssa.OpRsh8Ux16,
	{ir.ORSH, types.TINT8, types.TUINT32}:  ssa.OpRsh8x32,
	{ir.ORSH, types.TUINT8, types.TUINT32}: ssa.OpRsh8Ux32,
	{ir.ORSH, types.TINT8, types.TUINT64}:  ssa.OpRsh8x64,
	{ir.ORSH, types.TUINT8, types.TUINT64}: ssa.OpRsh8Ux64,

	{ir.ORSH, types.TINT16, types.TUINT8}:   ssa.OpRsh16x8,
	{ir.ORSH, types.TUINT16, types.TUINT8}:  ssa.OpRsh16Ux8,
	{ir.ORSH, types.TINT16, types.TUINT16}:  ssa.OpRsh16x16,
	{ir.ORSH, types.TUINT16, types.TUINT16}: ssa.OpRsh16Ux16,
	{ir.ORSH, types.TINT16, types.TUINT32}:  ssa.OpRsh16x32,
	{ir.ORSH, types.TUINT16, types.TUINT32}: ssa.OpRsh16Ux32,
	{ir.ORSH, types.TINT16, types.TUINT64}:  ssa.OpRsh16x64,
	{ir.ORSH, types.TUINT16, types.TUINT64}: ssa.OpRsh16Ux64,

	{ir.ORSH, types.TINT32, types.TUINT8}:   ssa.OpRsh32x8,
	{ir.ORSH, types.TUINT32, types.TUINT8}:  ssa.OpRsh32Ux8,
	{ir.ORSH, types.TINT32, types.TUINT16}:  ssa.OpRsh32x16,
	{ir.ORSH, types.TUINT32, types.TUINT16}: ssa.OpRsh32Ux16,
	{ir.ORSH, types.TINT32, types.TUINT32}:  ssa.OpRsh32x32,
	{ir.ORSH, types.TUINT32, types.TUINT32}: ssa.OpRsh32Ux32,
	{ir.ORSH, types.TINT32, types.TUINT64}:  ssa.OpRsh32x64,
	{ir.ORSH, types.TUINT32, types.TUINT64}: ssa.OpRsh32Ux64,

	{ir.ORSH, types.TINT64, types.TUINT8}:   ssa.OpRsh64x8,
	{ir.ORSH, types.TUINT64, types.TUINT8}:  ssa.OpRsh64Ux8,
	{ir.ORSH, types.TINT64, types.TUINT16}:  ssa.OpRsh64x16,
	{ir.ORSH, types.TUINT64, types.TUINT16}: ssa.OpRsh64Ux16,
	{ir.ORSH, types.TINT64, types.TUINT32}:  ssa.OpRsh64x32,
	{ir.ORSH, types.TUINT64, types.TUINT32}: ssa.OpRsh64Ux32,
	{ir.ORSH, types.TINT64, types.TUINT64}:  ssa.OpRsh64x64,
	{ir.ORSH, types.TUINT64, types.TUINT64}: ssa.OpRsh64Ux64,
}

func (s *state) ssaShiftOp(op ir.Op, t *types.Type, u *types.Type) ssa.Op {
	etype1 := s.concreteEtype(t)
	etype2 := s.concreteEtype(u)
	x, ok := shiftOpToSSA[opAndTwoTypes{op, etype1, etype2}]
	if !ok {
		s.Fatalf("unhandled shift op %v etype=%s/%s", op, etype1, etype2)
	}
	return x
}

func (s *state) uintptrConstant(v uint64) *ssa.Value {
	if s.config.PtrSize == 4 {
		return s.newValue0I(ssa.OpConst32, types.Types[types.TUINTPTR], int64(v))
	}
	return s.newValue0I(ssa.OpConst64, types.Types[types.TUINTPTR], int64(v))
}

func (s *state) conv(n ir.Node, v *ssa.Value, ft, tt *types.Type) *ssa.Value {
	if ft.IsBoolean() && tt.IsKind(types.TUINT8) {
		// Bool -> uint8 is generated internally when indexing into runtime.staticbyte.
		return s.newValue1(ssa.OpCvtBoolToUint8, tt, v)
	}
	if ft.IsInteger() && tt.IsInteger() {
		var op ssa.Op
		if tt.Size() == ft.Size() {
			op = ssa.OpCopy
		} else if tt.Size() < ft.Size() {
			// truncation
			switch 10*ft.Size() + tt.Size() {
			case 21:
				op = ssa.OpTrunc16to8
			case 41:
				op = ssa.OpTrunc32to8
			case 42:
				op = ssa.OpTrunc32to16
			case 81:
				op = ssa.OpTrunc64to8
			case 82:
				op = ssa.OpTrunc64to16
			case 84:
				op = ssa.OpTrunc64to32
			default:
				s.Fatalf("weird integer truncation %v -> %v", ft, tt)
			}
		} else if ft.IsSigned() {
			// sign extension
			switch 10*ft.Size() + tt.Size() {
			case 12:
				op = ssa.OpSignExt8to16
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
				s.Fatalf("bad integer sign extension %v -> %v", ft, tt)
			}
		} else {
			// zero extension
			switch 10*ft.Size() + tt.Size() {
			case 12:
				op = ssa.OpZeroExt8to16
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
				s.Fatalf("weird integer sign extension %v -> %v", ft, tt)
			}
		}
		return s.newValue1(op, tt, v)
	}

	if ft.IsComplex() && tt.IsComplex() {
		var op ssa.Op
		if ft.Size() == tt.Size() {
			switch ft.Size() {
			case 8:
				op = ssa.OpRound32F
			case 16:
				op = ssa.OpRound64F
			default:
				s.Fatalf("weird complex conversion %v -> %v", ft, tt)
			}
		} else if ft.Size() == 8 && tt.Size() == 16 {
			op = ssa.OpCvt32Fto64F
		} else if ft.Size() == 16 && tt.Size() == 8 {
			op = ssa.OpCvt64Fto32F
		} else {
			s.Fatalf("weird complex conversion %v -> %v", ft, tt)
		}
		ftp := types.FloatForComplex(ft)
		ttp := types.FloatForComplex(tt)
		return s.newValue2(ssa.OpComplexMake, tt,
			s.newValueOrSfCall1(op, ttp, s.newValue1(ssa.OpComplexReal, ftp, v)),
			s.newValueOrSfCall1(op, ttp, s.newValue1(ssa.OpComplexImag, ftp, v)))
	}

	if tt.IsComplex() { // and ft is not complex
		// Needed for generics support - can't happen in normal Go code.
		et := types.FloatForComplex(tt)
		v = s.conv(n, v, ft, et)
		return s.newValue2(ssa.OpComplexMake, tt, v, s.zeroVal(et))
	}

	if ft.IsFloat() || tt.IsFloat() {
		conv, ok := fpConvOpToSSA[twoTypes{s.concreteEtype(ft), s.concreteEtype(tt)}]
		if s.config.RegSize == 4 && Arch.LinkArch.Family != sys.MIPS && !s.softFloat {
			if conv1, ok1 := fpConvOpToSSA32[twoTypes{s.concreteEtype(ft), s.concreteEtype(tt)}]; ok1 {
				conv = conv1
			}
		}
		if Arch.LinkArch.Family == sys.ARM64 || Arch.LinkArch.Family == sys.Wasm || Arch.LinkArch.Family == sys.S390X || s.softFloat {
			if conv1, ok1 := uint64fpConvOpToSSA[twoTypes{s.concreteEtype(ft), s.concreteEtype(tt)}]; ok1 {
				conv = conv1
			}
		}

		if Arch.LinkArch.Family == sys.MIPS && !s.softFloat {
			if ft.Size() == 4 && ft.IsInteger() && !ft.IsSigned() {
				// tt is float32 or float64, and ft is also unsigned
				if tt.Size() == 4 {
					return s.uint32Tofloat32(n, v, ft, tt)
				}
				if tt.Size() == 8 {
					return s.uint32Tofloat64(n, v, ft, tt)
				}
			} else if tt.Size() == 4 && tt.IsInteger() && !tt.IsSigned() {
				// ft is float32 or float64, and tt is unsigned integer
				if ft.Size() == 4 {
					return s.float32ToUint32(n, v, ft, tt)
				}
				if ft.Size() == 8 {
					return s.float64ToUint32(n, v, ft, tt)
				}
			}
		}

		if !ok {
			s.Fatalf("weird float conversion %v -> %v", ft, tt)
		}
		op1, op2, it := conv.op1, conv.op2, conv.intermediateType

		if op1 != ssa.OpInvalid && op2 != ssa.OpInvalid {
			// normal case, not tripping over unsigned 64
			if op1 == ssa.OpCopy {
				if op2 == ssa.OpCopy {
					return v
				}
				return s.newValueOrSfCall1(op2, tt, v)
			}
			if op2 == ssa.OpCopy {
				return s.newValueOrSfCall1(op1, tt, v)
			}
			return s.newValueOrSfCall1(op2, tt, s.newValueOrSfCall1(op1, types.Types[it], v))
		}
		// Tricky 64-bit unsigned cases.
		if ft.IsInteger() {
			// tt is float32 or float64, and ft is also unsigned
			if tt.Size() == 4 {
				return s.uint64Tofloat32(n, v, ft, tt)
			}
			if tt.Size() == 8 {
				return s.uint64Tofloat64(n, v, ft, tt)
			}
			s.Fatalf("weird unsigned integer to float conversion %v -> %v", ft, tt)
		}
		// ft is float32 or float64, and tt is unsigned integer
		if ft.Size() == 4 {
			return s.float32ToUint64(n, v, ft, tt)
		}
		if ft.Size() == 8 {
			return s.float64ToUint64(n, v, ft, tt)
		}
		s.Fatalf("weird float to unsigned integer conversion %v -> %v", ft, tt)
		return nil
	}

	s.Fatalf("unhandled OCONV %s -> %s", ft.Kind(), tt.Kind())
	return nil
}

// expr converts the expression n to ssa, adds it to s and returns the ssa result.
func (s *state) expr(n ir.Node) *ssa.Value {
	return s.exprCheckPtr(n, true)
}

func (s *state) exprCheckPtr(n ir.Node, checkPtrOK bool) *ssa.Value {
	if ir.HasUniquePos(n) {
		// ONAMEs and named OLITERALs have the line number
		// of the decl, not the use. See issue 14742.
		s.pushLine(n.Pos())
		defer s.popLine()
	}

	s.stmtList(n.Init())
	switch n.Op() {
	case ir.OBYTES2STRTMP:
		n := n.(*ir.ConvExpr)
		slice := s.expr(n.X)
		ptr := s.newValue1(ssa.OpSlicePtr, s.f.Config.Types.BytePtr, slice)
		len := s.newValue1(ssa.OpSliceLen, types.Types[types.TINT], slice)
		return s.newValue2(ssa.OpStringMake, n.Type(), ptr, len)
	case ir.OSTR2BYTESTMP:
		n := n.(*ir.ConvExpr)
		str := s.expr(n.X)
		ptr := s.newValue1(ssa.OpStringPtr, s.f.Config.Types.BytePtr, str)
		if !n.NonNil() {
			// We need to ensure []byte("") evaluates to []byte{}, and not []byte(nil).
			//
			// TODO(mdempsky): Investigate using "len != 0" instead of "ptr != nil".
			cond := s.newValue2(ssa.OpNeqPtr, types.Types[types.TBOOL], ptr, s.constNil(ptr.Type))
			zerobase := s.newValue1A(ssa.OpAddr, ptr.Type, ir.Syms.Zerobase, s.sb)
			ptr = s.ternary(cond, ptr, zerobase)
		}
		len := s.newValue1(ssa.OpStringLen, types.Types[types.TINT], str)
		return s.newValue3(ssa.OpSliceMake, n.Type(), ptr, len, len)
	case ir.OCFUNC:
		n := n.(*ir.UnaryExpr)
		aux := n.X.(*ir.Name).Linksym()
		// OCFUNC is used to build function values, which must
		// always reference ABIInternal entry points.
		if aux.ABI() != obj.ABIInternal {
			s.Fatalf("expected ABIInternal: %v", aux.ABI())
		}
		return s.entryNewValue1A(ssa.OpAddr, n.Type(), aux, s.sb)
	case ir.ONAME:
		n := n.(*ir.Name)
		if n.Class == ir.PFUNC {
			// "value" of a function is the address of the function's closure
			sym := staticdata.FuncLinksym(n)
			return s.entryNewValue1A(ssa.OpAddr, types.NewPtr(n.Type()), sym, s.sb)
		}
		if s.canSSA(n) {
			return s.variable(n, n.Type())
		}
		return s.load(n.Type(), s.addr(n))
	case ir.OLINKSYMOFFSET:
		n := n.(*ir.LinksymOffsetExpr)
		return s.load(n.Type(), s.addr(n))
	case ir.ONIL:
		n := n.(*ir.NilExpr)
		t := n.Type()
		switch {
		case t.IsSlice():
			return s.constSlice(t)
		case t.IsInterface():
			return s.constInterface(t)
		default:
			return s.constNil(t)
		}
	case ir.OLITERAL:
		switch u := n.Val(); u.Kind() {
		case constant.Int:
			i := ir.IntVal(n.Type(), u)
			switch n.Type().Size() {
			case 1:
				return s.constInt8(n.Type(), int8(i))
			case 2:
				return s.constInt16(n.Type(), int16(i))
			case 4:
				return s.constInt32(n.Type(), int32(i))
			case 8:
				return s.constInt64(n.Type(), i)
			default:
				s.Fatalf("bad integer size %d", n.Type().Size())
				return nil
			}
		case constant.String:
			i := constant.StringVal(u)
			if i == "" {
				return s.constEmptyString(n.Type())
			}
			return s.entryNewValue0A(ssa.OpConstString, n.Type(), ssa.StringToAux(i))
		case constant.Bool:
			return s.constBool(constant.BoolVal(u))
		case constant.Float:
			f, _ := constant.Float64Val(u)
			switch n.Type().Size() {
			case 4:
				return s.constFloat32(n.Type(), f)
			case 8:
				return s.constFloat64(n.Type(), f)
			default:
				s.Fatalf("bad float size %d", n.Type().Size())
				return nil
			}
		case constant.Complex:
			re, _ := constant.Float64Val(constant.Real(u))
			im, _ := constant.Float64Val(constant.Imag(u))
			switch n.Type().Size() {
			case 8:
				pt := types.Types[types.TFLOAT32]
				return s.newValue2(ssa.OpComplexMake, n.Type(),
					s.constFloat32(pt, re),
					s.constFloat32(pt, im))
			case 16:
				pt := types.Types[types.TFLOAT64]
				return s.newValue2(ssa.OpComplexMake, n.Type(),
					s.constFloat64(pt, re),
					s.constFloat64(pt, im))
			default:
				s.Fatalf("bad complex size %d", n.Type().Size())
				return nil
			}
		default:
			s.Fatalf("unhandled OLITERAL %v", u.Kind())
			return nil
		}
	case ir.OCONVNOP:
		n := n.(*ir.ConvExpr)
		to := n.Type()
		from := n.X.Type()

		// Assume everything will work out, so set up our return value.
		// Anything interesting that happens from here is a fatal.
		x := s.expr(n.X)
		if to == from {
			return x
		}

		// Special case for not confusing GC and liveness.
		// We don't want pointers accidentally classified
		// as not-pointers or vice-versa because of copy
		// elision.
		if to.IsPtrShaped() != from.IsPtrShaped() {
			return s.newValue2(ssa.OpConvert, to, x, s.mem())
		}

		v := s.newValue1(ssa.OpCopy, to, x) // ensure that v has the right type

		// CONVNOP closure
		if to.Kind() == types.TFUNC && from.IsPtrShaped() {
			return v
		}

		// named <--> unnamed type or typed <--> untyped const
		if from.Kind() == to.Kind() {
			return v
		}

		// unsafe.Pointer <--> *T
		if to.IsUnsafePtr() && from.IsPtrShaped() || from.IsUnsafePtr() && to.IsPtrShaped() {
			if s.checkPtrEnabled && checkPtrOK && to.IsPtr() && from.IsUnsafePtr() {
				s.checkPtrAlignment(n, v, nil)
			}
			return v
		}

		// map <--> *hmap
		var mt *types.Type
		if buildcfg.Experiment.SwissMap {
			mt = types.NewPtr(reflectdata.SwissMapType())
		} else {
			mt = types.NewPtr(reflectdata.OldMapType())
		}
		if to.Kind() == types.TMAP && from == mt {
			return v
		}

		types.CalcSize(from)
		types.CalcSize(to)
		if from.Size() != to.Size() {
			s.Fatalf("CONVNOP width mismatch %v (%d) -> %v (%d)\n", from, from.Size(), to, to.Size())
			return nil
		}
		if etypesign(from.Kind()) != etypesign(to.Kind()) {
			s.Fatalf("CONVNOP sign mismatch %v (%s) -> %v (%s)\n", from, from.Kind(), to, to.Kind())
			return nil
		}

		if base.Flag.Cfg.Instrumenting {
			// These appear to be fine, but they fail the
			// integer constraint below, so okay them here.
			// Sample non-integer conversion: map[string]string -> *uint8
			return v
		}

		if etypesign(from.Kind()) == 0 {
			s.Fatalf("CONVNOP unrecognized non-integer %v -> %v\n", from, to)
			return nil
		}

		// integer, same width, same sign
		return v

	case ir.OCONV:
		n := n.(*ir.ConvExpr)
		x := s.expr(n.X)
		return s.conv(n, x, n.X.Type(), n.Type())

	case ir.ODOTTYPE:
		n := n.(*ir.TypeAssertExpr)
		res, _ := s.dottype(n, false)
		return res

	case ir.ODYNAMICDOTTYPE:
		n := n.(*ir.DynamicTypeAssertExpr)
		res, _ := s.dynamicDottype(n, false)
		return res

	// binary ops
	case ir.OLT, ir.OEQ, ir.ONE, ir.OLE, ir.OGE, ir.OGT:
		n := n.(*ir.BinaryExpr)
		a := s.expr(n.X)
		b := s.expr(n.Y)
		if n.X.Type().IsComplex() {
			pt := types.FloatForComplex(n.X.Type())
			op := s.ssaOp(ir.OEQ, pt)
			r := s.newValueOrSfCall2(op, types.Types[types.TBOOL], s.newValue1(ssa.OpComplexReal, pt, a), s.newValue1(ssa.OpComplexReal, pt, b))
			i := s.newValueOrSfCall2(op, types.Types[types.TBOOL], s.newValue1(ssa.OpComplexImag, pt, a), s.newValue1(ssa.OpComplexImag, pt, b))
			c := s.newValue2(ssa.OpAndB, types.Types[types.TBOOL], r, i)
			switch n.Op() {
			case ir.OEQ:
				return c
			case ir.ONE:
				return s.newValue1(ssa.OpNot, types.Types[types.TBOOL], c)
			default:
				s.Fatalf("ordered complex compare %v", n.Op())
			}
		}

		// Convert OGE and OGT into OLE and OLT.
		op := n.Op()
		switch op {
		case ir.OGE:
			op, a, b = ir.OLE, b, a
		case ir.OGT:
			op, a, b = ir.OLT, b, a
		}
		if n.X.Type().IsFloat() {
			// float comparison
			return s.newValueOrSfCall2(s.ssaOp(op, n.X.Type()), types.Types[types.TBOOL], a, b)
		}
		// integer comparison
		return s.newValue2(s.ssaOp(op, n.X.Type()), types.Types[types.TBOOL], a, b)
	case ir.OMUL:
		n := n.(*ir.BinaryExpr)
		a := s.expr(n.X)
		b := s.expr(n.Y)
		if n.Type().IsComplex() {
			mulop := ssa.OpMul64F
			addop := ssa.OpAdd64F
			subop := ssa.OpSub64F
			pt := types.FloatForComplex(n.Type()) // Could be Float32 or Float64
			wt := types.Types[types.TFLOAT64]     // Compute in Float64 to minimize cancellation error

			areal := s.newValue1(ssa.OpComplexReal, pt, a)
			breal := s.newValue1(ssa.OpComplexReal, pt, b)
			aimag := s.newValue1(ssa.OpComplexImag, pt, a)
			bimag := s.newValue1(ssa.OpComplexImag, pt, b)

			if pt != wt { // Widen for calculation
				areal = s.newValueOrSfCall1(ssa.OpCvt32Fto64F, wt, areal)
				breal = s.newValueOrSfCall1(ssa.OpCvt32Fto64F, wt, breal)
				aimag = s.newValueOrSfCall1(ssa.OpCvt32Fto64F, wt, aimag)
				bimag = s.newValueOrSfCall1(ssa.OpCvt32Fto64F, wt, bimag)
			}

			xreal := s.newValueOrSfCall2(subop, wt, s.newValueOrSfCall2(mulop, wt, areal, breal), s.newValueOrSfCall2(mulop, wt, aimag, bimag))
			ximag := s.newValueOrSfCall2(addop, wt, s.newValueOrSfCall2(mulop, wt, areal, bimag), s.newValueOrSfCall2(mulop, wt, aimag, breal))

			if pt != wt { // Narrow to store back
				xreal = s.newValueOrSfCall1(ssa.OpCvt64Fto32F, pt, xreal)
				ximag = s.newValueOrSfCall1(ssa.OpCvt64Fto32F, pt, ximag)
			}

			return s.newValue2(ssa.OpComplexMake, n.Type(), xreal, ximag)
		}

		if n.Type().IsFloat() {
			return s.newValueOrSfCall2(s.ssaOp(n.Op(), n.Type()), a.Type, a, b)
		}

		return s.newValue2(s.ssaOp(n.Op(), n.Type()), a.Type, a, b)

	case ir.ODIV:
		n := n.(*ir.BinaryExpr)
		a := s.expr(n.X)
		b := s.expr(n.Y)
		if n.Type().IsComplex() {
			// TODO this is not executed because the front-end substitutes a runtime call.
			// That probably ought to change; with modest optimization the widen/narrow
			// conversions could all be elided in larger expression trees.
			mulop := ssa.OpMul64F
			addop := ssa.OpAdd64F
			subop := ssa.OpSub64F
			divop := ssa.OpDiv64F
			pt := types.FloatForComplex(n.Type()) // Could be Float32 or Float64
			wt := types.Types[types.TFLOAT64]     // Compute in Float64 to minimize cancellation error

			areal := s.newValue1(ssa.OpComplexReal, pt, a)
			breal := s.newValue1(ssa.OpComplexReal, pt, b)
			aimag := s.newValue1(ssa.OpComplexImag, pt, a)
			bimag := s.newValue1(ssa.OpComplexImag, pt, b)

			if pt != wt { // Widen for calculation
				areal = s.newValueOrSfCall1(ssa.OpCvt32Fto64F, wt, areal)
				breal = s.newValueOrSfCall1(ssa.OpCvt32Fto64F, wt, breal)
				aimag = s.newValueOrSfCall1(ssa.OpCvt32Fto64F, wt, aimag)
				bimag = s.newValueOrSfCall1(ssa.OpCvt32Fto64F, wt, bimag)
			}

			denom := s.newValueOrSfCall2(addop, wt, s.newValueOrSfCall2(mulop, wt, breal, breal), s.newValueOrSfCall2(mulop, wt, bimag, bimag))
			xreal := s.newValueOrSfCall2(addop, wt, s.newValueOrSfCall2(mulop, wt, areal, breal), s.newValueOrSfCall2(mulop, wt, aimag, bimag))
			ximag := s.newValueOrSfCall2(subop, wt, s.newValueOrSfCall2(mulop, wt, aimag, breal), s.newValueOrSfCall2(mulop, wt, areal, bimag))

			// TODO not sure if this is best done in wide precision or narrow
			// Double-rounding might be an issue.
			// Note that the pre-SSA implementation does the entire calculation
			// in wide format, so wide is compatible.
			xreal = s.newValueOrSfCall2(divop, wt, xreal, denom)
			ximag = s.newValueOrSfCall2(divop, wt, ximag, denom)

			if pt != wt { // Narrow to store back
				xreal = s.newValueOrSfCall1(ssa.OpCvt64Fto32F, pt, xreal)
				ximag = s.newValueOrSfCall1(ssa.OpCvt64Fto32F, pt, ximag)
			}
			return s.newValue2(ssa.OpComplexMake, n.Type(), xreal, ximag)
		}
		if n.Type().IsFloat() {
			return s.newValueOrSfCall2(s.ssaOp(n.Op(), n.Type()), a.Type, a, b)
		}
		return s.intDivide(n, a, b)
	case ir.OMOD:
		n := n.(*ir.BinaryExpr)
		a := s.expr(n.X)
		b := s.expr(n.Y)
		return s.intDivide(n, a, b)
	case ir.OADD, ir.OSUB:
		n := n.(*ir.BinaryExpr)
		a := s.expr(n.X)
		b := s.expr(n.Y)
		if n.Type().IsComplex() {
			pt := types.FloatForComplex(n.Type())
			op := s.ssaOp(n.Op(), pt)
			return s.newValue2(ssa.OpComplexMake, n.Type(),
				s.newValueOrSfCall2(op, pt, s.newValue1(ssa.OpComplexReal, pt, a), s.newValue1(ssa.OpComplexReal, pt, b)),
				s.newValueOrSfCall2(op, pt, s.newValue1(ssa.OpComplexImag, pt, a), s.newValue1(ssa.OpComplexImag, pt, b)))
		}
		if n.Type().IsFloat() {
			return s.newValueOrSfCall2(s.ssaOp(n.Op(), n.Type()), a.Type, a, b)
		}
		return s.newValue2(s.ssaOp(n.Op(), n.Type()), a.Type, a, b)
	case ir.OAND, ir.OOR, ir.OXOR:
		n := n.(*ir.BinaryExpr)
		a := s.expr(n.X)
		b := s.expr(n.Y)
		return s.newValue2(s.ssaOp(n.Op(), n.Type()), a.Type, a, b)
	case ir.OANDNOT:
		n := n.(*ir.BinaryExpr)
		a := s.expr(n.X)
		b := s.expr(n.Y)
		b = s.newValue1(s.ssaOp(ir.OBITNOT, b.Type), b.Type, b)
		return s.newValue2(s.ssaOp(ir.OAND, n.Type()), a.Type, a, b)
	case ir.OLSH, ir.ORSH:
		n := n.(*ir.BinaryExpr)
		a := s.expr(n.X)
		b := s.expr(n.Y)
		bt := b.Type
		if bt.IsSigned() {
			cmp := s.newValue2(s.ssaOp(ir.OLE, bt), types.Types[types.TBOOL], s.zeroVal(bt), b)
			s.check(cmp, ir.Syms.Panicshift)
			bt = bt.ToUnsigned()
		}
		return s.newValue2(s.ssaShiftOp(n.Op(), n.Type(), bt), a.Type, a, b)
	case ir.OANDAND, ir.OOROR:
		// To implement OANDAND (and OOROR), we introduce a
		// new temporary variable to hold the result. The
		// variable is associated with the OANDAND node in the
		// s.vars table (normally variables are only
		// associated with ONAME nodes). We convert
		//     A && B
		// to
		//     var = A
		//     if var {
		//         var = B
		//     }
		// Using var in the subsequent block introduces the
		// necessary phi variable.
		n := n.(*ir.LogicalExpr)
		el := s.expr(n.X)
		s.vars[n] = el

		b := s.endBlock()
		b.Kind = ssa.BlockIf
		b.SetControl(el)
		// In theory, we should set b.Likely here based on context.
		// However, gc only gives us likeliness hints
		// in a single place, for plain OIF statements,
		// and passing around context is finicky, so don't bother for now.

		bRight := s.f.NewBlock(ssa.BlockPlain)
		bResult := s.f.NewBlock(ssa.BlockPlain)
		if n.Op() == ir.OANDAND {
			b.AddEdgeTo(bRight)
			b.AddEdgeTo(bResult)
		} else if n.Op() == ir.OOROR {
			b.AddEdgeTo(bResult)
			b.AddEdgeTo(bRight)
		}

		s.startBlock(bRight)
		er := s.expr(n.Y)
		s.vars[n] = er

		b = s.endBlock()
		b.AddEdgeTo(bResult)

		s.startBlock(bResult)
		return s.variable(n, types.Types[types.TBOOL])
	case ir.OCOMPLEX:
		n := n.(*ir.BinaryExpr)
		r := s.expr(n.X)
		i := s.expr(n.Y)
		return s.newValue2(ssa.OpComplexMake, n.Type(), r, i)

	// unary ops
	case ir.ONEG:
		n := n.(*ir.UnaryExpr)
		a := s.expr(n.X)
		if n.Type().IsComplex() {
			tp := types.FloatForComplex(n.Type())
			negop := s.ssaOp(n.Op(), tp)
			return s.newValue2(ssa.OpComplexMake, n.Type(),
				s.newValue1(negop, tp, s.newValue1(ssa.OpComplexReal, tp, a)),
				s.newValue1(negop, tp, s.newValue1(ssa.OpComplexImag, tp, a)))
		}
		return s.newValue1(s.ssaOp(n.Op(), n.Type()), a.Type, a)
	case ir.ONOT, ir.OBITNOT:
		n := n.(*ir.UnaryExpr)
		a := s.expr(n.X)
		return s.newValue1(s.ssaOp(n.Op(), n.Type()), a.Type, a)
	case ir.OIMAG, ir.OREAL:
		n := n.(*ir.UnaryExpr)
		a := s.expr(n.X)
		return s.newValue1(s.ssaOp(n.Op(), n.X.Type()), n.Type(), a)
	case ir.OPLUS:
		n := n.(*ir.UnaryExpr)
		return s.expr(n.X)

	case ir.OADDR:
		n := n.(*ir.AddrExpr)
		return s.addr(n.X)

	case ir.ORESULT:
		n := n.(*ir.ResultExpr)
		if s.prevCall == nil || s.prevCall.Op != ssa.OpStaticLECall && s.prevCall.Op != ssa.OpInterLECall && s.prevCall.Op != ssa.OpClosureLECall {
			panic("Expected to see a previous call")
		}
		which := n.Index
		if which == -1 {
			panic(fmt.Errorf("ORESULT %v does not match call %s", n, s.prevCall))
		}
		return s.resultOfCall(s.prevCall, which, n.Type())

	case ir.ODEREF:
		n := n.(*ir.StarExpr)
		p := s.exprPtr(n.X, n.Bounded(), n.Pos())
		return s.load(n.Type(), p)

	case ir.ODOT:
		n := n.(*ir.SelectorExpr)
		if n.X.Op() == ir.OSTRUCTLIT {
			// All literals with nonzero fields have already been
			// rewritten during walk. Any that remain are just T{}
			// or equivalents. Use the zero value.
			if !ir.IsZero(n.X) {
				s.Fatalf("literal with nonzero value in SSA: %v", n.X)
			}
			return s.zeroVal(n.Type())
		}
		// If n is addressable and can't be represented in
		// SSA, then load just the selected field. This
		// prevents false memory dependencies in race/msan/asan
		// instrumentation.
		if ir.IsAddressable(n) && !s.canSSA(n) {
			p := s.addr(n)
			return s.load(n.Type(), p)
		}
		v := s.expr(n.X)
		return s.newValue1I(ssa.OpStructSelect, n.Type(), int64(fieldIdx(n)), v)

	case ir.ODOTPTR:
		n := n.(*ir.SelectorExpr)
		p := s.exprPtr(n.X, n.Bounded(), n.Pos())
		p = s.newValue1I(ssa.OpOffPtr, types.NewPtr(n.Type()), n.Offset(), p)
		return s.load(n.Type(), p)

	case ir.OINDEX:
		n := n.(*ir.IndexExpr)
		switch {
		case n.X.Type().IsString():
			if n.Bounded() && ir.IsConst(n.X, constant.String) && ir.IsConst(n.Index, constant.Int) {
				// Replace "abc"[1] with 'b'.
				// Delayed until now because "abc"[1] is not an ideal constant.
				// See test/fixedbugs/issue11370.go.
				return s.newValue0I(ssa.OpConst8, types.Types[types.TUINT8], int64(int8(ir.StringVal(n.X)[ir.Int64Val(n.Index)])))
			}
			a := s.expr(n.X)
			i := s.expr(n.Index)
			len := s.newValue1(ssa.OpStringLen, types.Types[types.TINT], a)
			i = s.boundsCheck(i, len, ssa.BoundsIndex, n.Bounded())
			ptrtyp := s.f.Config.Types.BytePtr
			ptr := s.newValue1(ssa.OpStringPtr, ptrtyp, a)
			if ir.IsConst(n.Index, constant.Int) {
				ptr = s.newValue1I(ssa.OpOffPtr, ptrtyp, ir.Int64Val(n.Index), ptr)
			} else {
				ptr = s.newValue2(ssa.OpAddPtr, ptrtyp, ptr, i)
			}
			return s.load(types.Types[types.TUINT8], ptr)
		case n.X.Type().IsSlice():
			p := s.addr(n)
			return s.load(n.X.Type().Elem(), p)
		case n.X.Type().IsArray():
			if ssa.CanSSA(n.X.Type()) {
				// SSA can handle arrays of length at most 1.
				bound := n.X.Type().NumElem()
				a := s.expr(n.X)
				i := s.expr(n.Index)
				if bound == 0 {
					// Bounds check will never succeed.  Might as well
					// use constants for the bounds check.
					z := s.constInt(types.Types[types.TINT], 0)
					s.boundsCheck(z, z, ssa.BoundsIndex, false)
					// The return value won't be live, return junk.
					// But not quite junk, in case bounds checks are turned off. See issue 48092.
					return s.zeroVal(n.Type())
				}
				len := s.constInt(types.Types[types.TINT], bound)
				s.boundsCheck(i, len, ssa.BoundsIndex, n.Bounded()) // checks i == 0
				return s.newValue1I(ssa.OpArraySelect, n.Type(), 0, a)
			}
			p := s.addr(n)
			return s.load(n.X.Type().Elem(), p)
		default:
			s.Fatalf("bad type for index %v", n.X.Type())
			return nil
		}

	case ir.OLEN, ir.OCAP:
		n := n.(*ir.UnaryExpr)
		switch {
		case n.X.Type().IsSlice():
			op := ssa.OpSliceLen
			if n.Op() == ir.OCAP {
				op = ssa.OpSliceCap
			}
			return s.newValue1(op, types.Types[types.TINT], s.expr(n.X))
		case n.X.Type().IsString(): // string; not reachable for OCAP
			return s.newValue1(ssa.OpStringLen, types.Types[types.TINT], s.expr(n.X))
		case n.X.Type().IsMap(), n.X.Type().IsChan():
			return s.referenceTypeBuiltin(n, s.expr(n.X))
		default: // array
			return s.constInt(types.Types[types.TINT], n.X.Type().NumElem())
		}

	case ir.OSPTR:
		n := n.(*ir.UnaryExpr)
		a := s.expr(n.X)
		if n.X.Type().IsSlice() {
			if n.Bounded() {
				return s.newValue1(ssa.OpSlicePtr, n.Type(), a)
			}
			return s.newValue1(ssa.OpSlicePtrUnchecked, n.Type(), a)
		} else {
			return s.newValue1(ssa.OpStringPtr, n.Type(), a)
		}

	case ir.OITAB:
		n := n.(*ir.UnaryExpr)
		a := s.expr(n.X)
		return s.newValue1(ssa.OpITab, n.Type(), a)

	case ir.OIDATA:
		n := n.(*ir.UnaryExpr)
		a := s.expr(n.X)
		return s.newValue1(ssa.OpIData, n.Type(), a)

	case ir.OMAKEFACE:
		n := n.(*ir.BinaryExpr)
		tab := s.expr(n.X)
		data := s.expr(n.Y)
		return s.newValue2(ssa.OpIMake, n.Type(), tab, data)

	case ir.OSLICEHEADER:
		n := n.(*ir.SliceHeaderExpr)
		p := s.expr(n.Ptr)
		l := s.expr(n.Len)
		c := s.expr(n.Cap)
		return s.newValue3(ssa.OpSliceMake, n.Type(), p, l, c)

	case ir.OSTRINGHEADER:
		n := n.(*ir.StringHeaderExpr)
		p := s.expr(n.Ptr)
		l := s.expr(n.Len)
		return s.newValue2(ssa.OpStringMake, n.Type(), p, l)

	case ir.OSLICE, ir.OSLICEARR, ir.OSLICE3, ir.OSLICE3ARR:
		n := n.(*ir.SliceExpr)
		check := s.checkPtrEnabled && n.Op() == ir.OSLICE3ARR && n.X.Op() == ir.OCONVNOP && n.X.(*ir.ConvExpr).X.Type().IsUnsafePtr()
		v := s.exprCheckPtr(n.X, !check)
		var i, j, k *ssa.Value
		if n.Low != nil {
			i = s.expr(n.Low)
		}
		if n.High != nil {
			j = s.expr(n.High)
		}
		if n.Max != nil {
			k = s.expr(n.Max)
		}
		p, l, c := s.slice(v, i, j, k, n.Bounded())
		if check {
			// Emit checkptr instrumentation after bound check to prevent false positive, see #46938.
			s.checkPtrAlignment(n.X.(*ir.ConvExpr), v, s.conv(n.Max, k, k.Type, types.Types[types.TUINTPTR]))
		}
		return s.newValue3(ssa.OpSliceMake, n.Type(), p, l, c)

	case ir.OSLICESTR:
		n := n.(*ir.SliceExpr)
		v := s.expr(n.X)
		var i, j *ssa.Value
		if n.Low != nil {
			i = s.expr(n.Low)
		}
		if n.High != nil {
			j = s.expr(n.High)
		}
		p, l, _ := s.slice(v, i, j, nil, n.Bounded())
		return s.newValue2(ssa.OpStringMake, n.Type(), p, l)

	case ir.OSLICE2ARRPTR:
		// if arrlen > slice.len {
		//   panic(...)
		// }
		// slice.ptr
		n := n.(*ir.ConvExpr)
		v := s.expr(n.X)
		nelem := n.Type().Elem().NumElem()
		arrlen := s.constInt(types.Types[types.TINT], nelem)
		cap := s.newValue1(ssa.OpSliceLen, types.Types[types.TINT], v)
		s.boundsCheck(arrlen, cap, ssa.BoundsConvert, false)
		op := ssa.OpSlicePtr
		if nelem == 0 {
			op = ssa.OpSlicePtrUnchecked
		}
		return s.newValue1(op, n.Type(), v)

	case ir.OCALLFUNC:
		n := n.(*ir.CallExpr)
		if ir.IsIntrinsicCall(n) {
			return s.intrinsicCall(n)
		}
		fallthrough

	case ir.OCALLINTER:
		n := n.(*ir.CallExpr)
		return s.callResult(n, callNormal)

	case ir.OGETG:
		n := n.(*ir.CallExpr)
		return s.newValue1(ssa.OpGetG, n.Type(), s.mem())

	case ir.OGETCALLERSP:
		n := n.(*ir.CallExpr)
		return s.newValue1(ssa.OpGetCallerSP, n.Type(), s.mem())

	case ir.OAPPEND:
		return s.append(n.(*ir.CallExpr), false)

	case ir.OMIN, ir.OMAX:
		return s.minMax(n.(*ir.CallExpr))

	case ir.OSTRUCTLIT, ir.OARRAYLIT:
		// All literals with nonzero fields have already been
		// rewritten during walk. Any that remain are just T{}
		// or equivalents. Use the zero value.
		n := n.(*ir.CompLitExpr)
		if !ir.IsZero(n) {
			s.Fatalf("literal with nonzero value in SSA: %v", n)
		}
		return s.zeroVal(n.Type())

	case ir.ONEW:
		n := n.(*ir.UnaryExpr)
		var rtype *ssa.Value
		if x, ok := n.X.(*ir.DynamicType); ok && x.Op() == ir.ODYNAMICTYPE {
			rtype = s.expr(x.RType)
		}
		return s.newObject(n.Type().Elem(), rtype)

	case ir.OUNSAFEADD:
		n := n.(*ir.BinaryExpr)
		ptr := s.expr(n.X)
		len := s.expr(n.Y)

		// Force len to uintptr to prevent misuse of garbage bits in the
		// upper part of the register (#48536).
		len = s.conv(n, len, len.Type, types.Types[types.TUINTPTR])

		return s.newValue2(ssa.OpAddPtr, n.Type(), ptr, len)

	default:
		s.Fatalf("unhandled expr %v", n.Op())
		return nil
	}
}

func (s *state) resultOfCall(c *ssa.Value, which int64, t *types.Type) *ssa.Value {
	aux := c.Aux.(*ssa.AuxCall)
	pa := aux.ParamAssignmentForResult(which)
	// TODO(register args) determine if in-memory TypeOK is better loaded early from SelectNAddr or later when SelectN is expanded.
	// SelectN is better for pattern-matching and possible call-aware analysis we might want to do in the future.
	if len(pa.Registers) == 0 && !ssa.CanSSA(t) {
		addr := s.newValue1I(ssa.OpSelectNAddr, types.NewPtr(t), which, c)
		return s.rawLoad(t, addr)
	}
	return s.newValue1I(ssa.OpSelectN, t, which, c)
}

func (s *state) resultAddrOfCall(c *ssa.Value, which int64, t *types.Type) *ssa.Value {
	aux := c.Aux.(*ssa.AuxCall)
	pa := aux.ParamAssignmentForResult(which)
	if len(pa.Registers) == 0 {
		return s.newValue1I(ssa.OpSelectNAddr, types.NewPtr(t), which, c)
	}
	_, addr := s.temp(c.Pos, t)
	rval := s.newValue1I(ssa.OpSelectN, t, which, c)
	s.vars[memVar] = s.newValue3Apos(ssa.OpStore, types.TypeMem, t, addr, rval, s.mem(), false)
	return addr
}

// append converts an OAPPEND node to SSA.
// If inplace is false, it converts the OAPPEND expression n to an ssa.Value,
// adds it to s, and returns the Value.
// If inplace is true, it writes the result of the OAPPEND expression n
// back to the slice being appended to, and returns nil.
// inplace MUST be set to false if the slice can be SSA'd.
// Note: this code only handles fixed-count appends. Dotdotdot appends
// have already been rewritten at this point (by walk).
func (s *state) append(n *ir.CallExpr, inplace bool) *ssa.Value {
	// If inplace is false, process as expression "append(s, e1, e2, e3)":
	//
	// ptr, len, cap := s
	// len += 3
	// if uint(len) > uint(cap) {
	//     ptr, len, cap = growslice(ptr, len, cap, 3, typ)
	//     Note that len is unmodified by growslice.
	// }
	// // with write barriers, if needed:
	// *(ptr+(len-3)) = e1
	// *(ptr+(len-2)) = e2
	// *(ptr+(len-1)) = e3
	// return makeslice(ptr, len, cap)
	//
	//
	// If inplace is true, process as statement "s = append(s, e1, e2, e3)":
	//
	// a := &s
	// ptr, len, cap := s
	// len += 3
	// if uint(len) > uint(cap) {
	//    ptr, len, cap = growslice(ptr, len, cap, 3, typ)
	//    vardef(a)    // if necessary, advise liveness we are writing a new a
	//    *a.cap = cap // write before ptr to avoid a spill
	//    *a.ptr = ptr // with write barrier
	// }
	// *a.len = len
	// // with write barriers, if needed:
	// *(ptr+(len-3)) = e1
	// *(ptr+(len-2)) = e2
	// *(ptr+(len-1)) = e3

	et := n.Type().Elem()
	pt := types.NewPtr(et)

	// Evaluate slice
	sn := n.Args[0] // the slice node is the first in the list
	var slice, addr *ssa.Value
	if inplace {
		addr = s.addr(sn)
		slice = s.load(n.Type(), addr)
	} else {
		slice = s.expr(sn)
	}

	// Allocate new blocks
	grow := s.f.NewBlock(ssa.BlockPlain)
	assign := s.f.NewBlock(ssa.BlockPlain)

	// Decomposse input slice.
	p := s.newValue1(ssa.OpSlicePtr, pt, slice)
	l := s.newValue1(ssa.OpSliceLen, types.Types[types.TINT], slice)
	c := s.newValue1(ssa.OpSliceCap, types.Types[types.TINT], slice)

	// Add number of new elements to length.
	nargs := s.constInt(types.Types[types.TINT], int64(len(n.Args)-1))
	l = s.newValue2(s.ssaOp(ir.OADD, types.Types[types.TINT]), types.Types[types.TINT], l, nargs)

	// Decide if we need to grow
	cmp := s.newValue2(s.ssaOp(ir.OLT, types.Types[types.TUINT]), types.Types[types.TBOOL], c, l)

	// Record values of ptr/len/cap before branch.
	s.vars[ptrVar] = p
	s.vars[lenVar] = l
	if !inplace {
		s.vars[capVar] = c
	}

	b := s.endBlock()
	b.Kind = ssa.BlockIf
	b.Likely = ssa.BranchUnlikely
	b.SetControl(cmp)
	b.AddEdgeTo(grow)
	b.AddEdgeTo(assign)

	// Call growslice
	s.startBlock(grow)
	taddr := s.expr(n.Fun)
	r := s.rtcall(ir.Syms.Growslice, true, []*types.Type{n.Type()}, p, l, c, nargs, taddr)

	// Decompose output slice
	p = s.newValue1(ssa.OpSlicePtr, pt, r[0])
	l = s.newValue1(ssa.OpSliceLen, types.Types[types.TINT], r[0])
	c = s.newValue1(ssa.OpSliceCap, types.Types[types.TINT], r[0])

	s.vars[ptrVar] = p
	s.vars[lenVar] = l
	s.vars[capVar] = c
	if inplace {
		if sn.Op() == ir.ONAME {
			sn := sn.(*ir.Name)
			if sn.Class != ir.PEXTERN {
				// Tell liveness we're about to build a new slice
				s.vars[memVar] = s.newValue1A(ssa.OpVarDef, types.TypeMem, sn, s.mem())
			}
		}
		capaddr := s.newValue1I(ssa.OpOffPtr, s.f.Config.Types.IntPtr, types.SliceCapOffset, addr)
		s.store(types.Types[types.TINT], capaddr, c)
		s.store(pt, addr, p)
	}

	b = s.endBlock()
	b.AddEdgeTo(assign)

	// assign new elements to slots
	s.startBlock(assign)
	p = s.variable(ptrVar, pt)                      // generates phi for ptr
	l = s.variable(lenVar, types.Types[types.TINT]) // generates phi for len
	if !inplace {
		c = s.variable(capVar, types.Types[types.TINT]) // generates phi for cap
	}

	if inplace {
		// Update length in place.
		// We have to wait until here to make sure growslice succeeded.
		lenaddr := s.newValue1I(ssa.OpOffPtr, s.f.Config.Types.IntPtr, types.SliceLenOffset, addr)
		s.store(types.Types[types.TINT], lenaddr, l)
	}

	// Evaluate args
	type argRec struct {
		// if store is true, we're appending the value v.  If false, we're appending the
		// value at *v.
		v     *ssa.Value
		store bool
	}
	args := make([]argRec, 0, len(n.Args[1:]))
	for _, n := range n.Args[1:] {
		if ssa.CanSSA(n.Type()) {
			args = append(args, argRec{v: s.expr(n), store: true})
		} else {
			v := s.addr(n)
			args = append(args, argRec{v: v})
		}
	}

	// Write args into slice.
	oldLen := s.newValue2(s.ssaOp(ir.OSUB, types.Types[types.TINT]), types.Types[types.TINT], l, nargs)
	p2 := s.newValue2(ssa.OpPtrIndex, pt, p, oldLen)
	for i, arg := range args {
		addr := s.newValue2(ssa.OpPtrIndex, pt, p2, s.constInt(types.Types[types.TINT], int64(i)))
		if arg.store {
			s.storeType(et, addr, arg.v, 0, true)
		} else {
			s.move(et, addr, arg.v)
		}
	}

	// The following deletions have no practical effect at this time
	// because state.vars has been reset by the preceding state.startBlock.
	// They only enforce the fact that these variables are no longer need in
	// the current scope.
	delete(s.vars, ptrVar)
	delete(s.vars, lenVar)
	if !inplace {
		delete(s.vars, capVar)
	}

	// make result
	if inplace {
		return nil
	}
	return s.newValue3(ssa.OpSliceMake, n.Type(), p, l, c)
}

// minMax converts an OMIN/OMAX builtin call into SSA.
func (s *state) minMax(n *ir.CallExpr) *ssa.Value {
	// The OMIN/OMAX builtin is variadic, but its semantics are
	// equivalent to left-folding a binary min/max operation across the
	// arguments list.
	fold := func(op func(x, a *ssa.Value) *ssa.Value) *ssa.Value {
		x := s.expr(n.Args[0])
		for _, arg := range n.Args[1:] {
			x = op(x, s.expr(arg))
		}
		return x
	}

	typ := n.Type()

	if typ.IsFloat() || typ.IsString() {
		// min/max semantics for floats are tricky because of NaNs and
		// negative zero. Some architectures have instructions which
		// we can use to generate the right result. For others we must
		// call into the runtime instead.
		//
		// Strings are conceptually simpler, but we currently desugar
		// string comparisons during walk, not ssagen.

		if typ.IsFloat() {
			hasIntrinsic := false
			switch Arch.LinkArch.Family {
			case sys.AMD64, sys.ARM64, sys.Loong64, sys.RISCV64:
				hasIntrinsic = true
			case sys.PPC64:
				hasIntrinsic = buildcfg.GOPPC64 >= 9
			}

			if hasIntrinsic {
				var op ssa.Op
				switch {
				case typ.Kind() == types.TFLOAT64 && n.Op() == ir.OMIN:
					op = ssa.OpMin64F
				case typ.Kind() == types.TFLOAT64 && n.Op() == ir.OMAX:
					op = ssa.OpMax64F
				case typ.Kind() == types.TFLOAT32 && n.Op() == ir.OMIN:
					op = ssa.OpMin32F
				case typ.Kind() == types.TFLOAT32 && n.Op() == ir.OMAX:
					op = ssa.OpMax32F
				}
				return fold(func(x, a *ssa.Value) *ssa.Value {
					return s.newValue2(op, typ, x, a)
				})
			}
		}
		var name string
		switch typ.Kind() {
		case types.TFLOAT32:
			switch n.Op() {
			case ir.OMIN:
				name = "fmin32"
			case ir.OMAX:
				name = "fmax32"
			}
		case types.TFLOAT64:
			switch n.Op() {
			case ir.OMIN:
				name = "fmin64"
			case ir.OMAX:
				name = "fmax64"
			}
		case types.TSTRING:
			switch n.Op() {
			case ir.OMIN:
				name = "strmin"
			case ir.OMAX:
				name = "strmax"
			}
		}
		fn := typecheck.LookupRuntimeFunc(name)

		return fold(func(x, a *ssa.Value) *ssa.Value {
			return s.rtcall(fn, true, []*types.Type{typ}, x, a)[0]
		})
	}

	if typ.IsInteger() {
		if Arch.LinkArch.Family == sys.RISCV64 && buildcfg.GORISCV64 >= 22 && typ.Size() == 8 {
			var op ssa.Op
			switch {
			case typ.IsSigned() && n.Op() == ir.OMIN:
				op = ssa.OpMin64
			case typ.IsSigned() && n.Op() == ir.OMAX:
				op = ssa.OpMax64
			case typ.IsUnsigned() && n.Op() == ir.OMIN:
				op = ssa.OpMin64u
			case typ.IsUnsigned() && n.Op() == ir.OMAX:
				op = ssa.OpMax64u
			}
			return fold(func(x, a *ssa.Value) *ssa.Value {
				return s.newValue2(op, typ, x, a)
			})
		}
	}

	lt := s.ssaOp(ir.OLT, typ)

	return fold(func(x, a *ssa.Value) *ssa.Value {
		switch n.Op() {
		case ir.OMIN:
			// a < x ? a : x
			return s.ternary(s.newValue2(lt, types.Types[types.TBOOL], a, x), a, x)
		case ir.OMAX:
			// x < a ? a : x
			return s.ternary(s.newValue2(lt, types.Types[types.TBOOL], x, a), a, x)
		}
		panic("unreachable")
	})
}

// ternary emits code to evaluate cond ? x : y.
func (s *state) ternary(cond, x, y *ssa.Value) *ssa.Value {
	// Note that we need a new ternaryVar each time (unlike okVar where we can
	// reuse the variable) because it might have a different type every time.
	ternaryVar := ssaMarker("ternary")

	bThen := s.f.NewBlock(ssa.BlockPlain)
	bElse := s.f.NewBlock(ssa.BlockPlain)
	bEnd := s.f.NewBlock(ssa.BlockPlain)

	b := s.endBlock()
	b.Kind = ssa.BlockIf
	b.SetControl(cond)
	b.AddEdgeTo(bThen)
	b.AddEdgeTo(bElse)

	s.startBlock(bThen)
	s.vars[ternaryVar] = x
	s.endBlock().AddEdgeTo(bEnd)

	s.startBlock(bElse)
	s.vars[ternaryVar] = y
	s.endBlock().AddEdgeTo(bEnd)

	s.startBlock(bEnd)
	r := s.variable(ternaryVar, x.Type)
	delete(s.vars, ternaryVar)
	return r
}

// condBranch evaluates the boolean expression cond and branches to yes
// if cond is true and no if cond is false.
// This function is intended to handle && and || better than just calling
// s.expr(cond) and branching on the result.
func (s *state) condBranch(cond ir.Node, yes, no *ssa.Block, likely int8) {
	switch cond.Op() {
	case ir.OANDAND:
		cond := cond.(*i
"""




```