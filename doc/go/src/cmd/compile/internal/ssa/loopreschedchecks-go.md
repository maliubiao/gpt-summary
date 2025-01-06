Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The primary directive is to understand the *functionality* of `loopreschedchecks.go`. The name itself is a big hint: "loop reschedule checks." This suggests the code deals with ensuring that Go's scheduler can interrupt long-running loops.

2. **Identify Key Data Structures:**  Quickly scan the top of the file for type definitions. These provide the vocabulary of the code:
    * `edgeMem`:  Connects backedges (looping edges) with memory updates at the loop header.
    * `rewriteTarget`: Identifies where a value needs to be rewritten (a specific argument of a value).
    * `rewrite`:  Bundles the "before" and "after" values of a rewrite and the locations where the rewrite needs to happen.

3. **Focus on the Main Function:** The function `insertLoopReschedChecks(f *Func)` is clearly the core logic. Read its comments carefully. The comment block outlines the steps:
    * Locate backedges.
    * Record memory definitions.
    * Ensure necessary phi functions exist.
    * Record and apply modifications to memory uses.
    * Rewrite backedges to include the reschedule check.

4. **Deconstruct the Steps:**  Go through the steps in `insertLoopReschedChecks` and relate them back to the data structures and helper functions.

    * **Locate Backedges:** The `backedges(f)` function is called. Its purpose is clear from its name and implementation (a standard graph traversal to find edges that lead back to previously visited nodes).

    * **Record Memory Definitions:** `findLastMems(f)` is called. This function appears to track the last memory operation in each block. The code within it confirms this, looking for stores and handling `OpPhi` for memory.

    * **Ensure Phi Functions Exist:** This part is more involved. The code iterates through backedges and checks if a memory `OpPhi` exists at the loop header. If not, it creates one using `newPhiFor`. The `addDFphis` function is then called, suggesting it adds phi functions in the dominance frontier to propagate the new memory definition. The purpose of `rewriteNewPhis` becomes clearer: it updates the arguments of existing values to use the newly created phi functions.

    * **Record and Apply Modifications:** The `rewrite` struct and its `rewrites` field are used here. `rewriteNewPhis` populates these, finding all the places where the old memory value needs to be replaced by the new phi function. The loop `for _, r := range newmemphis` actually applies these recorded rewrites.

    * **Rewrite Backedges:** This is where the core rescheduling logic happens. A new "test" block is created to check the stack pointer against the stack bound. If the stack pointer is low, a call to `goschedguarded` is inserted in the "sched" block. The original backedge is redirected through these new blocks. The arguments of phi functions in the loop header are updated to account for the new incoming edge from the "sched" block.

5. **Infer Go Feature:** Based on the code's actions – checking the stack pointer against a limit and calling `goschedguarded` – the inferred Go feature is preemptive scheduling for long-running loops. The code is actively inserting checks to allow the scheduler to interrupt these loops.

6. **Create a Go Example:**  A simple `for` loop demonstrates the scenario where this code would be applied. The loop needs to be potentially long-running to trigger the need for rescheduling.

7. **Code Reasoning (Hypothetical Input/Output):**  Choose a simple loop example. Imagine the SSA representation *before* and *after* the `insertLoopReschedChecks` function runs. The key change is the insertion of the conditional branch and the call to `goschedguarded` on the backedge. The memory phi at the loop header will have an additional input.

8. **Command Line Arguments:** Since the code is part of the compiler, the relevant "command-line arguments" are actually compiler flags that control optimizations and debugging. `-N` (disable optimizations) and `-d ssa/loopreschedchecks/debug=1` (or higher) are relevant for understanding and debugging this specific pass.

9. **Common Mistakes:** Think about what could go wrong if the logic in `insertLoopReschedChecks` was flawed. A common mistake could be incorrectly updating phi functions, leading to incorrect data flow. Another potential error is not handling all types of backedges correctly.

10. **Refine and Organize:**  Structure the analysis clearly, using headings and bullet points. Explain the purpose of each function and data structure. Provide code examples and reasoning as requested.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this is about optimizing loop execution.
* **Correction:** The `goschedguarded` call strongly suggests it's about *allowing* rescheduling, not necessarily optimizing the loop itself. It's about fairness and preventing infinite loops from blocking the scheduler.
* **Initial thought about Phi functions:**  They're just there to merge values.
* **Refinement:**  In the context of this code, they're crucial for managing the memory state across loop iterations, especially when introducing new control flow paths (the reschedule check). The code explicitly creates and updates phi functions for the memory state.
* **Realization:** The "join" block optimization is interesting. Initially, one might think a separate "join" block would be created. The code comment explains *why* that's avoided (register allocation issues) and how the header block's phi functions are adapted instead. This shows a practical consideration in compiler design.

By following this structured approach, combining code reading with understanding the domain (compiler optimizations, scheduling), and iteratively refining understanding, one can effectively analyze and explain complex code like this.
这段代码是Go编译器 (`cmd/compile`) 中间表示（SSA）的一个Pass，专门负责在循环的回边（backedge）插入**重新调度检查（rescheduling checks）**。

**功能概览:**

这段代码的核心功能是确保长时间运行的Go程序中的循环不会无限期地占用CPU，从而阻塞其他goroutine的执行。它通过在循环的回边插入代码来实现，该代码会检查当前goroutine的堆栈指针是否接近其堆栈限制。如果接近，则调用 `runtime.goschedguarded` 函数，允许Go运行时调度器切换到其他goroutine。

**具体功能分解:**

1. **识别循环回边 (`backedges` 函数):**  代码首先通过图遍历算法（深度优先搜索）识别出SSA图中的所有循环回边。回边是指从循环体内部的某个块跳转回循环头部的边。

2. **记录内存状态 (`findLastMems` 函数):**  为了正确地插入重新调度检查，需要追踪循环回边处的内存状态。`findLastMems` 函数会找到每个基本块中最后一次内存操作（例如，存储操作或返回内存的函数调用）。这对于后续更新内存相关的SSA值至关重要。

3. **插入必要的 Phi 函数:**  当在循环回边插入新的控制流路径时，可能需要在循环头部插入新的 Phi 函数来合并不同路径上的内存状态。代码会检查循环头部是否存在内存类型的 Phi 函数。如果不存在，则创建一个新的，并使用 `addDFphis` 函数在支配边界上添加必要的 Phi 函数以保持SSA的正确性。

4. **重写 SSA 值 (`rewriteNewPhis` 函数):**  插入新的 Phi 函数后，需要更新其他使用了旧内存状态的 SSA 值，使其指向新的 Phi 函数。`rewriteNewPhis` 函数遍历支配树，找到所有需要更新的地方，并将旧的内存值替换为新的 Phi 函数。

5. **重写回边并插入调度检查:**  这是核心步骤。对于每个循环回边，代码会进行以下操作：
   - 创建一个新的条件分支块 (`test`)，用于检查堆栈指针。
   - 创建一个新的普通块 (`sched`)，用于在堆栈指针接近限制时调用 `runtime.goschedguarded`。
   - 在回边处插入 `test` 块。
   - 在 `test` 块中，比较当前堆栈指针 (`SP`) 和 goroutine 的堆栈限制 (`g.stack_limit`)。
   - 如果堆栈指针小于堆栈限制，则跳转到 `sched` 块。
   - 在 `sched` 块中，调用 `runtime.goschedguarded(mem)`，其中 `mem` 是当前的内存状态。`goschedguarded` 会触发一次安全点，允许调度器介入。
   - `sched` 块执行完毕后，跳转回循环头部。
   - 更新循环头部的内存 Phi 函数，使其包含来自新路径（经过 `sched` 块）的内存状态。
   - 对于循环头部其他的 Phi 函数，需要添加来自新路径的输入，通常是回边原来的值。

**推理实现的 Go 语言功能:**

这段代码是实现 **Go 语言的协作式抢占调度 (cooperative preemption)** 的一部分，特别是在循环场景下的应用。虽然Go语言主要依赖于 Goroutine 主动让出 CPU (例如通过 I/O 操作或 `runtime.Gosched()`)，但在长时间运行的、没有主动让出机会的循环中，需要一种机制来防止单个 Goroutine 饿死其他 Goroutine。

**Go 代码示例:**

```go
package main

func main() {
	sum := 0
	for i := 0; i < 1000000000; i++ { // 一个长时间运行的循环
		sum += i
	}
	println(sum)
}
```

**假设的输入与输出 (SSA 图):**

**输入 (简化的循环 SSA 图 - 忽略内存状态):**

```
b1 (入口):
  goto b2

b2 (循环头部):
  v1 = Phi(b1->, b3->v4) // 循环计数器
  if v1 < 1000000000 goto b3 else goto b4

b3 (循环体):
  v2 = Add(v1, 1)
  v3 = Add(sum_var, v1) // 假设 sum_var 是循环外部的变量
  goto b2

b4 (循环出口):
  // ...
```

**输出 (插入调度检查后的 SSA 图 - 忽略部分细节):**

```
b1 (入口):
  goto b2

b2 (循环头部):
  v1 = Phi(b1->, b5->v6) // 循环计数器
  v_mem_phi = Phi(b1->init_mem, b5->v_mem_sched) // 内存状态 Phi

  // 插入的调度检查
  v_g = GetG(v_mem_phi)
  v_sp = SP()
  v_limit_addr = OffPtr(v_g, offset_of_stack_limit)
  v_limit = Load(v_limit_addr, v_mem_phi)
  v_cmp = Less64U(v_sp, v_limit)
  if v_cmp goto b_sched else goto b3

b_sched:
  v_call_resched = StaticCall(goschedguarded, v_mem_phi)
  v_mem_sched = SelectN(0, v_call_resched)
  goto b3 // 或者直接跳回 b2，根据具体实现

b3 (循环体):
  v2 = Add(v1, 1)
  v3 = Add(sum_var, v1)
  goto b2 // 现在会跳转到修改后的 b2

b4 (循环出口):
  // ...
```

**代码推理:**

- `edgeMem` 结构体用于关联循环回边和循环头部的内存 Phi 函数，以便在插入调度检查后正确更新 Phi 函数的输入。
- `rewriteTarget` 和 `rewrite` 结构体用于记录和执行对 SSA 值的重写操作，主要是将旧的内存值替换为新插入的 Phi 函数。
- `insertLoopReschedChecks` 是主函数，它协调整个插入调度检查的过程。
- 代码中使用了支配树 (`idom`) 和后序遍历 (`postorder`) 等图论概念，这在编译器优化和代码分析中很常见。

**命令行参数:**

该代码本身不直接处理命令行参数。然而，作为 `cmd/compile` 的一部分，其行为可能会受到一些编译器标志的影响，例如：

- **`-N`:**  禁用优化。如果禁用了优化，可能就不会进行循环调度检查的插入。
- **`-d` (debug flags):**  编译器提供了一些调试标志，可以用来观察 SSA 中间表示的变化，包括循环调度检查的插入过程。例如，可以尝试使用 `-d ssa/loopreschedchecks/debug=1` 或更高的值来查看更详细的调试信息。

**使用者易犯错的点 (作为编译器开发者或贡献者):**

- **错误地识别循环回边:** 如果 `backedges` 函数的实现有误，可能会导致调度检查没有插入到正确的循环中，或者错误地在非循环结构中插入。
- **没有正确更新 Phi 函数:**  在插入新的控制流路径后，如果没有正确更新循环头部以及支配边界上的 Phi 函数，会导致 SSA 图不一致，从而产生错误的编译结果。特别是内存类型的 Phi 函数，对于保证程序的正确性至关重要。
- **考虑不周全的边界情况:**  例如，嵌套循环、包含 `goto` 语句的复杂控制流等情况可能会使插入调度检查的逻辑变得复杂，需要仔细考虑各种边界情况。
- **性能影响:**  虽然插入调度检查是为了保证程序的公平性，但也会带来一定的性能开销。需要在性能和公平性之间进行权衡，并确保插入的检查不会过于频繁，影响程序的整体性能。

总而言之，`loopreschedchecks.go` 是 Go 编译器中一个重要的组成部分，它通过在循环回边插入调度检查，实现了协作式抢占调度，保证了长时间运行的 Go 程序在并发环境下的公平性。理解这段代码需要一定的编译器和 SSA 知识。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/loopreschedchecks.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/types"
	"fmt"
)

// an edgeMem records a backedge, together with the memory
// phi functions at the target of the backedge that must
// be updated when a rescheduling check replaces the backedge.
type edgeMem struct {
	e Edge
	m *Value // phi for memory at dest of e
}

// a rewriteTarget is a value-argindex pair indicating
// where a rewrite is applied.  Note that this is for values,
// not for block controls, because block controls are not targets
// for the rewrites performed in inserting rescheduling checks.
type rewriteTarget struct {
	v *Value
	i int
}

type rewrite struct {
	before, after *Value          // before is the expected value before rewrite, after is the new value installed.
	rewrites      []rewriteTarget // all the targets for this rewrite.
}

func (r *rewrite) String() string {
	s := "\n\tbefore=" + r.before.String() + ", after=" + r.after.String()
	for _, rw := range r.rewrites {
		s += ", (i=" + fmt.Sprint(rw.i) + ", v=" + rw.v.LongString() + ")"
	}
	s += "\n"
	return s
}

// insertLoopReschedChecks inserts rescheduling checks on loop backedges.
func insertLoopReschedChecks(f *Func) {
	// TODO: when split information is recorded in export data, insert checks only on backedges that can be reached on a split-call-free path.

	// Loop reschedule checks compare the stack pointer with
	// the per-g stack bound.  If the pointer appears invalid,
	// that means a reschedule check is needed.
	//
	// Steps:
	// 1. locate backedges.
	// 2. Record memory definitions at block end so that
	//    the SSA graph for mem can be properly modified.
	// 3. Ensure that phi functions that will-be-needed for mem
	//    are present in the graph, initially with trivial inputs.
	// 4. Record all to-be-modified uses of mem;
	//    apply modifications (split into two steps to simplify and
	//    avoided nagging order-dependencies).
	// 5. Rewrite backedges to include reschedule check,
	//    and modify destination phi function appropriately with new
	//    definitions for mem.

	if f.NoSplit { // nosplit functions don't reschedule.
		return
	}

	backedges := backedges(f)
	if len(backedges) == 0 { // no backedges means no rescheduling checks.
		return
	}

	lastMems := findLastMems(f)
	defer f.Cache.freeValueSlice(lastMems)

	idom := f.Idom()
	po := f.postorder()
	// The ordering in the dominator tree matters; it's important that
	// the walk of the dominator tree also be a preorder (i.e., a node is
	// visited only after all its non-backedge predecessors have been visited).
	sdom := newSparseOrderedTree(f, idom, po)

	if f.pass.debug > 1 {
		fmt.Printf("before %s = %s\n", f.Name, sdom.treestructure(f.Entry))
	}

	tofixBackedges := []edgeMem{}

	for _, e := range backedges { // TODO: could filter here by calls in loops, if declared and inferred nosplit are recorded in export data.
		tofixBackedges = append(tofixBackedges, edgeMem{e, nil})
	}

	// It's possible that there is no memory state (no global/pointer loads/stores or calls)
	if lastMems[f.Entry.ID] == nil {
		lastMems[f.Entry.ID] = f.Entry.NewValue0(f.Entry.Pos, OpInitMem, types.TypeMem)
	}

	memDefsAtBlockEnds := f.Cache.allocValueSlice(f.NumBlocks()) // For each block, the mem def seen at its bottom. Could be from earlier block.
	defer f.Cache.freeValueSlice(memDefsAtBlockEnds)

	// Propagate last mem definitions forward through successor blocks.
	for i := len(po) - 1; i >= 0; i-- {
		b := po[i]
		mem := lastMems[b.ID]
		for j := 0; mem == nil; j++ { // if there's no def, then there's no phi, so the visible mem is identical in all predecessors.
			// loop because there might be backedges that haven't been visited yet.
			mem = memDefsAtBlockEnds[b.Preds[j].b.ID]
		}
		memDefsAtBlockEnds[b.ID] = mem
		if f.pass.debug > 2 {
			fmt.Printf("memDefsAtBlockEnds[%s] = %s\n", b, mem)
		}
	}

	// Maps from block to newly-inserted phi function in block.
	newmemphis := make(map[*Block]rewrite)

	// Insert phi functions as necessary for future changes to flow graph.
	for i, emc := range tofixBackedges {
		e := emc.e
		h := e.b

		// find the phi function for the memory input at "h", if there is one.
		var headerMemPhi *Value // look for header mem phi

		for _, v := range h.Values {
			if v.Op == OpPhi && v.Type.IsMemory() {
				headerMemPhi = v
			}
		}

		if headerMemPhi == nil {
			// if the header is nil, make a trivial phi from the dominator
			mem0 := memDefsAtBlockEnds[idom[h.ID].ID]
			headerMemPhi = newPhiFor(h, mem0)
			newmemphis[h] = rewrite{before: mem0, after: headerMemPhi}
			addDFphis(mem0, h, h, f, memDefsAtBlockEnds, newmemphis, sdom)

		}
		tofixBackedges[i].m = headerMemPhi

	}
	if f.pass.debug > 0 {
		for b, r := range newmemphis {
			fmt.Printf("before b=%s, rewrite=%s\n", b, r.String())
		}
	}

	// dfPhiTargets notes inputs to phis in dominance frontiers that should not
	// be rewritten as part of the dominated children of some outer rewrite.
	dfPhiTargets := make(map[rewriteTarget]bool)

	rewriteNewPhis(f.Entry, f.Entry, f, memDefsAtBlockEnds, newmemphis, dfPhiTargets, sdom)

	if f.pass.debug > 0 {
		for b, r := range newmemphis {
			fmt.Printf("after b=%s, rewrite=%s\n", b, r.String())
		}
	}

	// Apply collected rewrites.
	for _, r := range newmemphis {
		for _, rw := range r.rewrites {
			rw.v.SetArg(rw.i, r.after)
		}
	}

	// Rewrite backedges to include reschedule checks.
	for _, emc := range tofixBackedges {
		e := emc.e
		headerMemPhi := emc.m
		h := e.b
		i := e.i
		p := h.Preds[i]
		bb := p.b
		mem0 := headerMemPhi.Args[i]
		// bb e->p h,
		// Because we're going to insert a rare-call, make sure the
		// looping edge still looks likely.
		likely := BranchLikely
		if p.i != 0 {
			likely = BranchUnlikely
		}
		if bb.Kind != BlockPlain { // backedges can be unconditional. e.g., if x { something; continue }
			bb.Likely = likely
		}

		// rewrite edge to include reschedule check
		// existing edges:
		//
		// bb.Succs[p.i] == Edge{h, i}
		// h.Preds[i] == p == Edge{bb,p.i}
		//
		// new block(s):
		// test:
		//    if sp < g.limit { goto sched }
		//    goto join
		// sched:
		//    mem1 := call resched (mem0)
		//    goto join
		// join:
		//    mem2 := phi(mem0, mem1)
		//    goto h
		//
		// and correct arg i of headerMemPhi and headerCtrPhi
		//
		// EXCEPT: join block containing only phi functions is bad
		// for the register allocator.  Therefore, there is no
		// join, and branches targeting join must instead target
		// the header, and the other phi functions within header are
		// adjusted for the additional input.

		test := f.NewBlock(BlockIf)
		sched := f.NewBlock(BlockPlain)

		test.Pos = bb.Pos
		sched.Pos = bb.Pos

		// if sp < g.limit { goto sched }
		// goto header

		cfgtypes := &f.Config.Types
		pt := cfgtypes.Uintptr
		g := test.NewValue1(bb.Pos, OpGetG, pt, mem0)
		sp := test.NewValue0(bb.Pos, OpSP, pt)
		cmpOp := OpLess64U
		if pt.Size() == 4 {
			cmpOp = OpLess32U
		}
		limaddr := test.NewValue1I(bb.Pos, OpOffPtr, pt, 2*pt.Size(), g)
		lim := test.NewValue2(bb.Pos, OpLoad, pt, limaddr, mem0)
		cmp := test.NewValue2(bb.Pos, cmpOp, cfgtypes.Bool, sp, lim)
		test.SetControl(cmp)

		// if true, goto sched
		test.AddEdgeTo(sched)

		// if false, rewrite edge to header.
		// do NOT remove+add, because that will perturb all the other phi functions
		// as well as messing up other edges to the header.
		test.Succs = append(test.Succs, Edge{h, i})
		h.Preds[i] = Edge{test, 1}
		headerMemPhi.SetArg(i, mem0)

		test.Likely = BranchUnlikely

		// sched:
		//    mem1 := call resched (mem0)
		//    goto header
		resched := f.fe.Syslook("goschedguarded")
		call := sched.NewValue1A(bb.Pos, OpStaticCall, types.TypeResultMem, StaticAuxCall(resched, bb.Func.ABIDefault.ABIAnalyzeTypes(nil, nil)), mem0)
		mem1 := sched.NewValue1I(bb.Pos, OpSelectN, types.TypeMem, 0, call)
		sched.AddEdgeTo(h)
		headerMemPhi.AddArg(mem1)

		bb.Succs[p.i] = Edge{test, 0}
		test.Preds = append(test.Preds, Edge{bb, p.i})

		// Must correct all the other phi functions in the header for new incoming edge.
		// Except for mem phis, it will be the same value seen on the original
		// backedge at index i.
		for _, v := range h.Values {
			if v.Op == OpPhi && v != headerMemPhi {
				v.AddArg(v.Args[i])
			}
		}
	}

	f.invalidateCFG()

	if f.pass.debug > 1 {
		sdom = newSparseTree(f, f.Idom())
		fmt.Printf("after %s = %s\n", f.Name, sdom.treestructure(f.Entry))
	}
}

// newPhiFor inserts a new Phi function into b,
// with all inputs set to v.
func newPhiFor(b *Block, v *Value) *Value {
	phiV := b.NewValue0(b.Pos, OpPhi, v.Type)

	for range b.Preds {
		phiV.AddArg(v)
	}
	return phiV
}

// rewriteNewPhis updates newphis[h] to record all places where the new phi function inserted
// in block h will replace a previous definition.  Block b is the block currently being processed;
// if b has its own phi definition then it takes the place of h.
// defsForUses provides information about other definitions of the variable that are present
// (and if nil, indicates that the variable is no longer live)
// sdom must yield a preorder of the flow graph if recursively walked, root-to-children.
// The result of newSparseOrderedTree with order supplied by a dfs-postorder satisfies this
// requirement.
func rewriteNewPhis(h, b *Block, f *Func, defsForUses []*Value, newphis map[*Block]rewrite, dfPhiTargets map[rewriteTarget]bool, sdom SparseTree) {
	// If b is a block with a new phi, then a new rewrite applies below it in the dominator tree.
	if _, ok := newphis[b]; ok {
		h = b
	}
	change := newphis[h]
	x := change.before
	y := change.after

	// Apply rewrites to this block
	if x != nil { // don't waste time on the common case of no definition.
		p := &change.rewrites
		for _, v := range b.Values {
			if v == y { // don't rewrite self -- phi inputs are handled below.
				continue
			}
			for i, w := range v.Args {
				if w != x {
					continue
				}
				tgt := rewriteTarget{v, i}

				// It's possible dominated control flow will rewrite this instead.
				// Visiting in preorder (a property of how sdom was constructed)
				// ensures that these are seen in the proper order.
				if dfPhiTargets[tgt] {
					continue
				}
				*p = append(*p, tgt)
				if f.pass.debug > 1 {
					fmt.Printf("added block target for h=%v, b=%v, x=%v, y=%v, tgt.v=%s, tgt.i=%d\n",
						h, b, x, y, v, i)
				}
			}
		}

		// Rewrite appropriate inputs of phis reached in successors
		// in dominance frontier, self, and dominated.
		// If the variable def reaching uses in b is itself defined in b, then the new phi function
		// does not reach the successors of b.  (This assumes a bit about the structure of the
		// phi use-def graph, but it's true for memory.)
		if dfu := defsForUses[b.ID]; dfu != nil && dfu.Block != b {
			for _, e := range b.Succs {
				s := e.b

				for _, v := range s.Values {
					if v.Op == OpPhi && v.Args[e.i] == x {
						tgt := rewriteTarget{v, e.i}
						*p = append(*p, tgt)
						dfPhiTargets[tgt] = true
						if f.pass.debug > 1 {
							fmt.Printf("added phi target for h=%v, b=%v, s=%v, x=%v, y=%v, tgt.v=%s, tgt.i=%d\n",
								h, b, s, x, y, v.LongString(), e.i)
						}
						break
					}
				}
			}
		}
		newphis[h] = change
	}

	for c := sdom[b.ID].child; c != nil; c = sdom[c.ID].sibling {
		rewriteNewPhis(h, c, f, defsForUses, newphis, dfPhiTargets, sdom) // TODO: convert to explicit stack from recursion.
	}
}

// addDFphis creates new trivial phis that are necessary to correctly reflect (within SSA)
// a new definition for variable "x" inserted at h (usually but not necessarily a phi).
// These new phis can only occur at the dominance frontier of h; block s is in the dominance
// frontier of h if h does not strictly dominate s and if s is a successor of a block b where
// either b = h or h strictly dominates b.
// These newly created phis are themselves new definitions that may require addition of their
// own trivial phi functions in their own dominance frontier, and this is handled recursively.
func addDFphis(x *Value, h, b *Block, f *Func, defForUses []*Value, newphis map[*Block]rewrite, sdom SparseTree) {
	oldv := defForUses[b.ID]
	if oldv != x { // either a new definition replacing x, or nil if it is proven that there are no uses reachable from b
		return
	}
	idom := f.Idom()
outer:
	for _, e := range b.Succs {
		s := e.b
		// check phi functions in the dominance frontier
		if sdom.isAncestor(h, s) {
			continue // h dominates s, successor of b, therefore s is not in the frontier.
		}
		if _, ok := newphis[s]; ok {
			continue // successor s of b already has a new phi function, so there is no need to add another.
		}
		if x != nil {
			for _, v := range s.Values {
				if v.Op == OpPhi && v.Args[e.i] == x {
					continue outer // successor s of b has an old phi function, so there is no need to add another.
				}
			}
		}

		old := defForUses[idom[s.ID].ID] // new phi function is correct-but-redundant, combining value "old" on all inputs.
		headerPhi := newPhiFor(s, old)
		// the new phi will replace "old" in block s and all blocks dominated by s.
		newphis[s] = rewrite{before: old, after: headerPhi} // record new phi, to have inputs labeled "old" rewritten to "headerPhi"
		addDFphis(old, s, s, f, defForUses, newphis, sdom)  // the new definition may also create new phi functions.
	}
	for c := sdom[b.ID].child; c != nil; c = sdom[c.ID].sibling {
		addDFphis(x, h, c, f, defForUses, newphis, sdom) // TODO: convert to explicit stack from recursion.
	}
}

// findLastMems maps block ids to last memory-output op in a block, if any.
func findLastMems(f *Func) []*Value {

	var stores []*Value
	lastMems := f.Cache.allocValueSlice(f.NumBlocks())
	storeUse := f.newSparseSet(f.NumValues())
	defer f.retSparseSet(storeUse)
	for _, b := range f.Blocks {
		// Find all the stores in this block. Categorize their uses:
		//  storeUse contains stores which are used by a subsequent store.
		storeUse.clear()
		stores = stores[:0]
		var memPhi *Value
		for _, v := range b.Values {
			if v.Op == OpPhi {
				if v.Type.IsMemory() {
					memPhi = v
				}
				continue
			}
			if v.Type.IsMemory() {
				stores = append(stores, v)
				for _, a := range v.Args {
					if a.Block == b && a.Type.IsMemory() {
						storeUse.add(a.ID)
					}
				}
			}
		}
		if len(stores) == 0 {
			lastMems[b.ID] = memPhi
			continue
		}

		// find last store in the block
		var last *Value
		for _, v := range stores {
			if storeUse.contains(v.ID) {
				continue
			}
			if last != nil {
				b.Fatalf("two final stores - simultaneous live stores %s %s", last, v)
			}
			last = v
		}
		if last == nil {
			b.Fatalf("no last store found - cycle?")
		}

		// If this is a tuple containing a mem, select just
		// the mem. This will generate ops we don't need, but
		// it's the easiest thing to do.
		if last.Type.IsTuple() {
			last = b.NewValue1(last.Pos, OpSelect1, types.TypeMem, last)
		} else if last.Type.IsResults() {
			last = b.NewValue1I(last.Pos, OpSelectN, types.TypeMem, int64(last.Type.NumFields()-1), last)
		}

		lastMems[b.ID] = last
	}
	return lastMems
}

// mark values
type markKind uint8

const (
	notFound    markKind = iota // block has not been discovered yet
	notExplored                 // discovered and in queue, outedges not processed yet
	explored                    // discovered and in queue, outedges processed
	done                        // all done, in output ordering
)

type backedgesState struct {
	b *Block
	i int
}

// backedges returns a slice of successor edges that are back
// edges.  For reducible loops, edge.b is the header.
func backedges(f *Func) []Edge {
	edges := []Edge{}
	mark := make([]markKind, f.NumBlocks())
	stack := []backedgesState{}

	mark[f.Entry.ID] = notExplored
	stack = append(stack, backedgesState{f.Entry, 0})

	for len(stack) > 0 {
		l := len(stack)
		x := stack[l-1]
		if x.i < len(x.b.Succs) {
			e := x.b.Succs[x.i]
			stack[l-1].i++
			s := e.b
			if mark[s.ID] == notFound {
				mark[s.ID] = notExplored
				stack = append(stack, backedgesState{s, 0})
			} else if mark[s.ID] == notExplored {
				edges = append(edges, e)
			}
		} else {
			mark[x.b.ID] = done
			stack = stack[0 : l-1]
		}
	}
	return edges
}

"""



```