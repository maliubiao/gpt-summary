Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the code, potential Go feature implementation, code examples, command-line parameters, and common mistakes. The file path `go/src/cmd/compile/internal/ssa/nilcheck.go` immediately signals that this code is part of the Go compiler's static single assignment (SSA) optimization pipeline and deals with eliminating redundant nil checks.

2. **Initial Code Scan - Keywords and Structure:**  A quick scan reveals important keywords and structures:
    * `package ssa`:  Confirms it's part of the SSA package.
    * `func nilcheckelim(f *Func)` and `func nilcheckelim2(f *Func)`: Two distinct functions, likely representing different stages of nil check elimination. The comments indicate `nilcheckelim` runs on machine-independent code and `nilcheckelim2` after lowering and scheduling. This suggests different strategies are employed at different optimization levels.
    * Comments like "// A nil check is redundant if..." and "// Runs after lowering and scheduling." provide crucial high-level understanding.
    * Data structures like `SparseSet`, `SparseMap`, and slice allocations using `f.Cache` point to internal compiler optimizations.
    * Operations like `OpIsNonNil`, `OpNilCheck`, `OpAddr`, `OpLoad`, `OpStore`, etc., indicate SSA value types and operations related to pointer manipulation and memory access.

3. **Deep Dive into `nilcheckelim`:**
    * **Core Idea:** The comment "A nil check is redundant if the same nil check was successful in a dominating block" is key. This implies a dominance analysis. The code confirms this with `sdom := f.Sdom()`.
    * **Data Structures:** `nonNilValues` is a map to track values known to be non-nil. The comments explain how it's populated (address-taking, prior nil checks). The `work` slice and the `walkState` enum suggest a depth-first traversal of the control flow graph.
    * **Logic Flow:**
        * Initial population of `nonNilValues` based on address-taking operations.
        * Iterative propagation of non-nil information through Phi nodes.
        * Depth-first traversal (using `work`) of the dominator tree.
        * Inside the loop:
            * Checks for dominance by a prior `OpIsNonNil`.
            * Processes values, looking for `OpIsNonNil` and `OpNilCheck`.
            * Eliminates redundant checks by replacing them with `OpConstBool(true)` or `OpCopy` of the non-nil value.
            * Updates `nonNilValues` and the `work` list.
    * **Hypothesized Functionality:**  This function seems to be performing an early, more abstract elimination of nil checks based on control flow dominance.

4. **Deep Dive into `nilcheckelim2`:**
    * **Core Idea:** The comment "Remove nil checks on those pointers, as the faulting instruction effectively does the nil check for free" is crucial. This happens *after* lowering, so it's about leveraging the CPU's faulting behavior.
    * **Data Structures:** `unnecessary` maps pointers to the index of the faulting instruction. `pendingLines` handles statement boundary preservation.
    * **Logic Flow:**
        * Iterates through blocks and then values *backwards*.
        * Identifies instructions that fault on nil pointers (`opcodeTable[v.Op].faultOnNilArg0/1`).
        * If a preceding `OpNilCheck` operates on a pointer that will be dereferenced by a faulting instruction, the `OpNilCheck` is removed.
        * Handles statement boundary movement to maintain correct debugging information.
    * **Hypothesized Functionality:** This function performs a later, more low-level nil check elimination by identifying instructions that implicitly perform the check.

5. **Go Feature Implementation (Inference):** Based on the code, it's clearly related to:
    * **Pointer Dereferencing:**  The focus on `OpLoad`, `OpStore`, and similar operations implies this is about making pointer dereferences more efficient.
    * **Implicit Nil Checks:** The elimination in `nilcheckelim2` directly relates to the Go runtime's behavior of panicking on nil pointer dereferences.
    * **Compiler Optimizations:** This is a standard compiler optimization pass to improve performance by removing redundant checks.

6. **Code Example (Mental Construction):** To illustrate, consider a simple scenario:

   ```go
   func foo(p *int) {
       if p != nil { // OpIsNonNil
           println(*p)  // Implicit Nil Check before dereference
       }
   }
   ```

   * `nilcheckelim` would identify the `p != nil` check and potentially mark `p` as non-nil within the `if` block.
   * `nilcheckelim2` would see the `println(*p)` which implicitly checks for nil. If the `if p != nil` was still there after the first pass (maybe due to complexity), the second pass could remove it.

7. **Command-Line Parameters:** There are no explicit command-line parameters handled *within this specific code snippet*. However, compiler flags like `-N` (disable optimizations) or potentially flags controlling the level of nil check diagnostics (`f.fe.Debug_checknil()`) could indirectly influence the behavior of these passes.

8. **Common Mistakes (Thinking about the user's perspective):**  This code is part of the *compiler*. Users don't directly interact with these functions. However, understanding these optimizations can help explain why certain seemingly redundant checks might be optimized away. A potential "mistake" in understanding would be assuming that every explicit nil check is always necessary, without considering the compiler's ability to infer non-nullness.

9. **Refine and Organize:**  Structure the answer logically, separating the functionalities of the two functions, the inferred Go feature, the code example, etc. Use clear and concise language. Emphasize the different stages of optimization.

This detailed thought process, combining code analysis, comment interpretation, and knowledge of compiler optimization techniques, leads to the comprehensive answer provided previously.
这段代码是 Go 编译器中 SSA (Static Single Assignment) 中间表示的一个优化 pass，名为 `nilcheckelim` 和 `nilcheckelim2`，其主要功能是**消除不必要的 nil 检查**。

让我们分别解释这两个函数的功能：

**1. `nilcheckelim(f *Func)`**

这个函数在机器无关的代码上运行，它的核心思想是：**如果在一个支配块中已经成功地进行过相同的 nil 检查，那么当前的 nil 检查就是冗余的。**  它依赖于控制流图的支配关系（Dominance）。

**功能分解:**

* **查找支配的 nil 检查:** 它遍历控制流图，利用支配树 (`f.Sdom()`)，查找是否存在一个支配当前块的前驱块，该前驱块是一个 `BlockIf` 类型的块，并且该 `BlockIf` 的控制条件是一个 `OpIsNonNil` 操作，且跳转的目标是当前块。这意味着在进入当前块之前，已经通过了一个对相同指针的非 nil 检查。
* **记录已知的非 nil 值:**  它维护一个 `nonNilValues` 切片，用于记录在当前支配路径上已知非 nil 的值。
    * 初始时，通过分析指令，例如 `OpAddr`（取地址）、`OpLocalAddr`（取局部变量地址）、`OpAddPtr`（指针加偏移）等，可以推断出这些操作的结果肯定是非 nil 的，因此将它们记录在 `nonNilValues` 中。
    * 如果遇到 `OpPhi` 节点（用于合并不同控制流路径上的值），如果 `OpPhi` 节点的所有参数都已知是非 nil 的，那么该 `OpPhi` 节点的结果也被认为是是非 nil 的。
    * 当遇到 `OpIsNonNil` 且该检查的指针之前没有被标记为非 nil 时，会将该指针标记为非 nil。
* **消除冗余的 `OpIsNonNil`:** 如果发现一个 `OpIsNonNil` 操作的指针已经在 `nonNilValues` 中被标记为非 nil，则该 `OpIsNonNil` 操作是冗余的，会被替换为 `OpConstBool(true)`。
* **消除冗余的 `OpNilCheck`:** 如果发现一个 `OpNilCheck` 操作的指针已经在 `nonNilValues` 中被标记为非 nil，则该 `OpNilCheck` 操作是冗余的，会被替换为 `OpCopy` 操作，复制那个已知的非 nil 值。
* **处理语句边界:**  它还会处理代码的语句边界信息，确保在移除 nil 检查后，语句边界仍然正确。

**Go 代码示例 (推理):**

假设有以下 Go 代码：

```go
package main

func foo(p *int) {
	if p != nil {
		println(*p)
	}
}

func main() {
	var x int = 10
	foo(&x)
}
```

**SSA 代码片段 (假设):**

在 `nilcheckelim` 运行之前，`foo` 函数的 SSA 可能包含如下片段：

```
b1:
    v1 = Param: *int
    v2 = IsNonNil v1  // OpIsNonNil
    If v2 -> b2, b3

b2: // p != nil 的分支
    v3 = NilCheck v1  // OpNilCheck (隐式 nil 检查，用于触发 panic)
    v4 = Load v1       // 解引用 *p
    ...
```

**`nilcheckelim` 的处理 (假设):**

1. 在 `b1` 块中，`OpIsNonNil v1` 会将 `v1` 标记为在 `b2` 块中是非 nil 的（因为 `b2` 是 `b1` 的 `true` 分支）。
2. 当处理 `b2` 块时，遇到 `OpNilCheck v1`，因为 `v1` 已经在 `nonNilValues` 中，所以 `OpNilCheck v1` 被认为是冗余的，会被替换为 `OpCopy v1`。

**处理后的 SSA 代码片段 (假设):**

```
b1:
    v1 = Param: *int
    v2 = IsNonNil v1
    If v2 -> b2, b3

b2: // p != nil 的分支
    v3 = Copy v1
    v4 = Load v1
    ...
```

**假设的输入与输出:**

* **输入:** `Func` 类型的对象 `f`，代表 `foo` 函数的 SSA 中间表示。
* **输出:** 修改后的 `f`，其中冗余的 `OpNilCheck` 被移除。

**2. `nilcheckelim2(f *Func)`**

这个函数在 lowering 和调度之后运行，它利用了这样一个事实：**某些指令（如 Load, Store）在操作 nil 指针时会触发硬件级别的错误（segmentation fault），因此在这些指令之前的显式 nil 检查是多余的。**

**功能分解:**

* **向后遍历块:** 它从后向前遍历每个基本块 `b` 中的指令。
* **记录潜在的故障点:**  维护一个 `unnecessary` map，记录了如果指针为 nil，哪些指令将会触发错误。键是指针的值 ID，值是该指令在 `b.Values` 中的索引。
* **识别冗余的 `OpNilCheck`:** 当遇到一个 `OpNilCheck` 指令时，检查它的参数（指针）。如果该指针已经在 `unnecessary` map 中，意味着后面会有一个指令在它为 nil 时会触发错误，那么当前的 `OpNilCheck` 就是冗余的，会被替换为 `OpUnknown` (稍后会被移除)。
* **识别会触发故障的指令:**  检查指令的操作码 (`opcodeTable`) 是否标记了 `faultOnNilArg0` 或 `faultOnNilArg1`，并且判断是否满足触发故障的条件（例如，对于 AIX 系统，只有写操作才会触发故障）。
* **处理语句边界:** 类似于 `nilcheckelim`，它也负责处理语句边界信息。

**Go 代码示例 (推理):**

假设有以下 Go 代码：

```go
package main

func foo(p *int) {
	_ = *p // 解引用，如果 p 是 nil 会 panic
}

func main() {
	var ptr *int
	foo(ptr)
}
```

**SSA 代码片段 (假设):**

在 `nilcheckelim2` 运行之前，`foo` 函数的 SSA 可能包含如下片段：

```
b1:
    v1 = Param: *int
    v2 = NilCheck v1  // OpNilCheck
    v3 = Load v1
    ...
```

**`nilcheckelim2` 的处理 (假设):**

1. 从后向前遍历，当遇到 `v3 = Load v1` 时，由于 `opcodeTable[OpLoad].faultOnNilArg0` 为 true (假设)，并且满足触发故障的条件，因此将 `v1` 加入 `unnecessary` map，值为 `v3` 的索引。
2. 当向前遍历到 `v2 = NilCheck v1` 时，发现 `v1` 存在于 `unnecessary` map 中，因此 `v2` 被认为是冗余的，会被替换为 `OpUnknown`。
3. 最后，`OpUnknown` 的指令会被移除。

**假设的输入与输出:**

* **输入:** `Func` 类型的对象 `f`，代表 `foo` 函数的 SSA 中间表示。
* **输出:** 修改后的 `f`，其中冗余的 `OpNilCheck` 被移除。

**命令行参数:**

这段代码本身不直接处理命令行参数。但是，Go 编译器的其他命令行参数可能会影响这两个 pass 的行为，例如：

* **`-gcflags="-N"`:**  禁用所有优化，包括 nil 检查消除。
* **`-gcflags="-d=checkptr=1"` 或更高的值:** 启用更严格的指针检查，可能会影响 nil 检查消除的策略。
* **内部的调试选项:**  `f.fe.Debug_checknil()` 似乎是一个内部的调试标志，可能用于控制是否输出被移除的 nil 检查的警告信息。这个标志可能不是通过标准命令行参数直接控制的。

**使用者易犯错的点 (针对编译器开发者):**

* **不正确的支配关系分析:** `nilcheckelim` 依赖于正确的支配关系计算。如果支配树计算错误，可能会错误地移除必要的 nil 检查，导致程序崩溃。
* **错误的故障指令判断:** `nilcheckelim2` 依赖于 `opcodeTable` 中对哪些指令会在 nil 指针上触发故障的正确标记。如果标记错误，可能会错误地移除必要的 nil 检查，或者保留不必要的 nil 检查。
* **忽略内存操作的副作用:** 在 `nilcheckelim2` 中，需要仔细考虑哪些内存操作会改变内存状态，从而使之前记录的潜在故障点失效。例如，在两个可能触发故障的指令之间有一个 store 操作，那么第一个故障点的记录可能不再有效。
* **语句边界处理不当:**  在移除 nil 检查时，需要正确地移动或删除相关的语句边界信息，以保证调试信息的准确性。

**总结:**

`nilcheckelim` 和 `nilcheckelim2` 是 Go 编译器中重要的优化 pass，用于提高程序性能，减少不必要的 nil 检查。 `nilcheckelim` 利用控制流的支配关系，在更早的阶段进行优化，而 `nilcheckelim2` 则利用硬件的故障机制，在更低的层次上进行优化。理解这两个 pass 的工作原理有助于理解 Go 编译器的优化策略。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/nilcheck.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/ir"
	"cmd/internal/src"
	"internal/buildcfg"
)

// nilcheckelim eliminates unnecessary nil checks.
// runs on machine-independent code.
func nilcheckelim(f *Func) {
	// A nil check is redundant if the same nil check was successful in a
	// dominating block. The efficacy of this pass depends heavily on the
	// efficacy of the cse pass.
	sdom := f.Sdom()

	// TODO: Eliminate more nil checks.
	// We can recursively remove any chain of fixed offset calculations,
	// i.e. struct fields and array elements, even with non-constant
	// indices: x is non-nil iff x.a.b[i].c is.

	type walkState int
	const (
		Work     walkState = iota // process nil checks and traverse to dominees
		ClearPtr                  // forget the fact that ptr is nil
	)

	type bp struct {
		block *Block // block, or nil in ClearPtr state
		ptr   *Value // if non-nil, ptr that is to be cleared in ClearPtr state
		op    walkState
	}

	work := make([]bp, 0, 256)
	work = append(work, bp{block: f.Entry})

	// map from value ID to known non-nil version of that value ID
	// (in the current dominator path being walked). This slice is updated by
	// walkStates to maintain the known non-nil values.
	// If there is extrinsic information about non-nil-ness, this map
	// points a value to itself. If a value is known non-nil because we
	// already did a nil check on it, it points to the nil check operation.
	nonNilValues := f.Cache.allocValueSlice(f.NumValues())
	defer f.Cache.freeValueSlice(nonNilValues)

	// make an initial pass identifying any non-nil values
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			// a value resulting from taking the address of a
			// value, or a value constructed from an offset of a
			// non-nil ptr (OpAddPtr) implies it is non-nil
			// We also assume unsafe pointer arithmetic generates non-nil pointers. See #27180.
			// We assume that SlicePtr is non-nil because we do a bounds check
			// before the slice access (and all cap>0 slices have a non-nil ptr). See #30366.
			if v.Op == OpAddr || v.Op == OpLocalAddr || v.Op == OpAddPtr || v.Op == OpOffPtr || v.Op == OpAdd32 || v.Op == OpAdd64 || v.Op == OpSub32 || v.Op == OpSub64 || v.Op == OpSlicePtr {
				nonNilValues[v.ID] = v
			}
		}
	}

	for changed := true; changed; {
		changed = false
		for _, b := range f.Blocks {
			for _, v := range b.Values {
				// phis whose arguments are all non-nil
				// are non-nil
				if v.Op == OpPhi {
					argsNonNil := true
					for _, a := range v.Args {
						if nonNilValues[a.ID] == nil {
							argsNonNil = false
							break
						}
					}
					if argsNonNil {
						if nonNilValues[v.ID] == nil {
							changed = true
						}
						nonNilValues[v.ID] = v
					}
				}
			}
		}
	}

	// allocate auxiliary date structures for computing store order
	sset := f.newSparseSet(f.NumValues())
	defer f.retSparseSet(sset)
	storeNumber := f.Cache.allocInt32Slice(f.NumValues())
	defer f.Cache.freeInt32Slice(storeNumber)

	// perform a depth first walk of the dominee tree
	for len(work) > 0 {
		node := work[len(work)-1]
		work = work[:len(work)-1]

		switch node.op {
		case Work:
			b := node.block

			// First, see if we're dominated by an explicit nil check.
			if len(b.Preds) == 1 {
				p := b.Preds[0].b
				if p.Kind == BlockIf && p.Controls[0].Op == OpIsNonNil && p.Succs[0].b == b {
					if ptr := p.Controls[0].Args[0]; nonNilValues[ptr.ID] == nil {
						nonNilValues[ptr.ID] = ptr
						work = append(work, bp{op: ClearPtr, ptr: ptr})
					}
				}
			}

			// Next, order values in the current block w.r.t. stores.
			b.Values = storeOrder(b.Values, sset, storeNumber)

			pendingLines := f.cachedLineStarts // Holds statement boundaries that need to be moved to a new value/block
			pendingLines.clear()

			// Next, process values in the block.
			for _, v := range b.Values {
				switch v.Op {
				case OpIsNonNil:
					ptr := v.Args[0]
					if nonNilValues[ptr.ID] != nil {
						if v.Pos.IsStmt() == src.PosIsStmt { // Boolean true is a terrible statement boundary.
							pendingLines.add(v.Pos)
							v.Pos = v.Pos.WithNotStmt()
						}
						// This is a redundant explicit nil check.
						v.reset(OpConstBool)
						v.AuxInt = 1 // true
					}
				case OpNilCheck:
					ptr := v.Args[0]
					if nilCheck := nonNilValues[ptr.ID]; nilCheck != nil {
						// This is a redundant implicit nil check.
						// Logging in the style of the former compiler -- and omit line 1,
						// which is usually in generated code.
						if f.fe.Debug_checknil() && v.Pos.Line() > 1 {
							f.Warnl(v.Pos, "removed nil check")
						}
						if v.Pos.IsStmt() == src.PosIsStmt { // About to lose a statement boundary
							pendingLines.add(v.Pos)
						}
						v.Op = OpCopy
						v.SetArgs1(nilCheck)
						continue
					}
					// Record the fact that we know ptr is non nil, and remember to
					// undo that information when this dominator subtree is done.
					nonNilValues[ptr.ID] = v
					work = append(work, bp{op: ClearPtr, ptr: ptr})
					fallthrough // a non-eliminated nil check might be a good place for a statement boundary.
				default:
					if v.Pos.IsStmt() != src.PosNotStmt && !isPoorStatementOp(v.Op) && pendingLines.contains(v.Pos) {
						v.Pos = v.Pos.WithIsStmt()
						pendingLines.remove(v.Pos)
					}
				}
			}
			// This reduces the lost statement count in "go" by 5 (out of 500 total).
			for j := range b.Values { // is this an ordering problem?
				v := b.Values[j]
				if v.Pos.IsStmt() != src.PosNotStmt && !isPoorStatementOp(v.Op) && pendingLines.contains(v.Pos) {
					v.Pos = v.Pos.WithIsStmt()
					pendingLines.remove(v.Pos)
				}
			}
			if pendingLines.contains(b.Pos) {
				b.Pos = b.Pos.WithIsStmt()
				pendingLines.remove(b.Pos)
			}

			// Add all dominated blocks to the work list.
			for w := sdom[node.block.ID].child; w != nil; w = sdom[w.ID].sibling {
				work = append(work, bp{op: Work, block: w})
			}

		case ClearPtr:
			nonNilValues[node.ptr.ID] = nil
			continue
		}
	}
}

// All platforms are guaranteed to fault if we load/store to anything smaller than this address.
//
// This should agree with minLegalPointer in the runtime.
const minZeroPage = 4096

// faultOnLoad is true if a load to an address below minZeroPage will trigger a SIGSEGV.
var faultOnLoad = buildcfg.GOOS != "aix"

// nilcheckelim2 eliminates unnecessary nil checks.
// Runs after lowering and scheduling.
func nilcheckelim2(f *Func) {
	unnecessary := f.newSparseMap(f.NumValues()) // map from pointer that will be dereferenced to index of dereferencing value in b.Values[]
	defer f.retSparseMap(unnecessary)

	pendingLines := f.cachedLineStarts // Holds statement boundaries that need to be moved to a new value/block

	for _, b := range f.Blocks {
		// Walk the block backwards. Find instructions that will fault if their
		// input pointer is nil. Remove nil checks on those pointers, as the
		// faulting instruction effectively does the nil check for free.
		unnecessary.clear()
		pendingLines.clear()
		// Optimization: keep track of removed nilcheck with smallest index
		firstToRemove := len(b.Values)
		for i := len(b.Values) - 1; i >= 0; i-- {
			v := b.Values[i]
			if opcodeTable[v.Op].nilCheck && unnecessary.contains(v.Args[0].ID) {
				if f.fe.Debug_checknil() && v.Pos.Line() > 1 {
					f.Warnl(v.Pos, "removed nil check")
				}
				// For bug 33724, policy is that we might choose to bump an existing position
				// off the faulting load/store in favor of the one from the nil check.

				// Iteration order means that first nilcheck in the chain wins, others
				// are bumped into the ordinary statement preservation algorithm.
				u := b.Values[unnecessary.get(v.Args[0].ID)]
				if !u.Pos.SameFileAndLine(v.Pos) {
					if u.Pos.IsStmt() == src.PosIsStmt {
						pendingLines.add(u.Pos)
					}
					u.Pos = v.Pos
				} else if v.Pos.IsStmt() == src.PosIsStmt {
					pendingLines.add(v.Pos)
				}

				v.reset(OpUnknown)
				firstToRemove = i
				continue
			}
			if v.Type.IsMemory() || v.Type.IsTuple() && v.Type.FieldType(1).IsMemory() {
				if v.Op == OpVarLive || (v.Op == OpVarDef && !v.Aux.(*ir.Name).Type().HasPointers()) {
					// These ops don't really change memory.
					continue
					// Note: OpVarDef requires that the defined variable not have pointers.
					// We need to make sure that there's no possible faulting
					// instruction between a VarDef and that variable being
					// fully initialized. If there was, then anything scanning
					// the stack during the handling of that fault will see
					// a live but uninitialized pointer variable on the stack.
					//
					// If we have:
					//
					//   NilCheck p
					//   VarDef x
					//   x = *p
					//
					// We can't rewrite that to
					//
					//   VarDef x
					//   NilCheck p
					//   x = *p
					//
					// Particularly, even though *p faults on p==nil, we still
					// have to do the explicit nil check before the VarDef.
					// See issue #32288.
				}
				// This op changes memory.  Any faulting instruction after v that
				// we've recorded in the unnecessary map is now obsolete.
				unnecessary.clear()
			}

			// Find any pointers that this op is guaranteed to fault on if nil.
			var ptrstore [2]*Value
			ptrs := ptrstore[:0]
			if opcodeTable[v.Op].faultOnNilArg0 && (faultOnLoad || v.Type.IsMemory()) {
				// On AIX, only writing will fault.
				ptrs = append(ptrs, v.Args[0])
			}
			if opcodeTable[v.Op].faultOnNilArg1 && (faultOnLoad || (v.Type.IsMemory() && v.Op != OpPPC64LoweredMove)) {
				// On AIX, only writing will fault.
				// LoweredMove is a special case because it's considered as a "mem" as it stores on arg0 but arg1 is accessed as a load and should be checked.
				ptrs = append(ptrs, v.Args[1])
			}

			for _, ptr := range ptrs {
				// Check to make sure the offset is small.
				switch opcodeTable[v.Op].auxType {
				case auxSym:
					if v.Aux != nil {
						continue
					}
				case auxSymOff:
					if v.Aux != nil || v.AuxInt < 0 || v.AuxInt >= minZeroPage {
						continue
					}
				case auxSymValAndOff:
					off := ValAndOff(v.AuxInt).Off()
					if v.Aux != nil || off < 0 || off >= minZeroPage {
						continue
					}
				case auxInt32:
					// Mips uses this auxType for atomic add constant. It does not affect the effective address.
				case auxInt64:
					// ARM uses this auxType for duffcopy/duffzero/alignment info.
					// It does not affect the effective address.
				case auxNone:
					// offset is zero.
				default:
					v.Fatalf("can't handle aux %s (type %d) yet\n", v.auxString(), int(opcodeTable[v.Op].auxType))
				}
				// This instruction is guaranteed to fault if ptr is nil.
				// Any previous nil check op is unnecessary.
				unnecessary.set(ptr.ID, int32(i))
			}
		}
		// Remove values we've clobbered with OpUnknown.
		i := firstToRemove
		for j := i; j < len(b.Values); j++ {
			v := b.Values[j]
			if v.Op != OpUnknown {
				if !notStmtBoundary(v.Op) && pendingLines.contains(v.Pos) { // Late in compilation, so any remaining NotStmt values are probably okay now.
					v.Pos = v.Pos.WithIsStmt()
					pendingLines.remove(v.Pos)
				}
				b.Values[i] = v
				i++
			}
		}

		if pendingLines.contains(b.Pos) {
			b.Pos = b.Pos.WithIsStmt()
		}

		b.truncateValues(i)

		// TODO: if b.Kind == BlockPlain, start the analysis in the subsequent block to find
		// more unnecessary nil checks.  Would fix test/nilptr3.go:159.
	}
}

"""



```