Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understanding the Goal:** The request asks for the functionality of the provided Go code, which is located in `go/src/cmd/compile/internal/ssagen/phi.go`. The core clue is the filename and the package name: "phi" and "ssagen". This immediately suggests it deals with the placement of phi nodes in Static Single Assignment (SSA) form during Go compilation.

2. **Initial Code Scan - High-Level Structure:**  I'll quickly scan the code for key elements:
    * **Package and Imports:**  `package ssagen`, imports related to SSA, IR, types, and potentially data structures (`container/heap`). This confirms the compilation context.
    * **Constants:** `smallBlocks`, `debugPhi`. These provide insights into optimization strategies (handling small vs. large functions) and debugging.
    * **`fwdRefAux`:**  This struct and its methods seem related to forward references, a common concept in SSA construction.
    * **`insertPhis` function:**  The central function name directly indicates its purpose. Notice the conditional logic based on `smallBlocks`, suggesting two different algorithms.
    * **`phiState` and `simplePhiState` structs:** These likely hold the state required for the two phi insertion algorithms.
    * **Helper functions:**  Functions like `insertVarPhis`, `resolveFwdRefs`, `lookupVarOutgoing`. These suggest a step-by-step process.
    * **Data structures:** `blockHeap`, `sparseSet`. These indicate optimizations for managing blocks and sets of blocks.

3. **Focusing on the Core Functionality (`insertPhis`)**: The `insertPhis` function is the entry point. The conditional logic based on `len(s.f.Blocks)` is crucial. This immediately tells me there are two distinct approaches for small and large functions. The comments also explicitly mention the algorithms used: Braun et al. for small functions and Sreedhar & Gao for large functions.

4. **Analyzing the Large Function Algorithm (`phiState`):**
    * **Variable Identification:** The code iterates through `OpFwdRef` instructions to identify variables that need phi nodes. It optimizes for single-predecessor blocks.
    * **Definition Tracking:** It builds a `defs` structure to store where each variable is defined.
    * **Dominator Tree Construction:**  The code explicitly builds the dominator tree (`idom`, `tree`, `level`). This is a core component of many phi placement algorithms.
    * **Phi Insertion (`insertVarPhis`):** This function appears to implement the core logic. The use of a priority queue (`blockHeap`) hints at the Sreedhar & Gao algorithm. It iterates through definitions and walks the dominator tree to find where phis are needed.
    * **Forward Reference Resolution (`resolveFwdRefs`):** This function links the `OpFwdRef` instructions to their corresponding definitions or phi nodes. It uses a depth-first traversal of the dominator tree.

5. **Analyzing the Small Function Algorithm (`simplePhiState`):**
    * **Simpler Approach:** The code structure seems less complex. It directly iterates through `OpFwdRef` instructions.
    * **Iterative Resolution:** The `loop` and `lookupVarOutgoing` functions suggest an iterative approach to resolving forward references and inserting phis as needed. It doesn't explicitly construct a dominator tree.
    * **Local Reasoning:** The `lookupVarOutgoing` function focuses on looking up definitions in predecessors, suggesting a more local analysis.

6. **Inferring Go Language Features:** Based on the code's functionality, the most relevant Go feature is **variable assignment across control flow paths**. Phi nodes are precisely the mechanism to handle this in SSA. I can construct a simple example where a variable is assigned different values in different branches of an `if` statement, and then used after the `if`.

7. **Code Example Construction:**  The example should demonstrate a scenario where a phi node is necessary. An `if-else` statement with variable assignment in each branch is the classic example. The output should illustrate how the phi node merges the values.

8. **Command-Line Arguments:** Since the code is part of the compiler (`cmd/compile`), I need to consider how these phi insertion algorithms are triggered. Compiling a Go program will implicitly use these algorithms. There aren't specific command-line flags *just* for phi insertion, but compiler optimizations in general (`-N`, `-l`) might indirectly affect the SSA generation and thus phi placement.

9. **Common Mistakes:**  Thinking about potential pitfalls, the main one is misunderstanding *when* a phi node is needed. It's easy to assume a simple copy is sufficient. The example demonstrates why a phi is essential when control flow merges.

10. **Refining the Explanation:**  Review the generated information for clarity, accuracy, and completeness. Ensure the connections between the code, the algorithms, and the Go language feature are clearly explained. Add details about the data structures (sparse set, block heap) and the purpose of `fwdRefAux`.

This systematic approach, moving from high-level understanding to detailed analysis and example construction, allows for a comprehensive explanation of the code's functionality. The process involves code reading, pattern recognition (dominator trees, SSA concepts), and connecting the implementation to the underlying theoretical concepts.
这段代码是Go语言编译器中用于在 **静态单赋值 (SSA) 中插入 Phi 节点** 的实现。

**功能概览:**

这段代码的核心功能是在 Go 函数的 SSA 中找到所有需要插入 Phi 节点的位置并进行插入。Phi 节点是 SSA 形式的关键组成部分，用于合并来自不同控制流路径的变量定义。

代码针对不同大小的函数采用了两种不同的算法：

1. **小型函数 (blocks <= 500): Braun, Buchwald, Hack, Leißa, Mallon, and Zwinkau 算法**
   - `simplePhiState` 结构体及其 `insertPhis` 方法实现了这个算法。
   - 它通过迭代地遍历前向引用 (FwdRef)，并查找变量在每个前驱块的定义来决定是否需要插入 Phi 节点。
   - 如果一个变量在一个块的多个前驱块中具有不同的定义，则需要在该块的开头插入一个 Phi 节点来合并这些定义。

2. **大型函数 (blocks > 500): Sreedhar & Gao 算法**
   - `phiState` 结构体及其 `insertPhis` 方法实现了这个算法。
   - 这个算法基于支配树 (Dominator Tree) 和支配边界 (Dominance Frontier) 的概念。
   - 它首先构建函数的支配树。
   - 然后，对于每个在多个控制流路径中被定义的变量，它会在该变量定义的支配边界上的块中插入 Phi 节点。

**更具体的步骤和数据结构:**

* **`fwdRefAux`:**  这是一个辅助结构体，用于将 `ir.Node` (中间表示的节点，通常代表变量) 包装成 `ssa.Aux`，以便在 `OpFwdref` 操作中使用。`OpFwdref`  表示一个对尚未确定定义的变量的引用。

* **`insertPhis()`:**  这是入口函数，它根据函数块的数量选择使用 `simplePhiState` 或 `phiState` 来执行 Phi 节点的插入。

* **`phiState` 结构体:** 用于存储大型函数 Phi 节点插入所需的状态信息：
    * `s`: 指向 SSA 状态的指针。
    * `f`: 指向要处理的 SSA 函数的指针。
    * `defvars`: 一个切片，每个元素是一个 map，用于存储每个基本块结束时定义的变量及其对应的 SSA 值。
    * `varnum`: 一个 map，用于给需要插入 Phi 节点的变量分配唯一的编号。
    * **支配树相关:** `idom` (直接支配节点), `tree` (支配树的子节点和兄弟节点), `level` (节点在支配树中的层级)。
    * **临时存储:** `priq` (用于 Sreedhar & Gao 算法的优先级队列), `q` (内部循环队列), `queued` (记录已加入队列的块), `hasPhi` (记录已插入 Phi 节点的块), `hasDef` (记录变量已被定义的块)。
    * `placeholder`: 一个占位符 SSA 值，用于在 Phi 节点的参数尚未确定时使用。

* **`simplePhiState` 结构体:** 用于存储小型函数 Phi 节点插入所需的状态信息：
    * `s`, `f`, `defvars`: 与 `phiState` 类似。
    * `fwdrefs`:  需要处理的 `OpFwdRef` 操作的列表。
    * `reachable`: 一个布尔切片，指示哪些基本块是可达的。

* **`insertVarPhis()` (在 `phiState` 中):**  对于每个需要在多个控制流路径中定义的变量，这个函数执行以下操作：
    1. 使用优先级队列 `priq` 初始化定义了该变量的块。
    2. 从优先级队列中弹出块（从支配树的较深层到较浅层）。
    3. 遍历以当前块为根的支配子树。
    4. 找到支配边界上的块。
    5. 在支配边界上的块中插入 Phi 节点。

* **`resolveFwdRefs()` (在 `phiState` 中):**  在插入所有必要的 Phi 节点后，这个函数将所有的 `OpFwdRef` 操作替换为对正确定义或 Phi 节点的引用。它通过深度优先遍历支配树来跟踪每个变量的最新定义。

* **`lookupVarOutgoing()` (在 `simplePhiState` 中):**  用于查找在给定基本块结束时变量的值。如果变量在该块中没有定义，它会沿着控制流向后查找（如果只有一个前驱块）。如果找到多个前驱或到达入口块，它会创建一个新的 `OpFwdRef`。

**推断的 Go 语言功能实现:**

这段代码是 Go 编译器实现 SSA 转换过程中的关键一步。SSA 是现代编译器中常用的中间表示形式，它具有以下优点：

* **简化分析和优化:** 每个变量只被赋值一次，使得数据流分析和各种优化变得更容易实现。
* **方便寄存器分配:**  SSA 形式有助于编译器更有效地进行寄存器分配。

**Go 代码示例说明:**

```go
package main

func foo(a int, b bool) int {
	var x int
	if b {
		x = a + 1
	} else {
		x = a - 1
	}
	return x // 在这里需要一个 Phi 节点来合并 if 和 else 分支对 x 的赋值
}

func main() {
	println(foo(10, true))
	println(foo(10, false))
}
```

**假设的 SSA 输入 (简化):**

```
// Entry block
b1:
  v0 = Arg: a
  v1 = Arg: b
  goto b2

// If condition
b2:
  if v1 goto b3 else b4

// Then branch
b3:
  v2 = Add v0, 1
  goto b5

// Else branch
b4:
  v3 = Sub v0, 1
  goto b5

// Merge point
b5:
  // 在这里，x 的值可能来自 b3 (v2) 或 b4 (v3)
  // 需要一个 Phi 节点来合并这两个值
  v4 = Phi v2, v3
  Ret v4
```

**假设的 SSA 输出 (插入 Phi 节点后):**

```
// Entry block
b1:
  v0 = Arg: a
  v1 = Arg: b
  goto b2

// If condition
b2:
  if v1 goto b3 else b4

// Then branch
b3:
  v2 = Add v0, 1
  goto b5

// Else branch
b4:
  v3 = Sub v0, 1
  goto b5

// Merge point
b5:
  v4 = Phi v2, v3 // Phi 节点，根据前驱块选择 v2 或 v3
  Ret v4
```

在这个例子中，变量 `x` 在 `if` 语句的不同分支中被赋予了不同的值。当控制流汇聚到 `return x` 时，编译器需要知道 `x` 的值是哪个分支赋予的。Phi 节点 `v4 = Phi v2, v3` 就解决了这个问题。

**命令行参数:**

这段代码本身并不直接处理命令行参数。它是 Go 编译器内部实现的一部分。但是，Go 编译器的某些命令行参数可能会影响 SSA 的生成和优化，从而间接地影响 Phi 节点的插入：

* **`-N`:** 禁用优化。禁用优化可能会导致更少的 Phi 节点被优化掉。
* **`-l`:** 禁用内联。内联会改变函数的控制流图，从而影响 Phi 节点的插入位置。
* **`-gcflags`:**  允许传递底层的编译器标志。虽然不太可能直接控制 Phi 节点的插入，但一些更底层的标志可能会有影响。

**使用者易犯错的点:**

作为编译器内部的实现，普通 Go 程序员通常不会直接与这段代码交互，因此不容易犯错。 但是，理解 Phi 节点及其背后的概念对于理解编译器优化和程序性能至关重要。

**容易误解的地方:**

* **Phi 节点不是真正的运行时操作:**  Phi 节点存在于 SSA 中间表示，在最终的代码生成阶段会被替换成实际的移动或选择操作。初学者可能会误认为 Phi 节点是程序运行时执行的指令。
* **Phi 节点与变量的作用域无关:** Phi 节点的存在是为了处理控制流的汇聚，而不是为了定义变量的作用域。变量的作用域在更早的阶段就已经确定了。

总而言之，`phi.go` 文件中的代码是 Go 编译器中一个复杂但至关重要的部分，它负责将 Go 代码转换为高效的可执行代码的中间表示形式，为后续的优化和代码生成奠定了基础。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssagen/phi.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssagen

import (
	"container/heap"
	"fmt"

	"cmd/compile/internal/ir"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/types"
	"cmd/internal/src"
)

// This file contains the algorithm to place phi nodes in a function.
// For small functions, we use Braun, Buchwald, Hack, Leißa, Mallon, and Zwinkau.
// https://pp.info.uni-karlsruhe.de/uploads/publikationen/braun13cc.pdf
// For large functions, we use Sreedhar & Gao: A Linear Time Algorithm for Placing Φ-Nodes.
// http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.8.1979&rep=rep1&type=pdf

const smallBlocks = 500

const debugPhi = false

// fwdRefAux wraps an arbitrary ir.Node as an ssa.Aux for use with OpFwdref.
type fwdRefAux struct {
	_ [0]func() // ensure ir.Node isn't compared for equality
	N ir.Node
}

func (fwdRefAux) CanBeAnSSAAux() {}

// insertPhis finds all the places in the function where a phi is
// necessary and inserts them.
// Uses FwdRef ops to find all uses of variables, and s.defvars to find
// all definitions.
// Phi values are inserted, and all FwdRefs are changed to a Copy
// of the appropriate phi or definition.
// TODO: make this part of cmd/compile/internal/ssa somehow?
func (s *state) insertPhis() {
	if len(s.f.Blocks) <= smallBlocks {
		sps := simplePhiState{s: s, f: s.f, defvars: s.defvars}
		sps.insertPhis()
		return
	}
	ps := phiState{s: s, f: s.f, defvars: s.defvars}
	ps.insertPhis()
}

type phiState struct {
	s       *state                   // SSA state
	f       *ssa.Func                // function to work on
	defvars []map[ir.Node]*ssa.Value // defined variables at end of each block

	varnum map[ir.Node]int32 // variable numbering

	// properties of the dominator tree
	idom  []*ssa.Block // dominator parents
	tree  []domBlock   // dominator child+sibling
	level []int32      // level in dominator tree (0 = root or unreachable, 1 = children of root, ...)

	// scratch locations
	priq   blockHeap    // priority queue of blocks, higher level (toward leaves) = higher priority
	q      []*ssa.Block // inner loop queue
	queued *sparseSet   // has been put in q
	hasPhi *sparseSet   // has a phi
	hasDef *sparseSet   // has a write of the variable we're processing

	// miscellaneous
	placeholder *ssa.Value // value to use as a "not set yet" placeholder.
}

func (s *phiState) insertPhis() {
	if debugPhi {
		fmt.Println(s.f.String())
	}

	// Find all the variables for which we need to match up reads & writes.
	// This step prunes any basic-block-only variables from consideration.
	// Generate a numbering for these variables.
	s.varnum = map[ir.Node]int32{}
	var vars []ir.Node
	var vartypes []*types.Type
	for _, b := range s.f.Blocks {
		for _, v := range b.Values {
			if v.Op != ssa.OpFwdRef {
				continue
			}
			var_ := v.Aux.(fwdRefAux).N

			// Optimization: look back 1 block for the definition.
			if len(b.Preds) == 1 {
				c := b.Preds[0].Block()
				if w := s.defvars[c.ID][var_]; w != nil {
					v.Op = ssa.OpCopy
					v.Aux = nil
					v.AddArg(w)
					continue
				}
			}

			if _, ok := s.varnum[var_]; ok {
				continue
			}
			s.varnum[var_] = int32(len(vartypes))
			if debugPhi {
				fmt.Printf("var%d = %v\n", len(vartypes), var_)
			}
			vars = append(vars, var_)
			vartypes = append(vartypes, v.Type)
		}
	}

	if len(vartypes) == 0 {
		return
	}

	// Find all definitions of the variables we need to process.
	// defs[n] contains all the blocks in which variable number n is assigned.
	defs := make([][]*ssa.Block, len(vartypes))
	for _, b := range s.f.Blocks {
		for var_ := range s.defvars[b.ID] { // TODO: encode defvars some other way (explicit ops)? make defvars[n] a slice instead of a map.
			if n, ok := s.varnum[var_]; ok {
				defs[n] = append(defs[n], b)
			}
		}
	}

	// Make dominator tree.
	s.idom = s.f.Idom()
	s.tree = make([]domBlock, s.f.NumBlocks())
	for _, b := range s.f.Blocks {
		p := s.idom[b.ID]
		if p != nil {
			s.tree[b.ID].sibling = s.tree[p.ID].firstChild
			s.tree[p.ID].firstChild = b
		}
	}
	// Compute levels in dominator tree.
	// With parent pointers we can do a depth-first walk without
	// any auxiliary storage.
	s.level = make([]int32, s.f.NumBlocks())
	b := s.f.Entry
levels:
	for {
		if p := s.idom[b.ID]; p != nil {
			s.level[b.ID] = s.level[p.ID] + 1
			if debugPhi {
				fmt.Printf("level %s = %d\n", b, s.level[b.ID])
			}
		}
		if c := s.tree[b.ID].firstChild; c != nil {
			b = c
			continue
		}
		for {
			if c := s.tree[b.ID].sibling; c != nil {
				b = c
				continue levels
			}
			b = s.idom[b.ID]
			if b == nil {
				break levels
			}
		}
	}

	// Allocate scratch locations.
	s.priq.level = s.level
	s.q = make([]*ssa.Block, 0, s.f.NumBlocks())
	s.queued = newSparseSet(s.f.NumBlocks())
	s.hasPhi = newSparseSet(s.f.NumBlocks())
	s.hasDef = newSparseSet(s.f.NumBlocks())
	s.placeholder = s.s.entryNewValue0(ssa.OpUnknown, types.TypeInvalid)

	// Generate phi ops for each variable.
	for n := range vartypes {
		s.insertVarPhis(n, vars[n], defs[n], vartypes[n])
	}

	// Resolve FwdRefs to the correct write or phi.
	s.resolveFwdRefs()

	// Erase variable numbers stored in AuxInt fields of phi ops. They are no longer needed.
	for _, b := range s.f.Blocks {
		for _, v := range b.Values {
			if v.Op == ssa.OpPhi {
				v.AuxInt = 0
			}
			// Any remaining FwdRefs are dead code.
			if v.Op == ssa.OpFwdRef {
				v.Op = ssa.OpUnknown
				v.Aux = nil
			}
		}
	}
}

func (s *phiState) insertVarPhis(n int, var_ ir.Node, defs []*ssa.Block, typ *types.Type) {
	priq := &s.priq
	q := s.q
	queued := s.queued
	queued.clear()
	hasPhi := s.hasPhi
	hasPhi.clear()
	hasDef := s.hasDef
	hasDef.clear()

	// Add defining blocks to priority queue.
	for _, b := range defs {
		priq.a = append(priq.a, b)
		hasDef.add(b.ID)
		if debugPhi {
			fmt.Printf("def of var%d in %s\n", n, b)
		}
	}
	heap.Init(priq)

	// Visit blocks defining variable n, from deepest to shallowest.
	for len(priq.a) > 0 {
		currentRoot := heap.Pop(priq).(*ssa.Block)
		if debugPhi {
			fmt.Printf("currentRoot %s\n", currentRoot)
		}
		// Walk subtree below definition.
		// Skip subtrees we've done in previous iterations.
		// Find edges exiting tree dominated by definition (the dominance frontier).
		// Insert phis at target blocks.
		if queued.contains(currentRoot.ID) {
			s.s.Fatalf("root already in queue")
		}
		q = append(q, currentRoot)
		queued.add(currentRoot.ID)
		for len(q) > 0 {
			b := q[len(q)-1]
			q = q[:len(q)-1]
			if debugPhi {
				fmt.Printf("  processing %s\n", b)
			}

			currentRootLevel := s.level[currentRoot.ID]
			for _, e := range b.Succs {
				c := e.Block()
				// TODO: if the variable is dead at c, skip it.
				if s.level[c.ID] > currentRootLevel {
					// a D-edge, or an edge whose target is in currentRoot's subtree.
					continue
				}
				if hasPhi.contains(c.ID) {
					continue
				}
				// Add a phi to block c for variable n.
				hasPhi.add(c.ID)
				v := c.NewValue0I(currentRoot.Pos, ssa.OpPhi, typ, int64(n)) // TODO: line number right?
				// Note: we store the variable number in the phi's AuxInt field. Used temporarily by phi building.
				if var_.Op() == ir.ONAME {
					s.s.addNamedValue(var_.(*ir.Name), v)
				}
				for range c.Preds {
					v.AddArg(s.placeholder) // Actual args will be filled in by resolveFwdRefs.
				}
				if debugPhi {
					fmt.Printf("new phi for var%d in %s: %s\n", n, c, v)
				}
				if !hasDef.contains(c.ID) {
					// There's now a new definition of this variable in block c.
					// Add it to the priority queue to explore.
					heap.Push(priq, c)
					hasDef.add(c.ID)
				}
			}

			// Visit children if they have not been visited yet.
			for c := s.tree[b.ID].firstChild; c != nil; c = s.tree[c.ID].sibling {
				if !queued.contains(c.ID) {
					q = append(q, c)
					queued.add(c.ID)
				}
			}
		}
	}
}

// resolveFwdRefs links all FwdRef uses up to their nearest dominating definition.
func (s *phiState) resolveFwdRefs() {
	// Do a depth-first walk of the dominator tree, keeping track
	// of the most-recently-seen value for each variable.

	// Map from variable ID to SSA value at the current point of the walk.
	values := make([]*ssa.Value, len(s.varnum))
	for i := range values {
		values[i] = s.placeholder
	}

	// Stack of work to do.
	type stackEntry struct {
		b *ssa.Block // block to explore

		// variable/value pair to reinstate on exit
		n int32 // variable ID
		v *ssa.Value

		// Note: only one of b or n,v will be set.
	}
	var stk []stackEntry

	stk = append(stk, stackEntry{b: s.f.Entry})
	for len(stk) > 0 {
		work := stk[len(stk)-1]
		stk = stk[:len(stk)-1]

		b := work.b
		if b == nil {
			// On exit from a block, this case will undo any assignments done below.
			values[work.n] = work.v
			continue
		}

		// Process phis as new defs. They come before FwdRefs in this block.
		for _, v := range b.Values {
			if v.Op != ssa.OpPhi {
				continue
			}
			n := int32(v.AuxInt)
			// Remember the old assignment so we can undo it when we exit b.
			stk = append(stk, stackEntry{n: n, v: values[n]})
			// Record the new assignment.
			values[n] = v
		}

		// Replace a FwdRef op with the current incoming value for its variable.
		for _, v := range b.Values {
			if v.Op != ssa.OpFwdRef {
				continue
			}
			n := s.varnum[v.Aux.(fwdRefAux).N]
			v.Op = ssa.OpCopy
			v.Aux = nil
			v.AddArg(values[n])
		}

		// Establish values for variables defined in b.
		for var_, v := range s.defvars[b.ID] {
			n, ok := s.varnum[var_]
			if !ok {
				// some variable not live across a basic block boundary.
				continue
			}
			// Remember the old assignment so we can undo it when we exit b.
			stk = append(stk, stackEntry{n: n, v: values[n]})
			// Record the new assignment.
			values[n] = v
		}

		// Replace phi args in successors with the current incoming value.
		for _, e := range b.Succs {
			c, i := e.Block(), e.Index()
			for j := len(c.Values) - 1; j >= 0; j-- {
				v := c.Values[j]
				if v.Op != ssa.OpPhi {
					break // All phis will be at the end of the block during phi building.
				}
				// Only set arguments that have been resolved.
				// For very wide CFGs, this significantly speeds up phi resolution.
				// See golang.org/issue/8225.
				if w := values[v.AuxInt]; w.Op != ssa.OpUnknown {
					v.SetArg(i, w)
				}
			}
		}

		// Walk children in dominator tree.
		for c := s.tree[b.ID].firstChild; c != nil; c = s.tree[c.ID].sibling {
			stk = append(stk, stackEntry{b: c})
		}
	}
}

// domBlock contains extra per-block information to record the dominator tree.
type domBlock struct {
	firstChild *ssa.Block // first child of block in dominator tree
	sibling    *ssa.Block // next child of parent in dominator tree
}

// A block heap is used as a priority queue to implement the PiggyBank
// from Sreedhar and Gao.  That paper uses an array which is better
// asymptotically but worse in the common case when the PiggyBank
// holds a sparse set of blocks.
type blockHeap struct {
	a     []*ssa.Block // block IDs in heap
	level []int32      // depth in dominator tree (static, used for determining priority)
}

func (h *blockHeap) Len() int      { return len(h.a) }
func (h *blockHeap) Swap(i, j int) { a := h.a; a[i], a[j] = a[j], a[i] }

func (h *blockHeap) Push(x interface{}) {
	v := x.(*ssa.Block)
	h.a = append(h.a, v)
}
func (h *blockHeap) Pop() interface{} {
	old := h.a
	n := len(old)
	x := old[n-1]
	h.a = old[:n-1]
	return x
}
func (h *blockHeap) Less(i, j int) bool {
	return h.level[h.a[i].ID] > h.level[h.a[j].ID]
}

// TODO: stop walking the iterated domininance frontier when
// the variable is dead. Maybe detect that by checking if the
// node we're on is reverse dominated by all the reads?
// Reverse dominated by the highest common successor of all the reads?

// copy of ../ssa/sparseset.go
// TODO: move this file to ../ssa, then use sparseSet there.
type sparseSet struct {
	dense  []ssa.ID
	sparse []int32
}

// newSparseSet returns a sparseSet that can represent
// integers between 0 and n-1.
func newSparseSet(n int) *sparseSet {
	return &sparseSet{dense: nil, sparse: make([]int32, n)}
}

func (s *sparseSet) contains(x ssa.ID) bool {
	i := s.sparse[x]
	return i < int32(len(s.dense)) && s.dense[i] == x
}

func (s *sparseSet) add(x ssa.ID) {
	i := s.sparse[x]
	if i < int32(len(s.dense)) && s.dense[i] == x {
		return
	}
	s.dense = append(s.dense, x)
	s.sparse[x] = int32(len(s.dense)) - 1
}

func (s *sparseSet) clear() {
	s.dense = s.dense[:0]
}

// Variant to use for small functions.
type simplePhiState struct {
	s         *state                   // SSA state
	f         *ssa.Func                // function to work on
	fwdrefs   []*ssa.Value             // list of FwdRefs to be processed
	defvars   []map[ir.Node]*ssa.Value // defined variables at end of each block
	reachable []bool                   // which blocks are reachable
}

func (s *simplePhiState) insertPhis() {
	s.reachable = ssa.ReachableBlocks(s.f)

	// Find FwdRef ops.
	for _, b := range s.f.Blocks {
		for _, v := range b.Values {
			if v.Op != ssa.OpFwdRef {
				continue
			}
			s.fwdrefs = append(s.fwdrefs, v)
			var_ := v.Aux.(fwdRefAux).N
			if _, ok := s.defvars[b.ID][var_]; !ok {
				s.defvars[b.ID][var_] = v // treat FwdDefs as definitions.
			}
		}
	}

	var args []*ssa.Value

loop:
	for len(s.fwdrefs) > 0 {
		v := s.fwdrefs[len(s.fwdrefs)-1]
		s.fwdrefs = s.fwdrefs[:len(s.fwdrefs)-1]
		b := v.Block
		var_ := v.Aux.(fwdRefAux).N
		if b == s.f.Entry {
			// No variable should be live at entry.
			s.s.Fatalf("value %v (%v) incorrectly live at entry", var_, v)
		}
		if !s.reachable[b.ID] {
			// This block is dead.
			// It doesn't matter what we use here as long as it is well-formed.
			v.Op = ssa.OpUnknown
			v.Aux = nil
			continue
		}
		// Find variable value on each predecessor.
		args = args[:0]
		for _, e := range b.Preds {
			args = append(args, s.lookupVarOutgoing(e.Block(), v.Type, var_, v.Pos))
		}

		// Decide if we need a phi or not. We need a phi if there
		// are two different args (which are both not v).
		var w *ssa.Value
		for _, a := range args {
			if a == v {
				continue // self-reference
			}
			if a == w {
				continue // already have this witness
			}
			if w != nil {
				// two witnesses, need a phi value
				v.Op = ssa.OpPhi
				v.AddArgs(args...)
				v.Aux = nil
				continue loop
			}
			w = a // save witness
		}
		if w == nil {
			s.s.Fatalf("no witness for reachable phi %s", v)
		}
		// One witness. Make v a copy of w.
		v.Op = ssa.OpCopy
		v.Aux = nil
		v.AddArg(w)
	}
}

// lookupVarOutgoing finds the variable's value at the end of block b.
func (s *simplePhiState) lookupVarOutgoing(b *ssa.Block, t *types.Type, var_ ir.Node, line src.XPos) *ssa.Value {
	for {
		if v := s.defvars[b.ID][var_]; v != nil {
			return v
		}
		// The variable is not defined by b and we haven't looked it up yet.
		// If b has exactly one predecessor, loop to look it up there.
		// Otherwise, give up and insert a new FwdRef and resolve it later.
		if len(b.Preds) != 1 {
			break
		}
		b = b.Preds[0].Block()
		if !s.reachable[b.ID] {
			// This is rare; it happens with oddly interleaved infinite loops in dead code.
			// See issue 19783.
			break
		}
	}
	// Generate a FwdRef for the variable and return that.
	v := b.NewValue0A(line, ssa.OpFwdRef, t, fwdRefAux{N: var_})
	s.defvars[b.ID][var_] = v
	if var_.Op() == ir.ONAME {
		s.s.addNamedValue(var_.(*ir.Name), v)
	}
	s.fwdrefs = append(s.fwdrefs, v)
	return v
}

"""



```