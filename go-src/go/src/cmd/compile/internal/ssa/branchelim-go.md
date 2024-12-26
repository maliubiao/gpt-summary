Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding of the Goal:**

The first line `// branchelim tries to eliminate branches by generating CondSelect instructions.` immediately tells us the core purpose: branch elimination using conditional selects. This is a classic compiler optimization.

**2. Identifying Key Data Structures and Functions:**

Skimming the code, I see:

* `func branchelim(f *Func)`: This is the main entry point of the optimization pass. It operates on a `Func` (presumably representing a function in the intermediate representation).
* `sparseSet`:  This is used to track values involved in load addresses. The name suggests it's an efficient way to store a possibly sparse set of value IDs.
* `elimIf`, `elimIfElse`: These look like the core logic for identifying and transforming single-branch (`if`) and two-branch (`if/else`) structures.
* `canCondSelect`:  This function likely determines if a given `Value` can be safely and effectively converted to a conditional select.
* `isLeafPlain`, `clobberBlock`: These seem like helper functions for analyzing and manipulating the control flow graph (CFG).
* `shouldElimIfElse`:  This is likely a cost model to decide if the transformation is beneficial.
* `canSpeculativelyExecute`: This checks if code in the branches can be executed without side effects.

**3. Analyzing `branchelim`:**

* **Architecture Check:** The initial `switch f.Config.arch` suggests this optimization is architecture-specific. It lists the architectures where it's implemented. This is a common pattern in compilers for performance reasons.
* **`loadAddr` Calculation:** The code iterates through blocks and values to identify those involved in calculating load addresses. The nested loop and the condition `if loadAddr.size() == n { break }` suggest this is an iterative process to find all dependent values. The comment about avoiding data-dependent load addresses is a crucial insight into why this tracking is necessary.
* **Main Loop:** The `for change { ... }` loop indicates that the optimization runs iteratively until no more changes are made, suggesting that eliminating one branch might enable the elimination of others. It calls `elimIf` and `elimIfElse`.

**4. Deep Dive into `elimIf` and `elimIfElse`:**

* **Pattern Matching:** Both functions look for specific control flow patterns (diamond shapes for `elimIf` and a standard if/else structure for `elimIfElse`).
* **Preconditions:**  They check conditions like `isLeafPlain`, `len(post.Preds) == 2`, and whether the intermediate blocks are mostly empty. This is to ensure the transformation is safe and likely beneficial.
* **`canCondSelect` Check:** This is a critical step to ensure that the Phi nodes can be rewritten.
* **Rewriting Phis:** The core transformation involves changing `OpPhi` to `OpCondSelect` and adjusting the arguments. The `swap` variable handles the different order of arguments based on the branch taken.
* **CFG Manipulation:** The code updates the block kinds, controls, successors, and predecessors to reflect the branch elimination. It effectively merges the blocks.
* **Statement Mark Handling:**  The detailed logic for preserving statement marks is interesting. It shows attention to debugging information and source code mapping.
* **`clobberBlock`:** This function is used to mark the eliminated blocks as invalid.

**5. Understanding `canCondSelect`:**

* **Load Address Check:** The `loadAddr.contains(v.ID)` check reiterates the point about avoiding data-dependent load addresses.
* **Architecture-Specific Logic:** The Loong64 specific check about constant zeros is an example of how optimizations can be tailored to specific architectures.
* **Type and Size Restrictions:**  The code limits conditional selects to scalar types that fit in registers, with an exception for pointers. The amd64 byte register restriction is another architecture-specific detail.

**6. Analyzing `shouldElimIfElse`:**

This function provides a cost model. The amd64-specific implementation considers the number of Phis and potentially the cost of recalculating conditions. The comment about CMOV latency is important.

**7. Examining `canSpeculativelyExecute`:**

This function lists operations that prevent speculative execution (Phis, divisions, pointer arithmetic, memory operations, and those with side effects). This is essential for ensuring correctness.

**8. Inferring the Go Language Feature:**

Based on the function name `branchelim` and the use of `CondSelect`, the most likely Go language feature being implemented is the optimization of **short if/else statements** into **conditional move instructions**. This can improve performance by avoiding branch prediction penalties.

**9. Constructing the Go Code Example:**

The example should demonstrate a simple `if/else` that the optimization would likely target. The key is that the bodies of the `if` and `else` are relatively simple assignments.

**10. Considering Command-Line Arguments and Common Mistakes:**

Since this is a compiler optimization pass, it's unlikely to have direct command-line arguments exposed to the user. The mistakes would be internal to the compiler implementation (e.g., incorrect pattern matching, flawed cost models, or unsafe speculative execution). However, a user *might* indirectly observe the effects of this optimization through performance differences.

**Self-Correction/Refinement during the process:**

* Initially, I might have just focused on the basic branch elimination. However, noticing the `loadAddr` logic prompted a deeper understanding of the interaction with memory operations.
* The detailed statement mark handling seemed like an edge case at first, but realizing its importance for debugging information made me appreciate why it's included.
*  The architecture-specific checks highlighted the need to consider platform-specific details in compiler optimizations.
*  Realizing that this is an *internal* compiler optimization clarified why there are no direct command-line arguments.

By following this detailed analysis and iterative refinement, I arrived at the comprehensive explanation provided in the initial good answer.
这段代码是Go语言编译器中SSA（Static Single Assignment）中间表示的一个优化pass，名为 **branchelim**，它的主要功能是 **消除不必要的条件分支**，并通过生成 **CondSelect** 指令来提高代码执行效率。

更具体地说，`branchelim` 试图识别特定的控制流模式，特别是那些看起来像简单 `if` 或 `if/else` 语句的结构，并且可以将它们转换为条件选择操作。

**功能分解:**

1. **识别特定的控制流模式:**
   - 寻找只有一个分支的 `if` 结构（`elimIf` 函数）。
   - 寻找标准的 `if/else` 结构（`elimIfElse` 函数）。
   - 这些结构要求中间的 `then` 或 `else` 代码块非常简单，没有副作用。

2. **条件选择指令 (CondSelect):**
   - 当识别到可优化的分支结构时，`branchelim` 会将后续汇合块（postdominator block）中的 `Phi` 指令替换为 `CondSelect` 指令。
   - `CondSelect` 指令是一种条件赋值操作，它根据一个条件选择两个输入值中的一个作为结果。这可以避免实际的跳转指令，从而减少流水线刷新等开销。

3. **Load 地址依赖性考虑:**
   - 代码中维护了一个 `loadAddr` 集合，记录了所有用于计算内存加载地址的值。
   - 如果即将生成的条件移动指令的结果被用于计算加载地址，那么通常会避免生成 `CondSelect`。这是因为条件移动会使加载地址依赖于数据，而原始的分支结构只控制加载的执行，可能更有利于性能，尤其是在分支预测良好的情况下。

4. **架构特定的优化:**
   - `branchelim` 的实现是架构相关的。目前只在 `arm64`, `ppc64le`, `ppc64`, `amd64`, `wasm`, `loong64` 等架构上实现了。
   - `canCondSelect` 函数会根据不同的架构进行额外的检查，例如在 `amd64` 上，不支持对字节寄存器使用条件移动。
   - `shouldElimIfElse` 函数也可能根据架构来评估消除 `if/else` 分支的成本。

5. **投机执行安全检查 (`canSpeculativelyExecute`):**
   - 在将分支转换为 `CondSelect` 之前，需要确保中间的 `then` 或 `else` 代码块可以被“投机执行”而不会产生副作用，例如内存访问、panic 等。

**推理 Go 语言功能实现:**

`branchelim` 主要优化的是 Go 语言中的 **`if` 语句**。

**Go 代码示例:**

```go
package main

func branchEliminationExample(a int) int {
	var result int
	if a > 10 {
		result = a * 2
	} else {
		result = a + 5
	}
	return result
}

func main() {
	println(branchEliminationExample(5))  // Output: 10
	println(branchEliminationExample(15)) // Output: 30
}
```

**假设的 SSA 输入 (简化):**

对于 `branchEliminationExample` 函数，在 `branchelim` 优化之前，可能会有如下简化的 SSA 表示：

```
b1:
    v1 = Param: a int
    v2 = ConstInt 10
    v3 = GreaterThan v1 v2
    If v3 -> b2, b3

b2: // then block
    v4 = Mul v1 2
    Goto b4

b3: // else block
    v5 = Add v1 5
    Goto b4

b4: // merge block
    v6 = Phi v4 v5
    Return v6
```

**`branchelim` 的处理过程：**

`branchelim` 会识别出 `b1`, `b2`, `b3`, `b4` 构成了一个简单的 `if/else` 结构，并且 `b2` 和 `b3` 中的操作可以安全地进行条件选择。

**假设的 SSA 输出 (优化后):**

优化后，`Phi` 指令 `v6` 将被替换为 `CondSelect` 指令：

```
b1:
    v1 = Param: a int
    v2 = ConstInt 10
    v3 = GreaterThan v1 v2
    v4 = Mul v1 2
    v5 = Add v1 5
    v6 = CondSelect v3 v4 v5  // 根据 v3 的值选择 v4 或 v5
    Return v6
```

原来的 `b2` 和 `b3` 代码块会被消除，控制流变得更加直接。

**代码推理涉及的假设输入与输出:**

* **输入 (SSA 形式):** 如上述假设的 `branchEliminationExample` 函数的 SSA 表示。
* **输出 (SSA 形式):** 如上述假设的优化后的 SSA 表示，`Phi` 指令被替换为 `CondSelect` 指令。

**命令行参数:**

`branchelim` 作为编译器内部的优化 pass，通常 **没有直接的用户可配置的命令行参数**。Go 编译器的优化级别（例如 `-O1`, `-O2`）可能会影响是否执行此 pass，但不能单独控制 `branchelim`。

**使用者易犯错的点:**

由于 `branchelim` 是编译器内部的优化，开发者通常 **不会直接与它交互**，因此不容易犯错。然而，理解其背后的原理可以帮助开发者编写出更易于编译器优化的代码。

一个间接相关的“错误”可能是：

* **编写过于复杂的 `if` 语句，导致 `branchelim` 无法识别和优化。**  例如，在 `then` 或 `else` 代码块中包含复杂的逻辑、函数调用或有副作用的操作，都会阻止 `branchelim` 进行优化。

**示例说明可能无法优化的情况:**

```go
package main

import "fmt"

func complexBranchExample(a int) int {
	var result int
	if a > 10 {
		result = a * complicatedFunction(a) // 函数调用，有副作用的可能性
	} else {
		fmt.Println("a is not greater than 10") // 输出，有副作用
		result = a + 5
	}
	return result
}

func complicatedFunction(x int) int {
	// ... 一些复杂的计算 ...
	return x * 3
}

func main() {
	println(complexBranchExample(5))
	println(complexBranchExample(15))
}
```

在这个例子中，由于 `then` 分支调用了函数 `complicatedFunction`，并且 `else` 分支有打印输出，`branchelim` 很可能无法将其优化为 `CondSelect`，因为这些操作可能具有副作用，不能随意移动或投机执行。

**总结:**

`go/src/cmd/compile/internal/ssa/branchelim.go` 中的代码实现了 SSA 中间表示的一个重要优化 pass，它通过识别简单的条件分支结构并将其转换为条件选择指令来提高代码效率。理解其工作原理有助于开发者编写出更容易被编译器优化的代码，尽管开发者通常不会直接配置或调用这个 pass。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/branchelim.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import "cmd/internal/src"

// branchelim tries to eliminate branches by
// generating CondSelect instructions.
//
// Search for basic blocks that look like
//
//	bb0            bb0
//	 | \          /   \
//	 | bb1  or  bb1   bb2    <- trivial if/else blocks
//	 | /          \   /
//	bb2            bb3
//
// where the intermediate blocks are mostly empty (with no side-effects);
// rewrite Phis in the postdominator as CondSelects.
func branchelim(f *Func) {
	// FIXME: add support for lowering CondSelects on more architectures
	switch f.Config.arch {
	case "arm64", "ppc64le", "ppc64", "amd64", "wasm", "loong64":
		// implemented
	default:
		return
	}

	// Find all the values used in computing the address of any load.
	// Typically these values have operations like AddPtr, Lsh64x64, etc.
	loadAddr := f.newSparseSet(f.NumValues())
	defer f.retSparseSet(loadAddr)
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			switch v.Op {
			case OpLoad, OpAtomicLoad8, OpAtomicLoad32, OpAtomicLoad64, OpAtomicLoadPtr, OpAtomicLoadAcq32, OpAtomicLoadAcq64:
				loadAddr.add(v.Args[0].ID)
			case OpMove:
				loadAddr.add(v.Args[1].ID)
			}
		}
	}
	po := f.postorder()
	for {
		n := loadAddr.size()
		for _, b := range po {
			for i := len(b.Values) - 1; i >= 0; i-- {
				v := b.Values[i]
				if !loadAddr.contains(v.ID) {
					continue
				}
				for _, a := range v.Args {
					if a.Type.IsInteger() || a.Type.IsPtr() || a.Type.IsUnsafePtr() {
						loadAddr.add(a.ID)
					}
				}
			}
		}
		if loadAddr.size() == n {
			break
		}
	}

	change := true
	for change {
		change = false
		for _, b := range f.Blocks {
			change = elimIf(f, loadAddr, b) || elimIfElse(f, loadAddr, b) || change
		}
	}
}

func canCondSelect(v *Value, arch string, loadAddr *sparseSet) bool {
	if loadAddr.contains(v.ID) {
		// The result of the soon-to-be conditional move is used to compute a load address.
		// We want to avoid generating a conditional move in this case
		// because the load address would now be data-dependent on the condition.
		// Previously it would only be control-dependent on the condition, which is faster
		// if the branch predicts well (or possibly even if it doesn't, if the load will
		// be an expensive cache miss).
		// See issue #26306.
		return false
	}
	if arch == "loong64" {
		// We should not generate conditional moves if neither of the arguments is constant zero,
		// because it requires three instructions (OR, MASKEQZ, MASKNEZ) and will increase the
		// register pressure.
		if !(v.Args[0].isGenericIntConst() && v.Args[0].AuxInt == 0) &&
			!(v.Args[1].isGenericIntConst() && v.Args[1].AuxInt == 0) {
			return false
		}
	}
	// For now, stick to simple scalars that fit in registers
	switch {
	case v.Type.Size() > v.Block.Func.Config.RegSize:
		return false
	case v.Type.IsPtrShaped():
		return true
	case v.Type.IsInteger():
		if arch == "amd64" && v.Type.Size() < 2 {
			// amd64 doesn't support CMOV with byte registers
			return false
		}
		return true
	default:
		return false
	}
}

// elimIf converts the one-way branch starting at dom in f to a conditional move if possible.
// loadAddr is a set of values which are used to compute the address of a load.
// Those values are exempt from CMOV generation.
func elimIf(f *Func, loadAddr *sparseSet, dom *Block) bool {
	// See if dom is an If with one arm that
	// is trivial and succeeded by the other
	// successor of dom.
	if dom.Kind != BlockIf || dom.Likely != BranchUnknown {
		return false
	}
	var simple, post *Block
	for i := range dom.Succs {
		bb, other := dom.Succs[i].Block(), dom.Succs[i^1].Block()
		if isLeafPlain(bb) && bb.Succs[0].Block() == other {
			simple = bb
			post = other
			break
		}
	}
	if simple == nil || len(post.Preds) != 2 || post == dom {
		return false
	}

	// We've found our diamond CFG of blocks.
	// Now decide if fusing 'simple' into dom+post
	// looks profitable.

	// Check that there are Phis, and that all of them
	// can be safely rewritten to CondSelect.
	hasphis := false
	for _, v := range post.Values {
		if v.Op == OpPhi {
			hasphis = true
			if !canCondSelect(v, f.Config.arch, loadAddr) {
				return false
			}
		}
	}
	if !hasphis {
		return false
	}

	// Pick some upper bound for the number of instructions
	// we'd be willing to execute just to generate a dead
	// argument to CondSelect. In the worst case, this is
	// the number of useless instructions executed.
	const maxfuseinsts = 2

	if len(simple.Values) > maxfuseinsts || !canSpeculativelyExecute(simple) {
		return false
	}

	// Replace Phi instructions in b with CondSelect instructions
	swap := (post.Preds[0].Block() == dom) != (dom.Succs[0].Block() == post)
	for _, v := range post.Values {
		if v.Op != OpPhi {
			continue
		}
		v.Op = OpCondSelect
		if swap {
			v.Args[0], v.Args[1] = v.Args[1], v.Args[0]
		}
		v.AddArg(dom.Controls[0])
	}

	// Put all of the instructions into 'dom'
	// and update the CFG appropriately.
	dom.Kind = post.Kind
	dom.CopyControls(post)
	dom.Aux = post.Aux
	dom.Succs = append(dom.Succs[:0], post.Succs...)
	for i := range dom.Succs {
		e := dom.Succs[i]
		e.b.Preds[e.i].b = dom
	}

	// Try really hard to preserve statement marks attached to blocks.
	simplePos := simple.Pos
	postPos := post.Pos
	simpleStmt := simplePos.IsStmt() == src.PosIsStmt
	postStmt := postPos.IsStmt() == src.PosIsStmt

	for _, v := range simple.Values {
		v.Block = dom
	}
	for _, v := range post.Values {
		v.Block = dom
	}

	// findBlockPos determines if b contains a stmt-marked value
	// that has the same line number as the Pos for b itself.
	// (i.e. is the position on b actually redundant?)
	findBlockPos := func(b *Block) bool {
		pos := b.Pos
		for _, v := range b.Values {
			// See if there is a stmt-marked value already that matches simple.Pos (and perhaps post.Pos)
			if pos.SameFileAndLine(v.Pos) && v.Pos.IsStmt() == src.PosIsStmt {
				return true
			}
		}
		return false
	}
	if simpleStmt {
		simpleStmt = !findBlockPos(simple)
		if !simpleStmt && simplePos.SameFileAndLine(postPos) {
			postStmt = false
		}

	}
	if postStmt {
		postStmt = !findBlockPos(post)
	}

	// If simpleStmt and/or postStmt are still true, then try harder
	// to find the corresponding statement marks new homes.

	// setBlockPos determines if b contains a can-be-statement value
	// that has the same line number as the Pos for b itself, and
	// puts a statement mark on it, and returns whether it succeeded
	// in this operation.
	setBlockPos := func(b *Block) bool {
		pos := b.Pos
		for _, v := range b.Values {
			if pos.SameFileAndLine(v.Pos) && !isPoorStatementOp(v.Op) {
				v.Pos = v.Pos.WithIsStmt()
				return true
			}
		}
		return false
	}
	// If necessary and possible, add a mark to a value in simple
	if simpleStmt {
		if setBlockPos(simple) && simplePos.SameFileAndLine(postPos) {
			postStmt = false
		}
	}
	// If necessary and possible, add a mark to a value in post
	if postStmt {
		postStmt = !setBlockPos(post)
	}

	// Before giving up (this was added because it helps), try the end of "dom", and if that is not available,
	// try the values in the successor block if it is uncomplicated.
	if postStmt {
		if dom.Pos.IsStmt() != src.PosIsStmt {
			dom.Pos = postPos
		} else {
			// Try the successor block
			if len(dom.Succs) == 1 && len(dom.Succs[0].Block().Preds) == 1 {
				succ := dom.Succs[0].Block()
				for _, v := range succ.Values {
					if isPoorStatementOp(v.Op) {
						continue
					}
					if postPos.SameFileAndLine(v.Pos) {
						v.Pos = v.Pos.WithIsStmt()
					}
					postStmt = false
					break
				}
				// If postStmt still true, tag the block itself if possible
				if postStmt && succ.Pos.IsStmt() != src.PosIsStmt {
					succ.Pos = postPos
				}
			}
		}
	}

	dom.Values = append(dom.Values, simple.Values...)
	dom.Values = append(dom.Values, post.Values...)

	// Trash 'post' and 'simple'
	clobberBlock(post)
	clobberBlock(simple)

	f.invalidateCFG()
	return true
}

// is this a BlockPlain with one predecessor?
func isLeafPlain(b *Block) bool {
	return b.Kind == BlockPlain && len(b.Preds) == 1
}

func clobberBlock(b *Block) {
	b.Values = nil
	b.Preds = nil
	b.Succs = nil
	b.Aux = nil
	b.ResetControls()
	b.Likely = BranchUnknown
	b.Kind = BlockInvalid
}

// elimIfElse converts the two-way branch starting at dom in f to a conditional move if possible.
// loadAddr is a set of values which are used to compute the address of a load.
// Those values are exempt from CMOV generation.
func elimIfElse(f *Func, loadAddr *sparseSet, b *Block) bool {
	// See if 'b' ends in an if/else: it should
	// have two successors, both of which are BlockPlain
	// and succeeded by the same block.
	if b.Kind != BlockIf || b.Likely != BranchUnknown {
		return false
	}
	yes, no := b.Succs[0].Block(), b.Succs[1].Block()
	if !isLeafPlain(yes) || len(yes.Values) > 1 || !canSpeculativelyExecute(yes) {
		return false
	}
	if !isLeafPlain(no) || len(no.Values) > 1 || !canSpeculativelyExecute(no) {
		return false
	}
	if b.Succs[0].Block().Succs[0].Block() != b.Succs[1].Block().Succs[0].Block() {
		return false
	}
	// block that postdominates the if/else
	post := b.Succs[0].Block().Succs[0].Block()
	if len(post.Preds) != 2 || post == b {
		return false
	}
	hasphis := false
	for _, v := range post.Values {
		if v.Op == OpPhi {
			hasphis = true
			if !canCondSelect(v, f.Config.arch, loadAddr) {
				return false
			}
		}
	}
	if !hasphis {
		return false
	}

	// Don't generate CondSelects if branch is cheaper.
	if !shouldElimIfElse(no, yes, post, f.Config.arch) {
		return false
	}

	// now we're committed: rewrite each Phi as a CondSelect
	swap := post.Preds[0].Block() != b.Succs[0].Block()
	for _, v := range post.Values {
		if v.Op != OpPhi {
			continue
		}
		v.Op = OpCondSelect
		if swap {
			v.Args[0], v.Args[1] = v.Args[1], v.Args[0]
		}
		v.AddArg(b.Controls[0])
	}

	// Move the contents of all of these
	// blocks into 'b' and update CFG edges accordingly
	b.Kind = post.Kind
	b.CopyControls(post)
	b.Aux = post.Aux
	b.Succs = append(b.Succs[:0], post.Succs...)
	for i := range b.Succs {
		e := b.Succs[i]
		e.b.Preds[e.i].b = b
	}
	for i := range post.Values {
		post.Values[i].Block = b
	}
	for i := range yes.Values {
		yes.Values[i].Block = b
	}
	for i := range no.Values {
		no.Values[i].Block = b
	}
	b.Values = append(b.Values, yes.Values...)
	b.Values = append(b.Values, no.Values...)
	b.Values = append(b.Values, post.Values...)

	// trash post, yes, and no
	clobberBlock(yes)
	clobberBlock(no)
	clobberBlock(post)

	f.invalidateCFG()
	return true
}

// shouldElimIfElse reports whether estimated cost of eliminating branch
// is lower than threshold.
func shouldElimIfElse(no, yes, post *Block, arch string) bool {
	switch arch {
	default:
		return true
	case "amd64":
		const maxcost = 2
		phi := 0
		other := 0
		for _, v := range post.Values {
			if v.Op == OpPhi {
				// Each phi results in CondSelect, which lowers into CMOV,
				// CMOV has latency >1 on most CPUs.
				phi++
			}
			for _, x := range v.Args {
				if x.Block == no || x.Block == yes {
					other++
				}
			}
		}
		cost := phi * 1
		if phi > 1 {
			// If we have more than 1 phi and some values in post have args
			// in yes or no blocks, we may have to recalculate condition, because
			// those args may clobber flags. For now assume that all operations clobber flags.
			cost += other * 1
		}
		return cost < maxcost
	}
}

// canSpeculativelyExecute reports whether every value in the block can
// be evaluated without causing any observable side effects (memory
// accesses, panics and so on) except for execution time changes. It
// also ensures that the block does not contain any phis which we can't
// speculatively execute.
// Warning: this function cannot currently detect values that represent
// instructions the execution of which need to be guarded with CPU
// hardware feature checks. See issue #34950.
func canSpeculativelyExecute(b *Block) bool {
	// don't fuse memory ops, Phi ops, divides (can panic),
	// or anything else with side-effects
	for _, v := range b.Values {
		if v.Op == OpPhi || isDivMod(v.Op) || isPtrArithmetic(v.Op) || v.Type.IsMemory() ||
			v.MemoryArg() != nil || opcodeTable[v.Op].hasSideEffects {
			return false
		}
	}
	return true
}

func isDivMod(op Op) bool {
	switch op {
	case OpDiv8, OpDiv8u, OpDiv16, OpDiv16u,
		OpDiv32, OpDiv32u, OpDiv64, OpDiv64u, OpDiv128u,
		OpDiv32F, OpDiv64F,
		OpMod8, OpMod8u, OpMod16, OpMod16u,
		OpMod32, OpMod32u, OpMod64, OpMod64u:
		return true
	default:
		return false
	}
}

func isPtrArithmetic(op Op) bool {
	// Pointer arithmetic can't be speculatively executed because the result
	// may be an invalid pointer (if, for example, the condition is that the
	// base pointer is not nil). See issue 56990.
	switch op {
	case OpOffPtr, OpAddPtr, OpSubPtr:
		return true
	default:
		return false
	}
}

"""



```