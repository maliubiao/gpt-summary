Response:
Thinking Process to Answer the Request:

1. **Understand the Goal:** The primary goal is to analyze the provided Go code snippet and explain its functionality, particularly the "lifting" pass in the SSA context. I also need to address specific requests like example usage, error-prone aspects, and handling of command-line arguments (though the latter might not be directly present in the code).

2. **Identify the Core Functionality:** The code clearly states it's implementing a "lifting pass" for SSA (Static Single Assignment) form. The comments and variable names like `lift`, `Alloc`, `Phi`, `rename`, `domFrontier` strongly suggest this. The core idea is to move `Alloc` values (local variables and `new` allocations) into SSA registers whenever possible.

3. **Break Down the Process (Based on Comments and Code Structure):**

    * **Dominance Frontier Calculation:** The code starts by calculating the dominance frontier using the Cytron et al. algorithm. This is crucial for placing φ-nodes. I need to explain *why* the dominance frontier is needed (where different control flow paths merge, potential for different values of a variable).
    * **Liftable Alloc Determination:**  The `liftAlloc` function decides which `Alloc` instructions can be lifted. The conditions for not lifting (aggregates, named return values in functions with `defer` and `recover`, address taken) are important to note.
    * **Φ-Node Insertion:** If an `Alloc` can be lifted, φ-nodes are inserted at the join points (dominance frontier) where the variable might have different values coming from different control flow paths. The `newPhis` map tracks these.
    * **Renaming:** The `rename` function is the heart of the SSA construction. It walks the dominator tree and replaces uses of the original `Alloc` with the appropriate SSA value (either a dominating store or a φ-node). This is where loads and stores to the lifted `Alloc` are effectively eliminated.
    * **Dead Φ-Node Elimination:**  The `removeDeadPhis` function cleans up any φ-nodes that are not actually used. This is an optimization step.
    * **Code Modification:**  The code modifies the `BasicBlock.Instrs` to include the new φ-nodes and remove the lifted `Alloc` instructions, loads, and stores.

4. **Address Specific Questions:**

    * **Functionality Summary:**  Concise description of the lifting process and its benefits (register allocation potential, enabling optimizations).
    * **Go Language Feature:** Explain SSA and the concept of φ-nodes.
    * **Code Example:**  Craft a simple Go function with a local variable that gets lifted. Show the hypothetical SSA representation *after* lifting, highlighting the φ-node. Crucially, provide the *before* and *after* SSA to illustrate the transformation. **Initial thought:** Just show the Go code. **Correction:** The request asks about the *Go language feature's implementation*, so showing the intermediate SSA is key.
    * **Input/Output for Code Reasoning:**  The example itself serves this purpose.
    * **Command-Line Arguments:**  Scan the code for `flag` or `os.Args`. If absent, explicitly state that command-line argument processing isn't present in this *specific snippet*. Avoid making assumptions.
    * **Error-Prone Aspects:** Focus on the *conditions for not lifting* as potential pitfalls for someone trying to understand or modify this code. Misunderstanding these conditions could lead to incorrect assumptions about which variables will be lifted.

5. **Structure and Language:**  Use clear and concise Chinese. Organize the answer logically with headings. Use code formatting for examples. Explain technical terms like SSA and φ-nodes.

6. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check if all parts of the request have been addressed. Make sure the code example is correct and illustrative.

By following this structured approach, I can generate a comprehensive and accurate answer to the user's request. The key is to understand the underlying concepts of SSA and the specific steps involved in the lifting pass, as implemented in the given code. Paying attention to the specific details requested, like examples and error-prone areas, is also crucial.
这段代码是 Go 语言 SSA（Static Single Assignment）表示形式的一个优化步骤，称为 **"提升 (Lifting)"**。 它的主要功能是将原本存储在内存中的局部变量或 `new` 操作分配的变量（`Alloc` 指令表示）尽可能地移动到 SSA 寄存器中。

**核心功能：**

1. **识别可提升的 Alloc 指令:**  代码会分析函数中的 `Alloc` 指令，判断哪些 `Alloc` 可以被提升到 SSA 寄存器。  判断标准包括：
    * `Alloc` 的类型不能是数组或结构体（因为没有表示它们的零值的常量）。
    * 如果函数包含 `defer` 语句并且 `Alloc` 是一个具名返回值，则不提升（为了处理 `recover` 可能修改返回值的情况）。
    * `Alloc` 的地址没有被用作值传递（例如 `store value_of_alloc, another_variable`）。
    * 对 `Alloc` 的访问仅限于 `Load` (通过 `*` 解引用)、`Store` 和 `DebugRef` 操作。

2. **计算支配边界 (Dominance Frontier):**  为了正确地插入 φ-节点，代码首先计算每个基本块的支配边界。支配边界是指那些不是由当前块支配，但是其前驱块被当前块支配的块的集合。

3. **插入 φ-节点:** 如果一个 `Alloc` 可以被提升，代码会在其支配边界的每个基本块的开头插入 φ-节点。 φ-节点是一种特殊的 SSA 指令，用于合并来自不同控制流路径的变量值。

4. **重命名变量:** 代码会遍历支配树，将对原始 `Alloc` 的 `Load` 操作替换为存储到该内存位置的值，或者如果需要合并来自不同路径的值，则替换为相应的 φ-节点。  `Store` 操作会被删除，因为它们现在变成了对 SSA 寄存器的赋值。

5. **消除死 φ-节点:**  代码会删除那些没有被其他非 φ-节点或非 `DebugRef` 指令使用的 φ-节点，以优化 SSA 表示。

6. **更新基本块指令列表:**  最终，代码会更新每个基本块的指令列表，将新插入的 φ-节点放在前面，并移除被提升的 `Alloc` 指令以及相关的 `Load` 和 `Store` 指令。

**它是什么 Go 语言功能的实现：**

这段代码是 Go 语言编译器进行 **静态单赋值 (SSA) 转换** 的一部分。SSA 是一种中间表示形式，在编译器的优化阶段非常重要。通过将变量的赋值点限制为只有一个，并使用 φ-节点来处理控制流的合并，SSA 使得许多代码优化变得更加容易和高效。

**Go 代码举例说明：**

假设有以下 Go 代码片段：

```go
package main

func foo(a bool) int {
	var x int
	if a {
		x = 10
	} else {
		x = 20
	}
	return x
}
```

在转换为 SSA 形式并经过提升优化后， `x` 这个局部变量可能会被提升到 SSA 寄存器。下面是简化的、概念性的 SSA 表示，展示了提升的效果：

**假设的输入 SSA (在提升之前，`x` 是一个 `Alloc`):**

```
// Function: foo
b0:
  v0 = Param <bool> a
  v1 = Alloc <*int>  // x 的分配
  If v0 goto b1 else b2

b1: // predecessors: b0
  Store <int> 10, v1
  Goto b3

b2: // predecessors: b0
  Store <int> 20, v1
  Goto b3

b3: // predecessors: b1 b2
  v4 = Load <int> v1
  Return v4
```

**提升优化后的假设输出 SSA ( `x` 被提升到寄存器):**

```
// Function: foo
b0:
  v0 = Param <bool> a
  If v0 goto b1 else b2

b1: // predecessors: b0
  v2 = Const <int> 10
  Goto b3

b2: // predecessors: b0
  v3 = Const <int> 20
  Goto b3

b3: // predecessors: b1 b2
  v4 = Phi <int> [b1: v2, b2: v3]  // x 的值由 φ-节点合并
  Return v4
```

**代码推理：**

* **输入:** 上述的未提升的 SSA 表示。
* **分析:** `Alloc v1` 代表局部变量 `x` 的内存分配。`Store` 指令将值存储到 `v1` 指向的内存位置，`Load` 指令从该位置加载值。
* **提升过程:**  分析到对 `v1` 的访问都是 `Load` 和 `Store`，且类型不是聚合类型，因此可以提升。在 `b3` 块的开头插入了一个 φ-节点 `v4`，它根据前驱块的不同（`b1` 或 `b2`）选择不同的值。
* **输出:** 提升后的 SSA 表示中，`Alloc` 指令被移除，`Store` 指令被替换为常量赋值，`Load` 指令被替换为对 φ-节点的引用。

**命令行参数处理：**

这段代码本身 **没有直接处理命令行参数**。 它是一个编译器内部的优化步骤，由 Go 编译器的其他部分调用。命令行参数的处理通常发生在编译过程的早期阶段。

**使用者易犯错的点：**

对于直接使用 `go/ssa` 包的开发者来说，理解提升过程有助于理解 SSA 的结构和优化原理。一个可能容易犯错的点是 **过早地假设某个局部变量会一直存在于内存中**。  提升优化意味着某些变量可能只存在于 SSA 寄存器中，而不会在内存中实际分配空间。  如果开发者尝试直接访问 `Alloc` 指令，而该指令已经被提升并移除，就会导致错误。

例如，如果开发者在 `ssa` 包中遍历指令，并假设所有的局部变量都有对应的 `Alloc` 指令，那么在提升优化后，这种假设可能会失效。他们需要意识到，某些变量可能只以 φ-节点或常量值的形式存在。

总结来说，这段代码实现了 SSA 的提升优化，通过将局部变量尽可能地移动到寄存器中，提高了代码的执行效率并为后续的优化奠定了基础。 理解这个过程对于理解 Go 编译器的内部工作原理以及如何有效地使用 `go/ssa` 包至关重要。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/lift.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

// This file defines the lifting pass which tries to "lift" Alloc
// cells (new/local variables) into SSA registers, replacing loads
// with the dominating stored value, eliminating loads and stores, and
// inserting φ-nodes as needed.

// Cited papers and resources:
//
// Ron Cytron et al. 1991. Efficiently computing SSA form...
// http://doi.acm.org/10.1145/115372.115320
//
// Cooper, Harvey, Kennedy.  2001.  A Simple, Fast Dominance Algorithm.
// Software Practice and Experience 2001, 4:1-10.
// http://www.hipersoft.rice.edu/grads/publications/dom14.pdf
//
// Daniel Berlin, llvmdev mailing list, 2012.
// http://lists.cs.uiuc.edu/pipermail/llvmdev/2012-January/046638.html
// (Be sure to expand the whole thread.)

// TODO(adonovan): opt: there are many optimizations worth evaluating, and
// the conventional wisdom for SSA construction is that a simple
// algorithm well engineered often beats those of better asymptotic
// complexity on all but the most egregious inputs.
//
// Danny Berlin suggests that the Cooper et al. algorithm for
// computing the dominance frontier is superior to Cytron et al.
// Furthermore he recommends that rather than computing the DF for the
// whole function then renaming all alloc cells, it may be cheaper to
// compute the DF for each alloc cell separately and throw it away.
//
// Consider exploiting liveness information to avoid creating dead
// φ-nodes which we then immediately remove.
//
// Also see many other "TODO: opt" suggestions in the code.

import (
	"fmt"
	"go/token"
	"go/types"
	"math/big"
	"os"
)

// If true, show diagnostic information at each step of lifting.
// Very verbose.
const debugLifting = false

// domFrontier maps each block to the set of blocks in its dominance
// frontier.  The outer slice is conceptually a map keyed by
// Block.Index.  The inner slice is conceptually a set, possibly
// containing duplicates.
//
// TODO(adonovan): opt: measure impact of dups; consider a packed bit
// representation, e.g. big.Int, and bitwise parallel operations for
// the union step in the Children loop.
//
// domFrontier's methods mutate the slice's elements but not its
// length, so their receivers needn't be pointers.
//
type domFrontier [][]*BasicBlock

func (df domFrontier) add(u, v *BasicBlock) {
	p := &df[u.Index]
	*p = append(*p, v)
}

// build builds the dominance frontier df for the dominator (sub)tree
// rooted at u, using the Cytron et al. algorithm.
//
// TODO(adonovan): opt: consider Berlin approach, computing pruned SSA
// by pruning the entire IDF computation, rather than merely pruning
// the DF -> IDF step.
func (df domFrontier) build(u *BasicBlock) {
	// Encounter each node u in postorder of dom tree.
	for _, child := range u.dom.children {
		df.build(child)
	}
	for _, vb := range u.Succs {
		if v := vb.dom; v.idom != u {
			df.add(u, vb)
		}
	}
	for _, w := range u.dom.children {
		for _, vb := range df[w.Index] {
			// TODO(adonovan): opt: use word-parallel bitwise union.
			if v := vb.dom; v.idom != u {
				df.add(u, vb)
			}
		}
	}
}

func buildDomFrontier(fn *Function) domFrontier {
	df := make(domFrontier, len(fn.Blocks))
	df.build(fn.Blocks[0])
	if fn.Recover != nil {
		df.build(fn.Recover)
	}
	return df
}

func removeInstr(refs []Instruction, instr Instruction) []Instruction {
	i := 0
	for _, ref := range refs {
		if ref == instr {
			continue
		}
		refs[i] = ref
		i++
	}
	for j := i; j != len(refs); j++ {
		refs[j] = nil // aid GC
	}
	return refs[:i]
}

// lift replaces local and new Allocs accessed only with
// load/store by SSA registers, inserting φ-nodes where necessary.
// The result is a program in classical pruned SSA form.
//
// Preconditions:
// - fn has no dead blocks (blockopt has run).
// - Def/use info (Operands and Referrers) is up-to-date.
// - The dominator tree is up-to-date.
//
func lift(fn *Function) {
	// TODO(adonovan): opt: lots of little optimizations may be
	// worthwhile here, especially if they cause us to avoid
	// buildDomFrontier.  For example:
	//
	// - Alloc never loaded?  Eliminate.
	// - Alloc never stored?  Replace all loads with a zero constant.
	// - Alloc stored once?  Replace loads with dominating store;
	//   don't forget that an Alloc is itself an effective store
	//   of zero.
	// - Alloc used only within a single block?
	//   Use degenerate algorithm avoiding φ-nodes.
	// - Consider synergy with scalar replacement of aggregates (SRA).
	//   e.g. *(&x.f) where x is an Alloc.
	//   Perhaps we'd get better results if we generated this as x.f
	//   i.e. Field(x, .f) instead of Load(FieldIndex(x, .f)).
	//   Unclear.
	//
	// But we will start with the simplest correct code.
	df := buildDomFrontier(fn)

	if debugLifting {
		title := false
		for i, blocks := range df {
			if blocks != nil {
				if !title {
					fmt.Fprintf(os.Stderr, "Dominance frontier of %s:\n", fn)
					title = true
				}
				fmt.Fprintf(os.Stderr, "\t%s: %s\n", fn.Blocks[i], blocks)
			}
		}
	}

	newPhis := make(newPhiMap)

	// During this pass we will replace some BasicBlock.Instrs
	// (allocs, loads and stores) with nil, keeping a count in
	// BasicBlock.gaps.  At the end we will reset Instrs to the
	// concatenation of all non-dead newPhis and non-nil Instrs
	// for the block, reusing the original array if space permits.

	// While we're here, we also eliminate 'rundefers'
	// instructions in functions that contain no 'defer'
	// instructions.
	usesDefer := false

	// A counter used to generate ~unique ids for Phi nodes, as an
	// aid to debugging.  We use large numbers to make them highly
	// visible.  All nodes are renumbered later.
	fresh := 1000

	// Determine which allocs we can lift and number them densely.
	// The renaming phase uses this numbering for compact maps.
	numAllocs := 0
	for _, b := range fn.Blocks {
		b.gaps = 0
		b.rundefers = 0
		for _, instr := range b.Instrs {
			switch instr := instr.(type) {
			case *Alloc:
				index := -1
				if liftAlloc(df, instr, newPhis, &fresh) {
					index = numAllocs
					numAllocs++
				}
				instr.index = index
			case *Defer:
				usesDefer = true
			case *RunDefers:
				b.rundefers++
			}
		}
	}

	// renaming maps an alloc (keyed by index) to its replacement
	// value.  Initially the renaming contains nil, signifying the
	// zero constant of the appropriate type; we construct the
	// Const lazily at most once on each path through the domtree.
	// TODO(adonovan): opt: cache per-function not per subtree.
	renaming := make([]Value, numAllocs)

	// Renaming.
	rename(fn.Blocks[0], renaming, newPhis)

	// Eliminate dead φ-nodes.
	removeDeadPhis(fn.Blocks, newPhis)

	// Prepend remaining live φ-nodes to each block.
	for _, b := range fn.Blocks {
		nps := newPhis[b]
		j := len(nps)

		rundefersToKill := b.rundefers
		if usesDefer {
			rundefersToKill = 0
		}

		if j+b.gaps+rundefersToKill == 0 {
			continue // fast path: no new phis or gaps
		}

		// Compact nps + non-nil Instrs into a new slice.
		// TODO(adonovan): opt: compact in situ (rightwards)
		// if Instrs has sufficient space or slack.
		dst := make([]Instruction, len(b.Instrs)+j-b.gaps-rundefersToKill)
		for i, np := range nps {
			dst[i] = np.phi
		}
		for _, instr := range b.Instrs {
			if instr == nil {
				continue
			}
			if !usesDefer {
				if _, ok := instr.(*RunDefers); ok {
					continue
				}
			}
			dst[j] = instr
			j++
		}
		b.Instrs = dst
	}

	// Remove any fn.Locals that were lifted.
	j := 0
	for _, l := range fn.Locals {
		if l.index < 0 {
			fn.Locals[j] = l
			j++
		}
	}
	// Nil out fn.Locals[j:] to aid GC.
	for i := j; i < len(fn.Locals); i++ {
		fn.Locals[i] = nil
	}
	fn.Locals = fn.Locals[:j]
}

// removeDeadPhis removes φ-nodes not transitively needed by a
// non-Phi, non-DebugRef instruction.
func removeDeadPhis(blocks []*BasicBlock, newPhis newPhiMap) {
	// First pass: find the set of "live" φ-nodes: those reachable
	// from some non-Phi instruction.
	//
	// We compute reachability in reverse, starting from each φ,
	// rather than forwards, starting from each live non-Phi
	// instruction, because this way visits much less of the
	// Value graph.
	livePhis := make(map[*Phi]bool)
	for _, npList := range newPhis {
		for _, np := range npList {
			phi := np.phi
			if !livePhis[phi] && phiHasDirectReferrer(phi) {
				markLivePhi(livePhis, phi)
			}
		}
	}

	// Existing φ-nodes due to && and || operators
	// are all considered live (see Go issue 19622).
	for _, b := range blocks {
		for _, phi := range b.phis() {
			markLivePhi(livePhis, phi.(*Phi))
		}
	}

	// Second pass: eliminate unused phis from newPhis.
	for block, npList := range newPhis {
		j := 0
		for _, np := range npList {
			if livePhis[np.phi] {
				npList[j] = np
				j++
			} else {
				// discard it, first removing it from referrers
				for _, val := range np.phi.Edges {
					if refs := val.Referrers(); refs != nil {
						*refs = removeInstr(*refs, np.phi)
					}
				}
				np.phi.block = nil
			}
		}
		newPhis[block] = npList[:j]
	}
}

// markLivePhi marks phi, and all φ-nodes transitively reachable via
// its Operands, live.
func markLivePhi(livePhis map[*Phi]bool, phi *Phi) {
	livePhis[phi] = true
	for _, rand := range phi.Operands(nil) {
		if q, ok := (*rand).(*Phi); ok {
			if !livePhis[q] {
				markLivePhi(livePhis, q)
			}
		}
	}
}

// phiHasDirectReferrer reports whether phi is directly referred to by
// a non-Phi instruction.  Such instructions are the
// roots of the liveness traversal.
func phiHasDirectReferrer(phi *Phi) bool {
	for _, instr := range *phi.Referrers() {
		if _, ok := instr.(*Phi); !ok {
			return true
		}
	}
	return false
}

type blockSet struct{ big.Int } // (inherit methods from Int)

// add adds b to the set and returns true if the set changed.
func (s *blockSet) add(b *BasicBlock) bool {
	i := b.Index
	if s.Bit(i) != 0 {
		return false
	}
	s.SetBit(&s.Int, i, 1)
	return true
}

// take removes an arbitrary element from a set s and
// returns its index, or returns -1 if empty.
func (s *blockSet) take() int {
	l := s.BitLen()
	for i := 0; i < l; i++ {
		if s.Bit(i) == 1 {
			s.SetBit(&s.Int, i, 0)
			return i
		}
	}
	return -1
}

// newPhi is a pair of a newly introduced φ-node and the lifted Alloc
// it replaces.
type newPhi struct {
	phi   *Phi
	alloc *Alloc
}

// newPhiMap records for each basic block, the set of newPhis that
// must be prepended to the block.
type newPhiMap map[*BasicBlock][]newPhi

// liftAlloc determines whether alloc can be lifted into registers,
// and if so, it populates newPhis with all the φ-nodes it may require
// and returns true.
//
// fresh is a source of fresh ids for phi nodes.
//
func liftAlloc(df domFrontier, alloc *Alloc, newPhis newPhiMap, fresh *int) bool {
	// Don't lift aggregates into registers, because we don't have
	// a way to express their zero-constants.
	switch deref(alloc.Type()).Underlying().(type) {
	case *types.Array, *types.Struct:
		return false
	}

	// Don't lift named return values in functions that defer
	// calls that may recover from panic.
	if fn := alloc.Parent(); fn.Recover != nil {
		for _, nr := range fn.namedResults {
			if nr == alloc {
				return false
			}
		}
	}

	// Compute defblocks, the set of blocks containing a
	// definition of the alloc cell.
	var defblocks blockSet
	for _, instr := range *alloc.Referrers() {
		// Bail out if we discover the alloc is not liftable;
		// the only operations permitted to use the alloc are
		// loads/stores into the cell, and DebugRef.
		switch instr := instr.(type) {
		case *Store:
			if instr.Val == alloc {
				return false // address used as value
			}
			if instr.Addr != alloc {
				panic("Alloc.Referrers is inconsistent")
			}
			defblocks.add(instr.Block())
		case *UnOp:
			if instr.Op != token.MUL {
				return false // not a load
			}
			if instr.X != alloc {
				panic("Alloc.Referrers is inconsistent")
			}
		case *DebugRef:
			// ok
		default:
			return false // some other instruction
		}
	}
	// The Alloc itself counts as a (zero) definition of the cell.
	defblocks.add(alloc.Block())

	if debugLifting {
		fmt.Fprintln(os.Stderr, "\tlifting ", alloc, alloc.Name())
	}

	fn := alloc.Parent()

	// Φ-insertion.
	//
	// What follows is the body of the main loop of the insert-φ
	// function described by Cytron et al, but instead of using
	// counter tricks, we just reset the 'hasAlready' and 'work'
	// sets each iteration.  These are bitmaps so it's pretty cheap.
	//
	// TODO(adonovan): opt: recycle slice storage for W,
	// hasAlready, defBlocks across liftAlloc calls.
	var hasAlready blockSet

	// Initialize W and work to defblocks.
	var work blockSet = defblocks // blocks seen
	var W blockSet                // blocks to do
	W.Set(&defblocks.Int)

	// Traverse iterated dominance frontier, inserting φ-nodes.
	for i := W.take(); i != -1; i = W.take() {
		u := fn.Blocks[i]
		for _, v := range df[u.Index] {
			if hasAlready.add(v) {
				// Create φ-node.
				// It will be prepended to v.Instrs later, if needed.
				phi := &Phi{
					Edges:   make([]Value, len(v.Preds)),
					Comment: alloc.Comment,
				}
				// This is merely a debugging aid:
				phi.setNum(*fresh)
				*fresh++

				phi.pos = alloc.Pos()
				phi.setType(deref(alloc.Type()))
				phi.block = v
				if debugLifting {
					fmt.Fprintf(os.Stderr, "\tplace %s = %s at block %s\n", phi.Name(), phi, v)
				}
				newPhis[v] = append(newPhis[v], newPhi{phi, alloc})

				if work.add(v) {
					W.add(v)
				}
			}
		}
	}

	return true
}

// replaceAll replaces all intraprocedural uses of x with y,
// updating x.Referrers and y.Referrers.
// Precondition: x.Referrers() != nil, i.e. x must be local to some function.
//
func replaceAll(x, y Value) {
	var rands []*Value
	pxrefs := x.Referrers()
	pyrefs := y.Referrers()
	for _, instr := range *pxrefs {
		rands = instr.Operands(rands[:0]) // recycle storage
		for _, rand := range rands {
			if *rand != nil {
				if *rand == x {
					*rand = y
				}
			}
		}
		if pyrefs != nil {
			*pyrefs = append(*pyrefs, instr) // dups ok
		}
	}
	*pxrefs = nil // x is now unreferenced
}

// renamed returns the value to which alloc is being renamed,
// constructing it lazily if it's the implicit zero initialization.
//
func renamed(renaming []Value, alloc *Alloc) Value {
	v := renaming[alloc.index]
	if v == nil {
		v = zeroConst(deref(alloc.Type()))
		renaming[alloc.index] = v
	}
	return v
}

// rename implements the (Cytron et al) SSA renaming algorithm, a
// preorder traversal of the dominator tree replacing all loads of
// Alloc cells with the value stored to that cell by the dominating
// store instruction.  For lifting, we need only consider loads,
// stores and φ-nodes.
//
// renaming is a map from *Alloc (keyed by index number) to its
// dominating stored value; newPhis[x] is the set of new φ-nodes to be
// prepended to block x.
//
func rename(u *BasicBlock, renaming []Value, newPhis newPhiMap) {
	// Each φ-node becomes the new name for its associated Alloc.
	for _, np := range newPhis[u] {
		phi := np.phi
		alloc := np.alloc
		renaming[alloc.index] = phi
	}

	// Rename loads and stores of allocs.
	for i, instr := range u.Instrs {
		switch instr := instr.(type) {
		case *Alloc:
			if instr.index >= 0 { // store of zero to Alloc cell
				// Replace dominated loads by the zero value.
				renaming[instr.index] = nil
				if debugLifting {
					fmt.Fprintf(os.Stderr, "\tkill alloc %s\n", instr)
				}
				// Delete the Alloc.
				u.Instrs[i] = nil
				u.gaps++
			}

		case *Store:
			if alloc, ok := instr.Addr.(*Alloc); ok && alloc.index >= 0 { // store to Alloc cell
				// Replace dominated loads by the stored value.
				renaming[alloc.index] = instr.Val
				if debugLifting {
					fmt.Fprintf(os.Stderr, "\tkill store %s; new value: %s\n",
						instr, instr.Val.Name())
				}
				// Remove the store from the referrer list of the stored value.
				if refs := instr.Val.Referrers(); refs != nil {
					*refs = removeInstr(*refs, instr)
				}
				// Delete the Store.
				u.Instrs[i] = nil
				u.gaps++
			}

		case *UnOp:
			if instr.Op == token.MUL {
				if alloc, ok := instr.X.(*Alloc); ok && alloc.index >= 0 { // load of Alloc cell
					newval := renamed(renaming, alloc)
					if debugLifting {
						fmt.Fprintf(os.Stderr, "\tupdate load %s = %s with %s\n",
							instr.Name(), instr, newval.Name())
					}
					// Replace all references to
					// the loaded value by the
					// dominating stored value.
					replaceAll(instr, newval)
					// Delete the Load.
					u.Instrs[i] = nil
					u.gaps++
				}
			}

		case *DebugRef:
			if alloc, ok := instr.X.(*Alloc); ok && alloc.index >= 0 { // ref of Alloc cell
				if instr.IsAddr {
					instr.X = renamed(renaming, alloc)
					instr.IsAddr = false

					// Add DebugRef to instr.X's referrers.
					if refs := instr.X.Referrers(); refs != nil {
						*refs = append(*refs, instr)
					}
				} else {
					// A source expression denotes the address
					// of an Alloc that was optimized away.
					instr.X = nil

					// Delete the DebugRef.
					u.Instrs[i] = nil
					u.gaps++
				}
			}
		}
	}

	// For each φ-node in a CFG successor, rename the edge.
	for _, v := range u.Succs {
		phis := newPhis[v]
		if len(phis) == 0 {
			continue
		}
		i := v.predIndex(u)
		for _, np := range phis {
			phi := np.phi
			alloc := np.alloc
			newval := renamed(renaming, alloc)
			if debugLifting {
				fmt.Fprintf(os.Stderr, "\tsetphi %s edge %s -> %s (#%d) (alloc=%s) := %s\n",
					phi.Name(), u, v, i, alloc.Name(), newval.Name())
			}
			phi.Edges[i] = newval
			if prefs := newval.Referrers(); prefs != nil {
				*prefs = append(*prefs, phi)
			}
		}
	}

	// Continue depth-first recursion over domtree, pushing a
	// fresh copy of the renaming map for each subtree.
	for i, v := range u.dom.children {
		r := renaming
		if i < len(u.dom.children)-1 {
			// On all but the final iteration, we must make
			// a copy to avoid destructive update.
			r = make([]Value, len(renaming))
			copy(r, renaming)
		}
		rename(v, r, newPhis)
	}

}

"""



```