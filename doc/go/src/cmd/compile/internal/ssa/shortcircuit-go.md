Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - High Level:**

The first thing I notice is the package declaration: `package ssa`. This immediately tells me this code is part of the Go compiler, specifically dealing with Static Single Assignment (SSA) form. The comment at the beginning, "shortcircuit finds situations where branch directions are always correlated and rewrites the CFG to take advantage of that fact," provides the core functionality. It mentions `&&` and `||` expressions, hinting at boolean logic optimization.

**2. Deconstructing the `shortcircuit` Function:**

I see two main steps in the `shortcircuit` function:

* **Step 1: Phi Argument Replacement:**  The code iterates through blocks and values, looking for `OpPhi` (phi functions) with boolean types. It checks if a phi argument comes from the control value of a preceding `BlockIf`. The logic seems to be about replacing a phi argument with `true` or `false` if the preceding `If` block always goes in a certain direction.

* **Step 2: Control Flow Redirection:** This step calls a `fuse` function. The comment mentions redirecting control flow around known branches. The specific example involving a phi of `true` and an `if` statement suggests eliminating a conditional jump when the condition is always known.

**3. Analyzing `shortcircuitBlock`:**

This function seems to be the core logic for the "short-circuiting" optimization. I identify two main patterns it tries to match:

* **Pattern 1 (Single Phi):**  The comments and code describe looking for an `If` block whose control is a single phi function with a constant boolean argument. The goal is to directly connect the predecessor to the appropriate successor, bypassing the `If` block.

* **Pattern 2 (Multiple Phis):** This is a more complex case where the `If` block has other phi functions besides the one controlling the conditional. The function needs to ensure it can handle these other phis by either moving them or rewriting their uses.

**4. Dissecting `shortcircuitPhiPlan`:**

This function deals with the complexities of handling other phi functions in `shortcircuitBlock`'s second pattern. It checks for specific Control Flow Graph (CFG) structures where paths merge or one path exits. For each identified structure, it returns a function (`fixPhi`) that knows how to adjust the additional phi functions. This suggests that the handling of these extra phis is highly dependent on the surrounding CFG.

**5. Identifying Helper Functions:**

I notice `fuse`, `removePred`, `removePhiArg`, `AddArg`, `SetArg`, `ReplaceControl`, `replaceUses`, and `moveTo`. These are likely utility functions for manipulating the SSA representation, such as modifying block connections, phi function arguments, and moving values between blocks.

**6. Inferring Go Feature Implementation:**

Based on the function names, comments, and the logic, it's highly likely this code implements short-circuit evaluation for boolean expressions (`&&` and `||`). The transformations aim to avoid evaluating the second operand if the result can be determined from the first operand.

**7. Constructing Go Examples:**

Now I can create Go code examples that would benefit from this optimization. I focus on the identified patterns:

* **Simple `&&` and `||`:** These are the most obvious candidates for short-circuiting.
* **`if` with constant condition:** While not directly related to `&&` or `||`, the phi replacement logic in `shortcircuit` could apply here if a variable involved in the condition is always a specific value due to previous control flow.

**8. Reasoning about Inputs and Outputs:**

For the code examples, I can mentally simulate the SSA transformations. For instance, with `a && b`, if `a` is false, the `shortcircuit` pass should redirect control flow to avoid evaluating `b`. I can also consider cases with phi functions where the optimization might replace arguments with constants.

**9. Considering Command-Line Arguments (Less Relevant Here):**

I realize that this specific code snippet doesn't directly process command-line arguments. It's a compiler optimization pass that runs internally. Therefore, I note that it's not directly influenced by command-line flags. *Initially, I might have considered compiler flags related to optimization levels, but a closer look confirms this pass is more about a specific code transformation.*

**10. Identifying Potential Pitfalls:**

I think about what could go wrong or be confusing for someone using Go. While the optimization itself is transparent, understanding *why* certain code patterns are optimized might be challenging. Specifically, the interaction of phi functions and control flow can be subtle. I construct an example with a more complex conditional to illustrate where understanding SSA is helpful.

**11. Iterative Refinement:**

As I go through the code, I might refine my understanding. For instance, initially, I might not fully grasp the purpose of `shortcircuitPhiPlan`. However, by looking at the different CFG patterns it handles, I can deduce its role in making the more complex phi optimization work correctly. Similarly, the exact conditions for applying each transformation become clearer by examining the `if` statements in the code.

This iterative process of reading the code, understanding the comments, identifying patterns, constructing examples, and refining my understanding allows me to generate a comprehensive explanation of the code's functionality.
这段代码是 Go 编译器中 `ssa` 包的一部分，其主要功能是实现**短路求值优化**。

**功能概览:**

`shortcircuit.go` 文件的核心目标是通过分析控制流图 (CFG) 中分支之间的相关性，来优化 `&&` (逻辑与) 和 `||` (逻辑或) 表达式的编译。这种优化旨在避免不必要的计算，从而提高程序执行效率。

**详细功能分解:**

1. **`shortcircuit(f *Func)` 函数:**
   - 这是短路优化主要的入口函数，它接收一个函数 `f` 的 SSA 表示作为输入。
   - 它包含两个主要的步骤：
      - **步骤 1: Phi 节点参数替换:**  识别特定的模式，其中 `Phi` 节点的某个参数是前一个 `If` 块的控制值。在这种情况下，如果 `If` 块总是走向某个分支，那么 `Phi` 节点的对应参数可以用常量 `true` 或 `false` 替换。
      - **步骤 2: 控制流重定向:** 利用已知的分支方向，将控制流直接跳转到目标块，从而绕过中间的条件判断块。这通常发生在 `Phi` 节点的值已知为 `true` 或 `false` 的情况下。
   - 它调用 `fuse` 函数执行实际的控制流合并操作。

2. **`shortcircuitBlock(b *Block)` 函数:**
   - 该函数检查一个 `If` 类型的基本块 `b`，其控制值是一个 `Phi` 节点，并且该 `Phi` 节点包含一个常量布尔参数。
   - 它尝试识别两种主要的 CFG 结构：
      - **结构 1 (单个 Phi 节点):**  一个 `If` 块只有一个 `Phi` 节点作为控制值，并且该 `Phi` 节点只有一个用途（即作为该 `If` 块的控制值）。
      - **结构 2 (多个 Phi 节点):**  与结构 1 类似，但 `If` 块可能包含其他的 `Phi` 节点。
   - 对于识别出的结构，`shortcircuitBlock` 会重写 CFG，将控制流直接从前驱节点连接到根据常量布尔值确定的后继节点，从而消除中间的 `If` 块。
   - 如果存在其他的 `Phi` 节点，它会调用 `shortcircuitPhiPlan` 来处理这些额外的 `Phi` 节点，确保在 CFG 修改后这些 `Phi` 节点仍然能够正确工作。

3. **`shortcircuitPhiPlan(b *Block, ctl *Value, cidx int, ti int64) func(*Value, int)` 函数:**
   - 这个函数负责处理在 `shortcircuitBlock` 中遇到的，除了控制 `If` 块的 `Phi` 节点之外的其他 `Phi` 节点。
   - 它分析特定的 CFG 结构，其中从 `If` 块分出的路径会再次合并，或者其中一条路径是程序的出口。
   - 对于不同的 CFG 结构，它会返回一个函数，该函数知道如何调整这些额外的 `Phi` 节点。这可能涉及到将 `Phi` 节点移动到不同的块，或者根据已知的常量值替换 `Phi` 节点的参数。

4. **`replaceUses(old, new *Value)` 函数:**
   - 这是一个辅助函数，用于在一个基本块 `b` 中，将所有对旧值 `old` 的使用替换为新值 `new`。

5. **`moveTo(dst *Block, i int)` 函数:**
   - 这是一个辅助函数，用于将一个 SSA 值 `v` 从其当前的基本块移动到目标基本块 `dst`。它会更新 `Block.Values` 切片来反映这种移动。

**Go 语言功能实现推理 (短路求值):**

这段代码的核心目的是实现 Go 语言中 `&&` 和 `||` 运算符的短路求值特性。

**Go 代码示例:**

```go
package main

func main() {
	a := false
	b := computeExpensiveValue() // 假设这是一个计算量很大的函数

	// 使用 && 运算符
	if a && b {
		println("Both are true")
	}

	c := true
	d := anotherExpensiveComputation()

	// 使用 || 运算符
	if c || d {
		println("At least one is true")
	}
}

func computeExpensiveValue() bool {
	println("Computing expensive value...")
	// 模拟耗时操作
	return true
}

func anotherExpensiveComputation() bool {
	println("Computing another expensive value...")
	// 模拟耗时操作
	return false
}
```

**假设输入与输出 (基于 `shortcircuitBlock` 的简化示例):**

假设有如下 SSA 基本块 (简化表示):

**输入 (优化前):**

```
b1:
    v0 = ConstBool false
    If v0 goto b2 else b3

b2: <- b1
    v1 = Phi(v0, ...) // ... 表示其他前驱块的输入
    // ... 其他操作
```

**`shortcircuitBlock` 的处理:**

- `shortcircuitBlock` 会识别出 `b1` 是一个 `BlockIf`，其控制值 `v0` 是一个常量 `false`。
- 它会确定从 `b1` 进入时，总是会跳转到 `b3` 分支。
- 因此，它可以将前驱块直接连接到 `b3`，并移除 `b1` 和 `b2` 之间的连接。
- 在 `b2` 中的 `Phi` 节点 `v1`，由于是从 `b1` 进入的，其对应的参数 `v0` 是 `false`，可以被替换为常量 `false`。

**输出 (优化后):**

```
前驱块 -> b3:
    // ... 其他操作 (原本在 b2 中，可能需要调整)
```

**涉及到 `shortcircuitPhiPlan` 的示例 (更复杂的情况):**

假设有如下 SSA 基本块 (简化表示):

**输入 (优化前):**

```
b1:
    v0 = condition1
    If v0 goto b2 else b3

b2: <- b1
    v1 = Phi(true, ...)
    v2 = Phi(x, y)
    If v1 goto b4 else b5

b3: <- b1
    v3 = Phi(false, ...)
    v4 = Phi(z, w)
    If v3 goto b4 else b5

b4: <- b2, b3
    v5 = Phi(...)
    // ...
```

**`shortcircuitBlock` 和 `shortcircuitPhiPlan` 的处理:**

- `shortcircuitBlock` 会识别出 `b2` 的控制值 `v1` 是一个 `Phi` 节点，并且其中一个输入是常量 `true` (来自 `b1`)。
- 它可以优化 `b1` 到 `b2` 的路径，直接连接到 `b4`。
- 但是，`b2` 中还有 `Phi` 节点 `v2`。`shortcircuitPhiPlan` 会分析 CFG 结构，并可能将 `v2` 移动到 `b4`，并根据到达 `b4` 的路径设置其参数 (要么是 `x`，要么是 `z`)。

**命令行参数:**

这段代码本身并不直接处理命令行参数。它是 Go 编译器内部的优化阶段。然而，Go 编译器本身接受一些与优化相关的命令行参数，例如：

- `-N`:  禁用所有优化。
- `-l`:  禁用内联 (内联可能会影响短路优化的效果)。
- `-gcflags`:  允许传递更底层的参数给垃圾回收器和编译器，可以间接地影响优化。

**使用者易犯错的点:**

通常，Go 开发者不需要直接关心这种底层的编译器优化。短路求值是 Go 语言规范的一部分，编译器会自动进行优化。

但理解短路求值本身对于编写高效和正确的代码很重要。一个常见的误解是，在 `&&` 或 `||` 表达式中，所有的操作数都会被无条件地执行。

**易犯错的例子:**

```go
package main

import "fmt"

func riskyOperation() bool {
	fmt.Println("Risky operation executed!")
	// 假设这个操作可能导致错误或副作用
	return true
}

func main() {
	a := false
	if a && riskyOperation() { // 如果 a 是 false，riskyOperation() 不会被执行
		fmt.Println("This won't be printed")
	}

	b := true
	if b || riskyOperation() { // 如果 b 是 true，riskyOperation() 不会被执行
		fmt.Println("This will be printed")
	}
}
```

在这个例子中，如果开发者不理解短路求值，可能会认为 `riskyOperation()` 总是会被执行。但实际上，当 `a` 为 `false` 时，`a && riskyOperation()` 中的 `riskyOperation()` 不会被调用。同样，当 `b` 为 `true` 时，`b || riskyOperation()` 中的 `riskyOperation()` 不会被调用。

理解短路求值有助于避免潜在的错误和提高代码效率。编译器所做的优化正是基于这种语言特性。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/shortcircuit.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

// shortcircuit finds situations where branch directions
// are always correlated and rewrites the CFG to take
// advantage of that fact.
// This optimization is useful for compiling && and || expressions.
func shortcircuit(f *Func) {
	// Step 1: Replace a phi arg with a constant if that arg
	// is the control value of a preceding If block.
	// b1:
	//    If a goto b2 else b3
	// b2: <- b1 ...
	//    x = phi(a, ...)
	//
	// We can replace the "a" in the phi with the constant true.
	var ct, cf *Value
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != OpPhi {
				continue
			}
			if !v.Type.IsBoolean() {
				continue
			}
			for i, a := range v.Args {
				e := b.Preds[i]
				p := e.b
				if p.Kind != BlockIf {
					continue
				}
				if p.Controls[0] != a {
					continue
				}
				if e.i == 0 {
					if ct == nil {
						ct = f.ConstBool(f.Config.Types.Bool, true)
					}
					v.SetArg(i, ct)
				} else {
					if cf == nil {
						cf = f.ConstBool(f.Config.Types.Bool, false)
					}
					v.SetArg(i, cf)
				}
			}
		}
	}

	// Step 2: Redirect control flow around known branches.
	// p:
	//   ... goto b ...
	// b: <- p ...
	//   v = phi(true, ...)
	//   if v goto t else u
	// We can redirect p to go directly to t instead of b.
	// (If v is not live after b).
	fuse(f, fuseTypePlain|fuseTypeShortCircuit)
}

// shortcircuitBlock checks for a CFG in which an If block
// has as its control value a Phi that has a ConstBool arg.
// In some such cases, we can rewrite the CFG into a flatter form.
//
// (1) Look for a CFG of the form
//
//	p   other pred(s)
//	 \ /
//	  b
//	 / \
//	t   other succ
//
// in which b is an If block containing a single phi value with a single use (b's Control),
// which has a ConstBool arg.
// p is the predecessor corresponding to the argument slot in which the ConstBool is found.
// t is the successor corresponding to the value of the ConstBool arg.
//
// Rewrite this into
//
//	p   other pred(s)
//	|  /
//	| b
//	|/ \
//	t   u
//
// and remove the appropriate phi arg(s).
//
// (2) Look for a CFG of the form
//
//	p   q
//	 \ /
//	  b
//	 / \
//	t   u
//
// in which b is as described in (1).
// However, b may also contain other phi values.
// The CFG will be modified as described in (1).
// However, in order to handle those other phi values,
// for each other phi value w, we must be able to eliminate w from b.
// We can do that though a combination of moving w to a different block
// and rewriting uses of w to use a different value instead.
// See shortcircuitPhiPlan for details.
func shortcircuitBlock(b *Block) bool {
	if b.Kind != BlockIf {
		return false
	}
	// Look for control values of the form Copy(Not(Copy(Phi(const, ...)))).
	// Those must be the only values in the b, and they each must be used only by b.
	// Track the negations so that we can swap successors as needed later.
	ctl := b.Controls[0]
	nval := 1 // the control value
	var swap int64
	for ctl.Uses == 1 && ctl.Block == b && (ctl.Op == OpCopy || ctl.Op == OpNot) {
		if ctl.Op == OpNot {
			swap = 1 ^ swap
		}
		ctl = ctl.Args[0]
		nval++ // wrapper around control value
	}
	if ctl.Op != OpPhi || ctl.Block != b || ctl.Uses != 1 {
		return false
	}
	nOtherPhi := 0
	for _, w := range b.Values {
		if w.Op == OpPhi && w != ctl {
			nOtherPhi++
		}
	}
	if nOtherPhi > 0 && len(b.Preds) != 2 {
		// We rely on b having exactly two preds in shortcircuitPhiPlan
		// to reason about the values of phis.
		return false
	}
	if len(b.Values) != nval+nOtherPhi {
		return false
	}
	if nOtherPhi > 0 {
		// Check for any phi which is the argument of another phi.
		// These cases are tricky, as substitutions done by replaceUses
		// are no longer trivial to do in any ordering. See issue 45175.
		m := make(map[*Value]bool, 1+nOtherPhi)
		for _, v := range b.Values {
			if v.Op == OpPhi {
				m[v] = true
			}
		}
		for v := range m {
			for _, a := range v.Args {
				if a != v && m[a] {
					return false
				}
			}
		}
	}

	// Locate index of first const phi arg.
	cidx := -1
	for i, a := range ctl.Args {
		if a.Op == OpConstBool {
			cidx = i
			break
		}
	}
	if cidx == -1 {
		return false
	}

	// p is the predecessor corresponding to cidx.
	pe := b.Preds[cidx]
	p := pe.b
	pi := pe.i

	// t is the "taken" branch: the successor we always go to when coming in from p.
	ti := 1 ^ ctl.Args[cidx].AuxInt ^ swap
	te := b.Succs[ti]
	t := te.b
	if p == b || t == b {
		// This is an infinite loop; we can't remove it. See issue 33903.
		return false
	}

	var fixPhi func(*Value, int)
	if nOtherPhi > 0 {
		fixPhi = shortcircuitPhiPlan(b, ctl, cidx, ti)
		if fixPhi == nil {
			return false
		}
	}

	// We're committed. Update CFG and Phis.
	// If you modify this section, update shortcircuitPhiPlan corresponding.

	// Remove b's incoming edge from p.
	b.removePred(cidx)
	b.removePhiArg(ctl, cidx)

	// Redirect p's outgoing edge to t.
	p.Succs[pi] = Edge{t, len(t.Preds)}

	// Fix up t to have one more predecessor.
	t.Preds = append(t.Preds, Edge{p, pi})
	for _, v := range t.Values {
		if v.Op != OpPhi {
			continue
		}
		v.AddArg(v.Args[te.i])
	}

	if nOtherPhi != 0 {
		// Adjust all other phis as necessary.
		// Use a plain for loop instead of range because fixPhi may move phis,
		// thus modifying b.Values.
		for i := 0; i < len(b.Values); i++ {
			phi := b.Values[i]
			if phi.Uses == 0 || phi == ctl || phi.Op != OpPhi {
				continue
			}
			fixPhi(phi, i)
			if phi.Block == b {
				continue
			}
			// phi got moved to a different block with v.moveTo.
			// Adjust phi values in this new block that refer
			// to phi to refer to the corresponding phi arg instead.
			// phi used to be evaluated prior to this block,
			// and now it is evaluated in this block.
			for _, v := range phi.Block.Values {
				if v.Op != OpPhi || v == phi {
					continue
				}
				for j, a := range v.Args {
					if a == phi {
						v.SetArg(j, phi.Args[j])
					}
				}
			}
			if phi.Uses != 0 {
				phielimValue(phi)
			} else {
				phi.reset(OpInvalid)
			}
			i-- // v.moveTo put a new value at index i; reprocess
		}

		// We may have left behind some phi values with no uses
		// but the wrong number of arguments. Eliminate those.
		for _, v := range b.Values {
			if v.Uses == 0 {
				v.reset(OpInvalid)
			}
		}
	}

	if len(b.Preds) == 0 {
		// Block is now dead.
		b.Kind = BlockInvalid
	}

	phielimValue(ctl)
	return true
}

// shortcircuitPhiPlan returns a function to handle non-ctl phi values in b,
// where b is as described in shortcircuitBlock.
// The returned function accepts a value v
// and the index i of v in v.Block: v.Block.Values[i] == v.
// If the returned function moves v to a different block, it will use v.moveTo.
// cidx is the index in ctl of the ConstBool arg.
// ti is the index in b.Succs of the always taken branch when arriving from p.
// If shortcircuitPhiPlan returns nil, there is no plan available,
// and the CFG modifications must not proceed.
// The returned function assumes that shortcircuitBlock has completed its CFG modifications.
func shortcircuitPhiPlan(b *Block, ctl *Value, cidx int, ti int64) func(*Value, int) {
	// t is the "taken" branch: the successor we always go to when coming in from p.
	t := b.Succs[ti].b
	// u is the "untaken" branch: the successor we never go to when coming in from p.
	u := b.Succs[1^ti].b

	// In the following CFG matching, ensure that b's preds are entirely distinct from b's succs.
	// This is probably a stronger condition than required, but this happens extremely rarely,
	// and it makes it easier to avoid getting deceived by pretty ASCII charts. See #44465.
	if p0, p1 := b.Preds[0].b, b.Preds[1].b; p0 == t || p1 == t || p0 == u || p1 == u {
		return nil
	}

	// Look for some common CFG structures
	// in which the outbound paths from b merge,
	// with no other preds joining them.
	// In these cases, we can reconstruct what the value
	// of any phi in b must be in the successor blocks.

	if len(t.Preds) == 1 && len(t.Succs) == 1 &&
		len(u.Preds) == 1 && len(u.Succs) == 1 &&
		t.Succs[0].b == u.Succs[0].b && len(t.Succs[0].b.Preds) == 2 {
		// p   q
		//  \ /
		//   b
		//  / \
		// t   u
		//  \ /
		//   m
		//
		// After the CFG modifications, this will look like
		//
		// p   q
		// |  /
		// | b
		// |/ \
		// t   u
		//  \ /
		//   m
		//
		// NB: t.Preds is (b, p), not (p, b).
		m := t.Succs[0].b
		return func(v *Value, i int) {
			// Replace any uses of v in t and u with the value v must have,
			// given that we have arrived at that block.
			// Then move v to m and adjust its value accordingly;
			// this handles all other uses of v.
			argP, argQ := v.Args[cidx], v.Args[1^cidx]
			u.replaceUses(v, argQ)
			phi := t.Func.newValue(OpPhi, v.Type, t, v.Pos)
			phi.AddArg2(argQ, argP)
			t.replaceUses(v, phi)
			if v.Uses == 0 {
				return
			}
			v.moveTo(m, i)
			// The phi in m belongs to whichever pred idx corresponds to t.
			if m.Preds[0].b == t {
				v.SetArgs2(phi, argQ)
			} else {
				v.SetArgs2(argQ, phi)
			}
		}
	}

	if len(t.Preds) == 2 && len(u.Preds) == 1 && len(u.Succs) == 1 && u.Succs[0].b == t {
		// p   q
		//  \ /
		//   b
		//   |\
		//   | u
		//   |/
		//   t
		//
		// After the CFG modifications, this will look like
		//
		//     q
		//    /
		//   b
		//   |\
		// p | u
		//  \|/
		//   t
		//
		// NB: t.Preds is (b or u, b or u, p).
		return func(v *Value, i int) {
			// Replace any uses of v in u. Then move v to t.
			argP, argQ := v.Args[cidx], v.Args[1^cidx]
			u.replaceUses(v, argQ)
			v.moveTo(t, i)
			v.SetArgs3(argQ, argQ, argP)
		}
	}

	if len(u.Preds) == 2 && len(t.Preds) == 1 && len(t.Succs) == 1 && t.Succs[0].b == u {
		// p   q
		//  \ /
		//   b
		//  /|
		// t |
		//  \|
		//   u
		//
		// After the CFG modifications, this will look like
		//
		// p   q
		// |  /
		// | b
		// |/|
		// t |
		//  \|
		//   u
		//
		// NB: t.Preds is (b, p), not (p, b).
		return func(v *Value, i int) {
			// Replace any uses of v in t. Then move v to u.
			argP, argQ := v.Args[cidx], v.Args[1^cidx]
			phi := t.Func.newValue(OpPhi, v.Type, t, v.Pos)
			phi.AddArg2(argQ, argP)
			t.replaceUses(v, phi)
			if v.Uses == 0 {
				return
			}
			v.moveTo(u, i)
			v.SetArgs2(argQ, phi)
		}
	}

	// Look for some common CFG structures
	// in which one outbound path from b exits,
	// with no other preds joining.
	// In these cases, we can reconstruct what the value
	// of any phi in b must be in the path leading to exit,
	// and move the phi to the non-exit path.

	if len(t.Preds) == 1 && len(u.Preds) == 1 && len(t.Succs) == 0 {
		// p   q
		//  \ /
		//   b
		//  / \
		// t   u
		//
		// where t is an Exit/Ret block.
		//
		// After the CFG modifications, this will look like
		//
		// p   q
		// |  /
		// | b
		// |/ \
		// t   u
		//
		// NB: t.Preds is (b, p), not (p, b).
		return func(v *Value, i int) {
			// Replace any uses of v in t and x. Then move v to u.
			argP, argQ := v.Args[cidx], v.Args[1^cidx]
			// If there are no uses of v in t or x, this phi will be unused.
			// That's OK; it's not worth the cost to prevent that.
			phi := t.Func.newValue(OpPhi, v.Type, t, v.Pos)
			phi.AddArg2(argQ, argP)
			t.replaceUses(v, phi)
			if v.Uses == 0 {
				return
			}
			v.moveTo(u, i)
			v.SetArgs1(argQ)
		}
	}

	if len(u.Preds) == 1 && len(t.Preds) == 1 && len(u.Succs) == 0 {
		// p   q
		//  \ /
		//   b
		//  / \
		// t   u
		//
		// where u is an Exit/Ret block.
		//
		// After the CFG modifications, this will look like
		//
		// p   q
		// |  /
		// | b
		// |/ \
		// t   u
		//
		// NB: t.Preds is (b, p), not (p, b).
		return func(v *Value, i int) {
			// Replace any uses of v in u (and x). Then move v to t.
			argP, argQ := v.Args[cidx], v.Args[1^cidx]
			u.replaceUses(v, argQ)
			v.moveTo(t, i)
			v.SetArgs2(argQ, argP)
		}
	}

	// TODO: handle more cases; shortcircuit optimizations turn out to be reasonably high impact
	return nil
}

// replaceUses replaces all uses of old in b with new.
func (b *Block) replaceUses(old, new *Value) {
	for _, v := range b.Values {
		for i, a := range v.Args {
			if a == old {
				v.SetArg(i, new)
			}
		}
	}
	for i, v := range b.ControlValues() {
		if v == old {
			b.ReplaceControl(i, new)
		}
	}
}

// moveTo moves v to dst, adjusting the appropriate Block.Values slices.
// The caller is responsible for ensuring that this is safe.
// i is the index of v in v.Block.Values.
func (v *Value) moveTo(dst *Block, i int) {
	if dst.Func.scheduled {
		v.Fatalf("moveTo after scheduling")
	}
	src := v.Block
	if src.Values[i] != v {
		v.Fatalf("moveTo bad index %d", v, i)
	}
	if src == dst {
		return
	}
	v.Block = dst
	dst.Values = append(dst.Values, v)
	last := len(src.Values) - 1
	src.Values[i] = src.Values[last]
	src.Values[last] = nil
	src.Values = src.Values[:last]
}
```