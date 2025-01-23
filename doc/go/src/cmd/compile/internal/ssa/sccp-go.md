Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Core Goal:**

The initial comment block immediately gives us the high-level purpose: "Sparse Conditional Constant Propagation". The acronym SCCP is also important. The description mentions a three-level lattice (Top, Constant, Bottom) and propagation of constants along reachable control flow paths. This points towards an optimization pass in a compiler.

**2. Examining the Data Structures:**

Next, I'd look at the `struct` definitions:

* **`lattice`:** Clearly represents the three-level lattice, storing the `tag` (Top, Constant, Bottom) and the constant `val` if it's constant.
* **`worklist`:** This seems to be the central data structure for the algorithm. It holds:
    * `f`: The function being analyzed.
    * `edges`:  For traversing the Control Flow Graph (CFG).
    * `uses`:  A list of values to revisit when a constant changes.
    * `visited`: Tracks visited CFG edges.
    * `latticeCells`:  The core mapping of SSA values to their lattice states.
    * `defUse`, `defBlock`:  Information about how values are used (def-use chains) and which blocks use them (for control flow).
    * `visitedBlock`: Tracks visited blocks.

The names of the fields give strong hints about their purpose.

**3. Analyzing the `sccp` Function:**

This is the entry point of the SCCP pass. Key observations:

* **Initialization:** It creates a `worklist` and initializes its fields, notably adding the entry edge to `t.edges`.
* **`buildDefUses()`:** This is called early, suggesting that def-use information is crucial for the algorithm.
* **Main Loop:** The `for` loop processes either edges or uses from the worklist. This indicates an iterative propagation approach.
* **Edge Processing:**  When processing an edge, it marks the edge and destination block as visited and calls `t.visitValue()` for the block's values (especially Phis). It then calls `t.propagate()` to continue traversing the CFG.
* **Use Processing:** When processing a use, it calls `t.visitValue()` to update the lattice of that value.
* **`replaceConst()`:**  After the loop, this function applies the discovered constant information.

**4. Deconstructing Key Methods:**

Now, examine the helper functions:

* **`equals()`:** Compares lattices, handling the special case for constant values (comparing `AuxInt`).
* **`possibleConst()`:** Determines if a value *could* become a constant. This is an important optimization – no need to track lattices for things that can never be constant. The `switch` statement lists the eligible `Op` codes.
* **`getLatticeCell()`:** Retrieves the lattice for a value, defaulting to `top` (optimistic) if not yet visited.
* **`isConst()`:**  Checks if a value is already a constant.
* **`buildDefUses()`:** Populates the `defUse` and `defBlock` maps. This involves iterating through blocks and values to find uses.
* **`addUses()`:**  Adds the uses of a value to the worklist.
* **`meet()`:** Implements the meet operation of the lattice for Phi nodes. Crucially, it handles the "Top" case for unvisited incoming edges.
* **`computeLattice()`:**  *This is a clever trick!*  Instead of manually implementing constant folding for every operation, it *re-uses the existing generic rewrite rules*. This saves a lot of code but has a caveat – it needs to be careful not to permanently modify values. The temporary `constValue` and the `reset(OpInvalid)` are crucial here.
* **`visitValue()`:**  The heart of the lattice update logic. It retrieves the old lattice, computes the new lattice based on the operation and operand lattices, and then adds uses to the worklist if the lattice changed. The `switch` statement handles different operation types and applies the `computeLattice` trick.
* **`propagate()`:**  Decides which successor blocks to add to the worklist based on the control flow instruction and the lattice of the condition (if any).
* **`rewireSuccessor()`:** Modifies the CFG based on constant conditions, making branches unconditional.
* **`replaceConst()`:**  Replaces non-constant values with their constant equivalents and calls `rewireSuccessor` to simplify control flow.

**5. Inferring the Go Feature:**

Based on the function name (`sccp`), the focus on constant propagation, conditional branches, and the use of SSA (Static Single Assignment form), it's highly likely that this code implements the **Sparse Conditional Constant Propagation optimization pass** within the Go compiler. This optimization aims to identify values that are constant at compile time, even if their constancy depends on the execution path.

**6. Developing the Example (and Anticipating Inputs/Outputs):**

To illustrate, I'd think of a simple Go function where SCCP could make a difference:

```go
package main

func example(a int) int {
	if a > 10 {
		return 5
	} else {
		return 5
	}
}
```

In this case, regardless of the input `a`, the function always returns 5. SCCP should be able to detect this.

* **Hypothetical Input (SSA Representation):**  I'd imagine the SSA representation would involve a conditional branch (`if a > 10`) and two return statements, each producing the constant value 5.
* **SCCP's Process:**  SCCP would initially assume the return values are `top`. As it propagates through the branches, it would discover that both branches lead to the constant 5. The `meet` operation on the Phi node (if there were one) would result in `constant(5)`.
* **Hypothetical Output (Optimized SSA):** The optimized SSA would likely replace the conditional return with a direct return of the constant 5.

**7. Considering Command-Line Parameters:**

Since this is compiler code, I'd think about how such an optimization might be enabled or controlled. Compiler flags related to optimization levels (e.g., `-O1`, `-O2`) or specific optimization passes would be relevant. I'd look for comments or logic within the code that might indicate how these parameters are handled (though this specific snippet doesn't show that).

**8. Identifying Common Mistakes:**

For potential errors, I'd consider:

* **Incorrect `meet` implementation:**  A faulty `meet` function could lead to incorrect constant propagation.
* **Missing cases in `possibleConst` or `visitValue`:**  If an operation that *can* produce a constant is not handled correctly, SCCP might miss optimization opportunities.
* **Errors in `propagate`:** Incorrectly determining reachable blocks would lead to incomplete or incorrect constant propagation.
* **The trick in `computeLattice`:** If the temporary `constValue` isn't handled correctly (not reset), it could cause issues.

This systematic approach, combining understanding the high-level goal, analyzing the data structures and key functions, inferring the Go feature, and then constructing examples and considering edge cases, allows for a comprehensive understanding of the provided code snippet.
这段代码是 Go 编译器中 **稀疏有条件的常量传播 (Sparse Conditional Constant Propagation, SCCP)** 算法的实现。

**功能列举:**

1. **常量传播:**  `sccp` 函数的目标是识别并传播在编译时可以确定为常量的值。
2. **条件控制流分析:**  SCCP 算法会考虑程序中的条件分支 (例如 `if` 语句) 和其他控制流结构，只在可能执行到的路径上进行常量传播。这就是 "有条件" 的含义。
3. **稀疏分析:**  与传统的常量传播不同，SCCP 算法只关注可能成为常量的值，避免在所有值上进行不必要的分析。这通过 `possibleConst` 函数来判断一个值是否有可能成为常量来实现。
4. **三级格 (Three-level Lattice):**  代码中使用 `lattice` 结构体来表示 SSA 值的状态，包含 `top` (未定义)、`constant` (常量) 和 `bottom` (非常量) 三种状态。
5. **工作列表 (Worklist):**  `worklist` 结构体用于管理待处理的边 (CFG 中的边) 和 SSA 值，驱动算法的迭代过程。
6. **定值-使用链 (Def-Use Chains):**  `buildDefUses` 函数构建了值的定值-使用链，用于在值的状态改变时快速找到其使用者。
7. **格的合并 (Meet Operation):** `meet` 函数实现了格的合并操作，用于计算 `phi` 节点的格状态。`phi` 节点的值取决于其所有可能的前驱，因此需要将来自不同前驱的值的格状态合并。
8. **常量折叠 (Constant Folding):**  在 `visitValue` 函数中，当一个操作的所有输入都是常量时，代码会尝试使用通用的重写规则 (`rewriteValuegeneric`) 来计算该操作的结果，从而实现常量折叠。
9. **常量替换 (Constant Replacement):** `replaceConst` 函数遍历所有分析过的 SSA 值，如果其格状态为 `constant` 且自身不是常量，则将其替换为常量值。
10. **死代码消除 (Dead Code Elimination, 通过控制流重写实现):**  `rewireSuccessor` 函数根据条件控制值的常量结果，重写控制流，例如将 `if` 语句替换为无条件跳转，从而使得一些代码块变得不可达，后续的死代码消除 pass 可以将其移除。

**Go 语言功能实现推断与代码示例:**

基于以上功能，可以推断出 `sccp.go` 是 Go 编译器中实现 **常量传播优化** 的一部分。常量传播是一种重要的编译器优化技术，它可以将编译时就能确定的表达式替换为其常量值，从而提高程序的执行效率。

**Go 代码示例:**

假设有以下 Go 代码：

```go
package main

func foo(x int) int {
	y := 5
	if x > 10 {
		return y
	} else {
		return y
	}
}

func main() {
	result := foo(7)
	println(result) // 输出 5
}
```

在 `foo` 函数中，变量 `y` 被赋值为常量 `5`。 无论 `x` 的值是多少，函数最终都会返回 `y` 的值，也就是 `5`。 SCCP 优化就能识别出这一点。

**假设的 SSA 输入和输出:**

为了简化，我们只关注 `foo` 函数内部的关键部分。

**假设的 SSA 输入 (简化):**

```
b1:
    v1 = ConstInt 5
    v2 = Arg <int>  // 参数 x
    If v2 > 10 goto b2 else b3

b2:
    Return v1

b3:
    Return v1
```

**SCCP 的执行过程 (简化):**

1. **初始化:** 所有 SSA 值的格状态初始化为 `top`。
2. **访问 b1:**
   - `v1` (常量 5): 格状态变为 `constant(5)`。
   - 条件 `v2 > 10` 的格状态取决于 `v2` 的格状态，初始为 `top`。
3. **访问 b2 (假设条件为真):**
   - `Return v1`:  `v1` 的格状态已经是 `constant(5)`。
4. **访问 b3 (假设条件为假):**
   - `Return v1`:  `v1` 的格状态已经是 `constant(5)`。
5. **常量传播:**  SCCP 发现无论执行哪个分支，最终返回的值都是常量 `5`。

**假设的 SSA 输出 (优化后，简化):**

```
b1:
    Return (ConstInt 5)
```

或者，在更底层的表示中，可能会直接将 `foo` 函数的调用替换为常量 `5`。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。SCCP 优化通常是 Go 编译器优化管道中的一个环节，它会在编译过程中自动运行。

Go 编译器的优化级别可以通过 `-gcflags` 传递给 `compile` 工具，例如：

```bash
go build -gcflags="-N -l" main.go  # 禁用优化和内联
go build main.go                      # 默认启用优化
go build -gcflags="-m" main.go        # 查看内联决策
```

虽然没有专门针对 SCCP 的命令行参数，但更高级别的优化 (例如 `-O2`) 通常会包含 SCCP 以及其他常量相关的优化。

**使用者易犯错的点 (与 SCCP 直接相关的错误较少，更多是理解优化):**

由于 SCCP 是编译器自动执行的优化，用户通常不会直接与之交互，因此不容易犯与 SCCP 本身相关的错误。然而，理解常量传播的原理可以帮助开发者更好地理解代码的性能特性。

一个可能相关的误解是：**认为所有看起来像常量的变量都会被优化掉。**

例如：

```go
package main

import "fmt"

func main() {
	const debugMode = true
	if debugMode {
		fmt.Println("Debugging information")
	}
}
```

在这种情况下，`debugMode` 是一个 `const` 常量，SCCP 很可能会将 `if debugMode` 直接替换为 `if true`，然后进一步优化掉 `fmt.Println` 语句。

但是，如果 `debugMode` 不是 `const`，而是一个普通的全局变量：

```go
package main

import "fmt"

var debugMode = true // 不是 const

func main() {
	if debugMode { // 此时 debugMode 的值在编译时无法确定
		fmt.Println("Debugging information")
	}
}
```

即使 `debugMode` 在定义时被初始化为 `true`，由于它不是 `const`，其值在运行时可能被修改，因此 SCCP 无法将其视为常量，`fmt.Println` 语句不会被优化掉。

**总结:**

`sccp.go` 文件实现了 Go 编译器中的稀疏有条件常量传播优化。它通过三级格和工作列表迭代地分析程序的控制流和数据流，识别并传播常量值，最终实现常量折叠和部分死代码消除，提高程序的执行效率。用户无需直接操作 SCCP，但理解其原理有助于编写更高效的 Go 代码。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/sccp.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"fmt"
)

// ----------------------------------------------------------------------------
// Sparse Conditional Constant Propagation
//
// Described in
// Mark N. Wegman, F. Kenneth Zadeck: Constant Propagation with Conditional Branches.
// TOPLAS 1991.
//
// This algorithm uses three level lattice for SSA value
//
//      Top        undefined
//     / | \
// .. 1  2  3 ..   constant
//     \ | /
//     Bottom      not constant
//
// It starts with optimistically assuming that all SSA values are initially Top
// and then propagates constant facts only along reachable control flow paths.
// Since some basic blocks are not visited yet, corresponding inputs of phi become
// Top, we use the meet(phi) to compute its lattice.
//
// 	  Top ∩ any = any
// 	  Bottom ∩ any = Bottom
// 	  ConstantA ∩ ConstantA = ConstantA
// 	  ConstantA ∩ ConstantB = Bottom
//
// Each lattice value is lowered most twice(Top to Constant, Constant to Bottom)
// due to lattice depth, resulting in a fast convergence speed of the algorithm.
// In this way, sccp can discover optimization opportunities that cannot be found
// by just combining constant folding and constant propagation and dead code
// elimination separately.

// Three level lattice holds compile time knowledge about SSA value
const (
	top      int8 = iota // undefined
	constant             // constant
	bottom               // not a constant
)

type lattice struct {
	tag int8   // lattice type
	val *Value // constant value
}

type worklist struct {
	f            *Func               // the target function to be optimized out
	edges        []Edge              // propagate constant facts through edges
	uses         []*Value            // re-visiting set
	visited      map[Edge]bool       // visited edges
	latticeCells map[*Value]lattice  // constant lattices
	defUse       map[*Value][]*Value // def-use chains for some values
	defBlock     map[*Value][]*Block // use blocks of def
	visitedBlock []bool              // visited block
}

// sccp stands for sparse conditional constant propagation, it propagates constants
// through CFG conditionally and applies constant folding, constant replacement and
// dead code elimination all together.
func sccp(f *Func) {
	var t worklist
	t.f = f
	t.edges = make([]Edge, 0)
	t.visited = make(map[Edge]bool)
	t.edges = append(t.edges, Edge{f.Entry, 0})
	t.defUse = make(map[*Value][]*Value)
	t.defBlock = make(map[*Value][]*Block)
	t.latticeCells = make(map[*Value]lattice)
	t.visitedBlock = f.Cache.allocBoolSlice(f.NumBlocks())
	defer f.Cache.freeBoolSlice(t.visitedBlock)

	// build it early since we rely heavily on the def-use chain later
	t.buildDefUses()

	// pick up either an edge or SSA value from worklist, process it
	for {
		if len(t.edges) > 0 {
			edge := t.edges[0]
			t.edges = t.edges[1:]
			if _, exist := t.visited[edge]; !exist {
				dest := edge.b
				destVisited := t.visitedBlock[dest.ID]

				// mark edge as visited
				t.visited[edge] = true
				t.visitedBlock[dest.ID] = true
				for _, val := range dest.Values {
					if val.Op == OpPhi || !destVisited {
						t.visitValue(val)
					}
				}
				// propagates constants facts through CFG, taking condition test
				// into account
				if !destVisited {
					t.propagate(dest)
				}
			}
			continue
		}
		if len(t.uses) > 0 {
			use := t.uses[0]
			t.uses = t.uses[1:]
			t.visitValue(use)
			continue
		}
		break
	}

	// apply optimizations based on discovered constants
	constCnt, rewireCnt := t.replaceConst()
	if f.pass.debug > 0 {
		if constCnt > 0 || rewireCnt > 0 {
			fmt.Printf("Phase SCCP for %v : %v constants, %v dce\n", f.Name, constCnt, rewireCnt)
		}
	}
}

func equals(a, b lattice) bool {
	if a == b {
		// fast path
		return true
	}
	if a.tag != b.tag {
		return false
	}
	if a.tag == constant {
		// The same content of const value may be different, we should
		// compare with auxInt instead
		v1 := a.val
		v2 := b.val
		if v1.Op == v2.Op && v1.AuxInt == v2.AuxInt {
			return true
		} else {
			return false
		}
	}
	return true
}

// possibleConst checks if Value can be folded to const. For those Values that can
// never become constants(e.g. StaticCall), we don't make futile efforts.
func possibleConst(val *Value) bool {
	if isConst(val) {
		return true
	}
	switch val.Op {
	case OpCopy:
		return true
	case OpPhi:
		return true
	case
		// negate
		OpNeg8, OpNeg16, OpNeg32, OpNeg64, OpNeg32F, OpNeg64F,
		OpCom8, OpCom16, OpCom32, OpCom64,
		// math
		OpFloor, OpCeil, OpTrunc, OpRoundToEven, OpSqrt,
		// conversion
		OpTrunc16to8, OpTrunc32to8, OpTrunc32to16, OpTrunc64to8,
		OpTrunc64to16, OpTrunc64to32, OpCvt32to32F, OpCvt32to64F,
		OpCvt64to32F, OpCvt64to64F, OpCvt32Fto32, OpCvt32Fto64,
		OpCvt64Fto32, OpCvt64Fto64, OpCvt32Fto64F, OpCvt64Fto32F,
		OpCvtBoolToUint8,
		OpZeroExt8to16, OpZeroExt8to32, OpZeroExt8to64, OpZeroExt16to32,
		OpZeroExt16to64, OpZeroExt32to64, OpSignExt8to16, OpSignExt8to32,
		OpSignExt8to64, OpSignExt16to32, OpSignExt16to64, OpSignExt32to64,
		// bit
		OpCtz8, OpCtz16, OpCtz32, OpCtz64,
		// mask
		OpSlicemask,
		// safety check
		OpIsNonNil,
		// not
		OpNot:
		return true
	case
		// add
		OpAdd64, OpAdd32, OpAdd16, OpAdd8,
		OpAdd32F, OpAdd64F,
		// sub
		OpSub64, OpSub32, OpSub16, OpSub8,
		OpSub32F, OpSub64F,
		// mul
		OpMul64, OpMul32, OpMul16, OpMul8,
		OpMul32F, OpMul64F,
		// div
		OpDiv32F, OpDiv64F,
		OpDiv8, OpDiv16, OpDiv32, OpDiv64,
		OpDiv8u, OpDiv16u, OpDiv32u, OpDiv64u,
		OpMod8, OpMod16, OpMod32, OpMod64,
		OpMod8u, OpMod16u, OpMod32u, OpMod64u,
		// compare
		OpEq64, OpEq32, OpEq16, OpEq8,
		OpEq32F, OpEq64F,
		OpLess64, OpLess32, OpLess16, OpLess8,
		OpLess64U, OpLess32U, OpLess16U, OpLess8U,
		OpLess32F, OpLess64F,
		OpLeq64, OpLeq32, OpLeq16, OpLeq8,
		OpLeq64U, OpLeq32U, OpLeq16U, OpLeq8U,
		OpLeq32F, OpLeq64F,
		OpEqB, OpNeqB,
		// shift
		OpLsh64x64, OpRsh64x64, OpRsh64Ux64, OpLsh32x64,
		OpRsh32x64, OpRsh32Ux64, OpLsh16x64, OpRsh16x64,
		OpRsh16Ux64, OpLsh8x64, OpRsh8x64, OpRsh8Ux64,
		// safety check
		OpIsInBounds, OpIsSliceInBounds,
		// bit
		OpAnd8, OpAnd16, OpAnd32, OpAnd64,
		OpOr8, OpOr16, OpOr32, OpOr64,
		OpXor8, OpXor16, OpXor32, OpXor64:
		return true
	default:
		return false
	}
}

func (t *worklist) getLatticeCell(val *Value) lattice {
	if !possibleConst(val) {
		// they are always worst
		return lattice{bottom, nil}
	}
	lt, exist := t.latticeCells[val]
	if !exist {
		return lattice{top, nil} // optimistically for un-visited value
	}
	return lt
}

func isConst(val *Value) bool {
	switch val.Op {
	case OpConst64, OpConst32, OpConst16, OpConst8,
		OpConstBool, OpConst32F, OpConst64F:
		return true
	default:
		return false
	}
}

// buildDefUses builds def-use chain for some values early, because once the
// lattice of a value is changed, we need to update lattices of use. But we don't
// need all uses of it, only uses that can become constants would be added into
// re-visit worklist since no matter how many times they are revisited, uses which
// can't become constants lattice remains unchanged, i.e. Bottom.
func (t *worklist) buildDefUses() {
	for _, block := range t.f.Blocks {
		for _, val := range block.Values {
			for _, arg := range val.Args {
				// find its uses, only uses that can become constants take into account
				if possibleConst(arg) && possibleConst(val) {
					if _, exist := t.defUse[arg]; !exist {
						t.defUse[arg] = make([]*Value, 0, arg.Uses)
					}
					t.defUse[arg] = append(t.defUse[arg], val)
				}
			}
		}
		for _, ctl := range block.ControlValues() {
			// for control values that can become constants, find their use blocks
			if possibleConst(ctl) {
				t.defBlock[ctl] = append(t.defBlock[ctl], block)
			}
		}
	}
}

// addUses finds all uses of value and appends them into work list for further process
func (t *worklist) addUses(val *Value) {
	for _, use := range t.defUse[val] {
		if val == use {
			// Phi may refer to itself as uses, ignore them to avoid re-visiting phi
			// for performance reason
			continue
		}
		t.uses = append(t.uses, use)
	}
	for _, block := range t.defBlock[val] {
		if t.visitedBlock[block.ID] {
			t.propagate(block)
		}
	}
}

// meet meets all of phi arguments and computes result lattice
func (t *worklist) meet(val *Value) lattice {
	optimisticLt := lattice{top, nil}
	for i := 0; i < len(val.Args); i++ {
		edge := Edge{val.Block, i}
		// If incoming edge for phi is not visited, assume top optimistically.
		// According to rules of meet:
		// 		Top ∩ any = any
		// Top participates in meet() but does not affect the result, so here
		// we will ignore Top and only take other lattices into consideration.
		if _, exist := t.visited[edge]; exist {
			lt := t.getLatticeCell(val.Args[i])
			if lt.tag == constant {
				if optimisticLt.tag == top {
					optimisticLt = lt
				} else {
					if !equals(optimisticLt, lt) {
						// ConstantA ∩ ConstantB = Bottom
						return lattice{bottom, nil}
					}
				}
			} else if lt.tag == bottom {
				// Bottom ∩ any = Bottom
				return lattice{bottom, nil}
			} else {
				// Top ∩ any = any
			}
		} else {
			// Top ∩ any = any
		}
	}

	// ConstantA ∩ ConstantA = ConstantA or Top ∩ any = any
	return optimisticLt
}

func computeLattice(f *Func, val *Value, args ...*Value) lattice {
	// In general, we need to perform constant evaluation based on constant args:
	//
	//  res := lattice{constant, nil}
	// 	switch op {
	// 	case OpAdd16:
	//		res.val = newConst(argLt1.val.AuxInt16() + argLt2.val.AuxInt16())
	// 	case OpAdd32:
	// 		res.val = newConst(argLt1.val.AuxInt32() + argLt2.val.AuxInt32())
	//	case OpDiv8:
	//		if !isDivideByZero(argLt2.val.AuxInt8()) {
	//			res.val = newConst(argLt1.val.AuxInt8() / argLt2.val.AuxInt8())
	//		}
	//  ...
	// 	}
	//
	// However, this would create a huge switch for all opcodes that can be
	// evaluated during compile time. Moreover, some operations can be evaluated
	// only if its arguments satisfy additional conditions(e.g. divide by zero).
	// It's fragile and error-prone. We did a trick by reusing the existing rules
	// in generic rules for compile-time evaluation. But generic rules rewrite
	// original value, this behavior is undesired, because the lattice of values
	// may change multiple times, once it was rewritten, we lose the opportunity
	// to change it permanently, which can lead to errors. For example, We cannot
	// change its value immediately after visiting Phi, because some of its input
	// edges may still not be visited at this moment.
	constValue := f.newValue(val.Op, val.Type, f.Entry, val.Pos)
	constValue.AddArgs(args...)
	matched := rewriteValuegeneric(constValue)
	if matched {
		if isConst(constValue) {
			return lattice{constant, constValue}
		}
	}
	// Either we can not match generic rules for given value or it does not
	// satisfy additional constraints(e.g. divide by zero), in these cases, clean
	// up temporary value immediately in case they are not dominated by their args.
	constValue.reset(OpInvalid)
	return lattice{bottom, nil}
}

func (t *worklist) visitValue(val *Value) {
	if !possibleConst(val) {
		// fast fail for always worst Values, i.e. there is no lowering happen
		// on them, their lattices must be initially worse Bottom.
		return
	}

	oldLt := t.getLatticeCell(val)
	defer func() {
		// re-visit all uses of value if its lattice is changed
		newLt := t.getLatticeCell(val)
		if !equals(newLt, oldLt) {
			if int8(oldLt.tag) > int8(newLt.tag) {
				t.f.Fatalf("Must lower lattice\n")
			}
			t.addUses(val)
		}
	}()

	switch val.Op {
	// they are constant values, aren't they?
	case OpConst64, OpConst32, OpConst16, OpConst8,
		OpConstBool, OpConst32F, OpConst64F: //TODO: support ConstNil ConstString etc
		t.latticeCells[val] = lattice{constant, val}
	// lattice value of copy(x) actually means lattice value of (x)
	case OpCopy:
		t.latticeCells[val] = t.getLatticeCell(val.Args[0])
	// phi should be processed specially
	case OpPhi:
		t.latticeCells[val] = t.meet(val)
	// fold 1-input operations:
	case
		// negate
		OpNeg8, OpNeg16, OpNeg32, OpNeg64, OpNeg32F, OpNeg64F,
		OpCom8, OpCom16, OpCom32, OpCom64,
		// math
		OpFloor, OpCeil, OpTrunc, OpRoundToEven, OpSqrt,
		// conversion
		OpTrunc16to8, OpTrunc32to8, OpTrunc32to16, OpTrunc64to8,
		OpTrunc64to16, OpTrunc64to32, OpCvt32to32F, OpCvt32to64F,
		OpCvt64to32F, OpCvt64to64F, OpCvt32Fto32, OpCvt32Fto64,
		OpCvt64Fto32, OpCvt64Fto64, OpCvt32Fto64F, OpCvt64Fto32F,
		OpCvtBoolToUint8,
		OpZeroExt8to16, OpZeroExt8to32, OpZeroExt8to64, OpZeroExt16to32,
		OpZeroExt16to64, OpZeroExt32to64, OpSignExt8to16, OpSignExt8to32,
		OpSignExt8to64, OpSignExt16to32, OpSignExt16to64, OpSignExt32to64,
		// bit
		OpCtz8, OpCtz16, OpCtz32, OpCtz64,
		// mask
		OpSlicemask,
		// safety check
		OpIsNonNil,
		// not
		OpNot:
		lt1 := t.getLatticeCell(val.Args[0])

		if lt1.tag == constant {
			// here we take a shortcut by reusing generic rules to fold constants
			t.latticeCells[val] = computeLattice(t.f, val, lt1.val)
		} else {
			t.latticeCells[val] = lattice{lt1.tag, nil}
		}
	// fold 2-input operations
	case
		// add
		OpAdd64, OpAdd32, OpAdd16, OpAdd8,
		OpAdd32F, OpAdd64F,
		// sub
		OpSub64, OpSub32, OpSub16, OpSub8,
		OpSub32F, OpSub64F,
		// mul
		OpMul64, OpMul32, OpMul16, OpMul8,
		OpMul32F, OpMul64F,
		// div
		OpDiv32F, OpDiv64F,
		OpDiv8, OpDiv16, OpDiv32, OpDiv64,
		OpDiv8u, OpDiv16u, OpDiv32u, OpDiv64u, //TODO: support div128u
		// mod
		OpMod8, OpMod16, OpMod32, OpMod64,
		OpMod8u, OpMod16u, OpMod32u, OpMod64u,
		// compare
		OpEq64, OpEq32, OpEq16, OpEq8,
		OpEq32F, OpEq64F,
		OpLess64, OpLess32, OpLess16, OpLess8,
		OpLess64U, OpLess32U, OpLess16U, OpLess8U,
		OpLess32F, OpLess64F,
		OpLeq64, OpLeq32, OpLeq16, OpLeq8,
		OpLeq64U, OpLeq32U, OpLeq16U, OpLeq8U,
		OpLeq32F, OpLeq64F,
		OpEqB, OpNeqB,
		// shift
		OpLsh64x64, OpRsh64x64, OpRsh64Ux64, OpLsh32x64,
		OpRsh32x64, OpRsh32Ux64, OpLsh16x64, OpRsh16x64,
		OpRsh16Ux64, OpLsh8x64, OpRsh8x64, OpRsh8Ux64,
		// safety check
		OpIsInBounds, OpIsSliceInBounds,
		// bit
		OpAnd8, OpAnd16, OpAnd32, OpAnd64,
		OpOr8, OpOr16, OpOr32, OpOr64,
		OpXor8, OpXor16, OpXor32, OpXor64:
		lt1 := t.getLatticeCell(val.Args[0])
		lt2 := t.getLatticeCell(val.Args[1])

		if lt1.tag == constant && lt2.tag == constant {
			// here we take a shortcut by reusing generic rules to fold constants
			t.latticeCells[val] = computeLattice(t.f, val, lt1.val, lt2.val)
		} else {
			if lt1.tag == bottom || lt2.tag == bottom {
				t.latticeCells[val] = lattice{bottom, nil}
			} else {
				t.latticeCells[val] = lattice{top, nil}
			}
		}
	default:
		// Any other type of value cannot be a constant, they are always worst(Bottom)
	}
}

// propagate propagates constants facts through CFG. If the block has single successor,
// add the successor anyway. If the block has multiple successors, only add the
// branch destination corresponding to lattice value of condition value.
func (t *worklist) propagate(block *Block) {
	switch block.Kind {
	case BlockExit, BlockRet, BlockRetJmp, BlockInvalid:
		// control flow ends, do nothing then
		break
	case BlockDefer:
		// we know nothing about control flow, add all branch destinations
		t.edges = append(t.edges, block.Succs...)
	case BlockFirst:
		fallthrough // always takes the first branch
	case BlockPlain:
		t.edges = append(t.edges, block.Succs[0])
	case BlockIf, BlockJumpTable:
		cond := block.ControlValues()[0]
		condLattice := t.getLatticeCell(cond)
		if condLattice.tag == bottom {
			// we know nothing about control flow, add all branch destinations
			t.edges = append(t.edges, block.Succs...)
		} else if condLattice.tag == constant {
			// add branchIdx destinations depends on its condition
			var branchIdx int64
			if block.Kind == BlockIf {
				branchIdx = 1 - condLattice.val.AuxInt
			} else {
				branchIdx = condLattice.val.AuxInt
			}
			t.edges = append(t.edges, block.Succs[branchIdx])
		} else {
			// condition value is not visited yet, don't propagate it now
		}
	default:
		t.f.Fatalf("All kind of block should be processed above.")
	}
}

// rewireSuccessor rewires corresponding successors according to constant value
// discovered by previous analysis. As the result, some successors become unreachable
// and thus can be removed in further deadcode phase
func rewireSuccessor(block *Block, constVal *Value) bool {
	switch block.Kind {
	case BlockIf:
		block.removeEdge(int(constVal.AuxInt))
		block.Kind = BlockPlain
		block.Likely = BranchUnknown
		block.ResetControls()
		return true
	case BlockJumpTable:
		// Remove everything but the known taken branch.
		idx := int(constVal.AuxInt)
		if idx < 0 || idx >= len(block.Succs) {
			// This can only happen in unreachable code,
			// as an invariant of jump tables is that their
			// input index is in range.
			// See issue 64826.
			return false
		}
		block.swapSuccessorsByIdx(0, idx)
		for len(block.Succs) > 1 {
			block.removeEdge(1)
		}
		block.Kind = BlockPlain
		block.Likely = BranchUnknown
		block.ResetControls()
		return true
	default:
		return false
	}
}

// replaceConst will replace non-constant values that have been proven by sccp
// to be constants.
func (t *worklist) replaceConst() (int, int) {
	constCnt, rewireCnt := 0, 0
	for val, lt := range t.latticeCells {
		if lt.tag == constant {
			if !isConst(val) {
				if t.f.pass.debug > 0 {
					fmt.Printf("Replace %v with %v\n", val.LongString(), lt.val.LongString())
				}
				val.reset(lt.val.Op)
				val.AuxInt = lt.val.AuxInt
				constCnt++
			}
			// If const value controls this block, rewires successors according to its value
			ctrlBlock := t.defBlock[val]
			for _, block := range ctrlBlock {
				if rewireSuccessor(block, lt.val) {
					rewireCnt++
					if t.f.pass.debug > 0 {
						fmt.Printf("Rewire %v %v successors\n", block.Kind, block)
					}
				}
			}
		}
	}
	return constCnt, rewireCnt
}
```