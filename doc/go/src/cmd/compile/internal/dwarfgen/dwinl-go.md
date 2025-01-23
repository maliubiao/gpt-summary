Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The first thing is to recognize the file path: `go/src/cmd/compile/internal/dwarfgen/dwinl.go`. This immediately tells us we're dealing with the Go compiler (`cmd/compile`), specifically the part responsible for generating DWARF debugging information (`dwarfgen`), and even more specifically, something related to inlined functions (`dwinl`). The comments at the top reinforce this.

2. **Identify Key Data Structures:**  Scan the code for type definitions and important variables. The `varPos` struct is clearly about tracking the original location of variables. The `assembleInlines` function returns a `dwarf.InlCalls`, suggesting this is the central data structure for representing inlined call information. Looking at the `dwarf` package import would be the next step to understand the structure of `dwarf.InlCalls` and `dwarf.Var`. (Even without looking up `dwarf.InlCalls` immediately, the code suggests it's a collection of inlined calls.)

3. **Analyze the Main Function: `assembleInlines`:** This is the core of the provided code. Break it down step-by-step:

    * **Initialization:**  It initializes `inlcalls` and `imap`. The comment about `imap` mapping inline index to `inlcalls.Calls` index is crucial.
    * **First Pass (Progs):** The code iterates through `fnsym.Func().Text`. This strongly indicates it's processing the compiled instructions (progs) of a function. The `posInlIndex` function suggests it's trying to find out if a particular instruction's source position corresponds to an inlined function call. `insertInlCall` is used to build the `inlcalls` structure.
    * **Second Pass (DWARF Vars):** The code iterates through `dwVars`. The comment indicates this is partitioning variables based on whether they were introduced by inlining. The logic for handling `dwv.InlIndex == 0` and `dwv.InlIndex > 0` is key to understanding how variables are associated with their inlined context.
    * **Third Pass (Assigning Child Indices):** The loop over `vmap` handles assigning `ChildIndex` to variables. The logic differs based on whether the variable is from the top-level function or an inlined function. The call to `makePreinlineDclMap` is important; it suggests retrieving information about the variables before inlining.
    * **Fourth Pass (PC Ranges):** The code iterates through the progs again, this time to determine the PC ranges for each inlined call. The `addRange` function is used to store these ranges.
    * **Unifying Ranges:** The loop involving `unifyCallRanges` aims to ensure parent inlines encompass the ranges of their children.
    * **Consistency Check:** `checkInlCall` verifies the integrity of the calculated PC ranges.
    * **Return:** Finally, the assembled `inlcalls` structure is returned.

4. **Identify Supporting Functions:** Look at the other functions and their roles:

    * `AbstractFunc`: Deals with generating DWARF information for *imported* inlined functions. The "precursor function" concept is important here.
    * `makePreinlineDclMap`: As the name suggests, it creates a map of variables declared before inlining, using their position and name as keys.
    * `insertInlCall`:  Adds a new inlined call entry to the `inlcalls` structure, handling parent-child relationships.
    * `posInlIndex`: Determines the inlining index associated with a given source position.
    * `addRange`: Adds a PC range to a specific inlined call.
    * `dumpInlCall`, `dumpInlCalls`, `dumpInlVars`: Debugging functions to print the collected information.
    * `rangesContains`, `rangesContainsAll`: Utility functions for checking if PC ranges are contained within other ranges.
    * `checkInlCall`:  Verifies the consistency of the inlined call ranges.
    * `unifyCallRanges`:  Merges PC ranges to ensure parent inlines include their children's ranges.

5. **Infer Functionality:** Based on the code structure, comments, and function names, the core functionality becomes clear: this code is responsible for collecting information about inlined function calls within a Go function during compilation. This information is then used to generate DWARF debugging information that allows debuggers to step through inlined code as if it were not inlined.

6. **Connect to Go Features:**  The "inlined subroutine" concept directly maps to Go's function inlining optimization. The code is clearly working to provide debugging support for this optimization.

7. **Construct Examples:** Now, think about how inlining works and how the debugger needs to represent it. A simple example with one level of inlining is good to start with. A more complex example with nested inlining helps illustrate the hierarchical structure managed by the code.

8. **Consider Command-Line Flags:** The `base.Debug.DwarfInl` check suggests a debug flag. Researching or knowing about Go compiler flags would reveal that this flag controls the output of DWARF inlining information for debugging.

9. **Identify Potential Mistakes:** Think about common issues with inlining and debugging. The code itself has consistency checks, which provide clues about potential problems (e.g., incorrect PC ranges). The interaction between the inliner and the debugger can sometimes be tricky. Variables optimized away or moved around by inlining are a potential source of confusion.

10. **Refine and Organize:** Finally, organize the findings into a clear and structured answer, covering the requested points (functionality, Go feature, code example, command-line arguments, common mistakes).

This systematic approach, starting with understanding the overall purpose and progressively digging into the details, is key to deciphering complex code like this. Understanding the context (Go compiler, DWARF) is also crucial.
这段代码是 Go 编译器的一部分，位于 `go/src/cmd/compile/internal/dwarfgen/dwinl.go`，其主要功能是**收集和组织用于生成 DWARF 调试信息的内联函数调用 (inlined subroutine) 数据**。

更具体地说，它实现了以下功能：

1. **识别和记录内联函数调用:**  它遍历函数的指令流 (`fnsym.Func().Text`)，利用 `posInlIndex` 函数判断当前指令是否位于内联函数调用的上下文中。
2. **构建内联调用树:** 它使用 `insertInlCall` 函数构建一个树状结构 (`dwarf.InlCalls`) 来表示内联函数的调用关系，包括父子关系。
3. **关联变量与内联调用:** 它将函数中的变量 (`dwVars`) 分配给它们所属的内联调用。如果变量是在内联过程中产生的，则会关联到相应的内联调用；否则，它会被认为是顶层函数的变量。
4. **计算内联调用的 PC 范围:** 它再次遍历指令流，计算每个内联函数调用在原始函数代码中的程序计数器 (PC) 范围。
5. **处理抽象函数:**  `AbstractFunc` 函数处理从其他包导入的内联函数的 DWARF 信息。
6. **处理预内联声明:** `makePreinlineDclMap` 函数用于创建内联前函数局部变量的映射，以便在生成 DWARF 信息时正确地关联变量。
7. **进行一致性检查:** 它会检查生成的内联调用信息的 PC 范围是否正确嵌套，防止出现错误。
8. **统一 PC 范围:** `unifyCallRanges` 函数确保父内联调用的 PC 范围包含其所有子内联调用的 PC 范围。
9. **提供调试输出:** 在 `base.Debug.DwarfInl != 0` 时，会输出详细的内联调用和变量信息，用于调试。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言**函数内联 (function inlining)** 功能的调试信息生成部分。函数内联是一种编译器优化技术，它将一个函数的调用位置替换为被调用函数的代码，以减少函数调用开销。为了让调试器能够理解内联后的代码，并允许开发者像调试未内联的代码一样进行调试，编译器需要生成额外的 DWARF 信息来描述内联发生的位置和上下文。

**Go 代码举例说明:**

假设我们有以下 Go 代码：

```go
package main

func add(a, b int) int {
	return a + b
}

func calculate(x int) int {
	y := 5
	return add(x, y) * 2
}

func main() {
	result := calculate(10)
	println(result)
}
```

在编译时，如果编译器决定内联 `add` 函数到 `calculate` 函数中，那么 `calculate` 函数的实际执行代码可能看起来像这样（简化表示）：

```
func calculate(x int) int {
	y := 5
	// 内联 add(x, y)
	temp := x + y
	return temp * 2
}
```

`dwinl.go` 中的代码负责生成 DWARF 信息，告诉调试器：

* `add` 函数被内联到 `calculate` 函数中。
* 内联发生的调用位置在 `calculate` 函数的哪个源代码行。
* 内联函数的局部变量（例如 `add` 函数中的参数 `a` 和 `b`）在内联后的上下文中的位置和值。

**假设的输入与输出 (代码推理):**

假设编译上述代码，并且 `add` 函数被内联到 `calculate` 中。`assembleInlines` 函数的输入 `fnsym` 是 `calculate` 函数的符号信息，`dwVars` 是 `calculate` 函数的变量信息 (包括 `x`, `y`, 和可能的临时变量)。

**输入 (部分假设):**

* `fnsym`: 代表 `calculate` 函数的 `obj.LSym`。
* `dwVars`: 一个包含 `calculate` 函数局部变量的 `dwarf.Var` 切片，例如：
    * `{Name: "x", InlIndex: 0, ...}` (表示 `x` 是 `calculate` 函数自身的变量)
    * `{Name: "y", InlIndex: 0, ...}` (表示 `y` 是 `calculate` 函数自身的变量)
    * 如果编译器为内联的 `add` 生成了调试信息，可能会有类似以下的条目：
        * `{Name: "a", InlIndex: 1, ...}` (表示 `add` 的参数 `a`，`InlIndex: 1` 可能表示第一次内联调用)
        * `{Name: "b", InlIndex: 1, ...}` (表示 `add` 的参数 `b`)

**输出 (部分推理):**

`assembleInlines` 函数会返回一个 `dwarf.InlCalls` 结构，它可能包含如下信息：

```
dwarf.InlCalls{
	Calls: []dwarf.InlCall{
		{
			InlIndex:  0, // 假设 calculate 函数本身没有被内联
			CallPos:   /* calculate 函数的起始位置 */,
			AbsFunSym: /* calculate 函数的抽象符号 */,
			Root:      true,
			Children:  []int{1}, // 指向第一个内联调用
			Ranges:    []dwarf.Range{ /* calculate 函数的 PC 范围 */ },
			InlVars:   []*dwarf.Var{/* calculate 函数的变量 x, y */},
		},
		{
			InlIndex:  1, // 代表 add 函数的内联调用
			CallPos:   /* 调用 add 函数的位置 */,
			AbsFunSym: /* add 函数的抽象符号 */,
			Root:      false,
			Children:  nil,
			Ranges:    []dwarf.Range{ /* add 函数内联代码的 PC 范围 */ },
			InlVars:   []*dwarf.Var{/* add 函数的参数 a, b */},
		},
	},
}
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。然而，它使用了 `base.Debug.DwarfInl` 这个变量来控制调试信息的输出。`base.Debug` 中的变量通常由 Go 编译器的命令行参数 `-gcflags` 传递的 `-dwarf` 选项来设置。

例如，使用以下命令编译上面的代码，可以启用 DWARF 内联信息的调试输出：

```bash
go build -gcflags="-dwarf=2" main.go
```

或者更具体地控制内联调试信息：

```bash
go build -gcflags="-dwarfinl=1" main.go
```

这里 `-dwarf=2` 或 `-dwarfinl=1` 会设置 `base.Debug.DwarfInl` 的值，从而激活 `dumpInlCalls` 和 `dumpInlVars` 等调试输出。

**使用者易犯错的点:**

这段代码是 Go 编译器内部实现的一部分，普通 Go 开发者不会直接使用或修改它。 然而，对于理解 Go 编译器的开发者来说，容易犯错的点可能包括：

1. **对 `InlIndex` 的理解:** `InlIndex` 是编译器内部用于标识内联调用的索引，与源代码中的调用顺序不一定直接对应。理解其含义需要深入了解编译器的内联过程。
2. **`ChildIndex` 的计算逻辑:**  理解变量的 `ChildIndex` 如何根据是否被内联以及在抽象函数中的位置计算是复杂的。`makePreinlineDclMap` 的作用至关重要。
3. **PC 范围的计算和统一:**  准确计算内联代码的 PC 范围并确保父子范围的正确包含关系是容易出错的地方。`unifyCallRanges` 和 `checkInlCall` 旨在解决这些问题。
4. **抽象函数的概念:** 理解何时以及如何使用抽象函数来表示内联函数的元信息对于理解 DWARF 的生成至关重要。 `AbstractFunc` 的作用需要清晰认识。

总而言之，`dwinl.go` 是 Go 编译器中一个关键的组成部分，它负责为内联函数生成必要的调试信息，使得开发者能够像调试普通函数一样调试内联后的代码。理解其功能需要对 Go 编译器的内联优化和 DWARF 调试信息格式有一定的了解。

### 提示词
```
这是路径为go/src/cmd/compile/internal/dwarfgen/dwinl.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dwarfgen

import (
	"fmt"
	"strings"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/internal/dwarf"
	"cmd/internal/obj"
	"cmd/internal/src"
)

// To identify variables by original source position.
type varPos struct {
	DeclName string
	DeclFile string
	DeclLine uint
	DeclCol  uint
}

// This is the main entry point for collection of raw material to
// drive generation of DWARF "inlined subroutine" DIEs. See proposal
// 22080 for more details and background info.
func assembleInlines(fnsym *obj.LSym, dwVars []*dwarf.Var) dwarf.InlCalls {
	var inlcalls dwarf.InlCalls

	if base.Debug.DwarfInl != 0 {
		base.Ctxt.Logf("assembling DWARF inlined routine info for %v\n", fnsym.Name)
	}

	// This maps inline index (from Ctxt.InlTree) to index in inlcalls.Calls
	imap := make(map[int]int)

	// Walk progs to build up the InlCalls data structure
	var prevpos src.XPos
	for p := fnsym.Func().Text; p != nil; p = p.Link {
		if p.Pos == prevpos {
			continue
		}
		ii := posInlIndex(p.Pos)
		if ii >= 0 {
			insertInlCall(&inlcalls, ii, imap)
		}
		prevpos = p.Pos
	}

	// This is used to partition DWARF vars by inline index. Vars not
	// produced by the inliner will wind up in the vmap[0] entry.
	vmap := make(map[int32][]*dwarf.Var)

	// Now walk the dwarf vars and partition them based on whether they
	// were produced by the inliner (dwv.InlIndex > 0) or were original
	// vars/params from the function (dwv.InlIndex == 0).
	for _, dwv := range dwVars {

		vmap[dwv.InlIndex] = append(vmap[dwv.InlIndex], dwv)

		// Zero index => var was not produced by an inline
		if dwv.InlIndex == 0 {
			continue
		}

		// Look up index in our map, then tack the var in question
		// onto the vars list for the correct inlined call.
		ii := int(dwv.InlIndex) - 1
		idx, ok := imap[ii]
		if !ok {
			// We can occasionally encounter a var produced by the
			// inliner for which there is no remaining prog; add a new
			// entry to the call list in this scenario.
			idx = insertInlCall(&inlcalls, ii, imap)
		}
		inlcalls.Calls[idx].InlVars =
			append(inlcalls.Calls[idx].InlVars, dwv)
	}

	// Post process the map above to assign child indices to vars.
	//
	// A given variable is treated differently depending on whether it
	// is part of the top-level function (ii == 0) or if it was
	// produced as a result of an inline (ii != 0).
	//
	// If a variable was not produced by an inline and its containing
	// function was not inlined, then we just assign an ordering of
	// based on variable name.
	//
	// If a variable was not produced by an inline and its containing
	// function was inlined, then we need to assign a child index
	// based on the order of vars in the abstract function (in
	// addition, those vars that don't appear in the abstract
	// function, such as "~r1", are flagged as such).
	//
	// If a variable was produced by an inline, then we locate it in
	// the pre-inlining decls for the target function and assign child
	// index accordingly.
	for ii, sl := range vmap {
		var m map[varPos]int
		if ii == 0 {
			if !fnsym.WasInlined() {
				for j, v := range sl {
					v.ChildIndex = int32(j)
				}
				continue
			}
			m = makePreinlineDclMap(fnsym)
		} else {
			ifnlsym := base.Ctxt.InlTree.InlinedFunction(int(ii - 1))
			m = makePreinlineDclMap(ifnlsym)
		}

		// Here we assign child indices to variables based on
		// pre-inlined decls, and set the "IsInAbstract" flag
		// appropriately. In addition: parameter and local variable
		// names are given "middle dot" version numbers as part of the
		// writing them out to export data (see issue 4326). If DWARF
		// inlined routine generation is turned on, we want to undo
		// this versioning, since DWARF variables in question will be
		// parented by the inlined routine and not the top-level
		// caller.
		synthCount := len(m)
		for _, v := range sl {
			vp := varPos{
				DeclName: v.Name,
				DeclFile: v.DeclFile,
				DeclLine: v.DeclLine,
				DeclCol:  v.DeclCol,
			}
			synthesized := strings.HasPrefix(v.Name, "~") || v.Name == "_"
			if idx, found := m[vp]; found {
				v.ChildIndex = int32(idx)
				v.IsInAbstract = !synthesized
			} else {
				// Variable can't be found in the pre-inline dcl list.
				// In the top-level case (ii=0) this can happen
				// because a composite variable was split into pieces,
				// and we're looking at a piece. We can also see
				// return temps (~r%d) that were created during
				// lowering, or unnamed params ("_").
				v.ChildIndex = int32(synthCount)
				synthCount++
			}
		}
	}

	// Make a second pass through the progs to compute PC ranges for
	// the various inlined calls.
	start := int64(-1)
	curii := -1
	var prevp *obj.Prog
	for p := fnsym.Func().Text; p != nil; prevp, p = p, p.Link {
		if prevp != nil && p.Pos == prevp.Pos {
			continue
		}
		ii := posInlIndex(p.Pos)
		if ii == curii {
			continue
		}
		// Close out the current range
		if start != -1 {
			addRange(inlcalls.Calls, start, p.Pc, curii, imap)
		}
		// Begin new range
		start = p.Pc
		curii = ii
	}
	if start != -1 {
		addRange(inlcalls.Calls, start, fnsym.Size, curii, imap)
	}

	// Issue 33188: if II foo is a child of II bar, then ensure that
	// bar's ranges include the ranges of foo (the loop above will produce
	// disjoint ranges).
	for k, c := range inlcalls.Calls {
		if c.Root {
			unifyCallRanges(inlcalls, k)
		}
	}

	// Debugging
	if base.Debug.DwarfInl != 0 {
		dumpInlCalls(inlcalls)
		dumpInlVars(dwVars)
	}

	// Perform a consistency check on inlined routine PC ranges
	// produced by unifyCallRanges above. In particular, complain in
	// cases where you have A -> B -> C (e.g. C is inlined into B, and
	// B is inlined into A) and the ranges for B are not enclosed
	// within the ranges for A, or C within B.
	for k, c := range inlcalls.Calls {
		if c.Root {
			checkInlCall(fnsym.Name, inlcalls, fnsym.Size, k, -1)
		}
	}

	return inlcalls
}

// Secondary hook for DWARF inlined subroutine generation. This is called
// late in the compilation when it is determined that we need an
// abstract function DIE for an inlined routine imported from a
// previously compiled package.
func AbstractFunc(fn *obj.LSym) {
	ifn := base.Ctxt.DwFixups.GetPrecursorFunc(fn)
	if ifn == nil {
		base.Ctxt.Diag("failed to locate precursor fn for %v", fn)
		return
	}
	_ = ifn.(*ir.Func)
	if base.Debug.DwarfInl != 0 {
		base.Ctxt.Logf("DwarfAbstractFunc(%v)\n", fn.Name)
	}
	base.Ctxt.DwarfAbstractFunc(ifn, fn)
}

// Given a function that was inlined as part of the compilation, dig
// up the pre-inlining DCL list for the function and create a map that
// supports lookup of pre-inline dcl index, based on variable
// position/name. NB: the recipe for computing variable pos/file/line
// needs to be kept in sync with the similar code in gc.createSimpleVars
// and related functions.
func makePreinlineDclMap(fnsym *obj.LSym) map[varPos]int {
	dcl := preInliningDcls(fnsym)
	m := make(map[varPos]int)
	for i, n := range dcl {
		pos := base.Ctxt.InnermostPos(n.Pos())
		vp := varPos{
			DeclName: n.Sym().Name,
			DeclFile: pos.RelFilename(),
			DeclLine: pos.RelLine(),
			DeclCol:  pos.RelCol(),
		}
		if _, found := m[vp]; found {
			// We can see collisions (variables with the same name/file/line/col) in obfuscated or machine-generated code -- see issue 44378 for an example. Skip duplicates in such cases, since it is unlikely that a human will be debugging such code.
			continue
		}
		m[vp] = i
	}
	return m
}

func insertInlCall(dwcalls *dwarf.InlCalls, inlIdx int, imap map[int]int) int {
	callIdx, found := imap[inlIdx]
	if found {
		return callIdx
	}

	// Haven't seen this inline yet. Visit parent of inline if there
	// is one. We do this first so that parents appear before their
	// children in the resulting table.
	parCallIdx := -1
	parInlIdx := base.Ctxt.InlTree.Parent(inlIdx)
	if parInlIdx >= 0 {
		parCallIdx = insertInlCall(dwcalls, parInlIdx, imap)
	}

	// Create new entry for this inline
	inlinedFn := base.Ctxt.InlTree.InlinedFunction(inlIdx)
	callXPos := base.Ctxt.InlTree.CallPos(inlIdx)
	callPos := base.Ctxt.InnermostPos(callXPos)
	absFnSym := base.Ctxt.DwFixups.AbsFuncDwarfSym(inlinedFn)
	ic := dwarf.InlCall{
		InlIndex:  inlIdx,
		CallPos:   callPos,
		AbsFunSym: absFnSym,
		Root:      parCallIdx == -1,
	}
	dwcalls.Calls = append(dwcalls.Calls, ic)
	callIdx = len(dwcalls.Calls) - 1
	imap[inlIdx] = callIdx

	if parCallIdx != -1 {
		// Add this inline to parent's child list
		dwcalls.Calls[parCallIdx].Children = append(dwcalls.Calls[parCallIdx].Children, callIdx)
	}

	return callIdx
}

// Given a src.XPos, return its associated inlining index if it
// corresponds to something created as a result of an inline, or -1 if
// there is no inline info. Note that the index returned will refer to
// the deepest call in the inlined stack, e.g. if you have "A calls B
// calls C calls D" and all three callees are inlined (B, C, and D),
// the index for a node from the inlined body of D will refer to the
// call to D from C. Whew.
func posInlIndex(xpos src.XPos) int {
	pos := base.Ctxt.PosTable.Pos(xpos)
	if b := pos.Base(); b != nil {
		ii := b.InliningIndex()
		if ii >= 0 {
			return ii
		}
	}
	return -1
}

func addRange(calls []dwarf.InlCall, start, end int64, ii int, imap map[int]int) {
	if start == -1 {
		panic("bad range start")
	}
	if end == -1 {
		panic("bad range end")
	}
	if ii == -1 {
		return
	}
	if start == end {
		return
	}
	// Append range to correct inlined call
	callIdx, found := imap[ii]
	if !found {
		base.Fatalf("can't find inlIndex %d in imap for prog at %d\n", ii, start)
	}
	call := &calls[callIdx]
	call.Ranges = append(call.Ranges, dwarf.Range{Start: start, End: end})
}

func dumpInlCall(inlcalls dwarf.InlCalls, idx, ilevel int) {
	for i := 0; i < ilevel; i++ {
		base.Ctxt.Logf("  ")
	}
	ic := inlcalls.Calls[idx]
	callee := base.Ctxt.InlTree.InlinedFunction(ic.InlIndex)
	base.Ctxt.Logf("  %d: II:%d (%s) V: (", idx, ic.InlIndex, callee.Name)
	for _, f := range ic.InlVars {
		base.Ctxt.Logf(" %v", f.Name)
	}
	base.Ctxt.Logf(" ) C: (")
	for _, k := range ic.Children {
		base.Ctxt.Logf(" %v", k)
	}
	base.Ctxt.Logf(" ) R:")
	for _, r := range ic.Ranges {
		base.Ctxt.Logf(" [%d,%d)", r.Start, r.End)
	}
	base.Ctxt.Logf("\n")
	for _, k := range ic.Children {
		dumpInlCall(inlcalls, k, ilevel+1)
	}

}

func dumpInlCalls(inlcalls dwarf.InlCalls) {
	for k, c := range inlcalls.Calls {
		if c.Root {
			dumpInlCall(inlcalls, k, 0)
		}
	}
}

func dumpInlVars(dwvars []*dwarf.Var) {
	for i, dwv := range dwvars {
		typ := "local"
		if dwv.Tag == dwarf.DW_TAG_formal_parameter {
			typ = "param"
		}
		ia := 0
		if dwv.IsInAbstract {
			ia = 1
		}
		base.Ctxt.Logf("V%d: %s CI:%d II:%d IA:%d %s\n", i, dwv.Name, dwv.ChildIndex, dwv.InlIndex-1, ia, typ)
	}
}

func rangesContains(par []dwarf.Range, rng dwarf.Range) (bool, string) {
	for _, r := range par {
		if rng.Start >= r.Start && rng.End <= r.End {
			return true, ""
		}
	}
	msg := fmt.Sprintf("range [%d,%d) not contained in {", rng.Start, rng.End)
	for _, r := range par {
		msg += fmt.Sprintf(" [%d,%d)", r.Start, r.End)
	}
	msg += " }"
	return false, msg
}

func rangesContainsAll(parent, child []dwarf.Range) (bool, string) {
	for _, r := range child {
		c, m := rangesContains(parent, r)
		if !c {
			return false, m
		}
	}
	return true, ""
}

// checkInlCall verifies that the PC ranges for inline info 'idx' are
// enclosed/contained within the ranges of its parent inline (or if
// this is a root/toplevel inline, checks that the ranges fall within
// the extent of the top level function). A panic is issued if a
// malformed range is found.
func checkInlCall(funcName string, inlCalls dwarf.InlCalls, funcSize int64, idx, parentIdx int) {

	// Callee
	ic := inlCalls.Calls[idx]
	callee := base.Ctxt.InlTree.InlinedFunction(ic.InlIndex).Name
	calleeRanges := ic.Ranges

	// Caller
	caller := funcName
	parentRanges := []dwarf.Range{dwarf.Range{Start: int64(0), End: funcSize}}
	if parentIdx != -1 {
		pic := inlCalls.Calls[parentIdx]
		caller = base.Ctxt.InlTree.InlinedFunction(pic.InlIndex).Name
		parentRanges = pic.Ranges
	}

	// Callee ranges contained in caller ranges?
	c, m := rangesContainsAll(parentRanges, calleeRanges)
	if !c {
		base.Fatalf("** malformed inlined routine range in %s: caller %s callee %s II=%d %s\n", funcName, caller, callee, idx, m)
	}

	// Now visit kids
	for _, k := range ic.Children {
		checkInlCall(funcName, inlCalls, funcSize, k, idx)
	}
}

// unifyCallRanges ensures that the ranges for a given inline
// transitively include all of the ranges for its child inlines.
func unifyCallRanges(inlcalls dwarf.InlCalls, idx int) {
	ic := &inlcalls.Calls[idx]
	for _, childIdx := range ic.Children {
		// First make sure child ranges are unified.
		unifyCallRanges(inlcalls, childIdx)

		// Then merge child ranges into ranges for this inline.
		cic := inlcalls.Calls[childIdx]
		ic.Ranges = dwarf.MergeRanges(ic.Ranges, cic.Ranges)
	}
}
```