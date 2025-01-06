Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The first step is to understand the overarching goal of the code. Looking at the package name (`inlheur`), type names like `callSiteAnalyzer`, `callSiteTableBuilder`, and function names like `computeCallSiteTable`, `addCallSite`, `UpdateCallsiteTable` strongly suggest this code is related to *inlining heuristics* and the analysis of *call sites* within a Go function.

2. **Analyze Key Data Structures:**  The next step is to examine the primary data structures involved:

    * `callSiteAnalyzer`:  Seems like a basic helper to analyze function calls. The `nameFinder` member suggests it also deals with identifying names and symbols.
    * `callSiteTableBuilder`: This appears to be the core worker. It builds a `CallSiteTab`. The presence of `ptab` (likely "panic table"), `nstack` (likely "node stack"), and `loopNest` suggests it tracks context during traversal.
    * `CallSiteTab`:  A map, probably storing information about each call site.
    * `CallSite`: A struct (not shown in the snippet, but its usage is clear) that holds details about a call site. The fields like `Call`, `Callee`, `Assign`, `ArgProps`, `Flags`, `ID`, and `Score` are key.
    * `CSPropBits`, `ActualExprPropBits`: Likely bitmasks representing properties of call sites and argument expressions.

3. **Trace the Workflow (Major Functions):**  Focus on the main functions and how they interact:

    * `makeCallSiteAnalyzer`, `makeCallSiteTableBuilder`:  These are constructors.
    * `computeCallSiteTable`: This seems to be the entry point for analyzing a region of code. It creates a `callSiteTableBuilder` and then traverses the provided `region` (AST nodes). The use of `doNode` with `ir.DoChildren` confirms an AST traversal.
    * `flagsForNode`: Determines certain flags for a call site, like whether it's inside a loop or an init function, and whether it's on a potential panic path.
    * `determinePanicPathBits`: This function is crucial. It walks *up* the `nstack` to see if an ancestor node is a `PANIC` or a node known to lead to panic. This is a key insight into the code's functionality.
    * `propsForArg`: Analyzes properties of call arguments (constant, concrete interface conversion, inlinable function, etc.).
    * `argPropsForCall`: Collects the argument properties for a call.
    * `addCallSite`: Creates a `CallSite` object and adds it to the `cstab`.
    * `nodeVisitPre`, `nodeVisitPost`: These are callback functions used during the AST traversal. They manage the `nstack` and update the `loopNest` counter. `nodeVisitPre` is where `addCallSite` is called for function calls.
    * `loopBody`, `hasTopLevelLoopBodyReturnOrBreak`: These functions help distinguish between "real" loops and syntactically similar constructs that don't iterate.
    * `containingAssignment`:  Tries to find the assignment statement where the result of a function call is used.
    * `UpdateCallsiteTable`:  Crucial for handling inlining. It updates the caller's call site table after a function has been inlined.

4. **Infer the Go Feature:** Based on the function names, the handling of call sites, inlining, and the context of the `cmd/compile` package, it's highly probable that this code is part of the **Go inlining optimization**. The analysis of call sites, determination of panic paths, and updating the call site table after inlining are all key aspects of this optimization.

5. **Construct Go Examples:** Now, create simple Go code examples that would exercise the functionalities observed in the code. This involves creating calls within loops, init functions, and on potential panic paths. The multi-return assignment example directly reflects the logic in `containingAssignment`.

6. **Hypothesize Inputs and Outputs:** For the code examples, think about what the `CallSite` objects might look like after analysis. Focus on the `Flags` and `ArgProps` fields, which are actively being set in the provided code.

7. **Analyze Command-Line Arguments (if applicable):**  While the snippet itself doesn't directly handle command-line arguments, the presence of `debugTrace` and the `enableDebugTraceIfEnv` function hint at a debugging mechanism potentially controlled by environment variables or build tags. Mention this possibility.

8. **Identify Potential Pitfalls:**  Think about areas where the logic might be subtle or error-prone. The distinction between "real" loops and those with early returns, and the handling of complex assignment scenarios in `containingAssignment`, are good candidates. Illustrate these with examples.

9. **Structure the Explanation:** Organize the findings logically, starting with the main functionality, then providing code examples, explanations of specific functions, input/output examples, and finally the potential pitfalls. Use clear and concise language.

10. **Refine and Iterate:** Review the explanation for clarity, accuracy, and completeness. Make sure the code examples accurately demonstrate the functionality being described. For instance, initially, I might not have focused enough on the panic path analysis, but upon closer inspection of `determinePanicPathBits`, its importance becomes clear. Similarly, understanding the purpose of `hasTopLevelLoopBodyReturnOrBreak` requires carefully reading the comments.这段代码是 Go 编译器 `cmd/compile/internal/inline/inlheur` 包的一部分，主要功能是**分析函数调用点 (call sites)**，并为这些调用点计算和存储一些属性信息，用于后续的内联优化决策。

更具体地说，它实现了以下功能：

1. **识别函数中的所有调用点:**  通过遍历函数的抽象语法树 (AST)，找到所有的函数调用表达式 (`ir.OCALLFUNC`)。
2. **收集调用点的属性:**  为每个调用点计算一些有用的属性，例如：
    * **是否在循环中 (`CallSiteInLoop`):**  判断调用是否发生在 `for` 或 `range` 循环内部。
    * **是否在 `init` 函数中 (`CallSiteInInitFunc`):** 判断调用是否发生在包的 `init` 函数中。
    * **是否在 panic 路径上 (`CallSiteOnPanicPath`):**  通过向上遍历 AST，判断调用是否位于一个必然导致 `panic` 或 `exit` 的代码路径上。
    * **参数的属性 (`ActualExprPropBits`):**  分析调用参数的类型，例如是否是常量、是否是接口类型的转换、是否是可内联的函数等。
3. **构建调用点表格 (`CallSiteTab`):**  将收集到的调用点及其属性信息存储在一个表格中，方便后续查询和使用。
4. **支持内联后的调用点更新 (`UpdateCallsiteTable`):** 当一个函数被内联到调用方后，需要更新调用方的调用点表格，将内联函数体内的调用点添加到调用方的表格中，并继承一些父调用的属性。

**它是什么 Go 语言功能的实现？**

这段代码是 **Go 编译器内联优化 (inlining optimization)** 的一部分。内联是一种编译器优化技术，它将一个函数的函数体插入到调用该函数的地方，从而避免函数调用的开销。`inlheur` 包（"inlining heuristics" 的缩写）负责制定内联决策，而 `analyze_func_callsites.go` 负责收集关于函数调用点的关键信息，这些信息会被用于评估内联的收益和风险。

**Go 代码举例说明:**

```go
package main

func add(a, b int) int {
	return a + b
}

func process(x int) {
	if x < 0 {
		panic("negative input")
	}
	result := add(x, 10) // 这里是一个调用点
	println(result)
}

func main() {
	for i := 0; i < 5; i++ {
		process(i) // 这里也是一个调用点，且在循环中
	}
}

func init() {
	println("initializing")
	add(1, 2) // 这里是一个调用点，且在 init 函数中
}
```

**假设输入与输出:**

假设我们分析 `process` 函数。

**输入 (部分 AST 结构):**

```
OFUNC (process) {
  ODCL (x param int)
  OIF (x < 0) {
    OPANIC ("negative input")
  }
  OAS (result) = OCALLFUNC (add(x, 10)) // 关注这个调用点
  OPRINTLN (result)
}
```

**输出 (针对 `add(x, 10)` 这个调用点):**

根据 `analyze_func_callsites.go` 的逻辑，可能会生成如下 `CallSite` 信息：

* `Call`: 指向 `add(x, 10)` 这个 `ir.CallExpr` 节点。
* `Callee`: 指向 `add` 函数的 `ir.Func` 节点。
* `Assign`: 指向 `result := add(x, 10)` 这个赋值语句的 `ir.AssignStmt` 节点。
* `ArgProps`:  `[]ActualExprPropBits{0, ActualExprConstant}`  (假设 `10` 被识别为常量)。
* `Flags`:  可能为 `0` (取决于 `process` 函数是否在循环或 `init` 函数中被调用，以及 panic 路径分析的结果)。如果 `process` 函数本身在 `main` 函数的循环中被调用，则 `Flags` 会包含 `CallSiteInLoop`。

**假设我们分析 `main` 函数中调用的 `process(i)`：**

* `Call`: 指向 `process(i)` 这个 `ir.CallExpr` 节点。
* `Callee`: 指向 `process` 函数的 `ir.Func` 节点。
* `Assign`:  `nil` (因为调用结果没有被赋值给变量)。
* `ArgProps`: `[]ActualExprPropBits{}` (假设 `i` 不是特殊类型的表达式)。
* `Flags`: 会包含 `CallSiteInLoop`。

**假设我们分析 `init` 函数中调用的 `add(1, 2)`：**

* `Flags`: 会包含 `CallSiteInInitFunc`。

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数。但是，它使用了 `debugTrace` 变量，这很可能是一个全局变量，可以通过编译器构建时的 tag 或者环境变量来控制，以开启或关闭调试输出。例如，可能存在一个构建 tag 或者环境变量，当设置后，`debugTrace&debugTraceCalls != 0` 的条件成立，从而输出更详细的调用点分析信息到标准错误流。

**使用者易犯错的点:**

作为 Go 编译器的开发者，在使用或理解这段代码时，容易犯错的点可能包括：

1. **对 `panic` 路径的误判:** `determinePanicPathBits` 的逻辑依赖于对 AST 结构的分析，对于复杂的控制流 (例如包含 `goto`)，可能会出现误判，将不在 `panic` 路径上的调用标记为在 `panic` 路径上，或者反之。
   * **例子:** 如果代码中使用了 `goto` 跳转到一个 `panic` 语句，但 `goto` 的条件很复杂，静态分析可能无法准确判断该调用是否在 `panic` 路径上。

2. **对循环的识别不准确:** `hasTopLevelLoopBodyReturnOrBreak` 函数用于区分真正的循环和只执行一次就返回或退出的 "伪循环"。如果循环体内部的控制流非常复杂，例如使用了 `goto` 跳出循环，这个函数可能无法正确判断。
   * **例子:**
     ```go
     for {
         if someCondition() {
             goto endLoop
         }
         // ... loop body ...
     }
     endLoop:
     ```
     在这种情况下，`hasTopLevelLoopBodyReturnOrBreak` 会返回 `false`，但实际上这仍然是一个可能多次迭代的循环。

3. **对包含赋值语句的调用点的理解:**  `containingAssignment` 函数旨在找到包含函数调用的顶级赋值语句。对于多返回值的情况，它需要处理一些特殊情况 (例如赋值给 auto-temps)。如果 AST 的结构发生变化，这个函数的逻辑可能需要更新，否则可能会找不到正确的赋值语句。

4. **对内联后调用点更新的理解:** `UpdateCallsiteTable` 的逻辑比较复杂，需要正确地将内联函数体内的调用点添加到调用方的表格中，并继承正确的属性。如果对父调用点的属性 (例如 `CallSiteOnPanicPath`, `CallSiteInLoop`) 的传递或处理有误，可能会导致内联决策错误。

总而言之，这段代码是 Go 编译器内联优化中的一个关键组成部分，它通过静态分析函数的 AST 结构，收集函数调用点的各种属性信息，为后续的内联决策提供依据。理解这段代码需要对 Go 编译器的内部表示 (AST) 和内联优化的原理有一定的了解。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/inline/inlheur/analyze_func_callsites.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package inlheur

import (
	"cmd/compile/internal/ir"
	"cmd/compile/internal/pgoir"
	"cmd/compile/internal/typecheck"
	"fmt"
	"os"
	"strings"
)

type callSiteAnalyzer struct {
	fn *ir.Func
	*nameFinder
}

type callSiteTableBuilder struct {
	fn *ir.Func
	*nameFinder
	cstab    CallSiteTab
	ptab     map[ir.Node]pstate
	nstack   []ir.Node
	loopNest int
	isInit   bool
}

func makeCallSiteAnalyzer(fn *ir.Func) *callSiteAnalyzer {
	return &callSiteAnalyzer{
		fn:         fn,
		nameFinder: newNameFinder(fn),
	}
}

func makeCallSiteTableBuilder(fn *ir.Func, cstab CallSiteTab, ptab map[ir.Node]pstate, loopNestingLevel int, nf *nameFinder) *callSiteTableBuilder {
	isInit := fn.IsPackageInit() || strings.HasPrefix(fn.Sym().Name, "init.")
	return &callSiteTableBuilder{
		fn:         fn,
		cstab:      cstab,
		ptab:       ptab,
		isInit:     isInit,
		loopNest:   loopNestingLevel,
		nstack:     []ir.Node{fn},
		nameFinder: nf,
	}
}

// computeCallSiteTable builds and returns a table of call sites for
// the specified region in function fn. A region here corresponds to a
// specific subtree within the AST for a function. The main intended
// use cases are for 'region' to be either A) an entire function body,
// or B) an inlined call expression.
func computeCallSiteTable(fn *ir.Func, region ir.Nodes, cstab CallSiteTab, ptab map[ir.Node]pstate, loopNestingLevel int, nf *nameFinder) CallSiteTab {
	cstb := makeCallSiteTableBuilder(fn, cstab, ptab, loopNestingLevel, nf)
	var doNode func(ir.Node) bool
	doNode = func(n ir.Node) bool {
		cstb.nodeVisitPre(n)
		ir.DoChildren(n, doNode)
		cstb.nodeVisitPost(n)
		return false
	}
	for _, n := range region {
		doNode(n)
	}
	return cstb.cstab
}

func (cstb *callSiteTableBuilder) flagsForNode(call *ir.CallExpr) CSPropBits {
	var r CSPropBits

	if debugTrace&debugTraceCalls != 0 {
		fmt.Fprintf(os.Stderr, "=-= analyzing call at %s\n",
			fmtFullPos(call.Pos()))
	}

	// Set a bit if this call is within a loop.
	if cstb.loopNest > 0 {
		r |= CallSiteInLoop
	}

	// Set a bit if the call is within an init function (either
	// compiler-generated or user-written).
	if cstb.isInit {
		r |= CallSiteInInitFunc
	}

	// Decide whether to apply the panic path heuristic. Hack: don't
	// apply this heuristic in the function "main.main" (mostly just
	// to avoid annoying users).
	if !isMainMain(cstb.fn) {
		r = cstb.determinePanicPathBits(call, r)
	}

	return r
}

// determinePanicPathBits updates the CallSiteOnPanicPath bit within
// "r" if we think this call is on an unconditional path to
// panic/exit. Do this by walking back up the node stack to see if we
// can find either A) an enclosing panic, or B) a statement node that
// we've determined leads to a panic/exit.
func (cstb *callSiteTableBuilder) determinePanicPathBits(call ir.Node, r CSPropBits) CSPropBits {
	cstb.nstack = append(cstb.nstack, call)
	defer func() {
		cstb.nstack = cstb.nstack[:len(cstb.nstack)-1]
	}()

	for ri := range cstb.nstack[:len(cstb.nstack)-1] {
		i := len(cstb.nstack) - ri - 1
		n := cstb.nstack[i]
		_, isCallExpr := n.(*ir.CallExpr)
		_, isStmt := n.(ir.Stmt)
		if isCallExpr {
			isStmt = false
		}

		if debugTrace&debugTraceCalls != 0 {
			ps, inps := cstb.ptab[n]
			fmt.Fprintf(os.Stderr, "=-= callpar %d op=%s ps=%s inptab=%v stmt=%v\n", i, n.Op().String(), ps.String(), inps, isStmt)
		}

		if n.Op() == ir.OPANIC {
			r |= CallSiteOnPanicPath
			break
		}
		if v, ok := cstb.ptab[n]; ok {
			if v == psCallsPanic {
				r |= CallSiteOnPanicPath
				break
			}
			if isStmt {
				break
			}
		}
	}
	return r
}

// propsForArg returns property bits for a given call argument expression arg.
func (cstb *callSiteTableBuilder) propsForArg(arg ir.Node) ActualExprPropBits {
	if cval := cstb.constValue(arg); cval != nil {
		return ActualExprConstant
	}
	if cstb.isConcreteConvIface(arg) {
		return ActualExprIsConcreteConvIface
	}
	fname := cstb.funcName(arg)
	if fname != nil {
		if fn := fname.Func; fn != nil && typecheck.HaveInlineBody(fn) {
			return ActualExprIsInlinableFunc
		}
		return ActualExprIsFunc
	}
	return 0
}

// argPropsForCall returns a slice of argument properties for the
// expressions being passed to the callee in the specific call
// expression; these will be stored in the CallSite object for a given
// call and then consulted when scoring. If no arg has any interesting
// properties we try to save some space and return a nil slice.
func (cstb *callSiteTableBuilder) argPropsForCall(ce *ir.CallExpr) []ActualExprPropBits {
	rv := make([]ActualExprPropBits, len(ce.Args))
	somethingInteresting := false
	for idx := range ce.Args {
		argProp := cstb.propsForArg(ce.Args[idx])
		somethingInteresting = somethingInteresting || (argProp != 0)
		rv[idx] = argProp
	}
	if !somethingInteresting {
		return nil
	}
	return rv
}

func (cstb *callSiteTableBuilder) addCallSite(callee *ir.Func, call *ir.CallExpr) {
	flags := cstb.flagsForNode(call)
	argProps := cstb.argPropsForCall(call)
	if debugTrace&debugTraceCalls != 0 {
		fmt.Fprintf(os.Stderr, "=-= props %+v for call %v\n", argProps, call)
	}
	// FIXME: maybe bulk-allocate these?
	cs := &CallSite{
		Call:     call,
		Callee:   callee,
		Assign:   cstb.containingAssignment(call),
		ArgProps: argProps,
		Flags:    flags,
		ID:       uint(len(cstb.cstab)),
	}
	if _, ok := cstb.cstab[call]; ok {
		fmt.Fprintf(os.Stderr, "*** cstab duplicate entry at: %s\n",
			fmtFullPos(call.Pos()))
		fmt.Fprintf(os.Stderr, "*** call: %+v\n", call)
		panic("bad")
	}
	// Set initial score for callsite to the cost computed
	// by CanInline; this score will be refined later based
	// on heuristics.
	cs.Score = int(callee.Inl.Cost)

	if cstb.cstab == nil {
		cstb.cstab = make(CallSiteTab)
	}
	cstb.cstab[call] = cs
	if debugTrace&debugTraceCalls != 0 {
		fmt.Fprintf(os.Stderr, "=-= added callsite: caller=%v callee=%v n=%s\n",
			cstb.fn, callee, fmtFullPos(call.Pos()))
	}
}

func (cstb *callSiteTableBuilder) nodeVisitPre(n ir.Node) {
	switch n.Op() {
	case ir.ORANGE, ir.OFOR:
		if !hasTopLevelLoopBodyReturnOrBreak(loopBody(n)) {
			cstb.loopNest++
		}
	case ir.OCALLFUNC:
		ce := n.(*ir.CallExpr)
		callee := pgoir.DirectCallee(ce.Fun)
		if callee != nil && callee.Inl != nil {
			cstb.addCallSite(callee, ce)
		}
	}
	cstb.nstack = append(cstb.nstack, n)
}

func (cstb *callSiteTableBuilder) nodeVisitPost(n ir.Node) {
	cstb.nstack = cstb.nstack[:len(cstb.nstack)-1]
	switch n.Op() {
	case ir.ORANGE, ir.OFOR:
		if !hasTopLevelLoopBodyReturnOrBreak(loopBody(n)) {
			cstb.loopNest--
		}
	}
}

func loopBody(n ir.Node) ir.Nodes {
	if forst, ok := n.(*ir.ForStmt); ok {
		return forst.Body
	}
	if rst, ok := n.(*ir.RangeStmt); ok {
		return rst.Body
	}
	return nil
}

// hasTopLevelLoopBodyReturnOrBreak examines the body of a "for" or
// "range" loop to try to verify that it is a real loop, as opposed to
// a construct that is syntactically loopy but doesn't actually iterate
// multiple times, like:
//
//	for {
//	  blah()
//	  return 1
//	}
//
// [Remark: the pattern above crops up quite a bit in the source code
// for the compiler itself, e.g. the auto-generated rewrite code]
//
// Note that we don't look for GOTO statements here, so it's possible
// we'll get the wrong result for a loop with complicated control
// jumps via gotos.
func hasTopLevelLoopBodyReturnOrBreak(loopBody ir.Nodes) bool {
	for _, n := range loopBody {
		if n.Op() == ir.ORETURN || n.Op() == ir.OBREAK {
			return true
		}
	}
	return false
}

// containingAssignment returns the top-level assignment statement
// for a statement level function call "n". Examples:
//
//	x := foo()
//	x, y := bar(z, baz())
//	if blah() { ...
//
// Here the top-level assignment statement for the foo() call is the
// statement assigning to "x"; the top-level assignment for "bar()"
// call is the assignment to x,y. For the baz() and blah() calls,
// there is no top level assignment statement.
//
// The unstated goal here is that we want to use the containing
// assignment to establish a connection between a given call and the
// variables to which its results/returns are being assigned.
//
// Note that for the "bar" command above, the front end sometimes
// decomposes this into two assignments, the first one assigning the
// call to a pair of auto-temps, then the second one assigning the
// auto-temps to the user-visible vars. This helper will return the
// second (outer) of these two.
func (cstb *callSiteTableBuilder) containingAssignment(n ir.Node) ir.Node {
	parent := cstb.nstack[len(cstb.nstack)-1]

	// assignsOnlyAutoTemps returns TRUE of the specified OAS2FUNC
	// node assigns only auto-temps.
	assignsOnlyAutoTemps := func(x ir.Node) bool {
		alst := x.(*ir.AssignListStmt)
		oa2init := alst.Init()
		if len(oa2init) == 0 {
			return false
		}
		for _, v := range oa2init {
			d := v.(*ir.Decl)
			if !ir.IsAutoTmp(d.X) {
				return false
			}
		}
		return true
	}

	// Simple case: x := foo()
	if parent.Op() == ir.OAS {
		return parent
	}

	// Multi-return case: x, y := bar()
	if parent.Op() == ir.OAS2FUNC {
		// Hack city: if the result vars are auto-temps, try looking
		// for an outer assignment in the tree. The code shape we're
		// looking for here is:
		//
		// OAS1({x,y},OCONVNOP(OAS2FUNC({auto1,auto2},OCALLFUNC(bar))))
		//
		if assignsOnlyAutoTemps(parent) {
			par2 := cstb.nstack[len(cstb.nstack)-2]
			if par2.Op() == ir.OAS2 {
				return par2
			}
			if par2.Op() == ir.OCONVNOP {
				par3 := cstb.nstack[len(cstb.nstack)-3]
				if par3.Op() == ir.OAS2 {
					return par3
				}
			}
		}
	}

	return nil
}

// UpdateCallsiteTable handles updating of callerfn's call site table
// after an inlined has been carried out, e.g. the call at 'n' as been
// turned into the inlined call expression 'ic' within function
// callerfn. The chief thing of interest here is to make sure that any
// call nodes within 'ic' are added to the call site table for
// 'callerfn' and scored appropriately.
func UpdateCallsiteTable(callerfn *ir.Func, n *ir.CallExpr, ic *ir.InlinedCallExpr) {
	enableDebugTraceIfEnv()
	defer disableDebugTrace()

	funcInlHeur, ok := fpmap[callerfn]
	if !ok {
		// This can happen for compiler-generated wrappers.
		if debugTrace&debugTraceCalls != 0 {
			fmt.Fprintf(os.Stderr, "=-= early exit, no entry for caller fn %v\n", callerfn)
		}
		return
	}

	if debugTrace&debugTraceCalls != 0 {
		fmt.Fprintf(os.Stderr, "=-= UpdateCallsiteTable(caller=%v, cs=%s)\n",
			callerfn, fmtFullPos(n.Pos()))
	}

	// Mark the call in question as inlined.
	oldcs, ok := funcInlHeur.cstab[n]
	if !ok {
		// This can happen for compiler-generated wrappers.
		return
	}
	oldcs.aux |= csAuxInlined

	if debugTrace&debugTraceCalls != 0 {
		fmt.Fprintf(os.Stderr, "=-= marked as inlined: callee=%v %s\n",
			oldcs.Callee, EncodeCallSiteKey(oldcs))
	}

	// Walk the inlined call region to collect new callsites.
	var icp pstate
	if oldcs.Flags&CallSiteOnPanicPath != 0 {
		icp = psCallsPanic
	}
	var loopNestLevel int
	if oldcs.Flags&CallSiteInLoop != 0 {
		loopNestLevel = 1
	}
	ptab := map[ir.Node]pstate{ic: icp}
	nf := newNameFinder(nil)
	icstab := computeCallSiteTable(callerfn, ic.Body, nil, ptab, loopNestLevel, nf)

	// Record parent callsite. This is primarily for debug output.
	for _, cs := range icstab {
		cs.parent = oldcs
	}

	// Score the calls in the inlined body. Note the setting of
	// "doCallResults" to false here: at the moment there isn't any
	// easy way to localize or region-ize the work done by
	// "rescoreBasedOnCallResultUses", which currently does a walk
	// over the entire function to look for uses of a given set of
	// results. Similarly we're passing nil to makeCallSiteAnalyzer,
	// so as to run name finding without the use of static value &
	// friends.
	csa := makeCallSiteAnalyzer(nil)
	const doCallResults = false
	csa.scoreCallsRegion(callerfn, ic.Body, icstab, doCallResults, ic)
}

"""



```