Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Initial Understanding of the Context:** The first line `// This file contains code to re-score callsites based on how the results of the call were used.` is the most crucial starting point. It immediately tells us the core purpose of this code: to adjust the inlining scores of function calls based on how their return values are utilized. The example provided further clarifies this with a scenario involving a function `bar()` whose return value influences subsequent code execution.

2. **Identifying Key Data Structures:**  I scanned the code for type definitions and prominent variables. The types `resultPropAndCS` and `resultUseAnalyzer` stood out. `resultPropAndCS` seems to hold information about a call result and the call site where it originated. `resultUseAnalyzer` looks like the main structure for this analysis, containing a map (`resultNameTab`) to store information about result usage, the function being analyzed (`fn`), and a call site table (`cstab`).

3. **Analyzing the Main Function:**  The function `rescoreBasedOnCallResultUses` is the entry point for the analysis. It initializes a `resultUseAnalyzer` and then walks the Abstract Syntax Tree (AST) of the function using `ir.DoChildren`. The `doNode` function calls `nodeVisitPre` and `nodeVisitPost` on each node, suggesting a pre-order and post-order traversal of the AST. This hints that the analysis happens during this traversal.

4. **Understanding `examineCallResults`:** This function is responsible for identifying and recording information about the return values of function calls. The `namesDefined` helper function is critical here. It extracts the names of the variables that receive the return values. The code then checks if the return values have "interesting" properties (like always returning the same constant) and if the receiving variables are not reassigned. If these conditions are met, it stores information about the result in `resultNameTab`.

5. **Deconstructing `namesDefined`:** This function is crucial for understanding how return values are tracked. It handles both single and multi-return value scenarios. The logic for multi-return values, especially the handling of auto-generated temporary variables, is important to note. The connection to `FuncProps` suggests that properties of the called function (determined in an earlier stage) are being used here.

6. **Analyzing the AST Traversal (`nodeVisitPre`):**  This function contains a `switch` statement that handles different types of AST nodes. The cases `ir.OCALLINTER` and `ir.OCALLFUNC` call `callTargetCheckResults`, indicating that indirect and direct calls are analyzed. The `ir.OIF` and `ir.OSWITCH` cases call `foldCheckResults`, suggesting that conditional statements are analyzed to see if inlining can enable optimizations.

7. **Understanding `callTargetCheckResults`:**  This function deals with scenarios where the target of a call (the function being called) is itself the result of another function call. It checks if the returned function or object has certain properties that make inlining beneficial.

8. **Understanding `foldCheckResults`:** This is where the core "re-scoring" logic based on conditional usage lies. It checks if the condition of an `if` or `switch` statement depends on the results of a function call, and if those results are constant. The `ShouldFoldIfNameConstant` function (not in the provided snippet) is hinted at as the place where the actual condition analysis happens.

9. **Identifying Helper Functions:** Functions like `collectNamesUsed`, `returnHasProp`, and `getCallResultName` provide supporting functionality for the main analysis. `getCallResultName` is particularly important for tracing back the origin of a value used in a call.

10. **Inferring the Overall Goal:** By connecting the dots, the overall goal becomes clear: to improve the accuracy of the inlining heuristic by considering how the results of function calls are used. If a return value directly influences control flow (like in an `if` or `switch`) or is used as the target of another call, and if the return value has consistent properties, then inlining the originating function becomes more attractive due to the potential for constant folding or dead code elimination.

11. **Considering Error-Prone Areas:** I thought about what could go wrong or be misunderstood when using this code. The reliance on the specific structure of the AST (e.g., how multi-return assignments are represented) and the "interesting" properties of return values are key assumptions. Users might mistakenly assume the analysis works for all kinds of return value usage or might not understand the limitations of the AST traversal.

12. **Generating Examples:** Finally, I formulated code examples to illustrate the core functionality, specifically focusing on the scenarios described in the comments (constant return values in conditionals, and returned functions being called). The examples aimed to demonstrate how the inlining score could be adjusted in these cases.

This step-by-step analysis, focusing on the code's structure, key functions, and the relationships between them, allowed me to understand its functionality and generate the explanation provided earlier.
这段Go语言代码是Go编译器中内联（inlining）优化的一个组成部分，专门用于**基于函数调用结果的使用方式来重新评估调用点（callsite）的内联得分**。

简单来说，这段代码的作用是：**观察一个函数调用的返回值是如何被使用的，如果返回值的使用方式暗示着内联后能带来额外的优化（例如常量折叠、死代码消除），则提高该调用点的内联得分。**

下面我将详细列举其功能，并尝试用Go代码举例说明：

**功能列表:**

1. **`rescoreBasedOnCallResultUses` 函数:** 这是入口函数，接收当前正在编译的函数 `fn`，一个存储了函数调用结果属性的映射表 `resultNameTab`，以及调用点信息表 `cstab`。它初始化一个 `resultUseAnalyzer` 结构体，并启动对函数体AST的遍历。
2. **`resultUseAnalyzer` 结构体:**  维护了分析过程中的状态信息，包括：
    * `resultNameTab`:  一个映射表，存储了函数调用结果的变量名以及对应的调用点和结果属性。
    * `fn`: 当前正在分析的函数。
    * `cstab`:  存储了函数中所有调用点信息的表格。
    * `condLevelTracker`: (在代码片段中未完全展示)  可能用于跟踪当前代码所处的条件语句的嵌套层级。
3. **`examineCallResults` 函数:**  检查一个特定的调用点 `cs` 的返回值是如何被赋值的。它会提取接收返回值的变量名，并判断这些返回值是否具有某些“有趣”的属性（例如，总是返回相同的常量、总是返回相同的可内联函数等）。如果满足条件，则将这些信息记录到 `resultNameTab` 中。
4. **`namesDefined` 函数:**  辅助 `examineCallResults`，用于识别函数调用的返回值被赋值给了哪些新的局部变量。它可以处理单返回值和多返回值的情况，并区分用户定义的变量和编译器自动生成的临时变量。
5. **`nodeVisitPre` 和 `nodeVisitPost` 函数:**  这两个函数是AST遍历的回调函数。`nodeVisitPre` 在进入一个AST节点时被调用，`nodeVisitPost` 在离开一个AST节点时被调用。`nodeVisitPre` 负责检查特定的节点类型（如函数调用、if语句、switch语句），并调用相应的处理函数。
6. **`callTargetCheckResults` 函数:**  检查函数调用的目标（即被调用的函数）是否是另一个函数调用的结果。例如，`f := getFunc(); f()`。如果返回的函数具有特定的属性（例如，总是返回相同的可内联函数），则可以调整相关调用点的得分。
7. **`foldCheckResults` 函数:**  检查 `if` 或 `switch` 语句的条件表达式是否使用了由某个函数调用返回的常量值。如果条件表达式只包含对这些常量值的简单引用和操作，则可以提高该函数调用的得分，因为内联后可以进行常量折叠。
8. **`collectNamesUsed` 函数:**  辅助 `foldCheckResults`，用于收集在一个表达式中使用的所有局部变量名。
9. **`returnHasProp` 函数:**  检查一个变量名对应的函数调用结果是否具有指定的属性。
10. **`getCallResultName` 函数:**  尝试获取一个函数调用表达式的目标（被调用的函数）的静态值，这有助于追踪函数调用链。

**Go代码举例说明:**

假设有以下Go代码：

```go
package main

func getConst() int {
	return 10
}

func useConst(x int) {
	if x == 10 {
		println("x is ten")
	} else {
		println("x is not ten")
	}
}

func main() {
	c := getConst() // 调用点 A
	useConst(c)
}
```

**推理过程:**

1. **初始评分:**  在初始的内联评分阶段，`getConst()` 可能会得到一个基础的评分。
2. **`examineCallResults`:** 当分析到 `c := getConst()` 这个调用点 A 时，`examineCallResults` 会识别出返回值被赋值给了变量 `c`。 `namesDefined` 会返回 `[c]`, 并且 `getConst` 的属性会表明它总是返回相同的常量 `10`。 这些信息会被记录到 `resultNameTab` 中。
3. **`rescoreBasedOnCallResultUses` 和 `nodeVisitPre`:** 当遍历到 `useConst(c)` 中的 `if x == 10` 语句时，`nodeVisitPre` 会识别出 `ir.OIF` 节点，并调用 `foldCheckResults`。
4. **`foldCheckResults`:**  `foldCheckResults` 会分析条件表达式 `x == 10`，并使用 `collectNamesUsed` 收集使用的变量名，这里是 `x`。
5. **关联调用点:**  `foldCheckResults` 会在 `resultNameTab` 中查找 `x` 的定义，发现它是由调用点 A (`getConst()`) 返回的，并且 `getConst()` 的返回值总是常量。
6. **重新评分:** 由于 `getConst()` 的返回值被用于一个条件判断，并且该返回值是常量，内联 `getConst()` 可以直接将 `x == 10` 替换为 `10 == 10`，从而进行常量折叠，优化 `useConst` 函数。因此，`foldCheckResults` 会提高调用点 A 的内联得分。

**假设的输入与输出 (针对 `foldCheckResults`):**

**输入:**

* `cond`:  `ir.Node` 代表表达式 `x == 10`。
* `resultNameTab`:  包含 `c` 的条目，指向调用点 A 和 `getConst` 返回常量的属性。
* 调用点 A 的初始得分 (例如: 50)。

**输出:**

* 调用点 A 的更新后的得分 (例如: 70，假设 `returnFeedsConstToIfAdj` 的调整值为 20)。

**命令行参数:**

这段代码本身不直接处理命令行参数。它是 Go 编译器内部内联优化流程的一部分。控制内联行为的命令行参数通常在编译器的其他部分处理，例如 `-gcflags` 中的 `-l` 参数可以禁用内联，或者使用 `-m` 参数来查看内联决策。

**易犯错的点:**

在实际的编译器开发中，一个可能易犯错的点是**过度激进的评分调整**。如果对所有看似能带来优化的场景都大幅提高内联得分，可能会导致过度内联，反而增加代码大小，降低性能，或者增加编译时间。

**例如:**

假设有一个函数 `expensiveCalc()` 返回一个常量，但这个常量只在一个很少执行到的 `if` 分支中使用。如果过度提高 `expensiveCalc()` 的内联得分，可能会导致即使在大多数情况下内联 `expensiveCalc()` 并没有带来实际好处，仍然会进行内联。这会增加代码体积，甚至可能因为指令缓存污染等原因导致性能下降。

因此，在调整内联得分时需要谨慎，需要考虑多种因素，并进行充分的测试和性能评估。

总而言之，这段代码通过分析函数调用结果的使用方式，来更精细地调整内联决策，目标是识别出那些内联后能带来显著优化的调用点，从而提升程序的整体性能。

### 提示词
```
这是路径为go/src/cmd/compile/internal/inline/inlheur/score_callresult_uses.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package inlheur

import (
	"cmd/compile/internal/ir"
	"fmt"
	"os"
)

// This file contains code to re-score callsites based on how the
// results of the call were used.  Example:
//
//    func foo() {
//       x, fptr := bar()
//       switch x {
//         case 10: fptr = baz()
//         default: blix()
//       }
//       fptr(100)
//     }
//
// The initial scoring pass will assign a score to "bar()" based on
// various criteria, however once the first pass of scoring is done,
// we look at the flags on the result from bar, and check to see
// how those results are used. If bar() always returns the same constant
// for its first result, and if the variable receiving that result
// isn't redefined, and if that variable feeds into an if/switch
// condition, then we will try to adjust the score for "bar" (on the
// theory that if we inlined, we can constant fold / deadcode).

type resultPropAndCS struct {
	defcs *CallSite
	props ResultPropBits
}

type resultUseAnalyzer struct {
	resultNameTab map[*ir.Name]resultPropAndCS
	fn            *ir.Func
	cstab         CallSiteTab
	*condLevelTracker
}

// rescoreBasedOnCallResultUses examines how call results are used,
// and tries to update the scores of calls based on how their results
// are used in the function.
func (csa *callSiteAnalyzer) rescoreBasedOnCallResultUses(fn *ir.Func, resultNameTab map[*ir.Name]resultPropAndCS, cstab CallSiteTab) {
	enableDebugTraceIfEnv()
	rua := &resultUseAnalyzer{
		resultNameTab:    resultNameTab,
		fn:               fn,
		cstab:            cstab,
		condLevelTracker: new(condLevelTracker),
	}
	var doNode func(ir.Node) bool
	doNode = func(n ir.Node) bool {
		rua.nodeVisitPre(n)
		ir.DoChildren(n, doNode)
		rua.nodeVisitPost(n)
		return false
	}
	doNode(fn)
	disableDebugTrace()
}

func (csa *callSiteAnalyzer) examineCallResults(cs *CallSite, resultNameTab map[*ir.Name]resultPropAndCS) map[*ir.Name]resultPropAndCS {
	if debugTrace&debugTraceScoring != 0 {
		fmt.Fprintf(os.Stderr, "=-= examining call results for %q\n",
			EncodeCallSiteKey(cs))
	}

	// Invoke a helper to pick out the specific ir.Name's the results
	// from this call are assigned into, e.g. "x, y := fooBar()". If
	// the call is not part of an assignment statement, or if the
	// variables in question are not newly defined, then we'll receive
	// an empty list here.
	//
	names, autoTemps, props := namesDefined(cs)
	if len(names) == 0 {
		return resultNameTab
	}

	if debugTrace&debugTraceScoring != 0 {
		fmt.Fprintf(os.Stderr, "=-= %d names defined\n", len(names))
	}

	// For each returned value, if the value has interesting
	// properties (ex: always returns the same constant), and the name
	// in question is never redefined, then make an entry in the
	// result table for it.
	const interesting = (ResultIsConcreteTypeConvertedToInterface |
		ResultAlwaysSameConstant | ResultAlwaysSameInlinableFunc | ResultAlwaysSameFunc)
	for idx, n := range names {
		rprop := props.ResultFlags[idx]

		if debugTrace&debugTraceScoring != 0 {
			fmt.Fprintf(os.Stderr, "=-= props for ret %d %q: %s\n",
				idx, n.Sym().Name, rprop.String())
		}

		if rprop&interesting == 0 {
			continue
		}
		if csa.nameFinder.reassigned(n) {
			continue
		}
		if resultNameTab == nil {
			resultNameTab = make(map[*ir.Name]resultPropAndCS)
		} else if _, ok := resultNameTab[n]; ok {
			panic("should never happen")
		}
		entry := resultPropAndCS{
			defcs: cs,
			props: rprop,
		}
		resultNameTab[n] = entry
		if autoTemps[idx] != nil {
			resultNameTab[autoTemps[idx]] = entry
		}
		if debugTrace&debugTraceScoring != 0 {
			fmt.Fprintf(os.Stderr, "=-= add resultNameTab table entry n=%v autotemp=%v props=%s\n", n, autoTemps[idx], rprop.String())
		}
	}
	return resultNameTab
}

// namesDefined returns a list of ir.Name's corresponding to locals
// that receive the results from the call at site 'cs', plus the
// properties object for the called function. If a given result
// isn't cleanly assigned to a newly defined local, the
// slot for that result in the returned list will be nil. Example:
//
//	call                             returned name list
//
//	x := foo()                       [ x ]
//	z, y := bar()                    [ nil, nil ]
//	_, q := baz()                    [ nil, q ]
//
// In the case of a multi-return call, such as "x, y := foo()",
// the pattern we see from the front end will be a call op
// assigning to auto-temps, and then an assignment of the auto-temps
// to the user-level variables. In such cases we return
// first the user-level variable (in the first func result)
// and then the auto-temp name in the second result.
func namesDefined(cs *CallSite) ([]*ir.Name, []*ir.Name, *FuncProps) {
	// If this call doesn't feed into an assignment (and of course not
	// all calls do), then we don't have anything to work with here.
	if cs.Assign == nil {
		return nil, nil, nil
	}
	funcInlHeur, ok := fpmap[cs.Callee]
	if !ok {
		// TODO: add an assert/panic here.
		return nil, nil, nil
	}
	if len(funcInlHeur.props.ResultFlags) == 0 {
		return nil, nil, nil
	}

	// Single return case.
	if len(funcInlHeur.props.ResultFlags) == 1 {
		asgn, ok := cs.Assign.(*ir.AssignStmt)
		if !ok {
			return nil, nil, nil
		}
		// locate name being assigned
		aname, ok := asgn.X.(*ir.Name)
		if !ok {
			return nil, nil, nil
		}
		return []*ir.Name{aname}, []*ir.Name{nil}, funcInlHeur.props
	}

	// Multi-return case
	asgn, ok := cs.Assign.(*ir.AssignListStmt)
	if !ok || !asgn.Def {
		return nil, nil, nil
	}
	userVars := make([]*ir.Name, len(funcInlHeur.props.ResultFlags))
	autoTemps := make([]*ir.Name, len(funcInlHeur.props.ResultFlags))
	for idx, x := range asgn.Lhs {
		if n, ok := x.(*ir.Name); ok {
			userVars[idx] = n
			r := asgn.Rhs[idx]
			if r.Op() == ir.OCONVNOP {
				r = r.(*ir.ConvExpr).X
			}
			if ir.IsAutoTmp(r) {
				autoTemps[idx] = r.(*ir.Name)
			}
			if debugTrace&debugTraceScoring != 0 {
				fmt.Fprintf(os.Stderr, "=-= multi-ret namedef uv=%v at=%v\n",
					x, autoTemps[idx])
			}
		} else {
			return nil, nil, nil
		}
	}
	return userVars, autoTemps, funcInlHeur.props
}

func (rua *resultUseAnalyzer) nodeVisitPost(n ir.Node) {
	rua.condLevelTracker.post(n)
}

func (rua *resultUseAnalyzer) nodeVisitPre(n ir.Node) {
	rua.condLevelTracker.pre(n)
	switch n.Op() {
	case ir.OCALLINTER:
		if debugTrace&debugTraceScoring != 0 {
			fmt.Fprintf(os.Stderr, "=-= rescore examine iface call %v:\n", n)
		}
		rua.callTargetCheckResults(n)
	case ir.OCALLFUNC:
		if debugTrace&debugTraceScoring != 0 {
			fmt.Fprintf(os.Stderr, "=-= rescore examine call %v:\n", n)
		}
		rua.callTargetCheckResults(n)
	case ir.OIF:
		ifst := n.(*ir.IfStmt)
		rua.foldCheckResults(ifst.Cond)
	case ir.OSWITCH:
		swst := n.(*ir.SwitchStmt)
		if swst.Tag != nil {
			rua.foldCheckResults(swst.Tag)
		}

	}
}

// callTargetCheckResults examines a given call to see whether the
// callee expression is potentially an inlinable function returned
// from a potentially inlinable call. Examples:
//
//	Scenario 1: named intermediate
//
//	   fn1 := foo()         conc := bar()
//	   fn1("blah")          conc.MyMethod()
//
//	Scenario 2: returned func or concrete object feeds directly to call
//
//	   foo()("blah")        bar().MyMethod()
//
// In the second case although at the source level the result of the
// direct call feeds right into the method call or indirect call,
// we're relying on the front end having inserted an auto-temp to
// capture the value.
func (rua *resultUseAnalyzer) callTargetCheckResults(call ir.Node) {
	ce := call.(*ir.CallExpr)
	rname := rua.getCallResultName(ce)
	if rname == nil {
		return
	}
	if debugTrace&debugTraceScoring != 0 {
		fmt.Fprintf(os.Stderr, "=-= staticvalue returns %v:\n",
			rname)
	}
	if rname.Class != ir.PAUTO {
		return
	}
	switch call.Op() {
	case ir.OCALLINTER:
		if debugTrace&debugTraceScoring != 0 {
			fmt.Fprintf(os.Stderr, "=-= in %s checking %v for cci prop:\n",
				rua.fn.Sym().Name, rname)
		}
		if cs := rua.returnHasProp(rname, ResultIsConcreteTypeConvertedToInterface); cs != nil {

			adj := returnFeedsConcreteToInterfaceCallAdj
			cs.Score, cs.ScoreMask = adjustScore(adj, cs.Score, cs.ScoreMask)
		}
	case ir.OCALLFUNC:
		if debugTrace&debugTraceScoring != 0 {
			fmt.Fprintf(os.Stderr, "=-= in %s checking %v for samefunc props:\n",
				rua.fn.Sym().Name, rname)
			v, ok := rua.resultNameTab[rname]
			if !ok {
				fmt.Fprintf(os.Stderr, "=-= no entry for %v in rt\n", rname)
			} else {
				fmt.Fprintf(os.Stderr, "=-= props for %v: %q\n", rname, v.props.String())
			}
		}
		if cs := rua.returnHasProp(rname, ResultAlwaysSameInlinableFunc); cs != nil {
			adj := returnFeedsInlinableFuncToIndCallAdj
			cs.Score, cs.ScoreMask = adjustScore(adj, cs.Score, cs.ScoreMask)
		} else if cs := rua.returnHasProp(rname, ResultAlwaysSameFunc); cs != nil {
			adj := returnFeedsFuncToIndCallAdj
			cs.Score, cs.ScoreMask = adjustScore(adj, cs.Score, cs.ScoreMask)

		}
	}
}

// foldCheckResults examines the specified if/switch condition 'cond'
// to see if it refers to locals defined by a (potentially inlinable)
// function call at call site C, and if so, whether 'cond' contains
// only combinations of simple references to all of the names in
// 'names' with selected constants + operators. If these criteria are
// met, then we adjust the score for call site C to reflect the
// fact that inlining will enable deadcode and/or constant propagation.
// Note: for this heuristic to kick in, the names in question have to
// be all from the same callsite. Examples:
//
//	  q, r := baz()	    x, y := foo()
//	  switch q+r {		a, b, c := bar()
//		...			    if x && y && a && b && c {
//	  }					   ...
//					    }
//
// For the call to "baz" above we apply a score adjustment, but not
// for the calls to "foo" or "bar".
func (rua *resultUseAnalyzer) foldCheckResults(cond ir.Node) {
	namesUsed := collectNamesUsed(cond)
	if len(namesUsed) == 0 {
		return
	}
	var cs *CallSite
	for _, n := range namesUsed {
		rpcs, found := rua.resultNameTab[n]
		if !found {
			return
		}
		if cs != nil && rpcs.defcs != cs {
			return
		}
		cs = rpcs.defcs
		if rpcs.props&ResultAlwaysSameConstant == 0 {
			return
		}
	}
	if debugTrace&debugTraceScoring != 0 {
		nls := func(nl []*ir.Name) string {
			r := ""
			for _, n := range nl {
				r += " " + n.Sym().Name
			}
			return r
		}
		fmt.Fprintf(os.Stderr, "=-= calling ShouldFoldIfNameConstant on names={%s} cond=%v\n", nls(namesUsed), cond)
	}

	if !ShouldFoldIfNameConstant(cond, namesUsed) {
		return
	}
	adj := returnFeedsConstToIfAdj
	cs.Score, cs.ScoreMask = adjustScore(adj, cs.Score, cs.ScoreMask)
}

func collectNamesUsed(expr ir.Node) []*ir.Name {
	res := []*ir.Name{}
	ir.Visit(expr, func(n ir.Node) {
		if n.Op() != ir.ONAME {
			return
		}
		nn := n.(*ir.Name)
		if nn.Class != ir.PAUTO {
			return
		}
		res = append(res, nn)
	})
	return res
}

func (rua *resultUseAnalyzer) returnHasProp(name *ir.Name, prop ResultPropBits) *CallSite {
	v, ok := rua.resultNameTab[name]
	if !ok {
		return nil
	}
	if v.props&prop == 0 {
		return nil
	}
	return v.defcs
}

func (rua *resultUseAnalyzer) getCallResultName(ce *ir.CallExpr) *ir.Name {
	var callTarg ir.Node
	if sel, ok := ce.Fun.(*ir.SelectorExpr); ok {
		// method call
		callTarg = sel.X
	} else if ctarg, ok := ce.Fun.(*ir.Name); ok {
		// regular call
		callTarg = ctarg
	} else {
		return nil
	}
	r := ir.StaticValue(callTarg)
	if debugTrace&debugTraceScoring != 0 {
		fmt.Fprintf(os.Stderr, "=-= staticname on %v returns %v:\n",
			callTarg, r)
	}
	if r.Op() == ir.OCALLFUNC {
		// This corresponds to the "x := foo()" case; here
		// ir.StaticValue has brought us all the way back to
		// the call expression itself. We need to back off to
		// the name defined by the call; do this by looking up
		// the callsite.
		ce := r.(*ir.CallExpr)
		cs, ok := rua.cstab[ce]
		if !ok {
			return nil
		}
		names, _, _ := namesDefined(cs)
		if len(names) == 0 {
			return nil
		}
		return names[0]
	} else if r.Op() == ir.ONAME {
		return r.(*ir.Name)
	}
	return nil
}
```