Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding of the Goal:**

The request asks for the functionality of the provided Go code, specifically focusing on `go/src/cmd/compile/internal/inline/inlheur/analyze.go`. The goal is to understand what this code does within the Go compiler's inlining process.

**2. Keyword Scan and Initial Clues:**

I immediately scan for keywords and identifiers that provide hints:

* **`inline` and `inlheur`:**  This strongly suggests the code is related to inlining heuristics, which are rules and strategies used to decide whether to inline a function call.
* **`AnalyzeFunc`:** This function name clearly indicates the core purpose: analyzing a Go function.
* **`FuncProps`:** This type likely holds properties of a function relevant to inlining decisions (size, complexity, etc.).
* **`CallSiteTab`:**  This suggests information about where the function is called.
* **`propAnalyzer`:**  An interface hinting at a modular approach to analyzing different aspects of a function.
* **`debugTrace...` constants:**  Indicate debugging and logging capabilities.
* **`DumpFuncProps`:**  Points to a mechanism for outputting analysis results, potentially for testing.
* **`fpmap`:** A global map likely used to store the analysis results for functions to avoid redundant computation.
* **`revisitInlinability`:** Suggests a second look at inlining decisions after properties are analyzed.

**3. Deciphering Key Functions and Structures:**

* **`propAnalyzer` Interface:** The comments clearly explain this is for modular analysis, with `nodeVisitPre`, `nodeVisitPost`, and `setResults` methods. This suggests a visitor pattern for traversing the function's abstract syntax tree (AST).
* **`fnInlHeur` Struct:**  This holds the analysis results (`props`), call site information (`cstab`), and function identification (`fname`, `file`, `line`). The comment about the test harness is important for understanding its broader usage.
* **`AnalyzeFunc` Function:**  This seems to be the entry point for analyzing a function. The logic for handling closures and updating `fpmap` is crucial. The call to `canInline` and `budgetForFunc` suggests interaction with the main inlining logic.
* **`analyzeFunc` Function:**  This is called by `AnalyzeFunc` to perform the actual property computation. It checks the `fpmap` for cached results.
* **`computeFuncProps` Function:**  This is where the different `propAnalyzer` implementations are instantiated and run.
* **`revisitInlinability` Function:**  This function uses the computed `FuncProps` to potentially undo an earlier decision to inline based on the cost and properties.
* **`DumpFuncProps` and related functions:**  These are clearly for dumping the analysis results, primarily for testing. The logic for handling different output modes (append, tagged) is interesting.

**4. Identifying the Overall Workflow:**

Based on the individual components, I can infer a workflow:

1. **`AnalyzeFunc` is called:** This is the main entry point for analyzing a function for inlining.
2. **Closure Handling:** It identifies and processes closures associated with the function.
3. **`analyzeFunc` is called:** This fetches cached properties or computes them.
4. **`computeFuncProps` is called:**  This creates different `propAnalyzer` instances.
5. **`propAnalyzer` implementations are run:** These traverse the function's AST and collect specific properties.
6. **`setResults` is called:** Each analyzer writes its results to the `FuncProps` object.
7. **`revisitInlinability` is called:** The inlining decision is re-evaluated based on the computed properties.
8. **Results are stored in `fpmap`:** The analysis results are cached.
9. **`DumpFuncProps` (optional):**  For testing, the results can be dumped to a file.

**5. Answering the Specific Questions:**

Now I can systematically answer the questions in the prompt:

* **Functionality:** Describe the main purpose of each function and the overall goal of the file.
* **Go Feature Implementation:** Connect the code to the inlining feature of the Go compiler. Provide a simple example illustrating how inlining works conceptually (even if the code doesn't directly perform the inlining).
* **Code Inference (Hypothetical Input/Output):**  Choose a key function like `computeFuncProps` and imagine a simple input function. Hypothesize what properties might be computed (e.g., number of statements, presence of loops).
* **Command-line Arguments:** Focus on the debugging flags (`debugTrace`) and the dumping flag (`-d=dumpinlfuncprops`). Explain their effects.
* **Common Mistakes:** Think about potential pitfalls for developers working on this code, such as misunderstanding the analyzer interface or incorrect handling of cached data.

**6. Refining and Structuring the Answer:**

Finally, organize the information logically, using clear headings and bullet points. Provide code examples where appropriate and ensure the explanation is easy to understand. Emphasize the core concepts like inlining heuristics, function properties, and the modular analyzer approach.

By following this thought process, combining code analysis with an understanding of the Go compiler's inlining process, I can arrive at a comprehensive and accurate answer to the request. The key is to start with the big picture and then zoom in on the details, connecting the individual pieces to the overall functionality.
The Go code snippet you provided is a part of the inlining heuristics implementation within the Go compiler. Its primary function is to **analyze Go functions to determine properties that are relevant for making inlining decisions**. This analysis helps the compiler decide which function calls are profitable to replace with the function's body directly at the call site.

Here's a breakdown of its functionalities:

**1. Function Property Analysis:**

* **`AnalyzeFunc(fn *ir.Func, ...)`:** This is the main entry point for analyzing a function. It takes an `ir.Func` (the compiler's internal representation of a function) as input.
* **`computeFuncProps(fn *ir.Func, ...)`:**  This function orchestrates the process of computing various properties of the function.
* **`propAnalyzer` interface:** This interface defines a contract for different analysis modules. Each module focuses on calculating a specific set of function properties. The code includes at least one concrete implementation implicitly (the `ffa := makeFuncFlagsAnalyzer(fn)` suggests an analyzer for function flags).
* **`FuncProps` struct (not shown but implied):**  This structure likely holds the collected properties of a function, such as its size, complexity, whether it contains loops or certain operations, etc.
* **Visitor Pattern:** The `propAnalyzer` interface and `runAnalyzersOnFunction` function suggest a visitor pattern. Different analyzers "visit" the nodes of the function's abstract syntax tree (AST) to extract information.
* **Caching:** The `fpmap` variable acts as a cache to store the analysis results for functions. This prevents redundant analysis if the same function is encountered multiple times.

**2. Handling Closures:**

* `AnalyzeFunc` explicitly handles closures. It iterates through closures within a function and analyzes them as well. This is important because inlining decisions for a function might depend on the properties of the closures it uses.

**3. Revisiting Inlinability:**

* **`revisitInlinability(fn *ir.Func, funcProps *FuncProps, ...)`:** After the function properties are computed, this function re-evaluates whether the function should still be considered for inlining. It uses the computed `funcProps` and a cost/budgeting mechanism to make this determination. If a function is too large or doesn't have beneficial properties, it might be excluded from inlining even if it was initially considered.

**4. Debugging and Testing:**

* **`debugTrace...` constants:** These constants control different levels of debugging output, allowing developers to trace the inlining analysis process.
* **`DumpFuncProps(fn *ir.Func, dumpfile string)`:** This function is designed for unit testing. It allows dumping the computed function properties to a file for verification and comparison against expected results.

**5. Call Site Analysis (Indirectly):**

* While the primary focus is function properties, the `CallSiteTab` and `computeCallSiteTable` suggest that information about where a function is called is also collected. This information can influence inlining decisions (e.g., inlining hot paths more aggressively).

**Inferred Go Language Feature Implementation: Inlining Heuristics**

This code directly contributes to the **inlining optimization** feature of the Go compiler. Inlining aims to improve performance by reducing function call overhead. However, inlining too aggressively can increase code size and potentially slow down execution. The heuristics implemented in this code help the compiler make informed decisions about which functions are good candidates for inlining.

**Go Code Example Illustrating the Concept (Simplified):**

Imagine a simplified version of how the properties might be used:

```go
package main

import "fmt"

// Hypothetical FuncProps struct (simplified)
type FuncProps struct {
	NumStatements int
	HasLoops      bool
}

// Hypothetical function to determine inlinability
func canInline(props *FuncProps, currentBudget int) bool {
	cost := props.NumStatements // Assume number of statements is the cost
	if props.HasLoops {
		cost *= 2 // Penalize functions with loops
	}
	return cost <= currentBudget
}

func add(a, b int) int {
	result := a + b
	return result
}

func main() {
	addProps := &FuncProps{NumStatements: 2, HasLoops: false}
	budget := 5

	if canInline(addProps, budget) {
		fmt.Println("Inlining 'add'")
		// In a real compiler, the call to 'add' would be replaced
		// with the body of the 'add' function here.
		result := 10 + 5
		fmt.Println(result)
	} else {
		fmt.Println("Not inlining 'add'")
		fmt.Println(add(10, 5))
	}
}
```

**Assumptions and Hypothetical Input/Output for `computeFuncProps`:**

**Assumption:**  Let's assume `computeFuncProps` has access to the function's AST.

**Hypothetical Input:**

```go
func exampleFunc(x int) int {
	y := x * 2
	if y > 10 {
		return y - 5
	}
	return y + 5
}
```

**Hypothetical Output (Values within `FuncProps`):**

```
FuncProps {
  NumStatements: 4, // Assuming variable declaration and if/else count as statements
  HasLoops: false,
  ContainsArithmetic: true,
  MaxDepth: 1,      // No nested control flow structures
  // ... other properties ...
}
```

**Explanation:**  The `computeFuncProps` function would analyze the `exampleFunc`'s AST. It would count the number of statements, detect the presence of arithmetic operations, and determine that there are no loops.

**Command-line Parameters (Based on Debugging Constants):**

The code uses bitwise flags and a global `debugTrace` variable (likely set via a command-line flag or environment variable) to control debugging output. Here's how some of the flags would work:

* **`debugTraceFuncs` (1):** If `debugTrace & debugTraceFuncs != 0`, it would print messages at the start and end of the `AnalyzeFunc` and `computeFuncProps` functions, showing which functions are being analyzed.
* **`debugTraceFuncFlags` (2):**  This would likely print information about the function flags being analyzed by the `makeFuncFlagsAnalyzer`.
* **`debugTraceResults` (4):**  This flag would probably trigger printing of the final computed `FuncProps` for each function.
* **`debugTraceParams` (8):** If enabled, it would likely show details about the function parameters being considered during analysis.
* **`debugTraceExprClassify` (16):** This might show how expressions within the function are being classified for analysis purposes.
* **`debugTraceCalls` (32):** This would probably print information about the function calls within the function being analyzed.
* **`debugTraceScoring` (64):**  If enabled, it might show the scoring or weighting applied to different function properties during the inlining decision process.

**Example of Setting Debugging Flags (Hypothetical):**

You might run the Go compiler with a flag like `-gcflags="-d=inltrace=7"` (where 7 is 1 + 2 + 4, enabling `debugTraceFuncs`, `debugTraceFuncFlags`, and `debugTraceResults`).

**Common Mistakes Users (Developers working on the compiler) Might Make:**

1. **Incorrectly Implementing `propAnalyzer`:**
   * **Forgetting to update `FuncProps`:** An analyzer might iterate through the function but fail to actually store the computed property in the `FuncProps` struct using the `setResults` method.
   * **Incorrectly traversing the AST:** An analyzer might miss important nodes or process them in the wrong order, leading to inaccurate property calculations.
   * **Introducing dependencies between analyzers:** The design assumes analyzers are independent. Creating dependencies can lead to unexpected behavior or incorrect results.

2. **Misunderstanding the Caching Mechanism:**
   * **Not considering when to invalidate cache:** If a function's definition changes, the cached `FuncProps` might become stale. The code needs mechanisms (not explicitly shown here) to handle this.
   * **Incorrectly accessing or updating `fpmap`:** Concurrent access to `fpmap` without proper synchronization could lead to race conditions.

3. **Overly Complex Heuristics:**
   * **Creating heuristics that are difficult to understand and maintain:**  Overly complex logic can make it hard to debug and reason about inlining decisions.
   * **Introducing heuristics that have unintended performance consequences:**  A poorly designed heuristic could lead to worse performance in some cases.

4. **Testing Issues:**
   * **Not writing comprehensive unit tests:** Thorough testing is crucial to ensure the accuracy of the inlining heuristics. The `DumpFuncProps` functionality is a tool to help with this.
   * **Assuming specific input will always trigger a certain inlining decision:** Inlining decisions are complex and can be affected by many factors.

This detailed explanation should provide a good understanding of the functionality of the provided Go code snippet and its role in the Go compiler's inlining process.

### 提示词
```
这是路径为go/src/cmd/compile/internal/inline/inlheur/analyze.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmp"
	"encoding/json"
	"fmt"
	"internal/buildcfg"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	debugTraceFuncs = 1 << iota
	debugTraceFuncFlags
	debugTraceResults
	debugTraceParams
	debugTraceExprClassify
	debugTraceCalls
	debugTraceScoring
)

// propAnalyzer interface is used for defining one or more analyzer
// helper objects, each tasked with computing some specific subset of
// the properties we're interested in. The assumption is that
// properties are independent, so each new analyzer that implements
// this interface can operate entirely on its own. For a given analyzer
// there will be a sequence of calls to nodeVisitPre and nodeVisitPost
// as the nodes within a function are visited, then a followup call to
// setResults so that the analyzer can transfer its results into the
// final properties object.
type propAnalyzer interface {
	nodeVisitPre(n ir.Node)
	nodeVisitPost(n ir.Node)
	setResults(funcProps *FuncProps)
}

// fnInlHeur contains inline heuristics state information about a
// specific Go function being analyzed/considered by the inliner. Note
// that in addition to constructing a fnInlHeur object by analyzing a
// specific *ir.Func, there is also code in the test harness
// (funcprops_test.go) that builds up fnInlHeur's by reading in and
// parsing a dump. This is the reason why we have file/fname/line
// fields below instead of just an *ir.Func field.
type fnInlHeur struct {
	props *FuncProps
	cstab CallSiteTab
	fname string
	file  string
	line  uint
}

var fpmap = map[*ir.Func]fnInlHeur{}

// AnalyzeFunc computes function properties for fn and its contained
// closures, updating the global 'fpmap' table. It is assumed that
// "CanInline" has been run on fn and on the closures that feed
// directly into calls; other closures not directly called will also
// be checked inlinability for inlinability here in case they are
// returned as a result.
func AnalyzeFunc(fn *ir.Func, canInline func(*ir.Func), budgetForFunc func(*ir.Func) int32, inlineMaxBudget int) {
	if fpmap == nil {
		// If fpmap is nil this indicates that the main inliner pass is
		// complete and we're doing inlining of wrappers (no heuristics
		// used here).
		return
	}
	if fn.OClosure != nil {
		// closures will be processed along with their outer enclosing func.
		return
	}
	enableDebugTraceIfEnv()
	if debugTrace&debugTraceFuncs != 0 {
		fmt.Fprintf(os.Stderr, "=-= AnalyzeFunc(%v)\n", fn)
	}
	// Build up a list containing 'fn' and any closures it contains. Along
	// the way, test to see whether each closure is inlinable in case
	// we might be returning it.
	funcs := []*ir.Func{fn}
	ir.VisitFuncAndClosures(fn, func(n ir.Node) {
		if clo, ok := n.(*ir.ClosureExpr); ok {
			funcs = append(funcs, clo.Func)
		}
	})

	// Analyze the list of functions. We want to visit a given func
	// only after the closures it contains have been processed, so
	// iterate through the list in reverse order. Once a function has
	// been analyzed, revisit the question of whether it should be
	// inlinable; if it is over the default hairiness limit and it
	// doesn't have any interesting properties, then we don't want
	// the overhead of writing out its inline body.
	nameFinder := newNameFinder(fn)
	for i := len(funcs) - 1; i >= 0; i-- {
		f := funcs[i]
		if f.OClosure != nil && !f.InlinabilityChecked() {
			canInline(f)
		}
		funcProps := analyzeFunc(f, inlineMaxBudget, nameFinder)
		revisitInlinability(f, funcProps, budgetForFunc)
		if f.Inl != nil {
			f.Inl.Properties = funcProps.SerializeToString()
		}
	}
	disableDebugTrace()
}

// TearDown is invoked at the end of the main inlining pass; doing
// function analysis and call site scoring is unlikely to help a lot
// after this point, so nil out fpmap and other globals to reclaim
// storage.
func TearDown() {
	fpmap = nil
	scoreCallsCache.tab = nil
	scoreCallsCache.csl = nil
}

func analyzeFunc(fn *ir.Func, inlineMaxBudget int, nf *nameFinder) *FuncProps {
	if funcInlHeur, ok := fpmap[fn]; ok {
		return funcInlHeur.props
	}
	funcProps, fcstab := computeFuncProps(fn, inlineMaxBudget, nf)
	file, line := fnFileLine(fn)
	entry := fnInlHeur{
		fname: fn.Sym().Name,
		file:  file,
		line:  line,
		props: funcProps,
		cstab: fcstab,
	}
	fn.SetNeverReturns(entry.props.Flags&FuncPropNeverReturns != 0)
	fpmap[fn] = entry
	if fn.Inl != nil && fn.Inl.Properties == "" {
		fn.Inl.Properties = entry.props.SerializeToString()
	}
	return funcProps
}

// revisitInlinability revisits the question of whether to continue to
// treat function 'fn' as an inline candidate based on the set of
// properties we've computed for it. If (for example) it has an
// initial size score of 150 and no interesting properties to speak
// of, then there isn't really any point to moving ahead with it as an
// inline candidate.
func revisitInlinability(fn *ir.Func, funcProps *FuncProps, budgetForFunc func(*ir.Func) int32) {
	if fn.Inl == nil {
		return
	}
	maxAdj := int32(LargestNegativeScoreAdjustment(fn, funcProps))
	budget := budgetForFunc(fn)
	if fn.Inl.Cost+maxAdj > budget {
		fn.Inl = nil
	}
}

// computeFuncProps examines the Go function 'fn' and computes for it
// a function "properties" object, to be used to drive inlining
// heuristics. See comments on the FuncProps type for more info.
func computeFuncProps(fn *ir.Func, inlineMaxBudget int, nf *nameFinder) (*FuncProps, CallSiteTab) {
	if debugTrace&debugTraceFuncs != 0 {
		fmt.Fprintf(os.Stderr, "=-= starting analysis of func %v:\n%+v\n",
			fn, fn)
	}
	funcProps := new(FuncProps)
	ffa := makeFuncFlagsAnalyzer(fn)
	analyzers := []propAnalyzer{ffa}
	analyzers = addResultsAnalyzer(fn, analyzers, funcProps, inlineMaxBudget, nf)
	analyzers = addParamsAnalyzer(fn, analyzers, funcProps, nf)
	runAnalyzersOnFunction(fn, analyzers)
	for _, a := range analyzers {
		a.setResults(funcProps)
	}
	cstab := computeCallSiteTable(fn, fn.Body, nil, ffa.panicPathTable(), 0, nf)
	return funcProps, cstab
}

func runAnalyzersOnFunction(fn *ir.Func, analyzers []propAnalyzer) {
	var doNode func(ir.Node) bool
	doNode = func(n ir.Node) bool {
		for _, a := range analyzers {
			a.nodeVisitPre(n)
		}
		ir.DoChildren(n, doNode)
		for _, a := range analyzers {
			a.nodeVisitPost(n)
		}
		return false
	}
	doNode(fn)
}

func propsForFunc(fn *ir.Func) *FuncProps {
	if funcInlHeur, ok := fpmap[fn]; ok {
		return funcInlHeur.props
	} else if fn.Inl != nil && fn.Inl.Properties != "" {
		// FIXME: considering adding some sort of cache or table
		// for deserialized properties of imported functions.
		return DeserializeFromString(fn.Inl.Properties)
	}
	return nil
}

func fnFileLine(fn *ir.Func) (string, uint) {
	p := base.Ctxt.InnermostPos(fn.Pos())
	return filepath.Base(p.Filename()), p.Line()
}

func Enabled() bool {
	return buildcfg.Experiment.NewInliner || UnitTesting()
}

func UnitTesting() bool {
	return base.Debug.DumpInlFuncProps != "" ||
		base.Debug.DumpInlCallSiteScores != 0
}

// DumpFuncProps computes and caches function properties for the func
// 'fn', writing out a description of the previously computed set of
// properties to the file given in 'dumpfile'. Used for the
// "-d=dumpinlfuncprops=..." command line flag, intended for use
// primarily in unit testing.
func DumpFuncProps(fn *ir.Func, dumpfile string) {
	if fn != nil {
		if fn.OClosure != nil {
			// closures will be processed along with their outer enclosing func.
			return
		}
		captureFuncDumpEntry(fn)
		ir.VisitFuncAndClosures(fn, func(n ir.Node) {
			if clo, ok := n.(*ir.ClosureExpr); ok {
				captureFuncDumpEntry(clo.Func)
			}
		})
	} else {
		emitDumpToFile(dumpfile)
	}
}

// emitDumpToFile writes out the buffer function property dump entries
// to a file, for unit testing. Dump entries need to be sorted by
// definition line, and due to generics we need to account for the
// possibility that several ir.Func's will have the same def line.
func emitDumpToFile(dumpfile string) {
	mode := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if dumpfile[0] == '+' {
		dumpfile = dumpfile[1:]
		mode = os.O_WRONLY | os.O_APPEND | os.O_CREATE
	}
	if dumpfile[0] == '%' {
		dumpfile = dumpfile[1:]
		d, b := filepath.Dir(dumpfile), filepath.Base(dumpfile)
		ptag := strings.ReplaceAll(types.LocalPkg.Path, "/", ":")
		dumpfile = d + "/" + ptag + "." + b
	}
	outf, err := os.OpenFile(dumpfile, mode, 0644)
	if err != nil {
		base.Fatalf("opening function props dump file %q: %v\n", dumpfile, err)
	}
	defer outf.Close()
	dumpFilePreamble(outf)

	atline := map[uint]uint{}
	sl := make([]fnInlHeur, 0, len(dumpBuffer))
	for _, e := range dumpBuffer {
		sl = append(sl, e)
		atline[e.line] = atline[e.line] + 1
	}
	sl = sortFnInlHeurSlice(sl)

	prevline := uint(0)
	for _, entry := range sl {
		idx := uint(0)
		if prevline == entry.line {
			idx++
		}
		prevline = entry.line
		atl := atline[entry.line]
		if err := dumpFnPreamble(outf, &entry, nil, idx, atl); err != nil {
			base.Fatalf("function props dump: %v\n", err)
		}
	}
	dumpBuffer = nil
}

// captureFuncDumpEntry grabs the function properties object for 'fn'
// and enqueues it for later dumping. Used for the
// "-d=dumpinlfuncprops=..." command line flag, intended for use
// primarily in unit testing.
func captureFuncDumpEntry(fn *ir.Func) {
	// avoid capturing compiler-generated equality funcs.
	if strings.HasPrefix(fn.Sym().Name, ".eq.") {
		return
	}
	funcInlHeur, ok := fpmap[fn]
	if !ok {
		// Missing entry is expected for functions that are too large
		// to inline. We still want to write out call site scores in
		// this case however.
		funcInlHeur = fnInlHeur{cstab: callSiteTab}
	}
	if dumpBuffer == nil {
		dumpBuffer = make(map[*ir.Func]fnInlHeur)
	}
	if _, ok := dumpBuffer[fn]; ok {
		return
	}
	if debugTrace&debugTraceFuncs != 0 {
		fmt.Fprintf(os.Stderr, "=-= capturing dump for %v:\n", fn)
	}
	dumpBuffer[fn] = funcInlHeur
}

// dumpFilePreamble writes out a file-level preamble for a given
// Go function as part of a function properties dump.
func dumpFilePreamble(w io.Writer) {
	fmt.Fprintf(w, "// DO NOT EDIT (use 'go test -v -update-expected' instead.)\n")
	fmt.Fprintf(w, "// See cmd/compile/internal/inline/inlheur/testdata/props/README.txt\n")
	fmt.Fprintf(w, "// for more information on the format of this file.\n")
	fmt.Fprintf(w, "// %s\n", preambleDelimiter)
}

// dumpFnPreamble writes out a function-level preamble for a given
// Go function as part of a function properties dump. See the
// README.txt file in testdata/props for more on the format of
// this preamble.
func dumpFnPreamble(w io.Writer, funcInlHeur *fnInlHeur, ecst encodedCallSiteTab, idx, atl uint) error {
	fmt.Fprintf(w, "// %s %s %d %d %d\n",
		funcInlHeur.file, funcInlHeur.fname, funcInlHeur.line, idx, atl)
	// emit props as comments, followed by delimiter
	fmt.Fprintf(w, "%s// %s\n", funcInlHeur.props.ToString("// "), comDelimiter)
	data, err := json.Marshal(funcInlHeur.props)
	if err != nil {
		return fmt.Errorf("marshal error %v\n", err)
	}
	fmt.Fprintf(w, "// %s\n", string(data))
	dumpCallSiteComments(w, funcInlHeur.cstab, ecst)
	fmt.Fprintf(w, "// %s\n", fnDelimiter)
	return nil
}

// sortFnInlHeurSlice sorts a slice of fnInlHeur based on
// the starting line of the function definition, then by name.
func sortFnInlHeurSlice(sl []fnInlHeur) []fnInlHeur {
	slices.SortStableFunc(sl, func(a, b fnInlHeur) int {
		if a.line != b.line {
			return cmp.Compare(a.line, b.line)
		}
		return strings.Compare(a.fname, b.fname)
	})
	return sl
}

// delimiters written to various preambles to make parsing of
// dumps easier.
const preambleDelimiter = "<endfilepreamble>"
const fnDelimiter = "<endfuncpreamble>"
const comDelimiter = "<endpropsdump>"
const csDelimiter = "<endcallsites>"

// dumpBuffer stores up function properties dumps when
// "-d=dumpinlfuncprops=..." is in effect.
var dumpBuffer map[*ir.Func]fnInlHeur
```