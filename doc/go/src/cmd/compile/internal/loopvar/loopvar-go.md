Response:
Let's break down the thought process for analyzing the provided Go code and fulfilling the request.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `loopvar.go` file within the Go compiler. This involves identifying its purpose, how it achieves it, any configuration options, and potential pitfalls for users.

**2. Initial Skim and Keyword Identification:**

The first step is to quickly read through the code, paying attention to comments, function names, type names, and key terms. Here's what stands out:

* **Package `loopvar`:** Clearly this package is about loop variables.
* **Copyright and License:** Standard Go boilerplate.
* **`VarAndLoop` struct:**  Seems to group a variable name with its associated loop. This suggests the code is tracking specific variables within loops.
* **`ForCapture` function:** This is the main function. The comment describes transforming `for` and `range` loops where variables might be captured by closures or escape to the heap. This is a crucial piece of information.
* **"capture," "closure," "escape," "heap":** These terms indicate the code is dealing with memory management and how variables are accessed by functions defined within loops.
* **`DistinctVars` field:**  This field on loop nodes controls whether the transformation is applied.
* **`base.LoopVarHash`, `base.Debug.LoopVar`, `GOEXPERIMENT=loopvar`:** These are configuration mechanisms that influence the transformation process. This suggests the behavior can be controlled for debugging, experimentation, or specific Go versions.
* **`possiblyLeaked` map:** This strongly suggests the code is analyzing whether loop variables might be accessed after the loop finishes.
* **Transformation logic within `scanChildrenThenTransform`:**  This function seems to be the core of the transformation process. It handles both `range` and `for` loops with different strategies.
* **Code manipulation (e.g., creating temporary variables, prepending assignments, rewriting `continue` statements):** This indicates the code is actively modifying the abstract syntax tree (AST) of the Go program.
* **`LogTransformations` function:**  This function is responsible for reporting which loops were transformed and why.

**3. Deeper Dive into `ForCapture`:**

Now, focus on the `ForCapture` function.

* **Purpose:**  The comment clearly states the goal: to transform loops where variables might be captured. The goal is to make each iteration of the loop have its own copy of the loop variable.
* **Mechanism:** The function iterates through the nodes of a function's AST. The `scanChildrenThenTransform` function is the key.
* **`scanChildrenThenTransform` logic:**
    * **Closure Detection:** It checks for closures that might capture loop variables.
    * **Address-of Operator:** It looks for taking the address of loop variables.
    * **`RangeStmt` Transformation:**  Relatively straightforward, creating a temporary variable and assigning the loop variable to it within the loop body.
    * **`ForStmt` Transformation (3-clause):**  More complex. It introduces new variables (e.g., `z'`), rewrites the loop condition and post statement, and handles `continue` statements. The numbered comments in the code are extremely helpful in understanding this complex transformation.
* **Configuration:** The code uses `DistinctVars`, `base.LoopVarHash`, and `base.Debug.LoopVar` to control whether a loop is transformed. The `GOEXPERIMENT` environment variable is also mentioned.
* **`possiblyLeaked`:** The logic for detecting potentially leaked variables is crucial. A variable is considered leaked if its address is taken or if it's captured by a closure.

**4. Inferring the Go Language Feature:**

Based on the keywords and the transformation logic, the most likely Go language feature being implemented is the **per-iteration loop variable capture semantics introduced in Go 1.22**. Prior to Go 1.22, loop variables were shared across iterations, which could lead to subtle bugs when used in goroutines or closures.

**5. Crafting the Go Code Example:**

To illustrate the feature, a simple example demonstrating the problem with pre-Go 1.22 behavior and the fix with per-iteration variables is ideal. This involves:

* A loop.
* Capturing a loop variable in a goroutine or closure.
* Observing the output difference between the old and new behavior.

**6. Analyzing Command-Line Parameters:**

The code mentions `base.Debug.LoopVar` and `base.LoopVarHash`. These are not standard command-line flags in the `go run` or `go build` sense. Instead, they are **internal compiler flags** or settings. The request asks for *command-line* parameters, so the relevant aspect here is how these *internal* settings might be influenced externally. The `GOEXPERIMENT=loopvar` environment variable is the most direct way a user can influence this behavior.

**7. Identifying User Mistakes:**

The core user mistake addressed by this feature is the incorrect assumption that closures within loops capture a *copy* of the loop variable's value at the time the closure is created. Instead, they captured the *same* variable, whose value could change in subsequent iterations. The example used earlier naturally demonstrates this mistake.

**8. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each part of the original request:

* **Functionality:** List the main actions of the code.
* **Go Language Feature:**  State the inferred feature and provide a clear Go example with "before" and "after" scenarios and explanations.
* **Command-Line Parameters:** Explain the relevant environment variable (`GOEXPERIMENT`) and the internal compiler flags (`base.Debug.LoopVar`, `base.LoopVarHash`) and how they relate.
* **User Mistakes:**  Provide a concrete example of the common mistake and how the new behavior prevents it.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Is this related to escape analysis in general?  Yes, but it's more specifically about *loop variable capture*. Escape analysis is a broader concept.
* **Clarifying "command-line parameters":** Realizing that `base.Debug.LoopVar` isn't a direct command-line flag, but rather an internal setting often controlled by environment variables or compiler flags, is important.
* **Emphasizing the Go 1.22 change:** Explicitly mentioning the Go version helps frame the context and importance of the code.
* **Refining the Go example:** Ensuring the example clearly demonstrates the problem and the solution is crucial for understanding.

By following these steps, combining careful reading, keyword analysis, logical deduction, and a good understanding of Go's memory management and closure behavior, one can effectively analyze and explain the functionality of the provided code snippet.
这段代码是 Go 编译器 `cmd/compile/internal/loopvar` 包的一部分，其主要功能是**实现 Go 语言中循环变量的捕获机制**。更具体地说，它负责转换 `for` 和 `range` 循环，确保在闭包中引用循环变量时，每个循环迭代都能获得该变量的独立副本。

**功能列表:**

1. **识别需要转换的循环:**  通过语法检查，保守地估计哪些循环中的变量可能被闭包捕获或逃逸到堆上。
2. **根据配置决定是否转换:**  转换的决定取决于循环节点上的 `DistinctVars` 字段，以及全局的 `base.LoopVarHash` 和包级别的 `base.Debug.LoopVar` 标志。
3. **转换 `range` 循环:** 对于 `range` 循环，如果检测到变量可能被捕获，则创建一个新的临时变量，并将循环变量的值赋给该临时变量，然后在闭包中使用该临时变量。
4. **转换 3-clause `for` 循环:** 对于更复杂的 3-clause `for` 循环，转换过程更加复杂，包括引入新的变量、修改循环的初始化、条件和 post 语句，以及重写 `continue` 语句。
5. **处理内联函数中的循环:**  `DistinctVars` 字段的设置会在内联过程中保留，确保即使函数被内联，循环的转换行为也保持一致。
6. **记录转换信息:**  记录哪些循环变量被转换，以便后续的日志输出和性能分析。
7. **提供调试选项:**  通过 `base.Debug.LoopVar` 标志，可以控制转换的行为，例如强制转换所有循环，或者开启更详细的调试信息。
8. **与 `GOEXPERIMENT=loopvar` 配合:** 当设置 `GOEXPERIMENT=loopvar` 时，会修改 `base.Debug.LoopVar` 的默认值，从而影响所有包的循环变量捕获行为。

**实现的 Go 语言功能：Go 1.22 循环变量语义**

在 Go 1.22 之前，`for` 循环和 `range` 循环中声明的变量在所有循环迭代中都是共享的。当在循环内部创建一个闭包（例如匿名函数或启动一个 goroutine）并引用循环变量时，闭包最终会访问到循环结束时的变量值，而不是创建闭包时的值。

Go 1.22 引入了新的循环变量语义，默认情况下，`for` 和 `range` 循环中声明的变量在每次循环迭代中都会被重新声明和初始化，从而为每个闭包提供该变量的独立副本。`loopvar.go` 中的代码正是实现了这种新的语义。

**Go 代码示例：**

假设有以下 Go 代码：

```go
package main

import (
	"fmt"
	"sync"
)

func main() {
	var wg sync.WaitGroup
	numbers := []int{1, 2, 3, 4, 5}

	// 旧的循环变量语义（Go < 1.22）
	fmt.Println("旧的循环变量语义:")
	for _, num := range numbers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println(num) // 所有 goroutine 可能都会打印 5
		}()
	}
	wg.Wait()

	fmt.Println("\n新的循环变量语义 (Go >= 1.22):")
	wg.Add(len(numbers))
	for _, num := range numbers {
		num := num // 显式地重新声明 num，模拟 Go 1.22 的行为
		go func() {
			defer wg.Done()
			fmt.Println(num) // 每个 goroutine 打印不同的数字
		}()
	}
	wg.Wait()
}
```

**假设的输入与输出：**

**在 Go 1.22 之前（或者没有应用 `loopvar` 包的转换）：**

```
旧的循环变量语义:
5
5
5
5
5

新的循环变量语义 (Go >= 1.22):
1
2
3
4
5
```

**在 Go 1.22 或之后（应用了 `loopvar` 包的转换）：**

```
旧的循环变量语义:
1
2
3
4
5

新的循环变量语义 (Go >= 1.22):
1
2
3
4
5
```

**代码推理：**

`loopvar.go` 中的 `ForCapture` 函数会识别出第一个循环中的 `num` 变量被闭包引用，并根据配置决定是否进行转换。如果进行转换，它会修改 AST，使得在每次循环迭代中，闭包捕获的是 `num` 的一个新副本，从而避免了所有 goroutine 打印相同值的问题。

在第二个循环中，我们通过显式地 `num := num` 模拟了 Go 1.22 的行为，创建了一个新的局部变量 `num`，闭包捕获的是这个新的局部变量。

**命令行参数的具体处理：**

代码中涉及的“命令行参数”实际上是 **编译器内部的配置选项**，主要通过以下方式控制：

* **`GOEXPERIMENT=loopvar` 环境变量:**  设置此环境变量会影响 `base.Debug.LoopVar` 的默认值。当设置为 `loopvar` 时，默认会启用循环变量的按迭代捕获。这可以被认为是影响编译器行为的一种外部配置。
* **`base.Debug.LoopVar` (包级别标志):**  这是一个整数标志，可以通过编译器命令行选项（例如 `-gcflags=-d=loopvar=1`）设置。不同的值代表不同的行为：
    * `0`: 默认值，根据 `DistinctVars` 和 `LoopVarHash` 决定是否转换。
    * `1`:  强制启用循环变量转换（除非 `>= 11`）。当 `base.LoopVarHash != nil` 时也会设置此值。
    * `11`:  强制转换所有循环，忽略语法检查和潜在的逃逸分析。不会输出日志。
    * 其他值 (例如 `2`, `4`, `12`): 用于输出更详细的日志信息，辅助调试。
* **`base.LoopVarHash`:**  这是一个用于调试的哈希表，可以根据循环变量的位置来决定是否进行转换。通常在测试或调试特定问题时使用。

**用户易犯错的点：**

在使用旧的 Go 版本（< 1.22）时，最容易犯的错误就是在循环内部创建闭包并引用循环变量，而没有意识到闭包捕获的是同一个变量。这会导致一些难以调试的并发问题或逻辑错误。

**示例：**

```go
package main

import (
	"fmt"
	"sync"
)

func main() {
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Println(i) // 期望打印 0 到 4，但实际上可能都打印 5
		}()
	}
	wg.Wait()
}
```

**在 Go 1.22 之前，这段代码的输出是不确定的，但很可能所有 goroutine 都会打印 `5`。**  这是因为所有闭包都引用了同一个变量 `i`，而当 goroutine 执行时，循环可能已经结束，`i` 的值变为 5。

**Go 1.22 的循环变量语义以及 `loopvar.go` 的作用，就是为了解决这个问题，确保每个 goroutine 捕获到的是 `i` 在其被创建时的值。**

总结来说，`loopvar.go` 是 Go 编译器中至关重要的一个组成部分，它实现了 Go 语言中循环变量的按迭代捕获语义，避免了在并发编程中常见的陷阱，并提升了代码的可靠性。它通过复杂的 AST 转换和配置选项来达到这个目标。

### 提示词
```
这是路径为go/src/cmd/compile/internal/loopvar/loopvar.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Package loopvar applies the proper variable capture, according
// to experiment, flags, language version, etc.
package loopvar

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/src"
	"fmt"
)

type VarAndLoop struct {
	Name    *ir.Name
	Loop    ir.Node  // the *ir.RangeStmt or *ir.ForStmt. Used for identity and position
	LastPos src.XPos // the last position observed within Loop
}

// ForCapture transforms for and range loops that declare variables that might be
// captured by a closure or escaped to the heap, using a syntactic check that
// conservatively overestimates the loops where capture occurs, but still avoids
// transforming the (large) majority of loops. It returns the list of names
// subject to this change, that may (once transformed) be heap allocated in the
// process. (This allows checking after escape analysis to call out any such
// variables, in case it causes allocation/performance problems).
//
// The decision to transform loops is normally encoded in the For/Range loop node
// field DistinctVars but is also dependent on base.LoopVarHash, and some values
// of base.Debug.LoopVar (which is set per-package).  Decisions encoded in DistinctVars
// are preserved across inlining, so if package a calls b.F and loops in b.F are
// transformed, then they are always transformed, whether b.F is inlined or not.
//
// Per-package, the debug flag settings that affect this transformer:
//
// base.LoopVarHash != nil => use hash setting to govern transformation.
// note that LoopVarHash != nil sets base.Debug.LoopVar to 1 (unless it is >= 11, for testing/debugging).
//
// base.Debug.LoopVar == 11 => transform ALL loops ignoring syntactic/potential escape. Do not log, can be in addition to GOEXPERIMENT.
//
// The effect of GOEXPERIMENT=loopvar is to change the default value (0) of base.Debug.LoopVar to 1 for all packages.
func ForCapture(fn *ir.Func) []VarAndLoop {
	// if a loop variable is transformed it is appended to this slice for later logging
	var transformed []VarAndLoop

	describe := func(n *ir.Name) string {
		pos := n.Pos()
		inner := base.Ctxt.InnermostPos(pos)
		outer := base.Ctxt.OutermostPos(pos)
		if inner == outer {
			return fmt.Sprintf("loop variable %v now per-iteration", n)
		}
		return fmt.Sprintf("loop variable %v now per-iteration (loop inlined into %s:%d)", n, outer.Filename(), outer.Line())
	}

	forCapture := func() {
		seq := 1

		dclFixups := make(map[*ir.Name]ir.Stmt)

		// possibly leaked includes names of declared loop variables that may be leaked;
		// the mapped value is true if the name is *syntactically* leaked, and those loops
		// will be transformed.
		possiblyLeaked := make(map[*ir.Name]bool)

		// these enable an optimization of "escape" under return statements
		loopDepth := 0
		returnInLoopDepth := 0

		// noteMayLeak is called for candidate variables in for range/3-clause, and
		// adds them (mapped to false) to possiblyLeaked.
		noteMayLeak := func(x ir.Node) {
			if n, ok := x.(*ir.Name); ok {
				if n.Type().Kind() == types.TBLANK {
					return
				}
				// default is false (leak candidate, not yet known to leak), but flag can make all variables "leak"
				possiblyLeaked[n] = base.Debug.LoopVar >= 11
			}
		}

		// For reporting, keep track of the last position within any loop.
		// Loops nest, also need to be sensitive to inlining.
		var lastPos src.XPos

		updateLastPos := func(p src.XPos) {
			pl, ll := p.Line(), lastPos.Line()
			if p.SameFile(lastPos) &&
				(pl > ll || pl == ll && p.Col() > lastPos.Col()) {
				lastPos = p
			}
		}

		// maybeReplaceVar unshares an iteration variable for a range loop,
		// if that variable was actually (syntactically) leaked,
		// subject to hash-variable debugging.
		maybeReplaceVar := func(k ir.Node, x *ir.RangeStmt) ir.Node {
			if n, ok := k.(*ir.Name); ok && possiblyLeaked[n] {
				desc := func() string {
					return describe(n)
				}
				if base.LoopVarHash.MatchPos(n.Pos(), desc) {
					// Rename the loop key, prefix body with assignment from loop key
					transformed = append(transformed, VarAndLoop{n, x, lastPos})
					tk := typecheck.TempAt(base.Pos, fn, n.Type())
					tk.SetTypecheck(1)
					as := ir.NewAssignStmt(x.Pos(), n, tk)
					as.Def = true
					as.SetTypecheck(1)
					x.Body.Prepend(as)
					dclFixups[n] = as
					return tk
				}
			}
			return k
		}

		// scanChildrenThenTransform processes node x to:
		//  1. if x is a for/range w/ DistinctVars, note declared iteration variables possiblyLeaked (PL)
		//  2. search all of x's children for syntactically escaping references to v in PL,
		//     meaning either address-of-v or v-captured-by-a-closure
		//  3. for all v in PL that had a syntactically escaping reference, transform the declaration
		//     and (in case of 3-clause loop) the loop to the unshared loop semantics.
		//  This is all much simpler for range loops; 3-clause loops can have an arbitrary number
		//  of iteration variables and the transformation is more involved, range loops have at most 2.
		var scanChildrenThenTransform func(x ir.Node) bool
		scanChildrenThenTransform = func(n ir.Node) bool {

			if loopDepth > 0 {
				updateLastPos(n.Pos())
			}

			switch x := n.(type) {
			case *ir.ClosureExpr:
				if returnInLoopDepth >= loopDepth {
					// This expression is a child of a return, which escapes all loops above
					// the return, but not those between this expression and the return.
					break
				}
				for _, cv := range x.Func.ClosureVars {
					v := cv.Canonical()
					if _, ok := possiblyLeaked[v]; ok {
						possiblyLeaked[v] = true
					}
				}

			case *ir.AddrExpr:
				if returnInLoopDepth >= loopDepth {
					// This expression is a child of a return, which escapes all loops above
					// the return, but not those between this expression and the return.
					break
				}
				// Explicitly note address-taken so that return-statements can be excluded
				y := ir.OuterValue(x.X)
				if y.Op() != ir.ONAME {
					break
				}
				z, ok := y.(*ir.Name)
				if !ok {
					break
				}
				switch z.Class {
				case ir.PAUTO, ir.PPARAM, ir.PPARAMOUT, ir.PAUTOHEAP:
					if _, ok := possiblyLeaked[z]; ok {
						possiblyLeaked[z] = true
					}
				}

			case *ir.ReturnStmt:
				savedRILD := returnInLoopDepth
				returnInLoopDepth = loopDepth
				defer func() { returnInLoopDepth = savedRILD }()

			case *ir.RangeStmt:
				if !(x.Def && x.DistinctVars) {
					// range loop must define its iteration variables AND have distinctVars.
					x.DistinctVars = false
					break
				}
				noteMayLeak(x.Key)
				noteMayLeak(x.Value)
				loopDepth++
				savedLastPos := lastPos
				lastPos = x.Pos() // this sets the file.
				ir.DoChildren(n, scanChildrenThenTransform)
				loopDepth--
				x.Key = maybeReplaceVar(x.Key, x)
				x.Value = maybeReplaceVar(x.Value, x)
				thisLastPos := lastPos
				lastPos = savedLastPos
				updateLastPos(thisLastPos) // this will propagate lastPos if in the same file.
				x.DistinctVars = false
				return false

			case *ir.ForStmt:
				if !x.DistinctVars {
					break
				}
				forAllDefInInit(x, noteMayLeak)
				loopDepth++
				savedLastPos := lastPos
				lastPos = x.Pos() // this sets the file.
				ir.DoChildren(n, scanChildrenThenTransform)
				loopDepth--
				var leaked []*ir.Name
				// Collect the leaking variables for the much-more-complex transformation.
				forAllDefInInit(x, func(z ir.Node) {
					if n, ok := z.(*ir.Name); ok && possiblyLeaked[n] {
						desc := func() string {
							return describe(n)
						}
						// Hash on n.Pos() for most precise failure location.
						if base.LoopVarHash.MatchPos(n.Pos(), desc) {
							leaked = append(leaked, n)
						}
					}
				})

				if len(leaked) > 0 {
					// need to transform the for loop just so.

					/* Contrived example, w/ numbered comments from the transformation:
									BEFORE:
										var escape []*int
										for z := 0; z < n; z++ {
											if reason() {
												escape = append(escape, &z)
												continue
											}
											z = z + z
											stuff
										}
									AFTER:
										for z', tmp_first := 0, true; ; { // (4)
											                              // (5) body' follows:
											z := z'                       // (1)
											if tmp_first {tmp_first = false} else {z++} // (6)
											if ! (z < n) { break }        // (7)
											                              // (3, 8) body_continue
											if reason() {
					                            escape = append(escape, &z)
												goto next                 // rewritten continue
											}
											z = z + z
											stuff
										next:                             // (9)
											z' = z                       // (2)
										}

										In the case that the loop contains no increment (z++),
										there is no need for step 6,
										and thus no need to test, update, or declare tmp_first (part of step 4).
										Similarly if the loop contains no exit test (z < n),
										then there is no need for step 7.
					*/

					// Expressed in terms of the input ForStmt
					//
					// 	type ForStmt struct {
					// 	init     Nodes
					// 	Label    *types.Sym
					// 	Cond     Node  // empty if OFORUNTIL
					// 	Post     Node
					// 	Body     Nodes
					// 	HasBreak bool
					// }

					// OFOR: init; loop: if !Cond {break}; Body; Post; goto loop

					// (1) prebody = {z := z' for z in leaked}
					// (2) postbody = {z' = z for z in leaked}
					// (3) body_continue = {body : s/continue/goto next}
					// (4) init' = (init : s/z/z' for z in leaked) + tmp_first := true
					// (5) body' = prebody +        // appears out of order below
					// (6)         if tmp_first {tmp_first = false} else {Post} +
					// (7)         if !cond {break} +
					// (8)         body_continue (3) +
					// (9)         next: postbody (2)
					// (10) cond' = {}
					// (11) post' = {}

					// minor optimizations:
					//   if Post is empty, tmp_first and step 6 can be skipped.
					//   if Cond is empty, that code can also be skipped.

					var preBody, postBody ir.Nodes

					// Given original iteration variable z, what is the corresponding z'
					// that carries the value from iteration to iteration?
					zPrimeForZ := make(map[*ir.Name]*ir.Name)

					// (1,2) initialize preBody and postBody
					for _, z := range leaked {
						transformed = append(transformed, VarAndLoop{z, x, lastPos})

						tz := typecheck.TempAt(base.Pos, fn, z.Type())
						tz.SetTypecheck(1)
						zPrimeForZ[z] = tz

						as := ir.NewAssignStmt(x.Pos(), z, tz)
						as.Def = true
						as.SetTypecheck(1)
						preBody.Append(as)
						dclFixups[z] = as

						as = ir.NewAssignStmt(x.Pos(), tz, z)
						as.SetTypecheck(1)
						postBody.Append(as)

					}

					// (3) rewrite continues in body -- rewrite is inplace, so works for top level visit, too.
					label := typecheck.Lookup(fmt.Sprintf(".3clNext_%d", seq))
					seq++
					labelStmt := ir.NewLabelStmt(x.Pos(), label)
					labelStmt.SetTypecheck(1)

					loopLabel := x.Label
					loopDepth := 0
					var editContinues func(x ir.Node) bool
					editContinues = func(x ir.Node) bool {

						switch c := x.(type) {
						case *ir.BranchStmt:
							// If this is a continue targeting the loop currently being rewritten, transform it to an appropriate GOTO
							if c.Op() == ir.OCONTINUE && (loopDepth == 0 && c.Label == nil || loopLabel != nil && c.Label == loopLabel) {
								c.Label = label
								c.SetOp(ir.OGOTO)
							}
						case *ir.RangeStmt, *ir.ForStmt:
							loopDepth++
							ir.DoChildren(x, editContinues)
							loopDepth--
							return false
						}
						ir.DoChildren(x, editContinues)
						return false
					}
					for _, y := range x.Body {
						editContinues(y)
					}
					bodyContinue := x.Body

					// (4) rewrite init
					forAllDefInInitUpdate(x, func(z ir.Node, pz *ir.Node) {
						// note tempFor[n] can be nil if hash searching.
						if n, ok := z.(*ir.Name); ok && possiblyLeaked[n] && zPrimeForZ[n] != nil {
							*pz = zPrimeForZ[n]
						}
					})

					postNotNil := x.Post != nil
					var tmpFirstDcl ir.Node
					if postNotNil {
						// body' = prebody +
						// (6)     if tmp_first {tmp_first = false} else {Post} +
						//         if !cond {break} + ...
						tmpFirst := typecheck.TempAt(base.Pos, fn, types.Types[types.TBOOL])
						tmpFirstDcl = typecheck.Stmt(ir.NewAssignStmt(x.Pos(), tmpFirst, ir.NewBool(base.Pos, true)))
						tmpFirstSetFalse := typecheck.Stmt(ir.NewAssignStmt(x.Pos(), tmpFirst, ir.NewBool(base.Pos, false)))
						ifTmpFirst := ir.NewIfStmt(x.Pos(), tmpFirst, ir.Nodes{tmpFirstSetFalse}, ir.Nodes{x.Post})
						ifTmpFirst.PtrInit().Append(typecheck.Stmt(ir.NewDecl(base.Pos, ir.ODCL, tmpFirst))) // declares tmpFirst
						preBody.Append(typecheck.Stmt(ifTmpFirst))
					}

					// body' = prebody +
					//         if tmp_first {tmp_first = false} else {Post} +
					// (7)     if !cond {break} + ...
					if x.Cond != nil {
						notCond := ir.NewUnaryExpr(x.Cond.Pos(), ir.ONOT, x.Cond)
						notCond.SetType(x.Cond.Type())
						notCond.SetTypecheck(1)
						newBreak := ir.NewBranchStmt(x.Pos(), ir.OBREAK, nil)
						newBreak.SetTypecheck(1)
						ifNotCond := ir.NewIfStmt(x.Pos(), notCond, ir.Nodes{newBreak}, nil)
						ifNotCond.SetTypecheck(1)
						preBody.Append(ifNotCond)
					}

					if postNotNil {
						x.PtrInit().Append(tmpFirstDcl)
					}

					// (8)
					preBody.Append(bodyContinue...)
					// (9)
					preBody.Append(labelStmt)
					preBody.Append(postBody...)

					// (5) body' = prebody + ...
					x.Body = preBody

					// (10) cond' = {}
					x.Cond = nil

					// (11) post' = {}
					x.Post = nil
				}
				thisLastPos := lastPos
				lastPos = savedLastPos
				updateLastPos(thisLastPos) // this will propagate lastPos if in the same file.
				x.DistinctVars = false

				return false
			}

			ir.DoChildren(n, scanChildrenThenTransform)

			return false
		}
		scanChildrenThenTransform(fn)
		if len(transformed) > 0 {
			// editNodes scans a slice C of ir.Node, looking for declarations that
			// appear in dclFixups.  Any declaration D whose "fixup" is an assignmnt
			// statement A is removed from the C and relocated to the Init
			// of A.  editNodes returns the modified slice of ir.Node.
			editNodes := func(c ir.Nodes) ir.Nodes {
				j := 0
				for _, n := range c {
					if d, ok := n.(*ir.Decl); ok {
						if s := dclFixups[d.X]; s != nil {
							switch a := s.(type) {
							case *ir.AssignStmt:
								a.PtrInit().Prepend(d)
								delete(dclFixups, d.X) // can't be sure of visit order, wouldn't want to visit twice.
							default:
								base.Fatalf("not implemented yet for node type %v", s.Op())
							}
							continue // do not copy this node, and do not increment j
						}
					}
					c[j] = n
					j++
				}
				for k := j; k < len(c); k++ {
					c[k] = nil
				}
				return c[:j]
			}
			// fixup all tagged declarations in all the statements lists in fn.
			rewriteNodes(fn, editNodes)
		}
	}
	ir.WithFunc(fn, forCapture)
	return transformed
}

// forAllDefInInitUpdate applies "do" to all the defining assignments in the Init clause of a ForStmt.
// This abstracts away some of the boilerplate from the already complex and verbose for-3-clause case.
func forAllDefInInitUpdate(x *ir.ForStmt, do func(z ir.Node, update *ir.Node)) {
	for _, s := range x.Init() {
		switch y := s.(type) {
		case *ir.AssignListStmt:
			if !y.Def {
				continue
			}
			for i, z := range y.Lhs {
				do(z, &y.Lhs[i])
			}
		case *ir.AssignStmt:
			if !y.Def {
				continue
			}
			do(y.X, &y.X)
		}
	}
}

// forAllDefInInit is forAllDefInInitUpdate without the update option.
func forAllDefInInit(x *ir.ForStmt, do func(z ir.Node)) {
	forAllDefInInitUpdate(x, func(z ir.Node, _ *ir.Node) { do(z) })
}

// rewriteNodes applies editNodes to all statement lists in fn.
func rewriteNodes(fn *ir.Func, editNodes func(c ir.Nodes) ir.Nodes) {
	var forNodes func(x ir.Node) bool
	forNodes = func(n ir.Node) bool {
		if stmt, ok := n.(ir.InitNode); ok {
			// process init list
			stmt.SetInit(editNodes(stmt.Init()))
		}
		switch x := n.(type) {
		case *ir.Func:
			x.Body = editNodes(x.Body)
		case *ir.InlinedCallExpr:
			x.Body = editNodes(x.Body)

		case *ir.CaseClause:
			x.Body = editNodes(x.Body)
		case *ir.CommClause:
			x.Body = editNodes(x.Body)

		case *ir.BlockStmt:
			x.List = editNodes(x.List)

		case *ir.ForStmt:
			x.Body = editNodes(x.Body)
		case *ir.RangeStmt:
			x.Body = editNodes(x.Body)
		case *ir.IfStmt:
			x.Body = editNodes(x.Body)
			x.Else = editNodes(x.Else)
		case *ir.SelectStmt:
			x.Compiled = editNodes(x.Compiled)
		case *ir.SwitchStmt:
			x.Compiled = editNodes(x.Compiled)
		}
		ir.DoChildren(n, forNodes)
		return false
	}
	forNodes(fn)
}

func LogTransformations(transformed []VarAndLoop) {
	print := 2 <= base.Debug.LoopVar && base.Debug.LoopVar != 11

	if print || logopt.Enabled() { // 11 is do them all, quietly, 12 includes debugging.
		fileToPosBase := make(map[string]*src.PosBase) // used to remove inline context for innermost reporting.

		// trueInlinedPos rebases inner w/o inline context so that it prints correctly in WarnfAt; otherwise it prints as outer.
		trueInlinedPos := func(inner src.Pos) src.XPos {
			afn := inner.AbsFilename()
			pb, ok := fileToPosBase[afn]
			if !ok {
				pb = src.NewFileBase(inner.Filename(), afn)
				fileToPosBase[afn] = pb
			}
			inner.SetBase(pb)
			return base.Ctxt.PosTable.XPos(inner)
		}

		type unit struct{}
		loopsSeen := make(map[ir.Node]unit)
		type loopPos struct {
			loop  ir.Node
			last  src.XPos
			curfn *ir.Func
		}
		var loops []loopPos
		for _, lv := range transformed {
			n := lv.Name
			if _, ok := loopsSeen[lv.Loop]; !ok {
				l := lv.Loop
				loopsSeen[l] = unit{}
				loops = append(loops, loopPos{l, lv.LastPos, n.Curfn})
			}
			pos := n.Pos()

			inner := base.Ctxt.InnermostPos(pos)
			outer := base.Ctxt.OutermostPos(pos)

			if logopt.Enabled() {
				// For automated checking of coverage of this transformation, include this in the JSON information.
				var nString interface{} = n
				if inner != outer {
					nString = fmt.Sprintf("%v (from inline)", n)
				}
				if n.Esc() == ir.EscHeap {
					logopt.LogOpt(pos, "iteration-variable-to-heap", "loopvar", ir.FuncName(n.Curfn), nString)
				} else {
					logopt.LogOpt(pos, "iteration-variable-to-stack", "loopvar", ir.FuncName(n.Curfn), nString)
				}
			}
			if print {
				if inner == outer {
					if n.Esc() == ir.EscHeap {
						base.WarnfAt(pos, "loop variable %v now per-iteration, heap-allocated", n)
					} else {
						base.WarnfAt(pos, "loop variable %v now per-iteration, stack-allocated", n)
					}
				} else {
					innerXPos := trueInlinedPos(inner)
					if n.Esc() == ir.EscHeap {
						base.WarnfAt(innerXPos, "loop variable %v now per-iteration, heap-allocated (loop inlined into %s:%d)", n, outer.Filename(), outer.Line())
					} else {
						base.WarnfAt(innerXPos, "loop variable %v now per-iteration, stack-allocated (loop inlined into %s:%d)", n, outer.Filename(), outer.Line())
					}
				}
			}
		}
		for _, l := range loops {
			pos := l.loop.Pos()
			last := l.last
			loopKind := "range"
			if _, ok := l.loop.(*ir.ForStmt); ok {
				loopKind = "for"
			}
			if logopt.Enabled() {
				// Intended to help with performance debugging, we record whole loop ranges
				logopt.LogOptRange(pos, last, "loop-modified-"+loopKind, "loopvar", ir.FuncName(l.curfn))
			}
			if print && 4 <= base.Debug.LoopVar {
				// TODO decide if we want to keep this, or not.  It was helpful for validating logopt, otherwise, eh.
				inner := base.Ctxt.InnermostPos(pos)
				outer := base.Ctxt.OutermostPos(pos)

				if inner == outer {
					base.WarnfAt(pos, "%s loop ending at %d:%d was modified", loopKind, last.Line(), last.Col())
				} else {
					pos = trueInlinedPos(inner)
					last = trueInlinedPos(base.Ctxt.InnermostPos(last))
					base.WarnfAt(pos, "%s loop ending at %d:%d was modified (loop inlined into %s:%d)", loopKind, last.Line(), last.Col(), outer.Filename(), outer.Line())
				}
			}
		}
	}
}
```