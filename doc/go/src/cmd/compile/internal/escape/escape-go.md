Response: Let's break down the thought process for analyzing this Go code snippet for escape analysis.

1. **Understand the Core Goal:** The initial comments clearly state the purpose: to determine if variables can be allocated on the stack or if they *must* be on the heap. This is about memory management optimization.

2. **Identify Key Data Structures:**  The code defines several structs: `batch`, `closure`, and `escape`. These are crucial for organizing the analysis. Note the purpose of each:
    * `batch`:  Shared state across multiple functions being analyzed together (important for interprocedural analysis).
    * `closure`: Information about closure expressions and how they capture variables.
    * `escape`: State specific to the *current* function being analyzed.

3. **Map High-Level Concepts to Code:**  The comments mention "locations" and "edges."  Scan the code for how these are represented.
    * `location` struct (not fully shown in the provided snippet, but implied by `b.allLocs`, `b.heapLoc`, etc.). This represents a variable or an allocation site.
    * Edges are represented implicitly through the `flow` function (also not shown, but the code uses it extensively). The `derefs` concept in the comments suggests the `flow` function likely considers pointer arithmetic.

4. **Follow the Main Execution Flow:** The `Funcs` and `Batch` functions are the entry points. Trace the steps within `Batch`:
    * Initialization (`batch` struct).
    * Iterating through functions to `initFunc` and `walkFunc`. These likely construct the graph of locations and edges.
    * Processing closures (`flowClosure`).
    * Determining heap allocations based on the analysis (`HeapAllocReason`, `b.flow(b.heapHole().addr(...), loc)`).
    * The core analysis happens in `walkAll` (not shown).
    * Finalization and reporting (`finish`).

5. **Focus on Key Functions:**  `initFunc`, `walkFunc`, `flowClosure`, and `finish` seem central to the analysis.
    * `initFunc`: Sets up the analysis for a single function, allocating "locations" for local variables and parameters.
    * `walkFunc`: Traverses the function's AST, building the flow graph by identifying assignments and address-taking. The label handling hints at dealing with control flow.
    * `flowClosure`:  Deals with how closures capture variables (by value or reference), a critical part of escape analysis.
    * `finish`:  Determines the final escape status of variables and reports warnings/optimizations. The parameter tagging is important for interprocedural analysis.

6. **Look for Specific Mechanisms:**
    * **Location Creation:** The `newLoc` and `oldLoc` functions are used to manage locations.
    * **Flow of Information:** The `flow` function is the core mechanism for tracking how data moves and whether addresses are taken.
    * **Attributes:** The `attrEscapes`, `attrPersists`, `attrMutates`, and `attrCalls` flags on `location` likely track the properties of a variable.
    * **Parameter Tags:** The `paramTag` function is used to summarize the escape behavior of function parameters, enabling interprocedural analysis.

7. **Infer Functionality from Names and Operations:**  Even without seeing the full code for `location`, `flow`, etc., you can infer their purpose from how they're used. For example, `b.heapHole().addr(...)` strongly suggests that `heapHole` represents the heap and `addr` indicates taking the address of something and moving it to the heap.

8. **Address the Specific Questions:**
    * **Functionality Listing:** Summarize the key actions of the code based on the analysis above.
    * **Go Feature Illustration:** Choose a simple example (like passing a local variable to a function) to demonstrate escape.
    * **Code Inference:** Pick a small part of the code (like `flowClosure`) and explain its logic, including assumptions about the behavior of unseen functions.
    * **Command-Line Arguments:**  Look for usage of `base.Flag`. This is the standard way to access compiler flags.
    * **Common Mistakes:** Think about scenarios where developers might not realize a variable is escaping. Closures are a common source of this.

9. **Refine and Structure:** Organize your findings logically, starting with the overall purpose and then diving into details. Use clear language and code examples to illustrate your points. Ensure you explicitly state any assumptions made.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe locations are just variables."  **Correction:** The comments mention implicit allocations and literals, so locations represent more than just named variables.
* **Initial thought:** "The `flow` function just copies attributes." **Correction:** The `derefs` concept suggests it's more sophisticated, considering pointer arithmetic.
* **Overlooking details:**  Initially focusing too much on the control flow within functions and missing the importance of interprocedural analysis (the `batch` struct and parameter tags). Realizing the significance of how information is shared *between* functions.

By following these steps and iteratively refining your understanding, you can effectively analyze and explain complex code like this escape analysis implementation.这段代码是 Go 编译器的一部分，位于 `go/src/cmd/compile/internal/escape/escape.go`，它实现了 **逃逸分析 (Escape Analysis)** 的功能。

**逃逸分析的功能：**

逃逸分析是 Go 编译器中的一个重要优化步骤，其主要目的是确定变量的存储位置：是在栈上分配还是在堆上分配。

1. **识别可能逃逸到堆上的变量:**  代码通过构建一个数据流图来追踪变量的赋值和取地址操作。如果分析发现一个变量的地址被存储到了堆上，或者它的生命周期可能超出其声明的函数（例如，通过返回值传递），那么这个变量就被标记为需要分配在堆上。

2. **构建数据流图:**  代码将每个分配语句或表达式（如变量声明、`new`、`make`、复合字面量）映射到一个唯一的 "位置" (location)。然后，它将 Go 语言的赋值操作表示为位置之间的有向边，边的权重表示解引用和取地址操作的次数。

3. **跨函数分析:** 为了支持跨函数分析，代码会记录函数参数到堆以及到返回值的数据流。这些信息被总结为 "参数标签" (parameter tags)，在静态调用点用于改进函数参数的逃逸分析。

4. **处理闭包:** 代码会分析闭包捕获的自由变量。它会决定这些变量是以值传递还是以引用传递的方式捕获。对于大小不超过 128 字节且从未重新赋值的变量，可以选择按值捕获。

5. **标记逃逸状态:**  根据逃逸分析的结果，代码会更新节点的 `Esc` 字段，标记变量是否逃逸到堆上 (`ir.EscHeap`) 或不逃逸 (`ir.EscNone`)。

6. **进行优化:** 基于逃逸分析的结果，编译器可以进行一些优化：
   - **栈上分配:**  对于没有逃逸的变量，可以在栈上分配，避免堆分配的开销和垃圾回收的压力。
   - **零拷贝字符串到字节切片转换:** 如果字符串到字节切片的转换结果不会被修改，可以直接重用字符串的内存。
   - **将某些值标记为瞬态 (Transient):**  对于不会逃逸的闭包、方法值和切片字面量，可以标记为瞬态，可能用于进一步的优化。

**Go 语言功能示例 (通过逃逸分析进行优化):**

假设有以下 Go 代码：

```go
package main

import "fmt"

func foo() *int {
	x := 10
	return &x // x 的地址被返回，可能逃逸
}

func bar() int {
	y := 20
	return y // y 的值被返回，不会逃逸
}

func main() {
	p := foo()
	fmt.Println(*p)

	q := bar()
	fmt.Println(q)
}
```

**逃逸分析推理：**

* **输入 (假设):** 上述 `main.go` 文件。
* **`foo` 函数分析:**
    * 变量 `x` 在 `foo` 函数内部声明。
    * `&x` 操作获取了 `x` 的地址。
    * 函数返回了 `&x`，这意味着 `x` 的地址被传递到了函数外部。
    * **结论:** 逃逸分析会判断 `x` 逃逸到堆上，因为它的生命周期可能超出 `foo` 函数。
* **`bar` 函数分析:**
    * 变量 `y` 在 `bar` 函数内部声明。
    * 函数直接返回了 `y` 的值。
    * **结论:** 逃逸分析会判断 `y` 不会逃逸，可以在栈上分配。
* **`main` 函数分析:**
    * `p := foo()`: `p` 指向堆上分配的 `x`。
    * `q := bar()`: `q` 的值来自于栈上分配的 `y`。

**命令行参数处理:**

代码中使用了 `base.Flag` 来获取编译器的标志。虽然没有直接列出具体的命令行参数处理逻辑，但可以推断一些相关的标志：

* **`-m`:**  用于控制编译器优化和诊断信息的输出级别。例如，`base.Flag.LowerM != 0` 会触发逃逸分析的警告信息输出。更大的 `-m` 值通常会输出更详细的信息。
* **`-gcflags`:** 可以传递给 Go 编译器，用于设置底层的 gc 编译器标志。这可能包含与逃逸分析相关的更底层的控制。

**易犯错的点 (使用者的角度):**

虽然逃逸分析是编译器自动进行的优化，但开发者理解其原理可以避免一些潜在的性能问题，并更好地理解 Go 的内存管理。一些容易犯错的点包括：

1. **不必要的指针传递:**  过度使用指针，即使在不需要共享数据或修改数据的情况下，也可能导致变量逃逸到堆上，增加 GC 压力。

   ```go
   package main

   type MyStruct struct {
       Value int
   }

   func process(s *MyStruct) { // 接收指针，可能导致 s 指向的对象逃逸
       fmt.Println(s.Value)
   }

   func main() {
       ms := MyStruct{Value: 10}
       process(&ms) // 将 ms 的地址传递给 process
   }
   ```

   在这个例子中，如果 `process` 函数不需要修改 `MyStruct` 的内容，可以考虑接收值类型，避免 `ms` 逃逸：

   ```go
   func process(s MyStruct) {
       fmt.Println(s.Value)
   }

   func main() {
       ms := MyStruct{Value: 10}
       process(ms)
   }
   ```

2. **闭包捕获:**  在闭包中捕获外部变量时，要注意捕获的方式（值捕获或引用捕获）。不小心捕获了大量数据的引用可能导致这些数据逃逸。

   ```go
   package main

   func createFunc() func() {
       largeData := [1000000]int{1} // 大量数据
       return func() {
           println(largeData[0]) // 捕获了 largeData 的引用
       }
   }

   func main() {
       f := createFunc()
       f()
   }
   ```

   在这个例子中，`largeData` 可能会逃逸到堆上，因为它被闭包捕获了。

3. **在函数外部访问局部变量的地址:**  像 `foo` 函数的例子一样，返回局部变量的地址是导致逃逸的常见原因。

**总结:**

`escape.go` 文件实现了 Go 编译器的逃逸分析功能，通过构建数据流图、追踪变量的赋值和取地址操作，来确定变量的分配位置，从而进行性能优化。理解逃逸分析的原理有助于开发者编写更高效的 Go 代码。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/escape/escape.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package escape

import (
	"fmt"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/src"
)

// Escape analysis.
//
// Here we analyze functions to determine which Go variables
// (including implicit allocations such as calls to "new" or "make",
// composite literals, etc.) can be allocated on the stack. The two
// key invariants we have to ensure are: (1) pointers to stack objects
// cannot be stored in the heap, and (2) pointers to a stack object
// cannot outlive that object (e.g., because the declaring function
// returned and destroyed the object's stack frame, or its space is
// reused across loop iterations for logically distinct variables).
//
// We implement this with a static data-flow analysis of the AST.
// First, we construct a directed weighted graph where vertices
// (termed "locations") represent variables allocated by statements
// and expressions, and edges represent assignments between variables
// (with weights representing addressing/dereference counts).
//
// Next we walk the graph looking for assignment paths that might
// violate the invariants stated above. If a variable v's address is
// stored in the heap or elsewhere that may outlive it, then v is
// marked as requiring heap allocation.
//
// To support interprocedural analysis, we also record data-flow from
// each function's parameters to the heap and to its result
// parameters. This information is summarized as "parameter tags",
// which are used at static call sites to improve escape analysis of
// function arguments.

// Constructing the location graph.
//
// Every allocating statement (e.g., variable declaration) or
// expression (e.g., "new" or "make") is first mapped to a unique
// "location."
//
// We also model every Go assignment as a directed edges between
// locations. The number of dereference operations minus the number of
// addressing operations is recorded as the edge's weight (termed
// "derefs"). For example:
//
//     p = &q    // -1
//     p = q     //  0
//     p = *q    //  1
//     p = **q   //  2
//
//     p = **&**&q  // 2
//
// Note that the & operator can only be applied to addressable
// expressions, and the expression &x itself is not addressable, so
// derefs cannot go below -1.
//
// Every Go language construct is lowered into this representation,
// generally without sensitivity to flow, path, or context; and
// without distinguishing elements within a compound variable. For
// example:
//
//     var x struct { f, g *int }
//     var u []*int
//
//     x.f = u[0]
//
// is modeled simply as
//
//     x = *u
//
// That is, we don't distinguish x.f from x.g, or u[0] from u[1],
// u[2], etc. However, we do record the implicit dereference involved
// in indexing a slice.

// A batch holds escape analysis state that's shared across an entire
// batch of functions being analyzed at once.
type batch struct {
	allLocs  []*location
	closures []closure

	heapLoc    location
	mutatorLoc location
	calleeLoc  location
	blankLoc   location
}

// A closure holds a closure expression and its spill hole (i.e.,
// where the hole representing storing into its closure record).
type closure struct {
	k   hole
	clo *ir.ClosureExpr
}

// An escape holds state specific to a single function being analyzed
// within a batch.
type escape struct {
	*batch

	curfn *ir.Func // function being analyzed

	labels map[*types.Sym]labelState // known labels

	// loopDepth counts the current loop nesting depth within
	// curfn. It increments within each "for" loop and at each
	// label with a corresponding backwards "goto" (i.e.,
	// unstructured loop).
	loopDepth int
}

func Funcs(all []*ir.Func) {
	ir.VisitFuncsBottomUp(all, Batch)
}

// Batch performs escape analysis on a minimal batch of
// functions.
func Batch(fns []*ir.Func, recursive bool) {
	var b batch
	b.heapLoc.attrs = attrEscapes | attrPersists | attrMutates | attrCalls
	b.mutatorLoc.attrs = attrMutates
	b.calleeLoc.attrs = attrCalls

	// Construct data-flow graph from syntax trees.
	for _, fn := range fns {
		if base.Flag.W > 1 {
			s := fmt.Sprintf("\nbefore escape %v", fn)
			ir.Dump(s, fn)
		}
		b.initFunc(fn)
	}
	for _, fn := range fns {
		if !fn.IsClosure() {
			b.walkFunc(fn)
		}
	}

	// We've walked the function bodies, so we've seen everywhere a
	// variable might be reassigned or have its address taken. Now we
	// can decide whether closures should capture their free variables
	// by value or reference.
	for _, closure := range b.closures {
		b.flowClosure(closure.k, closure.clo)
	}
	b.closures = nil

	for _, loc := range b.allLocs {
		if why := HeapAllocReason(loc.n); why != "" {
			b.flow(b.heapHole().addr(loc.n, why), loc)
		}
	}

	b.walkAll()
	b.finish(fns)
}

func (b *batch) with(fn *ir.Func) *escape {
	return &escape{
		batch:     b,
		curfn:     fn,
		loopDepth: 1,
	}
}

func (b *batch) initFunc(fn *ir.Func) {
	e := b.with(fn)
	if fn.Esc() != escFuncUnknown {
		base.Fatalf("unexpected node: %v", fn)
	}
	fn.SetEsc(escFuncPlanned)
	if base.Flag.LowerM > 3 {
		ir.Dump("escAnalyze", fn)
	}

	// Allocate locations for local variables.
	for _, n := range fn.Dcl {
		e.newLoc(n, true)
	}

	// Also for hidden parameters (e.g., the ".this" parameter to a
	// method value wrapper).
	if fn.OClosure == nil {
		for _, n := range fn.ClosureVars {
			e.newLoc(n.Canonical(), true)
		}
	}

	// Initialize resultIndex for result parameters.
	for i, f := range fn.Type().Results() {
		e.oldLoc(f.Nname.(*ir.Name)).resultIndex = 1 + i
	}
}

func (b *batch) walkFunc(fn *ir.Func) {
	e := b.with(fn)
	fn.SetEsc(escFuncStarted)

	// Identify labels that mark the head of an unstructured loop.
	ir.Visit(fn, func(n ir.Node) {
		switch n.Op() {
		case ir.OLABEL:
			n := n.(*ir.LabelStmt)
			if n.Label.IsBlank() {
				break
			}
			if e.labels == nil {
				e.labels = make(map[*types.Sym]labelState)
			}
			e.labels[n.Label] = nonlooping

		case ir.OGOTO:
			// If we visited the label before the goto,
			// then this is a looping label.
			n := n.(*ir.BranchStmt)
			if e.labels[n.Label] == nonlooping {
				e.labels[n.Label] = looping
			}
		}
	})

	e.block(fn.Body)

	if len(e.labels) != 0 {
		base.FatalfAt(fn.Pos(), "leftover labels after walkFunc")
	}
}

func (b *batch) flowClosure(k hole, clo *ir.ClosureExpr) {
	for _, cv := range clo.Func.ClosureVars {
		n := cv.Canonical()
		loc := b.oldLoc(cv)
		if !loc.captured {
			base.FatalfAt(cv.Pos(), "closure variable never captured: %v", cv)
		}

		// Capture by value for variables <= 128 bytes that are never reassigned.
		n.SetByval(!loc.addrtaken && !loc.reassigned && n.Type().Size() <= 128)
		if !n.Byval() {
			n.SetAddrtaken(true)
			if n.Sym().Name == typecheck.LocalDictName {
				base.FatalfAt(n.Pos(), "dictionary variable not captured by value")
			}
		}

		if base.Flag.LowerM > 1 {
			how := "ref"
			if n.Byval() {
				how = "value"
			}
			base.WarnfAt(n.Pos(), "%v capturing by %s: %v (addr=%v assign=%v width=%d)", n.Curfn, how, n, loc.addrtaken, loc.reassigned, n.Type().Size())
		}

		// Flow captured variables to closure.
		k := k
		if !cv.Byval() {
			k = k.addr(cv, "reference")
		}
		b.flow(k.note(cv, "captured by a closure"), loc)
	}
}

func (b *batch) finish(fns []*ir.Func) {
	// Record parameter tags for package export data.
	for _, fn := range fns {
		fn.SetEsc(escFuncTagged)

		for i, param := range fn.Type().RecvParams() {
			param.Note = b.paramTag(fn, 1+i, param)
		}
	}

	for _, loc := range b.allLocs {
		n := loc.n
		if n == nil {
			continue
		}

		if n.Op() == ir.ONAME {
			n := n.(*ir.Name)
			n.Opt = nil
		}

		// Update n.Esc based on escape analysis results.

		// Omit escape diagnostics for go/defer wrappers, at least for now.
		// Historically, we haven't printed them, and test cases don't expect them.
		// TODO(mdempsky): Update tests to expect this.
		goDeferWrapper := n.Op() == ir.OCLOSURE && n.(*ir.ClosureExpr).Func.Wrapper()

		if loc.hasAttr(attrEscapes) {
			if n.Op() == ir.ONAME {
				if base.Flag.CompilingRuntime {
					base.ErrorfAt(n.Pos(), 0, "%v escapes to heap, not allowed in runtime", n)
				}
				if base.Flag.LowerM != 0 {
					base.WarnfAt(n.Pos(), "moved to heap: %v", n)
				}
			} else {
				if base.Flag.LowerM != 0 && !goDeferWrapper {
					base.WarnfAt(n.Pos(), "%v escapes to heap", n)
				}
				if logopt.Enabled() {
					var e_curfn *ir.Func // TODO(mdempsky): Fix.
					logopt.LogOpt(n.Pos(), "escape", "escape", ir.FuncName(e_curfn))
				}
			}
			n.SetEsc(ir.EscHeap)
		} else {
			if base.Flag.LowerM != 0 && n.Op() != ir.ONAME && !goDeferWrapper {
				base.WarnfAt(n.Pos(), "%v does not escape", n)
			}
			n.SetEsc(ir.EscNone)
			if !loc.hasAttr(attrPersists) {
				switch n.Op() {
				case ir.OCLOSURE:
					n := n.(*ir.ClosureExpr)
					n.SetTransient(true)
				case ir.OMETHVALUE:
					n := n.(*ir.SelectorExpr)
					n.SetTransient(true)
				case ir.OSLICELIT:
					n := n.(*ir.CompLitExpr)
					n.SetTransient(true)
				}
			}
		}

		// If the result of a string->[]byte conversion is never mutated,
		// then it can simply reuse the string's memory directly.
		if base.Debug.ZeroCopy != 0 {
			if n, ok := n.(*ir.ConvExpr); ok && n.Op() == ir.OSTR2BYTES && !loc.hasAttr(attrMutates) {
				if base.Flag.LowerM >= 1 {
					base.WarnfAt(n.Pos(), "zero-copy string->[]byte conversion")
				}
				n.SetOp(ir.OSTR2BYTESTMP)
			}
		}
	}
}

// inMutualBatch reports whether function fn is in the batch of
// mutually recursive functions being analyzed. When this is true,
// fn has not yet been analyzed, so its parameters and results
// should be incorporated directly into the flow graph instead of
// relying on its escape analysis tagging.
func (b *batch) inMutualBatch(fn *ir.Name) bool {
	if fn.Defn != nil && fn.Defn.Esc() < escFuncTagged {
		if fn.Defn.Esc() == escFuncUnknown {
			base.FatalfAt(fn.Pos(), "graph inconsistency: %v", fn)
		}
		return true
	}
	return false
}

const (
	escFuncUnknown = 0 + iota
	escFuncPlanned
	escFuncStarted
	escFuncTagged
)

// Mark labels that have no backjumps to them as not increasing e.loopdepth.
type labelState int

const (
	looping labelState = 1 + iota
	nonlooping
)

func (b *batch) paramTag(fn *ir.Func, narg int, f *types.Field) string {
	name := func() string {
		if f.Nname != nil {
			return f.Nname.Sym().Name
		}
		return fmt.Sprintf("arg#%d", narg)
	}

	// Only report diagnostics for user code;
	// not for wrappers generated around them.
	// TODO(mdempsky): Generalize this.
	diagnose := base.Flag.LowerM != 0 && !(fn.Wrapper() || fn.Dupok())

	if len(fn.Body) == 0 {
		// Assume that uintptr arguments must be held live across the call.
		// This is most important for syscall.Syscall.
		// See golang.org/issue/13372.
		// This really doesn't have much to do with escape analysis per se,
		// but we are reusing the ability to annotate an individual function
		// argument and pass those annotations along to importing code.
		fn.Pragma |= ir.UintptrKeepAlive

		if f.Type.IsUintptr() {
			if diagnose {
				base.WarnfAt(f.Pos, "assuming %v is unsafe uintptr", name())
			}
			return ""
		}

		if !f.Type.HasPointers() { // don't bother tagging for scalars
			return ""
		}

		var esc leaks

		// External functions are assumed unsafe, unless
		// //go:noescape is given before the declaration.
		if fn.Pragma&ir.Noescape != 0 {
			if diagnose && f.Sym != nil {
				base.WarnfAt(f.Pos, "%v does not escape", name())
			}
			esc.AddMutator(0)
			esc.AddCallee(0)
		} else {
			if diagnose && f.Sym != nil {
				base.WarnfAt(f.Pos, "leaking param: %v", name())
			}
			esc.AddHeap(0)
		}

		return esc.Encode()
	}

	if fn.Pragma&ir.UintptrEscapes != 0 {
		if f.Type.IsUintptr() {
			if diagnose {
				base.WarnfAt(f.Pos, "marking %v as escaping uintptr", name())
			}
			return ""
		}
		if f.IsDDD() && f.Type.Elem().IsUintptr() {
			// final argument is ...uintptr.
			if diagnose {
				base.WarnfAt(f.Pos, "marking %v as escaping ...uintptr", name())
			}
			return ""
		}
	}

	if !f.Type.HasPointers() { // don't bother tagging for scalars
		return ""
	}

	// Unnamed parameters are unused and therefore do not escape.
	if f.Sym == nil || f.Sym.IsBlank() {
		var esc leaks
		return esc.Encode()
	}

	n := f.Nname.(*ir.Name)
	loc := b.oldLoc(n)
	esc := loc.paramEsc
	esc.Optimize()

	if diagnose && !loc.hasAttr(attrEscapes) {
		b.reportLeaks(f.Pos, name(), esc, fn.Type())
	}

	return esc.Encode()
}

func (b *batch) reportLeaks(pos src.XPos, name string, esc leaks, sig *types.Type) {
	warned := false
	if x := esc.Heap(); x >= 0 {
		if x == 0 {
			base.WarnfAt(pos, "leaking param: %v", name)
		} else {
			// TODO(mdempsky): Mention level=x like below?
			base.WarnfAt(pos, "leaking param content: %v", name)
		}
		warned = true
	}
	for i := 0; i < numEscResults; i++ {
		if x := esc.Result(i); x >= 0 {
			res := sig.Result(i).Nname.Sym().Name
			base.WarnfAt(pos, "leaking param: %v to result %v level=%d", name, res, x)
			warned = true
		}
	}

	if base.Debug.EscapeMutationsCalls <= 0 {
		if !warned {
			base.WarnfAt(pos, "%v does not escape", name)
		}
		return
	}

	if x := esc.Mutator(); x >= 0 {
		base.WarnfAt(pos, "mutates param: %v derefs=%v", name, x)
		warned = true
	}
	if x := esc.Callee(); x >= 0 {
		base.WarnfAt(pos, "calls param: %v derefs=%v", name, x)
		warned = true
	}

	if !warned {
		base.WarnfAt(pos, "%v does not escape, mutate, or call", name)
	}
}

"""



```