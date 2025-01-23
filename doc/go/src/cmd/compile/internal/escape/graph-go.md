Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a functional description of the `graph.go` code, potential Go language features it implements, example usage, command-line parameter handling, and common pitfalls.

2. **High-Level Overview (Skimming):**  A quick read reveals terms like `location`, `edge`, `hole`, `flow`, `escape`, `derefs`, `attrs`. This strongly suggests the code is related to **escape analysis**, a compiler optimization technique. The package name `escape` reinforces this. The comments mentioning "data flow edges" and "walking the AST" further support this.

3. **Key Data Structures Analysis:**

   * **`location`:** Represents a variable or expression's abstract location. Key fields include `n` (the IR node), `edges` (incoming assignments), `loopDepth`, `attrs` (like `attrEscapes`), `paramEsc`, `captured`, `reassigned`, and `addrtaken`. These fields are clearly designed to track properties relevant to escape analysis: where a variable is, how it's assigned, its lifetime (loop depth), and whether it might escape the stack.

   * **`edge`:** Represents an assignment relationship between two `location`s, including the number of dereferences (`derefs`). This is crucial for understanding how data flows through the program.

   * **`hole`:**  Represents a context for evaluating an expression, with a destination `location` (`dst`) and dereference count. The `addrtaken` flag is also important. This structure appears to be a way to temporarily hold information about an expression being evaluated and how its value will be used.

   * **`note`:** Seems to be for debugging or logging, attaching information about *why* a particular flow or escape occurs.

4. **Core Functionality Identification:**

   * **`flow(k hole, src *location)`:** This function seems central. It connects a source `location` to a destination specified by the `hole`. The logic inside checks for escape conditions (`dst.hasAttr(attrEscapes) && k.derefs < 0`) and updates the `src` `location`'s attributes if it escapes.

   * **`newLoc(n ir.Node, persists bool)`:**  Creates a new `location` object, associating it with an IR node. This is likely used when processing declarations and variable usages.

   * **`teeHole(ks ...hole)`:**  A helper for creating a fan-out of assignments, simulating multiple uses of the same expression.

   * **`later(k hole)`:**  Seems to delay the flow, possibly for optimization ordering.

   * **`leakTo(...)`:**  Explicitly records that a parameter "leaks" to another location (or the heap). This ties into the concept of escape.

5. **Inferring Go Feature Implementation:** Based on the code's purpose (escape analysis) and the data structures, it's reasonable to conclude that this code is part of the Go compiler's **escape analysis** implementation. This optimization determines whether a variable needs to be allocated on the heap or can reside on the stack.

6. **Constructing a Go Example:** To illustrate escape analysis, a simple example with and without escaping behavior is necessary. The key is to demonstrate a scenario where a variable's address is taken and passed outside its defining scope (leading to heap allocation).

7. **Considering Command-Line Parameters:**  The code imports `cmd/compile/internal/base`. Looking at the `base.Flag` usage suggests that command-line flags, particularly those related to logging and debugging (`-m`), might influence the behavior (e.g., printing escape analysis details).

8. **Identifying Common Pitfalls:** Understanding *why* escape analysis is important helps identify potential mistakes. Common issues include:
   * **Unintended heap allocation:** When developers don't realize their code forces a variable to the heap, leading to performance overhead.
   * **Misunderstanding value vs. pointer semantics:** Incorrectly assuming a value type will remain on the stack when its address is taken.

9. **Structuring the Output:**  Organize the findings logically, following the prompt's structure:
   * Functionality summary.
   * Go feature explanation.
   * Go code example with assumptions and output.
   * Command-line parameter details.
   * Common pitfalls with examples.

10. **Refinement and Details:**  Review the code again for specific details:
    * The role of `loopDepth`.
    * The different attributes in `locAttr`.
    * The meaning of `derefs` in `edge` and `hole`.
    * The purpose of `resultIndex` for function return values.

By following these steps, one can systematically analyze the provided Go code snippet and generate a comprehensive explanation of its functionality and context within the Go compiler. The key is to connect the code elements to the underlying concept of escape analysis.`go/src/cmd/compile/internal/escape/graph.go` 的代码实现了 Go 语言编译器中 **逃逸分析** 的关键部分，具体来说，它负责构建和维护一个 **数据流图**，用于跟踪程序中变量的赋值和使用情况，从而判断哪些变量需要分配在堆上（发生逃逸），哪些可以安全地分配在栈上。

以下是该代码的主要功能点：

**1. 定义了数据结构来表示数据流图：**

* **`location`:**  表示程序中的一个抽象位置，可以是一个变量、表达式或函数的返回值。它存储了与该位置相关的逃逸分析信息，例如：
    * `n`:  代表该位置的抽象语法树节点 (`ir.Node`)。
    * `curfn`:  该位置所属的函数 (`*ir.Func`)。
    * `edges`:  指向该位置的赋值边 (`[]edge`)，表示哪些位置的值流向了这里。
    * `loopDepth`:  该位置声明时的循环嵌套深度。
    * `attrs`:  一组位标志 (`locAttr`)，用于记录该位置的属性，例如是否发生逃逸 (`attrEscapes`)、是否持久存在 (`attrPersists`) 等。
    * `paramEsc`:  用于记录函数参数的逃逸信息 (`leaks`)。
    * `captured`:  是否被闭包捕获。
    * `reassigned`:  是否被重新赋值。
    * `addrtaken`:  是否被取地址。
* **`edge`:**  表示两个 `location` 之间的赋值关系，包含：
    * `src`:  赋值的源 `location`。
    * `derefs`:  源 `location` 需要解引用的次数，例如 `a = *b`，则 `derefs` 为 1。
    * `notes`:  用于记录一些调试或解释信息 (`*note`)。
* **`hole`:**  表示一个表达式的求值上下文，包含了赋值的目标 `location` (`dst`) 和需要的解引用次数 (`derefs`)。可以理解为赋值语句的左侧部分。
* **`note`:**  用于记录一些附加信息，例如在哪个 AST 节点以及为什么创建了这个边。

**2. 提供了操作数据流图的方法：**

* **`leakTo(l *location, sink *location, derefs int)` / `leakTo(b *batch, l *location, sink *location, derefs int)`:** 记录从 `l` 位置的值流向 `sink` 位置，并可能导致逃逸。根据目标位置是否为不逃逸的返回值，分别记录为结果逃逸或堆逃逸。
* **`flow(k hole, src *location)`:**  将源 `location` 的值流向目标 `hole` 指定的位置。这是构建数据流图的核心操作。它会检查是否发生逃逸，并更新源 `location` 的属性。
* **`newLoc(n ir.Node, persists bool)`:**  创建一个新的 `location` 对象，并将其与 AST 节点关联起来。
* **`teeHole(ks ...hole)`:**  创建一个新的 `hole`，它的值会流向多个其他的 `hole`，类似于 Unix 的 `tee` 命令。
* **`later(k hole)`:**  创建一个新的 `hole`，它接收 `k` 的值，但会延迟处理，用于优化变量的复用。
* **`asHole()` (在 `location` 上):** 将一个 `location` 转换为一个源 `hole`。
* **`discardHole()` (在 `batch` 上):** 返回一个表示丢弃值的 `hole`。
* **`heapHole()` / `mutatorHole()` / `calleeHole()` (在 `batch` 上):** 返回一些特殊的 `hole`，用于表示堆、内存修改操作、函数调用等。
* **`shift(delta int)` / `deref(where ir.Node, why string)` / `addr(where ir.Node, why string)` / `dotType(t *types.Type, where ir.Node, why string)` (在 `hole` 上):**  用于调整 `hole` 的解引用次数和记录相关信息。

**3. 辅助方法：**

* **`isName(c ir.Class)` (在 `location` 上):** 判断 `location` 代表的节点是否是指定类型的变量名。
* **`oldLoc(n *ir.Name)` (在 `batch` 上):** 获取一个已存在的变量名的 `location`。
* **`note(where ir.Node, why string)` (在 `hole` 上):**  为 `hole` 添加一个注释。
* **`hasAttr(attr locAttr)` (在 `location` 上):** 检查 `location` 是否具有指定的属性。
* **`Fmt(n ir.Node)`:**  用于格式化输出节点的逃逸分析信息。

**推理其实现的 Go 语言功能：逃逸分析**

正如前面所说，这段代码的核心目标是实现 Go 语言的 **逃逸分析 (Escape Analysis)**。逃逸分析是 Go 编译器的一项重要优化技术，用于决定一个变量应该分配在栈上还是堆上。

* **栈分配:**  速度快，生命周期与函数调用相关，函数返回时自动回收。
* **堆分配:**  需要垃圾回收，速度相对慢，生命周期更长。

逃逸分析的目标是尽可能地将变量分配在栈上，以提高程序的性能并减少垃圾回收的压力。

**Go 代码举例说明：**

```go
package main

func foo() *int {
	x := 10 // x 可能分配在栈上
	return &x // &x 导致 x 逃逸到堆上
}

func bar() int {
	y := 20 // y 很可能分配在栈上，因为没有被外部引用
	return y
}

func main() {
	ptr := foo()
	println(*ptr)

	val := bar()
	println(val)
}
```

**代码推理与假设的输入输出：**

**假设输入：** 上述 `main.go` 的抽象语法树（由 `cmd/compile/internal/gc` 生成）。

**`foo` 函数的逃逸分析过程（简化）：**

1. **`x := 10`:**  在 `foo` 函数中创建一个 `location` 对象来表示变量 `x`。初始状态，假设 `x` 可以分配在栈上。
2. **`return &x`:**  创建 `hole` 来表示 `&x` 这个表达式，目标是函数的返回值位置。`hole` 的 `derefs` 为 -1（取地址）。
3. **`flow(返回值hole, x的location)`:**  调用 `flow` 函数，发现目标 `hole` 是函数的返回值，并且发生了取地址操作 (`derefs < 0`)。
4. **逃逸判断:**  根据 `flow` 函数的逻辑，因为返回值可能在 `foo` 函数返回后被使用，且 `x` 的地址被返回，所以 `x` 的 `location` 的 `attrEscapes` 标志会被设置为 true。
5. **结果:**  逃逸分析器会标记 `x` 需要在堆上分配。

**`bar` 函数的逃逸分析过程（简化）：**

1. **`y := 20`:**  在 `bar` 函数中创建一个 `location` 对象来表示变量 `y`。
2. **`return y`:**  创建 `hole` 来表示返回值，目标是函数的返回值位置。
3. **`flow(返回值hole, y的location)`:** 调用 `flow` 函数，没有发生取地址或其他可能导致逃逸的操作。
4. **结果:**  逃逸分析器会判断 `y` 可以安全地分配在栈上。

**假设输出（`Fmt` 函数可能的输出）：**

如果编译器在编译 `main.go` 时开启了逃逸分析相关的输出，可能会看到类似这样的信息：

```
./main.go:4:6: can inline foo
./main.go:8:6: can inline bar
./main.go:5:2: leaking param: &x to result ~r0 level=0
./main.go:5:2: x escapes to heap
./main.go:14:2: moved to heap: x
```

这里的 `"escapes to heap"` 表明变量 `x` 发生了逃逸。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。命令行参数的处理通常在 `cmd/compile/internal/gc` 包中进行。但是，`graph.go` 中会使用到 `cmd/compile/internal/base` 包，该包可能会定义一些影响逃逸分析行为的标志。

常见的与逃逸分析相关的 Go 编译器命令行参数（通常通过 `-gcflags` 传递给 `go build`）：

* **`-m`:** 打印编译优化信息，包括逃逸分析的决策。使用 `-m=2` 可以获得更详细的逃逸分析信息。
* **`-l`:**  禁用内联优化。内联可能会影响逃逸分析的结果。
* **`-N`:**  禁用所有的优化，包括逃逸分析。

**例如：**

```bash
go build -gcflags="-m" main.go  # 查看基本的逃逸分析信息
go build -gcflags="-m=2" main.go # 查看更详细的逃逸分析信息
go build -gcflags="-l" main.go   # 禁用内联，观察对逃逸分析的影响
```

在 `graph.go` 中，可以看到对 `base.Flag.LowerM >= 2` 的判断，这表明代码会根据 `-m` 标志的值来输出更详细的日志信息。

**使用者易犯错的点：**

使用者通常不需要直接与 `graph.go` 交互，因为它是编译器内部的实现细节。然而，理解逃逸分析对于编写高性能的 Go 代码非常重要。

**易犯错的点：**

1. **不理解哪些操作会导致逃逸:**  例如，将局部变量的指针返回给外部、将局部变量赋值给全局变量、向 `interface{}` 类型的变量赋值非指针类型的值等都可能导致逃逸。

   ```go
   package main

   type MyInt int

   func willEscape() interface{} {
       i := MyInt(10)
       return i // MyInt 会逃逸，因为发生了装箱
   }

   func wontEscape() interface{} {
       i := 10
       return i // int 也可能逃逸，取决于编译器的优化
   }

   func main() {
       _ = willEscape()
       _ = wontEscape()
   }
   ```

2. **过度关注不必要的逃逸:**  虽然逃逸到堆上会有一定的性能开销，但现代 Go 编译器的逃逸分析已经非常智能，很多情况下即使发生了逃逸，性能影响也很小。过早优化或过度关注不重要的逃逸可能会浪费时间。

3. **错误地认为使用指针总是导致逃逸:**  虽然返回局部变量的指针会导致逃逸，但在函数内部传递指针并不一定总是会发生逃逸。编译器会进行分析，如果指针没有超出其作用域，仍然可能分配在栈上。

**总结：**

`go/src/cmd/compile/internal/escape/graph.go` 是 Go 语言编译器逃逸分析的核心组成部分，它负责构建和维护数据流图，用于跟踪变量的赋值和使用，最终决定变量的分配位置。理解逃逸分析的原理对于编写高效的 Go 代码至关重要，但开发者通常不需要直接操作此文件。

### 提示词
```
这是路径为go/src/cmd/compile/internal/escape/graph.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package escape

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/types"
	"fmt"
)

// Below we implement the methods for walking the AST and recording
// data flow edges. Note that because a sub-expression might have
// side-effects, it's important to always visit the entire AST.
//
// For example, write either:
//
//     if x {
//         e.discard(n.Left)
//     } else {
//         e.value(k, n.Left)
//     }
//
// or
//
//     if x {
//         k = e.discardHole()
//     }
//     e.value(k, n.Left)
//
// Do NOT write:
//
//    // BAD: possibly loses side-effects within n.Left
//    if !x {
//        e.value(k, n.Left)
//    }

// A location represents an abstract location that stores a Go
// variable.
type location struct {
	n         ir.Node  // represented variable or expression, if any
	curfn     *ir.Func // enclosing function
	edges     []edge   // incoming edges
	loopDepth int      // loopDepth at declaration

	// resultIndex records the tuple index (starting at 1) for
	// PPARAMOUT variables within their function's result type.
	// For non-PPARAMOUT variables it's 0.
	resultIndex int

	// derefs and walkgen are used during walkOne to track the
	// minimal dereferences from the walk root.
	derefs  int // >= -1
	walkgen uint32

	// dst and dstEdgeindex track the next immediate assignment
	// destination location during walkone, along with the index
	// of the edge pointing back to this location.
	dst        *location
	dstEdgeIdx int

	// queued is used by walkAll to track whether this location is
	// in the walk queue.
	queued bool

	// attrs is a bitset of location attributes.
	attrs locAttr

	// paramEsc records the represented parameter's leak set.
	paramEsc leaks

	captured   bool // has a closure captured this variable?
	reassigned bool // has this variable been reassigned?
	addrtaken  bool // has this variable's address been taken?
}

type locAttr uint8

const (
	// attrEscapes indicates whether the represented variable's address
	// escapes; that is, whether the variable must be heap allocated.
	attrEscapes locAttr = 1 << iota

	// attrPersists indicates whether the represented expression's
	// address outlives the statement; that is, whether its storage
	// cannot be immediately reused.
	attrPersists

	// attrMutates indicates whether pointers that are reachable from
	// this location may have their addressed memory mutated. This is
	// used to detect string->[]byte conversions that can be safely
	// optimized away.
	attrMutates

	// attrCalls indicates whether closures that are reachable from this
	// location may be called without tracking their results. This is
	// used to better optimize indirect closure calls.
	attrCalls
)

func (l *location) hasAttr(attr locAttr) bool { return l.attrs&attr != 0 }

// An edge represents an assignment edge between two Go variables.
type edge struct {
	src    *location
	derefs int // >= -1
	notes  *note
}

func (l *location) asHole() hole {
	return hole{dst: l}
}

// leak records that parameter l leaks to sink.
func (l *location) leakTo(sink *location, derefs int) {
	// If sink is a result parameter that doesn't escape (#44614)
	// and we can fit return bits into the escape analysis tag,
	// then record as a result leak.
	if !sink.hasAttr(attrEscapes) && sink.isName(ir.PPARAMOUT) && sink.curfn == l.curfn {
		ri := sink.resultIndex - 1
		if ri < numEscResults {
			// Leak to result parameter.
			l.paramEsc.AddResult(ri, derefs)
			return
		}
	}

	// Otherwise, record as heap leak.
	l.paramEsc.AddHeap(derefs)
}

// leakTo records that parameter l leaks to sink.
func (b *batch) leakTo(l, sink *location, derefs int) {
	if (logopt.Enabled() || base.Flag.LowerM >= 2) && !l.hasAttr(attrEscapes) {
		if base.Flag.LowerM >= 2 {
			fmt.Printf("%s: parameter %v leaks to %s with derefs=%d:\n", base.FmtPos(l.n.Pos()), l.n, b.explainLoc(sink), derefs)
		}
		explanation := b.explainPath(sink, l)
		if logopt.Enabled() {
			var e_curfn *ir.Func // TODO(mdempsky): Fix.
			logopt.LogOpt(l.n.Pos(), "leak", "escape", ir.FuncName(e_curfn),
				fmt.Sprintf("parameter %v leaks to %s with derefs=%d", l.n, b.explainLoc(sink), derefs), explanation)
		}
	}

	// If sink is a result parameter that doesn't escape (#44614)
	// and we can fit return bits into the escape analysis tag,
	// then record as a result leak.
	if !sink.hasAttr(attrEscapes) && sink.isName(ir.PPARAMOUT) && sink.curfn == l.curfn {
		if ri := sink.resultIndex - 1; ri < numEscResults {
			// Leak to result parameter.
			l.paramEsc.AddResult(ri, derefs)
			return
		}
	}

	// Otherwise, record as heap leak.
	l.paramEsc.AddHeap(derefs)
}

func (l *location) isName(c ir.Class) bool {
	return l.n != nil && l.n.Op() == ir.ONAME && l.n.(*ir.Name).Class == c
}

// A hole represents a context for evaluation of a Go
// expression. E.g., when evaluating p in "x = **p", we'd have a hole
// with dst==x and derefs==2.
type hole struct {
	dst    *location
	derefs int // >= -1
	notes  *note

	// addrtaken indicates whether this context is taking the address of
	// the expression, independent of whether the address will actually
	// be stored into a variable.
	addrtaken bool
}

type note struct {
	next  *note
	where ir.Node
	why   string
}

func (k hole) note(where ir.Node, why string) hole {
	if where == nil || why == "" {
		base.Fatalf("note: missing where/why")
	}
	if base.Flag.LowerM >= 2 || logopt.Enabled() {
		k.notes = &note{
			next:  k.notes,
			where: where,
			why:   why,
		}
	}
	return k
}

func (k hole) shift(delta int) hole {
	k.derefs += delta
	if k.derefs < -1 {
		base.Fatalf("derefs underflow: %v", k.derefs)
	}
	k.addrtaken = delta < 0
	return k
}

func (k hole) deref(where ir.Node, why string) hole { return k.shift(1).note(where, why) }
func (k hole) addr(where ir.Node, why string) hole  { return k.shift(-1).note(where, why) }

func (k hole) dotType(t *types.Type, where ir.Node, why string) hole {
	if !t.IsInterface() && !types.IsDirectIface(t) {
		k = k.shift(1)
	}
	return k.note(where, why)
}

func (b *batch) flow(k hole, src *location) {
	if k.addrtaken {
		src.addrtaken = true
	}

	dst := k.dst
	if dst == &b.blankLoc {
		return
	}
	if dst == src && k.derefs >= 0 { // dst = dst, dst = *dst, ...
		return
	}
	if dst.hasAttr(attrEscapes) && k.derefs < 0 { // dst = &src
		if base.Flag.LowerM >= 2 || logopt.Enabled() {
			pos := base.FmtPos(src.n.Pos())
			if base.Flag.LowerM >= 2 {
				fmt.Printf("%s: %v escapes to heap:\n", pos, src.n)
			}
			explanation := b.explainFlow(pos, dst, src, k.derefs, k.notes, []*logopt.LoggedOpt{})
			if logopt.Enabled() {
				var e_curfn *ir.Func // TODO(mdempsky): Fix.
				logopt.LogOpt(src.n.Pos(), "escapes", "escape", ir.FuncName(e_curfn), fmt.Sprintf("%v escapes to heap", src.n), explanation)
			}

		}
		src.attrs |= attrEscapes | attrPersists | attrMutates | attrCalls
		return
	}

	// TODO(mdempsky): Deduplicate edges?
	dst.edges = append(dst.edges, edge{src: src, derefs: k.derefs, notes: k.notes})
}

func (b *batch) heapHole() hole    { return b.heapLoc.asHole() }
func (b *batch) mutatorHole() hole { return b.mutatorLoc.asHole() }
func (b *batch) calleeHole() hole  { return b.calleeLoc.asHole() }
func (b *batch) discardHole() hole { return b.blankLoc.asHole() }

func (b *batch) oldLoc(n *ir.Name) *location {
	if n.Canonical().Opt == nil {
		base.FatalfAt(n.Pos(), "%v has no location", n)
	}
	return n.Canonical().Opt.(*location)
}

func (e *escape) newLoc(n ir.Node, persists bool) *location {
	if e.curfn == nil {
		base.Fatalf("e.curfn isn't set")
	}
	if n != nil && n.Type() != nil && n.Type().NotInHeap() {
		base.ErrorfAt(n.Pos(), 0, "%v is incomplete (or unallocatable); stack allocation disallowed", n.Type())
	}

	if n != nil && n.Op() == ir.ONAME {
		if canon := n.(*ir.Name).Canonical(); n != canon {
			base.FatalfAt(n.Pos(), "newLoc on non-canonical %v (canonical is %v)", n, canon)
		}
	}
	loc := &location{
		n:         n,
		curfn:     e.curfn,
		loopDepth: e.loopDepth,
	}
	if persists {
		loc.attrs |= attrPersists
	}
	e.allLocs = append(e.allLocs, loc)
	if n != nil {
		if n.Op() == ir.ONAME {
			n := n.(*ir.Name)
			if n.Class == ir.PPARAM && n.Curfn == nil {
				// ok; hidden parameter
			} else if n.Curfn != e.curfn {
				base.FatalfAt(n.Pos(), "curfn mismatch: %v != %v for %v", n.Curfn, e.curfn, n)
			}

			if n.Opt != nil {
				base.FatalfAt(n.Pos(), "%v already has a location", n)
			}
			n.Opt = loc
		}
	}
	return loc
}

// teeHole returns a new hole that flows into each hole of ks,
// similar to the Unix tee(1) command.
func (e *escape) teeHole(ks ...hole) hole {
	if len(ks) == 0 {
		return e.discardHole()
	}
	if len(ks) == 1 {
		return ks[0]
	}
	// TODO(mdempsky): Optimize if there's only one non-discard hole?

	// Given holes "l1 = _", "l2 = **_", "l3 = *_", ..., create a
	// new temporary location ltmp, wire it into place, and return
	// a hole for "ltmp = _".
	loc := e.newLoc(nil, false)
	for _, k := range ks {
		// N.B., "p = &q" and "p = &tmp; tmp = q" are not
		// semantically equivalent. To combine holes like "l1
		// = _" and "l2 = &_", we'd need to wire them as "l1 =
		// *ltmp" and "l2 = ltmp" and return "ltmp = &_"
		// instead.
		if k.derefs < 0 {
			base.Fatalf("teeHole: negative derefs")
		}

		e.flow(k, loc)
	}
	return loc.asHole()
}

// later returns a new hole that flows into k, but some time later.
// Its main effect is to prevent immediate reuse of temporary
// variables introduced during Order.
func (e *escape) later(k hole) hole {
	loc := e.newLoc(nil, true)
	e.flow(k, loc)
	return loc.asHole()
}

// Fmt is called from node printing to print information about escape analysis results.
func Fmt(n ir.Node) string {
	text := ""
	switch n.Esc() {
	case ir.EscUnknown:
		break

	case ir.EscHeap:
		text = "esc(h)"

	case ir.EscNone:
		text = "esc(no)"

	case ir.EscNever:
		text = "esc(N)"

	default:
		text = fmt.Sprintf("esc(%d)", n.Esc())
	}

	if n.Op() == ir.ONAME {
		n := n.(*ir.Name)
		if loc, ok := n.Opt.(*location); ok && loc.loopDepth != 0 {
			if text != "" {
				text += " "
			}
			text += fmt.Sprintf("ld(%d)", loc.loopDepth)
		}
	}

	return text
}
```