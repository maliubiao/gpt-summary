Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding of the Goal:**

The request asks for the functionality of the code, what Go feature it relates to, illustrative examples, and potential pitfalls for users. The file path `go/src/cmd/compile/internal/escape/expr.go` immediately suggests this is part of the Go compiler's escape analysis mechanism.

**2. Deconstructing the Code - Function by Function:**

* **`expr(k hole, n ir.Node)`:**  This is clearly the central function. It takes a `hole` and an `ir.Node`. The `hole` type (not shown here, but inferable) likely represents a destination for data flow, and `ir.Node` is an abstract syntax tree node representing a Go expression. The function's name "expr" strongly suggests it's about *evaluating* expressions. The call to `e.stmts(n.Init())` indicates handling initialization code associated with the expression. The call to `e.exprSkipInit` suggests separating the core evaluation logic from initialization.

* **`exprSkipInit(k hole, n ir.Node)`:**  This function contains a large `switch` statement based on `n.Op()`. This pattern is common in compiler code for handling different kinds of expressions. The different `case` blocks are clearly dealing with various Go expression types (literals, variables, operators, function calls, etc.). The calls to functions like `e.flow`, `e.discard`, `e.spill`, `e.call`, `e.assignHeap`, and `e.unsafeValue` within the `case` blocks give clues about the specific actions taken for each expression type in the context of escape analysis.

* **`unsafeValue(k hole, n ir.Node)`:** This function deals specifically with `uintptr` and unsafe pointer conversions. The comments within the `OCONV` case confirm that this is related to detecting potential escapes when converting to `unsafe.Pointer`.

* **`discard(n ir.Node)`:**  This appears to evaluate an expression solely for its side effects, ignoring the resulting value. The call to `e.expr(e.discardHole(), n)` reinforces this.

* **`discards(l ir.Nodes)`:** A simple helper to discard a list of expressions.

* **`spill(k hole, n ir.Node)`:** This function seems crucial. The name "spill" and the code `e.newLoc(n, false)` strongly suggest it's related to allocating memory (likely on the stack or heap, depending on the escape analysis). The call to `e.flow(k.addr(n, "spill"), loc)` indicates flowing the *address* of the allocated memory to the `hole`.

**3. Identifying the Core Functionality - Escape Analysis:**

Based on the file path, the function names, and the operations within the `switch` statement (handling addresses, dereferences, allocations, etc.), it becomes clear that this code implements a part of Go's *escape analysis*. Escape analysis determines whether a variable's lifetime extends beyond the function in which it's created, and thus needs to be allocated on the heap rather than the stack.

**4. Reasoning about Specific Cases:**

* **Literals (`ir.OLITERAL`, `ir.ONIL`):**  These don't typically escape, hence "nop".
* **Variables (`ir.ONAME`):**  The code checks if it's a function name and otherwise flows the location (`e.flow`). This is core to tracking variable usage.
* **Address-of (`ir.OADDR`):** The address of an expression is being taken, which might cause it to escape.
* **Dereference (`ir.ODEREF`):** Dereferencing a pointer accesses the pointed-to memory, which needs to be tracked.
* **Function Calls (`ir.OCALLMETH`, `ir.OCALLFUNC`):** Function call arguments and return values are crucial for escape analysis.
* **`new` and `make` (`ir.ONEW`, `ir.OMAKESLICE`):** These allocate memory, so the `spill` function is used.
* **Conversions to `unsafe.Pointer` (`ir.OCONV`):**  These are potential escape points due to the loss of type safety.
* **Closures (`ir.OCLOSURE`):** Capturing variables in closures is a major cause of escaping.

**5. Constructing Examples:**

With the understanding of escape analysis, the examples become relatively straightforward. Demonstrate cases where variables likely *don't* escape (basic local variables) and cases where they *do* escape (passing pointers to functions, returning pointers, using closures).

**6. Identifying Potential Pitfalls:**

Focus on areas where the compiler's behavior might be surprising to developers. The interaction between `unsafe.Pointer` and escape analysis is a good example. Implicit allocations due to interface conversions can also be a source of confusion.

**7. Refining the Explanation:**

Organize the findings logically. Start with the main purpose, explain the key functions, provide code examples with clear assumptions and outputs (even if the "output" is conceptual in terms of escape), and then discuss potential pitfalls. Use the terminology from the code (like "hole" and the `ir` node types) where appropriate, but also explain them in a user-friendly way.

This systematic approach of dissecting the code, understanding the underlying concept (escape analysis), and then building examples and identifying potential issues is crucial for analyzing and explaining complex compiler code.
这段代码是 Go 编译器中 **逃逸分析 (Escape Analysis)** 的一部分，具体来说，它负责分析各种 Go 语言表达式，并判断表达式中的变量或值是否会逃逸到堆上。

**功能列举:**

1. **`expr(k hole, n ir.Node)`:**
   - 这是处理表达式的核心入口函数。
   - 它接收两个参数：
     - `k hole`:  代表数据流向的目标位置或“接收者”。可以理解为一个“洞”，表达式的结果将被“流入”这个洞。
     - `n ir.Node`: 代表要分析的 Go 语言表达式的抽象语法树 (AST) 节点。
   - 它首先处理表达式的初始化语句 (`n.Init()`)。
   - 然后调用 `exprSkipInit` 函数来处理表达式本身，跳过初始化部分。

2. **`exprSkipInit(k hole, n ir.Node)`:**
   - 这是实际分析各种表达式类型的函数。
   - 它通过 `switch n.Op()` 来判断表达式的类型，并根据不同的类型进行不同的逃逸分析处理。
   - 对于每种表达式，它可能会执行以下操作：
     - **忽略 (nop):** 对于不会引起逃逸的字面量、nil 值等。
     - **数据流分析 (`e.flow`):** 将表达式的值或地址“流入”到目标 `hole`。
     - **丢弃 (`e.discard`):**  评估表达式的副作用，但忽略其返回值，表示该值不会逃逸。
     - **分配到堆 (`e.spill`):**  强制将表达式的结果分配到堆上。
     - **调用分析 (`e.call`):** 分析函数调用，包括参数和返回值。
     - **处理 `unsafe.Pointer` 转换 (`e.unsafeValue`):** 特殊处理涉及 `unsafe.Pointer` 的转换。
     - **处理闭包 (`e.OCLOSURE`):**  分析闭包捕获的变量。
     - **处理复合字面量 (`ir.OARRAYLIT`, `ir.OSLICELIT`, `ir.OSTRUCTLIT`, `ir.OMAPLIT`):** 分析复合字面量中的元素。

3. **`unsafeValue(k hole, n ir.Node)`:**
   - 专门处理 `uintptr` 类型的表达式，特别是那些可能涉及从 `unsafe.Pointer` 转换来的值。
   - 用于跟踪 `unsafe.Pointer` 的使用，因为不当使用可能导致内存安全问题。

4. **`discard(n ir.Node)`:**
   - 用于评估一个表达式的副作用，但不关心其结果是否逃逸。
   - 例如，对于一个只改变了某个变量值的表达式，我们可能只需要知道这个副作用发生了。

5. **`discards(l ir.Nodes)`:**
   - 简单地对一个表达式列表中的每个表达式调用 `discard`。

6. **`spill(k hole, n ir.Node)`:**
   - 这个函数非常关键，它表示将表达式 `n` 的值强制分配到堆上。
   - 它创建一个新的位置 (`e.newLoc`)，并将该位置的地址“流入”到目标 `hole`。
   - 返回一个新的 `hole`，用于将值写入到新分配的堆内存中。

**它是什么 Go 语言功能的实现：**

这段代码是 Go 编译器进行 **逃逸分析 (Escape Analysis)** 的核心实现之一。逃逸分析是 Go 编译器的一项重要优化技术，它用于决定变量应该分配在栈上还是堆上。

**Go 代码示例说明:**

```go
package main

func foo() *int {
	x := 10 // x 可能逃逸，因为它被返回了指针
	return &x
}

func bar() int {
	y := 20 // y 不会逃逸，因为它只在 bar 函数内部使用
	return y
}

func main() {
	ptr := foo()
	println(*ptr)
	val := bar()
	println(val)
}
```

**假设输入与输出 (针对 `expr` 函数):**

假设我们正在分析 `foo()` 函数中的 `&x` 表达式。

**假设输入:**

- `k`: 一个表示 `foo()` 函数返回值的 `hole`。
- `n`:  一个 `ir.AddrExpr` 节点，表示取地址操作 `&x`。
- `n.X`: 一个 `ir.Name` 节点，表示变量 `x`。

**代码推理 (涉及到的 `exprSkipInit` 的 `ir.OADDR` 分支):**

1. `exprSkipInit` 函数会进入 `case ir.OADDR:` 分支。
2. 它会创建一个新的 `hole`，记为 `k_addr`，并调用 `k.addr(n, "address-of")`，表示这是因为取地址操作导致的。
3. 递归调用 `e.expr(k_addr, n.X)`，即分析变量 `x` 本身，并将结果流入 `k_addr`。
4. 在分析 `x` 时，`exprSkipInit` 会进入 `case ir.ONAME:` 分支，并调用 `e.flow(k_addr, e.oldLoc(n.X))`，将变量 `x` 的位置信息与 `k_addr` 关联起来。

**假设输出 (基于逃逸分析的结果):**

- 逃逸分析器会判断 `x` 的地址被返回，因此 `x` 必须逃逸到堆上。
- `spill` 函数可能会被调用来为 `x` 在堆上分配内存。
- 最终，`foo()` 函数返回的指针指向堆上的 `x`。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。Go 编译器的命令行参数（例如 `-gcflags="-m"` 用于打印逃逸分析信息）是在编译器的其他部分进行解析和处理的。逃逸分析器会根据编译器的配置和参数来执行分析。

**使用者易犯错的点:**

虽然开发者通常不需要直接与逃逸分析的代码交互，但理解逃逸分析对于编写高性能的 Go 代码非常重要。以下是一些容易犯错的点，这些错误可能会导致不必要的堆分配：

1. **在函数外部访问局部变量的地址:**  如上面的 `foo()` 函数示例，返回局部变量的指针会导致变量逃逸。

   ```go
   func createValue() *int {
       val := 5
       return &val // 错误：val 逃逸到堆
   }
   ```

2. **向 `interface{}` 类型的变量赋值:** 将具体类型的值赋值给 `interface{}` 类型的变量时，如果编译器无法静态确定其类型，可能会导致逃逸。

   ```go
   func process(i interface{}) {
       println(i)
   }

   func main() {
       num := 10
       process(num) // num 可能逃逸
   }
   ```

3. **使用闭包捕获外部变量:** 如果闭包的生命周期比定义它的函数长，那么闭包捕获的变量很可能会逃逸。

   ```go
   func createCounter() func() int {
       count := 0
       return func() int {
           count++ // count 逃逸到堆
           return count
       }
   }

   func main() {
       counter := createCounter()
       println(counter())
       println(counter())
   }
   ```

4. **将值传递给 `reflect` 包的函数:** `reflect` 包需要运行时类型信息，这可能会导致变量逃逸。

   ```go
   import "reflect"

   func main() {
       num := 10
       reflect.TypeOf(num) // num 可能逃逸
   }
   ```

5. **在 `defer` 语句中使用外部变量:**  `defer` 语句会延迟执行，如果 `defer` 语句中使用了外部变量，这些变量可能会逃逸。

   ```go
   func main() {
       filename := "data.txt"
       f, _ := openFile(filename)
       defer f.Close() // filename 可能逃逸，因为 f 依赖 filename
       // ...
   }
   ```

理解这些可能导致逃逸的情况，可以帮助开发者编写更高效的 Go 代码，减少不必要的堆分配和垃圾回收的压力。 通过使用 `go build -gcflags="-m"` 命令，可以查看编译器的逃逸分析结果，从而更好地理解代码的内存分配行为。

### 提示词
```
这是路径为go/src/cmd/compile/internal/escape/expr.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"cmd/compile/internal/types"
)

// expr models evaluating an expression n and flowing the result into
// hole k.
func (e *escape) expr(k hole, n ir.Node) {
	if n == nil {
		return
	}
	e.stmts(n.Init())
	e.exprSkipInit(k, n)
}

func (e *escape) exprSkipInit(k hole, n ir.Node) {
	if n == nil {
		return
	}

	lno := ir.SetPos(n)
	defer func() {
		base.Pos = lno
	}()

	if k.derefs >= 0 && !n.Type().IsUntyped() && !n.Type().HasPointers() {
		k.dst = &e.blankLoc
	}

	switch n.Op() {
	default:
		base.Fatalf("unexpected expr: %s %v", n.Op().String(), n)

	case ir.OLITERAL, ir.ONIL, ir.OGETG, ir.OGETCALLERSP, ir.OTYPE, ir.OMETHEXPR, ir.OLINKSYMOFFSET:
		// nop

	case ir.ONAME:
		n := n.(*ir.Name)
		if n.Class == ir.PFUNC || n.Class == ir.PEXTERN {
			return
		}
		e.flow(k, e.oldLoc(n))

	case ir.OPLUS, ir.ONEG, ir.OBITNOT, ir.ONOT:
		n := n.(*ir.UnaryExpr)
		e.discard(n.X)
	case ir.OADD, ir.OSUB, ir.OOR, ir.OXOR, ir.OMUL, ir.ODIV, ir.OMOD, ir.OLSH, ir.ORSH, ir.OAND, ir.OANDNOT, ir.OEQ, ir.ONE, ir.OLT, ir.OLE, ir.OGT, ir.OGE:
		n := n.(*ir.BinaryExpr)
		e.discard(n.X)
		e.discard(n.Y)
	case ir.OANDAND, ir.OOROR:
		n := n.(*ir.LogicalExpr)
		e.discard(n.X)
		e.discard(n.Y)
	case ir.OADDR:
		n := n.(*ir.AddrExpr)
		e.expr(k.addr(n, "address-of"), n.X) // "address-of"
	case ir.ODEREF:
		n := n.(*ir.StarExpr)
		e.expr(k.deref(n, "indirection"), n.X) // "indirection"
	case ir.ODOT, ir.ODOTMETH, ir.ODOTINTER:
		n := n.(*ir.SelectorExpr)
		e.expr(k.note(n, "dot"), n.X)
	case ir.ODOTPTR:
		n := n.(*ir.SelectorExpr)
		e.expr(k.deref(n, "dot of pointer"), n.X) // "dot of pointer"
	case ir.ODOTTYPE, ir.ODOTTYPE2:
		n := n.(*ir.TypeAssertExpr)
		e.expr(k.dotType(n.Type(), n, "dot"), n.X)
	case ir.ODYNAMICDOTTYPE, ir.ODYNAMICDOTTYPE2:
		n := n.(*ir.DynamicTypeAssertExpr)
		e.expr(k.dotType(n.Type(), n, "dot"), n.X)
		// n.T doesn't need to be tracked; it always points to read-only storage.
	case ir.OINDEX:
		n := n.(*ir.IndexExpr)
		if n.X.Type().IsArray() {
			e.expr(k.note(n, "fixed-array-index-of"), n.X)
		} else {
			// TODO(mdempsky): Fix why reason text.
			e.expr(k.deref(n, "dot of pointer"), n.X)
		}
		e.discard(n.Index)
	case ir.OINDEXMAP:
		n := n.(*ir.IndexExpr)
		e.discard(n.X)
		e.discard(n.Index)
	case ir.OSLICE, ir.OSLICEARR, ir.OSLICE3, ir.OSLICE3ARR, ir.OSLICESTR:
		n := n.(*ir.SliceExpr)
		e.expr(k.note(n, "slice"), n.X)
		e.discard(n.Low)
		e.discard(n.High)
		e.discard(n.Max)

	case ir.OCONV, ir.OCONVNOP:
		n := n.(*ir.ConvExpr)
		if (ir.ShouldCheckPtr(e.curfn, 2) || ir.ShouldAsanCheckPtr(e.curfn)) && n.Type().IsUnsafePtr() && n.X.Type().IsPtr() {
			// When -d=checkptr=2 or -asan is enabled,
			// treat conversions to unsafe.Pointer as an
			// escaping operation. This allows better
			// runtime instrumentation, since we can more
			// easily detect object boundaries on the heap
			// than the stack.
			e.assignHeap(n.X, "conversion to unsafe.Pointer", n)
		} else if n.Type().IsUnsafePtr() && n.X.Type().IsUintptr() {
			e.unsafeValue(k, n.X)
		} else {
			e.expr(k, n.X)
		}
	case ir.OCONVIFACE:
		n := n.(*ir.ConvExpr)
		if !n.X.Type().IsInterface() && !types.IsDirectIface(n.X.Type()) {
			k = e.spill(k, n)
		}
		e.expr(k.note(n, "interface-converted"), n.X)
	case ir.OMAKEFACE:
		n := n.(*ir.BinaryExpr)
		// Note: n.X is not needed because it can never point to memory that might escape.
		e.expr(k, n.Y)
	case ir.OITAB, ir.OIDATA, ir.OSPTR:
		n := n.(*ir.UnaryExpr)
		e.expr(k, n.X)
	case ir.OSLICE2ARR:
		// Converting a slice to array is effectively a deref.
		n := n.(*ir.ConvExpr)
		e.expr(k.deref(n, "slice-to-array"), n.X)
	case ir.OSLICE2ARRPTR:
		// the slice pointer flows directly to the result
		n := n.(*ir.ConvExpr)
		e.expr(k, n.X)
	case ir.ORECV:
		n := n.(*ir.UnaryExpr)
		e.discard(n.X)

	case ir.OCALLMETH, ir.OCALLFUNC, ir.OCALLINTER, ir.OINLCALL,
		ir.OLEN, ir.OCAP, ir.OMIN, ir.OMAX, ir.OCOMPLEX, ir.OREAL, ir.OIMAG, ir.OAPPEND, ir.OCOPY, ir.ORECOVERFP,
		ir.OUNSAFEADD, ir.OUNSAFESLICE, ir.OUNSAFESTRING, ir.OUNSAFESTRINGDATA, ir.OUNSAFESLICEDATA:
		e.call([]hole{k}, n)

	case ir.ONEW:
		n := n.(*ir.UnaryExpr)
		e.spill(k, n)

	case ir.OMAKESLICE:
		n := n.(*ir.MakeExpr)
		e.spill(k, n)
		e.discard(n.Len)
		e.discard(n.Cap)
	case ir.OMAKECHAN:
		n := n.(*ir.MakeExpr)
		e.discard(n.Len)
	case ir.OMAKEMAP:
		n := n.(*ir.MakeExpr)
		e.spill(k, n)
		e.discard(n.Len)

	case ir.OMETHVALUE:
		// Flow the receiver argument to both the closure and
		// to the receiver parameter.

		n := n.(*ir.SelectorExpr)
		closureK := e.spill(k, n)

		m := n.Selection

		// We don't know how the method value will be called
		// later, so conservatively assume the result
		// parameters all flow to the heap.
		//
		// TODO(mdempsky): Change ks into a callback, so that
		// we don't have to create this slice?
		var ks []hole
		for i := m.Type.NumResults(); i > 0; i-- {
			ks = append(ks, e.heapHole())
		}
		name, _ := m.Nname.(*ir.Name)
		paramK := e.tagHole(ks, name, m.Type.Recv())

		e.expr(e.teeHole(paramK, closureK), n.X)

	case ir.OPTRLIT:
		n := n.(*ir.AddrExpr)
		e.expr(e.spill(k, n), n.X)

	case ir.OARRAYLIT:
		n := n.(*ir.CompLitExpr)
		for _, elt := range n.List {
			if elt.Op() == ir.OKEY {
				elt = elt.(*ir.KeyExpr).Value
			}
			e.expr(k.note(n, "array literal element"), elt)
		}

	case ir.OSLICELIT:
		n := n.(*ir.CompLitExpr)
		k = e.spill(k, n)

		for _, elt := range n.List {
			if elt.Op() == ir.OKEY {
				elt = elt.(*ir.KeyExpr).Value
			}
			e.expr(k.note(n, "slice-literal-element"), elt)
		}

	case ir.OSTRUCTLIT:
		n := n.(*ir.CompLitExpr)
		for _, elt := range n.List {
			e.expr(k.note(n, "struct literal element"), elt.(*ir.StructKeyExpr).Value)
		}

	case ir.OMAPLIT:
		n := n.(*ir.CompLitExpr)
		e.spill(k, n)

		// Map keys and values are always stored in the heap.
		for _, elt := range n.List {
			elt := elt.(*ir.KeyExpr)
			e.assignHeap(elt.Key, "map literal key", n)
			e.assignHeap(elt.Value, "map literal value", n)
		}

	case ir.OCLOSURE:
		n := n.(*ir.ClosureExpr)
		k = e.spill(k, n)
		e.closures = append(e.closures, closure{k, n})

		if fn := n.Func; fn.IsClosure() {
			for _, cv := range fn.ClosureVars {
				if loc := e.oldLoc(cv); !loc.captured {
					loc.captured = true

					// Ignore reassignments to the variable in straightline code
					// preceding the first capture by a closure.
					if loc.loopDepth == e.loopDepth {
						loc.reassigned = false
					}
				}
			}

			for _, n := range fn.Dcl {
				// Add locations for local variables of the
				// closure, if needed, in case we're not including
				// the closure func in the batch for escape
				// analysis (happens for escape analysis called
				// from reflectdata.methodWrapper)
				if n.Op() == ir.ONAME && n.Opt == nil {
					e.with(fn).newLoc(n, true)
				}
			}
			e.walkFunc(fn)
		}

	case ir.ORUNES2STR, ir.OBYTES2STR, ir.OSTR2RUNES, ir.OSTR2BYTES, ir.ORUNESTR:
		n := n.(*ir.ConvExpr)
		e.spill(k, n)
		e.discard(n.X)

	case ir.OADDSTR:
		n := n.(*ir.AddStringExpr)
		e.spill(k, n)

		// Arguments of OADDSTR never escape;
		// runtime.concatstrings makes sure of that.
		e.discards(n.List)

	case ir.ODYNAMICTYPE:
		// Nothing to do - argument is a *runtime._type (+ maybe a *runtime.itab) pointing to static data section
	}
}

// unsafeValue evaluates a uintptr-typed arithmetic expression looking
// for conversions from an unsafe.Pointer.
func (e *escape) unsafeValue(k hole, n ir.Node) {
	if n.Type().Kind() != types.TUINTPTR {
		base.Fatalf("unexpected type %v for %v", n.Type(), n)
	}
	if k.addrtaken {
		base.Fatalf("unexpected addrtaken")
	}

	e.stmts(n.Init())

	switch n.Op() {
	case ir.OCONV, ir.OCONVNOP:
		n := n.(*ir.ConvExpr)
		if n.X.Type().IsUnsafePtr() {
			e.expr(k, n.X)
		} else {
			e.discard(n.X)
		}
	case ir.ODOTPTR:
		n := n.(*ir.SelectorExpr)
		if ir.IsReflectHeaderDataField(n) {
			e.expr(k.deref(n, "reflect.Header.Data"), n.X)
		} else {
			e.discard(n.X)
		}
	case ir.OPLUS, ir.ONEG, ir.OBITNOT:
		n := n.(*ir.UnaryExpr)
		e.unsafeValue(k, n.X)
	case ir.OADD, ir.OSUB, ir.OOR, ir.OXOR, ir.OMUL, ir.ODIV, ir.OMOD, ir.OAND, ir.OANDNOT:
		n := n.(*ir.BinaryExpr)
		e.unsafeValue(k, n.X)
		e.unsafeValue(k, n.Y)
	case ir.OLSH, ir.ORSH:
		n := n.(*ir.BinaryExpr)
		e.unsafeValue(k, n.X)
		// RHS need not be uintptr-typed (#32959) and can't meaningfully
		// flow pointers anyway.
		e.discard(n.Y)
	default:
		e.exprSkipInit(e.discardHole(), n)
	}
}

// discard evaluates an expression n for side-effects, but discards
// its value.
func (e *escape) discard(n ir.Node) {
	e.expr(e.discardHole(), n)
}

func (e *escape) discards(l ir.Nodes) {
	for _, n := range l {
		e.discard(n)
	}
}

// spill allocates a new location associated with expression n, flows
// its address to k, and returns a hole that flows values to it. It's
// intended for use with most expressions that allocate storage.
func (e *escape) spill(k hole, n ir.Node) hole {
	loc := e.newLoc(n, false)
	e.flow(k.addr(n, "spill"), loc)
	return loc.asHole()
}
```