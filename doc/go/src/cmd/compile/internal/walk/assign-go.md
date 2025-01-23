Response: My thinking process to analyze the Go code and answer the request goes like this:

1. **Understand the Goal:** The request asks for the functionality of the provided Go code snippet, which is a part of the `cmd/compile/internal/walk` package, specifically the `assign.go` file. The goal is to describe what this code does within the Go compiler's compilation process. The request also asks for examples, potential errors, and command-line parameter relevance.

2. **Identify the Core Function:**  The file name `assign.go` and the central function `walkAssign` immediately suggest that this code deals with assignment operations in Go.

3. **Break Down `walkAssign`:** I'll examine the `walkAssign` function step-by-step:
    * **Input:** It takes an `*ir.Nodes` (likely a list of statements for initialization) and an `ir.Node` representing the assignment statement.
    * **Handle Different Assignment Types:** It checks for `ir.OAS` (simple assignment) and `ir.OASOP` (assignment with an operator like `+=`).
    * **Map Append Optimization:** The code looks for a specific pattern: `m[k] = append(m[k], ...)`. This suggests an optimization for map appends, likely to reuse the underlying map data structure more efficiently.
    * **Walk Left-Hand Side:** `walkExpr(left, init)` indicates that the left-hand side of the assignment is processed further (e.g., resolving identifiers, performing type checks). `safeExpr` might involve creating copies to avoid side effects.
    * **Rewrite `op=`:**  For `OASOP`, the code rewrites `x op= y` into `x = x op y`. This is a common compiler transformation to simplify later stages.
    * **Handle Literal Assignments:** `oaslit` suggests special handling for assignments where the right-hand side is a literal.
    * **Zero Value Assignments:** The code checks for assignments to the zero value of a type and might optimize them.
    * **Handle Receive Operations:** The `ir.ORECV` case deals with receiving values from channels (`x = <-c`). This involves calling a runtime function (`chanrecv1`).
    * **Handle Append Operations:** The `ir.OAPPEND` case is complex and has several sub-cases:
        * `isAppendOfMake`:  Optimizes `append(slice, make([]T, n)...)`.
        * `IsDDD`: Handles appending elements from a variadic function or a slice/string.
        * General `walkAppend`: Handles other append scenarios.
    * **Type Conversions:** `convas` suggests handling type conversions during assignment.

4. **Analyze Other Functions:** I'll then look at the other `walkAssign...` functions:
    * `walkAssignDotType`: Handles type assertions in assignments (`a, ok := i.(T)`).
    * `walkAssignFunc`:  Deals with assignments where the right-hand side is a function call.
    * `walkAssignList`: Handles assignments of multiple values (`a, b = x, y`).
    * `walkAssignMapRead`: Specifically handles reading from maps in an assignment context (`a, ok = m[k]`).
    * `walkAssignRecv`: Handles receiving from channels in a multi-value assignment (`a, ok = <-c`).

5. **Understand Helper Functions:** Functions like `ascompatet`, `ascompatee`, `readsMemory`, `appendSlice`, `isAppendOfMake`, and `extendSlice` provide more detail on how specific assignment scenarios are handled. I'll try to understand their purpose based on their names and the operations they perform.

6. **Infer Go Features:** Based on the operations performed in the code, I can infer the Go language features being implemented:
    * Basic assignments.
    * Assignment with operators (`+=`, `-=`, etc.).
    * Appending to slices.
    * Receiving from channels.
    * Type assertions.
    * Multiple assignments.
    * Reading from maps.

7. **Construct Go Code Examples:**  For each inferred Go feature, I'll create a simple, illustrative Go code snippet. This helps demonstrate the functionality in a user-friendly way.

8. **Infer Input and Output (for Code Reasoning):**  For the more complex parts, especially the `append` optimizations, I'll hypothesize input Go code and the likely transformed code that this `walk` phase would produce. This requires understanding the compiler's internal representation (`ir.Node`).

9. **Consider Command-Line Parameters:** I'll look for any references to `base.Flag` or other mechanisms that might indicate the code's behavior is affected by compiler flags. The code mentions `-N` and `-race`, suggesting optimizations and race detection influence this code.

10. **Identify Common Mistakes:** Based on the complexity of the code, I'll try to identify potential pitfalls for Go developers. For example, understanding how `append` works and its performance implications could be a source of errors. The map append optimization is also a subtle point.

11. **Structure the Answer:**  Finally, I'll organize the information into a clear and structured answer, covering the functionality, Go feature implementation, examples, code reasoning (with assumptions), command-line parameters, and common mistakes.

**Self-Correction/Refinement during the process:**

* **Initial Assumption Check:** I might initially assume a certain function's purpose, but then refine it as I analyze the code more closely. For example, `safeExpr` might seem like just preventing panics, but it's more about ensuring expressions are evaluated in the correct order and side effects are handled properly.
* **Focus on the "Walk" Phase:** I need to remember that this code is part of the "walk" phase of the compiler. This phase generally involves traversing the abstract syntax tree (AST) and performing transformations or lowerings. The output isn't final machine code but an intermediate representation.
* **Clarity of Examples:**  My Go code examples should be simple and directly relate to the described functionality. Avoid overly complex examples that obscure the point.
* **Specificity about Command-Line Parameters:** Instead of just saying "command-line parameters," I need to be specific about *which* parameters and *how* they affect the code's execution.

By following these steps, combining code analysis with knowledge of Go language features and compiler principles, I can generate a comprehensive and accurate answer to the request.
这段代码是Go编译器 `cmd/compile/internal/walk` 包中 `assign.go` 文件的一部分，它负责处理Go语言中的各种赋值语句。

**主要功能:**

这段代码的核心功能是将Go语言的赋值语句 (如 `x = y`, `x += y`, `a, b = f()`, `m[k] = v`, `a, ok := m[k]`, `ch <- x`, `x = <-ch`) 转换成更低级的、更接近目标机器指令的形式，以便后续的代码生成阶段能够处理。这个过程也涉及到一些优化和特殊情况的处理。

以下是各个函数的具体功能：

* **`walkAssign(init *ir.Nodes, n ir.Node)`**:  处理简单的赋值语句 (`OAS`) 和带运算符的赋值语句 (`OASOP`)。
    * **识别 `m[k] = append(m[k], ...)` 模式**:  针对向 map 中 key 对应的 slice 追加元素的常见操作进行优化，尝试复用 `mapassign` 的调用。
    * **将 `x op= y` 重写为 `x = x op y`**: 这是编译器进行转换的常见步骤，将复合赋值操作拆解为更基础的操作。
    * **处理字面量赋值 (`oaslit`)**:  可能涉及到一些优化，例如直接将字面量值写入内存。
    * **处理零值赋值**: 如果右侧是零值，可能会进行优化。
    * **处理接收操作 (`ORECV`, `x = <-c`)**:  将其转换为对运行时函数 `chanrecv1` 的调用。
    * **处理 `append` 操作 (`OAPPEND`)**:  这是最复杂的部分，根据 `append` 的不同用法进行不同的处理：
        * **`append(y, make([]T, y)...)`**: 调用 `extendSlice` 进行优化。
        * **`append(slice, string)` 或 `append(slice, anotherSlice...)`**: 调用 `appendSlice`。
        * **其他 `append` 情况**: 调用 `walkAppend`。

* **`walkAssignDotType(n *ir.AssignListStmt, init *ir.Nodes)`**: 处理类型断言的赋值语句 (`a, ok := i.(T)`)。

* **`walkAssignFunc(init *ir.Nodes, n *ir.AssignListStmt)`**: 处理将函数调用结果赋值给多个变量的情况 (`a, b = f()`)。

* **`walkAssignList(init *ir.Nodes, n *ir.AssignListStmt)`**: 处理多个变量同时赋值的情况 (`a, b = x, y`)。

* **`walkAssignMapRead(init *ir.Nodes, n *ir.AssignListStmt)`**: 处理从 map 中读取值并赋值给变量的情况 (`a, ok := m[k]`)。将其转换为对运行时函数 `mapaccess2` 或 `mapaccess2_fat` 的调用。

* **`walkAssignRecv(init *ir.Nodes, n *ir.AssignListStmt)`**: 处理从 channel 接收值并赋值给多个变量的情况 (`a, ok = <-ch`)。将其转换为对运行时函数 `chanrecv2` 的调用。

* **`walkReturn(n *ir.ReturnStmt)`**: 处理 `return` 语句，将返回值赋值给函数的结果变量。

* **`ascompatet(nl ir.Nodes, nr *types.Type)`**:  检查将函数返回值赋值给多个变量时，左右两侧类型是否匹配。

* **`ascompatee(op ir.Op, nl, nr []ir.Node)`**: 检查多个变量同时赋值时，左右两侧表达式的数量和类型是否匹配，并生成实际的赋值语句。它还处理了赋值顺序以及潜在的副作用问题，例如确保在赋值前对可能受影响的表达式进行复制。

* **`readsMemory(n ir.Node)`**:  判断一个表达式是否会直接从内存中读取数据，这在处理赋值顺序和副作用时很重要。

* **`appendSlice(n *ir.CallExpr, init *ir.Nodes)`**:  将 `append(slice, anotherSlice...)` 或 `append(slice, string)` 扩展为一系列更低级的操作，包括分配内存（如果需要）、复制元素等。

* **`isAppendOfMake(n ir.Node)`**:  判断一个 `append` 调用是否符合 `append(x, make([]T, y)...)` 的模式。

* **`extendSlice(n *ir.CallExpr, init *ir.Nodes)`**:  将 `append(l1, make([]T, l2)...)` 扩展为更低级的操作，这是一种常见的优化，可以预先分配足够的空间。

**推断的 Go 语言功能实现和代码示例:**

基于代码内容，可以推断出它实现了以下 Go 语言功能：

1. **简单赋值和带运算符的赋值:**
   ```go
   var x int
   var y int = 10
   x = y
   x += 5 // 内部会被处理成 x = x + 5
   ```

2. **多重赋值:**
   ```go
   func getValues() (int, string) {
       return 1, "hello"
   }
   a, b := getValues()
   ```

3. **Map 操作:**
   ```go
   m := make(map[string]int)
   m["key"] = 10
   value, ok := m["key"]
   ```

4. **Channel 操作:**
   ```go
   ch := make(chan int)
   go func() {
       ch <- 10
   }()
   x := <-ch
   y, ok := <-ch // 接收操作可以返回两个值
   ```

5. **Slice 的 `append` 操作:**
   ```go
   s := []int{1, 2, 3}
   s = append(s, 4)
   s = append(s, []int{5, 6}...)
   s = append(s, make([]int, 2)...) // 对应 extendSlice 的优化
   ```

6. **类型断言:**
   ```go
   var i interface{} = "hello"
   s, ok := i.(string)
   ```

**代码推理 (假设的输入与输出):**

假设输入的 Go 代码是：

```go
package main

func main() {
	m := make(map[int][]int)
	key := 1
	value := 2
	m[key] = append(m[key], value)
}
```

`walkAssign` 函数在处理 `m[key] = append(m[key], value)` 这行代码时，会识别出 `m[k] = append(m[k], ...)` 的模式。

**假设的输入 (抽象语法树的一部分):**

```
OAS (AssignStmt)
  X (IndexExpr)  // m[key]
    X (ONAME)    // m
    Index (ONAME) // key
  Y (CallExpr)   // append(m[key], value)
    Fun (ONAME)    // append
    Args (Nodes)
      0 (IndexExpr) // m[key]
        X (ONAME)   // m
        Index (ONAME) // key
      1 (ONAME)    // value
```

**可能的输出 (转换后的抽象语法树的一部分):**

输出可能会将 `append` 操作转换为对运行时函数的调用，并可能复用 `mapassign` 的结果。例如，可能会生成类似以下的中间表示：

```
OAS (AssignStmt)
  X (IndexExpr)  // m[key]
    X (ONAME)    // m
    Index (ONAME) // key
  Y (CallExpr)   // runtime.mapappend(m, key, value)  (简化表示)
    Fun (ONAME)    // mapappend (运行时函数)
    Args (Nodes)
      0 (ONAME)    // m
      1 (ONAME)    // key
      2 (ONAME)    // value
```

**命令行参数:**

这段代码本身似乎没有直接处理命令行参数。但是，`base.Flag.Cfg.Instrumenting` 和 `base.Flag.N`  这些标志表明，编译器的某些命令行参数会影响这段代码的执行，例如：

* **`-N` (禁用优化):** 如果禁用了优化，`isAppendOfMake` 可能会直接返回 `false`，导致不会执行 `extendSlice` 的优化路径。
* **`-race` (启用竞态检测):**  `base.Flag.Cfg.Instrumenting` 在启用竞态检测时会为内存操作添加额外的代码，这会影响 `appendSlice` 中是否直接使用 `memmove` 或调用带类型信息的 `typedslicecopy` 运行时函数。

**使用者易犯错的点:**

虽然这段代码是编译器内部实现，但了解其背后的逻辑可以帮助 Go 开发者避免一些常见的误解：

* **对 `append` 的性能理解**:  开发者需要了解 `append` 在容量不足时会触发内存重新分配和数据拷贝，这可能导致性能下降。`extendSlice` 的优化旨在减少这种情况的发生，但并非所有 `append` 都能被优化。
* **Map 的并发安全性**:  虽然代码处理了 map 的赋值和读取，但 Go 的 map 本身不是并发安全的。在并发环境中使用 map 需要额外的同步机制。
* **Channel 的阻塞行为**:  对 channel 的发送和接收操作是阻塞的。不理解这一点可能导致 goroutine 死锁。

总而言之，`go/src/cmd/compile/internal/walk/assign.go` 是 Go 编译器中负责处理赋值语句的核心部分，它将高级的 Go 语法转换为更底层的表示，并进行一些优化，为后续的代码生成阶段做准备。理解这部分代码的功能可以帮助我们更深入地了解 Go 语言的内部机制和编译过程。

### 提示词
```
这是路径为go/src/cmd/compile/internal/walk/assign.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package walk

import (
	"go/constant"
	"internal/abi"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/reflectdata"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/src"
)

// walkAssign walks an OAS (AssignExpr) or OASOP (AssignOpExpr) node.
func walkAssign(init *ir.Nodes, n ir.Node) ir.Node {
	init.Append(ir.TakeInit(n)...)

	var left, right ir.Node
	switch n.Op() {
	case ir.OAS:
		n := n.(*ir.AssignStmt)
		left, right = n.X, n.Y
	case ir.OASOP:
		n := n.(*ir.AssignOpStmt)
		left, right = n.X, n.Y
	}

	// Recognize m[k] = append(m[k], ...) so we can reuse
	// the mapassign call.
	var mapAppend *ir.CallExpr
	if left.Op() == ir.OINDEXMAP && right.Op() == ir.OAPPEND {
		left := left.(*ir.IndexExpr)
		mapAppend = right.(*ir.CallExpr)
		if !ir.SameSafeExpr(left, mapAppend.Args[0]) {
			base.Fatalf("not same expressions: %v != %v", left, mapAppend.Args[0])
		}
	}

	left = walkExpr(left, init)
	left = safeExpr(left, init)
	if mapAppend != nil {
		mapAppend.Args[0] = left
	}

	if n.Op() == ir.OASOP {
		// Rewrite x op= y into x = x op y.
		n = ir.NewAssignStmt(base.Pos, left, typecheck.Expr(ir.NewBinaryExpr(base.Pos, n.(*ir.AssignOpStmt).AsOp, left, right)))
	} else {
		n.(*ir.AssignStmt).X = left
	}
	as := n.(*ir.AssignStmt)

	if oaslit(as, init) {
		return ir.NewBlockStmt(as.Pos(), nil)
	}

	if as.Y == nil {
		// TODO(austin): Check all "implicit zeroing"
		return as
	}

	if !base.Flag.Cfg.Instrumenting && ir.IsZero(as.Y) {
		return as
	}

	switch as.Y.Op() {
	default:
		as.Y = walkExpr(as.Y, init)

	case ir.ORECV:
		// x = <-c; as.Left is x, as.Right.Left is c.
		// order.stmt made sure x is addressable.
		recv := as.Y.(*ir.UnaryExpr)
		recv.X = walkExpr(recv.X, init)

		n1 := typecheck.NodAddr(as.X)
		r := recv.X // the channel
		return mkcall1(chanfn("chanrecv1", 2, r.Type()), nil, init, r, n1)

	case ir.OAPPEND:
		// x = append(...)
		call := as.Y.(*ir.CallExpr)
		if call.Type().Elem().NotInHeap() {
			base.Errorf("%v can't be allocated in Go; it is incomplete (or unallocatable)", call.Type().Elem())
		}
		var r ir.Node
		switch {
		case isAppendOfMake(call):
			// x = append(y, make([]T, y)...)
			r = extendSlice(call, init)
		case call.IsDDD:
			r = appendSlice(call, init) // also works for append(slice, string).
		default:
			r = walkAppend(call, init, as)
		}
		as.Y = r
		if r.Op() == ir.OAPPEND {
			r := r.(*ir.CallExpr)
			// Left in place for back end.
			// Do not add a new write barrier.
			// Set up address of type for back end.
			r.Fun = reflectdata.AppendElemRType(base.Pos, r)
			return as
		}
		// Otherwise, lowered for race detector.
		// Treat as ordinary assignment.
	}

	if as.X != nil && as.Y != nil {
		return convas(as, init)
	}
	return as
}

// walkAssignDotType walks an OAS2DOTTYPE node.
func walkAssignDotType(n *ir.AssignListStmt, init *ir.Nodes) ir.Node {
	walkExprListSafe(n.Lhs, init)
	n.Rhs[0] = walkExpr(n.Rhs[0], init)
	return n
}

// walkAssignFunc walks an OAS2FUNC node.
func walkAssignFunc(init *ir.Nodes, n *ir.AssignListStmt) ir.Node {
	init.Append(ir.TakeInit(n)...)

	r := n.Rhs[0]
	walkExprListSafe(n.Lhs, init)
	r = walkExpr(r, init)

	if ir.IsIntrinsicCall(r.(*ir.CallExpr)) {
		n.Rhs = []ir.Node{r}
		return n
	}
	init.Append(r)

	ll := ascompatet(n.Lhs, r.Type())
	return ir.NewBlockStmt(src.NoXPos, ll)
}

// walkAssignList walks an OAS2 node.
func walkAssignList(init *ir.Nodes, n *ir.AssignListStmt) ir.Node {
	init.Append(ir.TakeInit(n)...)
	return ir.NewBlockStmt(src.NoXPos, ascompatee(ir.OAS, n.Lhs, n.Rhs))
}

// walkAssignMapRead walks an OAS2MAPR node.
func walkAssignMapRead(init *ir.Nodes, n *ir.AssignListStmt) ir.Node {
	init.Append(ir.TakeInit(n)...)

	r := n.Rhs[0].(*ir.IndexExpr)
	walkExprListSafe(n.Lhs, init)
	r.X = walkExpr(r.X, init)
	r.Index = walkExpr(r.Index, init)
	t := r.X.Type()

	fast := mapfast(t)
	key := mapKeyArg(fast, r, r.Index, false)

	// from:
	//   a,b = m[i]
	// to:
	//   var,b = mapaccess2*(t, m, i)
	//   a = *var
	a := n.Lhs[0]

	var call *ir.CallExpr
	if w := t.Elem().Size(); w <= abi.ZeroValSize {
		fn := mapfn(mapaccess2[fast], t, false)
		call = mkcall1(fn, fn.Type().ResultsTuple(), init, reflectdata.IndexMapRType(base.Pos, r), r.X, key)
	} else {
		fn := mapfn("mapaccess2_fat", t, true)
		z := reflectdata.ZeroAddr(w)
		call = mkcall1(fn, fn.Type().ResultsTuple(), init, reflectdata.IndexMapRType(base.Pos, r), r.X, key, z)
	}

	// mapaccess2* returns a typed bool, but due to spec changes,
	// the boolean result of i.(T) is now untyped so we make it the
	// same type as the variable on the lhs.
	if ok := n.Lhs[1]; !ir.IsBlank(ok) && ok.Type().IsBoolean() {
		call.Type().Field(1).Type = ok.Type()
	}
	n.Rhs = []ir.Node{call}
	n.SetOp(ir.OAS2FUNC)

	// don't generate a = *var if a is _
	if ir.IsBlank(a) {
		return walkExpr(typecheck.Stmt(n), init)
	}

	var_ := typecheck.TempAt(base.Pos, ir.CurFunc, types.NewPtr(t.Elem()))
	var_.SetTypecheck(1)
	var_.MarkNonNil() // mapaccess always returns a non-nil pointer

	n.Lhs[0] = var_
	init.Append(walkExpr(n, init))

	as := ir.NewAssignStmt(base.Pos, a, ir.NewStarExpr(base.Pos, var_))
	return walkExpr(typecheck.Stmt(as), init)
}

// walkAssignRecv walks an OAS2RECV node.
func walkAssignRecv(init *ir.Nodes, n *ir.AssignListStmt) ir.Node {
	init.Append(ir.TakeInit(n)...)

	r := n.Rhs[0].(*ir.UnaryExpr) // recv
	walkExprListSafe(n.Lhs, init)
	r.X = walkExpr(r.X, init)
	var n1 ir.Node
	if ir.IsBlank(n.Lhs[0]) {
		n1 = typecheck.NodNil()
	} else {
		n1 = typecheck.NodAddr(n.Lhs[0])
	}
	fn := chanfn("chanrecv2", 2, r.X.Type())
	ok := n.Lhs[1]
	call := mkcall1(fn, types.Types[types.TBOOL], init, r.X, n1)
	return typecheck.Stmt(ir.NewAssignStmt(base.Pos, ok, call))
}

// walkReturn walks an ORETURN node.
func walkReturn(n *ir.ReturnStmt) ir.Node {
	fn := ir.CurFunc

	fn.NumReturns++
	if len(n.Results) == 0 {
		return n
	}

	results := fn.Type().Results()
	dsts := make([]ir.Node, len(results))
	for i, v := range results {
		// TODO(mdempsky): typecheck should have already checked the result variables.
		dsts[i] = typecheck.AssignExpr(v.Nname.(*ir.Name))
	}

	n.Results = ascompatee(n.Op(), dsts, n.Results)
	return n
}

// check assign type list to
// an expression list. called in
//
//	expr-list = func()
func ascompatet(nl ir.Nodes, nr *types.Type) []ir.Node {
	if len(nl) != nr.NumFields() {
		base.Fatalf("ascompatet: assignment count mismatch: %d = %d", len(nl), nr.NumFields())
	}

	var nn ir.Nodes
	for i, l := range nl {
		if ir.IsBlank(l) {
			continue
		}
		r := nr.Field(i)

		// Order should have created autotemps of the appropriate type for
		// us to store results into.
		if tmp, ok := l.(*ir.Name); !ok || !tmp.AutoTemp() || !types.Identical(tmp.Type(), r.Type) {
			base.FatalfAt(l.Pos(), "assigning %v to %+v", r.Type, l)
		}

		res := ir.NewResultExpr(base.Pos, nil, types.BADWIDTH)
		res.Index = int64(i)
		res.SetType(r.Type)
		res.SetTypecheck(1)

		nn.Append(ir.NewAssignStmt(base.Pos, l, res))
	}
	return nn
}

// check assign expression list to
// an expression list. called in
//
//	expr-list = expr-list
func ascompatee(op ir.Op, nl, nr []ir.Node) []ir.Node {
	// cannot happen: should have been rejected during type checking
	if len(nl) != len(nr) {
		base.Fatalf("assignment operands mismatch: %+v / %+v", ir.Nodes(nl), ir.Nodes(nr))
	}

	var assigned ir.NameSet
	var memWrite, deferResultWrite bool

	// affected reports whether expression n could be affected by
	// the assignments applied so far.
	affected := func(n ir.Node) bool {
		if deferResultWrite {
			return true
		}
		return ir.Any(n, func(n ir.Node) bool {
			if n.Op() == ir.ONAME && assigned.Has(n.(*ir.Name)) {
				return true
			}
			if memWrite && readsMemory(n) {
				return true
			}
			return false
		})
	}

	// If a needed expression may be affected by an
	// earlier assignment, make an early copy of that
	// expression and use the copy instead.
	var early ir.Nodes
	save := func(np *ir.Node) {
		if n := *np; affected(n) {
			*np = copyExpr(n, n.Type(), &early)
		}
	}

	var late ir.Nodes
	for i, lorig := range nl {
		l, r := lorig, nr[i]

		// Do not generate 'x = x' during return. See issue 4014.
		if op == ir.ORETURN && ir.SameSafeExpr(l, r) {
			continue
		}

		// Save subexpressions needed on left side.
		// Drill through non-dereferences.
		for {
			// If an expression has init statements, they must be evaluated
			// before any of its saved sub-operands (#45706).
			// TODO(mdempsky): Disallow init statements on lvalues.
			init := ir.TakeInit(l)
			walkStmtList(init)
			early.Append(init...)

			switch ll := l.(type) {
			case *ir.IndexExpr:
				if ll.X.Type().IsArray() {
					save(&ll.Index)
					l = ll.X
					continue
				}
			case *ir.ParenExpr:
				l = ll.X
				continue
			case *ir.SelectorExpr:
				if ll.Op() == ir.ODOT {
					l = ll.X
					continue
				}
			}
			break
		}

		var name *ir.Name
		switch l.Op() {
		default:
			base.Fatalf("unexpected lvalue %v", l.Op())
		case ir.ONAME:
			name = l.(*ir.Name)
		case ir.OINDEX, ir.OINDEXMAP:
			l := l.(*ir.IndexExpr)
			save(&l.X)
			save(&l.Index)
		case ir.ODEREF:
			l := l.(*ir.StarExpr)
			save(&l.X)
		case ir.ODOTPTR:
			l := l.(*ir.SelectorExpr)
			save(&l.X)
		}

		// Save expression on right side.
		save(&r)

		appendWalkStmt(&late, convas(ir.NewAssignStmt(base.Pos, lorig, r), &late))

		// Check for reasons why we may need to compute later expressions
		// before this assignment happens.

		if name == nil {
			// Not a direct assignment to a declared variable.
			// Conservatively assume any memory access might alias.
			memWrite = true
			continue
		}

		if name.Class == ir.PPARAMOUT && ir.CurFunc.HasDefer() {
			// Assignments to a result parameter in a function with defers
			// becomes visible early if evaluation of any later expression
			// panics (#43835).
			deferResultWrite = true
			continue
		}

		if ir.IsBlank(name) {
			// We can ignore assignments to blank or anonymous result parameters.
			// These can't appear in expressions anyway.
			continue
		}

		if name.Addrtaken() || !name.OnStack() {
			// Global variable, heap escaped, or just addrtaken.
			// Conservatively assume any memory access might alias.
			memWrite = true
			continue
		}

		// Local, non-addrtaken variable.
		// Assignments can only alias with direct uses of this variable.
		assigned.Add(name)
	}

	early.Append(late.Take()...)
	return early
}

// readsMemory reports whether the evaluation n directly reads from
// memory that might be written to indirectly.
func readsMemory(n ir.Node) bool {
	switch n.Op() {
	case ir.ONAME:
		n := n.(*ir.Name)
		if n.Class == ir.PFUNC {
			return false
		}
		return n.Addrtaken() || !n.OnStack()

	case ir.OADD,
		ir.OAND,
		ir.OANDAND,
		ir.OANDNOT,
		ir.OBITNOT,
		ir.OCONV,
		ir.OCONVIFACE,
		ir.OCONVNOP,
		ir.ODIV,
		ir.ODOT,
		ir.ODOTTYPE,
		ir.OLITERAL,
		ir.OLSH,
		ir.OMOD,
		ir.OMUL,
		ir.ONEG,
		ir.ONIL,
		ir.OOR,
		ir.OOROR,
		ir.OPAREN,
		ir.OPLUS,
		ir.ORSH,
		ir.OSUB,
		ir.OXOR:
		return false
	}

	// Be conservative.
	return true
}

// expand append(l1, l2...) to
//
//	init {
//	  s := l1
//	  newLen := s.len + l2.len
//	  // Compare as uint so growslice can panic on overflow.
//	  if uint(newLen) <= uint(s.cap) {
//	    s = s[:newLen]
//	  } else {
//	    s = growslice(s.ptr, s.len, s.cap, l2.len, T)
//	  }
//	  memmove(&s[s.len-l2.len], &l2[0], l2.len*sizeof(T))
//	}
//	s
//
// l2 is allowed to be a string.
func appendSlice(n *ir.CallExpr, init *ir.Nodes) ir.Node {
	walkAppendArgs(n, init)

	l1 := n.Args[0]
	l2 := n.Args[1]
	l2 = cheapExpr(l2, init)
	n.Args[1] = l2

	var nodes ir.Nodes

	// var s []T
	s := typecheck.TempAt(base.Pos, ir.CurFunc, l1.Type())
	nodes.Append(ir.NewAssignStmt(base.Pos, s, l1)) // s = l1

	elemtype := s.Type().Elem()

	// Decompose slice.
	oldPtr := ir.NewUnaryExpr(base.Pos, ir.OSPTR, s)
	oldLen := ir.NewUnaryExpr(base.Pos, ir.OLEN, s)
	oldCap := ir.NewUnaryExpr(base.Pos, ir.OCAP, s)

	// Number of elements we are adding
	num := ir.NewUnaryExpr(base.Pos, ir.OLEN, l2)

	// newLen := oldLen + num
	newLen := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TINT])
	nodes.Append(ir.NewAssignStmt(base.Pos, newLen, ir.NewBinaryExpr(base.Pos, ir.OADD, oldLen, num)))

	// if uint(newLen) <= uint(oldCap)
	nif := ir.NewIfStmt(base.Pos, nil, nil, nil)
	nuint := typecheck.Conv(newLen, types.Types[types.TUINT])
	scapuint := typecheck.Conv(oldCap, types.Types[types.TUINT])
	nif.Cond = ir.NewBinaryExpr(base.Pos, ir.OLE, nuint, scapuint)
	nif.Likely = true

	// then { s = s[:newLen] }
	slice := ir.NewSliceExpr(base.Pos, ir.OSLICE, s, nil, newLen, nil)
	slice.SetBounded(true)
	nif.Body = []ir.Node{ir.NewAssignStmt(base.Pos, s, slice)}

	// else { s = growslice(oldPtr, newLen, oldCap, num, T) }
	call := walkGrowslice(s, nif.PtrInit(), oldPtr, newLen, oldCap, num)
	nif.Else = []ir.Node{ir.NewAssignStmt(base.Pos, s, call)}

	nodes.Append(nif)

	// Index to start copying into s.
	//   idx = newLen - len(l2)
	// We use this expression instead of oldLen because it avoids
	// a spill/restore of oldLen.
	// Note: this doesn't work optimally currently because
	// the compiler optimizer undoes this arithmetic.
	idx := ir.NewBinaryExpr(base.Pos, ir.OSUB, newLen, ir.NewUnaryExpr(base.Pos, ir.OLEN, l2))

	var ncopy ir.Node
	if elemtype.HasPointers() {
		// copy(s[idx:], l2)
		slice := ir.NewSliceExpr(base.Pos, ir.OSLICE, s, idx, nil, nil)
		slice.SetType(s.Type())
		slice.SetBounded(true)

		ir.CurFunc.SetWBPos(n.Pos())

		// instantiate typedslicecopy(typ *type, dstPtr *any, dstLen int, srcPtr *any, srcLen int) int
		fn := typecheck.LookupRuntime("typedslicecopy", l1.Type().Elem(), l2.Type().Elem())
		ptr1, len1 := backingArrayPtrLen(cheapExpr(slice, &nodes))
		ptr2, len2 := backingArrayPtrLen(l2)
		ncopy = mkcall1(fn, types.Types[types.TINT], &nodes, reflectdata.AppendElemRType(base.Pos, n), ptr1, len1, ptr2, len2)
	} else if base.Flag.Cfg.Instrumenting && !base.Flag.CompilingRuntime {
		// rely on runtime to instrument:
		//  copy(s[idx:], l2)
		// l2 can be a slice or string.
		slice := ir.NewSliceExpr(base.Pos, ir.OSLICE, s, idx, nil, nil)
		slice.SetType(s.Type())
		slice.SetBounded(true)

		ptr1, len1 := backingArrayPtrLen(cheapExpr(slice, &nodes))
		ptr2, len2 := backingArrayPtrLen(l2)

		fn := typecheck.LookupRuntime("slicecopy", ptr1.Type().Elem(), ptr2.Type().Elem())
		ncopy = mkcall1(fn, types.Types[types.TINT], &nodes, ptr1, len1, ptr2, len2, ir.NewInt(base.Pos, elemtype.Size()))
	} else {
		// memmove(&s[idx], &l2[0], len(l2)*sizeof(T))
		ix := ir.NewIndexExpr(base.Pos, s, idx)
		ix.SetBounded(true)
		addr := typecheck.NodAddr(ix)

		sptr := ir.NewUnaryExpr(base.Pos, ir.OSPTR, l2)

		nwid := cheapExpr(typecheck.Conv(ir.NewUnaryExpr(base.Pos, ir.OLEN, l2), types.Types[types.TUINTPTR]), &nodes)
		nwid = ir.NewBinaryExpr(base.Pos, ir.OMUL, nwid, ir.NewInt(base.Pos, elemtype.Size()))

		// instantiate func memmove(to *any, frm *any, length uintptr)
		fn := typecheck.LookupRuntime("memmove", elemtype, elemtype)
		ncopy = mkcall1(fn, nil, &nodes, addr, sptr, nwid)
	}
	ln := append(nodes, ncopy)

	typecheck.Stmts(ln)
	walkStmtList(ln)
	init.Append(ln...)
	return s
}

// isAppendOfMake reports whether n is of the form append(x, make([]T, y)...).
// isAppendOfMake assumes n has already been typechecked.
func isAppendOfMake(n ir.Node) bool {
	if base.Flag.N != 0 || base.Flag.Cfg.Instrumenting {
		return false
	}

	if n.Typecheck() == 0 {
		base.Fatalf("missing typecheck: %+v", n)
	}

	if n.Op() != ir.OAPPEND {
		return false
	}
	call := n.(*ir.CallExpr)
	if !call.IsDDD || len(call.Args) != 2 || call.Args[1].Op() != ir.OMAKESLICE {
		return false
	}

	mk := call.Args[1].(*ir.MakeExpr)
	if mk.Cap != nil {
		return false
	}

	// y must be either an integer constant or the largest possible positive value
	// of variable y needs to fit into a uint.

	// typecheck made sure that constant arguments to make are not negative and fit into an int.

	// The care of overflow of the len argument to make will be handled by an explicit check of int(len) < 0 during runtime.
	y := mk.Len
	if !ir.IsConst(y, constant.Int) && y.Type().Size() > types.Types[types.TUINT].Size() {
		return false
	}

	return true
}

// extendSlice rewrites append(l1, make([]T, l2)...) to
//
//	init {
//	  if l2 >= 0 { // Empty if block here for more meaningful node.SetLikely(true)
//	  } else {
//	    panicmakeslicelen()
//	  }
//	  s := l1
//	  if l2 != 0 {
//	    n := len(s) + l2
//	    // Compare n and s as uint so growslice can panic on overflow of len(s) + l2.
//	    // cap is a positive int and n can become negative when len(s) + l2
//	    // overflows int. Interpreting n when negative as uint makes it larger
//	    // than cap(s). growslice will check the int n arg and panic if n is
//	    // negative. This prevents the overflow from being undetected.
//	    if uint(n) <= uint(cap(s)) {
//	      s = s[:n]
//	    } else {
//	      s = growslice(T, s.ptr, n, s.cap, l2, T)
//	    }
//	    // clear the new portion of the underlying array.
//	    hp := &s[len(s)-l2]
//	    hn := l2 * sizeof(T)
//	    memclr(hp, hn)
//	  }
//	}
//	s
//
//	if T has pointers, the final memclr can go inside the "then" branch, as
//	growslice will have done the clearing for us.

func extendSlice(n *ir.CallExpr, init *ir.Nodes) ir.Node {
	// isAppendOfMake made sure all possible positive values of l2 fit into a uint.
	// The case of l2 overflow when converting from e.g. uint to int is handled by an explicit
	// check of l2 < 0 at runtime which is generated below.
	l2 := typecheck.Conv(n.Args[1].(*ir.MakeExpr).Len, types.Types[types.TINT])
	l2 = typecheck.Expr(l2)
	n.Args[1] = l2 // walkAppendArgs expects l2 in n.List.Second().

	walkAppendArgs(n, init)

	l1 := n.Args[0]
	l2 = n.Args[1] // re-read l2, as it may have been updated by walkAppendArgs

	var nodes []ir.Node

	// if l2 >= 0 (likely happens), do nothing
	nifneg := ir.NewIfStmt(base.Pos, ir.NewBinaryExpr(base.Pos, ir.OGE, l2, ir.NewInt(base.Pos, 0)), nil, nil)
	nifneg.Likely = true

	// else panicmakeslicelen()
	nifneg.Else = []ir.Node{mkcall("panicmakeslicelen", nil, init)}
	nodes = append(nodes, nifneg)

	// s := l1
	s := typecheck.TempAt(base.Pos, ir.CurFunc, l1.Type())
	nodes = append(nodes, ir.NewAssignStmt(base.Pos, s, l1))

	// if l2 != 0 {
	// Avoid work if we're not appending anything. But more importantly,
	// avoid allowing hp to be a past-the-end pointer when clearing. See issue 67255.
	nifnz := ir.NewIfStmt(base.Pos, ir.NewBinaryExpr(base.Pos, ir.ONE, l2, ir.NewInt(base.Pos, 0)), nil, nil)
	nifnz.Likely = true
	nodes = append(nodes, nifnz)

	elemtype := s.Type().Elem()

	// n := s.len + l2
	nn := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TINT])
	nifnz.Body = append(nifnz.Body, ir.NewAssignStmt(base.Pos, nn, ir.NewBinaryExpr(base.Pos, ir.OADD, ir.NewUnaryExpr(base.Pos, ir.OLEN, s), l2)))

	// if uint(n) <= uint(s.cap)
	nuint := typecheck.Conv(nn, types.Types[types.TUINT])
	capuint := typecheck.Conv(ir.NewUnaryExpr(base.Pos, ir.OCAP, s), types.Types[types.TUINT])
	nif := ir.NewIfStmt(base.Pos, ir.NewBinaryExpr(base.Pos, ir.OLE, nuint, capuint), nil, nil)
	nif.Likely = true

	// then { s = s[:n] }
	nt := ir.NewSliceExpr(base.Pos, ir.OSLICE, s, nil, nn, nil)
	nt.SetBounded(true)
	nif.Body = []ir.Node{ir.NewAssignStmt(base.Pos, s, nt)}

	// else { s = growslice(s.ptr, n, s.cap, l2, T) }
	nif.Else = []ir.Node{
		ir.NewAssignStmt(base.Pos, s, walkGrowslice(s, nif.PtrInit(),
			ir.NewUnaryExpr(base.Pos, ir.OSPTR, s),
			nn,
			ir.NewUnaryExpr(base.Pos, ir.OCAP, s),
			l2)),
	}

	nifnz.Body = append(nifnz.Body, nif)

	// hp := &s[s.len - l2]
	// TODO: &s[s.len] - hn?
	ix := ir.NewIndexExpr(base.Pos, s, ir.NewBinaryExpr(base.Pos, ir.OSUB, ir.NewUnaryExpr(base.Pos, ir.OLEN, s), l2))
	ix.SetBounded(true)
	hp := typecheck.ConvNop(typecheck.NodAddr(ix), types.Types[types.TUNSAFEPTR])

	// hn := l2 * sizeof(elem(s))
	hn := typecheck.Conv(ir.NewBinaryExpr(base.Pos, ir.OMUL, l2, ir.NewInt(base.Pos, elemtype.Size())), types.Types[types.TUINTPTR])

	clrname := "memclrNoHeapPointers"
	hasPointers := elemtype.HasPointers()
	if hasPointers {
		clrname = "memclrHasPointers"
		ir.CurFunc.SetWBPos(n.Pos())
	}

	var clr ir.Nodes
	clrfn := mkcall(clrname, nil, &clr, hp, hn)
	clr.Append(clrfn)
	if hasPointers {
		// growslice will have cleared the new entries, so only
		// if growslice isn't called do we need to do the zeroing ourselves.
		nif.Body = append(nif.Body, clr...)
	} else {
		nifnz.Body = append(nifnz.Body, clr...)
	}

	typecheck.Stmts(nodes)
	walkStmtList(nodes)
	init.Append(nodes...)
	return s
}
```