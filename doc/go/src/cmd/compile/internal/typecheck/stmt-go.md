Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - Core Goal:**

The first step is to recognize that this code is part of the Go compiler's type checking phase. The package name `typecheck` and the file name `stmt.go` strongly suggest this. The functions within likely handle type checking and related operations for different kinds of statements.

**2. Function-by-Function Analysis (High-Level):**

I'll iterate through each function, trying to grasp its purpose from its name and the operations it performs.

* **`RangeExprType`:**  "Range" and "Type" suggest something related to range loops. The logic about pointers to arrays is a key clue.
* **`typecheckrangeExpr`:** This is an empty function. This is important to note; it means the *actual* type checking logic for `range` statements might be elsewhere, or this could be a placeholder for future implementation or a point where other checks are triggered.
* **`tcAssign`:** "tc" likely stands for "type check." "Assign" clearly indicates assignment statements. The code handles single assignments (`n.Y == nil`) and delegates to an `assign` function.
* **`tcAssignList`:**  Similar to `tcAssign`, but for multiple assignments. It directly calls the `assign` function.
* **`assign`:**  This looks like the core logic for handling both single and multiple assignments. It handles type inference for variables declared during assignment, type checking of left and right-hand sides, and special cases like assignments with comma-ok (`x, ok = ...`). The function name itself is very descriptive.
* **`plural`:**  A helper function for formatting error messages. Simple string manipulation.
* **`tcCheckNil`:** Clearly related to checking for nil pointers. The `OCHECKNIL` op code confirms this.
* **`tcFor`:**  Type checking logic for `for` loops, handling the initialization, condition, and post statements.
* **`tcGoDefer`:**  Deals with `go` and `defer` statements. It normalizes the function call.
* **`normalizeGoDeferCall`:**  This is a crucial function. It explains *how* `go` and `defer` calls are handled internally, especially with arguments. The transformation into a closure is the key insight.
* **`tcIf`:** Type checking for `if` statements, similar to `tcFor` with condition handling.
* **`tcRange`:** More involved than `typecheckrangeExpr`. This function handles the type checking of the variables introduced in the `range` clause (key and value).
* **`tcReturn`:**  Type checking for `return` statements, ensuring the return values match the function signature.
* **`tcSelect`:** Handles type checking for `select` statements, with special handling for `case` clauses involving receives, sends, and assignments.
* **`tcSend`:** Type checks `send` operations on channels.
* **`tcSwitch`:** A dispatcher for different kinds of `switch` statements.
* **`tcSwitchExpr`:** Type checking for expression-based `switch` statements. Handles comparability and type matching in `case` clauses.
* **`tcSwitchType`:** Type checking for type switch statements. Handles interface types and the `case` types.
* **`typeSet`:** A helper struct and methods to track types within type switch cases to detect duplicates.

**3. Identifying Key Go Features:**

As I analyze the functions, I start connecting them to specific Go language features:

* **`RangeExprType`, `tcRange`:**  The `range` keyword for iterating over collections.
* **`tcAssign`, `tcAssignList`, `assign`:** Assignment statements, including single and multiple assignments, and the short variable declaration (`:=`).
* **`tcCheckNil`:**  The concept of `nil` and the need to check for it (often implicitly).
* **`tcFor`:**  `for` loops.
* **`tcGoDefer`, `normalizeGoDeferCall`:**  The `go` and `defer` keywords for concurrency and delayed execution.
* **`tcIf`:** `if` statements.
* **`tcReturn`:** `return` statements.
* **`tcSelect`:** `select` statements for channel operations.
* **`tcSend`:** Sending values on channels.
* **`tcSwitch`, `tcSwitchExpr`, `tcSwitchType`:**  `switch` statements, both expression and type switches.

**4. Providing Code Examples:**

Once I've identified the features, I can construct simple Go code examples that would exercise the logic within these functions. The examples should be clear and directly related to the function's purpose.

**5. Inferring Functionality and Providing Explanations:**

Based on the code and examples, I can explain the function's purpose in the context of Go's semantics and the compiler's role.

**6. Identifying Potential Pitfalls:**

I look for common mistakes programmers might make when using the features handled by the code. This involves thinking about type compatibility, assignment rules, the behavior of `go` and `defer`, and the intricacies of `select` and `switch` statements.

**7. Handling Missing Information (Command-line Arguments):**

The prompt asks about command-line arguments. If the code doesn't directly process command-line arguments (as is the case here), I need to explicitly state that and explain *why* it might not be present in this particular file (it's a type-checking phase, not a command-line parsing phase).

**8. Refinement and Structure:**

Finally, I organize the information clearly, using headings and bullet points to make it easy to read and understand. I ensure the examples are correctly formatted and the explanations are concise and accurate. I review for clarity and completeness.

This structured approach allows me to systematically analyze the code, understand its purpose, connect it to Go language features, provide relevant examples, and address all aspects of the prompt.
这段Go语言代码是Go编译器 `cmd/compile/internal/typecheck` 包中 `stmt.go` 文件的一部分，主要负责**类型检查Go语言的各种语句（statements）**。

以下是它包含的一些主要功能，并尝试推断其实现的Go语言特性：

**1. 类型检查 `range` 表达式:**

* **功能:** `RangeExprType(t *types.Type) *types.Type` 函数用于确定 `range` 表达式的目标类型。如果 `range` 的目标是指向数组的指针，它会返回数组的类型，否则返回原始类型。
* **实现的Go语言特性:**  `range` 循环，特别是针对数组和指向数组的指针的 `range` 行为。
* **代码示例:**

```go
package main

import "fmt"

func main() {
	arr := [3]int{1, 2, 3}
	ptr := &arr

	// range 数组
	for i, v := range arr {
		fmt.Printf("index: %d, value: %d\n", i, v)
	}

	// range 指向数组的指针
	for i, v := range ptr {
		fmt.Printf("index: %d, value: %d\n", i, v)
	}
}
```

**2. 类型检查赋值语句 (`=`):**

* **功能:** `tcAssign(n *ir.AssignStmt)` 函数负责类型检查赋值语句。它会处理单值赋值，并调用 `assign` 函数来处理更通用的赋值情况，包括类型推断（如果左侧是新变量声明）。
* **实现的Go语言特性:**  赋值语句，包括变量定义时的赋值 (短变量声明 `:=`)。
* **代码示例:**

```go
package main

func main() {
	var x int
	x = 10 // 单值赋值

	y := 20 // 短变量声明，赋值并推断类型

	var a, b int
	a, b = 30, 40 // 多重赋值
}
```

**3. 类型检查多重赋值语句 (`=`，左侧有多个变量):**

* **功能:** `tcAssignList(n *ir.AssignListStmt)` 函数负责类型检查左侧有多个变量的赋值语句。它也调用 `assign` 函数来执行实际的类型检查。
* **实现的Go语言特性:**  多重赋值，特别是与函数返回值或类型断言等结合的情况。
* **代码示例:**

```go
package main

func f() (int, string) {
	return 100, "hello"
}

func main() {
	num, str := f() // 多重赋值接收函数返回值

	var i interface{} = "world"
	s, ok := i.(string) // 类型断言后的多重赋值
	println(num, str, s, ok)
}
```

**4. 通用的赋值类型检查逻辑 (`assign`)**:

* **功能:** `assign(stmt ir.Node, lhs, rhs []ir.Node)` 函数是执行实际赋值类型检查的核心函数。它处理类型兼容性、类型转换、以及赋值给新声明的变量时的类型推断。它还处理了形如 `x, ok := y` 的赋值语句，例如从 `map` 或 `chan` 读取值。
* **实现的Go语言特性:**  所有类型的赋值操作，包括类型转换、类型断言、从 `map` 或 `chan` 读取值的赋值。
* **假设输入与输出（`x, ok = m[key]`）:**
    * **假设输入:** 一个 `ir.AssignListStmt` 节点，`lhs` 包含两个节点（变量 `x` 和 `ok`），`rhs` 包含一个 `ir.OINDEXMAP` 节点 (表示 map 取值操作)。 `m` 是一个 `map[string]int` 类型的变量，`key` 是一个字符串类型的变量。
    * **输出:**
        * `stmt` 的 `Op` 会被设置为 `ir.OAS2MAPR`。
        * `lhs[0]` (变量 `x`) 的类型会被设置为 `int`。
        * `lhs[1]` (变量 `ok`) 的类型会被设置为 `types.UntypedBool`。

**5. 类型检查 `nil` 检查语句 (`check nil`):**

* **功能:** `tcCheckNil(n *ir.UnaryExpr)` 函数检查 `CHECKNIL` 操作，确保操作数是指针类型。这通常是编译器内部插入的，用于在运行时检查空指针。
* **实现的Go语言特性:**  空指针检查，尽管这通常是隐式的，但在某些情况下编译器会插入显式的检查。
* **代码示例:**  Go 语言中通常不需要显式写 `check nil`，编译器会在必要时插入。

**6. 类型检查 `for` 循环:**

* **功能:** `tcFor(n *ir.ForStmt)` 函数负责类型检查 `for` 循环的各个部分：初始化语句、条件表达式和 post 语句。它会确保条件表达式是布尔类型。
* **实现的Go语言特性:**  `for` 循环。
* **代码示例:**

```go
package main

func main() {
	for i := 0; i < 10; i++ {
		println(i)
	}

	j := 0
	for j < 5 {
		println(j)
		j++
	}

	for { // 无限循环
		// ...
	}
}
```

**7. 类型检查 `go` 和 `defer` 语句:**

* **功能:** `tcGoDefer(n *ir.GoDeferStmt)` 函数处理 `go` 和 `defer` 语句的类型检查。它会调用 `normalizeGoDeferCall` 来将 `go` 或 `defer` 调用的函数转换为一个无参数无返回值的闭包。
* **实现的Go语言特性:**  `go` 协程和 `defer` 延迟执行。
* **代码示例:**

```go
package main

import "fmt"

func task(name string) {
	fmt.Println("Running task:", name)
}

func main() {
	go task("goroutine 1") // 启动一个 goroutine

	defer fmt.Println("This will be deferred") // 延迟执行

	fmt.Println("Main function")
}
```

* **`normalizeGoDeferCall` 的功能:**  这个函数将 `go` 或 `defer` 后的函数调用转换为一个闭包，捕获调用时的参数值。这确保了在 `go` 协程执行或 `defer` 函数调用时，使用的是定义时的参数值，而不是执行时的。

**8. 类型检查 `if` 语句:**

* **功能:** `tcIf(n *ir.IfStmt)` 函数负责类型检查 `if` 语句，确保条件表达式是布尔类型。
* **实现的Go语言特性:**  `if` 条件语句。
* **代码示例:**

```go
package main

func main() {
	x := 10
	if x > 5 {
		println("x is greater than 5")
	} else if x == 5 {
		println("x is equal to 5")
	} else {
		println("x is less than 5")
	}
}
```

**9. 类型检查 `range` 语句:**

* **功能:** `tcRange(n *ir.RangeStmt)` 函数负责类型检查 `range` 循环语句，包括 `key` 和 `value` 变量的类型推断和赋值类型检查。
* **实现的Go语言特性:** `range` 循环。
* **代码示例 (与上面 `RangeExprType` 的例子相同)。**

**10. 类型检查 `return` 语句:**

* **功能:** `tcReturn(n *ir.ReturnStmt)` 函数负责类型检查 `return` 语句，确保返回值的类型与函数签名匹配。
* **实现的Go语言特性:**  `return` 语句。
* **代码示例:**

```go
package main

func add(a, b int) int {
	return a + b
}

func greet(name string) (string, int) {
	return "Hello, " + name + "!", 200
}

func main() {
	sum := add(5, 3)
	message, code := greet("World")
	println(sum, message, code)
}
```

**11. 类型检查 `select` 语句:**

* **功能:** `tcSelect(sel *ir.SelectStmt)` 函数负责类型检查 `select` 语句，包括对 `case` 子句中接收 (`<-chan`)、发送 (`chan <- value`) 和赋值接收操作的类型检查。
* **实现的Go语言特性:**  `select` 语句，用于处理多个通道操作。
* **代码示例:**

```go
package main

import "time"

func main() {
	ch1 := make(chan int)
	ch2 := make(chan string)

	select {
	case val := <-ch1:
		println("Received from ch1:", val)
	case val, ok := <-ch2:
		if ok {
			println("Received from ch2:", val)
		} else {
			println("ch2 is closed")
		}
	case ch1 <- 10:
		println("Sent to ch1")
	case <-time.After(time.Second):
		println("Timeout")
	default:
		println("No channel operation ready")
	}
}
```

**12. 类型检查 `send` 语句:**

* **功能:** `tcSend(n *ir.SendStmt)` 函数负责类型检查发送到通道的语句 (`chan <- value`)，确保发送的值的类型与通道的元素类型兼容。
* **实现的Go语言特性:**  向通道发送数据。
* **代码示例 (与上面 `tcSelect` 的例子中发送到 `ch1` 的部分类似)。**

**13. 类型检查 `switch` 语句:**

* **功能:** `tcSwitch(n *ir.SwitchStmt)` 函数是 `switch` 语句类型检查的入口，它会根据 `switch` 语句的类型（表达式 switch 或类型 switch）调用 `tcSwitchExpr` 或 `tcSwitchType` 进行进一步的检查。
* **实现的Go语言特性:**  `switch` 语句，包括表达式 switch 和类型 switch。

**14. 类型检查表达式 `switch` 语句:**

* **功能:** `tcSwitchExpr(n *ir.SwitchStmt)` 函数负责类型检查基于表达式的 `switch` 语句，确保 `case` 子句中的表达式与 `switch` 表达式的类型兼容。
* **实现的Go语言特性:**  表达式 `switch` 语句。
* **代码示例:**

```go
package main

func main() {
	grade := 85
	switch {
	case grade >= 90:
		println("A")
	case grade >= 80:
		println("B")
	case grade >= 70:
		println("C")
	default:
		println("D")
	}

	day := "Monday"
	switch day {
	case "Monday", "Tuesday", "Wednesday", "Thursday", "Friday":
		println("Weekday")
	case "Saturday", "Sunday":
		println("Weekend")
	default:
		println("Invalid day")
	}
}
```

**15. 类型检查类型 `switch` 语句:**

* **功能:** `tcSwitchType(n *ir.SwitchStmt)` 函数负责类型检查类型 `switch` 语句，判断接口值的动态类型。
* **实现的Go语言特性:**  类型 `switch` 语句。
* **代码示例:**

```go
package main

import "fmt"

func main() {
	var i interface{} = 10

	switch v := i.(type) {
	case int:
		fmt.Printf("Type: int, Value: %d\n", v)
	case string:
		fmt.Printf("Type: string, Value: %s\n", v)
	default:
		fmt.Printf("Unknown type: %T\n", v)
	}
}
```

**命令行参数的具体处理:**

这段代码片段本身**不直接处理命令行参数**。 命令行参数的处理通常发生在编译器的更上层，例如在 `cmd/compile/internal/gc` 包中。  `base.Flag` 可能包含一些从命令行传递下来的编译选项，但具体的解析和处理不在这个文件中。

**使用者易犯错的点 (基于代码推理):**

* **`range` 循环中对指向数组的指针的处理:**  初学者可能会混淆直接 `range` 数组和 `range` 指向数组的指针，虽然效果类似，但 `RangeExprType` 函数体现了编译器内部对这两种情况的处理。
* **`go` 和 `defer` 中闭包的参数捕获:**  如果不理解 `normalizeGoDeferCall` 的作用，可能会错误地认为 `go` 或 `defer` 调用的函数会使用执行时的参数值，而不是定义时的。
* **`select` 语句的 `case` 子句类型:**  容易犯错的地方在于 `select` 的 `case` 必须是接收、发送操作或赋值接收操作，其他类型的语句是不允许的。
* **`switch` 语句的类型匹配:**  在表达式 `switch` 中，`case` 表达式的类型必须与 `switch` 表达式的类型兼容。在类型 `switch` 中，`case` 类型必须是具体的类型或 `nil`。

总而言之，`go/src/cmd/compile/internal/typecheck/stmt.go` 是 Go 编译器中负责对各种 Go 语句进行静态类型检查的关键部分，它确保了代码的类型安全性，并在编译时捕获潜在的类型错误。

### 提示词
```
这是路径为go/src/cmd/compile/internal/typecheck/stmt.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package typecheck

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/src"
	"internal/types/errors"
)

func RangeExprType(t *types.Type) *types.Type {
	if t.IsPtr() && t.Elem().IsArray() {
		return t.Elem()
	}
	return t
}

func typecheckrangeExpr(n *ir.RangeStmt) {
}

// type check assignment.
// if this assignment is the definition of a var on the left side,
// fill in the var's type.
func tcAssign(n *ir.AssignStmt) {
	if base.EnableTrace && base.Flag.LowerT {
		defer tracePrint("tcAssign", n)(nil)
	}

	if n.Y == nil {
		n.X = AssignExpr(n.X)
		return
	}

	lhs, rhs := []ir.Node{n.X}, []ir.Node{n.Y}
	assign(n, lhs, rhs)
	n.X, n.Y = lhs[0], rhs[0]

	// TODO(mdempsky): This seems out of place.
	if !ir.IsBlank(n.X) {
		types.CheckSize(n.X.Type()) // ensure width is calculated for backend
	}
}

func tcAssignList(n *ir.AssignListStmt) {
	if base.EnableTrace && base.Flag.LowerT {
		defer tracePrint("tcAssignList", n)(nil)
	}

	assign(n, n.Lhs, n.Rhs)
}

func assign(stmt ir.Node, lhs, rhs []ir.Node) {
	// delicate little dance.
	// the definition of lhs may refer to this assignment
	// as its definition, in which case it will call tcAssign.
	// in that case, do not call typecheck back, or it will cycle.
	// if the variable has a type (ntype) then typechecking
	// will not look at defn, so it is okay (and desirable,
	// so that the conversion below happens).

	checkLHS := func(i int, typ *types.Type) {
		if n := lhs[i]; typ != nil && ir.DeclaredBy(n, stmt) && n.Type() == nil {
			base.Assertf(typ.Kind() == types.TNIL, "unexpected untyped nil")
			n.SetType(defaultType(typ))
		}
		if lhs[i].Typecheck() == 0 {
			lhs[i] = AssignExpr(lhs[i])
		}
		checkassign(lhs[i])
	}

	assignType := func(i int, typ *types.Type) {
		checkLHS(i, typ)
		if typ != nil {
			checkassignto(typ, lhs[i])
		}
	}

	cr := len(rhs)
	if len(rhs) == 1 {
		rhs[0] = typecheck(rhs[0], ctxExpr|ctxMultiOK)
		if rtyp := rhs[0].Type(); rtyp != nil && rtyp.IsFuncArgStruct() {
			cr = rtyp.NumFields()
		}
	} else {
		Exprs(rhs)
	}

	// x, ok = y
assignOK:
	for len(lhs) == 2 && cr == 1 {
		stmt := stmt.(*ir.AssignListStmt)
		r := rhs[0]

		switch r.Op() {
		case ir.OINDEXMAP:
			stmt.SetOp(ir.OAS2MAPR)
		case ir.ORECV:
			stmt.SetOp(ir.OAS2RECV)
		case ir.ODOTTYPE:
			r := r.(*ir.TypeAssertExpr)
			stmt.SetOp(ir.OAS2DOTTYPE)
			r.SetOp(ir.ODOTTYPE2)
		case ir.ODYNAMICDOTTYPE:
			r := r.(*ir.DynamicTypeAssertExpr)
			stmt.SetOp(ir.OAS2DOTTYPE)
			r.SetOp(ir.ODYNAMICDOTTYPE2)
		default:
			break assignOK
		}

		assignType(0, r.Type())
		assignType(1, types.UntypedBool)
		return
	}

	if len(lhs) != cr {
		if r, ok := rhs[0].(*ir.CallExpr); ok && len(rhs) == 1 {
			if r.Type() != nil {
				base.ErrorfAt(stmt.Pos(), errors.WrongAssignCount, "assignment mismatch: %d variable%s but %v returns %d value%s", len(lhs), plural(len(lhs)), r.Fun, cr, plural(cr))
			}
		} else {
			base.ErrorfAt(stmt.Pos(), errors.WrongAssignCount, "assignment mismatch: %d variable%s but %v value%s", len(lhs), plural(len(lhs)), len(rhs), plural(len(rhs)))
		}

		for i := range lhs {
			checkLHS(i, nil)
		}
		return
	}

	// x,y,z = f()
	if cr > len(rhs) {
		stmt := stmt.(*ir.AssignListStmt)
		stmt.SetOp(ir.OAS2FUNC)
		r := rhs[0].(*ir.CallExpr)
		rtyp := r.Type()

		mismatched := false
		failed := false
		for i := range lhs {
			result := rtyp.Field(i).Type
			assignType(i, result)

			if lhs[i].Type() == nil || result == nil {
				failed = true
			} else if lhs[i] != ir.BlankNode && !types.Identical(lhs[i].Type(), result) {
				mismatched = true
			}
		}
		if mismatched && !failed {
			RewriteMultiValueCall(stmt, r)
		}
		return
	}

	for i, r := range rhs {
		checkLHS(i, r.Type())
		if lhs[i].Type() != nil {
			rhs[i] = AssignConv(r, lhs[i].Type(), "assignment")
		}
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// tcCheckNil typechecks an OCHECKNIL node.
func tcCheckNil(n *ir.UnaryExpr) ir.Node {
	n.X = Expr(n.X)
	if !n.X.Type().IsPtrShaped() {
		base.FatalfAt(n.Pos(), "%L is not pointer shaped", n.X)
	}
	return n
}

// tcFor typechecks an OFOR node.
func tcFor(n *ir.ForStmt) ir.Node {
	Stmts(n.Init())
	n.Cond = Expr(n.Cond)
	n.Cond = DefaultLit(n.Cond, nil)
	if n.Cond != nil {
		t := n.Cond.Type()
		if t != nil && !t.IsBoolean() {
			base.Errorf("non-bool %L used as for condition", n.Cond)
		}
	}
	n.Post = Stmt(n.Post)
	Stmts(n.Body)
	return n
}

// tcGoDefer typechecks (normalizes) an OGO/ODEFER statement.
func tcGoDefer(n *ir.GoDeferStmt) {
	call := normalizeGoDeferCall(n.Pos(), n.Op(), n.Call, n.PtrInit())
	call.GoDefer = true
	n.Call = call
}

// normalizeGoDeferCall normalizes call into a normal function call
// with no arguments and no results, suitable for use in an OGO/ODEFER
// statement.
//
// For example, it normalizes:
//
//	f(x, y)
//
// into:
//
//	x1, y1 := x, y          // added to init
//	func() { f(x1, y1) }()  // result
func normalizeGoDeferCall(pos src.XPos, op ir.Op, call ir.Node, init *ir.Nodes) *ir.CallExpr {
	init.Append(ir.TakeInit(call)...)

	if call, ok := call.(*ir.CallExpr); ok && call.Op() == ir.OCALLFUNC {
		if sig := call.Fun.Type(); sig.NumParams()+sig.NumResults() == 0 {
			return call // already in normal form
		}
	}

	// Create a new wrapper function without parameters or results.
	wrapperFn := ir.NewClosureFunc(pos, pos, op, types.NewSignature(nil, nil, nil), ir.CurFunc, Target)
	wrapperFn.DeclareParams(true)
	wrapperFn.SetWrapper(true)

	// argps collects the list of operands within the call expression
	// that must be evaluated at the go/defer statement.
	var argps []*ir.Node

	var visit func(argp *ir.Node)
	visit = func(argp *ir.Node) {
		arg := *argp
		if arg == nil {
			return
		}

		// Recognize a few common expressions that can be evaluated within
		// the wrapper, so we don't need to allocate space for them within
		// the closure.
		switch arg.Op() {
		case ir.OLITERAL, ir.ONIL, ir.OMETHEXPR, ir.ONEW:
			return
		case ir.ONAME:
			arg := arg.(*ir.Name)
			if arg.Class == ir.PFUNC {
				return // reference to global function
			}
		case ir.OADDR:
			arg := arg.(*ir.AddrExpr)
			if arg.X.Op() == ir.OLINKSYMOFFSET {
				return // address of global symbol
			}

		case ir.OCONVNOP:
			arg := arg.(*ir.ConvExpr)

			// For unsafe.Pointer->uintptr conversion arguments, save the
			// unsafe.Pointer argument. This is necessary to handle cases
			// like fixedbugs/issue24491a.go correctly.
			//
			// TODO(mdempsky): Limit to static callees with
			// //go:uintptr{escapes,keepalive}?
			if arg.Type().IsUintptr() && arg.X.Type().IsUnsafePtr() {
				visit(&arg.X)
				return
			}

		case ir.OARRAYLIT, ir.OSLICELIT, ir.OSTRUCTLIT:
			// TODO(mdempsky): For very large slices, it may be preferable
			// to construct them at the go/defer statement instead.
			list := arg.(*ir.CompLitExpr).List
			for i, el := range list {
				switch el := el.(type) {
				case *ir.KeyExpr:
					visit(&el.Value)
				case *ir.StructKeyExpr:
					visit(&el.Value)
				default:
					visit(&list[i])
				}
			}
			return
		}

		argps = append(argps, argp)
	}

	visitList := func(list []ir.Node) {
		for i := range list {
			visit(&list[i])
		}
	}

	switch call.Op() {
	default:
		base.Fatalf("unexpected call op: %v", call.Op())

	case ir.OCALLFUNC:
		call := call.(*ir.CallExpr)

		// If the callee is a named function, link to the original callee.
		if wrapped := ir.StaticCalleeName(call.Fun); wrapped != nil {
			wrapperFn.WrappedFunc = wrapped.Func
		}

		visit(&call.Fun)
		visitList(call.Args)

	case ir.OCALLINTER:
		call := call.(*ir.CallExpr)
		argps = append(argps, &call.Fun.(*ir.SelectorExpr).X) // must be first for OCHECKNIL; see below
		visitList(call.Args)

	case ir.OAPPEND, ir.ODELETE, ir.OPRINT, ir.OPRINTLN, ir.ORECOVERFP:
		call := call.(*ir.CallExpr)
		visitList(call.Args)
		visit(&call.RType)

	case ir.OCOPY:
		call := call.(*ir.BinaryExpr)
		visit(&call.X)
		visit(&call.Y)
		visit(&call.RType)

	case ir.OCLEAR, ir.OCLOSE, ir.OPANIC:
		call := call.(*ir.UnaryExpr)
		visit(&call.X)
	}

	if len(argps) != 0 {
		// Found one or more operands that need to be evaluated upfront
		// and spilled to temporary variables, which can be captured by
		// the wrapper function.

		stmtPos := base.Pos
		callPos := base.Pos

		as := ir.NewAssignListStmt(callPos, ir.OAS2, make([]ir.Node, len(argps)), make([]ir.Node, len(argps)))
		for i, argp := range argps {
			arg := *argp

			pos := callPos
			if ir.HasUniquePos(arg) {
				pos = arg.Pos()
			}

			// tmp := arg
			tmp := TempAt(pos, ir.CurFunc, arg.Type())
			init.Append(Stmt(ir.NewDecl(pos, ir.ODCL, tmp)))
			tmp.Defn = as
			as.Lhs[i] = tmp
			as.Rhs[i] = arg

			// Rewrite original expression to use/capture tmp.
			*argp = ir.NewClosureVar(pos, wrapperFn, tmp)
		}
		init.Append(Stmt(as))

		// For "go/defer iface.M()", if iface is nil, we need to panic at
		// the point of the go/defer statement.
		if call.Op() == ir.OCALLINTER {
			iface := as.Lhs[0]
			init.Append(Stmt(ir.NewUnaryExpr(stmtPos, ir.OCHECKNIL, ir.NewUnaryExpr(iface.Pos(), ir.OITAB, iface))))
		}
	}

	// Move call into the wrapper function, now that it's safe to
	// evaluate there.
	wrapperFn.Body = []ir.Node{call}

	// Finally, construct a call to the wrapper.
	return Call(call.Pos(), wrapperFn.OClosure, nil, false).(*ir.CallExpr)
}

// tcIf typechecks an OIF node.
func tcIf(n *ir.IfStmt) ir.Node {
	Stmts(n.Init())
	n.Cond = Expr(n.Cond)
	n.Cond = DefaultLit(n.Cond, nil)
	if n.Cond != nil {
		t := n.Cond.Type()
		if t != nil && !t.IsBoolean() {
			base.Errorf("non-bool %L used as if condition", n.Cond)
		}
	}
	Stmts(n.Body)
	Stmts(n.Else)
	return n
}

// range
func tcRange(n *ir.RangeStmt) {
	n.X = Expr(n.X)

	// delicate little dance.  see tcAssignList
	if n.Key != nil {
		if !ir.DeclaredBy(n.Key, n) {
			n.Key = AssignExpr(n.Key)
		}
		checkassign(n.Key)
	}
	if n.Value != nil {
		if !ir.DeclaredBy(n.Value, n) {
			n.Value = AssignExpr(n.Value)
		}
		checkassign(n.Value)
	}

	// second half of dance
	n.SetTypecheck(1)
	if n.Key != nil && n.Key.Typecheck() == 0 {
		n.Key = AssignExpr(n.Key)
	}
	if n.Value != nil && n.Value.Typecheck() == 0 {
		n.Value = AssignExpr(n.Value)
	}

	Stmts(n.Body)
}

// tcReturn typechecks an ORETURN node.
func tcReturn(n *ir.ReturnStmt) ir.Node {
	if ir.CurFunc == nil {
		base.FatalfAt(n.Pos(), "return outside function")
	}

	typecheckargs(n)
	if len(n.Results) != 0 {
		typecheckaste(ir.ORETURN, nil, false, ir.CurFunc.Type().Results(), n.Results, func() string { return "return argument" })
	}
	return n
}

// select
func tcSelect(sel *ir.SelectStmt) {
	var def *ir.CommClause
	lno := ir.SetPos(sel)
	Stmts(sel.Init())
	for _, ncase := range sel.Cases {
		if ncase.Comm == nil {
			// default
			if def != nil {
				base.ErrorfAt(ncase.Pos(), errors.DuplicateDefault, "multiple defaults in select (first at %v)", ir.Line(def))
			} else {
				def = ncase
			}
		} else {
			n := Stmt(ncase.Comm)
			ncase.Comm = n
			oselrecv2 := func(dst, recv ir.Node, def bool) {
				selrecv := ir.NewAssignListStmt(n.Pos(), ir.OSELRECV2, []ir.Node{dst, ir.BlankNode}, []ir.Node{recv})
				selrecv.Def = def
				selrecv.SetTypecheck(1)
				selrecv.SetInit(n.Init())
				ncase.Comm = selrecv
			}
			switch n.Op() {
			default:
				pos := n.Pos()
				if n.Op() == ir.ONAME {
					// We don't have the right position for ONAME nodes (see #15459 and
					// others). Using ncase.Pos for now as it will provide the correct
					// line number (assuming the expression follows the "case" keyword
					// on the same line). This matches the approach before 1.10.
					pos = ncase.Pos()
				}
				base.ErrorfAt(pos, errors.InvalidSelectCase, "select case must be receive, send or assign recv")

			case ir.OAS:
				// convert x = <-c into x, _ = <-c
				// remove implicit conversions; the eventual assignment
				// will reintroduce them.
				n := n.(*ir.AssignStmt)
				if r := n.Y; r.Op() == ir.OCONVNOP || r.Op() == ir.OCONVIFACE {
					r := r.(*ir.ConvExpr)
					if r.Implicit() {
						n.Y = r.X
					}
				}
				if n.Y.Op() != ir.ORECV {
					base.ErrorfAt(n.Pos(), errors.InvalidSelectCase, "select assignment must have receive on right hand side")
					break
				}
				oselrecv2(n.X, n.Y, n.Def)

			case ir.OAS2RECV:
				n := n.(*ir.AssignListStmt)
				if n.Rhs[0].Op() != ir.ORECV {
					base.ErrorfAt(n.Pos(), errors.InvalidSelectCase, "select assignment must have receive on right hand side")
					break
				}
				n.SetOp(ir.OSELRECV2)

			case ir.ORECV:
				// convert <-c into _, _ = <-c
				n := n.(*ir.UnaryExpr)
				oselrecv2(ir.BlankNode, n, false)

			case ir.OSEND:
				break
			}
		}

		Stmts(ncase.Body)
	}

	base.Pos = lno
}

// tcSend typechecks an OSEND node.
func tcSend(n *ir.SendStmt) ir.Node {
	n.Chan = Expr(n.Chan)
	n.Value = Expr(n.Value)
	n.Chan = DefaultLit(n.Chan, nil)
	t := n.Chan.Type()
	if t == nil {
		return n
	}
	if !t.IsChan() {
		base.Errorf("invalid operation: %v (send to non-chan type %v)", n, t)
		return n
	}

	if !t.ChanDir().CanSend() {
		base.Errorf("invalid operation: %v (send to receive-only type %v)", n, t)
		return n
	}

	n.Value = AssignConv(n.Value, t.Elem(), "send")
	if n.Value.Type() == nil {
		return n
	}
	return n
}

// tcSwitch typechecks a switch statement.
func tcSwitch(n *ir.SwitchStmt) {
	Stmts(n.Init())
	if n.Tag != nil && n.Tag.Op() == ir.OTYPESW {
		tcSwitchType(n)
	} else {
		tcSwitchExpr(n)
	}
}

func tcSwitchExpr(n *ir.SwitchStmt) {
	t := types.Types[types.TBOOL]
	if n.Tag != nil {
		n.Tag = Expr(n.Tag)
		n.Tag = DefaultLit(n.Tag, nil)
		t = n.Tag.Type()
	}

	var nilonly string
	if t != nil {
		switch {
		case t.IsMap():
			nilonly = "map"
		case t.Kind() == types.TFUNC:
			nilonly = "func"
		case t.IsSlice():
			nilonly = "slice"

		case !types.IsComparable(t):
			if t.IsStruct() {
				base.ErrorfAt(n.Pos(), errors.InvalidExprSwitch, "cannot switch on %L (struct containing %v cannot be compared)", n.Tag, types.IncomparableField(t).Type)
			} else {
				base.ErrorfAt(n.Pos(), errors.InvalidExprSwitch, "cannot switch on %L", n.Tag)
			}
			t = nil
		}
	}

	var defCase ir.Node
	for _, ncase := range n.Cases {
		ls := ncase.List
		if len(ls) == 0 { // default:
			if defCase != nil {
				base.ErrorfAt(ncase.Pos(), errors.DuplicateDefault, "multiple defaults in switch (first at %v)", ir.Line(defCase))
			} else {
				defCase = ncase
			}
		}

		for i := range ls {
			ir.SetPos(ncase)
			ls[i] = Expr(ls[i])
			ls[i] = DefaultLit(ls[i], t)
			n1 := ls[i]
			if t == nil || n1.Type() == nil {
				continue
			}

			if nilonly != "" && !ir.IsNil(n1) {
				base.ErrorfAt(ncase.Pos(), errors.MismatchedTypes, "invalid case %v in switch (can only compare %s %v to nil)", n1, nilonly, n.Tag)
			} else if t.IsInterface() && !n1.Type().IsInterface() && !types.IsComparable(n1.Type()) {
				base.ErrorfAt(ncase.Pos(), errors.UndefinedOp, "invalid case %L in switch (incomparable type)", n1)
			} else {
				op1, _ := assignOp(n1.Type(), t)
				op2, _ := assignOp(t, n1.Type())
				if op1 == ir.OXXX && op2 == ir.OXXX {
					if n.Tag != nil {
						base.ErrorfAt(ncase.Pos(), errors.MismatchedTypes, "invalid case %v in switch on %v (mismatched types %v and %v)", n1, n.Tag, n1.Type(), t)
					} else {
						base.ErrorfAt(ncase.Pos(), errors.MismatchedTypes, "invalid case %v in switch (mismatched types %v and bool)", n1, n1.Type())
					}
				}
			}
		}

		Stmts(ncase.Body)
	}
}

func tcSwitchType(n *ir.SwitchStmt) {
	guard := n.Tag.(*ir.TypeSwitchGuard)
	guard.X = Expr(guard.X)
	t := guard.X.Type()
	if t != nil && !t.IsInterface() {
		base.ErrorfAt(n.Pos(), errors.InvalidTypeSwitch, "cannot type switch on non-interface value %L", guard.X)
		t = nil
	}

	// We don't actually declare the type switch's guarded
	// declaration itself. So if there are no cases, we won't
	// notice that it went unused.
	if v := guard.Tag; v != nil && !ir.IsBlank(v) && len(n.Cases) == 0 {
		base.ErrorfAt(v.Pos(), errors.UnusedVar, "%v declared but not used", v.Sym())
	}

	var defCase, nilCase ir.Node
	var ts typeSet
	for _, ncase := range n.Cases {
		ls := ncase.List
		if len(ls) == 0 { // default:
			if defCase != nil {
				base.ErrorfAt(ncase.Pos(), errors.DuplicateDefault, "multiple defaults in switch (first at %v)", ir.Line(defCase))
			} else {
				defCase = ncase
			}
		}

		for i := range ls {
			ls[i] = typecheck(ls[i], ctxExpr|ctxType)
			n1 := ls[i]
			if t == nil || n1.Type() == nil {
				continue
			}

			if ir.IsNil(n1) { // case nil:
				if nilCase != nil {
					base.ErrorfAt(ncase.Pos(), errors.DuplicateCase, "multiple nil cases in type switch (first at %v)", ir.Line(nilCase))
				} else {
					nilCase = ncase
				}
				continue
			}
			if n1.Op() == ir.ODYNAMICTYPE {
				continue
			}
			if n1.Op() != ir.OTYPE {
				base.ErrorfAt(ncase.Pos(), errors.NotAType, "%L is not a type", n1)
				continue
			}
			if !n1.Type().IsInterface() {
				why := ImplementsExplain(n1.Type(), t)
				if why != "" {
					base.ErrorfAt(ncase.Pos(), errors.ImpossibleAssert, "impossible type switch case: %L cannot have dynamic type %v (%s)", guard.X, n1.Type(), why)
				}
				continue
			}

			ts.add(ncase.Pos(), n1.Type())
		}

		if ncase.Var != nil {
			// Assign the clause variable's type.
			vt := t
			if len(ls) == 1 {
				if ls[0].Op() == ir.OTYPE || ls[0].Op() == ir.ODYNAMICTYPE {
					vt = ls[0].Type()
				} else if !ir.IsNil(ls[0]) {
					// Invalid single-type case;
					// mark variable as broken.
					vt = nil
				}
			}

			nvar := ncase.Var
			nvar.SetType(vt)
			if vt != nil {
				nvar = AssignExpr(nvar).(*ir.Name)
			} else {
				// Clause variable is broken; prevent typechecking.
				nvar.SetTypecheck(1)
			}
			ncase.Var = nvar
		}

		Stmts(ncase.Body)
	}
}

type typeSet struct {
	m map[string]src.XPos
}

func (s *typeSet) add(pos src.XPos, typ *types.Type) {
	if s.m == nil {
		s.m = make(map[string]src.XPos)
	}

	ls := typ.LinkString()
	if prev, ok := s.m[ls]; ok {
		base.ErrorfAt(pos, errors.DuplicateCase, "duplicate case %v in type switch\n\tprevious case at %s", typ, base.FmtPos(prev))
		return
	}
	s.m[ls] = pos
}
```