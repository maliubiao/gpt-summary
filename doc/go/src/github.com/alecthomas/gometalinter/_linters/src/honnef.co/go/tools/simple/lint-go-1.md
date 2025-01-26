Response:
The user is asking for a summary of the functionality of the provided Go code snippet. This code snippet is part of a linter that checks for potential issues or stylistic improvements in Go code.

I need to analyze each of the functions defined in the snippet (`LintNilCheckAroundTypeAssert`, `LintDeclareAssign`, `LintRedundantBreak`, `Implements`, `LintRedundantSprintf`, `LintErrorsNewSprintf`, `LintRangeStringRunes`, `LintNilCheckAroundRange`, `isPermissibleSort`, `LintSortHelpers`, `isCommaOkMapIndex`, `LintGuardedDelete`, `LintSimplifyTypeSwitch`).

For each linting function, I will identify the specific pattern or rule it's checking for and summarize its purpose.
这段代码是 `honnef.co/go/tools/simple` 检查器的一部分，它包含了一系列用于检查 Go 语言代码的 lint 规则。总体来说，这段代码的功能是**检查和报告一些可以简化或改进的 Go 语言代码模式，以提高代码的可读性和效率**。

具体来说，它实现了以下几个 lint 功能：

1. **`LintNilCheckAroundTypeAssert`**: 检查类型断言后立即进行的 nil 检查是否可以优化。它会查找两种模式：
    *   `if _, ok := x.(T); !ok { return } if x != nil { ... }`
    *   `if a, ok := b.(c); ok { if a != nil { ... } }`
    并建议简化为直接在类型断言成功的分支中处理。

2. **`LintDeclareAssign`**: 检查变量声明后紧跟着赋值的情况，并建议将声明和赋值合并到一行。

3. **`LintRedundantBreak`**: 检查 `switch` 语句的 `case` 子句末尾是否有冗余的 `break` 语句，以及函数或方法末尾是否有冗余的 `return` 语句。

4. **`Implements`**:  这是一个辅助函数，用于判断一个类型是否实现了某个接口。它被其他 lint 函数使用。

5. **`LintRedundantSprintf`**: 检查 `fmt.Sprintf` 的使用场景，如果格式化字符串是 `"%s"` 并且参数已经是字符串或实现了 `fmt.Stringer` 接口，则建议直接使用 `String()` 方法或进行简单的类型转换。

6. **`LintErrorsNewSprintf`**: 检查 `errors.New(fmt.Sprintf(...))` 的使用模式，并建议使用 `fmt.Errorf(...)` 来代替。

7. **`LintRangeStringRunes`**:  调用了 `sharedcheck.CheckRangeStringRunes`，这部分代码没有直接展示，但可以推断出它是检查使用 `range` 迭代字符串时是否需要 `[]rune(string)` 转换。

8. **`LintNilCheckAroundRange`**: 检查在 `range` 循环之前是否有对 slice 或 map 进行不必要的 nil 检查。由于 `range` 在处理 nil slice 或 map 时不会 panic，因此该检查是多余的。

9. **`LintSortHelpers`**: 检查使用 `sort.Sort(sort.IntSlice(...))` 等模式，并建议使用更简洁的 `sort.Ints(...)` 等辅助函数。

10. **`LintGuardedDelete`**: 检查对 map 进行 `delete` 操作前是否有不必要的 guard，例如 `if _, ok := m[k]; ok { delete(m, k) }`。 由于 `delete` 函数在键不存在时不会产生错误，因此该 guard 是多余的。

11. **`LintSimplifyTypeSwitch`**: 检查 `type switch` 语句中，如果类型断言的结果没有被赋值给新的变量，而在 `case` 子句中又对相同的值进行了多次类型断言，则建议将类型断言的结果赋值给一个变量以避免重复断言。

**以下是一些功能的 Go 代码示例：**

**1. `LintNilCheckAroundTypeAssert`**

```go
package main

func main() {
	var i interface{} = "hello"

	// 假设的输入
	if s, ok := i.(string); ok {
		if i != nil { // honnef.co/go/tools/simple 会标记这里
			println(s)
		}
	}

	// 优化的代码
	if s, ok := i.(string); ok {
		println(s)
	}

	var err error

	// 假设的输入
	if _, ok := err.(interface{ Error() string }); !ok {
		return
	}
	if err != nil { // honnef.co/go/tools/simple 会标记这里
		println(err.Error())
	}

	// 优化的代码
	if e, ok := err.(interface{ Error() string }); ok {
		println(e.Error())
	}

}
```

**2. `LintDeclareAssign`**

```go
package main

func main() {
	// 假设的输入
	var name string // honnef.co/go/tools/simple 会标记这里
	name = "world"

	// 优化的代码
	name := "world"
}
```

**3. `LintRedundantBreak`**

```go
package main

func main() {
	x := 1
	switch x {
	case 1:
		println("one")
		break // honnef.co/go/tools/simple 会标记这里
	}

	// 假设的输入
	println("end")
	return // honnef.co/go/tools/simple 会标记这里
}
```

**5. `LintRedundantSprintf`**

```go
package main

import (
	"fmt"
)

type myString string

func (m myString) String() string {
	return string(m)
}

func main() {
	s := "hello"
	ms := myString("world")

	// 假设的输入
	fmt.Sprintf("%s", s)   // honnef.co/go/tools/simple 会标记这里
	fmt.Sprintf("%s", ms)  // honnef.co/go/tools/simple 会标记这里

	// 优化的代码
	s
	ms.String()
}
```

**6. `LintErrorsNewSprintf`**

```go
package main

import (
	"errors"
	"fmt"
)

func main() {
	name := "Alice"

	// 假设的输入
	errors.New(fmt.Sprintf("invalid name: %s", name)) // honnef.co/go/tools/simple 会标记这里

	// 优化的代码
	fmt.Errorf("invalid name: %s", name)
}
```

**8. `LintNilCheckAroundRange`**

```go
package main

func main() {
	var numbers []int

	// 假设的输入
	if numbers != nil { // honnef.co/go/tools/simple 会标记这里
		for _, num := range numbers {
			println(num)
		}
	}

	// 优化的代码
	for _, num := range numbers {
		println(num)
	}
}
```

**9. `LintSortHelpers`**

```go
package main

import "sort"

func main() {
	numbers := []int{3, 1, 4, 2}

	// 假设的输入
	sort.Sort(sort.IntSlice(numbers)) // honnef.co/go/tools/simple 会标记这里

	// 优化的代码
	sort.Ints(numbers)
}
```

**10. `LintGuardedDelete`**

```go
package main

func main() {
	ages := map[string]int{"Alice": 30, "Bob": 25}
	key := "Charlie"

	// 假设的输入
	if _, ok := ages[key]; ok { // honnef.co/go/tools/simple 会标记这里
		delete(ages, key)
	}

	// 优化的代码
	delete(ages, key)
}
```

**11. `LintSimplifyTypeSwitch`**

```go
package main

func process(i interface{}) {
	switch v := i.(type) {
	case int:
		println("int:", v)
		_ = v.(int) // honnef.co/go/tools/simple 会标记这里
	case string:
		println("string:", v)
		_ = v.(string) // honnef.co/go/tools/simple 会标记这里
	default:
		println("unknown")
	}
}

func main() {
	process(10)
	process("hello")
}
```

**命令行参数:**

这段代码本身没有直接处理命令行参数。它是一个 linter 的一部分，通常会由 `gometalinter` 或其他 lint 工具调用。这些工具会负责处理命令行参数，例如指定要检查的路径、启用/禁用特定的 linters 等。

**使用者易犯错的点 (针对部分 lint 规则):**

*   **`LintNilCheckAroundTypeAssert`**: 有时开发者可能认为类型断言后的 nil 检查是必要的，以处理接口变量本身为 nil 的情况。但实际上，类型断言 `i.(T)` 在 `i` 为 nil 时会返回零值和 `false`，不会 panic。所以额外的 nil 检查通常是冗余的。
*   **`LintNilCheckAroundRange`**:  新手可能会习惯性地在 `range` 循环前检查 slice 或 map 是否为 nil，即使 Go 语言对 nil slice 和 map 的 `range` 操作是安全的。
*   **`LintGuardedDelete`**:  开发者可能不清楚 `delete` 函数在键不存在时不会有副作用，因此添加了额外的判断。

总的来说，这段代码通过静态分析 Go 语言代码，帮助开发者发现一些可以改进的地方，遵循更简洁和地道的 Go 语言编程风格。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/simple/lint.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
 !ok || yident.Obj != ident.Obj {
			return false
		}
		return true
	}
	fn1 := func(node ast.Node) bool {
		ifstmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		assign, ok := ifstmt.Init.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 || !IsBlank(assign.Lhs[0]) {
			return true
		}
		assert, ok := assign.Rhs[0].(*ast.TypeAssertExpr)
		if !ok {
			return true
		}
		binop, ok := ifstmt.Cond.(*ast.BinaryExpr)
		if !ok || binop.Op != token.LAND {
			return true
		}
		assertIdent, ok := assert.X.(*ast.Ident)
		if !ok {
			return true
		}
		assignIdent, ok := assign.Lhs[1].(*ast.Ident)
		if !ok {
			return true
		}
		if !(isNilCheck(assertIdent, binop.X) && isOKCheck(assignIdent, binop.Y)) &&
			!(isNilCheck(assertIdent, binop.Y) && isOKCheck(assignIdent, binop.X)) {
			return true
		}
		j.Errorf(ifstmt, "when %s is true, %s can't be nil", Render(j, assignIdent), Render(j, assertIdent))
		return true
	}
	fn2 := func(node ast.Node) bool {
		// Check that outer ifstmt is an 'if x != nil {}'
		ifstmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		if ifstmt.Init != nil {
			return true
		}
		if ifstmt.Else != nil {
			return true
		}
		if len(ifstmt.Body.List) != 1 {
			return true
		}
		binop, ok := ifstmt.Cond.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		if binop.Op != token.NEQ {
			return true
		}
		lhs, ok := binop.X.(*ast.Ident)
		if !ok {
			return true
		}
		if !IsNil(j, binop.Y) {
			return true
		}

		// Check that inner ifstmt is an `if _, ok := x.(T); ok {}`
		ifstmt, ok = ifstmt.Body.List[0].(*ast.IfStmt)
		if !ok {
			return true
		}
		assign, ok := ifstmt.Init.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 || !IsBlank(assign.Lhs[0]) {
			return true
		}
		assert, ok := assign.Rhs[0].(*ast.TypeAssertExpr)
		if !ok {
			return true
		}
		assertIdent, ok := assert.X.(*ast.Ident)
		if !ok {
			return true
		}
		if lhs.Obj != assertIdent.Obj {
			return true
		}
		assignIdent, ok := assign.Lhs[1].(*ast.Ident)
		if !ok {
			return true
		}
		if !isOKCheck(assignIdent, ifstmt.Cond) {
			return true
		}
		j.Errorf(ifstmt, "when %s is true, %s can't be nil", Render(j, assignIdent), Render(j, assertIdent))
		return true
	}
	fn := func(node ast.Node) bool {
		b1 := fn1(node)
		b2 := fn2(node)
		return b1 || b2
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) LintDeclareAssign(j *lint.Job) {
	fn := func(node ast.Node) bool {
		block, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		if len(block.List) < 2 {
			return true
		}
		for i, stmt := range block.List[:len(block.List)-1] {
			_ = i
			decl, ok := stmt.(*ast.DeclStmt)
			if !ok {
				continue
			}
			gdecl, ok := decl.Decl.(*ast.GenDecl)
			if !ok || gdecl.Tok != token.VAR || len(gdecl.Specs) != 1 {
				continue
			}
			vspec, ok := gdecl.Specs[0].(*ast.ValueSpec)
			if !ok || len(vspec.Names) != 1 || len(vspec.Values) != 0 {
				continue
			}

			assign, ok := block.List[i+1].(*ast.AssignStmt)
			if !ok || assign.Tok != token.ASSIGN {
				continue
			}
			if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				continue
			}
			ident, ok := assign.Lhs[0].(*ast.Ident)
			if !ok {
				continue
			}
			if vspec.Names[0].Obj != ident.Obj {
				continue
			}

			if refersTo(j, assign.Rhs[0], ident) {
				continue
			}
			j.Errorf(decl, "should merge variable declaration with assignment on next line")
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) LintRedundantBreak(j *lint.Job) {
	fn1 := func(node ast.Node) {
		clause, ok := node.(*ast.CaseClause)
		if !ok {
			return
		}
		if len(clause.Body) < 2 {
			return
		}
		branch, ok := clause.Body[len(clause.Body)-1].(*ast.BranchStmt)
		if !ok || branch.Tok != token.BREAK || branch.Label != nil {
			return
		}
		j.Errorf(branch, "redundant break statement")
	}
	fn2 := func(node ast.Node) {
		var ret *ast.FieldList
		var body *ast.BlockStmt
		switch x := node.(type) {
		case *ast.FuncDecl:
			ret = x.Type.Results
			body = x.Body
		case *ast.FuncLit:
			ret = x.Type.Results
			body = x.Body
		default:
			return
		}
		// if the func has results, a return can't be redundant.
		// similarly, if there are no statements, there can be
		// no return.
		if ret != nil || body == nil || len(body.List) < 1 {
			return
		}
		rst, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
		if !ok {
			return
		}
		// we don't need to check rst.Results as we already
		// checked x.Type.Results to be nil.
		j.Errorf(rst, "redundant return statement")
	}
	fn := func(node ast.Node) bool {
		fn1(node)
		fn2(node)
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) Implements(j *lint.Job, typ types.Type, iface string) bool {
	// OPT(dh): we can cache the type lookup
	idx := strings.IndexRune(iface, '.')
	var scope *types.Scope
	var ifaceName string
	if idx == -1 {
		scope = types.Universe
		ifaceName = iface
	} else {
		pkgName := iface[:idx]
		pkg := j.Program.Package(pkgName)
		if pkg == nil {
			return false
		}
		scope = pkg.Types.Scope()
		ifaceName = iface[idx+1:]
	}

	obj := scope.Lookup(ifaceName)
	if obj == nil {
		return false
	}
	i, ok := obj.Type().Underlying().(*types.Interface)
	if !ok {
		return false
	}
	return types.Implements(typ, i)
}

func (c *Checker) LintRedundantSprintf(j *lint.Job) {
	fn := func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !IsCallToAST(j, call, "fmt.Sprintf") {
			return true
		}
		if len(call.Args) != 2 {
			return true
		}
		if s, ok := ExprToString(j, call.Args[Arg("fmt.Sprintf.format")]); !ok || s != "%s" {
			return true
		}
		arg := call.Args[Arg("fmt.Sprintf.a[0]")]
		typ := TypeOf(j, arg)

		if c.Implements(j, typ, "fmt.Stringer") {
			j.Errorf(call, "should use String() instead of fmt.Sprintf")
			return true
		}

		if typ.Underlying() == types.Universe.Lookup("string").Type() {
			if typ == types.Universe.Lookup("string").Type() {
				j.Errorf(call, "the argument is already a string, there's no need to use fmt.Sprintf")
			} else {
				j.Errorf(call, "the argument's underlying type is a string, should use a simple conversion instead of fmt.Sprintf")
			}
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) LintErrorsNewSprintf(j *lint.Job) {
	fn := func(node ast.Node) bool {
		if !IsCallToAST(j, node, "errors.New") {
			return true
		}
		call := node.(*ast.CallExpr)
		if !IsCallToAST(j, call.Args[Arg("errors.New.text")], "fmt.Sprintf") {
			return true
		}
		j.Errorf(node, "should use fmt.Errorf(...) instead of errors.New(fmt.Sprintf(...))")
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) LintRangeStringRunes(j *lint.Job) {
	sharedcheck.CheckRangeStringRunes(j)
}

func (c *Checker) LintNilCheckAroundRange(j *lint.Job) {
	fn := func(node ast.Node) bool {
		ifstmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}

		cond, ok := ifstmt.Cond.(*ast.BinaryExpr)
		if !ok {
			return true
		}

		if cond.Op != token.NEQ || !IsNil(j, cond.Y) || len(ifstmt.Body.List) != 1 {
			return true
		}

		loop, ok := ifstmt.Body.List[0].(*ast.RangeStmt)
		if !ok {
			return true
		}
		ifXIdent, ok := cond.X.(*ast.Ident)
		if !ok {
			return true
		}
		rangeXIdent, ok := loop.X.(*ast.Ident)
		if !ok {
			return true
		}
		if ifXIdent.Obj != rangeXIdent.Obj {
			return true
		}
		switch TypeOf(j, rangeXIdent).(type) {
		case *types.Slice, *types.Map:
			j.Errorf(node, "unnecessary nil check around range")
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func isPermissibleSort(j *lint.Job, node ast.Node) bool {
	call := node.(*ast.CallExpr)
	typeconv, ok := call.Args[0].(*ast.CallExpr)
	if !ok {
		return true
	}

	sel, ok := typeconv.Fun.(*ast.SelectorExpr)
	if !ok {
		return true
	}
	name := SelectorName(j, sel)
	switch name {
	case "sort.IntSlice", "sort.Float64Slice", "sort.StringSlice":
	default:
		return true
	}

	return false
}

func (c *Checker) LintSortHelpers(j *lint.Job) {
	fnFuncs := func(node ast.Node) bool {
		var body *ast.BlockStmt
		switch node := node.(type) {
		case *ast.FuncLit:
			body = node.Body
		case *ast.FuncDecl:
			body = node.Body
		default:
			return true
		}
		if body == nil {
			return true
		}

		type Error struct {
			node lint.Positioner
			msg  string
		}
		var errors []Error
		permissible := false
		fnSorts := func(node ast.Node) bool {
			if permissible {
				return false
			}
			if !IsCallToAST(j, node, "sort.Sort") {
				return true
			}
			if isPermissibleSort(j, node) {
				permissible = true
				return false
			}
			call := node.(*ast.CallExpr)
			typeconv := call.Args[Arg("sort.Sort.data")].(*ast.CallExpr)
			sel := typeconv.Fun.(*ast.SelectorExpr)
			name := SelectorName(j, sel)

			switch name {
			case "sort.IntSlice":
				errors = append(errors, Error{node, "should use sort.Ints(...) instead of sort.Sort(sort.IntSlice(...))"})
			case "sort.Float64Slice":
				errors = append(errors, Error{node, "should use sort.Float64s(...) instead of sort.Sort(sort.Float64Slice(...))"})
			case "sort.StringSlice":
				errors = append(errors, Error{node, "should use sort.Strings(...) instead of sort.Sort(sort.StringSlice(...))"})
			}
			return true
		}
		ast.Inspect(body, fnSorts)

		if permissible {
			return false
		}
		for _, err := range errors {
			j.Errorf(err.node, "%s", err.msg)
		}
		return false
	}

	for _, f := range j.Program.Files {
		ast.Inspect(f, fnFuncs)
	}
}

func (c *Checker) LintGuardedDelete(j *lint.Job) {
	isCommaOkMapIndex := func(stmt ast.Stmt) (b *ast.Ident, m ast.Expr, key ast.Expr, ok bool) {
		// Has to be of the form `_, <b:*ast.Ident> = <m:*types.Map>[<key>]

		assign, ok := stmt.(*ast.AssignStmt)
		if !ok {
			return nil, nil, nil, false
		}
		if len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
			return nil, nil, nil, false
		}
		if !IsBlank(assign.Lhs[0]) {
			return nil, nil, nil, false
		}
		ident, ok := assign.Lhs[1].(*ast.Ident)
		if !ok {
			return nil, nil, nil, false
		}
		index, ok := assign.Rhs[0].(*ast.IndexExpr)
		if !ok {
			return nil, nil, nil, false
		}
		if _, ok := TypeOf(j, index.X).(*types.Map); !ok {
			return nil, nil, nil, false
		}
		key = index.Index
		return ident, index.X, key, true
	}
	fn := func(node ast.Node) bool {
		stmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		if len(stmt.Body.List) != 1 {
			return true
		}
		expr, ok := stmt.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return true
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !IsCallToAST(j, call, "delete") {
			return true
		}
		b, m, key, ok := isCommaOkMapIndex(stmt.Init)
		if !ok {
			return true
		}
		if cond, ok := stmt.Cond.(*ast.Ident); !ok || ObjectOf(j, cond) != ObjectOf(j, b) {
			return true
		}
		if Render(j, call.Args[0]) != Render(j, m) || Render(j, call.Args[1]) != Render(j, key) {
			return true
		}
		j.Errorf(stmt, "unnecessary guard around call to delete")
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) LintSimplifyTypeSwitch(j *lint.Job) {
	fn := func(node ast.Node) bool {
		stmt, ok := node.(*ast.TypeSwitchStmt)
		if !ok {
			return true
		}
		if stmt.Init != nil {
			// bailing out for now, can't anticipate how type switches with initializers are being used
			return true
		}
		expr, ok := stmt.Assign.(*ast.ExprStmt)
		if !ok {
			// the user is in fact assigning the result
			return true
		}
		assert := expr.X.(*ast.TypeAssertExpr)
		ident, ok := assert.X.(*ast.Ident)
		if !ok {
			return true
		}
		x := ObjectOf(j, ident)
		var allOffenders []ast.Node
		for _, clause := range stmt.Body.List {
			clause := clause.(*ast.CaseClause)
			if len(clause.List) != 1 {
				continue
			}
			hasUnrelatedAssertion := false
			var offenders []ast.Node
			ast.Inspect(clause, func(node ast.Node) bool {
				assert2, ok := node.(*ast.TypeAssertExpr)
				if !ok {
					return true
				}
				ident, ok := assert2.X.(*ast.Ident)
				if !ok {
					hasUnrelatedAssertion = true
					return false
				}
				if ObjectOf(j, ident) != x {
					hasUnrelatedAssertion = true
					return false
				}

				if !types.Identical(TypeOf(j, clause.List[0]), TypeOf(j, assert2.Type)) {
					hasUnrelatedAssertion = true
					return false
				}
				offenders = append(offenders, assert2)
				return true
			})
			if !hasUnrelatedAssertion {
				// don't flag cases that have other type assertions
				// unrelated to the one in the case clause. often
				// times, this is done for symmetry, when two
				// different values have to be asserted to the same
				// type.
				allOffenders = append(allOffenders, offenders...)
			}
		}
		if len(allOffenders) != 0 {
			at := ""
			for _, offender := range allOffenders {
				pos := j.Program.DisplayPosition(offender.Pos())
				at += "\n\t" + pos.String()
			}
			j.Errorf(expr, "assigning the result of this type assertion to a variable (switch %s := %s.(type)) could eliminate the following type assertions:%s", Render(j, ident), Render(j, ident), at)
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

"""




```