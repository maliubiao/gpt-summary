Response:
Let's break down the thought process for analyzing this Go code snippet. The request asks for a summary of the functionality. Since this is part 2 of 2, it's reasonable to assume part 1 covered the foundational aspects of the linter, and this part delves into specific checks.

**1. Initial Scan and Keyword Spotting:**

The first step is a quick read-through, looking for keywords and patterns that suggest functionality. Things that jump out are:

* `lint...`:  Several functions start with "lint," strongly suggesting linting rules.
* `f.walk`: This suggests traversal of the Abstract Syntax Tree (AST).
* `f.errorf`:  Indicates reporting of errors or warnings.
* `category(...)`:  Errors are being categorized.
* `ast.Node`, `ast.FuncDecl`, `ast.AssignStmt`, etc.: These are AST node types, confirming AST processing.
* Specific Go language constructs being checked: receiver names, increment/decrement operators, error return positions, unexported returns, time variable names, `context.WithValue` keys, `context.Context` arguments.

**2. Function-by-Function Analysis (Deeper Dive):**

Now, go through each `lint...` function to understand its specific purpose.

* **`lintReceiver`:** Focuses on method receiver names. It checks for underscores, generic names ("this", "self"), and consistency across methods of the same type.

* **`lintIncDec`:**  Checks for the correct usage of increment and decrement operators (`++`, `--`) instead of equivalent assignment forms (`+= 1`, `-= 1`).

* **`lintErrorReturn`:**  Validates the position of error return values in function signatures. Errors should be the last return value.

* **`lintUnexportedReturn`:**  Checks if exported functions return unexported types, which can cause usability issues for consumers of the API. It considers both regular functions and methods.

* **`lintTimeNames`:**  Looks for variables of type `time.Duration` (or `*time.Duration`) and flags them if their names have time unit suffixes (e.g., "Milliseconds"). This encourages a more consistent naming convention.

* **`lintContextKeyTypes`:** Specifically targets calls to `context.WithValue` and warns if basic types are used as keys. This is based on a known Go issue and best practice.

* **`lintContextArgs`:**  Checks if `context.Context` parameters are the first argument in function signatures, as per Go conventions.

**3. Identifying Helper Functions:**

Notice functions like `receiverType`, `exportedType`, `isIdent`, `isPkgDot`, `isOne`, etc. These are utility functions that support the linting logic. Understanding their purpose helps clarify the overall flow. For instance, `receiverType` extracts the receiver type from a function declaration, which is used by `lintReceiver` and `lintUnexportedReturn`.

**4. Inferring Overall Goal:**

By examining the individual linting rules, the overarching goal becomes clear: **to enforce Go coding conventions and best practices to improve code readability, maintainability, and reduce potential errors.**  This aligns with the purpose of a linter.

**5. Addressing Specific Parts of the Prompt:**

* **Functionality Listing:**  This comes directly from the function-by-function analysis.
* **Go Language Feature:** The code is implementing static analysis/linting for Go code.
* **Code Examples:**  Think about how each rule could be violated and create simple examples that the linter would flag. For instance, for `lintReceiver`, create a method with a receiver named "this".
* **Command-Line Arguments:**  This section of the code doesn't show command-line processing. State that.
* **Common Mistakes:**  Consider what errors a developer might make that these linting rules catch. For `lintErrorReturn`, a common mistake is putting the error return in the middle.
* **Part 2 Summary:** Synthesize the findings into a concise summary focusing on the types of checks performed.

**6. Structuring the Answer:**

Organize the answer logically, starting with a general overview and then detailing each function's purpose. Use clear and concise language. Use bullet points or numbered lists for readability. Include the requested code examples and explanations.

**Self-Correction/Refinement during the process:**

* Initially, I might have just listed the function names without explaining their purpose. Realizing the prompt asks for *functionality*, I would refine the answer to describe *what* each function does.
* I might initially forget to mention the AST traversal. Reviewing the code, the `f.walk` calls are prominent, so I'd add that as a key mechanism.
* I might initially miss the connection between the linting rules and broader Go best practices. Reflecting on the individual rules helps identify the underlying principles (e.g., error handling conventions, API design).
* I might initially focus too much on the low-level details of AST node types. The prompt asks for a higher-level understanding of the *functionality*, so I'd adjust the focus accordingly.

By following these steps, the comprehensive and accurate answer provided previously can be constructed. The key is a systematic approach, moving from a high-level overview to specific details and then synthesizing the information.
这是 `go/src/github.com/golang/lint/lint.go` 文件的一部分，它实现了一系列用于检查 Go 语言代码风格和潜在错误的静态分析功能（linting）。 这部分代码专注于以下几个方面的检查：

**功能列表:**

1. **检查方法接收者 (receiver) 的命名:**
   - 确保方法接收者的命名符合 Go 的风格指南。
   - 禁止使用下划线 `_` 作为接收者名称。
   - 禁止使用过于通用的名称，如 `this` 或 `self`。
   - 强制同一类型的方法接收者名称保持一致。

2. **检查递增/递减语句的写法:**
   - 建议使用 `x++` 或 `x--` 替代等效的赋值语句，例如 `x += 1` 或 `x -= 1`。

3. **检查函数返回值中 `error` 的位置:**
   - 当函数返回多个值时，`error` 类型的值应该总是最后一个返回值。

4. **检查导出函数是否返回了未导出的类型:**
   - 如果一个导出的函数或方法返回了未导出的类型，会发出警告，因为这可能会给使用者带来不便。

5. **检查 `time.Duration` 类型变量的命名:**
   - 建议不要在 `time.Duration` 类型的变量名中使用表示时间单位的后缀（例如 "Sec", "MilliSeconds"）。

6. **检查 `context.WithValue` 的键类型:**
   - 建议不要使用基本类型（如 `int`, `string` 等）作为 `context.WithValue` 的键，以避免键冲突。

7. **检查带有 `context.Context` 参数的函数:**
   - 强制 `context.Context` 类型的参数作为函数的第一个参数。

**Go 语言功能实现：静态代码分析 (Linting)**

这段代码是 Go 语言静态分析工具的一部分，它通过遍历代码的抽象语法树 (AST) 来进行检查。  `f.walk` 函数用于遍历 AST 节点，针对不同类型的节点执行相应的检查逻辑。

**Go 代码举例说明:**

**1. 检查方法接收者的命名:**

```go
package main

type MyType struct {
	value int
}

// 错误示例：接收者使用下划线
func (_ MyType) GetValue1() int {
	return 1
}

// 错误示例：接收者使用通用名称
func (this MyType) GetValue2() int {
	return 2
}

// 正确示例
func (mt MyType) GetValue3() int {
	return mt.value
}

type AnotherType struct {
	data string
}

// 假设之前已经有了一个 AnotherType 的方法使用了接收者名称 "at"
// 错误示例：不一致的接收者名称
func (another AnotherType) Process() {
	println(another.data)
}

func main() {}
```

**假设输入:** 上述包含错误示例的 Go 代码文件。

**预期输出:**  lint 工具会报告以下错误：

```
lint.go:6:6: receiver name should not be an underscore, omit the name if it is unused
lint.go:11:6: receiver name should be a reflection of its identity; don't use generic names such as "this" or "self"
lint.go:22:6: receiver name another should be consistent with previous receiver name at for main.AnotherType
```

**2. 检查递增/递减语句的写法:**

```go
package main

func main() {
	x := 0
	x += 1 // 应该替换为 x++
	y := 10
	y -= 1 // 应该替换为 y--
}
```

**假设输入:** 上述包含非推荐写法的 Go 代码文件。

**预期输出:** lint 工具会报告以下错误：

```
lint.go:4:2: should replace x += 1 with x++
lint.go:6:2: should replace y -= 1 with y--
```

**3. 检查函数返回值中 `error` 的位置:**

```go
package main

import "errors"

func example() (string, error, int) {
	return "hello", errors.New("world"), 1
}

func main() {}
```

**假设输入:** 上述 `example` 函数返回 `error` 但不是最后一个。

**预期输出:** lint 工具会报告以下错误：

```
lint.go:5:13: error should be the last type when returning multiple items
```

**4. 检查导出函数是否返回了未导出的类型:**

```go
package mypackage

type internalType struct { // 未导出的类型
	value int
}

// MyExportedFunc 返回了未导出的类型
func MyExportedFunc() internalType {
	return internalType{value: 1}
}
```

**假设输入:** 上述代码中 `MyExportedFunc` 返回了未导出的 `internalType`。

**预期输出:** lint 工具会报告以下错误：

```
mypackage.go:7:1: exported func MyExportedFunc returns unexported type mypackage.internalType, which can be annoying to use
```

**5. 检查 `time.Duration` 类型变量的命名:**

```go
package main

import "time"

func main() {
	var timeoutSeconds time.Duration // 应该避免 "Seconds" 后缀
	timeoutSeconds = 5 * time.Second
}
```

**假设输入:** 上述代码中 `timeoutSeconds` 变量名包含 "Seconds" 后缀。

**预期输出:** lint 工具会报告以下错误：

```
main.go:6:6: var timeoutSeconds is of type time.Duration; don't use unit-specific suffix "Seconds"
```

**6. 检查 `context.WithValue` 的键类型:**

```go
package main

import (
	"context"
)

func main() {
	ctx := context.Background()
	ctx = context.WithValue(ctx, "mykey", "value") // 错误：使用字符串作为键
}
```

**假设输入:** 上述代码中 `context.WithValue` 使用了字符串字面量作为键。

**预期输出:** lint 工具会报告以下错误：

```
main.go:8:16: should not use basic type string as key in context.WithValue
```

**7. 检查带有 `context.Context` 参数的函数:**

```go
package main

import "context"

func process(data string, ctx context.Context) { // 错误：ctx 应该作为第一个参数
	println(data)
}

func main() {}
```

**假设输入:** 上述 `process` 函数中 `context.Context` 参数不是第一个。

**预期输出:** lint 工具会报告以下错误：

```
main.go:5:22: context.Context should be the first parameter of a function
```

**命令行参数处理:**

这段代码本身并没有直接处理命令行参数。它是一个用于执行具体检查逻辑的模块。通常，像 `golint` 这样的工具会有一个主程序来解析命令行参数，例如指定要检查的文件或目录，并调用 `lint.go` 中定义的检查功能。

你可以通过 `go help build` 或 `go help run` 等命令来了解 Go 语言本身处理命令行参数的方式，但对于 `golint` 这样的工具，它会有自己的命令行参数解析逻辑，通常会使用 `flag` 标准库或者第三方库来实现。

**使用者易犯错的点:**

1. **忽略 lint 工具的警告:**  初学者可能不理解 lint 工具的意义，或者觉得某些警告无关紧要，从而忽略这些提示。这会导致代码风格不一致，甚至引入潜在的错误。

2. **不理解某些检查规则背后的原因:** 例如，为什么 `error` 必须是最后一个返回值，或者为什么不应该在 `time.Duration` 变量名中使用单位后缀。理解这些规则背后的最佳实践可以帮助写出更规范、更易于维护的代码。

3. **过度依赖 lint 工具而忽略代码审查:**  lint 工具只能进行静态分析，无法发现所有的逻辑错误或设计缺陷。代码审查仍然是保证代码质量的重要环节。

**功能归纳（针对第2部分）:**

这段代码是 Go 语言静态分析工具 `golint` 的一部分，它定义了一系列具体的代码检查规则，用于强制执行 Go 语言的编码规范和最佳实践。这些规则涵盖了方法接收者命名、递增/递减语句写法、函数返回值顺序、导出 API 的类型使用、特定类型（如 `time.Duration` 和 `context.Context`）的使用规范等方面。  它通过遍历 Go 语言代码的抽象语法树，并根据预设的规则对代码进行检查，从而帮助开发者编写更清晰、更规范、更健壮的 Go 代码。 这一部分主要关注的是各种细粒度的代码风格和潜在问题的检查逻辑的具体实现。

Prompt: 
```
这是路径为go/src/github.com/golang/lint/lint.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
eceiver := map[string]string{}
	f.walk(func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
			return true
		}
		names := fn.Recv.List[0].Names
		if len(names) < 1 {
			return true
		}
		name := names[0].Name
		const ref = styleGuideBase + "#receiver-names"
		if name == "_" {
			f.errorf(n, 1, link(ref), category("naming"), `receiver name should not be an underscore, omit the name if it is unused`)
			return true
		}
		if name == "this" || name == "self" {
			f.errorf(n, 1, link(ref), category("naming"), `receiver name should be a reflection of its identity; don't use generic names such as "this" or "self"`)
			return true
		}
		recv := receiverType(fn)
		if prev, ok := typeReceiver[recv]; ok && prev != name {
			f.errorf(n, 1, link(ref), category("naming"), "receiver name %s should be consistent with previous receiver name %s for %s", name, prev, recv)
			return true
		}
		typeReceiver[recv] = name
		return true
	})
}

// lintIncDec examines statements that increment or decrement a variable.
// It complains if they don't use x++ or x--.
func (f *file) lintIncDec() {
	f.walk(func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if len(as.Lhs) != 1 {
			return true
		}
		if !isOne(as.Rhs[0]) {
			return true
		}
		var suffix string
		switch as.Tok {
		case token.ADD_ASSIGN:
			suffix = "++"
		case token.SUB_ASSIGN:
			suffix = "--"
		default:
			return true
		}
		f.errorf(as, 0.8, category("unary-op"), "should replace %s with %s%s", f.render(as), f.render(as.Lhs[0]), suffix)
		return true
	})
}

// lintErrorReturn examines function declarations that return an error.
// It complains if the error isn't the last parameter.
func (f *file) lintErrorReturn() {
	f.walk(func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Type.Results == nil {
			return true
		}
		ret := fn.Type.Results.List
		if len(ret) <= 1 {
			return true
		}
		if isIdent(ret[len(ret)-1].Type, "error") {
			return true
		}
		// An error return parameter should be the last parameter.
		// Flag any error parameters found before the last.
		for _, r := range ret[:len(ret)-1] {
			if isIdent(r.Type, "error") {
				f.errorf(fn, 0.9, category("arg-order"), "error should be the last type when returning multiple items")
				break // only flag one
			}
		}
		return true
	})
}

// lintUnexportedReturn examines exported function declarations.
// It complains if any return an unexported type.
func (f *file) lintUnexportedReturn() {
	f.walk(func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		if fn.Type.Results == nil {
			return false
		}
		if !fn.Name.IsExported() {
			return false
		}
		thing := "func"
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			thing = "method"
			if !ast.IsExported(receiverType(fn)) {
				// Don't report exported methods of unexported types,
				// such as private implementations of sort.Interface.
				return false
			}
		}
		for _, ret := range fn.Type.Results.List {
			typ := f.pkg.typeOf(ret.Type)
			if exportedType(typ) {
				continue
			}
			f.errorf(ret.Type, 0.8, category("unexported-type-in-api"),
				"exported %s %s returns unexported type %s, which can be annoying to use",
				thing, fn.Name.Name, typ)
			break // only flag one
		}
		return false
	})
}

// exportedType reports whether typ is an exported type.
// It is imprecise, and will err on the side of returning true,
// such as for composite types.
func exportedType(typ types.Type) bool {
	switch T := typ.(type) {
	case *types.Named:
		// Builtin types have no package.
		return T.Obj().Pkg() == nil || T.Obj().Exported()
	case *types.Map:
		return exportedType(T.Key()) && exportedType(T.Elem())
	case interface {
		Elem() types.Type
	}: // array, slice, pointer, chan
		return exportedType(T.Elem())
	}
	// Be conservative about other types, such as struct, interface, etc.
	return true
}

// timeSuffixes is a list of name suffixes that imply a time unit.
// This is not an exhaustive list.
var timeSuffixes = []string{
	"Sec", "Secs", "Seconds",
	"Msec", "Msecs",
	"Milli", "Millis", "Milliseconds",
	"Usec", "Usecs", "Microseconds",
	"MS", "Ms",
}

func (f *file) lintTimeNames() {
	f.walk(func(node ast.Node) bool {
		v, ok := node.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, name := range v.Names {
			origTyp := f.pkg.typeOf(name)
			// Look for time.Duration or *time.Duration;
			// the latter is common when using flag.Duration.
			typ := origTyp
			if pt, ok := typ.(*types.Pointer); ok {
				typ = pt.Elem()
			}
			if !f.pkg.isNamedType(typ, "time", "Duration") {
				continue
			}
			suffix := ""
			for _, suf := range timeSuffixes {
				if strings.HasSuffix(name.Name, suf) {
					suffix = suf
					break
				}
			}
			if suffix == "" {
				continue
			}
			f.errorf(v, 0.9, category("time"), "var %s is of type %v; don't use unit-specific suffix %q", name.Name, origTyp, suffix)
		}
		return true
	})
}

// lintContextKeyTypes checks for call expressions to context.WithValue with
// basic types used for the key argument.
// See: https://golang.org/issue/17293
func (f *file) lintContextKeyTypes() {
	f.walk(func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.CallExpr:
			f.checkContextKeyType(node)
		}

		return true
	})
}

// checkContextKeyType reports an error if the call expression calls
// context.WithValue with a key argument of basic type.
func (f *file) checkContextKeyType(x *ast.CallExpr) {
	sel, ok := x.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "context" {
		return
	}
	if sel.Sel.Name != "WithValue" {
		return
	}

	// key is second argument to context.WithValue
	if len(x.Args) != 3 {
		return
	}
	key := f.pkg.typesInfo.Types[x.Args[1]]

	if ktyp, ok := key.Type.(*types.Basic); ok && ktyp.Kind() != types.Invalid {
		f.errorf(x, 1.0, category("context"), fmt.Sprintf("should not use basic type %s as key in context.WithValue", key.Type))
	}
}

// lintContextArgs examines function declarations that contain an
// argument with a type of context.Context
// It complains if that argument isn't the first parameter.
func (f *file) lintContextArgs() {
	f.walk(func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || len(fn.Type.Params.List) <= 1 {
			return true
		}
		// A context.Context should be the first parameter of a function.
		// Flag any that show up after the first.
		for _, arg := range fn.Type.Params.List[1:] {
			if isPkgDot(arg.Type, "context", "Context") {
				f.errorf(fn, 0.9, link("https://golang.org/pkg/context/"), category("arg-order"), "context.Context should be the first parameter of a function")
				break // only flag one
			}
		}
		return true
	})
}

// containsComments returns whether the interval [start, end) contains any
// comments without "// MATCH " prefix.
func (f *file) containsComments(start, end token.Pos) bool {
	for _, cgroup := range f.f.Comments {
		comments := cgroup.List
		if comments[0].Slash >= end {
			// All comments starting with this group are after end pos.
			return false
		}
		if comments[len(comments)-1].Slash < start {
			// Comments group ends before start pos.
			continue
		}
		for _, c := range comments {
			if start <= c.Slash && c.Slash < end && !strings.HasPrefix(c.Text, "// MATCH ") {
				return true
			}
		}
	}
	return false
}

// receiverType returns the named type of the method receiver, sans "*",
// or "invalid-type" if fn.Recv is ill formed.
func receiverType(fn *ast.FuncDecl) string {
	switch e := fn.Recv.List[0].Type.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	// The parser accepts much more than just the legal forms.
	return "invalid-type"
}

func (f *file) walk(fn func(ast.Node) bool) {
	ast.Walk(walker(fn), f.f)
}

func (f *file) render(x interface{}) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, f.fset, x); err != nil {
		panic(err)
	}
	return buf.String()
}

func (f *file) debugRender(x interface{}) string {
	var buf bytes.Buffer
	if err := ast.Fprint(&buf, f.fset, x, nil); err != nil {
		panic(err)
	}
	return buf.String()
}

// walker adapts a function to satisfy the ast.Visitor interface.
// The function return whether the walk should proceed into the node's children.
type walker func(ast.Node) bool

func (w walker) Visit(node ast.Node) ast.Visitor {
	if w(node) {
		return w
	}
	return nil
}

func isIdent(expr ast.Expr, ident string) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == ident
}

// isBlank returns whether id is the blank identifier "_".
// If id == nil, the answer is false.
func isBlank(id *ast.Ident) bool { return id != nil && id.Name == "_" }

func isPkgDot(expr ast.Expr, pkg, name string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	return ok && isIdent(sel.X, pkg) && isIdent(sel.Sel, name)
}

func isOne(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "1"
}

func isCgoExported(f *ast.FuncDecl) bool {
	if f.Recv != nil || f.Doc == nil {
		return false
	}

	cgoExport := regexp.MustCompile(fmt.Sprintf("(?m)^//export %s$", regexp.QuoteMeta(f.Name.Name)))
	for _, c := range f.Doc.List {
		if cgoExport.MatchString(c.Text) {
			return true
		}
	}
	return false
}

var basicTypeKinds = map[types.BasicKind]string{
	types.UntypedBool:    "bool",
	types.UntypedInt:     "int",
	types.UntypedRune:    "rune",
	types.UntypedFloat:   "float64",
	types.UntypedComplex: "complex128",
	types.UntypedString:  "string",
}

// isUntypedConst reports whether expr is an untyped constant,
// and indicates what its default type is.
// scope may be nil.
func (f *file) isUntypedConst(expr ast.Expr) (defType string, ok bool) {
	// Re-evaluate expr outside of its context to see if it's untyped.
	// (An expr evaluated within, for example, an assignment context will get the type of the LHS.)
	exprStr := f.render(expr)
	tv, err := types.Eval(f.fset, f.pkg.typesPkg, expr.Pos(), exprStr)
	if err != nil {
		return "", false
	}
	if b, ok := tv.Type.(*types.Basic); ok {
		if dt, ok := basicTypeKinds[b.Kind()]; ok {
			return dt, true
		}
	}

	return "", false
}

// firstLineOf renders the given node and returns its first line.
// It will also match the indentation of another node.
func (f *file) firstLineOf(node, match ast.Node) string {
	line := f.render(node)
	if i := strings.Index(line, "\n"); i >= 0 {
		line = line[:i]
	}
	return f.indentOf(match) + line
}

func (f *file) indentOf(node ast.Node) string {
	line := srcLine(f.src, f.fset.Position(node.Pos()))
	for i, r := range line {
		switch r {
		case ' ', '\t':
		default:
			return line[:i]
		}
	}
	return line // unusual or empty line
}

func (f *file) srcLineWithMatch(node ast.Node, pattern string) (m []string) {
	line := srcLine(f.src, f.fset.Position(node.Pos()))
	line = strings.TrimSuffix(line, "\n")
	rx := regexp.MustCompile(pattern)
	return rx.FindStringSubmatch(line)
}

// imports returns true if the current file imports the specified package path.
func (f *file) imports(importPath string) bool {
	all := astutil.Imports(f.fset, f.f)
	for _, p := range all {
		for _, i := range p {
			uq, err := strconv.Unquote(i.Path.Value)
			if err == nil && importPath == uq {
				return true
			}
		}
	}
	return false
}

// srcLine returns the complete line at p, including the terminating newline.
func srcLine(src []byte, p token.Position) string {
	// Run to end of line in both directions if not at line start/end.
	lo, hi := p.Offset, p.Offset+1
	for lo > 0 && src[lo-1] != '\n' {
		lo--
	}
	for hi < len(src) && src[hi-1] != '\n' {
		hi++
	}
	return string(src[lo:hi])
}

"""




```