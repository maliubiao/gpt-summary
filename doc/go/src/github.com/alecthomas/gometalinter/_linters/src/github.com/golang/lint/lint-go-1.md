Response:
Let's break down the thought process for summarizing the Go linter code.

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code snippet, which is part of a linter. It's the *second part* of a larger file. This implies the first part likely handled file parsing and setup.

2. **Initial Scan for Key Functions:**  Quickly read through the function names and comments. This provides a high-level overview of what the linter is checking. Keywords like "lintErrorStrings," "lintReceiverNames," "lintIncDec," etc., immediately suggest specific checks.

3. **Categorize Functionality:** Group related functions together based on the kind of linting they perform. For example, functions starting with "lint" seem to be individual checks. Helper functions like `receiverType`, `exportedType`, `isIdent`, etc., likely support these checks.

4. **Detailed Analysis of `lint...` Functions:**  Go through each `lint...` function:
    * **Identify the Target:** What kind of code construct is being examined (e.g., error strings, receiver names, increment/decrement statements)? Look at the `walk` function and the type assertions inside (e.g., `*ast.CallExpr`, `*ast.FuncDecl`, `*ast.AssignStmt`).
    * **Determine the Rule:** What is the linter trying to enforce (e.g., error strings shouldn't be capitalized, receiver names should be consistent, use `++` instead of `+= 1`)? Look at the error messages generated by `f.errorf`.
    * **Note Confidence Levels:** Pay attention to the confidence level arguments passed to `f.errorf`. This indicates the severity or certainty of the rule.
    * **Consider Specific Cases and Edge Cases:**  Are there any specific conditions or exceptions mentioned in the code or comments (e.g., ignoring CGO exported functions)?

5. **Analyze Helper Functions:**  Understand the purpose of the supporting functions:
    * `lintErrorString`:  This is called by `lintErrorStrings` and performs the detailed checking of the error string content.
    * `receiverType`: Extracts the receiver type from a function declaration.
    * `exportedType`: Checks if a type is exported.
    * `isIdent`, `isBlank`, `isPkgDot`, `isZero`, `isOne`:  Basic checks on AST nodes.
    * `isUntypedConst`: Determines if an expression is an untyped constant.
    * `firstLineOf`, `indentOf`, `srcLineWithMatch`, `srcLine`: Utility functions for formatting error messages and extracting source code.

6. **Identify Data Structures:** Note any important data structures used, like `typeReceiver` in `lintReceiverNames`.

7. **Connect the Dots:** Understand how the different functions interact. For example, `lintErrorStrings` uses `lintErrorString`. The `walk` function is crucial for traversing the Abstract Syntax Tree (AST).

8. **Synthesize the Summary:**  Combine the information gathered into a concise summary, addressing the points requested in the original prompt:
    * **Overall Functionality:** Describe the main purpose of the code (performing static analysis of Go code).
    * **Specific Checks:** List the different kinds of linting checks performed, using clear and concise descriptions.
    * **Helper Functions:** Briefly mention the role of supporting functions.
    * **Underlying Mechanism:** Explain that it works by traversing the AST.
    * **Focus on Style and Best Practices:**  Highlight that the checks aim to enforce Go style conventions.

9. **Review and Refine:**  Read through the summary to ensure accuracy, completeness, and clarity. Check if it addresses all aspects of the prompt. Make sure the language is clear and easy to understand. For instance, initially, I might just say "checks error strings."  Refining it to "检查 `errors.New` 和 `fmt.Errorf` 创建的错误字符串，确保它们没有大写字母开头，并且没有以标点符号或换行符结尾" provides much more specific information. Similarly, expanding on the "naming conventions" to list specific examples like receiver names and time-related variable names enhances clarity.

10. **Consider the "Part 2" Aspect:** Remember that this is the *second* part. While the prompt doesn't explicitly ask about the first part, acknowledge that this section builds upon the foundation laid in the initial part (likely file parsing and AST creation). This provides context.

By following this structured approach, one can systematically analyze the code and generate a comprehensive and accurate summary of its functionality. The key is to move from a high-level understanding to a detailed analysis of individual components and then synthesize the findings back into a coherent description.
这是提供的 Go 语言代码片段的第 2 部分，它主要包含了 `lint.go` 文件中关于代码风格检查的具体实现逻辑。在第 1 部分中，可能包含了文件解析、AST 构建以及结构体定义等基础工作。

**功能归纳:**

这段代码的主要功能是**对 Go 语言代码进行静态分析，以检查并报告违反 Go 语言代码风格规范和一些潜在问题的代码。** 它通过遍历代码的抽象语法树 (AST)，并针对特定的代码结构和模式进行检查。

具体来说，这段代码实现了以下几个方面的代码检查：

1. **错误字符串 (Error Strings) 的格式检查:**
   - **规则:** 错误字符串不应该以大写字母开头，也不应该以标点符号或换行符结尾。
   - **实现:**  遍历所有 `errors.New` 和 `fmt.Errorf` 的调用，提取其参数中的字符串字面量，并使用 `lintErrorString` 函数进行检查。
   - **`lintErrorString` 函数:**  检查字符串的首字母是否大写，以及是否以标点符号结尾。它还会对首字母缩略词进行特殊处理，降低对包含首字母缩略词的错误字符串的警告置信度。

2. **接收者名称 (Receiver Names) 的一致性检查:**
   - **规则:** 对于同一个类型的方法，应该使用一致的接收者名称。接收者名称不应该是下划线 `_`，也不应该是通用的名称如 "this" 或 "self"。
   - **实现:** 遍历所有函数声明，提取其接收者名称和类型。使用 `typeReceiver` map 记录每个类型首次出现的接收者名称，如果后续出现不同的名称，则报告错误。

3. **自增/自减操作的规范性检查:**
   - **规则:**  应该使用 `x++` 或 `x--` 来进行自增或自减操作，而不是 `x += 1` 或 `x -= 1`。
   - **实现:** 遍历赋值语句，检查是否为加一或减一的操作，如果发现使用 `+= 1` 或 `-= 1` 的形式，则报告错误。

4. **错误返回值 (Error Return) 的位置检查:**
   - **规则:** 当函数返回多个值时，`error` 类型的值应该作为最后一个返回值。
   - **实现:** 遍历函数声明，检查其返回值列表。如果 `error` 类型的返回值出现在最后一个之前，则报告错误。

5. **导出函数返回未导出类型 (Unexported Return) 的检查:**
   - **规则:** 导出函数或方法的返回值不应该包含未导出的类型，因为这会使 API 的使用者难以使用这些返回值。
   - **实现:** 遍历导出的函数和方法声明，检查其返回值类型。使用 `exportedType` 函数判断类型是否已导出。
   - **`exportedType` 函数:**  判断一个类型是否已导出，对基本类型、命名类型、Map、数组、切片、指针、通道等类型进行递归检查。对于结构体和接口等其他类型，则保守地认为已导出。

6. **与时间相关的变量命名检查:**
   - **规则:**  如果变量的类型是 `time.Duration` 或 `*time.Duration`，则不应该在变量名中使用表示时间单位的后缀 (例如 "Sec", "Milli")。
   - **实现:** 遍历变量声明，检查其类型是否为 `time.Duration` 或 `*time.Duration`。如果变量名包含 `timeSuffixes` 中定义的后缀，则报告错误。

7. **`context.WithValue` 的键类型检查:**
   - **规则:**  不应该使用基本类型 (如 `int`, `string`, `bool`) 作为 `context.WithValue` 的键，应该使用自定义的类型。
   - **实现:** 遍历函数调用，检查是否调用了 `context.WithValue`。如果是，则检查其第二个参数（键）的类型是否为基本类型。

8. **`context.Context` 参数的位置检查:**
   - **规则:** 如果函数包含 `context.Context` 类型的参数，它应该作为第一个参数。
   - **实现:** 遍历函数声明，检查参数列表。如果 `context.Context` 类型的参数出现在第一个之后，则报告错误。

**Go 代码举例说明:**

```go
package example

import (
	"errors"
	"fmt"
	"time"
	"context"
)

// 错误字符串的例子
func badError() error {
	return errors.New("Error occurred.") // 错误：首字母大写，句号结尾
}

func goodError() error {
	return errors.New("error occurred")
}

func badErrorf() error {
	return fmt.Errorf("Error: %s", "something") // 错误：首字母大写
}

func goodErrorf() error {
	return fmt.Errorf("error: %s", "something")
}

// 接收者名称的例子
type MyType struct{}

func (t *MyType) DoSomething() {} // 良好

func (this *MyType) DoSomethingElse() {} // 错误：不应该使用 "this"

type AnotherType struct{}

func (a *AnotherType) Process() {} // 良好

func (b *AnotherType) Handle() {} // 错误：接收者名称不一致

// 自增/自减的例子
func increment(i int) {
	i += 1 // 错误：应该使用 i++
	i++    // 良好
}

// 错误返回值的例子
func badReturn() (string, error) {
	return "", errors.New("something went wrong") // 错误：error 不在最后
}

func goodReturn() (string, error) {
	return "", errors.New("something went wrong")
}

type unexportedType struct{}

// 导出函数返回未导出类型的例子
func ExportedFunc() unexportedType { // 错误：返回了未导出的类型
	return unexportedType{}
}

// 时间相关的变量命名例子
func process(timeoutSec time.Duration) { // 错误：不应使用 "Sec" 后缀
	fmt.Println(timeoutSec)
}

func processGood(timeout time.Duration) {
	fmt.Println(timeout)
}

// context.WithValue 键类型例子
func withBadContextKey(ctx context.Context, key string, value string) context.Context {
	return context.WithValue(ctx, key, value) // 错误：使用 string 作为 key
}

type contextKey string

func withGoodContextKey(ctx context.Context, key contextKey, value string) context.Context {
	return context.WithValue(ctx, key, value)
}

// context.Context 参数位置例子
func badContextArg(data string, ctx context.Context) { // 错误：context.Context 不在最前面
	fmt.Println(data, ctx)
}

func goodContextArg(ctx context.Context, data string) {
	fmt.Println(data, ctx)
}
```

**假设的输入与输出:**

假设我们有一个包含上面 `badError` 函数的 Go 源文件 `example.go`。

**输入:** `example.go` 的内容

**输出:**  gometalinter 可能会输出如下错误信息：

```
example.go:10:5: error strings should not be capitalized or end with punctuation or a newline (style)
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。`gometalinter` 作为调用它的工具，会负责解析命令行参数，例如要检查的文件路径、启用的 linters 等。这段代码是 `gometalinter` 内部 `golangci-lint` 的一部分，它的行为受到 `gometalinter` 的配置影响。  通常，`gometalinter` 会读取配置文件或者接收命令行参数来决定要执行哪些检查。

**使用者易犯错的点:**

1. **错误字符串首字母大写或以标点结尾:**  这是很常见的错误，尤其是在从其他语言迁移过来的开发者中。
2. **接收者名称不一致:**  在大型项目中，如果没有统一的规范，很容易出现同一个类型的方法使用不同的接收者名称。
3. **不规范的自增/自减操作:**  虽然 `+= 1` 和 `++` 的效果相同，但 Go 社区更推荐使用简洁的 `++` 和 `--`。
4. **错误返回值的位置:**  可能会忘记将 `error` 放在最后，特别是在返回多个值的情况下。
5. **在导出函数中返回未导出类型:**  这会导致 API 的使用者无法直接操作这些返回的值，需要进行类型断言或者通过其他方式间接访问。
6. **在类型为 `time.Duration` 的变量名中使用时间单位后缀:** 这会造成冗余，因为类型本身已经表明了单位。
7. **使用基本类型作为 `context.WithValue` 的键:** 这可能导致命名冲突，不同的包可能使用相同的基本类型键，但含义不同。
8. **`context.Context` 参数不在首位:**  这是 Go 社区的约定俗成，有助于提高代码的可读性和一致性。

总而言之，这段代码是 `gometalinter` 中用于进行代码风格检查的核心逻辑之一，它通过一系列规则来确保 Go 代码的质量和一致性。它专注于常见的代码风格问题和潜在的 API 设计问题。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/golang/lint/lint.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
per nouns and exported Go identifiers in error strings,
		// so decrease the confidence of warnings for capitalization.
		if len(s) <= firstN {
			return false, capConfidence
		}
		// Flag strings starting with something that doesn't look like an initialism.
		if second, _ := utf8.DecodeRuneInString(s[firstN:]); !unicode.IsUpper(second) {
			return false, capConfidence
		}
	}
	return true, 0
}

// lintErrorStrings examines error strings.
// It complains if they are capitalized or end in punctuation or a newline.
func (f *file) lintErrorStrings() {
	f.walk(func(node ast.Node) bool {
		ce, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !isPkgDot(ce.Fun, "errors", "New") && !isPkgDot(ce.Fun, "fmt", "Errorf") {
			return true
		}
		if len(ce.Args) < 1 {
			return true
		}
		str, ok := ce.Args[0].(*ast.BasicLit)
		if !ok || str.Kind != token.STRING {
			return true
		}
		s, _ := strconv.Unquote(str.Value) // can assume well-formed Go
		if s == "" {
			return true
		}
		clean, conf := lintErrorString(s)
		if clean {
			return true
		}

		f.errorf(str, conf, link(styleGuideBase+"#error-strings"), category("errors"),
			"error strings should not be capitalized or end with punctuation or a newline")
		return true
	})
}

// lintReceiverNames examines receiver names. It complains about inconsistent
// names used for the same type and names such as "this".
func (f *file) lintReceiverNames() {
	typeReceiver := map[string]string{}
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
			f.errorf(n, 1, link(ref), category("naming"), `receiver name should not be an underscore`)
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

func isZero(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
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