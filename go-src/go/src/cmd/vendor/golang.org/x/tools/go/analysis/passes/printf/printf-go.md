Response:
My thinking process to answer the request about `go/src/cmd/vendor/golang.org/x/tools/go/analysis/passes/printf/printf.go` went something like this:

1. **Understand the Goal:** The core request is to explain the functionality of the provided Go code snippet. This involves identifying what it does, illustrating its use, and pointing out potential pitfalls.

2. **Initial Scan and Keyword Spotting:** I quickly scanned the code for recognizable keywords and structures. Things like `package printf`, `import`, `func`, `analysis.Analyzer`, `fmt.Printf`, `fmt.Print`, `fmt.Errorf`, `%`, `string`, `interface{}`, etc., immediately jump out. This gives me a high-level idea that it's related to analyzing `printf`-like functions in Go code.

3. **Identifying the Main Analyzer:** The `Analyzer` variable is a key indicator. It defines an analysis pass within the `golang.org/x/tools/go/analysis` framework. The `Name`, `Doc`, `Requires`, and `Run` fields are essential for understanding its purpose and how it operates. Specifically, the `Requires: []*analysis.Analyzer{inspect.Analyzer}` tells me it uses the `inspect` pass to traverse the AST.

4. **Dissecting the `run` Function:**  The `run` function is the entry point of the analysis. It creates a `Result` struct and calls `findPrintfLike` and `checkCall`. This suggests two main phases of the analysis.

5. **Analyzing `findPrintfLike`:**  The function name itself hints at its purpose. Reading through the code, I see it identifies functions that *look* like `printf` wrappers based on their signature (`...interface{}`). It also builds a call graph of these potential wrappers. The code comments, particularly around "wrapper," confirm this.

6. **Analyzing `checkCall`:** This function uses the `inspect` pass to examine `CallExpr` nodes in the AST. The `printfNameAndKind` function determines if a called function is a known `printf`-like function or a discovered wrapper. Then, it calls `checkPrintf` or `checkPrint` based on the kind.

7. **Understanding `checkPrintf`:** This function focuses on calls to formatted print functions. It verifies the format string, checks for constant format strings (and suggests fixes for non-constant ones), and compares the format verbs with the provided arguments for type correctness. The parsing logic (`parsePrintfVerb`) is crucial here.

8. **Understanding `checkPrint`:** This function deals with unformatted print functions. It looks for potential format strings in the first argument and checks for redundant newlines in `Println`-like functions.

9. **Identifying Data Structures:** The `Result`, `Kind`, `printfWrapper`, `printfCaller`, `formatState`, and `printVerb` types are important for understanding how the analysis stores and manipulates information.

10. **Inferring the Go Language Feature:** Based on the analysis of these functions, the primary Go language feature being analyzed is the use of `fmt.Printf`, `fmt.Print`, and similar functions, including user-defined functions that behave like them. The analysis aims to detect potential errors in the format strings and argument types.

11. **Creating Code Examples:**  To illustrate the functionality, I needed examples of correct and incorrect usage that the analyzer would flag. This involved crafting scenarios where format strings and argument types don't match, where `...` is missing in wrapper functions, and where non-constant format strings are used.

12. **Considering Command-Line Arguments:** The `init` function and the `isPrint` variable point to the `-funcs` flag. I needed to explain how this flag allows users to specify additional function names to be treated as `printf`-like.

13. **Identifying Common Mistakes:** I thought about common errors developers make when using `printf`-like functions, such as:
    * Mismatched format specifiers and argument types.
    * Forgetting `...` when forwarding arguments in wrappers.
    * Passing a non-constant string to `Printf` that might contain `%`.
    * Recursive calls within `String()` or `Error()` methods.

14. **Structuring the Answer:**  I organized the information into logical sections (functionality, Go feature, examples, command-line arguments, common mistakes) to make it easier to understand. I used clear headings and bullet points.

15. **Review and Refinement:** I reviewed my answer to ensure accuracy, completeness, and clarity. I made sure the code examples were correct and the explanations were easy to follow. I also ensured I addressed all parts of the original request. For instance, explicitly mentioning that `isPrint` and the `-funcs` flag allows customization is important.

This iterative process of scanning, dissecting, inferring, and illustrating helped me to arrive at the comprehensive answer provided previously. The comments in the code were invaluable in understanding the intent behind various sections.
这段代码是 Go 语言 `printf` analysis pass 的一部分，它的主要功能是**静态分析 Go 代码中 `fmt.Printf` 和 `fmt.Print` 及其类似函数的调用，以检测格式字符串和参数之间的类型匹配问题，以及其他潜在的错误用法。**

以下是更详细的功能列表：

1. **识别 `printf`-like 函数:**
   - 默认情况下，它内置了对 `fmt` 包和 `log` 包中常见的 `Print`、`Printf`、`Println`、`Error`、`Errorf` 等函数的识别。
   - 它允许用户通过命令行参数 `-funcs` 自定义需要检查的 `printf`-like 函数列表。

2. **检查 `Printf`-like 函数的调用:**
   - **格式字符串匹配:**  它会解析格式字符串中的格式动词（例如 `%d`, `%s`, `%v` 等），并检查相应的参数类型是否与格式动词的要求匹配。
   - **参数数量检查:**  它会检查提供的参数数量是否与格式字符串中指定的格式动词数量相符。
   - **索引参数支持:**  它支持使用索引参数（例如 `%[1]d`）的格式字符串，并正确匹配参数。
   - **宽度和精度检查:**  它会解析格式字符串中的宽度和精度修饰符，并确保相关的参数类型正确（例如，宽度和精度通常需要是整数）。
   - **`%w` 错误包装指令检查:**  对于类似 `fmt.Errorf` 的函数，它会检查 `%w` 指令是否用于包装 `error` 类型的值。

3. **检查 `Print`-like 函数的调用:**
   - **潜在的格式字符串检测:**  对于非格式化的打印函数（如 `fmt.Print`, `fmt.Println`），它会尝试在第一个参数中检测是否意外地包含了 `Printf` 风格的格式指令，并发出警告。
   - **冗余换行符检查:**  对于 `Println`-like 函数，它会检查最后一个参数是否以换行符结尾，因为 `Println` 会自动添加换行符。
   - **函数值作为参数的检查:**  它会警告将函数值直接传递给 `Print` 或 `Printf`，因为这通常不是预期的行为，用户可能忘记了调用该函数。
   - **递归 `String()` 或 `Error()` 方法调用检测:**  它可以检测到在类型的 `String()` 或 `Error()` 方法中，如果使用格式化打印输出该类型的实例自身（或其指针），可能导致无限递归调用。

4. **支持自定义 `printf` 包装函数:**
   - 它能识别用户自定义的、行为类似于 `fmt.Print` 或 `fmt.Printf` 的包装函数。
   - 它通过分析函数签名（特别是是否接受 `...interface{}` 类型的变参）和函数体内的调用来推断包装函数的行为。
   - 这允许对项目中自定义的日志或输出函数进行 `printf` 风格的检查。

5. **提供代码修复建议:**
   - 对于一些常见的错误，例如在调用 `fmt.Printf` 时使用非常量字符串作为格式字符串，它会提供插入 `"%s"` 格式化动词的修复建议。
   - 对于将参数转发给 `printf`-like 函数时缺少 `...` 的情况，它会提示添加 `...`。

**它是什么 go 语言功能的实现:**

这段代码实现了一个 **静态代码分析器 (static analyzer)**，利用 `go/ast` (抽象语法树) 和 `go/types` (类型信息) 包来理解 Go 代码的结构和类型，并执行特定的检查规则。它属于 Go 语言工具链中的一部分，用于在编译前发现潜在的代码问题，提高代码质量。

**Go 代码举例说明:**

```go
package main

import "fmt"

func main() {
	name := "World"
	age := 30

	// 正确的用法
	fmt.Printf("Hello, %s! You are %d years old.\n", name, age)
	fmt.Print("This is a simple message.\n")

	// 错误的用法 - 类型不匹配
	// go vet 会报告：Printf format %d has arg name of wrong type string
	fmt.Printf("Your age is %d.\n", name)

	// 错误的用法 - 参数数量不匹配
	// go vet 会报告：Printf call needs 2 but has 1 arg(s)
	fmt.Printf("Name: %s, Age: %d\n", name)

	// 错误的用法 - Printf 调用使用了非常量格式字符串
	message := "Welcome, %s!"
	// go vet 会报告：non-constant format string in call to fmt.Printf
	fmt.Printf(message, name)

	// 自定义的 printf 包装函数
	logInfo("User logged in: %s", "Alice")
}

// 自定义的 printf 包装函数
func logInfo(format string, args ...interface{}) {
	fmt.Printf("[INFO] " + format + "\n", args...)
}
```

**假设的输入与输出:**

假设我们有上面的 `main.go` 文件，使用 `go vet` 运行 `printf` 分析器：

**输入 (命令行):**

```bash
go vet main.go
```

**输出 (go vet 的报告):**

```
# command-line-arguments
./main.go:13:2: Printf format %d has arg name of wrong type string
./main.go:17:2: Printf call needs 2 but has 1 arg
./main.go:21:2: non-constant format string in call to fmt.Printf
```

**命令行参数的具体处理:**

```go
func init() {
	Analyzer.Flags.Var(isPrint, "funcs", "comma-separated list of print function names to check")
}
```

- `Analyzer.Flags` 是 `go/analysis` 框架提供的用于定义分析器命令行标志的机制。
- `Var(isPrint, "funcs", ...)` 定义了一个名为 `funcs` 的命令行标志。
- `isPrint` 是一个 `stringSet` 类型的变量，用于存储需要检查的 `printf`-like 函数的名称。
- "comma-separated list of print function names to check" 是该标志的描述。

**使用方式:**

用户可以使用 `-funcs` 标志来扩展 `printf` 分析器要检查的函数列表。例如：

```bash
go vet -printf.funcs="Debug,LogError" main.go
```

这个命令会指示 `printf` 分析器除了默认的 `fmt` 和 `log` 包的函数外，还要检查名为 `Debug` 和 `LogError` 的函数是否被当作 `printf`-like 函数使用。

**使用者易犯错的点:**

1. **在 `Printf` 调用中使用非常量字符串作为格式字符串:** 这会导致静态分析器无法有效检查格式字符串和参数的匹配。`go vet` 会发出警告，并建议使用 `fmt.Printf("%s", message)` 的形式。

   ```go
   message := "Hello, %s!"
   name := "Bob"
   fmt.Printf(message, name) // 容易出错，如果 message 的内容改变，格式可能会出现问题
   ```

2. **自定义 `printf` 包装函数时忘记转发 `...`:**  如果自定义了一个接受变参的 `printf` 包装函数，但在调用底层的 `fmt.Printf` 时忘记使用 `...` 展开参数，会导致参数传递错误。

   ```go
   func myLog(format string, args ...interface{}) {
       fmt.Printf("[MY_LOG] " + format + "\n", args) // 错误：缺少 ...
   }

   func main() {
       myLog("User %s logged in", "Charlie")
   }
   ```
   `go vet` 会报告类似 "missing ... in args forwarded to printf-like function" 的错误。

3. **在 `Println`-like 函数的最后一个参数中添加冗余的换行符:**  `Println` 系列函数会自动添加换行符，手动添加会导致输出中出现两个换行符。

   ```go
   fmt.Println("This message has a newline.\n") // 冗余的 \n
   ```
   `go vet` 会报告 "Println arg list ends with redundant newline"。

4. **混淆 `Print` 和 `Printf` 的使用:** 有时开发者可能想使用格式化输出，但错误地使用了 `fmt.Print`，导致格式指令被当作普通字符串输出。

   ```go
   name := "David"
   fmt.Print("Hello, %s!\n", name) // 错误使用 Print，%s 不会被解释
   ```
   `go vet` 会报告 "Print call has possible Printf formatting directive %s"。

这段代码实现的 `printf` 分析器是 Go 语言代码质量保证的重要组成部分，它可以帮助开发者在早期发现与格式化输出相关的错误，避免在运行时出现意外的输出或程序崩溃。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/tools/go/analysis/passes/printf/printf.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package printf

import (
	"bytes"
	_ "embed"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/analysis/passes/internal/analysisutil"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/types/typeutil"
	"golang.org/x/tools/internal/typeparams"
)

func init() {
	Analyzer.Flags.Var(isPrint, "funcs", "comma-separated list of print function names to check")
}

//go:embed doc.go
var doc string

var Analyzer = &analysis.Analyzer{
	Name:       "printf",
	Doc:        analysisutil.MustExtractDoc(doc, "printf"),
	URL:        "https://pkg.go.dev/golang.org/x/tools/go/analysis/passes/printf",
	Requires:   []*analysis.Analyzer{inspect.Analyzer},
	Run:        run,
	ResultType: reflect.TypeOf((*Result)(nil)),
	FactTypes:  []analysis.Fact{new(isWrapper)},
}

// Kind is a kind of fmt function behavior.
type Kind int

const (
	KindNone   Kind = iota // not a fmt wrapper function
	KindPrint              // function behaves like fmt.Print
	KindPrintf             // function behaves like fmt.Printf
	KindErrorf             // function behaves like fmt.Errorf
)

func (kind Kind) String() string {
	switch kind {
	case KindPrint:
		return "print"
	case KindPrintf:
		return "printf"
	case KindErrorf:
		return "errorf"
	}
	return ""
}

// Result is the printf analyzer's result type. Clients may query the result
// to learn whether a function behaves like fmt.Print or fmt.Printf.
type Result struct {
	funcs map[*types.Func]Kind
}

// Kind reports whether fn behaves like fmt.Print or fmt.Printf.
func (r *Result) Kind(fn *types.Func) Kind {
	_, ok := isPrint[fn.FullName()]
	if !ok {
		// Next look up just "printf", for use with -printf.funcs.
		_, ok = isPrint[strings.ToLower(fn.Name())]
	}
	if ok {
		if strings.HasSuffix(fn.Name(), "f") {
			return KindPrintf
		} else {
			return KindPrint
		}
	}

	return r.funcs[fn]
}

// isWrapper is a fact indicating that a function is a print or printf wrapper.
type isWrapper struct{ Kind Kind }

func (f *isWrapper) AFact() {}

func (f *isWrapper) String() string {
	switch f.Kind {
	case KindPrintf:
		return "printfWrapper"
	case KindPrint:
		return "printWrapper"
	case KindErrorf:
		return "errorfWrapper"
	default:
		return "unknownWrapper"
	}
}

func run(pass *analysis.Pass) (interface{}, error) {
	res := &Result{
		funcs: make(map[*types.Func]Kind),
	}
	findPrintfLike(pass, res)
	checkCall(pass)
	return res, nil
}

type printfWrapper struct {
	obj     *types.Func
	fdecl   *ast.FuncDecl
	format  *types.Var
	args    *types.Var
	callers []printfCaller
	failed  bool // if true, not a printf wrapper
}

type printfCaller struct {
	w    *printfWrapper
	call *ast.CallExpr
}

// maybePrintfWrapper decides whether decl (a declared function) may be a wrapper
// around a fmt.Printf or fmt.Print function. If so it returns a printfWrapper
// function describing the declaration. Later processing will analyze the
// graph of potential printf wrappers to pick out the ones that are true wrappers.
// A function may be a Printf or Print wrapper if its last argument is ...interface{}.
// If the next-to-last argument is a string, then this may be a Printf wrapper.
// Otherwise it may be a Print wrapper.
func maybePrintfWrapper(info *types.Info, decl ast.Decl) *printfWrapper {
	// Look for functions with final argument type ...interface{}.
	fdecl, ok := decl.(*ast.FuncDecl)
	if !ok || fdecl.Body == nil {
		return nil
	}
	fn, ok := info.Defs[fdecl.Name].(*types.Func)
	// Type information may be incomplete.
	if !ok {
		return nil
	}

	sig := fn.Type().(*types.Signature)
	if !sig.Variadic() {
		return nil // not variadic
	}

	params := sig.Params()
	nparams := params.Len() // variadic => nonzero

	// Check final parameter is "args ...interface{}".
	args := params.At(nparams - 1)
	iface, ok := types.Unalias(args.Type().(*types.Slice).Elem()).(*types.Interface)
	if !ok || !iface.Empty() {
		return nil
	}

	// Is second last param 'format string'?
	var format *types.Var
	if nparams >= 2 {
		if p := params.At(nparams - 2); p.Type() == types.Typ[types.String] {
			format = p
		}
	}

	return &printfWrapper{
		obj:    fn,
		fdecl:  fdecl,
		format: format,
		args:   args,
	}
}

// findPrintfLike scans the entire package to find printf-like functions.
func findPrintfLike(pass *analysis.Pass, res *Result) (interface{}, error) {
	// Gather potential wrappers and call graph between them.
	byObj := make(map[*types.Func]*printfWrapper)
	var wrappers []*printfWrapper
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			w := maybePrintfWrapper(pass.TypesInfo, decl)
			if w == nil {
				continue
			}
			byObj[w.obj] = w
			wrappers = append(wrappers, w)
		}
	}

	// Walk the graph to figure out which are really printf wrappers.
	for _, w := range wrappers {
		// Scan function for calls that could be to other printf-like functions.
		ast.Inspect(w.fdecl.Body, func(n ast.Node) bool {
			if w.failed {
				return false
			}

			// TODO: Relax these checks; issue 26555.
			if assign, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range assign.Lhs {
					if match(pass.TypesInfo, lhs, w.format) ||
						match(pass.TypesInfo, lhs, w.args) {
						// Modifies the format
						// string or args in
						// some way, so not a
						// simple wrapper.
						w.failed = true
						return false
					}
				}
			}
			if un, ok := n.(*ast.UnaryExpr); ok && un.Op == token.AND {
				if match(pass.TypesInfo, un.X, w.format) ||
					match(pass.TypesInfo, un.X, w.args) {
					// Taking the address of the
					// format string or args,
					// so not a simple wrapper.
					w.failed = true
					return false
				}
			}

			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 || !match(pass.TypesInfo, call.Args[len(call.Args)-1], w.args) {
				return true
			}

			fn, kind := printfNameAndKind(pass, call)
			if kind != 0 {
				checkPrintfFwd(pass, w, call, kind, res)
				return true
			}

			// If the call is to another function in this package,
			// maybe we will find out it is printf-like later.
			// Remember this call for later checking.
			if fn != nil && fn.Pkg() == pass.Pkg && byObj[fn] != nil {
				callee := byObj[fn]
				callee.callers = append(callee.callers, printfCaller{w, call})
			}

			return true
		})
	}
	return nil, nil
}

func match(info *types.Info, arg ast.Expr, param *types.Var) bool {
	id, ok := arg.(*ast.Ident)
	return ok && info.ObjectOf(id) == param
}

// checkPrintfFwd checks that a printf-forwarding wrapper is forwarding correctly.
// It diagnoses writing fmt.Printf(format, args) instead of fmt.Printf(format, args...).
func checkPrintfFwd(pass *analysis.Pass, w *printfWrapper, call *ast.CallExpr, kind Kind, res *Result) {
	matched := kind == KindPrint ||
		kind != KindNone && len(call.Args) >= 2 && match(pass.TypesInfo, call.Args[len(call.Args)-2], w.format)
	if !matched {
		return
	}

	if !call.Ellipsis.IsValid() {
		typ, ok := pass.TypesInfo.Types[call.Fun].Type.(*types.Signature)
		if !ok {
			return
		}
		if len(call.Args) > typ.Params().Len() {
			// If we're passing more arguments than what the
			// print/printf function can take, adding an ellipsis
			// would break the program. For example:
			//
			//   func foo(arg1 string, arg2 ...interface{}) {
			//       fmt.Printf("%s %v", arg1, arg2)
			//   }
			return
		}
		desc := "printf"
		if kind == KindPrint {
			desc = "print"
		}
		pass.ReportRangef(call, "missing ... in args forwarded to %s-like function", desc)
		return
	}
	fn := w.obj
	var fact isWrapper
	if !pass.ImportObjectFact(fn, &fact) {
		fact.Kind = kind
		pass.ExportObjectFact(fn, &fact)
		res.funcs[fn] = kind
		for _, caller := range w.callers {
			checkPrintfFwd(pass, caller.w, caller.call, kind, res)
		}
	}
}

// isPrint records the print functions.
// If a key ends in 'f' then it is assumed to be a formatted print.
//
// Keys are either values returned by (*types.Func).FullName,
// or case-insensitive identifiers such as "errorf".
//
// The -funcs flag adds to this set.
//
// The set below includes facts for many important standard library
// functions, even though the analysis is capable of deducing that, for
// example, fmt.Printf forwards to fmt.Fprintf. We avoid relying on the
// driver applying analyzers to standard packages because "go vet" does
// not do so with gccgo, and nor do some other build systems.
var isPrint = stringSet{
	"fmt.Appendf":  true,
	"fmt.Append":   true,
	"fmt.Appendln": true,
	"fmt.Errorf":   true,
	"fmt.Fprint":   true,
	"fmt.Fprintf":  true,
	"fmt.Fprintln": true,
	"fmt.Print":    true,
	"fmt.Printf":   true,
	"fmt.Println":  true,
	"fmt.Sprint":   true,
	"fmt.Sprintf":  true,
	"fmt.Sprintln": true,

	"runtime/trace.Logf": true,

	"log.Print":             true,
	"log.Printf":            true,
	"log.Println":           true,
	"log.Fatal":             true,
	"log.Fatalf":            true,
	"log.Fatalln":           true,
	"log.Panic":             true,
	"log.Panicf":            true,
	"log.Panicln":           true,
	"(*log.Logger).Fatal":   true,
	"(*log.Logger).Fatalf":  true,
	"(*log.Logger).Fatalln": true,
	"(*log.Logger).Panic":   true,
	"(*log.Logger).Panicf":  true,
	"(*log.Logger).Panicln": true,
	"(*log.Logger).Print":   true,
	"(*log.Logger).Printf":  true,
	"(*log.Logger).Println": true,

	"(*testing.common).Error":  true,
	"(*testing.common).Errorf": true,
	"(*testing.common).Fatal":  true,
	"(*testing.common).Fatalf": true,
	"(*testing.common).Log":    true,
	"(*testing.common).Logf":   true,
	"(*testing.common).Skip":   true,
	"(*testing.common).Skipf":  true,
	// *testing.T and B are detected by induction, but testing.TB is
	// an interface and the inference can't follow dynamic calls.
	"(testing.TB).Error":  true,
	"(testing.TB).Errorf": true,
	"(testing.TB).Fatal":  true,
	"(testing.TB).Fatalf": true,
	"(testing.TB).Log":    true,
	"(testing.TB).Logf":   true,
	"(testing.TB).Skip":   true,
	"(testing.TB).Skipf":  true,
}

// formatStringIndex returns the index of the format string (the last
// non-variadic parameter) within the given printf-like call
// expression, or -1 if unknown.
func formatStringIndex(pass *analysis.Pass, call *ast.CallExpr) int {
	typ := pass.TypesInfo.Types[call.Fun].Type
	if typ == nil {
		return -1 // missing type
	}
	sig, ok := typ.(*types.Signature)
	if !ok {
		return -1 // ill-typed
	}
	if !sig.Variadic() {
		// Skip checking non-variadic functions.
		return -1
	}
	idx := sig.Params().Len() - 2
	if idx < 0 {
		// Skip checking variadic functions without
		// fixed arguments.
		return -1
	}
	return idx
}

// stringConstantExpr returns expression's string constant value.
//
// ("", false) is returned if expression isn't a string
// constant.
func stringConstantExpr(pass *analysis.Pass, expr ast.Expr) (string, bool) {
	lit := pass.TypesInfo.Types[expr].Value
	if lit != nil && lit.Kind() == constant.String {
		return constant.StringVal(lit), true
	}
	return "", false
}

// checkCall triggers the print-specific checks if the call invokes a print function.
func checkCall(pass *analysis.Pass) {
	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{
		(*ast.CallExpr)(nil),
	}
	inspect.Preorder(nodeFilter, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		fn, kind := printfNameAndKind(pass, call)
		switch kind {
		case KindPrintf, KindErrorf:
			checkPrintf(pass, kind, call, fn)
		case KindPrint:
			checkPrint(pass, call, fn)
		}
	})
}

func printfNameAndKind(pass *analysis.Pass, call *ast.CallExpr) (fn *types.Func, kind Kind) {
	fn, _ = typeutil.Callee(pass.TypesInfo, call).(*types.Func)
	if fn == nil {
		return nil, 0
	}

	// Facts are associated with generic declarations, not instantiations.
	fn = fn.Origin()

	_, ok := isPrint[fn.FullName()]
	if !ok {
		// Next look up just "printf", for use with -printf.funcs.
		_, ok = isPrint[strings.ToLower(fn.Name())]
	}
	if ok {
		if fn.FullName() == "fmt.Errorf" {
			kind = KindErrorf
		} else if strings.HasSuffix(fn.Name(), "f") {
			kind = KindPrintf
		} else {
			kind = KindPrint
		}
		return fn, kind
	}

	var fact isWrapper
	if pass.ImportObjectFact(fn, &fact) {
		return fn, fact.Kind
	}

	return fn, KindNone
}

// isFormatter reports whether t could satisfy fmt.Formatter.
// The only interface method to look for is "Format(State, rune)".
func isFormatter(typ types.Type) bool {
	// If the type is an interface, the value it holds might satisfy fmt.Formatter.
	if _, ok := typ.Underlying().(*types.Interface); ok {
		// Don't assume type parameters could be formatters. With the greater
		// expressiveness of constraint interface syntax we expect more type safety
		// when using type parameters.
		if !typeparams.IsTypeParam(typ) {
			return true
		}
	}
	obj, _, _ := types.LookupFieldOrMethod(typ, false, nil, "Format")
	fn, ok := obj.(*types.Func)
	if !ok {
		return false
	}
	sig := fn.Type().(*types.Signature)
	return sig.Params().Len() == 2 &&
		sig.Results().Len() == 0 &&
		analysisutil.IsNamedType(sig.Params().At(0).Type(), "fmt", "State") &&
		types.Identical(sig.Params().At(1).Type(), types.Typ[types.Rune])
}

// formatState holds the parsed representation of a printf directive such as "%3.*[4]d".
// It is constructed by parsePrintfVerb.
type formatState struct {
	verb     rune   // the format verb: 'd' for "%d"
	format   string // the full format directive from % through verb, "%.3d".
	name     string // Printf, Sprintf etc.
	flags    []byte // the list of # + etc.
	argNums  []int  // the successive argument numbers that are consumed, adjusted to refer to actual arg in call
	firstArg int    // Index of first argument after the format in the Printf call.
	// Used only during parse.
	pass         *analysis.Pass
	call         *ast.CallExpr
	argNum       int  // Which argument we're expecting to format now.
	hasIndex     bool // Whether the argument is indexed.
	indexPending bool // Whether we have an indexed argument that has not resolved.
	nbytes       int  // number of bytes of the format string consumed.
}

// checkPrintf checks a call to a formatted print routine such as Printf.
func checkPrintf(pass *analysis.Pass, kind Kind, call *ast.CallExpr, fn *types.Func) {
	idx := formatStringIndex(pass, call)
	if idx < 0 || idx >= len(call.Args) {
		return
	}
	formatArg := call.Args[idx]
	format, ok := stringConstantExpr(pass, formatArg)
	if !ok {
		// Format string argument is non-constant.

		// It is a common mistake to call fmt.Printf(msg) with a
		// non-constant format string and no arguments:
		// if msg contains "%", misformatting occurs.
		// Report the problem and suggest a fix: fmt.Printf("%s", msg).
		if !suppressNonconstants && idx == len(call.Args)-1 {
			pass.Report(analysis.Diagnostic{
				Pos: formatArg.Pos(),
				End: formatArg.End(),
				Message: fmt.Sprintf("non-constant format string in call to %s",
					fn.FullName()),
				SuggestedFixes: []analysis.SuggestedFix{{
					Message: `Insert "%s" format string`,
					TextEdits: []analysis.TextEdit{{
						Pos:     formatArg.Pos(),
						End:     formatArg.Pos(),
						NewText: []byte(`"%s", `),
					}},
				}},
			})
		}
		return
	}

	firstArg := idx + 1 // Arguments are immediately after format string.
	if !strings.Contains(format, "%") {
		if len(call.Args) > firstArg {
			pass.Reportf(call.Lparen, "%s call has arguments but no formatting directives", fn.FullName())
		}
		return
	}
	// Hard part: check formats against args.
	argNum := firstArg
	maxArgNum := firstArg
	anyIndex := false
	for i, w := 0, 0; i < len(format); i += w {
		w = 1
		if format[i] != '%' {
			continue
		}
		state := parsePrintfVerb(pass, call, fn.FullName(), format[i:], firstArg, argNum)
		if state == nil {
			return
		}
		w = len(state.format)
		if !okPrintfArg(pass, call, state) { // One error per format is enough.
			return
		}
		if state.hasIndex {
			anyIndex = true
		}
		if state.verb == 'w' {
			switch kind {
			case KindNone, KindPrint, KindPrintf:
				pass.Reportf(call.Pos(), "%s does not support error-wrapping directive %%w", state.name)
				return
			}
		}
		if len(state.argNums) > 0 {
			// Continue with the next sequential argument.
			argNum = state.argNums[len(state.argNums)-1] + 1
		}
		for _, n := range state.argNums {
			if n >= maxArgNum {
				maxArgNum = n + 1
			}
		}
	}
	// Dotdotdot is hard.
	if call.Ellipsis.IsValid() && maxArgNum >= len(call.Args)-1 {
		return
	}
	// If any formats are indexed, extra arguments are ignored.
	if anyIndex {
		return
	}
	// There should be no leftover arguments.
	if maxArgNum != len(call.Args) {
		expect := maxArgNum - firstArg
		numArgs := len(call.Args) - firstArg
		pass.ReportRangef(call, "%s call needs %v but has %v", fn.FullName(), count(expect, "arg"), count(numArgs, "arg"))
	}
}

// parseFlags accepts any printf flags.
func (s *formatState) parseFlags() {
	for s.nbytes < len(s.format) {
		switch c := s.format[s.nbytes]; c {
		case '#', '0', '+', '-', ' ':
			s.flags = append(s.flags, c)
			s.nbytes++
		default:
			return
		}
	}
}

// scanNum advances through a decimal number if present.
func (s *formatState) scanNum() {
	for ; s.nbytes < len(s.format); s.nbytes++ {
		c := s.format[s.nbytes]
		if c < '0' || '9' < c {
			return
		}
	}
}

// parseIndex scans an index expression. It returns false if there is a syntax error.
func (s *formatState) parseIndex() bool {
	if s.nbytes == len(s.format) || s.format[s.nbytes] != '[' {
		return true
	}
	// Argument index present.
	s.nbytes++ // skip '['
	start := s.nbytes
	s.scanNum()
	ok := true
	if s.nbytes == len(s.format) || s.nbytes == start || s.format[s.nbytes] != ']' {
		ok = false // syntax error is either missing "]" or invalid index.
		s.nbytes = strings.Index(s.format[start:], "]")
		if s.nbytes < 0 {
			s.pass.ReportRangef(s.call, "%s format %s is missing closing ]", s.name, s.format)
			return false
		}
		s.nbytes = s.nbytes + start
	}
	arg32, err := strconv.ParseInt(s.format[start:s.nbytes], 10, 32)
	if err != nil || !ok || arg32 <= 0 || arg32 > int64(len(s.call.Args)-s.firstArg) {
		s.pass.ReportRangef(s.call, "%s format has invalid argument index [%s]", s.name, s.format[start:s.nbytes])
		return false
	}
	s.nbytes++ // skip ']'
	arg := int(arg32)
	arg += s.firstArg - 1 // We want to zero-index the actual arguments.
	s.argNum = arg
	s.hasIndex = true
	s.indexPending = true
	return true
}

// parseNum scans a width or precision (or *). It returns false if there's a bad index expression.
func (s *formatState) parseNum() bool {
	if s.nbytes < len(s.format) && s.format[s.nbytes] == '*' {
		if s.indexPending { // Absorb it.
			s.indexPending = false
		}
		s.nbytes++
		s.argNums = append(s.argNums, s.argNum)
		s.argNum++
	} else {
		s.scanNum()
	}
	return true
}

// parsePrecision scans for a precision. It returns false if there's a bad index expression.
func (s *formatState) parsePrecision() bool {
	// If there's a period, there may be a precision.
	if s.nbytes < len(s.format) && s.format[s.nbytes] == '.' {
		s.flags = append(s.flags, '.') // Treat precision as a flag.
		s.nbytes++
		if !s.parseIndex() {
			return false
		}
		if !s.parseNum() {
			return false
		}
	}
	return true
}

// parsePrintfVerb looks the formatting directive that begins the format string
// and returns a formatState that encodes what the directive wants, without looking
// at the actual arguments present in the call. The result is nil if there is an error.
func parsePrintfVerb(pass *analysis.Pass, call *ast.CallExpr, name, format string, firstArg, argNum int) *formatState {
	state := &formatState{
		format:   format,
		name:     name,
		flags:    make([]byte, 0, 5),
		argNum:   argNum,
		argNums:  make([]int, 0, 1),
		nbytes:   1, // There's guaranteed to be a percent sign.
		firstArg: firstArg,
		pass:     pass,
		call:     call,
	}
	// There may be flags.
	state.parseFlags()
	// There may be an index.
	if !state.parseIndex() {
		return nil
	}
	// There may be a width.
	if !state.parseNum() {
		return nil
	}
	// There may be a precision.
	if !state.parsePrecision() {
		return nil
	}
	// Now a verb, possibly prefixed by an index (which we may already have).
	if !state.indexPending && !state.parseIndex() {
		return nil
	}
	if state.nbytes == len(state.format) {
		pass.ReportRangef(call.Fun, "%s format %s is missing verb at end of string", name, state.format)
		return nil
	}
	verb, w := utf8.DecodeRuneInString(state.format[state.nbytes:])
	state.verb = verb
	state.nbytes += w
	if verb != '%' {
		state.argNums = append(state.argNums, state.argNum)
	}
	state.format = state.format[:state.nbytes]
	return state
}

// printfArgType encodes the types of expressions a printf verb accepts. It is a bitmask.
type printfArgType int

const (
	argBool printfArgType = 1 << iota
	argInt
	argRune
	argString
	argFloat
	argComplex
	argPointer
	argError
	anyType printfArgType = ^0
)

type printVerb struct {
	verb  rune   // User may provide verb through Formatter; could be a rune.
	flags string // known flags are all ASCII
	typ   printfArgType
}

// Common flag sets for printf verbs.
const (
	noFlag       = ""
	numFlag      = " -+.0"
	sharpNumFlag = " -+.0#"
	allFlags     = " -+.0#"
)

// printVerbs identifies which flags are known to printf for each verb.
var printVerbs = []printVerb{
	// '-' is a width modifier, always valid.
	// '.' is a precision for float, max width for strings.
	// '+' is required sign for numbers, Go format for %v.
	// '#' is alternate format for several verbs.
	// ' ' is spacer for numbers
	{'%', noFlag, 0},
	{'b', sharpNumFlag, argInt | argFloat | argComplex | argPointer},
	{'c', "-", argRune | argInt},
	{'d', numFlag, argInt | argPointer},
	{'e', sharpNumFlag, argFloat | argComplex},
	{'E', sharpNumFlag, argFloat | argComplex},
	{'f', sharpNumFlag, argFloat | argComplex},
	{'F', sharpNumFlag, argFloat | argComplex},
	{'g', sharpNumFlag, argFloat | argComplex},
	{'G', sharpNumFlag, argFloat | argComplex},
	{'o', sharpNumFlag, argInt | argPointer},
	{'O', sharpNumFlag, argInt | argPointer},
	{'p', "-#", argPointer},
	{'q', " -+.0#", argRune | argInt | argString},
	{'s', " -+.0", argString},
	{'t', "-", argBool},
	{'T', "-", anyType},
	{'U', "-#", argRune | argInt},
	{'v', allFlags, anyType},
	{'w', allFlags, argError},
	{'x', sharpNumFlag, argRune | argInt | argString | argPointer | argFloat | argComplex},
	{'X', sharpNumFlag, argRune | argInt | argString | argPointer | argFloat | argComplex},
}

// okPrintfArg compares the formatState to the arguments actually present,
// reporting any discrepancies it can discern. If the final argument is ellipsissed,
// there's little it can do for that.
func okPrintfArg(pass *analysis.Pass, call *ast.CallExpr, state *formatState) (ok bool) {
	var v printVerb
	found := false
	// Linear scan is fast enough for a small list.
	for _, v = range printVerbs {
		if v.verb == state.verb {
			found = true
			break
		}
	}

	// Could current arg implement fmt.Formatter?
	// Skip check for the %w verb, which requires an error.
	formatter := false
	if v.typ != argError && state.argNum < len(call.Args) {
		if tv, ok := pass.TypesInfo.Types[call.Args[state.argNum]]; ok {
			formatter = isFormatter(tv.Type)
		}
	}

	if !formatter {
		if !found {
			pass.ReportRangef(call, "%s format %s has unknown verb %c", state.name, state.format, state.verb)
			return false
		}
		for _, flag := range state.flags {
			// TODO: Disable complaint about '0' for Go 1.10. To be fixed properly in 1.11.
			// See issues 23598 and 23605.
			if flag == '0' {
				continue
			}
			if !strings.ContainsRune(v.flags, rune(flag)) {
				pass.ReportRangef(call, "%s format %s has unrecognized flag %c", state.name, state.format, flag)
				return false
			}
		}
	}
	// Verb is good. If len(state.argNums)>trueArgs, we have something like %.*s and all
	// but the final arg must be an integer.
	trueArgs := 1
	if state.verb == '%' {
		trueArgs = 0
	}
	nargs := len(state.argNums)
	for i := 0; i < nargs-trueArgs; i++ {
		argNum := state.argNums[i]
		if !argCanBeChecked(pass, call, i, state) {
			return
		}
		arg := call.Args[argNum]
		if reason, ok := matchArgType(pass, argInt, arg); !ok {
			details := ""
			if reason != "" {
				details = " (" + reason + ")"
			}
			pass.ReportRangef(call, "%s format %s uses non-int %s%s as argument of *", state.name, state.format, analysisutil.Format(pass.Fset, arg), details)
			return false
		}
	}

	if state.verb == '%' || formatter {
		return true
	}
	argNum := state.argNums[len(state.argNums)-1]
	if !argCanBeChecked(pass, call, len(state.argNums)-1, state) {
		return false
	}
	arg := call.Args[argNum]
	if isFunctionValue(pass, arg) && state.verb != 'p' && state.verb != 'T' {
		pass.ReportRangef(call, "%s format %s arg %s is a func value, not called", state.name, state.format, analysisutil.Format(pass.Fset, arg))
		return false
	}
	if reason, ok := matchArgType(pass, v.typ, arg); !ok {
		typeString := ""
		if typ := pass.TypesInfo.Types[arg].Type; typ != nil {
			typeString = typ.String()
		}
		details := ""
		if reason != "" {
			details = " (" + reason + ")"
		}
		pass.ReportRangef(call, "%s format %s has arg %s of wrong type %s%s", state.name, state.format, analysisutil.Format(pass.Fset, arg), typeString, details)
		return false
	}
	if v.typ&argString != 0 && v.verb != 'T' && !bytes.Contains(state.flags, []byte{'#'}) {
		if methodName, ok := recursiveStringer(pass, arg); ok {
			pass.ReportRangef(call, "%s format %s with arg %s causes recursive %s method call", state.name, state.format, analysisutil.Format(pass.Fset, arg), methodName)
			return false
		}
	}
	return true
}

// recursiveStringer reports whether the argument e is a potential
// recursive call to stringer or is an error, such as t and &t in these examples:
//
//	func (t *T) String() string { printf("%s",  t) }
//	func (t  T) Error() string { printf("%s",  t) }
//	func (t  T) String() string { printf("%s", &t) }
func recursiveStringer(pass *analysis.Pass, e ast.Expr) (string, bool) {
	typ := pass.TypesInfo.Types[e].Type

	// It's unlikely to be a recursive stringer if it has a Format method.
	if isFormatter(typ) {
		return "", false
	}

	// Does e allow e.String() or e.Error()?
	strObj, _, _ := types.LookupFieldOrMethod(typ, false, pass.Pkg, "String")
	strMethod, strOk := strObj.(*types.Func)
	errObj, _, _ := types.LookupFieldOrMethod(typ, false, pass.Pkg, "Error")
	errMethod, errOk := errObj.(*types.Func)
	if !strOk && !errOk {
		return "", false
	}

	// inScope returns true if e is in the scope of f.
	inScope := func(e ast.Expr, f *types.Func) bool {
		return f.Scope() != nil && f.Scope().Contains(e.Pos())
	}

	// Is the expression e within the body of that String or Error method?
	var method *types.Func
	if strOk && strMethod.Pkg() == pass.Pkg && inScope(e, strMethod) {
		method = strMethod
	} else if errOk && errMethod.Pkg() == pass.Pkg && inScope(e, errMethod) {
		method = errMethod
	} else {
		return "", false
	}

	sig := method.Type().(*types.Signature)
	if !isStringer(sig) {
		return "", false
	}

	// Is it the receiver r, or &r?
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = u.X // strip off & from &r
	}
	if id, ok := e.(*ast.Ident); ok {
		if pass.TypesInfo.Uses[id] == sig.Recv() {
			return method.FullName(), true
		}
	}
	return "", false
}

// isStringer reports whether the method signature matches the String() definition in fmt.Stringer.
func isStringer(sig *types.Signature) bool {
	return sig.Params().Len() == 0 &&
		sig.Results().Len() == 1 &&
		sig.Results().At(0).Type() == types.Typ[types.String]
}

// isFunctionValue reports whether the expression is a function as opposed to a function call.
// It is almost always a mistake to print a function value.
func isFunctionValue(pass *analysis.Pass, e ast.Expr) bool {
	if typ := pass.TypesInfo.Types[e].Type; typ != nil {
		// Don't call Underlying: a named func type with a String method is ok.
		// TODO(adonovan): it would be more precise to check isStringer.
		_, ok := typ.(*types.Signature)
		return ok
	}
	return false
}

// argCanBeChecked reports whether the specified argument is statically present;
// it may be beyond the list of arguments or in a terminal slice... argument, which
// means we can't see it.
func argCanBeChecked(pass *analysis.Pass, call *ast.CallExpr, formatArg int, state *formatState) bool {
	argNum := state.argNums[formatArg]
	if argNum <= 0 {
		// Shouldn't happen, so catch it with prejudice.
		panic("negative arg num")
	}
	if argNum < len(call.Args)-1 {
		return true // Always OK.
	}
	if call.Ellipsis.IsValid() {
		return false // We just can't tell; there could be many more arguments.
	}
	if argNum < len(call.Args) {
		return true
	}
	// There are bad indexes in the format or there are fewer arguments than the format needs.
	// This is the argument number relative to the format: Printf("%s", "hi") will give 1 for the "hi".
	arg := argNum - state.firstArg + 1 // People think of arguments as 1-indexed.
	pass.ReportRangef(call, "%s format %s reads arg #%d, but call has %v", state.name, state.format, arg, count(len(call.Args)-state.firstArg, "arg"))
	return false
}

// printFormatRE is the regexp we match and report as a possible format string
// in the first argument to unformatted prints like fmt.Print.
// We exclude the space flag, so that printing a string like "x % y" is not reported as a format.
var printFormatRE = regexp.MustCompile(`%` + flagsRE + numOptRE + `\.?` + numOptRE + indexOptRE + verbRE)

const (
	flagsRE    = `[+\-#]*`
	indexOptRE = `(\[[0-9]+\])?`
	numOptRE   = `([0-9]+|` + indexOptRE + `\*)?`
	verbRE     = `[bcdefgopqstvxEFGTUX]`
)

// checkPrint checks a call to an unformatted print routine such as Println.
func checkPrint(pass *analysis.Pass, call *ast.CallExpr, fn *types.Func) {
	firstArg := 0
	typ := pass.TypesInfo.Types[call.Fun].Type
	if typ == nil {
		// Skip checking functions with unknown type.
		return
	}
	if sig, ok := typ.Underlying().(*types.Signature); ok {
		if !sig.Variadic() {
			// Skip checking non-variadic functions.
			return
		}
		params := sig.Params()
		firstArg = params.Len() - 1

		typ := params.At(firstArg).Type()
		typ = typ.(*types.Slice).Elem()
		it, ok := types.Unalias(typ).(*types.Interface)
		if !ok || !it.Empty() {
			// Skip variadic functions accepting non-interface{} args.
			return
		}
	}
	args := call.Args
	if len(args) <= firstArg {
		// Skip calls without variadic args.
		return
	}
	args = args[firstArg:]

	if firstArg == 0 {
		if sel, ok := call.Args[0].(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok {
				if x.Name == "os" && strings.HasPrefix(sel.Sel.Name, "Std") {
					pass.ReportRangef(call, "%s does not take io.Writer but has first arg %s", fn.FullName(), analysisutil.Format(pass.Fset, call.Args[0]))
				}
			}
		}
	}

	arg := args[0]
	if s, ok := stringConstantExpr(pass, arg); ok {
		// Ignore trailing % character
		// The % in "abc 0.0%" couldn't be a formatting directive.
		s = strings.TrimSuffix(s, "%")
		if strings.Contains(s, "%") {
			m := printFormatRE.FindStringSubmatch(s)
			if m != nil {
				pass.ReportRangef(call, "%s call has possible Printf formatting directive %s", fn.FullName(), m[0])
			}
		}
	}
	if strings.HasSuffix(fn.Name(), "ln") {
		// The last item, if a string, should not have a newline.
		arg = args[len(args)-1]
		if s, ok := stringConstantExpr(pass, arg); ok {
			if strings.HasSuffix(s, "\n") {
				pass.ReportRangef(call, "%s arg list ends with redundant newline", fn.FullName())
			}
		}
	}
	for _, arg := range args {
		if isFunctionValue(pass, arg) {
			pass.ReportRangef(call, "%s arg %s is a func value, not called", fn.FullName(), analysisutil.Format(pass.Fset, arg))
		}
		if methodName, ok := recursiveStringer(pass, arg); ok {
			pass.ReportRangef(call, "%s arg %s causes recursive call to %s method", fn.FullName(), analysisutil.Format(pass.Fset, arg), methodName)
		}
	}
}

// count(n, what) returns "1 what" or "N whats"
// (assuming the plural of what is whats).
func count(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// stringSet is a set-of-nonempty-strings-valued flag.
// Note: elements without a '.' get lower-cased.
type stringSet map[string]bool

func (ss stringSet) String() string {
	var list []string
	for name := range ss {
		list = append(list, name)
	}
	sort.Strings(list)
	return strings.Join(list, ",")
}

func (ss stringSet) Set(flag string) error {
	for _, name := range strings.Split(flag, ",") {
		if len(name) == 0 {
			return fmt.Errorf("empty string")
		}
		if !strings.Contains(name, ".") {
			name = strings.ToLower(name)
		}
		ss[name] = true
	}
	return nil
}

// suppressNonconstants suppresses reporting printf calls with
// non-constant formatting strings (proposal #60529) when true.
//
// This variable is to allow for staging the transition to newer
// versions of x/tools by vendoring.
//
// Remove this after the 1.24 release.
var suppressNonconstants bool

"""



```