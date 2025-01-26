Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding of the Goal:**

The request asks for an explanation of the provided Go code. Key aspects to cover include: functionality, underlying Go features, code examples, command-line parameters, and common mistakes. The file path `go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/kisielk/errcheck/internal/errcheck/errcheck.go` strongly suggests this is part of a static analysis tool focused on error handling. The package name "errcheck" reinforces this.

**2. Core Functionality Identification (Skimming and Keywords):**

I start by skimming the code for keywords and structural elements:

* **`package errcheck`**: Confirms the package's purpose.
* **`import` statements**:  Indicate dependencies and areas of focus (e.g., `go/ast`, `go/types`, `regexp`, `os`). The `go/ast` and `go/types` packages are strong indicators of static analysis.
* **`UncheckedError` struct**:  Represents a detected issue. This is a crucial data structure.
* **`CheckPackages` function**: Likely the main entry point for analyzing code.
* **`Checker` struct**:  Holds configuration options.
* **`visitor` struct and `Visit` method**:  Suggests an AST traversal pattern.
* **`ignore`, `Blank`, `Asserts` fields in `Checker`**: These are clearly configuration options, likely influencing which errors are reported.
* **Function names like `ignoreCall`, `callReturnsError`, `addErrorAtPosition`**: Describe the core logic.

**3. Deeper Dive into Key Components:**

Now, I look at the critical parts in more detail:

* **`UncheckedError` and `UncheckedErrors`**:  The structure reveals how errors are represented and collected. The `Append` method with a mutex indicates thread-safe error aggregation. The sorting methods hint at post-processing of the found errors.
* **`Checker`**:  The fields suggest the customizable nature of the tool. The `Ignore` map and `exclude` map stand out as ways to suppress certain error reports. The `Tags`, `WithoutTests`, and `WithoutGeneratedCode` fields clearly relate to filtering the scope of analysis.
* **`CheckPackages`**: The logic involves loading packages using `golang.org/x/tools/go/packages`, traversing the AST of each file, and using a `visitor` to find unchecked errors. The use of `sync.WaitGroup` suggests parallel processing of packages.
* **`visitor` and `Visit`**:  The `Visit` method handles different AST node types (`ExprStmt`, `GoStmt`, `DeferStmt`, `AssignStmt`). The logic within each case checks if a function call returns an error and if that error is handled. The handling of blank identifiers (`_`) and type assertions is explicit.
* **`ignoreCall` and `excludeCall`**:  These functions implement the logic for suppressing error reports based on configuration. The use of regular expressions in `ignoreCall` is significant.
* **`callReturnsError` and `errorsByArg`**: Determine if a function call returns an error type.

**4. Inferring Go Features and Providing Examples:**

Based on the analysis, I can infer the Go features being used:

* **AST Traversal (`go/ast`)**: The `visitor` pattern is a classic example.
* **Type Information (`go/types`)**:  Used to determine if a function returns an error. The `types.Implements` function is explicitly used.
* **Reflection (Implicit)**: While not using the `reflect` package directly, the ability to inspect types and function signatures is a form of reflection.
* **Concurrency (`sync`)**: The `sync.Mutex` and `sync.WaitGroup` are used for thread safety and parallel processing.
* **Regular Expressions (`regexp`)**: Used for ignoring specific function calls.

To illustrate these, I create simple Go code snippets:

* **Error Handling Example**:  Demonstrates a function returning an error and how `errcheck` would flag its unhandled use.
* **Ignoring Errors Example**: Shows how the `Ignore` configuration works with regular expressions.
* **Blank Identifier Example**: Illustrates the `--blank` flag's effect.
* **Type Assertion Example**: Demonstrates the `--asserts` flag's behavior.

**5. Command-Line Parameter Inference:**

By examining the `Checker` struct's fields (`Ignore`, `Blank`, `Asserts`, `Tags`, `Verbose`, `WithoutTests`, `WithoutGeneratedCode`), I can deduce the likely command-line parameters. I formulate how these parameters would influence the tool's behavior.

**6. Identifying Common Mistakes:**

Knowing the purpose of `errcheck`, the most common mistake is simply ignoring returned errors. I provide a concrete example of this.

**7. Structuring the Answer:**

Finally, I organize the information logically, using clear headings and bullet points. I start with a high-level summary of the functionality and then delve into the details, providing code examples and explanations for each aspect. I ensure the language is clear and concise, explaining technical terms where necessary. The use of code blocks and formatting enhances readability.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps the tool directly parses the source code.
* **Correction:**  The import of `golang.org/x/tools/go/packages` suggests it leverages the Go toolchain's package loading and parsing capabilities, which is more efficient and accurate.
* **Initial thought:** Focus heavily on individual functions.
* **Refinement:**  Shift focus to the overall workflow: loading packages, traversing the AST, and checking for errors, highlighting the roles of `Checker` and `visitor`.
* **Consideration:** How to explain the exclusion mechanisms clearly?
* **Solution:** Differentiate between the `Ignore` map (regex-based) and the `exclude` map (exact string matching), providing examples for both.

This iterative process of understanding, analyzing, inferring, and refining leads to a comprehensive and accurate explanation of the provided Go code.
这段Go语言代码是 `errcheck` 工具的核心部分，其主要功能是 **静态分析Go代码，用于检测未被检查的错误返回值**。

以下是更详细的分解：

**1. 核心功能：检测未检查的错误返回值**

`errcheck` 的主要目标是帮助开发者避免忽略可能发生的错误。在Go语言中，函数通常会返回一个或多个值，其中最后一个返回值常常是 `error` 类型。如果调用这些返回错误值的函数后没有显式地检查错误（例如，通过 `if err != nil`），`errcheck` 就会报告一个警告。

**2. 关键数据结构和类型**

* **`UncheckedError`**:  表示一个未被检查的错误。它包含错误发生的位置 (`Pos`)、包含错误调用的代码行 (`Line`) 和函数名 (`FuncName`)。
* **`UncheckedErrors`**:  一个 `UncheckedError` 的切片，用于存储在整个包或项目中发现的所有未检查的错误。它使用了 `sync.Mutex` 来保证并发安全地添加错误。
* **`Checker`**:  核心结构体，包含了 `errcheck` 的配置选项：
    * **`Ignore map[string]*regexp.Regexp`**:  允许用户指定哪些包或函数可以忽略错误检查。键是包的路径，值是一个正则表达式，用于匹配需要忽略的函数名。
    * **`Blank bool`**:  如果为 `true`，则将赋值给空白标识符 `_` 的错误返回值也视为未检查的错误。
    * **`Asserts bool`**: 如果为 `true`，则会检查未被使用的类型断言的错误结果。
    * **`Tags []string`**:  构建标签，用于指定在解析代码时需要考虑的构建约束。
    * **`Verbose bool`**:  启用详细输出。
    * **`WithoutTests bool`**:  如果为 `true`，则跳过对 `_test.go` 文件的检查。
    * **`WithoutGeneratedCode bool`**: 如果为 `true`，则跳过对包含 `// Code generated` 注释的文件的检查。
    * **`exclude map[string]bool`**:  一个用于排除特定函数调用的集合，这些函数调用通常被认为是安全的，即使它们返回错误。

* **`visitor`**:  实现了 `ast.Visitor` 接口，用于遍历Go代码的抽象语法树 (AST)。它的 `Visit` 方法定义了在遍历过程中如何检查错误返回值。

**3. 实现原理（代码推理）**

`errcheck` 的工作流程大致如下：

1. **加载包**: 使用 `golang.org/x/tools/go/packages` 加载指定的Go包及其依赖。
2. **遍历AST**:  对每个包中的Go源文件构建抽象语法树 (AST)，并使用 `visitor` 结构体遍历该 AST。
3. **检查函数调用**:  `visitor` 的 `Visit` 方法会检查各种类型的语句，特别是函数调用 (`*ast.CallExpr`)。
4. **判断是否返回错误**:  通过 `v.callReturnsError(call)` 函数判断被调用的函数是否返回错误类型的值。这通常通过检查函数签名的返回值类型是否实现了 `error` 接口来实现。
5. **判断错误是否被检查**:  `visitor` 会检查错误返回值是否被显式地处理，例如赋值给一个非空白标识符的变量，或者在 `if` 语句中进行判断。
6. **记录未检查的错误**: 如果一个返回错误的函数调用没有被检查，`visitor` 会创建一个 `UncheckedError` 实例并添加到 `v.errors` 中。
7. **报告错误**: `CheckPackages` 函数在遍历完成后，会将所有收集到的 `UncheckedError` 报告给用户。

**4. Go语言功能的应用**

* **`go/ast`**: 用于解析Go源代码并构建抽象语法树 (AST)。`errcheck` 使用 AST 来分析代码的结构，特别是函数调用和赋值语句。
* **`go/types`**:  用于获取Go程序的类型信息，例如函数的返回值类型。`errcheck` 使用它来确定一个函数是否返回错误类型的值。
* **接口 (`interface`)**: `errcheck` 利用 `error` 接口来判断一个类型是否代表一个错误。`types.Implements(t, errorType)`  用于检查类型 `t` 是否实现了 `error` 接口。
* **反射 (隐式)**: 虽然代码中没有直接使用 `reflect` 包，但 `go/types` 提供的类型信息实际上是 Go 语言反射能力的一种体现。
* **正则表达式 (`regexp`)**:  用于实现 `Ignore` 功能，允许用户灵活地指定需要忽略的函数或包。
* **并发 (`sync`)**: `UncheckedErrors` 结构体使用 `sync.Mutex` 来保证在并发场景下添加错误信息的线程安全。 `CheckPackages` 中使用了 `sync.WaitGroup` 来并发地检查多个包。

**5. 代码示例**

```go
package main

import (
	"fmt"
	"os"
)

func mightFail() error {
	return fmt.Errorf("something went wrong")
}

func main() {
	err := mightFail() // 错误返回值未被检查，errcheck会报告
	fmt.Println("程序继续执行")

	f, _ := os.Open("nonexistent_file.txt") // os.Open 返回 error，但被赋值给 _，如果 Checker.Blank 为 true，errcheck 会报告
	defer f.Close()

	res, ok := interface{}(1).(string) // 类型断言，如果 Checker.Asserts 为 true，且 ok 未被使用，errcheck会报告
	fmt.Println(res, ok)

	if err := mightFail(); err != nil { // 错误返回值被检查，errcheck不会报告
		fmt.Println("处理错误:", err)
	}
}
```

**假设的输入与输出：**

如果运行 `errcheck` 分析上面的代码，并且 `Checker` 的默认配置，输出可能如下：

```
./main.go:10:6: Error return value from `main.mightFail` is not checked
./main.go:13:6: Error return value from `os.Open` is not checked
```

如果 `Checker.Blank` 被设置为 `true`，输出可能会增加：

```
./main.go:10:6: Error return value from `main.mightFail` is not checked
./main.go:13:6: Error return value from `os.Open` is assigned to blank identifier
```

如果 `Checker.Asserts` 被设置为 `true`，输出可能会增加：

```
./main.go:10:6: Error return value from `main.mightFail` is not checked
./main.go:13:6: Error return value from `os.Open` is not checked
./main.go:16:6: Result of type assertion is not checked
```

**6. 命令行参数的具体处理**

虽然这段代码本身没有直接处理命令行参数，但根据 `Checker` 结构体的字段可以推断出 `errcheck` 工具可能接受的命令行参数：

* **`-ignore`**:  对应 `Checker.Ignore`。可以多次使用，指定要忽略的包和匹配的函数名的正则表达式。例如：`-ignore "fmt:^F.*"` 会忽略 `fmt` 包下所有以 `F` 开头的函数。
* **`-blank`**:  对应 `Checker.Blank`。一个布尔标志，用于启用对赋值给空白标识符的错误返回值的检查。
* **`-asserts`**: 对应 `Checker.Asserts`。一个布尔标志，用于启用对未检查的类型断言结果的检查。
* **`-tags`**: 对应 `Checker.Tags`。用于指定构建标签，多个标签可以用逗号分隔。
* **`-v` 或 `-verbose`**: 对应 `Checker.Verbose`。启用详细输出。
* **`-withouttests`**: 对应 `Checker.WithoutTests`。跳过对测试文件的检查。
* **`-withoutgenerated`**: 对应 `Checker.WithoutGeneratedCode`。跳过对生成代码的检查。
* **要检查的路径**:  命令行参数通常还会接受一个或多个Go包的路径，用于指定要分析的代码。

**7. 使用者易犯错的点**

* **过度使用 `-ignore`**:  为了快速消除 `errcheck` 的警告，一些开发者可能会过度使用 `-ignore` 参数，从而忽略了本应检查的错误。应该谨慎使用，并确保理解忽略特定错误的影响。
* **不理解 `-blank` 和 `-asserts` 的作用**:  开发者可能不清楚这两个参数的作用，导致某些潜在的错误被忽略。
* **忽略 `errcheck` 的输出**:  开发者可能运行了 `errcheck` 但没有仔细查看输出的警告信息，导致错误被遗漏。
* **与构建标签混淆**:  如果没有正确设置 `-tags` 参数，`errcheck` 可能无法分析所有相关的代码分支。

总而言之，这段代码是 `errcheck` 工具的核心逻辑，它利用 Go 语言的 AST 和类型信息来静态分析代码，帮助开发者发现并修复未被检查的错误返回值，从而提高代码的健壮性。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/kisielk/errcheck/internal/errcheck/errcheck.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Package errcheck is the library used to implement the errcheck command-line tool.
//
// Note: The API of this package has not been finalized and may change at any point.
package errcheck

import (
	"bufio"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
)

var errorType *types.Interface

func init() {
	errorType = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)

}

var (
	// ErrNoGoFiles is returned when CheckPackage is run on a package with no Go source files
	ErrNoGoFiles = errors.New("package contains no go source files")
)

// UncheckedError indicates the position of an unchecked error return.
type UncheckedError struct {
	Pos      token.Position
	Line     string
	FuncName string
}

// UncheckedErrors is returned from the CheckPackage function if the package contains
// any unchecked errors.
// Errors should be appended using the Append method, which is safe to use concurrently.
type UncheckedErrors struct {
	mu sync.Mutex

	// Errors is a list of all the unchecked errors in the package.
	// Printing an error reports its position within the file and the contents of the line.
	Errors []UncheckedError
}

func (e *UncheckedErrors) Append(errors ...UncheckedError) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Errors = append(e.Errors, errors...)
}

func (e *UncheckedErrors) Error() string {
	return fmt.Sprintf("%d unchecked errors", len(e.Errors))
}

// Len is the number of elements in the collection.
func (e *UncheckedErrors) Len() int { return len(e.Errors) }

// Swap swaps the elements with indexes i and j.
func (e *UncheckedErrors) Swap(i, j int) { e.Errors[i], e.Errors[j] = e.Errors[j], e.Errors[i] }

type byName struct{ *UncheckedErrors }

// Less reports whether the element with index i should sort before the element with index j.
func (e byName) Less(i, j int) bool {
	ei, ej := e.Errors[i], e.Errors[j]

	pi, pj := ei.Pos, ej.Pos

	if pi.Filename != pj.Filename {
		return pi.Filename < pj.Filename
	}
	if pi.Line != pj.Line {
		return pi.Line < pj.Line
	}
	if pi.Column != pj.Column {
		return pi.Column < pj.Column
	}

	return ei.Line < ej.Line
}

type Checker struct {
	// ignore is a map of package names to regular expressions. Identifiers from a package are
	// checked against its regular expressions and if any of the expressions match the call
	// is not checked.
	Ignore map[string]*regexp.Regexp

	// If blank is true then assignments to the blank identifier are also considered to be
	// ignored errors.
	Blank bool

	// If asserts is true then ignored type assertion results are also checked
	Asserts bool

	// build tags
	Tags []string

	Verbose bool

	// If true, checking of _test.go files is disabled
	WithoutTests bool

	// If true, checking of files with generated code is disabled
	WithoutGeneratedCode bool

	exclude map[string]bool
}

func NewChecker() *Checker {
	c := Checker{}
	c.SetExclude(map[string]bool{})
	return &c
}

func (c *Checker) SetExclude(l map[string]bool) {
	c.exclude = map[string]bool{}

	// Default exclude for stdlib functions
	for _, exc := range []string{
		// bytes
		"(*bytes.Buffer).Write",
		"(*bytes.Buffer).WriteByte",
		"(*bytes.Buffer).WriteRune",
		"(*bytes.Buffer).WriteString",

		// fmt
		"fmt.Errorf",
		"fmt.Print",
		"fmt.Printf",
		"fmt.Println",
		"fmt.Fprint(*bytes.Buffer)",
		"fmt.Fprintf(*bytes.Buffer)",
		"fmt.Fprintln(*bytes.Buffer)",
		"fmt.Fprint(*strings.Builder)",
		"fmt.Fprintf(*strings.Builder)",
		"fmt.Fprintln(*strings.Builder)",
		"fmt.Fprint(os.Stderr)",
		"fmt.Fprintf(os.Stderr)",
		"fmt.Fprintln(os.Stderr)",

		// math/rand
		"math/rand.Read",
		"(*math/rand.Rand).Read",

		// strings
		"(*strings.Builder).Write",
		"(*strings.Builder).WriteByte",
		"(*strings.Builder).WriteRune",
		"(*strings.Builder).WriteString",

		// hash
		"(hash.Hash).Write",
	} {
		c.exclude[exc] = true
	}

	for k := range l {
		c.exclude[k] = true
	}
}

func (c *Checker) logf(msg string, args ...interface{}) {
	if c.Verbose {
		fmt.Fprintf(os.Stderr, msg+"\n", args...)
	}
}

// loadPackages is used for testing.
var loadPackages = func(cfg *packages.Config, paths ...string) ([]*packages.Package, error) {
	return packages.Load(cfg, paths...)
}

func (c *Checker) load(paths ...string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode:       packages.LoadAllSyntax,
		Tests:      !c.WithoutTests,
		BuildFlags: []string{fmt.Sprintf("-tags=%s", strings.Join(c.Tags, " "))},
	}
	return loadPackages(cfg, paths...)
}

var generatedCodeRegexp = regexp.MustCompile("^// Code generated .* DO NOT EDIT\\.$")

func (c *Checker) shouldSkipFile(file *ast.File) bool {
	if !c.WithoutGeneratedCode {
		return false
	}

	for _, cg := range file.Comments {
		for _, comment := range cg.List {
			if generatedCodeRegexp.MatchString(comment.Text) {
				return true
			}
		}
	}

	return false
}

// CheckPackages checks packages for errors.
func (c *Checker) CheckPackages(paths ...string) error {
	pkgs, err := c.load(paths...)
	if err != nil {
		return err
	}
	// Check for errors in the initial packages.
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			return fmt.Errorf("errors while loading package %s: %v", pkg.ID, pkg.Errors)
		}
	}

	var wg sync.WaitGroup
	u := &UncheckedErrors{}
	for _, pkg := range pkgs {
		wg.Add(1)

		go func(pkg *packages.Package) {
			defer wg.Done()
			c.logf("Checking %s", pkg.Types.Path())

			v := &visitor{
				pkg:     pkg,
				ignore:  c.Ignore,
				blank:   c.Blank,
				asserts: c.Asserts,
				lines:   make(map[string][]string),
				exclude: c.exclude,
				errors:  []UncheckedError{},
			}

			for _, astFile := range v.pkg.Syntax {
				if c.shouldSkipFile(astFile) {
					continue
				}
				ast.Walk(v, astFile)
			}
			u.Append(v.errors...)
		}(pkg)
	}

	wg.Wait()
	if u.Len() > 0 {
		// Sort unchecked errors and remove duplicates. Duplicates may occur when a file
		// containing an unchecked error belongs to > 1 package.
		sort.Sort(byName{u})
		uniq := u.Errors[:0] // compact in-place
		for i, err := range u.Errors {
			if i == 0 || err != u.Errors[i-1] {
				uniq = append(uniq, err)
			}
		}
		u.Errors = uniq
		return u
	}
	return nil
}

// visitor implements the errcheck algorithm
type visitor struct {
	pkg     *packages.Package
	ignore  map[string]*regexp.Regexp
	blank   bool
	asserts bool
	lines   map[string][]string
	exclude map[string]bool

	errors []UncheckedError
}

// selectorAndFunc tries to get the selector and function from call expression.
// For example, given the call expression representing "a.b()", the selector
// is "a.b" and the function is "b" itself.
//
// The final return value will be true if it is able to do extract a selector
// from the call and look up the function object it refers to.
//
// If the call does not include a selector (like if it is a plain "f()" function call)
// then the final return value will be false.
func (v *visitor) selectorAndFunc(call *ast.CallExpr) (*ast.SelectorExpr, *types.Func, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, nil, false
	}

	fn, ok := v.pkg.TypesInfo.ObjectOf(sel.Sel).(*types.Func)
	if !ok {
		// Shouldn't happen, but be paranoid
		return nil, nil, false
	}

	return sel, fn, true

}

// fullName will return a package / receiver-type qualified name for a called function
// if the function is the result of a selector. Otherwise it will return
// the empty string.
//
// The name is fully qualified by the import path, possible type,
// function/method name and pointer receiver.
//
// For example,
//   - for "fmt.Printf(...)" it will return "fmt.Printf"
//   - for "base64.StdEncoding.Decode(...)" it will return "(*encoding/base64.Encoding).Decode"
//   - for "myFunc()" it will return ""
func (v *visitor) fullName(call *ast.CallExpr) string {
	_, fn, ok := v.selectorAndFunc(call)
	if !ok {
		return ""
	}

	// TODO(dh): vendored packages will have /vendor/ in their name,
	// thus not matching vendored standard library packages. If we
	// want to support vendored stdlib packages, we need to implement
	// FullName with our own logic.
	return fn.FullName()
}

// namesForExcludeCheck will return a list of fully-qualified function names
// from a function call that can be used to check against the exclusion list.
//
// If a function call is against a local function (like "myFunc()") then no
// names are returned. If the function is package-qualified (like "fmt.Printf()")
// then just that function's fullName is returned.
//
// Otherwise, we walk through all the potentially embeddded interfaces of the receiver
// the collect a list of type-qualified function names that we will check.
func (v *visitor) namesForExcludeCheck(call *ast.CallExpr) []string {
	sel, fn, ok := v.selectorAndFunc(call)
	if !ok {
		return nil
	}

	name := v.fullName(call)
	if name == "" {
		return nil
	}

	// This will be missing for functions without a receiver (like fmt.Printf),
	// so just fall back to the the function's fullName in that case.
	selection, ok := v.pkg.TypesInfo.Selections[sel]
	if !ok {
		return []string{name}
	}

	// This will return with ok false if the function isn't defined
	// on an interface, so just fall back to the fullName.
	ts, ok := walkThroughEmbeddedInterfaces(selection)
	if !ok {
		return []string{name}
	}

	result := make([]string, len(ts))
	for i, t := range ts {
		// Like in fullName, vendored packages will have /vendor/ in their name,
		// thus not matching vendored standard library packages. If we
		// want to support vendored stdlib packages, we need to implement
		// additional logic here.
		result[i] = fmt.Sprintf("(%s).%s", t.String(), fn.Name())
	}
	return result
}

// isBufferType checks if the expression type is a known in-memory buffer type.
func (v *visitor) argName(expr ast.Expr) string {
	// Special-case literal "os.Stdout" and "os.Stderr"
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		if obj := v.pkg.TypesInfo.ObjectOf(sel.Sel); obj != nil {
			vr, ok := obj.(*types.Var)
			if ok && vr.Pkg() != nil && vr.Pkg().Name() == "os" && (vr.Name() == "Stderr" || vr.Name() == "Stdout") {
				return "os." + vr.Name()
			}
		}
	}
	t := v.pkg.TypesInfo.TypeOf(expr)
	if t == nil {
		return ""
	}
	return t.String()
}

func (v *visitor) excludeCall(call *ast.CallExpr) bool {
	var arg0 string
	if len(call.Args) > 0 {
		arg0 = v.argName(call.Args[0])
	}
	for _, name := range v.namesForExcludeCheck(call) {
		if v.exclude[name] {
			return true
		}
		if arg0 != "" && v.exclude[name+"("+arg0+")"] {
			return true
		}
	}
	return false
}

func (v *visitor) ignoreCall(call *ast.CallExpr) bool {
	if v.excludeCall(call) {
		return true
	}

	// Try to get an identifier.
	// Currently only supports simple expressions:
	//     1. f()
	//     2. x.y.f()
	var id *ast.Ident
	switch exp := call.Fun.(type) {
	case (*ast.Ident):
		id = exp
	case (*ast.SelectorExpr):
		id = exp.Sel
	default:
		// eg: *ast.SliceExpr, *ast.IndexExpr
	}

	if id == nil {
		return false
	}

	// If we got an identifier for the function, see if it is ignored
	if re, ok := v.ignore[""]; ok && re.MatchString(id.Name) {
		return true
	}

	if obj := v.pkg.TypesInfo.Uses[id]; obj != nil {
		if pkg := obj.Pkg(); pkg != nil {
			if re, ok := v.ignore[pkg.Path()]; ok {
				return re.MatchString(id.Name)
			}

			// if current package being considered is vendored, check to see if it should be ignored based
			// on the unvendored path.
			if nonVendoredPkg, ok := nonVendoredPkgPath(pkg.Path()); ok {
				if re, ok := v.ignore[nonVendoredPkg]; ok {
					return re.MatchString(id.Name)
				}
			}
		}
	}

	return false
}

// nonVendoredPkgPath returns the unvendored version of the provided package path (or returns the provided path if it
// does not represent a vendored path). The second return value is true if the provided package was vendored, false
// otherwise.
func nonVendoredPkgPath(pkgPath string) (string, bool) {
	lastVendorIndex := strings.LastIndex(pkgPath, "/vendor/")
	if lastVendorIndex == -1 {
		return pkgPath, false
	}
	return pkgPath[lastVendorIndex+len("/vendor/"):], true
}

// errorsByArg returns a slice s such that
// len(s) == number of return types of call
// s[i] == true iff return type at position i from left is an error type
func (v *visitor) errorsByArg(call *ast.CallExpr) []bool {
	switch t := v.pkg.TypesInfo.Types[call].Type.(type) {
	case *types.Named:
		// Single return
		return []bool{isErrorType(t)}
	case *types.Pointer:
		// Single return via pointer
		return []bool{isErrorType(t)}
	case *types.Tuple:
		// Multiple returns
		s := make([]bool, t.Len())
		for i := 0; i < t.Len(); i++ {
			switch et := t.At(i).Type().(type) {
			case *types.Named:
				// Single return
				s[i] = isErrorType(et)
			case *types.Pointer:
				// Single return via pointer
				s[i] = isErrorType(et)
			default:
				s[i] = false
			}
		}
		return s
	}
	return []bool{false}
}

func (v *visitor) callReturnsError(call *ast.CallExpr) bool {
	if v.isRecover(call) {
		return true
	}
	for _, isError := range v.errorsByArg(call) {
		if isError {
			return true
		}
	}
	return false
}

// isRecover returns true if the given CallExpr is a call to the built-in recover() function.
func (v *visitor) isRecover(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.Ident); ok {
		if _, ok := v.pkg.TypesInfo.Uses[fun].(*types.Builtin); ok {
			return fun.Name == "recover"
		}
	}
	return false
}

func (v *visitor) addErrorAtPosition(position token.Pos, call *ast.CallExpr) {
	pos := v.pkg.Fset.Position(position)
	lines, ok := v.lines[pos.Filename]
	if !ok {
		lines = readfile(pos.Filename)
		v.lines[pos.Filename] = lines
	}

	line := "??"
	if pos.Line-1 < len(lines) {
		line = strings.TrimSpace(lines[pos.Line-1])
	}

	var name string
	if call != nil {
		name = v.fullName(call)
	}

	v.errors = append(v.errors, UncheckedError{pos, line, name})
}

func readfile(filename string) []string {
	var f, err = os.Open(filename)
	if err != nil {
		return nil
	}

	var lines []string
	var scanner = bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func (v *visitor) Visit(node ast.Node) ast.Visitor {
	switch stmt := node.(type) {
	case *ast.ExprStmt:
		if call, ok := stmt.X.(*ast.CallExpr); ok {
			if !v.ignoreCall(call) && v.callReturnsError(call) {
				v.addErrorAtPosition(call.Lparen, call)
			}
		}
	case *ast.GoStmt:
		if !v.ignoreCall(stmt.Call) && v.callReturnsError(stmt.Call) {
			v.addErrorAtPosition(stmt.Call.Lparen, stmt.Call)
		}
	case *ast.DeferStmt:
		if !v.ignoreCall(stmt.Call) && v.callReturnsError(stmt.Call) {
			v.addErrorAtPosition(stmt.Call.Lparen, stmt.Call)
		}
	case *ast.AssignStmt:
		if len(stmt.Rhs) == 1 {
			// single value on rhs; check against lhs identifiers
			if call, ok := stmt.Rhs[0].(*ast.CallExpr); ok {
				if !v.blank {
					break
				}
				if v.ignoreCall(call) {
					break
				}
				isError := v.errorsByArg(call)
				for i := 0; i < len(stmt.Lhs); i++ {
					if id, ok := stmt.Lhs[i].(*ast.Ident); ok {
						// We shortcut calls to recover() because errorsByArg can't
						// check its return types for errors since it returns interface{}.
						if id.Name == "_" && (v.isRecover(call) || isError[i]) {
							v.addErrorAtPosition(id.NamePos, call)
						}
					}
				}
			} else if assert, ok := stmt.Rhs[0].(*ast.TypeAssertExpr); ok {
				if !v.asserts {
					break
				}
				if assert.Type == nil {
					// type switch
					break
				}
				if len(stmt.Lhs) < 2 {
					// assertion result not read
					v.addErrorAtPosition(stmt.Rhs[0].Pos(), nil)
				} else if id, ok := stmt.Lhs[1].(*ast.Ident); ok && v.blank && id.Name == "_" {
					// assertion result ignored
					v.addErrorAtPosition(id.NamePos, nil)
				}
			}
		} else {
			// multiple value on rhs; in this case a call can't return
			// multiple values. Assume len(stmt.Lhs) == len(stmt.Rhs)
			for i := 0; i < len(stmt.Lhs); i++ {
				if id, ok := stmt.Lhs[i].(*ast.Ident); ok {
					if call, ok := stmt.Rhs[i].(*ast.CallExpr); ok {
						if !v.blank {
							continue
						}
						if v.ignoreCall(call) {
							continue
						}
						if id.Name == "_" && v.callReturnsError(call) {
							v.addErrorAtPosition(id.NamePos, call)
						}
					} else if assert, ok := stmt.Rhs[i].(*ast.TypeAssertExpr); ok {
						if !v.asserts {
							continue
						}
						if assert.Type == nil {
							// Shouldn't happen anyway, no multi assignment in type switches
							continue
						}
						v.addErrorAtPosition(id.NamePos, nil)
					}
				}
			}
		}
	default:
	}
	return v
}

func isErrorType(t types.Type) bool {
	return types.Implements(t, errorType)
}

"""



```