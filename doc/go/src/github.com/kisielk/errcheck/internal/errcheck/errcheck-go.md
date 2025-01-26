Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Reading and Understanding the Context:**

* **Package Declaration:** The first thing I see is `package errcheck`. This immediately tells me the code is part of a tool named "errcheck". The comment above reinforces this, stating it's "the library used to implement the errcheck command-line tool."
* **Import Statements:**  I scan the import statements to get a sense of the core functionalities being used. Key imports like `go/ast`, `go/token`, `go/types`, and `golang.org/x/tools/go/packages` strongly suggest this code is involved in static analysis of Go code. Other imports like `fmt`, `os`, `regexp`, `strings`, and `sync` indicate standard utility functions, file system operations, regular expressions, string manipulation, and concurrency control.
* **Key Data Structures:** I look for prominent data structures and type definitions. `UncheckedError` and `UncheckedErrors` stand out. Their names suggest they are used to store and manage information about errors that haven't been handled. The `Checker` struct also looks important as it likely holds the configuration and state of the error checking process.

**2. Identifying Core Functionality - "What does this code *do*?":**

* **Error Checking:** The package name and the `UncheckedError`/`UncheckedErrors` types strongly suggest the core function is related to finding unhandled errors in Go code.
* **Static Analysis:**  The imports from `go/*` packages confirm this. The code is likely traversing the Abstract Syntax Tree (AST) of Go code to identify potential issues.
* **Configuration and Options:** The `Checker` struct has fields like `Ignore`, `Blank`, `Asserts`, `Tags`, `WithoutTests`, and `WithoutGeneratedCode`. This indicates that the error checking behavior can be customized through various options.
* **Ignoring Specific Errors:** The `Ignore` field (a map of regular expressions) suggests a mechanism to suppress warnings for certain function calls.
* **Handling Blank Identifiers:** The `Blank` field implies the tool can be configured to treat assignments to the blank identifier (`_`) as ignored errors.
* **Type Assertions:** The `Asserts` field suggests the tool can check for unhandled results of type assertions.
* **Excluding Functions:** The `exclude` map within the `Checker` suggests a predefined or configurable list of functions whose error returns should be ignored.
* **Concurrency:** The `sync` package and the `UncheckedErrors` struct having a mutex (`mu`) indicate that the error checking process might be parallelized for performance.

**3. Inferring Go Features and Providing Examples:**

* **Error Handling:** The core functionality revolves around identifying functions that return errors but whose return values are not checked. I can provide a simple example of this.
* **Type Assertions:** The `Asserts` field directly points to the Go type assertion feature. I can demonstrate how an unchecked type assertion could be flagged.
* **Blank Identifier:** The `Blank` field relates to the use of the blank identifier to discard return values. An example illustrating this is necessary.

**4. Code Reasoning and Input/Output (More Detailed Analysis):**

* **`CheckPackages` function:** This seems to be the main entry point for initiating the error checking process on a set of packages. I need to think about what it does: loads packages, iterates through them, spawns goroutines (due to `sync.WaitGroup`), and uses a `visitor` to analyze each package's AST. The input would be package paths, and the output would be either `nil` (no errors) or an `UncheckedErrors` object.
* **`visitor` struct and `Visit` method:** The `visitor` seems to be the core logic for traversing the AST and identifying error-handling issues. The `Visit` method is part of the `ast.Visitor` interface. I need to analyze the different cases within the `Visit` method (`*ast.ExprStmt`, `*ast.GoStmt`, `*ast.DeferStmt`, `*ast.AssignStmt`) to understand how it detects unchecked errors in various contexts.
* **`ignoreCall` and `excludeCall` functions:**  These functions are responsible for determining whether a particular function call should be ignored based on configuration. I need to differentiate between the `Ignore` map (regular expressions) and the `exclude` map (exact function names).
* **`errorsByArg` function:** This function figures out which return values of a function call are error types. This is crucial for identifying potentially unchecked errors.

**5. Command-Line Arguments (Looking at the bigger picture):**

While the provided code doesn't explicitly parse command-line arguments, the presence of configurable options in the `Checker` struct strongly suggests that the `errcheck` command-line tool will likely have flags to control these options (e.g., `-ignore`, `-blank`, `-asserts`, `-tags`, etc.). I need to infer how these options might be used from the code itself.

**6. Common Mistakes:**

I need to think about how users might misuse the tool or make assumptions that lead to unexpected behavior. Ignoring errors using the blank identifier and not checking type assertion results are prime examples.

**7. Structuring the Answer:**

Finally, I need to organize my findings logically, starting with a high-level overview of the functionality and then going into more detail, providing examples, and explaining command-line arguments and potential pitfalls. Using clear headings and bullet points will make the answer easier to read and understand.

By following these steps, I can systematically analyze the provided code snippet and provide a comprehensive and accurate explanation of its functionality.
这段代码是 `errcheck` 工具的核心部分，用于静态分析 Go 代码并找出未检查的错误。以下是它的主要功能：

**1. 核心功能：检查未处理的错误**

`errcheck` 的主要目的是检测 Go 代码中函数返回的 `error` 类型的值是否被显式地检查。这意味着它会寻找那些调用了可能返回错误的函数，但返回值没有被赋值给一个变量（除了 `_`，且 `Checker.Blank` 为 `true` 时）或用于条件判断的情况。

**2. 可配置的忽略规则**

`Checker` 结构体提供了多种配置选项，允许用户自定义哪些错误应该被忽略：

* **`Ignore map[string]*regexp.Regexp`:**  允许用户通过正则表达式指定要忽略的包或函数。如果一个被调用函数的包路径和函数名匹配到任何一个正则表达式，则该调用的错误返回值将被忽略。
* **`Blank bool`:** 如果设置为 `true`，则将返回值赋值给空白标识符 `_` 也被认为是忽略了错误。
* **`Asserts bool`:** 如果设置为 `true`，则会检查类型断言的结果是否被使用。
* **`exclude map[string]bool`:**  一个硬编码的或用户提供的函数列表，这些函数的错误返回值将被忽略。默认情况下，标准库中一些不会真正返回有意义错误的函数（如 `fmt.Println`）会被排除。

**3. 支持构建标签（Build Tags）**

`Checker.Tags []string` 允许用户指定构建标签。在加载包时，`errcheck` 会使用这些标签，以便只分析在特定构建条件下编译的代码。

**4. 跳过测试文件和生成代码**

* **`WithoutTests bool`:** 如果设置为 `true`，则会跳过对 `_test.go` 文件的检查。
* **`WithoutGeneratedCode bool`:** 如果设置为 `true`，则会跳过包含 `// Code generated .* DO NOT EDIT.` 注释的文件的检查。

**5. 并发处理**

`CheckPackages` 函数使用 `sync.WaitGroup` 和 goroutine 来并发地检查多个包，以提高效率。

**6. 错误报告**

`UncheckedError` 结构体用于存储未检查错误的位置信息（文件名、行号、列号）和代码行内容。 `UncheckedErrors` 结构体用于收集所有未检查到的错误，并实现了 `error` 接口，方便返回和打印错误信息。

**代码推理示例：检测未检查的错误返回值**

假设有以下 Go 代码：

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	f, _ := os.Open("nonexistent.txt") // 错误返回值被忽略
	fmt.Println(f)
}
```

**假设输入：** `errcheck` 工具被运行在包含上述代码的包上。

**代码推理过程：**

1. `errcheck` 会加载该包的 AST (抽象语法树)。
2. `visitor` 结构体的 `Visit` 方法会被调用，遍历 AST 节点。
3. 当遍历到 `ast.AssignStmt` 节点时，它会检查赋值语句的右侧是否是函数调用 (`*ast.CallExpr`)。
4. 在上面的例子中，`os.Open("nonexistent.txt")` 是一个函数调用。
5. `visitor.callReturnsError(call)` 方法会检查 `os.Open` 函数的返回值类型。由于 `os.Open` 返回 `*os.File, error`，因此该方法返回 `true`。
6. `visitor.ignoreCall(call)` 方法会检查该调用是否应该被忽略（例如，在 `exclude` 列表中）。假设 `os.Open` 不在忽略列表中。
7. 由于赋值语句的左侧使用了空白标识符 `_`，并且 `Checker.Blank` 默认为 `false`，因此 `visitor.addErrorAtPosition` 方法会被调用，记录一个未检查的错误。

**假设输出：** `errcheck` 会输出类似以下的错误信息：

```
./main.go:7:2: Error return value of `os.Open` is not checked
```

**代码推理示例：使用 `Checker.Blank` 忽略错误**

如果我们将 `errcheck` 的 `-blank` 参数设置为 `true`，并运行在相同的代码上：

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	f, _ := os.Open("nonexistent.txt")
	fmt.Println(f)
}
```

**假设输入：** `errcheck -blank` 运行在包含上述代码的包上。

**代码推理过程：**

1. 前面的步骤相同，直到 `visitor.addErrorAtPosition` 的判断。
2. 因为 `Checker.Blank` 为 `true`，并且赋值语句的左侧使用了空白标识符 `_` 来接收错误返回值，所以这个错误被认为是显式忽略的，`visitor.addErrorAtPosition` 不会被调用。

**假设输出：** `errcheck` 不会输出任何错误信息。

**命令行参数处理**

这段代码本身并没有直接处理命令行参数。它是一个库，供 `errcheck` 命令行工具使用。`errcheck` 工具会使用类似 `flag` 包来解析命令行参数，并将解析后的值设置到 `Checker` 结构体的相应字段中。

例如，`errcheck` 工具可能会有以下命令行参数：

* `-ignore`: 接受一个正则表达式列表，用于设置 `Checker.Ignore`。
* `-blank`:  一个布尔标志，用于设置 `Checker.Blank`。
* `-asserts`: 一个布尔标志，用于设置 `Checker.Asserts`。
* `-tags`: 接受一个构建标签列表，用于设置 `Checker.Tags`。
* `-v` 或 `-verbose`:  一个布尔标志，用于设置 `Checker.Verbose`。
* `-withouttests`: 一个布尔标志，用于设置 `Checker.WithoutTests`。
* `-withoutgenerated`: 一个布尔标志，用于设置 `Checker.WithoutGeneratedCode`。
*  后面跟着要检查的 Go 包的路径。

**使用者易犯错的点**

1. **过度使用空白标识符 `_` 而不开启 `-blank` 选项:**  新手可能会习惯性地使用 `_` 来忽略错误，而没有意识到 `errcheck` 默认情况下会将其视为未检查的错误。

   ```go
   // 默认情况下，errcheck 会报错
   _, err := someFunctionThatReturnsError()
   if err != nil {
       // ...
   }
   ```

2. **对需要检查错误的函数进行排除:**  用户可能会不小心将一些确实需要检查错误的函数添加到 `exclude` 列表中或 `Ignore` 规则中，从而导致 `errcheck` 忽略了潜在的错误。

   ```
   // 错误的排除配置可能导致 errcheck 忽略对 os.Remove 的错误检查
   checker := errcheck.NewChecker()
   checker.SetExclude(map[string]bool{"os.Remove": true})
   ```

3. **对包含错误的包使用过于宽泛的忽略规则:**  使用不精确的正则表达式可能会导致 `errcheck` 忽略了本应检查的错误。

   ```
   // 可能错误地忽略了所有以 "file" 开头的函数
   checker := errcheck.NewChecker()
   checker.Ignore = map[string]*regexp.Regexp{"mypackage": regexp.MustCompile(`^file.*`)}
   ```

4. **不理解 `-asserts` 标志的作用:**  用户可能没有意识到 `errcheck` 默认不检查类型断言的结果，从而忽略了可能由于类型断言失败而导致的问题。

   ```go
   // 默认情况下，errcheck 不会报错
   val, _ := someInterface.(string)
   println(val)
   ```

总而言之，这段代码是 `errcheck` 工具的核心引擎，负责分析 Go 代码并报告潜在的未处理的错误。通过其丰富的配置选项，用户可以根据自己的需求定制错误检查的行为。理解其工作原理和配置选项对于有效地使用 `errcheck` 至关重要。

Prompt: 
```
这是路径为go/src/github.com/kisielk/errcheck/internal/errcheck/errcheck.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"os/exec"
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

	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	go111module := (err == nil) && strings.TrimSpace(string(gomod)) != ""
	ignore := c.Ignore
	if go111module {
		ignore = make(map[string]*regexp.Regexp)
		for pkg, re := range c.Ignore {
			if nonVendoredPkg, ok := nonVendoredPkgPath(pkg); ok {
				ignore[nonVendoredPkg] = re
			} else {
				ignore[pkg] = re
			}
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
				pkg:         pkg,
				ignore:      ignore,
				blank:       c.Blank,
				asserts:     c.Asserts,
				lines:       make(map[string][]string),
				exclude:     c.exclude,
				go111module: go111module,
				errors:      []UncheckedError{},
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
	pkg         *packages.Package
	ignore      map[string]*regexp.Regexp
	blank       bool
	asserts     bool
	lines       map[string][]string
	exclude     map[string]bool
	go111module bool

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
			if !v.go111module {
				if nonVendoredPkg, ok := nonVendoredPkgPath(pkg.Path()); ok {
					if re, ok := v.ignore[nonVendoredPkg]; ok {
						return re.MatchString(id.Name)
					}
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