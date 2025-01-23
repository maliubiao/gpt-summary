Response:
My thought process to analyze the Go code and fulfill the request goes like this:

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, targeting a specific file within the `golang.org/x/tools` repository. It also requests a demonstration of the functionality with code examples, command-line argument handling (if any), and common mistakes users might make.

2. **Identify the Core Functionality:**  The package name `tests` and the file name `tests.go` strongly suggest that this code is related to analyzing Go test files. Scanning the code quickly reveals several key function prefixes: `Example`, `Test`, `Benchmark`, and `Fuzz`. This confirms the initial intuition.

3. **Break Down the Code by Function Prefix:** I'll analyze the code based on the different kinds of test functions it handles:

    * **`Example` functions:** The `checkExampleName` and `checkExampleOutput` functions are clearly responsible for validating the structure and comments within example functions.
    * **`Test` and `Benchmark` functions:** The `checkTest` function, called for both `Test` and `Benchmark` prefixes, likely validates the signature (parameters and return values) of these functions.
    * **`Fuzz` functions:**  The `checkFuzz` function and its helper functions (`checkFuzzCall`, `checkAddCalls`, `isFuzzTargetDotFuzz`, `isFuzzTargetDotAdd`, `isFuzzTargetDot`, `validateFuzzArgs`, `isAcceptedFuzzType`, `formatAcceptedFuzzType`) form a significant portion of the code. This indicates a focus on validating fuzz tests.

4. **Analyze Key Functions in Detail:**

    * **`run` function:** This is the entry point for the analysis pass. It iterates through Go files, checks if they are test files (`_test.go`), and then dispatches to the appropriate check function based on the function name prefix.
    * **`checkExampleName`:**  Focuses on the naming conventions of example functions, including checks for parameters, return values, type parameters, and the structure of the example name (e.g., `Example`, `ExampleType`, `ExampleType_Method`, `ExampleType_Method_Suffix`).
    * **`checkExampleOutput`:**  Validates the presence and placement of "Output:" comment blocks within example functions.
    * **`checkTest`:**  Checks the signature of `Test` and `Benchmark` functions, specifically looking for a single parameter of type `*testing.T` or `*testing.B` and the absence of type parameters. It also validates the naming convention after the "Test" or "Benchmark" prefix.
    * **`checkFuzz`:**  The main function for fuzz test analysis. It calls `checkFuzzCall` and `checkAddCalls`.
    * **`checkFuzzCall`:**  Crucially, it verifies the structure of the `f.Fuzz()` call within a fuzz test. It checks the argument to `f.Fuzz()` (which should be a function), the signature of that function (parameters and return values), and restricts the use of `*F` methods within the fuzz target function.
    * **`checkAddCalls`:**  Validates the arguments passed to `f.Add()`, ensuring they match the types expected by the fuzz target function.
    * **Helper functions (e.g., `isFuzzTargetDotFuzz`, `isTestingType`, `isAcceptedFuzzType`):** These functions provide specific checks used by the main validation functions.

5. **Infer the Purpose of the Analysis Pass:** Based on the function names and the checks being performed, it's clear this analysis pass (`golang.org/x/tools/go/analysis/passes/tests`) aims to enforce best practices and correct usage of Go's testing features, including examples, standard tests, benchmarks, and fuzz tests. It identifies common errors that might prevent tests from running correctly or lead to unexpected behavior.

6. **Construct Example Code:** To illustrate the functionality, I'll create examples that violate the rules enforced by the analysis pass. This helps demonstrate the kinds of errors it detects. I'll create examples for each type of test function: `Example`, `Test`, `Benchmark`, and `Fuzz`, showcasing both correct and incorrect usage.

7. **Address Command-Line Arguments:** I'll examine the `Analyzer` variable. It doesn't define any specific command-line flags. The analysis pass is meant to be integrated into a larger analysis framework, which would handle command-line arguments for running the analyses. Therefore, I'll explain that this specific pass doesn't have its own command-line arguments.

8. **Identify Common Mistakes:** Based on the checks performed by the code, I can infer common mistakes users might make:

    * **Incorrect naming of test/example functions.**
    * **Incorrect signatures for test/example functions (parameters, return values, type parameters).**
    * **Incorrect use of "Output:" comments in examples.**
    * **Incorrect use of `f.Fuzz()` and `f.Add()` in fuzz tests.**
    * **Using disallowed `*F` methods within fuzz targets.**
    * **Passing incorrect types to `f.Add()` in fuzz tests.**

9. **Structure the Response:**  I'll organize the answer according to the prompt's requirements: functionality, Go code examples, code inference details, command-line arguments, and common mistakes. I'll use clear headings and formatting to make the information easy to understand.

10. **Review and Refine:**  Finally, I'll review my analysis and the generated examples to ensure accuracy and clarity. I'll make sure the examples effectively demonstrate the functionality of the analysis pass and the common mistakes it helps prevent. For instance, making sure the error messages in the examples align with what the analysis would actually report.
这段代码是 Go 语言 `analysis` 工具链中的一个 `pass`，名为 `tests`。它的主要功能是**静态分析 Go 语言的测试文件 (_test.go)，并检查其中定义的测试、基准测试、示例函数和模糊测试函数是否符合 Go 语言的规范和最佳实践。**

更具体地说，它会检查以下内容：

**1. 测试函数 (Test...)**

* **功能:** 检查以 `Test` 开头的函数是否符合测试函数的规范。
* **检查点:**
    * 函数签名是否为 `func TestXxx(t *testing.T)`。
    * 函数是否包含类型参数 (泛型)。
    * `Test` 后面的部分是否以大写字母开头。
* **Go 代码示例:**

```go
package mypackage

import "testing"

// 正确的测试函数
func TestAddition(t *testing.T) {
	if 1 + 1 != 2 {
		t.Errorf("1 + 1 should be 2")
	}
}

// 错误的测试函数：参数类型错误
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出参数类型应为 *testing.T
// func TestSubtraction(b *testing.B) { // 错误
// 	if 2 - 1 != 1 {
// 		b.Errorf("2 - 1 should be 1")
// 	}
// }

// 错误的测试函数：包含类型参数
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出测试函数不应有类型参数
// func TestGeneric[T any](t *testing.T) { // 错误
// }

// 错误的测试函数：名称不符合规范
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出 "testAddition" 的 "t" 应该是大写
// func Testaddition(t *testing.T) { // 错误
// }
```

**2. 基准测试函数 (Benchmark...)**

* **功能:** 检查以 `Benchmark` 开头的函数是否符合基准测试函数的规范。
* **检查点:**
    * 函数签名是否为 `func BenchmarkXxx(b *testing.B)`。
    * 函数是否包含类型参数 (泛型)。
    * `Benchmark` 后面的部分是否以大写字母开头。
* **Go 代码示例:**

```go
package mypackage

import "testing"

// 正确的基准测试函数
func BenchmarkAdd(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = 1 + 1
	}
}

// 错误的基准测试函数：参数类型错误
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出参数类型应为 *testing.B
// func BenchmarkSubtract(t *testing.T) { // 错误
// 	for i := 0; i < t.N; i++ {
// 		_ = 2 - 1
// 	}
// }

// 错误的基准测试函数：名称不符合规范
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出 "benchmarkAdd" 的 "a" 应该是大写
// func Benchmarkadd(b *testing.B) { // 错误
// 	for i := 0; i < b.N; i++ {
// 		_ = 1 + 1
// 	}
// }
```

**3. 示例函数 (Example...)**

* **功能:** 检查以 `Example` 开头的函数是否符合示例函数的规范，以及是否正确使用了 "Output:" 注释。
* **检查点:**
    * 函数签名是否为 `func ExampleXxx()`。
    * 函数是否返回任何值。
    * 函数是否包含类型参数 (泛型)。
    * "Output:" 注释是否是最后一个注释块。
    * `Example` 后面的部分是否指向已存在的标识符、字段或方法。
* **Go 代码示例:**

```go
package mypackage

import "fmt"

// 正确的示例函数
func ExampleHello() {
	fmt.Println("Hello")
	// Output: Hello
}

// 错误的示例函数：带有参数
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出示例函数应该是 niladic (无参数)
// func ExampleWorld(name string) { // 错误
// 	fmt.Println("Hello, ", name)
// 	// Output: Hello, World
// }

// 错误的示例函数：返回了值
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出示例函数不应该返回任何值
// func ExampleGoodbye() string { // 错误
// 	return "Goodbye"
// }

// 错误的示例函数：Output 注释不在最后
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出 Output 注释块必须是最后一个注释块
// func Example মাঝখানেOutput() {
// 	// Output: 中间
// 	fmt.Println("中间")
// 	fmt.Println("后面")
// }

// 错误的示例函数：指向未知的标识符
// 假设输入：文件包含此函数，且没有定义 UndefinedVar
// 输出：报告一个错误，指出 "ExampleUndefinedVar" 指向未知的标识符
// func ExampleUndefinedVar() { // 错误
// 	fmt.Println(UndefinedVar)
// 	// Output: ...
// }
```

**4. 模糊测试函数 (Fuzz...)**

* **功能:** 检查以 `Fuzz` 开头的函数是否符合模糊测试函数的规范，包括 `f.Fuzz()` 和 `f.Add()` 的使用。
* **检查点:**
    * 函数签名是否为 `func FuzzXxx(f *testing.F)`。
    * `f.Fuzz()` 的调用是否正确：
        * 只有一个函数作为参数。
        * 传递给 `f.Fuzz()` 的函数不能有返回值。
        * 传递给 `f.Fuzz()` 的函数的第一个参数必须是 `*testing.T`。
        * 传递给 `f.Fuzz()` 的函数的后续参数类型必须是支持模糊测试的类型（例如：`string`, `bool`, 数值类型，`[]byte`）。
        * 传递给 `f.Fuzz()` 的函数内部不能调用 `*F` 类型的方法，除了 `Name()` 和 `Failed()`。
    * `f.Add()` 的调用是否正确：
        * 参数数量和类型是否与传递给 `f.Fuzz()` 的函数的参数匹配（除了第一个 `*testing.T` 参数）。
* **Go 代码示例:**

```go
package mypackage

import (
	"fmt"
	"testing"
)

// 正确的模糊测试函数
func FuzzParseInt(f *testing.F) {
	f.Add("123")
	f.Fuzz(func(t *testing.T, s string) {
		_, err := fmt.Println(s)
		if err != nil {
			t.Error(err)
		}
	})
}

// 错误的模糊测试函数：参数类型错误
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出参数类型应为 *testing.F
// func FuzzExample(b *testing.B) { // 错误
// 	b.Fuzz(func(t *testing.T, s string) {})
// }

// 错误的模糊测试函数：f.Fuzz() 参数数量错误
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出 Fuzz 方法应该只接收一个参数
// func FuzzInvalidFuzzCall(f *testing.F) { // 错误
// 	f.Fuzz(func(t *testing.T, s string) {}, 123)
// }

// 错误的模糊测试函数：f.Fuzz() 目标函数返回了值
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出 fuzz 目标不能返回任何值
// func FuzzTargetReturns(f *testing.F) { // 错误
// 	f.Fuzz(func(t *testing.T, s string) string { return "test" })
// }

// 错误的模糊测试函数：f.Fuzz() 目标函数参数类型错误
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出模糊测试参数只能是指定的类型
// func FuzzInvalidTargetArgType(f *testing.F) { // 错误
// 	f.Fuzz(func(t *testing.T, ch chan int) {})
// }

// 错误的模糊测试函数：f.Fuzz() 目标函数调用了不允许的 *F 方法
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出 fuzz 目标不能调用任何 *F 方法
// func FuzzTargetCallsFLog(f *testing.F) { // 错误
// 	f.Fuzz(func(t *testing.T, s string) {
// 		f.Log("some log")
// 	})
// }

// 错误的模糊测试函数：f.Add() 参数数量不匹配
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出 f.Add 的参数数量错误
// func FuzzInvalidAddCallCount(f *testing.F) { // 错误
// 	f.Add("123", 456)
// 	f.Fuzz(func(t *testing.T, s string) {})
// }

// 错误的模糊测试函数：f.Add() 参数类型不匹配
// 假设输入：文件包含此函数
// 输出：报告一个错误，指出 f.Add 的参数类型错误
// func FuzzInvalidAddCallType(f *testing.F) { // 错误
// 	f.Add(123)
// 	f.Fuzz(func(t *testing.T, s string) {})
// }
```

**代码推理:**

这段代码主要使用了 `go/ast` 包来解析 Go 源代码的抽象语法树 (AST)，并使用 `go/types` 包来获取类型信息。

* **遍历 AST:** `run` 函数遍历文件中的所有声明，并根据函数名的前缀判断其类型（Test, Benchmark, Example, Fuzz）。
* **类型检查:**  对于每种类型的函数，都有相应的 `check` 函数来验证其签名和内部结构。例如，`checkTest` 检查 `Test` 和 `Benchmark` 函数的参数类型，`checkExampleName` 检查 `Example` 函数的命名规范，`checkFuzzCall` 和 `checkAddCalls` 检查 `Fuzz` 函数中 `f.Fuzz()` 和 `f.Add()` 的用法。
* **错误报告:**  如果发现任何不符合规范的地方，就会使用 `pass.Reportf` 或 `pass.ReportRangef` 函数报告错误。

**命令行参数的具体处理:**

这个特定的 `analysis pass` 本身**不直接处理命令行参数**。它是 `golang.org/x/tools/go/analysis` 框架的一部分，通常通过 `staticcheck` 或 `go vet` 等工具来运行。这些工具会处理命令行参数，并决定运行哪些 `analysis pass`。

例如，如果你使用 `staticcheck`，你可能会执行类似这样的命令：

```bash
staticcheck ./...
```

`staticcheck` 会加载你的代码，并运行配置好的 `analysis pass`，其中包括 `tests` 这个 pass。

**使用者易犯错的点:**

* **测试/基准测试函数签名错误:**  忘记将参数设置为 `*testing.T` 或 `*testing.B`。
* **示例函数签名错误:**  为示例函数添加了参数或返回值。
* **示例函数 "Output:" 注释位置错误:**  将 "Output:" 注释放在了示例函数的中间而不是结尾。
* **模糊测试函数 `f.Fuzz()` 的使用错误:**
    * 传递给 `f.Fuzz()` 的函数有返回值。
    * 传递给 `f.Fuzz()` 的函数参数类型不正确。
    * 在传递给 `f.Fuzz()` 的函数内部调用了不允许的 `*F` 方法。
* **模糊测试函数 `f.Add()` 的使用错误:**
    * `f.Add()` 的参数数量或类型与 `f.Fuzz()` 期望的参数不匹配。
* **测试/基准测试/示例/模糊测试函数命名不规范:**  例如，`Testabc` 而不是 `TestAbc`。
* **在测试/基准测试函数中使用了类型参数 (泛型)。**

这个 `tests` analysis pass 对于保证 Go 语言测试代码的质量和一致性非常有帮助，可以帮助开发者避免一些常见的错误。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/tools/go/analysis/passes/tests/tests.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	_ "embed"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/internal/analysisutil"
)

//go:embed doc.go
var doc string

var Analyzer = &analysis.Analyzer{
	Name: "tests",
	Doc:  analysisutil.MustExtractDoc(doc, "tests"),
	URL:  "https://pkg.go.dev/golang.org/x/tools/go/analysis/passes/tests",
	Run:  run,
}

var acceptedFuzzTypes = []types.Type{
	types.Typ[types.String],
	types.Typ[types.Bool],
	types.Typ[types.Float32],
	types.Typ[types.Float64],
	types.Typ[types.Int],
	types.Typ[types.Int8],
	types.Typ[types.Int16],
	types.Typ[types.Int32],
	types.Typ[types.Int64],
	types.Typ[types.Uint],
	types.Typ[types.Uint8],
	types.Typ[types.Uint16],
	types.Typ[types.Uint32],
	types.Typ[types.Uint64],
	types.NewSlice(types.Universe.Lookup("byte").Type()),
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, f := range pass.Files {
		if !strings.HasSuffix(pass.Fset.File(f.FileStart).Name(), "_test.go") {
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				// Ignore non-functions or functions with receivers.
				continue
			}
			switch {
			case strings.HasPrefix(fn.Name.Name, "Example"):
				checkExampleName(pass, fn)
				checkExampleOutput(pass, fn, f.Comments)
			case strings.HasPrefix(fn.Name.Name, "Test"):
				checkTest(pass, fn, "Test")
			case strings.HasPrefix(fn.Name.Name, "Benchmark"):
				checkTest(pass, fn, "Benchmark")
			case strings.HasPrefix(fn.Name.Name, "Fuzz"):
				checkTest(pass, fn, "Fuzz")
				checkFuzz(pass, fn)
			}
		}
	}
	return nil, nil
}

// checkFuzz checks the contents of a fuzz function.
func checkFuzz(pass *analysis.Pass, fn *ast.FuncDecl) {
	params := checkFuzzCall(pass, fn)
	if params != nil {
		checkAddCalls(pass, fn, params)
	}
}

// checkFuzzCall checks the arguments of f.Fuzz() calls:
//
//  1. f.Fuzz() should call a function and it should be of type (*testing.F).Fuzz().
//  2. The called function in f.Fuzz(func(){}) should not return result.
//  3. First argument of func() should be of type *testing.T
//  4. Second argument onwards should be of type []byte, string, bool, byte,
//     rune, float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16,
//     uint32, uint64
//  5. func() must not call any *F methods, e.g. (*F).Log, (*F).Error, (*F).Skip
//     The only *F methods that are allowed in the (*F).Fuzz function are (*F).Failed and (*F).Name.
//
// Returns the list of parameters to the fuzz function, if they are valid fuzz parameters.
func checkFuzzCall(pass *analysis.Pass, fn *ast.FuncDecl) (params *types.Tuple) {
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok {
			if !isFuzzTargetDotFuzz(pass, call) {
				return true
			}

			// Only one argument (func) must be passed to (*testing.F).Fuzz.
			if len(call.Args) != 1 {
				return true
			}
			expr := call.Args[0]
			if pass.TypesInfo.Types[expr].Type == nil {
				return true
			}
			t := pass.TypesInfo.Types[expr].Type.Underlying()
			tSign, argOk := t.(*types.Signature)
			// Argument should be a function
			if !argOk {
				pass.ReportRangef(expr, "argument to Fuzz must be a function")
				return false
			}
			// ff Argument function should not return
			if tSign.Results().Len() != 0 {
				pass.ReportRangef(expr, "fuzz target must not return any value")
			}
			// ff Argument function should have 1 or more argument
			if tSign.Params().Len() == 0 {
				pass.ReportRangef(expr, "fuzz target must have 1 or more argument")
				return false
			}
			ok := validateFuzzArgs(pass, tSign.Params(), expr)
			if ok && params == nil {
				params = tSign.Params()
			}
			// Inspect the function that was passed as an argument to make sure that
			// there are no calls to *F methods, except for Name and Failed.
			ast.Inspect(expr, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if !isFuzzTargetDot(pass, call, "") {
						return true
					}
					if !isFuzzTargetDot(pass, call, "Name") && !isFuzzTargetDot(pass, call, "Failed") {
						pass.ReportRangef(call, "fuzz target must not call any *F methods")
					}
				}
				return true
			})
			// We do not need to look at any calls to f.Fuzz inside of a Fuzz call,
			// since they are not allowed.
			return false
		}
		return true
	})
	return params
}

// checkAddCalls checks that the arguments of f.Add calls have the same number and type of arguments as
// the signature of the function passed to (*testing.F).Fuzz
func checkAddCalls(pass *analysis.Pass, fn *ast.FuncDecl, params *types.Tuple) {
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok {
			if !isFuzzTargetDotAdd(pass, call) {
				return true
			}

			// The first argument to function passed to (*testing.F).Fuzz is (*testing.T).
			if len(call.Args) != params.Len()-1 {
				pass.ReportRangef(call, "wrong number of values in call to (*testing.F).Add: %d, fuzz target expects %d", len(call.Args), params.Len()-1)
				return true
			}
			var mismatched []int
			for i, expr := range call.Args {
				if pass.TypesInfo.Types[expr].Type == nil {
					return true
				}
				t := pass.TypesInfo.Types[expr].Type
				if !types.Identical(t, params.At(i+1).Type()) {
					mismatched = append(mismatched, i)
				}
			}
			// If just one of the types is mismatched report for that
			// type only. Otherwise report for the whole call to (*testing.F).Add
			if len(mismatched) == 1 {
				i := mismatched[0]
				expr := call.Args[i]
				t := pass.TypesInfo.Types[expr].Type
				pass.ReportRangef(expr, "mismatched type in call to (*testing.F).Add: %v, fuzz target expects %v", t, params.At(i+1).Type())
			} else if len(mismatched) > 1 {
				var gotArgs, wantArgs []types.Type
				for i := 0; i < len(call.Args); i++ {
					gotArgs, wantArgs = append(gotArgs, pass.TypesInfo.Types[call.Args[i]].Type), append(wantArgs, params.At(i+1).Type())
				}
				pass.ReportRangef(call, "mismatched types in call to (*testing.F).Add: %v, fuzz target expects %v", gotArgs, wantArgs)
			}
		}
		return true
	})
}

// isFuzzTargetDotFuzz reports whether call is (*testing.F).Fuzz().
func isFuzzTargetDotFuzz(pass *analysis.Pass, call *ast.CallExpr) bool {
	return isFuzzTargetDot(pass, call, "Fuzz")
}

// isFuzzTargetDotAdd reports whether call is (*testing.F).Add().
func isFuzzTargetDotAdd(pass *analysis.Pass, call *ast.CallExpr) bool {
	return isFuzzTargetDot(pass, call, "Add")
}

// isFuzzTargetDot reports whether call is (*testing.F).<name>().
func isFuzzTargetDot(pass *analysis.Pass, call *ast.CallExpr, name string) bool {
	if selExpr, ok := call.Fun.(*ast.SelectorExpr); ok {
		if !isTestingType(pass.TypesInfo.Types[selExpr.X].Type, "F") {
			return false
		}
		if name == "" || selExpr.Sel.Name == name {
			return true
		}
	}
	return false
}

// Validate the arguments of fuzz target.
func validateFuzzArgs(pass *analysis.Pass, params *types.Tuple, expr ast.Expr) bool {
	fLit, isFuncLit := expr.(*ast.FuncLit)
	exprRange := expr
	ok := true
	if !isTestingType(params.At(0).Type(), "T") {
		if isFuncLit {
			exprRange = fLit.Type.Params.List[0].Type
		}
		pass.ReportRangef(exprRange, "the first parameter of a fuzz target must be *testing.T")
		ok = false
	}
	for i := 1; i < params.Len(); i++ {
		if !isAcceptedFuzzType(params.At(i).Type()) {
			if isFuncLit {
				curr := 0
				for _, field := range fLit.Type.Params.List {
					curr += len(field.Names)
					if i < curr {
						exprRange = field.Type
						break
					}
				}
			}
			pass.ReportRangef(exprRange, "fuzzing arguments can only have the following types: %s", formatAcceptedFuzzType())
			ok = false
		}
	}
	return ok
}

func isTestingType(typ types.Type, testingType string) bool {
	// No Unalias here: I doubt "go test" recognizes
	// "type A = *testing.T; func Test(A) {}" as a test.
	ptr, ok := typ.(*types.Pointer)
	if !ok {
		return false
	}
	return analysisutil.IsNamedType(ptr.Elem(), "testing", testingType)
}

// Validate that fuzz target function's arguments are of accepted types.
func isAcceptedFuzzType(paramType types.Type) bool {
	for _, typ := range acceptedFuzzTypes {
		if types.Identical(typ, paramType) {
			return true
		}
	}
	return false
}

func formatAcceptedFuzzType() string {
	var acceptedFuzzTypesStrings []string
	for _, typ := range acceptedFuzzTypes {
		acceptedFuzzTypesStrings = append(acceptedFuzzTypesStrings, typ.String())
	}
	acceptedFuzzTypesMsg := strings.Join(acceptedFuzzTypesStrings, ", ")
	return acceptedFuzzTypesMsg
}

func isExampleSuffix(s string) bool {
	r, size := utf8.DecodeRuneInString(s)
	return size > 0 && unicode.IsLower(r)
}

func isTestSuffix(name string) bool {
	if len(name) == 0 {
		// "Test" is ok.
		return true
	}
	r, _ := utf8.DecodeRuneInString(name)
	return !unicode.IsLower(r)
}

func isTestParam(typ ast.Expr, wantType string) bool {
	ptr, ok := typ.(*ast.StarExpr)
	if !ok {
		// Not a pointer.
		return false
	}
	// No easy way of making sure it's a *testing.T or *testing.B:
	// ensure the name of the type matches.
	if name, ok := ptr.X.(*ast.Ident); ok {
		return name.Name == wantType
	}
	if sel, ok := ptr.X.(*ast.SelectorExpr); ok {
		return sel.Sel.Name == wantType
	}
	return false
}

func lookup(pkg *types.Package, name string) []types.Object {
	if o := pkg.Scope().Lookup(name); o != nil {
		return []types.Object{o}
	}

	var ret []types.Object
	// Search through the imports to see if any of them define name.
	// It's hard to tell in general which package is being tested, so
	// for the purposes of the analysis, allow the object to appear
	// in any of the imports. This guarantees there are no false positives
	// because the example needs to use the object so it must be defined
	// in the package or one if its imports. On the other hand, false
	// negatives are possible, but should be rare.
	for _, imp := range pkg.Imports() {
		if obj := imp.Scope().Lookup(name); obj != nil {
			ret = append(ret, obj)
		}
	}
	return ret
}

// This pattern is taken from /go/src/go/doc/example.go
var outputRe = regexp.MustCompile(`(?i)^[[:space:]]*(unordered )?output:`)

type commentMetadata struct {
	isOutput bool
	pos      token.Pos
}

func checkExampleOutput(pass *analysis.Pass, fn *ast.FuncDecl, fileComments []*ast.CommentGroup) {
	commentsInExample := []commentMetadata{}
	numOutputs := 0

	// Find the comment blocks that are in the example. These comments are
	// guaranteed to be in order of appearance.
	for _, cg := range fileComments {
		if cg.Pos() < fn.Pos() {
			continue
		} else if cg.End() > fn.End() {
			break
		}

		isOutput := outputRe.MatchString(cg.Text())
		if isOutput {
			numOutputs++
		}

		commentsInExample = append(commentsInExample, commentMetadata{
			isOutput: isOutput,
			pos:      cg.Pos(),
		})
	}

	// Change message based on whether there are multiple output comment blocks.
	msg := "output comment block must be the last comment block"
	if numOutputs > 1 {
		msg = "there can only be one output comment block per example"
	}

	for i, cg := range commentsInExample {
		// Check for output comments that are not the last comment in the example.
		isLast := (i == len(commentsInExample)-1)
		if cg.isOutput && !isLast {
			pass.Report(
				analysis.Diagnostic{
					Pos:     cg.pos,
					Message: msg,
				},
			)
		}
	}
}

func checkExampleName(pass *analysis.Pass, fn *ast.FuncDecl) {
	fnName := fn.Name.Name
	if params := fn.Type.Params; len(params.List) != 0 {
		pass.Reportf(fn.Pos(), "%s should be niladic", fnName)
	}
	if results := fn.Type.Results; results != nil && len(results.List) != 0 {
		pass.Reportf(fn.Pos(), "%s should return nothing", fnName)
	}
	if tparams := fn.Type.TypeParams; tparams != nil && len(tparams.List) > 0 {
		pass.Reportf(fn.Pos(), "%s should not have type params", fnName)
	}

	if fnName == "Example" {
		// Nothing more to do.
		return
	}

	var (
		exName = strings.TrimPrefix(fnName, "Example")
		elems  = strings.SplitN(exName, "_", 3)
		ident  = elems[0]
		objs   = lookup(pass.Pkg, ident)
	)
	if ident != "" && len(objs) == 0 {
		// Check ExampleFoo and ExampleBadFoo.
		pass.Reportf(fn.Pos(), "%s refers to unknown identifier: %s", fnName, ident)
		// Abort since obj is absent and no subsequent checks can be performed.
		return
	}
	if len(elems) < 2 {
		// Nothing more to do.
		return
	}

	if ident == "" {
		// Check Example_suffix and Example_BadSuffix.
		if residual := strings.TrimPrefix(exName, "_"); !isExampleSuffix(residual) {
			pass.Reportf(fn.Pos(), "%s has malformed example suffix: %s", fnName, residual)
		}
		return
	}

	mmbr := elems[1]
	if !isExampleSuffix(mmbr) {
		// Check ExampleFoo_Method and ExampleFoo_BadMethod.
		found := false
		// Check if Foo.Method exists in this package or its imports.
		for _, obj := range objs {
			if obj, _, _ := types.LookupFieldOrMethod(obj.Type(), true, obj.Pkg(), mmbr); obj != nil {
				found = true
				break
			}
		}
		if !found {
			pass.Reportf(fn.Pos(), "%s refers to unknown field or method: %s.%s", fnName, ident, mmbr)
		}
	}
	if len(elems) == 3 && !isExampleSuffix(elems[2]) {
		// Check ExampleFoo_Method_suffix and ExampleFoo_Method_Badsuffix.
		pass.Reportf(fn.Pos(), "%s has malformed example suffix: %s", fnName, elems[2])
	}
}

type tokenRange struct {
	p, e token.Pos
}

func (r tokenRange) Pos() token.Pos {
	return r.p
}

func (r tokenRange) End() token.Pos {
	return r.e
}

func checkTest(pass *analysis.Pass, fn *ast.FuncDecl, prefix string) {
	// Want functions with 0 results and 1 parameter.
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 ||
		fn.Type.Params == nil ||
		len(fn.Type.Params.List) != 1 ||
		len(fn.Type.Params.List[0].Names) > 1 {
		return
	}

	// The param must look like a *testing.T or *testing.B.
	if !isTestParam(fn.Type.Params.List[0].Type, prefix[:1]) {
		return
	}

	if tparams := fn.Type.TypeParams; tparams != nil && len(tparams.List) > 0 {
		// Note: cmd/go/internal/load also errors about TestXXX and BenchmarkXXX functions with type parameters.
		// We have currently decided to also warn before compilation/package loading. This can help users in IDEs.
		at := tokenRange{tparams.Opening, tparams.Closing}
		pass.ReportRangef(at, "%s has type parameters: it will not be run by go test as a %sXXX function", fn.Name.Name, prefix)
	}

	if !isTestSuffix(fn.Name.Name[len(prefix):]) {
		pass.ReportRangef(fn.Name, "%s has malformed name: first letter after '%s' must not be lowercase", fn.Name.Name, prefix)
	}
}
```