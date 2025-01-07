Response:
My thought process to analyze the Go code and fulfill the request goes like this:

1. **Understand the Goal:** The overarching goal is to understand the functionality of the provided Go code snippet, which is part of the `go/types` package's testing suite. The request specifically asks for the *functions* it performs, examples of its use, potential pitfalls, and a summary of its core purpose.

2. **Initial Code Scan and Keyword Recognition:** I start by scanning the code for prominent keywords and package names. I see:
    * `package types_test`: This immediately tells me it's part of the testing infrastructure for the `go/types` package.
    * `import`: This lists the dependencies, giving hints about the code's functionality. I note `go/ast`, `go/importer`, `go/parser`, `go/token`, and `. "go/types"`. These indicate interaction with the Go abstract syntax tree, importing packages, parsing source code, managing source positions, and working with Go's type system. The `internal/` packages suggest testing internal functionality.
    * Function definitions like `mustParse`, `typecheck`, `mustTypecheck`, `pkgName`, `TestValuesInfo`, and `TestTypesInfo`, `TestInstanceInfo`. The `Test...` prefixes strongly suggest these are test functions.

3. **Analyzing Helper Functions:**  I examine the utility functions first, as they often provide building blocks for the tests:
    * `mustParse`:  Parses Go source code into an AST. The `panic(err)` suggests this is used in test scenarios where parsing *should* succeed.
    * `typecheck`:  The core function for type checking. It takes source code, a `Config`, and an `Info` struct. The `Config` controls the type checking process (error handling, importer), and `Info` is where type information is collected. This is a crucial function for the tests.
    * `mustTypecheck`: A wrapper around `typecheck` that panics on errors, similar to `mustParse`.
    * `pkgName`: Extracts the package name from the source code. This is a simple utility for test setup.

4. **Focusing on Test Functions:** The `Test...` functions are the heart of the provided code.

    * **`TestValuesInfo`:**
        * It defines a `tests` slice of structs. Each struct has `src` (source code), `expr` (an expression within the source), `typ` (the expected type of the expression), and `val` (the expected constant value of the expression, if applicable).
        * It iterates through these test cases.
        * For each case, it calls `mustTypecheck` to type-check the source code.
        * It uses the `Info` struct's `Types` map to find the `TypeAndValue` associated with the specified `expr`.
        * It then asserts that the `Type` and `Value` (if constant) match the expected values.
        * **Inference:** This test function verifies that the type checker correctly identifies the types and values of constant expressions.

    * **`TestTypesInfo`:**
        * Similar structure to `TestValuesInfo`, but the focus is on verifying the *types* of various expressions, including non-constant ones.
        * It tests cases involving `nil`, comma-ok assignments, parameterized functions, type parameters, and even intentionally broken code (marked with `broken +`).
        * **Inference:** This function checks the correctness of type inference for a wider range of Go language constructs.

    * **`TestInstanceInfo`:**
        * This function deals with *generic* functions and types.
        * The `testInst` struct holds the name of the generic function/type, its type arguments, and the expected instantiated type.
        * The tests cover instantiation of functions and types in various contexts.
        * **Inference:** This function is designed to test the type checker's ability to correctly instantiate generic functions and types.

5. **Identifying Functionality and Go Language Features:** Based on the analysis of the test functions, I can deduce the Go language features being tested:
    * Constant expressions and their evaluation.
    * Type inference for various expressions, including literals, variables, and function calls.
    * Handling of the `nil` value.
    * Comma-ok assignments (type assertions, map lookups, channel receives).
    * Variadic functions.
    * Type parameters (generics) in functions and types.
    * Instantiation of generic functions and types.
    * Reverse type inference (inferring type arguments from the context).
    * Parenthesized and pointer type expressions.
    * Interface types, including those with type lists and embedded constraints.

6. **Creating Code Examples:** For each identified feature, I try to create a concise Go code example demonstrating the functionality being tested. I focus on the core aspect being validated by the corresponding test function.

7. **Inferring Input and Output (for code reasoning):**  For examples that involve code reasoning within the test, I consider what the input to the `typecheck` function would be (the source code) and what the relevant output being checked is (the `TypeAndValue` in the `info.Types` map).

8. **Considering Command-Line Arguments:** The provided code doesn't directly process command-line arguments. The `testing` package handles running these tests. Therefore, I note that there are no specific command-line arguments within this code snippet.

9. **Identifying Common Mistakes:**  I reflect on common errors developers might make related to the features being tested. This often involves misunderstandings of type inference rules, especially with generics or `nil`.

10. **Summarizing Functionality:** Finally, I synthesize the findings into a concise summary of the code's overall purpose.

By following this systematic approach, I can accurately analyze the Go code, identify its functionality, provide relevant examples, and address all parts of the request. The iterative nature of this process allows me to refine my understanding as I delve deeper into the code.
这是 `go/src/go/types/api_test.go` 文件的一部分，其主要功能是**测试 `go/types` 包提供的 API，特别是关于类型信息和值的提取功能。**  它通过编写一系列测试用例，使用 `go/parser` 解析 Go 源代码，然后使用 `go/types` 包的 `Config` 和 `Info` 类型检查代码，并断言提取出的类型和值信息是否符合预期。

更具体地说，这部分代码主要测试了以下 `go/types` 包的功能：

1. **获取表达式的类型和值 (`Info.Types`)**:  `go/types` 包能够在类型检查后，记录每个表达式的类型 (`Type`) 和值 (`Value`) (如果表达式是常量)。这些信息存储在 `Info` 结构体的 `Types` 字段中。
2. **常量表达式的求值**: 测试代码会检查常量表达式的类型和求值结果是否正确，包括不同类型的常量 (bool, int, rune, float, complex, string)。
3. **变量的类型**:  测试代码会检查不同声明方式的变量的类型是否正确。
4. **类型转换表达式的类型和值**: 测试代码会检查显式类型转换表达式的类型和值是否正确。
5. **复合字面量的类型和值**:  例如 `[]byte("foo")` 的类型和值。
6. **非常小的浮点数和复数的处理**:  测试了极小浮点数和复数在类型检查中的表示。
7. **iota 的使用**: 测试了 `iota` 在常量声明中的行为。
8. **位移操作中的类型**: 测试了位移操作数和结果的类型。
9. **nil 值的类型**: 测试了 `nil` 在不同上下文中的类型 (例如，作为指针、函数、切片、map、channel 和 interface 的零值)。
10. **类型断言和类型查询的返回值类型**: 测试了类型断言 (`x.(T)`) 和类型查询 (`x.(type)`) 的返回值类型。
11. **channel 接收操作的返回值类型**: 测试了从 channel 接收值的操作 (`<-c`) 的返回值类型。
12. **可变参数的类型**: 测试了可变参数 (`...T`) 的类型。
13. **类型参数 (Generics) 的相关信息**: 测试了泛型函数和类型的声明和实例化过程中，`Info.Types` 记录的类型信息。 包括泛型函数本身的类型，以及实例化后的函数类型。

**如果你能推理出它是什么go语言功能的实现，请用go代码举例说明:**

这部分代码主要测试的是 Go 语言的 **类型系统** 和 **常量求值** 功能在 `go/types` 包中的实现。

**常量表达式求值示例:**

假设输入源代码：

```go
package example

const myConst = 10 + 5
var myVar = myConst * 2
```

测试代码可能会检查表达式 `myConst` 和 `myVar` 的类型和值。

```go
// 假设的测试代码片段
func TestConstantEvaluation(t *testing.T) {
	src := `package example

const myConst = 10 + 5
var myVar = myConst * 2
`
	info := Info{
		Types: make(map[ast.Expr]TypeAndValue),
	}
	fset := token.NewFileSet()
	f := mustParse(fset, src)
	mustTypecheck(src, nil, &info)

	// 查找 myConst 表达式
	var myConstExpr *ast.Ident
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "myConst" {
			myConstExpr = id
			return false
		}
		return true
	})

	if myConstExpr == nil {
		t.Fatal("未找到 myConst 表达式")
	}

	myConstTV := info.Types[myConstExpr]
	if myConstTV.Type.String() != "untyped int" {
		t.Errorf("myConst 的类型错误: got %s, want untyped int", myConstTV.Type.String())
	}
	if myConstTV.Value == nil || myConstTV.Value.String() != "15" {
		t.Errorf("myConst 的值错误: got %v, want 15", myConstTV.Value)
	}

	// 查找 myVar 表达式 (这里简化查找过程，实际可能需要更精细的AST遍历)
	var myVarExpr *ast.BinaryExpr
	ast.Inspect(f, func(n ast.Node) bool {
		if be, ok := n.(*ast.BinaryExpr); ok {
			if id, ok := be.X.(*ast.Ident); ok && id.Name == "myConst" {
				myVarExpr = be
				return false
			}
		}
		return true
	})

	if myVarExpr == nil {
		t.Fatal("未找到 myVar 表达式")
	}

	myVarTV := info.Types[myVarExpr]
	if myVarTV.Type.String() != "int" {
		t.Errorf("myVar 的类型错误: got %s, want int", myVarTV.Type.String())
	}
	if myVarTV.Value == nil || myVarTV.Value.String() != "30" {
		t.Errorf("myVar 的值错误: got %v, want 30", myVarTV.Value)
	}
}
```

**假设的输入与输出:**

* **输入 (src):** 上面的 Go 源代码字符串。
* **输出 (info.Types):**  `info.Types` map 中会包含 `myConstExpr` 和 `myVarExpr` 对应的 `TypeAndValue`，其 `Type` 和 `Value` 字段会被断言是否符合预期。

**如果涉及命令行参数的具体处理，请详细介绍一下:**

这段代码本身是测试代码，不直接处理命令行参数。 它的运行依赖于 `go test` 命令。  `go test` 命令有一些标准的命令行参数，例如：

* `-v`:  显示详细的测试输出。
* `-run <regexp>`:  只运行匹配正则表达式的测试用例。
* `-coverprofile <file>`:  生成覆盖率报告。

例如，要运行 `api_test.go` 文件中的所有测试用例，可以在命令行中执行：

```bash
go test go/src/go/types/api_test.go
```

要运行名称包含 "ValuesInfo" 的测试用例，可以执行：

```bash
go test -run ValuesInfo go/src/go/types/api_test.go
```

**如果有哪些使用者易犯错的点，请举例说明:**

对于 `go/types` 包的使用者来说，一些容易犯错的点可能包括：

1. **没有正确配置 `Config`**:  `Config` 结构体控制着类型检查的过程，例如需要提供 `Importer` 来解析导入的包。 如果 `Importer` 没有正确设置，类型检查可能会失败。

   ```go
   // 错误示例：未设置 Importer
   conf := &Config{}
   info := &Info{}
   _, err := conf.Check("mypkg", fset, []*ast.File{myFile}, info)
   if err != nil {
       // 可能会因为找不到导入的包而报错
   }
   ```

   **正确做法是使用 `importer.Default()` 或自定义的 `Importer`。**

2. **没有正确使用 `Info`**: `Info` 结构体用于存储类型检查的结果，例如表达式的类型、定义的对象等。  使用者需要理解哪些信息会存储在 `Info` 的哪些字段中。

   ```go
   // 错误示例：尝试在类型检查前访问 Info.Types
   info := &Info{
       Types: make(map[ast.Expr]TypeAndValue),
   }
   // 在类型检查之前，info.Types 是空的
   // ... 进行类型检查 ...
   ```

   **应该在类型检查之后访问 `Info` 的字段。**

3. **误解 `untyped` 类型**: Go 语言中有 `untyped` 的常量类型。  初学者可能不清楚 `untyped int` 和 `int` 的区别，以及它们在类型推断中的作用。

   ```go
   const myConst = 10 // untyped int
   var myInt int = myConst // 隐式转换发生
   var myFloat float64 = myConst // 隐式转换发生

   // 如果直接将 untyped 的常量赋值给不同类型的变量，可能会导致意外的结果或错误。
   ```

**请归纳一下它的功能**

这部分 `go/src/go/types/api_test.go` 代码的主要功能是**测试 `go/types` 包的 API，用于验证类型检查器是否能够正确地识别和记录 Go 语言代码中各种表达式的类型和常量值。**  它通过构造不同的 Go 源代码片段，然后利用 `go/types` 包进行类型检查，并断言检查结果（存储在 `Info` 结构体中）与预期一致，从而确保 `go/types` 包的正确性。 这部分代码重点测试了常量求值、变量类型推断、类型转换、复合字面量、泛型以及其他语言特性的类型信息提取功能。

Prompt: 
```
这是路径为go/src/go/types/api_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"internal/goversion"
	"internal/testenv"
	"slices"
	"strings"
	"sync"
	"testing"

	. "go/types"
)

// nopos indicates an unknown position
var nopos token.Pos

func mustParse(fset *token.FileSet, src string) *ast.File {
	f, err := parser.ParseFile(fset, pkgName(src), src, parser.ParseComments)
	if err != nil {
		panic(err) // so we don't need to pass *testing.T
	}
	return f
}

func typecheck(src string, conf *Config, info *Info) (*Package, error) {
	fset := token.NewFileSet()
	f := mustParse(fset, src)
	if conf == nil {
		conf = &Config{
			Error:    func(err error) {}, // collect all errors
			Importer: importer.Default(),
		}
	}
	return conf.Check(f.Name.Name, fset, []*ast.File{f}, info)
}

func mustTypecheck(src string, conf *Config, info *Info) *Package {
	pkg, err := typecheck(src, conf, info)
	if err != nil {
		panic(err) // so we don't need to pass *testing.T
	}
	return pkg
}

// pkgName extracts the package name from src, which must contain a package header.
func pkgName(src string) string {
	const kw = "package "
	if i := strings.Index(src, kw); i >= 0 {
		after := src[i+len(kw):]
		n := len(after)
		if i := strings.IndexAny(after, "\n\t ;/"); i >= 0 {
			n = i
		}
		return after[:n]
	}
	panic("missing package header: " + src)
}

func TestValuesInfo(t *testing.T) {
	var tests = []struct {
		src  string
		expr string // constant expression
		typ  string // constant type
		val  string // constant value
	}{
		{`package a0; const _ = false`, `false`, `untyped bool`, `false`},
		{`package a1; const _ = 0`, `0`, `untyped int`, `0`},
		{`package a2; const _ = 'A'`, `'A'`, `untyped rune`, `65`},
		{`package a3; const _ = 0.`, `0.`, `untyped float`, `0`},
		{`package a4; const _ = 0i`, `0i`, `untyped complex`, `(0 + 0i)`},
		{`package a5; const _ = "foo"`, `"foo"`, `untyped string`, `"foo"`},

		{`package b0; var _ = false`, `false`, `bool`, `false`},
		{`package b1; var _ = 0`, `0`, `int`, `0`},
		{`package b2; var _ = 'A'`, `'A'`, `rune`, `65`},
		{`package b3; var _ = 0.`, `0.`, `float64`, `0`},
		{`package b4; var _ = 0i`, `0i`, `complex128`, `(0 + 0i)`},
		{`package b5; var _ = "foo"`, `"foo"`, `string`, `"foo"`},

		{`package c0a; var _ = bool(false)`, `false`, `bool`, `false`},
		{`package c0b; var _ = bool(false)`, `bool(false)`, `bool`, `false`},
		{`package c0c; type T bool; var _ = T(false)`, `T(false)`, `c0c.T`, `false`},

		{`package c1a; var _ = int(0)`, `0`, `int`, `0`},
		{`package c1b; var _ = int(0)`, `int(0)`, `int`, `0`},
		{`package c1c; type T int; var _ = T(0)`, `T(0)`, `c1c.T`, `0`},

		{`package c2a; var _ = rune('A')`, `'A'`, `rune`, `65`},
		{`package c2b; var _ = rune('A')`, `rune('A')`, `rune`, `65`},
		{`package c2c; type T rune; var _ = T('A')`, `T('A')`, `c2c.T`, `65`},

		{`package c3a; var _ = float32(0.)`, `0.`, `float32`, `0`},
		{`package c3b; var _ = float32(0.)`, `float32(0.)`, `float32`, `0`},
		{`package c3c; type T float32; var _ = T(0.)`, `T(0.)`, `c3c.T`, `0`},

		{`package c4a; var _ = complex64(0i)`, `0i`, `complex64`, `(0 + 0i)`},
		{`package c4b; var _ = complex64(0i)`, `complex64(0i)`, `complex64`, `(0 + 0i)`},
		{`package c4c; type T complex64; var _ = T(0i)`, `T(0i)`, `c4c.T`, `(0 + 0i)`},

		{`package c5a; var _ = string("foo")`, `"foo"`, `string`, `"foo"`},
		{`package c5b; var _ = string("foo")`, `string("foo")`, `string`, `"foo"`},
		{`package c5c; type T string; var _ = T("foo")`, `T("foo")`, `c5c.T`, `"foo"`},
		{`package c5d; var _ = string(65)`, `65`, `untyped int`, `65`},
		{`package c5e; var _ = string('A')`, `'A'`, `untyped rune`, `65`},
		{`package c5f; type T string; var _ = T('A')`, `'A'`, `untyped rune`, `65`},

		{`package d0; var _ = []byte("foo")`, `"foo"`, `string`, `"foo"`},
		{`package d1; var _ = []byte(string("foo"))`, `"foo"`, `string`, `"foo"`},
		{`package d2; var _ = []byte(string("foo"))`, `string("foo")`, `string`, `"foo"`},
		{`package d3; type T []byte; var _ = T("foo")`, `"foo"`, `string`, `"foo"`},

		{`package e0; const _ = float32( 1e-200)`, `float32(1e-200)`, `float32`, `0`},
		{`package e1; const _ = float32(-1e-200)`, `float32(-1e-200)`, `float32`, `0`},
		{`package e2; const _ = float64( 1e-2000)`, `float64(1e-2000)`, `float64`, `0`},
		{`package e3; const _ = float64(-1e-2000)`, `float64(-1e-2000)`, `float64`, `0`},
		{`package e4; const _ = complex64( 1e-200)`, `complex64(1e-200)`, `complex64`, `(0 + 0i)`},
		{`package e5; const _ = complex64(-1e-200)`, `complex64(-1e-200)`, `complex64`, `(0 + 0i)`},
		{`package e6; const _ = complex128( 1e-2000)`, `complex128(1e-2000)`, `complex128`, `(0 + 0i)`},
		{`package e7; const _ = complex128(-1e-2000)`, `complex128(-1e-2000)`, `complex128`, `(0 + 0i)`},

		{`package f0 ; var _ float32 =  1e-200`, `1e-200`, `float32`, `0`},
		{`package f1 ; var _ float32 = -1e-200`, `-1e-200`, `float32`, `0`},
		{`package f2a; var _ float64 =  1e-2000`, `1e-2000`, `float64`, `0`},
		{`package f3a; var _ float64 = -1e-2000`, `-1e-2000`, `float64`, `0`},
		{`package f2b; var _         =  1e-2000`, `1e-2000`, `float64`, `0`},
		{`package f3b; var _         = -1e-2000`, `-1e-2000`, `float64`, `0`},
		{`package f4 ; var _ complex64  =  1e-200 `, `1e-200`, `complex64`, `(0 + 0i)`},
		{`package f5 ; var _ complex64  = -1e-200 `, `-1e-200`, `complex64`, `(0 + 0i)`},
		{`package f6a; var _ complex128 =  1e-2000i`, `1e-2000i`, `complex128`, `(0 + 0i)`},
		{`package f7a; var _ complex128 = -1e-2000i`, `-1e-2000i`, `complex128`, `(0 + 0i)`},
		{`package f6b; var _            =  1e-2000i`, `1e-2000i`, `complex128`, `(0 + 0i)`},
		{`package f7b; var _            = -1e-2000i`, `-1e-2000i`, `complex128`, `(0 + 0i)`},

		{`package g0; const (a = len([iota]int{}); b; c); const _ = c`, `c`, `int`, `2`}, // go.dev/issue/22341
		{`package g1; var(j int32; s int; n = 1.0<<s == j)`, `1.0`, `int32`, `1`},        // go.dev/issue/48422
	}

	for _, test := range tests {
		info := Info{
			Types: make(map[ast.Expr]TypeAndValue),
		}
		name := mustTypecheck(test.src, nil, &info).Name()

		// look for expression
		var expr ast.Expr
		for e := range info.Types {
			if ExprString(e) == test.expr {
				expr = e
				break
			}
		}
		if expr == nil {
			t.Errorf("package %s: no expression found for %s", name, test.expr)
			continue
		}
		tv := info.Types[expr]

		// check that type is correct
		if got := tv.Type.String(); got != test.typ {
			t.Errorf("package %s: got type %s; want %s", name, got, test.typ)
			continue
		}

		// if we have a constant, check that value is correct
		if tv.Value != nil {
			if got := tv.Value.ExactString(); got != test.val {
				t.Errorf("package %s: got value %s; want %s", name, got, test.val)
			}
		} else {
			if test.val != "" {
				t.Errorf("package %s: no constant found; want %s", name, test.val)
			}
		}
	}
}

func TestTypesInfo(t *testing.T) {
	// Test sources that are not expected to typecheck must start with the broken prefix.
	const broken = "package broken_"

	var tests = []struct {
		src  string
		expr string // expression
		typ  string // value type
	}{
		// single-valued expressions of untyped constants
		{`package b0; var x interface{} = false`, `false`, `bool`},
		{`package b1; var x interface{} = 0`, `0`, `int`},
		{`package b2; var x interface{} = 0.`, `0.`, `float64`},
		{`package b3; var x interface{} = 0i`, `0i`, `complex128`},
		{`package b4; var x interface{} = "foo"`, `"foo"`, `string`},

		// uses of nil
		{`package n0; var _ *int = nil`, `nil`, `untyped nil`},
		{`package n1; var _ func() = nil`, `nil`, `untyped nil`},
		{`package n2; var _ []byte = nil`, `nil`, `untyped nil`},
		{`package n3; var _ map[int]int = nil`, `nil`, `untyped nil`},
		{`package n4; var _ chan int = nil`, `nil`, `untyped nil`},
		{`package n5; var _ interface{} = nil`, `nil`, `untyped nil`},
		{`package n6; import "unsafe"; var _ unsafe.Pointer = nil`, `nil`, `untyped nil`},

		{`package n10; var (x *int; _ = x == nil)`, `nil`, `untyped nil`},
		{`package n11; var (x func(); _ = x == nil)`, `nil`, `untyped nil`},
		{`package n12; var (x []byte; _ = x == nil)`, `nil`, `untyped nil`},
		{`package n13; var (x map[int]int; _ = x == nil)`, `nil`, `untyped nil`},
		{`package n14; var (x chan int; _ = x == nil)`, `nil`, `untyped nil`},
		{`package n15; var (x interface{}; _ = x == nil)`, `nil`, `untyped nil`},
		{`package n15; import "unsafe"; var (x unsafe.Pointer; _ = x == nil)`, `nil`, `untyped nil`},

		{`package n20; var _ = (*int)(nil)`, `nil`, `untyped nil`},
		{`package n21; var _ = (func())(nil)`, `nil`, `untyped nil`},
		{`package n22; var _ = ([]byte)(nil)`, `nil`, `untyped nil`},
		{`package n23; var _ = (map[int]int)(nil)`, `nil`, `untyped nil`},
		{`package n24; var _ = (chan int)(nil)`, `nil`, `untyped nil`},
		{`package n25; var _ = (interface{})(nil)`, `nil`, `untyped nil`},
		{`package n26; import "unsafe"; var _ = unsafe.Pointer(nil)`, `nil`, `untyped nil`},

		{`package n30; func f(*int) { f(nil) }`, `nil`, `untyped nil`},
		{`package n31; func f(func()) { f(nil) }`, `nil`, `untyped nil`},
		{`package n32; func f([]byte) { f(nil) }`, `nil`, `untyped nil`},
		{`package n33; func f(map[int]int) { f(nil) }`, `nil`, `untyped nil`},
		{`package n34; func f(chan int) { f(nil) }`, `nil`, `untyped nil`},
		{`package n35; func f(interface{}) { f(nil) }`, `nil`, `untyped nil`},
		{`package n35; import "unsafe"; func f(unsafe.Pointer) { f(nil) }`, `nil`, `untyped nil`},

		// comma-ok expressions
		{`package p0; var x interface{}; var _, _ = x.(int)`,
			`x.(int)`,
			`(int, bool)`,
		},
		{`package p1; var x interface{}; func _() { _, _ = x.(int) }`,
			`x.(int)`,
			`(int, bool)`,
		},
		{`package p2a; type mybool bool; var m map[string]complex128; var b mybool; func _() { _, b = m["foo"] }`,
			`m["foo"]`,
			`(complex128, p2a.mybool)`,
		},
		{`package p2b; var m map[string]complex128; var b bool; func _() { _, b = m["foo"] }`,
			`m["foo"]`,
			`(complex128, bool)`,
		},
		{`package p3; var c chan string; var _, _ = <-c`,
			`<-c`,
			`(string, bool)`,
		},

		// go.dev/issue/6796
		{`package issue6796_a; var x interface{}; var _, _ = (x.(int))`,
			`x.(int)`,
			`(int, bool)`,
		},
		{`package issue6796_b; var c chan string; var _, _ = (<-c)`,
			`(<-c)`,
			`(string, bool)`,
		},
		{`package issue6796_c; var c chan string; var _, _ = (<-c)`,
			`<-c`,
			`(string, bool)`,
		},
		{`package issue6796_d; var c chan string; var _, _ = ((<-c))`,
			`(<-c)`,
			`(string, bool)`,
		},
		{`package issue6796_e; func f(c chan string) { _, _ = ((<-c)) }`,
			`(<-c)`,
			`(string, bool)`,
		},

		// go.dev/issue/7060
		{`package issue7060_a; var ( m map[int]string; x, ok = m[0] )`,
			`m[0]`,
			`(string, bool)`,
		},
		{`package issue7060_b; var ( m map[int]string; x, ok interface{} = m[0] )`,
			`m[0]`,
			`(string, bool)`,
		},
		{`package issue7060_c; func f(x interface{}, ok bool, m map[int]string) { x, ok = m[0] }`,
			`m[0]`,
			`(string, bool)`,
		},
		{`package issue7060_d; var ( ch chan string; x, ok = <-ch )`,
			`<-ch`,
			`(string, bool)`,
		},
		{`package issue7060_e; var ( ch chan string; x, ok interface{} = <-ch )`,
			`<-ch`,
			`(string, bool)`,
		},
		{`package issue7060_f; func f(x interface{}, ok bool, ch chan string) { x, ok = <-ch }`,
			`<-ch`,
			`(string, bool)`,
		},

		// go.dev/issue/28277
		{`package issue28277_a; func f(...int)`,
			`...int`,
			`[]int`,
		},
		{`package issue28277_b; func f(a, b int, c ...[]struct{})`,
			`...[]struct{}`,
			`[][]struct{}`,
		},

		// go.dev/issue/47243
		{`package issue47243_a; var x int32; var _ = x << 3`, `3`, `untyped int`},
		{`package issue47243_b; var x int32; var _ = x << 3.`, `3.`, `untyped float`},
		{`package issue47243_c; var x int32; var _ = 1 << x`, `1 << x`, `int`},
		{`package issue47243_d; var x int32; var _ = 1 << x`, `1`, `int`},
		{`package issue47243_e; var x int32; var _ = 1 << 2`, `1`, `untyped int`},
		{`package issue47243_f; var x int32; var _ = 1 << 2`, `2`, `untyped int`},
		{`package issue47243_g; var x int32; var _ = int(1) << 2`, `2`, `untyped int`},
		{`package issue47243_h; var x int32; var _ = 1 << (2 << x)`, `1`, `int`},
		{`package issue47243_i; var x int32; var _ = 1 << (2 << x)`, `(2 << x)`, `untyped int`},
		{`package issue47243_j; var x int32; var _ = 1 << (2 << x)`, `2`, `untyped int`},

		// tests for broken code that doesn't type-check
		{broken + `x0; func _() { var x struct {f string}; x.f := 0 }`, `x.f`, `string`},
		{broken + `x1; func _() { var z string; type x struct {f string}; y := &x{q: z}}`, `z`, `string`},
		{broken + `x2; func _() { var a, b string; type x struct {f string}; z := &x{f: a, f: b,}}`, `b`, `string`},
		{broken + `x3; var x = panic("");`, `panic`, `func(interface{})`},
		{`package x4; func _() { panic("") }`, `panic`, `func(interface{})`},
		{broken + `x5; func _() { var x map[string][...]int; x = map[string][...]int{"": {1,2,3}} }`, `x`, `map[string]invalid type`},

		// parameterized functions
		{`package p0; func f[T any](T) {}; var _ = f[int]`, `f`, `func[T any](T)`},
		{`package p1; func f[T any](T) {}; var _ = f[int]`, `f[int]`, `func(int)`},
		{`package p2; func f[T any](T) {}; func _() { f(42) }`, `f`, `func(int)`},
		{`package p3; func f[T any](T) {}; func _() { f[int](42) }`, `f[int]`, `func(int)`},
		{`package p4; func f[T any](T) {}; func _() { f[int](42) }`, `f`, `func[T any](T)`},
		{`package p5; func f[T any](T) {}; func _() { f(42) }`, `f(42)`, `()`},

		// type parameters
		{`package t0; type t[] int; var _ t`, `t`, `t0.t`}, // t[] is a syntax error that is ignored in this test in favor of t
		{`package t1; type t[P any] int; var _ t[int]`, `t`, `t1.t[P any]`},
		{`package t2; type t[P interface{}] int; var _ t[int]`, `t`, `t2.t[P interface{}]`},
		{`package t3; type t[P, Q interface{}] int; var _ t[int, int]`, `t`, `t3.t[P, Q interface{}]`},
		{broken + `t4; type t[P, Q interface{ m() }] int; var _ t[int, int]`, `t`, `broken_t4.t[P, Q interface{m()}]`},

		// instantiated types must be sanitized
		{`package g0; type t[P any] int; var x struct{ f t[int] }; var _ = x.f`, `x.f`, `g0.t[int]`},

		// go.dev/issue/45096
		{`package issue45096; func _[T interface{ ~int8 | ~int16 | ~int32  }](x T) { _ = x < 0 }`, `0`, `T`},

		// go.dev/issue/47895
		{`package p; import "unsafe"; type S struct { f int }; var s S; var _ = unsafe.Offsetof(s.f)`, `s.f`, `int`},

		// go.dev/issue/50093
		{`package u0a; func _[_ interface{int}]() {}`, `int`, `int`},
		{`package u1a; func _[_ interface{~int}]() {}`, `~int`, `~int`},
		{`package u2a; func _[_ interface{int | string}]() {}`, `int | string`, `int | string`},
		{`package u3a; func _[_ interface{int | string | ~bool}]() {}`, `int | string | ~bool`, `int | string | ~bool`},
		{`package u3a; func _[_ interface{int | string | ~bool}]() {}`, `int | string`, `int | string`},
		{`package u3a; func _[_ interface{int | string | ~bool}]() {}`, `~bool`, `~bool`},
		{`package u3a; func _[_ interface{int | string | ~float64|~bool}]() {}`, `int | string | ~float64`, `int | string | ~float64`},

		{`package u0b; func _[_ int]() {}`, `int`, `int`},
		{`package u1b; func _[_ ~int]() {}`, `~int`, `~int`},
		{`package u2b; func _[_ int | string]() {}`, `int | string`, `int | string`},
		{`package u3b; func _[_ int | string | ~bool]() {}`, `int | string | ~bool`, `int | string | ~bool`},
		{`package u3b; func _[_ int | string | ~bool]() {}`, `int | string`, `int | string`},
		{`package u3b; func _[_ int | string | ~bool]() {}`, `~bool`, `~bool`},
		{`package u3b; func _[_ int | string | ~float64|~bool]() {}`, `int | string | ~float64`, `int | string | ~float64`},

		{`package u0c; type _ interface{int}`, `int`, `int`},
		{`package u1c; type _ interface{~int}`, `~int`, `~int`},
		{`package u2c; type _ interface{int | string}`, `int | string`, `int | string`},
		{`package u3c; type _ interface{int | string | ~bool}`, `int | string | ~bool`, `int | string | ~bool`},
		{`package u3c; type _ interface{int | string | ~bool}`, `int | string`, `int | string`},
		{`package u3c; type _ interface{int | string | ~bool}`, `~bool`, `~bool`},
		{`package u3c; type _ interface{int | string | ~float64|~bool}`, `int | string | ~float64`, `int | string | ~float64`},

		// reverse type inference
		{`package r1; var _ func(int) = g; func g[P any](P) {}`, `g`, `func(int)`},
		{`package r2; var _ func(int) = g[int]; func g[P any](P) {}`, `g`, `func[P any](P)`}, // go.dev/issues/60212
		{`package r3; var _ func(int) = g[int]; func g[P any](P) {}`, `g[int]`, `func(int)`},
		{`package r4; var _ func(int, string) = g; func g[P, Q any](P, Q) {}`, `g`, `func(int, string)`},
		{`package r5; var _ func(int, string) = g[int]; func g[P, Q any](P, Q) {}`, `g`, `func[P, Q any](P, Q)`}, // go.dev/issues/60212
		{`package r6; var _ func(int, string) = g[int]; func g[P, Q any](P, Q) {}`, `g[int]`, `func(int, string)`},

		{`package s1; func _() { f(g) }; func f(func(int)) {}; func g[P any](P) {}`, `g`, `func(int)`},
		{`package s2; func _() { f(g[int]) }; func f(func(int)) {}; func g[P any](P) {}`, `g`, `func[P any](P)`}, // go.dev/issues/60212
		{`package s3; func _() { f(g[int]) }; func f(func(int)) {}; func g[P any](P) {}`, `g[int]`, `func(int)`},
		{`package s4; func _() { f(g) }; func f(func(int, string)) {}; func g[P, Q any](P, Q) {}`, `g`, `func(int, string)`},
		{`package s5; func _() { f(g[int]) }; func f(func(int, string)) {}; func g[P, Q any](P, Q) {}`, `g`, `func[P, Q any](P, Q)`}, // go.dev/issues/60212
		{`package s6; func _() { f(g[int]) }; func f(func(int, string)) {}; func g[P, Q any](P, Q) {}`, `g[int]`, `func(int, string)`},

		{`package s7; func _() { f(g, h) }; func f[P any](func(int, P), func(P, string)) {}; func g[P any](P, P) {}; func h[P, Q any](P, Q) {}`, `g`, `func(int, int)`},
		{`package s8; func _() { f(g, h) }; func f[P any](func(int, P), func(P, string)) {}; func g[P any](P, P) {}; func h[P, Q any](P, Q) {}`, `h`, `func(int, string)`},
		{`package s9; func _() { f(g, h[int]) }; func f[P any](func(int, P), func(P, string)) {}; func g[P any](P, P) {}; func h[P, Q any](P, Q) {}`, `h`, `func[P, Q any](P, Q)`}, // go.dev/issues/60212
		{`package s10; func _() { f(g, h[int]) }; func f[P any](func(int, P), func(P, string)) {}; func g[P any](P, P) {}; func h[P, Q any](P, Q) {}`, `h[int]`, `func(int, string)`},

		// go.dev/issue/68639
		// parenthesized and pointer type expressions in various positions
		// - as variable type, not generic
		{`package qa1; type T int; var x T`, `T`, `qa1.T`},
		{`package qa2; type T int; var x (T)`, `T`, `qa2.T`},
		{`package qa3; type T int; var x (T)`, `(T)`, `qa3.T`},
		{`package qa4; type T int; var x ((T))`, `T`, `qa4.T`},
		{`package qa5; type T int; var x ((T))`, `(T)`, `qa5.T`},
		{`package qa6; type T int; var x ((T))`, `((T))`, `qa6.T`},
		{`package qa7; type T int; var x *T`, `T`, `qa7.T`},
		{`package qa8; type T int; var x *T`, `*T`, `*qa8.T`},
		{`package qa9; type T int; var x (*T)`, `T`, `qa9.T`},
		{`package qa10; type T int; var x (*T)`, `*T`, `*qa10.T`},
		{`package qa11; type T int; var x *(T)`, `T`, `qa11.T`},
		{`package qa12; type T int; var x *(T)`, `(T)`, `qa12.T`},
		{`package qa13; type T int; var x *(T)`, `*(T)`, `*qa13.T`},
		{`package qa14; type T int; var x (*(T))`, `(T)`, `qa14.T`},
		{`package qa15; type T int; var x (*(T))`, `*(T)`, `*qa15.T`},
		{`package qa16; type T int; var x (*(T))`, `(*(T))`, `*qa16.T`},

		// - as ordinary function parameter, not generic
		{`package qb1; type T int; func _(T)`, `T`, `qb1.T`},
		{`package qb2; type T int; func _((T))`, `T`, `qb2.T`},
		{`package qb3; type T int; func _((T))`, `(T)`, `qb3.T`},
		{`package qb4; type T int; func _(((T)))`, `T`, `qb4.T`},
		{`package qb5; type T int; func _(((T)))`, `(T)`, `qb5.T`},
		{`package qb6; type T int; func _(((T)))`, `((T))`, `qb6.T`},
		{`package qb7; type T int; func _(*T)`, `T`, `qb7.T`},
		{`package qb8; type T int; func _(*T)`, `*T`, `*qb8.T`},
		{`package qb9; type T int; func _((*T))`, `T`, `qb9.T`},
		{`package qb10; type T int; func _((*T))`, `*T`, `*qb10.T`},
		{`package qb11; type T int; func _(*(T))`, `T`, `qb11.T`},
		{`package qb12; type T int; func _(*(T))`, `(T)`, `qb12.T`},
		{`package qb13; type T int; func _(*(T))`, `*(T)`, `*qb13.T`},
		{`package qb14; type T int; func _((*(T)))`, `(T)`, `qb14.T`},
		{`package qb15; type T int; func _((*(T)))`, `*(T)`, `*qb15.T`},
		{`package qb16; type T int; func _((*(T)))`, `(*(T))`, `*qb16.T`},

		// - as method receiver, not generic
		{`package qc1; type T int; func (T) _() {}`, `T`, `qc1.T`},
		{`package qc2; type T int; func ((T)) _() {}`, `T`, `qc2.T`},
		{`package qc3; type T int; func ((T)) _() {}`, `(T)`, `qc3.T`},
		{`package qc4; type T int; func (((T))) _() {}`, `T`, `qc4.T`},
		{`package qc5; type T int; func (((T))) _() {}`, `(T)`, `qc5.T`},
		{`package qc6; type T int; func (((T))) _() {}`, `((T))`, `qc6.T`},
		{`package qc7; type T int; func (*T) _() {}`, `T`, `qc7.T`},
		{`package qc8; type T int; func (*T) _() {}`, `*T`, `*qc8.T`},
		{`package qc9; type T int; func ((*T)) _() {}`, `T`, `qc9.T`},
		{`package qc10; type T int; func ((*T)) _() {}`, `*T`, `*qc10.T`},
		{`package qc11; type T int; func (*(T)) _() {}`, `T`, `qc11.T`},
		{`package qc12; type T int; func (*(T)) _() {}`, `(T)`, `qc12.T`},
		{`package qc13; type T int; func (*(T)) _() {}`, `*(T)`, `*qc13.T`},
		{`package qc14; type T int; func ((*(T))) _() {}`, `(T)`, `qc14.T`},
		{`package qc15; type T int; func ((*(T))) _() {}`, `*(T)`, `*qc15.T`},
		{`package qc16; type T int; func ((*(T))) _() {}`, `(*(T))`, `*qc16.T`},

		// - as variable type, generic
		{`package qd1; type T[_ any] int; var x T[int]`, `T`, `qd1.T[_ any]`},
		{`package qd2; type T[_ any] int; var x (T[int])`, `T[int]`, `qd2.T[int]`},
		{`package qd3; type T[_ any] int; var x (T[int])`, `(T[int])`, `qd3.T[int]`},
		{`package qd4; type T[_ any] int; var x ((T[int]))`, `T`, `qd4.T[_ any]`},
		{`package qd5; type T[_ any] int; var x ((T[int]))`, `(T[int])`, `qd5.T[int]`},
		{`package qd6; type T[_ any] int; var x ((T[int]))`, `((T[int]))`, `qd6.T[int]`},
		{`package qd7; type T[_ any] int; var x *T[int]`, `T`, `qd7.T[_ any]`},
		{`package qd8; type T[_ any] int; var x *T[int]`, `*T[int]`, `*qd8.T[int]`},
		{`package qd9; type T[_ any] int; var x (*T[int])`, `T`, `qd9.T[_ any]`},
		{`package qd10; type T[_ any] int; var x (*T[int])`, `*T[int]`, `*qd10.T[int]`},
		{`package qd11; type T[_ any] int; var x *(T[int])`, `T[int]`, `qd11.T[int]`},
		{`package qd12; type T[_ any] int; var x *(T[int])`, `(T[int])`, `qd12.T[int]`},
		{`package qd13; type T[_ any] int; var x *(T[int])`, `*(T[int])`, `*qd13.T[int]`},
		{`package qd14; type T[_ any] int; var x (*(T[int]))`, `(T[int])`, `qd14.T[int]`},
		{`package qd15; type T[_ any] int; var x (*(T[int]))`, `*(T[int])`, `*qd15.T[int]`},
		{`package qd16; type T[_ any] int; var x (*(T[int]))`, `(*(T[int]))`, `*qd16.T[int]`},

		// - as ordinary function parameter, generic
		{`package qe1; type T[_ any] int; func _(T[int])`, `T`, `qe1.T[_ any]`},
		{`package qe2; type T[_ any] int; func _((T[int]))`, `T[int]`, `qe2.T[int]`},
		{`package qe3; type T[_ any] int; func _((T[int]))`, `(T[int])`, `qe3.T[int]`},
		{`package qe4; type T[_ any] int; func _(((T[int])))`, `T`, `qe4.T[_ any]`},
		{`package qe5; type T[_ any] int; func _(((T[int])))`, `(T[int])`, `qe5.T[int]`},
		{`package qe6; type T[_ any] int; func _(((T[int])))`, `((T[int]))`, `qe6.T[int]`},
		{`package qe7; type T[_ any] int; func _(*T[int])`, `T`, `qe7.T[_ any]`},
		{`package qe8; type T[_ any] int; func _(*T[int])`, `*T[int]`, `*qe8.T[int]`},
		{`package qe9; type T[_ any] int; func _((*T[int]))`, `T`, `qe9.T[_ any]`},
		{`package qe10; type T[_ any] int; func _((*T[int]))`, `*T[int]`, `*qe10.T[int]`},
		{`package qe11; type T[_ any] int; func _(*(T[int]))`, `T[int]`, `qe11.T[int]`},
		{`package qe12; type T[_ any] int; func _(*(T[int]))`, `(T[int])`, `qe12.T[int]`},
		{`package qe13; type T[_ any] int; func _(*(T[int]))`, `*(T[int])`, `*qe13.T[int]`},
		{`package qe14; type T[_ any] int; func _((*(T[int])))`, `(T[int])`, `qe14.T[int]`},
		{`package qe15; type T[_ any] int; func _((*(T[int])))`, `*(T[int])`, `*qe15.T[int]`},
		{`package qe16; type T[_ any] int; func _((*(T[int])))`, `(*(T[int]))`, `*qe16.T[int]`},

		// - as method receiver, generic
		{`package qf1; type T[_ any] int; func (T[_]) _() {}`, `T`, `qf1.T[_ any]`},
		{`package qf2; type T[_ any] int; func ((T[_])) _() {}`, `T[_]`, `qf2.T[_]`},
		{`package qf3; type T[_ any] int; func ((T[_])) _() {}`, `(T[_])`, `qf3.T[_]`},
		{`package qf4; type T[_ any] int; func (((T[_]))) _() {}`, `T`, `qf4.T[_ any]`},
		{`package qf5; type T[_ any] int; func (((T[_]))) _() {}`, `(T[_])`, `qf5.T[_]`},
		{`package qf6; type T[_ any] int; func (((T[_]))) _() {}`, `((T[_]))`, `qf6.T[_]`},
		{`package qf7; type T[_ any] int; func (*T[_]) _() {}`, `T`, `qf7.T[_ any]`},
		{`package qf8; type T[_ any] int; func (*T[_]) _() {}`, `*T[_]`, `*qf8.T[_]`},
		{`package qf9; type T[_ any] int; func ((*T[_])) _() {}`, `T`, `qf9.T[_ any]`},
		{`package qf10; type T[_ any] int; func ((*T[_])) _() {}`, `*T[_]`, `*qf10.T[_]`},
		{`package qf11; type T[_ any] int; func (*(T[_])) _() {}`, `T[_]`, `qf11.T[_]`},
		{`package qf12; type T[_ any] int; func (*(T[_])) _() {}`, `(T[_])`, `qf12.T[_]`},
		{`package qf13; type T[_ any] int; func (*(T[_])) _() {}`, `*(T[_])`, `*qf13.T[_]`},
		{`package qf14; type T[_ any] int; func ((*(T[_]))) _() {}`, `(T[_])`, `qf14.T[_]`},
		{`package qf15; type T[_ any] int; func ((*(T[_]))) _() {}`, `*(T[_])`, `*qf15.T[_]`},
		{`package qf16; type T[_ any] int; func ((*(T[_]))) _() {}`, `(*(T[_]))`, `*qf16.T[_]`},

		// For historic reasons, type parameters in receiver type expressions
		// are considered both definitions and uses and thus also show up in
		// the Info.Types map (see go.dev/issue/68670).
		{`package t1; type T[_ any] int; func (T[P]) _() {}`, `P`, `P`},
		{`package t2; type T[_, _ any] int; func (T[P, Q]) _() {}`, `P`, `P`},
		{`package t3; type T[_, _ any] int; func (T[P, Q]) _() {}`, `Q`, `Q`},
	}

	for _, test := range tests {
		info := Info{Types: make(map[ast.Expr]TypeAndValue)}
		var name string
		if strings.HasPrefix(test.src, broken) {
			pkg, err := typecheck(test.src, nil, &info)
			if err == nil {
				t.Errorf("package %s: expected to fail but passed", pkg.Name())
				continue
			}
			if pkg != nil {
				name = pkg.Name()
			}
		} else {
			name = mustTypecheck(test.src, nil, &info).Name()
		}

		// look for expression type
		var typ Type
		for e, tv := range info.Types {
			if ExprString(e) == test.expr {
				typ = tv.Type
				break
			}
		}
		if typ == nil {
			t.Errorf("package %s: no type found for %s", name, test.expr)
			continue
		}

		// check that type is correct
		if got := typ.String(); got != test.typ {
			t.Errorf("package %s: expr = %s: got %s; want %s", name, test.expr, got, test.typ)
		}
	}
}

func TestInstanceInfo(t *testing.T) {
	const lib = `package lib

func F[P any](P) {}

type T[P any] []P
`

	type testInst struct {
		name  string
		targs []string
		typ   string
	}

	var tests = []struct {
		src       string
		instances []testInst // recorded instances in source order
	}{
		{`package p0; func f[T any](T) {}; func _() { f(42) }`,
			[]testInst{{`f`, []string{`int`}, `func(int)`}},
		},
		{`package p1; func f[T any](T) T { panic(0) }; func _() { f('@') }`,
			[]testInst{{`f`, []string{`rune`}, `func(rune) rune`}},
		},
		{`package p2; func f[T any](...T) T { panic(0) }; func _() { f(0i) }`,
			[]testInst{{`f`, []string{`complex128`}, `func(...complex128) complex128`}},
		},
		{`package p3; func f[A, B, C any](A, *B, []C) {}; func _() { f(1.2, new(string), []byte{}) }`,
			[]testInst{{`f`, []string{`float64`, `string`, `byte`}, `func(float64, *string, []byte)`}},
		},
		{`package p4; func f[A, B any](A, *B, ...[]B) {}; func _() { f(1.2, new(byte)) }`,
			[]testInst{{`f`, []string{`float64`, `byte`}, `func(float64, *byte, ...[]byte)`}},
		},

		{`package s1; func f[T any, P interface{*T}](x T) {}; func _(x string) { f(x) }`,
			[]testInst{{`f`, []string{`string`, `*string`}, `func(x string)`}},
		},
		{`package s2; func f[T any, P interface{*T}](x []T) {}; func _(x []int) { f(x) }`,
			[]testInst{{`f`, []string{`int`, `*int`}, `func(x []int)`}},
		},
		{`package s3; type C[T any] interface{chan<- T}; func f[T any, P C[T]](x []T) {}; func _(x []int) { f(x) }`,
			[]testInst{
				{`C`, []string{`T`}, `interface{chan<- T}`},
				{`f`, []string{`int`, `chan<- int`}, `func(x []int)`},
			},
		},
		{`package s4; type C[T any] interface{chan<- T}; func f[T any, P C[T], Q C[[]*P]](x []T) {}; func _(x []int) { f(x) }`,
			[]testInst{
				{`C`, []string{`T`}, `interface{chan<- T}`},
				{`C`, []string{`[]*P`}, `interface{chan<- []*P}`},
				{`f`, []string{`int`, `chan<- int`, `chan<- []*chan<- int`}, `func(x []int)`},
			},
		},

		{`package t1; func f[T any, P interface{*T}]() T { panic(0) }; func _() { _ = f[string] }`,
			[]testInst{{`f`, []string{`string`, `*string`}, `func() string`}},
		},
		{`package t2; func f[T any, P interface{*T}]() T { panic(0) }; func _() { _ = (f[string]) }`,
			[]testInst{{`f`, []string{`string`, `*string`}, `func() string`}},
		},
		{`package t3; type C[T any] interface{chan<- T}; func f[T any, P C[T], Q C[[]*P]]() []T { return nil }; func _() { _ = f[int] }`,
			[]testInst{
				{`C`, []string{`T`}, `interface{chan<- T}`},
				{`C`, []string{`[]*P`}, `interface{chan<- []*P}`},
				{`f`, []string{`int`, `chan<- int`, `chan<- []*chan<- int`}, `func() []int`},
			},
		},
		{`package t4; type C[T any] interface{chan<- T}; func f[T any, P C[T], Q C[[]*P]]() []T { return nil }; func _() { _ = (f[int]) }`,
			[]testInst{
				{`C`, []string{`T`}, `interface{chan<- T}`},
				{`C`, []string{`[]*P`}, `interface{chan<- []*P}`},
				{`f`, []string{`int`, `chan<- int`, `chan<- []*chan<- int`}, `func() []int`},
			},
		},
		{`package i0; import "lib"; func _() { lib.F(42) }`,
			[]testInst{{`F`, []string{`int`}, `func(int)`}},
		},

		{`package duplfunc0; func f[T any](T) {}; func _() { f(42); f("foo"); f[int](3) }`,
			[]testInst{
				{`f`, []string{`int`}, `func(int)`},
				{`f`, []string{`string`}, `func(string)`},
				{`f`, []string{`int`}, `func(int)`},
			},
		},
		{`package duplfunc1; import "lib"; func _() { lib.F(42); lib.F("foo"); lib.F(3) }`,
			[]testInst{
				{`F`, []string{`int`}, `func(int)`},
				{`F`, []string{`string`}, `func(string)`},
				{`F`, []string{`int`}, `func(int)`},
			},
		},

		{`package type0; type T[P interface{~int}] struct{ x P }; var _ T[int]`,
			[]testInst{{`T`, []string{`int`}, `struct{x int}`}},
		},
		{`package type1; type T[P interface{~int}] struct{ x P }; var _ (T[int])`,
			[]testInst{{`T`, []string{`int`}, `struct{x int}`}},
		},
		{`package type2; type T[P interface{~int}] struct{ x P }; var _ T[(int)]`,
			[]testInst{{`T`, []string{`int`}, `struct{x int}`}},
		},
		{`package type3; type T[P1 interface{~[]P2}, P2 any] struct{ x P1; y P2 }; var _ T[[]int, int]`,
			[]testInst{{`T`, []string{`[]int`, `int`}, `struct{x []int; y int}`}},
		},
		{`package type4; import "lib"; var _ lib.T[int]`,
			[]testInst{{`T`, []string{`int`}, `[]int`}},
		},

		{`package dupltype0; type T[P interface{~int}] struct{ x P }; var x T[int]; var y T[int]`,
			[]testInst{
				{`T`, []string{`int`}, `struct{x int}`},
				{`T`, []string{`int`}, `struct{x int}`},
			},
		},
		{`package dupltype1; type T[P ~int] struct{ x P }; func (r *T[Q]) add(z T[Q]) { r.x += z.x }`,
			[]testInst{
				{`T`, []string{`Q`}, `struct{x Q}`},
				{`T`, []string{`Q`}, `struct{x Q}`},
			},
		},
		{`package dupltype1; import "lib"; var x lib.T[int]; var y lib.T[int]; var z lib.T[string]`,
			[]testInst{
				{`T`, []string{`int`}, `[]int`},
				{`T`, []string{`int`}, `[]int`},
				{`T`, []string{`string`}, `[]string`},
			},
		},
		{`package issue51803; func foo[T any](T) {}; func _() { foo[int]( /* leave arg away on purpose */ ) }`,
			[]testInst{{`foo`, []string{`int`}, `func(int)`}},
		},

		// reverse type inference
		{`package reverse1a; var f func(int) = g; func g[P any](P) {}`,
			[]testInst{{`g`, []string{`int`}, `func(int)`}},
		},
		{`package reverse1b; func f(func(int)) {}; func g[P any](P) {}; func _() { f(g) }`,
			[]testInst{{`g`, []string{`int`}, `func(int)`}},
		},
		{`package reverse2a; var f func(int, string) = g; func g[P, Q any](P, Q) {}`,
			[]testInst{{`g`, []string{`int`, `string`}, `func(int, string)`}},
		},
		{`package reverse2b; func f(func(int, string)) {}; func g[P, Q any](P, Q) {}; func _() { f(g) }`,
			[]testInst{{`g`, []string{`int`, `string`}, `func
"""




```