Response: My thinking process to analyze the Go code snippet and fulfill the user's request goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of the `api_test.go` file, particularly within the context of the `types2` package in the Go compiler. The request is broken down into specific aspects like general functionality, examples, command-line arguments (unlikely here), common mistakes, and a summary.

2. **Identify Key Packages and Types:** I scan the import statements to get a high-level understanding of the dependencies. The core is `. "cmd/compile/internal/types2"`, indicating this file tests the `types2` package. Other imports like `syntax`, `strings`, `testing`, etc., suggest parsing and testing functionalities.

3. **Analyze Helper Functions:** I examine the functions defined at the beginning:
    * `mustParse`:  Clearly parses Go source code into an AST (`syntax.File`).
    * `typecheck`: The central function for performing type checking using the `types2` package. It takes source code and a `Config`, and returns a `Package` and an error. It utilizes `mustParse`.
    * `mustTypecheck`: A wrapper around `typecheck` that panics on errors, simplifying test setup.
    * `pkgName`: Extracts the package name from the source code.

4. **Focus on Test Functions:** The functions starting with `Test` are the core of the file's functionality. I look for patterns and the types of tests being performed.

    * **`TestValuesInfo`:**  This test iterates through a series of Go code snippets (`src`) and expressions (`expr`). It performs type checking and then checks the `Type` and `Value` (if it's a constant) of the specified expression. The structure of the `tests` slice suggests this test focuses on verifying the correct type and value information is extracted for various constant and variable declarations.

    * **`TestTypesInfo`:**  Similar structure to `TestValuesInfo`, but this test appears to focus on verifying the *type* of various expressions, including those involving `nil`, comma-ok assignments, and generics. The presence of `brokenPkg` hints at tests for code that *should* fail type checking.

5. **Infer the Overall Purpose:** Based on the helper functions and the initial test functions, I can infer that this file is a suite of *unit tests* for the `types2` package. Its primary goal is to ensure that the type checker correctly identifies and stores type and value information for different Go language constructs.

6. **Address Specific Requirements:**

    * **Functionality Listing:**  I summarize the identified functionalities: parsing, type checking, and specifically testing the correctness of `Info.Types` and `Info.Values`.

    * **Go Language Feature (Inference):** The tests in `TestValuesInfo` and `TestTypesInfo` directly relate to the fundamental Go language feature of *type checking*. The `types2` package is the core implementation of this feature within the Go compiler.

    * **Go Code Example:** I choose a simple but illustrative example demonstrating how the `typecheck` function is used. I include input and expected output.

    * **Command-Line Arguments:**  I recognize that this is a unit test file and doesn't directly process command-line arguments in the typical sense. I state this explicitly.

    * **Common Mistakes:** I analyze the code for potential areas where users of the `types2` package (or those writing similar tests) might make mistakes. The use of `panic` in the helper functions and the need for correct `Config` setup are potential pitfalls.

    * **Summary:** I synthesize the findings into a concise summary of the file's purpose.

7. **Structure the Output:**  I organize the information clearly, using headings and bullet points to address each part of the user's request. I provide code examples with clear input and output sections.

8. **Review and Refine:** I reread my analysis to ensure accuracy, clarity, and completeness. I double-check that I have addressed all aspects of the user's prompt. For example, I initially might have just said "tests type checking," but refining it to "verifying the correctness of type and value information..." is more precise.

By following these steps, I can systematically analyze the Go code and provide a comprehensive and informative response to the user's request. The key is to start with a high-level understanding and then drill down into the details of the code, focusing on the test structure and the interactions with the `types2` package.
好的，让我们来分析一下 `go/src/cmd/compile/internal/types2/api_test.go` 这个文件的第一部分代码。

**功能归纳 (第1部分)**

这部分代码主要定义了一些辅助函数和第一个测试函数 `TestValuesInfo`，用于测试 `cmd/compile/internal/types2` 包中关于 **表达式的值和类型信息** 的提取和存储功能。

具体来说，它提供了以下功能：

1. **辅助函数:**
   - `mustParse(src string) *syntax.File`:  将 Go 源代码字符串解析成语法树 (`syntax.File`)，如果解析出错则抛出 panic。
   - `typecheck(src string, conf *Config, info *Info) (*Package, error)`:  对给定的 Go 源代码进行类型检查。它使用 `mustParse` 解析代码，并使用提供的 `Config` 和 `Info` 进行类型检查。`Info` 结构体用于收集类型检查过程中的各种信息，例如表达式的类型和值。
   - `mustTypecheck(src string, conf *Config, info *Info) *Package`:  `typecheck` 的一个封装，如果类型检查出错则抛出 panic。
   - `pkgName(src string) string`:  从 Go 源代码字符串中提取包名。

2. **测试函数 `TestValuesInfo(t *testing.T)`:**
   - 这个函数定义了一个测试用例切片 `tests`，每个测试用例包含：
     - `src`: 一段 Go 源代码字符串。
     - `expr`:  源代码中的一个表达式字符串。
     - `typ`:  期望该表达式的类型字符串。
     - `val`:  期望该表达式的值字符串 (仅对常量表达式有效)。
   - 函数遍历 `tests` 切片，对每个测试用例执行以下操作：
     - 使用 `mustTypecheck` 对 `src` 进行类型检查，并将结果信息存储在 `info` 变量中。
     - 在 `info.Types` 映射中查找与 `expr` 匹配的表达式。`info.Types` 是 `Info` 结构体的一个字段，用于存储表达式到 `TypeAndValue` 的映射。
     - 断言查找到的表达式的类型 (`tv.Type.String()`) 是否与期望的类型 (`test.typ`) 相符。
     - 如果表达式是常量 ( `tv.Value != nil`)，则断言其值 (`tv.Value.ExactString()`) 是否与期望的值 (`test.val`) 相符。

**它是什么go语言功能的实现 (推断)**

这部分代码是 `types2` 包中 **类型检查** 功能的一部分测试。具体来说，`TestValuesInfo` 重点测试了类型检查器在处理不同类型的表达式（包括常量和变量）时，能否正确地推断和记录其 **类型** 和 **值**。

**Go代码举例说明**

假设我们有以下测试用例：

```go
{`package example; const x = 10`, `x`, `untyped int`, `10`}
```

`TestValuesInfo` 函数会执行以下步骤：

1. **解析代码:** `mustParse("package example; const x = 10")` 将源代码解析成语法树。
2. **类型检查:** `mustTypecheck("package example; const x = 10", nil, &info)` 对代码进行类型检查。在类型检查过程中，`types2` 包会分析常量 `x` 的定义，并将其类型推断为 `untyped int`，值记录为 `10`。这些信息会存储在 `info.Defs` 中 (定义) 和 `info.Types` 中 (表达式的类型和值)。
3. **查找表达式:** 遍历 `info.Types`，找到键为表示 `x` 的 `syntax.Expr` 的条目。
4. **断言类型:** 检查 `info.Types[x的Expr].Type.String()` 是否等于 `"untyped int"`。
5. **断言值:** 检查 `info.Types[x的Expr].Value.ExactString()` 是否等于 `"10"`。

**假设的输入与输出**

**输入 (对于上述测试用例):**

```go
src  = `package example; const x = 10`
expr = `x`
typ  = `untyped int`
val  = `10`
```

**输出 (期望):**

测试通过，因为类型检查器能够正确地识别常量 `x` 的类型和值。

**涉及命令行参数的具体处理**

这部分代码是单元测试，通常不涉及直接的命令行参数处理。`go test` 命令会执行这些测试，但测试代码本身并没有解析或使用任何命令行参数。

**使用者易犯错的点**

在编写类似的测试时，使用者可能容易犯以下错误：

1. **期望类型或值不正确:**  对于复杂的表达式或类型转换，很容易弄错期望的类型或值。例如，对于隐式类型转换或常量运算，需要仔细推断结果。
2. **表达式字符串与实际代码不匹配:**  `TestValuesInfo` 通过字符串比较来查找表达式。如果 `expr` 字符串与源代码中的表达式在语法上不完全一致，则可能找不到对应的表达式信息。
3. **忽略 `untyped` 类型:**  Go 语言中有 `untyped` 的常量类型。在断言类型时，需要注意区分 `untyped int` 和 `int` 等。
4. **对非常量表达式断言 `val`:**  `val` 字段只对常量表达式有意义。对变量或其他非常量表达式断言 `val` 会导致测试失败或产生误导。

**示例说明使用者易犯错的点**

假设使用者错误地认为常量 `10` 的类型是 `int`，则测试用例会写成：

```go
{`package example; const x = 10`, `x`, `int`, `10`}
```

这将导致 `TestValuesInfo` 中的类型断言失败，因为实际的类型是 `untyped int`。

又或者，使用者在 `expr` 中使用了错误的语法：

```go
{`package example; const x = 10`, `x `, `untyped int`, `10`} // 注意 "x" 后面多了一个空格
```

这会导致在 `info.Types` 中找不到匹配的表达式，因为 `ExprString(e)` 返回的字符串不会包含尾部的空格。

希望以上分析能够帮助你理解 `go/src/cmd/compile/internal/types2/api_test.go` 文件第一部分的功能。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/api_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types2_test

import (
	"cmd/compile/internal/syntax"
	"errors"
	"fmt"
	"internal/goversion"
	"internal/testenv"
	"slices"
	"strings"
	"sync"
	"testing"

	. "cmd/compile/internal/types2"
)

// nopos indicates an unknown position
var nopos syntax.Pos

func mustParse(src string) *syntax.File {
	f, err := syntax.Parse(syntax.NewFileBase(pkgName(src)), strings.NewReader(src), nil, nil, 0)
	if err != nil {
		panic(err) // so we don't need to pass *testing.T
	}
	return f
}

func typecheck(src string, conf *Config, info *Info) (*Package, error) {
	f := mustParse(src)
	if conf == nil {
		conf = &Config{
			Error:    func(err error) {}, // collect all errors
			Importer: defaultImporter(),
		}
	}
	return conf.Check(f.PkgName.Value, []*syntax.File{f}, info)
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
			Types: make(map[syntax.Expr]TypeAndValue),
		}
		name := mustTypecheck(test.src, nil, &info).Name()

		// look for expression
		var expr syntax.Expr
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
	const brokenPkg = "package broken_"

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
		{`package n0; var _ *int = nil`, `nil`, `*int`},
		{`package n1; var _ func() = nil`, `nil`, `func()`},
		{`package n2; var _ []byte = nil`, `nil`, `[]byte`},
		{`package n3; var _ map[int]int = nil`, `nil`, `map[int]int`},
		{`package n4; var _ chan int = nil`, `nil`, `chan int`},
		{`package n5a; var _ interface{} = (*int)(nil)`, `nil`, `*int`},
		{`package n5b; var _ interface{m()} = nil`, `nil`, `interface{m()}`},
		{`package n6; import "unsafe"; var _ unsafe.Pointer = nil`, `nil`, `unsafe.Pointer`},

		{`package n10; var (x *int; _ = x == nil)`, `nil`, `*int`},
		{`package n11; var (x func(); _ = x == nil)`, `nil`, `func()`},
		{`package n12; var (x []byte; _ = x == nil)`, `nil`, `[]byte`},
		{`package n13; var (x map[int]int; _ = x == nil)`, `nil`, `map[int]int`},
		{`package n14; var (x chan int; _ = x == nil)`, `nil`, `chan int`},
		{`package n15a; var (x interface{}; _ = x == (*int)(nil))`, `nil`, `*int`},
		{`package n15b; var (x interface{m()}; _ = x == nil)`, `nil`, `interface{m()}`},
		{`package n15; import "unsafe"; var (x unsafe.Pointer; _ = x == nil)`, `nil`, `unsafe.Pointer`},

		{`package n20; var _ = (*int)(nil)`, `nil`, `*int`},
		{`package n21; var _ = (func())(nil)`, `nil`, `func()`},
		{`package n22; var _ = ([]byte)(nil)`, `nil`, `[]byte`},
		{`package n23; var _ = (map[int]int)(nil)`, `nil`, `map[int]int`},
		{`package n24; var _ = (chan int)(nil)`, `nil`, `chan int`},
		{`package n25a; var _ = (interface{})((*int)(nil))`, `nil`, `*int`},
		{`package n25b; var _ = (interface{m()})(nil)`, `nil`, `interface{m()}`},
		{`package n26; import "unsafe"; var _ = unsafe.Pointer(nil)`, `nil`, `unsafe.Pointer`},

		{`package n30; func f(*int) { f(nil) }`, `nil`, `*int`},
		{`package n31; func f(func()) { f(nil) }`, `nil`, `func()`},
		{`package n32; func f([]byte) { f(nil) }`, `nil`, `[]byte`},
		{`package n33; func f(map[int]int) { f(nil) }`, `nil`, `map[int]int`},
		{`package n34; func f(chan int) { f(nil) }`, `nil`, `chan int`},
		{`package n35a; func f(interface{}) { f((*int)(nil)) }`, `nil`, `*int`},
		{`package n35b; func f(interface{m()}) { f(nil) }`, `nil`, `interface{m()}`},
		{`package n35; import "unsafe"; func f(unsafe.Pointer) { f(nil) }`, `nil`, `unsafe.Pointer`},

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
		{brokenPkg + `x0; func _() { var x struct {f string}; x.f := 0 }`, `x.f`, `string`},
		{brokenPkg + `x1; func _() { var z string; type x struct {f string}; y := &x{q: z}}`, `z`, `string`},
		{brokenPkg + `x2; func _() { var a, b string; type x struct {f string}; z := &x{f: a, f: b,}}`, `b`, `string`},
		{brokenPkg + `x3; var x = panic("");`, `panic`, `func(interface{})`},
		{`package x4; func _() { panic("") }`, `panic`, `func(interface{})`},
		{brokenPkg + `x5; func _() { var x map[string][...]int; x = map[string][...]int{"": {1,2,3}} }`, `x`, `map[string]invalid type`},

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
		{brokenPkg + `t4; type t[P, Q interface{ m() }] int; var _ t[int, int]`, `t`, `broken_t4.t[P, Q interface{m()}]`},

		// instantiated types must be sanitized
		{`package g0; type t[P any] int; var x struct{ f t[int] }; var _ = x.f`, `x.f`, `g0.t[int]`},

		// go.dev/issue/45096
		{`package issue45096; func _[T interface{ ~int8 | ~int16 | ~int32 }](x T) { _ = x < 0 }`, `0`, `T`},

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
		// (note that the syntax parser doesn't record unnecessary parentheses
		// around types, tests that fail because of that are commented out below)
		// - as variable type, not generic
		{`package qa1; type T int; var x T`, `T`, `qa1.T`},
		{`package qa2; type T int; var x (T)`, `T`, `qa2.T`},
		// {`package qa3; type T int; var x (T)`, `(T)`, `qa3.T`}, // parser doesn't record parens
		{`package qa4; type T int; var x ((T))`, `T`, `qa4.T`},
		// {`package qa5; type T int; var x ((T))`, `(T)`, `qa5.T`}, // parser doesn't record parens
		// {`package qa6; type T int; var x ((T))`, `((T))`, `qa6.T`}, // parser doesn't record parens
		{`package qa7; type T int; var x *T`, `T`, `qa7.T`},
		{`package qa8; type T int; var x *T`, `*T`, `*qa8.T`},
		{`package qa9; type T int; var x (*T)`, `T`, `qa9.T`},
		{`package qa10; type T int; var x (*T)`, `*T`, `*qa10.T`},
		{`package qa11; type T int; var x *(T)`, `T`, `qa11.T`},
		// {`package qa12; type T int; var x *(T)`, `(T)`, `qa12.T`}, // parser doesn't record parens
		// {`package qa13; type T int; var x *(T)`, `*(T)`, `*qa13.T`}, // parser doesn't record parens
		// {`package qa14; type T int; var x (*(T))`, `(T)`, `qa14.T`}, // parser doesn't record parens
		// {`package qa15; type T int; var x (*(T))`, `*(T)`, `*qa15.T`}, // parser doesn't record parens
		// {`package qa16; type T int; var x (*(T))`, `(*(T))`, `*qa16.T`}, // parser doesn't record parens

		// - as ordinary function parameter, not generic
		{`package qb1; type T int; func _(T)`, `T`, `qb1.T`},
		{`package qb2; type T int; func _((T))`, `T`, `qb2.T`},
		// {`package qb3; type T int; func _((T))`, `(T)`, `qb3.T`}, // parser doesn't record parens
		{`package qb4; type T int; func _(((T)))`, `T`, `qb4.T`},
		// {`package qb5; type T int; func _(((T)))`, `(T)`, `qb5.T`}, // parser doesn't record parens
		// {`package qb6; type T int; func _(((T)))`, `((T))`, `qb6.T`}, // parser doesn't record parens
		{`package qb7; type T int; func _(*T)`, `T`, `qb7.T`},
		{`package qb8; type T int; func _(*T)`, `*T`, `*qb8.T`},
		{`package qb9; type T int; func _((*T))`, `T`, `qb9.T`},
		{`package qb10; type T int; func _((*T))`, `*T`, `*qb10.T`},
		{`package qb11; type T int; func _(*(T))`, `T`, `qb11.T`},
		// {`package qb12; type T int; func _(*(T))`, `(T)`, `qb12.T`}, // parser doesn't record parens
		// {`package qb13; type T int; func _(*(T))`, `*(T)`, `*qb13.T`}, // parser doesn't record parens
		// {`package qb14; type T int; func _((*(T)))`, `(T)`, `qb14.T`}, // parser doesn't record parens
		// {`package qb15; type T int; func _((*(T)))`, `*(T)`, `*qb15.T`}, // parser doesn't record parens
		// {`package qb16; type T int; func _((*(T)))`, `(*(T))`, `*qb16.T`}, // parser doesn't record parens

		// - as method receiver, not generic
		{`package qc1; type T int; func (T) _() {}`, `T`, `qc1.T`},
		{`package qc2; type T int; func ((T)) _() {}`, `T`, `qc2.T`},
		// {`package qc3; type T int; func ((T)) _() {}`, `(T)`, `qc3.T`}, // parser doesn't record parens
		{`package qc4; type T int; func (((T))) _() {}`, `T`, `qc4.T`},
		// {`package qc5; type T int; func (((T))) _() {}`, `(T)`, `qc5.T`}, // parser doesn't record parens
		// {`package qc6; type T int; func (((T))) _() {}`, `((T))`, `qc6.T`}, // parser doesn't record parens
		{`package qc7; type T int; func (*T) _() {}`, `T`, `qc7.T`},
		{`package qc8; type T int; func (*T) _() {}`, `*T`, `*qc8.T`},
		{`package qc9; type T int; func ((*T)) _() {}`, `T`, `qc9.T`},
		{`package qc10; type T int; func ((*T)) _() {}`, `*T`, `*qc10.T`},
		{`package qc11; type T int; func (*(T)) _() {}`, `T`, `qc11.T`},
		// {`package qc12; type T int; func (*(T)) _() {}`, `(T)`, `qc12.T`}, // parser doesn't record parens
		// {`package qc13; type T int; func (*(T)) _() {}`, `*(T)`, `*qc13.T`}, // parser doesn't record parens
		// {`package qc14; type T int; func ((*(T))) _() {}`, `(T)`, `qc14.T`}, // parser doesn't record parens
		// {`package qc15; type T int; func ((*(T))) _() {}`, `*(T)`, `*qc15.T`}, // parser doesn't record parens
		// {`package qc16; type T int; func ((*(T))) _() {}`, `(*(T))`, `*qc16.T`}, // parser doesn't record parens

		// - as variable type, generic
		{`package qd1; type T[_ any] int; var x T[int]`, `T`, `qd1.T[_ any]`},
		{`package qd2; type T[_ any] int; var x (T[int])`, `T[int]`, `qd2.T[int]`},
		// {`package qd3; type T[_ any] int; var x (T[int])`, `(T[int])`, `qd3.T[int]`}, // parser doesn't record parens
		{`package qd4; type T[_ any] int; var x ((T[int]))`, `T`, `qd4.T[_ any]`},
		// {`package qd5; type T[_ any] int; var x ((T[int]))`, `(T[int])`, `qd5.T[int]`}, // parser doesn't record parens
		// {`package qd6; type T[_ any] int; var x ((T[int]))`, `((T[int]))`, `qd6.T[int]`}, // parser doesn't record parens
		{`package qd7; type T[_ any] int; var x *T[int]`, `T`, `qd7.T[_ any]`},
		{`package qd8; type T[_ any] int; var x *T[int]`, `*T[int]`, `*qd8.T[int]`},
		{`package qd9; type T[_ any] int; var x (*T[int])`, `T`, `qd9.T[_ any]`},
		{`package qd10; type T[_ any] int; var x (*T[int])`, `*T[int]`, `*qd10.T[int]`},
		{`package qd11; type T[_ any] int; var x *(T[int])`, `T[int]`, `qd11.T[int]`},
		// {`package qd12; type T[_ any] int; var x *(T[int])`, `(T[int])`, `qd12.T[int]`}, // parser doesn't record parens
		// {`package qd13; type T[_ any] int; var x *(T[int])`, `*(T[int])`, `*qd13.T[int]`}, // parser doesn't record parens
		// {`package qd14; type T[_ any] int; var x (*(T[int]))`, `(T[int])`, `qd14.T[int]`}, // parser doesn't record parens
		// {`package qd15; type T[_ any] int; var x (*(T[int]))`, `*(T[int])`, `*qd15.T[int]`}, // parser doesn't record parens
		// {`package qd16; type T[_ any] int; var x (*(T[int]))`, `(*(T[int]))`, `*qd16.T[int]`}, // parser doesn't record parens

		// - as ordinary function parameter, generic
		{`package qe1; type T[_ any] int; func _(T[int])`, `T`, `qe1.T[_ any]`},
		{`package qe2; type T[_ any] int; func _((T[int]))`, `T[int]`, `qe2.T[int]`},
		// {`package qe3; type T[_ any] int; func _((T[int]))`, `(T[int])`, `qe3.T[int]`}, // parser doesn't record parens
		{`package qe4; type T[_ any] int; func _(((T[int])))`, `T`, `qe4.T[_ any]`},
		// {`package qe5; type T[_ any] int; func _(((T[int])))`, `(T[int])`, `qe5.T[int]`}, // parser doesn't record parens
		// {`package qe6; type T[_ any] int; func _(((T[int])))`, `((T[int]))`, `qe6.T[int]`}, // parser doesn't record parens
		{`package qe7; type T[_ any] int; func _(*T[int])`, `T`, `qe7.T[_ any]`},
		{`package qe8; type T[_ any] int; func _(*T[int])`, `*T[int]`, `*qe8.T[int]`},
		{`package qe9; type T[_ any] int; func _((*T[int]))`, `T`, `qe9.T[_ any]`},
		{`package qe10; type T[_ any] int; func _((*T[int]))`, `*T[int]`, `*qe10.T[int]`},
		{`package qe11; type T[_ any] int; func _(*(T[int]))`, `T[int]`, `qe11.T[int]`},
		// {`package qe12; type T[_ any] int; func _(*(T[int]))`, `(T[int])`, `qe12.T[int]`}, // parser doesn't record parens
		// {`package qe13; type T[_ any] int; func _(*(T[int]))`, `*(T[int])`, `*qe13.T[int]`}, // parser doesn't record parens
		// {`package qe14; type T[_ any] int; func _((*(T[int])))`, `(T[int])`, `qe14.T[int]`}, // parser doesn't record parens
		// {`package qe15; type T[_ any] int; func _((*(T[int])))`, `*(T[int])`, `*qe15.T[int]`}, // parser doesn't record parens
		// {`package qe16; type T[_ any] int; func _((*(T[int])))`, `(*(T[int]))`, `*qe16.T[int]`}, // parser doesn't record parens

		// - as method receiver, generic
		{`package qf1; type T[_ any] int; func (T[_]) _() {}`, `T`, `qf1.T[_ any]`},
		{`package qf2; type T[_ any] int; func ((T[_])) _() {}`, `T[_]`, `qf2.T[_]`},
		// {`package qf3; type T[_ any] int; func ((T[_])) _() {}`, `(T[_])`, `qf3.T[_]`}, // parser doesn't record parens
		{`package qf4; type T[_ any] int; func (((T[_]))) _() {}`, `T`, `qf4.T[_ any]`},
		// {`package qf5; type T[_ any] int; func (((T[_]))) _() {}`, `(T[_])`, `qf5.T[_]`}, // parser doesn't record parens
		// {`package qf6; type T[_ any] int; func (((T[_]))) _() {}`, `((T[_]))`, `qf6.T[_]`}, // parser doesn't record parens
		{`package qf7; type T[_ any] int; func (*T[_]) _() {}`, `T`, `qf7.T[_ any]`},
		{`package qf8; type T[_ any] int; func (*T[_]) _() {}`, `*T[_]`, `*qf8.T[_]`},
		{`package qf9; type T[_ any] int; func ((*T[_])) _() {}`, `T`, `qf9.T[_ any]`},
		{`package qf10; type T[_ any] int; func ((*T[_])) _() {}`, `*T[_]`, `*qf10.T[_]`},
		{`package qf11; type T[_ any] int; func (*(T[_])) _() {}`, `T[_]`, `qf11.T[_]`},
		// {`package qf12; type T[_ any] int; func (*(T[_])) _() {}`, `(T[_])`, `qf12.T[_]`}, // parser doesn't record parens
		// {`package qf13; type T[_ any] int; func (*(T[_])) _() {}`, `*(T[_])`, `*qf13.T[_]`}, // parser doesn't record parens
		// {`package qf14; type T[_ any] int; func ((*(T[_]))) _() {}`, `(T[_])`, `qf14.T[_]`}, // parser doesn't record parens
		// {`package qf15; type T[_ any] int; func ((*(T[_]))) _() {}`, `*(T[_])`, `*qf15.T[_]`}, // parser doesn't record parens
		// {`package qf16; type T[_ any] int; func ((*(T[_]))) _() {}`, `(*(T[_]))`, `*qf16.T[_]`}, // parser doesn't record parens

		// For historic reasons, type parameters in receiver type expressions
		// are considered both definitions and uses and thus also show up in
		// the Info.Types map (see go.dev/issue/68670).
		{`package t1; type T[_ any] int; func (T[P]) _() {}`, `P`, `P`},
		{`package t2; type T[_, _ any] int; func (T[P, Q]) _() {}`, `P`, `P`},
		{`package t3; type T[_, _ any] int; func (T[P, Q]) _() {}`, `Q`, `Q`},
	}

	for _, test := range tests {
		info := Info{Types: make(map[syntax.Expr]TypeAndValue)}
		var name string
		if strings.HasPrefix(test.src, brokenPkg) {
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
			[]testInst{{`g`, []string{`int`, `string`}, `func(int, string)`}},
		},
		{`package reverse2c; func f(func(int, string)) {}; func g[P, Q any](P, Q) {}; func _() { f(g[int]) }`,
			[]testInst{{`g`, []string{`int`, `string`}, `func(int, string)`}},
		},
		// reverse3a not possible (cannot assign to generic function outside of argument passing)
		{`package reverse3b; func f[R any](func(int) R) {}; func g[P any](P) string { return "" }; func _() { f(g) }`,
			[]testInst{
				{`f`, []string{`string`}, `func(func(int) string)`},
				{`g`, []string{`int`}, `func(int) string`},
			},
		},
		{`package reverse4a; var _, _ func([]int, *float32) = g, h; func g[P, Q any]([]P, *Q) {}; func h[R any]([]R, *float32) {}`,
			[]testInst{
				{`g`, []string{`int`, `float32`}, `func([]int, *float32)`},
				{`h`, []string{`int`}, `func([]int, *float32)`},
			},
		},
		{`package reverse4b; func f(_, _ func([]int, *float32)) {}; func g[P, Q any]([]P, *Q) {}; func h[R any]([]R, *float32) {}; func _() { f(g, h) }`,
			[]testInst{
				{`g`, []string{`int`, `float32`}, `func([]int, *float32)`},
				{`h`, []string{`int`}, `func([]int, *float32)`},
			},
		},
		{`package issue59956; func f(func(int), func(string), func(bool)) {}; func g[P any](P) {}; func _() { f(g, g, g) }`,
			[]testInst{
				{`g`, []string{`int`}, `func(int)`},
				{`g`, []string{`string`}, `func(string)`},
				{`g`, []string{`bool`}, `func(bool)`},
			},
		},
	}

	for _, test := range tests {
		imports := make(testImporter)
		conf := Config{Importer: imports}
		instMap := make(map[*syntax.Name]Instance)
		useMap := make(map[*syntax.Name]Object)
		makePkg := func(src string) *Package {
			pkg, err := typecheck(src, &conf, &Info{Instances: instMap, Uses: useMap})
			// allow error for issue51803
			if err != nil && (pkg == nil || pkg.Name() != "issue51803") {
				t.Fatal(err)
			}
			imports[pkg.Name()] = pkg
			return pkg
		}
		makePkg(lib)
		pkg := makePkg(test.src)

		t.Run(pkg.Name(), func(t *testing.T) {
			// Sort instances in source order for stability.
			instances := sortedInstances(instMap)
			if got, want := len(instances), len(test.instances); got != want {
				t.Fatalf("got %d instances, want %d", got, want)
			}

			// Pairwise compare with the expected instances.
			for ii, inst := range instances {
				var targs []Type
				for i := 0; i < inst.Inst.TypeArgs.Len(); i++ {
					targs = append(targs, inst.Inst.TypeArgs.At(i))
				}
				typ := inst.Inst.Type

				testInst := test.instances[ii]
				if got := inst.Name.Value; got != testInst.name {
					t.Fatalf("got name %s, want %s", got, testInst.name)
				}

				if len(targs) != len(testInst.targs) {
					t.Fatalf("got %d type arguments; want %d", len(targs), len(testInst.targs))
				}
				for i, targ := range targs {
					if got := targ.String(); got != testInst.targs[i] {
						t.Errorf("type argument %d: got %s; want %s", i, got, testInst.targs[i])
					}
				}
				if got := typ.Underlying().String(); got != testInst.typ {
					t.Errorf("package %s: got %s; want %s", pkg.Name(), got, testInst.typ)
				}

				// Verify the invariant that re-instantiating the corresponding generic
				// type with TypeArgs results in an identical instance.
				ptype := useMap[inst.Name].Type()
				lister, _ := ptype.(interface{ TypeParams() *TypeParamList })
				if lister == nil || lister.TypeParams().Len() == 0 {
					t.Fatalf("info.Types[%v] = %v, want parameterized type", inst.Name, ptype)
				}
				inst2, err := Instantiate(nil, ptype, targs, true)
				if err != nil {
					t.Errorf("Instantiate(%v, %v) failed: %v", ptype, targs, err)
				}
				if !Identical(inst.Inst.Type, inst2) {
					t.Errorf("%v and %v are not identical", inst.Inst.Type, inst2)
				}
			}
		})
	}
}

type recordedInstance struct {
	Name *syntax.Name
	Inst Instance
}

func sortedInstances(m map[*syntax.Name]Instance) (instances []recordedInstance) {
	for id, inst := range m {
		instances = append(instances, recordedInstance{id, inst})
	}
	slices.SortFunc(instances, func(a, b recordedInstance) int {
		return CmpPos(a.Name.Pos(), b.Name.Pos())
	})
	return instances
}

func TestDefsInfo(t *testing.T) {
	var tests = []struct {
		src  string
		obj  string
		want string
	}{
		{`package p0; const x = 42`, `x`, `const p0.x untyped int`},
		{`package p1; const x int = 42`, `x`, `const p1.x int`},
		{`package p2; var x int`, `x`, `var p2.x int`},
		{`package p3; type x int`, `x`, `type p3.x int`},
		{`package p4; func f()`, `f`, `func p4.f()`},
		{`package p5; func f() int { x, _ := 1, 2; return x }`, `_`, `var _ int`},

		// Tests using generics.
		{`package g0; type x[T any] int`, `x`, `type g0.x[T any] int`},
		{`package g1; func f[T any]() {}`, `f`, `func g1.f[T any]()`},
		{`package g2; type x[T any] int; func (*x[_]) m() {}`, `m`, `func (*g2.x[_]).m()`},

		// Type parameters in receiver type expressions are definitions.
		{`package r0; type T[_ any] int; func (T[P]) _() {}`, `P`, `type parameter P any`},
		{`package r1; type T[_, _ any] int; func (T[P, Q]) _() {}`, `P`, `type parameter P any`},
		{`package r2; type T[_, _ any] int; func (T[P, Q]) _() {}`, `Q`, `type parameter Q any`},
	}

	for _, test := range tests {
		info := Info{
			Defs: make(map[*syntax.Name]Object),
		}
		name := mustTypecheck(test.src, nil, &info).Name()

		// find object
		var def Object
		for id, obj := range info.Defs {
			if id.Value == test.obj {
				def = obj
				break
			}
		}
		if def == nil {
			t.Errorf("package %s: %s not found", name, test.obj)
			continue
		}

		if got := def.String(); got != test.want {
			t.Errorf("package %s: got %s; want %s", name, got, test.want)
		}
	}
}

func TestUsesInfo(t *testing.T) {
	var tests = []struct {
		src  string
		obj  string
		want string
	}{
		{`package p0; func _() { _ = x }; const x = 42`, `x`, `const p0.x untyped int`},
		{`package p1; func _() { _ = x }; const x int = 42`, `x`, `const p1.x int`},
		{`package p2; func _() { _ = x }; var x int`, `x`, `var p2.x int`},
		{`package p3; func _() { type _ x }; type x int`, `x`, `type p3.x int`},
		{`package p4; func _() { _ = f }; func f()`, `f`, `func p4.f()`},

		// Tests using generics.
		{`package g0; func _[T any]() { _ = x }; const x = 42`, `x`, `const g0.x untyped int`},
		{`package g1; func _[T any](x T) { }`, `T`, `type parameter T any`},
		{`package g2; type N[A any] int; var _ N[int]`, `N`, `type g2.N[A any] int`},
		{`package g3; type N[A any] int; func (N[_]) m() {}`, `N`, `type g3.N[A any] int`},

		// Uses of fields are instantiated.
		{`package s1; type N[A any] struct{ a A }; var f = N[int]{}.a`, `a`, `field a int`},
		{`package s2; type N[A any] struct{ a A }; func (r N[B]) m(b B) { r.a = b }`, `a`, `field a B`},

		// Uses of methods are uses of the instantiated method.
		{`package m0; type N[A any] int; func (r N[B]) m() { r.n() }; func (N[C]) n() {}`, `n`, `func (m0.N[B]).n()`},
		{`package m1; type N[A any] int; func (r N[B]) m() { }; var f = N[int].m`, `m`, `func (m1.N[int]).m()`},
		{`package m2; func _[A any](v interface{ m() A }) { v.m() }`, `m`, `func (interface).m() A`},
		{`package m3; func f[A any]() interface{ m() A } { return nil }; var _ = f[int]().m()`, `m`, `func (interface).m() int`},
		{`package m4; type T[A any] func() interface{ m() A }; var x T[int]; var y = x().m`, `m`, `func (interface).m() int`},
		{`package m5; type T[A any] interface{ m() A }; func _[B any](t T[B]) { t.m() }`, `m`, `func (m5.T[B]).m() B`},
		{`package m6; type T[A any] interface{ m() }; func _[B any](t T[B]) { t.m() }`, `m`, `func (m6.T[B]).m()`},
		{`package m7; type T[A any] interface{ m() A }; func _(t T[int]) { t.m() }`, `m`, `func (m7.T[int]).m() int`},
		{`package m8; type T[A any] interface{ m() }; func _(t T[int]) { t.m() }`, `m`, `func (m8.T[int]).m()`},
		{`package m9; type T[A any] interface{ m() }; func _(t T[int]) { _ = t.m }`, `m`, `func (m9.T[int]).m()`},
		{
			`package m10; type E[A any] interface{ m() }; type T[B any] interface{ E[B]; n() }; func _(t T[int]) { t.m() }`,
			`m`,
			`func (m10.E[int]).m()`,
		},

		// For historic reasons, type parameters in receiver type expressions
		// are considered both definitions and uses (see go.dev/issue/68670).
		{`package r0; type T[_ any] int; func (T[P]) _() {}`, `P`, `type parameter P any`},
		{`package r1; type T[_, _ any] int; func (T[P, Q]) _() {}`, `P`, `type parameter P any`},
		{`package r2; type T[_, _ any] int; func (T[P, Q]) _() {}`, `Q`, `type parameter Q any`},
	}

	for _, test := range tests {
		info := Info{
			Uses: make(map[*syntax.Name]Object),
		}
		name := mustTypecheck(test.src, nil, &info).Name()

		// find object
		var use Object
		for id, obj := range info.Uses {
			if id.Value == test.obj {
				if use != nil {
					panic(fmt.Sprintf("multiple uses of %q", id.Value))
				}
				use = obj
			}
		}
		if use == nil {
			t.Errorf("package %s: %s not found", name, test.obj)
			continue
		}

		if got := use.String(); got != test.want {
			t.Errorf("package %s: got %s; want %s", name, got, test.want)
		}
	}
}

func TestGenericMethodInfo(t *testing.T) {
	src := `package p

type N[A any] int

func (r N[B]) m() { r.m(); r.n() }

func (r *N[C]) n() {  }
`
	f := mustParse(src)
	info := Info{
		Defs:       make(map[*syntax.Name]Object),
		Uses:       make(map[*syntax.Name]Object),
		Selections: make(map[*syntax.SelectorExpr]*Selection),
	}
	var conf Config
	pkg, err := conf.Check("p", []*syntax.File{f}, &info)
	if err != nil {
		t.Fatal(err)
	}

	N := pkg.Scope().Lookup("N").Type().(*Named)

	// Find the generic methods stored on N.
	gm, gn := N.Method(0), N.Method(1)
	if gm.Name() == "n" {
		gm, gn = gn, gm
	}

	// Collect objects from info.
	var dm, dn *Func   // the declared methods
	var dmm, dmn *Func // the methods used in the body of m
	for _, decl := range f.DeclList {
		fdecl, ok := decl.(*syntax.FuncDecl)
		if !ok {
			continue
		}
		def := info.Defs[fdecl.Name].(*Func)
		switch fdecl.Name.Value {
		case "m":
			dm = def
			syntax.Inspect(fdecl.Body, func(n syntax.Node) bool {
				if call, ok := n.(*syntax.CallExpr); ok {
					sel := call.Fun.(*syntax.SelectorExpr)
					use := info.Uses[sel.Sel].(*Func)
					selection := info.Selections[sel]
					if selection.Kind() != MethodVal {
						t.Errorf("Selection kind = %v, want %v", selection.Kind(), MethodVal)
					}
					if selection.Obj() != use {
						t.Errorf("info.Selections contains %v, want %v", selection.Obj(), use)
					}
					switch sel.Sel.Value {
					case "m":
						dmm = use
					case "n":
						dmn = use
					}
				}
				return true
			})
		case "n":
			dn = def
		}
	}

	if gm != dm {
		t.Errorf(`N.Method(...) returns %v for "m", but Info.Defs has %v`, gm, dm)
	}
	if gn != dn {
		t.Errorf(`N.Method(...) returns %v for "m", but Info.Defs has %v`, gm, dm)
	}
	if dmm != dm {
		t.Errorf(`Inside "m", r.m uses %v, want the defined func %v`, dmm, dm)
	}
	if dmn == dn {
		t.Errorf(`Inside "m", r.n uses %v, want a func distinct from %v`, dmm, dm)
	}
}

func TestImplicitsInfo(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	var tests = []struct {
		src  string
		want string
	}{
		{`package p2; import . "fmt"; var _ = Println`, ""},           // no Implicits entry
		{`package p0; import local "fmt"; var _ = local.Println`, ""}, // no Implicits entry
		{`package p1; import "fmt"; var _ = fmt.Println`, "importSpec: package fmt"},

		{`package p3; func f(x interface{}) { switch x.(type) { case int: } }`, ""}, // no Implicits entry
		{`package p4; func f(x interface{}) { switch t := x.(type) { case int: _ = t } }`, "caseClause: var t int"},
		{`package p5; func f(x interface{}) { switch t := x.(type) { case int, uint: _ = t } }`, "caseClause: var t interface{}"},
		{`package p6; func f(x interface{}) { switch t := x.(type) { default: _ = t } }`, "caseClause: var t interface{}"},

		{`package p7; func f(x int) {}`, ""}, // no Implicits entry
		{`package p8; func f(int) {}`, "field: var  int"},
		{`package p9; func f() (complex64) { return 0 }`, "field: var  complex64"},
		{`package p10; type T struct{}; func (*T) f() {}`, "field: var  *p10.T"},

		// Tests using generics.
		{`package f0; func f[T any](x int) {}`, ""}, // no Implicits entry
		{`package f1; func f[T any](int) {}`, "field: var  int"},
		{`package f2; func f[T any](T) {}`, "field: var  T"},
		{`package f3; func f[T any]() (complex64) { return 0 }`, "field: var  complex64"},
		{`package f4; func f[T any](t T) (T) { return t }`, "field: var  T"},
		{`package t0; type T[A any] struct{}; func (*T[_]) f() {}`, "field: var  *t0.T[_]"},
		{`package t1; type T[A any] struct{}; func _(x interface{}) { switch t := x.(type) { case T[int]: _ = t } }`, "caseClause: var t t1.T[int]"},
		{`package t2; type T[A any] struct{}; func _[P any](x interface{}) { switch t := x.(type) { case T[P]: _ = t } }`, "caseClause: var t t2.T[P]"},
		{`package t3; func _[P any](x interface{}) { switch t := x.(type) { case P: _ = t } }`, "caseClause: var t P"},
	}

	for _, test := range tests {
		info := Info{
			Implicits: make(map[syntax.Node]Object),
		}
		name := mustTypecheck(test.src, nil, &info).Name()

		// the test cases expect at most one Implicits entry
		if len(info.Implicits) > 1 {
			t.Errorf("package %s: %d Implicits entries found", name, len(info.Implicits))
			continue
		}

		// extract Implicits entry, if any
		var got string
		for n, obj := range info.Implicits {
			switch x := n.(type) {
			case *syntax.ImportDecl:
				got = "importSpec"
			case *syntax.CaseClause:
				got = "caseClause"
			case *syntax.Field:
				got = "field"
			default:
				t.Fatalf("package %s: unexpected %T", name, x)
			}
			got += ": " + obj.String()
		}

		// verify entry
		if got != test.want {
			t.Errorf("package %s: got %q; want %q", name, got, test.want)
		}
	}
}

func TestPkgNameOf(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	const src = `
package p

import (
	. "os"
	_ "io"
	"math"
	"path/filepath"
	snort "sort"
)

// avoid imported and not used errors
var (
	_ = Open // os.Open
	_ = math.Sin
	_ = filepath.Abs
	_ = snort.Ints
)
`

	var tests = []struct {
		path string // path string enclosed in "'s
		want string
	}{
		{`"os"`, "."},
		{`"io"`, "_"},
		{`"math"`, "math"},
		{`"path/filepath"`, "filepath"},
		{`"sort"`, "snort"},
	}

	f := mustParse(src)
	info := Info{
		Defs:      make(map[*syntax.Name]Object),
		Implicits: make(map[syntax.Node]Object),
	}
	var conf Config
	conf.Importer = defaultImporter()
	_, err := conf.Check("p", []*syntax.File{f}, &info)
	if err != nil {
		t.Fatal(err)
	}

	// map import paths to importDecl
	imports := make(map[string]*syntax.ImportDecl)
	for _, d := range f.DeclList {
		if imp, _ := d.(*syntax.ImportDecl); imp != nil {
			imports[imp.Path.Value] = imp
		}
	}

	for _, test := range tests {
		imp := imports[test.path]
		if imp == nil {
			t.Fatalf("invalid test case: import path %s not found", test.path)
		}
		got := info.PkgNameOf(imp)
		if got == nil {
			t.Fatalf("import %s: package name not found", test.path)
		}
		if got.Name() != test.want {
			t.Errorf("import %s: got %s; want %s", test.path, got.Name(), test.want)
		}
	}

	// test non-existing importDecl
	if got := info.PkgNameOf(new(syntax.ImportDecl)); got != nil {
		t.Errorf("got %s for non-existing import declaration", got.Name())
	}
}

func predString(tv TypeAndValue) string {
	var buf strings.Builder
	pred := func(b bool, s string) {
		if b {
			if buf.Len() > 0 {
				buf.WriteString(", ")
			}
			buf.WriteString(s)
		}
	}

	pred(tv.IsVoid(), "void")
	pred(tv.IsType(), "type")
	pred(tv.IsBuiltin(), "builtin")
	pred(tv.IsValue() && tv.Value != nil, "const")
	pred(tv.IsValue() && tv.Value == nil, "value")
	pred(tv.IsNil(), "nil")
	pred(tv.Addressable(), "addressable")
	pred(tv.Assignable(), "assignable")
	pred(tv.HasOk(), "hasOk")

	if buf.Len() == 0 {
		return "invalid"
	}
	return buf.String()
}

func TestPredicatesInfo(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	var tests = []struct {
		src  string
		expr string
		pred string
	}{
		// void
		{`package n0; func f() { f() }`, `f()`, `void`},

		// types
		{`package t0; type _ int`, `int`, `type`},
		{`package t1; type _ []int`, `[]int`, `type`},
		{`package t2; type _ func()`, `func()`, `type`},
		{`package t3; type _ func(int)`, `int`, `type`},
		{`package t3; type _ func(...int)`, `...int`, `type`},

		// built-ins
		{`package b0; var _ = len("")`, `len`, `builtin`},
		{`package b1; var _ = (len)("")`, `(len)`, `builtin`},

		// constants
		{`package c0; var _ = 42`, `42`, `const`},
		{`package c1; var _ = "foo" + "bar"`, `"foo" + "bar"`, `const`},
		{`package c2; const (i = 1i; _ = i)`, `i`, `const`},

		// values
		{`package v0; var (a, b int; _ = a + b)`, `a + b`, `value`},
		{`package v1; var _ = &[]int{1}`, `[]int{…}`, `value`},
		{`package v2; var _ = func(){}`, `func() {}`, `value`},
		{`package v4; func f() { _ = f }`, `f`, `value`},
		{`package v3; var _ *int = nil`, `nil`, `value, nil`},
		{`package v3; var _ *int = (nil)`, `(nil)`, `value, nil`},

		// addressable (and thus assignable) operands
		{`package a0; var (x int; _ = x)`, `x`, `value, addressable, assignable`},
		{`package a1; var (p *int; _ = *p)`, `*p`, `value, addressable, assignable`},
		{`package a2; var (s []int; _ = s[0])`, `s[0]`, `value, addressable, assignable`},
		{`package a3; var (s struct{f int}; _ = s.f)`, `s.f`, `value, addressable, assignable`},
		{`package a4; var (a [10]int; _ = a[0])`, `a[0]`, `value, addressable, assignable`},
		{`package a5; func _(x int) { _ = x }`, `x`, `value, addressable, assignable`},
		{`package a6; func _()(x int) { _ = x; return }`, `x`, `value, addressable, assignable`},
		{`package a7; type T int; func (x T) _() { _ = x }`, `x`, `value, addressable, assignable`},
		// composite literals are not addressable

		// assignable but not addressable values
		{`package s0; var (m map[int]int; _ = m[0])`, `m[0]`, `value, assignable, hasOk`},
		{`package s1; var (m map[int]int; _, _ = m[0])`, `m[0]`, `value, assignable, hasOk`},

		// hasOk expressions
		{`package k0; var (ch chan int; _ = <-ch)`, `<-ch`, `value, hasOk`},
		{`package k1; var (ch chan int; _, _ = <-ch)`, `<-ch`, `value, hasOk`},

		// missing entries
		// - package names are collected in the Uses map
		// - identifiers being declared are collected in the Defs map
		{`package m0; import "os"; func _() { _ = os.Stdout }`, `os`, `<missing>`},
		{`package m1; import p "os"; func _() { _ = p.Stdout }`, `p`, `<missing>`},
		{`package m2; const c = 0`, `c`, `<missing>`},
		{`package m3; type T int`, `T`, `<missing>`},
		{`package m4; var v int`, `v`, `<missing>`},
		{`package m5; func f() {}`, `f`, `<missing>`},
		{`package m6; func _(x int) {}`, `x`, `<missing>`},
		{`package m6; func _()(x int) { return }`, `x`, `<missing>`},
		{`package m6; type T int; func (x T) _() {}`, `x`, `<missing>`},
	}

	for _, test := range tests {
		info := Info{Types: make(map[syntax.Expr]TypeAndValue)}
		name := mustTypecheck(test.src, nil, &info).Name()

		// look for expression predicates
		got := "<missing>"
		for e, tv := range info.Types {
			//println(name, ExprString(e))
			if ExprString(e) == test.expr {
				got = predString(tv)
				break
			}
		}

		if got != test.pred {
			t.Errorf("package %s: got %s; want %s", name, got, test.pred)
		}
	}
}

func TestScopesInfo(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	var tests = []struct {
		src    string
		scopes []string // list of scope descriptors of the form kind:varlist
	}{
		{`package p0`, []string{
			"file:",
		}},
		{`package p1; import ( "fmt"; m "math"; _ "os" ); var ( _ = fmt.Println; _ = m.Pi )`, []string{
			"file:fmt m",
		}},
		{`package p2; func _() {}`, []string{
			"file:", "func:",
		}},
		{`package p3; func _(x, y int) {}`, []string{
			"file:", "func:x y",
		}},
		{`package p4; func _(x, y int) { x, z := 1, 2; _ = z }`, []string{
			"file:", "func:x y z", // redeclaration of x
		}},
		{`package p5; func _(x, y int) (u, _ int) { return }`, []string{
			"file:", "func:u x y",
		}},
		{`package p6; func _() { { var x int; _ = x } }`, []string{
			"file:", "func:", "block:x",
		}},
		{`package p7; func _() { if true {} }`, []string{
			"file:", "func:", "if:", "block:",
		}},
		{`package p8; func _() { if x := 0; x < 0 { y := x; _ = y } }`, []string{
			"file:", "func:", "if:x", "block:y",
		}},
		{`package p9; func _() { switch x := 0; x {} }`, []string{
			"file:", "func:", "switch:x",
		}},
		{`package p10; func _() { switch x := 0; x { case 1: y := x; _ = y; default: }}`, []string{
			"file:", "func:", "switch:x", "case:y", "case:",
		}},
		{`package p11; func _(t interface{}) { switch t.(type) {} }`, []string{
			"file:", "func:t", "switch:",
		}},
		{`package p12; func _(t interface{}) { switch t := t; t.(type) {} }`, []string{
			"file:", "func:t", "switch:t",
		}},
		{`package p13; func _(t interface{}) { switch x := t.(type) { case int: _ = x } }`, []string{
			"file:", "func:t", "switch:", "case:x", // x implicitly declared
		}},
		{`package p14; func _() { select{} }`, []string{
			"file:", "func:",
		}},
		{`package p15; func _(c chan int) { select{ case <-c: } }`, []string{
			"file:", "func:c", "comm:",
		}},
		{`package p16; func _(c chan int) { select{ case i := <-c: x := i; _ = x} }`, []string{
			"file:", "func:c", "comm:i x",
		}},
		{`package p17; func _() { for{} }`, []string{
			"file:", "func:", "for:", "block:",
		}},
		{`package p18; func _(n int) { for i := 0; i < n; i++ { _ = i } }`, []string{
			"file:", "func:n", "for:i", "block:",
		}},
		{`package p19; func _(a []int) { for i := range a { _ = i} }`, []string{
			"file:", "func:a", "for:i", "block:",
		}},
		{`package p20; var s int; func _(a []int) { for i, x := range a { s += x; _ = i } }`, []string{
			"file:", "func:a", "for:i x", "block:",
		}},
	}

	for _, test := range tests {
		info := Info{Scopes: make(map[syntax.Node]*Scope)}
		name := mustTypecheck(test.src, nil, &info).Name()

		// number of scopes must match
		if len(info.Scopes) != len(test.scopes) {
			t.Errorf("package %s: got %d scopes; want %d", name, len(info.Scopes), len(test.scopes))
		}

		// scope descriptions must match
		for node, scope := range info.Scopes {
			var kind string
			switch node.(type) {
			case *syntax.File:
				kind = "file"
			case *syntax.FuncType:
				kind = "func"
			case *syntax.BlockStmt:
				kind = "block"
			case *syntax.IfStmt:
				kind = "if"
			case *syntax.SwitchStmt:
				kind = "switch"
			case *syntax.SelectStmt:
				kind = "select"
			case *syntax.CaseClause:
				kind = "case"
			case *syntax.CommClause:
				kind = "comm"
			case *syntax.ForStmt:
				kind = "for"
			default:
				kind = fmt.Sprintf("%T", node)
			}

			// look for matching scope description
			desc := kind + ":" + strings.Join(scope.Names(), " ")
			if !slices.Contains(test.scopes, desc) {
				t.Errorf("package %s: no matching scope found for %s", name, desc)
			}
		}
	}
}

func TestInitOrderInfo(t *testing.T) {
	var tests = []struct {
		src   string
		inits []string
	}{
		{`package p0; var (x = 1; y = x)`, []string{
			"x = 1", "y = x",
		}},
		{`package p1; var (a = 1; b = 2; c = 3)`, []string{
			"a = 1", "b = 2", "c = 3",
		}},
		{`package p2; var (a, b, c = 1, 2, 3)`, []string{
			"a = 1", "b = 2", "c = 3",
		}},
		{`package p3; var _ = f(); func f() int { return 1 }`, []string{
			"_ = f()", // blank var
		}},
		{`package p4; var (a = 0; x = y; y = z; z = 0)`, []string{
			"a = 0", "z = 0", "y = z", "x = y",
		}},
		{`package p5; var (a, _ = m[0]; m map[int]string)`, []string{
			"a, _ = m[0]", // blank var
		}},
		{`package p6; var a, b = f(); func f() (_, _ int) { return z, z }; var z = 0`, []string{
			"z = 0", "a, b = f()",
		}},
		{`package p7; var (a = func() int { return b }(); b = 1)`, []string{
			"b = 1", "a = func() int {…}()",
		}},
		{`package p8; var (a, b = func() (_, _ int) { return c, c }(); c = 1)`, []string{
			"c = 1", "a, b = func() (_, _ int) {…}()",
		}},
		{`package p9; type T struct{}; func (T) m() int { _ = y; return 0 }; var x, y = T.m, 1`, []string{
			"y = 1", "x = T.m",
		}},
		{`package p10; var (d = c + b; a = 0; b = 0; c = 0)`, []string{
			"a = 0", "b = 0", "c = 0", "d = c + b",
		}},
		{`package p11; var (a = e + c; b = d + c; c = 0; d = 0; e = 0)`, []string{
			"c = 0", "d = 0", "b = d + c", "e = 0", "a = e + c",
		}},
		// emit an initializer for n:1 initializations only once (not for each node
		// on the lhs which may appear in different order in the dependency graph)
		{`package p12; var (a = x; b = 0; x, y = m[0]; m map[int]int)`, []string{
			"b = 0", "x, y = m[0]", "a = x",
		}},
		// test case from spec section on package initialization
		{`package p12

		var (
			a = c + b
			b = f()
			c = f()
			d = 3
		)

		func f() int {
			d++
			return d
		}`, []string{
			"d = 3", "b = f()", "c = f()", "a = c + b",
		}},
		// test case for go.dev/issue/7131
		{`package main

		var counter int
		func next() int { counter++; return counter }

		var _ = makeOrder()
		func makeOrder() []int { return []int{f, b, d, e, c, a} }

		var a       = next()
		var b, c    = next(), next()
		var d, e, f = next(), next(), next()
		`, []string{
			"a = next()", "b = next()", "c = next()", "d = next()", "e = next()", "f = next()", "_ = makeOrder()",
		}},
		// test case for go.dev/issue/10709
		{`package p13

		var (
		    v = t.m()
		    t = makeT(0)
		)

		type T struct{}

		func (T) m() int { return 0 }

		func makeT(n int) T {
		    if n > 0 {
		        return makeT(n-1)
		    }
		    return T{}
		}`, []string{
			"t = makeT(0)", "v = t.m()",
		}},
		// test case for go.dev/issue/10709: same as test before, but variable decls swapped
		{`package p14

		var (
		    t = makeT(0)
		    v = t.m()
		)

		type T struct{}

		func (T) m() int { return 0 }

		func makeT(n int) T {
		    if n > 0 {
		        return makeT(n-1)
		    }
		    return T{}
		}`, []string{
			"t = makeT(0)", "v = t.m()",
		}},
		// another candidate possibly causing problems with go.dev/issue/10709
		{`package p15

		var y1 = f1()

		func f1() int { return g1() }
		func g1() int { f1(); return x1 }

		var x1 = 0

		var y2 = f2()

		func f2() int { return g2() }
		func g2() int { return x2 }

		var x2 = 0`, []string{
			"x1 = 0", "y1 = f1()", "x2 = 0", "y2 = f2()",
		}},
	}

	for _, test := range tests {
		info := Info{}
		name := mustTypecheck(test.src, nil, &info).Name()

		// number of initializers must match
		if len(info.InitOrder) != len(test.inits) {
			t.Errorf("package %s: got %d initializers; want %d", name, len(info.InitOrder), len(test.inits))
			continue
		}

		// initializers must match
		for i, want := range test.inits {
			got := info.InitOrder[i].String()
			if got != want {
				t.Errorf("package %s, init %d: got %s; want %s", name, i, got, want)
				continue
			}
		}
	}
}

func TestMultiFileInitOrder(t *testing.T) {
	fileA := mustParse(`package main; var a = 1`)
	fileB := mustParse(`package main; var b = 2`)

	// The initialization order must not depend on the parse
	// order of the files, only on the presentation order to
	// the type-checker.
	for _, test := range []struct {
		files []*syntax.File
		want  string
	}{
		{[]*syntax.File{fileA, fileB}, "[a = 1 b = 2]"},
		{[]*syntax.File{fileB, fileA}, "[b = 2 a = 1]"},
	} {
		var info Info
		if _, err := new(Config).Check("main", test.files, &info); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(info.InitOrder); got != test.want {
			t.Fatalf("got %s; want %s", got, test.want)
		}
	}
}

func TestFiles(t *testing.T) {
	var sources = []string{
		"package p; type T struct{}; func (T) m1() {}",
		"package p; func (T) m2() {}; var x interface{ m1(); m2() } = T{}",
		"package p; func (T) m3() {}; var y interface{ m1(); m2(); m3() } = T{}",
		"package p",
	}

	var conf Config
	pkg := NewPackage("p", "p")
	var info Info
	check := NewChecker(&conf, pkg, &info)

	for _, src := range sources {
		if err := check.Files([]*syntax.File{mustParse(src)}); err != nil {
			t.Error(err)
		}
	}

	// check InitOrder is [x y]
	var vars []string
	for _, init := range info.InitOrder {
		for _, v := range init.Lhs {
			vars = append(vars, v.Name())
		}
	}
	if got, want := fmt.Sprint(vars), "[x y]"; got != want {
		t.Errorf("InitOrder == %s, want %s", got, want)
	}
}

type testImporter map[string]*Package

func (m testImporter) Import(path string) (*Package, error) {
	if pkg := m[path]; pkg != nil {
		return pkg, nil
	}
	return nil, fmt.Errorf("package %q not found", path)
}

func TestSelection(t *testing.T) {
	selections := make(map[*syntax.SelectorExpr]*Selection)

	imports := make(testImporter)
	conf := Config{Importer: imports}
	makePkg := func(path, src string) {
		pkg := mustTypecheck(src, &conf, &Info{Selections: selections})
		imports[path] = pkg
	}

	const libSrc = `
package lib
type T float64
const C T = 3
var V T
func F() {}
func (T) M() {}
`
	const mainSrc = `
package main
import "lib"

type A struct {
	*B
	C
}

type B struct {
	b int
}

func (B) f(int)

type C struct {
	c int
}

type G[P any] struct {
	p P
}

func (G[P]) m(P) {}

var Inst G[int]

func (C) g()
func (*C) h()

func main() {
	// qualified identifiers
	var _ lib.T
	_ = lib.C
	_ = lib.F
	_ = lib.V
	_ = lib.T.M

	// fields
	_ = A{}.B
	_ = new(A).B

	_ = A{}.C
	_ = new(A).C

	_ = A{}.b
	_ = new(A).b

	_ = A{}.c
	_ = new(A).c

	_ = Inst.p
	_ = G[string]{}.p

	// methods
	_ = A{}.f
	_ = new(A).f
	_ = A{}.g
	_ = new(A).g
	_ = new(A).h

	_ = B{}.f
	_ = new(B).f

	_ = C{}.g
	_ = new(C).g
	_ = new(C).h
	_ = Inst.m

	// method expressions
	_ = A.f
	_ = (*A).f
	_ = B.f
	_ = (*B).f
	_ = G[string].m
}`

	wantOut := map[string][2]string{
		"lib.T.M": {"method expr (lib.T) M(lib.T)", ".[0]"},

		"A{}.B":    {"field (main.A) B *main.B", ".[0]"},
		"new(A).B": {"field (*main.A) B *main.B", "->[0]"},
		"A{}.C":    {"field (main.A) C main.C", ".[1]"},
		"new(A).C": {"field (*main.A) C main.C", "->[1]"},
		"A{}.b":    {"field (main.A) b int", "->[0 0]"},
		"new(A).b": {"field (*main.A) b int", "->[0 0]"},
		"A{}.c":    {"field (main.A) c int", ".[1 0]"},
		"new(A).c": {"field (*main.A) c int", "->[1 0]"},
		"Inst.p":   {"field (main.G[int]) p int", ".[0]"},

		"A{}.f":    {"method (main.A) f(int)", "->[0 0]"},
		"new(A).f": {"method (*main.A) f(int)", "->[0 0]"},
		"A{}.g":    {"method (main.A) g()", ".[1 0]"},
		"new(A).g": {"method (*main.A) g()", "->[1 0]"},
		"new(A).h": {"method (*main.A) h()", "->[1 1]"}, // TODO(gri) should this report .[1 1] ?
		"B{}.f":    {"method (main.B) f(int)", ".[0]"},
		"new(B).f": {"method (*main.B) f(int)", "->[0]"},
		"C{}.g":    {"method (main.C) g()", ".[0]"},
		"new(C).g": {"method (*main.C) g()", "->[0]"},
		"new(C).h": {"method (*main.C) h()", "->[1]"}, // TODO(gri) should this report .[1] ?
		"Inst.m":   {"method (main.G[int]) m(int)", ".[0]"},

		"A.f":           {"method expr (main.A) f(
```