Response:
Let's break down the thought process for analyzing this Go code snippet for `parser_test.go`.

**1. Initial Understanding - What is the Goal?**

The filename `parser_test.go` immediately signals that this code contains test functions. The package name `parser` suggests it's testing a Go language parser. Therefore, the primary function of this code is to verify the correctness of the `go/parser` package.

**2. Scanning for Key Functions and Structures:**

I'll scan the code for important Go language constructs that indicate what's being tested. Keywords like `func Test...`, calls to `ParseFile`, `ParseDir`, `ParseExpr`, and the use of `go/ast` strongly suggest the testing of parsing different Go language source elements.

**3. Analyzing Individual Test Functions:**

* **`TestParse`:** This is a basic sanity check. It iterates through a list of valid Go files and tries to parse them. The core functionality is `ParseFile`. The absence of an error is the success condition.

* **`TestParseFile` and `TestParseExprFrom`:** These tests try to parse incomplete or invalid code snippets (the repeated `s[::]+` suggests an attempt to trigger a specific parsing error). The expectation is that parsing *fails* (error is not nil).

* **`TestParseDir`:** This function tests parsing an entire directory of Go files. It uses a filter (`dirFilter`) to select specific files. It checks if the correct number of packages and files are parsed.

* **`TestIssue42951`:**  Tests related to specific issues often point to edge cases or bug fixes. The name "Issue42951" directly indicates it's testing a fix for a reported bug.

* **`TestParseExpr`:** This is more comprehensive. It tests parsing various Go expressions (valid, invalid, type expressions). It also checks for errors when extra tokens are present after a valid expression. The use of `ast.BinaryExpr` and `ast.StructType` reveals it's inspecting the resulting Abstract Syntax Tree (AST).

* **`TestColonEqualsScope` and `TestVarScope`:** These tests focus on variable scope, especially how variables declared on the left-hand side of an assignment affect the resolution of identifiers on the right-hand side. The tests inspect the `Obj` field of `ast.Ident` to verify if identifiers are correctly resolved.

* **`TestObjects`:**  This test verifies that different language constructs (constants, types, variables, functions, labels) are correctly identified and categorized in the AST using `ast.Inspect` and checking the `Obj.Kind`.

* **`TestUnresolved`:**  This test specifically looks for *unresolved* identifiers after parsing. This is important for understanding how the parser handles forward references or references to undefined symbols.

* **`TestCommentGroups`:** This test examines how comments are grouped and associated with code elements when the `ParseComments` flag is used.

* **`TestLeadAndLineComments`:** This delves deeper into comment handling, specifically lead and line comments associated with struct fields. `ast.FileExports` suggests testing the interaction of comment parsing with export filtering.

* **`TestIssue9979`:** Focuses on the correct positioning and implicit semicolons of empty statements within blocks.

* **`TestFileStartEndPos`:** Checks that the `FileStart` and `FileEnd` positions in the AST accurately reflect the beginning and end of the file.

* **`TestIncompleteSelection`:** Tests how the parser handles incomplete selector expressions (e.g., `fmt.`).

* **`TestLastLineComment`:** A specific test for comments at the end of a line.

* **`TestParseDepthLimit` and `TestScopeDepthLimit`:** These are crucial for testing the parser's resilience to deeply nested code structures, verifying that it doesn't crash due to stack overflow or similar issues. The `maxNestLev` and `maxScopeDepth` constants (though not shown in the snippet) are implied.

* **`TestRangePos`:** Checks the accurate position information for the `range` keyword in `for...range` loops.

* **`TestIssue59180`:**  Deals with potential issues related to extremely large line numbers.

* **`TestGoVersion`:**  Tests the ability of the parser to identify the `//go:build` or `// +build` directives and extract the Go version information.

* **`TestIssue57490`:**  Handles error cases where the input code is incomplete, ensuring the parser doesn't panic when accessing position information near the end of the file.

* **`TestParseTypeParamsAsParenExpr`:**  Tests the parsing of type parameters, specifically ensuring that parenthesized type parameters are correctly represented in the AST.

* **`TestEmptyFileHasValidStartEnd`:** Tests the basic case of parsing empty or very short files.

**4. Inferring Functionality and Providing Examples:**

Based on the test names and the code within them, I can infer the core functionalities being tested:

* **Parsing Files (`ParseFile`):**  The ability to take Go source code as input and produce an Abstract Syntax Tree (`ast.File`).
* **Parsing Directories (`ParseDir`):** The ability to process multiple Go source files within a directory.
* **Parsing Expressions (`ParseExpr`, `ParseExprFrom`):** The capability to parse individual Go expressions in isolation.
* **Scope Resolution:** How the parser handles variable scoping and identifier resolution.
* **Comment Handling:**  Parsing and associating comments with the correct code elements.
* **Error Handling:**  The parser's ability to identify and report syntax errors.
* **Position Information:**  The accuracy of source code location information within the AST.
* **Depth Limits:** Preventing excessive recursion or resource consumption for very complex code.
* **Go Version Directives:** Recognizing and extracting Go version information from build tags.

For each functionality, I try to construct a simple Go code example that demonstrates its use and the expected outcome.

**5. Identifying Error-Prone Areas:**

By examining the test cases that expect errors, and considering the complexity of parsing, I can identify potential areas where users might make mistakes:

* **Incorrectly formed expressions:**  Forgetting operators, mismatched parentheses, etc.
* **Incomplete code:** Providing code snippets that are not complete Go programs.
* **Misunderstanding scope:**  Expecting variables to be accessible when they are not in scope.
* **Incorrectly handling errors:** Not checking the error return value from parsing functions.

**6. Structuring the Answer:**

Finally, I organize the information into a clear and structured answer, using headings and bullet points. I provide code examples with expected input and output, explain command-line argument processing (even if not explicitly present, I consider how these functions *could* be used with command-line tools), and list common mistakes.
这段代码是 Go 语言 `go/parser` 包中 `parser_test.go` 文件的一部分，它主要用于**测试 `go/parser` 包的解析功能**。

以下是它主要功能的详细列表：

1. **测试 `ParseFile` 函数：**
   - 验证 `ParseFile` 函数能否正确解析合法的 Go 语言源文件。
   - 验证 `ParseFile` 函数在处理包含特定语法结构（如不完整的切片索引 `s[::]+`）时会产生错误。
   - 测试 `ParseFile` 在遇到语法错误时是否返回预期的错误。

   **Go 代码示例：**

   ```go
   package main

   import (
       "fmt"
       "go/parser"
       "go/token"
   )

   func main() {
       fset := token.NewFileSet()
       // 合法的文件内容
       src := `package main\nfunc main() { fmt.Println("Hello") }`
       _, err := parser.ParseFile(fset, "hello.go", src, 0)
       if err != nil {
           fmt.Println("解析失败:", err)
       } else {
           fmt.Println("解析成功")
       }

       // 非法的文件内容
       invalidSrc := `package main\nfunc main() { fmt.Println("Hello" }` // 缺少闭合括号
       _, err = parser.ParseFile(fset, "error.go", invalidSrc, 0)
       if err != nil {
           fmt.Println("解析失败 (预期):", err)
       } else {
           fmt.Println("解析成功 (意外)")
       }
   }
   ```

   **假设输入与输出：**

   - **输入 (合法 `src`)：** `package main\nfunc main() { fmt.Println("Hello") }`
   - **输出：** `解析成功`
   - **输入 (非法 `invalidSrc`)：** `package main\nfunc main() { fmt.Println("Hello" }`
   - **输出：** `解析失败 (预期): error.go:2:35: expected ')', found '}'` (具体的错误信息可能略有不同)

2. **测试 `ParseDir` 函数：**
   - 验证 `ParseDir` 函数能否正确解析指定目录下的所有 Go 语言源文件。
   - 测试使用文件过滤器来选择性地解析目录中的文件。
   - 验证 `ParseDir` 能否正确识别和处理包（package）。

   **Go 代码示例：**

   假设当前目录下有 `a.go` 和 `b.go` 两个文件：

   ```go
   // a.go
   package mypackage
   func HelloA() string { return "Hello from A" }

   // b.go
   package mypackage
   func HelloB() string { return "Hello from B" }
   ```

   测试代码：

   ```go
   package main

   import (
       "fmt"
       "go/parser"
       "go/token"
       "io/fs"
       "log"
   )

   func main() {
       fset := token.NewFileSet()
       path := "." // 当前目录

       // 不使用过滤器，解析所有 .go 文件
       packages, err := parser.ParseDir(fset, path, nil, 0)
       if err != nil {
           log.Fatal(err)
       }
       if pkg, ok := packages["mypackage"]; ok {
           fmt.Println("找到包:", pkg.Name)
           fmt.Println("包含文件数量:", len(pkg.Files)) // 预期为 2
       }

       // 使用过滤器，只解析文件名包含 "a" 的文件
       filter := func(f fs.FileInfo) bool {
           return f.Name() == "a.go"
       }
       filteredPackages, err := parser.ParseDir(fset, path, filter, 0)
       if err != nil {
           log.Fatal(err)
       }
       if pkg, ok := filteredPackages["mypackage"]; ok {
           fmt.Println("找到包 (过滤后):", pkg.Name)
           fmt.Println("包含文件数量 (过滤后):", len(pkg.Files)) // 预期为 1
       }
   }
   ```

   **假设输入与输出：**

   假设当前目录包含 `a.go` 和 `b.go`。

   - **不使用过滤器：**
     ```
     找到包: mypackage
     包含文件数量: 2
     ```
   - **使用过滤器：**
     ```
     找到包 (过滤后): mypackage
     包含文件数量 (过滤后): 1
     ```

3. **测试 `ParseExpr` 和 `ParseExprFrom` 函数：**
   - 验证能否正确解析 Go 语言的表达式。
   - 测试解析合法的和非法的表达式。
   - 验证解析表达式时对额外 token 的处理（应该报错）。

   **Go 代码示例：**

   ```go
   package main

   import (
       "fmt"
       "go/ast"
       "go/parser"
       "go/token"
       "log"
   )

   func main() {
       fset := token.NewFileSet()
       // 合法的表达式
       exprSrc := "1 + 2 * 3"
       expr, err := parser.ParseExpr(exprSrc)
       if err != nil {
           log.Fatal(err)
       }
       fmt.Printf("合法的表达式: %T\n", expr) // 预期为 *ast.BinaryExpr

       // 非法的表达式
       invalidExprSrc := "1 + *"
       invalidExpr, err := parser.ParseExpr(invalidExprSrc)
       if err != nil {
           fmt.Println("解析非法表达式失败 (预期):", err)
           fmt.Printf("部分解析结果: %T\n", invalidExpr) // 可能为 *ast.BinaryExpr
       } else {
           fmt.Println("解析非法表达式成功 (意外)")
       }

       // 包含额外 token 的表达式
       extraTokenSrc := "a + b := c"
       _, err = parser.ParseExpr(extraTokenSrc)
       if err != nil {
           fmt.Println("解析包含额外 token 的表达式失败 (预期):", err)
       } else {
           fmt.Println("解析包含额外 token 的表达式成功 (意外)")
       }
   }
   ```

   **假设输入与输出：**

   - **合法表达式：**
     ```
     合法的表达式: *ast.BinaryExpr
     ```
   - **非法表达式：**
     ```
     解析非法表达式失败 (预期): 1:5: expected operand, found '*'
     部分解析结果: *ast.BinaryExpr
     ```
   - **包含额外 token 的表达式：**
     ```
     解析包含额外 token 的表达式失败 (预期): 1:7: expected ')', found ':='
     ```

4. **测试作用域（Scope）处理：**
   - 验证在短变量声明 `:=` 和 `var` 声明中，左侧声明的变量不会影响右侧同名变量的解析（右侧被认为是未定义的全局变量）。

5. **测试对象（Object）的识别：**
   - 验证解析器能否正确识别不同类型的 Go 语言对象（常量、类型、变量、函数、标签等）。

6. **测试未解析的标识符（Unresolved Identifiers）：**
   - 验证解析器能否记录未能在当前作用域内找到定义的标识符。

7. **测试注释组（Comment Groups）：**
   - 验证解析器能否将连续的注释正确地分组。

8. **测试前导和行尾注释（Lead and Line Comments）：**
   - 验证解析器能否正确地将注释与相应的代码元素（例如结构体字段）关联起来。

9. **测试空语句（Empty Statements）：**
   - 验证空语句的位置信息是否正确。

10. **测试文件起始和结束位置（File Start and End Positions）：**
    - 验证解析后的 AST 节点是否包含了正确的文件起始和结束位置信息。

11. **测试不完整的选择器表达式（Incomplete Selector Expressions）：**
    - 验证解析器如何处理类似 `fmt.` 这样的不完整表达式。

12. **测试行尾注释：**
    - 专门测试类型定义后的行尾注释是否能正确解析。

13. **测试解析深度限制（Parse Depth Limit）：**
    - 验证解析器是否能正确处理深度嵌套的语法结构，防止无限递归或资源耗尽。

14. **测试作用域深度限制（Scope Depth Limit）：**
    - 验证在进行对象解析时，对作用域的深度进行限制。

15. **测试 `range` 关键字的位置信息：**
    - 验证 `for ... range` 循环中 `range` 关键字的位置信息是否正确。

16. **测试大行号的处理：**
    - 验证解析器在遇到非常大的行号时不会出现无限循环等问题。

17. **测试 Go 版本指令：**
    - 验证解析器能否识别和处理 `//go:build` 或 `// +build` 指令中的 Go 版本信息。

18. **测试解析错误时的位置信息：**
    - 验证在解析出现错误时，相关的位置信息是否仍然有效。

19. **测试将类型参数解析为 ParenExpr：**
    - 验证泛型类型声明中的类型参数是否被正确解析为 `ast.ParenExpr`。

20. **测试空文件的起始和结束位置：**
    - 验证解析空文件时，起始和结束位置是否正确。

**涉及的代码推理和假设输入输出：**

上面在解释 `ParseFile`、`ParseDir` 和 `ParseExpr` 功能时，已经给出了相应的代码示例以及假设的输入和输出。 这些示例展示了如何使用这些函数以及预期的行为。

**命令行参数的具体处理：**

这个测试文件本身不涉及命令行参数的处理。它是一个单元测试文件，通常由 `go test` 命令执行。 `go test` 命令可以接受一些参数，例如指定要运行的测试文件或函数，但这些参数是 `go test` 命令本身的参数，而不是被测试代码（即 `go/parser` 包）处理的参数。

**使用者易犯错的点：**

基于代码内容，使用者在使用 `go/parser` 包时可能容易犯以下错误：

1. **假设可以解析不完整的 Go 代码片段并获得完整的 AST：**  `ParseFile` 期望输入的是完整的 Go 语言源文件。如果只提供一个表达式或者一个声明，应该使用 `ParseExpr` 或专门解析声明的函数（如果存在）。

2. **忽略错误返回值：**  `ParseFile`、`ParseDir` 和 `ParseExpr` 等函数都会返回 `error` 类型的值。使用者必须检查这个返回值，以确定解析是否成功。忽略错误可能导致程序在后续处理中出现意想不到的行为。

3. **不理解 `ParseDir` 的文件过滤机制：**  `ParseDir` 允许传入一个文件过滤器函数，用于指定哪些文件应该被解析。如果不理解或错误地使用了这个过滤器，可能会导致解析的文件不符合预期。

4. **错误地处理 `ParseExpr` 的结果：**  `ParseExpr` 返回的是 `ast.Expr` 接口。使用者需要根据实际解析的表达式类型进行类型断言，才能访问到具体的表达式信息。如果类型断言错误，会导致程序 panic 或得到错误的结果。

5. **不了解解析选项：**  `ParseFile` 等函数接受一个 `mode` 参数，用于控制解析行为，例如是否解析注释 (`ParseComments`)。如果对这些选项不了解，可能会导致解析结果缺少必要的信息。

这段测试代码通过各种场景验证了 `go/parser` 包的正确性和健壮性，帮助开发者确保他们使用这个包时能够得到可靠的解析结果。

Prompt: 
```
这是路径为go/src/go/parser/parser_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package parser

import (
	"fmt"
	"go/ast"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

var validFiles = []string{
	"parser.go",
	"parser_test.go",
	"error_test.go",
	"short_test.go",
}

func TestParse(t *testing.T) {
	for _, filename := range validFiles {
		_, err := ParseFile(token.NewFileSet(), filename, nil, DeclarationErrors)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", filename, err)
		}
	}
}

func nameFilter(filename string) bool {
	switch filename {
	case "parser.go", "interface.go", "parser_test.go":
		return true
	case "parser.go.orig":
		return true // permit but should be ignored by ParseDir
	}
	return false
}

func dirFilter(f fs.FileInfo) bool { return nameFilter(f.Name()) }

func TestParseFile(t *testing.T) {
	src := "package p\nvar _=s[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]"
	_, err := ParseFile(token.NewFileSet(), "", src, 0)
	if err == nil {
		t.Errorf("ParseFile(%s) succeeded unexpectedly", src)
	}
}

func TestParseExprFrom(t *testing.T) {
	src := "s[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]+\ns[::]"
	_, err := ParseExprFrom(token.NewFileSet(), "", src, 0)
	if err == nil {
		t.Errorf("ParseExprFrom(%s) succeeded unexpectedly", src)
	}
}

func TestParseDir(t *testing.T) {
	path := "."
	pkgs, err := ParseDir(token.NewFileSet(), path, dirFilter, 0)
	if err != nil {
		t.Fatalf("ParseDir(%s): %v", path, err)
	}
	if n := len(pkgs); n != 1 {
		t.Errorf("got %d packages; want 1", n)
	}
	pkg := pkgs["parser"]
	if pkg == nil {
		t.Errorf(`package "parser" not found`)
		return
	}
	if n := len(pkg.Files); n != 3 {
		t.Errorf("got %d package files; want 3", n)
	}
	for filename := range pkg.Files {
		if !nameFilter(filename) {
			t.Errorf("unexpected package file: %s", filename)
		}
	}
}

func TestIssue42951(t *testing.T) {
	path := "./testdata/issue42951"
	_, err := ParseDir(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Errorf("ParseDir(%s): %v", path, err)
	}
}

func TestParseExpr(t *testing.T) {
	// just kicking the tires:
	// a valid arithmetic expression
	src := "a + b"
	x, err := ParseExpr(src)
	if err != nil {
		t.Errorf("ParseExpr(%q): %v", src, err)
	}
	// sanity check
	if _, ok := x.(*ast.BinaryExpr); !ok {
		t.Errorf("ParseExpr(%q): got %T, want *ast.BinaryExpr", src, x)
	}

	// a valid type expression
	src = "struct{x *int}"
	x, err = ParseExpr(src)
	if err != nil {
		t.Errorf("ParseExpr(%q): %v", src, err)
	}
	// sanity check
	if _, ok := x.(*ast.StructType); !ok {
		t.Errorf("ParseExpr(%q): got %T, want *ast.StructType", src, x)
	}

	// an invalid expression
	src = "a + *"
	x, err = ParseExpr(src)
	if err == nil {
		t.Errorf("ParseExpr(%q): got no error", src)
	}
	if x == nil {
		t.Errorf("ParseExpr(%q): got no (partial) result", src)
	}
	if _, ok := x.(*ast.BinaryExpr); !ok {
		t.Errorf("ParseExpr(%q): got %T, want *ast.BinaryExpr", src, x)
	}

	// a valid expression followed by extra tokens is invalid
	src = "a[i] := x"
	if _, err := ParseExpr(src); err == nil {
		t.Errorf("ParseExpr(%q): got no error", src)
	}

	// a semicolon is not permitted unless automatically inserted
	src = "a + b\n"
	if _, err := ParseExpr(src); err != nil {
		t.Errorf("ParseExpr(%q): got error %s", src, err)
	}
	src = "a + b;"
	if _, err := ParseExpr(src); err == nil {
		t.Errorf("ParseExpr(%q): got no error", src)
	}

	// various other stuff following a valid expression
	const validExpr = "a + b"
	const anything = "dh3*#D)#_"
	for _, c := range "!)]};," {
		src := validExpr + string(c) + anything
		if _, err := ParseExpr(src); err == nil {
			t.Errorf("ParseExpr(%q): got no error", src)
		}
	}

	// ParseExpr must not crash
	for _, src := range valids {
		ParseExpr(src)
	}
}

func TestColonEqualsScope(t *testing.T) {
	f, err := ParseFile(token.NewFileSet(), "", `package p; func f() { x, y, z := x, y, z }`, 0)
	if err != nil {
		t.Fatal(err)
	}

	// RHS refers to undefined globals; LHS does not.
	as := f.Decls[0].(*ast.FuncDecl).Body.List[0].(*ast.AssignStmt)
	for _, v := range as.Rhs {
		id := v.(*ast.Ident)
		if id.Obj != nil {
			t.Errorf("rhs %s has Obj, should not", id.Name)
		}
	}
	for _, v := range as.Lhs {
		id := v.(*ast.Ident)
		if id.Obj == nil {
			t.Errorf("lhs %s does not have Obj, should", id.Name)
		}
	}
}

func TestVarScope(t *testing.T) {
	f, err := ParseFile(token.NewFileSet(), "", `package p; func f() { var x, y, z = x, y, z }`, 0)
	if err != nil {
		t.Fatal(err)
	}

	// RHS refers to undefined globals; LHS does not.
	as := f.Decls[0].(*ast.FuncDecl).Body.List[0].(*ast.DeclStmt).Decl.(*ast.GenDecl).Specs[0].(*ast.ValueSpec)
	for _, v := range as.Values {
		id := v.(*ast.Ident)
		if id.Obj != nil {
			t.Errorf("rhs %s has Obj, should not", id.Name)
		}
	}
	for _, id := range as.Names {
		if id.Obj == nil {
			t.Errorf("lhs %s does not have Obj, should", id.Name)
		}
	}
}

func TestObjects(t *testing.T) {
	const src = `
package p
import fmt "fmt"
const pi = 3.14
type T struct{}
var x int
func f() { L: }
`

	f, err := ParseFile(token.NewFileSet(), "", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	objects := map[string]ast.ObjKind{
		"p":   ast.Bad, // not in a scope
		"fmt": ast.Bad, // not resolved yet
		"pi":  ast.Con,
		"T":   ast.Typ,
		"x":   ast.Var,
		"int": ast.Bad, // not resolved yet
		"f":   ast.Fun,
		"L":   ast.Lbl,
	}

	ast.Inspect(f, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			obj := ident.Obj
			if obj == nil {
				if objects[ident.Name] != ast.Bad {
					t.Errorf("no object for %s", ident.Name)
				}
				return true
			}
			if obj.Name != ident.Name {
				t.Errorf("names don't match: obj.Name = %s, ident.Name = %s", obj.Name, ident.Name)
			}
			kind := objects[ident.Name]
			if obj.Kind != kind {
				t.Errorf("%s: obj.Kind = %s; want %s", ident.Name, obj.Kind, kind)
			}
		}
		return true
	})
}

func TestUnresolved(t *testing.T) {
	f, err := ParseFile(token.NewFileSet(), "", `
package p
//
func f1a(int)
func f2a(byte, int, float)
func f3a(a, b int, c float)
func f4a(...complex)
func f5a(a s1a, b ...complex)
//
func f1b(*int)
func f2b([]byte, (int), *float)
func f3b(a, b *int, c []float)
func f4b(...*complex)
func f5b(a s1a, b ...[]complex)
//
type s1a struct { int }
type s2a struct { byte; int; s1a }
type s3a struct { a, b int; c float }
//
type s1b struct { *int }
type s2b struct { byte; int; *float }
type s3b struct { a, b *s3b; c []float }
`, 0)
	if err != nil {
		t.Fatal(err)
	}

	want := "int " + // f1a
		"byte int float " + // f2a
		"int float " + // f3a
		"complex " + // f4a
		"complex " + // f5a
		//
		"int " + // f1b
		"byte int float " + // f2b
		"int float " + // f3b
		"complex " + // f4b
		"complex " + // f5b
		//
		"int " + // s1a
		"byte int " + // s2a
		"int float " + // s3a
		//
		"int " + // s1a
		"byte int float " + // s2a
		"float " // s3a

	// collect unresolved identifiers
	var buf strings.Builder
	for _, u := range f.Unresolved {
		buf.WriteString(u.Name)
		buf.WriteByte(' ')
	}
	got := buf.String()

	if got != want {
		t.Errorf("\ngot:  %s\nwant: %s", got, want)
	}
}

func TestCommentGroups(t *testing.T) {
	f, err := ParseFile(token.NewFileSet(), "", `
package p /* 1a */ /* 1b */      /* 1c */ // 1d
/* 2a
*/
// 2b
const pi = 3.1415
/* 3a */ // 3b
/* 3c */ const e = 2.7182

// Example from go.dev/issue/3139
func ExampleCount() {
	fmt.Println(strings.Count("cheese", "e"))
	fmt.Println(strings.Count("five", "")) // before & after each rune
	// Output:
	// 3
	// 5
}
`, ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	expected := [][]string{
		{"/* 1a */", "/* 1b */", "/* 1c */", "// 1d"},
		{"/* 2a\n*/", "// 2b"},
		{"/* 3a */", "// 3b", "/* 3c */"},
		{"// Example from go.dev/issue/3139"},
		{"// before & after each rune"},
		{"// Output:", "// 3", "// 5"},
	}
	if len(f.Comments) != len(expected) {
		t.Fatalf("got %d comment groups; expected %d", len(f.Comments), len(expected))
	}
	for i, exp := range expected {
		got := f.Comments[i].List
		if len(got) != len(exp) {
			t.Errorf("got %d comments in group %d; expected %d", len(got), i, len(exp))
			continue
		}
		for j, exp := range exp {
			got := got[j].Text
			if got != exp {
				t.Errorf("got %q in group %d; expected %q", got, i, exp)
			}
		}
	}
}

func getField(file *ast.File, fieldname string) *ast.Field {
	parts := strings.Split(fieldname, ".")
	for _, d := range file.Decls {
		if d, ok := d.(*ast.GenDecl); ok && d.Tok == token.TYPE {
			for _, s := range d.Specs {
				if s, ok := s.(*ast.TypeSpec); ok && s.Name.Name == parts[0] {
					if s, ok := s.Type.(*ast.StructType); ok {
						for _, f := range s.Fields.List {
							for _, name := range f.Names {
								if name.Name == parts[1] {
									return f
								}
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// Don't use ast.CommentGroup.Text() - we want to see exact comment text.
func commentText(c *ast.CommentGroup) string {
	var buf strings.Builder
	if c != nil {
		for _, c := range c.List {
			buf.WriteString(c.Text)
		}
	}
	return buf.String()
}

func checkFieldComments(t *testing.T, file *ast.File, fieldname, lead, line string) {
	f := getField(file, fieldname)
	if f == nil {
		t.Fatalf("field not found: %s", fieldname)
	}
	if got := commentText(f.Doc); got != lead {
		t.Errorf("got lead comment %q; expected %q", got, lead)
	}
	if got := commentText(f.Comment); got != line {
		t.Errorf("got line comment %q; expected %q", got, line)
	}
}

func TestLeadAndLineComments(t *testing.T) {
	f, err := ParseFile(token.NewFileSet(), "", `
package p
type T struct {
	/* F1 lead comment */
	//
	F1 int  /* F1 */ // line comment
	// F2 lead
	// comment
	F2 int  // F2 line comment
	// f3 lead comment
	f3 int  // f3 line comment

	f4 int   /* not a line comment */ ;
        f5 int ; // f5 line comment
	f6 int ; /* f6 line comment */
	f7 int ; /*f7a*/ /*f7b*/ //f7c
}
`, ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	checkFieldComments(t, f, "T.F1", "/* F1 lead comment *///", "/* F1 */// line comment")
	checkFieldComments(t, f, "T.F2", "// F2 lead// comment", "// F2 line comment")
	checkFieldComments(t, f, "T.f3", "// f3 lead comment", "// f3 line comment")
	checkFieldComments(t, f, "T.f4", "", "")
	checkFieldComments(t, f, "T.f5", "", "// f5 line comment")
	checkFieldComments(t, f, "T.f6", "", "/* f6 line comment */")
	checkFieldComments(t, f, "T.f7", "", "/*f7a*//*f7b*///f7c")

	ast.FileExports(f)
	checkFieldComments(t, f, "T.F1", "/* F1 lead comment *///", "/* F1 */// line comment")
	checkFieldComments(t, f, "T.F2", "// F2 lead// comment", "// F2 line comment")
	if getField(f, "T.f3") != nil {
		t.Error("not expected to find T.f3")
	}
}

// TestIssue9979 verifies that empty statements are contained within their enclosing blocks.
func TestIssue9979(t *testing.T) {
	for _, src := range []string{
		"package p; func f() {;}",
		"package p; func f() {L:}",
		"package p; func f() {L:;}",
		"package p; func f() {L:\n}",
		"package p; func f() {L:\n;}",
		"package p; func f() { ; }",
		"package p; func f() { L: }",
		"package p; func f() { L: ; }",
		"package p; func f() { L: \n}",
		"package p; func f() { L: \n; }",
	} {
		fset := token.NewFileSet()
		f, err := ParseFile(fset, "", src, 0)
		if err != nil {
			t.Fatal(err)
		}

		var pos, end token.Pos
		ast.Inspect(f, func(x ast.Node) bool {
			switch s := x.(type) {
			case *ast.BlockStmt:
				pos, end = s.Pos()+1, s.End()-1 // exclude "{", "}"
			case *ast.LabeledStmt:
				pos, end = s.Pos()+2, s.End() // exclude "L:"
			case *ast.EmptyStmt:
				// check containment
				if s.Pos() < pos || s.End() > end {
					t.Errorf("%s: %T[%d, %d] not inside [%d, %d]", src, s, s.Pos(), s.End(), pos, end)
				}
				// check semicolon
				offs := fset.Position(s.Pos()).Offset
				if ch := src[offs]; ch != ';' != s.Implicit {
					want := "want ';'"
					if s.Implicit {
						want = "but ';' is implicit"
					}
					t.Errorf("%s: found %q at offset %d; %s", src, ch, offs, want)
				}
			}
			return true
		})
	}
}

func TestFileStartEndPos(t *testing.T) {
	const src = `// Copyright

//+build tag

// Package p doc comment.
package p

var lastDecl int

/* end of file */
`
	fset := token.NewFileSet()
	f, err := ParseFile(fset, "file.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	// File{Start,End} spans the entire file, not just the declarations.
	if got, want := fset.Position(f.FileStart).String(), "file.go:1:1"; got != want {
		t.Errorf("for File.FileStart, got %s, want %s", got, want)
	}
	// The end position is the newline at the end of the /* end of file */ line.
	if got, want := fset.Position(f.FileEnd).String(), "file.go:10:19"; got != want {
		t.Errorf("for File.FileEnd, got %s, want %s", got, want)
	}
}

// TestIncompleteSelection ensures that an incomplete selector
// expression is parsed as a (blank) *ast.SelectorExpr, not a
// *ast.BadExpr.
func TestIncompleteSelection(t *testing.T) {
	for _, src := range []string{
		"package p; var _ = fmt.",             // at EOF
		"package p; var _ = fmt.\ntype X int", // not at EOF
	} {
		fset := token.NewFileSet()
		f, err := ParseFile(fset, "", src, 0)
		if err == nil {
			t.Errorf("ParseFile(%s) succeeded unexpectedly", src)
			continue
		}

		const wantErr = "expected selector or type assertion"
		if !strings.Contains(err.Error(), wantErr) {
			t.Errorf("ParseFile returned wrong error %q, want %q", err, wantErr)
		}

		var sel *ast.SelectorExpr
		ast.Inspect(f, func(n ast.Node) bool {
			if n, ok := n.(*ast.SelectorExpr); ok {
				sel = n
			}
			return true
		})
		if sel == nil {
			t.Error("found no *ast.SelectorExpr")
			continue
		}
		const wantSel = "&{fmt _}"
		if fmt.Sprint(sel) != wantSel {
			t.Errorf("found selector %s, want %s", sel, wantSel)
			continue
		}
	}
}

func TestLastLineComment(t *testing.T) {
	const src = `package main
type x int // comment
`
	fset := token.NewFileSet()
	f, err := ParseFile(fset, "", src, ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	comment := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.TypeSpec).Comment.List[0].Text
	if comment != "// comment" {
		t.Errorf("got %q, want %q", comment, "// comment")
	}
}

var parseDepthTests = []struct {
	name   string
	format string
	// parseMultiplier is used when a single statement may result in more than one
	// change in the depth level, for instance "1+(..." produces a BinaryExpr
	// followed by a UnaryExpr, which increments the depth twice. The test
	// case comment explains which nodes are triggering the multiple depth
	// changes.
	parseMultiplier int
	// scope is true if we should also test the statement for the resolver scope
	// depth limit.
	scope bool
	// scopeMultiplier does the same as parseMultiplier, but for the scope
	// depths.
	scopeMultiplier int
}{
	// The format expands the part inside « » many times.
	// A second set of brackets nested inside the first stops the repetition,
	// so that for example «(«1»)» expands to (((...((((1))))...))).
	{name: "array", format: "package main; var x «[1]»int"},
	{name: "slice", format: "package main; var x «[]»int"},
	{name: "struct", format: "package main; var x «struct { X «int» }»", scope: true},
	{name: "pointer", format: "package main; var x «*»int"},
	{name: "func", format: "package main; var x «func()»int", scope: true},
	{name: "chan", format: "package main; var x «chan »int"},
	{name: "chan2", format: "package main; var x «<-chan »int"},
	{name: "interface", format: "package main; var x «interface { M() «int» }»", scope: true, scopeMultiplier: 2}, // Scopes: InterfaceType, FuncType
	{name: "map", format: "package main; var x «map[int]»int"},
	{name: "slicelit", format: "package main; var x = []any{«[]any{«»}»}", parseMultiplier: 3},      // Parser nodes: UnaryExpr, CompositeLit
	{name: "arraylit", format: "package main; var x = «[1]any{«nil»}»", parseMultiplier: 3},         // Parser nodes: UnaryExpr, CompositeLit
	{name: "structlit", format: "package main; var x = «struct{x any}{«nil»}»", parseMultiplier: 3}, // Parser nodes: UnaryExpr, CompositeLit
	{name: "maplit", format: "package main; var x = «map[int]any{1:«nil»}»", parseMultiplier: 3},    // Parser nodes: CompositeLit, KeyValueExpr
	{name: "element", format: "package main; var x = struct{x any}{x: «{«»}»}"},
	{name: "dot", format: "package main; var x = «x.»x"},
	{name: "index", format: "package main; var x = x«[1]»"},
	{name: "slice", format: "package main; var x = x«[1:2]»"},
	{name: "slice3", format: "package main; var x = x«[1:2:3]»"},
	{name: "dottype", format: "package main; var x = x«.(any)»"},
	{name: "callseq", format: "package main; var x = x«()»"},
	{name: "methseq", format: "package main; var x = x«.m()»", parseMultiplier: 2}, // Parser nodes: SelectorExpr, CallExpr
	{name: "binary", format: "package main; var x = «1+»1"},
	{name: "binaryparen", format: "package main; var x = «1+(«1»)»", parseMultiplier: 2}, // Parser nodes: BinaryExpr, ParenExpr
	{name: "unary", format: "package main; var x = «^»1"},
	{name: "addr", format: "package main; var x = «& »x"},
	{name: "star", format: "package main; var x = «*»x"},
	{name: "recv", format: "package main; var x = «<-»x"},
	{name: "call", format: "package main; var x = «f(«1»)»", parseMultiplier: 2},    // Parser nodes: Ident, CallExpr
	{name: "conv", format: "package main; var x = «(*T)(«1»)»", parseMultiplier: 2}, // Parser nodes: ParenExpr, CallExpr
	{name: "label", format: "package main; func main() { «Label:» }"},
	{name: "if", format: "package main; func main() { «if true { «» }»}", parseMultiplier: 2, scope: true, scopeMultiplier: 2}, // Parser nodes: IfStmt, BlockStmt. Scopes: IfStmt, BlockStmt
	{name: "ifelse", format: "package main; func main() { «if true {} else » {} }", scope: true},
	{name: "switch", format: "package main; func main() { «switch { default: «» }»}", scope: true, scopeMultiplier: 2},               // Scopes: TypeSwitchStmt, CaseClause
	{name: "typeswitch", format: "package main; func main() { «switch x.(type) { default: «» }» }", scope: true, scopeMultiplier: 2}, // Scopes: TypeSwitchStmt, CaseClause
	{name: "for0", format: "package main; func main() { «for { «» }» }", scope: true, scopeMultiplier: 2},                            // Scopes: ForStmt, BlockStmt
	{name: "for1", format: "package main; func main() { «for x { «» }» }", scope: true, scopeMultiplier: 2},                          // Scopes: ForStmt, BlockStmt
	{name: "for3", format: "package main; func main() { «for f(); g(); h() { «» }» }", scope: true, scopeMultiplier: 2},              // Scopes: ForStmt, BlockStmt
	{name: "forrange0", format: "package main; func main() { «for range x { «» }» }", scope: true, scopeMultiplier: 2},               // Scopes: RangeStmt, BlockStmt
	{name: "forrange1", format: "package main; func main() { «for x = range z { «» }» }", scope: true, scopeMultiplier: 2},           // Scopes: RangeStmt, BlockStmt
	{name: "forrange2", format: "package main; func main() { «for x, y = range z { «» }» }", scope: true, scopeMultiplier: 2},        // Scopes: RangeStmt, BlockStmt
	{name: "go", format: "package main; func main() { «go func() { «» }()» }", parseMultiplier: 2, scope: true},                      // Parser nodes: GoStmt, FuncLit
	{name: "defer", format: "package main; func main() { «defer func() { «» }()» }", parseMultiplier: 2, scope: true},                // Parser nodes: DeferStmt, FuncLit
	{name: "select", format: "package main; func main() { «select { default: «» }» }", scope: true},
}

// split splits pre«mid»post into pre, mid, post.
// If the string does not have that form, split returns x, "", "".
func split(x string) (pre, mid, post string) {
	start, end := strings.Index(x, "«"), strings.LastIndex(x, "»")
	if start < 0 || end < 0 {
		return x, "", ""
	}
	return x[:start], x[start+len("«") : end], x[end+len("»"):]
}

func TestParseDepthLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("test requires significant memory")
	}
	for _, tt := range parseDepthTests {
		for _, size := range []string{"small", "big"} {
			t.Run(tt.name+"/"+size, func(t *testing.T) {
				n := maxNestLev + 1
				if tt.parseMultiplier > 0 {
					n /= tt.parseMultiplier
				}
				if size == "small" {
					// Decrease the number of statements by 10, in order to check
					// that we do not fail when under the limit. 10 is used to
					// provide some wiggle room for cases where the surrounding
					// scaffolding syntax adds some noise to the depth that changes
					// on a per testcase basis.
					n -= 10
				}

				pre, mid, post := split(tt.format)
				if strings.Contains(mid, "«") {
					left, base, right := split(mid)
					mid = strings.Repeat(left, n) + base + strings.Repeat(right, n)
				} else {
					mid = strings.Repeat(mid, n)
				}
				input := pre + mid + post

				fset := token.NewFileSet()
				_, err := ParseFile(fset, "", input, ParseComments|SkipObjectResolution)
				if size == "small" {
					if err != nil {
						t.Errorf("ParseFile(...): %v (want success)", err)
					}
				} else {
					expected := "exceeded max nesting depth"
					if err == nil || !strings.HasSuffix(err.Error(), expected) {
						t.Errorf("ParseFile(...) = _, %v, want %q", err, expected)
					}
				}
			})
		}
	}
}

func TestScopeDepthLimit(t *testing.T) {
	for _, tt := range parseDepthTests {
		if !tt.scope {
			continue
		}
		for _, size := range []string{"small", "big"} {
			t.Run(tt.name+"/"+size, func(t *testing.T) {
				n := maxScopeDepth + 1
				if tt.scopeMultiplier > 0 {
					n /= tt.scopeMultiplier
				}
				if size == "small" {
					// Decrease the number of statements by 10, in order to check
					// that we do not fail when under the limit. 10 is used to
					// provide some wiggle room for cases where the surrounding
					// scaffolding syntax adds some noise to the depth that changes
					// on a per testcase basis.
					n -= 10
				}

				pre, mid, post := split(tt.format)
				if strings.Contains(mid, "«") {
					left, base, right := split(mid)
					mid = strings.Repeat(left, n) + base + strings.Repeat(right, n)
				} else {
					mid = strings.Repeat(mid, n)
				}
				input := pre + mid + post

				fset := token.NewFileSet()
				_, err := ParseFile(fset, "", input, DeclarationErrors)
				if size == "small" {
					if err != nil {
						t.Errorf("ParseFile(...): %v (want success)", err)
					}
				} else {
					expected := "exceeded max scope depth during object resolution"
					if err == nil || !strings.HasSuffix(err.Error(), expected) {
						t.Errorf("ParseFile(...) = _, %v, want %q", err, expected)
					}
				}
			})
		}
	}
}

// proposal go.dev/issue/50429
func TestRangePos(t *testing.T) {
	testcases := []string{
		"package p; func _() { for range x {} }",
		"package p; func _() { for i = range x {} }",
		"package p; func _() { for i := range x {} }",
		"package p; func _() { for k, v = range x {} }",
		"package p; func _() { for k, v := range x {} }",
	}

	for _, src := range testcases {
		fset := token.NewFileSet()
		f, err := ParseFile(fset, src, src, 0)
		if err != nil {
			t.Fatal(err)
		}

		ast.Inspect(f, func(x ast.Node) bool {
			switch s := x.(type) {
			case *ast.RangeStmt:
				pos := fset.Position(s.Range)
				if pos.Offset != strings.Index(src, "range") {
					t.Errorf("%s: got offset %v, want %v", src, pos.Offset, strings.Index(src, "range"))
				}
			}
			return true
		})
	}
}

// TestIssue59180 tests that line number overflow doesn't cause an infinite loop.
func TestIssue59180(t *testing.T) {
	testcases := []string{
		"package p\n//line :9223372036854775806\n\n//",
		"package p\n//line :1:9223372036854775806\n\n//",
		"package p\n//line file:9223372036854775806\n\n//",
	}

	for _, src := range testcases {
		_, err := ParseFile(token.NewFileSet(), "", src, ParseComments)
		if err == nil {
			t.Errorf("ParseFile(%s) succeeded unexpectedly", src)
		}
	}
}

func TestGoVersion(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := ParseDir(fset, "./testdata/goversion", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range pkgs {
		want := strings.ReplaceAll(p.Name, "_", ".")
		if want == "none" {
			want = ""
		}
		for _, f := range p.Files {
			if f.GoVersion != want {
				t.Errorf("%s: GoVersion = %q, want %q", fset.Position(f.Pos()), f.GoVersion, want)
			}
		}
	}
}

func TestIssue57490(t *testing.T) {
	src := `package p; func f() { var x struct` // program not correctly terminated
	fset := token.NewFileSet()
	file, err := ParseFile(fset, "", src, 0)
	if err == nil {
		t.Fatalf("syntax error expected, but no error reported")
	}

	// Because of the syntax error, the end position of the function declaration
	// is past the end of the file's position range.
	funcEnd := file.Decls[0].End()

	// Offset(funcEnd) must not panic (to test panic, set debug=true in token package)
	// (panic: offset 35 out of bounds [0, 34] (position 36 out of bounds [1, 35]))
	tokFile := fset.File(file.Pos())
	offset := tokFile.Offset(funcEnd)
	if offset != tokFile.Size() {
		t.Fatalf("offset = %d, want %d", offset, tokFile.Size())
	}
}

func TestParseTypeParamsAsParenExpr(t *testing.T) {
	const src = "package p; type X[A (B),] struct{}"

	fset := token.NewFileSet()
	f, err := ParseFile(fset, "test.go", src, ParseComments|SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}

	typeParam := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.TypeSpec).TypeParams.List[0].Type
	_, ok := typeParam.(*ast.ParenExpr)
	if !ok {
		t.Fatalf("typeParam is a %T; want: *ast.ParenExpr", typeParam)
	}
}

// TestEmptyFileHasValidStartEnd is a regression test for #70162.
func TestEmptyFileHasValidStartEnd(t *testing.T) {
	for _, test := range []struct {
		src  string
		want string // "Pos() FileStart FileEnd"
	}{
		{src: "", want: "0 1 1"},
		{src: "package ", want: "0 1 9"},
		{src: "package p", want: "1 1 10"},
		{src: "type T int", want: "0 1 11"},
	} {
		fset := token.NewFileSet()
		f, _ := ParseFile(fset, "a.go", test.src, 0)
		got := fmt.Sprintf("%d %d %d", f.Pos(), f.FileStart, f.FileEnd)
		if got != test.want {
			t.Fatalf("src = %q: got %s, want %s", test.src, got, test.want)
		}
	}
}

"""



```