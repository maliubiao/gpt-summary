Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The filename `issues_test.go` within the `go/types` package immediately signals that this file contains test cases specifically designed to address and prevent regressions for reported issues in the Go type checker. The package declaration `package types_test` confirms this is an external test package for `go/types`.

2. **High-Level Structure:**  The file primarily consists of multiple `TestIssueXXXXX(t *testing.T)` functions. Each function seems to target a specific issue identified by its number (e.g., Issue 5770). This is the core organizational principle.

3. **Individual Test Analysis (Iterative Approach):**  Let's take a few examples and build a pattern:

    * **`TestIssue5770`:**
        * Code: `_, err := typecheck(\`package p; type S struct{T}\`, nil, nil)`
        * Goal:  Check for an "undefined: T" error.
        * Inference: This tests the type checker's ability to identify undefined types within struct definitions.

    * **`TestIssue5849`:**
        * Code:  Contains a series of variable declarations using type conversions and bit shifts.
        * `mustTypecheck` and `Info{Types: types}` indicate that the test is collecting type information during type checking.
        * The loop iterates through the collected types, comparing the inferred type with expected types based on the expression.
        * Inference: This tests the type checker's ability to correctly infer types for expressions involving constants, bit shifts, and type conversions, including untyped `nil`.

    * **`TestIssue6413`:**
        * Code: Includes `defer f()` and `go f()`.
        * The test counts the number of `CallExpr` and verifies their type is `int`.
        * Inference:  This likely tests the type checker's handling of function calls within `defer` and `go` statements, ensuring the return type is correctly identified.

    * **`TestIssue7245`:**
        * Code: Defines a method before its receiver type.
        * It compares the `Object` representing the result variable declared in the function signature and the named result variable.
        * Inference: This likely checks if the type checker correctly associates the named return value with the declared return type, even when the receiver type is defined later.

    * **`TestIssue7827`:**
        * Code:  Tests multiple assignments, including re-declarations and attempts to assign to a constant.
        * Explicitly uses `token.NewFileSet()` and collects `Defs` and `Uses`.
        * Compares the collected definitions and uses against a `want` string.
        * Inference: This focuses on ensuring the type checker correctly identifies variable definitions and uses, particularly in short variable declarations and when attempting illegal assignments.

4. **Identifying Common Helper Functions:** Notice the repeated use of `typecheck`, `mustTypecheck`, and `mustParse`. These are likely helper functions within the `types_test` package to simplify the creation and execution of type-checking scenarios. `Info` struct is also frequently used to collect information during type checking.

5. **Recognizing Specific Go Features Being Tested:**  As you go through the tests, specific language features become apparent:
    * Undefined types
    * Type inference for various expressions
    * `defer` and `go` statements
    * Method receivers defined after the method
    * Short variable declarations
    * Constants
    * Imports and package paths
    * Interface implementation checks
    * Generic functions and type parameters
    * Conversions
    * CGO interaction

6. **Inferring the Overall Goal:**  The consistent structure and naming convention point to a clear goal: rigorously test the `go/types` package by simulating reported bugs and edge cases. The tests aim to prevent future regressions by ensuring the type checker behaves correctly in these specific scenarios.

7. **Considering Error Handling:** Many tests explicitly check for expected errors (e.g., `TestIssue5770`). The `Config` struct's `Error` field is sometimes used to collect or handle errors during type checking.

8. **Looking for Edge Cases and Specific Scenarios:**  Some tests target more intricate scenarios like import order (`TestIssue13898`), recursive types (`TestIssue43088`), or interactions with CGO (`TestIssue59944`). These highlight the need for thorough testing in a complex system like a type checker.

9. **Formulating the Summary:** Based on the individual test analyses and the overall structure, you can then formulate a comprehensive summary of the file's functionality. This includes:
    * Its purpose (testing `go/types`).
    * Its organization (tests per issue).
    * The range of Go features covered.
    * The use of helper functions.
    * The focus on error handling and specific edge cases.

10. **Go Code Examples:** To illustrate the functionality, choose a few representative tests and explain what they demonstrate with a simple code example. For instance, `TestIssue5770` clearly demonstrates undefined type checking.

11. **Code Reasoning (with Assumptions):**  For tests involving more complex logic (like `TestIssue5849` or `TestIssue7827`), explain the *intended* logic and the assertions being made. If you need to make assumptions about the input or expected output, state them explicitly.

12. **Command-Line Arguments (If Applicable):**  Scan the code for any interaction with `os.Args` or similar mechanisms. In this specific snippet, there's no direct handling of command-line arguments *within the tests themselves*. However,  `testenv.MustHaveGoBuild(t)` and `testenv.MustHaveCGO(t)` indirectly point to external dependencies or environment requirements for some tests to run correctly.

13. **Common Mistakes:** Think about how a user might misuse the features being tested. For example, forgetting to define a type before using it (related to `TestIssue5770`), or misunderstanding the rules of short variable declarations (related to `TestIssue7827`).

By following this iterative and analytical approach, you can effectively understand the purpose and functionality of even a relatively large and complex test file like this one.
这个文件 `go/src/go/types/issues_test.go` 是 Go 语言 `go/types` 包的一部分，专门用于测试在 `go/types` 包开发过程中发现的各种问题（issues）的修复情况，并防止这些问题再次出现（即进行回归测试）。

**主要功能：**

1. **问题复现测试:** 每个以 `TestIssueNNNNN` 命名的函数都对应一个特定的 issue 编号。这些函数编写用于重现该 issue 发生时的场景。
2. **回归测试:**  一旦某个 issue 被修复，相应的测试函数会保留下来，确保未来的代码修改不会导致该问题再次出现。
3. **覆盖 `go/types` 包的各种功能:** 这些测试覆盖了类型检查器在处理各种 Go 语言特性时可能遇到的问题，例如：
    * 未定义的类型
    * 类型推断
    * 常量和位运算
    * `defer` 和 `go` 语句
    * 方法的定义和调用
    * 变量的定义和使用
    * 包的导入和依赖关系
    * 接口的实现
    * 泛型
    * 类型别名
    * CGO 互操作
    * 错误处理

**可以推理出的一些 `go/types` 功能的实现及代码举例：**

**1. 检测未定义的类型：**

`TestIssue5770` 测试了当结构体字段使用了未定义的类型时，类型检查器是否能正确报错。

```go
func TestIssue5770(t *testing.T) {
	_, err := typecheck(`package p; type S struct{T}`, nil, nil)
	const want = "undefined: T"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("got: %v; want: %s", err, want)
	}
}
```

**功能实现推断:** `go/types` 包在解析结构体定义时，会查找每个字段的类型。如果找不到对应的类型定义，就会产生 "undefined: T" 这样的错误。

**Go 代码举例：**

```go
package main

type MyStruct struct {
	UnknownType int // UnknownType 未定义
}

func main() {
	// 这段代码在编译时会报错： undefined: UnknownType
}
```

**假设输入与输出:**

* **输入:**  Go 源代码字符串 `"package p; type S struct{T}"`
* **输出:**  类型检查错误，错误信息包含 `"undefined: T"`。

**2. 类型推断（例如，在常量表达式中）：**

`TestIssue5849` 测试了类型检查器在包含常量、位运算和类型转换的表达式中进行类型推断的能力。

```go
func TestIssue5849(t *testing.T) {
	src := `
package p
var (
	s uint
	_ = uint8(8)
	_ = uint16(16) << s
	_ = uint32(32 << s)
	_ = uint64(64 << s + s)
	_ = (interface{})("foo")
	_ = (interface{})(nil)
)`
	types := make(map[ast.Expr]TypeAndValue)
	mustTypecheck(src, nil, &Info{Types: types})

	// ... (后续断言，验证推断出的类型是否正确)
}
```

**功能实现推断:** `go/types` 包需要能够分析表达式的结构，结合类型转换和运算符的规则，推断出表达式的最终类型。例如，`uint16(16) << s` 中，常量 `16` 被转换为 `uint16`，然后与 `uint` 类型的 `s` 进行位运算，结果的类型需要根据 Go 的类型转换和运算规则来确定。

**Go 代码举例：**

```go
package main

import "fmt"

func main() {
	var s uint = 5
	var a = uint8(8)
	var b = uint16(16) << s
	var c = uint32(32 << s)
	var d = uint64(64 << s + s)
	var e = (interface{})("hello")
	var f = (interface{})(nil)

	fmt.Printf("Type of a: %T\n", a) // Output: Type of a: uint8
	fmt.Printf("Type of b: %T\n", b) // Output: Type of b: uint16
	fmt.Printf("Type of c: %T\n", c) // Output: Type of c: uint32
	fmt.Printf("Type of d: %T\n", d) // Output: Type of d: uint64
	fmt.Printf("Type of e: %T\n", e) // Output: Type of e: string
	fmt.Printf("Type of f: %T\n", f) // Output: Type of f: <nil>
}
```

**假设输入与输出 (针对 `_ = uint64(64 << s + s)`):**

* **假设输入:** 源代码包含 `s uint; _ = uint64(64 << s + s)`，其中 `s` 的类型为 `uint`。
* **输出:**  `go/types` 包会推断出表达式 `uint64(64 << s + s)` 的类型为 `uint64`。

**3. 识别变量的定义和使用：**

`TestIssue7827` 测试了 `go/types` 包如何区分变量的定义 (`Defs`) 和使用 (`Uses`)，以及如何处理非法赋值。

```go
func TestIssue7827(t *testing.T) {
	const src = `
package p
func _() {
	const w = 1        // defs w
        x, y := 2, 3       // defs x, y
        w, x, z := 4, 5, 6 // uses w, x, defs z; error: cannot assign to w
        _, _, _ = x, y, z  // uses x, y, z
}
`
	// ... (后续代码检查 Defs 和 Uses 的映射)
}
```

**功能实现推断:** `go/types` 包在进行静态分析时，需要跟踪每个标识符（identifier）在哪里被定义（首次声明）和在哪里被使用。这对于诸如检查变量是否被声明后使用、避免重定义等非常重要。

**Go 代码举例：**

```go
package main

func main() {
	x := 1 // 定义 x
	y := x + 2 // 使用 x，定义 y
	println(y) // 使用 y
}
```

**假设输入与输出 (针对 `w, x, z := 4, 5, 6`):**

* **假设输入:**  源代码包含 `const w = 1; x, y := 2, 3; w, x, z := 4, 5, 6`
* **输出:** `go/types` 包会记录：
    * `w` 在第一行被定义 (`Defs`)。
    * `x` 在第二行被定义 (`Defs`)。
    * `w` 和 `x` 在第三行被使用 (`Uses`)。
    * `z` 在第三行被定义 (`Defs`)。
    * 同时，会检测到尝试给常量 `w` 赋值的错误。

**命令行参数的具体处理：**

在这个文件中，没有直接处理命令行参数的代码。这个文件是单元测试，通常由 `go test` 命令执行，而 `go test` 命令本身会处理一些参数，例如指定要运行的测试函数或包。

**使用者易犯错的点（通过测试用例推断）：**

1. **在结构体定义中使用未定义的类型名 (对应 `TestIssue5770`)：**  初学者可能会忘记导入需要的包或者拼写错误类型名。

   ```go
   package main

   type MyStruct struct {
       strnig string // 易错：拼写错误
   }

   func main() {}
   ```

2. **对常量进行赋值 (对应 `TestIssue7827`)：**  Go 中的常量在定义后不能被修改。

   ```go
   package main

   func main() {
       const myConst = 10
       myConst = 20 // 错误：cannot assign to myConst
   }
   ```

3. **在接口方法定义中使用来自不同包的相同结构体类型 (对应 `TestIssue54258`)：**  如果接口在一个包中定义，而实现该接口的方法使用了来自另一个包的相同结构的结构体，即使结构体字段相同，类型也不匹配。

   ```go
   // package a
   package a
   type MyStruct struct {
       Field string
   }

   type MyInterface interface {
       DoSomething(MyStruct)
   }

   // package b
   package b

   type MyStruct struct { // 注意：这是 b 包的 MyStruct
       Field string
   }

   type MyImplementer struct{}

   func (m MyImplementer) DoSomething(s MyStruct) {} // 这里使用的是 b 包的 MyStruct
   ```

   如果尝试将 `b.MyImplementer` 的实例赋值给 `a.MyInterface` 类型的变量，会因为方法签名中的参数类型不匹配而报错。

总的来说，`go/src/go/types/issues_test.go` 是一个宝贵的资源，它展示了 `go/types` 包在处理各种 Go 语言特性和潜在错误场景时的行为，并通过测试用例确保了类型检查器的稳定性和正确性。

Prompt: 
```
这是路径为go/src/go/types/issues_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements tests for various issues.

package types_test

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"internal/testenv"
	"regexp"
	"slices"
	"strings"
	"testing"

	. "go/types"
)

func TestIssue5770(t *testing.T) {
	_, err := typecheck(`package p; type S struct{T}`, nil, nil)
	const want = "undefined: T"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("got: %v; want: %s", err, want)
	}
}

func TestIssue5849(t *testing.T) {
	src := `
package p
var (
	s uint
	_ = uint8(8)
	_ = uint16(16) << s
	_ = uint32(32 << s)
	_ = uint64(64 << s + s)
	_ = (interface{})("foo")
	_ = (interface{})(nil)
)`
	types := make(map[ast.Expr]TypeAndValue)
	mustTypecheck(src, nil, &Info{Types: types})

	for x, tv := range types {
		var want Type
		switch x := x.(type) {
		case *ast.BasicLit:
			switch x.Value {
			case `8`:
				want = Typ[Uint8]
			case `16`:
				want = Typ[Uint16]
			case `32`:
				want = Typ[Uint32]
			case `64`:
				want = Typ[Uint] // because of "+ s", s is of type uint
			case `"foo"`:
				want = Typ[String]
			}
		case *ast.Ident:
			if x.Name == "nil" {
				want = Typ[UntypedNil]
			}
		}
		if want != nil && !Identical(tv.Type, want) {
			t.Errorf("got %s; want %s", tv.Type, want)
		}
	}
}

func TestIssue6413(t *testing.T) {
	src := `
package p
func f() int {
	defer f()
	go f()
	return 0
}
`
	types := make(map[ast.Expr]TypeAndValue)
	mustTypecheck(src, nil, &Info{Types: types})

	want := Typ[Int]
	n := 0
	for x, tv := range types {
		if _, ok := x.(*ast.CallExpr); ok {
			if tv.Type != want {
				t.Errorf("%s: got %s; want %s", fset.Position(x.Pos()), tv.Type, want)
			}
			n++
		}
	}

	if n != 2 {
		t.Errorf("got %d CallExprs; want 2", n)
	}
}

func TestIssue7245(t *testing.T) {
	src := `
package p
func (T) m() (res bool) { return }
type T struct{} // receiver type after method declaration
`
	f := mustParse(fset, src)

	var conf Config
	defs := make(map[*ast.Ident]Object)
	_, err := conf.Check(f.Name.Name, fset, []*ast.File{f}, &Info{Defs: defs})
	if err != nil {
		t.Fatal(err)
	}

	m := f.Decls[0].(*ast.FuncDecl)
	res1 := defs[m.Name].(*Func).Signature().Results().At(0)
	res2 := defs[m.Type.Results.List[0].Names[0]].(*Var)

	if res1 != res2 {
		t.Errorf("got %s (%p) != %s (%p)", res1, res2, res1, res2)
	}
}

// This tests that uses of existing vars on the LHS of an assignment
// are Uses, not Defs; and also that the (illegal) use of a non-var on
// the LHS of an assignment is a Use nonetheless.
func TestIssue7827(t *testing.T) {
	const src = `
package p
func _() {
	const w = 1        // defs w
        x, y := 2, 3       // defs x, y
        w, x, z := 4, 5, 6 // uses w, x, defs z; error: cannot assign to w
        _, _, _ = x, y, z  // uses x, y, z
}
`
	// We need a specific fileset in this test below for positions.
	// Cannot use typecheck helper.
	fset := token.NewFileSet()
	f := mustParse(fset, src)

	const want = `L3 defs func p._()
L4 defs const w untyped int
L5 defs var x int
L5 defs var y int
L6 defs var z int
L6 uses const w untyped int
L6 uses var x int
L7 uses var x int
L7 uses var y int
L7 uses var z int`

	// don't abort at the first error
	conf := Config{Error: func(err error) { t.Log(err) }}
	defs := make(map[*ast.Ident]Object)
	uses := make(map[*ast.Ident]Object)
	_, err := conf.Check(f.Name.Name, fset, []*ast.File{f}, &Info{Defs: defs, Uses: uses})
	if s := err.Error(); !strings.HasSuffix(s, "cannot assign to w") {
		t.Errorf("Check: unexpected error: %s", s)
	}

	var facts []string
	for id, obj := range defs {
		if obj != nil {
			fact := fmt.Sprintf("L%d defs %s", fset.Position(id.Pos()).Line, obj)
			facts = append(facts, fact)
		}
	}
	for id, obj := range uses {
		fact := fmt.Sprintf("L%d uses %s", fset.Position(id.Pos()).Line, obj)
		facts = append(facts, fact)
	}
	slices.Sort(facts)

	got := strings.Join(facts, "\n")
	if got != want {
		t.Errorf("Unexpected defs/uses\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// This tests that the package associated with the types.Object.Pkg method
// is the type's package independent of the order in which the imports are
// listed in the sources src1, src2 below.
// The actual issue is in go/internal/gcimporter which has a corresponding
// test; we leave this test here to verify correct behavior at the go/types
// level.
func TestIssue13898(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	const src0 = `
package main

import "go/types"

func main() {
	var info types.Info
	for _, obj := range info.Uses {
		_ = obj.Pkg()
	}
}
`
	// like src0, but also imports go/importer
	const src1 = `
package main

import (
	"go/types"
	_ "go/importer"
)

func main() {
	var info types.Info
	for _, obj := range info.Uses {
		_ = obj.Pkg()
	}
}
`
	// like src1 but with different import order
	// (used to fail with this issue)
	const src2 = `
package main

import (
	_ "go/importer"
	"go/types"
)

func main() {
	var info types.Info
	for _, obj := range info.Uses {
		_ = obj.Pkg()
	}
}
`
	f := func(test, src string) {
		info := &Info{Uses: make(map[*ast.Ident]Object)}
		mustTypecheck(src, nil, info)

		var pkg *Package
		count := 0
		for id, obj := range info.Uses {
			if id.Name == "Pkg" {
				pkg = obj.Pkg()
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s: got %d entries named Pkg; want 1", test, count)
		}
		if pkg.Name() != "types" {
			t.Fatalf("%s: got %v; want package types", test, pkg)
		}
	}

	f("src0", src0)
	f("src1", src1)
	f("src2", src2)
}

func TestIssue22525(t *testing.T) {
	const src = `package p; func f() { var a, b, c, d, e int }`

	got := "\n"
	conf := Config{Error: func(err error) { got += err.Error() + "\n" }}
	typecheck(src, &conf, nil) // do not crash
	want := "\n" +
		"p:1:27: declared and not used: a\n" +
		"p:1:30: declared and not used: b\n" +
		"p:1:33: declared and not used: c\n" +
		"p:1:36: declared and not used: d\n" +
		"p:1:39: declared and not used: e\n"
	if got != want {
		t.Errorf("got: %swant: %s", got, want)
	}
}

func TestIssue25627(t *testing.T) {
	const prefix = `package p; import "unsafe"; type P *struct{}; type I interface{}; type T `
	// The src strings (without prefix) are constructed such that the number of semicolons
	// plus one corresponds to the number of fields expected in the respective struct.
	for _, src := range []string{
		`struct { x Missing }`,
		`struct { Missing }`,
		`struct { *Missing }`,
		`struct { unsafe.Pointer }`,
		`struct { P }`,
		`struct { *I }`,
		`struct { a int; b Missing; *Missing }`,
	} {
		f := mustParse(fset, prefix+src)

		cfg := Config{Importer: importer.Default(), Error: func(err error) {}}
		info := &Info{Types: make(map[ast.Expr]TypeAndValue)}
		_, err := cfg.Check(f.Name.Name, fset, []*ast.File{f}, info)
		if err != nil {
			if _, ok := err.(Error); !ok {
				t.Fatal(err)
			}
		}

		ast.Inspect(f, func(n ast.Node) bool {
			if spec, _ := n.(*ast.TypeSpec); spec != nil {
				if tv, ok := info.Types[spec.Type]; ok && spec.Name.Name == "T" {
					want := strings.Count(src, ";") + 1
					if got := tv.Type.(*Struct).NumFields(); got != want {
						t.Errorf("%s: got %d fields; want %d", src, got, want)
					}
				}
			}
			return true
		})
	}
}

func TestIssue28005(t *testing.T) {
	// method names must match defining interface name for this test
	// (see last comment in this function)
	sources := [...]string{
		"package p; type A interface{ A() }",
		"package p; type B interface{ B() }",
		"package p; type X interface{ A; B }",
	}

	// compute original file ASTs
	var orig [len(sources)]*ast.File
	for i, src := range sources {
		orig[i] = mustParse(fset, src)
	}

	// run the test for all order permutations of the incoming files
	for _, perm := range [][len(sources)]int{
		{0, 1, 2},
		{0, 2, 1},
		{1, 0, 2},
		{1, 2, 0},
		{2, 0, 1},
		{2, 1, 0},
	} {
		// create file order permutation
		files := make([]*ast.File, len(sources))
		for i := range perm {
			files[i] = orig[perm[i]]
		}

		// type-check package with given file order permutation
		var conf Config
		info := &Info{Defs: make(map[*ast.Ident]Object)}
		_, err := conf.Check("", fset, files, info)
		if err != nil {
			t.Fatal(err)
		}

		// look for interface object X
		var obj Object
		for name, def := range info.Defs {
			if name.Name == "X" {
				obj = def
				break
			}
		}
		if obj == nil {
			t.Fatal("object X not found")
		}
		iface := obj.Type().Underlying().(*Interface) // object X must be an interface

		// Each iface method m is embedded; and m's receiver base type name
		// must match the method's name per the choice in the source file.
		for i := 0; i < iface.NumMethods(); i++ {
			m := iface.Method(i)
			recvName := m.Signature().Recv().Type().(*Named).Obj().Name()
			if recvName != m.Name() {
				t.Errorf("perm %v: got recv %s; want %s", perm, recvName, m.Name())
			}
		}
	}
}

func TestIssue28282(t *testing.T) {
	// create type interface { error }
	et := Universe.Lookup("error").Type()
	it := NewInterfaceType(nil, []Type{et})
	it.Complete()
	// verify that after completing the interface, the embedded method remains unchanged
	want := et.Underlying().(*Interface).Method(0)
	got := it.Method(0)
	if got != want {
		t.Fatalf("%s.Method(0): got %q (%p); want %q (%p)", it, got, got, want, want)
	}
	// verify that lookup finds the same method in both interfaces (redundant check)
	obj, _, _ := LookupFieldOrMethod(et, false, nil, "Error")
	if obj != want {
		t.Fatalf("%s.Lookup: got %q (%p); want %q (%p)", et, obj, obj, want, want)
	}
	obj, _, _ = LookupFieldOrMethod(it, false, nil, "Error")
	if obj != want {
		t.Fatalf("%s.Lookup: got %q (%p); want %q (%p)", it, obj, obj, want, want)
	}
}

func TestIssue29029(t *testing.T) {
	f1 := mustParse(fset, `package p; type A interface { M() }`)
	f2 := mustParse(fset, `package p; var B interface { A }`)

	// printInfo prints the *Func definitions recorded in info, one *Func per line.
	printInfo := func(info *Info) string {
		var buf strings.Builder
		for _, obj := range info.Defs {
			if fn, ok := obj.(*Func); ok {
				fmt.Fprintln(&buf, fn)
			}
		}
		return buf.String()
	}

	// The *Func (method) definitions for package p must be the same
	// independent on whether f1 and f2 are type-checked together, or
	// incrementally.

	// type-check together
	var conf Config
	info := &Info{Defs: make(map[*ast.Ident]Object)}
	check := NewChecker(&conf, fset, NewPackage("", "p"), info)
	if err := check.Files([]*ast.File{f1, f2}); err != nil {
		t.Fatal(err)
	}
	want := printInfo(info)

	// type-check incrementally
	info = &Info{Defs: make(map[*ast.Ident]Object)}
	check = NewChecker(&conf, fset, NewPackage("", "p"), info)
	if err := check.Files([]*ast.File{f1}); err != nil {
		t.Fatal(err)
	}
	if err := check.Files([]*ast.File{f2}); err != nil {
		t.Fatal(err)
	}
	got := printInfo(info)

	if got != want {
		t.Errorf("\ngot : %swant: %s", got, want)
	}
}

func TestIssue34151(t *testing.T) {
	const asrc = `package a; type I interface{ M() }; type T struct { F interface { I } }`
	const bsrc = `package b; import "a"; type T struct { F interface { a.I } }; var _ = a.T(T{})`

	a := mustTypecheck(asrc, nil, nil)

	conf := Config{Importer: importHelper{pkg: a}}
	mustTypecheck(bsrc, &conf, nil)
}

type importHelper struct {
	pkg      *Package
	fallback Importer
}

func (h importHelper) Import(path string) (*Package, error) {
	if path == h.pkg.Path() {
		return h.pkg, nil
	}
	if h.fallback == nil {
		return nil, fmt.Errorf("got package path %q; want %q", path, h.pkg.Path())
	}
	return h.fallback.Import(path)
}

// TestIssue34921 verifies that we don't update an imported type's underlying
// type when resolving an underlying type. Specifically, when determining the
// underlying type of b.T (which is the underlying type of a.T, which is int)
// we must not set the underlying type of a.T again since that would lead to
// a race condition if package b is imported elsewhere, in a package that is
// concurrently type-checked.
func TestIssue34921(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Error(r)
		}
	}()

	var sources = []string{
		`package a; type T int`,
		`package b; import "a"; type T a.T`,
	}

	var pkg *Package
	for _, src := range sources {
		conf := Config{Importer: importHelper{pkg: pkg}}
		pkg = mustTypecheck(src, &conf, nil) // pkg imported by the next package in this test
	}
}

func TestIssue43088(t *testing.T) {
	// type T1 struct {
	//         _ T2
	// }
	//
	// type T2 struct {
	//         _ struct {
	//                 _ T2
	//         }
	// }
	n1 := NewTypeName(nopos, nil, "T1", nil)
	T1 := NewNamed(n1, nil, nil)
	n2 := NewTypeName(nopos, nil, "T2", nil)
	T2 := NewNamed(n2, nil, nil)
	s1 := NewStruct([]*Var{NewField(nopos, nil, "_", T2, false)}, nil)
	T1.SetUnderlying(s1)
	s2 := NewStruct([]*Var{NewField(nopos, nil, "_", T2, false)}, nil)
	s3 := NewStruct([]*Var{NewField(nopos, nil, "_", s2, false)}, nil)
	T2.SetUnderlying(s3)

	// These calls must terminate (no endless recursion).
	Comparable(T1)
	Comparable(T2)
}

func TestIssue44515(t *testing.T) {
	typ := Unsafe.Scope().Lookup("Pointer").Type()

	got := TypeString(typ, nil)
	want := "unsafe.Pointer"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	qf := func(pkg *Package) string {
		if pkg == Unsafe {
			return "foo"
		}
		return ""
	}
	got = TypeString(typ, qf)
	want = "foo.Pointer"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestIssue43124(t *testing.T) {
	// TODO(rFindley) move this to testdata by enhancing support for importing.

	testenv.MustHaveGoBuild(t) // The go command is needed for the importer to determine the locations of stdlib .a files.

	// All involved packages have the same name (template). Error messages should
	// disambiguate between text/template and html/template by printing the full
	// path.
	const (
		asrc = `package a; import "text/template"; func F(template.Template) {}; func G(int) {}`
		bsrc = `
package b

import (
	"a"
	"html/template"
)

func _() {
	// Packages should be fully qualified when there is ambiguity within the
	// error string itself.
	a.F(template /* ERRORx "cannot use.*html/template.* as .*text/template" */ .Template{})
}
`
		csrc = `
package c

import (
	"a"
	"fmt"
	"html/template"
)

// go.dev/issue/46905: make sure template is not the first package qualified.
var _ fmt.Stringer = 1 // ERRORx "cannot use 1.*as fmt\\.Stringer"

// Packages should be fully qualified when there is ambiguity in reachable
// packages. In this case both a (and for that matter html/template) import
// text/template.
func _() { a.G(template /* ERRORx "cannot use .*html/template.*Template" */ .Template{}) }
`

		tsrc = `
package template

import "text/template"

type T int

// Verify that the current package name also causes disambiguation.
var _ T = template /* ERRORx "cannot use.*text/template.* as T value" */.Template{}
`
	)

	a := mustTypecheck(asrc, nil, nil)
	imp := importHelper{pkg: a, fallback: importer.Default()}

	withImporter := func(cfg *Config) {
		cfg.Importer = imp
	}

	testFiles(t, []string{"b.go"}, [][]byte{[]byte(bsrc)}, false, withImporter)
	testFiles(t, []string{"c.go"}, [][]byte{[]byte(csrc)}, false, withImporter)
	testFiles(t, []string{"t.go"}, [][]byte{[]byte(tsrc)}, false, withImporter)
}

func TestIssue50646(t *testing.T) {
	anyType := Universe.Lookup("any").Type().Underlying()
	comparableType := Universe.Lookup("comparable").Type()

	if !Comparable(anyType) {
		t.Error("any is not a comparable type")
	}
	if !Comparable(comparableType) {
		t.Error("comparable is not a comparable type")
	}

	if Implements(anyType, comparableType.Underlying().(*Interface)) {
		t.Error("any implements comparable")
	}
	if !Implements(comparableType, anyType.(*Interface)) {
		t.Error("comparable does not implement any")
	}

	if AssignableTo(anyType, comparableType) {
		t.Error("any assignable to comparable")
	}
	if !AssignableTo(comparableType, anyType) {
		t.Error("comparable not assignable to any")
	}
}

func TestIssue55030(t *testing.T) {
	// makeSig makes the signature func(typ...)
	makeSig := func(typ Type) {
		par := NewVar(nopos, nil, "", typ)
		params := NewTuple(par)
		NewSignatureType(nil, nil, nil, params, nil, true)
	}

	// makeSig must not panic for the following (example) types:
	// []int
	makeSig(NewSlice(Typ[Int]))

	// string
	makeSig(Typ[String])

	// P where P's core type is string
	{
		P := NewTypeName(nopos, nil, "P", nil) // [P string]
		makeSig(NewTypeParam(P, NewInterfaceType(nil, []Type{Typ[String]})))
	}

	// P where P's core type is an (unnamed) slice
	{
		P := NewTypeName(nopos, nil, "P", nil) // [P []int]
		makeSig(NewTypeParam(P, NewInterfaceType(nil, []Type{NewSlice(Typ[Int])})))
	}

	// P where P's core type is bytestring (i.e., string or []byte)
	{
		t1 := NewTerm(true, Typ[String])          // ~string
		t2 := NewTerm(false, NewSlice(Typ[Byte])) // []byte
		u := NewUnion([]*Term{t1, t2})            // ~string | []byte
		P := NewTypeName(nopos, nil, "P", nil)    // [P ~string | []byte]
		makeSig(NewTypeParam(P, NewInterfaceType(nil, []Type{u})))
	}
}

func TestIssue51093(t *testing.T) {
	// Each test stands for a conversion of the form P(val)
	// where P is a type parameter with typ as constraint.
	// The test ensures that P(val) has the correct type P
	// and is not a constant.
	var tests = []struct {
		typ string
		val string
	}{
		{"bool", "false"},
		{"int", "-1"},
		{"uint", "1.0"},
		{"rune", "'a'"},
		{"float64", "3.5"},
		{"complex64", "1.25"},
		{"string", "\"foo\""},

		// some more complex constraints
		{"~byte", "1"},
		{"~int | ~float64 | complex128", "1"},
		{"~uint64 | ~rune", "'X'"},
	}

	for _, test := range tests {
		src := fmt.Sprintf("package p; func _[P %s]() { _ = P(%s) }", test.typ, test.val)
		types := make(map[ast.Expr]TypeAndValue)
		mustTypecheck(src, nil, &Info{Types: types})

		var n int
		for x, tv := range types {
			if x, _ := x.(*ast.CallExpr); x != nil {
				// there must be exactly one CallExpr which is the P(val) conversion
				n++
				tpar, _ := tv.Type.(*TypeParam)
				if tpar == nil {
					t.Fatalf("%s: got type %s, want type parameter", ExprString(x), tv.Type)
				}
				if name := tpar.Obj().Name(); name != "P" {
					t.Fatalf("%s: got type parameter name %s, want P", ExprString(x), name)
				}
				// P(val) must not be constant
				if tv.Value != nil {
					t.Errorf("%s: got constant value %s (%s), want no constant", ExprString(x), tv.Value, tv.Value.String())
				}
			}
		}

		if n != 1 {
			t.Fatalf("%s: got %d CallExpr nodes; want 1", src, 1)
		}
	}
}

func TestIssue54258(t *testing.T) {

	tests := []struct{ main, b, want string }{
		{ //---------------------------------------------------------------
			`package main
import "b"
type I0 interface {
	M0(w struct{ f string })
}
var _ I0 = b.S{}
`,
			`package b
type S struct{}
func (S) M0(struct{ f string }) {}
`,
			`6:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I0 value in variable declaration: b[.]S does not implement I0 [(]wrong type for method M0[)]
.*have M0[(]struct{f string /[*] package b [*]/ }[)]
.*want M0[(]struct{f string /[*] package main [*]/ }[)]`},

		{ //---------------------------------------------------------------
			`package main
import "b"
type I1 interface {
	M1(struct{ string })
}
var _ I1 = b.S{}
`,
			`package b
type S struct{}
func (S) M1(struct{ string }) {}
`,
			`6:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I1 value in variable declaration: b[.]S does not implement I1 [(]wrong type for method M1[)]
.*have M1[(]struct{string /[*] package b [*]/ }[)]
.*want M1[(]struct{string /[*] package main [*]/ }[)]`},

		{ //---------------------------------------------------------------
			`package main
import "b"
type I2 interface {
	M2(y struct{ f struct{ f string } })
}
var _ I2 = b.S{}
`,
			`package b
type S struct{}
func (S) M2(struct{ f struct{ f string } }) {}
`,
			`6:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I2 value in variable declaration: b[.]S does not implement I2 [(]wrong type for method M2[)]
.*have M2[(]struct{f struct{f string} /[*] package b [*]/ }[)]
.*want M2[(]struct{f struct{f string} /[*] package main [*]/ }[)]`},

		{ //---------------------------------------------------------------
			`package main
import "b"
type I3 interface {
	M3(z struct{ F struct{ f string } })
}
var _ I3 = b.S{}
`,
			`package b
type S struct{}
func (S) M3(struct{ F struct{ f string } }) {}
`,
			`6:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I3 value in variable declaration: b[.]S does not implement I3 [(]wrong type for method M3[)]
.*have M3[(]struct{F struct{f string /[*] package b [*]/ }}[)]
.*want M3[(]struct{F struct{f string /[*] package main [*]/ }}[)]`},

		{ //---------------------------------------------------------------
			`package main
import "b"
type I4 interface {
	M4(_ struct { *string })
}
var _ I4 = b.S{}
`,
			`package b
type S struct{}
func (S) M4(struct { *string }) {}
`,
			`6:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I4 value in variable declaration: b[.]S does not implement I4 [(]wrong type for method M4[)]
.*have M4[(]struct{[*]string /[*] package b [*]/ }[)]
.*want M4[(]struct{[*]string /[*] package main [*]/ }[)]`},

		{ //---------------------------------------------------------------
			`package main
import "b"
type t struct{ A int }
type I5 interface {
	M5(_ struct {b.S;t})
}
var _ I5 = b.S{}
`,
			`package b
type S struct{}
type t struct{ A int }
func (S) M5(struct {S;t}) {}
`,
			`7:12: cannot use b[.]S{} [(]value of struct type b[.]S[)] as I5 value in variable declaration: b[.]S does not implement I5 [(]wrong type for method M5[)]
.*have M5[(]struct{b[.]S; b[.]t}[)]
.*want M5[(]struct{b[.]S; t}[)]`},
	}

	fset := token.NewFileSet()
	test := func(main, b, want string) {
		re := regexp.MustCompile(want)
		bpkg := mustTypecheck(b, nil, nil)
		mast := mustParse(fset, main)
		conf := Config{Importer: importHelper{pkg: bpkg}}
		_, err := conf.Check(mast.Name.Name, fset, []*ast.File{mast}, nil)
		if err == nil {
			t.Error("Expected failure, but it did not")
		} else if got := err.Error(); !re.MatchString(got) {
			t.Errorf("Wanted match for\n\t%s\n but got\n\t%s", want, got)
		} else if testing.Verbose() {
			t.Logf("Saw expected\n\t%s", err.Error())
		}
	}
	for _, t := range tests {
		test(t.main, t.b, t.want)
	}
}

func TestIssue59944(t *testing.T) {
	testenv.MustHaveCGO(t)

	// Methods declared on aliases of cgo types are not permitted.
	const src = `// -gotypesalias=1

package p

/*
struct layout {};
*/
import "C"

type Layout = C.struct_layout

func (*Layout /* ERROR "cannot define new methods on non-local type Layout" */) Binding() {}
`

	// code generated by cmd/cgo for the above source.
	const cgoTypes = `
// Code generated by cmd/cgo; DO NOT EDIT.

package p

import "unsafe"

import "syscall"

import _cgopackage "runtime/cgo"

type _ _cgopackage.Incomplete
var _ syscall.Errno
func _Cgo_ptr(ptr unsafe.Pointer) unsafe.Pointer { return ptr }

//go:linkname _Cgo_always_false runtime.cgoAlwaysFalse
var _Cgo_always_false bool
//go:linkname _Cgo_use runtime.cgoUse
func _Cgo_use(interface{})
//go:linkname _Cgo_keepalive runtime.cgoKeepAlive
//go:noescape
func _Cgo_keepalive(interface{})
//go:linkname _Cgo_no_callback runtime.cgoNoCallback
func _Cgo_no_callback(bool)
type _Ctype_struct_layout struct {
}

type _Ctype_void [0]byte

//go:linkname _cgo_runtime_cgocall runtime.cgocall
func _cgo_runtime_cgocall(unsafe.Pointer, uintptr) int32

//go:linkname _cgoCheckPointer runtime.cgoCheckPointer
//go:noescape
func _cgoCheckPointer(interface{}, interface{})

//go:linkname _cgoCheckResult runtime.cgoCheckResult
//go:noescape
func _cgoCheckResult(interface{})
`
	testFiles(t, []string{"p.go", "_cgo_gotypes.go"}, [][]byte{[]byte(src), []byte(cgoTypes)}, false, func(cfg *Config) {
		*boolFieldAddr(cfg, "go115UsesCgo") = true
	})
}

func TestIssue61931(t *testing.T) {
	const src = `
package p

func A(func(any), ...any) {}
func B[T any](T)          {}

func _() {
	A(B, nil // syntax error: missing ',' before newline in argument list
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, pkgName(src), src, 0)
	if err == nil {
		t.Fatal("expected syntax error")
	}

	var conf Config
	conf.Check(f.Name.Name, fset, []*ast.File{f}, nil) // must not panic
}

func TestIssue61938(t *testing.T) {
	const src = `
package p

func f[T any]() {}
func _()        { f() }
`
	// no error handler provided (this issue)
	var conf Config
	typecheck(src, &conf, nil) // must not panic

	// with error handler (sanity check)
	conf.Error = func(error) {}
	typecheck(src, &conf, nil) // must not panic
}

func TestIssue63260(t *testing.T) {
	const src = `
package p

func _() {
        use(f[*string])
}

func use(func()) {}

func f[I *T, T any]() {
        var v T
        _ = v
}`

	info := Info{
		Defs: make(map[*ast.Ident]Object),
	}
	pkg := mustTypecheck(src, nil, &info)

	// get type parameter T in signature of f
	T := pkg.Scope().Lookup("f").Type().(*Signature).TypeParams().At(1)
	if T.Obj().Name() != "T" {
		t.Fatalf("got type parameter %s, want T", T)
	}

	// get type of variable v in body of f
	var v Object
	for name, obj := range info.Defs {
		if name.Name == "v" {
			v = obj
			break
		}
	}
	if v == nil {
		t.Fatal("variable v not found")
	}

	// type of v and T must be pointer-identical
	if v.Type() != T {
		t.Fatalf("types of v and T are not pointer-identical: %p != %p", v.Type().(*TypeParam), T)
	}
}

func TestIssue44410(t *testing.T) {
	const src = `
package p

type A = []int
type S struct{ A }
`

	t.Setenv("GODEBUG", "gotypesalias=1")
	pkg := mustTypecheck(src, nil, nil)

	S := pkg.Scope().Lookup("S")
	if S == nil {
		t.Fatal("object S not found")
	}

	got := S.String()
	const want = "type p.S struct{p.A}"
	if got != want {
		t.Fatalf("got %q; want %q", got, want)
	}
}

func TestIssue59831(t *testing.T) {
	// Package a exports a type S with an unexported method m;
	// the tests check the error messages when m is not found.
	const asrc = `package a; type S struct{}; func (S) m() {}`
	apkg := mustTypecheck(asrc, nil, nil)

	// Package b exports a type S with an exported method m;
	// the tests check the error messages when M is not found.
	const bsrc = `package b; type S struct{}; func (S) M() {}`
	bpkg := mustTypecheck(bsrc, nil, nil)

	tests := []struct {
		imported *Package
		src, err string
	}{
		// tests importing a (or nothing)
		{apkg, `package a1; import "a"; var _ interface { M() } = a.S{}`,
			"a.S does not implement interface{M()} (missing method M) have m() want M()"},

		{apkg, `package a2; import "a"; var _ interface { m() } = a.S{}`,
			"a.S does not implement interface{m()} (unexported method m)"}, // test for issue

		{nil, `package a3; type S struct{}; func (S) m(); var _ interface { M() } = S{}`,
			"S does not implement interface{M()} (missing method M) have m() want M()"},

		{nil, `package a4; type S struct{}; func (S) m(); var _ interface { m() } = S{}`,
			""}, // no error expected

		{nil, `package a5; type S struct{}; func (S) m(); var _ interface { n() } = S{}`,
			"S does not implement interface{n()} (missing method n)"},

		// tests importing b (or nothing)
		{bpkg, `package b1; import "b"; var _ interface { m() } = b.S{}`,
			"b.S does not implement interface{m()} (missing method m) have M() want m()"},

		{bpkg, `package b2; import "b"; var _ interface { M() } = b.S{}`,
			""}, // no error expected

		{nil, `package b3; type S struct{}; func (S) M(); var _ interface { M() } = S{}`,
			""}, // no error expected

		{nil, `package b4; type S struct{}; func (S) M(); var _ interface { m() } = S{}`,
			"S does not implement interface{m()} (missing method m) have M() want m()"},

		{nil, `package b5; type S struct{}; func (S) M(); var _ interface { n() } = S{}`,
			"S does not implement interface{n()} (missing method n)"},
	}

	for _, test := range tests {
		// typecheck test source
		conf := Config{Importer: importHelper{pkg: test.imported}}
		pkg, err := typecheck(test.src, &conf, nil)
		if err == nil {
			if test.err != "" {
				t.Errorf("package %s: got no error, want %q", pkg.Name(), test.err)
			}
			continue
		}
		if test.err == "" {
			t.Errorf("package %s: got %q, want not error", pkg.Name(), err.Error())
		}

		// flatten reported error message
		errmsg := strings.ReplaceAll(err.Error(), "\n", " ")
		errmsg = strings.ReplaceAll(errmsg, "\t", "")

		// verify error message
		if !strings.Contains(errmsg, test.err) {
			t.Errorf("package %s: got %q, want %q", pkg.Name(), errmsg, test.err)
		}
	}
}

func TestIssue64759(t *testing.T) {
	const src = `
//go:build go1.18
package p

func f[S ~[]E, E any](S) {}

func _() {
	f([]string{})
}
`
	// Per the go:build directive, the source must typecheck
	// even though the (module) Go version is set to go1.17.
	conf := Config{GoVersion: "go1.17"}
	mustTypecheck(src, &conf, nil)
}

func TestIssue68334(t *testing.T) {
	const src = `
package p

func f(x int) {
	for i, j := range x {
		_, _ = i, j
	}
	var a, b int
	for a, b = range x {
		_, _ = a, b
	}
}
`

	got := ""
	conf := Config{
		GoVersion: "go1.21",                                      // #68334 requires GoVersion <= 1.21
		Error:     func(err error) { got += err.Error() + "\n" }, // #68334 requires Error != nil
	}
	typecheck(src, &conf, nil) // do not crash

	want := "p:5:20: cannot range over x (variable of type int): requires go1.22 or later\n" +
		"p:9:19: cannot range over x (variable of type int): requires go1.22 or later\n"
	if got != want {
		t.Errorf("got: %s want: %s", got, want)
	}
}

func TestIssue68877(t *testing.T) {
	const src = `
package p

type (
	S struct{}
	A = S
	T A
)`

	t.Setenv("GODEBUG", "gotypesalias=1")
	pkg := mustTypecheck(src, nil, nil)
	T := pkg.Scope().Lookup("T").(*TypeName)
	got := T.String() // this must not panic (was issue)
	const want = "type p.T struct{}"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestIssue69092(t *testing.T) {
	const src = `
package p

var _ = T{{x}}
`

	fset := token.NewFileSet()
	file := mustParse(fset, src)
	conf := Config{Error: func(err error) {}} // ignore errors
	info := Info{Types: make(map[ast.Expr]TypeAndValue)}
	conf.Check("p", fset, []*ast.File{file}, &info)

	// look for {x} expression
	outer := file.Decls[0].(*ast.GenDecl).Specs[0].(*ast.ValueSpec).Values[0].(*ast.CompositeLit) // T{{x}}
	inner := outer.Elts[0]                                                                        // {x}

	// type of {x} must have been recorded
	tv, ok := info.Types[inner]
	if !ok {
		t.Fatal("no type found for {x}")
	}
	if tv.Type != Typ[Invalid] {
		t.Fatalf("unexpected type for {x}: %s", tv.Type)
	}
}

"""



```