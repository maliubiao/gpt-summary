Response:
Let's break down the thought process for analyzing this Go code.

1. **Understand the Goal:** The first step is to understand the overall purpose of the code. The file name `scope_test.go` and the function name `TestScopeRanges` strongly suggest this code is testing something related to scopes in Go programs, particularly how they are represented in DWARF debugging information. The comments at the beginning of `TestScopeRanges` confirm this.

2. **Identify Key Data Structures:**  The code uses several custom types. Pinpointing these is crucial:
    * `testline`:  Represents a line of Go source code and the expected scope and variable information for that line. This is the input data for the tests.
    * `lexblock`: Represents a lexical scope (a block of code). It contains information about its ID, address ranges, variables declared within it, and nested scopes. This is the data structure extracted from the DWARF information.
    * `variable`: Represents a variable within a scope, including its expression (type and name) and declaration line.
    * `line`: A simple struct to represent a file path and line number.

3. **Trace the Core Logic (`TestScopeRanges`):**  This function is the heart of the testing. Let's follow its steps:
    * **Compilation:**  It uses `gobuild` to compile a Go program from the `testfile` data. The `-gcflags=-N -l` flag is important because it disables optimizations, making the DWARF output more predictable and directly related to the source code structure.
    * **DWARF Extraction:** It opens the compiled object file and extracts the DWARF debugging information using `f.DWARF()`.
    * **DWARF Parsing:** It iterates through the DWARF entries, looking specifically for `DW_TAG_Subprogram` entries, which represent functions. It filters for functions starting with "main.Test".
    * **Scope Building (`readScope`):**  For each relevant function, it calls `readScope` to recursively build a `lexblock` tree representing the nested scopes within the function. This function is key to understanding how the DWARF information is interpreted.
    * **Line Mapping (`markLines`):**  The `markLines` method of `lexblock` is used to associate source code lines with the lexical scopes they belong to. It uses the PC-Line table from the object file (`pcln`).
    * **Verification:** The code then iterates through the `testfile` again and compares the extracted scope and variable information (`lines`) with the expected information defined in `testfile`. It uses `checkScopes` and `checkVars` for the comparisons.

4. **Analyze Helper Functions:**  Understanding the helper functions clarifies the details of the process:
    * `gobuild`:  Compiles the Go code defined in `testfile`. Notice the command-line flags used for compilation.
    * `readScope`:  Parses the DWARF entries to build the `lexblock` tree. Pay attention to how it handles different DWARF tags (`DW_TAG_LexDwarfBlock`, `DW_TAG_Variable`, `DW_TAG_FormalParameter`).
    * `markLines`:  Connects the DWARF scope information back to the source code lines using the PC-Line table.
    * `checkScopes`, `checkVars`:  Perform the comparisons between the expected and actual scope/variable information.
    * `scopesToString`, `declLineForVar`: Utility functions for formatting and searching.

5. **Infer Functionality:** Based on the above analysis, it becomes clear that this code tests the correctness of the Go compiler's DWARF output regarding lexical scopes and variable locations. It verifies that the DWARF information accurately reflects the nesting of code blocks and the variables declared within them.

6. **Construct Examples:**  To illustrate the functionality, pick a simple test case from `testfile`, like `TestNestedFor`. Explain how the scopes are nested and how the variables `a` and `i` are associated with those scopes at different lines.

7. **Identify Command-Line Aspects:** The `gobuild` function uses `go build`. The key here is the `-gcflags=-N -l` flag, which disables optimization. Explain why this is important for testing DWARF output.

8. **Consider Potential Errors:**  Think about what could go wrong when writing these kinds of tests. The most likely issue is a mismatch between the expected scope/variable information and the actual DWARF output. This could be due to incorrect assumptions about how the compiler generates DWARF or errors in the `testfile` data. Provide an example of a common mistake in defining the `testline` data.

9. **Review and Refine:**  Read through your analysis to ensure it's clear, accurate, and covers all the key aspects of the code. Make sure the Go code examples are correct and easy to understand.

This systematic approach, starting with the overall goal and drilling down into the details of the code and data structures, helps in thoroughly understanding and explaining the functionality of the given Go code.
这段代码是 Go 语言编译器的一部分，位于 `go/src/cmd/compile/internal/dwarfgen/scope_test.go`，它的主要功能是**测试 Go 编译器生成 DWARF 调试信息的过程中，关于代码作用域（scope）的表示是否正确**。

具体来说，它通过编译一段包含各种作用域结构的 Go 代码，然后解析生成的 DWARF 信息，并与预期的作用域信息进行比较，以此来验证编译器的正确性。

以下是代码功能的详细解释：

**1. 定义测试数据结构 `testline`:**

* `line string`:  存储一行 Go 源代码。
* `scopes []int`:  存储该行代码所属的词法作用域的 ID 列表。作用域 ID 是对函数内的词法块进行前序遍历分配的。作用域 ID 是函数特定的，即作用域 0 始终是该行代码所属函数的根作用域。空作用域不会分配 ID。作用域 0 在此列表中被省略，因为它属于所有行。
* `vars []string`:  存储属于 `scopes` 中最后一个作用域的变量列表。局部变量以 "var " 为前缀，形参以 "arg " 为前缀。必须按字母顺序排序。设置为 `nil` 则跳过此检查。
* `decl []string`:  存储在该行声明的变量列表。
* `declBefore []string`: 存储在该行或之前声明的变量列表。

**2. 定义测试用例 `testfile`:**

* `testfile` 是一个 `[]testline` 类型的切片，包含了多个测试用例。每个 `testline` 描述了一行 Go 代码以及期望的 DWARF 作用域和变量信息。
* 这些测试用例覆盖了各种 Go 语言的作用域场景，例如：
    * 嵌套的 `for` 循环 (`TestNestedFor`)
    * 多返回值赋值 (`TestOas2`)
    * `if-else` 语句 (`TestIfElse`)
    * `switch` 语句 (`TestSwitch`)
    * 类型断言 (`TestTypeSwitch`)
    * `select` 语句 (`TestSelectScope`)
    * 显式代码块 (`TestBlock`)
    * 不连续的代码范围 (`TestDiscontiguousRanges`)
    * 闭包 (`TestClosureScope`)
    * 变量逃逸分析 (`TestEscape`)
    * 闭包捕获变量 (`TestCaptureVar`)

**3. 测试函数 `TestScopeRanges(t *testing.T)`:**

* 该函数是主要的测试函数。
* 它首先使用 `gobuild` 函数编译 `testfile` 中的 Go 代码，生成一个包含 DWARF 信息的二进制文件。
* 然后，它解析二进制文件中的 DWARF 信息，提取每个函数的词法作用域信息。
* 关键步骤：
    * 遍历 DWARF 条目，找到 `DW_TAG_Subprogram` 类型的条目（代表函数）。
    * 对于每个以 "main.Test" 开头的函数，调用 `readScope` 函数递归地读取该函数的词法作用域信息，构建一个 `lexblock` 树。
    * `readScope` 函数解析 DWARF 信息，识别 `DW_TAG_lexical_block`（词法块）、`DW_TAG_variable`（变量）、`DW_TAG_formal_parameter`（形参）等条目，并构建 `lexblock` 结构体。
    * `markLines` 函数将解析出的 `lexblock` 信息与源代码行号关联起来。它遍历每个作用域的地址范围，将这些范围内的指令对应的源代码行标记为属于该作用域。
* 最后，它遍历 `testfile`，将从 DWARF 信息中提取的作用域和变量信息与 `testfile` 中预期的信息进行比较。
* `checkScopes` 函数比较实际的作用域 ID 列表与期望的列表是否一致。
* `checkVars` 函数比较实际的变量列表与期望的列表是否一致。
* 如果发现任何不一致，测试将失败。

**4. 辅助函数:**

* `gobuild(t *testing.T, dir string, optimized bool, testfile []testline) (string, *objfile.File)`:  编译 `testfile` 中定义的 Go 代码，并返回源文件路径和生成的对象文件。`optimized` 参数控制是否禁用优化（`-gcflags=-N -l` 禁用优化和内联，这对于调试 DWARF 信息非常重要）。
* `readScope(ctxt *scopexplainContext, scope *lexblock, entry *dwarf.Entry)`:  递归读取 DWARF 信息，构建 `lexblock` 结构体，表示词法作用域。
* `markLines(pcln objfile.Liner, lines map[line][]*lexblock)`:  将词法作用域信息与源代码行号关联。
* `checkScopes(tgt []int, out []*lexblock) bool`:  比较期望的作用域 ID 和实际解析出的作用域 ID。
* `checkVars(tgt []string, out []variable) bool`:  比较期望的变量列表和实际解析出的变量列表。
* `scopesToString(v []*lexblock) string`:  将作用域列表转换为字符串表示。
* `declLineForVar(scope []variable, name string) int`:  查找变量在其作用域内的声明行号。
* `entryToVar(e *dwarf.Entry, kind string, typ dwarf.Type) variable`:  从 DWARF 条目中提取变量信息。

**5. 测试 `TestEmptyDwarfRanges(t *testing.T)`:**

* 这个测试函数检查生成的 DWARF 信息中是否存在起始地址和结束地址相同的范围条目。这通常是一个错误，表示编译器可能生成了无效的 DWARF 信息。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码主要测试 Go 编译器在生成 DWARF 调试信息时，对 **词法作用域** 的处理是否正确。词法作用域是编程语言中一个非常基础且重要的概念，它决定了变量的可访问范围。Go 语言的词法作用域规则包括：

* 代码块（例如 `if`、`for`、`switch` 语句的花括号内部）会创建新的作用域。
* 函数体也会创建一个作用域。
* 闭包会捕获其定义时所在作用域的变量。

这段测试代码通过覆盖各种包含不同作用域结构的 Go 代码，来确保编译器能够正确地将这些作用域信息编码到 DWARF 调试信息中，以便调试器能够准确地理解程序执行时的变量状态。

**Go 代码举例说明 (基于 `TestNestedFor` 测试用例):**

```go
package main

import "fmt"

func f1(x int) {}
func f2(x int) {}
func f3(x int) {}
func f4(x int) {}
func f5(x int) {}

func TestNestedFor() {
	a := 0
	f1(a)
	for i := 0; i < 5; i++ { // 作用域 1 开始
		f2(i)
		for i := 0; i < 5; i++ { // 作用域 2 开始 (嵌套在作用域 1 内)
			f3(i)
		} // 作用域 2 结束
		f4(i)
	} // 作用域 1 结束
	f5(a)
}

func main() {
	TestNestedFor()
}
```

**假设的输入与输出 (针对 `TestNestedFor`):**

* **输入 (源代码行):**
    * `a := 0`
    * `for i := 0; i < 5; i++ {`
    * `f2(i)`
    * `for i := 0; i < 5; i++ {`
    * `f3(i)`
    * `f4(i)`

* **输出 (基于 `testfile` 中的定义):**
    * `a := 0`: `scopes: []`, `vars: ["var a int"]`, `decl: ["a"]` (属于根作用域 0，但 `scopes` 中省略)
    * `for i := 0; i < 5; i++ {`: `scopes: [1]`, `vars: ["var i int"]`, `decl: ["i"]` (属于作用域 1)
    * `f2(i)`: `scopes: [1]`
    * `for i := 0; i < 5; i++ {`: `scopes: [1, 2]`, `vars: ["var i int"]`, `decl: ["i"]` (属于作用域 1 和嵌套的作用域 2)
    * `f3(i)`: `scopes: [1, 2]`
    * `f4(i)`: `scopes: [1]`

**命令行参数的具体处理:**

`TestScopeRanges` 函数内部调用了 `gobuild` 函数来编译 Go 代码。`gobuild` 函数使用了 `go build` 命令。

```go
cmd := testenv.Command(t, testenv.GoToolPath(t), args...)
```

`args` 变量包含了传递给 `go build` 命令的参数。在 `TestScopeRanges` 中，默认情况下（`optimized` 为 `false`）会添加 `-gcflags=-N -l` 参数：

* `-gcflags`:  用于将参数传递给 Go 编译器。
* `-N`:  禁用编译器优化。这对于调试非常重要，因为优化可能会改变代码的结构，使得生成的 DWARF 信息与源代码的直观结构不一致。
* `-l`:  禁用内联。内联也会改变代码结构，影响作用域的表示。

因此，`gobuild` 函数会执行类似以下的命令：

```bash
go build -gcflags=-N -l -o <临时目录>/out.o <临时目录>/test.go
```

如果 `optimized` 为 `true`，则不会添加 `-gcflags=-N -l` 参数，`go build` 将使用默认的优化设置。`TestEmptyDwarfRanges` 函数就使用了优化构建。

**使用者易犯错的点:**

在编写类似的 DWARF 测试时，一个常见的错误是**对编译器优化和内联的影响考虑不足**。

**示例：**

假设你编写了一个测试用例，期望在某个内联函数内部声明的变量出现在特定的作用域中。但是，如果编译器决定内联这个函数，那么该变量的作用域可能会被合并到调用者的作用域中，导致你的测试用例失败。

```go
// 错误的测试用例假设内联不会发生
var testfile_wrong = []testline{
	{line: "package main"},
	{line: "func inlineMe() int { x := 1; return x }"},
	{line: "func TestInline() {", vars: []string{}},
	{line: "  y := inlineMe()", scopes: []int{1}, vars: []string{"var y int", "var x int"}}, // 错误假设：x 在这里可见
	{line: "  _ = y"},
	{line: "}", vars: []string{}},
}
```

在这个错误的示例中，我们假设变量 `x` 在 `TestInline` 函数的作用域 1 中可见。但是，如果 `inlineMe` 函数被内联，`x` 的作用域将仅限于 `inlineMe` 函数被内联的位置，而不会出现在 `TestInline` 函数的作用域中。

为了避免这类错误，在编写 DWARF 测试时，通常需要禁用优化和内联（使用 `-gcflags=-N -l`），以便 DWARF 信息更直接地反映源代码的结构。或者，如果测试的目的是验证优化后的 DWARF 信息，则需要仔细考虑优化可能带来的影响，并相应地调整预期的输出。

总结来说，这段代码是 Go 编译器测试框架的重要组成部分，专门用于验证编译器生成的 DWARF 调试信息中关于代码作用域的表示是否正确，这对于调试器的正常工作至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/dwarfgen/scope_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dwarfgen

import (
	"cmp"
	"debug/dwarf"
	"fmt"
	"internal/platform"
	"internal/testenv"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"cmd/internal/objfile"
)

type testline struct {
	// line is one line of go source
	line string

	// scopes is a list of scope IDs of all the lexical scopes that this line
	// of code belongs to.
	// Scope IDs are assigned by traversing the tree of lexical blocks of a
	// function in pre-order
	// Scope IDs are function specific, i.e. scope 0 is always the root scope
	// of the function that this line belongs to. Empty scopes are not assigned
	// an ID (because they are not saved in debug_info).
	// Scope 0 is always omitted from this list since all lines always belong
	// to it.
	scopes []int

	// vars is the list of variables that belong in scopes[len(scopes)-1].
	// Local variables are prefixed with "var ", formal parameters with "arg ".
	// Must be ordered alphabetically.
	// Set to nil to skip the check.
	vars []string

	// decl is the list of variables declared at this line.
	decl []string

	// declBefore is the list of variables declared at or before this line.
	declBefore []string
}

var testfile = []testline{
	{line: "package main"},
	{line: "var sink any"},
	{line: "func f1(x int) { }"},
	{line: "func f2(x int) { }"},
	{line: "func f3(x int) { }"},
	{line: "func f4(x int) { }"},
	{line: "func f5(x int) { }"},
	{line: "func f6(x int) { }"},
	{line: "func leak(x interface{}) { sink = x }"},
	{line: "func gret1() int { return 2 }"},
	{line: "func gretbool() bool { return true }"},
	{line: "func gret3() (int, int, int) { return 0, 1, 2 }"},
	{line: "var v = []int{ 0, 1, 2 }"},
	{line: "var ch = make(chan int)"},
	{line: "var floatch = make(chan float64)"},
	{line: "var iface interface{}"},
	{line: "func TestNestedFor() {", vars: []string{"var a int"}},
	{line: "	a := 0", decl: []string{"a"}},
	{line: "	f1(a)"},
	{line: "	for i := 0; i < 5; i++ {", scopes: []int{1}, vars: []string{"var i int"}, decl: []string{"i"}},
	{line: "		f2(i)", scopes: []int{1}},
	{line: "		for i := 0; i < 5; i++ {", scopes: []int{1, 2}, vars: []string{"var i int"}, decl: []string{"i"}},
	{line: "			f3(i)", scopes: []int{1, 2}},
	{line: "		}"},
	{line: "		f4(i)", scopes: []int{1}},
	{line: "	}"},
	{line: "	f5(a)"},
	{line: "}"},
	{line: "func TestOas2() {", vars: []string{}},
	{line: "	if a, b, c := gret3(); a != 1 {", scopes: []int{1}, vars: []string{"var a int", "var b int", "var c int"}},
	{line: "		f1(a)", scopes: []int{1}},
	{line: "		f1(b)", scopes: []int{1}},
	{line: "		f1(c)", scopes: []int{1}},
	{line: "	}"},
	{line: "	for i, x := range v {", scopes: []int{2}, vars: []string{"var i int", "var x int"}},
	{line: "		f1(i)", scopes: []int{2}},
	{line: "		f1(x)", scopes: []int{2}},
	{line: "	}"},
	{line: "	if a, ok := <- ch; ok {", scopes: []int{3}, vars: []string{"var a int", "var ok bool"}},
	{line: "		f1(a)", scopes: []int{3}},
	{line: "	}"},
	{line: "	if a, ok := iface.(int); ok {", scopes: []int{4}, vars: []string{"var a int", "var ok bool"}},
	{line: "		f1(a)", scopes: []int{4}},
	{line: "	}"},
	{line: "}"},
	{line: "func TestIfElse() {"},
	{line: "	if x := gret1(); x != 0 {", scopes: []int{1}, vars: []string{"var x int"}},
	{line: "		a := 0", scopes: []int{1, 2}, vars: []string{"var a int"}},
	{line: "		f1(a); f1(x)", scopes: []int{1, 2}},
	{line: "	} else {"},
	{line: "		b := 1", scopes: []int{1, 3}, vars: []string{"var b int"}},
	{line: "		f1(b); f1(x+1)", scopes: []int{1, 3}},
	{line: "	}"},
	{line: "}"},
	{line: "func TestSwitch() {", vars: []string{}},
	{line: "	switch x := gret1(); x {", scopes: []int{1}, vars: []string{"var x int"}},
	{line: "	case 0:", scopes: []int{1, 2}},
	{line: "		i := x + 5", scopes: []int{1, 2}, vars: []string{"var i int"}},
	{line: "		f1(x); f1(i)", scopes: []int{1, 2}},
	{line: "	case 1:", scopes: []int{1, 3}},
	{line: "		j := x + 10", scopes: []int{1, 3}, vars: []string{"var j int"}},
	{line: "		f1(x); f1(j)", scopes: []int{1, 3}},
	{line: "	case 2:", scopes: []int{1, 4}},
	{line: "		k := x + 2", scopes: []int{1, 4}, vars: []string{"var k int"}},
	{line: "		f1(x); f1(k)", scopes: []int{1, 4}},
	{line: "	}"},
	{line: "}"},
	{line: "func TestTypeSwitch() {", vars: []string{}},
	{line: "	switch x := iface.(type) {"},
	{line: "	case int:", scopes: []int{1}},
	{line: "		f1(x)", scopes: []int{1}, vars: []string{"var x int"}},
	{line: "	case uint8:", scopes: []int{2}},
	{line: "		f1(int(x))", scopes: []int{2}, vars: []string{"var x uint8"}},
	{line: "	case float64:", scopes: []int{3}},
	{line: "		f1(int(x)+1)", scopes: []int{3}, vars: []string{"var x float64"}},
	{line: "	}"},
	{line: "}"},
	{line: "func TestSelectScope() {"},
	{line: "	select {"},
	{line: "	case i := <- ch:", scopes: []int{1}},
	{line: "		f1(i)", scopes: []int{1}, vars: []string{"var i int"}},
	{line: "	case f := <- floatch:", scopes: []int{2}},
	{line: "		f1(int(f))", scopes: []int{2}, vars: []string{"var f float64"}},
	{line: "	}"},
	{line: "}"},
	{line: "func TestBlock() {", vars: []string{"var a int"}},
	{line: "	a := 1"},
	{line: "	{"},
	{line: "		b := 2", scopes: []int{1}, vars: []string{"var b int"}},
	{line: "		f1(b)", scopes: []int{1}},
	{line: "		f1(a)", scopes: []int{1}},
	{line: "	}"},
	{line: "}"},
	{line: "func TestDiscontiguousRanges() {", vars: []string{"var a int"}},
	{line: "	a := 0"},
	{line: "	f1(a)"},
	{line: "	{"},
	{line: "		b := 0", scopes: []int{1}, vars: []string{"var b int"}},
	{line: "		f2(b)", scopes: []int{1}},
	{line: "		if gretbool() {", scopes: []int{1}},
	{line: "			c := 0", scopes: []int{1, 2}, vars: []string{"var c int"}},
	{line: "			f3(c)", scopes: []int{1, 2}},
	{line: "		} else {"},
	{line: "			c := 1.1", scopes: []int{1, 3}, vars: []string{"var c float64"}},
	{line: "			f4(int(c))", scopes: []int{1, 3}},
	{line: "		}"},
	{line: "		f5(b)", scopes: []int{1}},
	{line: "	}"},
	{line: "	f6(a)"},
	{line: "}"},
	{line: "func TestClosureScope() {", vars: []string{"var a int", "var b int", "var f func(int)"}},
	{line: "	a := 1; b := 1"},
	{line: "	f := func(c int) {", scopes: []int{0}, vars: []string{"arg c int", "var &b *int", "var a int", "var d int"}, declBefore: []string{"&b", "a"}},
	{line: "		d := 3"},
	{line: "		f1(c); f1(d)"},
	{line: "		if e := 3; e != 0 {", scopes: []int{1}, vars: []string{"var e int"}},
	{line: "			f1(e)", scopes: []int{1}},
	{line: "			f1(a)", scopes: []int{1}},
	{line: "			b = 2", scopes: []int{1}},
	{line: "		}"},
	{line: "	}"},
	{line: "	f(3); f1(b)"},
	{line: "}"},
	{line: "func TestEscape() {"},
	{line: "	a := 1", vars: []string{"var a int"}},
	{line: "	{"},
	{line: "		b := 2", scopes: []int{1}, vars: []string{"var &b *int", "var p *int"}},
	{line: "		p := &b", scopes: []int{1}},
	{line: "		f1(a)", scopes: []int{1}},
	{line: "		leak(p)", scopes: []int{1}},
	{line: "	}"},
	{line: "}"},
	{line: "var fglob func() int"},
	{line: "func TestCaptureVar(flag bool) {"},
	{line: "	a := 1", vars: []string{"arg flag bool", "var a int"}}, // TODO(register args) restore "arg ~r1 func() int",
	{line: "	if flag {"},
	{line: "		b := 2", scopes: []int{1}, vars: []string{"var b int", "var f func() int"}},
	{line: "		f := func() int {", scopes: []int{1, 0}},
	{line: "			return b + 1"},
	{line: "		}"},
	{line: "		fglob = f", scopes: []int{1}},
	{line: "	}"},
	{line: "	f1(a)"},
	{line: "}"},
	{line: "func main() {"},
	{line: "	TestNestedFor()"},
	{line: "	TestOas2()"},
	{line: "	TestIfElse()"},
	{line: "	TestSwitch()"},
	{line: "	TestTypeSwitch()"},
	{line: "	TestSelectScope()"},
	{line: "	TestBlock()"},
	{line: "	TestDiscontiguousRanges()"},
	{line: "	TestClosureScope()"},
	{line: "	TestEscape()"},
	{line: "	TestCaptureVar(true)"},
	{line: "}"},
}

const detailOutput = false

// Compiles testfile checks that the description of lexical blocks emitted
// by the linker in debug_info, for each function in the main package,
// corresponds to what we expect it to be.
func TestScopeRanges(t *testing.T) {
	testenv.MustHaveGoBuild(t)
	t.Parallel()

	if !platform.ExecutableHasDWARF(runtime.GOOS, runtime.GOARCH) {
		t.Skipf("skipping on %s/%s: no DWARF symbol table in executables", runtime.GOOS, runtime.GOARCH)
	}

	src, f := gobuild(t, t.TempDir(), false, testfile)
	defer f.Close()

	// the compiler uses forward slashes for paths even on windows
	src = strings.Replace(src, "\\", "/", -1)

	pcln, err := f.PCLineTable()
	if err != nil {
		t.Fatal(err)
	}
	dwarfData, err := f.DWARF()
	if err != nil {
		t.Fatal(err)
	}
	dwarfReader := dwarfData.Reader()

	lines := make(map[line][]*lexblock)

	for {
		entry, err := dwarfReader.Next()
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil {
			break
		}

		if entry.Tag != dwarf.TagSubprogram {
			continue
		}

		name, ok := entry.Val(dwarf.AttrName).(string)
		if !ok || !strings.HasPrefix(name, "main.Test") {
			continue
		}

		var scope lexblock
		ctxt := scopexplainContext{
			dwarfData:   dwarfData,
			dwarfReader: dwarfReader,
			scopegen:    1,
		}

		readScope(&ctxt, &scope, entry)

		scope.markLines(pcln, lines)
	}

	anyerror := false
	for i := range testfile {
		tgt := testfile[i].scopes
		out := lines[line{src, i + 1}]

		if detailOutput {
			t.Logf("%s // %v", testfile[i].line, out)
		}

		scopesok := checkScopes(tgt, out)
		if !scopesok {
			t.Logf("mismatch at line %d %q: expected: %v got: %v\n", i, testfile[i].line, tgt, scopesToString(out))
		}

		varsok := true
		if testfile[i].vars != nil {
			if len(out) > 0 {
				varsok = checkVars(testfile[i].vars, out[len(out)-1].vars)
				if !varsok {
					t.Logf("variable mismatch at line %d %q for scope %d: expected: %v got: %v\n", i+1, testfile[i].line, out[len(out)-1].id, testfile[i].vars, out[len(out)-1].vars)
				}
				for j := range testfile[i].decl {
					if line := declLineForVar(out[len(out)-1].vars, testfile[i].decl[j]); line != i+1 {
						t.Errorf("wrong declaration line for variable %s, expected %d got: %d", testfile[i].decl[j], i+1, line)
					}
				}

				for j := range testfile[i].declBefore {
					if line := declLineForVar(out[len(out)-1].vars, testfile[i].declBefore[j]); line > i+1 {
						t.Errorf("wrong declaration line for variable %s, expected %d (or less) got: %d", testfile[i].declBefore[j], i+1, line)
					}
				}
			}
		}

		anyerror = anyerror || !scopesok || !varsok
	}

	if anyerror {
		t.Fatalf("mismatched output")
	}
}

func scopesToString(v []*lexblock) string {
	r := make([]string, len(v))
	for i, s := range v {
		r[i] = strconv.Itoa(s.id)
	}
	return "[ " + strings.Join(r, ", ") + " ]"
}

func checkScopes(tgt []int, out []*lexblock) bool {
	if len(out) > 0 {
		// omit scope 0
		out = out[1:]
	}
	if len(tgt) != len(out) {
		return false
	}
	for i := range tgt {
		if tgt[i] != out[i].id {
			return false
		}
	}
	return true
}

func checkVars(tgt []string, out []variable) bool {
	if len(tgt) != len(out) {
		return false
	}
	for i := range tgt {
		if tgt[i] != out[i].expr {
			return false
		}
	}
	return true
}

func declLineForVar(scope []variable, name string) int {
	for i := range scope {
		if scope[i].name() == name {
			return scope[i].declLine
		}
	}
	return -1
}

type lexblock struct {
	id     int
	ranges [][2]uint64
	vars   []variable
	scopes []lexblock
}

type variable struct {
	expr     string
	declLine int
}

func (v *variable) name() string {
	return strings.Split(v.expr, " ")[1]
}

type line struct {
	file   string
	lineno int
}

type scopexplainContext struct {
	dwarfData   *dwarf.Data
	dwarfReader *dwarf.Reader
	scopegen    int
}

// readScope reads the DW_TAG_lexical_block or the DW_TAG_subprogram in
// entry and writes a description in scope.
// Nested DW_TAG_lexical_block entries are read recursively.
func readScope(ctxt *scopexplainContext, scope *lexblock, entry *dwarf.Entry) {
	var err error
	scope.ranges, err = ctxt.dwarfData.Ranges(entry)
	if err != nil {
		panic(err)
	}
	for {
		e, err := ctxt.dwarfReader.Next()
		if err != nil {
			panic(err)
		}
		switch e.Tag {
		case 0:
			slices.SortFunc(scope.vars, func(a, b variable) int {
				return cmp.Compare(a.expr, b.expr)
			})
			return
		case dwarf.TagFormalParameter:
			typ, err := ctxt.dwarfData.Type(e.Val(dwarf.AttrType).(dwarf.Offset))
			if err != nil {
				panic(err)
			}
			scope.vars = append(scope.vars, entryToVar(e, "arg", typ))
		case dwarf.TagVariable:
			typ, err := ctxt.dwarfData.Type(e.Val(dwarf.AttrType).(dwarf.Offset))
			if err != nil {
				panic(err)
			}
			scope.vars = append(scope.vars, entryToVar(e, "var", typ))
		case dwarf.TagLexDwarfBlock:
			scope.scopes = append(scope.scopes, lexblock{id: ctxt.scopegen})
			ctxt.scopegen++
			readScope(ctxt, &scope.scopes[len(scope.scopes)-1], e)
		}
	}
}

func entryToVar(e *dwarf.Entry, kind string, typ dwarf.Type) variable {
	return variable{
		fmt.Sprintf("%s %s %s", kind, e.Val(dwarf.AttrName).(string), typ.String()),
		int(e.Val(dwarf.AttrDeclLine).(int64)),
	}
}

// markLines marks all lines that belong to this scope with this scope
// Recursively calls markLines for all children scopes.
func (scope *lexblock) markLines(pcln objfile.Liner, lines map[line][]*lexblock) {
	for _, r := range scope.ranges {
		for pc := r[0]; pc < r[1]; pc++ {
			file, lineno, _ := pcln.PCToLine(pc)
			l := line{file, lineno}
			if len(lines[l]) == 0 || lines[l][len(lines[l])-1] != scope {
				lines[l] = append(lines[l], scope)
			}
		}
	}

	for i := range scope.scopes {
		scope.scopes[i].markLines(pcln, lines)
	}
}

func gobuild(t *testing.T, dir string, optimized bool, testfile []testline) (string, *objfile.File) {
	src := filepath.Join(dir, "test.go")
	dst := filepath.Join(dir, "out.o")

	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	for i := range testfile {
		f.Write([]byte(testfile[i].line))
		f.Write([]byte{'\n'})
	}
	f.Close()

	args := []string{"build"}
	if !optimized {
		args = append(args, "-gcflags=-N -l")
	}
	args = append(args, "-o", dst, src)

	cmd := testenv.Command(t, testenv.GoToolPath(t), args...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Logf("build: %s\n", string(b))
		t.Fatal(err)
	}

	pkg, err := objfile.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	return src, pkg
}

// TestEmptyDwarfRanges tests that no list entry in debug_ranges has start == end.
// See issue #23928.
func TestEmptyDwarfRanges(t *testing.T) {
	testenv.MustHaveGoRun(t)
	t.Parallel()

	if !platform.ExecutableHasDWARF(runtime.GOOS, runtime.GOARCH) {
		t.Skipf("skipping on %s/%s: no DWARF symbol table in executables", runtime.GOOS, runtime.GOARCH)
	}

	_, f := gobuild(t, t.TempDir(), true, []testline{{line: "package main"}, {line: "func main(){ println(\"hello\") }"}})
	defer f.Close()

	dwarfData, err := f.DWARF()
	if err != nil {
		t.Fatal(err)
	}
	dwarfReader := dwarfData.Reader()

	for {
		entry, err := dwarfReader.Next()
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil {
			break
		}

		ranges, err := dwarfData.Ranges(entry)
		if err != nil {
			t.Fatal(err)
		}
		if ranges == nil {
			continue
		}

		for _, rng := range ranges {
			if rng[0] == rng[1] {
				t.Errorf("range entry with start == end: %v", rng)
			}
		}
	}
}
```