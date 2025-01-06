Response:
Let's break down the thought process for analyzing this Go test file.

**1. Initial Understanding: Context and Purpose**

The filename `doc_test.go` and the package `main` within `cmd/doc` immediately suggest this is testing functionality related to the `go doc` command. The `// Copyright ...` header reinforces this. The `import` statements provide crucial clues about the core functionalities being tested (package loading, file system interaction, regular expressions, testing framework, etc.).

**2. Deconstructing `TestMain`:**

* **`buildCtx.GOPATH = ""` and `testGOPATH = true`:** This is a strong indicator that the tests need to run in a controlled environment, isolated from the user's actual Go setup. It's forcing a specific GOPATH mode, likely for consistency and avoiding interference.
* **`buildCtx.GOROOT = testenv.GOROOT(nil)` and `build.Default.GOROOT = ...`:**  This suggests ensuring the tests use the correct Go root directory, especially important in environments where the runtime might not have the accurate path. The comment about `-trimpath` further clarifies why this is necessary.
* **`dirsInit(...)`:** This is the most important part. It's explicitly setting up the directories that `go doc` will consider for package lookup. The inclusion of `testdata` and its subdirectories is a clear sign that the tests rely on specific files within that directory. The comment about `testdata` directories being normally ignored but being "hacked around" is a key observation.

**3. Analyzing Helper Functions and Data Structures:**

* **`maybeSkip`:** This is a standard testing utility to skip tests on certain platforms (like iOS).
* **`isDotSlashTest` and `TestIsDotSlashPath`:** This tests a utility function (`isDotSlash`) likely used to handle path prefixes like `./` and `../` in package names, which is relevant to how `go doc` interprets user input. The provided test cases are very helpful in understanding the expected behavior.
* **`test` struct:**  This is the core structure for defining the main tests. It clearly outlines:
    * `name`: A descriptive name for the test case.
    * `args`:  The arguments that would be passed to the `go doc` command.
    * `yes`: Regular expressions that *should* be present in the output.
    * `no`: Regular expressions that *should not* be present in the output.
* **`tests` slice:** This is where the bulk of the test cases are defined, covering various scenarios and flags for `go doc`. Carefully examining these test cases is essential to understanding the functionality being tested.

**4. Understanding `TestDoc`:**

* **`maybeSkip(t)`:** Again, platform skipping.
* **`defer log.SetOutput(log.Writer())`:**  This ensures that any logging during the test is captured.
* **The `for _, test := range tests` loop:** This iterates through each defined test case.
* **`bytes.Buffer`, `flag.FlagSet`, `log.SetOutput`:** Setting up the necessary components to simulate running `go doc` and capturing its output.
* **`do(&b, &flagSet, test.args)`:** This is the crucial call – it's the function under test. Based on the context, it simulates the execution of the `go doc` command with the specified arguments.
* **The loops for `test.yes` and `test.no`:** These verify the output of `go doc` against the expected regular expressions, confirming the correctness of the output.
* **`bytes.Count(output, []byte("TYPES\n")) > 1`:** This checks for duplicate headers, indicating a potential issue in the output formatting.
* **`if failed { t.Logf("\n%s", output) }`:**  Prints the output for debugging when tests fail.

**5. Analyzing `TestMultiplePackages` and `TestTwoArgLookup`:**

These tests specifically address how `go doc` resolves package and symbol names, especially when there are multiple packages with similar names. They highlight the search and disambiguation logic within `go doc`.

**6. Analyzing `TestDotSlashLookup`:**

This test targets how `go doc` handles relative import paths, a common use case when working within a Go project.

**7. Analyzing `TestNoPackageClauseWhenNoMatch`:**

This tests a specific bug fix or improvement where `go doc` should not print spurious output when no matching symbol is found.

**8. Analyzing `TestTrim`:**

This tests a utility function (`trim`) likely used for manipulating file paths, possibly in the context of displaying relative paths or shortening output.

**9. Inferring Functionality and Providing Examples:**

Based on the test cases and the overall structure, I could infer the core functionality of `go doc` and provide relevant Go code examples. The key was to connect the test scenarios (arguments passed to `do`) with the expected behavior (the `yes` and `no` regular expressions).

**Self-Correction/Refinement during Analysis:**

* Initially, I might not immediately understand the significance of `dirsInit`. However, seeing the hardcoded `testdata` paths would lead me to realize it's about controlling the package lookup scope.
* When seeing tests with `-u`, I'd deduce that it's related to showing unexported symbols.
*  The regular expressions in `yes` and `no` are crucial. Analyzing them carefully provides the best insight into what `go doc` is supposed to output in different situations.
*  Realizing that `do` is the core function being tested is a key step. The rest of the test code is setup and verification around this function.

By systematically breaking down the code, analyzing the test cases, and understanding the purpose of each part, I could accurately deduce the functionality of the `go doc` command as tested by this file.
这个文件 `go/src/cmd/doc/doc_test.go` 是 Go 语言 `doc` 命令的测试文件。 `doc` 命令用于提取 Go 语言包和其中导出的标识符的文档注释。

以下是 `doc_test.go` 中主要的功能点：

**1. 测试 `go doc` 命令的核心功能:**

* **提取包的文档:** 测试 `go doc <package_path>` 能否正确提取整个包的文档注释，包括包级别的注释，常量、变量、函数、类型等的注释。
* **提取特定标识符的文档:** 测试 `go doc <package_path>.<identifier>` 能否正确提取包中特定导出标识符（常量、变量、函数、类型、方法、字段）的文档注释。
* **处理导出和未导出的标识符:** 通过 `-u` 标志，测试 `go doc` 是否能正确显示未导出的标识符的文档。
* **处理不同类型的标识符:** 测试对常量、变量、函数、结构体、接口、方法、字段等不同类型标识符的文档提取。
* **处理多行注释和格式化注释:** 测试 `go doc` 是否能正确处理和显示多行以及包含特定格式的文档注释（例如，代码示例）。
* **处理类型别名:** 测试 `go doc` 如何显示类型别名的文档。
* **处理约束类型 (Constraints):** 测试 `go doc` 如何显示接口类型的约束。

**2. 测试 `go doc` 命令的各种标志:**

* **`-all`:** 测试 `-all` 标志是否能显示所有（包括未导出）的常量、变量、函数和类型。
* **`-short`:** 测试 `-short` 标志是否能生成更简洁的输出。
* **`-u`:** 测试 `-u` 标志是否能显示未导出的标识符的文档。
* **`-src`:** 测试 `-src` 标志是否能显示函数和方法的源代码。
* **`-c`:** 测试 `-c` 标志是否启用大小写敏感的匹配。

**3. 测试 `go doc` 命令的参数解析和处理:**

* **包路径解析:** 测试 `go doc` 能否正确解析和找到指定的包路径。
* **标识符解析:** 测试 `go doc` 能否正确解析和找到指定包中的标识符。
* **处理相对路径 (`./`)**: 测试 `go doc` 能否正确处理以 `./` 开头的相对路径。

**4. 测试 `go doc` 命令在不同场景下的行为:**

* **在没有匹配项时的情况:** 测试当找不到指定的包或标识符时，`go doc` 是否能给出合理的错误提示，并且不会输出不必要的信息。
* **处理多个同名包的情况:** 测试当存在多个同名包时，`go doc` 如何进行查找和提示。

**如果你能推理出它是什么go语言功能的实现，请用go代码举例说明:**

这个测试文件主要测试的是 `go/doc` 包和 `go/build` 包的功能，这两个包是 Go 语言工具链中用于解析和提取 Go 代码信息的关键部分。

* **`go/doc` 包:**  负责解析 Go 源文件中的文档注释，并将它们组织成结构化的数据，方便进一步处理和展示。
* **`go/build` 包:**  负责查找和加载 Go 语言包，包括确定包的源代码位置、依赖关系等。

下面是一些基于测试文件内容推断出的 `go/doc` 和 `go/build` 包的使用示例：

```go
package main

import (
	"fmt"
	"go/build"
	"go/doc"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
)

func main() {
	// 使用 go/build 包查找指定的包
	pkgInfo, err := build.Import("fmt", ".", build.ImportMode(0))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Package Name:", pkgInfo.Name)
	fmt.Println("Import Path:", pkgInfo.ImportPath)
	fmt.Println("Go Files:", pkgInfo.GoFiles)

	// 使用 go/parser 包解析包中的一个 Go 文件
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filepath.Join(pkgInfo.Dir, "print.go"), nil, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}

	// 使用 go/doc 包提取包的文档信息
	packageDoc := doc.New(node, pkgInfo.ImportPath, 0) // flags 可以控制是否包含未导出的标识符
	fmt.Println("\nPackage Doc:", packageDoc.Doc)

	// 遍历包中的常量并打印其文档
	fmt.Println("\nConstants:")
	for _, c := range packageDoc.Consts {
		fmt.Printf("  Name: %s, Doc: %s\n", c.Names[0], c.Doc)
	}

	// 遍历包中的函数并打印其文档
	fmt.Println("\nFunctions:")
	for _, f := range packageDoc.Funcs {
		fmt.Printf("  Name: %s, Doc: %s\n", f.Name, f.Doc)
	}

	// 遍历包中的类型并打印其文档
	fmt.Println("\nTypes:")
	for _, t := range packageDoc.Types {
		fmt.Printf("  Name: %s, Doc: %s\n", t.Name, t.Doc)
		// 遍历类型的方法并打印其文档
		for _, m := range t.Methods {
			fmt.Printf("    Method: %s, Doc: %s\n", m.Name, m.Doc)
		}
	}
}
```

**假设的输入与输出 (基于上面的代码示例):**

**假设执行上述代码。**

**可能的输出:**

```
Package Name: fmt
Import Path: fmt
Go Files: [doc.go format.go fscan.go print.go scan.go sprint.go]

Package Doc: Package fmt implements formatted I/O with functions analogous to C's printf and scanf.

Constants:
  Name: Printf, Doc: Printf formats according to a format specifier and writes to standard output.
  ...

Functions:
  Name: Printf, Doc: Printf formats according to a format specifier and writes to standard output.
  ...

Types:
  Name: Formatter, Doc: A Formatter is implemented by types that know how to render themselves in a specified format.
    Method: Format, Doc: Format writes to w.
  ...
```

**命令行参数的具体处理:**

虽然 `doc_test.go` 本身不直接处理命令行参数，但它测试的 `doc` 命令会处理。根据测试用例，我们可以推断出 `doc` 命令会处理以下参数：

* **`[package_path]`:**  指定要查看文档的包的导入路径。可以是标准库的包，也可以是用户自定义的包。
* **`[package_path.identifier]`:** 指定要查看文档的包和其中的特定标识符。
* **`-all`:** 显示所有（包括未导出）的常量、变量、函数和类型。
* **`-short`:** 生成更简洁的输出。
* **`-u`:** 显示未导出的标识符的文档。
* **`-src`:** 显示函数和方法的源代码。
* **`-c`:** 启用大小写敏感的匹配。

`doc` 命令内部会使用 `flag` 包来解析这些命令行参数。

**使用者易犯错的点:**

1. **包路径错误:**  用户可能会输入错误的包导入路径，导致 `go doc` 无法找到指定的包。例如，输入 `strs` 而不是 `strings`。

   ```bash
   go doc strs.Contains  // 错误，找不到 strs 包
   go doc strings.Contains // 正确
   ```

2. **标识符拼写错误或大小写错误:**  用户可能会拼错标识符的名称，或者在没有使用 `-c` 标志的情况下，大小写不匹配，导致 `go doc` 找不到指定的标识符。

   ```bash
   go doc strings.contain  // 错误，拼写错误
   go doc strings.Contains // 正确

   go doc -c strings.contains // 使用 -c 标志可以匹配小写
   ```

3. **忘记使用 `-u` 查看未导出标识符的文档:** 用户可能想要查看未导出标识符的文档，但忘记使用 `-u` 标志。

   ```bash
   go doc cmd/doc/testdata.internalConstant // 默认情况下看不到未导出的
   go doc -u cmd/doc/testdata.internalConstant // 使用 -u 可以看到
   ```

4. **在错误的工作目录下使用相对路径:** 当使用 `./` 开头的相对路径时，用户需要在正确的 Go 项目的 `src` 目录下执行 `go doc` 命令，否则可能找不到对应的包。

   ```bash
   # 假设当前不在 go/src 目录下
   go doc ./cmd/doc  // 可能找不到 cmd/doc 包

   cd $GOROOT/src
   go doc ./cmd/doc  // 正确
   ```

总而言之，`doc_test.go` 是对 `go doc` 命令的功能和各种使用场景进行全面测试的重要组成部分，确保了 `go doc` 命令的正确性和可靠性。

Prompt: 
```
这是路径为go/src/cmd/doc/doc_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"go/build"
	"internal/testenv"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// Clear GOPATH so we don't access the user's own packages in the test.
	buildCtx.GOPATH = ""
	testGOPATH = true // force GOPATH mode; module test is in cmd/go/testdata/script/mod_doc.txt

	// Set GOROOT in case runtime.GOROOT is wrong (for example, if the test was
	// built with -trimpath). dirsInit would identify it using 'go env GOROOT',
	// but we can't be sure that the 'go' in $PATH is the right one either.
	buildCtx.GOROOT = testenv.GOROOT(nil)
	build.Default.GOROOT = testenv.GOROOT(nil)

	// Add $GOROOT/src/cmd/doc/testdata explicitly so we can access its contents in the test.
	// Normally testdata directories are ignored, but sending it to dirs.scan directly is
	// a hack that works around the check.
	testdataDir, err := filepath.Abs("testdata")
	if err != nil {
		panic(err)
	}
	dirsInit(
		Dir{importPath: "testdata", dir: testdataDir},
		Dir{importPath: "testdata/nested", dir: filepath.Join(testdataDir, "nested")},
		Dir{importPath: "testdata/nested/nested", dir: filepath.Join(testdataDir, "nested", "nested")})

	os.Exit(m.Run())
}

func maybeSkip(t *testing.T) {
	if runtime.GOOS == "ios" {
		t.Skip("iOS does not have a full file tree")
	}
}

type isDotSlashTest struct {
	str    string
	result bool
}

var isDotSlashTests = []isDotSlashTest{
	{``, false},
	{`x`, false},
	{`...`, false},
	{`.../`, false},
	{`...\`, false},

	{`.`, true},
	{`./`, true},
	{`.\`, true},
	{`./x`, true},
	{`.\x`, true},

	{`..`, true},
	{`../`, true},
	{`..\`, true},
	{`../x`, true},
	{`..\x`, true},
}

func TestIsDotSlashPath(t *testing.T) {
	for _, test := range isDotSlashTests {
		if result := isDotSlash(test.str); result != test.result {
			t.Errorf("isDotSlash(%q) = %t; expected %t", test.str, result, test.result)
		}
	}
}

type test struct {
	name string
	args []string // Arguments to "[go] doc".
	yes  []string // Regular expressions that should match.
	no   []string // Regular expressions that should not match.
}

const p = "cmd/doc/testdata"

var tests = []test{
	// Sanity check.
	{
		"sanity check",
		[]string{p},
		[]string{`type ExportedType struct`},
		nil,
	},

	// Package dump includes import, package statement.
	{
		"package clause",
		[]string{p},
		[]string{`package pkg.*cmd/doc/testdata`},
		nil,
	},

	// Constants.
	// Package dump
	{
		"full package",
		[]string{p},
		[]string{
			`Package comment`,
			`const ExportedConstant = 1`,                                   // Simple constant.
			`const ConstOne = 1`,                                           // First entry in constant block.
			`const ConstFive ...`,                                          // From block starting with unexported constant.
			`var ExportedVariable = 1`,                                     // Simple variable.
			`var VarOne = 1`,                                               // First entry in variable block.
			`func ExportedFunc\(a int\) bool`,                              // Function.
			`func ReturnUnexported\(\) unexportedType`,                     // Function with unexported return type.
			`type ExportedType struct{ ... }`,                              // Exported type.
			`const ExportedTypedConstant ExportedType = iota`,              // Typed constant.
			`const ExportedTypedConstant_unexported unexportedType`,        // Typed constant, exported for unexported type.
			`const ConstLeft2 uint64 ...`,                                  // Typed constant using unexported iota.
			`const ConstGroup1 unexportedType = iota ...`,                  // Typed constant using unexported type.
			`const ConstGroup4 ExportedType = ExportedType{}`,              // Typed constant using exported type.
			`const MultiLineConst = ...`,                                   // Multi line constant.
			`var MultiLineVar = map\[struct{ ... }\]struct{ ... }{ ... }`,  // Multi line variable.
			`func MultiLineFunc\(x interface{ ... }\) \(r struct{ ... }\)`, // Multi line function.
			`var LongLine = newLongLine\(("someArgument[1-4]", ){4}...\)`,  // Long list of arguments.
			`type T1 = T2`,                                                 // Type alias
			`type SimpleConstraint interface{ ... }`,
			`type TildeConstraint interface{ ... }`,
			`type StructConstraint interface{ ... }`,
		},
		[]string{
			`const internalConstant = 2`,       // No internal constants.
			`var internalVariable = 2`,         // No internal variables.
			`func internalFunc(a int) bool`,    // No internal functions.
			`Comment about exported constant`,  // No comment for single constant.
			`Comment about exported variable`,  // No comment for single variable.
			`Comment about block of constants`, // No comment for constant block.
			`Comment about block of variables`, // No comment for variable block.
			`Comment before ConstOne`,          // No comment for first entry in constant block.
			`Comment before VarOne`,            // No comment for first entry in variable block.
			`ConstTwo = 2`,                     // No second entry in constant block.
			`VarTwo = 2`,                       // No second entry in variable block.
			`VarFive = 5`,                      // From block starting with unexported variable.
			`type unexportedType`,              // No unexported type.
			`unexportedTypedConstant`,          // No unexported typed constant.
			`\bField`,                          // No fields.
			`Method`,                           // No methods.
			`someArgument[5-8]`,                // No truncated arguments.
			`type T1 T2`,                       // Type alias does not display as type declaration.
			`ignore:directive`,                 // Directives should be dropped.
		},
	},
	// Package dump -all
	{
		"full package",
		[]string{"-all", p},
		[]string{
			`package pkg .*import`,
			`Package comment`,
			`CONSTANTS`,
			`Comment before ConstOne`,
			`ConstOne = 1`,
			`ConstTwo = 2 // Comment on line with ConstTwo`,
			`ConstFive`,
			`ConstSix`,
			`Const block where first entry is unexported`,
			`ConstLeft2, constRight2 uint64`,
			`constLeft3, ConstRight3`,
			`ConstLeft4, ConstRight4`,
			`Duplicate = iota`,
			`const CaseMatch = 1`,
			`const Casematch = 2`,
			`const ExportedConstant = 1`,
			`const MultiLineConst = `,
			`MultiLineString1`,
			`VARIABLES`,
			`Comment before VarOne`,
			`VarOne = 1`,
			`Comment about block of variables`,
			`VarFive = 5`,
			`var ExportedVariable = 1`,
			`var ExportedVarOfUnExported unexportedType`,
			`var LongLine = newLongLine\(`,
			`var MultiLineVar = map\[struct {`,
			`FUNCTIONS`,
			`func ExportedFunc\(a int\) bool`,
			`Comment about exported function`,
			`func MultiLineFunc\(x interface`,
			`func ReturnUnexported\(\) unexportedType`,
			`TYPES`,
			`type ExportedInterface interface`,
			`type ExportedStructOneField struct`,
			`type ExportedType struct`,
			`Comment about exported type`,
			`const ConstGroup4 ExportedType = ExportedType`,
			`ExportedTypedConstant ExportedType = iota`,
			`Constants tied to ExportedType`,
			`func ExportedTypeConstructor\(\) \*ExportedType`,
			`Comment about constructor for exported type`,
			`func ReturnExported\(\) ExportedType`,
			`func \(ExportedType\) ExportedMethod\(a int\) bool`,
			`Comment about exported method`,
			`type T1 = T2`,
			`type T2 int`,
			`type SimpleConstraint interface {`,
			`type TildeConstraint interface {`,
			`type StructConstraint interface {`,
			`BUG: function body note`,
		},
		[]string{
			`constThree`,
			`_, _ uint64 = 2 \* iota, 1 << iota`,
			`constLeft1, constRight1`,
			`duplicate`,
			`varFour`,
			`func internalFunc`,
			`unexportedField`,
			`func \(unexportedType\)`,
			`ignore:directive`,
		},
	},
	// Package with just the package declaration. Issue 31457.
	{
		"only package declaration",
		[]string{"-all", p + "/nested/empty"},
		[]string{`package empty .*import`},
		nil,
	},
	// Package dump -short
	{
		"full package with -short",
		[]string{`-short`, p},
		[]string{
			`const ExportedConstant = 1`,               // Simple constant.
			`func ReturnUnexported\(\) unexportedType`, // Function with unexported return type.
		},
		[]string{
			`MultiLine(String|Method|Field)`, // No data from multi line portions.
		},
	},
	// Package dump -u
	{
		"full package with u",
		[]string{`-u`, p},
		[]string{
			`const ExportedConstant = 1`,               // Simple constant.
			`const internalConstant = 2`,               // Internal constants.
			`func internalFunc\(a int\) bool`,          // Internal functions.
			`func ReturnUnexported\(\) unexportedType`, // Function with unexported return type.
		},
		[]string{
			`Comment about exported constant`,  // No comment for simple constant.
			`Comment about block of constants`, // No comment for constant block.
			`Comment about internal function`,  // No comment for internal function.
			`MultiLine(String|Method|Field)`,   // No data from multi line portions.
			`ignore:directive`,
		},
	},
	// Package dump -u -all
	{
		"full package",
		[]string{"-u", "-all", p},
		[]string{
			`package pkg .*import`,
			`Package comment`,
			`CONSTANTS`,
			`Comment before ConstOne`,
			`ConstOne += 1`,
			`ConstTwo += 2 // Comment on line with ConstTwo`,
			`constThree = 3 // Comment on line with constThree`,
			`ConstFive`,
			`const internalConstant += 2`,
			`Comment about internal constant`,
			`VARIABLES`,
			`Comment before VarOne`,
			`VarOne += 1`,
			`Comment about block of variables`,
			`varFour += 4`,
			`VarFive += 5`,
			`varSix += 6`,
			`var ExportedVariable = 1`,
			`var LongLine = newLongLine\(`,
			`var MultiLineVar = map\[struct {`,
			`var internalVariable = 2`,
			`Comment about internal variable`,
			`FUNCTIONS`,
			`func ExportedFunc\(a int\) bool`,
			`Comment about exported function`,
			`func MultiLineFunc\(x interface`,
			`func internalFunc\(a int\) bool`,
			`Comment about internal function`,
			`func newLongLine\(ss .*string\)`,
			`TYPES`,
			`type ExportedType struct`,
			`type T1 = T2`,
			`type T2 int`,
			`type unexportedType int`,
			`Comment about unexported type`,
			`ConstGroup1 unexportedType = iota`,
			`ConstGroup2`,
			`ConstGroup3`,
			`ExportedTypedConstant_unexported unexportedType = iota`,
			`Constants tied to unexportedType`,
			`const unexportedTypedConstant unexportedType = 1`,
			`func ReturnUnexported\(\) unexportedType`,
			`func \(unexportedType\) ExportedMethod\(\) bool`,
			`func \(unexportedType\) unexportedMethod\(\) bool`,
		},
		[]string{
			`ignore:directive`,
		},
	},

	// Single constant.
	{
		"single constant",
		[]string{p, `ExportedConstant`},
		[]string{
			`Comment about exported constant`, // Include comment.
			`const ExportedConstant = 1`,
		},
		nil,
	},
	// Single constant -u.
	{
		"single constant with -u",
		[]string{`-u`, p, `internalConstant`},
		[]string{
			`Comment about internal constant`, // Include comment.
			`const internalConstant = 2`,
		},
		nil,
	},
	// Block of constants.
	{
		"block of constants",
		[]string{p, `ConstTwo`},
		[]string{
			`Comment before ConstOne.\n.*ConstOne = 1`,    // First...
			`ConstTwo = 2.*Comment on line with ConstTwo`, // And second show up.
			`Comment about block of constants`,            // Comment does too.
		},
		[]string{
			`constThree`, // No unexported constant.
		},
	},
	// Block of constants -u.
	{
		"block of constants with -u",
		[]string{"-u", p, `constThree`},
		[]string{
			`constThree = 3.*Comment on line with constThree`,
		},
		nil,
	},
	// Block of constants -src.
	{
		"block of constants with -src",
		[]string{"-src", p, `ConstTwo`},
		[]string{
			`Comment about block of constants`, // Top comment.
			`ConstOne.*=.*1`,                   // Each constant seen.
			`ConstTwo.*=.*2.*Comment on line with ConstTwo`,
			`constThree`, // Even unexported constants.
		},
		nil,
	},
	// Block of constants with carryover type from unexported field.
	{
		"block of constants with carryover type",
		[]string{p, `ConstLeft2`},
		[]string{
			`ConstLeft2, constRight2 uint64`,
			`constLeft3, ConstRight3`,
			`ConstLeft4, ConstRight4`,
		},
		nil,
	},
	// Block of constants -u with carryover type from unexported field.
	{
		"block of constants with carryover type",
		[]string{"-u", p, `ConstLeft2`},
		[]string{
			`_, _ uint64 = 2 \* iota, 1 << iota`,
			`constLeft1, constRight1`,
			`ConstLeft2, constRight2`,
			`constLeft3, ConstRight3`,
			`ConstLeft4, ConstRight4`,
		},
		nil,
	},

	// Single variable.
	{
		"single variable",
		[]string{p, `ExportedVariable`},
		[]string{
			`ExportedVariable`, // Include comment.
			`var ExportedVariable = 1`,
		},
		nil,
	},
	// Single variable -u.
	{
		"single variable with -u",
		[]string{`-u`, p, `internalVariable`},
		[]string{
			`Comment about internal variable`, // Include comment.
			`var internalVariable = 2`,
		},
		nil,
	},
	// Block of variables.
	{
		"block of variables",
		[]string{p, `VarTwo`},
		[]string{
			`Comment before VarOne.\n.*VarOne = 1`,    // First...
			`VarTwo = 2.*Comment on line with VarTwo`, // And second show up.
			`Comment about block of variables`,        // Comment does too.
		},
		[]string{
			`varThree= 3`, // No unexported variable.
		},
	},
	// Block of variables -u.
	{
		"block of variables with -u",
		[]string{"-u", p, `varThree`},
		[]string{
			`varThree = 3.*Comment on line with varThree`,
		},
		nil,
	},

	// Function.
	{
		"function",
		[]string{p, `ExportedFunc`},
		[]string{
			`Comment about exported function`, // Include comment.
			`func ExportedFunc\(a int\) bool`,
		},
		nil,
	},
	// Function -u.
	{
		"function with -u",
		[]string{"-u", p, `internalFunc`},
		[]string{
			`Comment about internal function`, // Include comment.
			`func internalFunc\(a int\) bool`,
		},
		nil,
	},
	// Function with -src.
	{
		"function with -src",
		[]string{"-src", p, `ExportedFunc`},
		[]string{
			`Comment about exported function`, // Include comment.
			`func ExportedFunc\(a int\) bool`,
			`return true != false`, // Include body.
		},
		nil,
	},

	// Type.
	{
		"type",
		[]string{p, `ExportedType`},
		[]string{
			`Comment about exported type`, // Include comment.
			`type ExportedType struct`,    // Type definition.
			`Comment before exported field.*\n.*ExportedField +int` +
				`.*Comment on line with exported field`,
			`ExportedEmbeddedType.*Comment on line with exported embedded field`,
			`Has unexported fields`,
			`func \(ExportedType\) ExportedMethod\(a int\) bool`,
			`const ExportedTypedConstant ExportedType = iota`, // Must include associated constant.
			`func ExportedTypeConstructor\(\) \*ExportedType`, // Must include constructor.
			`io.Reader.*Comment on line with embedded Reader`,
		},
		[]string{
			`unexportedField`,               // No unexported field.
			`int.*embedded`,                 // No unexported embedded field.
			`Comment about exported method`, // No comment about exported method.
			`unexportedMethod`,              // No unexported method.
			`unexportedTypedConstant`,       // No unexported constant.
			`error`,                         // No embedded error.
		},
	},
	// Type with -src. Will see unexported fields.
	{
		"type",
		[]string{"-src", p, `ExportedType`},
		[]string{
			`Comment about exported type`, // Include comment.
			`type ExportedType struct`,    // Type definition.
			`Comment before exported field`,
			`ExportedField.*Comment on line with exported field`,
			`ExportedEmbeddedType.*Comment on line with exported embedded field`,
			`unexportedType.*Comment on line with unexported embedded field`,
			`func \(ExportedType\) ExportedMethod\(a int\) bool`,
			`const ExportedTypedConstant ExportedType = iota`, // Must include associated constant.
			`func ExportedTypeConstructor\(\) \*ExportedType`, // Must include constructor.
			`io.Reader.*Comment on line with embedded Reader`,
		},
		[]string{
			`Comment about exported method`, // No comment about exported method.
			`unexportedMethod`,              // No unexported method.
			`unexportedTypedConstant`,       // No unexported constant.
		},
	},
	// Type -all.
	{
		"type",
		[]string{"-all", p, `ExportedType`},
		[]string{
			`type ExportedType struct {`,                        // Type definition as source.
			`Comment about exported type`,                       // Include comment afterwards.
			`const ConstGroup4 ExportedType = ExportedType\{\}`, // Related constants.
			`ExportedTypedConstant ExportedType = iota`,
			`Constants tied to ExportedType`,
			`func ExportedTypeConstructor\(\) \*ExportedType`,
			`Comment about constructor for exported type.`,
			`func ReturnExported\(\) ExportedType`,
			`func \(ExportedType\) ExportedMethod\(a int\) bool`,
			`Comment about exported method.`,
			`func \(ExportedType\) Uncommented\(a int\) bool\n\n`, // Ensure line gap after method with no comment
		},
		[]string{
			`unexportedType`,
		},
	},
	// Type T1 dump (alias).
	{
		"type T1",
		[]string{p + ".T1"},
		[]string{
			`type T1 = T2`,
		},
		[]string{
			`type T1 T2`,
			`type ExportedType`,
		},
	},
	// Type -u with unexported fields.
	{
		"type with unexported fields and -u",
		[]string{"-u", p, `ExportedType`},
		[]string{
			`Comment about exported type`, // Include comment.
			`type ExportedType struct`,    // Type definition.
			`Comment before exported field.*\n.*ExportedField +int`,
			`unexportedField.*int.*Comment on line with unexported field`,
			`ExportedEmbeddedType.*Comment on line with exported embedded field`,
			`\*ExportedEmbeddedType.*Comment on line with exported embedded \*field`,
			`\*qualified.ExportedEmbeddedType.*Comment on line with exported embedded \*selector.field`,
			`unexportedType.*Comment on line with unexported embedded field`,
			`\*unexportedType.*Comment on line with unexported embedded \*field`,
			`io.Reader.*Comment on line with embedded Reader`,
			`error.*Comment on line with embedded error`,
			`func \(ExportedType\) unexportedMethod\(a int\) bool`,
			`unexportedTypedConstant`,
		},
		[]string{
			`Has unexported fields`,
		},
	},
	// Unexported type with -u.
	{
		"unexported type with -u",
		[]string{"-u", p, `unexportedType`},
		[]string{
			`Comment about unexported type`, // Include comment.
			`type unexportedType int`,       // Type definition.
			`func \(unexportedType\) ExportedMethod\(\) bool`,
			`func \(unexportedType\) unexportedMethod\(\) bool`,
			`ExportedTypedConstant_unexported unexportedType = iota`,
			`const unexportedTypedConstant unexportedType = 1`,
		},
		nil,
	},

	// Interface.
	{
		"interface type",
		[]string{p, `ExportedInterface`},
		[]string{
			`Comment about exported interface`, // Include comment.
			`type ExportedInterface interface`, // Interface definition.
			`Comment before exported method.\n.*//\n.*//	// Code block showing how to use ExportedMethod\n.*//	func DoSomething\(\) error {\n.*//		ExportedMethod\(\)\n.*//		return nil\n.*//	}\n.*//.*\n.*ExportedMethod\(\)` +
				`.*Comment on line with exported method`,
			`io.Reader.*Comment on line with embedded Reader`,
			`error.*Comment on line with embedded error`,
			`Has unexported methods`,
		},
		[]string{
			`unexportedField`,               // No unexported field.
			`Comment about exported method`, // No comment about exported method.
			`unexportedMethod`,              // No unexported method.
			`unexportedTypedConstant`,       // No unexported constant.
		},
	},
	// Interface -u with unexported methods.
	{
		"interface type with unexported methods and -u",
		[]string{"-u", p, `ExportedInterface`},
		[]string{
			`Comment about exported interface`, // Include comment.
			`type ExportedInterface interface`, // Interface definition.
			`Comment before exported method.\n.*//\n.*//	// Code block showing how to use ExportedMethod\n.*//	func DoSomething\(\) error {\n.*//		ExportedMethod\(\)\n.*//		return nil\n.*//	}\n.*//.*\n.*ExportedMethod\(\)` + `.*Comment on line with exported method`,
			`unexportedMethod\(\).*Comment on line with unexported method`,
			`io.Reader.*Comment on line with embedded Reader`,
			`error.*Comment on line with embedded error`,
		},
		[]string{
			`Has unexported methods`,
		},
	},

	// Interface method.
	{
		"interface method",
		[]string{p, `ExportedInterface.ExportedMethod`},
		[]string{
			`Comment before exported method.\n.*//\n.*//	// Code block showing how to use ExportedMethod\n.*//	func DoSomething\(\) error {\n.*//		ExportedMethod\(\)\n.*//		return nil\n.*//	}\n.*//.*\n.*ExportedMethod\(\)` +
				`.*Comment on line with exported method`,
		},
		[]string{
			`Comment about exported interface`,
		},
	},
	// Interface method at package level.
	{
		"interface method at package level",
		[]string{p, `ExportedMethod`},
		[]string{
			`func \(ExportedType\) ExportedMethod\(a int\) bool`,
			`Comment about exported method`,
		},
		[]string{
			`Comment before exported method.*\n.*ExportedMethod\(\)` +
				`.*Comment on line with exported method`,
		},
	},

	// Method.
	{
		"method",
		[]string{p, `ExportedType.ExportedMethod`},
		[]string{
			`func \(ExportedType\) ExportedMethod\(a int\) bool`,
			`Comment about exported method`,
		},
		nil,
	},
	// Method  with -u.
	{
		"method with -u",
		[]string{"-u", p, `ExportedType.unexportedMethod`},
		[]string{
			`func \(ExportedType\) unexportedMethod\(a int\) bool`,
			`Comment about unexported method`,
		},
		nil,
	},
	// Method with -src.
	{
		"method with -src",
		[]string{"-src", p, `ExportedType.ExportedMethod`},
		[]string{
			`func \(ExportedType\) ExportedMethod\(a int\) bool`,
			`Comment about exported method`,
			`return true != true`,
		},
		nil,
	},

	// Field.
	{
		"field",
		[]string{p, `ExportedType.ExportedField`},
		[]string{
			`type ExportedType struct`,
			`ExportedField int`,
			`Comment before exported field`,
			`Comment on line with exported field`,
			`other fields elided`,
		},
		nil,
	},

	// Field with -u.
	{
		"method with -u",
		[]string{"-u", p, `ExportedType.unexportedField`},
		[]string{
			`unexportedField int`,
			`Comment on line with unexported field`,
		},
		nil,
	},

	// Field of struct with only one field.
	{
		"single-field struct",
		[]string{p, `ExportedStructOneField.OnlyField`},
		[]string{`the only field`},
		[]string{`other fields elided`},
	},

	// Case matching off.
	{
		"case matching off",
		[]string{p, `casematch`},
		[]string{
			`CaseMatch`,
			`Casematch`,
		},
		nil,
	},

	// Case matching on.
	{
		"case matching on",
		[]string{"-c", p, `Casematch`},
		[]string{
			`Casematch`,
		},
		[]string{
			`CaseMatch`,
		},
	},

	// Merging comments with -src.
	{
		"merge comments with -src A",
		[]string{"-src", p + "/merge", `A`},
		[]string{
			`A doc`,
			`func A`,
			`A comment`,
		},
		[]string{
			`Package A doc`,
			`Package B doc`,
			`B doc`,
			`B comment`,
			`B doc`,
		},
	},
	{
		"merge comments with -src B",
		[]string{"-src", p + "/merge", `B`},
		[]string{
			`B doc`,
			`func B`,
			`B comment`,
		},
		[]string{
			`Package A doc`,
			`Package B doc`,
			`A doc`,
			`A comment`,
			`A doc`,
		},
	},

	// No dups with -u. Issue 21797.
	{
		"case matching on, no dups",
		[]string{"-u", p, `duplicate`},
		[]string{
			`Duplicate`,
			`duplicate`,
		},
		[]string{
			"\\)\n+const", // This will appear if the const decl appears twice.
		},
	},
	{
		"non-imported: pkg.sym",
		[]string{"nested.Foo"},
		[]string{"Foo struct"},
		nil,
	},
	{
		"non-imported: pkg only",
		[]string{"nested"},
		[]string{"Foo struct"},
		nil,
	},
	{
		"non-imported: pkg sym",
		[]string{"nested", "Foo"},
		[]string{"Foo struct"},
		nil,
	},
	{
		"formatted doc on function",
		[]string{p, "ExportedFormattedDoc"},
		[]string{
			`func ExportedFormattedDoc\(a int\) bool`,
			`    Comment about exported function with formatting\.

    Example

        fmt\.Println\(FormattedDoc\(\)\)

    Text after pre-formatted block\.`,
		},
		nil,
	},
	{
		"formatted doc on type field",
		[]string{p, "ExportedFormattedType.ExportedField"},
		[]string{
			`type ExportedFormattedType struct`,
			`    // Comment before exported field with formatting\.
    //[ ]
    // Example
    //[ ]
    //     a\.ExportedField = 123
    //[ ]
    // Text after pre-formatted block\.`,
			`ExportedField int`,
		},
		[]string{"ignore:directive"},
	},
	{
		"formatted doc on entire type",
		[]string{p, "ExportedFormattedType"},
		[]string{
			`type ExportedFormattedType struct`,
			`	// Comment before exported field with formatting\.
	//
	// Example
	//
	//	a\.ExportedField = 123
	//
	// Text after pre-formatted block\.`,
			`ExportedField int`,
		},
		[]string{"ignore:directive"},
	},
	{
		"formatted doc on entire type with -all",
		[]string{"-all", p, "ExportedFormattedType"},
		[]string{
			`type ExportedFormattedType struct`,
			`	// Comment before exported field with formatting\.
	//
	// Example
	//
	//	a\.ExportedField = 123
	//
	// Text after pre-formatted block\.`,
			`ExportedField int`,
		},
		[]string{"ignore:directive"},
	},
}

func TestDoc(t *testing.T) {
	maybeSkip(t)
	defer log.SetOutput(log.Writer())
	for _, test := range tests {
		var b bytes.Buffer
		var flagSet flag.FlagSet
		var logbuf bytes.Buffer
		log.SetOutput(&logbuf)
		err := do(&b, &flagSet, test.args)
		if err != nil {
			t.Fatalf("%s %v: %s\n", test.name, test.args, err)
		}
		if logbuf.Len() > 0 {
			t.Errorf("%s %v: unexpected log messages:\n%s", test.name, test.args, logbuf.Bytes())
		}
		output := b.Bytes()
		failed := false
		for j, yes := range test.yes {
			re, err := regexp.Compile(yes)
			if err != nil {
				t.Fatalf("%s.%d: compiling %#q: %s", test.name, j, yes, err)
			}
			if !re.Match(output) {
				t.Errorf("%s.%d: no match for %s %#q", test.name, j, test.args, yes)
				failed = true
			}
		}
		for j, no := range test.no {
			re, err := regexp.Compile(no)
			if err != nil {
				t.Fatalf("%s.%d: compiling %#q: %s", test.name, j, no, err)
			}
			if re.Match(output) {
				t.Errorf("%s.%d: incorrect match for %s %#q", test.name, j, test.args, no)
				failed = true
			}
		}
		if bytes.Count(output, []byte("TYPES\n")) > 1 {
			t.Fatalf("%s: repeating headers", test.name)
		}
		if failed {
			t.Logf("\n%s", output)
		}
	}
}

// Test the code to try multiple packages. Our test case is
//
//	go doc rand.Float64
//
// This needs to find math/rand.Float64; however crypto/rand, which doesn't
// have the symbol, usually appears first in the directory listing.
func TestMultiplePackages(t *testing.T) {
	if testing.Short() {
		t.Skip("scanning file system takes too long")
	}
	maybeSkip(t)
	var b bytes.Buffer // We don't care about the output.
	// Make sure crypto/rand does not have the symbol.
	{
		var flagSet flag.FlagSet
		err := do(&b, &flagSet, []string{"crypto/rand.float64"})
		if err == nil {
			t.Errorf("expected error from crypto/rand.float64")
		} else if !strings.Contains(err.Error(), "no symbol float64") {
			t.Errorf("unexpected error %q from crypto/rand.float64", err)
		}
	}
	// Make sure math/rand does have the symbol.
	{
		var flagSet flag.FlagSet
		err := do(&b, &flagSet, []string{"math/rand.float64"})
		if err != nil {
			t.Errorf("unexpected error %q from math/rand.float64", err)
		}
	}
	// Try the shorthand.
	{
		var flagSet flag.FlagSet
		err := do(&b, &flagSet, []string{"rand.float64"})
		if err != nil {
			t.Errorf("unexpected error %q from rand.float64", err)
		}
	}
	// Now try a missing symbol. We should see both packages in the error.
	{
		var flagSet flag.FlagSet
		err := do(&b, &flagSet, []string{"rand.doesnotexit"})
		if err == nil {
			t.Errorf("expected error from rand.doesnotexit")
		} else {
			errStr := err.Error()
			if !strings.Contains(errStr, "no symbol") {
				t.Errorf("error %q should contain 'no symbol", errStr)
			}
			if !strings.Contains(errStr, "crypto/rand") {
				t.Errorf("error %q should contain crypto/rand", errStr)
			}
			if !strings.Contains(errStr, "math/rand") {
				t.Errorf("error %q should contain math/rand", errStr)
			}
		}
	}
}

// Test the code to look up packages when given two args. First test case is
//
//	go doc binary BigEndian
//
// This needs to find encoding/binary.BigEndian, which means
// finding the package encoding/binary given only "binary".
// Second case is
//
//	go doc rand Float64
//
// which again needs to find math/rand and not give up after crypto/rand,
// which has no such function.
func TestTwoArgLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("scanning file system takes too long")
	}
	maybeSkip(t)
	var b bytes.Buffer // We don't care about the output.
	{
		var flagSet flag.FlagSet
		err := do(&b, &flagSet, []string{"binary", "BigEndian"})
		if err != nil {
			t.Errorf("unexpected error %q from binary BigEndian", err)
		}
	}
	{
		var flagSet flag.FlagSet
		err := do(&b, &flagSet, []string{"rand", "Float64"})
		if err != nil {
			t.Errorf("unexpected error %q from rand Float64", err)
		}
	}
	{
		var flagSet flag.FlagSet
		err := do(&b, &flagSet, []string{"bytes", "Foo"})
		if err == nil {
			t.Errorf("expected error from bytes Foo")
		} else if !strings.Contains(err.Error(), "no symbol Foo") {
			t.Errorf("unexpected error %q from bytes Foo", err)
		}
	}
	{
		var flagSet flag.FlagSet
		err := do(&b, &flagSet, []string{"nosuchpackage", "Foo"})
		if err == nil {
			// actually present in the user's filesystem
		} else if !strings.Contains(err.Error(), "no such package") {
			t.Errorf("unexpected error %q from nosuchpackage Foo", err)
		}
	}
}

// Test the code to look up packages when the first argument starts with "./".
// Our test case is in effect "cd src/text; doc ./template". This should get
// text/template but before Issue 23383 was fixed would give html/template.
func TestDotSlashLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("scanning file system takes too long")
	}
	maybeSkip(t)
	t.Chdir(filepath.Join(buildCtx.GOROOT, "src", "text"))

	var b strings.Builder
	var flagSet flag.FlagSet
	err := do(&b, &flagSet, []string{"./template"})
	if err != nil {
		t.Errorf("unexpected error %q from ./template", err)
	}
	// The output should contain information about the text/template package.
	const want = `package template // import "text/template"`
	output := b.String()
	if !strings.HasPrefix(output, want) {
		t.Fatalf("wrong package: %.*q...", len(want), output)
	}
}

// Test that we don't print spurious package clauses
// when there should be no output at all. Issue 37969.
func TestNoPackageClauseWhenNoMatch(t *testing.T) {
	maybeSkip(t)
	var b strings.Builder
	var flagSet flag.FlagSet
	err := do(&b, &flagSet, []string{"template.ZZZ"})
	// Expect an error.
	if err == nil {
		t.Error("expect an error for template.zzz")
	}
	// And the output should not contain any package clauses.
	const dontWant = `package template // import `
	output := b.String()
	if strings.Contains(output, dontWant) {
		t.Fatalf("improper package clause printed:\n%s", output)
	}
}

type trimTest struct {
	path   string
	prefix string
	result string
	ok     bool
}

var trimTests = []trimTest{
	{"", "", "", true},
	{"/usr/gopher", "/usr/gopher", "/usr/gopher", true},
	{"/usr/gopher/bar", "/usr/gopher", "bar", true},
	{"/usr/gopherflakes", "/usr/gopher", "/usr/gopherflakes", false},
	{"/usr/gopher/bar", "/usr/zot", "/usr/gopher/bar", false},
}

func TestTrim(t *testing.T) {
	for _, test := range trimTests {
		result, ok := trim(test.path, test.prefix)
		if ok != test.ok {
			t.Errorf("%s %s expected %t got %t", test.path, test.prefix, test.ok, ok)
			continue
		}
		if result != test.result {
			t.Errorf("%s %s expected %q got %q", test.path, test.prefix, test.result, result)
			continue
		}
	}
}

"""



```