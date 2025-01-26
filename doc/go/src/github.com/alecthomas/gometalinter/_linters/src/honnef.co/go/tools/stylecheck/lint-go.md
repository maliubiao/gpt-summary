Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Understanding the Goal:**

The core request is to understand what the Go code does, particularly in the context of style checking. The prompt mentions the file path, which is helpful context (a linter within a larger linting tool). The request also asks for examples, potential errors, and how command-line arguments might be involved.

**2. Initial Skim and Identification of Key Structures:**

The first step is to quickly read through the code, looking for prominent structures and patterns. Key things that immediately stand out are:

* **Package Declaration:** `package stylecheck` -  Confirms the purpose.
* **Imports:** A standard set of Go imports related to AST manipulation (`go/ast`), type checking (`go/types`), tokenization (`go/token`), string manipulation, Unicode, and importantly, imports from `honnef.co/go/tools/lint` and `golang.org/x/tools/go/types/typeutil`. This strongly suggests it's part of a linting framework.
* **`Checker` Struct:**  The `Checker` struct with a `CheckGenerated` field is a central piece. The `NewChecker()` function reinforces this.
* **Methods on `Checker`:**  Methods like `Name()`, `Prefix()`, `Init()`, and `Checks()` are typical for a linter within a larger system. The `Checks()` method is crucial, as it lists the individual style checks performed.
* **Individual Check Functions:** Functions like `CheckPackageComment`, `CheckDotImports`, `CheckErrorStrings`, etc., clearly define the specific style checks.

**3. Analyzing `Checks()` and Individual Check Functions:**

The `Checks()` method is the roadmap. It reveals a set of rules identified by IDs (e.g., "ST1000"). The `FilterGenerated` flag suggests these checks can be selectively applied to generated code. The `Fn` field points to the functions implementing the checks.

Next, delve into a few of the check functions to understand their logic:

* **`CheckPackageComment`:**  Checks for the presence and format of package comments in non-`main` packages.
* **`CheckDotImports`:**  Flags the use of dot imports (with a whitelist exception).
* **`CheckErrorStrings`:**  Enforces conventions for error message capitalization and punctuation.
* **`CheckHTTPStatusCodes`:** Suggests using `net/http` constants for HTTP status codes.

**4. Inferring Overall Functionality:**

Based on the individual checks, it becomes clear that this code implements a set of style guidelines for Go code. It aims to enforce consistency and best practices related to naming conventions, error handling, import usage, and more.

**5. Identifying Go Language Features and Providing Examples:**

For each check function, try to understand the underlying Go language feature being addressed:

* **Package Comments:** The standard Go documentation mechanism.
* **Dot Imports:**  Go's import syntax.
* **Error Strings:**  The standard `error` interface and common practices for creating error messages.
* **HTTP Status Codes:**  Constants defined in the `net/http` package.

Create simple, illustrative Go code examples demonstrating violations of these rules and how the linter would flag them. Include both the "bad" code (input) and what the linter would likely report (output).

**6. Considering Command-Line Arguments:**

While the code itself doesn't *directly* handle command-line arguments, the `lint.Program` and the `pkg.Config` suggest that the *larger* linting tool (gometalinter) likely provides configuration options. The `DotImportWhitelist` and `HTTPStatusCodeWhitelist` within the check functions point to configuration possibilities. Infer how these might be set via command-line flags or configuration files in the parent tool.

**7. Identifying Common Mistakes:**

Think about the kinds of errors developers might make that these checks are designed to catch. For example:

* Forgetting package comments.
* Using dot imports carelessly.
* Writing inconsistent error messages.
* Using magic numbers for HTTP status codes.

Create simple examples of these mistakes.

**8. Structuring the Answer:**

Organize the findings logically:

* **Overall Function:** Start with a high-level summary of the code's purpose.
* **Detailed Functionality (Check by Check):**  Go through the individual check functions, explaining what they do and providing examples.
* **Go Language Feature Implementation:**  Explicitly state which Go language features are being checked.
* **Command-Line Arguments:** Explain how configuration might work in the larger context.
* **Common Mistakes:**  Provide examples of errors the linter helps prevent.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This looks like just some random style checks."
* **Correction:** "Ah, the `honnef.co/go/tools/lint` imports indicate this is part of a structured linting framework. The `Checker` struct and `Checks()` method are key to how it integrates."
* **Initial thought:** "How do the whitelists work?"
* **Correction:** "The `pkg.Config` suggests that the parent tool provides configuration mechanisms to customize the linter's behavior."

By following this methodical approach, analyzing the code structure, inferring its purpose from its components, and providing concrete examples, a comprehensive and accurate understanding of the code can be achieved.
这段代码是 `honnef.co/go/tools/stylecheck` 包中的 `lint.go` 文件的一部分。这个包实现了一系列的 Go 语言代码风格检查。它可以作为 `gometalinter` 或其他 Go 语言静态分析工具的一部分来使用，用于帮助开发者遵循一致的代码风格规范。

以下是代码中各个部分的功能分解：

**1. 包声明和导入:**

```go
package stylecheck // import "honnef.co/go/tools/stylecheck"

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"honnef.co/go/tools/lint"
	. "honnef.co/go/tools/lint/lintdsl"
	"honnef.co/go/tools/ssa"

	"golang.org/x/tools/go/types/typeutil"
)
```

* 声明了 `stylecheck` 包。
* 导入了 Go 语言标准库和第三方库，这些库用于处理 Go 语言的抽象语法树 (AST)、类型信息、字符串操作、Unicode 处理以及 `honnef.co/go/tools/lint` 提供的 linting 框架。

**2. `Checker` 结构体和相关方法:**

```go
type Checker struct {
	CheckGenerated bool
}

func NewChecker() *Checker {
	return &Checker{}
}

func (*Checker) Name() string              { return "stylecheck" }
func (*Checker) Prefix() string            { return "ST" }
func (c *Checker) Init(prog *lint.Program) {}

func (c *Checker) Checks() []lint.Check {
	// ... 定义了一系列的代码检查
}
```

* 定义了一个名为 `Checker` 的结构体，它有一个字段 `CheckGenerated`，用于控制是否检查生成的代码。
* `NewChecker()` 函数用于创建一个 `Checker` 实例。
* `Name()` 方法返回检查器的名称（"stylecheck"）。
* `Prefix()` 方法返回检查器报告问题的 ID 前缀（"ST"）。
* `Init()` 方法是一个空实现，可能在将来用于初始化操作。
* `Checks()` 方法返回一个 `lint.Check` 结构体的切片，每个结构体定义了一个具体的代码风格检查。

**3. 代码检查列表 (`Checks()` 方法):**

`Checks()` 方法定义了 `stylecheck` 执行的所有代码风格检查。每个检查都包含一个 ID、一个布尔值 `FilterGenerated` (指示是否忽略生成的代码) 和一个执行检查的函数 `Fn`。

以下是一些检查及其功能的推断：

* **`ST1000: CheckPackageComment`**: 检查包注释的规范性。
* **`ST1001: CheckDotImports`**: 检查是否使用了点导入 (`.`)。
* **`ST1003: CheckNames`**:  很可能检查标识符（变量、函数名等）的命名规范。
* **`ST1005: CheckErrorStrings`**: 检查错误字符串的格式（例如，不应以标点符号结尾）。
* **`ST1006: CheckReceiverNames`**: 检查方法接收者名称的规范性。
* **`ST1008: CheckErrorReturn`**: 检查函数返回错误的位置，通常建议作为最后一个返回值。
* **`ST1011: CheckTimeNames`**: 检查 `time.Duration` 类型变量的命名，避免使用单位后缀。
* **`ST1012: CheckErrorVarNames`**: 检查错误类型变量的命名规范（例如，以 `err` 或 `Err` 开头）。
* **`ST1013: CheckHTTPStatusCodes`**: 检查是否应该使用 `net/http` 包中的常量来表示 HTTP 状态码，而不是硬编码的数字。
* **`ST1015: CheckDefaultCaseOrder`**: 检查 `switch` 语句中 `default` case 的位置，通常建议放在开头或结尾。
* **`ST1016: CheckReceiverNamesIdentical`**: 检查同一类型的所有方法是否使用了相同的接收者名称。
* **`ST1017: CheckYodaConditions`**: 检查是否使用了 Yoda 条件表达式（例如，`nil == variable`），通常不推荐。

**4. 具体的代码检查函数:**

代码中定义了一系列以 `Check` 开头的函数，每个函数对应 `Checks()` 方法中列出的一个检查。让我们详细分析一些：

**4.1. `CheckPackageComment(j *lint.Job)`:**

```go
func (c *Checker) CheckPackageComment(j *lint.Job) {
	// ...
}
```

**功能:** 检查非 `main` 包中是否至少有一个文件包含包注释，并且注释的格式是否为 "Package <包名> ..."。

**Go 语言功能实现:**  检查 AST 中的 `File` 节点的 `Doc` 字段，该字段包含了包注释。

**代码推理和示例:**

假设有以下 Go 代码文件 `mypackage/file.go`:

```go
// 这是 mypackage 包的注释。
package mypackage

func DoSomething() {}
```

**输入:**  `lint.Job` 对象，其中包含了 `mypackage/file.go` 的 AST。

**输出:**  如果包注释缺失或格式不正确，则会调用 `j.Errorf` 报告错误。

**示例（缺少包注释的情况）:**

```go
package mypackage

func DoSomething() {}
```

**假设输入:**  包含上述代码的 `lint.Job`。

**可能的输出:**  `mypackage/file.go:1:1: at least one file in a package should have a package comment`

**示例（包注释格式不正确的情况）:**

```go
// My package.
package mypackage

func DoSomething() {}
```

**假设输入:**  包含上述代码的 `lint.Job`。

**可能的输出:**  `mypackage/file.go:1:1: package comment should be of the form "Package mypackage ..."`

**4.2. `CheckDotImports(j *lint.Job)`:**

```go
func (c *Checker) CheckDotImports(j *lint.Job) {
	// ...
}
```

**功能:** 检查是否使用了点导入 (`import . "path/to/package"`), 这通常被认为是不好的实践，因为它会污染当前命名空间。它允许通过配置白名单来忽略特定的点导入。

**Go 语言功能实现:** 遍历 AST 中的 `ImportSpec` 节点，检查 `Name` 字段是否为 `.`。

**代码推理和示例:**

假设有以下 Go 代码：

```go
package main

import . "fmt" // 点导入

func main() {
	Println("Hello, world!")
}
```

**输入:** 包含上述代码的 `lint.Job` 对象。

**输出:**  如果使用了点导入且不在白名单中，则会调用 `j.Errorf` 报告错误。

**假设输入:**  包含上述代码的 `lint.Job`，且 `pkg.Config.DotImportWhitelist` 为空或不包含 `"fmt"`。

**可能的输出:**  `main.go:3:8: should not use dot imports`

**4.3. `CheckErrorStrings(j *lint.Job)`:**

```go
func (c *Checker) CheckErrorStrings(j *lint.Job) {
	// ...
}
```

**功能:** 检查错误字符串的格式，例如：
    * 错误字符串不应以标点符号（. : ! \n）结尾。
    * 错误字符串的首字母不应大写（除非是专有名词或首字母缩略词）。

**Go 语言功能实现:** 遍历 SSA 代码中的 `Call` 指令，查找对 `errors.New` 和 `fmt.Errorf` 的调用，并检查其参数（错误字符串）。

**代码推理和示例:**

```go
package main

import "errors"

func main() {
	err := errors.New("something went wrong.") // 错误字符串以句点结尾
	_ = err
}
```

**输入:** 包含上述代码的 `lint.Job` 对象。

**输出:**

**假设输入:** 包含上述代码的 `lint.Job`。

**可能的输出:** `main.go:6:17: error strings should not end with punctuation or a newline`

```go
package main

import "errors"

func main() {
	err := errors.New("Something went wrong") // 错误字符串首字母大写
	_ = err
}
```

**假设输入:** 包含上述代码的 `lint.Job`。

**可能的输出:** `main.go:6:17: error strings should not be capitalized`

**5. 命令行参数处理:**

这段代码本身并没有直接处理命令行参数。`stylecheck` 是一个代码检查器，它的配置通常由使用它的工具（如 `gometalinter`) 来处理。

`gometalinter` 会读取配置文件或接收命令行参数，然后将配置信息传递给各个检查器。例如，`DotImportWhitelist` 和 `HTTPStatusCodeWhitelist` 很可能通过 `gometalinter` 的配置进行设置。

**示例 (假设 `gometalinter` 的用法):**

```bash
gometalinter --enable=stylecheck --stylecheck.dot-import-whitelist=fmt ./...
```

这个命令启用了 `stylecheck` 检查器，并设置了点导入白名单，允许导入 `fmt` 包。

**6. 使用者易犯错的点:**

* **忽略包注释:**  初学者或快速编写代码时可能会忘记添加包注释。
* **滥用点导入:** 为了方便而使用点导入，但可能导致命名冲突和代码可读性下降。
* **错误字符串格式不一致:**  不同的开发者可能以不同的方式编写错误字符串，导致风格不统一。
* **硬编码 HTTP 状态码:**  不使用 `net/http` 包中的常量，使得代码难以理解和维护。
* **`switch` 语句中 `default` 的位置不规范:**  可能导致代码可读性下降。
* **使用 Yoda 条件表达式:**  虽然功能上没有问题，但通常认为不符合 Go 的代码风格，可读性较差。

这段代码是构建一个 Go 语言风格检查器的基础。它定义了要执行的检查以及执行这些检查的逻辑。通过与其他 linting 工具集成，它可以帮助开发者编写更规范、更易于维护的 Go 代码。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/stylecheck/lint.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package stylecheck // import "honnef.co/go/tools/stylecheck"

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"honnef.co/go/tools/lint"
	. "honnef.co/go/tools/lint/lintdsl"
	"honnef.co/go/tools/ssa"

	"golang.org/x/tools/go/types/typeutil"
)

type Checker struct {
	CheckGenerated bool
}

func NewChecker() *Checker {
	return &Checker{}
}

func (*Checker) Name() string              { return "stylecheck" }
func (*Checker) Prefix() string            { return "ST" }
func (c *Checker) Init(prog *lint.Program) {}

func (c *Checker) Checks() []lint.Check {
	return []lint.Check{
		{ID: "ST1000", FilterGenerated: false, Fn: c.CheckPackageComment},
		{ID: "ST1001", FilterGenerated: true, Fn: c.CheckDotImports},
		// {ID: "ST1002", FilterGenerated: true, Fn: c.CheckBlankImports},
		{ID: "ST1003", FilterGenerated: true, Fn: c.CheckNames},
		// {ID: "ST1004", FilterGenerated: false, Fn: nil, 			  },
		{ID: "ST1005", FilterGenerated: false, Fn: c.CheckErrorStrings},
		{ID: "ST1006", FilterGenerated: false, Fn: c.CheckReceiverNames},
		// {ID: "ST1007", FilterGenerated: true, Fn: c.CheckIncDec},
		{ID: "ST1008", FilterGenerated: false, Fn: c.CheckErrorReturn},
		// {ID: "ST1009", FilterGenerated: false, Fn: c.CheckUnexportedReturn},
		// {ID: "ST1010", FilterGenerated: false, Fn: c.CheckContextFirstArg},
		{ID: "ST1011", FilterGenerated: false, Fn: c.CheckTimeNames},
		{ID: "ST1012", FilterGenerated: false, Fn: c.CheckErrorVarNames},
		{ID: "ST1013", FilterGenerated: true, Fn: c.CheckHTTPStatusCodes},
		{ID: "ST1015", FilterGenerated: true, Fn: c.CheckDefaultCaseOrder},
		{ID: "ST1016", FilterGenerated: false, Fn: c.CheckReceiverNamesIdentical},
		{ID: "ST1017", FilterGenerated: true, Fn: c.CheckYodaConditions},
	}
}

func (c *Checker) CheckPackageComment(j *lint.Job) {
	// - At least one file in a non-main package should have a package comment
	//
	// - The comment should be of the form
	// "Package x ...". This has a slight potential for false
	// positives, as multiple files can have package comments, in
	// which case they get appended. But that doesn't happen a lot in
	// the real world.

	for _, pkg := range j.Program.InitialPackages {
		if pkg.Name == "main" {
			continue
		}
		hasDocs := false
		for _, f := range pkg.Syntax {
			if IsInTest(j, f) {
				continue
			}
			if f.Doc != nil && len(f.Doc.List) > 0 {
				hasDocs = true
				prefix := "Package " + f.Name.Name + " "
				if !strings.HasPrefix(strings.TrimSpace(f.Doc.Text()), prefix) {
					j.Errorf(f.Doc, `package comment should be of the form "%s..."`, prefix)
				}
				f.Doc.Text()
			}
		}

		if !hasDocs {
			for _, f := range pkg.Syntax {
				if IsInTest(j, f) {
					continue
				}
				j.Errorf(f, "at least one file in a package should have a package comment")
			}
		}
	}
}

func (c *Checker) CheckDotImports(j *lint.Job) {
	for _, pkg := range j.Program.InitialPackages {
		for _, f := range pkg.Syntax {
		imports:
			for _, imp := range f.Imports {
				path := imp.Path.Value
				path = path[1 : len(path)-1]
				for _, w := range pkg.Config.DotImportWhitelist {
					if w == path {
						continue imports
					}
				}

				if imp.Name != nil && imp.Name.Name == "." && !IsInTest(j, f) {
					j.Errorf(imp, "should not use dot imports")
				}
			}
		}
	}
}

func (c *Checker) CheckBlankImports(j *lint.Job) {
	fset := j.Program.Fset()
	for _, f := range j.Program.Files {
		if IsInMain(j, f) || IsInTest(j, f) {
			continue
		}

		// Collect imports of the form `import _ "foo"`, i.e. with no
		// parentheses, as their comment will be associated with the
		// (paren-free) GenDecl, not the import spec itself.
		//
		// We don't directly process the GenDecl so that we can
		// correctly handle the following:
		//
		//  import _ "foo"
		//  import _ "bar"
		//
		// where only the first import should get flagged.
		skip := map[ast.Spec]bool{}
		ast.Inspect(f, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.File:
				return true
			case *ast.GenDecl:
				if node.Tok != token.IMPORT {
					return false
				}
				if node.Lparen == token.NoPos && node.Doc != nil {
					skip[node.Specs[0]] = true
				}
				return false
			}
			return false
		})
		for i, imp := range f.Imports {
			pos := fset.Position(imp.Pos())

			if !IsBlank(imp.Name) {
				continue
			}
			// Only flag the first blank import in a group of imports,
			// or don't flag any of them, if the first one is
			// commented
			if i > 0 {
				prev := f.Imports[i-1]
				prevPos := fset.Position(prev.Pos())
				if pos.Line-1 == prevPos.Line && IsBlank(prev.Name) {
					continue
				}
			}

			if imp.Doc == nil && imp.Comment == nil && !skip[imp] {
				j.Errorf(imp, "a blank import should be only in a main or test package, or have a comment justifying it")
			}
		}
	}
}

func (c *Checker) CheckIncDec(j *lint.Job) {
	// TODO(dh): this can be noisy for function bodies that look like this:
	// 	x += 3
	// 	...
	// 	x += 2
	// 	...
	// 	x += 1
	fn := func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || (assign.Tok != token.ADD_ASSIGN && assign.Tok != token.SUB_ASSIGN) {
			return true
		}
		if (len(assign.Lhs) != 1 || len(assign.Rhs) != 1) ||
			!IsIntLiteral(assign.Rhs[0], "1") {
			return true
		}

		suffix := ""
		switch assign.Tok {
		case token.ADD_ASSIGN:
			suffix = "++"
		case token.SUB_ASSIGN:
			suffix = "--"
		}

		j.Errorf(assign, "should replace %s with %s%s", Render(j, assign), Render(j, assign.Lhs[0]), suffix)
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckErrorReturn(j *lint.Job) {
fnLoop:
	for _, fn := range j.Program.InitialFunctions {
		sig := fn.Type().(*types.Signature)
		rets := sig.Results()
		if rets == nil || rets.Len() < 2 {
			continue
		}

		if rets.At(rets.Len()-1).Type() == types.Universe.Lookup("error").Type() {
			// Last return type is error. If the function also returns
			// errors in other positions, that's fine.
			continue
		}
		for i := rets.Len() - 2; i >= 0; i-- {
			if rets.At(i).Type() == types.Universe.Lookup("error").Type() {
				j.Errorf(rets.At(i), "error should be returned as the last argument")
				continue fnLoop
			}
		}
	}
}

// CheckUnexportedReturn checks that exported functions on exported
// types do not return unexported types.
func (c *Checker) CheckUnexportedReturn(j *lint.Job) {
	for _, fn := range j.Program.InitialFunctions {
		if fn.Synthetic != "" || fn.Parent() != nil {
			continue
		}
		if !ast.IsExported(fn.Name()) || IsInMain(j, fn) || IsInTest(j, fn) {
			continue
		}
		sig := fn.Type().(*types.Signature)
		if sig.Recv() != nil && !ast.IsExported(Dereference(sig.Recv().Type()).(*types.Named).Obj().Name()) {
			continue
		}
		res := sig.Results()
		for i := 0; i < res.Len(); i++ {
			if named, ok := DereferenceR(res.At(i).Type()).(*types.Named); ok &&
				!ast.IsExported(named.Obj().Name()) &&
				named != types.Universe.Lookup("error").Type() {
				j.Errorf(fn, "should not return unexported type")
			}
		}
	}
}

func (c *Checker) CheckReceiverNames(j *lint.Job) {
	for _, pkg := range j.Program.InitialPackages {
		for _, m := range pkg.SSA.Members {
			if T, ok := m.Object().(*types.TypeName); ok && !T.IsAlias() {
				ms := typeutil.IntuitiveMethodSet(T.Type(), nil)
				for _, sel := range ms {
					fn := sel.Obj().(*types.Func)
					recv := fn.Type().(*types.Signature).Recv()
					if Dereference(recv.Type()) != T.Type() {
						// skip embedded methods
						continue
					}
					if recv.Name() == "self" || recv.Name() == "this" {
						j.Errorf(recv, `receiver name should be a reflection of its identity; don't use generic names such as "this" or "self"`)
					}
					if recv.Name() == "_" {
						j.Errorf(recv, "receiver name should not be an underscore, omit the name if it is unused")
					}
				}
			}
		}
	}
}

func (c *Checker) CheckReceiverNamesIdentical(j *lint.Job) {
	for _, pkg := range j.Program.InitialPackages {
		for _, m := range pkg.SSA.Members {
			names := map[string]int{}

			var firstFn *types.Func
			if T, ok := m.Object().(*types.TypeName); ok && !T.IsAlias() {
				ms := typeutil.IntuitiveMethodSet(T.Type(), nil)
				for _, sel := range ms {
					fn := sel.Obj().(*types.Func)
					recv := fn.Type().(*types.Signature).Recv()
					if Dereference(recv.Type()) != T.Type() {
						// skip embedded methods
						continue
					}
					if firstFn == nil {
						firstFn = fn
					}
					if recv.Name() != "" && recv.Name() != "_" {
						names[recv.Name()]++
					}
				}
			}

			if len(names) > 1 {
				var seen []string
				for name, count := range names {
					seen = append(seen, fmt.Sprintf("%dx %q", count, name))
				}

				j.Errorf(firstFn, "methods on the same type should have the same receiver name (seen %s)", strings.Join(seen, ", "))
			}
		}
	}
}

func (c *Checker) CheckContextFirstArg(j *lint.Job) {
	// TODO(dh): this check doesn't apply to test helpers. Example from the stdlib:
	// 	func helperCommandContext(t *testing.T, ctx context.Context, s ...string) (cmd *exec.Cmd) {
fnLoop:
	for _, fn := range j.Program.InitialFunctions {
		if fn.Synthetic != "" || fn.Parent() != nil {
			continue
		}
		params := fn.Signature.Params()
		if params.Len() < 2 {
			continue
		}
		if types.TypeString(params.At(0).Type(), nil) == "context.Context" {
			continue
		}
		for i := 1; i < params.Len(); i++ {
			param := params.At(i)
			if types.TypeString(param.Type(), nil) == "context.Context" {
				j.Errorf(param, "context.Context should be the first argument of a function")
				continue fnLoop
			}
		}
	}
}

func (c *Checker) CheckErrorStrings(j *lint.Job) {
	fnNames := map[*ssa.Package]map[string]bool{}
	for _, fn := range j.Program.InitialFunctions {
		m := fnNames[fn.Package()]
		if m == nil {
			m = map[string]bool{}
			fnNames[fn.Package()] = m
		}
		m[fn.Name()] = true
	}

	for _, fn := range j.Program.InitialFunctions {
		if IsInTest(j, fn) {
			// We don't care about malformed error messages in tests;
			// they're usually for direct human consumption, not part
			// of an API
			continue
		}
		for _, block := range fn.Blocks {
		instrLoop:
			for _, ins := range block.Instrs {
				call, ok := ins.(*ssa.Call)
				if !ok {
					continue
				}
				if !IsCallTo(call.Common(), "errors.New") && !IsCallTo(call.Common(), "fmt.Errorf") {
					continue
				}

				k, ok := call.Common().Args[0].(*ssa.Const)
				if !ok {
					continue
				}

				s := constant.StringVal(k.Value)
				if len(s) == 0 {
					continue
				}
				switch s[len(s)-1] {
				case '.', ':', '!', '\n':
					j.Errorf(call, "error strings should not end with punctuation or a newline")
				}
				idx := strings.IndexByte(s, ' ')
				if idx == -1 {
					// single word error message, probably not a real
					// error but something used in tests or during
					// debugging
					continue
				}
				word := s[:idx]
				first, n := utf8.DecodeRuneInString(word)
				if !unicode.IsUpper(first) {
					continue
				}
				for _, c := range word[n:] {
					if unicode.IsUpper(c) {
						// Word is probably an initialism or
						// multi-word function name
						continue instrLoop
					}
				}

				word = strings.TrimRightFunc(word, func(r rune) bool { return unicode.IsPunct(r) })
				if fnNames[fn.Package()][word] {
					// Word is probably the name of a function in this package
					continue
				}
				// First word in error starts with a capital
				// letter, and the word doesn't contain any other
				// capitals, making it unlikely to be an
				// initialism or multi-word function name.
				//
				// It could still be a proper noun, though.

				j.Errorf(call, "error strings should not be capitalized")
			}
		}
	}
}

func (c *Checker) CheckTimeNames(j *lint.Job) {
	suffixes := []string{
		"Sec", "Secs", "Seconds",
		"Msec", "Msecs",
		"Milli", "Millis", "Milliseconds",
		"Usec", "Usecs", "Microseconds",
		"MS", "Ms",
	}
	fn := func(T types.Type, names []*ast.Ident) {
		if !IsType(T, "time.Duration") && !IsType(T, "*time.Duration") {
			return
		}
		for _, name := range names {
			for _, suffix := range suffixes {
				if strings.HasSuffix(name.Name, suffix) {
					j.Errorf(name, "var %s is of type %v; don't use unit-specific suffix %q", name.Name, T, suffix)
					break
				}
			}
		}
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.ValueSpec:
				T := TypeOf(j, node.Type)
				fn(T, node.Names)
			case *ast.FieldList:
				for _, field := range node.List {
					T := TypeOf(j, field.Type)
					fn(T, field.Names)
				}
			}
			return true
		})
	}
}

func (c *Checker) CheckErrorVarNames(j *lint.Job) {
	for _, f := range j.Program.Files {
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				spec := spec.(*ast.ValueSpec)
				if len(spec.Names) != len(spec.Values) {
					continue
				}

				for i, name := range spec.Names {
					val := spec.Values[i]
					if !IsCallToAST(j, val, "errors.New") && !IsCallToAST(j, val, "fmt.Errorf") {
						continue
					}

					prefix := "err"
					if name.IsExported() {
						prefix = "Err"
					}
					if !strings.HasPrefix(name.Name, prefix) {
						j.Errorf(name, "error var %s should have name of the form %sFoo", name.Name, prefix)
					}
				}
			}
		}
	}
}

var httpStatusCodes = map[int]string{
	100: "StatusContinue",
	101: "StatusSwitchingProtocols",
	102: "StatusProcessing",
	200: "StatusOK",
	201: "StatusCreated",
	202: "StatusAccepted",
	203: "StatusNonAuthoritativeInfo",
	204: "StatusNoContent",
	205: "StatusResetContent",
	206: "StatusPartialContent",
	207: "StatusMultiStatus",
	208: "StatusAlreadyReported",
	226: "StatusIMUsed",
	300: "StatusMultipleChoices",
	301: "StatusMovedPermanently",
	302: "StatusFound",
	303: "StatusSeeOther",
	304: "StatusNotModified",
	305: "StatusUseProxy",
	307: "StatusTemporaryRedirect",
	308: "StatusPermanentRedirect",
	400: "StatusBadRequest",
	401: "StatusUnauthorized",
	402: "StatusPaymentRequired",
	403: "StatusForbidden",
	404: "StatusNotFound",
	405: "StatusMethodNotAllowed",
	406: "StatusNotAcceptable",
	407: "StatusProxyAuthRequired",
	408: "StatusRequestTimeout",
	409: "StatusConflict",
	410: "StatusGone",
	411: "StatusLengthRequired",
	412: "StatusPreconditionFailed",
	413: "StatusRequestEntityTooLarge",
	414: "StatusRequestURITooLong",
	415: "StatusUnsupportedMediaType",
	416: "StatusRequestedRangeNotSatisfiable",
	417: "StatusExpectationFailed",
	418: "StatusTeapot",
	422: "StatusUnprocessableEntity",
	423: "StatusLocked",
	424: "StatusFailedDependency",
	426: "StatusUpgradeRequired",
	428: "StatusPreconditionRequired",
	429: "StatusTooManyRequests",
	431: "StatusRequestHeaderFieldsTooLarge",
	451: "StatusUnavailableForLegalReasons",
	500: "StatusInternalServerError",
	501: "StatusNotImplemented",
	502: "StatusBadGateway",
	503: "StatusServiceUnavailable",
	504: "StatusGatewayTimeout",
	505: "StatusHTTPVersionNotSupported",
	506: "StatusVariantAlsoNegotiates",
	507: "StatusInsufficientStorage",
	508: "StatusLoopDetected",
	510: "StatusNotExtended",
	511: "StatusNetworkAuthenticationRequired",
}

func (c *Checker) CheckHTTPStatusCodes(j *lint.Job) {
	for _, pkg := range j.Program.InitialPackages {
		whitelist := map[string]bool{}
		for _, code := range pkg.Config.HTTPStatusCodeWhitelist {
			whitelist[code] = true
		}
		fn := func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			var arg int
			switch CallNameAST(j, call) {
			case "net/http.Error":
				arg = 2
			case "net/http.Redirect":
				arg = 3
			case "net/http.StatusText":
				arg = 0
			case "net/http.RedirectHandler":
				arg = 1
			default:
				return true
			}
			lit, ok := call.Args[arg].(*ast.BasicLit)
			if !ok {
				return true
			}
			if whitelist[lit.Value] {
				return true
			}

			n, err := strconv.Atoi(lit.Value)
			if err != nil {
				return true
			}
			s, ok := httpStatusCodes[n]
			if !ok {
				return true
			}
			j.Errorf(lit, "should use constant http.%s instead of numeric literal %d", s, n)
			return true
		}
		for _, f := range pkg.Syntax {
			ast.Inspect(f, fn)
		}
	}
}

func (c *Checker) CheckDefaultCaseOrder(j *lint.Job) {
	fn := func(node ast.Node) bool {
		stmt, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		list := stmt.Body.List
		for i, c := range list {
			if c.(*ast.CaseClause).List == nil && i != 0 && i != len(list)-1 {
				j.Errorf(c, "default case should be first or last in switch statement")
				break
			}
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckYodaConditions(j *lint.Job) {
	fn := func(node ast.Node) bool {
		cond, ok := node.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		if cond.Op != token.EQL && cond.Op != token.NEQ {
			return true
		}
		if _, ok := cond.X.(*ast.BasicLit); !ok {
			return true
		}
		if _, ok := cond.Y.(*ast.BasicLit); ok {
			// Don't flag lit == lit conditions, just in case
			return true
		}
		j.Errorf(cond, "don't use Yoda conditions")
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

"""



```