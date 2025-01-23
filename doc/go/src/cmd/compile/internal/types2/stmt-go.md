Response: Let's break down the thought process for analyzing the provided Go code snippet and generating the comprehensive explanation.

**1. Initial Understanding and Goal:**

The first step is to recognize that this code is part of the `types2` package in the Go compiler (`cmd/compile/internal`). The immediate goal is to understand the *functionality* of the `stmt.go` file. The prompt specifically asks for a listing of its functions, inference about the Go language features it implements, code examples, handling of command-line arguments, and common pitfalls.

**2. Identifying Key Functions and Their Roles:**

The most direct approach is to go through the file and identify the top-level functions. This gives us a starting point for understanding the major responsibilities of the file. I would list them out:

* `funcBody`
* `usage`
* `simpleStmt`
* `trimTrailingEmptyStmts`
* `stmtList`
* `multipleSwitchDefaults`
* `multipleSelectDefaults`
* `openScope`
* `closeScope`
* `suspendedCall`
* `goVal`
* `caseValues`
* `isNil`
* `caseTypes`
* `stmt`
* `switchStmt`
* `typeSwitchStmt`
* `rangeStmt`
* `rangeKeyVal`

For each function, I would try to infer its purpose based on its name and the types of its parameters. For example:

* `funcBody`:  Likely handles the type checking of the body of a function. The parameters `decl`, `name`, `sig`, `body` strongly suggest this.
* `usage`:  Probably related to checking if variables are used.
* `stmtList`, `stmt`:  Almost certainly deal with processing lists of statements and individual statements, respectively.
* `switchStmt`, `typeSwitchStmt`, `rangeStmt`: These directly map to specific Go control flow structures.

**3. Connecting Functions to Go Language Features:**

Once the major functions are identified, the next step is to connect them to the Go language features they are likely responsible for implementing. This involves looking for patterns and keywords within the function bodies.

* **`funcBody`**:  Clear association with function definitions.
* **`usage`**:  Related to variable declarations and usage, potentially the "declared and not used" compiler warning.
* **`stmtList`, `stmt`**:  General statement processing, but the `switch` statement inside `stmt` points to handling control flow.
* **`switchStmt`, `caseValues`**: Implementing the `switch` statement, specifically handling case value comparisons.
* **`typeSwitchStmt`, `caseTypes`**: Implementing the `switch x.(type)` construct.
* **`rangeStmt`, `rangeKeyVal`**:  Implementing the `for...range` loop.
* **`suspendedCall`**:  Handles `go` and `defer` statements, which involve function calls.

**4. Inferring Logic and Potential Issues:**

With a basic understanding of the functions' roles, I'd start to infer the logic within them. For instance:

* `funcBody`:  The saving and restoring of the `environment` suggests handling scope. The check for `missing return` indicates it's validating function return values.
* `usage`:  The iteration through `scope.elems` and checking `v.used` confirms its purpose.
* `stmt`: The large `switch` statement on the statement type reveals how different statement kinds are processed.
* `caseValues`, `caseTypes`: The checks for duplicate cases are important for the correctness of `switch` statements.

This is also where potential pitfalls or error-prone areas might emerge. For example, the check for "unused variable" in `funcBody` and `usage` suggests that a common mistake is declaring variables that are never used. The checks for `fallthrough` and misplaced `break`/`continue` in `stmt` highlight common control flow errors.

**5. Generating Code Examples:**

To illustrate the functionality, creating simple Go code examples that exercise the features implemented by the functions is crucial. The examples should be focused and demonstrate the specific behavior being discussed.

* For `funcBody`, a simple function with a return statement is sufficient.
* For `usage`, declare an unused variable.
* For `switchStmt`, create a `switch` statement with duplicate cases.
* For `typeSwitchStmt`, create a `type switch` with duplicate types.
* For `rangeStmt`, demonstrate the different forms of `range` (slice, map, string).

**6. Considering Command-Line Arguments:**

The code itself doesn't directly parse command-line arguments. However, the presence of `check.conf.IgnoreFuncBodies` and `check.conf.Trace` suggests that the `Checker` struct (likely configured elsewhere) has options that can influence the type-checking process. The prompt asks for this even if it's not directly in this file, so it's important to mention the likely existence of such configurations.

**7. Addressing Common Mistakes:**

Based on the inferred logic and the checks within the code, I'd list potential common mistakes. These are often related to the constraints and rules that the type checker enforces.

* Unused variables.
* Duplicate `case` values in `switch` statements.
* Duplicate types in `type switch` statements.
* Misplaced `break`, `continue`, and `fallthrough`.
* Invalid expressions in `go` and `defer` statements.

**8. Structuring the Explanation:**

Finally, organize the information logically, using clear headings and bullet points to make it easy to read and understand. Start with a summary of the file's purpose, then detail the functionality of each function, provide illustrative code examples, discuss command-line arguments (if applicable), and conclude with common mistakes.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe `usage` also handles unused imports. **Correction:** The code specifically iterates over `scope.elems`, which are variables, not imports. Unused imports are likely handled elsewhere.
* **Initial thought:** The command-line arguments are parsed in this file. **Correction:**  The code uses `check.conf`, implying the configuration happens elsewhere. Mention the likely existence of such a configuration.
* **Realization:** The `goVal` function has a comment about matching the implementation restriction of other compilers. This is a detail worth mentioning.

By following these steps – understanding the code's context, identifying key functions, connecting them to language features, inferring logic, generating examples, and considering potential pitfalls – a comprehensive and accurate explanation can be constructed.
这段代码是 Go 语言编译器 `cmd/compile/internal/types2` 包中 `stmt.go` 文件的一部分，主要负责对 Go 语言的各种语句进行类型检查。以下是它的主要功能：

**1. 函数体类型检查 (`funcBody`)**

* **功能:** 对函数体内的语句列表进行类型检查。
* **实现:**
    * 设置函数体内的作用域环境。
    * 递归调用 `stmtList` 处理函数体内的语句列表。
    * 检查函数是否有标签，如果有则调用 `labels` 进行标签检查。
    * 如果函数有返回值且函数体没有以 `return` 语句结尾，则报错 "missing return"。
    * 检查函数体内声明的变量是否被使用，如果未被使用则发出警告。
* **Go 代码示例:**
```go
package main

func add(a int, b int) int {
	sum := a + b // 声明并使用变量 sum
	return sum
}

func greet(name string) { // 没有返回值
	println("Hello, " + name + "!")
}

func unused() int {
	x := 10 // 声明了变量 x，但未使用
	return 0
}
```
* **假设的输入与输出:**
    * **输入:** `add` 函数的抽象语法树 (AST)。
    * **输出:** 如果类型正确，则无输出。如果 `sum` 未被使用，则会输出类似 "declared and not used: sum"。如果 `add` 函数没有 `return` 语句，则会输出 "missing return"。

**2. 检查变量使用情况 (`usage`)**

* **功能:** 检查给定作用域内声明的变量是否被使用。
* **实现:**
    * 遍历作用域内的所有元素，找到变量。
    * 如果变量的 `used` 字段为 `false`，则表示该变量未被使用，添加到 `unused` 列表中。
    * 对 `unused` 列表进行排序，并对每个未使用的变量发出警告。
    * 递归调用 `usage` 检查子作用域（除了函数字面量）。
* **Go 代码示例:**  见 `funcBody` 中的 `unused` 函数示例。

**3. 简单语句类型检查 (`simpleStmt`)**

* **功能:** 对简单的语句（如赋值语句、表达式语句）进行类型检查。
* **实现:** 如果语句不为空，则调用 `stmt` 进行类型检查。

**4. 去除尾部空语句 (`trimTrailingEmptyStmts`)**

* **功能:** 从语句列表中移除尾部的空语句。
* **实现:** 从列表末尾开始向前遍历，直到遇到非空语句或列表为空。

**5. 语句列表类型检查 (`stmtList`)**

* **功能:** 对语句列表中的每个语句进行类型检查。
* **实现:**
    * 遍历语句列表，对每个语句调用 `stmt` 进行类型检查。
    * 处理 `fallthrough` 语句的上下文，确保它只能出现在 `switch` 或 `select` 语句的 `case` 子句中，并且不能出现在最后一个 `case` 子句中。

**6. 检查重复的 `switch` 默认分支 (`multipleSwitchDefaults`)**

* **功能:** 检查 `switch` 语句中是否存在多个 `default` 分支。
* **实现:** 遍历 `case` 子句列表，如果找到多个 `Cases` 为 `nil` 的子句（表示 `default`），则报错。

**7. 检查重复的 `select` 默认分支 (`multipleSelectDefaults`)**

* **功能:** 检查 `select` 语句中是否存在多个 `default` 分支。
* **实现:** 遍历 `comm` 子句列表，如果找到多个 `Comm` 为 `nil` 的子句（表示 `default`），则报错。

**8. 打开和关闭作用域 (`openScope`, `closeScope`)**

* **功能:** 创建和销毁新的作用域。
* **实现:** `openScope` 创建一个新的 `Scope` 对象，并将其设置为当前的 `check.scope`。`closeScope` 将 `check.scope` 恢复到父作用域。

**9. `go` 和 `defer` 语句类型检查 (`suspendedCall`)**

* **功能:** 对 `go` 和 `defer` 关键字后跟随的函数调用进行类型检查。
* **实现:**
    * 检查 `call` 是否为函数调用表达式。
    * 调用 `rawExpr` 对函数调用表达式进行初步的类型检查。
    * 根据 `rawExpr` 的结果，判断是否需要发出错误信息，例如 "expression in go must be function call" 或 "discards result of ..."。

**10. 获取常量值的 Go 值 (`goVal`)**

* **功能:** 将 `constant.Value` 转换为 Go 的 `interface{}` 类型的值。
* **实现:**  只对整数、浮点数和字符串类型的常量进行转换，这与其他 Go 编译器的实现限制相匹配。

**11. `switch` 语句的 `case` 值类型检查 (`caseValues`)**

* **功能:** 检查 `switch` 语句的 `case` 子句中的值是否与 `switch` 表达式的类型兼容，并检查是否存在重复的 `case` 值。
* **实现:**
    * 遍历 `case` 子句中的表达式。
    * 对每个表达式进行类型检查，并将其转换为 `switch` 表达式的类型。
    * 检查转换后的值是否与 `switch` 表达式的值可以进行比较。
    * 如果 `case` 值是常量，则将其转换为 Go 的值，并检查是否已存在相同的常量值（和类型）。
* **Go 代码示例:**
```go
package main

func main() {
	x := 1
	switch x {
	case 1:
		println("one")
	case 2:
		println("two")
	case 1: // 错误：重复的 case 值
		println("another one")
	}
}
```
* **假设的输入与输出:**
    * **输入:** 上述 `switch` 语句的 AST。
    * **输出:** 错误信息 "duplicate case 1 in expression switch" 以及 "previous case"。

**12. 判断表达式是否为 `nil` (`isNil`)**

* **功能:** 判断给定的表达式是否表示预定义的 `nil` 值。
* **实现:** 检查表达式是否为标识符 `nil`（可能包含在括号中）。

**13. 类型 `switch` 语句的 `case` 类型检查 (`caseTypes`)**

* **功能:** 检查类型 `switch` 语句的 `case` 子句中的类型是否合法，并检查是否存在重复的类型。
* **实现:**
    * 遍历 `case` 子句中的类型表达式。
    * 对每个类型表达式进行类型检查。
    * 检查是否存在重复的类型。
    * 验证每个类型是否与类型 `switch` 表达式的类型兼容。
    * 返回 `case` 子句中引入的变量的类型。如果只有一个类型，则返回该类型；如果有多个类型或包含 `nil`，则返回 `switch` 表达式的类型。
* **Go 代码示例:**
```go
package main

import "fmt"

func typeSwitch(i interface{}) {
	switch v := i.(type) {
	case int:
		fmt.Printf("int: %d\n", v)
	case string:
		fmt.Printf("string: %s\n", v)
	case int: // 错误：重复的 case 类型
		fmt.Println("another int")
	default:
		fmt.Printf("unknown: %v\n", v)
	}
}
```
* **假设的输入与输出:**
    * **输入:** 上述 `typeSwitch` 函数的 `switch` 语句的 AST。
    * **输出:** 错误信息 "duplicate case int in type switch" 以及 "previous case"。

**14. 通用语句类型检查 (`stmt`)**

* **功能:** 对各种类型的语句进行类型检查，是语句类型检查的核心函数。
* **实现:** 使用 `switch` 语句根据不同的语句类型调用相应的处理函数，例如：
    * `EmptyStmt`: 空语句，忽略。
    * `DeclStmt`: 声明语句，调用 `declStmt`。
    * `LabeledStmt`: 标签语句，递归调用 `stmt` 处理内部语句。
    * `ExprStmt`: 表达式语句，检查表达式的用途。
    * `SendStmt`: 发送语句，检查通道和发送的值的类型。
    * `AssignStmt`: 赋值语句，调用 `assignVars` 或 `shortVarDecl`。
    * `CallStmt`: 调用语句 (`go` 或 `defer`)，调用 `suspendedCall`。
    * `ReturnStmt`: 返回语句，检查返回值是否与函数签名匹配。
    * `BranchStmt`: 分支语句 (`break`, `continue`, `goto`, `fallthrough`)，检查其是否在合法的上下文中使用。
    * `BlockStmt`: 代码块，打开新的作用域并调用 `stmtList` 处理内部语句。
    * `IfStmt`: `if` 语句，检查条件表达式的类型，并递归调用 `stmt` 处理 `then` 和 `else` 分支。
    * `SwitchStmt`: `switch` 语句，区分类型 `switch` 和表达式 `switch`，并调用相应的处理函数。
    * `SelectStmt`: `select` 语句，检查 `case` 子句中的发送或接收操作。
    * `ForStmt`: `for` 循环语句，区分 `range` 循环和普通 `for` 循环，并调用相应的处理函数。

**15. 表达式 `switch` 语句类型检查 (`switchStmt`)**

* **功能:** 对非类型 `switch` 语句进行类型检查。
* **实现:**
    * 检查 `switch` 表达式的类型，确保其是可比较的。
    * 调用 `multipleSwitchDefaults` 检查是否有重复的 `default` 分支。
    * 遍历 `case` 子句，调用 `caseValues` 检查 `case` 值。
    * 为每个 `case` 子句打开新的作用域，并调用 `stmtList` 处理内部语句。

**16. 类型 `switch` 语句类型检查 (`typeSwitchStmt`)**

* **功能:** 对类型 `switch` 语句进行类型检查。
* **实现:**
    * 检查类型断言表达式的格式。
    * 检查 `switch` 表达式是否为接口类型。
    * 调用 `multipleSwitchDefaults` 检查是否有重复的 `default` 分支。
    * 遍历 `case` 子句，调用 `caseTypes` 检查 `case` 类型。
    * 为每个 `case` 子句打开新的作用域，声明 `case` 子句中定义的变量，并调用 `stmtList` 处理内部语句。
    * 检查类型 `switch` 中声明的变量是否被使用。

**17. `range` 循环语句类型检查 (`rangeStmt`)**

* **功能:** 对 `for...range` 循环语句进行类型检查。
* **实现:**
    * 检查 `range` 表达式的类型，确定迭代的键和值类型。
    * 根据是否使用了短变量声明 (`:=`)，进行相应的变量声明和赋值检查。
    * 调用 `stmt` 处理循环体。

**18. 获取 `range` 循环的键值类型 (`rangeKeyVal`)**

* **功能:** 根据 `range` 表达式的类型，推断出 `range` 循环的键和值类型。
* **实现:** 使用 `switch` 语句根据不同的类型返回相应的键和值类型。例如，对数组或切片返回 `int` 和元素类型，对 `map` 返回键类型和值类型，对字符串返回 `int` 和 `rune`。

**关于命令行参数:**

这段代码本身并不直接处理命令行参数。它是 `types2` 包的一部分，负责类型检查的逻辑。命令行参数的处理通常发生在 Go 编译器的其他阶段，例如词法分析、语法分析和主程序入口。

然而，可以推断出一些可能的配置选项，这些选项可能会影响此代码的执行，例如：

* **`-gcflags=-G=3` 或 `-lang=go1.22` 等:**  这些标志会影响 Go 语言的版本，进而影响一些新的语言特性（例如 `range` over integer）是否启用。`rangeKeyVal` 函数中 `allowVersion` 的使用就体现了这一点。
* **可能存在控制是否忽略函数体的选项:** 从 `check.conf.IgnoreFuncBodies` 可以推断，可能存在一个命令行参数或构建标签来控制是否跳过函数体的类型检查。
* **可能存在控制是否启用 tracing 的选项:**  `check.conf.Trace` 表明可能有一个选项来启用或禁用类型检查过程的跟踪输出。

**使用者易犯错的点:**

1. **`switch` 语句中 `case` 值或类型重复:**  如上代码示例所示，在同一个 `switch` 语句中出现相同的 `case` 值或类型会导致编译错误。
2. **类型 `switch` 中变量声明后未使用:** 如果在类型 `switch` 的 `case` 子句中使用短变量声明，但声明的变量没有在 `case` 代码块中使用，则会收到 "declared and not used" 的警告。
3. **`fallthrough` 的误用:**  `fallthrough` 语句只能用于 `switch` 语句的 `case` 子句中，并且不能出现在最后一个 `case` 子句中。在类型 `switch` 中使用 `fallthrough` 也是不允许的。
4. **在 `go` 或 `defer` 语句后跟非函数调用表达式:** `go` 和 `defer` 关键字后面必须跟随函数调用。
5. **`range` 循环中迭代变量的错误使用:**  例如，尝试在只能迭代一个值的类型上使用两个迭代变量，或者在不允许迭代变量的类型上使用迭代变量。
6. **在有返回值的函数中缺少 `return` 语句:**  如果函数签名定义了返回值，那么所有可能的执行路径都必须以 `return` 语句结束。
7. **声明了未使用的变量:** 虽然这通常是警告而不是错误，但它表明代码可能存在冗余或潜在的逻辑问题。

总而言之，`stmt.go` 文件是 Go 语言编译器类型检查的关键部分，它负责验证各种语句是否符合 Go 语言的类型规则，并帮助开发者在编译时发现潜在的错误。理解其功能有助于更深入地了解 Go 语言的类型系统和编译过程。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/stmt.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements typechecking of statements.

package types2

import (
	"cmd/compile/internal/syntax"
	"go/constant"
	"internal/buildcfg"
	. "internal/types/errors"
	"slices"
)

// decl may be nil
func (check *Checker) funcBody(decl *declInfo, name string, sig *Signature, body *syntax.BlockStmt, iota constant.Value) {
	if check.conf.IgnoreFuncBodies {
		panic("function body not ignored")
	}

	if check.conf.Trace {
		check.trace(body.Pos(), "-- %s: %s", name, sig)
	}

	// save/restore current environment and set up function environment
	// (and use 0 indentation at function start)
	defer func(env environment, indent int) {
		check.environment = env
		check.indent = indent
	}(check.environment, check.indent)
	check.environment = environment{
		decl:    decl,
		scope:   sig.scope,
		version: check.version, // TODO(adonovan): would decl.version (if decl != nil) be better?
		iota:    iota,
		sig:     sig,
	}
	check.indent = 0

	check.stmtList(0, body.List)

	if check.hasLabel && !check.conf.IgnoreBranchErrors {
		check.labels(body)
	}

	if sig.results.Len() > 0 && !check.isTerminating(body, "") {
		check.error(body.Rbrace, MissingReturn, "missing return")
	}

	// spec: "Implementation restriction: A compiler may make it illegal to
	// declare a variable inside a function body if the variable is never used."
	check.usage(sig.scope)
}

func (check *Checker) usage(scope *Scope) {
	var unused []*Var
	for name, elem := range scope.elems {
		elem = resolve(name, elem)
		if v, _ := elem.(*Var); v != nil && !v.used {
			unused = append(unused, v)
		}
	}
	slices.SortFunc(unused, func(a, b *Var) int {
		return cmpPos(a.pos, b.pos)
	})
	for _, v := range unused {
		check.softErrorf(v.pos, UnusedVar, "declared and not used: %s", v.name)
	}

	for _, scope := range scope.children {
		// Don't go inside function literal scopes a second time;
		// they are handled explicitly by funcBody.
		if !scope.isFunc {
			check.usage(scope)
		}
	}
}

// stmtContext is a bitset describing which
// control-flow statements are permissible,
// and provides additional context information
// for better error messages.
type stmtContext uint

const (
	// permissible control-flow statements
	breakOk stmtContext = 1 << iota
	continueOk
	fallthroughOk

	// additional context information
	finalSwitchCase
	inTypeSwitch
)

func (check *Checker) simpleStmt(s syntax.Stmt) {
	if s != nil {
		check.stmt(0, s)
	}
}

func trimTrailingEmptyStmts(list []syntax.Stmt) []syntax.Stmt {
	for i := len(list); i > 0; i-- {
		if _, ok := list[i-1].(*syntax.EmptyStmt); !ok {
			return list[:i]
		}
	}
	return nil
}

func (check *Checker) stmtList(ctxt stmtContext, list []syntax.Stmt) {
	ok := ctxt&fallthroughOk != 0
	inner := ctxt &^ fallthroughOk
	list = trimTrailingEmptyStmts(list) // trailing empty statements are "invisible" to fallthrough analysis
	for i, s := range list {
		inner := inner
		if ok && i+1 == len(list) {
			inner |= fallthroughOk
		}
		check.stmt(inner, s)
	}
}

func (check *Checker) multipleSwitchDefaults(list []*syntax.CaseClause) {
	var first *syntax.CaseClause
	for _, c := range list {
		if c.Cases == nil {
			if first != nil {
				check.errorf(c, DuplicateDefault, "multiple defaults (first at %s)", first.Pos())
				// TODO(gri) probably ok to bail out after first error (and simplify this code)
			} else {
				first = c
			}
		}
	}
}

func (check *Checker) multipleSelectDefaults(list []*syntax.CommClause) {
	var first *syntax.CommClause
	for _, c := range list {
		if c.Comm == nil {
			if first != nil {
				check.errorf(c, DuplicateDefault, "multiple defaults (first at %s)", first.Pos())
				// TODO(gri) probably ok to bail out after first error (and simplify this code)
			} else {
				first = c
			}
		}
	}
}

func (check *Checker) openScope(node syntax.Node, comment string) {
	scope := NewScope(check.scope, node.Pos(), syntax.EndPos(node), comment)
	check.recordScope(node, scope)
	check.scope = scope
}

func (check *Checker) closeScope() {
	check.scope = check.scope.Parent()
}

func (check *Checker) suspendedCall(keyword string, call syntax.Expr) {
	code := InvalidDefer
	if keyword == "go" {
		code = InvalidGo
	}

	if _, ok := call.(*syntax.CallExpr); !ok {
		check.errorf(call, code, "expression in %s must be function call", keyword)
		check.use(call)
		return
	}

	var x operand
	var msg string
	switch check.rawExpr(nil, &x, call, nil, false) {
	case conversion:
		msg = "requires function call, not conversion"
	case expression:
		msg = "discards result of"
		code = UnusedResults
	case statement:
		return
	default:
		panic("unreachable")
	}
	check.errorf(&x, code, "%s %s %s", keyword, msg, &x)
}

// goVal returns the Go value for val, or nil.
func goVal(val constant.Value) interface{} {
	// val should exist, but be conservative and check
	if val == nil {
		return nil
	}
	// Match implementation restriction of other compilers.
	// gc only checks duplicates for integer, floating-point
	// and string values, so only create Go values for these
	// types.
	switch val.Kind() {
	case constant.Int:
		if x, ok := constant.Int64Val(val); ok {
			return x
		}
		if x, ok := constant.Uint64Val(val); ok {
			return x
		}
	case constant.Float:
		if x, ok := constant.Float64Val(val); ok {
			return x
		}
	case constant.String:
		return constant.StringVal(val)
	}
	return nil
}

// A valueMap maps a case value (of a basic Go type) to a list of positions
// where the same case value appeared, together with the corresponding case
// types.
// Since two case values may have the same "underlying" value but different
// types we need to also check the value's types (e.g., byte(1) vs myByte(1))
// when the switch expression is of interface type.
type (
	valueMap  map[interface{}][]valueType // underlying Go value -> valueType
	valueType struct {
		pos syntax.Pos
		typ Type
	}
)

func (check *Checker) caseValues(x *operand, values []syntax.Expr, seen valueMap) {
L:
	for _, e := range values {
		var v operand
		check.expr(nil, &v, e)
		if x.mode == invalid || v.mode == invalid {
			continue L
		}
		check.convertUntyped(&v, x.typ)
		if v.mode == invalid {
			continue L
		}
		// Order matters: By comparing v against x, error positions are at the case values.
		res := v // keep original v unchanged
		check.comparison(&res, x, syntax.Eql, true)
		if res.mode == invalid {
			continue L
		}
		if v.mode != constant_ {
			continue L // we're done
		}
		// look for duplicate values
		if val := goVal(v.val); val != nil {
			// look for duplicate types for a given value
			// (quadratic algorithm, but these lists tend to be very short)
			for _, vt := range seen[val] {
				if Identical(v.typ, vt.typ) {
					err := check.newError(DuplicateCase)
					err.addf(&v, "duplicate case %s in expression switch", &v)
					err.addf(vt.pos, "previous case")
					err.report()
					continue L
				}
			}
			seen[val] = append(seen[val], valueType{v.Pos(), v.typ})
		}
	}
}

// isNil reports whether the expression e denotes the predeclared value nil.
func (check *Checker) isNil(e syntax.Expr) bool {
	// The only way to express the nil value is by literally writing nil (possibly in parentheses).
	if name, _ := syntax.Unparen(e).(*syntax.Name); name != nil {
		_, ok := check.lookup(name.Value).(*Nil)
		return ok
	}
	return false
}

// caseTypes typechecks the type expressions of a type case, checks for duplicate types
// using the seen map, and verifies that each type is valid with respect to the type of
// the operand x corresponding to the type switch expression. If that expression is not
// valid, x must be nil.
//
//	switch <x>.(type) {
//	case <types>: ...
//	...
//	}
//
// caseTypes returns the case-specific type for a variable v introduced through a short
// variable declaration by the type switch:
//
//	switch v := <x>.(type) {
//	case <types>: // T is the type of <v> in this case
//	...
//	}
//
// If there is exactly one type expression, T is the type of that expression. If there
// are multiple type expressions, or if predeclared nil is among the types, the result
// is the type of x. If x is invalid (nil), the result is the invalid type.
func (check *Checker) caseTypes(x *operand, types []syntax.Expr, seen map[Type]syntax.Expr) Type {
	var T Type
	var dummy operand
L:
	for _, e := range types {
		// The spec allows the value nil instead of a type.
		if check.isNil(e) {
			T = nil
			check.expr(nil, &dummy, e) // run e through expr so we get the usual Info recordings
		} else {
			T = check.varType(e)
			if !isValid(T) {
				continue L
			}
		}
		// look for duplicate types
		// (quadratic algorithm, but type switches tend to be reasonably small)
		for t, other := range seen {
			if T == nil && t == nil || T != nil && t != nil && Identical(T, t) {
				// talk about "case" rather than "type" because of nil case
				Ts := "nil"
				if T != nil {
					Ts = TypeString(T, check.qualifier)
				}
				err := check.newError(DuplicateCase)
				err.addf(e, "duplicate case %s in type switch", Ts)
				err.addf(other, "previous case")
				err.report()
				continue L
			}
		}
		seen[T] = e
		if x != nil && T != nil {
			check.typeAssertion(e, x, T, true)
		}
	}

	// spec: "In clauses with a case listing exactly one type, the variable has that type;
	// otherwise, the variable has the type of the expression in the TypeSwitchGuard.
	if len(types) != 1 || T == nil {
		T = Typ[Invalid]
		if x != nil {
			T = x.typ
		}
	}

	assert(T != nil)
	return T
}

// TODO(gri) Once we are certain that typeHash is correct in all situations, use this version of caseTypes instead.
// (Currently it may be possible that different types have identical names and import paths due to ImporterFrom.)
func (check *Checker) caseTypes_currently_unused(x *operand, xtyp *Interface, types []syntax.Expr, seen map[string]syntax.Expr) Type {
	var T Type
	var dummy operand
L:
	for _, e := range types {
		// The spec allows the value nil instead of a type.
		var hash string
		if check.isNil(e) {
			check.expr(nil, &dummy, e) // run e through expr so we get the usual Info recordings
			T = nil
			hash = "<nil>" // avoid collision with a type named nil
		} else {
			T = check.varType(e)
			if !isValid(T) {
				continue L
			}
			panic("enable typeHash(T, nil)")
			// hash = typeHash(T, nil)
		}
		// look for duplicate types
		if other := seen[hash]; other != nil {
			// talk about "case" rather than "type" because of nil case
			Ts := "nil"
			if T != nil {
				Ts = TypeString(T, check.qualifier)
			}
			err := check.newError(DuplicateCase)
			err.addf(e, "duplicate case %s in type switch", Ts)
			err.addf(other, "previous case")
			err.report()
			continue L
		}
		seen[hash] = e
		if T != nil {
			check.typeAssertion(e, x, T, true)
		}
	}

	// spec: "In clauses with a case listing exactly one type, the variable has that type;
	// otherwise, the variable has the type of the expression in the TypeSwitchGuard.
	if len(types) != 1 || T == nil {
		T = Typ[Invalid]
		if x != nil {
			T = x.typ
		}
	}

	assert(T != nil)
	return T
}

// stmt typechecks statement s.
func (check *Checker) stmt(ctxt stmtContext, s syntax.Stmt) {
	// statements must end with the same top scope as they started with
	if debug {
		defer func(scope *Scope) {
			// don't check if code is panicking
			if p := recover(); p != nil {
				panic(p)
			}
			assert(scope == check.scope)
		}(check.scope)
	}

	// process collected function literals before scope changes
	defer check.processDelayed(len(check.delayed))

	// reset context for statements of inner blocks
	inner := ctxt &^ (fallthroughOk | finalSwitchCase | inTypeSwitch)

	switch s := s.(type) {
	case *syntax.EmptyStmt:
		// ignore

	case *syntax.DeclStmt:
		check.declStmt(s.DeclList)

	case *syntax.LabeledStmt:
		check.hasLabel = true
		check.stmt(ctxt, s.Stmt)

	case *syntax.ExprStmt:
		// spec: "With the exception of specific built-in functions,
		// function and method calls and receive operations can appear
		// in statement context. Such statements may be parenthesized."
		var x operand
		kind := check.rawExpr(nil, &x, s.X, nil, false)
		var msg string
		var code Code
		switch x.mode {
		default:
			if kind == statement {
				return
			}
			msg = "is not used"
			code = UnusedExpr
		case builtin:
			msg = "must be called"
			code = UncalledBuiltin
		case typexpr:
			msg = "is not an expression"
			code = NotAnExpr
		}
		check.errorf(&x, code, "%s %s", &x, msg)

	case *syntax.SendStmt:
		var ch, val operand
		check.expr(nil, &ch, s.Chan)
		check.expr(nil, &val, s.Value)
		if ch.mode == invalid || val.mode == invalid {
			return
		}
		u := coreType(ch.typ)
		if u == nil {
			check.errorf(s, InvalidSend, invalidOp+"cannot send to %s: no core type", &ch)
			return
		}
		uch, _ := u.(*Chan)
		if uch == nil {
			check.errorf(s, InvalidSend, invalidOp+"cannot send to non-channel %s", &ch)
			return
		}
		if uch.dir == RecvOnly {
			check.errorf(s, InvalidSend, invalidOp+"cannot send to receive-only channel %s", &ch)
			return
		}
		check.assignment(&val, uch.elem, "send")

	case *syntax.AssignStmt:
		if s.Rhs == nil {
			// x++ or x--
			// (no need to call unpackExpr as s.Lhs must be single-valued)
			var x operand
			check.expr(nil, &x, s.Lhs)
			if x.mode == invalid {
				return
			}
			if !allNumeric(x.typ) {
				check.errorf(s.Lhs, NonNumericIncDec, invalidOp+"%s%s%s (non-numeric type %s)", s.Lhs, s.Op, s.Op, x.typ)
				return
			}
			check.assignVar(s.Lhs, nil, &x, "assignment")
			return
		}

		lhs := syntax.UnpackListExpr(s.Lhs)
		rhs := syntax.UnpackListExpr(s.Rhs)
		switch s.Op {
		case 0:
			check.assignVars(lhs, rhs)
			return
		case syntax.Def:
			check.shortVarDecl(s.Pos(), lhs, rhs)
			return
		}

		// assignment operations
		if len(lhs) != 1 || len(rhs) != 1 {
			check.errorf(s, MultiValAssignOp, "assignment operation %s requires single-valued expressions", s.Op)
			return
		}

		var x operand
		check.binary(&x, nil, lhs[0], rhs[0], s.Op)
		check.assignVar(lhs[0], nil, &x, "assignment")

	case *syntax.CallStmt:
		kind := "go"
		if s.Tok == syntax.Defer {
			kind = "defer"
		}
		check.suspendedCall(kind, s.Call)

	case *syntax.ReturnStmt:
		res := check.sig.results
		// Return with implicit results allowed for function with named results.
		// (If one is named, all are named.)
		results := syntax.UnpackListExpr(s.Results)
		if len(results) == 0 && res.Len() > 0 && res.vars[0].name != "" {
			// spec: "Implementation restriction: A compiler may disallow an empty expression
			// list in a "return" statement if a different entity (constant, type, or variable)
			// with the same name as a result parameter is in scope at the place of the return."
			for _, obj := range res.vars {
				if alt := check.lookup(obj.name); alt != nil && alt != obj {
					err := check.newError(OutOfScopeResult)
					err.addf(s, "result parameter %s not in scope at return", obj.name)
					err.addf(alt, "inner declaration of %s", obj)
					err.report()
					// ok to continue
				}
			}
		} else {
			var lhs []*Var
			if res.Len() > 0 {
				lhs = res.vars
			}
			check.initVars(lhs, results, s)
		}

	case *syntax.BranchStmt:
		if s.Label != nil {
			check.hasLabel = true
			break // checked in 2nd pass (check.labels)
		}
		if check.conf.IgnoreBranchErrors {
			break
		}
		switch s.Tok {
		case syntax.Break:
			if ctxt&breakOk == 0 {
				check.error(s, MisplacedBreak, "break not in for, switch, or select statement")
			}
		case syntax.Continue:
			if ctxt&continueOk == 0 {
				check.error(s, MisplacedContinue, "continue not in for statement")
			}
		case syntax.Fallthrough:
			if ctxt&fallthroughOk == 0 {
				var msg string
				switch {
				case ctxt&finalSwitchCase != 0:
					msg = "cannot fallthrough final case in switch"
				case ctxt&inTypeSwitch != 0:
					msg = "cannot fallthrough in type switch"
				default:
					msg = "fallthrough statement out of place"
				}
				check.error(s, MisplacedFallthrough, msg)
			}
		case syntax.Goto:
			// goto's must have labels, should have been caught above
			fallthrough
		default:
			check.errorf(s, InvalidSyntaxTree, "branch statement: %s", s.Tok)
		}

	case *syntax.BlockStmt:
		check.openScope(s, "block")
		defer check.closeScope()

		check.stmtList(inner, s.List)

	case *syntax.IfStmt:
		check.openScope(s, "if")
		defer check.closeScope()

		check.simpleStmt(s.Init)
		var x operand
		check.expr(nil, &x, s.Cond)
		if x.mode != invalid && !allBoolean(x.typ) {
			check.error(s.Cond, InvalidCond, "non-boolean condition in if statement")
		}
		check.stmt(inner, s.Then)
		// The parser produces a correct AST but if it was modified
		// elsewhere the else branch may be invalid. Check again.
		switch s.Else.(type) {
		case nil:
			// valid or error already reported
		case *syntax.IfStmt, *syntax.BlockStmt:
			check.stmt(inner, s.Else)
		default:
			check.error(s.Else, InvalidSyntaxTree, "invalid else branch in if statement")
		}

	case *syntax.SwitchStmt:
		inner |= breakOk
		check.openScope(s, "switch")
		defer check.closeScope()

		check.simpleStmt(s.Init)

		if g, _ := s.Tag.(*syntax.TypeSwitchGuard); g != nil {
			check.typeSwitchStmt(inner|inTypeSwitch, s, g)
		} else {
			check.switchStmt(inner, s)
		}

	case *syntax.SelectStmt:
		inner |= breakOk

		check.multipleSelectDefaults(s.Body)

		for _, clause := range s.Body {
			if clause == nil {
				continue // error reported before
			}

			// clause.Comm must be a SendStmt, RecvStmt, or default case
			valid := false
			var rhs syntax.Expr // rhs of RecvStmt, or nil
			switch s := clause.Comm.(type) {
			case nil, *syntax.SendStmt:
				valid = true
			case *syntax.AssignStmt:
				if _, ok := s.Rhs.(*syntax.ListExpr); !ok {
					rhs = s.Rhs
				}
			case *syntax.ExprStmt:
				rhs = s.X
			}

			// if present, rhs must be a receive operation
			if rhs != nil {
				if x, _ := syntax.Unparen(rhs).(*syntax.Operation); x != nil && x.Y == nil && x.Op == syntax.Recv {
					valid = true
				}
			}

			if !valid {
				check.error(clause.Comm, InvalidSelectCase, "select case must be send or receive (possibly with assignment)")
				continue
			}
			check.openScope(clause, "case")
			if clause.Comm != nil {
				check.stmt(inner, clause.Comm)
			}
			check.stmtList(inner, clause.Body)
			check.closeScope()
		}

	case *syntax.ForStmt:
		inner |= breakOk | continueOk

		if rclause, _ := s.Init.(*syntax.RangeClause); rclause != nil {
			check.rangeStmt(inner, s, rclause)
			break
		}

		check.openScope(s, "for")
		defer check.closeScope()

		check.simpleStmt(s.Init)
		if s.Cond != nil {
			var x operand
			check.expr(nil, &x, s.Cond)
			if x.mode != invalid && !allBoolean(x.typ) {
				check.error(s.Cond, InvalidCond, "non-boolean condition in for statement")
			}
		}
		check.simpleStmt(s.Post)
		// spec: "The init statement may be a short variable
		// declaration, but the post statement must not."
		if s, _ := s.Post.(*syntax.AssignStmt); s != nil && s.Op == syntax.Def {
			// The parser already reported an error.
			check.use(s.Lhs) // avoid follow-up errors
		}
		check.stmt(inner, s.Body)

	default:
		check.error(s, InvalidSyntaxTree, "invalid statement")
	}
}

func (check *Checker) switchStmt(inner stmtContext, s *syntax.SwitchStmt) {
	// init statement already handled

	var x operand
	if s.Tag != nil {
		check.expr(nil, &x, s.Tag)
		// By checking assignment of x to an invisible temporary
		// (as a compiler would), we get all the relevant checks.
		check.assignment(&x, nil, "switch expression")
		if x.mode != invalid && !Comparable(x.typ) && !hasNil(x.typ) {
			check.errorf(&x, InvalidExprSwitch, "cannot switch on %s (%s is not comparable)", &x, x.typ)
			x.mode = invalid
		}
	} else {
		// spec: "A missing switch expression is
		// equivalent to the boolean value true."
		x.mode = constant_
		x.typ = Typ[Bool]
		x.val = constant.MakeBool(true)
		// TODO(gri) should have a better position here
		pos := s.Rbrace
		if len(s.Body) > 0 {
			pos = s.Body[0].Pos()
		}
		x.expr = syntax.NewName(pos, "true")
	}

	check.multipleSwitchDefaults(s.Body)

	seen := make(valueMap) // map of seen case values to positions and types
	for i, clause := range s.Body {
		if clause == nil {
			check.error(clause, InvalidSyntaxTree, "incorrect expression switch case")
			continue
		}
		inner := inner
		if i+1 < len(s.Body) {
			inner |= fallthroughOk
		} else {
			inner |= finalSwitchCase
		}
		check.caseValues(&x, syntax.UnpackListExpr(clause.Cases), seen)
		check.openScope(clause, "case")
		check.stmtList(inner, clause.Body)
		check.closeScope()
	}
}

func (check *Checker) typeSwitchStmt(inner stmtContext, s *syntax.SwitchStmt, guard *syntax.TypeSwitchGuard) {
	// init statement already handled

	// A type switch guard must be of the form:
	//
	//     TypeSwitchGuard = [ identifier ":=" ] PrimaryExpr "." "(" "type" ")" .
	//                          \__lhs__/        \___rhs___/

	// check lhs, if any
	lhs := guard.Lhs
	if lhs != nil {
		if lhs.Value == "_" {
			// _ := x.(type) is an invalid short variable declaration
			check.softErrorf(lhs, NoNewVar, "no new variable on left side of :=")
			lhs = nil // avoid declared and not used error below
		} else {
			check.recordDef(lhs, nil) // lhs variable is implicitly declared in each cause clause
		}
	}

	// check rhs
	var sx *operand // switch expression against which cases are compared against; nil if invalid
	{
		var x operand
		check.expr(nil, &x, guard.X)
		if x.mode != invalid {
			if isTypeParam(x.typ) {
				check.errorf(&x, InvalidTypeSwitch, "cannot use type switch on type parameter value %s", &x)
			} else if IsInterface(x.typ) {
				sx = &x
			} else {
				check.errorf(&x, InvalidTypeSwitch, "%s is not an interface", &x)
			}
		}
	}

	check.multipleSwitchDefaults(s.Body)

	var lhsVars []*Var                 // list of implicitly declared lhs variables
	seen := make(map[Type]syntax.Expr) // map of seen types to positions
	for _, clause := range s.Body {
		if clause == nil {
			check.error(s, InvalidSyntaxTree, "incorrect type switch case")
			continue
		}
		// Check each type in this type switch case.
		cases := syntax.UnpackListExpr(clause.Cases)
		T := check.caseTypes(sx, cases, seen)
		check.openScope(clause, "case")
		// If lhs exists, declare a corresponding variable in the case-local scope.
		if lhs != nil {
			obj := NewVar(lhs.Pos(), check.pkg, lhs.Value, T)
			check.declare(check.scope, nil, obj, clause.Colon)
			check.recordImplicit(clause, obj)
			// For the "declared and not used" error, all lhs variables act as
			// one; i.e., if any one of them is 'used', all of them are 'used'.
			// Collect them for later analysis.
			lhsVars = append(lhsVars, obj)
		}
		check.stmtList(inner, clause.Body)
		check.closeScope()
	}

	// If lhs exists, we must have at least one lhs variable that was used.
	// (We can't use check.usage because that only looks at one scope; and
	// we don't want to use the same variable for all scopes and change the
	// variable type underfoot.)
	if lhs != nil {
		var used bool
		for _, v := range lhsVars {
			if v.used {
				used = true
			}
			v.used = true // avoid usage error when checking entire function
		}
		if !used {
			check.softErrorf(lhs, UnusedVar, "%s declared and not used", lhs.Value)
		}
	}
}

func (check *Checker) rangeStmt(inner stmtContext, s *syntax.ForStmt, rclause *syntax.RangeClause) {
	// Convert syntax form to local variables.
	type Expr = syntax.Expr
	type identType = syntax.Name
	identName := func(n *identType) string { return n.Value }
	sKey := rclause.Lhs // possibly nil
	var sValue, sExtra syntax.Expr
	if p, _ := sKey.(*syntax.ListExpr); p != nil {
		if len(p.ElemList) < 2 {
			check.error(s, InvalidSyntaxTree, "invalid lhs in range clause")
			return
		}
		// len(p.ElemList) >= 2
		sKey = p.ElemList[0]
		sValue = p.ElemList[1]
		if len(p.ElemList) > 2 {
			// delay error reporting until we know more
			sExtra = p.ElemList[2]
		}
	}
	isDef := rclause.Def
	rangeVar := rclause.X
	noNewVarPos := s

	// Do not use rclause anymore.
	rclause = nil

	// Everything from here on is shared between cmd/compile/internal/types2 and go/types.

	// check expression to iterate over
	var x operand
	check.expr(nil, &x, rangeVar)

	// determine key/value types
	var key, val Type
	if x.mode != invalid {
		// Ranging over a type parameter is permitted if it has a core type.
		k, v, cause, ok := rangeKeyVal(x.typ, func(v goVersion) bool {
			return check.allowVersion(v)
		})
		switch {
		case !ok && cause != "":
			check.softErrorf(&x, InvalidRangeExpr, "cannot range over %s: %s", &x, cause)
		case !ok:
			check.softErrorf(&x, InvalidRangeExpr, "cannot range over %s", &x)
		case k == nil && sKey != nil:
			check.softErrorf(sKey, InvalidIterVar, "range over %s permits no iteration variables", &x)
		case v == nil && sValue != nil:
			check.softErrorf(sValue, InvalidIterVar, "range over %s permits only one iteration variable", &x)
		case sExtra != nil:
			check.softErrorf(sExtra, InvalidIterVar, "range clause permits at most two iteration variables")
		}
		key, val = k, v
	}

	// Open the for-statement block scope now, after the range clause.
	// Iteration variables declared with := need to go in this scope (was go.dev/issue/51437).
	check.openScope(s, "range")
	defer check.closeScope()

	// check assignment to/declaration of iteration variables
	// (irregular assignment, cannot easily map to existing assignment checks)

	// lhs expressions and initialization value (rhs) types
	lhs := [2]Expr{sKey, sValue} // sKey, sValue may be nil
	rhs := [2]Type{key, val}     // key, val may be nil

	rangeOverInt := isInteger(x.typ)

	if isDef {
		// short variable declaration
		var vars []*Var
		for i, lhs := range lhs {
			if lhs == nil {
				continue
			}

			// determine lhs variable
			var obj *Var
			if ident, _ := lhs.(*identType); ident != nil {
				// declare new variable
				name := identName(ident)
				obj = NewVar(ident.Pos(), check.pkg, name, nil)
				check.recordDef(ident, obj)
				// _ variables don't count as new variables
				if name != "_" {
					vars = append(vars, obj)
				}
			} else {
				check.errorf(lhs, InvalidSyntaxTree, "cannot declare %s", lhs)
				obj = NewVar(lhs.Pos(), check.pkg, "_", nil) // dummy variable
			}
			assert(obj.typ == nil)

			// initialize lhs iteration variable, if any
			typ := rhs[i]
			if typ == nil || typ == Typ[Invalid] {
				// typ == Typ[Invalid] can happen if allowVersion fails.
				obj.typ = Typ[Invalid]
				obj.used = true // don't complain about unused variable
				continue
			}

			if rangeOverInt {
				assert(i == 0) // at most one iteration variable (rhs[1] == nil or Typ[Invalid] for rangeOverInt)
				check.initVar(obj, &x, "range clause")
			} else {
				var y operand
				y.mode = value
				y.expr = lhs // we don't have a better rhs expression to use here
				y.typ = typ
				check.initVar(obj, &y, "assignment") // error is on variable, use "assignment" not "range clause"
			}
			assert(obj.typ != nil)
		}

		// declare variables
		if len(vars) > 0 {
			scopePos := s.Body.Pos()
			for _, obj := range vars {
				check.declare(check.scope, nil /* recordDef already called */, obj, scopePos)
			}
		} else {
			check.error(noNewVarPos, NoNewVar, "no new variables on left side of :=")
		}
	} else if sKey != nil /* lhs[0] != nil */ {
		// ordinary assignment
		for i, lhs := range lhs {
			if lhs == nil {
				continue
			}

			// assign to lhs iteration variable, if any
			typ := rhs[i]
			if typ == nil || typ == Typ[Invalid] {
				continue
			}

			if rangeOverInt {
				assert(i == 0) // at most one iteration variable (rhs[1] == nil or Typ[Invalid] for rangeOverInt)
				check.assignVar(lhs, nil, &x, "range clause")
				// If the assignment succeeded, if x was untyped before, it now
				// has a type inferred via the assignment. It must be an integer.
				// (go.dev/issues/67027)
				if x.mode != invalid && !isInteger(x.typ) {
					check.softErrorf(lhs, InvalidRangeExpr, "cannot use iteration variable of type %s", x.typ)
				}
			} else {
				var y operand
				y.mode = value
				y.expr = lhs // we don't have a better rhs expression to use here
				y.typ = typ
				check.assignVar(lhs, nil, &y, "assignment") // error is on variable, use "assignment" not "range clause"
			}
		}
	} else if rangeOverInt {
		// If we don't have any iteration variables, we still need to
		// check that a (possibly untyped) integer range expression x
		// is valid.
		// We do this by checking the assignment _ = x. This ensures
		// that an untyped x can be converted to a value of its default
		// type (rune or int).
		check.assignment(&x, nil, "range clause")
	}

	check.stmt(inner, s.Body)
}

// rangeKeyVal returns the key and value type produced by a range clause
// over an expression of type typ.
// If allowVersion != nil, it is used to check the required language version.
// If the range clause is not permitted, rangeKeyVal returns ok = false.
// When ok = false, rangeKeyVal may also return a reason in cause.
func rangeKeyVal(typ Type, allowVersion func(goVersion) bool) (key, val Type, cause string, ok bool) {
	bad := func(cause string) (Type, Type, string, bool) {
		return Typ[Invalid], Typ[Invalid], cause, false
	}

	orig := typ
	switch typ := arrayPtrDeref(coreType(typ)).(type) {
	case nil:
		return bad("no core type")
	case *Basic:
		if isString(typ) {
			return Typ[Int], universeRune, "", true // use 'rune' name
		}
		if isInteger(typ) {
			if allowVersion != nil && !allowVersion(go1_22) {
				return bad("requires go1.22 or later")
			}
			return orig, nil, "", true
		}
	case *Array:
		return Typ[Int], typ.elem, "", true
	case *Slice:
		return Typ[Int], typ.elem, "", true
	case *Map:
		return typ.key, typ.elem, "", true
	case *Chan:
		if typ.dir == SendOnly {
			return bad("receive from send-only channel")
		}
		return typ.elem, nil, "", true
	case *Signature:
		if !buildcfg.Experiment.RangeFunc && allowVersion != nil && !allowVersion(go1_23) {
			return bad("requires go1.23 or later")
		}
		// check iterator arity
		switch {
		case typ.Params().Len() != 1:
			return bad("func must be func(yield func(...) bool): wrong argument count")
		case typ.Results().Len() != 0:
			return bad("func must be func(yield func(...) bool): unexpected results")
		}
		assert(typ.Recv() == nil)
		// check iterator argument type
		cb, _ := coreType(typ.Params().At(0).Type()).(*Signature)
		switch {
		case cb == nil:
			return bad("func must be func(yield func(...) bool): argument is not func")
		case cb.Params().Len() > 2:
			return bad("func must be func(yield func(...) bool): yield func has too many parameters")
		case cb.Results().Len() != 1 || !isBoolean(cb.Results().At(0).Type()):
			return bad("func must be func(yield func(...) bool): yield func does not return bool")
		}
		assert(cb.Recv() == nil)
		// determine key and value types, if any
		if cb.Params().Len() >= 1 {
			key = cb.Params().At(0).Type()
		}
		if cb.Params().Len() >= 2 {
			val = cb.Params().At(1).Type()
		}
		return key, val, "", true
	}
	return
}
```