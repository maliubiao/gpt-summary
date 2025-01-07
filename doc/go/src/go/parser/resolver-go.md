Response:
Let's break down the thought process for analyzing the Go resolver code.

1. **Identify the Core Purpose:** The very first comment `// resolveFile walks the given file to resolve identifiers within the file scope, updating ast.Ident.Obj fields with declaration information.` immediately tells us the central goal: **identifier resolution**. This is the foundation for understanding everything else.

2. **High-Level Workflow (resolveFile function):**  Read the `resolveFile` function carefully. It initializes a `resolver` struct, iterates through declarations in the file, and uses `ast.Walk` with the `resolver` to traverse the AST. The crucial part is the loop at the end dealing with `r.unresolved`. This suggests a two-pass approach: first, try to resolve locally; second, resolve remaining unresolved identifiers within the file's package scope.

3. **The `resolver` struct:** Examine the fields of the `resolver` struct. This gives insights into the data structures needed for resolution:
    * `handle`: For position information.
    * `declErr`:  Error reporting.
    * `pkgScope`, `topScope`:  Management of identifier scopes. The hierarchy (`topScope` might be the `pkgScope` or a nested scope) is important.
    * `unresolved`:  A temporary holding place for identifiers that couldn't be resolved immediately.
    * `depth`:  Keeps track of scope nesting (for debugging/panic).
    * `labelScope`, `targetStack`: Separate management for labels and `goto`/`break`/`continue`.

4. **Key Methods and Their Roles:** Go through the methods of the `resolver` struct:
    * `openScope`, `closeScope`:  Manage the creation and destruction of identifier scopes.
    * `openLabelScope`, `closeLabelScope`:  Similar for label scopes, and importantly, the resolution of labels happens in `closeLabelScope`.
    * `declare`:  Registers a declared identifier in the current scope. Note the checks for redeclaration.
    * `shortVarDecl`:  Handles the specifics of short variable declarations (`:=`).
    * `resolve`: The heart of the resolution process. It searches up the scope chain. The `collectUnresolved` flag is a key detail.
    * `walkExprs`, `walkLHS`, `walkStmts`: Helper methods to traverse different parts of the AST.
    * `Visit`: The core of the `ast.Visitor` interface. Analyze the `switch` statement to see how different AST nodes are handled. This is where the real logic of scope entry/exit and declaration/resolution happens for various language constructs.
    * `walkFuncType`, `resolveList`, `declareList`, `walkRecv`, `walkFieldList`, `walkTParams`, `walkBody`:  Specialized traversal functions for different parts of declarations and function bodies.

5. **Identify Key Go Features Supported:** Based on the `Visit` method's `switch` statement and the logic within the methods, map the code to Go language features:
    * Variable declarations (explicit and short).
    * Constants.
    * Types (including struct and interface).
    * Functions (including receivers and type parameters).
    * Control flow statements (if, switch, for, range, labeled statements, break/continue/goto).
    * Composite literals.

6. **Code Examples and Reasoning:**  For significant features, create concise Go code examples demonstrating the resolver's actions. Think about:
    * **Scoping:**  Variables declared inside blocks.
    * **Redeclaration:** How the resolver detects errors.
    * **Unresolved identifiers:**  How identifiers are resolved later.
    * **Labels:** How `goto`, `break`, and `continue` work.
    * **Short variable declarations:** The rules about new variables.

7. **Error-Prone Areas:**  Consider common mistakes developers make related to identifier resolution:
    * **Shadowing:** Declaring a variable with the same name in an inner scope.
    * **Undeclared variables:** Using a variable before it's declared.
    * **Redeclaration in the same scope:** Trying to declare the same variable twice (except for the specific rule in short variable declarations).
    * **Incorrect label usage:**  `goto`ing to a non-existent label or outside its scope.

8. **Command-Line Arguments:** Carefully read the code for any interaction with command-line arguments. In this case, there's **no direct handling of command-line arguments**. The resolver operates on an already parsed AST. This is an important distinction.

9. **Refine and Organize:** Structure the answer logically. Start with the overall function, then delve into details, providing code examples and explanations. Use clear headings and bullet points.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is this the entire resolver?"  No, it's a *part* of the resolver, specifically focused on name resolution within a single file. The broader Go compiler has other stages.
* **Realization:** The `unresolved` list and the final loop in `resolveFile` are crucial for understanding how cross-declaration resolution within a file works.
* **Focus on `Visit`:**  The `Visit` method is the workhorse. Spending time understanding how each `case` works is key.
* **Example selection:** Choose examples that clearly illustrate the concepts being explained. Keep them simple and focused.
* **Error analysis:** Think from the perspective of a developer making mistakes. What are the common pitfalls related to variable scope and declaration?

By following this systematic approach, combining code reading with knowledge of Go's semantics, and focusing on the purpose and mechanisms of the code, you can effectively analyze and explain the functionality of a complex piece of code like the Go resolver.
这段代码是 Go 语言编译器中 **`go/parser` 包** 的一部分，主要负责 **解析 Go 源代码并进行标识符解析（Identifier Resolution）**。更具体地说，它实现了将源代码中的标识符（例如变量名、函数名、类型名等）与其声明关联起来的过程。

以下是它的主要功能：

1. **标识符查找和绑定 (Identifier Lookup and Binding):**
   - 遍历抽象语法树 (AST)，查找每个标识符。
   - 在不同的作用域 (Scope) 中查找与标识符名称匹配的声明。
   - 如果找到匹配的声明，则将 `ast.Ident` 节点的 `Obj` 字段设置为指向该声明的 `ast.Object`。这表示标识符已被成功解析。

2. **作用域管理 (Scope Management):**
   - 代码维护了词法作用域的概念，使用 `ast.Scope` 结构来表示不同的作用域，例如包级别、函数级别、代码块级别等。
   - `openScope` 和 `closeScope` 方法用于创建和销毁新的作用域，当进入一个新的代码块（例如函数体、if 语句块）时会打开一个新的作用域，退出时关闭。
   - `pkgScope` 存储了包级别的声明。
   - `topScope` 指向当前正在处理的最内层作用域。

3. **未解析标识符管理 (Unresolved Identifier Management):**
   - 如果在当前作用域链中找不到标识符的声明，则会将其添加到 `unresolved` 列表中。
   - 在处理完整个文件后，代码会尝试在包级别作用域中解析这些未解析的标识符。这允许在同一个包的不同文件中引用声明。

4. **标签解析 (Label Resolution):**
   - 对于 `goto`、`break` 和 `continue` 语句中使用的标签，代码会维护一个单独的标签作用域 (`labelScope`) 和一个目标栈 (`targetStack`)。
   - `openLabelScope` 和 `closeLabelScope` 用于管理标签作用域。
   - 当遇到 `goto`、`break` 或 `continue` 语句时，如果指定了标签，则会将该标签添加到 `targetStack` 中。
   - 在关闭标签作用域时，代码会尝试解析这些标签，即查找与标签名称匹配的 `ast.LabeledStmt`。

5. **声明处理 (Declaration Handling):**
   - `declare` 方法用于将声明的标识符添加到当前作用域中。
   - 它会创建 `ast.Object` 实例来表示声明的对象，并将其与 `ast.Ident` 关联起来。
   - 代码会检查同一作用域内的重复声明，并通过 `declErr` 函数报告错误。

6. **短变量声明处理 (Short Variable Declaration Handling):**
   - `shortVarDecl` 方法专门处理短变量声明 (`:=`)。
   - 它遵循 Go 语言的规则，允许在同一代码块中重新声明变量，前提是至少有一个新变量被声明。

7. **错误报告 (Error Reporting):**
   - `declErr` 是一个函数类型的字段，用于报告声明错误，例如重复声明或未定义的标签。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言编译器前端中 **名称解析 (Name Resolution) 或标识符解析 (Identifier Resolution)** 功能的核心实现。  名称解析是编译过程中的一个关键步骤，它将源代码中用人类可读的名称表示的实体（变量、函数、类型等）与其在编译器内部的表示联系起来。

**Go 代码示例：**

假设我们有以下 Go 代码：

```go
package main

import "fmt"

var globalVar int = 10

func main() {
	localVar := 5
	sum := globalVar + localVar
	fmt.Println(sum)
}
```

**假设的输入 (当 `resolveFile` 处理 `main.go` 文件时):**

- `file`:  代表上述代码的 `ast.File` 结构，其中 `ast.Ident` 节点的 `Obj` 字段初始为 `nil`。
- `handle`:  表示 `main.go` 文件的 `token.File`。
- `declErr`:  一个用于报告错误的函数，例如 `func(pos token.Pos, msg string) { fmt.Printf("Error at %s: %s\n", handle.Position(pos), msg) }`。

**代码推理与输出：**

1. **包级别作用域：** 首先会创建一个包级别作用域 `pkgScope`。
2. **全局变量声明：** 处理 `var globalVar int = 10` 时，`declare` 方法会将 `globalVar` 添加到 `pkgScope` 中，并创建一个 `ast.Object` 与其关联。
3. **`main` 函数声明：**  处理 `func main()` 时，`declare` 方法会将 `main` 添加到 `pkgScope` 中。
4. **函数体作用域：** 进入 `main` 函数体时，会打开一个新的作用域。
5. **局部变量声明：** 处理 `localVar := 5` 时，`shortVarDecl` 方法会将 `localVar` 添加到当前函数体作用域中。
6. **标识符解析：**
   - 处理 `globalVar` 时，`resolve` 方法会在当前函数体作用域中查找，找不到，然后会在其父作用域（包级别作用域）中找到 `globalVar` 的声明，并将 `globalVar` 对应的 `ast.Ident` 的 `Obj` 字段设置为指向该声明的 `ast.Object`。
   - 处理 `localVar` 时，`resolve` 方法会在当前函数体作用域中找到 `localVar` 的声明。
   - 处理 `fmt.Println` 时，`resolve` 方法会找到 `fmt` 包的导入，并最终找到 `Println` 函数的声明（这可能涉及跨文件或预定义的符号）。
7. **未解析标识符：**  如果在任何作用域中都找不到标识符的声明，则会被添加到 `unresolved` 列表中。在本例中，假设 `fmt` 包的解析是在其他阶段完成的，那么在 `resolveFile` 的末尾，`unresolved` 列表可能为空，或者只包含在当前文件中未找到声明的标识符（如果存在）。
8. **输出 (取决于 `declErr` 的实现):** 如果代码中存在重复声明或其他声明错误，`declErr` 函数会被调用以报告错误。对于上述代码，如果没有错误，则不会有输出。

**命令行参数的具体处理：**

这段代码本身 **不直接处理命令行参数**。 它是 `go/parser` 包内部的一个组成部分，负责解析已经读取到的源代码。  命令行参数的处理通常发生在 `go` 工具链的其他部分，例如 `go build` 命令会解析命令行参数以确定要编译的文件、构建目标等，然后将要解析的源代码传递给 `go/parser` 包。

**使用者易犯错的点：**

这段代码是 Go 语言编译器内部的实现细节，普通 Go 语言开发者不会直接使用它。然而，理解其背后的原理可以帮助开发者避免一些常见的与作用域相关的错误：

1. **变量遮蔽 (Variable Shadowing):** 在内层作用域中声明与外层作用域中同名的变量，导致外层变量被“遮蔽”。

   ```go
   package main

   import "fmt"

   var x int = 10

   func main() {
       x := 5 // 内部的 x 遮蔽了全局的 x
       fmt.Println(x) // 输出 5
   }
   ```

   这段代码不会报错，但是可能会导致意外的行为，因为在 `main` 函数内部访问 `x` 时，访问的是局部变量 `x`，而不是全局变量 `x`。

2. **在作用域外使用变量：** 尝试访问在当前作用域不可见的变量。

   ```go
   package main

   import "fmt"

   func main() {
       if true {
           y := 20
       }
       fmt.Println(y) // 错误：y 未定义
   }
   ```

   这段代码会导致编译错误，因为变量 `y` 只在 `if` 语句块内部定义，在外部不可见。

3. **短变量声明的误用：**  不理解短变量声明的规则，导致意外的行为或错误。

   ```go
   package main

   import "fmt"

   var z int

   func main() {
       z := 30 // 重新声明了全局变量 z，但只在 main 函数作用域内有效
       fmt.Println(z)
   }
   ```

   这段代码会编译通过，但在 `main` 函数内部修改的是局部变量 `z`，不会影响全局变量 `z` 的值。如果在其他函数中访问全局变量 `z`，其值仍然是初始值（如果没有显式初始化，则为零值）。

了解 `resolver.go` 的工作原理有助于理解 Go 语言的作用域规则和名称解析机制，从而编写更健壮和易于理解的代码。

Prompt: 
```
这是路径为go/src/go/parser/resolver.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package parser

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
)

const debugResolve = false

// resolveFile walks the given file to resolve identifiers within the file
// scope, updating ast.Ident.Obj fields with declaration information.
//
// If declErr is non-nil, it is used to report declaration errors during
// resolution. tok is used to format position in error messages.
func resolveFile(file *ast.File, handle *token.File, declErr func(token.Pos, string)) {
	pkgScope := ast.NewScope(nil)
	r := &resolver{
		handle:   handle,
		declErr:  declErr,
		topScope: pkgScope,
		pkgScope: pkgScope,
		depth:    1,
	}

	for _, decl := range file.Decls {
		ast.Walk(r, decl)
	}

	r.closeScope()
	assert(r.topScope == nil, "unbalanced scopes")
	assert(r.labelScope == nil, "unbalanced label scopes")

	// resolve global identifiers within the same file
	i := 0
	for _, ident := range r.unresolved {
		// i <= index for current ident
		assert(ident.Obj == unresolved, "object already resolved")
		ident.Obj = r.pkgScope.Lookup(ident.Name) // also removes unresolved sentinel
		if ident.Obj == nil {
			r.unresolved[i] = ident
			i++
		} else if debugResolve {
			pos := ident.Obj.Decl.(interface{ Pos() token.Pos }).Pos()
			r.trace("resolved %s@%v to package object %v", ident.Name, ident.Pos(), pos)
		}
	}
	file.Scope = r.pkgScope
	file.Unresolved = r.unresolved[0:i]
}

const maxScopeDepth int = 1e3

type resolver struct {
	handle  *token.File
	declErr func(token.Pos, string)

	// Ordinary identifier scopes
	pkgScope   *ast.Scope   // pkgScope.Outer == nil
	topScope   *ast.Scope   // top-most scope; may be pkgScope
	unresolved []*ast.Ident // unresolved identifiers
	depth      int          // scope depth

	// Label scopes
	// (maintained by open/close LabelScope)
	labelScope  *ast.Scope     // label scope for current function
	targetStack [][]*ast.Ident // stack of unresolved labels
}

func (r *resolver) trace(format string, args ...any) {
	fmt.Println(strings.Repeat(". ", r.depth) + r.sprintf(format, args...))
}

func (r *resolver) sprintf(format string, args ...any) string {
	for i, arg := range args {
		switch arg := arg.(type) {
		case token.Pos:
			args[i] = r.handle.Position(arg)
		}
	}
	return fmt.Sprintf(format, args...)
}

func (r *resolver) openScope(pos token.Pos) {
	r.depth++
	if r.depth > maxScopeDepth {
		panic(bailout{pos: pos, msg: "exceeded max scope depth during object resolution"})
	}
	if debugResolve {
		r.trace("opening scope @%v", pos)
	}
	r.topScope = ast.NewScope(r.topScope)
}

func (r *resolver) closeScope() {
	r.depth--
	if debugResolve {
		r.trace("closing scope")
	}
	r.topScope = r.topScope.Outer
}

func (r *resolver) openLabelScope() {
	r.labelScope = ast.NewScope(r.labelScope)
	r.targetStack = append(r.targetStack, nil)
}

func (r *resolver) closeLabelScope() {
	// resolve labels
	n := len(r.targetStack) - 1
	scope := r.labelScope
	for _, ident := range r.targetStack[n] {
		ident.Obj = scope.Lookup(ident.Name)
		if ident.Obj == nil && r.declErr != nil {
			r.declErr(ident.Pos(), fmt.Sprintf("label %s undefined", ident.Name))
		}
	}
	// pop label scope
	r.targetStack = r.targetStack[0:n]
	r.labelScope = r.labelScope.Outer
}

func (r *resolver) declare(decl, data any, scope *ast.Scope, kind ast.ObjKind, idents ...*ast.Ident) {
	for _, ident := range idents {
		if ident.Obj != nil {
			panic(fmt.Sprintf("%v: identifier %s already declared or resolved", ident.Pos(), ident.Name))
		}
		obj := ast.NewObj(kind, ident.Name)
		// remember the corresponding declaration for redeclaration
		// errors and global variable resolution/typechecking phase
		obj.Decl = decl
		obj.Data = data
		// Identifiers (for receiver type parameters) are written to the scope, but
		// never set as the resolved object. See go.dev/issue/50956.
		if _, ok := decl.(*ast.Ident); !ok {
			ident.Obj = obj
		}
		if ident.Name != "_" {
			if debugResolve {
				r.trace("declaring %s@%v", ident.Name, ident.Pos())
			}
			if alt := scope.Insert(obj); alt != nil && r.declErr != nil {
				prevDecl := ""
				if pos := alt.Pos(); pos.IsValid() {
					prevDecl = r.sprintf("\n\tprevious declaration at %v", pos)
				}
				r.declErr(ident.Pos(), fmt.Sprintf("%s redeclared in this block%s", ident.Name, prevDecl))
			}
		}
	}
}

func (r *resolver) shortVarDecl(decl *ast.AssignStmt) {
	// Go spec: A short variable declaration may redeclare variables
	// provided they were originally declared in the same block with
	// the same type, and at least one of the non-blank variables is new.
	n := 0 // number of new variables
	for _, x := range decl.Lhs {
		if ident, isIdent := x.(*ast.Ident); isIdent {
			assert(ident.Obj == nil, "identifier already declared or resolved")
			obj := ast.NewObj(ast.Var, ident.Name)
			// remember corresponding assignment for other tools
			obj.Decl = decl
			ident.Obj = obj
			if ident.Name != "_" {
				if debugResolve {
					r.trace("declaring %s@%v", ident.Name, ident.Pos())
				}
				if alt := r.topScope.Insert(obj); alt != nil {
					ident.Obj = alt // redeclaration
				} else {
					n++ // new declaration
				}
			}
		}
	}
	if n == 0 && r.declErr != nil {
		r.declErr(decl.Lhs[0].Pos(), "no new variables on left side of :=")
	}
}

// The unresolved object is a sentinel to mark identifiers that have been added
// to the list of unresolved identifiers. The sentinel is only used for verifying
// internal consistency.
var unresolved = new(ast.Object)

// If x is an identifier, resolve attempts to resolve x by looking up
// the object it denotes. If no object is found and collectUnresolved is
// set, x is marked as unresolved and collected in the list of unresolved
// identifiers.
func (r *resolver) resolve(ident *ast.Ident, collectUnresolved bool) {
	if ident.Obj != nil {
		panic(r.sprintf("%v: identifier %s already declared or resolved", ident.Pos(), ident.Name))
	}
	// '_' should never refer to existing declarations, because it has special
	// handling in the spec.
	if ident.Name == "_" {
		return
	}
	for s := r.topScope; s != nil; s = s.Outer {
		if obj := s.Lookup(ident.Name); obj != nil {
			if debugResolve {
				r.trace("resolved %v:%s to %v", ident.Pos(), ident.Name, obj)
			}
			assert(obj.Name != "", "obj with no name")
			// Identifiers (for receiver type parameters) are written to the scope,
			// but never set as the resolved object. See go.dev/issue/50956.
			if _, ok := obj.Decl.(*ast.Ident); !ok {
				ident.Obj = obj
			}
			return
		}
	}
	// all local scopes are known, so any unresolved identifier
	// must be found either in the file scope, package scope
	// (perhaps in another file), or universe scope --- collect
	// them so that they can be resolved later
	if collectUnresolved {
		ident.Obj = unresolved
		r.unresolved = append(r.unresolved, ident)
	}
}

func (r *resolver) walkExprs(list []ast.Expr) {
	for _, node := range list {
		ast.Walk(r, node)
	}
}

func (r *resolver) walkLHS(list []ast.Expr) {
	for _, expr := range list {
		expr := ast.Unparen(expr)
		if _, ok := expr.(*ast.Ident); !ok && expr != nil {
			ast.Walk(r, expr)
		}
	}
}

func (r *resolver) walkStmts(list []ast.Stmt) {
	for _, stmt := range list {
		ast.Walk(r, stmt)
	}
}

func (r *resolver) Visit(node ast.Node) ast.Visitor {
	if debugResolve && node != nil {
		r.trace("node %T@%v", node, node.Pos())
	}

	switch n := node.(type) {

	// Expressions.
	case *ast.Ident:
		r.resolve(n, true)

	case *ast.FuncLit:
		r.openScope(n.Pos())
		defer r.closeScope()
		r.walkFuncType(n.Type)
		r.walkBody(n.Body)

	case *ast.SelectorExpr:
		ast.Walk(r, n.X)
		// Note: don't try to resolve n.Sel, as we don't support qualified
		// resolution.

	case *ast.StructType:
		r.openScope(n.Pos())
		defer r.closeScope()
		r.walkFieldList(n.Fields, ast.Var)

	case *ast.FuncType:
		r.openScope(n.Pos())
		defer r.closeScope()
		r.walkFuncType(n)

	case *ast.CompositeLit:
		if n.Type != nil {
			ast.Walk(r, n.Type)
		}
		for _, e := range n.Elts {
			if kv, _ := e.(*ast.KeyValueExpr); kv != nil {
				// See go.dev/issue/45160: try to resolve composite lit keys, but don't
				// collect them as unresolved if resolution failed. This replicates
				// existing behavior when resolving during parsing.
				if ident, _ := kv.Key.(*ast.Ident); ident != nil {
					r.resolve(ident, false)
				} else {
					ast.Walk(r, kv.Key)
				}
				ast.Walk(r, kv.Value)
			} else {
				ast.Walk(r, e)
			}
		}

	case *ast.InterfaceType:
		r.openScope(n.Pos())
		defer r.closeScope()
		r.walkFieldList(n.Methods, ast.Fun)

	// Statements
	case *ast.LabeledStmt:
		r.declare(n, nil, r.labelScope, ast.Lbl, n.Label)
		ast.Walk(r, n.Stmt)

	case *ast.AssignStmt:
		r.walkExprs(n.Rhs)
		if n.Tok == token.DEFINE {
			r.shortVarDecl(n)
		} else {
			r.walkExprs(n.Lhs)
		}

	case *ast.BranchStmt:
		// add to list of unresolved targets
		if n.Tok != token.FALLTHROUGH && n.Label != nil {
			depth := len(r.targetStack) - 1
			r.targetStack[depth] = append(r.targetStack[depth], n.Label)
		}

	case *ast.BlockStmt:
		r.openScope(n.Pos())
		defer r.closeScope()
		r.walkStmts(n.List)

	case *ast.IfStmt:
		r.openScope(n.Pos())
		defer r.closeScope()
		if n.Init != nil {
			ast.Walk(r, n.Init)
		}
		ast.Walk(r, n.Cond)
		ast.Walk(r, n.Body)
		if n.Else != nil {
			ast.Walk(r, n.Else)
		}

	case *ast.CaseClause:
		r.walkExprs(n.List)
		r.openScope(n.Pos())
		defer r.closeScope()
		r.walkStmts(n.Body)

	case *ast.SwitchStmt:
		r.openScope(n.Pos())
		defer r.closeScope()
		if n.Init != nil {
			ast.Walk(r, n.Init)
		}
		if n.Tag != nil {
			// The scope below reproduces some unnecessary behavior of the parser,
			// opening an extra scope in case this is a type switch. It's not needed
			// for expression switches.
			// TODO: remove this once we've matched the parser resolution exactly.
			if n.Init != nil {
				r.openScope(n.Tag.Pos())
				defer r.closeScope()
			}
			ast.Walk(r, n.Tag)
		}
		if n.Body != nil {
			r.walkStmts(n.Body.List)
		}

	case *ast.TypeSwitchStmt:
		if n.Init != nil {
			r.openScope(n.Pos())
			defer r.closeScope()
			ast.Walk(r, n.Init)
		}
		r.openScope(n.Assign.Pos())
		defer r.closeScope()
		ast.Walk(r, n.Assign)
		// s.Body consists only of case clauses, so does not get its own
		// scope.
		if n.Body != nil {
			r.walkStmts(n.Body.List)
		}

	case *ast.CommClause:
		r.openScope(n.Pos())
		defer r.closeScope()
		if n.Comm != nil {
			ast.Walk(r, n.Comm)
		}
		r.walkStmts(n.Body)

	case *ast.SelectStmt:
		// as for switch statements, select statement bodies don't get their own
		// scope.
		if n.Body != nil {
			r.walkStmts(n.Body.List)
		}

	case *ast.ForStmt:
		r.openScope(n.Pos())
		defer r.closeScope()
		if n.Init != nil {
			ast.Walk(r, n.Init)
		}
		if n.Cond != nil {
			ast.Walk(r, n.Cond)
		}
		if n.Post != nil {
			ast.Walk(r, n.Post)
		}
		ast.Walk(r, n.Body)

	case *ast.RangeStmt:
		r.openScope(n.Pos())
		defer r.closeScope()
		ast.Walk(r, n.X)
		var lhs []ast.Expr
		if n.Key != nil {
			lhs = append(lhs, n.Key)
		}
		if n.Value != nil {
			lhs = append(lhs, n.Value)
		}
		if len(lhs) > 0 {
			if n.Tok == token.DEFINE {
				// Note: we can't exactly match the behavior of object resolution
				// during the parsing pass here, as it uses the position of the RANGE
				// token for the RHS OpPos. That information is not contained within
				// the AST.
				as := &ast.AssignStmt{
					Lhs:    lhs,
					Tok:    token.DEFINE,
					TokPos: n.TokPos,
					Rhs:    []ast.Expr{&ast.UnaryExpr{Op: token.RANGE, X: n.X}},
				}
				// TODO(rFindley): this walkLHS reproduced the parser resolution, but
				// is it necessary? By comparison, for a normal AssignStmt we don't
				// walk the LHS in case there is an invalid identifier list.
				r.walkLHS(lhs)
				r.shortVarDecl(as)
			} else {
				r.walkExprs(lhs)
			}
		}
		ast.Walk(r, n.Body)

	// Declarations
	case *ast.GenDecl:
		switch n.Tok {
		case token.CONST, token.VAR:
			for i, spec := range n.Specs {
				spec := spec.(*ast.ValueSpec)
				kind := ast.Con
				if n.Tok == token.VAR {
					kind = ast.Var
				}
				r.walkExprs(spec.Values)
				if spec.Type != nil {
					ast.Walk(r, spec.Type)
				}
				r.declare(spec, i, r.topScope, kind, spec.Names...)
			}
		case token.TYPE:
			for _, spec := range n.Specs {
				spec := spec.(*ast.TypeSpec)
				// Go spec: The scope of a type identifier declared inside a function begins
				// at the identifier in the TypeSpec and ends at the end of the innermost
				// containing block.
				r.declare(spec, nil, r.topScope, ast.Typ, spec.Name)
				if spec.TypeParams != nil {
					r.openScope(spec.Pos())
					defer r.closeScope()
					r.walkTParams(spec.TypeParams)
				}
				ast.Walk(r, spec.Type)
			}
		}

	case *ast.FuncDecl:
		// Open the function scope.
		r.openScope(n.Pos())
		defer r.closeScope()

		r.walkRecv(n.Recv)

		// Type parameters are walked normally: they can reference each other, and
		// can be referenced by normal parameters.
		if n.Type.TypeParams != nil {
			r.walkTParams(n.Type.TypeParams)
			// TODO(rFindley): need to address receiver type parameters.
		}

		// Resolve and declare parameters in a specific order to get duplicate
		// declaration errors in the correct location.
		r.resolveList(n.Type.Params)
		r.resolveList(n.Type.Results)
		r.declareList(n.Recv, ast.Var)
		r.declareList(n.Type.Params, ast.Var)
		r.declareList(n.Type.Results, ast.Var)

		r.walkBody(n.Body)
		if n.Recv == nil && n.Name.Name != "init" {
			r.declare(n, nil, r.pkgScope, ast.Fun, n.Name)
		}

	default:
		return r
	}

	return nil
}

func (r *resolver) walkFuncType(typ *ast.FuncType) {
	// typ.TypeParams must be walked separately for FuncDecls.
	r.resolveList(typ.Params)
	r.resolveList(typ.Results)
	r.declareList(typ.Params, ast.Var)
	r.declareList(typ.Results, ast.Var)
}

func (r *resolver) resolveList(list *ast.FieldList) {
	if list == nil {
		return
	}
	for _, f := range list.List {
		if f.Type != nil {
			ast.Walk(r, f.Type)
		}
	}
}

func (r *resolver) declareList(list *ast.FieldList, kind ast.ObjKind) {
	if list == nil {
		return
	}
	for _, f := range list.List {
		r.declare(f, nil, r.topScope, kind, f.Names...)
	}
}

func (r *resolver) walkRecv(recv *ast.FieldList) {
	// If our receiver has receiver type parameters, we must declare them before
	// trying to resolve the rest of the receiver, and avoid re-resolving the
	// type parameter identifiers.
	if recv == nil || len(recv.List) == 0 {
		return // nothing to do
	}
	typ := recv.List[0].Type
	if ptr, ok := typ.(*ast.StarExpr); ok {
		typ = ptr.X
	}

	var declareExprs []ast.Expr // exprs to declare
	var resolveExprs []ast.Expr // exprs to resolve
	switch typ := typ.(type) {
	case *ast.IndexExpr:
		declareExprs = []ast.Expr{typ.Index}
		resolveExprs = append(resolveExprs, typ.X)
	case *ast.IndexListExpr:
		declareExprs = typ.Indices
		resolveExprs = append(resolveExprs, typ.X)
	default:
		resolveExprs = append(resolveExprs, typ)
	}
	for _, expr := range declareExprs {
		if id, _ := expr.(*ast.Ident); id != nil {
			r.declare(expr, nil, r.topScope, ast.Typ, id)
		} else {
			// The receiver type parameter expression is invalid, but try to resolve
			// it anyway for consistency.
			resolveExprs = append(resolveExprs, expr)
		}
	}
	for _, expr := range resolveExprs {
		if expr != nil {
			ast.Walk(r, expr)
		}
	}
	// The receiver is invalid, but try to resolve it anyway for consistency.
	for _, f := range recv.List[1:] {
		if f.Type != nil {
			ast.Walk(r, f.Type)
		}
	}
}

func (r *resolver) walkFieldList(list *ast.FieldList, kind ast.ObjKind) {
	if list == nil {
		return
	}
	r.resolveList(list)
	r.declareList(list, kind)
}

// walkTParams is like walkFieldList, but declares type parameters eagerly so
// that they may be resolved in the constraint expressions held in the field
// Type.
func (r *resolver) walkTParams(list *ast.FieldList) {
	r.declareList(list, ast.Typ)
	r.resolveList(list)
}

func (r *resolver) walkBody(body *ast.BlockStmt) {
	if body == nil {
		return
	}
	r.openLabelScope()
	defer r.closeLabelScope()
	r.walkStmts(body.List)
}

"""



```