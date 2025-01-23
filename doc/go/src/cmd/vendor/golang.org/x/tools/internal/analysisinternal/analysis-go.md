Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for an explanation of the Go code in `analysis.go`. Specifically, it wants to know the functions' purposes, examples of their usage (ideally with input/output), details about command-line arguments (if any), and common pitfalls.

2. **Initial Code Scan (High-Level):** I'll first read through the code to get a general understanding of what it does. I see import statements related to `go/ast`, `go/token`, `go/types`, `go/scanner`, and `golang.org/x/tools/go/analysis`. This immediately tells me the code is working with Go source code, abstract syntax trees, type information, and likely part of a static analysis tool. The package name `analysisinternal` suggests these are helper functions for internal use within a larger analysis framework.

3. **Analyze Individual Functions:**  I'll go through each function one by one, focusing on its purpose and how it manipulates the input data.

    * **`TypeErrorEndPos`:**  The comments and code indicate this function tries to determine the end position of a type error in the source code. It seems to have some heuristics based on scanning tokens and looking for delimiters. The comment mentioning `golang/go#69505` is a good hint to research if I need deeper understanding, although the comment within the code is already quite informative about its limitations.

    * **`StmtToInsertVarBefore`:** This function aims to find the correct location to insert a variable declaration before a given statement. The examples in the comments are very helpful in understanding its behavior with `if` and `switch` statements. The logic involves walking up the AST path.

    * **`baseIfStmt`:** This is a helper function for `StmtToInsertVarBefore`, clearly designed to traverse `if`/`else if` chains to find the root `if` statement.

    * **`WalkASTWithParent`:** The name and the usage of `ast.Inspect` immediately suggest this function traverses the AST, providing both the current node and its parent to the provided function.

    * **`MatchingIdents`:** This function looks for identifiers within an AST node that match specific types and are in scope at a given position. The comments about preventing circular definitions and checking scope are important.

    * **`equivalentTypes`:** A helper function to determine if two types are equivalent, handling untyped constants.

    * **`MakeReadFile`:** This function creates a `ReadFile` function that respects the `analysis.Pass`'s file access policy.

    * **`CheckReadable`:** This function enforces the file access policy.

    * **`slicesContains`:** A utility function to check if a slice contains a specific element. The comment notes it's for older Go versions.

    * **`AddImport`:** This function handles adding import statements to a Go file, ensuring the imported package is in scope and avoiding naming conflicts.

    * **`importedPkgName`:** Another helper function to get the `PkgName` object from an `ImportSpec`.

4. **Synthesize Functionality Summary:** After analyzing each function, I'll summarize the overall purpose of the `analysis.go` file. It provides helper functions for Go static analysis, particularly those dealing with type information, AST manipulation, and managing file access.

5. **Code Examples:** For the more complex functions like `TypeErrorEndPos`, `StmtToInsertVarBefore`, and `MatchingIdents`, I'll create illustrative Go code examples. These examples will have:
    * **Input:** A snippet of Go code, an AST node or path, or a position.
    * **Function Call:**  Calling the target function with the input.
    * **Output:** The expected result, explaining *why* that result is returned.

6. **Reasoning and Assumptions:** When providing examples, especially for `TypeErrorEndPos`, I'll clearly state any assumptions I'm making about the input (e.g., the content of the `src` byte slice). For `StmtToInsertVarBefore`, demonstrating different `if` and `switch` scenarios is important.

7. **Command-Line Arguments:**  I'll carefully examine the functions for any interaction with command-line arguments. In this case, these functions are primarily utility functions, and the command-line argument handling is likely done at a higher level in the `gopls` tool. Therefore, I'll state that these functions don't directly handle command-line arguments but are used within tools that do.

8. **Common Pitfalls:** I'll consider potential errors developers might make when using these functions. For example:
    * For `TypeErrorEndPos`, relying too heavily on its heuristic nature.
    * For `StmtToInsertVarBefore`, misunderstanding how it handles nested statements.
    * For `MatchingIdents`, not understanding the scope checks.
    * For `AddImport`, not considering the implications of adding imports on code formatting.

9. **Structure and Formatting:** I'll organize the information logically with clear headings and code formatting to make it easy to read and understand. I'll use code blocks for examples and clearly label inputs and outputs.

10. **Review and Refine:** Finally, I'll reread my answer to ensure accuracy, clarity, and completeness. I'll check if I've addressed all aspects of the original request. For example, double-checking if I've explained *why* a particular output is expected in the code examples.

By following these steps, I can break down the task into manageable parts and create a comprehensive and informative answer. The process involves understanding the code's purpose, providing concrete examples, and anticipating potential user errors.
这段代码是 Go 语言工具 `gopls` 的一部分，位于 `go/src/cmd/vendor/golang.org/x/tools/internal/analysisinternal/analysis.go`，它提供了一系列用于 Go 代码静态分析的辅助函数。这些函数主要操作类型化的语法树 (`go/ast` 和 `go/types` 包)。

以下是这些函数的功能以及可能的 Go 语言功能实现：

**1. `TypeErrorEndPos(fset *token.FileSet, src []byte, start token.Pos) token.Pos`**

* **功能:**  尝试确定类型错误在源代码中的结束位置。
* **推理:**  当 Go 编译器或静态分析工具遇到类型错误时，通常只提供错误的起始位置。此函数尝试通过扫描源代码，找到一个更合理的错误结束位置，以便在编辑器或其他工具中高亮显示错误范围。
* **代码示例:**

```go
package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"golang.org/x/tools/internal/analysisinternal"
)

func main() {
	src := []byte("package main\n\nfunc main() {\n\tx := 1 + \"hello\"\n}")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		// 假设我们从 error 中获取了起始位置
		var startPos token.Pos
		for _, e := range err.(scanner.ErrorList) {
			startPos = e.Pos
			break
		}

		endPos := analysisinternal.TypeErrorEndPos(fset, src, startPos)
		fmt.Printf("Error starts at: %s\n", fset.Position(startPos))
		fmt.Printf("Error potentially ends at: %s\n", fset.Position(endPos))
	}
}

// 假设输入源代码 "package main\n\nfunc main() {\n\tx := 1 + \"hello\"\n}"
// 假设解析错误报告的起始位置指向 "1"

// 输出可能类似于:
// Error starts at: test.go:4:6
// Error potentially ends at: test.go:4:15
```

* **易犯错的点:**  函数注释中也提到了，这个函数使用的启发式方法可能不精确，其目的是找到“主要操作数”的结尾，但实际实现可能存在偏差。不要过分依赖其返回的精确结束位置。

**2. `StmtToInsertVarBefore(path []ast.Node) ast.Stmt`**

* **功能:**  给定一个 AST 节点路径，找到可以安全插入新的变量声明的语句。
* **推理:**  这个函数用于在代码中插入新变量声明的场景，例如自动补全或快速修复。它需要找到一个合适的语句，使得新声明的变量在其后的代码中是可见的。
* **代码示例:**

```go
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"golang.org/x/tools/internal/analysisinternal"
)

func main() {
	src := []byte("package main\n\nfunc main() {\n\ty := z + x\n}")
	fset := token.NewFileSet()
	file, _ := parser.ParseFile(fset, "test.go", src, 0)

	// 假设我们找到了标识符 "x" 的 AST 节点，并构造了从根节点到它的路径
	var path []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == "x" {
			//  (通常需要更严谨的路径构建方式)
			//  这里简化模拟路径
			blockStmt := file.Decls[0].(*ast.FuncDecl).Body
			assignStmt := blockStmt.List[0].(*ast.AssignStmt)
			binaryExpr := assignStmt.Rhs.(*ast.BinaryExpr)
			path = []ast.Node{file, file.Decls[0], blockStmt, assignStmt, binaryExpr.Y}
			return false
		}
		return true
	})

	stmt := analysisinternal.StmtToInsertVarBefore(path)
	fmt.Printf("Insert variable declaration before: %#v\n", stmt)
}

// 假设输入源代码 "package main\n\nfunc main() {\n\ty := z + x\n}"
// 假设路径指向标识符 "x"

// 输出:
// Insert variable declaration before: &ast.AssignStmt{TokPos:41, Lhs:[]ast.Expr{...}, Tok:0xa, Rhs:(*ast.BinaryExpr)(0xc00008e180)}
```

* **If 语句示例:**

```go
// ... (前面导入部分省略)

func main() {
	src := []byte("package main\n\nfunc main() {\n\tif z == 1 {\n\t} else if z == y {}\n}")
	fset := token.NewFileSet()
	file, _ := parser.ParseFile(fset, "test.go", src, 0)

	// 假设路径指向 "y"
	var path []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == "y" {
			//  简化模拟路径
			blockStmt := file.Decls[0].(*ast.FuncDecl).Body
			ifStmt := blockStmt.List[0].(*ast.IfStmt)
			elseIfStmt := ifStmt.Else.(*ast.IfStmt)
			binaryExpr := elseIfStmt.Cond.(*ast.BinaryExpr)
			path = []ast.Node{file, file.Decls[0], blockStmt, ifStmt, elseIfStmt, binaryExpr.Y}
			return false
		}
		return true
	})

	stmt := analysisinternal.StmtToInsertVarBefore(path)
	fmt.Printf("Insert variable declaration before: %#v\n", stmt)
}

// 假设输入源代码 "package main\n\nfunc main() {\n\tif z == 1 {\n\t} else if z == y {}\n}"
// 假设路径指向标识符 "y"

// 输出:
// Insert variable declaration before: &ast.IfStmt{If:41, Cond:(*ast.BinaryExpr)(0xc0000b0000), Body:(*ast.BlockStmt)(0xc0000b00c0), Else:(*ast.IfStmt)(0xc0000b0180)}
```

**3. `baseIfStmt(path []ast.Node, index int) ast.Stmt`**

* **功能:**  给定一个 AST 节点路径和索引，如果该节点是 `if` 或 `else if` 语句的一部分，则向上遍历 `if`/`else if` 链，直到找到顶层的 `if` 语句。
* **推理:** 这是 `StmtToInsertVarBefore` 的辅助函数，用于处理 `if`/`else if` 结构。

**4. `WalkASTWithParent(n ast.Node, f func(n ast.Node, parent ast.Node) bool)`**

* **功能:**  遍历以 `n` 为根的 AST 树，并在每次访问节点时，将当前节点及其父节点传递给函数 `f`。
* **推理:**  类似于 `ast.Inspect`，但提供了父节点信息，这在某些分析场景中很有用。

**5. `MatchingIdents(typs []types.Type, node ast.Node, pos token.Pos, info *types.Info, pkg *types.Package) map[types.Type][]string`**

* **功能:**  在给定的 AST 节点 `node` 中，查找与 `typs` 中任何类型匹配的标识符。`pos` 表示标识符可能被插入的位置。
* **推理:**  用于代码补全或建议，例如，当需要一个特定类型的变量时，可以查找当前作用域中是否存在该类型的变量。
* **代码示例:**

```go
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"golang.org/x/tools/internal/analysisinternal"
)

func main() {
	src := []byte("package main\n\nfunc main() {\n\tintVal := 10\n\tstrVal := \"hello\"\n\t_ =  }\n")
	fset := token.NewFileSet()
	file, _ := parser.ParseFile(fset, "test.go", src, 0)

	info := &types.Info{
		Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object),
	}
	conf := types.Config{}
	pkg, _ := conf.Check("main", fset, []*ast.File{file}, info)

	// 假设光标位置在 " _ =  " 后面
	cursorPos := fset.PositionFor(file.Pos()+int(len(src)-2), false).Pos()

	intType := types.Typ[types.Int]
	stringType := types.Typ[types.String]

	matches := analysisinternal.MatchingIdents([]types.Type{intType, stringType}, file, cursorPos, info, pkg)
	fmt.Printf("Matching identifiers: %#v\n", matches)
}

// 假设输入源代码 "package main\n\nfunc main() {\n\tintVal := 10\n\tstrVal := \"hello\"\n\t_ =  }\n"
// 假设光标位置在 " _ =  " 之后

// 输出可能类似于:
// Matching identifiers: map[types.Type][]string{(*types.Basic)(0x1069580):[]string{"intVal"}, (*types.Basic)(0x1069700):[]string{"strVal"}}
```

* **易犯错的点:**  `pos` 参数非常重要，它必须在所选标识符的作用域内。否则，插入的变量可能无法被识别。函数还会检查避免在赋值语句中选择正在被赋值的变量，以防止循环定义。

**6. `equivalentTypes(want, got types.Type) bool`**

* **功能:**  检查两个 `types.Type` 是否等价。
* **推理:**  用于比较类型，考虑了 untyped 常量的情况。

**7. `MakeReadFile(pass *analysis.Pass) func(filename string) ([]byte, error)`**

* **功能:**  创建一个 `ReadFile` 函数，该函数使用 `analysis.Pass` 中定义的访问策略来读取文件。
* **推理:**  `analysis.Pass` 结构体包含了分析过程中的各种信息，包括允许访问的文件列表。这个函数确保分析器只读取允许的文件。

**8. `CheckReadable(pass *analysis.Pass, filename string) error`**

* **功能:**  检查给定的文件名是否在 `analysis.Pass` 允许读取的文件列表中。
* **推理:**  用于实施文件访问控制。

**9. `slicesContains[S ~[]E, E comparable](slice S, x E) bool`**

* **功能:**  检查切片 `slice` 是否包含元素 `x`。
* **推理:**  一个泛型的切片包含检查函数，在 Go 1.18 引入泛型之前可能需要这样的辅助函数。

**10. `AddImport(info *types.Info, file *ast.File, pos token.Pos, pkgpath, preferredName string) (name string, newImport []analysis.TextEdit)`**

* **功能:**  检查文件是否已经导入了 `pkgpath`，并且该导入在 `pos` 位置是可见的。如果不是，则添加一个新的导入声明。
* **推理:**  用于自动添加导入语句，例如在代码补全或快速修复中。
* **代码示例:**

```go
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/internal/analysisinternal"
)

func main() {
	src := []byte("package main\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}")
	fset := token.NewFileSet()
	file, _ := parser.ParseFile(fset, "test.go", src, 0)

	info := &types.Info{
		Scopes: make(map[ast.Node]*types.Scope),
		Defs:   make(map[*ast.Ident]types.Object),
		Uses:   make(map[*ast.Ident]types.Object),
	}
	conf := types.Config{}
	pkg, _ := conf.Check("main", fset, []*ast.File{file}, info)

	// 假设需要在 main 函数内部添加对 "strings" 包的引用
	mainFunc := file.Decls[0].(*ast.FuncDecl)
	pos := mainFunc.Body.Lbrace + 1 // 在函数体开始的大括号之后插入

	newName, edits := analysisinternal.AddImport(info, file, pos, "strings", "strings")
	fmt.Printf("New import name: %s\n", newName)
	fmt.Printf("Text edits: %#v\n", edits)
}

// 假设输入源代码 "package main\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}"
// 假设需要在 main 函数内部添加对 "strings" 包的引用

// 输出可能类似于:
// New import name: strings
// Text edits: []analysis.TextEdit{analysis.TextEdit{Pos:21, End:21, NewText:[]byte("import \"strings\"\n\n")}}
```

**11. `importedPkgName(info *types.Info, imp *ast.ImportSpec) (*types.PkgName, bool)`**

* **功能:**  从 `ast.ImportSpec` 中获取导入的包名对象。
* **推理:**  用于获取导入包的信息。

**总结:**

`analysis.go` 文件中的函数是为 `gopls` 这样的 Go 语言工具提供基础的静态分析能力。它们处理底层的 AST 和类型信息，使得上层的功能（如错误提示、代码补全、快速修复等）能够更容易地实现。这些函数本身不直接处理命令行参数，而是被更高级别的分析逻辑调用。

**使用者易犯错的点:**

* **`TypeErrorEndPos`:** 依赖其返回的精确结束位置，因为它使用的是启发式方法。
* **`StmtToInsertVarBefore`:** 可能难以理解在复杂控制流结构（如嵌套的 `if` 语句或 `switch` 语句）中，变量声明应该插入到哪个位置。
* **`MatchingIdents`:**  没有正确理解 `pos` 参数的作用域限制，导致插入的变量无法被识别。
* **`AddImport`:**  假设总是能使用 `preferredName` 作为导入别名，而忽略了可能存在的命名冲突。

总的来说，这个文件提供了一组强大的工具，用于理解和操作 Go 代码的结构和类型信息，是构建 Go 语言分析工具的重要组成部分。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/tools/internal/analysisinternal/analysis.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package analysisinternal provides gopls' internal analyses with a
// number of helper functions that operate on typed syntax trees.
package analysisinternal

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/scanner"
	"go/token"
	"go/types"
	"os"
	pathpkg "path"

	"golang.org/x/tools/go/analysis"
)

func TypeErrorEndPos(fset *token.FileSet, src []byte, start token.Pos) token.Pos {
	// Get the end position for the type error.
	file := fset.File(start)
	if file == nil {
		return start
	}
	if offset := file.PositionFor(start, false).Offset; offset > len(src) {
		return start
	} else {
		src = src[offset:]
	}

	// Attempt to find a reasonable end position for the type error.
	//
	// TODO(rfindley): the heuristic implemented here is unclear. It looks like
	// it seeks the end of the primary operand starting at start, but that is not
	// quite implemented (for example, given a func literal this heuristic will
	// return the range of the func keyword).
	//
	// We should formalize this heuristic, or deprecate it by finally proposing
	// to add end position to all type checker errors.
	//
	// Nevertheless, ensure that the end position at least spans the current
	// token at the cursor (this was golang/go#69505).
	end := start
	{
		var s scanner.Scanner
		fset := token.NewFileSet()
		f := fset.AddFile("", fset.Base(), len(src))
		s.Init(f, src, nil /* no error handler */, scanner.ScanComments)
		pos, tok, lit := s.Scan()
		if tok != token.SEMICOLON && token.Pos(f.Base()) <= pos && pos <= token.Pos(f.Base()+f.Size()) {
			off := file.Offset(pos) + len(lit)
			src = src[off:]
			end += token.Pos(off)
		}
	}

	// Look for bytes that might terminate the current operand. See note above:
	// this is imprecise.
	if width := bytes.IndexAny(src, " \n,():;[]+-*/"); width > 0 {
		end += token.Pos(width)
	}
	return end
}

// StmtToInsertVarBefore returns the ast.Stmt before which we can
// safely insert a new var declaration, or nil if the path denotes a
// node outside any statement.
//
// Basic Example:
//
//	z := 1
//	y := z + x
//
// If x is undeclared, then this function would return `y := z + x`, so that we
// can insert `x := ` on the line before `y := z + x`.
//
// If stmt example:
//
//	if z == 1 {
//	} else if z == y {}
//
// If y is undeclared, then this function would return `if z == 1 {`, because we cannot
// insert a statement between an if and an else if statement. As a result, we need to find
// the top of the if chain to insert `y := ` before.
func StmtToInsertVarBefore(path []ast.Node) ast.Stmt {
	enclosingIndex := -1
	for i, p := range path {
		if _, ok := p.(ast.Stmt); ok {
			enclosingIndex = i
			break
		}
	}
	if enclosingIndex == -1 {
		return nil // no enclosing statement: outside function
	}
	enclosingStmt := path[enclosingIndex]
	switch enclosingStmt.(type) {
	case *ast.IfStmt:
		// The enclosingStmt is inside of the if declaration,
		// We need to check if we are in an else-if stmt and
		// get the base if statement.
		// TODO(adonovan): for non-constants, it may be preferable
		// to add the decl as the Init field of the innermost
		// enclosing ast.IfStmt.
		return baseIfStmt(path, enclosingIndex)
	case *ast.CaseClause:
		// Get the enclosing switch stmt if the enclosingStmt is
		// inside of the case statement.
		for i := enclosingIndex + 1; i < len(path); i++ {
			if node, ok := path[i].(*ast.SwitchStmt); ok {
				return node
			} else if node, ok := path[i].(*ast.TypeSwitchStmt); ok {
				return node
			}
		}
	}
	if len(path) <= enclosingIndex+1 {
		return enclosingStmt.(ast.Stmt)
	}
	// Check if the enclosing statement is inside another node.
	switch expr := path[enclosingIndex+1].(type) {
	case *ast.IfStmt:
		// Get the base if statement.
		return baseIfStmt(path, enclosingIndex+1)
	case *ast.ForStmt:
		if expr.Init == enclosingStmt || expr.Post == enclosingStmt {
			return expr
		}
	case *ast.SwitchStmt, *ast.TypeSwitchStmt:
		return expr.(ast.Stmt)
	}
	return enclosingStmt.(ast.Stmt)
}

// baseIfStmt walks up the if/else-if chain until we get to
// the top of the current if chain.
func baseIfStmt(path []ast.Node, index int) ast.Stmt {
	stmt := path[index]
	for i := index + 1; i < len(path); i++ {
		if node, ok := path[i].(*ast.IfStmt); ok && node.Else == stmt {
			stmt = node
			continue
		}
		break
	}
	return stmt.(ast.Stmt)
}

// WalkASTWithParent walks the AST rooted at n. The semantics are
// similar to ast.Inspect except it does not call f(nil).
func WalkASTWithParent(n ast.Node, f func(n ast.Node, parent ast.Node) bool) {
	var ancestors []ast.Node
	ast.Inspect(n, func(n ast.Node) (recurse bool) {
		if n == nil {
			ancestors = ancestors[:len(ancestors)-1]
			return false
		}

		var parent ast.Node
		if len(ancestors) > 0 {
			parent = ancestors[len(ancestors)-1]
		}
		ancestors = append(ancestors, n)
		return f(n, parent)
	})
}

// MatchingIdents finds the names of all identifiers in 'node' that match any of the given types.
// 'pos' represents the position at which the identifiers may be inserted. 'pos' must be within
// the scope of each of identifier we select. Otherwise, we will insert a variable at 'pos' that
// is unrecognized.
func MatchingIdents(typs []types.Type, node ast.Node, pos token.Pos, info *types.Info, pkg *types.Package) map[types.Type][]string {

	// Initialize matches to contain the variable types we are searching for.
	matches := make(map[types.Type][]string)
	for _, typ := range typs {
		if typ == nil {
			continue // TODO(adonovan): is this reachable?
		}
		matches[typ] = nil // create entry
	}

	seen := map[types.Object]struct{}{}
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		// Prevent circular definitions. If 'pos' is within an assignment statement, do not
		// allow any identifiers in that assignment statement to be selected. Otherwise,
		// we could do the following, where 'x' satisfies the type of 'f0':
		//
		// x := fakeStruct{f0: x}
		//
		if assign, ok := n.(*ast.AssignStmt); ok && pos > assign.Pos() && pos <= assign.End() {
			return false
		}
		if n.End() > pos {
			return n.Pos() <= pos
		}
		ident, ok := n.(*ast.Ident)
		if !ok || ident.Name == "_" {
			return true
		}
		obj := info.Defs[ident]
		if obj == nil || obj.Type() == nil {
			return true
		}
		if _, ok := obj.(*types.TypeName); ok {
			return true
		}
		// Prevent duplicates in matches' values.
		if _, ok = seen[obj]; ok {
			return true
		}
		seen[obj] = struct{}{}
		// Find the scope for the given position. Then, check whether the object
		// exists within the scope.
		innerScope := pkg.Scope().Innermost(pos)
		if innerScope == nil {
			return true
		}
		_, foundObj := innerScope.LookupParent(ident.Name, pos)
		if foundObj != obj {
			return true
		}
		// The object must match one of the types that we are searching for.
		// TODO(adonovan): opt: use typeutil.Map?
		if names, ok := matches[obj.Type()]; ok {
			matches[obj.Type()] = append(names, ident.Name)
		} else {
			// If the object type does not exactly match
			// any of the target types, greedily find the first
			// target type that the object type can satisfy.
			for typ := range matches {
				if equivalentTypes(obj.Type(), typ) {
					matches[typ] = append(matches[typ], ident.Name)
				}
			}
		}
		return true
	})
	return matches
}

func equivalentTypes(want, got types.Type) bool {
	if types.Identical(want, got) {
		return true
	}
	// Code segment to help check for untyped equality from (golang/go#32146).
	if rhs, ok := want.(*types.Basic); ok && rhs.Info()&types.IsUntyped > 0 {
		if lhs, ok := got.Underlying().(*types.Basic); ok {
			return rhs.Info()&types.IsConstType == lhs.Info()&types.IsConstType
		}
	}
	return types.AssignableTo(want, got)
}

// MakeReadFile returns a simple implementation of the Pass.ReadFile function.
func MakeReadFile(pass *analysis.Pass) func(filename string) ([]byte, error) {
	return func(filename string) ([]byte, error) {
		if err := CheckReadable(pass, filename); err != nil {
			return nil, err
		}
		return os.ReadFile(filename)
	}
}

// CheckReadable enforces the access policy defined by the ReadFile field of [analysis.Pass].
func CheckReadable(pass *analysis.Pass, filename string) error {
	if slicesContains(pass.OtherFiles, filename) ||
		slicesContains(pass.IgnoredFiles, filename) {
		return nil
	}
	for _, f := range pass.Files {
		if pass.Fset.File(f.FileStart).Name() == filename {
			return nil
		}
	}
	return fmt.Errorf("Pass.ReadFile: %s is not among OtherFiles, IgnoredFiles, or names of Files", filename)
}

// TODO(adonovan): use go1.21 slices.Contains.
func slicesContains[S ~[]E, E comparable](slice S, x E) bool {
	for _, elem := range slice {
		if elem == x {
			return true
		}
	}
	return false
}

// AddImport checks whether this file already imports pkgpath and
// that import is in scope at pos. If so, it returns the name under
// which it was imported and a zero edit. Otherwise, it adds a new
// import of pkgpath, using a name derived from the preferred name,
// and returns the chosen name along with the edit for the new import.
//
// It does not mutate its arguments.
func AddImport(info *types.Info, file *ast.File, pos token.Pos, pkgpath, preferredName string) (name string, newImport []analysis.TextEdit) {
	// Find innermost enclosing lexical block.
	scope := info.Scopes[file].Innermost(pos)
	if scope == nil {
		panic("no enclosing lexical block")
	}

	// Is there an existing import of this package?
	// If so, are we in its scope? (not shadowed)
	for _, spec := range file.Imports {
		pkgname, ok := importedPkgName(info, spec)
		if ok && pkgname.Imported().Path() == pkgpath {
			if _, obj := scope.LookupParent(pkgname.Name(), pos); obj == pkgname {
				return pkgname.Name(), nil
			}
		}
	}

	// We must add a new import.
	// Ensure we have a fresh name.
	newName := preferredName
	for i := 0; ; i++ {
		if _, obj := scope.LookupParent(newName, pos); obj == nil {
			break // fresh
		}
		newName = fmt.Sprintf("%s%d", preferredName, i)
	}

	// For now, keep it real simple: create a new import
	// declaration before the first existing declaration (which
	// must exist), including its comments, and let goimports tidy it up.
	//
	// Use a renaming import whenever the preferred name is not
	// available, or the chosen name does not match the last
	// segment of its path.
	newText := fmt.Sprintf("import %q\n\n", pkgpath)
	if newName != preferredName || newName != pathpkg.Base(pkgpath) {
		newText = fmt.Sprintf("import %s %q\n\n", newName, pkgpath)
	}
	decl0 := file.Decls[0]
	var before ast.Node = decl0
	switch decl0 := decl0.(type) {
	case *ast.GenDecl:
		if decl0.Doc != nil {
			before = decl0.Doc
		}
	case *ast.FuncDecl:
		if decl0.Doc != nil {
			before = decl0.Doc
		}
	}
	return newName, []analysis.TextEdit{{
		Pos:     before.Pos(),
		End:     before.Pos(),
		NewText: []byte(newText),
	}}
}

// importedPkgName returns the PkgName object declared by an ImportSpec.
// TODO(adonovan): use go1.22's Info.PkgNameOf.
func importedPkgName(info *types.Info, imp *ast.ImportSpec) (*types.PkgName, bool) {
	var obj types.Object
	if imp.Name != nil {
		obj = info.Defs[imp.Name]
	} else {
		obj = info.Implicits[imp]
	}
	pkgname, ok := obj.(*types.PkgName)
	return pkgname, ok
}
```