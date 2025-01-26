Response:
Let's break down the thought process for analyzing the provided Go code and answering the prompt.

1. **Understanding the Goal:** The core request is to understand the functionality of the provided Go code snippet, which is part of the `ineffassign` linter. The request asks for a description of its features, a demonstration with Go code examples, an explanation of command-line arguments, and potential user errors.

2. **Initial Code Scan and Keyword Spotting:**  The first step is to quickly scan the code for recognizable Go keywords and structures. Keywords like `package`, `import`, `func`, `if`, `for`, `switch`, `return`, `ast`, `token`, `flag`, `filepath`, and `os` immediately stand out. The imports of `go/ast`, `go/parser`, and `go/token` strongly suggest this code is involved in analyzing Go source code. The use of `flag` indicates command-line argument processing.

3. **Identifying the Main Function:** The `main` function is the entry point. It uses `flag.Parse()` to process command-line arguments and then iterates through the arguments. The core logic seems to be within the `walkPath` function.

4. **Analyzing `walkPath`:** This function uses `filepath.Walk` to traverse directories. It checks for `.go` files and calls `checkPath` on them. The output prints messages about "ineffectual assignment". The `-n` flag is handled here to control recursion.

5. **Dissecting `checkPath`:** This function parses the Go file using `parser.ParseFile`. It creates `builder` and `checker` instances and seems to perform some kind of analysis. The `builder` walks the AST, and the `checker` then analyzes the built information.

6. **Investigating `builder` and `checker`:** The `builder` struct seems to collect information about variables and their assignments within different code blocks. The `checker` then uses this information to identify "ineffectual assignments". The definition of "ineffectual assignment" is crucial: an assignment to a variable where the assigned value is never used.

7. **Formulating the Core Functionality:** Based on the analysis so far, the central purpose of the code is to detect and report "ineffectual assignments" in Go code.

8. **Developing a Go Code Example:** To illustrate the functionality, a simple Go program with an ineffective assignment is needed. This helps to demonstrate what the linter is looking for. A case with shadowing is also a good example.

9. **Explaining the Command-line Argument:** The `flag` package is used for parsing arguments. The code expects one or more file paths as arguments. The `-n` flag for non-recursive checking is important.

10. **Identifying Potential User Errors:** Users might forget to provide file paths, or they might not understand what "ineffectual assignment" means. Shadowing is a common source of such errors.

11. **Structuring the Answer:**  The answer should be organized according to the prompt's requests:
    * Functionality description.
    * Go code example with explanation.
    * Explanation of command-line arguments.
    * Common user errors.

12. **Refining the Language:** Use clear and concise Chinese. Explain technical terms if necessary. For example, explicitly define "ineffectual assignment".

13. **Review and Verification:**  Read through the answer to ensure accuracy and completeness. Double-check the Go code examples and the explanation of the command-line arguments. Make sure the identified user errors are relevant.

**(Self-Correction during the process):**

* **Initial thought:**  Could this be related to unused variables?  *Correction:*  No, it specifically focuses on *assignments* where the assigned value isn't subsequently *used*. Unused variables are a related but distinct concept.
* **Considering edge cases:**  What about assignments in `if` statements or loops? The code handles these with the `builder` and `checker` structures which track variable usage within different blocks of code.
* **Command-line flag details:**  Initially, I might just say "handles a flag for recursion". *Correction:* Be more specific and mention the `-n` flag and its meaning.
* **User error clarity:** Instead of a vague "misunderstanding," provide a concrete example like the shadowing scenario.

By following this structured approach, including self-correction, we can arrive at a comprehensive and accurate answer to the prompt.
这段Go语言代码实现了一个静态分析工具，用于检测Go程序中**无效的变量赋值 (ineffectual assignment)**。 换句话说，它会查找那些被赋值后，其值在后续的代码中没有被使用的变量赋值操作。

以下是它的主要功能：

1. **命令行参数解析:**
   - 使用 `flag` 包来处理命令行参数。
   - 定义了一个布尔类型的 flag `-n`，默认值为 `false`。当设置为 `true` 时，表示**不递归**检查指定的路径下的子目录。

2. **路径处理:**
   - 接受一个或多个文件或目录路径作为命令行参数。
   - 将输入的路径转换为绝对路径。
   - 遍历指定的路径。如果是目录，则递归遍历其下的 `.go` 文件（除非使用了 `-n` flag）。

3. **Go代码解析:**
   - 对于每个 `.go` 文件，使用 `go/parser` 包将其解析为抽象语法树 (AST)。

4. **构建控制流图 (CFG) 和变量信息:**
   - 使用 `builder` 结构体遍历 AST，构建代码的控制流图，并记录每个变量的赋值和使用情况。
   - `builder` 结构体维护了代码块 (block) 的层级关系，以及每个代码块中变量的操作 (赋值或使用)。
   - 它还跟踪了 `break`、`continue` 和 `goto` 语句的目标位置。

5. **检测无效赋值:**
   - 使用 `checker` 结构体分析 `builder` 构建的信息，检测无效的变量赋值。
   - 它遍历每个代码块中的变量赋值操作。
   - 如果一个变量被赋值后，在当前代码块以及其后续的控制流中都没有被使用，那么这个赋值就被认为是无效的。
   - `checker` 会忽略那些可能发生逃逸的变量（例如，通过取地址传递的变量），因为它们的用途可能在当前分析的上下文中不可见。

6. **报告无效赋值:**
   - 如果检测到无效赋值，则打印出包含文件路径、行号和变量名的错误信息。

**它是什么Go语言功能的实现？**

这段代码实现了一个 **静态代码分析器** 或 **linter**，专注于检测 Go 语言中的 **无效变量赋值**。 静态代码分析是在不实际执行代码的情况下，通过分析源代码来发现潜在问题的技术。

**Go代码举例说明:**

假设有以下 `example.go` 文件：

```go
package main

import "fmt"

func main() {
	x := 10 // 假设的输入：这里被赋值
	y := 20
	fmt.Println(y) // 假设的输出：y 被使用，x 没有
}
```

如果使用 `ineffassign example.go` 运行这个工具，它会输出类似以下的信息：

```
example.go:6:2: ineffectual assignment to x
```

这表示在 `example.go` 文件的第 6 行，变量 `x` 被赋值了，但是它的值在后续的代码中没有被使用。

**假设的输入与输出（代码推理）：**

考虑以下 `test.go` 文件：

```go
package main

func main() {
	a := 1
	a = 2 // 第一次赋值的 1 没有被使用
	b := 3
	if true {
		b = 4 // 第一次赋值的 3 没有被使用，但在 if 块中被重新赋值
	}
	_ = b // b 最终被使用，虽然是赋值给 blank identifier
}
```

**假设的命令行输入:** `ineffassign test.go`

**假设的输出:**

```
test.go:4:2: ineffectual assignment to a
test.go:6:2: ineffectual assignment to b
```

**解释:**

- 对于变量 `a`，它首先被赋值为 `1`，然后立即被赋值为 `2`，所以第一次赋值是无效的。
- 对于变量 `b`，它首先被赋值为 `3`，然后在 `if` 语句块中被赋值为 `4`。即使 `if true` 总是执行，第一次对 `b` 的赋值也是无效的，因为它在接下来的控制流中被覆盖了。 注意，如果 `if` 条件是动态的，分析器可能无法准确判断是否无效。
- 最终 `b` 被赋值给了 `_`，这被认为是一种使用，因此最后一次对 `b` 的赋值（在 `if` 块中）不是无效的。

**命令行参数的具体处理:**

程序使用 `flag` 包来处理命令行参数。

- `flag.Parse()`:  这个函数会解析命令行参数，并将它们的值设置到对应的 flag 变量上。
- `flag.Args()`:  这个函数返回所有非 flag 参数的切片，也就是用户提供的文件或目录路径。
- `*dontRecurseFlag`:  这是一个指向布尔值的指针，它存储了 `-n` flag 的值。如果用户在命令行中使用了 `-n`，那么 `*dontRecurseFlag` 的值将变为 `true`。

在 `walkPath` 函数中，会检查 `*dontRecurseFlag` 的值：

```go
if fi.IsDir() {
	if path != root && (*dontRecurseFlag ||
		filepath.Base(path) == "testdata" ||
		filepath.Base(path) == "vendor") {
		return filepath.SkipDir
	}
	return nil
}
```

- 如果当前遍历到的 `path` 是一个目录，并且不是根目录，同时满足以下任一条件：
    - `*dontRecurseFlag` 为 `true` (用户使用了 `-n` flag)。
    - 目录名为 "testdata" 或 "vendor"。
- 那么 `filepath.SkipDir` 会被返回，导致 `filepath.Walk` 跳过对该目录的递归遍历。

**使用者易犯错的点:**

1. **忘记提供文件路径:**  如果用户在没有任何参数的情况下运行程序，`len(flag.Args()) == 0` 会为真，程序会打印错误信息并退出。

   ```bash
   ineffassign
   ```

   输出:

   ```
   missing argument: filepath
   ```

2. **不理解 "ineffectual assignment" 的含义:** 用户可能会误认为所有未使用的变量都会被标记，但实际上，这个工具只关注被赋值后没有被使用的变量。

   ```go
   package main

   import "fmt"

   func main() {
       x := 10 // 这里虽然没有被使用，但没有后续的赋值，不会被标记为 ineffectual assignment
       fmt.Println("Hello")
   }
   ```

   `ineffassign` 不会报告上面的 `x`。它只关注像这样的情况：

   ```go
   package main

   import "fmt"

   func main() {
       x := 10
       x = 20 // 第一次对 x 的赋值 (10) 是 ineffectual
       fmt.Println(x)
   }
   ```

   `ineffassign` 会报告对 `x` 的第一次赋值是无效的。

3. **对 `-n` flag 的理解偏差:** 用户可能不清楚 `-n` flag 的作用，导致在希望递归检查子目录时使用了 `-n`，反之亦然。

总而言之，这段代码是一个用于检测 Go 代码中无效变量赋值的实用工具，它可以帮助开发者发现潜在的代码冗余和提高代码质量。它通过解析 Go 源代码，构建控制流图，并分析变量的赋值和使用情况来实现其功能。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/gordonklaus/ineffassign/ineffassign.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const invalidArgumentExitCode = 3

var dontRecurseFlag = flag.Bool("n", false, "don't recursively check paths")

func main() {
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Println("missing argument: filepath")
		os.Exit(invalidArgumentExitCode)
	}

	lintFailed := false
	for _, path := range flag.Args() {
		root, err := filepath.Abs(path)
		if err != nil {
			fmt.Printf("Error finding absolute path: %s", err)
			os.Exit(invalidArgumentExitCode)
		}
		if walkPath(root) {
			lintFailed = true
		}
	}
	if lintFailed {
		os.Exit(1)
	}
}

func walkPath(root string) bool {
	lintFailed := false
	filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("Error during filesystem walk: %v\n", err)
			return nil
		}
		if fi.IsDir() {
			if path != root && (*dontRecurseFlag ||
				filepath.Base(path) == "testdata" ||
				filepath.Base(path) == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		fset, _, ineff := checkPath(path)
		for _, id := range ineff {
			fmt.Printf("%s: ineffectual assignment to %s\n", fset.Position(id.Pos()), id.Name)
			lintFailed = true
		}
		return nil
	})
	return lintFailed
}

func checkPath(path string) (*token.FileSet, []*ast.CommentGroup, []*ast.Ident) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, nil, nil
	}

	bld := &builder{vars: map[*ast.Object]*variable{}}
	bld.walk(f)

	chk := &checker{vars: bld.vars, seen: map[*block]bool{}}
	for _, b := range bld.roots {
		chk.check(b)
	}
	sort.Sort(chk.ineff)

	return fset, f.Comments, chk.ineff
}

type builder struct {
	roots     []*block
	block     *block
	vars      map[*ast.Object]*variable
	results   []*ast.FieldList
	breaks    branchStack
	continues branchStack
	gotos     branchStack
	labelStmt *ast.LabeledStmt
}

type block struct {
	children []*block
	ops      map[*ast.Object][]operation
}

func (b *block) addChild(c *block) {
	b.children = append(b.children, c)
}

type operation struct {
	id     *ast.Ident
	assign bool
}

type variable struct {
	fundept int
	escapes bool
}

func (bld *builder) walk(n ast.Node) {
	if n != nil {
		ast.Walk(bld, n)
	}
}

func (bld *builder) Visit(n ast.Node) ast.Visitor {
	switch n := n.(type) {
	case *ast.FuncDecl:
		if n.Body != nil {
			bld.fun(n.Type, n.Body)
		}
	case *ast.FuncLit:
		bld.fun(n.Type, n.Body)
	case *ast.IfStmt:
		bld.walk(n.Init)
		bld.walk(n.Cond)
		b0 := bld.block
		bld.newBlock(b0)
		bld.walk(n.Body)
		b1 := bld.block
		if n.Else != nil {
			bld.newBlock(b0)
			bld.walk(n.Else)
			b0 = bld.block
		}
		bld.newBlock(b0, b1)
	case *ast.ForStmt:
		lbl := bld.stmtLabel(n)
		brek := bld.breaks.push(lbl)
		continu := bld.continues.push(lbl)
		bld.walk(n.Init)
		start := bld.newBlock(bld.block)
		bld.walk(n.Cond)
		cond := bld.block
		bld.newBlock(cond)
		bld.walk(n.Body)
		continu.setDestination(bld.newBlock(bld.block))
		bld.walk(n.Post)
		bld.block.addChild(start)
		brek.setDestination(bld.newBlock(cond))
		bld.breaks.pop()
		bld.continues.pop()
	case *ast.RangeStmt:
		lbl := bld.stmtLabel(n)
		brek := bld.breaks.push(lbl)
		continu := bld.continues.push(lbl)
		bld.walk(n.X)
		pre := bld.newBlock(bld.block)
		start := bld.newBlock(pre)
		if n.Key != nil {
			lhs := []ast.Expr{n.Key}
			if n.Value != nil {
				lhs = append(lhs, n.Value)
			}
			bld.walk(&ast.AssignStmt{Lhs: lhs, Tok: n.Tok, TokPos: n.TokPos, Rhs: []ast.Expr{&ast.Ident{NamePos: n.X.End()}}})
		}
		bld.walk(n.Body)
		bld.block.addChild(start)
		continu.setDestination(pre)
		brek.setDestination(bld.newBlock(pre, bld.block))
		bld.breaks.pop()
		bld.continues.pop()
	case *ast.SwitchStmt:
		bld.walk(n.Init)
		bld.walk(n.Tag)
		bld.swtch(n, n.Body.List)
	case *ast.TypeSwitchStmt:
		bld.walk(n.Init)
		bld.walk(n.Assign)
		bld.swtch(n, n.Body.List)
	case *ast.SelectStmt:
		brek := bld.breaks.push(bld.stmtLabel(n))
		for _, c := range n.Body.List {
			c := c.(*ast.CommClause).Comm
			if s, ok := c.(*ast.AssignStmt); ok {
				bld.walk(s.Rhs[0])
			} else {
				bld.walk(c)
			}
		}
		b0 := bld.block
		exits := make([]*block, len(n.Body.List))
		dfault := false
		for i, c := range n.Body.List {
			c := c.(*ast.CommClause)
			bld.newBlock(b0)
			bld.walk(c)
			exits[i] = bld.block
			dfault = dfault || c.Comm == nil
		}
		if !dfault {
			exits = append(exits, b0)
		}
		brek.setDestination(bld.newBlock(exits...))
		bld.breaks.pop()
	case *ast.LabeledStmt:
		bld.gotos.get(n.Label).setDestination(bld.newBlock(bld.block))
		bld.labelStmt = n
		bld.walk(n.Stmt)
	case *ast.BranchStmt:
		switch n.Tok {
		case token.BREAK:
			bld.breaks.get(n.Label).addSource(bld.block)
			bld.newBlock()
		case token.CONTINUE:
			bld.continues.get(n.Label).addSource(bld.block)
			bld.newBlock()
		case token.GOTO:
			bld.gotos.get(n.Label).addSource(bld.block)
			bld.newBlock()
		}

	case *ast.AssignStmt:
		if n.Tok == token.QUO_ASSIGN || n.Tok == token.REM_ASSIGN {
			bld.maybePanic()
		}

		for _, x := range n.Rhs {
			bld.walk(x)
		}
		for i, x := range n.Lhs {
			if id, ok := ident(x); ok {
				if n.Tok >= token.ADD_ASSIGN && n.Tok <= token.AND_NOT_ASSIGN {
					bld.use(id)
				}
				// Don't treat explicit initialization to zero as assignment; it is often used as shorthand for a bare declaration.
				if n.Tok == token.DEFINE && i < len(n.Rhs) && isZeroLiteral(n.Rhs[i]) {
					bld.use(id)
				} else {
					bld.assign(id)
				}
			} else {
				bld.walk(x)
			}
		}
	case *ast.GenDecl:
		if n.Tok == token.VAR {
			for _, s := range n.Specs {
				s := s.(*ast.ValueSpec)
				for _, x := range s.Values {
					bld.walk(x)
				}
				for _, id := range s.Names {
					if len(s.Values) > 0 {
						bld.assign(id)
					} else {
						bld.use(id)
					}
				}
			}
		}
	case *ast.IncDecStmt:
		if id, ok := ident(n.X); ok {
			bld.use(id)
			bld.assign(id)
		} else {
			bld.walk(n.X)
		}
	case *ast.Ident:
		bld.use(n)
	case *ast.ReturnStmt:
		for _, x := range n.Results {
			bld.walk(x)
		}
		res := bld.results[len(bld.results)-1]
		if res == nil {
			break
		}
		for _, f := range res.List {
			for _, id := range f.Names {
				if n.Results != nil {
					bld.assign(id)
				}
				bld.use(id)
			}
		}
	case *ast.SendStmt:
		bld.maybePanic()
		return bld

	case *ast.BinaryExpr:
		if n.Op == token.EQL || n.Op == token.QUO || n.Op == token.REM {
			bld.maybePanic()
		}
		return bld
	case *ast.CallExpr:
		bld.maybePanic()
		return bld
	case *ast.IndexExpr:
		bld.maybePanic()
		return bld
	case *ast.UnaryExpr:
		id, ok := ident(n.X)
		if ix, isIx := n.X.(*ast.IndexExpr); isIx {
			// We don't care about indexing into slices, but without type information we can do no better.
			id, ok = ident(ix.X)
		}
		if ok && n.Op == token.AND {
			if v, ok := bld.vars[id.Obj]; ok {
				v.escapes = true
			}
		}
		return bld
	case *ast.SelectorExpr:
		bld.maybePanic()
		// A method call (possibly delayed via a method value) might implicitly take
		// the address of its receiver, causing it to escape.
		// We can't do any better here without knowing the variable's type.
		if id, ok := ident(n.X); ok {
			if v, ok := bld.vars[id.Obj]; ok {
				v.escapes = true
			}
		}
		return bld
	case *ast.SliceExpr:
		bld.maybePanic()
		// We don't care about slicing into slices, but without type information we can do no better.
		if id, ok := ident(n.X); ok {
			if v, ok := bld.vars[id.Obj]; ok {
				v.escapes = true
			}
		}
		return bld
	case *ast.StarExpr:
		bld.maybePanic()
		return bld
	case *ast.TypeAssertExpr:
		bld.maybePanic()
		return bld

	default:
		return bld
	}
	return nil
}

func isZeroLiteral(x ast.Expr) bool {
	b, ok := x.(*ast.BasicLit)
	if !ok {
		return false
	}
	switch b.Value {
	case "0", "0.0", "0.", ".0", `""`:
		return true
	}
	return false
}

func (bld *builder) fun(typ *ast.FuncType, body *ast.BlockStmt) {
	for _, v := range bld.vars {
		v.fundept++
	}
	bld.results = append(bld.results, typ.Results)

	b := bld.block
	bld.newBlock()
	bld.roots = append(bld.roots, bld.block)
	bld.walk(typ)
	bld.walk(body)
	bld.block = b

	bld.results = bld.results[:len(bld.results)-1]
	for _, v := range bld.vars {
		v.fundept--
	}
}

func (bld *builder) swtch(stmt ast.Stmt, cases []ast.Stmt) {
	brek := bld.breaks.push(bld.stmtLabel(stmt))
	b0 := bld.block
	list := b0
	exits := make([]*block, 0, len(cases)+1)
	var dfault, fallthru *block
	for _, c := range cases {
		c := c.(*ast.CaseClause)

		if c.List != nil {
			list = bld.newBlock(list)
			for _, x := range c.List {
				bld.walk(x)
			}
		}

		parents := []*block{}
		if c.List != nil {
			parents = append(parents, list)
		}
		if fallthru != nil {
			parents = append(parents, fallthru)
			fallthru = nil
		}
		bld.newBlock(parents...)
		if c.List == nil {
			dfault = bld.block
		}
		for _, s := range c.Body {
			bld.walk(s)
			if s, ok := s.(*ast.BranchStmt); ok && s.Tok == token.FALLTHROUGH {
				fallthru = bld.block
			}
		}

		if fallthru == nil {
			exits = append(exits, bld.block)
		}
	}
	if dfault != nil {
		list.addChild(dfault)
	} else {
		exits = append(exits, b0)
	}
	brek.setDestination(bld.newBlock(exits...))
	bld.breaks.pop()
}

// An operation that might panic marks named function results as used.
func (bld *builder) maybePanic() {
	if len(bld.results) == 0 {
		return
	}
	res := bld.results[len(bld.results)-1]
	if res == nil {
		return
	}
	for _, f := range res.List {
		for _, id := range f.Names {
			bld.use(id)
		}
	}
}

func (bld *builder) newBlock(parents ...*block) *block {
	bld.block = &block{ops: map[*ast.Object][]operation{}}
	for _, b := range parents {
		b.addChild(bld.block)
	}
	return bld.block
}

func (bld *builder) stmtLabel(s ast.Stmt) *ast.Object {
	if ls := bld.labelStmt; ls != nil && ls.Stmt == s {
		return ls.Label.Obj
	}
	return nil
}

func (bld *builder) assign(id *ast.Ident) {
	bld.newOp(id, true)
}

func (bld *builder) use(id *ast.Ident) {
	bld.newOp(id, false)
}

func (bld *builder) newOp(id *ast.Ident, assign bool) {
	if id.Name == "_" || id.Obj == nil {
		return
	}

	v, ok := bld.vars[id.Obj]
	if !ok {
		v = &variable{}
		bld.vars[id.Obj] = v
	}
	v.escapes = v.escapes || v.fundept > 0 || bld.block == nil

	if b := bld.block; b != nil {
		b.ops[id.Obj] = append(b.ops[id.Obj], operation{id, assign})
	}
}

type branchStack []*branch

type branch struct {
	label *ast.Object
	srcs  []*block
	dst   *block
}

func (s *branchStack) push(lbl *ast.Object) *branch {
	br := &branch{label: lbl}
	*s = append(*s, br)
	return br
}

func (s *branchStack) get(lbl *ast.Ident) *branch {
	for i := len(*s) - 1; i >= 0; i-- {
		if br := (*s)[i]; lbl == nil || br.label == lbl.Obj {
			return br
		}
	}
	return s.push(lbl.Obj)
}

func (br *branch) addSource(src *block) {
	br.srcs = append(br.srcs, src)
	if br.dst != nil {
		src.addChild(br.dst)
	}
}

func (br *branch) setDestination(dst *block) {
	br.dst = dst
	for _, src := range br.srcs {
		src.addChild(dst)
	}
}

func (s *branchStack) pop() {
	*s = (*s)[:len(*s)-1]
}

func ident(x ast.Expr) (*ast.Ident, bool) {
	if p, ok := x.(*ast.ParenExpr); ok {
		return ident(p.X)
	}
	id, ok := x.(*ast.Ident)
	return id, ok
}

type checker struct {
	vars  map[*ast.Object]*variable
	seen  map[*block]bool
	ineff idents
}

func (chk *checker) check(b *block) {
	if chk.seen[b] {
		return
	}
	chk.seen[b] = true

	for obj, ops := range b.ops {
		if chk.vars[obj].escapes {
			continue
		}
	ops:
		for i, op := range ops {
			if !op.assign {
				continue
			}
			if i+1 < len(ops) {
				if ops[i+1].assign {
					chk.ineff = append(chk.ineff, op.id)
				}
				continue
			}
			seen := map[*block]bool{}
			for _, b := range b.children {
				if used(obj, b, seen) {
					continue ops
				}
			}
			chk.ineff = append(chk.ineff, op.id)
		}
	}

	for _, b := range b.children {
		chk.check(b)
	}
}

func used(obj *ast.Object, b *block, seen map[*block]bool) bool {
	if seen[b] {
		return false
	}
	seen[b] = true

	if ops := b.ops[obj]; len(ops) > 0 {
		return !ops[0].assign
	}
	for _, b := range b.children {
		if used(obj, b, seen) {
			return true
		}
	}
	return false
}

type idents []*ast.Ident

func (ids idents) Len() int           { return len(ids) }
func (ids idents) Less(i, j int) bool { return ids[i].Pos() < ids[j].Pos() }
func (ids idents) Swap(i, j int)      { ids[i], ids[j] = ids[j], ids[i] }

"""



```