Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - Context is Key:**

The first and most crucial step is to understand the *context*. The prompt explicitly mentions the file path: `go/src/github.com/alecthomas/gometalinter/_linters/src/mvdan.cc/interfacer/check/check.go`. This immediately tells us:

* **Tooling:** This is part of a code analysis or linting tool (`gometalinter`).
* **Specific Linter:**  It's within a sub-package named "interfacer," suggesting it deals with interfaces.
* **Check Functionality:** The directory name "check" and the function name `CheckArgs` strongly indicate this code is responsible for *checking* something related to interfaces.

**2. High-Level Functionality - Skimming the Code:**

Next, skim through the code to get a general sense of its operations. Look for key functions and data structures:

* **`CheckArgs(args []string)`:** This is the entry point, taking command-line arguments (import paths). It uses `golang.org/x/tools/go/loader` and `golang.org/x/tools/go/ssa` to load and analyze Go code. This confirms it's a static analysis tool.
* **`Checker` struct:**  This likely holds the state for the analysis. It contains fields like `lprog` (loaded program), `prog` (SSA representation), `funcs`, `vars`, and `ifaces`. The presence of `ssa` confirms Static Single Assignment analysis.
* **`Check()` method:** This is where the main checking logic resides. It iterates through functions, packages, and calls other check-related methods.
* **`interfaceMatching()`:**  This function name strongly suggests the core logic is about finding suitable interfaces.
* **`varUsage` struct:**  This seems to track how variables are used, specifically their method calls and assignments.

**3. Deeper Dive - Understanding Key Algorithms:**

Now, let's examine the crucial parts in more detail:

* **Interface Inference:** The `interfaceMatching` function, along with `varUsage`, seems to be the core. The logic revolves around tracking the *methods called* on a variable. If a variable of a concrete type only uses methods that are part of an interface, the tool suggests that the variable's type could be changed to that interface.
* **SSA (Static Single Assignment):** The use of `golang.org/x/tools/go/ssa` is a strong indicator of how the analysis works. SSA makes it easier to track variable assignments and usage.
* **`toDiscard`:** This function seems to identify situations where an interface suggestion isn't applicable (e.g., the variable is discarded).
* **`allCalls`:** This recursively gathers all the methods called on a variable and its assigned variables.

**4. Code Examples and Reasoning:**

Based on the above understanding, we can construct code examples to illustrate the functionality. The goal is to show how the tool identifies opportunities to use interfaces:

* **Input:**  A function taking a concrete type (e.g., `*bytes.Buffer`) but only calling methods that exist on `io.Writer`.
* **Output:** A suggestion to change the parameter type to `io.Writer`.

The code examples should demonstrate the core logic without getting bogged down in overly complex scenarios.

**5. Command-Line Arguments:**

The `CheckArgs` function handles command-line arguments. It uses `gotool.ImportPaths` to resolve import paths. This means the tool takes Go package import paths as input.

**6. Common Mistakes:**

Consider how a developer might unknowingly write code that this tool would flag. The key mistake is using a concrete type when an interface would be sufficient, reducing coupling and improving flexibility. Examples of this were already developed in the "Code Examples" step.

**7. Structuring the Answer:**

Finally, organize the information logically, following the prompt's requests:

* **功能 (Functionality):** Start with a concise summary of the tool's purpose.
* **Go 语言功能实现 (Go Feature Implementation):** Explain the underlying Go feature it's checking (interface usage).
* **Go 代码举例 (Go Code Examples):** Provide clear examples with input and expected output.
* **命令行参数 (Command-Line Arguments):** Describe how to invoke the tool.
* **使用者易犯错的点 (Common Mistakes):** Highlight the typical coding patterns that trigger the tool's suggestions.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:** Maybe it's just checking if an interface is implemented.
* **Correction:**  The `interfaceMatching` and `varUsage` logic suggest it's *inferring* potential interfaces, not just checking existing implementations. It looks for opportunities to *introduce* interfaces.
* **Initial thought:** Focus on complex scenarios with multiple assignments.
* **Correction:** Start with simpler examples to illustrate the core concept before moving to more intricate cases if needed. The current examples are sufficient to demonstrate the core logic.
* **Consider edge cases:**  What happens with empty interfaces? What about variables that are never used?  The `toDiscard` function seems to handle some of these. Mentioning this briefly adds to the completeness of the answer.

By following these steps, combining code analysis with an understanding of the surrounding context and the prompt's requirements, we arrive at a comprehensive and accurate answer.
这段Go语言代码是 `mvdan.cc/interfacer` 工具的核心部分，它的主要功能是**检查Go代码中是否可以将具体的类型转换为更通用的接口类型**。简单来说，它会分析代码中变量的使用方式，如果一个变量只调用了某个接口定义的方法，那么它会建议将该变量的类型更改为该接口类型。

下面详细列举其功能：

1. **加载和解析Go代码:**  `CheckArgs` 函数是入口点，它使用 `golang.org/x/tools/go/loader` 包加载指定的Go包及其依赖项，并将代码解析为抽象语法树 (AST)。

2. **构建静态单赋值 (SSA) 中间表示:** 代码使用 `golang.org/x/tools/go/ssa` 包将加载的代码转换为静态单赋值 (SSA) 的形式。SSA 是一种编译器中间表示，它使得变量的定义和使用关系更加明确，便于进行程序分析。

3. **跟踪变量的使用情况:** `Checker` 结构体及其相关方法，特别是 `varUsage` 结构体和 `addUsed`、`addAssign` 等方法，负责跟踪代码中变量的使用方式。它会记录变量调用了哪些方法，是否被赋值给其他变量等信息。

4. **识别可以替换为接口的场景:** `interfaceMatching` 函数是核心逻辑，它基于变量的使用情况，尝试找到一个合适的接口类型。如果一个变量只调用了某个接口定义的方法，该函数就会返回该接口的名称和方法签名信息。

5. **生成代码改进建议:**  `groupIssues` 和 `packageIssues` 函数遍历分析结果，生成可以将具体类型替换为接口的建议。这些建议以 `lint.Issue` 的形式返回，包含了代码位置和改进信息。

6. **处理命令行参数:** `CheckArgs` 函数接收命令行参数，这些参数通常是Go包的导入路径。

**它是什么Go语言功能的实现：**

这段代码主要实现了对 **Go 接口 (interface)** 的静态分析和优化建议。Go 接口是 Go 语言中一种强大的抽象机制，它允许我们编写更灵活、更可测试的代码。`interfacer` 工具的目标是帮助开发者更好地利用接口，通过将具体的类型替换为接口，可以降低代码的耦合性，提高代码的可重用性和可扩展性。

**Go代码举例说明：**

假设有以下Go代码 `example.go`:

```go
package main

import (
	"bytes"
	"fmt"
	"io"
)

func processData(buf *bytes.Buffer) {
	fmt.Println(buf.String())
}

func main() {
	var b bytes.Buffer
	b.WriteString("Hello, world!")
	processData(&b)
}
```

**假设输入：**  运行 `interfacer` 工具并指定 `example.go` 所在的目录或包路径。

**代码推理:**

`interfacer` 会分析 `processData` 函数的参数 `buf *bytes.Buffer` 的使用情况。它会发现 `processData` 函数内部只调用了 `buf` 的 `String()` 方法。而 `String()` 方法是 `io.Reader` 接口的一部分。因此，`interfacer` 会建议将 `processData` 函数的参数类型从 `*bytes.Buffer` 修改为 `io.Reader`。

**假设输出：**

```
example.go:7:19: buf can be io.Reader
```

这意味着在 `example.go` 文件的第 7 行，第 19 列（`buf` 参数的位置），可以将 `buf` 的类型从 `*bytes.Buffer` 修改为 `io.Reader`。

**修改后的代码：**

```go
package main

import (
	"bytes"
	"fmt"
	"io"
)

func processData(r io.Reader) {
	b, _ := io.ReadAll(r)
	fmt.Println(string(b))
}

func main() {
	var b bytes.Buffer
	b.WriteString("Hello, world!")
	processData(&b)
}
```

**命令行参数的具体处理：**

`CheckArgs` 函数接收一个字符串切片 `args` 作为输入，这些字符串通常是通过命令行传递的。

1. **`gotool.ImportPaths(args)`:**  首先，使用 `github.com/kisielk/gotool` 包的 `ImportPaths` 函数将命令行参数转换为Go包的导入路径。这个函数会处理 `.`（当前目录）、相对路径和绝对路径等情况，将其转换为标准的导入路径。

2. **`loader.Config{}`:** 创建一个 `golang.org/x/tools/go/loader` 包的 `Config` 结构体，用于配置代码加载过程。

3. **`conf.AllowErrors = true`:**  设置允许加载过程中出现错误，但这并不意味着会忽略错误，而是会继续尝试加载其他包。

4. **`conf.FromArgs(paths, false)`:**  使用 `conf.FromArgs` 方法根据解析后的导入路径加载Go包。第二个参数 `false` 表示不加载测试文件。该方法会返回无法解析为包路径的剩余参数 (`rest`) 和一个错误 (`err`)。

5. **错误处理:** 检查 `conf.FromArgs` 是否返回错误，如果返回错误，则直接返回。同时检查是否存在无法解析的额外参数 (`len(rest) > 0`)，如果存在，则返回一个包含错误信息的错误。

6. **`conf.Load()`:**  调用 `conf.Load()` 方法执行代码加载过程，返回一个 `loader.Program` 实例 (`lprog`) 和一个错误 (`err`)。

7. **构建SSA程序:** 使用 `ssautil.CreateProgram(lprog, 0)` 和 `prog.Build()` 基于加载的程序构建 SSA 中间表示。

8. **创建Checker实例:**  创建一个 `Checker` 实例。

9. **设置Program信息:** 调用 `c.Program(lprog)` 和 `c.ProgramSSA(prog)` 将加载的程序和 SSA 程序信息传递给 `Checker` 实例。

10. **执行检查:** 调用 `c.Check()` 方法执行主要的接口检查逻辑，返回一个 `lint.Issue` 切片 (`issues`) 和一个错误 (`err`)。

11. **格式化输出:** 获取当前工作目录，并遍历 `issues` 切片，将每个 `lint.Issue` 的位置信息格式化为相对于当前工作目录的相对路径，并将位置和错误信息组合成字符串。

**使用者易犯错的点：**

使用者在使用 `interfacer` 这类工具时，可能会遇到以下易犯错的点：

* **过度追求接口化:**  虽然将具体类型替换为接口可以提高代码的灵活性，但并非所有场景都适合。过度地使用接口可能会导致代码可读性下降，因为调用者需要查看接口的定义才能了解具体能调用哪些方法。应该根据实际情况权衡利弊。
* **忽略性能影响:** 在某些性能敏感的场景下，使用接口可能会引入额外的间接调用，导致性能略有下降。虽然这种影响通常很小，但在某些极端情况下可能需要考虑。
* **不理解工具的建议:**  使用者可能会不理解工具提出的建议，例如，不明白为什么一个具体的类型可以替换为某个接口。这时需要仔细分析工具的输出，并理解接口的定义和具体类型的方法集合之间的关系。
* **误报或过度建议:** 静态分析工具可能会存在误报或提出一些不必要的建议。例如，如果一个变量只在一个很小的局部范围内使用，并且明确知道其具体类型，那么将其替换为接口的意义可能不大。

**举例说明使用者易犯错的点：**

假设有以下代码：

```go
package main

import "fmt"

type MyInt int

func printValue(val MyInt) {
	fmt.Println(val)
}

func main() {
	var num MyInt = 10
	printValue(num)
}
```

`interfacer` 可能会建议将 `printValue` 函数的参数类型从 `MyInt` 修改为 `interface{}`，因为 `fmt.Println` 可以接受任何类型。然而，这样做并没有实际意义，因为我们明确知道 `printValue` 函数是用来处理 `MyInt` 类型的。过度地遵循工具的建议可能会导致代码失去类型信息。

总而言之，这段代码是 `mvdan.cc/interfacer` 工具的核心，它通过静态分析Go代码，识别可以将具体类型替换为更通用接口的场景，从而帮助开发者编写更灵活和可维护的Go代码。它涉及到Go语言的AST解析、SSA构建以及类型系统分析等多个方面。理解其功能和原理可以帮助开发者更好地利用这个工具，并在实际开发中写出更符合Go语言设计哲学的代码。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/mvdan.cc/interfacer/check/check.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright (c) 2015, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package check // import "mvdan.cc/interfacer/check"

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"strings"

	"golang.org/x/tools/go/loader"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/kisielk/gotool"
	"mvdan.cc/lint"
)

func toDiscard(usage *varUsage) bool {
	if usage.discard {
		return true
	}
	for to := range usage.assigned {
		if toDiscard(to) {
			return true
		}
	}
	return false
}

func allCalls(usage *varUsage, all, ftypes map[string]string) {
	for fname := range usage.calls {
		all[fname] = ftypes[fname]
	}
	for to := range usage.assigned {
		allCalls(to, all, ftypes)
	}
}

func (c *Checker) interfaceMatching(param *types.Var, usage *varUsage) (string, string) {
	if toDiscard(usage) {
		return "", ""
	}
	ftypes := typeFuncMap(param.Type())
	called := make(map[string]string, len(usage.calls))
	allCalls(usage, called, ftypes)
	s := funcMapString(called)
	return c.ifaces[s], s
}

type varUsage struct {
	calls   map[string]struct{}
	discard bool

	assigned map[*varUsage]struct{}
}

type funcDecl struct {
	astDecl *ast.FuncDecl
	ssaFn   *ssa.Function
}

// CheckArgs checks the packages specified by their import paths in
// args.
func CheckArgs(args []string) ([]string, error) {
	paths := gotool.ImportPaths(args)
	conf := loader.Config{}
	conf.AllowErrors = true
	rest, err := conf.FromArgs(paths, false)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unwanted extra args: %v", rest)
	}
	lprog, err := conf.Load()
	if err != nil {
		return nil, err
	}
	prog := ssautil.CreateProgram(lprog, 0)
	prog.Build()
	c := new(Checker)
	c.Program(lprog)
	c.ProgramSSA(prog)
	issues, err := c.Check()
	if err != nil {
		return nil, err
	}
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	lines := make([]string, len(issues))
	for i, issue := range issues {
		fpos := prog.Fset.Position(issue.Pos()).String()
		if strings.HasPrefix(fpos, wd) {
			fpos = fpos[len(wd)+1:]
		}
		lines[i] = fmt.Sprintf("%s: %s", fpos, issue.Message())
	}
	return lines, nil
}

type Checker struct {
	lprog *loader.Program
	prog  *ssa.Program

	pkgTypes
	*loader.PackageInfo

	funcs []*funcDecl

	ssaByPos map[token.Pos]*ssa.Function

	discardFuncs map[*types.Signature]struct{}

	vars map[*types.Var]*varUsage
}

var (
	_ lint.Checker = (*Checker)(nil)
	_ lint.WithSSA = (*Checker)(nil)
)

func (c *Checker) Program(lprog *loader.Program) {
	c.lprog = lprog
}

func (c *Checker) ProgramSSA(prog *ssa.Program) {
	c.prog = prog
}

func (c *Checker) Check() ([]lint.Issue, error) {
	var total []lint.Issue
	c.ssaByPos = make(map[token.Pos]*ssa.Function)
	wantPkg := make(map[*types.Package]bool)
	for _, pinfo := range c.lprog.InitialPackages() {
		wantPkg[pinfo.Pkg] = true
	}
	for fn := range ssautil.AllFunctions(c.prog) {
		if fn.Pkg == nil { // builtin?
			continue
		}
		if len(fn.Blocks) == 0 { // stub
			continue
		}
		if !wantPkg[fn.Pkg.Pkg] { // not part of given pkgs
			continue
		}
		c.ssaByPos[fn.Pos()] = fn
	}
	for _, pinfo := range c.lprog.InitialPackages() {
		pkg := pinfo.Pkg
		c.getTypes(pkg)
		c.PackageInfo = c.lprog.AllPackages[pkg]
		total = append(total, c.checkPkg()...)
	}
	return total, nil
}

func (c *Checker) checkPkg() []lint.Issue {
	c.discardFuncs = make(map[*types.Signature]struct{})
	c.vars = make(map[*types.Var]*varUsage)
	c.funcs = c.funcs[:0]
	findFuncs := func(node ast.Node) bool {
		decl, ok := node.(*ast.FuncDecl)
		if !ok {
			return true
		}
		ssaFn := c.ssaByPos[decl.Name.Pos()]
		if ssaFn == nil {
			return true
		}
		fd := &funcDecl{
			astDecl: decl,
			ssaFn:   ssaFn,
		}
		if c.funcSigns[signString(fd.ssaFn.Signature)] {
			// implements interface
			return true
		}
		c.funcs = append(c.funcs, fd)
		ast.Walk(c, decl.Body)
		return true
	}
	for _, f := range c.Files {
		ast.Inspect(f, findFuncs)
	}
	return c.packageIssues()
}

func paramVarAndType(sign *types.Signature, i int) (*types.Var, types.Type) {
	params := sign.Params()
	extra := sign.Variadic() && i >= params.Len()-1
	if !extra {
		if i >= params.Len() {
			// builtins with multiple signatures
			return nil, nil
		}
		vr := params.At(i)
		return vr, vr.Type()
	}
	last := params.At(params.Len() - 1)
	switch x := last.Type().(type) {
	case *types.Slice:
		return nil, x.Elem()
	default:
		return nil, x
	}
}

func (c *Checker) varUsage(e ast.Expr) *varUsage {
	id, ok := e.(*ast.Ident)
	if !ok {
		return nil
	}
	param, ok := c.ObjectOf(id).(*types.Var)
	if !ok {
		// not a variable
		return nil
	}
	if usage, e := c.vars[param]; e {
		return usage
	}
	if !interesting(param.Type()) {
		return nil
	}
	usage := &varUsage{
		calls:    make(map[string]struct{}),
		assigned: make(map[*varUsage]struct{}),
	}
	c.vars[param] = usage
	return usage
}

func (c *Checker) addUsed(e ast.Expr, as types.Type) {
	if as == nil {
		return
	}
	if usage := c.varUsage(e); usage != nil {
		// using variable
		iface, ok := as.Underlying().(*types.Interface)
		if !ok {
			usage.discard = true
			return
		}
		for i := 0; i < iface.NumMethods(); i++ {
			m := iface.Method(i)
			usage.calls[m.Name()] = struct{}{}
		}
	} else if t, ok := c.TypeOf(e).(*types.Signature); ok {
		// using func
		c.discardFuncs[t] = struct{}{}
	}
}

func (c *Checker) addAssign(to, from ast.Expr) {
	pto := c.varUsage(to)
	pfrom := c.varUsage(from)
	if pto == nil || pfrom == nil {
		// either isn't interesting
		return
	}
	pfrom.assigned[pto] = struct{}{}
}

func (c *Checker) discard(e ast.Expr) {
	if usage := c.varUsage(e); usage != nil {
		usage.discard = true
	}
}

func (c *Checker) comparedWith(e, with ast.Expr) {
	if _, ok := with.(*ast.BasicLit); ok {
		c.discard(e)
	}
}

func (c *Checker) Visit(node ast.Node) ast.Visitor {
	switch x := node.(type) {
	case *ast.SelectorExpr:
		if _, ok := c.TypeOf(x.Sel).(*types.Signature); !ok {
			c.discard(x.X)
		}
	case *ast.StarExpr:
		c.discard(x.X)
	case *ast.UnaryExpr:
		c.discard(x.X)
	case *ast.IndexExpr:
		c.discard(x.X)
	case *ast.IncDecStmt:
		c.discard(x.X)
	case *ast.BinaryExpr:
		switch x.Op {
		case token.EQL, token.NEQ:
			c.comparedWith(x.X, x.Y)
			c.comparedWith(x.Y, x.X)
		default:
			c.discard(x.X)
			c.discard(x.Y)
		}
	case *ast.ValueSpec:
		for _, val := range x.Values {
			c.addUsed(val, c.TypeOf(x.Type))
		}
	case *ast.AssignStmt:
		for i, val := range x.Rhs {
			left := x.Lhs[i]
			if x.Tok == token.ASSIGN {
				c.addUsed(val, c.TypeOf(left))
			}
			c.addAssign(left, val)
		}
	case *ast.CompositeLit:
		for i, e := range x.Elts {
			switch y := e.(type) {
			case *ast.KeyValueExpr:
				c.addUsed(y.Key, c.TypeOf(y.Value))
				c.addUsed(y.Value, c.TypeOf(y.Key))
			case *ast.Ident:
				c.addUsed(y, compositeIdentType(c.TypeOf(x), i))
			}
		}
	case *ast.CallExpr:
		switch y := c.TypeOf(x.Fun).Underlying().(type) {
		case *types.Signature:
			c.onMethodCall(x, y)
		default:
			// type conversion
			if len(x.Args) == 1 {
				c.addUsed(x.Args[0], y)
			}
		}
	}
	return c
}

func compositeIdentType(t types.Type, i int) types.Type {
	switch x := t.(type) {
	case *types.Named:
		return compositeIdentType(x.Underlying(), i)
	case *types.Struct:
		return x.Field(i).Type()
	case *types.Array:
		return x.Elem()
	case *types.Slice:
		return x.Elem()
	}
	return nil
}

func (c *Checker) onMethodCall(ce *ast.CallExpr, sign *types.Signature) {
	for i, e := range ce.Args {
		paramObj, t := paramVarAndType(sign, i)
		// Don't if this is a parameter being re-used as itself
		// in a recursive call
		if id, ok := e.(*ast.Ident); ok {
			if paramObj == c.ObjectOf(id) {
				continue
			}
		}
		c.addUsed(e, t)
	}
	sel, ok := ce.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	// receiver func call on the left side
	if usage := c.varUsage(sel.X); usage != nil {
		usage.calls[sel.Sel.Name] = struct{}{}
	}
}

func (fd *funcDecl) paramGroups() [][]*types.Var {
	astList := fd.astDecl.Type.Params.List
	groups := make([][]*types.Var, len(astList))
	signIndex := 0
	for i, field := range astList {
		group := make([]*types.Var, len(field.Names))
		for j := range field.Names {
			group[j] = fd.ssaFn.Signature.Params().At(signIndex)
			signIndex++
		}
		groups[i] = group
	}
	return groups
}

func (c *Checker) packageIssues() []lint.Issue {
	var issues []lint.Issue
	for _, fd := range c.funcs {
		if _, e := c.discardFuncs[fd.ssaFn.Signature]; e {
			continue
		}
		for _, group := range fd.paramGroups() {
			issues = append(issues, c.groupIssues(fd, group)...)
		}
	}
	return issues
}

type Issue struct {
	pos token.Pos
	msg string
}

func (i Issue) Pos() token.Pos  { return i.pos }
func (i Issue) Message() string { return i.msg }

func (c *Checker) groupIssues(fd *funcDecl, group []*types.Var) []lint.Issue {
	var issues []lint.Issue
	for _, param := range group {
		usage := c.vars[param]
		if usage == nil {
			return nil
		}
		newType := c.paramNewType(fd.astDecl.Name.Name, param, usage)
		if newType == "" {
			return nil
		}
		issues = append(issues, Issue{
			pos: param.Pos(),
			msg: fmt.Sprintf("%s can be %s", param.Name(), newType),
		})
	}
	return issues
}

func willAddAllocation(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Pointer, *types.Interface:
		return false
	}
	return true
}

func (c *Checker) paramNewType(funcName string, param *types.Var, usage *varUsage) string {
	t := param.Type()
	if !ast.IsExported(funcName) && willAddAllocation(t) {
		return ""
	}
	if named := typeNamed(t); named != nil {
		tname := named.Obj().Name()
		vname := param.Name()
		if mentionsName(funcName, tname) || mentionsName(funcName, vname) {
			return ""
		}
	}
	ifname, iftype := c.interfaceMatching(param, usage)
	if ifname == "" {
		return ""
	}
	if types.IsInterface(t.Underlying()) {
		if have := funcMapString(typeFuncMap(t)); have == iftype {
			return ""
		}
	}
	return ifname
}

"""



```