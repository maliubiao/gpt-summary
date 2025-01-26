Response:
我的思考过程如下：

1. **理解目标：**  我的目标是分析给定的 Go 源代码片段（`types_test.go` 的一部分），并解释其功能，尤其是关于类型检查和解析方面的。  我需要识别它在做什么，并用示例代码和可能的错误用法来辅助解释。

2. **代码结构概览：** 首先，我浏览了代码，注意到了以下关键部分：
    * **`flag.Bool("test-stdlib", ...)`:**  这是一个命令行标志，表明可能有测试标准库的功能。
    * **`astVisitor` 类型和 `Visit` 方法:**  这表明代码使用了 Go 的 AST (抽象语法树) 来遍历代码结构。
    * **`parseDir` 函数:**  这个函数很可能负责解析目录中的 Go 代码并构建 AST。
    * **`checkExprs` 函数:**  这个函数是核心，它遍历 AST 并检查表达式的类型。  `ExprType` 函数是关键，它负责获取表达式的类型信息。
    * **`TestStdLib` 函数:**  这个函数使用 `filepath.Walk` 遍历标准库源代码目录，并对每个包调用 `checkExprs`，证实了对标准库进行测试的功能。
    * **`TestCompile` 函数:**  这个函数尝试将生成的代码写入文件，这可能用于验证生成的代码是否能编译。
    * **`TestOneFile` 函数和 `testExpr` 函数:**  这两个函数一起工作，解析一段测试代码（`testCode`），遍历其 AST，并使用 `ExprType` 检查特定表达式的类型。  `translateSymbols` 函数看起来用于修改 `testCode` 以便进行测试。
    * **`translateSymbols` 函数:** 这是一个重要的辅助函数，它修改测试代码，用特定的前缀（"xx"）标记符号，并在 `offsetMap` 中记录这些符号的信息（名称、偏移量、类型）。  这允许测试代码在不实际解析完整符号名称的情况下引用它们。
    * **`testCode` 变量:**  这是一个包含 Go 代码的字符串，用于 `TestOneFile` 测试。

3. **核心功能识别：**  通过分析代码结构，我确定了主要功能是 **类型检查和表达式解析**。  `checkExprs` 函数的目标是确定给定表达式的类型 (`ExprType`)。  `TestStdLib` 表明它能够对整个标准库进行这种检查。 `TestOneFile` 和相关的函数提供了一种更细粒度的测试机制，通过 `translateSymbols` 修改代码并断言特定表达式的类型信息。

4. **Go 语言功能推理：** 基于核心功能，我推断这个代码片段实现了 **获取 Go 语言表达式的类型信息** 的功能。  这通常是静态分析工具（如 `godef`）的核心需求。

5. **代码示例：** 为了说明这个功能，我需要展示如何使用 `ExprType` 函数。 我构造了一个简单的例子，展示了如何解析一段代码，获取一个标识符的 AST 节点，并调用 `ExprType` 来获取其类型信息。我添加了必要的导入和设置。

6. **代码推理 - `translateSymbols`：**  `translateSymbols` 函数比较复杂。我需要理解它的作用以及如何使用它。我注意到它使用 "xx" 前缀来标记符号，并使用 `@` 符号来指定符号的类型。  我推断它的目的是创建一个简化的测试环境，允许测试特定符号的类型解析，而无需编写完整的、可编译的 Go 代码。我举例说明了输入和输出，解释了 "xx_var@v" 会被转换成 "xx_var"，并且 `offsetMap` 会记录原始位置和类型信息。

7. **命令行参数：**  我注意到 `flag.Bool("test-stdlib", ...)`，这是一个用于控制是否运行标准库测试的命令行标志。 我解释了如何使用这个标志。

8. **易犯错误点：**  我思考了使用这个测试框架时可能出现的错误。 `translateSymbols` 的语法是一个潜在的陷阱，用户可能会忘记添加 `@` 符号或使用错误的类型字符。  我提供了一个例子来解释这个问题。

9. **组织和润色：** 最后，我将所有的分析结果组织成清晰的中文答案，包括功能概述、Go 语言功能说明、代码示例、`translateSymbols` 的推理、命令行参数说明和易犯错误点。  我确保语言简洁明了，并使用代码块和格式化来提高可读性。

通过这个逐步分析的过程，我能够理解代码的功能，并以清晰和全面的方式进行解释。  关键在于理解代码的结构、核心函数的作用，并将其与 Go 语言的特性（如 AST 和类型系统）联系起来。

这段代码是 Go 语言 `go/types` 包的一部分，用于测试类型检查和表达式求值的功能。 让我们分解一下它的主要功能：

**主要功能：测试 Go 代码中表达式的类型解析**

该文件主要用于测试 `go/types` 包的核心功能：给定 Go 语言的表达式，能否正确地推断出其类型信息（例如，它是哪个类型的变量、常量、函数等）。它通过解析 Go 源代码，构建抽象语法树 (AST)，然后利用 `ExprType` 函数来尝试解析 AST 中各种表达式的类型。

**更具体的功能点：**

1. **`TestStdLib` 函数：测试标准库的类型解析 (可选)。**
   - 通过命令行参数 `-test-stdlib` 启用。
   - 遍历 Go 安装目录下的 `src` 目录，解析标准库的源代码。
   - 对每个解析的包，调用 `checkExprs` 函数来检查所有表达式的类型解析是否正确。
   - 这是一个比较重量级的测试，因为标准库的代码量很大。

2. **`checkExprs` 函数：遍历 AST 并检查表达式的类型。**
   - 接收一个 AST 包 (`*ast.File`)，一个 `Importer` 接口的实现，以及一个 `token.FileSet`。
   - 使用 `ast.Walk` 函数遍历 AST 中的所有节点。
   - 针对不同类型的 AST 节点（例如 `ast.Ident`，`ast.SelectorExpr`），调用 `ExprType` 函数尝试获取其类型信息。
   - 如果 `ExprType` 返回 `nil` 并且该节点需要被解析 (例如，不是下划线 `_` 标识符)，则会报告一个错误。
   - 它还处理了一些特殊情况，例如跳过 `import .` 导入和为 `init` 函数添加对象。

3. **`TestCompile` 函数：生成测试代码并尝试编译 (通常被跳过)。**
   - 将 `testCode` 变量中的代码通过 `translateSymbols` 函数处理后写入 `/tmp/testcode.go` 文件。
   - 这允许开发者手动检查生成的代码是否符合预期，并且可以编译通过。

4. **`TestOneFile` 函数和 `testExpr` 函数：针对特定代码片段进行更精细的类型解析测试。**
   - `testCode` 变量包含一段用于测试的 Go 代码片段。
   - `translateSymbols` 函数会对 `testCode` 进行预处理，方便测试。
   - `TestOneFile` 函数解析 `testCode`，然后使用 `identVisitor` 遍历 AST 中的标识符和选择器表达式。
   - 对于每个找到的表达式，调用 `testExpr` 函数进行断言：
     - 确保能够找到该表达式对应的对象 (`ExprType` 不为 `nil`)。
     - 确保能够找到该表达式的类型 (`typ.Kind` 不为 `ast.Bad`)。
     - 比较找到的对象的名称是否与表达式的名称一致。
     - 比较找到的对象的声明位置是否与 `translateSymbols` 函数记录的位置一致。
     - 比较找到的对象的类型种类是否与 `translateSymbols` 函数记录的类型种类一致。

5. **`translateSymbols` 函数：预处理测试代码，用于更精确的类型解析测试。**
   - 接收一段 Go 代码 (`[]byte`) 作为输入。
   - 它的主要目的是为了在测试代码中标记需要测试的符号，并记录这些符号的原始位置和类型信息。
   - 它会查找以 "xx" 开头的符号。
   - 如果符号后面跟着 `@` 和一个类型字符（例如 `v` 表示变量，`t` 表示类型），则记录该符号的信息。
   - 返回处理后的代码和 `offsetMap`，`offsetMap` 存储了原始代码中标记符号的位置和类型信息。
   - 例如，`xx_var@v` 会被转换为 `xx_var`，并在 `offsetMap` 中记录 `xx_var` 首次出现的位置和类型为变量。后续对 `xx_var` 的引用会使用 `offsetMap` 中的信息进行验证。

6. **`identVisitor` 类型：用于遍历 AST 并查找特定的标识符。**
   - 它是一个实现了 `ast.Visitor` 接口的类型。
   - 它会查找以 "xx" 开头的标识符和选择器表达式，并将它们发送到一个 channel 中。

**它是什么 Go 语言功能的实现？**

这个文件主要用于测试 **Go 语言的类型系统和类型推断功能** 的实现。 更具体地说，它测试了 `go/types` 包中用于确定表达式类型的核心逻辑。 `ExprType` 函数是这个测试的核心，它模拟了 Go 编译器在编译时进行类型检查的过程。

**Go 代码示例：**

假设我们有以下简单的 Go 代码：

```go
package main

import "fmt"

var globalInt int = 10

func main() {
	localVar := 5
	result := globalInt + localVar
	fmt.Println(result)
}
```

`go/types` 包的功能（`ExprType` 函数）就是能够分析像 `globalInt`, `localVar`, `globalInt + localVar` 这样的表达式，并确定它们的类型分别是 `int`, `int`, 和 `int`。

**假设的输入与输出 (针对 `testExpr` 函数)：**

假设 `testCode` 中有如下片段：

```go
var xx_myVar@v int
func main() {
  _ = xx_myVar
}
```

- **假设输入 (在 `testExpr` 中)：**
    - `e`: 指向 `xx_myVar` 标识符的 `ast.Ident` 节点。
    - `offsetMap`: 包含 `xx_myVar` 的信息，例如它的偏移量和类型 (`ast.Var`)。

- **预期输出 (在 `testExpr` 中)：**
    - `ExprType(e, DefaultImporter, fset)` 应该返回一个 `*types.Var` 对象，其名称为 "xx_myVar"，类型为 `int`。
    - `DeclPos(obj)` 应该返回 `xx_myVar` 声明的位置，该位置应该与 `offsetMap` 中记录的偏移量一致。
    - `typ.Kind` 应该等于 `ast.Var`。

**命令行参数的具体处理：**

- `-test-stdlib`:  这是一个布尔类型的 flag。
    - 如果在运行测试时指定了 `-test-stdlib`，那么 `*testStdlib` 变量的值将为 `true`，`TestStdLib` 函数会被执行，从而测试标准库的类型解析。
    - 如果没有指定该 flag，`*testStdlib` 变量的值将为 `false`，`TestStdLib` 函数会直接 `SkipNow()`，跳过标准库的测试。

**使用者易犯错的点 (针对 `translateSymbols`)：**

1. **忘记添加类型标记 `@`：**  如果开发者在 `testCode` 中使用了 "xx" 前缀的符号，但忘记在首次声明时添加 `@` 和类型字符，`translateSymbols` 函数会抛出 panic。
   ```go
   // 错误示例：缺少 @v
   var xx_myVar int

   // 正确示例
   var xx_myVar@v int
   ```

2. **使用了错误的类型字符：** `translateSymbols` 中预定义了一些类型字符 (`kinds` map)，如果使用了未定义的字符，也会导致 panic。
   ```go
   // 错误示例：使用了未定义的类型字符 'x'
   var xx_myVar@x int

   // 正确示例
   var xx_myVar@v int
   ```

总而言之，这段代码是 `go/types` 包进行自我测试的关键部分，它专注于验证类型解析的正确性，特别是通过 `translateSymbols` 函数，它提供了一种精巧的方式来针对特定的代码模式和符号进行细粒度的测试。

Prompt: 
```
这是路径为go/src/github.com/rogpeppe/godef/go/types/types_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package types

import (
	"bytes"
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/rogpeppe/godef/go/ast"
	"github.com/rogpeppe/godef/go/parser"
	"github.com/rogpeppe/godef/go/token"
)

var testStdlib = flag.Bool("test-stdlib", false, "test all symbols in standard library (will fail)")

// TODO recursive types avoiding infinite loop.
// e.g.
// type A struct {*A}
// func (a *A) Foo() {
// }
// var x *A

type astVisitor func(n ast.Node) bool

func (f astVisitor) Visit(n ast.Node) ast.Visitor {
	if f(n) {
		return f
	}
	return nil
}

func parseDir(dir string) *ast.Package {
	pkgs, _ := parser.ParseDir(FileSet, dir, isGoFile, 0, DefaultImportPathToName)
	if len(pkgs) == 0 {
		return nil
	}
	delete(pkgs, "documentation")
	for name, pkg := range pkgs {
		if len(pkgs) == 1 || name != "main" {
			return pkg
		}
	}
	return nil
}

func checkExprs(t *testing.T, pkg *ast.File, importer Importer, fset *token.FileSet) {
	var visit astVisitor
	stopped := false
	visit = func(n ast.Node) bool {
		if stopped {
			return false
		}
		mustResolve := false
		var e ast.Expr
		switch n := n.(type) {
		case *ast.ImportSpec:
			// If the file imports a package to ".", abort
			// because we don't support that (yet).
			if n.Name != nil && n.Name.Name == "." {
				stopped = true
				return false
			}
			return true

		case *ast.FuncDecl:
			// add object for init functions
			if n.Recv == nil && n.Name.Name == "init" {
				n.Name.Obj = ast.NewObj(ast.Fun, "init")
			}
			return true

		case *ast.Ident:
			if n.Name == "_" {
				return false
			}
			e = n
			mustResolve = true

		case *ast.KeyValueExpr:
			// don't try to resolve the key part of a key-value
			// because it might be a map key which doesn't
			// need resolving, and we can't tell without being
			// complicated with types.
			ast.Walk(visit, n.Value)
			return false

		case *ast.SelectorExpr:
			ast.Walk(visit, n.X)
			e = n
			mustResolve = true

		case *ast.File:
			for _, d := range n.Decls {
				ast.Walk(visit, d)
			}
			return false

		case ast.Expr:
			e = n

		default:
			return true
		}
		defer func() {
			if err := recover(); err != nil {
				t.Fatalf("panic (%v) on %T", err, e)
				//t.Fatalf("panic (%v) on %v at %v\n", err, e, FileSet.Position(e.Pos()))
			}
		}()
		obj, _ := ExprType(e, importer, fset)
		if obj == nil && mustResolve {
			t.Errorf("no object for %v(%p, %T) at %v\n", e, e, e, FileSet.Position(e.Pos()))
		}
		return false
	}
	ast.Walk(visit, pkg)
}

func TestStdLib(t *testing.T) {
	if !*testStdlib {
		t.SkipNow()
	}
	Panic = false
	defer func() {
		Panic = true
	}()
	root := os.Getenv("GOROOT") + "/src"
	cache := make(map[string]*ast.Package)
	importer := func(path, srcDir string) *ast.Package {
		p := filepath.Join(root, "pkg", path)
		if pkg := cache[p]; pkg != nil {
			return pkg
		}
		pkg := DefaultImporter(path, srcDir)
		cache[p] = pkg
		return pkg
	}
	//	excluded := map[string]bool{
	//		filepath.Join(root, "pkg/exp/wingui"): true,
	//	}
	visit := func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !f.IsDir() {
			return nil
		}
		pkg := cache[path]
		if pkg == nil {
			pkg = parseDir(path)
		}
		if pkg != nil {
			for _, f := range pkg.Files {
				checkExprs(t, f, importer, FileSet)
			}
		}
		return nil
	}

	filepath.Walk(root, visit)
}

// TestCompile writes the test code to /tmp/testcode.go so
// that it can be verified that it actually compiles.
func TestCompile(t *testing.T) {
	return // avoid usually
	code, _ := translateSymbols(testCode)
	err := ioutil.WriteFile("/tmp/testcode.go", code, 0666)
	if err != nil {
		t.Errorf("write file failed: %v", err)
	}
}

func TestOneFile(t *testing.T) {
	code, offsetMap := translateSymbols(testCode)
	//fmt.Printf("------------------- {%s}\n", code)
	f, err := parser.ParseFile(FileSet, "xx.go", code, 0, ast.NewScope(parser.Universe), DefaultImportPathToName)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	v := make(identVisitor)
	go func() {
		ast.Walk(v, f)
		close(v)
	}()
	for e := range v {
		testExpr(t, FileSet, e, offsetMap)
	}
}

func testExpr(t *testing.T, fset *token.FileSet, e ast.Expr, offsetMap map[int]*sym) {
	var name *ast.Ident
	switch e := e.(type) {
	case *ast.SelectorExpr:
		name = e.Sel
	case *ast.Ident:
		name = e
	default:
		panic("unexpected expression type")
	}
	from := fset.Position(name.NamePos)
	obj, typ := ExprType(e, DefaultImporter, fset)
	if obj == nil {
		t.Errorf("no object found for %v at %v", pretty{e}, from)
		return
	}
	if typ.Kind == ast.Bad {
		t.Errorf("no type found for %v at %v", pretty{e}, from)
		return
	}
	if name.Name != obj.Name {
		t.Errorf("wrong name found for %v at %v; expected %q got %q", pretty{e}, from, name, obj.Name)
		return
	}
	to := offsetMap[from.Offset]
	if to == nil {
		t.Errorf("no source symbol entered for %s at %v", name.Name, from)
		return
	}
	found := fset.Position(DeclPos(obj))
	if found.Offset != to.offset {
		t.Errorf("wrong offset found for %v at %v, decl %T (%#v); expected %d got %d", pretty{e}, from, obj.Decl, obj.Decl, to.offset, found.Offset)
	}
	if typ.Kind != to.kind {
		t.Errorf("wrong type for %s at %v; expected %v got %v", name.Name, from, to.kind, typ.Kind)
	}
}

type identVisitor chan ast.Expr

func (v identVisitor) Visit(n ast.Node) ast.Visitor {
	switch n := n.(type) {
	case *ast.Ident:
		if strings.HasPrefix(n.Name, prefix) {
			v <- n
		}
		return nil
	case *ast.SelectorExpr:
		ast.Walk(v, n.X)
		if strings.HasPrefix(n.Sel.Name, prefix) {
			v <- n
		}
		return nil
	}
	return v
}

const prefix = "xx"

var kinds = map[rune]ast.ObjKind{
	'v': ast.Var,
	'c': ast.Con,
	't': ast.Typ,
	'f': ast.Fun,
	'l': ast.Lbl,
}

type sym struct {
	name   string
	offset int
	kind   ast.ObjKind
}

// transateSymbols performs a non-parsing translation of some Go source
// code. For each symbol starting with xx, it returns an entry in
// offsetMap mapping from the reference in the source code to the first
// occurrence of that symbol. If the symbol is followed by #x, it refers
// to a particular version of the symbol. The translated code will
// produce only the bare symbol, but the expected symbol can be
// determined from the returned map.
//
// The first occurrence of a translated symbol must be followed by a @
// and letter representing the symbol kind (see kinds, above). All
// subsequent references to that symbol must resolve to the given kind.
//
func translateSymbols(code []byte) (result []byte, offsetMap map[int]*sym) {
	offsetMap = make(map[int]*sym)
	buf := bytes.NewBuffer(code)
	syms := make(map[string]*sym)
	var wbuf, sbuf bytes.Buffer
	for {
		r, _, err := buf.ReadRune()
		if err != nil {
			break
		}
		if r != rune(prefix[0]) {
			wbuf.WriteRune(r)
			continue
		}
		sbuf.Reset()
		for unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '#' {
			sbuf.WriteRune(r)
			r, _, err = buf.ReadRune()
			if err != nil {
				break
			}
		}
		var typec rune
		if r == '@' {
			typec, _, err = buf.ReadRune()
		} else {
			buf.UnreadRune()
		}
		name := sbuf.String()
		if !strings.HasPrefix(name, prefix) {
			sbuf.WriteString(name)
			continue
		}
		bareName := name
		if i := strings.IndexRune(bareName, '#'); i >= 0 {
			bareName = bareName[:i]
		}
		s := syms[name]
		if s == nil {
			if typec == 0 {
				panic("missing type character for symbol: " + name)
			}
			s = &sym{name, wbuf.Len(), kinds[typec]}
			if s.kind == ast.Bad {
				panic("bad type character " + string(typec))
			}
			syms[name] = s
		}
		offsetMap[wbuf.Len()] = s
		wbuf.WriteString(bareName)
	}
	result = wbuf.Bytes()
	return
}

var testCode = []byte(
	`package main

import "os"

type xx_struct@t struct {
	xx_1@v int
	xx_2@v int
}

type xx_link@t struct {
	xx_3@v    int
	xx_next@v *xx_link
}

type xx_structEmbed@t struct {
	xx_struct#f@v
}

type xx_interface@t interface {
	xx_value#i@f()
}

type xx_interfaceAndMethod#t@t interface {
	xx_interfaceAndMethod#i@f()
}

type xx_interfaceEmbed@t interface {
	xx_interface
	xx_interfaceAndMethod#t
}

type xx_int@t int

func (xx_int) xx_k@f() {}

const (
	xx_inta@c, xx_int1@c = xx_int(iota), xx_int(iota * 2)
	xx_intb@c, xx_int2@c
	xx_intc@c, xx_int3@c
)

var fd1 = os.Stdin

func (xx_4@v *xx_struct) xx_ptr@f()  {
	_ = xx_4.xx_1
}
func (xx_5@v xx_struct) xx_value#s@f() {
	_ = xx_5.xx_2
}

func (s xx_structEmbed) xx_value#e@f() {}

type xx_other@t bool
func (xx_other) xx_value#x@f() {}

type xx_alias@t = xx_other

var xxv_int@v xx_int

var xx_chan@v chan xx_struct
var xx_map@v map[string]xx_struct
var xx_slice@v []xx_int

var (
	xx_func@v func() xx_struct
	xx_mvfunc@v func() (string, xx_struct, xx_struct)
	xxv_interface@v interface{}
)
var xxv_link@v *xx_link

func xx_foo@f(xx_int) xx_int {
	return 0
}

func main() {

	fd := os.NewFile(1, "/dev/stdout")
	_, _ = fd.Write(nil)
	fd1.Write(nil)

	_ = (<-xx_chan).xx_1
	xx_structv@v := <-xx_chan
	_ = xx_struct
	tmp, _ := <-xx_chan
	_ = tmp.xx_1

	_ = xx_map[""].xx_1
	_ = xx_slice[xxv_int:xxv_int:xxv_int]

	xx_a2@v, _ := xx_map[""]
	_ = xx_a2.xx_2

	_ = xx_func().xx_1

	xx_c@v, xx_d@v, xx_e@v := xx_mvfunc()
	_ = xx_d.xx_2
	_ = xx_e.xx_1

	xx_f@v := func() xx_struct { return xx_struct{} }
	_ = xx_f().xx_2

	xx_g@v := xxv_interface.(xx_struct).xx_1
	xx_h@v, _ := xxv_interface.(xx_struct)
	_ = xx_h.xx_2

	var xx_6@v xx_interface = xx_struct{}

	switch xx_i@v := xx_6.(type) {
	case xx_struct, xx_structEmbed:
		xx_i.xx_value#i()
	case xx_interface:
		xx_i.xx_value#i()
	case xx_other:
		xx_i.xx_value#x()
	}
	var xx_iembed@v xx_interfaceEmbed
	xx_iembed.xx_value#i()
	xx_iembed.xx_interfaceAndMethod#i()

	var xx_ialiasvar@v xx_alias
	xx_ialiasvar.xx_value#x()

	xx_map2@v := make(map[xx_int]xx_struct)
	for xx_a@v, xx_b@v := range xx_map2 {
		xx_a.xx_k()
		_ = xx_b.xx_2
	}
	for xx_a3@v := range xx_map2 {
		xx_a3.xx_k()
	}

	for xx_a4@v := range xx_chan {
		_ = xx_a4.xx_1
	}

	xxv_struct@v := new(xx_struct)
	_ = xxv_struct.xx_1

	var xx_1e@v xx_structEmbed
	xx_1e.xx_value#e()
	xx_1e.xx_ptr()
	_ = xx_1e.xx_struct#f

	var xx_2e@v xx_struct
	xx_2e.xx_value#s()
	xx_2e.xx_ptr()

	xxv_int.xx_k()
	xx_inta.xx_k()
	xx_intb.xx_k()
	xx_intc.xx_k()
	xx_int1.xx_k()
	xx_int2.xx_k()
	xx_int3.xx_k()

	xxa@v := []xx_int{1, 2, 3}
	xxa[0].xx_k()

	xxp@v := new(int)
	(*xx_int)(xxp).xx_k()
	var xx_label#v@v xx_struct

xx_label#l@l:
	xx_foo(5).xx_k()

	goto xx_label#l
	_ = xx_label#v.xx_1

	_ = xxv_link.xx_next.xx_next.xx_3

	type xx_internalType@t struct {
		xx_7@v xx_struct
	}
	xx_intern@v := xx_internalType{}
	_ = xx_intern.xx_7.xx_1

	use(xx_c, xx_d, xx_e, xx_f, xx_g, xx_h)
}


func xx_varargs@f(xx_args@v ... xx_struct) {
	_ = xx_args[0].xx_1
}

func use(...interface{}) {}
`)

"""



```