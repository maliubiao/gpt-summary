Response:
Let's break down the thought process to answer the request about the `types.go` file.

**1. Initial Understanding & Goal:**

The core request is to analyze the provided Go code snippet (`types.go`) and describe its functionality, identify the Go feature it implements, provide code examples, discuss command-line arguments (if any), and highlight potential pitfalls. The target audience is someone familiar with Go but perhaps not the internal workings of tools like `godef`.

**2. High-Level Overview (Skimming the Code):**

The first step is to skim the code to get a general idea of its purpose. Keywords and structural elements immediately jump out:

* **Package `types`:** This suggests the code deals with type information.
* **`Type` struct:**  This is a central data structure, likely representing the type of a Go expression. The fields (`Node`, `Kind`, `Pkg`) give clues about what information is stored.
* **`MultiValue` struct:** This likely handles functions returning multiple values.
* **`ExprType` function:** This strongly suggests the core functionality of determining the type of an expression.
* **`Member`, `Iter` functions:**  These hint at the ability to inspect the members (fields, methods, etc.) of a type.
* **Imports like `go/ast`, `go/parser`, `go/token`:**  These confirm the code works with the Go abstract syntax tree, meaning it's involved in static analysis of Go code.
* **`DefaultImporter`:**  This indicates how the code resolves package imports.
* **`Debug` variable:**  This suggests debugging/logging capabilities.

**3. Deeper Dive into Key Functionality:**

Now, let's examine the more important parts in detail:

* **`Type` struct:**  The comments explain it represents the type of a Go expression, a package, or a Go type. The fields store the AST node representing the type, the kind of object, and the package path.
* **`ExprType` function:**  This function takes an `ast.Expr`, an `Importer`, and a `token.FileSet` as input and returns an `ast.Object` and a `Type`. This confirms its role in determining the type of an expression. The `exprTypeContext` struct suggests a context is needed during the type inference process.
* **The `switch` statement inside `exprType`:** This is the heart of the type inference logic. It handles different kinds of Go expressions (identifiers, literals, function calls, etc.) and attempts to determine their types.
* **`Member` and `Iter`:** These functions operate on a `Type` and allow access to its members. `Member` finds a specific member by name, while `Iter` returns a channel of all members.
* **`DefaultImporter`:**  This function uses `go/build` to find packages and `go/parser` to parse them. It manages the `FileSet`.

**4. Identifying the Go Feature:**

Based on the analysis, the code's primary function is **static type analysis** or **type inference** for Go code. It allows you to determine the type of an expression without actually executing the code. This is a crucial component of tools that provide code navigation, refactoring, and error detection.

**5. Creating Code Examples:**

To illustrate the functionality, we need examples of how someone might *use* this code (or a tool built on top of it). Since the provided code is a library, the examples will be conceptual, demonstrating what the functions achieve:

* **Getting the type of a variable:**  Show how `ExprType` would determine the type of a declared variable.
* **Getting the type of a function call:**  Illustrate how `ExprType` handles function calls and return types.
* **Accessing members of a struct:** Demonstrate how `Member` or iterating through the channel returned by `Iter` can reveal the fields of a struct.
* **Accessing members of an interface:** Show how methods of an interface are accessed.

**6. Command-Line Arguments:**

The code itself doesn't directly handle command-line arguments. However, because it's part of the `godef` tool, it's important to mention how *that* tool uses command-line arguments to specify the file and position for analysis.

**7. Potential Pitfalls:**

Think about common mistakes users of such a tool might make:

* **Incorrect file and offset:**  Providing the wrong location will lead to incorrect results.
* **Unsaved changes:**  The tool analyzes the code on disk, so unsaved changes won't be reflected.
* **Build errors:** If the code has syntax errors or type errors that prevent parsing, the tool might not work correctly.

**8. Structuring the Answer:**

Organize the information logically using the prompts in the request:

* **Functionality:** Start with a concise summary of the code's purpose.
* **Go Feature:** Clearly identify the Go feature it implements.
* **Code Examples:** Provide illustrative Go code snippets and explain the expected input and output (even if it's conceptual).
* **Command-Line Arguments:** Describe how `godef` (the likely user of this code) uses command-line arguments.
* **Common Mistakes:**  List potential errors users might encounter.

**9. Refinement and Language:**

Finally, review and refine the answer. Ensure clarity, accuracy, and use appropriate terminology. Use Chinese as requested in the prompt. For example, translate key terms like "type inference," "abstract syntax tree," etc.

By following these steps, we can systematically analyze the code and provide a comprehensive and helpful answer to the request. The process involves understanding the code's structure, identifying its core functions, connecting it to relevant Go concepts, and thinking about how it would be used in practice.
这段代码是 Go 语言工具 `godef` 中 `go/types` 包的一部分，它的主要功能是**对 Go 语言表达式进行静态类型推断，并允许枚举类型的成员（字段或方法）**。

更具体地说，它实现了以下功能：

1. **类型表示 (`Type` 结构体):** 定义了一个 `Type` 结构体，用于表示 Go 表达式的类型，包括基本类型、复合类型、包以及类型定义等。它包含了类型对应的抽象语法树节点 (`ast.Node`)，对象的种类 (`ast.ObjKind`)，以及类型所属的包路径 (`Pkg`)。

2. **多返回值表示 (`MultiValue` 结构体):**  定义了 `MultiValue` 结构体，用于表示返回多个值的函数调用的结果。

3. **内置标识符预定义:**  预定义了一些内置的 Go 标识符，例如 `make`, `new`, `true`, `false`, `bool`, `int`, `string` 等。

4. **包导入 (`Importer` 类型和 `DefaultImporter` 函数):**
   - 定义了一个 `Importer` 函数类型，用于抽象包的导入过程。
   - 提供了 `DefaultImporter` 函数，实现了默认的包导入逻辑。它使用 `go/build` 包查找包，并使用 `go/parser` 包解析包中的 Go 源代码文件。`FileSet` 变量用于管理解析过程中的文件集合。

5. **表达式类型推断 (`ExprType` 函数和 `exprTypeContext` 结构体):**
   - 核心功能是由 `ExprType` 函数实现的。它接收一个 `ast.Expr` (Go 表达式的抽象语法树节点)、一个 `Importer` 和一个 `token.FileSet` 作为输入，返回表达式对应的对象 (`ast.Object`) 和类型 (`Type`)。
   - `exprTypeContext` 结构体用于存储类型推断的上下文信息，例如 `Importer` 和 `FileSet`。
   - `exprTypeContext` 的 `exprType` 方法是实际进行类型推断的递归函数，它根据不同类型的表达式节点 (例如 `ast.Ident`、`ast.CallExpr`、`ast.SelectorExpr` 等) 执行相应的类型推断逻辑。

6. **成员查找 (`Member` 函数):**  `Type` 结构体的 `Member` 方法允许查找给定类型中的指定名称的成员（字段、方法或包级别的导出声明）。对于包类型，它可以查找包中导出的顶层声明。

7. **成员迭代 (`Iter` 函数):**  `Type` 结构体的 `Iter` 方法返回一个 channel，该 channel 会发送类型的所有成员。它使用广度优先搜索的方式遍历类型的成员。

8. **底层类型获取 (`Underlying` 函数):** `Type` 结构体的 `Underlying` 方法用于获取命名类型的底层类型。如果 `all` 参数为 true，则会一直追溯到非命名类型为止。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 Go 语言的**静态类型系统**的核心部分，特别是**类型推断**和**反射的基础设施**。 虽然它不完全是 `reflect` 标准库的实现，但它提供了构建类似 `reflect` 功能的底层能力，允许在编译时对代码的类型信息进行分析。

**Go 代码举例说明:**

假设我们有以下 Go 代码：

```go
package main

import "fmt"

type MyInt int

type MyStruct struct {
	Field1 int
	Field2 string
}

func (ms *MyStruct) MyMethod() {
	fmt.Println("Hello from MyMethod")
}

func add(a, b int) int {
	return a + b
}

var globalVar int = 10

func main() {
	var x int = 5
	var y MyInt = 20
	z := "hello"
	ms := MyStruct{Field1: 1, Field2: "world"}
	fmt.Println(add(x, int(y)))
	ms.MyMethod()
	fmt.Println(globalVar)
}
```

如果我们使用 `godef/go/types/types.go` 中的功能，可以推断出以下信息（这里只是概念性演示，实际使用需要结合 `go/parser` 等将代码解析成 AST）：

**假设输入：** 我们有一个表示 `main` 包的 `ast.Package`，并且想推断变量 `x` 的类型。

**代码示例 (概念性):**

```go
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"path/filepath"

	"github.com/rogpeppe/godef/go/types"
)

func main() {
	fset := token.NewFileSet()
	filename := "main.go" // 假设上面的代码保存在 main.go 文件中
	src := `
package main

import "fmt"

type MyInt int

type MyStruct struct {
	Field1 int
	Field2 string
}

func (ms *MyStruct) MyMethod() {
	fmt.Println("Hello from MyMethod")
}

func add(a, b int) int {
	return a + b
}

var globalVar int = 10

func main() {
	var x int = 5
	var y MyInt = 20
	z := "hello"
	ms := MyStruct{Field1: 1, Field2: "world"}
	fmt.Println(add(x, int(y)))
	ms.MyMethod()
	fmt.Println(globalVar)
}
`

	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		log.Fatal(err)
	}

	// 假设我们找到了表示变量 'x' 的 *ast.Ident 节点
	var xIdent *ast.Ident
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "x" {
			xIdent = id
			return false // 找到后停止遍历
		}
		return true
	})

	if xIdent == nil {
		log.Fatal("Could not find identifier 'x'")
	}

	importer := func(path string, srcDir string) *ast.Package {
		if path == "fmt" {
			// 模拟导入 fmt 包
			fset := token.NewFileSet()
			file, _ := parser.ParseFile(fset, filepath.Join(srcDir, "fmt.go"), `package fmt; func Println(a ...interface{}) (n int, err error) {}`, 0)
			return &ast.Package{Name: "fmt", Files: map[string]*ast.File{"fmt.go": file}, Scope: file.Scope}
		}
		return nil
	}

	obj, typ := types.ExprType(xIdent, importer, fset)

	fmt.Printf("变量 '%s' 的类型信息:\n", xIdent.Name)
	fmt.Printf("  Kind: %v\n", obj.Kind)
	fmt.Printf("  Type: %v\n", typ)
	fmt.Printf("  Type Node: %T\n", typ.Node) // *ast.Ident

	// 推断函数调用 add(x, int(y)) 的返回类型
	var addCall *ast.CallExpr
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if fun, ok := call.Fun.(*ast.Ident); ok && fun.Name == "add" {
				addCall = call
				return false
			}
		}
		return true
	})

	if addCall != nil {
		addObj, addType := types.ExprType(addCall, importer, fset)
		fmt.Printf("\n函数调用 'add(x, int(y))' 的类型信息:\n")
		fmt.Printf("  Kind: %v\n", addObj.Kind) // 通常是 ast.Fun
		fmt.Printf("  Type: %v\n", addType)
		// 对于函数调用，Type.Node 通常是 *ast.FuncType
	}

	// 获取 MyStruct 类型的成员
	var myStructType *ast.TypeSpec
	ast.Inspect(f, func(n ast.Node) bool {
		if ts, ok := n.(*ast.TypeSpec); ok && ts.Name.Name == "MyStruct" {
			myStructType = ts
			return false
		}
		return true
	})

	if myStructType != nil {
		_, structType := types.ExprType(myStructType.Name, importer, fset)
		fmt.Println("\nMyStruct 类型的成员:")
		for member := range structType.Iter() {
			fmt.Printf("  Name: %s, Kind: %v\n", member.Name, member.Kind)
		}
	}
}
```

**假设输出:**

```
变量 'x' 的类型信息:
  Kind: var
  Type: Type{Var "" *ast.Ident {50 /Users/you/main.go int}}
  Type Node: *ast.Ident

函数调用 'add(x, int(y))' 的类型信息:
  Kind: func
  Type: Type{Fun "" *ast.FuncType {145 func (a int, b int) int}}

MyStruct 类型的成员:
  Name: Field1, Kind: field
  Name: Field2, Kind: field
  Name: MyMethod, Kind: func
```

**涉及命令行参数的具体处理:**

这段代码本身是一个库，并不直接处理命令行参数。但是，`godef` 工具（使用了这个库）会接收命令行参数来指定要分析的代码位置。

典型的 `godef` 命令如下：

```bash
godef -f <文件名> -o <字节偏移量>
```

- `-f <文件名>`：指定要分析的 Go 源代码文件的路径。
- `-o <字节偏移量>`：指定光标在文件中的字节偏移量。`godef` 会根据这个偏移量找到对应的标识符或表达式。

`godef` 工具内部会使用 `go/parser` 解析指定的文件，然后使用 `go/types` 包中的功能，根据提供的偏移量处的标识符或表达式，推断其类型并找到其定义的位置。

**使用者易犯错的点:**

1. **文件路径不正确:**  如果 `-f` 参数指定的文件路径不存在或不正确，`godef` 将无法找到要分析的代码。

2. **字节偏移量不正确:** `-o` 参数指定的字节偏移量必须精确对应到想要分析的标识符或表达式的位置。偏移量错误会导致 `godef` 找不到目标或者找到错误的符号。可以使用编辑器或工具查看文件的字节偏移量。

3. **代码未保存:** 如果在编辑器中修改了代码但未保存，`godef` 分析的是磁盘上的旧版本文件，可能导致结果不准确。

4. **依赖包未安装或路径配置错误:** 如果要分析的代码依赖于未安装或路径配置不正确的包，`DefaultImporter` 可能无法正确加载这些包，导致类型推断失败。Go 的 `GOPATH` 或模块系统配置需要正确。

5. **分析构建失败的代码:** 如果要分析的代码存在编译错误，`go/parser` 可能无法正确解析代码，从而导致 `go/types` 无法进行类型推断。在运行 `godef` 之前，最好确保代码可以正常编译。

**示例说明易犯错的点:**

假设 `main.go` 文件内容如下，但我们故意在编辑器中修改了 `var x int = 5` 为 `var x string = "hello"` 但没有保存。

当我们执行 `godef -f main.go -o <指向 'x' 的旧偏移量>` 时，`godef` 可能会仍然认为 `x` 的类型是 `int`，因为它读取的是磁盘上未保存的旧版本文件。

另一个例子，如果 `import "some/nonexistent/package"` 出现在代码中，并且该包没有安装或 `GOPATH` 设置不正确，`DefaultImporter` 将返回 `nil`，导致与该包相关的类型推断失败。

Prompt: 
```
这是路径为go/src/github.com/rogpeppe/godef/go/types/types.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Types infers source locations and types from Go expressions.
// and allows enumeration of the type's method or field members.
package types

import (
	"bytes"
	"container/list"
	"fmt"
	"go/build"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/rogpeppe/godef/go/ast"
	"github.com/rogpeppe/godef/go/parser"
	"github.com/rogpeppe/godef/go/printer"
	"github.com/rogpeppe/godef/go/scanner"
	"github.com/rogpeppe/godef/go/token"
)

// Type represents the type of a Go expression.
// It can represent a Go package and a Go type as well as the
// usual expression types.
//
type Type struct {
	// Parse-tree representation of the expression's type.
	Node ast.Node

	// The kind of the expression.
	Kind ast.ObjKind

	// The path of the package that the type is relative to.
	Pkg string

	// exprTypeContext holds the context that was used
	// to create the type.
	ctxt *exprTypeContext
}

// MultiValue represents a multiple valued Go
// expression - the result of a function that returns
// more than one value.
type MultiValue struct {
	Types []ast.Expr
}

func (MultiValue) Pos() token.Pos {
	return token.NoPos
}
func (MultiValue) End() token.Pos {
	return token.NoPos
}

var badType = Type{Kind: ast.Bad}

var makeIdent = predecl("make")
var newIdent = predecl("new")
var falseIdent = predecl("false")
var trueIdent = predecl("true")
var iotaIdent = predecl("iota")
var boolIdent = predecl("bool")
var intIdent = predecl("int")
var floatIdent = predecl("float")
var stringIdent = predecl("string")

func predecl(name string) *ast.Ident {
	return &ast.Ident{Name: name, Obj: parser.Universe.Lookup(name)}
}

type Importer func(path string, srcDir string) *ast.Package

// When DefaultImporter is called, it adds any files to FileSet.
var FileSet = token.NewFileSet()

// DefaultImporter looks for the package; if it finds it,
// it parses and returns it. If no package was found, it returns nil.
func DefaultImporter(path string, srcDir string) *ast.Package {
	bpkg, err := build.Default.Import(path, srcDir, 0)
	if err != nil {
		return nil
	}
	goFiles := make(map[string]bool)
	for _, f := range bpkg.GoFiles {
		goFiles[f] = true
	}
	for _, f := range bpkg.CgoFiles {
		goFiles[f] = true
	}
	shouldInclude := func(d os.FileInfo) bool {
		return goFiles[d.Name()]
	}
	pkgs, err := parser.ParseDir(FileSet, bpkg.Dir, shouldInclude, 0, DefaultImportPathToName)
	if err != nil {
		if Debug {
			switch err := err.(type) {
			case scanner.ErrorList:
				for _, e := range err {
					debugp("\t%v: %s", e.Pos, e.Msg)
				}
			default:
				debugp("\terror parsing %s: %v", bpkg.Dir, err)
			}
		}
		return nil
	}
	if pkg := pkgs[bpkg.Name]; pkg != nil {
		return pkg
	}
	if Debug {
		debugp("package not found by ParseDir!")
	}
	return nil
}

// DefaultImportPathToName returns the package identifier
// for the given import path.
func DefaultImportPathToName(path, srcDir string) (string, error) {
	if path == "C" {
		return "C", nil
	}
	pkg, err := build.Default.Import(path, srcDir, 0)
	return pkg.Name, err
}

// isGoFile returns true if we will consider the file as a
// possible candidate for parsing as part of a package.
// Including _test.go here isn't quite right, but what
// else can we do?
//
func isGoFile(d os.FileInfo) bool {
	return strings.HasSuffix(d.Name(), ".go") &&
		!strings.HasSuffix(d.Name(), "_test.go") &&
		!strings.HasPrefix(d.Name(), ".") &&
		goodOSArch(d.Name())
}

// When Debug is true, log messages will be printed.
var Debug = false

// String is for debugging purposes.
func (t Type) String() string {
	return fmt.Sprintf("Type{%v %q %T %v}", t.Kind, t.Pkg, t.Node, pretty{t.Node})
}

var Panic = true

// Member looks for a member with the given name inside
// the type. For packages, the member can be any exported
// top level declaration inside the package.
func (t Type) Member(name string) *ast.Object {
	debugp("member %v '%s' {", t, name)
	if t.Pkg != "" && !ast.IsExported(name) {
		return nil
	}
	c := make(chan *ast.Object)
	go func() {
		if !Panic {
			defer func() {
				if err := recover(); err != nil {
					log.Printf("panic: %v", err)
					c <- nil
				}
			}()
		}
		doMembers(t, name, func(obj *ast.Object) {
			if obj.Name == name {
				c <- obj
				runtime.Goexit()
			}
		})
		c <- nil
	}()
	m := <-c
	debugp("} -> %v", m)
	return m
}

// Iter returns a channel, sends on it
// all the members of the type, then closes it.
// Members at a shallower depth will be
// sent first.
//
func (t Type) Iter() <-chan *ast.Object {
	// TODO avoid sending members with the same name twice.
	c := make(chan *ast.Object)
	go func() {
		internal := t.Pkg == ""
		doMembers(t, "", func(obj *ast.Object) {
			if internal || ast.IsExported(obj.Name) {
				c <- obj
			}
		})
		close(c)
	}()
	return c
}

// ExprType returns the type for the given expression,
// and the object that represents it, if there is one.
// All variables, methods, top level functions, packages, struct and
// interface members, and types have objects.
// The returned object can be used with DeclPos to find out
// the source location of the definition of the object.
//
func ExprType(e ast.Expr, importer Importer, fs *token.FileSet) (obj *ast.Object, typ Type) {
	ctxt := &exprTypeContext{
		importer: importer,
		fileSet:  fs,
	}
	return ctxt.exprType(e, false, "")
}

type exprTypeContext struct {
	importer Importer
	fileSet  *token.FileSet
}

func (ctxt *exprTypeContext) exprType(n ast.Node, expectTuple bool, pkg string) (xobj *ast.Object, typ Type) {
	debugp("exprType tuple:%v pkg:%s %T %v [", expectTuple, pkg, n, pretty{n})
	defer func() {
		debugp("] -> %p, %v", xobj, typ)
	}()
	switch n := n.(type) {
	case nil:
	case *ast.Ident:
		obj := n.Obj
		if obj == nil || obj.Kind == ast.Bad {
			break
		}
		// A non-aliased type object represents itself.
		if obj.Kind == ast.Typ && !isTypeAlias(obj) {
			// Objects in the universal scope don't live
			// in any package.
			if parser.Universe.Lookup(obj.Name) == obj {
				pkg = ""
			}
			return obj, ctxt.newType(n, obj.Kind, pkg)
		}
		expr, typ := splitDecl(obj, n)
		switch {
		case typ != nil:
			_, t := ctxt.exprType(typ, false, pkg)
			if t.Kind != ast.Bad {
				t.Kind = obj.Kind
			}
			return obj, t

		case expr != nil:
			_, t := ctxt.exprType(expr, false, pkg)
			if t.Kind == ast.Typ {
				debugp("expected value, got type %v", t)
				t = badType
			}
			return obj, t

		default:
			switch n.Obj {
			case falseIdent.Obj, trueIdent.Obj:
				return obj, ctxt.newType(boolIdent, ast.Con, "")
			case iotaIdent.Obj:
				return obj, ctxt.newType(intIdent, ast.Con, "")
			default:
				return obj, Type{}
			}
		}
	case *ast.LabeledStmt:
		return n.Label.Obj, ctxt.newType(n, ast.Lbl, pkg)

	case *ast.ImportSpec:
		return nil, ctxt.newType(n, ast.Pkg, "")

	case *ast.ParenExpr:
		return ctxt.exprType(n.X, expectTuple, pkg)

	case *ast.CompositeLit:
		return nil, ctxt.certify(n.Type, ast.Var, pkg)

	case *ast.FuncLit:
		return nil, ctxt.certify(n.Type, ast.Var, pkg)

	case *ast.SelectorExpr:
		_, t := ctxt.exprType(n.X, false, pkg)
		// TODO: method expressions. when t.Kind == ast.Typ,
		// 	mutate a method declaration into a function with
		//	the receiver as first argument
		if t.Kind == ast.Bad {
			break
		}
		obj := t.Member(n.Sel.Name)
		if obj == nil {
			return nil, badType
		}
		if t.Kind == ast.Pkg {
			eobj, et := ctxt.exprType(&ast.Ident{Name: obj.Name, Obj: obj}, false, t.Pkg)
			et.Pkg = litToString(t.Node.(*ast.ImportSpec).Path)
			return eobj, et
		}
		// a method turns into a function type;
		// the number of formal arguments depends
		// on the class of the receiver expression.
		if fd, ismethod := obj.Decl.(*ast.FuncDecl); ismethod {
			if t.Kind == ast.Typ {
				return obj, ctxt.certify(methodExpr(fd), ast.Fun, t.Pkg)
			}
			return obj, ctxt.certify(fd.Type, ast.Fun, t.Pkg)
		} else if obj.Kind == ast.Typ {
			return obj, ctxt.certify(&ast.Ident{Name: obj.Name, Obj: obj}, ast.Typ, t.Pkg)
		}
		_, typ := splitDecl(obj, nil)
		return obj, ctxt.certify(typ, obj.Kind, t.Pkg)

	case *ast.FuncDecl:
		return nil, ctxt.certify(methodExpr(n), ast.Fun, pkg)

	case *ast.IndexExpr:
		_, t0 := ctxt.exprType(n.X, false, pkg)
		t := t0.Underlying(true)
		switch n := t.Node.(type) {
		case *ast.ArrayType:
			return nil, ctxt.certify(n.Elt, ast.Var, t.Pkg)
		case *ast.MapType:
			t := ctxt.certify(n.Value, ast.Var, t.Pkg)
			if expectTuple && t.Kind != badType.Kind {
				return nil, ctxt.newType(MultiValue{[]ast.Expr{t.Node.(ast.Expr), predecl("bool")}}, ast.Var, t.Pkg)
			}
			return nil, t
		}

	case *ast.SliceExpr:
		_, typ := ctxt.exprType(n.X, false, pkg)
		return nil, typ

	case *ast.CallExpr:
		switch exprName(n.Fun) {
		case makeIdent.Obj:
			if len(n.Args) > 0 {
				return nil, ctxt.certify(n.Args[0], ast.Var, pkg)
			}
		case newIdent.Obj:
			if len(n.Args) > 0 {
				t := ctxt.certify(n.Args[0], ast.Var, pkg)
				if t.Kind != ast.Bad {
					return nil, ctxt.newType(&ast.StarExpr{n.Pos(), t.Node.(ast.Expr)}, ast.Var, t.Pkg)
				}
			}
		default:
			if _, fntype := ctxt.exprType(n.Fun, false, pkg); fntype.Kind != ast.Bad {
				// A type cast transforms a type expression
				// into a value expression.
				if fntype.Kind == ast.Typ {
					fntype.Kind = ast.Var
					// Preserve constness if underlying expr is constant.
					if len(n.Args) == 1 {
						_, argtype := ctxt.exprType(n.Args[0], false, pkg)
						if argtype.Kind == ast.Con {
							fntype.Kind = ast.Con
						}
					}
					return nil, fntype
				}
				// A function call operates on the underlying type,
				t := fntype.Underlying(true)
				if fn, ok := t.Node.(*ast.FuncType); ok {
					return nil, ctxt.certify(fields2type(fn.Results), ast.Var, t.Pkg)
				}
			}
		}

	case *ast.StarExpr:
		if _, t := ctxt.exprType(n.X, false, pkg); t.Kind != ast.Bad {
			if t.Kind == ast.Typ {
				return nil, ctxt.newType(&ast.StarExpr{n.Pos(), t.Node.(ast.Expr)}, ast.Typ, t.Pkg)
			}
			if n, ok := t.Node.(*ast.StarExpr); ok {
				return nil, ctxt.certify(n.X, ast.Var, t.Pkg)
			}
		}

	case *ast.TypeAssertExpr:
		t := ctxt.certify(n.Type, ast.Var, pkg)
		if expectTuple && t.Kind != ast.Bad {
			return nil, ctxt.newType(MultiValue{[]ast.Expr{t.Node.(ast.Expr), predecl("bool")}}, ast.Var, t.Pkg)
		}
		return nil, t

	case *ast.UnaryExpr:
		if _, t := ctxt.exprType(n.X, false, pkg); t.Kind != ast.Bad {
			u := t.Underlying(true)
			switch n.Op {
			case token.ARROW:
				if ct, ok := u.Node.(*ast.ChanType); ok {
					t := ctxt.certify(ct.Value, ast.Var, u.Pkg)
					if expectTuple && t.Kind != ast.Bad {
						return nil, ctxt.newType(MultiValue{[]ast.Expr{t.Node.(ast.Expr), predecl("bool")}}, ast.Var, t.Pkg)
					}
					return nil, ctxt.certify(ct.Value, ast.Var, u.Pkg)
				}
			case token.RANGE:
				switch n := u.Node.(type) {
				case *ast.ArrayType:
					if expectTuple {
						return nil, ctxt.newType(MultiValue{[]ast.Expr{predecl("int"), n.Elt}}, ast.Var, u.Pkg)
					}

					return nil, ctxt.newType(predecl("bool"), ast.Var, "")

				case *ast.MapType:
					if expectTuple {
						return nil, ctxt.newType(MultiValue{[]ast.Expr{n.Key, n.Value}}, ast.Var, u.Pkg)
					}
					return nil, ctxt.certify(n.Key, ast.Var, u.Pkg)

				case *ast.ChanType:
					return nil, ctxt.certify(n.Value, ast.Var, u.Pkg)
				}

			case token.AND:
				if t.Kind == ast.Var {
					return nil, ctxt.newType(&ast.StarExpr{n.Pos(), t.Node.(ast.Expr)}, ast.Var, t.Pkg)
				}

			case token.NOT:
				return nil, ctxt.newType(predecl("bool"), t.Kind, "")

			default:
				return nil, t
			}
		}

	case *ast.BinaryExpr:
		switch n.Op {
		case token.LSS, token.EQL, token.GTR, token.NEQ, token.LEQ, token.GEQ, token.ARROW, token.LOR, token.LAND:
			_, t := ctxt.exprType(n.X, false, pkg)
			if t.Kind == ast.Con {
				_, t = ctxt.exprType(n.Y, false, pkg)
			}
			return nil, ctxt.newType(predecl("bool"), t.Kind, "")

		case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.AND, token.AND_NOT, token.XOR:
			_, tx := ctxt.exprType(n.X, false, pkg)
			_, ty := ctxt.exprType(n.Y, false, pkg)
			switch {
			case tx.Kind == ast.Bad || ty.Kind == ast.Bad:

			case !isNamedType(tx):
				return nil, ty
			case !isNamedType(ty):
				return nil, tx
			}
			// could check type equality
			return nil, tx

		case token.SHL, token.SHR:
			_, typ := ctxt.exprType(n.X, false, pkg)
			return nil, typ
		}

	case *ast.BasicLit:
		var id *ast.Ident
		switch n.Kind {
		case token.STRING:
			id = stringIdent

		case token.INT, token.CHAR:
			id = intIdent

		case token.FLOAT:
			id = floatIdent

		default:
			debugp("unknown constant type %v", n.Kind)
		}
		if id != nil {
			return nil, ctxt.newType(id, ast.Con, "")
		}

	case *ast.StructType, *ast.ChanType, *ast.MapType, *ast.ArrayType, *ast.InterfaceType, *ast.FuncType:
		return nil, ctxt.newType(n.(ast.Node), ast.Typ, pkg)

	case MultiValue:
		return nil, ctxt.newType(n, ast.Typ, pkg)

	case *exprIndex:
		_, t := ctxt.exprType(n.x, true, pkg)
		if t.Kind != ast.Bad {
			if ts, ok := t.Node.(MultiValue); ok {
				if n.i < len(ts.Types) {
					return nil, ctxt.certify(ts.Types[n.i], ast.Var, t.Pkg)
				}
			}
		}
	case *ast.Ellipsis:
		t := ctxt.certify(n.Elt, ast.Var, pkg)
		if t.Kind != ast.Bad {
			return nil, ctxt.newType(&ast.ArrayType{n.Pos(), nil, t.Node.(ast.Expr)}, ast.Var, t.Pkg)
		}

	default:
		panic(fmt.Sprintf("unknown type %T", n))
	}
	return nil, badType
}

func (ctxt *exprTypeContext) newType(n ast.Node, kind ast.ObjKind, pkg string) Type {
	return Type{
		Node: n,
		Kind: kind,
		Pkg:  pkg,
		ctxt: ctxt,
	}
}

// litToString converts from a string literal to a regular string.
func litToString(lit *ast.BasicLit) (v string) {
	if lit.Kind != token.STRING {
		panic("expected string")
	}
	v, err := strconv.Unquote(string(lit.Value))
	if err != nil {
		panic("cannot unquote")
	}
	return v
}

// doMembers iterates through a type's members, calling
// fn for each member. If name is non-empty, it looks
// directly for members with that name when possible.
// It uses the list q as a queue to perform breadth-first
// traversal, as per the Go specification.
func doMembers(typ Type, name string, fn func(*ast.Object)) {
	switch t := typ.Node.(type) {
	case nil:
		return

	case *ast.ImportSpec:
		path := litToString(t.Path)
		pos := typ.ctxt.fileSet.Position(typ.Node.Pos())
		if pkg := typ.ctxt.importer(path, filepath.Dir(pos.Filename)); pkg != nil {
			doScope(pkg.Scope, name, fn, path)
		}
		return
	}

	q := list.New()
	q.PushBack(typ)
	for e := q.Front(); e != nil; e = q.Front() {
		doTypeMembers(e.Value.(Type), name, fn, q)
		q.Remove(e)
	}
}

// doTypeMembers calls fn for each member of the given type,
// at one level only. Unnamed members are pushed onto the queue.
func doTypeMembers(t Type, name string, fn func(*ast.Object), q *list.List) {
	// strip off single indirection
	// TODO: eliminate methods disallowed when indirected.
	if u, ok := t.Node.(*ast.StarExpr); ok {
		_, t = t.ctxt.exprType(u.X, false, t.Pkg)
	}
	if id, _ := t.Node.(*ast.Ident); id != nil && id.Obj != nil {
		if scope, ok := id.Obj.Type.(*ast.Scope); ok {
			doScope(scope, name, fn, t.Pkg)
		}
	}
	u := t.Underlying(true)
	switch n := u.Node.(type) {
	case *ast.StructType:
		t.ctxt.doStructMembers(n.Fields.List, t.Pkg, fn, q)

	case *ast.InterfaceType:
		t.ctxt.doInterfaceMembers(n.Methods.List, t.Pkg, fn)
	}
}

func (ctxt *exprTypeContext) doInterfaceMembers(fields []*ast.Field, pkg string, fn func(*ast.Object)) {
	// Go Spec: An interface may contain an interface type name T in place of a method
	// specification. The effect is equivalent to enumerating the methods of T explicitly
	// in the interface.

	for _, f := range fields {
		if len(f.Names) > 0 {
			for _, fname := range f.Names {
				fn(fname.Obj)
			}
		} else {
			_, typ := ctxt.exprType(f.Type, false, pkg)
			typ = typ.Underlying(true)
			switch n := typ.Node.(type) {
			case *ast.InterfaceType:
				ctxt.doInterfaceMembers(n.Methods.List, typ.Pkg, fn)
			default:
				debugp("unknown anon type in interface: %T\n", n)
			}
		}
	}
}

func (ctxt *exprTypeContext) doStructMembers(fields []*ast.Field, pkg string, fn func(*ast.Object), q *list.List) {
	// Go Spec: For a value x of type T or *T where T is not an interface type, x.f
	// denotes the field or method at the shallowest depth in T where there
	// is such an f.
	// Thus we traverse shallower fields first, pushing anonymous fields
	// onto the queue for later.

	for _, f := range fields {
		if len(f.Names) > 0 {
			for _, fname := range f.Names {
				fn(fname.Obj)
			}
		} else {
			m := unnamedFieldName(f.Type)
			fn(m.Obj)
			// The unnamed field's Decl points to the
			// original type declaration.
			_, typeNode := splitDecl(m.Obj, nil)
			obj, typ := ctxt.exprType(typeNode, false, pkg)
			if typ.Kind == ast.Typ {
				q.PushBack(typ)
			} else {
				debugp("unnamed field kind %v (obj %v) not a type; %v", typ.Kind, obj, typ.Node)
			}
		}
	}
}

// unnamedFieldName returns the field name for
// an unnamed field with its type given by ast node t.
//
func unnamedFieldName(t ast.Node) *ast.Ident {
	switch t := t.(type) {
	case *ast.Ident:
		return t

	case *ast.SelectorExpr:
		return t.Sel

	case *ast.StarExpr:
		return unnamedFieldName(t.X)
	}

	panic("no name found for unnamed field")
}

// doScope iterates through all the functions in the given scope, at
// the top level only.
func doScope(s *ast.Scope, name string, fn func(*ast.Object), pkg string) {
	if s == nil {
		return
	}
	if name != "" {
		if obj := s.Lookup(name); obj != nil {
			fn(obj)
		}
		return
	}
	for _, obj := range s.Objects {
		if obj.Kind == ast.Bad || pkg != "" && !ast.IsExported(obj.Name) {
			continue
		}
		fn(obj)
	}
}

// If typ represents a named type, Underlying returns
// the type that it was defined as. If all is true,
// it repeats this process until the type is not
// a named type.
func (typ Type) Underlying(all bool) Type {
	for {
		id, _ := typ.Node.(*ast.Ident)
		if id == nil || id.Obj == nil {
			break
		}
		_, typNode := splitDecl(id.Obj, id)
		_, t := typ.ctxt.exprType(typNode, false, typ.Pkg)
		if t.Kind != ast.Typ {
			return badType
		}
		typ.Node = t.Node
		typ.Pkg = t.Pkg
		if !all {
			break
		}
	}
	return typ
}

func noParens(typ interface{}) interface{} {
	for {
		if n, ok := typ.(*ast.ParenExpr); ok {
			typ = n.X
		} else {
			break
		}
	}
	return typ
}

// make sure that the type is really a type expression
func (ctxt *exprTypeContext) certify(typ ast.Node, kind ast.ObjKind, pkg string) Type {
	_, t := ctxt.exprType(typ, false, pkg)
	if t.Kind == ast.Typ {
		return ctxt.newType(t.Node, kind, t.Pkg)
	}
	return badType
}

// If n represents a single identifier, exprName returns its object.
func exprName(typ interface{}) *ast.Object {
	switch t := noParens(typ).(type) {
	case *ast.Ident:
		return t.Obj
	case *ast.Object:
		return t
	}
	return nil
}

// exprIndex represents the selection of one member
// of a multiple-value expression, as in
// _, err := fd.Read(...)
type exprIndex struct {
	i int
	x ast.Expr
}

func (e *exprIndex) Pos() token.Pos {
	return token.NoPos
}
func (e *exprIndex) End() token.Pos {
	return token.NoPos
}

// splitDecl splits obj.Decl and returns the expression part and the type part.
// Either may be nil, but not both if the declaration is value.
//
// If id is non-nil, it gives the referring identifier. This is only used
// to determine which node in a type switch is being referred to.
//
func splitDecl(obj *ast.Object, id *ast.Ident) (expr, typ ast.Node) {
	switch decl := obj.Decl.(type) {
	case nil:
		return nil, nil
	case *ast.ValueSpec:
		return splitVarDecl(obj.Name, decl.Names, decl.Values, decl.Type)

	case *ast.TypeSpec:
		return nil, decl.Type

	case *ast.FuncDecl:
		if decl.Recv != nil {
			return decl, decl.Type
		}
		return decl.Body, decl.Type

	case *ast.Field:
		return nil, decl.Type

	case *ast.LabeledStmt:
		return decl, nil

	case *ast.ImportSpec:
		return nil, decl

	case *ast.AssignStmt:
		return splitVarDecl(obj.Name, exprsToIdents(decl.Lhs), decl.Rhs, nil)

	case *ast.GenDecl:
		if decl.Tok == token.CONST {
			return splitConstDecl(obj.Name, decl)
		}
	case *ast.TypeSwitchStmt:
		expr := decl.Assign.(*ast.AssignStmt).Rhs[0].(*ast.TypeAssertExpr).X
		for _, stmt := range decl.Body.List {
			tcase := stmt.(*ast.CaseClause)
			for _, stmt := range tcase.Body {
				if containsNode(stmt, id) {
					if len(tcase.List) == 1 {
						return expr, tcase.List[0]
					}
					return expr, nil
				}
			}
		}
		return expr, nil
	}
	debugp("unknown decl type %T %v", obj.Decl, pretty{obj.Decl})
	return nil, nil
}

// splitVarDecl finds the declaration expression and type from a
// variable declaration (short form or long form).
func splitVarDecl(name string, names []*ast.Ident, values []ast.Expr, vtype ast.Expr) (expr, typ ast.Node) {
	if len(names) == 1 && len(values) == 1 {
		return values[0], vtype
	}
	p := 0
	for i, aname := range names {
		if aname != nil && aname.Name == name {
			p = i
			break
		}
	}
	if len(values) > 1 {
		return values[p], vtype
	}
	if len(values) == 0 {
		return nil, vtype
	}
	return &exprIndex{p, values[0]}, vtype
}

func exprsToIdents(exprs []ast.Expr) []*ast.Ident {
	idents := make([]*ast.Ident, len(exprs))
	for i, e := range exprs {
		idents[i], _ = e.(*ast.Ident)
	}
	return idents
}

// Constant declarations can omit the type, so the declaration for
// a const may be the entire GenDecl - we find the relevant
// clause and infer the type and expression.
func splitConstDecl(name string, decl *ast.GenDecl) (expr, typ ast.Node) {
	var lastSpec *ast.ValueSpec // last spec with >0 values.
	for _, spec := range decl.Specs {
		vspec := spec.(*ast.ValueSpec)
		if len(vspec.Values) > 0 {
			lastSpec = vspec
		}
		for i, vname := range vspec.Names {
			if vname.Name == name {
				if i < len(lastSpec.Values) {
					return lastSpec.Values[i], lastSpec.Type
				}
				return nil, lastSpec.Type
			}
		}
	}
	return nil, nil
}

// funcVisitor allows an ast.Visitor to be implemented
// by a single function.
type funcVisitor func(n ast.Node) bool

func (f funcVisitor) Visit(n ast.Node) ast.Visitor {
	if f(n) {
		return f
	}
	return nil
}

// constainsNode returns true if x is found somewhere
// inside node.
func containsNode(node, x ast.Node) (found bool) {
	ast.Walk(funcVisitor(func(n ast.Node) bool {
		if !found {
			found = n == x
		}
		return !found
	}),
		node)
	return
}

func isNamedType(typ Type) bool {
	return typ.Underlying(false).Node != typ.Node
}

func isTypeAlias(obj *ast.Object) bool {
	if obj.Kind != ast.Typ {
		return false
	}
	ts, ok := obj.Decl.(*ast.TypeSpec)
	return ok && ts.Assign.IsValid()
}

func fields2type(fields *ast.FieldList) ast.Node {
	if fields == nil {
		return MultiValue{nil}
	}
	n := 0
	for _, f := range fields.List {
		j := len(f.Names)
		if j == 0 {
			j = 1
		}
		n += j
	}
	switch n {
	case 0:
		return nil
	case 1:
		return fields.List[0].Type
	}
	elist := make([]ast.Expr, n)
	i := 0
	for _, f := range fields.List {
		j := len(f.Names)
		if j == 0 {
			j = 1
		}
		for ; j > 0; j-- {
			elist[i] = f.Type
			i++
		}
	}
	return MultiValue{elist}
}

// TODO
func methodExpr(fd *ast.FuncDecl) *ast.FuncType {
	return fd.Type
}

// XXX  the following stuff is for debugging - remove later.

func debugp(f string, a ...interface{}) {
	if Debug {
		log.Printf(f, a...)
	}
}

type pretty struct {
	n interface{}
}

func (p pretty) String() string {
	var b bytes.Buffer
	printer.Fprint(&b, FileSet, p.n)
	return b.String()
}

"""



```