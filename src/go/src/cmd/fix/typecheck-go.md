Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Initial Skim and Keywords:** The first step is a quick read-through to get a general idea and identify keywords. I see `typecheck`, `TypeConfig`, `ast`, `parser`, `cgo`, `typeof`, `assign`, `func`, `struct`, `interface` (implicitly through methods), and mentions of "partial type checker."  This immediately tells me it's related to understanding Go code's structure and types, but with limitations.

2. **Understanding the Core Goal:** The comments at the beginning are crucial. They explicitly state "Partial type checker."  This is the central theme. The input is an AST and *partial* type information. The goal isn't a complete compilation, but to infer as much type information as possible to help with code fixes. This explains the "TODO: Replace with go/typechecker" comment – this is a custom, simplified implementation.

3. **Dissecting Key Structures:**  Next, I examine the important data structures:

    * **`TypeConfig`:** This holds the "universe of relevant types."  The `Type`, `Var`, `Func`, and `External` maps are key. The comment about `TypeByName` being where strings are resolved is important for understanding how the string-based type system is managed.
    * **`Type`:**  Represents the structure of a type (struct or interface). `Field`, `Method`, and `Embed` are the core components. The `dot` method's purpose (resolving `typ.name`) becomes clear.

4. **Tracing the `typecheck` Function:** This is the main entry point. I follow the flow:

    * Initialization of `typeof` and `assign` maps.
    * Handling "C" imports and cgo:  This is a significant part and involves running `cgo`, parsing the generated code, and extracting type information. The error handling and `reportCgoError` are also important details.
    * Gathering function and struct declarations:  This populates the initial type information. The distinction between `typeof[fn.Name]` and `typeof[fn.Name.Obj]` for future references is a subtle but important detail.
    * Calling `typecheck1`:  This signals the recursive nature of the type checking process.

5. **Analyzing `typecheck1`:** This is where the actual type inference happens. I note the `set` helper function and `typecheckAssign`. The `before` and `after` functions used with `walkBeforeAfter` suggest a depth-first traversal of the AST. The `after` function contains the core logic, handling various AST node types:

    * **Declarations (`*ast.ValueSpec`, `*ast.AssignStmt`):** How types are assigned during declaration and regular assignments.
    * **Identifiers (`*ast.Ident`):**  Looking up types based on the `Obj` field.
    * **Selectors (`*ast.SelectorExpr`):** Resolving field and method types. The logic for package selectors is also present.
    * **Calls (`*ast.CallExpr`):**  Special handling for `make` and `new`, otherwise using function type information.
    * **Type Assertions (`*ast.TypeAssertExpr`):** Handling both `x.(type)` and `x.(T)`.
    * **Slices, Indexes, Stars, Unary Expressions, Composite Literals, Paren Expressions, Range Statements, Type Switches, Return Statements, Binary Expressions:** How the type checker infers types for these constructs. The comments like "Lazy" highlight the partial nature of the checker. The re-typechecking in `RangeStmt` and the handling of `TypeSwitchStmt` to refine types within cases are notable.

6. **Understanding Helper Functions:** The functions `splitFunc`, `joinFunc`, `split`, and `join` are crucial for managing the string-based representation of function types. This reinforces the idea that this is a simplified type system.

7. **Putting It All Together and Synthesizing the Functionality:**  Now I can formulate the main functionalities:

    * **Partial Type Inference:** The core goal, emphasizing the limitations.
    * **Handling Declarations and Assignments:**  Inferring types from variable and constant declarations and assignments.
    * **Function and Method Type Resolution:**  Determining the types of function calls and method invocations.
    * **Struct and Interface Member Access:**  Resolving the types of fields and methods of structs and interfaces.
    * **Basic Language Constructs:** Handling type assertions, slice expressions, index expressions, pointer operations, composite literals, range loops, type switches, and return statements.
    * **Cgo Integration (Partial):**  A mechanism to incorporate type information from cgo-generated code.

8. **Illustrative Go Code Examples:**  Based on the understanding of the functionalities, I can create simple Go code examples that demonstrate how the type checker might operate and what type information it would likely infer. These examples should cover various scenarios like variable declarations, function calls, struct access, and type assertions.

9. **Command-Line Arguments (If Applicable):**  I scan the code for anything related to `os.Args` or flag parsing. In this specific snippet, there's no direct command-line argument processing. However, the interaction with `gofmt` and `cgo` suggests it's likely part of a larger tool.

10. **Common Mistakes:** I think about the limitations of the partial type checker. What could go wrong or be misinterpreted?  The biggest issue is its *partial* nature. It might not catch all type errors a full compiler would. Assumptions made in the code (e.g., no nested brackets) can also lead to inaccuracies. The string-based type representation could also be a source of errors if not handled carefully.

11. **Refining and Structuring the Output:** Finally, I organize the information logically, starting with the core functionalities, providing code examples, discussing command-line arguments (or the lack thereof), and highlighting potential pitfalls. Using clear headings and bullet points improves readability.

This systematic approach, combining code reading, comment analysis, tracing execution flow, and understanding data structures, allows for a comprehensive understanding of the code's purpose and functionality.
这段 `go/src/cmd/fix/typecheck.go` 文件实现了一个**Go语言代码的局部类型检查器**。  之所以说是“局部”的，是因为它不需要程序中所有依赖包的完整类型信息，而只需要一些关键包的类型信息就可以进行检查。这个类型检查器的主要目的是为了辅助 `go fix` 工具进行代码重构和修复。

以下是它的主要功能：

1. **接收部分类型信息配置 (`TypeConfig`) 和抽象语法树 (`ast.File`) 作为输入。** `TypeConfig` 包含了已知类型的定义、变量类型、函数签名等信息，这些信息可能是不完整的。
2. **对输入的抽象语法树进行类型推断。**  它会尽力根据已有的类型信息（包括变量声明、函数和方法返回值、类型断言等）推断出程序中各个表达式的类型。
3. **输出类型信息 (`typeof`) 和赋值关系 (`assign`)。**
    * `typeof` 是一个映射，将 AST 节点（例如表达式、标识符等）映射到它们的推断出的类型字符串（使用 `gofmt` 格式）。
    * `assign` 是一个映射，将类型字符串映射到一个表达式列表，这些表达式被赋值为该类型的值。这可以帮助理解类型之间的转换和赋值关系。
4. **处理 `cgo` 生成的代码。** 如果代码中导入了 "C" 包，它会尝试运行 `cgo` 工具来生成 `_cgo_gotypes.go` 文件，并从中提取 cgo 对象的类型信息，将其添加到 `TypeConfig` 中。这使得类型检查器能够理解与 C 代码交互部分的类型。

**它可以被看作是 `go/types` 包的一个轻量级替代方案，专门用于 `go fix` 场景，在信息不全的情况下也能提供有用的类型信息。** 它的目标不是完成完整的类型检查并报错，而是为了帮助 `go fix` 理解代码的结构和类型，从而安全地进行代码修改。

**Go 代码举例说明:**

假设我们有以下 Go 代码片段：

```go
package main

import "fmt"

type MyInt int

func add(a, b int) int {
	return a + b
}

func main() {
	var x int = 10
	y := 20
	z := add(x, y)
	var m MyInt = MyInt(z)
	fmt.Println(m)
}
```

以及一个 `TypeConfig`，它可能包含以下信息：

```go
cfg := &TypeConfig{
	Type: map[string]*Type{
		"int": {},
		"main.MyInt": {Def: "int"}, // MyInt 的底层类型是 int
		"fmt.Println": {Method: map[string]string{"": "func(a ...interface{}) (n int, err error)"}},
	},
	Func: map[string]string{
		"main.add": "(int, int) int",
	},
	Var: map[string]string{},
}
```

**假设输入 AST 对应上面的 Go 代码。**

**推理过程与输出：**

* **变量声明:**
    * `var x int = 10`:  `typeof[x]` 将被推断为 "int"。
    * `y := 20`: `typeof[y]` 将被推断为 "int"（根据赋值推断）。
    * `z := add(x, y)`:  根据 `cfg.Func["main.add"]` 的信息，`typeof[add(x, y)]` 将被推断为 "int"，因此 `typeof[z]` 也将是 "int"。
    * `var m MyInt = MyInt(z)`: 根据 `cfg.Type["main.MyInt"].Def` 的信息，`typeof[m]` 将被推断为 "main.MyInt"。 `typeof[MyInt(z)]` 也将被推断为 "main.MyInt"。

* **函数调用:**
    * `fmt.Println(m)`: 根据 `cfg.Type["fmt.Println"]` 的信息，类型检查器会理解 `Println` 接受可变参数 `...interface{}`。

* **赋值关系 (`assign`):**
    * `assign["int"]` 可能包含 `y` 和 `z`，因为它们被赋值为 `int` 类型的值。
    * `assign["main.MyInt"]` 可能包含 `m`。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。它主要是作为一个库函数被 `go fix` 命令调用。 `go fix` 命令会负责解析命令行参数，然后将相关的 AST 和类型信息传递给 `typecheck` 函数。

**使用者易犯错的点：**

由于这是一个局部类型检查器，它的信息是不完备的，所以使用者容易犯的错误是：

1. **依赖于它提供完整的类型检查结果。**  这个检查器不会像 `go build` 那样报告所有类型错误，它只是尽力推断。
2. **假设它可以处理所有复杂的类型场景。**  由于是“局部”的，它可能无法处理所有复杂的类型关系，例如涉及接口的隐式实现等。
3. **忽略 `TypeConfig` 的重要性。**  `TypeConfig` 提供的信息质量直接影响类型检查器的准确性。如果 `TypeConfig` 中缺少关键类型信息，类型检查器可能无法正确推断类型。

**举例说明易犯错的点：**

假设 `TypeConfig` 中没有 `main.MyInt` 的定义，那么在处理 `var m MyInt = MyInt(z)` 时，类型检查器可能无法正确推断出 `m` 的类型。它可能会将 `MyInt` 当作一个未知的标识符处理。

总而言之，`go/src/cmd/fix/typecheck.go` 实现了一个针对 `go fix` 工具的、具备部分类型推断能力的 Go 语言代码分析器。它的核心在于利用有限的类型信息尽可能准确地理解代码结构，辅助代码重构和修复工作。

Prompt: 
```
这是路径为go/src/cmd/fix/typecheck.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

// Partial type checker.
//
// The fact that it is partial is very important: the input is
// an AST and a description of some type information to
// assume about one or more packages, but not all the
// packages that the program imports. The checker is
// expected to do as much as it can with what it has been
// given. There is not enough information supplied to do
// a full type check, but the type checker is expected to
// apply information that can be derived from variable
// declarations, function and method returns, and type switches
// as far as it can, so that the caller can still tell the types
// of expression relevant to a particular fix.
//
// TODO(rsc,gri): Replace with go/typechecker.
// Doing that could be an interesting test case for go/typechecker:
// the constraints about working with partial information will
// likely exercise it in interesting ways. The ideal interface would
// be to pass typecheck a map from importpath to package API text
// (Go source code), but for now we use data structures (TypeConfig, Type).
//
// The strings mostly use gofmt form.
//
// A Field or FieldList has as its type a comma-separated list
// of the types of the fields. For example, the field list
//	x, y, z int
// has type "int, int, int".

// The prefix "type " is the type of a type.
// For example, given
//	var x int
//	type T int
// x's type is "int" but T's type is "type int".
// mkType inserts the "type " prefix.
// getType removes it.
// isType tests for it.

func mkType(t string) string {
	return "type " + t
}

func getType(t string) string {
	if !isType(t) {
		return ""
	}
	return t[len("type "):]
}

func isType(t string) bool {
	return strings.HasPrefix(t, "type ")
}

// TypeConfig describes the universe of relevant types.
// For ease of creation, the types are all referred to by string
// name (e.g., "reflect.Value").  TypeByName is the only place
// where the strings are resolved.

type TypeConfig struct {
	Type map[string]*Type
	Var  map[string]string
	Func map[string]string

	// External maps from a name to its type.
	// It provides additional typings not present in the Go source itself.
	// For now, the only additional typings are those generated by cgo.
	External map[string]string
}

// typeof returns the type of the given name, which may be of
// the form "x" or "p.X".
func (cfg *TypeConfig) typeof(name string) string {
	if cfg.Var != nil {
		if t := cfg.Var[name]; t != "" {
			return t
		}
	}
	if cfg.Func != nil {
		if t := cfg.Func[name]; t != "" {
			return "func()" + t
		}
	}
	return ""
}

// Type describes the Fields and Methods of a type.
// If the field or method cannot be found there, it is next
// looked for in the Embed list.
type Type struct {
	Field  map[string]string // map field name to type
	Method map[string]string // map method name to comma-separated return types (should start with "func ")
	Embed  []string          // list of types this type embeds (for extra methods)
	Def    string            // definition of named type
}

// dot returns the type of "typ.name", making its decision
// using the type information in cfg.
func (typ *Type) dot(cfg *TypeConfig, name string) string {
	if typ.Field != nil {
		if t := typ.Field[name]; t != "" {
			return t
		}
	}
	if typ.Method != nil {
		if t := typ.Method[name]; t != "" {
			return t
		}
	}

	for _, e := range typ.Embed {
		etyp := cfg.Type[e]
		if etyp != nil {
			if t := etyp.dot(cfg, name); t != "" {
				return t
			}
		}
	}

	return ""
}

// typecheck type checks the AST f assuming the information in cfg.
// It returns two maps with type information:
// typeof maps AST nodes to type information in gofmt string form.
// assign maps type strings to lists of expressions that were assigned
// to values of another type that were assigned to that type.
func typecheck(cfg *TypeConfig, f *ast.File) (typeof map[any]string, assign map[string][]any) {
	typeof = make(map[any]string)
	assign = make(map[string][]any)
	cfg1 := &TypeConfig{}
	*cfg1 = *cfg // make copy so we can add locally
	copied := false

	// If we import "C", add types of cgo objects.
	cfg.External = map[string]string{}
	cfg1.External = cfg.External
	if imports(f, "C") {
		// Run cgo on gofmtFile(f)
		// Parse, extract decls from _cgo_gotypes.go
		// Map _Ctype_* types to C.* types.
		err := func() error {
			txt, err := gofmtFile(f)
			if err != nil {
				return err
			}
			dir, err := os.MkdirTemp(os.TempDir(), "fix_cgo_typecheck")
			if err != nil {
				return err
			}
			defer os.RemoveAll(dir)
			err = os.WriteFile(filepath.Join(dir, "in.go"), txt, 0600)
			if err != nil {
				return err
			}
			goCmd := "go"
			if goroot := runtime.GOROOT(); goroot != "" {
				goCmd = filepath.Join(goroot, "bin", "go")
			}
			cmd := exec.Command(goCmd, "tool", "cgo", "-objdir", dir, "-srcdir", dir, "in.go")
			if reportCgoError != nil {
				// Since cgo command errors will be reported, also forward the error
				// output from the command for debugging.
				cmd.Stderr = os.Stderr
			}
			err = cmd.Run()
			if err != nil {
				return err
			}
			out, err := os.ReadFile(filepath.Join(dir, "_cgo_gotypes.go"))
			if err != nil {
				return err
			}
			cgo, err := parser.ParseFile(token.NewFileSet(), "cgo.go", out, 0)
			if err != nil {
				return err
			}
			for _, decl := range cgo.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				if strings.HasPrefix(fn.Name.Name, "_Cfunc_") {
					var params, results []string
					for _, p := range fn.Type.Params.List {
						t := gofmt(p.Type)
						t = strings.ReplaceAll(t, "_Ctype_", "C.")
						params = append(params, t)
					}
					for _, r := range fn.Type.Results.List {
						t := gofmt(r.Type)
						t = strings.ReplaceAll(t, "_Ctype_", "C.")
						results = append(results, t)
					}
					cfg.External["C."+fn.Name.Name[7:]] = joinFunc(params, results)
				}
			}
			return nil
		}()
		if err != nil {
			if reportCgoError == nil {
				fmt.Fprintf(os.Stderr, "go fix: warning: no cgo types: %s\n", err)
			} else {
				reportCgoError(err)
			}
		}
	}

	// gather function declarations
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		typecheck1(cfg, fn.Type, typeof, assign)
		t := typeof[fn.Type]
		if fn.Recv != nil {
			// The receiver must be a type.
			rcvr := typeof[fn.Recv]
			if !isType(rcvr) {
				if len(fn.Recv.List) != 1 {
					continue
				}
				rcvr = mkType(gofmt(fn.Recv.List[0].Type))
				typeof[fn.Recv.List[0].Type] = rcvr
			}
			rcvr = getType(rcvr)
			if rcvr != "" && rcvr[0] == '*' {
				rcvr = rcvr[1:]
			}
			typeof[rcvr+"."+fn.Name.Name] = t
		} else {
			if isType(t) {
				t = getType(t)
			} else {
				t = gofmt(fn.Type)
			}
			typeof[fn.Name] = t

			// Record typeof[fn.Name.Obj] for future references to fn.Name.
			typeof[fn.Name.Obj] = t
		}
	}

	// gather struct declarations
	for _, decl := range f.Decls {
		d, ok := decl.(*ast.GenDecl)
		if ok {
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.TypeSpec:
					if cfg1.Type[s.Name.Name] != nil {
						break
					}
					if !copied {
						copied = true
						// Copy map lazily: it's time.
						cfg1.Type = maps.Clone(cfg.Type)
						if cfg1.Type == nil {
							cfg1.Type = make(map[string]*Type)
						}
					}
					t := &Type{Field: map[string]string{}}
					cfg1.Type[s.Name.Name] = t
					switch st := s.Type.(type) {
					case *ast.StructType:
						for _, f := range st.Fields.List {
							for _, n := range f.Names {
								t.Field[n.Name] = gofmt(f.Type)
							}
						}
					case *ast.ArrayType, *ast.StarExpr, *ast.MapType:
						t.Def = gofmt(st)
					}
				}
			}
		}
	}

	typecheck1(cfg1, f, typeof, assign)
	return typeof, assign
}

// reportCgoError, if non-nil, reports a non-nil error from running the "cgo"
// tool. (Set to a non-nil hook during testing if cgo is expected to work.)
var reportCgoError func(err error)

func makeExprList(a []*ast.Ident) []ast.Expr {
	var b []ast.Expr
	for _, x := range a {
		b = append(b, x)
	}
	return b
}

// typecheck1 is the recursive form of typecheck.
// It is like typecheck but adds to the information in typeof
// instead of allocating a new map.
func typecheck1(cfg *TypeConfig, f any, typeof map[any]string, assign map[string][]any) {
	// set sets the type of n to typ.
	// If isDecl is true, n is being declared.
	set := func(n ast.Expr, typ string, isDecl bool) {
		if typeof[n] != "" || typ == "" {
			if typeof[n] != typ {
				assign[typ] = append(assign[typ], n)
			}
			return
		}
		typeof[n] = typ

		// If we obtained typ from the declaration of x
		// propagate the type to all the uses.
		// The !isDecl case is a cheat here, but it makes
		// up in some cases for not paying attention to
		// struct fields. The real type checker will be
		// more accurate so we won't need the cheat.
		if id, ok := n.(*ast.Ident); ok && id.Obj != nil && (isDecl || typeof[id.Obj] == "") {
			typeof[id.Obj] = typ
		}
	}

	// Type-check an assignment lhs = rhs.
	// If isDecl is true, this is := so we can update
	// the types of the objects that lhs refers to.
	typecheckAssign := func(lhs, rhs []ast.Expr, isDecl bool) {
		if len(lhs) > 1 && len(rhs) == 1 {
			if _, ok := rhs[0].(*ast.CallExpr); ok {
				t := split(typeof[rhs[0]])
				// Lists should have same length but may not; pair what can be paired.
				for i := 0; i < len(lhs) && i < len(t); i++ {
					set(lhs[i], t[i], isDecl)
				}
				return
			}
		}
		if len(lhs) == 1 && len(rhs) == 2 {
			// x = y, ok
			rhs = rhs[:1]
		} else if len(lhs) == 2 && len(rhs) == 1 {
			// x, ok = y
			lhs = lhs[:1]
		}

		// Match as much as we can.
		for i := 0; i < len(lhs) && i < len(rhs); i++ {
			x, y := lhs[i], rhs[i]
			if typeof[y] != "" {
				set(x, typeof[y], isDecl)
			} else {
				set(y, typeof[x], false)
			}
		}
	}

	expand := func(s string) string {
		typ := cfg.Type[s]
		if typ != nil && typ.Def != "" {
			return typ.Def
		}
		return s
	}

	// The main type check is a recursive algorithm implemented
	// by walkBeforeAfter(n, before, after).
	// Most of it is bottom-up, but in a few places we need
	// to know the type of the function we are checking.
	// The before function records that information on
	// the curfn stack.
	var curfn []*ast.FuncType

	before := func(n any) {
		// push function type on stack
		switch n := n.(type) {
		case *ast.FuncDecl:
			curfn = append(curfn, n.Type)
		case *ast.FuncLit:
			curfn = append(curfn, n.Type)
		}
	}

	// After is the real type checker.
	after := func(n any) {
		if n == nil {
			return
		}
		if false && reflect.TypeOf(n).Kind() == reflect.Pointer { // debugging trace
			defer func() {
				if t := typeof[n]; t != "" {
					pos := fset.Position(n.(ast.Node).Pos())
					fmt.Fprintf(os.Stderr, "%s: typeof[%s] = %s\n", pos, gofmt(n), t)
				}
			}()
		}

		switch n := n.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			// pop function type off stack
			curfn = curfn[:len(curfn)-1]

		case *ast.FuncType:
			typeof[n] = mkType(joinFunc(split(typeof[n.Params]), split(typeof[n.Results])))

		case *ast.FieldList:
			// Field list is concatenation of sub-lists.
			t := ""
			for _, field := range n.List {
				if t != "" {
					t += ", "
				}
				t += typeof[field]
			}
			typeof[n] = t

		case *ast.Field:
			// Field is one instance of the type per name.
			all := ""
			t := typeof[n.Type]
			if !isType(t) {
				// Create a type, because it is typically *T or *p.T
				// and we might care about that type.
				t = mkType(gofmt(n.Type))
				typeof[n.Type] = t
			}
			t = getType(t)
			if len(n.Names) == 0 {
				all = t
			} else {
				for _, id := range n.Names {
					if all != "" {
						all += ", "
					}
					all += t
					typeof[id.Obj] = t
					typeof[id] = t
				}
			}
			typeof[n] = all

		case *ast.ValueSpec:
			// var declaration. Use type if present.
			if n.Type != nil {
				t := typeof[n.Type]
				if !isType(t) {
					t = mkType(gofmt(n.Type))
					typeof[n.Type] = t
				}
				t = getType(t)
				for _, id := range n.Names {
					set(id, t, true)
				}
			}
			// Now treat same as assignment.
			typecheckAssign(makeExprList(n.Names), n.Values, true)

		case *ast.AssignStmt:
			typecheckAssign(n.Lhs, n.Rhs, n.Tok == token.DEFINE)

		case *ast.Ident:
			// Identifier can take its type from underlying object.
			if t := typeof[n.Obj]; t != "" {
				typeof[n] = t
			}

		case *ast.SelectorExpr:
			// Field or method.
			name := n.Sel.Name
			if t := typeof[n.X]; t != "" {
				t = strings.TrimPrefix(t, "*") // implicit *
				if typ := cfg.Type[t]; typ != nil {
					if t := typ.dot(cfg, name); t != "" {
						typeof[n] = t
						return
					}
				}
				tt := typeof[t+"."+name]
				if isType(tt) {
					typeof[n] = getType(tt)
					return
				}
			}
			// Package selector.
			if x, ok := n.X.(*ast.Ident); ok && x.Obj == nil {
				str := x.Name + "." + name
				if cfg.Type[str] != nil {
					typeof[n] = mkType(str)
					return
				}
				if t := cfg.typeof(x.Name + "." + name); t != "" {
					typeof[n] = t
					return
				}
			}

		case *ast.CallExpr:
			// make(T) has type T.
			if isTopName(n.Fun, "make") && len(n.Args) >= 1 {
				typeof[n] = gofmt(n.Args[0])
				return
			}
			// new(T) has type *T
			if isTopName(n.Fun, "new") && len(n.Args) == 1 {
				typeof[n] = "*" + gofmt(n.Args[0])
				return
			}
			// Otherwise, use type of function to determine arguments.
			t := typeof[n.Fun]
			if t == "" {
				t = cfg.External[gofmt(n.Fun)]
			}
			in, out := splitFunc(t)
			if in == nil && out == nil {
				return
			}
			typeof[n] = join(out)
			for i, arg := range n.Args {
				if i >= len(in) {
					break
				}
				if typeof[arg] == "" {
					typeof[arg] = in[i]
				}
			}

		case *ast.TypeAssertExpr:
			// x.(type) has type of x.
			if n.Type == nil {
				typeof[n] = typeof[n.X]
				return
			}
			// x.(T) has type T.
			if t := typeof[n.Type]; isType(t) {
				typeof[n] = getType(t)
			} else {
				typeof[n] = gofmt(n.Type)
			}

		case *ast.SliceExpr:
			// x[i:j] has type of x.
			typeof[n] = typeof[n.X]

		case *ast.IndexExpr:
			// x[i] has key type of x's type.
			t := expand(typeof[n.X])
			if strings.HasPrefix(t, "[") || strings.HasPrefix(t, "map[") {
				// Lazy: assume there are no nested [] in the array
				// length or map key type.
				if _, elem, ok := strings.Cut(t, "]"); ok {
					typeof[n] = elem
				}
			}

		case *ast.StarExpr:
			// *x for x of type *T has type T when x is an expr.
			// We don't use the result when *x is a type, but
			// compute it anyway.
			t := expand(typeof[n.X])
			if isType(t) {
				typeof[n] = "type *" + getType(t)
			} else if strings.HasPrefix(t, "*") {
				typeof[n] = t[len("*"):]
			}

		case *ast.UnaryExpr:
			// &x for x of type T has type *T.
			t := typeof[n.X]
			if t != "" && n.Op == token.AND {
				typeof[n] = "*" + t
			}

		case *ast.CompositeLit:
			// T{...} has type T.
			typeof[n] = gofmt(n.Type)

			// Propagate types down to values used in the composite literal.
			t := expand(typeof[n])
			if strings.HasPrefix(t, "[") { // array or slice
				// Lazy: assume there are no nested [] in the array length.
				if _, et, ok := strings.Cut(t, "]"); ok {
					for _, e := range n.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok {
							e = kv.Value
						}
						if typeof[e] == "" {
							typeof[e] = et
						}
					}
				}
			}
			if strings.HasPrefix(t, "map[") { // map
				// Lazy: assume there are no nested [] in the map key type.
				if kt, vt, ok := strings.Cut(t[len("map["):], "]"); ok {
					for _, e := range n.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok {
							if typeof[kv.Key] == "" {
								typeof[kv.Key] = kt
							}
							if typeof[kv.Value] == "" {
								typeof[kv.Value] = vt
							}
						}
					}
				}
			}
			if typ := cfg.Type[t]; typ != nil && len(typ.Field) > 0 { // struct
				for _, e := range n.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if ft := typ.Field[fmt.Sprintf("%s", kv.Key)]; ft != "" {
							if typeof[kv.Value] == "" {
								typeof[kv.Value] = ft
							}
						}
					}
				}
			}

		case *ast.ParenExpr:
			// (x) has type of x.
			typeof[n] = typeof[n.X]

		case *ast.RangeStmt:
			t := expand(typeof[n.X])
			if t == "" {
				return
			}
			var key, value string
			if t == "string" {
				key, value = "int", "rune"
			} else if strings.HasPrefix(t, "[") {
				key = "int"
				_, value, _ = strings.Cut(t, "]")
			} else if strings.HasPrefix(t, "map[") {
				if k, v, ok := strings.Cut(t[len("map["):], "]"); ok {
					key, value = k, v
				}
			}
			changed := false
			if n.Key != nil && key != "" {
				changed = true
				set(n.Key, key, n.Tok == token.DEFINE)
			}
			if n.Value != nil && value != "" {
				changed = true
				set(n.Value, value, n.Tok == token.DEFINE)
			}
			// Ugly failure of vision: already type-checked body.
			// Do it again now that we have that type info.
			if changed {
				typecheck1(cfg, n.Body, typeof, assign)
			}

		case *ast.TypeSwitchStmt:
			// Type of variable changes for each case in type switch,
			// but go/parser generates just one variable.
			// Repeat type check for each case with more precise
			// type information.
			as, ok := n.Assign.(*ast.AssignStmt)
			if !ok {
				return
			}
			varx, ok := as.Lhs[0].(*ast.Ident)
			if !ok {
				return
			}
			t := typeof[varx]
			for _, cas := range n.Body.List {
				cas := cas.(*ast.CaseClause)
				if len(cas.List) == 1 {
					// Variable has specific type only when there is
					// exactly one type in the case list.
					if tt := typeof[cas.List[0]]; isType(tt) {
						tt = getType(tt)
						typeof[varx] = tt
						typeof[varx.Obj] = tt
						typecheck1(cfg, cas.Body, typeof, assign)
					}
				}
			}
			// Restore t.
			typeof[varx] = t
			typeof[varx.Obj] = t

		case *ast.ReturnStmt:
			if len(curfn) == 0 {
				// Probably can't happen.
				return
			}
			f := curfn[len(curfn)-1]
			res := n.Results
			if f.Results != nil {
				t := split(typeof[f.Results])
				for i := 0; i < len(res) && i < len(t); i++ {
					set(res[i], t[i], false)
				}
			}

		case *ast.BinaryExpr:
			// Propagate types across binary ops that require two args of the same type.
			switch n.Op {
			case token.EQL, token.NEQ: // TODO: more cases. This is enough for the cftype fix.
				if typeof[n.X] != "" && typeof[n.Y] == "" {
					typeof[n.Y] = typeof[n.X]
				}
				if typeof[n.X] == "" && typeof[n.Y] != "" {
					typeof[n.X] = typeof[n.Y]
				}
			}
		}
	}
	walkBeforeAfter(f, before, after)
}

// Convert between function type strings and lists of types.
// Using strings makes this a little harder, but it makes
// a lot of the rest of the code easier. This will all go away
// when we can use go/typechecker directly.

// splitFunc splits "func(x,y,z) (a,b,c)" into ["x", "y", "z"] and ["a", "b", "c"].
func splitFunc(s string) (in, out []string) {
	if !strings.HasPrefix(s, "func(") {
		return nil, nil
	}

	i := len("func(") // index of beginning of 'in' arguments
	nparen := 0
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '(':
			nparen++
		case ')':
			nparen--
			if nparen < 0 {
				// found end of parameter list
				out := strings.TrimSpace(s[j+1:])
				if len(out) >= 2 && out[0] == '(' && out[len(out)-1] == ')' {
					out = out[1 : len(out)-1]
				}
				return split(s[i:j]), split(out)
			}
		}
	}
	return nil, nil
}

// joinFunc is the inverse of splitFunc.
func joinFunc(in, out []string) string {
	outs := ""
	if len(out) == 1 {
		outs = " " + out[0]
	} else if len(out) > 1 {
		outs = " (" + join(out) + ")"
	}
	return "func(" + join(in) + ")" + outs
}

// split splits "int, float" into ["int", "float"] and splits "" into [].
func split(s string) []string {
	out := []string{}
	i := 0 // current type being scanned is s[i:j].
	nparen := 0
	for j := 0; j < len(s); j++ {
		switch s[j] {
		case ' ':
			if i == j {
				i++
			}
		case '(':
			nparen++
		case ')':
			nparen--
			if nparen < 0 {
				// probably can't happen
				return nil
			}
		case ',':
			if nparen == 0 {
				if i < j {
					out = append(out, s[i:j])
				}
				i = j + 1
			}
		}
	}
	if nparen != 0 {
		// probably can't happen
		return nil
	}
	if i < len(s) {
		out = append(out, s[i:])
	}
	return out
}

// join is the inverse of split.
func join(x []string) string {
	return strings.Join(x, ", ")
}

"""



```