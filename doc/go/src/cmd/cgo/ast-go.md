Response:
My thought process for analyzing the provided Go code snippet went something like this:

1. **Understand the Context:** The first line, `// go/src/cmd/cgo/ast.go`, immediately tells me this code is part of the `cgo` tool within the Go standard library. `cgo` is the tool that enables Go programs to interact with C code. Knowing this is crucial for interpreting the functions.

2. **Identify Key Data Structures:** The code defines a `File` struct (although its full definition isn't shown in this snippet). Several maps within `File` are declared: `Name`, `NamePos`, `Ref`, `Calls`, `ExpFunc`. These likely store information extracted from the Go source code.

3. **Analyze the `parse` Function:** This function uses the standard `go/parser` package to parse Go source code into an Abstract Syntax Tree (AST). The flags passed to `parser.ParseFile` (`parser.SkipObjectResolution|parser.ParseComments`) indicate that it's parsing with comments but skipping the resolution of object identifiers. The error handling suggests a focus on robust parsing, especially concerning multiple errors.

4. **Examine the `ParseGo` Method:** This is the core of the provided snippet. It's clearly responsible for processing a Go source file in the context of `cgo`. Here's a breakdown of my sub-steps in analyzing `ParseGo`:

    * **Dual Parsing:** The code parses the file *twice*: once with comments (`ast1`) and once without (`ast2`). This immediately suggests that comments are important for some parts of the process (like extracting the C preamble) but not for others (like the core AST manipulation).
    * **Import "C":** The code iterates through the declarations looking for `import "C"`. This is the hallmark of `cgo`.
    * **C Preamble Extraction:**  The code specifically extracts comments associated with the `import "C"` statement. This is the mechanism by which you embed C code within your Go file for `cgo` to process. The `#line` directives indicate how the C code's line numbers are tracked.
    * **Method on C Types Restriction:** The code checks for and rejects attempts to define methods on types imported from "C". This makes sense as those types are defined in the C world.
    * **Stripping/Replacing Import "C":** The code handles the `import "C"` differently depending on the `godefs` flag (which likely relates to generating Go type definitions from C). If `godefs` is true, it removes the import. Otherwise, it replaces it with `_ "unsafe"`. This is a key `cgo` behavior to keep the Go code compilable even after `cgo` has processed it.
    * **Accumulating References to C:** The `f.walk(ast2, ctxProg, (*File).validateIdents)` and `f.walk(ast2, ctxProg, (*File).saveExprs)` calls, along with the `saveRef` and `saveCall` methods, clearly indicate that the code is identifying and storing all uses of `C.xxx`. This is essential for `cgo` to understand how Go code interacts with the embedded C code.
    * **Accumulating Exported Functions:** The `saveExport` and `saveExport2` methods and the `ExpFunc` field suggest the code is identifying Go functions that are intended to be exported and made accessible from C. The `//export` comment is the marker for this.
    * **AST Walking:** The `walk` function is a standard AST traversal mechanism. It recursively visits each node in the AST and calls a provided `visit` function. The `astContext` parameter likely helps differentiate how different parts of the AST are being processed.

5. **Analyze Helper Functions:**  Functions like `sourceLine`, `commentText`, `validateIdents`, `saveExprs`, `saveRef`, `saveCall`, `saveExport`, and `saveExport2` are all focused on extracting and processing specific information from the AST related to `cgo`'s functionality. `unparen` is a common utility for removing parentheses in AST expressions.

6. **Infer Overall Functionality:** Based on the identified key elements, I concluded that this code snippet is responsible for the *initial parsing and analysis* stage of the `cgo` tool. It takes Go source code, identifies the `import "C"` statement, extracts the C preamble, finds all uses of `C.xxx`, identifies exported Go functions, and builds internal data structures to represent this information for later stages of the `cgo` process (like generating C wrappers and Go stubs).

7. **Construct Examples:**  To illustrate the functionality, I thought about the core use cases of `cgo`: embedding C code and exporting Go functions. This led to the example demonstrating the C preamble and the example showing the `//export` comment.

8. **Identify Potential Errors:**  Knowing how `cgo` works, I considered common mistakes users make, such as forgetting the `import "C"` or having invalid C syntax in the preamble. The "cannot rename import "C"" error message in the code itself also pointed to a specific potential mistake.

By following this structured analysis, I could break down the code into manageable parts, understand the purpose of each part in the context of `cgo`, and ultimately explain its functionality and provide relevant examples.
这段代码是 Go 语言 `cgo` 工具的一部分，位于 `go/src/cmd/cgo/ast.go` 文件中。它的主要功能是**解析 Go 源代码，提取与 C 语言互操作相关的信息，并构建用于后续处理的内部表示 (AST)。**

更具体地说，这段代码做了以下事情：

1. **解析 Go 代码:**
   - 使用 `go/parser` 包将 Go 源代码解析成抽象语法树 (AST)。
   - 提供了两个解析函数 `parse`，一个用于解析包含注释的 AST (`ast1`)，另一个用于解析不包含注释的 AST (`ast2`)。这样做是为了在处理注释时有更精细的控制。

2. **处理 `import "C"`:**
   - 查找 `import "C"` 语句，这是 `cgo` 的关键标识。
   - 提取与 `import "C"` 语句相关的注释，这些注释被认为是 C 语言的序言 (preamble)。
   - 检查是否尝试重命名 `import "C"`，并报错。
   - 在非 `godefs` 模式下，将 `import "C"` 替换为 `_ "unsafe"`，以保持 Go 代码的语法有效性，因为在后续处理中 `cgo` 会生成相应的 C 代码。

3. **识别对 C 代码的引用:**
   - 遍历 AST，查找对 `C.xxx` 的引用，例如 `C.int`, `C.malloc` 等。
   - 将这些引用存储在 `File` 结构体的 `Ref` 字段中，方便后续生成 C 代码。
   - 检查一些不允许直接引用的 C 符号，例如 `errno` 和 `_CMalloc`。

4. **识别需要导出的 Go 函数:**
   - 遍历 AST，查找带有 `//export <函数名>` 形式注释的 Go 函数。
   - 将这些需要导出的函数信息（函数定义、导出名称、文档注释）存储在 `File` 结构体的 `ExpFunc` 字段中。

5. **进行语法检查和名称验证:**
   - 检查标识符是否与 `cgo` 生成的标识符冲突。
   - 阻止在 C 类型上定义新的方法。

6. **构建内部表示:**
   - 使用 `File` 结构体来存储从 Go 源代码中提取的与 C 互操作相关的信息，例如 C 序言、对 C 代码的引用、导出的 Go 函数等。
   - 使用 `walk` 函数遍历 AST，并在遍历过程中执行各种操作，例如保存引用、保存调用、保存导出函数等。

**它可以被认为是 `cgo` 工具的预处理阶段，负责理解 Go 代码中与 C 语言的交互意图。**

## Go 代码举例说明

假设我们有以下 Go 代码文件 `example.go`:

```go
package main

/*
#include <stdio.h>
#include <stdlib.h>

void print_message(const char *msg) {
    printf("%s\n", msg);
}
*/
import "C"
import "fmt"
import "unsafe"

//export SayHello
func SayHello(name string) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	C.print_message(cName)
}

func main() {
	fmt.Println("Calling C function:")
	C.print_message(C.CString("Hello from Go!"))
}
```

当 `cgo` 处理这个文件时，`ast.go` 中的代码会执行以下操作：

**假设输入:**  `example.go` 文件的内容。

**推理过程:**

1. **解析:**  `parse` 函数会被调用两次，分别生成包含注释和不包含注释的 AST。
2. **处理 `import "C"`:**
   - 检测到 `import "C"`。
   - 提取 C 序言：`#include <stdio.h>\n#include <stdlib.h>\n\nvoid print_message(const char *msg) {\n    printf("%s\\n", msg);\n}\n`
   - 将 `import "C"` 替换为 `_ "unsafe"` (如果不是 `godefs` 模式)。
3. **识别对 C 代码的引用:**
   - 找到 `C.CString`, `C.free`, `C.print_message` 等引用。
   - 这些引用会被添加到 `f.Ref` 中，并记录其上下文（例如，是否在函数调用中）。
4. **识别导出的 Go 函数:**
   - 找到带有 `//export SayHello` 注释的 `SayHello` 函数。
   - 将 `SayHello` 的信息（函数定义、导出名 "SayHello"）添加到 `f.ExpFunc` 中。

**可能的输出 (内部数据结构的片段):**

```
File {
    Package: "main",
    Preamble: "#line 3 \"example.go\"\n#include <stdio.h>\n#include <stdlib.h>\n\nvoid print_message(const char *msg) {\n    printf("%s\\n", msg);\n}\n#line 1 \"cgo-generated-wrapper\"\n",
    Ref: []*Ref{
        {Name: &Name{Go: "CString"}, Expr: *ast.SelectorExpr{X: *ast.Ident{Name: "C"}, Sel: *ast.Ident{Name: "CString"}}},
        {Name: &Name{Go: "free"}, Expr: *ast.SelectorExpr{X: *ast.Ident{Name: "C"}, Sel: *ast.Ident{Name: "free"}}},
        {Name: &Name{Go: "print_message"}, Expr: *ast.SelectorExpr{X: *ast.Ident{Name: "C"}, Sel: *ast.Ident{Name: "print_message"}}},
        // ... 更多的引用
    },
    ExpFunc: []*ExpFunc{
        {
            Func: *ast.FuncDecl{
                Name: *ast.Ident{Name: "SayHello"},
                // ... 函数的其他信息
            },
            ExpName: "SayHello",
            Doc: "", // 可能包含其他文档注释
        },
    },
    // ... 其他字段
}
```

## 命令行参数的具体处理

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `cgo` 工具的主入口文件中 (可能是 `go/src/cmd/cgo/main.go`)。

但是，这段代码中与命令行参数相关的概念是 `godefs` 标志。`*godefs` 是一个包级别的布尔指针，它可能通过命令行参数进行设置。

- 如果 `godefs` 为 `true`，则 `cgo` 的行为会发生变化，它会生成 C 代码的 Go 类型定义，而不是通常的 C 包装器。在这种模式下，`import "C"` 会被直接从 AST 中移除。
- 如果 `godefs` 为 `false` (默认情况)，则 `import "C"` 会被替换为 `_ "unsafe"`。

因此，虽然这段代码不直接解析命令行参数，但它会根据全局的 `godefs` 标志来调整其行为。

## 使用者易犯错的点

1. **忘记 `import "C"`:**  如果 Go 文件中没有 `import "C"`，`cgo` 会报错。
   ```go
   package main

   /*
   #include <stdio.h>
   */
   // import "C"  // 忘记导入
   import "fmt"

   func main() {
       // C.printf("Hello from C!\n") // 编译错误
       fmt.Println("Hello")
   }
   ```
   **错误信息:** `example.go: cannot find import "C"`

2. **C 序言语法错误:** C 序言中的语法错误会导致 `cgo` 解析失败。
   ```go
   package main

   /*
   int main() // 错误的 C 函数定义
   {
       printf("Hello\n");
       return 0;
   }
   */
   import "C"

   func main() {}
   ```
   **错误信息:** 具体的 C 语法错误信息，例如：`example.go:3:1: expected '=', ',', ';', 'asm' or '__attribute__'`

3. **`//export` 注释格式错误:** `//export` 注释必须紧跟在要导出的函数声明之前，并且格式必须正确。
   ```go
   package main

   import "C"

   /*
   */
   //export  MyFunc // 导出名称缺失
   func MyFunc() {}
   ```
   **错误信息:** `example.go:7:1: export missing name`

   ```go
   package main

   import "C"

   /*
   */
   // export MyFunc
   func AnotherFunc() {} // 导出注释与函数名不符
   ```
   **错误信息:** `example.go:7:1: export comment has wrong name "MyFunc", want "AnotherFunc"`

4. **在 C 类型上定义方法:**  Go 不允许在导入自 C 的类型上定义新的方法。
   ```go
   package main

   /*
   typedef int my_int;
   */
   import "C"

   type MyInt C.my_int

   func (i MyInt) String() string { // 尝试在 C 类型上定义方法
       return "my int"
   }

   func main() {}
   ```
   **错误信息:** `example.go:9:6: cannot define new methods on non-local type C.my_int`

理解 `ast.go` 的功能对于深入了解 `cgo` 的工作原理至关重要，它可以帮助开发者避免在使用 `cgo` 时犯一些常见的错误。

Prompt: 
```
这是路径为go/src/cmd/cgo/ast.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Parse input AST and prepare Prog structure.

package main

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"strings"
)

func parse(name string, src []byte, flags parser.Mode) *ast.File {
	ast1, err := parser.ParseFile(fset, name, src, flags)
	if err != nil {
		if list, ok := err.(scanner.ErrorList); ok {
			// If err is a scanner.ErrorList, its String will print just
			// the first error and then (+n more errors).
			// Instead, turn it into a new Error that will return
			// details for all the errors.
			for _, e := range list {
				fmt.Fprintln(os.Stderr, e)
			}
			os.Exit(2)
		}
		fatalf("parsing %s: %s", name, err)
	}
	return ast1
}

func sourceLine(n ast.Node) int {
	return fset.Position(n.Pos()).Line
}

// ParseGo populates f with information learned from the Go source code
// which was read from the named file. It gathers the C preamble
// attached to the import "C" comment, a list of references to C.xxx,
// a list of exported functions, and the actual AST, to be rewritten and
// printed.
func (f *File) ParseGo(abspath string, src []byte) {
	// Two different parses: once with comments, once without.
	// The printer is not good enough at printing comments in the
	// right place when we start editing the AST behind its back,
	// so we use ast1 to look for the doc comments on import "C"
	// and on exported functions, and we use ast2 for translating
	// and reprinting.
	// In cgo mode, we ignore ast2 and just apply edits directly
	// the text behind ast1. In godefs mode we modify and print ast2.
	ast1 := parse(abspath, src, parser.SkipObjectResolution|parser.ParseComments)
	ast2 := parse(abspath, src, parser.SkipObjectResolution)

	f.Package = ast1.Name.Name
	f.Name = make(map[string]*Name)
	f.NamePos = make(map[*Name]token.Pos)

	// In ast1, find the import "C" line and get any extra C preamble.
	sawC := false
	for _, decl := range ast1.Decls {
		switch decl := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				s, ok := spec.(*ast.ImportSpec)
				if !ok || s.Path.Value != `"C"` {
					continue
				}
				sawC = true
				if s.Name != nil {
					error_(s.Path.Pos(), `cannot rename import "C"`)
				}
				cg := s.Doc
				if cg == nil && len(decl.Specs) == 1 {
					cg = decl.Doc
				}
				if cg != nil {
					if strings.ContainsAny(abspath, "\r\n") {
						// This should have been checked when the file path was first resolved,
						// but we double check here just to be sure.
						fatalf("internal error: ParseGo: abspath contains unexpected newline character: %q", abspath)
					}
					f.Preamble += fmt.Sprintf("#line %d %q\n", sourceLine(cg), abspath)
					f.Preamble += commentText(cg) + "\n"
					f.Preamble += "#line 1 \"cgo-generated-wrapper\"\n"
				}
			}

		case *ast.FuncDecl:
			// Also, reject attempts to declare methods on C.T or *C.T.
			// (The generated code would otherwise accept this
			// invalid input; see issue #57926.)
			if decl.Recv != nil && len(decl.Recv.List) > 0 {
				recvType := decl.Recv.List[0].Type
				if recvType != nil {
					t := recvType
					if star, ok := unparen(t).(*ast.StarExpr); ok {
						t = star.X
					}
					if sel, ok := unparen(t).(*ast.SelectorExpr); ok {
						var buf strings.Builder
						format.Node(&buf, fset, recvType)
						error_(sel.Pos(), `cannot define new methods on non-local type %s`, &buf)
					}
				}
			}
		}

	}
	if !sawC {
		error_(ast1.Package, `cannot find import "C"`)
	}

	// In ast2, strip the import "C" line.
	if *godefs {
		w := 0
		for _, decl := range ast2.Decls {
			d, ok := decl.(*ast.GenDecl)
			if !ok {
				ast2.Decls[w] = decl
				w++
				continue
			}
			ws := 0
			for _, spec := range d.Specs {
				s, ok := spec.(*ast.ImportSpec)
				if !ok || s.Path.Value != `"C"` {
					d.Specs[ws] = spec
					ws++
				}
			}
			if ws == 0 {
				continue
			}
			d.Specs = d.Specs[0:ws]
			ast2.Decls[w] = d
			w++
		}
		ast2.Decls = ast2.Decls[0:w]
	} else {
		for _, decl := range ast2.Decls {
			d, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range d.Specs {
				if s, ok := spec.(*ast.ImportSpec); ok && s.Path.Value == `"C"` {
					// Replace "C" with _ "unsafe", to keep program valid.
					// (Deleting import statement or clause is not safe if it is followed
					// in the source by an explicit semicolon.)
					f.Edit.Replace(f.offset(s.Path.Pos()), f.offset(s.Path.End()), `_ "unsafe"`)
				}
			}
		}
	}

	// Accumulate pointers to uses of C.x.
	if f.Ref == nil {
		f.Ref = make([]*Ref, 0, 8)
	}
	f.walk(ast2, ctxProg, (*File).validateIdents)
	f.walk(ast2, ctxProg, (*File).saveExprs)

	// Accumulate exported functions.
	// The comments are only on ast1 but we need to
	// save the function bodies from ast2.
	// The first walk fills in ExpFunc, and the
	// second walk changes the entries to
	// refer to ast2 instead.
	f.walk(ast1, ctxProg, (*File).saveExport)
	f.walk(ast2, ctxProg, (*File).saveExport2)

	f.Comments = ast1.Comments
	f.AST = ast2
}

// Like ast.CommentGroup's Text method but preserves
// leading blank lines, so that line numbers line up.
func commentText(g *ast.CommentGroup) string {
	pieces := make([]string, 0, len(g.List))
	for _, com := range g.List {
		c := com.Text
		// Remove comment markers.
		// The parser has given us exactly the comment text.
		switch c[1] {
		case '/':
			//-style comment (no newline at the end)
			c = c[2:] + "\n"
		case '*':
			/*-style comment */
			c = c[2 : len(c)-2]
		}
		pieces = append(pieces, c)
	}
	return strings.Join(pieces, "")
}

func (f *File) validateIdents(x interface{}, context astContext) {
	if x, ok := x.(*ast.Ident); ok {
		if f.isMangledName(x.Name) {
			error_(x.Pos(), "identifier %q may conflict with identifiers generated by cgo", x.Name)
		}
	}
}

// Save various references we are going to need later.
func (f *File) saveExprs(x interface{}, context astContext) {
	switch x := x.(type) {
	case *ast.Expr:
		switch (*x).(type) {
		case *ast.SelectorExpr:
			f.saveRef(x, context)
		}
	case *ast.CallExpr:
		f.saveCall(x, context)
	}
}

// Save references to C.xxx for later processing.
func (f *File) saveRef(n *ast.Expr, context astContext) {
	sel := (*n).(*ast.SelectorExpr)
	// For now, assume that the only instance of capital C is when
	// used as the imported package identifier.
	// The parser should take care of scoping in the future, so
	// that we will be able to distinguish a "top-level C" from a
	// local C.
	if l, ok := sel.X.(*ast.Ident); !ok || l.Name != "C" {
		return
	}
	if context == ctxAssign2 {
		context = ctxExpr
	}
	if context == ctxEmbedType {
		error_(sel.Pos(), "cannot embed C type")
	}
	goname := sel.Sel.Name
	if goname == "errno" {
		error_(sel.Pos(), "cannot refer to errno directly; see documentation")
		return
	}
	if goname == "_CMalloc" {
		error_(sel.Pos(), "cannot refer to C._CMalloc; use C.malloc")
		return
	}
	if goname == "malloc" {
		goname = "_CMalloc"
	}
	name := f.Name[goname]
	if name == nil {
		name = &Name{
			Go: goname,
		}
		f.Name[goname] = name
		f.NamePos[name] = sel.Pos()
	}
	f.Ref = append(f.Ref, &Ref{
		Name:    name,
		Expr:    n,
		Context: context,
	})
}

// Save calls to C.xxx for later processing.
func (f *File) saveCall(call *ast.CallExpr, context astContext) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	if l, ok := sel.X.(*ast.Ident); !ok || l.Name != "C" {
		return
	}
	c := &Call{Call: call, Deferred: context == ctxDefer}
	f.Calls = append(f.Calls, c)
}

// If a function should be exported add it to ExpFunc.
func (f *File) saveExport(x interface{}, context astContext) {
	n, ok := x.(*ast.FuncDecl)
	if !ok {
		return
	}

	if n.Doc == nil {
		return
	}
	for _, c := range n.Doc.List {
		if !strings.HasPrefix(c.Text, "//export ") {
			continue
		}

		name := strings.TrimSpace(c.Text[9:])
		if name == "" {
			error_(c.Pos(), "export missing name")
		}

		if name != n.Name.Name {
			error_(c.Pos(), "export comment has wrong name %q, want %q", name, n.Name.Name)
		}

		doc := ""
		for _, c1 := range n.Doc.List {
			if c1 != c {
				doc += c1.Text + "\n"
			}
		}

		f.ExpFunc = append(f.ExpFunc, &ExpFunc{
			Func:    n,
			ExpName: name,
			Doc:     doc,
		})
		break
	}
}

// Make f.ExpFunc[i] point at the Func from this AST instead of the other one.
func (f *File) saveExport2(x interface{}, context astContext) {
	n, ok := x.(*ast.FuncDecl)
	if !ok {
		return
	}

	for _, exp := range f.ExpFunc {
		if exp.Func.Name.Name == n.Name.Name {
			exp.Func = n
			break
		}
	}
}

type astContext int

const (
	ctxProg astContext = iota
	ctxEmbedType
	ctxType
	ctxStmt
	ctxExpr
	ctxField
	ctxParam
	ctxAssign2 // assignment of a single expression to two variables
	ctxSwitch
	ctxTypeSwitch
	ctxFile
	ctxDecl
	ctxSpec
	ctxDefer
	ctxCall  // any function call other than ctxCall2
	ctxCall2 // function call whose result is assigned to two variables
	ctxSelector
)

// walk walks the AST x, calling visit(f, x, context) for each node.
func (f *File) walk(x interface{}, context astContext, visit func(*File, interface{}, astContext)) {
	visit(f, x, context)
	switch n := x.(type) {
	case *ast.Expr:
		f.walk(*n, context, visit)

	// everything else just recurs
	default:
		f.walkUnexpected(x, context, visit)

	case nil:

	// These are ordered and grouped to match ../../go/ast/ast.go
	case *ast.Field:
		if len(n.Names) == 0 && context == ctxField {
			f.walk(&n.Type, ctxEmbedType, visit)
		} else {
			f.walk(&n.Type, ctxType, visit)
		}
	case *ast.FieldList:
		for _, field := range n.List {
			f.walk(field, context, visit)
		}
	case *ast.BadExpr:
	case *ast.Ident:
	case *ast.Ellipsis:
		f.walk(&n.Elt, ctxType, visit)
	case *ast.BasicLit:
	case *ast.FuncLit:
		f.walk(n.Type, ctxType, visit)
		f.walk(n.Body, ctxStmt, visit)
	case *ast.CompositeLit:
		f.walk(&n.Type, ctxType, visit)
		f.walk(n.Elts, ctxExpr, visit)
	case *ast.ParenExpr:
		f.walk(&n.X, context, visit)
	case *ast.SelectorExpr:
		f.walk(&n.X, ctxSelector, visit)
	case *ast.IndexExpr:
		f.walk(&n.X, ctxExpr, visit)
		f.walk(&n.Index, ctxExpr, visit)
	case *ast.SliceExpr:
		f.walk(&n.X, ctxExpr, visit)
		if n.Low != nil {
			f.walk(&n.Low, ctxExpr, visit)
		}
		if n.High != nil {
			f.walk(&n.High, ctxExpr, visit)
		}
		if n.Max != nil {
			f.walk(&n.Max, ctxExpr, visit)
		}
	case *ast.TypeAssertExpr:
		f.walk(&n.X, ctxExpr, visit)
		f.walk(&n.Type, ctxType, visit)
	case *ast.CallExpr:
		if context == ctxAssign2 {
			f.walk(&n.Fun, ctxCall2, visit)
		} else {
			f.walk(&n.Fun, ctxCall, visit)
		}
		f.walk(n.Args, ctxExpr, visit)
	case *ast.StarExpr:
		f.walk(&n.X, context, visit)
	case *ast.UnaryExpr:
		f.walk(&n.X, ctxExpr, visit)
	case *ast.BinaryExpr:
		f.walk(&n.X, ctxExpr, visit)
		f.walk(&n.Y, ctxExpr, visit)
	case *ast.KeyValueExpr:
		f.walk(&n.Key, ctxExpr, visit)
		f.walk(&n.Value, ctxExpr, visit)

	case *ast.ArrayType:
		f.walk(&n.Len, ctxExpr, visit)
		f.walk(&n.Elt, ctxType, visit)
	case *ast.StructType:
		f.walk(n.Fields, ctxField, visit)
	case *ast.FuncType:
		if tparams := funcTypeTypeParams(n); tparams != nil {
			f.walk(tparams, ctxParam, visit)
		}
		f.walk(n.Params, ctxParam, visit)
		if n.Results != nil {
			f.walk(n.Results, ctxParam, visit)
		}
	case *ast.InterfaceType:
		f.walk(n.Methods, ctxField, visit)
	case *ast.MapType:
		f.walk(&n.Key, ctxType, visit)
		f.walk(&n.Value, ctxType, visit)
	case *ast.ChanType:
		f.walk(&n.Value, ctxType, visit)

	case *ast.BadStmt:
	case *ast.DeclStmt:
		f.walk(n.Decl, ctxDecl, visit)
	case *ast.EmptyStmt:
	case *ast.LabeledStmt:
		f.walk(n.Stmt, ctxStmt, visit)
	case *ast.ExprStmt:
		f.walk(&n.X, ctxExpr, visit)
	case *ast.SendStmt:
		f.walk(&n.Chan, ctxExpr, visit)
		f.walk(&n.Value, ctxExpr, visit)
	case *ast.IncDecStmt:
		f.walk(&n.X, ctxExpr, visit)
	case *ast.AssignStmt:
		f.walk(n.Lhs, ctxExpr, visit)
		if len(n.Lhs) == 2 && len(n.Rhs) == 1 {
			f.walk(n.Rhs, ctxAssign2, visit)
		} else {
			f.walk(n.Rhs, ctxExpr, visit)
		}
	case *ast.GoStmt:
		f.walk(n.Call, ctxExpr, visit)
	case *ast.DeferStmt:
		f.walk(n.Call, ctxDefer, visit)
	case *ast.ReturnStmt:
		f.walk(n.Results, ctxExpr, visit)
	case *ast.BranchStmt:
	case *ast.BlockStmt:
		f.walk(n.List, context, visit)
	case *ast.IfStmt:
		f.walk(n.Init, ctxStmt, visit)
		f.walk(&n.Cond, ctxExpr, visit)
		f.walk(n.Body, ctxStmt, visit)
		f.walk(n.Else, ctxStmt, visit)
	case *ast.CaseClause:
		if context == ctxTypeSwitch {
			context = ctxType
		} else {
			context = ctxExpr
		}
		f.walk(n.List, context, visit)
		f.walk(n.Body, ctxStmt, visit)
	case *ast.SwitchStmt:
		f.walk(n.Init, ctxStmt, visit)
		f.walk(&n.Tag, ctxExpr, visit)
		f.walk(n.Body, ctxSwitch, visit)
	case *ast.TypeSwitchStmt:
		f.walk(n.Init, ctxStmt, visit)
		f.walk(n.Assign, ctxStmt, visit)
		f.walk(n.Body, ctxTypeSwitch, visit)
	case *ast.CommClause:
		f.walk(n.Comm, ctxStmt, visit)
		f.walk(n.Body, ctxStmt, visit)
	case *ast.SelectStmt:
		f.walk(n.Body, ctxStmt, visit)
	case *ast.ForStmt:
		f.walk(n.Init, ctxStmt, visit)
		f.walk(&n.Cond, ctxExpr, visit)
		f.walk(n.Post, ctxStmt, visit)
		f.walk(n.Body, ctxStmt, visit)
	case *ast.RangeStmt:
		f.walk(&n.Key, ctxExpr, visit)
		f.walk(&n.Value, ctxExpr, visit)
		f.walk(&n.X, ctxExpr, visit)
		f.walk(n.Body, ctxStmt, visit)

	case *ast.ImportSpec:
	case *ast.ValueSpec:
		f.walk(&n.Type, ctxType, visit)
		if len(n.Names) == 2 && len(n.Values) == 1 {
			f.walk(&n.Values[0], ctxAssign2, visit)
		} else {
			f.walk(n.Values, ctxExpr, visit)
		}
	case *ast.TypeSpec:
		if tparams := typeSpecTypeParams(n); tparams != nil {
			f.walk(tparams, ctxParam, visit)
		}
		f.walk(&n.Type, ctxType, visit)

	case *ast.BadDecl:
	case *ast.GenDecl:
		f.walk(n.Specs, ctxSpec, visit)
	case *ast.FuncDecl:
		if n.Recv != nil {
			f.walk(n.Recv, ctxParam, visit)
		}
		f.walk(n.Type, ctxType, visit)
		if n.Body != nil {
			f.walk(n.Body, ctxStmt, visit)
		}

	case *ast.File:
		f.walk(n.Decls, ctxDecl, visit)

	case *ast.Package:
		for _, file := range n.Files {
			f.walk(file, ctxFile, visit)
		}

	case []ast.Decl:
		for _, d := range n {
			f.walk(d, context, visit)
		}
	case []ast.Expr:
		for i := range n {
			f.walk(&n[i], context, visit)
		}
	case []ast.Stmt:
		for _, s := range n {
			f.walk(s, context, visit)
		}
	case []ast.Spec:
		for _, s := range n {
			f.walk(s, context, visit)
		}
	}
}

// If x is of the form (T), unparen returns unparen(T), otherwise it returns x.
func unparen(x ast.Expr) ast.Expr {
	if p, isParen := x.(*ast.ParenExpr); isParen {
		x = unparen(p.X)
	}
	return x
}

"""



```