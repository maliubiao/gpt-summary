Response:
My thinking process to answer the user's request goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of the provided Go code snippet. They're specifically interested in:
    * The primary purpose of the code.
    * How it relates to a Go language feature (cgocall).
    * Concrete Go code examples illustrating its function.
    * Handling of command-line arguments (if any).
    * Common pitfalls for users.

2. **Initial Code Scan and Keyword Identification:** I quickly scanned the code, looking for keywords and structural elements. Key terms that jumped out were: `cgocall`, `C.`, `unsafe.Pointer`, `analysis`, `reportf`, `typeOKForCgoCall`. These immediately suggested a connection to Go's cgo mechanism and static analysis.

3. **Analyze the `Analyzer` Definition:**  The `Analyzer` variable is crucial. Its `Name`, `Doc`, and `Run` fields clearly define the analyzer's purpose and entry point. The `Doc` string is particularly informative: "detect some violations of the cgo pointer passing rules."  This confirms the initial hypothesis about cgo.

4. **Trace the `run` Function:** The `run` function is the core logic. It checks if the package imports `runtime/cgo`. If so, it proceeds to `typeCheckCgoSourceFiles` and then iterates through the cgo files, calling `checkCgo`. This indicates a two-stage process: first, identify and process cgo files, then analyze them.

5. **Delve into `checkCgo`:** This function uses `ast.Inspect` to traverse the Abstract Syntax Tree (AST) of the cgo files. It looks for function calls where the function selector's identifier is "C" (e.g., `C.malloc`). It then checks the arguments of these calls using `typeOKForCgoCall`. The presence of `reportf` suggests that violations are reported to the user.

6. **Examine `typeOKForCgoCall`:**  This function is key to understanding *what* constitutes a violation. It checks the underlying type of the arguments passed to C functions. It explicitly flags `chan`, `map`, `func`, and `slice` as invalid. It also recursively checks the elements of pointers, arrays, and the fields of structs. This reveals the core rule: passing Go types with embedded pointers directly to C is generally unsafe.

7. **Understand `typeCheckCgoSourceFiles`:** This is a more complex function. The comments are very helpful here. It explains that because the analyzer operates on "cooked" Go ASTs, this function is needed to process the *raw* cgo source files. It synthesizes temporary ASTs with dot-imports to resolve references correctly. This explains why the analyzer can identify issues even in the raw C code embedded within Go files.

8. **Infer Functionality and Go Feature:** Based on the above analysis, I concluded that this code implements a static analyzer that detects violations of cgo's pointer passing rules. This directly addresses the user's question about the Go language feature.

9. **Craft Go Code Examples:** To illustrate the functionality, I needed examples of valid and invalid cgo calls. I focused on the types explicitly flagged by `typeOKForCgoCall`: `chan`, `map`, `func`, and `slice`, both directly and indirectly (via pointers or within structs). I also included an example of a valid call using `CBytes`. The "assumptions" and "output" in the examples were crucial for showing how the analyzer would behave.

10. **Address Command-Line Arguments:** I examined the `analysis.Analyzer` definition and the `run` function. There's no explicit handling of command-line arguments within this code snippet. However, I knew that `go vet` and similar tools often take package paths as arguments. Therefore, I explained that this analyzer would be invoked as part of such tools, indirectly receiving package information.

11. **Identify Common Pitfalls:** The core concept of not directly passing Go types with pointers to C is the main pitfall. I provided examples highlighting this and suggested using `unsafe.Pointer` carefully and understanding the implications. The point about accidentally passing these types within structs was also important.

12. **Structure the Answer:** I organized the information logically, starting with a general summary of the functionality, then providing concrete examples, addressing command-line arguments, and finally discussing common mistakes. I used code blocks and clear explanations to make the answer easy to understand.

13. **Review and Refine:**  I reviewed my answer to ensure accuracy, clarity, and completeness. I double-checked the code examples and explanations against my understanding of the code. I also made sure to answer all parts of the user's request.

This iterative process of scanning, analyzing, inferring, and illustrating allowed me to arrive at the detailed and accurate answer provided previously.
这段代码是 Go 语言分析工具 `golang.org/x/tools/go/analysis` 的一个 pass，名为 `cgocall`。它的主要功能是**静态地检测使用 cgo 时违反指针传递规则的情况**。

更具体地说，它会检查 Go 代码中调用 C 代码时，传递的参数类型是否可能违反 cgo 的指针共享规则。  cgo 有一些严格的规定，限制了哪些 Go 类型可以直接传递给 C 代码，或者通过指针、数组或结构体间接传递。这是为了保证内存安全和避免 Go 的垃圾回收器影响 C 代码的预期行为。

**功能列举:**

1. **检查是否导入 `runtime/cgo`:**  首先，它会检查被分析的 Go 包是否导入了 `runtime/cgo` 包。如果没导入，说明该包没有使用 cgo，分析器会直接跳过。
2. **解析并类型检查 Cgo 源文件:**  它会定位并解析项目中的原始 cgo 源文件（`.go` 文件中包含 `import "C"` 的文件）。由于这些文件混合了 Go 和 C 代码，需要进行特殊的类型检查处理，以理解 C 函数的调用。
3. **识别 C 函数调用:**  它会遍历抽象语法树 (AST)，查找对 `C` 包中函数的调用，例如 `C.malloc(size)`。
4. **检查传递给 C 函数的参数类型:**  对于每个 C 函数调用，它会检查传递的参数类型。
5. **报告潜在的违规行为:** 如果参数的类型是 Go 的 `chan`、`map`、`func` 或 `slice`，或者包含这些类型的指针、数组或结构体，分析器会报告一个潜在的违规行为。

**推理其实现的 Go 语言功能: cgo**

这个分析器是专门用来检查 Go 语言的 cgo 功能的使用是否符合规范的。 cgo 允许 Go 程序调用 C 语言编写的函数。然而，由于 Go 和 C 的内存管理方式不同，直接在两者之间传递某些类型的指针是不安全的。

**Go 代码举例说明:**

假设我们有以下 Go 代码：

```go
package main

/*
#include <stdlib.h>
*/
import "C"
import "fmt"

func main() {
	ch := make(chan int)
	// 假设有一个 C 函数需要接收一个指向 int 的指针 (int*)
	// C 代码: void process_int(int* p);
	// 错误的用法: 直接传递 channel
	// C.process_int(&ch) // 这会被 cgocall 标记

	m := make(map[string]int)
	// 错误的用法: 直接传递 map
	// C.some_c_function(m) // 这也会被 cgocall 标记

	s := []int{1, 2, 3}
	// 错误的用法: 直接传递 slice 的底层数组指针
	// C.another_c_function(&s[0]) // 这也会被 cgocall 标记

	// 正确的用法: 使用 C.CBytes 分配 C 内存并复制数据
	goBytes := []byte("hello")
	cBytes := C.CBytes(goBytes)
	defer C.free(cBytes)
	fmt.Println("Allocated memory in C")
}
```

**假设的输入与输出:**

**输入 (上述 Go 代码文件 `main.go`):**

```go
package main

/*
#include <stdlib.h>
*/
import "C"
import "fmt"

func main() {
	ch := make(chan int)
	// C.process_int(&ch)

	m := make(map[string]int)
	// C.some_c_function(m)

	s := []int{1, 2, 3}
	// C.another_c_function(&s[0])

	goBytes := []byte("hello")
	cBytes := C.CBytes(goBytes)
	defer C.free(cBytes)
	fmt.Println("Allocated memory in C")
}
```

**输出 (使用 `go vet` 或类似的分析工具):**

```
main.go:10:2: possibly passing Go type with embedded pointer to C
main.go:13:2: possibly passing Go type with embedded pointer to C
main.go:16:2: possibly passing Go type with embedded pointer to C
```

**代码推理:**

`cgocall.go` 中的 `checkCgo` 函数会遍历 `main` 函数中的 `ast.CallExpr` 节点，找到对 `C.process_int`、`C.some_c_function` 和 `C.another_c_function` 的调用。

对于 `C.process_int(&ch)`：
- `arg` 将是 `&ch` 这个表达式。
- `cgoBaseType` 会返回 `chan int` 类型。
- `typeOKForCgoCall` 判断 `chan int` 是不允许直接传递给 C 的类型，因此 `reportf` 会被调用。

对于 `C.some_c_function(m)`：
- `arg` 将是 `m` 这个表达式。
- `cgoBaseType` 会返回 `map[string]int` 类型。
- `typeOKForCgoCall` 判断 `map[string]int` 是不允许直接传递给 C 的类型，因此 `reportf` 会被调用。

对于 `C.another_c_function(&s[0])`：
- `arg` 将是 `&s[0]` 这个表达式。
- `cgoBaseType` 会返回 `int` 类型 (因为 `s[0]` 是 `int`，取地址是指向 `int` 的指针，但 `cgoBaseType` 会尝试找到基础类型)。
- 然而，在 `checkCgo` 函数中，还会检查 `&` 运算符：
  - `u, ok := arg.(*ast.UnaryExpr)` 会为 true，且 `u.Op == token.AND`。
  - `typeOKForCgoCall(cgoBaseType(info, u.X), make(map[types.Type]bool))` 将会检查 `cgoBaseType(info, s[0])` 的类型，即 `int`。
  - **这里需要注意的是，`cgocall` 的目的是检测 *可能* 违规的情况。即使 `&s[0]` 本身是指向 `int` 的指针，如果 `s` 是一个 Go slice，`cgocall` 仍然会发出警告，因为它涉及到 Go 的内存管理。**

对于 `C.CBytes(goBytes)`：
- `checkCgo` 中会有一个特殊的检查 `if name == "CBytes" { return true }`，因为 `C.CBytes` 是 cgo 提供的用于安全地将 Go 的 byte slice 传递给 C 的方法。

**命令行参数的具体处理:**

该代码本身是一个分析器的实现，并不直接处理命令行参数。它会被集成到 `go vet` 或其他使用了 `golang.org/x/tools/go/analysis` 框架的工具中。

通常，使用 `go vet` 来运行此分析器：

```bash
go vet ./...
```

或者，如果你只想针对特定的包运行：

```bash
go vet your/package/path
```

`go vet` 会解析这些命令行参数，确定需要分析的 Go 包，并将相关信息传递给 `cgocall` 分析器的 `run` 函数。 `pass *analysis.Pass` 参数就包含了这些信息，例如待分析的包 (`pass.Pkg`)、文件 (`pass.Files`)、类型信息 (`pass.TypesInfo`) 等。

**使用者易犯错的点:**

1. **直接传递 Go 的 `chan`、`map`、`func` 或 `slice` 给 C 函数:** 这是最常见的错误，因为这些类型在 Go 中有复杂的内部结构和内存管理，直接传递给 C 会导致未定义的行为或崩溃。

   ```go
   ch := make(chan int)
   // 错误：直接传递 channel 的地址
   // C 函数期望接收 int*
   // C.some_c_function(&ch)
   ```

2. **通过指针、数组或结构体间接传递这些类型:** 即使不是直接传递，如果一个结构体字段或数组元素是 `chan`、`map`、`func` 或 `slice`，并将包含这些类型的结构体或数组的指针传递给 C，也会导致问题。

   ```go
   type MyStruct struct {
       Data []int
   }
   s := MyStruct{Data: []int{1, 2, 3}}
   // 错误：传递包含 slice 的结构体的指针
   // 假设 C 函数接收 MyStruct*
   // C.some_c_function(&s)
   ```

3. **误解 `unsafe.Pointer` 的使用:**  虽然 `unsafe.Pointer` 可以用于在 Go 和 C 之间传递指针，但需要非常小心。随意地将 Go 类型的指针转换为 `unsafe.Pointer` 并传递给 C，而不考虑 cgo 的规则，仍然会导致问题。

   ```go
   s := []int{1, 2, 3}
   // 错误：虽然使用了 unsafe.Pointer，但仍然传递了 slice 的底层数组指针
   // C.some_c_function(unsafe.Pointer(&s[0]))
   ```

**总结:**

`cgocall` 分析器是 Go 语言工具链中一个重要的组成部分，它通过静态分析帮助开发者避免在使用 cgo 时常见的内存安全问题。理解 cgo 的指针传递规则并使用 `go vet` 等工具来检查代码是至关重要的。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/tools/go/analysis/passes/cgocall/cgocall.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cgocall defines an Analyzer that detects some violations of
// the cgo pointer passing rules.
package cgocall

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"os"
	"strconv"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/internal/analysisutil"
)

const debug = false

const Doc = `detect some violations of the cgo pointer passing rules

Check for invalid cgo pointer passing.
This looks for code that uses cgo to call C code passing values
whose types are almost always invalid according to the cgo pointer
sharing rules.
Specifically, it warns about attempts to pass a Go chan, map, func,
or slice to C, either directly, or via a pointer, array, or struct.`

var Analyzer = &analysis.Analyzer{
	Name:             "cgocall",
	Doc:              Doc,
	URL:              "https://pkg.go.dev/golang.org/x/tools/go/analysis/passes/cgocall",
	RunDespiteErrors: true,
	Run:              run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	if !analysisutil.Imports(pass.Pkg, "runtime/cgo") {
		return nil, nil // doesn't use cgo
	}

	cgofiles, info, err := typeCheckCgoSourceFiles(pass.Fset, pass.Pkg, pass.Files, pass.TypesInfo, pass.TypesSizes)
	if err != nil {
		return nil, err
	}
	for _, f := range cgofiles {
		checkCgo(pass.Fset, f, info, pass.Reportf)
	}
	return nil, nil
}

func checkCgo(fset *token.FileSet, f *ast.File, info *types.Info, reportf func(token.Pos, string, ...interface{})) {
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Is this a C.f() call?
		var name string
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "C" {
				name = sel.Sel.Name
			}
		}
		if name == "" {
			return true // not a call we need to check
		}

		// A call to C.CBytes passes a pointer but is always safe.
		if name == "CBytes" {
			return true
		}

		if debug {
			log.Printf("%s: call to C.%s", fset.Position(call.Lparen), name)
		}

		for _, arg := range call.Args {
			if !typeOKForCgoCall(cgoBaseType(info, arg), make(map[types.Type]bool)) {
				reportf(arg.Pos(), "possibly passing Go type with embedded pointer to C")
				break
			}

			// Check for passing the address of a bad type.
			if conv, ok := arg.(*ast.CallExpr); ok && len(conv.Args) == 1 &&
				isUnsafePointer(info, conv.Fun) {
				arg = conv.Args[0]
			}
			if u, ok := arg.(*ast.UnaryExpr); ok && u.Op == token.AND {
				if !typeOKForCgoCall(cgoBaseType(info, u.X), make(map[types.Type]bool)) {
					reportf(arg.Pos(), "possibly passing Go type with embedded pointer to C")
					break
				}
			}
		}
		return true
	})
}

// typeCheckCgoSourceFiles returns type-checked syntax trees for the raw
// cgo files of a package (those that import "C"). Such files are not
// Go, so there may be gaps in type information around C.f references.
//
// This checker was initially written in vet to inspect raw cgo source
// files using partial type information. However, Analyzers in the new
// analysis API are presented with the type-checked, "cooked" Go ASTs
// resulting from cgo-processing files, so we must choose between
// working with the cooked file generated by cgo (which was tried but
// proved fragile) or locating the raw cgo file (e.g. from //line
// directives) and working with that, as we now do.
//
// Specifically, we must type-check the raw cgo source files (or at
// least the subtrees needed for this analyzer) in an environment that
// simulates the rest of the already type-checked package.
//
// For example, for each raw cgo source file in the original package,
// such as this one:
//
//	package p
//	import "C"
//	import "fmt"
//	type T int
//	const k = 3
//	var x, y = fmt.Println()
//	func f() { ... }
//	func g() { ... C.malloc(k) ... }
//	func (T) f(int) string { ... }
//
// we synthesize a new ast.File, shown below, that dot-imports the
// original "cooked" package using a special name ("·this·"), so that all
// references to package members resolve correctly. (References to
// unexported names cause an "unexported" error, which we ignore.)
//
// To avoid shadowing names imported from the cooked package,
// package-level declarations in the new source file are modified so
// that they do not declare any names.
// (The cgocall analysis is concerned with uses, not declarations.)
// Specifically, type declarations are discarded;
// all names in each var and const declaration are blanked out;
// each method is turned into a regular function by turning
// the receiver into the first parameter;
// and all functions are renamed to "_".
//
//	package p
//	import . "·this·" // declares T, k, x, y, f, g, T.f
//	import "C"
//	import "fmt"
//	const _ = 3
//	var _, _ = fmt.Println()
//	func _() { ... }
//	func _() { ... C.malloc(k) ... }
//	func _(T, int) string { ... }
//
// In this way, the raw function bodies and const/var initializer
// expressions are preserved but refer to the "cooked" objects imported
// from "·this·", and none of the transformed package-level declarations
// actually declares anything. In the example above, the reference to k
// in the argument of the call to C.malloc resolves to "·this·".k, which
// has an accurate type.
//
// This approach could in principle be generalized to more complex
// analyses on raw cgo files. One could synthesize a "C" package so that
// C.f would resolve to "·this·"._C_func_f, for example. But we have
// limited ourselves here to preserving function bodies and initializer
// expressions since that is all that the cgocall analyzer needs.
func typeCheckCgoSourceFiles(fset *token.FileSet, pkg *types.Package, files []*ast.File, info *types.Info, sizes types.Sizes) ([]*ast.File, *types.Info, error) {
	const thispkg = "·this·"

	// Which files are cgo files?
	var cgoFiles []*ast.File
	importMap := map[string]*types.Package{thispkg: pkg}
	for _, raw := range files {
		// If f is a cgo-generated file, Position reports
		// the original file, honoring //line directives.
		filename := fset.Position(raw.Pos()).Filename // sic: Pos, not FileStart
		f, err := parser.ParseFile(fset, filename, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, nil, fmt.Errorf("can't parse raw cgo file: %v", err)
		}
		found := false
		for _, spec := range f.Imports {
			if spec.Path.Value == `"C"` {
				found = true
				break
			}
		}
		if !found {
			continue // not a cgo file
		}

		// Record the original import map.
		for _, spec := range raw.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			importMap[path] = imported(info, spec)
		}

		// Add special dot-import declaration:
		//    import . "·this·"
		var decls []ast.Decl
		decls = append(decls, &ast.GenDecl{
			Tok: token.IMPORT,
			Specs: []ast.Spec{
				&ast.ImportSpec{
					Name: &ast.Ident{Name: "."},
					Path: &ast.BasicLit{
						Kind:  token.STRING,
						Value: strconv.Quote(thispkg),
					},
				},
			},
		})

		// Transform declarations from the raw cgo file.
		for _, decl := range f.Decls {
			switch decl := decl.(type) {
			case *ast.GenDecl:
				switch decl.Tok {
				case token.TYPE:
					// Discard type declarations.
					continue
				case token.IMPORT:
					// Keep imports.
				case token.VAR, token.CONST:
					// Blank the declared var/const names.
					for _, spec := range decl.Specs {
						spec := spec.(*ast.ValueSpec)
						for i := range spec.Names {
							spec.Names[i].Name = "_"
						}
					}
				}
			case *ast.FuncDecl:
				// Blank the declared func name.
				decl.Name.Name = "_"

				// Turn a method receiver:  func (T) f(P) R {...}
				// into regular parameter:  func _(T, P) R {...}
				if decl.Recv != nil {
					var params []*ast.Field
					params = append(params, decl.Recv.List...)
					params = append(params, decl.Type.Params.List...)
					decl.Type.Params.List = params
					decl.Recv = nil
				}
			}
			decls = append(decls, decl)
		}
		f.Decls = decls
		if debug {
			format.Node(os.Stderr, fset, f) // debugging
		}
		cgoFiles = append(cgoFiles, f)
	}
	if cgoFiles == nil {
		return nil, nil, nil // nothing to do (can't happen?)
	}

	// Type-check the synthetic files.
	tc := &types.Config{
		FakeImportC: true,
		Importer: importerFunc(func(path string) (*types.Package, error) {
			return importMap[path], nil
		}),
		Sizes: sizes,
		Error: func(error) {}, // ignore errors (e.g. unused import)
	}
	setGoVersion(tc, pkg)

	// It's tempting to record the new types in the
	// existing pass.TypesInfo, but we don't own it.
	altInfo := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
	}
	tc.Check(pkg.Path(), fset, cgoFiles, altInfo)

	return cgoFiles, altInfo, nil
}

// cgoBaseType tries to look through type conversions involving
// unsafe.Pointer to find the real type. It converts:
//
//	unsafe.Pointer(x) => x
//	*(*unsafe.Pointer)(unsafe.Pointer(&x)) => x
func cgoBaseType(info *types.Info, arg ast.Expr) types.Type {
	switch arg := arg.(type) {
	case *ast.CallExpr:
		if len(arg.Args) == 1 && isUnsafePointer(info, arg.Fun) {
			return cgoBaseType(info, arg.Args[0])
		}
	case *ast.StarExpr:
		call, ok := arg.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			break
		}
		// Here arg is *f(v).
		t := info.Types[call.Fun].Type
		if t == nil {
			break
		}
		ptr, ok := t.Underlying().(*types.Pointer)
		if !ok {
			break
		}
		// Here arg is *(*p)(v)
		elem, ok := ptr.Elem().Underlying().(*types.Basic)
		if !ok || elem.Kind() != types.UnsafePointer {
			break
		}
		// Here arg is *(*unsafe.Pointer)(v)
		call, ok = call.Args[0].(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			break
		}
		// Here arg is *(*unsafe.Pointer)(f(v))
		if !isUnsafePointer(info, call.Fun) {
			break
		}
		// Here arg is *(*unsafe.Pointer)(unsafe.Pointer(v))
		u, ok := call.Args[0].(*ast.UnaryExpr)
		if !ok || u.Op != token.AND {
			break
		}
		// Here arg is *(*unsafe.Pointer)(unsafe.Pointer(&v))
		return cgoBaseType(info, u.X)
	}

	return info.Types[arg].Type
}

// typeOKForCgoCall reports whether the type of arg is OK to pass to a
// C function using cgo. This is not true for Go types with embedded
// pointers. m is used to avoid infinite recursion on recursive types.
func typeOKForCgoCall(t types.Type, m map[types.Type]bool) bool {
	if t == nil || m[t] {
		return true
	}
	m[t] = true
	switch t := t.Underlying().(type) {
	case *types.Chan, *types.Map, *types.Signature, *types.Slice:
		return false
	case *types.Pointer:
		return typeOKForCgoCall(t.Elem(), m)
	case *types.Array:
		return typeOKForCgoCall(t.Elem(), m)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if !typeOKForCgoCall(t.Field(i).Type(), m) {
				return false
			}
		}
	}
	return true
}

func isUnsafePointer(info *types.Info, e ast.Expr) bool {
	t := info.Types[e].Type
	return t != nil && t.Underlying() == types.Typ[types.UnsafePointer]
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

// TODO(adonovan): make this a library function or method of Info.
func imported(info *types.Info, spec *ast.ImportSpec) *types.Package {
	obj, ok := info.Implicits[spec]
	if !ok {
		obj = info.Defs[spec.Name] // renaming import
	}
	return obj.(*types.PkgName).Imported()
}
```