Response:
Let's break down the thought process to analyze the provided Go code snippet.

**1. Initial Understanding: What is the Goal?**

The code belongs to `go/src/go/doc/reader.go`. The `doc` package in Go is responsible for extracting documentation from Go source code. The `reader.go` file likely handles the process of reading and interpreting the source code to build a structured representation of the documentation.

**2. High-Level Structure and Key Types:**

*   The code starts with copyright and package declaration, confirming the context.
*   Immediately, we see comments explaining sections: "function/method sets," "Named types," and "AST reader." This gives a strong clue about the code's organization and main concerns.
*   Key types jump out: `methodSet`, `namedType`, and `reader`. These are likely the central data structures used for organizing and processing information.

**3. Deeper Dive into Sections:**

*   **Function/Method Sets:**  The comments and code clearly show this section deals with managing collections of functions and methods. The `methodSet` type (a `map`) stores `Func` pointers. The functions `recvString`, `recvParam`, `set`, and `add` are about manipulating these sets, specifically handling receiver types and adding/merging function definitions. The concept of "conflict entries" is interesting, suggesting a way to handle ambiguity.

*   **Named Types:** This section focuses on representing Go types (structs, interfaces, etc.). The `namedType` struct stores information about a type like its documentation, name, declaration, whether it's embedded, and associated functions/methods/values. The `embeddedSet` is used to track embedded types within structs. `baseTypeName` extracts the base name of a type.

*   **AST Reader:** This is the core processing logic. The `reader` struct holds the state while reading and processing a Go package's AST (Abstract Syntax Tree). The fields in `reader` are crucial: `doc` (package doc), `imports`, `values`, `types`, `funcs`, etc. The methods of `reader` (like `isVisible`, `lookupType`, `readValue`, `readType`, `readFunc`, `readFile`, `readPackage`) suggest a step-by-step process of parsing the AST and extracting relevant documentation information.

**4. Identifying Key Functionalities and Relationships:**

*   **Reading and Parsing:** The `reader` struct and its methods are central to this. The `readFile` function processes a single file, and `readPackage` coordinates the processing of all files in a package.
*   **Documentation Extraction:**  Methods like `readDoc` and the `Doc` fields in structs like `Func`, `namedType`, and `Value` directly deal with extracting comments as documentation.
*   **Type and Method Association:** The code carefully associates functions and methods with their respective types (or the package level). The logic in `readFunc` for handling methods and factory functions is important.
*   **Embedded Types:**  The `embeddedSet` and `collectEmbeddedMethods` are designed to handle the complexities of method promotion through embedding.
*   **Visibility:** The `isVisible` method and the `mode` field control which declarations are considered (exported vs. all).
*   **Sorting:** The `sortedValues`, `sortedTypes`, and `sortedFuncs` functions indicate a step to organize the extracted information for presentation.
*   **Notes/Annotations:** The `readNotes` function and related regexes show how special comments (like `// BUG(user): ...`) are extracted.

**5. Inferring Go Language Feature Implementation:**

Based on the code's functionality, it's clear this is implementing a core part of the `go doc` tool or similar documentation generation. It's responsible for understanding Go syntax and semantics to extract meaningful documentation.

**6. Developing Examples (Mental Model First):**

Before writing code, think about scenarios that exercise the different parts of the code.

*   **Method Sets:** Imagine a type with methods and how they are stored. Consider cases with pointer vs. value receivers.
*   **Named Types:** Think about structs with embedded fields (both named and anonymous) and how their methods are collected.
*   **AST Reading:**  Consider a simple package with constants, variables, types, and functions. How would the reader process it?

**7. Writing Example Code and Specifying Input/Output:**

Translate the mental models into actual Go code. Crucially, define example *input* (Go source code) and the expected *output* (the `Doc` representation). This helps verify the understanding of the code.

**8. Considering Command-Line Arguments and Error Points:**

Think about how a tool using this code might be invoked. Are there options to control visibility (like showing unexported members)? What common mistakes might users make that this code helps to address or might expose?  For instance, misunderstanding method promotion with embedded types.

**9. Structuring the Answer:**

Organize the findings logically using the prompts' structure as a guide:

*   List of functionalities.
*   Go language feature implementation.
*   Code examples with input/output.
*   Command-line argument considerations.
*   Common mistakes.

**Self-Correction/Refinement During Analysis:**

*   **Initial Guess:**  Might initially think it's *only* about `go doc`. But realize it's a more general part of the `go/doc` package, which could be used by other tools too.
*   **Embedded Methods:** The logic around `collectEmbeddedMethods` is a bit complex. Re-read the comments and code carefully to understand the handling of pointer vs. value embedding and the `level` concept.
*   **Predeclared Types:** The interaction with `predeclaredTypes` and `shadowedPredecl` is a specific concern related to how `go doc` handles built-in types.

By following this structured thought process, combining code reading with conceptual understanding, and developing concrete examples, you can effectively analyze and explain the functionality of the provided Go code snippet.
这段代码是 Go 语言 `go/doc` 包中 `reader.go` 文件的一部分，它主要负责**读取和解析 Go 语言源代码的抽象语法树（AST），提取包、类型、函数、方法、常量、变量以及注释等信息，用于生成文档。** 简单来说，它的核心功能是**从 Go 源码中提取文档信息**。

以下是它更详细的功能列表：

1. **识别和存储包的文档注释 (`readDoc`)**:  从 AST 中提取包级别的注释，存储为包的文档。
2. **管理导入声明 (`readFile`, `readPackage`)**: 记录包的导入路径和别名，判断是否存在 `.` 导入。
3. **识别和存储常量和变量 (`readValue`)**:  提取常量和变量的声明信息，包括文档注释、名称和关联的类型（如果可以推断）。
4. **识别和存储类型声明 (`readType`)**:  提取类型（结构体、接口、其他类型）的声明信息，包括文档注释、名称和关联的字段（对于结构体）或方法（对于接口）。
5. **识别和存储函数和方法声明 (`readFunc`)**:  提取函数和方法的声明信息，包括文档注释、名称、接收者类型（对于方法）。它还会尝试将工厂函数关联到其返回类型。
6. **处理匿名字段 (`recordAnonymousField`)**:  识别结构体中的匿名字段（嵌入字段），并记录它们的信息，这对于后续收集嵌入类型的方法至关重要。
7. **收集和处理 "Notes" (`readNotes`, `readNote`)**: 识别特定格式的注释，例如 `// BUG(user): ...` 或 `// TODO(user): ...`，并将它们作为 Notes 存储起来。
8. **计算类型的完整方法集 (`computeMethodSets`, `collectEmbeddedMethods`)**:  对于结构体类型，它会递归地收集嵌入类型的方法，并将其添加到结构体的方法集中。这包括处理指针接收者的情况。
9. **清理和过滤类型信息 (`cleanupTypes`)**:  移除没有声明或不可见的类型信息，并将与这些类型关联的函数和方法移回包级别。这处理了预声明类型和未导出类型的情况。
10. **对提取的信息进行排序 (`sortedValues`, `sortedTypes`, `sortedFuncs`)**:  对常量、变量、类型、函数和方法等信息进行排序，以便生成一致的文档输出。
11. **识别预声明标识符 (`IsPredeclared`)**:  判断给定的字符串是否是 Go 语言的预声明类型、函数或常量。
12. **辅助函数**: 提供一些辅助函数，如 `recvString`（将接收者类型转换为字符串）、`baseTypeName`（提取基本类型名称）、`assumedPackageName`（根据导入路径推断包名）等。

**它是什么 Go 语言功能的实现：**

这段代码是 Go 语言标准库中 `go doc` 工具的核心组成部分。`go doc` 是一个命令行工具，用于显示 Go 包或其中导出符号的文档。`reader.go` 中的代码负责解析源代码，构建一个表示文档信息的内部数据结构，然后 `go doc` 工具的其他部分会使用这些数据来生成最终的文档输出（例如，在终端显示或生成 HTML 页面）。

**Go 代码举例说明:**

假设我们有以下 Go 代码文件 `example.go`：

```go
// Package example provides a simple example.
package example

import "fmt"

// MyConstant is a constant value.
const MyConstant = 10

// MyVariable is a variable.
var MyVariable int = 20

// MyStruct is a sample struct.
type MyStruct struct {
	// FieldA is the first field.
	FieldA string
	FieldB int
}

// NewMyStruct creates a new MyStruct.
func NewMyStruct(a string, b int) *MyStruct {
	return &MyStruct{a, b}
}

// MyMethod is a method of MyStruct.
func (s *MyStruct) MyMethod() {
	fmt.Println("MyMethod called")
}

// MyFunc is a standalone function.
func MyFunc() {
	fmt.Println("MyFunc called")
}

// BUG(user): This is a known bug.
```

当 `go doc` 工具处理这个 `example.go` 文件时，`reader.go` 中的代码会执行以下操作（简化说明）：

1. `readDoc` 会提取 `"Package example provides a simple example."` 作为包的文档。
2. `readValue` 会提取 `MyConstant` 和 `MyVariable` 的信息，包括它们的文档注释和类型。
3. `readType` 会提取 `MyStruct` 的信息，包括其文档注释和字段 `FieldA` 和 `FieldB` 的文档注释。
4. `readFunc` 会提取 `NewMyStruct` 和 `MyFunc` 的信息，以及 `MyStruct` 的方法 `MyMethod` 的信息。它还会尝试将 `NewMyStruct` 关联到 `MyStruct` 类型，因为它看起来像一个工厂函数。
5. `readNotes` 会提取 `BUG(user): This is a known bug.` 并将其存储为一个 Note。

**假设的输入与输出 (代码推理):**

以下是一些 `reader.go` 中关键函数的输入和输出示例：

*   **`recvString(recv ast.Expr)`**:
    *   **假设输入:** 一个表示接收者类型的 `ast.Expr`，例如 `*ast.Ident{Name: "MyStruct"}`。
    *   **假设输出:** 字符串 `"*MyStruct"`。
    *   **假设输入:** 一个表示接收者类型的 `ast.Expr`，例如 `*ast.StarExpr{X: &ast.Ident{Name: "MyStruct"}}`。
    *   **假设输出:** 字符串 `"*MyStruct"`。
    *   **假设输入:** 一个表示接收者类型的 `ast.Expr`，例如 `*ast.IndexExpr{X: &ast.Ident{Name: "Slice"}, Index: &ast.Ident{Name: "int"}}`。
    *   **假设输出:** 字符串 `"Slice[int]"`。

*   **`(mset methodSet) set(f *ast.FuncDecl, preserveAST bool)`**:
    *   **假设输入:**  一个表示 `MyMethod` 函数声明的 `ast.FuncDecl`，以及 `preserveAST = false`。
    *   **假设输出:** `mset` 中会添加一个键为 `"MyMethod"`，值为指向 `Func` 结构体的指针，其中包含了 `MyMethod` 的文档、名称、接收者类型 `"*MyStruct"` 等信息。并且 `f.Doc` 会被设置为 `nil`。

*   **`baseTypeName(x ast.Expr)`**:
    *   **假设输入:** 一个表示类型 `MyStruct` 的 `ast.Ident{Name: "MyStruct"}`。
    *   **假设输出:** `"MyStruct", false`。
    *   **假设输入:** 一个表示类型 `pkg.OtherType` 的 `ast.SelectorExpr{X: &ast.Ident{Name: "pkg"}, Sel: &ast.Ident{Name: "OtherType"}}`。
    *   **假设输出:** `"OtherType", true`。

**命令行参数的具体处理:**

`reader.go` 本身并不直接处理命令行参数。它的功能是读取和解析源代码。命令行参数的处理发生在 `go doc` 工具的其他部分，通常在 `main` 函数中。 `go doc` 工具会根据命令行参数决定要处理哪些包、哪些符号，并控制输出格式等。

例如，常见的 `go doc` 命令及其作用：

*   `go doc <package_path>`: 显示指定包的文档。
*   `go doc <package_path>.<symbol>`: 显示指定包中某个符号（例如，函数、类型、常量）的文档。
*   `go doc -all <package_path>`: 显示所有符号的文档，包括未导出的。

**使用者易犯错的点:**

*   **误解方法集和嵌入**:  Go 语言中，嵌入类型的方法会被提升到嵌入它的结构体中。如果使用者不理解这个概念，可能会认为某些方法不属于某个类型。`reader.go` 的 `computeMethodSets` 功能正是为了处理这种情况。例如，如果 `MyStruct` 嵌入了另一个具有方法的类型，那些方法也会被 `reader.go` 收集到 `MyStruct` 的方法集中。

*   **文档注释的格式**: `go doc` 工具依赖于特定的文档注释格式。使用者可能会因为注释格式不正确而导致文档无法正确生成。例如，包级别的注释必须紧跟在 `package` 关键字之后，并且不能有空行。

*   **未导出符号的文档**: 默认情况下，`go doc` 只显示导出符号的文档。使用者可能会忘记使用 `-all` 参数来查看未导出符号的文档。 `reader.go` 的 `isVisible` 函数会根据 `mode` 来判断是否应该处理未导出的符号。

总而言之，`go/src/go/doc/reader.go` 是 Go 语言文档生成工具链中的一个关键组件，它负责从源代码中提取结构化的文档信息，为后续的文档展示和生成奠定基础。

### 提示词
```
这是路径为go/src/go/doc/reader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package doc

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/token"
	"internal/lazyregexp"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ----------------------------------------------------------------------------
// function/method sets
//
// Internally, we treat functions like methods and collect them in method sets.

// A methodSet describes a set of methods. Entries where Decl == nil are conflict
// entries (more than one method with the same name at the same embedding level).
type methodSet map[string]*Func

// recvString returns a string representation of recv of the form "T", "*T",
// "T[A, ...]", "*T[A, ...]" or "BADRECV" (if not a proper receiver type).
func recvString(recv ast.Expr) string {
	switch t := recv.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + recvString(t.X)
	case *ast.IndexExpr:
		// Generic type with one parameter.
		return fmt.Sprintf("%s[%s]", recvString(t.X), recvParam(t.Index))
	case *ast.IndexListExpr:
		// Generic type with multiple parameters.
		if len(t.Indices) > 0 {
			var b strings.Builder
			b.WriteString(recvString(t.X))
			b.WriteByte('[')
			b.WriteString(recvParam(t.Indices[0]))
			for _, e := range t.Indices[1:] {
				b.WriteString(", ")
				b.WriteString(recvParam(e))
			}
			b.WriteByte(']')
			return b.String()
		}
	}
	return "BADRECV"
}

func recvParam(p ast.Expr) string {
	if id, ok := p.(*ast.Ident); ok {
		return id.Name
	}
	return "BADPARAM"
}

// set creates the corresponding Func for f and adds it to mset.
// If there are multiple f's with the same name, set keeps the first
// one with documentation; conflicts are ignored. The boolean
// specifies whether to leave the AST untouched.
func (mset methodSet) set(f *ast.FuncDecl, preserveAST bool) {
	name := f.Name.Name
	if g := mset[name]; g != nil && g.Doc != "" {
		// A function with the same name has already been registered;
		// since it has documentation, assume f is simply another
		// implementation and ignore it. This does not happen if the
		// caller is using go/build.ScanDir to determine the list of
		// files implementing a package.
		return
	}
	// function doesn't exist or has no documentation; use f
	recv := ""
	if f.Recv != nil {
		var typ ast.Expr
		// be careful in case of incorrect ASTs
		if list := f.Recv.List; len(list) == 1 {
			typ = list[0].Type
		}
		recv = recvString(typ)
	}
	mset[name] = &Func{
		Doc:  f.Doc.Text(),
		Name: name,
		Decl: f,
		Recv: recv,
		Orig: recv,
	}
	if !preserveAST {
		f.Doc = nil // doc consumed - remove from AST
	}
}

// add adds method m to the method set; m is ignored if the method set
// already contains a method with the same name at the same or a higher
// level than m.
func (mset methodSet) add(m *Func) {
	old := mset[m.Name]
	if old == nil || m.Level < old.Level {
		mset[m.Name] = m
		return
	}
	if m.Level == old.Level {
		// conflict - mark it using a method with nil Decl
		mset[m.Name] = &Func{
			Name:  m.Name,
			Level: m.Level,
		}
	}
}

// ----------------------------------------------------------------------------
// Named types

// baseTypeName returns the name of the base type of x (or "")
// and whether the type is imported or not.
func baseTypeName(x ast.Expr) (name string, imported bool) {
	switch t := x.(type) {
	case *ast.Ident:
		return t.Name, false
	case *ast.IndexExpr:
		return baseTypeName(t.X)
	case *ast.IndexListExpr:
		return baseTypeName(t.X)
	case *ast.SelectorExpr:
		if _, ok := t.X.(*ast.Ident); ok {
			// only possible for qualified type names;
			// assume type is imported
			return t.Sel.Name, true
		}
	case *ast.ParenExpr:
		return baseTypeName(t.X)
	case *ast.StarExpr:
		return baseTypeName(t.X)
	}
	return "", false
}

// An embeddedSet describes a set of embedded types.
type embeddedSet map[*namedType]bool

// A namedType represents a named unqualified (package local, or possibly
// predeclared) type. The namedType for a type name is always found via
// reader.lookupType.
type namedType struct {
	doc  string       // doc comment for type
	name string       // type name
	decl *ast.GenDecl // nil if declaration hasn't been seen yet

	isEmbedded bool        // true if this type is embedded
	isStruct   bool        // true if this type is a struct
	embedded   embeddedSet // true if the embedded type is a pointer

	// associated declarations
	values  []*Value // consts and vars
	funcs   methodSet
	methods methodSet
}

// ----------------------------------------------------------------------------
// AST reader

// reader accumulates documentation for a single package.
// It modifies the AST: Comments (declaration documentation)
// that have been collected by the reader are set to nil
// in the respective AST nodes so that they are not printed
// twice (once when printing the documentation and once when
// printing the corresponding AST node).
type reader struct {
	mode Mode

	// package properties
	doc       string // package documentation, if any
	filenames []string
	notes     map[string][]*Note

	// imports
	imports      map[string]int
	hasDotImp    bool // if set, package contains a dot import
	importByName map[string]string

	// declarations
	values []*Value // consts and vars
	order  int      // sort order of const and var declarations (when we can't use a name)
	types  map[string]*namedType
	funcs  methodSet

	// support for package-local shadowing of predeclared types
	shadowedPredecl map[string]bool
	fixmap          map[string][]*ast.InterfaceType
}

func (r *reader) isVisible(name string) bool {
	return r.mode&AllDecls != 0 || token.IsExported(name)
}

// lookupType returns the base type with the given name.
// If the base type has not been encountered yet, a new
// type with the given name but no associated declaration
// is added to the type map.
func (r *reader) lookupType(name string) *namedType {
	if name == "" || name == "_" {
		return nil // no type docs for anonymous types
	}
	if typ, found := r.types[name]; found {
		return typ
	}
	// type not found - add one without declaration
	typ := &namedType{
		name:     name,
		embedded: make(embeddedSet),
		funcs:    make(methodSet),
		methods:  make(methodSet),
	}
	r.types[name] = typ
	return typ
}

// recordAnonymousField registers fieldType as the type of an
// anonymous field in the parent type. If the field is imported
// (qualified name) or the parent is nil, the field is ignored.
// The function returns the field name.
func (r *reader) recordAnonymousField(parent *namedType, fieldType ast.Expr) (fname string) {
	fname, imp := baseTypeName(fieldType)
	if parent == nil || imp {
		return
	}
	if ftype := r.lookupType(fname); ftype != nil {
		ftype.isEmbedded = true
		_, ptr := fieldType.(*ast.StarExpr)
		parent.embedded[ftype] = ptr
	}
	return
}

func (r *reader) readDoc(comment *ast.CommentGroup) {
	// By convention there should be only one package comment
	// but collect all of them if there are more than one.
	text := comment.Text()
	if r.doc == "" {
		r.doc = text
		return
	}
	r.doc += "\n" + text
}

func (r *reader) remember(predecl string, typ *ast.InterfaceType) {
	if r.fixmap == nil {
		r.fixmap = make(map[string][]*ast.InterfaceType)
	}
	r.fixmap[predecl] = append(r.fixmap[predecl], typ)
}

func specNames(specs []ast.Spec) []string {
	names := make([]string, 0, len(specs)) // reasonable estimate
	for _, s := range specs {
		// s guaranteed to be an *ast.ValueSpec by readValue
		for _, ident := range s.(*ast.ValueSpec).Names {
			names = append(names, ident.Name)
		}
	}
	return names
}

// readValue processes a const or var declaration.
func (r *reader) readValue(decl *ast.GenDecl) {
	// determine if decl should be associated with a type
	// Heuristic: For each typed entry, determine the type name, if any.
	//            If there is exactly one type name that is sufficiently
	//            frequent, associate the decl with the respective type.
	domName := ""
	domFreq := 0
	prev := ""
	n := 0
	for _, spec := range decl.Specs {
		s, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue // should not happen, but be conservative
		}
		name := ""
		switch {
		case s.Type != nil:
			// a type is present; determine its name
			if n, imp := baseTypeName(s.Type); !imp {
				name = n
			}
		case decl.Tok == token.CONST && len(s.Values) == 0:
			// no type or value is present but we have a constant declaration;
			// use the previous type name (possibly the empty string)
			name = prev
		}
		if name != "" {
			// entry has a named type
			if domName != "" && domName != name {
				// more than one type name - do not associate
				// with any type
				domName = ""
				break
			}
			domName = name
			domFreq++
		}
		prev = name
		n++
	}

	// nothing to do w/o a legal declaration
	if n == 0 {
		return
	}

	// determine values list with which to associate the Value for this decl
	values := &r.values
	const threshold = 0.75
	if domName != "" && r.isVisible(domName) && domFreq >= int(float64(len(decl.Specs))*threshold) {
		// typed entries are sufficiently frequent
		if typ := r.lookupType(domName); typ != nil {
			values = &typ.values // associate with that type
		}
	}

	*values = append(*values, &Value{
		Doc:   decl.Doc.Text(),
		Names: specNames(decl.Specs),
		Decl:  decl,
		order: r.order,
	})
	if r.mode&PreserveAST == 0 {
		decl.Doc = nil // doc consumed - remove from AST
	}
	// Note: It's important that the order used here is global because the cleanupTypes
	// methods may move values associated with types back into the global list. If the
	// order is list-specific, sorting is not deterministic because the same order value
	// may appear multiple times (was bug, found when fixing #16153).
	r.order++
}

// fields returns a struct's fields or an interface's methods.
func fields(typ ast.Expr) (list []*ast.Field, isStruct bool) {
	var fields *ast.FieldList
	switch t := typ.(type) {
	case *ast.StructType:
		fields = t.Fields
		isStruct = true
	case *ast.InterfaceType:
		fields = t.Methods
	}
	if fields != nil {
		list = fields.List
	}
	return
}

// readType processes a type declaration.
func (r *reader) readType(decl *ast.GenDecl, spec *ast.TypeSpec) {
	typ := r.lookupType(spec.Name.Name)
	if typ == nil {
		return // no name or blank name - ignore the type
	}

	// A type should be added at most once, so typ.decl
	// should be nil - if it is not, simply overwrite it.
	typ.decl = decl

	// compute documentation
	doc := spec.Doc
	if doc == nil {
		// no doc associated with the spec, use the declaration doc, if any
		doc = decl.Doc
	}
	if r.mode&PreserveAST == 0 {
		spec.Doc = nil // doc consumed - remove from AST
		decl.Doc = nil // doc consumed - remove from AST
	}
	typ.doc = doc.Text()

	// record anonymous fields (they may contribute methods)
	// (some fields may have been recorded already when filtering
	// exports, but that's ok)
	var list []*ast.Field
	list, typ.isStruct = fields(spec.Type)
	for _, field := range list {
		if len(field.Names) == 0 {
			r.recordAnonymousField(typ, field.Type)
		}
	}
}

// isPredeclared reports whether n denotes a predeclared type.
func (r *reader) isPredeclared(n string) bool {
	return predeclaredTypes[n] && r.types[n] == nil
}

// readFunc processes a func or method declaration.
func (r *reader) readFunc(fun *ast.FuncDecl) {
	// strip function body if requested.
	if r.mode&PreserveAST == 0 {
		fun.Body = nil
	}

	// associate methods with the receiver type, if any
	if fun.Recv != nil {
		// method
		if len(fun.Recv.List) == 0 {
			// should not happen (incorrect AST); (See issue 17788)
			// don't show this method
			return
		}
		recvTypeName, imp := baseTypeName(fun.Recv.List[0].Type)
		if imp {
			// should not happen (incorrect AST);
			// don't show this method
			return
		}
		if typ := r.lookupType(recvTypeName); typ != nil {
			typ.methods.set(fun, r.mode&PreserveAST != 0)
		}
		// otherwise ignore the method
		// TODO(gri): There may be exported methods of non-exported types
		// that can be called because of exported values (consts, vars, or
		// function results) of that type. Could determine if that is the
		// case and then show those methods in an appropriate section.
		return
	}

	// Associate factory functions with the first visible result type, as long as
	// others are predeclared types.
	if fun.Type.Results.NumFields() >= 1 {
		var typ *namedType // type to associate the function with
		numResultTypes := 0
		for _, res := range fun.Type.Results.List {
			factoryType := res.Type
			if t, ok := factoryType.(*ast.ArrayType); ok {
				// We consider functions that return slices or arrays of type
				// T (or pointers to T) as factory functions of T.
				factoryType = t.Elt
			}
			if n, imp := baseTypeName(factoryType); !imp && r.isVisible(n) && !r.isPredeclared(n) {
				if lookupTypeParam(n, fun.Type.TypeParams) != nil {
					// Issue #49477: don't associate fun with its type parameter result.
					// A type parameter is not a defined type.
					continue
				}
				if t := r.lookupType(n); t != nil {
					typ = t
					numResultTypes++
					if numResultTypes > 1 {
						break
					}
				}
			}
		}
		// If there is exactly one result type,
		// associate the function with that type.
		if numResultTypes == 1 {
			typ.funcs.set(fun, r.mode&PreserveAST != 0)
			return
		}
	}

	// just an ordinary function
	r.funcs.set(fun, r.mode&PreserveAST != 0)
}

// lookupTypeParam searches for type parameters named name within the tparams
// field list, returning the relevant identifier if found, or nil if not.
func lookupTypeParam(name string, tparams *ast.FieldList) *ast.Ident {
	if tparams == nil {
		return nil
	}
	for _, field := range tparams.List {
		for _, id := range field.Names {
			if id.Name == name {
				return id
			}
		}
	}
	return nil
}

var (
	noteMarker    = `([A-Z][A-Z]+)\(([^)]+)\):?`                // MARKER(uid), MARKER at least 2 chars, uid at least 1 char
	noteMarkerRx  = lazyregexp.New(`^[ \t]*` + noteMarker)      // MARKER(uid) at text start
	noteCommentRx = lazyregexp.New(`^/[/*][ \t]*` + noteMarker) // MARKER(uid) at comment start
)

// clean replaces each sequence of space, \r, or \t characters
// with a single space and removes any trailing and leading spaces.
func clean(s string) string {
	var b []byte
	p := byte(' ')
	for i := 0; i < len(s); i++ {
		q := s[i]
		if q == '\r' || q == '\t' {
			q = ' '
		}
		if q != ' ' || p != ' ' {
			b = append(b, q)
			p = q
		}
	}
	// remove trailing blank, if any
	if n := len(b); n > 0 && p == ' ' {
		b = b[0 : n-1]
	}
	return string(b)
}

// readNote collects a single note from a sequence of comments.
func (r *reader) readNote(list []*ast.Comment) {
	text := (&ast.CommentGroup{List: list}).Text()
	if m := noteMarkerRx.FindStringSubmatchIndex(text); m != nil {
		// The note body starts after the marker.
		// We remove any formatting so that we don't
		// get spurious line breaks/indentation when
		// showing the TODO body.
		body := clean(text[m[1]:])
		if body != "" {
			marker := text[m[2]:m[3]]
			r.notes[marker] = append(r.notes[marker], &Note{
				Pos:  list[0].Pos(),
				End:  list[len(list)-1].End(),
				UID:  text[m[4]:m[5]],
				Body: body,
			})
		}
	}
}

// readNotes extracts notes from comments.
// A note must start at the beginning of a comment with "MARKER(uid):"
// and is followed by the note body (e.g., "// BUG(gri): fix this").
// The note ends at the end of the comment group or at the start of
// another note in the same comment group, whichever comes first.
func (r *reader) readNotes(comments []*ast.CommentGroup) {
	for _, group := range comments {
		i := -1 // comment index of most recent note start, valid if >= 0
		list := group.List
		for j, c := range list {
			if noteCommentRx.MatchString(c.Text) {
				if i >= 0 {
					r.readNote(list[i:j])
				}
				i = j
			}
		}
		if i >= 0 {
			r.readNote(list[i:])
		}
	}
}

// readFile adds the AST for a source file to the reader.
func (r *reader) readFile(src *ast.File) {
	// add package documentation
	if src.Doc != nil {
		r.readDoc(src.Doc)
		if r.mode&PreserveAST == 0 {
			src.Doc = nil // doc consumed - remove from AST
		}
	}

	// add all declarations but for functions which are processed in a separate pass
	for _, decl := range src.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			switch d.Tok {
			case token.IMPORT:
				// imports are handled individually
				for _, spec := range d.Specs {
					if s, ok := spec.(*ast.ImportSpec); ok {
						if import_, err := strconv.Unquote(s.Path.Value); err == nil {
							r.imports[import_] = 1
							var name string
							if s.Name != nil {
								name = s.Name.Name
								if name == "." {
									r.hasDotImp = true
								}
							}
							if name != "." {
								if name == "" {
									name = assumedPackageName(import_)
								}
								old, ok := r.importByName[name]
								if !ok {
									r.importByName[name] = import_
								} else if old != import_ && old != "" {
									r.importByName[name] = "" // ambiguous
								}
							}
						}
					}
				}
			case token.CONST, token.VAR:
				// constants and variables are always handled as a group
				r.readValue(d)
			case token.TYPE:
				// types are handled individually
				if len(d.Specs) == 1 && !d.Lparen.IsValid() {
					// common case: single declaration w/o parentheses
					// (if a single declaration is parenthesized,
					// create a new fake declaration below, so that
					// go/doc type declarations always appear w/o
					// parentheses)
					if s, ok := d.Specs[0].(*ast.TypeSpec); ok {
						r.readType(d, s)
					}
					break
				}
				for _, spec := range d.Specs {
					if s, ok := spec.(*ast.TypeSpec); ok {
						// use an individual (possibly fake) declaration
						// for each type; this also ensures that each type
						// gets to (re-)use the declaration documentation
						// if there's none associated with the spec itself
						fake := &ast.GenDecl{
							Doc: d.Doc,
							// don't use the existing TokPos because it
							// will lead to the wrong selection range for
							// the fake declaration if there are more
							// than one type in the group (this affects
							// src/cmd/godoc/godoc.go's posLink_urlFunc)
							TokPos: s.Pos(),
							Tok:    token.TYPE,
							Specs:  []ast.Spec{s},
						}
						r.readType(fake, s)
					}
				}
			}
		}
	}

	// collect MARKER(...): annotations
	r.readNotes(src.Comments)
	if r.mode&PreserveAST == 0 {
		src.Comments = nil // consumed unassociated comments - remove from AST
	}
}

func (r *reader) readPackage(pkg *ast.Package, mode Mode) {
	// initialize reader
	r.filenames = make([]string, len(pkg.Files))
	r.imports = make(map[string]int)
	r.mode = mode
	r.types = make(map[string]*namedType)
	r.funcs = make(methodSet)
	r.notes = make(map[string][]*Note)
	r.importByName = make(map[string]string)

	// sort package files before reading them so that the
	// result does not depend on map iteration order
	i := 0
	for filename := range pkg.Files {
		r.filenames[i] = filename
		i++
	}
	slices.Sort(r.filenames)

	// process files in sorted order
	for _, filename := range r.filenames {
		f := pkg.Files[filename]
		if mode&AllDecls == 0 {
			r.fileExports(f)
		}
		r.readFile(f)
	}

	for name, path := range r.importByName {
		if path == "" {
			delete(r.importByName, name)
		}
	}

	// process functions now that we have better type information
	for _, f := range pkg.Files {
		for _, decl := range f.Decls {
			if d, ok := decl.(*ast.FuncDecl); ok {
				r.readFunc(d)
			}
		}
	}
}

// ----------------------------------------------------------------------------
// Types

func customizeRecv(f *Func, recvTypeName string, embeddedIsPtr bool, level int) *Func {
	if f == nil || f.Decl == nil || f.Decl.Recv == nil || len(f.Decl.Recv.List) != 1 {
		return f // shouldn't happen, but be safe
	}

	// copy existing receiver field and set new type
	newField := *f.Decl.Recv.List[0]
	origPos := newField.Type.Pos()
	_, origRecvIsPtr := newField.Type.(*ast.StarExpr)
	newIdent := &ast.Ident{NamePos: origPos, Name: recvTypeName}
	var typ ast.Expr = newIdent
	if !embeddedIsPtr && origRecvIsPtr {
		newIdent.NamePos++ // '*' is one character
		typ = &ast.StarExpr{Star: origPos, X: newIdent}
	}
	newField.Type = typ

	// copy existing receiver field list and set new receiver field
	newFieldList := *f.Decl.Recv
	newFieldList.List = []*ast.Field{&newField}

	// copy existing function declaration and set new receiver field list
	newFuncDecl := *f.Decl
	newFuncDecl.Recv = &newFieldList

	// copy existing function documentation and set new declaration
	newF := *f
	newF.Decl = &newFuncDecl
	newF.Recv = recvString(typ)
	// the Orig field never changes
	newF.Level = level

	return &newF
}

// collectEmbeddedMethods collects the embedded methods of typ in mset.
func (r *reader) collectEmbeddedMethods(mset methodSet, typ *namedType, recvTypeName string, embeddedIsPtr bool, level int, visited embeddedSet) {
	visited[typ] = true
	for embedded, isPtr := range typ.embedded {
		// Once an embedded type is embedded as a pointer type
		// all embedded types in those types are treated like
		// pointer types for the purpose of the receiver type
		// computation; i.e., embeddedIsPtr is sticky for this
		// embedding hierarchy.
		thisEmbeddedIsPtr := embeddedIsPtr || isPtr
		for _, m := range embedded.methods {
			// only top-level methods are embedded
			if m.Level == 0 {
				mset.add(customizeRecv(m, recvTypeName, thisEmbeddedIsPtr, level))
			}
		}
		if !visited[embedded] {
			r.collectEmbeddedMethods(mset, embedded, recvTypeName, thisEmbeddedIsPtr, level+1, visited)
		}
	}
	delete(visited, typ)
}

// computeMethodSets determines the actual method sets for each type encountered.
func (r *reader) computeMethodSets() {
	for _, t := range r.types {
		// collect embedded methods for t
		if t.isStruct {
			// struct
			r.collectEmbeddedMethods(t.methods, t, t.name, false, 1, make(embeddedSet))
		} else {
			// interface
			// TODO(gri) fix this
		}
	}

	// For any predeclared names that are declared locally, don't treat them as
	// exported fields anymore.
	for predecl := range r.shadowedPredecl {
		for _, ityp := range r.fixmap[predecl] {
			removeAnonymousField(predecl, ityp)
		}
	}
}

// cleanupTypes removes the association of functions and methods with
// types that have no declaration. Instead, these functions and methods
// are shown at the package level. It also removes types with missing
// declarations or which are not visible.
func (r *reader) cleanupTypes() {
	for _, t := range r.types {
		visible := r.isVisible(t.name)
		predeclared := predeclaredTypes[t.name]

		if t.decl == nil && (predeclared || visible && (t.isEmbedded || r.hasDotImp)) {
			// t.name is a predeclared type (and was not redeclared in this package),
			// or it was embedded somewhere but its declaration is missing (because
			// the AST is incomplete), or we have a dot-import (and all bets are off):
			// move any associated values, funcs, and methods back to the top-level so
			// that they are not lost.
			// 1) move values
			r.values = append(r.values, t.values...)
			// 2) move factory functions
			for name, f := range t.funcs {
				// in a correct AST, package-level function names
				// are all different - no need to check for conflicts
				r.funcs[name] = f
			}
			// 3) move methods
			if !predeclared {
				for name, m := range t.methods {
					// don't overwrite functions with the same name - drop them
					if _, found := r.funcs[name]; !found {
						r.funcs[name] = m
					}
				}
			}
		}
		// remove types w/o declaration or which are not visible
		if t.decl == nil || !visible {
			delete(r.types, t.name)
		}
	}
}

// ----------------------------------------------------------------------------
// Sorting

func sortedKeys(m map[string]int) []string {
	list := make([]string, len(m))
	i := 0
	for key := range m {
		list[i] = key
		i++
	}
	slices.Sort(list)
	return list
}

// sortingName returns the name to use when sorting d into place.
func sortingName(d *ast.GenDecl) string {
	if len(d.Specs) == 1 {
		if s, ok := d.Specs[0].(*ast.ValueSpec); ok {
			return s.Names[0].Name
		}
	}
	return ""
}

func sortedValues(m []*Value, tok token.Token) []*Value {
	list := make([]*Value, len(m)) // big enough in any case
	i := 0
	for _, val := range m {
		if val.Decl.Tok == tok {
			list[i] = val
			i++
		}
	}
	list = list[0:i]

	slices.SortFunc(list, func(a, b *Value) int {
		r := strings.Compare(sortingName(a.Decl), sortingName(b.Decl))
		if r != 0 {
			return r
		}
		return cmp.Compare(a.order, b.order)
	})

	return list
}

func sortedTypes(m map[string]*namedType, allMethods bool) []*Type {
	list := make([]*Type, len(m))
	i := 0
	for _, t := range m {
		list[i] = &Type{
			Doc:     t.doc,
			Name:    t.name,
			Decl:    t.decl,
			Consts:  sortedValues(t.values, token.CONST),
			Vars:    sortedValues(t.values, token.VAR),
			Funcs:   sortedFuncs(t.funcs, true),
			Methods: sortedFuncs(t.methods, allMethods),
		}
		i++
	}

	slices.SortFunc(list, func(a, b *Type) int {
		return strings.Compare(a.Name, b.Name)
	})

	return list
}

func removeStar(s string) string {
	if len(s) > 0 && s[0] == '*' {
		return s[1:]
	}
	return s
}

func sortedFuncs(m methodSet, allMethods bool) []*Func {
	list := make([]*Func, len(m))
	i := 0
	for _, m := range m {
		// determine which methods to include
		switch {
		case m.Decl == nil:
			// exclude conflict entry
		case allMethods, m.Level == 0, !token.IsExported(removeStar(m.Orig)):
			// forced inclusion, method not embedded, or method
			// embedded but original receiver type not exported
			list[i] = m
			i++
		}
	}
	list = list[0:i]
	slices.SortFunc(list, func(a, b *Func) int {
		return strings.Compare(a.Name, b.Name)
	})
	return list
}

// noteBodies returns a list of note body strings given a list of notes.
// This is only used to populate the deprecated Package.Bugs field.
func noteBodies(notes []*Note) []string {
	var list []string
	for _, n := range notes {
		list = append(list, n.Body)
	}
	return list
}

// ----------------------------------------------------------------------------
// Predeclared identifiers

// IsPredeclared reports whether s is a predeclared identifier.
func IsPredeclared(s string) bool {
	return predeclaredTypes[s] || predeclaredFuncs[s] || predeclaredConstants[s]
}

var predeclaredTypes = map[string]bool{
	"any":        true,
	"bool":       true,
	"byte":       true,
	"comparable": true,
	"complex64":  true,
	"complex128": true,
	"error":      true,
	"float32":    true,
	"float64":    true,
	"int":        true,
	"int8":       true,
	"int16":      true,
	"int32":      true,
	"int64":      true,
	"rune":       true,
	"string":     true,
	"uint":       true,
	"uint8":      true,
	"uint16":     true,
	"uint32":     true,
	"uint64":     true,
	"uintptr":    true,
}

var predeclaredFuncs = map[string]bool{
	"append":  true,
	"cap":     true,
	"clear":   true,
	"close":   true,
	"complex": true,
	"copy":    true,
	"delete":  true,
	"imag":    true,
	"len":     true,
	"make":    true,
	"max":     true,
	"min":     true,
	"new":     true,
	"panic":   true,
	"print":   true,
	"println": true,
	"real":    true,
	"recover": true,
}

var predeclaredConstants = map[string]bool{
	"false": true,
	"iota":  true,
	"nil":   true,
	"true":  true,
}

// assumedPackageName returns the assumed package name
// for a given import path. This is a copy of
// golang.org/x/tools/internal/imports.ImportPathToAssumedName.
func assumedPackageName(importPath string) string {
	notIdentifier := func(ch rune) bool {
		return !('a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' ||
			'0' <= ch && ch <= '9' ||
			ch == '_' ||
			ch >= utf8.RuneSelf && (unicode.IsLetter(ch) || unicode.IsDigit(ch)))
	}

	base := path.Base(importPath)
	if strings.HasPrefix(base, "v") {
		if _, err := strconv.Atoi(base[1:]); err == nil {
			dir := path.Dir(importPath)
			if dir != "." {
				base = path.Base(dir)
			}
		}
	}
	base = strings.TrimPrefix(base, "go-")
	if i := strings.IndexFunc(base, notIdentifier); i >= 0 {
		base = base[:i]
	}
	return base
}
```