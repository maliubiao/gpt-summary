Response:
我的思考过程如下：

1. **理解目标：** 目标是分析给定的 Go 代码片段 `go/src/go/types/api.go` 的功能，并用 Go 代码示例、命令行参数处理、以及易错点进行说明。

2. **识别核心功能：** 代码注释中明确指出 `Package types declares the data types and implements the algorithms for type-checking of Go packages.`  这说明这个文件的核心功能是 Go 语言的类型检查。

3. **分解类型检查过程：** 注释中列出了类型检查的几个关键阶段：
    * **Name resolution (名称解析):** 将标识符 (`ast.Ident`) 映射到其代表的符号 (`Object`)。
    * **Constant folding (常量折叠):** 计算编译时常量表达式 (`ast.Expr`) 的确切常量值 (`constant.Value`)。
    * **Type deduction (类型推断):** 计算表达式 (`ast.Expr`) 的类型 (`Type`) 并检查是否符合语言规范。

4. **关联代码结构与功能：**
    * `Error` 结构体定义了类型检查错误的信息。
    * `Importer` 和 `ImporterFrom` 接口负责导入包。
    * `Config` 结构体包含了类型检查的配置选项。
    * `Info` 结构体存储了类型检查的结果信息，包括 `Types`、`Instances`、`Defs`、`Uses`、`Implicits`、`Selections`、`Scopes`、`InitOrder` 和 `FileVersions` 等 map，这些 map 对应了类型检查的不同阶段和结果。
    * `Check` 函数是执行类型检查的主要入口点。

5. **构建功能列表：** 基于以上分析，可以列出以下功能：
    * 定义类型检查过程中可能出现的错误 (`Error`)。
    * 定义了包导入器接口 (`Importer`, `ImporterFrom`)，用于查找依赖的包。
    * 定义了类型检查的配置结构体 (`Config`)，允许用户自定义类型检查的行为，例如指定 Go 版本、忽略函数体、处理 Cgo 导入等。
    * 定义了存储类型检查结果信息的结构体 (`Info`)，包含了各种映射，用于访问类型、对象、作用域等信息。
    * 提供了执行类型检查的入口函数 (`Check`)。
    * 实现了类型检查的几个核心阶段：名称解析、常量折叠、类型推断。

6. **构思 Go 代码示例：**  需要展示如何使用 `types` 包进行类型检查。最直接的方式是使用 `Config` 和 `Check` 函数。  需要构造一些简单的 Go 代码，并创建一个 `Config` 和 `Info` 实例来调用 `Check`。  重点展示如何访问 `Info` 中的 `Types` 来获取表达式的类型。

7. **思考命令行参数：**  `go/types` 包本身是一个库，通常不会直接通过命令行调用。 但可以思考 `Config` 结构体中的字段，哪些会受到构建工具或 IDE 的影响。例如，Go 版本 (`GoVersion`) 可能会在构建时指定。  Cgo 相关的选项 (`FakeImportC`, `go115UsesCgo`) 也会受到构建环境的影响。

8. **考虑易错点：**  使用 `Info` 结构体时，最容易出错的地方是不清楚哪些 map 包含了哪些信息。 例如，混淆 `Defs` 和 `Uses` 的作用，或者不了解 `Implicits` 存储了哪些隐式声明的对象。  另外，`Importer` 的使用也可能出错，特别是涉及到 vendor 目录时。

9. **组织答案并进行中文翻译：**  将以上分析组织成结构化的中文答案，包括功能列表、代码示例、命令行参数说明和易错点。 代码示例需要包含必要的注释和假设的输入输出。 命令行参数需要说明其作用。易错点需要结合具体场景进行解释。

10. **审查和完善：**  最后，仔细检查答案的准确性和完整性，确保逻辑清晰，表达准确。 特别是代码示例需要可运行，命令行参数的解释需要准确，易错点的描述需要具体。

通过以上步骤，我能够系统地分析 `go/src/go/types/api.go` 的功能并提供详细的解答。  在思考过程中，我始终将代码注释作为最重要的参考，因为它直接说明了设计意图和功能。  同时，结合 Go 语言的类型检查概念，能够更好地理解代码的含义。
这段代码是 Go 语言 `go/types` 包的核心部分，它定义了用于 Go 语言包类型检查的数据结构和算法。 让我们分解一下它的功能：

**核心功能：Go 语言的类型检查**

`go/types` 包的主要目的是对 Go 语言编写的代码进行静态类型检查。  类型检查是编译器在编译代码之前执行的一个重要步骤，它可以帮助发现代码中的类型错误，提高代码的可靠性和安全性。

**具体功能列表：**

1. **定义类型检查过程的各个阶段:**  代码注释中明确列出了类型检查的三个主要阶段：
    * **名称解析 (Name resolution):** 将程序中的标识符（`ast.Ident`）映射到其代表的符号（`Object`）。
    * **常量折叠 (Constant folding):** 计算编译时常量表达式（`ast.Expr`）的精确常量值（`constant.Value`）。
    * **类型推断 (Type deduction):** 计算每个表达式（`ast.Expr`）的类型（`Type`）并检查是否符合 Go 语言规范。

2. **定义了表示类型检查错误的结构体 `Error`:**  该结构体包含了错误发生的文件、位置、消息以及错误类型（软错误或硬错误）。

3. **定义了包导入器接口 `Importer` 和 `ImporterFrom`:** 这些接口用于解析 import 语句中引用的包。 `ImporterFrom` 支持 vendoring 机制。

4. **定义了类型检查的配置结构体 `Config`:**  `Config` 包含了进行类型检查所需的各种配置选项，例如：
    * `GoVersion`:  指定的 Go 语言版本。
    * `IgnoreFuncBodies`: 是否忽略函数体的类型检查。
    * `FakeImportC`: 是否模拟 `import "C"` (用于处理 Cgo)。
    * `Importer`:  使用的包导入器。
    * `Sizes`:  用于确定类型大小的函数。
    * `DisableUnusedImportCheck`: 是否禁用未使用的导入检查。

5. **定义了存储类型检查结果信息的结构体 `Info`:** `Info` 包含了类型检查过程中收集到的各种信息，例如：
    * `Types`:  存储表达式到其类型和常量值的映射。
    * `Instances`: 存储泛型类型或函数的实例化信息。
    * `Defs`:  存储标识符到其定义对象的映射。
    * `Uses`:  存储标识符到其使用对象的映射。
    * `Implicits`: 存储隐式声明的对象的映射。
    * `Selections`: 存储选择器表达式的对应选择信息的映射。
    * `Scopes`:  存储作用域信息的映射。
    * `InitOrder`:  存储包级别初始化器的执行顺序。
    * `FileVersions`: 存储每个文件的 Go 版本信息。

6. **提供了执行类型检查的函数 `Check`:**  `Check` 函数接收包的路径、文件集合、抽象语法树（AST）以及一个可选的 `Info` 结构体，并执行类型检查。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言**类型系统**的核心实现之一。它负责理解 Go 语言的类型规则，并根据这些规则来验证代码的正确性。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
)

func main() {
	// 源代码字符串
	src := `package foo

	import "fmt"

	func main() {
		x := 10
		y := "hello"
		fmt.Println(x + y) // 这里会触发类型错误
	}`

	// 创建一个 FileSet 和解析源代码
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		panic(err)
	}

	// 配置类型检查器
	conf := types.Config{Importer: nil, Error: func(err error) { fmt.Println(err) }}

	// 执行类型检查
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}
	pkg, err := conf.Check("foo", fset, []*ast.File{file}, info)
	if err != nil {
		fmt.Println("Type checking errors found:")
	} else {
		fmt.Println("No type checking errors.")
	}

	fmt.Println("Package:", pkg)

	// 假设输入是上面的源代码，输出将会包含类型错误信息
	// 例如: main.go:10:17: invalid operation: x + y (mismatched types int and string)

	// 我们可以访问 info 来获取更多类型信息
	for expr, tv := range info.Types {
		fmt.Printf("Expression: %v, Type: %v, Value: %v\n", expr, tv.Type, tv.Value)
	}
}
```

**假设的输入与输出：**

* **输入:** 上面的 `src` 字符串。
* **输出:**
  ```
  main.go:10:17: invalid operation: x + y (mismatched types int and string)
  Type checking errors found:
  Package: foo
  Expression: 10, Type: int, Value: 10
  Expression: "hello", Type: untyped string, Value: hello
  ```

**命令行参数的具体处理：**

`go/types` 包本身是一个库，通常不会直接通过命令行参数来调用。然而，`Config` 结构体中的字段可以间接地受到构建工具（如 `go build`）和 IDE 的影响。例如：

* **`GoVersion`:**  构建工具可能会根据项目配置或环境变量来设置 Go 语言版本，这会影响 `go/types` 的类型检查行为。
* **Cgo 相关的选项 (`FakeImportC`, `go115UsesCgo`):**  构建工具在处理包含 Cgo 代码的项目时，会根据项目的配置来设置这些选项。

**使用者易犯错的点：**

* **不理解 `Info` 结构体中不同 map 的作用:**  使用者可能会混淆 `Defs` 和 `Uses`，或者不清楚哪些信息存储在 `Implicits` 中。例如，期望在 `Types` 中找到所有标识符的类型，但实际上 `Types` 只存储表达式的类型。
* **忽略 `Config` 的重要性:**  使用者可能使用默认的 `Config`，而没有根据自己的需求进行配置。例如，在处理包含 Cgo 代码的项目时，如果忘记设置 `FakeImportC` 或 `go115UsesCgo`，可能会导致类型检查错误。
* **错误地使用 `Importer`:**  自定义 `Importer` 时，可能没有正确处理包的查找和加载，导致类型检查无法找到依赖的包。特别是对于使用了 vendoring 的项目，需要正确实现 `ImporterFrom` 接口。

这段代码是 Go 语言类型检查的核心，理解它的功能对于编写高质量的 Go 代码至关重要。通过 `go/types` 包，开发者和工具可以深入了解 Go 代码的类型信息，进行静态分析和代码验证。

Prompt: 
```
这是路径为go/src/go/types/api.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package types declares the data types and implements
// the algorithms for type-checking of Go packages. Use
// [Config.Check] to invoke the type checker for a package.
// Alternatively, create a new type checker with [NewChecker]
// and invoke it incrementally by calling [Checker.Files].
//
// Type-checking consists of several interdependent phases:
//
// Name resolution maps each identifier ([ast.Ident]) in the program
// to the symbol ([Object]) it denotes. Use the Defs and Uses fields
// of [Info] or the [Info.ObjectOf] method to find the symbol for an
// identifier, and use the Implicits field of [Info] to find the
// symbol for certain other kinds of syntax node.
//
// Constant folding computes the exact constant value
// ([constant.Value]) of every expression ([ast.Expr]) that is a
// compile-time constant. Use the Types field of [Info] to find the
// results of constant folding for an expression.
//
// Type deduction computes the type ([Type]) of every expression
// ([ast.Expr]) and checks for compliance with the language
// specification. Use the Types field of [Info] for the results of
// type deduction.
//
// For a tutorial, see https://go.dev/s/types-tutorial.
package types

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	. "internal/types/errors"
	_ "unsafe" // for linkname
)

// An Error describes a type-checking error; it implements the error interface.
// A "soft" error is an error that still permits a valid interpretation of a
// package (such as "unused variable"); "hard" errors may lead to unpredictable
// behavior if ignored.
type Error struct {
	Fset *token.FileSet // file set for interpretation of Pos
	Pos  token.Pos      // error position
	Msg  string         // error message
	Soft bool           // if set, error is "soft"

	// go116code is a future API, unexported as the set of error codes is large
	// and likely to change significantly during experimentation. Tools wishing
	// to preview this feature may read go116code using reflection (see
	// errorcodes_test.go), but beware that there is no guarantee of future
	// compatibility.
	go116code  Code
	go116start token.Pos
	go116end   token.Pos
}

// Error returns an error string formatted as follows:
// filename:line:column: message
func (err Error) Error() string {
	return fmt.Sprintf("%s: %s", err.Fset.Position(err.Pos), err.Msg)
}

// An ArgumentError holds an error associated with an argument index.
type ArgumentError struct {
	Index int
	Err   error
}

func (e *ArgumentError) Error() string { return e.Err.Error() }
func (e *ArgumentError) Unwrap() error { return e.Err }

// An Importer resolves import paths to Packages.
//
// CAUTION: This interface does not support the import of locally
// vendored packages. See https://golang.org/s/go15vendor.
// If possible, external implementations should implement [ImporterFrom].
type Importer interface {
	// Import returns the imported package for the given import path.
	// The semantics is like for ImporterFrom.ImportFrom except that
	// dir and mode are ignored (since they are not present).
	Import(path string) (*Package, error)
}

// ImportMode is reserved for future use.
type ImportMode int

// An ImporterFrom resolves import paths to packages; it
// supports vendoring per https://golang.org/s/go15vendor.
// Use go/importer to obtain an ImporterFrom implementation.
type ImporterFrom interface {
	// Importer is present for backward-compatibility. Calling
	// Import(path) is the same as calling ImportFrom(path, "", 0);
	// i.e., locally vendored packages may not be found.
	// The types package does not call Import if an ImporterFrom
	// is present.
	Importer

	// ImportFrom returns the imported package for the given import
	// path when imported by a package file located in dir.
	// If the import failed, besides returning an error, ImportFrom
	// is encouraged to cache and return a package anyway, if one
	// was created. This will reduce package inconsistencies and
	// follow-on type checker errors due to the missing package.
	// The mode value must be 0; it is reserved for future use.
	// Two calls to ImportFrom with the same path and dir must
	// return the same package.
	ImportFrom(path, dir string, mode ImportMode) (*Package, error)
}

// A Config specifies the configuration for type checking.
// The zero value for Config is a ready-to-use default configuration.
type Config struct {
	// Context is the context used for resolving global identifiers. If nil, the
	// type checker will initialize this field with a newly created context.
	Context *Context

	// GoVersion describes the accepted Go language version. The string must
	// start with a prefix of the form "go%d.%d" (e.g. "go1.20", "go1.21rc1", or
	// "go1.21.0") or it must be empty; an empty string disables Go language
	// version checks. If the format is invalid, invoking the type checker will
	// result in an error.
	GoVersion string

	// If IgnoreFuncBodies is set, function bodies are not
	// type-checked.
	IgnoreFuncBodies bool

	// If FakeImportC is set, `import "C"` (for packages requiring Cgo)
	// declares an empty "C" package and errors are omitted for qualified
	// identifiers referring to package C (which won't find an object).
	// This feature is intended for the standard library cmd/api tool.
	//
	// Caution: Effects may be unpredictable due to follow-on errors.
	//          Do not use casually!
	FakeImportC bool

	// If go115UsesCgo is set, the type checker expects the
	// _cgo_gotypes.go file generated by running cmd/cgo to be
	// provided as a package source file. Qualified identifiers
	// referring to package C will be resolved to cgo-provided
	// declarations within _cgo_gotypes.go.
	//
	// It is an error to set both FakeImportC and go115UsesCgo.
	go115UsesCgo bool

	// If _Trace is set, a debug trace is printed to stdout.
	_Trace bool

	// If Error != nil, it is called with each error found
	// during type checking; err has dynamic type Error.
	// Secondary errors (for instance, to enumerate all types
	// involved in an invalid recursive type declaration) have
	// error strings that start with a '\t' character.
	// If Error == nil, type-checking stops with the first
	// error found.
	Error func(err error)

	// An importer is used to import packages referred to from
	// import declarations.
	// If the installed importer implements ImporterFrom, the type
	// checker calls ImportFrom instead of Import.
	// The type checker reports an error if an importer is needed
	// but none was installed.
	Importer Importer

	// If Sizes != nil, it provides the sizing functions for package unsafe.
	// Otherwise SizesFor("gc", "amd64") is used instead.
	Sizes Sizes

	// If DisableUnusedImportCheck is set, packages are not checked
	// for unused imports.
	DisableUnusedImportCheck bool

	// If a non-empty _ErrorURL format string is provided, it is used
	// to format an error URL link that is appended to the first line
	// of an error message. ErrorURL must be a format string containing
	// exactly one "%s" format, e.g. "[go.dev/e/%s]".
	_ErrorURL string

	// If EnableAlias is set, alias declarations produce an Alias type. Otherwise
	// the alias information is only in the type name, which points directly to
	// the actual (aliased) type.
	//
	// This setting must not differ among concurrent type-checking operations,
	// since it affects the behavior of Universe.Lookup("any").
	//
	// This flag will eventually be removed (with Go 1.24 at the earliest).
	_EnableAlias bool
}

// Linkname for use from srcimporter.
//go:linkname srcimporter_setUsesCgo

func srcimporter_setUsesCgo(conf *Config) {
	conf.go115UsesCgo = true
}

// Info holds result type information for a type-checked package.
// Only the information for which a map is provided is collected.
// If the package has type errors, the collected information may
// be incomplete.
type Info struct {
	// Types maps expressions to their types, and for constant
	// expressions, also their values. Invalid expressions are
	// omitted.
	//
	// For (possibly parenthesized) identifiers denoting built-in
	// functions, the recorded signatures are call-site specific:
	// if the call result is not a constant, the recorded type is
	// an argument-specific signature. Otherwise, the recorded type
	// is invalid.
	//
	// The Types map does not record the type of every identifier,
	// only those that appear where an arbitrary expression is
	// permitted. For instance, the identifier f in a selector
	// expression x.f is found only in the Selections map, the
	// identifier z in a variable declaration 'var z int' is found
	// only in the Defs map, and identifiers denoting packages in
	// qualified identifiers are collected in the Uses map.
	Types map[ast.Expr]TypeAndValue

	// Instances maps identifiers denoting generic types or functions to their
	// type arguments and instantiated type.
	//
	// For example, Instances will map the identifier for 'T' in the type
	// instantiation T[int, string] to the type arguments [int, string] and
	// resulting instantiated *Named type. Given a generic function
	// func F[A any](A), Instances will map the identifier for 'F' in the call
	// expression F(int(1)) to the inferred type arguments [int], and resulting
	// instantiated *Signature.
	//
	// Invariant: Instantiating Uses[id].Type() with Instances[id].TypeArgs
	// results in an equivalent of Instances[id].Type.
	Instances map[*ast.Ident]Instance

	// Defs maps identifiers to the objects they define (including
	// package names, dots "." of dot-imports, and blank "_" identifiers).
	// For identifiers that do not denote objects (e.g., the package name
	// in package clauses, or symbolic variables t in t := x.(type) of
	// type switch headers), the corresponding objects are nil.
	//
	// For an embedded field, Defs returns the field *Var it defines.
	//
	// Invariant: Defs[id] == nil || Defs[id].Pos() == id.Pos()
	Defs map[*ast.Ident]Object

	// Uses maps identifiers to the objects they denote.
	//
	// For an embedded field, Uses returns the *TypeName it denotes.
	//
	// Invariant: Uses[id].Pos() != id.Pos()
	Uses map[*ast.Ident]Object

	// Implicits maps nodes to their implicitly declared objects, if any.
	// The following node and object types may appear:
	//
	//     node               declared object
	//
	//     *ast.ImportSpec    *PkgName for imports without renames
	//     *ast.CaseClause    type-specific *Var for each type switch case clause (incl. default)
	//     *ast.Field         anonymous parameter *Var (incl. unnamed results)
	//
	Implicits map[ast.Node]Object

	// Selections maps selector expressions (excluding qualified identifiers)
	// to their corresponding selections.
	Selections map[*ast.SelectorExpr]*Selection

	// Scopes maps ast.Nodes to the scopes they define. Package scopes are not
	// associated with a specific node but with all files belonging to a package.
	// Thus, the package scope can be found in the type-checked Package object.
	// Scopes nest, with the Universe scope being the outermost scope, enclosing
	// the package scope, which contains (one or more) files scopes, which enclose
	// function scopes which in turn enclose statement and function literal scopes.
	// Note that even though package-level functions are declared in the package
	// scope, the function scopes are embedded in the file scope of the file
	// containing the function declaration.
	//
	// The Scope of a function contains the declarations of any
	// type parameters, parameters, and named results, plus any
	// local declarations in the body block.
	// It is coextensive with the complete extent of the
	// function's syntax ([*ast.FuncDecl] or [*ast.FuncLit]).
	// The Scopes mapping does not contain an entry for the
	// function body ([*ast.BlockStmt]); the function's scope is
	// associated with the [*ast.FuncType].
	//
	// The following node types may appear in Scopes:
	//
	//     *ast.File
	//     *ast.FuncType
	//     *ast.TypeSpec
	//     *ast.BlockStmt
	//     *ast.IfStmt
	//     *ast.SwitchStmt
	//     *ast.TypeSwitchStmt
	//     *ast.CaseClause
	//     *ast.CommClause
	//     *ast.ForStmt
	//     *ast.RangeStmt
	//
	Scopes map[ast.Node]*Scope

	// InitOrder is the list of package-level initializers in the order in which
	// they must be executed. Initializers referring to variables related by an
	// initialization dependency appear in topological order, the others appear
	// in source order. Variables without an initialization expression do not
	// appear in this list.
	InitOrder []*Initializer

	// FileVersions maps a file to its Go version string.
	// If the file doesn't specify a version, the reported
	// string is Config.GoVersion.
	// Version strings begin with “go”, like “go1.21”, and
	// are suitable for use with the [go/version] package.
	FileVersions map[*ast.File]string
}

func (info *Info) recordTypes() bool {
	return info.Types != nil
}

// TypeOf returns the type of expression e, or nil if not found.
// Precondition: the Types, Uses and Defs maps are populated.
func (info *Info) TypeOf(e ast.Expr) Type {
	if t, ok := info.Types[e]; ok {
		return t.Type
	}
	if id, _ := e.(*ast.Ident); id != nil {
		if obj := info.ObjectOf(id); obj != nil {
			return obj.Type()
		}
	}
	return nil
}

// ObjectOf returns the object denoted by the specified id,
// or nil if not found.
//
// If id is an embedded struct field, [Info.ObjectOf] returns the field (*[Var])
// it defines, not the type (*[TypeName]) it uses.
//
// Precondition: the Uses and Defs maps are populated.
func (info *Info) ObjectOf(id *ast.Ident) Object {
	if obj := info.Defs[id]; obj != nil {
		return obj
	}
	return info.Uses[id]
}

// PkgNameOf returns the local package name defined by the import,
// or nil if not found.
//
// For dot-imports, the package name is ".".
//
// Precondition: the Defs and Implicts maps are populated.
func (info *Info) PkgNameOf(imp *ast.ImportSpec) *PkgName {
	var obj Object
	if imp.Name != nil {
		obj = info.Defs[imp.Name]
	} else {
		obj = info.Implicits[imp]
	}
	pkgname, _ := obj.(*PkgName)
	return pkgname
}

// TypeAndValue reports the type and value (for constants)
// of the corresponding expression.
type TypeAndValue struct {
	mode  operandMode
	Type  Type
	Value constant.Value
}

// IsVoid reports whether the corresponding expression
// is a function call without results.
func (tv TypeAndValue) IsVoid() bool {
	return tv.mode == novalue
}

// IsType reports whether the corresponding expression specifies a type.
func (tv TypeAndValue) IsType() bool {
	return tv.mode == typexpr
}

// IsBuiltin reports whether the corresponding expression denotes
// a (possibly parenthesized) built-in function.
func (tv TypeAndValue) IsBuiltin() bool {
	return tv.mode == builtin
}

// IsValue reports whether the corresponding expression is a value.
// Builtins are not considered values. Constant values have a non-
// nil Value.
func (tv TypeAndValue) IsValue() bool {
	switch tv.mode {
	case constant_, variable, mapindex, value, commaok, commaerr:
		return true
	}
	return false
}

// IsNil reports whether the corresponding expression denotes the
// predeclared value nil.
func (tv TypeAndValue) IsNil() bool {
	return tv.mode == value && tv.Type == Typ[UntypedNil]
}

// Addressable reports whether the corresponding expression
// is addressable (https://golang.org/ref/spec#Address_operators).
func (tv TypeAndValue) Addressable() bool {
	return tv.mode == variable
}

// Assignable reports whether the corresponding expression
// is assignable to (provided a value of the right type).
func (tv TypeAndValue) Assignable() bool {
	return tv.mode == variable || tv.mode == mapindex
}

// HasOk reports whether the corresponding expression may be
// used on the rhs of a comma-ok assignment.
func (tv TypeAndValue) HasOk() bool {
	return tv.mode == commaok || tv.mode == mapindex
}

// Instance reports the type arguments and instantiated type for type and
// function instantiations. For type instantiations, [Type] will be of dynamic
// type *[Named]. For function instantiations, [Type] will be of dynamic type
// *Signature.
type Instance struct {
	TypeArgs *TypeList
	Type     Type
}

// An Initializer describes a package-level variable, or a list of variables in case
// of a multi-valued initialization expression, and the corresponding initialization
// expression.
type Initializer struct {
	Lhs []*Var // var Lhs = Rhs
	Rhs ast.Expr
}

func (init *Initializer) String() string {
	var buf bytes.Buffer
	for i, lhs := range init.Lhs {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(lhs.Name())
	}
	buf.WriteString(" = ")
	WriteExpr(&buf, init.Rhs)
	return buf.String()
}

// Check type-checks a package and returns the resulting package object and
// the first error if any. Additionally, if info != nil, Check populates each
// of the non-nil maps in the [Info] struct.
//
// The package is marked as complete if no errors occurred, otherwise it is
// incomplete. See [Config.Error] for controlling behavior in the presence of
// errors.
//
// The package is specified by a list of *ast.Files and corresponding
// file set, and the package path the package is identified with.
// The clean path must not be empty or dot (".").
func (conf *Config) Check(path string, fset *token.FileSet, files []*ast.File, info *Info) (*Package, error) {
	pkg := NewPackage(path, "")
	return pkg, NewChecker(conf, fset, pkg, info).Files(files)
}

"""



```