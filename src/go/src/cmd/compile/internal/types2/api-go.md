Response: Let's break down the request and analyze the provided Go code. The goal is to understand the functionality of `go/src/cmd/compile/internal/types2/api.go`.

**1. Initial Understanding of the Code:**

The code snippet is from the `types2` package, a key part of the Go compiler responsible for type checking. The comments at the beginning clearly state its purpose: declaring data types and implementing algorithms for type checking. It mentions the core phases: name resolution, constant folding, and type inference.

**2. Deconstructing the Request:**

The request asks for the following:

* **List the functionalities:**  This requires identifying the key components and their roles within the type-checking process. I'll need to look at the structs, interfaces, and functions defined in the code.
* **Infer Go language feature implementation (with examples):**  This involves connecting the code to higher-level Go language concepts. For instance, the `Importer` interface relates to the `import` statement. I'll need to provide Go code examples to illustrate these connections.
* **Code inference with assumptions (input/output):** When providing code examples, I should illustrate how the `types2` package *might* be used, even though it's an internal package. This will require making reasonable assumptions about inputs and the expected outputs from the type checker.
* **Command-line parameter handling:**  This is less prominent in this specific file, which focuses more on the API. However, I need to scan for anything relevant, even if indirectly related (e.g., configurations that might be set via command-line flags in other parts of the compiler).
* **Common mistakes:**  This requires thinking about how developers might misuse the API, particularly around configuration or assumptions about the type-checking process.

**3. Functionality Identification (Iterating through the code):**

* **`Error` struct:**  Represents a type-checking error, containing position, message, and severity.
* **`ArgumentError` struct:**  Represents an error associated with a function argument.
* **`Importer` interface:**  Abstracts the process of resolving import paths to `Package` objects. This is crucial for handling dependencies.
* **`ImporterFrom` interface:**  An extended `Importer` that supports vendoring.
* **`ImportMode` type:** Reserved for future use (important to note limitations).
* **`Config` struct:**  Holds configuration options for the type checker (Go version, ignoring function bodies, Cgo settings, tracing, error handling, importer, sizes, etc.). This is central to customizing the type-checking process.
* **`Info` struct:**  Stores the results of the type-checking process. This includes mappings for types, definitions, uses, implicit declarations, selections, scopes, and initialization order. This is the primary output of the type checker.
* **`TypeAndValue` struct:**  Combines the type and constant value of an expression.
* **`Instance` struct:** Represents the type arguments and instantiated type for generic types/functions.
* **`Initializer` struct:**  Describes a package-level variable and its initialization expression.
* **`Check` function:** The main entry point for type-checking a package. It uses a `Config` and produces a `Package` and potential errors.

**4. Inferring Go Language Features:**

* **`Importer` and `ImporterFrom`:** Directly relate to the `import` statement and how Go resolves package dependencies.
* **`Config.GoVersion`:**  Connects to the `//go:build goXX` directives and language versioning features.
* **`Config.IgnoreFuncBodies`:**  Might be used in tools that need to analyze code structure without fully type-checking function implementations (e.g., linters, documentation generators).
* **`Config.FakeImportC` and `Config.go115UsesCgo`:**  Clearly tied to Cgo integration.
* **`Info.Types`:** Reflects the type inference system in Go, determining the type of expressions.
* **`Info.Defs` and `Info.Uses`:**  Represent name resolution, linking identifiers to their declared objects.
* **`Info.Scopes`:**  Underpins Go's lexical scoping rules.
* **`Info.Instances`:**  Directly relates to Go's generics feature.
* **`Initializer`:**  Reflects the initialization order of package-level variables.

**5. Code Inference (Example Scenarios):**

I'll create simple scenarios demonstrating how the `types2` package could be used conceptually. Since it's internal, direct usage is unlikely, but we can simulate its behavior.

* **Scenario: Resolving a variable's type:** Show how `Info.Types` or `Info.ObjectOf` could be used to get the type of a variable.
* **Scenario:  Checking an import:**  Illustrate the role of the `Importer` in finding a package.
* **Scenario:  Working with generics:** Demonstrate how `Info.Instances` captures generic instantiation information.

**6. Command-Line Parameters:**

While this file doesn't directly handle command-line arguments, the `Config` struct contains fields that are *likely* influenced by compiler flags. I'll mention this connection but clarify that the file itself doesn't parse flags. Examples might include `-lang` for `GoVersion`, or flags related to Cgo.

**7. Common Mistakes:**

* **Incorrect `Importer` implementation:**  A custom importer that doesn't correctly handle package paths or vendoring can lead to errors.
* **Assuming `Info` is always complete:**  If type-checking fails, the information in `Info` might be incomplete or inaccurate.
* **Misunderstanding the purpose of `FakeImportC`:**  Using it outside of its intended scope (like the `cmd/api` tool) can have unpredictable consequences.
* **Not considering the impact of `EnableAlias`:** This flag affects the representation of type aliases, which could lead to subtle differences in type comparisons if not consistently used.

**Pre-computation/Analysis Complete.**  I now have a solid understanding of the code and the request. I can proceed with generating the structured response.

`go/src/cmd/compile/internal/types2/api.go` 文件是 Go 语言编译器 `types2` 包的核心部分，它定义了用于 Go 语言包类型检查的数据结构和接口。这个包实现了 Go 语言的类型检查算法。

以下是 `api.go` 文件的主要功能：

1. **定义了类型检查过程中使用的核心数据结构:**
   - `Error`:  表示一个类型检查错误，包含了错误的位置、消息、完整消息（用于调试）、是否为软错误以及错误代码。
   - `ArgumentError`: 表示与函数参数相关的错误。
   - `Importer` 和 `ImporterFrom`:  定义了导入器接口，用于将导入路径解析为 `Package` 对象。`ImporterFrom` 接口支持 Go Modules 的 vendor 机制。
   - `Config`:  包含了类型检查的配置信息，例如 Go 语言版本、是否忽略函数体、是否启用 CGO 相关特性、是否打印跟踪信息、错误处理函数、导入器、大小信息等。
   - `Info`:  存储了类型检查的结果信息，包括表达式的类型和值、标识符的定义和使用、隐式声明的对象、选择器表达式的选择信息、作用域信息、初始化顺序以及文件对应的 Go 版本。
   - `TypeAndValue`:  表示表达式的类型和值（用于常量表达式）。
   - `Instance`: 表示泛型类型或函数的实例化信息，包括类型参数和实例化后的类型。
   - `Initializer`:  描述了包级别变量的初始化表达式。

2. **定义了类型检查的入口点:**
   - `Check` 函数是执行类型检查的主要函数。它接收包的路径、语法树文件列表和配置信息，返回类型检查后的 `Package` 对象以及可能发生的错误。

3. **提供了访问类型检查结果的便捷方法:**
   - `Info` 结构体中的各种 map 提供了访问类型、定义、使用等信息的途径。
   - `Info.TypeOf`:  返回表达式的类型。
   - `Info.ObjectOf`: 返回标识符所指代的对象。
   - `Info.PkgNameOf`: 返回 import 声明定义的本地包名。

**它是什么 Go 语言功能的实现？**

`types2` 包是 Go 语言编译器中类型检查功能的具体实现。类型检查是编译过程中的一个关键步骤，它确保代码符合 Go 语言的类型系统规则，例如：

- **类型匹配:** 检查赋值、函数调用等操作中类型的兼容性。
- **名称解析:** 将代码中的标识符关联到其声明的对象（变量、函数、类型等）。
- **常量求值:** 在编译时计算常量表达式的值。
- **泛型实例化:**  处理泛型类型和函数的实例化过程。
- **作用域管理:**  维护和查找标识符在不同作用域中的定义。
- **导入处理:**  解析 `import` 语句，加载依赖的包。
- **初始化顺序:**  确定包级别变量的初始化顺序。

**Go 代码举例说明:**

虽然 `types2` 包是编译器内部使用的，但我们可以模拟其功能来理解其作用。假设我们有以下 Go 代码片段：

```go
package main

import "fmt"

const x = 10

var y int = x + 5

func add(a int, b int) int {
	return a + b
}

func main() {
	z := add(y, 20)
	fmt.Println(z)
}
```

如果我们使用 `types2` 包对这段代码进行类型检查（这通常由编译器完成），`Info` 结构体将会包含以下信息（部分）：

**假设输入:**  表示上述代码的 `syntax.File` 结构体列表。

**推理和输出:**

- **`Info.Types`:**
  - 对于表达式 `10`，`Info.Types[表达式]` 的 `Type` 将是 `untyped int`，`Value` 将是 `constant.MakeInt64(10)`。
  - 对于表达式 `x + 5`，`Info.Types[表达式]` 的 `Type` 将是 `untyped int`，`Value` 将是 `constant.MakeInt64(15)`。
  - 对于变量 `z` 的赋值表达式 `add(y, 20)`，`Info.Types[表达式]` 的 `Type` 将是 `int`。
- **`Info.Defs`:**
  - `Info.Defs["x"]` 将指向常量 `x` 的 `Object`（一个 `Const` 类型）。
  - `Info.Defs["y"]` 将指向变量 `y` 的 `Object`（一个 `Var` 类型）。
  - `Info.Defs["add"]` 将指向函数 `add` 的 `Object`（一个 `Func` 类型）。
  - `Info.Defs["main"]` 将指向函数 `main` 的 `Object`。
  - `Info.Defs["z"]` 将指向变量 `z` 的 `Object`。
- **`Info.Uses`:**
  - `Info.Uses["fmt"]` 将指向 `import "fmt"` 引入的包名对象。
  - 在 `y int = x + 5` 中，`Info.Uses["x"]` 将指向常量 `x` 的 `Object`。
  - 在 `z := add(y, 20)` 中，`Info.Uses["add"]` 将指向函数 `add` 的 `Object`，`Info.Uses["y"]` 将指向变量 `y` 的 `Object`。
- **`Info.Scopes`:**
  - 将包含包级别作用域，其中定义了 `x`、`y`、`add` 和 `main`。
  - 将包含 `main` 函数的作用域，其中定义了 `z`。
  - 将包含 `add` 函数的作用域，其中定义了参数 `a` 和 `b`。
- **`Info.InitOrder`:**
  - 将包含 `y` 的初始化信息，因为它有初始化表达式 `x + 5`。

**命令行参数的具体处理:**

`api.go` 文件本身并不直接处理命令行参数。命令行参数的处理通常发生在 `cmd/compile/internal/gc` 包或其他更上层的编译器组件中。这些组件会解析命令行参数，并根据参数的值来配置 `types2` 包的 `Config` 结构体。

例如，以下是一些可能通过命令行参数影响 `Config` 的情况：

- **`-lang` 或 `-gcflags=-std=go1.xx`**:  这些参数会影响 `Config.GoVersion`，指定要使用的 Go 语言版本。
- **`-N`**:  可能影响到是否需要进行更精细的类型信息收集，但这通常不是直接控制 `types2` 的配置。
- **CGO 相关的参数 (例如 `-cgo_flags`)**:  可能会间接影响到是否设置 `Config.go115UsesCgo`。

**使用者易犯错的点:**

由于 `types2` 包是编译器内部使用，普通 Go 开发者不会直接使用它。然而，如果开发者尝试编写需要进行静态分析或类型检查的工具，并且选择使用 `types2` 包（尽管通常会使用 `go/types` 包，它是 `types2` 的公开 API），可能会遇到以下易错点：

1. **不正确的 `Importer` 实现:**  如果需要自定义导入行为，开发者需要实现 `Importer` 或 `ImporterFrom` 接口。错误的实现可能导致找不到依赖包或加载错误的包版本。例如，一个简单的错误是只查找标准库的包，而忽略了项目内部的包或 vendor 目录下的包。

   ```go
   type MyImporter struct{}

   func (m MyImporter) Import(path string) (*Package, error) {
       // 错误：只查找标准库
       if pkg, ok := stdlibPackages[path]; ok {
           return pkg, nil
       }
       return nil, fmt.Errorf("package not found: %s", path)
   }
   ```

2. **错误地理解 `Config` 的各个选项:**  `Config` 结构体有很多选项，每个选项都会影响类型检查的行为。不理解这些选项的含义可能会导致意外的结果。例如，错误地设置 `IgnoreFuncBodies` 可能会导致某些类型检查被跳过。

3. **假设 `Info` 中的所有信息始终完整和正确:**  如果类型检查过程中发生错误，`Info` 结构体中的某些信息可能是不完整的或不准确的。依赖这些不完整的信息进行进一步分析可能会导致错误。

4. **混淆 `types2` 和 `go/types`:**  `go/types` 包是 Go 标准库提供的公开的类型检查 API，而 `types2` 是编译器内部的实现。直接使用 `types2` 包可能会面临 API 不稳定和未来更改的风险。通常应该优先使用 `go/types`。

总而言之，`go/src/cmd/compile/internal/types2/api.go` 文件定义了 Go 语言类型检查的核心数据结构和接口，是实现 Go 语言类型系统规则的关键组成部分。它虽然是编译器内部使用，但其设计思想和包含的概念对于理解 Go 语言的类型系统至关重要。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/types2/api.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package types2 declares the data types and implements
// the algorithms for type-checking of Go packages. Use
// Config.Check to invoke the type checker for a package.
// Alternatively, create a new type checker with NewChecker
// and invoke it incrementally by calling Checker.Files.
//
// Type-checking consists of several interdependent phases:
//
// Name resolution maps each identifier (syntax.Name) in the program to the
// language object (Object) it denotes.
// Use Info.{Defs,Uses,Implicits} for the results of name resolution.
//
// Constant folding computes the exact constant value (constant.Value)
// for every expression (syntax.Expr) that is a compile-time constant.
// Use Info.Types[expr].Value for the results of constant folding.
//
// Type inference computes the type (Type) of every expression (syntax.Expr)
// and checks for compliance with the language specification.
// Use Info.Types[expr].Type for the results of type inference.
package types2

import (
	"cmd/compile/internal/syntax"
	"fmt"
	"go/constant"
	. "internal/types/errors"
	"strings"
)

// An Error describes a type-checking error; it implements the error interface.
// A "soft" error is an error that still permits a valid interpretation of a
// package (such as "unused variable"); "hard" errors may lead to unpredictable
// behavior if ignored.
type Error struct {
	Pos  syntax.Pos // error position
	Msg  string     // default error message, user-friendly
	Full string     // full error message, for debugging (may contain internal details)
	Soft bool       // if set, error is "soft"
	Code Code       // error code
}

// Error returns an error string formatted as follows:
// filename:line:column: message
func (err Error) Error() string {
	return fmt.Sprintf("%s: %s", err.Pos, err.Msg)
}

// FullError returns an error string like Error, buy it may contain
// type-checker internal details such as subscript indices for type
// parameters and more. Useful for debugging.
func (err Error) FullError() string {
	return fmt.Sprintf("%s: %s", err.Pos, err.Full)
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
// If possible, external implementations should implement ImporterFrom.
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

	// If IgnoreBranchErrors is set, branch/label errors are ignored.
	IgnoreBranchErrors bool

	// If go115UsesCgo is set, the type checker expects the
	// _cgo_gotypes.go file generated by running cmd/cgo to be
	// provided as a package source file. Qualified identifiers
	// referring to package C will be resolved to cgo-provided
	// declarations within _cgo_gotypes.go.
	//
	// It is an error to set both FakeImportC and go115UsesCgo.
	go115UsesCgo bool

	// If Trace is set, a debug trace is printed to stdout.
	Trace bool

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

	// If a non-empty ErrorURL format string is provided, it is used
	// to format an error URL link that is appended to the first line
	// of an error message. ErrorURL must be a format string containing
	// exactly one "%s" format, e.g. "[go.dev/e/%s]".
	ErrorURL string

	// If EnableAlias is set, alias declarations produce an Alias type. Otherwise
	// the alias information is only in the type name, which points directly to
	// the actual (aliased) type.
	//
	// This setting must not differ among concurrent type-checking operations,
	// since it affects the behavior of Universe.Lookup("any").
	//
	// This flag will eventually be removed (with Go 1.24 at the earliest).
	EnableAlias bool
}

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
	Types map[syntax.Expr]TypeAndValue

	// If StoreTypesInSyntax is set, type information identical to
	// that which would be put in the Types map, will be set in
	// syntax.Expr.TypeAndValue (independently of whether Types
	// is nil or not).
	StoreTypesInSyntax bool

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
	Instances map[*syntax.Name]Instance

	// Defs maps identifiers to the objects they define (including
	// package names, dots "." of dot-imports, and blank "_" identifiers).
	// For identifiers that do not denote objects (e.g., the package name
	// in package clauses, or symbolic variables t in t := x.(type) of
	// type switch headers), the corresponding objects are nil.
	//
	// For an embedded field, Defs returns the field *Var it defines.
	//
	// Invariant: Defs[id] == nil || Defs[id].Pos() == id.Pos()
	Defs map[*syntax.Name]Object

	// Uses maps identifiers to the objects they denote.
	//
	// For an embedded field, Uses returns the *TypeName it denotes.
	//
	// Invariant: Uses[id].Pos() != id.Pos()
	Uses map[*syntax.Name]Object

	// Implicits maps nodes to their implicitly declared objects, if any.
	// The following node and object types may appear:
	//
	//     node               declared object
	//
	//     *syntax.ImportDecl    *PkgName for imports without renames
	//     *syntax.CaseClause    type-specific *Var for each type switch case clause (incl. default)
	//     *syntax.Field         anonymous parameter *Var (incl. unnamed results)
	//
	Implicits map[syntax.Node]Object

	// Selections maps selector expressions (excluding qualified identifiers)
	// to their corresponding selections.
	Selections map[*syntax.SelectorExpr]*Selection

	// Scopes maps syntax.Nodes to the scopes they define. Package scopes are not
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
	//     *syntax.File
	//     *syntax.FuncType
	//     *syntax.TypeDecl
	//     *syntax.BlockStmt
	//     *syntax.IfStmt
	//     *syntax.SwitchStmt
	//     *syntax.CaseClause
	//     *syntax.CommClause
	//     *syntax.ForStmt
	//
	Scopes map[syntax.Node]*Scope

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
	FileVersions map[*syntax.PosBase]string
}

func (info *Info) recordTypes() bool {
	return info.Types != nil || info.StoreTypesInSyntax
}

// TypeOf returns the type of expression e, or nil if not found.
// Precondition 1: the Types map is populated or StoreTypesInSyntax is set.
// Precondition 2: Uses and Defs maps are populated.
func (info *Info) TypeOf(e syntax.Expr) Type {
	if info.Types != nil {
		if t, ok := info.Types[e]; ok {
			return t.Type
		}
	} else if info.StoreTypesInSyntax {
		if tv := e.GetTypeInfo(); tv.Type != nil {
			return tv.Type
		}
	}

	if id, _ := e.(*syntax.Name); id != nil {
		if obj := info.ObjectOf(id); obj != nil {
			return obj.Type()
		}
	}
	return nil
}

// ObjectOf returns the object denoted by the specified id,
// or nil if not found.
//
// If id is an embedded struct field, ObjectOf returns the field (*Var)
// it defines, not the type (*TypeName) it uses.
//
// Precondition: the Uses and Defs maps are populated.
func (info *Info) ObjectOf(id *syntax.Name) Object {
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
func (info *Info) PkgNameOf(imp *syntax.ImportDecl) *PkgName {
	var obj Object
	if imp.LocalPkgName != nil {
		obj = info.Defs[imp.LocalPkgName]
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
	case constant_, variable, mapindex, value, nilvalue, commaok, commaerr:
		return true
	}
	return false
}

// IsNil reports whether the corresponding expression denotes the
// predeclared value nil. Depending on context, it may have been
// given a type different from UntypedNil.
func (tv TypeAndValue) IsNil() bool {
	return tv.mode == nilvalue
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
// function instantiations. For type instantiations, Type will be of dynamic
// type *Named. For function instantiations, Type will be of dynamic type
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
	Rhs syntax.Expr
}

func (init *Initializer) String() string {
	var buf strings.Builder
	for i, lhs := range init.Lhs {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(lhs.Name())
	}
	buf.WriteString(" = ")
	syntax.Fprint(&buf, init.Rhs, syntax.ShortForm)
	return buf.String()
}

// Check type-checks a package and returns the resulting package object and
// the first error if any. Additionally, if info != nil, Check populates each
// of the non-nil maps in the Info struct.
//
// The package is marked as complete if no errors occurred, otherwise it is
// incomplete. See Config.Error for controlling behavior in the presence of
// errors.
//
// The package is specified by a list of *syntax.Files and corresponding
// file set, and the package path the package is identified with.
// The clean path must not be empty or dot (".").
func (conf *Config) Check(path string, files []*syntax.File, info *Info) (*Package, error) {
	pkg := NewPackage(path, "")
	return pkg, NewChecker(conf, pkg, info).Files(files)
}

"""



```