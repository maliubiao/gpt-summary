Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Initial Skim for Familiar Concepts:**  My first pass involves quickly scanning for keywords and structures I recognize from Go's type system and compiler. I see `package types`, `import`, `struct`, `func`, `ast`, `constant`, `token`, `error`, `Scope`, `Object`, `Package`, `Checker`, etc. These immediately suggest this code is deeply involved in the type-checking process.

2. **Identifying Key Data Structures:** I notice several important struct types: `declInfo`, `Checker`, `PkgName`, and `Package`. The relationships between these structs are crucial. `declInfo` seems to hold information about declarations. `Checker` is likely the central type-checking engine. `PkgName` represents imported packages. `Package` represents a Go package.

3. **Focusing on `declInfo`:** The comment for `declInfo` is a good starting point: "A declInfo describes a package-level const, type, var, or func declaration." This tells me the purpose of this struct. The fields within it provide more detail: `file`, `version`, `lhs`, `vtyp`, `init`, `inherited`, `tdecl`, `fdecl`, and `deps`. I can infer that this struct helps track the attributes and dependencies of various kinds of declarations.

4. **Analyzing `Checker` Methods:**  I then look at the methods defined on the `Checker` struct. Methods like `arityMatch`, `validatedImportPath`, `declarePkgObj`, `importPackage`, `collectObjects`, `unpackRecv`, `resolveBaseTypeName`, `packageObjects`, and `unusedImports` give strong hints about the code's functionality.

5. **Inferring Functionality from Method Names:**
    * `arityMatch`: Likely checks if the number of left-hand side variables matches the number of right-hand side expressions in assignments.
    * `validatedImportPath`:  Probably validates and unquotes import paths.
    * `declarePkgObj`:  Seems to register package-level objects (constants, types, variables, functions) in the package's scope.
    * `importPackage`: Deals with importing other Go packages. This likely involves interacting with the file system or an import resolver.
    * `collectObjects`:  A crucial function! The name suggests it gathers all the declared objects within a package.
    * `unpackRecv`:  Seems to dissect receiver types in method declarations.
    * `resolveBaseTypeName`:  Likely resolves type aliases and finds the underlying concrete type.
    * `packageObjects`:  Suggests type-checking of package-level entities.
    * `unusedImports`: Checks for and reports unused import statements.

6. **Connecting Methods to Go Features:** Now, I start connecting these methods to specific Go language features:
    * **Imports:** `importPackage` and `unusedImports` directly relate to the `import` statement.
    * **Declarations:** `declarePkgObj`, `collectObjects`, and `declInfo` are central to handling `const`, `type`, `var`, and `func` declarations.
    * **Method Receivers:** `unpackRecv` and `resolveBaseTypeName` are clearly involved in how methods are defined with receivers.
    * **Type Aliases:** `resolveBaseTypeName` explicitly mentions handling type aliases.
    * **Initialization:** `arityMatch` and the `init` field in `declInfo` point to how Go handles variable and constant initialization.

7. **Formulating Examples:**  With these connections in mind, I can start constructing simple Go code examples to illustrate the functionality. For instance, to demonstrate `arityMatch`, I'd create examples of correct and incorrect variable assignments. For `importPackage`, I would show a basic import statement and perhaps a failing one. For method receivers, I'd define a struct and a method with a pointer receiver.

8. **Considering Edge Cases and Errors:** I look for error-related code and comments. The `check.error`, `check.errorf`, and the various error codes (like `WrongAssignCount`, `BadImportPath`, `DuplicateDecl`) are important. The comments about "使用者易犯错的点" prompt me to think about common mistakes developers make related to these features (e.g., incorrect number of initializers, invalid import paths, unused imports).

9. **Command-Line Arguments (If Applicable):** I scan for any explicit handling of command-line arguments. In this snippet, I don't see direct command-line argument parsing. However, the `check.conf` field (of type `Config`) suggests that the type checker's behavior *can* be influenced by configuration, which might originate from command-line flags (though this snippet doesn't show that part).

10. **Refining the Explanation:** Finally, I organize my findings into a clear and concise explanation, using Chinese as requested. I provide a high-level overview, then delve into specific functionalities with code examples, paying attention to error scenarios and potential pitfalls for users. I also explicitly state my assumptions when code interpretation involves inference.

This iterative process of scanning, identifying key components, inferring functionality, connecting to language features, and formulating examples allows me to understand and explain the purpose of the given Go code snippet effectively.
这段代码是 Go 语言 `go/types` 包中 `resolver.go` 文件的一部分，其主要功能是**解析 Go 源代码中的声明，并将声明的对象（如常量、类型、变量、函数、包等）与其在代码中的标识符关联起来，构建符号表，并进行初步的语义检查。**  更具体地说，它负责**名称解析**和**对象收集**的早期阶段。

以下是它的一些核心功能：

1. **维护声明信息 (`declInfo`)**:  `declInfo` 结构体用于存储关于包级别常量、类型、变量或函数声明的信息。这包括声明所在的文件作用域、Go 版本、左侧变量（对于多赋值）、类型表达式、初始化表达式、类型声明和函数声明的 AST 节点，以及初始化表达式的依赖关系。

2. **检查赋值语句的左右两侧数量是否匹配 (`arityMatch`)**:  此函数用于确保常量或变量声明的左侧名称数量与右侧初始化表达式的数量相符。如果数量不匹配，则会报告错误。

3. **验证导入路径 (`validatedImportPath`)**:  此函数用于验证导入语句中的路径字符串是否合法，包括检查是否包含非法字符。

4. **声明包级别对象 (`declarePkgObj`)**:  此函数将标识符与对应的包级别对象（常量、类型、变量）关联起来，并将其添加到包的作用域中。它还会进行一些基本的检查，例如不允许声明名为 `init` 或 `main` 的常量、类型或变量。

5. **导入包 (`importPackage`)**:  此函数负责导入其他 Go 包。它会查找或加载指定的包，并将其添加到当前包的导入列表中。它还处理导入错误，并在导入失败时创建“伪”包，以便继续进行类型检查。它还处理了 `import "C"` 的特殊情况（用于 Cgo）。

6. **收集对象 (`collectObjects`)**:  这是一个核心函数，它遍历所有源文件中的声明，并将它们对应的对象添加到文件和包的作用域中。
    * 它处理 `import` 声明，将导入的包添加到作用域中。
    * 它处理 `const` 声明，创建常量对象并记录其信息。
    * 它处理 `var` 声明，创建变量对象并记录其信息。
    * 它处理 `type` 声明，创建类型名对象并记录其信息。
    * 它处理 `func` 声明，创建函数对象并记录其信息。对于方法声明，它会收集方法信息，以便后续将其与接收者类型关联。
    * 它会检查同一作用域内是否存在重复声明。
    * 它会将收集到的方法与它们的接收者基础类型关联起来。

7. **解包接收者类型 (`unpackRecv`)**:  此函数用于解析方法声明中的接收者类型表达式，提取其指针信息、基础类型表达式以及类型参数（如果存在）。

8. **解析基础类型名称 (`resolveBaseTypeName`)**:  此函数用于查找给定类型名称的非别名基础类型名称。这在处理方法声明时用于确定方法是属于哪个类型。它会处理类型别名和指针类型。

9. **类型检查包对象 (`packageObjects`)**:  此函数负责对包级别的对象进行类型检查，但不包括函数体。它按照声明的顺序处理对象，并处理类型别名的情况。

10. **检查未使用的导入 (`unusedImports`)**:  此函数检查是否存在已导入但未在代码中使用的包，并报告相应的错误。

**推理其实现的 Go 语言功能:**

这段代码是 Go 语言编译器中类型检查器 (`Checker`) 的一部分，负责构建符号表和执行初步的语义分析。它直接参与了以下 Go 语言功能的实现：

* **包导入 (`import`)**:  `importPackage` 和 `unusedImports` 函数直接处理 `import` 语句，负责加载外部包和检查未使用的导入。
* **常量、变量、类型和函数的声明 (`const`, `var`, `type`, `func`)**:  `collectObjects` 函数和 `declInfo` 结构体负责处理这些声明，创建相应的对象并记录其信息。
* **方法 (`method`)**: `collectObjects`, `unpackRecv`, 和 `resolveBaseTypeName` 函数共同处理方法声明，包括解析接收者类型和将其与类型关联。
* **类型别名 (`type A = B`)**: `resolveBaseTypeName` 函数负责解析类型别名，找到其底层的实际类型。
* **初始化表达式**: `arityMatch` 函数检查初始化表达式的数量是否正确，`declInfo` 结构体存储了初始化表达式的信息。

**Go 代码示例:**

```go
package main

import (
	"fmt" // 演示包导入
)

// 演示常量声明
const version = "1.0.0"

// 演示类型声明
type MyInt int

// 演示变量声明
var count int
var name string = "example"

// 演示函数声明
func greet(msg string) {
	fmt.Println(msg)
}

// 演示方法声明
type MyStruct struct {
	Value int
}

func (m MyStruct) PrintValue() {
	fmt.Println(m.Value)
}

// 演示类型别名 (Go 1.9+)
type Integer = int

func main() {
	greet("Hello, world!")
	s := MyStruct{Value: 10}
	s.PrintValue()
	var i Integer = 5
	fmt.Println(i)
}
```

**假设的输入与输出 (针对 `arityMatch`):**

**假设输入:**

```go
package main

// 正确的赋值
var a, b int = 1, 2

// 错误的赋值，缺少初始化表达式
var c, d int = 3

// 错误的赋值，多余的初始化表达式
var e int = 4, 5
```

**预期输出 (类型检查器的错误信息):**

```
./main.go:6:13: missing init expr for d
./main.go:9:12: extra init expr 5
```

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。然而，`Checker` 结构体通常会在类型检查过程的早期阶段被初始化，而其配置 (`check.conf`) 可能会受到命令行参数的影响。例如，`go build` 或 `go vet` 等命令的参数可能会影响类型检查的行为，例如是否启用 Cgo (`check.conf.go115UsesCgo`) 或使用伪导入 C 包 (`check.conf.FakeImportC`)。 这些参数的解析和配置通常发生在调用类型检查器之前的阶段。

**使用者易犯错的点:**

1. **导入路径错误 (`BadImportPath`)**: 使用了无效的字符或格式错误的导入路径。

   ```go
   import "my-invalid/package!" // 错误：包含非法字符
   ```

2. **未使用的导入 (`UnusedImport`)**: 导入了包但没有在代码中使用其导出的标识符。

   ```go
   import "fmt" // 如果代码中没有使用 fmt.Println 等
   ```

3. **赋值语句左右两侧数量不匹配 (`WrongAssignCount`)**: 在变量或常量声明中，左右两侧的变量名和初始化表达式数量不一致。

   ```go
   var x, y int = 1 // 错误：缺少一个初始化表达式
   const a int = 1, 2 // 错误：多余的初始化表达式
   ```

4. **重复声明 (`DuplicateDecl`)**: 在同一作用域内声明了相同名称的变量、常量、类型或函数。

   ```go
   var count int
   var count string // 错误：重复声明
   ```

这段代码是 Go 语言类型检查器的核心组成部分，它在编译过程中扮演着至关重要的角色，确保代码的语义正确性。

### 提示词
```
这是路径为go/src/go/types/resolver.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	. "internal/types/errors"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// A declInfo describes a package-level const, type, var, or func declaration.
type declInfo struct {
	file      *Scope        // scope of file containing this declaration
	version   goVersion     // Go version of file containing this declaration
	lhs       []*Var        // lhs of n:1 variable declarations, or nil
	vtyp      ast.Expr      // type, or nil (for const and var declarations only)
	init      ast.Expr      // init/orig expression, or nil (for const and var declarations only)
	inherited bool          // if set, the init expression is inherited from a previous constant declaration
	tdecl     *ast.TypeSpec // type declaration, or nil
	fdecl     *ast.FuncDecl // func declaration, or nil

	// The deps field tracks initialization expression dependencies.
	deps map[Object]bool // lazily initialized
}

// hasInitializer reports whether the declared object has an initialization
// expression or function body.
func (d *declInfo) hasInitializer() bool {
	return d.init != nil || d.fdecl != nil && d.fdecl.Body != nil
}

// addDep adds obj to the set of objects d's init expression depends on.
func (d *declInfo) addDep(obj Object) {
	m := d.deps
	if m == nil {
		m = make(map[Object]bool)
		d.deps = m
	}
	m[obj] = true
}

// arityMatch checks that the lhs and rhs of a const or var decl
// have the appropriate number of names and init exprs. For const
// decls, init is the value spec providing the init exprs; for
// var decls, init is nil (the init exprs are in s in this case).
func (check *Checker) arityMatch(s, init *ast.ValueSpec) {
	l := len(s.Names)
	r := len(s.Values)
	if init != nil {
		r = len(init.Values)
	}

	const code = WrongAssignCount
	switch {
	case init == nil && r == 0:
		// var decl w/o init expr
		if s.Type == nil {
			check.error(s, code, "missing type or init expr")
		}
	case l < r:
		if l < len(s.Values) {
			// init exprs from s
			n := s.Values[l]
			check.errorf(n, code, "extra init expr %s", n)
			// TODO(gri) avoid declared and not used error here
		} else {
			// init exprs "inherited"
			check.errorf(s, code, "extra init expr at %s", check.fset.Position(init.Pos()))
			// TODO(gri) avoid declared and not used error here
		}
	case l > r && (init != nil || r != 1):
		n := s.Names[r]
		check.errorf(n, code, "missing init expr for %s", n)
	}
}

func validatedImportPath(path string) (string, error) {
	s, err := strconv.Unquote(path)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", fmt.Errorf("empty string")
	}
	const illegalChars = `!"#$%&'()*,:;<=>?[\]^{|}` + "`\uFFFD"
	for _, r := range s {
		if !unicode.IsGraphic(r) || unicode.IsSpace(r) || strings.ContainsRune(illegalChars, r) {
			return s, fmt.Errorf("invalid character %#U", r)
		}
	}
	return s, nil
}

// declarePkgObj declares obj in the package scope, records its ident -> obj mapping,
// and updates check.objMap. The object must not be a function or method.
func (check *Checker) declarePkgObj(ident *ast.Ident, obj Object, d *declInfo) {
	assert(ident.Name == obj.Name())

	// spec: "A package-scope or file-scope identifier with name init
	// may only be declared to be a function with this (func()) signature."
	if ident.Name == "init" {
		check.error(ident, InvalidInitDecl, "cannot declare init - must be func")
		return
	}

	// spec: "The main package must have package name main and declare
	// a function main that takes no arguments and returns no value."
	if ident.Name == "main" && check.pkg.name == "main" {
		check.error(ident, InvalidMainDecl, "cannot declare main - must be func")
		return
	}

	check.declare(check.pkg.scope, ident, obj, nopos)
	check.objMap[obj] = d
	obj.setOrder(uint32(len(check.objMap)))
}

// filename returns a filename suitable for debugging output.
func (check *Checker) filename(fileNo int) string {
	file := check.files[fileNo]
	if pos := file.Pos(); pos.IsValid() {
		return check.fset.File(pos).Name()
	}
	return fmt.Sprintf("file[%d]", fileNo)
}

func (check *Checker) importPackage(at positioner, path, dir string) *Package {
	// If we already have a package for the given (path, dir)
	// pair, use it instead of doing a full import.
	// Checker.impMap only caches packages that are marked Complete
	// or fake (dummy packages for failed imports). Incomplete but
	// non-fake packages do require an import to complete them.
	key := importKey{path, dir}
	imp := check.impMap[key]
	if imp != nil {
		return imp
	}

	// no package yet => import it
	if path == "C" && (check.conf.FakeImportC || check.conf.go115UsesCgo) {
		if check.conf.FakeImportC && check.conf.go115UsesCgo {
			check.error(at, BadImportPath, "cannot use FakeImportC and go115UsesCgo together")
		}
		imp = NewPackage("C", "C")
		imp.fake = true // package scope is not populated
		imp.cgo = check.conf.go115UsesCgo
	} else {
		// ordinary import
		var err error
		if importer := check.conf.Importer; importer == nil {
			err = fmt.Errorf("Config.Importer not installed")
		} else if importerFrom, ok := importer.(ImporterFrom); ok {
			imp, err = importerFrom.ImportFrom(path, dir, 0)
			if imp == nil && err == nil {
				err = fmt.Errorf("Config.Importer.ImportFrom(%s, %s, 0) returned nil but no error", path, dir)
			}
		} else {
			imp, err = importer.Import(path)
			if imp == nil && err == nil {
				err = fmt.Errorf("Config.Importer.Import(%s) returned nil but no error", path)
			}
		}
		// make sure we have a valid package name
		// (errors here can only happen through manipulation of packages after creation)
		if err == nil && imp != nil && (imp.name == "_" || imp.name == "") {
			err = fmt.Errorf("invalid package name: %q", imp.name)
			imp = nil // create fake package below
		}
		if err != nil {
			check.errorf(at, BrokenImport, "could not import %s (%s)", path, err)
			if imp == nil {
				// create a new fake package
				// come up with a sensible package name (heuristic)
				name := path
				if i := len(name); i > 0 && name[i-1] == '/' {
					name = name[:i-1]
				}
				if i := strings.LastIndex(name, "/"); i >= 0 {
					name = name[i+1:]
				}
				imp = NewPackage(path, name)
			}
			// continue to use the package as best as we can
			imp.fake = true // avoid follow-up lookup failures
		}
	}

	// package should be complete or marked fake, but be cautious
	if imp.complete || imp.fake {
		check.impMap[key] = imp
		// Once we've formatted an error message, keep the pkgPathMap
		// up-to-date on subsequent imports. It is used for package
		// qualification in error messages.
		if check.pkgPathMap != nil {
			check.markImports(imp)
		}
		return imp
	}

	// something went wrong (importer may have returned incomplete package without error)
	return nil
}

// collectObjects collects all file and package objects and inserts them
// into their respective scopes. It also performs imports and associates
// methods with receiver base type names.
func (check *Checker) collectObjects() {
	pkg := check.pkg

	// pkgImports is the set of packages already imported by any package file seen
	// so far. Used to avoid duplicate entries in pkg.imports. Allocate and populate
	// it (pkg.imports may not be empty if we are checking test files incrementally).
	// Note that pkgImports is keyed by package (and thus package path), not by an
	// importKey value. Two different importKey values may map to the same package
	// which is why we cannot use the check.impMap here.
	var pkgImports = make(map[*Package]bool)
	for _, imp := range pkg.imports {
		pkgImports[imp] = true
	}

	type methodInfo struct {
		obj  *Func      // method
		ptr  bool       // true if pointer receiver
		recv *ast.Ident // receiver type name
	}
	var methods []methodInfo // collected methods with valid receivers and non-blank _ names

	fileScopes := make([]*Scope, len(check.files)) // fileScopes[i] corresponds to check.files[i]
	for fileNo, file := range check.files {
		check.version = asGoVersion(check.versions[file])

		// The package identifier denotes the current package,
		// but there is no corresponding package object.
		check.recordDef(file.Name, nil)

		// Use the actual source file extent rather than *ast.File extent since the
		// latter doesn't include comments which appear at the start or end of the file.
		// Be conservative and use the *ast.File extent if we don't have a *token.File.
		pos, end := file.Pos(), file.End()
		if f := check.fset.File(file.Pos()); f != nil {
			pos, end = token.Pos(f.Base()), token.Pos(f.Base()+f.Size())
		}
		fileScope := NewScope(pkg.scope, pos, end, check.filename(fileNo))
		fileScopes[fileNo] = fileScope
		check.recordScope(file, fileScope)

		// determine file directory, necessary to resolve imports
		// FileName may be "" (typically for tests) in which case
		// we get "." as the directory which is what we would want.
		fileDir := dir(check.fset.Position(file.Name.Pos()).Filename)

		check.walkDecls(file.Decls, func(d decl) {
			switch d := d.(type) {
			case importDecl:
				// import package
				if d.spec.Path.Value == "" {
					return // error reported by parser
				}
				path, err := validatedImportPath(d.spec.Path.Value)
				if err != nil {
					check.errorf(d.spec.Path, BadImportPath, "invalid import path (%s)", err)
					return
				}

				imp := check.importPackage(d.spec.Path, path, fileDir)
				if imp == nil {
					return
				}

				// local name overrides imported package name
				name := imp.name
				if d.spec.Name != nil {
					name = d.spec.Name.Name
					if path == "C" {
						// match 1.17 cmd/compile (not prescribed by spec)
						check.error(d.spec.Name, ImportCRenamed, `cannot rename import "C"`)
						return
					}
				}

				if name == "init" {
					check.error(d.spec, InvalidInitDecl, "cannot import package as init - init must be a func")
					return
				}

				// add package to list of explicit imports
				// (this functionality is provided as a convenience
				// for clients; it is not needed for type-checking)
				if !pkgImports[imp] {
					pkgImports[imp] = true
					pkg.imports = append(pkg.imports, imp)
				}

				pkgName := NewPkgName(d.spec.Pos(), pkg, name, imp)
				if d.spec.Name != nil {
					// in a dot-import, the dot represents the package
					check.recordDef(d.spec.Name, pkgName)
				} else {
					check.recordImplicit(d.spec, pkgName)
				}

				if imp.fake {
					// match 1.17 cmd/compile (not prescribed by spec)
					pkgName.used = true
				}

				// add import to file scope
				check.imports = append(check.imports, pkgName)
				if name == "." {
					// dot-import
					if check.dotImportMap == nil {
						check.dotImportMap = make(map[dotImportKey]*PkgName)
					}
					// merge imported scope with file scope
					for name, obj := range imp.scope.elems {
						// Note: Avoid eager resolve(name, obj) here, so we only
						// resolve dot-imported objects as needed.

						// A package scope may contain non-exported objects,
						// do not import them!
						if token.IsExported(name) {
							// declare dot-imported object
							// (Do not use check.declare because it modifies the object
							// via Object.setScopePos, which leads to a race condition;
							// the object may be imported into more than one file scope
							// concurrently. See go.dev/issue/32154.)
							if alt := fileScope.Lookup(name); alt != nil {
								err := check.newError(DuplicateDecl)
								err.addf(d.spec.Name, "%s redeclared in this block", alt.Name())
								err.addAltDecl(alt)
								err.report()
							} else {
								fileScope.insert(name, obj)
								check.dotImportMap[dotImportKey{fileScope, name}] = pkgName
							}
						}
					}
				} else {
					// declare imported package object in file scope
					// (no need to provide s.Name since we called check.recordDef earlier)
					check.declare(fileScope, nil, pkgName, nopos)
				}
			case constDecl:
				// declare all constants
				for i, name := range d.spec.Names {
					obj := NewConst(name.Pos(), pkg, name.Name, nil, constant.MakeInt64(int64(d.iota)))

					var init ast.Expr
					if i < len(d.init) {
						init = d.init[i]
					}

					d := &declInfo{file: fileScope, version: check.version, vtyp: d.typ, init: init, inherited: d.inherited}
					check.declarePkgObj(name, obj, d)
				}

			case varDecl:
				lhs := make([]*Var, len(d.spec.Names))
				// If there's exactly one rhs initializer, use
				// the same declInfo d1 for all lhs variables
				// so that each lhs variable depends on the same
				// rhs initializer (n:1 var declaration).
				var d1 *declInfo
				if len(d.spec.Values) == 1 {
					// The lhs elements are only set up after the for loop below,
					// but that's ok because declareVar only collects the declInfo
					// for a later phase.
					d1 = &declInfo{file: fileScope, version: check.version, lhs: lhs, vtyp: d.spec.Type, init: d.spec.Values[0]}
				}

				// declare all variables
				for i, name := range d.spec.Names {
					obj := NewVar(name.Pos(), pkg, name.Name, nil)
					lhs[i] = obj

					di := d1
					if di == nil {
						// individual assignments
						var init ast.Expr
						if i < len(d.spec.Values) {
							init = d.spec.Values[i]
						}
						di = &declInfo{file: fileScope, version: check.version, vtyp: d.spec.Type, init: init}
					}

					check.declarePkgObj(name, obj, di)
				}
			case typeDecl:
				obj := NewTypeName(d.spec.Name.Pos(), pkg, d.spec.Name.Name, nil)
				check.declarePkgObj(d.spec.Name, obj, &declInfo{file: fileScope, version: check.version, tdecl: d.spec})
			case funcDecl:
				name := d.decl.Name.Name
				obj := NewFunc(d.decl.Name.Pos(), pkg, name, nil) // signature set later
				hasTParamError := false                           // avoid duplicate type parameter errors
				if d.decl.Recv.NumFields() == 0 {
					// regular function
					if d.decl.Recv != nil {
						check.error(d.decl.Recv, BadRecv, "method has no receiver")
						// treat as function
					}
					if name == "init" || (name == "main" && check.pkg.name == "main") {
						code := InvalidInitDecl
						if name == "main" {
							code = InvalidMainDecl
						}
						if d.decl.Type.TypeParams.NumFields() != 0 {
							check.softErrorf(d.decl.Type.TypeParams.List[0], code, "func %s must have no type parameters", name)
							hasTParamError = true
						}
						if t := d.decl.Type; t.Params.NumFields() != 0 || t.Results != nil {
							// TODO(rFindley) Should this be a hard error?
							check.softErrorf(d.decl.Name, code, "func %s must have no arguments and no return values", name)
						}
					}
					if name == "init" {
						// don't declare init functions in the package scope - they are invisible
						obj.parent = pkg.scope
						check.recordDef(d.decl.Name, obj)
						// init functions must have a body
						if d.decl.Body == nil {
							// TODO(gri) make this error message consistent with the others above
							check.softErrorf(obj, MissingInitBody, "missing function body")
						}
					} else {
						check.declare(pkg.scope, d.decl.Name, obj, nopos)
					}
				} else {
					// method

					// TODO(rFindley) earlier versions of this code checked that methods
					//                have no type parameters, but this is checked later
					//                when type checking the function type. Confirm that
					//                we don't need to check tparams here.

					ptr, base, _ := check.unpackRecv(d.decl.Recv.List[0].Type, false)
					// (Methods with invalid receiver cannot be associated to a type, and
					// methods with blank _ names are never found; no need to collect any
					// of them. They will still be type-checked with all the other functions.)
					if recv, _ := base.(*ast.Ident); recv != nil && name != "_" {
						methods = append(methods, methodInfo{obj, ptr, recv})
					}
					check.recordDef(d.decl.Name, obj)
				}
				_ = d.decl.Type.TypeParams.NumFields() != 0 && !hasTParamError && check.verifyVersionf(d.decl.Type.TypeParams.List[0], go1_18, "type parameter")
				info := &declInfo{file: fileScope, version: check.version, fdecl: d.decl}
				// Methods are not package-level objects but we still track them in the
				// object map so that we can handle them like regular functions (if the
				// receiver is invalid); also we need their fdecl info when associating
				// them with their receiver base type, below.
				check.objMap[obj] = info
				obj.setOrder(uint32(len(check.objMap)))
			}
		})
	}

	// verify that objects in package and file scopes have different names
	for _, scope := range fileScopes {
		for name, obj := range scope.elems {
			if alt := pkg.scope.Lookup(name); alt != nil {
				obj = resolve(name, obj)
				err := check.newError(DuplicateDecl)
				if pkg, ok := obj.(*PkgName); ok {
					err.addf(alt, "%s already declared through import of %s", alt.Name(), pkg.Imported())
					err.addAltDecl(pkg)
				} else {
					err.addf(alt, "%s already declared through dot-import of %s", alt.Name(), obj.Pkg())
					// TODO(gri) dot-imported objects don't have a position; addAltDecl won't print anything
					err.addAltDecl(obj)
				}
				err.report()
			}
		}
	}

	// Now that we have all package scope objects and all methods,
	// associate methods with receiver base type name where possible.
	// Ignore methods that have an invalid receiver. They will be
	// type-checked later, with regular functions.
	if methods == nil {
		return
	}

	check.methods = make(map[*TypeName][]*Func)
	for i := range methods {
		m := &methods[i]
		// Determine the receiver base type and associate m with it.
		ptr, base := check.resolveBaseTypeName(m.ptr, m.recv)
		if base != nil {
			m.obj.hasPtrRecv_ = ptr
			check.methods[base] = append(check.methods[base], m.obj)
		}
	}
}

// unpackRecv unpacks a receiver type expression and returns its components: ptr indicates
// whether rtyp is a pointer receiver, base is the receiver base type expression stripped
// of its type parameters (if any), and tparams are its type parameter names, if any. The
// type parameters are only unpacked if unpackParams is set. For instance, given the rtyp
//
//	*T[A, _]
//
// ptr is true, base is T, and tparams is [A, _] (assuming unpackParams is set).
// Note that base may not be a *ast.Ident for erroneous programs.
func (check *Checker) unpackRecv(rtyp ast.Expr, unpackParams bool) (ptr bool, base ast.Expr, tparams []*ast.Ident) {
	// unpack receiver type
	base = ast.Unparen(rtyp)
	if t, _ := base.(*ast.StarExpr); t != nil {
		ptr = true
		base = ast.Unparen(t.X)
	}

	// unpack type parameters, if any
	switch base.(type) {
	case *ast.IndexExpr, *ast.IndexListExpr:
		ix := unpackIndexedExpr(base)
		base = ix.x
		if unpackParams {
			for _, arg := range ix.indices {
				var par *ast.Ident
				switch arg := arg.(type) {
				case *ast.Ident:
					par = arg
				case *ast.BadExpr:
					// ignore - error already reported by parser
				case nil:
					check.error(ix.orig, InvalidSyntaxTree, "parameterized receiver contains nil parameters")
				default:
					check.errorf(arg, BadDecl, "receiver type parameter %s must be an identifier", arg)
				}
				if par == nil {
					par = &ast.Ident{NamePos: arg.Pos(), Name: "_"}
				}
				tparams = append(tparams, par)
			}
		}
	}

	return
}

// resolveBaseTypeName returns the non-alias base type name for the given name, and whether
// there was a pointer indirection to get to it. The base type name must be declared
// in package scope, and there can be at most one pointer indirection. Traversals
// through generic alias types are not permitted. If no such type name exists, the
// returned base is nil.
func (check *Checker) resolveBaseTypeName(ptr bool, name *ast.Ident) (ptr_ bool, base *TypeName) {
	// Algorithm: Starting from name, which is expected to denote a type,
	// we follow that type through non-generic alias declarations until
	// we reach a non-alias type name.
	var seen map[*TypeName]bool
	for name != nil {
		// name must denote an object found in the current package scope
		// (note that dot-imported objects are not in the package scope!)
		obj := check.pkg.scope.Lookup(name.Name)
		if obj == nil {
			break
		}

		// the object must be a type name...
		tname, _ := obj.(*TypeName)
		if tname == nil {
			break
		}

		// ... which we have not seen before
		if seen[tname] {
			break
		}

		// we're done if tdecl describes a defined type (not an alias)
		tdecl := check.objMap[tname].tdecl // must exist for objects in package scope
		if !tdecl.Assign.IsValid() {
			return ptr, tname
		}

		// an alias must not be generic
		// (importantly, we must not collect such methods - was https://go.dev/issue/70417)
		if tdecl.TypeParams != nil {
			break
		}

		// otherwise, remember this type name and continue resolving
		if seen == nil {
			seen = make(map[*TypeName]bool)
		}
		seen[tname] = true

		// The go/parser keeps parentheses; strip them, if any.
		typ := ast.Unparen(tdecl.Type)

		// dereference a pointer type
		if pexpr, _ := typ.(*ast.StarExpr); pexpr != nil {
			// if we've already seen a pointer, we're done
			if ptr {
				break
			}
			ptr = true
			typ = ast.Unparen(pexpr.X) // continue with pointer base type
		}

		// After dereferencing, typ must be a locally defined type name.
		// Referring to other packages (qualified identifiers) or going
		// through instantiated types (index expressions) is not permitted,
		// so we can ignore those.
		name, _ = typ.(*ast.Ident)
		if name == nil {
			break
		}
	}

	// no base type found
	return false, nil
}

// packageObjects typechecks all package objects, but not function bodies.
func (check *Checker) packageObjects() {
	// process package objects in source order for reproducible results
	objList := make([]Object, len(check.objMap))
	i := 0
	for obj := range check.objMap {
		objList[i] = obj
		i++
	}
	slices.SortFunc(objList, func(a, b Object) int {
		return cmp.Compare(a.order(), b.order())
	})

	// add new methods to already type-checked types (from a prior Checker.Files call)
	for _, obj := range objList {
		if obj, _ := obj.(*TypeName); obj != nil && obj.typ != nil {
			check.collectMethods(obj)
		}
	}

	if false && check.conf._EnableAlias {
		// With Alias nodes we can process declarations in any order.
		//
		// TODO(adonovan): unfortunately, Alias nodes
		// (GODEBUG=gotypesalias=1) don't entirely resolve
		// problems with cycles. For example, in
		// GOROOT/test/typeparam/issue50259.go,
		//
		// 	type T[_ any] struct{}
		// 	type A T[B]
		// 	type B = T[A]
		//
		// TypeName A has Type Named during checking, but by
		// the time the unified export data is written out,
		// its Type is Invalid.
		//
		// Investigate and reenable this branch.
		for _, obj := range objList {
			check.objDecl(obj, nil)
		}
	} else {
		// Without Alias nodes, we process non-alias type declarations first, followed by
		// alias declarations, and then everything else. This appears to avoid most situations
		// where the type of an alias is needed before it is available.
		// There may still be cases where this is not good enough (see also go.dev/issue/25838).
		// In those cases Checker.ident will report an error ("invalid use of type alias").
		var aliasList []*TypeName
		var othersList []Object // everything that's not a type
		// phase 1: non-alias type declarations
		for _, obj := range objList {
			if tname, _ := obj.(*TypeName); tname != nil {
				if check.objMap[tname].tdecl.Assign.IsValid() {
					aliasList = append(aliasList, tname)
				} else {
					check.objDecl(obj, nil)
				}
			} else {
				othersList = append(othersList, obj)
			}
		}
		// phase 2: alias type declarations
		for _, obj := range aliasList {
			check.objDecl(obj, nil)
		}
		// phase 3: all other declarations
		for _, obj := range othersList {
			check.objDecl(obj, nil)
		}
	}

	// At this point we may have a non-empty check.methods map; this means that not all
	// entries were deleted at the end of typeDecl because the respective receiver base
	// types were not found. In that case, an error was reported when declaring those
	// methods. We can now safely discard this map.
	check.methods = nil
}

// unusedImports checks for unused imports.
func (check *Checker) unusedImports() {
	// If function bodies are not checked, packages' uses are likely missing - don't check.
	if check.conf.IgnoreFuncBodies {
		return
	}

	// spec: "It is illegal (...) to directly import a package without referring to
	// any of its exported identifiers. To import a package solely for its side-effects
	// (initialization), use the blank identifier as explicit package name."

	for _, obj := range check.imports {
		if !obj.used && obj.name != "_" {
			check.errorUnusedPkg(obj)
		}
	}
}

func (check *Checker) errorUnusedPkg(obj *PkgName) {
	// If the package was imported with a name other than the final
	// import path element, show it explicitly in the error message.
	// Note that this handles both renamed imports and imports of
	// packages containing unconventional package declarations.
	// Note that this uses / always, even on Windows, because Go import
	// paths always use forward slashes.
	path := obj.imported.path
	elem := path
	if i := strings.LastIndex(elem, "/"); i >= 0 {
		elem = elem[i+1:]
	}
	if obj.name == "" || obj.name == "." || obj.name == elem {
		check.softErrorf(obj, UnusedImport, "%q imported and not used", path)
	} else {
		check.softErrorf(obj, UnusedImport, "%q imported as %s and not used", path, obj.name)
	}
}

// dir makes a good-faith attempt to return the directory
// portion of path. If path is empty, the result is ".".
// (Per the go/build package dependency tests, we cannot import
// path/filepath and simply use filepath.Dir.)
func dir(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i > 0 {
		return path[:i]
	}
	// i <= 0
	return "."
}
```