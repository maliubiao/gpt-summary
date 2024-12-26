Response: My goal is to analyze the provided Go code snippet from `go/src/cmd/compile/internal/types2/resolver.go` and explain its functionality. Here's my thinking process:

1. **Identify the Core Purpose:** The file name "resolver.go" strongly suggests this code is responsible for resolving names and declarations within Go code. The package name `types2` hints that this is related to type checking and analysis.

2. **Scan for Key Data Structures:** I look for prominent structs and types that seem central to the resolution process. `declInfo` stands out immediately. Its fields (`file`, `version`, `lhs`, `vtyp`, `init`, `inherited`, `tdecl`, `fdecl`, `deps`) clearly hold information about declarations (constants, types, variables, functions).

3. **Analyze `declInfo` Methods:** The methods associated with `declInfo` (`hasInitializer`, `addDep`) provide further clues. `hasInitializer` suggests tracking whether a declaration has an initial value or function body. `addDep` indicates the resolver is tracking dependencies between declarations, likely for initialization order or cycle detection.

4. **Examine `Checker` Methods:** The `Checker` struct is the central type checker. I scan its methods present in the snippet, focusing on those interacting with `declInfo` or handling declarations directly. Key methods I identify are:
    * `arity`: Checks if the number of names on the left-hand side matches the number of initialization values on the right-hand side of a declaration.
    * `validatedImportPath`:  Validates import paths.
    * `declarePkgObj`: Declares an object in the package scope.
    * `importPackage`:  Handles importing external packages.
    * `collectObjects`:  A crucial method that iterates through declarations, populates scopes, handles imports, and associates methods with types.
    * `unpackRecv`:  Parses the receiver type of a method.
    * `resolveBaseTypeName`: Resolves a type name to its underlying non-alias base type.
    * `packageObjects`:  Type-checks package-level objects.
    * `unusedImports`: Checks for unused imports.

5. **Infer Functionality from Method Names and Logic:**
    * `arity`: Directly related to assignment count validation.
    * `validatedImportPath`:  Implements the rules for valid import paths.
    * `declarePkgObj`:  Handles the core action of making a declared object available within its scope.
    * `importPackage`:  Implements the `import` statement's logic, including handling "C" and caching imported packages.
    * `collectObjects`:  This seems to be the main entry point for collecting and organizing information about declarations. It ties together scope creation, import processing, and method association. The loop iterating over `file.DeclList` is a strong indicator of this.
    * `unpackRecv`:  Specifically for parsing method receivers, handling pointers and type parameters.
    * `resolveBaseTypeName`:  Essential for resolving type aliases and finding the underlying type for method association.
    * `packageObjects`:  The stage where actual type checking of package-level entities occurs. The different phases suggest an attempt to handle type dependencies and aliases correctly.
    * `unusedImports`:  Implements the Go rule about unused imports.

6. **Look for Specific Go Language Features:** Based on the identified functionalities, I can connect them to specific Go language features:
    * **Constants, Variables, Functions, Types:** `declInfo` and the handling of `ConstDecl`, `VarDecl`, `FuncDecl`, and `TypeDecl` in `collectObjects` directly relate to these core Go declaration types.
    * **Imports:** `importPackage` and the processing of `ImportDecl` handle the `import` statement.
    * **Packages:** The creation of `Package` objects and the management of scopes (package and file scopes) are fundamental to Go's package system.
    * **Methods:** `unpackRecv`, `resolveBaseTypeName`, and the association of methods in `collectObjects` are key to how Go handles methods on types.
    * **Type Aliases:**  The `resolveBaseTypeName` function and the phased processing in `packageObjects` indicate handling of type aliases.
    * **`init` and `main` functions:** The specific checks for these functions in `declarePkgObj` and `collectObjects` show how these special functions are handled.

7. **Construct Examples:**  For the identified features, I construct simple Go code examples to illustrate the resolver's role. I focus on scenarios where the resolver's actions are evident (e.g., checking assignment counts, handling imports, associating methods).

8. **Consider Potential Errors:**  I think about common mistakes developers might make related to the functionalities handled by this code. Unused imports are explicitly checked. Incorrect assignment counts are handled by `arity`. Invalid import paths are validated.

9. **Refine and Organize:**  I organize my findings into a structured answer, covering the core functionalities, related Go features, code examples, and potential errors. I ensure the language is clear and concise.

By following these steps, I can systematically analyze the code snippet and arrive at a comprehensive understanding of its role in the Go type-checking process. The key is to start with the obvious (file name, package name), delve into the data structures and methods, infer functionality, and then connect those functionalities back to specific Go language features.
这段代码是 Go 语言编译器 `types2` 包中的 `resolver.go` 文件的一部分，它主要负责 **解析 Go 源代码中的声明和引用，并将它们与类型信息关联起来**。  简单来说，它构建了符号表，这是类型检查的基础。

以下是它的一些主要功能：

1. **处理各种声明:**
   - **常量 (const):**  识别常量声明，提取常量名、类型和初始值，并将其添加到作用域中。它还处理 `iota`。
   - **类型 (type):**  识别类型声明，提取类型名和类型定义，并将其添加到作用域中。
   - **变量 (var):**  识别变量声明，提取变量名、类型和初始值，并将其添加到作用域中。它还处理多变量声明。
   - **函数 (func):** 识别函数声明（包括普通函数和方法），提取函数名、参数、返回值和函数体。方法会关联到它们的接收者类型。
   - **导入 (import):** 处理 `import` 语句，解析导入路径，查找并加载外部包。它还处理别名导入和 `.` 导入。

2. **管理作用域 (Scope):**  为包和文件创建和管理作用域。作用域用于存储在特定代码块中声明的标识符（例如变量名、类型名）。

3. **解析标识符 (Identifier Resolution):**  将代码中使用的标识符（例如变量名、函数名）与其声明关联起来。这包括在当前作用域和导入的包中查找标识符。

4. **处理 `init` 函数:**  识别并特殊处理 `init` 函数，确保它们是无参数无返回值的函数，并且不能被显式声明在包级别之外。

5. **处理 `main` 函数:**  识别并特殊处理 `main` 包中的 `main` 函数，确保它是无参数无返回值的函数。

6. **处理方法 (Methods):**  解析方法的接收者类型，并将方法关联到相应的类型。这包括处理指针接收者。

7. **检查声明的合法性:**
   - 检查常量和变量声明中左右两边赋值的数量是否匹配。
   - 检查导入路径是否合法。
   - 检查 `init` 和 `main` 函数的声明是否符合规范。
   - 检查重复声明。

8. **跟踪依赖关系:**  对于常量和变量声明，`declInfo` 结构体中的 `deps` 字段用于跟踪初始化表达式依赖的其他对象，这对于后续的初始化顺序分析很重要。

9. **处理导入包:** 加载和缓存导入的包，避免重复加载。它还处理 `import "C"` 的特殊情况（用于 Cgo）。

10. **检查未使用的导入:**  在类型检查的后期阶段，检查是否有导入的包没有被使用。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言编译器进行 **类型检查** 的一部分，特别是在 **符号解析** 阶段起着关键作用。 它是理解 Go 语言中标识符的含义以及它们如何与类型系统关联的核心组件。

**Go 代码示例说明:**

假设有以下 Go 代码：

```go
package main

import "fmt"

const message = "Hello"
var count int = 10

type MyString string

func greet(name string) string {
	return fmt.Sprintf("%s, %s!", message, name)
}

func main() {
	fmt.Println(greet("World"))
}
```

`resolver.go` 的功能会包括：

- **`import "fmt"`:**  `importPackage` 函数会被调用，解析 "fmt" 路径，并加载 `fmt` 包。`PkgName` 对象会被创建并添加到当前包的作用域中。
- **`const message = "Hello"`:**  `collectObjects` 函数会识别常量声明，创建一个 `Const` 对象，类型为 `string`，值为 "Hello"，并将其添加到包的作用域中。 `declInfo` 会记录相关信息。
- **`var count int = 10`:** `collectObjects` 函数会识别变量声明，创建一个 `Var` 对象，类型为 `int`，初始值为 10，并添加到包的作用域中。 `declInfo` 会记录相关信息。
- **`type MyString string`:** `collectObjects` 函数会识别类型声明，创建一个 `TypeName` 对象，表示 `MyString` 类型是 `string` 的别名，并添加到包的作用域中。
- **`func greet(name string) string`:** `collectObjects` 函数会识别函数声明，创建一个 `Func` 对象，参数为 `name string`，返回值类型为 `string`，并添加到包的作用域中。
- **`func main() { ... }`:** `collectObjects` 函数会识别 `main` 函数声明，并进行特殊处理，确保其签名正确。

**代码推理 (带假设的输入与输出):**

假设 `collectObjects` 函数处理以下代码片段：

```go
const (
	a = 10
	b // 假设 b 继承了 a 的初始化表达式
	c = 20
)
```

**假设的输入:**  一个 `syntax.File` 结构体，其 `DeclList` 包含上述常量声明的 `syntax.ConstDecl` 节点。

**推理过程:**

1. `collectObjects` 遍历 `DeclList`。
2. 对于 `a = 10`，创建一个 `Const` 对象，类型为未知的常量类型（后续推断），值为常量 10。`declInfo` 记录 `init: 10` 和 `inherited: false`。
3. 对于 `b`，由于没有显式的初始化表达式，并且处于同一个 `const` 块中，`collectObjects` 会判断它继承了前一个常量 `a` 的初始化表达式。 创建一个 `Const` 对象，`declInfo` 记录 `init: 10`（继承的）和 `inherited: true`。
4. 对于 `c = 20`，创建一个 `Const` 对象，类型为未知的常量类型，值为常量 20。`declInfo` 记录 `init: 20` 和 `inherited: false`。

**假设的输出:**  在包的作用域中创建了三个 `Const` 对象，分别对应 `a`、`b` 和 `c`，并且它们的 `declInfo` 结构体中的 `init` 和 `inherited` 字段被正确设置。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `cmd/compile/internal/gc` 包或其他更上层的编译器组件中。  `types2` 包作为一个类型检查器，主要关注源代码的结构和语义。

然而，`Checker` 结构体中的 `Config` 字段会包含一些配置信息，这些信息可能来源于命令行参数的解析。例如：

- `check.conf.FakeImportC`:  这个配置项可能通过命令行参数控制是否允许模拟导入 "C" 包，用于非 Cgo 构建。
- `check.conf.go115UsesCgo`:  这个配置项可能通过命令行参数控制 Go 版本相关的 Cgo 处理逻辑。
- `check.conf.Importer`:  这是一个 `go/importer` 接口的实现，负责查找和加载包。具体的 `Importer` 实现可能根据命令行参数（例如 `-p` 指定的包搜索路径）进行初始化。

**使用者易犯错的点 (示例):**

1. **在 `init` 函数中声明变量或常量:**  Go 语言规范不允许在包级别的 `init` 函数中声明变量或常量。  `declarePkgObj` 函数会捕获这种错误：

   ```go
   package main

   func init() {
       var x int = 5 // 错误：不能在 init 函数中声明包级别变量
   }
   ```

   `resolver.go` 会在处理到 `var x int = 5` 时，由于 `ident.Value == "init"`，调用 `check.error` 报告 `InvalidInitDecl` 错误。

2. **在 `main` 包中声明名为 `main` 的非函数对象:** `declarePkgObj` 会检查 `main` 包中是否声明了非函数的 `main` 标识符：

   ```go
   package main

   var main int // 错误：main 包中不能声明名为 main 的非函数对象
   ```

   `resolver.go` 会在处理到 `var main int` 时，由于 `ident.Value == "main"` 并且 `check.pkg.name == "main"`，调用 `check.error` 报告 `InvalidMainDecl` 错误。

3. **导入的包名与本地别名冲突:** 如果导入的包名与当前文件中声明的顶级对象名称冲突，会导致编译错误。`collectObjects` 在遍历文件作用域时会检查是否存在这种情况：

   ```go
   package main

   import "fmt"

   var fmt int // 错误：fmt 与导入的包名冲突

   func main() {
       fmt.Println("Hello")
   }
   ```

   `resolver.go` 会在 `collectObjects` 中，当处理 `var fmt int` 时，发现文件作用域中已经存在一个名为 `fmt` 的 `PkgName` 对象（来自 `import "fmt"`），从而报告 `DuplicateDecl` 错误。

总而言之，`resolver.go` 是 Go 语言类型检查器中至关重要的一个环节，它负责理解代码的结构，将标识符与其声明关联，并执行一些基本的语义检查，为后续的类型推断和类型一致性检查奠定基础。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/types2/resolver.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types2

import (
	"cmd/compile/internal/syntax"
	"cmp"
	"fmt"
	"go/constant"
	. "internal/types/errors"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// A declInfo describes a package-level const, type, var, or func declaration.
type declInfo struct {
	file      *Scope           // scope of file containing this declaration
	version   goVersion        // Go version of file containing this declaration
	lhs       []*Var           // lhs of n:1 variable declarations, or nil
	vtyp      syntax.Expr      // type, or nil (for const and var declarations only)
	init      syntax.Expr      // init/orig expression, or nil (for const and var declarations only)
	inherited bool             // if set, the init expression is inherited from a previous constant declaration
	tdecl     *syntax.TypeDecl // type declaration, or nil
	fdecl     *syntax.FuncDecl // func declaration, or nil

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

// arity checks that the lhs and rhs of a const or var decl
// have a matching number of names and initialization values.
// If inherited is set, the initialization values are from
// another (constant) declaration.
func (check *Checker) arity(pos syntax.Pos, names []*syntax.Name, inits []syntax.Expr, constDecl, inherited bool) {
	l := len(names)
	r := len(inits)

	const code = WrongAssignCount
	switch {
	case l < r:
		n := inits[l]
		if inherited {
			check.errorf(pos, code, "extra init expr at %s", n.Pos())
		} else {
			check.errorf(n, code, "extra init expr %s", n)
		}
	case l > r && (constDecl || r != 1): // if r == 1 it may be a multi-valued function and we can't say anything yet
		n := names[r]
		check.errorf(n, code, "missing init expr for %s", n.Value)
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
func (check *Checker) declarePkgObj(ident *syntax.Name, obj Object, d *declInfo) {
	assert(ident.Value == obj.Name())

	// spec: "A package-scope or file-scope identifier with name init
	// may only be declared to be a function with this (func()) signature."
	if ident.Value == "init" {
		check.error(ident, InvalidInitDecl, "cannot declare init - must be func")
		return
	}

	// spec: "The main package must have package name main and declare
	// a function main that takes no arguments and returns no value."
	if ident.Value == "main" && check.pkg.name == "main" {
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
	if pos := file.Pos(); pos.IsKnown() {
		// return check.fset.File(pos).Name()
		// TODO(gri) do we need the actual file name here?
		return pos.RelFilename()
	}
	return fmt.Sprintf("file[%d]", fileNo)
}

func (check *Checker) importPackage(pos syntax.Pos, path, dir string) *Package {
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
			check.error(pos, BadImportPath, "cannot use FakeImportC and go115UsesCgo together")
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
			check.errorf(pos, BrokenImport, "could not import %s (%s)", path, err)
			if imp == nil {
				// create a new fake package
				// come up with a sensible package name (heuristic)
				name := strings.TrimSuffix(path, "/")
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
		obj  *Func        // method
		ptr  bool         // true if pointer receiver
		recv *syntax.Name // receiver type name
	}
	var methods []methodInfo // collected methods with valid receivers and non-blank _ names

	fileScopes := make([]*Scope, len(check.files)) // fileScopes[i] corresponds to check.files[i]
	for fileNo, file := range check.files {
		check.version = asGoVersion(check.versions[file.Pos().FileBase()])

		// The package identifier denotes the current package,
		// but there is no corresponding package object.
		check.recordDef(file.PkgName, nil)

		fileScope := NewScope(pkg.scope, syntax.StartPos(file), syntax.EndPos(file), check.filename(fileNo))
		fileScopes[fileNo] = fileScope
		check.recordScope(file, fileScope)

		// determine file directory, necessary to resolve imports
		// FileName may be "" (typically for tests) in which case
		// we get "." as the directory which is what we would want.
		fileDir := dir(file.PkgName.Pos().RelFilename()) // TODO(gri) should this be filename?

		first := -1                // index of first ConstDecl in the current group, or -1
		var last *syntax.ConstDecl // last ConstDecl with init expressions, or nil
		for index, decl := range file.DeclList {
			if _, ok := decl.(*syntax.ConstDecl); !ok {
				first = -1 // we're not in a constant declaration
			}

			switch s := decl.(type) {
			case *syntax.ImportDecl:
				// import package
				if s.Path == nil || s.Path.Bad {
					continue // error reported during parsing
				}
				path, err := validatedImportPath(s.Path.Value)
				if err != nil {
					check.errorf(s.Path, BadImportPath, "invalid import path (%s)", err)
					continue
				}

				imp := check.importPackage(s.Path.Pos(), path, fileDir)
				if imp == nil {
					continue
				}

				// local name overrides imported package name
				name := imp.name
				if s.LocalPkgName != nil {
					name = s.LocalPkgName.Value
					if path == "C" {
						// match 1.17 cmd/compile (not prescribed by spec)
						check.error(s.LocalPkgName, ImportCRenamed, `cannot rename import "C"`)
						continue
					}
				}

				if name == "init" {
					check.error(s, InvalidInitDecl, "cannot import package as init - init must be a func")
					continue
				}

				// add package to list of explicit imports
				// (this functionality is provided as a convenience
				// for clients; it is not needed for type-checking)
				if !pkgImports[imp] {
					pkgImports[imp] = true
					pkg.imports = append(pkg.imports, imp)
				}

				pkgName := NewPkgName(s.Pos(), pkg, name, imp)
				if s.LocalPkgName != nil {
					// in a dot-import, the dot represents the package
					check.recordDef(s.LocalPkgName, pkgName)
				} else {
					check.recordImplicit(s, pkgName)
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
						if isExported(name) {
							// declare dot-imported object
							// (Do not use check.declare because it modifies the object
							// via Object.setScopePos, which leads to a race condition;
							// the object may be imported into more than one file scope
							// concurrently. See go.dev/issue/32154.)
							if alt := fileScope.Lookup(name); alt != nil {
								err := check.newError(DuplicateDecl)
								err.addf(s.LocalPkgName, "%s redeclared in this block", alt.Name())
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
					// (no need to provide s.LocalPkgName since we called check.recordDef earlier)
					check.declare(fileScope, nil, pkgName, nopos)
				}

			case *syntax.ConstDecl:
				// iota is the index of the current constDecl within the group
				if first < 0 || s.Group == nil || file.DeclList[index-1].(*syntax.ConstDecl).Group != s.Group {
					first = index
					last = nil
				}
				iota := constant.MakeInt64(int64(index - first))

				// determine which initialization expressions to use
				inherited := true
				switch {
				case s.Type != nil || s.Values != nil:
					last = s
					inherited = false
				case last == nil:
					last = new(syntax.ConstDecl) // make sure last exists
					inherited = false
				}

				// declare all constants
				values := syntax.UnpackListExpr(last.Values)
				for i, name := range s.NameList {
					obj := NewConst(name.Pos(), pkg, name.Value, nil, iota)

					var init syntax.Expr
					if i < len(values) {
						init = values[i]
					}

					d := &declInfo{file: fileScope, version: check.version, vtyp: last.Type, init: init, inherited: inherited}
					check.declarePkgObj(name, obj, d)
				}

				// Constants must always have init values.
				check.arity(s.Pos(), s.NameList, values, true, inherited)

			case *syntax.VarDecl:
				lhs := make([]*Var, len(s.NameList))
				// If there's exactly one rhs initializer, use
				// the same declInfo d1 for all lhs variables
				// so that each lhs variable depends on the same
				// rhs initializer (n:1 var declaration).
				var d1 *declInfo
				if _, ok := s.Values.(*syntax.ListExpr); !ok {
					// The lhs elements are only set up after the for loop below,
					// but that's ok because declarePkgObj only collects the declInfo
					// for a later phase.
					d1 = &declInfo{file: fileScope, version: check.version, lhs: lhs, vtyp: s.Type, init: s.Values}
				}

				// declare all variables
				values := syntax.UnpackListExpr(s.Values)
				for i, name := range s.NameList {
					obj := NewVar(name.Pos(), pkg, name.Value, nil)
					lhs[i] = obj

					d := d1
					if d == nil {
						// individual assignments
						var init syntax.Expr
						if i < len(values) {
							init = values[i]
						}
						d = &declInfo{file: fileScope, version: check.version, vtyp: s.Type, init: init}
					}

					check.declarePkgObj(name, obj, d)
				}

				// If we have no type, we must have values.
				if s.Type == nil || values != nil {
					check.arity(s.Pos(), s.NameList, values, false, false)
				}

			case *syntax.TypeDecl:
				obj := NewTypeName(s.Name.Pos(), pkg, s.Name.Value, nil)
				check.declarePkgObj(s.Name, obj, &declInfo{file: fileScope, version: check.version, tdecl: s})

			case *syntax.FuncDecl:
				name := s.Name.Value
				obj := NewFunc(s.Name.Pos(), pkg, name, nil)
				hasTParamError := false // avoid duplicate type parameter errors
				if s.Recv == nil {
					// regular function
					if name == "init" || name == "main" && pkg.name == "main" {
						code := InvalidInitDecl
						if name == "main" {
							code = InvalidMainDecl
						}
						if len(s.TParamList) != 0 {
							check.softErrorf(s.TParamList[0], code, "func %s must have no type parameters", name)
							hasTParamError = true
						}
						if t := s.Type; len(t.ParamList) != 0 || len(t.ResultList) != 0 {
							check.softErrorf(s.Name, code, "func %s must have no arguments and no return values", name)
						}
					}
					// don't declare init functions in the package scope - they are invisible
					if name == "init" {
						obj.parent = pkg.scope
						check.recordDef(s.Name, obj)
						// init functions must have a body
						if s.Body == nil {
							// TODO(gri) make this error message consistent with the others above
							check.softErrorf(obj.pos, MissingInitBody, "missing function body")
						}
					} else {
						check.declare(pkg.scope, s.Name, obj, nopos)
					}
				} else {
					// method
					// d.Recv != nil
					ptr, base, _ := check.unpackRecv(s.Recv.Type, false)
					// Methods with invalid receiver cannot be associated to a type, and
					// methods with blank _ names are never found; no need to collect any
					// of them. They will still be type-checked with all the other functions.
					if recv, _ := base.(*syntax.Name); recv != nil && name != "_" {
						methods = append(methods, methodInfo{obj, ptr, recv})
					}
					check.recordDef(s.Name, obj)
				}
				_ = len(s.TParamList) != 0 && !hasTParamError && check.verifyVersionf(s.TParamList[0], go1_18, "type parameter")
				info := &declInfo{file: fileScope, version: check.version, fdecl: s}
				// Methods are not package-level objects but we still track them in the
				// object map so that we can handle them like regular functions (if the
				// receiver is invalid); also we need their fdecl info when associating
				// them with their receiver base type, below.
				check.objMap[obj] = info
				obj.setOrder(uint32(len(check.objMap)))

			default:
				check.errorf(s, InvalidSyntaxTree, "unknown syntax.Decl node %T", s)
			}
		}
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
// Note that base may not be a *syntax.Name for erroneous programs.
func (check *Checker) unpackRecv(rtyp syntax.Expr, unpackParams bool) (ptr bool, base syntax.Expr, tparams []*syntax.Name) {
	// unpack receiver type
	base = syntax.Unparen(rtyp)
	if t, _ := base.(*syntax.Operation); t != nil && t.Op == syntax.Mul && t.Y == nil {
		ptr = true
		base = syntax.Unparen(t.X)
	}

	// unpack type parameters, if any
	if ptyp, _ := base.(*syntax.IndexExpr); ptyp != nil {
		base = ptyp.X
		if unpackParams {
			for _, arg := range syntax.UnpackListExpr(ptyp.Index) {
				var par *syntax.Name
				switch arg := arg.(type) {
				case *syntax.Name:
					par = arg
				case *syntax.BadExpr:
					// ignore - error already reported by parser
				case nil:
					check.error(ptyp, InvalidSyntaxTree, "parameterized receiver contains nil parameters")
				default:
					check.errorf(arg, BadDecl, "receiver type parameter %s must be an identifier", arg)
				}
				if par == nil {
					par = syntax.NewName(arg.Pos(), "_")
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
func (check *Checker) resolveBaseTypeName(ptr bool, name *syntax.Name) (ptr_ bool, base *TypeName) {
	// Algorithm: Starting from name, which is expected to denote a type,
	// we follow that type through non-generic alias declarations until
	// we reach a non-alias type name.
	var seen map[*TypeName]bool
	for name != nil {
		// name must denote an object found in the current package scope
		// (note that dot-imported objects are not in the package scope!)
		obj := check.pkg.scope.Lookup(name.Value)
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
		if !tdecl.Alias {
			return ptr, tname
		}

		// an alias must not be generic
		// (importantly, we must not collect such methods - was https://go.dev/issue/70417)
		if tdecl.TParamList != nil {
			break
		}

		// otherwise, remember this type name and continue resolving
		if seen == nil {
			seen = make(map[*TypeName]bool)
		}
		seen[tname] = true

		// The syntax parser strips unnecessary parentheses; call Unparen for consistency with go/types.
		typ := syntax.Unparen(tdecl.Type)

		// dereference a pointer type
		if pexpr, _ := typ.(*syntax.Operation); pexpr != nil && pexpr.Op == syntax.Mul && pexpr.Y == nil {
			// if we've already seen a pointer, we're done
			if ptr {
				break
			}
			ptr = true
			typ = syntax.Unparen(pexpr.X) // continue with pointer base type
		}

		// After dereferencing, typ must be a locally defined type name.
		// Referring to other packages (qualified identifiers) or going
		// through instantiated types (index expressions) is not permitted,
		// so we can ignore those.
		name, _ = typ.(*syntax.Name)
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

	if false && check.conf.EnableAlias {
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
				if check.objMap[tname].tdecl.Alias {
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

"""



```