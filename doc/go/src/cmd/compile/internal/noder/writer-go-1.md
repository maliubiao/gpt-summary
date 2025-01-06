Response: The user wants to understand the functionality of the Go code snippet provided, which is part of the `go/src/cmd/compile/internal/noder/writer.go` file. This file is involved in the compilation process of Go code.

Here's a breakdown of how to address the request:

1. **Identify the main structures and their roles:** The code defines `declCollector`, `fileImports`, and augments `pkgWriter`. `declCollector` seems to be responsible for gathering information about declarations. `fileImports` tracks imported packages. `pkgWriter` holds compilation state.

2. **Analyze the `declCollector`'s `Visit` method:** This method traverses the syntax tree and performs actions based on the type of node encountered. Key actions include:
    - Checking pragmas (`//go:build`, `//go:embed`, etc.).
    - Tracking imported packages ("embed", "unsafe").
    - Storing function and type declarations along with their associated syntax nodes.
    - Assigning unique IDs to locally defined types within functions.
    - Handling `//go:embed` directives in variable declarations.

3. **Analyze the `collectDecls` method of `pkgWriter`:** This method orchestrates the collection of declaration information by using `declCollector`. It also handles `//go:linkname` directives and checks for their validity.

4. **Analyze the `checkPragmas` method of `pkgWriter`:** This method verifies the placement and allowed flags for compiler pragmas.

5. **Analyze the `pkgInit` method of `writer`:** This method seems to be involved in writing package-level information, including cgo pragmas, initialization order, and declarations.

6. **Analyze the `pkgInitOrder` method of `writer`:** This method writes the order of initialization for package-level variables.

7. **Analyze the `pkgDecl` method of `writer`:** This method handles writing information about different kinds of declarations (imports, constants, functions, types, variables). It skips generic declarations and blank identifiers. It also handles writing `//go:embed` information for variables.

8. **Analyze the `pkgObjs` method of `writer`:** This method writes information about declared objects (names).

9. **Analyze the helper functions:** These functions provide utility for analyzing expressions, identifying object types, and more. Pay attention to functions like `staticBool`, `hasImplicitTypeParams`, `lookupObj`, `isNil`, `isBuiltin`, and `terminates`.

10. **Infer the overall purpose:** Based on the individual components, the code seems to be responsible for collecting information about package-level declarations and their attributes during the Go compilation process. This information is likely used in later stages of compilation for code generation or optimization.

11. **Provide Go code examples:** Illustrate the usage of pragmas like `//go:embed` and `//go:linkname` to demonstrate the functionality being implemented.

12. **Explain command-line parameters (if applicable):**  The code doesn't directly handle command-line parameters within this snippet. The broader `compile` command would handle these.

13. **Identify common mistakes:** Focus on incorrect usage of pragmas (`//go:embed` outside variable declarations, `//go:linkname` without importing "unsafe", etc.).

14. **Summarize the functionality:** Concisely describe the role of this code in the Go compilation process.
Based on the provided Go code snippet from `go/src/cmd/compile/internal/noder/writer.go`, here's a breakdown of its functionality:

**Overall Functionality:**

This code snippet defines structures and functions responsible for collecting information about Go package declarations and preparing this information for later stages of the Go compilation process. It acts as an intermediary, bridging the gap between the parsed syntax tree and the internal representation used by the compiler. Specifically, it focuses on:

1. **Collecting Declaration Metadata:**  It gathers details about various declarations (constants, functions, types, variables, and imports) that are not directly tracked by the `types2` package (which handles type checking). This includes:
    - Associating declarations with their corresponding syntax tree nodes.
    - Tracking implicit type parameters introduced by generic functions or types.
    - Assigning unique "generation" numbers to locally defined types within functions.
    - Recording the presence of `//go:embed` and `//go:linkname` directives and their associated information.

2. **Handling Compiler Pragmas:** It processes compiler directives (pragmas) like `//go:build`, `//go:embed`, `//go:linkname`, etc., validating their placement and extracting relevant data.

3. **Preparing Data for Serialization:**  The `pkgWriter` and `writer` structures, along with methods like `pkgInit`, `pkgDecl`, and `pkgObjs`, seem to be involved in organizing the collected information in a way that can be efficiently written to a binary format (likely for inter-process communication or storage during the compilation process). This is hinted at by methods like `w.Len`, `w.Strings`, `w.Code`, and `w.Sync`, which suggest writing data with length prefixes and synchronization markers.

**Specific Functionality Breakdown:**

* **`fileImports` struct:**  Keeps track of whether the "embed" and "unsafe" packages have been imported in the current file. This information is used for validating pragmas like `//go:embed` and `//go:linkname`.

* **`declCollector` struct and its `Visit` method:** This is the core of the declaration collection process. It implements the `syntax.Visitor` interface to traverse the abstract syntax tree (AST). The `Visit` method handles different types of syntax nodes:
    * **`*syntax.File`:** Checks package-level pragmas.
    * **`*syntax.ImportDecl`:** Records imports of "embed" and "unsafe" and checks import pragmas.
    * **`*syntax.ConstDecl`:** Checks constant declaration pragmas.
    * **`*syntax.FuncDecl`:** Stores the function declaration node, checks pragmas, and handles implicit type parameters.
    * **`*syntax.TypeDecl`:** Stores the type declaration node, assigns generation numbers to local types, checks pragmas, and handles implicit type parameters.
    * **`*syntax.VarDecl`:** Checks pragmas and specifically handles `//go:embed` directives, validating their usage.
    * **`*syntax.BlockStmt`:**  Manages the `withinFunc` context to identify local type declarations.

* **`pkgWriter` struct and its `collectDecls` method:** The `collectDecls` method drives the declaration collection by creating a `declCollector` and walking the syntax tree of each file in the package. It also handles `//go:linkname` directives, verifying that the "unsafe" package is imported and that the linked symbol is a declared function or variable.

* **`pkgWriter`'s `checkPragmas` method:**  Ensures that compiler pragmas are placed correctly and use allowed flags. It specifically flags misplaced `//go:embed` directives.

* **`writer` struct and its methods (`pkgInit`, `pkgInitOrder`, `pkgDecl`, `pkgObjs`):** These methods appear to be responsible for writing the collected declaration information and other package-level data into a binary format.
    * **`pkgInit`:**  Writes cgo pragmas, calls `pkgInitOrder`, and then iterates through declarations in each file, calling `pkgDecl` for each.
    * **`pkgInitOrder`:** Writes the initialization order of package-level variables.
    * **`pkgDecl`:** Handles writing information for different declaration types (constants, functions, types, variables), skipping generic declarations and blank identifiers. It also writes information about `//go:embed` directives on variables.
    * **`pkgObjs`:** Writes information about declared objects (names).

* **Helper functions:**  Functions like `staticBool`, `hasImplicitTypeParams`, `lookupObj`, `isNil`, `isBuiltin`, and `terminates` provide utility for analyzing expressions and determining properties of code elements during the collection process.

**In summary, this part of the Go compiler is responsible for extracting metadata and structural information about Go package declarations from the syntax tree, validating compiler directives, and organizing this information for subsequent stages of the compilation process.**

**Illustrative Go Code Example (Hypothetical Scenario):**

Let's say you have the following Go code:

```go
package mypackage

import "embed"
import "unsafe"

//go:embed version.txt
var version string

//go:linkname os_Getenv os.Getenv
func os_Getenv(key string) string

type MyInt int

func Add(a, b MyInt) MyInt {
	type localString string // Local type definition
	var s localString = "result"
	_ = s
	return a + b
}
```

**Hypothetical Input & Output (Conceptual):**

When the `declCollector` and `pkgWriter` process this code, they would generate internal data structures (not directly visible as output code) that could be conceptually represented as follows:

* **`fileImports`:**  `importedEmbed: true`, `importedUnsafe: true`
* **`pw.funDecls`:**  Map containing the `*types2.Func` for `os_Getenv` and `Add`, pointing to their respective `*syntax.FuncDecl` nodes.
* **`pw.typDecls`:** Map containing:
    * The `*types2.TypeName` for `MyInt`, pointing to its `*syntax.TypeDecl`.
    * The `*types2.TypeName` for the local `localString` type within `Add`, pointing to its `*syntax.TypeDecl` and having a unique `gen` number assigned because it's local.
* **`pw.linknames`:** Map containing the `*types2.Func` for `os_Getenv` as the key and `"os.Getenv"` as the value.
* **Embedded data for `version`:** Information about the `//go:embed` directive, including the pattern "version.txt".

**Command-Line Parameters:**

This specific code snippet doesn't directly handle command-line parameters. However, the `go build` command (which invokes the compiler) accepts various parameters that influence the compilation process, such as:

* **`-o <output>`:** Specifies the output file name.
* **`-gcflags <flags>`:**  Passes flags to the Go compiler.
* **`-ldflags <flags>`:** Passes flags to the linker.

These parameters would indirectly affect the behavior of the broader compilation process that uses this code. For example, build tags specified via command-line parameters influence which code is included in the compilation, which would affect the syntax tree traversed by the `declCollector`.

**Common Mistakes (Hypothetical):**

* **Misplaced `//go:embed`:**

```go
package mypackage

//go:embed version.txt // INCORRECT: Not on a var declaration
func loadVersion() string {
  // ...
}
```
The `declCollector` and `checkPragmas` would flag this as an error because `//go:embed` is only allowed on variable declarations.

* **Using `//go:linkname` without importing "unsafe":**

```go
package mypackage

//go:linkname os_Getenv os.Getenv // INCORRECT: Missing "unsafe" import
func os_Getenv(key string) string {
  // ...
}
```
The `collectDecls` method would detect the missing "unsafe" import and issue an error.

* **Incorrect `//go:linkname` target:**

```go
package mypackage

import "unsafe"

var someVar int

//go:linkname someVar os.SomeGlobal // INCORRECT: Linking to a variable across packages
var linkedVar int
```
While the syntax is valid, linking to variables in other packages using `//go:linkname` has specific limitations and might lead to runtime issues. The compiler might not catch all such errors at this stage. (Note: The provided code snippet has a check that suggests linking to variables is allowed since Go 1.18).

**Summary of Functionality (Part 2):**

This second part of the code focuses on the **serialization and writing of the collected declaration information**. It defines the `writer` structure and its methods that take the metadata gathered by the `declCollector` and `pkgWriter` and encode it into a structured format suitable for later stages of the compiler pipeline. This involves writing information about:

* Cgo pragmas.
* The order of initialization for package-level variables.
* Details about each declaration (type, name, associated objects).
* Specific attributes like the patterns for `//go:embed` directives on variables.

The `writer` acts as a serializer, preparing the extracted declaration information for efficient storage or transmission within the compilation process.

Prompt: 
```
这是路径为go/src/cmd/compile/internal/noder/writer.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
cope at this type declaration.
	implicits []*types2.TypeParam
}

type fileImports struct {
	importedEmbed, importedUnsafe bool
}

// declCollector is a visitor type that collects compiler-needed
// information about declarations that types2 doesn't track.
//
// Notably, it maps declared types and functions back to their
// declaration statement, keeps track of implicit type parameters, and
// assigns unique type "generation" numbers to local defined types.
type declCollector struct {
	pw         *pkgWriter
	typegen    *int
	file       *fileImports
	withinFunc bool
	implicits  []*types2.TypeParam
}

func (c *declCollector) withTParams(obj types2.Object) *declCollector {
	tparams := objTypeParams(obj)
	n := tparams.Len()
	if n == 0 {
		return c
	}

	copy := *c
	copy.implicits = copy.implicits[:len(copy.implicits):len(copy.implicits)]
	for i := 0; i < n; i++ {
		copy.implicits = append(copy.implicits, tparams.At(i))
	}
	return &copy
}

func (c *declCollector) Visit(n syntax.Node) syntax.Visitor {
	pw := c.pw

	switch n := n.(type) {
	case *syntax.File:
		pw.checkPragmas(n.Pragma, ir.GoBuildPragma, false)

	case *syntax.ImportDecl:
		pw.checkPragmas(n.Pragma, 0, false)

		switch pw.info.PkgNameOf(n).Imported().Path() {
		case "embed":
			c.file.importedEmbed = true
		case "unsafe":
			c.file.importedUnsafe = true
		}

	case *syntax.ConstDecl:
		pw.checkPragmas(n.Pragma, 0, false)

	case *syntax.FuncDecl:
		pw.checkPragmas(n.Pragma, funcPragmas, false)

		obj := pw.info.Defs[n.Name].(*types2.Func)
		pw.funDecls[obj] = n

		return c.withTParams(obj)

	case *syntax.TypeDecl:
		obj := pw.info.Defs[n.Name].(*types2.TypeName)
		d := typeDeclGen{TypeDecl: n, implicits: c.implicits}

		if n.Alias {
			pw.checkPragmas(n.Pragma, 0, false)
		} else {
			pw.checkPragmas(n.Pragma, 0, false)

			// Assign a unique ID to function-scoped defined types.
			if c.withinFunc {
				*c.typegen++
				d.gen = *c.typegen
			}
		}

		pw.typDecls[obj] = d

		// TODO(mdempsky): Omit? Not strictly necessary; only matters for
		// type declarations within function literals within parameterized
		// type declarations, but types2 the function literals will be
		// constant folded away.
		return c.withTParams(obj)

	case *syntax.VarDecl:
		pw.checkPragmas(n.Pragma, 0, true)

		if p, ok := n.Pragma.(*pragmas); ok && len(p.Embeds) > 0 {
			if err := checkEmbed(n, c.file.importedEmbed, c.withinFunc); err != nil {
				pw.errorf(p.Embeds[0].Pos, "%s", err)
			}
		}

	case *syntax.BlockStmt:
		if !c.withinFunc {
			copy := *c
			copy.withinFunc = true
			return &copy
		}
	}

	return c
}

func (pw *pkgWriter) collectDecls(noders []*noder) {
	var typegen int
	for _, p := range noders {
		var file fileImports

		syntax.Walk(p.file, &declCollector{
			pw:      pw,
			typegen: &typegen,
			file:    &file,
		})

		pw.cgoPragmas = append(pw.cgoPragmas, p.pragcgobuf...)

		for _, l := range p.linknames {
			if !file.importedUnsafe {
				pw.errorf(l.pos, "//go:linkname only allowed in Go files that import \"unsafe\"")
				continue
			}
			if strings.Contains(l.remote, "[") && strings.Contains(l.remote, "]") {
				pw.errorf(l.pos, "//go:linkname reference of an instantiation is not allowed")
				continue
			}

			switch obj := pw.curpkg.Scope().Lookup(l.local).(type) {
			case *types2.Func, *types2.Var:
				if _, ok := pw.linknames[obj]; !ok {
					pw.linknames[obj] = l.remote
				} else {
					pw.errorf(l.pos, "duplicate //go:linkname for %s", l.local)
				}

			default:
				if types.AllowsGoVersion(1, 18) {
					pw.errorf(l.pos, "//go:linkname must refer to declared function or variable")
				}
			}
		}
	}
}

func (pw *pkgWriter) checkPragmas(p syntax.Pragma, allowed ir.PragmaFlag, embedOK bool) {
	if p == nil {
		return
	}
	pragma := p.(*pragmas)

	for _, pos := range pragma.Pos {
		if pos.Flag&^allowed != 0 {
			pw.errorf(pos.Pos, "misplaced compiler directive")
		}
	}

	if !embedOK {
		for _, e := range pragma.Embeds {
			pw.errorf(e.Pos, "misplaced go:embed directive")
		}
	}
}

func (w *writer) pkgInit(noders []*noder) {
	w.Len(len(w.p.cgoPragmas))
	for _, cgoPragma := range w.p.cgoPragmas {
		w.Strings(cgoPragma)
	}

	w.pkgInitOrder()

	w.Sync(pkgbits.SyncDecls)
	for _, p := range noders {
		for _, decl := range p.file.DeclList {
			w.pkgDecl(decl)
		}
	}
	w.Code(declEnd)

	w.Sync(pkgbits.SyncEOF)
}

func (w *writer) pkgInitOrder() {
	// TODO(mdempsky): Write as a function body instead?
	w.Len(len(w.p.info.InitOrder))
	for _, init := range w.p.info.InitOrder {
		w.Len(len(init.Lhs))
		for _, v := range init.Lhs {
			w.obj(v, nil)
		}
		w.expr(init.Rhs)
	}
}

func (w *writer) pkgDecl(decl syntax.Decl) {
	switch decl := decl.(type) {
	default:
		w.p.unexpected("declaration", decl)

	case *syntax.ImportDecl:

	case *syntax.ConstDecl:
		w.Code(declOther)
		w.pkgObjs(decl.NameList...)

	case *syntax.FuncDecl:
		if decl.Name.Value == "_" {
			break // skip blank functions
		}

		obj := w.p.info.Defs[decl.Name].(*types2.Func)
		sig := obj.Type().(*types2.Signature)

		if sig.RecvTypeParams() != nil || sig.TypeParams() != nil {
			break // skip generic functions
		}

		if recv := sig.Recv(); recv != nil {
			w.Code(declMethod)
			w.typ(recvBase(recv))
			w.selector(obj)
			break
		}

		w.Code(declFunc)
		w.pkgObjs(decl.Name)

	case *syntax.TypeDecl:
		if len(decl.TParamList) != 0 {
			break // skip generic type decls
		}

		if decl.Name.Value == "_" {
			break // skip blank type decls
		}

		name := w.p.info.Defs[decl.Name].(*types2.TypeName)
		// Skip type declarations for interfaces that are only usable as
		// type parameter bounds.
		if iface, ok := name.Type().Underlying().(*types2.Interface); ok && !iface.IsMethodSet() {
			break
		}

		w.Code(declOther)
		w.pkgObjs(decl.Name)

	case *syntax.VarDecl:
		w.Code(declVar)
		w.pkgObjs(decl.NameList...)

		var embeds []pragmaEmbed
		if p, ok := decl.Pragma.(*pragmas); ok {
			embeds = p.Embeds
		}
		w.Len(len(embeds))
		for _, embed := range embeds {
			w.pos(embed.Pos)
			w.Strings(embed.Patterns)
		}
	}
}

func (w *writer) pkgObjs(names ...*syntax.Name) {
	w.Sync(pkgbits.SyncDeclNames)
	w.Len(len(names))

	for _, name := range names {
		obj, ok := w.p.info.Defs[name]
		assert(ok)

		w.Sync(pkgbits.SyncDeclName)
		w.obj(obj, nil)
	}
}

// @@@ Helpers

// staticBool analyzes a boolean expression and reports whether it's
// always true (positive result), always false (negative result), or
// unknown (zero).
//
// It also simplifies the expression while preserving semantics, if
// possible.
func (pw *pkgWriter) staticBool(ep *syntax.Expr) int {
	if val := pw.typeAndValue(*ep).Value; val != nil {
		if constant.BoolVal(val) {
			return +1
		} else {
			return -1
		}
	}

	if e, ok := (*ep).(*syntax.Operation); ok {
		switch e.Op {
		case syntax.Not:
			return pw.staticBool(&e.X)

		case syntax.AndAnd:
			x := pw.staticBool(&e.X)
			if x < 0 {
				*ep = e.X
				return x
			}

			y := pw.staticBool(&e.Y)
			if x > 0 || y < 0 {
				if pw.typeAndValue(e.X).Value != nil {
					*ep = e.Y
				}
				return y
			}

		case syntax.OrOr:
			x := pw.staticBool(&e.X)
			if x > 0 {
				*ep = e.X
				return x
			}

			y := pw.staticBool(&e.Y)
			if x < 0 || y > 0 {
				if pw.typeAndValue(e.X).Value != nil {
					*ep = e.Y
				}
				return y
			}
		}
	}

	return 0
}

// hasImplicitTypeParams reports whether obj is a defined type with
// implicit type parameters (e.g., declared within a generic function
// or method).
func (pw *pkgWriter) hasImplicitTypeParams(obj *types2.TypeName) bool {
	if obj.Pkg() == pw.curpkg {
		decl, ok := pw.typDecls[obj]
		assert(ok)
		if len(decl.implicits) != 0 {
			return true
		}
	}
	return false
}

// isDefinedType reports whether obj is a defined type.
func isDefinedType(obj types2.Object) bool {
	if obj, ok := obj.(*types2.TypeName); ok {
		return !obj.IsAlias()
	}
	return false
}

// isGlobal reports whether obj was declared at package scope.
//
// Caveat: blank objects are not declared.
func isGlobal(obj types2.Object) bool {
	return obj.Parent() == obj.Pkg().Scope()
}

// lookupObj returns the object that expr refers to, if any. If expr
// is an explicit instantiation of a generic object, then the instance
// object is returned as well.
func lookupObj(p *pkgWriter, expr syntax.Expr) (obj types2.Object, inst types2.Instance) {
	if index, ok := expr.(*syntax.IndexExpr); ok {
		args := syntax.UnpackListExpr(index.Index)
		if len(args) == 1 {
			tv := p.typeAndValue(args[0])
			if tv.IsValue() {
				return // normal index expression
			}
		}

		expr = index.X
	}

	// Strip package qualifier, if present.
	if sel, ok := expr.(*syntax.SelectorExpr); ok {
		if !isPkgQual(p.info, sel) {
			return // normal selector expression
		}
		expr = sel.Sel
	}

	if name, ok := expr.(*syntax.Name); ok {
		obj = p.info.Uses[name]
		inst = p.info.Instances[name]
	}
	return
}

// isPkgQual reports whether the given selector expression is a
// package-qualified identifier.
func isPkgQual(info *types2.Info, sel *syntax.SelectorExpr) bool {
	if name, ok := sel.X.(*syntax.Name); ok {
		_, isPkgName := info.Uses[name].(*types2.PkgName)
		return isPkgName
	}
	return false
}

// isNil reports whether expr is a (possibly parenthesized) reference
// to the predeclared nil value.
func isNil(p *pkgWriter, expr syntax.Expr) bool {
	tv := p.typeAndValue(expr)
	return tv.IsNil()
}

// isBuiltin reports whether expr is a (possibly parenthesized)
// referenced to the specified built-in function.
func (pw *pkgWriter) isBuiltin(expr syntax.Expr, builtin string) bool {
	if name, ok := syntax.Unparen(expr).(*syntax.Name); ok && name.Value == builtin {
		return pw.typeAndValue(name).IsBuiltin()
	}
	return false
}

// recvBase returns the base type for the given receiver parameter.
func recvBase(recv *types2.Var) *types2.Named {
	typ := types2.Unalias(recv.Type())
	if ptr, ok := typ.(*types2.Pointer); ok {
		typ = types2.Unalias(ptr.Elem())
	}
	return typ.(*types2.Named)
}

// namesAsExpr returns a list of names as a syntax.Expr.
func namesAsExpr(names []*syntax.Name) syntax.Expr {
	if len(names) == 1 {
		return names[0]
	}

	exprs := make([]syntax.Expr, len(names))
	for i, name := range names {
		exprs[i] = name
	}
	return &syntax.ListExpr{ElemList: exprs}
}

// fieldIndex returns the index of the struct field named by key.
func fieldIndex(info *types2.Info, str *types2.Struct, key *syntax.Name) int {
	field := info.Uses[key].(*types2.Var)

	for i := 0; i < str.NumFields(); i++ {
		if str.Field(i) == field {
			return i
		}
	}

	panic(fmt.Sprintf("%s: %v is not a field of %v", key.Pos(), field, str))
}

// objTypeParams returns the type parameters on the given object.
func objTypeParams(obj types2.Object) *types2.TypeParamList {
	switch obj := obj.(type) {
	case *types2.Func:
		sig := obj.Type().(*types2.Signature)
		if sig.Recv() != nil {
			return sig.RecvTypeParams()
		}
		return sig.TypeParams()
	case *types2.TypeName:
		switch t := obj.Type().(type) {
		case *types2.Named:
			return t.TypeParams()
		case *types2.Alias:
			return t.TypeParams()
		}
	}
	return nil
}

// splitNamed decomposes a use of a defined type into its original
// type definition and the type arguments used to instantiate it.
func splitNamed(typ *types2.Named) (*types2.TypeName, *types2.TypeList) {
	base.Assertf(typ.TypeParams().Len() == typ.TypeArgs().Len(), "use of uninstantiated type: %v", typ)

	orig := typ.Origin()
	base.Assertf(orig.TypeArgs() == nil, "origin %v of %v has type arguments", orig, typ)
	base.Assertf(typ.Obj() == orig.Obj(), "%v has object %v, but %v has object %v", typ, typ.Obj(), orig, orig.Obj())

	return typ.Obj(), typ.TypeArgs()
}

// splitAlias is like splitNamed, but for an alias type.
func splitAlias(typ *types2.Alias) (*types2.TypeName, *types2.TypeList) {
	orig := typ.Origin()
	base.Assertf(typ.Obj() == orig.Obj(), "alias type %v has object %v, but %v has object %v", typ, typ.Obj(), orig, orig.Obj())

	return typ.Obj(), typ.TypeArgs()
}

func asPragmaFlag(p syntax.Pragma) ir.PragmaFlag {
	if p == nil {
		return 0
	}
	return p.(*pragmas).Flag
}

func asWasmImport(p syntax.Pragma) *WasmImport {
	if p == nil {
		return nil
	}
	return p.(*pragmas).WasmImport
}

func asWasmExport(p syntax.Pragma) *WasmExport {
	if p == nil {
		return nil
	}
	return p.(*pragmas).WasmExport
}

// isPtrTo reports whether from is the type *to.
func isPtrTo(from, to types2.Type) bool {
	ptr, ok := types2.Unalias(from).(*types2.Pointer)
	return ok && types2.Identical(ptr.Elem(), to)
}

// hasFallthrough reports whether stmts ends in a fallthrough
// statement.
func hasFallthrough(stmts []syntax.Stmt) bool {
	// From spec: the last non-empty statement may be a (possibly labeled) "fallthrough" statement
	// Stripping (possible nested) labeled statement if any.
	stmt := lastNonEmptyStmt(stmts)
	for {
		ls, ok := stmt.(*syntax.LabeledStmt)
		if !ok {
			break
		}
		stmt = ls.Stmt
	}
	last, ok := stmt.(*syntax.BranchStmt)
	return ok && last.Tok == syntax.Fallthrough
}

// lastNonEmptyStmt returns the last non-empty statement in list, if
// any.
func lastNonEmptyStmt(stmts []syntax.Stmt) syntax.Stmt {
	for i := len(stmts) - 1; i >= 0; i-- {
		stmt := stmts[i]
		if _, ok := stmt.(*syntax.EmptyStmt); !ok {
			return stmt
		}
	}
	return nil
}

// terminates reports whether stmt terminates normal control flow
// (i.e., does not merely advance to the following statement).
func (pw *pkgWriter) terminates(stmt syntax.Stmt) bool {
	switch stmt := stmt.(type) {
	case *syntax.BranchStmt:
		if stmt.Tok == syntax.Goto {
			return true
		}
	case *syntax.ReturnStmt:
		return true
	case *syntax.ExprStmt:
		if call, ok := syntax.Unparen(stmt.X).(*syntax.CallExpr); ok {
			if pw.isBuiltin(call.Fun, "panic") {
				return true
			}
		}

		// The handling of BlockStmt here is approximate, but it serves to
		// allow dead-code elimination for:
		//
		//	if true {
		//		return x
		//	}
		//	unreachable
	case *syntax.IfStmt:
		cond := pw.staticBool(&stmt.Cond)
		return (cond < 0 || pw.terminates(stmt.Then)) && (cond > 0 || pw.terminates(stmt.Else))
	case *syntax.BlockStmt:
		return pw.terminates(lastNonEmptyStmt(stmt.List))
	}

	return false
}

"""




```