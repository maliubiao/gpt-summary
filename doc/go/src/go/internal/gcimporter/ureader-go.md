Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understanding the Goal:** The request asks for the functionality of the `ureader.go` file, its role in the Go language, example usage, handling of command-line arguments, and potential pitfalls.

2. **Initial Scan and Keyword Recognition:**  I quickly scanned the code for keywords and recognizable structures:
    * `package gcimporter`:  This immediately suggests it's related to importing Go packages, likely during compilation or type checking.
    * `pkgReader`, `reader`, `readerDict`:  These struct names indicate a reader pattern, suggesting the code is involved in deserializing or interpreting some data format.
    * `pkgbits.PkgDecoder`, `pkgbits.Decoder`, `pkgbits.Reloc...`, `pkgbits.Sync...`: The `pkgbits` package is central. This hints at a custom binary format for representing package information. "Reloc" likely refers to relocation or indexing within this format, and "Sync" suggests synchronization points.
    * `go/token`, `go/types`: These are standard Go packages for representing source code tokens and type information. This confirms the code's connection to Go's type system.
    * `types.Context`, `types.Package`, `types.Type`:  These reinforce the idea of type information processing.
    * `laterFns`, `ifaces.Complete()`:  These suggest deferred actions, likely related to resolving dependencies or completing object construction.

3. **Identifying Core Functionality (Deduction from Structure):**
    * **`readUnifiedPackage` function:** This is the entry point for reading a package. It initializes a `pkgReader` and iterates through objects in the package. The "unified IR export data decoder" comment strongly suggests it's reading a serialized representation of a Go package.
    * **`pkgReader` struct:** It holds the state for reading the entire package, including imported packages, position bases (filenames), package data, and type data. The `PkgDecoder` field indicates it consumes data from the `pkgbits` format.
    * **`reader` struct:** Represents the state for reading individual elements (like types or objects) within a package. It uses a `pkgbits.Decoder`.
    * **`readerDict` struct:**  Deals with type parameters, hinting at support for generics.
    * **Functions like `pos()`, `pkg()`, `typ()`, `obj()`:** These are clearly responsible for reading specific components of the package data, like position information, package references, type information, and object declarations. The use of `Reloc...` and `Sync...` within these functions confirms they're interacting with the `pkgbits` decoder.

4. **Inferring the Purpose (Connecting the Dots):** Based on the package name (`gcimporter`), the use of `go/types`, and the reading of a "unified IR," I concluded that this code is responsible for *importing pre-compiled Go packages*. The "unified IR" is likely an intermediate representation used to speed up compilation by avoiding the need to re-parse and type-check imported packages from source.

5. **Constructing an Example (Illustrating the Functionality):**
    * I needed to show how this code would be used in practice. The key is that it's used *during compilation*. Therefore, the example should demonstrate a scenario where a package imports another package.
    * I chose a simple example of `package main` importing `fmt`. This is a common and easy-to-understand case.
    * The crucial part was to emphasize that the *input* to `readUnifiedPackage` is the *output* of a previous compilation step (the "unified IR"). Since we don't have access to the actual binary format, I represented the input as a conceptual "unified IR data" for the `fmt` package.
    * The output is the `*types.Package` representing the imported `fmt` package.

6. **Reasoning about Command-Line Arguments:** I reviewed the code for any direct interaction with command-line arguments. There were none. However, I recognized that the behavior of the importer might be *influenced* by build flags or environment variables that control the compilation process. I specifically mentioned `GODEBUG=...` because the code explicitly checks `godebug.New("gotypesalias")`.

7. **Identifying Potential Pitfalls:**
    * **Incorrect `pkgbits` Data:**  The most obvious issue is providing malformed or incorrect unified IR data. This would lead to errors during decoding. I framed this as a scenario where a custom tool might generate incorrect data.
    * **Version Mismatch:**  Since the format seems to evolve (indicated by `r.Version().Has(...)`), using an importer built for one Go version with data generated by a different version could cause problems.

8. **Structuring the Answer:** I organized the information into logical sections: Functionality, Core Implementation, Example, Command-line Arguments, and Potential Pitfalls. I used clear and concise language, avoiding overly technical jargon where possible. I included code snippets in the example to make it more concrete.

9. **Refinement and Review:** I reread the initial request to ensure I had addressed all the points. I also reviewed my answer for clarity, accuracy, and completeness. For example, I made sure to explain *why* `iface.Complete()` is called later.

This step-by-step process, combining code analysis, deduction, and knowledge of Go's compilation process, allowed me to arrive at a comprehensive and accurate answer. The key was to understand the *context* of the code within the larger Go toolchain.
这段 `go/src/go/internal/gcimporter/ureader.go` 文件是 Go 语言编译器 `gc` 的一部分，其核心功能是**读取和解析 Go 语言统一中间表示 (Unified IR) 的包导出数据**。  更具体地说，它实现了将已编译的包的元数据（例如类型信息、常量、函数签名等）从一种高效的二进制格式（Unified IR）加载到 `go/types` 包所使用的数据结构中。

可以将其理解为 Go 编译器在处理 `import` 语句时，如何理解和使用已经编译好的其他包的信息。

**主要功能列举：**

1. **读取 Unified IR 数据:**  `readUnifiedPackage` 函数是入口点，负责从 `pkgbits.PkgDecoder` 中读取包的描述信息。`pkgbits` 包定义了 Unified IR 的格式。
2. **构建 `types.Package`:** 将读取到的信息转换为 `go/types` 包中的 `types.Package` 结构，这个结构包含了包的名称、导入的包、导出的对象（类型、常量、变量、函数等）以及作用域信息。
3. **处理类型信息:**  文件中包含大量的类型相关的读取函数（例如 `typ()`, `doTyp()`, `structType()`, `interfaceType()`, `signature()` 等），这些函数负责解析 Unified IR 中表示的各种 Go 语言类型，并构建 `go/types` 包中的 `types.Type` 接口的实现（例如 `types.Basic`, `types.Named`, `types.Struct`, `types.Interface` 等）。
4. **处理对象信息:**  `obj()` 和相关的函数负责读取和创建包中导出的各种对象，例如常量 (`types.Const`)、函数 (`types.Func`)、类型 (`types.TypeName`)、变量 (`types.Var`) 和类型别名 (`types.Alias`)。
5. **处理泛型信息:** `readerDict` 结构以及 `typeParamNames()` 函数负责处理泛型类型参数，允许读取包含泛型的包的元数据。
6. **延迟处理 (Later Functions):**  `laterFns` 机制用于延迟执行一些需要在包的大部分信息读取完毕后才能进行的操作，例如设置类型参数的约束。
7. **完成接口类型:**  `ifaces` 用于存储创建的接口类型，并在所有类型信息加载完成后调用 `Complete()` 方法，以完成接口类型的构建。
8. **处理位置信息:** `pos()` 和相关的函数用于读取 Unified IR 中存储的源代码位置信息，并将其转换为 `go/token.Pos`。

**Go 语言功能实现示例 (泛型):**

假设我们有一个简单的 Go 包 `mypkg`，其中定义了一个泛型函数：

```go
// mypkg/mypkg.go
package mypkg

func Max[T comparable](a, b T) T {
	if a > b {
		return a
	}
	return b
}
```

当 `gc` 编译器编译 `mypkg` 时，它会生成包含 `Max` 函数的 Unified IR 数据。  `ureader.go` 的代码会负责读取这段数据，并将其转换为 `go/types` 中的表示。

**假设的 Unified IR 输入（简化表示）：**

```
// 假设的 pkgbits 数据，实际是二进制格式
Package: mypkg
Objects:
  - Name: Max
    Kind: Func
    TypeParams:
      - Name: T
        Constraint: comparable
    Signature: (a T, b T) T
```

**`ureader.go` 的处理过程（伪代码）：**

```go
// 在 readUnifiedPackage 函数中...
// ... 读取到 "Max" 对象 ...
switch tag {
case pkgbits.ObjFunc:
    pos := r.pos()
    tparams := r.typeParamNames() // 读取类型参数信息 (T comparable)
    sig := r.signature(nil, nil, tparams) // 读取函数签名信息
    declare(types.NewFunc(pos, objPkg, objName, sig)) // 创建 types.Func 对象
}

// 在 typeParamNames 函数中...
r.Sync(pkgbits.SyncTypeParamNames)
// ... 读取类型参数名称 "T" ...
// ... 读取类型参数约束 "comparable" ...
tname := types.NewTypeName(pos, pkg, name, nil)
tparam := types.NewTypeParam(tname, /* comparable 接口的 types.Type 表示 */)
r.dict.tparams = append(r.dict.tparams, tparam)
```

**输出的 `types.Object` (简化表示):**

```
types.Func {
    Name: "Max",
    Type: types.Signature {
        TypeParams: []*types.TypeParam {
            { Name: "T", Constraint: comparable接口的types.Type },
        },
        Params: []*types.Var {
            { Name: "a", Type: T },
            { Name: "b", Type: T },
        },
        Results: []*types.Var {
            { Type: T },
        },
    },
}
```

**命令行参数处理:**

这段代码本身并不直接处理命令行参数。它的输入是 `pkgbits.PkgDecoder`，这通常是由其他编译器的组件（例如负责读取 `.o` 文件或 export data 的部分）提供的。 命令行参数的处理发生在更上层的编译流程中。  例如， `-p` 参数指定导入路径， `-I` 参数指定 import 路径等，这些参数会影响编译器如何找到需要导入的包，并最终影响 `pkgbits.PkgDecoder` 中提供的数据。

**使用者易犯错的点 (理论上，因为 `gcimporter` 是内部组件):**

由于 `gcimporter` 是 Go 编译器内部使用的包，普通 Go 开发者不会直接调用它。 然而，如果有人尝试手动解析或生成 Unified IR 数据，可能会遇到以下问题：

1. **Unified IR 格式不稳定:**  Unified IR 的格式是编译器内部的实现细节，可能会在不同的 Go 版本之间发生变化。手动生成的 Unified IR 数据可能与当前 Go 版本的编译器不兼容，导致解析错误。
2. **`pkgbits` 包的复杂性:** `pkgbits` 包定义了复杂的编码规则和数据结构。理解和正确生成符合 `pkgbits` 规范的数据需要深入了解编译器的内部工作原理。
3. **依赖 `go/types` 的数据结构:**  正确地将 Unified IR 数据映射到 `go/types` 的数据结构需要对 `go/types` 包的语义有深刻的理解。  例如，错误地处理类型之间的关系或作用域可能会导致类型检查错误。

**总结:**

`go/src/go/internal/gcimporter/ureader.go` 是 Go 编译器中一个至关重要的组件，它负责将已编译包的元数据从高效的二进制格式加载到编译器可以理解的 `go/types` 数据结构中。这使得 Go 编译器能够高效地处理 `import` 语句，并进行跨包的类型检查和代码生成。 它涉及到对 Unified IR 格式的解析、`go/types` 包的使用，以及对泛型等复杂语言特性的处理。

### 提示词
```
这是路径为go/src/go/internal/gcimporter/ureader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gcimporter

import (
	"go/token"
	"go/types"
	"internal/godebug"
	"internal/pkgbits"
	"slices"
	"strings"
)

// A pkgReader holds the shared state for reading a unified IR package
// description.
type pkgReader struct {
	pkgbits.PkgDecoder

	fake fakeFileSet

	ctxt    *types.Context
	imports map[string]*types.Package // previously imported packages, indexed by path

	// lazily initialized arrays corresponding to the unified IR
	// PosBase, Pkg, and Type sections, respectively.
	posBases []string // position bases (i.e., file names)
	pkgs     []*types.Package
	typs     []types.Type

	// laterFns holds functions that need to be invoked at the end of
	// import reading.
	laterFns []func()

	// ifaces holds a list of constructed Interfaces, which need to have
	// Complete called after importing is done.
	ifaces []*types.Interface
}

// later adds a function to be invoked at the end of import reading.
func (pr *pkgReader) later(fn func()) {
	pr.laterFns = append(pr.laterFns, fn)
}

// readUnifiedPackage reads a package description from the given
// unified IR export data decoder.
func readUnifiedPackage(fset *token.FileSet, ctxt *types.Context, imports map[string]*types.Package, input pkgbits.PkgDecoder) *types.Package {
	pr := pkgReader{
		PkgDecoder: input,

		fake: fakeFileSet{
			fset:  fset,
			files: make(map[string]*fileInfo),
		},

		ctxt:    ctxt,
		imports: imports,

		posBases: make([]string, input.NumElems(pkgbits.RelocPosBase)),
		pkgs:     make([]*types.Package, input.NumElems(pkgbits.RelocPkg)),
		typs:     make([]types.Type, input.NumElems(pkgbits.RelocType)),
	}
	defer pr.fake.setLines()

	r := pr.newReader(pkgbits.RelocMeta, pkgbits.PublicRootIdx, pkgbits.SyncPublic)
	pkg := r.pkg()
	if r.Version().Has(pkgbits.HasInit) {
		r.Bool()
	}

	for i, n := 0, r.Len(); i < n; i++ {
		// As if r.obj(), but avoiding the Scope.Lookup call,
		// to avoid eager loading of imports.
		r.Sync(pkgbits.SyncObject)
		if r.Version().Has(pkgbits.DerivedFuncInstance) {
			assert(!r.Bool())
		}
		r.p.objIdx(r.Reloc(pkgbits.RelocObj))
		assert(r.Len() == 0)
	}

	r.Sync(pkgbits.SyncEOF)

	for _, fn := range pr.laterFns {
		fn()
	}

	for _, iface := range pr.ifaces {
		iface.Complete()
	}

	// Imports() of pkg are all of the transitive packages that were loaded.
	var imps []*types.Package
	for _, imp := range pr.pkgs {
		if imp != nil && imp != pkg {
			imps = append(imps, imp)
		}
	}
	slices.SortFunc(imps, func(a, b *types.Package) int {
		return strings.Compare(a.Path(), b.Path())
	})
	pkg.SetImports(imps)

	pkg.MarkComplete()
	return pkg
}

// A reader holds the state for reading a single unified IR element
// within a package.
type reader struct {
	pkgbits.Decoder

	p *pkgReader

	dict *readerDict
}

// A readerDict holds the state for type parameters that parameterize
// the current unified IR element.
type readerDict struct {
	// bounds is a slice of typeInfos corresponding to the underlying
	// bounds of the element's type parameters.
	bounds []typeInfo

	// tparams is a slice of the constructed TypeParams for the element.
	tparams []*types.TypeParam

	// derived is a slice of types derived from tparams, which may be
	// instantiated while reading the current element.
	derived      []derivedInfo
	derivedTypes []types.Type // lazily instantiated from derived
}

func (pr *pkgReader) newReader(k pkgbits.RelocKind, idx pkgbits.Index, marker pkgbits.SyncMarker) *reader {
	return &reader{
		Decoder: pr.NewDecoder(k, idx, marker),
		p:       pr,
	}
}

func (pr *pkgReader) tempReader(k pkgbits.RelocKind, idx pkgbits.Index, marker pkgbits.SyncMarker) *reader {
	return &reader{
		Decoder: pr.TempDecoder(k, idx, marker),
		p:       pr,
	}
}

func (pr *pkgReader) retireReader(r *reader) {
	pr.RetireDecoder(&r.Decoder)
}

// @@@ Positions

func (r *reader) pos() token.Pos {
	r.Sync(pkgbits.SyncPos)
	if !r.Bool() {
		return token.NoPos
	}

	// TODO(mdempsky): Delta encoding.
	posBase := r.posBase()
	line := r.Uint()
	col := r.Uint()
	return r.p.fake.pos(posBase, int(line), int(col))
}

func (r *reader) posBase() string {
	return r.p.posBaseIdx(r.Reloc(pkgbits.RelocPosBase))
}

func (pr *pkgReader) posBaseIdx(idx pkgbits.Index) string {
	if b := pr.posBases[idx]; b != "" {
		return b
	}

	var filename string
	{
		r := pr.tempReader(pkgbits.RelocPosBase, idx, pkgbits.SyncPosBase)

		// Within types2, position bases have a lot more details (e.g.,
		// keeping track of where //line directives appeared exactly).
		//
		// For go/types, we just track the file name.

		filename = r.String()

		if r.Bool() { // file base
			// Was: "b = token.NewTrimmedFileBase(filename, true)"
		} else { // line base
			pos := r.pos()
			line := r.Uint()
			col := r.Uint()

			// Was: "b = token.NewLineBase(pos, filename, true, line, col)"
			_, _, _ = pos, line, col
		}
		pr.retireReader(r)
	}
	b := filename
	pr.posBases[idx] = b
	return b
}

// @@@ Packages

func (r *reader) pkg() *types.Package {
	r.Sync(pkgbits.SyncPkg)
	return r.p.pkgIdx(r.Reloc(pkgbits.RelocPkg))
}

func (pr *pkgReader) pkgIdx(idx pkgbits.Index) *types.Package {
	// TODO(mdempsky): Consider using some non-nil pointer to indicate
	// the universe scope, so we don't need to keep re-reading it.
	if pkg := pr.pkgs[idx]; pkg != nil {
		return pkg
	}

	pkg := pr.newReader(pkgbits.RelocPkg, idx, pkgbits.SyncPkgDef).doPkg()
	pr.pkgs[idx] = pkg
	return pkg
}

func (r *reader) doPkg() *types.Package {
	path := r.String()
	switch path {
	case "":
		path = r.p.PkgPath()
	case "builtin":
		return nil // universe
	case "unsafe":
		return types.Unsafe
	}

	if pkg := r.p.imports[path]; pkg != nil {
		return pkg
	}

	name := r.String()

	pkg := types.NewPackage(path, name)
	r.p.imports[path] = pkg

	return pkg
}

// @@@ Types

func (r *reader) typ() types.Type {
	return r.p.typIdx(r.typInfo(), r.dict)
}

func (r *reader) typInfo() typeInfo {
	r.Sync(pkgbits.SyncType)
	if r.Bool() {
		return typeInfo{idx: pkgbits.Index(r.Len()), derived: true}
	}
	return typeInfo{idx: r.Reloc(pkgbits.RelocType), derived: false}
}

func (pr *pkgReader) typIdx(info typeInfo, dict *readerDict) types.Type {
	idx := info.idx
	var where *types.Type
	if info.derived {
		where = &dict.derivedTypes[idx]
		idx = dict.derived[idx].idx
	} else {
		where = &pr.typs[idx]
	}

	if typ := *where; typ != nil {
		return typ
	}

	var typ types.Type
	{
		r := pr.tempReader(pkgbits.RelocType, idx, pkgbits.SyncTypeIdx)
		r.dict = dict

		typ = r.doTyp()
		assert(typ != nil)
		pr.retireReader(r)
	}
	// See comment in pkgReader.typIdx explaining how this happens.
	if prev := *where; prev != nil {
		return prev
	}

	*where = typ
	return typ
}

func (r *reader) doTyp() (res types.Type) {
	switch tag := pkgbits.CodeType(r.Code(pkgbits.SyncType)); tag {
	default:
		errorf("unhandled type tag: %v", tag)
		panic("unreachable")

	case pkgbits.TypeBasic:
		return types.Typ[r.Len()]

	case pkgbits.TypeNamed:
		obj, targs := r.obj()
		name := obj.(*types.TypeName)
		if len(targs) != 0 {
			t, _ := types.Instantiate(r.p.ctxt, name.Type(), targs, false)
			return t
		}
		return name.Type()

	case pkgbits.TypeTypeParam:
		return r.dict.tparams[r.Len()]

	case pkgbits.TypeArray:
		len := int64(r.Uint64())
		return types.NewArray(r.typ(), len)
	case pkgbits.TypeChan:
		dir := types.ChanDir(r.Len())
		return types.NewChan(dir, r.typ())
	case pkgbits.TypeMap:
		return types.NewMap(r.typ(), r.typ())
	case pkgbits.TypePointer:
		return types.NewPointer(r.typ())
	case pkgbits.TypeSignature:
		return r.signature(nil, nil, nil)
	case pkgbits.TypeSlice:
		return types.NewSlice(r.typ())
	case pkgbits.TypeStruct:
		return r.structType()
	case pkgbits.TypeInterface:
		return r.interfaceType()
	case pkgbits.TypeUnion:
		return r.unionType()
	}
}

func (r *reader) structType() *types.Struct {
	fields := make([]*types.Var, r.Len())
	var tags []string
	for i := range fields {
		pos := r.pos()
		pkg, name := r.selector()
		ftyp := r.typ()
		tag := r.String()
		embedded := r.Bool()

		fields[i] = types.NewField(pos, pkg, name, ftyp, embedded)
		if tag != "" {
			for len(tags) < i {
				tags = append(tags, "")
			}
			tags = append(tags, tag)
		}
	}
	return types.NewStruct(fields, tags)
}

func (r *reader) unionType() *types.Union {
	terms := make([]*types.Term, r.Len())
	for i := range terms {
		terms[i] = types.NewTerm(r.Bool(), r.typ())
	}
	return types.NewUnion(terms)
}

func (r *reader) interfaceType() *types.Interface {
	methods := make([]*types.Func, r.Len())
	embeddeds := make([]types.Type, r.Len())
	implicit := len(methods) == 0 && len(embeddeds) == 1 && r.Bool()

	for i := range methods {
		pos := r.pos()
		pkg, name := r.selector()
		mtyp := r.signature(nil, nil, nil)
		methods[i] = types.NewFunc(pos, pkg, name, mtyp)
	}

	for i := range embeddeds {
		embeddeds[i] = r.typ()
	}

	iface := types.NewInterfaceType(methods, embeddeds)
	if implicit {
		iface.MarkImplicit()
	}

	// We need to call iface.Complete(), but if there are any embedded
	// defined types, then we may not have set their underlying
	// interface type yet. So we need to defer calling Complete until
	// after we've called SetUnderlying everywhere.
	//
	// TODO(mdempsky): After CL 424876 lands, it should be safe to call
	// iface.Complete() immediately.
	r.p.ifaces = append(r.p.ifaces, iface)

	return iface
}

func (r *reader) signature(recv *types.Var, rtparams, tparams []*types.TypeParam) *types.Signature {
	r.Sync(pkgbits.SyncSignature)

	params := r.params()
	results := r.params()
	variadic := r.Bool()

	return types.NewSignatureType(recv, rtparams, tparams, params, results, variadic)
}

func (r *reader) params() *types.Tuple {
	r.Sync(pkgbits.SyncParams)

	params := make([]*types.Var, r.Len())
	for i := range params {
		params[i] = r.param()
	}

	return types.NewTuple(params...)
}

func (r *reader) param() *types.Var {
	r.Sync(pkgbits.SyncParam)

	pos := r.pos()
	pkg, name := r.localIdent()
	typ := r.typ()

	return types.NewParam(pos, pkg, name, typ)
}

// @@@ Objects

func (r *reader) obj() (types.Object, []types.Type) {
	r.Sync(pkgbits.SyncObject)

	if r.Version().Has(pkgbits.DerivedFuncInstance) {
		assert(!r.Bool())
	}

	pkg, name := r.p.objIdx(r.Reloc(pkgbits.RelocObj))
	obj := pkgScope(pkg).Lookup(name)

	targs := make([]types.Type, r.Len())
	for i := range targs {
		targs[i] = r.typ()
	}

	return obj, targs
}

func (pr *pkgReader) objIdx(idx pkgbits.Index) (*types.Package, string) {

	var objPkg *types.Package
	var objName string
	var tag pkgbits.CodeObj
	{
		rname := pr.tempReader(pkgbits.RelocName, idx, pkgbits.SyncObject1)

		objPkg, objName = rname.qualifiedIdent()
		assert(objName != "")

		tag = pkgbits.CodeObj(rname.Code(pkgbits.SyncCodeObj))
		pr.retireReader(rname)
	}

	if tag == pkgbits.ObjStub {
		assert(objPkg == nil || objPkg == types.Unsafe)
		return objPkg, objName
	}

	// Ignore local types promoted to global scope (#55110).
	if _, suffix := splitVargenSuffix(objName); suffix != "" {
		return objPkg, objName
	}

	if objPkg.Scope().Lookup(objName) == nil {
		dict := pr.objDictIdx(idx)

		r := pr.newReader(pkgbits.RelocObj, idx, pkgbits.SyncObject1)
		r.dict = dict

		declare := func(obj types.Object) {
			objPkg.Scope().Insert(obj)
		}

		switch tag {
		default:
			panic("weird")

		case pkgbits.ObjAlias:
			pos := r.pos()
			var tparams []*types.TypeParam
			if r.Version().Has(pkgbits.AliasTypeParamNames) {
				tparams = r.typeParamNames()
			}
			typ := r.typ()
			declare(newAliasTypeName(pos, objPkg, objName, typ, tparams))

		case pkgbits.ObjConst:
			pos := r.pos()
			typ := r.typ()
			val := r.Value()
			declare(types.NewConst(pos, objPkg, objName, typ, val))

		case pkgbits.ObjFunc:
			pos := r.pos()
			tparams := r.typeParamNames()
			sig := r.signature(nil, nil, tparams)
			declare(types.NewFunc(pos, objPkg, objName, sig))

		case pkgbits.ObjType:
			pos := r.pos()

			obj := types.NewTypeName(pos, objPkg, objName, nil)
			named := types.NewNamed(obj, nil, nil)
			declare(obj)

			named.SetTypeParams(r.typeParamNames())

			underlying := r.typ().Underlying()

			// If the underlying type is an interface, we need to
			// duplicate its methods so we can replace the receiver
			// parameter's type (#49906).
			if iface, ok := underlying.(*types.Interface); ok && iface.NumExplicitMethods() != 0 {
				methods := make([]*types.Func, iface.NumExplicitMethods())
				for i := range methods {
					fn := iface.ExplicitMethod(i)
					sig := fn.Type().(*types.Signature)

					recv := types.NewVar(fn.Pos(), fn.Pkg(), "", named)
					methods[i] = types.NewFunc(fn.Pos(), fn.Pkg(), fn.Name(), types.NewSignature(recv, sig.Params(), sig.Results(), sig.Variadic()))
				}

				embeds := make([]types.Type, iface.NumEmbeddeds())
				for i := range embeds {
					embeds[i] = iface.EmbeddedType(i)
				}

				newIface := types.NewInterfaceType(methods, embeds)
				r.p.ifaces = append(r.p.ifaces, newIface)
				underlying = newIface
			}

			named.SetUnderlying(underlying)

			for i, n := 0, r.Len(); i < n; i++ {
				named.AddMethod(r.method())
			}

		case pkgbits.ObjVar:
			pos := r.pos()
			typ := r.typ()
			declare(types.NewVar(pos, objPkg, objName, typ))
		}
	}

	return objPkg, objName
}

func (pr *pkgReader) objDictIdx(idx pkgbits.Index) *readerDict {

	var dict readerDict

	{
		r := pr.tempReader(pkgbits.RelocObjDict, idx, pkgbits.SyncObject1)
		if implicits := r.Len(); implicits != 0 {
			errorf("unexpected object with %v implicit type parameter(s)", implicits)
		}

		dict.bounds = make([]typeInfo, r.Len())
		for i := range dict.bounds {
			dict.bounds[i] = r.typInfo()
		}

		dict.derived = make([]derivedInfo, r.Len())
		dict.derivedTypes = make([]types.Type, len(dict.derived))
		for i := range dict.derived {
			dict.derived[i] = derivedInfo{idx: r.Reloc(pkgbits.RelocType)}
			if r.Version().Has(pkgbits.DerivedInfoNeeded) {
				assert(!r.Bool())
			}
		}

		pr.retireReader(r)
	}
	// function references follow, but reader doesn't need those

	return &dict
}

func (r *reader) typeParamNames() []*types.TypeParam {
	r.Sync(pkgbits.SyncTypeParamNames)

	// Note: This code assumes it only processes objects without
	// implement type parameters. This is currently fine, because
	// reader is only used to read in exported declarations, which are
	// always package scoped.

	if len(r.dict.bounds) == 0 {
		return nil
	}

	// Careful: Type parameter lists may have cycles. To allow for this,
	// we construct the type parameter list in two passes: first we
	// create all the TypeNames and TypeParams, then we construct and
	// set the bound type.

	r.dict.tparams = make([]*types.TypeParam, len(r.dict.bounds))
	for i := range r.dict.bounds {
		pos := r.pos()
		pkg, name := r.localIdent()

		tname := types.NewTypeName(pos, pkg, name, nil)
		r.dict.tparams[i] = types.NewTypeParam(tname, nil)
	}

	typs := make([]types.Type, len(r.dict.bounds))
	for i, bound := range r.dict.bounds {
		typs[i] = r.p.typIdx(bound, r.dict)
	}

	// TODO(mdempsky): This is subtle, elaborate further.
	//
	// We have to save tparams outside of the closure, because
	// typeParamNames() can be called multiple times with the same
	// dictionary instance.
	//
	// Also, this needs to happen later to make sure SetUnderlying has
	// been called.
	//
	// TODO(mdempsky): Is it safe to have a single "later" slice or do
	// we need to have multiple passes? See comments on CL 386002 and
	// go.dev/issue/52104.
	tparams := r.dict.tparams
	r.p.later(func() {
		for i, typ := range typs {
			tparams[i].SetConstraint(typ)
		}
	})

	return r.dict.tparams
}

func (r *reader) method() *types.Func {
	r.Sync(pkgbits.SyncMethod)
	pos := r.pos()
	pkg, name := r.selector()

	rparams := r.typeParamNames()
	sig := r.signature(r.param(), rparams, nil)

	_ = r.pos() // TODO(mdempsky): Remove; this is a hacker for linker.go.
	return types.NewFunc(pos, pkg, name, sig)
}

func (r *reader) qualifiedIdent() (*types.Package, string) { return r.ident(pkgbits.SyncSym) }
func (r *reader) localIdent() (*types.Package, string)     { return r.ident(pkgbits.SyncLocalIdent) }
func (r *reader) selector() (*types.Package, string)       { return r.ident(pkgbits.SyncSelector) }

func (r *reader) ident(marker pkgbits.SyncMarker) (*types.Package, string) {
	r.Sync(marker)
	return r.pkg(), r.String()
}

// pkgScope returns pkg.Scope().
// If pkg is nil, it returns types.Universe instead.
//
// TODO(mdempsky): Remove after x/tools can depend on Go 1.19.
func pkgScope(pkg *types.Package) *types.Scope {
	if pkg != nil {
		return pkg.Scope()
	}
	return types.Universe
}

// newAliasTypeName returns a new TypeName, with a materialized *types.Alias if supported.
func newAliasTypeName(pos token.Pos, pkg *types.Package, name string, rhs types.Type, tparams []*types.TypeParam) *types.TypeName {
	// When GODEBUG=gotypesalias=1 or unset, the Type() of the return value is a
	// *types.Alias. Copied from x/tools/internal/aliases.NewAlias.
	switch godebug.New("gotypesalias").Value() {
	case "", "1":
		tname := types.NewTypeName(pos, pkg, name, nil)
		a := types.NewAlias(tname, rhs) // form TypeName -> Alias cycle
		a.SetTypeParams(tparams)
		return tname
	}
	assert(len(tparams) == 0)
	return types.NewTypeName(pos, pkg, name, rhs)
}
```