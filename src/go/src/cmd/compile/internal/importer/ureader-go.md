Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The initial comment `package importer implements package reading for gc-generated object files` is the most crucial starting point. This immediately tells us this code is about *reading* compiled Go code (object files) to understand its structure and types. The `gc` likely refers to the standard Go compiler.

2. **Look for Key Data Structures:**  The `pkgReader` struct is central. Its fields provide clues about what information is being read:
    * `pkgbits.PkgDecoder`:  Suggests interaction with a lower-level format for storing package information. `pkgbits` is a strong indicator of the format.
    * `ctxt *types2.Context`:  Indicates interaction with the `types2` package, which is Go's type checker and representation.
    * `imports map[string]*types2.Package`:  Clearly manages imported packages.
    * `enableAlias bool`:  Suggests handling type aliases.
    * `posBases []*syntax.PosBase`:  Related to source code positions.
    * `pkgs []*types2.Package`, `typs []types2.Type`:  Store loaded package and type information.

3. **Analyze Key Functions:**  `ReadPackage` seems like the main entry point. Its arguments (`ctxt`, `imports`, `input pkgbits.PkgDecoder`) confirm the reading purpose and connection to the `types2` package. The logic inside `ReadPackage` reveals the steps involved in reading:
    * Initialization of `pkgReader`.
    * Reading metadata using `pr.newReader(pkgbits.RelocMeta, ...)`.
    * Looping through objects within the package.
    * Marking the package as complete.

4. **Examine Supporting Structures and Functions:**
    * `reader`: Seems like a helper for reading specific parts of the `pkgbits` stream.
    * `readerDict`:  Likely holds temporary dictionaries of type information.
    * Functions prefixed with `@@@` like `pos`, `posBase`, `pkg`, `typ`, `obj`:  These clearly handle reading specific elements like source positions, packages, types, and objects. The `Reloc...` constants passed to `newReader` and `NewDecoder` suggest different categories of data within the object file.

5. **Connect the Dots and Infer Functionality:** Based on the names and types, we can start connecting the pieces:
    * The code reads information from `pkgbits.PkgDecoder`, which likely represents the binary format of a compiled Go package.
    * It uses this information to populate `types2` data structures, representing the Go package's type information, including its declared types, functions, variables, and imports.
    * The `types2.Context` and `imports` map help resolve type references across packages.

6. **Formulate the Main Functionality Summary:** Based on the above analysis, the primary function is reading compiled Go package information from object files and constructing an in-memory representation using the `types2` package. This is essential for type checking and other static analysis tools.

7. **Infer Specific Go Features:**  As we delve deeper into functions like `doTyp` and the handling of different `pkgbits.CodeType` values, we can start to identify the Go language features being represented:
    * `TypeBasic`: Basic types like `int`, `string`, `bool`.
    * `TypeNamed`: Named types (structs, interfaces, etc.).
    * `TypeTypeParam`: Generics (type parameters).
    * `TypeArray`, `TypeChan`, `TypeMap`, `TypePointer`, `TypeSignature`, `TypeSlice`, `TypeStruct`, `TypeInterface`, `TypeUnion`:  Core Go type constructs.
    * `ObjAlias`: Type aliases.
    * `ObjConst`, `ObjFunc`, `ObjType`, `ObjVar`: Different kinds of package-level declarations.

8. **Construct Code Examples:** Once the features are identified, creating illustrative Go code examples becomes possible. For instance, seeing `TypeStruct` and the logic around fields leads to a struct example. `ObjFunc` and `TypeSignature` point to function examples. The presence of `TypeTypeParam` strongly suggests generics.

9. **Consider Command-Line Arguments:** Since this code is part of the compiler (`cmd/compile`), it's reasonable to assume it doesn't directly process user-provided command-line arguments. Instead, it receives the compiled package data as input.

10. **Identify Potential Pitfalls:** Look for areas where assumptions are made or where the code handles potential variations:
    * The handling of the "builtin" package as a special case.
    * The lazy loading of object information using `InsertLazy`.
    * The handling of type parameter constraints.
    * The note about potential cycles in type parameter lists.

11. **Refine and Organize:**  Finally, organize the findings into a clear and structured response, addressing each part of the prompt. Use clear language and provide concise explanations.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this is about *writing* object files. *Correction:* The package name `importer` and the function `ReadPackage` strongly suggest reading.
* **Confusion about `pkgbits`:**  Initially, the purpose of `pkgbits` might be unclear. *Refinement:* Realizing it's a separate package within the Go toolchain for representing the compiled package format clarifies its role.
* **Overlooking the `@@@` markers:**  Initially, these might seem like comments. *Correction:* Recognizing they delineate sections for different kinds of data (positions, packages, types, objects) helps in understanding the code's organization.
* **Not immediately recognizing `types2`:**  If unfamiliar with the Go compiler internals, `types2` might not be immediately obvious. *Refinement:* Recognizing the context within `cmd/compile` and searching for `types2` will reveal its role in type checking.

By following these steps, moving from the general purpose to specific details, and continually connecting the pieces, we can effectively analyze and understand the functionality of this Go code snippet.
这段代码是Go语言编译器 `cmd/compile` 的一部分，位于 `internal/importer` 包中，专门负责从编译器生成的**目标文件（object files）中读取包的信息**。它的核心功能是将编译后的二进制表示转换回 Go 语言的类型系统表示，以便进行类型检查、代码生成等后续操作。

**主要功能:**

1. **读取包的元数据 (Metadata):** `ReadPackage` 函数是入口，它接收一个 `types2.Context` (类型检查上下文)、一个已导入包的 map 和一个 `pkgbits.PkgDecoder` (用于解码目标文件内容)，并返回一个 `types2.Package` 对象。这个函数主要负责读取包的名称、导入的包列表等基本信息。

2. **读取源文件位置信息 (Positions):**  代码中定义了与位置相关的函数，如 `pos()`, `posBase()`, `posBaseIdx()`, 这些函数用于从目标文件中读取并重建源代码的位置信息，这对于错误报告和调试非常重要。

3. **读取包信息 (Packages):** `pkg()`, `pkgIdx()`, `doPkg()` 等函数用于读取目标文件中关于包的定义信息，包括包的路径、名称以及它所导入的其他包。

4. **读取类型信息 (Types):**  这是最核心的功能之一。`typ()`, `typInfo()`, `typIdx()`, `doTyp()` 以及各种具体的类型读取函数 (如 `structType()`, `interfaceType()`, `signature()`) 负责从目标文件中解码各种 Go 语言类型，包括基本类型、命名类型、类型参数（泛型）、数组、切片、指针、函数签名、结构体、接口、联合类型等。

5. **读取对象信息 (Objects):** `obj()`, `objIdx()`, `objDictIdx()` 等函数用于读取包中定义的各种对象，例如常量 (`ObjConst`)、函数 (`ObjFunc`)、类型 (`ObjType`) 和变量 (`ObjVar`)。对于类型，它还会读取类型的方法。

6. **处理类型别名 (Type Aliases):** `newAliasTypeName` 函数负责创建类型别名的 `types2.TypeName` 对象。`enableAlias` 字段控制是否启用别名处理。

**它是什么Go语言功能的实现？**

这段代码是 Go 语言**包导入机制**的核心实现之一。 当编译器在编译一个包时遇到 `import` 声明时，它需要读取被导入包的编译结果（目标文件）来获取该包提供的类型和对象信息。`ureader.go` 中的代码就是负责完成这个读取过程，将目标文件中的二进制数据还原成 Go 语言的类型系统表示。

**Go 代码举例说明:**

假设我们有两个 Go 源文件，`mypkg/mypkg.go`:

```go
package mypkg

type MyInt int

func Add(a, b MyInt) MyInt {
	return a + b
}
```

以及 `main.go`:

```go
package main

import "mypkg"
import "fmt"

func main() {
	var x mypkg.MyInt = 10
	var y mypkg.MyInt = 20
	sum := mypkg.Add(x, y)
	fmt.Println(sum)
}
```

当编译 `main.go` 时，编译器会执行以下步骤（简化）：

1. 遇到 `import "mypkg"`，编译器会查找 `mypkg` 的目标文件（通常是 `mypkg.o` 或类似的）。
2. `ureader.go` 中的 `ReadPackage` 函数会被调用，传入类型检查上下文、已导入的包信息以及用于读取 `mypkg` 目标文件的 `pkgbits.PkgDecoder`。
3. `ureader.go` 会从目标文件中读取 `mypkg` 的元数据（包名等）。
4. `ureader.go` 会读取 `mypkg` 中定义的类型信息，例如 `MyInt` 是一个 `int` 的别名。
5. `ureader.go` 会读取 `mypkg` 中定义的对象信息，例如 `Add` 函数的签名。
6. 这些读取到的信息会被转换成 `types2.Package` 对象，其中包含了 `mypkg` 的类型和对象定义。
7. 编译器使用这些信息来检查 `main.go` 中对 `mypkg.MyInt` 和 `mypkg.Add` 的使用是否正确。

**代码推理 (假设的输入与输出):**

假设 `mypkg.o` 目标文件中包含了以下简化后的信息：

* **包路径:** "mypkg"
* **包名:** "mypkg"
* **定义了一个类型别名:** `MyInt` -> `int`
* **定义了一个函数:**
    * **名称:** `Add`
    * **参数:** `a` (类型 `MyInt`), `b` (类型 `MyInt`)
    * **返回值:** `MyInt`

**输入 (简化):** 一个指向 `mypkg.o` 目标文件内容的 `pkgbits.PkgDecoder` 实例。

**输出:** 一个 `types2.Package` 对象，其关键属性如下：

```go
&types2.Package{
    path:     "mypkg",
    name:     "mypkg",
    scope: &types2.Scope{
        // ... 其他对象 ...
        "MyInt": &types2.TypeName{
            name: "MyInt",
            // ... 其他属性 ...
            // 可能包含一个指向 int 类型的 Alias 对象
        },
        "Add": &types2.Func{
            name: "Add",
            // ... 其他属性 ...
            sig: &types2.Signature{
                // ... 参数和返回值类型信息，会引用到 MyInt 的 types2.TypeName
            },
        },
    },
    // ... 其他属性，例如导入的包列表 ...
}
```

**命令行参数的具体处理:**

`ureader.go` 本身并不直接处理命令行参数。它是编译器内部的一个模块，由编译器的其他部分调用。当 `go build` 或 `go compile` 命令执行时，编译器会解析命令行参数，确定需要编译的包，然后读取这些包依赖的其他包的目标文件，此时会用到 `ureader.go` 中的功能。

**使用者易犯错的点:**

作为编译器内部的代码，普通 Go 开发者不会直接使用 `ureader.go` 中的函数。然而，理解其背后的原理有助于理解 Go 的编译过程。

对于编译器开发者而言，使用 `pkgbits` 和 `types2` 包进行目标文件读写和类型系统操作时，容易犯以下错误（尽管这些不是直接使用 `ureader.go` 引起的）：

* **目标文件格式理解不透彻:** `pkgbits` 定义了目标文件的二进制格式，如果对其理解不足，可能会导致读取错误或数据解析错误。
* **类型系统操作错误:** `types2` 包提供了丰富的类型操作方法，但使用不当可能导致类型信息不完整或不正确。例如，在处理泛型类型时，需要正确处理类型参数和约束。
* **同步标记错误:** `pkgbits` 使用同步标记 (`Sync...`) 来确保读写过程的同步，如果同步标记使用错误，可能导致数据流错乱。

总而言之，`ureader.go` 是 Go 编译器中一个至关重要的组成部分，它负责将编译后的包信息反序列化为 Go 语言的类型系统表示，为后续的编译阶段提供必要的类型信息。理解其功能有助于深入理解 Go 的编译原理。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/importer/ureader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// package importer implements package reading for gc-generated object files.
package importer

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/syntax"
	"cmd/compile/internal/types2"
	"cmd/internal/src"
	"internal/pkgbits"
)

type pkgReader struct {
	pkgbits.PkgDecoder

	ctxt        *types2.Context
	imports     map[string]*types2.Package
	enableAlias bool // whether to use aliases

	posBases []*syntax.PosBase
	pkgs     []*types2.Package
	typs     []types2.Type
}

func ReadPackage(ctxt *types2.Context, imports map[string]*types2.Package, input pkgbits.PkgDecoder) *types2.Package {
	pr := pkgReader{
		PkgDecoder: input,

		ctxt:        ctxt,
		imports:     imports,
		enableAlias: true,

		posBases: make([]*syntax.PosBase, input.NumElems(pkgbits.RelocPosBase)),
		pkgs:     make([]*types2.Package, input.NumElems(pkgbits.RelocPkg)),
		typs:     make([]types2.Type, input.NumElems(pkgbits.RelocType)),
	}

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

	pkg.MarkComplete()
	return pkg
}

type reader struct {
	pkgbits.Decoder

	p *pkgReader

	dict *readerDict
}

type readerDict struct {
	bounds []typeInfo

	tparams []*types2.TypeParam

	derived      []derivedInfo
	derivedTypes []types2.Type
}

type readerTypeBound struct {
	derived  bool
	boundIdx int
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

func (r *reader) pos() syntax.Pos {
	r.Sync(pkgbits.SyncPos)
	if !r.Bool() {
		return syntax.Pos{}
	}

	// TODO(mdempsky): Delta encoding.
	posBase := r.posBase()
	line := r.Uint()
	col := r.Uint()
	return syntax.MakePos(posBase, line, col)
}

func (r *reader) posBase() *syntax.PosBase {
	return r.p.posBaseIdx(r.Reloc(pkgbits.RelocPosBase))
}

func (pr *pkgReader) posBaseIdx(idx pkgbits.Index) *syntax.PosBase {
	if b := pr.posBases[idx]; b != nil {
		return b
	}
	var b *syntax.PosBase
	{
		r := pr.tempReader(pkgbits.RelocPosBase, idx, pkgbits.SyncPosBase)

		filename := r.String()

		if r.Bool() {
			b = syntax.NewTrimmedFileBase(filename, true)
		} else {
			pos := r.pos()
			line := r.Uint()
			col := r.Uint()
			b = syntax.NewLineBase(pos, filename, true, line, col)
		}
		pr.retireReader(r)
	}

	pr.posBases[idx] = b
	return b
}

// @@@ Packages

func (r *reader) pkg() *types2.Package {
	r.Sync(pkgbits.SyncPkg)
	return r.p.pkgIdx(r.Reloc(pkgbits.RelocPkg))
}

func (pr *pkgReader) pkgIdx(idx pkgbits.Index) *types2.Package {
	// TODO(mdempsky): Consider using some non-nil pointer to indicate
	// the universe scope, so we don't need to keep re-reading it.
	if pkg := pr.pkgs[idx]; pkg != nil {
		return pkg
	}

	pkg := pr.newReader(pkgbits.RelocPkg, idx, pkgbits.SyncPkgDef).doPkg()
	pr.pkgs[idx] = pkg
	return pkg
}

func (r *reader) doPkg() *types2.Package {
	path := r.String()
	switch path {
	case "":
		path = r.p.PkgPath()
	case "builtin":
		return nil // universe
	case "unsafe":
		return types2.Unsafe
	}

	if pkg := r.p.imports[path]; pkg != nil {
		return pkg
	}

	name := r.String()
	pkg := types2.NewPackage(path, name)
	r.p.imports[path] = pkg

	// TODO(mdempsky): The list of imported packages is important for
	// go/types, but we could probably skip populating it for types2.
	imports := make([]*types2.Package, r.Len())
	for i := range imports {
		imports[i] = r.pkg()
	}
	pkg.SetImports(imports)

	return pkg
}

// @@@ Types

func (r *reader) typ() types2.Type {
	return r.p.typIdx(r.typInfo(), r.dict)
}

func (r *reader) typInfo() typeInfo {
	r.Sync(pkgbits.SyncType)
	if r.Bool() {
		return typeInfo{idx: pkgbits.Index(r.Len()), derived: true}
	}
	return typeInfo{idx: r.Reloc(pkgbits.RelocType), derived: false}
}

func (pr *pkgReader) typIdx(info typeInfo, dict *readerDict) types2.Type {
	idx := info.idx
	var where *types2.Type
	if info.derived {
		where = &dict.derivedTypes[idx]
		idx = dict.derived[idx].idx
	} else {
		where = &pr.typs[idx]
	}

	if typ := *where; typ != nil {
		return typ
	}

	var typ types2.Type
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

func (r *reader) doTyp() (res types2.Type) {
	switch tag := pkgbits.CodeType(r.Code(pkgbits.SyncType)); tag {
	default:
		base.FatalfAt(src.NoXPos, "unhandled type tag: %v", tag)
		panic("unreachable")

	case pkgbits.TypeBasic:
		return types2.Typ[r.Len()]

	case pkgbits.TypeNamed:
		obj, targs := r.obj()
		name := obj.(*types2.TypeName)
		if len(targs) != 0 {
			t, _ := types2.Instantiate(r.p.ctxt, name.Type(), targs, false)
			return t
		}
		return name.Type()

	case pkgbits.TypeTypeParam:
		return r.dict.tparams[r.Len()]

	case pkgbits.TypeArray:
		len := int64(r.Uint64())
		return types2.NewArray(r.typ(), len)
	case pkgbits.TypeChan:
		dir := types2.ChanDir(r.Len())
		return types2.NewChan(dir, r.typ())
	case pkgbits.TypeMap:
		return types2.NewMap(r.typ(), r.typ())
	case pkgbits.TypePointer:
		return types2.NewPointer(r.typ())
	case pkgbits.TypeSignature:
		return r.signature(nil, nil, nil)
	case pkgbits.TypeSlice:
		return types2.NewSlice(r.typ())
	case pkgbits.TypeStruct:
		return r.structType()
	case pkgbits.TypeInterface:
		return r.interfaceType()
	case pkgbits.TypeUnion:
		return r.unionType()
	}
}

func (r *reader) structType() *types2.Struct {
	fields := make([]*types2.Var, r.Len())
	var tags []string
	for i := range fields {
		pos := r.pos()
		pkg, name := r.selector()
		ftyp := r.typ()
		tag := r.String()
		embedded := r.Bool()

		fields[i] = types2.NewField(pos, pkg, name, ftyp, embedded)
		if tag != "" {
			for len(tags) < i {
				tags = append(tags, "")
			}
			tags = append(tags, tag)
		}
	}
	return types2.NewStruct(fields, tags)
}

func (r *reader) unionType() *types2.Union {
	terms := make([]*types2.Term, r.Len())
	for i := range terms {
		terms[i] = types2.NewTerm(r.Bool(), r.typ())
	}
	return types2.NewUnion(terms)
}

func (r *reader) interfaceType() *types2.Interface {
	methods := make([]*types2.Func, r.Len())
	embeddeds := make([]types2.Type, r.Len())
	implicit := len(methods) == 0 && len(embeddeds) == 1 && r.Bool()

	for i := range methods {
		pos := r.pos()
		pkg, name := r.selector()
		mtyp := r.signature(nil, nil, nil)
		methods[i] = types2.NewFunc(pos, pkg, name, mtyp)
	}

	for i := range embeddeds {
		embeddeds[i] = r.typ()
	}

	iface := types2.NewInterfaceType(methods, embeddeds)
	if implicit {
		iface.MarkImplicit()
	}
	return iface
}

func (r *reader) signature(recv *types2.Var, rtparams, tparams []*types2.TypeParam) *types2.Signature {
	r.Sync(pkgbits.SyncSignature)

	params := r.params()
	results := r.params()
	variadic := r.Bool()

	return types2.NewSignatureType(recv, rtparams, tparams, params, results, variadic)
}

func (r *reader) params() *types2.Tuple {
	r.Sync(pkgbits.SyncParams)
	params := make([]*types2.Var, r.Len())
	for i := range params {
		params[i] = r.param()
	}
	return types2.NewTuple(params...)
}

func (r *reader) param() *types2.Var {
	r.Sync(pkgbits.SyncParam)

	pos := r.pos()
	pkg, name := r.localIdent()
	typ := r.typ()

	return types2.NewParam(pos, pkg, name, typ)
}

// @@@ Objects

func (r *reader) obj() (types2.Object, []types2.Type) {
	r.Sync(pkgbits.SyncObject)

	if r.Version().Has(pkgbits.DerivedFuncInstance) {
		assert(!r.Bool())
	}

	pkg, name := r.p.objIdx(r.Reloc(pkgbits.RelocObj))
	obj := pkg.Scope().Lookup(name)

	targs := make([]types2.Type, r.Len())
	for i := range targs {
		targs[i] = r.typ()
	}

	return obj, targs
}

func (pr *pkgReader) objIdx(idx pkgbits.Index) (*types2.Package, string) {
	var objPkg *types2.Package
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
		base.Assertf(objPkg == nil || objPkg == types2.Unsafe, "unexpected stub package: %v", objPkg)
		return objPkg, objName
	}

	objPkg.Scope().InsertLazy(objName, func() types2.Object {
		dict := pr.objDictIdx(idx)

		r := pr.newReader(pkgbits.RelocObj, idx, pkgbits.SyncObject1)
		r.dict = dict

		switch tag {
		default:
			panic("weird")

		case pkgbits.ObjAlias:
			pos := r.pos()
			var tparams []*types2.TypeParam
			if r.Version().Has(pkgbits.AliasTypeParamNames) {
				tparams = r.typeParamNames()
			}
			typ := r.typ()
			return newAliasTypeName(pr.enableAlias, pos, objPkg, objName, typ, tparams)

		case pkgbits.ObjConst:
			pos := r.pos()
			typ := r.typ()
			val := r.Value()
			return types2.NewConst(pos, objPkg, objName, typ, val)

		case pkgbits.ObjFunc:
			pos := r.pos()
			tparams := r.typeParamNames()
			sig := r.signature(nil, nil, tparams)
			return types2.NewFunc(pos, objPkg, objName, sig)

		case pkgbits.ObjType:
			pos := r.pos()

			return types2.NewTypeNameLazy(pos, objPkg, objName, func(named *types2.Named) (tparams []*types2.TypeParam, underlying types2.Type, methods []*types2.Func) {
				tparams = r.typeParamNames()

				// TODO(mdempsky): Rewrite receiver types to underlying is an
				// Interface? The go/types importer does this (I think because
				// unit tests expected that), but cmd/compile doesn't care
				// about it, so maybe we can avoid worrying about that here.
				underlying = r.typ().Underlying()

				methods = make([]*types2.Func, r.Len())
				for i := range methods {
					methods[i] = r.method()
				}

				return
			})

		case pkgbits.ObjVar:
			pos := r.pos()
			typ := r.typ()
			return types2.NewVar(pos, objPkg, objName, typ)
		}
	})

	return objPkg, objName
}

func (pr *pkgReader) objDictIdx(idx pkgbits.Index) *readerDict {
	var dict readerDict
	{
		r := pr.tempReader(pkgbits.RelocObjDict, idx, pkgbits.SyncObject1)

		if implicits := r.Len(); implicits != 0 {
			base.Fatalf("unexpected object with %v implicit type parameter(s)", implicits)
		}

		dict.bounds = make([]typeInfo, r.Len())
		for i := range dict.bounds {
			dict.bounds[i] = r.typInfo()
		}

		dict.derived = make([]derivedInfo, r.Len())
		dict.derivedTypes = make([]types2.Type, len(dict.derived))
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

func (r *reader) typeParamNames() []*types2.TypeParam {
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

	r.dict.tparams = make([]*types2.TypeParam, len(r.dict.bounds))
	for i := range r.dict.bounds {
		pos := r.pos()
		pkg, name := r.localIdent()

		tname := types2.NewTypeName(pos, pkg, name, nil)
		r.dict.tparams[i] = types2.NewTypeParam(tname, nil)
	}

	for i, bound := range r.dict.bounds {
		r.dict.tparams[i].SetConstraint(r.p.typIdx(bound, r.dict))
	}

	return r.dict.tparams
}

func (r *reader) method() *types2.Func {
	r.Sync(pkgbits.SyncMethod)
	pos := r.pos()
	pkg, name := r.selector()

	rtparams := r.typeParamNames()
	sig := r.signature(r.param(), rtparams, nil)

	_ = r.pos() // TODO(mdempsky): Remove; this is a hacker for linker.go.
	return types2.NewFunc(pos, pkg, name, sig)
}

func (r *reader) qualifiedIdent() (*types2.Package, string) { return r.ident(pkgbits.SyncSym) }
func (r *reader) localIdent() (*types2.Package, string)     { return r.ident(pkgbits.SyncLocalIdent) }
func (r *reader) selector() (*types2.Package, string)       { return r.ident(pkgbits.SyncSelector) }

func (r *reader) ident(marker pkgbits.SyncMarker) (*types2.Package, string) {
	r.Sync(marker)
	return r.pkg(), r.String()
}

// newAliasTypeName returns a new TypeName, with a materialized *types2.Alias if supported.
func newAliasTypeName(aliases bool, pos syntax.Pos, pkg *types2.Package, name string, rhs types2.Type, tparams []*types2.TypeParam) *types2.TypeName {
	// Copied from x/tools/internal/aliases.NewAlias via
	// GOROOT/src/go/internal/gcimporter/ureader.go.
	if aliases {
		tname := types2.NewTypeName(pos, pkg, name, nil)
		a := types2.NewAlias(tname, rhs) // form TypeName -> Alias cycle
		a.SetTypeParams(tparams)
		return tname
	}
	assert(len(tparams) == 0)
	return types2.NewTypeName(pos, pkg, name, rhs)
}

"""



```