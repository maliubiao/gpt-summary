Response: My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided Go code snippet, located at `go/src/cmd/compile/internal/noder/reader.go`. It also asks for specific details like the Go feature it implements (if inferable), examples, command-line argument handling (if any), and common mistakes (if any).

2. **Initial Code Scan (Keywords and Structure):** I quickly scan the code for key terms and structural elements. I see:
    * `package noder` -  Indicates this is part of the `noder` package within the Go compiler.
    * `import` statements -  Reveal dependencies on other compiler internals (`cmd/compile/internal/...`) and standard library packages. This strongly suggests this code is involved in the compilation process.
    * Struct definitions like `pkgReader`, `reader`, `readerDict`, `pkgReaderIndex` - These are the primary data structures. Their fields offer clues about their purpose.
    * Functions like `newPkgReader`, `newReader`, `pos`, `pkg`, `typ`, `obj`, `funcBody`, `stmt`, `expr` - These seem to be the core operations. The names are quite suggestive.
    * Comments like `// This file implements cmd/compile backend's reader for the Unified IR export data.` - This is a crucial piece of information directly stating the file's purpose.
    * The presence of `pkgbits` and `pkgDecoder` - Points towards reading a serialized representation of package information.
    * References to `ir.Node`, `types.Pkg`, `types.Type`, `types.Sym` - These are fundamental data structures in the Go compiler's intermediate representation (IR) and type system.

3. **Identify the Core Functionality (Based on Initial Scan):** The comments and function names strongly suggest this code is responsible for *reading* and *interpreting* a serialized representation of Go code. The term "Unified IR export data" is key. This implies that the compiler has previously *written* this data, and this code is responsible for *reading it back in*.

4. **Infer the Go Feature:** Given that it's reading an "export" format and deals with types, packages, functions, and other code elements, it's highly likely this code is part of the *import* process in Go. When the compiler needs to use code from a different package, it reads the exported information from that package's compiled output.

5. **Develop a High-Level Functional Summary:** Based on the above points, I formulate a summary like: "This Go code implements the reader for the Unified IR export data format within the Go compiler. It's responsible for deserializing the compiled representation of Go packages, including type information, function definitions, and other declarations, allowing the compiler to use code from imported packages."

6. **Dive Deeper into Key Structures and Functions:**  I examine the fields of the main structs and the logic of key functions to get a more granular understanding:
    * `pkgReader`:  Manages the overall reading process for a package, including indices for various elements.
    * `reader`: Handles reading individual elements (like types, expressions, statements) from the bitstream.
    * `readerDict`: Deals with type instantiation in the presence of generics.
    * Functions like `pos`, `pkg`, `typ`, `obj`: These clearly read position information, package references, type information, and object (variable, function, type) definitions, respectively.
    * Functions like `funcBody`, `stmt`, `expr`: These handle the deserialization of function bodies, statements, and expressions.

7. **Look for Specific Clues for Examples and Advanced Features:** I search for patterns that might indicate specific Go features being handled:
    * The presence of `readerDict` and related logic strongly points to the implementation of *generics* (type parameters, instantiation).
    * The `inl...` prefixes in field and function names suggest handling of *inlining*.
    * The `dwarfgen` import points towards the generation of *debugging information*.

8. **Construct Examples (Focusing on Generics):** Since generics are strongly suggested by the code, I devise a simple Go example that demonstrates the use of generics and how the compiler would need to read the exported information for the generic function. This involves defining a generic function and then instantiating it.

9. **Consider Command-Line Arguments:** I review the imports and function calls for any indications of command-line flag processing. While the provided snippet doesn't directly handle command-line arguments, I know from the import of `cmd/compile/internal/base` that the compiler framework uses flags. Therefore, I mention that this *reader* likely uses information derived from command-line flags but doesn't directly parse them itself.

10. **Identify Potential Pitfalls (Focusing on Generics and Type Resolution):**  I think about common issues developers might encounter related to the functionality being implemented. For the import process, especially with generics, a common mistake is incorrect or insufficient type information when instantiating generic types or functions. This leads to the "cannot use generic type without instantiation" error.

11. **Refine the Functional Summary:** Based on the deeper analysis, I refine the initial summary to be more precise and include the handling of generics, inlining, and the reading of a "Unified IR."

12. **Structure the Answer:** I organize the information into the requested sections: Functionality, Go Feature Implementation (with example), Code Reasoning (with assumptions, input, output), Command-Line Arguments, Common Mistakes, and a final concise summary.

By following this systematic approach, I can effectively analyze the code snippet, infer its purpose, identify relevant Go features, construct meaningful examples, and address the specific points raised in the request. The process involves both a high-level understanding of the compiler's architecture and a more detailed examination of the code's structure and logic.
好的，让我们来分析一下 `go/src/cmd/compile/internal/noder/reader.go` 的第一部分代码。

**功能归纳：**

这段代码是 Go 编译器后端 `cmd/compile` 中 `noder` 包的一部分，主要负责 **读取 (deserializing) 统一中间表示 (Unified IR) 的导出数据**。它定义了用于从字节流中读取 Go 代码编译产物的结构体和方法，以便编译器能够使用来自其他已编译包的信息。

**更详细的功能点：**

1. **核心结构体 `pkgReader` 和 `reader`:**
   - `pkgReader` 负责读取整个包的导出数据，维护了读取过程中的状态，例如位置信息、包信息、类型信息等。它内部使用了 `pkgbits.PkgDecoder` 来进行底层的 bitstream 解码。
   - `reader` 负责读取单个元素 (例如类型、对象、表达式、语句) 的信息。它基于 `pkgbits.Decoder`，并持有一个 `pkgReader` 的引用。

2. **延迟加载机制:** 代码中使用了 `// Indices for encoded things; lazily populated as needed.` 的注释，表明很多信息的读取是延迟的，只有在需要的时候才会被加载和解析。例如，类型 (`typs`) 和包 (`pkgs`) 的信息是通过索引来访问的，并在首次访问时通过 `pkgIdx` 和 `typIdx` 等函数进行加载。

3. **位置信息处理:**
   - 代码定义了 `posBases` 来存储位置信息的基础 (例如文件名)。
   - `pos()`, `origPos()`, `posBase()` 等函数用于从 bitstream 中读取并解析源代码的位置信息，包括处理内联 (inlining) 带来的位置调整。

4. **包信息处理:**
   - `pkg()` 和 `pkgIdx()` 函数用于读取和解析包的信息，包括包的路径和名称。

5. **类型信息处理:**
   - `typ()`, `typInfo()`, `typIdx()` 等函数用于读取和解析类型信息，支持基本类型、命名类型、类型参数、数组、channel、map、指针、函数签名、切片、结构体、接口和联合类型。
   - `readerDict` 结构体用于处理泛型类型实例化时的类型参数。

6. **对象信息处理:**
   - `objReader` 是一个全局 map，用于缓存已经读取过的对象信息。
   - `obj()`, `objInfo()`, `objInstIdx()`, `objIdx()` 等函数用于读取和解析各种 Go 语言对象的信息，例如常量、函数、类型、变量等。
   - 对泛型对象的实例化进行了特殊处理，涉及到 `readerDict` 的使用。

7. **编译器扩展信息处理:**
   - `funcExt()`, `typeExt()`, `varExt()`, `linkname()`, `pragmaFlag()` 等函数用于读取和解析 Go 编译器特有的扩展信息，例如函数的链接名称、编译指令等。

8. **函数体信息处理:**
   - `bodyReader` 和 `importBodyReader` 用于存储函数体的读取入口。
   - `addBody()` 和 `funcBody()` 函数用于读取和解析函数体的 IR。
   - 对泛型函数的函数体实例化进行了特殊处理，可能需要调用其对应的 "shaped" 版本。

9. **语句和表达式处理 (部分):**
   - 代码中定义了 `stmt()` 和 `stmts()` 来读取语句块。
   - `stmt1()` 函数根据不同的语句类型标签进行处理，例如赋值语句、分支语句、调用语句、循环语句、条件语句等。
   - `expr()` 函数开始处理表达式的读取，目前只实现了部分表达式类型的处理，例如本地变量、全局变量、常量、复合字面量、函数字面量、字段访问、方法值、方法表达式、索引、切片、类型断言、一元运算符、二元运算符、接收操作、调用等。

**推断的 Go 语言功能实现 (与代码推理)：**

基于代码的结构和使用的类型，可以推断这段代码主要负责实现 **Go 语言的包导入机制**，特别是处理包含了泛型的包的导入。它读取已编译的包信息，使得编译器能够理解和使用来自这些包的类型、函数、变量等。

**Go 代码示例：**

假设有一个名为 `mypackage` 的包，其中定义了一个泛型函数：

```go
// mypackage/mypackage.go
package mypackage

func Max[T comparable](a, b T) T {
	if a > b {
		return a
	}
	return b
}
```

另一个包想要使用 `mypackage.Max[int]`：

```go
// main.go
package main

import "mypackage"
import "fmt"

func main() {
	result := mypackage.Max[int](10, 5)
	fmt.Println(result) // Output: 10
}
```

当编译 `main.go` 时，编译器需要读取 `mypackage` 的导出数据。`reader.go` 中的代码就负责解析 `mypackage` 编译后导出的 IR 数据，其中包括 `Max` 函数的泛型信息。

**代码推理 (假设的输入与输出)：**

**假设输入：** `mypackage` 编译后的导出数据 (bitstream)，其中包含了 `Max` 函数的定义，以及它的泛型类型参数 `T` 和约束 `comparable`。

**`reader.go` 处理过程 (简化描述)：**

1. `newPkgReader` 创建一个 `pkgReader` 实例来处理 `mypackage` 的数据。
2. 当编译器遇到 `mypackage.Max[int]` 时，`obj()` 或相关的函数会被调用。
3. `objIdx()` 函数会查找 `Max` 的信息。由于是泛型函数，会涉及到 `readerDict` 的创建。
4. `objDictIdx()` 函数会读取 `Max` 函数的字典信息，包括类型参数 `T` 的信息。
5. 当需要实例化 `Max[int]` 时，`typIdx()` 会被调用来解析 `int` 类型。
6. `funcBody()` (如果需要) 会读取 `Max` 函数的 IR 代码。
7. 对于泛型函数，编译器可能会生成一个 "shaped" 的版本，`callShaped()` 可能会被用到。

**假设输出：**  编译器内部的 `ir.Func` 节点，代表 `mypackage.Max[int]` 的实例化版本，包含了它的类型信息 (`func(int, int) int`) 和 IR 代码。

**命令行参数的具体处理：**

这段代码本身**不直接处理命令行参数**。它接收的是已经准备好的 `pkgbits.PkgDecoder`，这个 decoder 的创建和初始化可能受到命令行参数的影响。

例如，编译器的 `-I` 参数指定了 import 路径，这会影响到 `mypackage` 导出数据的查找和加载。但是，`reader.go` 只是负责读取已经找到的数据。

**使用者易犯错的点：**

作为编译器内部的代码，普通 Go 开发者不会直接使用 `reader.go`。但是，理解其工作原理有助于理解 Go 的编译过程和包导入机制。

**这段代码的第一部分主要功能总结：**

这段代码实现了 Go 编译器后端中读取统一 IR 导出数据的核心功能。它定义了读取器结构体和方法，用于从字节流中反序列化包、类型、对象和部分语句表达式的信息，是 Go 语言包导入和泛型实现的关键组成部分。它通过延迟加载和索引机制高效地读取编译产物，为后续的编译阶段提供必要的信息。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/noder/reader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noder

import (
	"encoding/hex"
	"fmt"
	"go/constant"
	"internal/buildcfg"
	"internal/pkgbits"
	"path/filepath"
	"strings"

	"cmd/compile/internal/base"
	"cmd/compile/internal/dwarfgen"
	"cmd/compile/internal/inline"
	"cmd/compile/internal/inline/interleaved"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/objw"
	"cmd/compile/internal/reflectdata"
	"cmd/compile/internal/staticinit"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/hash"
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/src"
)

// This file implements cmd/compile backend's reader for the Unified
// IR export data.

// A pkgReader reads Unified IR export data.
type pkgReader struct {
	pkgbits.PkgDecoder

	// Indices for encoded things; lazily populated as needed.
	//
	// Note: Objects (i.e., ir.Names) are lazily instantiated by
	// populating their types.Sym.Def; see objReader below.

	posBases []*src.PosBase
	pkgs     []*types.Pkg
	typs     []*types.Type

	// offset for rewriting the given (absolute!) index into the output,
	// but bitwise inverted so we can detect if we're missing the entry
	// or not.
	newindex []index
}

func newPkgReader(pr pkgbits.PkgDecoder) *pkgReader {
	return &pkgReader{
		PkgDecoder: pr,

		posBases: make([]*src.PosBase, pr.NumElems(pkgbits.RelocPosBase)),
		pkgs:     make([]*types.Pkg, pr.NumElems(pkgbits.RelocPkg)),
		typs:     make([]*types.Type, pr.NumElems(pkgbits.RelocType)),

		newindex: make([]index, pr.TotalElems()),
	}
}

// A pkgReaderIndex compactly identifies an index (and its
// corresponding dictionary) within a package's export data.
type pkgReaderIndex struct {
	pr        *pkgReader
	idx       index
	dict      *readerDict
	methodSym *types.Sym

	synthetic func(pos src.XPos, r *reader)
}

func (pri pkgReaderIndex) asReader(k pkgbits.RelocKind, marker pkgbits.SyncMarker) *reader {
	if pri.synthetic != nil {
		return &reader{synthetic: pri.synthetic}
	}

	r := pri.pr.newReader(k, pri.idx, marker)
	r.dict = pri.dict
	r.methodSym = pri.methodSym
	return r
}

func (pr *pkgReader) newReader(k pkgbits.RelocKind, idx index, marker pkgbits.SyncMarker) *reader {
	return &reader{
		Decoder: pr.NewDecoder(k, idx, marker),
		p:       pr,
	}
}

// A reader provides APIs for reading an individual element.
type reader struct {
	pkgbits.Decoder

	p *pkgReader

	dict *readerDict

	// TODO(mdempsky): The state below is all specific to reading
	// function bodies. It probably makes sense to split it out
	// separately so that it doesn't take up space in every reader
	// instance.

	curfn       *ir.Func
	locals      []*ir.Name
	closureVars []*ir.Name

	// funarghack is used during inlining to suppress setting
	// Field.Nname to the inlined copies of the parameters. This is
	// necessary because we reuse the same types.Type as the original
	// function, and most of the compiler still relies on field.Nname to
	// find parameters/results.
	funarghack bool

	// methodSym is the name of method's name, if reading a method.
	// It's nil if reading a normal function or closure body.
	methodSym *types.Sym

	// dictParam is the .dict param, if any.
	dictParam *ir.Name

	// synthetic is a callback function to construct a synthetic
	// function body. It's used for creating the bodies of function
	// literals used to curry arguments to shaped functions.
	synthetic func(pos src.XPos, r *reader)

	// scopeVars is a stack tracking the number of variables declared in
	// the current function at the moment each open scope was opened.
	scopeVars         []int
	marker            dwarfgen.ScopeMarker
	lastCloseScopePos src.XPos

	// === details for handling inline body expansion ===

	// If we're reading in a function body because of inlining, this is
	// the call that we're inlining for.
	inlCaller    *ir.Func
	inlCall      *ir.CallExpr
	inlFunc      *ir.Func
	inlTreeIndex int
	inlPosBases  map[*src.PosBase]*src.PosBase

	// suppressInlPos tracks whether position base rewriting for
	// inlining should be suppressed. See funcLit.
	suppressInlPos int

	delayResults bool

	// Label to return to.
	retlabel *types.Sym
}

// A readerDict represents an instantiated "compile-time dictionary,"
// used for resolving any derived types needed for instantiating a
// generic object.
//
// A compile-time dictionary can either be "shaped" or "non-shaped."
// Shaped compile-time dictionaries are only used for instantiating
// shaped type definitions and function bodies, while non-shaped
// compile-time dictionaries are used for instantiating runtime
// dictionaries.
type readerDict struct {
	shaped bool // whether this is a shaped dictionary

	// baseSym is the symbol for the object this dictionary belongs to.
	// If the object is an instantiated function or defined type, then
	// baseSym is the mangled symbol, including any type arguments.
	baseSym *types.Sym

	// For non-shaped dictionaries, shapedObj is a reference to the
	// corresponding shaped object (always a function or defined type).
	shapedObj *ir.Name

	// targs holds the implicit and explicit type arguments in use for
	// reading the current object. For example:
	//
	//	func F[T any]() {
	//		type X[U any] struct { t T; u U }
	//		var _ X[string]
	//	}
	//
	//	var _ = F[int]
	//
	// While instantiating F[int], we need to in turn instantiate
	// X[string]. [int] and [string] are explicit type arguments for F
	// and X, respectively; but [int] is also the implicit type
	// arguments for X.
	//
	// (As an analogy to function literals, explicits are the function
	// literal's formal parameters, while implicits are variables
	// captured by the function literal.)
	targs []*types.Type

	// implicits counts how many of types within targs are implicit type
	// arguments; the rest are explicit.
	implicits int

	derived      []derivedInfo // reloc index of the derived type's descriptor
	derivedTypes []*types.Type // slice of previously computed derived types

	// These slices correspond to entries in the runtime dictionary.
	typeParamMethodExprs []readerMethodExprInfo
	subdicts             []objInfo
	rtypes               []typeInfo
	itabs                []itabInfo
}

type readerMethodExprInfo struct {
	typeParamIdx int
	method       *types.Sym
}

func setType(n ir.Node, typ *types.Type) {
	n.SetType(typ)
	n.SetTypecheck(1)
}

func setValue(name *ir.Name, val constant.Value) {
	name.SetVal(val)
	name.Defn = nil
}

// @@@ Positions

// pos reads a position from the bitstream.
func (r *reader) pos() src.XPos {
	return base.Ctxt.PosTable.XPos(r.pos0())
}

// origPos reads a position from the bitstream, and returns both the
// original raw position and an inlining-adjusted position.
func (r *reader) origPos() (origPos, inlPos src.XPos) {
	r.suppressInlPos++
	origPos = r.pos()
	r.suppressInlPos--
	inlPos = r.inlPos(origPos)
	return
}

func (r *reader) pos0() src.Pos {
	r.Sync(pkgbits.SyncPos)
	if !r.Bool() {
		return src.NoPos
	}

	posBase := r.posBase()
	line := r.Uint()
	col := r.Uint()
	return src.MakePos(posBase, line, col)
}

// posBase reads a position base from the bitstream.
func (r *reader) posBase() *src.PosBase {
	return r.inlPosBase(r.p.posBaseIdx(r.Reloc(pkgbits.RelocPosBase)))
}

// posBaseIdx returns the specified position base, reading it first if
// needed.
func (pr *pkgReader) posBaseIdx(idx index) *src.PosBase {
	if b := pr.posBases[idx]; b != nil {
		return b
	}

	r := pr.newReader(pkgbits.RelocPosBase, idx, pkgbits.SyncPosBase)
	var b *src.PosBase

	absFilename := r.String()
	filename := absFilename

	// For build artifact stability, the export data format only
	// contains the "absolute" filename as returned by objabi.AbsFile.
	// However, some tests (e.g., test/run.go's asmcheck tests) expect
	// to see the full, original filename printed out. Re-expanding
	// "$GOROOT" to buildcfg.GOROOT is a close-enough approximation to
	// satisfy this.
	//
	// The export data format only ever uses slash paths
	// (for cross-operating-system reproducible builds),
	// but error messages need to use native paths (backslash on Windows)
	// as if they had been specified on the command line.
	// (The go command always passes native paths to the compiler.)
	const dollarGOROOT = "$GOROOT"
	if buildcfg.GOROOT != "" && strings.HasPrefix(filename, dollarGOROOT) {
		filename = filepath.FromSlash(buildcfg.GOROOT + filename[len(dollarGOROOT):])
	}

	if r.Bool() {
		b = src.NewFileBase(filename, absFilename)
	} else {
		pos := r.pos0()
		line := r.Uint()
		col := r.Uint()
		b = src.NewLinePragmaBase(pos, filename, absFilename, line, col)
	}

	pr.posBases[idx] = b
	return b
}

// inlPosBase returns the inlining-adjusted src.PosBase corresponding
// to oldBase, which must be a non-inlined position. When not
// inlining, this is just oldBase.
func (r *reader) inlPosBase(oldBase *src.PosBase) *src.PosBase {
	if index := oldBase.InliningIndex(); index >= 0 {
		base.Fatalf("oldBase %v already has inlining index %v", oldBase, index)
	}

	if r.inlCall == nil || r.suppressInlPos != 0 {
		return oldBase
	}

	if newBase, ok := r.inlPosBases[oldBase]; ok {
		return newBase
	}

	newBase := src.NewInliningBase(oldBase, r.inlTreeIndex)
	r.inlPosBases[oldBase] = newBase
	return newBase
}

// inlPos returns the inlining-adjusted src.XPos corresponding to
// xpos, which must be a non-inlined position. When not inlining, this
// is just xpos.
func (r *reader) inlPos(xpos src.XPos) src.XPos {
	pos := base.Ctxt.PosTable.Pos(xpos)
	pos.SetBase(r.inlPosBase(pos.Base()))
	return base.Ctxt.PosTable.XPos(pos)
}

// @@@ Packages

// pkg reads a package reference from the bitstream.
func (r *reader) pkg() *types.Pkg {
	r.Sync(pkgbits.SyncPkg)
	return r.p.pkgIdx(r.Reloc(pkgbits.RelocPkg))
}

// pkgIdx returns the specified package from the export data, reading
// it first if needed.
func (pr *pkgReader) pkgIdx(idx index) *types.Pkg {
	if pkg := pr.pkgs[idx]; pkg != nil {
		return pkg
	}

	pkg := pr.newReader(pkgbits.RelocPkg, idx, pkgbits.SyncPkgDef).doPkg()
	pr.pkgs[idx] = pkg
	return pkg
}

// doPkg reads a package definition from the bitstream.
func (r *reader) doPkg() *types.Pkg {
	path := r.String()
	switch path {
	case "":
		path = r.p.PkgPath()
	case "builtin":
		return types.BuiltinPkg
	case "unsafe":
		return types.UnsafePkg
	}

	name := r.String()

	pkg := types.NewPkg(path, "")

	if pkg.Name == "" {
		pkg.Name = name
	} else {
		base.Assertf(pkg.Name == name, "package %q has name %q, but want %q", pkg.Path, pkg.Name, name)
	}

	return pkg
}

// @@@ Types

func (r *reader) typ() *types.Type {
	return r.typWrapped(true)
}

// typWrapped is like typ, but allows suppressing generation of
// unnecessary wrappers as a compile-time optimization.
func (r *reader) typWrapped(wrapped bool) *types.Type {
	return r.p.typIdx(r.typInfo(), r.dict, wrapped)
}

func (r *reader) typInfo() typeInfo {
	r.Sync(pkgbits.SyncType)
	if r.Bool() {
		return typeInfo{idx: index(r.Len()), derived: true}
	}
	return typeInfo{idx: r.Reloc(pkgbits.RelocType), derived: false}
}

// typListIdx returns a list of the specified types, resolving derived
// types within the given dictionary.
func (pr *pkgReader) typListIdx(infos []typeInfo, dict *readerDict) []*types.Type {
	typs := make([]*types.Type, len(infos))
	for i, info := range infos {
		typs[i] = pr.typIdx(info, dict, true)
	}
	return typs
}

// typIdx returns the specified type. If info specifies a derived
// type, it's resolved within the given dictionary. If wrapped is
// true, then method wrappers will be generated, if appropriate.
func (pr *pkgReader) typIdx(info typeInfo, dict *readerDict, wrapped bool) *types.Type {
	idx := info.idx
	var where **types.Type
	if info.derived {
		where = &dict.derivedTypes[idx]
		idx = dict.derived[idx].idx
	} else {
		where = &pr.typs[idx]
	}

	if typ := *where; typ != nil {
		return typ
	}

	r := pr.newReader(pkgbits.RelocType, idx, pkgbits.SyncTypeIdx)
	r.dict = dict

	typ := r.doTyp()
	if typ == nil {
		base.Fatalf("doTyp returned nil for info=%v", info)
	}

	// For recursive type declarations involving interfaces and aliases,
	// above r.doTyp() call may have already set pr.typs[idx], so just
	// double check and return the type.
	//
	// Example:
	//
	//     type F = func(I)
	//
	//     type I interface {
	//         m(F)
	//     }
	//
	// The writer writes data types in following index order:
	//
	//     0: func(I)
	//     1: I
	//     2: interface{m(func(I))}
	//
	// The reader resolves it in following index order:
	//
	//     0 -> 1 -> 2 -> 0 -> 1
	//
	// and can divide in logically 2 steps:
	//
	//  - 0 -> 1     : first time the reader reach type I,
	//                 it creates new named type with symbol I.
	//
	//  - 2 -> 0 -> 1: the reader ends up reaching symbol I again,
	//                 now the symbol I was setup in above step, so
	//                 the reader just return the named type.
	//
	// Now, the functions called return, the pr.typs looks like below:
	//
	//  - 0 -> 1 -> 2 -> 0 : [<T> I <T>]
	//  - 0 -> 1 -> 2      : [func(I) I <T>]
	//  - 0 -> 1           : [func(I) I interface { "".m(func("".I)) }]
	//
	// The idx 1, corresponding with type I was resolved successfully
	// after r.doTyp() call.

	if prev := *where; prev != nil {
		return prev
	}

	if wrapped {
		// Only cache if we're adding wrappers, so that other callers that
		// find a cached type know it was wrapped.
		*where = typ

		r.needWrapper(typ)
	}

	if !typ.IsUntyped() {
		types.CheckSize(typ)
	}

	return typ
}

func (r *reader) doTyp() *types.Type {
	switch tag := pkgbits.CodeType(r.Code(pkgbits.SyncType)); tag {
	default:
		panic(fmt.Sprintf("unexpected type: %v", tag))

	case pkgbits.TypeBasic:
		return *basics[r.Len()]

	case pkgbits.TypeNamed:
		obj := r.obj()
		assert(obj.Op() == ir.OTYPE)
		return obj.Type()

	case pkgbits.TypeTypeParam:
		return r.dict.targs[r.Len()]

	case pkgbits.TypeArray:
		len := int64(r.Uint64())
		return types.NewArray(r.typ(), len)
	case pkgbits.TypeChan:
		dir := dirs[r.Len()]
		return types.NewChan(r.typ(), dir)
	case pkgbits.TypeMap:
		return types.NewMap(r.typ(), r.typ())
	case pkgbits.TypePointer:
		return types.NewPtr(r.typ())
	case pkgbits.TypeSignature:
		return r.signature(nil)
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

func (r *reader) unionType() *types.Type {
	// In the types1 universe, we only need to handle value types.
	// Impure interfaces (i.e., interfaces with non-trivial type sets
	// like "int | string") can only appear as type parameter bounds,
	// and this is enforced by the types2 type checker.
	//
	// However, type unions can still appear in pure interfaces if the
	// type union is equivalent to "any". E.g., typeparam/issue52124.go
	// declares variables with the type "interface { any | int }".
	//
	// To avoid needing to represent type unions in types1 (since we
	// don't have any uses for that today anyway), we simply fold them
	// to "any".

	// TODO(mdempsky): Restore consistency check to make sure folding to
	// "any" is safe. This is unfortunately tricky, because a pure
	// interface can reference impure interfaces too, including
	// cyclically (#60117).
	if false {
		pure := false
		for i, n := 0, r.Len(); i < n; i++ {
			_ = r.Bool() // tilde
			term := r.typ()
			if term.IsEmptyInterface() {
				pure = true
			}
		}
		if !pure {
			base.Fatalf("impure type set used in value type")
		}
	}

	return types.Types[types.TINTER]
}

func (r *reader) interfaceType() *types.Type {
	nmethods, nembeddeds := r.Len(), r.Len()
	implicit := nmethods == 0 && nembeddeds == 1 && r.Bool()
	assert(!implicit) // implicit interfaces only appear in constraints

	fields := make([]*types.Field, nmethods+nembeddeds)
	methods, embeddeds := fields[:nmethods], fields[nmethods:]

	for i := range methods {
		methods[i] = types.NewField(r.pos(), r.selector(), r.signature(types.FakeRecv()))
	}
	for i := range embeddeds {
		embeddeds[i] = types.NewField(src.NoXPos, nil, r.typ())
	}

	if len(fields) == 0 {
		return types.Types[types.TINTER] // empty interface
	}
	return types.NewInterface(fields)
}

func (r *reader) structType() *types.Type {
	fields := make([]*types.Field, r.Len())
	for i := range fields {
		field := types.NewField(r.pos(), r.selector(), r.typ())
		field.Note = r.String()
		if r.Bool() {
			field.Embedded = 1
		}
		fields[i] = field
	}
	return types.NewStruct(fields)
}

func (r *reader) signature(recv *types.Field) *types.Type {
	r.Sync(pkgbits.SyncSignature)

	params := r.params()
	results := r.params()
	if r.Bool() { // variadic
		params[len(params)-1].SetIsDDD(true)
	}

	return types.NewSignature(recv, params, results)
}

func (r *reader) params() []*types.Field {
	r.Sync(pkgbits.SyncParams)
	params := make([]*types.Field, r.Len())
	for i := range params {
		params[i] = r.param()
	}
	return params
}

func (r *reader) param() *types.Field {
	r.Sync(pkgbits.SyncParam)
	return types.NewField(r.pos(), r.localIdent(), r.typ())
}

// @@@ Objects

// objReader maps qualified identifiers (represented as *types.Sym) to
// a pkgReader and corresponding index that can be used for reading
// that object's definition.
var objReader = map[*types.Sym]pkgReaderIndex{}

// obj reads an instantiated object reference from the bitstream.
func (r *reader) obj() ir.Node {
	return r.p.objInstIdx(r.objInfo(), r.dict, false)
}

// objInfo reads an instantiated object reference from the bitstream
// and returns the encoded reference to it, without instantiating it.
func (r *reader) objInfo() objInfo {
	r.Sync(pkgbits.SyncObject)
	if r.Version().Has(pkgbits.DerivedFuncInstance) {
		assert(!r.Bool())
	}
	idx := r.Reloc(pkgbits.RelocObj)

	explicits := make([]typeInfo, r.Len())
	for i := range explicits {
		explicits[i] = r.typInfo()
	}

	return objInfo{idx, explicits}
}

// objInstIdx returns the encoded, instantiated object. If shaped is
// true, then the shaped variant of the object is returned instead.
func (pr *pkgReader) objInstIdx(info objInfo, dict *readerDict, shaped bool) ir.Node {
	explicits := pr.typListIdx(info.explicits, dict)

	var implicits []*types.Type
	if dict != nil {
		implicits = dict.targs
	}

	return pr.objIdx(info.idx, implicits, explicits, shaped)
}

// objIdx returns the specified object, instantiated with the given
// type arguments, if any.
// If shaped is true, then the shaped variant of the object is returned
// instead.
func (pr *pkgReader) objIdx(idx index, implicits, explicits []*types.Type, shaped bool) ir.Node {
	n, err := pr.objIdxMayFail(idx, implicits, explicits, shaped)
	if err != nil {
		base.Fatalf("%v", err)
	}
	return n
}

// objIdxMayFail is equivalent to objIdx, but returns an error rather than
// failing the build if this object requires type arguments and the incorrect
// number of type arguments were passed.
//
// Other sources of internal failure (such as duplicate definitions) still fail
// the build.
func (pr *pkgReader) objIdxMayFail(idx index, implicits, explicits []*types.Type, shaped bool) (ir.Node, error) {
	rname := pr.newReader(pkgbits.RelocName, idx, pkgbits.SyncObject1)
	_, sym := rname.qualifiedIdent()
	tag := pkgbits.CodeObj(rname.Code(pkgbits.SyncCodeObj))

	if tag == pkgbits.ObjStub {
		assert(!sym.IsBlank())
		switch sym.Pkg {
		case types.BuiltinPkg, types.UnsafePkg:
			return sym.Def.(ir.Node), nil
		}
		if pri, ok := objReader[sym]; ok {
			return pri.pr.objIdxMayFail(pri.idx, nil, explicits, shaped)
		}
		if sym.Pkg.Path == "runtime" {
			return typecheck.LookupRuntime(sym.Name), nil
		}
		base.Fatalf("unresolved stub: %v", sym)
	}

	dict, err := pr.objDictIdx(sym, idx, implicits, explicits, shaped)
	if err != nil {
		return nil, err
	}

	sym = dict.baseSym
	if !sym.IsBlank() && sym.Def != nil {
		return sym.Def.(*ir.Name), nil
	}

	r := pr.newReader(pkgbits.RelocObj, idx, pkgbits.SyncObject1)
	rext := pr.newReader(pkgbits.RelocObjExt, idx, pkgbits.SyncObject1)

	r.dict = dict
	rext.dict = dict

	do := func(op ir.Op, hasTParams bool) *ir.Name {
		pos := r.pos()
		setBasePos(pos)
		if hasTParams {
			r.typeParamNames()
		}

		name := ir.NewDeclNameAt(pos, op, sym)
		name.Class = ir.PEXTERN // may be overridden later
		if !sym.IsBlank() {
			if sym.Def != nil {
				base.FatalfAt(name.Pos(), "already have a definition for %v", name)
			}
			assert(sym.Def == nil)
			sym.Def = name
		}
		return name
	}

	switch tag {
	default:
		panic("unexpected object")

	case pkgbits.ObjAlias:
		name := do(ir.OTYPE, false)

		if r.Version().Has(pkgbits.AliasTypeParamNames) {
			r.typeParamNames()
		}

		// Clumsy dance: the r.typ() call here might recursively find this
		// type alias name, before we've set its type (#66873). So we
		// temporarily clear sym.Def and then restore it later, if still
		// unset.
		hack := sym.Def == name
		if hack {
			sym.Def = nil
		}
		typ := r.typ()
		if hack {
			if sym.Def != nil {
				name = sym.Def.(*ir.Name)
				assert(name.Type() == typ)
				return name, nil
			}
			sym.Def = name
		}

		setType(name, typ)
		name.SetAlias(true)
		return name, nil

	case pkgbits.ObjConst:
		name := do(ir.OLITERAL, false)
		typ := r.typ()
		val := FixValue(typ, r.Value())
		setType(name, typ)
		setValue(name, val)
		return name, nil

	case pkgbits.ObjFunc:
		if sym.Name == "init" {
			sym = Renameinit()
		}

		npos := r.pos()
		setBasePos(npos)
		r.typeParamNames()
		typ := r.signature(nil)
		fpos := r.pos()

		fn := ir.NewFunc(fpos, npos, sym, typ)
		name := fn.Nname
		if !sym.IsBlank() {
			if sym.Def != nil {
				base.FatalfAt(name.Pos(), "already have a definition for %v", name)
			}
			assert(sym.Def == nil)
			sym.Def = name
		}

		if r.hasTypeParams() {
			name.Func.SetDupok(true)
			if r.dict.shaped {
				setType(name, shapeSig(name.Func, r.dict))
			} else {
				todoDicts = append(todoDicts, func() {
					r.dict.shapedObj = pr.objIdx(idx, implicits, explicits, true).(*ir.Name)
				})
			}
		}

		rext.funcExt(name, nil)
		return name, nil

	case pkgbits.ObjType:
		name := do(ir.OTYPE, true)
		typ := types.NewNamed(name)
		setType(name, typ)
		if r.hasTypeParams() && r.dict.shaped {
			typ.SetHasShape(true)
		}

		// Important: We need to do this before SetUnderlying.
		rext.typeExt(name)

		// We need to defer CheckSize until we've called SetUnderlying to
		// handle recursive types.
		types.DeferCheckSize()
		typ.SetUnderlying(r.typWrapped(false))
		types.ResumeCheckSize()

		if r.hasTypeParams() && !r.dict.shaped {
			todoDicts = append(todoDicts, func() {
				r.dict.shapedObj = pr.objIdx(idx, implicits, explicits, true).(*ir.Name)
			})
		}

		methods := make([]*types.Field, r.Len())
		for i := range methods {
			methods[i] = r.method(rext)
		}
		if len(methods) != 0 {
			typ.SetMethods(methods)
		}

		if !r.dict.shaped {
			r.needWrapper(typ)
		}

		return name, nil

	case pkgbits.ObjVar:
		name := do(ir.ONAME, false)
		setType(name, r.typ())
		rext.varExt(name)
		return name, nil
	}
}

func (dict *readerDict) mangle(sym *types.Sym) *types.Sym {
	if !dict.hasTypeParams() {
		return sym
	}

	// If sym is a locally defined generic type, we need the suffix to
	// stay at the end after mangling so that types/fmt.go can strip it
	// out again when writing the type's runtime descriptor (#54456).
	base, suffix := types.SplitVargenSuffix(sym.Name)

	var buf strings.Builder
	buf.WriteString(base)
	buf.WriteByte('[')
	for i, targ := range dict.targs {
		if i > 0 {
			if i == dict.implicits {
				buf.WriteByte(';')
			} else {
				buf.WriteByte(',')
			}
		}
		buf.WriteString(targ.LinkString())
	}
	buf.WriteByte(']')
	buf.WriteString(suffix)
	return sym.Pkg.Lookup(buf.String())
}

// shapify returns the shape type for targ.
//
// If basic is true, then the type argument is used to instantiate a
// type parameter whose constraint is a basic interface.
func shapify(targ *types.Type, basic bool) *types.Type {
	if targ.Kind() == types.TFORW {
		if targ.IsFullyInstantiated() {
			// For recursive instantiated type argument, it may  still be a TFORW
			// when shapifying happens. If we don't have targ's underlying type,
			// shapify won't work. The worst case is we end up not reusing code
			// optimally in some tricky cases.
			if base.Debug.Shapify != 0 {
				base.Warn("skipping shaping of recursive type %v", targ)
			}
			if targ.HasShape() {
				return targ
			}
		} else {
			base.Fatalf("%v is missing its underlying type", targ)
		}
	}
	// For fully instantiated shape interface type, use it as-is. Otherwise, the instantiation
	// involved recursive generic interface may cause mismatching in function signature, see issue #65362.
	if targ.Kind() == types.TINTER && targ.IsFullyInstantiated() && targ.HasShape() {
		return targ
	}

	// When a pointer type is used to instantiate a type parameter
	// constrained by a basic interface, we know the pointer's element
	// type can't matter to the generated code. In this case, we can use
	// an arbitrary pointer type as the shape type. (To match the
	// non-unified frontend, we use `*byte`.)
	//
	// Otherwise, we simply use the type's underlying type as its shape.
	//
	// TODO(mdempsky): It should be possible to do much more aggressive
	// shaping still; e.g., collapsing all pointer-shaped types into a
	// common type, collapsing scalars of the same size/alignment into a
	// common type, recursively shaping the element types of composite
	// types, and discarding struct field names and tags. However, we'll
	// need to start tracking how type parameters are actually used to
	// implement some of these optimizations.
	under := targ.Underlying()
	if basic && targ.IsPtr() && !targ.Elem().NotInHeap() {
		under = types.NewPtr(types.Types[types.TUINT8])
	}

	// Hash long type names to bound symbol name length seen by users,
	// particularly for large protobuf structs (#65030).
	uls := under.LinkString()
	if base.Debug.MaxShapeLen != 0 &&
		len(uls) > base.Debug.MaxShapeLen {
		h := hash.Sum32([]byte(uls))
		uls = hex.EncodeToString(h[:])
	}

	sym := types.ShapePkg.Lookup(uls)
	if sym.Def == nil {
		name := ir.NewDeclNameAt(under.Pos(), ir.OTYPE, sym)
		typ := types.NewNamed(name)
		typ.SetUnderlying(under)
		sym.Def = typed(typ, name)
	}
	res := sym.Def.Type()
	assert(res.IsShape())
	assert(res.HasShape())
	return res
}

// objDictIdx reads and returns the specified object dictionary.
func (pr *pkgReader) objDictIdx(sym *types.Sym, idx index, implicits, explicits []*types.Type, shaped bool) (*readerDict, error) {
	r := pr.newReader(pkgbits.RelocObjDict, idx, pkgbits.SyncObject1)

	dict := readerDict{
		shaped: shaped,
	}

	nimplicits := r.Len()
	nexplicits := r.Len()

	if nimplicits > len(implicits) || nexplicits != len(explicits) {
		return nil, fmt.Errorf("%v has %v+%v params, but instantiated with %v+%v args", sym, nimplicits, nexplicits, len(implicits), len(explicits))
	}

	dict.targs = append(implicits[:nimplicits:nimplicits], explicits...)
	dict.implicits = nimplicits

	// Within the compiler, we can just skip over the type parameters.
	for range dict.targs[dict.implicits:] {
		// Skip past bounds without actually evaluating them.
		r.typInfo()
	}

	dict.derived = make([]derivedInfo, r.Len())
	dict.derivedTypes = make([]*types.Type, len(dict.derived))
	for i := range dict.derived {
		dict.derived[i] = derivedInfo{idx: r.Reloc(pkgbits.RelocType)}
		if r.Version().Has(pkgbits.DerivedInfoNeeded) {
			assert(!r.Bool())
		}
	}

	// Runtime dictionary information; private to the compiler.

	// If any type argument is already shaped, then we're constructing a
	// shaped object, even if not explicitly requested (i.e., calling
	// objIdx with shaped==true). This can happen with instantiating
	// types that are referenced within a function body.
	for _, targ := range dict.targs {
		if targ.HasShape() {
			dict.shaped = true
			break
		}
	}

	// And if we're constructing a shaped object, then shapify all type
	// arguments.
	for i, targ := range dict.targs {
		basic := r.Bool()
		if dict.shaped {
			dict.targs[i] = shapify(targ, basic)
		}
	}

	dict.baseSym = dict.mangle(sym)

	dict.typeParamMethodExprs = make([]readerMethodExprInfo, r.Len())
	for i := range dict.typeParamMethodExprs {
		typeParamIdx := r.Len()
		method := r.selector()

		dict.typeParamMethodExprs[i] = readerMethodExprInfo{typeParamIdx, method}
	}

	dict.subdicts = make([]objInfo, r.Len())
	for i := range dict.subdicts {
		dict.subdicts[i] = r.objInfo()
	}

	dict.rtypes = make([]typeInfo, r.Len())
	for i := range dict.rtypes {
		dict.rtypes[i] = r.typInfo()
	}

	dict.itabs = make([]itabInfo, r.Len())
	for i := range dict.itabs {
		dict.itabs[i] = itabInfo{typ: r.typInfo(), iface: r.typInfo()}
	}

	return &dict, nil
}

func (r *reader) typeParamNames() {
	r.Sync(pkgbits.SyncTypeParamNames)

	for range r.dict.targs[r.dict.implicits:] {
		r.pos()
		r.localIdent()
	}
}

func (r *reader) method(rext *reader) *types.Field {
	r.Sync(pkgbits.SyncMethod)
	npos := r.pos()
	sym := r.selector()
	r.typeParamNames()
	recv := r.param()
	typ := r.signature(recv)

	fpos := r.pos()
	fn := ir.NewFunc(fpos, npos, ir.MethodSym(recv.Type, sym), typ)
	name := fn.Nname

	if r.hasTypeParams() {
		name.Func.SetDupok(true)
		if r.dict.shaped {
			typ = shapeSig(name.Func, r.dict)
			setType(name, typ)
		}
	}

	rext.funcExt(name, sym)

	meth := types.NewField(name.Func.Pos(), sym, typ)
	meth.Nname = name
	meth.SetNointerface(name.Func.Pragma&ir.Nointerface != 0)

	return meth
}

func (r *reader) qualifiedIdent() (pkg *types.Pkg, sym *types.Sym) {
	r.Sync(pkgbits.SyncSym)
	pkg = r.pkg()
	if name := r.String(); name != "" {
		sym = pkg.Lookup(name)
	}
	return
}

func (r *reader) localIdent() *types.Sym {
	r.Sync(pkgbits.SyncLocalIdent)
	pkg := r.pkg()
	if name := r.String(); name != "" {
		return pkg.Lookup(name)
	}
	return nil
}

func (r *reader) selector() *types.Sym {
	r.Sync(pkgbits.SyncSelector)
	pkg := r.pkg()
	name := r.String()
	if types.IsExported(name) {
		pkg = types.LocalPkg
	}
	return pkg.Lookup(name)
}

func (r *reader) hasTypeParams() bool {
	return r.dict.hasTypeParams()
}

func (dict *readerDict) hasTypeParams() bool {
	return dict != nil && len(dict.targs) != 0
}

// @@@ Compiler extensions

func (r *reader) funcExt(name *ir.Name, method *types.Sym) {
	r.Sync(pkgbits.SyncFuncExt)

	fn := name.Func

	// XXX: Workaround because linker doesn't know how to copy Pos.
	if !fn.Pos().IsKnown() {
		fn.SetPos(name.Pos())
	}

	// Normally, we only compile local functions, which saves redundant compilation work.
	// n.Defn is not nil for local functions, and is nil for imported function. But for
	// generic functions, we might have an instantiation that no other package has seen before.
	// So we need to be conservative and compile it again.
	//
	// That's why name.Defn is set here, so ir.VisitFuncsBottomUp can analyze function.
	// TODO(mdempsky,cuonglm): find a cleaner way to handle this.
	if name.Sym().Pkg == types.LocalPkg || r.hasTypeParams() {
		name.Defn = fn
	}

	fn.Pragma = r.pragmaFlag()
	r.linkname(name)

	if buildcfg.GOARCH == "wasm" {
		importmod := r.String()
		importname := r.String()
		exportname := r.String()

		if importmod != "" && importname != "" {
			fn.WasmImport = &ir.WasmImport{
				Module: importmod,
				Name:   importname,
			}
		}
		if exportname != "" {
			if method != nil {
				base.ErrorfAt(fn.Pos(), 0, "cannot use //go:wasmexport on a method")
			}
			fn.WasmExport = &ir.WasmExport{Name: exportname}
		}
	}

	if r.Bool() {
		assert(name.Defn == nil)

		fn.ABI = obj.ABI(r.Uint64())

		// Escape analysis.
		for _, f := range name.Type().RecvParams() {
			f.Note = r.String()
		}

		if r.Bool() {
			fn.Inl = &ir.Inline{
				Cost:            int32(r.Len()),
				CanDelayResults: r.Bool(),
			}
			if buildcfg.Experiment.NewInliner {
				fn.Inl.Properties = r.String()
			}
		}
	} else {
		r.addBody(name.Func, method)
	}
	r.Sync(pkgbits.SyncEOF)
}

func (r *reader) typeExt(name *ir.Name) {
	r.Sync(pkgbits.SyncTypeExt)

	typ := name.Type()

	if r.hasTypeParams() {
		// Mark type as fully instantiated to ensure the type descriptor is written
		// out as DUPOK and method wrappers are generated even for imported types.
		typ.SetIsFullyInstantiated(true)
		// HasShape should be set if any type argument is or has a shape type.
		for _, targ := range r.dict.targs {
			if targ.HasShape() {
				typ.SetHasShape(true)
				break
			}
		}
	}

	name.SetPragma(r.pragmaFlag())

	typecheck.SetBaseTypeIndex(typ, r.Int64(), r.Int64())
}

func (r *reader) varExt(name *ir.Name) {
	r.Sync(pkgbits.SyncVarExt)
	r.linkname(name)
}

func (r *reader) linkname(name *ir.Name) {
	assert(name.Op() == ir.ONAME)
	r.Sync(pkgbits.SyncLinkname)

	if idx := r.Int64(); idx >= 0 {
		lsym := name.Linksym()
		lsym.SymIdx = int32(idx)
		lsym.Set(obj.AttrIndexed, true)
	} else {
		linkname := r.String()
		sym := name.Sym()
		sym.Linkname = linkname
		if sym.Pkg == types.LocalPkg && linkname != "" {
			// Mark linkname in the current package. We don't mark the
			// ones that are imported and propagated (e.g. through
			// inlining or instantiation, which are marked in their
			// corresponding packages). So we can tell in which package
			// the linkname is used (pulled), and the linker can
			// make a decision for allowing or disallowing it.
			sym.Linksym().Set(obj.AttrLinkname, true)
		}
	}
}

func (r *reader) pragmaFlag() ir.PragmaFlag {
	r.Sync(pkgbits.SyncPragma)
	return ir.PragmaFlag(r.Int())
}

// @@@ Function bodies

// bodyReader tracks where the serialized IR for a local or imported,
// generic function's body can be found.
var bodyReader = map[*ir.Func]pkgReaderIndex{}

// importBodyReader tracks where the serialized IR for an imported,
// static (i.e., non-generic) function body can be read.
var importBodyReader = map[*types.Sym]pkgReaderIndex{}

// bodyReaderFor returns the pkgReaderIndex for reading fn's
// serialized IR, and whether one was found.
func bodyReaderFor(fn *ir.Func) (pri pkgReaderIndex, ok bool) {
	if fn.Nname.Defn != nil {
		pri, ok = bodyReader[fn]
		base.AssertfAt(ok, base.Pos, "must have bodyReader for %v", fn) // must always be available
	} else {
		pri, ok = importBodyReader[fn.Sym()]
	}
	return
}

// todoDicts holds the list of dictionaries that still need their
// runtime dictionary objects constructed.
var todoDicts []func()

// todoBodies holds the list of function bodies that still need to be
// constructed.
var todoBodies []*ir.Func

// addBody reads a function body reference from the element bitstream,
// and associates it with fn.
func (r *reader) addBody(fn *ir.Func, method *types.Sym) {
	// addBody should only be called for local functions or imported
	// generic functions; see comment in funcExt.
	assert(fn.Nname.Defn != nil)

	idx := r.Reloc(pkgbits.RelocBody)

	pri := pkgReaderIndex{r.p, idx, r.dict, method, nil}
	bodyReader[fn] = pri

	if r.curfn == nil {
		todoBodies = append(todoBodies, fn)
		return
	}

	pri.funcBody(fn)
}

func (pri pkgReaderIndex) funcBody(fn *ir.Func) {
	r := pri.asReader(pkgbits.RelocBody, pkgbits.SyncFuncBody)
	r.funcBody(fn)
}

// funcBody reads a function body definition from the element
// bitstream, and populates fn with it.
func (r *reader) funcBody(fn *ir.Func) {
	r.curfn = fn
	r.closureVars = fn.ClosureVars
	if len(r.closureVars) != 0 && r.hasTypeParams() {
		r.dictParam = r.closureVars[len(r.closureVars)-1] // dictParam is last; see reader.funcLit
	}

	ir.WithFunc(fn, func() {
		r.declareParams()

		if r.syntheticBody(fn.Pos()) {
			return
		}

		if !r.Bool() {
			return
		}

		body := r.stmts()
		if body == nil {
			body = []ir.Node{typecheck.Stmt(ir.NewBlockStmt(src.NoXPos, nil))}
		}
		fn.Body = body
		fn.Endlineno = r.pos()
	})

	r.marker.WriteTo(fn)
}

// syntheticBody adds a synthetic body to r.curfn if appropriate, and
// reports whether it did.
func (r *reader) syntheticBody(pos src.XPos) bool {
	if r.synthetic != nil {
		r.synthetic(pos, r)
		return true
	}

	// If this function has type parameters and isn't shaped, then we
	// just tail call its corresponding shaped variant.
	if r.hasTypeParams() && !r.dict.shaped {
		r.callShaped(pos)
		return true
	}

	return false
}

// callShaped emits a tail call to r.shapedFn, passing along the
// arguments to the current function.
func (r *reader) callShaped(pos src.XPos) {
	shapedObj := r.dict.shapedObj
	assert(shapedObj != nil)

	var shapedFn ir.Node
	if r.methodSym == nil {
		// Instantiating a generic function; shapedObj is the shaped
		// function itself.
		assert(shapedObj.Op() == ir.ONAME && shapedObj.Class == ir.PFUNC)
		shapedFn = shapedObj
	} else {
		// Instantiating a generic type's method; shapedObj is the shaped
		// type, so we need to select it's corresponding method.
		shapedFn = shapedMethodExpr(pos, shapedObj, r.methodSym)
	}

	params := r.syntheticArgs()

	// Construct the arguments list: receiver (if any), then runtime
	// dictionary, and finally normal parameters.
	//
	// Note: For simplicity, shaped methods are added as normal methods
	// on their shaped types. So existing code (e.g., packages ir and
	// typecheck) expects the shaped type to appear as the receiver
	// parameter (or first parameter, as a method expression). Hence
	// putting the dictionary parameter after that is the least invasive
	// solution at the moment.
	var args ir.Nodes
	if r.methodSym != nil {
		args.Append(params[0])
		params = params[1:]
	}
	args.Append(typecheck.Expr(ir.NewAddrExpr(pos, r.p.dictNameOf(r.dict))))
	args.Append(params...)

	r.syntheticTailCall(pos, shapedFn, args)
}

// syntheticArgs returns the recvs and params arguments passed to the
// current function.
func (r *reader) syntheticArgs() ir.Nodes {
	sig := r.curfn.Nname.Type()
	return ir.ToNodes(r.curfn.Dcl[:sig.NumRecvs()+sig.NumParams()])
}

// syntheticTailCall emits a tail call to fn, passing the given
// arguments list.
func (r *reader) syntheticTailCall(pos src.XPos, fn ir.Node, args ir.Nodes) {
	// Mark the function as a wrapper so it doesn't show up in stack
	// traces.
	r.curfn.SetWrapper(true)

	call := typecheck.Call(pos, fn, args, fn.Type().IsVariadic()).(*ir.CallExpr)

	var stmt ir.Node
	if fn.Type().NumResults() != 0 {
		stmt = typecheck.Stmt(ir.NewReturnStmt(pos, []ir.Node{call}))
	} else {
		stmt = call
	}
	r.curfn.Body.Append(stmt)
}

// dictNameOf returns the runtime dictionary corresponding to dict.
func (pr *pkgReader) dictNameOf(dict *readerDict) *ir.Name {
	pos := base.AutogeneratedPos

	// Check that we only instantiate runtime dictionaries with real types.
	base.AssertfAt(!dict.shaped, pos, "runtime dictionary of shaped object %v", dict.baseSym)

	sym := dict.baseSym.Pkg.Lookup(objabi.GlobalDictPrefix + "." + dict.baseSym.Name)
	if sym.Def != nil {
		return sym.Def.(*ir.Name)
	}

	name := ir.NewNameAt(pos, sym, dict.varType())
	name.Class = ir.PEXTERN
	sym.Def = name // break cycles with mutual subdictionaries

	lsym := name.Linksym()
	ot := 0

	assertOffset := func(section string, offset int) {
		base.AssertfAt(ot == offset*types.PtrSize, pos, "writing section %v at offset %v, but it should be at %v*%v", section, ot, offset, types.PtrSize)
	}

	assertOffset("type param method exprs", dict.typeParamMethodExprsOffset())
	for _, info := range dict.typeParamMethodExprs {
		typeParam := dict.targs[info.typeParamIdx]
		method := typecheck.NewMethodExpr(pos, typeParam, info.method)

		rsym := method.FuncName().Linksym()
		assert(rsym.ABI() == obj.ABIInternal) // must be ABIInternal; see ir.OCFUNC in ssagen/ssa.go

		ot = objw.SymPtr(lsym, ot, rsym, 0)
	}

	assertOffset("subdictionaries", dict.subdictsOffset())
	for _, info := range dict.subdicts {
		explicits := pr.typListIdx(info.explicits, dict)

		// Careful: Due to subdictionary cycles, name may not be fully
		// initialized yet.
		name := pr.objDictName(info.idx, dict.targs, explicits)

		ot = objw.SymPtr(lsym, ot, name.Linksym(), 0)
	}

	assertOffset("rtypes", dict.rtypesOffset())
	for _, info := range dict.rtypes {
		typ := pr.typIdx(info, dict, true)
		ot = objw.SymPtr(lsym, ot, reflectdata.TypeLinksym(typ), 0)

		// TODO(mdempsky): Double check this.
		reflectdata.MarkTypeUsedInInterface(typ, lsym)
	}

	// For each (typ, iface) pair, we write the *runtime.itab pointer
	// for the pair. For pairs that don't actually require an itab
	// (i.e., typ is an interface, or iface is an empty interface), we
	// write a nil pointer instead. This is wasteful, but rare in
	// practice (e.g., instantiating a type parameter with an interface
	// type).
	assertOffset("itabs", dict.itabsOffset())
	for _, info := range dict.itabs {
		typ := pr.typIdx(info.typ, dict, true)
		iface := pr.typIdx(info.iface, dict, true)

		if !typ.IsInterface() && iface.IsInterface() && !iface.IsEmptyInterface() {
			ot = objw.SymPtr(lsym, ot, reflectdata.ITabLsym(typ, iface), 0)
		} else {
			ot += types.PtrSize
		}

		// TODO(mdempsky): Double check this.
		reflectdata.MarkTypeUsedInInterface(typ, lsym)
		reflectdata.MarkTypeUsedInInterface(iface, lsym)
	}

	objw.Global(lsym, int32(ot), obj.DUPOK|obj.RODATA)

	return name
}

// typeParamMethodExprsOffset returns the offset of the runtime
// dictionary's type parameter method expressions section, in words.
func (dict *readerDict) typeParamMethodExprsOffset() int {
	return 0
}

// subdictsOffset returns the offset of the runtime dictionary's
// subdictionary section, in words.
func (dict *readerDict) subdictsOffset() int {
	return dict.typeParamMethodExprsOffset() + len(dict.typeParamMethodExprs)
}

// rtypesOffset returns the offset of the runtime dictionary's rtypes
// section, in words.
func (dict *readerDict) rtypesOffset() int {
	return dict.subdictsOffset() + len(dict.subdicts)
}

// itabsOffset returns the offset of the runtime dictionary's itabs
// section, in words.
func (dict *readerDict) itabsOffset() int {
	return dict.rtypesOffset() + len(dict.rtypes)
}

// numWords returns the total number of words that comprise dict's
// runtime dictionary variable.
func (dict *readerDict) numWords() int64 {
	return int64(dict.itabsOffset() + len(dict.itabs))
}

// varType returns the type of dict's runtime dictionary variable.
func (dict *readerDict) varType() *types.Type {
	return types.NewArray(types.Types[types.TUINTPTR], dict.numWords())
}

func (r *reader) declareParams() {
	r.curfn.DeclareParams(!r.funarghack)

	for _, name := range r.curfn.Dcl {
		if name.Sym().Name == dictParamName {
			r.dictParam = name
			continue
		}

		r.addLocal(name)
	}
}

func (r *reader) addLocal(name *ir.Name) {
	if r.synthetic == nil {
		r.Sync(pkgbits.SyncAddLocal)
		if r.p.SyncMarkers() {
			want := r.Int()
			if have := len(r.locals); have != want {
				base.FatalfAt(name.Pos(), "locals table has desynced")
			}
		}
		r.varDictIndex(name)
	}

	r.locals = append(r.locals, name)
}

func (r *reader) useLocal() *ir.Name {
	r.Sync(pkgbits.SyncUseObjLocal)
	if r.Bool() {
		return r.locals[r.Len()]
	}
	return r.closureVars[r.Len()]
}

func (r *reader) openScope() {
	r.Sync(pkgbits.SyncOpenScope)
	pos := r.pos()

	if base.Flag.Dwarf {
		r.scopeVars = append(r.scopeVars, len(r.curfn.Dcl))
		r.marker.Push(pos)
	}
}

func (r *reader) closeScope() {
	r.Sync(pkgbits.SyncCloseScope)
	r.lastCloseScopePos = r.pos()

	r.closeAnotherScope()
}

// closeAnotherScope is like closeScope, but it reuses the same mark
// position as the last closeScope call. This is useful for "for" and
// "if" statements, as their implicit blocks always end at the same
// position as an explicit block.
func (r *reader) closeAnotherScope() {
	r.Sync(pkgbits.SyncCloseAnotherScope)

	if base.Flag.Dwarf {
		scopeVars := r.scopeVars[len(r.scopeVars)-1]
		r.scopeVars = r.scopeVars[:len(r.scopeVars)-1]

		// Quirkish: noder decides which scopes to keep before
		// typechecking, whereas incremental typechecking during IR
		// construction can result in new autotemps being allocated. To
		// produce identical output, we ignore autotemps here for the
		// purpose of deciding whether to retract the scope.
		//
		// This is important for net/http/fcgi, because it contains:
		//
		//	var body io.ReadCloser
		//	if len(content) > 0 {
		//		body, req.pw = io.Pipe()
		//	} else { … }
		//
		// Notably, io.Pipe is inlinable, and inlining it introduces a ~R0
		// variable at the call site.
		//
		// Noder does not preserve the scope where the io.Pipe() call
		// resides, because it doesn't contain any declared variables in
		// source. So the ~R0 variable ends up being assigned to the
		// enclosing scope instead.
		//
		// However, typechecking this assignment also introduces
		// autotemps, because io.Pipe's results need conversion before
		// they can be assigned to their respective destination variables.
		//
		// TODO(mdempsky): We should probably just keep all scopes, and
		// let dwarfgen take care of pruning them instead.
		retract := true
		for _, n := range r.curfn.Dcl[scopeVars:] {
			if !n.AutoTemp() {
				retract = false
				break
			}
		}

		if retract {
			// no variables were declared in this scope, so we can retract it.
			r.marker.Unpush()
		} else {
			r.marker.Pop(r.lastCloseScopePos)
		}
	}
}

// @@@ Statements

func (r *reader) stmt() ir.Node {
	return block(r.stmts())
}

func block(stmts []ir.Node) ir.Node {
	switch len(stmts) {
	case 0:
		return nil
	case 1:
		return stmts[0]
	default:
		return ir.NewBlockStmt(stmts[0].Pos(), stmts)
	}
}

func (r *reader) stmts() ir.Nodes {
	assert(ir.CurFunc == r.curfn)
	var res ir.Nodes

	r.Sync(pkgbits.SyncStmts)
	for {
		tag := codeStmt(r.Code(pkgbits.SyncStmt1))
		if tag == stmtEnd {
			r.Sync(pkgbits.SyncStmtsEnd)
			return res
		}

		if n := r.stmt1(tag, &res); n != nil {
			res.Append(typecheck.Stmt(n))
		}
	}
}

func (r *reader) stmt1(tag codeStmt, out *ir.Nodes) ir.Node {
	var label *types.Sym
	if n := len(*out); n > 0 {
		if ls, ok := (*out)[n-1].(*ir.LabelStmt); ok {
			label = ls.Label
		}
	}

	switch tag {
	default:
		panic("unexpected statement")

	case stmtAssign:
		pos := r.pos()
		names, lhs := r.assignList()
		rhs := r.multiExpr()

		if len(rhs) == 0 {
			for _, name := range names {
				as := ir.NewAssignStmt(pos, name, nil)
				as.PtrInit().Append(ir.NewDecl(pos, ir.ODCL, name))
				out.Append(typecheck.Stmt(as))
			}
			return nil
		}

		if len(lhs) == 1 && len(rhs) == 1 {
			n := ir.NewAssignStmt(pos, lhs[0], rhs[0])
			n.Def = r.initDefn(n, names)
			return n
		}

		n := ir.NewAssignListStmt(pos, ir.OAS2, lhs, rhs)
		n.Def = r.initDefn(n, names)
		return n

	case stmtAssignOp:
		op := r.op()
		lhs := r.expr()
		pos := r.pos()
		rhs := r.expr()
		return ir.NewAssignOpStmt(pos, op, lhs, rhs)

	case stmtIncDec:
		op := r.op()
		lhs := r.expr()
		pos := r.pos()
		n := ir.NewAssignOpStmt(pos, op, lhs, ir.NewOne(pos, lhs.Type()))
		n.IncDec = true
		return n

	case stmtBlock:
		out.Append(r.blockStmt()...)
		return nil

	case stmtBranch:
		pos := r.pos()
		op := r.op()
		sym := r.optLabel()
		return ir.NewBranchStmt(pos, op, sym)

	case stmtCall:
		pos := r.pos()
		op := r.op()
		call := r.expr()
		stmt := ir.NewGoDeferStmt(pos, op, call)
		if op == ir.ODEFER {
			x := r.optExpr()
			if x != nil {
				stmt.DeferAt = x.(ir.Expr)
			}
		}
		return stmt

	case stmtExpr:
		return r.expr()

	case stmtFor:
		return r.forStmt(label)

	case stmtIf:
		return r.ifStmt()

	case stmtLabel:
		pos := r.pos()
		sym := r.label()
		return ir.NewLabelStmt(pos, sym)

	case stmtReturn:
		pos := r.pos()
		results := r.multiExpr()
		return ir.NewReturnStmt(pos, results)

	case stmtSelect:
		return r.selectStmt(label)

	case stmtSend:
		pos := r.pos()
		ch := r.expr()
		value := r.expr()
		return ir.NewSendStmt(pos, ch, value)

	case stmtSwitch:
		return r.switchStmt(label)
	}
}

func (r *reader) assignList() ([]*ir.Name, []ir.Node) {
	lhs := make([]ir.Node, r.Len())
	var names []*ir.Name

	for i := range lhs {
		expr, def := r.assign()
		lhs[i] = expr
		if def {
			names = append(names, expr.(*ir.Name))
		}
	}

	return names, lhs
}

// assign returns an assignee expression. It also reports whether the
// returned expression is a newly declared variable.
func (r *reader) assign() (ir.Node, bool) {
	switch tag := codeAssign(r.Code(pkgbits.SyncAssign)); tag {
	default:
		panic("unhandled assignee expression")

	case assignBlank:
		return typecheck.AssignExpr(ir.BlankNode), false

	case assignDef:
		pos := r.pos()
		setBasePos(pos) // test/fixedbugs/issue49767.go depends on base.Pos being set for the r.typ() call here, ugh
		name := r.curfn.NewLocal(pos, r.localIdent(), r.typ())
		r.addLocal(name)
		return name, true

	case assignExpr:
		return r.expr(), false
	}
}

func (r *reader) blockStmt() []ir.Node {
	r.Sync(pkgbits.SyncBlockStmt)
	r.openScope()
	stmts := r.stmts()
	r.closeScope()
	return stmts
}

func (r *reader) forStmt(label *types.Sym) ir.Node {
	r.Sync(pkgbits.SyncForStmt)

	r.openScope()

	if r.Bool() {
		pos := r.pos()
		rang := ir.NewRangeStmt(pos, nil, nil, nil, nil, false)
		rang.Label = label

		names, lhs := r.assignList()
		if len(lhs) >= 1 {
			rang.Key = lhs[0]
			if len(lhs) >= 2 {
				rang.Value = lhs[1]
			}
		}
		rang.Def = r.initDefn(rang, names)

		rang.X = r.expr()
		if rang.X.Type().IsMap() {
			rang.RType = r.rtype(pos)
		}
		if rang.Key != nil && !ir.IsBlank(rang.Key) {
			rang.KeyTypeWord, rang.KeySrcRType = r.convRTTI(pos)
		}
		if rang.Value != nil && !ir.IsBlank(rang.Value) {
			rang.ValueTypeWord, rang.ValueSrcRType = r.convRTTI(pos)
		}

		rang.Body = r.blockStmt()
		rang.DistinctVars = r.Bool()
		r.closeAnotherScope()

		return rang
	}

	pos := r.pos()
	init := r.stmt()
	cond := r.optExpr()
	post := r.stmt()
	body := r.blockStmt()
	perLoopVars := r.Bool()
	r.closeAnotherScope()

	if ir.IsConst(cond, constant.Bool) && !ir.BoolVal(cond) {
		return init // simplify "for init; false; post { ... }" into "init"
	}

	stmt := ir.NewForStmt(pos, init, cond, post, body, perLoopVars)
	stmt.Label = label
	return stmt
}

func (r *reader) ifStmt() ir.Node {
	r.Sync(pkgbits.SyncIfStmt)
	r.openScope()
	pos := r.pos()
	init := r.stmts()
	cond := r.expr()
	staticCond := r.Int()
	var then, els []ir.Node
	if staticCond >= 0 {
		then = r.blockStmt()
	} else {
		r.lastCloseScopePos = r.pos()
	}
	if staticCond <= 0 {
		els = r.stmts()
	}
	r.closeAnotherScope()

	if staticCond != 0 {
		// We may have removed a dead return statement, which can trip up
		// later passes (#62211). To avoid confusion, we instead flatten
		// the if statement into a block.

		if cond.Op() != ir.OLITERAL {
			init.Append(typecheck.Stmt(ir.NewAssignStmt(pos, ir.BlankNode, cond))) // for side effects
		}
		init.Append(then...)
		init.Append(els...)
		return block(init)
	}

	n := ir.NewIfStmt(pos, cond, then, els)
	n.SetInit(init)
	return n
}

func (r *reader) selectStmt(label *types.Sym) ir.Node {
	r.Sync(pkgbits.SyncSelectStmt)

	pos := r.pos()
	clauses := make([]*ir.CommClause, r.Len())
	for i := range clauses {
		if i > 0 {
			r.closeScope()
		}
		r.openScope()

		pos := r.pos()
		comm := r.stmt()
		body := r.stmts()

		// "case i = <-c: ..." may require an implicit conversion (e.g.,
		// see fixedbugs/bug312.go). Currently, typecheck throws away the
		// implicit conversion and relies on it being reinserted later,
		// but that would lose any explicit RTTI operands too. To preserve
		// RTTI, we rewrite this as "case tmp := <-c: i = tmp; ...".
		if as, ok := comm.(*ir.AssignStmt); ok && as.Op() == ir.OAS && !as.Def {
			if conv, ok := as.Y.(*ir.ConvExpr); ok && conv.Op() == ir.OCONVIFACE {
				base.AssertfAt(conv.Implicit(), conv.Pos(), "expected implicit conversion: %v", conv)

				recv := conv.X
				base.AssertfAt(recv.Op() == ir.ORECV, recv.Pos(), "expected receive expression: %v", recv)

				tmp := r.temp(pos, recv.Type())

				// Replace comm with `tmp := <-c`.
				tmpAs := ir.NewAssignStmt(pos, tmp, recv)
				tmpAs.Def = true
				tmpAs.PtrInit().Append(ir.NewDecl(pos, ir.ODCL, tmp))
				comm = tmpAs

				// Change original assignment to `i = tmp`, and prepend to body.
				conv.X = tmp
				body = append([]ir.Node{as}, body...)
			}
		}

		// multiExpr will have desugared a comma-ok receive expression
		// into a separate statement. However, the rest of the compiler
		// expects comm to be the OAS2RECV statement itself, so we need to
		// shuffle things around to fit that pattern.
		if as2, ok := comm.(*ir.AssignListStmt); ok && as2.Op() == ir.OAS2 {
			init := ir.TakeInit(as2.Rhs[0])
			base.AssertfAt(len(init) == 1 && init[0].Op() == ir.OAS2RECV, as2.Pos(), "unexpected assignment: %+v", as2)

			comm = init[0]
			body = append([]ir.Node{as2}, body...)
		}

		clauses[i] = ir.NewCommStmt(pos, comm, body)
	}
	if len(clauses) > 0 {
		r.closeScope()
	}
	n := ir.NewSelectStmt(pos, clauses)
	n.Label = label
	return n
}

func (r *reader) switchStmt(label *types.Sym) ir.Node {
	r.Sync(pkgbits.SyncSwitchStmt)

	r.openScope()
	pos := r.pos()
	init := r.stmt()

	var tag ir.Node
	var ident *ir.Ident
	var iface *types.Type
	if r.Bool() {
		pos := r.pos()
		if r.Bool() {
			ident = ir.NewIdent(r.pos(), r.localIdent())
		}
		x := r.expr()
		iface = x.Type()
		tag = ir.NewTypeSwitchGuard(pos, ident, x)
	} else {
		tag = r.optExpr()
	}

	clauses := make([]*ir.CaseClause, r.Len())
	for i := range clauses {
		if i > 0 {
			r.closeScope()
		}
		r.openScope()

		pos := r.pos()
		var cases, rtypes []ir.Node
		if iface != nil {
			cases = make([]ir.Node, r.Len())
			if len(cases) == 0 {
				cases = nil // TODO(mdempsky): Unclear if this matters.
			}
			for i := range cases {
				if r.Bool() { // case nil
					cases[i] = typecheck.Expr(types.BuiltinPkg.Lookup("nil").Def.(*ir.NilExpr))
				} else {
					cases[i] = r.exprType()
				}
			}
		} else {
			cases = r.exprList()

			// For `switch { case any(true): }` (e.g., issue 3980 in
			// test/switch.go), the backend still creates a mixed bool/any
			// comparison, and we need to explicitly supply the RTTI for the
			// comparison.
			//
			// TODO(mdempsky): Change writer.go to desugar "switch {" into
			// "switch true {", which we already handle correctly.
			if tag == nil {
				for i, cas := range cases {
					if cas.Type().IsEmptyInterface() {
						for len(rtypes) < i {
							rtypes = append(rtypes, nil)
						}
						rtypes = append(rtypes, reflectdata.TypePtrAt(cas.Pos(), types.Types[types.TBOOL]))
					}
				}
			}
		}

		clause := ir.NewCaseStmt(pos, cases, nil)
		clause.RTypes = rtypes

		if ident != nil {
			name := r.curfn.NewLocal(r.pos(), ident.Sym(), r.typ())
			r.addLocal(name)
			clause.Var = name
			name.Defn = tag
		}

		clause.Body = r.stmts()
		clauses[i] = clause
	}
	if len(clauses) > 0 {
		r.closeScope()
	}
	r.closeScope()

	n := ir.NewSwitchStmt(pos, tag, clauses)
	n.Label = label
	if init != nil {
		n.SetInit([]ir.Node{init})
	}
	return n
}

func (r *reader) label() *types.Sym {
	r.Sync(pkgbits.SyncLabel)
	name := r.String()
	if r.inlCall != nil && name != "_" {
		name = fmt.Sprintf("~%s·%d", name, inlgen)
	}
	return typecheck.Lookup(name)
}

func (r *reader) optLabel() *types.Sym {
	r.Sync(pkgbits.SyncOptLabel)
	if r.Bool() {
		return r.label()
	}
	return nil
}

// initDefn marks the given names as declared by defn and populates
// its Init field with ODCL nodes. It then reports whether any names
// were so declared, which can be used to initialize defn.Def.
func (r *reader) initDefn(defn ir.InitNode, names []*ir.Name) bool {
	if len(names) == 0 {
		return false
	}

	init := make([]ir.Node, len(names))
	for i, name := range names {
		name.Defn = defn
		init[i] = ir.NewDecl(name.Pos(), ir.ODCL, name)
	}
	defn.SetInit(init)
	return true
}

// @@@ Expressions

// expr reads and returns a typechecked expression.
func (r *reader) expr() (res ir.Node) {
	defer func() {
		if res != nil && res.Typecheck() == 0 {
			base.FatalfAt(res.Pos(), "%v missed typecheck", res)
		}
	}()

	switch tag := codeExpr(r.Code(pkgbits.SyncExpr)); tag {
	default:
		panic("unhandled expression")

	case exprLocal:
		return typecheck.Expr(r.useLocal())

	case exprGlobal:
		// Callee instead of Expr allows builtins
		// TODO(mdempsky): Handle builtins directly in exprCall, like method calls?
		return typecheck.Callee(r.obj())

	case exprFuncInst:
		origPos, pos := r.origPos()
		wrapperFn, baseFn, dictPtr := r.funcInst(pos)
		if wrapperFn != nil {
			return wrapperFn
		}
		return r.curry(origPos, false, baseFn, dictPtr, nil)

	case exprConst:
		pos := r.pos()
		typ := r.typ()
		val := FixValue(typ, r.Value())
		return ir.NewBasicLit(pos, typ, val)

	case exprZero:
		pos := r.pos()
		typ := r.typ()
		return ir.NewZero(pos, typ)

	case exprCompLit:
		return r.compLit()

	case exprFuncLit:
		return r.funcLit()

	case exprFieldVal:
		x := r.expr()
		pos := r.pos()
		sym := r.selector()

		return typecheck.XDotField(pos, x, sym)

	case exprMethodVal:
		recv := r.expr()
		origPos, pos := r.origPos()
		wrapperFn, baseFn, dictPtr := r.methodExpr()

		// For simple wrapperFn values, the existing machinery for creating
		// and deduplicating wrapperFn value wrappers still works fine.
		if wrapperFn, ok := wrapperFn.(*ir.SelectorExpr); ok && wrapperFn.Op() == ir.OMETHEXPR {
			// The receiver expression we constructed may have a shape type.
			// For example, in fixedbugs/issue54343.go, `New[int]()` is
			// constructed as `New[go.shape.int](&.dict.New[int])`, which
			// has type `*T[go.shape.int]`, not `*T[int]`.
			//
			// However, the method we want to select here is `(*T[int]).M`,
			// not `(*T[go.shape.int]).M`, so we need to manually convert
			// the type back so that the OXDOT resolves correctly.
			//
			// TODO(mdempsky): Logically it might make more sense for
			// exprCall to take responsibility for setting a non-shaped
			// result type, but this is the only place where we care
			// currently. And only because existing ir.OMETHVALUE backend
			// code relies on n.X.Type() instead of n.Selection.Recv().Type
			// (because the latter is types.FakeRecvType() in the case of
			// interface method values).
			//
			if recv.Type().HasShape() {
				typ := wrapperFn.Type().Param(0).Type
				if !types.Identical(typ, recv.Type()) {
					base.FatalfAt(wrapperFn.Pos(), "receiver %L does not match %L", recv, wrapperFn)
				}
				recv = typecheck.Expr(ir.NewConvExpr(recv.Pos(), ir.OCONVNOP, typ, recv))
			}

			n := typecheck.XDotMethod(pos, recv, wrapperFn.Sel, false)

			// As a consistency check here, we make sure "n" selected the
			// same method (represented by a types.Field) that wrapperFn
			// selected. However, for anonymous receiver types, there can be
			// multiple such types.Field instances (#58563). So we may need
			// to fallback to making sure Sym and Type (including the
			// receiver parameter's type) match.
			if n.Selection != wrapperFn.Selection {
				assert(n.Selection.Sym == wrapperFn.Selection.Sym)
				assert(types.Identical(n.Selection.Type, wrapperFn.Selection.Type))
				assert(types.Identical(n.Selection.Type.Recv().Type, wrapperFn.Selection.Type.Recv().Type))
			}

			wrapper := methodValueWrapper{
				rcvr:   n.X.Type(),
				method: n.Selection,
			}

			if r.importedDef() {
				haveMethodValueWrappers = append(haveMethodValueWrappers, wrapper)
			} else {
				needMethodValueWrappers = append(needMethodValueWrappers, wrapper)
			}
			return n
		}

		// For more complicated method expressions, we construct a
		// function literal wrapper.
		return r.curry(origPos, true, baseFn, recv, dictPtr)

	case exprMethodExpr:
		recv := r.typ()

		implicits := make([]int, r.Len())
		for i := range implicits {
			implicits[i] = r.Len()
		}
		var deref, addr bool
		if r.Bool() {
			deref = true
		} else if r.Bool() {
			addr = true
		}

		origPos, pos := r.origPos()
		wrapperFn, baseFn, dictPtr := r.methodExpr()

		// If we already have a wrapper and don't need to do anything with
		// it, we can just return the wrapper directly.
		//
		// N.B., we use implicits/deref/addr here as the source of truth
		// rather than types.Identical, because the latter can be confused
		// by tricky promoted methods (e.g., typeparam/mdempsky/21.go).
		if wrapperFn != nil && len(implicits) == 0 && !deref && !addr {
			if !types.Identical(recv, wrapperFn.Type().Param(0).Type) {
				base.FatalfAt(pos, "want receiver type %v, but have method %L", recv, wrapperFn)
			}
			return wrapperFn
		}

		// Otherwise, if the wrapper function is a static method
		// expression (OMETHEXPR) and the receiver type is unshaped, then
		// we can rely on a statically generated wrapper being available.
		if method, ok := wrapperFn.(*ir.SelectorExpr); ok && method.Op() == ir.OMETHEXPR && !recv.HasShape() {
			return typecheck.NewMethodExpr(pos, recv, method.Sel)
		}

		return r.methodExprWrap(origPos, recv, implicits, deref, addr, baseFn, dictPtr)

	case exprIndex:
		x := r.expr()
		pos := r.pos()
		index := r.expr()
		n := typecheck.Expr(ir.NewIndexExpr(pos, x, index))
		switch n.Op() {
		case ir.OINDEXMAP:
			n := n.(*ir.IndexExpr)
			n.RType = r.rtype(pos)
		}
		return n

	case exprSlice:
		x := r.expr()
		pos := r.pos()
		var index [3]ir.Node
		for i := range index {
			index[i] = r.optExpr()
		}
		op := ir.OSLICE
		if index[2] != nil {
			op = ir.OSLICE3
		}
		return typecheck.Expr(ir.NewSliceExpr(pos, op, x, index[0], index[1], index[2]))

	case exprAssert:
		x := r.expr()
		pos := r.pos()
		typ := r.exprType()
		srcRType := r.rtype(pos)

		// TODO(mdempsky): Always emit ODYNAMICDOTTYPE for uniformity?
		if typ, ok := typ.(*ir.DynamicType); ok && typ.Op() == ir.ODYNAMICTYPE {
			assert := ir.NewDynamicTypeAssertExpr(pos, ir.ODYNAMICDOTTYPE, x, typ.RType)
			assert.SrcRType = srcRType
			assert.ITab = typ.ITab
			return typed(typ.Type(), assert)
		}
		return typecheck.Expr(ir.NewTypeAssertExpr(pos, x, typ.Type()))

	case exprUnaryOp:
		op := r.op()
		pos := r.pos()
		x := r.expr()

		switch op {
		case ir.OADDR:
			return typecheck.Expr(typecheck.NodAddrAt(pos, x))
		case ir.ODEREF:
			return typecheck.Expr(ir.NewStarExpr(pos, x))
		}
		return typecheck.Expr(ir.NewUnaryExpr(pos, op, x))

	case exprBinaryOp:
		op := r.op()
		x := r.expr()
		pos := r.pos()
		y := r.expr()

		switch op {
		case ir.OANDAND, ir.OOROR:
			return typecheck.Expr(ir.NewLogicalExpr(pos, op, x, y))
		case ir.OLSH, ir.ORSH:
			// Untyped rhs of non-constant shift, e.g. x << 1.0.
			// If we have a constant value, it must be an int >= 0.
			if ir.IsConstNode(y) {
				val := constant.ToInt(y.Val())
				assert(val.Kind() == constant.Int && constant.Sign(val) >= 0)
			}
		}
		return typecheck.Expr(ir.NewBinaryExpr(pos, op, x, y))

	case exprRecv:
		x := r.expr()
		pos := r.pos()
		for i, n := 0, r.Len(); i < n; i++ {
			x = Implicit(typecheck.DotField(pos, x, r.Len()))
		}
		if r.Bool() { // needs deref
			x = Implicit(Deref(pos, x.Type().Elem(), x))
		} else if r.Bool() { // needs addr
			x = Implicit(Addr(pos, x))
		}
		return x

	case exprCall:
		var fun ir.Node
		var args ir.Nodes
		if r.Bool() { // method call
			recv := r.expr()
			_, method, dictPtr := r.methodExpr()

			if recv.Type().IsInterface() && method.Op() == ir.OMETHEXPR {
				method := method.(*ir.SelectorExpr)

				// The compiler backend (e.g., devirtualization) handle
				// OCALLINTER/ODOTINTER better than OCALLFUNC/OMETHEXPR for
				// interface calls, so we prefer to continue constructing
				// calls that way where possible.
				//
				// There are also corner cases where semantically it's perhaps
				// significant; e.g., fixedbugs/issue15975.go, #38634, #52025.

				fun = typecheck.XDotMethod(method.Pos(), recv, method.Sel, true)
			} else {
				if recv.Type().IsInterface() {
					// N.B., this happens currently for typeparam/issue51521.go
					// and typeparam/typeswitch3.go.
					if base.Flag.LowerM != 0 {
						base.WarnfAt(method.Pos(), "imprecise interface call")
					}
				}

				fun = method
				args.Append(recv)
			}
			if dictPtr != nil {
				args.Append(dictPtr)
			}
		} else if r.Bool() { // call to instanced function
			pos := r.pos()
			_, shapedFn, dictPtr := r.funcInst(pos)
			fun = shapedFn
			args.Append(dictPtr)
		} else {
			fun = r.expr()
		}
		pos := r.pos()
		args.Append(r.multiExpr()...)
		dots := r.Bool()
		n := typecheck.Call(pos, fun, args, dots)
		switch n.Op() {
		case ir.OAPPEND:
			n := n.(*ir.CallExpr)
			n.RType = r.rtype(pos)
			// For append(a, b...), we don't need the implicit conversion. The typechecker already
			// ensured that a and b are both slices with the same base type, or []byte and string.
			if n.IsDDD {
				if conv, ok := n.Args[1].(*ir.ConvExpr); ok && conv.Op() == ir.OCONVNOP && conv.Implicit() {
					n.Args[1] = conv.X
				}
			}
		case ir.OCOPY:
			n := n.(*ir.BinaryExpr)
			n.RType = r.rtype(pos)
		case ir.ODELETE:
			n := n.(*ir.CallExpr)
			n.RType = r.rtype(pos)
		case ir.OUNSAFESLICE:
			n := n.(*ir.BinaryExpr)
			n.RType = r.rtype(pos)
		}
		return n

	case exprMake:
		pos := r.pos()
		typ := r.exprType()
		extra := r.exprs()
		n := typecheck.Expr(ir.NewCallExpr(pos, ir.OMAKE, nil, append([]ir.Node{typ}, extra...))).(*ir.MakeExpr)
		n.RType = r.rtype(pos)
		return n

	case exprNew:
		pos := r.pos()
		typ := r.exprType()
		return typecheck.Expr(ir.NewUnaryExpr(pos, ir.ONEW, typ))

	case exprSizeof:
		return ir.NewUintptr(r.pos(), r.typ().Size())

	case exprAlignof:
		return ir.NewUintptr(r.pos(), r.typ().Alignment())

	case exprOffsetof:
		pos := r.pos()
		typ := r.typ()
		types.CalcSize(typ)

		var offset int64
		for i := r.Len(); i >= 0; i-- {
			field := typ.Fi
"""




```