Response: The user wants to understand the functionality of the provided Go code snippet. The code is part of the `noder` package in the Go compiler, specifically the `writer.go` file.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The initial comments clearly state the file implements the "Unified IR package writer." This immediately tells us the code is responsible for converting Go language constructs into a specific binary format for later use (like linking or inlining).

2. **Key Types and Their Roles:** The comments highlight `writer` and `pkgWriter`. Focus on understanding their individual responsibilities.
    * `pkgWriter`:  Manages the overall writing process for a package, keeps track of already written elements (to avoid redundancy), and holds package-level information. Think of it as the orchestrator.
    * `writer`: Handles the writing of individual elements into the binary stream. It works within the context of a specific element and interacts with `pkgbits`.

3. **Method Structure:** The comments mention patterns like `writer.thing`, `pkgWriter.thingIdx`, and `writer.doThing`. Recognize this as a systematic approach for writing different kinds of Go language elements.
    * `writer.thing`: Writes a "use" or reference to an already defined element.
    * `pkgWriter.thingIdx`: Reserves an index and initiates the writing process for a new element.
    * `writer.doThing`: Writes the actual definition of an element.

4. **Dependencies:** Note the imports, especially `internal/pkgbits`. This confirms the low-level encoding is handled by another internal package.

5. **Infer Go Feature Implementation (High-Level):** Based on the types and methods, infer the general Go language features being handled. Keywords like "package," "object," "type," "function body," "statements," and "expressions" are strong indicators. This suggests the code is involved in representing the entire structure and semantics of Go code.

6. **Go Code Example (Illustrative):**  Create a simple Go example that demonstrates the kind of constructs this writer would process. A basic function with a local variable and a type declaration is sufficient. This example needs to be simple enough to understand and map to the writer's responsibilities.

7. **Reasoning about Input and Output:** Explain that the input to this part of the compiler is the output of the type checker (`types2.Info`, `types2.Package`) and the parsed syntax tree (`syntax`). The output is the encoded binary data representing the package's IR.

8. **Command-Line Parameters (Speculative):**  Since this is part of the compiler, think about relevant command-line flags. Flags related to debugging, synchronization markers (as seen in the code), and potentially experiments (like `aliasTypeParams`) are good candidates.

9. **Common Mistakes (Speculative):** Consider potential pitfalls for users *if* they were interacting directly with this (which they don't typically). Focus on things like version mismatches or corruption of the export data. Since this is internal, direct user mistakes are unlikely, so keep this section brief or skip if unsure.

10. **Summarize the Functionality:** Combine the understanding of the key types, methods, and inferred Go features into a concise summary.

11. **Review and Refine:** Read through the generated answer to ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or missing information. For instance, ensure the Go example aligns with the functionalities described. Double-check the explanation of command-line flags and common mistakes for plausibility.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the low-level details of `pkgbits`. However, the prompt emphasizes understanding the *functionality* at a higher level. The comments explicitly state that `pkgbits` handles the low-level aspects, so the answer should reflect that separation of concerns.
* I considered providing a more complex Go example with generics, but a simpler example is more effective for illustrating the basic concepts. Generics could be mentioned as a feature handled by the writer.
* I initially thought about including specific details about the binary format. However, the prompt asks for functionality, and the comments indicate the format is documented elsewhere (and subject to change). Stick to the higher-level purpose.
* Regarding common mistakes, it's important to frame these as *potential* issues if users were directly manipulating the output, rather than actual user errors in normal Go development.

By following these steps, the generated answer effectively addresses the user's request, providing a comprehensive overview of the `writer.go` file's functionality.
好的，让我们来分析一下 `go/src/cmd/compile/internal/noder/writer.go` 这个文件的部分代码的功能。

**核心功能归纳：**

这段代码的主要功能是**将 Go 语言的类型检查器（types2）的输出信息和抽象语法树（syntax）表示的 Go 源代码，转换为一种中间表示形式，称为 Unified IR (Unified Intermediate Representation) 的导出数据。**  这种导出数据会被 Go 编译器的后续阶段使用，例如链接器和内联优化器。

**具体功能点：**

1. **定义了 Unified IR 导出数据的格式：** 代码中定义了 `pkgWriter` 和 `writer` 两个核心类型，以及一系列用于编码不同 Go 语言构造（如位置信息、包、对象、类型等）的方法。这些方法共同定义了 Unified IR 的序列化格式。

2. **实现了将 Go 语言构造映射到 Unified IR 元素的方法：**
   - 提供了将各种 Go 语言实体（例如 `types2.Package`, `types2.Type`, `types2.Object`, `syntax.Expr`, `syntax.Stmt` 等）编码到 Unified IR 的方法，例如 `writer.pos`, `writer.pkg`, `writer.typ`, `writer.obj`, `writer.stmt`, `writer.expr` 等。
   - 使用 `internal/pkgbits` 包来处理底层的字节编码和交叉引用。

3. **管理已编码的元素：** `pkgWriter` 负责跟踪哪些元素已经被编码，以避免重复编码，并为每个元素分配一个唯一的索引。

4. **处理类型和对象的字典信息：** `writerDict` 用于跟踪当前声明使用的类型和对象，特别是用于处理泛型类型参数和派生类型。

5. **处理函数体：** 提供了编码函数体（`bodyIdx`）、局部变量、闭包变量以及语句和表达式的方法。

6. **处理泛型：**  代码中大量涉及到对泛型的处理，包括类型参数的编码、泛型函数的实例化、以及运行时字典信息的编码。

7. **处理编译器扩展：** 提供了编码编译器特定的扩展信息的方法，例如 `//go:linkname` 和 `//go:cgo_*` 指令。

**推理 Go 语言功能的实现（带有 Go 代码示例）：**

这段代码是 Go 编译器将高级的 Go 语言结构转换为更底层的、可被后续编译器阶段处理的形式的关键部分。它涉及到许多核心的 Go 语言功能。

**示例：类型定义和使用**

假设我们有以下 Go 代码：

```go
package main

type MyInt int

func main() {
	var x MyInt = 10
	println(x)
}
```

`writer.go` 中的代码会处理 `MyInt` 类型的定义和使用。

**假设输入：**

- `pkg`: 指向 `main` 包的 `types2.Package` 对象。
- `info`: 包含类型信息的 `types2.Info` 对象，其中包含 `MyInt` 的类型定义。
- `syntax`: `MyInt` 的 `syntax.TypeDecl` 节点。
- `x` 的 `types2.Var` 对象。

**相关方法调用（简化）：**

1. `pkgWriter.typIdx(MyInt的types2.Type)`:  为 `MyInt` 类型分配索引并编码其定义。这将调用 `writer.doThing` 中的类型相关的分支，最终调用 `writer.namedType` 来处理命名类型。
2. `pkgWriter.objIdx(MyInt的types2.TypeName)`: 为 `MyInt` 类型名分配索引并编码其定义。
3. 在 `main` 函数的编码过程中，当遇到 `var x MyInt` 时，会调用 `writer.typ(MyInt的types2.Type)` 来引用 `MyInt` 类型。
4. 当遇到常量 `10` 时，会调用 `writer.expr` 中的常量处理分支，使用 `writer.typ` 编码其类型（`int`）。

**Unified IR 的可能输出（简化，仅用于说明概念）：**

```
// 类型定义
TypeDef:
  Index: 1
  Kind: Named
  Name: MyInt
  Package: main
  UnderlyingType: int

// 类型引用
TypeRef: 1
```

**示例：函数定义和调用**

假设我们有以下 Go 代码：

```go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	result := add(5, 3)
	println(result)
}
```

**假设输入：**

- `pkg`: 指向 `main` 包的 `types2.Package` 对象。
- `info`: 包含类型和对象信息的 `types2.Info` 对象。
- `syntax`: `add` 和 `main` 函数的 `syntax.FuncDecl` 节点。
- `add` 函数的 `types2.Func` 对象。

**相关方法调用（简化）：**

1. `pkgWriter.objIdx(add的types2.Func)`: 为 `add` 函数分配索引并编码其定义。这会调用 `writer.doObj` 中的函数处理分支，最终调用 `writer.signature` 编码函数签名，并调用 `pkgWriter.bodyIdx` 编码函数体。
2. 在 `main` 函数的编码过程中，当遇到 `add(5, 3)` 调用时，会调用 `writer.expr` 中的函数调用处理分支，最终调用 `writer.obj` 引用 `add` 函数。
3. 常量 `5` 和 `3` 的处理类似于上面的类型示例。

**Unified IR 的可能输出（简化）：**

```
// 函数定义
FuncDef:
  Index: 2
  Name: add
  Package: main
  Signature: ... // 编码函数签名
  Body: ...      // 编码函数体

// 函数调用
Call:
  Function: FuncRef(2)
  Arguments: [Const(5), Const(3)]
```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 Go 编译器的更上层，例如 `cmd/compile/internal/gc` 包。然而，代码中会用到一些全局的配置信息，这些信息可能受命令行参数影响，例如：

- `base.Debug.SyncFrames`:  这可能与 `-d=syncframes` 或类似的调试标志有关，用于在导出数据中插入同步帧信息。
- `buildcfg.Experiment.AliasTypeParams`: 这可能与 `-lang=go1.18` 或更新的版本设置有关，用于控制是否使用 V2 版本的编码。

**易犯错的点：**

作为 Go 编译器的内部实现，开发者通常不会直接与这段代码交互。然而，如果修改了这段代码，一些常见的错误点可能包括：

- **不正确地处理类型或对象的编码：**  例如，忘记处理某种特定的类型或对象，或者编码的顺序或内容不正确，会导致后续的编译器阶段无法正确解析 Unified IR。
- **引入不一致的索引：** 如果 `pkgWriter` 没有正确地跟踪已编码的元素，可能会导致对同一个元素分配了不同的索引，从而破坏交叉引用。
- **未能正确处理泛型相关的编码：** 泛型的编码比较复杂，需要正确处理类型参数、类型实参以及运行时字典信息。
- **修改了 `internal/pkgbits` 的接口但没有同步更新 `writer.go`：**  `writer.go` 依赖于 `pkgbits` 提供的底层编码接口，如果 `pkgbits` 的接口发生变化，`writer.go` 也需要相应地更新。

**这段代码（第 1 部分）的功能归纳：**

这段 `writer.go` 代码的核心功能是 **Go 编译器的 Unified IR 导出器的前半部分**。它负责：

- **初始化导出器 (`pkgWriter`) 并配置编码版本。**
- **管理全局的包、类型和对象索引。**
- **提供用于编写基本类型（如位置、包）的方法。**
- **提供用于编写复杂类型定义（如命名类型、数组、切片、函数签名等）的方法。**
- **提供用于编写对象定义（如常量、函数、类型名、变量）的方法，但可能不包含函数体的完整编码（这可能是第 2 部分的内容）。**

这段代码建立了将 Go 语言的语义信息转换为 Unified IR 格式的基础框架和核心方法。后续的代码（第 2 部分）可能会专注于更复杂的结构的编码，例如函数体的具体实现细节。

### 提示词
```
这是路径为go/src/cmd/compile/internal/noder/writer.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noder

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/version"
	"internal/buildcfg"
	"internal/pkgbits"
	"os"
	"strings"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/syntax"
	"cmd/compile/internal/types"
	"cmd/compile/internal/types2"
)

// This file implements the Unified IR package writer and defines the
// Unified IR export data format.
//
// Low-level coding details (e.g., byte-encoding of individual
// primitive values, or handling element bitstreams and
// cross-references) are handled by internal/pkgbits, so here we only
// concern ourselves with higher-level worries like mapping Go
// language constructs into elements.

// There are two central types in the writing process: the "writer"
// type handles writing out individual elements, while the "pkgWriter"
// type keeps track of which elements have already been created.
//
// For each sort of "thing" (e.g., position, package, object, type)
// that can be written into the export data, there are generally
// several methods that work together:
//
// - writer.thing handles writing out a *use* of a thing, which often
//   means writing a relocation to that thing's encoded index.
//
// - pkgWriter.thingIdx handles reserving an index for a thing, and
//   writing out any elements needed for the thing.
//
// - writer.doThing handles writing out the *definition* of a thing,
//   which in general is a mix of low-level coding primitives (e.g.,
//   ints and strings) or uses of other things.
//
// A design goal of Unified IR is to have a single, canonical writer
// implementation, but multiple reader implementations each tailored
// to their respective needs. For example, within cmd/compile's own
// backend, inlining is implemented largely by just re-running the
// function body reading code.

// TODO(mdempsky): Add an importer for Unified IR to the x/tools repo,
// and better document the file format boundary between public and
// private data.

type index = pkgbits.Index

func assert(p bool) { base.Assert(p) }

// A pkgWriter constructs Unified IR export data from the results of
// running the types2 type checker on a Go compilation unit.
type pkgWriter struct {
	pkgbits.PkgEncoder

	m                     posMap
	curpkg                *types2.Package
	info                  *types2.Info
	rangeFuncBodyClosures map[*syntax.FuncLit]bool // non-public information, e.g., which functions are closures range function bodies?

	// Indices for previously written syntax and types2 things.

	posBasesIdx map[*syntax.PosBase]index
	pkgsIdx     map[*types2.Package]index
	typsIdx     map[types2.Type]index
	objsIdx     map[types2.Object]index

	// Maps from types2.Objects back to their syntax.Decl.

	funDecls map[*types2.Func]*syntax.FuncDecl
	typDecls map[*types2.TypeName]typeDeclGen

	// linknames maps package-scope objects to their linker symbol name,
	// if specified by a //go:linkname directive.
	linknames map[types2.Object]string

	// cgoPragmas accumulates any //go:cgo_* pragmas that need to be
	// passed through to cmd/link.
	cgoPragmas [][]string
}

// newPkgWriter returns an initialized pkgWriter for the specified
// package.
func newPkgWriter(m posMap, pkg *types2.Package, info *types2.Info, otherInfo map[*syntax.FuncLit]bool) *pkgWriter {
	// Use V2 as the encoded version aliastypeparams GOEXPERIMENT is enabled.
	version := pkgbits.V1
	if buildcfg.Experiment.AliasTypeParams {
		version = pkgbits.V2
	}
	return &pkgWriter{
		PkgEncoder: pkgbits.NewPkgEncoder(version, base.Debug.SyncFrames),

		m:                     m,
		curpkg:                pkg,
		info:                  info,
		rangeFuncBodyClosures: otherInfo,

		pkgsIdx: make(map[*types2.Package]index),
		objsIdx: make(map[types2.Object]index),
		typsIdx: make(map[types2.Type]index),

		posBasesIdx: make(map[*syntax.PosBase]index),

		funDecls: make(map[*types2.Func]*syntax.FuncDecl),
		typDecls: make(map[*types2.TypeName]typeDeclGen),

		linknames: make(map[types2.Object]string),
	}
}

// errorf reports a user error about thing p.
func (pw *pkgWriter) errorf(p poser, msg string, args ...interface{}) {
	base.ErrorfAt(pw.m.pos(p), 0, msg, args...)
}

// fatalf reports an internal compiler error about thing p.
func (pw *pkgWriter) fatalf(p poser, msg string, args ...interface{}) {
	base.FatalfAt(pw.m.pos(p), msg, args...)
}

// unexpected reports a fatal error about a thing of unexpected
// dynamic type.
func (pw *pkgWriter) unexpected(what string, p poser) {
	pw.fatalf(p, "unexpected %s: %v (%T)", what, p, p)
}

func (pw *pkgWriter) typeAndValue(x syntax.Expr) syntax.TypeAndValue {
	tv, ok := pw.maybeTypeAndValue(x)
	if !ok {
		pw.fatalf(x, "missing Types entry: %v", syntax.String(x))
	}
	return tv
}

func (pw *pkgWriter) maybeTypeAndValue(x syntax.Expr) (syntax.TypeAndValue, bool) {
	tv := x.GetTypeInfo()

	// If x is a generic function whose type arguments are inferred
	// from assignment context, then we need to find its inferred type
	// in Info.Instances instead.
	if name, ok := x.(*syntax.Name); ok {
		if inst, ok := pw.info.Instances[name]; ok {
			tv.Type = inst.Type
		}
	}

	return tv, tv.Type != nil
}

// typeOf returns the Type of the given value expression.
func (pw *pkgWriter) typeOf(expr syntax.Expr) types2.Type {
	tv := pw.typeAndValue(expr)
	if !tv.IsValue() {
		pw.fatalf(expr, "expected value: %v", syntax.String(expr))
	}
	return tv.Type
}

// A writer provides APIs for writing out an individual element.
type writer struct {
	p *pkgWriter

	pkgbits.Encoder

	// sig holds the signature for the current function body, if any.
	sig *types2.Signature

	// TODO(mdempsky): We should be able to prune localsIdx whenever a
	// scope closes, and then maybe we can just use the same map for
	// storing the TypeParams too (as their TypeName instead).

	// localsIdx tracks any local variables declared within this
	// function body. It's unused for writing out non-body things.
	localsIdx map[*types2.Var]int

	// closureVars tracks any free variables that are referenced by this
	// function body. It's unused for writing out non-body things.
	closureVars    []posVar
	closureVarsIdx map[*types2.Var]int // index of previously seen free variables

	dict *writerDict

	// derived tracks whether the type being written out references any
	// type parameters. It's unused for writing non-type things.
	derived bool
}

// A writerDict tracks types and objects that are used by a declaration.
type writerDict struct {
	// implicits is a slice of type parameters from the enclosing
	// declarations.
	implicits []*types2.TypeParam

	// derived is a slice of type indices for computing derived types
	// (i.e., types that depend on the declaration's type parameters).
	derived []derivedInfo

	// derivedIdx maps a Type to its corresponding index within the
	// derived slice, if present.
	derivedIdx map[types2.Type]index

	// These slices correspond to entries in the runtime dictionary.
	typeParamMethodExprs []writerMethodExprInfo
	subdicts             []objInfo
	rtypes               []typeInfo
	itabs                []itabInfo
}

type itabInfo struct {
	typ   typeInfo
	iface typeInfo
}

// typeParamIndex returns the index of the given type parameter within
// the dictionary. This may differ from typ.Index() when there are
// implicit type parameters due to defined types declared within a
// generic function or method.
func (dict *writerDict) typeParamIndex(typ *types2.TypeParam) int {
	for idx, implicit := range dict.implicits {
		if implicit == typ {
			return idx
		}
	}

	return len(dict.implicits) + typ.Index()
}

// A derivedInfo represents a reference to an encoded generic Go type.
type derivedInfo struct {
	idx index
}

// A typeInfo represents a reference to an encoded Go type.
//
// If derived is true, then the typeInfo represents a generic Go type
// that contains type parameters. In this case, idx is an index into
// the readerDict.derived{,Types} arrays.
//
// Otherwise, the typeInfo represents a non-generic Go type, and idx
// is an index into the reader.typs array instead.
type typeInfo struct {
	idx     index
	derived bool
}

// An objInfo represents a reference to an encoded, instantiated (if
// applicable) Go object.
type objInfo struct {
	idx       index      // index for the generic function declaration
	explicits []typeInfo // info for the type arguments
}

// A selectorInfo represents a reference to an encoded field or method
// name (i.e., objects that can only be accessed using selector
// expressions).
type selectorInfo struct {
	pkgIdx  index
	nameIdx index
}

// anyDerived reports whether any of info's explicit type arguments
// are derived types.
func (info objInfo) anyDerived() bool {
	for _, explicit := range info.explicits {
		if explicit.derived {
			return true
		}
	}
	return false
}

// equals reports whether info and other represent the same Go object
// (i.e., same base object and identical type arguments, if any).
func (info objInfo) equals(other objInfo) bool {
	if info.idx != other.idx {
		return false
	}
	assert(len(info.explicits) == len(other.explicits))
	for i, targ := range info.explicits {
		if targ != other.explicits[i] {
			return false
		}
	}
	return true
}

type writerMethodExprInfo struct {
	typeParamIdx int
	methodInfo   selectorInfo
}

// typeParamMethodExprIdx returns the index where the given encoded
// method expression function pointer appears within this dictionary's
// type parameters method expressions section, adding it if necessary.
func (dict *writerDict) typeParamMethodExprIdx(typeParamIdx int, methodInfo selectorInfo) int {
	newInfo := writerMethodExprInfo{typeParamIdx, methodInfo}

	for idx, oldInfo := range dict.typeParamMethodExprs {
		if oldInfo == newInfo {
			return idx
		}
	}

	idx := len(dict.typeParamMethodExprs)
	dict.typeParamMethodExprs = append(dict.typeParamMethodExprs, newInfo)
	return idx
}

// subdictIdx returns the index where the given encoded object's
// runtime dictionary appears within this dictionary's subdictionary
// section, adding it if necessary.
func (dict *writerDict) subdictIdx(newInfo objInfo) int {
	for idx, oldInfo := range dict.subdicts {
		if oldInfo.equals(newInfo) {
			return idx
		}
	}

	idx := len(dict.subdicts)
	dict.subdicts = append(dict.subdicts, newInfo)
	return idx
}

// rtypeIdx returns the index where the given encoded type's
// *runtime._type value appears within this dictionary's rtypes
// section, adding it if necessary.
func (dict *writerDict) rtypeIdx(newInfo typeInfo) int {
	for idx, oldInfo := range dict.rtypes {
		if oldInfo == newInfo {
			return idx
		}
	}

	idx := len(dict.rtypes)
	dict.rtypes = append(dict.rtypes, newInfo)
	return idx
}

// itabIdx returns the index where the given encoded type pair's
// *runtime.itab value appears within this dictionary's itabs section,
// adding it if necessary.
func (dict *writerDict) itabIdx(typInfo, ifaceInfo typeInfo) int {
	newInfo := itabInfo{typInfo, ifaceInfo}

	for idx, oldInfo := range dict.itabs {
		if oldInfo == newInfo {
			return idx
		}
	}

	idx := len(dict.itabs)
	dict.itabs = append(dict.itabs, newInfo)
	return idx
}

func (pw *pkgWriter) newWriter(k pkgbits.RelocKind, marker pkgbits.SyncMarker) *writer {
	return &writer{
		Encoder: pw.NewEncoder(k, marker),
		p:       pw,
	}
}

// @@@ Positions

// pos writes the position of p into the element bitstream.
func (w *writer) pos(p poser) {
	w.Sync(pkgbits.SyncPos)
	pos := p.Pos()

	// TODO(mdempsky): Track down the remaining cases here and fix them.
	if !w.Bool(pos.IsKnown()) {
		return
	}

	// TODO(mdempsky): Delta encoding.
	w.posBase(pos.Base())
	w.Uint(pos.Line())
	w.Uint(pos.Col())
}

// posBase writes a reference to the given PosBase into the element
// bitstream.
func (w *writer) posBase(b *syntax.PosBase) {
	w.Reloc(pkgbits.RelocPosBase, w.p.posBaseIdx(b))
}

// posBaseIdx returns the index for the given PosBase.
func (pw *pkgWriter) posBaseIdx(b *syntax.PosBase) index {
	if idx, ok := pw.posBasesIdx[b]; ok {
		return idx
	}

	w := pw.newWriter(pkgbits.RelocPosBase, pkgbits.SyncPosBase)
	w.p.posBasesIdx[b] = w.Idx

	w.String(trimFilename(b))

	if !w.Bool(b.IsFileBase()) {
		w.pos(b)
		w.Uint(b.Line())
		w.Uint(b.Col())
	}

	return w.Flush()
}

// @@@ Packages

// pkg writes a use of the given Package into the element bitstream.
func (w *writer) pkg(pkg *types2.Package) {
	w.pkgRef(w.p.pkgIdx(pkg))
}

func (w *writer) pkgRef(idx index) {
	w.Sync(pkgbits.SyncPkg)
	w.Reloc(pkgbits.RelocPkg, idx)
}

// pkgIdx returns the index for the given package, adding it to the
// package export data if needed.
func (pw *pkgWriter) pkgIdx(pkg *types2.Package) index {
	if idx, ok := pw.pkgsIdx[pkg]; ok {
		return idx
	}

	w := pw.newWriter(pkgbits.RelocPkg, pkgbits.SyncPkgDef)
	pw.pkgsIdx[pkg] = w.Idx

	// The universe and package unsafe need to be handled specially by
	// importers anyway, so we serialize them using just their package
	// path. This ensures that readers don't confuse them for
	// user-defined packages.
	switch pkg {
	case nil: // universe
		w.String("builtin") // same package path used by godoc
	case types2.Unsafe:
		w.String("unsafe")
	default:
		// TODO(mdempsky): Write out pkg.Path() for curpkg too.
		var path string
		if pkg != w.p.curpkg {
			path = pkg.Path()
		}
		base.Assertf(path != "builtin" && path != "unsafe", "unexpected path for user-defined package: %q", path)
		w.String(path)
		w.String(pkg.Name())

		w.Len(len(pkg.Imports()))
		for _, imp := range pkg.Imports() {
			w.pkg(imp)
		}
	}

	return w.Flush()
}

// @@@ Types

var (
	anyTypeName        = types2.Universe.Lookup("any").(*types2.TypeName)
	comparableTypeName = types2.Universe.Lookup("comparable").(*types2.TypeName)
	runeTypeName       = types2.Universe.Lookup("rune").(*types2.TypeName)
)

// typ writes a use of the given type into the bitstream.
func (w *writer) typ(typ types2.Type) {
	w.typInfo(w.p.typIdx(typ, w.dict))
}

// typInfo writes a use of the given type (specified as a typeInfo
// instead) into the bitstream.
func (w *writer) typInfo(info typeInfo) {
	w.Sync(pkgbits.SyncType)
	if w.Bool(info.derived) {
		w.Len(int(info.idx))
		w.derived = true
	} else {
		w.Reloc(pkgbits.RelocType, info.idx)
	}
}

// typIdx returns the index where the export data description of type
// can be read back in. If no such index exists yet, it's created.
//
// typIdx also reports whether typ is a derived type; that is, whether
// its identity depends on type parameters.
func (pw *pkgWriter) typIdx(typ types2.Type, dict *writerDict) typeInfo {
	// Strip non-global aliases, because they only appear in inline
	// bodies anyway. Otherwise, they can cause types.Sym collisions
	// (e.g., "main.C" for both of the local type aliases in
	// test/fixedbugs/issue50190.go).
	for {
		if alias, ok := typ.(*types2.Alias); ok && !isGlobal(alias.Obj()) {
			typ = alias.Rhs()
		} else {
			break
		}
	}

	if idx, ok := pw.typsIdx[typ]; ok {
		return typeInfo{idx: idx, derived: false}
	}
	if dict != nil {
		if idx, ok := dict.derivedIdx[typ]; ok {
			return typeInfo{idx: idx, derived: true}
		}
	}

	w := pw.newWriter(pkgbits.RelocType, pkgbits.SyncTypeIdx)
	w.dict = dict

	switch typ := typ.(type) {
	default:
		base.Fatalf("unexpected type: %v (%T)", typ, typ)

	case *types2.Basic:
		switch kind := typ.Kind(); {
		case kind == types2.Invalid:
			base.Fatalf("unexpected types2.Invalid")

		case types2.Typ[kind] == typ:
			w.Code(pkgbits.TypeBasic)
			w.Len(int(kind))

		default:
			// Handle "byte" and "rune" as references to their TypeNames.
			obj := types2.Universe.Lookup(typ.Name()).(*types2.TypeName)
			assert(obj.Type() == typ)

			w.Code(pkgbits.TypeNamed)
			w.namedType(obj, nil)
		}

	case *types2.Named:
		w.Code(pkgbits.TypeNamed)
		w.namedType(splitNamed(typ))

	case *types2.Alias:
		w.Code(pkgbits.TypeNamed)
		w.namedType(splitAlias(typ))

	case *types2.TypeParam:
		w.derived = true
		w.Code(pkgbits.TypeTypeParam)
		w.Len(w.dict.typeParamIndex(typ))

	case *types2.Array:
		w.Code(pkgbits.TypeArray)
		w.Uint64(uint64(typ.Len()))
		w.typ(typ.Elem())

	case *types2.Chan:
		w.Code(pkgbits.TypeChan)
		w.Len(int(typ.Dir()))
		w.typ(typ.Elem())

	case *types2.Map:
		w.Code(pkgbits.TypeMap)
		w.typ(typ.Key())
		w.typ(typ.Elem())

	case *types2.Pointer:
		w.Code(pkgbits.TypePointer)
		w.typ(typ.Elem())

	case *types2.Signature:
		base.Assertf(typ.TypeParams() == nil, "unexpected type params: %v", typ)
		w.Code(pkgbits.TypeSignature)
		w.signature(typ)

	case *types2.Slice:
		w.Code(pkgbits.TypeSlice)
		w.typ(typ.Elem())

	case *types2.Struct:
		w.Code(pkgbits.TypeStruct)
		w.structType(typ)

	case *types2.Interface:
		// Handle "any" as reference to its TypeName.
		// The underlying "any" interface is canonical, so this logic handles both
		// GODEBUG=gotypesalias=1 (when any is represented as a types2.Alias), and
		// gotypesalias=0.
		if types2.Unalias(typ) == types2.Unalias(anyTypeName.Type()) {
			w.Code(pkgbits.TypeNamed)
			w.obj(anyTypeName, nil)
			break
		}

		w.Code(pkgbits.TypeInterface)
		w.interfaceType(typ)

	case *types2.Union:
		w.Code(pkgbits.TypeUnion)
		w.unionType(typ)
	}

	if w.derived {
		idx := index(len(dict.derived))
		dict.derived = append(dict.derived, derivedInfo{idx: w.Flush()})
		dict.derivedIdx[typ] = idx
		return typeInfo{idx: idx, derived: true}
	}

	pw.typsIdx[typ] = w.Idx
	return typeInfo{idx: w.Flush(), derived: false}
}

// namedType writes a use of the given named type into the bitstream.
func (w *writer) namedType(obj *types2.TypeName, targs *types2.TypeList) {
	// Named types that are declared within a generic function (and
	// thus have implicit type parameters) are always derived types.
	if w.p.hasImplicitTypeParams(obj) {
		w.derived = true
	}

	w.obj(obj, targs)
}

func (w *writer) structType(typ *types2.Struct) {
	w.Len(typ.NumFields())
	for i := 0; i < typ.NumFields(); i++ {
		f := typ.Field(i)
		w.pos(f)
		w.selector(f)
		w.typ(f.Type())
		w.String(typ.Tag(i))
		w.Bool(f.Embedded())
	}
}

func (w *writer) unionType(typ *types2.Union) {
	w.Len(typ.Len())
	for i := 0; i < typ.Len(); i++ {
		t := typ.Term(i)
		w.Bool(t.Tilde())
		w.typ(t.Type())
	}
}

func (w *writer) interfaceType(typ *types2.Interface) {
	// If typ has no embedded types but it's not a basic interface, then
	// the natural description we write out below will fail to
	// reconstruct it.
	if typ.NumEmbeddeds() == 0 && !typ.IsMethodSet() {
		// Currently, this can only happen for the underlying Interface of
		// "comparable", which is needed to handle type declarations like
		// "type C comparable".
		assert(typ == comparableTypeName.Type().(*types2.Named).Underlying())

		// Export as "interface{ comparable }".
		w.Len(0)                         // NumExplicitMethods
		w.Len(1)                         // NumEmbeddeds
		w.Bool(false)                    // IsImplicit
		w.typ(comparableTypeName.Type()) // EmbeddedType(0)
		return
	}

	w.Len(typ.NumExplicitMethods())
	w.Len(typ.NumEmbeddeds())

	if typ.NumExplicitMethods() == 0 && typ.NumEmbeddeds() == 1 {
		w.Bool(typ.IsImplicit())
	} else {
		// Implicit interfaces always have 0 explicit methods and 1
		// embedded type, so we skip writing out the implicit flag
		// otherwise as a space optimization.
		assert(!typ.IsImplicit())
	}

	for i := 0; i < typ.NumExplicitMethods(); i++ {
		m := typ.ExplicitMethod(i)
		sig := m.Type().(*types2.Signature)
		assert(sig.TypeParams() == nil)

		w.pos(m)
		w.selector(m)
		w.signature(sig)
	}

	for i := 0; i < typ.NumEmbeddeds(); i++ {
		w.typ(typ.EmbeddedType(i))
	}
}

func (w *writer) signature(sig *types2.Signature) {
	w.Sync(pkgbits.SyncSignature)
	w.params(sig.Params())
	w.params(sig.Results())
	w.Bool(sig.Variadic())
}

func (w *writer) params(typ *types2.Tuple) {
	w.Sync(pkgbits.SyncParams)
	w.Len(typ.Len())
	for i := 0; i < typ.Len(); i++ {
		w.param(typ.At(i))
	}
}

func (w *writer) param(param *types2.Var) {
	w.Sync(pkgbits.SyncParam)
	w.pos(param)
	w.localIdent(param)
	w.typ(param.Type())
}

// @@@ Objects

// obj writes a use of the given object into the bitstream.
//
// If obj is a generic object, then explicits are the explicit type
// arguments used to instantiate it (i.e., used to substitute the
// object's own declared type parameters).
func (w *writer) obj(obj types2.Object, explicits *types2.TypeList) {
	w.objInfo(w.p.objInstIdx(obj, explicits, w.dict))
}

// objInfo writes a use of the given encoded object into the
// bitstream.
func (w *writer) objInfo(info objInfo) {
	w.Sync(pkgbits.SyncObject)
	if w.Version().Has(pkgbits.DerivedFuncInstance) {
		w.Bool(false)
	}
	w.Reloc(pkgbits.RelocObj, info.idx)

	w.Len(len(info.explicits))
	for _, info := range info.explicits {
		w.typInfo(info)
	}
}

// objInstIdx returns the indices for an object and a corresponding
// list of type arguments used to instantiate it, adding them to the
// export data as needed.
func (pw *pkgWriter) objInstIdx(obj types2.Object, explicits *types2.TypeList, dict *writerDict) objInfo {
	explicitInfos := make([]typeInfo, explicits.Len())
	for i := range explicitInfos {
		explicitInfos[i] = pw.typIdx(explicits.At(i), dict)
	}
	return objInfo{idx: pw.objIdx(obj), explicits: explicitInfos}
}

// objIdx returns the index for the given Object, adding it to the
// export data as needed.
func (pw *pkgWriter) objIdx(obj types2.Object) index {
	// TODO(mdempsky): Validate that obj is a global object (or a local
	// defined type, which we hoist to global scope anyway).

	if idx, ok := pw.objsIdx[obj]; ok {
		return idx
	}

	dict := &writerDict{
		derivedIdx: make(map[types2.Type]index),
	}

	if isDefinedType(obj) && obj.Pkg() == pw.curpkg {
		decl, ok := pw.typDecls[obj.(*types2.TypeName)]
		assert(ok)
		dict.implicits = decl.implicits
	}

	// We encode objects into 4 elements across different sections, all
	// sharing the same index:
	//
	// - RelocName has just the object's qualified name (i.e.,
	//   Object.Pkg and Object.Name) and the CodeObj indicating what
	//   specific type of Object it is (Var, Func, etc).
	//
	// - RelocObj has the remaining public details about the object,
	//   relevant to go/types importers.
	//
	// - RelocObjExt has additional private details about the object,
	//   which are only relevant to cmd/compile itself. This is
	//   separated from RelocObj so that go/types importers are
	//   unaffected by internal compiler changes.
	//
	// - RelocObjDict has public details about the object's type
	//   parameters and derived type's used by the object. This is
	//   separated to facilitate the eventual introduction of
	//   shape-based stenciling.
	//
	// TODO(mdempsky): Re-evaluate whether RelocName still makes sense
	// to keep separate from RelocObj.

	w := pw.newWriter(pkgbits.RelocObj, pkgbits.SyncObject1)
	wext := pw.newWriter(pkgbits.RelocObjExt, pkgbits.SyncObject1)
	wname := pw.newWriter(pkgbits.RelocName, pkgbits.SyncObject1)
	wdict := pw.newWriter(pkgbits.RelocObjDict, pkgbits.SyncObject1)

	pw.objsIdx[obj] = w.Idx // break cycles
	assert(wext.Idx == w.Idx)
	assert(wname.Idx == w.Idx)
	assert(wdict.Idx == w.Idx)

	w.dict = dict
	wext.dict = dict

	code := w.doObj(wext, obj)
	w.Flush()
	wext.Flush()

	wname.qualifiedIdent(obj)
	wname.Code(code)
	wname.Flush()

	wdict.objDict(obj, w.dict)
	wdict.Flush()

	return w.Idx
}

// doObj writes the RelocObj definition for obj to w, and the
// RelocObjExt definition to wext.
func (w *writer) doObj(wext *writer, obj types2.Object) pkgbits.CodeObj {
	if obj.Pkg() != w.p.curpkg {
		return pkgbits.ObjStub
	}

	switch obj := obj.(type) {
	default:
		w.p.unexpected("object", obj)
		panic("unreachable")

	case *types2.Const:
		w.pos(obj)
		w.typ(obj.Type())
		w.Value(obj.Val())
		return pkgbits.ObjConst

	case *types2.Func:
		decl, ok := w.p.funDecls[obj]
		assert(ok)
		sig := obj.Type().(*types2.Signature)

		w.pos(obj)
		w.typeParamNames(sig.TypeParams())
		w.signature(sig)
		w.pos(decl)
		wext.funcExt(obj)
		return pkgbits.ObjFunc

	case *types2.TypeName:
		if obj.IsAlias() {
			w.pos(obj)
			rhs := obj.Type()
			var tparams *types2.TypeParamList
			if alias, ok := rhs.(*types2.Alias); ok { // materialized alias
				assert(alias.TypeArgs() == nil)
				tparams = alias.TypeParams()
				rhs = alias.Rhs()
			}
			if w.Version().Has(pkgbits.AliasTypeParamNames) {
				w.typeParamNames(tparams)
			}
			assert(w.Version().Has(pkgbits.AliasTypeParamNames) || tparams.Len() == 0)
			w.typ(rhs)
			return pkgbits.ObjAlias
		}

		named := obj.Type().(*types2.Named)
		assert(named.TypeArgs() == nil)

		w.pos(obj)
		w.typeParamNames(named.TypeParams())
		wext.typeExt(obj)
		w.typ(named.Underlying())

		w.Len(named.NumMethods())
		for i := 0; i < named.NumMethods(); i++ {
			w.method(wext, named.Method(i))
		}

		return pkgbits.ObjType

	case *types2.Var:
		w.pos(obj)
		w.typ(obj.Type())
		wext.varExt(obj)
		return pkgbits.ObjVar
	}
}

// objDict writes the dictionary needed for reading the given object.
func (w *writer) objDict(obj types2.Object, dict *writerDict) {
	// TODO(mdempsky): Split objDict into multiple entries? reader.go
	// doesn't care about the type parameter bounds, and reader2.go
	// doesn't care about referenced functions.

	w.dict = dict // TODO(mdempsky): This is a bit sketchy.

	w.Len(len(dict.implicits))

	tparams := objTypeParams(obj)
	ntparams := tparams.Len()
	w.Len(ntparams)
	for i := 0; i < ntparams; i++ {
		w.typ(tparams.At(i).Constraint())
	}

	nderived := len(dict.derived)
	w.Len(nderived)
	for _, typ := range dict.derived {
		w.Reloc(pkgbits.RelocType, typ.idx)
		if w.Version().Has(pkgbits.DerivedInfoNeeded) {
			w.Bool(false)
		}
	}

	// Write runtime dictionary information.
	//
	// N.B., the go/types importer reads up to the section, but doesn't
	// read any further, so it's safe to change. (See TODO above.)

	// For each type parameter, write out whether the constraint is a
	// basic interface. This is used to determine how aggressively we
	// can shape corresponding type arguments.
	//
	// This is somewhat redundant with writing out the full type
	// parameter constraints above, but the compiler currently skips
	// over those. Also, we don't care about the *declared* constraints,
	// but how the type parameters are actually *used*. E.g., if a type
	// parameter is constrained to `int | uint` but then never used in
	// arithmetic/conversions/etc, we could shape those together.
	for _, implicit := range dict.implicits {
		w.Bool(implicit.Underlying().(*types2.Interface).IsMethodSet())
	}
	for i := 0; i < ntparams; i++ {
		tparam := tparams.At(i)
		w.Bool(tparam.Underlying().(*types2.Interface).IsMethodSet())
	}

	w.Len(len(dict.typeParamMethodExprs))
	for _, info := range dict.typeParamMethodExprs {
		w.Len(info.typeParamIdx)
		w.selectorInfo(info.methodInfo)
	}

	w.Len(len(dict.subdicts))
	for _, info := range dict.subdicts {
		w.objInfo(info)
	}

	w.Len(len(dict.rtypes))
	for _, info := range dict.rtypes {
		w.typInfo(info)
	}

	w.Len(len(dict.itabs))
	for _, info := range dict.itabs {
		w.typInfo(info.typ)
		w.typInfo(info.iface)
	}

	assert(len(dict.derived) == nderived)
}

func (w *writer) typeParamNames(tparams *types2.TypeParamList) {
	w.Sync(pkgbits.SyncTypeParamNames)

	ntparams := tparams.Len()
	for i := 0; i < ntparams; i++ {
		tparam := tparams.At(i).Obj()
		w.pos(tparam)
		w.localIdent(tparam)
	}
}

func (w *writer) method(wext *writer, meth *types2.Func) {
	decl, ok := w.p.funDecls[meth]
	assert(ok)
	sig := meth.Type().(*types2.Signature)

	w.Sync(pkgbits.SyncMethod)
	w.pos(meth)
	w.selector(meth)
	w.typeParamNames(sig.RecvTypeParams())
	w.param(sig.Recv())
	w.signature(sig)

	w.pos(decl) // XXX: Hack to workaround linker limitations.
	wext.funcExt(meth)
}

// qualifiedIdent writes out the name of an object declared at package
// scope. (For now, it's also used to refer to local defined types.)
func (w *writer) qualifiedIdent(obj types2.Object) {
	w.Sync(pkgbits.SyncSym)

	name := obj.Name()
	if isDefinedType(obj) && obj.Pkg() == w.p.curpkg {
		decl, ok := w.p.typDecls[obj.(*types2.TypeName)]
		assert(ok)
		if decl.gen != 0 {
			// For local defined types, we embed a scope-disambiguation
			// number directly into their name. types.SplitVargenSuffix then
			// knows to look for this.
			//
			// TODO(mdempsky): Find a better solution; this is terrible.
			name = fmt.Sprintf("%s·%v", name, decl.gen)
		}
	}

	w.pkg(obj.Pkg())
	w.String(name)
}

// TODO(mdempsky): We should be able to omit pkg from both localIdent
// and selector, because they should always be known from context.
// However, past frustrations with this optimization in iexport make
// me a little nervous to try it again.

// localIdent writes the name of a locally declared object (i.e.,
// objects that can only be accessed by non-qualified name, within the
// context of a particular function).
func (w *writer) localIdent(obj types2.Object) {
	assert(!isGlobal(obj))
	w.Sync(pkgbits.SyncLocalIdent)
	w.pkg(obj.Pkg())
	w.String(obj.Name())
}

// selector writes the name of a field or method (i.e., objects that
// can only be accessed using selector expressions).
func (w *writer) selector(obj types2.Object) {
	w.selectorInfo(w.p.selectorIdx(obj))
}

func (w *writer) selectorInfo(info selectorInfo) {
	w.Sync(pkgbits.SyncSelector)
	w.pkgRef(info.pkgIdx)
	w.StringRef(info.nameIdx)
}

func (pw *pkgWriter) selectorIdx(obj types2.Object) selectorInfo {
	pkgIdx := pw.pkgIdx(obj.Pkg())
	nameIdx := pw.StringIdx(obj.Name())
	return selectorInfo{pkgIdx: pkgIdx, nameIdx: nameIdx}
}

// @@@ Compiler extensions

func (w *writer) funcExt(obj *types2.Func) {
	decl, ok := w.p.funDecls[obj]
	assert(ok)

	// TODO(mdempsky): Extend these pragma validation flags to account
	// for generics. E.g., linkname probably doesn't make sense at
	// least.

	pragma := asPragmaFlag(decl.Pragma)
	if pragma&ir.Systemstack != 0 && pragma&ir.Nosplit != 0 {
		w.p.errorf(decl, "go:nosplit and go:systemstack cannot be combined")
	}
	wi := asWasmImport(decl.Pragma)
	we := asWasmExport(decl.Pragma)

	if decl.Body != nil {
		if pragma&ir.Noescape != 0 {
			w.p.errorf(decl, "can only use //go:noescape with external func implementations")
		}
		if wi != nil {
			w.p.errorf(decl, "can only use //go:wasmimport with external func implementations")
		}
		if (pragma&ir.UintptrKeepAlive != 0 && pragma&ir.UintptrEscapes == 0) && pragma&ir.Nosplit == 0 {
			// Stack growth can't handle uintptr arguments that may
			// be pointers (as we don't know which are pointers
			// when creating the stack map). Thus uintptrkeepalive
			// functions (and all transitive callees) must be
			// nosplit.
			//
			// N.B. uintptrescapes implies uintptrkeepalive but it
			// is OK since the arguments must escape to the heap.
			//
			// TODO(prattmic): Add recursive nosplit check of callees.
			// TODO(prattmic): Functions with no body (i.e.,
			// assembly) must also be nosplit, but we can't check
			// that here.
			w.p.errorf(decl, "go:uintptrkeepalive requires go:nosplit")
		}
	} else {
		if base.Flag.Complete || decl.Name.Value == "init" {
			// Linknamed functions are allowed to have no body. Hopefully
			// the linkname target has a body. See issue 23311.
			// Wasmimport functions are also allowed to have no body.
			if _, ok := w.p.linknames[obj]; !ok && wi == nil {
				w.p.errorf(decl, "missing function body")
			}
		}
	}

	sig, block := obj.Type().(*types2.Signature), decl.Body
	body, closureVars := w.p.bodyIdx(sig, block, w.dict)
	if len(closureVars) > 0 {
		fmt.Fprintln(os.Stderr, "CLOSURE", closureVars)
	}
	assert(len(closureVars) == 0)

	w.Sync(pkgbits.SyncFuncExt)
	w.pragmaFlag(pragma)
	w.linkname(obj)

	if buildcfg.GOARCH == "wasm" {
		if wi != nil {
			w.String(wi.Module)
			w.String(wi.Name)
		} else {
			w.String("")
			w.String("")
		}
		if we != nil {
			w.String(we.Name)
		} else {
			w.String("")
		}
	}

	w.Bool(false) // stub extension
	w.Reloc(pkgbits.RelocBody, body)
	w.Sync(pkgbits.SyncEOF)
}

func (w *writer) typeExt(obj *types2.TypeName) {
	decl, ok := w.p.typDecls[obj]
	assert(ok)

	w.Sync(pkgbits.SyncTypeExt)

	w.pragmaFlag(asPragmaFlag(decl.Pragma))

	// No LSym.SymIdx info yet.
	w.Int64(-1)
	w.Int64(-1)
}

func (w *writer) varExt(obj *types2.Var) {
	w.Sync(pkgbits.SyncVarExt)
	w.linkname(obj)
}

func (w *writer) linkname(obj types2.Object) {
	w.Sync(pkgbits.SyncLinkname)
	w.Int64(-1)
	w.String(w.p.linknames[obj])
}

func (w *writer) pragmaFlag(p ir.PragmaFlag) {
	w.Sync(pkgbits.SyncPragma)
	w.Int(int(p))
}

// @@@ Function bodies

// bodyIdx returns the index for the given function body (specified by
// block), adding it to the export data
func (pw *pkgWriter) bodyIdx(sig *types2.Signature, block *syntax.BlockStmt, dict *writerDict) (idx index, closureVars []posVar) {
	w := pw.newWriter(pkgbits.RelocBody, pkgbits.SyncFuncBody)
	w.sig = sig
	w.dict = dict

	w.declareParams(sig)
	if w.Bool(block != nil) {
		w.stmts(block.List)
		w.pos(block.Rbrace)
	}

	return w.Flush(), w.closureVars
}

func (w *writer) declareParams(sig *types2.Signature) {
	addLocals := func(params *types2.Tuple) {
		for i := 0; i < params.Len(); i++ {
			w.addLocal(params.At(i))
		}
	}

	if recv := sig.Recv(); recv != nil {
		w.addLocal(recv)
	}
	addLocals(sig.Params())
	addLocals(sig.Results())
}

// addLocal records the declaration of a new local variable.
func (w *writer) addLocal(obj *types2.Var) {
	idx := len(w.localsIdx)

	w.Sync(pkgbits.SyncAddLocal)
	if w.p.SyncMarkers() {
		w.Int(idx)
	}
	w.varDictIndex(obj)

	if w.localsIdx == nil {
		w.localsIdx = make(map[*types2.Var]int)
	}
	w.localsIdx[obj] = idx
}

// useLocal writes a reference to the given local or free variable
// into the bitstream.
func (w *writer) useLocal(pos syntax.Pos, obj *types2.Var) {
	w.Sync(pkgbits.SyncUseObjLocal)

	if idx, ok := w.localsIdx[obj]; w.Bool(ok) {
		w.Len(idx)
		return
	}

	idx, ok := w.closureVarsIdx[obj]
	if !ok {
		if w.closureVarsIdx == nil {
			w.closureVarsIdx = make(map[*types2.Var]int)
		}
		idx = len(w.closureVars)
		w.closureVars = append(w.closureVars, posVar{pos, obj})
		w.closureVarsIdx[obj] = idx
	}
	w.Len(idx)
}

func (w *writer) openScope(pos syntax.Pos) {
	w.Sync(pkgbits.SyncOpenScope)
	w.pos(pos)
}

func (w *writer) closeScope(pos syntax.Pos) {
	w.Sync(pkgbits.SyncCloseScope)
	w.pos(pos)
	w.closeAnotherScope()
}

func (w *writer) closeAnotherScope() {
	w.Sync(pkgbits.SyncCloseAnotherScope)
}

// @@@ Statements

// stmt writes the given statement into the function body bitstream.
func (w *writer) stmt(stmt syntax.Stmt) {
	var stmts []syntax.Stmt
	if stmt != nil {
		stmts = []syntax.Stmt{stmt}
	}
	w.stmts(stmts)
}

func (w *writer) stmts(stmts []syntax.Stmt) {
	dead := false
	w.Sync(pkgbits.SyncStmts)
	var lastLabel = -1
	for i, stmt := range stmts {
		if _, ok := stmt.(*syntax.LabeledStmt); ok {
			lastLabel = i
		}
	}
	for i, stmt := range stmts {
		if dead && i > lastLabel {
			// Any statements after a terminating and last label statement are safe to omit.
			// Otherwise, code after label statement may refer to dead stmts between terminating
			// and label statement, see issue #65593.
			if _, ok := stmt.(*syntax.LabeledStmt); !ok {
				continue
			}
		}
		w.stmt1(stmt)
		dead = w.p.terminates(stmt)
	}
	w.Code(stmtEnd)
	w.Sync(pkgbits.SyncStmtsEnd)
}

func (w *writer) stmt1(stmt syntax.Stmt) {
	switch stmt := stmt.(type) {
	default:
		w.p.unexpected("statement", stmt)

	case nil, *syntax.EmptyStmt:
		return

	case *syntax.AssignStmt:
		switch {
		case stmt.Rhs == nil:
			w.Code(stmtIncDec)
			w.op(binOps[stmt.Op])
			w.expr(stmt.Lhs)
			w.pos(stmt)

		case stmt.Op != 0 && stmt.Op != syntax.Def:
			w.Code(stmtAssignOp)
			w.op(binOps[stmt.Op])
			w.expr(stmt.Lhs)
			w.pos(stmt)

			var typ types2.Type
			if stmt.Op != syntax.Shl && stmt.Op != syntax.Shr {
				typ = w.p.typeOf(stmt.Lhs)
			}
			w.implicitConvExpr(typ, stmt.Rhs)

		default:
			w.assignStmt(stmt, stmt.Lhs, stmt.Rhs)
		}

	case *syntax.BlockStmt:
		w.Code(stmtBlock)
		w.blockStmt(stmt)

	case *syntax.BranchStmt:
		w.Code(stmtBranch)
		w.pos(stmt)
		var op ir.Op
		switch stmt.Tok {
		case syntax.Break:
			op = ir.OBREAK
		case syntax.Continue:
			op = ir.OCONTINUE
		case syntax.Fallthrough:
			op = ir.OFALL
		case syntax.Goto:
			op = ir.OGOTO
		}
		w.op(op)
		w.optLabel(stmt.Label)

	case *syntax.CallStmt:
		w.Code(stmtCall)
		w.pos(stmt)
		var op ir.Op
		switch stmt.Tok {
		case syntax.Defer:
			op = ir.ODEFER
		case syntax.Go:
			op = ir.OGO
		}
		w.op(op)
		w.expr(stmt.Call)
		if stmt.Tok == syntax.Defer {
			w.optExpr(stmt.DeferAt)
		}

	case *syntax.DeclStmt:
		for _, decl := range stmt.DeclList {
			w.declStmt(decl)
		}

	case *syntax.ExprStmt:
		w.Code(stmtExpr)
		w.expr(stmt.X)

	case *syntax.ForStmt:
		w.Code(stmtFor)
		w.forStmt(stmt)

	case *syntax.IfStmt:
		w.Code(stmtIf)
		w.ifStmt(stmt)

	case *syntax.LabeledStmt:
		w.Code(stmtLabel)
		w.pos(stmt)
		w.label(stmt.Label)
		w.stmt1(stmt.Stmt)

	case *syntax.ReturnStmt:
		w.Code(stmtReturn)
		w.pos(stmt)

		resultTypes := w.sig.Results()
		dstType := func(i int) types2.Type {
			return resultTypes.At(i).Type()
		}
		w.multiExpr(stmt, dstType, syntax.UnpackListExpr(stmt.Results))

	case *syntax.SelectStmt:
		w.Code(stmtSelect)
		w.selectStmt(stmt)

	case *syntax.SendStmt:
		chanType := types2.CoreType(w.p.typeOf(stmt.Chan)).(*types2.Chan)

		w.Code(stmtSend)
		w.pos(stmt)
		w.expr(stmt.Chan)
		w.implicitConvExpr(chanType.Elem(), stmt.Value)

	case *syntax.SwitchStmt:
		w.Code(stmtSwitch)
		w.switchStmt(stmt)
	}
}

func (w *writer) assignList(expr syntax.Expr) {
	exprs := syntax.UnpackListExpr(expr)
	w.Len(len(exprs))

	for _, expr := range exprs {
		w.assign(expr)
	}
}

func (w *writer) assign(expr syntax.Expr) {
	expr = syntax.Unparen(expr)

	if name, ok := expr.(*syntax.Name); ok {
		if name.Value == "_" {
			w.Code(assignBlank)
			return
		}

		if obj, ok := w.p.info.Defs[name]; ok {
			obj := obj.(*types2.Var)

			w.Code(assignDef)
			w.pos(obj)
			w.localIdent(obj)
			w.typ(obj.Type())

			// TODO(mdempsky): Minimize locals index size by deferring
			// this until the variables actually come into scope.
			w.addLocal(obj)
			return
		}
	}

	w.Code(assignExpr)
	w.expr(expr)
}

func (w *writer) declStmt(decl syntax.Decl) {
	switch decl := decl.(type) {
	default:
		w.p.unexpected("declaration", decl)

	case *syntax.ConstDecl, *syntax.TypeDecl:

	case *syntax.VarDecl:
		w.assignStmt(decl, namesAsExpr(decl.NameList), decl.Values)
	}
}

// assignStmt writes out an assignment for "lhs = rhs".
func (w *writer) assignStmt(pos poser, lhs0, rhs0 syntax.Expr) {
	lhs := syntax.UnpackListExpr(lhs0)
	rhs := syntax.UnpackListExpr(rhs0)

	w.Code(stmtAssign)
	w.pos(pos)

	// As if w.assignList(lhs0).
	w.Len(len(lhs))
	for _, expr := range lhs {
		w.assign(expr)
	}

	dstType := func(i int) types2.Type {
		dst := lhs[i]

		// Finding dstType is somewhat involved, because for VarDecl
		// statements, the Names are only added to the info.{Defs,Uses}
		// maps, not to info.Types.
		if name, ok := syntax.Unparen(dst).(*syntax.Name); ok {
			if name.Value == "_" {
				return nil // ok: no implicit conversion
			} else if def, ok := w.p.info.Defs[name].(*types2.Var); ok {
				return def.Type()
			} else if use, ok := w.p.info.Uses[name].(*types2.Var); ok {
				return use.Type()
			} else {
				w.p.fatalf(dst, "cannot find type of destination object: %v", dst)
			}
		}

		return w.p.typeOf(dst)
	}

	w.multiExpr(pos, dstType, rhs)
}

func (w *writer) blockStmt(stmt *syntax.BlockStmt) {
	w.Sync(pkgbits.SyncBlockStmt)
	w.openScope(stmt.Pos())
	w.stmts(stmt.List)
	w.closeScope(stmt.Rbrace)
}

func (w *writer) forStmt(stmt *syntax.ForStmt) {
	w.Sync(pkgbits.SyncForStmt)
	w.openScope(stmt.Pos())

	if rang, ok := stmt.Init.(*syntax.RangeClause); w.Bool(ok) {
		w.pos(rang)
		w.assignList(rang.Lhs)
		w.expr(rang.X)

		xtyp := w.p.typeOf(rang.X)
		if _, isMap := types2.CoreType(xtyp).(*types2.Map); isMap {
			w.rtype(xtyp)
		}
		{
			lhs := syntax.UnpackListExpr(rang.Lhs)
			assign := func(i int, src types2.Type) {
				if i >= len(lhs) {
					return
				}
				dst := syntax.Unparen(lhs[i])
				if name, ok := dst.(*syntax.Name); ok && name.Value == "_" {
					return
				}

				var dstType types2.Type
				if rang.Def {
					// For `:=` assignments, the LHS names only appear in Defs,
					// not Types (as used by typeOf).
					dstType = w.p.info.Defs[dst.(*syntax.Name)].(*types2.Var).Type()
				} else {
					dstType = w.p.typeOf(dst)
				}

				w.convRTTI(src, dstType)
			}

			keyType, valueType := types2.RangeKeyVal(w.p.typeOf(rang.X))
			assign(0, keyType)
			assign(1, valueType)
		}

	} else {
		if stmt.Cond != nil && w.p.staticBool(&stmt.Cond) < 0 { // always false
			stmt.Post = nil
			stmt.Body.List = nil
		}

		w.pos(stmt)
		w.stmt(stmt.Init)
		w.optExpr(stmt.Cond)
		w.stmt(stmt.Post)
	}

	w.blockStmt(stmt.Body)
	w.Bool(w.distinctVars(stmt))
	w.closeAnotherScope()
}

func (w *writer) distinctVars(stmt *syntax.ForStmt) bool {
	lv := base.Debug.LoopVar
	fileVersion := w.p.info.FileVersions[stmt.Pos().Base()]
	is122 := fileVersion == "" || version.Compare(fileVersion, "go1.22") >= 0

	// Turning off loopvar for 1.22 is only possible with loopvarhash=qn
	//
	// Debug.LoopVar values to be preserved for 1.21 compatibility are 1 and 2,
	// which are also set (=1) by GOEXPERIMENT=loopvar.  The knobs for turning on
	// the new, unshared, loopvar behavior apply to versions less than 1.21 because
	// (1) 1.21 also did that and (2) this is believed to be the likely use case;
	// anyone checking to see if it affects their code will just run the GOEXPERIMENT
	// but will not also update all their go.mod files to 1.21.
	//
	// -gcflags=-d=loopvar=3 enables logging for 1.22 but does not turn loopvar on for <= 1.21.

	return is122 || lv > 0 && lv != 3
}

func (w *writer) ifStmt(stmt *syntax.IfStmt) {
	cond := w.p.staticBool(&stmt.Cond)

	w.Sync(pkgbits.SyncIfStmt)
	w.openScope(stmt.Pos())
	w.pos(stmt)
	w.stmt(stmt.Init)
	w.expr(stmt.Cond)
	w.Int(cond)
	if cond >= 0 {
		w.blockStmt(stmt.Then)
	} else {
		w.pos(stmt.Then.Rbrace)
	}
	if cond <= 0 {
		w.stmt(stmt.Else)
	}
	w.closeAnotherScope()
}

func (w *writer) selectStmt(stmt *syntax.SelectStmt) {
	w.Sync(pkgbits.SyncSelectStmt)

	w.pos(stmt)
	w.Len(len(stmt.Body))
	for i, clause := range stmt.Body {
		if i > 0 {
			w.closeScope(clause.Pos())
		}
		w.openScope(clause.Pos())

		w.pos(clause)
		w.stmt(clause.Comm)
		w.stmts(clause.Body)
	}
	if len(stmt.Body) > 0 {
		w.closeScope(stmt.Rbrace)
	}
}

func (w *writer) switchStmt(stmt *syntax.SwitchStmt) {
	w.Sync(pkgbits.SyncSwitchStmt)

	w.openScope(stmt.Pos())
	w.pos(stmt)
	w.stmt(stmt.Init)

	var iface, tagType types2.Type
	var tagTypeIsChan bool
	if guard, ok := stmt.Tag.(*syntax.TypeSwitchGuard); w.Bool(ok) {
		iface = w.p.typeOf(guard.X)

		w.pos(guard)
		if tag := guard.Lhs; w.Bool(tag != nil) {
			w.pos(tag)

			// Like w.localIdent, but we don't have a types2.Object.
			w.Sync(pkgbits.SyncLocalIdent)
			w.pkg(w.p.curpkg)
			w.String(tag.Value)
		}
		w.expr(guard.X)
	} else {
		tag := stmt.Tag

		var tagValue constant.Value
		if tag != nil {
			tv := w.p.typeAndValue(tag)
			tagType = tv.Type
			tagValue = tv.Value
			_, tagTypeIsChan = tagType.Underlying().(*types2.Chan)
		} else {
			tagType = types2.Typ[types2.Bool]
			tagValue = constant.MakeBool(true)
		}

		if tagValue != nil {
			// If the switch tag has a constant value, look for a case
			// clause that we always branch to.
			func() {
				var target *syntax.CaseClause
			Outer:
				for _, clause := range stmt.Body {
					if clause.Cases == nil {
						target = clause
					}
					for _, cas := range syntax.UnpackListExpr(clause.Cases) {
						tv := w.p.typeAndValue(cas)
						if tv.Value == nil {
							return // non-constant case; give up
						}
						if constant.Compare(tagValue, token.EQL, tv.Value) {
							target = clause
							break Outer
						}
					}
				}
				// We've found the target clause, if any.

				if target != nil {
					if hasFallthrough(target.Body) {
						return // fallthrough is tricky; give up
					}

					// Rewrite as single "default" case.
					target.Cases = nil
					stmt.Body = []*syntax.CaseClause{target}
				} else {
					stmt.Body = nil
				}

				// Clear switch tag (i.e., replace with implicit "true").
				tag = nil
				stmt.Tag = nil
				tagType = types2.Typ[types2.Bool]
			}()
		}

		// Walk is going to emit comparisons between the tag value and
		// each case expression, and we want these comparisons to always
		// have the same type. If there are any case values that can't be
		// converted to the tag value's type, then convert everything to
		// `any` instead.
		//
		// Except that we need to keep comparisons of channel values from
		// being wrapped in any(). See issue #67190.

		if !tagTypeIsChan {
		Outer:
			for _, clause := range stmt.Body {
				for _, cas := range syntax.UnpackListExpr(clause.Cases) {
					if casType := w.p.typeOf(cas); !types2.AssignableTo(casType, tagType) && (types2.IsInterface(casType) || types2.IsInterface(tagType)) {
						tagType = types2.NewInterfaceType(nil, nil)
						break Outer
					}
				}
			}
		}

		if w.Bool(tag != nil) {
			w.implicitConvExpr(tagType, tag)
		}
	}

	w.Len(len(stmt.Body))
	for i, clause := range stmt.Body {
		if i > 0 {
			w.closeScope(clause.Pos())
		}
		w.openScope(clause.Pos())

		w.pos(clause)

		cases := syntax.UnpackListExpr(clause.Cases)
		if iface != nil {
			w.Len(len(cases))
			for _, cas := range cases {
				if w.Bool(isNil(w.p, cas)) {
					continue
				}
				w.exprType(iface, cas)
			}
		} else {
			// As if w.exprList(clause.Cases),
			// but with implicit conversions to tagType.

			w.Sync(pkgbits.SyncExprList)
			w.Sync(pkgbits.SyncExprs)
			w.Len(len(cases))
			for _, cas := range cases {
				typ := tagType
				if tagTypeIsChan {
					typ = nil
				}
				w.implicitConvExpr(typ, cas)
			}
		}

		if obj, ok := w.p.info.Implicits[clause]; ok {
			// TODO(mdempsky): These pos details are quirkish, but also
			// necessary so the variable's position is correct for DWARF
			// scope assignment later. It would probably be better for us to
			// instead just set the variable's DWARF scoping info earlier so
			// we can give it the correct position information.
			pos := clause.Pos()
			if typs := syntax.UnpackListExpr(clause.Cases); len(typs) != 0 {
				pos = typeExprEndPos(typs[len(typs)-1])
			}
			w.pos(pos)

			obj := obj.(*types2.Var)
			w.typ(obj.Type())
			w.addLocal(obj)
		}

		w.stmts(clause.Body)
	}
	if len(stmt.Body) > 0 {
		w.closeScope(stmt.Rbrace)
	}

	w.closeScope(stmt.Rbrace)
}

func (w *writer) label(label *syntax.Name) {
	w.Sync(pkgbits.SyncLabel)

	// TODO(mdempsky): Replace label strings with dense indices.
	w.String(label.Value)
}

func (w *writer) optLabel(label *syntax.Name) {
	w.Sync(pkgbits.SyncOptLabel)
	if w.Bool(label != nil) {
		w.label(label)
	}
}

// @@@ Expressions

// expr writes the given expression into the function body bitstream.
func (w *writer) expr(expr syntax.Expr) {
	base.Assertf(expr != nil, "missing expression")

	expr = syntax.Unparen(expr) // skip parens; unneeded after typecheck

	obj, inst := lookupObj(w.p, expr)
	targs := inst.TypeArgs

	if tv, ok := w.p.maybeTypeAndValue(expr); ok {
		if tv.IsRuntimeHelper() {
			if pkg := obj.Pkg(); pkg != nil && pkg.Name() == "runtime" {
				objName := obj.Name()
				w.Code(exprRuntimeBuiltin)
				w.String(objName)
				return
			}
		}

		if tv.IsType() {
			w.p.fatalf(expr, "unexpected type expression %v", syntax.String(expr))
		}

		if tv.Value != nil {
			w.Code(exprConst)
			w.pos(expr)
			typ := idealType(tv)
			assert(typ != nil)
			w.typ(typ)
			w.Value(tv.Value)
			return
		}

		if _, isNil := obj.(*types2.Nil); isNil {
			w.Code(exprZero)
			w.pos(expr)
			w.typ(tv.Type)
			return
		}

		// With shape types (and particular pointer shaping), we may have
		// an expression of type "go.shape.*uint8", but need to reshape it
		// to another shape-identical type to allow use in field
		// selection, indexing, etc.
		if typ := tv.Type; !tv.IsBuiltin() && !isTuple(typ) && !isUntyped(typ) {
			w.Code(exprReshape)
			w.typ(typ)
			// fallthrough
		}
	}

	if obj != nil {
		if targs.Len() != 0 {
			obj := obj.(*types2.Func)

			w.Code(exprFuncInst)
			w.pos(expr)
			w.funcInst(obj, targs)
			return
		}

		if isGlobal(obj) {
			w.Code(exprGlobal)
			w.obj(obj, nil)
			return
		}

		obj := obj.(*types2.Var)
		assert(!obj.IsField())

		w.Code(exprLocal)
		w.useLocal(expr.Pos(), obj)
		return
	}

	switch expr := expr.(type) {
	default:
		w.p.unexpected("expression", expr)

	case *syntax.CompositeLit:
		w.Code(exprCompLit)
		w.compLit(expr)

	case *syntax.FuncLit:
		w.Code(exprFuncLit)
		w.funcLit(expr)

	case *syntax.SelectorExpr:
		sel, ok := w.p.info.Selections[expr]
		assert(ok)

		switch sel.Kind() {
		default:
			w.p.fatalf(expr, "unexpected selection kind: %v", sel.Kind())

		case types2.FieldVal:
			w.Code(exprFieldVal)
			w.expr(expr.X)
			w.pos(expr)
			w.selector(sel.Obj())

		case types2.MethodVal:
			w.Code(exprMethodVal)
			typ := w.recvExpr(expr, sel)
			w.pos(expr)
			w.methodExpr(expr, typ, sel)

		case types2.MethodExpr:
			w.Code(exprMethodExpr)

			tv := w.p.typeAndValue(expr.X)
			assert(tv.IsType())

			index := sel.Index()
			implicits := index[:len(index)-1]

			typ := tv.Type
			w.typ(typ)

			w.Len(len(implicits))
			for _, ix := range implicits {
				w.Len(ix)
				typ = deref2(typ).Underlying().(*types2.Struct).Field(ix).Type()
			}

			recv := sel.Obj().(*types2.Func).Type().(*types2.Signature).Recv().Type()
			if w.Bool(isPtrTo(typ, recv)) { // need deref
				typ = recv
			} else if w.Bool(isPtrTo(recv, typ)) { // need addr
				typ = recv
			}

			w.pos(expr)
			w.methodExpr(expr, typ, sel)
		}

	case *syntax.IndexExpr:
		_ = w.p.typeOf(expr.Index) // ensure this is an index expression, not an instantiation

		xtyp := w.p.typeOf(expr.X)

		var keyType types2.Type
		if mapType, ok := types2.CoreType(xtyp).(*types2.Map); ok {
			keyType = mapType.Key()
		}

		w.Code(exprIndex)
		w.expr(expr.X)
		w.pos(expr)
		w.implicitConvExpr(keyType, expr.Index)
		if keyType != nil {
			w.rtype(xtyp)
		}

	case *syntax.SliceExpr:
		w.Code(exprSlice)
		w.expr(expr.X)
		w.pos(expr)
		for _, n := range &expr.Index {
			w.optExpr(n)
		}

	case *syntax.AssertExpr:
		iface := w.p.typeOf(expr.X)

		w.Code(exprAssert)
		w.expr(expr.X)
		w.pos(expr)
		w.exprType(iface, expr.Type)
		w.rtype(iface)

	case *syntax.Operation:
		if expr.Y == nil {
			w.Code(exprUnaryOp)
			w.op(unOps[expr.Op])
			w.pos(expr)
			w.expr(expr.X)
			break
		}

		var commonType types2.Type
		switch expr.Op {
		case syntax.Shl, syntax.Shr:
			// ok: operands are allowed to have different types
		default:
			xtyp := w.p.typeOf(expr.X)
			ytyp := w.p.typeOf(expr.Y)
			switch {
			case types2.AssignableTo(xtyp, ytyp):
				commonType = ytyp
			case types2.AssignableTo(ytyp, xtyp):
				commonType = xtyp
			default:
				w.p.fatalf(expr, "failed to find common type between %v and %v", xtyp, ytyp)
			}
		}

		w.Code(exprBinaryOp)
		w.op(binOps[expr.Op])
		w.implicitConvExpr(commonType, expr.X)
		w.pos(expr)
		w.implicitConvExpr(commonType, expr.Y)

	case *syntax.CallExpr:
		tv := w.p.typeAndValue(expr.Fun)
		if tv.IsType() {
			assert(len(expr.ArgList) == 1)
			assert(!expr.HasDots)
			w.convertExpr(tv.Type, expr.ArgList[0], false)
			break
		}

		var rtype types2.Type
		if tv.IsBuiltin() {
			switch obj, _ := lookupObj(w.p, syntax.Unparen(expr.Fun)); obj.Name() {
			case "make":
				assert(len(expr.ArgList) >= 1)
				assert(!expr.HasDots)

				w.Code(exprMake)
				w.pos(expr)
				w.exprType(nil, expr.ArgList[0])
				w.exprs(expr.ArgList[1:])

				typ := w.p.typeOf(expr)
				switch coreType := types2.CoreType(typ).(type) {
				default:
					w.p.fatalf(expr, "unexpected core type: %v", coreType)
				case *types2.Chan:
					w.rtype(typ)
				case *types2.Map:
					w.rtype(typ)
				case *types2.Slice:
					w.rtype(sliceElem(typ))
				}

				return

			case "new":
				assert(len(expr.ArgList) == 1)
				assert(!expr.HasDots)

				w.Code(exprNew)
				w.pos(expr)
				w.exprType(nil, expr.ArgList[0])
				return

			case "Sizeof":
				assert(len(expr.ArgList) == 1)
				assert(!expr.HasDots)

				w.Code(exprSizeof)
				w.pos(expr)
				w.typ(w.p.typeOf(expr.ArgList[0]))
				return

			case "Alignof":
				assert(len(expr.ArgList) == 1)
				assert(!expr.HasDots)

				w.Code(exprAlignof)
				w.pos(expr)
				w.typ(w.p.typeOf(expr.ArgList[0]))
				return

			case "Offsetof":
				assert(len(expr.ArgList) == 1)
				assert(!expr.HasDots)
				selector := syntax.Unparen(expr.ArgList[0]).(*syntax.SelectorExpr)
				index := w.p.info.Selections[selector].Index()

				w.Code(exprOffsetof)
				w.pos(expr)
				w.typ(deref2(w.p.typeOf(selector.X)))
				w.Len(len(index) - 1)
				for _, idx := range index {
					w.Len(idx)
				}
				return

			case "append":
				rtype = sliceElem(w.p.typeOf(expr))
			case "copy":
				typ := w.p.typeOf(expr.ArgList[0])
				if tuple, ok := typ.(*types2.Tuple); ok { // "copy(g())"
					typ = tuple.At(0).Type()
				}
				rtype = sliceElem(typ)
			case "delete":
				typ := w.p.typeOf(expr.ArgList[0])
				if tuple, ok := typ.(*types2.Tuple); ok { // "delete(g())"
					typ = tuple.At(0).Type()
				}
				rtype = typ
			case "Slice":
				rtype = sliceElem(w.p.typeOf(expr))
			}
		}

		writeFunExpr := func() {
			fun := syntax.Unparen(expr.Fun)

			if selector, ok := fun.(*syntax.SelectorExpr); ok {
				if sel, ok := w.p.info.Selections[selector]; ok && sel.Kind() == types2.MethodVal {
					w.Bool(true) // method call
					typ := w.recvExpr(selector, sel)
					w.methodExpr(selector, typ, sel)
					return
				}
			}

			w.Bool(false) // not a method call (i.e., normal function call)

			if obj, inst := lookupObj(w.p, fun); w.Bool(obj != nil && inst.TypeArgs.Len() != 0) {
				obj := obj.(*types2.Func)

				w.pos(fun)
				w.funcInst(obj, inst.TypeArgs)
				return
			}

			w.expr(fun)
		}

		sigType := types2.CoreType(tv.Type).(*types2.Signature)
		paramTypes := sigType.Params()

		w.Code(exprCall)
		writeFunExpr()
		w.pos(expr)

		paramType := func(i int) types2.Type {
			if sigType.Variadic() && !expr.HasDots && i >= paramTypes.Len()-1 {
				return paramTypes.At(paramTypes.Len() - 1).Type().(*types2.Slice).Elem()
			}
			return paramTypes.At(i).Type()
		}

		w.multiExpr(expr, paramType, expr.ArgList)
		w.Bool(expr.HasDots)
		if rtype != nil {
			w.rtype(rtype)
		}
	}
}

func sliceElem(typ types2.Type) types2.Type {
	return types2.CoreType(typ).(*types2.Slice).Elem()
}

func (w *writer) optExpr(expr syntax.Expr) {
	if w.Bool(expr != nil) {
		w.expr(expr)
	}
}

// recvExpr writes out expr.X, but handles any implicit addressing,
// dereferencing, and field selections appropriate for the method
// selection.
func (w *writer) recvExpr(expr *syntax.SelectorExpr, sel *types2.Selection) types2.Type {
	index := sel.Index()
	implicits := index[:len(index)-1]

	w.Code(exprRecv)
	w.expr(expr.X)
	w.pos(expr)
	w.Len(len(implicits))

	typ := w.p.typeOf(expr.X)
	for _, ix := range implicits {
		typ = deref2(typ).Underlying().(*types2.Struct).Field(ix).Type()
		w.Len(ix)
	}

	recv := sel.Obj().(*types2.Func).Type().(*types2.Signature).Recv().Type()
	if w.Bool(isPtrTo(typ, recv)) { // needs deref
		typ = recv
	} else if w.Bool(isPtrTo(recv, typ)) { // needs addr
		typ = recv
	}

	return typ
}

// funcInst writes a reference to an instantiated function.
func (w *writer) funcInst(obj *types2.Func, targs *types2.TypeList) {
	info := w.p.objInstIdx(obj, targs, w.dict)

	// Type arguments list contains derived types; we can emit a static
	// call to the shaped function, but need to dynamically compute the
	// runtime dictionary pointer.
	if w.Bool(info.anyDerived()) {
		w.Len(w.dict.subdictIdx(info))
		return
	}

	// Type arguments list is statically known; we can emit a static
	// call with a statically reference to the respective runtime
	// dictionary.
	w.objInfo(info)
}

// methodExpr writes out a reference to the method selected by
// expr. sel should be the corresponding types2.Selection, and recv
// the type produced after any implicit addressing, dereferencing, and
// field selection. (Note: recv might differ from sel.Obj()'s receiver
// parameter in the case of interface types, and is needed for
// handling type parameter methods.)
func (w *writer) methodExpr(expr *syntax.SelectorExpr, recv types2.Type, sel *types2.Selection) {
	fun := sel.Obj().(*types2.Func)
	sig := fun.Type().(*types2.Signature)

	w.typ(recv)
	w.typ(sig)
	w.pos(expr)
	w.selector(fun)

	// Method on a type parameter. These require an indirect call
	// through the current function's runtime dictionary.
	if typeParam, ok := types2.Unalias(recv).(*types2.TypeParam); w.Bool(ok) {
		typeParamIdx := w.dict.typeParamIndex(typeParam)
		methodInfo := w.p.selectorIdx(fun)

		w.Len(w.dict.typeParamMethodExprIdx(typeParamIdx, methodInfo))
		return
	}

	if isInterface(recv) != isInterface(sig.Recv().Type()) {
		w.p.fatalf(expr, "isInterface inconsistency: %v and %v", recv, sig.Recv().Type())
	}

	if !isInterface(recv) {
		if named, ok := types2.Unalias(deref2(recv)).(*types2.Named); ok {
			obj, targs := splitNamed(named)
			info := w.p.objInstIdx(obj, targs, w.dict)

			// Method on a derived receiver type. These can be handled by a
			// static call to the shaped method, but require dynamically
			// looking up the appropriate dictionary argument in the current
			// function's runtime dictionary.
			if w.p.hasImplicitTypeParams(obj) || info.anyDerived() {
				w.Bool(true) // dynamic subdictionary
				w.Len(w.dict.subdictIdx(info))
				return
			}

			// Method on a fully known receiver type. These can be handled
			// by a static call to the shaped method, and with a static
			// reference to the receiver type's dictionary.
			if targs.Len() != 0 {
				w.Bool(false) // no dynamic subdictionary
				w.Bool(true)  // static dictionary
				w.objInfo(info)
				return
			}
		}
	}

	w.Bool(false) // no dynamic subdictionary
	w.Bool(false) // no static dictionary
}

// multiExpr writes a sequence of expressions, where the i'th value is
// implicitly converted to dstType(i). It also handles when exprs is a
// single, multi-valued expression (e.g., the multi-valued argument in
// an f(g()) call, or the RHS operand in a comma-ok assignment).
func (w *writer) multiExpr(pos poser, dstType func(int) types2.Type, exprs []syntax.Expr) {
	w.Sync(pkgbits.SyncMultiExpr)

	if len(exprs) == 1 {
		expr := exprs[0]
		if tuple, ok := w.p.typeOf(expr).(*types2.Tuple); ok {
			assert(tuple.Len() > 1)
			w.Bool(true) // N:1 assignment
			w.pos(pos)
			w.expr(expr)

			w.Len(tuple.Len())
			for i := 0; i < tuple.Len(); i++ {
				src := tuple.At(i).Type()
				// TODO(mdempsky): Investigate not writing src here. I think
				// the reader should be able to infer it from expr anyway.
				w.typ(src)
				if dst := dstType(i); w.Bool(dst != nil && !types2.Identical(src, dst)) {
					if src == nil || dst == nil {
						w.p.fatalf(pos, "src is %v, dst is %v", src, dst)
					}
					if !types2.AssignableTo(src, dst) {
						w.p.fatalf(pos, "%v is not assignable to %v", src, dst)
					}
					w.typ(dst)
					w.convRTTI(src, dst)
				}
			}
			return
		}
	}

	w.Bool(false) // N:N assignment
	w.Len(len(exprs))
	for i, expr := range exprs {
		w.implicitConvExpr(dstType(i), expr)
	}
}

// implicitConvExpr is like expr, but if dst is non-nil and different
// from expr's type, then an implicit conversion operation is inserted
// at expr's position.
func (w *writer) implicitConvExpr(dst types2.Type, expr syntax.Expr) {
	w.convertExpr(dst, expr, true)
}

func (w *writer) convertExpr(dst types2.Type, expr syntax.Expr, implicit bool) {
	src := w.p.typeOf(expr)

	// Omit implicit no-op conversions.
	identical := dst == nil || types2.Identical(src, dst)
	if implicit && identical {
		w.expr(expr)
		return
	}

	if implicit && !types2.AssignableTo(src, dst) {
		w.p.fatalf(expr, "%v is not assignable to %v", src, dst)
	}

	w.Code(exprConvert)
	w.Bool(implicit)
	w.typ(dst)
	w.pos(expr)
	w.convRTTI(src, dst)
	w.Bool(isTypeParam(dst))
	w.Bool(identical)
	w.expr(expr)
}

func (w *writer) compLit(lit *syntax.CompositeLit) {
	typ := w.p.typeOf(lit)

	w.Sync(pkgbits.SyncCompLit)
	w.pos(lit)
	w.typ(typ)

	if ptr, ok := types2.CoreType(typ).(*types2.Pointer); ok {
		typ = ptr.Elem()
	}
	var keyType, elemType types2.Type
	var structType *types2.Struct
	switch typ0 := typ; typ := types2.CoreType(typ).(type) {
	default:
		w.p.fatalf(lit, "unexpected composite literal type: %v", typ)
	case *types2.Array:
		elemType = typ.Elem()
	case *types2.Map:
		w.rtype(typ0)
		keyType, elemType = typ.Key(), typ.Elem()
	case *types2.Slice:
		elemType = typ.Elem()
	case *types2.Struct:
		structType = typ
	}

	w.Len(len(lit.ElemList))
	for i, elem := range lit.ElemList {
		elemType := elemType
		if structType != nil {
			if kv, ok := elem.(*syntax.KeyValueExpr); ok {
				// use position of expr.Key rather than of elem (which has position of ':')
				w.pos(kv.Key)
				i = fieldIndex(w.p.info, structType, kv.Key.(*syntax.Name))
				elem = kv.Value
			} else {
				w.pos(elem)
			}
			elemType = structType.Field(i).Type()
			w.Len(i)
		} else {
			if kv, ok := elem.(*syntax.KeyValueExpr); w.Bool(ok) {
				// use position of expr.Key rather than of elem (which has position of ':')
				w.pos(kv.Key)
				w.implicitConvExpr(keyType, kv.Key)
				elem = kv.Value
			}
		}
		w.implicitConvExpr(elemType, elem)
	}
}

func (w *writer) funcLit(expr *syntax.FuncLit) {
	sig := w.p.typeOf(expr).(*types2.Signature)

	body, closureVars := w.p.bodyIdx(sig, expr.Body, w.dict)

	w.Sync(pkgbits.SyncFuncLit)
	w.pos(expr)
	w.signature(sig)
	w.Bool(w.p.rangeFuncBodyClosures[expr])

	w.Len(len(closureVars))
	for _, cv := range closureVars {
		w.pos(cv.pos)
		w.useLocal(cv.pos, cv.var_)
	}

	w.Reloc(pkgbits.RelocBody, body)
}

type posVar struct {
	pos  syntax.Pos
	var_ *types2.Var
}

func (p posVar) String() string {
	return p.pos.String() + ":" + p.var_.String()
}

func (w *writer) exprList(expr syntax.Expr) {
	w.Sync(pkgbits.SyncExprList)
	w.exprs(syntax.UnpackListExpr(expr))
}

func (w *writer) exprs(exprs []syntax.Expr) {
	w.Sync(pkgbits.SyncExprs)
	w.Len(len(exprs))
	for _, expr := range exprs {
		w.expr(expr)
	}
}

// rtype writes information so that the reader can construct an
// expression of type *runtime._type representing typ.
func (w *writer) rtype(typ types2.Type) {
	typ = types2.Default(typ)

	info := w.p.typIdx(typ, w.dict)
	w.rtypeInfo(info)
}

func (w *writer) rtypeInfo(info typeInfo) {
	w.Sync(pkgbits.SyncRType)

	if w.Bool(info.derived) {
		w.Len(w.dict.rtypeIdx(info))
	} else {
		w.typInfo(info)
	}
}

// varDictIndex writes out information for populating DictIndex for
// the ir.Name that will represent obj.
func (w *writer) varDictIndex(obj *types2.Var) {
	info := w.p.typIdx(obj.Type(), w.dict)
	if w.Bool(info.derived) {
		w.Len(w.dict.rtypeIdx(info))
	}
}

// isUntyped reports whether typ is an untyped type.
func isUntyped(typ types2.Type) bool {
	// Note: types2.Unalias is unnecessary here, since untyped types can't be aliased.
	basic, ok := typ.(*types2.Basic)
	return ok && basic.Info()&types2.IsUntyped != 0
}

// isTuple reports whether typ is a tuple type.
func isTuple(typ types2.Type) bool {
	// Note: types2.Unalias is unnecessary here, since tuple types can't be aliased.
	_, ok := typ.(*types2.Tuple)
	return ok
}

func (w *writer) itab(typ, iface types2.Type) {
	typ = types2.Default(typ)
	iface = types2.Default(iface)

	typInfo := w.p.typIdx(typ, w.dict)
	ifaceInfo := w.p.typIdx(iface, w.dict)

	w.rtypeInfo(typInfo)
	w.rtypeInfo(ifaceInfo)
	if w.Bool(typInfo.derived || ifaceInfo.derived) {
		w.Len(w.dict.itabIdx(typInfo, ifaceInfo))
	}
}

// convRTTI writes information so that the reader can construct
// expressions for converting from src to dst.
func (w *writer) convRTTI(src, dst types2.Type) {
	w.Sync(pkgbits.SyncConvRTTI)
	w.itab(src, dst)
}

func (w *writer) exprType(iface types2.Type, typ syntax.Expr) {
	base.Assertf(iface == nil || isInterface(iface), "%v must be nil or an interface type", iface)

	tv := w.p.typeAndValue(typ)
	assert(tv.IsType())

	w.Sync(pkgbits.SyncExprType)
	w.pos(typ)

	if w.Bool(iface != nil && !iface.Underlying().(*types2.Interface).Empty()) {
		w.itab(tv.Type, iface)
	} else {
		w.rtype(tv.Type)

		info := w.p.typIdx(tv.Type, w.dict)
		w.Bool(info.derived)
	}
}

// isInterface reports whether typ is known to be an interface type.
// If typ is a type parameter, then isInterface reports an internal
// compiler error instead.
func isInterface(typ types2.Type) bool {
	if _, ok := types2.Unalias(typ).(*types2.TypeParam); ok {
		// typ is a type parameter and may be instantiated as either a
		// concrete or interface type, so the writer can't depend on
		// knowing this.
		base.Fatalf("%v is a type parameter", typ)
	}

	_, ok := typ.Underlying().(*types2.Interface)
	return ok
}

// op writes an Op into the bitstream.
func (w *writer) op(op ir.Op) {
	// TODO(mdempsky): Remove in favor of explicit codes? Would make
	// export data more stable against internal refactorings, but low
	// priority at the moment.
	assert(op != 0)
	w.Sync(pkgbits.SyncOp)
	w.Len(int(op))
}

// @@@ Package initialization

// Caution: This code is still clumsy, because toolstash -cmp is
// particularly sensitive to it.

type typeDeclGen struct {
	*syntax.TypeDecl
	gen int

	// Implicit type parameters in s
```