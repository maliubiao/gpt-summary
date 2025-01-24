Response:
The user wants a summary of the functionalities of the Go code snippet. The code is part of the `loader` package in the `cmd/link` tool. It seems to be responsible for loading and managing symbols from object files during the linking process.

Here's a breakdown of the code's functionalities:

1. **Symbol Management:** Defines structures (`Sym`, `Relocs`, `ExtReloc`, `Reloc`, `Aux`) to represent symbols and their related information like relocations and auxiliary data.
2. **Object File Reading:** Introduces `oReader` to encapsulate `goobj.Reader` and additional information about an object file, such as the compilation unit and symbol mappings.
3. **Global Symbol Table:** Implements a global symbol table (`Loader`) to store and retrieve symbols. It uses a combination of direct indexing (`objSyms`) and name-based lookups (`symsByName`, `extStaticSyms`).
4. **External Symbols:** Handles symbols defined outside the current set of object files.
5. **Symbol Attributes:** Manages various attributes of symbols, like reachability, visibility, and whether they are duplicates.
6. **Relocation Handling:** Provides mechanisms to access and manipulate relocation information for symbols.
7. **Auxiliary Symbol Data:** Supports access to auxiliary data associated with symbols, including DWARF information and function metadata.
8. **Error Handling:** Includes an `ErrorReporter` for reporting linking errors.

The request asks for a high-level summary of the first part of the code.
这是 `go/src/cmd/link/internal/loader/loader.go` 文件的第一部分，主要功能是定义了**链接器在加载和管理符号时使用的数据结构和核心逻辑**。它构建了一个全局的符号表，能够读取、存储和查找来自不同对象文件的符号信息。

以下是其主要功能的归纳：

1. **定义核心数据结构:**
    *   **`Sym`:**  表示全局唯一的符号索引。
    *   **`Relocs`:** 封装了特定符号的重定位信息。
    *   **`ExtReloc`:**  用于表示外部重定位的信息。
    *   **`Reloc`:** 提供访问对象文件中重定位记录的句柄。
    *   **`Aux`:**  提供访问对象文件中辅助符号记录的句柄。
    *   **`oReader`:** 包装了 `goobj.Reader`，并包含了关于对象文件的额外信息，例如编译单元、符号映射和包引用。
    *   **`objSym`:** 表示对象文件中的一个符号，包含对象文件索引和本地符号索引。
    *   **`Loader`:**  核心结构，负责加载对象文件和解析符号引用，维护全局符号表。

2. **全局符号表管理 (`Loader` 结构):**
    *   维护已加载的对象文件列表 (`objs`).
    *   区分内部符号和外部符号，并设置外部符号的起始索引 (`extStart`).
    *   存储内置符号的全局索引 (`builtinSyms`).
    *   将全局索引映射到本地索引和对象文件 (`objSyms`).
    *   通过名称和 ABI 版本存储符号 (`symsByName`, `extStaticSyms`).
    *   管理外部符号的载荷数据 (`payloads`).
    *   存储符号的值、节信息和对齐方式。
    *   使用位图 (`Bitmap`) 和映射 (`map`) 来存储符号的各种属性和元数据 (如可达性、是否在符号表、外部名称等)。
    *   维护符号之间的父子关系 (`outer`, `sub`).

3. **加载和添加符号:**
    *   `addObj` 方法用于添加新的对象文件。
    *   `addSym` 方法用于从对象文件中添加符号到全局符号表，并处理重复符号的情况。
    *   `newExtSym` 和 `LookupOrCreateSym` 用于创建和查找外部符号。
    *   处理不同类型的符号 (包定义符号、哈希符号、非包符号)。

4. **符号查找:**
    *   `Lookup` 方法用于通过名称和版本查找符号。
    *   `resolve` 方法用于解析对象文件中的本地符号引用，返回全局索引。

5. **符号属性管理:**
    *   提供 `Attr...` 和 `SetAttr...` 系列方法来获取和设置符号的各种属性，例如 `AttrReachable`，`SetAttrLocal` 等。

6. **重定位信息访问:**
    *   `Relocs` 方法返回符号的重定位信息。

7. **辅助符号信息访问:**
    *   `Aux` 方法提供访问辅助符号信息的能力。

8. **错误处理:**
    *   使用 `ErrorReporter` 结构来报告链接错误。

**可以推断出这是 Go 语言链接器实现的核心部分，负责构建链接过程中的符号信息中心。**

**Go 代码举例说明 (符号添加和查找):**

假设我们有两个 Go 源文件 `a.go` 和 `b.go`，它们被编译成了对象文件。

**a.go:**

```go
package main

var GlobalVarA int = 10

func FuncA() {
	println("Hello from FuncA")
}
```

**b.go:**

```go
package main

import "fmt"

func FuncB() {
	fmt.Println("Hello from FuncB, GlobalVarA is:", GlobalVarA)
}
```

在链接过程中，`loader.go` 中的代码会读取 `a.o` 和 `b.o` 两个对象文件，并将其中定义的符号（如 `main.GlobalVarA`, `main.FuncA`, `main.FuncB`）添加到 `Loader` 的全局符号表中。

**假设输入:** 两个对象文件 `a.o` 和 `b.o` 的 `oReader` 实例被创建并传递给 `Loader`。

**代码片段模拟 `addSym` (简化):**

```go
package main

import "fmt"

type Loader struct {
	symsByName map[string]Sym // 假设只使用名称查找
	objSyms  []objSym
}

type Sym int

type objSym struct {
	name string
	obj  string // 对象文件名
}

func (l *Loader) addSym(name string, obj string) Sym {
	if _, ok := l.symsByName[name]; ok {
		fmt.Printf("Symbol %s already exists\n", name)
		return l.symsByName[name]
	}
	newSym := Sym(len(l.objSyms) + 1)
	l.symsByName[name] = newSym
	l.objSyms = append(l.objSyms, objSym{name: name, obj: obj})
	fmt.Printf("Added symbol %s with ID %d from %s\n", name, newSym, obj)
	return newSym
}

func main() {
	loader := Loader{
		symsByName: make(map[string]Sym),
		objSyms:  make([]objSym, 0),
	}

	// 模拟从 a.o 读取符号
	loader.addSym("main.GlobalVarA", "a.o")
	loader.addSym("main.FuncA", "a.o")

	// 模拟从 b.o 读取符号
	loader.addSym("main.FuncB", "b.o")

	// 尝试添加重复符号
	loader.addSym("main.GlobalVarA", "b.o")
}
```

**可能的输出:**

```
Added symbol main.GlobalVarA with ID 1 from a.o
Added symbol main.FuncA with ID 2 from a.o
Added symbol main.FuncB with ID 3 from b.o
Symbol main.GlobalVarA already exists
```

**归纳第一部分的功能:**

`loader.go` 的第一部分主要负责**构建和维护链接过程中的核心数据结构，特别是全局符号表**。它定义了表示符号及其相关信息的各种类型，并提供了添加、查找和管理符号的基本功能。这是链接器实现的基础，为后续的符号解析、重定位和代码生成等步骤提供了必要的符号信息。

### 提示词
```
这是路径为go/src/cmd/link/internal/loader/loader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package loader

import (
	"bytes"
	"cmd/internal/bio"
	"cmd/internal/goobj"
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/sym"
	"debug/elf"
	"fmt"
	"internal/abi"
	"io"
	"log"
	"math/bits"
	"os"
	"sort"
	"strings"
)

var _ = fmt.Print

// Sym encapsulates a global symbol index, used to identify a specific
// Go symbol. The 0-valued Sym is corresponds to an invalid symbol.
type Sym = sym.LoaderSym

// Relocs encapsulates the set of relocations on a given symbol; an
// instance of this type is returned by the Loader Relocs() method.
type Relocs struct {
	rs []goobj.Reloc

	li uint32   // local index of symbol whose relocs we're examining
	r  *oReader // object reader for containing package
	l  *Loader  // loader
}

// ExtReloc contains the payload for an external relocation.
type ExtReloc struct {
	Xsym Sym
	Xadd int64
	Type objabi.RelocType
	Size uint8
}

// Reloc holds a "handle" to access a relocation record from an
// object file.
type Reloc struct {
	*goobj.Reloc
	r *oReader
	l *Loader
}

func (rel Reloc) Type() objabi.RelocType     { return objabi.RelocType(rel.Reloc.Type()) &^ objabi.R_WEAK }
func (rel Reloc) Weak() bool                 { return objabi.RelocType(rel.Reloc.Type())&objabi.R_WEAK != 0 }
func (rel Reloc) SetType(t objabi.RelocType) { rel.Reloc.SetType(uint16(t)) }
func (rel Reloc) Sym() Sym                   { return rel.l.resolve(rel.r, rel.Reloc.Sym()) }
func (rel Reloc) SetSym(s Sym)               { rel.Reloc.SetSym(goobj.SymRef{PkgIdx: 0, SymIdx: uint32(s)}) }
func (rel Reloc) IsMarker() bool             { return rel.Siz() == 0 }

// Aux holds a "handle" to access an aux symbol record from an
// object file.
type Aux struct {
	*goobj.Aux
	r *oReader
	l *Loader
}

func (a Aux) Sym() Sym { return a.l.resolve(a.r, a.Aux.Sym()) }

// oReader is a wrapper type of obj.Reader, along with some
// extra information.
type oReader struct {
	*goobj.Reader
	unit         *sym.CompilationUnit
	version      int // version of static symbol
	pkgprefix    string
	syms         []Sym    // Sym's global index, indexed by local index
	pkg          []uint32 // indices of referenced package by PkgIdx (index into loader.objs array)
	ndef         int      // cache goobj.Reader.NSym()
	nhashed64def int      // cache goobj.Reader.NHashed64Def()
	nhasheddef   int      // cache goobj.Reader.NHashedDef()
	objidx       uint32   // index of this reader in the objs slice
}

// Total number of defined symbols (package symbols, hashed symbols, and
// non-package symbols).
func (r *oReader) NAlldef() int { return r.ndef + r.nhashed64def + r.nhasheddef + r.NNonpkgdef() }

// objSym represents a symbol in an object file. It is a tuple of
// the object and the symbol's local index.
// For external symbols, objidx is the index of l.extReader (extObj),
// s is its index into the payload array.
// {0, 0} represents the nil symbol.
type objSym struct {
	objidx uint32 // index of the object (in l.objs array)
	s      uint32 // local index
}

type nameVer struct {
	name string
	v    int
}

type Bitmap []uint32

// set the i-th bit.
func (bm Bitmap) Set(i Sym) {
	n, r := uint(i)/32, uint(i)%32
	bm[n] |= 1 << r
}

// unset the i-th bit.
func (bm Bitmap) Unset(i Sym) {
	n, r := uint(i)/32, uint(i)%32
	bm[n] &^= (1 << r)
}

// whether the i-th bit is set.
func (bm Bitmap) Has(i Sym) bool {
	n, r := uint(i)/32, uint(i)%32
	return bm[n]&(1<<r) != 0
}

// return current length of bitmap in bits.
func (bm Bitmap) Len() int {
	return len(bm) * 32
}

// return the number of bits set.
func (bm Bitmap) Count() int {
	s := 0
	for _, x := range bm {
		s += bits.OnesCount32(x)
	}
	return s
}

func MakeBitmap(n int) Bitmap {
	return make(Bitmap, (n+31)/32)
}

// growBitmap insures that the specified bitmap has enough capacity,
// reallocating (doubling the size) if needed.
func growBitmap(reqLen int, b Bitmap) Bitmap {
	curLen := b.Len()
	if reqLen > curLen {
		b = append(b, MakeBitmap(reqLen+1-curLen)...)
	}
	return b
}

type symAndSize struct {
	sym  Sym
	size uint32
}

// A Loader loads new object files and resolves indexed symbol references.
//
// Notes on the layout of global symbol index space:
//
//   - Go object files are read before host object files; each Go object
//     read adds its defined package symbols to the global index space.
//     Nonpackage symbols are not yet added.
//
//   - In loader.LoadNonpkgSyms, add non-package defined symbols and
//     references in all object files to the global index space.
//
//   - Host object file loading happens; the host object loader does a
//     name/version lookup for each symbol it finds; this can wind up
//     extending the external symbol index space range. The host object
//     loader stores symbol payloads in loader.payloads using SymbolBuilder.
//
//   - Each symbol gets a unique global index. For duplicated and
//     overwriting/overwritten symbols, the second (or later) appearance
//     of the symbol gets the same global index as the first appearance.
type Loader struct {
	objs        []*oReader
	extStart    Sym   // from this index on, the symbols are externally defined
	builtinSyms []Sym // global index of builtin symbols

	objSyms []objSym // global index mapping to local index

	symsByName    [2]map[string]Sym // map symbol name to index, two maps are for ABI0 and ABIInternal
	extStaticSyms map[nameVer]Sym   // externally defined static symbols, keyed by name

	extReader    *oReader // a dummy oReader, for external symbols
	payloadBatch []extSymPayload
	payloads     []*extSymPayload // contents of linker-materialized external syms
	values       []int64          // symbol values, indexed by global sym index

	sects    []*sym.Section // sections
	symSects []uint16       // symbol's section, index to sects array

	align []uint8 // symbol 2^N alignment, indexed by global index

	deferReturnTramp map[Sym]bool // whether the symbol is a trampoline of a deferreturn call

	objByPkg map[string]uint32 // map package path to the index of its Go object reader

	anonVersion int // most recently assigned ext static sym pseudo-version

	// Bitmaps and other side structures used to store data used to store
	// symbol flags/attributes; these are to be accessed via the
	// corresponding loader "AttrXXX" and "SetAttrXXX" methods. Please
	// visit the comments on these methods for more details on the
	// semantics / interpretation of the specific flags or attribute.
	attrReachable        Bitmap // reachable symbols, indexed by global index
	attrOnList           Bitmap // "on list" symbols, indexed by global index
	attrLocal            Bitmap // "local" symbols, indexed by global index
	attrNotInSymbolTable Bitmap // "not in symtab" symbols, indexed by global idx
	attrUsedInIface      Bitmap // "used in interface" symbols, indexed by global idx
	attrSpecial          Bitmap // "special" frame symbols, indexed by global idx
	attrVisibilityHidden Bitmap // hidden symbols, indexed by ext sym index
	attrDuplicateOK      Bitmap // dupOK symbols, indexed by ext sym index
	attrShared           Bitmap // shared symbols, indexed by ext sym index
	attrExternal         Bitmap // external symbols, indexed by ext sym index
	generatedSyms        Bitmap // symbols that generate their content, indexed by ext sym idx

	attrReadOnly         map[Sym]bool     // readonly data for this sym
	attrCgoExportDynamic map[Sym]struct{} // "cgo_export_dynamic" symbols
	attrCgoExportStatic  map[Sym]struct{} // "cgo_export_static" symbols

	// Outer and Sub relations for symbols.
	outer []Sym // indexed by global index
	sub   map[Sym]Sym

	dynimplib   map[Sym]string      // stores Dynimplib symbol attribute
	dynimpvers  map[Sym]string      // stores Dynimpvers symbol attribute
	localentry  map[Sym]uint8       // stores Localentry symbol attribute
	extname     map[Sym]string      // stores Extname symbol attribute
	elfType     map[Sym]elf.SymType // stores elf type symbol property
	elfSym      map[Sym]int32       // stores elf sym symbol property
	localElfSym map[Sym]int32       // stores "local" elf sym symbol property
	symPkg      map[Sym]string      // stores package for symbol, or library for shlib-derived syms
	plt         map[Sym]int32       // stores dynimport for pe objects
	got         map[Sym]int32       // stores got for pe objects
	dynid       map[Sym]int32       // stores Dynid for symbol

	relocVariant map[relocId]sym.RelocVariant // stores variant relocs

	// Used to implement field tracking; created during deadcode if
	// field tracking is enabled. Reachparent[K] contains the index of
	// the symbol that triggered the marking of symbol K as live.
	Reachparent []Sym

	// CgoExports records cgo-exported symbols by SymName.
	CgoExports map[string]Sym

	WasmExports []Sym

	flags uint32

	strictDupMsgs int // number of strict-dup warning/errors, when FlagStrictDups is enabled

	errorReporter *ErrorReporter

	npkgsyms    int // number of package symbols, for accounting
	nhashedsyms int // number of hashed symbols, for accounting
}

const (
	pkgDef = iota
	hashed64Def
	hashedDef
	nonPkgDef
	nonPkgRef
)

// objidx
const (
	nilObj = iota
	extObj
	goObjStart
)

// extSymPayload holds the payload (data + relocations) for linker-synthesized
// external symbols (note that symbol value is stored in a separate slice).
type extSymPayload struct {
	name   string // TODO: would this be better as offset into str table?
	size   int64
	ver    int
	kind   sym.SymKind
	objidx uint32 // index of original object if sym made by cloneToExternal
	relocs []goobj.Reloc
	data   []byte
	auxs   []goobj.Aux
}

const (
	// Loader.flags
	FlagStrictDups = 1 << iota
	FlagCheckLinkname
)

func NewLoader(flags uint32, reporter *ErrorReporter) *Loader {
	nbuiltin := goobj.NBuiltin()
	extReader := &oReader{objidx: extObj}
	ldr := &Loader{
		objs:                 []*oReader{nil, extReader}, // reserve index 0 for nil symbol, 1 for external symbols
		objSyms:              make([]objSym, 1, 1),       // This will get overwritten later.
		extReader:            extReader,
		symsByName:           [2]map[string]Sym{make(map[string]Sym, 80000), make(map[string]Sym, 50000)}, // preallocate ~2MB for ABI0 and ~1MB for ABI1 symbols
		objByPkg:             make(map[string]uint32),
		sub:                  make(map[Sym]Sym),
		dynimplib:            make(map[Sym]string),
		dynimpvers:           make(map[Sym]string),
		localentry:           make(map[Sym]uint8),
		extname:              make(map[Sym]string),
		attrReadOnly:         make(map[Sym]bool),
		elfType:              make(map[Sym]elf.SymType),
		elfSym:               make(map[Sym]int32),
		localElfSym:          make(map[Sym]int32),
		symPkg:               make(map[Sym]string),
		plt:                  make(map[Sym]int32),
		got:                  make(map[Sym]int32),
		dynid:                make(map[Sym]int32),
		attrCgoExportDynamic: make(map[Sym]struct{}),
		attrCgoExportStatic:  make(map[Sym]struct{}),
		deferReturnTramp:     make(map[Sym]bool),
		extStaticSyms:        make(map[nameVer]Sym),
		builtinSyms:          make([]Sym, nbuiltin),
		flags:                flags,
		errorReporter:        reporter,
		sects:                []*sym.Section{nil}, // reserve index 0 for nil section
	}
	reporter.ldr = ldr
	return ldr
}

// Add object file r
func (l *Loader) addObj(pkg string, r *oReader) {
	pkg = objabi.PathToPrefix(pkg) // the object file contains escaped package path
	if _, ok := l.objByPkg[pkg]; !ok {
		l.objByPkg[pkg] = r.objidx
	}
	l.objs = append(l.objs, r)
}

// Add a symbol from an object file, return the global index.
// If the symbol already exist, it returns the index of that symbol.
func (st *loadState) addSym(name string, ver int, r *oReader, li uint32, kind int, osym *goobj.Sym) Sym {
	l := st.l
	if l.extStart != 0 {
		panic("addSym called after external symbol is created")
	}
	i := Sym(len(l.objSyms))
	if int(i) != len(l.objSyms) { // overflow
		panic("too many symbols")
	}
	addToGlobal := func() {
		l.objSyms = append(l.objSyms, objSym{r.objidx, li})
	}
	if name == "" && kind != hashed64Def && kind != hashedDef {
		addToGlobal()
		return i // unnamed aux symbol
	}
	if ver == r.version {
		// Static symbol. Add its global index but don't
		// add to name lookup table, as it cannot be
		// referenced by name.
		addToGlobal()
		return i
	}
	switch kind {
	case pkgDef:
		// Defined package symbols cannot be dup to each other.
		// We load all the package symbols first, so we don't need
		// to check dup here.
		// We still add it to the lookup table, as it may still be
		// referenced by name (e.g. through linkname).
		l.symsByName[ver][name] = i
		addToGlobal()
		return i
	case hashed64Def, hashedDef:
		// Hashed (content-addressable) symbol. Check the hash
		// but don't add to name lookup table, as they are not
		// referenced by name. Also no need to do overwriting
		// check, as same hash indicates same content.
		var checkHash func() (symAndSize, bool)
		var addToHashMap func(symAndSize)
		var h64 uint64        // only used for hashed64Def
		var h *goobj.HashType // only used for hashedDef
		if kind == hashed64Def {
			checkHash = func() (symAndSize, bool) {
				h64 = r.Hash64(li - uint32(r.ndef))
				s, existed := st.hashed64Syms[h64]
				return s, existed
			}
			addToHashMap = func(ss symAndSize) { st.hashed64Syms[h64] = ss }
		} else {
			checkHash = func() (symAndSize, bool) {
				h = r.Hash(li - uint32(r.ndef+r.nhashed64def))
				s, existed := st.hashedSyms[*h]
				return s, existed
			}
			addToHashMap = func(ss symAndSize) { st.hashedSyms[*h] = ss }
		}
		siz := osym.Siz()
		if s, existed := checkHash(); existed {
			// The content hash is built from symbol data and relocations. In the
			// object file, the symbol data may not always contain trailing zeros,
			// e.g. for [5]int{1,2,3} and [100]int{1,2,3}, the data is same
			// (although the size is different).
			// Also, for short symbols, the content hash is the identity function of
			// the 8 bytes, and trailing zeros doesn't change the hash value, e.g.
			// hash("A") == hash("A\0\0\0").
			// So when two symbols have the same hash, we need to use the one with
			// larger size.
			if siz > s.size {
				// New symbol has larger size, use the new one. Rewrite the index mapping.
				l.objSyms[s.sym] = objSym{r.objidx, li}
				addToHashMap(symAndSize{s.sym, siz})
			}
			return s.sym
		}
		addToHashMap(symAndSize{i, siz})
		addToGlobal()
		return i
	}

	// Non-package (named) symbol.
	// Check if it already exists.
	oldi, existed := l.symsByName[ver][name]
	if !existed {
		l.symsByName[ver][name] = i
		addToGlobal()
		return i
	}
	// symbol already exists
	if osym.Dupok() {
		if l.flags&FlagStrictDups != 0 {
			l.checkdup(name, r, li, oldi)
		}
		// Fix for issue #47185 -- given two dupok symbols with
		// different sizes, favor symbol with larger size. See
		// also issue #46653.
		szdup := l.SymSize(oldi)
		sz := int64(r.Sym(li).Siz())
		if szdup < sz {
			// new symbol overwrites old symbol.
			l.objSyms[oldi] = objSym{r.objidx, li}
		}
		return oldi
	}
	oldr, oldli := l.toLocal(oldi)
	oldsym := oldr.Sym(oldli)
	if oldsym.Dupok() {
		return oldi
	}
	overwrite := r.DataSize(li) != 0
	if overwrite {
		// new symbol overwrites old symbol.
		oldtyp := sym.AbiSymKindToSymKind[objabi.SymKind(oldsym.Type())]
		if !(oldtyp.IsData() && oldr.DataSize(oldli) == 0) {
			log.Fatalf("duplicated definition of symbol %s, from %s and %s", name, r.unit.Lib.Pkg, oldr.unit.Lib.Pkg)
		}
		l.objSyms[oldi] = objSym{r.objidx, li}
	} else {
		// old symbol overwrites new symbol.
		typ := sym.AbiSymKindToSymKind[objabi.SymKind(oldsym.Type())]
		if !typ.IsData() { // only allow overwriting data symbol
			log.Fatalf("duplicated definition of symbol %s, from %s and %s", name, r.unit.Lib.Pkg, oldr.unit.Lib.Pkg)
		}
	}
	return oldi
}

// newExtSym creates a new external sym with the specified
// name/version.
func (l *Loader) newExtSym(name string, ver int) Sym {
	i := Sym(len(l.objSyms))
	if int(i) != len(l.objSyms) { // overflow
		panic("too many symbols")
	}
	if l.extStart == 0 {
		l.extStart = i
	}
	l.growValues(int(i) + 1)
	l.growOuter(int(i) + 1)
	l.growAttrBitmaps(int(i) + 1)
	pi := l.newPayload(name, ver)
	l.objSyms = append(l.objSyms, objSym{l.extReader.objidx, uint32(pi)})
	l.extReader.syms = append(l.extReader.syms, i)
	return i
}

// LookupOrCreateSym looks up the symbol with the specified name/version,
// returning its Sym index if found. If the lookup fails, a new external
// Sym will be created, entered into the lookup tables, and returned.
func (l *Loader) LookupOrCreateSym(name string, ver int) Sym {
	i := l.Lookup(name, ver)
	if i != 0 {
		return i
	}
	i = l.newExtSym(name, ver)
	static := ver >= sym.SymVerStatic || ver < 0
	if static {
		l.extStaticSyms[nameVer{name, ver}] = i
	} else {
		l.symsByName[ver][name] = i
	}
	return i
}

// AddCgoExport records a cgo-exported symbol in l.CgoExports.
// This table is used to identify the correct Go symbol ABI to use
// to resolve references from host objects (which don't have ABIs).
func (l *Loader) AddCgoExport(s Sym) {
	if l.CgoExports == nil {
		l.CgoExports = make(map[string]Sym)
	}
	l.CgoExports[l.SymName(s)] = s
}

// LookupOrCreateCgoExport is like LookupOrCreateSym, but if ver
// indicates a global symbol, it uses the CgoExport table to determine
// the appropriate symbol version (ABI) to use. ver must be either 0
// or a static symbol version.
func (l *Loader) LookupOrCreateCgoExport(name string, ver int) Sym {
	if ver >= sym.SymVerStatic {
		return l.LookupOrCreateSym(name, ver)
	}
	if ver != 0 {
		panic("ver must be 0 or a static version")
	}
	// Look for a cgo-exported symbol from Go.
	if s, ok := l.CgoExports[name]; ok {
		return s
	}
	// Otherwise, this must just be a symbol in the host object.
	// Create a version 0 symbol for it.
	return l.LookupOrCreateSym(name, 0)
}

func (l *Loader) IsExternal(i Sym) bool {
	r, _ := l.toLocal(i)
	return l.isExtReader(r)
}

func (l *Loader) isExtReader(r *oReader) bool {
	return r == l.extReader
}

// For external symbol, return its index in the payloads array.
// XXX result is actually not a global index. We (ab)use the Sym type
// so we don't need conversion for accessing bitmaps.
func (l *Loader) extIndex(i Sym) Sym {
	_, li := l.toLocal(i)
	return Sym(li)
}

// Get a new payload for external symbol, return its index in
// the payloads array.
func (l *Loader) newPayload(name string, ver int) int {
	pi := len(l.payloads)
	pp := l.allocPayload()
	pp.name = name
	pp.ver = ver
	l.payloads = append(l.payloads, pp)
	l.growExtAttrBitmaps()
	return pi
}

// getPayload returns a pointer to the extSymPayload struct for an
// external symbol if the symbol has a payload. Will panic if the
// symbol in question is bogus (zero or not an external sym).
func (l *Loader) getPayload(i Sym) *extSymPayload {
	if !l.IsExternal(i) {
		panic(fmt.Sprintf("bogus symbol index %d in getPayload", i))
	}
	pi := l.extIndex(i)
	return l.payloads[pi]
}

// allocPayload allocates a new payload.
func (l *Loader) allocPayload() *extSymPayload {
	batch := l.payloadBatch
	if len(batch) == 0 {
		batch = make([]extSymPayload, 1000)
	}
	p := &batch[0]
	l.payloadBatch = batch[1:]
	return p
}

func (ms *extSymPayload) Grow(siz int64) {
	if int64(int(siz)) != siz {
		log.Fatalf("symgrow size %d too long", siz)
	}
	if int64(len(ms.data)) >= siz {
		return
	}
	if cap(ms.data) < int(siz) {
		cl := len(ms.data)
		ms.data = append(ms.data, make([]byte, int(siz)+1-cl)...)
		ms.data = ms.data[0:cl]
	}
	ms.data = ms.data[:siz]
}

// Convert a local index to a global index.
func (l *Loader) toGlobal(r *oReader, i uint32) Sym {
	return r.syms[i]
}

// Convert a global index to a local index.
func (l *Loader) toLocal(i Sym) (*oReader, uint32) {
	return l.objs[l.objSyms[i].objidx], l.objSyms[i].s
}

// Resolve a local symbol reference. Return global index.
func (l *Loader) resolve(r *oReader, s goobj.SymRef) Sym {
	var rr *oReader
	switch p := s.PkgIdx; p {
	case goobj.PkgIdxInvalid:
		// {0, X} with non-zero X is never a valid sym reference from a Go object.
		// We steal this space for symbol references from external objects.
		// In this case, X is just the global index.
		if l.isExtReader(r) {
			return Sym(s.SymIdx)
		}
		if s.SymIdx != 0 {
			panic("bad sym ref")
		}
		return 0
	case goobj.PkgIdxHashed64:
		i := int(s.SymIdx) + r.ndef
		return r.syms[i]
	case goobj.PkgIdxHashed:
		i := int(s.SymIdx) + r.ndef + r.nhashed64def
		return r.syms[i]
	case goobj.PkgIdxNone:
		i := int(s.SymIdx) + r.ndef + r.nhashed64def + r.nhasheddef
		return r.syms[i]
	case goobj.PkgIdxBuiltin:
		if bi := l.builtinSyms[s.SymIdx]; bi != 0 {
			return bi
		}
		l.reportMissingBuiltin(int(s.SymIdx), r.unit.Lib.Pkg)
		return 0
	case goobj.PkgIdxSelf:
		rr = r
	default:
		rr = l.objs[r.pkg[p]]
	}
	return l.toGlobal(rr, s.SymIdx)
}

// reportMissingBuiltin issues an error in the case where we have a
// relocation against a runtime builtin whose definition is not found
// when the runtime package is built. The canonical example is
// "runtime.racefuncenter" -- currently if you do something like
//
//	go build -gcflags=-race myprogram.go
//
// the compiler will insert calls to the builtin runtime.racefuncenter,
// but the version of the runtime used for linkage won't actually contain
// definitions of that symbol. See issue #42396 for details.
//
// As currently implemented, this is a fatal error. This has drawbacks
// in that if there are multiple missing builtins, the error will only
// cite the first one. On the plus side, terminating the link here has
// advantages in that we won't run the risk of panics or crashes later
// on in the linker due to R_CALL relocations with 0-valued target
// symbols.
func (l *Loader) reportMissingBuiltin(bsym int, reflib string) {
	bname, _ := goobj.BuiltinName(bsym)
	log.Fatalf("reference to undefined builtin %q from package %q",
		bname, reflib)
}

// Look up a symbol by name, return global index, or 0 if not found.
// This is more like Syms.ROLookup than Lookup -- it doesn't create
// new symbol.
func (l *Loader) Lookup(name string, ver int) Sym {
	if ver >= sym.SymVerStatic || ver < 0 {
		return l.extStaticSyms[nameVer{name, ver}]
	}
	return l.symsByName[ver][name]
}

// Check that duplicate symbols have same contents.
func (l *Loader) checkdup(name string, r *oReader, li uint32, dup Sym) {
	p := r.Data(li)
	rdup, ldup := l.toLocal(dup)
	pdup := rdup.Data(ldup)
	reason := "same length but different contents"
	if len(p) != len(pdup) {
		reason = fmt.Sprintf("new length %d != old length %d", len(p), len(pdup))
	} else if bytes.Equal(p, pdup) {
		// For BSS symbols, we need to check size as well, see issue 46653.
		szdup := l.SymSize(dup)
		sz := int64(r.Sym(li).Siz())
		if szdup == sz {
			return
		}
		reason = fmt.Sprintf("different sizes: new size %d != old size %d",
			sz, szdup)
	}
	fmt.Fprintf(os.Stderr, "cmd/link: while reading object for '%v': duplicate symbol '%s', previous def at '%v', with mismatched payload: %s\n", r.unit.Lib, name, rdup.unit.Lib, reason)

	// For the moment, allow DWARF subprogram DIEs for
	// auto-generated wrapper functions. What seems to happen
	// here is that we get different line numbers on formal
	// params; I am guessing that the pos is being inherited
	// from the spot where the wrapper is needed.
	allowed := strings.HasPrefix(name, "go:info.go.interface") ||
		strings.HasPrefix(name, "go:info.go.builtin") ||
		strings.HasPrefix(name, "go:debuglines")
	if !allowed {
		l.strictDupMsgs++
	}
}

func (l *Loader) NStrictDupMsgs() int { return l.strictDupMsgs }

// Number of total symbols.
func (l *Loader) NSym() int {
	return len(l.objSyms)
}

// Number of defined Go symbols.
func (l *Loader) NDef() int {
	return int(l.extStart)
}

// Number of reachable symbols.
func (l *Loader) NReachableSym() int {
	return l.attrReachable.Count()
}

// Returns the name of the i-th symbol.
func (l *Loader) SymName(i Sym) string {
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		return pp.name
	}
	r, li := l.toLocal(i)
	if r == nil {
		return "?"
	}
	return r.Sym(li).Name(r.Reader)
}

// Returns the version of the i-th symbol.
func (l *Loader) SymVersion(i Sym) int {
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		return pp.ver
	}
	r, li := l.toLocal(i)
	return int(abiToVer(r.Sym(li).ABI(), r.version))
}

func (l *Loader) IsFileLocal(i Sym) bool {
	return l.SymVersion(i) >= sym.SymVerStatic
}

// IsFromAssembly returns true if this symbol is derived from an
// object file generated by the Go assembler.
func (l *Loader) IsFromAssembly(i Sym) bool {
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		if pp.objidx != 0 {
			r := l.objs[pp.objidx]
			return r.FromAssembly()
		}
		return false
	}
	r, _ := l.toLocal(i)
	return r.FromAssembly()
}

// Returns the type of the i-th symbol.
func (l *Loader) SymType(i Sym) sym.SymKind {
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		if pp != nil {
			return pp.kind
		}
		return 0
	}
	r, li := l.toLocal(i)
	return sym.AbiSymKindToSymKind[objabi.SymKind(r.Sym(li).Type())]
}

// Returns the attributes of the i-th symbol.
func (l *Loader) SymAttr(i Sym) uint8 {
	if l.IsExternal(i) {
		// TODO: do something? External symbols have different representation of attributes.
		// For now, ReflectMethod, NoSplit, GoType, and Typelink are used and they cannot be
		// set by external symbol.
		return 0
	}
	r, li := l.toLocal(i)
	return r.Sym(li).Flag()
}

// Returns the size of the i-th symbol.
func (l *Loader) SymSize(i Sym) int64 {
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		return pp.size
	}
	r, li := l.toLocal(i)
	return int64(r.Sym(li).Siz())
}

// AttrReachable returns true for symbols that are transitively
// referenced from the entry points. Unreachable symbols are not
// written to the output.
func (l *Loader) AttrReachable(i Sym) bool {
	return l.attrReachable.Has(i)
}

// SetAttrReachable sets the reachability property for a symbol (see
// AttrReachable).
func (l *Loader) SetAttrReachable(i Sym, v bool) {
	if v {
		l.attrReachable.Set(i)
	} else {
		l.attrReachable.Unset(i)
	}
}

// AttrOnList returns true for symbols that are on some list (such as
// the list of all text symbols, or one of the lists of data symbols)
// and is consulted to avoid bugs where a symbol is put on a list
// twice.
func (l *Loader) AttrOnList(i Sym) bool {
	return l.attrOnList.Has(i)
}

// SetAttrOnList sets the "on list" property for a symbol (see
// AttrOnList).
func (l *Loader) SetAttrOnList(i Sym, v bool) {
	if v {
		l.attrOnList.Set(i)
	} else {
		l.attrOnList.Unset(i)
	}
}

// AttrLocal returns true for symbols that are only visible within the
// module (executable or shared library) being linked. This attribute
// is applied to thunks and certain other linker-generated symbols.
func (l *Loader) AttrLocal(i Sym) bool {
	return l.attrLocal.Has(i)
}

// SetAttrLocal the "local" property for a symbol (see AttrLocal above).
func (l *Loader) SetAttrLocal(i Sym, v bool) {
	if v {
		l.attrLocal.Set(i)
	} else {
		l.attrLocal.Unset(i)
	}
}

// AttrUsedInIface returns true for a type symbol that is used in
// an interface.
func (l *Loader) AttrUsedInIface(i Sym) bool {
	return l.attrUsedInIface.Has(i)
}

func (l *Loader) SetAttrUsedInIface(i Sym, v bool) {
	if v {
		l.attrUsedInIface.Set(i)
	} else {
		l.attrUsedInIface.Unset(i)
	}
}

// SymAddr checks that a symbol is reachable, and returns its value.
func (l *Loader) SymAddr(i Sym) int64 {
	if !l.AttrReachable(i) {
		panic("unreachable symbol in symaddr")
	}
	return l.values[i]
}

// AttrNotInSymbolTable returns true for symbols that should not be
// added to the symbol table of the final generated load module.
func (l *Loader) AttrNotInSymbolTable(i Sym) bool {
	return l.attrNotInSymbolTable.Has(i)
}

// SetAttrNotInSymbolTable the "not in symtab" property for a symbol
// (see AttrNotInSymbolTable above).
func (l *Loader) SetAttrNotInSymbolTable(i Sym, v bool) {
	if v {
		l.attrNotInSymbolTable.Set(i)
	} else {
		l.attrNotInSymbolTable.Unset(i)
	}
}

// AttrVisibilityHidden symbols returns true for ELF symbols with
// visibility set to STV_HIDDEN. They become local symbols in
// the final executable. Only relevant when internally linking
// on an ELF platform.
func (l *Loader) AttrVisibilityHidden(i Sym) bool {
	if !l.IsExternal(i) {
		return false
	}
	return l.attrVisibilityHidden.Has(l.extIndex(i))
}

// SetAttrVisibilityHidden sets the "hidden visibility" property for a
// symbol (see AttrVisibilityHidden).
func (l *Loader) SetAttrVisibilityHidden(i Sym, v bool) {
	if !l.IsExternal(i) {
		panic("tried to set visibility attr on non-external symbol")
	}
	if v {
		l.attrVisibilityHidden.Set(l.extIndex(i))
	} else {
		l.attrVisibilityHidden.Unset(l.extIndex(i))
	}
}

// AttrDuplicateOK returns true for a symbol that can be present in
// multiple object files.
func (l *Loader) AttrDuplicateOK(i Sym) bool {
	if !l.IsExternal(i) {
		// TODO: if this path winds up being taken frequently, it
		// might make more sense to copy the flag value out of the object
		// into a larger bitmap during preload.
		r, li := l.toLocal(i)
		return r.Sym(li).Dupok()
	}
	return l.attrDuplicateOK.Has(l.extIndex(i))
}

// SetAttrDuplicateOK sets the "duplicate OK" property for an external
// symbol (see AttrDuplicateOK).
func (l *Loader) SetAttrDuplicateOK(i Sym, v bool) {
	if !l.IsExternal(i) {
		panic("tried to set dupok attr on non-external symbol")
	}
	if v {
		l.attrDuplicateOK.Set(l.extIndex(i))
	} else {
		l.attrDuplicateOK.Unset(l.extIndex(i))
	}
}

// AttrShared returns true for symbols compiled with the -shared option.
func (l *Loader) AttrShared(i Sym) bool {
	if !l.IsExternal(i) {
		// TODO: if this path winds up being taken frequently, it
		// might make more sense to copy the flag value out of the
		// object into a larger bitmap during preload.
		r, _ := l.toLocal(i)
		return r.Shared()
	}
	return l.attrShared.Has(l.extIndex(i))
}

// SetAttrShared sets the "shared" property for an external
// symbol (see AttrShared).
func (l *Loader) SetAttrShared(i Sym, v bool) {
	if !l.IsExternal(i) {
		panic(fmt.Sprintf("tried to set shared attr on non-external symbol %d %s", i, l.SymName(i)))
	}
	if v {
		l.attrShared.Set(l.extIndex(i))
	} else {
		l.attrShared.Unset(l.extIndex(i))
	}
}

// AttrExternal returns true for function symbols loaded from host
// object files.
func (l *Loader) AttrExternal(i Sym) bool {
	if !l.IsExternal(i) {
		return false
	}
	return l.attrExternal.Has(l.extIndex(i))
}

// SetAttrExternal sets the "external" property for a host object
// symbol (see AttrExternal).
func (l *Loader) SetAttrExternal(i Sym, v bool) {
	if !l.IsExternal(i) {
		panic(fmt.Sprintf("tried to set external attr on non-external symbol %q", l.SymName(i)))
	}
	if v {
		l.attrExternal.Set(l.extIndex(i))
	} else {
		l.attrExternal.Unset(l.extIndex(i))
	}
}

// AttrSpecial returns true for a symbols that do not have their
// address (i.e. Value) computed by the usual mechanism of
// data.go:dodata() & data.go:address().
func (l *Loader) AttrSpecial(i Sym) bool {
	return l.attrSpecial.Has(i)
}

// SetAttrSpecial sets the "special" property for a symbol (see
// AttrSpecial).
func (l *Loader) SetAttrSpecial(i Sym, v bool) {
	if v {
		l.attrSpecial.Set(i)
	} else {
		l.attrSpecial.Unset(i)
	}
}

// AttrCgoExportDynamic returns true for a symbol that has been
// specially marked via the "cgo_export_dynamic" compiler directive
// written by cgo (in response to //export directives in the source).
func (l *Loader) AttrCgoExportDynamic(i Sym) bool {
	_, ok := l.attrCgoExportDynamic[i]
	return ok
}

// SetAttrCgoExportDynamic sets the "cgo_export_dynamic" for a symbol
// (see AttrCgoExportDynamic).
func (l *Loader) SetAttrCgoExportDynamic(i Sym, v bool) {
	if v {
		l.attrCgoExportDynamic[i] = struct{}{}
	} else {
		delete(l.attrCgoExportDynamic, i)
	}
}

// ForAllCgoExportDynamic calls f for every symbol that has been
// marked with the "cgo_export_dynamic" compiler directive.
func (l *Loader) ForAllCgoExportDynamic(f func(Sym)) {
	for s := range l.attrCgoExportDynamic {
		f(s)
	}
}

// AttrCgoExportStatic returns true for a symbol that has been
// specially marked via the "cgo_export_static" directive
// written by cgo.
func (l *Loader) AttrCgoExportStatic(i Sym) bool {
	_, ok := l.attrCgoExportStatic[i]
	return ok
}

// SetAttrCgoExportStatic sets the "cgo_export_static" for a symbol
// (see AttrCgoExportStatic).
func (l *Loader) SetAttrCgoExportStatic(i Sym, v bool) {
	if v {
		l.attrCgoExportStatic[i] = struct{}{}
	} else {
		delete(l.attrCgoExportStatic, i)
	}
}

// IsGeneratedSym returns true if a symbol's been previously marked as a
// generator symbol through the SetIsGeneratedSym. The functions for generator
// symbols are kept in the Link context.
func (l *Loader) IsGeneratedSym(i Sym) bool {
	if !l.IsExternal(i) {
		return false
	}
	return l.generatedSyms.Has(l.extIndex(i))
}

// SetIsGeneratedSym marks symbols as generated symbols. Data shouldn't be
// stored in generated symbols, and a function is registered and called for
// each of these symbols.
func (l *Loader) SetIsGeneratedSym(i Sym, v bool) {
	if !l.IsExternal(i) {
		panic("only external symbols can be generated")
	}
	if v {
		l.generatedSyms.Set(l.extIndex(i))
	} else {
		l.generatedSyms.Unset(l.extIndex(i))
	}
}

func (l *Loader) AttrCgoExport(i Sym) bool {
	return l.AttrCgoExportDynamic(i) || l.AttrCgoExportStatic(i)
}

// AttrReadOnly returns true for a symbol whose underlying data
// is stored via a read-only mmap.
func (l *Loader) AttrReadOnly(i Sym) bool {
	if v, ok := l.attrReadOnly[i]; ok {
		return v
	}
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		if pp.objidx != 0 {
			return l.objs[pp.objidx].ReadOnly()
		}
		return false
	}
	r, _ := l.toLocal(i)
	return r.ReadOnly()
}

// SetAttrReadOnly sets the "data is read only" property for a symbol
// (see AttrReadOnly).
func (l *Loader) SetAttrReadOnly(i Sym, v bool) {
	l.attrReadOnly[i] = v
}

// AttrSubSymbol returns true for symbols that are listed as a
// sub-symbol of some other outer symbol. The sub/outer mechanism is
// used when loading host objects (sections from the host object
// become regular linker symbols and symbols go on the Sub list of
// their section) and for constructing the global offset table when
// internally linking a dynamic executable.
//
// Note that in later stages of the linker, we set Outer(S) to some
// container symbol C, but don't set Sub(C). Thus we have two
// distinct scenarios:
//
// - Outer symbol covers the address ranges of its sub-symbols.
//   Outer.Sub is set in this case.
// - Outer symbol doesn't cover the address ranges. It is zero-sized
//   and doesn't have sub-symbols. In the case, the inner symbol is
//   not actually a "SubSymbol". (Tricky!)
//
// This method returns TRUE only for sub-symbols in the first scenario.
//
// FIXME: would be better to do away with this and have a better way
// to represent container symbols.

func (l *Loader) AttrSubSymbol(i Sym) bool {
	// we don't explicitly store this attribute any more -- return
	// a value based on the sub-symbol setting.
	o := l.OuterSym(i)
	if o == 0 {
		return false
	}
	return l.SubSym(o) != 0
}

// Note that we don't have a 'SetAttrSubSymbol' method in the loader;
// clients should instead use the AddInteriorSym method to establish
// containment relationships for host object symbols.

// Returns whether the i-th symbol has ReflectMethod attribute set.
func (l *Loader) IsReflectMethod(i Sym) bool {
	return l.SymAttr(i)&goobj.SymFlagReflectMethod != 0
}

// Returns whether the i-th symbol is nosplit.
func (l *Loader) IsNoSplit(i Sym) bool {
	return l.SymAttr(i)&goobj.SymFlagNoSplit != 0
}

// Returns whether this is a Go type symbol.
func (l *Loader) IsGoType(i Sym) bool {
	return l.SymAttr(i)&goobj.SymFlagGoType != 0
}

// Returns whether this symbol should be included in typelink.
func (l *Loader) IsTypelink(i Sym) bool {
	return l.SymAttr(i)&goobj.SymFlagTypelink != 0
}

// Returns whether this symbol is an itab symbol.
func (l *Loader) IsItab(i Sym) bool {
	if l.IsExternal(i) {
		return false
	}
	r, li := l.toLocal(i)
	return r.Sym(li).IsItab()
}

// Returns whether this symbol is a dictionary symbol.
func (l *Loader) IsDict(i Sym) bool {
	if l.IsExternal(i) {
		return false
	}
	r, li := l.toLocal(i)
	return r.Sym(li).IsDict()
}

// Returns whether this symbol is a compiler-generated package init func.
func (l *Loader) IsPkgInit(i Sym) bool {
	if l.IsExternal(i) {
		return false
	}
	r, li := l.toLocal(i)
	return r.Sym(li).IsPkgInit()
}

// Return whether this is a trampoline of a deferreturn call.
func (l *Loader) IsDeferReturnTramp(i Sym) bool {
	return l.deferReturnTramp[i]
}

// Set that i is a trampoline of a deferreturn call.
func (l *Loader) SetIsDeferReturnTramp(i Sym, v bool) {
	l.deferReturnTramp[i] = v
}

// growValues grows the slice used to store symbol values.
func (l *Loader) growValues(reqLen int) {
	curLen := len(l.values)
	if reqLen > curLen {
		l.values = append(l.values, make([]int64, reqLen+1-curLen)...)
	}
}

// SymValue returns the value of the i-th symbol. i is global index.
func (l *Loader) SymValue(i Sym) int64 {
	return l.values[i]
}

// SetSymValue sets the value of the i-th symbol. i is global index.
func (l *Loader) SetSymValue(i Sym, val int64) {
	l.values[i] = val
}

// AddToSymValue adds to the value of the i-th symbol. i is the global index.
func (l *Loader) AddToSymValue(i Sym, val int64) {
	l.values[i] += val
}

// Returns the symbol content of the i-th symbol. i is global index.
func (l *Loader) Data(i Sym) []byte {
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		if pp != nil {
			return pp.data
		}
		return nil
	}
	r, li := l.toLocal(i)
	return r.Data(li)
}

// Returns the symbol content of the i-th symbol as a string. i is global index.
func (l *Loader) DataString(i Sym) string {
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		return string(pp.data)
	}
	r, li := l.toLocal(i)
	return r.DataString(li)
}

// FreeData clears the symbol data of an external symbol, allowing the memory
// to be freed earlier. No-op for non-external symbols.
// i is global index.
func (l *Loader) FreeData(i Sym) {
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		if pp != nil {
			pp.data = nil
		}
	}
}

// SymAlign returns the alignment for a symbol.
func (l *Loader) SymAlign(i Sym) int32 {
	if int(i) >= len(l.align) {
		// align is extended lazily -- it the sym in question is
		// outside the range of the existing slice, then we assume its
		// alignment has not yet been set.
		return 0
	}
	// TODO: would it make sense to return an arch-specific
	// alignment depending on section type? E.g. STEXT => 32,
	// SDATA => 1, etc?
	abits := l.align[i]
	if abits == 0 {
		return 0
	}
	return int32(1 << (abits - 1))
}

// SetSymAlign sets the alignment for a symbol.
func (l *Loader) SetSymAlign(i Sym, align int32) {
	// Reject nonsense alignments.
	if align < 0 || align&(align-1) != 0 {
		panic("bad alignment value")
	}
	if int(i) >= len(l.align) {
		l.align = append(l.align, make([]uint8, l.NSym()-len(l.align))...)
	}
	if align == 0 {
		l.align[i] = 0
	}
	l.align[i] = uint8(bits.Len32(uint32(align)))
}

// SymSect returns the section of the i-th symbol. i is global index.
func (l *Loader) SymSect(i Sym) *sym.Section {
	if int(i) >= len(l.symSects) {
		// symSects is extended lazily -- it the sym in question is
		// outside the range of the existing slice, then we assume its
		// section has not yet been set.
		return nil
	}
	return l.sects[l.symSects[i]]
}

// SetSymSect sets the section of the i-th symbol. i is global index.
func (l *Loader) SetSymSect(i Sym, sect *sym.Section) {
	if int(i) >= len(l.symSects) {
		l.symSects = append(l.symSects, make([]uint16, l.NSym()-len(l.symSects))...)
	}
	l.symSects[i] = sect.Index
}

// NewSection creates a new (output) section.
func (l *Loader) NewSection() *sym.Section {
	sect := new(sym.Section)
	idx := len(l.sects)
	if idx != int(uint16(idx)) {
		panic("too many sections created")
	}
	sect.Index = uint16(idx)
	l.sects = append(l.sects, sect)
	return sect
}

// SymDynimplib returns the "dynimplib" attribute for the specified
// symbol, making up a portion of the info for a symbol specified
// on a "cgo_import_dynamic" compiler directive.
func (l *Loader) SymDynimplib(i Sym) string {
	return l.dynimplib[i]
}

// SetSymDynimplib sets the "dynimplib" attribute for a symbol.
func (l *Loader) SetSymDynimplib(i Sym, value string) {
	// reject bad symbols
	if i >= Sym(len(l.objSyms)) || i == 0 {
		panic("bad symbol index in SetDynimplib")
	}
	if value == "" {
		delete(l.dynimplib, i)
	} else {
		l.dynimplib[i] = value
	}
}

// SymDynimpvers returns the "dynimpvers" attribute for the specified
// symbol, making up a portion of the info for a symbol specified
// on a "cgo_import_dynamic" compiler directive.
func (l *Loader) SymDynimpvers(i Sym) string {
	return l.dynimpvers[i]
}

// SetSymDynimpvers sets the "dynimpvers" attribute for a symbol.
func (l *Loader) SetSymDynimpvers(i Sym, value string) {
	// reject bad symbols
	if i >= Sym(len(l.objSyms)) || i == 0 {
		panic("bad symbol index in SetDynimpvers")
	}
	if value == "" {
		delete(l.dynimpvers, i)
	} else {
		l.dynimpvers[i] = value
	}
}

// SymExtname returns the "extname" value for the specified
// symbol.
func (l *Loader) SymExtname(i Sym) string {
	if s, ok := l.extname[i]; ok {
		return s
	}
	return l.SymName(i)
}

// SetSymExtname sets the  "extname" attribute for a symbol.
func (l *Loader) SetSymExtname(i Sym, value string) {
	// reject bad symbols
	if i >= Sym(len(l.objSyms)) || i == 0 {
		panic("bad symbol index in SetExtname")
	}
	if value == "" {
		delete(l.extname, i)
	} else {
		l.extname[i] = value
	}
}

// SymElfType returns the previously recorded ELF type for a symbol
// (used only for symbols read from shared libraries by ldshlibsyms).
// It is not set for symbols defined by the packages being linked or
// by symbols read by ldelf (and so is left as elf.STT_NOTYPE).
func (l *Loader) SymElfType(i Sym) elf.SymType {
	if et, ok := l.elfType[i]; ok {
		return et
	}
	return elf.STT_NOTYPE
}

// SetSymElfType sets the elf type attribute for a symbol.
func (l *Loader) SetSymElfType(i Sym, et elf.SymType) {
	// reject bad symbols
	if i >= Sym(len(l.objSyms)) || i == 0 {
		panic("bad symbol index in SetSymElfType")
	}
	if et == elf.STT_NOTYPE {
		delete(l.elfType, i)
	} else {
		l.elfType[i] = et
	}
}

// SymElfSym returns the ELF symbol index for a given loader
// symbol, assigned during ELF symtab generation.
func (l *Loader) SymElfSym(i Sym) int32 {
	return l.elfSym[i]
}

// SetSymElfSym sets the elf symbol index for a symbol.
func (l *Loader) SetSymElfSym(i Sym, es int32) {
	if i == 0 {
		panic("bad sym index")
	}
	if es == 0 {
		delete(l.elfSym, i)
	} else {
		l.elfSym[i] = es
	}
}

// SymLocalElfSym returns the "local" ELF symbol index for a given loader
// symbol, assigned during ELF symtab generation.
func (l *Loader) SymLocalElfSym(i Sym) int32 {
	return l.localElfSym[i]
}

// SetSymLocalElfSym sets the "local" elf symbol index for a symbol.
func (l *Loader) SetSymLocalElfSym(i Sym, es int32) {
	if i == 0 {
		panic("bad sym index")
	}
	if es == 0 {
		delete(l.localElfSym, i)
	} else {
		l.localElfSym[i] = es
	}
}

// SymPlt returns the PLT offset of symbol s.
func (l *Loader) SymPlt(s Sym) int32 {
	if v, ok := l.plt[s]; ok {
		return v
	}
	return -1
}

// SetPlt sets the PLT offset of symbol i.
func (l *Loader) SetPlt(i Sym, v int32) {
	if i >= Sym(len(l.objSyms)) || i == 0 {
		panic("bad symbol for SetPlt")
	}
	if v == -1 {
		delete(l.plt, i)
	} else {
		l.plt[i] = v
	}
}

// SymGot returns the GOT offset of symbol s.
func (l *Loader) SymGot(s Sym) int32 {
	if v, ok := l.got[s]; ok {
		return v
	}
	return -1
}

// SetGot sets the GOT offset of symbol i.
func (l *Loader) SetGot(i Sym, v int32) {
	if i >= Sym(len(l.objSyms)) || i == 0 {
		panic("bad symbol for SetGot")
	}
	if v == -1 {
		delete(l.got, i)
	} else {
		l.got[i] = v
	}
}

// SymDynid returns the "dynid" property for the specified symbol.
func (l *Loader) SymDynid(i Sym) int32 {
	if s, ok := l.dynid[i]; ok {
		return s
	}
	return -1
}

// SetSymDynid sets the "dynid" property for a symbol.
func (l *Loader) SetSymDynid(i Sym, val int32) {
	// reject bad symbols
	if i >= Sym(len(l.objSyms)) || i == 0 {
		panic("bad symbol index in SetSymDynid")
	}
	if val == -1 {
		delete(l.dynid, i)
	} else {
		l.dynid[i] = val
	}
}

// DynidSyms returns the set of symbols for which dynID is set to an
// interesting (non-default) value. This is expected to be a fairly
// small set.
func (l *Loader) DynidSyms() []Sym {
	sl := make([]Sym, 0, len(l.dynid))
	for s := range l.dynid {
		sl = append(sl, s)
	}
	sort.Slice(sl, func(i, j int) bool { return sl[i] < sl[j] })
	return sl
}

// SymGoType returns the 'Gotype' property for a given symbol (set by
// the Go compiler for variable symbols). This version relies on
// reading aux symbols for the target sym -- it could be that a faster
// approach would be to check for gotype during preload and copy the
// results in to a map (might want to try this at some point and see
// if it helps speed things up).
func (l *Loader) SymGoType(i Sym) Sym { return l.aux1(i, goobj.AuxGotype) }

// SymUnit returns the compilation unit for a given symbol (which will
// typically be nil for external or linker-manufactured symbols).
func (l *Loader) SymUnit(i Sym) *sym.CompilationUnit {
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		if pp.objidx != 0 {
			r := l.objs[pp.objidx]
			return r.unit
		}
		return nil
	}
	r, _ := l.toLocal(i)
	return r.unit
}

// SymPkg returns the package where the symbol came from (for
// regular compiler-generated Go symbols), but in the case of
// building with "-linkshared" (when a symbol is read from a
// shared library), will hold the library name.
// NOTE: this corresponds to sym.Symbol.File field.
func (l *Loader) SymPkg(i Sym) string {
	if f, ok := l.symPkg[i]; ok {
		return f
	}
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		if pp.objidx != 0 {
			r := l.objs[pp.objidx]
			return r.unit.Lib.Pkg
		}
		return ""
	}
	r, _ := l.toLocal(i)
	return r.unit.Lib.Pkg
}

// SetSymPkg sets the package/library for a symbol. This is
// needed mainly for external symbols, specifically those imported
// from shared libraries.
func (l *Loader) SetSymPkg(i Sym, pkg string) {
	// reject bad symbols
	if i >= Sym(len(l.objSyms)) || i == 0 {
		panic("bad symbol index in SetSymPkg")
	}
	l.symPkg[i] = pkg
}

// SymLocalentry returns an offset in bytes of the "local entry" of a symbol.
//
// On PPC64, a value of 1 indicates the symbol does not use or preserve a TOC
// pointer in R2, nor does it have a distinct local entry.
func (l *Loader) SymLocalentry(i Sym) uint8 {
	return l.localentry[i]
}

// SetSymLocalentry sets the "local entry" offset attribute for a symbol.
func (l *Loader) SetSymLocalentry(i Sym, value uint8) {
	// reject bad symbols
	if i >= Sym(len(l.objSyms)) || i == 0 {
		panic("bad symbol index in SetSymLocalentry")
	}
	if value == 0 {
		delete(l.localentry, i)
	} else {
		l.localentry[i] = value
	}
}

// Returns the number of aux symbols given a global index.
func (l *Loader) NAux(i Sym) int {
	if l.IsExternal(i) {
		return 0
	}
	r, li := l.toLocal(i)
	return r.NAux(li)
}

// Returns the "handle" to the j-th aux symbol of the i-th symbol.
func (l *Loader) Aux(i Sym, j int) Aux {
	if l.IsExternal(i) {
		return Aux{}
	}
	r, li := l.toLocal(i)
	if j >= r.NAux(li) {
		return Aux{}
	}
	return Aux{r.Aux(li, j), r, l}
}

// WasmImportSym returns the auxiliary WebAssembly import symbol associated with
// a given function symbol. The aux sym only exists for Go function stubs that
// have been annotated with the //go:wasmimport directive.  The aux sym
// contains the information necessary for the linker to add a WebAssembly
// import statement.
// (https://webassembly.github.io/spec/core/syntax/modules.html#imports)
func (l *Loader) WasmImportSym(fnSymIdx Sym) Sym {
	if !l.SymType(fnSymIdx).IsText() {
		log.Fatalf("error: non-function sym %d/%s t=%s passed to WasmImportSym", fnSymIdx, l.SymName(fnSymIdx), l.SymType(fnSymIdx).String())
	}
	return l.aux1(fnSymIdx, goobj.AuxWasmImport)
}

func (l *Loader) WasmTypeSym(s Sym) Sym {
	return l.aux1(s, goobj.AuxWasmType)
}

// SEHUnwindSym returns the auxiliary SEH unwind symbol associated with
// a given function symbol.
func (l *Loader) SEHUnwindSym(fnSymIdx Sym) Sym {
	if !l.SymType(fnSymIdx).IsText() {
		log.Fatalf("error: non-function sym %d/%s t=%s passed to SEHUnwindSym", fnSymIdx, l.SymName(fnSymIdx), l.SymType(fnSymIdx).String())
	}

	return l.aux1(fnSymIdx, goobj.AuxSehUnwindInfo)
}

// GetFuncDwarfAuxSyms collects and returns the auxiliary DWARF
// symbols associated with a given function symbol.  Prior to the
// introduction of the loader, this was done purely using name
// lookups, e.f. for function with name XYZ we would then look up
// go.info.XYZ, etc.
func (l *Loader) GetFuncDwarfAuxSyms(fnSymIdx Sym) (auxDwarfInfo, auxDwarfLoc, auxDwarfRanges, auxDwarfLines Sym) {
	if !l.SymType(fnSymIdx).IsText() {
		log.Fatalf("error: non-function sym %d/%s t=%s passed to GetFuncDwarfAuxSyms", fnSymIdx, l.SymName(fnSymIdx), l.SymType(fnSymIdx).String())
	}
	r, auxs := l.auxs(fnSymIdx)

	for i := range auxs {
		a := &auxs[i]
		switch a.Type() {
		case goobj.AuxDwarfInfo:
			auxDwarfInfo = l.resolve(r, a.Sym())
			if l.SymType(auxDwarfInfo) != sym.SDWARFFCN {
				panic("aux dwarf info sym with wrong type")
			}
		case goobj.AuxDwarfLoc:
			auxDwarfLoc = l.resolve(r, a.Sym())
			if l.SymType(auxDwarfLoc) != sym.SDWARFLOC {
				panic("aux dwarf loc sym with wrong type")
			}
		case goobj.AuxDwarfRanges:
			auxDwarfRanges = l.resolve(r, a.Sym())
			if l.SymType(auxDwarfRanges) != sym.SDWARFRANGE {
				panic("aux dwarf ranges sym with wrong type")
			}
		case goobj.AuxDwarfLines:
			auxDwarfLines = l.resolve(r, a.Sym())
			if l.SymType(auxDwarfLines) != sym.SDWARFLINES {
				panic("aux dwarf lines sym with wrong type")
			}
		}
	}
	return
}

func (l *Loader) GetVarDwarfAuxSym(i Sym) Sym {
	aux := l.aux1(i, goobj.AuxDwarfInfo)
	if aux != 0 && l.SymType(aux) != sym.SDWARFVAR {
		fmt.Println(l.SymName(i), l.SymType(i), l.SymType(aux), sym.SDWARFVAR)
		panic("aux dwarf info sym with wrong type")
	}
	return aux
}

// AddInteriorSym sets up 'interior' as an interior symbol of
// container/payload symbol 'container'. An interior symbol does not
// itself have data, but gives a name to a subrange of the data in its
// container symbol. The container itself may or may not have a name.
// This method is intended primarily for use in the host object
// loaders, to capture the semantics of symbols and sections in an
// object file. When reading a host object file, we'll typically
// encounter a static section symbol (ex: ".text") containing content
// for a collection of functions, then a series of ELF (or macho, etc)
// symbol table entries each of which points into a sub-section
// (offset and length) of its corresponding container symbol. Within
// the go linker we create a loader.Sym for the container (which is
// expected to have the actual content/payload) and then a set of
// interior loader.Sym's that point into a portion of the container.
func (l *Loader) AddInteriorSym(container Sym, interior Sym) {
	// Container symbols are expected to have content/data.
	// NB: this restriction may turn out to be too strict (it's possible
	// to imagine a zero-sized container with an interior symbol pointing
	// into it); it's ok to relax or remove it if we counter an
	// oddball host object that triggers this.
	if l.SymSize(container) == 0 && len(l.Data(container)) == 0 {
		panic("unexpected empty container symbol")
	}
	// The interior symbols for a container are not expected to have
	// content/data or relocations.
	if len(l.Data(interior)) != 0 {
		panic("unexpected non-empty interior symbol")
	}
	// Interior symbol is expected to be in the symbol table.
	if l.AttrNotInSymbolTable(interior) {
		panic("interior symbol must be in symtab")
	}
	// Only a single level of containment is allowed.
	if l.OuterSym(container) != 0 {
		panic("outer has outer itself")
	}
	// Interior sym should not already have a sibling.
	if l.SubSym(interior) != 0 {
		panic("sub set for subsym")
	}
	// Interior sym should not already point at a container.
	if l.OuterSym(interior) != 0 {
		panic("outer already set for subsym")
	}
	l.sub[interior] = l.sub[container]
	l.sub[container] = interior
	l.outer[interior] = container
}

// OuterSym gets the outer/container symbol.
func (l *Loader) OuterSym(i Sym) Sym {
	return l.outer[i]
}

// SubSym gets the subsymbol for host object loaded symbols.
func (l *Loader) SubSym(i Sym) Sym {
	return l.sub[i]
}

// growOuter grows the slice used to store outer symbol.
func (l *Loader) growOuter(reqLen int) {
	curLen := len(l.outer)
	if reqLen > curLen {
		l.outer = append(l.outer, make([]Sym, reqLen-curLen)...)
	}
}

// SetCarrierSym declares that 'c' is the carrier or container symbol
// for 's'. Carrier symbols are used in the linker to as a container
// for a collection of sub-symbols where the content of the
// sub-symbols is effectively concatenated to form the content of the
// carrier. The carrier is given a name in the output symbol table
// while the sub-symbol names are not. For example, the Go compiler
// emits named string symbols (type SGOSTRING) when compiling a
// package; after being deduplicated, these symbols are collected into
// a single unit by assigning them a new carrier symbol named
// "go:string.*" (which appears in the final symbol table for the
// output load module).
func (l *Loader) SetCarrierSym(s Sym, c Sym) {
	if c == 0 {
		panic("invalid carrier in SetCarrierSym")
	}
	if s == 0 {
		panic("invalid sub-symbol in SetCarrierSym")
	}
	// Carrier symbols are not expected to have content/data. It is
	// ok for them to have non-zero size (to allow for use of generator
	// symbols).
	if len(l.Data(c)) != 0 {
		panic("unexpected non-empty carrier symbol")
	}
	l.outer[s] = c
	// relocsym's foldSubSymbolOffset requires that we only
	// have a single level of containment-- enforce here.
	if l.outer[c] != 0 {
		panic("invalid nested carrier sym")
	}
}

// Initialize Reachable bitmap and its siblings for running deadcode pass.
func (l *Loader) InitReachable() {
	l.growAttrBitmaps(l.NSym() + 1)
}

type symWithVal struct {
	s Sym
	v int64
}
type bySymValue []symWithVal

func (s bySymValue) Len() int           { return len(s) }
func (s bySymValue) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s bySymValue) Less(i, j int) bool { return s[i].v < s[j].v }

// SortSub walks through the sub-symbols for 's' and sorts them
// in place by increasing value. Return value is the new
// sub symbol for the specified outer symbol.
func (l *Loader) SortSub(s Sym) Sym {

	if s == 0 || l.sub[s] == 0 {
		return s
	}

	// Sort symbols using a slice first. Use a stable sort on the off
	// chance that there's more than once symbol with the same value,
	// so as to preserve reproducible builds.
	sl := []symWithVal{}
	for ss := l.sub[s]; ss != 0; ss = l.sub[ss] {
		sl = append(sl, symWithVal{s: ss, v: l.SymValue(ss)})
	}
	sort.Stable(bySymValue(sl))

	// Then apply any changes needed to the sub map.
	ns := Sym(0)
	for i := len(sl) - 1; i >= 0; i-- {
		s := sl[i].s
		l.sub[s] = ns
		ns = s
	}

	// Update sub for outer symbol, then return
	l.sub[s] = sl[0].s
	return sl[0].s
}

// SortSyms sorts a list of symbols by their value.
func (l *Loader) SortSyms(ss []Sym) {
	sort.SliceStable(ss, func(i, j int) bool { return l.SymValue(ss[i]) < l.SymValue(ss[j]) })
}

// Insure that reachable bitmap and its siblings have enough size.
func (l *Loader) growAttrBitmaps(reqLen int) {
	if reqLen > l.attrReachable.Len() {
		// These are indexed by global symbol
		l.attrReachable = growBitmap(reqLen, l.attrReachable)
		l.attrOnList = growBitmap(reqLen, l.attrOnList)
		l.attrLocal = growBitmap(reqLen, l.attrLocal)
		l.attrNotInSymbolTable = growBitmap(reqLen, l.attrNotInSymbolTable)
		l.attrUsedInIface = growBitmap(reqLen, l.attrUsedInIface)
		l.attrSpecial = growBitmap(reqLen, l.attrSpecial)
	}
	l.growExtAttrBitmaps()
}

func (l *Loader) growExtAttrBitmaps() {
	// These are indexed by external symbol index (e.g. l.extIndex(i))
	extReqLen := len(l.payloads)
	if extReqLen > l.attrVisibilityHidden.Len() {
		l.attrVisibilityHidden = growBitmap(extReqLen, l.attrVisibilityHidden)
		l.attrDuplicateOK = growBitmap(extReqLen, l.attrDuplicateOK)
		l.attrShared = growBitmap(extReqLen, l.attrShared)
		l.attrExternal = growBitmap(extReqLen, l.attrExternal)
		l.generatedSyms = growBitmap(extReqLen, l.generatedSyms)
	}
}

func (relocs *Relocs) Count() int { return len(relocs.rs) }

// At returns the j-th reloc for a global symbol.
func (relocs *Relocs) At(j int) Reloc {
	if relocs.l.isExtReader(relocs.r) {
		return Reloc{&relocs.rs[j], relocs.r, relocs.l}
	}
	return Reloc{&relocs.rs[j], relocs.r, relocs.l}
}

// Relocs returns a Relocs object for the given global sym.
func (l *Loader) Relocs(i Sym) Relocs {
	r, li := l.toLocal(i)
	if r == nil {
		panic(fmt.Sprintf("trying to get oreader for invalid sym %d\n\n", i))
	}
	return l.relocs(r, li)
}

// relocs returns a Relocs object given a local sym index and reader.
func (l *Loader) relocs(r *oReader, li uint32) Relocs {
	var rs []goobj.Reloc
	if l.isExtReader(r) {
		pp := l.payloads[li]
		rs = pp.relocs
	} else {
		rs = r.Relocs(li)
	}
	return Relocs{
		rs: rs,
		li: li,
		r:  r,
		l:  l,
	}
}

func (l *Loader) auxs(i Sym) (*oReader, []goobj.Aux) {
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		return l.objs[pp.objidx], pp.auxs
	} else {
		r, li := l.toLocal(i)
		return r, r.Auxs(li)
	}
}

// Returns a specific aux symbol of type t for symbol i.
func (l *Loader) aux1(i Sym, t uint8) Sym {
	r, auxs := l.auxs(i)
	for j := range auxs {
		a := &auxs[j]
		if a.Type() == t {
			return l.resolve(r, a.Sym())
		}
	}
	return 0
}

func (l *Loader) Pcsp(i Sym) Sym { return l.aux1(i, goobj.AuxPcsp) }

// Returns all aux symbols of per-PC data for symbol i.
// tmp is a scratch space for the pcdata slice.
func (l *Loader) PcdataAuxs(i Sym, tmp []Sym) (pcsp, pcfile, pcline, pcinline Sym, pcdata []Sym) {
	pcdata = tmp[:0]
	r, auxs := l.auxs(i)
	for j := range auxs {
		a := &auxs[j]
		switch a.Type() {
		case goobj.AuxPcsp:
			pcsp = l.resolve(r, a.Sym())
		case goobj.AuxPcline:
			pcline = l.resolve(r, a.Sym())
		case goobj.AuxPcfile:
			pcfile = l.resolve(r, a.Sym())
		case goobj.AuxPcinline:
			pcinline = l.resolve(r, a.Sym())
		case goobj.AuxPcdata:
			pcdata = append(pcdata, l.resolve(r, a.Sym()))
		}
	}
	return
}

// Returns the number of pcdata for symbol i.
func (l *Loader) NumPcdata(i Sym) int {
	n := 0
	_, auxs := l.auxs(i)
	for j := range auxs {
		a := &auxs[j]
		if a.Type() == goobj.AuxPcdata {
			n++
		}
	}
	return n
}

// Returns all funcdata symbols of symbol i.
// tmp is a scratch space.
func (l *Loader) Funcdata(i Sym, tmp []Sym) []Sym {
	fd := tmp[:0]
	r, auxs := l.auxs(i)
	for j := range auxs {
		a := &auxs[j]
		if a.Type() == goobj.AuxFuncdata {
			fd = append(fd, l.resolve(r, a.Sym()))
		}
	}
	return fd
}

// Returns the number of funcdata for symbol i.
func (l *Loader) NumFuncdata(i Sym) int {
	n := 0
	_, auxs := l.auxs(i)
	for j := range auxs {
		a := &auxs[j]
		if a.Type() == goobj.AuxFuncdata {
			n++
		}
	}
	return n
}

// FuncInfo provides hooks to access goobj.FuncInfo in the objects.
type FuncInfo struct {
	l       *Loader
	r       *oReader
	data    []byte
	lengths goobj.FuncInfoLengths
}

func (fi *FuncInfo) Valid() bool { return fi.r != nil }

func (fi *FuncInfo) Args() int {
	return int((*goobj.FuncInfo)(nil).ReadArgs(fi.data))
}

func (fi *FuncInfo) Locals() int {
	return int((*goobj.FuncInfo)(nil).ReadLocals(fi.data))
}

func (fi *FuncInfo) FuncID() abi.FuncID {
	return (*goobj.FuncInfo)(nil).ReadFuncID(fi.data)
}

func (fi *FuncInfo) FuncFlag() abi.FuncFlag {
	return (*goobj.FuncInfo)(nil).ReadFuncFlag(fi.data)
}

func (fi *FuncInfo) StartLine() int32 {
	return (*goobj.FuncInfo)(nil).ReadStartLine(fi.data)
}

// Preload has to be called prior to invoking the various methods
// below related to pcdata, funcdataoff, files, and inltree nodes.
func (fi *FuncInfo) Preload() {
	fi.lengths = (*goobj.FuncInfo)(nil).ReadFuncInfoLengths(fi.data)
}

func (fi *FuncInfo) NumFile() uint32 {
	if !fi.lengths.Initialized {
		panic("need to call Preload first")
	}
	return fi.lengths.NumFile
}

func (fi *FuncInfo) File(k int) goobj.CUFileIndex {
	if !fi.lengths.Initialized {
		panic("need to call Preload first")
	}
	return (*goobj.FuncInfo)(nil).ReadFile(fi.data, fi.lengths.FileOff, uint32(k))
}

// TopFrame returns true if the function associated with this FuncInfo
// is an entry point, meaning that unwinders should stop when they hit
// this function.
func (fi *FuncInfo) TopFrame() bool {
	return (fi.FuncFlag() & abi.FuncFlagTopFrame) != 0
}

type InlTreeNode struct {
	Parent   int32
	File     goobj.CUFileIndex
	Line     int32
	Func     Sym
	ParentPC int32
}

func (fi *FuncInfo) NumInlTree() uint32 {
	if !fi.lengths.Initialized {
		panic("need to call Preload first")
	}
	return fi.lengths.NumInlTree
}

func (fi *FuncInfo) InlTree(k int) InlTreeNode {
	if !fi.lengths.Initialized {
		panic("need to call Preload first")
	}
	node := (*goobj.FuncInfo)(nil).ReadInlTree(fi.data, fi.lengths.InlTreeOff, uint32(k))
	return InlTreeNode{
		Parent:   node.Parent,
		File:     node.File,
		Line:     node.Line,
		Func:     fi.l.resolve(fi.r, node.Func),
		ParentPC: node.ParentPC,
	}
}

func (l *Loader) FuncInfo(i Sym) FuncInfo {
	r, auxs := l.auxs(i)
	for j := range auxs {
		a := &auxs[j]
		if a.Type() == goobj.AuxFuncInfo {
			b := r.Data(a.Sym().SymIdx)
			return FuncInfo{l, r, b, goobj.FuncInfoLengths{}}
		}
	}
	return FuncInfo{}
}

// Preload a package: adds autolib.
// Does not add defined package or non-packaged symbols to the symbol table.
// These are done in LoadSyms.
// Does not read symbol data.
// Returns the fingerprint of the object.
func (l *Loader) Preload(localSymVersion int, f *bio.Reader, lib *sym.Library, unit *sym.CompilationUnit, length int64) goobj.FingerprintType {
	roObject, readonly, err := f.Slice(uint64(length)) // TODO: no need to map blocks that are for tools only (e.g. RefName)
	if err != nil {
		log.Fatal("cannot read object file:", err)
	}
	r := goobj.NewReaderFromBytes(roObject, readonly)
	if r == nil {
		if len(roObject) >= 8 && bytes.Equal(roObject[:8], []byte("\x00go114ld")) {
			log.Fatalf("found object file %s in old format", f.File().Name())
		}
		panic("cannot read object file")
	}
	pkgprefix := objabi.PathToPrefix(lib.Pkg) + "."
	ndef := r.NSym()
	nhashed64def := r.NHashed64def()
	nhasheddef := r.NHasheddef()
	or := &oReader{
		Reader:       r,
		unit:         unit,
		version:      localSymVersion,
		pkgprefix:    pkgprefix,
		syms:         make([]Sym, ndef+nhashed64def+nhasheddef+r.NNonpkgdef()+r.NNonpkgref()),
		ndef:         ndef,
		nhasheddef:   nhasheddef,
		nhashed64def: nhashed64def,
		objidx:       uint32(len(l.objs)),
	}

	if r.Unlinkable() {
		log.Fatalf("link: unlinkable object (from package %s) - compiler requires -p flag", lib.Pkg)
	}

	// Autolib
	lib.Autolib = append(lib.Autolib, r.Autolib()...)

	// DWARF file table
	nfile := r.NFile()
	unit.FileTable = make([]string, nfile)
	for i := range unit.FileTable {
		unit.FileTable[i] = r.File(i)
	}

	l.addObj(lib.Pkg, or)

	// The caller expects us consuming all the data
	f.MustSeek(length, io.SeekCurrent)

	return r.Fingerprint()
}

// Holds the loader along with temporary states for loading symbols.
type loadState struct {
	l            *Loader
	hashed64Syms map[uint64]symAndSize         // short hashed (content-addressable) symbols, keyed by content hash
	hashedSyms   map[goobj.HashType]symAndSize // hashed (content-addressable) symbols, keyed by content hash

	linknameVarRefs []linknameVarRef // linknamed var refererces
}

type linknameVarRef struct {
	pkg  string // package of reference (not definition)
	name string
	sym  Sym
}

// Preload symbols of given kind from an object.
func (st *loadState) preloadSyms(r *oReader, kind int) {
	l := st.l
	var start, end uint32
	switch kind {
	case pkgDef:
		start = 0
		end = uint32(r.ndef)
	case hashed64Def:
		start = uint32(r.ndef)
		end = uint32(r.ndef + r.nhashed64def)
	case hashedDef:
		start = uint32(r.ndef + r.nhashed64def)
		end = uint32(r.ndef + r.nhashed64def + r.nhasheddef)
	case nonPkgDef:
		start = uint32(r.ndef + r.nhashed64def + r.nhasheddef)
		end = uint32(r.ndef + r.nhashed64def + r.nhasheddef + r.NNonpkgdef())
	default:
		panic("preloadSyms: bad kind")
	}
	l.growAttrBitmaps(len(l.objSyms) + int(end-start))
	loadingRuntimePkg := r.unit.Lib.Pkg == "runtime"
	for i := start; i < end; i++ {
		osym := r.Sym(i)
		var name string
		var v int
		if kind != hashed64Def && kind != hashedDef { // we don't need the name, etc. for hashed symbols
			name = osym.Name(r.Reader)
			v = abiToVer(osym.ABI(), r.version)
		}
		gi := st.addSym(name, v, r, i, kind, osym)
		r.syms[i] = gi
		if kind == nonPkgDef && osym.IsLinkname() && r.DataSize(i) == 0 && strings.Contains(name, ".") {
			// This is a linknamed "var" "reference" (var x T with no data and //go:linkname x).
			// We want to check if a link
```