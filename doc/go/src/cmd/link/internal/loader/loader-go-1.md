Response:
The user wants a summary of the functionalities of the Go code snippet provided. This is the second part of a two-part code.

Here's a breakdown of how to approach this:

1. **Identify Key Data Structures:** Look for the main types and fields used in the code. This gives a high-level understanding. The `Loader` struct is central.
2. **Analyze Function Groups:**  Group the functions based on their purpose. For example, symbol loading, relocation handling, error reporting.
3. **Summarize Each Group:** Briefly describe what each group of functions does.
4. **Consider the Context:** The code is from `cmd/link`, indicating it's part of the linking process. This helps in understanding the overall goal.
5. **Infer Go Features:** Based on the function names and actions (like `linknameVarRefs`, `WasmExports`), try to deduce which Go language features are being handled.
6. **Address Specific Instructions:** Ensure that the summary addresses all the explicit requests in the prompt (functionality, inferred Go features with examples, command-line parameters, common mistakes - although the snippet doesn't directly show command-line handling or common mistakes in *using* this code itself).
7. **Focus on the "Second Part" aspect:** Remember that this is part 2, so it likely builds upon concepts introduced in part 1. While the provided snippet is self-contained, acknowledging this context is important.
根据提供的 Go 语言代码片段，我们可以归纳出以下 `loader.go` 文件的功能：

**核心功能：符号加载和管理**

这段代码主要负责加载和管理链接过程中的各种符号信息，这些符号来源于编译后的 Go 目标文件 (`.o` 文件)。它构建了一个中心化的数据结构 (`Loader`) 来存储和查询这些符号，以便后续的链接操作，例如符号解析、重定位等。

**具体功能点：**

1. **加载符号定义 (Definitions):**
   - `preloadSyms`: 遍历目标文件中的符号，根据符号的类型（包内定义、哈希定义、非包定义）将其添加到 `Loader` 的相应数据结构中。
   - 区分不同类型的符号：
     - 包内符号 (package definitions): 属于特定 Go 包的符号。
     - 哈希符号 (hashed definitions):  使用内容哈希进行标识的符号，用于去重。
     - 非包符号 (non-package definitions): 不属于任何 Go 包的符号，通常是 C 符号或者汇编符号。
   - 处理 `linkname` 指令：
     - 记录使用了 `//go:linkname` 的变量引用 (`linknameVarRefs`)，以便在所有符号定义加载完成后进行检查。
     - `checkLinkname`: 检查 `linkname` 的使用是否符合规则，例如是否在允许的包中引用。
   - 记录符号的属性：例如是否是本地符号 (`Local`)，是否在接口中使用 (`UsedInIface`)，对齐方式 (`Align`)，是否是 Wasm 导出符号 (`WasmExport`)。
   - 处理内置符号 (`builtinSyms`)：识别并记录 `runtime` 包中特殊的内置符号。

2. **加载符号引用 (References):**
   - `LoadSyms`: 作为加载符号的入口，它分配存储符号的空间，并调用 `preloadSyms` 加载不同类型的符号定义。之后调用 `loadObjRefs` 加载符号的引用。
   - `loadObjRefs`:  处理目标文件中对其他符号的引用。
   - 处理非包引用 (non-package references):  加载对 C 符号或汇编符号的引用。
   - 处理包引用 (package references):  记录当前目标文件引用的其他 Go 包。
   - 处理引用标志 (reference flags):  记录引用的额外属性，例如是否在接口中使用。

3. **符号属性管理:**
   - `SetAttrLocal`, `SetAttrUsedInIface`, `SetSymAlign`, `SetAttrDuplicateOK`, `SetAttrShared`:  设置符号的各种属性。

4. **外部符号处理:**
   - `cloneToExternal`:  将目标文件中的符号克隆成一个外部符号，用于在链接过程中修改符号内容。
   - `CopySym`: 将一个外部符号的内容复制到另一个外部符号。
   - `CreateExtSym`: 创建一个新的外部符号。
   - `CreateStaticSym`: 创建一个新的静态符号（具有唯一的负版本号，不参与名称查找）。
   - `FreeSym`: 释放外部符号的 payload 空间。

5. **重定位信息管理:**
   - `SetRelocVariant`: 设置符号重定位条目的变体属性。
   - `RelocVariant`: 获取符号重定位条目的变体属性。
   - `UndefinedRelocTargets`: 查找具有指向未定义符号的重定位的符号，用于检测链接错误。

6. **文本段符号排序:**
   - `AssignTextSymbolOrder`:  将代码段 (`.text`) 的符号按照依赖顺序分配到各个库和编译单元中，确保链接时代码的正确布局。

7. **错误报告:**
   - `ErrorReporter`:  提供错误报告机制，用于在链接过程中输出错误信息。
   - `Errorf`:  记录错误信息。

8. **符号信息查询和统计:**
   - `TopLevelSym`: 判断一个符号是否是顶层符号（参与链接），而不是辅助符号。
   - `Stat`:  返回符号的统计信息。
   - `Dump`:  输出 `Loader` 中存储的符号信息，用于调试。

**推断的 Go 语言功能实现：`//go:linkname` 指令**

代码中对 `linknameVarRefs` 的处理以及 `checkLinkname` 函数，明显是在处理 `//go:linkname` 指令。这个指令允许将一个 Go 语言符号关联到另一个包甚至非 Go 语言的符号。

**Go 代码示例：`//go:linkname` 的使用**

假设在 `mypkg` 包中，你想引用 `libc` 中的 `malloc` 函数：

```go
package mypkg

import "unsafe"

//go:linkname myMalloc runtime.malloc
func myMalloc(size uintptr) unsafe.Pointer

func Alloc(size int) unsafe.Pointer {
	return myMalloc(uintptr(size))
}
```

在这个例子中，`//go:linkname myMalloc runtime.malloc` 将 `mypkg.myMalloc` 链接到了 `runtime` 包的内部 `malloc` 函数。在链接阶段，`loader.go` 中的代码会识别并处理这种链接关系。

**假设的输入与输出（针对 `checkLinkname`）**

**假设输入：**

- `l`: `Loader` 实例
- `pkg`: "mypkg" (当前引用 `linkname` 的包)
- `name`: "runtime.malloc" (被引用的符号名称)
- `s`:  `runtime.malloc` 对应的 `Sym`

**假设 `blockedLinknames` 中没有 "runtime.malloc" 的条目，并且 `runtime.malloc` 的定义有 `//go:linkname` 指令。**

**预期输出：**

`checkLinkname` 函数不会产生错误，因为：

1. `runtime.malloc` 不在 `blockedLinknames` 中。
2. `runtime.malloc` 的定义（假设）使用了 `//go:linkname` (对应 `osym.IsLinkname()` 返回 `true`)。

**如果 `blockedLinknames` 中有 `"runtime.malloc": {"someotherpkg"}`，且 `pkg` 不是 "someotherpkg"，则会调用 `log.Fatalf` 报错。**

**命令行参数的具体处理：**

这段代码片段本身没有直接处理命令行参数的逻辑。命令行参数的处理通常发生在 `cmd/link/main.go` 或相关的初始化代码中。但是，代码中的 `l.flags&FlagCheckLinkname` 表明存在一个名为 `FlagCheckLinkname` 的标志，这很可能是一个通过命令行参数控制的选项，用于开启或关闭 `linkname` 的检查。

**使用者易犯错的点（基于代码推断）：**

虽然这段代码是链接器的内部实现，普通 Go 开发者不会直接使用它，但是理解其背后的逻辑有助于避免在使用 `//go:linkname` 时犯错：

- **错误的 `linkname` 目标:**  将 `//go:linkname` 指向不存在的符号或错误的包。
- **违反 `blockedLinknames` 规则:** 在不允许的包中引用某些被限制的 `linkname` 符号。 例如，尝试在非 `iter` 包中链接 `runtime.coroswitch`。

**总结：**

`loader.go` 的这一部分是 Go 链接器中至关重要的组成部分，它负责从编译后的目标文件中加载和组织符号信息，并对 `//go:linkname` 指令进行管理和校验。它为后续的链接阶段（如符号解析、重定位、代码布局）提供了必要的数据基础。

Prompt: 
```
这是路径为go/src/cmd/link/internal/loader/loader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
name reference is allowed. Here we haven't loaded all
			// symbol definitions, so we don't yet know all the push linknames. So we add to a
			// list and check later after all symbol defs are loaded. Linknamed vars are rare,
			// so this list won't be long.
			// Only check references (pull), not definitions (push, with non-zero size),
			// so push is always allowed.
			// This use of linkname is usually for referencing C symbols, so allow symbols
			// with no "." in its name (not a regular Go symbol).
			// Linkname is always a non-package reference.
			st.linknameVarRefs = append(st.linknameVarRefs, linknameVarRef{r.unit.Lib.Pkg, name, gi})
		}
		if osym.Local() {
			l.SetAttrLocal(gi, true)
		}
		if osym.UsedInIface() {
			l.SetAttrUsedInIface(gi, true)
		}
		if strings.HasPrefix(name, "runtime.") ||
			(loadingRuntimePkg && strings.HasPrefix(name, "type:")) {
			if bi := goobj.BuiltinIdx(name, int(osym.ABI())); bi != -1 {
				// This is a definition of a builtin symbol. Record where it is.
				l.builtinSyms[bi] = gi
			}
		}
		if a := int32(osym.Align()); a != 0 && a > l.SymAlign(gi) {
			l.SetSymAlign(gi, a)
		}
		if osym.WasmExport() {
			l.WasmExports = append(l.WasmExports, gi)
		}
	}
}

// Add syms, hashed (content-addressable) symbols, non-package symbols, and
// references to external symbols (which are always named).
func (l *Loader) LoadSyms(arch *sys.Arch) {
	// Allocate space for symbols, making a guess as to how much space we need.
	// This function was determined empirically by looking at the cmd/compile on
	// Darwin, and picking factors for hashed and hashed64 syms.
	var symSize, hashedSize, hashed64Size int
	for _, r := range l.objs[goObjStart:] {
		symSize += r.ndef + r.nhasheddef/2 + r.nhashed64def/2 + r.NNonpkgdef()
		hashedSize += r.nhasheddef / 2
		hashed64Size += r.nhashed64def / 2
	}
	// Index 0 is invalid for symbols.
	l.objSyms = make([]objSym, 1, symSize)

	st := loadState{
		l:            l,
		hashed64Syms: make(map[uint64]symAndSize, hashed64Size),
		hashedSyms:   make(map[goobj.HashType]symAndSize, hashedSize),
	}

	for _, r := range l.objs[goObjStart:] {
		st.preloadSyms(r, pkgDef)
	}
	l.npkgsyms = l.NSym()
	for _, r := range l.objs[goObjStart:] {
		st.preloadSyms(r, hashed64Def)
		st.preloadSyms(r, hashedDef)
		st.preloadSyms(r, nonPkgDef)
	}
	for _, vr := range st.linknameVarRefs {
		l.checkLinkname(vr.pkg, vr.name, vr.sym)
	}
	l.nhashedsyms = len(st.hashed64Syms) + len(st.hashedSyms)
	for _, r := range l.objs[goObjStart:] {
		loadObjRefs(l, r, arch)
	}
	l.values = make([]int64, l.NSym(), l.NSym()+1000) // +1000 make some room for external symbols
	l.outer = make([]Sym, l.NSym(), l.NSym()+1000)
}

func loadObjRefs(l *Loader, r *oReader, arch *sys.Arch) {
	// load non-package refs
	ndef := uint32(r.NAlldef())
	for i, n := uint32(0), uint32(r.NNonpkgref()); i < n; i++ {
		osym := r.Sym(ndef + i)
		name := osym.Name(r.Reader)
		v := abiToVer(osym.ABI(), r.version)
		gi := l.LookupOrCreateSym(name, v)
		r.syms[ndef+i] = gi
		if osym.IsLinkname() {
			// Check if a linkname reference is allowed.
			// Only check references (pull), not definitions (push),
			// so push is always allowed.
			// Linkname is always a non-package reference.
			l.checkLinkname(r.unit.Lib.Pkg, name, gi)
		}
		if osym.Local() {
			l.SetAttrLocal(gi, true)
		}
		if osym.UsedInIface() {
			l.SetAttrUsedInIface(gi, true)
		}
	}

	// referenced packages
	npkg := r.NPkg()
	r.pkg = make([]uint32, npkg)
	for i := 1; i < npkg; i++ { // PkgIdx 0 is a dummy invalid package
		pkg := r.Pkg(i)
		objidx, ok := l.objByPkg[pkg]
		if !ok {
			log.Fatalf("%v: reference to nonexistent package %s", r.unit.Lib, pkg)
		}
		r.pkg[i] = objidx
	}

	// load flags of package refs
	for i, n := 0, r.NRefFlags(); i < n; i++ {
		rf := r.RefFlags(i)
		gi := l.resolve(r, rf.Sym())
		if rf.Flag2()&goobj.SymFlagUsedInIface != 0 {
			l.SetAttrUsedInIface(gi, true)
		}
	}
}

func abiToVer(abi uint16, localSymVersion int) int {
	var v int
	if abi == goobj.SymABIstatic {
		// Static
		v = localSymVersion
	} else if abiver := sym.ABIToVersion(obj.ABI(abi)); abiver != -1 {
		// Note that data symbols are "ABI0", which maps to version 0.
		v = abiver
	} else {
		log.Fatalf("invalid symbol ABI: %d", abi)
	}
	return v
}

// A list of blocked linknames. Some linknames are allowed only
// in specific packages. This maps symbol names to allowed packages.
// If a name is not in this map, it is allowed iff the definition
// has a linkname (push).
// If a name is in this map, it is allowed only in listed packages,
// even if it has a linknamed definition.
var blockedLinknames = map[string][]string{
	// coroutines
	"runtime.coroswitch": {"iter"},
	"runtime.newcoro":    {"iter"},
	// fips info
	"go:fipsinfo": {"crypto/internal/fips140/check"},
	// New internal linknames in Go 1.24
	// Pushed from runtime
	"crypto/internal/fips140.fatal":         {"crypto/internal/fips140"},
	"crypto/internal/fips140.getIndicator":  {"crypto/internal/fips140"},
	"crypto/internal/fips140.setIndicator":  {"crypto/internal/fips140"},
	"crypto/internal/sysrand.fatal":         {"crypto/internal/sysrand"},
	"crypto/rand.fatal":                     {"crypto/rand"},
	"internal/runtime/maps.errNilAssign":    {"internal/runtime/maps"},
	"internal/runtime/maps.fatal":           {"internal/runtime/maps"},
	"internal/runtime/maps.mapKeyError":     {"internal/runtime/maps"},
	"internal/runtime/maps.newarray":        {"internal/runtime/maps"},
	"internal/runtime/maps.newobject":       {"internal/runtime/maps"},
	"internal/runtime/maps.typedmemclr":     {"internal/runtime/maps"},
	"internal/runtime/maps.typedmemmove":    {"internal/runtime/maps"},
	"internal/sync.fatal":                   {"internal/sync"},
	"internal/sync.runtime_canSpin":         {"internal/sync"},
	"internal/sync.runtime_doSpin":          {"internal/sync"},
	"internal/sync.runtime_nanotime":        {"internal/sync"},
	"internal/sync.runtime_Semrelease":      {"internal/sync"},
	"internal/sync.runtime_SemacquireMutex": {"internal/sync"},
	"internal/sync.throw":                   {"internal/sync"},
	"internal/synctest.Run":                 {"internal/synctest"},
	"internal/synctest.Wait":                {"internal/synctest"},
	"internal/synctest.acquire":             {"internal/synctest"},
	"internal/synctest.release":             {"internal/synctest"},
	"internal/synctest.inBubble":            {"internal/synctest"},
	"runtime.getStaticuint64s":              {"reflect"},
	"sync.runtime_SemacquireWaitGroup":      {"sync"},
	"time.runtimeNow":                       {"time"},
	"time.runtimeNano":                      {"time"},
	// Pushed to runtime from internal/runtime/maps
	// (other map functions are already linknamed in Go 1.23)
	"runtime.mapaccess1":         {"runtime"},
	"runtime.mapaccess1_fast32":  {"runtime"},
	"runtime.mapaccess1_fast64":  {"runtime"},
	"runtime.mapaccess1_faststr": {"runtime"},
	"runtime.mapdelete_fast32":   {"runtime"},
	"runtime.mapdelete_fast64":   {"runtime"},
	"runtime.mapdelete_faststr":  {"runtime"},
}

// check if a linkname reference to symbol s from pkg is allowed
func (l *Loader) checkLinkname(pkg, name string, s Sym) {
	if l.flags&FlagCheckLinkname == 0 {
		return
	}

	error := func() {
		log.Fatalf("%s: invalid reference to %s", pkg, name)
	}
	pkgs, ok := blockedLinknames[name]
	if ok {
		for _, p := range pkgs {
			if pkg == p {
				return // pkg is allowed
			}
		}
		error()
	}
	r, li := l.toLocal(s)
	if r == l.extReader { // referencing external symbol is okay
		return
	}
	if !r.Std() { // For now, only check for symbols defined in std
		return
	}
	if r.unit.Lib.Pkg == pkg { // assembly reference from same package
		return
	}
	osym := r.Sym(li)
	if osym.IsLinkname() || osym.ABIWrapper() {
		// Allow if the def has a linkname (push).
		// ABI wrapper usually wraps an assembly symbol, a linknamed symbol,
		// or an external symbol, or provide access of a Go symbol to assembly.
		// For now, allow ABI wrappers.
		// TODO: check the wrapped symbol?
		return
	}
	error()
}

// TopLevelSym tests a symbol (by name and kind) to determine whether
// the symbol first class sym (participating in the link) or is an
// anonymous aux or sub-symbol containing some sub-part or payload of
// another symbol.
func (l *Loader) TopLevelSym(s Sym) bool {
	return topLevelSym(l.SymName(s), l.SymType(s))
}

// topLevelSym tests a symbol name and kind to determine whether
// the symbol first class sym (participating in the link) or is an
// anonymous aux or sub-symbol containing some sub-part or payload of
// another symbol.
func topLevelSym(sname string, skind sym.SymKind) bool {
	if sname != "" {
		return true
	}
	switch skind {
	case sym.SDWARFFCN, sym.SDWARFABSFCN, sym.SDWARFTYPE, sym.SDWARFCONST, sym.SDWARFCUINFO, sym.SDWARFRANGE, sym.SDWARFLOC, sym.SDWARFLINES, sym.SGOFUNC:
		return true
	default:
		return false
	}
}

// cloneToExternal takes the existing object file symbol (symIdx)
// and creates a new external symbol payload that is a clone with
// respect to name, version, type, relocations, etc. The idea here
// is that if the linker decides it wants to update the contents of
// a symbol originally discovered as part of an object file, it's
// easier to do this if we make the updates to an external symbol
// payload.
func (l *Loader) cloneToExternal(symIdx Sym) {
	if l.IsExternal(symIdx) {
		panic("sym is already external, no need for clone")
	}

	// Read the particulars from object.
	r, li := l.toLocal(symIdx)
	osym := r.Sym(li)
	sname := osym.Name(r.Reader)
	sver := abiToVer(osym.ABI(), r.version)
	skind := sym.AbiSymKindToSymKind[objabi.SymKind(osym.Type())]

	// Create new symbol, update version and kind.
	pi := l.newPayload(sname, sver)
	pp := l.payloads[pi]
	pp.kind = skind
	pp.ver = sver
	pp.size = int64(osym.Siz())
	pp.objidx = r.objidx

	// If this is a def, then copy the guts. We expect this case
	// to be very rare (one case it may come up is with -X).
	if li < uint32(r.NAlldef()) {

		// Copy relocations
		relocs := l.Relocs(symIdx)
		pp.relocs = make([]goobj.Reloc, relocs.Count())
		for i := range pp.relocs {
			// Copy the relocs slice.
			// Convert local reference to global reference.
			rel := relocs.At(i)
			pp.relocs[i].Set(rel.Off(), rel.Siz(), uint16(rel.Type()), rel.Add(), goobj.SymRef{PkgIdx: 0, SymIdx: uint32(rel.Sym())})
		}

		// Copy data
		pp.data = r.Data(li)
	}

	// If we're overriding a data symbol, collect the associated
	// Gotype, so as to propagate it to the new symbol.
	auxs := r.Auxs(li)
	pp.auxs = auxs

	// Install new payload to global index space.
	// (This needs to happen at the end, as the accessors above
	// need to access the old symbol content.)
	l.objSyms[symIdx] = objSym{l.extReader.objidx, uint32(pi)}
	l.extReader.syms = append(l.extReader.syms, symIdx)

	// Some attributes were encoded in the object file. Copy them over.
	l.SetAttrDuplicateOK(symIdx, r.Sym(li).Dupok())
	l.SetAttrShared(symIdx, r.Shared())
}

// Copy the payload of symbol src to dst. Both src and dst must be external
// symbols.
// The intended use case is that when building/linking against a shared library,
// where we do symbol name mangling, the Go object file may have reference to
// the original symbol name whereas the shared library provides a symbol with
// the mangled name. When we do mangling, we copy payload of mangled to original.
func (l *Loader) CopySym(src, dst Sym) {
	if !l.IsExternal(dst) {
		panic("dst is not external") //l.newExtSym(l.SymName(dst), l.SymVersion(dst))
	}
	if !l.IsExternal(src) {
		panic("src is not external") //l.cloneToExternal(src)
	}
	l.payloads[l.extIndex(dst)] = l.payloads[l.extIndex(src)]
	l.SetSymPkg(dst, l.SymPkg(src))
	// TODO: other attributes?
}

// CreateExtSym creates a new external symbol with the specified name
// without adding it to any lookup tables, returning a Sym index for it.
func (l *Loader) CreateExtSym(name string, ver int) Sym {
	return l.newExtSym(name, ver)
}

// CreateStaticSym creates a new static symbol with the specified name
// without adding it to any lookup tables, returning a Sym index for it.
func (l *Loader) CreateStaticSym(name string) Sym {
	// Assign a new unique negative version -- this is to mark the
	// symbol so that it is not included in the name lookup table.
	l.anonVersion--
	return l.newExtSym(name, l.anonVersion)
}

func (l *Loader) FreeSym(i Sym) {
	if l.IsExternal(i) {
		pp := l.getPayload(i)
		*pp = extSymPayload{}
	}
}

// relocId is essentially a <S,R> tuple identifying the Rth
// relocation of symbol S.
type relocId struct {
	sym  Sym
	ridx int
}

// SetRelocVariant sets the 'variant' property of a relocation on
// some specific symbol.
func (l *Loader) SetRelocVariant(s Sym, ri int, v sym.RelocVariant) {
	// sanity check
	if relocs := l.Relocs(s); ri >= relocs.Count() {
		panic("invalid relocation ID")
	}
	if l.relocVariant == nil {
		l.relocVariant = make(map[relocId]sym.RelocVariant)
	}
	if v != 0 {
		l.relocVariant[relocId{s, ri}] = v
	} else {
		delete(l.relocVariant, relocId{s, ri})
	}
}

// RelocVariant returns the 'variant' property of a relocation on
// some specific symbol.
func (l *Loader) RelocVariant(s Sym, ri int) sym.RelocVariant {
	return l.relocVariant[relocId{s, ri}]
}

// UndefinedRelocTargets iterates through the global symbol index
// space, looking for symbols with relocations targeting undefined
// references. The linker's loadlib method uses this to determine if
// there are unresolved references to functions in system libraries
// (for example, libgcc.a), presumably due to CGO code. Return value
// is a pair of lists of loader.Sym's. First list corresponds to the
// corresponding to the undefined symbols themselves, the second list
// is the symbol that is making a reference to the undef. The "limit"
// param controls the maximum number of results returned; if "limit"
// is -1, then all undefs are returned.
func (l *Loader) UndefinedRelocTargets(limit int) ([]Sym, []Sym) {
	result, fromr := []Sym{}, []Sym{}
outerloop:
	for si := Sym(1); si < Sym(len(l.objSyms)); si++ {
		relocs := l.Relocs(si)
		for ri := 0; ri < relocs.Count(); ri++ {
			r := relocs.At(ri)
			rs := r.Sym()
			if rs != 0 && l.SymType(rs) == sym.SXREF && l.SymName(rs) != ".got" {
				result = append(result, rs)
				fromr = append(fromr, si)
				if limit != -1 && len(result) >= limit {
					break outerloop
				}
			}
		}
	}
	return result, fromr
}

// AssignTextSymbolOrder populates the Textp slices within each
// library and compilation unit, insuring that packages are laid down
// in dependency order (internal first, then everything else). Return value
// is a slice of all text syms.
func (l *Loader) AssignTextSymbolOrder(libs []*sym.Library, intlibs []bool, extsyms []Sym) []Sym {

	// Library Textp lists should be empty at this point.
	for _, lib := range libs {
		if len(lib.Textp) != 0 {
			panic("expected empty Textp slice for library")
		}
		if len(lib.DupTextSyms) != 0 {
			panic("expected empty DupTextSyms slice for library")
		}
	}

	// Used to record which dupok symbol we've assigned to a unit.
	// Can't use the onlist attribute here because it will need to
	// clear for the later assignment of the sym.Symbol to a unit.
	// NB: we can convert to using onList once we no longer have to
	// call the regular addToTextp.
	assignedToUnit := MakeBitmap(l.NSym() + 1)

	// Start off textp with reachable external syms.
	textp := []Sym{}
	for _, sym := range extsyms {
		if !l.attrReachable.Has(sym) {
			continue
		}
		textp = append(textp, sym)
	}

	// Walk through all text symbols from Go object files and append
	// them to their corresponding library's textp list.
	for _, r := range l.objs[goObjStart:] {
		lib := r.unit.Lib
		for i, n := uint32(0), uint32(r.NAlldef()); i < n; i++ {
			gi := l.toGlobal(r, i)
			if !l.attrReachable.Has(gi) {
				continue
			}
			osym := r.Sym(i)
			st := sym.AbiSymKindToSymKind[objabi.SymKind(osym.Type())]
			if !st.IsText() {
				continue
			}
			dupok := osym.Dupok()
			if r2, i2 := l.toLocal(gi); r2 != r || i2 != i {
				// A dupok text symbol is resolved to another package.
				// We still need to record its presence in the current
				// package, as the trampoline pass expects packages
				// are laid out in dependency order.
				lib.DupTextSyms = append(lib.DupTextSyms, sym.LoaderSym(gi))
				continue // symbol in different object
			}
			if dupok {
				lib.DupTextSyms = append(lib.DupTextSyms, sym.LoaderSym(gi))
				continue
			}

			lib.Textp = append(lib.Textp, sym.LoaderSym(gi))
		}
	}

	// Now assemble global textp, and assign text symbols to units.
	for _, doInternal := range [2]bool{true, false} {
		for idx, lib := range libs {
			if intlibs[idx] != doInternal {
				continue
			}
			lists := [2][]sym.LoaderSym{lib.Textp, lib.DupTextSyms}
			for i, list := range lists {
				for _, s := range list {
					sym := Sym(s)
					if !assignedToUnit.Has(sym) {
						textp = append(textp, sym)
						unit := l.SymUnit(sym)
						if unit != nil {
							unit.Textp = append(unit.Textp, s)
							assignedToUnit.Set(sym)
						}
						// Dupok symbols may be defined in multiple packages; the
						// associated package for a dupok sym is chosen sort of
						// arbitrarily (the first containing package that the linker
						// loads). Canonicalizes its Pkg to the package with which
						// it will be laid down in text.
						if i == 1 /* DupTextSyms2 */ && l.SymPkg(sym) != lib.Pkg {
							l.SetSymPkg(sym, lib.Pkg)
						}
					}
				}
			}
			lib.Textp = nil
			lib.DupTextSyms = nil
		}
	}

	return textp
}

// ErrorReporter is a helper class for reporting errors.
type ErrorReporter struct {
	ldr              *Loader
	AfterErrorAction func()
}

// Errorf method logs an error message.
//
// After each error, the error actions function will be invoked; this
// will either terminate the link immediately (if -h option given)
// or it will keep a count and exit if more than 20 errors have been printed.
//
// Logging an error means that on exit cmd/link will delete any
// output file and return a non-zero error code.
func (reporter *ErrorReporter) Errorf(s Sym, format string, args ...interface{}) {
	if s != 0 && reporter.ldr.SymName(s) != "" {
		// Note: Replace is needed here because symbol names might have % in them,
		// due to the use of LinkString for names of instantiating types.
		format = strings.Replace(reporter.ldr.SymName(s), "%", "%%", -1) + ": " + format
	} else {
		format = fmt.Sprintf("sym %d: %s", s, format)
	}
	format += "\n"
	fmt.Fprintf(os.Stderr, format, args...)
	reporter.AfterErrorAction()
}

// GetErrorReporter returns the loader's associated error reporter.
func (l *Loader) GetErrorReporter() *ErrorReporter {
	return l.errorReporter
}

// Errorf method logs an error message. See ErrorReporter.Errorf for details.
func (l *Loader) Errorf(s Sym, format string, args ...interface{}) {
	l.errorReporter.Errorf(s, format, args...)
}

// Symbol statistics.
func (l *Loader) Stat() string {
	s := fmt.Sprintf("%d symbols, %d reachable\n", l.NSym(), l.NReachableSym())
	s += fmt.Sprintf("\t%d package symbols, %d hashed symbols, %d non-package symbols, %d external symbols\n",
		l.npkgsyms, l.nhashedsyms, int(l.extStart)-l.npkgsyms-l.nhashedsyms, l.NSym()-int(l.extStart))
	return s
}

// For debugging.
func (l *Loader) Dump() {
	fmt.Println("objs")
	for _, r := range l.objs[goObjStart:] {
		if r != nil {
			fmt.Println(r.unit.Lib)
		}
	}
	fmt.Println("extStart:", l.extStart)
	fmt.Println("Nsyms:", len(l.objSyms))
	fmt.Println("syms")
	for i := Sym(1); i < Sym(len(l.objSyms)); i++ {
		pi := ""
		if l.IsExternal(i) {
			pi = fmt.Sprintf("<ext %d>", l.extIndex(i))
		}
		sect := ""
		if l.SymSect(i) != nil {
			sect = l.SymSect(i).Name
		}
		fmt.Printf("%v %v %v %v %x %v\n", i, l.SymName(i), l.SymType(i), pi, l.SymValue(i), sect)
	}
	fmt.Println("symsByName")
	for name, i := range l.symsByName[0] {
		fmt.Println(i, name, 0)
	}
	for name, i := range l.symsByName[1] {
		fmt.Println(i, name, 1)
	}
	fmt.Println("payloads:")
	for i := range l.payloads {
		pp := l.payloads[i]
		fmt.Println(i, pp.name, pp.ver, pp.kind)
	}
}

"""




```