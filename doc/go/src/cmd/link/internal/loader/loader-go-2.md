Response:
My thinking process to answer the request about `loader.go` goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code snippet, which is part of the Go linker. It emphasizes identifying the Go features being implemented and providing examples.

2. **Initial Scan for Keywords and Structure:** I'll quickly scan the code for important keywords and overall structure:
    * **`Loader` struct:** This is the central data structure.
    * **`LoadSyms`:**  A key function for loading symbols.
    * **`preloadSyms`:**  Called within `LoadSyms`, suggesting a multi-pass loading process.
    * **`loadObjRefs`:** Deals with references between object files.
    * **`checkLinkname`:**  Manages `linkname` directives.
    * **`cloneToExternal`, `CopySym`, `CreateExtSym`, `CreateStaticSym`:** Functions for manipulating symbols.
    * **`SetRelocVariant`, `RelocVariant`, `UndefinedRelocTargets`:**  Relocation-related functions.
    * **`AssignTextSymbolOrder`:**  Arranges text symbols.
    * **`ErrorReporter`, `Errorf`:**  Error handling.
    * **`Stat`, `Dump`:** Debugging/information functions.

3. **Identify Core Functionality Areas:** Based on the keywords and structure, I can group the functionalities into these areas:
    * **Symbol Loading and Management:** This is the most prominent aspect. It involves reading symbol information from object files, creating internal representations, and handling different types of symbols (package, hashed, non-package, external).
    * **Linkname Processing:**  The `linkname` feature is explicitly handled.
    * **Relocation Handling:**  Functions for managing and querying relocation information.
    * **Text Symbol Ordering:**  Organizing code symbols for linking.
    * **Error Reporting:**  A mechanism for reporting linking errors.
    * **Debugging/Information:**  Utilities for inspecting the linker's state.

4. **Infer Go Features Being Implemented:**  Now I'll look for clues about the Go language features being supported:
    * **`// name reference is allowed.` and `st.linknameVarRefs` and `l.checkLinkname`:**  This clearly points to the `//go:linkname` directive, which allows linking to symbols with different names.
    * **`if strings.HasPrefix(name, "runtime.") || (loadingRuntimePkg && strings.HasPrefix(name, "type:"))` and `l.builtinSyms`:** This hints at the special handling of runtime and type information, which are fundamental to Go's execution model.
    * **`if osym.WasmExport()`:**  Indicates support for WebAssembly exports.
    * **`if abi == goobj.SymABIstatic`:** Relates to static linking and symbol ABI.
    * **Relocation functions:**  These are essential for linking, especially for handling external dependencies and resolving addresses.

5. **Construct Explanations and Examples:** For each major functionality area, I'll formulate an explanation in Chinese and provide Go code examples where applicable:
    * **Symbol Loading:** Explain how it reads symbols from object files and creates internal representations. No specific Go code example for this internal process.
    * **Linkname:** Explain the purpose of `//go:linkname` and provide an example demonstrating how it's used to link to a C function or rename an internal function. Include the blocked linkname concept.
    * **Relocations:** Explain the role of relocations in linking and how the code manages them. No specific Go code example, as this is internal to the linker.
    * **Text Symbol Ordering:** Explain the importance of ordering for initialization and dependency management. No specific Go code example.
    * **Error Reporting:** Describe the error handling mechanism. No specific Go code example.

6. **Address Specific Requirements:**
    * **Code Reasoning with Assumptions:** Where I provide examples (like `linkname`), I'll make explicit assumptions about the input (e.g., a C function `c_function` and a Go function `goWrapper`).
    * **Command-Line Arguments:**  The provided snippet doesn't show direct command-line argument processing. I'll mention this and if possible,  infer potential related flags like `-linknamed`. *Self-correction:* I see `l.flags&FlagCheckLinkname`, which suggests a `-linknamed` or similar flag might exist, although the exact parsing isn't in the snippet.
    * **Common Mistakes:** Focus on the potential misuse of `//go:linkname`, especially regarding the blocked linknames and the need for matching types.
    * **Functionality Summary:** Concisely summarize the main purpose of the code.

7. **Review and Refine:**  Finally, I'll review my answer for clarity, accuracy, and completeness. I'll ensure that the language is clear and easy to understand, and that all parts of the request have been addressed. I'll double-check that the Go code examples are correct and illustrate the concepts effectively.

By following these steps, I can systematically break down the provided code and generate a comprehensive and informative answer that addresses all aspects of the user's request. The key is to move from the general structure and keywords to infer specific functionality and then connect that back to relevant Go language features.
## 对 `go/src/cmd/link/internal/loader/loader.go` 第 3 部分功能的归纳

这是 `go/src/cmd/link/internal/loader/loader.go` 文件的最后一部分代码，它主要负责以下功能：

**1. 符号的克隆、复制和创建：**

* **`cloneToExternal(symIdx Sym)`:**  这个函数用于将一个已有的内部符号（来自对象文件）克隆到一个新的外部符号。这样做是为了方便在链接过程中修改符号的内容，特别是当链接器需要更新从对象文件中读取的符号时。克隆会复制符号的名称、版本、类型、重定位信息和数据。
* **`CopySym(src, dst Sym)`:** 用于将一个外部符号的内容复制到另一个外部符号。这通常用于共享库链接的场景，当符号名称被 mangled 时，可以将 mangled 符号的内容复制到原始名称的符号。
* **`CreateExtSym(name string, ver int) Sym`:** 创建一个新的外部符号，但不会将其添加到任何查找表中。
* **`CreateStaticSym(name string) Sym`:** 创建一个新的静态符号，同样不会添加到查找表，并分配一个唯一的负版本号以标记它。
* **`FreeSym(i Sym)`:** 释放一个外部符号的payload，用于内存管理。

**2. 重定位信息的管理：**

* **`SetRelocVariant(s Sym, ri int, v sym.RelocVariant)`:** 设置指定符号的某个重定位项的变体属性。重定位变体指示了重定位的具体类型或特性。
* **`RelocVariant(s Sym, ri int) sym.RelocVariant`:** 获取指定符号的某个重定位项的变体属性。
* **`UndefinedRelocTargets(limit int) ([]Sym, []Sym)`:**  遍历所有符号，查找具有指向未定义符号的重定位项的符号。这用于检测是否存在对系统库中未定义函数的引用（通常是由于 CGO 代码）。

**3. 文本符号的排序和分配：**

* **`AssignTextSymbolOrder(libs []*sym.Library, intlibs []bool, extsyms []Sym) []Sym`:**  这个函数非常重要，它负责将代码符号（文本符号）按照依赖顺序分配到不同的库和编译单元中。它确保内部包的代码先被放置，然后再放置其他代码。返回所有文本符号的切片。

**4. 错误报告：**

* **`ErrorReporter` 结构体和相关方法 `Errorf`:** 提供了一个统一的错误报告机制。当链接过程中发生错误时，可以使用 `Errorf` 方法记录错误信息。根据链接器的配置，错误发生后可能会立即终止链接，或者在达到一定数量的错误后终止。
* **`GetErrorReporter() *ErrorReporter`:** 获取链接器的错误报告器实例。

**5. 统计和调试信息：**

* **`Stat() string`:** 返回链接器中符号的统计信息，例如符号总数、可达符号数、不同类型的符号数量等。
* **`Dump()`:**  用于调试，打印链接器的内部状态，包括对象文件信息、符号信息、payload 信息等。

**功能归纳：**

总的来说，`loader.go` 的这部分代码主要负责在链接过程的后期阶段对符号进行更精细的管理和处理。它提供了以下关键能力：

* **符号的生命周期管理：** 创建、克隆、复制和释放符号，特别是外部符号，以便于在链接过程中修改和管理符号。
* **重定位信息的精细控制：**  允许设置和查询重定位的变体信息，以及检测未定义的重定位目标。
* **代码符号的有序布局：** 确保代码符号按照正确的依赖顺序排列，这对于程序的正确初始化和执行至关重要。
* **统一的错误报告机制：**  提供了一种标准化的方式来报告链接过程中出现的错误。
* **调试和统计工具：**  提供了一些方法来查看链接器的内部状态和统计信息，方便开发者进行调试和分析。

**可以推断出的 Go 语言功能的实现：**

* **`//go:linkname` 指令的实现:**  `checkLinkname` 函数和 `blockedLinknames` 变量是实现 `//go:linkname` 指令的关键部分。这个指令允许将一个 Go 符号链接到另一个不同名称的符号，通常用于链接到 C 代码或者重命名内部函数。

**Go 代码示例 (关于 `//go:linkname`)：**

假设我们有一个 C 函数：

```c
// my_c_code.c
#include <stdio.h>

void c_function() {
    printf("Hello from C!\n");
}
```

我们想要在 Go 代码中调用这个 C 函数，并使用不同的 Go 函数名：

```go
package main

// #cgo LDFLAGS: -lmylib  // 假设你的 C 代码被编译成了 libmylib.so 或 libmylib.a
import "C"
import "fmt"

//go:linkname goWrapper c_function

func goWrapper() // 注意这里没有函数体
```

在链接过程中，`loader.go` 中的 `checkLinkname` 函数会检查这个 `//go:linkname` 指令是否合法（例如，是否在允许的包中使用）。

**假设的输入与输出 (关于 `cloneToExternal`)：**

**输入：**

* `l`: `Loader` 实例，包含已加载的对象文件和符号信息。
* `symIdx`: 一个内部符号的索引，例如，一个定义在某个 Go 源文件中的函数 `myGoFunc` 的符号索引。

**处理过程：**

`cloneToExternal` 函数会执行以下操作：

1. 从内部符号 `symIdx` 对应的对象文件中读取符号的名称、版本、类型、大小、重定位信息和数据。
2. 创建一个新的外部符号 payload，并复制上述信息。
3. 将内部符号 `symIdx` 的信息更新为指向新创建的外部符号 payload。

**输出：**

*  内部符号 `symIdx` 现在指向一个与原始符号具有相同内容的新创建的外部符号。链接器可以安全地修改这个外部符号的内容，而不会影响原始对象文件中的符号。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。命令行参数的处理通常发生在 `cmd/link/internal/main.go` 等更上层的代码中。但是，我们可以推断出一些可能相关的命令行参数，例如：

* **`-linknamed` 或类似的参数:**  可能用于启用或禁用 `//go:linkname` 指令的检查。`l.flags&FlagCheckLinkname` 表明存在这样的标志。
* **`-X importpath.name=value`:** 用于在链接时修改包中变量的值。`cloneToExternal` 函数中提到，如果符号是定义，则会复制内容，这可能与 `-X` 选项有关。

**使用者易犯错的点 (关于 `//go:linkname`)：**

* **在不允许的包中使用 `//go:linkname`:** `blockedLinknames` 变量定义了一些只允许在特定包中使用的 `linkname`。如果在其他包中使用这些 `linkname`，链接器会报错。例如，尝试在非 `iter` 包中 `linkname` `runtime.coroswitch` 会导致错误。
* **`//go:linkname` 的目标符号不存在或类型不匹配:** 如果 `//go:linkname` 指向的符号在链接时找不到，或者类型与 Go 函数不匹配，链接器会报错。

**总结：**

这是 `go/src/cmd/link/internal/loader/loader.go` 文件的最后一部分，它专注于符号的精细管理，包括克隆、复制、创建、重定位管理、文本符号排序、错误报告以及提供调试信息。 这部分代码对于链接器的核心功能至关重要，特别是对于处理复杂的链接场景，例如涉及 C 代码互操作或需要精确控制代码布局的情况。它也是 Go 语言中 `//go:linkname` 指令实现的关键组成部分。

Prompt: 
```
这是路径为go/src/cmd/link/internal/loader/loader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能

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