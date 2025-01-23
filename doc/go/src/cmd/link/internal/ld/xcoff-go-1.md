Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the `xcoff.go` file in the Go linker. This code appears to be responsible for generating XCOFF (Extended Common Object File Format) files, a format used by AIX.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name `xcoff.go` and the presence of functions like `doxcoff`, `asmbXcoff`, `xcoffwrite`, and structures like `xcoffFile`, `XcoffLdHdr64`, etc., strongly suggest that this code is involved in generating XCOFF files.

2. **Analyze Key Functions:**
    * `asmaixsym`:  Likely responsible for assembling AIX-specific symbols.
    * `genDynSym`:  Focuses on generating dynamic symbols.
    * `adddynimpsym`: Adds dynamic import symbols.
    * `Xcoffadddynrel`: Adds dynamic relocations.
    * `doxcoff`:  A high-level function likely orchestrating the XCOFF process.
    * `Loaderblk` and `writeLdrScn`: Deal with the `.loader` section, crucial for dynamic linking.
    * `writeFileHeader`: Writes the XCOFF file header.
    * `xcoffwrite`:  Likely writes the entire XCOFF file.
    * `asmbXcoff`:  Another high-level function, probably for assembling the XCOFF structure.
    * `emitRelocations`: Handles relocation entries.
    * `xcoffCreateExportFile`: Creates an export file, relevant for external linking on AIX.

3. **Group Functionalities:** Based on the function names and their interactions, group them into logical units:
    * **Symbol Handling:** `asmaixsym`, `genDynSym`, `adddynimpsym`.
    * **Relocation Handling:** `Xcoffadddynrel`, `emitRelocations`.
    * **Loader Section Management:** `Loaderblk`, `writeLdrScn`.
    * **File Structure and Writing:** `writeFileHeader`, `xcoffwrite`, `asmbXcoff`.
    * **External Linking Support:** `xcoffCreateExportFile`.

4. **Infer Go Feature Implementation:**  The code heavily interacts with the `ctxt` (link context) and `ldr` (loader). It deals with symbols, sections, and relocations. This strongly indicates that it's part of the **Go linker** and is responsible for generating executable or object files in the XCOFF format.

5. **Infer Usage Scenarios and Potential Errors:**
    * The presence of `ctxt.IsExternal()` and checks related to `cgo_export` suggest that this code handles both internal and external linking scenarios, particularly with C code integration using cgo.
    * Errors like "imported symbol must have a given library" highlight a potential pitfall for users of dynamic linking.
    * The comments about symbol types and relocation types suggest that incorrect symbol/relocation configurations could lead to errors.

6. **Construct the Summary:** Combine the identified functionalities and the inferred Go feature implementation into a concise summary, using clear and understandable language.

7. **Review and Refine:** Ensure the summary accurately reflects the code's purpose and scope. For example, initially, I might just say "generates XCOFF files," but then I'd refine it to be more specific, mentioning aspects like symbol and relocation handling, and the loader section.
这段代码是 Go 语言链接器 `cmd/link` 的一部分，专门用于处理生成 AIX 操作系统上使用的 **XCOFF** (Extended Common Object File Format) 格式的目标文件。这是该功能的第二部分，主要负责完成 XCOFF 文件的组装和写入，特别是处理符号表、重定位信息以及 `.loader` 段。

**归纳一下它的功能:**

这段代码主要负责以下几个关键步骤，以完成 XCOFF 文件的最终生成：

1. **处理符号表 (Symbol Table):**
   - `asmaixsym` 函数遍历链接器中的符号，并根据其类型、属性等信息，将其添加到 XCOFF 的符号表中。
   - 它会特殊处理 `runtime.text.n` 和 `runtime.etext` 等运行时相关的文本符号。
   - 它会根据符号的类型（例如 `STLSBSS`, `SBSS`, `SDYNIMPORT` 等）决定是否将其放入符号表，并赋予相应的 XCOFF 符号类型。
   - 它还会处理 CGO 导出的符号，在外部链接模式下，会为导出的函数创建两个符号：一个以 `.` 开头的 `.text` 符号和一个用于函数描述符的 `.data` 符号。

2. **生成动态符号表 (Dynamic Symbol Table):**
   - `genDynSym` 函数用于生成动态符号表，其中包含了需要在运行时动态链接的符号，例如由 `cgo_import_dynamic` 导入的符号。
   - 它会收集类型为 `SHOSTOBJ` 或 `SDYNIMPORT` 且可达的符号。

3. **添加动态导入符号 (Dynamic Import Symbols):**
   - `adddynimpsym` 函数将一个动态符号添加到 XCOFF 文件中。
   - 它会创建一个新的动态符号，并将其添加到 `.loader` 段和符号表中。
   - 原始的符号会被转换为 `SXCOFFTOC` 类型并放入 `.data` 段。
   - 它会为动态导入的符号添加重定位信息。

4. **添加动态重定位 (Dynamic Relocation):**
   - `Xcoffadddynrel` 函数用于在 XCOFF 文件中添加动态重定位信息，这些重定位由加载器在运行时完成。
   - 它会根据重定位的类型和目标符号的段，确定相应的重定位类型和符号索引。

5. **生成和写入 `.loader` 段 (Loader Section):**
   - `Loaderblk` 和 `writeLdrScn` 函数负责创建和写入 `.loader` 段。这个段包含了动态链接器所需的信息，如符号表、字符串表、导入文件表和重定位表。
   - `writeLdrScn` 会按照 XCOFF 的格式写入 Loader Header、符号表、重定位表和导入文件表。

6. **写入文件头 (File Header):**
   - `writeFileHeader` 函数负责写入 XCOFF 文件的头部信息，包括魔数、段的数量、符号表偏移量等。
   - 对于可执行文件，还会写入辅助头部 (Auxiliary Header)，包含入口地址、TOC 地址等信息。

7. **写入段 (Section):**
   - `xcoffwrite` 函数负责将各个段的内容写入到输出文件中。

8. **组装 XCOFF 文件 (Assemble XCOFF):**
   - `asmbXcoff` 函数是组装 XCOFF 文件的核心函数。
   - 它会添加 `.text`, `.data`, `.bss` 等标准段，以及 DWARF 调试信息段。
   - 如果是内部链接模式，还会添加 `.loader` 段。
   - 它会调用 `asmaixsym` 创建符号表。
   - 如果是外部链接模式，还会调用 `emitRelocations` 生成重定位信息。
   - 最后，它会写入符号表、字符串表和文件头。

9. **生成重定位信息 (Emit Relocations):**
   - `emitRelocations` 函数用于在外部链接模式下生成 `go.o` 文件的重定位条目。
   - 它会遍历各个段中的符号，并为每个符号的重定位信息调用架构特定的 `Xcoffreloc1` 函数进行处理和写入。

10. **创建导出文件 (Create Export File):**
    - `xcoffCreateExportFile` 函数用于创建导出符号的文件，这个文件在外部链接时配合 `-Wl,-bE` 选项使用，用于指定需要导出的符号。

**总结来说，这段代码是 Go 语言链接器中生成 AIX 平台 XCOFF 格式目标文件的关键部分，它负责组织程序的代码、数据、符号以及动态链接信息，最终生成可执行文件或共享库。**

由于这是第二部分，它假定第一部分已经完成了 XCOFF 文件结构的基本设置，例如定义了各个段和一些基本符号。

**可以推断出这是 Go 语言链接器实现 XCOFF 文件生成的功能。**

**代码示例：**

由于这段代码是链接器内部的实现，直接用 Go 代码示例来演示其功能比较困难。它的主要作用是将 Go 编译器输出的中间表示（可能是 object 文件）转换为 XCOFF 格式。

但我们可以想象一下，在链接过程中，链接器会处理类似以下的 Go 代码产生的符号：

```go
package main

import "fmt"

var globalVar int = 10

func main() {
	fmt.Println("Hello, world!")
}

//go:cgo_export_function add
func add(a, b int) int {
	return a + b
}
```

对于上面的代码，`asmaixsym` 函数可能会处理以下符号：

- `main.globalVar` (类型可能是 `sym.SBSS` 或 `sym.SNOPTRBSS`)
- `main.main` (类型是 `sym.STEXT`)
- `fmt.Println` (类型可能是 `sym.SDYNIMPORT`，如果 `fmt` 包是动态链接的)
- `main.add` (类型是 `sym.STEXT`)
- `._cgoexp_0_add` (由 `//go:cgo_export_function` 生成，类型是 `sym.STEXT`)
- `add` (为 C 代码导出的符号生成的描述符，类型可能是 `sym.SNOPTRDATA`)

`genDynSym` 可能会处理 `fmt.Println` 这样的动态导入符号。

`adddynimpsym` 会为 `fmt.Println` 这样的符号创建动态符号表项。

`emitRelocations` 会为 `main.globalVar` 的初始化或者 `fmt.Println` 的调用生成重定位信息。

**假设的输入与输出：**

**输入（链接器的中间表示，简化）：**

```
SYMBOL main.globalVar (SBSS, size=8)
SYMBOL main.main (STEXT, address=0x1000)
  RELOCATE call fmt.Println (R_CALL, offset=10)
SYMBOL fmt.Println (SDYNIMPORT, library="libSystem.dylib")
SYMBOL main.add (STEXT, address=0x1020)
```

**输出（`asmaixsym` 函数的部分行为）：**

`asmaixsym` 函数会将上述符号转换为 XCOFF 符号表项，例如：

- `main.globalVar`:  XCOFF 符号类型可能对应于 BSS 段的符号。
- `main.main`: XCOFF 符号类型对应于代码段的符号，其值为 `0x1000`。
- `fmt.Println`: XCOFF 符号类型可能对应于一个外部导入的符号，会记录其动态库信息。
- `main.add`: XCOFF 符号类型对应于代码段的符号，其值为 `0x1020`。

`emitRelocations` 函数会处理 `RELOCATE call fmt.Println`，生成 XCOFF 的重定位条目，指示在 `main.main` 函数的偏移 `10` 处需要进行重定位，以指向 `fmt.Println` 的地址。

**命令行参数的具体处理：**

这段代码本身没有直接处理命令行参数，命令行参数的处理通常在 `cmd/link/internal/ld/main.go` 等文件中进行。但是，这段代码会使用链接器上下文中解析的参数，例如：

- `*flagEntrySymbol`:  入口符号的名称，用于设置 XCOFF 辅助头部的入口地址。
- `*FlagS`: 是否去除符号表和调试信息。
- `*flagTmpdir`: 临时目录，用于创建导出文件。
- `*FlagRound`: 段对齐大小。

**使用者易犯错的点：**

这段代码是链接器的内部实现，普通 Go 开发者不会直接与之交互。但是，如果涉及到使用 CGO 进行跨平台编译到 AIX 平台，可能会遇到一些与 XCOFF 格式相关的错误，例如：

- **动态链接库依赖问题：** 如果 CGO 代码依赖的动态链接库在目标系统上找不到，链接过程或运行时会出错。这段代码中的 `adddynimpsym` 函数就处理了动态导入的符号，如果库名不正确或者库不存在，就会出错。
- **CGO 导出符号的问题：** 使用 `//go:cgo_export_function` 导出 Go 函数给 C 代码调用时，需要确保导出的符号名称符合 XCOFF 的规范。这段代码中对 CGO 导出符号的处理逻辑就体现了这一点。
- **重定位错误：** 如果链接器无法正确生成重定位信息，或者目标系统加载器无法正确处理这些重定位信息，程序运行时会出错。

总而言之，这段代码是 Go 语言链接器为了支持 AIX 平台而实现的底层细节，它确保了 Go 程序能够被正确地链接成 XCOFF 格式的可执行文件或共享库。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/xcoff.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
in the symtab.
			break
		}
		s = ldr.Lookup(fmt.Sprintf("runtime.text.%d", n), 0)
		if s == 0 {
			break
		}
		if ldr.SymType(s).IsText() {
			putaixsym(ctxt, s, TextSym)
		}
		n++
	}

	s = ldr.Lookup("runtime.etext", 0)
	if ldr.SymType(s).IsText() {
		// We've already included this symbol in ctxt.Textp
		// on AIX with external linker.
		// See data.go:/textaddress
		if !ctxt.IsExternal() {
			putaixsym(ctxt, s, TextSym)
		}
	}

	shouldBeInSymbolTable := func(s loader.Sym, name string) bool {
		if ldr.AttrNotInSymbolTable(s) {
			return false
		}
		if (name == "" || name[0] == '.') && !ldr.IsFileLocal(s) && name != ".TOC." {
			return false
		}
		return true
	}

	for s, nsym := loader.Sym(1), loader.Sym(ldr.NSym()); s < nsym; s++ {
		if !shouldBeInSymbolTable(s, ldr.SymName(s)) {
			continue
		}
		st := ldr.SymType(s)
		switch {
		case st == sym.STLSBSS:
			if ctxt.IsExternal() {
				putaixsym(ctxt, s, TLSSym)
			}

		case st == sym.SBSS, st == sym.SNOPTRBSS, st == sym.SLIBFUZZER_8BIT_COUNTER, st == sym.SCOVERAGE_COUNTER:
			if ldr.AttrReachable(s) {
				data := ldr.Data(s)
				if len(data) > 0 {
					ldr.Errorf(s, "should not be bss (size=%d type=%v special=%v)", len(data), ldr.SymType(s), ldr.AttrSpecial(s))
				}
				putaixsym(ctxt, s, BSSSym)
			}

		case st >= sym.SELFRXSECT && st < sym.SXREF: // data sections handled in dodata
			if ldr.AttrReachable(s) {
				putaixsym(ctxt, s, DataSym)
			}

		case st == sym.SUNDEFEXT:
			putaixsym(ctxt, s, UndefinedSym)

		case st == sym.SDYNIMPORT:
			if ldr.AttrReachable(s) {
				putaixsym(ctxt, s, UndefinedSym)
			}
		}
	}

	for _, s := range ctxt.Textp {
		putaixsym(ctxt, s, TextSym)
	}

	if ctxt.Debugvlog != 0 {
		ctxt.Logf("symsize = %d\n", uint32(symSize))
	}
	xfile.updatePreviousFile(ctxt, true)
}

func (f *xcoffFile) genDynSym(ctxt *Link) {
	ldr := ctxt.loader
	var dynsyms []loader.Sym
	for s := loader.Sym(1); s < loader.Sym(ldr.NSym()); s++ {
		if !ldr.AttrReachable(s) {
			continue
		}
		if t := ldr.SymType(s); t != sym.SHOSTOBJ && t != sym.SDYNIMPORT {
			continue
		}
		dynsyms = append(dynsyms, s)
	}

	for _, s := range dynsyms {
		f.adddynimpsym(ctxt, s)

		if _, ok := f.dynLibraries[ldr.SymDynimplib(s)]; !ok {
			f.dynLibraries[ldr.SymDynimplib(s)] = len(f.dynLibraries)
		}
	}
}

// (*xcoffFile)adddynimpsym adds the dynamic symbol "s" to a XCOFF file.
// A new symbol named s.Extname() is created to be the actual dynamic symbol
// in the .loader section and in the symbol table as an External Reference.
// The symbol "s" is transformed to SXCOFFTOC to end up in .data section.
// However, there is no writing protection on those symbols and
// it might need to be added.
// TODO(aix): Handles dynamic symbols without library.
func (f *xcoffFile) adddynimpsym(ctxt *Link, s loader.Sym) {
	// Check that library name is given.
	// Pattern is already checked when compiling.
	ldr := ctxt.loader
	if ctxt.IsInternal() && ldr.SymDynimplib(s) == "" {
		ctxt.Errorf(s, "imported symbol must have a given library")
	}

	sb := ldr.MakeSymbolUpdater(s)
	sb.SetReachable(true)
	sb.SetType(sym.SXCOFFTOC)

	// Create new dynamic symbol
	extsym := ldr.CreateSymForUpdate(ldr.SymExtname(s), 0)
	extsym.SetType(sym.SDYNIMPORT)
	extsym.SetDynimplib(ldr.SymDynimplib(s))
	extsym.SetExtname(ldr.SymExtname(s))
	extsym.SetDynimpvers(ldr.SymDynimpvers(s))

	// Add loader symbol
	lds := &xcoffLoaderSymbol{
		sym:    extsym.Sym(),
		smtype: XTY_IMP,
		smclas: XMC_DS,
	}
	if ldr.SymName(s) == "__n_pthreads" {
		// Currently, all imported symbols made by cgo_import_dynamic are
		// syscall functions, except __n_pthreads which is a variable.
		// TODO(aix): Find a way to detect variables imported by cgo.
		lds.smclas = XMC_RW
	}
	f.loaderSymbols = append(f.loaderSymbols, lds)

	// Relocation to retrieve the external address
	sb.AddBytes(make([]byte, 8))
	r, _ := sb.AddRel(objabi.R_ADDR)
	r.SetSym(extsym.Sym())
	r.SetSiz(uint8(ctxt.Arch.PtrSize))
	// TODO: maybe this could be
	// sb.SetSize(0)
	// sb.SetData(nil)
	// sb.AddAddr(ctxt.Arch, extsym.Sym())
	// If the size is not 0 to begin with, I don't think the added 8 bytes
	// of zeros are necessary.
}

// Xcoffadddynrel adds a dynamic relocation in a XCOFF file.
// This relocation will be made by the loader.
func Xcoffadddynrel(target *Target, ldr *loader.Loader, syms *ArchSyms, s loader.Sym, r loader.Reloc, rIdx int) bool {
	if target.IsExternal() {
		return true
	}
	if ldr.SymType(s) <= sym.SPCLNTAB {
		ldr.Errorf(s, "cannot have a relocation to %s in a text section symbol", ldr.SymName(r.Sym()))
		return false
	}

	xldr := &xcoffLoaderReloc{
		sym:  s,
		roff: r.Off(),
	}
	targ := r.Sym()
	var targType sym.SymKind
	if targ != 0 {
		targType = ldr.SymType(targ)
	}

	switch r.Type() {
	default:
		ldr.Errorf(s, "unexpected .loader relocation to symbol: %s (type: %s)", ldr.SymName(targ), r.Type().String())
		return false
	case objabi.R_ADDR:
		if ldr.SymType(s) == sym.SXCOFFTOC && targType == sym.SDYNIMPORT {
			// Imported symbol relocation
			for i, dynsym := range xfile.loaderSymbols {
				if ldr.SymName(dynsym.sym) == ldr.SymName(targ) {
					xldr.symndx = int32(i + 3) // +3 because of 3 section symbols
					break
				}
			}
		} else if t := ldr.SymType(s); t.IsDATA() || t.IsNOPTRDATA() || t == sym.SBUILDINFO || t == sym.SXCOFFTOC {
			switch ldr.SymSect(targ).Seg {
			default:
				ldr.Errorf(s, "unknown segment for .loader relocation with symbol %s", ldr.SymName(targ))
			case &Segtext:
			case &Segrodata:
				xldr.symndx = 0 // .text
			case &Segdata:
				if targType == sym.SBSS || targType == sym.SNOPTRBSS {
					xldr.symndx = 2 // .bss
				} else {
					xldr.symndx = 1 // .data
				}
			}

		} else {
			ldr.Errorf(s, "unexpected type for .loader relocation R_ADDR for symbol %s: %s to %s", ldr.SymName(targ), ldr.SymType(s), ldr.SymType(targ))
			return false
		}

		xldr.rtype = 0x3F<<8 + XCOFF_R_POS
	}

	xfile.Lock()
	xfile.loaderReloc = append(xfile.loaderReloc, xldr)
	xfile.Unlock()
	return true
}

func (ctxt *Link) doxcoff() {
	ldr := ctxt.loader

	// TOC
	toc := ldr.CreateSymForUpdate("TOC", 0)
	toc.SetType(sym.SXCOFFTOC)
	toc.SetVisibilityHidden(true)

	// Add entry point to .loader symbols.
	ep := ldr.Lookup(*flagEntrySymbol, 0)
	if ep == 0 || !ldr.AttrReachable(ep) {
		Exitf("wrong entry point")
	}

	xfile.loaderSymbols = append(xfile.loaderSymbols, &xcoffLoaderSymbol{
		sym:    ep,
		smtype: XTY_ENT | XTY_SD,
		smclas: XMC_DS,
	})

	xfile.genDynSym(ctxt)

	for s := loader.Sym(1); s < loader.Sym(ldr.NSym()); s++ {
		if strings.HasPrefix(ldr.SymName(s), "TOC.") {
			sb := ldr.MakeSymbolUpdater(s)
			sb.SetType(sym.SXCOFFTOC)
		}
	}

	if ctxt.IsExternal() {
		// Change rt0_go name to match name in runtime/cgo:main().
		rt0 := ldr.Lookup("runtime.rt0_go", 0)
		ldr.SetSymExtname(rt0, "runtime_rt0_go")

		nsym := loader.Sym(ldr.NSym())
		for s := loader.Sym(1); s < nsym; s++ {
			if !ldr.AttrCgoExport(s) {
				continue
			}
			if ldr.IsFileLocal(s) {
				panic("cgo_export on static symbol")
			}

			if ldr.SymType(s).IsText() {
				// On AIX, an exported function must have two symbols:
				// - a .text symbol which must start with a ".".
				// - a .data symbol which is a function descriptor.
				name := ldr.SymExtname(s)
				ldr.SetSymExtname(s, "."+name)

				desc := ldr.MakeSymbolUpdater(ldr.CreateExtSym(name, 0))
				desc.SetReachable(true)
				desc.SetType(sym.SNOPTRDATA)
				desc.AddAddr(ctxt.Arch, s)
				desc.AddAddr(ctxt.Arch, toc.Sym())
				desc.AddUint64(ctxt.Arch, 0)
			}
		}
	}
}

// Loader section
// Currently, this section is created from scratch when assembling the XCOFF file
// according to information retrieved in xfile object.

// Create loader section and returns its size.
func Loaderblk(ctxt *Link, off uint64) {
	xfile.writeLdrScn(ctxt, off)
}

func (f *xcoffFile) writeLdrScn(ctxt *Link, globalOff uint64) {
	var symtab []*XcoffLdSym64
	var strtab []*XcoffLdStr64
	var importtab []*XcoffLdImportFile64
	var reloctab []*XcoffLdRel64
	var dynimpreloc []*XcoffLdRel64

	// As the string table is updated in any loader subsection,
	//  its length must be computed at the same time.
	stlen := uint32(0)

	// Loader Header
	hdr := &XcoffLdHdr64{
		Lversion: 2,
		Lsymoff:  LDHDRSZ_64,
	}

	ldr := ctxt.loader
	/* Symbol table */
	for _, s := range f.loaderSymbols {
		lds := &XcoffLdSym64{
			Loffset: uint32(stlen + 2),
			Lsmtype: s.smtype,
			Lsmclas: s.smclas,
		}
		sym := s.sym
		switch s.smtype {
		default:
			ldr.Errorf(sym, "unexpected loader symbol type: 0x%x", s.smtype)
		case XTY_ENT | XTY_SD:
			lds.Lvalue = uint64(ldr.SymValue(sym))
			lds.Lscnum = f.getXCOFFscnum(ldr.SymSect(sym))
		case XTY_IMP:
			lds.Lifile = int32(f.dynLibraries[ldr.SymDynimplib(sym)] + 1)
		}
		ldstr := &XcoffLdStr64{
			size: uint16(len(ldr.SymName(sym)) + 1), // + null terminator
			name: ldr.SymName(sym),
		}
		stlen += uint32(2 + ldstr.size) // 2 = sizeof ldstr.size
		symtab = append(symtab, lds)
		strtab = append(strtab, ldstr)

	}

	hdr.Lnsyms = int32(len(symtab))
	hdr.Lrldoff = hdr.Lsymoff + uint64(24*hdr.Lnsyms) // 24 = sizeof one symbol
	off := hdr.Lrldoff                                // current offset is the same of reloc offset

	/* Reloc */
	// Ensure deterministic order
	sort.Slice(f.loaderReloc, func(i, j int) bool {
		r1, r2 := f.loaderReloc[i], f.loaderReloc[j]
		if r1.sym != r2.sym {
			return r1.sym < r2.sym
		}
		if r1.roff != r2.roff {
			return r1.roff < r2.roff
		}
		if r1.rtype != r2.rtype {
			return r1.rtype < r2.rtype
		}
		return r1.symndx < r2.symndx
	})

	ep := ldr.Lookup(*flagEntrySymbol, 0)
	xldr := &XcoffLdRel64{
		Lvaddr:  uint64(ldr.SymValue(ep)),
		Lrtype:  0x3F00,
		Lrsecnm: f.getXCOFFscnum(ldr.SymSect(ep)),
		Lsymndx: 0,
	}
	off += 16
	reloctab = append(reloctab, xldr)

	off += uint64(16 * len(f.loaderReloc))
	for _, r := range f.loaderReloc {
		symp := r.sym
		if symp == 0 {
			panic("unexpected 0 sym value")
		}
		xldr = &XcoffLdRel64{
			Lvaddr:  uint64(ldr.SymValue(symp) + int64(r.roff)),
			Lrtype:  r.rtype,
			Lsymndx: r.symndx,
		}

		if ldr.SymSect(symp) != nil {
			xldr.Lrsecnm = f.getXCOFFscnum(ldr.SymSect(symp))
		}

		reloctab = append(reloctab, xldr)
	}

	off += uint64(16 * len(dynimpreloc))
	reloctab = append(reloctab, dynimpreloc...)

	hdr.Lnreloc = int32(len(reloctab))
	hdr.Limpoff = off

	/* Import */
	// Default import: /usr/lib:/lib
	ldimpf := &XcoffLdImportFile64{
		Limpidpath: "/usr/lib:/lib",
	}
	off += uint64(len(ldimpf.Limpidpath) + len(ldimpf.Limpidbase) + len(ldimpf.Limpidmem) + 3) // + null delimiter
	importtab = append(importtab, ldimpf)

	// The map created by adddynimpsym associates the name to a number
	// This number represents the librairie index (- 1) in this import files section
	// Therefore, they must be sorted before being put inside the section
	libsOrdered := make([]string, len(f.dynLibraries))
	for key, val := range f.dynLibraries {
		if libsOrdered[val] != "" {
			continue
		}
		libsOrdered[val] = key
	}

	for _, lib := range libsOrdered {
		// lib string is defined as base.a/mem.o or path/base.a/mem.o
		n := strings.Split(lib, "/")
		path := ""
		base := n[len(n)-2]
		mem := n[len(n)-1]
		if len(n) > 2 {
			path = lib[:len(lib)-len(base)-len(mem)-2]

		}
		ldimpf = &XcoffLdImportFile64{
			Limpidpath: path,
			Limpidbase: base,
			Limpidmem:  mem,
		}
		off += uint64(len(ldimpf.Limpidpath) + len(ldimpf.Limpidbase) + len(ldimpf.Limpidmem) + 3) // + null delimiter
		importtab = append(importtab, ldimpf)
	}

	hdr.Lnimpid = int32(len(importtab))
	hdr.Listlen = uint32(off - hdr.Limpoff)
	hdr.Lstoff = off
	hdr.Lstlen = stlen

	/* Writing */
	ctxt.Out.SeekSet(int64(globalOff))
	binary.Write(ctxt.Out, ctxt.Arch.ByteOrder, hdr)

	for _, s := range symtab {
		binary.Write(ctxt.Out, ctxt.Arch.ByteOrder, s)

	}
	for _, r := range reloctab {
		binary.Write(ctxt.Out, ctxt.Arch.ByteOrder, r)
	}
	for _, f := range importtab {
		ctxt.Out.WriteString(f.Limpidpath)
		ctxt.Out.Write8(0)
		ctxt.Out.WriteString(f.Limpidbase)
		ctxt.Out.Write8(0)
		ctxt.Out.WriteString(f.Limpidmem)
		ctxt.Out.Write8(0)
	}
	for _, s := range strtab {
		ctxt.Out.Write16(s.size)
		ctxt.Out.WriteString(s.name)
		ctxt.Out.Write8(0) // null terminator
	}

	f.loaderSize = off + uint64(stlen)
}

// XCOFF assembling and writing file

func (f *xcoffFile) writeFileHeader(ctxt *Link) {
	// File header
	f.xfhdr.Fmagic = U64_TOCMAGIC
	f.xfhdr.Fnscns = uint16(len(f.sections))
	f.xfhdr.Ftimedat = 0

	if !*FlagS {
		f.xfhdr.Fsymptr = uint64(f.symtabOffset)
		f.xfhdr.Fnsyms = int32(f.symbolCount)
	}

	if ctxt.BuildMode == BuildModeExe && ctxt.LinkMode == LinkInternal {
		ldr := ctxt.loader
		f.xfhdr.Fopthdr = AOUTHSZ_EXEC64
		f.xfhdr.Fflags = F_EXEC

		// auxiliary header
		f.xahdr.Ovstamp = 1 // based on dump -o
		f.xahdr.Omagic = 0x10b
		copy(f.xahdr.Omodtype[:], "1L")
		entry := ldr.Lookup(*flagEntrySymbol, 0)
		f.xahdr.Oentry = uint64(ldr.SymValue(entry))
		f.xahdr.Osnentry = f.getXCOFFscnum(ldr.SymSect(entry))
		toc := ldr.Lookup("TOC", 0)
		f.xahdr.Otoc = uint64(ldr.SymValue(toc))
		f.xahdr.Osntoc = f.getXCOFFscnum(ldr.SymSect(toc))

		f.xahdr.Oalgntext = int16(logBase2(int(XCOFFSECTALIGN)))
		f.xahdr.Oalgndata = 0x5

		binary.Write(ctxt.Out, binary.BigEndian, &f.xfhdr)
		binary.Write(ctxt.Out, binary.BigEndian, &f.xahdr)
	} else {
		f.xfhdr.Fopthdr = 0
		binary.Write(ctxt.Out, binary.BigEndian, &f.xfhdr)
	}

}

func xcoffwrite(ctxt *Link) {
	ctxt.Out.SeekSet(0)

	xfile.writeFileHeader(ctxt)

	for _, sect := range xfile.sections {
		sect.write(ctxt)
	}
}

// Generate XCOFF assembly file.
func asmbXcoff(ctxt *Link) {
	ctxt.Out.SeekSet(0)
	fileoff := int64(Segdwarf.Fileoff + Segdwarf.Filelen)
	fileoff = int64(Rnd(int64(fileoff), *FlagRound))

	xfile.sectNameToScnum = make(map[string]int16)

	// Add sections
	s := xfile.addSection(".text", Segtext.Vaddr, Segtext.Length, Segtext.Fileoff, STYP_TEXT)
	xfile.xahdr.Otextstart = s.Svaddr
	xfile.xahdr.Osntext = xfile.sectNameToScnum[".text"]
	xfile.xahdr.Otsize = s.Ssize
	xfile.sectText = s

	segdataVaddr := Segdata.Vaddr
	segdataFilelen := Segdata.Filelen
	segdataFileoff := Segdata.Fileoff
	segbssFilelen := Segdata.Length - Segdata.Filelen
	if len(Segrelrodata.Sections) > 0 {
		// Merge relro segment to data segment as
		// relro data are inside data segment on AIX.
		segdataVaddr = Segrelrodata.Vaddr
		segdataFileoff = Segrelrodata.Fileoff
		segdataFilelen = Segdata.Vaddr + Segdata.Filelen - Segrelrodata.Vaddr
	}

	s = xfile.addSection(".data", segdataVaddr, segdataFilelen, segdataFileoff, STYP_DATA)
	xfile.xahdr.Odatastart = s.Svaddr
	xfile.xahdr.Osndata = xfile.sectNameToScnum[".data"]
	xfile.xahdr.Odsize = s.Ssize
	xfile.sectData = s

	s = xfile.addSection(".bss", segdataVaddr+segdataFilelen, segbssFilelen, 0, STYP_BSS)
	xfile.xahdr.Osnbss = xfile.sectNameToScnum[".bss"]
	xfile.xahdr.Obsize = s.Ssize
	xfile.sectBss = s

	if ctxt.LinkMode == LinkExternal {
		var tbss *sym.Section
		for _, s := range Segdata.Sections {
			if s.Name == ".tbss" {
				tbss = s
				break
			}
		}
		s = xfile.addSection(".tbss", tbss.Vaddr, tbss.Length, 0, STYP_TBSS)
	}

	// add dwarf sections
	for _, sect := range Segdwarf.Sections {
		xfile.addDwarfSection(sect)
	}

	// add and write remaining sections
	if ctxt.LinkMode == LinkInternal {
		// Loader section
		if ctxt.BuildMode == BuildModeExe {
			Loaderblk(ctxt, uint64(fileoff))
			s = xfile.addSection(".loader", 0, xfile.loaderSize, uint64(fileoff), STYP_LOADER)
			xfile.xahdr.Osnloader = xfile.sectNameToScnum[".loader"]

			// Update fileoff for symbol table
			fileoff += int64(xfile.loaderSize)
		}
	}

	// Create Symbol table
	xfile.asmaixsym(ctxt)

	if ctxt.LinkMode == LinkExternal {
		xfile.emitRelocations(ctxt, fileoff)
	}

	// Write Symbol table
	xfile.symtabOffset = ctxt.Out.Offset()
	for _, s := range xfile.symtabSym {
		binary.Write(ctxt.Out, ctxt.Arch.ByteOrder, s)
	}
	// write string table
	xfile.stringTable.write(ctxt.Out)

	// write headers
	xcoffwrite(ctxt)
}

// emitRelocations emits relocation entries for go.o in external linking.
func (f *xcoffFile) emitRelocations(ctxt *Link, fileoff int64) {
	ctxt.Out.SeekSet(fileoff)
	for ctxt.Out.Offset()&7 != 0 {
		ctxt.Out.Write8(0)
	}

	ldr := ctxt.loader
	// relocsect relocates symbols from first in section sect, and returns
	// the total number of relocations emitted.
	relocsect := func(sect *sym.Section, syms []loader.Sym, base uint64) uint32 {
		// ctxt.Logf("%s 0x%x\n", sect.Name, sect.Vaddr)
		// If main section has no bits, nothing to relocate.
		if sect.Vaddr >= sect.Seg.Vaddr+sect.Seg.Filelen {
			return 0
		}
		sect.Reloff = uint64(ctxt.Out.Offset())
		for i, s := range syms {
			if !ldr.AttrReachable(s) {
				continue
			}
			if uint64(ldr.SymValue(s)) >= sect.Vaddr {
				syms = syms[i:]
				break
			}
		}
		eaddr := int64(sect.Vaddr + sect.Length)
		for _, s := range syms {
			if !ldr.AttrReachable(s) {
				continue
			}
			if ldr.SymValue(s) >= int64(eaddr) {
				break
			}

			// Compute external relocations on the go, and pass to Xcoffreloc1 to stream out.
			// Relocation must be ordered by address, so create a list of sorted indices.
			relocs := ldr.Relocs(s)
			sorted := make([]int, relocs.Count())
			for i := 0; i < relocs.Count(); i++ {
				sorted[i] = i
			}
			sort.Slice(sorted, func(i, j int) bool {
				return relocs.At(sorted[i]).Off() < relocs.At(sorted[j]).Off()
			})

			for _, ri := range sorted {
				r := relocs.At(ri)
				rr, ok := extreloc(ctxt, ldr, s, r)
				if !ok {
					continue
				}
				if rr.Xsym == 0 {
					ldr.Errorf(s, "missing xsym in relocation")
					continue
				}
				if ldr.SymDynid(rr.Xsym) < 0 {
					ldr.Errorf(s, "reloc %s to non-coff symbol %s (outer=%s) %d %d", r.Type(), ldr.SymName(r.Sym()), ldr.SymName(rr.Xsym), ldr.SymType(r.Sym()), ldr.SymDynid(rr.Xsym))
				}
				if !thearch.Xcoffreloc1(ctxt.Arch, ctxt.Out, ldr, s, rr, int64(uint64(ldr.SymValue(s)+int64(r.Off()))-base)) {
					ldr.Errorf(s, "unsupported obj reloc %d(%s)/%d to %s", r.Type(), r.Type(), r.Siz(), ldr.SymName(r.Sym()))
				}
			}
		}
		sect.Rellen = uint64(ctxt.Out.Offset()) - sect.Reloff
		return uint32(sect.Rellen) / RELSZ_64
	}
	sects := []struct {
		xcoffSect *XcoffScnHdr64
		segs      []*sym.Segment
	}{
		{f.sectText, []*sym.Segment{&Segtext}},
		{f.sectData, []*sym.Segment{&Segrelrodata, &Segdata}},
	}
	for _, s := range sects {
		s.xcoffSect.Srelptr = uint64(ctxt.Out.Offset())
		n := uint32(0)
		for _, seg := range s.segs {
			for _, sect := range seg.Sections {
				if sect.Name == ".text" {
					n += relocsect(sect, ctxt.Textp, 0)
				} else {
					n += relocsect(sect, ctxt.datap, 0)
				}
			}
		}
		s.xcoffSect.Snreloc += n
	}

dwarfLoop:
	for i := 0; i < len(Segdwarf.Sections); i++ {
		sect := Segdwarf.Sections[i]
		si := dwarfp[i]
		if si.secSym() != loader.Sym(sect.Sym) ||
			ldr.SymSect(si.secSym()) != sect {
			panic("inconsistency between dwarfp and Segdwarf")
		}
		for _, xcoffSect := range f.sections {
			_, subtyp := xcoffGetDwarfSubtype(sect.Name)
			if xcoffSect.Sflags&0xF0000 == subtyp {
				xcoffSect.Srelptr = uint64(ctxt.Out.Offset())
				xcoffSect.Snreloc = relocsect(sect, si.syms, sect.Vaddr)
				continue dwarfLoop
			}
		}
		Errorf("emitRelocations: could not find %q section", sect.Name)
	}
}

// xcoffCreateExportFile creates a file with exported symbols for
// -Wl,-bE option.
// ld won't export symbols unless they are listed in an export file.
func xcoffCreateExportFile(ctxt *Link) (fname string) {
	fname = filepath.Join(*flagTmpdir, "export_file.exp")
	var buf bytes.Buffer

	ldr := ctxt.loader
	for s, nsym := loader.Sym(1), loader.Sym(ldr.NSym()); s < nsym; s++ {
		if !ldr.AttrCgoExport(s) {
			continue
		}
		extname := ldr.SymExtname(s)
		if !strings.HasPrefix(extname, "._cgoexp_") {
			continue
		}
		if ldr.IsFileLocal(s) {
			continue // Only export non-static symbols
		}

		// Retrieve the name of the initial symbol
		// exported by cgo.
		// The corresponding Go symbol is:
		// _cgoexp_hashcode_symname.
		name := strings.SplitN(extname, "_", 4)[3]

		buf.Write([]byte(name + "\n"))
	}

	err := os.WriteFile(fname, buf.Bytes(), 0666)
	if err != nil {
		Errorf("WriteFile %s failed: %v", fname, err)
	}

	return fname
}
```