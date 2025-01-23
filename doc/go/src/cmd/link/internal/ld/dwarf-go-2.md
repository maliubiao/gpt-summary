Response:
Let's break down the thought process for analyzing this Go code snippet and answering the prompt.

**1. Initial Scan and Identification of Key Areas:**

The first thing I do is scan the code for recognizable keywords and function names related to DWARF debugging information. I see `dwarf`, `debug_info`, `debug_line`, `debug_frame`, `debug_loc`, `CompilationUnit`, `DIE`, `relocs`, `sym`, `loader`, `Link`. These immediately tell me this code is heavily involved in generating DWARF debugging data.

**2. Understanding the `dwarf.go` Context:**

The file path `go/src/cmd/link/internal/ld/dwarf.go` is crucial. It indicates this code is part of the Go linker (`cmd/link`), specifically within the `internal/ld` (internal linker) package, and focuses on DWARF functionality. This context helps understand the purpose: generating DWARF information *during the linking process*.

**3. Analyzing Individual Functions and Methods:**

I go through the functions and methods, trying to understand their individual roles:

* **`dwarfGenerateDebugInfo2`:** The name suggests this function is responsible for generating the `.debug_info` section. The code iterates through symbols, checks their types, handles dictionaries, and appends `VarDIEs` to compilation units. The calls to `synthesizestringtypes`, etc., indicate it's also synthesizing DWARF entries for various Go types.
* **`dwarfGenerateDebugSyms`:**  This function seems to orchestrate the generation of several DWARF sections (`debug_line`, `debug_frame`, `debug_loc`). It calls `dwarfGenerateDebugInfo2` and uses concurrency (`sync.WaitGroup`, `runtime.GOMAXPROCS`) for parallel processing.
* **`dwUnitSyms`:**  This is a data structure (struct) to hold input and output symbols related to a compilation unit during DWARF generation.
* **`dwUnitPortion`:** This function processes a single compilation unit, writing DWARF information for it (`debug_info`, `debug_lines`, `debug_ranges`, `debug_loc`). The comment emphasizes the order of calls.
* **`dwarfGenerateDebugSyms` (the method):** This is the core logic within the `dwctxt` struct. It sets up the DWARF sections, iterates through compilation units, and launches goroutines to process each unit. It also handles the `.debug_frame` section separately.
* **Helper functions:** `collectUnitLocs`, `dwarfaddshstrings`, `dwarfaddelfsectionsyms`, `dwarfcompress`, `compilationUnitByStartPCCmp`, `getPkgFromCUSym`, `getDwsectCUSize`, `addDwsectCUSize` each have specific roles in DWARF generation or management.

**4. Identifying the Core Functionality:**

By analyzing the functions, I deduce the primary function of this code is to generate DWARF debugging information during the linking process. This involves:

* **Collecting information:**  Iterating through symbols, understanding their types, and relating them to compilation units.
* **Structuring the information:** Creating a hierarchical structure of DWARF information (DIEs) within compilation units.
* **Generating DWARF sections:**  Creating the `.debug_info`, `.debug_line`, `.debug_frame`, `.debug_loc`, and `.debug_ranges` sections.
* **Optimizing output:**  Compressing DWARF sections if enabled.
* **Handling different object file formats:**  Adding section header string table entries and ELF section symbols.
* **Using concurrency:**  Speeding up the process by generating DWARF information for different compilation units in parallel.

**5. Reasoning About Go Feature Implementation:**

The code specifically mentions handling Go types (`d.defgotype`, `synthesize...types`). This strongly suggests this code is involved in representing Go's type system in DWARF. The handling of dictionaries (`IsDict`, `R_USEIFACE`) points to support for Go's map type.

**6. Constructing Examples (Mental Walkthrough):**

I consider how these functions would operate with some example Go code. Imagine a simple function and a struct:

```go
package main

type MyStruct struct {
	Field1 int
	Field2 string
}

func myFunction(a int) MyStruct {
	s := MyStruct{Field1: a, Field2: "hello"}
	return s
}

func main() {
	myFunction(10)
}
```

I mentally trace how the linker would process this:

* The compiler would generate symbol information for `MyStruct`, `myFunction`, and their members.
* `dwarfGenerateDebugInfo2` would be responsible for creating DWARF entries for `MyStruct`'s fields and `myFunction`'s parameters and return type.
* `dwarfGenerateDebugSyms` would organize this information into the appropriate DWARF sections.
* Relocations would be used to link the DWARF information to the actual code addresses.

**7. Considering Command-Line Arguments (Hypothesis):**

Although not explicitly in the code, I know linkers often have flags to control DWARF generation. I'd hypothesize flags like `-dwarf=0` (disable), `-dwarf=1` (minimal), `-dwarf=2` (full), and potentially a flag to control DWARF compression (`-compressdwarf`).

**8. Identifying Potential Pitfalls:**

The code's complexity suggests potential issues with concurrency (race conditions, though the mutexes suggest they're trying to avoid this). Also, incorrect handling of symbol types or relocations could lead to incorrect or incomplete DWARF information. The comment about symbols being listed multiple times in the info section highlights a past concurrency issue.

**9. Structuring the Answer:**

Finally, I organize the information into the requested format, addressing each point in the prompt: functionality, feature implementation with examples, command-line arguments, common mistakes, and the overall summary. I use clear and concise language, providing code examples and explanations where necessary. The "mental walkthrough" helps ensure the examples are relevant and demonstrate the code's purpose.
这是 `go/src/cmd/link/internal/ld/dwarf.go` 文件的第三部分，结合你提供的第一部分和第二部分，我们可以归纳一下它的主要功能：

**核心功能：生成 DWARF 调试信息**

这个文件是 Go 链接器 (`cmd/link`) 中负责生成 DWARF (Debugging With Arbitrary Record Format) 调试信息的核心部分。DWARF 是一种标准的调试数据格式，用于在程序运行时进行调试，例如查看变量值、设置断点、单步执行等。

**具体功能归纳：**

1. **`dwarfGenerateDebugInfo2` (第一部分涉及):**
   -  遍历所有符号，特别是全局符号。
   -  为全局变量和类型生成 DWARF 信息条目 (DIEs - Debugging Information Entries)。
   -  处理 Go 语言特有的类型信息 (`gotype`)，确保这些类型信息在 DWARF 中被正确表示。
   -  处理字典 (map) 类型，确保字典中引用的类型也是可达的。
   -  跳过文件局部符号，例如静态临时变量和汇编源文件中的局部符号。
   -  关联编译器生成的 DWARF 辅助符号 (`VarDIE`) 到相应的编译单元。
   -  合成字符串、切片、Map 和 Channel 类型的 DWARF 信息。

2. **`dwarfGenerateDebugSyms`:**
   - 作为生成 DWARF 符号的入口点。
   - 创建 `dwctxt` 结构体，用于存储 DWARF 生成的上下文信息。
   - 调用 `dwarfGenerateDebugSyms` 方法执行具体的符号生成。

3. **`dwUnitSyms`:**
   - 定义了一个结构体，用于存储单个编译单元在 DWARF 生成过程中的输入和输出符号。
   - 输入符号包括行信息序言 (`lineProlog`)、范围信息序言 (`rangeProlog`) 和信息结尾 (`infoEpilog`)。
   - 输出符号包括行信息符号 (`linesyms`)、信息符号 (`infosyms`)、位置信息符号 (`locsyms`) 和范围信息符号 (`rangessyms`)。

4. **`dwUnitPortion`:**
   - 处理单个编译单元的 DWARF 内容生成。
   - 调用 `writelines` 生成 `.debug_line` 部分。
   - 调用 `writepcranges` 生成 `.debug_ranges` 部分。
   - 调用 `collectUnitLocs` 收集单元的位置信息。
   - 调用 `writeUnitInfo` 生成 `.debug_info` 部分。
   - **重点：执行顺序很重要，因为 `writelines` 和 `writepcranges` 会更新编译单元 DIE。**

5. **`dwarfGenerateDebugSyms` (方法):**
   - 调用 `writeabbrev` 生成 `.debug_abbrev` 部分。
   - 计算编译单元的范围。
   - 反转 DIE 树，确保 DIE 的顺序与创建顺序一致。
   - 将类型信息相关的 DIE 移动到模块级别。
   - 创建 DWARF 各个 section 的符号 (例如 `.debug_frame`, `.debug_loc`, `.debug_line`, `.debug_ranges`, `.debug_info`)。
   - 使用 Goroutine 并发处理各个编译单元的 DWARF 信息生成，提高效率。
   - 调用 `dwUnitPortion` 为每个编译单元生成 DWARF 内容。
   - 合并各个编译单元生成的 DWARF 符号到对应的 section 中。
   - 调用 `writeframes` 生成 `.debug_frame` 部分。
   - 调用 `writegdbscript` 生成 `.debug_gdb_scripts` 部分。
   - 检查 `.debug_info` section 中是否存在重复的符号。

6. **`collectUnitLocs`:**
   - 收集单个编译单元中函数的位置列表符号 (`.debug_loc`)。

7. **`dwarfaddshstrings`:**
   - 将 DWARF section 的名称添加到 section header 字符串表中 (仅限 ELF 格式)。

8. **`dwarfaddelfsectionsyms`:**
   - 为 DWARF section 创建 ELF 节区符号 (仅限外部链接模式)。

9. **`dwarfcompress`:**
   - 压缩 DWARF sections，以减小最终可执行文件的大小。
   - 并行压缩各个 DWARF section。
   - 如果压缩效果不佳，则不进行压缩。
   - 更新压缩后的 section 和符号的信息。

10. **`compilationUnitByStartPCCmp`:**
    - 用于排序编译单元，排序的依据是它们代码段的起始 PC (Program Counter) 值。

11. **`getPkgFromCUSym`:**
    - 从编译单元的符号名中提取包名。

12. **`dwsectCUSizeMu` 和 `dwsectCUSize`:**
    - 用于在 AIX 平台上记录每个包在各个 `.dw` section 中的大小，以便在符号表中记录这些信息。
    - `getDwsectCUSize` 和 `addDwsectCUSize` 用于获取和添加这些大小信息。

**总结来说，这段代码以及其上下文 (第一部分和第二部分) 负责 Go 链接器生成 DWARF 调试信息的关键流程，包括：**

- **组织和构建 DWARF 信息结构 (DIE 树)。**
- **将 DWARF 信息写入到不同的 section 中 (例如 `.debug_info`, `.debug_line`, `.debug_frame` 等)。**
- **处理 Go 语言特有的类型信息和数据结构。**
- **优化 DWARF 信息的大小 (例如通过压缩)。**
- **支持不同的目标平台和文件格式 (例如 ELF)。**
- **利用并发提高 DWARF 生成的效率。**

这段代码是 Go 语言调试能力的重要组成部分，它使得开发者可以使用诸如 `gdb` 或 `dlv` 这样的调试器来调试 Go 程序。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/dwarf.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
with no type, unless it's a dictionary
		gt := d.ldr.SymGoType(idx)
		if gt == 0 {
			if t == sym.SRODATA {
				if d.ldr.IsDict(idx) {
					// This is a dictionary, make sure that all types referenced by this dictionary are reachable
					relocs := d.ldr.Relocs(idx)
					for i := 0; i < relocs.Count(); i++ {
						reloc := relocs.At(i)
						if reloc.Type() == objabi.R_USEIFACE {
							d.defgotype(reloc.Sym())
						}
					}
				}
			}
			continue
		}
		// Skip file local symbols (this includes static tmps, stack
		// object symbols, and local symbols in assembler src files).
		if d.ldr.IsFileLocal(idx) {
			continue
		}

		// Find compiler-generated DWARF info sym for global in question,
		// and tack it onto the appropriate unit.  Note that there are
		// circumstances under which we can't find the compiler-generated
		// symbol-- this typically happens as a result of compiler options
		// (e.g. compile package X with "-dwarf=0").
		varDIE := d.ldr.GetVarDwarfAuxSym(idx)
		if varDIE != 0 {
			unit := d.ldr.SymUnit(idx)
			d.defgotype(gt)
			unit.VarDIEs = append(unit.VarDIEs, sym.LoaderSym(varDIE))
		}
	}

	d.synthesizestringtypes(ctxt, dwtypes.Child)
	d.synthesizeslicetypes(ctxt, dwtypes.Child)
	d.synthesizemaptypes(ctxt, dwtypes.Child)
	d.synthesizechantypes(ctxt, dwtypes.Child)
}

// dwarfGenerateDebugSyms constructs debug_line, debug_frame, and
// debug_loc. It also writes out the debug_info section using symbols
// generated in dwarfGenerateDebugInfo2.
func dwarfGenerateDebugSyms(ctxt *Link) {
	if !dwarfEnabled(ctxt) {
		return
	}
	d := &dwctxt{
		linkctxt: ctxt,
		ldr:      ctxt.loader,
		arch:     ctxt.Arch,
		dwmu:     new(sync.Mutex),
	}
	d.dwarfGenerateDebugSyms()
}

// dwUnitSyms stores input and output symbols for DWARF generation
// for a given compilation unit.
type dwUnitSyms struct {
	// Inputs for a given unit.
	lineProlog  loader.Sym
	rangeProlog loader.Sym
	infoEpilog  loader.Sym

	// Outputs for a given unit.
	linesyms   []loader.Sym
	infosyms   []loader.Sym
	locsyms    []loader.Sym
	rangessyms []loader.Sym
}

// dwUnitPortion assembles the DWARF content for a given compilation
// unit: debug_info, debug_lines, debug_ranges, debug_loc (debug_frame
// is handled elsewhere). Order is important; the calls to writelines
// and writepcranges below make updates to the compilation unit DIE,
// hence they have to happen before the call to writeUnitInfo.
func (d *dwctxt) dwUnitPortion(u *sym.CompilationUnit, abbrevsym loader.Sym, us *dwUnitSyms) {
	if u.DWInfo.Abbrev != dwarf.DW_ABRV_COMPUNIT_TEXTLESS {
		us.linesyms = d.writelines(u, us.lineProlog)
		base := loader.Sym(u.Textp[0])
		us.rangessyms = d.writepcranges(u, base, u.PCs, us.rangeProlog)
		us.locsyms = d.collectUnitLocs(u)
	}
	us.infosyms = d.writeUnitInfo(u, abbrevsym, us.infoEpilog)
}

func (d *dwctxt) dwarfGenerateDebugSyms() {
	abbrevSec := d.writeabbrev()
	dwarfp = append(dwarfp, abbrevSec)
	d.calcCompUnitRanges()
	slices.SortFunc(d.linkctxt.compUnits, compilationUnitByStartPCCmp)

	// newdie adds DIEs to the *beginning* of the parent's DIE list.
	// Now that we're done creating DIEs, reverse the trees so DIEs
	// appear in the order they were created.
	for _, u := range d.linkctxt.compUnits {
		reversetree(&u.DWInfo.Child)
	}
	reversetree(&dwtypes.Child)
	movetomodule(d.linkctxt, &dwtypes)

	mkSecSym := func(name string) loader.Sym {
		s := d.ldr.CreateSymForUpdate(name, 0)
		s.SetType(sym.SDWARFSECT)
		s.SetReachable(true)
		return s.Sym()
	}
	mkAnonSym := func(kind sym.SymKind) loader.Sym {
		s := d.ldr.MakeSymbolUpdater(d.ldr.CreateExtSym("", 0))
		s.SetType(kind)
		s.SetReachable(true)
		return s.Sym()
	}

	// Create the section symbols.
	frameSym := mkSecSym(".debug_frame")
	locSym := mkSecSym(".debug_loc")
	lineSym := mkSecSym(".debug_line")
	rangesSym := mkSecSym(".debug_ranges")
	infoSym := mkSecSym(".debug_info")

	// Create the section objects
	lineSec := dwarfSecInfo{syms: []loader.Sym{lineSym}}
	locSec := dwarfSecInfo{syms: []loader.Sym{locSym}}
	rangesSec := dwarfSecInfo{syms: []loader.Sym{rangesSym}}
	frameSec := dwarfSecInfo{syms: []loader.Sym{frameSym}}
	infoSec := dwarfSecInfo{syms: []loader.Sym{infoSym}}

	// Create any new symbols that will be needed during the
	// parallel portion below.
	ncu := len(d.linkctxt.compUnits)
	unitSyms := make([]dwUnitSyms, ncu)
	for i := 0; i < ncu; i++ {
		us := &unitSyms[i]
		us.lineProlog = mkAnonSym(sym.SDWARFLINES)
		us.rangeProlog = mkAnonSym(sym.SDWARFRANGE)
		us.infoEpilog = mkAnonSym(sym.SDWARFFCN)
	}

	var wg sync.WaitGroup
	sema := make(chan struct{}, runtime.GOMAXPROCS(0))

	// Kick off generation of .debug_frame, since it doesn't have
	// any entanglements and can be started right away.
	wg.Add(1)
	go func() {
		sema <- struct{}{}
		defer func() {
			<-sema
			wg.Done()
		}()
		frameSec = d.writeframes(frameSym)
	}()

	// Create a goroutine per comp unit to handle the generation that
	// unit's portion of .debug_line, .debug_loc, .debug_ranges, and
	// .debug_info.
	wg.Add(len(d.linkctxt.compUnits))
	for i := 0; i < ncu; i++ {
		go func(u *sym.CompilationUnit, us *dwUnitSyms) {
			sema <- struct{}{}
			defer func() {
				<-sema
				wg.Done()
			}()
			d.dwUnitPortion(u, abbrevSec.secSym(), us)
		}(d.linkctxt.compUnits[i], &unitSyms[i])
	}
	wg.Wait()

	markReachable := func(syms []loader.Sym) []loader.Sym {
		for _, s := range syms {
			d.ldr.SetAttrNotInSymbolTable(s, true)
			d.ldr.SetAttrReachable(s, true)
		}
		return syms
	}

	// Stitch together the results.
	for i := 0; i < ncu; i++ {
		r := &unitSyms[i]
		lineSec.syms = append(lineSec.syms, markReachable(r.linesyms)...)
		infoSec.syms = append(infoSec.syms, markReachable(r.infosyms)...)
		locSec.syms = append(locSec.syms, markReachable(r.locsyms)...)
		rangesSec.syms = append(rangesSec.syms, markReachable(r.rangessyms)...)
	}
	dwarfp = append(dwarfp, lineSec)
	dwarfp = append(dwarfp, frameSec)
	gdbScriptSec := d.writegdbscript()
	if gdbScriptSec.secSym() != 0 {
		dwarfp = append(dwarfp, gdbScriptSec)
	}
	dwarfp = append(dwarfp, infoSec)
	if len(locSec.syms) > 1 {
		dwarfp = append(dwarfp, locSec)
	}
	dwarfp = append(dwarfp, rangesSec)

	// Check to make sure we haven't listed any symbols more than once
	// in the info section. This used to be done by setting and
	// checking the OnList attribute in "putdie", but that strategy
	// was not friendly for concurrency.
	seen := loader.MakeBitmap(d.ldr.NSym())
	for _, s := range infoSec.syms {
		if seen.Has(s) {
			log.Fatalf("dwarf symbol %s listed multiple times",
				d.ldr.SymName(s))
		}
		seen.Set(s)
	}
}

func (d *dwctxt) collectUnitLocs(u *sym.CompilationUnit) []loader.Sym {
	syms := []loader.Sym{}
	for _, fn := range u.FuncDIEs {
		relocs := d.ldr.Relocs(loader.Sym(fn))
		for i := 0; i < relocs.Count(); i++ {
			reloc := relocs.At(i)
			if reloc.Type() != objabi.R_DWARFSECREF {
				continue
			}
			rsym := reloc.Sym()
			if d.ldr.SymType(rsym) == sym.SDWARFLOC {
				syms = append(syms, rsym)
				// One location list entry per function, but many relocations to it. Don't duplicate.
				break
			}
		}
	}
	return syms
}

// Add DWARF section names to the section header string table, by calling add
// on each name. ELF only.
func dwarfaddshstrings(ctxt *Link, add func(string)) {
	if *FlagW { // disable dwarf
		return
	}

	secs := []string{"abbrev", "frame", "info", "loc", "line", "gdb_scripts", "ranges"}
	for _, sec := range secs {
		add(".debug_" + sec)
		if ctxt.IsExternal() {
			add(elfRelType + ".debug_" + sec)
		}
	}
}

func dwarfaddelfsectionsyms(ctxt *Link) {
	if *FlagW { // disable dwarf
		return
	}
	if ctxt.LinkMode != LinkExternal {
		return
	}

	ldr := ctxt.loader
	for _, si := range dwarfp {
		s := si.secSym()
		sect := ldr.SymSect(si.secSym())
		putelfsectionsym(ctxt, ctxt.Out, s, sect.Elfsect.(*ElfShdr).shnum)
	}
}

// dwarfcompress compresses the DWARF sections. Relocations are applied
// on the fly. After this, dwarfp will contain a different (new) set of
// symbols, and sections may have been replaced.
func dwarfcompress(ctxt *Link) {
	// compressedSect is a helper type for parallelizing compression.
	type compressedSect struct {
		index      int
		compressed []byte
		syms       []loader.Sym
	}

	supported := ctxt.IsELF || ctxt.IsWindows() || ctxt.IsDarwin()
	if !ctxt.compressDWARF || !supported || ctxt.IsExternal() {
		return
	}

	var compressedCount int
	resChannel := make(chan compressedSect)
	for i := range dwarfp {
		go func(resIndex int, syms []loader.Sym) {
			resChannel <- compressedSect{resIndex, compressSyms(ctxt, syms), syms}
		}(compressedCount, dwarfp[i].syms)
		compressedCount++
	}
	res := make([]compressedSect, compressedCount)
	for ; compressedCount > 0; compressedCount-- {
		r := <-resChannel
		res[r.index] = r
	}

	ldr := ctxt.loader
	var newDwarfp []dwarfSecInfo
	Segdwarf.Sections = Segdwarf.Sections[:0]
	for _, z := range res {
		s := z.syms[0]
		if z.compressed == nil {
			// Compression didn't help.
			ds := dwarfSecInfo{syms: z.syms}
			newDwarfp = append(newDwarfp, ds)
			Segdwarf.Sections = append(Segdwarf.Sections, ldr.SymSect(s))
		} else {
			var compressedSegName string
			if ctxt.IsELF {
				compressedSegName = ldr.SymSect(s).Name
			} else {
				compressedSegName = ".zdebug_" + ldr.SymSect(s).Name[len(".debug_"):]
			}
			sect := addsection(ctxt.loader, ctxt.Arch, &Segdwarf, compressedSegName, 04)
			sect.Align = int32(ctxt.Arch.Alignment)
			sect.Length = uint64(len(z.compressed))
			sect.Compressed = true
			newSym := ldr.MakeSymbolBuilder(compressedSegName)
			ldr.SetAttrReachable(s, true)
			newSym.SetData(z.compressed)
			newSym.SetSize(int64(len(z.compressed)))
			ldr.SetSymSect(newSym.Sym(), sect)
			ds := dwarfSecInfo{syms: []loader.Sym{newSym.Sym()}}
			newDwarfp = append(newDwarfp, ds)

			// compressed symbols are no longer needed.
			for _, s := range z.syms {
				ldr.SetAttrReachable(s, false)
				ldr.FreeSym(s)
			}
		}
	}
	dwarfp = newDwarfp

	// Re-compute the locations of the compressed DWARF symbols
	// and sections, since the layout of these within the file is
	// based on Section.Vaddr and Symbol.Value.
	pos := Segdwarf.Vaddr
	var prevSect *sym.Section
	for _, si := range dwarfp {
		for _, s := range si.syms {
			ldr.SetSymValue(s, int64(pos))
			sect := ldr.SymSect(s)
			if sect != prevSect {
				sect.Vaddr = uint64(pos)
				prevSect = sect
			}
			if ldr.SubSym(s) != 0 {
				log.Fatalf("%s: unexpected sub-symbols", ldr.SymName(s))
			}
			pos += uint64(ldr.SymSize(s))
			if ctxt.IsWindows() {
				pos = uint64(Rnd(int64(pos), PEFILEALIGN))
			}
		}
	}
	Segdwarf.Length = pos - Segdwarf.Vaddr
}

func compilationUnitByStartPCCmp(a, b *sym.CompilationUnit) int {
	switch {
	case len(a.Textp) == 0 && len(b.Textp) == 0:
		return strings.Compare(a.Lib.Pkg, b.Lib.Pkg)
	case len(a.Textp) != 0 && len(b.Textp) == 0:
		return -1
	case len(a.Textp) == 0 && len(b.Textp) != 0:
		return +1
	default:
		return cmp.Compare(a.PCs[0].Start, b.PCs[0].Start)
	}
}

// getPkgFromCUSym returns the package name for the compilation unit
// represented by s.
// The prefix dwarf.InfoPrefix+".pkg." needs to be removed in order to get
// the package name.
func (d *dwctxt) getPkgFromCUSym(s loader.Sym) string {
	return strings.TrimPrefix(d.ldr.SymName(s), dwarf.InfoPrefix+".pkg.")
}

// On AIX, the symbol table needs to know where are the compilation units parts
// for a specific package in each .dw section.
// dwsectCUSize map will save the size of a compilation unit for
// the corresponding .dw section.
// This size can later be retrieved with the index "sectionName.pkgName".
var dwsectCUSizeMu sync.Mutex
var dwsectCUSize map[string]uint64

// getDwsectCUSize retrieves the corresponding package size inside the current section.
func getDwsectCUSize(sname string, pkgname string) uint64 {
	return dwsectCUSize[sname+"."+pkgname]
}

func addDwsectCUSize(sname string, pkgname string, size uint64) {
	dwsectCUSizeMu.Lock()
	defer dwsectCUSizeMu.Unlock()
	dwsectCUSize[sname+"."+pkgname] += size
}
```