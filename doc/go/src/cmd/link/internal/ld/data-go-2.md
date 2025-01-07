Response:
The user is asking for a summary of the functionality of the provided Go code snippet. This code snippet is part of the Go linker and deals with the allocation of memory sections for different types of data and code.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core task:** The code is about memory layout during linking. It's assigning sections to segments and calculating their virtual addresses and lengths.

2. **Recognize the main data structures:** Notice the `dodataState` struct and the `Seg*` variables like `Segtext`, `Segrodata`, `Segdata`, etc. These represent different memory segments. The `sym.Section` type is also key, representing individual sections within segments.

3. **Analyze the key functions:**
    * `dodata`: This is the main function in the snippet. It handles the allocation of data and read-only data sections. It sets up various symbols related to runtime and fuzzing. It distinguishes between read-only data (`.rodata`) and read-only data with relocations (`.data.rel.ro`).
    * `allocateDwarfSections`: This function specifically handles the allocation of sections for DWARF debugging information.
    * `allocateSEHSections`: This function allocates sections for SEH (Structured Exception Handling) data, primarily used on Windows.
    * `dodataSect`:  This function sorts symbols within a section based on their size and handles special placement for certain runtime symbols.
    * `textbuildid`:  This function adds a build ID to the beginning of the text segment for non-ELF systems.
    * `buildinfo`: This function writes build information into a special symbol.
    * `textaddress`:  This is crucial for assigning virtual addresses to code (`.text`) sections. It handles potential randomization of function order and the insertion of trampolines for long jumps.
    * `assignAddress`:  This helper function assigns an address to a single text symbol, considering alignment and the possibility of splitting text sections.
    * `resetAddress`:  Resets the address of a symbol.
    * `splitTextSections`: Determines if text sections need to be split based on architecture and linking mode.
    * `address`:  This is the final stage where virtual addresses are assigned to all segments and sections, considering alignment and platform-specific constraints (like Wasm's reserved memory).

4. **Group functionalities by purpose:**  The code can be grouped into logical blocks:
    * **Data and Read-Only Data Allocation:** `dodata`, `allocateNamedDataSection`, dealing with `.rodata`, `.data.rel.ro`, etc.
    * **Debugging Information Allocation:** `allocateDwarfSections`.
    * **Exception Handling Data Allocation:** `allocateSEHSections`.
    * **Symbol Sorting and Placement within Sections:** `dodataSect`.
    * **Build Information Embedding:** `textbuildid`, `buildinfo`.
    * **Code Address Assignment:** `textaddress`, `assignAddress`, `resetAddress`, `splitTextSections`.
    * **Final Address Assignment to Segments and Sections:** `address`.

5. **Identify key concepts:**
    * **Segments:**  High-level memory regions (e.g., `Segtext` for code, `Segdata` for mutable data).
    * **Sections:**  More granular divisions within segments (e.g., `.text`, `.rodata`, `.bss`).
    * **Symbols:**  Represent named locations in memory (functions, variables, etc.).
    * **Virtual Addresses:** The addresses the program will see at runtime.
    * **Alignment:** Ensuring data and code start at memory addresses that are multiples of certain values.
    * **Trampolines:** Small code snippets used for long jumps when direct calls are out of range.
    * **RelRO:** Read-only relocations, a security feature.

6. **Formulate the summary:** Combine the grouped functionalities and key concepts into a concise description. Emphasize the main goal of the code.

7. **Refine the summary:**  Ensure the language is clear and accurate. Use terms like "allocates," "assigns," and "manages" to describe the actions. Mention the different types of data and code being processed.

By following these steps, we can arrive at a comprehensive and accurate summary of the code's functionality, as demonstrated in the provided good answer.
这段代码是Go语言链接器 `cmd/link` 中处理数据段（data segment）和只读数据段（read-only data segment）布局的关键部分。它是 `dodata` 函数的一部分，负责将各种类型的符号分配到相应的内存段和节（section）中，并计算它们的虚拟地址和长度。

**具体功能归纳如下：**

1. **处理特殊符号并分配到数据段：**
   - 将与覆盖率分析 (`__start_coverage_mapping`, `__stop_coverage_mapping`) 和模糊测试 (`internal/fuzz._counters`, `internal/fuzz._ecounters`) 相关的特殊符号分配到 `.data.o` 节。
   - 将 `runtime.end` 符号指向数据段的最后一个节，用于标记数据段的结束。

2. **处理线程局部存储（TLS）数据：**
   - 如果存在 TLS 数据 (`state.data[sym.STLSBSS]`)，则根据目标平台和链接模式，可能创建一个 `.tbss` 节。
   - 将 TLS 符号分配到 `.tbss` 节（如果创建了）。
   - 计算 TLS 数据的大小并更新 `state.datsize`。

3. **处理只读数据并分配到只读数据段：**
   - **确定只读数据段的目标：** 根据目标平台和链接模式，确定只读数据应该分配到 `Segrodata` (独立的只读数据段) 还是 `Segtext` (与代码段合并)。
   - **处理只读可执行节：** 检查是否存在 `sym.STEXT` 类型的符号被错误地放入了数据处理流程。
   - **分配只读 ELF/Mach-O 节：**  分配 `SELFRXSECT` 和 `SMACHOPLT` 类型的符号到 `Segtext` 段。
   - **分配 `.rodata` 节：** 创建 `.rodata` 节，并将 `runtime.rodata` 和 `runtime.erodata` 等符号指向该节。
   - **处理真正的只读数据：** 遍历 `sym.ReadOnly` 中定义的符号类型，将相应的符号分配到 `.rodata` 节，并计算它们的大小。
   - **分配只读 ELF/Mach-O 节：** 分配 `SELFROSECT` 类型的符号到只读数据段。

4. **处理只读数据但需要重定位的情况（RelRO）：**
   - **确定 RelRO 数据段的目标：** 如果启用了 RelRO (`ctxt.UseRelro()`)，则可能创建一个独立的 `Segrelrodata` 段，否则仍然使用 `Segrodata`。
   - **分配 RelRO 节：** 创建以 `.data.rel.ro` 为前缀的节，并将 `runtime.types` 和 `runtime.etypes` 等符号指向该节。
   - **处理需要重定位的只读数据：** 遍历 `sym.ReadOnly` 中定义的符号类型，将对应的 `sym.RelROMap` 中的符号分配到 RelRO 节，并计算大小。
   - **分配只读 ELF/Mach-O RelRO 节：** 分配 `SELFRELROSECT` 类型的符号到 RelRO 数据段。

5. **处理其他特定的只读数据节：**
   - **`.typelink` 节：**  创建 `.typelink` 节，并将 `runtime.typelink` 符号分配到该节。
   - **`.itablink` 节：** 创建 `.itablink` 节，并将 `runtime.itablink` 符号分配到该节。
   - **`.gosymtab` 节：** 创建 `.gosymtab` 节，并将符号表相关的符号 (`runtime.symtab`, `runtime.esymtab`) 分配到该节。
   - **`.gopclntab` 节：** 创建 `.gopclntab` 节，并将 Go 程序计数器行号表相关的符号 (`runtime.pclntab`, `runtime.pcheader` 等) 分配到该节，并记录该节的大小。

6. **数据段大小限制检查：**
   - 对于某些架构（如 6g），检查只读数据段的大小是否超过 32 位限制。

7. **收集数据段符号：**
   - 将分配到数据段的符号收集到 `ctxt.datap` 切片中。

总而言之，这段代码的主要功能是 **组织和分配程序运行时所需的各种数据到内存中的不同节和段中，并为这些节和段设定起始地址和大小。它区分了可修改的数据、只读数据以及需要重定位的只读数据，并根据目标平台的特性进行不同的处理。** 这对于链接器的后续步骤，例如地址分配和重定位至关重要。

Prompt: 
```
这是路径为go/src/cmd/link/internal/ld/data.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能

"""
me.__stop___sancov_cntrs", 0), sect)
		ldr.SetSymSect(ldr.LookupOrCreateSym("internal/fuzz._counters", 0), sect)
		ldr.SetSymSect(ldr.LookupOrCreateSym("internal/fuzz._ecounters", 0), sect)
	}

	// Assign runtime.end to the last section of data segment.
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.end", 0), Segdata.Sections[len(Segdata.Sections)-1])

	if len(state.data[sym.STLSBSS]) > 0 {
		var sect *sym.Section
		// FIXME: not clear why it is sometimes necessary to suppress .tbss section creation.
		if (ctxt.IsELF || ctxt.HeadType == objabi.Haix) && (ctxt.LinkMode == LinkExternal || !*FlagD) {
			sect = addsection(ldr, ctxt.Arch, &Segdata, ".tbss", 06)
			sect.Align = int32(ctxt.Arch.PtrSize)
			// FIXME: why does this need to be set to zero?
			sect.Vaddr = 0
		}
		state.datsize = 0

		for _, s := range state.data[sym.STLSBSS] {
			state.datsize = aligndatsize(state, state.datsize, s)
			if sect != nil {
				ldr.SetSymSect(s, sect)
			}
			ldr.SetSymValue(s, state.datsize)
			state.datsize += ldr.SymSize(s)
		}
		state.checkdatsize(sym.STLSBSS)

		if sect != nil {
			sect.Length = uint64(state.datsize)
		}
	}

	/*
	 * We finished data, begin read-only data.
	 * Not all systems support a separate read-only non-executable data section.
	 * ELF and Windows PE systems do.
	 * OS X and Plan 9 do not.
	 * And if we're using external linking mode, the point is moot,
	 * since it's not our decision; that code expects the sections in
	 * segtext.
	 */
	var segro *sym.Segment
	if ctxt.IsELF && ctxt.LinkMode == LinkInternal {
		segro = &Segrodata
	} else if ctxt.HeadType == objabi.Hwindows {
		segro = &Segrodata
	} else {
		segro = &Segtext
	}

	state.datsize = 0

	/* read-only executable ELF, Mach-O sections */
	if len(state.data[sym.STEXT]) != 0 {
		culprit := ldr.SymName(state.data[sym.STEXT][0])
		Errorf("dodata found an sym.STEXT symbol: %s", culprit)
	}
	state.allocateSingleSymSections(&Segtext, sym.SELFRXSECT, sym.SRODATA, 05)
	state.allocateSingleSymSections(&Segtext, sym.SMACHOPLT, sym.SRODATA, 05)

	/* read-only data */
	sect = state.allocateNamedDataSection(segro, ".rodata", sym.ReadOnly, 04)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.rodata", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.erodata", 0), sect)
	if !ctxt.UseRelro() {
		ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.types", 0), sect)
		ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.etypes", 0), sect)
	}
	for _, symn := range sym.ReadOnly {
		symnStartValue := state.datsize
		if len(state.data[symn]) != 0 {
			symnStartValue = aligndatsize(state, symnStartValue, state.data[symn][0])
		}
		state.assignToSection(sect, symn, sym.SRODATA)
		setCarrierSize(symn, state.datsize-symnStartValue)
		if ctxt.HeadType == objabi.Haix {
			// Read-only symbols might be wrapped inside their outer
			// symbol.
			// XCOFF symbol table needs to know the size of
			// these outer symbols.
			xcoffUpdateOuterSize(ctxt, state.datsize-symnStartValue, symn)
		}
	}

	/* read-only ELF, Mach-O sections */
	state.allocateSingleSymSections(segro, sym.SELFROSECT, sym.SRODATA, 04)

	// There is some data that are conceptually read-only but are written to by
	// relocations. On GNU systems, we can arrange for the dynamic linker to
	// mprotect sections after relocations are applied by giving them write
	// permissions in the object file and calling them ".data.rel.ro.FOO". We
	// divide the .rodata section between actual .rodata and .data.rel.ro.rodata,
	// but for the other sections that this applies to, we just write a read-only
	// .FOO section or a read-write .data.rel.ro.FOO section depending on the
	// situation.
	// TODO(mwhudson): It would make sense to do this more widely, but it makes
	// the system linker segfault on darwin.
	const relroPerm = 06
	const fallbackPerm = 04
	relroSecPerm := fallbackPerm
	genrelrosecname := func(suffix string) string {
		if suffix == "" {
			return ".rodata"
		}
		return suffix
	}
	seg := segro

	if ctxt.UseRelro() {
		segrelro := &Segrelrodata
		if ctxt.LinkMode == LinkExternal && !ctxt.IsAIX() && !ctxt.IsDarwin() {
			// Using a separate segment with an external
			// linker results in some programs moving
			// their data sections unexpectedly, which
			// corrupts the moduledata. So we use the
			// rodata segment and let the external linker
			// sort out a rel.ro segment.
			segrelro = segro
		} else {
			// Reset datsize for new segment.
			state.datsize = 0
		}

		if !ctxt.IsDarwin() { // We don't need the special names on darwin.
			genrelrosecname = func(suffix string) string {
				return ".data.rel.ro" + suffix
			}
		}

		relroReadOnly := []sym.SymKind{}
		for _, symnro := range sym.ReadOnly {
			symn := sym.RelROMap[symnro]
			relroReadOnly = append(relroReadOnly, symn)
		}
		seg = segrelro
		relroSecPerm = relroPerm

		/* data only written by relocations */
		sect = state.allocateNamedDataSection(segrelro, genrelrosecname(""), relroReadOnly, relroSecPerm)

		ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.types", 0), sect)
		ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.etypes", 0), sect)

		for i, symnro := range sym.ReadOnly {
			if i == 0 && symnro == sym.STYPE && ctxt.HeadType != objabi.Haix {
				// Skip forward so that no type
				// reference uses a zero offset.
				// This is unlikely but possible in small
				// programs with no other read-only data.
				state.datsize++
			}

			symn := sym.RelROMap[symnro]
			if symn == sym.Sxxx {
				continue
			}
			symnStartValue := state.datsize
			if len(state.data[symn]) != 0 {
				symnStartValue = aligndatsize(state, symnStartValue, state.data[symn][0])
			}

			for _, s := range state.data[symn] {
				outer := ldr.OuterSym(s)
				if s != 0 && ldr.SymSect(outer) != nil && ldr.SymSect(outer) != sect {
					ctxt.Errorf(s, "s.Outer (%s) in different section from s, %s != %s", ldr.SymName(outer), ldr.SymSect(outer).Name, sect.Name)
				}
			}
			state.assignToSection(sect, symn, sym.SRODATA)
			setCarrierSize(symn, state.datsize-symnStartValue)
			if ctxt.HeadType == objabi.Haix {
				// Read-only symbols might be wrapped inside their outer
				// symbol.
				// XCOFF symbol table needs to know the size of
				// these outer symbols.
				xcoffUpdateOuterSize(ctxt, state.datsize-symnStartValue, symn)
			}
		}
		sect.Length = uint64(state.datsize) - sect.Vaddr

		state.allocateSingleSymSections(segrelro, sym.SELFRELROSECT, sym.SRODATA, relroSecPerm)
	}

	/* typelink */
	sect = state.allocateNamedDataSection(seg, genrelrosecname(".typelink"), []sym.SymKind{sym.STYPELINK}, relroSecPerm)

	typelink := ldr.CreateSymForUpdate("runtime.typelink", 0)
	ldr.SetSymSect(typelink.Sym(), sect)
	typelink.SetType(sym.SRODATA)
	state.datsize += typelink.Size()
	state.checkdatsize(sym.STYPELINK)
	sect.Length = uint64(state.datsize) - sect.Vaddr

	/* itablink */
	sect = state.allocateNamedDataSection(seg, genrelrosecname(".itablink"), []sym.SymKind{sym.SITABLINK}, relroSecPerm)

	itablink := ldr.CreateSymForUpdate("runtime.itablink", 0)
	ldr.SetSymSect(itablink.Sym(), sect)
	itablink.SetType(sym.SRODATA)
	state.datsize += itablink.Size()
	state.checkdatsize(sym.SITABLINK)
	sect.Length = uint64(state.datsize) - sect.Vaddr

	/* gosymtab */
	sect = state.allocateNamedSectionAndAssignSyms(seg, genrelrosecname(".gosymtab"), sym.SSYMTAB, sym.SRODATA, relroSecPerm)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.symtab", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.esymtab", 0), sect)

	/* gopclntab */
	sect = state.allocateNamedSectionAndAssignSyms(seg, genrelrosecname(".gopclntab"), sym.SPCLNTAB, sym.SRODATA, relroSecPerm)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.pclntab", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.pcheader", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.funcnametab", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.cutab", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.filetab", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.pctab", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.functab", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.epclntab", 0), sect)
	setCarrierSize(sym.SPCLNTAB, int64(sect.Length))
	if ctxt.HeadType == objabi.Haix {
		xcoffUpdateOuterSize(ctxt, int64(sect.Length), sym.SPCLNTAB)
	}

	// 6g uses 4-byte relocation offsets, so the entire segment must fit in 32 bits.
	if state.datsize != int64(uint32(state.datsize)) {
		Errorf("read-only data segment too large: %d", state.datsize)
	}

	siz := 0
	for symn := sym.SELFRXSECT; symn < sym.SXREF; symn++ {
		siz += len(state.data[symn])
	}
	ctxt.datap = make([]loader.Sym, 0, siz)
	for symn := sym.SELFRXSECT; symn < sym.SXREF; symn++ {
		ctxt.datap = append(ctxt.datap, state.data[symn]...)
	}
}

// allocateDwarfSections allocates sym.Section objects for DWARF
// symbols, and assigns symbols to sections.
func (state *dodataState) allocateDwarfSections(ctxt *Link) {

	alignOne := func(state *dodataState, datsize int64, s loader.Sym) int64 { return datsize }

	ldr := ctxt.loader
	for i := 0; i < len(dwarfp); i++ {
		// First the section symbol.
		s := dwarfp[i].secSym()
		sect := state.allocateNamedDataSection(&Segdwarf, ldr.SymName(s), []sym.SymKind{}, 04)
		ldr.SetSymSect(s, sect)
		sect.Sym = sym.LoaderSym(s)
		curType := ldr.SymType(s)
		state.setSymType(s, sym.SRODATA)
		ldr.SetSymValue(s, int64(uint64(state.datsize)-sect.Vaddr))
		state.datsize += ldr.SymSize(s)

		// Then any sub-symbols for the section symbol.
		subSyms := dwarfp[i].subSyms()
		state.assignDsymsToSection(sect, subSyms, sym.SRODATA, alignOne)

		for j := 0; j < len(subSyms); j++ {
			s := subSyms[j]
			if ctxt.HeadType == objabi.Haix && curType == sym.SDWARFLOC {
				// Update the size of .debug_loc for this symbol's
				// package.
				addDwsectCUSize(".debug_loc", ldr.SymPkg(s), uint64(ldr.SymSize(s)))
			}
		}
		sect.Length = uint64(state.datsize) - sect.Vaddr
		checkSectSize(sect)
	}
}

// allocateSEHSections allocate a sym.Section object for SEH
// symbols, and assigns symbols to sections.
func (state *dodataState) allocateSEHSections(ctxt *Link) {
	if len(sehp.pdata) > 0 {
		sect := state.allocateNamedDataSection(&Segpdata, ".pdata", []sym.SymKind{}, 04)
		state.assignDsymsToSection(sect, sehp.pdata, sym.SRODATA, aligndatsize)
		state.checkdatsize(sym.SSEHSECT)
	}
	if len(sehp.xdata) > 0 {
		sect := state.allocateNamedDataSection(&Segxdata, ".xdata", []sym.SymKind{}, 04)
		state.assignDsymsToSection(sect, sehp.xdata, sym.SRODATA, aligndatsize)
		state.checkdatsize(sym.SSEHSECT)
	}
}

type symNameSize struct {
	name string
	sz   int64
	val  int64
	sym  loader.Sym
}

func (state *dodataState) dodataSect(ctxt *Link, symn sym.SymKind, syms []loader.Sym) (result []loader.Sym, maxAlign int32) {
	var head, tail, zerobase loader.Sym
	ldr := ctxt.loader
	sl := make([]symNameSize, len(syms))

	// For ppc64, we want to interleave the .got and .toc sections
	// from input files. Both are type sym.SELFGOT, so in that case
	// we skip size comparison and do the name comparison instead
	// (conveniently, .got sorts before .toc).
	sortBySize := symn != sym.SELFGOT

	for k, s := range syms {
		ss := ldr.SymSize(s)
		sl[k] = symNameSize{sz: ss, sym: s}
		if !sortBySize {
			sl[k].name = ldr.SymName(s)
		}
		ds := int64(len(ldr.Data(s)))
		switch {
		case ss < ds:
			ctxt.Errorf(s, "initialize bounds (%d < %d)", ss, ds)
		case ss < 0:
			ctxt.Errorf(s, "negative size (%d bytes)", ss)
		case ss > cutoff:
			ctxt.Errorf(s, "symbol too large (%d bytes)", ss)
		}

		// If the usually-special section-marker symbols are being laid
		// out as regular symbols, put them either at the beginning or
		// end of their section.
		if (ctxt.DynlinkingGo() && ctxt.HeadType == objabi.Hdarwin) || (ctxt.HeadType == objabi.Haix && ctxt.LinkMode == LinkExternal) {
			switch ldr.SymName(s) {
			case "runtime.text", "runtime.bss", "runtime.data", "runtime.types", "runtime.rodata",
				"runtime.noptrdata", "runtime.noptrbss":
				head = s
				continue
			case "runtime.etext", "runtime.ebss", "runtime.edata", "runtime.etypes", "runtime.erodata",
				"runtime.enoptrdata", "runtime.enoptrbss":
				tail = s
				continue
			}
		}
	}
	zerobase = ldr.Lookup("runtime.zerobase", 0)

	// Perform the sort.
	if symn != sym.SPCLNTAB {
		sort.Slice(sl, func(i, j int) bool {
			si, sj := sl[i].sym, sl[j].sym
			isz, jsz := sl[i].sz, sl[j].sz
			switch {
			case si == head, sj == tail:
				return true
			case sj == head, si == tail:
				return false
			}
			if sortBySize {
				switch {
				// put zerobase right after all the zero-sized symbols,
				// so zero-sized symbols have the same address as zerobase.
				case si == zerobase:
					return jsz != 0 // zerobase < nonzero-sized, zerobase > zero-sized
				case sj == zerobase:
					return isz == 0 // 0-sized < zerobase, nonzero-sized > zerobase
				case isz != jsz:
					return isz < jsz
				}
			} else {
				iname := sl[i].name
				jname := sl[j].name
				if iname != jname {
					return iname < jname
				}
			}
			return si < sj // break ties by symbol number
		})
	} else {
		// PCLNTAB was built internally, and already has the proper order.
	}

	// Set alignment, construct result
	syms = syms[:0]
	for k := range sl {
		s := sl[k].sym
		if s != head && s != tail {
			align := symalign(ldr, s)
			if maxAlign < align {
				maxAlign = align
			}
		}
		syms = append(syms, s)
	}

	return syms, maxAlign
}

// Add buildid to beginning of text segment, on non-ELF systems.
// Non-ELF binary formats are not always flexible enough to
// give us a place to put the Go build ID. On those systems, we put it
// at the very beginning of the text segment.
// This “header” is read by cmd/go.
func (ctxt *Link) textbuildid() {
	if ctxt.IsELF || *flagBuildid == "" {
		return
	}

	ldr := ctxt.loader
	s := ldr.CreateSymForUpdate("go:buildid", 0)
	// The \xff is invalid UTF-8, meant to make it less likely
	// to find one of these accidentally.
	data := "\xff Go build ID: " + strconv.Quote(*flagBuildid) + "\n \xff"
	s.SetType(sym.STEXT)
	s.SetData([]byte(data))
	s.SetSize(int64(len(data)))

	ctxt.Textp = append(ctxt.Textp, 0)
	copy(ctxt.Textp[1:], ctxt.Textp)
	ctxt.Textp[0] = s.Sym()
}

func (ctxt *Link) buildinfo() {
	// Write the buildinfo symbol, which go version looks for.
	// The code reading this data is in package debug/buildinfo.
	ldr := ctxt.loader
	s := ldr.CreateSymForUpdate("go:buildinfo", 0)
	s.SetType(sym.SBUILDINFO)
	s.SetAlign(16)

	// The \xff is invalid UTF-8, meant to make it less likely
	// to find one of these accidentally.
	const prefix = "\xff Go buildinf:" // 14 bytes, plus 1 data byte filled in below

	// Header is always 32-bytes, a hold-over from before
	// https://go.dev/cl/369977.
	data := make([]byte, 32)
	copy(data, prefix)
	data[len(prefix)] = byte(ctxt.Arch.PtrSize)
	data[len(prefix)+1] = 0
	if ctxt.Arch.ByteOrder == binary.BigEndian {
		data[len(prefix)+1] = 1
	}
	data[len(prefix)+1] |= 2 // signals new pointer-free format
	data = appendString(data, strdata["runtime.buildVersion"])
	data = appendString(data, strdata["runtime.modinfo"])
	// MacOS linker gets very upset if the size is not a multiple of alignment.
	for len(data)%16 != 0 {
		data = append(data, 0)
	}
	s.SetData(data)
	s.SetSize(int64(len(data)))

	// Add reference to go:buildinfo from the rodata section,
	// so that external linking with -Wl,--gc-sections does not
	// delete the build info.
	sr := ldr.CreateSymForUpdate("go:buildinfo.ref", 0)
	sr.SetType(sym.SRODATA)
	sr.SetAlign(int32(ctxt.Arch.PtrSize))
	sr.AddAddr(ctxt.Arch, s.Sym())
}

// appendString appends s to data, prefixed by its varint-encoded length.
func appendString(data []byte, s string) []byte {
	var v [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(v[:], uint64(len(s)))
	data = append(data, v[:n]...)
	data = append(data, s...)
	return data
}

// assign addresses to text
func (ctxt *Link) textaddress() {
	addsection(ctxt.loader, ctxt.Arch, &Segtext, ".text", 05)

	// Assign PCs in text segment.
	// Could parallelize, by assigning to text
	// and then letting threads copy down, but probably not worth it.
	sect := Segtext.Sections[0]

	sect.Align = int32(Funcalign)

	ldr := ctxt.loader

	if *flagRandLayout != 0 {
		r := rand.New(rand.NewSource(*flagRandLayout))
		textp := ctxt.Textp
		i := 0
		// don't move the buildid symbol
		if len(textp) > 0 && ldr.SymName(textp[0]) == "go:buildid" {
			i++
		}
		// Skip over C symbols, as functions in a (C object) section must stay together.
		// TODO: maybe we can move a section as a whole.
		// Note: we load C symbols before Go symbols, so we can scan from the start.
		for i < len(textp) && (ldr.SubSym(textp[i]) != 0 || ldr.AttrSubSymbol(textp[i])) {
			i++
		}
		textp = textp[i:]
		r.Shuffle(len(textp), func(i, j int) {
			textp[i], textp[j] = textp[j], textp[i]
		})
	}

	// Sort the text symbols by type, so that FIPS symbols are
	// gathered together, with the FIPS start and end symbols
	// bracketing them , even if we've randomized the overall order.
	sort.SliceStable(ctxt.Textp, func(i, j int) bool {
		return ldr.SymType(ctxt.Textp[i]) < ldr.SymType(ctxt.Textp[j])
	})

	text := ctxt.xdefine("runtime.text", sym.STEXT, 0)
	etext := ctxt.xdefine("runtime.etext", sym.STEXTEND, 0)
	ldr.SetSymSect(text, sect)
	if ctxt.IsAIX() && ctxt.IsExternal() {
		// Setting runtime.text has a real symbol prevents ld to
		// change its base address resulting in wrong offsets for
		// reflect methods.
		u := ldr.MakeSymbolUpdater(text)
		u.SetAlign(sect.Align)
		u.SetSize(8)
	}

	if (ctxt.DynlinkingGo() && ctxt.IsDarwin()) || (ctxt.IsAIX() && ctxt.IsExternal()) {
		ldr.SetSymSect(etext, sect)
		ctxt.Textp = append(ctxt.Textp, etext, 0)
		copy(ctxt.Textp[1:], ctxt.Textp)
		ctxt.Textp[0] = text
	}

	start := uint64(Rnd(*FlagTextAddr, int64(Funcalign)))
	va := start
	n := 1
	sect.Vaddr = va

	limit := thearch.TrampLimit
	if limit == 0 {
		limit = 1 << 63 // unlimited
	}
	if *FlagDebugTextSize != 0 {
		limit = uint64(*FlagDebugTextSize)
	}
	if *FlagDebugTramp > 1 {
		limit = 1 // debug mode, force generating trampolines for everything
	}

	if ctxt.IsAIX() && ctxt.IsExternal() {
		// On AIX, normally we won't generate direct calls to external symbols,
		// except in one test, cmd/go/testdata/script/link_syso_issue33139.txt.
		// That test doesn't make much sense, and I'm not sure it ever works.
		// Just generate trampoline for now (which will turn a direct call to
		// an indirect call, which at least builds).
		limit = 1
	}

	// First pass: assign addresses assuming the program is small and will
	// not require trampoline generation.
	big := false
	for _, s := range ctxt.Textp {
		sect, n, va = assignAddress(ctxt, sect, n, s, va, false, big)
		if va-start >= limit {
			big = true
			break
		}
	}

	// Second pass: only if it is too big, insert trampolines for too-far
	// jumps and targets with unknown addresses.
	if big {
		// reset addresses
		for _, s := range ctxt.Textp {
			if s != text {
				resetAddress(ctxt, s)
			}
		}
		va = start

		ntramps := 0
		var curPkg string
		for i, s := range ctxt.Textp {
			// When we find the first symbol in a package, perform a
			// single iteration that assigns temporary addresses to all
			// of the text in the same package, using the maximum possible
			// number of trampolines. This allows for better decisions to
			// be made regarding reachability and the need for trampolines.
			if symPkg := ldr.SymPkg(s); symPkg != "" && curPkg != symPkg {
				curPkg = symPkg
				vaTmp := va
				for j := i; j < len(ctxt.Textp); j++ {
					curSym := ctxt.Textp[j]
					if symPkg := ldr.SymPkg(curSym); symPkg == "" || curPkg != symPkg {
						break
					}
					// We do not pass big to assignAddress here, as this
					// can result in side effects such as section splitting.
					sect, n, vaTmp = assignAddress(ctxt, sect, n, curSym, vaTmp, false, false)
					vaTmp += maxSizeTrampolines(ctxt, ldr, curSym, false)
				}
			}

			// Reset address for current symbol.
			if s != text {
				resetAddress(ctxt, s)
			}

			// Assign actual address for current symbol.
			sect, n, va = assignAddress(ctxt, sect, n, s, va, false, big)

			// Resolve jumps, adding trampolines if they are needed.
			trampoline(ctxt, s)

			// lay down trampolines after each function
			for ; ntramps < len(ctxt.tramps); ntramps++ {
				tramp := ctxt.tramps[ntramps]
				if ctxt.IsAIX() && strings.HasPrefix(ldr.SymName(tramp), "runtime.text.") {
					// Already set in assignAddress
					continue
				}
				sect, n, va = assignAddress(ctxt, sect, n, tramp, va, true, big)
			}
		}

		// merge tramps into Textp, keeping Textp in address order
		if ntramps != 0 {
			newtextp := make([]loader.Sym, 0, len(ctxt.Textp)+ntramps)
			i := 0
			for _, s := range ctxt.Textp {
				for ; i < ntramps && ldr.SymValue(ctxt.tramps[i]) < ldr.SymValue(s); i++ {
					newtextp = append(newtextp, ctxt.tramps[i])
				}
				newtextp = append(newtextp, s)
			}
			newtextp = append(newtextp, ctxt.tramps[i:ntramps]...)

			ctxt.Textp = newtextp
		}
	}

	// Add MinLC size after etext, so it won't collide with the next symbol
	// (which may confuse some symbolizer).
	sect.Length = va - sect.Vaddr + uint64(ctxt.Arch.MinLC)
	ldr.SetSymSect(etext, sect)
	if ldr.SymValue(etext) == 0 {
		// Set the address of the start/end symbols, if not already
		// (i.e. not darwin+dynlink or AIX+external, see above).
		ldr.SetSymValue(etext, int64(va))
		ldr.SetSymValue(text, int64(Segtext.Sections[0].Vaddr))
	}
}

// assigns address for a text symbol, returns (possibly new) section, its number, and the address.
func assignAddress(ctxt *Link, sect *sym.Section, n int, s loader.Sym, va uint64, isTramp, big bool) (*sym.Section, int, uint64) {
	ldr := ctxt.loader
	if thearch.AssignAddress != nil {
		return thearch.AssignAddress(ldr, sect, n, s, va, isTramp)
	}

	ldr.SetSymSect(s, sect)
	if ldr.AttrSubSymbol(s) {
		return sect, n, va
	}

	align := ldr.SymAlign(s)
	if align == 0 {
		align = int32(Funcalign)
	}
	va = uint64(Rnd(int64(va), int64(align)))
	if sect.Align < align {
		sect.Align = align
	}

	funcsize := uint64(abi.MINFUNC) // spacing required for findfunctab
	if ldr.SymSize(s) > abi.MINFUNC {
		funcsize = uint64(ldr.SymSize(s))
	}

	// If we need to split text sections, and this function doesn't fit in the current
	// section, then create a new one.
	//
	// Only break at outermost syms.
	if big && splitTextSections(ctxt) && ldr.OuterSym(s) == 0 {
		// For debugging purposes, allow text size limit to be cranked down,
		// so as to stress test the code that handles multiple text sections.
		var textSizelimit uint64 = thearch.TrampLimit
		if *FlagDebugTextSize != 0 {
			textSizelimit = uint64(*FlagDebugTextSize)
		}

		// Sanity check: make sure the limit is larger than any
		// individual text symbol.
		if funcsize > textSizelimit {
			panic(fmt.Sprintf("error: text size limit %d less than text symbol %s size of %d", textSizelimit, ldr.SymName(s), funcsize))
		}

		if va-sect.Vaddr+funcsize+maxSizeTrampolines(ctxt, ldr, s, isTramp) > textSizelimit {
			sectAlign := int32(thearch.Funcalign)
			if ctxt.IsPPC64() {
				// Align the next text section to the worst case function alignment likely
				// to be encountered when processing function symbols. The start address
				// is rounded against the final alignment of the text section later on in
				// (*Link).address. This may happen due to usage of PCALIGN directives
				// larger than Funcalign, or usage of ISA 3.1 prefixed instructions
				// (see ISA 3.1 Book I 1.9).
				const ppc64maxFuncalign = 64
				sectAlign = ppc64maxFuncalign
				va = uint64(Rnd(int64(va), ppc64maxFuncalign))
			}

			// Set the length for the previous text section
			sect.Length = va - sect.Vaddr

			// Create new section, set the starting Vaddr
			sect = addsection(ctxt.loader, ctxt.Arch, &Segtext, ".text", 05)

			sect.Vaddr = va
			sect.Align = sectAlign
			ldr.SetSymSect(s, sect)

			// Create a symbol for the start of the secondary text sections
			ntext := ldr.CreateSymForUpdate(fmt.Sprintf("runtime.text.%d", n), 0)
			ntext.SetSect(sect)
			if ctxt.IsAIX() {
				// runtime.text.X must be a real symbol on AIX.
				// Assign its address directly in order to be the
				// first symbol of this new section.
				ntext.SetType(sym.STEXT)
				ntext.SetSize(int64(abi.MINFUNC))
				ntext.SetOnList(true)
				ntext.SetAlign(sectAlign)
				ctxt.tramps = append(ctxt.tramps, ntext.Sym())

				ntext.SetValue(int64(va))
				va += uint64(ntext.Size())

				if align := ldr.SymAlign(s); align != 0 {
					va = uint64(Rnd(int64(va), int64(align)))
				} else {
					va = uint64(Rnd(int64(va), int64(Funcalign)))
				}
			}
			n++
		}
	}

	ldr.SetSymValue(s, 0)
	for sub := s; sub != 0; sub = ldr.SubSym(sub) {
		ldr.SetSymValue(sub, ldr.SymValue(sub)+int64(va))
		if ctxt.Debugvlog > 2 {
			fmt.Println("assign text address:", ldr.SymName(sub), ldr.SymValue(sub))
		}
	}

	va += funcsize

	return sect, n, va
}

func resetAddress(ctxt *Link, s loader.Sym) {
	ldr := ctxt.loader
	if ldr.OuterSym(s) != 0 {
		return
	}
	oldv := ldr.SymValue(s)
	for sub := s; sub != 0; sub = ldr.SubSym(sub) {
		ldr.SetSymValue(sub, ldr.SymValue(sub)-oldv)
	}
}

// Return whether we may need to split text sections.
//
// On PPC64x, when external linking, a text section should not be
// larger than 2^25 bytes due to the size of call target offset field
// in the 'bl' instruction. Splitting into smaller text sections
// smaller than this limit allows the system linker to modify the long
// calls appropriately. The limit allows for the space needed for
// tables inserted by the linker.
//
// The same applies to Darwin/ARM64, with 2^27 byte threshold.
//
// Similarly for ARM, we split sections (at 2^25 bytes) to avoid
// inconsistencies between the Go linker's reachability calculations
// (e.g. will direct call from X to Y need a trampoline) and similar
// machinery in the external linker; see #58425 for more on the
// history here.
func splitTextSections(ctxt *Link) bool {
	return (ctxt.IsARM() || ctxt.IsPPC64() || (ctxt.IsARM64() && ctxt.IsDarwin())) && ctxt.IsExternal()
}

// On Wasm, we reserve 4096 bytes for zero page, then 8192 bytes for wasm_exec.js
// to store command line args and environment variables.
// Data sections starts from at least address 12288.
// Keep in sync with wasm_exec.js.
const wasmMinDataAddr = 4096 + 8192

// address assigns virtual addresses to all segments and sections and
// returns all segments in file order.
func (ctxt *Link) address() []*sym.Segment {
	var order []*sym.Segment // Layout order

	va := uint64(*FlagTextAddr)
	order = append(order, &Segtext)
	Segtext.Rwx = 05
	Segtext.Vaddr = va
	for i, s := range Segtext.Sections {
		va = uint64(Rnd(int64(va), int64(s.Align)))
		s.Vaddr = va
		va += s.Length

		if ctxt.IsWasm() && i == 0 && va < wasmMinDataAddr {
			va = wasmMinDataAddr
		}
	}

	Segtext.Length = va - uint64(*FlagTextAddr)

	if len(Segrodata.Sections) > 0 {
		// align to page boundary so as not to mix
		// rodata and executable text.
		//
		// Note: gold or GNU ld will reduce the size of the executable
		// file by arranging for the relro segment to end at a page
		// boundary, and overlap the end of the text segment with the
		// start of the relro segment in the file.  The PT_LOAD segments
		// will be such that the last page of the text segment will be
		// mapped twice, once r-x and once starting out rw- and, after
		// relocation processing, changed to r--.
		//
		// Ideally the last page of the text segment would not be
		// writable even for this short period.
		va = uint64(Rnd(int64(va), *FlagRound))

		order = append(order, &Segrodata)
		Segrodata.Rwx = 04
		Segrodata.Vaddr = va
		for _, s := range Segrodata.Sections {
			va = uint64(Rnd(int64(va), int64(s.Align)))
			s.Vaddr = va
			va += s.Length
		}

		Segrodata.Length = va - Segrodata.Vaddr
	}
	if len(Segrelrodata.Sections) > 0 {
		// align to page boundary so as not to mix
		// rodata, rel-ro data, and executable text.
		va = uint64(Rnd(int64(va), *FlagRound))
		if ctxt.HeadType == objabi.Haix {
			// Relro data are inside data segment on AIX.
			va += uint64(XCOFFDATABASE) - uint64(XCOFFTEXTBASE)
		}

		order = append(order, &Segrelrodata)
		Segrelrodata.Rwx = 06
		Segrelrodata.Vaddr = va
		for _, s := range Segrelrodata.Sections {
			va = uint64(Rnd(int64(va), int64(s.Align)))
			s.Vaddr = va
			va += s.Length
		}

		Segrelrodata.Length = va - Segrelrodata.Vaddr
	}

	va = uint64(Rnd(int64(va), *FlagRound))
	if ctxt.HeadType == objabi.Haix && len(Segrelrodata.Sections) == 0 {
		// Data sections are moved to an unreachable segment
		// to ensure that they are position-independent.
		// Already done if relro sections exist.
		va += uint64(XCOFFDATABASE) - uint64(XCOFFTEXTBASE)
	}
	order = append(order, &Segdata)
	Segdata.Rwx = 06
	Segdata.Vaddr = va
	var data *sym.Section
	var noptr *sym.Section
	var bss *sym.Section
	var noptrbss *sym.Section
	var fuzzCounters *sym.Section
	for i, s := range Segdata.Sections {
		if (ctxt.IsELF || ctxt.HeadType == objabi.Haix) && s.Name == ".tbss" {
			continue
		}
		vlen := int64(s.Length)
		if i+1 < len(Segdata.Sections) && !((ctxt.IsELF || ctxt.HeadType == objabi.Haix) && Segdata.Sections[i+1].Name == ".tbss") {
			vlen = int64(Segdata.Sections[i+1].Vaddr - s.Vaddr)
		}
		s.Vaddr = va
		va += uint64(vlen)
		Segdata.Length = va - Segdata.Vaddr
		switch s.Name {
		case ".data":
			data = s
		case ".noptrdata":
			noptr = s
		case ".bss":
			bss = s
		case ".noptrbss":
			noptrbss = s
		case ".go.fuzzcntrs":
			fuzzCounters = s
		}
	}

	// Assign Segdata's Filelen omitting the BSS. We do this here
	// simply because right now we know where the BSS starts.
	Segdata.Filelen = bss.Vaddr - Segdata.Vaddr

	if len(Segpdata.Sections) > 0 {
		va = uint64(Rnd(int64(va), *FlagRound))
		order = append(order, &Segpdata)
		Segpdata.Rwx = 04
		Segpdata.Vaddr = va
		// Segpdata.Sections is intended to contain just one section.
		// Loop through the slice anyway for consistency.
		for _, s := range Segpdata.Sections {
			va = uint64(Rnd(int64(va), int64(s.Align)))
			s.Vaddr = va
			va += s.Length
		}
		Segpdata.Length = va - Segpdata.Vaddr
	}

	if len(Segxdata.Sections) > 0 {
		va = uint64(Rnd(int64(va), *FlagRound))
		order = append(order, &Segxdata)
		Segxdata.Rwx = 04
		Segxdata.Vaddr = va
		// Segxdata.Sections is intended to contain just one section.
		// Loop through the slice anyway for consistency.
		for _, s := range Segxdata.Sections {
			va = uint64(Rnd(int64(va), int64(s.Align)))
			s.Vaddr = va
			va += s.Length
		}
		Segxdata.Length = va - Segxdata.Vaddr
	}

	va = uint64(Rnd(int64(va), *FlagRound))
	order = append(order, &Segdwarf)
	Segdwarf.Rwx = 06
	Segdwarf.Vaddr = va
	for i, s := range Segdwarf.Sections {
		vlen := int64(s.Length)
		if i+1 < len(Segdwarf.Sections) {
			vlen = int64(Segdwarf.Sections[i+1].Vaddr - s.Vaddr)
		}
		s.Vaddr = va
		va += uint64(vlen)
		if ctxt.HeadType == objabi.Hwindows {
			va = uint64(Rnd(int64(va), PEFILEALIGN))
		}
		Segdwarf.Length = va - Segdwarf.Vaddr
	}

	ldr := ctxt.loader
	var (
		rodata  = ldr.SymSect(ldr.LookupOrCreateSym("runtime.rodata", 0))
		symtab  = ldr.SymSect(ldr.LookupOrCreateSym("runtime.symtab", 0))
		pclntab = ldr.SymSect(ldr.LookupOrCreateSym("runtime.pclntab", 0))
		types   = ldr.SymSect(ldr.LookupOrCreateSym("runtime.types", 0))
	)

	for _, s := range ctxt.datap {
		if sect := ldr.SymSect(s); sect != nil {
			ldr.AddToSymValue(s, int64(sect.Vaddr))
		}
		v := ldr.SymValue(s)
		for sub := ldr.SubSym(s); sub != 0; sub = ldr.SubSym(sub) {
			ldr.AddToSymValue(sub, v)
		}
	}

	for _, si := range dwarfp {
		for _, s := range si.syms {
			if sect := ldr.SymSect(s); sect != nil {
				ldr.AddToSymValue(s, int64(sect.Vaddr))
			}
			sub := ldr.SubSym(s)
			if sub != 0 {
				panic(fmt.Sprintf("unexpected sub-sym for %s %s", ldr.SymName(s), ldr.SymType(s).String()))
			}
			v := ldr.SymValue(s)
			for ; sub != 0; sub = ldr.SubSym(sub) {
				ldr.AddToSymValue(s, v)
			}
		}
	}

	for _, s := range sehp.pdata {
		if sect := ldr.SymSect(s); sect != nil {
			ldr.AddToSymValue(s, int64(sect.Vaddr))
		}
	}
	for _, s := range sehp.xdata {
		if sect := ldr.SymSect(s); sect != nil {
			ldr.AddToSymValue(s, int64(sect.Vaddr))
		}
	}

	if ctxt.BuildMode == BuildModeShared {
		s := ldr.LookupOrCreateSym("go:link.abihashbytes", 0)
		sect := ldr.SymSect(ldr.LookupOrCreateSym(".note.go.abihash", 0))
		ldr.SetSymSect(s, sect)
		ldr.SetSymValue(s, int64(sect.Vaddr+16))
	}

	// If there are multiple text sections, create runtime.text.n for
	// their section Vaddr, using n for index
	n := 1
	for _, sect := range Segtext.Sections[1:] {
		if sect.Name != ".text" {
			break
		}
		symname := fmt.Sprintf("runtime.text.%d", n)
		
"""




```