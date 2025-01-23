Response:
Let's break down the thought process for analyzing this Go code snippet related to DWARF generation.

**1. Initial Scan and Keyword Spotting:**

The first step is to quickly read through the code, looking for significant keywords and function names. Terms like "dwarf," "debug," "sym," "section," "unit," "DIE," "abbrev," "line," "loc," "ranges," "frame," "compress," and the names of DWARF sections (`.debug_info`, `.debug_line`, etc.) immediately stand out. This strongly suggests the code is responsible for generating DWARF debugging information.

**2. Function-Level Understanding:**

Next, I'd examine the purpose of each top-level function:

* `dwarfGenerateDebugInfo2`: This function iterates through symbols, looks for Go type information (`SymGoType`), and then seems to associate these types with DWARF information (`GetVarDwarfAuxSym`, `SymUnit`). It also calls `synthesize...types`. This points to linking Go types to DWARF entries.

* `dwarfGenerateDebugSyms`: This function seems to orchestrate the generation of various DWARF sections (`debug_line`, `debug_frame`, `debug_loc`). It initializes a `dwctxt`, calls `dwarfGenerateDebugSyms` (itself, a bit confusing initially), and then has logic involving `dwUnitPortion` and goroutines. This suggests a more complex process of generating the actual DWARF data.

* `dwUnitPortion`: This function takes a `CompilationUnit` and seems to generate specific parts of the DWARF information (`writelines`, `writepcranges`, `writeUnitInfo`). It's clearly handling a single compilation unit's DWARF data.

* `dwarfGenerateDebugSyms` (the method on `dwctxt`): This is the core logic for generating the DWARF sections. It creates symbols for the sections, uses goroutines for parallel processing, and combines the results.

* `collectUnitLocs`: This function specifically gathers location list symbols (`SDWARFLOC`) associated with functions in a compilation unit.

* `dwarfaddshstrings`: This function adds the names of the DWARF sections to the string table of the output file.

* `dwarfaddelfsectionsyms`: This function seems specific to ELF files and adds symbols for the DWARF sections to the ELF section header.

* `dwarfcompress`: This function deals with compressing the DWARF sections to reduce the output file size.

* `compilationUnitByStartPCCmp`: This is a comparison function, likely used for sorting compilation units.

* `getPkgFromCUSym`, `getDwsectCUSize`, `addDwsectCUSize`: These seem to handle package information related to compilation units, possibly for specific operating systems or file formats.

**3. Identifying Key Structures and Concepts:**

As I go through the functions, I identify important data structures and concepts:

* `dwctxt`: This appears to be a central context struct for DWARF generation.
* `dwUnitSyms`: This struct holds input and output symbols for a compilation unit's DWARF generation.
* `CompilationUnit`:  Represents a compilation unit and holds information needed for DWARF generation.
* `dwarfSecInfo`:  Likely holds information about a DWARF section (like the symbols it contains).
* The various `.debug_*` section names.
* The use of goroutines and wait groups for parallelism.

**4. Inferring Functionality and Go Features:**

Based on the keywords and function names, I start to infer the high-level functionality: generating DWARF debugging information for Go programs. I also notice the use of:

* **Reflection:** The code interacts with Go types (e.g., `d.ldr.SymGoType`).
* **Concurrency:** The use of `sync.WaitGroup` and goroutines in `dwarfGenerateDebugSyms` indicates parallel processing for generating DWARF information.
* **File Format Specifics:** The presence of `dwarfaddelfsectionsyms` and the conditional logic in `dwarfcompress` suggest handling of different executable formats (ELF, Windows, Darwin).

**5. Focusing on Specific Function Blocks for Deeper Understanding:**

I then zoom in on specific blocks, like the loop in `dwarfGenerateDebugInfo2` that handles symbols. I observe how it skips file-local symbols and then tries to find associated DWARF information (`GetVarDwarfAuxSym`). This suggests it's linking global variables and types to their DWARF representations. The `synthesize...types` calls indicate the creation of DWARF entries for built-in Go types.

In `dwarfGenerateDebugSyms`, I notice the clear division of labor:  `dwUnitPortion` handles individual units, and goroutines process these units concurrently. The creation of anonymous symbols (`mkAnonSym`) for intermediate stages is also a detail worth noting.

**6. Code Reasoning and Hypothetical Scenarios:**

To understand the code more deeply, I might think of hypothetical scenarios. For example:

* *Input:* A Go program with global variables and function definitions.
* *Expected Output:* Corresponding DWARF entries in the `.debug_info` section describing these variables and functions. The `.debug_line` section would map code addresses to source code lines.

For the dictionary handling in `dwarfGenerateDebugInfo2`, I'd consider:

* *Input:* A global variable of a map type.
* *Reasoning:* The code checks for `IsDict` and then iterates through relocations, looking for `R_USEIFACE`. This strongly suggests the dictionary's type information needs to be reachable for debugging.
* *Hypothetical Output:* DWARF entries describing the map's key and value types.

**7. Identifying Potential Pitfalls:**

The code itself doesn't explicitly highlight user errors. However, I can infer some potential issues based on my understanding of DWARF and linking:

* **Compiler Options:** The comment about compiler options impacting the presence of DWARF information is important. If a user compiles with `-dwarf=0`, the DWARF generation code will likely be skipped or produce minimal output.
* **Concurrency Issues (Internal):**  Although not a user error, the code uses concurrency, which can introduce subtle bugs if not handled correctly. The `sync.Mutex` in `dwctxt` hints at protecting shared resources.

**8. Synthesizing the Summary:**

Finally, I combine my observations and inferences to produce a concise summary of the code's functionality. I focus on the main purpose (DWARF generation), the key sections involved, the use of concurrency, and any specific features like compression.

This iterative process of scanning, understanding functions, identifying key concepts, inferring functionality, and reasoning through the code allows for a comprehensive analysis of the given Go snippet. The level of detail in each step depends on the complexity of the code and the desired level of understanding.
Based on the provided Go code snippet from `go/src/cmd/link/internal/ld/dwarf.go`, specifically the `dwarfGenerateDebugInfo2` and `dwarfGenerateDebugSyms` functions and related helper functions, here's a breakdown of its functionality:

**Overall Function:**

This code is responsible for generating DWARF (Debugging With Arbitrary Record Format) debugging information for Go binaries during the linking process. DWARF is a standard format used by debuggers (like GDB or Delve) to understand the structure and state of a program, including variables, types, and the mapping between code and source files.

**Detailed Functionality:**

**Part 1: `dwarfGenerateDebugInfo2(ctxt *Link)`**

This function primarily focuses on gathering and associating Go type information with DWARF entries. It iterates through the symbols in the program and performs the following:

* **Identifying Go Types:** It checks if a symbol has an associated Go type using `d.ldr.SymGoType(idx)`.
* **Handling Dictionaries:**  If a symbol is in the `.rodata` section and is identified as a dictionary (`d.ldr.IsDict(idx)`), it ensures that the types referenced by this dictionary are also included in the DWARF information. This is done by iterating through the dictionary's relocations and calling `d.defgotype` for any `objabi.R_USEIFACE` relocations (which indicate interface usage, often related to dictionary key/value types).
* **Skipping File-Local Symbols:** It ignores symbols that are file-local (e.g., static temporaries, stack objects, local assembler symbols).
* **Linking Symbols to DWARF Information:** For global symbols with associated Go types, it attempts to find the corresponding compiler-generated DWARF information symbol using `d.ldr.GetVarDwarfAuxSym(idx)`.
* **Attaching DWARF Information to Units:** If a DWARF information symbol is found, it's appended to the appropriate compilation unit's (`d.ldr.SymUnit(idx)`) list of variable DIEs (`unit.VarDIEs`). This links the Go symbol to its DWARF representation within a specific compilation unit.
* **Synthesizing Type Information:** It calls functions like `synthesizestringtypes`, `synthesizeslicetypes`, `synthesizemaptypes`, and `synthesizechantypes` to create DWARF entries for built-in Go types (string, slice, map, channel) if they are used in the program. These functions likely create DWARF "type unit" entries that describe the structure of these common types.

**Part 2: `dwarfGenerateDebugSyms(ctxt *Link)`**

This function is responsible for constructing the actual DWARF sections (`.debug_line`, `.debug_frame`, `.debug_loc`, `.debug_info`, `.debug_ranges`, `.debug_abbrev`).

* **Initialization:** It checks if DWARF generation is enabled (`dwarfEnabled(ctxt)`). If so, it initializes a `dwctxt` structure, which holds context information for DWARF generation.
* **Writing Abbreviation Section:** It calls `d.writeabbrev()` to create the `.debug_abbrev` section, which contains abbreviations for common DWARF entry structures, saving space in the other sections.
* **Calculating Compilation Unit Ranges:** It calls `d.calcCompUnitRanges()` to determine the address ranges covered by each compilation unit.
* **Reversing DIE Trees:** It reverses the order of children in the DWARF information trees (`DWInfo.Child`) for each compilation unit and for the type information. This ensures the correct ordering of DWARF entries.
* **Creating Section Symbols:** It creates symbols for each DWARF section (e.g., `.debug_frame`, `.debug_loc`, etc.) and sets their type to `sym.SDWARFSECT`.
* **Creating Section Objects:** It initializes `dwarfSecInfo` structures for each section, holding the section's symbol.
* **Parallel Processing:** It uses goroutines and a `sync.WaitGroup` to generate the DWARF information concurrently for each compilation unit.
    * A separate goroutine is launched for `.debug_frame` generation as it has no dependencies.
    * For each compilation unit, a goroutine calls `d.dwUnitPortion` to generate the unit's portion of `.debug_line`, `.debug_loc`, `.debug_ranges`, and `.debug_info`.
* **`dwUnitPortion(u *sym.CompilationUnit, abbrevsym loader.Sym, us *dwUnitSyms)`:** This method handles the DWARF content generation for a single compilation unit:
    * It calls `d.writelines` to generate the `.debug_line` information (mapping code addresses to source lines).
    * It calls `d.writepcranges` to generate the `.debug_ranges` information (specifying the address ranges where certain DWARF entries are valid).
    * It calls `d.collectUnitLocs` to gather location lists for the unit.
    * It calls `d.writeUnitInfo` to generate the `.debug_info` for the compilation unit.
* **Stitching Together Results:** After the goroutines complete, it gathers the generated symbols for each section from the `unitSyms` array and appends them to the corresponding `dwarfSecInfo` structures.
* **Marking Symbols Reachable:** It marks the symbols in the DWARF sections as reachable.
* **Appending Sections:** It appends the `dwarfSecInfo` structures to the `dwarfp` slice, which likely represents the ordered list of DWARF sections to be included in the output binary.
* **Writing GDB Script Section:** It calls `d.writegdbscript()` to generate a `.debug_gdb_scripts` section if needed.
* **Duplicate Symbol Check:** It checks for duplicate symbols within the `.debug_info` section to ensure data integrity.

**Helper Functions:**

* **`collectUnitLocs(u *sym.CompilationUnit)`:** This function gathers symbols of type `sym.SDWARFLOC` which represent location lists used in DWARF to describe where variables are stored.

**In summary, this part of the Go linker is responsible for:**

1. **Identifying and processing Go types and symbols.**
2. **Creating the necessary DWARF sections.**
3. **Populating these sections with information about the program's structure, types, variables, and code locations.**
4. **Using concurrency to speed up the DWARF generation process.**

**Illustrative Go Code Example (Conceptual):**

While this code is part of the linker, we can illustrate the *kind* of DWARF information it generates with a simple Go example:

```go
package main

type MyStruct struct {
	Name string
	Age  int
}

var GlobalVar int

func main() {
	localVar := "hello"
	myStruct := MyStruct{"Alice", 30}
	GlobalVar = 10
	println(localVar, myStruct.Name)
}
```

The DWARF information generated for this program would include:

* **`.debug_info`:**
    * A compilation unit entry describing the `main` package.
    * A DIE (Debugging Information Entry) for the `MyStruct` type, describing its members (`Name` of type `string`, `Age` of type `int`).
    * A DIE for the global variable `GlobalVar` of type `int`.
    * A DIE for the `main` function.
    * Within the `main` function's DIE:
        * A DIE for the local variable `localVar` of type `string`.
        * A DIE for the local variable `myStruct` of type `MyStruct`.
* **`.debug_line`:** Mappings between the assembly instructions of the `main` function and the corresponding lines in the `main.go` source file.
* **`.debug_loc`:** Information about where the variables are stored in memory (e.g., register, stack offset, address).

**Hypothetical Input and Output (Conceptual):**

**Input:** The Go compiler output (object files) for the `main.go` program above, containing symbol information and relocation data.

**Processing (within `dwarfGenerateDebugInfo2`):**

* The linker would iterate through symbols, finding symbols for `GlobalVar`, `main.localVar`, `main.myStruct`, and the `MyStruct` type.
* `d.ldr.SymGoType` would identify the Go types associated with these symbols.
* `d.ldr.GetVarDwarfAuxSym` would potentially find compiler-generated DWARF information symbols for `GlobalVar` and the `MyStruct` type.
* The `synthesize...types` functions would create DWARF entries for `string` and `int` if they haven't been created already.
* The information would be attached to the compilation unit for the `main` package.

**Processing (within `dwarfGenerateDebugSyms` and `dwUnitPortion`):**

* `writelines` would generate entries for `.debug_line` based on line number information in the object files.
* `writeUnitInfo` would create the actual DIEs in `.debug_info` for the types, variables, and functions, referencing the abbreviation information from `.debug_abbrev`.
* `collectUnitLocs` would gather information about the memory locations of the variables.

**Output:** The linked executable would contain the DWARF sections populated with the information described above, allowing a debugger to inspect the program's state.

**Command-Line Parameter Handling (Inferred):**

While the snippet doesn't directly show command-line argument parsing, the presence of `*FlagW` suggests a command-line flag (likely `-w`) that disables DWARF generation. The linker likely has other flags related to debugging information level (e.g., controlling the amount of DWARF data generated). These flags would be processed earlier in the linker's execution and would influence the behavior of these DWARF generation functions.

**User Mistakes (Potential):**

* **Compiling without Debug Information:** If a user compiles their Go code with flags that disable debug information (e.g., `-gcflags "-N -l"` for `compile`), the linker won't have the necessary information to generate meaningful DWARF data. Debuggers might still work but will have limited visibility into the program.
* **Stripping Debug Information:** After linking, users might use tools like `strip` to remove the DWARF sections from the executable to reduce its size. This will make debugging the stripped binary much harder.

This detailed breakdown should give you a good understanding of the functionality of this part of the Go linker's DWARF generation implementation.

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/dwarf.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
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