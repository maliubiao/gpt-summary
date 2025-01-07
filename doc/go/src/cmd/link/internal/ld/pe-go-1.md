Response:
My goal is to analyze the provided Go code snippet and explain its functionality within the context of the Go linker, specifically for generating PE (Portable Executable) files. Since this is the second part of the code, I need to summarize the functionality of *this specific part*, assuming the first part laid some groundwork.

Here's a breakdown of the thought process:

1. **Identify the Core Theme:** Scanning the function names like `initdynimport`, `addimports`, `initdynexport`, `addexports`, `addPEBaseReloc`, `addpersrc`, and `asmbPe` strongly suggests this code deals with the various sections and data structures within a PE file. It manages imports, exports, relocations, resources, and the overall assembly of the PE structure.

2. **Break Down Function by Function:**

   * **`initdynimport` and `addimports`:** These clearly handle dynamic imports. `initdynimport` seems to scan symbols, identify imported DLLs and functions, and organize them. `addimports` appears to write the import descriptor table, DLL names, function names, and manage the Original First Thunks (OFTs) and First Thunks (FTs). The difference between internal and external linking modes is also apparent here, particularly with how symbol names are handled.

   * **`initdynexport` and `addexports`:** These manage dynamic exports. `initdynexport` identifies exported symbols, and `addexports` constructs the export directory table, including addresses of functions, names, and ordinals.

   * **`addPEBaseReloc`:**  This function deals with base relocations, which are crucial for allowing the OS loader to load the executable at a different address than its preferred base address. It involves identifying relocation entries, grouping them into blocks per page, and writing the relocation table. The `needPEBaseReloc` function determines if this table is even necessary.

   * **`addpersrc`:** This handles resources. It iterates through resource symbols, writes their data to the `.rsrc` section, and updates the resource directory entry. The handling of "split resources" is a noteworthy detail.

   * **`asmbPe`:** This function seems to orchestrate the creation of the core PE sections: `.text` (code), `.rdata` (read-only data), `.data` (initialized data), and `.bss` (uninitialized data). It calls other functions to add imports, exports, relocations, and resources. The difference in how `.data` and `.bss` are handled in internal vs. external linking is important. It also calls functions related to SEH (Structured Exception Handling) and DWARF debugging information (though these aren't defined in the snippet).

3. **Identify Key Concepts:**  The code manipulates core PE concepts:
    * **Sections:** `.text`, `.rdata`, `.data`, `.bss`, `.idata`, `.edata`, `.reloc`, `.rsrc`.
    * **Data Directories:**  Entries like `IMAGE_DIRECTORY_ENTRY_IMPORT`, `IMAGE_DIRECTORY_ENTRY_EXPORT`, `IMAGE_DIRECTORY_ENTRY_BASERELOC`, `IMAGE_DIRECTORY_ENTRY_RESOURCE`, and `IMAGE_DIRECTORY_ENTRY_IAT`.
    * **Import Descriptor Table:**  Describes the imported DLLs and their functions.
    * **Export Directory Table:**  Describes the exported functions.
    * **Base Relocation Table:**  Allows rebasing of the executable.
    * **Resource Section:**  Contains application resources.
    * **Linking Modes:** Internal (`LinkInternal`) and external (`LinkExternal`) affect how certain parts of the PE file are generated.

4. **Consider Linking Modes:**  The code frequently checks `ctxt.LinkMode`. This highlights the difference between creating a fully self-contained executable (internal linking) versus creating an object file or DLL that will be linked with other components (external linking).

5. **Infer Overall Purpose:**  Based on the individual function functionalities and the manipulation of PE structures, the overarching purpose of this code segment is to **assemble the different parts of a PE executable file**. This includes managing dependencies (imports), providing interfaces (exports), ensuring the executable can load at different memory addresses (relocations), embedding resources, and organizing the code and data into appropriate sections.

6. **Formulate the Summary:**  Based on the above analysis, I constructed the summary, emphasizing the key functionalities and the overall goal of assembling the PE file. I highlighted the handling of imports, exports, relocations, resources, and the difference between internal and external linking.

7. **Refine and Organize:** I ensured the summary was concise, used clear language, and followed the requested format (Chinese). I made sure to mention the key data structures and sections being manipulated.

By following this structured approach, I could effectively analyze the code snippet and provide a comprehensive and accurate summary of its functionality within the larger context of the Go linker.
这段代码是 Go 语言链接器（`go link`）在构建 Windows PE（Portable Executable）可执行文件时负责 **组织和写入 PE 文件特定数据结构** 的一部分。 考虑到这是第二部分，我们可以推断第一部分可能已经处理了 PE 文件的基本头部结构和节（section）的定义。

**归纳一下它的功能：**

这段代码主要负责以下关键功能，以完成 PE 文件的构建：

1. **处理动态链接库导入 (Dynamic Imports):**
   - 识别需要从其他 DLL 导入的符号（函数）。
   - 组织导入的 DLL 列表和每个 DLL 中导入的函数。
   - 根据链接模式（内部链接或外部链接）生成不同的数据结构来表示导入信息。
   - 在 `.idata` 节（Import Data Section）中写入导入目录表（Import Directory Table）、DLL 名称表和导入名称表。
   - 在 `.data` 节（Data Section）中分配空间并写入导入地址表（IAT - Import Address Table）。
   - 更新 PE 头部的数据目录，指向 `.idata` 节和 IAT。

2. **处理动态链接库导出 (Dynamic Exports):**
   - 识别需要导出的符号（函数）。
   - 对导出的符号进行排序。
   - 在 `.edata` 节（Export Data Section）中写入导出目录表（Export Directory Table）、导出地址表、导出名称指针表和导出序号表。
   - 更新 PE 头部的数据目录，指向 `.edata` 节。

3. **处理基址重定位 (Base Relocation):**
   - 对于需要进行基址重定位的代码和数据段，识别需要重定位的地址。
   - 将重定位信息组织成按页划分的块。
   - 在 `.reloc` 节（Relocation Section）中写入基址重定位表，以便操作系统加载器可以将程序加载到不同的内存地址。

4. **处理资源 (Resources):**
   - 将 `.rsrc` 节（Resource Section）的数据写入到输出文件中。
   - 处理分割的资源节。
   - 更新 PE 头部的数据目录，指向 `.rsrc` 节。

5. **组装 PE 文件的节 (Assemble PE Sections):**
   - 创建和配置 PE 文件的标准节：`.text` (代码), `.rdata` (只读数据), `.data` (已初始化数据), `.bss` (未初始化数据)。
   - 为每个节设置其特性（如是否可执行、可读写等）。
   - 将节的内存地址和文件偏移与链接器的段（Segment）信息关联起来。
   - 调用其他函数添加 SEH (Structured Exception Handling) 和 DWARF 调试信息（这段代码中未直接展示其实现）。
   - 对于外部链接，添加 `.ctors` 节（构造函数表）。

6. **写入符号表和字符串表 (Write Symbol Table and String Table):**
   - 将链接过程中的符号信息和相关的字符串写入到 PE 文件中，这主要用于调试和其他工具。

7. **写入 PE 文件头 (Write PE Header):**
   - 将之前计算和填充的 PE 文件头、可选头和节头写入到输出文件中。

**功能代码示例 (假设的输入与输出):**

假设我们有一个简单的 Go 程序需要链接成 Windows 可执行文件，并且它引用了一个外部 DLL 中的函数 `MessageBoxW`。

**假设输入：**

- 链接器上下文 `ctxt` 包含了程序的符号信息，包括对 `MessageBoxW` 的动态导入符号。
- `ldr` 是链接器的加载器，包含了符号表的管理。
- 存在一个名为 `user32.dll` 的动态链接库，其中包含 `MessageBoxW` 函数。
- 符号 `s` 代表对 `MessageBoxW` 的动态导入。

**`initdynimport` 函数的执行过程 (部分模拟):**

```go
// ... (在 initdynimport 函数内部)
ldr := ctxt.loader
dynlib := "user32.dll" // 从符号 s 中获取
extName := "MessageBoxW" // 从符号 s 中获取

// 假设 dr 当前为 nil
d := new(Dll)
d.name = dynlib
d.next = dr
dr = d

m := new(Imp)
m.s = s // 关联导入符号
d.ms = m
ldr.SetSymExtname(s, extName)

// ... (函数继续处理其他导入符号)
```

**`addimports` 函数的执行过程 (部分模拟):**

```go
// ... (在 addimports 函数内部)
startoff := ctxt.Out.Offset() // 记录当前文件偏移

// ... (计算导入描述符表的大小)

// 写入 DLL 名称
d := dr
d.nameoff = uint64(ctxt.Out.Offset()) - uint64(startoff)
strput(ctxt.Out, d.name) // 将 "user32.dll" 写入

// 写入函数名称
m := d.ms
m.off = uint64(pefile.nextSectOffset) + uint64(ctxt.Out.Offset()) - uint64(startoff)
ctxt.Out.Write16(0) // hint
strput(ctxt.Out, ldr.SymExtname(m.s)) // 将 "MessageBoxW" 写入

// ... (写入 OriginalFirstThunks)

// ... (分配 .idata 节)

// ... (写入 FirstThunks 到 .data 节)

// 写入导入描述符表
ctxt.Out.SeekSet(startoff)
out := ctxt.Out
out.Write32(uint32(isect.virtualAddress) + oftbase + d.thunkoff) // OriginalFirstThunks
out.Write32(0)
out.Write32(0)
out.Write32(uint32(uint64(isect.virtualAddress) + d.nameoff)) // 指向 "user32.dll" 的偏移
out.Write32(uint32(datsect.virtualAddress) + ftbase + d.thunkoff) // 指向 MessageBoxW 的 IAT 条目的偏移

// ... (更新数据目录)
```

**假设输出：**

在生成的 PE 文件中，将会存在：

- `.idata` 节包含了描述 `user32.dll` 及其导入函数 `MessageBoxW` 的数据结构。
- `.data` 节中分配了用于 `MessageBoxW` 的导入地址表条目的空间。
- PE 头部的数据目录中 `IMAGE_DIRECTORY_ENTRY_IMPORT` 和 `IMAGE_DIRECTORY_ENTRY_IAT` 指向了 `.idata` 节和 IAT 在内存中的位置。

**命令行参数的具体处理：**

这段代码本身主要处理 PE 文件结构的构建，它依赖于链接器在更早的阶段对命令行参数的解析和处理。 命令行参数会影响链接器的行为，进而影响这段代码的执行。 例如：

- `-l` 参数（用于链接库）可能会影响 `initdynimport` 函数识别需要导入的 DLL。
- `-buildmode=...` 参数会影响链接模式 (`ctxt.LinkMode`)，从而改变导入导出和节的生成方式。
- `-o` 参数（指定输出文件名）会影响 `addexports` 函数中导出名称的写入。
- `-H windowsgui` 或 `-H windowsapp` 等参数可能会影响 PE 头的子系统字段，但这段代码片段中没有直接体现。

**使用者易犯错的点：**

这段代码是链接器的内部实现，普通 Go 语言开发者不会直接操作它。 然而，理解其功能有助于理解链接过程和可能遇到的链接错误。 一些可能导致问题的场景（开发者角度）：

- **错误的 `import "C"` 用法：** 如果在 Go 代码中使用 `import "C"` 导入了 C 代码，但没有正确配置 C 代码的编译和链接，可能会导致链接器无法找到所需的符号，从而导致 `initdynimport` 或 `addimports` 阶段出错。
- **CGO 导出符号冲突：** 如果使用 CGO 导出了与标准库或其他库中符号名称冲突的符号，可能会导致 `initdynexport` 或 `addexports` 阶段出错。
- **资源文件问题：** 如果资源文件格式错误或者与代码中的引用不匹配，可能会导致 `addpersrc` 阶段出错。

总的来说，这段代码是 Go 语言链接器中构建 Windows PE 可执行文件的核心部分，它负责将程序的代码、数据、依赖信息和资源组织成操作系统能够加载和执行的格式。

Prompt: 
```
这是路径为go/src/cmd/link/internal/ld/pe.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
olute address is irrelevant.
		PEBASE = 0
	}

	var sh [16]pe.SectionHeader32
	var fh pe.FileHeader
	PEFILEHEADR = int32(Rnd(int64(len(dosstub)+binary.Size(&fh)+l+binary.Size(&sh)), PEFILEALIGN))
	if ctxt.LinkMode != LinkExternal {
		PESECTHEADR = int32(Rnd(int64(PEFILEHEADR), PESECTALIGN))
	} else {
		PESECTHEADR = 0
	}
	pefile.nextSectOffset = uint32(PESECTHEADR)
	pefile.nextFileOffset = uint32(PEFILEHEADR)

	if ctxt.LinkMode == LinkInternal {
		// some mingw libs depend on this symbol, for example, FindPESectionByName
		for _, name := range [2]string{"__image_base__", "_image_base__"} {
			sb := ctxt.loader.CreateSymForUpdate(name, 0)
			sb.SetType(sym.SDATA)
			sb.SetValue(PEBASE)
			ctxt.loader.SetAttrSpecial(sb.Sym(), true)
			ctxt.loader.SetAttrLocal(sb.Sym(), true)
		}
	}

	HEADR = PEFILEHEADR
	if *FlagRound == -1 {
		*FlagRound = PESECTALIGN
	}
	if *FlagTextAddr == -1 {
		*FlagTextAddr = Rnd(PEBASE, *FlagRound) + int64(PESECTHEADR)
	}
}

func pewrite(ctxt *Link) {
	ctxt.Out.SeekSet(0)
	if ctxt.LinkMode != LinkExternal {
		ctxt.Out.Write(dosstub)
		ctxt.Out.WriteStringN("PE", 4)
	}

	pefile.writeFileHeader(ctxt)

	pefile.writeOptionalHeader(ctxt)

	for _, sect := range pefile.sections {
		sect.write(ctxt.Out, ctxt.LinkMode)
	}
}

func strput(out *OutBuf, s string) {
	out.WriteString(s)
	out.Write8(0)
	// string must be padded to even size
	if (len(s)+1)%2 != 0 {
		out.Write8(0)
	}
}

func initdynimport(ctxt *Link) *Dll {
	ldr := ctxt.loader
	var d *Dll

	dr = nil
	var m *Imp
	for s := loader.Sym(1); s < loader.Sym(ldr.NSym()); s++ {
		if !ldr.AttrReachable(s) || ldr.SymType(s) != sym.SDYNIMPORT {
			continue
		}
		dynlib := ldr.SymDynimplib(s)
		for d = dr; d != nil; d = d.next {
			if d.name == dynlib {
				m = new(Imp)
				break
			}
		}

		if d == nil {
			d = new(Dll)
			d.name = dynlib
			d.next = dr
			dr = d
			m = new(Imp)
		}

		// Because external link requires properly stdcall decorated name,
		// all external symbols in runtime use %n to denote that the number
		// of uinptrs this function consumes. Store the argsize and discard
		// the %n suffix if any.
		m.argsize = -1
		extName := ldr.SymExtname(s)
		if i := strings.IndexByte(extName, '%'); i >= 0 {
			var err error
			m.argsize, err = strconv.Atoi(extName[i+1:])
			if err != nil {
				ctxt.Errorf(s, "failed to parse stdcall decoration: %v", err)
			}
			m.argsize *= ctxt.Arch.PtrSize
			ldr.SetSymExtname(s, extName[:i])
		}

		m.s = s
		m.next = d.ms
		d.ms = m
	}

	if ctxt.IsExternal() {
		// Add real symbol name
		for d := dr; d != nil; d = d.next {
			for m = d.ms; m != nil; m = m.next {
				sb := ldr.MakeSymbolUpdater(m.s)
				sb.SetType(sym.SDATA)
				sb.Grow(int64(ctxt.Arch.PtrSize))
				dynName := sb.Extname()
				// only windows/386 requires stdcall decoration
				if ctxt.Is386() && m.argsize >= 0 {
					dynName += fmt.Sprintf("@%d", m.argsize)
				}
				dynSym := ldr.CreateSymForUpdate(dynName, 0)
				dynSym.SetType(sym.SHOSTOBJ)
				r, _ := sb.AddRel(objabi.R_ADDR)
				r.SetSym(dynSym.Sym())
				r.SetSiz(uint8(ctxt.Arch.PtrSize))
			}
		}
	} else {
		dynamic := ldr.CreateSymForUpdate(".windynamic", 0)
		dynamic.SetType(sym.SWINDOWS)
		for d := dr; d != nil; d = d.next {
			for m = d.ms; m != nil; m = m.next {
				sb := ldr.MakeSymbolUpdater(m.s)
				sb.SetType(sym.SWINDOWS)
				sb.SetValue(dynamic.Size())
				dynamic.SetSize(dynamic.Size() + int64(ctxt.Arch.PtrSize))
				dynamic.AddInteriorSym(m.s)
			}

			dynamic.SetSize(dynamic.Size() + int64(ctxt.Arch.PtrSize))
		}
	}

	return dr
}

// peimporteddlls returns the gcc command line argument to link all imported
// DLLs.
func peimporteddlls() []string {
	var dlls []string

	for d := dr; d != nil; d = d.next {
		dlls = append(dlls, "-l"+strings.TrimSuffix(d.name, ".dll"))
	}

	return dlls
}

func addimports(ctxt *Link, datsect *peSection) {
	ldr := ctxt.loader
	startoff := ctxt.Out.Offset()
	dynamic := ldr.LookupOrCreateSym(".windynamic", 0)

	// skip import descriptor table (will write it later)
	n := uint64(0)

	for d := dr; d != nil; d = d.next {
		n++
	}
	ctxt.Out.SeekSet(startoff + int64(binary.Size(&IMAGE_IMPORT_DESCRIPTOR{}))*int64(n+1))

	// write dll names
	for d := dr; d != nil; d = d.next {
		d.nameoff = uint64(ctxt.Out.Offset()) - uint64(startoff)
		strput(ctxt.Out, d.name)
	}

	// write function names
	for d := dr; d != nil; d = d.next {
		for m := d.ms; m != nil; m = m.next {
			m.off = uint64(pefile.nextSectOffset) + uint64(ctxt.Out.Offset()) - uint64(startoff)
			ctxt.Out.Write16(0) // hint
			strput(ctxt.Out, ldr.SymExtname(m.s))
		}
	}

	// write OriginalFirstThunks
	oftbase := uint64(ctxt.Out.Offset()) - uint64(startoff)

	n = uint64(ctxt.Out.Offset())
	for d := dr; d != nil; d = d.next {
		d.thunkoff = uint64(ctxt.Out.Offset()) - n
		for m := d.ms; m != nil; m = m.next {
			if pe64 != 0 {
				ctxt.Out.Write64(m.off)
			} else {
				ctxt.Out.Write32(uint32(m.off))
			}
		}

		if pe64 != 0 {
			ctxt.Out.Write64(0)
		} else {
			ctxt.Out.Write32(0)
		}
	}

	// add pe section and pad it at the end
	n = uint64(ctxt.Out.Offset()) - uint64(startoff)

	isect := pefile.addSection(".idata", int(n), int(n))
	isect.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
	isect.checkOffset(startoff)
	isect.pad(ctxt.Out, uint32(n))
	endoff := ctxt.Out.Offset()

	// write FirstThunks (allocated in .data section)
	ftbase := uint64(ldr.SymValue(dynamic)) - uint64(datsect.virtualAddress) - uint64(PEBASE)

	ctxt.Out.SeekSet(int64(uint64(datsect.pointerToRawData) + ftbase))
	for d := dr; d != nil; d = d.next {
		for m := d.ms; m != nil; m = m.next {
			if pe64 != 0 {
				ctxt.Out.Write64(m.off)
			} else {
				ctxt.Out.Write32(uint32(m.off))
			}
		}

		if pe64 != 0 {
			ctxt.Out.Write64(0)
		} else {
			ctxt.Out.Write32(0)
		}
	}

	// finally write import descriptor table
	out := ctxt.Out
	out.SeekSet(startoff)

	for d := dr; d != nil; d = d.next {
		out.Write32(uint32(uint64(isect.virtualAddress) + oftbase + d.thunkoff))
		out.Write32(0)
		out.Write32(0)
		out.Write32(uint32(uint64(isect.virtualAddress) + d.nameoff))
		out.Write32(uint32(uint64(datsect.virtualAddress) + ftbase + d.thunkoff))
	}

	out.Write32(0) //end
	out.Write32(0)
	out.Write32(0)
	out.Write32(0)
	out.Write32(0)

	// update data directory
	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = isect.virtualAddress
	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].Size = isect.virtualSize
	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = uint32(ldr.SymValue(dynamic) - PEBASE)
	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IAT].Size = uint32(ldr.SymSize(dynamic))

	out.SeekSet(endoff)
}

func initdynexport(ctxt *Link) {
	ldr := ctxt.loader
	for s := loader.Sym(1); s < loader.Sym(ldr.NSym()); s++ {
		if !ldr.AttrReachable(s) || !ldr.AttrCgoExportDynamic(s) {
			continue
		}
		if len(dexport) >= math.MaxUint16 {
			ctxt.Errorf(s, "pe dynexport table is full")
			errorexit()
		}

		dexport = append(dexport, s)
	}

	sort.Slice(dexport, func(i, j int) bool { return ldr.SymExtname(dexport[i]) < ldr.SymExtname(dexport[j]) })
}

func addexports(ctxt *Link) {
	ldr := ctxt.loader
	var e IMAGE_EXPORT_DIRECTORY

	nexport := len(dexport)
	size := binary.Size(&e) + 10*nexport + len(*flagOutfile) + 1
	for _, s := range dexport {
		size += len(ldr.SymExtname(s)) + 1
	}

	if nexport == 0 {
		return
	}

	sect := pefile.addSection(".edata", size, size)
	sect.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
	sect.checkOffset(ctxt.Out.Offset())
	va := int(sect.virtualAddress)
	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = uint32(va)
	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size = sect.virtualSize

	vaName := va + binary.Size(&e) + nexport*4
	vaAddr := va + binary.Size(&e)
	vaNa := va + binary.Size(&e) + nexport*8

	e.Characteristics = 0
	e.MajorVersion = 0
	e.MinorVersion = 0
	e.NumberOfFunctions = uint32(nexport)
	e.NumberOfNames = uint32(nexport)
	e.Name = uint32(va+binary.Size(&e)) + uint32(nexport)*10 // Program names.
	e.Base = 1
	e.AddressOfFunctions = uint32(vaAddr)
	e.AddressOfNames = uint32(vaName)
	e.AddressOfNameOrdinals = uint32(vaNa)

	out := ctxt.Out

	// put IMAGE_EXPORT_DIRECTORY
	binary.Write(out, binary.LittleEndian, &e)

	// put EXPORT Address Table
	for _, s := range dexport {
		out.Write32(uint32(ldr.SymValue(s) - PEBASE))
	}

	// put EXPORT Name Pointer Table
	v := int(e.Name + uint32(len(*flagOutfile)) + 1)

	for _, s := range dexport {
		out.Write32(uint32(v))
		v += len(ldr.SymExtname(s)) + 1
	}

	// put EXPORT Ordinal Table
	for i := 0; i < nexport; i++ {
		out.Write16(uint16(i))
	}

	// put Names
	out.WriteStringN(*flagOutfile, len(*flagOutfile)+1)

	for _, s := range dexport {
		name := ldr.SymExtname(s)
		out.WriteStringN(name, len(name)+1)
	}
	sect.pad(out, uint32(size))
}

// peBaseRelocEntry represents a single relocation entry.
type peBaseRelocEntry struct {
	typeOff uint16
}

// peBaseRelocBlock represents a Base Relocation Block. A block
// is a collection of relocation entries in a page, where each
// entry describes a single relocation.
// The block page RVA (Relative Virtual Address) is the index
// into peBaseRelocTable.blocks.
type peBaseRelocBlock struct {
	entries []peBaseRelocEntry
}

// pePages is a type used to store the list of pages for which there
// are base relocation blocks. This is defined as a type so that
// it can be sorted.
type pePages []uint32

// A PE base relocation table is a list of blocks, where each block
// contains relocation information for a single page. The blocks
// must be emitted in order of page virtual address.
// See https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-reloc-section-image-only
type peBaseRelocTable struct {
	blocks map[uint32]peBaseRelocBlock

	// pePages is a list of keys into blocks map.
	// It is stored separately for ease of sorting.
	pages pePages
}

func (rt *peBaseRelocTable) init(ctxt *Link) {
	rt.blocks = make(map[uint32]peBaseRelocBlock)
}

func (rt *peBaseRelocTable) addentry(ldr *loader.Loader, s loader.Sym, r *loader.Reloc) {
	// pageSize is the size in bytes of a page
	// described by a base relocation block.
	const pageSize = 0x1000
	const pageMask = pageSize - 1

	addr := ldr.SymValue(s) + int64(r.Off()) - int64(PEBASE)
	page := uint32(addr &^ pageMask)
	off := uint32(addr & pageMask)

	b, ok := rt.blocks[page]
	if !ok {
		rt.pages = append(rt.pages, page)
	}

	e := peBaseRelocEntry{
		typeOff: uint16(off & 0xFFF),
	}

	// Set entry type
	switch r.Siz() {
	default:
		Exitf("unsupported relocation size %d\n", r.Siz)
	case 4:
		e.typeOff |= uint16(IMAGE_REL_BASED_HIGHLOW << 12)
	case 8:
		e.typeOff |= uint16(IMAGE_REL_BASED_DIR64 << 12)
	}

	b.entries = append(b.entries, e)
	rt.blocks[page] = b
}

func (rt *peBaseRelocTable) write(ctxt *Link) {
	out := ctxt.Out

	// sort the pages array
	slices.Sort(rt.pages)

	// .reloc section must be 32-bit aligned
	if out.Offset()&3 != 0 {
		Errorf("internal error, start of .reloc not 32-bit aligned")
	}

	for _, p := range rt.pages {
		b := rt.blocks[p]

		// Add a dummy entry at the end of the list if we have an
		// odd number of entries, so as to ensure that the next
		// block starts on a 32-bit boundary (see issue 68260).
		if len(b.entries)&1 != 0 {
			b.entries = append(b.entries, peBaseRelocEntry{})
		}

		const sizeOfPEbaseRelocBlock = 8 // 2 * sizeof(uint32)
		blockSize := uint32(sizeOfPEbaseRelocBlock + len(b.entries)*2)
		out.Write32(p)
		out.Write32(blockSize)

		for _, e := range b.entries {
			out.Write16(e.typeOff)
		}
	}
}

func addPEBaseRelocSym(ldr *loader.Loader, s loader.Sym, rt *peBaseRelocTable) {
	relocs := ldr.Relocs(s)
	for ri := 0; ri < relocs.Count(); ri++ {
		r := relocs.At(ri)
		if r.Type() >= objabi.ElfRelocOffset {
			continue
		}
		if r.Siz() == 0 { // informational relocation
			continue
		}
		if r.Type() == objabi.R_DWARFFILEREF {
			continue
		}
		rs := r.Sym()
		if rs == 0 {
			continue
		}
		if !ldr.AttrReachable(s) {
			continue
		}

		switch r.Type() {
		default:
		case objabi.R_ADDR:
			rt.addentry(ldr, s, &r)
		}
	}
}

func needPEBaseReloc(ctxt *Link) bool {
	// Non-PIE x86 binaries don't need the base relocation table.
	// Everyone else does.
	if (ctxt.Arch.Family == sys.I386 || ctxt.Arch.Family == sys.AMD64) && ctxt.BuildMode != BuildModePIE {
		return false
	}
	return true
}

func addPEBaseReloc(ctxt *Link) {
	if !needPEBaseReloc(ctxt) {
		return
	}

	var rt peBaseRelocTable
	rt.init(ctxt)

	// Get relocation information
	ldr := ctxt.loader
	for _, s := range ctxt.Textp {
		addPEBaseRelocSym(ldr, s, &rt)
	}
	for _, s := range ctxt.datap {
		addPEBaseRelocSym(ldr, s, &rt)
	}

	// Write relocation information
	startoff := ctxt.Out.Offset()
	rt.write(ctxt)
	size := ctxt.Out.Offset() - startoff

	// Add a PE section and pad it at the end
	rsect := pefile.addSection(".reloc", int(size), int(size))
	rsect.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE
	rsect.checkOffset(startoff)
	rsect.pad(ctxt.Out, uint32(size))

	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = rsect.virtualAddress
	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = rsect.virtualSize
}

func (ctxt *Link) dope() {
	initdynimport(ctxt)
	initdynexport(ctxt)
	writeSEH(ctxt)
}

func setpersrc(ctxt *Link, syms []loader.Sym) {
	if len(rsrcsyms) != 0 {
		Errorf("too many .rsrc sections")
	}
	rsrcsyms = syms
}

func addpersrc(ctxt *Link) {
	if len(rsrcsyms) == 0 {
		return
	}

	var size int64
	for _, rsrcsym := range rsrcsyms {
		size += ctxt.loader.SymSize(rsrcsym)
	}
	h := pefile.addSection(".rsrc", int(size), int(size))
	h.characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA
	h.checkOffset(ctxt.Out.Offset())

	for _, rsrcsym := range rsrcsyms {
		// A split resource happens when the actual resource data and its relocations are
		// split across multiple sections, denoted by a $01 or $02 at the end of the .rsrc
		// section name.
		splitResources := strings.Contains(ctxt.loader.SymName(rsrcsym), ".rsrc$")
		relocs := ctxt.loader.Relocs(rsrcsym)
		data := ctxt.loader.Data(rsrcsym)
		for ri := 0; ri < relocs.Count(); ri++ {
			r := relocs.At(ri)
			p := data[r.Off():]
			val := uint32(int64(h.virtualAddress) + r.Add())
			if splitResources {
				// If we're a split resource section, and that section has relocation
				// symbols, then the data that it points to doesn't actually begin at
				// the virtual address listed in this current section, but rather
				// begins at the section immediately after this one. So, in order to
				// calculate the proper virtual address of the data it's pointing to,
				// we have to add the length of this section to the virtual address.
				// This works because .rsrc sections are divided into two (but not more)
				// of these sections.
				val += uint32(len(data))
			}
			binary.LittleEndian.PutUint32(p, val)
		}
		ctxt.Out.Write(data)
	}
	h.pad(ctxt.Out, uint32(size))

	// update data directory
	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = h.virtualAddress
	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = h.virtualSize
}

func asmbPe(ctxt *Link) {
	t := pefile.addSection(".text", int(Segtext.Length), int(Segtext.Length))
	t.characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
	if ctxt.LinkMode == LinkExternal {
		// some data symbols (e.g. masks) end up in the .text section, and they normally
		// expect larger alignment requirement than the default text section alignment.
		t.characteristics |= IMAGE_SCN_ALIGN_32BYTES
	}
	t.checkSegment(&Segtext)
	pefile.textSect = t

	ro := pefile.addSection(".rdata", int(Segrodata.Length), int(Segrodata.Length))
	ro.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
	if ctxt.LinkMode == LinkExternal {
		// some data symbols (e.g. masks) end up in the .rdata section, and they normally
		// expect larger alignment requirement than the default text section alignment.
		ro.characteristics |= IMAGE_SCN_ALIGN_32BYTES
	}
	ro.checkSegment(&Segrodata)
	pefile.rdataSect = ro

	var d *peSection
	if ctxt.LinkMode != LinkExternal {
		d = pefile.addSection(".data", int(Segdata.Length), int(Segdata.Filelen))
		d.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
		d.checkSegment(&Segdata)
		pefile.dataSect = d
	} else {
		d = pefile.addSection(".data", int(Segdata.Filelen), int(Segdata.Filelen))
		d.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_ALIGN_32BYTES
		d.checkSegment(&Segdata)
		pefile.dataSect = d

		b := pefile.addSection(".bss", int(Segdata.Length-Segdata.Filelen), 0)
		b.characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_ALIGN_32BYTES
		b.pointerToRawData = 0
		pefile.bssSect = b
	}

	pefile.addSEH(ctxt)
	pefile.addDWARF()

	if ctxt.LinkMode == LinkExternal {
		pefile.ctorsSect = pefile.addInitArray(ctxt)
	}

	ctxt.Out.SeekSet(int64(pefile.nextFileOffset))
	if ctxt.LinkMode != LinkExternal {
		addimports(ctxt, d)
		addexports(ctxt)
		addPEBaseReloc(ctxt)
	}
	pefile.writeSymbolTableAndStringTable(ctxt)
	addpersrc(ctxt)
	if ctxt.LinkMode == LinkExternal {
		pefile.emitRelocations(ctxt)
	}

	pewrite(ctxt)
}

"""




```