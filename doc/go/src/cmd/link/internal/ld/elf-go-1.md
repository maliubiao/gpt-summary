Response:
My thinking process to analyze the provided Go code snippet and answer the request is as follows:

1. **Understand the Request:** The request asks for the functionality of the given Go code, its role in the larger Go compilation process (if inferrable), code examples, command-line parameter handling, common mistakes, and a summary of its function. It specifically mentions this is "part 2 of 2" implying I should be looking for the latter stages of ELF generation.

2. **Initial Code Scan and Keyword Spotting:**  I'll quickly scan the code for keywords and function names that hint at its purpose. Keywords like `elf`, `section`, `reloc`, `symtab`, `phdr`, `shdr`, `dynamic`, `.text`, `.data`, `.rodata`, `note`, etc., strongly suggest this code is involved in generating ELF (Executable and Linkable Format) files. The presence of `ctxt *Link` as a common argument suggests this is part of the Go linker.

3. **Identify Key Functions and Their Roles:** I'll focus on the major functions and their interactions:
    * `elfrelocsect`:  This function clearly deals with relocations within a section. It iterates through symbols, computes relocations, and uses `thearch.ELF.Reloc1` to write them.
    * `elfEmitReloc`: This function orchestrates the relocation process by calling `elfrelocsect` for different sections (.text, .rodata, .data, dwarf sections). It also calls `sizeExtRelocs`, which suggests calculating the size of relocation data.
    * `addgonote`: This function creates and adds "notes" to the ELF file, which are used for storing metadata. The presence of `ELF_NOTE_GO_NAME` and tags like `ELF_NOTE_GOABIHASH_TAG` hints at Go-specific metadata.
    * `(ctxt *Link).doelf`: This looks like the main function responsible for generating the ELF structure. It handles section header string table creation (`shstrtabAddstring`), creates symbols for various ELF sections (.text, .data, .bss, .symtab, .strtab, .dynamic, etc.), and sets their types. It also handles dynamic linking related sections if `-d` is not specified.
    * `Asmbelfsetup`: This function seems to initialize section headers.
    * `asmbElf`: This function assembles the ELF file. It sets the ELF header (`ElfEhdr`), iterates through segments and sections, calls functions to write different parts of the ELF file (headers, program headers, section headers, data), and handles relocation if needed.
    * `elfadddynsym`: This function adds dynamic symbols to the `.dynsym` table, which is crucial for dynamic linking.

4. **Infer Overall Functionality:** Based on the identified functions, I can infer that this code is responsible for the final stages of generating an ELF file in the Go linker. It handles:
    * Defining and creating various ELF sections.
    * Managing section headers and program headers.
    * Writing section data.
    * Handling relocations.
    * Creating dynamic linking information (if not statically linked).
    * Adding Go-specific notes.

5. **Code Examples and Reasoning:**
    * **Relocations:** I can provide a simplified example of how a relocation might work. Assume a global variable `globalVar` is accessed in a function. The compiler generates a relocation entry so that the linker can patch the address of `globalVar` into the instruction.
    * **Go Notes:** I can illustrate how `addgonote` might be used to store the Go ABI hash or build ID within the ELF file.

6. **Command-Line Parameters:**  The code mentions `-d` (suppresses dynamic loader format), `-S` (strips symbol table), `-w` (strips DWARF debug information), and `--buildid`. I'll describe their impact based on the code.

7. **Common Mistakes:** I'll focus on potential issues like incorrect `-H` flag usage, leading to mismatches between expected and actual ELF structures, and the impact of incorrect `-d` flag usage.

8. **Summary:** I'll summarize the overall function as the part of the Go linker responsible for generating the final ELF binary, including handling sections, headers, relocations, and dynamic linking.

9. **Structure and Language:** I'll structure the answer clearly with headings and use precise technical terminology in Chinese. I will make sure to address all aspects of the request.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this is just about relocations.
* **Correction:** The presence of `doelf`, `asmbElf`, and the extensive handling of sections and headers makes it clear this is about the complete ELF generation process, not just relocations.
* **Initial thought:** Focus heavily on code details.
* **Correction:**  The request asks for functionality and higher-level understanding, so I'll balance code snippets with explanations of the overall purpose.
* **Initial thought:**  Provide very detailed code examples.
* **Correction:**  Simplified examples that illustrate the concepts are more effective for this kind of request. The user is looking for understanding, not a deep dive into every line of code.
* **Consideration:** Should I explain every single ELF section?
* **Decision:** No, I should focus on the important ones that are explicitly mentioned or strongly implied by the code, like `.text`, `.data`, `.rodata`, `.symtab`, `.strtab`, `.dynamic`, and note sections.

By following this structured approach and performing self-correction, I can generate a comprehensive and accurate answer to the request.
这是 `go/src/cmd/link/internal/ld/elf.go` 文件的第二部分，主要负责 ELF 文件的最终组装和写入工作。结合第一部分，我们可以归纳一下它的功能：

**整体功能归纳:**

这部分代码是 Go 链接器在生成 ELF (Executable and Linkable Format) 文件过程中的核心组成部分，负责以下关键任务：

1. **定义和管理 ELF 文件头 (ELF Header):**  设置 ELF 文件的基本属性，如魔数、架构、入口地址、程序头表和节头表的位置和大小等。

2. **创建和管理节头表 (Section Header Table):**
   - 定义各种需要的节 (Section)，例如 `.text` (代码段), `.rodata` (只读数据段), `.data` (可读写数据段), `.bss` (未初始化数据段), `.symtab` (符号表), `.strtab` (字符串表), `.shstrtab` (节头字符串表), `.dynamic` (动态链接信息), `.got` (全局偏移表), `.plt` (过程链接表) 等。
   - 为每个节分配节头 (Section Header)，包含节的名称、类型、标志、地址、偏移、大小、对齐等信息。
   - 管理节头字符串表，用于存储所有节的名称。

3. **处理重定位 (Relocation):**
   - `elfrelocsect` 函数负责处理特定节中的重定位项。它遍历节中的符号，根据需要计算重定位信息，并调用架构特定的 `thearch.ELF.Reloc1` 函数将重定位信息写入输出缓冲区。
   - `elfEmitReloc` 函数统筹所有需要重定位的节，例如 `.text`, `.rodata`, `.data` 以及 DWARF 调试信息相关的节，并调用 `elfrelocsect` 函数进行处理。

4. **添加 Go 特有的 Note 节:**
   - `addgonote` 函数用于向 ELF 文件中添加特定格式的 Note 节，用于存储 Go 语言相关的元数据，例如 Go 的构建信息、ABI 哈希值、依赖包列表等。

5. **处理动态链接 (Dynamic Linking):**
   - 如果链接模式为动态链接 (非 `-d` 选项)，则会创建和管理与动态链接相关的节，例如 `.interp` (解释器路径), `.hash` (符号哈希表), `.dynsym` (动态符号表), `.dynstr` (动态字符串表), `.got`, `.plt`, `.dynamic`, `.rel` 或 `.rela` (重定位表), `.gnu.version` (版本信息), `.gnu.version_r` (版本需求) 等。
   - `elfadddynsym` 函数负责向动态符号表添加符号。
   - 设置程序头表中与动态链接相关的项 (PT_INTERP, PT_DYNAMIC)。

6. **处理程序头表 (Program Header Table):**
   - 根据不同的节和链接模式，创建和填充程序头 (Program Header)，描述程序段 (Segment) 的加载信息，例如 PT_LOAD (可加载段), PT_INTERP (解释器段), PT_DYNAMIC (动态链接信息段), PT_NOTE (Note 段), PT_PHDR (程序头表段), PT_TLS (线程本地存储段) 等。

7. **最终 ELF 文件组装和写入:**
   - `asmbElf` 函数是组装 ELF 文件的核心函数。它按照 ELF 文件的格式，将文件头、程序头表、节头表以及各个节的数据依次写入输出缓冲区。
   - 根据链接模式和目标架构设置 ELF 文件头的各个字段。
   - 调用架构特定的函数 (如 `elfwritehdr`, `elfwritephdrs`, `elfwriteshdrs` 等) 将 ELF 文件头、程序头表和节头表写入输出。
   - 调用其他函数将各个节的数据 (包括代码、数据、重定位信息等) 写入输出。

**代码示例 (推理性):**

假设我们有一个简单的 Go 程序 `main.go`:

```go
package main

import "fmt"

var globalVar int = 10

func main() {
	fmt.Println(globalVar)
}
```

在链接这个程序时，`elfrelocsect` 和 `elfEmitReloc` 可能会处理与访问 `globalVar` 相关的重定位。例如，可能存在一个重定位项，指示在 `main` 函数中访问 `globalVar` 的指令需要被修改，以便在程序加载时指向 `globalVar` 在内存中的实际地址。

**假设输入:**

- `sect`: 代表 `.text` 代码段的 `sym.Section` 结构体。
- `syms`: 包含 `main` 函数符号的 `loader.Sym` 切片。
- `ldr`: `ctxt.loader`，提供符号信息的加载器。

**可能的 `elfrelocsect` 函数执行过程:**

1. 遍历 `syms`，找到 `main` 函数的符号 `s`。
2. 获取 `main` 函数的重定位信息 `relocs := ldr.Relocs(s)`。
3. 遍历 `relocs`，找到访问 `globalVar` 的重定位项 `r`。
4. 调用 `extreloc` 函数 (未在此代码段中) 获取外部符号 `globalVar` 的相关信息 `rr`。
5. 调用 `ElfSymForReloc` 函数获取 `globalVar` 的 ELF 符号。
6. 调用 `thearch.ELF.Reloc1(ctxt, out, ldr, s, rr, ri, offset)`，将重定位信息写入输出缓冲区 `out`。 `offset` 可能表示重定位项在 `.text` 节中的偏移。

**命令行参数处理:**

- **`-d`:**  如果指定了 `-d` 链接器选项，`ctxt.FlagD` 将为 true。这会影响 `(ctxt *Link).doelf` 函数的行为，它会跳过创建与动态链接相关的节 (如 `.interp`, `.hash`, `.got`, `.plt`, `.dynamic` 等)。这表明 `-d` 用于生成静态链接的可执行文件。

- **`-S`:** 如果指定了 `-S` 选项，`FlagS` 将为 true。在 `asmbElf` 函数中，如果 `FlagS` 为 true，则会跳过写入符号表 (`.symtab`)、字符串表 (`.strtab`) 和节头字符串表 (`.shstrtab`) 的数据，从而生成一个被剥离符号的可执行文件。

- **`-w`:** 如果指定了 `-w` 选项，`FlagW` 将为 true。在 `(ctxt *Link).doelf` 函数中，如果 `FlagW` 为 true，则会跳过添加 DWARF 调试信息相关的节头字符串。

- **`--buildid`:**  这个选项用于指定构建 ID。在 `(ctxt *Link).doelf` 函数中，如果指定了 `--buildid`，会将构建 ID 添加到 `.note.go.buildid` 节中。

**使用者易犯错的点 (推理性):**

由于这段代码是 Go 链接器的内部实现，普通 Go 开发者通常不会直接与之交互。但是，在构建过程中，一些配置错误可能会导致链接器生成不正确的 ELF 文件。例如：

- **不正确的 `-H` 目标操作系统标志:** 如果使用了错误的 `-H` 标志，导致链接器选择了错误的 ELF 格式或 ABI，可能会导致程序无法在目标系统上运行。例如，在一个 Linux 系统上使用了 FreeBSD 的 `-H` 标志。

- **错误地使用了 `-d` 选项:**  如果程序依赖于动态链接库，但错误地使用了 `-d` 选项进行静态链接，会导致程序在运行时找不到依赖库而崩溃。

**总结:**

总而言之，这部分 `elf.go` 代码是 Go 链接器生成 ELF 文件的关键部分，它负责定义和管理 ELF 文件的结构，包括文件头、节头表和程序头表，处理代码和数据的重定位，添加 Go 特有的元数据，并处理动态链接的相关信息，最终将所有这些信息组合成一个符合 ELF 格式的可执行文件或共享库。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/elf.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
edup(elfRelType + sect.Name)
		}
	}

	sh.Type = uint32(typ)
	sh.Entsize = uint64(arch.RegSize) * 2
	if typ == elf.SHT_RELA {
		sh.Entsize += uint64(arch.RegSize)
	}
	sh.Link = uint32(elfshname(".symtab").shnum)
	sh.Info = uint32(sect.Elfsect.(*ElfShdr).shnum)
	sh.Off = sect.Reloff
	sh.Size = sect.Rellen
	sh.Addralign = uint64(arch.RegSize)
	return sh
}

func elfrelocsect(ctxt *Link, out *OutBuf, sect *sym.Section, syms []loader.Sym) {
	// If main section is SHT_NOBITS, nothing to relocate.
	// Also nothing to relocate in .shstrtab.
	if sect.Vaddr >= sect.Seg.Vaddr+sect.Seg.Filelen {
		return
	}
	if sect.Name == ".shstrtab" {
		return
	}

	ldr := ctxt.loader
	for i, s := range syms {
		if !ldr.AttrReachable(s) {
			panic("should never happen")
		}
		if uint64(ldr.SymValue(s)) >= sect.Vaddr {
			syms = syms[i:]
			break
		}
	}

	eaddr := sect.Vaddr + sect.Length
	for _, s := range syms {
		if !ldr.AttrReachable(s) {
			continue
		}
		if ldr.SymValue(s) >= int64(eaddr) {
			break
		}

		// Compute external relocations on the go, and pass to
		// ELF.Reloc1 to stream out.
		relocs := ldr.Relocs(s)
		for ri := 0; ri < relocs.Count(); ri++ {
			r := relocs.At(ri)
			rr, ok := extreloc(ctxt, ldr, s, r)
			if !ok {
				continue
			}
			if rr.Xsym == 0 {
				ldr.Errorf(s, "missing xsym in relocation")
				continue
			}
			esr := ElfSymForReloc(ctxt, rr.Xsym)
			if esr == 0 {
				ldr.Errorf(s, "reloc %d (%s) to non-elf symbol %s (outer=%s) %d (%s)", r.Type(), sym.RelocName(ctxt.Arch, r.Type()), ldr.SymName(r.Sym()), ldr.SymName(rr.Xsym), ldr.SymType(r.Sym()), ldr.SymType(r.Sym()).String())
			}
			if !ldr.AttrReachable(rr.Xsym) {
				ldr.Errorf(s, "unreachable reloc %d (%s) target %v", r.Type(), sym.RelocName(ctxt.Arch, r.Type()), ldr.SymName(rr.Xsym))
			}
			if !thearch.ELF.Reloc1(ctxt, out, ldr, s, rr, ri, int64(uint64(ldr.SymValue(s)+int64(r.Off()))-sect.Vaddr)) {
				ldr.Errorf(s, "unsupported obj reloc %d (%s)/%d to %s", r.Type(), sym.RelocName(ctxt.Arch, r.Type()), r.Siz(), ldr.SymName(r.Sym()))
			}
		}
	}

	// sanity check
	if uint64(out.Offset()) != sect.Reloff+sect.Rellen {
		panic(fmt.Sprintf("elfrelocsect: size mismatch %d != %d + %d", out.Offset(), sect.Reloff, sect.Rellen))
	}
}

func elfEmitReloc(ctxt *Link) {
	for ctxt.Out.Offset()&7 != 0 {
		ctxt.Out.Write8(0)
	}

	sizeExtRelocs(ctxt, thearch.ELF.RelocSize)
	relocSect, wg := relocSectFn(ctxt, elfrelocsect)

	for _, sect := range Segtext.Sections {
		if sect.Name == ".text" {
			relocSect(ctxt, sect, ctxt.Textp)
		} else {
			relocSect(ctxt, sect, ctxt.datap)
		}
	}

	for _, sect := range Segrodata.Sections {
		relocSect(ctxt, sect, ctxt.datap)
	}
	for _, sect := range Segrelrodata.Sections {
		relocSect(ctxt, sect, ctxt.datap)
	}
	for _, sect := range Segdata.Sections {
		relocSect(ctxt, sect, ctxt.datap)
	}
	for i := 0; i < len(Segdwarf.Sections); i++ {
		sect := Segdwarf.Sections[i]
		si := dwarfp[i]
		if si.secSym() != loader.Sym(sect.Sym) ||
			ctxt.loader.SymSect(si.secSym()) != sect {
			panic("inconsistency between dwarfp and Segdwarf")
		}
		relocSect(ctxt, sect, si.syms)
	}
	wg.Wait()
}

func addgonote(ctxt *Link, sectionName string, tag uint32, desc []byte) {
	ldr := ctxt.loader
	s := ldr.CreateSymForUpdate(sectionName, 0)
	s.SetType(sym.SELFROSECT)
	// namesz
	s.AddUint32(ctxt.Arch, uint32(len(ELF_NOTE_GO_NAME)))
	// descsz
	s.AddUint32(ctxt.Arch, uint32(len(desc)))
	// tag
	s.AddUint32(ctxt.Arch, tag)
	// name + padding
	s.AddBytes(ELF_NOTE_GO_NAME)
	for len(s.Data())%4 != 0 {
		s.AddUint8(0)
	}
	// desc + padding
	s.AddBytes(desc)
	for len(s.Data())%4 != 0 {
		s.AddUint8(0)
	}
	s.SetSize(int64(len(s.Data())))
	s.SetAlign(4)
}

func (ctxt *Link) doelf() {
	ldr := ctxt.loader

	/* predefine strings we need for section headers */

	addshstr := func(s string) int {
		off := len(elfshstrdat)
		elfshstrdat = append(elfshstrdat, s...)
		elfshstrdat = append(elfshstrdat, 0)
		return off
	}

	shstrtabAddstring := func(s string) {
		off := addshstr(s)
		elfsetstring(ctxt, 0, s, int(off))
	}

	shstrtabAddstring("")
	shstrtabAddstring(".text")
	shstrtabAddstring(".noptrdata")
	shstrtabAddstring(".data")
	shstrtabAddstring(".bss")
	shstrtabAddstring(".noptrbss")
	shstrtabAddstring(".go.fuzzcntrs")
	shstrtabAddstring(".go.buildinfo")
	shstrtabAddstring(".go.fipsinfo")
	if ctxt.IsMIPS() {
		shstrtabAddstring(".MIPS.abiflags")
		shstrtabAddstring(".gnu.attributes")
	}

	// generate .tbss section for dynamic internal linker or external
	// linking, so that various binutils could correctly calculate
	// PT_TLS size. See https://golang.org/issue/5200.
	if !*FlagD || ctxt.IsExternal() {
		shstrtabAddstring(".tbss")
	}
	if ctxt.IsNetbsd() {
		shstrtabAddstring(".note.netbsd.ident")
		if *flagRace {
			shstrtabAddstring(".note.netbsd.pax")
		}
	}
	if ctxt.IsOpenbsd() {
		shstrtabAddstring(".note.openbsd.ident")
	}
	if ctxt.IsFreebsd() {
		shstrtabAddstring(".note.tag")
	}
	if len(buildinfo) > 0 {
		shstrtabAddstring(".note.gnu.build-id")
	}
	if *flagBuildid != "" {
		shstrtabAddstring(".note.go.buildid")
	}
	shstrtabAddstring(".elfdata")
	shstrtabAddstring(".rodata")
	// See the comment about data.rel.ro.FOO section names in data.go.
	relro_prefix := ""
	if ctxt.UseRelro() {
		shstrtabAddstring(".data.rel.ro")
		relro_prefix = ".data.rel.ro"
	}
	shstrtabAddstring(relro_prefix + ".typelink")
	shstrtabAddstring(relro_prefix + ".itablink")
	shstrtabAddstring(relro_prefix + ".gosymtab")
	shstrtabAddstring(relro_prefix + ".gopclntab")

	if ctxt.IsExternal() {
		*FlagD = true

		shstrtabAddstring(elfRelType + ".text")
		shstrtabAddstring(elfRelType + ".rodata")
		shstrtabAddstring(elfRelType + relro_prefix + ".typelink")
		shstrtabAddstring(elfRelType + relro_prefix + ".itablink")
		shstrtabAddstring(elfRelType + relro_prefix + ".gosymtab")
		shstrtabAddstring(elfRelType + relro_prefix + ".gopclntab")
		shstrtabAddstring(elfRelType + ".noptrdata")
		shstrtabAddstring(elfRelType + ".data")
		if ctxt.UseRelro() {
			shstrtabAddstring(elfRelType + ".data.rel.ro")
		}
		shstrtabAddstring(elfRelType + ".go.buildinfo")
		shstrtabAddstring(elfRelType + ".go.fipsinfo")
		if ctxt.IsMIPS() {
			shstrtabAddstring(elfRelType + ".MIPS.abiflags")
			shstrtabAddstring(elfRelType + ".gnu.attributes")
		}

		// add a .note.GNU-stack section to mark the stack as non-executable
		shstrtabAddstring(".note.GNU-stack")

		if ctxt.IsShared() {
			shstrtabAddstring(".note.go.abihash")
			shstrtabAddstring(".note.go.pkg-list")
			shstrtabAddstring(".note.go.deps")
		}
	}

	hasinitarr := ctxt.linkShared

	/* shared library initializer */
	switch ctxt.BuildMode {
	case BuildModeCArchive, BuildModeCShared, BuildModeShared, BuildModePlugin:
		hasinitarr = true
	}

	if hasinitarr {
		shstrtabAddstring(".init_array")
		shstrtabAddstring(elfRelType + ".init_array")
	}

	if !*FlagS {
		shstrtabAddstring(".symtab")
		shstrtabAddstring(".strtab")
	}
	if !*FlagW {
		dwarfaddshstrings(ctxt, shstrtabAddstring)
	}

	shstrtabAddstring(".shstrtab")

	if !*FlagD { /* -d suppresses dynamic loader format */
		shstrtabAddstring(".interp")
		shstrtabAddstring(".hash")
		shstrtabAddstring(".got")
		if ctxt.IsPPC64() {
			shstrtabAddstring(".glink")
		}
		shstrtabAddstring(".got.plt")
		shstrtabAddstring(".dynamic")
		shstrtabAddstring(".dynsym")
		shstrtabAddstring(".dynstr")
		shstrtabAddstring(elfRelType)
		shstrtabAddstring(elfRelType + ".plt")

		shstrtabAddstring(".plt")
		shstrtabAddstring(".gnu.version")
		shstrtabAddstring(".gnu.version_r")

		/* dynamic symbol table - first entry all zeros */
		dynsym := ldr.CreateSymForUpdate(".dynsym", 0)

		dynsym.SetType(sym.SELFROSECT)
		if elf64 {
			dynsym.SetSize(dynsym.Size() + ELF64SYMSIZE)
		} else {
			dynsym.SetSize(dynsym.Size() + ELF32SYMSIZE)
		}

		/* dynamic string table */
		dynstr := ldr.CreateSymForUpdate(".dynstr", 0)

		dynstr.SetType(sym.SELFROSECT)
		if dynstr.Size() == 0 {
			dynstr.Addstring("")
		}

		/* relocation table */
		s := ldr.CreateSymForUpdate(elfRelType, 0)
		s.SetType(sym.SELFROSECT)

		/* global offset table */
		got := ldr.CreateSymForUpdate(".got", 0)
		if ctxt.UseRelro() {
			got.SetType(sym.SELFRELROSECT)
		} else {
			got.SetType(sym.SELFGOT) // writable
		}

		/* ppc64 glink resolver */
		if ctxt.IsPPC64() {
			s := ldr.CreateSymForUpdate(".glink", 0)
			s.SetType(sym.SELFRXSECT)
		}

		/* hash */
		hash := ldr.CreateSymForUpdate(".hash", 0)
		hash.SetType(sym.SELFROSECT)

		gotplt := ldr.CreateSymForUpdate(".got.plt", 0)
		if ctxt.UseRelro() && *flagBindNow {
			gotplt.SetType(sym.SELFRELROSECT)
		} else {
			gotplt.SetType(sym.SELFSECT) // writable
		}

		plt := ldr.CreateSymForUpdate(".plt", 0)
		if ctxt.IsPPC64() {
			// In the ppc64 ABI, .plt is a data section
			// written by the dynamic linker.
			plt.SetType(sym.SELFSECT)
		} else {
			plt.SetType(sym.SELFRXSECT)
		}

		s = ldr.CreateSymForUpdate(elfRelType+".plt", 0)
		s.SetType(sym.SELFROSECT)

		s = ldr.CreateSymForUpdate(".gnu.version", 0)
		s.SetType(sym.SELFROSECT)

		s = ldr.CreateSymForUpdate(".gnu.version_r", 0)
		s.SetType(sym.SELFROSECT)

		/* define dynamic elf table */
		dynamic := ldr.CreateSymForUpdate(".dynamic", 0)
		switch {
		case thearch.ELF.DynamicReadOnly:
			dynamic.SetType(sym.SELFROSECT)
		case ctxt.UseRelro():
			dynamic.SetType(sym.SELFRELROSECT)
		default:
			dynamic.SetType(sym.SELFSECT)
		}

		if ctxt.IsS390X() {
			// S390X uses .got instead of .got.plt
			gotplt = got
		}
		thearch.ELF.SetupPLT(ctxt, ctxt.loader, plt, gotplt, dynamic.Sym())

		/*
		 * .dynamic table
		 */
		elfWriteDynEntSym(ctxt, dynamic, elf.DT_HASH, hash.Sym())

		elfWriteDynEntSym(ctxt, dynamic, elf.DT_SYMTAB, dynsym.Sym())
		if elf64 {
			Elfwritedynent(ctxt.Arch, dynamic, elf.DT_SYMENT, ELF64SYMSIZE)
		} else {
			Elfwritedynent(ctxt.Arch, dynamic, elf.DT_SYMENT, ELF32SYMSIZE)
		}
		elfWriteDynEntSym(ctxt, dynamic, elf.DT_STRTAB, dynstr.Sym())
		elfwritedynentsymsize(ctxt, dynamic, elf.DT_STRSZ, dynstr.Sym())
		if elfRelType == ".rela" {
			rela := ldr.LookupOrCreateSym(".rela", 0)
			elfWriteDynEntSym(ctxt, dynamic, elf.DT_RELA, rela)
			elfwritedynentsymsize(ctxt, dynamic, elf.DT_RELASZ, rela)
			Elfwritedynent(ctxt.Arch, dynamic, elf.DT_RELAENT, ELF64RELASIZE)
		} else {
			rel := ldr.LookupOrCreateSym(".rel", 0)
			elfWriteDynEntSym(ctxt, dynamic, elf.DT_REL, rel)
			elfwritedynentsymsize(ctxt, dynamic, elf.DT_RELSZ, rel)
			Elfwritedynent(ctxt.Arch, dynamic, elf.DT_RELENT, ELF32RELSIZE)
		}

		if rpath.val != "" {
			Elfwritedynent(ctxt.Arch, dynamic, elf.DT_RUNPATH, uint64(dynstr.Addstring(rpath.val)))
		}

		if ctxt.IsPPC64() {
			elfWriteDynEntSym(ctxt, dynamic, elf.DT_PLTGOT, plt.Sym())
		} else {
			elfWriteDynEntSym(ctxt, dynamic, elf.DT_PLTGOT, gotplt.Sym())
		}

		if ctxt.IsPPC64() {
			Elfwritedynent(ctxt.Arch, dynamic, elf.DT_PPC64_OPT, 0)
		}

		// Solaris dynamic linker can't handle an empty .rela.plt if
		// DT_JMPREL is emitted so we have to defer generation of elf.DT_PLTREL,
		// DT_PLTRELSZ, and elf.DT_JMPREL dynamic entries until after we know the
		// size of .rel(a).plt section.

		Elfwritedynent(ctxt.Arch, dynamic, elf.DT_DEBUG, 0)
	}

	if ctxt.IsShared() {
		// The go.link.abihashbytes symbol will be pointed at the appropriate
		// part of the .note.go.abihash section in data.go:func address().
		s := ldr.LookupOrCreateSym("go:link.abihashbytes", 0)
		sb := ldr.MakeSymbolUpdater(s)
		ldr.SetAttrLocal(s, true)
		sb.SetType(sym.SRODATA)
		ldr.SetAttrSpecial(s, true)
		sb.SetReachable(true)
		sb.SetSize(hash.Size20)
		slices.SortFunc(ctxt.Library, func(a, b *sym.Library) int {
			return strings.Compare(a.Pkg, b.Pkg)
		})
		h := hash.New20()
		for _, l := range ctxt.Library {
			h.Write(l.Fingerprint[:])
		}
		addgonote(ctxt, ".note.go.abihash", ELF_NOTE_GOABIHASH_TAG, h.Sum([]byte{}))
		addgonote(ctxt, ".note.go.pkg-list", ELF_NOTE_GOPKGLIST_TAG, pkglistfornote)
		var deplist []string
		for _, shlib := range ctxt.Shlibs {
			deplist = append(deplist, filepath.Base(shlib.Path))
		}
		addgonote(ctxt, ".note.go.deps", ELF_NOTE_GODEPS_TAG, []byte(strings.Join(deplist, "\n")))
	}

	if ctxt.LinkMode == LinkExternal && *flagBuildid != "" {
		addgonote(ctxt, ".note.go.buildid", ELF_NOTE_GOBUILDID_TAG, []byte(*flagBuildid))
	}

	//type mipsGnuAttributes struct {
	//	version uint8   // 'A'
	//	length  uint32  // 15 including itself
	//	gnu     [4]byte // "gnu\0"
	//	tag     uint8   // 1:file, 2: section, 3: symbol, 1 here
	//	taglen  uint32  // tag length, including tag, 7 here
	//	tagfp   uint8   // 4
	//	fpAbi  uint8    // see .MIPS.abiflags
	//}
	if ctxt.IsMIPS() {
		gnuattributes := ldr.CreateSymForUpdate(".gnu.attributes", 0)
		gnuattributes.SetType(sym.SELFROSECT)
		gnuattributes.SetReachable(true)
		gnuattributes.AddUint8('A')               // version 'A'
		gnuattributes.AddUint32(ctxt.Arch, 15)    // length 15 including itself
		gnuattributes.AddBytes([]byte("gnu\x00")) // "gnu\0"
		gnuattributes.AddUint8(1)                 // 1:file, 2: section, 3: symbol, 1 here
		gnuattributes.AddUint32(ctxt.Arch, 7)     // tag length, including tag, 7 here
		gnuattributes.AddUint8(4)                 // 4 for FP, 8 for MSA
		if buildcfg.GOMIPS == "softfloat" {
			gnuattributes.AddUint8(MIPS_FPABI_SOFT)
		} else {
			// Note: MIPS_FPABI_ANY is bad naming: in fact it is MIPS I style FPR usage.
			//       It is not for 'ANY'.
			// TODO: switch to FPXX after be sure that no odd-number-fpr is used.
			gnuattributes.AddUint8(MIPS_FPABI_ANY)
		}
	}
}

// Do not write DT_NULL.  elfdynhash will finish it.
func shsym(sh *ElfShdr, ldr *loader.Loader, s loader.Sym) {
	if s == 0 {
		panic("bad symbol in shsym2")
	}
	addr := ldr.SymValue(s)
	if sh.Flags&uint64(elf.SHF_ALLOC) != 0 {
		sh.Addr = uint64(addr)
	}
	sh.Off = uint64(datoff(ldr, s, addr))
	sh.Size = uint64(ldr.SymSize(s))
}

func phsh(ph *ElfPhdr, sh *ElfShdr) {
	ph.Vaddr = sh.Addr
	ph.Paddr = ph.Vaddr
	ph.Off = sh.Off
	ph.Filesz = sh.Size
	ph.Memsz = sh.Size
	ph.Align = sh.Addralign
}

func Asmbelfsetup() {
	/* This null SHdr must appear before all others */
	elfshname("")

	for _, sect := range Segtext.Sections {
		// There could be multiple .text sections. Instead check the Elfsect
		// field to determine if already has an ElfShdr and if not, create one.
		if sect.Name == ".text" {
			if sect.Elfsect == nil {
				sect.Elfsect = elfshnamedup(sect.Name)
			}
		} else {
			elfshalloc(sect)
		}
	}
	for _, sect := range Segrodata.Sections {
		elfshalloc(sect)
	}
	for _, sect := range Segrelrodata.Sections {
		elfshalloc(sect)
	}
	for _, sect := range Segdata.Sections {
		elfshalloc(sect)
	}
	for _, sect := range Segdwarf.Sections {
		elfshalloc(sect)
	}
}

func asmbElf(ctxt *Link) {
	var symo int64
	symo = int64(Segdwarf.Fileoff + Segdwarf.Filelen)
	symo = Rnd(symo, int64(ctxt.Arch.PtrSize))
	ctxt.Out.SeekSet(symo)
	if *FlagS {
		ctxt.Out.Write(elfshstrdat)
	} else {
		ctxt.Out.SeekSet(symo)
		asmElfSym(ctxt)
		ctxt.Out.Write(elfstrdat)
		ctxt.Out.Write(elfshstrdat)
		if ctxt.IsExternal() {
			elfEmitReloc(ctxt)
		}
	}
	ctxt.Out.SeekSet(0)

	ldr := ctxt.loader
	eh := getElfEhdr()
	switch ctxt.Arch.Family {
	default:
		Exitf("unknown architecture in asmbelf: %v", ctxt.Arch.Family)
	case sys.MIPS, sys.MIPS64:
		eh.Machine = uint16(elf.EM_MIPS)
	case sys.Loong64:
		eh.Machine = uint16(elf.EM_LOONGARCH)
	case sys.ARM:
		eh.Machine = uint16(elf.EM_ARM)
	case sys.AMD64:
		eh.Machine = uint16(elf.EM_X86_64)
	case sys.ARM64:
		eh.Machine = uint16(elf.EM_AARCH64)
	case sys.I386:
		eh.Machine = uint16(elf.EM_386)
	case sys.PPC64:
		eh.Machine = uint16(elf.EM_PPC64)
	case sys.RISCV64:
		eh.Machine = uint16(elf.EM_RISCV)
	case sys.S390X:
		eh.Machine = uint16(elf.EM_S390)
	}

	elfreserve := int64(ELFRESERVE)

	numtext := int64(0)
	for _, sect := range Segtext.Sections {
		if sect.Name == ".text" {
			numtext++
		}
	}

	// If there are multiple text sections, extra space is needed
	// in the elfreserve for the additional .text and .rela.text
	// section headers.  It can handle 4 extra now. Headers are
	// 64 bytes.

	if numtext > 4 {
		elfreserve += elfreserve + numtext*64*2
	}

	startva := *FlagTextAddr - int64(HEADR)
	resoff := elfreserve

	var pph *ElfPhdr
	var pnote *ElfPhdr
	getpnote := func() *ElfPhdr {
		if pnote == nil {
			pnote = newElfPhdr()
			pnote.Type = elf.PT_NOTE
			pnote.Flags = elf.PF_R
		}
		return pnote
	}
	if *flagRace && ctxt.IsNetbsd() {
		sh := elfshname(".note.netbsd.pax")
		resoff -= int64(elfnetbsdpax(sh, uint64(startva), uint64(resoff)))
		phsh(getpnote(), sh)
	}
	if ctxt.LinkMode == LinkExternal {
		/* skip program headers */
		eh.Phoff = 0

		eh.Phentsize = 0

		if ctxt.BuildMode == BuildModeShared {
			sh := elfshname(".note.go.pkg-list")
			sh.Type = uint32(elf.SHT_NOTE)
			sh = elfshname(".note.go.abihash")
			sh.Type = uint32(elf.SHT_NOTE)
			sh.Flags = uint64(elf.SHF_ALLOC)
			sh = elfshname(".note.go.deps")
			sh.Type = uint32(elf.SHT_NOTE)
		}

		if *flagBuildid != "" {
			sh := elfshname(".note.go.buildid")
			sh.Type = uint32(elf.SHT_NOTE)
			sh.Flags = uint64(elf.SHF_ALLOC)
		}

		goto elfobj
	}

	/* program header info */
	pph = newElfPhdr()

	pph.Type = elf.PT_PHDR
	pph.Flags = elf.PF_R
	pph.Off = uint64(eh.Ehsize)
	pph.Vaddr = uint64(*FlagTextAddr) - uint64(HEADR) + pph.Off
	pph.Paddr = uint64(*FlagTextAddr) - uint64(HEADR) + pph.Off
	pph.Align = uint64(*FlagRound)

	/*
	 * PHDR must be in a loaded segment. Adjust the text
	 * segment boundaries downwards to include it.
	 */
	{
		o := int64(Segtext.Vaddr - pph.Vaddr)
		Segtext.Vaddr -= uint64(o)
		Segtext.Length += uint64(o)
		o = int64(Segtext.Fileoff - pph.Off)
		Segtext.Fileoff -= uint64(o)
		Segtext.Filelen += uint64(o)
	}

	if !*FlagD { /* -d suppresses dynamic loader format */
		/* interpreter */
		sh := elfshname(".interp")

		sh.Type = uint32(elf.SHT_PROGBITS)
		sh.Flags = uint64(elf.SHF_ALLOC)
		sh.Addralign = 1

		if interpreter == "" && buildcfg.GOOS == runtime.GOOS && buildcfg.GOARCH == runtime.GOARCH && buildcfg.GO_LDSO != "" {
			interpreter = buildcfg.GO_LDSO
		}

		if interpreter == "" {
			switch ctxt.HeadType {
			case objabi.Hlinux:
				if buildcfg.GOOS == "android" {
					interpreter = thearch.ELF.Androiddynld
					if interpreter == "" {
						Exitf("ELF interpreter not set")
					}
				} else {
					interpreter = thearch.ELF.Linuxdynld
					// If interpreter does not exist, try musl instead.
					// This lets the same cmd/link binary work on
					// both glibc-based and musl-based systems.
					if _, err := os.Stat(interpreter); err != nil {
						if musl := thearch.ELF.LinuxdynldMusl; musl != "" {
							if _, err := os.Stat(musl); err == nil {
								interpreter = musl
							}
						}
					}
				}

			case objabi.Hfreebsd:
				interpreter = thearch.ELF.Freebsddynld

			case objabi.Hnetbsd:
				interpreter = thearch.ELF.Netbsddynld

			case objabi.Hopenbsd:
				interpreter = thearch.ELF.Openbsddynld

			case objabi.Hdragonfly:
				interpreter = thearch.ELF.Dragonflydynld

			case objabi.Hsolaris:
				interpreter = thearch.ELF.Solarisdynld
			}
		}

		resoff -= int64(elfinterp(sh, uint64(startva), uint64(resoff), interpreter))

		ph := newElfPhdr()
		ph.Type = elf.PT_INTERP
		ph.Flags = elf.PF_R
		phsh(ph, sh)
	}

	if ctxt.HeadType == objabi.Hnetbsd || ctxt.HeadType == objabi.Hopenbsd || ctxt.HeadType == objabi.Hfreebsd {
		var sh *ElfShdr
		switch ctxt.HeadType {
		case objabi.Hnetbsd:
			sh = elfshname(".note.netbsd.ident")
			resoff -= int64(elfnetbsdsig(sh, uint64(startva), uint64(resoff)))

		case objabi.Hopenbsd:
			sh = elfshname(".note.openbsd.ident")
			resoff -= int64(elfopenbsdsig(sh, uint64(startva), uint64(resoff)))

		case objabi.Hfreebsd:
			sh = elfshname(".note.tag")
			resoff -= int64(elffreebsdsig(sh, uint64(startva), uint64(resoff)))
		}
		// NetBSD, OpenBSD and FreeBSD require ident in an independent segment.
		pnotei := newElfPhdr()
		pnotei.Type = elf.PT_NOTE
		pnotei.Flags = elf.PF_R
		phsh(pnotei, sh)
	}

	if len(buildinfo) > 0 {
		sh := elfshname(".note.gnu.build-id")
		resoff -= int64(elfbuildinfo(sh, uint64(startva), uint64(resoff)))
		phsh(getpnote(), sh)
	}

	if *flagBuildid != "" {
		sh := elfshname(".note.go.buildid")
		resoff -= int64(elfgobuildid(sh, uint64(startva), uint64(resoff)))
		phsh(getpnote(), sh)
	}

	// Additions to the reserved area must be above this line.

	elfphload(&Segtext)
	if len(Segrodata.Sections) > 0 {
		elfphload(&Segrodata)
	}
	if len(Segrelrodata.Sections) > 0 {
		elfphload(&Segrelrodata)
		elfphrelro(&Segrelrodata)
	}
	elfphload(&Segdata)

	/* Dynamic linking sections */
	if !*FlagD {
		sh := elfshname(".dynsym")
		sh.Type = uint32(elf.SHT_DYNSYM)
		sh.Flags = uint64(elf.SHF_ALLOC)
		if elf64 {
			sh.Entsize = ELF64SYMSIZE
		} else {
			sh.Entsize = ELF32SYMSIZE
		}
		sh.Addralign = uint64(ctxt.Arch.RegSize)
		sh.Link = uint32(elfshname(".dynstr").shnum)

		// sh.info is the index of first non-local symbol (number of local symbols)
		s := ldr.Lookup(".dynsym", 0)
		i := uint32(0)
		for sub := s; sub != 0; sub = ldr.SubSym(sub) {
			i++
			if !ldr.AttrLocal(sub) {
				break
			}
		}
		sh.Info = i
		shsym(sh, ldr, s)

		sh = elfshname(".dynstr")
		sh.Type = uint32(elf.SHT_STRTAB)
		sh.Flags = uint64(elf.SHF_ALLOC)
		sh.Addralign = 1
		shsym(sh, ldr, ldr.Lookup(".dynstr", 0))

		if elfverneed != 0 {
			sh := elfshname(".gnu.version")
			sh.Type = uint32(elf.SHT_GNU_VERSYM)
			sh.Flags = uint64(elf.SHF_ALLOC)
			sh.Addralign = 2
			sh.Link = uint32(elfshname(".dynsym").shnum)
			sh.Entsize = 2
			shsym(sh, ldr, ldr.Lookup(".gnu.version", 0))

			sh = elfshname(".gnu.version_r")
			sh.Type = uint32(elf.SHT_GNU_VERNEED)
			sh.Flags = uint64(elf.SHF_ALLOC)
			sh.Addralign = uint64(ctxt.Arch.RegSize)
			sh.Info = uint32(elfverneed)
			sh.Link = uint32(elfshname(".dynstr").shnum)
			shsym(sh, ldr, ldr.Lookup(".gnu.version_r", 0))
		}

		if elfRelType == ".rela" {
			sh := elfshname(".rela.plt")
			sh.Type = uint32(elf.SHT_RELA)
			sh.Flags = uint64(elf.SHF_ALLOC)
			sh.Entsize = ELF64RELASIZE
			sh.Addralign = uint64(ctxt.Arch.RegSize)
			sh.Link = uint32(elfshname(".dynsym").shnum)
			sh.Info = uint32(elfshname(".plt").shnum)
			shsym(sh, ldr, ldr.Lookup(".rela.plt", 0))

			sh = elfshname(".rela")
			sh.Type = uint32(elf.SHT_RELA)
			sh.Flags = uint64(elf.SHF_ALLOC)
			sh.Entsize = ELF64RELASIZE
			sh.Addralign = 8
			sh.Link = uint32(elfshname(".dynsym").shnum)
			shsym(sh, ldr, ldr.Lookup(".rela", 0))
		} else {
			sh := elfshname(".rel.plt")
			sh.Type = uint32(elf.SHT_REL)
			sh.Flags = uint64(elf.SHF_ALLOC)
			sh.Entsize = ELF32RELSIZE
			sh.Addralign = 4
			sh.Link = uint32(elfshname(".dynsym").shnum)
			shsym(sh, ldr, ldr.Lookup(".rel.plt", 0))

			sh = elfshname(".rel")
			sh.Type = uint32(elf.SHT_REL)
			sh.Flags = uint64(elf.SHF_ALLOC)
			sh.Entsize = ELF32RELSIZE
			sh.Addralign = 4
			sh.Link = uint32(elfshname(".dynsym").shnum)
			shsym(sh, ldr, ldr.Lookup(".rel", 0))
		}

		if elf.Machine(eh.Machine) == elf.EM_PPC64 {
			sh := elfshname(".glink")
			sh.Type = uint32(elf.SHT_PROGBITS)
			sh.Flags = uint64(elf.SHF_ALLOC + elf.SHF_EXECINSTR)
			sh.Addralign = 4
			shsym(sh, ldr, ldr.Lookup(".glink", 0))
		}

		sh = elfshname(".plt")
		sh.Type = uint32(elf.SHT_PROGBITS)
		sh.Flags = uint64(elf.SHF_ALLOC + elf.SHF_EXECINSTR)
		if elf.Machine(eh.Machine) == elf.EM_X86_64 {
			sh.Entsize = 16
		} else if elf.Machine(eh.Machine) == elf.EM_S390 {
			sh.Entsize = 32
		} else if elf.Machine(eh.Machine) == elf.EM_PPC64 {
			// On ppc64, this is just a table of addresses
			// filled by the dynamic linker
			sh.Type = uint32(elf.SHT_NOBITS)

			sh.Flags = uint64(elf.SHF_ALLOC + elf.SHF_WRITE)
			sh.Entsize = 8
		} else {
			sh.Entsize = 4
		}
		sh.Addralign = sh.Entsize
		shsym(sh, ldr, ldr.Lookup(".plt", 0))

		// On ppc64, .got comes from the input files, so don't
		// create it here, and .got.plt is not used.
		if elf.Machine(eh.Machine) != elf.EM_PPC64 {
			sh := elfshname(".got")
			sh.Type = uint32(elf.SHT_PROGBITS)
			sh.Flags = uint64(elf.SHF_ALLOC + elf.SHF_WRITE)
			sh.Entsize = uint64(ctxt.Arch.RegSize)
			sh.Addralign = uint64(ctxt.Arch.RegSize)
			shsym(sh, ldr, ldr.Lookup(".got", 0))

			sh = elfshname(".got.plt")
			sh.Type = uint32(elf.SHT_PROGBITS)
			sh.Flags = uint64(elf.SHF_ALLOC + elf.SHF_WRITE)
			sh.Entsize = uint64(ctxt.Arch.RegSize)
			sh.Addralign = uint64(ctxt.Arch.RegSize)
			shsym(sh, ldr, ldr.Lookup(".got.plt", 0))
		}

		sh = elfshname(".hash")
		sh.Type = uint32(elf.SHT_HASH)
		sh.Flags = uint64(elf.SHF_ALLOC)
		sh.Entsize = 4
		sh.Addralign = uint64(ctxt.Arch.RegSize)
		sh.Link = uint32(elfshname(".dynsym").shnum)
		shsym(sh, ldr, ldr.Lookup(".hash", 0))

		/* sh and elf.PT_DYNAMIC for .dynamic section */
		sh = elfshname(".dynamic")

		sh.Type = uint32(elf.SHT_DYNAMIC)
		sh.Flags = uint64(elf.SHF_ALLOC + elf.SHF_WRITE)
		sh.Entsize = 2 * uint64(ctxt.Arch.RegSize)
		sh.Addralign = uint64(ctxt.Arch.RegSize)
		sh.Link = uint32(elfshname(".dynstr").shnum)
		shsym(sh, ldr, ldr.Lookup(".dynamic", 0))
		ph := newElfPhdr()
		ph.Type = elf.PT_DYNAMIC
		ph.Flags = elf.PF_R + elf.PF_W
		phsh(ph, sh)

		/*
		 * Thread-local storage segment (really just size).
		 */
		tlssize := uint64(0)
		for _, sect := range Segdata.Sections {
			if sect.Name == ".tbss" {
				tlssize = sect.Length
			}
		}
		if tlssize != 0 {
			ph := newElfPhdr()
			ph.Type = elf.PT_TLS
			ph.Flags = elf.PF_R
			ph.Memsz = tlssize
			ph.Align = uint64(ctxt.Arch.RegSize)
		}
	}

	if ctxt.HeadType == objabi.Hlinux || ctxt.HeadType == objabi.Hfreebsd {
		ph := newElfPhdr()
		ph.Type = elf.PT_GNU_STACK
		ph.Flags = elf.PF_W + elf.PF_R
		ph.Align = uint64(ctxt.Arch.RegSize)
	} else if ctxt.HeadType == objabi.Hopenbsd {
		ph := newElfPhdr()
		ph.Type = elf.PT_OPENBSD_NOBTCFI
		ph.Flags = elf.PF_X
	} else if ctxt.HeadType == objabi.Hsolaris {
		ph := newElfPhdr()
		ph.Type = elf.PT_SUNWSTACK
		ph.Flags = elf.PF_W + elf.PF_R
	}

elfobj:
	sh := elfshname(".shstrtab")
	eh.Shstrndx = uint16(sh.shnum)

	if ctxt.IsMIPS() {
		sh = elfshname(".MIPS.abiflags")
		sh.Type = uint32(elf.SHT_MIPS_ABIFLAGS)
		sh.Flags = uint64(elf.SHF_ALLOC)
		sh.Addralign = 8
		resoff -= int64(elfMipsAbiFlags(sh, uint64(startva), uint64(resoff)))

		ph := newElfPhdr()
		ph.Type = elf.PT_MIPS_ABIFLAGS
		ph.Flags = elf.PF_R
		phsh(ph, sh)

		sh = elfshname(".gnu.attributes")
		sh.Type = uint32(elf.SHT_GNU_ATTRIBUTES)
		sh.Addralign = 1
		ldr := ctxt.loader
		shsym(sh, ldr, ldr.Lookup(".gnu.attributes", 0))
	}

	// put these sections early in the list
	if !*FlagS {
		elfshname(".symtab")
		elfshname(".strtab")
	}
	elfshname(".shstrtab")

	for _, sect := range Segtext.Sections {
		elfshbits(ctxt.LinkMode, sect)
	}
	for _, sect := range Segrodata.Sections {
		elfshbits(ctxt.LinkMode, sect)
	}
	for _, sect := range Segrelrodata.Sections {
		elfshbits(ctxt.LinkMode, sect)
	}
	for _, sect := range Segdata.Sections {
		elfshbits(ctxt.LinkMode, sect)
	}
	for _, sect := range Segdwarf.Sections {
		elfshbits(ctxt.LinkMode, sect)
	}

	if ctxt.LinkMode == LinkExternal {
		for _, sect := range Segtext.Sections {
			elfshreloc(ctxt.Arch, sect)
		}
		for _, sect := range Segrodata.Sections {
			elfshreloc(ctxt.Arch, sect)
		}
		for _, sect := range Segrelrodata.Sections {
			elfshreloc(ctxt.Arch, sect)
		}
		for _, sect := range Segdata.Sections {
			elfshreloc(ctxt.Arch, sect)
		}
		for _, si := range dwarfp {
			sect := ldr.SymSect(si.secSym())
			elfshreloc(ctxt.Arch, sect)
		}
		// add a .note.GNU-stack section to mark the stack as non-executable
		sh := elfshname(".note.GNU-stack")

		sh.Type = uint32(elf.SHT_PROGBITS)
		sh.Addralign = 1
		sh.Flags = 0
	}

	var shstroff uint64
	if !*FlagS {
		sh := elfshname(".symtab")
		sh.Type = uint32(elf.SHT_SYMTAB)
		sh.Off = uint64(symo)
		sh.Size = uint64(symSize)
		sh.Addralign = uint64(ctxt.Arch.RegSize)
		sh.Entsize = 8 + 2*uint64(ctxt.Arch.RegSize)
		sh.Link = uint32(elfshname(".strtab").shnum)
		sh.Info = uint32(elfglobalsymndx)

		sh = elfshname(".strtab")
		sh.Type = uint32(elf.SHT_STRTAB)
		sh.Off = uint64(symo) + uint64(symSize)
		sh.Size = uint64(len(elfstrdat))
		sh.Addralign = 1
		shstroff = sh.Off + sh.Size
	} else {
		shstroff = uint64(symo)
	}

	sh = elfshname(".shstrtab")
	sh.Type = uint32(elf.SHT_STRTAB)
	sh.Off = shstroff
	sh.Size = uint64(len(elfshstrdat))
	sh.Addralign = 1

	/* Main header */
	copy(eh.Ident[:], elf.ELFMAG)

	var osabi elf.OSABI
	switch ctxt.HeadType {
	case objabi.Hfreebsd:
		osabi = elf.ELFOSABI_FREEBSD
	case objabi.Hnetbsd:
		osabi = elf.ELFOSABI_NETBSD
	case objabi.Hopenbsd:
		osabi = elf.ELFOSABI_OPENBSD
	case objabi.Hdragonfly:
		osabi = elf.ELFOSABI_NONE
	}
	eh.Ident[elf.EI_OSABI] = byte(osabi)

	if elf64 {
		eh.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	} else {
		eh.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS32)
	}
	if ctxt.Arch.ByteOrder == binary.BigEndian {
		eh.Ident[elf.EI_DATA] = byte(elf.ELFDATA2MSB)
	} else {
		eh.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	}
	eh.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)

	if ctxt.LinkMode == LinkExternal {
		eh.Type = uint16(elf.ET_REL)
	} else if ctxt.BuildMode == BuildModePIE {
		eh.Type = uint16(elf.ET_DYN)
	} else {
		eh.Type = uint16(elf.ET_EXEC)
	}

	if ctxt.LinkMode != LinkExternal {
		eh.Entry = uint64(Entryvalue(ctxt))
	}

	eh.Version = uint32(elf.EV_CURRENT)

	if pph != nil {
		pph.Filesz = uint64(eh.Phnum) * uint64(eh.Phentsize)
		pph.Memsz = pph.Filesz
	}

	ctxt.Out.SeekSet(0)
	a := int64(0)
	a += int64(elfwritehdr(ctxt.Out))
	a += int64(elfwritephdrs(ctxt.Out))
	a += int64(elfwriteshdrs(ctxt.Out))
	if !*FlagD {
		a += int64(elfwriteinterp(ctxt.Out))
	}
	if ctxt.IsMIPS() {
		a += int64(elfWriteMipsAbiFlags(ctxt))
	}

	if ctxt.LinkMode != LinkExternal {
		if ctxt.HeadType == objabi.Hnetbsd {
			a += int64(elfwritenetbsdsig(ctxt.Out))
		}
		if ctxt.HeadType == objabi.Hopenbsd {
			a += int64(elfwriteopenbsdsig(ctxt.Out))
		}
		if ctxt.HeadType == objabi.Hfreebsd {
			a += int64(elfwritefreebsdsig(ctxt.Out))
		}
		if len(buildinfo) > 0 {
			a += int64(elfwritebuildinfo(ctxt.Out))
		}
		if *flagBuildid != "" {
			a += int64(elfwritegobuildid(ctxt.Out))
		}
	}
	if *flagRace && ctxt.IsNetbsd() {
		a += int64(elfwritenetbsdpax(ctxt.Out))
	}

	if a > elfreserve {
		Errorf("ELFRESERVE too small: %d > %d with %d text sections", a, elfreserve, numtext)
	}

	// Verify the amount of space allocated for the elf header is sufficient.  The file offsets are
	// already computed in layout, so we could spill into another section.
	if a > int64(HEADR) {
		Errorf("HEADR too small: %d > %d with %d text sections", a, HEADR, numtext)
	}
}

func elfadddynsym(ldr *loader.Loader, target *Target, syms *ArchSyms, s loader.Sym) {
	ldr.SetSymDynid(s, int32(Nelfsym))
	Nelfsym++
	d := ldr.MakeSymbolUpdater(syms.DynSym)
	name := ldr.SymExtname(s)
	dstru := ldr.MakeSymbolUpdater(syms.DynStr)
	st := ldr.SymType(s)
	cgoeStatic := ldr.AttrCgoExportStatic(s)
	cgoeDynamic := ldr.AttrCgoExportDynamic(s)
	cgoexp := (cgoeStatic || cgoeDynamic)

	d.AddUint32(target.Arch, uint32(dstru.Addstring(name)))

	if elf64 {

		/* type */
		var t uint8

		if cgoexp && st.IsText() {
			t = elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC)
		} else {
			t = elf.ST_INFO(elf.STB_GLOBAL, elf.STT_OBJECT)
		}
		d.AddUint8(t)

		/* reserved */
		d.AddUint8(0)

		/* section where symbol is defined */
		if st == sym.SDYNIMPORT {
			d.AddUint16(target.Arch, uint16(elf.SHN_UNDEF))
		} else {
			d.AddUint16(target.Arch, 1)
		}

		/* value */
		if st == sym.SDYNIMPORT {
			d.AddUint64(target.Arch, 0)
		} else {
			d.AddAddrPlus(target.Arch, s, 0)
		}

		/* size of object */
		d.AddUint64(target.Arch, uint64(len(ldr.Data(s))))

		dil := ldr.SymDynimplib(s)

		if !cgoeDynamic && dil != "" && !seenlib[dil] {
			du := ldr.MakeSymbolUpdater(syms.Dynamic)
			Elfwritedynent(target.Arch, du, elf.DT_NEEDED, uint64(dstru.Addstring(dil)))
			seenlib[dil] = true
		}
	} else {

		/* value */
		if st == sym.SDYNIMPORT {
			d.AddUint32(target.Arch, 0)
		} else {
			d.AddAddrPlus(target.Arch, s, 0)
		}

		/* size of object */
		d.AddUint32(target.Arch, uint32(len(ldr.Data(s))))

		/* type */
		var t uint8

		// TODO(mwhudson): presumably the behavior should actually be the same on both arm and 386.
		if target.Arch.Family == sys.I386 && cgoexp && st.IsText() {
			t = elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC)
		} else if target.Arch.Family == sys.ARM && cgoeDynamic && st.IsText() {
			t = elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC)
		} else {
			t = elf.ST_INFO(elf.STB_GLOBAL, elf.STT_OBJECT)
		}
		d.AddUint8(t)
		d.AddUint8(0)

		/* shndx */
		if st == sym.SDYNIMPORT {
			d.AddUint16(target.Arch, uint16(elf.SHN_UNDEF))
		} else {
			d.AddUint16(target.Arch, 1)
		}
	}
}
```