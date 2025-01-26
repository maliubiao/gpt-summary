Response:
Let's break down the thought process for answering this request.

**1. Understanding the Request:**

The core request is to summarize the functionality of the provided Go code snippet. The snippet is clearly related to the ELF (Executable and Linkable Format) file format, as evidenced by the package path (`go/src/debug/elf`) and the numerous constants like `PT_LOAD`, `DT_NEEDED`, `R_X86_64_PC32`, etc.

The request specifically asks for:
* Listing functionalities.
* Inferring the Go feature it implements.
* Providing Go code examples (with assumptions for input/output).
* Explaining command-line argument handling (if any).
* Identifying common mistakes users might make (if any).
* Answering in Chinese.
* Specifically, for *this* part (part 2 of 5), to summarize its functionality.

**2. Initial Code Analysis and Keyword Spotting:**

The first step is to scan the code for key terms and patterns:

* **Constants:**  A large number of `const` definitions are present. These constants define various types, flags, and tags related to ELF. This immediately suggests the code is about representing and manipulating ELF file structures.
* **Types:**  Custom types like `ProgType`, `ProgFlag`, `DynTag`, `DynFlag`, `SymBind`, `SymType`, `SymVis`, `R_X86_64`, `R_AARCH64`, etc., are defined. This indicates the code is creating a type system to model the ELF format.
* **String Methods:**  Methods like `String()` and `GoString()` are implemented for these custom types. This is a standard Go idiom for providing string representations of data structures, useful for debugging and logging. The presence of `stringName` and `flagName` suggests helper functions for generating these strings.
* **Comments:**  The comments within the `const` blocks provide valuable context for understanding the meaning of each constant. They often directly correspond to definitions in the ELF specification.
* **Architecture Compatibility:** The comment `/* Architecture compatibility */` and the presence of architecture-specific constants (like those prefixed with `PT_MIPS_`, `PT_S390_`, `R_X86_64_`, `R_AARCH64_`) highlight the code's ability to handle different processor architectures.

**3. Inferring the Go Feature:**

Based on the analysis, the most logical conclusion is that this code implements the **parsing and representation of the ELF file format in Go**. It provides a structured way to access the various components and metadata within an ELF file. This is crucial for tools that need to inspect, analyze, or manipulate ELF files (debuggers, linkers, loaders, etc.).

**4. Planning the Go Code Example (Mental Outline):**

To illustrate how this code might be used, a simple example that reads an ELF file and prints some of the defined constants would be appropriate. This would demonstrate the access to `ProgType`, `DynTag`, etc.

* **Input:** An ELF file.
* **Process:** Open the file, parse the ELF header (though this part isn't in the snippet, it's a necessary conceptual step), and then access and print the values of the constants defined in the snippet.
* **Output:**  The string representations of the constants.

**5. Considering Command-Line Arguments and User Errors:**

Since the provided snippet focuses on type definitions and constants, it doesn't directly handle command-line arguments. The larger `elf` package likely does, but this specific part doesn't.

Similarly, the snippet itself doesn't present opportunities for direct user error *in this isolated part*. The types and constants are defined. Errors would likely occur in the *usage* of these types and constants, which is outside the scope of this specific code.

**6. Structuring the Answer in Chinese:**

The request specifies a Chinese answer, so all explanations need to be translated. This includes the functionalities, the Go feature, the code example, and any additional points.

**7. Focusing on Part 2 Summary:**

The request explicitly asks for a summary of the functionality of *this specific part*. Therefore, the summary should highlight the definition of the core data structures and constants used to represent ELF file components. It should emphasize the type system for program headers, dynamic tags, and relocation types.

**8. Refining the Code Example (Self-Correction):**

Initially, I might think of parsing an actual ELF file. However, since the snippet *only* contains the definitions, a more direct example that just uses the defined constants is more relevant and accurate for this specific code portion. This avoids bringing in concepts and code not present in the provided fragment.

**9. Final Review and Language Check:**

Before submitting the answer, it's crucial to review for clarity, accuracy, and correct Chinese grammar. Ensure all aspects of the request are addressed.

By following this thought process, breaking down the problem, analyzing the code, and focusing on the specifics of the request (especially the "part 2" aspect), a comprehensive and accurate answer can be constructed.
## 对 go/src/debug/elf/elf.go 部分代码的功能归纳 (第 2 部分)

这部分代码主要定义了用于表示 **ELF (Executable and Linkable Format)** 文件格式中关键数据结构的 **常量** 和 **类型**，特别是关于 **程序头 (Program Header)** 和 **动态段 (Dynamic Section)** 的相关内容。

**具体来说，它的功能可以归纳为：**

1. **定义了 `ProgType` 类型及其相关的常量：**  `ProgType` 代表了程序头条目的类型，例如 `PT_LOAD` (可加载段), `PT_DYNAMIC` (动态链接信息), `PT_INTERP` (解释器路径) 等。还包括了特定架构的程序头类型，如 `PT_AARCH64_UNWIND` 和 MIPS 相关的类型。 这些常量用于识别程序头条目的用途。

2. **定义了 `ProgFlag` 类型及其相关的常量：** `ProgFlag` 代表了程序头条目的标志位，例如 `PF_X` (可执行), `PF_W` (可写), `PF_R` (可读)。 这些标志位描述了段的访问权限。

3. **定义了 `DynTag` 类型及其相关的常量：** `DynTag` 代表了动态段条目的标签，例如 `DT_NEEDED` (依赖的共享库), `DT_STRTAB` (字符串表地址), `DT_SYMTAB` (符号表地址) 等。这些标签指示了动态段条目的含义。 同样包含了特定架构的动态标签，如 MIPS 和 PPC 相关的类型。

4. **定义了 `DynFlag` 和 `DynFlag1` 类型及其相关的常量：** 这两个类型代表了动态标志位，例如 `DF_ORIGIN` (支持 `$ORIGIN` 替换), `DF_SYMBOLIC` (符号链接), `DF_1_NOW` (立即处理所有重定位) 等。这些标志位控制了动态链接器的行为。

5. **定义了 `NType` 类型及其相关的常量：**  `NType` 用于表示核心转储文件中的 Note 条目的类型，例如 `NT_PRSTATUS` (进程状态), `NT_FPREGSET` (浮点寄存器) 等。

6. **定义了符号相关的类型和常量：**
    * `SymBind` (符号绑定)：例如 `STB_LOCAL` (本地符号), `STB_GLOBAL` (全局符号), `STB_WEAK` (弱符号)。
    * `SymType` (符号类型)：例如 `STT_NOTYPE` (未指定类型), `STT_OBJECT` (数据对象), `STT_FUNC` (函数)。
    * `SymVis` (符号可见性)：例如 `STV_DEFAULT` (默认可见性), `STV_HIDDEN` (隐藏)。
    这些类型和常量用于描述 ELF 文件中符号的属性。

7. **定义了不同架构的重定位类型及其常量：**
    * `R_X86_64` (x86-64 架构的重定位类型)，例如 `R_X86_64_PC32` (PC 相对 32 位符号值)。
    * `R_AARCH64` (AArch64 架构的重定位类型)，例如 `R_AARCH64_ABS64` (绝对 64 位)。
    这些常量定义了在链接过程中如何修改代码和数据段以适应加载地址。

8. **提供了将常量值转换为字符串表示的方法：**  通过实现 `String()` 和 `GoString()` 方法，可以将上述定义的枚举类型常量转换为易于阅读的字符串形式，方便调试和日志输出。 底层使用了 `stringName` 和 `flagName` 辅助函数。

**总而言之，这部分代码是 `debug/elf` 包的基础数据定义部分，它为 Go 语言提供了理解和操作 ELF 文件格式的能力，特别是关于程序结构、动态链接和符号信息方面。** 它是构建更高级 ELF 文件处理功能的基础，例如解析 ELF 文件头、段信息、符号表、重定位表等。

Prompt: 
```
这是路径为go/src/debug/elf/elf.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共5部分，请归纳一下它的功能

"""
/* Architecture compatibility */
	PT_AARCH64_UNWIND  ProgType = 0x70000001 /* Exception unwind tables */

	PT_MIPS_REGINFO  ProgType = 0x70000000 /* Register usage */
	PT_MIPS_RTPROC   ProgType = 0x70000001 /* Runtime procedures */
	PT_MIPS_OPTIONS  ProgType = 0x70000002 /* Options */
	PT_MIPS_ABIFLAGS ProgType = 0x70000003 /* ABI flags */

	PT_S390_PGSTE ProgType = 0x70000000 /* 4k page table size */

	PT_HIPROC ProgType = 0x7fffffff /* Last processor-specific type. */
)

var ptStrings = []intName{
	{0, "PT_NULL"},
	{1, "PT_LOAD"},
	{2, "PT_DYNAMIC"},
	{3, "PT_INTERP"},
	{4, "PT_NOTE"},
	{5, "PT_SHLIB"},
	{6, "PT_PHDR"},
	{7, "PT_TLS"},
	{0x60000000, "PT_LOOS"},
	{0x6474e550, "PT_GNU_EH_FRAME"},
	{0x6474e551, "PT_GNU_STACK"},
	{0x6474e552, "PT_GNU_RELRO"},
	{0x6474e553, "PT_GNU_PROPERTY"},
	{0x65041580, "PT_PAX_FLAGS"},
	{0x65a3dbe6, "PT_OPENBSD_RANDOMIZE"},
	{0x65a3dbe7, "PT_OPENBSD_WXNEEDED"},
	{0x65a41be6, "PT_OPENBSD_BOOTDATA"},
	{0x6ffffffb, "PT_SUNWSTACK"},
	{0x6fffffff, "PT_HIOS"},
	{0x70000000, "PT_LOPROC"},
	// We don't list the processor-dependent ProgTypes,
	// as the values overlap.
	{0x7fffffff, "PT_HIPROC"},
}

func (i ProgType) String() string   { return stringName(uint32(i), ptStrings, false) }
func (i ProgType) GoString() string { return stringName(uint32(i), ptStrings, true) }

// Prog.Flag
type ProgFlag uint32

const (
	PF_X        ProgFlag = 0x1        /* Executable. */
	PF_W        ProgFlag = 0x2        /* Writable. */
	PF_R        ProgFlag = 0x4        /* Readable. */
	PF_MASKOS   ProgFlag = 0x0ff00000 /* Operating system-specific. */
	PF_MASKPROC ProgFlag = 0xf0000000 /* Processor-specific. */
)

var pfStrings = []intName{
	{0x1, "PF_X"},
	{0x2, "PF_W"},
	{0x4, "PF_R"},
}

func (i ProgFlag) String() string   { return flagName(uint32(i), pfStrings, false) }
func (i ProgFlag) GoString() string { return flagName(uint32(i), pfStrings, true) }

// Dyn.Tag
type DynTag int

const (
	DT_NULL         DynTag = 0  /* Terminating entry. */
	DT_NEEDED       DynTag = 1  /* String table offset of a needed shared library. */
	DT_PLTRELSZ     DynTag = 2  /* Total size in bytes of PLT relocations. */
	DT_PLTGOT       DynTag = 3  /* Processor-dependent address. */
	DT_HASH         DynTag = 4  /* Address of symbol hash table. */
	DT_STRTAB       DynTag = 5  /* Address of string table. */
	DT_SYMTAB       DynTag = 6  /* Address of symbol table. */
	DT_RELA         DynTag = 7  /* Address of ElfNN_Rela relocations. */
	DT_RELASZ       DynTag = 8  /* Total size of ElfNN_Rela relocations. */
	DT_RELAENT      DynTag = 9  /* Size of each ElfNN_Rela relocation entry. */
	DT_STRSZ        DynTag = 10 /* Size of string table. */
	DT_SYMENT       DynTag = 11 /* Size of each symbol table entry. */
	DT_INIT         DynTag = 12 /* Address of initialization function. */
	DT_FINI         DynTag = 13 /* Address of finalization function. */
	DT_SONAME       DynTag = 14 /* String table offset of shared object name. */
	DT_RPATH        DynTag = 15 /* String table offset of library path. [sup] */
	DT_SYMBOLIC     DynTag = 16 /* Indicates "symbolic" linking. [sup] */
	DT_REL          DynTag = 17 /* Address of ElfNN_Rel relocations. */
	DT_RELSZ        DynTag = 18 /* Total size of ElfNN_Rel relocations. */
	DT_RELENT       DynTag = 19 /* Size of each ElfNN_Rel relocation. */
	DT_PLTREL       DynTag = 20 /* Type of relocation used for PLT. */
	DT_DEBUG        DynTag = 21 /* Reserved (not used). */
	DT_TEXTREL      DynTag = 22 /* Indicates there may be relocations in non-writable segments. [sup] */
	DT_JMPREL       DynTag = 23 /* Address of PLT relocations. */
	DT_BIND_NOW     DynTag = 24 /* [sup] */
	DT_INIT_ARRAY   DynTag = 25 /* Address of the array of pointers to initialization functions */
	DT_FINI_ARRAY   DynTag = 26 /* Address of the array of pointers to termination functions */
	DT_INIT_ARRAYSZ DynTag = 27 /* Size in bytes of the array of initialization functions. */
	DT_FINI_ARRAYSZ DynTag = 28 /* Size in bytes of the array of termination functions. */
	DT_RUNPATH      DynTag = 29 /* String table offset of a null-terminated library search path string. */
	DT_FLAGS        DynTag = 30 /* Object specific flag values. */
	DT_ENCODING     DynTag = 32 /* Values greater than or equal to DT_ENCODING
	   and less than DT_LOOS follow the rules for
	   the interpretation of the d_un union
	   as follows: even == 'd_ptr', even == 'd_val'
	   or none */
	DT_PREINIT_ARRAY   DynTag = 32 /* Address of the array of pointers to pre-initialization functions. */
	DT_PREINIT_ARRAYSZ DynTag = 33 /* Size in bytes of the array of pre-initialization functions. */
	DT_SYMTAB_SHNDX    DynTag = 34 /* Address of SHT_SYMTAB_SHNDX section. */

	DT_LOOS DynTag = 0x6000000d /* First OS-specific */
	DT_HIOS DynTag = 0x6ffff000 /* Last OS-specific */

	DT_VALRNGLO       DynTag = 0x6ffffd00
	DT_GNU_PRELINKED  DynTag = 0x6ffffdf5
	DT_GNU_CONFLICTSZ DynTag = 0x6ffffdf6
	DT_GNU_LIBLISTSZ  DynTag = 0x6ffffdf7
	DT_CHECKSUM       DynTag = 0x6ffffdf8
	DT_PLTPADSZ       DynTag = 0x6ffffdf9
	DT_MOVEENT        DynTag = 0x6ffffdfa
	DT_MOVESZ         DynTag = 0x6ffffdfb
	DT_FEATURE        DynTag = 0x6ffffdfc
	DT_POSFLAG_1      DynTag = 0x6ffffdfd
	DT_SYMINSZ        DynTag = 0x6ffffdfe
	DT_SYMINENT       DynTag = 0x6ffffdff
	DT_VALRNGHI       DynTag = 0x6ffffdff

	DT_ADDRRNGLO    DynTag = 0x6ffffe00
	DT_GNU_HASH     DynTag = 0x6ffffef5
	DT_TLSDESC_PLT  DynTag = 0x6ffffef6
	DT_TLSDESC_GOT  DynTag = 0x6ffffef7
	DT_GNU_CONFLICT DynTag = 0x6ffffef8
	DT_GNU_LIBLIST  DynTag = 0x6ffffef9
	DT_CONFIG       DynTag = 0x6ffffefa
	DT_DEPAUDIT     DynTag = 0x6ffffefb
	DT_AUDIT        DynTag = 0x6ffffefc
	DT_PLTPAD       DynTag = 0x6ffffefd
	DT_MOVETAB      DynTag = 0x6ffffefe
	DT_SYMINFO      DynTag = 0x6ffffeff
	DT_ADDRRNGHI    DynTag = 0x6ffffeff

	DT_VERSYM     DynTag = 0x6ffffff0
	DT_RELACOUNT  DynTag = 0x6ffffff9
	DT_RELCOUNT   DynTag = 0x6ffffffa
	DT_FLAGS_1    DynTag = 0x6ffffffb
	DT_VERDEF     DynTag = 0x6ffffffc
	DT_VERDEFNUM  DynTag = 0x6ffffffd
	DT_VERNEED    DynTag = 0x6ffffffe
	DT_VERNEEDNUM DynTag = 0x6fffffff

	DT_LOPROC DynTag = 0x70000000 /* First processor-specific type. */

	DT_MIPS_RLD_VERSION           DynTag = 0x70000001
	DT_MIPS_TIME_STAMP            DynTag = 0x70000002
	DT_MIPS_ICHECKSUM             DynTag = 0x70000003
	DT_MIPS_IVERSION              DynTag = 0x70000004
	DT_MIPS_FLAGS                 DynTag = 0x70000005
	DT_MIPS_BASE_ADDRESS          DynTag = 0x70000006
	DT_MIPS_MSYM                  DynTag = 0x70000007
	DT_MIPS_CONFLICT              DynTag = 0x70000008
	DT_MIPS_LIBLIST               DynTag = 0x70000009
	DT_MIPS_LOCAL_GOTNO           DynTag = 0x7000000a
	DT_MIPS_CONFLICTNO            DynTag = 0x7000000b
	DT_MIPS_LIBLISTNO             DynTag = 0x70000010
	DT_MIPS_SYMTABNO              DynTag = 0x70000011
	DT_MIPS_UNREFEXTNO            DynTag = 0x70000012
	DT_MIPS_GOTSYM                DynTag = 0x70000013
	DT_MIPS_HIPAGENO              DynTag = 0x70000014
	DT_MIPS_RLD_MAP               DynTag = 0x70000016
	DT_MIPS_DELTA_CLASS           DynTag = 0x70000017
	DT_MIPS_DELTA_CLASS_NO        DynTag = 0x70000018
	DT_MIPS_DELTA_INSTANCE        DynTag = 0x70000019
	DT_MIPS_DELTA_INSTANCE_NO     DynTag = 0x7000001a
	DT_MIPS_DELTA_RELOC           DynTag = 0x7000001b
	DT_MIPS_DELTA_RELOC_NO        DynTag = 0x7000001c
	DT_MIPS_DELTA_SYM             DynTag = 0x7000001d
	DT_MIPS_DELTA_SYM_NO          DynTag = 0x7000001e
	DT_MIPS_DELTA_CLASSSYM        DynTag = 0x70000020
	DT_MIPS_DELTA_CLASSSYM_NO     DynTag = 0x70000021
	DT_MIPS_CXX_FLAGS             DynTag = 0x70000022
	DT_MIPS_PIXIE_INIT            DynTag = 0x70000023
	DT_MIPS_SYMBOL_LIB            DynTag = 0x70000024
	DT_MIPS_LOCALPAGE_GOTIDX      DynTag = 0x70000025
	DT_MIPS_LOCAL_GOTIDX          DynTag = 0x70000026
	DT_MIPS_HIDDEN_GOTIDX         DynTag = 0x70000027
	DT_MIPS_PROTECTED_GOTIDX      DynTag = 0x70000028
	DT_MIPS_OPTIONS               DynTag = 0x70000029
	DT_MIPS_INTERFACE             DynTag = 0x7000002a
	DT_MIPS_DYNSTR_ALIGN          DynTag = 0x7000002b
	DT_MIPS_INTERFACE_SIZE        DynTag = 0x7000002c
	DT_MIPS_RLD_TEXT_RESOLVE_ADDR DynTag = 0x7000002d
	DT_MIPS_PERF_SUFFIX           DynTag = 0x7000002e
	DT_MIPS_COMPACT_SIZE          DynTag = 0x7000002f
	DT_MIPS_GP_VALUE              DynTag = 0x70000030
	DT_MIPS_AUX_DYNAMIC           DynTag = 0x70000031
	DT_MIPS_PLTGOT                DynTag = 0x70000032
	DT_MIPS_RWPLT                 DynTag = 0x70000034
	DT_MIPS_RLD_MAP_REL           DynTag = 0x70000035

	DT_PPC_GOT DynTag = 0x70000000
	DT_PPC_OPT DynTag = 0x70000001

	DT_PPC64_GLINK DynTag = 0x70000000
	DT_PPC64_OPD   DynTag = 0x70000001
	DT_PPC64_OPDSZ DynTag = 0x70000002
	DT_PPC64_OPT   DynTag = 0x70000003

	DT_SPARC_REGISTER DynTag = 0x70000001

	DT_AUXILIARY DynTag = 0x7ffffffd
	DT_USED      DynTag = 0x7ffffffe
	DT_FILTER    DynTag = 0x7fffffff

	DT_HIPROC DynTag = 0x7fffffff /* Last processor-specific type. */
)

var dtStrings = []intName{
	{0, "DT_NULL"},
	{1, "DT_NEEDED"},
	{2, "DT_PLTRELSZ"},
	{3, "DT_PLTGOT"},
	{4, "DT_HASH"},
	{5, "DT_STRTAB"},
	{6, "DT_SYMTAB"},
	{7, "DT_RELA"},
	{8, "DT_RELASZ"},
	{9, "DT_RELAENT"},
	{10, "DT_STRSZ"},
	{11, "DT_SYMENT"},
	{12, "DT_INIT"},
	{13, "DT_FINI"},
	{14, "DT_SONAME"},
	{15, "DT_RPATH"},
	{16, "DT_SYMBOLIC"},
	{17, "DT_REL"},
	{18, "DT_RELSZ"},
	{19, "DT_RELENT"},
	{20, "DT_PLTREL"},
	{21, "DT_DEBUG"},
	{22, "DT_TEXTREL"},
	{23, "DT_JMPREL"},
	{24, "DT_BIND_NOW"},
	{25, "DT_INIT_ARRAY"},
	{26, "DT_FINI_ARRAY"},
	{27, "DT_INIT_ARRAYSZ"},
	{28, "DT_FINI_ARRAYSZ"},
	{29, "DT_RUNPATH"},
	{30, "DT_FLAGS"},
	{32, "DT_ENCODING"},
	{32, "DT_PREINIT_ARRAY"},
	{33, "DT_PREINIT_ARRAYSZ"},
	{34, "DT_SYMTAB_SHNDX"},
	{0x6000000d, "DT_LOOS"},
	{0x6ffff000, "DT_HIOS"},
	{0x6ffffd00, "DT_VALRNGLO"},
	{0x6ffffdf5, "DT_GNU_PRELINKED"},
	{0x6ffffdf6, "DT_GNU_CONFLICTSZ"},
	{0x6ffffdf7, "DT_GNU_LIBLISTSZ"},
	{0x6ffffdf8, "DT_CHECKSUM"},
	{0x6ffffdf9, "DT_PLTPADSZ"},
	{0x6ffffdfa, "DT_MOVEENT"},
	{0x6ffffdfb, "DT_MOVESZ"},
	{0x6ffffdfc, "DT_FEATURE"},
	{0x6ffffdfd, "DT_POSFLAG_1"},
	{0x6ffffdfe, "DT_SYMINSZ"},
	{0x6ffffdff, "DT_SYMINENT"},
	{0x6ffffdff, "DT_VALRNGHI"},
	{0x6ffffe00, "DT_ADDRRNGLO"},
	{0x6ffffef5, "DT_GNU_HASH"},
	{0x6ffffef6, "DT_TLSDESC_PLT"},
	{0x6ffffef7, "DT_TLSDESC_GOT"},
	{0x6ffffef8, "DT_GNU_CONFLICT"},
	{0x6ffffef9, "DT_GNU_LIBLIST"},
	{0x6ffffefa, "DT_CONFIG"},
	{0x6ffffefb, "DT_DEPAUDIT"},
	{0x6ffffefc, "DT_AUDIT"},
	{0x6ffffefd, "DT_PLTPAD"},
	{0x6ffffefe, "DT_MOVETAB"},
	{0x6ffffeff, "DT_SYMINFO"},
	{0x6ffffeff, "DT_ADDRRNGHI"},
	{0x6ffffff0, "DT_VERSYM"},
	{0x6ffffff9, "DT_RELACOUNT"},
	{0x6ffffffa, "DT_RELCOUNT"},
	{0x6ffffffb, "DT_FLAGS_1"},
	{0x6ffffffc, "DT_VERDEF"},
	{0x6ffffffd, "DT_VERDEFNUM"},
	{0x6ffffffe, "DT_VERNEED"},
	{0x6fffffff, "DT_VERNEEDNUM"},
	{0x70000000, "DT_LOPROC"},
	// We don't list the processor-dependent DynTags,
	// as the values overlap.
	{0x7ffffffd, "DT_AUXILIARY"},
	{0x7ffffffe, "DT_USED"},
	{0x7fffffff, "DT_FILTER"},
}

func (i DynTag) String() string   { return stringName(uint32(i), dtStrings, false) }
func (i DynTag) GoString() string { return stringName(uint32(i), dtStrings, true) }

// DT_FLAGS values.
type DynFlag int

const (
	DF_ORIGIN DynFlag = 0x0001 /* Indicates that the object being loaded may
	   make reference to the
	   $ORIGIN substitution string */
	DF_SYMBOLIC DynFlag = 0x0002 /* Indicates "symbolic" linking. */
	DF_TEXTREL  DynFlag = 0x0004 /* Indicates there may be relocations in non-writable segments. */
	DF_BIND_NOW DynFlag = 0x0008 /* Indicates that the dynamic linker should
	   process all relocations for the object
	   containing this entry before transferring
	   control to the program. */
	DF_STATIC_TLS DynFlag = 0x0010 /* Indicates that the shared object or
	   executable contains code using a static
	   thread-local storage scheme. */
)

var dflagStrings = []intName{
	{0x0001, "DF_ORIGIN"},
	{0x0002, "DF_SYMBOLIC"},
	{0x0004, "DF_TEXTREL"},
	{0x0008, "DF_BIND_NOW"},
	{0x0010, "DF_STATIC_TLS"},
}

func (i DynFlag) String() string   { return flagName(uint32(i), dflagStrings, false) }
func (i DynFlag) GoString() string { return flagName(uint32(i), dflagStrings, true) }

// DT_FLAGS_1 values.
type DynFlag1 uint32

const (
	// Indicates that all relocations for this object must be processed before
	// returning control to the program.
	DF_1_NOW DynFlag1 = 0x00000001
	// Unused.
	DF_1_GLOBAL DynFlag1 = 0x00000002
	// Indicates that the object is a member of a group.
	DF_1_GROUP DynFlag1 = 0x00000004
	// Indicates that the object cannot be deleted from a process.
	DF_1_NODELETE DynFlag1 = 0x00000008
	// Meaningful only for filters. Indicates that all associated filtees be
	// processed immediately.
	DF_1_LOADFLTR DynFlag1 = 0x00000010
	// Indicates that this object's initialization section be run before any other
	// objects loaded.
	DF_1_INITFIRST DynFlag1 = 0x00000020
	// Indicates that the object cannot be added to a running process with dlopen.
	DF_1_NOOPEN DynFlag1 = 0x00000040
	// Indicates the object requires $ORIGIN processing.
	DF_1_ORIGIN DynFlag1 = 0x00000080
	// Indicates that the object should use direct binding information.
	DF_1_DIRECT DynFlag1 = 0x00000100
	// Unused.
	DF_1_TRANS DynFlag1 = 0x00000200
	// Indicates that the objects symbol table is to interpose before all symbols
	// except the primary load object, which is typically the executable.
	DF_1_INTERPOSE DynFlag1 = 0x00000400
	// Indicates that the search for dependencies of this object ignores any
	// default library search paths.
	DF_1_NODEFLIB DynFlag1 = 0x00000800
	// Indicates that this object is not dumped by dldump. Candidates are objects
	// with no relocations that might get included when generating alternative
	// objects using.
	DF_1_NODUMP DynFlag1 = 0x00001000
	// Identifies this object as a configuration alternative object generated by
	// crle. Triggers the runtime linker to search for a configuration file $ORIGIN/ld.config.app-name.
	DF_1_CONFALT DynFlag1 = 0x00002000
	// Meaningful only for filtees. Terminates a filters search for any
	// further filtees.
	DF_1_ENDFILTEE DynFlag1 = 0x00004000
	// Indicates that this object has displacement relocations applied.
	DF_1_DISPRELDNE DynFlag1 = 0x00008000
	// Indicates that this object has displacement relocations pending.
	DF_1_DISPRELPND DynFlag1 = 0x00010000
	// Indicates that this object contains symbols that cannot be directly
	// bound to.
	DF_1_NODIRECT DynFlag1 = 0x00020000
	// Reserved for internal use by the kernel runtime-linker.
	DF_1_IGNMULDEF DynFlag1 = 0x00040000
	// Reserved for internal use by the kernel runtime-linker.
	DF_1_NOKSYMS DynFlag1 = 0x00080000
	// Reserved for internal use by the kernel runtime-linker.
	DF_1_NOHDR DynFlag1 = 0x00100000
	// Indicates that this object has been edited or has been modified since the
	// objects original construction by the link-editor.
	DF_1_EDITED DynFlag1 = 0x00200000
	// Reserved for internal use by the kernel runtime-linker.
	DF_1_NORELOC DynFlag1 = 0x00400000
	// Indicates that the object contains individual symbols that should interpose
	// before all symbols except the primary load object, which is typically the
	// executable.
	DF_1_SYMINTPOSE DynFlag1 = 0x00800000
	// Indicates that the executable requires global auditing.
	DF_1_GLOBAUDIT DynFlag1 = 0x01000000
	// Indicates that the object defines, or makes reference to singleton symbols.
	DF_1_SINGLETON DynFlag1 = 0x02000000
	// Indicates that the object is a stub.
	DF_1_STUB DynFlag1 = 0x04000000
	// Indicates that the object is a position-independent executable.
	DF_1_PIE DynFlag1 = 0x08000000
	// Indicates that the object is a kernel module.
	DF_1_KMOD DynFlag1 = 0x10000000
	// Indicates that the object is a weak standard filter.
	DF_1_WEAKFILTER DynFlag1 = 0x20000000
	// Unused.
	DF_1_NOCOMMON DynFlag1 = 0x40000000
)

var dflag1Strings = []intName{
	{0x00000001, "DF_1_NOW"},
	{0x00000002, "DF_1_GLOBAL"},
	{0x00000004, "DF_1_GROUP"},
	{0x00000008, "DF_1_NODELETE"},
	{0x00000010, "DF_1_LOADFLTR"},
	{0x00000020, "DF_1_INITFIRST"},
	{0x00000040, "DF_1_NOOPEN"},
	{0x00000080, "DF_1_ORIGIN"},
	{0x00000100, "DF_1_DIRECT"},
	{0x00000200, "DF_1_TRANS"},
	{0x00000400, "DF_1_INTERPOSE"},
	{0x00000800, "DF_1_NODEFLIB"},
	{0x00001000, "DF_1_NODUMP"},
	{0x00002000, "DF_1_CONFALT"},
	{0x00004000, "DF_1_ENDFILTEE"},
	{0x00008000, "DF_1_DISPRELDNE"},
	{0x00010000, "DF_1_DISPRELPND"},
	{0x00020000, "DF_1_NODIRECT"},
	{0x00040000, "DF_1_IGNMULDEF"},
	{0x00080000, "DF_1_NOKSYMS"},
	{0x00100000, "DF_1_NOHDR"},
	{0x00200000, "DF_1_EDITED"},
	{0x00400000, "DF_1_NORELOC"},
	{0x00800000, "DF_1_SYMINTPOSE"},
	{0x01000000, "DF_1_GLOBAUDIT"},
	{0x02000000, "DF_1_SINGLETON"},
	{0x04000000, "DF_1_STUB"},
	{0x08000000, "DF_1_PIE"},
	{0x10000000, "DF_1_KMOD"},
	{0x20000000, "DF_1_WEAKFILTER"},
	{0x40000000, "DF_1_NOCOMMON"},
}

func (i DynFlag1) String() string   { return flagName(uint32(i), dflag1Strings, false) }
func (i DynFlag1) GoString() string { return flagName(uint32(i), dflag1Strings, true) }

// NType values; used in core files.
type NType int

const (
	NT_PRSTATUS NType = 1 /* Process status. */
	NT_FPREGSET NType = 2 /* Floating point registers. */
	NT_PRPSINFO NType = 3 /* Process state info. */
)

var ntypeStrings = []intName{
	{1, "NT_PRSTATUS"},
	{2, "NT_FPREGSET"},
	{3, "NT_PRPSINFO"},
}

func (i NType) String() string   { return stringName(uint32(i), ntypeStrings, false) }
func (i NType) GoString() string { return stringName(uint32(i), ntypeStrings, true) }

/* Symbol Binding - ELFNN_ST_BIND - st_info */
type SymBind int

const (
	STB_LOCAL  SymBind = 0  /* Local symbol */
	STB_GLOBAL SymBind = 1  /* Global symbol */
	STB_WEAK   SymBind = 2  /* like global - lower precedence */
	STB_LOOS   SymBind = 10 /* Reserved range for operating system */
	STB_HIOS   SymBind = 12 /*   specific semantics. */
	STB_LOPROC SymBind = 13 /* reserved range for processor */
	STB_HIPROC SymBind = 15 /*   specific semantics. */
)

var stbStrings = []intName{
	{0, "STB_LOCAL"},
	{1, "STB_GLOBAL"},
	{2, "STB_WEAK"},
	{10, "STB_LOOS"},
	{12, "STB_HIOS"},
	{13, "STB_LOPROC"},
	{15, "STB_HIPROC"},
}

func (i SymBind) String() string   { return stringName(uint32(i), stbStrings, false) }
func (i SymBind) GoString() string { return stringName(uint32(i), stbStrings, true) }

/* Symbol type - ELFNN_ST_TYPE - st_info */
type SymType int

const (
	STT_NOTYPE  SymType = 0  /* Unspecified type. */
	STT_OBJECT  SymType = 1  /* Data object. */
	STT_FUNC    SymType = 2  /* Function. */
	STT_SECTION SymType = 3  /* Section. */
	STT_FILE    SymType = 4  /* Source file. */
	STT_COMMON  SymType = 5  /* Uninitialized common block. */
	STT_TLS     SymType = 6  /* TLS object. */
	STT_LOOS    SymType = 10 /* Reserved range for operating system */
	STT_HIOS    SymType = 12 /*   specific semantics. */
	STT_LOPROC  SymType = 13 /* reserved range for processor */
	STT_HIPROC  SymType = 15 /*   specific semantics. */

	/* Non-standard symbol types. */
	STT_RELC      SymType = 8  /* Complex relocation expression. */
	STT_SRELC     SymType = 9  /* Signed complex relocation expression. */
	STT_GNU_IFUNC SymType = 10 /* Indirect code object. */
)

var sttStrings = []intName{
	{0, "STT_NOTYPE"},
	{1, "STT_OBJECT"},
	{2, "STT_FUNC"},
	{3, "STT_SECTION"},
	{4, "STT_FILE"},
	{5, "STT_COMMON"},
	{6, "STT_TLS"},
	{8, "STT_RELC"},
	{9, "STT_SRELC"},
	{10, "STT_LOOS"},
	{12, "STT_HIOS"},
	{13, "STT_LOPROC"},
	{15, "STT_HIPROC"},
}

func (i SymType) String() string   { return stringName(uint32(i), sttStrings, false) }
func (i SymType) GoString() string { return stringName(uint32(i), sttStrings, true) }

/* Symbol visibility - ELFNN_ST_VISIBILITY - st_other */
type SymVis int

const (
	STV_DEFAULT   SymVis = 0x0 /* Default visibility (see binding). */
	STV_INTERNAL  SymVis = 0x1 /* Special meaning in relocatable objects. */
	STV_HIDDEN    SymVis = 0x2 /* Not visible. */
	STV_PROTECTED SymVis = 0x3 /* Visible but not preemptible. */
)

var stvStrings = []intName{
	{0x0, "STV_DEFAULT"},
	{0x1, "STV_INTERNAL"},
	{0x2, "STV_HIDDEN"},
	{0x3, "STV_PROTECTED"},
}

func (i SymVis) String() string   { return stringName(uint32(i), stvStrings, false) }
func (i SymVis) GoString() string { return stringName(uint32(i), stvStrings, true) }

/*
 * Relocation types.
 */

// Relocation types for x86-64.
type R_X86_64 int

const (
	R_X86_64_NONE            R_X86_64 = 0  /* No relocation. */
	R_X86_64_64              R_X86_64 = 1  /* Add 64 bit symbol value. */
	R_X86_64_PC32            R_X86_64 = 2  /* PC-relative 32 bit signed sym value. */
	R_X86_64_GOT32           R_X86_64 = 3  /* PC-relative 32 bit GOT offset. */
	R_X86_64_PLT32           R_X86_64 = 4  /* PC-relative 32 bit PLT offset. */
	R_X86_64_COPY            R_X86_64 = 5  /* Copy data from shared object. */
	R_X86_64_GLOB_DAT        R_X86_64 = 6  /* Set GOT entry to data address. */
	R_X86_64_JMP_SLOT        R_X86_64 = 7  /* Set GOT entry to code address. */
	R_X86_64_RELATIVE        R_X86_64 = 8  /* Add load address of shared object. */
	R_X86_64_GOTPCREL        R_X86_64 = 9  /* Add 32 bit signed pcrel offset to GOT. */
	R_X86_64_32              R_X86_64 = 10 /* Add 32 bit zero extended symbol value */
	R_X86_64_32S             R_X86_64 = 11 /* Add 32 bit sign extended symbol value */
	R_X86_64_16              R_X86_64 = 12 /* Add 16 bit zero extended symbol value */
	R_X86_64_PC16            R_X86_64 = 13 /* Add 16 bit signed extended pc relative symbol value */
	R_X86_64_8               R_X86_64 = 14 /* Add 8 bit zero extended symbol value */
	R_X86_64_PC8             R_X86_64 = 15 /* Add 8 bit signed extended pc relative symbol value */
	R_X86_64_DTPMOD64        R_X86_64 = 16 /* ID of module containing symbol */
	R_X86_64_DTPOFF64        R_X86_64 = 17 /* Offset in TLS block */
	R_X86_64_TPOFF64         R_X86_64 = 18 /* Offset in static TLS block */
	R_X86_64_TLSGD           R_X86_64 = 19 /* PC relative offset to GD GOT entry */
	R_X86_64_TLSLD           R_X86_64 = 20 /* PC relative offset to LD GOT entry */
	R_X86_64_DTPOFF32        R_X86_64 = 21 /* Offset in TLS block */
	R_X86_64_GOTTPOFF        R_X86_64 = 22 /* PC relative offset to IE GOT entry */
	R_X86_64_TPOFF32         R_X86_64 = 23 /* Offset in static TLS block */
	R_X86_64_PC64            R_X86_64 = 24 /* PC relative 64-bit sign extended symbol value. */
	R_X86_64_GOTOFF64        R_X86_64 = 25
	R_X86_64_GOTPC32         R_X86_64 = 26
	R_X86_64_GOT64           R_X86_64 = 27
	R_X86_64_GOTPCREL64      R_X86_64 = 28
	R_X86_64_GOTPC64         R_X86_64 = 29
	R_X86_64_GOTPLT64        R_X86_64 = 30
	R_X86_64_PLTOFF64        R_X86_64 = 31
	R_X86_64_SIZE32          R_X86_64 = 32
	R_X86_64_SIZE64          R_X86_64 = 33
	R_X86_64_GOTPC32_TLSDESC R_X86_64 = 34
	R_X86_64_TLSDESC_CALL    R_X86_64 = 35
	R_X86_64_TLSDESC         R_X86_64 = 36
	R_X86_64_IRELATIVE       R_X86_64 = 37
	R_X86_64_RELATIVE64      R_X86_64 = 38
	R_X86_64_PC32_BND        R_X86_64 = 39
	R_X86_64_PLT32_BND       R_X86_64 = 40
	R_X86_64_GOTPCRELX       R_X86_64 = 41
	R_X86_64_REX_GOTPCRELX   R_X86_64 = 42
)

var rx86_64Strings = []intName{
	{0, "R_X86_64_NONE"},
	{1, "R_X86_64_64"},
	{2, "R_X86_64_PC32"},
	{3, "R_X86_64_GOT32"},
	{4, "R_X86_64_PLT32"},
	{5, "R_X86_64_COPY"},
	{6, "R_X86_64_GLOB_DAT"},
	{7, "R_X86_64_JMP_SLOT"},
	{8, "R_X86_64_RELATIVE"},
	{9, "R_X86_64_GOTPCREL"},
	{10, "R_X86_64_32"},
	{11, "R_X86_64_32S"},
	{12, "R_X86_64_16"},
	{13, "R_X86_64_PC16"},
	{14, "R_X86_64_8"},
	{15, "R_X86_64_PC8"},
	{16, "R_X86_64_DTPMOD64"},
	{17, "R_X86_64_DTPOFF64"},
	{18, "R_X86_64_TPOFF64"},
	{19, "R_X86_64_TLSGD"},
	{20, "R_X86_64_TLSLD"},
	{21, "R_X86_64_DTPOFF32"},
	{22, "R_X86_64_GOTTPOFF"},
	{23, "R_X86_64_TPOFF32"},
	{24, "R_X86_64_PC64"},
	{25, "R_X86_64_GOTOFF64"},
	{26, "R_X86_64_GOTPC32"},
	{27, "R_X86_64_GOT64"},
	{28, "R_X86_64_GOTPCREL64"},
	{29, "R_X86_64_GOTPC64"},
	{30, "R_X86_64_GOTPLT64"},
	{31, "R_X86_64_PLTOFF64"},
	{32, "R_X86_64_SIZE32"},
	{33, "R_X86_64_SIZE64"},
	{34, "R_X86_64_GOTPC32_TLSDESC"},
	{35, "R_X86_64_TLSDESC_CALL"},
	{36, "R_X86_64_TLSDESC"},
	{37, "R_X86_64_IRELATIVE"},
	{38, "R_X86_64_RELATIVE64"},
	{39, "R_X86_64_PC32_BND"},
	{40, "R_X86_64_PLT32_BND"},
	{41, "R_X86_64_GOTPCRELX"},
	{42, "R_X86_64_REX_GOTPCRELX"},
}

func (i R_X86_64) String() string   { return stringName(uint32(i), rx86_64Strings, false) }
func (i R_X86_64) GoString() string { return stringName(uint32(i), rx86_64Strings, true) }

// Relocation types for AArch64 (aka arm64)
type R_AARCH64 int

const (
	R_AARCH64_NONE                            R_AARCH64 = 0
	R_AARCH64_P32_ABS32                       R_AARCH64 = 1
	R_AARCH64_P32_ABS16                       R_AARCH64 = 2
	R_AARCH64_P32_PREL32                      R_AARCH64 = 3
	R_AARCH64_P32_PREL16                      R_AARCH64 = 4
	R_AARCH64_P32_MOVW_UABS_G0                R_AARCH64 = 5
	R_AARCH64_P32_MOVW_UABS_G0_NC             R_AARCH64 = 6
	R_AARCH64_P32_MOVW_UABS_G1                R_AARCH64 = 7
	R_AARCH64_P32_MOVW_SABS_G0                R_AARCH64 = 8
	R_AARCH64_P32_LD_PREL_LO19                R_AARCH64 = 9
	R_AARCH64_P32_ADR_PREL_LO21               R_AARCH64 = 10
	R_AARCH64_P32_ADR_PREL_PG_HI21            R_AARCH64 = 11
	R_AARCH64_P32_ADD_ABS_LO12_NC             R_AARCH64 = 12
	R_AARCH64_P32_LDST8_ABS_LO12_NC           R_AARCH64 = 13
	R_AARCH64_P32_LDST16_ABS_LO12_NC          R_AARCH64 = 14
	R_AARCH64_P32_LDST32_ABS_LO12_NC          R_AARCH64 = 15
	R_AARCH64_P32_LDST64_ABS_LO12_NC          R_AARCH64 = 16
	R_AARCH64_P32_LDST128_ABS_LO12_NC         R_AARCH64 = 17
	R_AARCH64_P32_TSTBR14                     R_AARCH64 = 18
	R_AARCH64_P32_CONDBR19                    R_AARCH64 = 19
	R_AARCH64_P32_JUMP26                      R_AARCH64 = 20
	R_AARCH64_P32_CALL26                      R_AARCH64 = 21
	R_AARCH64_P32_GOT_LD_PREL19               R_AARCH64 = 25
	R_AARCH64_P32_ADR_GOT_PAGE                R_AARCH64 = 26
	R_AARCH64_P32_LD32_GOT_LO12_NC            R_AARCH64 = 27
	R_AARCH64_P32_TLSGD_ADR_PAGE21            R_AARCH64 = 81
	R_AARCH64_P32_TLSGD_ADD_LO12_NC           R_AARCH64 = 82
	R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21   R_AARCH64 = 103
	R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC R_AARCH64 = 104
	R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19    R_AARCH64 = 105
	R_AARCH64_P32_TLSLE_MOVW_TPREL_G1         R_AARCH64 = 106
	R_AARCH64_P32_TLSLE_MOVW_TPREL_G0         R_AARCH64 = 107
	R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC      R_AARCH64 = 108
	R_AARCH64_P32_TLSLE_ADD_TPREL_HI12        R_AARCH64 = 109
	R_AARCH64_P32_TLSLE_ADD_TPREL_LO12        R_AARCH64 = 110
	R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC     R_AARCH64 = 111
	R_AARCH64_P32_TLSDESC_LD_PREL19           R_AARCH64 = 122
	R_AARCH64_P32_TLSDESC_ADR_PREL21          R_AARCH64 = 123
	R_AARCH64_P32_TLSDESC_ADR_PAGE21          R_AARCH64 = 124
	R_AARCH64_P32_TLSDESC_LD32_LO12_NC        R_AARCH64 = 125
	R_AARCH64_P32_TLSDESC_ADD_LO12_NC         R_AARCH64 = 126
	R_AARCH64_P32_TLSDESC_CALL                R_AARCH64 = 127
	R_AARCH64_P32_COPY                        R_AARCH64 = 180
	R_AARCH64_P32_GLOB_DAT                    R_AARCH64 = 181
	R_AARCH64_P32_JUMP_SLOT                   R_AARCH64 = 182
	R_AARCH64_P32_RELATIVE                    R_AARCH64 = 183
	R_AARCH64_P32_TLS_DTPMOD                  R_AARCH64 = 184
	R_AARCH64_P32_TLS_DTPREL                  R_AARCH64 = 185
	R_AARCH64_P32_TLS_TPREL                   R_AARCH64 = 186
	R_AARCH64_P32_TLSDESC                     R_AARCH64 = 187
	R_AARCH64_P32_IRELATIVE                   R_AARCH64 = 188
	R_AARCH64_NULL                            R_AARCH64 = 256
	R_AARCH64_ABS64                           R_AARCH64 = 257
	R_AARCH64_ABS32                           R_AARCH64 = 258
	R_AARCH64_ABS16                           R_AARCH64 = 259
	R_AARCH64_PREL64                          R_AARCH64 = 260
	R_AARCH64_PREL32                          R_AARCH64 = 261
	R_AARCH64_PREL16                          R_AARCH64 = 262
	R_AARCH64_MOVW_UABS_G0                    R_AARCH64 = 263
	R_AARCH64_MOVW_UABS_G0_NC                 R_AARCH64 = 264
	R_AARCH64_MOVW_UABS_G1                    R_AARCH64 = 265
	R_AARCH64_MOVW_UABS_G1_NC                 R_AARCH64 = 266
	R_AARCH64_MOVW_UABS_G2                    R_AARCH64 = 267
	R_AARCH64_MOVW_UABS_G2_NC                 R_AARCH64 = 268
	R_AARCH64_MOVW_UABS_G3                    R_AARCH64 = 269
	R_AARCH64_MOVW_SABS_G0                    R_AARCH64 = 270
	R_AARCH64_MOVW_SABS_G1                    R_AARCH64 = 271
	R_AARCH64_MOVW_SABS_G2                    R_AARCH64 = 272
	R_AARCH64_LD_PREL_LO19                    R_AARCH64 = 273
	R_AARCH64_ADR_PREL_LO21                   R_AARCH64 = 274
	R_AARCH64_ADR_PREL_PG_HI21                R_AARCH64 = 275
	R_AARCH64_ADR_PREL_PG_HI21_NC             R_AARCH64 = 276
	R_AARCH64_ADD_ABS_LO12_NC                 R_AARCH64 = 277
	R_AARCH64_LDST8_ABS_LO12_NC               R_AARCH64 = 278
	R_AARCH64_TSTBR14                         R_AARCH64 = 279
	R_AARCH64_CONDBR19                        R_AARCH64 = 280
	R_AARCH64_JUMP26                          R_AARCH64 = 282
	R_AARCH64_CALL26                          R_AARCH64 = 283
	R_AARCH64_LDST16_ABS_LO12_NC              R_AARCH64 = 284
	R_AARCH64_LDST32_ABS_LO12_NC              R_AARCH64 = 285
	R_AARCH64_LDST64_ABS_LO12_NC              R_AARCH64 = 286
	R_AARCH64_LDST128_ABS_LO12_NC             R_AARCH64 = 299
	R_AARCH64_GOT_LD_PREL19                   R_AARCH64 = 309
	R_AARCH64_LD64_GOTOFF_LO15                R_AARCH64 = 310
	R_AARCH64_ADR_GOT_PAGE                    R_AARCH64 = 311
	R_AARCH64_LD64_GOT_LO12_NC                R_AARCH64 = 312
	R_AARCH64_LD64_GOTPAGE_LO15               R_AARCH64 = 313
	R_AARCH64_TLSGD_ADR_PREL21                R_AARCH64 = 512
	R_AARCH64_TLSGD_ADR_PAGE21                R_AARCH64 = 513
	R_AARCH64_TLSGD_ADD_LO12_NC               R_AARCH64 = 514
	R_AARCH64_TLSGD_MOVW_G1                   R_AARCH64 = 515
	R_AARCH64_TLSGD_MOVW_G0_NC                R_AARCH64 = 516
	R_AARCH64_TLSLD_ADR_PREL21                R_AARCH64 = 517
	R_AARCH64_TLSLD_ADR_PAGE21                R_AARCH64 = 518
	R_AARCH64_TLSIE_MOVW_GOTTPREL_G1          R_AARCH64 = 539
	R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC       R_AARCH64 = 540
	R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21       R_AARCH64 = 541
	R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC     R_AARCH64 = 542
	R_AARCH64_TLSIE_LD_GOTTPREL_PREL19        R_AARCH64 = 543
	R_AARCH64_TLSLE_MOVW_TPREL_G2             R_AARCH64 = 544
	R_AARCH64_TLSLE_MOVW_TPREL_G1             R_AARCH64 = 545
	R_AARCH64_TLSLE_MOVW_TPREL_G1_NC          R_AARCH64 = 546
	R_AARCH64_TLSLE_MOVW_TPREL_G0             R_AARCH64 = 547
	R_AARCH64_TLSLE_MOVW_TPREL_G0_NC          R_AARCH64 = 548
	R_AARCH64_TLSLE_ADD_TPREL_HI12            R_AARCH64 = 549
	R_AARCH64_TLSLE_ADD_TPREL_LO12            R_AARCH64 = 550
	R_AARCH64_TLSLE_ADD_TPREL_LO12_NC         R_AARCH64 = 551
	R_AARCH64_TLSDESC_LD_PREL19               R_AARCH64 = 560
	R_AARCH64_TLSDESC_ADR_PREL21              R_AARCH64 = 561
	R_AARCH64_TLSDESC_ADR_PAGE21              R_AARCH64 = 562
	R_AARCH64_TLSDESC_LD64_LO12_NC            R_AARCH64 = 563
	R_AARCH64_TLSDESC_ADD_LO12_NC             R_AARCH64 = 564
	R_AARCH64_TLSDESC_OFF_G1                  R_AARCH64 = 565
	R_AARCH64_TLSDESC_OFF_G0_NC               R_AARCH64 = 566
	R_AARCH64_TLSDESC_LDR                     R_AARCH64 = 567
	R_AARCH64_TLSDESC_ADD                     R_AARCH64 = 568
	R_AARCH64_TLSDESC_CALL                    R_AARCH64 = 569
	R_AARCH64_TLSLE_LDST128_TPREL_LO12        R_AARCH64 = 570
	R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC     R_AARCH64 = 571
	R_AARCH64_TLSLD_LDST128_DTPREL_LO12       R_AARCH64 = 572
	R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC    R_AARCH64 = 573
	R_AARCH64_COPY                            R_AARCH64 = 1024
	R_AARCH64_GLOB_DAT                        R_AARCH64 = 1025
	R_AARCH64_JUMP_SLOT                       R_AARCH64 = 1026
	R_AARCH64_RELATIVE                        R_AARCH64 = 1027
	R_AARCH64_TLS_DTPMOD64                    R_AARCH64 = 1028
	R_AARCH64_TLS_DTPREL64                    R_AARCH64 = 1029
	R_AARCH64_TLS_TPREL64                     R_AARCH64 = 1030
	R_AARCH64_TLSDESC                         R_AARCH64 = 1031
	R_AARCH64_IRELATIVE                       R_AARCH64 = 1032
)

var raarch64Strings = []intName{
	{0, "R_AARCH64_NONE"},
	{1, "R_AARCH64_P32_ABS32"},
	{2, "R_AARCH64_P32_ABS16"},
	{3, "R_AARCH64_P32_PREL32"},
	{4, "R_AARCH64_P32_PREL16"},
	{5, "R_AARCH64_P32_MOVW_UABS_G0"},
	{6, "R_AARCH64_P32_MOVW_UABS_G0_NC"},
	{7, "R_AARCH64_P32_MOVW_UABS_G1"},
	{8, "R_AARCH64_P32_MOVW_SABS_G0"},
	{9, "R_AARCH64_P32_LD_PREL_LO19"},
	{10, "R_AARCH64_P32_ADR_PREL_LO21"},
	{11, "R_AARCH64_P32_ADR_PREL_PG_HI21"},
	{12, "R_AARCH64_P32_ADD_ABS_LO12_NC"},
	{13, "R_AARCH64_P32_LDST8_ABS_LO12_NC"},
	{14, "R_AARCH64_P32_LDST16_ABS_LO12_NC"},
	{15, "R_AARCH64_P32_LDST32_ABS_LO12_NC"},
	{16, "R_AARCH64_P32_LDST64_ABS_LO12_NC"},
	{17, "R_AARCH64_P32_LDS
"""




```