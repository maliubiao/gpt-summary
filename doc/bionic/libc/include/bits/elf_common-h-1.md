Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze the provided C header file (`elf_common.h`) and explain its function within the context of Android's Bionic library. This involves identifying the constants defined, categorizing them, explaining their purpose, and illustrating their connection to Android's dynamic linking and execution environment. The request also specifically asks for information about libc functions, dynamic linking, debugging with Frida, and common usage errors.

2. **Initial Scan and Categorization:** I first scan the file to get a general idea of the content. I immediately recognize a pattern:  `#define` statements defining constants. These constants seem to fall into several categories related to the ELF file format:

    * **Dynamic Linking Flags:**  Constants starting with `DF_` and `DF_1_` clearly relate to flags used during dynamic linking.
    * **Library Linking Flags:** Constants starting with `LL_` likely relate to library linking requirements.
    * **Note Section Types:** Constants starting with `NT_` define types of notes found in ELF files.
    * **Symbol Table Information:** Constants starting with `STB_`, `STT_`, `STV_` pertain to symbol binding, type, and visibility.
    * **Symbol Versioning:** Constants starting with `VER_` are for symbol versioning.
    * **Syminfo Flags:** Constants starting with `SYMINFO_FLG_` and `SYMINFO_BT_` relate to symbol information.
    * **Compression Types:** Constants starting with `ELFCOMPRESS_` define compression algorithms for sections.
    * **Auxiliary Vector Types (Commented Out):**  Constants starting with `AT_` are present but commented out, indicating they might be relevant but not actively used in this specific context.
    * **Relocation Types:**  Constants starting with `R_` define relocation types for various architectures.
    * **BSD Flags:** Constants starting with `ELF_BSDF_` are related to BSD-specific flags.

3. **Prioritize and Elaborate:**  I realize that focusing on the core functionalities is key. Dynamic linking is explicitly mentioned, so I prioritize explaining the `DF_`, `DF_1_`, `LL_`, symbol table, and relocation constants.

4. **Explain ELF Concepts:**  To make the explanation understandable, I need to introduce basic ELF concepts like:

    * **Dynamic Linking:** What it is and why it's important.
    * **Shared Objects (.so):** Their role in dynamic linking.
    * **Relocation:**  The process of adjusting addresses in shared objects.
    * **Global Offset Table (GOT):**  Used to access global data.
    * **Procedure Linkage Table (PLT):** Used to call functions in shared objects.
    * **Symbol Table:** Stores information about symbols (functions, variables).
    * **Note Sections:**  Hold additional information about the ELF file.
    * **Thread-Local Storage (TLS):**  A mechanism for thread-specific data.
    * **Auxiliary Vector:** A way for the kernel to pass information to the dynamic linker and program.

5. **Connect to Android:**  Since the request is specific to Android, I need to illustrate how these ELF concepts apply to the Android environment. This involves mentioning:

    * **Bionic:**  As the C library and dynamic linker.
    * **.so files:** The standard extension for shared libraries in Android.
    * **`dlopen`, `dlsym`, `dlclose`:**  The libc functions used for dynamic loading.
    * **`$ORIGIN`:**  A dynamic string token used in library paths.
    * **Position-Independent Executables (PIE):** Security feature in Android.
    * **ASLR (Address Space Layout Randomization):** Security feature related to `NT_FREEBSD_FCTL_ASLR_DISABLE`.
    * **NDK:**  How native code interacts with dynamic linking.

6. **Provide Examples:** Concrete examples make the explanation clearer. I need to:

    * **Illustrate relocation:** Show how different relocation types modify addresses.
    * **Show a sample .so layout:** Demonstrate the GOT, PLT, and code sections.
    * **Give a Frida hook example:** Show how to intercept dynamic linking functions.
    * **Provide common usage errors:** Highlight potential pitfalls in dynamic linking.

7. **Address Specific Request Points:** I ensure I cover all the explicit points raised in the prompt, such as:

    * **Listing functions:**  Although it's primarily constants, I list the *concepts* the constants relate to, which implicitly covers the functions involved in using those concepts (like dynamic linking functions).
    * **Detailed explanation of libc functions:** I focus on the dynamic linking functions (`dlopen`, etc.) as they are most relevant to the content of the header.
    * **Dynamic linker details:**  This is a major focus, covering relocation, GOT, PLT, and the loading process.
    * **Logical reasoning with input/output:** This is more applicable to actual code execution. Here, I infer the *effect* of certain flags (e.g., `DF_1_BIND_NOW` leads to immediate symbol resolution).
    * **Frida hook examples:**  Crucial for demonstrating debugging.
    * **Tracing the path from framework/NDK:**  Explaining the high-level flow of how Android components lead to dynamic linking.
    * **Summarizing the functionality:**  Providing a concise overview.

8. **Structure and Language:** I organize the information logically with clear headings and use precise language. Since the request is in Chinese, the response must also be in Chinese.

9. **Refinement and Review:** After drafting the initial response, I review it to ensure accuracy, clarity, and completeness. I check if I have addressed all aspects of the prompt and if the explanations are easy to understand. I correct any technical inaccuracies or unclear phrasing. For instance, I make sure to explain *why* certain flags are used and *what* effect they have.

By following these steps, I can construct a comprehensive and informative answer that addresses all the requirements of the user's request. The key is to break down the complex information into manageable chunks, explain the underlying concepts, and illustrate their practical application within the Android ecosystem.
这是对 `bionic/libc/include/bits/elf_common.h` 文件的功能归纳，作为第二部分。

**文件功能归纳:**

总的来说，`elf_common.h` 文件定义了与 **ELF (Executable and Linkable Format)** 文件格式相关的各种常量和宏定义。这些定义在 Android 的 Bionic 库中被广泛使用，尤其是在动态链接器 (`linker`) 和 C 库的其他部分。 它的主要目的是提供一种统一的方式来解释和操作 ELF 文件结构中的各种字段和标志。

更具体地说，该文件涵盖了以下几个关键领域：

1. **动态链接标志 (Dynamic Linking Flags):**  定义了用于控制动态链接器行为的各种标志，例如是否立即解析符号、是否将库标记为全局可见、是否禁止 `dlopen()` 加载等等。这些标志在加载和链接共享库时起着至关重要的作用。

2. **库链接标志 (Library Linking Flags):**  定义了在查找和链接共享库时使用的标志，例如是否需要完全匹配库名、是否忽略版本不兼容性等。

3. **Note Section 类型 (Note Section Types):** 定义了 ELF 文件中 Note Section 的各种类型，这些 Section 用于存储额外的非执行信息，例如操作系统标识、构建信息等。

4. **符号表信息 (Symbol Table Information):**  定义了符号表条目中使用的各种属性，例如符号绑定类型 (本地、全局、弱)、符号类型 (函数、对象、节) 和符号可见性。这些定义对于解析和链接符号至关重要。

5. **符号版本控制 (Symbol Versioning):**  定义了用于符号版本控制的标志和宏，允许在不同的共享库版本中管理相同的符号名称。

6. **Syminfo 标志 (Syminfo Flags):** 定义了 `syminfo` 表中使用的标志，该表提供了关于符号绑定的额外信息，例如是否直接绑定到定义对象、是否是复制重定位等。

7. **压缩类型 (Compression Types):**  定义了用于压缩 ELF 文件节的各种算法。

8. **重定位类型 (Relocation Types):**  定义了各种体系结构 (x86, ARM, AArch64, RISC-V, PowerPC, SPARC) 的重定位类型。重定位是动态链接的关键过程，用于在加载时调整代码和数据中的地址。

9. **BSD 标志 (BSD Flags):**  定义了与 FreeBSD 兼容性相关的标志。

**与 Android 功能的关系：**

这些定义直接影响着 Android 平台上应用程序和共享库的加载、链接和执行。例如：

* **`DF_1_BIND_NOW`:**  如果共享库设置了这个标志，动态链接器会在加载时立即解析所有符号，而不是延迟到首次使用时。这会影响启动时间，但可以避免运行时出现未找到符号的错误。
* **`DF_1_GLOBAL`:**  这个标志允许共享库中的符号对其他所有加载的共享库可见。
* **`R_AARCH64_JUMP_SLOT` / `R_X86_64_JMP_SLOT` 等重定位类型:**  这些定义告诉动态链接器如何修改 GOT (Global Offset Table) 条目，以便在运行时调用共享库中的函数。
* **`NT_GNU_BUILD_ID`:**  用于标识构建的唯一 ID，可能用于调试和问题追踪。

**总结:**

`elf_common.h` 文件是 Bionic 库中一个基础性的头文件，它抽象了 ELF 文件格式的底层细节，并为 Bionic 的各个组件 (特别是动态链接器) 提供了操作和理解 ELF 文件的标准定义。它不包含任何函数实现，而是定义了用于描述和控制 ELF 文件行为的常量。理解这些定义对于深入了解 Android 的动态链接机制至关重要。

总而言之，这个文件就像一本 ELF 文件格式的 "词汇表"，让 Bionic 能够正确地解析、加载和链接 Android 系统上的可执行文件和共享库。

Prompt: 
```
这是目录为bionic/libc/include/bits/elf_common.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能

"""
#define	DF_STATIC_TLS	0x0010	/* Indicates that the shared object or
				   executable contains code using a static
				   thread-local storage scheme. */

/* Values for DT_FLAGS_1 */
#define	DF_1_BIND_NOW	0x00000001	/* Same as DF_BIND_NOW */
#define	DF_1_GLOBAL	0x00000002	/* Set the RTLD_GLOBAL for object */
#define	DF_1_NODELETE	0x00000008	/* Set the RTLD_NODELETE for object */
#define	DF_1_LOADFLTR	0x00000010	/* Immediate loading of filtees */
#define	DF_1_NOOPEN     0x00000040	/* Do not allow loading on dlopen() */
#define	DF_1_ORIGIN	0x00000080	/* Process $ORIGIN */
#define	DF_1_INTERPOSE	0x00000400	/* Interpose all objects but main */
#define	DF_1_NODEFLIB	0x00000800	/* Do not search default paths */
#define	DF_1_PIE	0x08000000	/* Is position-independent executable */

/* Values for l_flags. */
#define	LL_NONE			0x0	/* no flags */
#define	LL_EXACT_MATCH		0x1	/* require an exact match */
#define	LL_IGNORE_INT_VER	0x2	/* ignore version incompatibilities */
#define	LL_REQUIRE_MINOR	0x4
#define	LL_EXPORTS		0x8
#define	LL_DELAY_LOAD		0x10
#define	LL_DELTA		0x20

/* Note section names */
#define	ELF_NOTE_FREEBSD	"FreeBSD"
#define	ELF_NOTE_NETBSD		"NetBSD"
#define	ELF_NOTE_SOLARIS	"SUNW Solaris"
#define	ELF_NOTE_GNU		"GNU"

/* Values for n_type used in executables. */
#define	NT_FREEBSD_ABI_TAG	1
#define	NT_FREEBSD_NOINIT_TAG	2
#define	NT_FREEBSD_ARCH_TAG	3
#define	NT_FREEBSD_FEATURE_CTL	4

/* NT_FREEBSD_FEATURE_CTL desc[0] bits */
#define	NT_FREEBSD_FCTL_ASLR_DISABLE	0x00000001
#define	NT_FREEBSD_FCTL_PROTMAX_DISABLE	0x00000002
#define	NT_FREEBSD_FCTL_STKGAP_DISABLE	0x00000004
#define	NT_FREEBSD_FCTL_WXNEEDED	0x00000008
#define	NT_FREEBSD_FCTL_LA48		0x00000010
/* was ASG_DISABLE, do not reuse	0x00000020 */

/* Values for n_type.  Used in core files. */
#define	NT_PRSTATUS	1	/* Process status. */
#define	NT_FPREGSET	2	/* Floating point registers. */
#define	NT_PRPSINFO	3	/* Process state info. */
#define	NT_THRMISC	7	/* Thread miscellaneous info. */
#define	NT_PROCSTAT_PROC	8	/* Procstat proc data. */
#define	NT_PROCSTAT_FILES	9	/* Procstat files data. */
#define	NT_PROCSTAT_VMMAP	10	/* Procstat vmmap data. */
#define	NT_PROCSTAT_GROUPS	11	/* Procstat groups data. */
#define	NT_PROCSTAT_UMASK	12	/* Procstat umask data. */
#define	NT_PROCSTAT_RLIMIT	13	/* Procstat rlimit data. */
#define	NT_PROCSTAT_OSREL	14	/* Procstat osreldate data. */
#define	NT_PROCSTAT_PSSTRINGS	15	/* Procstat ps_strings data. */
#define	NT_PROCSTAT_AUXV	16	/* Procstat auxv data. */
#define	NT_PTLWPINFO		17	/* Thread ptrace miscellaneous info. */
#define	NT_PPC_VMX	0x100	/* PowerPC Altivec/VMX registers */
#define	NT_PPC_VSX	0x102	/* PowerPC VSX registers */
#define	NT_X86_SEGBASES	0x200	/* x86 FS/GS base addresses. */
#define	NT_X86_XSTATE	0x202	/* x86 XSAVE extended state. */
#define	NT_ARM_VFP	0x400	/* ARM VFP registers */
#define	NT_ARM_TLS	0x401	/* ARM TLS register */
#define	NT_ARM_ADDR_MASK	0x406	/* arm64 address mask (e.g. for TBI) */

/* GNU note types. */
#define	NT_GNU_ABI_TAG		1
#define	NT_GNU_HWCAP		2
#define	NT_GNU_BUILD_ID		3
#define	NT_GNU_GOLD_VERSION	4
#define	NT_GNU_PROPERTY_TYPE_0	5

#define	GNU_PROPERTY_LOPROC			0xc0000000
#define	GNU_PROPERTY_HIPROC			0xdfffffff

#define	GNU_PROPERTY_AARCH64_FEATURE_1_AND	0xc0000000

// android-removed: #define	GNU_PROPERTY_AARCH64_FEATURE_1_BTI	0x00000001
#define	GNU_PROPERTY_AARCH64_FEATURE_1_PAC	0x00000002

#define	GNU_PROPERTY_X86_FEATURE_1_AND		0xc0000002

#define	GNU_PROPERTY_X86_FEATURE_1_IBT		0x00000001
#define	GNU_PROPERTY_X86_FEATURE_1_SHSTK	0x00000002

/* Symbol Binding - ELFNN_ST_BIND - st_info */
#define	STB_LOCAL	0	/* Local symbol */
#define	STB_GLOBAL	1	/* Global symbol */
#define	STB_WEAK	2	/* like global - lower precedence */
#define	STB_LOOS	10	/* Start of operating system reserved range. */
#define	STB_GNU_UNIQUE	10	/* Unique symbol (GNU) */
#define	STB_HIOS	12	/* End of operating system reserved range. */
#define	STB_LOPROC	13	/* reserved range for processor */
#define	STB_HIPROC	15	/*   specific semantics. */

/* Symbol type - ELFNN_ST_TYPE - st_info */
#define	STT_NOTYPE	0	/* Unspecified type. */
#define	STT_OBJECT	1	/* Data object. */
#define	STT_FUNC	2	/* Function. */
#define	STT_SECTION	3	/* Section. */
#define	STT_FILE	4	/* Source file. */
#define	STT_COMMON	5	/* Uninitialized common block. */
#define	STT_TLS		6	/* TLS object. */
#define	STT_NUM		7
#define	STT_LOOS	10	/* Reserved range for operating system */
#define	STT_GNU_IFUNC	10
#define	STT_HIOS	12	/*   specific semantics. */
#define	STT_LOPROC	13	/* Start of processor reserved range. */
#define	STT_SPARC_REGISTER 13	/* SPARC register information. */
#define	STT_HIPROC	15	/* End of processor reserved range. */

/* Symbol visibility - ELFNN_ST_VISIBILITY - st_other */
#define	STV_DEFAULT	0x0	/* Default visibility (see binding). */
#define	STV_INTERNAL	0x1	/* Special meaning in relocatable objects. */
#define	STV_HIDDEN	0x2	/* Not visible. */
#define	STV_PROTECTED	0x3	/* Visible but not preemptible. */
#define	STV_EXPORTED	0x4
#define	STV_SINGLETON	0x5
#define	STV_ELIMINATE	0x6

/* Special symbol table indexes. */
#define	STN_UNDEF	0	/* Undefined symbol index. */

/* Symbol versioning flags. */
#define	VER_DEF_CURRENT	1
#define	VER_DEF_IDX(x)	VER_NDX(x)

#define	VER_FLG_BASE	0x01
#define	VER_FLG_WEAK	0x02

#define	VER_NEED_CURRENT	1
#define	VER_NEED_WEAK	(1u << 15)
#define	VER_NEED_HIDDEN	VER_NDX_HIDDEN
#define	VER_NEED_IDX(x)	VER_NDX(x)

#define	VER_NDX_LOCAL	0
#define	VER_NDX_GLOBAL	1
#define	VER_NDX_GIVEN	2

#define	VER_NDX_HIDDEN	(1u << 15)
#define	VER_NDX(x)	((x) & ~(1u << 15))

#define	CA_SUNW_NULL	0
#define	CA_SUNW_HW_1	1		/* first hardware capabilities entry */
#define	CA_SUNW_SF_1	2		/* first software capabilities entry */

/*
 * Syminfo flag values
 */
#define	SYMINFO_FLG_DIRECT	0x0001	/* symbol ref has direct association */
					/*	to object containing defn. */
#define	SYMINFO_FLG_PASSTHRU	0x0002	/* ignored - see SYMINFO_FLG_FILTER */
#define	SYMINFO_FLG_COPY	0x0004	/* symbol is a copy-reloc */
#define	SYMINFO_FLG_LAZYLOAD	0x0008	/* object containing defn should be */
					/*	lazily-loaded */
#define	SYMINFO_FLG_DIRECTBIND	0x0010	/* ref should be bound directly to */
					/*	object containing defn. */
#define	SYMINFO_FLG_NOEXTDIRECT	0x0020	/* don't let an external reference */
					/*	directly bind to this symbol */
#define	SYMINFO_FLG_FILTER	0x0002	/* symbol ref is associated to a */
#define	SYMINFO_FLG_AUXILIARY	0x0040	/* 	standard or auxiliary filter */

/*
 * Syminfo.si_boundto values.
 */
#define	SYMINFO_BT_SELF		0xffff	/* symbol bound to self */
#define	SYMINFO_BT_PARENT	0xfffe	/* symbol bound to parent */
#define	SYMINFO_BT_NONE		0xfffd	/* no special symbol binding */
#define	SYMINFO_BT_EXTERN	0xfffc	/* symbol defined as external */
#define	SYMINFO_BT_LOWRESERVE	0xff00	/* beginning of reserved entries */

/*
 * Syminfo version values.
 */
#define	SYMINFO_NONE		0	/* Syminfo version */
#define	SYMINFO_CURRENT		1
#define	SYMINFO_NUM		2

/* Values for ch_type (compressed section headers). */
#define	ELFCOMPRESS_ZLIB	1	/* ZLIB/DEFLATE */
#define	ELFCOMPRESS_ZSTD	2	/* Zstandard */
#define	ELFCOMPRESS_LOOS	0x60000000	/* OS-specific */
#define	ELFCOMPRESS_HIOS	0x6fffffff
#define	ELFCOMPRESS_LOPROC	0x70000000	/* Processor-specific */
#define	ELFCOMPRESS_HIPROC	0x7fffffff

#if 0 // android-added
/* Values for a_type. */
#define	AT_NULL		0	/* Terminates the vector. */
#define	AT_IGNORE	1	/* Ignored entry. */
#define	AT_EXECFD	2	/* File descriptor of program to load. */
#define	AT_PHDR		3	/* Program header of program already loaded. */
#define	AT_PHENT	4	/* Size of each program header entry. */
#define	AT_PHNUM	5	/* Number of program header entries. */
#define	AT_PAGESZ	6	/* Page size in bytes. */
#define	AT_BASE		7	/* Interpreter's base address. */
#define	AT_FLAGS	8	/* Flags. */
#define	AT_ENTRY	9	/* Where interpreter should transfer control. */
#define	AT_NOTELF	10	/* Program is not ELF ?? */
#define	AT_UID		11	/* Real uid. */
#define	AT_EUID		12	/* Effective uid. */
#define	AT_GID		13	/* Real gid. */
#define	AT_EGID		14	/* Effective gid. */
#define	AT_EXECPATH	15	/* Path to the executable. */
#define	AT_CANARY	16	/* Canary for SSP. */
#define	AT_CANARYLEN	17	/* Length of the canary. */
#define	AT_OSRELDATE	18	/* OSRELDATE. */
#define	AT_NCPUS	19	/* Number of CPUs. */
#define	AT_PAGESIZES	20	/* Pagesizes. */
#define	AT_PAGESIZESLEN	21	/* Number of pagesizes. */
#define	AT_TIMEKEEP	22	/* Pointer to timehands. */
#define	AT_STACKPROT	23	/* Initial stack protection. */
#define	AT_EHDRFLAGS	24	/* e_flags field from elf hdr */
#define	AT_HWCAP	25	/* CPU feature flags. */
#define	AT_HWCAP2	26	/* CPU feature flags 2. */
#define	AT_BSDFLAGS	27	/* ELF BSD Flags. */
#define	AT_ARGC		28	/* Argument count */
#define	AT_ARGV		29	/* Argument vector */
#define	AT_ENVC		30	/* Environment count */
#define	AT_ENVV		31	/* Environment vector */
#define	AT_PS_STRINGS	32	/* struct ps_strings */
#define	AT_FXRNG	33	/* Pointer to root RNG seed version. */
#define	AT_KPRELOAD	34	/* Base of vdso, preloaded by rtld */
#define	AT_USRSTACKBASE	35	/* Top of user stack */
#define	AT_USRSTACKLIM	36	/* Grow limit of user stack */

#define	AT_COUNT	37	/* Count of defined aux entry types. */
#endif // android-added

/*
 * Relocation types.
 *
 * All machine architectures are defined here to allow tools on one to
 * handle others.
 */

#define	R_386_NONE		0	/* No relocation. */
#define	R_386_32		1	/* Add symbol value. */
#define	R_386_PC32		2	/* Add PC-relative symbol value. */
#define	R_386_GOT32		3	/* Add PC-relative GOT offset. */
#define	R_386_PLT32		4	/* Add PC-relative PLT offset. */
#define	R_386_COPY		5	/* Copy data from shared object. */
#define	R_386_GLOB_DAT		6	/* Set GOT entry to data address. */
#define	R_386_JMP_SLOT		7	/* Set GOT entry to code address. */
#define	R_386_RELATIVE		8	/* Add load address of shared object. */
#define	R_386_GOTOFF		9	/* Add GOT-relative symbol address. */
#define	R_386_GOTPC		10	/* Add PC-relative GOT table address. */
#define	R_386_32PLT		11
#define	R_386_TLS_TPOFF		14	/* Negative offset in static TLS block */
#define	R_386_TLS_IE		15	/* Absolute address of GOT for -ve static TLS */
#define	R_386_TLS_GOTIE		16	/* GOT entry for negative static TLS block */
#define	R_386_TLS_LE		17	/* Negative offset relative to static TLS */
#define	R_386_TLS_GD		18	/* 32 bit offset to GOT (index,off) pair */
#define	R_386_TLS_LDM		19	/* 32 bit offset to GOT (index,zero) pair */
#define	R_386_16		20
#define	R_386_PC16		21
#define	R_386_8			22
#define	R_386_PC8		23
#define	R_386_TLS_GD_32		24	/* 32 bit offset to GOT (index,off) pair */
#define	R_386_TLS_GD_PUSH	25	/* pushl instruction for Sun ABI GD sequence */
#define	R_386_TLS_GD_CALL	26	/* call instruction for Sun ABI GD sequence */
#define	R_386_TLS_GD_POP	27	/* popl instruction for Sun ABI GD sequence */
#define	R_386_TLS_LDM_32	28	/* 32 bit offset to GOT (index,zero) pair */
#define	R_386_TLS_LDM_PUSH	29	/* pushl instruction for Sun ABI LD sequence */
#define	R_386_TLS_LDM_CALL	30	/* call instruction for Sun ABI LD sequence */
#define	R_386_TLS_LDM_POP	31	/* popl instruction for Sun ABI LD sequence */
#define	R_386_TLS_LDO_32	32	/* 32 bit offset from start of TLS block */
#define	R_386_TLS_IE_32		33	/* 32 bit offset to GOT static TLS offset entry */
#define	R_386_TLS_LE_32		34	/* 32 bit offset within static TLS block */
#define	R_386_TLS_DTPMOD32	35	/* GOT entry containing TLS index */
#define	R_386_TLS_DTPOFF32	36	/* GOT entry containing TLS offset */
#define	R_386_TLS_TPOFF32	37	/* GOT entry of -ve static TLS offset */
#define	R_386_SIZE32		38
#define	R_386_TLS_GOTDESC	39
#define	R_386_TLS_DESC_CALL	40
#define	R_386_TLS_DESC		41
#define	R_386_IRELATIVE		42	/* PLT entry resolved indirectly at runtime */
#define	R_386_GOT32X		43

#define	R_AARCH64_NONE		0	/* No relocation */
#define	R_AARCH64_ABS64		257	/* Absolute offset */
#define	R_AARCH64_ABS32		258	/* Absolute, 32-bit overflow check */
#define	R_AARCH64_ABS16		259	/* Absolute, 16-bit overflow check */
#define	R_AARCH64_PREL64	260	/* PC relative */
#define	R_AARCH64_PREL32	261	/* PC relative, 32-bit overflow check */
#define	R_AARCH64_PREL16	262	/* PC relative, 16-bit overflow check */
#define	R_AARCH64_TSTBR14	279	/* TBZ/TBNZ immediate */
#define	R_AARCH64_CONDBR19	280	/* Conditional branch immediate */
#define	R_AARCH64_JUMP26	282	/* Branch immediate */
#define	R_AARCH64_CALL26	283	/* Call immediate */
#define	R_AARCH64_COPY		1024	/* Copy data from shared object */
#define	R_AARCH64_GLOB_DAT	1025	/* Set GOT entry to data address */
#define	R_AARCH64_JUMP_SLOT	1026	/* Set GOT entry to code address */
#define	R_AARCH64_RELATIVE 	1027	/* Add load address of shared object */
#define	R_AARCH64_TLS_DTPREL64	1028
#define	R_AARCH64_TLS_DTPMOD64	1029
#define	R_AARCH64_TLS_TPREL64 	1030
#define	R_AARCH64_TLSDESC 	1031	/* Identify the TLS descriptor */
#define	R_AARCH64_IRELATIVE	1032

#define	R_ARM_NONE		0	/* No relocation. */
#define	R_ARM_PC24		1
#define	R_ARM_ABS32		2
#define	R_ARM_REL32		3
#define	R_ARM_PC13		4
#define	R_ARM_ABS16		5
#define	R_ARM_ABS12		6
#define	R_ARM_THM_ABS5		7
#define	R_ARM_ABS8		8
#define	R_ARM_SBREL32		9
#define	R_ARM_THM_PC22		10
#define	R_ARM_THM_PC8		11
#define	R_ARM_AMP_VCALL9	12
#define	R_ARM_SWI24		13
#define	R_ARM_THM_SWI8		14
#define	R_ARM_XPC25		15
#define	R_ARM_THM_XPC22		16
/* TLS relocations */
#define	R_ARM_TLS_DTPMOD32	17	/* ID of module containing symbol */
#define	R_ARM_TLS_DTPOFF32	18	/* Offset in TLS block */
#define	R_ARM_TLS_TPOFF32	19	/* Offset in static TLS block */
#define	R_ARM_COPY		20	/* Copy data from shared object. */
#define	R_ARM_GLOB_DAT		21	/* Set GOT entry to data address. */
#define	R_ARM_JUMP_SLOT		22	/* Set GOT entry to code address. */
#define	R_ARM_RELATIVE		23	/* Add load address of shared object. */
#define	R_ARM_GOTOFF		24	/* Add GOT-relative symbol address. */
#define	R_ARM_GOTPC		25	/* Add PC-relative GOT table address. */
#define	R_ARM_GOT32		26	/* Add PC-relative GOT offset. */
#define	R_ARM_PLT32		27	/* Add PC-relative PLT offset. */
#define	R_ARM_GNU_VTENTRY	100
#define	R_ARM_GNU_VTINHERIT	101
#define	R_ARM_RSBREL32		250
#define	R_ARM_THM_RPC22		251
#define	R_ARM_RREL32		252
#define	R_ARM_RABS32		253
#define	R_ARM_RPC24		254
#define	R_ARM_RBASE		255

/*	Name			Value	   Field	Calculation */
#define	R_IA_64_NONE		0	/* None */
#define	R_IA_64_IMM14		0x21	/* immediate14	S + A */
#define	R_IA_64_IMM22		0x22	/* immediate22	S + A */
#define	R_IA_64_IMM64		0x23	/* immediate64	S + A */
#define	R_IA_64_DIR32MSB	0x24	/* word32 MSB	S + A */
#define	R_IA_64_DIR32LSB	0x25	/* word32 LSB	S + A */
#define	R_IA_64_DIR64MSB	0x26	/* word64 MSB	S + A */
#define	R_IA_64_DIR64LSB	0x27	/* word64 LSB	S + A */
#define	R_IA_64_GPREL22		0x2a	/* immediate22	@gprel(S + A) */
#define	R_IA_64_GPREL64I	0x2b	/* immediate64	@gprel(S + A) */
#define	R_IA_64_GPREL32MSB	0x2c	/* word32 MSB	@gprel(S + A) */
#define	R_IA_64_GPREL32LSB	0x2d	/* word32 LSB	@gprel(S + A) */
#define	R_IA_64_GPREL64MSB	0x2e	/* word64 MSB	@gprel(S + A) */
#define	R_IA_64_GPREL64LSB	0x2f	/* word64 LSB	@gprel(S + A) */
#define	R_IA_64_LTOFF22		0x32	/* immediate22	@ltoff(S + A) */
#define	R_IA_64_LTOFF64I	0x33	/* immediate64	@ltoff(S + A) */
#define	R_IA_64_PLTOFF22	0x3a	/* immediate22	@pltoff(S + A) */
#define	R_IA_64_PLTOFF64I	0x3b	/* immediate64	@pltoff(S + A) */
#define	R_IA_64_PLTOFF64MSB	0x3e	/* word64 MSB	@pltoff(S + A) */
#define	R_IA_64_PLTOFF64LSB	0x3f	/* word64 LSB	@pltoff(S + A) */
#define	R_IA_64_FPTR64I		0x43	/* immediate64	@fptr(S + A) */
#define	R_IA_64_FPTR32MSB	0x44	/* word32 MSB	@fptr(S + A) */
#define	R_IA_64_FPTR32LSB	0x45	/* word32 LSB	@fptr(S + A) */
#define	R_IA_64_FPTR64MSB	0x46	/* word64 MSB	@fptr(S + A) */
#define	R_IA_64_FPTR64LSB	0x47	/* word64 LSB	@fptr(S + A) */
#define	R_IA_64_PCREL60B	0x48	/* immediate60 form1 S + A - P */
#define	R_IA_64_PCREL21B	0x49	/* immediate21 form1 S + A - P */
#define	R_IA_64_PCREL21M	0x4a	/* immediate21 form2 S + A - P */
#define	R_IA_64_PCREL21F	0x4b	/* immediate21 form3 S + A - P */
#define	R_IA_64_PCREL32MSB	0x4c	/* word32 MSB	S + A - P */
#define	R_IA_64_PCREL32LSB	0x4d	/* word32 LSB	S + A - P */
#define	R_IA_64_PCREL64MSB	0x4e	/* word64 MSB	S + A - P */
#define	R_IA_64_PCREL64LSB	0x4f	/* word64 LSB	S + A - P */
#define	R_IA_64_LTOFF_FPTR22	0x52	/* immediate22	@ltoff(@fptr(S + A)) */
#define	R_IA_64_LTOFF_FPTR64I	0x53	/* immediate64	@ltoff(@fptr(S + A)) */
#define	R_IA_64_LTOFF_FPTR32MSB	0x54	/* word32 MSB	@ltoff(@fptr(S + A)) */
#define	R_IA_64_LTOFF_FPTR32LSB	0x55	/* word32 LSB	@ltoff(@fptr(S + A)) */
#define	R_IA_64_LTOFF_FPTR64MSB	0x56	/* word64 MSB	@ltoff(@fptr(S + A)) */
#define	R_IA_64_LTOFF_FPTR64LSB	0x57	/* word64 LSB	@ltoff(@fptr(S + A)) */
#define	R_IA_64_SEGREL32MSB	0x5c	/* word32 MSB	@segrel(S + A) */
#define	R_IA_64_SEGREL32LSB	0x5d	/* word32 LSB	@segrel(S + A) */
#define	R_IA_64_SEGREL64MSB	0x5e	/* word64 MSB	@segrel(S + A) */
#define	R_IA_64_SEGREL64LSB	0x5f	/* word64 LSB	@segrel(S + A) */
#define	R_IA_64_SECREL32MSB	0x64	/* word32 MSB	@secrel(S + A) */
#define	R_IA_64_SECREL32LSB	0x65	/* word32 LSB	@secrel(S + A) */
#define	R_IA_64_SECREL64MSB	0x66	/* word64 MSB	@secrel(S + A) */
#define	R_IA_64_SECREL64LSB	0x67	/* word64 LSB	@secrel(S + A) */
#define	R_IA_64_REL32MSB	0x6c	/* word32 MSB	BD + A */
#define	R_IA_64_REL32LSB	0x6d	/* word32 LSB	BD + A */
#define	R_IA_64_REL64MSB	0x6e	/* word64 MSB	BD + A */
#define	R_IA_64_REL64LSB	0x6f	/* word64 LSB	BD + A */
#define	R_IA_64_LTV32MSB	0x74	/* word32 MSB	S + A */
#define	R_IA_64_LTV32LSB	0x75	/* word32 LSB	S + A */
#define	R_IA_64_LTV64MSB	0x76	/* word64 MSB	S + A */
#define	R_IA_64_LTV64LSB	0x77	/* word64 LSB	S + A */
#define	R_IA_64_PCREL21BI	0x79	/* immediate21 form1 S + A - P */
#define	R_IA_64_PCREL22		0x7a	/* immediate22	S + A - P */
#define	R_IA_64_PCREL64I	0x7b	/* immediate64	S + A - P */
#define	R_IA_64_IPLTMSB		0x80	/* function descriptor MSB special */
#define	R_IA_64_IPLTLSB		0x81	/* function descriptor LSB special */
#define	R_IA_64_SUB		0x85	/* immediate64	A - S */
#define	R_IA_64_LTOFF22X	0x86	/* immediate22	special */
#define	R_IA_64_LDXMOV		0x87	/* immediate22	special */
#define	R_IA_64_TPREL14		0x91	/* imm14	@tprel(S + A) */
#define	R_IA_64_TPREL22		0x92	/* imm22	@tprel(S + A) */
#define	R_IA_64_TPREL64I	0x93	/* imm64	@tprel(S + A) */
#define	R_IA_64_TPREL64MSB	0x96	/* word64 MSB	@tprel(S + A) */
#define	R_IA_64_TPREL64LSB	0x97	/* word64 LSB	@tprel(S + A) */
#define	R_IA_64_LTOFF_TPREL22	0x9a	/* imm22	@ltoff(@tprel(S+A)) */
#define	R_IA_64_DTPMOD64MSB	0xa6	/* word64 MSB	@dtpmod(S + A) */
#define	R_IA_64_DTPMOD64LSB	0xa7	/* word64 LSB	@dtpmod(S + A) */
#define	R_IA_64_LTOFF_DTPMOD22	0xaa	/* imm22	@ltoff(@dtpmod(S+A)) */
#define	R_IA_64_DTPREL14	0xb1	/* imm14	@dtprel(S + A) */
#define	R_IA_64_DTPREL22	0xb2	/* imm22	@dtprel(S + A) */
#define	R_IA_64_DTPREL64I	0xb3	/* imm64	@dtprel(S + A) */
#define	R_IA_64_DTPREL32MSB	0xb4	/* word32 MSB	@dtprel(S + A) */
#define	R_IA_64_DTPREL32LSB	0xb5	/* word32 LSB	@dtprel(S + A) */
#define	R_IA_64_DTPREL64MSB	0xb6	/* word64 MSB	@dtprel(S + A) */
#define	R_IA_64_DTPREL64LSB	0xb7	/* word64 LSB	@dtprel(S + A) */
#define	R_IA_64_LTOFF_DTPREL22	0xba	/* imm22	@ltoff(@dtprel(S+A)) */

#define	R_MIPS_NONE	0	/* No reloc */
#define	R_MIPS_16	1	/* Direct 16 bit */
#define	R_MIPS_32	2	/* Direct 32 bit */
#define	R_MIPS_REL32	3	/* PC relative 32 bit */
#define	R_MIPS_26	4	/* Direct 26 bit shifted */
#define	R_MIPS_HI16	5	/* High 16 bit */
#define	R_MIPS_LO16	6	/* Low 16 bit */
#define	R_MIPS_GPREL16	7	/* GP relative 16 bit */
#define	R_MIPS_LITERAL	8	/* 16 bit literal entry */
#define	R_MIPS_GOT16	9	/* 16 bit GOT entry */
#define	R_MIPS_PC16	10	/* PC relative 16 bit */
#define	R_MIPS_CALL16	11	/* 16 bit GOT entry for function */
#define	R_MIPS_GPREL32	12	/* GP relative 32 bit */
#define	R_MIPS_64	18	/* Direct 64 bit */
#define	R_MIPS_GOT_DISP	19
#define	R_MIPS_GOT_PAGE	20
#define	R_MIPS_GOT_OFST	21
#define	R_MIPS_GOT_HI16	22	/* GOT HI 16 bit */
#define	R_MIPS_GOT_LO16	23	/* GOT LO 16 bit */
#define	R_MIPS_SUB	24
#define	R_MIPS_CALLHI16 30	/* upper 16 bit GOT entry for function */
#define	R_MIPS_CALLLO16 31	/* lower 16 bit GOT entry for function */
#define	R_MIPS_JALR	37
#define	R_MIPS_TLS_GD	42
#define	R_MIPS_COPY	126
#define	R_MIPS_JUMP_SLOT	127

#define	R_PPC_NONE		0	/* No relocation. */
#define	R_PPC_ADDR32		1
#define	R_PPC_ADDR24		2
#define	R_PPC_ADDR16		3
#define	R_PPC_ADDR16_LO		4
#define	R_PPC_ADDR16_HI		5
#define	R_PPC_ADDR16_HA		6
#define	R_PPC_ADDR14		7
#define	R_PPC_ADDR14_BRTAKEN	8
#define	R_PPC_ADDR14_BRNTAKEN	9
#define	R_PPC_REL24		10
#define	R_PPC_REL14		11
#define	R_PPC_REL14_BRTAKEN	12
#define	R_PPC_REL14_BRNTAKEN	13
#define	R_PPC_GOT16		14
#define	R_PPC_GOT16_LO		15
#define	R_PPC_GOT16_HI		16
#define	R_PPC_GOT16_HA		17
#define	R_PPC_PLTREL24		18
#define	R_PPC_COPY		19
#define	R_PPC_GLOB_DAT		20
#define	R_PPC_JMP_SLOT		21
#define	R_PPC_RELATIVE		22
#define	R_PPC_LOCAL24PC		23
#define	R_PPC_UADDR32		24
#define	R_PPC_UADDR16		25
#define	R_PPC_REL32		26
#define	R_PPC_PLT32		27
#define	R_PPC_PLTREL32		28
#define	R_PPC_PLT16_LO		29
#define	R_PPC_PLT16_HI		30
#define	R_PPC_PLT16_HA		31
#define	R_PPC_SDAREL16		32
#define	R_PPC_SECTOFF		33
#define	R_PPC_SECTOFF_LO	34
#define	R_PPC_SECTOFF_HI	35
#define	R_PPC_SECTOFF_HA	36
#define	R_PPC_IRELATIVE		248

/*
 * 64-bit relocations
 */
#define	R_PPC64_ADDR64		38
#define	R_PPC64_ADDR16_HIGHER	39
#define	R_PPC64_ADDR16_HIGHERA	40
#define	R_PPC64_ADDR16_HIGHEST	41
#define	R_PPC64_ADDR16_HIGHESTA	42
#define	R_PPC64_UADDR64		43
#define	R_PPC64_REL64		44
#define	R_PPC64_PLT64		45
#define	R_PPC64_PLTREL64	46
#define	R_PPC64_TOC16		47
#define	R_PPC64_TOC16_LO	48
#define	R_PPC64_TOC16_HI	49
#define	R_PPC64_TOC16_HA	50
#define	R_PPC64_TOC		51
#define	R_PPC64_DTPMOD64	68
#define	R_PPC64_TPREL64		73
#define	R_PPC64_DTPREL64	78

/*
 * TLS relocations
 */
#define	R_PPC_TLS		67
#define	R_PPC_DTPMOD32		68
#define	R_PPC_TPREL16		69
#define	R_PPC_TPREL16_LO	70
#define	R_PPC_TPREL16_HI	71
#define	R_PPC_TPREL16_HA	72
#define	R_PPC_TPREL32		73
#define	R_PPC_DTPREL16		74
#define	R_PPC_DTPREL16_LO	75
#define	R_PPC_DTPREL16_HI	76
#define	R_PPC_DTPREL16_HA	77
#define	R_PPC_DTPREL32		78
#define	R_PPC_GOT_TLSGD16	79
#define	R_PPC_GOT_TLSGD16_LO	80
#define	R_PPC_GOT_TLSGD16_HI	81
#define	R_PPC_GOT_TLSGD16_HA	82
#define	R_PPC_GOT_TLSLD16	83
#define	R_PPC_GOT_TLSLD16_LO	84
#define	R_PPC_GOT_TLSLD16_HI	85
#define	R_PPC_GOT_TLSLD16_HA	86
#define	R_PPC_GOT_TPREL16	87
#define	R_PPC_GOT_TPREL16_LO	88
#define	R_PPC_GOT_TPREL16_HI	89
#define	R_PPC_GOT_TPREL16_HA	90

/*
 * The remaining relocs are from the Embedded ELF ABI, and are not in the
 *  SVR4 ELF ABI.
 */

#define	R_PPC_EMB_NADDR32	101
#define	R_PPC_EMB_NADDR16	102
#define	R_PPC_EMB_NADDR16_LO	103
#define	R_PPC_EMB_NADDR16_HI	104
#define	R_PPC_EMB_NADDR16_HA	105
#define	R_PPC_EMB_SDAI16	106
#define	R_PPC_EMB_SDA2I16	107
#define	R_PPC_EMB_SDA2REL	108
#define	R_PPC_EMB_SDA21		109
#define	R_PPC_EMB_MRKREF	110
#define	R_PPC_EMB_RELSEC16	111
#define	R_PPC_EMB_RELST_LO	112
#define	R_PPC_EMB_RELST_HI	113
#define	R_PPC_EMB_RELST_HA	114
#define	R_PPC_EMB_BIT_FLD	115
#define	R_PPC_EMB_RELSDA	116

/*
 * RISC-V relocation types.
 */

/* Relocation types used by the dynamic linker. */
#define	R_RISCV_NONE		0
#define	R_RISCV_32		1
#define	R_RISCV_64		2
#define	R_RISCV_RELATIVE	3
#define	R_RISCV_COPY		4
#define	R_RISCV_JUMP_SLOT	5
#define	R_RISCV_TLS_DTPMOD32	6
#define	R_RISCV_TLS_DTPMOD64	7
#define	R_RISCV_TLS_DTPREL32	8
#define	R_RISCV_TLS_DTPREL64	9
#define	R_RISCV_TLS_TPREL32	10
#define	R_RISCV_TLS_TPREL64	11

/* Relocation types not used by the dynamic linker. */
#define	R_RISCV_BRANCH		16
#define	R_RISCV_JAL		17
#define	R_RISCV_CALL		18
#define	R_RISCV_CALL_PLT	19
#define	R_RISCV_GOT_HI20	20
#define	R_RISCV_TLS_GOT_HI20	21
#define	R_RISCV_TLS_GD_HI20	22
#define	R_RISCV_PCREL_HI20	23
#define	R_RISCV_PCREL_LO12_I	24
#define	R_RISCV_PCREL_LO12_S	25
#define	R_RISCV_HI20		26
#define	R_RISCV_LO12_I		27
#define	R_RISCV_LO12_S		28
#define	R_RISCV_TPREL_HI20	29
#define	R_RISCV_TPREL_LO12_I	30
#define	R_RISCV_TPREL_LO12_S	31
#define	R_RISCV_TPREL_ADD	32
#define	R_RISCV_ADD8		33
#define	R_RISCV_ADD16		34
#define	R_RISCV_ADD32		35
#define	R_RISCV_ADD64		36
#define	R_RISCV_SUB8		37
#define	R_RISCV_SUB16		38
#define	R_RISCV_SUB32		39
#define	R_RISCV_SUB64		40
#define	R_RISCV_ALIGN		43
#define	R_RISCV_RVC_BRANCH	44
#define	R_RISCV_RVC_JUMP	45
#define	R_RISCV_RVC_LUI		46
#define	R_RISCV_RELAX		51
#define	R_RISCV_SUB6		52
#define	R_RISCV_SET6		53
#define	R_RISCV_SET8		54
#define	R_RISCV_SET16		55
#define	R_RISCV_SET32		56
#define	R_RISCV_32_PCREL	57
#define	R_RISCV_IRELATIVE	58

#define	R_SPARC_NONE		0
#define	R_SPARC_8		1
#define	R_SPARC_16		2
#define	R_SPARC_32		3
#define	R_SPARC_DISP8		4
#define	R_SPARC_DISP16		5
#define	R_SPARC_DISP32		6
#define	R_SPARC_WDISP30		7
#define	R_SPARC_WDISP22		8
#define	R_SPARC_HI22		9
#define	R_SPARC_22		10
#define	R_SPARC_13		11
#define	R_SPARC_LO10		12
#define	R_SPARC_GOT10		13
#define	R_SPARC_GOT13		14
#define	R_SPARC_GOT22		15
#define	R_SPARC_PC10		16
#define	R_SPARC_PC22		17
#define	R_SPARC_WPLT30		18
#define	R_SPARC_COPY		19
#define	R_SPARC_GLOB_DAT	20
#define	R_SPARC_JMP_SLOT	21
#define	R_SPARC_RELATIVE	22
#define	R_SPARC_UA32		23
#define	R_SPARC_PLT32		24
#define	R_SPARC_HIPLT22		25
#define	R_SPARC_LOPLT10		26
#define	R_SPARC_PCPLT32		27
#define	R_SPARC_PCPLT22		28
#define	R_SPARC_PCPLT10		29
#define	R_SPARC_10		30
#define	R_SPARC_11		31
#define	R_SPARC_64		32
#define	R_SPARC_OLO10		33
#define	R_SPARC_HH22		34
#define	R_SPARC_HM10		35
#define	R_SPARC_LM22		36
#define	R_SPARC_PC_HH22		37
#define	R_SPARC_PC_HM10		38
#define	R_SPARC_PC_LM22		39
#define	R_SPARC_WDISP16		40
#define	R_SPARC_WDISP19		41
#define	R_SPARC_GLOB_JMP	42
#define	R_SPARC_7		43
#define	R_SPARC_5		44
#define	R_SPARC_6		45
#define	R_SPARC_DISP64		46
#define	R_SPARC_PLT64		47
#define	R_SPARC_HIX22		48
#define	R_SPARC_LOX10		49
#define	R_SPARC_H44		50
#define	R_SPARC_M44		51
#define	R_SPARC_L44		52
#define	R_SPARC_REGISTER	53
#define	R_SPARC_UA64		54
#define	R_SPARC_UA16		55
#define	R_SPARC_TLS_GD_HI22	56
#define	R_SPARC_TLS_GD_LO10	57
#define	R_SPARC_TLS_GD_ADD	58
#define	R_SPARC_TLS_GD_CALL	59
#define	R_SPARC_TLS_LDM_HI22	60
#define	R_SPARC_TLS_LDM_LO10	61
#define	R_SPARC_TLS_LDM_ADD	62
#define	R_SPARC_TLS_LDM_CALL	63
#define	R_SPARC_TLS_LDO_HIX22	64
#define	R_SPARC_TLS_LDO_LOX10	65
#define	R_SPARC_TLS_LDO_ADD	66
#define	R_SPARC_TLS_IE_HI22	67
#define	R_SPARC_TLS_IE_LO10	68
#define	R_SPARC_TLS_IE_LD	69
#define	R_SPARC_TLS_IE_LDX	70
#define	R_SPARC_TLS_IE_ADD	71
#define	R_SPARC_TLS_LE_HIX22	72
#define	R_SPARC_TLS_LE_LOX10	73
#define	R_SPARC_TLS_DTPMOD32	74
#define	R_SPARC_TLS_DTPMOD64	75
#define	R_SPARC_TLS_DTPOFF32	76
#define	R_SPARC_TLS_DTPOFF64	77
#define	R_SPARC_TLS_TPOFF32	78
#define	R_SPARC_TLS_TPOFF64	79

#define	R_X86_64_NONE		0	/* No relocation. */
#define	R_X86_64_64		1	/* Add 64 bit symbol value. */
#define	R_X86_64_PC32		2	/* PC-relative 32 bit signed sym value. */
#define	R_X86_64_GOT32		3	/* PC-relative 32 bit GOT offset. */
#define	R_X86_64_PLT32		4	/* PC-relative 32 bit PLT offset. */
#define	R_X86_64_COPY		5	/* Copy data from shared object. */
#define	R_X86_64_GLOB_DAT	6	/* Set GOT entry to data address. */
#define	R_X86_64_JMP_SLOT	7	/* Set GOT entry to code address. */
#define	R_X86_64_RELATIVE	8	/* Add load address of shared object. */
#define	R_X86_64_GOTPCREL	9	/* Add 32 bit signed pcrel offset to GOT. */
#define	R_X86_64_32		10	/* Add 32 bit zero extended symbol value */
#define	R_X86_64_32S		11	/* Add 32 bit sign extended symbol value */
#define	R_X86_64_16		12	/* Add 16 bit zero extended symbol value */
#define	R_X86_64_PC16		13	/* Add 16 bit signed extended pc relative symbol value */
#define	R_X86_64_8		14	/* Add 8 bit zero extended symbol value */
#define	R_X86_64_PC8		15	/* Add 8 bit signed extended pc relative symbol value */
#define	R_X86_64_DTPMOD64	16	/* ID of module containing symbol */
#define	R_X86_64_DTPOFF64	17	/* Offset in TLS block */
#define	R_X86_64_TPOFF64	18	/* Offset in static TLS block */
#define	R_X86_64_TLSGD		19	/* PC relative offset to GD GOT entry */
#define	R_X86_64_TLSLD		20	/* PC relative offset to LD GOT entry */
#define	R_X86_64_DTPOFF32	21	/* Offset in TLS block */
#define	R_X86_64_GOTTPOFF	22	/* PC relative offset to IE GOT entry */
#define	R_X86_64_TPOFF32	23	/* Offset in static TLS block */
#define	R_X86_64_PC64		24	/* PC-relative 64 bit signed sym value. */
#define	R_X86_64_GOTOFF64	25
#define	R_X86_64_GOTPC32	26
#define	R_X86_64_GOT64		27
#define	R_X86_64_GOTPCREL64	28
#define	R_X86_64_GOTPC64	29
#define	R_X86_64_GOTPLT64	30
#define	R_X86_64_PLTOFF64	31
#define	R_X86_64_SIZE32		32
#define	R_X86_64_SIZE64		33
#define	R_X86_64_GOTPC32_TLSDESC 34
#define	R_X86_64_TLSDESC_CALL	35
#define	R_X86_64_TLSDESC	36
#define	R_X86_64_IRELATIVE	37
#define	R_X86_64_RELATIVE64	38
/* 39 and 40 were BND-related, already decomissioned */
#define	R_X86_64_GOTPCRELX	41
#define	R_X86_64_REX_GOTPCRELX	42

#define	ELF_BSDF_SIGFASTBLK	0x0001	/* Kernel supports fast sigblock */
#define	ELF_BSDF_VMNOOVERCOMMIT	0x0002

#endif /* !_SYS_ELF_COMMON_H_ */

"""


```