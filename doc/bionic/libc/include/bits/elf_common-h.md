Response:
Let's break down the thought process for summarizing the provided C header file `elf_common.h`.

**1. Initial Understanding of the Request:**

The request asks for a functional summary of the `elf_common.h` file, specifically within the context of Android's Bionic library. It also asks to relate the contents to Android features, explain libc function implementations (though this file doesn't define functions), detail dynamic linker aspects with examples, address potential errors, and describe how Android framework/NDK interacts with this file. Finally, the request emphasizes that this is part 1 of 2 and wants a summarized overview.

**2. Core Purpose Identification:**

The first step is to recognize the file's name: `elf_common.h`. The "elf" strongly suggests it deals with the Executable and Linkable Format (ELF), a standard file format for executables, shared libraries, and object code. The "common" suggests it contains architecture-independent definitions. The path `bionic/libc/include/bits/` further reinforces this is a core part of the C library within Android.

**3. Content Examination and Categorization:**

The next step involves scanning the file's content and mentally grouping the definitions:

* **Copyright and License:** Standard boilerplate, acknowledge its presence but not a primary function.
* **Include Guard:** `#ifndef _SYS_ELF_COMMON_H_` - Important for preventing multiple inclusions, a standard practice in C/C++ headers.
* **Note Header (`Elf_Note`, `Elf_Nhdr`):**  Definitions related to note sections in ELF files, used for auxiliary information. The `#if 0 // android-added` is a crucial observation.
* **Option Kinds (`ODK_*`):**  A set of constants defining different kinds of options or metadata that can be associated with ELF sections.
* **Option Info Field Masks (`OEX_*`, `OPAD_*`, `OHW_*`, `OHWA0_*`, `OHWO0_*`, `OGP_*`):**  Bitmasks used to interpret the information fields associated with the option kinds.
* **GNU Hash Header (`Elf_GNU_Hash_Header`):**  Structure definition for the header of GNU-style hash tables used for symbol lookup. Again, note the `#if 0 // android-added`.
* **ELF Header Identifiers (`EI_*`):**  Indices into the `e_ident` array within the ELF header, which describes the ELF file's properties (magic number, class, data format, etc.).
* **ELF Magic Numbers and Constants (`ELFMAG*`, `SELFMAG`):**  Specific values used to identify an ELF file.
* **ELF Version (`EV_*`):**  Constants for ELF versioning.
* **ELF Class (`ELFCLASS_*`):**  Defines whether the ELF file is 32-bit or 64-bit.
* **ELF Data Format (`ELFDATANONE`, `ELFDATA2LSB`, `ELFDATA2MSB`):**  Specifies the byte order (endianness).
* **ELF OSABI (`ELFOSABI_*`):**  Identifies the operating system or ABI targeted by the ELF file. Crucially, this includes `ELFOSABI_LINUX` and `ELFOSABI_ARM_AEABI`, relevant to Android.
* **`IS_ELF` Macro:**  A simple macro to check if a given header matches the ELF magic number.
* **ELF Type (`ET_*`):**  Defines the type of ELF file (relocatable, executable, shared object, etc.).
* **ELF Machine (`EM_*`):**  Specifies the target architecture (x86, ARM, MIPS, RISC-V, etc.). This is a long list and vital for cross-platform compatibility.
* **ELF Flags (`EF_*`):**  Architecture-specific flags within the ELF header providing further details. Note the sections for ARM, MIPS, PPC, RISC-V, and SPARC.
* **Section Header Indexes (`SHN_*`):**  Special index values for section headers.
* **Section Header Types (`SHT_*`):**  Defines the purpose of each section within the ELF file (code, data, symbol table, relocation information, etc.). Notice the OS-specific and processor-specific ranges.
* **Section Header Flags (`SHF_*`):**  Properties of a section (writable, allocatable, executable, etc.).
* **Section Group Flags (`GRP_COMDAT`):** Flags specific to section groups.
* **Version Symbol Flags (`VERSYM_VERSION`, `VERSYM_HIDDEN`):** Flags used in the `.gnu.versym` section for symbol versioning.
* **Program Header Types (`PT_*`):**  Defines the purpose of each program header entry (loadable segment, dynamic linking info, interpreter path, etc.). Again, note OS-specific entries.
* **Program Header Flags (`PF_*`):**  Permissions for program segments (readable, writable, executable).
* **Extended Program Header Index (`PN_XNUM`):** Special value for when the number of program headers exceeds the standard field size.
* **Dynamic Tag Values (`DT_*`):**  Tags used in the `.dynamic` section of shared libraries, controlling the dynamic linker's behavior (needed libraries, symbol tables, relocations, etc.). This is a very extensive list and crucial for understanding dynamic linking.
* **Dynamic Flags (`DF_*`):** Flags associated with `DT_FLAGS` and `DT_FLAGS_1`, influencing the dynamic linker.

**4. Identifying Key Functionality:**

Based on the categorized content, the core functionality of `elf_common.h` can be summarized as:

* **Defining the structure and format of ELF files.**
* **Providing constants and identifiers for interpreting the various parts of an ELF file.**
* **Abstracting architecture-independent aspects of the ELF format.**

**5. Relating to Android Features:**

Think about how ELF is used in Android:

* **Executable files (`.apk` internals, native executables):** Android apps often contain native code compiled into ELF executables.
* **Shared libraries (`.so` files):** Android's framework and apps heavily rely on shared libraries for code reuse and modularity.
* **Dynamic linking:** The Android dynamic linker (`/system/bin/linker` or `linker64`) uses these definitions to load and link shared libraries.
* **NDK (Native Development Kit):**  NDK developers work directly with ELF files when building native libraries.

**6. Addressing Other Points (briefly for the summary):**

* **libc Function Implementation:** This header *defines* structures and constants, it doesn't implement libc functions.
* **Dynamic Linker:** The numerous `DT_*` tags are directly relevant to the dynamic linker's operation. Briefly mention its role in loading and linking.
* **Common Errors:**  Mention potential issues related to ABI compatibility, incorrect ELF headers, or missing dependencies.
* **Android Framework/NDK Interaction:** Highlight that the framework and NDK produce and consume ELF files, and the dynamic linker uses these definitions.
* **Frida Hooking:** Briefly mention the possibility of using Frida to inspect ELF structures at runtime.

**7. Structuring the Summary:**

Organize the findings into a clear and concise summary. Start with the main purpose, then elaborate on the key areas covered by the header file. Use bullet points for readability.

**8. Refining and Reviewing:**

Read through the summary to ensure accuracy, clarity, and completeness, given the constraints of this being part 1 of 2. Make sure the language is accessible. For instance, instead of just saying "ELF definitions," elaborate slightly by saying it defines the *structure and format* of ELF files.

This structured approach allows for a systematic analysis of the header file, leading to a comprehensive and accurate summary that addresses the key aspects of the request. The `#if 0 // android-added` comments are important hints about what parts are *not* actively used in the Android build, which is a crucial detail to include in the summary.
## 对 `bionic/libc/include/bits/elf_common.handroid` 的功能归纳 (第 1 部分)

这个头文件 `elf_common.handroid` 是 Android Bionic C 库的一部分，它定义了与 **Executable and Linkable Format (ELF)** 相关的、**架构无关**的通用数据结构、常量和宏。ELF 是一种用于可执行文件、共享库和目标代码的标准文件格式。

**主要功能可以归纳为：**

1. **定义了 ELF 文件的基本结构和组成部分:**  它声明了描述 ELF 文件头、节区头、程序头、动态链接信息等关键结构的 C 结构体（尽管在提供的代码片段中，一些结构体定义被 `#if 0 // android-added` 注释掉了，这可能意味着在 Android 的特定上下文中这些定义被其他地方覆盖或不再使用）。
2. **提供了用于识别和解析 ELF 文件的常量和宏:**  例如，定义了 ELF 魔数 (`ELFMAG`)，用于验证文件是否为 ELF 格式。还定义了用于表示 ELF 文件类型 (`ET_*`)、目标架构 (`EM_*`)、数据编码 (`ELFDATA_*`)、操作系统/ABI (`ELFOSABI_*`)、节区类型 (`SHT_*`)、程序段类型 (`PT_*`)、动态链接标签 (`DT_*`) 等的枚举值和宏。
3. **定义了用于处理 ELF 文件中各种信息的标志位和掩码:**  例如，节区头中的标志位 (`SHF_*`) 用于指示节区的属性（可写、可执行等），程序头中的标志位 (`PF_*`) 用于指示程序段的访问权限。
4. **为动态链接器提供了关键的数据结构和定义:**  特别是 `DT_*` 系列的宏定义，这些宏定义了动态链接段（`.dynamic` 节区）中使用的各种标签，这些标签指导着动态链接器如何加载、链接和解析共享库。
5. **定义了用于表示 Note 节区的数据结构:**  Note 节区用于存储额外的辅助信息，例如构建 ID、供应商信息等。

**简单来说，`elf_common.handroid`  为 Bionic 库提供了理解和操作 ELF 文件的基础词汇表和语法规则。**  它定义了构成 ELF 文件的基本 building blocks，使得 Bionic 的其他组件（例如动态链接器）能够正确地解析和处理 ELF 文件。

**关于 "android-added" 的注释：**

代码中多处出现的 `#if 0 // android-added` 注释表明，原始代码可能来自其他 BSD 衍生项目，而 Android 团队在此基础上进行了修改。被注释掉的部分可能在 Android 的 Bionic 库中被以不同的方式处理或定义。

在下一部分，我们可以更深入地探讨这些定义与 Android 功能的联系、libc 函数的实现细节、动态链接的处理过程以及潜在的使用错误等。

### 提示词
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
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2017, 2018 Dell EMC
 * Copyright (c) 2000, 2001, 2008, 2011, David E. O'Brien
 * Copyright (c) 1998 John D. Polstra.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_ELF_COMMON_H_
#define	_SYS_ELF_COMMON_H_ 1

/*
 * ELF definitions that are independent of architecture or word size.
 */

/*
 * Note header.  The ".note" section contains an array of notes.  Each
 * begins with this header, aligned to a word boundary.  Immediately
 * following the note header is n_namesz bytes of name, padded to the
 * next word boundary.  Then comes n_descsz bytes of descriptor, again
 * padded to a word boundary.  The values of n_namesz and n_descsz do
 * not include the padding.
 */

#if 0 // android-added
#if !defined(LOCORE) && !defined(__ASSEMBLER__)
typedef struct {
	u_int32_t	n_namesz;	/* Length of name. */
	u_int32_t	n_descsz;	/* Length of descriptor. */
	u_int32_t	n_type;		/* Type of this note. */
} Elf_Note;
typedef Elf_Note Elf_Nhdr;
#endif
#endif // android-added

/*
 * Option kinds.
 */
#define	ODK_NULL	0	/* undefined */
#define	ODK_REGINFO	1	/* register usage info */
#define	ODK_EXCEPTIONS	2	/* exception processing info */
#define	ODK_PAD		3	/* section padding */
#define	ODK_HWPATCH	4	/* hardware patch applied */
#define	ODK_FILL	5	/* fill value used by the linker */
#define	ODK_TAGS	6	/* reserved space for tools */
#define	ODK_HWAND	7	/* hardware AND patch applied */
#define	ODK_HWOR	8	/* hardware OR patch applied */
#define	ODK_GP_GROUP	9	/* GP group for text/data sections */
#define	ODK_IDENT	10	/* ID information */
#define	ODK_PAGESIZE	11	/* page size information */

/*
 * ODK_EXCEPTIONS info field masks.
 */
#define	OEX_FPU_MIN	0x0000001f	/* min FPU exception required */
#define	OEX_FPU_MAX	0x00001f00	/* max FPU exception allowed */
#define	OEX_PAGE0	0x00010000	/* page zero must be mapped */
#define	OEX_SMM		0x00020000	/* run in sequential memory mode */
#define	OEX_PRECISEFP	0x00040000	/* run in precise FP exception mode */
#define	OEX_DISMISS	0x00080000	/* dismiss invalid address traps */

/*
 * ODK_PAD info field masks.
 */
#define	OPAD_PREFIX	0x0001
#define	OPAD_POSTFIX	0x0002
#define	OPAD_SYMBOL	0x0004

/*
 * ODK_HWPATCH info field masks.
 */
#define	OHW_R4KEOP	0x00000001	/* patch for R4000 branch at end-of-page bug */
#define	OHW_R8KPFETCH	0x00000002	/* R8000 prefetch bug may occur */
#define	OHW_R5KEOP	0x00000004	/* patch for R5000 branch at end-of-page bug */
#define	OHW_R5KCVTL	0x00000008	/* R5000 cvt.[ds].l bug: clean == 1 */
#define	OHW_R10KLDL	0x00000010UL	/* need patch for R10000 misaligned load */

/*
 * ODK_HWAND/ODK_HWOR info field and hwp_flags[12] masks.
 */
#define	OHWA0_R4KEOP_CHECKED	0x00000001	/* object checked for R4000 end-of-page bug */
#define	OHWA0_R4KEOP_CLEAN	0x00000002	/* object verified clean for R4000 end-of-page bug */
#define	OHWO0_FIXADE		0x00000001	/* object requires call to fixade */

/*
 * ODK_IDENT/ODK_GP_GROUP info field masks.
 */
#define	OGP_GROUP	0x0000ffff	/* GP group number */
#define	OGP_SELF	0x00010000	/* GP group is self-contained */

/*
 * The header for GNU-style hash sections.
 */

#if 0 // android-added
#if !defined(LOCORE) && !defined(__ASSEMBLER__)
typedef struct {
	u_int32_t	gh_nbuckets;	/* Number of hash buckets. */
	u_int32_t	gh_symndx;	/* First visible symbol in .dynsym. */
	u_int32_t	gh_maskwords;	/* #maskwords used in bloom filter. */
	u_int32_t	gh_shift2;	/* Bloom filter shift count. */
} Elf_GNU_Hash_Header;
#endif
#endif

/* Indexes into the e_ident array.  Keep synced with
   http://www.sco.com/developers/gabi/latest/ch4.eheader.html */
#define	EI_MAG0		0	/* Magic number, byte 0. */
#define	EI_MAG1		1	/* Magic number, byte 1. */
#define	EI_MAG2		2	/* Magic number, byte 2. */
#define	EI_MAG3		3	/* Magic number, byte 3. */
#define	EI_CLASS	4	/* Class of machine. */
#define	EI_DATA		5	/* Data format. */
#define	EI_VERSION	6	/* ELF format version. */
#define	EI_OSABI	7	/* Operating system / ABI identification */
#define	EI_ABIVERSION	8	/* ABI version */
#define	OLD_EI_BRAND	8	/* Start of architecture identification. */
#define	EI_PAD		9	/* Start of padding (per SVR4 ABI). */
#define	EI_NIDENT	16	/* Size of e_ident array. */

/* Values for the magic number bytes. */
#define	ELFMAG0		0x7f
#define	ELFMAG1		'E'
#define	ELFMAG2		'L'
#define	ELFMAG3		'F'
#define	ELFMAG		"\177ELF"	/* magic string */
#define	SELFMAG		4		/* magic string size */

/* Values for e_ident[EI_VERSION] and e_version. */
#define	EV_NONE		0
#define	EV_CURRENT	1

/* Values for e_ident[EI_CLASS]. */
#define	ELFCLASSNONE	0	/* Unknown class. */
#define	ELFCLASS32	1	/* 32-bit architecture. */
#define	ELFCLASS64	2	/* 64-bit architecture. */

/* Values for e_ident[EI_DATA]. */
#define	ELFDATANONE	0	/* Unknown data format. */
#define	ELFDATA2LSB	1	/* 2's complement little-endian. */
#define	ELFDATA2MSB	2	/* 2's complement big-endian. */

/* Values for e_ident[EI_OSABI]. */
#define	ELFOSABI_NONE		0	/* UNIX System V ABI */
#define	ELFOSABI_HPUX		1	/* HP-UX operating system */
#define	ELFOSABI_NETBSD		2	/* NetBSD */
#define	ELFOSABI_LINUX		3	/* GNU/Linux */
#define	ELFOSABI_HURD		4	/* GNU/Hurd */
#define	ELFOSABI_86OPEN		5	/* 86Open common IA32 ABI */
#define	ELFOSABI_SOLARIS	6	/* Solaris */
#define	ELFOSABI_AIX		7	/* AIX */
#define	ELFOSABI_IRIX		8	/* IRIX */
#define	ELFOSABI_FREEBSD	9	/* FreeBSD */
#define	ELFOSABI_TRU64		10	/* TRU64 UNIX */
#define	ELFOSABI_MODESTO	11	/* Novell Modesto */
#define	ELFOSABI_OPENBSD	12	/* OpenBSD */
#define	ELFOSABI_OPENVMS	13	/* Open VMS */
#define	ELFOSABI_NSK		14	/* HP Non-Stop Kernel */
#define	ELFOSABI_AROS		15	/* Amiga Research OS */
#define	ELFOSABI_FENIXOS	16	/* FenixOS */
#define	ELFOSABI_CLOUDABI	17	/* Nuxi CloudABI */
#define	ELFOSABI_OPENVOS	18	/* Stratus Technologies OpenVOS */
#define	ELFOSABI_ARM_AEABI	64	/* ARM EABI */
#define	ELFOSABI_ARM		97	/* ARM */
#define	ELFOSABI_STANDALONE	255	/* Standalone (embedded) application */

#define	ELFOSABI_SYSV		ELFOSABI_NONE	/* symbol used in old spec */
#define	ELFOSABI_MONTEREY	ELFOSABI_AIX	/* Monterey */
#define	ELFOSABI_GNU		ELFOSABI_LINUX

/* e_ident */
#define	IS_ELF(ehdr)	((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
			 (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
			 (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
			 (ehdr).e_ident[EI_MAG3] == ELFMAG3)

/* Values for e_type. */
#define	ET_NONE		0	/* Unknown type. */
#define	ET_REL		1	/* Relocatable. */
#define	ET_EXEC		2	/* Executable. */
#define	ET_DYN		3	/* Shared object. */
#define	ET_CORE		4	/* Core file. */
#define	ET_LOOS		0xfe00	/* First operating system specific. */
#define	ET_HIOS		0xfeff	/* Last operating system-specific. */
#define	ET_LOPROC	0xff00	/* First processor-specific. */
#define	ET_HIPROC	0xffff	/* Last processor-specific. */

/* Values for e_machine. */
#define	EM_NONE		0	/* Unknown machine. */
#define	EM_M32		1	/* AT&T WE32100. */
#define	EM_SPARC	2	/* Sun SPARC. */
#define	EM_386		3	/* Intel i386. */
#define	EM_68K		4	/* Motorola 68000. */
#define	EM_88K		5	/* Motorola 88000. */
#define	EM_IAMCU	6	/* Intel MCU. */
#define	EM_860		7	/* Intel i860. */
#define	EM_MIPS		8	/* MIPS R3000 Big-Endian only. */
#define	EM_S370		9	/* IBM System/370. */
#define	EM_MIPS_RS3_LE	10	/* MIPS R3000 Little-Endian. */
#define	EM_PARISC	15	/* HP PA-RISC. */
#define	EM_VPP500	17	/* Fujitsu VPP500. */
#define	EM_SPARC32PLUS	18	/* SPARC v8plus. */
#define	EM_960		19	/* Intel 80960. */
#define	EM_PPC		20	/* PowerPC 32-bit. */
#define	EM_PPC64	21	/* PowerPC 64-bit. */
#define	EM_S390		22	/* IBM System/390. */
#define	EM_V800		36	/* NEC V800. */
#define	EM_FR20		37	/* Fujitsu FR20. */
#define	EM_RH32		38	/* TRW RH-32. */
#define	EM_RCE		39	/* Motorola RCE. */
#define	EM_ARM		40	/* ARM. */
#define	EM_SH		42	/* Hitachi SH. */
#define	EM_SPARCV9	43	/* SPARC v9 64-bit. */
#define	EM_TRICORE	44	/* Siemens TriCore embedded processor. */
#define	EM_ARC		45	/* Argonaut RISC Core. */
#define	EM_H8_300	46	/* Hitachi H8/300. */
#define	EM_H8_300H	47	/* Hitachi H8/300H. */
#define	EM_H8S		48	/* Hitachi H8S. */
#define	EM_H8_500	49	/* Hitachi H8/500. */
#define	EM_IA_64	50	/* Intel IA-64 Processor. */
#define	EM_MIPS_X	51	/* Stanford MIPS-X. */
#define	EM_COLDFIRE	52	/* Motorola ColdFire. */
#define	EM_68HC12	53	/* Motorola M68HC12. */
#define	EM_MMA		54	/* Fujitsu MMA. */
#define	EM_PCP		55	/* Siemens PCP. */
#define	EM_NCPU		56	/* Sony nCPU. */
#define	EM_NDR1		57	/* Denso NDR1 microprocessor. */
#define	EM_STARCORE	58	/* Motorola Star*Core processor. */
#define	EM_ME16		59	/* Toyota ME16 processor. */
#define	EM_ST100	60	/* STMicroelectronics ST100 processor. */
#define	EM_TINYJ	61	/* Advanced Logic Corp. TinyJ processor. */
#define	EM_X86_64	62	/* Advanced Micro Devices x86-64 */
#define	EM_AMD64	EM_X86_64	/* Advanced Micro Devices x86-64 (compat) */
#define	EM_PDSP		63	/* Sony DSP Processor. */
#define	EM_FX66		66	/* Siemens FX66 microcontroller. */
#define	EM_ST9PLUS	67	/* STMicroelectronics ST9+ 8/16
				   microcontroller. */
#define	EM_ST7		68	/* STmicroelectronics ST7 8-bit
				   microcontroller. */
#define	EM_68HC16	69	/* Motorola MC68HC16 microcontroller. */
#define	EM_68HC11	70	/* Motorola MC68HC11 microcontroller. */
#define	EM_68HC08	71	/* Motorola MC68HC08 microcontroller. */
#define	EM_68HC05	72	/* Motorola MC68HC05 microcontroller. */
#define	EM_SVX		73	/* Silicon Graphics SVx. */
#define	EM_ST19		74	/* STMicroelectronics ST19 8-bit mc. */
#define	EM_VAX		75	/* Digital VAX. */
#define	EM_CRIS		76	/* Axis Communications 32-bit embedded
				   processor. */
#define	EM_JAVELIN	77	/* Infineon Technologies 32-bit embedded
				   processor. */
#define	EM_FIREPATH	78	/* Element 14 64-bit DSP Processor. */
#define	EM_ZSP		79	/* LSI Logic 16-bit DSP Processor. */
#define	EM_MMIX		80	/* Donald Knuth's educational 64-bit proc. */
#define	EM_HUANY	81	/* Harvard University machine-independent
				   object files. */
#define	EM_PRISM	82	/* SiTera Prism. */
#define	EM_AVR		83	/* Atmel AVR 8-bit microcontroller. */
#define	EM_FR30		84	/* Fujitsu FR30. */
#define	EM_D10V		85	/* Mitsubishi D10V. */
#define	EM_D30V		86	/* Mitsubishi D30V. */
#define	EM_V850		87	/* NEC v850. */
#define	EM_M32R		88	/* Mitsubishi M32R. */
#define	EM_MN10300	89	/* Matsushita MN10300. */
#define	EM_MN10200	90	/* Matsushita MN10200. */
#define	EM_PJ		91	/* picoJava. */
#define	EM_OPENRISC	92	/* OpenRISC 32-bit embedded processor. */
#define	EM_ARC_A5	93	/* ARC Cores Tangent-A5. */
#define	EM_XTENSA	94	/* Tensilica Xtensa Architecture. */
#define	EM_VIDEOCORE	95	/* Alphamosaic VideoCore processor. */
#define	EM_TMM_GPP	96	/* Thompson Multimedia General Purpose
				   Processor. */
#define	EM_NS32K	97	/* National Semiconductor 32000 series. */
#define	EM_TPC		98	/* Tenor Network TPC processor. */
#define	EM_SNP1K	99	/* Trebia SNP 1000 processor. */
#define	EM_ST200	100	/* STMicroelectronics ST200 microcontroller. */
#define	EM_IP2K		101	/* Ubicom IP2xxx microcontroller family. */
#define	EM_MAX		102	/* MAX Processor. */
#define	EM_CR		103	/* National Semiconductor CompactRISC
				   microprocessor. */
#define	EM_F2MC16	104	/* Fujitsu F2MC16. */
#define	EM_MSP430	105	/* Texas Instruments embedded microcontroller
				   msp430. */
#define	EM_BLACKFIN	106	/* Analog Devices Blackfin (DSP) processor. */
#define	EM_SE_C33	107	/* S1C33 Family of Seiko Epson processors. */
#define	EM_SEP		108	/* Sharp embedded microprocessor. */
#define	EM_ARCA		109	/* Arca RISC Microprocessor. */
#define	EM_UNICORE	110	/* Microprocessor series from PKU-Unity Ltd.
				   and MPRC of Peking University */
#define	EM_AARCH64	183	/* AArch64 (64-bit ARM) */
#define	EM_RISCV	243	/* RISC-V */

/* Non-standard or deprecated. */
#define	EM_486		6	/* Intel i486. */
#define	EM_MIPS_RS4_BE	10	/* MIPS R4000 Big-Endian */
#define	EM_ALPHA_STD	41	/* Digital Alpha (standard value). */
#define	EM_ALPHA	0x9026	/* Alpha (written in the absence of an ABI) */

/**
 * e_flags
 */
#define	EF_ARM_RELEXEC	0x1
#define	EF_ARM_HASENTRY	0x2
#define	EF_ARM_SYMSARESORTED	0x4
#define	EF_ARM_DYNSYMSUSESEGIDX	0x8
#define	EF_ARM_MAPSYMSFIRST	0x10
#define	EF_ARM_LE8		0x00400000
#define	EF_ARM_BE8		0x00800000
#define	EF_ARM_EABIMASK		0xFF000000
#define	EF_ARM_EABI_UNKNOWN	0x00000000
#define	EF_ARM_EABI_VER1	0x01000000
#define	EF_ARM_EABI_VER2	0x02000000
#define	EF_ARM_EABI_VER3	0x03000000
#define	EF_ARM_EABI_VER4	0x04000000
#define	EF_ARM_EABI_VER5	0x05000000
#define	EF_ARM_EABI_VERSION(x)	((x) & EF_ARM_EABIMASK)
#define	EF_ARM_INTERWORK	0x00000004
#define	EF_ARM_APCS_26		0x00000008
#define	EF_ARM_APCS_FLOAT	0x00000010
#define	EF_ARM_PIC		0x00000020
#define	EF_ARM_ALIGN8		0x00000040
#define	EF_ARM_NEW_ABI		0x00000080
#define	EF_ARM_OLD_ABI		0x00000100
#define	EF_ARM_ABI_FLOAT_SOFT	0x00000200
#define	EF_ARM_SOFT_FLOAT	EF_ARM_ABI_FLOAT_SOFT /* Pre-V5 ABI name */
#define	EF_ARM_ABI_FLOAT_HARD	0x00000400
#define	EF_ARM_VFP_FLOAT	EF_ARM_ABI_FLOAT_HARD /* Pre-V5 ABI name */
#define	EF_ARM_MAVERICK_FLOAT	0x00000800

#define	EF_MIPS_NOREORDER	0x00000001
#define	EF_MIPS_PIC		0x00000002	/* Contains PIC code */
#define	EF_MIPS_CPIC		0x00000004	/* STD PIC calling sequence */
#define	EF_MIPS_UCODE		0x00000010
#define	EF_MIPS_ABI2		0x00000020	/* N32 */
#define	EF_MIPS_OPTIONS_FIRST	0x00000080
#define	EF_MIPS_ABI		0x0000F000
#define	EF_MIPS_ABI_O32		0x00001000
#define	EF_MIPS_ABI_O64		0x00002000
#define	EF_MIPS_ABI_EABI32	0x00003000
#define	EF_MIPS_ABI_EABI64	0x00004000
#define	EF_MIPS_ARCH_ASE	0x0F000000	/* Architectural extensions */
#define	EF_MIPS_ARCH_ASE_MDMX	0x08000000	/* MDMX multimedia extension */
#define	EF_MIPS_ARCH_ASE_M16	0x04000000	/* MIPS-16 ISA extensions */
#define	EF_MIPS_ARCH		0xF0000000	/* Architecture field */
#define	EF_MIPS_ARCH_1		0x00000000	/* -mips1 code */
#define	EF_MIPS_ARCH_2		0x10000000	/* -mips2 code */
#define	EF_MIPS_ARCH_3		0x20000000	/* -mips3 code */
#define	EF_MIPS_ARCH_4		0x30000000	/* -mips4 code */
#define	EF_MIPS_ARCH_5		0x40000000	/* -mips5 code */
#define	EF_MIPS_ARCH_32		0x50000000	/* -mips32 code */
#define	EF_MIPS_ARCH_64		0x60000000	/* -mips64 code */
#define	EF_MIPS_ARCH_32R2	0x70000000	/* -mips32r2 code */
#define	EF_MIPS_ARCH_64R2	0x80000000	/* -mips64r2 code */

#define	EF_PPC_EMB		0x80000000
#define	EF_PPC_RELOCATABLE	0x00010000
#define	EF_PPC_RELOCATABLE_LIB	0x00008000

#define	EF_RISCV_RVC		0x00000001
#define	EF_RISCV_FLOAT_ABI_MASK	0x00000006
#define	EF_RISCV_FLOAT_ABI_SOFT	0x00000000
#define	EF_RISCV_FLOAT_ABI_SINGLE 0x000002
#define	EF_RISCV_FLOAT_ABI_DOUBLE 0x000004
#define	EF_RISCV_FLOAT_ABI_QUAD	0x00000006
#define	EF_RISCV_RVE		0x00000008
#define	EF_RISCV_TSO		0x00000010

#define	EF_SPARC_EXT_MASK	0x00ffff00
#define	EF_SPARC_32PLUS		0x00000100
#define	EF_SPARC_SUN_US1	0x00000200
#define	EF_SPARC_HAL_R1		0x00000200
#define	EF_SPARC_SUN_US3	0x00000800

#define	EF_SPARCV9_MM		0x00000003
#define	EF_SPARCV9_TSO		0x00000000
#define	EF_SPARCV9_PSO		0x00000001
#define	EF_SPARCV9_RMO		0x00000002

/* Special section indexes. */
#define	SHN_UNDEF	     0		/* Undefined, missing, irrelevant. */
#define	SHN_LORESERVE	0xff00		/* First of reserved range. */
#define	SHN_LOPROC	0xff00		/* First processor-specific. */
#define	SHN_HIPROC	0xff1f		/* Last processor-specific. */
#define	SHN_LOOS	0xff20		/* First operating system-specific. */
#define	SHN_FBSD_CACHED	SHN_LOOS	/* Transient, for sys/kern/link_elf_obj
					   linker only: Cached global in local
					   symtab. */
#define	SHN_HIOS	0xff3f		/* Last operating system-specific. */
#define	SHN_ABS		0xfff1		/* Absolute values. */
#define	SHN_COMMON	0xfff2		/* Common data. */
#define	SHN_XINDEX	0xffff		/* Escape -- index stored elsewhere. */
#define	SHN_HIRESERVE	0xffff		/* Last of reserved range. */

/* sh_type */
#define	SHT_NULL		0	/* inactive */
#define	SHT_PROGBITS		1	/* program defined information */
#define	SHT_SYMTAB		2	/* symbol table section */
#define	SHT_STRTAB		3	/* string table section */
#define	SHT_RELA		4	/* relocation section with addends */
#define	SHT_HASH		5	/* symbol hash table section */
#define	SHT_DYNAMIC		6	/* dynamic section */
#define	SHT_NOTE		7	/* note section */
#define	SHT_NOBITS		8	/* no space section */
#define	SHT_REL			9	/* relocation section - no addends */
#define	SHT_SHLIB		10	/* reserved - purpose unknown */
#define	SHT_DYNSYM		11	/* dynamic symbol table section */
#define	SHT_INIT_ARRAY		14	/* Initialization function pointers. */
#define	SHT_FINI_ARRAY		15	/* Termination function pointers. */
#define	SHT_PREINIT_ARRAY	16	/* Pre-initialization function ptrs. */
#define	SHT_GROUP		17	/* Section group. */
#define	SHT_SYMTAB_SHNDX	18	/* Section indexes (see SHN_XINDEX). */
#define	SHT_LOOS		0x60000000	/* First of OS specific semantics */
#define	SHT_LOSUNW		0x6ffffff4
#define	SHT_SUNW_dof		0x6ffffff4
#define	SHT_SUNW_cap		0x6ffffff5
#define	SHT_GNU_ATTRIBUTES	0x6ffffff5
#define	SHT_SUNW_SIGNATURE	0x6ffffff6
#define	SHT_GNU_HASH		0x6ffffff6
#define	SHT_GNU_LIBLIST		0x6ffffff7
#define	SHT_SUNW_ANNOTATE	0x6ffffff7
#define	SHT_SUNW_DEBUGSTR	0x6ffffff8
#define	SHT_SUNW_DEBUG		0x6ffffff9
#define	SHT_SUNW_move		0x6ffffffa
#define	SHT_SUNW_COMDAT		0x6ffffffb
#define	SHT_SUNW_syminfo	0x6ffffffc
#define	SHT_SUNW_verdef		0x6ffffffd
#define	SHT_GNU_verdef		0x6ffffffd	/* Symbol versions provided */
#define	SHT_SUNW_verneed	0x6ffffffe
#define	SHT_GNU_verneed		0x6ffffffe	/* Symbol versions required */
#define	SHT_SUNW_versym		0x6fffffff
#define	SHT_GNU_versym		0x6fffffff	/* Symbol version table */
#define	SHT_HISUNW		0x6fffffff
#define	SHT_HIOS		0x6fffffff	/* Last of OS specific semantics */
#define	SHT_LOPROC		0x70000000	/* reserved range for processor */
#define	SHT_X86_64_UNWIND	0x70000001	/* unwind information */
#define	SHT_AMD64_UNWIND	SHT_X86_64_UNWIND 

#define	SHT_ARM_EXIDX		0x70000001	/* Exception index table. */
#define	SHT_ARM_PREEMPTMAP	0x70000002	/* BPABI DLL dynamic linking 
						   pre-emption map. */
#define	SHT_ARM_ATTRIBUTES	0x70000003	/* Object file compatibility 
						   attributes. */
#define	SHT_ARM_DEBUGOVERLAY	0x70000004	/* See DBGOVL for details. */
#define	SHT_ARM_OVERLAYSECTION	0x70000005	/* See DBGOVL for details. */
#define	SHT_MIPS_LIBLIST	0x70000000
#define	SHT_MIPS_MSYM		0x70000001
#define	SHT_MIPS_CONFLICT	0x70000002
#define	SHT_MIPS_GPTAB		0x70000003
#define	SHT_MIPS_UCODE		0x70000004
#define	SHT_MIPS_DEBUG		0x70000005
#define	SHT_MIPS_REGINFO	0x70000006
#define	SHT_MIPS_PACKAGE	0x70000007
#define	SHT_MIPS_PACKSYM	0x70000008
#define	SHT_MIPS_RELD		0x70000009
#define	SHT_MIPS_IFACE		0x7000000b
#define	SHT_MIPS_CONTENT	0x7000000c
#define	SHT_MIPS_OPTIONS	0x7000000d
#define	SHT_MIPS_DELTASYM	0x7000001b
#define	SHT_MIPS_DELTAINST	0x7000001c
#define	SHT_MIPS_DELTACLASS	0x7000001d
#define	SHT_MIPS_DWARF		0x7000001e	/* MIPS gcc uses MIPS_DWARF */
#define	SHT_MIPS_DELTADECL	0x7000001f
#define	SHT_MIPS_SYMBOL_LIB	0x70000020
#define	SHT_MIPS_EVENTS		0x70000021
#define	SHT_MIPS_TRANSLATE	0x70000022
#define	SHT_MIPS_PIXIE		0x70000023
#define	SHT_MIPS_XLATE		0x70000024
#define	SHT_MIPS_XLATE_DEBUG	0x70000025
#define	SHT_MIPS_WHIRL		0x70000026
#define	SHT_MIPS_EH_REGION	0x70000027
#define	SHT_MIPS_XLATE_OLD	0x70000028
#define	SHT_MIPS_PDR_EXCEPTION	0x70000029
#define	SHT_MIPS_ABIFLAGS	0x7000002a

#define	SHT_SPARC_GOTDATA	0x70000000

#define	SHTORDERED
#define	SHT_HIPROC		0x7fffffff	/* specific section header types */
#define	SHT_LOUSER		0x80000000	/* reserved range for application */
#define	SHT_HIUSER		0xffffffff	/* specific indexes */

/* Flags for sh_flags. */
#define	SHF_WRITE		0x1	/* Section contains writable data. */
#define	SHF_ALLOC		0x2	/* Section occupies memory. */
#define	SHF_EXECINSTR		0x4	/* Section contains instructions. */
#define	SHF_MERGE		0x10	/* Section may be merged. */
#define	SHF_STRINGS		0x20	/* Section contains strings. */
#define	SHF_INFO_LINK		0x40	/* sh_info holds section index. */
#define	SHF_LINK_ORDER		0x80	/* Special ordering requirements. */
#define	SHF_OS_NONCONFORMING	0x100	/* OS-specific processing required. */
#define	SHF_GROUP		0x200	/* Member of section group. */
#define	SHF_TLS			0x400	/* Section contains TLS data. */
#define	SHF_COMPRESSED		0x800	/* Section contains compressed data. */
#define	SHF_MASKOS	0x0ff00000	/* OS-specific semantics. */
#define	SHF_MASKPROC	0xf0000000	/* Processor-specific semantics. */

/* Flags for section groups. */
#define	GRP_COMDAT	0x1	/* COMDAT semantics. */

/*
 * Flags / mask for .gnu.versym sections.
 */
#define	VERSYM_VERSION	0x7fff
#define	VERSYM_HIDDEN	0x8000

/* Values for p_type. */
#define	PT_NULL		0	/* Unused entry. */
#define	PT_LOAD		1	/* Loadable segment. */
#define	PT_DYNAMIC	2	/* Dynamic linking information segment. */
#define	PT_INTERP	3	/* Pathname of interpreter. */
#define	PT_NOTE		4	/* Auxiliary information. */
#define	PT_SHLIB	5	/* Reserved (not used). */
#define	PT_PHDR		6	/* Location of program header itself. */
#define	PT_TLS		7	/* Thread local storage segment */
#define	PT_LOOS		0x60000000	/* First OS-specific. */
#define	PT_SUNW_UNWIND	0x6464e550	/* amd64 UNWIND program header */
// android-removed: #define	PT_GNU_EH_FRAME	0x6474e550
// android-removed: #define	PT_GNU_STACK	0x6474e551
// android-removed: #define	PT_GNU_RELRO	0x6474e552
#define	PT_DUMP_DELTA	0x6fb5d000	/* va->pa map for kernel dumps
					   (currently arm). */
#define	PT_LOSUNW	0x6ffffffa
#define	PT_SUNWBSS	0x6ffffffa	/* Sun Specific segment */
#define	PT_SUNWSTACK	0x6ffffffb	/* describes the stack segment */
#define	PT_SUNWDTRACE	0x6ffffffc	/* private */
#define	PT_SUNWCAP	0x6ffffffd	/* hard/soft capabilities segment */
#define	PT_HISUNW	0x6fffffff
#define	PT_HIOS		0x6fffffff	/* Last OS-specific. */
#define	PT_LOPROC	0x70000000	/* First processor-specific type. */
#define	PT_ARM_ARCHEXT	0x70000000	/* ARM arch compat information. */
#define	PT_ARM_EXIDX	0x70000001	/* ARM exception unwind tables. */
#define	PT_MIPS_REGINFO		0x70000000	/* MIPS register usage info */
#define	PT_MIPS_RTPROC		0x70000001	/* MIPS runtime procedure tbl */
#define	PT_MIPS_OPTIONS		0x70000002	/* MIPS e_flags value*/
#define	PT_MIPS_ABIFLAGS	0x70000003	/* MIPS fp mode */
#define	PT_HIPROC	0x7fffffff	/* Last processor-specific type. */

#define	PT_OPENBSD_RANDOMIZE	0x65A3DBE6	/* OpenBSD random data segment */
#define	PT_OPENBSD_WXNEEDED	0x65A3DBE7	/* OpenBSD EXEC/WRITE pages needed */
#define	PT_OPENBSD_BOOTDATA	0x65A41BE6	/* OpenBSD section for boot args */

/* Values for p_flags. */
#define	PF_X		0x1		/* Executable. */
#define	PF_W		0x2		/* Writable. */
#define	PF_R		0x4		/* Readable. */
#define	PF_MASKOS	0x0ff00000	/* Operating system-specific. */
#define	PF_MASKPROC	0xf0000000	/* Processor-specific. */

/* Extended program header index. */
#define	PN_XNUM		0xffff

/* Values for d_tag. */
#define	DT_NULL		0	/* Terminating entry. */
#define	DT_NEEDED	1	/* String table offset of a needed shared
				   library. */
#define	DT_PLTRELSZ	2	/* Total size in bytes of PLT relocations. */
#define	DT_PLTGOT	3	/* Processor-dependent address. */
#define	DT_HASH		4	/* Address of symbol hash table. */
#define	DT_STRTAB	5	/* Address of string table. */
#define	DT_SYMTAB	6	/* Address of symbol table. */
#define	DT_RELA		7	/* Address of ElfNN_Rela relocations. */
#define	DT_RELASZ	8	/* Total size of ElfNN_Rela relocations. */
#define	DT_RELAENT	9	/* Size of each ElfNN_Rela relocation entry. */
#define	DT_STRSZ	10	/* Size of string table. */
#define	DT_SYMENT	11	/* Size of each symbol table entry. */
#define	DT_INIT		12	/* Address of initialization function. */
#define	DT_FINI		13	/* Address of finalization function. */
#define	DT_SONAME	14	/* String table offset of shared object
				   name. */
#define	DT_RPATH	15	/* String table offset of library path. [sup] */
#define	DT_SYMBOLIC	16	/* Indicates "symbolic" linking. [sup] */
#define	DT_REL		17	/* Address of ElfNN_Rel relocations. */
#define	DT_RELSZ	18	/* Total size of ElfNN_Rel relocations. */
#define	DT_RELENT	19	/* Size of each ElfNN_Rel relocation. */
#define	DT_PLTREL	20	/* Type of relocation used for PLT. */
#define	DT_DEBUG	21	/* Reserved (not used). */
#define	DT_TEXTREL	22	/* Indicates there may be relocations in
				   non-writable segments. [sup] */
#define	DT_JMPREL	23	/* Address of PLT relocations. */
#define	DT_BIND_NOW	24	/* [sup] */
#define	DT_INIT_ARRAY	25	/* Address of the array of pointers to
				   initialization functions */
#define	DT_FINI_ARRAY	26	/* Address of the array of pointers to
				   termination functions */
#define	DT_INIT_ARRAYSZ	27	/* Size in bytes of the array of
				   initialization functions. */
#define	DT_FINI_ARRAYSZ	28	/* Size in bytes of the array of
				   termination functions. */
#define	DT_RUNPATH	29	/* String table offset of a null-terminated
				   library search path string. */
#define	DT_FLAGS	30	/* Object specific flag values. */
#define	DT_ENCODING	32	/* Values greater than or equal to DT_ENCODING
				   and less than DT_LOOS follow the rules for
				   the interpretation of the d_un union
				   as follows: even == 'd_ptr', odd == 'd_val'
				   or none */
#define	DT_PREINIT_ARRAY 32	/* Address of the array of pointers to
				   pre-initialization functions. */
#define	DT_PREINIT_ARRAYSZ 33	/* Size in bytes of the array of
				   pre-initialization functions. */
#define	DT_MAXPOSTAGS	34	/* number of positive tags */
#define	DT_RELRSZ	35	/* Total size of ElfNN_Relr relocations. */
#define	DT_RELR		36	/* Address of ElfNN_Relr relocations. */
#define	DT_RELRENT	37	/* Size of each ElfNN_Relr relocation. */
#define	DT_LOOS		0x6000000d	/* First OS-specific */
#define	DT_SUNW_AUXILIARY	0x6000000d	/* symbol auxiliary name */
#define	DT_SUNW_RTLDINF		0x6000000e	/* ld.so.1 info (private) */
#define	DT_SUNW_FILTER		0x6000000f	/* symbol filter name */
#define	DT_SUNW_CAP		0x60000010	/* hardware/software */
#define	DT_SUNW_ASLR		0x60000023	/* ASLR control */
#define	DT_HIOS		0x6ffff000	/* Last OS-specific */

/*
 * DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
 * Dyn.d_un.d_val field of the Elf*_Dyn structure.
 */
#define	DT_VALRNGLO	0x6ffffd00
#define	DT_GNU_PRELINKED	0x6ffffdf5 /* prelinking timestamp */
#define	DT_GNU_CONFLICTSZ	0x6ffffdf6 /* size of conflict section */
#define	DT_GNU_LIBLISTSZ	0x6ffffdf7 /* size of library list */
#define	DT_CHECKSUM	0x6ffffdf8	/* elf checksum */
#define	DT_PLTPADSZ	0x6ffffdf9	/* pltpadding size */
#define	DT_MOVEENT	0x6ffffdfa	/* move table entry size */
#define	DT_MOVESZ	0x6ffffdfb	/* move table size */
#define	DT_FEATURE	0x6ffffdfc	/* feature holder */
#define	DT_FEATURE_1	DT_FEATURE
#define	DT_POSFLAG_1	0x6ffffdfd	/* flags for DT_* entries, effecting */
					/*	the following DT_* entry. */
					/*	See DF_P1_* definitions */
#define	DT_SYMINSZ	0x6ffffdfe	/* syminfo table size (in bytes) */
#define	DT_SYMINENT	0x6ffffdff	/* syminfo entry size (in bytes) */
#define	DT_VALRNGHI	0x6ffffdff

/*
 * DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
 * Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
 *
 * If any adjustment is made to the ELF object after it has been
 * built, these entries will need to be adjusted.
 */
#define	DT_ADDRRNGLO	0x6ffffe00
#define	DT_GNU_HASH	0x6ffffef5	/* GNU-style hash table */
#define	DT_TLSDESC_PLT	0x6ffffef6	/* loc. of PLT for tlsdesc resolver */
#define	DT_TLSDESC_GOT	0x6ffffef7	/* loc. of GOT for tlsdesc resolver */
#define	DT_GNU_CONFLICT	0x6ffffef8	/* address of conflict section */
#define	DT_GNU_LIBLIST	0x6ffffef9	/* address of library list */
#define	DT_CONFIG	0x6ffffefa	/* configuration information */
#define	DT_DEPAUDIT	0x6ffffefb	/* dependency auditing */
#define	DT_AUDIT	0x6ffffefc	/* object auditing */
#define	DT_PLTPAD	0x6ffffefd	/* pltpadding (sparcv9) */
#define	DT_MOVETAB	0x6ffffefe	/* move table */
#define	DT_SYMINFO	0x6ffffeff	/* syminfo table */
#define	DT_ADDRRNGHI	0x6ffffeff

#define	DT_VERSYM	0x6ffffff0	/* Address of versym section. */
#define	DT_RELACOUNT	0x6ffffff9	/* number of RELATIVE relocations */
#define	DT_RELCOUNT	0x6ffffffa	/* number of RELATIVE relocations */
#define	DT_FLAGS_1	0x6ffffffb	/* state flags - see DF_1_* defs */
#define	DT_VERDEF	0x6ffffffc	/* Address of verdef section. */
#define	DT_VERDEFNUM	0x6ffffffd	/* Number of elems in verdef section */
#define	DT_VERNEED	0x6ffffffe	/* Address of verneed section. */
#define	DT_VERNEEDNUM	0x6fffffff	/* Number of elems in verneed section */

#define	DT_LOPROC	0x70000000	/* First processor-specific type. */

#define	DT_AARCH64_BTI_PLT		0x70000001
#define	DT_AARCH64_PAC_PLT		0x70000003
#define	DT_AARCH64_VARIANT_PCS		0x70000005

#define	DT_ARM_SYMTABSZ			0x70000001
#define	DT_ARM_PREEMPTMAP		0x70000002

#define	DT_SPARC_REGISTER		0x70000001
#define	DT_DEPRECATED_SPARC_REGISTER	0x7000001

#define	DT_MIPS_RLD_VERSION		0x70000001
#define	DT_MIPS_TIME_STAMP		0x70000002
#define	DT_MIPS_ICHECKSUM		0x70000003
#define	DT_MIPS_IVERSION		0x70000004
#define	DT_MIPS_FLAGS			0x70000005
#define	DT_MIPS_BASE_ADDRESS		0x70000006
#define	DT_MIPS_CONFLICT		0x70000008
#define	DT_MIPS_LIBLIST			0x70000009
#define	DT_MIPS_LOCAL_GOTNO		0x7000000a
#define	DT_MIPS_CONFLICTNO		0x7000000b
#define	DT_MIPS_LIBLISTNO		0x70000010
#define	DT_MIPS_SYMTABNO		0x70000011
#define	DT_MIPS_UNREFEXTNO		0x70000012
#define	DT_MIPS_GOTSYM			0x70000013
#define	DT_MIPS_HIPAGENO		0x70000014
#define	DT_MIPS_RLD_MAP			0x70000016
#define	DT_MIPS_DELTA_CLASS		0x70000017
#define	DT_MIPS_DELTA_CLASS_NO		0x70000018
#define	DT_MIPS_DELTA_INSTANCE		0x70000019
#define	DT_MIPS_DELTA_INSTANCE_NO	0x7000001A
#define	DT_MIPS_DELTA_RELOC		0x7000001B
#define	DT_MIPS_DELTA_RELOC_NO		0x7000001C
#define	DT_MIPS_DELTA_SYM		0x7000001D
#define	DT_MIPS_DELTA_SYM_NO		0x7000001E
#define	DT_MIPS_DELTA_CLASSSYM		0x70000020
#define	DT_MIPS_DELTA_CLASSSYM_NO	0x70000021
#define	DT_MIPS_CXX_FLAGS		0x70000022
#define	DT_MIPS_PIXIE_INIT		0x70000023
#define	DT_MIPS_SYMBOL_LIB		0x70000024
#define	DT_MIPS_LOCALPAGE_GOTIDX	0x70000025
#define	DT_MIPS_LOCAL_GOTIDX		0x70000026
#define	DT_MIPS_HIDDEN_GOTIDX		0x70000027
#define	DT_MIPS_PROTECTED_GOTIDX	0x70000028
#define	DT_MIPS_OPTIONS			0x70000029
#define	DT_MIPS_INTERFACE		0x7000002A
#define	DT_MIPS_DYNSTR_ALIGN		0x7000002B
#define	DT_MIPS_INTERFACE_SIZE		0x7000002C
#define	DT_MIPS_RLD_TEXT_RESOLVE_ADDR	0x7000002D
#define	DT_MIPS_PERF_SUFFIX		0x7000002E
#define	DT_MIPS_COMPACT_SIZE		0x7000002F
#define	DT_MIPS_GP_VALUE		0x70000030
#define	DT_MIPS_AUX_DYNAMIC		0x70000031
#define	DT_MIPS_PLTGOT			0x70000032
#define	DT_MIPS_RLD_OBJ_UPDATE		0x70000033
#define	DT_MIPS_RWPLT			0x70000034
#define	DT_MIPS_RLD_MAP_REL		0x70000035

#define	DT_PPC_GOT			0x70000000
#define	DT_PPC_TLSOPT			0x70000001

#define	DT_PPC64_GLINK			0x70000000
#define	DT_PPC64_OPD			0x70000001
#define	DT_PPC64_OPDSZ			0x70000002
#define	DT_PPC64_TLSOPT			0x70000003

#define	DT_AUXILIARY	0x7ffffffd	/* shared library auxiliary name */
#define	DT_USED		0x7ffffffe	/* ignored - same as needed */
#define	DT_FILTER	0x7fffffff	/* shared library filter name */
#define	DT_HIPROC	0x7fffffff	/* Last processor-specific type. */

/* Values for DT_FLAGS */
#define	DF_ORIGIN	0x0001	/* Indicates that the object being loaded may
				   make reference to the $ORIGIN substitution
				   string */
#define	DF_SYMBOLIC	0x0002	/* Indicates "symbolic" linking. */
#define	DF_TEXTREL	0x0004	/* Indicates there may be relocations in
				   non-writable segments. */
#define	DF_BIND_NOW	0x0008	/* Indicates that the dynamic linker should
				   process all relocations for the object
				   containing this entry before transferring
				   control to the program. */
```