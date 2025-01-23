Response:
Let's break down the thought process for analyzing the provided Go code snippet for the `internal/xcoff` package.

**1. Initial Understanding: The Package Name**

The first clue is the package name: `xcoff`. This immediately suggests that the code deals with the XCOFF file format. A quick search for "XCOFF" confirms it's a variant of the COFF (Common Object File Format), primarily used by IBM's AIX operating system. This context is crucial for understanding the purpose of the structures and constants.

**2. Identifying Core Data Structures**

The code primarily defines `struct` types. These likely represent the different sections and entries within an XCOFF file. I would group them logically:

* **File Header:** `FileHeader32`, `FileHeader64`. These are the starting point of the file, containing metadata about the overall structure. The `32` and `64` suffixes clearly indicate support for both 32-bit and 64-bit architectures.
* **Section Header:** `SectionHeader32`, `SectionHeader64`. These describe individual segments of code, data, or metadata within the file. Again, the bitness difference is present.
* **Symbol Table Entry:** `SymEnt32`, `SymEnt64`. These entries hold information about symbols (functions, variables, etc.) within the object file.
* **Auxiliary Entries:** `AuxFile64`, `AuxFcn32`, `AuxFcn64`, `AuxSect64`, `AuxCSect32`, `AuxCSect64`. These structures provide additional information related to the preceding symbol table entries. The naming conventions (`AuxFile`, `AuxFcn`, etc.) hint at what kind of information they contain.
* **Loader Header:** `LoaderHeader32`, `LoaderHeader64`. These appear to be specific to loadable object files and might contain information used by the system's dynamic linker.
* **Loader Symbol:** `LoaderSymbol32`, `LoaderSymbol64`. Symbols specifically within the loader section.
* **Relocation Entry:** `Reloc32`, `Reloc64`. These are crucial for the dynamic linking process, describing how addresses need to be adjusted when the object file is loaded into memory.

**3. Examining Constants and Their Purpose**

The code also defines numerous constants. I would categorize them as follows:

* **Magic Numbers:** `U802TOCMAGIC`, `U64_TOCMAGIC`. These likely serve as identifiers at the beginning of the file to confirm it's a valid XCOFF file of a specific type. The names suggest compatibility with AIX and indicate 32-bit and 64-bit versions.
* **File Header Flags:** Constants starting with `F_` (e.g., `F_RELFLG`, `F_EXEC`). These bit flags within the `FileHeader` likely describe the file's type and purpose (e.g., relocatable, executable, shared object).
* **Section Header Flags:** Constants starting with `STYP_` and `SSUBTYP_` (e.g., `STYP_TEXT`, `STYP_DATA`, `SSUBTYP_DWINFO`). These flags within the `SectionHeader` describe the content of each section (e.g., code, data, debugging information). The `SSUBTYP_` prefix suggests subtypes within broader categories, likely related to DWARF debugging information.
* **Symbol Table Constants:** Constants related to `Nscnum` (e.g., `N_DEBUG`, `N_ABS`, `N_UNDEF`), `Ntype` (e.g., `SYM_V_INTERNAL`, `SYM_TYPE_FUNC`), and Storage Class (`C_NULL`, `C_EXT`, `C_STAT`). These constants define the meaning of different fields within the `SymEnt` structures.
* **Auxiliary Entry Constants:** Constants starting with `_AUX_` (e.g., `_AUX_EXCEPT`, `_AUX_FCN`). These likely indicate the type of auxiliary information being provided.
* **Symbol Type Constants:** Constants starting with `XTY_` (e.g., `XTY_ER`, `XTY_SD`). These define the basic type of a symbol.
* **File Auxiliary Type Constants:** Constants starting with `XFT_` (e.g., `XFT_FN`, `XFT_CT`). These define the specific information stored in `AuxFile64`.
* **Storage Mapping Class Constants:** Constants starting with `XMC_` (e.g., `XMC_PR`, `XMC_RO`). These define the memory mapping characteristics of a symbol or section.
* **Loader Header Constants:** `LDHDRSZ_32`, `LDHDRSZ_64`. These specify the sizes of the loader headers.
* **Relocation Constants:** Constants starting with `R_` (e.g., `R_POS`, `R_NEG`, `R_REL`). These define the different types of relocations needed. The presence of `R_TOC` strongly suggests this is related to PowerPC architectures where a Table of Contents (TOC) is used. The `R_TLS` constants indicate support for thread-local storage.

**4. Inferring Functionality**

Based on the identified structures and constants, I can infer the primary function of this code:

* **Data Structures for XCOFF:** It provides Go data structures that directly map to the XCOFF file format specification. This allows Go programs to parse and manipulate XCOFF files.
* **Constants for Interpretation:** The constants provide a way to interpret the raw binary data within an XCOFF file, making it human-understandable and programmatically accessible.
* **Architecture Awareness:** The presence of `32` and `64` variants for many structures indicates support for both 32-bit and 64-bit XCOFF files.
* **Support for Key XCOFF Features:**  The structures cover essential aspects like file headers, sections, symbols, relocation information, and loader segments.

**5. Reasoning About Go Feature Implementation**

The `internal/` path suggests this package is not intended for direct public use. It's likely a supporting component for other Go tools, such as the linker or debugger, that need to work with XCOFF object files.

**6. Code Examples and Assumptions**

To provide code examples, I would focus on the most common use case: reading and interpreting an XCOFF file. I'd make assumptions about how a higher-level tool might use this package:

* **Assumption:** There's a function in a related package that handles opening and reading the raw bytes of an XCOFF file.
* **Assumption:** There are functions to read data from a given offset and size.

Based on these assumptions, I could demonstrate how to read the file header, section headers, and symbol table entries.

**7. Command-Line Arguments (If Applicable)**

Since this is an internal package defining data structures, it's unlikely to directly process command-line arguments. However, a tool *using* this package (like a linker) would certainly handle command-line arguments to specify input files, output files, etc.

**8. Common Mistakes**

Thinking about potential pitfalls, I would consider:

* **Incorrectly Handling 32-bit vs. 64-bit:**  Failing to check the magic number and using the wrong header structure would lead to incorrect parsing.
* **Endianness Issues:** While not explicitly stated, object files are often endian-specific. If the target architecture has a different endianness than the system running the Go code, byte order conversions might be necessary. (Though Go usually handles this).
* **Incorrectly Calculating Offsets:**  Errors in calculating the offsets to different parts of the file (symbol table, section data, etc.) would cause parsing failures.
* **Misinterpreting Flags and Constants:**  Not understanding the meaning of the various flags and constants could lead to misinterpreting the object file's contents.

By following these steps, I can systematically analyze the provided code snippet and arrive at a comprehensive understanding of its purpose and functionality within the broader Go ecosystem. The key is to leverage the naming conventions, the structure of the code, and knowledge of common file formats to infer its role.
这段Go语言代码定义了用于解析和表示XCOFF（Extended Common Object File Format）文件结构的各种数据结构和常量。XCOFF是IBM的AIX操作系统及其前身使用的目标文件格式。

**功能列举:**

1. **定义XCOFF文件头结构:** `FileHeader32` 和 `FileHeader64` 分别定义了32位和64位XCOFF文件的文件头结构，包含了魔数（用于标识文件类型），节的数量，创建时间，符号表偏移和大小，以及可选头大小和标志等信息。
2. **定义节头结构:** `SectionHeader32` 和 `SectionHeader64` 定义了32位和64位XCOFF文件中每个节的头信息，包括节的名称，物理地址，虚拟地址，大小，数据偏移，重定位信息偏移和数量，行号信息偏移和数量，以及节的标志。
3. **定义符号表项结构:** `SymEnt32` 和 `SymEnt64` 定义了32位和64位XCOFF文件中符号表中的条目，包含符号名（或者字符串表偏移），符号值，节号，类型，存储类以及辅助条目的数量。
4. **定义辅助条目结构:**  定义了多种辅助条目结构，如 `AuxFile64`（文件辅助信息），`AuxFcn32` 和 `AuxFcn64`（函数辅助信息）， `AuxSect64`（节辅助信息）， `AuxCSect32` 和 `AuxCSect64`（csect辅助信息）。这些结构提供了关于符号的额外信息。
5. **定义加载器头结构:** `LoaderHeader32` 和 `LoaderHeader64` 定义了32位和64位XCOFF文件中加载器段的头信息，包含了版本号，符号表和重定位表条目数量，导入文件ID字符串表长度和偏移，以及字符串表的长度和偏移等。
6. **定义加载器符号结构:** `LoaderSymbol32` 和 `LoaderSymbol64` 定义了加载器段的符号表条目。
7. **定义重定位表项结构:** `Reloc32` 和 `Reloc64` 定义了32位和64位XCOFF文件中的重定位信息，包含了需要重定位的地址，符号表索引，大小和类型。
8. **定义各种常量:** 定义了大量的常量，用于表示魔数、文件头标志、节头标志、符号类型、存储类、辅助类型、符号类型字段、文件辅助定义、存储映射类以及重定位类型等。这些常量用于解析和理解XCOFF文件中的各种标志和属性。

**推理其实现的Go语言功能:**

这段代码是 Go 语言标准库中用于处理特定目标文件格式（XCOFF）的一部分，主要用于 **链接器** 或 **二进制工具（如 `objdump`）** 等需要读取和理解 XCOFF 文件的场景。它提供了 Go 程序理解 XCOFF 文件结构的基础。

**Go 代码示例:**

以下代码示例展示了如何使用这些结构读取 XCOFF 文件的文件头信息（假设你已经有了一个 `io.Reader` 类型的 `r` 指向一个 XCOFF 文件）：

```go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"internal/xcoff"
)

func main() {
	f, err := os.Open("your_xcoff_file") // 替换为你的 XCOFF 文件路径
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	var magic uint16
	if err := binary.Read(f, binary.BigEndian, &magic); err != nil {
		fmt.Println("Error reading magic number:", err)
		return
	}

	if magic == xcoff.U802TOCMAGIC {
		var header xcoff.FileHeader32
		if err := binary.Read(f, binary.BigEndian, &header); err != nil {
			fmt.Println("Error reading 32-bit file header:", err)
			return
		}
		fmt.Printf("32-bit XCOFF File Header:\n")
		fmt.Printf("  Magic: 0%o\n", header.Fmagic)
		fmt.Printf("  Number of sections: %d\n", header.Fnscns)
		fmt.Printf("  Time and date: %d\n", header.Ftimedat)
		fmt.Printf("  Symbol table offset: %d\n", header.Fsymptr)
		fmt.Printf("  Number of symbols: %d\n", header.Fnsyms)
		fmt.Printf("  Optional header size: %d\n", header.Fopthdr)
		fmt.Printf("  Flags: 0x%04x\n", header.Fflags)
	} else if magic == xcoff.U64_TOCMAGIC {
		var header xcoff.FileHeader64
		if err := binary.Read(f, binary.BigEndian, &header); err != nil {
			fmt.Println("Error reading 64-bit file header:", err)
			return
		}
		fmt.Printf("64-bit XCOFF File Header:\n")
		fmt.Printf("  Magic: 0%o\n", header.Fmagic)
		fmt.Printf("  Number of sections: %d\n", header.Fnscns)
		fmt.Printf("  Time and date: %d\n", header.Ftimedat)
		fmt.Printf("  Symbol table offset: %d\n", header.Fsymptr)
		fmt.Printf("  Optional header size: %d\n", header.Fopthdr)
		fmt.Printf("  Flags: 0x%04x\n", header.Fflags)
		fmt.Printf("  Number of symbols: %d\n", header.Fnsyms)
	} else {
		fmt.Println("Unknown XCOFF magic number:", magic)
	}
}
```

**假设的输入与输出:**

**输入 (your_xcoff_file 的内容):**  假设 `your_xcoff_file` 是一个 32 位的 AIX XCOFF 可执行文件，其文件头的十六进制表示如下 (部分)：

```
07 37 03 00 ... (后续的字节代表 FileHeader32 的其他字段)
```

这里 `07 37` 是 `U802TOCMAGIC` 的大端字节序表示。

**输出:**

```
32-bit XCOFF File Header:
  Magic: 0737
  Number of sections: 3
  Time and date: ...
  Symbol table offset: ...
  Number of symbols: ...
  Optional header size: ...
  Flags: ...
```

输出的具体数值会根据 `your_xcoff_file` 的实际内容而变化。

**命令行参数的具体处理:**

这个 `internal/xcoff` 包本身并不直接处理命令行参数。它只是定义了数据结构。处理命令行参数通常发生在更高层次的工具中，例如 Go 语言的 `cmd/link` (链接器) 或自定义的 XCOFF 解析工具。这些工具会使用 `flag` 或其他库来解析命令行参数，例如指定要处理的 XCOFF 文件路径。

例如，一个假设的 XCOFF 解析工具可能会有如下的命令行参数处理：

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"internal/xcoff" // 引入 xcoff 包
)

func main() {
	var inputFile string
	flag.StringVar(&inputFile, "input", "", "Path to the XCOFF input file")
	flag.Parse()

	if inputFile == "" {
		fmt.Println("Please provide an input file using the -input flag.")
		return
	}

	// ... (打开文件并使用 xcoff 包中的结构解析文件)
}
```

在这个例子中，`-input` 就是一个命令行参数，用于指定 XCOFF 文件的路径。

**使用者易犯错的点:**

1. **字节序问题:** XCOFF 文件通常使用大端字节序。如果使用者在读取二进制数据时没有正确指定字节序（例如使用了 `binary.LittleEndian` 而不是 `binary.BigEndian`），会导致解析出的数据错误。
   ```go
   // 错误示例 (假设 XCOFF 是大端序的)
   var header xcoff.FileHeader32
   if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
       // ...
   }
   ```

2. **32位和64位文件的区分:**  使用者需要先读取文件头的魔数 (`Fmagic`) 来判断是 32 位还是 64 位的 XCOFF 文件，然后使用对应的结构体 (`FileHeader32` 或 `FileHeader64`) 进行解析。如果判断错误，会导致结构体字段错位，解析出错误的信息。

3. **偏移量计算错误:**  在读取节头、符号表等数据时，需要依赖文件头和节头中提供的偏移量信息。如果计算偏移量时出现错误，将无法定位到正确的数据位置。例如，符号表的起始位置由 `FileHeader.Fsymptr` 给出，符号表的大小需要根据 `FileHeader.Fnsyms` 和符号表项的大小 (`SYMESZ`) 计算。

4. **忽略辅助条目:** 符号表项后面可能会跟随辅助条目，`SymEnt.Nnumaux` 字段指示了辅助条目的数量。如果使用者只读取符号表项而忽略了辅助条目，可能会丢失重要的符号信息。

总而言之，`internal/xcoff` 包为 Go 语言提供了处理 XCOFF 文件格式的基础能力，它定义了与 XCOFF 文件结构相对应的数据结构和常量，供 Go 程序进行解析和操作。理解 XCOFF 文件的结构和字节序是正确使用这个包的关键。

### 提示词
```
这是路径为go/src/internal/xcoff/xcoff.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xcoff

// File Header.
type FileHeader32 struct {
	Fmagic   uint16 // Target machine
	Fnscns   uint16 // Number of sections
	Ftimedat uint32 // Time and date of file creation
	Fsymptr  uint32 // Byte offset to symbol table start
	Fnsyms   uint32 // Number of entries in symbol table
	Fopthdr  uint16 // Number of bytes in optional header
	Fflags   uint16 // Flags
}

type FileHeader64 struct {
	Fmagic   uint16 // Target machine
	Fnscns   uint16 // Number of sections
	Ftimedat uint32 // Time and date of file creation
	Fsymptr  uint64 // Byte offset to symbol table start
	Fopthdr  uint16 // Number of bytes in optional header
	Fflags   uint16 // Flags
	Fnsyms   uint32 // Number of entries in symbol table
}

const (
	FILHSZ_32 = 20
	FILHSZ_64 = 24
)
const (
	U802TOCMAGIC = 0737 // AIX 32-bit XCOFF
	U64_TOCMAGIC = 0767 // AIX 64-bit XCOFF
)

// Flags that describe the type of the object file.
const (
	F_RELFLG    = 0x0001
	F_EXEC      = 0x0002
	F_LNNO      = 0x0004
	F_FDPR_PROF = 0x0010
	F_FDPR_OPTI = 0x0020
	F_DSA       = 0x0040
	F_VARPG     = 0x0100
	F_DYNLOAD   = 0x1000
	F_SHROBJ    = 0x2000
	F_LOADONLY  = 0x4000
)

// Section Header.
type SectionHeader32 struct {
	Sname    [8]byte // Section name
	Spaddr   uint32  // Physical address
	Svaddr   uint32  // Virtual address
	Ssize    uint32  // Section size
	Sscnptr  uint32  // Offset in file to raw data for section
	Srelptr  uint32  // Offset in file to relocation entries for section
	Slnnoptr uint32  // Offset in file to line number entries for section
	Snreloc  uint16  // Number of relocation entries
	Snlnno   uint16  // Number of line number entries
	Sflags   uint32  // Flags to define the section type
}

type SectionHeader64 struct {
	Sname    [8]byte // Section name
	Spaddr   uint64  // Physical address
	Svaddr   uint64  // Virtual address
	Ssize    uint64  // Section size
	Sscnptr  uint64  // Offset in file to raw data for section
	Srelptr  uint64  // Offset in file to relocation entries for section
	Slnnoptr uint64  // Offset in file to line number entries for section
	Snreloc  uint32  // Number of relocation entries
	Snlnno   uint32  // Number of line number entries
	Sflags   uint32  // Flags to define the section type
	Spad     uint32  // Needs to be 72 bytes long
}

// Flags defining the section type.
const (
	STYP_DWARF  = 0x0010
	STYP_TEXT   = 0x0020
	STYP_DATA   = 0x0040
	STYP_BSS    = 0x0080
	STYP_EXCEPT = 0x0100
	STYP_INFO   = 0x0200
	STYP_TDATA  = 0x0400
	STYP_TBSS   = 0x0800
	STYP_LOADER = 0x1000
	STYP_DEBUG  = 0x2000
	STYP_TYPCHK = 0x4000
	STYP_OVRFLO = 0x8000
)
const (
	SSUBTYP_DWINFO  = 0x10000 // DWARF info section
	SSUBTYP_DWLINE  = 0x20000 // DWARF line-number section
	SSUBTYP_DWPBNMS = 0x30000 // DWARF public names section
	SSUBTYP_DWPBTYP = 0x40000 // DWARF public types section
	SSUBTYP_DWARNGE = 0x50000 // DWARF aranges section
	SSUBTYP_DWABREV = 0x60000 // DWARF abbreviation section
	SSUBTYP_DWSTR   = 0x70000 // DWARF strings section
	SSUBTYP_DWRNGES = 0x80000 // DWARF ranges section
	SSUBTYP_DWLOC   = 0x90000 // DWARF location lists section
	SSUBTYP_DWFRAME = 0xA0000 // DWARF frames section
	SSUBTYP_DWMAC   = 0xB0000 // DWARF macros section
)

// Symbol Table Entry.
type SymEnt32 struct {
	Nname   [8]byte // Symbol name
	Nvalue  uint32  // Symbol value
	Nscnum  uint16  // Section number of symbol
	Ntype   uint16  // Basic and derived type specification
	Nsclass uint8   // Storage class of symbol
	Nnumaux uint8   // Number of auxiliary entries
}

type SymEnt64 struct {
	Nvalue  uint64 // Symbol value
	Noffset uint32 // Offset of the name in string table or .debug section
	Nscnum  uint16 // Section number of symbol
	Ntype   uint16 // Basic and derived type specification
	Nsclass uint8  // Storage class of symbol
	Nnumaux uint8  // Number of auxiliary entries
}

const SYMESZ = 18

const (
	// Nscnum
	N_DEBUG = -2
	N_ABS   = -1
	N_UNDEF = 0

	//Ntype
	SYM_V_INTERNAL  = 0x1000
	SYM_V_HIDDEN    = 0x2000
	SYM_V_PROTECTED = 0x3000
	SYM_V_EXPORTED  = 0x4000
	SYM_TYPE_FUNC   = 0x0020 // is function
)

// Storage Class.
const (
	C_NULL    = 0   // Symbol table entry marked for deletion
	C_EXT     = 2   // External symbol
	C_STAT    = 3   // Static symbol
	C_BLOCK   = 100 // Beginning or end of inner block
	C_FCN     = 101 // Beginning or end of function
	C_FILE    = 103 // Source file name and compiler information
	C_HIDEXT  = 107 // Unnamed external symbol
	C_BINCL   = 108 // Beginning of include file
	C_EINCL   = 109 // End of include file
	C_WEAKEXT = 111 // Weak external symbol
	C_DWARF   = 112 // DWARF symbol
	C_GSYM    = 128 // Global variable
	C_LSYM    = 129 // Automatic variable allocated on stack
	C_PSYM    = 130 // Argument to subroutine allocated on stack
	C_RSYM    = 131 // Register variable
	C_RPSYM   = 132 // Argument to function or procedure stored in register
	C_STSYM   = 133 // Statically allocated symbol
	C_BCOMM   = 135 // Beginning of common block
	C_ECOML   = 136 // Local member of common block
	C_ECOMM   = 137 // End of common block
	C_DECL    = 140 // Declaration of object
	C_ENTRY   = 141 // Alternate entry
	C_FUN     = 142 // Function or procedure
	C_BSTAT   = 143 // Beginning of static block
	C_ESTAT   = 144 // End of static block
	C_GTLS    = 145 // Global thread-local variable
	C_STTLS   = 146 // Static thread-local variable
)

// File Auxiliary Entry
type AuxFile64 struct {
	Xfname   [8]byte // Name or offset inside string table
	Xftype   uint8   // Source file string type
	Xauxtype uint8   // Type of auxiliary entry
}

// Function Auxiliary Entry
type AuxFcn32 struct {
	Xexptr   uint32 // File offset to exception table entry
	Xfsize   uint32 // Size of function in bytes
	Xlnnoptr uint32 // File pointer to line number
	Xendndx  uint32 // Symbol table index of next entry
	Xpad     uint16 // Unused
}
type AuxFcn64 struct {
	Xlnnoptr uint64 // File pointer to line number
	Xfsize   uint32 // Size of function in bytes
	Xendndx  uint32 // Symbol table index of next entry
	Xpad     uint8  // Unused
	Xauxtype uint8  // Type of auxiliary entry
}

type AuxSect64 struct {
	Xscnlen  uint64 // section length
	Xnreloc  uint64 // Num RLDs
	pad      uint8
	Xauxtype uint8 // Type of auxiliary entry
}

// csect Auxiliary Entry.
type AuxCSect32 struct {
	Xscnlen   uint32 // Length or symbol table index
	Xparmhash uint32 // Offset of parameter type-check string
	Xsnhash   uint16 // .typchk section number
	Xsmtyp    uint8  // Symbol alignment and type
	Xsmclas   uint8  // Storage-mapping class
	Xstab     uint32 // Reserved
	Xsnstab   uint16 // Reserved
}

type AuxCSect64 struct {
	Xscnlenlo uint32 // Lower 4 bytes of length or symbol table index
	Xparmhash uint32 // Offset of parameter type-check string
	Xsnhash   uint16 // .typchk section number
	Xsmtyp    uint8  // Symbol alignment and type
	Xsmclas   uint8  // Storage-mapping class
	Xscnlenhi uint32 // Upper 4 bytes of length or symbol table index
	Xpad      uint8  // Unused
	Xauxtype  uint8  // Type of auxiliary entry
}

// Auxiliary type
const (
	_AUX_EXCEPT = 255
	_AUX_FCN    = 254
	_AUX_SYM    = 253
	_AUX_FILE   = 252
	_AUX_CSECT  = 251
	_AUX_SECT   = 250
)

// Symbol type field.
const (
	XTY_ER = 0 // External reference
	XTY_SD = 1 // Section definition
	XTY_LD = 2 // Label definition
	XTY_CM = 3 // Common csect definition
)

// Defines for File auxiliary definitions: x_ftype field of x_file
const (
	XFT_FN = 0   // Source File Name
	XFT_CT = 1   // Compile Time Stamp
	XFT_CV = 2   // Compiler Version Number
	XFT_CD = 128 // Compiler Defined Information
)

// Storage-mapping class.
const (
	XMC_PR     = 0  // Program code
	XMC_RO     = 1  // Read-only constant
	XMC_DB     = 2  // Debug dictionary table
	XMC_TC     = 3  // TOC entry
	XMC_UA     = 4  // Unclassified
	XMC_RW     = 5  // Read/Write data
	XMC_GL     = 6  // Global linkage
	XMC_XO     = 7  // Extended operation
	XMC_SV     = 8  // 32-bit supervisor call descriptor
	XMC_BS     = 9  // BSS class
	XMC_DS     = 10 // Function descriptor
	XMC_UC     = 11 // Unnamed FORTRAN common
	XMC_TC0    = 15 // TOC anchor
	XMC_TD     = 16 // Scalar data entry in the TOC
	XMC_SV64   = 17 // 64-bit supervisor call descriptor
	XMC_SV3264 = 18 // Supervisor call descriptor for both 32-bit and 64-bit
	XMC_TL     = 20 // Read/Write thread-local data
	XMC_UL     = 21 // Read/Write thread-local data (.tbss)
	XMC_TE     = 22 // TOC entry
)

// Loader Header.
type LoaderHeader32 struct {
	Lversion uint32 // Loader section version number
	Lnsyms   uint32 // Number of symbol table entries
	Lnreloc  uint32 // Number of relocation table entries
	Listlen  uint32 // Length of import file ID string table
	Lnimpid  uint32 // Number of import file IDs
	Limpoff  uint32 // Offset to start of import file IDs
	Lstlen   uint32 // Length of string table
	Lstoff   uint32 // Offset to start of string table
}

type LoaderHeader64 struct {
	Lversion uint32 // Loader section version number
	Lnsyms   uint32 // Number of symbol table entries
	Lnreloc  uint32 // Number of relocation table entries
	Listlen  uint32 // Length of import file ID string table
	Lnimpid  uint32 // Number of import file IDs
	Lstlen   uint32 // Length of string table
	Limpoff  uint64 // Offset to start of import file IDs
	Lstoff   uint64 // Offset to start of string table
	Lsymoff  uint64 // Offset to start of symbol table
	Lrldoff  uint64 // Offset to start of relocation entries
}

const (
	LDHDRSZ_32 = 32
	LDHDRSZ_64 = 56
)

// Loader Symbol.
type LoaderSymbol32 struct {
	Lname   [8]byte // Symbol name or byte offset into string table
	Lvalue  uint32  // Address field
	Lscnum  uint16  // Section number containing symbol
	Lsmtype uint8   // Symbol type, export, import flags
	Lsmclas uint8   // Symbol storage class
	Lifile  uint32  // Import file ID; ordinal of import file IDs
	Lparm   uint32  // Parameter type-check field
}

type LoaderSymbol64 struct {
	Lvalue  uint64 // Address field
	Loffset uint32 // Byte offset into string table of symbol name
	Lscnum  uint16 // Section number containing symbol
	Lsmtype uint8  // Symbol type, export, import flags
	Lsmclas uint8  // Symbol storage class
	Lifile  uint32 // Import file ID; ordinal of import file IDs
	Lparm   uint32 // Parameter type-check field
}

type Reloc32 struct {
	Rvaddr  uint32 // (virtual) address of reference
	Rsymndx uint32 // Index into symbol table
	Rsize   uint8  // Sign and reloc bit len
	Rtype   uint8  // Toc relocation type
}

type Reloc64 struct {
	Rvaddr  uint64 // (virtual) address of reference
	Rsymndx uint32 // Index into symbol table
	Rsize   uint8  // Sign and reloc bit len
	Rtype   uint8  // Toc relocation type
}

const (
	R_POS = 0x00 // A(sym) Positive Relocation
	R_NEG = 0x01 // -A(sym) Negative Relocation
	R_REL = 0x02 // A(sym-*) Relative to self
	R_TOC = 0x03 // A(sym-TOC) Relative to TOC
	R_TRL = 0x12 // A(sym-TOC) TOC Relative indirect load.

	R_TRLA = 0x13 // A(sym-TOC) TOC Rel load address. modifiable inst
	R_GL   = 0x05 // A(external TOC of sym) Global Linkage
	R_TCL  = 0x06 // A(local TOC of sym) Local object TOC address
	R_RL   = 0x0C // A(sym) Pos indirect load. modifiable instruction
	R_RLA  = 0x0D // A(sym) Pos Load Address. modifiable instruction
	R_REF  = 0x0F // AL0(sym) Non relocating ref. No garbage collect
	R_BA   = 0x08 // A(sym) Branch absolute. Cannot modify instruction
	R_RBA  = 0x18 // A(sym) Branch absolute. modifiable instruction
	R_BR   = 0x0A // A(sym-*) Branch rel to self. non modifiable
	R_RBR  = 0x1A // A(sym-*) Branch rel to self. modifiable instr

	R_TLS    = 0x20 // General-dynamic reference to TLS symbol
	R_TLS_IE = 0x21 // Initial-exec reference to TLS symbol
	R_TLS_LD = 0x22 // Local-dynamic reference to TLS symbol
	R_TLS_LE = 0x23 // Local-exec reference to TLS symbol
	R_TLSM   = 0x24 // Module reference to TLS symbol
	R_TLSML  = 0x25 // Module reference to local (own) module

	R_TOCU = 0x30 // Relative to TOC - high order bits
	R_TOCL = 0x31 // Relative to TOC - low order bits
)
```