Response:
My thinking process to answer the request about `go/src/cmd/link/internal/ld/pe.go` goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of this Go file, ideally inferring its role within the Go toolchain and backing it up with code examples and details about command-line flags and potential pitfalls.

2. **Initial Scan and Keywords:** I quickly scanned the code, looking for keywords and patterns that stand out. Terms like `PE`, `Portable Executable`, `IMAGE_IMPORT_DESCRIPTOR`, `IMAGE_EXPORT_DIRECTORY`, `relocations`, `sections`, `.text`, `.rdata`, `.data`, `.bss`, `symbol table`, and `string table` immediately suggest this file is related to creating Windows executable files. The presence of constants like `IMAGE_SCN_CNT_CODE` and `IMAGE_REL_I386_DIR32` confirms this is dealing with the PE file format at a low level.

3. **Identify Key Structures:**  The `IMAGE_IMPORT_DESCRIPTOR` and `IMAGE_EXPORT_DIRECTORY` structs are crucial. They indicate this code handles importing functions from DLLs and exporting functions from the executable itself. The `peFile` struct is central, as it aggregates information about the various sections and tables needed for the PE file. The `peSection` struct represents individual sections within the PE file.

4. **Infer the Primary Functionality:** Based on the structures and keywords, I can infer that `pe.go` is responsible for *generating* the PE file format when the Go linker is targeting Windows. This involves:
    * Defining the layout of the PE file header and optional header.
    * Creating and managing different sections (.text, .rdata, .data, .bss, etc.).
    * Handling imports from and exports to DLLs.
    * Generating relocation information needed for the operating system to load the executable at different memory addresses.
    * Creating the symbol table and string table for debugging and linking purposes.

5. **Look for Functions that Manifest the Functionality:** I then looked for functions that *do* the work:
    * `Peinit`: Likely initializes PE-specific settings based on the target architecture.
    * `pewrite`:  Seems to be the function that actually writes the PE file to the output.
    * `addimports`, `addexports`: Clearly handle import and export functionalities.
    * `emitRelocations`:  Deals with generating relocation entries.
    * `writeSymbolTableAndStringTable`, `writeSymbols`:  Manage symbol and string table creation.
    * `addSection`:  A utility for creating new sections.

6. **Connect to Go Linking:** I considered *where* this file fits within the Go toolchain. The package `cmd/link/internal/ld` strongly suggests this is part of the Go linker. The `Link` struct passed around in functions like `Peinit` and `pewrite` is likely the linker's central context.

7. **Formulate the Main Functionality Description:**  Based on the above, I drafted the main function of the file: generating PE files.

8. **Infer Go Language Feature Implementation:**  Knowing it's for PE files, the immediate thought is *building Windows executables*. This involves concepts like:
    * **Linking against DLLs:**  The import structures directly relate to this.
    * **Exporting functions from a DLL (less common for Go executables, more for Go DLLs):** The export structures.
    * **Relocations:** Necessary for executables to load at different addresses.

9. **Create Go Code Examples:**  To illustrate, I thought of simple scenarios:
    * **Importing a function:**  `syscall.LoadLibrary` and `syscall.GetProcAddress` are the natural choices.
    * **Exporting a function (less typical for Go executables, so I noted the `-buildmode=c-shared` scenario):**  A simple function marked with `//go:nosplit`.

10. **Identify Command-Line Flags:** I searched for uses of `flag.` and `*Flag...` variables within the code. This revealed flags like `-s` (strip symbols), `-w` (disable DWARF), `-o` (output file), and others that influence the PE file generation. I focused on the most relevant ones, especially those directly used within the provided snippet.

11. **Consider Assumptions and Inputs/Outputs for Code Reasoning:**  For functions like `emitRelocations`, which involve more complex logic, I considered what inputs would trigger certain behaviors. For instance, the type of relocation (`R_ADDR`, `R_PCREL`) and the architecture influence the output. I made a simplified assumption about a relocation and demonstrated how the offset is calculated.

12. **Identify Common Mistakes:** I thought about what developers might get wrong when working with PE files or when using the Go linker for Windows targets. Incorrectly specifying import libraries, issues with symbol decoration (especially with C/C++ interop), and problems with architecture mismatches came to mind.

13. **Structure and Refine:**  Finally, I organized the information into the requested categories: functionality, Go feature implementation (with examples), code reasoning (with assumptions), command-line arguments, and common mistakes. I reviewed and refined the language for clarity and accuracy.

This iterative process of scanning, identifying key elements, inferring functionality, finding supporting code, and then illustrating with examples and considering practical aspects helped me construct a comprehensive answer to the user's request.
基于您提供的 Go 语言代码片段（路径为 `go/src/cmd/link/internal/ld/pe.go` 的一部分），我们可以分析出它的主要功能是：

**核心功能：生成 Windows PE (Portable Executable) 文件。**

这个文件是 Go 链接器 (`cmd/link`) 在为 Windows 平台构建可执行文件（.exe）或动态链接库（.dll）时负责生成 PE 文件格式的核心部分。它实现了将链接后的 Go 代码和数据按照 PE 规范组织起来，以便操作系统能够正确加载和执行。

**具体功能点:**

1. **定义 PE 文件结构:**  代码中定义了关键的 PE 数据结构，例如 `IMAGE_IMPORT_DESCRIPTOR`（描述导入表）、`IMAGE_EXPORT_DIRECTORY`（描述导出表）以及用于表示 PE 文件自身的结构 `peFile` 和 PE 节区的结构 `peSection`。这些结构直接对应于 PE 文件格式的定义。

2. **管理 PE 文件头和可选头:**  `writeFileHeader` 和 `writeOptionalHeader` 函数负责写入 PE 文件的文件头（File Header）和可选头（Optional Header），其中包含了关于可执行文件的基本信息，如目标架构、入口点、代码和数据大小、内存对齐方式等。

3. **创建和管理节区 (Sections):** 代码中定义了常见的 PE 节区，如 `.text`（代码段）、`.rdata`（只读数据段）、`.data`（可读写数据段）、`.bss`（未初始化数据段）、`.idata`（导入表）、`.edata`（导出表）、`.reloc`（重定位表）等。`addSection` 函数用于创建新的节区，并设置其属性（例如执行权限、读写权限、对齐方式等）。

4. **处理符号表和字符串表:** `writeSymbolTableAndStringTable` 和 `writeSymbols` 函数负责生成 PE 文件的符号表（Symbol Table）和字符串表（String Table）。符号表包含了程序中定义的函数和变量的信息，用于调试和链接。字符串表用于存储符号名称等字符串。

5. **处理导入 (Imports):** `initdynimport`、`addimports` 和 `peimporteddlls` 函数负责处理从其他 DLL 导入的函数。这包括：
    * 识别需要导入的 DLL 和函数。
    * 构建 `IMAGE_IMPORT_DESCRIPTOR` 结构，描述每个导入的 DLL。
    * 在 `.idata` 节区中写入导入表和相关数据（DLL 名称、函数名称等）。
    * 在 `.data` 节区中分配空间用于存储导入函数的地址（IAT - Import Address Table）。

6. **处理导出 (Exports):** `initdynexport` 和 `addexports` 函数负责处理将当前可执行文件或 DLL 中定义的函数导出给其他模块使用。这包括：
    * 识别需要导出的函数。
    * 构建 `IMAGE_EXPORT_DIRECTORY` 结构，描述导出的函数。
    * 在 `.edata` 节区中写入导出表和相关数据（导出函数地址、名称等）。

7. **处理重定位 (Relocations):** `emitRelocations`、`addPEBaseReloc` 和相关的 `peBaseRelocTable` 结构负责处理 PE 文件的重定位信息。重定位是当程序加载到内存中的不同地址时，需要调整代码和数据中某些地址引用的机制。这对于生成可重定位的 DLL 和 PIE (Position Independent Executable) 可执行文件非常重要。

8. **处理 SEH (Structured Exception Handling) 数据:** `addSEH` 函数负责添加用于 Windows 结构化异常处理的数据节区 (`.pdata` 和 `.xdata`)。

9. **处理 DWARF 调试信息:** `addDWARF` 函数负责将 DWARF 调试信息添加到 PE 文件中，用于程序调试。

10. **处理资源 (Resources):** `setpersrc` 和 `addpersrc` 函数负责将程序资源（例如图标、字符串、对话框等）添加到 PE 文件的 `.rsrc` 节区中。

11. **设置 PE 文件头参数:**  代码中定义了 `PEBASE`（基地址）、`PESECTALIGN`（节区对齐）、`PEFILEALIGN`（文件对齐）等常量，用于控制生成的 PE 文件的布局。

**推断 Go 语言功能的实现 (并举例说明):**

这段代码是 Go 语言链接器实现 **构建 Windows 可执行文件和动态链接库** 的一部分。

**Go 代码示例 (说明导入 DLL 函数):**

假设你的 Go 代码需要调用 Windows API 中的 `MessageBoxW` 函数：

```go
package main

import (
	"syscall"
	"unsafe"
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	messageBoxW      = user32.NewProc("MessageBoxW")
)

func MessageBox(caption, text string) int {
	ret, _, _ := messageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(text))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(caption))),
		0,
	)
	return int(ret)
}

func main() {
	MessageBox("Hello", "你好，世界！")
}
```

在这个例子中，`syscall.NewLazyDLL("user32.dll")` 和 `user32.NewProc("MessageBoxW")`  指示 Go 运行时需要在 `user32.dll` 中查找 `MessageBoxW` 函数。当链接器处理这段代码时，`pe.go` 中的相关逻辑（`initdynimport` 和 `addimports`）会被触发，在生成的 PE 文件的 `.idata` 节区中创建相应的导入表项，记录需要从 `user32.dll` 导入 `MessageBoxW` 函数的信息。

**假设的输入与输出 (针对 `emitRelocations` 函数简化示例):**

**假设输入:**

* 一个包含代码的 `.text` 节区，其中包含一条指令，需要跳转到另一个函数 `targetFunc`。
* `targetFunc` 的地址在链接时确定。
* 需要生成针对 x86-64 架构的 PE 文件。

**代码片段 (假设 `.text` 节区中的指令):**

```assembly
; ... 一些代码 ...
call targetFunc  ; 这是一个需要重定位的指令 (R_PCREL)
; ... 更多代码 ...
```

**`emitRelocations` 函数处理逻辑 (简化):**

`emitRelocations` 会遍历 `.text` 节区中的重定位信息。对于 `call targetFunc` 指令，它会识别出这是一个需要计算相对于当前指令地址的偏移量的重定位 (`R_PCREL` 或类似的 PE 重定位类型，例如 `IMAGE_REL_AMD64_REL32`)。

**假设输出 (在 `.reloc` 节区中生成的重定位表项):**

假设 `call targetFunc` 指令的偏移量在 `.text` 节区中是 `0x1000`，并且需要生成一个相对于当前指令地址的 32 位偏移量重定位：

```
Offset: 0x1000  ; 需要重定位的地址在 .text 节区中的偏移
Type: IMAGE_REL_AMD64_REL32 ; 重定位类型为相对于指令指针的 32 位偏移
```

**解释:** 当操作系统加载这个 PE 文件时，它会读取重定位表，找到偏移量为 `0x1000` 的位置，并根据 `IMAGE_REL_AMD64_REL32` 的类型，计算出 `targetFunc` 的实际加载地址与 `call` 指令地址之间的差值，然后将这个差值写入到 `0x1000` 的位置，从而确保跳转指令能够正确执行。

**命令行参数的具体处理:**

虽然这段代码本身不直接处理命令行参数，但它会受到链接器命令行参数的影响。一些相关的参数包括：

* **`-o <output_file>`:**  指定输出文件名，`addexports` 函数中使用 `*flagOutfile` 来获取输出文件名，用于填充导出表中的模块名称。
* **`-s`:**  传递给链接器的 `-s` 参数会阻止 `writeSymbolTableAndStringTable` 和 `writeSymbols` 函数写入符号表，从而生成一个更小的、但难以调试的可执行文件。代码中的 `if !*FlagS` 条件判断了是否需要写入符号表。
* **`-w`:**  传递给链接器的 `-w` 参数会阻止 `addDWARF` 函数添加 DWARF 调试信息。代码中的 `if *FlagW` 条件判断了是否需要添加 DWARF 信息。
* **`-buildmode=...`:**  构建模式会影响 PE 文件的某些特性，例如是否生成可重定位的执行文件 (PIE)。`needPEBaseReloc` 函数会根据构建模式判断是否需要添加基址重定位表。
* **`-H windowsgui` 或 `-H windowsapp`:**  这些参数会影响 `writeOptionalHeader` 函数中设置的子系统类型 (`oh64.Subsystem` 和 `oh.Subsystem`)，决定是生成 GUI 应用程序还是控制台应用程序。
* **`-ldflags="-extldflags=..."`:**  可以传递额外的链接器标志给底层的 C/C++ 链接器（例如 MinGW），这些标志可能会影响 PE 文件的生成，但 `pe.go` 本身不直接处理这些标志。

**使用者易犯错的点:**

由于 `pe.go` 是 Go 链接器的内部实现，普通 Go 开发者通常不会直接与其交互。然而，在一些高级场景下，例如：

1. **CGO 互操作:**  当使用 CGO 调用 C/C++ 代码时，Windows 下的符号修饰规则 (name mangling) 可能会导致链接错误。`mangleABIName` 函数尝试处理这些规则，但开发者可能需要理解这些规则以确保 Go 和 C/C++ 代码之间的符号匹配。

2. **自定义链接器脚本 (不太常见于 Go):** 虽然 Go 链接器不使用传统的链接器脚本，但在某些极端情况下，开发者可能需要理解 PE 文件结构以进行更底层的控制。

3. **与外部链接器 (例如 MinGW) 集成:**  在外部链接模式下，Go 链接器会将部分工作委托给外部链接器。如果外部链接器的配置不正确，或者传递了不兼容的链接器标志，可能会导致 PE 文件生成失败。例如，需要确保 MinGW 的库路径设置正确。

4. **资源编译问题:**  如果资源文件（.rc）编译不正确或者与 Go 代码中的引用不匹配，会导致 `addpersrc` 函数处理资源时出错。

**示例说明 CGO 互操作可能遇到的错误:**

假设一个 C 头文件 `my_library.h` 中定义了一个函数：

```c
// my_library.h
__declspec(dllexport) int __stdcall MyFunction(int arg);
```

如果 Go 代码中尝试直接导入 `MyFunction`，可能会遇到链接错误，因为 Windows 下的 `__stdcall` 调用约定会导致函数名被修饰为 `_MyFunction@4` (在 32 位系统上)。

为了解决这个问题，Go 代码可能需要使用正确的修饰名：

```go
package main

/*
#cgo LDFLAGS: -L. -lmylibrary
#include "my_library.h"
*/
import "C"
import "fmt"

func main() {
	result := C.MyFunction(C.int(10))
	fmt.Println("Result from C:", result)
}
```

或者，在外部链接模式下，可能需要在 `.def` 文件中指定导出函数的名称和入口点。

总而言之，`go/src/cmd/link/internal/ld/pe.go` 是 Go 链接器在 Windows 平台上生成 PE 可执行文件的核心组件，它负责将链接后的代码和数据按照 PE 规范组织起来，以便操作系统能够正确加载和执行。理解其功能有助于理解 Go 程序的构建过程以及在 Windows 平台上的运行机制。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/pe.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// PE (Portable Executable) file writing
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

package ld

import (
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"internal/buildcfg"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type IMAGE_IMPORT_DESCRIPTOR struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

var (
	// PEBASE is the base address for the executable.
	// It is small for 32-bit and large for 64-bit.
	PEBASE int64

	// SectionAlignment must be greater than or equal to FileAlignment.
	// The default is the page size for the architecture.
	PESECTALIGN int64 = 0x1000

	// FileAlignment should be a power of 2 between 512 and 64 K, inclusive.
	// The default is 512. If the SectionAlignment is less than
	// the architecture's page size, then FileAlignment must match SectionAlignment.
	PEFILEALIGN int64 = 2 << 8
)

const (
	IMAGE_SCN_CNT_CODE               = 0x00000020
	IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
	IMAGE_SCN_LNK_OTHER              = 0x00000100
	IMAGE_SCN_LNK_INFO               = 0x00000200
	IMAGE_SCN_LNK_REMOVE             = 0x00000800
	IMAGE_SCN_LNK_COMDAT             = 0x00001000
	IMAGE_SCN_GPREL                  = 0x00008000
	IMAGE_SCN_MEM_PURGEABLE          = 0x00020000
	IMAGE_SCN_MEM_16BIT              = 0x00020000
	IMAGE_SCN_MEM_LOCKED             = 0x00040000
	IMAGE_SCN_MEM_PRELOAD            = 0x00080000
	IMAGE_SCN_ALIGN_1BYTES           = 0x00100000
	IMAGE_SCN_ALIGN_2BYTES           = 0x00200000
	IMAGE_SCN_ALIGN_4BYTES           = 0x00300000
	IMAGE_SCN_ALIGN_8BYTES           = 0x00400000
	IMAGE_SCN_ALIGN_16BYTES          = 0x00500000
	IMAGE_SCN_ALIGN_32BYTES          = 0x00600000
	IMAGE_SCN_ALIGN_64BYTES          = 0x00700000
	IMAGE_SCN_ALIGN_128BYTES         = 0x00800000
	IMAGE_SCN_ALIGN_256BYTES         = 0x00900000
	IMAGE_SCN_ALIGN_512BYTES         = 0x00A00000
	IMAGE_SCN_ALIGN_1024BYTES        = 0x00B00000
	IMAGE_SCN_ALIGN_2048BYTES        = 0x00C00000
	IMAGE_SCN_ALIGN_4096BYTES        = 0x00D00000
	IMAGE_SCN_ALIGN_8192BYTES        = 0x00E00000
	IMAGE_SCN_LNK_NRELOC_OVFL        = 0x01000000
	IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
	IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
	IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000
	IMAGE_SCN_MEM_SHARED             = 0x10000000
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000
	IMAGE_SCN_MEM_READ               = 0x40000000
	IMAGE_SCN_MEM_WRITE              = 0x80000000
)

// See https://docs.microsoft.com/en-us/windows/win32/debug/pe-format.
// TODO(crawshaw): add these constants to debug/pe.
const (
	IMAGE_SYM_TYPE_NULL      = 0
	IMAGE_SYM_TYPE_STRUCT    = 8
	IMAGE_SYM_DTYPE_FUNCTION = 2
	IMAGE_SYM_DTYPE_ARRAY    = 3
	IMAGE_SYM_CLASS_EXTERNAL = 2
	IMAGE_SYM_CLASS_STATIC   = 3

	IMAGE_REL_I386_DIR32   = 0x0006
	IMAGE_REL_I386_DIR32NB = 0x0007
	IMAGE_REL_I386_SECREL  = 0x000B
	IMAGE_REL_I386_REL32   = 0x0014

	IMAGE_REL_AMD64_ADDR64   = 0x0001
	IMAGE_REL_AMD64_ADDR32   = 0x0002
	IMAGE_REL_AMD64_ADDR32NB = 0x0003
	IMAGE_REL_AMD64_REL32    = 0x0004
	IMAGE_REL_AMD64_SECREL   = 0x000B

	IMAGE_REL_ARM_ABSOLUTE = 0x0000
	IMAGE_REL_ARM_ADDR32   = 0x0001
	IMAGE_REL_ARM_ADDR32NB = 0x0002
	IMAGE_REL_ARM_BRANCH24 = 0x0003
	IMAGE_REL_ARM_BRANCH11 = 0x0004
	IMAGE_REL_ARM_SECREL   = 0x000F

	IMAGE_REL_ARM64_ABSOLUTE       = 0x0000
	IMAGE_REL_ARM64_ADDR32         = 0x0001
	IMAGE_REL_ARM64_ADDR32NB       = 0x0002
	IMAGE_REL_ARM64_BRANCH26       = 0x0003
	IMAGE_REL_ARM64_PAGEBASE_REL21 = 0x0004
	IMAGE_REL_ARM64_REL21          = 0x0005
	IMAGE_REL_ARM64_PAGEOFFSET_12A = 0x0006
	IMAGE_REL_ARM64_PAGEOFFSET_12L = 0x0007
	IMAGE_REL_ARM64_SECREL         = 0x0008
	IMAGE_REL_ARM64_SECREL_LOW12A  = 0x0009
	IMAGE_REL_ARM64_SECREL_HIGH12A = 0x000A
	IMAGE_REL_ARM64_SECREL_LOW12L  = 0x000B
	IMAGE_REL_ARM64_TOKEN          = 0x000C
	IMAGE_REL_ARM64_SECTION        = 0x000D
	IMAGE_REL_ARM64_ADDR64         = 0x000E
	IMAGE_REL_ARM64_BRANCH19       = 0x000F
	IMAGE_REL_ARM64_BRANCH14       = 0x0010
	IMAGE_REL_ARM64_REL32          = 0x0011

	IMAGE_REL_BASED_HIGHLOW = 3
	IMAGE_REL_BASED_DIR64   = 10
)

const (
	PeMinimumTargetMajorVersion = 6
	PeMinimumTargetMinorVersion = 1
)

// DOS stub that prints out
// "This program cannot be run in DOS mode."
// See IMAGE_DOS_HEADER in the Windows SDK for the format of the header used here.
var dosstub = []uint8{
	0x4d,
	0x5a,
	0x90,
	0x00,
	0x03,
	0x00,
	0x00,
	0x00,
	0x04,
	0x00,
	0x00,
	0x00,
	0xff,
	0xff,
	0x00,
	0x00,
	0x8b,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x40,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x80,
	0x00,
	0x00,
	0x00,
	0x0e,
	0x1f,
	0xba,
	0x0e,
	0x00,
	0xb4,
	0x09,
	0xcd,
	0x21,
	0xb8,
	0x01,
	0x4c,
	0xcd,
	0x21,
	0x54,
	0x68,
	0x69,
	0x73,
	0x20,
	0x70,
	0x72,
	0x6f,
	0x67,
	0x72,
	0x61,
	0x6d,
	0x20,
	0x63,
	0x61,
	0x6e,
	0x6e,
	0x6f,
	0x74,
	0x20,
	0x62,
	0x65,
	0x20,
	0x72,
	0x75,
	0x6e,
	0x20,
	0x69,
	0x6e,
	0x20,
	0x44,
	0x4f,
	0x53,
	0x20,
	0x6d,
	0x6f,
	0x64,
	0x65,
	0x2e,
	0x0d,
	0x0d,
	0x0a,
	0x24,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
}

type Imp struct {
	s       loader.Sym
	off     uint64
	next    *Imp
	argsize int
}

type Dll struct {
	name     string
	nameoff  uint64
	thunkoff uint64
	ms       *Imp
	next     *Dll
}

var (
	rsrcsyms    []loader.Sym
	PESECTHEADR int32
	PEFILEHEADR int32
	pe64        int
	dr          *Dll

	dexport []loader.Sym
)

// peStringTable is a COFF string table.
type peStringTable struct {
	strings    []string
	stringsLen int
}

// size returns size of string table t.
func (t *peStringTable) size() int {
	// string table starts with 4-byte length at the beginning
	return t.stringsLen + 4
}

// add adds string str to string table t.
func (t *peStringTable) add(str string) int {
	off := t.size()
	t.strings = append(t.strings, str)
	t.stringsLen += len(str) + 1 // each string will have 0 appended to it
	return off
}

// write writes string table t into the output file.
func (t *peStringTable) write(out *OutBuf) {
	out.Write32(uint32(t.size()))
	for _, s := range t.strings {
		out.WriteString(s)
		out.Write8(0)
	}
}

// peSection represents section from COFF section table.
type peSection struct {
	name                 string
	shortName            string
	index                int // one-based index into the Section Table
	virtualSize          uint32
	virtualAddress       uint32
	sizeOfRawData        uint32
	pointerToRawData     uint32
	pointerToRelocations uint32
	numberOfRelocations  uint16
	characteristics      uint32
}

// checkOffset verifies COFF section sect offset in the file.
func (sect *peSection) checkOffset(off int64) {
	if off != int64(sect.pointerToRawData) {
		Errorf("%s.PointerToRawData = %#x, want %#x", sect.name, uint64(int64(sect.pointerToRawData)), uint64(off))
		errorexit()
	}
}

// checkSegment verifies COFF section sect matches address
// and file offset provided in segment seg.
func (sect *peSection) checkSegment(seg *sym.Segment) {
	if seg.Vaddr-uint64(PEBASE) != uint64(sect.virtualAddress) {
		Errorf("%s.VirtualAddress = %#x, want %#x", sect.name, uint64(int64(sect.virtualAddress)), uint64(int64(seg.Vaddr-uint64(PEBASE))))
		errorexit()
	}
	if seg.Fileoff != uint64(sect.pointerToRawData) {
		Errorf("%s.PointerToRawData = %#x, want %#x", sect.name, uint64(int64(sect.pointerToRawData)), uint64(int64(seg.Fileoff)))
		errorexit()
	}
}

// pad adds zeros to the section sect. It writes as many bytes
// as necessary to make section sect.SizeOfRawData bytes long.
// It assumes that n bytes are already written to the file.
func (sect *peSection) pad(out *OutBuf, n uint32) {
	out.WriteStringN("", int(sect.sizeOfRawData-n))
}

// write writes COFF section sect into the output file.
func (sect *peSection) write(out *OutBuf, linkmode LinkMode) error {
	h := pe.SectionHeader32{
		VirtualSize:          sect.virtualSize,
		SizeOfRawData:        sect.sizeOfRawData,
		PointerToRawData:     sect.pointerToRawData,
		PointerToRelocations: sect.pointerToRelocations,
		NumberOfRelocations:  sect.numberOfRelocations,
		Characteristics:      sect.characteristics,
	}
	if linkmode != LinkExternal {
		h.VirtualAddress = sect.virtualAddress
	}
	copy(h.Name[:], sect.shortName)
	return binary.Write(out, binary.LittleEndian, h)
}

// emitRelocations emits the relocation entries for the sect.
// The actual relocations are emitted by relocfn.
// This updates the corresponding PE section table entry
// with the relocation offset and count.
func (sect *peSection) emitRelocations(out *OutBuf, relocfn func() int) {
	sect.pointerToRelocations = uint32(out.Offset())
	// first entry: extended relocs
	out.Write32(0) // placeholder for number of relocation + 1
	out.Write32(0)
	out.Write16(0)

	n := relocfn() + 1

	cpos := out.Offset()
	out.SeekSet(int64(sect.pointerToRelocations))
	out.Write32(uint32(n))
	out.SeekSet(cpos)
	if n > 0x10000 {
		n = 0x10000
		sect.characteristics |= IMAGE_SCN_LNK_NRELOC_OVFL
	} else {
		sect.pointerToRelocations += 10 // skip the extend reloc entry
	}
	sect.numberOfRelocations = uint16(n - 1)
}

// peFile is used to build COFF file.
type peFile struct {
	sections       []*peSection
	stringTable    peStringTable
	textSect       *peSection
	rdataSect      *peSection
	dataSect       *peSection
	bssSect        *peSection
	ctorsSect      *peSection
	pdataSect      *peSection
	xdataSect      *peSection
	nextSectOffset uint32
	nextFileOffset uint32
	symtabOffset   int64 // offset to the start of symbol table
	symbolCount    int   // number of symbol table records written
	dataDirectory  [16]pe.DataDirectory
}

// addSection adds section to the COFF file f.
func (f *peFile) addSection(name string, sectsize int, filesize int) *peSection {
	sect := &peSection{
		name:             name,
		shortName:        name,
		index:            len(f.sections) + 1,
		virtualAddress:   f.nextSectOffset,
		pointerToRawData: f.nextFileOffset,
	}
	f.nextSectOffset = uint32(Rnd(int64(f.nextSectOffset)+int64(sectsize), PESECTALIGN))
	if filesize > 0 {
		sect.virtualSize = uint32(sectsize)
		sect.sizeOfRawData = uint32(Rnd(int64(filesize), PEFILEALIGN))
		f.nextFileOffset += sect.sizeOfRawData
	} else {
		sect.sizeOfRawData = uint32(sectsize)
	}
	f.sections = append(f.sections, sect)
	return sect
}

// addDWARFSection adds DWARF section to the COFF file f.
// This function is similar to addSection, but DWARF section names are
// longer than 8 characters, so they need to be stored in the string table.
func (f *peFile) addDWARFSection(name string, size int) *peSection {
	if size == 0 {
		Exitf("DWARF section %q is empty", name)
	}
	// DWARF section names are longer than 8 characters.
	// PE format requires such names to be stored in string table,
	// and section names replaced with slash (/) followed by
	// correspondent string table index.
	// see http://www.microsoft.com/whdc/system/platform/firmware/PECOFFdwn.mspx
	// for details
	off := f.stringTable.add(name)
	h := f.addSection(name, size, size)
	h.shortName = fmt.Sprintf("/%d", off)
	h.characteristics = IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_CNT_INITIALIZED_DATA
	return h
}

// addDWARF adds DWARF information to the COFF file f.
func (f *peFile) addDWARF() {
	if *FlagS { // disable symbol table
		return
	}
	if *FlagW { // disable dwarf
		return
	}
	for _, sect := range Segdwarf.Sections {
		h := f.addDWARFSection(sect.Name, int(sect.Length))
		fileoff := sect.Vaddr - Segdwarf.Vaddr + Segdwarf.Fileoff
		if uint64(h.pointerToRawData) != fileoff {
			Exitf("%s.PointerToRawData = %#x, want %#x", sect.Name, h.pointerToRawData, fileoff)
		}
	}
}

// addSEH adds SEH information to the COFF file f.
func (f *peFile) addSEH(ctxt *Link) {
	// .pdata section can exist without the .xdata section.
	// .xdata section depends on the .pdata section.
	if Segpdata.Length == 0 {
		return
	}
	d := pefile.addSection(".pdata", int(Segpdata.Length), int(Segpdata.Length))
	d.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
	if ctxt.LinkMode == LinkExternal {
		// Some gcc versions don't honor the default alignment for the .pdata section.
		d.characteristics |= IMAGE_SCN_ALIGN_4BYTES
	}
	pefile.pdataSect = d
	d.checkSegment(&Segpdata)
	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = d.virtualAddress
	pefile.dataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = d.virtualSize

	if Segxdata.Length > 0 {
		d = pefile.addSection(".xdata", int(Segxdata.Length), int(Segxdata.Length))
		d.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
		if ctxt.LinkMode == LinkExternal {
			// Some gcc versions don't honor the default alignment for the .xdata section.
			d.characteristics |= IMAGE_SCN_ALIGN_4BYTES
		}
		pefile.xdataSect = d
		d.checkSegment(&Segxdata)
	}
}

// addInitArray adds .ctors COFF section to the file f.
func (f *peFile) addInitArray(ctxt *Link) *peSection {
	// The size below was determined by the specification for array relocations,
	// and by observing what GCC writes here. If the initarray section grows to
	// contain more than one constructor entry, the size will need to be 8 * constructor_count.
	// However, the entire Go runtime is initialized from just one function, so it is unlikely
	// that this will need to grow in the future.
	var size int
	var alignment uint32
	switch buildcfg.GOARCH {
	default:
		Exitf("peFile.addInitArray: unsupported GOARCH=%q\n", buildcfg.GOARCH)
	case "386", "arm":
		size = 4
		alignment = IMAGE_SCN_ALIGN_4BYTES
	case "amd64", "arm64":
		size = 8
		alignment = IMAGE_SCN_ALIGN_8BYTES
	}
	sect := f.addSection(".ctors", size, size)
	sect.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | alignment
	sect.sizeOfRawData = uint32(size)
	ctxt.Out.SeekSet(int64(sect.pointerToRawData))
	sect.checkOffset(ctxt.Out.Offset())

	init_entry := ctxt.loader.Lookup(*flagEntrySymbol, 0)
	addr := uint64(ctxt.loader.SymValue(init_entry)) - ctxt.loader.SymSect(init_entry).Vaddr
	switch buildcfg.GOARCH {
	case "386", "arm":
		ctxt.Out.Write32(uint32(addr))
	case "amd64", "arm64":
		ctxt.Out.Write64(addr)
	}
	return sect
}

// emitRelocations emits relocation entries for go.o in external linking.
func (f *peFile) emitRelocations(ctxt *Link) {
	for ctxt.Out.Offset()&7 != 0 {
		ctxt.Out.Write8(0)
	}

	ldr := ctxt.loader

	// relocsect relocates symbols from first in section sect, and returns
	// the total number of relocations emitted.
	relocsect := func(sect *sym.Section, syms []loader.Sym, base uint64) int {
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
			if ldr.SymValue(s) >= eaddr {
				break
			}
			// Compute external relocations on the go, and pass to PEreloc1
			// to stream out.
			relocs := ldr.Relocs(s)
			for ri := 0; ri < relocs.Count(); ri++ {
				r := relocs.At(ri)
				rr, ok := extreloc(ctxt, ldr, s, r)
				if !ok {
					continue
				}
				if rr.Xsym == 0 {
					ctxt.Errorf(s, "missing xsym in relocation")
					continue
				}
				if ldr.SymDynid(rr.Xsym) < 0 {
					ctxt.Errorf(s, "reloc %d to non-coff symbol %s (outer=%s) %d", r.Type(), ldr.SymName(r.Sym()), ldr.SymName(rr.Xsym), ldr.SymType(r.Sym()))
				}
				if !thearch.PEreloc1(ctxt.Arch, ctxt.Out, ldr, s, rr, int64(uint64(ldr.SymValue(s)+int64(r.Off()))-base)) {
					ctxt.Errorf(s, "unsupported obj reloc %v/%d to %s", r.Type(), r.Siz(), ldr.SymName(r.Sym()))
				}
			}
		}
		sect.Rellen = uint64(ctxt.Out.Offset()) - sect.Reloff
		const relocLen = 4 + 4 + 2
		return int(sect.Rellen / relocLen)
	}

	type relsect struct {
		peSect *peSection
		seg    *sym.Segment
		syms   []loader.Sym
	}
	sects := []relsect{
		{f.textSect, &Segtext, ctxt.Textp},
		{f.rdataSect, &Segrodata, ctxt.datap},
		{f.dataSect, &Segdata, ctxt.datap},
	}
	if len(sehp.pdata) != 0 {
		sects = append(sects, relsect{f.pdataSect, &Segpdata, sehp.pdata})
	}
	if len(sehp.xdata) != 0 {
		sects = append(sects, relsect{f.xdataSect, &Segxdata, sehp.xdata})
	}
	for _, s := range sects {
		s.peSect.emitRelocations(ctxt.Out, func() int {
			var n int
			for _, sect := range s.seg.Sections {
				n += relocsect(sect, s.syms, s.seg.Vaddr)
			}
			return n
		})
	}

dwarfLoop:
	for i := 0; i < len(Segdwarf.Sections); i++ {
		sect := Segdwarf.Sections[i]
		si := dwarfp[i]
		if si.secSym() != loader.Sym(sect.Sym) ||
			ldr.SymSect(si.secSym()) != sect {
			panic("inconsistency between dwarfp and Segdwarf")
		}
		for _, pesect := range f.sections {
			if sect.Name == pesect.name {
				pesect.emitRelocations(ctxt.Out, func() int {
					return relocsect(sect, si.syms, sect.Vaddr)
				})
				continue dwarfLoop
			}
		}
		Errorf("emitRelocations: could not find %q section", sect.Name)
	}

	if f.ctorsSect == nil {
		return
	}

	f.ctorsSect.emitRelocations(ctxt.Out, func() int {
		dottext := ldr.Lookup(".text", 0)
		ctxt.Out.Write32(0)
		ctxt.Out.Write32(uint32(ldr.SymDynid(dottext)))
		switch buildcfg.GOARCH {
		default:
			ctxt.Errorf(dottext, "unknown architecture for PE: %q\n", buildcfg.GOARCH)
		case "386":
			ctxt.Out.Write16(IMAGE_REL_I386_DIR32)
		case "amd64":
			ctxt.Out.Write16(IMAGE_REL_AMD64_ADDR64)
		case "arm":
			ctxt.Out.Write16(IMAGE_REL_ARM_ADDR32)
		case "arm64":
			ctxt.Out.Write16(IMAGE_REL_ARM64_ADDR64)
		}
		return 1
	})
}

// writeSymbol appends symbol s to file f symbol table.
// It also sets s.Dynid to written symbol number.
func (f *peFile) writeSymbol(out *OutBuf, ldr *loader.Loader, s loader.Sym, name string, value int64, sectidx int, typ uint16, class uint8) {
	if len(name) > 8 {
		out.Write32(0)
		out.Write32(uint32(f.stringTable.add(name)))
	} else {
		out.WriteStringN(name, 8)
	}
	out.Write32(uint32(value))
	out.Write16(uint16(sectidx))
	out.Write16(typ)
	out.Write8(class)
	out.Write8(0) // no aux entries

	ldr.SetSymDynid(s, int32(f.symbolCount))

	f.symbolCount++
}

// mapToPESection searches peFile f for s symbol's location.
// It returns PE section index, and offset within that section.
func (f *peFile) mapToPESection(ldr *loader.Loader, s loader.Sym, linkmode LinkMode) (pesectidx int, offset int64, err error) {
	sect := ldr.SymSect(s)
	if sect == nil {
		return 0, 0, fmt.Errorf("could not map %s symbol with no section", ldr.SymName(s))
	}
	if sect.Seg == &Segtext {
		return f.textSect.index, int64(uint64(ldr.SymValue(s)) - Segtext.Vaddr), nil
	}
	if sect.Seg == &Segrodata {
		return f.rdataSect.index, int64(uint64(ldr.SymValue(s)) - Segrodata.Vaddr), nil
	}
	if sect.Seg != &Segdata {
		return 0, 0, fmt.Errorf("could not map %s symbol with non .text or .rdata or .data section", ldr.SymName(s))
	}
	v := uint64(ldr.SymValue(s)) - Segdata.Vaddr
	if linkmode != LinkExternal {
		return f.dataSect.index, int64(v), nil
	}
	if ldr.SymType(s).IsDATA() {
		return f.dataSect.index, int64(v), nil
	}
	// Note: although address of runtime.edata (type sym.SDATA) is at the start of .bss section
	// it still belongs to the .data section, not the .bss section.
	if v < Segdata.Filelen {
		return f.dataSect.index, int64(v), nil
	}
	return f.bssSect.index, int64(v - Segdata.Filelen), nil
}

var isLabel = make(map[loader.Sym]bool)

func AddPELabelSym(ldr *loader.Loader, s loader.Sym) {
	isLabel[s] = true
}

// writeSymbols writes all COFF symbol table records.
func (f *peFile) writeSymbols(ctxt *Link) {
	ldr := ctxt.loader
	addsym := func(s loader.Sym) {
		t := ldr.SymType(s)
		if ldr.SymSect(s) == nil && t != sym.SDYNIMPORT && t != sym.SHOSTOBJ && t != sym.SUNDEFEXT {
			return
		}

		name := ldr.SymName(s)

		// Only windows/386 requires underscore prefix on external symbols.
		if ctxt.Is386() && ctxt.IsExternal() &&
			(t == sym.SHOSTOBJ || t == sym.SUNDEFEXT || ldr.AttrCgoExport(s) ||
				// TODO(cuonglm): remove this hack
				//
				// Previously, windows/386 requires underscore prefix on external symbols,
				// but that's only applied for SHOSTOBJ/SUNDEFEXT or cgo export symbols.
				// "go.buildid" is STEXT, "type.*" is STYPE, thus they are not prefixed
				// with underscore.
				//
				// In external linking mode, the external linker can't resolve them as
				// external symbols. But we are lucky that they have "." in their name,
				// so the external linker see them as Forwarder RVA exports. See:
				//
				//  - https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-address-table
				//  - https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=ld/pe-dll.c;h=e7b82ba6ffadf74dc1b9ee71dc13d48336941e51;hb=HEAD#l972
				//
				// CL 317917 changes "." to ":" in symbols name, so these symbols can not be
				// found by external linker anymore. So a hacky way is adding the
				// underscore prefix for these 2 symbols. I don't have enough knowledge to
				// verify whether adding the underscore for all STEXT/STYPE symbols are
				// fine, even if it could be, that would be done in future CL.
				name == "go:buildid" || name == "type:*") {
			name = "_" + name
		}

		name = mangleABIName(ctxt, ldr, s, name)

		var peSymType uint16 = IMAGE_SYM_TYPE_NULL
		switch {
		case t.IsText(), t == sym.SDYNIMPORT, t == sym.SHOSTOBJ, t == sym.SUNDEFEXT:
			// Microsoft's PE documentation is contradictory. It says that the symbol's complex type
			// is stored in the pesym.Type most significant byte, but MSVC, LLVM, and mingw store it
			// in the 4 high bits of the less significant byte. Also, the PE documentation says that
			// the basic type for a function should be IMAGE_SYM_TYPE_VOID,
			// but the reality is that it uses IMAGE_SYM_TYPE_NULL instead.
			peSymType = IMAGE_SYM_DTYPE_FUNCTION<<4 + IMAGE_SYM_TYPE_NULL
		}
		sect, value, err := f.mapToPESection(ldr, s, ctxt.LinkMode)
		if err != nil {
			switch t {
			case sym.SDYNIMPORT, sym.SHOSTOBJ, sym.SUNDEFEXT:
			default:
				ctxt.Errorf(s, "addpesym: %v", err)
			}
		}
		class := IMAGE_SYM_CLASS_EXTERNAL
		if ldr.IsFileLocal(s) || ldr.AttrVisibilityHidden(s) || ldr.AttrLocal(s) {
			class = IMAGE_SYM_CLASS_STATIC
		}
		f.writeSymbol(ctxt.Out, ldr, s, name, value, sect, peSymType, uint8(class))
	}

	if ctxt.LinkMode == LinkExternal {
		// Include section symbols as external, because
		// .ctors and .debug_* section relocations refer to it.
		for _, pesect := range f.sections {
			s := ldr.LookupOrCreateSym(pesect.name, 0)
			f.writeSymbol(ctxt.Out, ldr, s, pesect.name, 0, pesect.index, IMAGE_SYM_TYPE_NULL, IMAGE_SYM_CLASS_STATIC)
		}
	}

	// Add special runtime.text and runtime.etext symbols.
	s := ldr.Lookup("runtime.text", 0)
	if ldr.SymType(s).IsText() {
		addsym(s)
	}
	s = ldr.Lookup("runtime.etext", 0)
	if ldr.SymType(s).IsText() {
		addsym(s)
	}

	// Add text symbols.
	for _, s := range ctxt.Textp {
		addsym(s)
	}

	shouldBeInSymbolTable := func(s loader.Sym) bool {
		if ldr.AttrNotInSymbolTable(s) {
			return false
		}
		name := ldr.SymName(s) // TODO: try not to read the name
		if name == "" || name[0] == '.' {
			return false
		}
		return true
	}

	// Add data symbols and external references.
	for s := loader.Sym(1); s < loader.Sym(ldr.NSym()); s++ {
		if !ldr.AttrReachable(s) {
			continue
		}
		t := ldr.SymType(s)
		if t >= sym.SELFRXSECT && t < sym.SXREF { // data sections handled in dodata
			if t == sym.STLSBSS {
				continue
			}
			if !shouldBeInSymbolTable(s) {
				continue
			}
			addsym(s)
		}

		switch t {
		case sym.SDYNIMPORT, sym.SHOSTOBJ, sym.SUNDEFEXT:
			addsym(s)
		default:
			if len(isLabel) > 0 && isLabel[s] {
				addsym(s)
			}
		}
	}
}

// writeSymbolTableAndStringTable writes out symbol and string tables for peFile f.
func (f *peFile) writeSymbolTableAndStringTable(ctxt *Link) {
	f.symtabOffset = ctxt.Out.Offset()

	// write COFF symbol table
	if !*FlagS || ctxt.LinkMode == LinkExternal {
		f.writeSymbols(ctxt)
	}

	// update COFF file header and section table
	size := f.stringTable.size() + 18*f.symbolCount
	var h *peSection
	if ctxt.LinkMode != LinkExternal {
		// We do not really need .symtab for go.o, and if we have one, ld
		// will also include it in the exe, and that will confuse windows.
		h = f.addSection(".symtab", size, size)
		h.characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE
		h.checkOffset(f.symtabOffset)
	}

	// write COFF string table
	f.stringTable.write(ctxt.Out)
	if ctxt.LinkMode != LinkExternal {
		h.pad(ctxt.Out, uint32(size))
	}
}

// writeFileHeader writes COFF file header for peFile f.
func (f *peFile) writeFileHeader(ctxt *Link) {
	var fh pe.FileHeader

	switch ctxt.Arch.Family {
	default:
		Exitf("unknown PE architecture: %v", ctxt.Arch.Family)
	case sys.AMD64:
		fh.Machine = pe.IMAGE_FILE_MACHINE_AMD64
	case sys.I386:
		fh.Machine = pe.IMAGE_FILE_MACHINE_I386
	case sys.ARM:
		fh.Machine = pe.IMAGE_FILE_MACHINE_ARMNT
	case sys.ARM64:
		fh.Machine = pe.IMAGE_FILE_MACHINE_ARM64
	}

	fh.NumberOfSections = uint16(len(f.sections))

	// Being able to produce identical output for identical input is
	// much more beneficial than having build timestamp in the header.
	fh.TimeDateStamp = 0

	if ctxt.LinkMode != LinkExternal {
		fh.Characteristics = pe.IMAGE_FILE_EXECUTABLE_IMAGE
		switch ctxt.Arch.Family {
		case sys.AMD64, sys.I386:
			if ctxt.BuildMode != BuildModePIE {
				fh.Characteristics |= pe.IMAGE_FILE_RELOCS_STRIPPED
			}
		}
	}
	if pe64 != 0 {
		var oh64 pe.OptionalHeader64
		fh.SizeOfOptionalHeader = uint16(binary.Size(&oh64))
		fh.Characteristics |= pe.IMAGE_FILE_LARGE_ADDRESS_AWARE
	} else {
		var oh pe.OptionalHeader32
		fh.SizeOfOptionalHeader = uint16(binary.Size(&oh))
		fh.Characteristics |= pe.IMAGE_FILE_32BIT_MACHINE
	}

	fh.PointerToSymbolTable = uint32(f.symtabOffset)
	fh.NumberOfSymbols = uint32(f.symbolCount)

	binary.Write(ctxt.Out, binary.LittleEndian, &fh)
}

// writeOptionalHeader writes COFF optional header for peFile f.
func (f *peFile) writeOptionalHeader(ctxt *Link) {
	var oh pe.OptionalHeader32
	var oh64 pe.OptionalHeader64

	if pe64 != 0 {
		oh64.Magic = 0x20b // PE32+
	} else {
		oh.Magic = 0x10b // PE32
		oh.BaseOfData = f.dataSect.virtualAddress
	}

	// Fill out both oh64 and oh. We only use one. Oh well.
	oh64.MajorLinkerVersion = 3
	oh.MajorLinkerVersion = 3
	oh64.MinorLinkerVersion = 0
	oh.MinorLinkerVersion = 0
	oh64.SizeOfCode = f.textSect.sizeOfRawData
	oh.SizeOfCode = f.textSect.sizeOfRawData
	oh64.SizeOfInitializedData = f.dataSect.sizeOfRawData
	oh.SizeOfInitializedData = f.dataSect.sizeOfRawData
	oh64.SizeOfUninitializedData = 0
	oh.SizeOfUninitializedData = 0
	if ctxt.LinkMode != LinkExternal {
		oh64.AddressOfEntryPoint = uint32(Entryvalue(ctxt) - PEBASE)
		oh.AddressOfEntryPoint = uint32(Entryvalue(ctxt) - PEBASE)
	}
	oh64.BaseOfCode = f.textSect.virtualAddress
	oh.BaseOfCode = f.textSect.virtualAddress
	oh64.ImageBase = uint64(PEBASE)
	oh.ImageBase = uint32(PEBASE)
	oh64.SectionAlignment = uint32(PESECTALIGN)
	oh.SectionAlignment = uint32(PESECTALIGN)
	oh64.FileAlignment = uint32(PEFILEALIGN)
	oh.FileAlignment = uint32(PEFILEALIGN)
	oh64.MajorOperatingSystemVersion = PeMinimumTargetMajorVersion
	oh.MajorOperatingSystemVersion = PeMinimumTargetMajorVersion
	oh64.MinorOperatingSystemVersion = PeMinimumTargetMinorVersion
	oh.MinorOperatingSystemVersion = PeMinimumTargetMinorVersion
	oh64.MajorImageVersion = 1
	oh.MajorImageVersion = 1
	oh64.MinorImageVersion = 0
	oh.MinorImageVersion = 0
	oh64.MajorSubsystemVersion = PeMinimumTargetMajorVersion
	oh.MajorSubsystemVersion = PeMinimumTargetMajorVersion
	oh64.MinorSubsystemVersion = PeMinimumTargetMinorVersion
	oh.MinorSubsystemVersion = PeMinimumTargetMinorVersion
	oh64.SizeOfImage = f.nextSectOffset
	oh.SizeOfImage = f.nextSectOffset
	oh64.SizeOfHeaders = uint32(PEFILEHEADR)
	oh.SizeOfHeaders = uint32(PEFILEHEADR)
	if windowsgui {
		oh64.Subsystem = pe.IMAGE_SUBSYSTEM_WINDOWS_GUI
		oh.Subsystem = pe.IMAGE_SUBSYSTEM_WINDOWS_GUI
	} else {
		oh64.Subsystem = pe.IMAGE_SUBSYSTEM_WINDOWS_CUI
		oh.Subsystem = pe.IMAGE_SUBSYSTEM_WINDOWS_CUI
	}

	// Mark as having awareness of terminal services, to avoid ancient compatibility hacks.
	oh64.DllCharacteristics |= pe.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
	oh.DllCharacteristics |= pe.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE

	// Enable DEP
	oh64.DllCharacteristics |= pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT
	oh.DllCharacteristics |= pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT

	// The DLL can be relocated at load time.
	if needPEBaseReloc(ctxt) {
		oh64.DllCharacteristics |= pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		oh.DllCharacteristics |= pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
	}

	// Image can handle a high entropy 64-bit virtual address space.
	if ctxt.BuildMode == BuildModePIE {
		oh64.DllCharacteristics |= pe.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
	}

	// Disable stack growth as we don't want Windows to
	// fiddle with the thread stack limits, which we set
	// ourselves to circumvent the stack checks in the
	// Windows exception dispatcher.
	// Commit size must be strictly less than reserve
	// size otherwise reserve will be rounded up to a
	// larger size, as verified with VMMap.

	// On 64-bit, we always reserve 2MB stacks. "Pure" Go code is
	// okay with much smaller stacks, but the syscall package
	// makes it easy to call into arbitrary C code without cgo,
	// and system calls even in "pure" Go code are actually C
	// calls that may need more stack than we think.
	//
	// The default stack reserve size directly affects only the main
	// thread.
	//
	// For other threads, the runtime explicitly asks the kernel
	// to use the default stack size so that all stacks are
	// consistent.
	//
	// At thread start, in minit, the runtime queries the OS for
	// the actual stack bounds so that the stack size doesn't need
	// to be hard-coded into the runtime.
	oh64.SizeOfStackReserve = 0x00200000
	if !iscgo {
		oh64.SizeOfStackCommit = 0x00001000
	} else {
		// TODO(brainman): Maybe remove optional header writing altogether for cgo.
		// For cgo it is the external linker that is building final executable.
		// And it probably does not use any information stored in optional header.
		oh64.SizeOfStackCommit = 0x00200000 - 0x2000 // account for 2 guard pages
	}

	oh.SizeOfStackReserve = 0x00100000
	if !iscgo {
		oh.SizeOfStackCommit = 0x00001000
	} else {
		oh.SizeOfStackCommit = 0x00100000 - 0x2000 // account for 2 guard pages
	}

	oh64.SizeOfHeapReserve = 0x00100000
	oh.SizeOfHeapReserve = 0x00100000
	oh64.SizeOfHeapCommit = 0x00001000
	oh.SizeOfHeapCommit = 0x00001000
	oh64.NumberOfRvaAndSizes = 16
	oh.NumberOfRvaAndSizes = 16

	if pe64 != 0 {
		oh64.DataDirectory = f.dataDirectory
	} else {
		oh.DataDirectory = f.dataDirectory
	}

	if pe64 != 0 {
		binary.Write(ctxt.Out, binary.LittleEndian, &oh64)
	} else {
		binary.Write(ctxt.Out, binary.LittleEndian, &oh)
	}
}

var pefile peFile

func Peinit(ctxt *Link) {
	var l int

	if ctxt.Arch.PtrSize == 8 {
		// 64-bit architectures
		pe64 = 1
		PEBASE = 1 << 32
		if ctxt.Arch.Family == sys.AMD64 {
			// TODO(rsc): For cgo we currently use 32-bit relocations
			// that fail when PEBASE is too large.
			// We need to fix this, but for now, use a smaller PEBASE.
			PEBASE = 1 << 22
		}
		var oh64 pe.OptionalHeader64
		l = binary.Size(&oh64)
	} else {
		// 32-bit architectures
		PEBASE = 1 << 22
		var oh pe.OptionalHeader32
		l = binary.Size(&oh)
	}

	if ctxt.LinkMode == LinkExternal {
		// .rdata section will contain "masks" and "shifts" symbols, and they
		// need to be aligned to 16-bytes. So make all sections aligned
		// to 32-byte and mark them all IMAGE_SCN_ALIGN_32BYTES so external
		// linker will honour that requirement.
		PESECTALIGN = 32
		PEFILEALIGN = 0
		// We are creating an object file. The absolute address is irrelevant.
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
```