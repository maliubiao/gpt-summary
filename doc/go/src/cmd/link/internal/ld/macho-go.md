Response:
The user wants to understand the functionality of the provided Go code snippet, which is a part of the Go linker responsible for generating Mach-O files.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The package name `ld` and the file name `macho.go` clearly indicate that this code deals with the Mach-O file format, primarily used by macOS, iOS, and other Apple operating systems. The presence of `cmd/link/internal/ld` suggests this is part of the Go linker.

2. **Analyze Key Data Structures:** Look for `struct` definitions. These represent the building blocks of the Mach-O file format as understood by the linker. Key structures like `MachoHdr`, `MachoSeg`, `MachoSect`, `MachoLoad`, and `MachoPlatformLoad` map directly to concepts in the Mach-O specification. This suggests the code is involved in creating and manipulating these structures.

3. **Examine Key Functions:** Identify functions that perform significant actions. Functions like `machowrite`, `domacho`, `asmbMacho`, `collectmachosyms`, `machosymtab`, `doMachoLink`, `machoEmitReloc`, and `machoDyldInfo` suggest core parts of the Mach-O generation process.

4. **Trace the Workflow (High-Level):**  Based on the function names and the data structures, infer the general flow of how a Mach-O file is constructed. It likely involves:
    * Setting up the header.
    * Defining segments and sections.
    * Handling symbols.
    * Creating load commands.
    * Writing the data to the output file.
    * Performing post-processing like code signing.

5. **Connect Functions to Functionality:** Match the functions to specific tasks in the Mach-O generation process. For example:
    * `machowrite` seems to be the function that writes the Mach-O header, segments, sections, and load commands to the output buffer.
    * `domacho` appears to be a higher-level function that orchestrates the Mach-O specific linking process, including handling platform information and symbol tables.
    * `asmbMacho` likely performs the final assembly and writing of the Mach-O file.
    * `collectmachosyms` focuses on gathering and classifying symbols for the Mach-O symbol table.
    * `machosymtab` generates the actual symbol table data.
    * `doMachoLink` coordinates the writing of the `__LINKEDIT` segment.
    * `machoEmitReloc` handles the generation and writing of relocation information.
    * `machoDyldInfo` is responsible for creating the dynamic linker information.

6. **Identify Specific Go Features:**  Look for usage patterns that indicate specific Go features:
    * **Structs:** Already identified as the core data representation.
    * **Constants:** Used extensively to define Mach-O magic numbers, CPU types, load command types, section flags, etc.
    * **Slices:** Used for managing lists of segments, sections, load commands, and symbols.
    * **Pointers:** Used for manipulating Mach-O data structures.
    * **Bitwise Operations:**  Common for working with Mach-O flags and masks.
    * **String Manipulation:** Necessary for handling segment and section names.
    * **Binary Encoding:** Used to write data in the correct byte order for the Mach-O format.
    * **File I/O:**  Used for reading host object files and writing the final Mach-O output.
    * **Sorting:** Used for ordering symbols in the symbol table.

7. **Reason about Go Function Implementation (with Examples):**  Choose a few illustrative functions and explain their purpose with a simple Go code example. Focus on demonstrating how the data structures are used. For instance, show how to create a new Mach-O load command or segment.

8. **Infer Command Line Argument Handling:** Look for patterns or mentions of command-line flags. The presence of `*FlagD`, `*FlagTextAddr`, `*FlagRound`, `*FlagW`, and `*FlagS` suggests the code reacts to these flags. Infer their possible meanings based on the context (e.g., `-D` for debug, `-T` for text address).

9. **Consider Potential Pitfalls:** Think about common errors developers might make when working with this code or the concepts it represents. For example, incorrect understanding of memory layout, incorrect flag usage, or issues with code signing.

10. **Structure the Answer:** Organize the findings logically with clear headings and bullet points. Start with a general overview, then delve into specifics like data structures, functions, Go features, and potential issues. Provide code examples where appropriate.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on individual function details.
* **Correction:** Shift to a higher-level overview first, explaining the overall purpose and then drilling down into specific functions and data structures. This provides better context.
* **Initial thought:** Provide very complex code examples.
* **Correction:** Simplify examples to illustrate core concepts clearly without overwhelming detail.
* **Initial thought:**  List all constants without explanation.
* **Correction:** Group constants thematically (e.g., header, segment, section related) to improve readability and understanding.
* **Initial thought:**  Only describe what the code *does*.
* **Correction:** Also explain *why* it does certain things, referencing the Mach-O file format concepts.

By following this thought process, combining code analysis with knowledge of the Mach-O format and Go's features, we can generate a comprehensive and informative answer to the user's request.
这段代码是 Go 语言链接器 `cmd/link` 的一部分，专门负责生成 **Mach-O** 格式的可执行文件或目标文件。Mach-O 是 macOS、iOS 和其他 Apple 操作系统使用的可执行文件格式。

以下是其主要功能：

1. **定义 Mach-O 文件结构体:**
   - `MachoHdr`: 表示 Mach-O 文件头。
   - `MachoSeg`: 表示 Mach-O 段 (Segment)。
   - `MachoSect`: 表示 Mach-O 节 (Section)。
   - `MachoLoad`: 表示 Mach-O 加载命令 (Load Command)。
   - `MachoPlatformLoad`:  表示特定平台的加载命令，例如 `LC_VERSION_MIN_*` 或 `LC_BUILD_VERSION`。

2. **管理 Mach-O 文件头的创建:**
   - `getMachoHdr()`: 获取指向全局 `machohdr` 变量的指针，该变量用于构建 Mach-O 文件头。
   - 设置 CPU 类型 (`cpu`) 和子类型 (`subcpu`)，例如 `MACHO_CPU_AMD64`, `MACHO_SUBCPU_X86`, `MACHO_CPU_ARM64` 等，这些常量用于指定目标架构。
   - 设置文件类型 (`MH_OBJECT` 或 `MH_EXECUTE`)，取决于链接模式是生成目标文件还是可执行文件。
   - 设置标志 (`flags`)，例如 `MH_NOUNDEFS` (没有未定义的符号), `MH_DYLDLINK` (用于动态链接), `MH_PIE` (位置无关可执行文件)。

3. **管理 Mach-O 段和节的创建:**
   - `newMachoLoad()`: 创建一个新的 Mach-O 加载命令。
   - `newMachoSeg()`: 创建一个新的 Mach-O 段。
   - `newMachoSect()`: 在一个段内创建一个新的 Mach-O 节。
   - 代码中定义了各种预定义的段名，例如 `__PAGEZERO`, `__TEXT`, `__DATA_CONST`, `__DATA`, `__DWARF`, `__LINKEDIT`。
   - 代码中也定义了各种预定义的节名和标志，例如 `.text`, `.rodata`, `.data`, `.bss`, `.plt`, `.got` 以及 `S_REGULAR`, `S_ZEROFILL`, `S_SYMBOL_STUBS` 等。

4. **处理动态链接库 (dylib):**
   - `machoadddynlib()`:  记录需要链接的动态链接库。这会添加到 Mach-O 头的加载命令中，以便动态链接器在运行时加载这些库。
   - 涉及计算加载动态链接库所需的空间，并根据需要调整文件头的大小 (`loadBudget`, `HEADR`).

5. **生成 Mach-O 文件内容:**
   - `machowrite()`:  将构建好的 Mach-O 头、段、节和加载命令写入到输出缓冲区 `OutBuf` 中。这包括写入魔数 (`MH_MAGIC`, `MH_MAGIC_64`), CPU 信息, 文件类型, 加载命令的数量和大小，以及段和节的具体信息。

6. **核心的 Mach-O 链接流程 (`domacho`, `asmbMacho`, `doMachoLink`):**
   - `domacho()`:  执行 Mach-O 特定的链接准备工作，例如处理平台加载命令，创建特殊的符号 (例如 `.machosymstr`, `.machosymtab`, `.plt`, `.got`)。还会处理插件的符号导出问题。
   - `asmbMacho()`:  执行 Mach-O 文件的最终组装和写入。它设置 Mach-O 文件头的信息，创建和配置各个段（如 `__TEXT`, `__DATA`, `__DWARF`, `__LINKEDIT`），并为可执行文件添加入口点加载命令 (`LC_UNIXTHREAD` 或 `LC_MAIN`)。如果需要代码签名，也会添加 `LC_CODE_SIGNATURE` 加载命令。
   - `doMachoLink()`:  负责生成 `__LINKEDIT` 段的内容，其中包含重定位信息、符号表、字符串表以及动态链接信息。

7. **处理符号表:**
   - `collectmachosyms()`: 收集需要添加到 Mach-O 符号表中的符号。
   - `machosymorder()`: 对符号进行排序，特别是在 macOS Mountain Lion 上，导出的符号需要排序。
   - `machosymtab()`:  生成 Mach-O 符号表的数据。
   - `machodysymtab()`: 生成 Mach-O 动态符号表的数据。

8. **处理重定位:**
   - `machoshbits()`:  为每个节设置 Mach-O 特定的属性，包括是否需要重定位。
   - `machoEmitReloc()`: 负责生成和写入 Mach-O 重定位信息。
   - `machorelocsect()`:  处理特定节的重定位。

9. **处理动态链接信息:**
   - `machoDyldInfo()`:  生成用于动态链接器的信息，例如 `.machorebase` 和 `.machobind` 表。
   - `MachoAddRebase()`: 添加重定位记录，用于在内存中加载时调整地址。
   - `MachoAddBind()`: 添加绑定记录，用于将 GOT 条目绑定到动态导入的符号。

10. **代码签名:**
    - `machoCodeSigSym()`: 创建代码签名符号。
    - `machoCodeSign()`:  对 Mach-O 文件进行代码签名 (ad-hoc 签名)。

11. **从 host object 中提取平台信息:**
    - `hostobjMachoPlatform()` 和 `peekMachoPlatform()`:  用于从 host object 文件中读取现有的 Mach-O 加载命令，特别是 `LC_VERSION_MIN_*` 或 `LC_BUILD_VERSION`，以便在最终的 Mach-O 文件中保留或调整平台信息。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码是 Go 语言链接器生成 **可执行文件或目标文件** (取决于链接模式) 的一部分，目标平台是使用 **Mach-O** 文件格式的操作系统（如 macOS、iOS）。

**Go 代码举例说明:**

假设我们要创建一个简单的 Mach-O 可执行文件，包含一个 `main` 函数。链接器会使用这段代码来构建 Mach-O 结构。

```go
package main

import "fmt"

func main() {
	fmt.Println("Hello, Mach-O!")
}
```

在链接这个程序时，`macho.go` 中的代码会参与以下步骤 (简化)：

1. **创建 Mach-O 头:** 设置 `machohdr.cpu` 为 `MACHO_CPU_AMD64` 或 `MACHO_CPU_ARM64`，设置文件类型为 `MH_EXECUTE`。
2. **创建 `__TEXT` 段:** 包含 `main` 函数的机器码。
   - 创建 `.text` 节，存放 `main` 函数的代码。
3. **创建 `__DATA` 段:**  可能包含全局变量等数据。
4. **创建符号表:**
   - 将 `main` 函数的符号信息添加到 `.machosymtab` 和 `.machosymstr`。
5. **创建入口点加载命令:**  指定程序从 `main` 函数开始执行。
6. **写入 Mach-O 文件:** 使用 `machowrite()` 将所有构建好的信息写入到输出文件中。

**代码推理示例 (假设的输入与输出):**

假设链接器处理一个包含 `func add(a, b int) int { return a + b }` 函数的 Go 源文件。

**假设输入:**
- Go 编译器生成的包含 `add` 函数机器码的目标文件。
- 链接器的配置信息，指定目标架构为 AMD64。

**`collectmachosyms` 函数的可能行为:**
- 输入：`ctxt.Textp` 中包含 `add` 函数的符号信息。
- 输出：`sortsym` 切片中包含 `add` 函数的符号，`nkind[SymKindLocal]` 计数器会增加。

**`machosymtab` 函数的可能行为:**
- 输入：`sortsym` 切片中包含 `add` 函数的符号信息。
- 输出：`.machosymtab` 符号表中会添加 `add` 函数的条目，包含其在 `.machosymstr` 中的偏移量，节号，以及地址。`.machosymstr` 字符串表中会添加 "_add" 字符串。

**命令行参数的具体处理:**

代码中使用了全局变量 `FlagD`, `FlagTextAddr`, `FlagRound`, `FlagW`, `FlagS` 等，这些变量很可能是在链接器的命令行参数解析阶段被设置的。

- **`*FlagD`:**  可能表示 "Debug" 模式。如果设置，`domacho` 函数可能会直接返回，跳过 Mach-O 相关的处理。
- **`*FlagTextAddr`:**  可能指定代码段的起始地址。这会影响 `asmbMacho` 中 `__TEXT` 段的 `vaddr`。
- **`*FlagRound`:**  可能指定段在文件中的对齐方式。这会影响 `asmbMacho` 中计算段大小时的 `Rnd` 函数调用。
- **`*FlagW`:**  可能表示是否生成 DWARF 调试信息。如果设置，与 DWARF 相关的段和节可能不会被创建。
- **`*FlagS`:**  可能表示是否进行符号剥离。如果设置，`collectmachosyms` 函数在收集符号时会跳过一些本地符号。

**使用者易犯错的点 (示例):**

1. **文件头大小不足 (`HEADR too small`):**  如果在链接过程中，需要添加的加载命令过多，导致预留的文件头空间不足，`machowrite` 函数会检查并可能触发 `Exitf("HEADR too small: %d > %d", a, HEADR)`。这通常需要调整链接器的配置或重新评估预留的文件头大小。

2. **段或节的数量过多 (`too many segs`, `too many sects in segment %s`):**  代码中使用了固定大小的数组 (`seg [16]MachoSeg`) 来存储段信息。如果需要创建的段超过了这个限制，会导致 `newMachoSeg` 函数调用 `Exitf("too many segs")`。类似地，每个段的节数量也有 `msect` 的限制。

3. **不理解代码签名的必要性:** 在 macOS 等平台上，对可执行文件进行代码签名是常见的安全要求。如果使用了某些需要签名的特性，但链接器没有正确配置代码签名，可能会导致程序无法正常运行。`machoCodeSign` 函数及其相关逻辑就是处理这个问题的。

4. **动态链接库路径错误:** 如果在链接时指定的动态链接库路径不正确，动态链接器在运行时可能无法找到这些库，导致程序启动失败。`machoadddynlib` 和后续的加载命令生成负责将这些路径写入 Mach-O 文件。

这些只是代码片段的功能和可能的使用场景。要完全理解 `macho.go` 的作用，需要结合 `cmd/link` 的其他部分以及 Mach-O 文件格式的详细规范进行分析。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/macho.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package ld

import (
	"bytes"
	"cmd/internal/codesign"
	imacho "cmd/internal/macho"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"internal/buildcfg"
	"io"
	"os"
	"sort"
	"strings"
	"unsafe"
)

type MachoHdr struct {
	cpu    uint32
	subcpu uint32
}

type MachoSect struct {
	name    string
	segname string
	addr    uint64
	size    uint64
	off     uint32
	align   uint32
	reloc   uint32
	nreloc  uint32
	flag    uint32
	res1    uint32
	res2    uint32
}

type MachoSeg struct {
	name       string
	vsize      uint64
	vaddr      uint64
	fileoffset uint64
	filesize   uint64
	prot1      uint32
	prot2      uint32
	nsect      uint32
	msect      uint32
	sect       []MachoSect
	flag       uint32
}

// MachoPlatformLoad represents a LC_VERSION_MIN_* or
// LC_BUILD_VERSION load command.
type MachoPlatformLoad struct {
	platform MachoPlatform // One of PLATFORM_* constants.
	cmd      MachoLoad
}

type MachoLoad struct {
	type_ uint32
	data  []uint32
}

type MachoPlatform int

/*
 * Total amount of space to reserve at the start of the file
 * for Header, PHeaders, and SHeaders.
 * May waste some.
 */
const (
	INITIAL_MACHO_HEADR = 4 * 1024
)

const (
	MACHO_CPU_AMD64                      = 1<<24 | 7
	MACHO_CPU_386                        = 7
	MACHO_SUBCPU_X86                     = 3
	MACHO_CPU_ARM                        = 12
	MACHO_SUBCPU_ARM                     = 0
	MACHO_SUBCPU_ARMV7                   = 9
	MACHO_CPU_ARM64                      = 1<<24 | 12
	MACHO_SUBCPU_ARM64_ALL               = 0
	MACHO_SUBCPU_ARM64_V8                = 1
	MACHO_SUBCPU_ARM64E                  = 2
	MACHO32SYMSIZE                       = 12
	MACHO64SYMSIZE                       = 16
	MACHO_X86_64_RELOC_UNSIGNED          = 0
	MACHO_X86_64_RELOC_SIGNED            = 1
	MACHO_X86_64_RELOC_BRANCH            = 2
	MACHO_X86_64_RELOC_GOT_LOAD          = 3
	MACHO_X86_64_RELOC_GOT               = 4
	MACHO_X86_64_RELOC_SUBTRACTOR        = 5
	MACHO_X86_64_RELOC_SIGNED_1          = 6
	MACHO_X86_64_RELOC_SIGNED_2          = 7
	MACHO_X86_64_RELOC_SIGNED_4          = 8
	MACHO_ARM_RELOC_VANILLA              = 0
	MACHO_ARM_RELOC_PAIR                 = 1
	MACHO_ARM_RELOC_SECTDIFF             = 2
	MACHO_ARM_RELOC_BR24                 = 5
	MACHO_ARM64_RELOC_UNSIGNED           = 0
	MACHO_ARM64_RELOC_BRANCH26           = 2
	MACHO_ARM64_RELOC_PAGE21             = 3
	MACHO_ARM64_RELOC_PAGEOFF12          = 4
	MACHO_ARM64_RELOC_GOT_LOAD_PAGE21    = 5
	MACHO_ARM64_RELOC_GOT_LOAD_PAGEOFF12 = 6
	MACHO_ARM64_RELOC_ADDEND             = 10
	MACHO_GENERIC_RELOC_VANILLA          = 0
	MACHO_FAKE_GOTPCREL                  = 100
)

const (
	MH_MAGIC    = 0xfeedface
	MH_MAGIC_64 = 0xfeedfacf

	MH_OBJECT  = 0x1
	MH_EXECUTE = 0x2

	MH_NOUNDEFS = 0x1
	MH_DYLDLINK = 0x4
	MH_PIE      = 0x200000
)

const (
	S_REGULAR                  = 0x0
	S_ZEROFILL                 = 0x1
	S_NON_LAZY_SYMBOL_POINTERS = 0x6
	S_SYMBOL_STUBS             = 0x8
	S_MOD_INIT_FUNC_POINTERS   = 0x9
	S_ATTR_PURE_INSTRUCTIONS   = 0x80000000
	S_ATTR_DEBUG               = 0x02000000
	S_ATTR_SOME_INSTRUCTIONS   = 0x00000400
)

const (
	PLATFORM_MACOS       MachoPlatform = 1
	PLATFORM_IOS         MachoPlatform = 2
	PLATFORM_TVOS        MachoPlatform = 3
	PLATFORM_WATCHOS     MachoPlatform = 4
	PLATFORM_BRIDGEOS    MachoPlatform = 5
	PLATFORM_MACCATALYST MachoPlatform = 6
)

// rebase table opcode
const (
	REBASE_TYPE_POINTER         = 1
	REBASE_TYPE_TEXT_ABSOLUTE32 = 2
	REBASE_TYPE_TEXT_PCREL32    = 3

	REBASE_OPCODE_MASK                               = 0xF0
	REBASE_IMMEDIATE_MASK                            = 0x0F
	REBASE_OPCODE_DONE                               = 0x00
	REBASE_OPCODE_SET_TYPE_IMM                       = 0x10
	REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB        = 0x20
	REBASE_OPCODE_ADD_ADDR_ULEB                      = 0x30
	REBASE_OPCODE_ADD_ADDR_IMM_SCALED                = 0x40
	REBASE_OPCODE_DO_REBASE_IMM_TIMES                = 0x50
	REBASE_OPCODE_DO_REBASE_ULEB_TIMES               = 0x60
	REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB            = 0x70
	REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80
)

// bind table opcode
const (
	BIND_TYPE_POINTER         = 1
	BIND_TYPE_TEXT_ABSOLUTE32 = 2
	BIND_TYPE_TEXT_PCREL32    = 3

	BIND_SPECIAL_DYLIB_SELF            = 0
	BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = -1
	BIND_SPECIAL_DYLIB_FLAT_LOOKUP     = -2
	BIND_SPECIAL_DYLIB_WEAK_LOOKUP     = -3

	BIND_OPCODE_MASK                                         = 0xF0
	BIND_IMMEDIATE_MASK                                      = 0x0F
	BIND_OPCODE_DONE                                         = 0x00
	BIND_OPCODE_SET_DYLIB_ORDINAL_IMM                        = 0x10
	BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB                       = 0x20
	BIND_OPCODE_SET_DYLIB_SPECIAL_IMM                        = 0x30
	BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM                = 0x40
	BIND_OPCODE_SET_TYPE_IMM                                 = 0x50
	BIND_OPCODE_SET_ADDEND_SLEB                              = 0x60
	BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB                  = 0x70
	BIND_OPCODE_ADD_ADDR_ULEB                                = 0x80
	BIND_OPCODE_DO_BIND                                      = 0x90
	BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB                        = 0xA0
	BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED                  = 0xB0
	BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB             = 0xC0
	BIND_OPCODE_THREADED                                     = 0xD0
	BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB = 0x00
	BIND_SUBOPCODE_THREADED_APPLY                            = 0x01
)

const machoHeaderSize64 = 8 * 4 // size of 64-bit Mach-O header

// Mach-O file writing
// https://developer.apple.com/mac/library/DOCUMENTATION/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html

var machohdr MachoHdr

var load []MachoLoad

var machoPlatform MachoPlatform

var seg [16]MachoSeg

var nseg int

var ndebug int

var nsect int

const (
	SymKindLocal = 0 + iota
	SymKindExtdef
	SymKindUndef
	NumSymKind
)

var nkind [NumSymKind]int

var sortsym []loader.Sym

var nsortsym int

// Amount of space left for adding load commands
// that refer to dynamic libraries. Because these have
// to go in the Mach-O header, we can't just pick a
// "big enough" header size. The initial header is
// one page, the non-dynamic library stuff takes
// up about 1300 bytes; we overestimate that as 2k.
var loadBudget = INITIAL_MACHO_HEADR - 2*1024

func getMachoHdr() *MachoHdr {
	return &machohdr
}

// Create a new Mach-O load command. ndata is the number of 32-bit words for
// the data (not including the load command header).
func newMachoLoad(arch *sys.Arch, type_ uint32, ndata uint32) *MachoLoad {
	if arch.PtrSize == 8 && (ndata&1 != 0) {
		ndata++
	}

	load = append(load, MachoLoad{})
	l := &load[len(load)-1]
	l.type_ = type_
	l.data = make([]uint32, ndata)
	return l
}

func newMachoSeg(name string, msect int) *MachoSeg {
	if nseg >= len(seg) {
		Exitf("too many segs")
	}

	s := &seg[nseg]
	nseg++
	s.name = name
	s.msect = uint32(msect)
	s.sect = make([]MachoSect, msect)
	return s
}

func newMachoSect(seg *MachoSeg, name string, segname string) *MachoSect {
	if seg.nsect >= seg.msect {
		Exitf("too many sects in segment %s", seg.name)
	}

	s := &seg.sect[seg.nsect]
	seg.nsect++
	s.name = name
	s.segname = segname
	nsect++
	return s
}

// Generic linking code.

var dylib []string

var linkoff int64

func machowrite(ctxt *Link, arch *sys.Arch, out *OutBuf, linkmode LinkMode) int {
	o1 := out.Offset()

	loadsize := 4 * 4 * ndebug
	for i := range load {
		loadsize += 4 * (len(load[i].data) + 2)
	}
	if arch.PtrSize == 8 {
		loadsize += 18 * 4 * nseg
		loadsize += 20 * 4 * nsect
	} else {
		loadsize += 14 * 4 * nseg
		loadsize += 17 * 4 * nsect
	}

	if arch.PtrSize == 8 {
		out.Write32(MH_MAGIC_64)
	} else {
		out.Write32(MH_MAGIC)
	}
	out.Write32(machohdr.cpu)
	out.Write32(machohdr.subcpu)
	if linkmode == LinkExternal {
		out.Write32(MH_OBJECT) /* file type - mach object */
	} else {
		out.Write32(MH_EXECUTE) /* file type - mach executable */
	}
	out.Write32(uint32(len(load)) + uint32(nseg) + uint32(ndebug))
	out.Write32(uint32(loadsize))
	flags := uint32(0)
	if nkind[SymKindUndef] == 0 {
		flags |= MH_NOUNDEFS
	}
	if ctxt.IsPIE() && linkmode == LinkInternal {
		flags |= MH_PIE | MH_DYLDLINK
	}
	out.Write32(flags) /* flags */
	if arch.PtrSize == 8 {
		out.Write32(0) /* reserved */
	}

	for i := 0; i < nseg; i++ {
		s := &seg[i]
		if arch.PtrSize == 8 {
			out.Write32(imacho.LC_SEGMENT_64)
			out.Write32(72 + 80*s.nsect)
			out.WriteStringN(s.name, 16)
			out.Write64(s.vaddr)
			out.Write64(s.vsize)
			out.Write64(s.fileoffset)
			out.Write64(s.filesize)
			out.Write32(s.prot1)
			out.Write32(s.prot2)
			out.Write32(s.nsect)
			out.Write32(s.flag)
		} else {
			out.Write32(imacho.LC_SEGMENT)
			out.Write32(56 + 68*s.nsect)
			out.WriteStringN(s.name, 16)
			out.Write32(uint32(s.vaddr))
			out.Write32(uint32(s.vsize))
			out.Write32(uint32(s.fileoffset))
			out.Write32(uint32(s.filesize))
			out.Write32(s.prot1)
			out.Write32(s.prot2)
			out.Write32(s.nsect)
			out.Write32(s.flag)
		}

		for j := uint32(0); j < s.nsect; j++ {
			t := &s.sect[j]
			if arch.PtrSize == 8 {
				out.WriteStringN(t.name, 16)
				out.WriteStringN(t.segname, 16)
				out.Write64(t.addr)
				out.Write64(t.size)
				out.Write32(t.off)
				out.Write32(t.align)
				out.Write32(t.reloc)
				out.Write32(t.nreloc)
				out.Write32(t.flag)
				out.Write32(t.res1) /* reserved */
				out.Write32(t.res2) /* reserved */
				out.Write32(0)      /* reserved */
			} else {
				out.WriteStringN(t.name, 16)
				out.WriteStringN(t.segname, 16)
				out.Write32(uint32(t.addr))
				out.Write32(uint32(t.size))
				out.Write32(t.off)
				out.Write32(t.align)
				out.Write32(t.reloc)
				out.Write32(t.nreloc)
				out.Write32(t.flag)
				out.Write32(t.res1) /* reserved */
				out.Write32(t.res2) /* reserved */
			}
		}
	}

	for i := range load {
		l := &load[i]
		out.Write32(l.type_)
		out.Write32(4 * (uint32(len(l.data)) + 2))
		for j := 0; j < len(l.data); j++ {
			out.Write32(l.data[j])
		}
	}

	return int(out.Offset() - o1)
}

func (ctxt *Link) domacho() {
	if *FlagD {
		return
	}

	// Copy platform load command.
	for _, h := range hostobj {
		load, err := hostobjMachoPlatform(&h)
		if err != nil {
			Exitf("%v", err)
		}
		if load != nil {
			machoPlatform = load.platform
			ml := newMachoLoad(ctxt.Arch, load.cmd.type_, uint32(len(load.cmd.data)))
			copy(ml.data, load.cmd.data)
			break
		}
	}
	if machoPlatform == 0 {
		machoPlatform = PLATFORM_MACOS
		if buildcfg.GOOS == "ios" {
			machoPlatform = PLATFORM_IOS
		}
		if ctxt.LinkMode == LinkInternal && machoPlatform == PLATFORM_MACOS {
			var version uint32
			switch ctxt.Arch.Family {
			case sys.ARM64, sys.AMD64:
				// This must be fairly recent for Apple signing (go.dev/issue/30488).
				// Having too old a version here was also implicated in some problems
				// calling into macOS libraries (go.dev/issue/56784).
				// In general this can be the most recent supported macOS version.
				version = 11<<16 | 0<<8 | 0<<0 // 11.0.0
			}
			ml := newMachoLoad(ctxt.Arch, imacho.LC_BUILD_VERSION, 4)
			ml.data[0] = uint32(machoPlatform)
			ml.data[1] = version // OS version
			ml.data[2] = version // SDK version
			ml.data[3] = 0       // ntools
		}
	}

	// empirically, string table must begin with " \x00".
	s := ctxt.loader.LookupOrCreateSym(".machosymstr", 0)
	sb := ctxt.loader.MakeSymbolUpdater(s)

	sb.SetType(sym.SMACHOSYMSTR)
	sb.SetReachable(true)
	sb.AddUint8(' ')
	sb.AddUint8('\x00')

	s = ctxt.loader.LookupOrCreateSym(".machosymtab", 0)
	sb = ctxt.loader.MakeSymbolUpdater(s)
	sb.SetType(sym.SMACHOSYMTAB)
	sb.SetReachable(true)

	if ctxt.IsInternal() {
		s = ctxt.loader.LookupOrCreateSym(".plt", 0) // will be __symbol_stub
		sb = ctxt.loader.MakeSymbolUpdater(s)
		sb.SetType(sym.SMACHOPLT)
		sb.SetReachable(true)

		s = ctxt.loader.LookupOrCreateSym(".got", 0) // will be __nl_symbol_ptr
		sb = ctxt.loader.MakeSymbolUpdater(s)
		sb.SetType(sym.SMACHOGOT)
		sb.SetReachable(true)
		sb.SetAlign(4)

		s = ctxt.loader.LookupOrCreateSym(".linkedit.plt", 0) // indirect table for .plt
		sb = ctxt.loader.MakeSymbolUpdater(s)
		sb.SetType(sym.SMACHOINDIRECTPLT)
		sb.SetReachable(true)

		s = ctxt.loader.LookupOrCreateSym(".linkedit.got", 0) // indirect table for .got
		sb = ctxt.loader.MakeSymbolUpdater(s)
		sb.SetType(sym.SMACHOINDIRECTGOT)
		sb.SetReachable(true)
	}

	// Add a dummy symbol that will become the __asm marker section.
	if ctxt.IsExternal() {
		s = ctxt.loader.LookupOrCreateSym(".llvmasm", 0)
		sb = ctxt.loader.MakeSymbolUpdater(s)
		sb.SetType(sym.SMACHO)
		sb.SetReachable(true)
		sb.AddUint8(0)
	}

	// Un-export runtime symbols from plugins. Since the runtime
	// is included in both the main binary and each plugin, these
	// symbols appear in both images. If we leave them exported in
	// the plugin, then the dynamic linker will resolve
	// relocations to these functions in the plugin's functab to
	// point to the main image, causing the runtime to think the
	// plugin's functab is corrupted. By unexporting them, these
	// become static references, which are resolved to the
	// plugin's text.
	//
	// It would be better to omit the runtime from plugins. (Using
	// relative PCs in the functab instead of relocations would
	// also address this.)
	//
	// See issue #18190.
	if ctxt.BuildMode == BuildModePlugin {
		for _, name := range []string{"_cgo_topofstack", "__cgo_topofstack", "_cgo_panic", "crosscall2"} {
			// Most of these are data symbols or C
			// symbols, so they have symbol version 0.
			ver := 0
			// _cgo_panic is a Go function, so it uses ABIInternal.
			if name == "_cgo_panic" {
				ver = abiInternalVer
			}
			s := ctxt.loader.Lookup(name, ver)
			if s != 0 {
				ctxt.loader.SetAttrCgoExportDynamic(s, false)
			}
		}
	}
}

func machoadddynlib(lib string, linkmode LinkMode) {
	if seenlib[lib] || linkmode == LinkExternal {
		return
	}
	seenlib[lib] = true

	// Will need to store the library name rounded up
	// and 24 bytes of header metadata. If not enough
	// space, grab another page of initial space at the
	// beginning of the output file.
	loadBudget -= (len(lib)+7)/8*8 + 24

	if loadBudget < 0 {
		HEADR += 4096
		*FlagTextAddr += 4096
		loadBudget += 4096
	}

	dylib = append(dylib, lib)
}

func machoshbits(ctxt *Link, mseg *MachoSeg, sect *sym.Section, segname string) {
	buf := "__" + strings.Replace(sect.Name[1:], ".", "_", -1)

	msect := newMachoSect(mseg, buf, segname)

	if sect.Rellen > 0 {
		msect.reloc = uint32(sect.Reloff)
		msect.nreloc = uint32(sect.Rellen / 8)
	}

	for 1<<msect.align < sect.Align {
		msect.align++
	}
	msect.addr = sect.Vaddr
	msect.size = sect.Length

	if sect.Vaddr < sect.Seg.Vaddr+sect.Seg.Filelen {
		// data in file
		if sect.Length > sect.Seg.Vaddr+sect.Seg.Filelen-sect.Vaddr {
			Errorf("macho cannot represent section %s crossing data and bss", sect.Name)
		}
		msect.off = uint32(sect.Seg.Fileoff + sect.Vaddr - sect.Seg.Vaddr)
	} else {
		msect.off = 0
		msect.flag |= S_ZEROFILL
	}

	if sect.Rwx&1 != 0 {
		msect.flag |= S_ATTR_SOME_INSTRUCTIONS
	}

	if sect.Name == ".text" {
		msect.flag |= S_ATTR_PURE_INSTRUCTIONS
	}

	if sect.Name == ".plt" {
		msect.name = "__symbol_stub1"
		msect.flag = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS | S_SYMBOL_STUBS
		msect.res1 = 0 //nkind[SymKindLocal];
		msect.res2 = 6
	}

	if sect.Name == ".got" {
		msect.name = "__nl_symbol_ptr"
		msect.flag = S_NON_LAZY_SYMBOL_POINTERS
		msect.res1 = uint32(ctxt.loader.SymSize(ctxt.ArchSyms.LinkEditPLT) / 4) /* offset into indirect symbol table */
	}

	if sect.Name == ".init_array" {
		msect.name = "__mod_init_func"
		msect.flag = S_MOD_INIT_FUNC_POINTERS
	}

	// Some platforms such as watchOS and tvOS require binaries with
	// bitcode enabled. The Go toolchain can't output bitcode, so use
	// a marker section in the __LLVM segment, "__asm", to tell the Apple
	// toolchain that the Go text came from assembler and thus has no
	// bitcode. This is not true, but Kotlin/Native, Rust and Flutter
	// are also using this trick.
	if sect.Name == ".llvmasm" {
		msect.name = "__asm"
		msect.segname = "__LLVM"
	}

	if segname == "__DWARF" {
		msect.flag |= S_ATTR_DEBUG
	}
}

func asmbMacho(ctxt *Link) {
	machlink := doMachoLink(ctxt)
	if ctxt.IsExternal() {
		symo := int64(Segdwarf.Fileoff + uint64(Rnd(int64(Segdwarf.Filelen), *FlagRound)) + uint64(machlink))
		ctxt.Out.SeekSet(symo)
		machoEmitReloc(ctxt)
	}
	ctxt.Out.SeekSet(0)

	ldr := ctxt.loader

	/* apple MACH */
	va := *FlagTextAddr - int64(HEADR)

	mh := getMachoHdr()
	switch ctxt.Arch.Family {
	default:
		Exitf("unknown macho architecture: %v", ctxt.Arch.Family)

	case sys.AMD64:
		mh.cpu = MACHO_CPU_AMD64
		mh.subcpu = MACHO_SUBCPU_X86

	case sys.ARM64:
		mh.cpu = MACHO_CPU_ARM64
		mh.subcpu = MACHO_SUBCPU_ARM64_ALL
	}

	var ms *MachoSeg
	if ctxt.LinkMode == LinkExternal {
		/* segment for entire file */
		ms = newMachoSeg("", 40)

		ms.fileoffset = Segtext.Fileoff
		ms.filesize = Segdwarf.Fileoff + Segdwarf.Filelen - Segtext.Fileoff
		ms.vsize = Segdwarf.Vaddr + Segdwarf.Length - Segtext.Vaddr
	}

	/* segment for zero page */
	if ctxt.LinkMode != LinkExternal {
		ms = newMachoSeg("__PAGEZERO", 0)
		ms.vsize = uint64(va)
	}

	/* text */
	v := Rnd(int64(uint64(HEADR)+Segtext.Length), *FlagRound)

	var mstext *MachoSeg
	if ctxt.LinkMode != LinkExternal {
		ms = newMachoSeg("__TEXT", 20)
		ms.vaddr = uint64(va)
		ms.vsize = uint64(v)
		ms.fileoffset = 0
		ms.filesize = uint64(v)
		ms.prot1 = 7
		ms.prot2 = 5
		mstext = ms
	}

	for _, sect := range Segtext.Sections {
		machoshbits(ctxt, ms, sect, "__TEXT")
	}

	/* rodata */
	if ctxt.LinkMode != LinkExternal && Segrelrodata.Length > 0 {
		ms = newMachoSeg("__DATA_CONST", 20)
		ms.vaddr = Segrelrodata.Vaddr
		ms.vsize = Segrelrodata.Length
		ms.fileoffset = Segrelrodata.Fileoff
		ms.filesize = Segrelrodata.Filelen
		ms.prot1 = 3
		ms.prot2 = 3
		ms.flag = 0x10 // SG_READ_ONLY
	}

	for _, sect := range Segrelrodata.Sections {
		machoshbits(ctxt, ms, sect, "__DATA_CONST")
	}

	/* data */
	if ctxt.LinkMode != LinkExternal {
		ms = newMachoSeg("__DATA", 20)
		ms.vaddr = Segdata.Vaddr
		ms.vsize = Segdata.Length
		ms.fileoffset = Segdata.Fileoff
		ms.filesize = Segdata.Filelen
		ms.prot1 = 3
		ms.prot2 = 3
	}

	for _, sect := range Segdata.Sections {
		machoshbits(ctxt, ms, sect, "__DATA")
	}

	/* dwarf */
	if !*FlagW {
		if ctxt.LinkMode != LinkExternal {
			ms = newMachoSeg("__DWARF", 20)
			ms.vaddr = Segdwarf.Vaddr
			ms.vsize = 0
			ms.fileoffset = Segdwarf.Fileoff
			ms.filesize = Segdwarf.Filelen
		}
		for _, sect := range Segdwarf.Sections {
			machoshbits(ctxt, ms, sect, "__DWARF")
		}
	}

	if ctxt.LinkMode != LinkExternal {
		switch ctxt.Arch.Family {
		default:
			Exitf("unknown macho architecture: %v", ctxt.Arch.Family)

		case sys.AMD64:
			ml := newMachoLoad(ctxt.Arch, imacho.LC_UNIXTHREAD, 42+2)
			ml.data[0] = 4                           /* thread type */
			ml.data[1] = 42                          /* word count */
			ml.data[2+32] = uint32(Entryvalue(ctxt)) /* start pc */
			ml.data[2+32+1] = uint32(Entryvalue(ctxt) >> 32)

		case sys.ARM64:
			ml := newMachoLoad(ctxt.Arch, imacho.LC_MAIN, 4)
			ml.data[0] = uint32(uint64(Entryvalue(ctxt)) - (Segtext.Vaddr - uint64(HEADR)))
			ml.data[1] = uint32((uint64(Entryvalue(ctxt)) - (Segtext.Vaddr - uint64(HEADR))) >> 32)
		}
	}

	var codesigOff int64
	if !*FlagD {
		// must match doMachoLink below
		s1 := ldr.SymSize(ldr.Lookup(".machorebase", 0))
		s2 := ldr.SymSize(ldr.Lookup(".machobind", 0))
		s3 := ldr.SymSize(ldr.Lookup(".machosymtab", 0))
		s4 := ldr.SymSize(ctxt.ArchSyms.LinkEditPLT)
		s5 := ldr.SymSize(ctxt.ArchSyms.LinkEditGOT)
		s6 := ldr.SymSize(ldr.Lookup(".machosymstr", 0))
		s7 := ldr.SymSize(ldr.Lookup(".machocodesig", 0))

		if ctxt.LinkMode != LinkExternal {
			ms := newMachoSeg("__LINKEDIT", 0)
			ms.vaddr = uint64(Rnd(int64(Segdata.Vaddr+Segdata.Length), *FlagRound))
			ms.vsize = uint64(s1 + s2 + s3 + s4 + s5 + s6 + s7)
			ms.fileoffset = uint64(linkoff)
			ms.filesize = ms.vsize
			ms.prot1 = 1
			ms.prot2 = 1

			codesigOff = linkoff + s1 + s2 + s3 + s4 + s5 + s6
		}

		if ctxt.LinkMode != LinkExternal && ctxt.IsPIE() {
			ml := newMachoLoad(ctxt.Arch, imacho.LC_DYLD_INFO_ONLY, 10)
			ml.data[0] = uint32(linkoff)      // rebase off
			ml.data[1] = uint32(s1)           // rebase size
			ml.data[2] = uint32(linkoff + s1) // bind off
			ml.data[3] = uint32(s2)           // bind size
			ml.data[4] = 0                    // weak bind off
			ml.data[5] = 0                    // weak bind size
			ml.data[6] = 0                    // lazy bind off
			ml.data[7] = 0                    // lazy bind size
			ml.data[8] = 0                    // export
			ml.data[9] = 0                    // export size
		}

		ml := newMachoLoad(ctxt.Arch, imacho.LC_SYMTAB, 4)
		ml.data[0] = uint32(linkoff + s1 + s2)                /* symoff */
		ml.data[1] = uint32(nsortsym)                         /* nsyms */
		ml.data[2] = uint32(linkoff + s1 + s2 + s3 + s4 + s5) /* stroff */
		ml.data[3] = uint32(s6)                               /* strsize */

		if ctxt.LinkMode != LinkExternal {
			machodysymtab(ctxt, linkoff+s1+s2)

			ml := newMachoLoad(ctxt.Arch, imacho.LC_LOAD_DYLINKER, 6)
			ml.data[0] = 12 /* offset to string */
			stringtouint32(ml.data[1:], "/usr/lib/dyld")

			for _, lib := range dylib {
				ml = newMachoLoad(ctxt.Arch, imacho.LC_LOAD_DYLIB, 4+(uint32(len(lib))+1+7)/8*2)
				ml.data[0] = 24 /* offset of string from beginning of load */
				ml.data[1] = 0  /* time stamp */
				ml.data[2] = 0  /* version */
				ml.data[3] = 0  /* compatibility version */
				stringtouint32(ml.data[4:], lib)
			}
		}

		if ctxt.IsInternal() && len(buildinfo) > 0 {
			ml := newMachoLoad(ctxt.Arch, imacho.LC_UUID, 4)
			// Mach-O UUID is 16 bytes
			if len(buildinfo) < 16 {
				buildinfo = append(buildinfo, make([]byte, 16)...)
			}
			// By default, buildinfo is already in UUIDv3 format
			// (see uuidFromGoBuildId).
			ml.data[0] = ctxt.Arch.ByteOrder.Uint32(buildinfo)
			ml.data[1] = ctxt.Arch.ByteOrder.Uint32(buildinfo[4:])
			ml.data[2] = ctxt.Arch.ByteOrder.Uint32(buildinfo[8:])
			ml.data[3] = ctxt.Arch.ByteOrder.Uint32(buildinfo[12:])
		}

		if ctxt.IsInternal() && ctxt.NeedCodeSign() {
			ml := newMachoLoad(ctxt.Arch, imacho.LC_CODE_SIGNATURE, 2)
			ml.data[0] = uint32(codesigOff)
			ml.data[1] = uint32(s7)
		}
	}

	a := machowrite(ctxt, ctxt.Arch, ctxt.Out, ctxt.LinkMode)
	if int32(a) > HEADR {
		Exitf("HEADR too small: %d > %d", a, HEADR)
	}

	// Now we have written everything. Compute the code signature (which
	// is a hash of the file content, so it must be done at last.)
	if ctxt.IsInternal() && ctxt.NeedCodeSign() {
		cs := ldr.Lookup(".machocodesig", 0)
		data := ctxt.Out.Data()
		if int64(len(data)) != codesigOff {
			panic("wrong size")
		}
		codesign.Sign(ldr.Data(cs), bytes.NewReader(data), "a.out", codesigOff, int64(mstext.fileoffset), int64(mstext.filesize), ctxt.IsExe() || ctxt.IsPIE())
		ctxt.Out.SeekSet(codesigOff)
		ctxt.Out.Write(ldr.Data(cs))
	}
}

func symkind(ldr *loader.Loader, s loader.Sym) int {
	if t := ldr.SymType(s); t == sym.SDYNIMPORT || t == sym.SHOSTOBJ || t == sym.SUNDEFEXT {
		return SymKindUndef
	}
	if ldr.AttrCgoExport(s) {
		return SymKindExtdef
	}
	return SymKindLocal
}

func collectmachosyms(ctxt *Link) {
	ldr := ctxt.loader

	addsym := func(s loader.Sym) {
		sortsym = append(sortsym, s)
		nkind[symkind(ldr, s)]++
	}

	// On Mach-O, even with -s, we still need to keep dynamically exported and
	// referenced symbols. We can strip defined local text and data symbols.
	// So *FlagS is applied based on symbol type.

	// Add special runtime.text and runtime.etext symbols (which are local).
	// We've already included this symbol in Textp on darwin if ctxt.DynlinkingGo().
	// See data.go:/textaddress
	// NOTE: runtime.text.N symbols (if we split text sections) are not added, though,
	// so we handle them here.
	if !*FlagS {
		if !ctxt.DynlinkingGo() {
			s := ldr.Lookup("runtime.text", 0)
			if ldr.SymType(s).IsText() {
				addsym(s)
			}
		}
		for n := range Segtext.Sections[1:] {
			s := ldr.Lookup(fmt.Sprintf("runtime.text.%d", n+1), 0)
			if s != 0 {
				addsym(s)
			} else {
				break
			}
		}
		if !ctxt.DynlinkingGo() {
			s := ldr.Lookup("runtime.etext", 0)
			if ldr.SymType(s).IsText() {
				addsym(s)
			}
		}
	}

	// Add text symbols.
	for _, s := range ctxt.Textp {
		if *FlagS && !ldr.AttrCgoExportDynamic(s) {
			continue
		}
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
				// TLSBSS is not used on darwin. See data.go:allocateDataSections
				continue
			}
			if !shouldBeInSymbolTable(s) {
				continue
			}
			if *FlagS && !ldr.AttrCgoExportDynamic(s) {
				continue
			}
			addsym(s)
			continue
		}

		switch t {
		case sym.SDYNIMPORT, sym.SHOSTOBJ, sym.SUNDEFEXT:
			// Keep dynamic symbol references even if *FlagS.
			addsym(s)
		}

		// Some 64-bit functions have a "$INODE64" or "$INODE64$UNIX2003" suffix.
		if t == sym.SDYNIMPORT && ldr.SymDynimplib(s) == "/usr/lib/libSystem.B.dylib" {
			// But only on macOS.
			if machoPlatform == PLATFORM_MACOS || machoPlatform == PLATFORM_MACCATALYST {
				switch n := ldr.SymExtname(s); n {
				case "fdopendir":
					switch buildcfg.GOARCH {
					case "amd64":
						ldr.SetSymExtname(s, n+"$INODE64")
					}
				case "readdir_r", "getfsstat":
					switch buildcfg.GOARCH {
					case "amd64":
						ldr.SetSymExtname(s, n+"$INODE64")
					}
				}
			}
		}
	}

	nsortsym = len(sortsym)
}

func machosymorder(ctxt *Link) {
	ldr := ctxt.loader

	// On Mac OS X Mountain Lion, we must sort exported symbols
	// So we sort them here and pre-allocate dynid for them
	// See https://golang.org/issue/4029
	for _, s := range ctxt.dynexp {
		if !ldr.AttrReachable(s) {
			panic("dynexp symbol is not reachable")
		}
	}
	collectmachosyms(ctxt)
	sort.Slice(sortsym[:nsortsym], func(i, j int) bool {
		s1 := sortsym[i]
		s2 := sortsym[j]
		k1 := symkind(ldr, s1)
		k2 := symkind(ldr, s2)
		if k1 != k2 {
			return k1 < k2
		}
		return ldr.SymExtname(s1) < ldr.SymExtname(s2) // Note: unnamed symbols are not added in collectmachosyms
	})
	for i, s := range sortsym {
		ldr.SetSymDynid(s, int32(i))
	}
}

// AddMachoSym adds s to Mach-O symbol table, used in GenSymLate.
// Currently only used on ARM64 when external linking.
func AddMachoSym(ldr *loader.Loader, s loader.Sym) {
	ldr.SetSymDynid(s, int32(nsortsym))
	sortsym = append(sortsym, s)
	nsortsym++
	nkind[symkind(ldr, s)]++
}

// machoShouldExport reports whether a symbol needs to be exported.
//
// When dynamically linking, all non-local variables and plugin-exported
// symbols need to be exported.
func machoShouldExport(ctxt *Link, ldr *loader.Loader, s loader.Sym) bool {
	if !ctxt.DynlinkingGo() || ldr.AttrLocal(s) {
		return false
	}
	if ctxt.BuildMode == BuildModePlugin && strings.HasPrefix(ldr.SymExtname(s), objabi.PathToPrefix(*flagPluginPath)) {
		return true
	}
	name := ldr.SymName(s)
	if strings.HasPrefix(name, "go:itab.") {
		return true
	}
	if strings.HasPrefix(name, "type:") && !strings.HasPrefix(name, "type:.") {
		// reduce runtime typemap pressure, but do not
		// export alg functions (type:.*), as these
		// appear in pclntable.
		return true
	}
	if strings.HasPrefix(name, "go:link.pkghash") {
		return true
	}
	return ldr.SymType(s) >= sym.SFirstWritable // only writable sections
}

func machosymtab(ctxt *Link) {
	ldr := ctxt.loader
	symtab := ldr.CreateSymForUpdate(".machosymtab", 0)
	symstr := ldr.CreateSymForUpdate(".machosymstr", 0)

	for _, s := range sortsym[:nsortsym] {
		symtab.AddUint32(ctxt.Arch, uint32(symstr.Size()))

		export := machoShouldExport(ctxt, ldr, s)

		// Prefix symbol names with "_" to match the system toolchain.
		// (We used to only prefix C symbols, which is all required for the build.
		// But some tools don't recognize Go symbols as symbols, so we prefix them
		// as well.)
		symstr.AddUint8('_')

		// replace "·" as ".", because DTrace cannot handle it.
		name := strings.Replace(ldr.SymExtname(s), "·", ".", -1)

		name = mangleABIName(ctxt, ldr, s, name)
		symstr.Addstring(name)

		if t := ldr.SymType(s); t == sym.SDYNIMPORT || t == sym.SHOSTOBJ || t == sym.SUNDEFEXT {
			symtab.AddUint8(0x01)                             // type N_EXT, external symbol
			symtab.AddUint8(0)                                // no section
			symtab.AddUint16(ctxt.Arch, 0)                    // desc
			symtab.AddUintXX(ctxt.Arch, 0, ctxt.Arch.PtrSize) // no value
		} else {
			if export || ldr.AttrCgoExportDynamic(s) {
				symtab.AddUint8(0x0f) // N_SECT | N_EXT
			} else if ldr.AttrCgoExportStatic(s) {
				// Only export statically, not dynamically. (N_PEXT is like hidden visibility)
				symtab.AddUint8(0x1f) // N_SECT | N_EXT | N_PEXT
			} else {
				symtab.AddUint8(0x0e) // N_SECT
			}
			o := s
			if outer := ldr.OuterSym(o); outer != 0 {
				o = outer
			}
			if ldr.SymSect(o) == nil {
				ldr.Errorf(s, "missing section for symbol")
				symtab.AddUint8(0)
			} else {
				symtab.AddUint8(uint8(ldr.SymSect(o).Extnum))
			}
			symtab.AddUint16(ctxt.Arch, 0) // desc
			symtab.AddUintXX(ctxt.Arch, uint64(ldr.SymAddr(s)), ctxt.Arch.PtrSize)
		}
	}
}

func machodysymtab(ctxt *Link, base int64) {
	ml := newMachoLoad(ctxt.Arch, imacho.LC_DYSYMTAB, 18)

	n := 0
	ml.data[0] = uint32(n)                   /* ilocalsym */
	ml.data[1] = uint32(nkind[SymKindLocal]) /* nlocalsym */
	n += nkind[SymKindLocal]

	ml.data[2] = uint32(n)                    /* iextdefsym */
	ml.data[3] = uint32(nkind[SymKindExtdef]) /* nextdefsym */
	n += nkind[SymKindExtdef]

	ml.data[4] = uint32(n)                   /* iundefsym */
	ml.data[5] = uint32(nkind[SymKindUndef]) /* nundefsym */

	ml.data[6] = 0  /* tocoffset */
	ml.data[7] = 0  /* ntoc */
	ml.data[8] = 0  /* modtaboff */
	ml.data[9] = 0  /* nmodtab */
	ml.data[10] = 0 /* extrefsymoff */
	ml.data[11] = 0 /* nextrefsyms */

	ldr := ctxt.loader

	// must match domacholink below
	s1 := ldr.SymSize(ldr.Lookup(".machosymtab", 0))
	s2 := ldr.SymSize(ctxt.ArchSyms.LinkEditPLT)
	s3 := ldr.SymSize(ctxt.ArchSyms.LinkEditGOT)
	ml.data[12] = uint32(base + s1)     /* indirectsymoff */
	ml.data[13] = uint32((s2 + s3) / 4) /* nindirectsyms */

	ml.data[14] = 0 /* extreloff */
	ml.data[15] = 0 /* nextrel */
	ml.data[16] = 0 /* locreloff */
	ml.data[17] = 0 /* nlocrel */
}

func doMachoLink(ctxt *Link) int64 {
	machosymtab(ctxt)
	machoDyldInfo(ctxt)

	ldr := ctxt.loader

	// write data that will be linkedit section
	s1 := ldr.Lookup(".machorebase", 0)
	s2 := ldr.Lookup(".machobind", 0)
	s3 := ldr.Lookup(".machosymtab", 0)
	s4 := ctxt.ArchSyms.LinkEditPLT
	s5 := ctxt.ArchSyms.LinkEditGOT
	s6 := ldr.Lookup(".machosymstr", 0)

	size := ldr.SymSize(s1) + ldr.SymSize(s2) + ldr.SymSize(s3) + ldr.SymSize(s4) + ldr.SymSize(s5) + ldr.SymSize(s6)

	// Force the linkedit section to end on a 16-byte
	// boundary. This allows pure (non-cgo) Go binaries
	// to be code signed correctly.
	//
	// Apple's codesign_allocate (a helper utility for
	// the codesign utility) can do this fine itself if
	// it is run on a dynamic Mach-O binary. However,
	// when it is run on a pure (non-cgo) Go binary, where
	// the linkedit section is mostly empty, it fails to
	// account for the extra padding that it itself adds
	// when adding the LC_CODE_SIGNATURE load command
	// (which must be aligned on a 16-byte boundary).
	//
	// By forcing the linkedit section to end on a 16-byte
	// boundary, codesign_allocate will not need to apply
	// any alignment padding itself, working around the
	// issue.
	if size%16 != 0 {
		n := 16 - size%16
		s6b := ldr.MakeSymbolUpdater(s6)
		s6b.Grow(s6b.Size() + n)
		s6b.SetSize(s6b.Size() + n)
		size += n
	}

	if size > 0 {
		linkoff = Rnd(int64(uint64(HEADR)+Segtext.Length), *FlagRound) + Rnd(int64(Segrelrodata.Filelen), *FlagRound) + Rnd(int64(Segdata.Filelen), *FlagRound) + Rnd(int64(Segdwarf.Filelen), *FlagRound)
		ctxt.Out.SeekSet(linkoff)

		ctxt.Out.Write(ldr.Data(s1))
		ctxt.Out.Write(ldr.Data(s2))
		ctxt.Out.Write(ldr.Data(s3))
		ctxt.Out.Write(ldr.Data(s4))
		ctxt.Out.Write(ldr.Data(s5))
		ctxt.Out.Write(ldr.Data(s6))

		// Add code signature if necessary. This must be the last.
		s7 := machoCodeSigSym(ctxt, linkoff+size)
		size += ldr.SymSize(s7)
	}

	return Rnd(size, *FlagRound)
}

func machorelocsect(ctxt *Link, out *OutBuf, sect *sym.Section, syms []loader.Sym) {
	// If main section has no bits, nothing to relocate.
	if sect.Vaddr >= sect.Seg.Vaddr+sect.Seg.Filelen {
		return
	}
	ldr := ctxt.loader

	for i, s := range syms {
		if !ldr.AttrReachable(s) {
			continue
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

		// Compute external relocations on the go, and pass to Machoreloc1
		// to stream out.
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
			if !ldr.AttrReachable(rr.Xsym) {
				ldr.Errorf(s, "unreachable reloc %d (%s) target %v", r.Type(), sym.RelocName(ctxt.Arch, r.Type()), ldr.SymName(rr.Xsym))
			}
			if !thearch.Machoreloc1(ctxt.Arch, out, ldr, s, rr, int64(uint64(ldr.SymValue(s)+int64(r.Off()))-sect.Vaddr)) {
				ldr.Errorf(s, "unsupported obj reloc %d (%s)/%d to %s", r.Type(), sym.RelocName(ctxt.Arch, r.Type()), r.Siz(), ldr.SymName(r.Sym()))
			}
		}
	}

	// sanity check
	if uint64(out.Offset()) != sect.Reloff+sect.Rellen {
		panic("machorelocsect: size mismatch")
	}
}

func machoEmitReloc(ctxt *Link) {
	for ctxt.Out.Offset()&7 != 0 {
		ctxt.Out.Write8(0)
	}

	sizeExtRelocs(ctxt, thearch.MachorelocSize)
	relocSect, wg := relocSectFn(ctxt, machorelocsect)

	relocSect(ctxt, Segtext.Sections[0], ctxt.Textp)
	for _, sect := range Segtext.Sections[1:] {
		if sect.Name == ".text" {
			relocSect(ctxt, sect, ctxt.Textp)
		} else {
			relocSect(ctxt, sect, ctxt.datap)
		}
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

// hostobjMachoPlatform returns the first platform load command found
// in the host object, if any.
func hostobjMachoPlatform(h *Hostobj) (*MachoPlatformLoad, error) {
	f, err := os.Open(h.file)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to open host object: %v\n", h.file, err)
	}
	defer f.Close()
	sr := io.NewSectionReader(f, h.off, h.length)
	m, err := macho.NewFile(sr)
	if err != nil {
		// Not a valid Mach-O file.
		return nil, nil
	}
	return peekMachoPlatform(m)
}

// peekMachoPlatform returns the first LC_VERSION_MIN_* or LC_BUILD_VERSION
// load command found in the Mach-O file, if any.
func peekMachoPlatform(m *macho.File) (*MachoPlatformLoad, error) {
	for _, cmd := range m.Loads {
		raw := cmd.Raw()
		ml := MachoLoad{
			type_: m.ByteOrder.Uint32(raw),
		}
		// Skip the type and command length.
		data := raw[8:]
		var p MachoPlatform
		switch ml.type_ {
		case imacho.LC_VERSION_MIN_IPHONEOS:
			p = PLATFORM_IOS
		case imacho.LC_VERSION_MIN_MACOSX:
			p = PLATFORM_MACOS
		case imacho.LC_VERSION_MIN_WATCHOS:
			p = PLATFORM_WATCHOS
		case imacho.LC_VERSION_MIN_TVOS:
			p = PLATFORM_TVOS
		case imacho.LC_BUILD_VERSION:
			p = MachoPlatform(m.ByteOrder.Uint32(data))
		default:
			continue
		}
		ml.data = make([]uint32, len(data)/4)
		r := bytes.NewReader(data)
		if err := binary.Read(r, m.ByteOrder, &ml.data); err != nil {
			return nil, err
		}
		return &MachoPlatformLoad{
			platform: p,
			cmd:      ml,
		}, nil
	}
	return nil, nil
}

// A rebase entry tells the dynamic linker the data at sym+off needs to be
// relocated when the in-memory image moves. (This is somewhat like, say,
// ELF R_X86_64_RELATIVE).
// For now, the only kind of entry we support is that the data is an absolute
// address. That seems all we need.
// In the binary it uses a compact stateful bytecode encoding. So we record
// entries as we go and build the table at the end.
type machoRebaseRecord struct {
	sym loader.Sym
	off int64
}

var machorebase []machoRebaseRecord

func MachoAddRebase(s loader.Sym, off int64) {
	machorebase = append(machorebase, machoRebaseRecord{s, off})
}

// A bind entry tells the dynamic linker the data at GOT+off should be bound
// to the address of the target symbol, which is a dynamic import.
// For now, the only kind of entry we support is that the data is an absolute
// address, and the source symbol is always the GOT. That seems all we need.
// In the binary it uses a compact stateful bytecode encoding. So we record
// entries as we go and build the table at the end.
type machoBindRecord struct {
	off  int64
	targ loader.Sym
}

var machobind []machoBindRecord

func MachoAddBind(off int64, targ loader.Sym) {
	machobind = append(machobind, machoBindRecord{off, targ})
}

// Generate data for the dynamic linker, used in LC_DYLD_INFO_ONLY load command.
// See mach-o/loader.h, struct dyld_info_command, for the encoding.
// e.g. https://opensource.apple.com/source/xnu/xnu-6153.81.5/EXTERNAL_HEADERS/mach-o/loader.h
func machoDyldInfo(ctxt *Link) {
	ldr := ctxt.loader
	rebase := ldr.CreateSymForUpdate(".machorebase", 0)
	bind := ldr.CreateSymForUpdate(".machobind", 0)

	if !(ctxt.IsPIE() && ctxt.IsInternal()) {
		return
	}

	segId := func(seg *sym.Segment) uint8 {
		switch seg {
		case &Segtext:
			return 1
		case &Segrelrodata:
			return 2
		case &Segdata:
			if Segrelrodata.Length > 0 {
				return 3
			}
			return 2
		}
		panic("unknown segment")
	}

	dylibId := func(s loader.Sym) int {
		slib := ldr.SymDynimplib(s)
		for i, lib := range dylib {
			if lib == slib {
				return i + 1
			}
		}
		return BIND_SPECIAL_DYLIB_FLAT_LOOKUP // don't know where it is from
	}

	// Rebase table.
	// TODO: use more compact encoding. The encoding is stateful, and
	// we can use delta encoding.
	rebase.AddUint8(REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER)
	for _, r := range machorebase {
		seg := ldr.SymSect(r.sym).Seg
		off := uint64(ldr.SymValue(r.sym)+r.off) - seg.Vaddr
		rebase.AddUint8(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | segId(seg))
		rebase.AddUleb(off)

		rebase.AddUint8(REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1)
	}
	rebase.AddUint8(REBASE_OPCODE_DONE)
	sz := Rnd(rebase.Size(), 8)
	rebase.Grow(sz)
	rebase.SetSize(sz)

	// Bind table.
	// TODO: compact encoding, as above.
	// TODO: lazy binding?
	got := ctxt.GOT
	seg := ldr.SymSect(got).Seg
	gotAddr := ldr.SymValue(got)
	bind.AddUint8(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER)
	for _, r := range machobind {
		off := uint64(gotAddr+r.off) - seg.Vaddr
		bind.AddUint8(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | segId(seg))
		bind.AddUleb(off)

		d := dylibId(r.targ)
		if d > 0 && d < 128 {
			bind.AddUint8(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | uint8(d)&0xf)
		} else if d >= 128 {
			bind.AddUint8(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB)
			bind.AddUleb(uint64(d))
		} else { // d <= 0
			bind.AddUint8(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | uint8(d)&0xf)
		}

		bind.AddUint8(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM)
		// target symbol name as a C string, with _ prefix
		bind.AddUint8('_')
		bind.Addstring(ldr.SymExtname(r.targ))

		bind.AddUint8(BIND_OPCODE_DO_BIND)
	}
	bind.AddUint8(BIND_OPCODE_DONE)
	sz = Rnd(bind.Size(), 16) // make it 16-byte aligned, see the comment in doMachoLink
	bind.Grow(sz)
	bind.SetSize(sz)

	// TODO: export table.
	// The symbols names are encoded as a trie. I'm really too lazy to do that
	// for now.
	// Without it, the symbols are not dynamically exported, so they cannot be
	// e.g. dlsym'd. But internal linking is not the default in that case, so
	// it is fine.
}

// machoCodeSigSym creates and returns a symbol for code signature.
// The symbol context is left as zeros, which will be generated at the end
// (as it depends on the rest of the file).
func machoCodeSigSym(ctxt *Link, codeSize int64) loader.Sym {
	ldr := ctxt.loader
	cs := ldr.CreateSymForUpdate(".machocodesig", 0)
	if !ctxt.NeedCodeSign() || ctxt.IsExternal() {
		return cs.Sym()
	}
	sz := codesign.Size(codeSize, "a.out")
	cs.Grow(sz)
	cs.SetSize(sz)
	return cs.Sym()
}

// machoCodeSign code-signs Mach-O file fname with an ad-hoc signature.
// This is used for updating an external linker generated binary.
func machoCodeSign(ctxt *Link, fname string) error {
	f, err := os.OpenFile(fname, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	mf, err := macho.NewFile(f)
	if err != nil {
		return err
	}
	if mf.Magic != macho.Magic64 {
		Exitf("not 64-bit Mach-O file: %s", fname)
	}

	// Find existing LC_CODE_SIGNATURE and __LINKEDIT segment
	var sigOff, sigSz, csCmdOff, linkeditOff int64
	var linkeditSeg, textSeg *macho.Segment
	loadOff := int64(machoHeaderSize64)
	get32 := mf.ByteOrder.Uint32
	for _, l := range mf.Loads {
		data := l.Raw()
		cmd, sz := get32(data), get32(data[4:])
		if cmd == imacho.LC_CODE_SIGNATURE {
			sigOff = int64(get32(data[8:]))
			sigSz = int64(get32(data[12:]))
			csCmdOff = loadOff
		}
		if seg, ok := l.(*macho.Segment); ok {
			switch seg.Name {
			case "__LINKEDIT":
				linkeditSeg = seg
				linkeditOff = loadOff
			case "__TEXT":
				textSeg = seg
			}
		}
		loadOff += int64(sz)
	}

	if sigOff == 0 {
		// The C linker doesn't generate a signed binary, for some reason.
		// Skip.
		return nil
	}

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if sigOff+sigSz != fi.Size() {
		// We don't expect anything after the signature (this will invalidate
		// the signature anyway.)
		return fmt.Errorf("unexpected content after code signature")
	}

	sz := codesign.Size(sigOff, "a.out")
	if sz != sigSz {
		// Update the load command,
		var tmp [8]byte
		mf.ByteOrder.PutUint32(tmp[:4], uint32(sz))
		_, err = f.WriteAt(tmp[:4], csCmdOff+12)
		if err != nil {
			return err
		}

		// Uodate the __LINKEDIT segment.
		segSz := sigOff + sz - int64(linkeditSeg.Offset)
		mf.ByteOrder.PutUint64(tmp[:8], uint64(segSz))
		_, err = f.WriteAt(tmp[:8], int64(linkeditOff)+int64(unsafe.Offsetof(macho.Segment64{}.Memsz)))
		if err != nil {
			return err
		}
		_, err = f.WriteAt(tmp[:8], int64(linkeditOff)+int64(unsafe.Offsetof(macho.Segment64{}.Filesz)))
		if err != nil {
			return err
		}
	}

	cs := make([]byte, sz)
	codesign.Sign(cs, f, "a.out", sigOff, int64(textSeg.Offset), int64(textSeg.Filesz), ctxt.IsExe() || ctxt.IsPIE())
	_, err = f.WriteAt(cs, sigOff)
	if err != nil {
		return err
	}
	err = f.Truncate(sigOff + sz)
	return err
}
```