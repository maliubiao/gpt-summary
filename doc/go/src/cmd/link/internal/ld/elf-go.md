Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The file path `go/src/cmd/link/internal/ld/elf.go` immediately suggests that this code is related to the ELF (Executable and Linkable Format) file format within the Go linker. The package name `ld` further reinforces this.

2. **Initial Scan for Key Data Structures:**  A quick skim reveals several `struct` definitions: `elfNote`, `ElfEhdr`, `ElfShdr`, `ElfPhdr`, `ELFArch`, `Elfstring`, and `Elfaux`/`Elflib`. These are likely representations of ELF data structures or helper structures used during ELF processing.

3. **Analyze Key Data Structures:**
    * `elfNote`:  This directly corresponds to the ELF note structure used for embedding metadata.
    * `ElfEhdr`, `ElfShdr`, `ElfPhdr`: These are clearly the ELF header, section header, and program header structures, respectively. The comments and the embedded `elf` package types (`elf.Header64`, `elf.Section64`, `elf.ProgHeader`) confirm this. The aliases `ElfEhdr elf.Header64` are interesting; it suggests a common structure with potential for 32/64-bit variations handled elsewhere.
    * `ELFArch`: This appears to be an interface or structure holding architecture-specific functions and data related to ELF linking. The names of the fields (`Androiddynld`, `Linuxdynld`, `Reloc1`, `SetupPLT`) hint at target-specific dynamic linker paths and relocation handling.
    * `Elfstring`:  Likely used for managing strings in the ELF string tables.
    * `Elfaux`/`Elflib`: These seem related to handling shared library dependencies and versioning (the `vers` field in `Elfaux` is a strong clue).

4. **Identify Key Functions:**  Look for functions that seem to perform significant actions. Some prominent examples are: `Elfinit`, `elf64phdr`/`elf32phdr`, `elf64shdr`/`elf32shdr`, `elfwriteshdrs`, `elfwritephdrs`, `newElfPhdr`, `newElfShdr`, `elfwritehdr`, `elfhash`, `Elfwritedynent*`, `elfinterp`, `elfnote`, `elfwritenotehdr`, `elfMipsAbiFlags`/`elfWriteMipsAbiFlags`, `addbuildinfo`, `elfbuildinfo`/`elfwritebuildinfo`, `elfdynhash`, `elfphload`, `elfshname`, `elfshbits`, `elfshreloc`, `elfrelocsect`, `elfEmitReloc`, `addgonote`, `doelf`, `Asmbelfsetup`, `asmbElf`, `elfadddynsym`.

5. **Categorize Function Functionality:** Group the functions based on their purpose:
    * **Initialization:** `Elfinit`
    * **Writing ELF Headers/Sections/Segments:**  Functions like `elfwritehdr`, `elfwritephdrs`, `elfwriteshdrs`, `elf64phdr`/`elf32phdr`, `elf64shdr`/`elf32shdr`.
    * **Creating ELF Structures:** `newElfPhdr`, `newElfShdr`.
    * **String Table Management:** `elfsetstring`.
    * **Note Handling:** `elfnote`, `elfwritenotehdr`, and the specific note functions for NetBSD, OpenBSD, FreeBSD.
    * **Dynamic Linking Support:**  `elfdynhash`, `Elfwritedynent*`, `elfinterp`.
    * **Relocation Handling:** `elfshreloc`, `elfrelocsect`, `elfEmitReloc`.
    * **Architecture-Specific Logic:**  The `ELFArch` structure and functions like `elfMipsAbiFlags`/`elfWriteMipsAbiFlags`.
    * **Build Information:** `addbuildinfo`, `elfbuildinfo`/`elfwritebuildinfo`.
    * **Section Lookup:** `elfshname`.
    * **Main ELF Processing:** `doelf`, `asmbElf`.
    * **Symbol Handling:** `elfadddynsym`.

6. **Infer Go Feature Implementation (Where Possible):**
    * **`-buildid` Flag:** The functions `addbuildinfo`, `elfbuildinfo`, and `elfwritebuildinfo`, along with the note structures, clearly implement the embedding of build IDs into the ELF.
    * **`-race` Flag:** The conditional logic around NetBSD and FreeBSD note sections suggests handling for disabling ASLR when the race detector is enabled.
    * **Dynamic Linking and Shared Libraries:**  The presence of `.dynamic`, `.dynsym`, `.dynstr`, `.got`, `.plt`, relocation sections, and the functions related to `DT_*` tags strongly indicate support for dynamic linking and shared libraries. The `Elfaux`/`Elflib` structures confirm versioning support.
    * **Notes (General):** The `elfNote` structure and the functions for writing different types of notes (GNU build ID, OS-specific notes, Go-specific notes) demonstrate the implementation of ELF note sections for embedding metadata.
    * **Section and Segment Management:** The functions for creating and writing section and program headers are fundamental to ELF structure.

7. **Code Example Construction:** Based on the identified features, construct minimal Go code examples that would result in the linker using this `elf.go` code. For example, using the `-buildid` flag to trigger build ID embedding.

8. **Command Line Argument Analysis:**  Look for variables that seem to be influenced by command-line flags (e.g., `*flagBuildid`, `*flagRace`, `*FlagD`). The code that initializes and uses these flags provides information on their impact.

9. **Identify Potential User Errors:** Consider how a user might misuse the linker or its flags in a way related to ELF output. The note about needing to use `CGO_ENABLED=1` for C shared libraries is a good example, as is the interaction between `-buildid` and `-B gobuildid`. The mention of `ELFRESERVE` and `HEADR` being too small also hints at potential internal errors if the linker isn't configured correctly.

10. **Review and Refine:**  Go back through the analysis and ensure consistency and accuracy. Check for any missed details or areas where the explanation could be clearer. For example, explicitly stating the relationship between `ElfEhdr` and `elf.Header64` improves understanding.

This structured approach, starting with the high-level purpose and gradually diving into the details of data structures, functions, and their interactions, allows for a comprehensive understanding of the code's functionality. The key is to connect the code elements back to the overall goal of generating valid ELF files.
`go/src/cmd/link/internal/ld/elf.go` 是 Go 语言链接器 `cmd/link` 的一部分，专门负责处理 **ELF (Executable and Linkable Format)** 文件的生成。 ELF 是一种用于可执行文件、目标代码、共享库和核心转储的标准文件格式，广泛应用于类 Unix 系统。

**主要功能列举：**

1. **定义 ELF 数据结构:**  定义了与 ELF 文件格式相关的各种数据结构，例如：
    * `elfNote`:  表示 ELF Note Section 的头部信息。
    * `ElfEhdr`:  表示 ELF 文件头 (Header)。
    * `ElfShdr`:  表示 ELF Section Header。
    * `ElfPhdr`:  表示 ELF Program Header。
    * `ELFArch`: 定义了针对不同架构的特定 ELF 相关钩子函数和数据。
    * 其他辅助结构，如 `Elfstring`, `Elfaux`, `Elflib`，用于管理 ELF 字符串表和动态链接信息。

2. **初始化 ELF 头信息 (`Elfinit`):**  根据目标架构和操作系统，初始化全局变量 `ehdr` (ElfEhdr)，包括文件类型、机器架构、入口点地址、程序头和节头表的偏移和大小等信息。

3. **生成和写入 ELF Header (`elfwritehdr`, `elf64writehdr`, `elf32writehdr`):**  将 `ehdr` 结构体的内容写入输出文件的开头，构成 ELF 文件头。针对 32 位和 64 位架构有不同的写入函数。

4. **生成和写入 Program Headers (`elfwritephdrs`, `elf64phdr`, `elf32phdr`, `newElfPhdr`):**  创建和写入 Program Header Table，用于描述程序的内存段 (Segment) 信息，例如加载地址、大小、权限等。

5. **生成和写入 Section Headers (`elfwriteshdrs`, `elf64shdr`, `elf32shdr`, `newElfShdr`):** 创建和写入 Section Header Table，用于描述 ELF 文件中的各个节 (Section)，例如代码段、数据段、符号表等。

6. **处理 `.interp` Section (`elfinterp`, `elfwriteinterp`):**  如果需要动态链接，则创建并写入 `.interp` 节，其中包含动态链接器的路径。

7. **处理 Note Sections (`elfnote`, `elfwritenotehdr`, `elfnetbsdsig`, `elfwritefreebsdsig`, `elfbuildinfo`, `elfwritebuildinfo` 等):**  创建和写入各种 Note 节，用于嵌入额外的元数据，例如操作系统标识、构建信息等。针对不同的操作系统有特定的 Note 节处理函数。

8. **处理动态链接相关的 Section (`elfdynhash`, `Elfwritedynent*`):**  如果需要动态链接，则创建和写入与动态链接相关的节，例如 `.hash` (符号哈希表), `.dynsym` (动态符号表), `.dynstr` (动态字符串表), `.got` (全局偏移表), `.plt` (过程链接表), `.dynamic` (动态链接表) 等。

9. **处理重定位 (`elfshreloc`, `elfrelocsect`, `elfEmitReloc`):**  创建和处理重定位节 (Relocation Section)，用于在链接时修正代码和数据中的地址引用。

10. **处理符号表 (`asmElfSym`，尽管代码中未包含):**  虽然代码片段中没有 `asmElfSym` 函数，但通常这个文件中会包含生成和写入符号表 (`.symtab`, `.strtab`) 的逻辑。

11. **处理 MIPS 特定的 ABI 标志 (`elfMipsAbiFlags`, `elfWriteMipsAbiFlags`):** 针对 MIPS 架构，处理 ABI (Application Binary Interface) 相关的标志信息。

12. **添加 Go 特定的 Note (`addgonote`):**  添加 Go 语言链接器特有的 Note 节，例如包含 ABI 哈希值、依赖包列表等信息。

13. **计算和设置 Section 和 Program Header 的地址和偏移 (`shsym`, `phsh`):**  根据布局计算各个节和段在内存和文件中的地址和偏移。

14. **主 ELF 生成流程 (`doelf`):**  组织和协调上述各个步骤，完成 ELF 文件的构建。

15. **汇编 ELF 设置 (`Asmbelfsetup`):** 在汇编阶段进行一些 ELF 相关的设置。

16. **执行 ELF 汇编 (`asmbElf`):**  在汇编阶段执行 ELF 文件的最终生成。

17. **添加动态符号 (`elfadddynsym`):**  将符合条件的符号添加到动态符号表中。

**Go 语言功能的实现推断：**

根据代码内容，可以推断出该文件主要实现了 Go 语言的 **外部链接 (External Linking)** 和 **动态链接 (Dynamic Linking)** 功能。

**外部链接:**  当使用 `-linkmode=external` 标志时，Go 链接器会将 Go 代码与 C/C++ 代码或其他语言的目标文件链接在一起，生成一个可执行文件或共享库。`elf.go` 中的代码负责生成符合 ELF 标准的目标文件或可执行文件。

**动态链接:**  当构建共享库 (`-buildmode=shared`) 或使用了 `import "C"` 导入 C 代码时，Go 链接器需要生成支持动态链接的 ELF 文件。`elf.go` 中的代码负责生成必要的动态链接节，例如 `.dynamic`, `.dynsym`, `.dynstr`, `.got`, `.plt` 等，并填充相应的数据。

**代码示例 (动态链接):**

假设我们有一个简单的 Go 程序 `main.go`，它导入了一个 C 共享库 `libexample.so`：

```go
// main.go
package main

//#cgo LDFLAGS: -lexample
import "C"

func main() {
	C.some_function_from_c()
}
```

以及一个简单的 C 代码 `example.c`:

```c
// example.c
#include <stdio.h>

void some_function_from_c() {
    printf("Hello from C!\n");
}
```

编译并链接生成共享库和可执行文件：

```bash
# 编译 C 代码为共享库
gcc -shared -o libexample.so example.c

# 编译 Go 代码并链接 C 共享库
go build -ldflags="-r /path/to/libexample.so" -buildmode=default main.go
```

**假设输入:**

* 目标架构是 Linux amd64。
* 存在名为 `libexample.so` 的共享库。
* `go build` 命令带有 `-ldflags="-r /path/to/libexample.so"` 和默认的 `-buildmode=default` (此时会生成动态链接的可执行文件)。

**代码推理 (涉及 `elfdynhash`, `Elfwritedynent*`, `elfadddynsym` 等函数):**

在链接 `main.go` 时，`elf.go` 中的代码会执行以下与动态链接相关的操作：

1. **`.dynamic` 节生成:**  `doelf` 函数会创建 `.dynamic` 节，用于描述动态链接器的信息。
2. **`DT_NEEDED` 条目:** `elfadddynsym` 函数在处理导入的 C 函数时，会检测到需要链接 `libexample.so`，并在 `.dynamic` 节中添加一个 `DT_NEEDED` 条目，指向包含 "libexample.so" 字符串的 `.dynstr` 节。
3. **`.dynsym` 和 `.dynstr` 节生成:** `elfadddynsym` 函数会将 C 函数 `some_function_from_c` 的符号信息添加到 `.dynsym` 节，并将符号名称添加到 `.dynstr` 节。
4. **`.got` 和 `.plt` 节生成:** `doelf` 函数会创建 `.got` 和 `.plt` 节，用于在运行时进行动态符号解析和跳转。
5. **`.hash` 节生成:** `elfdynhash` 函数会生成 `.hash` 节，用于加速动态符号查找。

**可能的输出 (简化描述):**

生成的 ELF 文件 `main` 将包含以下与动态链接相关的节：

* **`.interp`:**  包含动态链接器的路径 (例如 `/lib64/ld-linux-x86-64.so.2`)。
* **`.dynamic`:**
    * `DT_NEEDED`: 指向 `.dynstr` 中 "libexample.so" 的偏移。
    * `DT_HASH`: 指向 `.hash` 节。
    * `DT_SYMTAB`: 指向 `.dynsym` 节。
    * `DT_STRTAB`: 指向 `.dynstr` 节。
    * ...其他动态链接相关的条目。
* **`.dynsym`:** 包含 `some_function_from_c` 的符号信息 (类型为 `STT_FUNC`, binding 为 `STB_GLOBAL`, section index 为 `SHN_UNDEF`)。
* **`.dynstr`:** 包含字符串 "libexample.so" 和 "some_function_from_c"。
* **`.got`:**  用于存储全局变量的地址。
* **`.plt`:**  用于实现函数的延迟绑定。
* **`.hash`:** 符号哈希表。

**命令行参数的具体处理：**

该文件内部主要负责 ELF 文件的结构化生成，它所使用的信息很大程度上来源于链接器的主流程，主流程会解析各种命令行参数。 但在该文件中，可以看到对某些命令行标志的直接引用，例如：

* **`*flagRace`:** 用于判断是否启用了竞态检测，影响 NetBSD 和 FreeBSD 的 Note 节生成 (用于禁用 ASLR)。
* **`*FlagD`:**  用于判断是否禁用动态链接器格式 (生成可执行文件时不包含动态链接相关的节)。
* **`*FlagRound`:**  用于设置 Program Header 中段的对齐方式。
* **`*FlagTextAddr`:**  用于设置代码段的起始地址。
* **`*FlagS`:** 用于判断是否剥离符号信息。
* **`*FlagW`:** 用于判断是否剥离 DWARF 调试信息。
* **`*flagBuildid` 和 `*flagHostBuildid`:** 用于处理构建 ID 相关的 Note 节生成。
* **`*flagBindNow`:**  用于设置是否立即绑定动态符号。

这些标志通常在链接器的 `main.go` 或其他初始化代码中被解析和设置，然后在 `elf.go` 中被读取和使用，以控制 ELF 文件的生成过程。

**使用者易犯错的点：**

由于 `elf.go` 是链接器内部实现的一部分，直接使用者是 Go 开发者，但他们通常不会直接修改或调用这个文件。 然而，开发者在使用 `go build` 命令时，可能会因为对链接参数理解不足而遇到问题，这些参数会影响 `elf.go` 的行为。

1. **缺少必要的 C 共享库链接参数:**  如果 Go 代码导入了 C 代码，但编译时忘记使用 `-ldflags` 指定 C 共享库的路径和名称，链接器会报错，提示找不到相关的符号。例如，在上面的例子中，如果编译时漏掉了 `-ldflags="-lexample"`，链接器会找不到 `some_function_from_c` 的定义。

2. **`-buildmode` 参数理解错误:**  如果开发者错误地选择了 `-buildmode`，例如期望生成共享库却选择了默认的可执行文件模式，或者反之，会导致生成的 ELF 文件结构不符合预期，在运行时出现问题。

3. **`-linkmode=external` 参数使用不当:**  外部链接涉及到与非 Go 代码的交互，需要开发者对 C/C++ 的链接过程也有一定的了解。如果外部链接的配置不正确，例如缺少必要的库或链接器脚本，会导致链接失败。

4. **构建 ID 相关参数的混淆使用:**  如果同时使用了 `-buildid` 和 `-B gobuildid` 且 `-buildid` 未提供，则会报错，因为 `-B gobuildid` 依赖于 `-buildid` 提供 Go 构建 ID。

**总结:**

`go/src/cmd/link/internal/ld/elf.go` 是 Go 链接器中负责生成 ELF 文件的核心组件，它定义了 ELF 文件的数据结构，并实现了生成 ELF 文件头、节头、程序头以及各种标准和自定义节的逻辑，特别是对动态链接和外部链接提供了关键的支持。 开发者在使用 `go build` 命令时，需要正确理解和使用相关的链接参数，才能生成符合预期的 ELF 文件。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/elf.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"cmd/internal/hash"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"internal/buildcfg"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

/*
 * Derived from:
 * $FreeBSD: src/sys/sys/elf32.h,v 1.8.14.1 2005/12/30 22:13:58 marcel Exp $
 * $FreeBSD: src/sys/sys/elf64.h,v 1.10.14.1 2005/12/30 22:13:58 marcel Exp $
 * $FreeBSD: src/sys/sys/elf_common.h,v 1.15.8.1 2005/12/30 22:13:58 marcel Exp $
 * $FreeBSD: src/sys/alpha/include/elf.h,v 1.14 2003/09/25 01:10:22 peter Exp $
 * $FreeBSD: src/sys/amd64/include/elf.h,v 1.18 2004/08/03 08:21:48 dfr Exp $
 * $FreeBSD: src/sys/arm/include/elf.h,v 1.5.2.1 2006/06/30 21:42:52 cognet Exp $
 * $FreeBSD: src/sys/i386/include/elf.h,v 1.16 2004/08/02 19:12:17 dfr Exp $
 * $FreeBSD: src/sys/powerpc/include/elf.h,v 1.7 2004/11/02 09:47:01 ssouhlal Exp $
 * $FreeBSD: src/sys/sparc64/include/elf.h,v 1.12 2003/09/25 01:10:26 peter Exp $
 *
 * Copyright (c) 1996-1998 John D. Polstra.  All rights reserved.
 * Copyright (c) 2001 David E. O'Brien
 * Portions Copyright 2009 The Go Authors. All rights reserved.
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
 *
 */

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
type elfNote struct {
	nNamesz uint32
	nDescsz uint32
	nType   uint32
}

/* For accessing the fields of r_info. */

/* For constructing r_info from field values. */

/*
 * Relocation types.
 */
const (
	ARM_MAGIC_TRAMP_NUMBER = 0x5c000003
)

/*
 * Symbol table entries.
 */

/* For accessing the fields of st_info. */

/* For constructing st_info from field values. */

/* For accessing the fields of st_other. */

/*
 * ELF header.
 */
type ElfEhdr elf.Header64

/*
 * Section header.
 */
type ElfShdr struct {
	elf.Section64
	shnum elf.SectionIndex
}

/*
 * Program header.
 */
type ElfPhdr elf.ProgHeader

/* For accessing the fields of r_info. */

/* For constructing r_info from field values. */

/*
 * Symbol table entries.
 */

/* For accessing the fields of st_info. */

/* For constructing st_info from field values. */

/* For accessing the fields of st_other. */

/*
 * Go linker interface
 */
const (
	ELF64HDRSIZE  = 64
	ELF64PHDRSIZE = 56
	ELF64SHDRSIZE = 64
	ELF64RELSIZE  = 16
	ELF64RELASIZE = 24
	ELF64SYMSIZE  = 24
	ELF32HDRSIZE  = 52
	ELF32PHDRSIZE = 32
	ELF32SHDRSIZE = 40
	ELF32SYMSIZE  = 16
	ELF32RELSIZE  = 8
)

/*
 * The interface uses the 64-bit structures always,
 * to avoid code duplication.  The writers know how to
 * marshal a 32-bit representation from the 64-bit structure.
 */

var elfstrdat, elfshstrdat []byte

/*
 * Total amount of space to reserve at the start of the file
 * for Header, PHeaders, SHeaders, and interp.
 * May waste some.
 * On FreeBSD, cannot be larger than a page.
 */
const (
	ELFRESERVE = 4096
)

/*
 * We use the 64-bit data structures on both 32- and 64-bit machines
 * in order to write the code just once.  The 64-bit data structure is
 * written in the 32-bit format on the 32-bit machines.
 */
const (
	NSECT = 400
)

var (
	Nelfsym = 1

	elf64 bool
	// Either ".rel" or ".rela" depending on which type of relocation the
	// target platform uses.
	elfRelType string

	ehdr ElfEhdr
	phdr [NSECT]*ElfPhdr
	shdr [NSECT]*ElfShdr

	interp string
)

// ELFArch includes target-specific hooks for ELF targets.
// This is initialized by the target-specific Init function
// called by the linker's main function in cmd/link/main.go.
type ELFArch struct {
	// TODO: Document these fields.

	Androiddynld   string
	Linuxdynld     string
	LinuxdynldMusl string
	Freebsddynld   string
	Netbsddynld    string
	Openbsddynld   string
	Dragonflydynld string
	Solarisdynld   string

	Reloc1    func(*Link, *OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int, int64) bool
	RelocSize uint32 // size of an ELF relocation record, must match Reloc1.
	SetupPLT  func(ctxt *Link, ldr *loader.Loader, plt, gotplt *loader.SymbolBuilder, dynamic loader.Sym)

	// DynamicReadOnly can be set to true to make the .dynamic
	// section read-only. By default it is writable.
	// This is used by MIPS targets.
	DynamicReadOnly bool
}

type Elfstring struct {
	s   string
	off int
}

var elfstr [100]Elfstring

var nelfstr int

var buildinfo []byte

/*
Initialize the global variable that describes the ELF header. It will be updated as
we write section and prog headers.
*/
func Elfinit(ctxt *Link) {
	ctxt.IsELF = true

	if ctxt.Arch.InFamily(sys.AMD64, sys.ARM64, sys.Loong64, sys.MIPS64, sys.PPC64, sys.RISCV64, sys.S390X) {
		elfRelType = ".rela"
	} else {
		elfRelType = ".rel"
	}

	switch ctxt.Arch.Family {
	// 64-bit architectures
	case sys.PPC64, sys.S390X:
		if ctxt.Arch.ByteOrder == binary.BigEndian && ctxt.HeadType != objabi.Hopenbsd {
			ehdr.Flags = 1 /* Version 1 ABI */
		} else {
			ehdr.Flags = 2 /* Version 2 ABI */
		}
		fallthrough
	case sys.AMD64, sys.ARM64, sys.Loong64, sys.MIPS64, sys.RISCV64:
		if ctxt.Arch.Family == sys.MIPS64 {
			ehdr.Flags = 0x20000004 /* MIPS 3 CPIC */
		}
		if ctxt.Arch.Family == sys.Loong64 {
			ehdr.Flags = 0x43 /* DOUBLE_FLOAT, OBJABI_V1 */
		}
		if ctxt.Arch.Family == sys.RISCV64 {
			ehdr.Flags = 0x4 /* RISCV Float ABI Double */
		}
		elf64 = true

		ehdr.Phoff = ELF64HDRSIZE      /* Must be ELF64HDRSIZE: first PHdr must follow ELF header */
		ehdr.Shoff = ELF64HDRSIZE      /* Will move as we add PHeaders */
		ehdr.Ehsize = ELF64HDRSIZE     /* Must be ELF64HDRSIZE */
		ehdr.Phentsize = ELF64PHDRSIZE /* Must be ELF64PHDRSIZE */
		ehdr.Shentsize = ELF64SHDRSIZE /* Must be ELF64SHDRSIZE */

	// 32-bit architectures
	case sys.ARM, sys.MIPS:
		if ctxt.Arch.Family == sys.ARM {
			// we use EABI on linux/arm, freebsd/arm, netbsd/arm.
			if ctxt.HeadType == objabi.Hlinux || ctxt.HeadType == objabi.Hfreebsd || ctxt.HeadType == objabi.Hnetbsd {
				// We set a value here that makes no indication of which
				// float ABI the object uses, because this is information
				// used by the dynamic linker to compare executables and
				// shared libraries -- so it only matters for cgo calls, and
				// the information properly comes from the object files
				// produced by the host C compiler. parseArmAttributes in
				// ldelf.go reads that information and updates this field as
				// appropriate.
				ehdr.Flags = 0x5000002 // has entry point, Version5 EABI
			}
		} else if ctxt.Arch.Family == sys.MIPS {
			ehdr.Flags = 0x50001004 /* MIPS 32 CPIC O32*/
		}
		fallthrough
	default:
		ehdr.Phoff = ELF32HDRSIZE
		/* Must be ELF32HDRSIZE: first PHdr must follow ELF header */
		ehdr.Shoff = ELF32HDRSIZE      /* Will move as we add PHeaders */
		ehdr.Ehsize = ELF32HDRSIZE     /* Must be ELF32HDRSIZE */
		ehdr.Phentsize = ELF32PHDRSIZE /* Must be ELF32PHDRSIZE */
		ehdr.Shentsize = ELF32SHDRSIZE /* Must be ELF32SHDRSIZE */
	}
}

// Make sure PT_LOAD is aligned properly and
// that there is no gap,
// correct ELF loaders will do this implicitly,
// but buggy ELF loaders like the one in some
// versions of QEMU and UPX won't.
func fixElfPhdr(e *ElfPhdr) {
	frag := int(e.Vaddr & (e.Align - 1))

	e.Off -= uint64(frag)
	e.Vaddr -= uint64(frag)
	e.Paddr -= uint64(frag)
	e.Filesz += uint64(frag)
	e.Memsz += uint64(frag)
}

func elf64phdr(out *OutBuf, e *ElfPhdr) {
	if e.Type == elf.PT_LOAD {
		fixElfPhdr(e)
	}

	out.Write32(uint32(e.Type))
	out.Write32(uint32(e.Flags))
	out.Write64(e.Off)
	out.Write64(e.Vaddr)
	out.Write64(e.Paddr)
	out.Write64(e.Filesz)
	out.Write64(e.Memsz)
	out.Write64(e.Align)
}

func elf32phdr(out *OutBuf, e *ElfPhdr) {
	if e.Type == elf.PT_LOAD {
		fixElfPhdr(e)
	}

	out.Write32(uint32(e.Type))
	out.Write32(uint32(e.Off))
	out.Write32(uint32(e.Vaddr))
	out.Write32(uint32(e.Paddr))
	out.Write32(uint32(e.Filesz))
	out.Write32(uint32(e.Memsz))
	out.Write32(uint32(e.Flags))
	out.Write32(uint32(e.Align))
}

func elf64shdr(out *OutBuf, e *ElfShdr) {
	out.Write32(e.Name)
	out.Write32(uint32(e.Type))
	out.Write64(uint64(e.Flags))
	out.Write64(e.Addr)
	out.Write64(e.Off)
	out.Write64(e.Size)
	out.Write32(e.Link)
	out.Write32(e.Info)
	out.Write64(e.Addralign)
	out.Write64(e.Entsize)
}

func elf32shdr(out *OutBuf, e *ElfShdr) {
	out.Write32(e.Name)
	out.Write32(uint32(e.Type))
	out.Write32(uint32(e.Flags))
	out.Write32(uint32(e.Addr))
	out.Write32(uint32(e.Off))
	out.Write32(uint32(e.Size))
	out.Write32(e.Link)
	out.Write32(e.Info)
	out.Write32(uint32(e.Addralign))
	out.Write32(uint32(e.Entsize))
}

func elfwriteshdrs(out *OutBuf) uint32 {
	if elf64 {
		for i := 0; i < int(ehdr.Shnum); i++ {
			elf64shdr(out, shdr[i])
		}
		return uint32(ehdr.Shnum) * ELF64SHDRSIZE
	}

	for i := 0; i < int(ehdr.Shnum); i++ {
		elf32shdr(out, shdr[i])
	}
	return uint32(ehdr.Shnum) * ELF32SHDRSIZE
}

func elfsetstring(ctxt *Link, s loader.Sym, str string, off int) {
	if nelfstr >= len(elfstr) {
		ctxt.Errorf(s, "too many elf strings")
		errorexit()
	}

	elfstr[nelfstr].s = str
	elfstr[nelfstr].off = off
	nelfstr++
}

func elfwritephdrs(out *OutBuf) uint32 {
	if elf64 {
		for i := 0; i < int(ehdr.Phnum); i++ {
			elf64phdr(out, phdr[i])
		}
		return uint32(ehdr.Phnum) * ELF64PHDRSIZE
	}

	for i := 0; i < int(ehdr.Phnum); i++ {
		elf32phdr(out, phdr[i])
	}
	return uint32(ehdr.Phnum) * ELF32PHDRSIZE
}

func newElfPhdr() *ElfPhdr {
	e := new(ElfPhdr)
	if ehdr.Phnum >= NSECT {
		Errorf("too many phdrs")
	} else {
		phdr[ehdr.Phnum] = e
		ehdr.Phnum++
	}
	if elf64 {
		ehdr.Shoff += ELF64PHDRSIZE
	} else {
		ehdr.Shoff += ELF32PHDRSIZE
	}
	return e
}

func newElfShdr(name int64) *ElfShdr {
	e := new(ElfShdr)
	e.Name = uint32(name)
	e.shnum = elf.SectionIndex(ehdr.Shnum)
	if ehdr.Shnum >= NSECT {
		Errorf("too many shdrs")
	} else {
		shdr[ehdr.Shnum] = e
		ehdr.Shnum++
	}

	return e
}

func getElfEhdr() *ElfEhdr {
	return &ehdr
}

func elf64writehdr(out *OutBuf) uint32 {
	out.Write(ehdr.Ident[:])
	out.Write16(uint16(ehdr.Type))
	out.Write16(uint16(ehdr.Machine))
	out.Write32(uint32(ehdr.Version))
	out.Write64(ehdr.Entry)
	out.Write64(ehdr.Phoff)
	out.Write64(ehdr.Shoff)
	out.Write32(ehdr.Flags)
	out.Write16(ehdr.Ehsize)
	out.Write16(ehdr.Phentsize)
	out.Write16(ehdr.Phnum)
	out.Write16(ehdr.Shentsize)
	out.Write16(ehdr.Shnum)
	out.Write16(ehdr.Shstrndx)
	return ELF64HDRSIZE
}

func elf32writehdr(out *OutBuf) uint32 {
	out.Write(ehdr.Ident[:])
	out.Write16(uint16(ehdr.Type))
	out.Write16(uint16(ehdr.Machine))
	out.Write32(uint32(ehdr.Version))
	out.Write32(uint32(ehdr.Entry))
	out.Write32(uint32(ehdr.Phoff))
	out.Write32(uint32(ehdr.Shoff))
	out.Write32(ehdr.Flags)
	out.Write16(ehdr.Ehsize)
	out.Write16(ehdr.Phentsize)
	out.Write16(ehdr.Phnum)
	out.Write16(ehdr.Shentsize)
	out.Write16(ehdr.Shnum)
	out.Write16(ehdr.Shstrndx)
	return ELF32HDRSIZE
}

func elfwritehdr(out *OutBuf) uint32 {
	if elf64 {
		return elf64writehdr(out)
	}
	return elf32writehdr(out)
}

/* Taken directly from the definition document for ELF64. */
func elfhash(name string) uint32 {
	var h uint32
	for i := 0; i < len(name); i++ {
		h = (h << 4) + uint32(name[i])
		if g := h & 0xf0000000; g != 0 {
			h ^= g >> 24
		}
		h &= 0x0fffffff
	}
	return h
}

func elfWriteDynEntSym(ctxt *Link, s *loader.SymbolBuilder, tag elf.DynTag, t loader.Sym) {
	Elfwritedynentsymplus(ctxt, s, tag, t, 0)
}

func Elfwritedynent(arch *sys.Arch, s *loader.SymbolBuilder, tag elf.DynTag, val uint64) {
	if elf64 {
		s.AddUint64(arch, uint64(tag))
		s.AddUint64(arch, val)
	} else {
		s.AddUint32(arch, uint32(tag))
		s.AddUint32(arch, uint32(val))
	}
}

func Elfwritedynentsymplus(ctxt *Link, s *loader.SymbolBuilder, tag elf.DynTag, t loader.Sym, add int64) {
	if elf64 {
		s.AddUint64(ctxt.Arch, uint64(tag))
	} else {
		s.AddUint32(ctxt.Arch, uint32(tag))
	}
	s.AddAddrPlus(ctxt.Arch, t, add)
}

func elfwritedynentsymsize(ctxt *Link, s *loader.SymbolBuilder, tag elf.DynTag, t loader.Sym) {
	if elf64 {
		s.AddUint64(ctxt.Arch, uint64(tag))
	} else {
		s.AddUint32(ctxt.Arch, uint32(tag))
	}
	s.AddSize(ctxt.Arch, t)
}

func elfinterp(sh *ElfShdr, startva uint64, resoff uint64, p string) int {
	interp = p
	n := len(interp) + 1
	sh.Addr = startva + resoff - uint64(n)
	sh.Off = resoff - uint64(n)
	sh.Size = uint64(n)

	return n
}

func elfwriteinterp(out *OutBuf) int {
	sh := elfshname(".interp")
	out.SeekSet(int64(sh.Off))
	out.WriteString(interp)
	out.Write8(0)
	return int(sh.Size)
}

// member of .gnu.attributes of MIPS for fpAbi
const (
	// No floating point is present in the module (default)
	MIPS_FPABI_NONE = 0
	// FP code in the module uses the FP32 ABI for a 32-bit ABI
	MIPS_FPABI_ANY = 1
	// FP code in the module only uses single precision ABI
	MIPS_FPABI_SINGLE = 2
	// FP code in the module uses soft-float ABI
	MIPS_FPABI_SOFT = 3
	// FP code in the module assumes an FPU with FR=1 and has 12
	// callee-saved doubles. Historic, no longer supported.
	MIPS_FPABI_HIST = 4
	// FP code in the module uses the FPXX  ABI
	MIPS_FPABI_FPXX = 5
	// FP code in the module uses the FP64  ABI
	MIPS_FPABI_FP64 = 6
	// FP code in the module uses the FP64A ABI
	MIPS_FPABI_FP64A = 7
)

func elfMipsAbiFlags(sh *ElfShdr, startva uint64, resoff uint64) int {
	n := 24
	sh.Addr = startva + resoff - uint64(n)
	sh.Off = resoff - uint64(n)
	sh.Size = uint64(n)
	sh.Type = uint32(elf.SHT_MIPS_ABIFLAGS)
	sh.Flags = uint64(elf.SHF_ALLOC)

	return n
}

// Layout is given by this C definition:
//
//	typedef struct
//	{
//	  /* Version of flags structure.  */
//	  uint16_t version;
//	  /* The level of the ISA: 1-5, 32, 64.  */
//	  uint8_t isa_level;
//	  /* The revision of ISA: 0 for MIPS V and below, 1-n otherwise.  */
//	  uint8_t isa_rev;
//	  /* The size of general purpose registers.  */
//	  uint8_t gpr_size;
//	  /* The size of co-processor 1 registers.  */
//	  uint8_t cpr1_size;
//	  /* The size of co-processor 2 registers.  */
//	  uint8_t cpr2_size;
//	  /* The floating-point ABI.  */
//	  uint8_t fp_abi;
//	  /* Processor-specific extension.  */
//	  uint32_t isa_ext;
//	  /* Mask of ASEs used.  */
//	  uint32_t ases;
//	  /* Mask of general flags.  */
//	  uint32_t flags1;
//	  uint32_t flags2;
//	} Elf_Internal_ABIFlags_v0;
func elfWriteMipsAbiFlags(ctxt *Link) int {
	sh := elfshname(".MIPS.abiflags")
	ctxt.Out.SeekSet(int64(sh.Off))
	ctxt.Out.Write16(0) // version
	ctxt.Out.Write8(32) // isaLevel
	ctxt.Out.Write8(1)  // isaRev
	ctxt.Out.Write8(1)  // gprSize
	ctxt.Out.Write8(1)  // cpr1Size
	ctxt.Out.Write8(0)  // cpr2Size
	if buildcfg.GOMIPS == "softfloat" {
		ctxt.Out.Write8(MIPS_FPABI_SOFT) // fpAbi
	} else {
		// Go cannot make sure non odd-number-fpr is used (ie, in load a double from memory).
		// So, we mark the object is MIPS I style paired float/double register scheme,
		// aka MIPS_FPABI_ANY. If we mark the object as FPXX, the kernel may use FR=1 mode,
		// then we meet some problem.
		// Note: MIPS_FPABI_ANY is bad naming: in fact it is MIPS I style FPR usage.
		//       It is not for 'ANY'.
		// TODO: switch to FPXX after be sure that no odd-number-fpr is used.
		ctxt.Out.Write8(MIPS_FPABI_ANY) // fpAbi
	}
	ctxt.Out.Write32(0) // isaExt
	ctxt.Out.Write32(0) // ases
	ctxt.Out.Write32(0) // flags1
	ctxt.Out.Write32(0) // flags2
	return int(sh.Size)
}

func elfnote(sh *ElfShdr, startva uint64, resoff uint64, sizes ...int) int {
	n := resoff % 4
	// if section contains multiple notes (as is the case with FreeBSD signature),
	// multiple note sizes can be specified
	for _, sz := range sizes {
		n += 3*4 + uint64(sz)
	}

	sh.Type = uint32(elf.SHT_NOTE)
	sh.Flags = uint64(elf.SHF_ALLOC)
	sh.Addralign = 4
	sh.Addr = startva + resoff - n
	sh.Off = resoff - n
	sh.Size = n - resoff%4

	return int(n)
}

func elfwritenotehdr(out *OutBuf, str string, namesz uint32, descsz uint32, tag uint32) *ElfShdr {
	sh := elfshname(str)

	// Write Elf_Note header.
	out.SeekSet(int64(sh.Off))

	out.Write32(namesz)
	out.Write32(descsz)
	out.Write32(tag)

	return sh
}

// NetBSD Signature (as per sys/exec_elf.h)
const (
	ELF_NOTE_NETBSD_NAMESZ  = 7
	ELF_NOTE_NETBSD_DESCSZ  = 4
	ELF_NOTE_NETBSD_TAG     = 1
	ELF_NOTE_NETBSD_VERSION = 700000000 /* NetBSD 7.0 */
)

var ELF_NOTE_NETBSD_NAME = []byte("NetBSD\x00")

func elfnetbsdsig(sh *ElfShdr, startva uint64, resoff uint64) int {
	n := int(Rnd(ELF_NOTE_NETBSD_NAMESZ, 4) + Rnd(ELF_NOTE_NETBSD_DESCSZ, 4))
	return elfnote(sh, startva, resoff, n)
}

func elfwritenetbsdsig(out *OutBuf) int {
	// Write Elf_Note header.
	sh := elfwritenotehdr(out, ".note.netbsd.ident", ELF_NOTE_NETBSD_NAMESZ, ELF_NOTE_NETBSD_DESCSZ, ELF_NOTE_NETBSD_TAG)

	if sh == nil {
		return 0
	}

	// Followed by NetBSD string and version.
	out.Write(ELF_NOTE_NETBSD_NAME)
	out.Write8(0)
	out.Write32(ELF_NOTE_NETBSD_VERSION)

	return int(sh.Size)
}

// The race detector can't handle ASLR (address space layout randomization).
// ASLR is on by default for NetBSD, so we turn the ASLR off explicitly
// using a magic elf Note when building race binaries.

func elfnetbsdpax(sh *ElfShdr, startva uint64, resoff uint64) int {
	n := int(Rnd(4, 4) + Rnd(4, 4))
	return elfnote(sh, startva, resoff, n)
}

func elfwritenetbsdpax(out *OutBuf) int {
	sh := elfwritenotehdr(out, ".note.netbsd.pax", 4 /* length of PaX\x00 */, 4 /* length of flags */, 0x03 /* PaX type */)
	if sh == nil {
		return 0
	}
	out.Write([]byte("PaX\x00"))
	out.Write32(0x20) // 0x20 = Force disable ASLR
	return int(sh.Size)
}

// OpenBSD Signature
const (
	ELF_NOTE_OPENBSD_NAMESZ  = 8
	ELF_NOTE_OPENBSD_DESCSZ  = 4
	ELF_NOTE_OPENBSD_TAG     = 1
	ELF_NOTE_OPENBSD_VERSION = 0
)

var ELF_NOTE_OPENBSD_NAME = []byte("OpenBSD\x00")

func elfopenbsdsig(sh *ElfShdr, startva uint64, resoff uint64) int {
	n := ELF_NOTE_OPENBSD_NAMESZ + ELF_NOTE_OPENBSD_DESCSZ
	return elfnote(sh, startva, resoff, n)
}

func elfwriteopenbsdsig(out *OutBuf) int {
	// Write Elf_Note header.
	sh := elfwritenotehdr(out, ".note.openbsd.ident", ELF_NOTE_OPENBSD_NAMESZ, ELF_NOTE_OPENBSD_DESCSZ, ELF_NOTE_OPENBSD_TAG)

	if sh == nil {
		return 0
	}

	// Followed by OpenBSD string and version.
	out.Write(ELF_NOTE_OPENBSD_NAME)

	out.Write32(ELF_NOTE_OPENBSD_VERSION)

	return int(sh.Size)
}

// FreeBSD Signature (as per sys/elf_common.h)
const (
	ELF_NOTE_FREEBSD_NAMESZ            = 8
	ELF_NOTE_FREEBSD_DESCSZ            = 4
	ELF_NOTE_FREEBSD_ABI_TAG           = 1
	ELF_NOTE_FREEBSD_NOINIT_TAG        = 2
	ELF_NOTE_FREEBSD_FEATURE_CTL_TAG   = 4
	ELF_NOTE_FREEBSD_VERSION           = 1203000 // 12.3-RELEASE
	ELF_NOTE_FREEBSD_FCTL_ASLR_DISABLE = 0x1
)

const ELF_NOTE_FREEBSD_NAME = "FreeBSD\x00"

func elffreebsdsig(sh *ElfShdr, startva uint64, resoff uint64) int {
	n := ELF_NOTE_FREEBSD_NAMESZ + ELF_NOTE_FREEBSD_DESCSZ
	// FreeBSD signature section contains 3 equally sized notes
	return elfnote(sh, startva, resoff, n, n, n)
}

// elfwritefreebsdsig writes FreeBSD .note section.
//
// See https://www.netbsd.org/docs/kernel/elf-notes.html for the description of
// a Note element format and
// https://github.com/freebsd/freebsd-src/blob/main/sys/sys/elf_common.h#L790
// for the FreeBSD-specific values.
func elfwritefreebsdsig(out *OutBuf) int {
	sh := elfshname(".note.tag")
	if sh == nil {
		return 0
	}
	out.SeekSet(int64(sh.Off))

	// NT_FREEBSD_ABI_TAG
	out.Write32(ELF_NOTE_FREEBSD_NAMESZ)
	out.Write32(ELF_NOTE_FREEBSD_DESCSZ)
	out.Write32(ELF_NOTE_FREEBSD_ABI_TAG)
	out.WriteString(ELF_NOTE_FREEBSD_NAME)
	out.Write32(ELF_NOTE_FREEBSD_VERSION)

	// NT_FREEBSD_NOINIT_TAG
	out.Write32(ELF_NOTE_FREEBSD_NAMESZ)
	out.Write32(ELF_NOTE_FREEBSD_DESCSZ)
	out.Write32(ELF_NOTE_FREEBSD_NOINIT_TAG)
	out.WriteString(ELF_NOTE_FREEBSD_NAME)
	out.Write32(0)

	// NT_FREEBSD_FEATURE_CTL
	out.Write32(ELF_NOTE_FREEBSD_NAMESZ)
	out.Write32(ELF_NOTE_FREEBSD_DESCSZ)
	out.Write32(ELF_NOTE_FREEBSD_FEATURE_CTL_TAG)
	out.WriteString(ELF_NOTE_FREEBSD_NAME)
	if *flagRace {
		// The race detector can't handle ASLR, turn the ASLR off when compiling with -race.
		out.Write32(ELF_NOTE_FREEBSD_FCTL_ASLR_DISABLE)
	} else {
		out.Write32(0)
	}

	return int(sh.Size)
}

func addbuildinfo(ctxt *Link) {
	val := *flagHostBuildid
	if val == "" || val == "none" {
		return
	}
	if val == "gobuildid" {
		buildID := *flagBuildid
		if buildID == "" {
			Exitf("-B gobuildid requires a Go build ID supplied via -buildid")
		}

		if ctxt.IsDarwin() {
			buildinfo = uuidFromGoBuildId(buildID)
			return
		}

		hashedBuildID := hash.Sum32([]byte(buildID))
		buildinfo = hashedBuildID[:20]

		return
	}

	if !strings.HasPrefix(val, "0x") {
		Exitf("-B argument must start with 0x: %s", val)
	}
	ov := val
	val = val[2:]

	maxLen := 32
	if ctxt.IsDarwin() {
		maxLen = 16
	}
	if hex.DecodedLen(len(val)) > maxLen {
		Exitf("-B option too long (max %d digits): %s", maxLen, ov)
	}

	b, err := hex.DecodeString(val)
	if err != nil {
		if err == hex.ErrLength {
			Exitf("-B argument must have even number of digits: %s", ov)
		}
		if inv, ok := err.(hex.InvalidByteError); ok {
			Exitf("-B argument contains invalid hex digit %c: %s", byte(inv), ov)
		}
		Exitf("-B argument contains invalid hex: %s", ov)
	}

	buildinfo = b
}

// Build info note
const (
	ELF_NOTE_BUILDINFO_NAMESZ = 4
	ELF_NOTE_BUILDINFO_TAG    = 3
)

var ELF_NOTE_BUILDINFO_NAME = []byte("GNU\x00")

func elfbuildinfo(sh *ElfShdr, startva uint64, resoff uint64) int {
	n := int(ELF_NOTE_BUILDINFO_NAMESZ + Rnd(int64(len(buildinfo)), 4))
	return elfnote(sh, startva, resoff, n)
}

func elfgobuildid(sh *ElfShdr, startva uint64, resoff uint64) int {
	n := len(ELF_NOTE_GO_NAME) + int(Rnd(int64(len(*flagBuildid)), 4))
	return elfnote(sh, startva, resoff, n)
}

func elfwritebuildinfo(out *OutBuf) int {
	sh := elfwritenotehdr(out, ".note.gnu.build-id", ELF_NOTE_BUILDINFO_NAMESZ, uint32(len(buildinfo)), ELF_NOTE_BUILDINFO_TAG)
	if sh == nil {
		return 0
	}

	out.Write(ELF_NOTE_BUILDINFO_NAME)
	out.Write(buildinfo)
	var zero = make([]byte, 4)
	out.Write(zero[:int(Rnd(int64(len(buildinfo)), 4)-int64(len(buildinfo)))])

	return int(sh.Size)
}

func elfwritegobuildid(out *OutBuf) int {
	sh := elfwritenotehdr(out, ".note.go.buildid", uint32(len(ELF_NOTE_GO_NAME)), uint32(len(*flagBuildid)), ELF_NOTE_GOBUILDID_TAG)
	if sh == nil {
		return 0
	}

	out.Write(ELF_NOTE_GO_NAME)
	out.Write([]byte(*flagBuildid))
	var zero = make([]byte, 4)
	out.Write(zero[:int(Rnd(int64(len(*flagBuildid)), 4)-int64(len(*flagBuildid)))])

	return int(sh.Size)
}

// Go specific notes
const (
	ELF_NOTE_GOPKGLIST_TAG = 1
	ELF_NOTE_GOABIHASH_TAG = 2
	ELF_NOTE_GODEPS_TAG    = 3
	ELF_NOTE_GOBUILDID_TAG = 4
)

var ELF_NOTE_GO_NAME = []byte("Go\x00\x00")

var elfverneed int

type Elfaux struct {
	next *Elfaux
	num  int
	vers string
}

type Elflib struct {
	next *Elflib
	aux  *Elfaux
	file string
}

func addelflib(list **Elflib, file string, vers string) *Elfaux {
	var lib *Elflib

	for lib = *list; lib != nil; lib = lib.next {
		if lib.file == file {
			goto havelib
		}
	}
	lib = new(Elflib)
	lib.next = *list
	lib.file = file
	*list = lib

havelib:
	for aux := lib.aux; aux != nil; aux = aux.next {
		if aux.vers == vers {
			return aux
		}
	}
	aux := new(Elfaux)
	aux.next = lib.aux
	aux.vers = vers
	lib.aux = aux

	return aux
}

func elfdynhash(ctxt *Link) {
	if !ctxt.IsELF {
		return
	}

	nsym := Nelfsym
	ldr := ctxt.loader
	s := ldr.CreateSymForUpdate(".hash", 0)
	s.SetType(sym.SELFROSECT)

	i := nsym
	nbucket := 1
	for i > 0 {
		nbucket++
		i >>= 1
	}

	var needlib *Elflib
	need := make([]*Elfaux, nsym)
	chain := make([]uint32, nsym)
	buckets := make([]uint32, nbucket)

	for _, sy := range ldr.DynidSyms() {

		dynid := ldr.SymDynid(sy)
		if ldr.SymDynimpvers(sy) != "" {
			need[dynid] = addelflib(&needlib, ldr.SymDynimplib(sy), ldr.SymDynimpvers(sy))
		}

		name := ldr.SymExtname(sy)
		hc := elfhash(name)

		b := hc % uint32(nbucket)
		chain[dynid] = buckets[b]
		buckets[b] = uint32(dynid)
	}

	// s390x (ELF64) hash table entries are 8 bytes
	if ctxt.Arch.Family == sys.S390X {
		s.AddUint64(ctxt.Arch, uint64(nbucket))
		s.AddUint64(ctxt.Arch, uint64(nsym))
		for i := 0; i < nbucket; i++ {
			s.AddUint64(ctxt.Arch, uint64(buckets[i]))
		}
		for i := 0; i < nsym; i++ {
			s.AddUint64(ctxt.Arch, uint64(chain[i]))
		}
	} else {
		s.AddUint32(ctxt.Arch, uint32(nbucket))
		s.AddUint32(ctxt.Arch, uint32(nsym))
		for i := 0; i < nbucket; i++ {
			s.AddUint32(ctxt.Arch, buckets[i])
		}
		for i := 0; i < nsym; i++ {
			s.AddUint32(ctxt.Arch, chain[i])
		}
	}

	dynstr := ldr.CreateSymForUpdate(".dynstr", 0)

	// version symbols
	gnuVersionR := ldr.CreateSymForUpdate(".gnu.version_r", 0)
	s = gnuVersionR
	i = 2
	nfile := 0
	for l := needlib; l != nil; l = l.next {
		nfile++

		// header
		s.AddUint16(ctxt.Arch, 1) // table version
		j := 0
		for x := l.aux; x != nil; x = x.next {
			j++
		}
		s.AddUint16(ctxt.Arch, uint16(j))                        // aux count
		s.AddUint32(ctxt.Arch, uint32(dynstr.Addstring(l.file))) // file string offset
		s.AddUint32(ctxt.Arch, 16)                               // offset from header to first aux
		if l.next != nil {
			s.AddUint32(ctxt.Arch, 16+uint32(j)*16) // offset from this header to next
		} else {
			s.AddUint32(ctxt.Arch, 0)
		}

		for x := l.aux; x != nil; x = x.next {
			x.num = i
			i++

			// aux struct
			s.AddUint32(ctxt.Arch, elfhash(x.vers))                  // hash
			s.AddUint16(ctxt.Arch, 0)                                // flags
			s.AddUint16(ctxt.Arch, uint16(x.num))                    // other - index we refer to this by
			s.AddUint32(ctxt.Arch, uint32(dynstr.Addstring(x.vers))) // version string offset
			if x.next != nil {
				s.AddUint32(ctxt.Arch, 16) // offset from this aux to next
			} else {
				s.AddUint32(ctxt.Arch, 0)
			}
		}
	}

	// version references
	gnuVersion := ldr.CreateSymForUpdate(".gnu.version", 0)
	s = gnuVersion

	for i := 0; i < nsym; i++ {
		if i == 0 {
			s.AddUint16(ctxt.Arch, 0) // first entry - no symbol
		} else if need[i] == nil {
			s.AddUint16(ctxt.Arch, 1) // global
		} else {
			s.AddUint16(ctxt.Arch, uint16(need[i].num))
		}
	}

	s = ldr.CreateSymForUpdate(".dynamic", 0)

	var dtFlags1 elf.DynFlag1
	if *flagBindNow {
		dtFlags1 |= elf.DF_1_NOW
		Elfwritedynent(ctxt.Arch, s, elf.DT_FLAGS, uint64(elf.DF_BIND_NOW))
	}
	if ctxt.BuildMode == BuildModePIE {
		dtFlags1 |= elf.DF_1_PIE
	}
	Elfwritedynent(ctxt.Arch, s, elf.DT_FLAGS_1, uint64(dtFlags1))

	elfverneed = nfile
	if elfverneed != 0 {
		elfWriteDynEntSym(ctxt, s, elf.DT_VERNEED, gnuVersionR.Sym())
		Elfwritedynent(ctxt.Arch, s, elf.DT_VERNEEDNUM, uint64(nfile))
		elfWriteDynEntSym(ctxt, s, elf.DT_VERSYM, gnuVersion.Sym())
	}

	sy := ldr.CreateSymForUpdate(elfRelType+".plt", 0)
	if sy.Size() > 0 {
		if elfRelType == ".rela" {
			Elfwritedynent(ctxt.Arch, s, elf.DT_PLTREL, uint64(elf.DT_RELA))
		} else {
			Elfwritedynent(ctxt.Arch, s, elf.DT_PLTREL, uint64(elf.DT_REL))
		}
		elfwritedynentsymsize(ctxt, s, elf.DT_PLTRELSZ, sy.Sym())
		elfWriteDynEntSym(ctxt, s, elf.DT_JMPREL, sy.Sym())
	}

	Elfwritedynent(ctxt.Arch, s, elf.DT_NULL, 0)
}

func elfphload(seg *sym.Segment) *ElfPhdr {
	ph := newElfPhdr()
	ph.Type = elf.PT_LOAD
	if seg.Rwx&4 != 0 {
		ph.Flags |= elf.PF_R
	}
	if seg.Rwx&2 != 0 {
		ph.Flags |= elf.PF_W
	}
	if seg.Rwx&1 != 0 {
		ph.Flags |= elf.PF_X
	}
	ph.Vaddr = seg.Vaddr
	ph.Paddr = seg.Vaddr
	ph.Memsz = seg.Length
	ph.Off = seg.Fileoff
	ph.Filesz = seg.Filelen
	ph.Align = uint64(*FlagRound)

	return ph
}

func elfphrelro(seg *sym.Segment) {
	ph := newElfPhdr()
	ph.Type = elf.PT_GNU_RELRO
	ph.Flags = elf.PF_R
	ph.Vaddr = seg.Vaddr
	ph.Paddr = seg.Vaddr
	ph.Memsz = seg.Length
	ph.Off = seg.Fileoff
	ph.Filesz = seg.Filelen
	ph.Align = uint64(*FlagRound)
}

func elfshname(name string) *ElfShdr {
	for i := 0; i < nelfstr; i++ {
		if name != elfstr[i].s {
			continue
		}
		off := elfstr[i].off
		for i = 0; i < int(ehdr.Shnum); i++ {
			sh := shdr[i]
			if sh.Name == uint32(off) {
				return sh
			}
		}
		return newElfShdr(int64(off))
	}
	Exitf("cannot find elf name %s", name)
	return nil
}

// Create an ElfShdr for the section with name.
// Create a duplicate if one already exists with that name.
func elfshnamedup(name string) *ElfShdr {
	for i := 0; i < nelfstr; i++ {
		if name == elfstr[i].s {
			off := elfstr[i].off
			return newElfShdr(int64(off))
		}
	}

	Errorf("cannot find elf name %s", name)
	errorexit()
	return nil
}

func elfshalloc(sect *sym.Section) *ElfShdr {
	sh := elfshname(sect.Name)
	sect.Elfsect = sh
	return sh
}

func elfshbits(linkmode LinkMode, sect *sym.Section) *ElfShdr {
	var sh *ElfShdr

	if sect.Name == ".text" {
		if sect.Elfsect == nil {
			sect.Elfsect = elfshnamedup(sect.Name)
		}
		sh = sect.Elfsect.(*ElfShdr)
	} else {
		sh = elfshalloc(sect)
	}

	// If this section has already been set up as a note, we assume type_ and
	// flags are already correct, but the other fields still need filling in.
	if sh.Type == uint32(elf.SHT_NOTE) {
		if linkmode != LinkExternal {
			// TODO(mwhudson): the approach here will work OK when
			// linking internally for notes that we want to be included
			// in a loadable segment (e.g. the abihash note) but not for
			// notes that we do not want to be mapped (e.g. the package
			// list note). The real fix is probably to define new values
			// for Symbol.Type corresponding to mapped and unmapped notes
			// and handle them in dodata().
			Errorf("sh.Type == SHT_NOTE in elfshbits when linking internally")
		}
		sh.Addralign = uint64(sect.Align)
		sh.Size = sect.Length
		sh.Off = sect.Seg.Fileoff + sect.Vaddr - sect.Seg.Vaddr
		return sh
	}
	if sh.Type > 0 {
		return sh
	}

	if sect.Vaddr < sect.Seg.Vaddr+sect.Seg.Filelen {
		switch sect.Name {
		case ".init_array":
			sh.Type = uint32(elf.SHT_INIT_ARRAY)
		default:
			sh.Type = uint32(elf.SHT_PROGBITS)
		}
	} else {
		sh.Type = uint32(elf.SHT_NOBITS)
	}
	sh.Flags = uint64(elf.SHF_ALLOC)
	if sect.Rwx&1 != 0 {
		sh.Flags |= uint64(elf.SHF_EXECINSTR)
	}
	if sect.Rwx&2 != 0 {
		sh.Flags |= uint64(elf.SHF_WRITE)
	}
	if sect.Name == ".tbss" {
		sh.Flags |= uint64(elf.SHF_TLS)
		sh.Type = uint32(elf.SHT_NOBITS)
	}
	if linkmode != LinkExternal {
		sh.Addr = sect.Vaddr
	}

	if strings.HasPrefix(sect.Name, ".debug") || strings.HasPrefix(sect.Name, ".zdebug") {
		sh.Flags = 0
		sh.Addr = 0
		if sect.Compressed {
			sh.Flags |= uint64(elf.SHF_COMPRESSED)
		}
	}

	sh.Addralign = uint64(sect.Align)
	sh.Size = sect.Length
	if sect.Name != ".tbss" {
		sh.Off = sect.Seg.Fileoff + sect.Vaddr - sect.Seg.Vaddr
	}

	return sh
}

func elfshreloc(arch *sys.Arch, sect *sym.Section) *ElfShdr {
	// If main section is SHT_NOBITS, nothing to relocate.
	// Also nothing to relocate in .shstrtab or notes.
	if sect.Vaddr >= sect.Seg.Vaddr+sect.Seg.Filelen {
		return nil
	}
	if sect.Name == ".shstrtab" || sect.Name == ".tbss" {
		return nil
	}
	if sect.Elfsect.(*ElfShdr).Type == uint32(elf.SHT_NOTE) {
		return nil
	}

	typ := elf.SHT_REL
	if elfRelType == ".rela" {
		typ = elf.SHT_RELA
	}

	sh := elfshname(elfRelType + sect.Name)
	// There could be multiple text sections but each needs
	// its own .rela.text.

	if sect.Name == ".text" {
		if sh.Info != 0 && sh.Info != uint32(sect.Elfsect.(*ElfShdr).shnum) {
			sh = elfshnamedup(elfRelType + sect.Name)
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