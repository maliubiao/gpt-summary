Response:
My thought process for analyzing the `ldmacho.go` code went something like this:

1. **Understand the Goal:** The filename and package name (`loadmacho`) immediately suggest that this code is responsible for reading and interpreting Mach-O files. Given it's in the `cmd/link` directory, it's likely used by the Go linker.

2. **Identify Key Data Structures:** I scanned the code for `struct` definitions. These represent the core data being parsed from the Mach-O file. The prominent structures are:
    * `ldMachoObj`: Represents the overall Mach-O object file.
    * `ldMachoCmd`:  Represents a load command within the Mach-O file.
    * `ldMachoSeg`: Represents a segment (like `__TEXT` or `__DATA`).
    * `ldMachoSect`: Represents a section within a segment (like `__text` or `__bss`).
    * `ldMachoRel`: Represents a relocation entry.
    * `ldMachoSymtab`: Represents the symbol table.
    * `ldMachoSym`: Represents a symbol entry.
    * `ldMachoDysymtab`: Represents the dynamic symbol table.

3. **Trace the Parsing Logic:**  I looked for functions that seem to be driving the parsing process. The `Load` function is the obvious entry point, taking a `bio.Reader` (for reading the file) and other linker context. Within `Load`, I noted these steps:
    * **Magic Number Check:**  Verifies the file is a Mach-O file.
    * **Header Parsing:** Extracts basic information like CPU type, file type, and the number and size of load commands.
    * **Load Command Iteration:**  Loops through the load commands and calls `unpackcmd` to process each one.
    * **`unpackcmd` Logic:**  A large `switch` statement that handles different load command types (`LC_SEGMENT`, `LC_SYMTAB`, `LC_DYSYMTAB`, etc.), parsing the command-specific data.
    * **Symbol Table Loading:**  Calls `macholoadsym` to load the symbol table.
    * **Dynamic Symbol Table Loading:** Calls `macholoaddsym` to load the dynamic symbol table.
    * **Segment Loading:**  Finds the text and data segments and loads their content into memory.
    * **Relocation Loading:**  Calls `macholoadrel` to load and process relocation entries.

4. **Analyze Individual Functions:** I examined the purpose of each function:
    * `unpackcmd`: Decodes the raw byte stream of a load command into the corresponding `ldMachoCmd` struct.
    * `macholoadrel`: Reads and interprets relocation entries for a given section. It handles both scattered and standard relocations.
    * `macholoaddsym` (for Dysymtab): Reads the indirect symbol table.
    * `macholoadsym` (for Symtab): Reads the symbol table and the associated string table.
    * `Load`: The main function orchestrating the loading and processing of the Mach-O file.
    * `cstring`: A utility function to read null-terminated C-style strings.

5. **Identify Core Functionality:** Based on the above analysis, I summarized the key functionalities:
    * Parsing the Mach-O header.
    * Processing different types of load commands.
    * Loading symbol tables (static and dynamic).
    * Loading segment data (text, data, etc.).
    * Handling relocations.

6. **Infer the Go Feature:**  Knowing that this code is part of the Go linker (`cmd/link`), and it's parsing Mach-O files, the most logical conclusion is that it's responsible for **linking Go programs on macOS (and potentially other Darwin-based systems)**. Mach-O is the executable file format used by these operating systems.

7. **Construct a Code Example:** To illustrate the functionality, I thought about a simple Go program being compiled and linked. The linker would use this code to read the compiled object files (which are in Mach-O format on macOS). The example needs to show how symbols and relocations are involved. A simple function call across different compilation units demonstrates this nicely.

8. **Consider Command-Line Arguments:**  Since this is part of the linker, I considered what command-line flags the linker might use that would affect this code. Flags related to architecture (`-arch`), operating system (`-os`), and input files (`.o` files) are relevant.

9. **Think About Common Mistakes:**  I focused on potential errors a *user* of Go (not necessarily someone directly using this `loadmacho` package) might encounter that relate to Mach-O files. Architecture mismatches (trying to link object files for the wrong architecture) are a common problem.

10. **Refine and Organize:** I structured my answer logically, starting with a high-level overview of the functionality, then providing more details about the code, the inferred Go feature, the example, command-line arguments, and potential errors. I tried to use the terminology from the code itself (like "load commands," "segments," "sections," "symbols").
这段Go语言代码是Go链接器（`cmd/link`）的一部分，专门用于加载和解析 Mach-O (Mach Object) 文件。Mach-O 是 macOS 和其他基于 Darwin 的操作系统（如 iOS）上使用的可执行文件、目标代码、动态链接库和内核转储的格式。

**核心功能:**

1. **读取 Mach-O 文件结构:** 代码定义了一系列结构体 (`ldMachoObj`, `ldMachoCmd`, `ldMachoSeg`, `ldMachoSect`, `ldMachoRel`, `ldMachoSymtab`, `ldMachoSym`, `ldMachoDysymtab`)，用于映射 Mach-O 文件的各个部分，如头部、加载命令、段（segment）、节（section）、重定位信息、符号表等。

2. **解析 Mach-O 头部:** `Load` 函数首先读取 Mach-O 文件的头部，识别魔数（magic number）以确定字节序（大端或小端）和文件类型（32位或64位）。

3. **处理加载命令 (Load Commands):**  代码遍历 Mach-O 文件中的加载命令，并使用 `unpackcmd` 函数根据命令类型解析其内容。常见的加载命令包括：
    * `LC_SEGMENT` 和 `LC_SEGMENT_64`: 定义内存段，如 `__TEXT` (代码段) 和 `__DATA` (数据段)。代码会解析段的虚拟地址、大小、文件偏移等信息，并进一步解析段内的节。
    * `LC_SYMTAB`: 指向符号表的偏移和大小。代码会使用 `macholoadsym` 函数加载符号表。
    * `LC_DYSYMTAB`: 指向动态符号表的偏移和大小。代码会使用 `macholoaddsym` 函数加载动态符号表。

4. **加载段和节的数据:**  对于代码段 (`__TEXT`) 和数据段 (`__DATA`)，代码会读取它们在文件中的数据，并将其与链接器的符号关联起来。

5. **加载符号表:** `macholoadsym` 函数读取符号表和字符串表，解析每个符号的名称、类型、所在节、描述符和值。

6. **加载动态符号表:** `macholoaddsym` 函数读取动态符号表的额外信息，如本地符号、外部定义符号、未定义符号等的索引。

7. **处理重定位信息:** `macholoadrel` 函数读取并解析节的重定位信息，这些信息指示了在链接时需要修改的指令或数据的位置，以便正确引用符号。代码支持不同的重定位类型，例如针对 x86-64 和 ARM64 架构的重定位。

8. **将 Mach-O 信息集成到 Go 链接器:**  `Load` 函数会将解析得到的 Mach-O 文件信息，如符号、段、节和重定位信息，添加到 Go 链接器的内部数据结构中（通过 `loader.Loader` 接口）。

**推理 Go 语言功能的实现:**

基于以上分析，可以推断 `ldmacho.go` 代码是 Go 链接器支持 **链接 Mach-O 格式的目标文件** 的关键部分。当你在 macOS 或 iOS 上编译 Go 程序时，编译器会生成 Mach-O 格式的目标文件（`.o` 文件）。链接器使用这段代码来读取这些目标文件，合并它们的代码和数据，解析符号引用，并最终生成可执行文件或动态链接库。

**Go 代码示例:**

假设我们有两个简单的 Go 源文件 `a.go` 和 `b.go`:

**a.go:**

```go
package main

func Hello() string {
	return "Hello from a.go"
}
```

**b.go:**

```go
package main

import "fmt"

func main() {
	message := Hello()
	fmt.Println(message)
}
```

当我们使用 `go build` 命令编译这个程序时，Go 工具链会执行以下步骤（简化）：

1. **编译:** `go compiler` 将 `a.go` 和 `b.go` 分别编译成 Mach-O 格式的目标文件 `a.o` 和 `b.o`。这些 `.o` 文件包含了编译后的机器码、符号表和重定位信息。

2. **链接:** `go linker`（即 `cmd/link`）会读取 `a.o` 和 `b.o` 文件。这时，`ldmacho.go` 中的 `Load` 函数会被调用，解析这两个 Mach-O 文件。

   * `ldmacho.go` 会识别 `Hello` 函数在 `a.o` 的代码段中，以及 `main` 函数在 `b.o` 的代码段中。
   * 它会解析 `b.o` 中对 `Hello` 函数的引用（这会体现在 `b.o` 的重定位信息中）。
   * 链接器会根据重定位信息，将 `b.o` 中调用 `Hello` 的地址修改为 `Hello` 函数在内存中的实际地址。

3. **生成可执行文件:**  链接器最终生成可执行文件 `main` (在 macOS 上也是 Mach-O 格式)。

**假设的输入与输出 (针对 `macholoadrel` 函数):**

假设我们正在处理 `b.o` 文件的一个代码节（`__text`），并且其中包含一个对 `Hello` 函数的函数调用。

**假设的输入:**

* `m`: 代表 `b.o` 文件的 `ldMachoObj` 结构体。
* `sect`: 代表 `__text` 节的 `ldMachoSect` 结构体，其中 `sect.nreloc` 大于 0，表示有重定位信息。
* `sect.reloff`: 指向 `b.o` 文件中重定位信息起始位置的偏移量。
* `sect.rel` 为 `nil`。
* 文件 `b.o` 在 `sect.reloff` 处包含一条重定位记录，指示在某个地址（例如 `rel.addr`）处有一个对外部符号 `Hello` 的引用，并且需要进行地址修正。假设重定位类型是 `MACHO_X86_64_RELOC_BRANCH` (跳转指令)。
* 符号表 (`symtab`) 中包含 `Hello` 函数的条目。

**假设的输出:**

* `macholoadrel` 函数成功执行，返回 0。
* `sect.rel` 不再为 `nil`，它是一个 `[]ldMachoRel`，包含了从文件中解析出的重定位信息。
* `sect.rel` 中的某个 `ldMachoRel` 元素会反映之前假设的重定位记录：
    * `rel.addr`: 函数调用指令在节内的偏移地址。
    * `rel.type_`:  表示重定位类型 (例如，指向代码的相对跳转)。
    * `rel.extrn`:  为 1，表示这是一个外部符号引用。
    * `rel.symnum`: 指向符号表中 `Hello` 函数的索引。

**命令行参数的具体处理:**

`ldmacho.go` 自身并不直接处理命令行参数。命令行参数的处理发生在 `cmd/link` 包的其他部分。但是，链接器的命令行参数会间接地影响 `ldmacho.go` 的行为。例如：

* **`-buildmode=...`**:  选择构建模式（如 `exe`, `pie`, `c-shared`）。这会影响链接器生成的可执行文件的 Mach-O 文件类型 (`LdMachoFileExecutable`,  可能还有其他类型)，从而影响 `ldmacho.go` 加载目标文件的方式。
* **`-arch <architecture>`**:  指定目标架构（如 `amd64`, `arm64`）。`ldmacho.go` 中的 `Load` 函数会检查目标文件的架构是否与 `-arch` 参数匹配。如果不匹配，会报错。
* **输入的目标文件 (`.o` 文件)**:  链接器接收一系列目标文件作为输入。`ldmacho.go` 的 `Load` 函数会针对每个输入的 Mach-O 目标文件被调用。

**使用者易犯错的点:**

对于 *Go 语言开发者* 而言，直接与 `ldmacho.go` 交互的情况非常少。但他们可能会遇到与 Mach-O 文件相关的错误，这些错误可能是 `ldmacho.go` 在解析过程中发现的。

1. **架构不匹配:** 如果尝试链接为不同架构编译的目标文件，`ldmacho.go` 会检测到 Mach-O 文件的 `cputype` 与目标架构不符，并报告错误，例如 "mach-o object but not amd64"。

   ```bash
   # 假设你在 x86_64 机器上，但尝试链接一个 arm64 的 .o 文件
   go build -ldflags="-linkmode external -extldflags=-target=arm64" your_program.go
   # 可能会看到类似 "loadmacho: your_object.o: mach-o object but not amd64" 的错误
   ```

2. **损坏的 Mach-O 文件:** 如果目标文件被损坏，导致 Mach-O 头部或加载命令无法正确解析，`ldmacho.go` 可能会报告 "bad magic - not mach-o file" 或 "implausible mach-o header" 等错误。

3. **缺少必要的符号:** 如果一个目标文件引用了另一个目标文件中不存在的符号，链接器会报错。虽然错误信息可能不会直接指向 `ldmacho.go`，但 `ldmacho.go` 在加载符号表时会发现这些缺失的引用。

总而言之，`ldmacho.go` 是 Go 链接器中处理 Mach-O 文件格式的核心组件，负责将编译后的目标代码整合在一起，生成最终的可执行文件或动态库。理解它的功能有助于理解 Go 程序的编译和链接过程。

Prompt: 
```
这是路径为go/src/cmd/link/internal/loadmacho/ldmacho.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package loadmacho implements a Mach-O file reader.
package loadmacho

import (
	"bytes"
	"cmd/internal/bio"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"encoding/binary"
	"fmt"
)

/*
Derived from Plan 9 from User Space's src/libmach/elf.h, elf.c
https://github.com/9fans/plan9port/tree/master/src/libmach/

	Copyright © 2004 Russ Cox.
	Portions Copyright © 2008-2010 Google Inc.
	Portions Copyright © 2010 The Go Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// TODO(crawshaw): de-duplicate these symbols with cmd/link/internal/ld
const (
	MACHO_X86_64_RELOC_UNSIGNED = 0
	MACHO_X86_64_RELOC_SIGNED   = 1
	MACHO_ARM64_RELOC_ADDEND    = 10
)

type ldMachoObj struct {
	f          *bio.Reader
	base       int64 // off in f where Mach-O begins
	length     int64 // length of Mach-O
	is64       bool
	name       string
	e          binary.ByteOrder
	cputype    uint
	subcputype uint
	filetype   uint32
	flags      uint32
	cmd        []ldMachoCmd
	ncmd       uint
}

type ldMachoCmd struct {
	type_ int
	off   uint32
	size  uint32
	seg   ldMachoSeg
	sym   ldMachoSymtab
	dsym  ldMachoDysymtab
}

type ldMachoSeg struct {
	name     string
	vmaddr   uint64
	vmsize   uint64
	fileoff  uint32
	filesz   uint32
	maxprot  uint32
	initprot uint32
	nsect    uint32
	flags    uint32
	sect     []ldMachoSect
}

type ldMachoSect struct {
	name    string
	segname string
	addr    uint64
	size    uint64
	off     uint32
	align   uint32
	reloff  uint32
	nreloc  uint32
	flags   uint32
	res1    uint32
	res2    uint32
	sym     loader.Sym
	rel     []ldMachoRel
}

type ldMachoRel struct {
	addr      uint32
	symnum    uint32
	pcrel     uint8
	length    uint8
	extrn     uint8
	type_     uint8
	scattered uint8
	value     uint32
}

type ldMachoSymtab struct {
	symoff  uint32
	nsym    uint32
	stroff  uint32
	strsize uint32
	str     []byte
	sym     []ldMachoSym
}

type ldMachoSym struct {
	name    string
	type_   uint8
	sectnum uint8
	desc    uint16
	kind    int8
	value   uint64
	sym     loader.Sym
}

type ldMachoDysymtab struct {
	ilocalsym      uint32
	nlocalsym      uint32
	iextdefsym     uint32
	nextdefsym     uint32
	iundefsym      uint32
	nundefsym      uint32
	tocoff         uint32
	ntoc           uint32
	modtaboff      uint32
	nmodtab        uint32
	extrefsymoff   uint32
	nextrefsyms    uint32
	indirectsymoff uint32
	nindirectsyms  uint32
	extreloff      uint32
	nextrel        uint32
	locreloff      uint32
	nlocrel        uint32
	indir          []uint32
}

// ldMachoSym.type_
const (
	N_EXT  = 0x01
	N_TYPE = 0x1e
	N_STAB = 0xe0
)

// ldMachoSym.desc
const (
	N_WEAK_REF = 0x40
	N_WEAK_DEF = 0x80
)

const (
	LdMachoCpuVax         = 1
	LdMachoCpu68000       = 6
	LdMachoCpu386         = 7
	LdMachoCpuAmd64       = 1<<24 | 7
	LdMachoCpuMips        = 8
	LdMachoCpu98000       = 10
	LdMachoCpuHppa        = 11
	LdMachoCpuArm         = 12
	LdMachoCpuArm64       = 1<<24 | 12
	LdMachoCpu88000       = 13
	LdMachoCpuSparc       = 14
	LdMachoCpu860         = 15
	LdMachoCpuAlpha       = 16
	LdMachoCpuPower       = 18
	LdMachoCmdSegment     = 1
	LdMachoCmdSymtab      = 2
	LdMachoCmdSymseg      = 3
	LdMachoCmdThread      = 4
	LdMachoCmdDysymtab    = 11
	LdMachoCmdSegment64   = 25
	LdMachoFileObject     = 1
	LdMachoFileExecutable = 2
	LdMachoFileFvmlib     = 3
	LdMachoFileCore       = 4
	LdMachoFilePreload    = 5
)

func unpackcmd(p []byte, m *ldMachoObj, c *ldMachoCmd, type_ uint, sz uint) int {
	e4 := m.e.Uint32
	e8 := m.e.Uint64

	c.type_ = int(type_)
	c.size = uint32(sz)
	switch type_ {
	default:
		return -1

	case LdMachoCmdSegment:
		if sz < 56 {
			return -1
		}
		c.seg.name = cstring(p[8:24])
		c.seg.vmaddr = uint64(e4(p[24:]))
		c.seg.vmsize = uint64(e4(p[28:]))
		c.seg.fileoff = e4(p[32:])
		c.seg.filesz = e4(p[36:])
		c.seg.maxprot = e4(p[40:])
		c.seg.initprot = e4(p[44:])
		c.seg.nsect = e4(p[48:])
		c.seg.flags = e4(p[52:])
		c.seg.sect = make([]ldMachoSect, c.seg.nsect)
		if uint32(sz) < 56+c.seg.nsect*68 {
			return -1
		}
		p = p[56:]
		var s *ldMachoSect
		for i := 0; uint32(i) < c.seg.nsect; i++ {
			s = &c.seg.sect[i]
			s.name = cstring(p[0:16])
			s.segname = cstring(p[16:32])
			s.addr = uint64(e4(p[32:]))
			s.size = uint64(e4(p[36:]))
			s.off = e4(p[40:])
			s.align = e4(p[44:])
			s.reloff = e4(p[48:])
			s.nreloc = e4(p[52:])
			s.flags = e4(p[56:])
			s.res1 = e4(p[60:])
			s.res2 = e4(p[64:])
			p = p[68:]
		}

	case LdMachoCmdSegment64:
		if sz < 72 {
			return -1
		}
		c.seg.name = cstring(p[8:24])
		c.seg.vmaddr = e8(p[24:])
		c.seg.vmsize = e8(p[32:])
		c.seg.fileoff = uint32(e8(p[40:]))
		c.seg.filesz = uint32(e8(p[48:]))
		c.seg.maxprot = e4(p[56:])
		c.seg.initprot = e4(p[60:])
		c.seg.nsect = e4(p[64:])
		c.seg.flags = e4(p[68:])
		c.seg.sect = make([]ldMachoSect, c.seg.nsect)
		if uint32(sz) < 72+c.seg.nsect*80 {
			return -1
		}
		p = p[72:]
		var s *ldMachoSect
		for i := 0; uint32(i) < c.seg.nsect; i++ {
			s = &c.seg.sect[i]
			s.name = cstring(p[0:16])
			s.segname = cstring(p[16:32])
			s.addr = e8(p[32:])
			s.size = e8(p[40:])
			s.off = e4(p[48:])
			s.align = e4(p[52:])
			s.reloff = e4(p[56:])
			s.nreloc = e4(p[60:])
			s.flags = e4(p[64:])
			s.res1 = e4(p[68:])
			s.res2 = e4(p[72:])

			// p+76 is reserved
			p = p[80:]
		}

	case LdMachoCmdSymtab:
		if sz < 24 {
			return -1
		}
		c.sym.symoff = e4(p[8:])
		c.sym.nsym = e4(p[12:])
		c.sym.stroff = e4(p[16:])
		c.sym.strsize = e4(p[20:])

	case LdMachoCmdDysymtab:
		if sz < 80 {
			return -1
		}
		c.dsym.ilocalsym = e4(p[8:])
		c.dsym.nlocalsym = e4(p[12:])
		c.dsym.iextdefsym = e4(p[16:])
		c.dsym.nextdefsym = e4(p[20:])
		c.dsym.iundefsym = e4(p[24:])
		c.dsym.nundefsym = e4(p[28:])
		c.dsym.tocoff = e4(p[32:])
		c.dsym.ntoc = e4(p[36:])
		c.dsym.modtaboff = e4(p[40:])
		c.dsym.nmodtab = e4(p[44:])
		c.dsym.extrefsymoff = e4(p[48:])
		c.dsym.nextrefsyms = e4(p[52:])
		c.dsym.indirectsymoff = e4(p[56:])
		c.dsym.nindirectsyms = e4(p[60:])
		c.dsym.extreloff = e4(p[64:])
		c.dsym.nextrel = e4(p[68:])
		c.dsym.locreloff = e4(p[72:])
		c.dsym.nlocrel = e4(p[76:])
	}

	return 0
}

func macholoadrel(m *ldMachoObj, sect *ldMachoSect) int {
	if sect.rel != nil || sect.nreloc == 0 {
		return 0
	}
	rel := make([]ldMachoRel, sect.nreloc)
	m.f.MustSeek(m.base+int64(sect.reloff), 0)
	buf, _, err := m.f.Slice(uint64(sect.nreloc * 8))
	if err != nil {
		return -1
	}
	for i := uint32(0); i < sect.nreloc; i++ {
		r := &rel[i]
		p := buf[i*8:]
		r.addr = m.e.Uint32(p)

		// TODO(rsc): Wrong interpretation for big-endian bitfields?
		if r.addr&0x80000000 != 0 {
			// scatterbrained relocation
			r.scattered = 1

			v := r.addr >> 24
			r.addr &= 0xFFFFFF
			r.type_ = uint8(v & 0xF)
			v >>= 4
			r.length = 1 << (v & 3)
			v >>= 2
			r.pcrel = uint8(v & 1)
			r.value = m.e.Uint32(p[4:])
		} else {
			v := m.e.Uint32(p[4:])
			r.symnum = v & 0xFFFFFF
			v >>= 24
			r.pcrel = uint8(v & 1)
			v >>= 1
			r.length = 1 << (v & 3)
			v >>= 2
			r.extrn = uint8(v & 1)
			v >>= 1
			r.type_ = uint8(v)
		}
	}

	sect.rel = rel
	return 0
}

func macholoaddsym(m *ldMachoObj, d *ldMachoDysymtab) int {
	n := int(d.nindirectsyms)
	m.f.MustSeek(m.base+int64(d.indirectsymoff), 0)
	p, _, err := m.f.Slice(uint64(n * 4))
	if err != nil {
		return -1
	}

	d.indir = make([]uint32, n)
	for i := 0; i < n; i++ {
		d.indir[i] = m.e.Uint32(p[4*i:])
	}
	return 0
}

func macholoadsym(m *ldMachoObj, symtab *ldMachoSymtab) int {
	if symtab.sym != nil {
		return 0
	}

	m.f.MustSeek(m.base+int64(symtab.stroff), 0)
	strbuf, _, err := m.f.Slice(uint64(symtab.strsize))
	if err != nil {
		return -1
	}

	symsize := 12
	if m.is64 {
		symsize = 16
	}
	n := int(symtab.nsym * uint32(symsize))
	m.f.MustSeek(m.base+int64(symtab.symoff), 0)
	symbuf, _, err := m.f.Slice(uint64(n))
	if err != nil {
		return -1
	}
	sym := make([]ldMachoSym, symtab.nsym)
	p := symbuf
	for i := uint32(0); i < symtab.nsym; i++ {
		s := &sym[i]
		v := m.e.Uint32(p)
		if v >= symtab.strsize {
			return -1
		}
		s.name = cstring(strbuf[v:])
		s.type_ = p[4]
		s.sectnum = p[5]
		s.desc = m.e.Uint16(p[6:])
		if m.is64 {
			s.value = m.e.Uint64(p[8:])
		} else {
			s.value = uint64(m.e.Uint32(p[8:]))
		}
		p = p[symsize:]
	}

	symtab.str = strbuf
	symtab.sym = sym
	return 0
}

// Load the Mach-O file pn from f.
// Symbols are written into syms, and a slice of the text symbols is returned.
func Load(l *loader.Loader, arch *sys.Arch, localSymVersion int, f *bio.Reader, pkg string, length int64, pn string) (textp []loader.Sym, err error) {
	errorf := func(str string, args ...interface{}) ([]loader.Sym, error) {
		return nil, fmt.Errorf("loadmacho: %v: %v", pn, fmt.Sprintf(str, args...))
	}

	base := f.Offset()

	hdr, _, err := f.Slice(7 * 4)
	if err != nil {
		return errorf("reading hdr: %v", err)
	}

	var e binary.ByteOrder
	if binary.BigEndian.Uint32(hdr[:])&^1 == 0xFEEDFACE {
		e = binary.BigEndian
	} else if binary.LittleEndian.Uint32(hdr[:])&^1 == 0xFEEDFACE {
		e = binary.LittleEndian
	} else {
		return errorf("bad magic - not mach-o file")
	}

	is64 := e.Uint32(hdr[:]) == 0xFEEDFACF
	ncmd := e.Uint32(hdr[4*4:])
	cmdsz := e.Uint32(hdr[5*4:])
	if ncmd > 0x10000 || cmdsz >= 0x01000000 {
		return errorf("implausible mach-o header ncmd=%d cmdsz=%d", ncmd, cmdsz)
	}

	if is64 {
		f.MustSeek(4, 1) // skip reserved word in header
	}

	m := &ldMachoObj{
		f:          f,
		e:          e,
		cputype:    uint(e.Uint32(hdr[1*4:])),
		subcputype: uint(e.Uint32(hdr[2*4:])),
		filetype:   e.Uint32(hdr[3*4:]),
		ncmd:       uint(ncmd),
		flags:      e.Uint32(hdr[6*4:]),
		is64:       is64,
		base:       base,
		length:     length,
		name:       pn,
	}

	switch arch.Family {
	default:
		return errorf("mach-o %s unimplemented", arch.Name)
	case sys.AMD64:
		if e != binary.LittleEndian || m.cputype != LdMachoCpuAmd64 {
			return errorf("mach-o object but not amd64")
		}
	case sys.ARM64:
		if e != binary.LittleEndian || m.cputype != LdMachoCpuArm64 {
			return errorf("mach-o object but not arm64")
		}
	}

	m.cmd = make([]ldMachoCmd, ncmd)
	cmdp, _, err := f.Slice(uint64(cmdsz))
	if err != nil {
		return errorf("reading cmds: %v", err)
	}

	// read and parse load commands
	var c *ldMachoCmd

	var symtab *ldMachoSymtab
	var dsymtab *ldMachoDysymtab

	off := uint32(len(hdr))
	for i := uint32(0); i < ncmd; i++ {
		ty := e.Uint32(cmdp)
		sz := e.Uint32(cmdp[4:])
		m.cmd[i].off = off
		unpackcmd(cmdp, m, &m.cmd[i], uint(ty), uint(sz))
		cmdp = cmdp[sz:]
		off += sz
		if ty == LdMachoCmdSymtab {
			if symtab != nil {
				return errorf("multiple symbol tables")
			}

			symtab = &m.cmd[i].sym
			macholoadsym(m, symtab)
		}

		if ty == LdMachoCmdDysymtab {
			dsymtab = &m.cmd[i].dsym
			macholoaddsym(m, dsymtab)
		}

		if (is64 && ty == LdMachoCmdSegment64) || (!is64 && ty == LdMachoCmdSegment) {
			if c != nil {
				return errorf("multiple load commands")
			}

			c = &m.cmd[i]
		}
	}

	// load text and data segments into memory.
	// they are not as small as the load commands, but we'll need
	// the memory anyway for the symbol images, so we might
	// as well use one large chunk.
	if c == nil {
		return errorf("no load command")
	}

	if symtab == nil {
		// our work is done here - no symbols means nothing can refer to this file
		return
	}

	if int64(c.seg.fileoff+c.seg.filesz) >= length {
		return errorf("load segment out of range")
	}

	f.MustSeek(m.base+int64(c.seg.fileoff), 0)
	dat, readOnly, err := f.Slice(uint64(c.seg.filesz))
	if err != nil {
		return errorf("cannot load object data: %v", err)
	}

	for i := uint32(0); i < c.seg.nsect; i++ {
		sect := &c.seg.sect[i]
		if sect.segname != "__TEXT" && sect.segname != "__DATA" {
			continue
		}
		if sect.name == "__eh_frame" {
			continue
		}
		name := fmt.Sprintf("%s(%s/%s)", pkg, sect.segname, sect.name)
		s := l.LookupOrCreateSym(name, localSymVersion)
		bld := l.MakeSymbolUpdater(s)
		if bld.Type() != 0 {
			return errorf("duplicate %s/%s", sect.segname, sect.name)
		}

		if sect.flags&0xff == 1 { // S_ZEROFILL
			bld.SetData(make([]byte, sect.size))
		} else {
			bld.SetReadOnly(readOnly)
			bld.SetData(dat[sect.addr-c.seg.vmaddr:][:sect.size])
		}
		bld.SetSize(int64(len(bld.Data())))

		if sect.segname == "__TEXT" {
			if sect.name == "__text" {
				bld.SetType(sym.STEXT)
			} else {
				bld.SetType(sym.SRODATA)
			}
		} else {
			if sect.name == "__bss" {
				bld.SetType(sym.SNOPTRBSS)
				bld.SetData(nil)
			} else {
				bld.SetType(sym.SNOPTRDATA)
			}
		}

		sect.sym = s
	}

	// enter sub-symbols into symbol table.
	// have to guess sizes from next symbol.
	for i := uint32(0); i < symtab.nsym; i++ {
		machsym := &symtab.sym[i]
		if machsym.type_&N_STAB != 0 {
			continue
		}

		// TODO: check sym->type against outer->type.
		name := machsym.name

		if name[0] == '_' && name[1] != '\x00' {
			name = name[1:]
		}
		v := 0
		if machsym.type_&N_EXT == 0 {
			v = localSymVersion
		}
		s := l.LookupOrCreateCgoExport(name, v)
		if machsym.type_&N_EXT == 0 {
			l.SetAttrDuplicateOK(s, true)
		}
		if machsym.desc&(N_WEAK_REF|N_WEAK_DEF) != 0 {
			l.SetAttrDuplicateOK(s, true)
		}
		machsym.sym = s
		if machsym.sectnum == 0 { // undefined
			continue
		}
		if uint32(machsym.sectnum) > c.seg.nsect {
			return errorf("reference to invalid section %d", machsym.sectnum)
		}

		sect := &c.seg.sect[machsym.sectnum-1]
		bld := l.MakeSymbolUpdater(s)
		outer := sect.sym
		if outer == 0 {
			continue // ignore reference to invalid section
		}

		if osym := l.OuterSym(s); osym != 0 {
			if l.AttrDuplicateOK(s) {
				continue
			}
			return errorf("duplicate symbol reference: %s in both %s and %s", l.SymName(s), l.SymName(osym), l.SymName(sect.sym))
		}

		bld.SetType(l.SymType(outer))
		if l.SymSize(outer) != 0 { // skip empty section (0-sized symbol)
			l.AddInteriorSym(outer, s)
		}

		bld.SetValue(int64(machsym.value - sect.addr))
		if !l.AttrCgoExportDynamic(s) {
			bld.SetDynimplib("") // satisfy dynimport
		}
		if l.SymType(outer).IsText() {
			if bld.External() && !bld.DuplicateOK() {
				return errorf("%v: duplicate symbol definition", s)
			}
			bld.SetExternal(true)
		}
	}

	// Sort outer lists by address, adding to textp.
	// This keeps textp in increasing address order.
	for i := 0; uint32(i) < c.seg.nsect; i++ {
		sect := &c.seg.sect[i]
		s := sect.sym
		if s == 0 {
			continue
		}
		bld := l.MakeSymbolUpdater(s)
		if bld.SubSym() != 0 {

			bld.SortSub()

			// assign sizes, now that we know symbols in sorted order.
			for s1 := bld.Sub(); s1 != 0; s1 = l.SubSym(s1) {
				s1Bld := l.MakeSymbolUpdater(s1)
				if sub := l.SubSym(s1); sub != 0 {
					s1Bld.SetSize(l.SymValue(sub) - l.SymValue(s1))
				} else {
					dlen := int64(len(l.Data(s)))
					s1Bld.SetSize(l.SymValue(s) + dlen - l.SymValue(s1))
				}
			}
		}

		if bld.Type().IsText() {
			if bld.OnList() {
				return errorf("symbol %s listed multiple times", bld.Name())
			}
			bld.SetOnList(true)
			textp = append(textp, s)
			for s1 := bld.Sub(); s1 != 0; s1 = l.SubSym(s1) {
				if l.AttrOnList(s1) {
					return errorf("symbol %s listed multiple times", l.SymName(s1))
				}
				l.SetAttrOnList(s1, true)
				textp = append(textp, s1)
			}
		}
	}

	// load relocations
	for i := 0; uint32(i) < c.seg.nsect; i++ {
		sect := &c.seg.sect[i]
		s := sect.sym
		if s == 0 {
			continue
		}
		macholoadrel(m, sect)
		if sect.rel == nil {
			continue
		}

		sb := l.MakeSymbolUpdater(sect.sym)
		var rAdd int64
		for j := uint32(0); j < sect.nreloc; j++ {
			var (
				rOff  int32
				rSize uint8
				rType objabi.RelocType
				rSym  loader.Sym
			)
			rel := &sect.rel[j]
			if rel.scattered != 0 {
				// mach-o only uses scattered relocation on 32-bit platforms,
				// which are no longer supported.
				return errorf("%v: unexpected scattered relocation", s)
			}

			if arch.Family == sys.ARM64 && rel.type_ == MACHO_ARM64_RELOC_ADDEND {
				// Two relocations. This addend will be applied to the next one.
				rAdd = int64(rel.symnum) << 40 >> 40 // convert unsigned 24-bit to signed 24-bit
				continue
			}

			rSize = rel.length
			rType = objabi.MachoRelocOffset + (objabi.RelocType(rel.type_) << 1) + objabi.RelocType(rel.pcrel)
			rOff = int32(rel.addr)

			// Handle X86_64_RELOC_SIGNED referencing a section (rel.extrn == 0).
			p := l.Data(s)
			if arch.Family == sys.AMD64 {
				if rel.extrn == 0 && rel.type_ == MACHO_X86_64_RELOC_SIGNED {
					// Calculate the addend as the offset into the section.
					//
					// The rip-relative offset stored in the object file is encoded
					// as follows:
					//
					//    movsd	0x00000360(%rip),%xmm0
					//
					// To get the absolute address of the value this rip-relative address is pointing
					// to, we must add the address of the next instruction to it. This is done by
					// taking the address of the relocation and adding 4 to it (since the rip-relative
					// offset can at most be 32 bits long).  To calculate the offset into the section the
					// relocation is referencing, we subtract the vaddr of the start of the referenced
					// section found in the original object file.
					//
					// [For future reference, see Darwin's /usr/include/mach-o/x86_64/reloc.h]
					secaddr := c.seg.sect[rel.symnum-1].addr
					rAdd = int64(uint64(int64(int32(e.Uint32(p[rOff:])))+int64(rOff)+4) - secaddr)
				} else {
					rAdd = int64(int32(e.Uint32(p[rOff:])))
				}
			}

			// An unsigned internal relocation has a value offset
			// by the section address.
			if arch.Family == sys.AMD64 && rel.extrn == 0 && rel.type_ == MACHO_X86_64_RELOC_UNSIGNED {
				secaddr := c.seg.sect[rel.symnum-1].addr
				rAdd -= int64(secaddr)
			}

			if rel.extrn == 0 {
				if rel.symnum < 1 || rel.symnum > c.seg.nsect {
					return errorf("invalid relocation: section reference out of range %d vs %d", rel.symnum, c.seg.nsect)
				}

				rSym = c.seg.sect[rel.symnum-1].sym
				if rSym == 0 {
					return errorf("invalid relocation: %s", c.seg.sect[rel.symnum-1].name)
				}
			} else {
				if rel.symnum >= symtab.nsym {
					return errorf("invalid relocation: symbol reference out of range")
				}

				rSym = symtab.sym[rel.symnum].sym
			}

			r, _ := sb.AddRel(rType)
			r.SetOff(rOff)
			r.SetSiz(rSize)
			r.SetSym(rSym)
			r.SetAdd(rAdd)

			rAdd = 0 // clear rAdd for next iteration
		}

		sb.SortRelocs()
	}

	return textp, nil
}

func cstring(x []byte) string {
	i := bytes.IndexByte(x, '\x00')
	if i >= 0 {
		x = x[:i]
	}
	return string(x)
}

"""



```