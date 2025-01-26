Response:
My thought process to answer the prompt goes like this:

1. **Understand the Goal:** The request is to analyze a Go test file (`file_test.go`) and summarize its functionality. Specifically, it asks for:
    * A list of its functions.
    * Inferences about the Go language feature being tested, with code examples.
    * Details on code reasoning (with input/output assumptions).
    * Information on command-line argument handling (if applicable).
    * Common mistakes users might make (if any).
    * A summary of the file's overall function (for this first part).

2. **Initial Scan and Identification of Key Structures:** I quickly scan the provided code and identify the main structures:
    * `fileTest` struct:  This clearly defines a test case, holding information about an ELF file, its headers, sections, program headers, needed libraries, and symbols. This is the core of the test setup.
    * `fileTests` slice:  This slice contains multiple `fileTest` instances, implying the code tests against various ELF files.
    * `TestOpen` function:  This is a standard Go testing function, strongly suggesting that the primary function being tested is the `Open` function (or a related function like `NewFile`) in the `debug/elf` package.
    * `decompress` function: This function handles decompression of gzipped files, which are among the test data.
    * `relocationTestEntry` and `relocationTest` structs, and `relocationTests` slice:  These suggest a second area of testing related to ELF relocations and DWARF debugging information.

3. **Focus on `TestOpen` (The Obvious Core Functionality):**  The `TestOpen` function iterates through the `fileTests`. For each test case, it attempts to open the specified ELF file (handling gzipped files via `decompress`). Then, it performs a series of checks:
    * **File Header Comparison:**  It compares the `FileHeader` read from the file with the expected header defined in the `fileTest` struct.
    * **Section Header Comparison:** It compares the `SectionHeader` array.
    * **Program Header Comparison:** It compares the `ProgHeader` array.
    * **Section and Program Header Lengths:** It verifies the number of sections and program headers matches expectations.
    * **Imported Libraries (DT_NEEDED):** It uses `f.ImportedLibraries()` to get the dynamically linked libraries and compares them.
    * **Symbols:** It calls `f.Symbols()` and checks for the expected symbols or the `ErrNoSymbols` error.

4. **Inferring the Tested Go Feature:** Based on the focus of `TestOpen` and the structures involved (especially `FileHeader`, `SectionHeader`, `ProgHeader`), it's clear the code is testing the functionality of the `debug/elf` package to **parse and read ELF (Executable and Linkable Format) files**.

5. **Providing Code Examples (Based on Inference):** To illustrate the `debug/elf` package usage, I construct a simple example: opening an ELF file and accessing its header, sections, and program headers. This directly reflects the actions in `TestOpen`.

6. **Reasoning About Code (Input/Output):** I explain the logic of `TestOpen`, pointing out that the `fileTests` slice provides the expected input and output. I specifically mention how the test cases are structured and what aspects of the ELF file are being validated.

7. **Command-Line Arguments:** I observe that the provided code doesn't explicitly handle command-line arguments. The test cases are hardcoded in the `fileTests` slice. So, I state that command-line argument handling isn't a primary focus here.

8. **Common Mistakes:**  I consider potential issues when using the `debug/elf` package:
    * **Incorrect File Path:**  A fundamental mistake.
    * **Handling Errors:**  Forgetting to check errors after opening the file or calling other functions.
    * **Assumptions About ELF Structure:**  Assuming a specific structure without proper validation.

9. **Summarizing the Functionality (for Part 1):**  For this first part, I focus on the core functionality evident in `TestOpen`: reading and parsing ELF files. I mention the validation of headers, sections, program headers, and imported libraries. I explicitly exclude the relocation testing for now, as the prompt indicates this is part 1.

10. **Review and Refine:** I reread my answer to ensure clarity, accuracy, and completeness, addressing all parts of the prompt. I check that the code examples are valid and easy to understand.

By following this structured approach, I can break down the provided code, understand its purpose, and generate a comprehensive answer that addresses all the requirements of the prompt. The key is to identify the core testing logic and connect it back to the underlying Go library being examined.
## 对 go/src/debug/elf/file_test.go (第1部分) 的功能归纳

这个Go语言源文件 `go/src/debug/elf/file_test.go` 的主要功能是**测试 `debug/elf` 标准库中用于解析和读取 ELF (Executable and Linkable Format) 文件的相关功能**。

具体来说，这部分代码主要关注以下几点：

1. **测试 ELF 文件的打开和基本信息读取:**
   -  它定义了一个名为 `fileTest` 的结构体，用于描述一个测试用的 ELF 文件及其预期的头部信息 (`FileHeader`)、节区头部信息 (`SectionHeader`)、程序头部信息 (`ProgHeader`)、依赖的动态链接库 (`needed`) 和符号表 (`symbols`)。
   -  它定义了一个名为 `fileTests` 的 `fileTest` 结构体切片，包含了多个预先准备好的 ELF 测试文件及其对应的预期数据。这些测试文件涵盖了不同的架构（386, amd64）、操作系统（FreeBSD, Linux）、文件类型（可执行文件, core dump, 目标文件）以及压缩状态 (gzip)。
   -  `TestOpen` 函数是这部分测试的核心。它遍历 `fileTests` 中的每一个测试用例：
     -  尝试打开对应的 ELF 文件，如果文件是 gzip 压缩的，会先使用 `decompress` 函数解压。
     -  读取打开的 ELF 文件的头部信息 (`f.FileHeader`)，并与预期的头部信息 (`tt.hdr`) 进行比对。
     -  遍历读取到的节区头部信息 (`f.Sections`) 和程序头部信息 (`f.Progs`)，并与预期的信息 (`tt.sections`, `tt.progs`) 进行逐一比对。
     -  检查读取到的节区和程序头部的数量是否与预期一致。
     -  调用 `f.ImportedLibraries()` 函数，获取该 ELF 文件依赖的动态链接库，并与预期的依赖库列表 (`tt.needed`) 进行比对。
     -  调用 `f.Symbols()` 函数，尝试读取 ELF 文件的符号表，并根据测试用例的预期，检查是否成功读取符号表或返回预期的错误 (`ErrNoSymbols`)，并比对读取到的符号表内容。

2. **提供了解压 gzip 压缩 ELF 文件的辅助函数:**
   -  `decompress` 函数用于解压 gzip 压缩的 ELF 文件。它接收一个文件路径作为参数，打开文件，使用 `gzip.NewReader` 创建 gzip 解压读取器，然后将解压后的内容写入 `bytes.Buffer`，最后返回一个 `bytes.Reader`，使其满足 `elf.NewFile` 函数的 `io.ReaderAt` 接口要求。

**可以推断出，这部分代码主要在测试 `debug/elf` 包中以下 Go 语言功能的实现：**

- **`Open(name string) (*File, error)`:**  用于打开一个 ELF 文件。
- **`NewFile(r io.ReaderAt) (*File, error)`:**  用于从一个 `io.ReaderAt` 接口读取 ELF 文件信息。
- **`File` 结构体及其字段:**  用于存储 ELF 文件的头部、节区、程序头部等信息。
- **`FileHeader` 结构体:**  用于表示 ELF 文件头部的结构。
- **`SectionHeader` 结构体:**  用于表示 ELF 文件节区头部的结构。
- **`ProgHeader` 结构体:**  用于表示 ELF 文件程序头部的结构。
- **`(*File) ImportedLibraries() ([]string, error)`:**  用于获取 ELF 文件依赖的动态链接库。
- **`(*File) Symbols() ([]Symbol, error)`:**  用于获取 ELF 文件的符号表。
- **错误处理，例如 `ErrNoSymbols`:**  用于表示 ELF 文件没有符号表的情况。

**Go 代码举例说明 (基于推断的功能):**

假设我们有一个名为 `test.elf` 的 ELF 文件，我们可以使用 `debug/elf` 包来读取它的基本信息：

```go
package main

import (
	"debug/elf"
	"fmt"
	"log"
	"os"
)

func main() {
	f, err := elf.Open("test.elf")
	if err != nil {
		log.Fatalf("failed to open ELF file: %v", err)
	}
	defer f.Close()

	fmt.Printf("ELF Header: %+v\n", f.FileHeader)

	fmt.Println("\nSection Headers:")
	for _, section := range f.Sections {
		fmt.Printf("%+v\n", section.SectionHeader)
	}

	fmt.Println("\nProgram Headers:")
	for _, prog := range f.Progs {
		fmt.Printf("%+v\n", prog.ProgHeader)
	}

	libs, err := f.ImportedLibraries()
	if err != nil {
		fmt.Printf("Error getting imported libraries: %v\n", err)
	} else {
		fmt.Printf("\nImported Libraries: %v\n", libs)
	}

	symbols, err := f.Symbols()
	if err != nil {
		fmt.Printf("Error getting symbols: %v\n", err)
	} else {
		fmt.Println("\nSymbols:")
		for _, sym := range symbols {
			fmt.Printf("%+v\n", sym)
		}
	}
}
```

**假设的输入与输出:**

假设 `test.elf` 是一个简单的可执行文件，其头部信息、节区、程序头部、依赖库和符号表与 `fileTests` 中的某个条目相似。运行上面的代码，输出将包含类似以下的结构化信息：

```
ELF Header: {Class:1 Data:1 Version:1 OSABI:0 ABIVersion:0 ByteOrder:LittleEndian Type:2 Machine:3 Entry:134513868}

Section Headers:
{Name: Off:0 Addr:0 Size:0 Type:0 Flags:0 Link:0 Info:0 Addralign:0 Entsize:0}
{Name:.interp Off:132 Addr:134512852 Size:21 Type:3 Flags:2 Link:0 Info:0 Addralign:1 Entsize:0}
... (更多节区头部信息)

Program Headers:
{Type:6 Flags:5 Off:52 Vaddr:134512852 Paddr:134512852 Filesz:160 Memsz:160 Align:4}
{Type:3 Flags:4 Off:212 Vaddr:134512980 Paddr:134512980 Filesz:21 Memsz:21 Align:1}
... (更多程序头部信息)

Imported Libraries: [libc.so.6]

Symbols:
{Name: Offset:0 Info:3 Other:0 Section:1 Value:134512852 Size:0}
{Name: Offset:0 Info:3 Other:0 Section:2 Value:134512876 Size:0}
... (更多符号信息)
```

**命令行参数的具体处理:**

在这部分代码中，并没有涉及到命令行参数的具体处理。测试用例中使用的 ELF 文件路径是硬编码在 `fileTests` 变量中的。

**使用者易犯错的点:**

一个使用 `debug/elf` 包时容易犯的错误是**假设所有 ELF 文件都具有相同的结构或包含特定的节区或程序头部**。例如，一些工具可能依赖于符号表的存在，但并非所有 ELF 文件（例如 stripped 的二进制文件或某些目标文件）都包含符号表。

```go
package main

import (
	"debug/elf"
	"fmt"
	"log"
)

func main() {
	f, err := elf.Open("stripped.elf") // 假设 stripped.elf 没有符号表
	if err != nil {
		log.Fatalf("failed to open ELF file: %v", err)
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err != nil {
		// 易错点：直接假设 err 为 nil，而没有处理 ErrNoSymbols
		fmt.Printf("Error getting symbols: %v\n", err) // 可能会输出 "ELF file has no symbol table"
	} else {
		fmt.Println("Symbols:")
		for _, sym := range symbols {
			fmt.Printf("%+v\n", sym)
		}
	}
}
```

正确的做法是检查错误类型，例如使用 `errors.Is(err, elf.ErrNoSymbols)` 来判断是否是因为没有符号表而导致的错误。

**功能归纳 (针对第 1 部分):**

总而言之，`go/src/debug/elf/file_test.go` 的第 1 部分主要功能是**通过一系列预定义的测试用例，验证 `debug/elf` 包能够正确地打开和解析不同类型和架构的 ELF 文件，并能准确地读取其头部信息、节区信息、程序头部信息、依赖的动态链接库以及符号表信息。** 这部分测试重点在于 `Open` 和 `NewFile` 函数的基础功能以及对 ELF 文件基本结构的解析能力。

Prompt: 
```
这是路径为go/src/debug/elf/file_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package elf

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"debug/dwarf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type fileTest struct {
	file     string
	hdr      FileHeader
	sections []SectionHeader
	progs    []ProgHeader
	needed   []string
	symbols  []Symbol
}

var fileTests = []fileTest{
	{
		"testdata/gcc-386-freebsd-exec",
		FileHeader{ELFCLASS32, ELFDATA2LSB, EV_CURRENT, ELFOSABI_FREEBSD, 0, binary.LittleEndian, ET_EXEC, EM_386, 0x80483cc},
		[]SectionHeader{
			{"", SHT_NULL, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			{".interp", SHT_PROGBITS, SHF_ALLOC, 0x80480d4, 0xd4, 0x15, 0x0, 0x0, 0x1, 0x0, 0x15},
			{".hash", SHT_HASH, SHF_ALLOC, 0x80480ec, 0xec, 0x90, 0x3, 0x0, 0x4, 0x4, 0x90},
			{".dynsym", SHT_DYNSYM, SHF_ALLOC, 0x804817c, 0x17c, 0x110, 0x4, 0x1, 0x4, 0x10, 0x110},
			{".dynstr", SHT_STRTAB, SHF_ALLOC, 0x804828c, 0x28c, 0xbb, 0x0, 0x0, 0x1, 0x0, 0xbb},
			{".rel.plt", SHT_REL, SHF_ALLOC, 0x8048348, 0x348, 0x20, 0x3, 0x7, 0x4, 0x8, 0x20},
			{".init", SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR, 0x8048368, 0x368, 0x11, 0x0, 0x0, 0x4, 0x0, 0x11},
			{".plt", SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR, 0x804837c, 0x37c, 0x50, 0x0, 0x0, 0x4, 0x4, 0x50},
			{".text", SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR, 0x80483cc, 0x3cc, 0x180, 0x0, 0x0, 0x4, 0x0, 0x180},
			{".fini", SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR, 0x804854c, 0x54c, 0xc, 0x0, 0x0, 0x4, 0x0, 0xc},
			{".rodata", SHT_PROGBITS, SHF_ALLOC, 0x8048558, 0x558, 0xa3, 0x0, 0x0, 0x1, 0x0, 0xa3},
			{".data", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x80495fc, 0x5fc, 0xc, 0x0, 0x0, 0x4, 0x0, 0xc},
			{".eh_frame", SHT_PROGBITS, SHF_ALLOC, 0x8049608, 0x608, 0x4, 0x0, 0x0, 0x4, 0x0, 0x4},
			{".dynamic", SHT_DYNAMIC, SHF_WRITE + SHF_ALLOC, 0x804960c, 0x60c, 0x98, 0x4, 0x0, 0x4, 0x8, 0x98},
			{".ctors", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x80496a4, 0x6a4, 0x8, 0x0, 0x0, 0x4, 0x0, 0x8},
			{".dtors", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x80496ac, 0x6ac, 0x8, 0x0, 0x0, 0x4, 0x0, 0x8},
			{".jcr", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x80496b4, 0x6b4, 0x4, 0x0, 0x0, 0x4, 0x0, 0x4},
			{".got", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x80496b8, 0x6b8, 0x1c, 0x0, 0x0, 0x4, 0x4, 0x1c},
			{".bss", SHT_NOBITS, SHF_WRITE + SHF_ALLOC, 0x80496d4, 0x6d4, 0x20, 0x0, 0x0, 0x4, 0x0, 0x20},
			{".comment", SHT_PROGBITS, 0x0, 0x0, 0x6d4, 0x12d, 0x0, 0x0, 0x1, 0x0, 0x12d},
			{".debug_aranges", SHT_PROGBITS, 0x0, 0x0, 0x801, 0x20, 0x0, 0x0, 0x1, 0x0, 0x20},
			{".debug_pubnames", SHT_PROGBITS, 0x0, 0x0, 0x821, 0x1b, 0x0, 0x0, 0x1, 0x0, 0x1b},
			{".debug_info", SHT_PROGBITS, 0x0, 0x0, 0x83c, 0x11d, 0x0, 0x0, 0x1, 0x0, 0x11d},
			{".debug_abbrev", SHT_PROGBITS, 0x0, 0x0, 0x959, 0x41, 0x0, 0x0, 0x1, 0x0, 0x41},
			{".debug_line", SHT_PROGBITS, 0x0, 0x0, 0x99a, 0x35, 0x0, 0x0, 0x1, 0x0, 0x35},
			{".debug_frame", SHT_PROGBITS, 0x0, 0x0, 0x9d0, 0x30, 0x0, 0x0, 0x4, 0x0, 0x30},
			{".debug_str", SHT_PROGBITS, 0x0, 0x0, 0xa00, 0xd, 0x0, 0x0, 0x1, 0x0, 0xd},
			{".shstrtab", SHT_STRTAB, 0x0, 0x0, 0xa0d, 0xf8, 0x0, 0x0, 0x1, 0x0, 0xf8},
			{".symtab", SHT_SYMTAB, 0x0, 0x0, 0xfb8, 0x4b0, 0x1d, 0x38, 0x4, 0x10, 0x4b0},
			{".strtab", SHT_STRTAB, 0x0, 0x0, 0x1468, 0x206, 0x0, 0x0, 0x1, 0x0, 0x206},
		},
		[]ProgHeader{
			{PT_PHDR, PF_R + PF_X, 0x34, 0x8048034, 0x8048034, 0xa0, 0xa0, 0x4},
			{PT_INTERP, PF_R, 0xd4, 0x80480d4, 0x80480d4, 0x15, 0x15, 0x1},
			{PT_LOAD, PF_R + PF_X, 0x0, 0x8048000, 0x8048000, 0x5fb, 0x5fb, 0x1000},
			{PT_LOAD, PF_R + PF_W, 0x5fc, 0x80495fc, 0x80495fc, 0xd8, 0xf8, 0x1000},
			{PT_DYNAMIC, PF_R + PF_W, 0x60c, 0x804960c, 0x804960c, 0x98, 0x98, 0x4},
		},
		[]string{"libc.so.6"},
		[]Symbol{
			{"", 3, 0, false, 0, 1, 134512852, 0, "", ""},
			{"", 3, 0, false, 0, 2, 134512876, 0, "", ""},
			{"", 3, 0, false, 0, 3, 134513020, 0, "", ""},
			{"", 3, 0, false, 0, 4, 134513292, 0, "", ""},
			{"", 3, 0, false, 0, 5, 134513480, 0, "", ""},
			{"", 3, 0, false, 0, 6, 134513512, 0, "", ""},
			{"", 3, 0, false, 0, 7, 134513532, 0, "", ""},
			{"", 3, 0, false, 0, 8, 134513612, 0, "", ""},
			{"", 3, 0, false, 0, 9, 134513996, 0, "", ""},
			{"", 3, 0, false, 0, 10, 134514008, 0, "", ""},
			{"", 3, 0, false, 0, 11, 134518268, 0, "", ""},
			{"", 3, 0, false, 0, 12, 134518280, 0, "", ""},
			{"", 3, 0, false, 0, 13, 134518284, 0, "", ""},
			{"", 3, 0, false, 0, 14, 134518436, 0, "", ""},
			{"", 3, 0, false, 0, 15, 134518444, 0, "", ""},
			{"", 3, 0, false, 0, 16, 134518452, 0, "", ""},
			{"", 3, 0, false, 0, 17, 134518456, 0, "", ""},
			{"", 3, 0, false, 0, 18, 134518484, 0, "", ""},
			{"", 3, 0, false, 0, 19, 0, 0, "", ""},
			{"", 3, 0, false, 0, 20, 0, 0, "", ""},
			{"", 3, 0, false, 0, 21, 0, 0, "", ""},
			{"", 3, 0, false, 0, 22, 0, 0, "", ""},
			{"", 3, 0, false, 0, 23, 0, 0, "", ""},
			{"", 3, 0, false, 0, 24, 0, 0, "", ""},
			{"", 3, 0, false, 0, 25, 0, 0, "", ""},
			{"", 3, 0, false, 0, 26, 0, 0, "", ""},
			{"", 3, 0, false, 0, 27, 0, 0, "", ""},
			{"", 3, 0, false, 0, 28, 0, 0, "", ""},
			{"", 3, 0, false, 0, 29, 0, 0, "", ""},
			{"crt1.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"/usr/src/lib/csu/i386-elf/crti.S", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"<command line>", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"<built-in>", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"/usr/src/lib/csu/i386-elf/crti.S", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"crtstuff.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"__CTOR_LIST__", 1, 0, false, 0, 14, 134518436, 0, "", ""},
			{"__DTOR_LIST__", 1, 0, false, 0, 15, 134518444, 0, "", ""},
			{"__EH_FRAME_BEGIN__", 1, 0, false, 0, 12, 134518280, 0, "", ""},
			{"__JCR_LIST__", 1, 0, false, 0, 16, 134518452, 0, "", ""},
			{"p.0", 1, 0, false, 0, 11, 134518276, 0, "", ""},
			{"completed.1", 1, 0, false, 0, 18, 134518484, 1, "", ""},
			{"__do_global_dtors_aux", 2, 0, false, 0, 8, 134513760, 0, "", ""},
			{"object.2", 1, 0, false, 0, 18, 134518488, 24, "", ""},
			{"frame_dummy", 2, 0, false, 0, 8, 134513836, 0, "", ""},
			{"crtstuff.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"__CTOR_END__", 1, 0, false, 0, 14, 134518440, 0, "", ""},
			{"__DTOR_END__", 1, 0, false, 0, 15, 134518448, 0, "", ""},
			{"__FRAME_END__", 1, 0, false, 0, 12, 134518280, 0, "", ""},
			{"__JCR_END__", 1, 0, false, 0, 16, 134518452, 0, "", ""},
			{"__do_global_ctors_aux", 2, 0, false, 0, 8, 134513960, 0, "", ""},
			{"/usr/src/lib/csu/i386-elf/crtn.S", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"<command line>", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"<built-in>", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"/usr/src/lib/csu/i386-elf/crtn.S", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"hello.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"printf", 18, 0, false, 0, 0, 0, 44, "", ""},
			{"_DYNAMIC", 17, 0, false, 0, 65521, 134518284, 0, "", ""},
			{"__dso_handle", 17, 2, false, 0, 11, 134518272, 0, "", ""},
			{"_init", 18, 0, false, 0, 6, 134513512, 0, "", ""},
			{"environ", 17, 0, false, 0, 18, 134518512, 4, "", ""},
			{"__deregister_frame_info", 32, 0, false, 0, 0, 0, 0, "", ""},
			{"__progname", 17, 0, false, 0, 11, 134518268, 4, "", ""},
			{"_start", 18, 0, false, 0, 8, 134513612, 145, "", ""},
			{"__bss_start", 16, 0, false, 0, 65521, 134518484, 0, "", ""},
			{"main", 18, 0, false, 0, 8, 134513912, 46, "", ""},
			{"_init_tls", 18, 0, false, 0, 0, 0, 5, "", ""},
			{"_fini", 18, 0, false, 0, 9, 134513996, 0, "", ""},
			{"atexit", 18, 0, false, 0, 0, 0, 43, "", ""},
			{"_edata", 16, 0, false, 0, 65521, 134518484, 0, "", ""},
			{"_GLOBAL_OFFSET_TABLE_", 17, 0, false, 0, 65521, 134518456, 0, "", ""},
			{"_end", 16, 0, false, 0, 65521, 134518516, 0, "", ""},
			{"exit", 18, 0, false, 0, 0, 0, 68, "", ""},
			{"_Jv_RegisterClasses", 32, 0, false, 0, 0, 0, 0, "", ""},
			{"__register_frame_info", 32, 0, false, 0, 0, 0, 0, "", ""},
		},
	},
	{
		"testdata/gcc-amd64-linux-exec",
		FileHeader{ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE, 0, binary.LittleEndian, ET_EXEC, EM_X86_64, 0x4003e0},
		[]SectionHeader{
			{"", SHT_NULL, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			{".interp", SHT_PROGBITS, SHF_ALLOC, 0x400200, 0x200, 0x1c, 0x0, 0x0, 0x1, 0x0, 0x1c},
			{".note.ABI-tag", SHT_NOTE, SHF_ALLOC, 0x40021c, 0x21c, 0x20, 0x0, 0x0, 0x4, 0x0, 0x20},
			{".hash", SHT_HASH, SHF_ALLOC, 0x400240, 0x240, 0x24, 0x5, 0x0, 0x8, 0x4, 0x24},
			{".gnu.hash", SHT_LOOS + 268435446, SHF_ALLOC, 0x400268, 0x268, 0x1c, 0x5, 0x0, 0x8, 0x0, 0x1c},
			{".dynsym", SHT_DYNSYM, SHF_ALLOC, 0x400288, 0x288, 0x60, 0x6, 0x1, 0x8, 0x18, 0x60},
			{".dynstr", SHT_STRTAB, SHF_ALLOC, 0x4002e8, 0x2e8, 0x3d, 0x0, 0x0, 0x1, 0x0, 0x3d},
			{".gnu.version", SHT_HIOS, SHF_ALLOC, 0x400326, 0x326, 0x8, 0x5, 0x0, 0x2, 0x2, 0x8},
			{".gnu.version_r", SHT_LOOS + 268435454, SHF_ALLOC, 0x400330, 0x330, 0x20, 0x6, 0x1, 0x8, 0x0, 0x20},
			{".rela.dyn", SHT_RELA, SHF_ALLOC, 0x400350, 0x350, 0x18, 0x5, 0x0, 0x8, 0x18, 0x18},
			{".rela.plt", SHT_RELA, SHF_ALLOC, 0x400368, 0x368, 0x30, 0x5, 0xc, 0x8, 0x18, 0x30},
			{".init", SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR, 0x400398, 0x398, 0x18, 0x0, 0x0, 0x4, 0x0, 0x18},
			{".plt", SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR, 0x4003b0, 0x3b0, 0x30, 0x0, 0x0, 0x4, 0x10, 0x30},
			{".text", SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR, 0x4003e0, 0x3e0, 0x1b4, 0x0, 0x0, 0x10, 0x0, 0x1b4},
			{".fini", SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR, 0x400594, 0x594, 0xe, 0x0, 0x0, 0x4, 0x0, 0xe},
			{".rodata", SHT_PROGBITS, SHF_ALLOC, 0x4005a4, 0x5a4, 0x11, 0x0, 0x0, 0x4, 0x0, 0x11},
			{".eh_frame_hdr", SHT_PROGBITS, SHF_ALLOC, 0x4005b8, 0x5b8, 0x24, 0x0, 0x0, 0x4, 0x0, 0x24},
			{".eh_frame", SHT_PROGBITS, SHF_ALLOC, 0x4005e0, 0x5e0, 0xa4, 0x0, 0x0, 0x8, 0x0, 0xa4},
			{".ctors", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x600688, 0x688, 0x10, 0x0, 0x0, 0x8, 0x0, 0x10},
			{".dtors", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x600698, 0x698, 0x10, 0x0, 0x0, 0x8, 0x0, 0x10},
			{".jcr", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x6006a8, 0x6a8, 0x8, 0x0, 0x0, 0x8, 0x0, 0x8},
			{".dynamic", SHT_DYNAMIC, SHF_WRITE + SHF_ALLOC, 0x6006b0, 0x6b0, 0x1a0, 0x6, 0x0, 0x8, 0x10, 0x1a0},
			{".got", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x600850, 0x850, 0x8, 0x0, 0x0, 0x8, 0x8, 0x8},
			{".got.plt", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x600858, 0x858, 0x28, 0x0, 0x0, 0x8, 0x8, 0x28},
			{".data", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x600880, 0x880, 0x18, 0x0, 0x0, 0x8, 0x0, 0x18},
			{".bss", SHT_NOBITS, SHF_WRITE + SHF_ALLOC, 0x600898, 0x898, 0x8, 0x0, 0x0, 0x4, 0x0, 0x8},
			{".comment", SHT_PROGBITS, 0x0, 0x0, 0x898, 0x126, 0x0, 0x0, 0x1, 0x0, 0x126},
			{".debug_aranges", SHT_PROGBITS, 0x0, 0x0, 0x9c0, 0x90, 0x0, 0x0, 0x10, 0x0, 0x90},
			{".debug_pubnames", SHT_PROGBITS, 0x0, 0x0, 0xa50, 0x25, 0x0, 0x0, 0x1, 0x0, 0x25},
			{".debug_info", SHT_PROGBITS, 0x0, 0x0, 0xa75, 0x1a7, 0x0, 0x0, 0x1, 0x0, 0x1a7},
			{".debug_abbrev", SHT_PROGBITS, 0x0, 0x0, 0xc1c, 0x6f, 0x0, 0x0, 0x1, 0x0, 0x6f},
			{".debug_line", SHT_PROGBITS, 0x0, 0x0, 0xc8b, 0x13f, 0x0, 0x0, 0x1, 0x0, 0x13f},
			{".debug_str", SHT_PROGBITS, SHF_MERGE + SHF_STRINGS, 0x0, 0xdca, 0xb1, 0x0, 0x0, 0x1, 0x1, 0xb1},
			{".debug_ranges", SHT_PROGBITS, 0x0, 0x0, 0xe80, 0x90, 0x0, 0x0, 0x10, 0x0, 0x90},
			{".shstrtab", SHT_STRTAB, 0x0, 0x0, 0xf10, 0x149, 0x0, 0x0, 0x1, 0x0, 0x149},
			{".symtab", SHT_SYMTAB, 0x0, 0x0, 0x19a0, 0x6f0, 0x24, 0x39, 0x8, 0x18, 0x6f0},
			{".strtab", SHT_STRTAB, 0x0, 0x0, 0x2090, 0x1fc, 0x0, 0x0, 0x1, 0x0, 0x1fc},
		},
		[]ProgHeader{
			{PT_PHDR, PF_R + PF_X, 0x40, 0x400040, 0x400040, 0x1c0, 0x1c0, 0x8},
			{PT_INTERP, PF_R, 0x200, 0x400200, 0x400200, 0x1c, 0x1c, 1},
			{PT_LOAD, PF_R + PF_X, 0x0, 0x400000, 0x400000, 0x684, 0x684, 0x200000},
			{PT_LOAD, PF_R + PF_W, 0x688, 0x600688, 0x600688, 0x210, 0x218, 0x200000},
			{PT_DYNAMIC, PF_R + PF_W, 0x6b0, 0x6006b0, 0x6006b0, 0x1a0, 0x1a0, 0x8},
			{PT_NOTE, PF_R, 0x21c, 0x40021c, 0x40021c, 0x20, 0x20, 0x4},
			{PT_LOOS + 0x474E550, PF_R, 0x5b8, 0x4005b8, 0x4005b8, 0x24, 0x24, 0x4},
			{PT_LOOS + 0x474E551, PF_R + PF_W, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8},
		},
		[]string{"libc.so.6"},
		[]Symbol{
			{"", 3, 0, false, 0, 1, 4194816, 0, "", ""},
			{"", 3, 0, false, 0, 2, 4194844, 0, "", ""},
			{"", 3, 0, false, 0, 3, 4194880, 0, "", ""},
			{"", 3, 0, false, 0, 4, 4194920, 0, "", ""},
			{"", 3, 0, false, 0, 5, 4194952, 0, "", ""},
			{"", 3, 0, false, 0, 6, 4195048, 0, "", ""},
			{"", 3, 0, false, 0, 7, 4195110, 0, "", ""},
			{"", 3, 0, false, 0, 8, 4195120, 0, "", ""},
			{"", 3, 0, false, 0, 9, 4195152, 0, "", ""},
			{"", 3, 0, false, 0, 10, 4195176, 0, "", ""},
			{"", 3, 0, false, 0, 11, 4195224, 0, "", ""},
			{"", 3, 0, false, 0, 12, 4195248, 0, "", ""},
			{"", 3, 0, false, 0, 13, 4195296, 0, "", ""},
			{"", 3, 0, false, 0, 14, 4195732, 0, "", ""},
			{"", 3, 0, false, 0, 15, 4195748, 0, "", ""},
			{"", 3, 0, false, 0, 16, 4195768, 0, "", ""},
			{"", 3, 0, false, 0, 17, 4195808, 0, "", ""},
			{"", 3, 0, false, 0, 18, 6293128, 0, "", ""},
			{"", 3, 0, false, 0, 19, 6293144, 0, "", ""},
			{"", 3, 0, false, 0, 20, 6293160, 0, "", ""},
			{"", 3, 0, false, 0, 21, 6293168, 0, "", ""},
			{"", 3, 0, false, 0, 22, 6293584, 0, "", ""},
			{"", 3, 0, false, 0, 23, 6293592, 0, "", ""},
			{"", 3, 0, false, 0, 24, 6293632, 0, "", ""},
			{"", 3, 0, false, 0, 25, 6293656, 0, "", ""},
			{"", 3, 0, false, 0, 26, 0, 0, "", ""},
			{"", 3, 0, false, 0, 27, 0, 0, "", ""},
			{"", 3, 0, false, 0, 28, 0, 0, "", ""},
			{"", 3, 0, false, 0, 29, 0, 0, "", ""},
			{"", 3, 0, false, 0, 30, 0, 0, "", ""},
			{"", 3, 0, false, 0, 31, 0, 0, "", ""},
			{"", 3, 0, false, 0, 32, 0, 0, "", ""},
			{"", 3, 0, false, 0, 33, 0, 0, "", ""},
			{"init.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"initfini.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"call_gmon_start", 2, 0, false, 0, 13, 4195340, 0, "", ""},
			{"crtstuff.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"__CTOR_LIST__", 1, 0, false, 0, 18, 6293128, 0, "", ""},
			{"__DTOR_LIST__", 1, 0, false, 0, 19, 6293144, 0, "", ""},
			{"__JCR_LIST__", 1, 0, false, 0, 20, 6293160, 0, "", ""},
			{"__do_global_dtors_aux", 2, 0, false, 0, 13, 4195376, 0, "", ""},
			{"completed.6183", 1, 0, false, 0, 25, 6293656, 1, "", ""},
			{"p.6181", 1, 0, false, 0, 24, 6293648, 0, "", ""},
			{"frame_dummy", 2, 0, false, 0, 13, 4195440, 0, "", ""},
			{"crtstuff.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"__CTOR_END__", 1, 0, false, 0, 18, 6293136, 0, "", ""},
			{"__DTOR_END__", 1, 0, false, 0, 19, 6293152, 0, "", ""},
			{"__FRAME_END__", 1, 0, false, 0, 17, 4195968, 0, "", ""},
			{"__JCR_END__", 1, 0, false, 0, 20, 6293160, 0, "", ""},
			{"__do_global_ctors_aux", 2, 0, false, 0, 13, 4195680, 0, "", ""},
			{"initfini.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"hello.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"_GLOBAL_OFFSET_TABLE_", 1, 2, false, 0, 23, 6293592, 0, "", ""},
			{"__init_array_end", 0, 2, false, 0, 18, 6293124, 0, "", ""},
			{"__init_array_start", 0, 2, false, 0, 18, 6293124, 0, "", ""},
			{"_DYNAMIC", 1, 2, false, 0, 21, 6293168, 0, "", ""},
			{"data_start", 32, 0, false, 0, 24, 6293632, 0, "", ""},
			{"__libc_csu_fini", 18, 0, false, 0, 13, 4195520, 2, "", ""},
			{"_start", 18, 0, false, 0, 13, 4195296, 0, "", ""},
			{"__gmon_start__", 32, 0, false, 0, 0, 0, 0, "", ""},
			{"_Jv_RegisterClasses", 32, 0, false, 0, 0, 0, 0, "", ""},
			{"puts@@GLIBC_2.2.5", 18, 0, false, 0, 0, 0, 396, "", ""},
			{"_fini", 18, 0, false, 0, 14, 4195732, 0, "", ""},
			{"__libc_start_main@@GLIBC_2.2.5", 18, 0, false, 0, 0, 0, 450, "", ""},
			{"_IO_stdin_used", 17, 0, false, 0, 15, 4195748, 4, "", ""},
			{"__data_start", 16, 0, false, 0, 24, 6293632, 0, "", ""},
			{"__dso_handle", 17, 2, false, 0, 24, 6293640, 0, "", ""},
			{"__libc_csu_init", 18, 0, false, 0, 13, 4195536, 137, "", ""},
			{"__bss_start", 16, 0, false, 0, 65521, 6293656, 0, "", ""},
			{"_end", 16, 0, false, 0, 65521, 6293664, 0, "", ""},
			{"_edata", 16, 0, false, 0, 65521, 6293656, 0, "", ""},
			{"main", 18, 0, false, 0, 13, 4195480, 27, "", ""},
			{"_init", 18, 0, false, 0, 11, 4195224, 0, "", ""},
		},
	},
	{
		"testdata/hello-world-core.gz",
		FileHeader{ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE, 0x0, binary.LittleEndian, ET_CORE, EM_X86_64, 0x0},
		[]SectionHeader{},
		[]ProgHeader{
			{Type: PT_NOTE, Flags: 0x0, Off: 0x3f8, Vaddr: 0x0, Paddr: 0x0, Filesz: 0x8ac, Memsz: 0x0, Align: 0x0},
			{Type: PT_LOAD, Flags: PF_X + PF_R, Off: 0x1000, Vaddr: 0x400000, Paddr: 0x0, Filesz: 0x0, Memsz: 0x1000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_R, Off: 0x1000, Vaddr: 0x401000, Paddr: 0x0, Filesz: 0x1000, Memsz: 0x1000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_W + PF_R, Off: 0x2000, Vaddr: 0x402000, Paddr: 0x0, Filesz: 0x1000, Memsz: 0x1000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_X + PF_R, Off: 0x3000, Vaddr: 0x7f54078b8000, Paddr: 0x0, Filesz: 0x0, Memsz: 0x1b5000, Align: 0x1000},
			{Type: PT_LOAD, Flags: 0x0, Off: 0x3000, Vaddr: 0x7f5407a6d000, Paddr: 0x0, Filesz: 0x0, Memsz: 0x1ff000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_R, Off: 0x3000, Vaddr: 0x7f5407c6c000, Paddr: 0x0, Filesz: 0x4000, Memsz: 0x4000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_W + PF_R, Off: 0x7000, Vaddr: 0x7f5407c70000, Paddr: 0x0, Filesz: 0x2000, Memsz: 0x2000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_W + PF_R, Off: 0x9000, Vaddr: 0x7f5407c72000, Paddr: 0x0, Filesz: 0x5000, Memsz: 0x5000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_X + PF_R, Off: 0xe000, Vaddr: 0x7f5407c77000, Paddr: 0x0, Filesz: 0x0, Memsz: 0x22000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_W + PF_R, Off: 0xe000, Vaddr: 0x7f5407e81000, Paddr: 0x0, Filesz: 0x3000, Memsz: 0x3000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_W + PF_R, Off: 0x11000, Vaddr: 0x7f5407e96000, Paddr: 0x0, Filesz: 0x3000, Memsz: 0x3000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_R, Off: 0x14000, Vaddr: 0x7f5407e99000, Paddr: 0x0, Filesz: 0x1000, Memsz: 0x1000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_W + PF_R, Off: 0x15000, Vaddr: 0x7f5407e9a000, Paddr: 0x0, Filesz: 0x2000, Memsz: 0x2000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_W + PF_R, Off: 0x17000, Vaddr: 0x7fff79972000, Paddr: 0x0, Filesz: 0x23000, Memsz: 0x23000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_X + PF_R, Off: 0x3a000, Vaddr: 0x7fff799f8000, Paddr: 0x0, Filesz: 0x1000, Memsz: 0x1000, Align: 0x1000},
			{Type: PT_LOAD, Flags: PF_X + PF_R, Off: 0x3b000, Vaddr: 0xffffffffff600000, Paddr: 0x0, Filesz: 0x1000, Memsz: 0x1000, Align: 0x1000},
		},
		nil,
		nil,
	},
	{
		"testdata/compressed-32.obj",
		FileHeader{ELFCLASS32, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE, 0x0, binary.LittleEndian, ET_REL, EM_386, 0x0},
		[]SectionHeader{
			{"", SHT_NULL, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			{".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0x0, 0x34, 0x17, 0x0, 0x0, 0x1, 0x0, 0x17},
			{".rel.text", SHT_REL, SHF_INFO_LINK, 0x0, 0x3dc, 0x10, 0x13, 0x1, 0x4, 0x8, 0x10},
			{".data", SHT_PROGBITS, SHF_WRITE | SHF_ALLOC, 0x0, 0x4b, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0},
			{".bss", SHT_NOBITS, SHF_WRITE | SHF_ALLOC, 0x0, 0x4b, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0},
			{".rodata", SHT_PROGBITS, SHF_ALLOC, 0x0, 0x4b, 0xd, 0x0, 0x0, 0x1, 0x0, 0xd},
			{".debug_info", SHT_PROGBITS, SHF_COMPRESSED, 0x0, 0x58, 0xb4, 0x0, 0x0, 0x1, 0x0, 0x84},
			{".rel.debug_info", SHT_REL, SHF_INFO_LINK, 0x0, 0x3ec, 0xa0, 0x13, 0x6, 0x4, 0x8, 0xa0},
			{".debug_abbrev", SHT_PROGBITS, 0x0, 0x0, 0xdc, 0x5a, 0x0, 0x0, 0x1, 0x0, 0x5a},
			{".debug_aranges", SHT_PROGBITS, 0x0, 0x0, 0x136, 0x20, 0x0, 0x0, 0x1, 0x0, 0x20},
			{".rel.debug_aranges", SHT_REL, SHF_INFO_LINK, 0x0, 0x48c, 0x10, 0x13, 0x9, 0x4, 0x8, 0x10},
			{".debug_line", SHT_PROGBITS, 0x0, 0x0, 0x156, 0x5c, 0x0, 0x0, 0x1, 0x0, 0x5c},
			{".rel.debug_line", SHT_REL, SHF_INFO_LINK, 0x0, 0x49c, 0x8, 0x13, 0xb, 0x4, 0x8, 0x8},
			{".debug_str", SHT_PROGBITS, SHF_MERGE | SHF_STRINGS | SHF_COMPRESSED, 0x0, 0x1b2, 0x10f, 0x0, 0x0, 0x1, 0x1, 0xb3},
			{".comment", SHT_PROGBITS, SHF_MERGE | SHF_STRINGS, 0x0, 0x265, 0x2a, 0x0, 0x0, 0x1, 0x1, 0x2a},
			{".note.GNU-stack", SHT_PROGBITS, 0x0, 0x0, 0x28f, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0},
			{".eh_frame", SHT_PROGBITS, SHF_ALLOC, 0x0, 0x290, 0x38, 0x0, 0x0, 0x4, 0x0, 0x38},
			{".rel.eh_frame", SHT_REL, SHF_INFO_LINK, 0x0, 0x4a4, 0x8, 0x13, 0x10, 0x4, 0x8, 0x8},
			{".shstrtab", SHT_STRTAB, 0x0, 0x0, 0x4ac, 0xab, 0x0, 0x0, 0x1, 0x0, 0xab},
			{".symtab", SHT_SYMTAB, 0x0, 0x0, 0x2c8, 0x100, 0x14, 0xe, 0x4, 0x10, 0x100},
			{".strtab", SHT_STRTAB, 0x0, 0x0, 0x3c8, 0x13, 0x0, 0x0, 0x1, 0x0, 0x13},
		},
		[]ProgHeader{},
		nil,
		[]Symbol{
			{"hello.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"", 3, 0, false, 0, 1, 0, 0, "", ""},
			{"", 3, 0, false, 0, 3, 0, 0, "", ""},
			{"", 3, 0, false, 0, 4, 0, 0, "", ""},
			{"", 3, 0, false, 0, 5, 0, 0, "", ""},
			{"", 3, 0, false, 0, 6, 0, 0, "", ""},
			{"", 3, 0, false, 0, 8, 0, 0, "", ""},
			{"", 3, 0, false, 0, 9, 0, 0, "", ""},
			{"", 3, 0, false, 0, 11, 0, 0, "", ""},
			{"", 3, 0, false, 0, 13, 0, 0, "", ""},
			{"", 3, 0, false, 0, 15, 0, 0, "", ""},
			{"", 3, 0, false, 0, 16, 0, 0, "", ""},
			{"", 3, 0, false, 0, 14, 0, 0, "", ""},
			{"main", 18, 0, false, 0, 1, 0, 23, "", ""},
			{"puts", 16, 0, false, 0, 0, 0, 0, "", ""},
		},
	},
	{
		"testdata/compressed-64.obj",
		FileHeader{ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE, 0x0, binary.LittleEndian, ET_REL, EM_X86_64, 0x0},
		[]SectionHeader{
			{"", SHT_NULL, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			{".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0x0, 0x40, 0x1b, 0x0, 0x0, 0x1, 0x0, 0x1b},
			{".rela.text", SHT_RELA, SHF_INFO_LINK, 0x0, 0x488, 0x30, 0x13, 0x1, 0x8, 0x18, 0x30},
			{".data", SHT_PROGBITS, SHF_WRITE | SHF_ALLOC, 0x0, 0x5b, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0},
			{".bss", SHT_NOBITS, SHF_WRITE | SHF_ALLOC, 0x0, 0x5b, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0},
			{".rodata", SHT_PROGBITS, SHF_ALLOC, 0x0, 0x5b, 0xd, 0x0, 0x0, 0x1, 0x0, 0xd},
			{".debug_info", SHT_PROGBITS, SHF_COMPRESSED, 0x0, 0x68, 0xba, 0x0, 0x0, 0x1, 0x0, 0x72},
			{".rela.debug_info", SHT_RELA, SHF_INFO_LINK, 0x0, 0x4b8, 0x1c8, 0x13, 0x6, 0x8, 0x18, 0x1c8},
			{".debug_abbrev", SHT_PROGBITS, 0x0, 0x0, 0xda, 0x5c, 0x0, 0x0, 0x1, 0x0, 0x5c},
			{".debug_aranges", SHT_PROGBITS, SHF_COMPRESSED, 0x0, 0x136, 0x30, 0x0, 0x0, 0x1, 0x0, 0x2f},
			{".rela.debug_aranges", SHT_RELA, SHF_INFO_LINK, 0x0, 0x680, 0x30, 0x13, 0x9, 0x8, 0x18, 0x30},
			{".debug_line", SHT_PROGBITS, 0x0, 0x0, 0x165, 0x60, 0x0, 0x0, 0x1, 0x0, 0x60},
			{".rela.debug_line", SHT_RELA, SHF_INFO_LINK, 0x0, 0x6b0, 0x18, 0x13, 0xb, 0x8, 0x18, 0x18},
			{".debug_str", SHT_PROGBITS, SHF_MERGE | SHF_STRINGS | SHF_COMPRESSED, 0x0, 0x1c5, 0x104, 0x0, 0x0, 0x1, 0x1, 0xc3},
			{".comment", SHT_PROGBITS, SHF_MERGE | SHF_STRINGS, 0x0, 0x288, 0x2a, 0x0, 0x0, 0x1, 0x1, 0x2a},
			{".note.GNU-stack", SHT_PROGBITS, 0x0, 0x0, 0x2b2, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0},
			{".eh_frame", SHT_PROGBITS, SHF_ALLOC, 0x0, 0x2b8, 0x38, 0x0, 0x0, 0x8, 0x0, 0x38},
			{".rela.eh_frame", SHT_RELA, SHF_INFO_LINK, 0x0, 0x6c8, 0x18, 0x13, 0x10, 0x8, 0x18, 0x18},
			{".shstrtab", SHT_STRTAB, 0x0, 0x0, 0x6e0, 0xb0, 0x0, 0x0, 0x1, 0x0, 0xb0},
			{".symtab", SHT_SYMTAB, 0x0, 0x0, 0x2f0, 0x180, 0x14, 0xe, 0x8, 0x18, 0x180},
			{".strtab", SHT_STRTAB, 0x0, 0x0, 0x470, 0x13, 0x0, 0x0, 0x1, 0x0, 0x13},
		},
		[]ProgHeader{},
		nil,
		[]Symbol{
			{"hello.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"", 3, 0, false, 0, 1, 0, 0, "", ""},
			{"", 3, 0, false, 0, 3, 0, 0, "", ""},
			{"", 3, 0, false, 0, 4, 0, 0, "", ""},
			{"", 3, 0, false, 0, 5, 0, 0, "", ""},
			{"", 3, 0, false, 0, 6, 0, 0, "", ""},
			{"", 3, 0, false, 0, 8, 0, 0, "", ""},
			{"", 3, 0, false, 0, 9, 0, 0, "", ""},
			{"", 3, 0, false, 0, 11, 0, 0, "", ""},
			{"", 3, 0, false, 0, 13, 0, 0, "", ""},
			{"", 3, 0, false, 0, 15, 0, 0, "", ""},
			{"", 3, 0, false, 0, 16, 0, 0, "", ""},
			{"", 3, 0, false, 0, 14, 0, 0, "", ""},
			{"main", 18, 0, false, 0, 1, 0, 27, "", ""},
			{"puts", 16, 0, false, 0, 0, 0, 0, "", ""},
		},
	},
	{
		"testdata/go-relocation-test-gcc620-sparc64.obj",
		FileHeader{Class: ELFCLASS64, Data: ELFDATA2MSB, Version: EV_CURRENT, OSABI: ELFOSABI_NONE, ABIVersion: 0x0, ByteOrder: binary.BigEndian, Type: ET_REL, Machine: EM_SPARCV9, Entry: 0x0},
		[]SectionHeader{
			{"", SHT_NULL, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			{".text", SHT_PROGBITS, SHF_ALLOC + SHF_EXECINSTR, 0x0, 0x40, 0x2c, 0x0, 0x0, 0x4, 0x0, 0x2c},
			{".rela.text", SHT_RELA, SHF_INFO_LINK, 0x0, 0xa58, 0x48, 0x13, 0x1, 0x8, 0x18, 0x48},
			{".data", SHT_PROGBITS, SHF_WRITE + SHF_ALLOC, 0x0, 0x6c, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0},
			{".bss", SHT_NOBITS, SHF_WRITE + SHF_ALLOC, 0x0, 0x6c, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0},
			{".rodata", SHT_PROGBITS, SHF_ALLOC, 0x0, 0x70, 0xd, 0x0, 0x0, 0x8, 0x0, 0xd},
			{".debug_info", SHT_PROGBITS, 0x0, 0x0, 0x7d, 0x346, 0x0, 0x0, 0x1, 0x0, 0x346},
			{".rela.debug_info", SHT_RELA, SHF_INFO_LINK, 0x0, 0xaa0, 0x630, 0x13, 0x6, 0x8, 0x18, 0x630},
			{".debug_abbrev", SHT_PROGBITS, 0x0, 0x0, 0x3c3, 0xf1, 0x0, 0x0, 0x1, 0x0, 0xf1},
			{".debug_aranges", SHT_PROGBITS, 0x0, 0x0, 0x4b4, 0x30, 0x0, 0x0, 0x1, 0x0, 0x30},
			{".rela.debug_aranges", SHT_RELA, SHF_INFO_LINK, 0x0, 0x10d0, 0x30, 0x13, 0x9, 0x8, 0x18, 0x30},
			{".debug_line", SHT_PROGBITS, 0x0, 0x0, 0x4e4, 0xd3, 0x0, 0x0, 0x1, 0x0, 0xd3},
			{".rela.debug_line", SHT_RELA, SHF_INFO_LINK, 0x0, 0x1100, 0x18, 0x13, 0xb, 0x8, 0x18, 0x18},
			{".debug_str", SHT_PROGBITS, SHF_MERGE + SHF_STRINGS, 0x0, 0x5b7, 0x2a3, 0x0, 0x0, 0x1, 0x1, 0x2a3},
			{".comment", SHT_PROGBITS, SHF_MERGE + SHF_STRINGS, 0x0, 0x85a, 0x2e, 0x0, 0x0, 0x1, 0x1, 0x2e},
			{".note.GNU-stack", SHT_PROGBITS, 0x0, 0x0, 0x888, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0},
			{".debug_frame", SHT_PROGBITS, 0x0, 0x0, 0x888, 0x38, 0x0, 0x0, 0x8, 0x0, 0x38},
			{".rela.debug_frame", SHT_RELA, SHF_INFO_LINK, 0x0, 0x1118, 0x30, 0x13, 0x10, 0x8, 0x18, 0x30},
			{".shstrtab", SHT_STRTAB, 0x0, 0x0, 0x1148, 0xb3, 0x0, 0x0, 0x1, 0x0, 0xb3},
			{".symtab", SHT_SYMTAB, 0x0, 0x0, 0x8c0, 0x180, 0x14, 0xe, 0x8, 0x18, 0x180},
			{".strtab", SHT_STRTAB, 0x0, 0x0, 0xa40, 0x13, 0x0, 0x0, 0x1, 0x0, 0x13},
		},
		[]ProgHeader{},
		nil,
		[]Symbol{
			{"hello.c", 4, 0, false, 0, 65521, 0, 0, "", ""},
			{"", 3, 0, false, 0, 1, 0, 0, "", ""},
			{"", 3, 0, false, 0, 3, 0, 0, "", ""},
			{"", 3, 0, false, 0, 4, 0, 0, "", ""},
			{"", 3, 0, false, 0, 5, 0, 0, "", ""},
			{"", 3, 0, false, 0, 6, 0, 0, "", ""},
			{"", 3, 0, false, 0, 8, 0, 0, "", ""},
			{"", 3, 0, false, 0, 9, 0, 0, "", ""},
			{"", 3, 0, false, 0, 11, 0, 0, "", ""},
			{"", 3, 0, false, 0, 13, 0, 0, "", ""},
			{"", 3, 0, false, 0, 15, 0, 0, "", ""},
			{"", 3, 0, false, 0, 16, 0, 0, "", ""},
			{"", 3, 0, false, 0, 14, 0, 0, "", ""},
			{"main", 18, 0, false, 0, 1, 0, 44, "", ""},
			{"puts", 16, 0, false, 0, 0, 0, 0, "", ""},
		},
	},
}

func TestOpen(t *testing.T) {
	for i := range fileTests {
		tt := &fileTests[i]

		var f *File
		var err error
		if path.Ext(tt.file) == ".gz" {
			var r io.ReaderAt
			if r, err = decompress(tt.file); err == nil {
				f, err = NewFile(r)
			}
		} else {
			f, err = Open(tt.file)
		}
		if err != nil {
			t.Errorf("cannot open file %s: %v", tt.file, err)
			continue
		}
		defer f.Close()
		if f.FileHeader != tt.hdr {
			t.Errorf("open %s:\n\thave %#v\n\twant %#v\n", tt.file, f.FileHeader, tt.hdr)
			continue
		}
		for i, s := range f.Sections {
			if i >= len(tt.sections) {
				break
			}
			sh := tt.sections[i]
			if s.SectionHeader != sh {
				t.Errorf("open %s, section %d:\n\thave %#v\n\twant %#v\n", tt.file, i, s.SectionHeader, sh)
			}
		}
		for i, p := range f.Progs {
			if i >= len(tt.progs) {
				break
			}
			ph := tt.progs[i]
			if p.ProgHeader != ph {
				t.Errorf("open %s, program %d:\n\thave %#v\n\twant %#v\n", tt.file, i, p.ProgHeader, ph)
			}
		}
		tn := len(tt.sections)
		fn := len(f.Sections)
		if tn != fn {
			t.Errorf("open %s: len(Sections) = %d, want %d", tt.file, fn, tn)
		}
		tn = len(tt.progs)
		fn = len(f.Progs)
		if tn != fn {
			t.Errorf("open %s: len(Progs) = %d, want %d", tt.file, fn, tn)
		}
		tl := tt.needed
		fl, err := f.ImportedLibraries()
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(tl, fl) {
			t.Errorf("open %s: DT_NEEDED = %v, want %v", tt.file, tl, fl)
		}
		symbols, err := f.Symbols()
		if tt.symbols == nil {
			if !errors.Is(err, ErrNoSymbols) {
				t.Errorf("open %s: Symbols() expected ErrNoSymbols, have nil", tt.file)
			}
			if symbols != nil {
				t.Errorf("open %s: Symbols() expected no symbols, have %v", tt.file, symbols)
			}
		} else {
			if err != nil {
				t.Errorf("open %s: Symbols() unexpected error %v", tt.file, err)
			}
			if !slices.Equal(symbols, tt.symbols) {
				t.Errorf("open %s: Symbols() = %v, want %v", tt.file, symbols, tt.symbols)
			}
		}
	}
}

// elf.NewFile requires io.ReaderAt, which compress/gzip cannot
// provide. Decompress the file to a bytes.Reader.
func decompress(gz string) (io.ReaderAt, error) {
	in, err := os.Open(gz)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	r, err := gzip.NewReader(in)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	_, err = io.Copy(&out, r)
	return bytes.NewReader(out.Bytes()), err
}

type relocationTestEntry struct {
	entryNumber int
	entry       *dwarf.Entry
	pcRanges    [][2]uint64
}

type relocationTest struct {
	file    string
	entries []relocationTestEntry
}

var relocationTests = []relocationTest{
	{
		"testdata/go-relocation-test-gcc441-x86-64.obj",
		[]relocationTestEntry{
			{
				entry: &dwarf.Entry{
					Offset:   0xb,
					Tag:      dwarf.TagCompileUnit,
					Children: true,
					Field: []dwarf.Field{
						{Attr: dwarf.AttrProducer, Val: "GNU C 4.4.1", Class: dwarf.ClassString},
						{Attr: dwarf.AttrLanguage, Val: int64(1), Class: dwarf.ClassConstant},
						{Attr: dwarf.AttrName, Val: "go-relocation-test.c", Class: dwarf.ClassString},
						{Attr: dwarf.AttrCompDir, Val: "/tmp", Class: dwarf.ClassString},
						{Attr: dwarf.AttrLowpc, Val: uint64(0x0), Class: dwarf.ClassAddress},
						{Attr: dwarf.AttrHighpc, Val: uint64(0x6), Class: dwarf.ClassAddress},
						{Attr: dwarf.AttrStmtList, Val: int64(0), Class: dwarf.ClassLinePtr},
					},
				},
				pcRanges: [][2]uint64{{0x0, 0x6}},
			},
		},
	},
	{
		"testdata/go-relocation-test-gcc441-x86.obj",
		[]relocationTestEntry{
			{
				entry: &dwarf.Entry{
					Offset:   0xb,
					Tag:      dwarf.TagCompileUnit,
					Children: true,
					Field: []dwarf.Field{
						{Attr: dwarf.AttrProducer, Val: "GNU C 4.4.1", Class: dwarf.ClassString},
						{Attr: dwarf.AttrLanguage, Val: int64(1), Class: dwarf.ClassConstant},
						{Attr: dwarf.AttrName, Val: "t.c", Class: dwarf.ClassString},
						{Attr: dwarf.AttrCompDir, Val: "/tmp", Class: dwarf.ClassString},
						{Attr: dwarf.AttrLowpc, Val: uint64(0x0), Class: dwarf.ClassAddress},
						{Attr: dwarf.AttrHighpc, Val: uint64(0x5), Class: dwarf.ClassAddress},
						{Attr: dwarf.AttrStmtList, Val: int64(0), Class: dwarf.ClassLinePtr},
					},
				},
				pcRanges: [][2]uint64{{0x0, 0x5}},
			},
		},
	},
	{
		"testdata/go-relocation-test-gcc424-x86-64.obj",
		[]relocationTestEntry{
			{
				entry: &dwarf.Entry{
					Offset:   0xb,
					Tag:      dwarf.TagCompileUnit,
					Children: true,
					Field: []dwarf.Field{
						{Attr: dwarf.AttrProducer, Val: "GNU C 4.2.4 (Ubuntu 4.2.4-1ubuntu4)", Class: dwarf.ClassString},
						{Attr: dwarf.AttrLanguage, Val: int64(1), Class: dwarf.ClassConstant},
						{Attr: dwarf.AttrName, Val: "go-relocation-test-gcc424.c", Class: dwarf.ClassString},
						{Attr: dwarf.AttrCompDir, Val: "/tmp", Class: dwarf.ClassString},
						{Attr: dwarf.AttrLowpc, Val: uint64(0x0), Class: dwarf.ClassAddress},
						{Attr: dwarf.AttrHighpc, Val: uint64(0x6), Class: dwarf.ClassAddress},
						{Attr: dwarf.AttrStmtList, Val: int64(0), Class: dwarf.ClassLinePtr},
					},
				},
				pcRanges: [][2]uint64{{0x0, 0x6}},
			},
		},
	},
	{
		"testdata/go-relocation-test-gcc482-aarch64.obj",
		[]relocationTestEntry{
			{
				entry: &dwarf.Entry{
					Offset:   0xb,
					Tag:      dwarf.TagCompileUnit,
					Children: true,
					Field: []dwarf.Field{
						{Attr: dwarf.AttrProducer, Val: "GNU C 4.8.2 -g -fstack-protector", Class: dwarf.ClassString},
						{Attr: dwarf.AttrLanguage, Val: int64(1), Class: dwarf.ClassConstant},
						{Attr: dwarf.AttrName, Val: "go-relocation-test-gcc482.c", Class: dwarf.ClassString},
						{Attr: dwarf.AttrCompDir, Val: "/tmp", Class: dwarf.ClassString},
						{Attr: dwarf.AttrLowpc, Val: uint64(0x0), Class: dwarf.ClassAddress},
						{Attr: dwa
"""




```