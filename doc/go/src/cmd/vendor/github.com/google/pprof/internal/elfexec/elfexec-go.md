Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `elfexec.go` file within the context of the `pprof` tool. This means we're looking for what tasks this file performs related to processing ELF (Executable and Linkable Format) files.

**2. Initial Code Scan and Keyword Spotting:**

The first step is a quick scan of the code to identify key data structures, functions, and constants. This gives a high-level overview. Keywords like `elf`, `Note`, `BuildID`, `Base`, `ProgHeader`, `Section`, and concepts like "alignment", "padding", and "kernel" immediately jump out as important.

**3. Analyzing Data Structures:**

* **`elfNote`:**  This structure clearly represents a note entry within an ELF file. The fields `Name`, `Desc`, and `Type` are standard components of ELF notes.

**4. Analyzing Functions - Focusing on Publicly Accessible Ones:**

* **`parseNotes`:** This function's name and parameters (`io.Reader`, `alignment`, `binary.ByteOrder`) suggest it's responsible for reading and interpreting note sections or segments from an ELF file. The internal logic involving reading headers, handling names, descriptions, and padding reinforces this.

* **`GetBuildID`:**  The name strongly suggests it's extracting the build ID from an ELF file. The logic iterates through program headers and section headers, looking for `PT_NOTE` and `SHT_NOTE` types, and then uses `parseNotes` to analyze them. The search for a "GNU" note with a specific type (`noteTypeGNUBuildID`) confirms this.

* **`kernelBase`:** The name hints at handling base addresses specifically for kernel mappings. The presence of constants like `pageOffsetPpc64` and `pageSize` and the logic involving comparisons with `start`, `limit`, and `offset` support this. The comment about "obfuscation" and "ChromeOS" adds context.

* **`GetBase`:**  This function appears to be the core logic for calculating the base address. The switch statement based on `fh.Type` (ELF file type) and the different handling for `ET_EXEC`, `ET_REL`, and `ET_DYN` are significant. The calls to `kernelBase` further emphasize the special kernel handling.

* **`FindTextProgHeader`:** The name suggests finding the program header associated with the `.text` section. The logic iterates through sections, finds `.text`, then searches for a `PT_LOAD` program header that encompasses it.

* **`ProgramHeadersForMapping`:**  The name and parameters suggest identifying program headers relevant to a specific memory mapping. The logic involves checks for overlap, file size, and alignment considerations. The internal constant `pageSize` is relevant here.

* **`HeaderForFileOffset`:**  This function seems to pinpoint a specific program header based on a given file offset. The error condition about finding multiple headers points to potential issues with stripped binaries or uninitialized data.

**5. Inferring Go Language Features:**

* **`io.Reader`:**  Clearly demonstrates the use of interfaces for abstracting input sources. Any type implementing `io.Reader` can be used.

* **`bufio.NewReader`:**  Shows the use of buffered input for efficiency.

* **`encoding/binary`:**  Highlights the need to handle byte order (endianness) when parsing binary data.

* **`debug/elf`:** The core dependency, providing the Go standard library's facilities for working with ELF files.

* **Constants and Enums:** The `const` definitions and the use of `elf.PT_NOTE`, `elf.SHT_NOTE`, etc., demonstrate the use of constants and enums for clarity and maintainability.

* **Error Handling:** The functions consistently return errors, demonstrating proper error handling practices.

**6. Code Reasoning and Examples:**

For each function, the goal was to provide a concise explanation of its purpose and illustrate its use with a simple Go code example. This involved:

* **Identifying Key Inputs and Outputs:**  What does the function take in, and what does it return?
* **Simulating a Scenario:** Creating a plausible situation where the function would be used.
* **Providing a Minimal Working Example:**  Focusing on the core functionality without unnecessary complexity.
* **Specifying Assumptions:**  Clearly stating any assumptions made about the input data.
* **Showing Expected Output:** Indicating what the function would likely return for the given input.

**7. Command-Line Arguments and Common Mistakes:**

This section required connecting the code's functionality to the broader context of the `pprof` tool. Since this specific file doesn't directly handle command-line arguments, the explanation focuses on how `pprof` would use the functionality provided by `elfexec.go`. The "common mistakes" section is based on understanding potential issues when working with ELF files, such as incorrect file paths or insufficient permissions.

**8. Iterative Refinement:**

The process wasn't necessarily linear. There was likely some back-and-forth between reading the code, forming hypotheses about its purpose, and then verifying those hypotheses through closer inspection and by looking for connections between functions. For example, understanding `GetBuildID` requires understanding how `parseNotes` works.

**Self-Correction Example During Analysis:**

Initially, I might have thought `GetBase` simply calculates the base address for all ELF files in the same way. However, noticing the `switch` statement based on `fh.Type` and the separate `kernelBase` function would lead me to correct this initial assumption and realize that different ELF types (executables, shared libraries, kernel images) require different handling. Similarly, the comments in `kernelBase` about ChromeOS and obfuscation provide crucial context that might not be immediately obvious from the code alone.
这段Go语言代码文件 `elfexec.go` 的主要功能是提供用于检查和解析 ELF (Executable and Linkable Format) 二进制文件的实用程序。它被 `pprof` 工具使用，以理解程序执行时的内存布局和符号信息。

以下是它的主要功能：

1. **解析 ELF Note Section/Segment:**
   - `parseNotes` 函数用于解析 ELF 文件中的 Note Section (类型为 `SHT_NOTE`) 或 Note Segment (类型为 `PT_NOTE`)。
   - Note Section/Segment 通常包含一些额外的元数据，例如构建 ID。
   - 该函数读取 Note 的头部信息（name size, desc size, type），然后读取 name 和 description 的内容，并考虑了对齐和填充。

2. **获取 GNU Build ID:**
   - `GetBuildID` 函数用于从 ELF 文件中提取 GNU Build ID。
   - Build ID 是一个唯一的标识符，用于标识特定版本的二进制文件。
   - 它会遍历 ELF 文件的 Program Headers 和 Section Headers，查找类型为 `PT_NOTE` 或 `SHT_NOTE` 的条目，并调用 `parseNotes` 解析其中的内容。
   - 它查找 name 为 "GNU" 且 type 为 `noteTypeGNUBuildID` (值为 3) 的 Note，其 description 就是 Build ID。
   - 如果找到多个 Build ID，则会返回错误。

3. **计算内核基地址:**
   - `kernelBase` 函数用于计算内核映射的基地址。
   - 内核映射通常需要特殊处理。一些工具（如 `perf`）使用内核重定位符号（如 `_text` 或 `_stext`）的地址作为 mmap 的起始地址。
   - 该函数考虑了一些特殊情况，例如 ChromeOS 将内核镜像重新映射到第 0 页的情况。
   - 它会根据 `loadSegment` 的虚拟地址、起始地址 `start`、结束地址 `limit`、偏移量 `offset` 以及 `stextOffset`（`_text` 或 `_stext` 符号的偏移量）等信息来推断基地址。

4. **计算基地址:**
   - `GetBase` 函数用于确定从虚拟地址中减去以获得符号表地址的基地址。
   - 对于可执行文件，基地址通常为 0。
   - 对于共享库，基地址是映射的起始地址。
   - 该函数根据 ELF 文件的类型 (`fh.Type`) 以及提供的 `loadSegment`、`stextOffset`、`start`、`limit` 和 `offset` 等信息进行计算。
   - 它针对不同的 ELF 类型（`ET_EXEC`, `ET_REL`, `ET_DYN`）采取不同的计算方式，并调用 `kernelBase` 处理内核的情况。

5. **查找包含 .text Section 的 Program Header:**
   - `FindTextProgHeader` 函数用于查找包含 `.text` section 的 Program Segment Header。
   - `.text` section 通常包含程序的执行代码。
   - 它遍历 ELF 文件的 Section Headers，找到名为 `.text` 的 section，然后遍历 Program Headers，找到类型为 `PT_LOAD` 且具有执行权限 (`elf.PF_X`) 并包含 `.text` section 地址范围的 segment。

6. **为内存映射查找 Program Headers:**
   - `ProgramHeadersForMapping` 函数用于返回与运行时内存映射重叠的 Program Segment Headers。
   - 它接收一个 Program Header 切片、映射的文件偏移量 `mapOff` 和映射大小 `mapSz` 作为参数。
   - 它会过滤掉文件大小为零的 segment，因为它们的文件偏移量不可靠。
   - 它会检查 segment 是否与给定的内存映射重叠，并考虑了页对齐等因素。

7. **根据文件偏移量查找 Program Header:**
   - `HeaderForFileOffset` 函数尝试根据给定的文件偏移量找到唯一的 Program Header。
   - 如果找到多个匹配的 Program Header，则会返回错误，这通常发生在二进制文件被 strip 掉部分 section 或 program segment 包含未初始化的数据时。

**它是什么 Go 语言功能的实现：**

这个文件主要是对 ELF 文件格式的解析和操作的实现。它利用了 Go 标准库中的 `debug/elf` 包来读取和理解 ELF 文件的结构。

**Go 代码示例：**

以下代码演示了如何使用 `elfexec` 包中的 `GetBuildID` 函数来获取 ELF 文件的 Build ID：

```go
package main

import (
	"debug/elf"
	"fmt"
	"log"
	"os"

	"cmd/vendor/github.com/google/pprof/internal/elfexec"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("用法: go run main.go <elf_文件路径>")
		return
	}

	filePath := os.Args[1]
	f, err := elf.Open(filePath)
	if err != nil {
		log.Fatalf("打开 ELF 文件失败: %v", err)
	}
	defer f.Close()

	buildID, err := elfexec.GetBuildID(f)
	if err != nil {
		log.Fatalf("获取 Build ID 失败: %v", err)
	}

	if buildID != nil {
		fmt.Printf("Build ID: %x\n", buildID)
	} else {
		fmt.Println("未找到 Build ID")
	}
}
```

**假设的输入与输出：**

假设我们有一个名为 `myprogram` 的 ELF 可执行文件，并且它包含一个 GNU Build ID。

**输入：**

```
go run main.go myprogram
```

**输出：**

```
Build ID: a1b2c3d4e5f678901234567890abcdef0
```

如果 `myprogram` 没有 Build ID，输出将是：

```
未找到 Build ID
```

**命令行参数的具体处理：**

这个 `elfexec.go` 文件本身并没有直接处理命令行参数。它提供的功能被 `pprof` 等工具调用，这些工具会处理命令行参数，然后使用 `elfexec` 包来解析 ELF 文件。

例如，`pprof` 工具可能会接收一个 ELF 文件路径作为命令行参数，然后内部调用 `elfexec.Open` 打开该文件，并使用 `elfexec.GetBuildID` 等函数来获取信息。

**使用者易犯错的点：**

1. **文件路径错误：**  调用 `elf.Open` 时，如果提供的 ELF 文件路径不正确，会导致程序无法打开文件并报错。例如，拼写错误或文件不存在。

   ```go
   f, err := elf.Open("/path/to/my_program_that_does_not_exist")
   if err != nil {
       log.Fatalf("打开 ELF 文件失败: %v", err) // 可能会输出 "打开 ELF 文件失败: open /path/to/my_program_that_does_not_exist: no such file or directory"
   }
   ```

2. **权限问题：**  如果程序没有读取 ELF 文件的权限，也会导致打开失败。

   ```go
   // 假设 myprogram 只有执行权限，没有读取权限
   f, err := elf.Open("myprogram")
   if err != nil {
       log.Fatalf("打开 ELF 文件失败: %v", err) // 可能会输出 "打开 ELF 文件失败: open myprogram: permission denied"
   }
   ```

3. **假设所有 ELF 文件都包含 Build ID：**  并非所有 ELF 文件都一定包含 GNU Build ID。如果代码依赖 Build ID 存在，但处理了不包含 Build ID 的文件，可能会导致程序逻辑错误或 panic。应该检查 `GetBuildID` 的返回值是否为 `nil`。

   ```go
   buildID, err := elfexec.GetBuildID(f)
   if err != nil {
       log.Fatalf("获取 Build ID 失败: %v", err)
   }
   if buildID == nil {
       fmt.Println("警告: 未找到 Build ID，后续操作可能受影响")
       // ... 其他处理逻辑 ...
   } else {
       fmt.Printf("Build ID: %x\n", buildID)
   }
   ```

总而言之，`elfexec.go` 是 `pprof` 工具箱中一个重要的组成部分，它提供了低级别的 ELF 文件解析能力，使得 `pprof` 能够理解程序运行时的二进制文件结构，从而进行性能分析和剖析。

### 提示词
```
这是路径为go/src/cmd/vendor/github.com/google/pprof/internal/elfexec/elfexec.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package elfexec provides utility routines to examine ELF binaries.
package elfexec

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	maxNoteSize        = 1 << 20 // in bytes
	noteTypeGNUBuildID = 3
)

// elfNote is the payload of a Note Section in an ELF file.
type elfNote struct {
	Name string // Contents of the "name" field, omitting the trailing zero byte.
	Desc []byte // Contents of the "desc" field.
	Type uint32 // Contents of the "type" field.
}

// parseNotes returns the notes from a SHT_NOTE section or PT_NOTE segment.
func parseNotes(reader io.Reader, alignment int, order binary.ByteOrder) ([]elfNote, error) {
	r := bufio.NewReader(reader)

	// padding returns the number of bytes required to pad the given size to an
	// alignment boundary.
	padding := func(size int) int {
		return ((size + (alignment - 1)) &^ (alignment - 1)) - size
	}

	var notes []elfNote
	for {
		noteHeader := make([]byte, 12) // 3 4-byte words
		if _, err := io.ReadFull(r, noteHeader); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		namesz := order.Uint32(noteHeader[0:4])
		descsz := order.Uint32(noteHeader[4:8])
		typ := order.Uint32(noteHeader[8:12])

		if uint64(namesz) > uint64(maxNoteSize) {
			return nil, fmt.Errorf("note name too long (%d bytes)", namesz)
		}
		var name string
		if namesz > 0 {
			// Documentation differs as to whether namesz is meant to include the
			// trailing zero, but everyone agrees that name is null-terminated.
			// So we'll just determine the actual length after the fact.
			var err error
			name, err = r.ReadString('\x00')
			if err == io.EOF {
				return nil, fmt.Errorf("missing note name (want %d bytes)", namesz)
			} else if err != nil {
				return nil, err
			}
			namesz = uint32(len(name))
			name = name[:len(name)-1]
		}

		// Drop padding bytes until the desc field.
		for n := padding(len(noteHeader) + int(namesz)); n > 0; n-- {
			if _, err := r.ReadByte(); err == io.EOF {
				return nil, fmt.Errorf(
					"missing %d bytes of padding after note name", n)
			} else if err != nil {
				return nil, err
			}
		}

		if uint64(descsz) > uint64(maxNoteSize) {
			return nil, fmt.Errorf("note desc too long (%d bytes)", descsz)
		}
		desc := make([]byte, int(descsz))
		if _, err := io.ReadFull(r, desc); err == io.EOF {
			return nil, fmt.Errorf("missing desc (want %d bytes)", len(desc))
		} else if err != nil {
			return nil, err
		}

		notes = append(notes, elfNote{Name: name, Desc: desc, Type: typ})

		// Drop padding bytes until the next note or the end of the section,
		// whichever comes first.
		for n := padding(len(desc)); n > 0; n-- {
			if _, err := r.ReadByte(); err == io.EOF {
				// We hit the end of the section before an alignment boundary.
				// This can happen if this section is at the end of the file or the next
				// section has a smaller alignment requirement.
				break
			} else if err != nil {
				return nil, err
			}
		}
	}
	return notes, nil
}

// GetBuildID returns the GNU build-ID for an ELF binary.
//
// If no build-ID was found but the binary was read without error, it returns
// (nil, nil).
func GetBuildID(f *elf.File) ([]byte, error) {
	findBuildID := func(notes []elfNote) ([]byte, error) {
		var buildID []byte
		for _, note := range notes {
			if note.Name == "GNU" && note.Type == noteTypeGNUBuildID {
				if buildID == nil {
					buildID = note.Desc
				} else {
					return nil, fmt.Errorf("multiple build ids found, don't know which to use")
				}
			}
		}
		return buildID, nil
	}

	for _, p := range f.Progs {
		if p.Type != elf.PT_NOTE {
			continue
		}
		notes, err := parseNotes(p.Open(), int(p.Align), f.ByteOrder)
		if err != nil {
			return nil, err
		}
		if b, err := findBuildID(notes); b != nil || err != nil {
			return b, err
		}
	}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_NOTE {
			continue
		}
		notes, err := parseNotes(s.Open(), int(s.Addralign), f.ByteOrder)
		if err != nil {
			return nil, err
		}
		if b, err := findBuildID(notes); b != nil || err != nil {
			return b, err
		}
	}
	return nil, nil
}

// kernelBase calculates the base for kernel mappings, which usually require
// special handling. For kernel mappings, tools (like perf) use the address of
// the kernel relocation symbol (_text or _stext) as the mmap start. Additionally,
// for obfuscation, ChromeOS profiles have the kernel image remapped to the 0-th page.
func kernelBase(loadSegment *elf.ProgHeader, stextOffset *uint64, start, limit, offset uint64) (uint64, bool) {
	const (
		// PAGE_OFFSET for PowerPC64, see arch/powerpc/Kconfig in the kernel sources.
		pageOffsetPpc64 = 0xc000000000000000
		pageSize        = 4096
	)

	if loadSegment.Vaddr == start-offset {
		return offset, true
	}
	if start == 0 && limit != 0 && stextOffset != nil {
		// ChromeOS remaps its kernel to 0. Nothing else should come
		// down this path. Empirical values:
		//       VADDR=0xffffffff80200000
		// stextOffset=0xffffffff80200198
		return start - *stextOffset, true
	}
	if start >= 0x8000000000000000 && limit > start && (offset == 0 || offset == pageOffsetPpc64 || offset == start) {
		// Some kernels look like:
		//       VADDR=0xffffffff80200000
		// stextOffset=0xffffffff80200198
		//       Start=0xffffffff83200000
		//       Limit=0xffffffff84200000
		//      Offset=0 (0xc000000000000000 for PowerPC64) (== Start for ASLR kernel)
		// So the base should be:
		if stextOffset != nil && (start%pageSize) == (*stextOffset%pageSize) {
			// perf uses the address of _stext as start. Some tools may
			// adjust for this before calling GetBase, in which case the page
			// alignment should be different from that of stextOffset.
			return start - *stextOffset, true
		}

		return start - loadSegment.Vaddr, true
	}
	if start%pageSize != 0 && stextOffset != nil && *stextOffset%pageSize == start%pageSize {
		// ChromeOS remaps its kernel to 0 + start%pageSize. Nothing
		// else should come down this path. Empirical values:
		//       start=0x198 limit=0x2f9fffff offset=0
		//       VADDR=0xffffffff81000000
		// stextOffset=0xffffffff81000198
		return start - *stextOffset, true
	}
	return 0, false
}

// GetBase determines the base address to subtract from virtual
// address to get symbol table address. For an executable, the base
// is 0. Otherwise, it's a shared library, and the base is the
// address where the mapping starts. The kernel needs special handling.
func GetBase(fh *elf.FileHeader, loadSegment *elf.ProgHeader, stextOffset *uint64, start, limit, offset uint64) (uint64, error) {

	if start == 0 && offset == 0 && (limit == ^uint64(0) || limit == 0) {
		// Some tools may introduce a fake mapping that spans the entire
		// address space. Assume that the address has already been
		// adjusted, so no additional base adjustment is necessary.
		return 0, nil
	}

	switch fh.Type {
	case elf.ET_EXEC:
		if loadSegment == nil {
			// Assume fixed-address executable and so no adjustment.
			return 0, nil
		}
		if stextOffset == nil && start > 0 && start < 0x8000000000000000 {
			// A regular user-mode executable. Compute the base offset using same
			// arithmetics as in ET_DYN case below, see the explanation there.
			// Ideally, the condition would just be "stextOffset == nil" as that
			// represents the address of _stext symbol in the vmlinux image. Alas,
			// the caller may skip reading it from the binary (it's expensive to scan
			// all the symbols) and so it may be nil even for the kernel executable.
			// So additionally check that the start is within the user-mode half of
			// the 64-bit address space.
			return start - offset + loadSegment.Off - loadSegment.Vaddr, nil
		}
		// Various kernel heuristics and cases are handled separately.
		if base, match := kernelBase(loadSegment, stextOffset, start, limit, offset); match {
			return base, nil
		}
		// ChromeOS can remap its kernel to 0, and the caller might have not found
		// the _stext symbol. Split this case from kernelBase() above, since we don't
		// want to apply it to an ET_DYN user-mode executable.
		if start == 0 && limit != 0 && stextOffset == nil {
			return start - loadSegment.Vaddr, nil
		}

		return 0, fmt.Errorf("don't know how to handle EXEC segment: %v start=0x%x limit=0x%x offset=0x%x", *loadSegment, start, limit, offset)
	case elf.ET_REL:
		if offset != 0 {
			return 0, fmt.Errorf("don't know how to handle mapping.Offset")
		}
		return start, nil
	case elf.ET_DYN:
		// The process mapping information, start = start of virtual address range,
		// and offset = offset in the executable file of the start address, tells us
		// that a runtime virtual address x maps to a file offset
		// fx = x - start + offset.
		if loadSegment == nil {
			return start - offset, nil
		}
		// Kernels compiled as PIE can be ET_DYN as well. Use heuristic, similar to
		// the ET_EXEC case above.
		if base, match := kernelBase(loadSegment, stextOffset, start, limit, offset); match {
			return base, nil
		}
		// The program header, if not nil, indicates the offset in the file where
		// the executable segment is located (loadSegment.Off), and the base virtual
		// address where the first byte of the segment is loaded
		// (loadSegment.Vaddr). A file offset fx maps to a virtual (symbol) address
		// sx = fx - loadSegment.Off + loadSegment.Vaddr.
		//
		// Thus, a runtime virtual address x maps to a symbol address
		// sx = x - start + offset - loadSegment.Off + loadSegment.Vaddr.
		return start - offset + loadSegment.Off - loadSegment.Vaddr, nil
	}
	return 0, fmt.Errorf("don't know how to handle FileHeader.Type %v", fh.Type)
}

// FindTextProgHeader finds the program segment header containing the .text
// section or nil if the segment cannot be found.
func FindTextProgHeader(f *elf.File) *elf.ProgHeader {
	for _, s := range f.Sections {
		if s.Name == ".text" {
			// Find the LOAD segment containing the .text section.
			for _, p := range f.Progs {
				if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && s.Addr >= p.Vaddr && s.Addr < p.Vaddr+p.Memsz {
					return &p.ProgHeader
				}
			}
		}
	}
	return nil
}

// ProgramHeadersForMapping returns the program segment headers that overlap
// the runtime mapping with file offset mapOff and memory size mapSz. We skip
// over segments zero file size because their file offset values are unreliable.
// Even if overlapping, a segment is not selected if its aligned file offset is
// greater than the mapping file offset, or if the mapping includes the last
// page of the segment, but not the full segment and the mapping includes
// additional pages after the segment end.
// The function returns a slice of pointers to the headers in the input
// slice, which are valid only while phdrs is not modified or discarded.
func ProgramHeadersForMapping(phdrs []elf.ProgHeader, mapOff, mapSz uint64) []*elf.ProgHeader {
	const (
		// pageSize defines the virtual memory page size used by the loader. This
		// value is dependent on the memory management unit of the CPU. The page
		// size is 4KB virtually on all the architectures that we care about, so we
		// define this metric as a constant. If we encounter architectures where
		// page sie is not 4KB, we must try to guess the page size on the system
		// where the profile was collected, possibly using the architecture
		// specified in the ELF file header.
		pageSize       = 4096
		pageOffsetMask = pageSize - 1
	)
	mapLimit := mapOff + mapSz
	var headers []*elf.ProgHeader
	for i := range phdrs {
		p := &phdrs[i]
		// Skip over segments with zero file size. Their file offsets can have
		// arbitrary values, see b/195427553.
		if p.Filesz == 0 {
			continue
		}
		segLimit := p.Off + p.Memsz
		// The segment must overlap the mapping.
		if p.Type == elf.PT_LOAD && mapOff < segLimit && p.Off < mapLimit {
			// If the mapping offset is strictly less than the page aligned segment
			// offset, then this mapping comes from a different segment, fixes
			// b/179920361.
			alignedSegOffset := uint64(0)
			if p.Off > (p.Vaddr & pageOffsetMask) {
				alignedSegOffset = p.Off - (p.Vaddr & pageOffsetMask)
			}
			if mapOff < alignedSegOffset {
				continue
			}
			// If the mapping starts in the middle of the segment, it covers less than
			// one page of the segment, and it extends at least one page past the
			// segment, then this mapping comes from a different segment.
			if mapOff > p.Off && (segLimit < mapOff+pageSize) && (mapLimit >= segLimit+pageSize) {
				continue
			}
			headers = append(headers, p)
		}
	}
	return headers
}

// HeaderForFileOffset attempts to identify a unique program header that
// includes the given file offset. It returns an error if it cannot identify a
// unique header.
func HeaderForFileOffset(headers []*elf.ProgHeader, fileOffset uint64) (*elf.ProgHeader, error) {
	var ph *elf.ProgHeader
	for _, h := range headers {
		if fileOffset >= h.Off && fileOffset < h.Off+h.Memsz {
			if ph != nil {
				// Assuming no other bugs, this can only happen if we have two or
				// more small program segments that fit on the same page, and a
				// segment other than the last one includes uninitialized data, or
				// if the debug binary used for symbolization is stripped of some
				// sections, so segment file sizes are smaller than memory sizes.
				return nil, fmt.Errorf("found second program header (%#v) that matches file offset %x, first program header is %#v. Is this a stripped binary, or does the first program segment contain uninitialized data?", *h, fileOffset, *ph)
			}
			ph = h
		}
	}
	if ph == nil {
		return nil, fmt.Errorf("no program header matches file offset %x", fileOffset)
	}
	return ph, nil
}
```