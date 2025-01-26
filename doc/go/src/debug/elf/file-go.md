Response:
The user wants a summary of the functionalities implemented in the provided Go code snippet from `go/src/debug/elf/file.go`. This involves analyzing the structs and methods defined within the code.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The package comment clearly states that this package implements access to ELF object files. This is the central theme around which all functionalities revolve.

2. **Analyze Key Data Structures:** Look for the primary structs.
    * `FileHeader`: Represents the ELF file header, containing basic information about the file (class, data encoding, type, machine, entry point).
    * `File`: Represents an open ELF file, holding the file header, sections, program headers, and a closer for the underlying file.
    * `SectionHeader`:  Represents the header of a single section within the ELF file (name, type, flags, address, offset, size, etc.). Crucially, it also distinguishes between `Size` (uncompressed) and `FileSize` (compressed).
    * `Section`: Represents a single section, combining its header with a `ReaderAt` to access the section's content. It handles decompression if necessary.
    * `ProgHeader`: Represents the header of a program segment.
    * `Prog`: Represents a program segment with its header and a `ReaderAt`.
    * `Symbol`: Represents an entry in the symbol table.

3. **Examine Key Methods and Their Functionality:**  Focus on the methods associated with the core structs.
    * `File.Close()`: Closes the underlying file if it was opened using `Open`.
    * `File.SectionByType()`: Finds a section by its type.
    * `File.NewFile()`:  The primary function for parsing an ELF file from a `ReaderAt`. This involves reading and interpreting the header and all section/program headers. A large portion of the code is dedicated to this.
    * `Section.Data()`: Reads the *uncompressed* content of a section.
    * `Section.Open()`: Returns a `ReadSeeker` for reading the *uncompressed* content of a section, handling decompression.
    * `File.stringTable()`:  Retrieves the string table associated with a section.
    * `Prog.Open()`: Returns a `ReadSeeker` for reading a program segment.
    * `File.getSymbols()` (and its variants `getSymbols32`, `getSymbols64`):  Parses symbol tables.
    * `File.Section()`: Finds a section by its name.
    * `File.applyRelocations()` (and architecture-specific variants): Applies relocations to a data buffer.

4. **Identify Key Internal Helper Functions:** Notice functions that are not directly associated with the main structs but are important for the overall functionality.
    * `getString()`:  Extracts strings from a string table.

5. **Pay Attention to Comments and Error Handling:**  Note comments explaining specific logic or potential issues (like the security warning). Observe how errors are handled (e.g., `FormatError`).

6. **Synthesize the Information into a Summary:** Group related functionalities and describe their purpose in concise sentences. Emphasize the core goal of parsing and accessing ELF file data. Highlight key aspects like handling different architectures, decompression, and symbol tables. Mention the security considerations.

7. **Review and Refine:**  Read the summary to ensure it accurately reflects the code's functionality and is easy to understand. Check for any missing key aspects. For example, initially, I might have overlooked the relocation functionality, but a closer look at the methods associated with `File` reveals its importance. Also, ensure the summary is in the requested language (Chinese).
这段Go语言代码是 `debug/elf` 包中用于解析和表示 ELF (Executable and Linkable Format) 文件的核心部分。它的主要功能可以归纳为：

1. **定义了表示 ELF 文件结构的各种数据结构**:
   - `FileHeader`:  表示 ELF 文件的头部信息，例如文件类别（32位或64位）、数据编码方式、版本、操作系统ABI、目标架构等。
   - `File`: 表示一个打开的 ELF 文件，包含了文件头、节区（Sections）信息、程序头（Progs）信息等。
   - `SectionHeader`: 表示 ELF 文件中单个节区的头部信息，例如节区名称、类型、标志、地址、偏移、大小等。
   - `Section`: 表示 ELF 文件中的一个节区，包含了节区头部信息以及读取节区内容的接口 (`io.ReaderAt`)。它还处理了压缩节区的解压。
   - `ProgHeader`: 表示 ELF 文件中单个程序头的头部信息，用于描述程序的段。
   - `Prog`: 表示 ELF 文件中的一个程序段，包含了程序头信息以及读取段内容的接口。
   - `Symbol`: 表示 ELF 文件符号表中的一个条目，包含了符号的名称、信息、节区索引、值和大小等。

2. **提供了打开和关闭 ELF 文件的功能**:
   - `Open(name string) (*File, error)`:  通过文件名打开一个 ELF 文件。
   - `NewFile(r io.ReaderAt) (*File, error)`:  从一个 `io.ReaderAt` 接口读取并解析 ELF 文件。
   - `Close() error`: 关闭已打开的 ELF 文件。

3. **提供了访问 ELF 文件各个组成部分的方法**:
   - `SectionByType(typ SectionType) *Section`:  根据节区类型查找并返回第一个匹配的节区。
   - `Section(name string) *Section`:  根据节区名称查找并返回匹配的节区。
   - `Data() ([]byte, error)` (在 `Section` 结构体中):  读取并返回节区的全部内容，即使节区是压缩的也会返回解压后的数据。
   - `Open() io.ReadSeeker` (在 `Section` 和 `Prog` 结构体中):  返回一个用于读取节区或程序段内容的 `io.ReadSeeker`，对于压缩节区，返回的 `io.ReadSeeker` 会自动解压数据。
   - `getSymbols(typ SectionType) ([]Symbol, []byte, error)`:  解析指定类型的符号表节区，并返回符号列表和字符串表数据。

4. **实现了对压缩节区的处理**: 代码能够识别并解压使用 ZLIB 或 ZSTD 算法压缩的节区。

5. **实现了符号表的读取**:  可以读取 `.symtab` (符号表) 和 `.dynsym` (动态符号表) 等节区，并解析其中的符号信息。

6. **提供了应用重定位的功能**:  `applyRelocations` 系列方法用于将重定位信息应用到指定的数据段，这是链接器和加载器需要执行的关键步骤。代码支持多种架构的重定位处理 (如 AMD64, 386, ARM, ARM64 等)。

**可以推理出这是 Go 语言 `debug/elf` 包中用于解析 ELF 文件的核心实现。**  它提供了一种结构化的方式来读取和理解 ELF 文件的内容，这对于各种与二进制文件分析、调试和链接相关的工具至关重要。例如，`go build` 工具在链接过程中会用到这个包来处理目标文件。

**Go 代码示例：**

假设我们有一个名为 `test.o` 的 ELF 目标文件。以下代码展示了如何使用 `debug/elf` 包来读取该文件的节区信息：

```go
package main

import (
	"debug/elf"
	"fmt"
	"log"
	"os"
)

func main() {
	f, err := elf.Open("test.o")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	fmt.Println("ELF 文件头信息:")
	fmt.Printf("  Class: %v\n", f.Class)
	fmt.Printf("  Data: %v\n", f.Data)
	fmt.Printf("  Type: %v\n", f.Type)
	fmt.Printf("  Machine: %v\n", f.Machine)
	fmt.Printf("  Entry: 0x%x\n", f.Entry)

	fmt.Println("\n节区信息:")
	for _, section := range f.Sections {
		fmt.Printf("  Name: %-20s Type: %-15v Flags: %-8v Size: %d\n", section.Name, section.Type, section.Flags, section.Size)
	}
}
```

**假设输入 `test.o` 是一个简单的 ELF 目标文件。**

**可能的输出：**

```
ELF 文件头信息:
  Class: ELFCLASS64
  Data: ELFDATA2LSB
  Type: ET_REL
  Machine: EM_X86_64
  Entry: 0x0

节区信息:
  Name:                    Type: SHT_NULL        Flags:            Size: 0
  Name: .text               Type: SHT_PROGBITS    Flags: SHF_ALLOC|SHF_EXECINSTR Size: 102
  Name: .rela.text          Type: SHT_RELA        Flags: SHF_INFO_LINK    Size: 24
  Name: .data               Type: SHT_PROGBITS    Flags: SHF_WRITE|SHF_ALLOC Size: 8
  Name: .bss                Type: SHT_NOBITS      Flags: SHF_WRITE|SHF_ALLOC Size: 8
  Name: .comment            Type: SHT_PROGBITS    Flags: SHF_MERGE|SHF_STRINGS Size: 33
  Name: .note.GNU-stack     Type: SHT_PROGBITS    Flags:            Size: 0
  Name: .eh_frame            Type: SHT_PROGBITS    Flags: SHF_ALLOC|SHF_GROUP Size: 48
  Name: .rela.eh_frame       Type: SHT_RELA        Flags: SHF_INFO_LINK    Size: 24
  Name: .symtab              Type: SHT_SYMTAB      Flags:            Size: 384
  Name: .strtab              Type: SHT_STRTAB      Flags:            Size: 224
  Name: .shstrtab            Type: SHT_STRTAB      Flags:            Size: 325
```

**这段代码没有涉及到具体的命令行参数处理。**  `debug/elf` 包主要是在 Go 程序内部使用，而不是作为一个独立的命令行工具。它的输入通常是文件路径或 `io.ReaderAt` 接口。

**使用者易犯错的点：**

一个常见的错误是**没有正确处理压缩节区**。直接读取压缩节区的 `ReaderAt` 可能会得到压缩的数据。应该使用 `Section.Open()` 获取 `io.ReadSeeker` 来读取解压后的数据，或者使用 `Section.Data()` 一次性获取解压后的全部数据。

例如，如果一个节区 `.zdebug_info` 使用了 ZLIB 压缩，直接使用 `section.sr.ReadAt()` 读取可能会得到错误的结果，因为读取的是压缩的数据。应该使用 `section.Open()` 返回的 `io.ReadSeeker` 进行读取。

**总结一下它的功能：**

这段代码实现了 Go 语言 `debug/elf` 包的核心功能，用于解析和表示 ELF 文件的结构。它定义了各种数据结构来映射 ELF 文件的组成部分，并提供了打开、关闭和访问 ELF 文件内容的方法，包括处理压缩节区和读取符号表。这是 Go 语言中用于处理 ELF 二进制文件的基础库。

Prompt: 
```
这是路径为go/src/debug/elf/file.go的go语言实现的一部分， 请列举一下它的功能, 　
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

/*
Package elf implements access to ELF object files.

# Security

This package is not designed to be hardened against adversarial inputs, and is
outside the scope of https://go.dev/security/policy. In particular, only basic
validation is done when parsing object files. As such, care should be taken when
parsing untrusted inputs, as parsing malformed files may consume significant
resources, or cause panics.
*/
package elf

import (
	"bytes"
	"compress/zlib"
	"debug/dwarf"
	"encoding/binary"
	"errors"
	"fmt"
	"internal/saferio"
	"internal/zstd"
	"io"
	"os"
	"strings"
	"unsafe"
)

// TODO: error reporting detail

/*
 * Internal ELF representation
 */

// A FileHeader represents an ELF file header.
type FileHeader struct {
	Class      Class
	Data       Data
	Version    Version
	OSABI      OSABI
	ABIVersion uint8
	ByteOrder  binary.ByteOrder
	Type       Type
	Machine    Machine
	Entry      uint64
}

// A File represents an open ELF file.
type File struct {
	FileHeader
	Sections    []*Section
	Progs       []*Prog
	closer      io.Closer
	dynVers     []DynamicVersion
	dynVerNeeds []DynamicVersionNeed
	gnuVersym   []byte
}

// A SectionHeader represents a single ELF section header.
type SectionHeader struct {
	Name      string
	Type      SectionType
	Flags     SectionFlag
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64

	// FileSize is the size of this section in the file in bytes.
	// If a section is compressed, FileSize is the size of the
	// compressed data, while Size (above) is the size of the
	// uncompressed data.
	FileSize uint64
}

// A Section represents a single section in an ELF file.
type Section struct {
	SectionHeader

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	//
	// ReaderAt may be nil if the section is not easily available
	// in a random-access form. For example, a compressed section
	// may have a nil ReaderAt.
	io.ReaderAt
	sr *io.SectionReader

	compressionType   CompressionType
	compressionOffset int64
}

// Data reads and returns the contents of the ELF section.
// Even if the section is stored compressed in the ELF file,
// Data returns uncompressed data.
//
// For an [SHT_NOBITS] section, Data always returns a non-nil error.
func (s *Section) Data() ([]byte, error) {
	return saferio.ReadData(s.Open(), s.Size)
}

// stringTable reads and returns the string table given by the
// specified link value.
func (f *File) stringTable(link uint32) ([]byte, error) {
	if link <= 0 || link >= uint32(len(f.Sections)) {
		return nil, errors.New("section has invalid string table link")
	}
	return f.Sections[link].Data()
}

// Open returns a new ReadSeeker reading the ELF section.
// Even if the section is stored compressed in the ELF file,
// the ReadSeeker reads uncompressed data.
//
// For an [SHT_NOBITS] section, all calls to the opened reader
// will return a non-nil error.
func (s *Section) Open() io.ReadSeeker {
	if s.Type == SHT_NOBITS {
		return io.NewSectionReader(&nobitsSectionReader{}, 0, int64(s.Size))
	}

	var zrd func(io.Reader) (io.ReadCloser, error)
	if s.Flags&SHF_COMPRESSED == 0 {

		if !strings.HasPrefix(s.Name, ".zdebug") {
			return io.NewSectionReader(s.sr, 0, 1<<63-1)
		}

		b := make([]byte, 12)
		n, _ := s.sr.ReadAt(b, 0)
		if n != 12 || string(b[:4]) != "ZLIB" {
			return io.NewSectionReader(s.sr, 0, 1<<63-1)
		}

		s.compressionOffset = 12
		s.compressionType = COMPRESS_ZLIB
		s.Size = binary.BigEndian.Uint64(b[4:12])
		zrd = zlib.NewReader

	} else if s.Flags&SHF_ALLOC != 0 {
		return errorReader{&FormatError{int64(s.Offset),
			"SHF_COMPRESSED applies only to non-allocable sections", s.compressionType}}
	}

	switch s.compressionType {
	case COMPRESS_ZLIB:
		zrd = zlib.NewReader
	case COMPRESS_ZSTD:
		zrd = func(r io.Reader) (io.ReadCloser, error) {
			return io.NopCloser(zstd.NewReader(r)), nil
		}
	}

	if zrd == nil {
		return errorReader{&FormatError{int64(s.Offset), "unknown compression type", s.compressionType}}
	}

	return &readSeekerFromReader{
		reset: func() (io.Reader, error) {
			fr := io.NewSectionReader(s.sr, s.compressionOffset, int64(s.FileSize)-s.compressionOffset)
			return zrd(fr)
		},
		size: int64(s.Size),
	}
}

// A ProgHeader represents a single ELF program header.
type ProgHeader struct {
	Type   ProgType
	Flags  ProgFlag
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

// A Prog represents a single ELF program header in an ELF binary.
type Prog struct {
	ProgHeader

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
}

// Open returns a new ReadSeeker reading the ELF program body.
func (p *Prog) Open() io.ReadSeeker { return io.NewSectionReader(p.sr, 0, 1<<63-1) }

// A Symbol represents an entry in an ELF symbol table section.
type Symbol struct {
	Name        string
	Info, Other byte

	// HasVersion reports whether the symbol has any version information.
	// This will only be true for the dynamic symbol table.
	HasVersion bool
	// VersionIndex is the symbol's version index.
	// Use the methods of the [VersionIndex] type to access it.
	// This field is only meaningful if HasVersion is true.
	VersionIndex VersionIndex

	Section     SectionIndex
	Value, Size uint64

	// These fields are present only for the dynamic symbol table.
	Version string
	Library string
}

/*
 * ELF reader
 */

type FormatError struct {
	off int64
	msg string
	val any
}

func (e *FormatError) Error() string {
	msg := e.msg
	if e.val != nil {
		msg += fmt.Sprintf(" '%v' ", e.val)
	}
	msg += fmt.Sprintf("in record at byte %#x", e.off)
	return msg
}

// Open opens the named file using [os.Open] and prepares it for use as an ELF binary.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ff.closer = f
	return ff, nil
}

// Close closes the [File].
// If the [File] was created using [NewFile] directly instead of [Open],
// Close has no effect.
func (f *File) Close() error {
	var err error
	if f.closer != nil {
		err = f.closer.Close()
		f.closer = nil
	}
	return err
}

// SectionByType returns the first section in f with the
// given type, or nil if there is no such section.
func (f *File) SectionByType(typ SectionType) *Section {
	for _, s := range f.Sections {
		if s.Type == typ {
			return s
		}
	}
	return nil
}

// NewFile creates a new [File] for accessing an ELF binary in an underlying reader.
// The ELF binary is expected to start at position 0 in the ReaderAt.
func NewFile(r io.ReaderAt) (*File, error) {
	sr := io.NewSectionReader(r, 0, 1<<63-1)
	// Read and decode ELF identifier
	var ident [16]uint8
	if _, err := r.ReadAt(ident[0:], 0); err != nil {
		return nil, err
	}
	if ident[0] != '\x7f' || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {
		return nil, &FormatError{0, "bad magic number", ident[0:4]}
	}

	f := new(File)
	f.Class = Class(ident[EI_CLASS])
	switch f.Class {
	case ELFCLASS32:
	case ELFCLASS64:
		// ok
	default:
		return nil, &FormatError{0, "unknown ELF class", f.Class}
	}

	f.Data = Data(ident[EI_DATA])
	var bo binary.ByteOrder
	switch f.Data {
	case ELFDATA2LSB:
		bo = binary.LittleEndian
	case ELFDATA2MSB:
		bo = binary.BigEndian
	default:
		return nil, &FormatError{0, "unknown ELF data encoding", f.Data}
	}
	f.ByteOrder = bo

	f.Version = Version(ident[EI_VERSION])
	if f.Version != EV_CURRENT {
		return nil, &FormatError{0, "unknown ELF version", f.Version}
	}

	f.OSABI = OSABI(ident[EI_OSABI])
	f.ABIVersion = ident[EI_ABIVERSION]

	// Read ELF file header
	var phoff int64
	var phentsize, phnum int
	var shoff int64
	var shentsize, shnum, shstrndx int
	switch f.Class {
	case ELFCLASS32:
		var hdr Header32
		data := make([]byte, unsafe.Sizeof(hdr))
		if _, err := sr.ReadAt(data, 0); err != nil {
			return nil, err
		}
		f.Type = Type(bo.Uint16(data[unsafe.Offsetof(hdr.Type):]))
		f.Machine = Machine(bo.Uint16(data[unsafe.Offsetof(hdr.Machine):]))
		f.Entry = uint64(bo.Uint32(data[unsafe.Offsetof(hdr.Entry):]))
		if v := Version(bo.Uint32(data[unsafe.Offsetof(hdr.Version):])); v != f.Version {
			return nil, &FormatError{0, "mismatched ELF version", v}
		}
		phoff = int64(bo.Uint32(data[unsafe.Offsetof(hdr.Phoff):]))
		phentsize = int(bo.Uint16(data[unsafe.Offsetof(hdr.Phentsize):]))
		phnum = int(bo.Uint16(data[unsafe.Offsetof(hdr.Phnum):]))
		shoff = int64(bo.Uint32(data[unsafe.Offsetof(hdr.Shoff):]))
		shentsize = int(bo.Uint16(data[unsafe.Offsetof(hdr.Shentsize):]))
		shnum = int(bo.Uint16(data[unsafe.Offsetof(hdr.Shnum):]))
		shstrndx = int(bo.Uint16(data[unsafe.Offsetof(hdr.Shstrndx):]))
	case ELFCLASS64:
		var hdr Header64
		data := make([]byte, unsafe.Sizeof(hdr))
		if _, err := sr.ReadAt(data, 0); err != nil {
			return nil, err
		}
		f.Type = Type(bo.Uint16(data[unsafe.Offsetof(hdr.Type):]))
		f.Machine = Machine(bo.Uint16(data[unsafe.Offsetof(hdr.Machine):]))
		f.Entry = bo.Uint64(data[unsafe.Offsetof(hdr.Entry):])
		if v := Version(bo.Uint32(data[unsafe.Offsetof(hdr.Version):])); v != f.Version {
			return nil, &FormatError{0, "mismatched ELF version", v}
		}
		phoff = int64(bo.Uint64(data[unsafe.Offsetof(hdr.Phoff):]))
		phentsize = int(bo.Uint16(data[unsafe.Offsetof(hdr.Phentsize):]))
		phnum = int(bo.Uint16(data[unsafe.Offsetof(hdr.Phnum):]))
		shoff = int64(bo.Uint64(data[unsafe.Offsetof(hdr.Shoff):]))
		shentsize = int(bo.Uint16(data[unsafe.Offsetof(hdr.Shentsize):]))
		shnum = int(bo.Uint16(data[unsafe.Offsetof(hdr.Shnum):]))
		shstrndx = int(bo.Uint16(data[unsafe.Offsetof(hdr.Shstrndx):]))
	}

	if shoff < 0 {
		return nil, &FormatError{0, "invalid shoff", shoff}
	}
	if phoff < 0 {
		return nil, &FormatError{0, "invalid phoff", phoff}
	}

	if shoff == 0 && shnum != 0 {
		return nil, &FormatError{0, "invalid ELF shnum for shoff=0", shnum}
	}

	if shnum > 0 && shstrndx >= shnum {
		return nil, &FormatError{0, "invalid ELF shstrndx", shstrndx}
	}

	var wantPhentsize, wantShentsize int
	switch f.Class {
	case ELFCLASS32:
		wantPhentsize = 8 * 4
		wantShentsize = 10 * 4
	case ELFCLASS64:
		wantPhentsize = 2*4 + 6*8
		wantShentsize = 4*4 + 6*8
	}
	if phnum > 0 && phentsize < wantPhentsize {
		return nil, &FormatError{0, "invalid ELF phentsize", phentsize}
	}

	// Read program headers
	f.Progs = make([]*Prog, phnum)
	phdata, err := saferio.ReadDataAt(sr, uint64(phnum)*uint64(phentsize), phoff)
	if err != nil {
		return nil, err
	}
	for i := 0; i < phnum; i++ {
		off := uintptr(i) * uintptr(phentsize)
		p := new(Prog)
		switch f.Class {
		case ELFCLASS32:
			var ph Prog32
			p.ProgHeader = ProgHeader{
				Type:   ProgType(bo.Uint32(phdata[off+unsafe.Offsetof(ph.Type):])),
				Flags:  ProgFlag(bo.Uint32(phdata[off+unsafe.Offsetof(ph.Flags):])),
				Off:    uint64(bo.Uint32(phdata[off+unsafe.Offsetof(ph.Off):])),
				Vaddr:  uint64(bo.Uint32(phdata[off+unsafe.Offsetof(ph.Vaddr):])),
				Paddr:  uint64(bo.Uint32(phdata[off+unsafe.Offsetof(ph.Paddr):])),
				Filesz: uint64(bo.Uint32(phdata[off+unsafe.Offsetof(ph.Filesz):])),
				Memsz:  uint64(bo.Uint32(phdata[off+unsafe.Offsetof(ph.Memsz):])),
				Align:  uint64(bo.Uint32(phdata[off+unsafe.Offsetof(ph.Align):])),
			}
		case ELFCLASS64:
			var ph Prog64
			p.ProgHeader = ProgHeader{
				Type:   ProgType(bo.Uint32(phdata[off+unsafe.Offsetof(ph.Type):])),
				Flags:  ProgFlag(bo.Uint32(phdata[off+unsafe.Offsetof(ph.Flags):])),
				Off:    bo.Uint64(phdata[off+unsafe.Offsetof(ph.Off):]),
				Vaddr:  bo.Uint64(phdata[off+unsafe.Offsetof(ph.Vaddr):]),
				Paddr:  bo.Uint64(phdata[off+unsafe.Offsetof(ph.Paddr):]),
				Filesz: bo.Uint64(phdata[off+unsafe.Offsetof(ph.Filesz):]),
				Memsz:  bo.Uint64(phdata[off+unsafe.Offsetof(ph.Memsz):]),
				Align:  bo.Uint64(phdata[off+unsafe.Offsetof(ph.Align):]),
			}
		}
		if int64(p.Off) < 0 {
			return nil, &FormatError{phoff + int64(off), "invalid program header offset", p.Off}
		}
		if int64(p.Filesz) < 0 {
			return nil, &FormatError{phoff + int64(off), "invalid program header file size", p.Filesz}
		}
		p.sr = io.NewSectionReader(r, int64(p.Off), int64(p.Filesz))
		p.ReaderAt = p.sr
		f.Progs[i] = p
	}

	// If the number of sections is greater than or equal to SHN_LORESERVE
	// (0xff00), shnum has the value zero and the actual number of section
	// header table entries is contained in the sh_size field of the section
	// header at index 0.
	if shoff > 0 && shnum == 0 {
		var typ, link uint32
		sr.Seek(shoff, io.SeekStart)
		switch f.Class {
		case ELFCLASS32:
			sh := new(Section32)
			if err := binary.Read(sr, bo, sh); err != nil {
				return nil, err
			}
			shnum = int(sh.Size)
			typ = sh.Type
			link = sh.Link
		case ELFCLASS64:
			sh := new(Section64)
			if err := binary.Read(sr, bo, sh); err != nil {
				return nil, err
			}
			shnum = int(sh.Size)
			typ = sh.Type
			link = sh.Link
		}
		if SectionType(typ) != SHT_NULL {
			return nil, &FormatError{shoff, "invalid type of the initial section", SectionType(typ)}
		}

		if shnum < int(SHN_LORESERVE) {
			return nil, &FormatError{shoff, "invalid ELF shnum contained in sh_size", shnum}
		}

		// If the section name string table section index is greater than or
		// equal to SHN_LORESERVE (0xff00), this member has the value
		// SHN_XINDEX (0xffff) and the actual index of the section name
		// string table section is contained in the sh_link field of the
		// section header at index 0.
		if shstrndx == int(SHN_XINDEX) {
			shstrndx = int(link)
			if shstrndx < int(SHN_LORESERVE) {
				return nil, &FormatError{shoff, "invalid ELF shstrndx contained in sh_link", shstrndx}
			}
		}
	}

	if shnum > 0 && shentsize < wantShentsize {
		return nil, &FormatError{0, "invalid ELF shentsize", shentsize}
	}

	// Read section headers
	c := saferio.SliceCap[Section](uint64(shnum))
	if c < 0 {
		return nil, &FormatError{0, "too many sections", shnum}
	}
	if shnum > 0 && ((1<<64)-1)/uint64(shnum) < uint64(shentsize) {
		return nil, &FormatError{0, "section header overflow", shnum}
	}
	f.Sections = make([]*Section, 0, c)
	names := make([]uint32, 0, c)
	shdata, err := saferio.ReadDataAt(sr, uint64(shnum)*uint64(shentsize), shoff)
	if err != nil {
		return nil, err
	}
	for i := 0; i < shnum; i++ {
		off := uintptr(i) * uintptr(shentsize)
		s := new(Section)
		switch f.Class {
		case ELFCLASS32:
			var sh Section32
			names = append(names, bo.Uint32(shdata[off+unsafe.Offsetof(sh.Name):]))
			s.SectionHeader = SectionHeader{
				Type:      SectionType(bo.Uint32(shdata[off+unsafe.Offsetof(sh.Type):])),
				Flags:     SectionFlag(bo.Uint32(shdata[off+unsafe.Offsetof(sh.Flags):])),
				Addr:      uint64(bo.Uint32(shdata[off+unsafe.Offsetof(sh.Addr):])),
				Offset:    uint64(bo.Uint32(shdata[off+unsafe.Offsetof(sh.Off):])),
				FileSize:  uint64(bo.Uint32(shdata[off+unsafe.Offsetof(sh.Size):])),
				Link:      bo.Uint32(shdata[off+unsafe.Offsetof(sh.Link):]),
				Info:      bo.Uint32(shdata[off+unsafe.Offsetof(sh.Info):]),
				Addralign: uint64(bo.Uint32(shdata[off+unsafe.Offsetof(sh.Addralign):])),
				Entsize:   uint64(bo.Uint32(shdata[off+unsafe.Offsetof(sh.Entsize):])),
			}
		case ELFCLASS64:
			var sh Section64
			names = append(names, bo.Uint32(shdata[off+unsafe.Offsetof(sh.Name):]))
			s.SectionHeader = SectionHeader{
				Type:      SectionType(bo.Uint32(shdata[off+unsafe.Offsetof(sh.Type):])),
				Flags:     SectionFlag(bo.Uint64(shdata[off+unsafe.Offsetof(sh.Flags):])),
				Offset:    bo.Uint64(shdata[off+unsafe.Offsetof(sh.Off):]),
				FileSize:  bo.Uint64(shdata[off+unsafe.Offsetof(sh.Size):]),
				Addr:      bo.Uint64(shdata[off+unsafe.Offsetof(sh.Addr):]),
				Link:      bo.Uint32(shdata[off+unsafe.Offsetof(sh.Link):]),
				Info:      bo.Uint32(shdata[off+unsafe.Offsetof(sh.Info):]),
				Addralign: bo.Uint64(shdata[off+unsafe.Offsetof(sh.Addralign):]),
				Entsize:   bo.Uint64(shdata[off+unsafe.Offsetof(sh.Entsize):]),
			}
		}
		if int64(s.Offset) < 0 {
			return nil, &FormatError{shoff + int64(off), "invalid section offset", int64(s.Offset)}
		}
		if int64(s.FileSize) < 0 {
			return nil, &FormatError{shoff + int64(off), "invalid section size", int64(s.FileSize)}
		}
		s.sr = io.NewSectionReader(r, int64(s.Offset), int64(s.FileSize))

		if s.Flags&SHF_COMPRESSED == 0 {
			s.ReaderAt = s.sr
			s.Size = s.FileSize
		} else {
			// Read the compression header.
			switch f.Class {
			case ELFCLASS32:
				var ch Chdr32
				chdata := make([]byte, unsafe.Sizeof(ch))
				if _, err := s.sr.ReadAt(chdata, 0); err != nil {
					return nil, err
				}
				s.compressionType = CompressionType(bo.Uint32(chdata[unsafe.Offsetof(ch.Type):]))
				s.Size = uint64(bo.Uint32(chdata[unsafe.Offsetof(ch.Size):]))
				s.Addralign = uint64(bo.Uint32(chdata[unsafe.Offsetof(ch.Addralign):]))
				s.compressionOffset = int64(unsafe.Sizeof(ch))
			case ELFCLASS64:
				var ch Chdr64
				chdata := make([]byte, unsafe.Sizeof(ch))
				if _, err := s.sr.ReadAt(chdata, 0); err != nil {
					return nil, err
				}
				s.compressionType = CompressionType(bo.Uint32(chdata[unsafe.Offsetof(ch.Type):]))
				s.Size = bo.Uint64(chdata[unsafe.Offsetof(ch.Size):])
				s.Addralign = bo.Uint64(chdata[unsafe.Offsetof(ch.Addralign):])
				s.compressionOffset = int64(unsafe.Sizeof(ch))
			}
		}

		f.Sections = append(f.Sections, s)
	}

	if len(f.Sections) == 0 {
		return f, nil
	}

	// Load section header string table.
	if shstrndx == 0 {
		// If the file has no section name string table,
		// shstrndx holds the value SHN_UNDEF (0).
		return f, nil
	}
	shstr := f.Sections[shstrndx]
	if shstr.Type != SHT_STRTAB {
		return nil, &FormatError{shoff + int64(shstrndx*shentsize), "invalid ELF section name string table type", shstr.Type}
	}
	shstrtab, err := shstr.Data()
	if err != nil {
		return nil, err
	}
	for i, s := range f.Sections {
		var ok bool
		s.Name, ok = getString(shstrtab, int(names[i]))
		if !ok {
			return nil, &FormatError{shoff + int64(i*shentsize), "bad section name index", names[i]}
		}
	}

	return f, nil
}

// getSymbols returns a slice of Symbols from parsing the symbol table
// with the given type, along with the associated string table.
func (f *File) getSymbols(typ SectionType) ([]Symbol, []byte, error) {
	switch f.Class {
	case ELFCLASS64:
		return f.getSymbols64(typ)

	case ELFCLASS32:
		return f.getSymbols32(typ)
	}

	return nil, nil, errors.New("not implemented")
}

// ErrNoSymbols is returned by [File.Symbols] and [File.DynamicSymbols]
// if there is no such section in the File.
var ErrNoSymbols = errors.New("no symbol section")

func (f *File) getSymbols32(typ SectionType) ([]Symbol, []byte, error) {
	symtabSection := f.SectionByType(typ)
	if symtabSection == nil {
		return nil, nil, ErrNoSymbols
	}

	data, err := symtabSection.Data()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot load symbol section: %w", err)
	}
	if len(data) == 0 {
		return nil, nil, errors.New("symbol section is empty")
	}
	if len(data)%Sym32Size != 0 {
		return nil, nil, errors.New("length of symbol section is not a multiple of SymSize")
	}

	strdata, err := f.stringTable(symtabSection.Link)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot load string table section: %w", err)
	}

	// The first entry is all zeros.
	data = data[Sym32Size:]

	symbols := make([]Symbol, len(data)/Sym32Size)

	i := 0
	var sym Sym32
	for len(data) > 0 {
		sym.Name = f.ByteOrder.Uint32(data[0:4])
		sym.Value = f.ByteOrder.Uint32(data[4:8])
		sym.Size = f.ByteOrder.Uint32(data[8:12])
		sym.Info = data[12]
		sym.Other = data[13]
		sym.Shndx = f.ByteOrder.Uint16(data[14:16])
		str, _ := getString(strdata, int(sym.Name))
		symbols[i].Name = str
		symbols[i].Info = sym.Info
		symbols[i].Other = sym.Other
		symbols[i].Section = SectionIndex(sym.Shndx)
		symbols[i].Value = uint64(sym.Value)
		symbols[i].Size = uint64(sym.Size)
		i++
		data = data[Sym32Size:]
	}

	return symbols, strdata, nil
}

func (f *File) getSymbols64(typ SectionType) ([]Symbol, []byte, error) {
	symtabSection := f.SectionByType(typ)
	if symtabSection == nil {
		return nil, nil, ErrNoSymbols
	}

	data, err := symtabSection.Data()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot load symbol section: %w", err)
	}
	if len(data)%Sym64Size != 0 {
		return nil, nil, errors.New("length of symbol section is not a multiple of Sym64Size")
	}

	strdata, err := f.stringTable(symtabSection.Link)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot load string table section: %w", err)
	}

	// The first entry is all zeros.
	data = data[Sym64Size:]

	symbols := make([]Symbol, len(data)/Sym64Size)

	i := 0
	var sym Sym64
	for len(data) > 0 {
		sym.Name = f.ByteOrder.Uint32(data[0:4])
		sym.Info = data[4]
		sym.Other = data[5]
		sym.Shndx = f.ByteOrder.Uint16(data[6:8])
		sym.Value = f.ByteOrder.Uint64(data[8:16])
		sym.Size = f.ByteOrder.Uint64(data[16:24])
		str, _ := getString(strdata, int(sym.Name))
		symbols[i].Name = str
		symbols[i].Info = sym.Info
		symbols[i].Other = sym.Other
		symbols[i].Section = SectionIndex(sym.Shndx)
		symbols[i].Value = sym.Value
		symbols[i].Size = sym.Size
		i++
		data = data[Sym64Size:]
	}

	return symbols, strdata, nil
}

// getString extracts a string from an ELF string table.
func getString(section []byte, start int) (string, bool) {
	if start < 0 || start >= len(section) {
		return "", false
	}

	for end := start; end < len(section); end++ {
		if section[end] == 0 {
			return string(section[start:end]), true
		}
	}
	return "", false
}

// Section returns a section with the given name, or nil if no such
// section exists.
func (f *File) Section(name string) *Section {
	for _, s := range f.Sections {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// applyRelocations applies relocations to dst. rels is a relocations section
// in REL or RELA format.
func (f *File) applyRelocations(dst []byte, rels []byte) error {
	switch {
	case f.Class == ELFCLASS64 && f.Machine == EM_X86_64:
		return f.applyRelocationsAMD64(dst, rels)
	case f.Class == ELFCLASS32 && f.Machine == EM_386:
		return f.applyRelocations386(dst, rels)
	case f.Class == ELFCLASS32 && f.Machine == EM_ARM:
		return f.applyRelocationsARM(dst, rels)
	case f.Class == ELFCLASS64 && f.Machine == EM_AARCH64:
		return f.applyRelocationsARM64(dst, rels)
	case f.Class == ELFCLASS32 && f.Machine == EM_PPC:
		return f.applyRelocationsPPC(dst, rels)
	case f.Class == ELFCLASS64 && f.Machine == EM_PPC64:
		return f.applyRelocationsPPC64(dst, rels)
	case f.Class == ELFCLASS32 && f.Machine == EM_MIPS:
		return f.applyRelocationsMIPS(dst, rels)
	case f.Class == ELFCLASS64 && f.Machine == EM_MIPS:
		return f.applyRelocationsMIPS64(dst, rels)
	case f.Class == ELFCLASS64 && f.Machine == EM_LOONGARCH:
		return f.applyRelocationsLOONG64(dst, rels)
	case f.Class == ELFCLASS64 && f.Machine == EM_RISCV:
		return f.applyRelocationsRISCV64(dst, rels)
	case f.Class == ELFCLASS64 && f.Machine == EM_S390:
		return f.applyRelocationss390x(dst, rels)
	case f.Class == ELFCLASS64 && f.Machine == EM_SPARCV9:
		return f.applyRelocationsSPARC64(dst, rels)
	default:
		return errors.New("applyRelocations: not implemented")
	}
}

// canApplyRelocation reports whether we should try to apply a
// relocation to a DWARF data section, given a pointer to the symbol
// targeted by the relocation.
// Most relocations in DWARF data tend to be section-relative, but
// some target non-section symbols (for example, low_PC attrs on
// subprogram or compilation unit DIEs that target function symbols).
func canApplyRelocation(sym *Symbol) bool {
	return sym.Section != SHN_UNDEF && sym.Section < SHN_LORESERVE
}

func (f *File) applyRelocationsAMD64(dst []byte, rels []byte) error {
	// 24 is the size of Rela64.
	if len(rels)%24 != 0 {
		return errors.New("length of relocation section is not a multiple of 24")
	}

	symbols, _, err := f.getSymbols(SHT_SYMTAB)
	if err != nil {
		return err
	}

	b := bytes.NewReader(rels)
	var rela Rela64

	for b.Len() > 0 {
		binary.Read(b, f.ByteOrder, &rela)
		symNo := rela.Info >> 32
		t := R_X86_64(rela.Info & 0xffff)

		if symNo == 0 || symNo > uint64(len(symbols)) {
			continue
		}
		sym := &symbols[symNo-1]
		if !canApplyRelocation(sym) {
			continue
		}

		// There are relocations, so this must be a normal
		// object file.  The code below handles only basic relocations
		// of the form S + A (symbol plus addend).

		switch t {
		case R_X86_64_64:
			if rela.Off+8 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val64 := sym.Value + uint64(rela.Addend)
			f.ByteOrder.PutUint64(dst[rela.Off:rela.Off+8], val64)
		case R_X86_64_32:
			if rela.Off+4 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val32 := uint32(sym.Value) + uint32(rela.Addend)
			f.ByteOrder.PutUint32(dst[rela.Off:rela.Off+4], val32)
		}
	}

	return nil
}

func (f *File) applyRelocations386(dst []byte, rels []byte) error {
	// 8 is the size of Rel32.
	if len(rels)%8 != 0 {
		return errors.New("length of relocation section is not a multiple of 8")
	}

	symbols, _, err := f.getSymbols(SHT_SYMTAB)
	if err != nil {
		return err
	}

	b := bytes.NewReader(rels)
	var rel Rel32

	for b.Len() > 0 {
		binary.Read(b, f.ByteOrder, &rel)
		symNo := rel.Info >> 8
		t := R_386(rel.Info & 0xff)

		if symNo == 0 || symNo > uint32(len(symbols)) {
			continue
		}
		sym := &symbols[symNo-1]

		if t == R_386_32 {
			if rel.Off+4 >= uint32(len(dst)) {
				continue
			}
			val := f.ByteOrder.Uint32(dst[rel.Off : rel.Off+4])
			val += uint32(sym.Value)
			f.ByteOrder.PutUint32(dst[rel.Off:rel.Off+4], val)
		}
	}

	return nil
}

func (f *File) applyRelocationsARM(dst []byte, rels []byte) error {
	// 8 is the size of Rel32.
	if len(rels)%8 != 0 {
		return errors.New("length of relocation section is not a multiple of 8")
	}

	symbols, _, err := f.getSymbols(SHT_SYMTAB)
	if err != nil {
		return err
	}

	b := bytes.NewReader(rels)
	var rel Rel32

	for b.Len() > 0 {
		binary.Read(b, f.ByteOrder, &rel)
		symNo := rel.Info >> 8
		t := R_ARM(rel.Info & 0xff)

		if symNo == 0 || symNo > uint32(len(symbols)) {
			continue
		}
		sym := &symbols[symNo-1]

		switch t {
		case R_ARM_ABS32:
			if rel.Off+4 >= uint32(len(dst)) {
				continue
			}
			val := f.ByteOrder.Uint32(dst[rel.Off : rel.Off+4])
			val += uint32(sym.Value)
			f.ByteOrder.PutUint32(dst[rel.Off:rel.Off+4], val)
		}
	}

	return nil
}

func (f *File) applyRelocationsARM64(dst []byte, rels []byte) error {
	// 24 is the size of Rela64.
	if len(rels)%24 != 0 {
		return errors.New("length of relocation section is not a multiple of 24")
	}

	symbols, _, err := f.getSymbols(SHT_SYMTAB)
	if err != nil {
		return err
	}

	b := bytes.NewReader(rels)
	var rela Rela64

	for b.Len() > 0 {
		binary.Read(b, f.ByteOrder, &rela)
		symNo := rela.Info >> 32
		t := R_AARCH64(rela.Info & 0xffff)

		if symNo == 0 || symNo > uint64(len(symbols)) {
			continue
		}
		sym := &symbols[symNo-1]
		if !canApplyRelocation(sym) {
			continue
		}

		// There are relocations, so this must be a normal
		// object file.  The code below handles only basic relocations
		// of the form S + A (symbol plus addend).

		switch t {
		case R_AARCH64_ABS64:
			if rela.Off+8 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val64 := sym.Value + uint64(rela.Addend)
			f.ByteOrder.PutUint64(dst[rela.Off:rela.Off+8], val64)
		case R_AARCH64_ABS32:
			if rela.Off+4 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val32 := uint32(sym.Value) + uint32(rela.Addend)
			f.ByteOrder.PutUint32(dst[rela.Off:rela.Off+4], val32)
		}
	}

	return nil
}

func (f *File) applyRelocationsPPC(dst []byte, rels []byte) error {
	// 12 is the size of Rela32.
	if len(rels)%12 != 0 {
		return errors.New("length of relocation section is not a multiple of 12")
	}

	symbols, _, err := f.getSymbols(SHT_SYMTAB)
	if err != nil {
		return err
	}

	b := bytes.NewReader(rels)
	var rela Rela32

	for b.Len() > 0 {
		binary.Read(b, f.ByteOrder, &rela)
		symNo := rela.Info >> 8
		t := R_PPC(rela.Info & 0xff)

		if symNo == 0 || symNo > uint32(len(symbols)) {
			continue
		}
		sym := &symbols[symNo-1]
		if !canApplyRelocation(sym) {
			continue
		}

		switch t {
		case R_PPC_ADDR32:
			if rela.Off+4 >= uint32(len(dst)) || rela.Addend < 0 {
				continue
			}
			val32 := uint32(sym.Value) + uint32(rela.Addend)
			f.ByteOrder.PutUint32(dst[rela.Off:rela.Off+4], val32)
		}
	}

	return nil
}

func (f *File) applyRelocationsPPC64(dst []byte, rels []byte) error {
	// 24 is the size of Rela64.
	if len(rels)%24 != 0 {
		return errors.New("length of relocation section is not a multiple of 24")
	}

	symbols, _, err := f.getSymbols(SHT_SYMTAB)
	if err != nil {
		return err
	}

	b := bytes.NewReader(rels)
	var rela Rela64

	for b.Len() > 0 {
		binary.Read(b, f.ByteOrder, &rela)
		symNo := rela.Info >> 32
		t := R_PPC64(rela.Info & 0xffff)

		if symNo == 0 || symNo > uint64(len(symbols)) {
			continue
		}
		sym := &symbols[symNo-1]
		if !canApplyRelocation(sym) {
			continue
		}

		switch t {
		case R_PPC64_ADDR64:
			if rela.Off+8 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val64 := sym.Value + uint64(rela.Addend)
			f.ByteOrder.PutUint64(dst[rela.Off:rela.Off+8], val64)
		case R_PPC64_ADDR32:
			if rela.Off+4 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val32 := uint32(sym.Value) + uint32(rela.Addend)
			f.ByteOrder.PutUint32(dst[rela.Off:rela.Off+4], val32)
		}
	}

	return nil
}

func (f *File) applyRelocationsMIPS(dst []byte, rels []byte) error {
	// 8 is the size of Rel32.
	if len(rels)%8 != 0 {
		return errors.New("length of relocation section is not a multiple of 8")
	}

	symbols, _, err := f.getSymbols(SHT_SYMTAB)
	if err != nil {
		return err
	}

	b := bytes.NewReader(rels)
	var rel Rel32

	for b.Len() > 0 {
		binary.Read(b, f.ByteOrder, &rel)
		symNo := rel.Info >> 8
		t := R_MIPS(rel.Info & 0xff)

		if symNo == 0 || symNo > uint32(len(symbols)) {
			continue
		}
		sym := &symbols[symNo-1]

		switch t {
		case R_MIPS_32:
			if rel.Off+4 >= uint32(len(dst)) {
				continue
			}
			val := f.ByteOrder.Uint32(dst[rel.Off : rel.Off+4])
			val += uint32(sym.Value)
			f.ByteOrder.PutUint32(dst[rel.Off:rel.Off+4], val)
		}
	}

	return nil
}

func (f *File) applyRelocationsMIPS64(dst []byte, rels []byte) error {
	// 24 is the size of Rela64.
	if len(rels)%24 != 0 {
		return errors.New("length of relocation section is not a multiple of 24")
	}

	symbols, _, err := f.getSymbols(SHT_SYMTAB)
	if err != nil {
		return err
	}

	b := bytes.NewReader(rels)
	var rela Rela64

	for b.Len() > 0 {
		binary.Read(b, f.ByteOrder, &rela)
		var symNo uint64
		var t R_MIPS
		if f.ByteOrder == binary.BigEndian {
			symNo = rela.Info >> 32
			t = R_MIPS(rela.Info & 0xff)
		} else {
			symNo = rela.Info & 0xffffffff
			t = R_MIPS(rela.Info >> 56)
		}

		if symNo == 0 || symNo > uint64(len(symbols)) {
			continue
		}
		sym := &symbols[symNo-1]
		if !canApplyRelocation(sym) {
			continue
		}

		switch t {
		case R_MIPS_64:
			if rela.Off+8 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val64 := sym.Value + uint64(rela.Addend)
			f.ByteOrder.PutUint64(dst[rela.Off:rela.Off+8], val64)
		case R_MIPS_32:
			if rela.Off+4 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val32 := uint32(sym.Value) + uint32(rela.Addend)
			f.ByteOrder.PutUint32(dst[rela.Off:rela.Off+4], val32)
		}
	}

	return nil
}

func (f *File) applyRelocationsLOONG64(dst []byte, rels []byte) error {
	// 24 is the size of Rela64.
	if len(rels)%24 != 0 {
		return errors.New("length of relocation section is not a multiple of 24")
	}

	symbols, _, err := f.getSymbols(SHT_SYMTAB)
	if err != nil {
		return err
	}

	b := bytes.NewReader(rels)
	var rela Rela64

	for b.Len() > 0 {
		binary.Read(b, f.ByteOrder, &rela)
		var symNo uint64
		var t R_LARCH
		symNo = rela.Info >> 32
		t = R_LARCH(rela.Info & 0xffff)

		if symNo == 0 || symNo > uint64(len(symbols)) {
			continue
		}
		sym := &symbols[symNo-1]
		if !canApplyRelocation(sym) {
			continue
		}

		switch t {
		case R_LARCH_64:
			if rela.Off+8 >= uint64(len(dst)) || rela.Addend < 0 {
				continue
			}
			val64 := sym.Value + uint64(rela.Addend)
			f.ByteOrder.PutUint64(dst[rela.Off:rela.Off+8], val64)
		case R_LARCH_32:
			if rela.Off+4 >= uint64(len(dst)) || rela.Addend < 0
"""




```