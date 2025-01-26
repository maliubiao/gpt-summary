Response:
Let's break down the thought process for analyzing the provided Go code and generating the answer.

1. **Understand the Goal:** The request asks for a breakdown of the `buildinfo` package's functionality, including its purpose, examples, command-line interaction (if any), potential pitfalls, and explanations of internal mechanisms like code inference.

2. **Initial Scan and Keyword Identification:** I'd start by quickly reading the package documentation at the top and looking for keywords. "build information," "Go toolchain version," "modules," "currently running binary," `ReadFile`, `Read`, and the various platform-specific file format handling (`elf`, `macho`, `pe`, etc.) stand out. This gives a high-level idea of the package's core function: extracting build details from Go executables.

3. **Decomposition by Functionality:**  I'd then organize the analysis around the main functions and concepts:

    * **Core Purpose:** The package provides a way to access build information embedded in Go binaries. This is stated clearly in the package doc.

    * **Key Functions:** `ReadFile` and `Read` are the primary entry points. `ReadFile` takes a file path, while `Read` takes an `io.ReaderAt`. This suggests flexibility in how the binary data is accessed.

    * **Information Extracted:** The documentation mentions Go toolchain version and module information. The code itself reveals more details about how this information is located and parsed (the `buildInfoMagic`, header structure, etc.).

    * **File Format Support:** The code has `switch` statements based on magic numbers (`\x7FELF`, `MZ`, etc.), indicating support for different executable formats (ELF, PE, Mach-O, etc.). This is a significant aspect of the package.

    * **Build Information Location:**  The code mentions searching for a special section (`.go.buildinfo` for ELF) or within the data segment. This is important for understanding the internal workings.

    * **Error Handling:** The code defines `errUnrecognizedFormat` and `errNotGoExe`, signaling different failure scenarios. The `linkname` comment about `errNotGoExe` is a notable detail.

4. **Code Inference and Examples:**

    * **Core Use Case (ReadFile):**  The most straightforward use case is reading build info from a file. I'd construct a simple example demonstrating this. I need a Go binary, so I'd compile a simple program. The output of `ReadFile` is a `BuildInfo` struct, which I'd then access.

    * **Core Use Case (Read):**  To demonstrate `Read`, I need to show how to get an `io.ReaderAt`. Opening the file and passing the `os.File` is the obvious approach.

    * **Internal Mechanism (readRawBuildInfo):**  This function is crucial. I'd focus on its role in locating the magic string and parsing the header. While providing a full code example for this internal function isn't practical for the user, I'd describe its steps: identify file format, find data segment, search for the magic, and parse the header.

    * **Header Structure:** The code reveals the structure of the build info header and the distinction between older and newer formats (using pointers vs. inline strings). This is important to explain.

5. **Command-Line Arguments:** I'd carefully examine the `ReadFile` function. It takes a filename as an argument. This is the primary way users interact with the package through the command line (indirectly, by calling a program that uses this package).

6. **Potential Pitfalls:**

    * **File Not Found/Permissions:**  The standard `os.Open` errors are possible.
    * **Incorrect File Format:**  Providing a non-executable file or an executable in an unsupported format would lead to errors.
    * **Not a Go Executable:**  Providing an executable not built with Go would also cause an error.
    * **Changes in Go Versions:** The code handles different build info formats. A user might encounter issues if they try to use an older version of the library with a newer Go binary (though the code tries to be forward-compatible).

7. **Structure and Language:** I'd organize the answer logically, starting with the basic functionality and then diving into more technical details. Using clear and concise language, avoiding jargon where possible, and providing code examples are important. The request specifically asked for Chinese, so the entire response would be in Chinese.

8. **Review and Refinement:**  After drafting the answer, I'd review it to ensure accuracy, completeness, and clarity. I'd double-check the code examples and ensure they compile and demonstrate the intended functionality. I'd also ensure that all parts of the original request are addressed.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe provide overly detailed code examples for internal functions.
* **Correction:** Realized that focusing on the public API (`ReadFile`, `Read`) is more useful for the user. Briefly explain the internal mechanisms instead of providing complex code.

* **Initial thought:**  Focus heavily on the different executable formats.
* **Correction:**  While important, emphasize the *purpose* of this format detection – locating the build information – rather than just listing the formats.

* **Initial thought:** Missed the detail about the two different build info header formats.
* **Correction:**  Recognized the `flagsVersionMask` check and added an explanation of the pre-Go 1.18 and post-Go 1.18 differences.

By following these steps, breaking down the problem, and iteratively refining the analysis, I can construct a comprehensive and accurate answer like the example provided in the initial prompt.
这段Go语言代码是 `debug/buildinfo` 包的一部分，其主要功能是**读取并解析嵌入在Go二进制文件中的构建信息**。 这些信息包括用于构建该二进制文件的 Go 工具链版本以及所使用的模块（对于以模块模式构建的二进制文件）。

更具体地说，`buildinfo.go` 实现了以下功能：

1. **读取二进制文件:**  提供了 `ReadFile` 函数，该函数接受一个文件路径作为参数，打开该文件，并调用 `Read` 函数来处理文件内容。
2. **读取 `io.ReaderAt`:** 提供了 `Read` 函数，该函数接受一个 `io.ReaderAt` 接口作为参数，允许从不同的数据源（不仅仅是文件）读取二进制数据。
3. **识别二进制文件格式:**  通过读取文件的前几个字节（magic number），代码能够识别多种可执行文件格式，包括 ELF (Linux, Unix)、PE (Windows)、Mach-O (macOS, iOS)、Plan 9 和 XCOFF (AIX)。
4. **定位构建信息:**  针对不同的文件格式，代码会查找特定的区段或段（section或segment）来定位嵌入的构建信息。这通常是一个名为 `.go.buildinfo` 的 section，或者位于可写的数据段的开头附近。
5. **解析构建信息头:**  构建信息以一个特定的魔数 (`\xff Go buildinf:`) 开头，后跟一个固定大小的头部。头部包含关于构建信息格式版本和偏移量的信息。代码会读取并解析这个头部。
6. **解码版本和模块信息:**  根据头部中的标志位，代码会以不同的方式解码 Go 版本字符串和模块信息字符串。在 Go 1.18 之前，版本和模块信息的地址存储在头部中，需要根据指针大小和字节序读取。在 Go 1.18 及之后，版本和模块信息直接内联在头部之后，并使用变长编码表示长度。
7. **处理模块信息格式:**  代码会检查模块信息是否包含由 `cmd/go/internal/modload` 包添加的起始和结束标记，并将其剥离。
8. **错误处理:**  定义了 `errUnrecognizedFormat` (无法识别的文件格式) 和 `errNotGoExe` (不是 Go 可执行文件) 错误，用于指示读取构建信息失败的不同原因。

**可以推理出它是 Go 语言运行时 `runtime/debug` 包中 `ReadBuildInfo` 功能的底层实现。** `runtime/debug.ReadBuildInfo()` 函数用于获取当前运行的 Go 程序的构建信息。  `debug/buildinfo` 包提供的功能允许外部工具或库解析任意 Go 二进制文件的构建信息，而 `runtime/debug.ReadBuildInfo` 则专注于当前运行的程序。

**Go 代码举例说明:**

假设我们有一个名为 `myprogram` 的 Go 可执行文件。我们可以使用 `buildinfo` 包来读取它的构建信息：

```go
package main

import (
	"debug/buildinfo"
	"fmt"
	"log"
)

func main() {
	info, err := buildinfo.ReadFile("myprogram")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Go Version:", info.GoVersion)
	if info.Module != nil {
		fmt.Println("Main Module Path:", info.Module.Path)
		fmt.Println("Main Module Version:", info.Module.Version)
		if len(info.Deps) > 0 {
			fmt.Println("Dependencies:")
			for _, dep := range info.Deps {
				fmt.Printf("  %s: %s\n", dep.Path, dep.Version)
			}
		}
	} else {
		fmt.Println("Binary not built with modules.")
	}
}
```

**假设的输入与输出:**

假设 `myprogram` 是一个用 Go 1.20 构建的、使用了 Go Modules 的程序。

**输入:**  执行上述 Go 代码，并提供可执行文件 `myprogram` 的路径给 `buildinfo.ReadFile` 函数。

**输出:**

```
Go Version: go1.20
Main Module Path: example.com/myprogram
Main Module Version: v1.0.0
Dependencies:
  golang.org/x/text: v0.10.0
```

如果 `myprogram` 是一个用旧版本 Go 构建的，或者没有使用 Go Modules 的程序，输出可能会有所不同。 例如，如果未使用模块，`info.Module` 将为 `nil`。

**命令行参数的具体处理:**

`debug/buildinfo` 包本身并没有直接处理命令行参数。它的 `ReadFile` 函数接收一个文件路径字符串作为参数，这个路径通常是在调用该函数的程序中硬编码的或者通过该程序的命令行参数解析得到的。

例如，在上面的 Go 代码示例中，`"myprogram"` 是硬编码的文件路径。在一个更实际的工具中，你可能会使用 `flag` 包来解析命令行参数，并将用户提供的文件路径传递给 `buildinfo.ReadFile`。

```go
package main

import (
	"debug/buildinfo"
	"flag"
	"fmt"
	"log"
)

func main() {
	filePath := flag.String("file", "", "Path to the Go executable")
	flag.Parse()

	if *filePath == "" {
		log.Fatal("Please provide the path to the Go executable using the -file flag.")
	}

	info, err := buildinfo.ReadFile(*filePath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Go Version:", info.GoVersion)
	// ... (输出其他构建信息)
}
```

在这个例子中，程序使用 `-file` 命令行参数来接收可执行文件的路径，然后将这个路径传递给 `buildinfo.ReadFile`。

**使用者易犯错的点:**

1. **文件路径错误:**  最常见的问题是提供了不存在的可执行文件路径或者程序没有读取该文件的权限。这会导致 `os.Open` 函数返回错误。

   ```go
   info, err := buildinfo.ReadFile("non_existent_program")
   if err != nil {
       // err 会是一个 *fs.PathError，指示文件未找到。
       fmt.Println("Error:", err)
   }
   ```

2. **尝试读取非 Go 可执行文件:**  如果尝试读取一个不是 Go 编译的可执行文件，`buildinfo.ReadFile` 或 `buildinfo.Read` 将会返回 `errNotGoExe` 错误。

   ```go
   info, err := buildinfo.ReadFile("/bin/ls") // 假设 /bin/ls 不是 Go 程序
   if err != nil {
       if errors.Is(err, buildinfo.ErrNotGoExe) {
           fmt.Println("Error: Not a Go executable")
       } else {
           fmt.Println("Error:", err)
       }
   }
   ```

3. **假设所有 Go 程序都使用模块:**  早期的 Go 版本或者使用 `GO111MODULE=off` 构建的程序可能没有模块信息。访问 `info.Module` 之前应该检查其是否为 `nil`。

   ```go
   info, err := buildinfo.ReadFile("old_go_program")
   if err == nil {
       if info.Module != nil {
           fmt.Println("Module Path:", info.Module.Path)
       } else {
           fmt.Println("Program was not built with modules.")
       }
   }
   ```

总而言之，`debug/buildinfo` 包提供了一种强大的方式来检查 Go 二进制文件的构建方式，这对于调试、版本管理和软件分发等场景非常有用。理解其工作原理和潜在的错误情况可以帮助开发者更好地利用这个包。

Prompt: 
```
这是路径为go/src/debug/buildinfo/buildinfo.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package buildinfo provides access to information embedded in a Go binary
// about how it was built. This includes the Go toolchain version, and the
// set of modules used (for binaries built in module mode).
//
// Build information is available for the currently running binary in
// runtime/debug.ReadBuildInfo.
package buildinfo

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"debug/plan9obj"
	"encoding/binary"
	"errors"
	"fmt"
	"internal/saferio"
	"internal/xcoff"
	"io"
	"io/fs"
	"os"
	"runtime/debug"
	_ "unsafe" // for linkname
)

// Type alias for build info. We cannot move the types here, since
// runtime/debug would need to import this package, which would make it
// a much larger dependency.
type BuildInfo = debug.BuildInfo

// errUnrecognizedFormat is returned when a given executable file doesn't
// appear to be in a known format, or it breaks the rules of that format,
// or when there are I/O errors reading the file.
var errUnrecognizedFormat = errors.New("unrecognized file format")

// errNotGoExe is returned when a given executable file is valid but does
// not contain Go build information.
//
// errNotGoExe should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/quay/claircore
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname errNotGoExe
var errNotGoExe = errors.New("not a Go executable")

// The build info blob left by the linker is identified by a 32-byte header,
// consisting of buildInfoMagic (14 bytes), followed by version-dependent
// fields.
var buildInfoMagic = []byte("\xff Go buildinf:")

const (
	buildInfoAlign      = 16
	buildInfoHeaderSize = 32
)

// ReadFile returns build information embedded in a Go binary
// file at the given path. Most information is only available for binaries built
// with module support.
func ReadFile(name string) (info *BuildInfo, err error) {
	defer func() {
		if pathErr := (*fs.PathError)(nil); errors.As(err, &pathErr) {
			err = fmt.Errorf("could not read Go build info: %w", err)
		} else if err != nil {
			err = fmt.Errorf("could not read Go build info from %s: %w", name, err)
		}
	}()

	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// Read returns build information embedded in a Go binary file
// accessed through the given ReaderAt. Most information is only available for
// binaries built with module support.
func Read(r io.ReaderAt) (*BuildInfo, error) {
	vers, mod, err := readRawBuildInfo(r)
	if err != nil {
		return nil, err
	}
	bi, err := debug.ParseBuildInfo(mod)
	if err != nil {
		return nil, err
	}
	bi.GoVersion = vers
	return bi, nil
}

type exe interface {
	// DataStart returns the virtual address and size of the segment or section that
	// should contain build information. This is either a specially named section
	// or the first writable non-zero data segment.
	DataStart() (uint64, uint64)

	// DataReader returns an io.ReaderAt that reads from addr until the end
	// of segment or section that contains addr.
	DataReader(addr uint64) (io.ReaderAt, error)
}

// readRawBuildInfo extracts the Go toolchain version and module information
// strings from a Go binary. On success, vers should be non-empty. mod
// is empty if the binary was not built with modules enabled.
func readRawBuildInfo(r io.ReaderAt) (vers, mod string, err error) {
	// Read the first bytes of the file to identify the format, then delegate to
	// a format-specific function to load segment and section headers.
	ident := make([]byte, 16)
	if n, err := r.ReadAt(ident, 0); n < len(ident) || err != nil {
		return "", "", errUnrecognizedFormat
	}

	var x exe
	switch {
	case bytes.HasPrefix(ident, []byte("\x7FELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			return "", "", errUnrecognizedFormat
		}
		x = &elfExe{f}
	case bytes.HasPrefix(ident, []byte("MZ")):
		f, err := pe.NewFile(r)
		if err != nil {
			return "", "", errUnrecognizedFormat
		}
		x = &peExe{f}
	case bytes.HasPrefix(ident, []byte("\xFE\xED\xFA")) || bytes.HasPrefix(ident[1:], []byte("\xFA\xED\xFE")):
		f, err := macho.NewFile(r)
		if err != nil {
			return "", "", errUnrecognizedFormat
		}
		x = &machoExe{f}
	case bytes.HasPrefix(ident, []byte("\xCA\xFE\xBA\xBE")) || bytes.HasPrefix(ident, []byte("\xCA\xFE\xBA\xBF")):
		f, err := macho.NewFatFile(r)
		if err != nil || len(f.Arches) == 0 {
			return "", "", errUnrecognizedFormat
		}
		x = &machoExe{f.Arches[0].File}
	case bytes.HasPrefix(ident, []byte{0x01, 0xDF}) || bytes.HasPrefix(ident, []byte{0x01, 0xF7}):
		f, err := xcoff.NewFile(r)
		if err != nil {
			return "", "", errUnrecognizedFormat
		}
		x = &xcoffExe{f}
	case hasPlan9Magic(ident):
		f, err := plan9obj.NewFile(r)
		if err != nil {
			return "", "", errUnrecognizedFormat
		}
		x = &plan9objExe{f}
	default:
		return "", "", errUnrecognizedFormat
	}

	// Read segment or section to find the build info blob.
	// On some platforms, the blob will be in its own section, and DataStart
	// returns the address of that section. On others, it's somewhere in the
	// data segment; the linker puts it near the beginning.
	// See cmd/link/internal/ld.Link.buildinfo.
	dataAddr, dataSize := x.DataStart()
	if dataSize == 0 {
		return "", "", errNotGoExe
	}

	addr, err := searchMagic(x, dataAddr, dataSize)
	if err != nil {
		return "", "", err
	}

	// Read in the full header first.
	header, err := readData(x, addr, buildInfoHeaderSize)
	if err == io.EOF {
		return "", "", errNotGoExe
	} else if err != nil {
		return "", "", err
	}
	if len(header) < buildInfoHeaderSize {
		return "", "", errNotGoExe
	}

	const (
		ptrSizeOffset = 14
		flagsOffset   = 15
		versPtrOffset = 16

		flagsEndianMask   = 0x1
		flagsEndianLittle = 0x0
		flagsEndianBig    = 0x1

		flagsVersionMask = 0x2
		flagsVersionPtr  = 0x0
		flagsVersionInl  = 0x2
	)

	// Decode the blob. The blob is a 32-byte header, optionally followed
	// by 2 varint-prefixed string contents.
	//
	// type buildInfoHeader struct {
	// 	magic       [14]byte
	// 	ptrSize     uint8 // used if flagsVersionPtr
	// 	flags       uint8
	// 	versPtr     targetUintptr // used if flagsVersionPtr
	// 	modPtr      targetUintptr // used if flagsVersionPtr
	// }
	//
	// The version bit of the flags field determines the details of the format.
	//
	// Prior to 1.18, the flags version bit is flagsVersionPtr. In this
	// case, the header includes pointers to the version and modinfo Go
	// strings in the header. The ptrSize field indicates the size of the
	// pointers and the endian bit of the flag indicates the pointer
	// endianness.
	//
	// Since 1.18, the flags version bit is flagsVersionInl. In this case,
	// the header is followed by the string contents inline as
	// length-prefixed (as varint) string contents. First is the version
	// string, followed immediately by the modinfo string.
	flags := header[flagsOffset]
	if flags&flagsVersionMask == flagsVersionInl {
		vers, addr, err = decodeString(x, addr+buildInfoHeaderSize)
		if err != nil {
			return "", "", err
		}
		mod, _, err = decodeString(x, addr)
		if err != nil {
			return "", "", err
		}
	} else {
		// flagsVersionPtr (<1.18)
		ptrSize := int(header[ptrSizeOffset])
		bigEndian := flags&flagsEndianMask == flagsEndianBig
		var bo binary.ByteOrder
		if bigEndian {
			bo = binary.BigEndian
		} else {
			bo = binary.LittleEndian
		}
		var readPtr func([]byte) uint64
		if ptrSize == 4 {
			readPtr = func(b []byte) uint64 { return uint64(bo.Uint32(b)) }
		} else if ptrSize == 8 {
			readPtr = bo.Uint64
		} else {
			return "", "", errNotGoExe
		}
		vers = readString(x, ptrSize, readPtr, readPtr(header[versPtrOffset:]))
		mod = readString(x, ptrSize, readPtr, readPtr(header[versPtrOffset+ptrSize:]))
	}
	if vers == "" {
		return "", "", errNotGoExe
	}
	if len(mod) >= 33 && mod[len(mod)-17] == '\n' {
		// Strip module framing: sentinel strings delimiting the module info.
		// These are cmd/go/internal/modload.infoStart and infoEnd.
		mod = mod[16 : len(mod)-16]
	} else {
		mod = ""
	}

	return vers, mod, nil
}

func hasPlan9Magic(magic []byte) bool {
	if len(magic) >= 4 {
		m := binary.BigEndian.Uint32(magic)
		switch m {
		case plan9obj.Magic386, plan9obj.MagicAMD64, plan9obj.MagicARM:
			return true
		}
	}
	return false
}

func decodeString(x exe, addr uint64) (string, uint64, error) {
	// varint length followed by length bytes of data.

	// N.B. ReadData reads _up to_ size bytes from the section containing
	// addr. So we don't need to check that size doesn't overflow the
	// section.
	b, err := readData(x, addr, binary.MaxVarintLen64)
	if err == io.EOF {
		return "", 0, errNotGoExe
	} else if err != nil {
		return "", 0, err
	}

	length, n := binary.Uvarint(b)
	if n <= 0 {
		return "", 0, errNotGoExe
	}
	addr += uint64(n)

	b, err = readData(x, addr, length)
	if err == io.EOF {
		return "", 0, errNotGoExe
	} else if err == io.ErrUnexpectedEOF {
		// Length too large to allocate. Clearly bogus value.
		return "", 0, errNotGoExe
	} else if err != nil {
		return "", 0, err
	}
	if uint64(len(b)) < length {
		// Section ended before we could read the full string.
		return "", 0, errNotGoExe
	}

	return string(b), addr + length, nil
}

// readString returns the string at address addr in the executable x.
func readString(x exe, ptrSize int, readPtr func([]byte) uint64, addr uint64) string {
	hdr, err := readData(x, addr, uint64(2*ptrSize))
	if err != nil || len(hdr) < 2*ptrSize {
		return ""
	}
	dataAddr := readPtr(hdr)
	dataLen := readPtr(hdr[ptrSize:])
	data, err := readData(x, dataAddr, dataLen)
	if err != nil || uint64(len(data)) < dataLen {
		return ""
	}
	return string(data)
}

const searchChunkSize = 1 << 20 // 1 MB

// searchMagic returns the aligned first instance of buildInfoMagic in the data
// range [addr, addr+size). Returns false if not found.
func searchMagic(x exe, start, size uint64) (uint64, error) {
	end := start + size
	if end < start {
		// Overflow.
		return 0, errUnrecognizedFormat
	}

	// Round up start; magic can't occur in the initial unaligned portion.
	start = (start + buildInfoAlign - 1) &^ (buildInfoAlign - 1)
	if start >= end {
		return 0, errNotGoExe
	}

	var buf []byte
	for start < end {
		// Read in chunks to avoid consuming too much memory if data is large.
		//
		// Normally it would be somewhat painful to handle the magic crossing a
		// chunk boundary, but since it must be 16-byte aligned we know it will
		// fall within a single chunk.
		remaining := end - start
		chunkSize := uint64(searchChunkSize)
		if chunkSize > remaining {
			chunkSize = remaining
		}

		if buf == nil {
			buf = make([]byte, chunkSize)
		} else {
			// N.B. chunkSize can only decrease, and only on the
			// last chunk.
			buf = buf[:chunkSize]
			clear(buf)
		}

		n, err := readDataInto(x, start, buf)
		if err == io.EOF {
			// EOF before finding the magic; must not be a Go executable.
			return 0, errNotGoExe
		} else if err != nil {
			return 0, err
		}

		data := buf[:n]
		for len(data) > 0 {
			i := bytes.Index(data, buildInfoMagic)
			if i < 0 {
				break
			}
			if remaining-uint64(i) < buildInfoHeaderSize {
				// Found magic, but not enough space left for the full header.
				return 0, errNotGoExe
			}
			if i%buildInfoAlign != 0 {
				// Found magic, but misaligned. Keep searching.
				next := (i + buildInfoAlign - 1) &^ (buildInfoAlign - 1)
				if next > len(data) {
					// Corrupt object file: the remaining
					// count says there is more data,
					// but we didn't read it.
					return 0, errNotGoExe
				}
				data = data[next:]
				continue
			}
			// Good match!
			return start + uint64(i), nil
		}

		start += chunkSize
	}

	return 0, errNotGoExe
}

func readData(x exe, addr, size uint64) ([]byte, error) {
	r, err := x.DataReader(addr)
	if err != nil {
		return nil, err
	}

	b, err := saferio.ReadDataAt(r, size, 0)
	if len(b) > 0 && err == io.EOF {
		err = nil
	}
	return b, err
}

func readDataInto(x exe, addr uint64, b []byte) (int, error) {
	r, err := x.DataReader(addr)
	if err != nil {
		return 0, err
	}

	n, err := r.ReadAt(b, 0)
	if n > 0 && err == io.EOF {
		err = nil
	}
	return n, err
}

// elfExe is the ELF implementation of the exe interface.
type elfExe struct {
	f *elf.File
}

func (x *elfExe) DataReader(addr uint64) (io.ReaderAt, error) {
	for _, prog := range x.f.Progs {
		if prog.Vaddr <= addr && addr <= prog.Vaddr+prog.Filesz-1 {
			remaining := prog.Vaddr + prog.Filesz - addr
			return io.NewSectionReader(prog, int64(addr-prog.Vaddr), int64(remaining)), nil
		}
	}
	return nil, errUnrecognizedFormat
}

func (x *elfExe) DataStart() (uint64, uint64) {
	for _, s := range x.f.Sections {
		if s.Name == ".go.buildinfo" {
			return s.Addr, s.Size
		}
	}
	for _, p := range x.f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&(elf.PF_X|elf.PF_W) == elf.PF_W {
			return p.Vaddr, p.Memsz
		}
	}
	return 0, 0
}

// peExe is the PE (Windows Portable Executable) implementation of the exe interface.
type peExe struct {
	f *pe.File
}

func (x *peExe) imageBase() uint64 {
	switch oh := x.f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		return oh.ImageBase
	}
	return 0
}

func (x *peExe) DataReader(addr uint64) (io.ReaderAt, error) {
	addr -= x.imageBase()
	for _, sect := range x.f.Sections {
		if uint64(sect.VirtualAddress) <= addr && addr <= uint64(sect.VirtualAddress+sect.Size-1) {
			remaining := uint64(sect.VirtualAddress+sect.Size) - addr
			return io.NewSectionReader(sect, int64(addr-uint64(sect.VirtualAddress)), int64(remaining)), nil
		}
	}
	return nil, errUnrecognizedFormat
}

func (x *peExe) DataStart() (uint64, uint64) {
	// Assume data is first writable section.
	const (
		IMAGE_SCN_CNT_CODE               = 0x00000020
		IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
		IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
		IMAGE_SCN_MEM_EXECUTE            = 0x20000000
		IMAGE_SCN_MEM_READ               = 0x40000000
		IMAGE_SCN_MEM_WRITE              = 0x80000000
		IMAGE_SCN_MEM_DISCARDABLE        = 0x2000000
		IMAGE_SCN_LNK_NRELOC_OVFL        = 0x1000000
		IMAGE_SCN_ALIGN_32BYTES          = 0x600000
	)
	for _, sect := range x.f.Sections {
		if sect.VirtualAddress != 0 && sect.Size != 0 &&
			sect.Characteristics&^IMAGE_SCN_ALIGN_32BYTES == IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE {
			return uint64(sect.VirtualAddress) + x.imageBase(), uint64(sect.VirtualSize)
		}
	}
	return 0, 0
}

// machoExe is the Mach-O (Apple macOS/iOS) implementation of the exe interface.
type machoExe struct {
	f *macho.File
}

func (x *machoExe) DataReader(addr uint64) (io.ReaderAt, error) {
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Addr <= addr && addr <= seg.Addr+seg.Filesz-1 {
			if seg.Name == "__PAGEZERO" {
				continue
			}
			remaining := seg.Addr + seg.Filesz - addr
			return io.NewSectionReader(seg, int64(addr-seg.Addr), int64(remaining)), nil
		}
	}
	return nil, errUnrecognizedFormat
}

func (x *machoExe) DataStart() (uint64, uint64) {
	// Look for section named "__go_buildinfo".
	for _, sec := range x.f.Sections {
		if sec.Name == "__go_buildinfo" {
			return sec.Addr, sec.Size
		}
	}
	// Try the first non-empty writable segment.
	const RW = 3
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if ok && seg.Addr != 0 && seg.Filesz != 0 && seg.Prot == RW && seg.Maxprot == RW {
			return seg.Addr, seg.Memsz
		}
	}
	return 0, 0
}

// xcoffExe is the XCOFF (AIX eXtended COFF) implementation of the exe interface.
type xcoffExe struct {
	f *xcoff.File
}

func (x *xcoffExe) DataReader(addr uint64) (io.ReaderAt, error) {
	for _, sect := range x.f.Sections {
		if sect.VirtualAddress <= addr && addr <= sect.VirtualAddress+sect.Size-1 {
			remaining := sect.VirtualAddress + sect.Size - addr
			return io.NewSectionReader(sect, int64(addr-sect.VirtualAddress), int64(remaining)), nil
		}
	}
	return nil, errors.New("address not mapped")
}

func (x *xcoffExe) DataStart() (uint64, uint64) {
	if s := x.f.SectionByType(xcoff.STYP_DATA); s != nil {
		return s.VirtualAddress, s.Size
	}
	return 0, 0
}

// plan9objExe is the Plan 9 a.out implementation of the exe interface.
type plan9objExe struct {
	f *plan9obj.File
}

func (x *plan9objExe) DataStart() (uint64, uint64) {
	if s := x.f.Section("data"); s != nil {
		return uint64(s.Offset), uint64(s.Size)
	}
	return 0, 0
}

func (x *plan9objExe) DataReader(addr uint64) (io.ReaderAt, error) {
	for _, sect := range x.f.Sections {
		if uint64(sect.Offset) <= addr && addr <= uint64(sect.Offset+sect.Size-1) {
			remaining := uint64(sect.Offset+sect.Size) - addr
			return io.NewSectionReader(sect, int64(addr-uint64(sect.Offset)), int64(remaining)), nil
		}
	}
	return nil, errors.New("address not mapped")
}

"""



```