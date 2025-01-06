Response:
Let's break down the thought process for analyzing the provided Go code snippet for `fips140.go`.

**1. Initial Reading and Keyword Spotting:**

The first step is to read through the comments and code, looking for keywords and phrases that give clues about the file's purpose. Immediately, "FIPS-140", "hash", "verification", "symbols", "sections", "contiguous", "start", "end", "crypto/internal/fips140/check", and "go:fipsinfo" jump out. These tell me the code is related to FIPS 140 compliance in Go and involves hashing specific parts of the binary.

**2. Understanding the Core Problem:**

The comments clearly state the goal: to verify the integrity of the FIPS-compliant code and data within the Go binary. This involves calculating a hash of these sections and storing it in a way that the runtime can later verify.

**3. Deconstructing "FIPS Symbol Layout":**

This section explains *how* the FIPS code and data are identified. The key takeaway is the introduction of "bracketing symbols" like `go:textfipsstart` and `go:textfipsend`. These are real symbols, unlike `runtime.text`, which simplifies their handling by the linker. This is a crucial design decision.

**4. Understanding "FIPS Info Layout":**

This describes the structure where the hash and section boundaries are stored. The `go:fipsinfo` symbol holds a struct containing the hash (`sum`), a self-pointer (`self`), and an array of start/end addresses for the FIPS sections. The comment mentions `crypto/internal/fips140/check`, indicating the runtime component that will use this information.

**5. Tracing "FIPS Info Calculation":**

This explains *when* and *how* the hash is computed and written. It differentiates between internal (`asmbfips`) and external linking (`hostlinkfips`). The core idea is that with external linking, the final binary needs to be read back to account for potential linker modifications (like PLT entries). The `fipsObj` struct encapsulates the hashing logic.

**6. Recognizing the Role of `loadfips`:**

This function is called during the linking process. It creates the bracketing symbols and the `go:fipsinfo` symbol. This happens *before* the actual hashing.

**7. Analyzing `fipsObj`:**

This struct and its methods (`newFipsObj`, `addSection`, `sum`, `Close`) provide the central mechanism for calculating the hash. The debugging section mentioning `-fipso` is important – it allows writing the "FIPS object" to a file for inspection.

**8. Dissecting `asmbfips` and `hostlinkfips`:**

These functions implement the FIPS info calculation for internal and external linking, respectively. `asmbfips` works directly with the linker's output. `hostlinkfips` has to open and parse the final executable (ELF, Mach-O, or PE) to extract the FIPS sections and update the `go:fipsinfo`. The conditional logic based on the operating system's executable format is significant.

**9. Identifying Potential User Errors:**

As I read through the code, I look for areas where a user might misunderstand or misuse the FIPS functionality. The main point of confusion could be around the different linking modes and how the hash is generated in each case. Also, the debugging mechanism using `-fipso` is something a user might not be aware of.

**10. Structuring the Answer:**

Finally, I organize the information into the requested categories:

* **Functionality:** A high-level summary of what the code does.
* **Go Language Feature:**  Focus on the practical application of embedding data and performing runtime checks. The example code demonstrates accessing the `go:fipsinfo` symbol.
* **Code Inference:**  Highlight the role of bracketing symbols and how they define the FIPS sections. Provide a simplified example of how `addSection` would work.
* **Command-line Arguments:** Explain the `-fipso` flag and its purpose.
* **Common Mistakes:**  Point out the potential confusion between internal and external linking.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the low-level details of ELF/Mach-O/PE parsing. I then realized the core concept is the *process* of hashing, and the OS-specific parts are just implementation details of `hostlinkfips`.
* I needed to emphasize the *why* behind the bracketing symbols – simplifying linker handling compared to pseudo-symbols.
* I also made sure to explicitly connect the linker code with the runtime verification (`crypto/internal/fips140/check`).

By following these steps, I can systematically analyze the code and provide a comprehensive answer that addresses the user's request. The process involves reading, understanding, deconstructing, connecting the pieces, and then structuring the information clearly.
这段代码是 Go 语言链接器 (`cmd/link`) 中用于支持 FIPS 140 验证功能的一部分。它的主要功能是：

**1. 标记和收集 FIPS 代码和数据段：**

- 它定义了一组特殊的符号类型（如 `STEXTFIPS`, `SRODATAFIPS` 等）来标记需要进行 FIPS 140 验证的代码和数据段。
- 它创建了一些特殊的 "括号" 符号（例如 `go:textfipsstart`, `go:textfipsend`）来明确标识这些 FIPS 段的起始和结束位置。这些符号会被放置在实际的 FIPS 代码/数据段的前后。

**2. 创建 FIPS 信息符号 `go:fipsinfo`：**

- 它创建一个名为 `go:fipsinfo` 的特殊符号，用于存储 FIPS 验证所需的信息。
- 这个符号的数据结构包含：
    - `sum`:  一个 32 字节的数组，用于存储 FIPS 代码和数据的哈希值。
    - `self`:  一个指向 `go:fipsinfo` 自身起始地址的指针。
    - `sects`:  一个包含 4 个结构体的数组，每个结构体存储一个 FIPS 段的起始和结束地址。

**3. 计算 FIPS 代码和数据的哈希值：**

- 它定义了一个 `fipsObj` 类型，用于读取指定的二进制文件部分，计算它们的哈希值，并可选择将正在哈希的内容写入文件以进行调试。
- 根据链接模式的不同（内部链接或外部链接），哈希计算的时机和方式有所不同：
    - **内部链接 (`asmbfips`)**:  在写入输出二进制文件之后，但在代码签名之前，从输出文件中读取相关的 FIPS 段，计算哈希值，并将哈希值和段地址信息写入 `go:fipsinfo` 符号中。
    - **外部链接 (`hostlinkfips`)**: 在外部链接器完成链接后，读取最终的可执行文件，找到 `go:fipsinfo` 符号，根据其中记录的段地址信息，读取相应的 FIPS 段，计算哈希值，并将哈希值写回 `go:fipsinfo` 符号的 `sum` 字段。这主要是为了处理外部链接器可能引入的与位置无关代码（PIC）相关的修改。

**4. 提供调试支持：**

- 提供了 `-fipso` 链接器标志，允许将正在哈希的 "FIPS 对象" 写入到指定的文件中，方便开发者在哈希校验失败时进行调试。

**它是什么 Go 语言功能的实现：**

这段代码是 Go 语言链接器为了支持 FIPS 140 规范而实现的功能。FIPS 140 是一种美国政府标准，用于认证密码模块。通过计算和验证特定代码和数据段的哈希值，可以确保这些关键部分在编译和链接过程中没有被篡改。

**Go 代码示例：**

虽然这段代码主要在链接器层面工作，但我们可以通过一个简化的 Go 程序来说明 `go:fipsinfo` 符号在运行时是如何被访问的：

```go
package main

import (
	_ "unsafe" // For go:linkname

	"crypto/sha256"
	"fmt"
)

//go:linkname fipsInfo go:fipsinfo
var fipsInfo struct {
	Sum   [32]byte
	Self  uintptr
	Sects [4]struct {
		Start uintptr
		End   uintptr
	}
}

func main() {
	fmt.Printf("FIPS Info Address: 0x%x\n", fipsInfo.Self)
	fmt.Printf("Expected FIPS Hash: %x\n", fipsInfo.Sum)

	// 假设我们知道要验证的 FIPS 代码段的起始和结束地址（从 fipsInfo 中获取）
	if len(fipsInfo.Sects) > 0 {
		start := fipsInfo.Sects[0].Start
		end := fipsInfo.Sects[0].End
		fmt.Printf("FIPS Section 1: Start=0x%x, End=0x%x\n", start, end)

		// 注意：实际运行时校验需要读取内存，这里只是演示如何访问 fipsInfo
		// 真正的校验逻辑在 crypto/internal/fips140/check 包中
	}
}
```

**假设的输入与输出：**

假设我们有一个包含标记为 FIPS 的代码段的 Go 程序。在链接过程中，`loadfips` 函数会创建 `go:textfipsstart` 和 `go:textfipsend` 符号来包裹这个代码段。

**内部链接 (`asmbfips`)：**

- **输入：** 链接器处理后的二进制数据，其中 FIPS 代码段位于 `go:textfipsstart` 和 `go:textfipsend` 之间。
- **过程：** `asmbfips` 读取这段内存，使用 SHA256 计算哈希值。假设计算出的哈希值为 `abcdef...123456`。同时，它也获取了 `go:textfipsstart` 和 `go:textfipsend` 的地址（例如 `0x1000` 和 `0x2000`）。
- **输出：** `go:fipsinfo` 符号的数据将被更新，包含：
    - `Sum`: `abcdef...123456`
    - `Self`: `go:fipsinfo` 符号的地址 (例如 `0x3000`)
    - `Sects[0].Start`: `0x1000`
    - `Sects[0].End`: `0x2000`

**外部链接 (`hostlinkfips`)：**

- **输入：**  最终链接完成的可执行文件。
- **过程：** `hostlinkfips` 打开可执行文件，找到 `.go.fipsinfo` 段（或 Mach-O 的 `__go_fipsinfo` 段，或扫描 PE 文件）。读取 `go:fipsinfo` 的内容，获取 FIPS 段的起始和结束地址。然后，它根据这些地址从可执行文件中读取相应的代码和数据，计算哈希值。
- **输出：** 可执行文件中 `go:fipsinfo` 符号的 `Sum` 字段会被更新为计算出的哈希值。

**命令行参数的具体处理：**

- **`-fipso <filename>`:**  这是一个链接器标志，用于指定一个文件名。如果设置了这个标志，链接器在计算 FIPS 哈希时，会将正在哈希的内容写入到指定的文件中。这对于调试 FIPS 哈希校验失败的情况非常有用。

   **示例：** `go build -ldflags="-fipso=/tmp/fips.o" myprogram.go`

   在这个例子中，链接器在计算 `myprogram` 的 FIPS 哈希时，会将正在哈希的数据写入到 `/tmp/fips.o` 文件中。

**使用者易犯错的点：**

目前这段代码没有直接暴露给最终用户可配置的选项，它更多是链接器内部的实现细节。使用者在启用 FIPS 功能后，主要依赖于 Go 工具链的正确配置和 FIPS 相关的编译选项。

一个潜在的混淆点可能在于 **内部链接和外部链接的区别** 以及它们对 FIPS 哈希计算的影响。  用户可能不理解为什么在某些情况下需要读取最终的可执行文件来计算哈希。  这主要是因为外部链接器可能会修改代码段（例如插入 PLT 条目），因此必须在最终链接完成后才能计算准确的哈希值。

例如，如果用户在外部链接模式下，并且没有正确配置环境或者链接器，导致 FIPS 哈希计算不正确，那么运行时校验就会失败，但用户可能不清楚是链接过程中的哪个环节出了问题。 `-fipso` 标志在这种情况下可以帮助定位问题，通过对比链接时生成的 `/tmp/fips.o` 和运行时校验失败时可能生成的调试文件（代码注释中提到的 `/tmp/fipscheck.o`）来找出差异。

Prompt: 
```
这是路径为go/src/cmd/link/internal/ld/fips140.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
FIPS-140 Verification Support

See ../../../internal/obj/fips.go for a basic overview.
This file is concerned with computing the hash of the FIPS code+data.
Package obj has taken care of marking the FIPS symbols with the
special types STEXTFIPS, SRODATAFIPS, SNOPTRDATAFIPS, and SDATAFIPS.

# FIPS Symbol Layout

The first order of business is collecting the FIPS symbols into
contiguous sections of the final binary and identifying the start and
end of those sections. The linker already tracks the start and end of
the text section as runtime.text and runtime.etext, and similarly for
other sections, but the implementation of those symbols is tricky and
platform-specific. The problem is that they are zero-length
pseudo-symbols that share addresses with other symbols, which makes
everything harder. For the FIPS sections, we avoid that subtlety by
defining actual non-zero-length symbols bracketing each section and
use those symbols as the boundaries.

Specifically, we define a 1-byte symbol go:textfipsstart of type
STEXTFIPSSTART and a 1-byte symbol go:textfipsend of type STEXTFIPSEND,
and we place those two symbols immediately before and after the
STEXTFIPS symbols. We do the same for SRODATAFIPS, SNOPTRDATAFIPS,
and SDATAFIPS. Because the symbols are real (but otherwise unused) data,
they can be treated as normal symbols for symbol table purposes and
don't need the same kind of special handling that runtime.text and
friends do.

Note that treating the FIPS text as starting at &go:textfipsstart and
ending at &go:textfipsend means that go:textfipsstart is included in
the verified data while go:textfipsend is not. That's fine: they are
only framing and neither strictly needs to be in the hash.

The new special symbols are created by [loadfips].

# FIPS Info Layout

Having collated the FIPS symbols, we need to compute the hash
and then leave both the expected hash and the FIPS address ranges
for the run-time check in crypto/internal/fips140/check.
We do that by creating a special symbol named go:fipsinfo of the form

	struct {
		sum   [32]byte
		self  uintptr // points to start of struct
		sects [4]struct{
			start uintptr
			end   uintptr
		}
	}

The crypto/internal/fips140/check uses linkname to access this symbol,
which is of course not included in the hash.

# FIPS Info Calculation

When using internal linking, [asmbfips] runs after writing the output
binary but before code-signing it. It reads the relevant sections
back from the output file, hashes them, and then writes the go:fipsinfo
content into the output file.

When using external linking, especially with -buildmode=pie, we cannot
predict the specific PLT index references that the linker will insert
into the FIPS code sections, so we must read the final linked executable
after external linking, compute the hash, and then write it back to the
executable in the go:fipsinfo sum field. [hostlinkfips] does this.
It finds go:fipsinfo easily because that symbol is given its own section
(.go.fipsinfo on ELF, __go_fipsinfo on Mach-O), and then it can use the
sections field to find the relevant parts of the executable, hash them,
and fill in sum.

Both [asmbfips] and [hostlinkfips] need the same hash calculation code.
The [fipsObj] type provides that calculation.

# Debugging

It is of course impossible to debug a mismatched hash directly:
two random 32-byte strings differ. For debugging, the linker flag
-fipso can be set to the name of a file (such as /tmp/fips.o)
where the linker will write the “FIPS object” that is being hashed.

There is also commented-out code in crypto/internal/fips140/check that
will write /tmp/fipscheck.o during the run-time verification.

When the hashes differ, the first step is to uncomment the
/tmp/fipscheck.o-writing code and then rebuild with
-ldflags=-fipso=/tmp/fips.o. Then when the hash check fails,
compare /tmp/fips.o and /tmp/fipscheck.o to find the differences.
*/

package ld

import (
	"bufio"
	"bytes"
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"crypto/hmac"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
)

const enableFIPS = true

// fipsSyms are the special FIPS section bracketing symbols.
var fipsSyms = []struct {
	name string
	kind sym.SymKind
	sym  loader.Sym
	seg  *sym.Segment
}{
	{name: "go:textfipsstart", kind: sym.STEXTFIPSSTART, seg: &Segtext},
	{name: "go:textfipsend", kind: sym.STEXTFIPSEND},
	{name: "go:rodatafipsstart", kind: sym.SRODATAFIPSSTART, seg: &Segrodata},
	{name: "go:rodatafipsend", kind: sym.SRODATAFIPSEND},
	{name: "go:noptrdatafipsstart", kind: sym.SNOPTRDATAFIPSSTART, seg: &Segdata},
	{name: "go:noptrdatafipsend", kind: sym.SNOPTRDATAFIPSEND},
	{name: "go:datafipsstart", kind: sym.SDATAFIPSSTART, seg: &Segdata},
	{name: "go:datafipsend", kind: sym.SDATAFIPSEND},
}

// fipsinfo is the loader symbol for go:fipsinfo.
var fipsinfo loader.Sym

const (
	fipsMagic    = "\xff Go fipsinfo \xff\x00"
	fipsMagicLen = 16
	fipsSumLen   = 32
)

// loadfips creates the special bracketing symbols and go:fipsinfo.
func loadfips(ctxt *Link) {
	if !obj.EnableFIPS() {
		return
	}
	if ctxt.BuildMode == BuildModePlugin { // not sure why this doesn't work
		return
	}
	// Write the fipsinfo symbol, which crypto/internal/fips140/check uses.
	ldr := ctxt.loader
	// TODO lock down linkname
	info := ldr.CreateSymForUpdate("go:fipsinfo", 0)
	info.SetType(sym.SFIPSINFO)

	data := make([]byte, fipsMagicLen+fipsSumLen)
	copy(data, fipsMagic)
	info.SetData(data)
	info.SetSize(int64(len(data)))      // magic + checksum, to be filled in
	info.AddAddr(ctxt.Arch, info.Sym()) // self-reference

	for i := range fipsSyms {
		s := &fipsSyms[i]
		sb := ldr.CreateSymForUpdate(s.name, 0)
		sb.SetType(s.kind)
		sb.SetLocal(true)
		sb.SetSize(1)
		s.sym = sb.Sym()
		info.AddAddr(ctxt.Arch, s.sym)
		if s.kind == sym.STEXTFIPSSTART || s.kind == sym.STEXTFIPSEND {
			ctxt.Textp = append(ctxt.Textp, s.sym)
		}
	}

	fipsinfo = info.Sym()
}

// fipsObj calculates the fips object hash and optionally writes
// the hashed content to a file for debugging.
type fipsObj struct {
	r   io.ReaderAt
	w   io.Writer
	wf  *os.File
	h   hash.Hash
	tmp [8]byte
}

// newFipsObj creates a fipsObj reading from r and writing to fipso
// (unless fipso is the empty string, in which case it writes nowhere
// and only computes the hash).
func newFipsObj(r io.ReaderAt, fipso string) (*fipsObj, error) {
	f := &fipsObj{r: r}
	f.h = hmac.New(sha256.New, make([]byte, 32))
	f.w = f.h
	if fipso != "" {
		wf, err := os.Create(fipso)
		if err != nil {
			return nil, err
		}
		f.wf = wf
		f.w = io.MultiWriter(f.h, wf)
	}

	if _, err := f.w.Write([]byte("go fips object v1\n")); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// addSection adds the section of r (passed to newFipsObj)
// starting at byte offset start and ending before byte offset end
// to the fips object file.
func (f *fipsObj) addSection(start, end int64) error {
	n := end - start
	binary.BigEndian.PutUint64(f.tmp[:], uint64(n))
	f.w.Write(f.tmp[:])
	_, err := io.Copy(f.w, io.NewSectionReader(f.r, start, n))
	return err
}

// sum returns the hash of the fips object file.
func (f *fipsObj) sum() []byte {
	return f.h.Sum(nil)
}

// Close closes the fipsObj. In particular it closes the output
// object file specified by fipso in the call to [newFipsObj].
func (f *fipsObj) Close() error {
	if f.wf != nil {
		return f.wf.Close()
	}
	return nil
}

// asmbfips is called from [asmb] to update go:fipsinfo
// when using internal linking.
// See [hostlinkfips] for external linking.
func asmbfips(ctxt *Link, fipso string) {
	if !obj.EnableFIPS() {
		return
	}
	if ctxt.LinkMode == LinkExternal {
		return
	}
	if ctxt.BuildMode == BuildModePlugin { // not sure why this doesn't work
		return
	}

	// Create a new FIPS object with data read from our output file.
	f, err := newFipsObj(bytes.NewReader(ctxt.Out.Data()), fipso)
	if err != nil {
		Errorf("asmbfips: %v", err)
		return
	}
	defer f.Close()

	// Add the FIPS sections to the FIPS object.
	ldr := ctxt.loader
	for i := 0; i < len(fipsSyms); i += 2 {
		start := &fipsSyms[i]
		end := &fipsSyms[i+1]
		startAddr := ldr.SymValue(start.sym)
		endAddr := ldr.SymValue(end.sym)
		seg := start.seg
		if seg.Vaddr == 0 && seg == &Segrodata { // some systems use text instead of separate rodata
			seg = &Segtext
		}
		base := int64(seg.Fileoff - seg.Vaddr)
		if !(seg.Vaddr <= uint64(startAddr) && startAddr <= endAddr && uint64(endAddr) <= seg.Vaddr+seg.Filelen) {
			Errorf("asmbfips: %s not in expected segment (%#x..%#x not in %#x..%#x)", start.name, startAddr, endAddr, seg.Vaddr, seg.Vaddr+seg.Filelen)
			return
		}

		if err := f.addSection(startAddr+base, endAddr+base); err != nil {
			Errorf("asmbfips: %v", err)
			return
		}
	}

	// Overwrite the go:fipsinfo sum field with the calculated sum.
	addr := uint64(ldr.SymValue(fipsinfo))
	seg := &Segdata
	if !(seg.Vaddr <= addr && addr+32 < seg.Vaddr+seg.Filelen) {
		Errorf("asmbfips: fipsinfo not in expected segment (%#x..%#x not in %#x..%#x)", addr, addr+32, seg.Vaddr, seg.Vaddr+seg.Filelen)
		return
	}
	ctxt.Out.SeekSet(int64(seg.Fileoff + addr - seg.Vaddr + fipsMagicLen))
	ctxt.Out.Write(f.sum())

	if err := f.Close(); err != nil {
		Errorf("asmbfips: %v", err)
		return
	}
}

// hostlinkfips is called from [hostlink] to update go:fipsinfo
// when using external linking.
// See [asmbfips] for internal linking.
func hostlinkfips(ctxt *Link, exe, fipso string) error {
	if !obj.EnableFIPS() {
		return nil
	}
	if ctxt.BuildMode == BuildModePlugin { // not sure why this doesn't work
		return nil
	}
	switch {
	case ctxt.IsElf():
		return elffips(ctxt, exe, fipso)
	case ctxt.HeadType == objabi.Hdarwin:
		return machofips(ctxt, exe, fipso)
	case ctxt.HeadType == objabi.Hwindows:
		return pefips(ctxt, exe, fipso)
	}

	// If we can't do FIPS, leave the output binary alone.
	// If people enable FIPS the init-time check will fail,
	// but the binaries will work otherwise.
	return fmt.Errorf("fips unsupported on %s", ctxt.HeadType)
}

// machofips updates go:fipsinfo after external linking
// on systems using Mach-O (GOOS=darwin, GOOS=ios).
func machofips(ctxt *Link, exe, fipso string) error {
	// Open executable both for reading Mach-O and for the fipsObj.
	mf, err := macho.Open(exe)
	if err != nil {
		return err
	}
	defer mf.Close()

	wf, err := os.OpenFile(exe, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer wf.Close()

	f, err := newFipsObj(wf, fipso)
	if err != nil {
		return err
	}
	defer f.Close()

	// Find the go:fipsinfo symbol.
	sect := mf.Section("__go_fipsinfo")
	if sect == nil {
		return fmt.Errorf("cannot find __go_fipsinfo")
	}
	data, err := sect.Data()
	if err != nil {
		return err
	}

	uptr := ctxt.Arch.ByteOrder.Uint64
	if ctxt.Arch.PtrSize == 4 {
		uptr = func(x []byte) uint64 {
			return uint64(ctxt.Arch.ByteOrder.Uint32(x))
		}
	}

	// Add the sections listed in go:fipsinfo to the FIPS object.
	// On Mac, the debug/macho package is not reporting any relocations,
	// but the addends are all in the data already, all relative to
	// the same base.
	// Determine the base used for the self pointer, and then apply
	// that base to the other uintptrs.
	// The very high bits of the uint64s seem to be relocation metadata,
	// so clear them.
	// For non-pie builds, there are no relocations at all:
	// the data holds the actual pointers.
	// This code handles both pie and non-pie binaries.
	const addendMask = 1<<48 - 1
	data = data[fipsMagicLen+fipsSumLen:]
	self := int64(uptr(data)) & addendMask
	base := int64(sect.Offset) - self
	data = data[ctxt.Arch.PtrSize:]

	for i := 0; i < 4; i++ {
		start := int64(uptr(data[0:]))&addendMask + base
		end := int64(uptr(data[ctxt.Arch.PtrSize:]))&addendMask + base
		data = data[2*ctxt.Arch.PtrSize:]
		if err := f.addSection(start, end); err != nil {
			return err
		}
	}

	// Overwrite the go:fipsinfo sum field with the calculated sum.
	if _, err := wf.WriteAt(f.sum(), int64(sect.Offset)+fipsMagicLen); err != nil {
		return err
	}
	if err := wf.Close(); err != nil {
		return err
	}
	return f.Close()
}

// machofips updates go:fipsinfo after external linking
// on systems using ELF (most Unix systems).
func elffips(ctxt *Link, exe, fipso string) error {
	// Open executable both for reading ELF and for the fipsObj.
	ef, err := elf.Open(exe)
	if err != nil {
		return err
	}
	defer ef.Close()

	wf, err := os.OpenFile(exe, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer wf.Close()

	f, err := newFipsObj(wf, fipso)
	if err != nil {
		return err
	}
	defer f.Close()

	// Find the go:fipsinfo symbol.
	sect := ef.Section(".go.fipsinfo")
	if sect == nil {
		return fmt.Errorf("cannot find .go.fipsinfo")
	}

	data, err := sect.Data()
	if err != nil {
		return err
	}

	uptr := ctxt.Arch.ByteOrder.Uint64
	if ctxt.Arch.PtrSize == 4 {
		uptr = func(x []byte) uint64 {
			return uint64(ctxt.Arch.ByteOrder.Uint32(x))
		}
	}

	// Add the sections listed in go:fipsinfo to the FIPS object.
	// We expect R_zzz_RELATIVE relocations where the zero-based
	// values are already stored in the data. That is, the addend
	// is in the data itself in addition to being in the relocation tables.
	// So no need to parse the relocation tables unless we find a
	// toolchain that doesn't initialize the data this way.
	// For non-pie builds, there are no relocations at all:
	// the data holds the actual pointers.
	// This code handles both pie and non-pie binaries.
	data = data[fipsMagicLen+fipsSumLen:]
	data = data[ctxt.Arch.PtrSize:]

Addrs:
	for i := 0; i < 4; i++ {
		start := uptr(data[0:])
		end := uptr(data[ctxt.Arch.PtrSize:])
		data = data[2*ctxt.Arch.PtrSize:]
		for _, prog := range ef.Progs {
			if prog.Type == elf.PT_LOAD && prog.Vaddr <= start && start <= end && end <= prog.Vaddr+prog.Filesz {
				if err := f.addSection(int64(start+prog.Off-prog.Vaddr), int64(end+prog.Off-prog.Vaddr)); err != nil {
					return err
				}
				continue Addrs
			}
		}
		return fmt.Errorf("invalid pointers found in .go.fipsinfo")
	}

	// Overwrite the go:fipsinfo sum field with the calculated sum.
	if _, err := wf.WriteAt(f.sum(), int64(sect.Offset)+fipsMagicLen); err != nil {
		return err
	}
	if err := wf.Close(); err != nil {
		return err
	}
	return f.Close()
}

// pefips updates go:fipsinfo after external linking
// on systems using PE (GOOS=windows).
func pefips(ctxt *Link, exe, fipso string) error {
	// Open executable both for reading Mach-O and for the fipsObj.
	pf, err := pe.Open(exe)
	if err != nil {
		return err
	}
	defer pf.Close()

	wf, err := os.OpenFile(exe, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer wf.Close()

	f, err := newFipsObj(wf, fipso)
	if err != nil {
		return err
	}
	defer f.Close()

	// Find the go:fipsinfo symbol.
	// PE does not put it in its own section, so we have to scan for it.
	// It is near the start of the data segment, right after go:buildinfo,
	// so we should not have to scan too far.
	const maxScan = 16 << 20
	sect := pf.Section(".data")
	if sect == nil {
		return fmt.Errorf("cannot find .data")
	}
	b := bufio.NewReader(sect.Open())
	off := int64(0)
	data := make([]byte, fipsMagicLen+fipsSumLen+9*ctxt.Arch.PtrSize)
	for ; ; off += 16 {
		if off >= maxScan {
			break
		}
		if _, err := io.ReadFull(b, data[:fipsMagicLen]); err != nil {
			return fmt.Errorf("scanning PE for FIPS magic: %v", err)
		}
		if string(data[:fipsMagicLen]) == fipsMagic {
			if _, err := io.ReadFull(b, data[fipsMagicLen:]); err != nil {
				return fmt.Errorf("scanning PE for FIPS magic: %v", err)
			}
			break
		}
	}

	uptr := ctxt.Arch.ByteOrder.Uint64
	if ctxt.Arch.PtrSize == 4 {
		uptr = func(x []byte) uint64 {
			return uint64(ctxt.Arch.ByteOrder.Uint32(x))
		}
	}

	// Add the sections listed in go:fipsinfo to the FIPS object.
	// Determine the base used for the self pointer, and then apply
	// that base to the other uintptrs.
	// For pie builds, the addends are in the data.
	// For non-pie builds, there are no relocations at all:
	// the data holds the actual pointers.
	// This code handles both pie and non-pie binaries.
	data = data[fipsMagicLen+fipsSumLen:]
	self := int64(uptr(data))
	data = data[ctxt.Arch.PtrSize:]

	// On 64-bit binaries the pointers have extra bits set
	// that don't appear in the actual section headers.
	// For example, one generated test binary looks like:
	//
	//	.data VirtualAddress = 0x2af000
	//	.data (file) Offset = 0x2ac400
	//	.data (file) Size = 0x1fc00
	//	go:fipsinfo found at offset 0x2ac5e0 (off=0x1e0)
	//	go:fipsinfo self pointer = 0x01402af1e0
	//
	// From the section headers, the address of the go:fipsinfo symbol
	// should be 0x2af000 + (0x2ac5e0 - 0x2ac400) = 0x2af1e0,
	// yet in this case its pointer is 0x1402af1e0, meaning the
	// data section's VirtualAddress is really 0x1402af000.
	// This is not (only) a 32-bit truncation problem, since the uint32
	// truncation of that address would be 0x402af000, not 0x2af000.
	// Perhaps there is some 64-bit extension that debug/pe is not
	// reading or is misreading. In any event, we can derive the delta
	// between computed VirtualAddress and listed VirtualAddress
	// and apply it to the rest of the pointers.
	// As a sanity check, the low 12 bits (virtual page offset)
	// must match between our computed address and the actual one.
	peself := int64(sect.VirtualAddress) + off
	if self&0xfff != off&0xfff {
		return fmt.Errorf("corrupt pointer found in go:fipsinfo")
	}
	delta := peself - self

Addrs:
	for i := 0; i < 4; i++ {
		start := int64(uptr(data[0:])) + delta
		end := int64(uptr(data[ctxt.Arch.PtrSize:])) + delta
		data = data[2*ctxt.Arch.PtrSize:]
		for _, sect := range pf.Sections {
			if int64(sect.VirtualAddress) <= start && start <= end && end <= int64(sect.VirtualAddress)+int64(sect.Size) {
				off := int64(sect.Offset) - int64(sect.VirtualAddress)
				if err := f.addSection(start+off, end+off); err != nil {
					return err
				}
				continue Addrs
			}
		}
		return fmt.Errorf("invalid pointers found in go:fipsinfo")
	}

	// Overwrite the go:fipsinfo sum field with the calculated sum.
	if _, err := wf.WriteAt(f.sum(), int64(sect.Offset)+off+fipsMagicLen); err != nil {
		return err
	}
	if err := wf.Close(); err != nil {
		return err
	}
	return f.Close()
}

"""



```