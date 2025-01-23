Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Request:**

The core request is to understand the functionality of the Go code and explain it in Chinese. The request specifically asks about:

* **Functionality Listing:** What does this code do?
* **Go Feature Implementation:** Which Go language features are being used?  Provide examples.
* **Code Inference:** If there's logic to infer, illustrate with input/output examples.
* **Command-Line Arguments:** How are command-line arguments handled?
* **Common Mistakes:** What are potential pitfalls for users?

**2. Initial Scan and High-Level Understanding:**

The first step is to read through the code to get a general sense of its purpose. Keywords like `package tar`, comments about "tar archive format," and constants like `FormatUSTAR`, `FormatPAX`, `FormatGNU` strongly suggest this code deals with parsing and potentially generating tar archives. The presence of `Header` types (`headerV7`, `headerGNU`, etc.) reinforces this idea.

**3. Deeper Dive into Key Structures and Constants:**

* **`Format` type:** This is clearly the central concept. It's an `int` with bitwise operations (`has`, `mayBe`, `mayOnlyBe`, `mustNotBe`). This suggests a way to represent and manipulate different tar formats. The constants `FormatUnknown`, `FormatUSTAR`, `FormatPAX`, `FormatGNU` define the possible values.
* **`formatNames` map:** This map associates the `Format` constants with their string representations, useful for debugging or display.
* **Magic constants:** `magicGNU`, `magicUSTAR`, `trailerSTAR` suggest these strings are used to identify the specific tar format when reading an archive.
* **Size constants:**  `blockSize`, `nameSize`, `prefixSize`, `maxSpecialFileSize` define limits related to the structure of tar archives.
* **`block` type:** This seems to represent a fundamental unit of a tar archive, with a fixed size of `blockSize`.
* **Header structs (`headerV7`, `headerGNU`, `headerUSTAR`, `headerSTAR`):** These define the structure of the header within a tar block for different formats. They expose methods to access specific fields.

**4. Analyzing Key Functions:**

* **`String()` method on `Format`:** This converts a `Format` value to a human-readable string, handling cases with multiple format flags.
* **`getFormat()` method on `block`:** This is crucial for identifying the format of a given tar block by checking checksums and magic values. The logic with `switch` statements and format-specific magic numbers is key. The handling of checksum discrepancies (Sun tar) is also interesting.
* **`setFormat()` method on `block`:** This function is the counterpart to `getFormat()`. It sets the magic values for a given format and updates the checksum.
* **`computeChecksum()` method on `block`:** This calculates the checksum of a block, taking into account the special handling of the checksum field itself. The inclusion of both unsigned and signed checksum calculations is notable.
* **Helper functions on header structs (e.g., `name()`, `mode()`, `magic()`):** These provide convenient ways to access specific fields within the header structures.

**5. Connecting the Dots and Inferring Functionality:**

Based on the analysis, it's clear this code is a core part of a `tar` package in Go. It focuses on:

* **Representing different tar archive formats:**  The `Format` type and associated constants are key.
* **Identifying the format of a tar block:** The `getFormat()` function implements this logic using magic numbers and checksums.
* **Setting the format of a tar block:** The `setFormat()` function handles this, including setting magic numbers and checksums.
* **Providing access to header fields:** The header structs provide structured access to the data within a tar header block.
* **Handling checksum verification:** The `computeChecksum()` function is essential for ensuring data integrity.

**6. Addressing Specific Questions from the Request:**

* **Functionality Listing:**  Summarize the key functionalities identified above.
* **Go Feature Implementation:** Identify the use of structs, constants, methods on structs, bitwise operations, maps, and string manipulation. Provide examples for each.
* **Code Inference:** Focus on `getFormat()`. Create an example `block` with USTAR magic numbers and demonstrate how `getFormat()` would correctly identify it. Similarly, show a block with an incorrect checksum resulting in `FormatUnknown`.
* **Command-Line Arguments:**  Acknowledge that this *specific* code snippet doesn't handle command-line arguments. Explain *where* that logic would typically reside in a full `tar` implementation (likely in a separate command-line utility).
* **Common Mistakes:**  Think about scenarios where the code might be misused or where assumptions could lead to errors. Incorrectly setting the `Format`, manually modifying header fields without recalculating the checksum, and misunderstanding the limitations of different formats are potential pitfalls.

**7. Structuring the Answer in Chinese:**

Finally, organize the findings into a clear and concise Chinese explanation, addressing each point of the original request. Use appropriate terminology and examples.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the specific details of each header field. It's important to step back and identify the overall purpose.
* Realizing that command-line argument handling isn't in *this* snippet is crucial. Don't invent functionality that isn't there.
*  The request emphasizes "易犯错的点."  Thinking like a user of this code helps identify potential issues.

By following this structured approach, we can systematically analyze the code and provide a comprehensive and accurate answer in Chinese.
这段Go语言代码是 `archive/tar` 包中 `format.go` 文件的一部分，它主要负责定义和处理不同的 **tar 归档格式**。

以下是它的功能列表：

1. **定义了 `Format` 类型:**  这是一个整数类型，用于表示不同的 tar 归档格式。
2. **定义了不同的 tar 格式常量:**  例如 `FormatUnknown`, `FormatV7`, `FormatUSTAR`, `FormatPAX`, `FormatGNU`, `formatSTAR`。 这些常量用于标识不同的 tar 格式标准。
3. **提供了方法来检查和操作 `Format` 类型的值:**
   - `has(f2 Format) bool`: 检查一个 `Format` 值是否包含另一个 `Format` 值（使用位运算）。
   - `mayBe(f2 Format)`:  使用位 OR 操作将另一个 `Format` 值添加到当前的 `Format` 值中。
   - `mayOnlyBe(f2 Format)`: 使用位 AND 操作，只保留当前 `Format` 值中与另一个 `Format` 值相同的位。
   - `mustNotBe(f2 Format)`: 使用位 AND NOT 操作，从当前 `Format` 值中移除另一个 `Format` 值。
   - `String() string`:  将 `Format` 值转换为可读的字符串表示，例如 "USTAR", "PAX", 或 "(USTAR | PAX)"。
4. **定义了用于识别不同格式的魔术字符串 (Magic Strings) 和版本号:** 例如 `magicGNU`, `versionGNU`, `magicUSTAR`, `versionUSTAR`, `trailerSTAR`。这些字符串用于在读取 tar 归档时判断其格式。
5. **定义了与 tar 格式相关的尺寸常量:** 例如 `blockSize` (块大小), `nameSize` (文件名最大长度), `prefixSize` (路径前缀最大长度) 等。
6. **定义了 `block` 类型:**  这是一个 `[blockSize]byte` 类型的数组，代表 tar 归档中的一个数据块。
7. **提供了将 `block` 转换为不同格式头部的方法:** 例如 `toV7()`, `toGNU()`, `toUSTAR()`, `toSTAR()`。这些方法允许将一个通用的 `block` 解释为特定格式的头部结构。
8. **提供了 `getFormat()` 方法:**  用于判断一个 `block` 的 tar 格式。它通过校验和以及检查魔术字符串来尝试识别格式。
9. **提供了 `setFormat()` 方法:**  用于在一个 `block` 中设置特定 tar 格式的魔术字符串和版本号，并更新校验和。
10. **提供了 `computeChecksum()` 方法:**  用于计算 tar 头部块的校验和。
11. **提供了 `reset()` 方法:**  用于将一个 `block` 的所有字节设置为零。
12. **定义了不同 tar 格式的头部结构体:** 例如 `headerV7`, `headerGNU`, `headerUSTAR`, `headerSTAR`。这些结构体定义了不同格式 tar 头部中各个字段的布局。
13. **为头部结构体提供了访问字段的方法:** 例如 `headerUSTAR` 的 `name()`, `magic()`, `version()`, `prefix()` 等。

**它是什么Go语言功能的实现？**

这段代码主要实现了以下 Go 语言功能：

* **类型定义 (`type Format int`)**:  创建自定义类型。
* **常量定义 (`const ...`)**: 定义具名的常量值。
* **结构体定义 (`type headerV7 [blockSize]byte`)**: 定义复合数据类型，表示不同 tar 格式的头部。
* **方法定义 (`func (f Format) has(f2 Format) bool`)**:  为自定义类型和结构体定义方法，用于操作和访问其数据。
* **位运算 (`&`, `|`, `^`)**: 用于灵活地表示和操作不同的 tar 格式组合。
* **切片 (`[]byte`)**: 用于表示字符串和二进制数据。
* **类型转换 (`(*headerV7)(b)`)**: 用于将一个类型的指针转换为另一个类型的指针。
* **映射 (`map[Format]string`)**: 用于存储 `Format` 值到其字符串表示的映射。

**Go 代码举例说明:**

假设我们有一个代表 tar 头部块的 `block` 实例，我们想判断它的格式并获取文件名：

```go
package main

import (
	"archive/tar"
	"fmt"
)

func main() {
	// 假设我们从一个 tar 文件中读取了一个 block
	var b tar.block

	// 模拟一个 USTAR 格式的头部 (部分字段)
	copy(b[257:263], []byte("ustar\x00")) // 设置 magic
	copy(b[263:265], []byte("00"))     // 设置 version
	copy(b[0:100], []byte("example.txt\x00")) // 设置文件名

	format := b.getFormat()
	fmt.Println("Detected format:", format) // 输出: Detected format: USTAR

	if format.has(tar.FormatUSTAR) {
		header := b.toUSTAR()
		filename := string(header.name())
		fmt.Println("Filename:", filename) // 输出: Filename: example.txt
	}
}
```

**假设的输入与输出 (针对 `getFormat()` 方法):**

**假设输入 1 (USTAR 格式头部):**

```
var b tar.block
copy(b[257:263], []byte("ustar\x00"))
copy(b[263:265], []byte("00"))
// 假设校验和正确
```

**假设输出 1:**

```
FormatUSTAR
```

**假设输入 2 (GNU 格式头部):**

```
var b tar.block
copy(b[257:263], []byte("ustar "))
copy(b[263:265], []byte(" \x00"))
// 假设校验和正确
```

**假设输出 2:**

```
FormatGNU
```

**假设输入 3 (校验和错误):**

```
var b tar.block
copy(b[257:263], []byte("ustar\x00"))
copy(b[263:265], []byte("00"))
// 故意设置错误的校验和
b[148] = '0'
b[149] = '0'
b[150] = '0'
b[151] = '0'
b[152] = '0'
b[153] = '0'
b[154] = '0'
b[155] = '0'
```

**假设输出 3:**

```
FormatUnknown
```

**命令行参数的具体处理:**

这段代码本身 **并不直接处理命令行参数**。 它只是 `archive/tar` 包的一部分，负责定义 tar 格式和提供操作 tar 头部的方法。  处理命令行参数通常发生在更上层的应用程序中，比如 `tar` 命令行工具本身。  该工具会使用 `archive/tar` 包来读取和写入 tar 文件。

**使用者易犯错的点:**

1. **误解 `Format` 类型的位运算:**  新手可能不熟悉使用位运算来组合和检查不同的格式特性。 例如，他们可能直接比较 `format == tar.FormatUSTAR`，而忽略了该格式可能也兼容 PAX。  应该使用 `format.has(tar.FormatUSTAR)` 来检查是否包含某个格式。

   ```go
   // 错误的做法
   if format == tar.FormatUSTAR || format == tar.FormatPAX {
       // ...
   }

   // 正确的做法
   if format.has(tar.FormatUSTAR) || format.has(tar.FormatPAX) {
       // ...
   }
   ```

2. **手动修改头部字段后忘记更新校验和:**  如果用户直接操作 `block` 或 header 结构体的字段，例如修改文件名，那么必须调用 `computeChecksum()` 重新计算校验和，并使用 `setFormat()` 或手动设置校验和字段，否则会导致读取错误。

   ```go
   var b tar.block
   header := b.toUSTAR()
   copy(header.name(), []byte("new_filename.txt\x00"))

   // 必须重新计算校验和并设置
   unsignedSum, _ := b.computeChecksum()
   var f tar.formatter
   field := b.toV7().chksum()
   f.formatOctal(field[:7], unsignedSum)
   field[7] = ' '
   ```

3. **不了解不同 tar 格式的限制:**  用户可能在使用 USTAR 格式时尝试存储超过 8GB 的文件或超过 256 字符的文件名，导致数据丢失或错误。应该根据需求选择合适的 tar 格式（例如 PAX 或 GNU）。

   ```go
   // 假设要创建一个非常大的文件名的头部，使用 USTAR 会失败
   var b tar.block
   header := b.toUSTAR()
   longName := strings.Repeat("a", 300)
   copy(header.name(), []byte(longName)) // 这会截断文件名

   // 应该使用 PAX 或 GNU 格式
   ```

这段代码是 `archive/tar` 包的核心部分，为 Go 语言处理 tar 归档提供了基础的数据结构和方法，使得开发者可以方便地读取、写入和操作不同格式的 tar 文件。

### 提示词
```
这是路径为go/src/archive/tar/format.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tar

import "strings"

// Format represents the tar archive format.
//
// The original tar format was introduced in Unix V7.
// Since then, there have been multiple competing formats attempting to
// standardize or extend the V7 format to overcome its limitations.
// The most common formats are the USTAR, PAX, and GNU formats,
// each with their own advantages and limitations.
//
// The following table captures the capabilities of each format:
//
//	                  |  USTAR |       PAX |       GNU
//	------------------+--------+-----------+----------
//	Name              |   256B | unlimited | unlimited
//	Linkname          |   100B | unlimited | unlimited
//	Size              | uint33 | unlimited |    uint89
//	Mode              | uint21 |    uint21 |    uint57
//	Uid/Gid           | uint21 | unlimited |    uint57
//	Uname/Gname       |    32B | unlimited |       32B
//	ModTime           | uint33 | unlimited |     int89
//	AccessTime        |    n/a | unlimited |     int89
//	ChangeTime        |    n/a | unlimited |     int89
//	Devmajor/Devminor | uint21 |    uint21 |    uint57
//	------------------+--------+-----------+----------
//	string encoding   |  ASCII |     UTF-8 |    binary
//	sub-second times  |     no |       yes |        no
//	sparse files      |     no |       yes |       yes
//
// The table's upper portion shows the [Header] fields, where each format reports
// the maximum number of bytes allowed for each string field and
// the integer type used to store each numeric field
// (where timestamps are stored as the number of seconds since the Unix epoch).
//
// The table's lower portion shows specialized features of each format,
// such as supported string encodings, support for sub-second timestamps,
// or support for sparse files.
//
// The Writer currently provides no support for sparse files.
type Format int

// Constants to identify various tar formats.
const (
	// Deliberately hide the meaning of constants from public API.
	_ Format = (1 << iota) / 4 // Sequence of 0, 0, 1, 2, 4, 8, etc...

	// FormatUnknown indicates that the format is unknown.
	FormatUnknown

	// The format of the original Unix V7 tar tool prior to standardization.
	formatV7

	// FormatUSTAR represents the USTAR header format defined in POSIX.1-1988.
	//
	// While this format is compatible with most tar readers,
	// the format has several limitations making it unsuitable for some usages.
	// Most notably, it cannot support sparse files, files larger than 8GiB,
	// filenames larger than 256 characters, and non-ASCII filenames.
	//
	// Reference:
	//	http://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html#tag_20_92_13_06
	FormatUSTAR

	// FormatPAX represents the PAX header format defined in POSIX.1-2001.
	//
	// PAX extends USTAR by writing a special file with Typeflag TypeXHeader
	// preceding the original header. This file contains a set of key-value
	// records, which are used to overcome USTAR's shortcomings, in addition to
	// providing the ability to have sub-second resolution for timestamps.
	//
	// Some newer formats add their own extensions to PAX by defining their
	// own keys and assigning certain semantic meaning to the associated values.
	// For example, sparse file support in PAX is implemented using keys
	// defined by the GNU manual (e.g., "GNU.sparse.map").
	//
	// Reference:
	//	http://pubs.opengroup.org/onlinepubs/009695399/utilities/pax.html
	FormatPAX

	// FormatGNU represents the GNU header format.
	//
	// The GNU header format is older than the USTAR and PAX standards and
	// is not compatible with them. The GNU format supports
	// arbitrary file sizes, filenames of arbitrary encoding and length,
	// sparse files, and other features.
	//
	// It is recommended that PAX be chosen over GNU unless the target
	// application can only parse GNU formatted archives.
	//
	// Reference:
	//	https://www.gnu.org/software/tar/manual/html_node/Standard.html
	FormatGNU

	// Schily's tar format, which is incompatible with USTAR.
	// This does not cover STAR extensions to the PAX format; these fall under
	// the PAX format.
	formatSTAR

	formatMax
)

func (f Format) has(f2 Format) bool   { return f&f2 != 0 }
func (f *Format) mayBe(f2 Format)     { *f |= f2 }
func (f *Format) mayOnlyBe(f2 Format) { *f &= f2 }
func (f *Format) mustNotBe(f2 Format) { *f &^= f2 }

var formatNames = map[Format]string{
	formatV7: "V7", FormatUSTAR: "USTAR", FormatPAX: "PAX", FormatGNU: "GNU", formatSTAR: "STAR",
}

func (f Format) String() string {
	var ss []string
	for f2 := Format(1); f2 < formatMax; f2 <<= 1 {
		if f.has(f2) {
			ss = append(ss, formatNames[f2])
		}
	}
	switch len(ss) {
	case 0:
		return "<unknown>"
	case 1:
		return ss[0]
	default:
		return "(" + strings.Join(ss, " | ") + ")"
	}
}

// Magics used to identify various formats.
const (
	magicGNU, versionGNU     = "ustar ", " \x00"
	magicUSTAR, versionUSTAR = "ustar\x00", "00"
	trailerSTAR              = "tar\x00"
)

// Size constants from various tar specifications.
const (
	blockSize  = 512 // Size of each block in a tar stream
	nameSize   = 100 // Max length of the name field in USTAR format
	prefixSize = 155 // Max length of the prefix field in USTAR format

	// Max length of a special file (PAX header, GNU long name or link).
	// This matches the limit used by libarchive.
	maxSpecialFileSize = 1 << 20
)

// blockPadding computes the number of bytes needed to pad offset up to the
// nearest block edge where 0 <= n < blockSize.
func blockPadding(offset int64) (n int64) {
	return -offset & (blockSize - 1)
}

var zeroBlock block

type block [blockSize]byte

// Convert block to any number of formats.
func (b *block) toV7() *headerV7       { return (*headerV7)(b) }
func (b *block) toGNU() *headerGNU     { return (*headerGNU)(b) }
func (b *block) toSTAR() *headerSTAR   { return (*headerSTAR)(b) }
func (b *block) toUSTAR() *headerUSTAR { return (*headerUSTAR)(b) }
func (b *block) toSparse() sparseArray { return sparseArray(b[:]) }

// getFormat checks that the block is a valid tar header based on the checksum.
// It then attempts to guess the specific format based on magic values.
// If the checksum fails, then FormatUnknown is returned.
func (b *block) getFormat() Format {
	// Verify checksum.
	var p parser
	value := p.parseOctal(b.toV7().chksum())
	chksum1, chksum2 := b.computeChecksum()
	if p.err != nil || (value != chksum1 && value != chksum2) {
		return FormatUnknown
	}

	// Guess the magic values.
	magic := string(b.toUSTAR().magic())
	version := string(b.toUSTAR().version())
	trailer := string(b.toSTAR().trailer())
	switch {
	case magic == magicUSTAR && trailer == trailerSTAR:
		return formatSTAR
	case magic == magicUSTAR:
		return FormatUSTAR | FormatPAX
	case magic == magicGNU && version == versionGNU:
		return FormatGNU
	default:
		return formatV7
	}
}

// setFormat writes the magic values necessary for specified format
// and then updates the checksum accordingly.
func (b *block) setFormat(format Format) {
	// Set the magic values.
	switch {
	case format.has(formatV7):
		// Do nothing.
	case format.has(FormatGNU):
		copy(b.toGNU().magic(), magicGNU)
		copy(b.toGNU().version(), versionGNU)
	case format.has(formatSTAR):
		copy(b.toSTAR().magic(), magicUSTAR)
		copy(b.toSTAR().version(), versionUSTAR)
		copy(b.toSTAR().trailer(), trailerSTAR)
	case format.has(FormatUSTAR | FormatPAX):
		copy(b.toUSTAR().magic(), magicUSTAR)
		copy(b.toUSTAR().version(), versionUSTAR)
	default:
		panic("invalid format")
	}

	// Update checksum.
	// This field is special in that it is terminated by a NULL then space.
	var f formatter
	field := b.toV7().chksum()
	chksum, _ := b.computeChecksum() // Possible values are 256..128776
	f.formatOctal(field[:7], chksum) // Never fails since 128776 < 262143
	field[7] = ' '
}

// computeChecksum computes the checksum for the header block.
// POSIX specifies a sum of the unsigned byte values, but the Sun tar used
// signed byte values.
// We compute and return both.
func (b *block) computeChecksum() (unsigned, signed int64) {
	for i, c := range b {
		if 148 <= i && i < 156 {
			c = ' ' // Treat the checksum field itself as all spaces.
		}
		unsigned += int64(c)
		signed += int64(int8(c))
	}
	return unsigned, signed
}

// reset clears the block with all zeros.
func (b *block) reset() {
	*b = block{}
}

type headerV7 [blockSize]byte

func (h *headerV7) name() []byte     { return h[000:][:100] }
func (h *headerV7) mode() []byte     { return h[100:][:8] }
func (h *headerV7) uid() []byte      { return h[108:][:8] }
func (h *headerV7) gid() []byte      { return h[116:][:8] }
func (h *headerV7) size() []byte     { return h[124:][:12] }
func (h *headerV7) modTime() []byte  { return h[136:][:12] }
func (h *headerV7) chksum() []byte   { return h[148:][:8] }
func (h *headerV7) typeFlag() []byte { return h[156:][:1] }
func (h *headerV7) linkName() []byte { return h[157:][:100] }

type headerGNU [blockSize]byte

func (h *headerGNU) v7() *headerV7       { return (*headerV7)(h) }
func (h *headerGNU) magic() []byte       { return h[257:][:6] }
func (h *headerGNU) version() []byte     { return h[263:][:2] }
func (h *headerGNU) userName() []byte    { return h[265:][:32] }
func (h *headerGNU) groupName() []byte   { return h[297:][:32] }
func (h *headerGNU) devMajor() []byte    { return h[329:][:8] }
func (h *headerGNU) devMinor() []byte    { return h[337:][:8] }
func (h *headerGNU) accessTime() []byte  { return h[345:][:12] }
func (h *headerGNU) changeTime() []byte  { return h[357:][:12] }
func (h *headerGNU) sparse() sparseArray { return sparseArray(h[386:][:24*4+1]) }
func (h *headerGNU) realSize() []byte    { return h[483:][:12] }

type headerSTAR [blockSize]byte

func (h *headerSTAR) v7() *headerV7      { return (*headerV7)(h) }
func (h *headerSTAR) magic() []byte      { return h[257:][:6] }
func (h *headerSTAR) version() []byte    { return h[263:][:2] }
func (h *headerSTAR) userName() []byte   { return h[265:][:32] }
func (h *headerSTAR) groupName() []byte  { return h[297:][:32] }
func (h *headerSTAR) devMajor() []byte   { return h[329:][:8] }
func (h *headerSTAR) devMinor() []byte   { return h[337:][:8] }
func (h *headerSTAR) prefix() []byte     { return h[345:][:131] }
func (h *headerSTAR) accessTime() []byte { return h[476:][:12] }
func (h *headerSTAR) changeTime() []byte { return h[488:][:12] }
func (h *headerSTAR) trailer() []byte    { return h[508:][:4] }

type headerUSTAR [blockSize]byte

func (h *headerUSTAR) v7() *headerV7     { return (*headerV7)(h) }
func (h *headerUSTAR) magic() []byte     { return h[257:][:6] }
func (h *headerUSTAR) version() []byte   { return h[263:][:2] }
func (h *headerUSTAR) userName() []byte  { return h[265:][:32] }
func (h *headerUSTAR) groupName() []byte { return h[297:][:32] }
func (h *headerUSTAR) devMajor() []byte  { return h[329:][:8] }
func (h *headerUSTAR) devMinor() []byte  { return h[337:][:8] }
func (h *headerUSTAR) prefix() []byte    { return h[345:][:155] }

type sparseArray []byte

func (s sparseArray) entry(i int) sparseElem { return sparseElem(s[i*24:]) }
func (s sparseArray) isExtended() []byte     { return s[24*s.maxEntries():][:1] }
func (s sparseArray) maxEntries() int        { return len(s) / 24 }

type sparseElem []byte

func (s sparseElem) offset() []byte { return s[00:][:12] }
func (s sparseElem) length() []byte { return s[12:][:12] }
```