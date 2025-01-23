Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Request:**

The request asks for a functional description of the Go code, specifically from `go/src/compress/flate/inflate.go`. It also requires:

* **Identifying the Go functionality:** What higher-level concept does this code implement?
* **Providing a Go code example:**  Illustrating how to use this functionality.
* **Explaining code reasoning (with assumptions, input, and output):** If any internal logic needs clarification.
* **Detailing command-line argument handling:** Though unlikely in this specific file.
* **Highlighting common user errors:**  If applicable.
* **Answering in Chinese.**

**2. Initial Code Scan and Keyword Identification:**

I started by scanning the code for key terms and structural elements:

* **`package flate`:**  Immediately tells me this is the `flate` package, likely related to data compression.
* **Comments referencing RFC 1951:** This is a crucial clue, pointing to the DEFLATE compression algorithm.
* **`inflate.go`:** The file name confirms it's the *decompression* part of the `flate` package.
* **`NewReader` and `NewReaderDict`:** These function names strongly suggest the creation of readers for decompression.
* **`io.Reader`, `io.ReadCloser`, `io.ByteReader`:**  Indicates interaction with the standard Go I/O interfaces.
* **`huffmanDecoder`:** Points to Huffman coding, a key element of DEFLATE.
* **`decompressor` struct:** The central structure managing the decompression process.
* **Error types (`CorruptInputError`, `InternalError`):**  Show error handling during decompression.
* **Constants (`maxCodeLen`, `maxNumLit`, `maxNumDist`, `numCodes`):**  Likely parameters of the DEFLATE algorithm.
* **`Resetter` interface:** Indicates the ability to reuse the reader.

**3. Core Functionality Deduction:**

Based on the keywords and comments, I concluded that this code implements **DEFLATE decompression** in Go. This is the primary function.

**4. Illustrative Go Code Example:**

To demonstrate usage, I needed a simple decompression scenario. This involved:

* **Creating compressed data:**  I chose to use the `compress/zlib` package for this, as it uses DEFLATE.
* **Using `bytes.Buffer` for in-memory I/O:**  This simplifies the example.
* **Calling `flate.NewReader`:** The core function to create the decompressor.
* **Reading from the decompressor:** Using `io.ReadAll`.
* **Handling potential errors.**

**5. Code Reasoning (Huffman Decoding):**

The `huffmanDecoder` and the `huffSym` function are the most complex parts. I focused on explaining:

* **Purpose of Huffman coding:** Efficient representation of symbols.
* **The `huffmanDecoder` struct:** Its components (`chunks`, `links`, `min`).
* **The `init` method:** How it builds the decoding tables from code lengths.
* **The `huffSym` method:** How it reads bits and uses the tables to decode symbols.
* **Assumptions:** That the input stream follows the DEFLATE Huffman coding rules.
* **Input/Output:**  Illustrating the process with a simple example of code lengths and how `init` might populate the `chunks` table.

**6. Command-Line Argument Handling:**

I correctly identified that this specific code snippet doesn't handle command-line arguments. The `flate` package itself is a library.

**7. Common User Errors:**

I thought about potential pitfalls when using decompression:

* **Incorrect input:**  Providing non-DEFLATE data.
* **Using the wrong dictionary:** For data compressed with a dictionary.
* **Resource management (closing the reader):** Though this is a general I/O issue, it's still relevant.

**8. Structuring the Answer in Chinese:**

Finally, I translated my understanding into clear and concise Chinese, ensuring proper terminology for programming concepts. I followed the requested format, listing functionalities, providing the code example, explaining code reasoning, addressing command-line arguments (or lack thereof), and discussing potential errors.

**Self-Correction/Refinement during the process:**

* **Initially, I considered focusing more on the `decompressor` struct.**  However, I realized that the Huffman decoding was a more specific and complex aspect requiring explanation.
* **I made sure the Go code example was self-contained and easy to understand.** Using standard library packages helped.
* **I double-checked the Chinese translation for accuracy and clarity.**  Technical terms needed to be precise.
* **I ensured that the "assumptions, input, output" for code reasoning were concrete and illustrative, rather than abstract.**

By following these steps, I arrived at the comprehensive and accurate answer provided previously. The key was breaking down the code into its functional components, identifying the core purpose, and then elaborating on the more technical aspects with clear examples and explanations.
这段代码是 Go 语言 `compress/flate` 包中 `inflate.go` 文件的一部分，它实现了 **DEFLATE 解压缩算法**。

以下是它的主要功能：

1. **定义了错误类型:**
   - `CorruptInputError`:  表示输入数据损坏。
   - `InternalError`: 表示 `flate` 包内部错误。
   - `ReadError`, `WriteError`: (已废弃) 曾经用于报告读写错误。

2. **定义了 `Resetter` 接口:**
   - 允许重用 `NewReader` 或 `NewReaderDict` 返回的 `ReadCloser`，避免重复分配内存。

3. **实现了 Huffman 解码器 (`huffmanDecoder`):**
   - 使用查找表和溢出链接来高效地解码 Huffman 编码。
   - `init` 方法根据给定的码长数组初始化 Huffman 解码表。

4. **定义了读取器接口 (`Reader`):**
   - 规定了解压缩器所需的输入接口，需要同时实现 `io.Reader` 和 `io.ByteReader`。

5. **实现了 `decompressor` 结构体:**
   - 存储了解压缩过程中的所有状态信息，例如：
     - 输入源 (`r`, `rBuf`, `roffset`)
     - 输入位缓冲区 (`b`, `nb`)
     - Huffman 解码器 (`h1`, `h2`)
     - 码长数组 (`bits`, `codebits`)
     - 输出历史缓冲区 (`dict`)
     - 临时缓冲区 (`buf`)
     - 解压缩步骤和状态 (`step`, `stepState`, `final`)
     - 错误信息 (`err`)
     - 待读取的输出数据 (`toRead`)
     - 当前处理的 Huffman 解码器 (`hl`, `hd`)
     - 复制长度和距离 (`copyLen`, `copyDist`)

6. **实现了 `Read` 方法:**
   - 是 `io.Reader` 接口的一部分，用于从解压缩器中读取解压后的数据。
   - 根据当前解压缩状态调用不同的步骤函数 (`step`) 来处理数据。

7. **实现了 `Close` 方法:**
   - 是 `io.Closer` 接口的一部分，用于关闭解压缩器。

8. **实现了不同的解压缩步骤函数:**
   - `nextBlock`: 读取下一个数据块的头部信息，判断块类型（未压缩、固定 Huffman 编码、动态 Huffman 编码）。
   - `dataBlock`: 处理未压缩的数据块。
   - `huffmanBlock`: 处理使用 Huffman 编码压缩的数据块。
   - `readHuffman`: 读取动态 Huffman 编码表的定义。
   - `copyData`: 将输入数据复制到输出缓冲区。

9. **实现了辅助函数:**
   - `moreBits`: 从输入流中读取更多位。
   - `huffSym`: 根据给定的 Huffman 解码器解码一个符号。
   - `makeReader`:  根据传入的 `io.Reader` 创建内部使用的 `Reader`，如果输入没有实现 `io.ByteReader`，则使用 `bufio.Reader` 进行缓冲。
   - `fixedHuffmanDecoderInit`: 初始化固定 Huffman 解码器 (只执行一次)。
   - `noEOF`: 将 `io.EOF` 转换为 `io.ErrUnexpectedEOF`。

10. **实现了 `Reset` 方法:**
    - 允许重置解压缩器以使用新的输入源和可选的预设字典。

11. **实现了 `NewReader` 函数:**
    - 创建一个新的 `io.ReadCloser`，用于读取未压缩的数据。
    - 如果传入的 `io.Reader` 没有实现 `io.ByteReader`，内部会使用缓冲。

12. **实现了 `NewReaderDict` 函数:**
    - 与 `NewReader` 类似，但允许指定一个预设字典，用于解压使用字典压缩的数据。

**它可以推理出是什么 Go 语言功能的实现：**

这段代码实现了 Go 语言标准库 `compress/flate` 包中的 **DEFLATE 解压缩功能**。DEFLATE 是一种广泛使用的无损数据压缩算法，常用于 gzip 和 zlib 等压缩格式。

**Go 代码举例说明:**

```go
package main

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"log"
)

func main() {
	// 假设这是经过 DEFLATE 压缩的数据
	compressedData := []byte{
		0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xfe, 0xfd,
	}

	// 使用 flate.NewReader 创建解压缩器
	reader := flate.NewReader(bytes.NewReader(compressedData))
	defer reader.Close()

	// 读取解压后的数据
	decompressedData, err := io.ReadAll(reader)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("解压后的数据: %s\n", string(decompressedData))

	// 使用 NewReaderDict 的例子 (假设我们有一个字典)
	compressedDataWithDict := []byte{
		// ... 一些使用字典压缩的数据 ...
	}
	dictionary := []byte("预设字典内容")

	readerWithDict := flate.NewReaderDict(bytes.NewReader(compressedDataWithDict), dictionary)
	defer readerWithDict.Close()

	decompressedDataWithDict, err := io.ReadAll(readerWithDict)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("使用字典解压后的数据: %s\n", string(decompressedDataWithDict))
}
```

**假设的输入与输出 (针对 `huffSym` 函数的代码推理):**

假设我们有一个简单的 Huffman 解码器，其 `chunks` 数组部分内容如下（简化示例，实际情况更复杂）：

```
h.chunks = [
    0x0308, // 索引 0: 值 3，长度 8
    0x0408, // 索引 1: 值 4，长度 8
    // ... 其他项 ...
]
h.min = 8
```

并且输入位缓冲区 `f.b` 中包含以下位（从低位到高位）：`10100110 0000...`， 且 `f.nb = 12`。

1. **输入:**  `f.b = ...000010100110`, `f.nb = 12`, `h.min = 8`
2. **`huffSym` 函数执行:**
   - 首次循环，`n = h.min = 8`。
   - `b & (huffmanNumChunks - 1)`，假设 `huffmanNumChunks` 是 512，则会取 `b` 的低 9 位 (因为 `huffmanChunkBits` 是 9)。假设低 9 位的值映射到 `h.chunks` 的索引 6，且 `h.chunks[6]` 的值为 `0x0308`。
   - `chunk & huffmanCountMask` 得到长度 `n = 8`。
   - `n <= nb` (8 <= 12) 为真。
   - `f.b >>= n`，`f.b` 右移 8 位。
   - `f.nb -= n`，`f.nb` 变为 4。
   - 返回 `int(chunk >> huffmanValueShift)`，即 `int(0x0308 >> 4)`，得到值 `3`。

3. **输出:** `3`

**假设的输入与输出 (针对 `dataBlock` 函数的代码推理):**

假设输入流 `f.r` 的下一个 4 字节为 `0x05 0x00 0xfa 0xff`。

1. **输入:** 输入流接下来的 4 字节: `0x05 0x00 0xfa 0xff`
2. **`dataBlock` 函数执行:**
   - 从 `f.r` 读取 4 字节到 `f.buf[0:4]`。
   - `n` 计算为 `int(0x05) | int(0x00)<<8 = 5`。
   - `nn` 计算为 `int(0xfa) | int(0xff)<<8 = 65530`。
   - 检查 `uint16(nn) != uint16(^n)`，其中 `^n` (按位取反) 为 `^5 = ...11111010` (二进制)，其低 16 位为 `0xfffa`，转换为十进制为 65530。
   - 条件成立，继续执行。
   - 假设 `n` 不为 0，`f.copyLen` 设置为 5。
   - 调用 `f.copyData()`，将接下来的 5 字节从输入流复制到输出缓冲区。

3. **输出:** 如果 `f.dict` 成功写入了 5 字节，则输出缓冲区会增加这 5 字节的数据。

**命令行参数的具体处理:**

这段代码本身是库代码，不直接处理命令行参数。命令行参数的处理通常发生在调用此库的应用程序中。例如，如果一个名为 `mygzip` 的程序使用了 `compress/flate`，那么 `mygzip` 的 `main` 函数会处理命令行参数，例如输入和输出文件名。

**使用者易犯错的点:**

1. **没有正确处理 `Close` 方法:**  `NewReader` 和 `NewReaderDict` 返回的是 `io.ReadCloser`，使用完毕后需要调用 `Close` 方法释放资源。不调用 `Close` 可能会导致资源泄漏。

   ```go
   // 错误示例
   func processCompressedData(r io.Reader) error {
       reader := flate.NewReader(r)
       data, err := io.ReadAll(reader)
       if err != nil {
           return err
       }
       // ... 处理 data ...
       return nil // 忘记调用 reader.Close()
   }

   // 正确示例
   func processCompressedDataCorrectly(r io.Reader) error {
       reader := flate.NewReader(r)
       defer reader.Close() // 确保在函数退出时关闭 reader
       data, err := io.ReadAll(reader)
       if err != nil {
           return err
       }
       // ... 处理 data ...
       return nil
   }
   ```

2. **在需要字典解压时使用了 `NewReader` 而不是 `NewReaderDict`:** 如果数据是用字典压缩的，必须使用 `NewReaderDict` 并提供相同的字典才能正确解压。

   ```go
   // 错误示例 (假设 dataWithDict 是用字典压缩的)
   func decompressWithoutDict(r io.Reader) ([]byte, error) {
       reader := flate.NewReader(r)
       defer reader.Close()
       return io.ReadAll(reader) // 解压失败或得到错误结果
   }

   // 正确示例
   func decompressWithDict(r io.Reader, dict []byte) ([]byte, error) {
       reader := flate.NewReaderDict(r, dict)
       defer reader.Close()
       return io.ReadAll(reader) // 正确解压
   }
   ```

3. **假设输入总是有效的 DEFLATE 数据:**  如果提供的输入不是有效的 DEFLATE 压缩数据，`flate.NewReader` 返回的读取器在 `Read` 方法中会返回 `CorruptInputError`。使用者需要妥善处理这种错误。

总而言之，这段代码是 Go 语言中处理 DEFLATE 解压缩的核心实现，它定义了数据结构、错误类型以及解压缩的各个步骤，为上层应用提供了可靠的解压缩能力。

### 提示词
```
这是路径为go/src/compress/flate/inflate.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package flate implements the DEFLATE compressed data format, described in
// RFC 1951.  The gzip and zlib packages implement access to DEFLATE-based file
// formats.
package flate

import (
	"bufio"
	"io"
	"math/bits"
	"strconv"
	"sync"
)

const (
	maxCodeLen = 16 // max length of Huffman code
	// The next three numbers come from the RFC section 3.2.7, with the
	// additional proviso in section 3.2.5 which implies that distance codes
	// 30 and 31 should never occur in compressed data.
	maxNumLit  = 286
	maxNumDist = 30
	numCodes   = 19 // number of codes in Huffman meta-code
)

// Initialize the fixedHuffmanDecoder only once upon first use.
var fixedOnce sync.Once
var fixedHuffmanDecoder huffmanDecoder

// A CorruptInputError reports the presence of corrupt input at a given offset.
type CorruptInputError int64

func (e CorruptInputError) Error() string {
	return "flate: corrupt input before offset " + strconv.FormatInt(int64(e), 10)
}

// An InternalError reports an error in the flate code itself.
type InternalError string

func (e InternalError) Error() string { return "flate: internal error: " + string(e) }

// A ReadError reports an error encountered while reading input.
//
// Deprecated: No longer returned.
type ReadError struct {
	Offset int64 // byte offset where error occurred
	Err    error // error returned by underlying Read
}

func (e *ReadError) Error() string {
	return "flate: read error at offset " + strconv.FormatInt(e.Offset, 10) + ": " + e.Err.Error()
}

// A WriteError reports an error encountered while writing output.
//
// Deprecated: No longer returned.
type WriteError struct {
	Offset int64 // byte offset where error occurred
	Err    error // error returned by underlying Write
}

func (e *WriteError) Error() string {
	return "flate: write error at offset " + strconv.FormatInt(e.Offset, 10) + ": " + e.Err.Error()
}

// Resetter resets a ReadCloser returned by [NewReader] or [NewReaderDict]
// to switch to a new underlying [Reader]. This permits reusing a ReadCloser
// instead of allocating a new one.
type Resetter interface {
	// Reset discards any buffered data and resets the Resetter as if it was
	// newly initialized with the given reader.
	Reset(r io.Reader, dict []byte) error
}

// The data structure for decoding Huffman tables is based on that of
// zlib. There is a lookup table of a fixed bit width (huffmanChunkBits),
// For codes smaller than the table width, there are multiple entries
// (each combination of trailing bits has the same value). For codes
// larger than the table width, the table contains a link to an overflow
// table. The width of each entry in the link table is the maximum code
// size minus the chunk width.
//
// Note that you can do a lookup in the table even without all bits
// filled. Since the extra bits are zero, and the DEFLATE Huffman codes
// have the property that shorter codes come before longer ones, the
// bit length estimate in the result is a lower bound on the actual
// number of bits.
//
// See the following:
//	https://github.com/madler/zlib/raw/master/doc/algorithm.txt

// chunk & 15 is number of bits
// chunk >> 4 is value, including table link

const (
	huffmanChunkBits  = 9
	huffmanNumChunks  = 1 << huffmanChunkBits
	huffmanCountMask  = 15
	huffmanValueShift = 4
)

type huffmanDecoder struct {
	min      int                      // the minimum code length
	chunks   [huffmanNumChunks]uint32 // chunks as described above
	links    [][]uint32               // overflow links
	linkMask uint32                   // mask the width of the link table
}

// Initialize Huffman decoding tables from array of code lengths.
// Following this function, h is guaranteed to be initialized into a complete
// tree (i.e., neither over-subscribed nor under-subscribed). The exception is a
// degenerate case where the tree has only a single symbol with length 1. Empty
// trees are permitted.
func (h *huffmanDecoder) init(lengths []int) bool {
	// Sanity enables additional runtime tests during Huffman
	// table construction. It's intended to be used during
	// development to supplement the currently ad-hoc unit tests.
	const sanity = false

	if h.min != 0 {
		*h = huffmanDecoder{}
	}

	// Count number of codes of each length,
	// compute min and max length.
	var count [maxCodeLen]int
	var min, max int
	for _, n := range lengths {
		if n == 0 {
			continue
		}
		if min == 0 || n < min {
			min = n
		}
		if n > max {
			max = n
		}
		count[n]++
	}

	// Empty tree. The decompressor.huffSym function will fail later if the tree
	// is used. Technically, an empty tree is only valid for the HDIST tree and
	// not the HCLEN and HLIT tree. However, a stream with an empty HCLEN tree
	// is guaranteed to fail since it will attempt to use the tree to decode the
	// codes for the HLIT and HDIST trees. Similarly, an empty HLIT tree is
	// guaranteed to fail later since the compressed data section must be
	// composed of at least one symbol (the end-of-block marker).
	if max == 0 {
		return true
	}

	code := 0
	var nextcode [maxCodeLen]int
	for i := min; i <= max; i++ {
		code <<= 1
		nextcode[i] = code
		code += count[i]
	}

	// Check that the coding is complete (i.e., that we've
	// assigned all 2-to-the-max possible bit sequences).
	// Exception: To be compatible with zlib, we also need to
	// accept degenerate single-code codings. See also
	// TestDegenerateHuffmanCoding.
	if code != 1<<uint(max) && !(code == 1 && max == 1) {
		return false
	}

	h.min = min
	if max > huffmanChunkBits {
		numLinks := 1 << (uint(max) - huffmanChunkBits)
		h.linkMask = uint32(numLinks - 1)

		// create link tables
		link := nextcode[huffmanChunkBits+1] >> 1
		h.links = make([][]uint32, huffmanNumChunks-link)
		for j := uint(link); j < huffmanNumChunks; j++ {
			reverse := int(bits.Reverse16(uint16(j)))
			reverse >>= uint(16 - huffmanChunkBits)
			off := j - uint(link)
			if sanity && h.chunks[reverse] != 0 {
				panic("impossible: overwriting existing chunk")
			}
			h.chunks[reverse] = uint32(off<<huffmanValueShift | (huffmanChunkBits + 1))
			h.links[off] = make([]uint32, numLinks)
		}
	}

	for i, n := range lengths {
		if n == 0 {
			continue
		}
		code := nextcode[n]
		nextcode[n]++
		chunk := uint32(i<<huffmanValueShift | n)
		reverse := int(bits.Reverse16(uint16(code)))
		reverse >>= uint(16 - n)
		if n <= huffmanChunkBits {
			for off := reverse; off < len(h.chunks); off += 1 << uint(n) {
				// We should never need to overwrite
				// an existing chunk. Also, 0 is
				// never a valid chunk, because the
				// lower 4 "count" bits should be
				// between 1 and 15.
				if sanity && h.chunks[off] != 0 {
					panic("impossible: overwriting existing chunk")
				}
				h.chunks[off] = chunk
			}
		} else {
			j := reverse & (huffmanNumChunks - 1)
			if sanity && h.chunks[j]&huffmanCountMask != huffmanChunkBits+1 {
				// Longer codes should have been
				// associated with a link table above.
				panic("impossible: not an indirect chunk")
			}
			value := h.chunks[j] >> huffmanValueShift
			linktab := h.links[value]
			reverse >>= huffmanChunkBits
			for off := reverse; off < len(linktab); off += 1 << uint(n-huffmanChunkBits) {
				if sanity && linktab[off] != 0 {
					panic("impossible: overwriting existing chunk")
				}
				linktab[off] = chunk
			}
		}
	}

	if sanity {
		// Above we've sanity checked that we never overwrote
		// an existing entry. Here we additionally check that
		// we filled the tables completely.
		for i, chunk := range h.chunks {
			if chunk == 0 {
				// As an exception, in the degenerate
				// single-code case, we allow odd
				// chunks to be missing.
				if code == 1 && i%2 == 1 {
					continue
				}
				panic("impossible: missing chunk")
			}
		}
		for _, linktab := range h.links {
			for _, chunk := range linktab {
				if chunk == 0 {
					panic("impossible: missing chunk")
				}
			}
		}
	}

	return true
}

// The actual read interface needed by [NewReader].
// If the passed in io.Reader does not also have ReadByte,
// the [NewReader] will introduce its own buffering.
type Reader interface {
	io.Reader
	io.ByteReader
}

// Decompress state.
type decompressor struct {
	// Input source.
	r       Reader
	rBuf    *bufio.Reader // created if provided io.Reader does not implement io.ByteReader
	roffset int64

	// Input bits, in top of b.
	b  uint32
	nb uint

	// Huffman decoders for literal/length, distance.
	h1, h2 huffmanDecoder

	// Length arrays used to define Huffman codes.
	bits     *[maxNumLit + maxNumDist]int
	codebits *[numCodes]int

	// Output history, buffer.
	dict dictDecoder

	// Temporary buffer (avoids repeated allocation).
	buf [4]byte

	// Next step in the decompression,
	// and decompression state.
	step      func(*decompressor)
	stepState int
	final     bool
	err       error
	toRead    []byte
	hl, hd    *huffmanDecoder
	copyLen   int
	copyDist  int
}

func (f *decompressor) nextBlock() {
	for f.nb < 1+2 {
		if f.err = f.moreBits(); f.err != nil {
			return
		}
	}
	f.final = f.b&1 == 1
	f.b >>= 1
	typ := f.b & 3
	f.b >>= 2
	f.nb -= 1 + 2
	switch typ {
	case 0:
		f.dataBlock()
	case 1:
		// compressed, fixed Huffman tables
		f.hl = &fixedHuffmanDecoder
		f.hd = nil
		f.huffmanBlock()
	case 2:
		// compressed, dynamic Huffman tables
		if f.err = f.readHuffman(); f.err != nil {
			break
		}
		f.hl = &f.h1
		f.hd = &f.h2
		f.huffmanBlock()
	default:
		// 3 is reserved.
		f.err = CorruptInputError(f.roffset)
	}
}

func (f *decompressor) Read(b []byte) (int, error) {
	for {
		if len(f.toRead) > 0 {
			n := copy(b, f.toRead)
			f.toRead = f.toRead[n:]
			if len(f.toRead) == 0 {
				return n, f.err
			}
			return n, nil
		}
		if f.err != nil {
			return 0, f.err
		}
		f.step(f)
		if f.err != nil && len(f.toRead) == 0 {
			f.toRead = f.dict.readFlush() // Flush what's left in case of error
		}
	}
}

func (f *decompressor) Close() error {
	if f.err == io.EOF {
		return nil
	}
	return f.err
}

// RFC 1951 section 3.2.7.
// Compression with dynamic Huffman codes

var codeOrder = [...]int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

func (f *decompressor) readHuffman() error {
	// HLIT[5], HDIST[5], HCLEN[4].
	for f.nb < 5+5+4 {
		if err := f.moreBits(); err != nil {
			return err
		}
	}
	nlit := int(f.b&0x1F) + 257
	if nlit > maxNumLit {
		return CorruptInputError(f.roffset)
	}
	f.b >>= 5
	ndist := int(f.b&0x1F) + 1
	if ndist > maxNumDist {
		return CorruptInputError(f.roffset)
	}
	f.b >>= 5
	nclen := int(f.b&0xF) + 4
	// numCodes is 19, so nclen is always valid.
	f.b >>= 4
	f.nb -= 5 + 5 + 4

	// (HCLEN+4)*3 bits: code lengths in the magic codeOrder order.
	for i := 0; i < nclen; i++ {
		for f.nb < 3 {
			if err := f.moreBits(); err != nil {
				return err
			}
		}
		f.codebits[codeOrder[i]] = int(f.b & 0x7)
		f.b >>= 3
		f.nb -= 3
	}
	for i := nclen; i < len(codeOrder); i++ {
		f.codebits[codeOrder[i]] = 0
	}
	if !f.h1.init(f.codebits[0:]) {
		return CorruptInputError(f.roffset)
	}

	// HLIT + 257 code lengths, HDIST + 1 code lengths,
	// using the code length Huffman code.
	for i, n := 0, nlit+ndist; i < n; {
		x, err := f.huffSym(&f.h1)
		if err != nil {
			return err
		}
		if x < 16 {
			// Actual length.
			f.bits[i] = x
			i++
			continue
		}
		// Repeat previous length or zero.
		var rep int
		var nb uint
		var b int
		switch x {
		default:
			return InternalError("unexpected length code")
		case 16:
			rep = 3
			nb = 2
			if i == 0 {
				return CorruptInputError(f.roffset)
			}
			b = f.bits[i-1]
		case 17:
			rep = 3
			nb = 3
			b = 0
		case 18:
			rep = 11
			nb = 7
			b = 0
		}
		for f.nb < nb {
			if err := f.moreBits(); err != nil {
				return err
			}
		}
		rep += int(f.b & uint32(1<<nb-1))
		f.b >>= nb
		f.nb -= nb
		if i+rep > n {
			return CorruptInputError(f.roffset)
		}
		for j := 0; j < rep; j++ {
			f.bits[i] = b
			i++
		}
	}

	if !f.h1.init(f.bits[0:nlit]) || !f.h2.init(f.bits[nlit:nlit+ndist]) {
		return CorruptInputError(f.roffset)
	}

	// As an optimization, we can initialize the min bits to read at a time
	// for the HLIT tree to the length of the EOB marker since we know that
	// every block must terminate with one. This preserves the property that
	// we never read any extra bytes after the end of the DEFLATE stream.
	if f.h1.min < f.bits[endBlockMarker] {
		f.h1.min = f.bits[endBlockMarker]
	}

	return nil
}

// Decode a single Huffman block from f.
// hl and hd are the Huffman states for the lit/length values
// and the distance values, respectively. If hd == nil, using the
// fixed distance encoding associated with fixed Huffman blocks.
func (f *decompressor) huffmanBlock() {
	const (
		stateInit = iota // Zero value must be stateInit
		stateDict
	)

	switch f.stepState {
	case stateInit:
		goto readLiteral
	case stateDict:
		goto copyHistory
	}

readLiteral:
	// Read literal and/or (length, distance) according to RFC section 3.2.3.
	{
		v, err := f.huffSym(f.hl)
		if err != nil {
			f.err = err
			return
		}
		var n uint // number of bits extra
		var length int
		switch {
		case v < 256:
			f.dict.writeByte(byte(v))
			if f.dict.availWrite() == 0 {
				f.toRead = f.dict.readFlush()
				f.step = (*decompressor).huffmanBlock
				f.stepState = stateInit
				return
			}
			goto readLiteral
		case v == 256:
			f.finishBlock()
			return
		// otherwise, reference to older data
		case v < 265:
			length = v - (257 - 3)
			n = 0
		case v < 269:
			length = v*2 - (265*2 - 11)
			n = 1
		case v < 273:
			length = v*4 - (269*4 - 19)
			n = 2
		case v < 277:
			length = v*8 - (273*8 - 35)
			n = 3
		case v < 281:
			length = v*16 - (277*16 - 67)
			n = 4
		case v < 285:
			length = v*32 - (281*32 - 131)
			n = 5
		case v < maxNumLit:
			length = 258
			n = 0
		default:
			f.err = CorruptInputError(f.roffset)
			return
		}
		if n > 0 {
			for f.nb < n {
				if err = f.moreBits(); err != nil {
					f.err = err
					return
				}
			}
			length += int(f.b & uint32(1<<n-1))
			f.b >>= n
			f.nb -= n
		}

		var dist int
		if f.hd == nil {
			for f.nb < 5 {
				if err = f.moreBits(); err != nil {
					f.err = err
					return
				}
			}
			dist = int(bits.Reverse8(uint8(f.b & 0x1F << 3)))
			f.b >>= 5
			f.nb -= 5
		} else {
			if dist, err = f.huffSym(f.hd); err != nil {
				f.err = err
				return
			}
		}

		switch {
		case dist < 4:
			dist++
		case dist < maxNumDist:
			nb := uint(dist-2) >> 1
			// have 1 bit in bottom of dist, need nb more.
			extra := (dist & 1) << nb
			for f.nb < nb {
				if err = f.moreBits(); err != nil {
					f.err = err
					return
				}
			}
			extra |= int(f.b & uint32(1<<nb-1))
			f.b >>= nb
			f.nb -= nb
			dist = 1<<(nb+1) + 1 + extra
		default:
			f.err = CorruptInputError(f.roffset)
			return
		}

		// No check on length; encoding can be prescient.
		if dist > f.dict.histSize() {
			f.err = CorruptInputError(f.roffset)
			return
		}

		f.copyLen, f.copyDist = length, dist
		goto copyHistory
	}

copyHistory:
	// Perform a backwards copy according to RFC section 3.2.3.
	{
		cnt := f.dict.tryWriteCopy(f.copyDist, f.copyLen)
		if cnt == 0 {
			cnt = f.dict.writeCopy(f.copyDist, f.copyLen)
		}
		f.copyLen -= cnt

		if f.dict.availWrite() == 0 || f.copyLen > 0 {
			f.toRead = f.dict.readFlush()
			f.step = (*decompressor).huffmanBlock // We need to continue this work
			f.stepState = stateDict
			return
		}
		goto readLiteral
	}
}

// Copy a single uncompressed data block from input to output.
func (f *decompressor) dataBlock() {
	// Uncompressed.
	// Discard current half-byte.
	f.nb = 0
	f.b = 0

	// Length then ones-complement of length.
	nr, err := io.ReadFull(f.r, f.buf[0:4])
	f.roffset += int64(nr)
	if err != nil {
		f.err = noEOF(err)
		return
	}
	n := int(f.buf[0]) | int(f.buf[1])<<8
	nn := int(f.buf[2]) | int(f.buf[3])<<8
	if uint16(nn) != uint16(^n) {
		f.err = CorruptInputError(f.roffset)
		return
	}

	if n == 0 {
		f.toRead = f.dict.readFlush()
		f.finishBlock()
		return
	}

	f.copyLen = n
	f.copyData()
}

// copyData copies f.copyLen bytes from the underlying reader into f.hist.
// It pauses for reads when f.hist is full.
func (f *decompressor) copyData() {
	buf := f.dict.writeSlice()
	if len(buf) > f.copyLen {
		buf = buf[:f.copyLen]
	}

	cnt, err := io.ReadFull(f.r, buf)
	f.roffset += int64(cnt)
	f.copyLen -= cnt
	f.dict.writeMark(cnt)
	if err != nil {
		f.err = noEOF(err)
		return
	}

	if f.dict.availWrite() == 0 || f.copyLen > 0 {
		f.toRead = f.dict.readFlush()
		f.step = (*decompressor).copyData
		return
	}
	f.finishBlock()
}

func (f *decompressor) finishBlock() {
	if f.final {
		if f.dict.availRead() > 0 {
			f.toRead = f.dict.readFlush()
		}
		f.err = io.EOF
	}
	f.step = (*decompressor).nextBlock
}

// noEOF returns err, unless err == io.EOF, in which case it returns io.ErrUnexpectedEOF.
func noEOF(e error) error {
	if e == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return e
}

func (f *decompressor) moreBits() error {
	c, err := f.r.ReadByte()
	if err != nil {
		return noEOF(err)
	}
	f.roffset++
	f.b |= uint32(c) << f.nb
	f.nb += 8
	return nil
}

// Read the next Huffman-encoded symbol from f according to h.
func (f *decompressor) huffSym(h *huffmanDecoder) (int, error) {
	// Since a huffmanDecoder can be empty or be composed of a degenerate tree
	// with single element, huffSym must error on these two edge cases. In both
	// cases, the chunks slice will be 0 for the invalid sequence, leading it
	// satisfy the n == 0 check below.
	n := uint(h.min)
	// Optimization. Compiler isn't smart enough to keep f.b,f.nb in registers,
	// but is smart enough to keep local variables in registers, so use nb and b,
	// inline call to moreBits and reassign b,nb back to f on return.
	nb, b := f.nb, f.b
	for {
		for nb < n {
			c, err := f.r.ReadByte()
			if err != nil {
				f.b = b
				f.nb = nb
				return 0, noEOF(err)
			}
			f.roffset++
			b |= uint32(c) << (nb & 31)
			nb += 8
		}
		chunk := h.chunks[b&(huffmanNumChunks-1)]
		n = uint(chunk & huffmanCountMask)
		if n > huffmanChunkBits {
			chunk = h.links[chunk>>huffmanValueShift][(b>>huffmanChunkBits)&h.linkMask]
			n = uint(chunk & huffmanCountMask)
		}
		if n <= nb {
			if n == 0 {
				f.b = b
				f.nb = nb
				f.err = CorruptInputError(f.roffset)
				return 0, f.err
			}
			f.b = b >> (n & 31)
			f.nb = nb - n
			return int(chunk >> huffmanValueShift), nil
		}
	}
}

func (f *decompressor) makeReader(r io.Reader) {
	if rr, ok := r.(Reader); ok {
		f.rBuf = nil
		f.r = rr
		return
	}
	// Reuse rBuf if possible. Invariant: rBuf is always created (and owned) by decompressor.
	if f.rBuf != nil {
		f.rBuf.Reset(r)
	} else {
		// bufio.NewReader will not return r, as r does not implement flate.Reader, so it is not bufio.Reader.
		f.rBuf = bufio.NewReader(r)
	}
	f.r = f.rBuf
}

func fixedHuffmanDecoderInit() {
	fixedOnce.Do(func() {
		// These come from the RFC section 3.2.6.
		var bits [288]int
		for i := 0; i < 144; i++ {
			bits[i] = 8
		}
		for i := 144; i < 256; i++ {
			bits[i] = 9
		}
		for i := 256; i < 280; i++ {
			bits[i] = 7
		}
		for i := 280; i < 288; i++ {
			bits[i] = 8
		}
		fixedHuffmanDecoder.init(bits[:])
	})
}

func (f *decompressor) Reset(r io.Reader, dict []byte) error {
	*f = decompressor{
		rBuf:     f.rBuf,
		bits:     f.bits,
		codebits: f.codebits,
		dict:     f.dict,
		step:     (*decompressor).nextBlock,
	}
	f.makeReader(r)
	f.dict.init(maxMatchOffset, dict)
	return nil
}

// NewReader returns a new ReadCloser that can be used
// to read the uncompressed version of r.
// If r does not also implement [io.ByteReader],
// the decompressor may read more data than necessary from r.
// The reader returns [io.EOF] after the final block in the DEFLATE stream has
// been encountered. Any trailing data after the final block is ignored.
//
// The [io.ReadCloser] returned by NewReader also implements [Resetter].
func NewReader(r io.Reader) io.ReadCloser {
	fixedHuffmanDecoderInit()

	var f decompressor
	f.makeReader(r)
	f.bits = new([maxNumLit + maxNumDist]int)
	f.codebits = new([numCodes]int)
	f.step = (*decompressor).nextBlock
	f.dict.init(maxMatchOffset, nil)
	return &f
}

// NewReaderDict is like [NewReader] but initializes the reader
// with a preset dictionary. The returned [Reader] behaves as if
// the uncompressed data stream started with the given dictionary,
// which has already been read. NewReaderDict is typically used
// to read data compressed by NewWriterDict.
//
// The ReadCloser returned by NewReaderDict also implements [Resetter].
func NewReaderDict(r io.Reader, dict []byte) io.ReadCloser {
	fixedHuffmanDecoderInit()

	var f decompressor
	f.makeReader(r)
	f.bits = new([maxNumLit + maxNumDist]int)
	f.codebits = new([numCodes]int)
	f.step = (*decompressor).nextBlock
	f.dict.init(maxMatchOffset, dict)
	return &f
}
```