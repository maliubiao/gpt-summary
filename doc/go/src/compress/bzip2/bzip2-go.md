Response:
My thinking process to answer the user's request about the `bzip2.go` file goes like this:

1. **Understand the Goal:** The user wants to know the functionality of the provided Go code snippet, which is a part of the `compress/bzip2` package. They also want examples and information about potential pitfalls.

2. **Identify the Core Functionality:**  The package name and the `NewReader` function immediately suggest that this code is for *decompressing* bzip2 compressed data. The comments confirm this.

3. **Break Down the Code into Key Components:** I mentally (or could physically) divide the code into logical sections:
    * **Error Handling:** `StructuralError`
    * **Main Reader Structure:** `reader` struct and its fields. I need to understand what each field represents in the decompression process.
    * **`NewReader` Function:** The entry point for using the decompressor.
    * **Magic Number Handling:** `bzip2FileMagic`, `bzip2BlockMagic`, `bzip2FinalMagic`, and the `setup` function.
    * **`Read` Function:** The core method for reading and decompressing data.
    * **Block Processing:** `readFromBlock` and `readBlock`. These seem crucial to the bzip2 format.
    * **Inverse Burrows-Wheeler Transform (IBWT):** The `inverseBWT` function.
    * **Cyclic Redundancy Check (CRC):** `updateCRC` and related constants.

4. **Analyze Each Component and Explain Its Purpose:**

    * **Error Handling:**  Straightforward – indicates invalid bzip2 data.
    * **`reader` struct:** I need to describe the role of each field:
        * `br`: Reading bits from the input stream.
        * `fileCRC`, `blockCRC`, `wantBlockCRC`: Integrity checks.
        * `setupDone`, `eof`: State management.
        * `blockSize`:  Compression parameter.
        * `c`, `tt`: Internal buffers used for decompression (IBWT).
        * `tPos`:  Index within `tt`.
        * `preRLE`, `preRLEUsed`, `lastByte`, `byteRepeats`, `repeats`:  Run-length encoding related state.
    * **`NewReader`:**  Simple constructor. Important to note the `io.ByteReader` point.
    * **Magic Numbers and `setup`:** Explain the purpose of the magic numbers for identifying file and block boundaries. The `setup` function parses the header and extracts key parameters like the compression level.
    * **`Read`:** This is the main interface. It initializes the decompression (calls `setup`), reads from blocks, and handles end-of-file conditions.
    * **`readFromBlock`:** Explains the run-length decoding logic. Highlight the state management within the `reader` struct.
    * **`readBlock`:**  Details the processing of a single bzip2 block: CRC checking, handling Huffman codes, move-to-front decoding, and the IBWT.
    * **`inverseBWT`:** Describe the function's role in reversing the BWT, a key part of bzip2.
    * **CRC:** Explain its purpose in data integrity.

5. **Illustrate with Go Code Examples:** For the core functionality (decompression), provide a simple example using `NewReader` and `io.ReadAll`. This demonstrates how to use the package.

6. **Address Code Reasoning (with Assumptions):**  Focus on the `readBlock` function as it's the most complex. Create a simplified scenario with assumptions about input bitstream values to show how Huffman decoding, move-to-front, and the beginning of IBWT work. This will require making up plausible (but simple) bit sequences and showing the transformations. *Initially, I considered going deeper into the IBWT, but realized it would make the example too complex for a reasonable explanation. Focusing on the earlier stages is sufficient.*

7. **Explain Command-Line Arguments (If Applicable):**  In this case, the `bzip2` package doesn't directly handle command-line arguments. Mention this and point out that external tools like `gzip` or shell commands would use this package.

8. **Highlight Common Mistakes:** Think about the common ways users might misuse the package:
    * **Not handling errors:**  Emphasize checking the error returned by `Read`.
    * **Providing non-bzip2 data:** Explain what happens in this scenario (the `StructuralError`).
    * **Incorrect usage with large files:** Although not explicitly in the code, consider mentioning potential memory usage if users try to read very large compressed files entirely into memory. *Decided against this as the user's question is focused on the code itself.*

9. **Structure the Answer Clearly:** Use headings, bullet points, and code formatting to make the answer easy to read and understand. Start with a high-level summary and then go into more detail.

10. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check that the code examples are correct and the explanations are easy to follow. Ensure the language is natural and in Chinese as requested.

By following these steps, I can generate a comprehensive and helpful answer that addresses all aspects of the user's request. The key is to break down the problem, analyze each component, provide relevant examples, and anticipate potential issues.
这段Go语言代码是 `compress/bzip2` 包的一部分，它实现了 **bzip2 格式的解压缩功能**。

以下是它的具体功能分解：

**1. 定义了错误类型 `StructuralError`:**

   - 这个自定义错误类型用于表示 bzip2 数据格式不正确或损坏的情况。
   - 当解析 bzip2 数据时遇到语法错误，例如魔数不匹配、压缩级别无效等，会返回 `StructuralError`。

**2. 定义了解压缩器 `reader` 结构体:**

   - `reader` 结构体是 bzip2 解压缩器的核心。它包含了解压缩过程所需的各种状态信息和缓冲区。
   - 主要字段包括：
     - `br`: `bitReader` 类型的字段，用于从输入流中按位读取数据。
     - `fileCRC`, `blockCRC`, `wantBlockCRC`: 用于校验文件和数据块的 CRC 校验和。
     - `setupDone`: 布尔值，指示是否已完成 bzip2 头的解析。
     - `eof`: 布尔值，指示是否已到达输入流的末尾。
     - `blockSize`: 整型，表示数据块的大小（以字节为单位）。
     - `c`: `[256]uint` 类型的数组，用于逆 BWT（Burrows-Wheeler Transform）。
     - `tt`: `[]uint32` 类型的切片，用于存储逆 BWT 的中间结果和 P 数组。
     - `tPos`: `uint32` 类型，指示 `tt` 中下一个输出字节的索引。
     - `preRLE`: `[]uint32` 类型的切片，存储尚未处理的 RLE（Run-Length Encoding）数据。
     - `preRLEUsed`: 整型，指示 `preRLE` 中已使用的条目数量。
     - `lastByte`: 整型，记录上一个遇到的字节值。
     - `byteRepeats`: `uint` 类型，记录连续重复的 `lastByte` 的次数。
     - `repeats`: `uint` 类型，记录需要输出的 `lastByte` 的副本数量。

**3. 提供了 `NewReader` 函数:**

   - `NewReader(r io.Reader) io.Reader` 函数接收一个 `io.Reader` 类型的参数 `r`，该参数提供 bzip2 压缩的数据流。
   - 它创建一个新的 `reader` 实例，并使用传入的 `io.Reader` 初始化其内部的 `bitReader`。
   - 返回一个 `io.Reader` 接口，用户可以通过这个接口读取解压缩后的数据。
   - **注意:** 如果传入的 `io.Reader` 没有实现 `io.ByteReader` 接口，解压缩器可能会从 `r` 中读取比实际需要更多的数据。

**4. 定义了 bzip2 的魔数值:**

   - `bzip2FileMagic = 0x425a` ("BZ"): 文件头的魔数。
   - `bzip2BlockMagic = 0x314159265359`: 数据块头的魔数。
   - `bzip2FinalMagic = 0x177245385090`: 文件结束标志的魔数。

**5. 实现了 `setup` 方法:**

   - `setup(needMagic bool) error` 方法用于解析 bzip2 文件的头部信息。
   - 如果 `needMagic` 为 `true`，它会首先检查文件头的魔数是否为 `bzip2FileMagic`。
   - 接着，它读取压缩方法（必须为 'h'，表示 Huffman 编码）和压缩级别（'1' 到 '9'）。
   - 根据压缩级别计算数据块大小 `blockSize`。
   - 初始化文件 CRC 校验和。

**6. 实现了 `Read` 方法:**

   - `Read(buf []byte) (n int, err error)` 是 `io.Reader` 接口的实现，用于读取解压缩后的数据到提供的缓冲区 `buf` 中。
   - 如果尚未完成头部解析 (`!bz2.setupDone`)，则会先调用 `setup` 方法。
   - 调用内部的 `read` 方法来实际执行读取和解压缩操作。
   - 处理底层的 `bitReader` 发生的错误。

**7. 实现了 `readFromBlock` 方法:**

   - `readFromBlock(buf []byte) int` 方法负责从当前解压缩的数据块中读取数据到缓冲区 `buf` 中。
   - 它处理 bzip2 的 Run-Length Encoding (RLE) 预处理步骤。
   - 它维护 RLE 的状态（`lastByte`, `byteRepeats`, `repeats`）来还原原始数据。

**8. 实现了 `read` 方法:**

   - `read(buf []byte) (int, error)` 方法是主要的解压缩逻辑所在。
   - 它循环读取数据块，直到缓冲区 `buf` 填满或遇到文件结尾。
   - 调用 `readFromBlock` 从当前块读取数据。
   - 在每个数据块结束时，它会检查块的 CRC 校验和。
   - 它会查找下一个数据块的魔数 (`bzip2BlockMagic`) 或文件结束的魔数 (`bzip2FinalMagic`)。
   - 如果遇到文件结束魔数，它会校验整个文件的 CRC 校验和。
   - 它还处理连续的 bzip2 文件拼接的情况。

**9. 实现了 `readBlock` 方法:**

   - `readBlock() error` 方法负责读取和解压缩一个 bzip2 数据块。
   - 它读取块的 CRC 校验和，并更新文件 CRC 校验和。
   - 检查是否使用了已弃用的随机化特性。
   - 读取原始指针 `origPtr`，该指针在逆 BWT 中使用。
   - 解码符号映射表，确定当前块中使用的字节值。
   - 读取 Huffman 树的数量，并解码每个 Huffman 树的码字长度。
   - 解码选择器列表，用于指示每 50 个符号使用哪个 Huffman 树。
   - 使用 Move-To-Front (MTF) 算法解码符号。
   - 使用 Huffman 解码器解码数据，并处理 RUNA 和 RUNB 符号（用于表示重复）。
   - 执行逆 BWT (Inverse Burrows-Wheeler Transform) 来还原原始字节序列。
   - 将解压缩后的数据存储到 `bz2.preRLE` 缓冲区中，并初始化 RLE 解码的状态。

**10. 实现了 `inverseBWT` 函数:**

    - `inverseBWT(tt []uint32, origPtr uint, c []uint) uint32` 函数实现了逆 Burrows-Wheeler 变换，这是 bzip2 解压缩的核心步骤之一。
    - 它接收 `tt` 数组、原始指针 `origPtr` 和累积计数数组 `c` 作为输入。
    - 它根据 BWT 的原理，将 `tt` 数组中的数据还原成原始顺序。
    - 返回第一个字节在 `tt` 数组中的索引。

**11. 实现了 CRC32 校验和计算:**

    - 定义了 CRC32 校验和的查找表 `crctab` 和初始化方法。
    - `updateCRC(val uint32, b []byte) uint32` 函数用于更新 CRC 校验和的值。

**它可以推理出是什么 Go 语言功能的实现：**

这段代码实现了 `io.Reader` 接口，这意味着它可以作为任何接受 `io.Reader` 的 Go 函数的输入。它主要用于处理 bzip2 压缩的数据流，并将其解压缩为原始数据。这属于 **数据流处理** 和 **压缩算法** 的范畴。

**Go 代码举例说明:**

```go
package main

import (
	"compress/bzip2"
	"fmt"
	"io"
	"os"
)

func main() {
	// 假设你有一个名为 "compressed.bz2" 的 bzip2 压缩文件
	compressedFile, err := os.Open("compressed.bz2")
	if err != nil {
		fmt.Println("Error opening compressed file:", err)
		return
	}
	defer compressedFile.Close()

	// 创建 bzip2 解压缩器
	bzip2Reader := bzip2.NewReader(compressedFile)

	// 读取解压缩后的数据
	decompressedData, err := io.ReadAll(bzip2Reader)
	if err != nil {
		fmt.Println("Error decompressing data:", err)
		return
	}

	// 打印解压缩后的数据 (或者进行其他处理)
	fmt.Println(string(decompressedData))
}
```

**假设的输入与输出:**

**输入 (compressed.bz2 内容，假设已使用 bzip2 压缩 "Hello, world!"):**

```
BZh91AY&SY ?g¼è¼$@Ç                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           
```

**输出:**

```
Hello, world!
```

**涉及命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。`compress/bzip2` 包主要提供了解压缩的功能，通常被其他工具或程序使用。例如，在 Linux 或 macOS 系统中，`bunzip2` 命令或 `tar` 命令在处理 `.bz2` 文件时会使用这个包。

如果需要处理命令行参数，通常会在使用 `compress/bzip2` 包的更上层应用中进行。例如，一个自定义的解压缩工具可能会使用 `flag` 包来解析命令行参数，指定输入文件、输出文件等。

**使用者易犯错的点:**

1. **未处理错误:** 使用 `NewReader` 创建解压缩器后，调用 `Read` 方法时务必检查返回的 `error`。如果 bzip2 数据损坏或格式不正确，`Read` 方法会返回 `StructuralError` 或其他 `error`。

   ```go
   n, err := bzip2Reader.Read(buffer)
   if err != nil && err != io.EOF {
       fmt.Println("读取错误:", err) // 应该妥善处理错误
   }
   ```

2. **假设输入是有效的 bzip2 数据:** 直接将任意 `io.Reader` 传递给 `NewReader` 而不进行校验可能导致程序崩溃或panic。应该确保输入流包含有效的 bzip2 格式数据。

3. **忘记关闭文件:** 如果从文件中读取压缩数据，务必使用 `defer file.Close()` 关闭文件，避免资源泄漏。

4. **对大数据文件处理不当:**  一次性将所有解压缩后的数据读取到内存中可能导致内存溢出，特别是对于非常大的 bzip2 文件。应该考虑使用循环读取和处理数据的方式。

5. **误解 `io.ByteReader` 的作用:** 如果传入 `NewReader` 的 `io.Reader` 没有实现 `io.ByteReader`，解压缩器可能会读取更多的数据，这在某些场景下可能会产生意外的影响，例如从网络流中读取数据时。虽然这不算是直接的错误，但理解其行为很重要。

Prompt: 
```
这是路径为go/src/compress/bzip2/bzip2.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bzip2 implements bzip2 decompression.
package bzip2

import "io"

// There's no RFC for bzip2. I used the Wikipedia page for reference and a lot
// of guessing: https://en.wikipedia.org/wiki/Bzip2
// The source code to pyflate was useful for debugging:
// http://www.paul.sladen.org/projects/pyflate

// A StructuralError is returned when the bzip2 data is found to be
// syntactically invalid.
type StructuralError string

func (s StructuralError) Error() string {
	return "bzip2 data invalid: " + string(s)
}

// A reader decompresses bzip2 compressed data.
type reader struct {
	br           bitReader
	fileCRC      uint32
	blockCRC     uint32
	wantBlockCRC uint32
	setupDone    bool // true if we have parsed the bzip2 header.
	eof          bool
	blockSize    int       // blockSize in bytes, i.e. 900 * 1000.
	c            [256]uint // the ``C'' array for the inverse BWT.
	tt           []uint32  // mirrors the ``tt'' array in the bzip2 source and contains the P array in the upper 24 bits.
	tPos         uint32    // Index of the next output byte in tt.

	preRLE      []uint32 // contains the RLE data still to be processed.
	preRLEUsed  int      // number of entries of preRLE used.
	lastByte    int      // the last byte value seen.
	byteRepeats uint     // the number of repeats of lastByte seen.
	repeats     uint     // the number of copies of lastByte to output.
}

// NewReader returns an io.Reader which decompresses bzip2 data from r.
// If r does not also implement [io.ByteReader],
// the decompressor may read more data than necessary from r.
func NewReader(r io.Reader) io.Reader {
	bz2 := new(reader)
	bz2.br = newBitReader(r)
	return bz2
}

const bzip2FileMagic = 0x425a // "BZ"
const bzip2BlockMagic = 0x314159265359
const bzip2FinalMagic = 0x177245385090

// setup parses the bzip2 header.
func (bz2 *reader) setup(needMagic bool) error {
	br := &bz2.br

	if needMagic {
		magic := br.ReadBits(16)
		if magic != bzip2FileMagic {
			return StructuralError("bad magic value")
		}
	}

	t := br.ReadBits(8)
	if t != 'h' {
		return StructuralError("non-Huffman entropy encoding")
	}

	level := br.ReadBits(8)
	if level < '1' || level > '9' {
		return StructuralError("invalid compression level")
	}

	bz2.fileCRC = 0
	bz2.blockSize = 100 * 1000 * (level - '0')
	if bz2.blockSize > len(bz2.tt) {
		bz2.tt = make([]uint32, bz2.blockSize)
	}
	return nil
}

func (bz2 *reader) Read(buf []byte) (n int, err error) {
	if bz2.eof {
		return 0, io.EOF
	}

	if !bz2.setupDone {
		err = bz2.setup(true)
		brErr := bz2.br.Err()
		if brErr != nil {
			err = brErr
		}
		if err != nil {
			return 0, err
		}
		bz2.setupDone = true
	}

	n, err = bz2.read(buf)
	brErr := bz2.br.Err()
	if brErr != nil {
		err = brErr
	}
	return
}

func (bz2 *reader) readFromBlock(buf []byte) int {
	// bzip2 is a block based compressor, except that it has a run-length
	// preprocessing step. The block based nature means that we can
	// preallocate fixed-size buffers and reuse them. However, the RLE
	// preprocessing would require allocating huge buffers to store the
	// maximum expansion. Thus we process blocks all at once, except for
	// the RLE which we decompress as required.
	n := 0
	for (bz2.repeats > 0 || bz2.preRLEUsed < len(bz2.preRLE)) && n < len(buf) {
		// We have RLE data pending.

		// The run-length encoding works like this:
		// Any sequence of four equal bytes is followed by a length
		// byte which contains the number of repeats of that byte to
		// include. (The number of repeats can be zero.) Because we are
		// decompressing on-demand our state is kept in the reader
		// object.

		if bz2.repeats > 0 {
			buf[n] = byte(bz2.lastByte)
			n++
			bz2.repeats--
			if bz2.repeats == 0 {
				bz2.lastByte = -1
			}
			continue
		}

		bz2.tPos = bz2.preRLE[bz2.tPos]
		b := byte(bz2.tPos)
		bz2.tPos >>= 8
		bz2.preRLEUsed++

		if bz2.byteRepeats == 3 {
			bz2.repeats = uint(b)
			bz2.byteRepeats = 0
			continue
		}

		if bz2.lastByte == int(b) {
			bz2.byteRepeats++
		} else {
			bz2.byteRepeats = 0
		}
		bz2.lastByte = int(b)

		buf[n] = b
		n++
	}

	return n
}

func (bz2 *reader) read(buf []byte) (int, error) {
	for {
		n := bz2.readFromBlock(buf)
		if n > 0 || len(buf) == 0 {
			bz2.blockCRC = updateCRC(bz2.blockCRC, buf[:n])
			return n, nil
		}

		// End of block. Check CRC.
		if bz2.blockCRC != bz2.wantBlockCRC {
			bz2.br.err = StructuralError("block checksum mismatch")
			return 0, bz2.br.err
		}

		// Find next block.
		br := &bz2.br
		switch br.ReadBits64(48) {
		default:
			return 0, StructuralError("bad magic value found")

		case bzip2BlockMagic:
			// Start of block.
			err := bz2.readBlock()
			if err != nil {
				return 0, err
			}

		case bzip2FinalMagic:
			// Check end-of-file CRC.
			wantFileCRC := uint32(br.ReadBits64(32))
			if br.err != nil {
				return 0, br.err
			}
			if bz2.fileCRC != wantFileCRC {
				br.err = StructuralError("file checksum mismatch")
				return 0, br.err
			}

			// Skip ahead to byte boundary.
			// Is there a file concatenated to this one?
			// It would start with BZ.
			if br.bits%8 != 0 {
				br.ReadBits(br.bits % 8)
			}
			b, err := br.r.ReadByte()
			if err == io.EOF {
				br.err = io.EOF
				bz2.eof = true
				return 0, io.EOF
			}
			if err != nil {
				br.err = err
				return 0, err
			}
			z, err := br.r.ReadByte()
			if err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				br.err = err
				return 0, err
			}
			if b != 'B' || z != 'Z' {
				return 0, StructuralError("bad magic value in continuation file")
			}
			if err := bz2.setup(false); err != nil {
				return 0, err
			}
		}
	}
}

// readBlock reads a bzip2 block. The magic number should already have been consumed.
func (bz2 *reader) readBlock() (err error) {
	br := &bz2.br
	bz2.wantBlockCRC = uint32(br.ReadBits64(32)) // skip checksum. TODO: check it if we can figure out what it is.
	bz2.blockCRC = 0
	bz2.fileCRC = (bz2.fileCRC<<1 | bz2.fileCRC>>31) ^ bz2.wantBlockCRC
	randomized := br.ReadBits(1)
	if randomized != 0 {
		return StructuralError("deprecated randomized files")
	}
	origPtr := uint(br.ReadBits(24))

	// If not every byte value is used in the block (i.e., it's text) then
	// the symbol set is reduced. The symbols used are stored as a
	// two-level, 16x16 bitmap.
	symbolRangeUsedBitmap := br.ReadBits(16)
	symbolPresent := make([]bool, 256)
	numSymbols := 0
	for symRange := uint(0); symRange < 16; symRange++ {
		if symbolRangeUsedBitmap&(1<<(15-symRange)) != 0 {
			bits := br.ReadBits(16)
			for symbol := uint(0); symbol < 16; symbol++ {
				if bits&(1<<(15-symbol)) != 0 {
					symbolPresent[16*symRange+symbol] = true
					numSymbols++
				}
			}
		}
	}

	if numSymbols == 0 {
		// There must be an EOF symbol.
		return StructuralError("no symbols in input")
	}

	// A block uses between two and six different Huffman trees.
	numHuffmanTrees := br.ReadBits(3)
	if numHuffmanTrees < 2 || numHuffmanTrees > 6 {
		return StructuralError("invalid number of Huffman trees")
	}

	// The Huffman tree can switch every 50 symbols so there's a list of
	// tree indexes telling us which tree to use for each 50 symbol block.
	numSelectors := br.ReadBits(15)
	treeIndexes := make([]uint8, numSelectors)

	// The tree indexes are move-to-front transformed and stored as unary
	// numbers.
	mtfTreeDecoder := newMTFDecoderWithRange(numHuffmanTrees)
	for i := range treeIndexes {
		c := 0
		for {
			inc := br.ReadBits(1)
			if inc == 0 {
				break
			}
			c++
		}
		if c >= numHuffmanTrees {
			return StructuralError("tree index too large")
		}
		treeIndexes[i] = mtfTreeDecoder.Decode(c)
	}

	// The list of symbols for the move-to-front transform is taken from
	// the previously decoded symbol bitmap.
	symbols := make([]byte, numSymbols)
	nextSymbol := 0
	for i := 0; i < 256; i++ {
		if symbolPresent[i] {
			symbols[nextSymbol] = byte(i)
			nextSymbol++
		}
	}
	mtf := newMTFDecoder(symbols)

	numSymbols += 2 // to account for RUNA and RUNB symbols
	huffmanTrees := make([]huffmanTree, numHuffmanTrees)

	// Now we decode the arrays of code-lengths for each tree.
	lengths := make([]uint8, numSymbols)
	for i := range huffmanTrees {
		// The code lengths are delta encoded from a 5-bit base value.
		length := br.ReadBits(5)
		for j := range lengths {
			for {
				if length < 1 || length > 20 {
					return StructuralError("Huffman length out of range")
				}
				if !br.ReadBit() {
					break
				}
				if br.ReadBit() {
					length--
				} else {
					length++
				}
			}
			lengths[j] = uint8(length)
		}
		huffmanTrees[i], err = newHuffmanTree(lengths)
		if err != nil {
			return err
		}
	}

	selectorIndex := 1 // the next tree index to use
	if len(treeIndexes) == 0 {
		return StructuralError("no tree selectors given")
	}
	if int(treeIndexes[0]) >= len(huffmanTrees) {
		return StructuralError("tree selector out of range")
	}
	currentHuffmanTree := huffmanTrees[treeIndexes[0]]
	bufIndex := 0 // indexes bz2.buf, the output buffer.
	// The output of the move-to-front transform is run-length encoded and
	// we merge the decoding into the Huffman parsing loop. These two
	// variables accumulate the repeat count. See the Wikipedia page for
	// details.
	repeat := 0
	repeatPower := 0

	// The `C' array (used by the inverse BWT) needs to be zero initialized.
	clear(bz2.c[:])

	decoded := 0 // counts the number of symbols decoded by the current tree.
	for {
		if decoded == 50 {
			if selectorIndex >= numSelectors {
				return StructuralError("insufficient selector indices for number of symbols")
			}
			if int(treeIndexes[selectorIndex]) >= len(huffmanTrees) {
				return StructuralError("tree selector out of range")
			}
			currentHuffmanTree = huffmanTrees[treeIndexes[selectorIndex]]
			selectorIndex++
			decoded = 0
		}

		v := currentHuffmanTree.Decode(br)
		decoded++

		if v < 2 {
			// This is either the RUNA or RUNB symbol.
			if repeat == 0 {
				repeatPower = 1
			}
			repeat += repeatPower << v
			repeatPower <<= 1

			// This limit of 2 million comes from the bzip2 source
			// code. It prevents repeat from overflowing.
			if repeat > 2*1024*1024 {
				return StructuralError("repeat count too large")
			}
			continue
		}

		if repeat > 0 {
			// We have decoded a complete run-length so we need to
			// replicate the last output symbol.
			if repeat > bz2.blockSize-bufIndex {
				return StructuralError("repeats past end of block")
			}
			for i := 0; i < repeat; i++ {
				b := mtf.First()
				bz2.tt[bufIndex] = uint32(b)
				bz2.c[b]++
				bufIndex++
			}
			repeat = 0
		}

		if int(v) == numSymbols-1 {
			// This is the EOF symbol. Because it's always at the
			// end of the move-to-front list, and never gets moved
			// to the front, it has this unique value.
			break
		}

		// Since two metasymbols (RUNA and RUNB) have values 0 and 1,
		// one would expect |v-2| to be passed to the MTF decoder.
		// However, the front of the MTF list is never referenced as 0,
		// it's always referenced with a run-length of 1. Thus 0
		// doesn't need to be encoded and we have |v-1| in the next
		// line.
		b := mtf.Decode(int(v - 1))
		if bufIndex >= bz2.blockSize {
			return StructuralError("data exceeds block size")
		}
		bz2.tt[bufIndex] = uint32(b)
		bz2.c[b]++
		bufIndex++
	}

	if origPtr >= uint(bufIndex) {
		return StructuralError("origPtr out of bounds")
	}

	// We have completed the entropy decoding. Now we can perform the
	// inverse BWT and setup the RLE buffer.
	bz2.preRLE = bz2.tt[:bufIndex]
	bz2.preRLEUsed = 0
	bz2.tPos = inverseBWT(bz2.preRLE, origPtr, bz2.c[:])
	bz2.lastByte = -1
	bz2.byteRepeats = 0
	bz2.repeats = 0

	return nil
}

// inverseBWT implements the inverse Burrows-Wheeler transform as described in
// http://www.hpl.hp.com/techreports/Compaq-DEC/SRC-RR-124.pdf, section 4.2.
// In that document, origPtr is called “I” and c is the “C” array after the
// first pass over the data. It's an argument here because we merge the first
// pass with the Huffman decoding.
//
// This also implements the “single array” method from the bzip2 source code
// which leaves the output, still shuffled, in the bottom 8 bits of tt with the
// index of the next byte in the top 24-bits. The index of the first byte is
// returned.
func inverseBWT(tt []uint32, origPtr uint, c []uint) uint32 {
	sum := uint(0)
	for i := 0; i < 256; i++ {
		sum += c[i]
		c[i] = sum - c[i]
	}

	for i := range tt {
		b := tt[i] & 0xff
		tt[c[b]] |= uint32(i) << 8
		c[b]++
	}

	return tt[origPtr] >> 8
}

// This is a standard CRC32 like in hash/crc32 except that all the shifts are reversed,
// causing the bits in the input to be processed in the reverse of the usual order.

var crctab [256]uint32

func init() {
	const poly = 0x04C11DB7
	for i := range crctab {
		crc := uint32(i) << 24
		for j := 0; j < 8; j++ {
			if crc&0x80000000 != 0 {
				crc = (crc << 1) ^ poly
			} else {
				crc <<= 1
			}
		}
		crctab[i] = crc
	}
}

// updateCRC updates the crc value to incorporate the data in b.
// The initial value is 0.
func updateCRC(val uint32, b []byte) uint32 {
	crc := ^val
	for _, v := range b {
		crc = crctab[byte(crc>>24)^v] ^ (crc << 8)
	}
	return ^crc
}

"""



```