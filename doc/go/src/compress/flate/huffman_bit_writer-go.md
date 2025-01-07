Response:
Let's break down the thought process for answering this request.

1. **Understand the Goal:** The core request is to analyze a Go source code snippet related to Huffman coding and explain its functionalities, provide usage examples, and highlight potential pitfalls.

2. **Initial Scan for Keywords:** Quickly scan the code for key terms like "huffman," "bit," "writer," "flush," "encode," "decode," "compress," "offset," "literal," "dynamic," "fixed," "stored," "header," "bits," "bytes," and constants like `endBlockMarker`. These immediately hint at the module's purpose.

3. **Identify the Main Type:** The `huffmanBitWriter` struct is clearly the central component. Its fields and methods will define its behavior. Pay close attention to its members like `writer`, `bits`, `nbits`, `bytes`, `literalFreq`, `offsetFreq`, `literalEncoding`, and `offsetEncoding`. These strongly suggest the class is designed to write Huffman-encoded data to an underlying `io.Writer`.

4. **Analyze Key Methods:**  Focus on the public methods of `huffmanBitWriter`. What do they do?
    * `newHuffmanBitWriter`:  Constructor, initializes the writer and frequency tables.
    * `reset`: Resets the writer for reuse.
    * `flush`: Writes any buffered data and bits to the underlying writer.
    * `write`:  A low-level write to the underlying writer (important: the comment warns against direct use).
    * `writeBits`: Writes a specified number of bits. The buffering mechanism here is crucial.
    * `writeBytes`: Writes a byte slice, ensuring bit alignment.
    * `generateCodegen`:  A more complex method likely related to generating code for the Huffman trees themselves.
    * `dynamicSize`, `fixedSize`, `storedSize`: These methods calculate the size of different encoding methods. This strongly implies the code supports different compression strategies.
    * `writeCode`: Writes a Huffman code.
    * `writeDynamicHeader`, `writeStoredHeader`, `writeFixedHeader`:  Methods for writing the headers associated with different compression types.
    * `writeBlock`, `writeBlockDynamic`, `writeBlockHuff`: High-level methods for writing compressed blocks using different strategies.
    * `indexTokens`:  Analyzes tokens to build frequency tables for Huffman encoding.
    * `writeTokens`: Writes tokens using pre-calculated Huffman codes.

5. **Infer Functionality:** Based on the identified types and methods, infer the overall functionality: This code implements a writer that can output data compressed using the DEFLATE algorithm's Huffman coding scheme. It supports different block types (dynamic Huffman, fixed Huffman, and stored). It manages bit-level writing and buffering for efficiency.

6. **Connect to Go Concepts:** Recognize the use of `io.Writer` interface, which is a standard Go way to handle output. The buffering mechanism using a byte array and bit manipulation is a common low-level technique.

7. **Illustrate with Examples:**  Think about how you would *use* this code. Since it's a *writer*, you'd need something to provide the data to compress. The `flate` package is used for DEFLATE, so an example involving `flate.NewWriter` and writing data makes sense. Demonstrate the different block writing methods (`writeBlock`, `writeBlockDynamic`, `writeBlockHuff`). Since the code deals with internal bit manipulation and Huffman coding details, a direct "encoding" example within *this specific code* is difficult to show without more context about how the tokens are generated. Focus on how this writer *consumes* the results of that process.

8. **Address Potential Pitfalls:** Look for areas where a user might make mistakes. The comment about not using the underlying `writer` directly is a key point. The buffering behavior and the need to `flush` are also important. The different block types and when to use them could be confusing. The lack of explicit error handling in the provided snippet (besides the sticky `w.err`) could be mentioned.

9. **Structure the Answer:** Organize the information logically. Start with a summary of the functionality. Then, provide details about each aspect, like the Go feature implementation, code examples, and potential errors. Use clear headings and formatting.

10. **Refine and Review:** Reread the answer to ensure clarity, accuracy, and completeness. Check if all parts of the original request have been addressed. Are the examples clear and easy to understand? Is the explanation of potential errors helpful?

**Self-Correction/Refinement during the process:**

* **Initial thought:**  This is just a bit writer.
* **Correction:**  It's a *Huffman* bit writer specifically for the `flate` package, which implies DEFLATE compression.
* **Initial thought:**  Show a simple example of writing bits.
* **Correction:**  The user needs to understand the higher-level purpose. Show examples of writing blocks using the different methods, even if the token generation is assumed.
* **Initial thought:** Focus on the technical details of bit manipulation.
* **Correction:**  Balance technical details with the broader context of compression and the different encoding strategies (fixed, dynamic, stored).
* **Initial thought:**  Just list the methods.
* **Correction:** Explain the *purpose* of each key method and how they contribute to the overall functionality.

By following this structured approach, combining code analysis with domain knowledge (compression, DEFLATE), and focusing on the user's perspective, a comprehensive and helpful answer can be generated.
这段代码是 Go 语言 `compress/flate` 包中用于实现 **DEFLATE 压缩算法** 的一部分，具体来说，它实现了 **将数据按照 Huffman 编码的方式写入比特流** 的功能。

以下是它的主要功能：

1. **比特流写入和缓冲:**
   - 它维护一个内部缓冲区 (`bytes`) 和一个比特缓冲区 (`bits`, `nbits`)，用于高效地将比特写入底层的 `io.Writer`。
   - 它会先将比特数据累积到比特缓冲区，当比特数足够时，将其转换为字节并写入字节缓冲区。
   - 当字节缓冲区满或需要刷新时，它会将缓冲区中的内容写入到 `io.Writer`。

2. **支持不同的 Huffman 编码方式:**
   - **固定 Huffman 编码:** 代码中提到了 `fixedLiteralEncoding` 和 `fixedOffsetEncoding`，暗示了对固定 Huffman 编码的支持（尽管这段代码本身没有直接实现固定 Huffman 编码表，但它可以利用这些预定义的编码）。
   - **动态 Huffman 编码:**  代码的核心功能是支持动态 Huffman 编码。它能够：
     - 统计输入数据的频率 (`literalFreq`, `offsetFreq`)。
     - 根据频率生成 Huffman 编码表 (`literalEncoding`, `offsetEncoding`)。
     - 生成用于表示 Huffman 编码表的编码 (`codegen`, `codegenFreq`, `codegenEncoding`)。
     - 将编码后的数据写入比特流。

3. **支持不同的压缩块类型:**
   - **动态 Huffman 块:** 使用动态生成的 Huffman 编码表压缩数据。
   - **固定 Huffman 块:** 使用预定义的固定 Huffman 编码表压缩数据。
   - **存储块 (Stored Block):**  不进行压缩，直接存储原始数据。代码中会根据压缩效率决定是否使用存储块。

4. **处理长度和距离编码:**
   - DEFLATE 算法使用长度-距离对来表示重复的数据。这段代码处理了将长度和距离转换为相应的 Huffman 编码。
   - `lengthExtraBits` 和 `lengthBase` 数组用于处理长度编码的额外比特。
   - `offsetExtraBits` 和 `offsetBase` 数组用于处理距离编码的额外比特。

5. **生成 Code-Length 编码:**
   - `generateCodegen` 函数实现了 RFC 1951 中描述的特殊游程编码，用于表示字面量/长度和距离的 Huffman 编码长度。

6. **计算不同编码方式的大小:**
   - `dynamicSize`, `fixedSize`, `storedSize` 函数用于估算不同编码方式所需的比特数，以便选择最优的压缩方式。

**它是什么 Go 语言功能的实现？**

这段代码是 `compress/flate` 包中实现 **DEFLATE 压缩算法的 Huffman 编码部分** 的核心组件。DEFLATE 算法被广泛应用于 `gzip`、`zip` 等压缩格式中。

**Go 代码举例说明:**

假设我们已经有一些需要压缩的数据，并且将数据分为了字面量和匹配（长度-距离对）的 tokens。以下代码展示了如何使用 `huffmanBitWriter` 将这些 tokens 编码并写入一个 `io.Writer`：

```go
package main

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
)

// 假设的 token 类型
type token int

const (
	literalType token = iota
	matchType
)

type hcode struct {
	code uint32
	len  uint8
}

// 假设的 token 生成函数 (实际实现会更复杂)
func generateTokens(data []byte) []token {
	// 这里只是一个简化示例，实际的 token 生成会涉及到查找重复子串等操作
	tokens := make([]token, len(data))
	for i := range data {
		tokens[i] = token(data[i]) // 将每个字节视为一个字面量 token
	}
	return tokens
}

func main() {
	var buf bytes.Buffer
	writer := flate.NewWriter(&buf, flate.DefaultCompression) // 使用 flate 包的 Writer

	// 获取 huffmanBitWriter (这是一个内部类型，通常不直接访问)
	// 这里为了演示，假设我们可以通过某种方式获取到它，
	// 实际使用中，flate.Writer 会管理 huffmanBitWriter
	hbw := getHuffmanBitWriter(writer) // 假设有这么一个函数可以获取

	data := []byte("hello world hello")
	tokens := generateTokens(data)

	// 手动调用 writeBlockDynamic 进行动态 Huffman 编码
	// 注意：实际使用 flate.Writer 会自动处理这些
	hbw.writeBlockDynamic(tokens, true, data)

	err := writer.Close()
	if err != nil {
		fmt.Println("Error closing writer:", err)
		return
	}

	fmt.Printf("Compressed data: %x\n", buf.Bytes())
}

// 这是一个占位函数，用于演示目的，实际中你需要从 flate.Writer 中获取 huffmanBitWriter
func getHuffmanBitWriter(w io.WriteCloser) *flate.huffmanBitWriter {
	// 实际的获取方式会更复杂，涉及到反射或者访问内部结构
	// 这里为了演示概念，假设存在这个函数
	fw, ok := w.(*flate.Writer)
	if !ok {
		return nil
	}
	return fw.Hbw // 假设 flate.Writer 暴露了 hbw 字段
}
```

**假设的输入与输出:**

假设输入数据是 `[]byte("aaabbc")`。

1. **Tokenization (假设):**  `generateTokens` 函数可能会生成如下的字面量 token 序列： `[97, 97, 97, 98, 98, 99]` (假设 ASCII 码 a=97, b=98, c=99)。

2. **频率统计:** `indexTokens` 函数会统计字面量的频率：`literalFreq[97] = 3`, `literalFreq[98] = 2`, `literalFreq[99] = 1`。

3. **Huffman 编码生成:** `literalEncoding.generate` 会根据频率生成 Huffman 编码，例如：
   - 'a' (97):  `0`
   - 'b' (98):  `10`
   - 'c' (99):  `11`

4. **动态 Huffman 头部写入:** `writeDynamicHeader` 会写入必要的头部信息，包括指示这是动态 Huffman 块，以及字面量/长度和距离编码表的描述信息。

5. **数据编码:** `writeTokens` 会将 token 序列按照生成的 Huffman 编码写入比特流：
   - `a`: `0`
   - `a`: `0`
   - `a`: `0`
   - `b`: `10`
   - `b`: `10`
   - `c`: `11`
   - 结束符 (endBlockMarker): 假设其编码为 `1` (实际编码会根据频率动态生成)

6. **输出 (比特流):**  `0001010111` (这只是一个简化的例子，实际的比特流会更复杂，包含头部信息和可能的填充比特)。

**注意:**  直接使用 `huffmanBitWriter` 通常不是用户需要做的，`compress/flate.Writer` 会在内部管理 `huffmanBitWriter` 的使用。这个例子只是为了说明其内部的工作原理。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `compress/flate` 包的更上层，例如在 `gzip` 或 `zip` 等使用 `flate` 包的工具中。这些工具会解析命令行参数来确定压缩级别等设置，然后传递给 `flate.NewWriter` 函数。

例如，在使用 `gzip` 命令时：

```bash
gzip -1 input.txt  # 使用最快的压缩级别 (对应 flate.BestSpeed)
gzip -9 input.txt  # 使用最好的压缩级别 (对应 flate.BestCompression)
```

`gzip` 工具会解析 `-1` 或 `-9` 这些参数，并将相应的压缩级别传递给 `flate` 包，`flate` 包内部会根据压缩级别选择合适的策略（例如，是否更倾向于使用动态 Huffman 编码，或者更积极地查找重复子串）。

**使用者易犯错的点:**

虽然使用者通常不会直接操作 `huffmanBitWriter`，但理解其背后的原理有助于理解 `compress/flate` 包的使用。

一个潜在的易错点是 **不理解缓冲和刷新的概念**。如果直接使用底层的 `io.Writer` 而不调用 `flush`，可能会导致部分数据没有被写入。  在 `flate.Writer` 中，`Close()` 方法会确保所有缓冲的数据都被刷新。

另一个概念上的误解可能是 **认为 Huffman 编码总是能带来显著的压缩效果**。实际上，对于熵值很高的随机数据，Huffman 编码可能无法实现有效的压缩，甚至可能导致数据膨胀。`huffmanBitWriter` 的设计中也考虑了存储块，以便在压缩效果不佳时选择不压缩。

总而言之，`huffmanBitWriter` 是 `compress/flate` 包中实现 DEFLATE 压缩算法的关键部分，负责将数据高效地编码成 Huffman 比特流，并支持动态和固定 Huffman 编码以及不同的压缩块类型。理解其功能有助于更深入地理解 DEFLATE 压缩算法和 Go 语言的压缩库。

Prompt: 
```
这是路径为go/src/compress/flate/huffman_bit_writer.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package flate

import (
	"io"
)

const (
	// The largest offset code.
	offsetCodeCount = 30

	// The special code used to mark the end of a block.
	endBlockMarker = 256

	// The first length code.
	lengthCodesStart = 257

	// The number of codegen codes.
	codegenCodeCount = 19
	badCode          = 255

	// bufferFlushSize indicates the buffer size
	// after which bytes are flushed to the writer.
	// Should preferably be a multiple of 6, since
	// we accumulate 6 bytes between writes to the buffer.
	bufferFlushSize = 240

	// bufferSize is the actual output byte buffer size.
	// It must have additional headroom for a flush
	// which can contain up to 8 bytes.
	bufferSize = bufferFlushSize + 8
)

// The number of extra bits needed by length code X - LENGTH_CODES_START.
var lengthExtraBits = []int8{
	/* 257 */ 0, 0, 0,
	/* 260 */ 0, 0, 0, 0, 0, 1, 1, 1, 1, 2,
	/* 270 */ 2, 2, 2, 3, 3, 3, 3, 4, 4, 4,
	/* 280 */ 4, 5, 5, 5, 5, 0,
}

// The length indicated by length code X - LENGTH_CODES_START.
var lengthBase = []uint32{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 10,
	12, 14, 16, 20, 24, 28, 32, 40, 48, 56,
	64, 80, 96, 112, 128, 160, 192, 224, 255,
}

// offset code word extra bits.
var offsetExtraBits = []int8{
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3,
	4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
	9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
}

var offsetBase = []uint32{
	0x000000, 0x000001, 0x000002, 0x000003, 0x000004,
	0x000006, 0x000008, 0x00000c, 0x000010, 0x000018,
	0x000020, 0x000030, 0x000040, 0x000060, 0x000080,
	0x0000c0, 0x000100, 0x000180, 0x000200, 0x000300,
	0x000400, 0x000600, 0x000800, 0x000c00, 0x001000,
	0x001800, 0x002000, 0x003000, 0x004000, 0x006000,
}

// The odd order in which the codegen code sizes are written.
var codegenOrder = []uint32{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

type huffmanBitWriter struct {
	// writer is the underlying writer.
	// Do not use it directly; use the write method, which ensures
	// that Write errors are sticky.
	writer io.Writer

	// Data waiting to be written is bytes[0:nbytes]
	// and then the low nbits of bits.  Data is always written
	// sequentially into the bytes array.
	bits            uint64
	nbits           uint
	bytes           [bufferSize]byte
	codegenFreq     [codegenCodeCount]int32
	nbytes          int
	literalFreq     []int32
	offsetFreq      []int32
	codegen         []uint8
	literalEncoding *huffmanEncoder
	offsetEncoding  *huffmanEncoder
	codegenEncoding *huffmanEncoder
	err             error
}

func newHuffmanBitWriter(w io.Writer) *huffmanBitWriter {
	return &huffmanBitWriter{
		writer:          w,
		literalFreq:     make([]int32, maxNumLit),
		offsetFreq:      make([]int32, offsetCodeCount),
		codegen:         make([]uint8, maxNumLit+offsetCodeCount+1),
		literalEncoding: newHuffmanEncoder(maxNumLit),
		codegenEncoding: newHuffmanEncoder(codegenCodeCount),
		offsetEncoding:  newHuffmanEncoder(offsetCodeCount),
	}
}

func (w *huffmanBitWriter) reset(writer io.Writer) {
	w.writer = writer
	w.bits, w.nbits, w.nbytes, w.err = 0, 0, 0, nil
}

func (w *huffmanBitWriter) flush() {
	if w.err != nil {
		w.nbits = 0
		return
	}
	n := w.nbytes
	for w.nbits != 0 {
		w.bytes[n] = byte(w.bits)
		w.bits >>= 8
		if w.nbits > 8 { // Avoid underflow
			w.nbits -= 8
		} else {
			w.nbits = 0
		}
		n++
	}
	w.bits = 0
	w.write(w.bytes[:n])
	w.nbytes = 0
}

func (w *huffmanBitWriter) write(b []byte) {
	if w.err != nil {
		return
	}
	_, w.err = w.writer.Write(b)
}

func (w *huffmanBitWriter) writeBits(b int32, nb uint) {
	if w.err != nil {
		return
	}
	w.bits |= uint64(b) << w.nbits
	w.nbits += nb
	if w.nbits >= 48 {
		bits := w.bits
		w.bits >>= 48
		w.nbits -= 48
		n := w.nbytes
		bytes := w.bytes[n : n+6]
		bytes[0] = byte(bits)
		bytes[1] = byte(bits >> 8)
		bytes[2] = byte(bits >> 16)
		bytes[3] = byte(bits >> 24)
		bytes[4] = byte(bits >> 32)
		bytes[5] = byte(bits >> 40)
		n += 6
		if n >= bufferFlushSize {
			w.write(w.bytes[:n])
			n = 0
		}
		w.nbytes = n
	}
}

func (w *huffmanBitWriter) writeBytes(bytes []byte) {
	if w.err != nil {
		return
	}
	n := w.nbytes
	if w.nbits&7 != 0 {
		w.err = InternalError("writeBytes with unfinished bits")
		return
	}
	for w.nbits != 0 {
		w.bytes[n] = byte(w.bits)
		w.bits >>= 8
		w.nbits -= 8
		n++
	}
	if n != 0 {
		w.write(w.bytes[:n])
	}
	w.nbytes = 0
	w.write(bytes)
}

// RFC 1951 3.2.7 specifies a special run-length encoding for specifying
// the literal and offset lengths arrays (which are concatenated into a single
// array).  This method generates that run-length encoding.
//
// The result is written into the codegen array, and the frequencies
// of each code is written into the codegenFreq array.
// Codes 0-15 are single byte codes. Codes 16-18 are followed by additional
// information. Code badCode is an end marker
//
//	numLiterals      The number of literals in literalEncoding
//	numOffsets       The number of offsets in offsetEncoding
//	litenc, offenc   The literal and offset encoder to use
func (w *huffmanBitWriter) generateCodegen(numLiterals int, numOffsets int, litEnc, offEnc *huffmanEncoder) {
	clear(w.codegenFreq[:])
	// Note that we are using codegen both as a temporary variable for holding
	// a copy of the frequencies, and as the place where we put the result.
	// This is fine because the output is always shorter than the input used
	// so far.
	codegen := w.codegen // cache
	// Copy the concatenated code sizes to codegen. Put a marker at the end.
	cgnl := codegen[:numLiterals]
	for i := range cgnl {
		cgnl[i] = uint8(litEnc.codes[i].len)
	}

	cgnl = codegen[numLiterals : numLiterals+numOffsets]
	for i := range cgnl {
		cgnl[i] = uint8(offEnc.codes[i].len)
	}
	codegen[numLiterals+numOffsets] = badCode

	size := codegen[0]
	count := 1
	outIndex := 0
	for inIndex := 1; size != badCode; inIndex++ {
		// INVARIANT: We have seen "count" copies of size that have not yet
		// had output generated for them.
		nextSize := codegen[inIndex]
		if nextSize == size {
			count++
			continue
		}
		// We need to generate codegen indicating "count" of size.
		if size != 0 {
			codegen[outIndex] = size
			outIndex++
			w.codegenFreq[size]++
			count--
			for count >= 3 {
				n := 6
				if n > count {
					n = count
				}
				codegen[outIndex] = 16
				outIndex++
				codegen[outIndex] = uint8(n - 3)
				outIndex++
				w.codegenFreq[16]++
				count -= n
			}
		} else {
			for count >= 11 {
				n := 138
				if n > count {
					n = count
				}
				codegen[outIndex] = 18
				outIndex++
				codegen[outIndex] = uint8(n - 11)
				outIndex++
				w.codegenFreq[18]++
				count -= n
			}
			if count >= 3 {
				// count >= 3 && count <= 10
				codegen[outIndex] = 17
				outIndex++
				codegen[outIndex] = uint8(count - 3)
				outIndex++
				w.codegenFreq[17]++
				count = 0
			}
		}
		count--
		for ; count >= 0; count-- {
			codegen[outIndex] = size
			outIndex++
			w.codegenFreq[size]++
		}
		// Set up invariant for next time through the loop.
		size = nextSize
		count = 1
	}
	// Marker indicating the end of the codegen.
	codegen[outIndex] = badCode
}

// dynamicSize returns the size of dynamically encoded data in bits.
func (w *huffmanBitWriter) dynamicSize(litEnc, offEnc *huffmanEncoder, extraBits int) (size, numCodegens int) {
	numCodegens = len(w.codegenFreq)
	for numCodegens > 4 && w.codegenFreq[codegenOrder[numCodegens-1]] == 0 {
		numCodegens--
	}
	header := 3 + 5 + 5 + 4 + (3 * numCodegens) +
		w.codegenEncoding.bitLength(w.codegenFreq[:]) +
		int(w.codegenFreq[16])*2 +
		int(w.codegenFreq[17])*3 +
		int(w.codegenFreq[18])*7
	size = header +
		litEnc.bitLength(w.literalFreq) +
		offEnc.bitLength(w.offsetFreq) +
		extraBits

	return size, numCodegens
}

// fixedSize returns the size of dynamically encoded data in bits.
func (w *huffmanBitWriter) fixedSize(extraBits int) int {
	return 3 +
		fixedLiteralEncoding.bitLength(w.literalFreq) +
		fixedOffsetEncoding.bitLength(w.offsetFreq) +
		extraBits
}

// storedSize calculates the stored size, including header.
// The function returns the size in bits and whether the block
// fits inside a single block.
func (w *huffmanBitWriter) storedSize(in []byte) (int, bool) {
	if in == nil {
		return 0, false
	}
	if len(in) <= maxStoreBlockSize {
		return (len(in) + 5) * 8, true
	}
	return 0, false
}

func (w *huffmanBitWriter) writeCode(c hcode) {
	if w.err != nil {
		return
	}
	w.bits |= uint64(c.code) << w.nbits
	w.nbits += uint(c.len)
	if w.nbits >= 48 {
		bits := w.bits
		w.bits >>= 48
		w.nbits -= 48
		n := w.nbytes
		bytes := w.bytes[n : n+6]
		bytes[0] = byte(bits)
		bytes[1] = byte(bits >> 8)
		bytes[2] = byte(bits >> 16)
		bytes[3] = byte(bits >> 24)
		bytes[4] = byte(bits >> 32)
		bytes[5] = byte(bits >> 40)
		n += 6
		if n >= bufferFlushSize {
			w.write(w.bytes[:n])
			n = 0
		}
		w.nbytes = n
	}
}

// Write the header of a dynamic Huffman block to the output stream.
//
//	numLiterals  The number of literals specified in codegen
//	numOffsets   The number of offsets specified in codegen
//	numCodegens  The number of codegens used in codegen
func (w *huffmanBitWriter) writeDynamicHeader(numLiterals int, numOffsets int, numCodegens int, isEof bool) {
	if w.err != nil {
		return
	}
	var firstBits int32 = 4
	if isEof {
		firstBits = 5
	}
	w.writeBits(firstBits, 3)
	w.writeBits(int32(numLiterals-257), 5)
	w.writeBits(int32(numOffsets-1), 5)
	w.writeBits(int32(numCodegens-4), 4)

	for i := 0; i < numCodegens; i++ {
		value := uint(w.codegenEncoding.codes[codegenOrder[i]].len)
		w.writeBits(int32(value), 3)
	}

	i := 0
	for {
		var codeWord int = int(w.codegen[i])
		i++
		if codeWord == badCode {
			break
		}
		w.writeCode(w.codegenEncoding.codes[uint32(codeWord)])

		switch codeWord {
		case 16:
			w.writeBits(int32(w.codegen[i]), 2)
			i++
		case 17:
			w.writeBits(int32(w.codegen[i]), 3)
			i++
		case 18:
			w.writeBits(int32(w.codegen[i]), 7)
			i++
		}
	}
}

func (w *huffmanBitWriter) writeStoredHeader(length int, isEof bool) {
	if w.err != nil {
		return
	}
	var flag int32
	if isEof {
		flag = 1
	}
	w.writeBits(flag, 3)
	w.flush()
	w.writeBits(int32(length), 16)
	w.writeBits(int32(^uint16(length)), 16)
}

func (w *huffmanBitWriter) writeFixedHeader(isEof bool) {
	if w.err != nil {
		return
	}
	// Indicate that we are a fixed Huffman block
	var value int32 = 2
	if isEof {
		value = 3
	}
	w.writeBits(value, 3)
}

// writeBlock will write a block of tokens with the smallest encoding.
// The original input can be supplied, and if the huffman encoded data
// is larger than the original bytes, the data will be written as a
// stored block.
// If the input is nil, the tokens will always be Huffman encoded.
func (w *huffmanBitWriter) writeBlock(tokens []token, eof bool, input []byte) {
	if w.err != nil {
		return
	}

	tokens = append(tokens, endBlockMarker)
	numLiterals, numOffsets := w.indexTokens(tokens)

	var extraBits int
	storedSize, storable := w.storedSize(input)
	if storable {
		// We only bother calculating the costs of the extra bits required by
		// the length of offset fields (which will be the same for both fixed
		// and dynamic encoding), if we need to compare those two encodings
		// against stored encoding.
		for lengthCode := lengthCodesStart + 8; lengthCode < numLiterals; lengthCode++ {
			// First eight length codes have extra size = 0.
			extraBits += int(w.literalFreq[lengthCode]) * int(lengthExtraBits[lengthCode-lengthCodesStart])
		}
		for offsetCode := 4; offsetCode < numOffsets; offsetCode++ {
			// First four offset codes have extra size = 0.
			extraBits += int(w.offsetFreq[offsetCode]) * int(offsetExtraBits[offsetCode])
		}
	}

	// Figure out smallest code.
	// Fixed Huffman baseline.
	var literalEncoding = fixedLiteralEncoding
	var offsetEncoding = fixedOffsetEncoding
	var size = w.fixedSize(extraBits)

	// Dynamic Huffman?
	var numCodegens int

	// Generate codegen and codegenFrequencies, which indicates how to encode
	// the literalEncoding and the offsetEncoding.
	w.generateCodegen(numLiterals, numOffsets, w.literalEncoding, w.offsetEncoding)
	w.codegenEncoding.generate(w.codegenFreq[:], 7)
	dynamicSize, numCodegens := w.dynamicSize(w.literalEncoding, w.offsetEncoding, extraBits)

	if dynamicSize < size {
		size = dynamicSize
		literalEncoding = w.literalEncoding
		offsetEncoding = w.offsetEncoding
	}

	// Stored bytes?
	if storable && storedSize < size {
		w.writeStoredHeader(len(input), eof)
		w.writeBytes(input)
		return
	}

	// Huffman.
	if literalEncoding == fixedLiteralEncoding {
		w.writeFixedHeader(eof)
	} else {
		w.writeDynamicHeader(numLiterals, numOffsets, numCodegens, eof)
	}

	// Write the tokens.
	w.writeTokens(tokens, literalEncoding.codes, offsetEncoding.codes)
}

// writeBlockDynamic encodes a block using a dynamic Huffman table.
// This should be used if the symbols used have a disproportionate
// histogram distribution.
// If input is supplied and the compression savings are below 1/16th of the
// input size the block is stored.
func (w *huffmanBitWriter) writeBlockDynamic(tokens []token, eof bool, input []byte) {
	if w.err != nil {
		return
	}

	tokens = append(tokens, endBlockMarker)
	numLiterals, numOffsets := w.indexTokens(tokens)

	// Generate codegen and codegenFrequencies, which indicates how to encode
	// the literalEncoding and the offsetEncoding.
	w.generateCodegen(numLiterals, numOffsets, w.literalEncoding, w.offsetEncoding)
	w.codegenEncoding.generate(w.codegenFreq[:], 7)
	size, numCodegens := w.dynamicSize(w.literalEncoding, w.offsetEncoding, 0)

	// Store bytes, if we don't get a reasonable improvement.
	if ssize, storable := w.storedSize(input); storable && ssize < (size+size>>4) {
		w.writeStoredHeader(len(input), eof)
		w.writeBytes(input)
		return
	}

	// Write Huffman table.
	w.writeDynamicHeader(numLiterals, numOffsets, numCodegens, eof)

	// Write the tokens.
	w.writeTokens(tokens, w.literalEncoding.codes, w.offsetEncoding.codes)
}

// indexTokens indexes a slice of tokens, and updates
// literalFreq and offsetFreq, and generates literalEncoding
// and offsetEncoding.
// The number of literal and offset tokens is returned.
func (w *huffmanBitWriter) indexTokens(tokens []token) (numLiterals, numOffsets int) {
	clear(w.literalFreq)
	clear(w.offsetFreq)

	for _, t := range tokens {
		if t < matchType {
			w.literalFreq[t.literal()]++
			continue
		}
		length := t.length()
		offset := t.offset()
		w.literalFreq[lengthCodesStart+lengthCode(length)]++
		w.offsetFreq[offsetCode(offset)]++
	}

	// get the number of literals
	numLiterals = len(w.literalFreq)
	for w.literalFreq[numLiterals-1] == 0 {
		numLiterals--
	}
	// get the number of offsets
	numOffsets = len(w.offsetFreq)
	for numOffsets > 0 && w.offsetFreq[numOffsets-1] == 0 {
		numOffsets--
	}
	if numOffsets == 0 {
		// We haven't found a single match. If we want to go with the dynamic encoding,
		// we should count at least one offset to be sure that the offset huffman tree could be encoded.
		w.offsetFreq[0] = 1
		numOffsets = 1
	}
	w.literalEncoding.generate(w.literalFreq, 15)
	w.offsetEncoding.generate(w.offsetFreq, 15)
	return
}

// writeTokens writes a slice of tokens to the output.
// codes for literal and offset encoding must be supplied.
func (w *huffmanBitWriter) writeTokens(tokens []token, leCodes, oeCodes []hcode) {
	if w.err != nil {
		return
	}
	for _, t := range tokens {
		if t < matchType {
			w.writeCode(leCodes[t.literal()])
			continue
		}
		// Write the length
		length := t.length()
		lengthCode := lengthCode(length)
		w.writeCode(leCodes[lengthCode+lengthCodesStart])
		extraLengthBits := uint(lengthExtraBits[lengthCode])
		if extraLengthBits > 0 {
			extraLength := int32(length - lengthBase[lengthCode])
			w.writeBits(extraLength, extraLengthBits)
		}
		// Write the offset
		offset := t.offset()
		offsetCode := offsetCode(offset)
		w.writeCode(oeCodes[offsetCode])
		extraOffsetBits := uint(offsetExtraBits[offsetCode])
		if extraOffsetBits > 0 {
			extraOffset := int32(offset - offsetBase[offsetCode])
			w.writeBits(extraOffset, extraOffsetBits)
		}
	}
}

// huffOffset is a static offset encoder used for huffman only encoding.
// It can be reused since we will not be encoding offset values.
var huffOffset *huffmanEncoder

func init() {
	offsetFreq := make([]int32, offsetCodeCount)
	offsetFreq[0] = 1
	huffOffset = newHuffmanEncoder(offsetCodeCount)
	huffOffset.generate(offsetFreq, 15)
}

// writeBlockHuff encodes a block of bytes as either
// Huffman encoded literals or uncompressed bytes if the
// results only gains very little from compression.
func (w *huffmanBitWriter) writeBlockHuff(eof bool, input []byte) {
	if w.err != nil {
		return
	}

	// Clear histogram
	clear(w.literalFreq)

	// Add everything as literals
	histogram(input, w.literalFreq)

	w.literalFreq[endBlockMarker] = 1

	const numLiterals = endBlockMarker + 1
	w.offsetFreq[0] = 1
	const numOffsets = 1

	w.literalEncoding.generate(w.literalFreq, 15)

	// Figure out smallest code.
	// Always use dynamic Huffman or Store
	var numCodegens int

	// Generate codegen and codegenFrequencies, which indicates how to encode
	// the literalEncoding and the offsetEncoding.
	w.generateCodegen(numLiterals, numOffsets, w.literalEncoding, huffOffset)
	w.codegenEncoding.generate(w.codegenFreq[:], 7)
	size, numCodegens := w.dynamicSize(w.literalEncoding, huffOffset, 0)

	// Store bytes, if we don't get a reasonable improvement.
	if ssize, storable := w.storedSize(input); storable && ssize < (size+size>>4) {
		w.writeStoredHeader(len(input), eof)
		w.writeBytes(input)
		return
	}

	// Huffman.
	w.writeDynamicHeader(numLiterals, numOffsets, numCodegens, eof)
	encoding := w.literalEncoding.codes[:257]
	n := w.nbytes
	for _, t := range input {
		// Bitwriting inlined, ~30% speedup
		c := encoding[t]
		w.bits |= uint64(c.code) << w.nbits
		w.nbits += uint(c.len)
		if w.nbits < 48 {
			continue
		}
		// Store 6 bytes
		bits := w.bits
		w.bits >>= 48
		w.nbits -= 48
		bytes := w.bytes[n : n+6]
		bytes[0] = byte(bits)
		bytes[1] = byte(bits >> 8)
		bytes[2] = byte(bits >> 16)
		bytes[3] = byte(bits >> 24)
		bytes[4] = byte(bits >> 32)
		bytes[5] = byte(bits >> 40)
		n += 6
		if n < bufferFlushSize {
			continue
		}
		w.write(w.bytes[:n])
		if w.err != nil {
			return // Return early in the event of write failures
		}
		n = 0
	}
	w.nbytes = n
	w.writeCode(encoding[endBlockMarker])
}

// histogram accumulates a histogram of b in h.
//
// len(h) must be >= 256, and h's elements must be all zeroes.
func histogram(b []byte, h []int32) {
	h = h[:256]
	for _, t := range b {
		h[t]++
	}
}

"""



```