Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The request asks for the functionality of the given Go code, explanations with examples, and potential pitfalls for users. The core file is `huffman_code.go`, hinting at Huffman encoding, a data compression technique.

**2. Initial Code Scan and Keyword Identification:**

I started by quickly scanning the code, looking for keywords and data structures that provide clues:

* **`package flate`:** This immediately tells me it's part of the `flate` package, which is related to the DEFLATE compression algorithm (used in ZIP, gzip, etc.).
* **`hcode`:**  Likely represents a Huffman code, containing the actual bit code and its length.
* **`huffmanEncoder`:**  This is the central structure, responsible for generating and managing Huffman codes.
* **`literalNode`:** Seems to represent a symbol (literal) and its frequency.
* **`bitCount`:**  Probably tracks the number of codes of a certain bit length.
* **`generateFixedLiteralEncoding`, `generateFixedOffsetEncoding`:**  Suggests the implementation handles fixed Huffman code tables, which are part of the DEFLATE standard.
* **`generate`:** This function likely generates a Huffman code based on input frequencies.
* **`reverseBits`:**  This is a crucial detail for Huffman coding as the codes need to be reversed before being written to the bitstream.
* **`sort.Sort`:** Indicates sorting operations are important, likely for constructing the Huffman tree efficiently.

**3. Deciphering the Data Structures:**

* **`hcode`:** Simple structure holding the encoded bit pattern (`code`) and its length (`len`).
* **`huffmanEncoder`:**  Contains the generated Huffman codes (`codes`), a cache for frequencies (`freqcache`), bit counts (`bitCount`), and sorting helpers (`lns`, `lfs`). The sorting helpers are optimizations to avoid repeated allocations.
* **`literalNode`:** Stores the symbol (`literal`) and its frequency (`freq`).

**4. Understanding the Key Functions:**

* **`generateFixedLiteralEncoding()` and `generateFixedOffsetEncoding()`:** These are straightforward. They create pre-defined Huffman codes based on the DEFLATE specification. The `switch` statement in `generateFixedLiteralEncoding` directly maps literal values to their corresponding fixed codes and lengths.
* **`generate(freq []int32, maxBits int32)`:** This is the core function for generating *dynamic* Huffman codes. The steps involved are:
    1. **Counting Frequencies:**  It takes an array of frequencies as input.
    2. **Sorting by Frequency:**  The `lfs.sort(list)` call sorts the literals by frequency, which is essential for Huffman tree construction.
    3. **Calculating Bit Counts (`bitCounts`)**:  This is the most complex part. It implements a somewhat optimized algorithm for determining the number of codes of each length, respecting the `maxBits` limit. The `levelInfo` structure and the nested loops are related to building the Huffman tree level by level (implicitly, not explicitly as a tree data structure).
    4. **Assigning Codes (`assignEncodingAndSize`)**: This function takes the calculated bit counts and assigns actual bit codes to the literals. The codes are assigned in a way that preserves prefix-freeness. The `reverseBits` function is used here to get the correct bit order.
* **`bitLength(freq []int32)`:** Calculates the total number of bits required to encode data given the frequencies and the generated Huffman codes.

**5. Inferring the Overall Functionality:**

Based on the individual components, it's clear that this code implements the core logic for Huffman encoding, a key part of the DEFLATE compression algorithm. It can generate both the fixed Huffman codes specified by the standard and dynamic Huffman codes based on input data frequencies.

**6. Constructing Examples:**

* **Fixed Encoding:**  Easy to demonstrate by simply calling the `generateFixedLiteralEncoding` function and inspecting the generated codes for specific literals.
* **Dynamic Encoding:**  Requires providing sample frequencies to the `generate` function. I chose a simple example with a few distinct frequencies to illustrate the process. Showing the output `hcode` values demonstrates the result of the encoding.

**7. Identifying Potential Pitfalls:**

I focused on common issues when working with compression and Huffman coding:

* **Incorrect Frequency Calculation:**  If the input frequencies are wrong, the generated Huffman codes will be suboptimal or even invalid.
* **Exceeding `maxBits`:**  Understanding the `maxBits` parameter is important. Setting it too low can lead to errors or suboptimal compression.
* **Misunderstanding Fixed vs. Dynamic:**  It's crucial to know when to use the fixed codes and when to generate dynamic codes.

**8. Structuring the Answer:**

I organized the answer into the following sections:

* **功能列举:**  A high-level summary of the code's capabilities.
* **功能实现推理 (Dynamic Huffman Coding):**  Focused on the most interesting part, the dynamic code generation, providing a Go code example.
* **功能实现推理 (Fixed Huffman Coding):**  A simpler example for the fixed codes.
* **易犯错的点:**  Addressed the potential pitfalls identified earlier.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the low-level details of the `bitCounts` function. I realized that the high-level purpose is more important for the user.
* I ensured the examples were clear and illustrative, showing both input and output.
* I double-checked the terminology (literal, code, length, frequency) to be consistent.
* I made sure to explain the `reverseBits` function's role, as it's a crucial detail often overlooked.

By following these steps, I was able to provide a comprehensive and informative answer to the user's request.
这段Go语言代码是 `compress/flate` 包中实现 **霍夫曼编码 (Huffman Coding)** 的一部分。霍夫曼编码是一种用于无损数据压缩的熵编码算法。这段代码定义了用于生成和管理霍夫曼编码的数据结构和函数。

以下是它的主要功能：

1. **定义霍夫曼编码的数据结构 (`hcode`)**:  `hcode` 结构体用于存储一个霍夫曼编码的实际比特码 (`code`) 和比特长度 (`len`)。

2. **定义霍夫曼编码器的结构 (`huffmanEncoder`)**: `huffmanEncoder` 结构体负责生成霍夫曼编码。它包含：
   - `codes`: 一个 `hcode` 类型的切片，存储每个符号的霍夫曼编码。
   - `freqcache`: 一个 `literalNode` 类型的切片，用于缓存频率信息，避免重复分配内存。
   - `bitCount`: 一个 `int32` 类型的数组，记录不同比特长度的编码数量。
   - `lns`: 一个 `byLiteral` 类型的实例，用于按字面值排序。
   - `lfs`: 一个 `byFreq` 类型的实例，用于按频率排序。

3. **定义表示字面值的节点 (`literalNode`)**: `literalNode` 结构体存储一个字面值 (`literal`) 和它的频率 (`freq`)。

4. **定义层级信息 (`levelInfo`)**:  `levelInfo` 结构体在构建霍夫曼树的过程中用于跟踪特定深度的状态。它包含当前层级、最后一个节点的频率、下一个要添加的字符的频率等信息。

5. **提供设置编码的方法 (`set`)**: `hcode` 的 `set` 方法用于设置编码的比特码和长度。

6. **创建新的霍夫曼编码器 (`newHuffmanEncoder`)**:  `newHuffmanEncoder` 函数创建一个指定大小的 `huffmanEncoder` 实例。

7. **生成固定霍夫曼编码 (`generateFixedLiteralEncoding`, `generateFixedOffsetEncoding`)**: 这两个函数生成预定义的、固定的霍夫曼编码，用于 DEFLATE 压缩算法中的固定霍夫曼编码表。
   - `generateFixedLiteralEncoding` 生成用于表示字面值和长度的固定编码。
   - `generateFixedOffsetEncoding` 生成用于表示距离的固定编码。

8. **计算编码后的比特长度 (`bitLength`)**:  `bitLength` 方法计算使用当前霍夫曼编码对给定频率的符号进行编码所需的总比特数。

9. **计算不同比特长度的编码数量 (`bitCounts`)**: `bitCounts` 方法根据字面值的频率列表和最大比特数，计算出每个比特长度应该有多少个编码。这是构建霍夫曼树的关键步骤。

10. **分配编码和大小 (`assignEncodingAndSize`)**:  `assignEncodingAndSize` 方法根据计算出的不同比特长度的编码数量，为每个字面值分配实际的比特码和长度。它会根据字面值的顺序分配编码，并使用 `reverseBits` 函数反转比特顺序。

11. **生成霍夫曼编码 (`generate`)**: `generate` 方法是生成动态霍夫曼编码的核心函数。它接收一个频率数组和最大比特数，并根据这些信息生成最优的霍夫曼编码。它会处理特殊情况（少于等于两个字面值的情况），并调用 `bitCounts` 和 `assignEncodingAndSize` 来完成编码的生成。

12. **提供按字面值和频率排序的功能 (`byLiteral`, `byFreq`)**: 这两个类型实现了 `sort.Interface`，用于对 `literalNode` 切片进行排序，方便构建霍夫曼树。

13. **反转比特顺序 (`reverseBits`)**: `reverseBits` 函数用于反转一个无符号 16 位整数的指定长度的比特顺序，这在霍夫曼编码中是必需的，因为比特是按照相反的顺序写入的。

**功能实现推理 (动态霍夫曼编码):**

这段代码实现了根据输入数据的频率动态生成霍夫曼编码的功能。

**Go 代码示例：**

假设我们有一些字面值及其对应的频率：

```go
package main

import (
	"fmt"
	"compress/flate"
)

func main() {
	freq := []int32{
		5, // 'A'
		1, // 'B'
		2, // 'C'
		8, // 'D'
	}
	maxBits := int32(15) // 设置最大比特长度

	encoder := flate.NewHuffmanEncoder(len(freq))
	encoder.Generate(freq, maxBits)

	fmt.Println("生成的霍夫曼编码:")
	for i, code := range encoder.Codes[:len(freq)] {
		fmt.Printf("字面值 %c: 编码 %b, 长度 %d\n", 'A'+byte(i), code.Code, code.Len)
	}
}
```

**假设的输入与输出：**

**输入 (频率):**
- 'A': 5
- 'B': 1
- 'C': 2
- 'D': 8

**输出 (生成的霍夫曼编码 - 输出可能因排序和算法实现细节略有不同，但基本原理一致):**

```
生成的霍夫曼编码:
字面值 A: 编码 10, 长度 2
字面值 B: 编码 110, 长度 3
字面值 C: 编码 111, 长度 3
字面值 D: 编码 0, 长度 1
```

**解释：** 频率最高的 'D' 被分配了最短的编码 '0'，频率最低的 'B' 被分配了较长的编码 '110'。

**功能实现推理 (固定霍夫曼编码):**

这段代码也实现了生成固定霍夫曼编码的功能，这是 DEFLATE 规范中预定义的编码表。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"compress/flate"
)

func main() {
	fixedLiteralEncoder := flate.GenerateFixedLiteralEncoding()

	fmt.Println("部分固定字面值霍夫曼编码:")
	// 打印一些字面值的固定编码
	for i := 0; i < 10; i++ {
		code := fixedLiteralEncoder.Codes[i]
		fmt.Printf("字面值 %d: 编码 %b, 长度 %d\n", i, code.Code, code.Len)
	}

	fixedOffsetEncoder := flate.GenerateFixedOffsetEncoding()
	fmt.Println("\n部分固定距离霍夫曼编码:")
	for i := 0; i < 5; i++ {
		code := fixedOffsetEncoder.Codes[i]
		fmt.Printf("距离代码 %d: 编码 %b, 长度 %d\n", i, code.Code, code.Len)
	}
}
```

**假设的输出：**

```
部分固定字面值霍夫曼编码:
字面值 0: 编码 11000000, 长度 8
字面值 1: 编码 11000001, 长度 8
字面值 2: 编码 11000010, 长度 8
字面值 3: 编码 11000011, 长度 8
字面值 4: 编码 11000100, 长度 8
字面值 5: 编码 11000101, 长度 8
字面值 6: 编码 11000110, 长度 8
字面值 7: 编码 11000111, 长度 8
字面值 8: 编码 110010000, 长度 9
字面值 9: 编码 110010001, 长度 9

部分固定距离霍夫曼编码:
距离代码 0: 编码 00000, 长度 5
距离代码 1: 编码 00001, 长度 5
距离代码 2: 编码 00010, 长度 5
距离代码 3: 编码 00011, 长度 5
距离代码 4: 编码 00100, 长度 5
```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它的功能是提供霍夫曼编码的生成能力，通常被更上层的压缩逻辑调用。例如，在 `compress/flate` 包的其他部分，可能会有代码读取输入数据，计算频率，然后调用 `huffmanEncoder` 的 `Generate` 方法来生成编码。

如果要结合命令行参数，通常需要编写一个使用 `compress/flate` 包的应用程序，该应用程序会解析命令行参数以确定输入文件、输出文件、压缩级别等，并根据这些参数调用相应的压缩功能。

**使用者易犯错的点：**

1. **错误地计算频率：**  生成有效的霍夫曼编码的关键是准确计算输入数据的字面值频率。如果频率计算错误，生成的编码将不是最优的，甚至可能导致解压失败。例如，如果漏掉了一些字面值，或者对某些字面值的频率计算过高或过低，都会影响编码效果。

   **示例：**  假设要压缩字符串 "AAABBC"，但错误地将频率计算为 A:2, B:3, C:1。生成的霍夫曼编码将与实际最优编码不同。

2. **不理解固定霍夫曼编码和动态霍夫曼编码的区别和应用场景：**  DEFLATE 算法允许使用固定的或动态生成的霍夫曼编码。固定编码不需要在压缩数据中存储编码表，但压缩率可能不如动态编码高。动态编码会根据输入数据生成最优的编码，但需要在压缩数据中包含编码表。错误地选择或实现这两种编码方式会导致压缩效率低下或解压错误。

3. **`maxBits` 参数设置不合理：**  `generate` 方法中的 `maxBits` 参数限制了任何编码的最大比特长度。如果设置得太小，可能无法为所有字面值生成唯一的编码，导致程序出错或生成无效的编码。通常，`maxBits` 的合理值是根据 DEFLATE 规范确定的（例如，字面值/长度码的最大长度为 15，距离码的最大长度为 15）。

4. **忽略 `reverseBits` 的作用：**  霍夫曼编码的比特顺序是反向的。如果在使用生成的 `code` 时没有考虑到这一点，直接按从左到右的顺序写入比特流，会导致解压时无法正确识别编码。

这段代码是实现霍夫曼编码的核心部分，理解其功能对于理解和使用 Go 语言的 `compress/flate` 包进行数据压缩至关重要。

### 提示词
```
这是路径为go/src/compress/flate/huffman_code.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package flate

import (
	"math"
	"math/bits"
	"sort"
)

// hcode is a huffman code with a bit code and bit length.
type hcode struct {
	code, len uint16
}

type huffmanEncoder struct {
	codes     []hcode
	freqcache []literalNode
	bitCount  [17]int32
	lns       byLiteral // stored to avoid repeated allocation in generate
	lfs       byFreq    // stored to avoid repeated allocation in generate
}

type literalNode struct {
	literal uint16
	freq    int32
}

// A levelInfo describes the state of the constructed tree for a given depth.
type levelInfo struct {
	// Our level.  for better printing
	level int32

	// The frequency of the last node at this level
	lastFreq int32

	// The frequency of the next character to add to this level
	nextCharFreq int32

	// The frequency of the next pair (from level below) to add to this level.
	// Only valid if the "needed" value of the next lower level is 0.
	nextPairFreq int32

	// The number of chains remaining to generate for this level before moving
	// up to the next level
	needed int32
}

// set sets the code and length of an hcode.
func (h *hcode) set(code uint16, length uint16) {
	h.len = length
	h.code = code
}

func maxNode() literalNode { return literalNode{math.MaxUint16, math.MaxInt32} }

func newHuffmanEncoder(size int) *huffmanEncoder {
	return &huffmanEncoder{codes: make([]hcode, size)}
}

// Generates a HuffmanCode corresponding to the fixed literal table.
func generateFixedLiteralEncoding() *huffmanEncoder {
	h := newHuffmanEncoder(maxNumLit)
	codes := h.codes
	var ch uint16
	for ch = 0; ch < maxNumLit; ch++ {
		var bits uint16
		var size uint16
		switch {
		case ch < 144:
			// size 8, 000110000  .. 10111111
			bits = ch + 48
			size = 8
		case ch < 256:
			// size 9, 110010000 .. 111111111
			bits = ch + 400 - 144
			size = 9
		case ch < 280:
			// size 7, 0000000 .. 0010111
			bits = ch - 256
			size = 7
		default:
			// size 8, 11000000 .. 11000111
			bits = ch + 192 - 280
			size = 8
		}
		codes[ch] = hcode{code: reverseBits(bits, byte(size)), len: size}
	}
	return h
}

func generateFixedOffsetEncoding() *huffmanEncoder {
	h := newHuffmanEncoder(30)
	codes := h.codes
	for ch := range codes {
		codes[ch] = hcode{code: reverseBits(uint16(ch), 5), len: 5}
	}
	return h
}

var fixedLiteralEncoding *huffmanEncoder = generateFixedLiteralEncoding()
var fixedOffsetEncoding *huffmanEncoder = generateFixedOffsetEncoding()

func (h *huffmanEncoder) bitLength(freq []int32) int {
	var total int
	for i, f := range freq {
		if f != 0 {
			total += int(f) * int(h.codes[i].len)
		}
	}
	return total
}

const maxBitsLimit = 16

// bitCounts computes the number of literals assigned to each bit size in the Huffman encoding.
// It is only called when list.length >= 3.
// The cases of 0, 1, and 2 literals are handled by special case code.
//
// list is an array of the literals with non-zero frequencies
// and their associated frequencies. The array is in order of increasing
// frequency and has as its last element a special element with frequency
// MaxInt32.
//
// maxBits is the maximum number of bits that should be used to encode any literal.
// It must be less than 16.
//
// bitCounts returns an integer slice in which slice[i] indicates the number of literals
// that should be encoded in i bits.
func (h *huffmanEncoder) bitCounts(list []literalNode, maxBits int32) []int32 {
	if maxBits >= maxBitsLimit {
		panic("flate: maxBits too large")
	}
	n := int32(len(list))
	list = list[0 : n+1]
	list[n] = maxNode()

	// The tree can't have greater depth than n - 1, no matter what. This
	// saves a little bit of work in some small cases
	if maxBits > n-1 {
		maxBits = n - 1
	}

	// Create information about each of the levels.
	// A bogus "Level 0" whose sole purpose is so that
	// level1.prev.needed==0.  This makes level1.nextPairFreq
	// be a legitimate value that never gets chosen.
	var levels [maxBitsLimit]levelInfo
	// leafCounts[i] counts the number of literals at the left
	// of ancestors of the rightmost node at level i.
	// leafCounts[i][j] is the number of literals at the left
	// of the level j ancestor.
	var leafCounts [maxBitsLimit][maxBitsLimit]int32

	for level := int32(1); level <= maxBits; level++ {
		// For every level, the first two items are the first two characters.
		// We initialize the levels as if we had already figured this out.
		levels[level] = levelInfo{
			level:        level,
			lastFreq:     list[1].freq,
			nextCharFreq: list[2].freq,
			nextPairFreq: list[0].freq + list[1].freq,
		}
		leafCounts[level][level] = 2
		if level == 1 {
			levels[level].nextPairFreq = math.MaxInt32
		}
	}

	// We need a total of 2*n - 2 items at top level and have already generated 2.
	levels[maxBits].needed = 2*n - 4

	level := maxBits
	for {
		l := &levels[level]
		if l.nextPairFreq == math.MaxInt32 && l.nextCharFreq == math.MaxInt32 {
			// We've run out of both leaves and pairs.
			// End all calculations for this level.
			// To make sure we never come back to this level or any lower level,
			// set nextPairFreq impossibly large.
			l.needed = 0
			levels[level+1].nextPairFreq = math.MaxInt32
			level++
			continue
		}

		prevFreq := l.lastFreq
		if l.nextCharFreq < l.nextPairFreq {
			// The next item on this row is a leaf node.
			n := leafCounts[level][level] + 1
			l.lastFreq = l.nextCharFreq
			// Lower leafCounts are the same of the previous node.
			leafCounts[level][level] = n
			l.nextCharFreq = list[n].freq
		} else {
			// The next item on this row is a pair from the previous row.
			// nextPairFreq isn't valid until we generate two
			// more values in the level below
			l.lastFreq = l.nextPairFreq
			// Take leaf counts from the lower level, except counts[level] remains the same.
			copy(leafCounts[level][:level], leafCounts[level-1][:level])
			levels[l.level-1].needed = 2
		}

		if l.needed--; l.needed == 0 {
			// We've done everything we need to do for this level.
			// Continue calculating one level up. Fill in nextPairFreq
			// of that level with the sum of the two nodes we've just calculated on
			// this level.
			if l.level == maxBits {
				// All done!
				break
			}
			levels[l.level+1].nextPairFreq = prevFreq + l.lastFreq
			level++
		} else {
			// If we stole from below, move down temporarily to replenish it.
			for levels[level-1].needed > 0 {
				level--
			}
		}
	}

	// Somethings is wrong if at the end, the top level is null or hasn't used
	// all of the leaves.
	if leafCounts[maxBits][maxBits] != n {
		panic("leafCounts[maxBits][maxBits] != n")
	}

	bitCount := h.bitCount[:maxBits+1]
	bits := 1
	counts := &leafCounts[maxBits]
	for level := maxBits; level > 0; level-- {
		// chain.leafCount gives the number of literals requiring at least "bits"
		// bits to encode.
		bitCount[bits] = counts[level] - counts[level-1]
		bits++
	}
	return bitCount
}

// Look at the leaves and assign them a bit count and an encoding as specified
// in RFC 1951 3.2.2
func (h *huffmanEncoder) assignEncodingAndSize(bitCount []int32, list []literalNode) {
	code := uint16(0)
	for n, bits := range bitCount {
		code <<= 1
		if n == 0 || bits == 0 {
			continue
		}
		// The literals list[len(list)-bits] .. list[len(list)-bits]
		// are encoded using "bits" bits, and get the values
		// code, code + 1, ....  The code values are
		// assigned in literal order (not frequency order).
		chunk := list[len(list)-int(bits):]

		h.lns.sort(chunk)
		for _, node := range chunk {
			h.codes[node.literal] = hcode{code: reverseBits(code, uint8(n)), len: uint16(n)}
			code++
		}
		list = list[0 : len(list)-int(bits)]
	}
}

// Update this Huffman Code object to be the minimum code for the specified frequency count.
//
// freq is an array of frequencies, in which freq[i] gives the frequency of literal i.
// maxBits  The maximum number of bits to use for any literal.
func (h *huffmanEncoder) generate(freq []int32, maxBits int32) {
	if h.freqcache == nil {
		// Allocate a reusable buffer with the longest possible frequency table.
		// Possible lengths are codegenCodeCount, offsetCodeCount and maxNumLit.
		// The largest of these is maxNumLit, so we allocate for that case.
		h.freqcache = make([]literalNode, maxNumLit+1)
	}
	list := h.freqcache[:len(freq)+1]
	// Number of non-zero literals
	count := 0
	// Set list to be the set of all non-zero literals and their frequencies
	for i, f := range freq {
		if f != 0 {
			list[count] = literalNode{uint16(i), f}
			count++
		} else {
			h.codes[i].len = 0
		}
	}

	list = list[:count]
	if count <= 2 {
		// Handle the small cases here, because they are awkward for the general case code. With
		// two or fewer literals, everything has bit length 1.
		for i, node := range list {
			// "list" is in order of increasing literal value.
			h.codes[node.literal].set(uint16(i), 1)
		}
		return
	}
	h.lfs.sort(list)

	// Get the number of literals for each bit count
	bitCount := h.bitCounts(list, maxBits)
	// And do the assignment
	h.assignEncodingAndSize(bitCount, list)
}

type byLiteral []literalNode

func (s *byLiteral) sort(a []literalNode) {
	*s = byLiteral(a)
	sort.Sort(s)
}

func (s byLiteral) Len() int { return len(s) }

func (s byLiteral) Less(i, j int) bool {
	return s[i].literal < s[j].literal
}

func (s byLiteral) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

type byFreq []literalNode

func (s *byFreq) sort(a []literalNode) {
	*s = byFreq(a)
	sort.Sort(s)
}

func (s byFreq) Len() int { return len(s) }

func (s byFreq) Less(i, j int) bool {
	if s[i].freq == s[j].freq {
		return s[i].literal < s[j].literal
	}
	return s[i].freq < s[j].freq
}

func (s byFreq) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func reverseBits(number uint16, bitLength byte) uint16 {
	return bits.Reverse16(number << (16 - bitLength))
}
```