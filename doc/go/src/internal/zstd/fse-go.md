Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Identification of Key Structures:**

My first step is always to quickly read through the code to identify the main data structures and function signatures. I see:

* `fseEntry`: A struct with `sym`, `bits`, and `base`. This looks like a fundamental building block. The name "fseEntry" suggests it's related to Finite State Entropy (FSE) decoding.
* `readFSE`: A method on `Reader` that takes `data`, `off`, `maxSym`, `maxBits`, and `table` as input and returns `tableBits`, `roff`, and `error`. The name strongly suggests reading and building an FSE table.
* `buildFSE`: Another method on `Reader` that takes `off`, `norm`, `table`, and `tableBits`. This likely handles the final construction of the FSE table based on normalized probabilities.
* `fseBaselineEntry`: A struct similar to `fseEntry`, but with `baseline` and `basebits`. This hints at a variation of FSE that incorporates baseline values and additional bits.
* `makeLiteralBaselineFSE`, `makeOffsetBaselineFSE`, `makeMatchBaselineFSE`:  Methods on `Reader` that convert `fseEntry` tables to `fseBaselineEntry` tables. The names indicate they are specific to different types of data (literals, offsets, matches).
* `predefined...Table`: Global variables of type `[...]fseBaselineEntry`. These look like precomputed tables for common cases.

**2. Focusing on the Core Functionality: `readFSE` and `buildFSE`:**

The presence of `readFSE` and `buildFSE` together strongly suggests a two-stage process:

* **`readFSE`**: Reads the compressed representation of the FSE table from the input `data`. It decodes the probabilities (or counts) of different symbols. The `accuracyLog` variable and the logic around `remaining`, `threshold`, and `bitsNeeded` suggest a process of iteratively refining probability estimates. The handling of `prev0` indicates a special encoding for sequences of zero counts.
* **`buildFSE`**: Takes the normalized probabilities (or counts) computed by `readFSE` and constructs the actual decoding table (`table`). The logic involving `highThreshold`, `next`, `pos`, and `step` is likely related to efficiently distributing symbols within the table based on their probabilities. The calculation of `bits` and `base` within the loop is crucial for the actual FSE decoding process.

**3. Inferring the Purpose of `fseBaselineEntry` and the `make...BaselineFSE` functions:**

The `fseBaselineEntry` struct with its `baseline` and `basebits` fields suggests that some symbols require additional information beyond the basic FSE state transition. The `make...BaselineFSE` functions are clearly responsible for transforming the standard FSE table into this baseline format. The names of the functions (`Literal`, `Offset`, `Match`) strongly suggest that this is related to different elements of a compression algorithm.

**4. Connecting to Zstandard (zstd):**

The package name `internal/zstd` and the mention of "RFC 4.1.1" in the `readFSE` documentation are strong indicators that this code is part of a Zstandard (zstd) decompression implementation. FSE is a known entropy coding method used in zstd.

**5. Hypothesizing Go Features and Providing Examples:**

Based on the above analysis, I can hypothesize that the code implements FSE decoding, a core part of zstd. To demonstrate this in Go, I need to show how this code *could* be used in a larger zstd decompression context. This involves:

* **Creating a `Reader`**:  The `readFSE` and other methods are on a `Reader` type, so I need to instantiate one (or at least show how it could be done).
* **Providing Input Data**: The `readFSE` function takes `data` (a `block` type, likely a slice of bytes). I need to provide sample input data that represents a compressed FSE table.
* **Allocating the FSE Table**:  The `readFSE` function writes to a `table` slice. I need to show how to allocate a sufficiently sized slice.
* **Calling `readFSE` and Potentially `buildFSE`**:  Demonstrate the invocation of the core functions.
* **Interpreting the Output**:  Explain the meaning of `tableBits` and the structure of the `table`.

For the baseline FSE, I need to illustrate how the `make...BaselineFSE` functions are used, linking them to the different types of data they handle (literals, offsets, matches).

**6. Considering Command-Line Arguments (if applicable):**

Since the provided code snippet focuses on the internal workings of FSE decoding, it doesn't directly handle command-line arguments. Therefore, I would state that it doesn't involve command-line processing.

**7. Identifying Potential Pitfalls:**

Based on the function signatures and the logic within the functions, I can identify potential errors:

* **Incorrect Table Size**: Providing a `table` slice that is too small for `maxBits` will lead to issues.
* **Invalid Input Data**: Corrupted or malformed input data in the `block` can cause decoding errors. The `br.makeError` calls within `readFSE` indicate error handling for such cases.
* **Symbol Overflow**: The checks for `sym > maxSym` and similar conditions in the baseline functions indicate that exceeding the expected symbol range is a potential error.

**8. Structuring the Answer in Chinese:**

Finally, I organize my analysis into a clear and structured Chinese response, covering all the points mentioned in the prompt. This involves:

* Clearly stating the primary function: FSE decoding for zstd.
* Explaining the purpose of each key data structure and function.
* Providing illustrative Go code examples with hypothetical inputs and outputs.
* Explicitly mentioning the lack of command-line argument handling.
* Listing potential user errors with concrete examples.
* Using precise technical terminology in Chinese.

This systematic approach allows me to thoroughly analyze the code snippet and provide a comprehensive and accurate answer.
这段代码是 Go 语言实现的 zstd 压缩库的一部分，主要负责 **FSE (Finite State Entropy)** 解码。FSE 是一种用于高效数据压缩的熵编码方法。

**主要功能:**

1. **读取 FSE 表 (`readFSE` 函数):**
   - 从给定的 `data` 字节切片的指定偏移量 `off` 开始，解析 FSE 表的压缩表示。
   - `maxSym` 和 `maxBits` 参数分别指定了表中允许的最大符号值和最大比特数。
   - 将解析出的 FSE 表信息写入到提供的 `table` 切片中。`table` 的大小必须至少为 `1<<maxBits`。
   - 返回 FSE 表的比特长度 (`tableBits`)、新的读取偏移量 (`roff`) 以及可能发生的错误。
   - 该函数实现了 RFC 4.1.1 中描述的 FSE 表读取过程。

2. **构建 FSE 解码表 (`buildFSE` 函数):**
   - 基于提供的符号概率分布 `norm` 构建实际的 FSE 解码表 `table`。
   - `tableBits` 指定了解码表的比特数，决定了表的大小。
   - 该函数根据符号的概率，在解码表中分配条目，以便能够高效地进行解码。

3. **构建基线 FSE 表 (`makeLiteralBaselineFSE`, `makeOffsetBaselineFSE`, `makeMatchBaselineFSE` 函数):**
   - 将标准的 `fseEntry` 类型的 FSE 表转换为 `fseBaselineEntry` 类型的基线 FSE 表。
   - 基线 FSE 表用于处理需要额外基线值和比特位读取的符号，例如字面量长度、偏移量和匹配长度。
   - `makeLiteralBaselineFSE` 用于转换字面量长度的 FSE 表。
   - `makeOffsetBaselineFSE` 用于转换偏移量的 FSE 表。
   - `makeMatchBaselineFSE` 用于转换匹配长度的 FSE 表。

4. **提供预定义的 FSE 基线表 (`predefinedLiteralTable`, `predefinedOffsetTable`, `predefinedMatchTable`):**
   - 定义了用于字面量长度、偏移量和匹配长度的预定义的 FSE 基线表。
   - 这些表是根据 zstd 规范预先计算好的，可以直接使用，避免了在某些情况下重新构建表的开销。

**它是什么 Go 语言功能的实现？**

这段代码实现了 zstd 压缩算法中用于熵解码的关键部分，特别是 FSE 解码。FSE 是一种高效的有限状态熵编码方法，用于将符号序列转换为比特流，并在解码时反向操作。

**Go 代码举例说明:**

假设我们有一段表示压缩数据的 `block` 和一个 `Reader` 实例 `r`。我们想要读取并构建一个用于解码字面量的 FSE 表。

```go
package main

import (
	"fmt"
	"internal/zstd" // 注意：这是 internal 包，通常不直接在外部使用
)

func main() {
	r := &zstd.Reader{} // 创建一个 Reader 实例
	data := zstd.Block{ // 假设这是包含 FSE 表数据的压缩块
		Data: []byte{ /* ... 压缩的 FSE 表数据 ... */ },
	}
	off := 0          // 起始偏移量
	maxSym := 255     // 假设最大符号值为 255
	maxBits := 12     // 假设最大比特数为 12
	tableSize := 1 << maxBits
	table := make([]zstd.FSEEntry, tableSize)

	tableBits, roff, err := r.ReadFSE(data, off, maxSym, maxBits, table)
	if err != nil {
		fmt.Println("读取 FSE 表失败:", err)
		return
	}

	fmt.Printf("FSE 表比特数: %d\n", tableBits)
	fmt.Printf("新的偏移量: %d\n", roff)
	// 可以进一步使用构建的 table 进行解码操作
}
```

**假设的输入与输出:**

假设 `data.Data` 中包含以下表示 FSE 表的字节（这只是一个简化示例，实际的 FSE 表数据会更复杂）：`[]byte{0b00001010}`。

- `0b00001010` 的低 4 位 `0010` 表示 `accuracyLog - 5`，即 `accuracyLog - 5 = 2`，所以 `accuracyLog = 7`。

在这种情况下，调用 `readFSE` 后，可能会得到以下输出（具体取决于 `data` 的实际内容和后续的概率解析）：

- `tableBits`: `7` (与计算出的 `accuracyLog` 相同)
- `roff`:  取决于读取了多少字节来解析 FSE 表，如果完整解析可能为 `1`。
- `table`:  `table` 中的元素会被填充，例如 `table[0] = zstd.FSEEntry{sym: 0, bits: 3, base: 0}` (这只是一个假设的例子，实际值取决于输入数据)。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是 zstd 解码库的内部实现部分。zstd 命令行工具会使用这个库来进行解压缩操作，但命令行参数的处理逻辑在 zstd 工具的更上层。

**使用者易犯错的点:**

1. **`table` 切片大小不足:**  `readFSE` 函数要求提供的 `table` 切片的大小至少为 `1<<maxBits`。如果 `table` 的大小不足，会导致索引越界或其他不可预测的错误。

   ```go
   // 错误示例：table 大小不足
   maxBits := 10
   table := make([]zstd.FSEEntry, 1<<9) // 错误：应该至少是 1<<10
   r.ReadFSE(data, off, maxSym, maxBits, table) // 可能导致错误
   ```

2. **`maxBits` 设置不正确:**  如果 `maxBits` 的值与压缩数据中实际使用的最大比特数不匹配，会导致解码错误。通常，`maxBits` 的值需要从压缩数据的元数据中获取。

3. **直接使用 `internal` 包:**  `internal` 包在 Go 语言中是不稳定的，不保证向后兼容。直接在外部代码中使用 `internal/zstd` 包可能会导致未来的代码编译或运行时错误。应该使用 zstd 库提供的公共 API，例如 `github.com/klauspost/compress/zstd` 或官方的 `github.com/DataDog/zstd`。

总而言之，这段 Go 代码实现了 zstd 解压缩过程中至关重要的 FSE 解码功能，包括读取压缩的 FSE 表、构建解码表以及处理不同类型的基线 FSE 表。理解这段代码有助于深入了解 zstd 压缩算法的内部工作原理。

### 提示词
```
这是路径为go/src/internal/zstd/fse.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zstd

import (
	"math/bits"
)

// fseEntry is one entry in an FSE table.
type fseEntry struct {
	sym  uint8  // value that this entry records
	bits uint8  // number of bits to read to determine next state
	base uint16 // add those bits to this state to get the next state
}

// readFSE reads an FSE table from data starting at off.
// maxSym is the maximum symbol value.
// maxBits is the maximum number of bits permitted for symbols in the table.
// The FSE is written into table, which must be at least 1<<maxBits in size.
// This returns the number of bits in the FSE table and the new offset.
// RFC 4.1.1.
func (r *Reader) readFSE(data block, off, maxSym, maxBits int, table []fseEntry) (tableBits, roff int, err error) {
	br := r.makeBitReader(data, off)
	if err := br.moreBits(); err != nil {
		return 0, 0, err
	}

	accuracyLog := int(br.val(4)) + 5
	if accuracyLog > maxBits {
		return 0, 0, br.makeError("FSE accuracy log too large")
	}

	// The number of remaining probabilities, plus 1.
	// This determines the number of bits to be read for the next value.
	remaining := (1 << accuracyLog) + 1

	// The current difference between small and large values,
	// which depends on the number of remaining values.
	// Small values use 1 less bit.
	threshold := 1 << accuracyLog

	// The number of bits needed to compute threshold.
	bitsNeeded := accuracyLog + 1

	// The next character value.
	sym := 0

	// Whether the last count was 0.
	prev0 := false

	var norm [256]int16

	for remaining > 1 && sym <= maxSym {
		if err := br.moreBits(); err != nil {
			return 0, 0, err
		}

		if prev0 {
			// Previous count was 0, so there is a 2-bit
			// repeat flag. If the 2-bit flag is 0b11,
			// it adds 3 and then there is another repeat flag.
			zsym := sym
			for (br.bits & 0xfff) == 0xfff {
				zsym += 3 * 6
				br.bits >>= 12
				br.cnt -= 12
				if err := br.moreBits(); err != nil {
					return 0, 0, err
				}
			}
			for (br.bits & 3) == 3 {
				zsym += 3
				br.bits >>= 2
				br.cnt -= 2
				if err := br.moreBits(); err != nil {
					return 0, 0, err
				}
			}

			// We have at least 14 bits here,
			// no need to call moreBits

			zsym += int(br.val(2))

			if zsym > maxSym {
				return 0, 0, br.makeError("FSE symbol index overflow")
			}

			for ; sym < zsym; sym++ {
				norm[uint8(sym)] = 0
			}

			prev0 = false
			continue
		}

		max := (2*threshold - 1) - remaining
		var count int
		if int(br.bits&uint32(threshold-1)) < max {
			// A small value.
			count = int(br.bits & uint32((threshold - 1)))
			br.bits >>= bitsNeeded - 1
			br.cnt -= uint32(bitsNeeded - 1)
		} else {
			// A large value.
			count = int(br.bits & uint32((2*threshold - 1)))
			if count >= threshold {
				count -= max
			}
			br.bits >>= bitsNeeded
			br.cnt -= uint32(bitsNeeded)
		}

		count--
		if count >= 0 {
			remaining -= count
		} else {
			remaining--
		}
		if sym >= 256 {
			return 0, 0, br.makeError("FSE sym overflow")
		}
		norm[uint8(sym)] = int16(count)
		sym++

		prev0 = count == 0

		for remaining < threshold {
			bitsNeeded--
			threshold >>= 1
		}
	}

	if remaining != 1 {
		return 0, 0, br.makeError("too many symbols in FSE table")
	}

	for ; sym <= maxSym; sym++ {
		norm[uint8(sym)] = 0
	}

	br.backup()

	if err := r.buildFSE(off, norm[:maxSym+1], table, accuracyLog); err != nil {
		return 0, 0, err
	}

	return accuracyLog, int(br.off), nil
}

// buildFSE builds an FSE decoding table from a list of probabilities.
// The probabilities are in norm. next is scratch space. The number of bits
// in the table is tableBits.
func (r *Reader) buildFSE(off int, norm []int16, table []fseEntry, tableBits int) error {
	tableSize := 1 << tableBits
	highThreshold := tableSize - 1

	var next [256]uint16

	for i, n := range norm {
		if n >= 0 {
			next[uint8(i)] = uint16(n)
		} else {
			table[highThreshold].sym = uint8(i)
			highThreshold--
			next[uint8(i)] = 1
		}
	}

	pos := 0
	step := (tableSize >> 1) + (tableSize >> 3) + 3
	mask := tableSize - 1
	for i, n := range norm {
		for j := 0; j < int(n); j++ {
			table[pos].sym = uint8(i)
			pos = (pos + step) & mask
			for pos > highThreshold {
				pos = (pos + step) & mask
			}
		}
	}
	if pos != 0 {
		return r.makeError(off, "FSE count error")
	}

	for i := 0; i < tableSize; i++ {
		sym := table[i].sym
		nextState := next[sym]
		next[sym]++

		if nextState == 0 {
			return r.makeError(off, "FSE state error")
		}

		highBit := 15 - bits.LeadingZeros16(nextState)

		bits := tableBits - highBit
		table[i].bits = uint8(bits)
		table[i].base = (nextState << bits) - uint16(tableSize)
	}

	return nil
}

// fseBaselineEntry is an entry in an FSE baseline table.
// We use these for literal/match/length values.
// Those require mapping the symbol to a baseline value,
// and then reading zero or more bits and adding the value to the baseline.
// Rather than looking these up in separate tables,
// we convert the FSE table to an FSE baseline table.
type fseBaselineEntry struct {
	baseline uint32 // baseline for value that this entry represents
	basebits uint8  // number of bits to read to add to baseline
	bits     uint8  // number of bits to read to determine next state
	base     uint16 // add the bits to this base to get the next state
}

// Given a literal length code, we need to read a number of bits and
// add that to a baseline. For states 0 to 15 the baseline is the
// state and the number of bits is zero. RFC 3.1.1.3.2.1.1.

const literalLengthOffset = 16

var literalLengthBase = []uint32{
	16 | (1 << 24),
	18 | (1 << 24),
	20 | (1 << 24),
	22 | (1 << 24),
	24 | (2 << 24),
	28 | (2 << 24),
	32 | (3 << 24),
	40 | (3 << 24),
	48 | (4 << 24),
	64 | (6 << 24),
	128 | (7 << 24),
	256 | (8 << 24),
	512 | (9 << 24),
	1024 | (10 << 24),
	2048 | (11 << 24),
	4096 | (12 << 24),
	8192 | (13 << 24),
	16384 | (14 << 24),
	32768 | (15 << 24),
	65536 | (16 << 24),
}

// makeLiteralBaselineFSE converts the literal length fseTable to baselineTable.
func (r *Reader) makeLiteralBaselineFSE(off int, fseTable []fseEntry, baselineTable []fseBaselineEntry) error {
	for i, e := range fseTable {
		be := fseBaselineEntry{
			bits: e.bits,
			base: e.base,
		}
		if e.sym < literalLengthOffset {
			be.baseline = uint32(e.sym)
			be.basebits = 0
		} else {
			if e.sym > 35 {
				return r.makeError(off, "FSE baseline symbol overflow")
			}
			idx := e.sym - literalLengthOffset
			basebits := literalLengthBase[idx]
			be.baseline = basebits & 0xffffff
			be.basebits = uint8(basebits >> 24)
		}
		baselineTable[i] = be
	}
	return nil
}

// makeOffsetBaselineFSE converts the offset length fseTable to baselineTable.
func (r *Reader) makeOffsetBaselineFSE(off int, fseTable []fseEntry, baselineTable []fseBaselineEntry) error {
	for i, e := range fseTable {
		be := fseBaselineEntry{
			bits: e.bits,
			base: e.base,
		}
		if e.sym > 31 {
			return r.makeError(off, "FSE offset symbol overflow")
		}

		// The simple way to write this is
		//     be.baseline = 1 << e.sym
		//     be.basebits = e.sym
		// That would give us an offset value that corresponds to
		// the one described in the RFC. However, for offsets > 3
		// we have to subtract 3. And for offset values 1, 2, 3
		// we use a repeated offset.
		//
		// The baseline is always a power of 2, and is never 0,
		// so for those low values we will see one entry that is
		// baseline 1, basebits 0, and one entry that is baseline 2,
		// basebits 1. All other entries will have baseline >= 4
		// basebits >= 2.
		//
		// So we can check for RFC offset <= 3 by checking for
		// basebits <= 1. That means that we can subtract 3 here
		// and not worry about doing it in the hot loop.

		be.baseline = 1 << e.sym
		if e.sym >= 2 {
			be.baseline -= 3
		}
		be.basebits = e.sym
		baselineTable[i] = be
	}
	return nil
}

// Given a match length code, we need to read a number of bits and add
// that to a baseline. For states 0 to 31 the baseline is state+3 and
// the number of bits is zero. RFC 3.1.1.3.2.1.1.

const matchLengthOffset = 32

var matchLengthBase = []uint32{
	35 | (1 << 24),
	37 | (1 << 24),
	39 | (1 << 24),
	41 | (1 << 24),
	43 | (2 << 24),
	47 | (2 << 24),
	51 | (3 << 24),
	59 | (3 << 24),
	67 | (4 << 24),
	83 | (4 << 24),
	99 | (5 << 24),
	131 | (7 << 24),
	259 | (8 << 24),
	515 | (9 << 24),
	1027 | (10 << 24),
	2051 | (11 << 24),
	4099 | (12 << 24),
	8195 | (13 << 24),
	16387 | (14 << 24),
	32771 | (15 << 24),
	65539 | (16 << 24),
}

// makeMatchBaselineFSE converts the match length fseTable to baselineTable.
func (r *Reader) makeMatchBaselineFSE(off int, fseTable []fseEntry, baselineTable []fseBaselineEntry) error {
	for i, e := range fseTable {
		be := fseBaselineEntry{
			bits: e.bits,
			base: e.base,
		}
		if e.sym < matchLengthOffset {
			be.baseline = uint32(e.sym) + 3
			be.basebits = 0
		} else {
			if e.sym > 52 {
				return r.makeError(off, "FSE baseline symbol overflow")
			}
			idx := e.sym - matchLengthOffset
			basebits := matchLengthBase[idx]
			be.baseline = basebits & 0xffffff
			be.basebits = uint8(basebits >> 24)
		}
		baselineTable[i] = be
	}
	return nil
}

// predefinedLiteralTable is the predefined table to use for literal lengths.
// Generated from table in RFC 3.1.1.3.2.2.1.
// Checked by TestPredefinedTables.
var predefinedLiteralTable = [...]fseBaselineEntry{
	{0, 0, 4, 0}, {0, 0, 4, 16}, {1, 0, 5, 32},
	{3, 0, 5, 0}, {4, 0, 5, 0}, {6, 0, 5, 0},
	{7, 0, 5, 0}, {9, 0, 5, 0}, {10, 0, 5, 0},
	{12, 0, 5, 0}, {14, 0, 6, 0}, {16, 1, 5, 0},
	{20, 1, 5, 0}, {22, 1, 5, 0}, {28, 2, 5, 0},
	{32, 3, 5, 0}, {48, 4, 5, 0}, {64, 6, 5, 32},
	{128, 7, 5, 0}, {256, 8, 6, 0}, {1024, 10, 6, 0},
	{4096, 12, 6, 0}, {0, 0, 4, 32}, {1, 0, 4, 0},
	{2, 0, 5, 0}, {4, 0, 5, 32}, {5, 0, 5, 0},
	{7, 0, 5, 32}, {8, 0, 5, 0}, {10, 0, 5, 32},
	{11, 0, 5, 0}, {13, 0, 6, 0}, {16, 1, 5, 32},
	{18, 1, 5, 0}, {22, 1, 5, 32}, {24, 2, 5, 0},
	{32, 3, 5, 32}, {40, 3, 5, 0}, {64, 6, 4, 0},
	{64, 6, 4, 16}, {128, 7, 5, 32}, {512, 9, 6, 0},
	{2048, 11, 6, 0}, {0, 0, 4, 48}, {1, 0, 4, 16},
	{2, 0, 5, 32}, {3, 0, 5, 32}, {5, 0, 5, 32},
	{6, 0, 5, 32}, {8, 0, 5, 32}, {9, 0, 5, 32},
	{11, 0, 5, 32}, {12, 0, 5, 32}, {15, 0, 6, 0},
	{18, 1, 5, 32}, {20, 1, 5, 32}, {24, 2, 5, 32},
	{28, 2, 5, 32}, {40, 3, 5, 32}, {48, 4, 5, 32},
	{65536, 16, 6, 0}, {32768, 15, 6, 0}, {16384, 14, 6, 0},
	{8192, 13, 6, 0},
}

// predefinedOffsetTable is the predefined table to use for offsets.
// Generated from table in RFC 3.1.1.3.2.2.3.
// Checked by TestPredefinedTables.
var predefinedOffsetTable = [...]fseBaselineEntry{
	{1, 0, 5, 0}, {61, 6, 4, 0}, {509, 9, 5, 0},
	{32765, 15, 5, 0}, {2097149, 21, 5, 0}, {5, 3, 5, 0},
	{125, 7, 4, 0}, {4093, 12, 5, 0}, {262141, 18, 5, 0},
	{8388605, 23, 5, 0}, {29, 5, 5, 0}, {253, 8, 4, 0},
	{16381, 14, 5, 0}, {1048573, 20, 5, 0}, {1, 2, 5, 0},
	{125, 7, 4, 16}, {2045, 11, 5, 0}, {131069, 17, 5, 0},
	{4194301, 22, 5, 0}, {13, 4, 5, 0}, {253, 8, 4, 16},
	{8189, 13, 5, 0}, {524285, 19, 5, 0}, {2, 1, 5, 0},
	{61, 6, 4, 16}, {1021, 10, 5, 0}, {65533, 16, 5, 0},
	{268435453, 28, 5, 0}, {134217725, 27, 5, 0}, {67108861, 26, 5, 0},
	{33554429, 25, 5, 0}, {16777213, 24, 5, 0},
}

// predefinedMatchTable is the predefined table to use for match lengths.
// Generated from table in RFC 3.1.1.3.2.2.2.
// Checked by TestPredefinedTables.
var predefinedMatchTable = [...]fseBaselineEntry{
	{3, 0, 6, 0}, {4, 0, 4, 0}, {5, 0, 5, 32},
	{6, 0, 5, 0}, {8, 0, 5, 0}, {9, 0, 5, 0},
	{11, 0, 5, 0}, {13, 0, 6, 0}, {16, 0, 6, 0},
	{19, 0, 6, 0}, {22, 0, 6, 0}, {25, 0, 6, 0},
	{28, 0, 6, 0}, {31, 0, 6, 0}, {34, 0, 6, 0},
	{37, 1, 6, 0}, {41, 1, 6, 0}, {47, 2, 6, 0},
	{59, 3, 6, 0}, {83, 4, 6, 0}, {131, 7, 6, 0},
	{515, 9, 6, 0}, {4, 0, 4, 16}, {5, 0, 4, 0},
	{6, 0, 5, 32}, {7, 0, 5, 0}, {9, 0, 5, 32},
	{10, 0, 5, 0}, {12, 0, 6, 0}, {15, 0, 6, 0},
	{18, 0, 6, 0}, {21, 0, 6, 0}, {24, 0, 6, 0},
	{27, 0, 6, 0}, {30, 0, 6, 0}, {33, 0, 6, 0},
	{35, 1, 6, 0}, {39, 1, 6, 0}, {43, 2, 6, 0},
	{51, 3, 6, 0}, {67, 4, 6, 0}, {99, 5, 6, 0},
	{259, 8, 6, 0}, {4, 0, 4, 32}, {4, 0, 4, 48},
	{5, 0, 4, 16}, {7, 0, 5, 32}, {8, 0, 5, 32},
	{10, 0, 5, 32}, {11, 0, 5, 32}, {14, 0, 6, 0},
	{17, 0, 6, 0}, {20, 0, 6, 0}, {23, 0, 6, 0},
	{26, 0, 6, 0}, {29, 0, 6, 0}, {32, 0, 6, 0},
	{65539, 16, 6, 0}, {32771, 15, 6, 0}, {16387, 14, 6, 0},
	{8195, 13, 6, 0}, {4099, 12, 6, 0}, {2051, 11, 6, 0},
	{1027, 10, 6, 0},
}
```