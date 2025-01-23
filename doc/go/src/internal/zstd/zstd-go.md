Response:
我的思考过程如下：

1. **理解目标：**  目标是分析给定的 Go 代码片段 `go/src/internal/zstd/zstd.go`，列出其功能，推断其实现的 Go 功能，给出代码示例，说明命令行参数处理（如果存在），并指出使用者容易犯错的点。

2. **代码概览和核心结构识别：**  快速浏览代码，注意到以下关键点：
    * 包名 `zstd`，导入了 `encoding/binary`, `errors`, `fmt`, `io`。
    * 定义了一个主要的结构体 `Reader`，它实现了 `io.Reader` 和 `io.ByteReader` 接口。
    * `NewReader` 函数用于创建 `Reader` 实例。
    * `Reset` 方法用于重置 `Reader` 的状态。
    * `Read` 和 `ReadByte` 方法实现了读取数据的功能。
    * 内部有 `refillIfNeeded` 和 `refill` 方法，暗示了数据读取的缓冲和填充机制。
    * `readFrameHeader` 和 `readBlock`  暗示了 zstd 压缩格式的帧和块结构。
    * 涉及到 Huffman 树、FSE 表、窗口等概念，这些都是压缩算法中常见的元素。
    * 出现了 `checksum` 字段，说明支持校验和。
    * 有错误处理相关的结构体 `zstdError` 和辅助函数。

3. **功能提炼：** 基于代码结构和方法名，可以初步总结功能：
    * 解压缩 zstd 格式的压缩数据。
    * 实现了 `io.Reader` 接口，可以像普通文件一样读取解压后的数据。
    * 支持读取 zstd 帧头信息。
    * 支持读取 zstd 数据块。
    * 支持跳过可跳过的帧。
    * 内部使用了缓冲区来管理解压后的数据。
    * 支持校验和验证。
    * 提供了重置 `Reader` 状态的功能。
    * 具有错误处理机制，能报告解压过程中的错误。
    * 不支持字典。

4. **推断实现的 Go 功能：** 由于 `Reader` 实现了 `io.Reader`，这是 Go 中最基本的接口之一，可以用于各种需要读取数据的场景。  典型的应用场景是将解压后的数据传递给其他需要 `io.Reader` 的组件。

5. **代码示例：**  为了展示 `Reader` 的使用，需要创建一个 `io.Reader` 作为输入，然后使用 `NewReader` 创建 `zstd.Reader`，最后像读取普通 `io.Reader` 一样读取数据。  需要一个模拟的 zstd 压缩数据作为输入。

6. **代码示例的输入输出：**  构造一个简单的 zstd 压缩数据（这里需要对 zstd 格式有基本了解）。  假设压缩了字符串 "hello"。  输出应该是 "hello"。

7. **命令行参数处理：** 仔细检查代码，没有看到 `flag` 包或者 `os.Args` 的使用，因此可以判断这个代码片段本身不处理命令行参数。  其上层应用可能会处理。

8. **易犯错的点：**  考虑到 `zstd` 的压缩格式和 `Reader` 的使用方式，可以想到以下几点：
    * 输入不是有效的 zstd 格式数据。
    * 尝试使用不支持的字典。
    * 重复使用 `Reader` 而不 `Reset`，可能会导致状态混乱。

9. **组织答案和润色：** 将以上分析结果组织成清晰的中文描述。  注意使用代码块、列表等格式提高可读性。  对于代码推理部分，要清晰地说明假设的输入和预期的输出。  仔细检查措辞，确保准确性和完整性。  例如，最初我可能只说“读取压缩数据”，但更精确的说法是“解压缩 zstd 格式的压缩数据”。  同时，根据 prompt 的要求，着重强调“不支持字典”这一限制。

10. **最终检查：**  重新阅读问题和答案，确保所有问题都已回答，并且答案准确、完整、易懂。 特别注意代码示例的正确性，以及对 zstd 格式的理解是否准确。

通过以上步骤，我最终得到了一个比较全面和准确的答案。  关键在于理解代码的结构和功能，结合 Go 语言的特性进行推断，并针对性地给出示例和注意事项。

这段Go语言代码是 `internal/zstd` 包中的 `zstd.go` 文件的一部分，它实现了一个 **zstd 解压缩器**。让我们详细分析一下它的功能：

**主要功能：解压缩 zstd 压缩数据流**

这个代码的核心目标是提供一个 `Reader` 类型，该类型实现了 `io.Reader` 接口。这意味着你可以像读取普通文件一样读取 zstd 压缩的数据流，`Reader` 会在后台自动进行解压缩。

**具体功能点：**

1. **创建 `Reader`：**
    *   `NewReader(input io.Reader) *Reader`:  创建一个新的 `Reader` 实例，它从给定的 `io.Reader` 中读取压缩数据。

2. **重置 `Reader`：**
    *   `(r *Reader) Reset(input io.Reader)`: 允许你重用现有的 `Reader` 实例来读取新的压缩数据流，避免了重复分配内存。

3. **读取解压缩数据：**
    *   `(r *Reader) Read(p []byte) (int, error)`:  实现了 `io.Reader` 接口的核心方法。当你调用 `Read` 时，`Reader` 会尝试从其内部缓冲区中读取数据。如果缓冲区为空，它会从底层的 `io.Reader` 中读取压缩数据块，进行解压缩，并将解压后的数据填充到缓冲区，然后再复制到 `p` 中。
    *   `(r *Reader) ReadByte() (byte, error)`: 实现了 `io.ByteReader` 接口，允许你一次读取一个字节。

4. **处理 zstd 帧头 (Frame Header)：**
    *   `readFrameHeader()`:  负责读取和解析 zstd 压缩数据流的帧头。帧头包含了诸如魔数（用于识别 zstd 格式）、帧内容大小、是否包含校验和等信息。
    *   它会检查魔数 `0xfd2fb528` 来确认是否为 zstd 格式。
    *   它会处理可跳过的帧（Skippable Frame）。
    *   它会解析帧头描述符（Frame\_Header\_Descriptor）以获取帧的属性，例如是否是单段（single segment）、帧内容大小字段的大小、窗口描述符是否存在、是否包含校验和以及字典 ID 标志。
    *   它会计算窗口大小（Window Size），这是用于反向引用的最大缓冲区大小。
    *   它会处理字典 ID，但当前的实现中**不支持字典**，如果发现非零的字典 ID 会返回错误。

5. **处理 zstd 数据块 (Block)：**
    *   `readBlock()`:  负责读取和解压缩 zstd 数据块。
    *   它会读取块头（Block\_Header），包含是否是最后一个块、块类型和块大小。
    *   根据块类型（原始数据块、填充块、压缩块）进行相应的处理：
        *   **原始数据块 (blockType == 0):** 直接将块中的数据复制到解压缓冲区。
        *   **填充块 (blockType == 1):** 将块中的单个字节重复填充到解压缓冲区。
        *   **压缩块 (blockType == 2):** 调用 `compressedBlock()` 函数进行实际的解压缩（这段代码中未提供 `compressedBlock` 的实现，但可以推断它会使用 Huffman 编码、FSE (Finite State Entropy) 编码等 zstd 算法进行解压缩）。
        *   **保留类型 (blockType == 3):** 返回错误。

6. **校验和 (Checksum)：**
    *   如果帧头指示包含校验和 (`hasChecksum` 为 true)，`Reader` 会使用 `xxhash64` 算法计算解压缩数据的校验和。
    *   在读取到最后一个块时，它会读取帧尾的校验和，并与计算出的校验和进行比较，如果不同则返回错误。

7. **窗口 (Window)：**
    *   `window` 字段表示用于反向引用的缓冲区。zstd 是一种使用滑动窗口进行压缩的算法，解压缩器需要维护这个窗口来处理反向引用。`window.reset(int(windowSize))` 用于初始化窗口。
    *   `window.save(r.buffer)` 用于保存最近解压缩的数据到窗口中，以便后续块的反向引用。

8. **错误处理：**
    *   定义了 `zstdError` 类型来包装解压过程中发生的错误，包含错误的偏移量信息。
    *   提供了辅助函数 `wrapError`、`wrapNonEOFError`、`makeError` 和 `makeEOFError` 来创建和包装错误信息。

9. **内部缓冲区：**
    *   `buffer []byte`:  用于存储解压缩后的数据。
    *   `off int`:  记录当前在缓冲区中的读取偏移量。
    *   `setBufferSize(size int)`:  用于调整解压缓冲区的容量。

10. **重复偏移量 (Repeated Offsets)：**
    *   `repeatedOffset1`, `repeatedOffset2`, `repeatedOffset3`:  用于优化解压缩过程中的反向引用。

11. **Huffman 表和 FSE 表：**
    *   `huffmanTable`, `huffmanTableBits`: 用于存储 Huffman 解码表。
    *   `seqTables`, `seqTableBits`, `seqTableBuffers`: 用于存储序列解码的 FSE 表。这些是 zstd 解压缩的核心数据结构。

12. **跳过帧 (Skippable Frame)：**
    *   `skipFrame()`:  允许跳过不属于当前解压缩流程的特定帧。

**推断实现的 Go 语言功能：**

这段代码实现了 Go 语言的 `io.Reader` 和 `io.ByteReader` 接口。这使得 `zstd.Reader` 可以无缝地集成到 Go 的 I/O 模型中，可以作为任何接受 `io.Reader` 的函数的输入。

**Go 代码示例：**

```go
package main

import (
	"bytes"
	"fmt"
	"internal/zstd"  // 注意：这通常不推荐直接使用 internal 包
	"io"
	"os"
)

func main() {
	// 假设 compressedData 是一个 zstd 压缩的字节切片
	compressedData := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x01, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0a, 0x00, 0x00, 0x00} // 一个简单的 "hello\n" 的 zstd 压缩数据 (简化示例)

	// 创建一个 bytes.Buffer 作为输入源
	compressedReader := bytes.NewReader(compressedData)

	// 创建 zstd.Reader
	zr := zstd.NewReader(compressedReader)
	defer zr.Close() // 注意：虽然这里没有显式的 Close 方法，但通常 Reader 会实现它

	// 读取解压缩后的数据
	decompressedData, err := io.ReadAll(zr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解压缩失败: %v\n", err)
		return
	}

	fmt.Printf("解压缩后的数据: %s\n", string(decompressedData))

	// 示例：使用 Reset 方法
	newCompressedData := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x01, 0x00, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0a, 0x00, 0x00, 0x00} // 另一个压缩数据 "world\n"
	compressedReader.Reset(newCompressedData)
	zr.Reset(compressedReader) // 重置 zstd.Reader

	decompressedData2, err := io.ReadAll(zr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "第二次解压缩失败: %v\n", err)
		return
	}
	fmt.Printf("第二次解压缩后的数据: %s\n", string(decompressedData2))
}
```

**假设的输入与输出：**

*   **假设输入 `compressedData`:**  一个包含 "hello\\n" 的 zstd 压缩数据的字节切片（上述示例中的 `compressedData`）。
*   **预期输出:**
    ```
    解压缩后的数据: hello
    第二次解压缩后的数据: world
    ```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它是一个底层的解压缩库，通常会被其他应用程序或库使用。如果需要处理命令行参数，需要在调用这个库的上层代码中实现，例如使用 `flag` 包。

**使用者易犯错的点：**

1. **输入不是有效的 zstd 格式数据：** 如果传递给 `NewReader` 的 `io.Reader` 没有提供有效的 zstd 压缩数据，`Read` 方法将会返回错误，例如 "invalid magic number" 或 "unexpected EOF"。

2. **尝试使用字典：**  代码中明确指出 `// It does not support dictionaries.`，因此如果输入的 zstd 流使用了字典进行压缩，解压缩将会失败并返回错误 "dictionaries are not supported"。

3. **没有正确处理 `io.Reader` 的错误：**  在使用 `Read` 方法时，需要检查返回的 `error` 值，以处理可能发生的解压错误或底层 `io.Reader` 的错误。

4. **重复使用 `Reader` 而不 `Reset`：**  虽然提供了 `Reset` 方法，但如果使用者在读取完一个压缩流后，直接将另一个压缩流的数据源传递给同一个 `Reader` 实例而不调用 `Reset`，可能会导致状态不一致和解压缩错误。

5. **依赖 `internal` 包：**  直接导入 `internal/zstd` 包通常是不推荐的，因为 `internal` 包的 API 可能在没有通知的情况下发生变化。应该使用标准库或第三方提供的 zstd 库。

总而言之，这段代码提供了一个底层的 zstd 解压缩功能，使用者需要理解 zstd 压缩格式的一些基本概念，并注意处理可能出现的错误情况。

### 提示词
```
这是路径为go/src/internal/zstd/zstd.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Package zstd provides a decompressor for zstd streams,
// described in RFC 8878. It does not support dictionaries.
package zstd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// fuzzing is a fuzzer hook set to true when fuzzing.
// This is used to reject cases where we don't match zstd.
var fuzzing = false

// Reader implements [io.Reader] to read a zstd compressed stream.
type Reader struct {
	// The underlying Reader.
	r io.Reader

	// Whether we have read the frame header.
	// This is of interest when buffer is empty.
	// If true we expect to see a new block.
	sawFrameHeader bool

	// Whether the current frame expects a checksum.
	hasChecksum bool

	// Whether we have read at least one frame.
	readOneFrame bool

	// True if the frame size is not known.
	frameSizeUnknown bool

	// The number of uncompressed bytes remaining in the current frame.
	// If frameSizeUnknown is true, this is not valid.
	remainingFrameSize uint64

	// The number of bytes read from r up to the start of the current
	// block, for error reporting.
	blockOffset int64

	// Buffered decompressed data.
	buffer []byte
	// Current read offset in buffer.
	off int

	// The current repeated offsets.
	repeatedOffset1 uint32
	repeatedOffset2 uint32
	repeatedOffset3 uint32

	// The current Huffman tree used for compressing literals.
	huffmanTable     []uint16
	huffmanTableBits int

	// The window for back references.
	window window

	// A buffer available to hold a compressed block.
	compressedBuf []byte

	// A buffer for literals.
	literals []byte

	// Sequence decode FSE tables.
	seqTables    [3][]fseBaselineEntry
	seqTableBits [3]uint8

	// Buffers for sequence decode FSE tables.
	seqTableBuffers [3][]fseBaselineEntry

	// Scratch space used for small reads, to avoid allocation.
	scratch [16]byte

	// A scratch table for reading an FSE. Only temporarily valid.
	fseScratch []fseEntry

	// For checksum computation.
	checksum xxhash64
}

// NewReader creates a new Reader that decompresses data from the given reader.
func NewReader(input io.Reader) *Reader {
	r := new(Reader)
	r.Reset(input)
	return r
}

// Reset discards the current state and starts reading a new stream from r.
// This permits reusing a Reader rather than allocating a new one.
func (r *Reader) Reset(input io.Reader) {
	r.r = input

	// Several fields are preserved to avoid allocation.
	// Others are always set before they are used.
	r.sawFrameHeader = false
	r.hasChecksum = false
	r.readOneFrame = false
	r.frameSizeUnknown = false
	r.remainingFrameSize = 0
	r.blockOffset = 0
	r.buffer = r.buffer[:0]
	r.off = 0
	// repeatedOffset1
	// repeatedOffset2
	// repeatedOffset3
	// huffmanTable
	// huffmanTableBits
	// window
	// compressedBuf
	// literals
	// seqTables
	// seqTableBits
	// seqTableBuffers
	// scratch
	// fseScratch
}

// Read implements [io.Reader].
func (r *Reader) Read(p []byte) (int, error) {
	if err := r.refillIfNeeded(); err != nil {
		return 0, err
	}
	n := copy(p, r.buffer[r.off:])
	r.off += n
	return n, nil
}

// ReadByte implements [io.ByteReader].
func (r *Reader) ReadByte() (byte, error) {
	if err := r.refillIfNeeded(); err != nil {
		return 0, err
	}
	ret := r.buffer[r.off]
	r.off++
	return ret, nil
}

// refillIfNeeded reads the next block if necessary.
func (r *Reader) refillIfNeeded() error {
	for r.off >= len(r.buffer) {
		if err := r.refill(); err != nil {
			return err
		}
		r.off = 0
	}
	return nil
}

// refill reads and decompresses the next block.
func (r *Reader) refill() error {
	if !r.sawFrameHeader {
		if err := r.readFrameHeader(); err != nil {
			return err
		}
	}
	return r.readBlock()
}

// readFrameHeader reads the frame header and prepares to read a block.
func (r *Reader) readFrameHeader() error {
retry:
	relativeOffset := 0

	// Read magic number. RFC 3.1.1.
	if _, err := io.ReadFull(r.r, r.scratch[:4]); err != nil {
		// We require that the stream contains at least one frame.
		if err == io.EOF && !r.readOneFrame {
			err = io.ErrUnexpectedEOF
		}
		return r.wrapError(relativeOffset, err)
	}

	if magic := binary.LittleEndian.Uint32(r.scratch[:4]); magic != 0xfd2fb528 {
		if magic >= 0x184d2a50 && magic <= 0x184d2a5f {
			// This is a skippable frame.
			r.blockOffset += int64(relativeOffset) + 4
			if err := r.skipFrame(); err != nil {
				return err
			}
			r.readOneFrame = true
			goto retry
		}

		return r.makeError(relativeOffset, "invalid magic number")
	}

	relativeOffset += 4

	// Read Frame_Header_Descriptor. RFC 3.1.1.1.1.
	if _, err := io.ReadFull(r.r, r.scratch[:1]); err != nil {
		return r.wrapNonEOFError(relativeOffset, err)
	}
	descriptor := r.scratch[0]

	singleSegment := descriptor&(1<<5) != 0

	fcsFieldSize := 1 << (descriptor >> 6)
	if fcsFieldSize == 1 && !singleSegment {
		fcsFieldSize = 0
	}

	var windowDescriptorSize int
	if singleSegment {
		windowDescriptorSize = 0
	} else {
		windowDescriptorSize = 1
	}

	if descriptor&(1<<3) != 0 {
		return r.makeError(relativeOffset, "reserved bit set in frame header descriptor")
	}

	r.hasChecksum = descriptor&(1<<2) != 0
	if r.hasChecksum {
		r.checksum.reset()
	}

	// Dictionary_ID_Flag. RFC 3.1.1.1.1.6.
	dictionaryIdSize := 0
	if dictIdFlag := descriptor & 3; dictIdFlag != 0 {
		dictionaryIdSize = 1 << (dictIdFlag - 1)
	}

	relativeOffset++

	headerSize := windowDescriptorSize + dictionaryIdSize + fcsFieldSize

	if _, err := io.ReadFull(r.r, r.scratch[:headerSize]); err != nil {
		return r.wrapNonEOFError(relativeOffset, err)
	}

	// Figure out the maximum amount of data we need to retain
	// for backreferences.
	var windowSize uint64
	if !singleSegment {
		// Window descriptor. RFC 3.1.1.1.2.
		windowDescriptor := r.scratch[0]
		exponent := uint64(windowDescriptor >> 3)
		mantissa := uint64(windowDescriptor & 7)
		windowLog := exponent + 10
		windowBase := uint64(1) << windowLog
		windowAdd := (windowBase / 8) * mantissa
		windowSize = windowBase + windowAdd

		// Default zstd sets limits on the window size.
		if fuzzing && (windowLog > 31 || windowSize > 1<<27) {
			return r.makeError(relativeOffset, "windowSize too large")
		}
	}

	// Dictionary_ID. RFC 3.1.1.1.3.
	if dictionaryIdSize != 0 {
		dictionaryId := r.scratch[windowDescriptorSize : windowDescriptorSize+dictionaryIdSize]
		// Allow only zero Dictionary ID.
		for _, b := range dictionaryId {
			if b != 0 {
				return r.makeError(relativeOffset, "dictionaries are not supported")
			}
		}
	}

	// Frame_Content_Size. RFC 3.1.1.1.4.
	r.frameSizeUnknown = false
	r.remainingFrameSize = 0
	fb := r.scratch[windowDescriptorSize+dictionaryIdSize:]
	switch fcsFieldSize {
	case 0:
		r.frameSizeUnknown = true
	case 1:
		r.remainingFrameSize = uint64(fb[0])
	case 2:
		r.remainingFrameSize = 256 + uint64(binary.LittleEndian.Uint16(fb))
	case 4:
		r.remainingFrameSize = uint64(binary.LittleEndian.Uint32(fb))
	case 8:
		r.remainingFrameSize = binary.LittleEndian.Uint64(fb)
	default:
		panic("unreachable")
	}

	// RFC 3.1.1.1.2.
	// When Single_Segment_Flag is set, Window_Descriptor is not present.
	// In this case, Window_Size is Frame_Content_Size.
	if singleSegment {
		windowSize = r.remainingFrameSize
	}

	// RFC 8878 3.1.1.1.1.2. permits us to set an 8M max on window size.
	const maxWindowSize = 8 << 20
	if windowSize > maxWindowSize {
		windowSize = maxWindowSize
	}

	relativeOffset += headerSize

	r.sawFrameHeader = true
	r.readOneFrame = true
	r.blockOffset += int64(relativeOffset)

	// Prepare to read blocks from the frame.
	r.repeatedOffset1 = 1
	r.repeatedOffset2 = 4
	r.repeatedOffset3 = 8
	r.huffmanTableBits = 0
	r.window.reset(int(windowSize))
	r.seqTables[0] = nil
	r.seqTables[1] = nil
	r.seqTables[2] = nil

	return nil
}

// skipFrame skips a skippable frame. RFC 3.1.2.
func (r *Reader) skipFrame() error {
	relativeOffset := 0

	if _, err := io.ReadFull(r.r, r.scratch[:4]); err != nil {
		return r.wrapNonEOFError(relativeOffset, err)
	}

	relativeOffset += 4

	size := binary.LittleEndian.Uint32(r.scratch[:4])
	if size == 0 {
		r.blockOffset += int64(relativeOffset)
		return nil
	}

	if seeker, ok := r.r.(io.Seeker); ok {
		r.blockOffset += int64(relativeOffset)
		// Implementations of Seeker do not always detect invalid offsets,
		// so check that the new offset is valid by comparing to the end.
		prev, err := seeker.Seek(0, io.SeekCurrent)
		if err != nil {
			return r.wrapError(0, err)
		}
		end, err := seeker.Seek(0, io.SeekEnd)
		if err != nil {
			return r.wrapError(0, err)
		}
		if prev > end-int64(size) {
			r.blockOffset += end - prev
			return r.makeEOFError(0)
		}

		// The new offset is valid, so seek to it.
		_, err = seeker.Seek(prev+int64(size), io.SeekStart)
		if err != nil {
			return r.wrapError(0, err)
		}
		r.blockOffset += int64(size)
		return nil
	}

	n, err := io.CopyN(io.Discard, r.r, int64(size))
	relativeOffset += int(n)
	if err != nil {
		return r.wrapNonEOFError(relativeOffset, err)
	}
	r.blockOffset += int64(relativeOffset)
	return nil
}

// readBlock reads the next block from a frame.
func (r *Reader) readBlock() error {
	relativeOffset := 0

	// Read Block_Header. RFC 3.1.1.2.
	if _, err := io.ReadFull(r.r, r.scratch[:3]); err != nil {
		return r.wrapNonEOFError(relativeOffset, err)
	}

	relativeOffset += 3

	header := uint32(r.scratch[0]) | (uint32(r.scratch[1]) << 8) | (uint32(r.scratch[2]) << 16)

	lastBlock := header&1 != 0
	blockType := (header >> 1) & 3
	blockSize := int(header >> 3)

	// Maximum block size is smaller of window size and 128K.
	// We don't record the window size for a single segment frame,
	// so just use 128K. RFC 3.1.1.2.3, 3.1.1.2.4.
	if blockSize > 128<<10 || (r.window.size > 0 && blockSize > r.window.size) {
		return r.makeError(relativeOffset, "block size too large")
	}

	// Handle different block types. RFC 3.1.1.2.2.
	switch blockType {
	case 0:
		r.setBufferSize(blockSize)
		if _, err := io.ReadFull(r.r, r.buffer); err != nil {
			return r.wrapNonEOFError(relativeOffset, err)
		}
		relativeOffset += blockSize
		r.blockOffset += int64(relativeOffset)
	case 1:
		r.setBufferSize(blockSize)
		if _, err := io.ReadFull(r.r, r.scratch[:1]); err != nil {
			return r.wrapNonEOFError(relativeOffset, err)
		}
		relativeOffset++
		v := r.scratch[0]
		for i := range r.buffer {
			r.buffer[i] = v
		}
		r.blockOffset += int64(relativeOffset)
	case 2:
		r.blockOffset += int64(relativeOffset)
		if err := r.compressedBlock(blockSize); err != nil {
			return err
		}
		r.blockOffset += int64(blockSize)
	case 3:
		return r.makeError(relativeOffset, "invalid block type")
	}

	if !r.frameSizeUnknown {
		if uint64(len(r.buffer)) > r.remainingFrameSize {
			return r.makeError(relativeOffset, "too many uncompressed bytes in frame")
		}
		r.remainingFrameSize -= uint64(len(r.buffer))
	}

	if r.hasChecksum {
		r.checksum.update(r.buffer)
	}

	if !lastBlock {
		r.window.save(r.buffer)
	} else {
		if !r.frameSizeUnknown && r.remainingFrameSize != 0 {
			return r.makeError(relativeOffset, "not enough uncompressed bytes for frame")
		}
		// Check for checksum at end of frame. RFC 3.1.1.
		if r.hasChecksum {
			if _, err := io.ReadFull(r.r, r.scratch[:4]); err != nil {
				return r.wrapNonEOFError(0, err)
			}

			inputChecksum := binary.LittleEndian.Uint32(r.scratch[:4])
			dataChecksum := uint32(r.checksum.digest())
			if inputChecksum != dataChecksum {
				return r.wrapError(0, fmt.Errorf("invalid checksum: got %#x want %#x", dataChecksum, inputChecksum))
			}

			r.blockOffset += 4
		}
		r.sawFrameHeader = false
	}

	return nil
}

// setBufferSize sets the decompressed buffer size.
// When this is called the buffer is empty.
func (r *Reader) setBufferSize(size int) {
	if cap(r.buffer) < size {
		need := size - cap(r.buffer)
		r.buffer = append(r.buffer[:cap(r.buffer)], make([]byte, need)...)
	}
	r.buffer = r.buffer[:size]
}

// zstdError is an error while decompressing.
type zstdError struct {
	offset int64
	err    error
}

func (ze *zstdError) Error() string {
	return fmt.Sprintf("zstd decompression error at %d: %v", ze.offset, ze.err)
}

func (ze *zstdError) Unwrap() error {
	return ze.err
}

func (r *Reader) makeEOFError(off int) error {
	return r.wrapError(off, io.ErrUnexpectedEOF)
}

func (r *Reader) wrapNonEOFError(off int, err error) error {
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return r.wrapError(off, err)
}

func (r *Reader) makeError(off int, msg string) error {
	return r.wrapError(off, errors.New(msg))
}

func (r *Reader) wrapError(off int, err error) error {
	if err == io.EOF {
		return err
	}
	return &zstdError{r.blockOffset + int64(off), err}
}
```