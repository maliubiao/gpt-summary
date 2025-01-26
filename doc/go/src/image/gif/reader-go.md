Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a functional summary, identification of Go features used, example code, handling of command-line arguments (if any), and potential pitfalls for users. The core is about understanding the `go/src/image/gif/reader.go` file.

2. **Initial Scan for Key Information:** Quickly read through the comments at the beginning. "Package gif implements a GIF image decoder and encoder."  This is the most crucial piece of information. The provided snippet is *part* of the GIF decoding logic.

3. **Identify Core Structures and Functions:** Look for type definitions and function declarations. The `decoder` struct is central. It holds state during the decoding process. Functions like `decode`, `readHeaderAndScreenDescriptor`, `readColorTable`, `readExtension`, `readImageDescriptor`, `readBlock`, `uninterlace` stand out as important steps in the decoding process.

4. **Trace the Decoding Process (High Level):**  The `decode` function seems to be the main entry point. It reads different "blocks" (identified by constants like `sExtension`, `sImageDescriptor`, `sTrailer`). This suggests a state machine or a sequence of steps based on the encountered block type.

5. **Examine Individual Functions:**
    * **`readHeaderAndScreenDescriptor`:** Reads the initial bytes defining the GIF version, dimensions, and global color table.
    * **`readColorTable`:** Extracts the color palette data.
    * **`readExtension`:** Handles different extension blocks (like animation loops or comments).
    * **`readGraphicControl`:**  Parses information about frame delays and transparency.
    * **`readImageDescriptor`:**  Gets details about an individual image frame (position, size, local color table).
    * **`readBlock`:** Reads data blocks with a preceding length byte. This is a fundamental part of the GIF format.
    * **`blockReader`:** A custom reader designed to handle the block structure and feed data to the LZW decoder. This is a clever optimization to avoid extra buffering.
    * **`uninterlace`:** Rearranges pixels for interlaced GIFs.

6. **Identify Go Features:**  As you analyze the functions, note the Go features being used:
    * **Structs:**  `decoder`, `blockReader`, `GIF`, `interlaceScan`.
    * **Interfaces:** `io.Reader`, `io.ByteReader`, the custom `reader` interface.
    * **Constants:**  Named constants for block types, flags, etc. (`sExtension`, `fColorTable`).
    * **Error Handling:** `errors.New`, returning `error` from functions.
    * **Slices:** Used for `d.tmp`, `d.image`, `d.delay`, `d.disposal`, `m.Pix`.
    * **Maps (indirectly through `color.Palette`):**  The color table is essentially a map of indices to colors.
    * **`bufio`:** Used for buffering input if the reader doesn't support `ReadByte`.
    * **`compress/lzw`:**  The core LZW decompression logic.
    * **`image` package:**  Using `image.Image`, `image.Paletted`, `image.Config`, `image.Rect`, `image.Point`, `color.RGBA`, `color.Palette`, and `image.RegisterFormat`.
    * **`fmt` package:** For formatted error messages.

7. **Infer Overall Functionality:** Based on the identified components, it's clear this code implements the *decoding* of GIF image files. It parses the file structure, extracts frame data, handles extensions, and performs LZW decompression.

8. **Construct Example Code:**  Think about how this decoder would be used. The `image` package's `Decode` function is the obvious entry point. You'd need an `io.Reader` for the GIF data. A simple example would involve reading a GIF file from disk.

9. **Consider Command-Line Arguments:**  The provided code doesn't directly handle command-line arguments. The standard library's `flag` package would be used for that, but it's not present here. So, the answer is that this specific code doesn't deal with command-line arguments.

10. **Identify Potential Pitfalls:** Think about common errors when working with image formats:
    * **Invalid GIF files:** The decoder handles this with error messages.
    * **Large GIFs:**  Memory consumption could be an issue, but this snippet doesn't show specific memory management strategies.
    * **Interlacing:**  Users might not realize their GIFs are interlaced, but the decoder handles this automatically.
    * **Animation loops:**  Understanding how `LoopCount` works might be a point of confusion.
    * **Transparency:**  The interaction of transparency with disposal methods could be tricky. The code shows it handles transparency indices and palette adjustments.

11. **Structure the Answer:** Organize the findings into the categories requested by the prompt: functionality, Go features, example, command-line arguments, and potential pitfalls. Use clear and concise language. Provide code snippets and explanations.

12. **Review and Refine:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or missing information. For instance, initially, I might have overlooked the significance of `blockReader` and its role in handling the block structure for the LZW decoder. A review would help catch this. Similarly, clarifying the distinction between `Decode` and `DecodeAll` is important.
这段 `go/src/image/gif/reader.go` 文件是 Go 语言 `image/gif` 标准库中用于 **解码 GIF 图像** 的一部分实现。  它主要负责将 GIF 文件的二进制数据解析成 Go 语言可以理解的图像数据结构。

以下是它的主要功能点：

1. **读取 GIF 文件头 (Header) 和逻辑屏幕描述符 (Logical Screen Descriptor)：**  解析 GIF 文件的起始部分，获取 GIF 的版本信息（GIF87a 或 GIF89a），图像的宽度和高度，以及是否存在全局颜色表等信息。

2. **读取全局颜色表 (Global Color Table)：** 如果文件头中指示存在全局颜色表，则读取该表。全局颜色表定义了图像中使用的颜色索引与实际颜色的映射关系。

3. **处理扩展块 (Extension Blocks)：** GIF 文件中可以包含各种扩展块，这段代码能够处理以下几种常见的扩展块：
    * **图形控制扩展 (Graphic Control Extension)：**  包含有关如何渲染后续图像帧的信息，例如帧之间的延迟时间、处置方法（如何处理上一帧）、是否设置透明色等。
    * **注释扩展 (Comment Extension)：**  读取 GIF 文件中的注释信息。
    * **应用程序扩展 (Application Extension)：**  允许应用程序特定的数据嵌入到 GIF 文件中。这段代码特别处理了 "NETSCAPE2.0" 应用程序扩展，用于获取 GIF 动画的循环次数。
    * **纯文本扩展 (Plain Text Extension)：** 读取 GIF 文件中的纯文本信息（虽然现代 GIF 很少使用）。

4. **读取图像描述符 (Image Descriptor)：**  解析每个图像帧的信息，包括帧在逻辑屏幕中的位置 (left, top)、宽度和高度，以及是否存在局部颜色表等。

5. **读取局部颜色表 (Local Color Table)：** 如果图像描述符指示存在局部颜色表，则读取该表。局部颜色表只应用于当前的图像帧。

6. **读取图像数据 (Image Data)：**  这是解码的核心部分。它使用 **LZW (Lempel-Ziv-Welch) 算法** 解压缩图像像素数据。
    * **`blockReader`:**  自定义的 `io.Reader` 实现，用于处理 GIF 数据的块结构。GIF 图像数据被分成多个长度不超过 255 字节的子块，`blockReader` 负责将这些子块拼接起来，提供给 LZW 解码器。
    * **`lzw.NewReader`:**  使用 Go 标准库 `compress/lzw` 包提供的 LZW 解码器。

7. **处理隔行扫描 (Interlacing)：**  如果图像描述符中指示图像是隔行扫描的，则调用 `uninterlace` 函数重新排列像素，恢复原始的扫描线顺序。

8. **存储解码后的图像信息：** 将解码后的图像数据（像素颜色索引）、延迟时间、处置方法等信息存储在 `decoder` 结构体中。

9. **提供解码 API：**  最终通过 `Decode` 和 `DecodeAll` 函数向用户提供解码 GIF 图像的能力。
    * `Decode`: 解码 GIF 文件的第一个图像帧。
    * `DecodeAll`: 解码 GIF 文件的所有图像帧，以及相关的动画信息（延迟时间、循环次数等）。
    * `DecodeConfig`:  只读取 GIF 文件的配置信息（全局颜色表、宽度、高度），不解码实际的图像数据。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 **GIF 图像的解码功能**。  它可以将符合 GIF 87a 和 GIF 89a 规范的图像文件转换成 Go 语言的 `image.Image` 类型，特别是 `image.Paletted` 类型（对于索引颜色图像）。

**Go 代码举例说明：**

假设我们有一个名为 `animated.gif` 的 GIF 动画文件。以下是如何使用这段代码进行解码的示例：

```go
package main

import (
	"fmt"
	"image"
	"image/gif"
	"os"
)

func main() {
	f, err := os.Open("animated.gif")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	// 解码 GIF 文件的所有帧和动画信息
	g, err := gif.DecodeAll(f)
	if err != nil {
		fmt.Println("Error decoding GIF:", err)
		return
	}

	fmt.Printf("GIF has %d frames\n", len(g.Image))
	fmt.Printf("Loop count: %d\n", g.LoopCount)

	for i, img := range g.Image {
		fmt.Printf("Frame %d: Delay = %d (1/100 秒), Disposal = %d\n", i, g.Delay[i], g.Disposal[i])
		// 可以进一步处理每个图像帧 (img)
		_ = img // 使用 img 避免编译错误
	}

	// 如果只想解码第一帧
	f.Seek(0, 0) // 将文件指针重置到开头
	firstFrame, err := gif.Decode(f)
	if err != nil {
		fmt.Println("Error decoding first frame:", err)
		return
	}
	fmt.Printf("First frame dimensions: %dx%d\n", firstFrame.Bounds().Dx(), firstFrame.Bounds().Dy())
}
```

**假设的输入与输出：**

**输入:** 一个名为 `animated.gif` 的 GIF 动画文件，包含 3 帧，循环播放 2 次，每帧延迟 10 个 1/100 秒。

**输出:**  运行上述代码的输出可能如下：

```
GIF has 3 frames
Loop count: 0
Frame 0: Delay = 10 (1/100 秒), Disposal = 0
Frame 1: Delay = 10 (1/100 秒), Disposal = 0
Frame 2: Delay = 10 (1/100 秒), Disposal = 0
First frame dimensions: 100x50
```

**注意：** `Loop count: 0` 表示无限循环，因为代码中 `d.loopCount` 被初始化为 `-1`，而 `DecodeAll` 会根据 NETSCAPE 扩展将其转换为 `0` 表示无限循环。

**命令行参数的具体处理：**

这段代码本身 **不涉及** 命令行参数的处理。它只是 GIF 解码逻辑的实现。如果需要通过命令行指定 GIF 文件路径等参数，需要在调用此代码的程序中进行处理，例如使用 Go 的 `flag` 包。

**使用者易犯错的点：**

1. **未正确处理错误：** 在调用 `gif.Decode` 或 `gif.DecodeAll` 时，如果没有检查返回的 `error`，可能会导致程序在遇到无效 GIF 文件时崩溃或产生不可预测的行为。

   ```go
   // 错误示例
   img, _ := gif.Decode(file) // 忽略了错误

   // 正确示例
   img, err := gif.Decode(file)
   if err != nil {
       fmt.Println("解码失败:", err)
       // 进行错误处理，例如退出程序或返回错误
   }
   ```

2. **假设所有 GIF 都是静态图像：** 有些使用者可能只调用 `gif.Decode` 来处理 GIF 文件，而忽略了动画 GIF 的多帧特性。如果需要处理动画，应该使用 `gif.DecodeAll`。

3. **不理解延迟时间和处置方法：**  动画 GIF 的行为受到每帧的延迟时间和处置方法的影响。不理解这些概念可能会导致在自定义 GIF 播放器或编辑器中出现显示问题。例如， `DisposalBackground` 方法会让当前帧的背景色填充上一帧的区域，而 `DisposalPrevious` 方法则会将画布恢复到上一帧的状态。

4. **忘记关闭文件：**  在打开 GIF 文件后，务必使用 `defer file.Close()` 来确保文件资源被及时释放，防止资源泄露。

5. **直接操作 `image.Paletted` 的 `Pix` 数据：**  虽然可以访问 `image.Paletted` 的 `Pix` 字段来获取像素索引，但直接修改它可能会导致与图像的 `Palette` 不一致，从而产生错误的颜色显示。 应该通过安全的方式操作图像数据，例如创建新的图像或使用图像处理相关的库。

总而言之，`go/src/image/gif/reader.go` 是 Go 语言 GIF 解码功能的核心实现，它负责将 GIF 文件的二进制数据转换为 Go 语言可以操作的图像数据结构，并提供了方便的 API 供用户使用。理解其内部工作原理有助于更有效地使用和调试与 GIF 相关的 Go 程序。

Prompt: 
```
这是路径为go/src/image/gif/reader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gif implements a GIF image decoder and encoder.
//
// The GIF specification is at https://www.w3.org/Graphics/GIF/spec-gif89a.txt.
package gif

import (
	"bufio"
	"compress/lzw"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
)

var (
	errNotEnough = errors.New("gif: not enough image data")
	errTooMuch   = errors.New("gif: too much image data")
	errBadPixel  = errors.New("gif: invalid pixel value")
)

// If the io.Reader does not also have ReadByte, then decode will introduce its own buffering.
type reader interface {
	io.Reader
	io.ByteReader
}

// Masks etc.
const (
	// Fields.
	fColorTable         = 1 << 7
	fInterlace          = 1 << 6
	fColorTableBitsMask = 7

	// Graphic control flags.
	gcTransparentColorSet = 1 << 0
	gcDisposalMethodMask  = 7 << 2
)

// Disposal Methods.
const (
	DisposalNone       = 0x01
	DisposalBackground = 0x02
	DisposalPrevious   = 0x03
)

// Section indicators.
const (
	sExtension       = 0x21
	sImageDescriptor = 0x2C
	sTrailer         = 0x3B
)

// Extensions.
const (
	eText           = 0x01 // Plain Text
	eGraphicControl = 0xF9 // Graphic Control
	eComment        = 0xFE // Comment
	eApplication    = 0xFF // Application
)

func readFull(r io.Reader, b []byte) error {
	_, err := io.ReadFull(r, b)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func readByte(r io.ByteReader) (byte, error) {
	b, err := r.ReadByte()
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return b, err
}

// decoder is the type used to decode a GIF file.
type decoder struct {
	r reader

	// From header.
	vers            string
	width           int
	height          int
	loopCount       int
	delayTime       int
	backgroundIndex byte
	disposalMethod  byte

	// From image descriptor.
	imageFields byte

	// From graphics control.
	transparentIndex    byte
	hasTransparentIndex bool

	// Computed.
	globalColorTable color.Palette

	// Used when decoding.
	delay    []int
	disposal []byte
	image    []*image.Paletted
	tmp      [1024]byte // must be at least 768 so we can read color table
}

// blockReader parses the block structure of GIF image data, which comprises
// (n, (n bytes)) blocks, with 1 <= n <= 255. It is the reader given to the
// LZW decoder, which is thus immune to the blocking. After the LZW decoder
// completes, there will be a 0-byte block remaining (0, ()), which is
// consumed when checking that the blockReader is exhausted.
//
// To avoid the allocation of a bufio.Reader for the lzw Reader, blockReader
// implements io.ByteReader and buffers blocks into the decoder's "tmp" buffer.
type blockReader struct {
	d    *decoder
	i, j uint8 // d.tmp[i:j] contains the buffered bytes
	err  error
}

func (b *blockReader) fill() {
	if b.err != nil {
		return
	}
	b.j, b.err = readByte(b.d.r)
	if b.j == 0 && b.err == nil {
		b.err = io.EOF
	}
	if b.err != nil {
		return
	}

	b.i = 0
	b.err = readFull(b.d.r, b.d.tmp[:b.j])
	if b.err != nil {
		b.j = 0
	}
}

func (b *blockReader) ReadByte() (byte, error) {
	if b.i == b.j {
		b.fill()
		if b.err != nil {
			return 0, b.err
		}
	}

	c := b.d.tmp[b.i]
	b.i++
	return c, nil
}

// blockReader must implement io.Reader, but its Read shouldn't ever actually
// be called in practice. The compress/lzw package will only call [blockReader.ReadByte].
func (b *blockReader) Read(p []byte) (int, error) {
	if len(p) == 0 || b.err != nil {
		return 0, b.err
	}
	if b.i == b.j {
		b.fill()
		if b.err != nil {
			return 0, b.err
		}
	}

	n := copy(p, b.d.tmp[b.i:b.j])
	b.i += uint8(n)
	return n, nil
}

// close primarily detects whether or not a block terminator was encountered
// after reading a sequence of data sub-blocks. It allows at most one trailing
// sub-block worth of data. I.e., if some number of bytes exist in one sub-block
// following the end of LZW data, the very next sub-block must be the block
// terminator. If the very end of LZW data happened to fill one sub-block, at
// most one more sub-block of length 1 may exist before the block-terminator.
// These accommodations allow us to support GIFs created by less strict encoders.
// See https://golang.org/issue/16146.
func (b *blockReader) close() error {
	if b.err == io.EOF {
		// A clean block-sequence terminator was encountered while reading.
		return nil
	} else if b.err != nil {
		// Some other error was encountered while reading.
		return b.err
	}

	if b.i == b.j {
		// We reached the end of a sub block reading LZW data. We'll allow at
		// most one more sub block of data with a length of 1 byte.
		b.fill()
		if b.err == io.EOF {
			return nil
		} else if b.err != nil {
			return b.err
		} else if b.j > 1 {
			return errTooMuch
		}
	}

	// Part of a sub-block remains buffered. We expect that the next attempt to
	// buffer a sub-block will reach the block terminator.
	b.fill()
	if b.err == io.EOF {
		return nil
	} else if b.err != nil {
		return b.err
	}

	return errTooMuch
}

// decode reads a GIF image from r and stores the result in d.
func (d *decoder) decode(r io.Reader, configOnly, keepAllFrames bool) error {
	// Add buffering if r does not provide ReadByte.
	if rr, ok := r.(reader); ok {
		d.r = rr
	} else {
		d.r = bufio.NewReader(r)
	}

	d.loopCount = -1

	err := d.readHeaderAndScreenDescriptor()
	if err != nil {
		return err
	}
	if configOnly {
		return nil
	}

	for {
		c, err := readByte(d.r)
		if err != nil {
			return fmt.Errorf("gif: reading frames: %v", err)
		}
		switch c {
		case sExtension:
			if err = d.readExtension(); err != nil {
				return err
			}

		case sImageDescriptor:
			if err = d.readImageDescriptor(keepAllFrames); err != nil {
				return err
			}

			if !keepAllFrames && len(d.image) == 1 {
				return nil
			}

		case sTrailer:
			if len(d.image) == 0 {
				return fmt.Errorf("gif: missing image data")
			}
			return nil

		default:
			return fmt.Errorf("gif: unknown block type: 0x%.2x", c)
		}
	}
}

func (d *decoder) readHeaderAndScreenDescriptor() error {
	err := readFull(d.r, d.tmp[:13])
	if err != nil {
		return fmt.Errorf("gif: reading header: %v", err)
	}
	d.vers = string(d.tmp[:6])
	if d.vers != "GIF87a" && d.vers != "GIF89a" {
		return fmt.Errorf("gif: can't recognize format %q", d.vers)
	}
	d.width = int(d.tmp[6]) + int(d.tmp[7])<<8
	d.height = int(d.tmp[8]) + int(d.tmp[9])<<8
	if fields := d.tmp[10]; fields&fColorTable != 0 {
		d.backgroundIndex = d.tmp[11]
		// readColorTable overwrites the contents of d.tmp, but that's OK.
		if d.globalColorTable, err = d.readColorTable(fields); err != nil {
			return err
		}
	}
	// d.tmp[12] is the Pixel Aspect Ratio, which is ignored.
	return nil
}

func (d *decoder) readColorTable(fields byte) (color.Palette, error) {
	n := 1 << (1 + uint(fields&fColorTableBitsMask))
	err := readFull(d.r, d.tmp[:3*n])
	if err != nil {
		return nil, fmt.Errorf("gif: reading color table: %s", err)
	}
	j, p := 0, make(color.Palette, n)
	for i := range p {
		p[i] = color.RGBA{d.tmp[j+0], d.tmp[j+1], d.tmp[j+2], 0xFF}
		j += 3
	}
	return p, nil
}

func (d *decoder) readExtension() error {
	extension, err := readByte(d.r)
	if err != nil {
		return fmt.Errorf("gif: reading extension: %v", err)
	}
	size := 0
	switch extension {
	case eText:
		size = 13
	case eGraphicControl:
		return d.readGraphicControl()
	case eComment:
		// nothing to do but read the data.
	case eApplication:
		b, err := readByte(d.r)
		if err != nil {
			return fmt.Errorf("gif: reading extension: %v", err)
		}
		// The spec requires size be 11, but Adobe sometimes uses 10.
		size = int(b)
	default:
		return fmt.Errorf("gif: unknown extension 0x%.2x", extension)
	}
	if size > 0 {
		if err := readFull(d.r, d.tmp[:size]); err != nil {
			return fmt.Errorf("gif: reading extension: %v", err)
		}
	}

	// Application Extension with "NETSCAPE2.0" as string and 1 in data means
	// this extension defines a loop count.
	if extension == eApplication && string(d.tmp[:size]) == "NETSCAPE2.0" {
		n, err := d.readBlock()
		if err != nil {
			return fmt.Errorf("gif: reading extension: %v", err)
		}
		if n == 0 {
			return nil
		}
		if n == 3 && d.tmp[0] == 1 {
			d.loopCount = int(d.tmp[1]) | int(d.tmp[2])<<8
		}
	}
	for {
		n, err := d.readBlock()
		if err != nil {
			return fmt.Errorf("gif: reading extension: %v", err)
		}
		if n == 0 {
			return nil
		}
	}
}

func (d *decoder) readGraphicControl() error {
	if err := readFull(d.r, d.tmp[:6]); err != nil {
		return fmt.Errorf("gif: can't read graphic control: %s", err)
	}
	if d.tmp[0] != 4 {
		return fmt.Errorf("gif: invalid graphic control extension block size: %d", d.tmp[0])
	}
	flags := d.tmp[1]
	d.disposalMethod = (flags & gcDisposalMethodMask) >> 2
	d.delayTime = int(d.tmp[2]) | int(d.tmp[3])<<8
	if flags&gcTransparentColorSet != 0 {
		d.transparentIndex = d.tmp[4]
		d.hasTransparentIndex = true
	}
	if d.tmp[5] != 0 {
		return fmt.Errorf("gif: invalid graphic control extension block terminator: %d", d.tmp[5])
	}
	return nil
}

func (d *decoder) readImageDescriptor(keepAllFrames bool) error {
	m, err := d.newImageFromDescriptor()
	if err != nil {
		return err
	}
	useLocalColorTable := d.imageFields&fColorTable != 0
	if useLocalColorTable {
		m.Palette, err = d.readColorTable(d.imageFields)
		if err != nil {
			return err
		}
	} else {
		if d.globalColorTable == nil {
			return errors.New("gif: no color table")
		}
		m.Palette = d.globalColorTable
	}
	if d.hasTransparentIndex {
		if !useLocalColorTable {
			// Clone the global color table.
			m.Palette = append(color.Palette(nil), d.globalColorTable...)
		}
		if ti := int(d.transparentIndex); ti < len(m.Palette) {
			m.Palette[ti] = color.RGBA{}
		} else {
			// The transparentIndex is out of range, which is an error
			// according to the spec, but Firefox and Google Chrome
			// seem OK with this, so we enlarge the palette with
			// transparent colors. See golang.org/issue/15059.
			p := make(color.Palette, ti+1)
			copy(p, m.Palette)
			for i := len(m.Palette); i < len(p); i++ {
				p[i] = color.RGBA{}
			}
			m.Palette = p
		}
	}
	litWidth, err := readByte(d.r)
	if err != nil {
		return fmt.Errorf("gif: reading image data: %v", err)
	}
	if litWidth < 2 || litWidth > 8 {
		return fmt.Errorf("gif: pixel size in decode out of range: %d", litWidth)
	}
	// A wonderfully Go-like piece of magic.
	br := &blockReader{d: d}
	lzwr := lzw.NewReader(br, lzw.LSB, int(litWidth))
	defer lzwr.Close()
	if err = readFull(lzwr, m.Pix); err != nil {
		if err != io.ErrUnexpectedEOF {
			return fmt.Errorf("gif: reading image data: %v", err)
		}
		return errNotEnough
	}
	// In theory, both lzwr and br should be exhausted. Reading from them
	// should yield (0, io.EOF).
	//
	// The spec (Appendix F - Compression), says that "An End of
	// Information code... must be the last code output by the encoder
	// for an image". In practice, though, giflib (a widely used C
	// library) does not enforce this, so we also accept lzwr returning
	// io.ErrUnexpectedEOF (meaning that the encoded stream hit io.EOF
	// before the LZW decoder saw an explicit end code), provided that
	// the io.ReadFull call above successfully read len(m.Pix) bytes.
	// See https://golang.org/issue/9856 for an example GIF.
	if n, err := lzwr.Read(d.tmp[256:257]); n != 0 || (err != io.EOF && err != io.ErrUnexpectedEOF) {
		if err != nil {
			return fmt.Errorf("gif: reading image data: %v", err)
		}
		return errTooMuch
	}

	// In practice, some GIFs have an extra byte in the data sub-block
	// stream, which we ignore. See https://golang.org/issue/16146.
	if err := br.close(); err == errTooMuch {
		return errTooMuch
	} else if err != nil {
		return fmt.Errorf("gif: reading image data: %v", err)
	}

	// Check that the color indexes are inside the palette.
	if len(m.Palette) < 256 {
		for _, pixel := range m.Pix {
			if int(pixel) >= len(m.Palette) {
				return errBadPixel
			}
		}
	}

	// Undo the interlacing if necessary.
	if d.imageFields&fInterlace != 0 {
		uninterlace(m)
	}

	if keepAllFrames || len(d.image) == 0 {
		d.image = append(d.image, m)
		d.delay = append(d.delay, d.delayTime)
		d.disposal = append(d.disposal, d.disposalMethod)
	}
	// The GIF89a spec, Section 23 (Graphic Control Extension) says:
	// "The scope of this extension is the first graphic rendering block
	// to follow." We therefore reset the GCE fields to zero.
	d.delayTime = 0
	d.hasTransparentIndex = false
	return nil
}

func (d *decoder) newImageFromDescriptor() (*image.Paletted, error) {
	if err := readFull(d.r, d.tmp[:9]); err != nil {
		return nil, fmt.Errorf("gif: can't read image descriptor: %s", err)
	}
	left := int(d.tmp[0]) + int(d.tmp[1])<<8
	top := int(d.tmp[2]) + int(d.tmp[3])<<8
	width := int(d.tmp[4]) + int(d.tmp[5])<<8
	height := int(d.tmp[6]) + int(d.tmp[7])<<8
	d.imageFields = d.tmp[8]

	// The GIF89a spec, Section 20 (Image Descriptor) says: "Each image must
	// fit within the boundaries of the Logical Screen, as defined in the
	// Logical Screen Descriptor."
	//
	// This is conceptually similar to testing
	//	frameBounds := image.Rect(left, top, left+width, top+height)
	//	imageBounds := image.Rect(0, 0, d.width, d.height)
	//	if !frameBounds.In(imageBounds) { etc }
	// but the semantics of the Go image.Rectangle type is that r.In(s) is true
	// whenever r is an empty rectangle, even if r.Min.X > s.Max.X. Here, we
	// want something stricter.
	//
	// Note that, by construction, left >= 0 && top >= 0, so we only have to
	// explicitly compare frameBounds.Max (left+width, top+height) against
	// imageBounds.Max (d.width, d.height) and not frameBounds.Min (left, top)
	// against imageBounds.Min (0, 0).
	if left+width > d.width || top+height > d.height {
		return nil, errors.New("gif: frame bounds larger than image bounds")
	}
	return image.NewPaletted(image.Rectangle{
		Min: image.Point{left, top},
		Max: image.Point{left + width, top + height},
	}, nil), nil
}

func (d *decoder) readBlock() (int, error) {
	n, err := readByte(d.r)
	if n == 0 || err != nil {
		return 0, err
	}
	if err := readFull(d.r, d.tmp[:n]); err != nil {
		return 0, err
	}
	return int(n), nil
}

// interlaceScan defines the ordering for a pass of the interlace algorithm.
type interlaceScan struct {
	skip, start int
}

// interlacing represents the set of scans in an interlaced GIF image.
var interlacing = []interlaceScan{
	{8, 0}, // Group 1 : Every 8th. row, starting with row 0.
	{8, 4}, // Group 2 : Every 8th. row, starting with row 4.
	{4, 2}, // Group 3 : Every 4th. row, starting with row 2.
	{2, 1}, // Group 4 : Every 2nd. row, starting with row 1.
}

// uninterlace rearranges the pixels in m to account for interlaced input.
func uninterlace(m *image.Paletted) {
	var nPix []uint8
	dx := m.Bounds().Dx()
	dy := m.Bounds().Dy()
	nPix = make([]uint8, dx*dy)
	offset := 0 // steps through the input by sequential scan lines.
	for _, pass := range interlacing {
		nOffset := pass.start * dx // steps through the output as defined by pass.
		for y := pass.start; y < dy; y += pass.skip {
			copy(nPix[nOffset:nOffset+dx], m.Pix[offset:offset+dx])
			offset += dx
			nOffset += dx * pass.skip
		}
	}
	m.Pix = nPix
}

// Decode reads a GIF image from r and returns the first embedded
// image as an [image.Image].
func Decode(r io.Reader) (image.Image, error) {
	var d decoder
	if err := d.decode(r, false, false); err != nil {
		return nil, err
	}
	return d.image[0], nil
}

// GIF represents the possibly multiple images stored in a GIF file.
type GIF struct {
	Image []*image.Paletted // The successive images.
	Delay []int             // The successive delay times, one per frame, in 100ths of a second.
	// LoopCount controls the number of times an animation will be
	// restarted during display.
	// A LoopCount of 0 means to loop forever.
	// A LoopCount of -1 means to show each frame only once.
	// Otherwise, the animation is looped LoopCount+1 times.
	LoopCount int
	// Disposal is the successive disposal methods, one per frame. For
	// backwards compatibility, a nil Disposal is valid to pass to EncodeAll,
	// and implies that each frame's disposal method is 0 (no disposal
	// specified).
	Disposal []byte
	// Config is the global color table (palette), width and height. A nil or
	// empty-color.Palette Config.ColorModel means that each frame has its own
	// color table and there is no global color table. Each frame's bounds must
	// be within the rectangle defined by the two points (0, 0) and
	// (Config.Width, Config.Height).
	//
	// For backwards compatibility, a zero-valued Config is valid to pass to
	// EncodeAll, and implies that the overall GIF's width and height equals
	// the first frame's bounds' Rectangle.Max point.
	Config image.Config
	// BackgroundIndex is the background index in the global color table, for
	// use with the DisposalBackground disposal method.
	BackgroundIndex byte
}

// DecodeAll reads a GIF image from r and returns the sequential frames
// and timing information.
func DecodeAll(r io.Reader) (*GIF, error) {
	var d decoder
	if err := d.decode(r, false, true); err != nil {
		return nil, err
	}
	gif := &GIF{
		Image:     d.image,
		LoopCount: d.loopCount,
		Delay:     d.delay,
		Disposal:  d.disposal,
		Config: image.Config{
			ColorModel: d.globalColorTable,
			Width:      d.width,
			Height:     d.height,
		},
		BackgroundIndex: d.backgroundIndex,
	}
	return gif, nil
}

// DecodeConfig returns the global color model and dimensions of a GIF image
// without decoding the entire image.
func DecodeConfig(r io.Reader) (image.Config, error) {
	var d decoder
	if err := d.decode(r, true, false); err != nil {
		return image.Config{}, err
	}
	return image.Config{
		ColorModel: d.globalColorTable,
		Width:      d.width,
		Height:     d.height,
	}, nil
}

func init() {
	image.RegisterFormat("gif", "GIF8?a", Decode, DecodeConfig)
}

"""



```