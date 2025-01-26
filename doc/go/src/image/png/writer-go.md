Response:
Let's break down the thought process to answer the request about `go/src/image/png/writer.go`.

**1. Understanding the Core Task:**

The request asks for the functionality of the provided Go code snippet, specifically the `writer.go` file within the `image/png` package. The core task is PNG encoding.

**2. Identifying Key Structures and Functions:**

The first step is to scan the code for prominent types and functions. These immediately jump out:

* **`Encoder`:**  This struct clearly holds configuration for encoding.
* **`EncoderBufferPool` and `EncoderBuffer`:** These suggest a mechanism for efficient memory management during encoding.
* **`encoder` (lowercase):** This struct seems to be the actual encoding engine, holding state and buffers.
* **`Encode(w io.Writer, m image.Image) error`:** This is a top-level function and the most likely entry point for users.
* **`(*Encoder).Encode(w io.Writer, m image.Image) error`:** This is the method attached to the `Encoder` struct, likely the core logic.
* **`writeChunk`, `writeIHDR`, `writePLTEAndTRNS`, `writeIDATs`, `writeIEND`:**  These functions strongly hint at the structure of a PNG file (chunks like IHDR, PLTE, IDAT, IEND).
* **`filter`:** This function deals with PNG filtering, a compression optimization technique.
* **`writeImage`:**  This function likely handles the pixel data encoding and compression.

**3. Inferring Functionality based on Names and Types:**

Now, let's reason about what these components do:

* **`Encoder` and Compression:** The `CompressionLevel` field in `Encoder` suggests that the code handles different levels of zlib compression. The constants like `DefaultCompression`, `NoCompression`, etc., reinforce this.
* **Buffer Pooling:** The `EncoderBufferPool` interface clearly allows for reusing `EncoderBuffer`s, which are likely used as temporary storage during encoding. This is a performance optimization.
* **Chunk Writing:**  The `writeChunk` function takes a byte slice and a "name" (like "IHDR"). This directly maps to the chunk structure of PNG files. It also calculates and writes the CRC checksum.
* **Header Writing (`writeIHDR`):** This function takes information from the `image.Image` (dimensions, color model) and constructs the IHDR chunk. The `cb` field in the `encoder` struct (and constants like `cbG8`, `cbTC8`) likely represent color encoding modes.
* **Palette Handling (`writePLTEAndTRNS`):**  This function handles the PLTE (palette) and tRNS (transparency) chunks for paletted images.
* **Image Data Writing (`writeIDATs`, `writeImage`):** This is the core of the encoding. `writeImage` seems to handle the actual pixel processing, filtering, and compression using `zlib`. `writeIDATs` likely wraps the compressed data into IDAT chunks.
* **Filtering (`filter`):** This function implements the different PNG filter algorithms to optimize compression. It compares the results of different filters and chooses the one that minimizes the sum of absolute differences.
* **End Marker (`writeIEND`):** This writes the IEND chunk, marking the end of the PNG file.

**4. Connecting the Dots - The Encoding Process:**

By looking at the functions called within `(*Encoder).Encode`, we can deduce the encoding process:

1. **Initialization:**  Set up the `encoder` struct, potentially using a buffer pool.
2. **Header:** Write the PNG signature (`pngHeader`) and the IHDR chunk.
3. **Palette (if needed):** If the image is paletted, write the PLTE and tRNS chunks.
4. **Image Data:** Write the image data in IDAT chunks, compressing it using zlib with the specified compression level. This involves:
    * Iterating through rows of the image.
    * Converting pixel data to bytes according to the color model.
    * Applying filtering (if compression is enabled and it's not a paletted image).
    * Compressing the filtered row data using zlib.
    * Writing the compressed data into IDAT chunks.
5. **End:** Write the IEND chunk.

**5. Addressing Specific Requirements of the Request:**

* **Function Listing:**  This is straightforward after identifying the key functions.
* **Go Language Feature (Interfaces):** The `EncoderBufferPool` is a prime example of an interface. We can provide a concrete implementation.
* **Code Example:**  Demonstrate basic usage of `Encode` with a simple `image.NewRGBA`.
* **Assumptions, Inputs, Outputs:** For the `filter` function example, create a hypothetical scenario with a previous and current row, and calculate the output of one filter.
* **Command Line Arguments:** The provided code *doesn't* directly handle command-line arguments. This needs to be stated explicitly.
* **Common Mistakes:**  Think about common errors when working with images and encoding: incorrect color models, forgetting to handle errors, not flushing buffers, etc.

**6. Structuring the Answer:**

Organize the answer logically with clear headings for each part of the request (functionality, Go feature, code example, etc.). Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus too much on the low-level byte manipulation. *Correction:*  Elevate the description to focus on the overall encoding process and the purpose of different parts.
* **Initial thought:**  Provide a very detailed explanation of each filter algorithm. *Correction:*  Keep the explanation concise and focus on the high-level purpose of filtering.
* **Initial thought:**  Assume the user understands all PNG concepts. *Correction:* Provide brief explanations of key PNG terms like "chunks."

By following this structured thought process, combining code analysis with knowledge of PNG format and Go language features, a comprehensive and accurate answer can be constructed.
这段代码是 Go 语言 `image/png` 标准库中用于 **PNG 图片编码** 的一部分。它定义了将 `image.Image` 类型的数据编码为 PNG 格式的功能。

**主要功能列举:**

1. **PNG 编码器配置:**
   - 定义了 `Encoder` 结构体，用于配置 PNG 编码的参数，例如压缩级别 (`CompressionLevel`) 和缓冲区池 (`BufferPool`)。
   - 提供了 `CompressionLevel` 类型和相关的常量 (`DefaultCompression`, `NoCompression`, `BestSpeed`, `BestCompression`) 来控制 zlib 压缩的强度。
   - 提供了 `EncoderBufferPool` 接口和 `EncoderBuffer` 类型，允许用户自定义或复用编码过程中使用的缓冲区，以提高性能。

2. **PNG 数据块写入:**
   - 实现了 `writeChunk` 方法，用于将任意数据块（chunk）写入到输出流。每个 PNG 数据块都包含长度、类型、数据和 CRC 校验和。

3. **IHDR 数据块写入:**
   - 实现了 `writeIHDR` 方法，用于写入 PNG 文件的头部信息块 (IHDR)。它包含了图像的宽度、高度、位深度、颜色类型、压缩方法、滤波方法和隔行扫描方法等信息。

4. **PLTE 和 tRNS 数据块写入:**
   - 实现了 `writePLTEAndTRNS` 方法，用于写入调色板数据块 (PLTE) 和透明度数据块 (tRNS)（如果存在）。这主要用于索引颜色类型的 PNG 图片。

5. **IDAT 数据块写入:**
   - 实现了 `writeIDATs` 和相关的 `writeImage` 方法，这是核心的图像数据编码部分。
   - `writeImage` 负责将 `image.Image` 的像素数据转换为特定颜色类型的字节流，并应用 PNG 滤波算法（如 None, Sub, Up, Average, Paeth）以提高压缩率。
   - 使用 `zlib` 库进行数据压缩。
   - `writeIDATs` 将压缩后的数据分割成多个 IDAT (Image Data) 数据块写入输出流。

6. **IEND 数据块写入:**
   - 实现了 `writeIEND` 方法，用于写入 PNG 文件的结束标志块 (IEND)。

7. **顶层编码函数:**
   - 提供了 `Encode(w io.Writer, m image.Image) error` 函数，这是用户最常用的入口点，用于将一个 `image.Image` 编码为 PNG 格式并写入 `io.Writer`。
   - 提供了 `(*Encoder).Encode(w io.Writer, m image.Image) error` 方法，允许用户使用自定义的 `Encoder` 配置进行编码。

8. **辅助函数:**
   - `opaque(m image.Image)`: 判断图像是否完全不透明。
   - `abs8(d uint8)`: 计算一个字节的绝对值（用于滤波算法）。
   - `filter(...)`:  实现 PNG 的滤波算法选择，选择能获得最佳压缩效果的滤波器。
   - `levelToZlib(l CompressionLevel)`: 将 `CompressionLevel` 转换为 `zlib` 库的压缩级别。

**它是什么 Go 语言功能的实现 (PNG 编码):**

这段代码实现了将 Go 语言的 `image.Image` 接口表示的图像数据编码成符合 PNG 标准的字节流的功能。它利用了 Go 标准库中的其他包，如 `bufio`（缓冲写入），`compress/zlib`（zlib 压缩），`encoding/binary`（二进制数据编码），`hash/crc32`（CRC 校验和计算）和 `image/color`（颜色模型）。

**Go 代码举例说明:**

```go
package main

import (
	"image"
	"image/color"
	"image/png"
	"os"
)

func main() {
	// 创建一个简单的 100x100 的红色图像
	width := 100
	height := 100
	upLeft := image.Point{0, 0}
	downRight := image.Point{width, height}
	img := image.NewRGBA(image.Rect(upLeft.X, upLeft.Y, downRight.X, downRight.Y), color.RGBA{255, 0, 0, 255})

	// 创建输出文件
	f, err := os.Create("red_square.png")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// 使用默认配置编码图像并写入文件
	err = png.Encode(f, img)
	if err != nil {
		panic(err)
	}

	println("PNG 文件已生成: red_square.png")
}
```

**假设的输入与输出 (针对 `filter` 函数的推理):**

**假设输入:**

- `cr`: 一个 `[nFilter][]uint8` 类型的二维切片，代表当前行的不同滤波方式的结果。假设 `cr[0]` 是未经过滤的原始像素数据。
- `pr`: 一个 `[]uint8` 类型的切片，代表前一行的像素数据。
- `bpp`:  整数，表示每个像素的字节数（Bytes Per Pixel）。

**假设输入数据:**

```
cr[0][1:] = {100, 120, 150, 110, 130, 160} // 当前行原始数据
pr[1:]    = {90, 110, 140, 100, 120, 150}  // 前一行数据
bpp        = 3                               // 假设是 RGB 图像
```

**推理过程 (以 Up 滤镜为例):**

`filter` 函数会遍历不同的滤波方式，计算每种滤波方式处理后的数据的绝对差值之和，并选择和最小的滤波器。对于 Up 滤镜 (假设其索引为 `ftUp = 2`)：

- 它会将当前行的每个字节减去前一行的对应字节。
- `cr[2][1]` = `cr[0][1]` - `pr[1]` = 100 - 90 = 10
- `cr[2][2]` = `cr[0][2]` - `pr[2]` = 120 - 110 = 10
- `cr[2][3]` = `cr[0][3]` - `pr[3]` = 150 - 140 = 10
- `cr[2][4]` = `cr[0][4]` - `pr[4]` = 110 - 100 = 10
- `cr[2][5]` = `cr[0][5]` - `pr[5]` = 130 - 120 = 10
- `cr[2][6]` = `cr[0][6]` - `pr[6]` = 160 - 150 = 10

然后计算绝对差值之和: `abs(10) + abs(10) + abs(10) + abs(10) + abs(10) + abs(10) = 60`

`filter` 函数会对所有滤波器进行类似的计算，并返回具有最小绝对差值和的滤波器的索引。

**假设输出:**

假设经过计算，Up 滤波器的绝对差值和最小，那么 `filter` 函数会返回 `2` (假设 `ftUp` 的值为 2)。同时，`cr[2]` 中的数据会被更新为应用 Up 滤波器后的结果：`{0, 10, 10, 10, 10, 10, 10}` (第一个字节是滤波器类型标识)。

**命令行参数的具体处理:**

这段代码本身 **不涉及** 命令行参数的具体处理。 它是一个库，主要提供 API 供其他 Go 程序调用。如果需要从命令行编码 PNG 图片，你需要编写一个使用 `image/png` 库的 Go 程序，并使用 `flag` 或其他命令行参数解析库来处理命令行输入，例如输入和输出文件路径、压缩级别等。

**使用者易犯错的点:**

1. **未处理错误:**  在调用 `png.Encode` 时，可能会忽略返回值中的 `error`，这可能导致程序在编码失败时无法正确处理，例如文件写入错误或无效的图像数据。

   ```go
   // 错误的做法
   png.Encode(f, img)

   // 正确的做法
   err := png.Encode(f, img)
   if err != nil {
       println("编码失败:", err.Error())
       // 进行错误处理，例如退出程序或返回错误
   }
   ```

2. **颜色模型不匹配:** `png.Encode` 可以编码任何实现了 `image.Image` 接口的图像，但对于非 `image.NRGBA` 类型的图像，编码过程可能会是 **有损的**。例如，将 `image.RGBA` 编码为 PNG 时，如果存在半透明像素，会被转换为非预乘的 RGBA 值。使用者可能没有意识到这种转换，导致颜色显示上的细微差异。

3. **对调色板图像的误解:** 对于调色板图像 (`image.Paletted`)，`png.Encode` 会自动处理调色板信息的写入。使用者可能会尝试手动处理调色板，导致编码错误或生成无效的 PNG 文件。

4. **缓冲区池的使用不当:** 如果使用了 `EncoderBufferPool`，需要确保正确地 `Get()` 和 `Put()` 缓冲区，否则可能会导致资源泄漏或并发问题。

5. **压缩级别的误用:** 错误地设置 `CompressionLevel` 可能会导致生成的文件过大（例如设置为 `NoCompression`）或编码速度过慢（例如设置为 `BestCompression` 但对性能要求较高）。理解不同压缩级别的含义并根据实际需求选择合适的级别很重要。

总而言之，这段代码提供了强大的 PNG 编码功能。理解其内部机制和正确使用其 API 可以帮助开发者有效地生成和处理 PNG 图像。

Prompt: 
```
这是路径为go/src/image/png/writer.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package png

import (
	"bufio"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"io"
	"strconv"
)

// Encoder configures encoding PNG images.
type Encoder struct {
	CompressionLevel CompressionLevel

	// BufferPool optionally specifies a buffer pool to get temporary
	// EncoderBuffers when encoding an image.
	BufferPool EncoderBufferPool
}

// EncoderBufferPool is an interface for getting and returning temporary
// instances of the [EncoderBuffer] struct. This can be used to reuse buffers
// when encoding multiple images.
type EncoderBufferPool interface {
	Get() *EncoderBuffer
	Put(*EncoderBuffer)
}

// EncoderBuffer holds the buffers used for encoding PNG images.
type EncoderBuffer encoder

type encoder struct {
	enc     *Encoder
	w       io.Writer
	m       image.Image
	cb      int
	err     error
	header  [8]byte
	footer  [4]byte
	tmp     [4 * 256]byte
	cr      [nFilter][]uint8
	pr      []uint8
	zw      *zlib.Writer
	zwLevel int
	bw      *bufio.Writer
}

// CompressionLevel indicates the compression level.
type CompressionLevel int

const (
	DefaultCompression CompressionLevel = 0
	NoCompression      CompressionLevel = -1
	BestSpeed          CompressionLevel = -2
	BestCompression    CompressionLevel = -3

	// Positive CompressionLevel values are reserved to mean a numeric zlib
	// compression level, although that is not implemented yet.
)

type opaquer interface {
	Opaque() bool
}

// Returns whether or not the image is fully opaque.
func opaque(m image.Image) bool {
	if o, ok := m.(opaquer); ok {
		return o.Opaque()
	}
	b := m.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			_, _, _, a := m.At(x, y).RGBA()
			if a != 0xffff {
				return false
			}
		}
	}
	return true
}

// The absolute value of a byte interpreted as a signed int8.
func abs8(d uint8) int {
	if d < 128 {
		return int(d)
	}
	return 256 - int(d)
}

func (e *encoder) writeChunk(b []byte, name string) {
	if e.err != nil {
		return
	}
	n := uint32(len(b))
	if int(n) != len(b) {
		e.err = UnsupportedError(name + " chunk is too large: " + strconv.Itoa(len(b)))
		return
	}
	binary.BigEndian.PutUint32(e.header[:4], n)
	e.header[4] = name[0]
	e.header[5] = name[1]
	e.header[6] = name[2]
	e.header[7] = name[3]
	crc := crc32.NewIEEE()
	crc.Write(e.header[4:8])
	crc.Write(b)
	binary.BigEndian.PutUint32(e.footer[:4], crc.Sum32())

	_, e.err = e.w.Write(e.header[:8])
	if e.err != nil {
		return
	}
	_, e.err = e.w.Write(b)
	if e.err != nil {
		return
	}
	_, e.err = e.w.Write(e.footer[:4])
}

func (e *encoder) writeIHDR() {
	b := e.m.Bounds()
	binary.BigEndian.PutUint32(e.tmp[0:4], uint32(b.Dx()))
	binary.BigEndian.PutUint32(e.tmp[4:8], uint32(b.Dy()))
	// Set bit depth and color type.
	switch e.cb {
	case cbG8:
		e.tmp[8] = 8
		e.tmp[9] = ctGrayscale
	case cbTC8:
		e.tmp[8] = 8
		e.tmp[9] = ctTrueColor
	case cbP8:
		e.tmp[8] = 8
		e.tmp[9] = ctPaletted
	case cbP4:
		e.tmp[8] = 4
		e.tmp[9] = ctPaletted
	case cbP2:
		e.tmp[8] = 2
		e.tmp[9] = ctPaletted
	case cbP1:
		e.tmp[8] = 1
		e.tmp[9] = ctPaletted
	case cbTCA8:
		e.tmp[8] = 8
		e.tmp[9] = ctTrueColorAlpha
	case cbG16:
		e.tmp[8] = 16
		e.tmp[9] = ctGrayscale
	case cbTC16:
		e.tmp[8] = 16
		e.tmp[9] = ctTrueColor
	case cbTCA16:
		e.tmp[8] = 16
		e.tmp[9] = ctTrueColorAlpha
	}
	e.tmp[10] = 0 // default compression method
	e.tmp[11] = 0 // default filter method
	e.tmp[12] = 0 // non-interlaced
	e.writeChunk(e.tmp[:13], "IHDR")
}

func (e *encoder) writePLTEAndTRNS(p color.Palette) {
	if len(p) < 1 || len(p) > 256 {
		e.err = FormatError("bad palette length: " + strconv.Itoa(len(p)))
		return
	}
	last := -1
	for i, c := range p {
		c1 := color.NRGBAModel.Convert(c).(color.NRGBA)
		e.tmp[3*i+0] = c1.R
		e.tmp[3*i+1] = c1.G
		e.tmp[3*i+2] = c1.B
		if c1.A != 0xff {
			last = i
		}
		e.tmp[3*256+i] = c1.A
	}
	e.writeChunk(e.tmp[:3*len(p)], "PLTE")
	if last != -1 {
		e.writeChunk(e.tmp[3*256:3*256+1+last], "tRNS")
	}
}

// An encoder is an io.Writer that satisfies writes by writing PNG IDAT chunks,
// including an 8-byte header and 4-byte CRC checksum per Write call. Such calls
// should be relatively infrequent, since writeIDATs uses a [bufio.Writer].
//
// This method should only be called from writeIDATs (via writeImage).
// No other code should treat an encoder as an io.Writer.
func (e *encoder) Write(b []byte) (int, error) {
	e.writeChunk(b, "IDAT")
	if e.err != nil {
		return 0, e.err
	}
	return len(b), nil
}

// Chooses the filter to use for encoding the current row, and applies it.
// The return value is the index of the filter and also of the row in cr that has had it applied.
func filter(cr *[nFilter][]byte, pr []byte, bpp int) int {
	// We try all five filter types, and pick the one that minimizes the sum of absolute differences.
	// This is the same heuristic that libpng uses, although the filters are attempted in order of
	// estimated most likely to be minimal (ftUp, ftPaeth, ftNone, ftSub, ftAverage), rather than
	// in their enumeration order (ftNone, ftSub, ftUp, ftAverage, ftPaeth).
	cdat0 := cr[0][1:]
	cdat1 := cr[1][1:]
	cdat2 := cr[2][1:]
	cdat3 := cr[3][1:]
	cdat4 := cr[4][1:]
	pdat := pr[1:]
	n := len(cdat0)

	// The up filter.
	sum := 0
	for i := 0; i < n; i++ {
		cdat2[i] = cdat0[i] - pdat[i]
		sum += abs8(cdat2[i])
	}
	best := sum
	filter := ftUp

	// The Paeth filter.
	sum = 0
	for i := 0; i < bpp; i++ {
		cdat4[i] = cdat0[i] - pdat[i]
		sum += abs8(cdat4[i])
	}
	for i := bpp; i < n; i++ {
		cdat4[i] = cdat0[i] - paeth(cdat0[i-bpp], pdat[i], pdat[i-bpp])
		sum += abs8(cdat4[i])
		if sum >= best {
			break
		}
	}
	if sum < best {
		best = sum
		filter = ftPaeth
	}

	// The none filter.
	sum = 0
	for i := 0; i < n; i++ {
		sum += abs8(cdat0[i])
		if sum >= best {
			break
		}
	}
	if sum < best {
		best = sum
		filter = ftNone
	}

	// The sub filter.
	sum = 0
	for i := 0; i < bpp; i++ {
		cdat1[i] = cdat0[i]
		sum += abs8(cdat1[i])
	}
	for i := bpp; i < n; i++ {
		cdat1[i] = cdat0[i] - cdat0[i-bpp]
		sum += abs8(cdat1[i])
		if sum >= best {
			break
		}
	}
	if sum < best {
		best = sum
		filter = ftSub
	}

	// The average filter.
	sum = 0
	for i := 0; i < bpp; i++ {
		cdat3[i] = cdat0[i] - pdat[i]/2
		sum += abs8(cdat3[i])
	}
	for i := bpp; i < n; i++ {
		cdat3[i] = cdat0[i] - uint8((int(cdat0[i-bpp])+int(pdat[i]))/2)
		sum += abs8(cdat3[i])
		if sum >= best {
			break
		}
	}
	if sum < best {
		filter = ftAverage
	}

	return filter
}

func (e *encoder) writeImage(w io.Writer, m image.Image, cb int, level int) error {
	if e.zw == nil || e.zwLevel != level {
		zw, err := zlib.NewWriterLevel(w, level)
		if err != nil {
			return err
		}
		e.zw = zw
		e.zwLevel = level
	} else {
		e.zw.Reset(w)
	}
	defer e.zw.Close()

	bitsPerPixel := 0

	switch cb {
	case cbG8:
		bitsPerPixel = 8
	case cbTC8:
		bitsPerPixel = 24
	case cbP8:
		bitsPerPixel = 8
	case cbP4:
		bitsPerPixel = 4
	case cbP2:
		bitsPerPixel = 2
	case cbP1:
		bitsPerPixel = 1
	case cbTCA8:
		bitsPerPixel = 32
	case cbTC16:
		bitsPerPixel = 48
	case cbTCA16:
		bitsPerPixel = 64
	case cbG16:
		bitsPerPixel = 16
	}

	// cr[*] and pr are the bytes for the current and previous row.
	// cr[0] is unfiltered (or equivalently, filtered with the ftNone filter).
	// cr[ft], for non-zero filter types ft, are buffers for transforming cr[0] under the
	// other PNG filter types. These buffers are allocated once and re-used for each row.
	// The +1 is for the per-row filter type, which is at cr[*][0].
	b := m.Bounds()
	sz := 1 + (bitsPerPixel*b.Dx()+7)/8
	for i := range e.cr {
		if cap(e.cr[i]) < sz {
			e.cr[i] = make([]uint8, sz)
		} else {
			e.cr[i] = e.cr[i][:sz]
		}
		e.cr[i][0] = uint8(i)
	}
	cr := e.cr
	if cap(e.pr) < sz {
		e.pr = make([]uint8, sz)
	} else {
		e.pr = e.pr[:sz]
		clear(e.pr)
	}
	pr := e.pr

	gray, _ := m.(*image.Gray)
	rgba, _ := m.(*image.RGBA)
	paletted, _ := m.(*image.Paletted)
	nrgba, _ := m.(*image.NRGBA)

	for y := b.Min.Y; y < b.Max.Y; y++ {
		// Convert from colors to bytes.
		i := 1
		switch cb {
		case cbG8:
			if gray != nil {
				offset := (y - b.Min.Y) * gray.Stride
				copy(cr[0][1:], gray.Pix[offset:offset+b.Dx()])
			} else {
				for x := b.Min.X; x < b.Max.X; x++ {
					c := color.GrayModel.Convert(m.At(x, y)).(color.Gray)
					cr[0][i] = c.Y
					i++
				}
			}
		case cbTC8:
			// We have previously verified that the alpha value is fully opaque.
			cr0 := cr[0]
			stride, pix := 0, []byte(nil)
			if rgba != nil {
				stride, pix = rgba.Stride, rgba.Pix
			} else if nrgba != nil {
				stride, pix = nrgba.Stride, nrgba.Pix
			}
			if stride != 0 {
				j0 := (y - b.Min.Y) * stride
				j1 := j0 + b.Dx()*4
				for j := j0; j < j1; j += 4 {
					cr0[i+0] = pix[j+0]
					cr0[i+1] = pix[j+1]
					cr0[i+2] = pix[j+2]
					i += 3
				}
			} else {
				for x := b.Min.X; x < b.Max.X; x++ {
					r, g, b, _ := m.At(x, y).RGBA()
					cr0[i+0] = uint8(r >> 8)
					cr0[i+1] = uint8(g >> 8)
					cr0[i+2] = uint8(b >> 8)
					i += 3
				}
			}
		case cbP8:
			if paletted != nil {
				offset := (y - b.Min.Y) * paletted.Stride
				copy(cr[0][1:], paletted.Pix[offset:offset+b.Dx()])
			} else {
				pi := m.(image.PalettedImage)
				for x := b.Min.X; x < b.Max.X; x++ {
					cr[0][i] = pi.ColorIndexAt(x, y)
					i += 1
				}
			}

		case cbP4, cbP2, cbP1:
			pi := m.(image.PalettedImage)

			var a uint8
			var c int
			pixelsPerByte := 8 / bitsPerPixel
			for x := b.Min.X; x < b.Max.X; x++ {
				a = a<<uint(bitsPerPixel) | pi.ColorIndexAt(x, y)
				c++
				if c == pixelsPerByte {
					cr[0][i] = a
					i += 1
					a = 0
					c = 0
				}
			}
			if c != 0 {
				for c != pixelsPerByte {
					a = a << uint(bitsPerPixel)
					c++
				}
				cr[0][i] = a
			}

		case cbTCA8:
			if nrgba != nil {
				offset := (y - b.Min.Y) * nrgba.Stride
				copy(cr[0][1:], nrgba.Pix[offset:offset+b.Dx()*4])
			} else if rgba != nil {
				dst := cr[0][1:]
				src := rgba.Pix[rgba.PixOffset(b.Min.X, y):rgba.PixOffset(b.Max.X, y)]
				for ; len(src) >= 4; dst, src = dst[4:], src[4:] {
					d := (*[4]byte)(dst)
					s := (*[4]byte)(src)
					if s[3] == 0x00 {
						d[0] = 0
						d[1] = 0
						d[2] = 0
						d[3] = 0
					} else if s[3] == 0xff {
						copy(d[:], s[:])
					} else {
						// This code does the same as color.NRGBAModel.Convert(
						// rgba.At(x, y)).(color.NRGBA) but with no extra memory
						// allocations or interface/function call overhead.
						//
						// The multiplier m combines 0x101 (which converts
						// 8-bit color to 16-bit color) and 0xffff (which, when
						// combined with the division-by-a, converts from
						// alpha-premultiplied to non-alpha-premultiplied).
						const m = 0x101 * 0xffff
						a := uint32(s[3]) * 0x101
						d[0] = uint8((uint32(s[0]) * m / a) >> 8)
						d[1] = uint8((uint32(s[1]) * m / a) >> 8)
						d[2] = uint8((uint32(s[2]) * m / a) >> 8)
						d[3] = s[3]
					}
				}
			} else {
				// Convert from image.Image (which is alpha-premultiplied) to PNG's non-alpha-premultiplied.
				for x := b.Min.X; x < b.Max.X; x++ {
					c := color.NRGBAModel.Convert(m.At(x, y)).(color.NRGBA)
					cr[0][i+0] = c.R
					cr[0][i+1] = c.G
					cr[0][i+2] = c.B
					cr[0][i+3] = c.A
					i += 4
				}
			}
		case cbG16:
			for x := b.Min.X; x < b.Max.X; x++ {
				c := color.Gray16Model.Convert(m.At(x, y)).(color.Gray16)
				cr[0][i+0] = uint8(c.Y >> 8)
				cr[0][i+1] = uint8(c.Y)
				i += 2
			}
		case cbTC16:
			// We have previously verified that the alpha value is fully opaque.
			for x := b.Min.X; x < b.Max.X; x++ {
				r, g, b, _ := m.At(x, y).RGBA()
				cr[0][i+0] = uint8(r >> 8)
				cr[0][i+1] = uint8(r)
				cr[0][i+2] = uint8(g >> 8)
				cr[0][i+3] = uint8(g)
				cr[0][i+4] = uint8(b >> 8)
				cr[0][i+5] = uint8(b)
				i += 6
			}
		case cbTCA16:
			// Convert from image.Image (which is alpha-premultiplied) to PNG's non-alpha-premultiplied.
			for x := b.Min.X; x < b.Max.X; x++ {
				c := color.NRGBA64Model.Convert(m.At(x, y)).(color.NRGBA64)
				cr[0][i+0] = uint8(c.R >> 8)
				cr[0][i+1] = uint8(c.R)
				cr[0][i+2] = uint8(c.G >> 8)
				cr[0][i+3] = uint8(c.G)
				cr[0][i+4] = uint8(c.B >> 8)
				cr[0][i+5] = uint8(c.B)
				cr[0][i+6] = uint8(c.A >> 8)
				cr[0][i+7] = uint8(c.A)
				i += 8
			}
		}

		// Apply the filter.
		// Skip filter for NoCompression and paletted images (cbP8) as
		// "filters are rarely useful on palette images" and will result
		// in larger files (see http://www.libpng.org/pub/png/book/chapter09.html).
		f := ftNone
		if level != zlib.NoCompression && cb != cbP8 && cb != cbP4 && cb != cbP2 && cb != cbP1 {
			// Since we skip paletted images we don't have to worry about
			// bitsPerPixel not being a multiple of 8
			bpp := bitsPerPixel / 8
			f = filter(&cr, pr, bpp)
		}

		// Write the compressed bytes.
		if _, err := e.zw.Write(cr[f]); err != nil {
			return err
		}

		// The current row for y is the previous row for y+1.
		pr, cr[0] = cr[0], pr
	}
	return nil
}

// Write the actual image data to one or more IDAT chunks.
func (e *encoder) writeIDATs() {
	if e.err != nil {
		return
	}
	if e.bw == nil {
		e.bw = bufio.NewWriterSize(e, 1<<15)
	} else {
		e.bw.Reset(e)
	}
	e.err = e.writeImage(e.bw, e.m, e.cb, levelToZlib(e.enc.CompressionLevel))
	if e.err != nil {
		return
	}
	e.err = e.bw.Flush()
}

// This function is required because we want the zero value of
// Encoder.CompressionLevel to map to zlib.DefaultCompression.
func levelToZlib(l CompressionLevel) int {
	switch l {
	case DefaultCompression:
		return zlib.DefaultCompression
	case NoCompression:
		return zlib.NoCompression
	case BestSpeed:
		return zlib.BestSpeed
	case BestCompression:
		return zlib.BestCompression
	default:
		return zlib.DefaultCompression
	}
}

func (e *encoder) writeIEND() { e.writeChunk(nil, "IEND") }

// Encode writes the Image m to w in PNG format. Any Image may be
// encoded, but images that are not [image.NRGBA] might be encoded lossily.
func Encode(w io.Writer, m image.Image) error {
	var e Encoder
	return e.Encode(w, m)
}

// Encode writes the Image m to w in PNG format.
func (enc *Encoder) Encode(w io.Writer, m image.Image) error {
	// Obviously, negative widths and heights are invalid. Furthermore, the PNG
	// spec section 11.2.2 says that zero is invalid. Excessively large images are
	// also rejected.
	mw, mh := int64(m.Bounds().Dx()), int64(m.Bounds().Dy())
	if mw <= 0 || mh <= 0 || mw >= 1<<32 || mh >= 1<<32 {
		return FormatError("invalid image size: " + strconv.FormatInt(mw, 10) + "x" + strconv.FormatInt(mh, 10))
	}

	var e *encoder
	if enc.BufferPool != nil {
		buffer := enc.BufferPool.Get()
		e = (*encoder)(buffer)

	}
	if e == nil {
		e = &encoder{}
	}
	if enc.BufferPool != nil {
		defer enc.BufferPool.Put((*EncoderBuffer)(e))
	}

	e.enc = enc
	e.w = w
	e.m = m

	var pal color.Palette
	// cbP8 encoding needs PalettedImage's ColorIndexAt method.
	if _, ok := m.(image.PalettedImage); ok {
		pal, _ = m.ColorModel().(color.Palette)
	}
	if pal != nil {
		if len(pal) <= 2 {
			e.cb = cbP1
		} else if len(pal) <= 4 {
			e.cb = cbP2
		} else if len(pal) <= 16 {
			e.cb = cbP4
		} else {
			e.cb = cbP8
		}
	} else {
		switch m.ColorModel() {
		case color.GrayModel:
			e.cb = cbG8
		case color.Gray16Model:
			e.cb = cbG16
		case color.RGBAModel, color.NRGBAModel, color.AlphaModel:
			if opaque(m) {
				e.cb = cbTC8
			} else {
				e.cb = cbTCA8
			}
		default:
			if opaque(m) {
				e.cb = cbTC16
			} else {
				e.cb = cbTCA16
			}
		}
	}

	_, e.err = io.WriteString(w, pngHeader)
	e.writeIHDR()
	if pal != nil {
		e.writePLTEAndTRNS(pal)
	}
	e.writeIDATs()
	e.writeIEND()
	return e.err
}

"""



```