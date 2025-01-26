Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Understanding the Request:**

The request asks for an explanation of a Go source code file (`writer_test.go`) related to PNG encoding. The key elements requested are:

* **Functionality:** What does this code *do*?
* **Go Feature Implementation:**  If it implements a Go feature, provide an example.
* **Code Reasoning:** If there's logic, illustrate with input/output examples.
* **Command-line Arguments:**  Describe any handling of command-line arguments.
* **Common Mistakes:** Point out potential pitfalls for users.
* **Language:**  Respond in Chinese.

**2. Initial Code Scan and Identification of Key Areas:**

My first pass involves quickly skimming the code to identify the main sections and their purpose. Keywords like `func Test...`, `Benchmark...`, and function names like `diff`, `encodeDecode`, `convertToNRGBA` are strong indicators. I also notice the import statements, which tell me it's related to image processing, compression (zlib), and testing.

* **Testing Functions (`TestWriter`, `TestWriterPaletted`, `TestWriterLevels`, `TestSubImage`, `TestWriteRGBA`):**  These clearly are the core of the test suite. They seem to be testing different scenarios of PNG encoding and decoding.
* **Benchmark Functions (`BenchmarkEncode...`):**  These measure the performance of different encoding scenarios.
* **Helper Functions (`diff`, `encodeDecode`, `convertToNRGBA`):** These are utilities used within the tests.

**3. Analyzing Each Section (Iterative Refinement):**

Now I'll go through each section in more detail:

* **`diff` function:** This function compares two `image.Image` instances pixel by pixel. It's a crucial part of the testing process to verify that encoding and decoding don't introduce errors. I mentally note that this is used for correctness checks.

* **`encodeDecode` function:** This function encapsulates the process of encoding an image to a `bytes.Buffer` and then decoding it back. This is a core pattern for testing the round-trip fidelity of the PNG encoder/decoder.

* **`convertToNRGBA` function:** This function converts a generic `image.Image` to a specific `*image.NRGBA` type. This suggests that the tests might need to work with a specific color model.

* **`TestWriter` function:** This test iterates through a list of PNG files (`filenames`, `filenamesShort`) and performs a round-trip encode-decode test. It reads the image, encodes it, decodes it, and then compares the original and the decoded image using the `diff` function. This confirms basic encoding/decoding functionality.

* **`TestWriterPaletted` function:** This test specifically focuses on encoding paletted images. It tests different palette sizes and bit depths. It carefully examines the encoded byte stream to ensure the correct bit depth is being written and verifies the uncompressed data length. This reveals the handling of indexed color images.

* **`TestWriterLevels` function:** This test checks the impact of different compression levels (`DefaultCompression` vs. `NoCompression`). It verifies that using no compression results in a larger output size but that both compressed and uncompressed data can be decoded.

* **`TestSubImage` function:** This test encodes a sub-region of an image to verify that the encoder correctly handles image bounds and offsets.

* **`TestWriteRGBA` function:** This test covers various RGBA image scenarios, including fully transparent, fully opaque, mixed transparency, and translucent images. This helps ensure that alpha channel handling is correct.

* **`BenchmarkEncode...` functions:** These functions measure the time it takes to encode different types of images (Gray, NRGBA, Paletted, RGBA) with varying levels of optimization (like using a `BufferPool`). They use the `testing.B` type for benchmarking.

**4. Identifying Go Feature Implementations:**

Based on the code, the most prominent Go feature being implemented is the `image.Image` interface and its related types (`image.RGBA`, `image.NRGBA`, `image.Paletted`, `color.Palette`, etc.). The `encoding/binary` package is used for manipulating binary data, and `compress/zlib` is used for the core PNG compression. The testing framework itself (`testing` package) is also a key Go feature demonstrated.

**5. Code Reasoning and Examples:**

For the `TestWriterPaletted` function, I can reason about the input and expected output based on the loop and the checks within. For instance, a palette of size 16 and bit depth 4 means that each pixel will be represented by 4 bits. The calculation of `datalen` confirms this logic.

**6. Command-line Arguments:**

I noticed the `testing.Short()` call. This is a standard Go testing mechanism that allows running a reduced set of tests when the `-short` flag is passed to `go test`. This is the only direct interaction with command-line arguments in this specific code snippet.

**7. Common Mistakes:**

The code itself doesn't directly show user-facing API calls that would lead to common mistakes. However, the tests around different color models and compression levels hint at potential areas where users might make mistakes if they don't understand these concepts. For example, misunderstanding how paletted images work or not considering the impact of compression levels.

**8. Structuring the Answer in Chinese:**

Finally, I would organize my findings into a clear and structured answer in Chinese, addressing each point of the original request. I would use precise technical terms and provide code examples where applicable. I would pay attention to the requested format and detail level for each point.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the code handles command-line arguments for setting compression levels.
* **Correction:**  A closer look reveals that compression levels are set programmatically within the `TestWriterLevels` function, not via command-line arguments. The only command-line interaction is through `testing.Short()`.

* **Initial thought:**  Focus heavily on the `Encode` and `Decode` functions.
* **Refinement:** Recognize that the *test code* is the subject of the analysis, so understanding the test setup (like `diff`) and the different test cases is equally important.

By following this structured approach of scanning, analyzing, identifying key features, and then reasoning about the code, I can effectively understand and explain the functionality of the given Go source code. The iterative refinement step is crucial for correcting initial assumptions and ensuring accuracy.
这段代码是 Go 语言标准库 `image/png` 包中 `writer_test.go` 文件的一部分，它主要用于**测试 PNG 图片的编码功能**。

具体来说，它包含了多个测试函数，用于验证 `image/png` 包中的编码器 (`Encoder`) 是否能够正确地将各种类型的 `image.Image` 编码成符合 PNG 标准的字节流，并且能够被 `image/png` 包中的解码器 (`Decoder`) 成功解码。

以下是这段代码的主要功能点：

1. **`diff(m0, m1 image.Image) error` 函数:**
   - **功能:**  比较两个 `image.Image` 是否完全相同。
   - **实现原理:**  它会逐像素地比较两个图片的颜色值（RGBA），如果发现任何像素的颜色不同，则返回一个包含错误信息的 `error`。
   - **在测试中的作用:** 用于验证编码后再解码的图片与原始图片是否一致，是测试正确性的关键工具。

2. **`encodeDecode(m image.Image) (image.Image, error)` 函数:**
   - **功能:**  将一个 `image.Image` 编码成 PNG 格式，然后再将其解码回 `image.Image`。
   - **实现原理:**  它使用 `png.Encode` 将图片编码到 `bytes.Buffer` 中，然后使用 `png.Decode` 从该 `bytes.Buffer` 中解码图片。
   - **在测试中的作用:**  这是一个核心的辅助函数，用于进行端到端的编码-解码测试。

3. **`convertToNRGBA(m image.Image) *image.NRGBA` 函数:**
   - **功能:**  将任意 `image.Image` 转换为 `*image.NRGBA` 类型。
   - **实现原理:**  它创建一个新的 `image.NRGBA` 图片，并使用 `draw.Draw` 将原始图片的内容绘制到新的 `NRGBA` 图片上。
   - **在测试中的作用:**  在某些测试场景中，需要将不同类型的图片转换为统一的 `NRGBA` 格式进行比较。

4. **`TestWriter(t *testing.T)` 函数:**
   - **功能:**  测试基本的 PNG 编码和解码功能。
   - **实现原理:**
     - 它从 `testdata/pngsuite/` 目录下读取一系列预先存在的 PNG 测试图片（文件名由 `filenames` 或 `filenamesShort` 变量定义，后者用于简短测试）。
     - 对于每个图片，它先读取两次（`m0` 和 `m1`）。
     - 然后将其中一个副本 (`m1`) 进行编码和解码，得到 `m2`。
     - 最后使用 `diff` 函数比较原始图片 `m0` 和编码解码后的图片 `m2`，以验证编码和解码的正确性。
   - **假设的输入与输出:**
     - **假设输入:** `testdata/pngsuite/basn0g01.png` (一个黑白 PNG 图片)
     - **预期输出:** 编码后再解码得到的图片应该与原始的 `basn0g01.png` 图片在像素级别上完全一致。

5. **`TestWriterPaletted(t *testing.T)` 函数:**
   - **功能:**  专门测试 paletted (索引颜色) 图像的编码功能。
   - **实现原理:**
     - 它定义了一系列测试用例，每个用例包含不同的调色板大小 (`plen`) 和对应的位深度 (`bitdepth`)。
     - 对于每个用例，它创建一个具有特定调色板的 `image.Paletted` 图片，并填充一些颜色。
     - 然后对图片进行编码，并检查编码后的字节流：
       - 验证 IHDR chunk 中的位深度是否正确。
       - 解压缩 IDAT chunk 中的图像数据，并检查解压后的数据长度是否与预期一致。
   - **假设的输入与输出:**
     - **假设输入:**  一个 32x16 的 `image.Paletted` 图片，调色板大小为 16，每个像素的颜色索引根据循环赋值。
     - **预期输出:**  编码后的 PNG 数据中，IHDR chunk 的位深度字段应该为 4，IDAT chunk 解压后的数据长度应为 `(1 + 32/2) * 16` 字节。

6. **`TestWriterLevels(t *testing.T)` 函数:**
   - **功能:**  测试不同的 PNG 压缩级别。
   - **实现原理:**
     - 它创建一个 `image.NRGBA` 图片。
     - 使用默认的 `Encoder` 配置进行编码。
     - 创建一个配置了 `NoCompression` 的 `Encoder` 进行编码。
     - 比较两种编码结果的大小，预期无压缩的编码结果会更大。
     - 尝试解码两种编码结果，确保都能成功解码。

7. **`TestSubImage(t *testing.T)` 函数:**
   - **功能:**  测试对子图像进行编码和解码的功能。
   - **实现原理:**
     - 它创建一个大的 `image.RGBA` 图片，并填充一些颜色。
     - 使用 `SubImage` 方法创建一个子图像。
     - 对子图像进行编码和解码。
     - 使用 `diff` 函数比较原始子图像和编码解码后的图像。

8. **`TestWriteRGBA(t *testing.T)` 函数:**
   - **功能:**  测试编码不同透明度 RGBA 图像的功能。
   - **实现原理:**
     - 它创建了四种不同的 `image.RGBA` 图片：完全透明、完全不透明、部分透明、以及具有不同 alpha 值的半透明图片。
     - 对每种图片进行编码和解码。
     - 使用 `diff` 函数比较原始图片（先转换为 `NRGBA`）和编码解码后的图片。

9. **`BenchmarkEncode... (b *testing.B)` 函数:**
   - **功能:**  进行性能基准测试，衡量不同类型图像的编码速度。
   - **实现原理:**  使用 Go 的 `testing` 包提供的基准测试框架，多次执行编码操作，并报告每次操作的耗时和内存分配情况。
   - **涉及的图像类型:**  Gray, NRGBA (opaque 和 non-opaque), Paletted, RGB (opaque), RGBA。
   - **`BenchmarkEncodeGrayWithBufferPool`:**  演示了使用 `EncoderBuffer` 池来优化内存分配，提高编码性能。

**Go 语言功能的实现示例:**

* **使用 `image` 包处理图像:**
  ```go
  package main

  import (
    "bytes"
    "fmt"
    "image"
    "image/color"
    "image/png"
    "os"
  )

  func main() {
    // 创建一个新的 RGBA 图像
    img := image.NewRGBA(image.Rect(0, 0, 100, 100))

    // 设置一些像素颜色
    for x := 0; x < 100; x++ {
      for y := 0; y < 100; y++ {
        img.Set(x, y, color.RGBA{uint8(x), uint8(y), 100, 255})
      }
    }

    // 将图像编码为 PNG
    buf := new(bytes.Buffer)
    err := png.Encode(buf, img)
    if err != nil {
      fmt.Println("编码错误:", err)
      return
    }

    // 将编码后的数据写入文件
    err = os.WriteFile("output.png", buf.Bytes(), 0644)
    if err != nil {
      fmt.Println("写入文件错误:", err)
      return
    }

    fmt.Println("PNG 图片已保存到 output.png")
  }
  ```

**代码推理示例:**

在 `TestWriterPaletted` 函数中，对于以下测试用例：

```go
{
  plen:     16,
  bitdepth: 4,
  datalen:  (1 + width/2) * height,
},
```

* **假设输入:**  一个 32x16 的 `image.Paletted` 图片，调色板包含 16 种颜色。
* **推理过程:**
    - 由于调色板大小为 16，所以每个像素可以用 4 位 (2<sup>4</sup> = 16) 来表示其颜色索引。
    - 在 PNG 的 IDAT 数据中，每一行数据前会有一个 filter byte。
    - 因此，每行像素数据占用的字节数为 `width / (8 / bitdepth)`，即 `32 / (8 / 4) = 16` 字节。
    - 加上每行的 filter byte，每行占用 `1 + 16 = 17` 字节。
    - 总共有 `height` 行，所以 IDAT 数据的预期解压长度为 `(1 + width/(8/tc.bitdepth)) * height`，代入 `bitdepth = 4`，得到 `(1 + 32/2) * 16 = 17 * 16 = 272` 字节。
* **预期输出:**  当检查 IDAT chunk 的解压数据长度时，应该得到 272。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是一个测试文件，通常通过 `go test` 命令来运行。

`go test` 命令有一些常用的 flag，例如：

* `-v`:  显示详细的测试输出。
* `-run <pattern>`:  只运行匹配指定模式的测试函数。
* `-bench <pattern>`:  运行匹配指定模式的基准测试函数。
* `-short`:  运行简短的测试，可能会跳过一些耗时的测试用例 (例如 `TestWriter` 中使用了 `testing.Short()` 来控制是否运行所有测试图片)。

例如，要运行 `writer_test.go` 文件中的所有测试函数，可以使用命令：

```bash
go test image/png
```

要只运行 `TestWriterPaletted` 函数，可以使用命令：

```bash
go test -run TestWriterPaletted image/png
```

要运行所有的基准测试函数，可以使用命令：

```bash
go test -bench . image/png
```

**使用者易犯错的点:**

这段测试代码本身是内部测试，使用者通常不会直接与它交互。然而，从测试用例中可以推断出使用 `image/png` 包时可能犯的错误：

* **不理解 paletted 图像的原理:**  使用者可能不清楚如何创建和编码 paletted 图像，或者对位深度的概念理解不足，导致编码后的文件不符合预期。例如，创建 paletted 图像时没有正确设置调色板。
* **错误地设置压缩级别:**  使用者可能不了解不同的压缩级别会对文件大小和编码速度产生影响。例如，在不需要高压缩比的场景下使用了默认的压缩级别，导致编码速度较慢。
* **处理透明度时出现问题:**  使用者可能对 RGBA 图像的 alpha 通道理解不足，导致透明度处理不当。例如，想要创建完全不透明的图像，但 alpha 值设置不正确。
* **在解码前未正确读取整个 PNG 数据:**  如果使用者尝试从一个未完全读取的 io.Reader 中解码 PNG，可能会导致解码失败。

总而言之，`go/src/image/png/writer_test.go` 是一个用于验证 PNG 编码器正确性的测试套件，它通过多种测试用例覆盖了不同类型的图像和编码选项，确保了 `image/png` 包的编码功能能够可靠地工作。

Prompt: 
```
这是路径为go/src/image/png/writer_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"io"
	"testing"
)

func diff(m0, m1 image.Image) error {
	b0, b1 := m0.Bounds(), m1.Bounds()
	if !b0.Size().Eq(b1.Size()) {
		return fmt.Errorf("dimensions differ: %v vs %v", b0, b1)
	}
	dx := b1.Min.X - b0.Min.X
	dy := b1.Min.Y - b0.Min.Y
	for y := b0.Min.Y; y < b0.Max.Y; y++ {
		for x := b0.Min.X; x < b0.Max.X; x++ {
			c0 := m0.At(x, y)
			c1 := m1.At(x+dx, y+dy)
			r0, g0, b0, a0 := c0.RGBA()
			r1, g1, b1, a1 := c1.RGBA()
			if r0 != r1 || g0 != g1 || b0 != b1 || a0 != a1 {
				return fmt.Errorf("colors differ at (%d, %d): %T%v vs %T%v", x, y, c0, c0, c1, c1)
			}
		}
	}
	return nil
}

func encodeDecode(m image.Image) (image.Image, error) {
	var b bytes.Buffer
	err := Encode(&b, m)
	if err != nil {
		return nil, err
	}
	return Decode(&b)
}

func convertToNRGBA(m image.Image) *image.NRGBA {
	b := m.Bounds()
	ret := image.NewNRGBA(b)
	draw.Draw(ret, b, m, b.Min, draw.Src)
	return ret
}

func TestWriter(t *testing.T) {
	// The filenames variable is declared in reader_test.go.
	names := filenames
	if testing.Short() {
		names = filenamesShort
	}
	for _, fn := range names {
		qfn := "testdata/pngsuite/" + fn + ".png"
		// Read the image.
		m0, err := readPNG(qfn)
		if err != nil {
			t.Error(fn, err)
			continue
		}
		// Read the image again, encode it, and decode it.
		m1, err := readPNG(qfn)
		if err != nil {
			t.Error(fn, err)
			continue
		}
		m2, err := encodeDecode(m1)
		if err != nil {
			t.Error(fn, err)
			continue
		}
		// Compare the two.
		err = diff(m0, m2)
		if err != nil {
			t.Error(fn, err)
			continue
		}
	}
}

func TestWriterPaletted(t *testing.T) {
	const width, height = 32, 16

	testCases := []struct {
		plen     int
		bitdepth uint8
		datalen  int
	}{

		{
			plen:     256,
			bitdepth: 8,
			datalen:  (1 + width) * height,
		},

		{
			plen:     128,
			bitdepth: 8,
			datalen:  (1 + width) * height,
		},

		{
			plen:     16,
			bitdepth: 4,
			datalen:  (1 + width/2) * height,
		},

		{
			plen:     4,
			bitdepth: 2,
			datalen:  (1 + width/4) * height,
		},

		{
			plen:     2,
			bitdepth: 1,
			datalen:  (1 + width/8) * height,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("plen-%d", tc.plen), func(t *testing.T) {
			// Create a paletted image with the correct palette length
			palette := make(color.Palette, tc.plen)
			for i := range palette {
				palette[i] = color.NRGBA{
					R: uint8(i),
					G: uint8(i),
					B: uint8(i),
					A: 255,
				}
			}
			m0 := image.NewPaletted(image.Rect(0, 0, width, height), palette)

			i := 0
			for y := 0; y < height; y++ {
				for x := 0; x < width; x++ {
					m0.SetColorIndex(x, y, uint8(i%tc.plen))
					i++
				}
			}

			// Encode the image
			var b bytes.Buffer
			if err := Encode(&b, m0); err != nil {
				t.Error(err)
				return
			}
			const chunkFieldsLength = 12 // 4 bytes for length, name and crc
			data := b.Bytes()
			i = len(pngHeader)

			for i < len(data)-chunkFieldsLength {
				length := binary.BigEndian.Uint32(data[i : i+4])
				name := string(data[i+4 : i+8])

				switch name {
				case "IHDR":
					bitdepth := data[i+8+8]
					if bitdepth != tc.bitdepth {
						t.Errorf("got bitdepth %d, want %d", bitdepth, tc.bitdepth)
					}
				case "IDAT":
					// Uncompress the image data
					r, err := zlib.NewReader(bytes.NewReader(data[i+8 : i+8+int(length)]))
					if err != nil {
						t.Error(err)
						return
					}
					n, err := io.Copy(io.Discard, r)
					if err != nil {
						t.Errorf("got error while reading image data: %v", err)
					}
					if n != int64(tc.datalen) {
						t.Errorf("got uncompressed data length %d, want %d", n, tc.datalen)
					}
				}

				i += chunkFieldsLength + int(length)
			}
		})

	}
}

func TestWriterLevels(t *testing.T) {
	m := image.NewNRGBA(image.Rect(0, 0, 100, 100))

	var b1, b2 bytes.Buffer
	if err := (&Encoder{}).Encode(&b1, m); err != nil {
		t.Fatal(err)
	}
	noenc := &Encoder{CompressionLevel: NoCompression}
	if err := noenc.Encode(&b2, m); err != nil {
		t.Fatal(err)
	}

	if b2.Len() <= b1.Len() {
		t.Error("DefaultCompression encoding was larger than NoCompression encoding")
	}
	if _, err := Decode(&b1); err != nil {
		t.Error("cannot decode DefaultCompression")
	}
	if _, err := Decode(&b2); err != nil {
		t.Error("cannot decode NoCompression")
	}
}

func TestSubImage(t *testing.T) {
	m0 := image.NewRGBA(image.Rect(0, 0, 256, 256))
	for y := 0; y < 256; y++ {
		for x := 0; x < 256; x++ {
			m0.Set(x, y, color.RGBA{uint8(x), uint8(y), 0, 255})
		}
	}
	m0 = m0.SubImage(image.Rect(50, 30, 250, 130)).(*image.RGBA)
	m1, err := encodeDecode(m0)
	if err != nil {
		t.Error(err)
		return
	}
	err = diff(m0, m1)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestWriteRGBA(t *testing.T) {
	const width, height = 640, 480
	transparentImg := image.NewRGBA(image.Rect(0, 0, width, height))
	opaqueImg := image.NewRGBA(image.Rect(0, 0, width, height))
	mixedImg := image.NewRGBA(image.Rect(0, 0, width, height))
	translucentImg := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			opaqueColor := color.RGBA{uint8(x), uint8(y), uint8(y + x), 255}
			translucentColor := color.RGBA{uint8(x) % 128, uint8(y) % 128, uint8(y+x) % 128, 128}
			opaqueImg.Set(x, y, opaqueColor)
			translucentImg.Set(x, y, translucentColor)
			if y%2 == 0 {
				mixedImg.Set(x, y, opaqueColor)
			}
		}
	}

	testCases := []struct {
		name string
		img  image.Image
	}{
		{"Transparent RGBA", transparentImg},
		{"Opaque RGBA", opaqueImg},
		{"50/50 Transparent/Opaque RGBA", mixedImg},
		{"RGBA with variable alpha", translucentImg},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m0 := tc.img
			m1, err := encodeDecode(m0)
			if err != nil {
				t.Fatal(err)
			}
			err = diff(convertToNRGBA(m0), m1)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func BenchmarkEncodeGray(b *testing.B) {
	img := image.NewGray(image.Rect(0, 0, 640, 480))
	b.SetBytes(640 * 480 * 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(io.Discard, img)
	}
}

type pool struct {
	b *EncoderBuffer
}

func (p *pool) Get() *EncoderBuffer {
	return p.b
}

func (p *pool) Put(b *EncoderBuffer) {
	p.b = b
}

func BenchmarkEncodeGrayWithBufferPool(b *testing.B) {
	img := image.NewGray(image.Rect(0, 0, 640, 480))
	e := Encoder{
		BufferPool: &pool{},
	}
	b.SetBytes(640 * 480 * 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Encode(io.Discard, img)
	}
}

func BenchmarkEncodeNRGBOpaque(b *testing.B) {
	img := image.NewNRGBA(image.Rect(0, 0, 640, 480))
	// Set all pixels to 0xFF alpha to force opaque mode.
	bo := img.Bounds()
	for y := bo.Min.Y; y < bo.Max.Y; y++ {
		for x := bo.Min.X; x < bo.Max.X; x++ {
			img.Set(x, y, color.NRGBA{0, 0, 0, 255})
		}
	}
	if !img.Opaque() {
		b.Fatal("expected image to be opaque")
	}
	b.SetBytes(640 * 480 * 4)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(io.Discard, img)
	}
}

func BenchmarkEncodeNRGBA(b *testing.B) {
	img := image.NewNRGBA(image.Rect(0, 0, 640, 480))
	if img.Opaque() {
		b.Fatal("expected image not to be opaque")
	}
	b.SetBytes(640 * 480 * 4)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(io.Discard, img)
	}
}

func BenchmarkEncodePaletted(b *testing.B) {
	img := image.NewPaletted(image.Rect(0, 0, 640, 480), color.Palette{
		color.RGBA{0, 0, 0, 255},
		color.RGBA{255, 255, 255, 255},
	})
	b.SetBytes(640 * 480 * 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(io.Discard, img)
	}
}

func BenchmarkEncodeRGBOpaque(b *testing.B) {
	img := image.NewRGBA(image.Rect(0, 0, 640, 480))
	// Set all pixels to 0xFF alpha to force opaque mode.
	bo := img.Bounds()
	for y := bo.Min.Y; y < bo.Max.Y; y++ {
		for x := bo.Min.X; x < bo.Max.X; x++ {
			img.Set(x, y, color.RGBA{0, 0, 0, 255})
		}
	}
	if !img.Opaque() {
		b.Fatal("expected image to be opaque")
	}
	b.SetBytes(640 * 480 * 4)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(io.Discard, img)
	}
}

func BenchmarkEncodeRGBA(b *testing.B) {
	const width, height = 640, 480
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			percent := (x + y) % 100
			switch {
			case percent < 10: // 10% of pixels are translucent (have alpha >0 and <255)
				img.Set(x, y, color.NRGBA{uint8(x), uint8(y), uint8(x * y), uint8(percent)})
			case percent < 40: // 30% of pixels are transparent (have alpha == 0)
				img.Set(x, y, color.NRGBA{uint8(x), uint8(y), uint8(x * y), 0})
			default: // 60% of pixels are opaque (have alpha == 255)
				img.Set(x, y, color.NRGBA{uint8(x), uint8(y), uint8(x * y), 255})
			}
		}
	}
	if img.Opaque() {
		b.Fatal("expected image not to be opaque")
	}
	b.SetBytes(width * height * 4)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(io.Discard, img)
	}
}

"""



```