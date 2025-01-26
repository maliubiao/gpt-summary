Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understanding the Goal:** The request asks for the functionality of the provided Go code snippet, which is a part of the JPEG decoding process. The key is to identify what tasks this specific code handles within the larger JPEG decoding workflow.

2. **Initial Scan and Keywords:**  Quickly read through the code, paying attention to function names, comments, and key variable names. Words like `makeImg`, `processSOS`, `refine`, `reconstructBlock`, `decoder`, `image`, `YCbCr`, `Gray`, `huffman`, `quant`, `block`, `progressive`, `SOS`, `RST` stand out. These provide initial clues about the code's purpose.

3. **Function-by-Function Analysis:**  Examine each function individually:

    * **`makeImg(mxx, myy int)`:**  The name suggests creating an image. The logic checks `d.nComp` (number of components) and allocates either a `image.Gray` or `image.YCbCr` image. The `subsampleRatio` calculation strongly indicates it's handling different chroma subsampling schemes (4:4:4, 4:2:0, etc.). The allocation size based on `mxx`, `myy`, and component sampling factors confirms its role in image buffer creation.

    * **`processSOS(n int) error`:**  "SOS" likely refers to "Start of Scan" marker in the JPEG format. The function validates the SOS marker's length and content. It iterates through the components, checking for valid component selectors, DC/AC table assignments, and sampling factors. The handling of `zigStart`, `zigEnd`, `ah`, `al` strongly points to supporting both sequential and progressive JPEG decoding. The core decoding loop (iterating through MCUs and blocks) is within this function, indicating its central role in processing the compressed image data. The interaction with `d.bits` and Huffman decoding further reinforces this.

    * **`refine(b *block, h *huffman, zigStart, zigEnd, delta int32) error`:** The name "refine" and the parameters suggest this function deals with progressive JPEG decoding, specifically refining previously decoded coefficients. The handling of DC and AC components differently within refinement confirms this.

    * **`refineNonZeroes(b *block, zig, zigEnd, nz, delta int32) (int32, error)`:** This function seems to be a helper for `refine`, focusing on the logic of refining non-zero coefficients in the block.

    * **`reconstructProgressiveImage() error`:** The name clearly states its purpose. It iterates through the previously decoded coefficients (stored in `d.progCoeffs`) and calls `reconstructBlock` to finalize the image data.

    * **`reconstructBlock(b *block, bx, by, compIndex int) error`:** This function performs the final steps of decoding a block: dequantization (using `d.quant`), inverse DCT (`idct`), level shifting, and clipping, before writing the pixel data to the image buffer. The handling of different component indices (0 for Y, 1 for Cb, 2 for Cr) is evident.

    * **`findRST(expectedRST uint8) error`:** "RST" likely refers to "Restart" markers. This function is responsible for finding the next expected restart marker in the bitstream, which is crucial for error recovery in JPEG decoding.

4. **Identifying Core Functionality:** Based on the function analysis, the core functionalities are:

    * **Image Buffer Allocation (`makeImg`)**
    * **Processing the Start of Scan (SOS) marker and decoding the compressed data (`processSOS`)**
    * **Handling progressive JPEG decoding refinements (`refine`, `refineNonZeroes`, `reconstructProgressiveImage`)**
    * **Reconstructing a decoded block into pixel data (`reconstructBlock`)**
    * **Finding Restart Markers for error recovery (`findRST`)**

5. **Inferring Go Feature Implementation:**  The code heavily utilizes:

    * **Structs:**  The `decoder` struct holds the decoding state.
    * **Pointers:** Used extensively for modifying data in place (e.g., `*block`).
    * **Slices:** For representing image data (`d.img1.Pix`, `d.img3.Y`, etc.).
    * **Error Handling:** Using the `error` interface and returning specific error types (e.g., `FormatError`, `UnsupportedError`).
    * **Switch Statements:** For handling different chroma subsampling ratios and component indices.
    * **Bit Manipulation:**  Implicit in the Huffman decoding and restart marker handling (although the explicit bit decoding functions aren't shown in this snippet).

6. **Crafting Examples:**  Based on the inferred functionalities, create simple Go code examples demonstrating the use of the `jpeg` package for both basic (sequential) and progressive JPEG decoding. This involves creating a decoder, parsing headers, and accessing the decoded image data.

7. **Considering User Errors:**  Think about common pitfalls users might encounter when using this functionality. Examples include:

    * **Incorrect File Paths:** A basic programming error.
    * **Corrupted JPEG Files:** Leading to decoding errors.
    * **Handling Progressive vs. Sequential:**  Users might not be aware of the differences and how the decoding process might vary.

8. **Structuring the Answer:** Organize the information logically, starting with the overall functionalities, then delving into specific functions, illustrating with code examples, and finally addressing potential user errors. Use clear and concise language.

9. **Review and Refine:**  Read through the answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas where more explanation might be needed. For example, initially, I might have just said "decodes JPEG," but the request asks for more granular detail, so breaking it down function by function is crucial. Also, ensuring the code examples are runnable and illustrative is important. Adding comments to the examples enhances understanding.
这段代码是 Go 语言 `image/jpeg` 标准库中用于 JPEG 解码过程中的扫描线处理部分 (`scan.go`)。它主要负责解析 JPEG 图像数据中的扫描（scan）部分，并将其解码为图像数据。

以下是它列举的功能：

1. **图像内存分配和初始化 (`makeImg` 函数):**
   - 根据 JPEG 图像的组件数量 (`d.nComp`) 和采样比例，分配并初始化目标图像的内存。
   - 如果是单通道（灰度）图像，则创建 `image.Gray` 类型的图像。
   - 如果是多通道（通常是 YCbCr）图像，则创建 `image.YCbCr` 类型的图像，并根据采样比例（例如 4:4:4, 4:2:0 等）设置 `YCbCrSubsampleRatio`。
   - 如果是四通道图像，还会分配额外的 `blackPix` 用于存储第四个通道的数据。

2. **处理扫描开始 (Start Of Scan, SOS) 标记 (`processSOS` 函数):**
   - 解析 JPEG 数据流中的 SOS 标记。
   - 验证 SOS 标记的长度和内容是否符合 JPEG 规范。
   - 读取扫描组件的信息，包括组件选择器、DC 和 AC 系数的霍夫曼表选择器。
   - 检查组件选择器是否有效且唯一。
   - 验证 DC 和 AC 霍夫曼表选择器是否有效。
   - 对于多组件扫描，检查总采样因子是否过大。
   - 处理渐进式 JPEG 的光谱选择 (`zigStart`, `zigEnd`) 和逐次逼近 (`ah`, `al`) 参数。
   - 计算图像中最小编码单元 (MCU) 的数量 (`mxx`, `myy`)。
   - 如果尚未创建图像，则调用 `makeImg` 分配内存。
   - 对于渐进式 JPEG，如果需要，初始化用于存储部分解码系数的 `d.progCoeffs`。
   - 初始化位读取器 (`d.bits`)。
   - 进入解码循环，逐个 MCU 和块地解码图像数据。
   - 在解码循环中，根据是否是渐进式 JPEG 以及扫描的类型（交错或非交错），确定要解码的块的位置。
   - 如果是渐进式 JPEG，加载之前部分解码的系数。
   - 根据渐进式参数 (`ah`)，选择调用 `refine` 函数进行系数细化，或者直接解码 DC 和 AC 系数。
   - 解码 DC 系数：读取霍夫曼码字，接收扩展位，并更新 DC 系数值。
   - 解码 AC 系数：读取霍夫曼码字，接收扩展位，并存储到块中。
   - 如果是顺序式 JPEG，解码完成后调用 `reconstructBlock` 重构图像块。
   - 处理重启间隔 (Restart Interval, RI) 标记，如果遇到，则查找并同步下一个 RST 标记，并重置霍夫曼解码器和 DC 系数。

3. **细化系数 (用于渐进式 JPEG) (`refine` 函数):**
   - 用于渐进式 JPEG 的逐次逼近解码，用于细化之前解码的系数。
   - 对于 DC 系数，读取一位，如果为 1，则将 `delta` 值加到系数上。
   - 对于 AC 系数，读取霍夫曼码字，并根据其值来决定是否需要细化系数。
   - 调用 `refineNonZeroes` 函数来细化非零系数。

4. **细化非零系数 (用于渐进式 JPEG) (`refineNonZeroes` 函数):**
   - `refine` 函数的辅助函数，用于细化块中非零的 AC 系数。
   - 按照 Z 字形顺序遍历系数，如果系数非零，则读取一位，并根据该位来增加或减少系数的值。

5. **重构渐进式图像 (`reconstructProgressiveImage` 函数):**
   - 在所有 SOS 标记处理完成后，用于将渐进式解码得到的系数重构为完整的图像。
   - 遍历所有组件和块，调用 `reconstructBlock` 函数来重构每个块。

6. **重构图像块 (`reconstructBlock` 函数):**
   - 对解码后的系数进行反量化。
   - 执行逆离散余弦变换 (IDCT)。
   - 将变换后的值进行电平偏移 (+128) 并裁剪到 [0, 255] 范围内。
   - 将像素值写入目标图像的对应位置。

7. **查找 RST 标记 (`findRST` 函数):**
   - 用于在数据流中查找下一个预期的 RST (Restart) 标记。
   - 当解码过程中遇到错误或到达重启间隔时，可以使用此函数来尝试重新同步解码器。
   - 它会跳过无效的字节，直到找到预期的 RST 标记。

**推断的 Go 语言功能实现及代码示例:**

这段代码是 `image/jpeg` 包内部实现的一部分，使用者通常不会直接调用这些函数。使用者会通过 `image.Decode` 函数来解码 JPEG 图像，而 `image.Decode` 内部会调用这里的解码逻辑。

**示例代码：**

```go
package main

import (
	"fmt"
	"image"
	"image/jpeg"
	"os"
)

func main() {
	// 假设有一个名为 "test.jpg" 的 JPEG 文件
	file, err := os.Open("test.jpg")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// 使用 image.Decode 解码 JPEG 图像
	img, err := jpeg.Decode(file)
	if err != nil {
		fmt.Println("Error decoding JPEG:", err)
		return
	}

	// 获取图像的边界
	bounds := img.Bounds()
	fmt.Printf("Decoded image dimensions: %dx%d\n", bounds.Max.X, bounds.Max.Y)

	// 可以进一步处理解码后的图像，例如保存为其他格式
	// ...
}
```

**假设的输入与输出：**

假设 `test.jpg` 是一个 640x480 的标准 JPEG 文件。

**输入:** `test.jpg` 文件的二进制数据。

**输出:**
- `jpeg.Decode(file)` 函数成功返回一个 `image.Image` 接口类型的实例，其中包含了 `test.jpg` 解码后的像素数据。
- 控制台输出：`Decoded image dimensions: 640x480`

**命令行参数处理：**

这段代码本身并不直接处理命令行参数。JPEG 解码通常是通过 `image.Decode` 函数完成的，该函数接收一个 `io.Reader` 接口作为输入，可以是打开的文件、网络连接等。 命令行参数的处理通常在调用 `image.Decode` 的上层代码中完成。例如，使用 `flag` 包来解析命令行参数以获取 JPEG 文件路径。

**使用者易犯错的点：**

1. **误解解码过程:**  使用者可能会误以为需要手动调用 `processSOS` 或其他内部函数来解码 JPEG。实际上，应该使用 `jpeg.Decode` 或 `image.Decode`。

   ```go
   // 错误的做法：尝试直接使用内部的解码器结构
   // decoder := jpeg.decoder{}
   // decoder.processSOS(...) // 错误！

   // 正确的做法：使用 jpeg.Decode
   file, _ := os.Open("image.jpg")
   img, err := jpeg.Decode(file)
   // ...
   ```

2. **文件 I/O 错误处理不足:**  打开 JPEG 文件时可能会发生错误，解码过程中也可能遇到损坏的数据。使用者需要妥善处理这些错误。

   ```go
   file, err := os.Open("image.jpg")
   if err != nil {
       fmt.Println("Error opening file:", err)
       return
   }
   defer file.Close()

   img, err := jpeg.Decode(file)
   if err != nil {
       fmt.Println("Error decoding image:", err)
       return
   }
   ```

3. **对渐进式 JPEG 的处理不当:** 虽然 `jpeg.Decode` 会自动处理渐进式 JPEG，但如果使用者需要深入了解解码过程，可能会对渐进式 JPEG 的多遍解码和系数细化感到困惑。

这段代码是 JPEG 解码器核心逻辑的一部分，它负责从压缩的 JPEG 数据中提取并重建图像信息。理解其功能有助于深入了解 JPEG 解码的原理。

Prompt: 
```
这是路径为go/src/image/jpeg/scan.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jpeg

import (
	"image"
)

// makeImg allocates and initializes the destination image.
func (d *decoder) makeImg(mxx, myy int) {
	if d.nComp == 1 {
		m := image.NewGray(image.Rect(0, 0, 8*mxx, 8*myy))
		d.img1 = m.SubImage(image.Rect(0, 0, d.width, d.height)).(*image.Gray)
		return
	}

	h0 := d.comp[0].h
	v0 := d.comp[0].v
	hRatio := h0 / d.comp[1].h
	vRatio := v0 / d.comp[1].v
	var subsampleRatio image.YCbCrSubsampleRatio
	switch hRatio<<4 | vRatio {
	case 0x11:
		subsampleRatio = image.YCbCrSubsampleRatio444
	case 0x12:
		subsampleRatio = image.YCbCrSubsampleRatio440
	case 0x21:
		subsampleRatio = image.YCbCrSubsampleRatio422
	case 0x22:
		subsampleRatio = image.YCbCrSubsampleRatio420
	case 0x41:
		subsampleRatio = image.YCbCrSubsampleRatio411
	case 0x42:
		subsampleRatio = image.YCbCrSubsampleRatio410
	default:
		panic("unreachable")
	}
	m := image.NewYCbCr(image.Rect(0, 0, 8*h0*mxx, 8*v0*myy), subsampleRatio)
	d.img3 = m.SubImage(image.Rect(0, 0, d.width, d.height)).(*image.YCbCr)

	if d.nComp == 4 {
		h3, v3 := d.comp[3].h, d.comp[3].v
		d.blackPix = make([]byte, 8*h3*mxx*8*v3*myy)
		d.blackStride = 8 * h3 * mxx
	}
}

// Specified in section B.2.3.
func (d *decoder) processSOS(n int) error {
	if d.nComp == 0 {
		return FormatError("missing SOF marker")
	}
	if n < 6 || 4+2*d.nComp < n || n%2 != 0 {
		return FormatError("SOS has wrong length")
	}
	if err := d.readFull(d.tmp[:n]); err != nil {
		return err
	}
	nComp := int(d.tmp[0])
	if n != 4+2*nComp {
		return FormatError("SOS length inconsistent with number of components")
	}
	var scan [maxComponents]struct {
		compIndex uint8
		td        uint8 // DC table selector.
		ta        uint8 // AC table selector.
	}
	totalHV := 0
	for i := 0; i < nComp; i++ {
		cs := d.tmp[1+2*i] // Component selector.
		compIndex := -1
		for j, comp := range d.comp[:d.nComp] {
			if cs == comp.c {
				compIndex = j
			}
		}
		if compIndex < 0 {
			return FormatError("unknown component selector")
		}
		scan[i].compIndex = uint8(compIndex)
		// Section B.2.3 states that "the value of Cs_j shall be different from
		// the values of Cs_1 through Cs_(j-1)". Since we have previously
		// verified that a frame's component identifiers (C_i values in section
		// B.2.2) are unique, it suffices to check that the implicit indexes
		// into d.comp are unique.
		for j := 0; j < i; j++ {
			if scan[i].compIndex == scan[j].compIndex {
				return FormatError("repeated component selector")
			}
		}
		totalHV += d.comp[compIndex].h * d.comp[compIndex].v

		// The baseline t <= 1 restriction is specified in table B.3.
		scan[i].td = d.tmp[2+2*i] >> 4
		if t := scan[i].td; t > maxTh || (d.baseline && t > 1) {
			return FormatError("bad Td value")
		}
		scan[i].ta = d.tmp[2+2*i] & 0x0f
		if t := scan[i].ta; t > maxTh || (d.baseline && t > 1) {
			return FormatError("bad Ta value")
		}
	}
	// Section B.2.3 states that if there is more than one component then the
	// total H*V values in a scan must be <= 10.
	if d.nComp > 1 && totalHV > 10 {
		return FormatError("total sampling factors too large")
	}

	// zigStart and zigEnd are the spectral selection bounds.
	// ah and al are the successive approximation high and low values.
	// The spec calls these values Ss, Se, Ah and Al.
	//
	// For progressive JPEGs, these are the two more-or-less independent
	// aspects of progression. Spectral selection progression is when not
	// all of a block's 64 DCT coefficients are transmitted in one pass.
	// For example, three passes could transmit coefficient 0 (the DC
	// component), coefficients 1-5, and coefficients 6-63, in zig-zag
	// order. Successive approximation is when not all of the bits of a
	// band of coefficients are transmitted in one pass. For example,
	// three passes could transmit the 6 most significant bits, followed
	// by the second-least significant bit, followed by the least
	// significant bit.
	//
	// For sequential JPEGs, these parameters are hard-coded to 0/63/0/0, as
	// per table B.3.
	zigStart, zigEnd, ah, al := int32(0), int32(blockSize-1), uint32(0), uint32(0)
	if d.progressive {
		zigStart = int32(d.tmp[1+2*nComp])
		zigEnd = int32(d.tmp[2+2*nComp])
		ah = uint32(d.tmp[3+2*nComp] >> 4)
		al = uint32(d.tmp[3+2*nComp] & 0x0f)
		if (zigStart == 0 && zigEnd != 0) || zigStart > zigEnd || blockSize <= zigEnd {
			return FormatError("bad spectral selection bounds")
		}
		if zigStart != 0 && nComp != 1 {
			return FormatError("progressive AC coefficients for more than one component")
		}
		if ah != 0 && ah != al+1 {
			return FormatError("bad successive approximation values")
		}
	}

	// mxx and myy are the number of MCUs (Minimum Coded Units) in the image.
	h0, v0 := d.comp[0].h, d.comp[0].v // The h and v values from the Y components.
	mxx := (d.width + 8*h0 - 1) / (8 * h0)
	myy := (d.height + 8*v0 - 1) / (8 * v0)
	if d.img1 == nil && d.img3 == nil {
		d.makeImg(mxx, myy)
	}
	if d.progressive {
		for i := 0; i < nComp; i++ {
			compIndex := scan[i].compIndex
			if d.progCoeffs[compIndex] == nil {
				d.progCoeffs[compIndex] = make([]block, mxx*myy*d.comp[compIndex].h*d.comp[compIndex].v)
			}
		}
	}

	d.bits = bits{}
	mcu, expectedRST := 0, uint8(rst0Marker)
	var (
		// b is the decoded coefficients, in natural (not zig-zag) order.
		b  block
		dc [maxComponents]int32
		// bx and by are the location of the current block, in units of 8x8
		// blocks: the third block in the first row has (bx, by) = (2, 0).
		bx, by     int
		blockCount int
	)
	for my := 0; my < myy; my++ {
		for mx := 0; mx < mxx; mx++ {
			for i := 0; i < nComp; i++ {
				compIndex := scan[i].compIndex
				hi := d.comp[compIndex].h
				vi := d.comp[compIndex].v
				for j := 0; j < hi*vi; j++ {
					// The blocks are traversed one MCU at a time. For 4:2:0 chroma
					// subsampling, there are four Y 8x8 blocks in every 16x16 MCU.
					//
					// For a sequential 32x16 pixel image, the Y blocks visiting order is:
					//	0 1 4 5
					//	2 3 6 7
					//
					// For progressive images, the interleaved scans (those with nComp > 1)
					// are traversed as above, but non-interleaved scans are traversed left
					// to right, top to bottom:
					//	0 1 2 3
					//	4 5 6 7
					// Only DC scans (zigStart == 0) can be interleaved. AC scans must have
					// only one component.
					//
					// To further complicate matters, for non-interleaved scans, there is no
					// data for any blocks that are inside the image at the MCU level but
					// outside the image at the pixel level. For example, a 24x16 pixel 4:2:0
					// progressive image consists of two 16x16 MCUs. The interleaved scans
					// will process 8 Y blocks:
					//	0 1 4 5
					//	2 3 6 7
					// The non-interleaved scans will process only 6 Y blocks:
					//	0 1 2
					//	3 4 5
					if nComp != 1 {
						bx = hi*mx + j%hi
						by = vi*my + j/hi
					} else {
						q := mxx * hi
						bx = blockCount % q
						by = blockCount / q
						blockCount++
						if bx*8 >= d.width || by*8 >= d.height {
							continue
						}
					}

					// Load the previous partially decoded coefficients, if applicable.
					if d.progressive {
						b = d.progCoeffs[compIndex][by*mxx*hi+bx]
					} else {
						b = block{}
					}

					if ah != 0 {
						if err := d.refine(&b, &d.huff[acTable][scan[i].ta], zigStart, zigEnd, 1<<al); err != nil {
							return err
						}
					} else {
						zig := zigStart
						if zig == 0 {
							zig++
							// Decode the DC coefficient, as specified in section F.2.2.1.
							value, err := d.decodeHuffman(&d.huff[dcTable][scan[i].td])
							if err != nil {
								return err
							}
							if value > 16 {
								return UnsupportedError("excessive DC component")
							}
							dcDelta, err := d.receiveExtend(value)
							if err != nil {
								return err
							}
							dc[compIndex] += dcDelta
							b[0] = dc[compIndex] << al
						}

						if zig <= zigEnd && d.eobRun > 0 {
							d.eobRun--
						} else {
							// Decode the AC coefficients, as specified in section F.2.2.2.
							huff := &d.huff[acTable][scan[i].ta]
							for ; zig <= zigEnd; zig++ {
								value, err := d.decodeHuffman(huff)
								if err != nil {
									return err
								}
								val0 := value >> 4
								val1 := value & 0x0f
								if val1 != 0 {
									zig += int32(val0)
									if zig > zigEnd {
										break
									}
									ac, err := d.receiveExtend(val1)
									if err != nil {
										return err
									}
									b[unzig[zig]] = ac << al
								} else {
									if val0 != 0x0f {
										d.eobRun = uint16(1 << val0)
										if val0 != 0 {
											bits, err := d.decodeBits(int32(val0))
											if err != nil {
												return err
											}
											d.eobRun |= uint16(bits)
										}
										d.eobRun--
										break
									}
									zig += 0x0f
								}
							}
						}
					}

					if d.progressive {
						// Save the coefficients.
						d.progCoeffs[compIndex][by*mxx*hi+bx] = b
						// At this point, we could call reconstructBlock to dequantize and perform the
						// inverse DCT, to save early stages of a progressive image to the *image.YCbCr
						// buffers (the whole point of progressive encoding), but in Go, the jpeg.Decode
						// function does not return until the entire image is decoded, so we "continue"
						// here to avoid wasted computation. Instead, reconstructBlock is called on each
						// accumulated block by the reconstructProgressiveImage method after all of the
						// SOS markers are processed.
						continue
					}
					if err := d.reconstructBlock(&b, bx, by, int(compIndex)); err != nil {
						return err
					}
				} // for j
			} // for i
			mcu++
			if d.ri > 0 && mcu%d.ri == 0 && mcu < mxx*myy {
				// For well-formed input, the RST[0-7] restart marker follows
				// immediately. For corrupt input, call findRST to try to
				// resynchronize.
				if err := d.readFull(d.tmp[:2]); err != nil {
					return err
				} else if d.tmp[0] != 0xff || d.tmp[1] != expectedRST {
					if err := d.findRST(expectedRST); err != nil {
						return err
					}
				}
				expectedRST++
				if expectedRST == rst7Marker+1 {
					expectedRST = rst0Marker
				}
				// Reset the Huffman decoder.
				d.bits = bits{}
				// Reset the DC components, as per section F.2.1.3.1.
				dc = [maxComponents]int32{}
				// Reset the progressive decoder state, as per section G.1.2.2.
				d.eobRun = 0
			}
		} // for mx
	} // for my

	return nil
}

// refine decodes a successive approximation refinement block, as specified in
// section G.1.2.
func (d *decoder) refine(b *block, h *huffman, zigStart, zigEnd, delta int32) error {
	// Refining a DC component is trivial.
	if zigStart == 0 {
		if zigEnd != 0 {
			panic("unreachable")
		}
		bit, err := d.decodeBit()
		if err != nil {
			return err
		}
		if bit {
			b[0] |= delta
		}
		return nil
	}

	// Refining AC components is more complicated; see sections G.1.2.2 and G.1.2.3.
	zig := zigStart
	if d.eobRun == 0 {
	loop:
		for ; zig <= zigEnd; zig++ {
			z := int32(0)
			value, err := d.decodeHuffman(h)
			if err != nil {
				return err
			}
			val0 := value >> 4
			val1 := value & 0x0f

			switch val1 {
			case 0:
				if val0 != 0x0f {
					d.eobRun = uint16(1 << val0)
					if val0 != 0 {
						bits, err := d.decodeBits(int32(val0))
						if err != nil {
							return err
						}
						d.eobRun |= uint16(bits)
					}
					break loop
				}
			case 1:
				z = delta
				bit, err := d.decodeBit()
				if err != nil {
					return err
				}
				if !bit {
					z = -z
				}
			default:
				return FormatError("unexpected Huffman code")
			}

			zig, err = d.refineNonZeroes(b, zig, zigEnd, int32(val0), delta)
			if err != nil {
				return err
			}
			if zig > zigEnd {
				return FormatError("too many coefficients")
			}
			if z != 0 {
				b[unzig[zig]] = z
			}
		}
	}
	if d.eobRun > 0 {
		d.eobRun--
		if _, err := d.refineNonZeroes(b, zig, zigEnd, -1, delta); err != nil {
			return err
		}
	}
	return nil
}

// refineNonZeroes refines non-zero entries of b in zig-zag order. If nz >= 0,
// the first nz zero entries are skipped over.
func (d *decoder) refineNonZeroes(b *block, zig, zigEnd, nz, delta int32) (int32, error) {
	for ; zig <= zigEnd; zig++ {
		u := unzig[zig]
		if b[u] == 0 {
			if nz == 0 {
				break
			}
			nz--
			continue
		}
		bit, err := d.decodeBit()
		if err != nil {
			return 0, err
		}
		if !bit {
			continue
		}
		if b[u] >= 0 {
			b[u] += delta
		} else {
			b[u] -= delta
		}
	}
	return zig, nil
}

func (d *decoder) reconstructProgressiveImage() error {
	// The h0, mxx, by and bx variables have the same meaning as in the
	// processSOS method.
	h0 := d.comp[0].h
	mxx := (d.width + 8*h0 - 1) / (8 * h0)
	for i := 0; i < d.nComp; i++ {
		if d.progCoeffs[i] == nil {
			continue
		}
		v := 8 * d.comp[0].v / d.comp[i].v
		h := 8 * d.comp[0].h / d.comp[i].h
		stride := mxx * d.comp[i].h
		for by := 0; by*v < d.height; by++ {
			for bx := 0; bx*h < d.width; bx++ {
				if err := d.reconstructBlock(&d.progCoeffs[i][by*stride+bx], bx, by, i); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// reconstructBlock dequantizes, performs the inverse DCT and stores the block
// to the image.
func (d *decoder) reconstructBlock(b *block, bx, by, compIndex int) error {
	qt := &d.quant[d.comp[compIndex].tq]
	for zig := 0; zig < blockSize; zig++ {
		b[unzig[zig]] *= qt[zig]
	}
	idct(b)
	dst, stride := []byte(nil), 0
	if d.nComp == 1 {
		dst, stride = d.img1.Pix[8*(by*d.img1.Stride+bx):], d.img1.Stride
	} else {
		switch compIndex {
		case 0:
			dst, stride = d.img3.Y[8*(by*d.img3.YStride+bx):], d.img3.YStride
		case 1:
			dst, stride = d.img3.Cb[8*(by*d.img3.CStride+bx):], d.img3.CStride
		case 2:
			dst, stride = d.img3.Cr[8*(by*d.img3.CStride+bx):], d.img3.CStride
		case 3:
			dst, stride = d.blackPix[8*(by*d.blackStride+bx):], d.blackStride
		default:
			return UnsupportedError("too many components")
		}
	}
	// Level shift by +128, clip to [0, 255], and write to dst.
	for y := 0; y < 8; y++ {
		y8 := y * 8
		yStride := y * stride
		for x := 0; x < 8; x++ {
			c := b[y8+x]
			if c < -128 {
				c = 0
			} else if c > 127 {
				c = 255
			} else {
				c += 128
			}
			dst[yStride+x] = uint8(c)
		}
	}
	return nil
}

// findRST advances past the next RST restart marker that matches expectedRST.
// Other than I/O errors, it is also an error if we encounter an {0xFF, M}
// two-byte marker sequence where M is not 0x00, 0xFF or the expectedRST.
//
// This is similar to libjpeg's jdmarker.c's next_marker function.
// https://github.com/libjpeg-turbo/libjpeg-turbo/blob/2dfe6c0fe9e18671105e94f7cbf044d4a1d157e6/jdmarker.c#L892-L935
//
// Precondition: d.tmp[:2] holds the next two bytes of JPEG-encoded input
// (input in the d.readFull sense).
func (d *decoder) findRST(expectedRST uint8) error {
	for {
		// i is the index such that, at the bottom of the loop, we read 2-i
		// bytes into d.tmp[i:2], maintaining the invariant that d.tmp[:2]
		// holds the next two bytes of JPEG-encoded input. It is either 0 or 1,
		// so that each iteration advances by 1 or 2 bytes (or returns).
		i := 0

		if d.tmp[0] == 0xff {
			if d.tmp[1] == expectedRST {
				return nil
			} else if d.tmp[1] == 0xff {
				i = 1
			} else if d.tmp[1] != 0x00 {
				// libjpeg's jdmarker.c's jpeg_resync_to_restart does something
				// fancy here, treating RST markers within two (modulo 8) of
				// expectedRST differently from RST markers that are 'more
				// distant'. Until we see evidence that recovering from such
				// cases is frequent enough to be worth the complexity, we take
				// a simpler approach for now. Any marker that's not 0x00, 0xff
				// or expectedRST is a fatal FormatError.
				return FormatError("bad RST marker")
			}

		} else if d.tmp[1] == 0xff {
			d.tmp[0] = 0xff
			i = 1
		}

		if err := d.readFull(d.tmp[i:2]); err != nil {
			return err
		}
	}
}

"""



```