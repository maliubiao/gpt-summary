Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The filename `draw_test.go` immediately suggests this code is part of the testing framework for the `image/draw` package in Go. The `package draw` declaration confirms this. The presence of `import "testing"` reinforces this.

2. **Examine Top-Level Declarations:**  Look at the globally defined types and functions.

   * **`slowestRGBA` and `slowerRGBA`:** These are custom image types that resemble `image.RGBA` but are explicitly designed *not* to trigger the optimized paths in the `draw` package. The comments clearly state this purpose. The difference between them is the implementation of `RGBA64Image` interface. This immediately signals a focus on performance testing and ensuring different code paths are exercised.

   * **`convertToSlowestRGBA` and `convertToSlowerRGBA`:** These functions convert a general `image.Image` to the custom `slowestRGBA` and `slowerRGBA` types. This supports the idea of testing different implementations.

   * **`eq`:** This is a helper function to compare colors, ensuring all color components are equal. It uses `RGBA()` which implies a focus on comparing colors after any potential color model conversions.

   * **`fillBlue`, `fillAlpha`, `vgradGreen`, `vgradAlpha`, `vgradGreenNRGBA`, `vgradCr`, `vgradGray`, `vgradMagenta`, `hgradRed`, `gradYellow`:** These are helper functions that create different kinds of test images (uniform colors, gradients, different color models). This indicates a comprehensive set of test scenarios.

   * **`drawTest` struct:** This defines the structure of a test case, including a description, source and mask images, the drawing operation, and the expected resulting color at a specific point.

   * **`drawTests` slice:** This is a collection of `drawTest` instances, outlining various drawing scenarios. Scanning the contents shows tests for different blend modes (`Over`, `Src`), different mask types (uniform, variable, nil), and different source image types (RGBA, NRGBA, YCbCr, Gray, CMYK, and the custom `slowerRGBA` and `slowestRGBA`).

   * **`makeGolden`:** This function implements a "golden" or reference implementation of the drawing operation. It's designed to be correct but potentially slower, serving as a ground truth for comparing against the optimized `draw` package functions.

   * **`TestDraw`:** This is the primary test function. It iterates through various destination rectangles (`rr`) and test cases (`drawTests`). It tests the `DrawMask` function, comparing the results against the `makeGolden` output. The loop with `i < 3` suggests testing with standard `image.RGBA`, `slowerRGBA`, and `slowestRGBA` as destinations.

   * **`TestDrawOverlap`:**  This function specifically tests scenarios where the source and destination images overlap, which can introduce edge cases and require careful implementation.

   * **`TestNonZeroSrcPt`:** Tests drawing with a source point that isn't (0,0).

   * **`TestFill`:** Tests filling areas of an image with a uniform color using `DrawMask`. It tests filling pixel by pixel, row by row, column by column, and the entire area at once.

   * **`TestDrawSrcNonpremultiplied`:** This function focuses on testing how the `Draw` function handles non-premultiplied alpha color images (`image.NRGBA` and `image.NRGBA64`). This is crucial because non-premultiplied alpha requires different blending calculations.

   * **`TestFloydSteinbergCheckerboard`:** Tests the `FloydSteinberg` dithering algorithm. The specific test case checks if a 50% gray image is dithered into a checkerboard pattern with a black and white palette.

   * **`embeddedPaletted` struct:** This is a wrapper around `image.Paletted`.

   * **`TestPaletted`:** Tests that the drawing functions work correctly even when the destination is a type that *embeds* `image.Paletted` rather than being directly a `*image.Paletted`.

   * **`TestSqDiff`:** Tests the `sqDiff` helper function, likely used internally for color difference calculations. It compares it against a known correct implementation and uses property-based testing (`quick.CheckEqual`).

3. **Infer Functionality and Purpose:** Based on the identified components, the primary function of this code is to rigorously test the `image/draw` package in Go. It checks:

   * **Correctness of blending operations:** By comparing the output of `DrawMask` against the `makeGolden` implementation for various blend modes and image types.
   * **Performance considerations:** By using `slowerRGBA` and `slowestRGBA` to ensure different code paths are executed and the optimized paths are indeed faster but produce the same results.
   * **Handling of different image types:** RGBA, NRGBA, YCbCr, Gray, CMYK, and Paletted images are all tested as sources. The tests also check if the destination image type matters.
   * **Edge cases:** Overlapping source and destination regions, non-zero source points, and operations on sub-images are explicitly tested.
   * **Specific drawing algorithms:** The `FloydSteinberg` dithering algorithm is specifically tested.
   * **Color model handling:** Tests ensure correct handling of premultiplied and non-premultiplied alpha.

4. **Construct Examples and Explanations:**  Once the functionality is understood, it's possible to create code examples that demonstrate how the tested features are used. This involves selecting relevant test cases or creating simplified versions. For example, the `TestDraw` function clearly shows the usage of `DrawMask` with different parameters.

5. **Identify Potential Pitfalls:**  Analyzing the test cases and the design of the `slowerRGBA` and `slowestRGBA` types can reveal common mistakes users might make. For example, the existence of these types highlights the potential performance differences when using non-standard image types with the `draw` package. The tests for overlapping regions highlight the importance of understanding how `DrawMask` handles such situations.

6. **Review and Refine:** Finally, review the generated explanations and examples for clarity, accuracy, and completeness. Ensure the language is accessible and addresses the specific requirements of the prompt. For instance, explicitly mention that the code is *testing* the `image/draw` package.

This systematic approach allows for a thorough understanding of the code and the ability to generate comprehensive and informative answers.
这是一个 Go 语言的测试文件，路径为 `go/src/image/draw/draw_test.go`，它用于测试 `image/draw` 包的功能。  从代码内容来看，它主要涵盖了以下功能测试：

**1. `Draw` 和 `DrawMask` 函数的基本功能测试：**

*   测试了在不同的目标图像 (`dst`) 上使用不同的源图像 (`src`)、遮罩 (`mask`) 和 Porter-Duff 合成操作 (`Op`) 的结果是否符合预期。
*   目标图像的类型包括标准的 `image.RGBA` 以及自定义的 `slowerRGBA` 和 `slowestRGBA` 类型。这两种自定义类型是为了模拟性能较低的 `draw.Image` 实现，以确保 `draw` 包的优化代码路径和通用代码路径都能正确工作。
*   源图像的类型包括 `image.Uniform` (单一颜色)、各种渐变图像 (`vgradGreen`, `hgradRed` 等)、以及不同颜色模型 (RGBA, NRGBA, YCbCr, Gray, CMYK) 的图像。
*   遮罩图像的类型包括 `image.Uniform` (单一透明度)、渐变透明度图像 (`vgradAlpha`) 和 `nil` (无遮罩)。
*   测试的合成操作主要有 `draw.Over` 和 `draw.Src`。
*   通过 `drawTests` 变量定义了大量的测试用例，每个用例包含一个描述、源图像、遮罩、合成操作和预期的结果颜色。

**2. `Draw` 函数处理源图像偏移 (`src Point`) 的测试 (`TestNonZeroSrcPt`)：**

*   测试了当源图像的起始点不是 (0, 0) 时，`Draw` 函数能否正确地将源图像的内容绘制到目标图像上。

**3. `Draw` 函数处理目标图像不同区域填充的测试 (`TestFill`)：**

*   测试了使用 `DrawMask` 函数填充目标图像的不同矩形区域，包括单个像素、单行、单列以及整个区域。

**4. `Draw` 函数处理非预乘 Alpha 通道的源图像的测试 (`TestDrawSrcNonpremultiplied`)：**

*   测试了当源图像是 `image.NRGBA` 或 `image.NRGBA64` 类型（非预乘 Alpha 通道）时，`Draw` 函数能否正确处理颜色合成。

**5. `FloydSteinberg` 抖动算法的测试 (`TestFloydSteinbergCheckerboard`)：**

*   测试了 `draw.FloydSteinberg` 抖动器是否能将一个均匀的 50% 灰度图像抖动成黑白棋盘格图案。

**6. 处理自定义 `Paletted` 图像类型的测试 (`TestPaletted`)：**

*   创建了一个名为 `embeddedPaletted` 的自定义类型，它嵌入了 `image.Paletted`。
*   测试了 `draw.Draw` 和 `draw.FloydSteinberg.Draw` 是否能正确处理这种自定义的调色板图像类型，确保它们与直接使用 `*image.Paletted` 的行为一致。

**7. `sqDiff` 函数的测试 (`TestSqDiff`)：**

*   测试了 `draw` 包内部使用的 `sqDiff` 函数，该函数计算两个 `int32` 值的平方差。

**它是什么 Go 语言功能的实现？**

这段代码主要测试了 Go 语言 `image/draw` 包中提供的图像绘制和合成功能。`image/draw` 包实现了各种图像合成操作，允许开发者将一个图像（源图像）绘制到另一个图像（目标图像）上，并可以指定遮罩和合成模式。 这在图像处理、图形界面编程等领域非常有用。

**Go 代码举例说明：**

假设我们要将一个红色的 10x10 的正方形绘制到一个蓝色的 20x20 的画布上，使用 `draw.Over` 合成模式。

```go
package main

import (
	"image"
	"image/color"
	"image/draw"
)

func main() {
	// 创建一个蓝色的 20x20 的目标图像
	dst := image.NewRGBA(image.Rect(0, 0, 20, 20))
	draw.Draw(dst, dst.Bounds(), &image.Uniform{color.RGBA{0, 0, 255, 255}}, image.Point{}, draw.Src)

	// 创建一个红色的 10x10 的源图像
	src := image.NewRGBA(image.Rect(0, 0, 10, 10))
	draw.Draw(src, src.Bounds(), &image.Uniform{color.RGBA{255, 0, 0, 255}}, image.Point{}, draw.Src)

	// 将红色的正方形绘制到蓝色画布的 (5, 5) 位置，使用 Over 合成模式
	draw.Draw(dst, image.Rect(5, 5, 15, 15), src, image.Point{}, draw.Over)

	// 你可以将 dst 保存为图像文件进行查看，例如使用 image/png 包
	// ...
}
```

**假设的输入与输出 (针对 `TestDraw` 中的一个用例):**

假设我们执行 `TestDraw` 中的以下测试用例：

```go
{
    desc:     "fill",
    src:      fillBlue(90), // 一个蓝色的 uniform 图像，alpha 值为 90
    mask:     fillAlpha(255), // 一个完全不透明的 mask
    op:       Over,
    expected: color.RGBA{88, 0, 90, 255}, // 预期的结果颜色
}
```

并且目标图像 `dst` 在 (8, 8) 处的初始颜色是红色 `color.RGBA{136, 0, 0, 255}`。

**输入:**

*   **目标图像 (dst):**  一个 `image.RGBA`，在矩形区域内 (8, 8) 处颜色为 `color.RGBA{136, 0, 0, 255}`。
*   **源图像 (src):**  一个 16x16 的蓝色 uniform 图像，颜色为 `color.RGBA{0, 0, 90, 90}`。
*   **遮罩 (mask):** 一个 16x16 的 uniform 图像，alpha 值为 255 (完全不透明)。
*   **操作 (op):** `draw.Over`。
*   **绘制区域:** 假设 `TestDraw` 循环遍历的矩形 `r` 包含了点 (8, 8)。

**输出 (在目标图像的 (8, 8) 处):**

*   根据 `draw.Over` 的合成规则，新的颜色计算如下：
    *   `源颜色 * 源 Alpha + 目标颜色 * (1 - 源 Alpha)`
    *   `{0, 0, 90, 90}` 的颜色可以近似看作 `RGBA{0, 0, 90, 90}`（简化计算，实际会更复杂，涉及到预乘）。
    *   假设目标颜色和源颜色都已经是非预乘的。
    *   红色分量: `0 * 90/255 + 136 * (255 - 90)/255`  ≈ `88`
    *   绿色分量: `0 * 90/255 + 0 * (255 - 90)/255` ≈ `0`
    *   蓝色分量: `90 * 90/255 + 0 * (255 - 90)/255` ≈ `31.7` （这里简化了，`fillBlue` 的实现可能直接返回带 Alpha 的颜色）
    *   Alpha 分量:  源 Alpha (因为遮罩不透明) = `90`

    实际上，`fillBlue(90)` 创建的颜色是 `color.RGBA{0, 0, 90, 90}`。使用 `draw.Over` 合成，并且遮罩完全不透明，目标像素的新颜色将是：

    *   红色: `(0 * 90 + 136 * (255 - 90)) / 255` ≈ 88
    *   绿色: `(0 * 90 + 0 * (255 - 90)) / 255` ≈ 0
    *   蓝色: `(90 * 90 + 0 * (255 - 90)) / 255` ≈ 32 (这部分计算可能需要考虑颜色模型的转换)
    *   Alpha: `90 + 255*(1 - 90/255)` = 255

    测试代码中预期的结果是 `color.RGBA{88, 0, 90, 255}`。 这表明 `draw.Over` 的实现细节会更复杂，需要考虑颜色预乘等因素。  `makeGolden` 函数提供了更精确的计算方式。

**命令行参数的具体处理：**

这个测试文件本身不涉及命令行参数的处理。它是通过 `go test` 命令来执行的。 `go test` 会自动查找并运行当前目录及其子目录下的 `*_test.go` 文件中的测试函数。

**使用者易犯错的点：**

1. **误解 `draw.Image` 接口:**  使用者可能不理解 `draw.Image` 接口的含义，错误地认为任何实现了 `image.Image` 接口的类型都可以高效地用于 `draw` 包的函数。实际上，`draw` 包针对 `*image.RGBA` 等特定类型进行了优化。使用自定义的 `draw.Image` 实现可能会导致性能下降，正如 `slowerRGBA` 和 `slowestRGBA` 所演示的。

2. **不理解 Porter-Duff 合成操作:**  不同的 `Op` 值代表不同的合成规则。使用者可能会混淆 `draw.Src` (直接替换) 和 `draw.Over` (正常混合) 等操作的效果。

3. **忽略遮罩的影响:**  遮罩图像的 Alpha 通道会影响源图像的透明度在合成时的贡献。使用者可能会忘记或错误地设置遮罩，导致合成结果与预期不符。

4. **颜色模型和预乘 Alpha 的问题:**  当处理不同颜色模型的图像 (例如 `image.NRGBA`) 时，需要理解预乘 Alpha 的概念。  直接使用非预乘的颜色值进行合成，可能得不到正确的结果。

5. **目标图像的边界和绘制区域:**  使用者需要确保绘制的区域在目标图像的边界内，否则部分或全部绘制操作可能不会生效。

**示例说明易犯错的点：**

假设使用者想将一个半透明的红色正方形绘制到一个蓝色画布上，但他错误地使用了 `draw.Src` 操作，而不是 `draw.Over`。

```go
package main

import (
	"image"
	"image/color"
	"image/draw"
)

func main() {
	// 蓝色画布
	dst := image.NewRGBA(image.Rect(0, 0, 20, 20))
	draw.Draw(dst, dst.Bounds(), &image.Uniform{color.RGBA{0, 0, 255, 255}}, image.Point{}, draw.Src)

	// 半透明的红色正方形
	src := image.NewRGBA(image.Rect(0, 0, 10, 10))
	draw.Draw(src, src.Bounds(), &image.Uniform{color.RGBA{255, 0, 0, 128}}, image.Point{}, draw.Src)

	// 错误地使用了 draw.Src
	draw.Draw(dst, image.Rect(5, 5, 15, 15), src, image.Point{}, draw.Src)

	// 使用 draw.Over 才能得到预期的混合效果
	// draw.Draw(dst, image.Rect(5, 5, 15, 15), src, image.Point{}, draw.Over)

	// ... 保存图像
}
```

在这个例子中，由于使用了 `draw.Src`，红色的正方形会直接覆盖蓝色画布上的对应区域，而不是与蓝色进行混合产生预期的半透明效果。使用者应该使用 `draw.Over` 来实现颜色的混合。

Prompt: 
```
这是路径为go/src/image/draw/draw_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package draw

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"testing"
	"testing/quick"
)

// slowestRGBA is a draw.Image like image.RGBA, but it is a different type and
// therefore does not trigger the draw.go fastest code paths.
//
// Unlike slowerRGBA, it does not implement the draw.RGBA64Image interface.
type slowestRGBA struct {
	Pix    []uint8
	Stride int
	Rect   image.Rectangle
}

func (p *slowestRGBA) ColorModel() color.Model { return color.RGBAModel }

func (p *slowestRGBA) Bounds() image.Rectangle { return p.Rect }

func (p *slowestRGBA) At(x, y int) color.Color {
	return p.RGBA64At(x, y)
}

func (p *slowestRGBA) RGBA64At(x, y int) color.RGBA64 {
	if !(image.Point{x, y}.In(p.Rect)) {
		return color.RGBA64{}
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	r := uint16(s[0])
	g := uint16(s[1])
	b := uint16(s[2])
	a := uint16(s[3])
	return color.RGBA64{
		(r << 8) | r,
		(g << 8) | g,
		(b << 8) | b,
		(a << 8) | a,
	}
}

func (p *slowestRGBA) Set(x, y int, c color.Color) {
	if !(image.Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	c1 := color.RGBAModel.Convert(c).(color.RGBA)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = c1.R
	s[1] = c1.G
	s[2] = c1.B
	s[3] = c1.A
}

func (p *slowestRGBA) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*4
}

func convertToSlowestRGBA(m image.Image) *slowestRGBA {
	if rgba, ok := m.(*image.RGBA); ok {
		return &slowestRGBA{
			Pix:    append([]byte(nil), rgba.Pix...),
			Stride: rgba.Stride,
			Rect:   rgba.Rect,
		}
	}
	rgba := image.NewRGBA(m.Bounds())
	Draw(rgba, rgba.Bounds(), m, m.Bounds().Min, Src)
	return &slowestRGBA{
		Pix:    rgba.Pix,
		Stride: rgba.Stride,
		Rect:   rgba.Rect,
	}
}

func init() {
	var p any = (*slowestRGBA)(nil)
	if _, ok := p.(RGBA64Image); ok {
		panic("slowestRGBA should not be an RGBA64Image")
	}
}

// slowerRGBA is a draw.Image like image.RGBA but it is a different type and
// therefore does not trigger the draw.go fastest code paths.
//
// Unlike slowestRGBA, it still implements the draw.RGBA64Image interface.
type slowerRGBA struct {
	Pix    []uint8
	Stride int
	Rect   image.Rectangle
}

func (p *slowerRGBA) ColorModel() color.Model { return color.RGBAModel }

func (p *slowerRGBA) Bounds() image.Rectangle { return p.Rect }

func (p *slowerRGBA) At(x, y int) color.Color {
	return p.RGBA64At(x, y)
}

func (p *slowerRGBA) RGBA64At(x, y int) color.RGBA64 {
	if !(image.Point{x, y}.In(p.Rect)) {
		return color.RGBA64{}
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	r := uint16(s[0])
	g := uint16(s[1])
	b := uint16(s[2])
	a := uint16(s[3])
	return color.RGBA64{
		(r << 8) | r,
		(g << 8) | g,
		(b << 8) | b,
		(a << 8) | a,
	}
}

func (p *slowerRGBA) Set(x, y int, c color.Color) {
	if !(image.Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	c1 := color.RGBAModel.Convert(c).(color.RGBA)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = c1.R
	s[1] = c1.G
	s[2] = c1.B
	s[3] = c1.A
}

func (p *slowerRGBA) SetRGBA64(x, y int, c color.RGBA64) {
	if !(image.Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = uint8(c.R >> 8)
	s[1] = uint8(c.G >> 8)
	s[2] = uint8(c.B >> 8)
	s[3] = uint8(c.A >> 8)
}

func (p *slowerRGBA) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*4
}

func convertToSlowerRGBA(m image.Image) *slowerRGBA {
	if rgba, ok := m.(*image.RGBA); ok {
		return &slowerRGBA{
			Pix:    append([]byte(nil), rgba.Pix...),
			Stride: rgba.Stride,
			Rect:   rgba.Rect,
		}
	}
	rgba := image.NewRGBA(m.Bounds())
	Draw(rgba, rgba.Bounds(), m, m.Bounds().Min, Src)
	return &slowerRGBA{
		Pix:    rgba.Pix,
		Stride: rgba.Stride,
		Rect:   rgba.Rect,
	}
}

func init() {
	var p any = (*slowerRGBA)(nil)
	if _, ok := p.(RGBA64Image); !ok {
		panic("slowerRGBA should be an RGBA64Image")
	}
}

func eq(c0, c1 color.Color) bool {
	r0, g0, b0, a0 := c0.RGBA()
	r1, g1, b1, a1 := c1.RGBA()
	return r0 == r1 && g0 == g1 && b0 == b1 && a0 == a1
}

func fillBlue(alpha int) image.Image {
	return image.NewUniform(color.RGBA{0, 0, uint8(alpha), uint8(alpha)})
}

func fillAlpha(alpha int) image.Image {
	return image.NewUniform(color.Alpha{uint8(alpha)})
}

func vgradGreen(alpha int) image.Image {
	m := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			m.Set(x, y, color.RGBA{0, uint8(y * alpha / 15), 0, uint8(alpha)})
		}
	}
	return m
}

func vgradAlpha(alpha int) image.Image {
	m := image.NewAlpha(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			m.Set(x, y, color.Alpha{uint8(y * alpha / 15)})
		}
	}
	return m
}

func vgradGreenNRGBA(alpha int) image.Image {
	m := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			m.Set(x, y, color.RGBA{0, uint8(y * 0x11), 0, uint8(alpha)})
		}
	}
	return m
}

func vgradCr() image.Image {
	m := &image.YCbCr{
		Y:              make([]byte, 16*16),
		Cb:             make([]byte, 16*16),
		Cr:             make([]byte, 16*16),
		YStride:        16,
		CStride:        16,
		SubsampleRatio: image.YCbCrSubsampleRatio444,
		Rect:           image.Rect(0, 0, 16, 16),
	}
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			m.Cr[y*m.CStride+x] = uint8(y * 0x11)
		}
	}
	return m
}

func vgradGray() image.Image {
	m := image.NewGray(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			m.Set(x, y, color.Gray{uint8(y * 0x11)})
		}
	}
	return m
}

func vgradMagenta() image.Image {
	m := image.NewCMYK(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			m.Set(x, y, color.CMYK{0, uint8(y * 0x11), 0, 0x3f})
		}
	}
	return m
}

func hgradRed(alpha int) Image {
	m := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			m.Set(x, y, color.RGBA{uint8(x * alpha / 15), 0, 0, uint8(alpha)})
		}
	}
	return m
}

func gradYellow(alpha int) Image {
	m := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			m.Set(x, y, color.RGBA{uint8(x * alpha / 15), uint8(y * alpha / 15), 0, uint8(alpha)})
		}
	}
	return m
}

type drawTest struct {
	desc     string
	src      image.Image
	mask     image.Image
	op       Op
	expected color.Color
}

var drawTests = []drawTest{
	// Uniform mask (0% opaque).
	{"nop", vgradGreen(255), fillAlpha(0), Over, color.RGBA{136, 0, 0, 255}},
	{"clear", vgradGreen(255), fillAlpha(0), Src, color.RGBA{0, 0, 0, 0}},
	// Uniform mask (100%, 75%, nil) and uniform source.
	// At (x, y) == (8, 8):
	// The destination pixel is {136, 0, 0, 255}.
	// The source pixel is {0, 0, 90, 90}.
	{"fill", fillBlue(90), fillAlpha(255), Over, color.RGBA{88, 0, 90, 255}},
	{"fillSrc", fillBlue(90), fillAlpha(255), Src, color.RGBA{0, 0, 90, 90}},
	{"fillAlpha", fillBlue(90), fillAlpha(192), Over, color.RGBA{100, 0, 68, 255}},
	{"fillAlphaSrc", fillBlue(90), fillAlpha(192), Src, color.RGBA{0, 0, 68, 68}},
	{"fillNil", fillBlue(90), nil, Over, color.RGBA{88, 0, 90, 255}},
	{"fillNilSrc", fillBlue(90), nil, Src, color.RGBA{0, 0, 90, 90}},
	// Uniform mask (100%, 75%, nil) and variable source.
	// At (x, y) == (8, 8):
	// The destination pixel is {136, 0, 0, 255}.
	// The source pixel is {0, 48, 0, 90}.
	{"copy", vgradGreen(90), fillAlpha(255), Over, color.RGBA{88, 48, 0, 255}},
	{"copySrc", vgradGreen(90), fillAlpha(255), Src, color.RGBA{0, 48, 0, 90}},
	{"copyAlpha", vgradGreen(90), fillAlpha(192), Over, color.RGBA{100, 36, 0, 255}},
	{"copyAlphaSrc", vgradGreen(90), fillAlpha(192), Src, color.RGBA{0, 36, 0, 68}},
	{"copyNil", vgradGreen(90), nil, Over, color.RGBA{88, 48, 0, 255}},
	{"copyNilSrc", vgradGreen(90), nil, Src, color.RGBA{0, 48, 0, 90}},
	// Uniform mask (100%, 75%, nil) and variable NRGBA source.
	// At (x, y) == (8, 8):
	// The destination pixel is {136, 0, 0, 255}.
	// The source pixel is {0, 136, 0, 90} in NRGBA-space, which is {0, 48, 0, 90} in RGBA-space.
	// The result pixel is different than in the "copy*" test cases because of rounding errors.
	{"nrgba", vgradGreenNRGBA(90), fillAlpha(255), Over, color.RGBA{88, 46, 0, 255}},
	{"nrgbaSrc", vgradGreenNRGBA(90), fillAlpha(255), Src, color.RGBA{0, 46, 0, 90}},
	{"nrgbaAlpha", vgradGreenNRGBA(90), fillAlpha(192), Over, color.RGBA{100, 34, 0, 255}},
	{"nrgbaAlphaSrc", vgradGreenNRGBA(90), fillAlpha(192), Src, color.RGBA{0, 34, 0, 68}},
	{"nrgbaNil", vgradGreenNRGBA(90), nil, Over, color.RGBA{88, 46, 0, 255}},
	{"nrgbaNilSrc", vgradGreenNRGBA(90), nil, Src, color.RGBA{0, 46, 0, 90}},
	// Uniform mask (100%, 75%, nil) and variable YCbCr source.
	// At (x, y) == (8, 8):
	// The destination pixel is {136, 0, 0, 255}.
	// The source pixel is {0, 0, 136} in YCbCr-space, which is {11, 38, 0, 255} in RGB-space.
	{"ycbcr", vgradCr(), fillAlpha(255), Over, color.RGBA{11, 38, 0, 255}},
	{"ycbcrSrc", vgradCr(), fillAlpha(255), Src, color.RGBA{11, 38, 0, 255}},
	{"ycbcrAlpha", vgradCr(), fillAlpha(192), Over, color.RGBA{42, 28, 0, 255}},
	{"ycbcrAlphaSrc", vgradCr(), fillAlpha(192), Src, color.RGBA{8, 28, 0, 192}},
	{"ycbcrNil", vgradCr(), nil, Over, color.RGBA{11, 38, 0, 255}},
	{"ycbcrNilSrc", vgradCr(), nil, Src, color.RGBA{11, 38, 0, 255}},
	// Uniform mask (100%, 75%, nil) and variable Gray source.
	// At (x, y) == (8, 8):
	// The destination pixel is {136, 0, 0, 255}.
	// The source pixel is {136} in Gray-space, which is {136, 136, 136, 255} in RGBA-space.
	{"gray", vgradGray(), fillAlpha(255), Over, color.RGBA{136, 136, 136, 255}},
	{"graySrc", vgradGray(), fillAlpha(255), Src, color.RGBA{136, 136, 136, 255}},
	{"grayAlpha", vgradGray(), fillAlpha(192), Over, color.RGBA{136, 102, 102, 255}},
	{"grayAlphaSrc", vgradGray(), fillAlpha(192), Src, color.RGBA{102, 102, 102, 192}},
	{"grayNil", vgradGray(), nil, Over, color.RGBA{136, 136, 136, 255}},
	{"grayNilSrc", vgradGray(), nil, Src, color.RGBA{136, 136, 136, 255}},
	// Same again, but with a slowerRGBA source.
	{"graySlower", convertToSlowerRGBA(vgradGray()), fillAlpha(255),
		Over, color.RGBA{136, 136, 136, 255}},
	{"graySrcSlower", convertToSlowerRGBA(vgradGray()), fillAlpha(255),
		Src, color.RGBA{136, 136, 136, 255}},
	{"grayAlphaSlower", convertToSlowerRGBA(vgradGray()), fillAlpha(192),
		Over, color.RGBA{136, 102, 102, 255}},
	{"grayAlphaSrcSlower", convertToSlowerRGBA(vgradGray()), fillAlpha(192),
		Src, color.RGBA{102, 102, 102, 192}},
	{"grayNilSlower", convertToSlowerRGBA(vgradGray()), nil,
		Over, color.RGBA{136, 136, 136, 255}},
	{"grayNilSrcSlower", convertToSlowerRGBA(vgradGray()), nil,
		Src, color.RGBA{136, 136, 136, 255}},
	// Same again, but with a slowestRGBA source.
	{"graySlowest", convertToSlowestRGBA(vgradGray()), fillAlpha(255),
		Over, color.RGBA{136, 136, 136, 255}},
	{"graySrcSlowest", convertToSlowestRGBA(vgradGray()), fillAlpha(255),
		Src, color.RGBA{136, 136, 136, 255}},
	{"grayAlphaSlowest", convertToSlowestRGBA(vgradGray()), fillAlpha(192),
		Over, color.RGBA{136, 102, 102, 255}},
	{"grayAlphaSrcSlowest", convertToSlowestRGBA(vgradGray()), fillAlpha(192),
		Src, color.RGBA{102, 102, 102, 192}},
	{"grayNilSlowest", convertToSlowestRGBA(vgradGray()), nil,
		Over, color.RGBA{136, 136, 136, 255}},
	{"grayNilSrcSlowest", convertToSlowestRGBA(vgradGray()), nil,
		Src, color.RGBA{136, 136, 136, 255}},
	// Uniform mask (100%, 75%, nil) and variable CMYK source.
	// At (x, y) == (8, 8):
	// The destination pixel is {136, 0, 0, 255}.
	// The source pixel is {0, 136, 0, 63} in CMYK-space, which is {192, 89, 192} in RGB-space.
	{"cmyk", vgradMagenta(), fillAlpha(255), Over, color.RGBA{192, 89, 192, 255}},
	{"cmykSrc", vgradMagenta(), fillAlpha(255), Src, color.RGBA{192, 89, 192, 255}},
	{"cmykAlpha", vgradMagenta(), fillAlpha(192), Over, color.RGBA{178, 67, 145, 255}},
	{"cmykAlphaSrc", vgradMagenta(), fillAlpha(192), Src, color.RGBA{145, 67, 145, 192}},
	{"cmykNil", vgradMagenta(), nil, Over, color.RGBA{192, 89, 192, 255}},
	{"cmykNilSrc", vgradMagenta(), nil, Src, color.RGBA{192, 89, 192, 255}},
	// Variable mask and uniform source.
	// At (x, y) == (8, 8):
	// The destination pixel is {136, 0, 0, 255}.
	// The source pixel is {0, 0, 255, 255}.
	// The mask pixel's alpha is 102, or 40%.
	{"generic", fillBlue(255), vgradAlpha(192), Over, color.RGBA{81, 0, 102, 255}},
	{"genericSrc", fillBlue(255), vgradAlpha(192), Src, color.RGBA{0, 0, 102, 102}},
	// Same again, but with a slowerRGBA mask.
	{"genericSlower", fillBlue(255), convertToSlowerRGBA(vgradAlpha(192)),
		Over, color.RGBA{81, 0, 102, 255}},
	{"genericSrcSlower", fillBlue(255), convertToSlowerRGBA(vgradAlpha(192)),
		Src, color.RGBA{0, 0, 102, 102}},
	// Same again, but with a slowestRGBA mask.
	{"genericSlowest", fillBlue(255), convertToSlowestRGBA(vgradAlpha(192)),
		Over, color.RGBA{81, 0, 102, 255}},
	{"genericSrcSlowest", fillBlue(255), convertToSlowestRGBA(vgradAlpha(192)),
		Src, color.RGBA{0, 0, 102, 102}},
	// Variable mask and variable source.
	// At (x, y) == (8, 8):
	// The destination pixel is {136, 0, 0, 255}.
	// The source pixel is:
	//   - {0, 48, 0, 90}.
	//   - {136} in Gray-space, which is {136, 136, 136, 255} in RGBA-space.
	// The mask pixel's alpha is 102, or 40%.
	{"rgbaVariableMaskOver", vgradGreen(90), vgradAlpha(192), Over, color.RGBA{117, 19, 0, 255}},
	{"grayVariableMaskOver", vgradGray(), vgradAlpha(192), Over, color.RGBA{136, 54, 54, 255}},
}

func makeGolden(dst image.Image, r image.Rectangle, src image.Image, sp image.Point, mask image.Image, mp image.Point, op Op) image.Image {
	// Since golden is a newly allocated image, we don't have to check if the
	// input source and mask images and the output golden image overlap.
	b := dst.Bounds()
	sb := src.Bounds()
	mb := image.Rect(-1e9, -1e9, 1e9, 1e9)
	if mask != nil {
		mb = mask.Bounds()
	}
	golden := image.NewRGBA(image.Rect(0, 0, b.Max.X, b.Max.Y))
	for y := r.Min.Y; y < r.Max.Y; y++ {
		sy := y + sp.Y - r.Min.Y
		my := y + mp.Y - r.Min.Y
		for x := r.Min.X; x < r.Max.X; x++ {
			if !(image.Pt(x, y).In(b)) {
				continue
			}
			sx := x + sp.X - r.Min.X
			if !(image.Pt(sx, sy).In(sb)) {
				continue
			}
			mx := x + mp.X - r.Min.X
			if !(image.Pt(mx, my).In(mb)) {
				continue
			}

			const M = 1<<16 - 1
			var dr, dg, db, da uint32
			if op == Over {
				dr, dg, db, da = dst.At(x, y).RGBA()
			}
			sr, sg, sb, sa := src.At(sx, sy).RGBA()
			ma := uint32(M)
			if mask != nil {
				_, _, _, ma = mask.At(mx, my).RGBA()
			}
			a := M - (sa * ma / M)
			golden.Set(x, y, color.RGBA64{
				uint16((dr*a + sr*ma) / M),
				uint16((dg*a + sg*ma) / M),
				uint16((db*a + sb*ma) / M),
				uint16((da*a + sa*ma) / M),
			})
		}
	}
	return golden.SubImage(b)
}

func TestDraw(t *testing.T) {
	rr := []image.Rectangle{
		image.Rect(0, 0, 0, 0),
		image.Rect(0, 0, 16, 16),
		image.Rect(3, 5, 12, 10),
		image.Rect(0, 0, 9, 9),
		image.Rect(8, 8, 16, 16),
		image.Rect(8, 0, 9, 16),
		image.Rect(0, 8, 16, 9),
		image.Rect(8, 8, 9, 9),
		image.Rect(8, 8, 8, 8),
	}
	for _, r := range rr {
	loop:
		for _, test := range drawTests {
			for i := 0; i < 3; i++ {
				dst := hgradRed(255).(*image.RGBA).SubImage(r).(Image)
				// For i != 0, substitute a different-typed dst that will take
				// us off the fastest code paths. We should still get the same
				// result, in terms of final pixel RGBA values.
				switch i {
				case 1:
					dst = convertToSlowerRGBA(dst)
				case 2:
					dst = convertToSlowestRGBA(dst)
				}

				// Draw the (src, mask, op) onto a copy of dst using a slow but obviously correct implementation.
				golden := makeGolden(dst, image.Rect(0, 0, 16, 16), test.src, image.Point{}, test.mask, image.Point{}, test.op)
				b := dst.Bounds()
				if !b.Eq(golden.Bounds()) {
					t.Errorf("draw %v %s on %T: bounds %v versus %v",
						r, test.desc, dst, dst.Bounds(), golden.Bounds())
					continue
				}
				// Draw the same combination onto the actual dst using the optimized DrawMask implementation.
				DrawMask(dst, image.Rect(0, 0, 16, 16), test.src, image.Point{}, test.mask, image.Point{}, test.op)
				if image.Pt(8, 8).In(r) {
					// Check that the resultant pixel at (8, 8) matches what we expect
					// (the expected value can be verified by hand).
					if !eq(dst.At(8, 8), test.expected) {
						t.Errorf("draw %v %s on %T: at (8, 8) %v versus %v",
							r, test.desc, dst, dst.At(8, 8), test.expected)
						continue
					}
				}
				// Check that the resultant dst image matches the golden output.
				for y := b.Min.Y; y < b.Max.Y; y++ {
					for x := b.Min.X; x < b.Max.X; x++ {
						if !eq(dst.At(x, y), golden.At(x, y)) {
							t.Errorf("draw %v %s on %T: at (%d, %d), %v versus golden %v",
								r, test.desc, dst, x, y, dst.At(x, y), golden.At(x, y))
							continue loop
						}
					}
				}
			}
		}
	}
}

func TestDrawOverlap(t *testing.T) {
	for _, op := range []Op{Over, Src} {
		for yoff := -2; yoff <= 2; yoff++ {
		loop:
			for xoff := -2; xoff <= 2; xoff++ {
				m := gradYellow(127).(*image.RGBA)
				dst := m.SubImage(image.Rect(5, 5, 10, 10)).(*image.RGBA)
				src := m.SubImage(image.Rect(5+xoff, 5+yoff, 10+xoff, 10+yoff)).(*image.RGBA)
				b := dst.Bounds()
				// Draw the (src, mask, op) onto a copy of dst using a slow but obviously correct implementation.
				golden := makeGolden(dst, b, src, src.Bounds().Min, nil, image.Point{}, op)
				if !b.Eq(golden.Bounds()) {
					t.Errorf("drawOverlap xoff=%d,yoff=%d: bounds %v versus %v", xoff, yoff, dst.Bounds(), golden.Bounds())
					continue
				}
				// Draw the same combination onto the actual dst using the optimized DrawMask implementation.
				DrawMask(dst, b, src, src.Bounds().Min, nil, image.Point{}, op)
				// Check that the resultant dst image matches the golden output.
				for y := b.Min.Y; y < b.Max.Y; y++ {
					for x := b.Min.X; x < b.Max.X; x++ {
						if !eq(dst.At(x, y), golden.At(x, y)) {
							t.Errorf("drawOverlap xoff=%d,yoff=%d: at (%d, %d), %v versus golden %v", xoff, yoff, x, y, dst.At(x, y), golden.At(x, y))
							continue loop
						}
					}
				}
			}
		}
	}
}

// TestNonZeroSrcPt checks drawing with a non-zero src point parameter.
func TestNonZeroSrcPt(t *testing.T) {
	a := image.NewRGBA(image.Rect(0, 0, 1, 1))
	b := image.NewRGBA(image.Rect(0, 0, 2, 2))
	b.Set(0, 0, color.RGBA{0, 0, 0, 5})
	b.Set(1, 0, color.RGBA{0, 0, 5, 5})
	b.Set(0, 1, color.RGBA{0, 5, 0, 5})
	b.Set(1, 1, color.RGBA{5, 0, 0, 5})
	Draw(a, image.Rect(0, 0, 1, 1), b, image.Pt(1, 1), Over)
	if !eq(color.RGBA{5, 0, 0, 5}, a.At(0, 0)) {
		t.Errorf("non-zero src pt: want %v got %v", color.RGBA{5, 0, 0, 5}, a.At(0, 0))
	}
}

func TestFill(t *testing.T) {
	rr := []image.Rectangle{
		image.Rect(0, 0, 0, 0),
		image.Rect(0, 0, 40, 30),
		image.Rect(10, 0, 40, 30),
		image.Rect(0, 20, 40, 30),
		image.Rect(10, 20, 40, 30),
		image.Rect(10, 20, 15, 25),
		image.Rect(10, 0, 35, 30),
		image.Rect(0, 15, 40, 16),
		image.Rect(24, 24, 25, 25),
		image.Rect(23, 23, 26, 26),
		image.Rect(22, 22, 27, 27),
		image.Rect(21, 21, 28, 28),
		image.Rect(20, 20, 29, 29),
	}
	for _, r := range rr {
		m := image.NewRGBA(image.Rect(0, 0, 40, 30)).SubImage(r).(*image.RGBA)
		b := m.Bounds()
		c := color.RGBA{11, 0, 0, 255}
		src := &image.Uniform{C: c}
		check := func(desc string) {
			for y := b.Min.Y; y < b.Max.Y; y++ {
				for x := b.Min.X; x < b.Max.X; x++ {
					if !eq(c, m.At(x, y)) {
						t.Errorf("%s fill: at (%d, %d), sub-image bounds=%v: want %v got %v", desc, x, y, r, c, m.At(x, y))
						return
					}
				}
			}
		}
		// Draw 1 pixel at a time.
		for y := b.Min.Y; y < b.Max.Y; y++ {
			for x := b.Min.X; x < b.Max.X; x++ {
				DrawMask(m, image.Rect(x, y, x+1, y+1), src, image.Point{}, nil, image.Point{}, Src)
			}
		}
		check("pixel")
		// Draw 1 row at a time.
		c = color.RGBA{0, 22, 0, 255}
		src = &image.Uniform{C: c}
		for y := b.Min.Y; y < b.Max.Y; y++ {
			DrawMask(m, image.Rect(b.Min.X, y, b.Max.X, y+1), src, image.Point{}, nil, image.Point{}, Src)
		}
		check("row")
		// Draw 1 column at a time.
		c = color.RGBA{0, 0, 33, 255}
		src = &image.Uniform{C: c}
		for x := b.Min.X; x < b.Max.X; x++ {
			DrawMask(m, image.Rect(x, b.Min.Y, x+1, b.Max.Y), src, image.Point{}, nil, image.Point{}, Src)
		}
		check("column")
		// Draw the whole image at once.
		c = color.RGBA{44, 55, 66, 77}
		src = &image.Uniform{C: c}
		DrawMask(m, b, src, image.Point{}, nil, image.Point{}, Src)
		check("whole")
	}
}

func TestDrawSrcNonpremultiplied(t *testing.T) {
	var (
		opaqueGray       = color.NRGBA{0x99, 0x99, 0x99, 0xff}
		transparentBlue  = color.NRGBA{0x00, 0x00, 0xff, 0x00}
		transparentGreen = color.NRGBA{0x00, 0xff, 0x00, 0x00}
		transparentRed   = color.NRGBA{0xff, 0x00, 0x00, 0x00}

		opaqueGray64        = color.NRGBA64{0x9999, 0x9999, 0x9999, 0xffff}
		transparentPurple64 = color.NRGBA64{0xfedc, 0x0000, 0x7654, 0x0000}
	)

	// dst and src are 1x3 images but the dr rectangle (and hence the overlap)
	// is only 1x2. The Draw call should affect dst's pixels at (1, 10) and (2,
	// 10) but the pixel at (0, 10) should be untouched.
	//
	// The src image is entirely transparent (and the Draw operator is Src) so
	// the two touched pixels should be set to transparent colors.
	//
	// In general, Go's color.Color type (and specifically the Color.RGBA
	// method) works in premultiplied alpha, where there's no difference
	// between "transparent blue" and "transparent red". It's all "just
	// transparent" and canonically "transparent black" (all zeroes).
	//
	// However, since the operator is Src (so the pixels are 'copied', not
	// 'blended') and both dst and src images are *image.NRGBA (N stands for
	// Non-premultiplied alpha which *does* distinguish "transparent blue" and
	// "transparent red"), we prefer that this distinction carries through and
	// dst's touched pixels should be transparent blue and transparent green,
	// not just transparent black.
	{
		dst := image.NewNRGBA(image.Rect(0, 10, 3, 11))
		dst.SetNRGBA(0, 10, opaqueGray)
		src := image.NewNRGBA(image.Rect(1, 20, 4, 21))
		src.SetNRGBA(1, 20, transparentBlue)
		src.SetNRGBA(2, 20, transparentGreen)
		src.SetNRGBA(3, 20, transparentRed)

		dr := image.Rect(1, 10, 3, 11)
		Draw(dst, dr, src, image.Point{1, 20}, Src)

		if got, want := dst.At(0, 10), opaqueGray; got != want {
			t.Errorf("At(0, 10):\ngot  %#v\nwant %#v", got, want)
		}
		if got, want := dst.At(1, 10), transparentBlue; got != want {
			t.Errorf("At(1, 10):\ngot  %#v\nwant %#v", got, want)
		}
		if got, want := dst.At(2, 10), transparentGreen; got != want {
			t.Errorf("At(2, 10):\ngot  %#v\nwant %#v", got, want)
		}
	}

	// Check image.NRGBA64 (not image.NRGBA) similarly.
	{
		dst := image.NewNRGBA64(image.Rect(0, 0, 1, 1))
		dst.SetNRGBA64(0, 0, opaqueGray64)
		src := image.NewNRGBA64(image.Rect(0, 0, 1, 1))
		src.SetNRGBA64(0, 0, transparentPurple64)
		Draw(dst, dst.Bounds(), src, image.Point{0, 0}, Src)
		if got, want := dst.At(0, 0), transparentPurple64; got != want {
			t.Errorf("At(0, 0):\ngot  %#v\nwant %#v", got, want)
		}
	}
}

// TestFloydSteinbergCheckerboard tests that the result of Floyd-Steinberg
// error diffusion of a uniform 50% gray source image with a black-and-white
// palette is a checkerboard pattern.
func TestFloydSteinbergCheckerboard(t *testing.T) {
	b := image.Rect(0, 0, 640, 480)
	// We can't represent 50% exactly, but 0x7fff / 0xffff is close enough.
	src := &image.Uniform{color.Gray16{0x7fff}}
	dst := image.NewPaletted(b, color.Palette{color.Black, color.White})
	FloydSteinberg.Draw(dst, b, src, image.Point{})
	nErr := 0
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			got := dst.Pix[dst.PixOffset(x, y)]
			want := uint8(x+y) % 2
			if got != want {
				t.Errorf("at (%d, %d): got %d, want %d", x, y, got, want)
				if nErr++; nErr == 10 {
					t.Fatal("there may be more errors")
				}
			}
		}
	}
}

// embeddedPaletted is an Image that behaves like an *image.Paletted but whose
// type is not *image.Paletted.
type embeddedPaletted struct {
	*image.Paletted
}

// TestPaletted tests that the drawPaletted function behaves the same
// regardless of whether dst is an *image.Paletted.
func TestPaletted(t *testing.T) {
	f, err := os.Open("../testdata/video-001.png")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	video001, err := png.Decode(f)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	b := video001.Bounds()

	cgaPalette := color.Palette{
		color.RGBA{0x00, 0x00, 0x00, 0xff},
		color.RGBA{0x55, 0xff, 0xff, 0xff},
		color.RGBA{0xff, 0x55, 0xff, 0xff},
		color.RGBA{0xff, 0xff, 0xff, 0xff},
	}
	drawers := map[string]Drawer{
		"src":             Src,
		"floyd-steinberg": FloydSteinberg,
	}
	sources := map[string]image.Image{
		"uniform":  &image.Uniform{color.RGBA{0xff, 0x7f, 0xff, 0xff}},
		"video001": video001,
	}

	for dName, d := range drawers {
	loop:
		for sName, src := range sources {
			dst0 := image.NewPaletted(b, cgaPalette)
			dst1 := image.NewPaletted(b, cgaPalette)
			d.Draw(dst0, b, src, image.Point{})
			d.Draw(embeddedPaletted{dst1}, b, src, image.Point{})
			for y := b.Min.Y; y < b.Max.Y; y++ {
				for x := b.Min.X; x < b.Max.X; x++ {
					if !eq(dst0.At(x, y), dst1.At(x, y)) {
						t.Errorf("%s / %s: at (%d, %d), %v versus %v",
							dName, sName, x, y, dst0.At(x, y), dst1.At(x, y))
						continue loop
					}
				}
			}
		}
	}
}

func TestSqDiff(t *testing.T) {
	// This test is similar to the one from the image/color package, but
	// sqDiff in this package accepts int32 instead of uint32, so test it
	// for appropriate input.

	// canonical sqDiff implementation
	orig := func(x, y int32) uint32 {
		var d uint32
		if x > y {
			d = uint32(x - y)
		} else {
			d = uint32(y - x)
		}
		return (d * d) >> 2
	}
	testCases := []int32{
		0,
		1,
		2,
		0x0fffd,
		0x0fffe,
		0x0ffff,
		0x10000,
		0x10001,
		0x10002,
		0x7ffffffd,
		0x7ffffffe,
		0x7fffffff,
		-0x7ffffffd,
		-0x7ffffffe,
		-0x80000000,
	}
	for _, x := range testCases {
		for _, y := range testCases {
			if got, want := sqDiff(x, y), orig(x, y); got != want {
				t.Fatalf("sqDiff(%#x, %#x): got %d, want %d", x, y, got, want)
			}
		}
	}
	if err := quick.CheckEqual(orig, sqDiff, &quick.Config{MaxCountScale: 10}); err != nil {
		t.Fatal(err)
	}
}

"""



```