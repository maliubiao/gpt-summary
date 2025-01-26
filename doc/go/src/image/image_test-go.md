Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Context:** The prompt clearly states this is part of `go/src/image/image_test.go`. The `_test.go` suffix immediately signals that this file contains *tests* for the `image` package. This is crucial information.

2. **Identify the Core Purpose:**  The code defines an interface `image` (lowercase 'i') that extends the `image.Image` interface. It also has a `cmp` function for comparing colors. The presence of `testImages` and functions like `TestImage` and `TestNewXxxBadRectangle` strongly confirms this is a testing file. The main purpose is to test the functionality of various image types within the `image` package.

3. **Analyze Key Structures:**

   * **`image` interface:** This custom interface adds `Opaque()` and `Set()` methods to the standard `image.Image` and includes a `SubImage` method. This suggests the tests will focus on these aspects.

   * **`cmp` function:**  This function standardizes color comparison by converting colors to a common model and checking RGBA values. This avoids direct equality checks which might fail due to different underlying representations.

   * **`testImages` slice:** This slice is a crucial element. It defines a set of image types to be tested. The `func() image` structure allows for creating a new instance of each image type within the tests. This immediately points to testing the creation and basic properties of `RGBA`, `RGBA64`, `NRGBA`, etc.

   * **`TestImage` function:** This is a primary test function. It iterates through `testImages` and performs several checks on each image type:
      * Bounds checking (`m.Bounds()`).
      * Initial color value checking (`m.At()`).
      * Setting a pixel color and re-checking (`m.Set()`, `m.At()`).
      * Checking the `Opaque()` method on a sub-image.
      * Creating and testing a sub-image.
      * Testing empty sub-image creation to ensure no panic.

   * **`TestNewXxxBadRectangle` function:** This function specifically tests the error handling (panics) when creating new images with invalid rectangles (negative dimensions or extremely large dimensions). It uses a `call` helper function to safely execute the `NewXxx` functions and check for panics.

   * **`Test16BitsPerColorChannel` function:**  This focuses on testing the accuracy of color representation for 16-bit color channels in `RGBA64`, `NRGBA64`, `Alpha16`, and `Gray16` image types.

   * **`TestRGBA64Image` function:** This test checks the `RGBA64At` method against the general `At` method for various image types, including those that implement the (unexported in this snippet) `draw.RGBA64Image` interface. It also includes special handling for image types without `SetRGBA64` like `YCbCr` and `Uniform`.

   * **`Benchmark...` functions:** These are performance benchmarks for various operations like `At`, `Set`, `RGBAAt`, etc., for different image types. They use the `testing.B` type.

4. **Infer Functionality based on Tests:**  By looking at what the tests *do*, we can infer the underlying functionality being tested. For instance, `TestImage` demonstrates the core functionality of getting and setting pixel colors, checking bounds, and creating sub-images. `TestNewXxxBadRectangle` tests the robustness of image creation against invalid input.

5. **Construct Code Examples:** Based on the identified functionality, create simple Go code snippets that illustrate the usage. Focus on the `NewXxx` functions for creation, `At` and `Set` for pixel manipulation, and `SubImage` for creating sub-regions.

6. **Identify Potential Pitfalls:** Think about how a user might misuse these functions. The `TestNewXxxBadRectangle` function itself gives clues – creating images with invalid dimensions is a common mistake. Also, the difference between `image.Point` and rectangle boundaries can be confusing.

7. **Explain Command-Line Parameters (if applicable):** In this specific case, the code is purely for testing and doesn't directly interact with command-line arguments. Therefore, this section would be "not applicable". If the code *did* use `flag` or similar, this would be the place to explain those flags.

8. **Structure the Answer:** Organize the findings logically. Start with a general overview of the file's purpose, then detail the specific functionalities, provide code examples, discuss potential pitfalls, and address command-line arguments (or the lack thereof). Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about images."  **Correction:**  Realize it's specifically about *testing* the `image` package, which provides more context.
* **Confusion:** "What's the difference between `image` and `image.Image`?" **Clarification:** Understand that the lowercase `image` is a *local* interface defined for testing purposes, while `image.Image` is the standard interface from the Go standard library.
* **Oversight:** "The benchmarks are just for speed." **Insight:** While true, they also indirectly demonstrate the existence of specific methods like `RGBAAt`, `SetRGBA`, etc., for optimized access.
* **Missing detail:**  Initially, I might forget to mention the `cmp` function. **Correction:** Realize its importance in reliable color comparison and add it to the analysis.

By following these steps, and continuously refining the understanding of the code, a comprehensive and accurate answer can be constructed.
这是一个 Go 语言测试文件 `image_test.go`，它位于 Go 标准库的 `image` 包的 `src/image` 目录下。它的主要功能是 **测试 `image` 包中定义的图像类型和相关操作的正确性**。

下面我们详细列举一下它的功能：

1. **定义了一个自定义的 `image` 接口:**  这个接口扩展了标准库中的 `image.Image` 接口，增加了 `Opaque()`, `Set(int, int, color.Color)` 和 `SubImage(Rectangle) Image` 这几个方法。这可能是为了更方便地在测试中使用特定的图像操作。

2. **定义了一个颜色比较函数 `cmp`:**  这个函数 `cmp(cm color.Model, c0, c1 color.Color) bool` 用于比较两个颜色 `c0` 和 `c1` 在给定的颜色模型 `cm` 下是否相等。它会将两个颜色都转换为 RGBA 格式，然后比较它们的 R、G、B、A 分量。这避免了由于颜色表示方式不同而导致的比较错误。

3. **定义了一个测试用例切片 `testImages`:**  这个切片包含了多个匿名结构体，每个结构体定义了一个图像类型的名称 (`name`) 和一个创建该类型图像的函数 (`image func() image`)。它覆盖了 `image` 包中常见的几种图像类型，如 `RGBA`, `RGBA64`, `NRGBA`, `NRGBA64`, `Alpha`, `Alpha16`, `Gray`, `Gray16`, 和 `Paletted`。

4. **`TestImage` 函数:** 这是主要的测试函数之一，它遍历 `testImages` 中的每种图像类型，并进行以下测试：
    * **检查图像的边界 (Bounds):** 确保创建的图像的边界符合预期 (这里是 0, 0, 10, 10)。
    * **检查初始颜色:**  测试图像在某个特定坐标 (6, 3) 的初始颜色是否为透明色 (Transparent)。
    * **设置和检查像素颜色:**  测试通过 `Set` 方法设置像素颜色，并使用 `At` 方法检查颜色是否设置成功。
    * **测试 `Opaque()` 方法:**  对于一个包含非透明像素的子图像，测试其 `Opaque()` 方法是否返回 `true`。
    * **测试 `SubImage()` 方法:**  创建子图像，并检查子图像的边界以及像素颜色是否符合预期。
    * **测试创建空子图像:**  测试在图像的四个角落创建空子图像是否会发生 panic。

5. **`TestNewXxxBadRectangle` 函数:**  这个函数专门测试当使用无效的 `Rectangle` 创建新的图像时是否会发生 panic。它测试了以下几种情况：
    * **负宽度或负高度的矩形:** 循环测试各种 `NewXxx` 函数，传入宽度或高度为负数的矩形，预期会发生 panic。
    * **宽度和高度为最大整数的矩形:** 测试传入宽度和高度为 `MaxInt` 的矩形，预期会发生溢出 panic。

6. **`Test16BitsPerColorChannel` 函数:**  这个函数测试了 16 位颜色通道的图像类型（`RGBA64`, `NRGBA64`, `Alpha16`, `Gray16`）的颜色精度。
    * **测试颜色模型转换:**  测试将 `color.RGBA64` 转换为其他 16 位颜色模型的准确性。
    * **测试 `Set` 和 `At` 方法:**  设置 16 位图像的像素颜色，并检查读取到的颜色是否正确。

7. **`TestRGBA64Image` 函数:**  这个函数测试了与 `RGBA64Image` 接口相关的操作，并验证 `RGBA64At` 方法与 `At` 方法返回的 RGBA 值是否一致。它覆盖了多种图像类型，包括实现了 `draw.RGBA64Image` 接口的类型以及其他类型。对于某些特殊类型（如 `YCbCr`），由于其特殊的颜色模型，使用了 `memset` 直接操作底层数据。

8. **Benchmark 函数:**  文件中包含多个以 `Benchmark` 开头的函数，这些是性能基准测试。它们用于测量不同图像类型和操作的性能，例如 `At`, `Set`, `RGBAAt`, `SetRGBA` 等。这些基准测试可以帮助开发者了解不同图像操作的效率。

**它可以推理出它是什么 go 语言功能的实现：**

从代码结构和测试内容来看，这个文件主要测试了 Go 语言标准库 `image` 包中关于 **图像表示和操作** 的功能。具体来说，它测试了各种预定义的图像类型 (如 `RGBA`, `Gray`, `Paletted` 等) 的创建、像素访问 (通过 `At` 方法)、像素设置 (通过 `Set` 方法)、子图像创建 (`SubImage` 方法) 以及颜色模型的转换和比较。

**Go 代码举例说明:**

以下代码演示了如何使用 `image` 包中的 `RGBA` 类型，以及 `At` 和 `Set` 方法：

```go
package main

import (
	"fmt"
	"image"
	"image/color"
)

func main() {
	// 创建一个 10x10 的 RGBA 图像
	rgbaImage := image.NewRGBA(image.Rect(0, 0, 10, 10))

	// 获取坐标 (2, 3) 的颜色
	c := rgbaImage.At(2, 3)
	fmt.Printf("Color at (2, 3): %v\n", c)

	// 设置坐标 (5, 5) 的颜色为红色
	red := color.RGBA{255, 0, 0, 255}
	rgbaImage.Set(5, 5, red)

	// 再次获取坐标 (5, 5) 的颜色
	c = rgbaImage.At(5, 5)
	fmt.Printf("Color at (5, 5): %v\n", c)

	// 创建子图像
	subImage := rgbaImage.SubImage(image.Rect(1, 1, 5, 5))
	fmt.Printf("SubImage bounds: %v\n", subImage.Bounds())
}
```

**假设的输入与输出 (针对 `TestImage` 函数):**

假设 `TestImage` 函数正在测试 `RGBA` 图像类型。

* **假设输入:**  创建一个 10x10 的 `RGBA` 图像。
* **预期输出:**
    * `m.Bounds()` 应该等于 `image.Rect(0, 0, 10, 10)`。
    * `m.At(6, 3)` 的初始颜色应该近似于 `color.Transparent` (例如，RGBA 值为 0, 0, 0, 0)。
    * 设置 `m.Set(6, 3, Opaque)` 后，`m.At(6, 3)` 的颜色应该近似于 `color.Opaque` (例如，RGBA 值为非零值，通常是白色或黑色)。
    * `m.SubImage(Rect(6, 3, 7, 4))` 的 `Opaque()` 方法应该返回 `true`（假设 `Opaque` 常量是非透明的）。
    * 子图像的边界 `m.Bounds()` 应该等于 `image.Rect(3, 2, 9, 8)`。
    * 子图像在坐标 (6, 3) 的颜色应该与原始图像在相同相对位置的颜色相同（即非透明色）。
    * 子图像在坐标 (3, 3) 的颜色应该是初始颜色（即透明色）。
    * 设置子图像的像素后，该像素的颜色应该被更新。
    * 创建空子图像的操作不应该导致程序 panic。

**命令行参数的具体处理:**

这个测试文件本身 **不涉及** 命令行参数的处理。Go 的测试工具 `go test` 会自动运行 `_test.go` 文件中的测试函数，无需手动指定参数。如果需要传递特定的参数来控制测试行为，通常会使用 build 标签或者在测试代码中硬编码一些配置。

**使用者易犯错的点 (基于代码推理):**

1. **创建图像时使用无效的 `Rectangle`:**  `TestNewXxxBadRectangle` 已经明确指出了这个问题。如果用户尝试使用负宽度或高度的 `Rectangle` 来创建图像，会导致程序 panic。例如：

   ```go
   // 错误示例：使用负宽度创建图像
   badRect := image.Rect(0, 0, -10, 10)
   rgbaImage := image.NewRGBA(badRect) // 这里会发生 panic
   ```

2. **混淆 `image.Point` 和 `image.Rectangle`:**  `image.Point` 表示一个点，而 `image.Rectangle` 表示一个矩形区域。在创建图像或子图像时，需要使用 `image.Rectangle`，它由两个 `image.Point` 组成 (最小点和最大点)。

   ```go
   // 错误示例：尝试使用 Point 创建图像（编译错误）
   // badPoint := image.Point{0, 0}
   // rgbaImage := image.NewRGBA(badPoint)

   // 正确示例：使用 Rectangle 创建图像
   rect := image.Rect(0, 0, 10, 10)
   rgbaImage := image.NewRGBA(rect)
   ```

3. **假设所有图像类型都有相同的特性和性能:**  不同的图像类型在内存布局、颜色模型和操作性能上可能存在差异。例如，直接访问 `RGBA` 图像的像素可能比访问 `Paletted` 图像的像素更快，因为 `Paletted` 图像需要进行颜色查找。基准测试部分就体现了这一点。

4. **在子图像操作中混淆坐标系:**  子图像拥有自己的坐标系，其原点位于父图像的某个位置。用户需要注意将子图像的坐标映射回父图像的坐标，反之亦然。

   ```go
   rgbaImage := image.NewRGBA(image.Rect(0, 0, 10, 10))
   subImage := rgbaImage.SubImage(image.Rect(2, 3, 7, 8)).(image.Image)

   // 在子图像中设置 (0, 0) 的颜色，实际上会修改父图像的 (2, 3) 位置
   subImage.(interface{ Set(int, int, color.Color) }).Set(0, 0, color.Black)
   fmt.Println(rgbaImage.At(2, 3)) // 输出黑色
   ```

总而言之，`go/src/image/image_test.go` 是 `image` 包的重要组成部分，它通过大量的测试用例确保了图像处理相关功能的正确性和健壮性。理解这个测试文件的内容有助于我们更好地理解和使用 `image` 包。

Prompt: 
```
这是路径为go/src/image/image_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package image

import (
	"image/color"
	"image/color/palette"
	"testing"
)

type image interface {
	Image
	Opaque() bool
	Set(int, int, color.Color)
	SubImage(Rectangle) Image
}

func cmp(cm color.Model, c0, c1 color.Color) bool {
	r0, g0, b0, a0 := cm.Convert(c0).RGBA()
	r1, g1, b1, a1 := cm.Convert(c1).RGBA()
	return r0 == r1 && g0 == g1 && b0 == b1 && a0 == a1
}

var testImages = []struct {
	name  string
	image func() image
}{
	{"rgba", func() image { return NewRGBA(Rect(0, 0, 10, 10)) }},
	{"rgba64", func() image { return NewRGBA64(Rect(0, 0, 10, 10)) }},
	{"nrgba", func() image { return NewNRGBA(Rect(0, 0, 10, 10)) }},
	{"nrgba64", func() image { return NewNRGBA64(Rect(0, 0, 10, 10)) }},
	{"alpha", func() image { return NewAlpha(Rect(0, 0, 10, 10)) }},
	{"alpha16", func() image { return NewAlpha16(Rect(0, 0, 10, 10)) }},
	{"gray", func() image { return NewGray(Rect(0, 0, 10, 10)) }},
	{"gray16", func() image { return NewGray16(Rect(0, 0, 10, 10)) }},
	{"paletted", func() image {
		return NewPaletted(Rect(0, 0, 10, 10), color.Palette{
			Transparent,
			Opaque,
		})
	}},
}

func TestImage(t *testing.T) {
	for _, tc := range testImages {
		m := tc.image()
		if !Rect(0, 0, 10, 10).Eq(m.Bounds()) {
			t.Errorf("%T: want bounds %v, got %v", m, Rect(0, 0, 10, 10), m.Bounds())
			continue
		}
		if !cmp(m.ColorModel(), Transparent, m.At(6, 3)) {
			t.Errorf("%T: at (6, 3), want a zero color, got %v", m, m.At(6, 3))
			continue
		}
		m.Set(6, 3, Opaque)
		if !cmp(m.ColorModel(), Opaque, m.At(6, 3)) {
			t.Errorf("%T: at (6, 3), want a non-zero color, got %v", m, m.At(6, 3))
			continue
		}
		if !m.SubImage(Rect(6, 3, 7, 4)).(image).Opaque() {
			t.Errorf("%T: at (6, 3) was not opaque", m)
			continue
		}
		m = m.SubImage(Rect(3, 2, 9, 8)).(image)
		if !Rect(3, 2, 9, 8).Eq(m.Bounds()) {
			t.Errorf("%T: sub-image want bounds %v, got %v", m, Rect(3, 2, 9, 8), m.Bounds())
			continue
		}
		if !cmp(m.ColorModel(), Opaque, m.At(6, 3)) {
			t.Errorf("%T: sub-image at (6, 3), want a non-zero color, got %v", m, m.At(6, 3))
			continue
		}
		if !cmp(m.ColorModel(), Transparent, m.At(3, 3)) {
			t.Errorf("%T: sub-image at (3, 3), want a zero color, got %v", m, m.At(3, 3))
			continue
		}
		m.Set(3, 3, Opaque)
		if !cmp(m.ColorModel(), Opaque, m.At(3, 3)) {
			t.Errorf("%T: sub-image at (3, 3), want a non-zero color, got %v", m, m.At(3, 3))
			continue
		}
		// Test that taking an empty sub-image starting at a corner does not panic.
		m.SubImage(Rect(0, 0, 0, 0))
		m.SubImage(Rect(10, 0, 10, 0))
		m.SubImage(Rect(0, 10, 0, 10))
		m.SubImage(Rect(10, 10, 10, 10))
	}
}

func TestNewXxxBadRectangle(t *testing.T) {
	// call calls f(r) and reports whether it ran without panicking.
	call := func(f func(Rectangle), r Rectangle) (ok bool) {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		f(r)
		return true
	}

	testCases := []struct {
		name string
		f    func(Rectangle)
	}{
		{"RGBA", func(r Rectangle) { NewRGBA(r) }},
		{"RGBA64", func(r Rectangle) { NewRGBA64(r) }},
		{"NRGBA", func(r Rectangle) { NewNRGBA(r) }},
		{"NRGBA64", func(r Rectangle) { NewNRGBA64(r) }},
		{"Alpha", func(r Rectangle) { NewAlpha(r) }},
		{"Alpha16", func(r Rectangle) { NewAlpha16(r) }},
		{"Gray", func(r Rectangle) { NewGray(r) }},
		{"Gray16", func(r Rectangle) { NewGray16(r) }},
		{"CMYK", func(r Rectangle) { NewCMYK(r) }},
		{"Paletted", func(r Rectangle) { NewPaletted(r, color.Palette{color.Black, color.White}) }},
		{"YCbCr", func(r Rectangle) { NewYCbCr(r, YCbCrSubsampleRatio422) }},
		{"NYCbCrA", func(r Rectangle) { NewNYCbCrA(r, YCbCrSubsampleRatio444) }},
	}

	for _, tc := range testCases {
		// Calling NewXxx(r) should fail (panic, since NewXxx doesn't return an
		// error) unless r's width and height are both non-negative.
		for _, negDx := range []bool{false, true} {
			for _, negDy := range []bool{false, true} {
				r := Rectangle{
					Min: Point{15, 28},
					Max: Point{16, 29},
				}
				if negDx {
					r.Max.X = 14
				}
				if negDy {
					r.Max.Y = 27
				}

				got := call(tc.f, r)
				want := !negDx && !negDy
				if got != want {
					t.Errorf("New%s: negDx=%t, negDy=%t: got %t, want %t",
						tc.name, negDx, negDy, got, want)
				}
			}
		}

		// Passing a Rectangle whose width and height is MaxInt should also fail
		// (panic), due to overflow.
		{
			zeroAsUint := uint(0)
			maxUint := zeroAsUint - 1
			maxInt := int(maxUint / 2)
			got := call(tc.f, Rectangle{
				Min: Point{0, 0},
				Max: Point{maxInt, maxInt},
			})
			if got {
				t.Errorf("New%s: overflow: got ok, want !ok", tc.name)
			}
		}
	}
}

func Test16BitsPerColorChannel(t *testing.T) {
	testColorModel := []color.Model{
		color.RGBA64Model,
		color.NRGBA64Model,
		color.Alpha16Model,
		color.Gray16Model,
	}
	for _, cm := range testColorModel {
		c := cm.Convert(color.RGBA64{0x1234, 0x1234, 0x1234, 0x1234}) // Premultiplied alpha.
		r, _, _, _ := c.RGBA()
		if r != 0x1234 {
			t.Errorf("%T: want red value 0x%04x got 0x%04x", c, 0x1234, r)
			continue
		}
	}
	testImage := []image{
		NewRGBA64(Rect(0, 0, 10, 10)),
		NewNRGBA64(Rect(0, 0, 10, 10)),
		NewAlpha16(Rect(0, 0, 10, 10)),
		NewGray16(Rect(0, 0, 10, 10)),
	}
	for _, m := range testImage {
		m.Set(1, 2, color.NRGBA64{0xffff, 0xffff, 0xffff, 0x1357}) // Non-premultiplied alpha.
		r, _, _, _ := m.At(1, 2).RGBA()
		if r != 0x1357 {
			t.Errorf("%T: want red value 0x%04x got 0x%04x", m, 0x1357, r)
			continue
		}
	}
}

func TestRGBA64Image(t *testing.T) {
	// memset sets every element of s to v.
	memset := func(s []byte, v byte) {
		for i := range s {
			s[i] = v
		}
	}

	r := Rect(0, 0, 3, 2)
	testCases := []Image{
		NewAlpha(r),
		NewAlpha16(r),
		NewCMYK(r),
		NewGray(r),
		NewGray16(r),
		NewNRGBA(r),
		NewNRGBA64(r),
		NewNYCbCrA(r, YCbCrSubsampleRatio444),
		NewPaletted(r, palette.Plan9),
		NewRGBA(r),
		NewRGBA64(r),
		NewUniform(color.RGBA64{}),
		NewYCbCr(r, YCbCrSubsampleRatio444),
		r,
	}
	for _, tc := range testCases {
		switch tc := tc.(type) {
		// Most of the concrete image types in the testCases implement the
		// draw.RGBA64Image interface: they have a SetRGBA64 method. We use an
		// interface literal here, instead of importing "image/draw", to avoid
		// an import cycle.
		//
		// The YCbCr and NYCbCrA types are special-cased. Chroma subsampling
		// means that setting one pixel can modify neighboring pixels. They
		// don't have Set or SetRGBA64 methods because that side effect could
		// be surprising. Here, we just memset the channel buffers instead.
		//
		// The Uniform and Rectangle types are also special-cased, as they
		// don't have a Set or SetRGBA64 method.
		case interface {
			SetRGBA64(x, y int, c color.RGBA64)
		}:
			tc.SetRGBA64(1, 1, color.RGBA64{0x7FFF, 0x3FFF, 0x0000, 0x7FFF})

		case *NYCbCrA:
			memset(tc.YCbCr.Y, 0x77)
			memset(tc.YCbCr.Cb, 0x88)
			memset(tc.YCbCr.Cr, 0x99)
			memset(tc.A, 0xAA)

		case *Uniform:
			tc.C = color.RGBA64{0x7FFF, 0x3FFF, 0x0000, 0x7FFF}

		case *YCbCr:
			memset(tc.Y, 0x77)
			memset(tc.Cb, 0x88)
			memset(tc.Cr, 0x99)

		case Rectangle:
			// No-op. Rectangle pixels' colors are immutable. They're always
			// color.Opaque.

		default:
			t.Errorf("could not initialize pixels for %T", tc)
			continue
		}

		// Check that RGBA64At(x, y) is equivalent to At(x, y).RGBA().
		rgba64Image, ok := tc.(RGBA64Image)
		if !ok {
			t.Errorf("%T is not an RGBA64Image", tc)
			continue
		}
		got := rgba64Image.RGBA64At(1, 1)
		wantR, wantG, wantB, wantA := tc.At(1, 1).RGBA()
		if (uint32(got.R) != wantR) || (uint32(got.G) != wantG) ||
			(uint32(got.B) != wantB) || (uint32(got.A) != wantA) {
			t.Errorf("%T:\ngot  (0x%04X, 0x%04X, 0x%04X, 0x%04X)\n"+
				"want (0x%04X, 0x%04X, 0x%04X, 0x%04X)", tc,
				got.R, got.G, got.B, got.A,
				wantR, wantG, wantB, wantA)
			continue
		}
	}
}

func BenchmarkAt(b *testing.B) {
	for _, tc := range testImages {
		b.Run(tc.name, func(b *testing.B) {
			m := tc.image()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.At(4, 5)
			}
		})
	}
}

func BenchmarkSet(b *testing.B) {
	c := color.Gray{0xff}
	for _, tc := range testImages {
		b.Run(tc.name, func(b *testing.B) {
			m := tc.image()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.Set(4, 5, c)
			}
		})
	}
}

func BenchmarkRGBAAt(b *testing.B) {
	m := NewRGBA(Rect(0, 0, 10, 10))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.RGBAAt(4, 5)
	}
}

func BenchmarkRGBASetRGBA(b *testing.B) {
	m := NewRGBA(Rect(0, 0, 10, 10))
	c := color.RGBA{0xff, 0xff, 0xff, 0x13}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.SetRGBA(4, 5, c)
	}
}

func BenchmarkRGBA64At(b *testing.B) {
	m := NewRGBA64(Rect(0, 0, 10, 10))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.RGBA64At(4, 5)
	}
}

func BenchmarkRGBA64SetRGBA64(b *testing.B) {
	m := NewRGBA64(Rect(0, 0, 10, 10))
	c := color.RGBA64{0xffff, 0xffff, 0xffff, 0x1357}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.SetRGBA64(4, 5, c)
	}
}

func BenchmarkNRGBAAt(b *testing.B) {
	m := NewNRGBA(Rect(0, 0, 10, 10))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.NRGBAAt(4, 5)
	}
}

func BenchmarkNRGBASetNRGBA(b *testing.B) {
	m := NewNRGBA(Rect(0, 0, 10, 10))
	c := color.NRGBA{0xff, 0xff, 0xff, 0x13}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.SetNRGBA(4, 5, c)
	}
}

func BenchmarkNRGBA64At(b *testing.B) {
	m := NewNRGBA64(Rect(0, 0, 10, 10))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.NRGBA64At(4, 5)
	}
}

func BenchmarkNRGBA64SetNRGBA64(b *testing.B) {
	m := NewNRGBA64(Rect(0, 0, 10, 10))
	c := color.NRGBA64{0xffff, 0xffff, 0xffff, 0x1357}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.SetNRGBA64(4, 5, c)
	}
}

func BenchmarkAlphaAt(b *testing.B) {
	m := NewAlpha(Rect(0, 0, 10, 10))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.AlphaAt(4, 5)
	}
}

func BenchmarkAlphaSetAlpha(b *testing.B) {
	m := NewAlpha(Rect(0, 0, 10, 10))
	c := color.Alpha{0x13}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.SetAlpha(4, 5, c)
	}
}

func BenchmarkAlpha16At(b *testing.B) {
	m := NewAlpha16(Rect(0, 0, 10, 10))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.Alpha16At(4, 5)
	}
}

func BenchmarkAlphaSetAlpha16(b *testing.B) {
	m := NewAlpha16(Rect(0, 0, 10, 10))
	c := color.Alpha16{0x13}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.SetAlpha16(4, 5, c)
	}
}

func BenchmarkGrayAt(b *testing.B) {
	m := NewGray(Rect(0, 0, 10, 10))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.GrayAt(4, 5)
	}
}

func BenchmarkGraySetGray(b *testing.B) {
	m := NewGray(Rect(0, 0, 10, 10))
	c := color.Gray{0x13}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.SetGray(4, 5, c)
	}
}

func BenchmarkGray16At(b *testing.B) {
	m := NewGray16(Rect(0, 0, 10, 10))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.Gray16At(4, 5)
	}
}

func BenchmarkGraySetGray16(b *testing.B) {
	m := NewGray16(Rect(0, 0, 10, 10))
	c := color.Gray16{0x13}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		m.SetGray16(4, 5, c)
	}
}

"""



```