Response:
My goal is to analyze the provided Go code snippet and explain its functionality in Chinese. Here's a breakdown of the thinking process:

1. **Identify the Core Purpose:** The initial comments clearly state that the `draw` package provides image composition functions. This is the overarching theme.

2. **Examine Key Types and Interfaces:** I'll go through the defined types and interfaces to understand their roles:
    * `Image`:  Extends `image.Image` with a `Set` method. This signifies the ability to modify individual pixels.
    * `RGBA64Image`: Extends `Image` and `image.RGBA64Image`, adding `SetRGBA64` for potential optimization when working with `color.RGBA64`.
    * `Quantizer`:  Responsible for creating a palette from an image, necessary for converting to paletted images.
    * `Op`: An enumeration for Porter-Duff compositing operators (`Over`, `Src`).
    * `Drawer`: An interface with a `Draw` method, representing an object that can perform drawing operations.
    * `FloydSteinberg`: A specific `Drawer` implementation using the `Src` operator with Floyd-Steinberg error diffusion.

3. **Analyze Key Functions:**
    * `Draw` (as a method of `Op` and a standalone function):  Performs the core drawing operation, compositing a source image onto a destination image. The standalone `Draw` calls `DrawMask` with a nil mask.
    * `DrawMask`: The central function for compositing, taking into account a mask image and a compositing operator. It handles clipping, fast paths for specific image types, and fallback implementations.
    * `clip`:  A utility function to adjust the drawing rectangle and source/mask points to ensure they are within the bounds of the images.
    * `processBackward`: A helper function to determine if the drawing operation needs to be performed in reverse order (right-to-left, bottom-up) to handle overlapping source and destination.
    * `drawFillOver`, `drawFillSrc`, `drawCopyOver`, `drawCopySrc`, `drawNRGBAOver`, `drawNRGBASrc`, `drawGray`, `drawCMYK`, `drawGlyphOver`, `drawGrayMaskOver`, `drawRGBAMaskOver`, `drawRGBA64ImageMaskOver`, `drawRGBA`, `drawPaletted`:  These are highly optimized, type-specific implementations for different drawing scenarios, handling various source and destination image types and compositing operations. The comments within these functions often explain the optimizations.
    * `clamp`, `sqDiff`: Utility functions used in the `drawPaletted` function for color quantization and error calculation.

4. **Identify Go Language Features:**
    * **Interfaces:**  The code heavily uses interfaces (`Image`, `RGBA64Image`, `Quantizer`, `Drawer`) for abstraction and polymorphism. This allows the `DrawMask` function to handle different image types and drawing strategies.
    * **Type Switching:** The `switch dst0 := dst.(type)` construct is used extensively in `DrawMask` to implement fast paths for specific image types.
    * **Method Sets:** The `Op` type has a `Draw` method, demonstrating how methods can be associated with custom types.
    * **Constants:** The `m` constant defines the maximum color value.
    * **Structs:** `floydSteinberg` is a struct used to implement the `Drawer` interface.
    * **Pointers:** Pointers are used to modify the drawing rectangle and source/mask points in the `clip` function.
    * **Slices:** The code manipulates image pixel data using slices (`dst.Pix`, `src.Pix`).
    * **Built-in Functions:**  `copy` is used for efficient memory copying in some drawing functions.

5. **Infer Functionality and Provide Examples:** Based on the identified types and functions, I can infer the core functionality: image composition (drawing one image onto another). I will then create concise Go code examples demonstrating basic usage, such as drawing a solid color onto an image or copying one image to another.

6. **Address Code Reasoning (with Assumptions):**  When explaining the optimized drawing functions (like `drawCopyOver`), I will make assumptions about the input image types and the drawing rectangle to illustrate the logic of pixel manipulation and the handling of overlapping regions.

7. **Command-Line Arguments:** This specific code snippet doesn't directly handle command-line arguments. I need to explicitly state this. The `image` package as a whole might be used in programs that take command-line arguments for image processing, but this file is focused on the core drawing logic.

8. **Common Mistakes:**  I'll consider potential pitfalls for users, such as forgetting to handle different image types or incorrectly specifying the source point. The concept of overlapping source and destination regions needing special handling is also important.

9. **Structure the Answer:**  I'll organize the answer into logical sections (functionality, Go features, examples, code reasoning, command-line arguments, common mistakes, summary) using clear and concise Chinese.

10. **Review and Refine:** After drafting the initial answer, I'll review it for accuracy, clarity, and completeness, ensuring it addresses all aspects of the prompt. I will double-check that the examples are correct and easy to understand. Specifically, for the summary in this first part, I'll focus on the high-level purpose.

By following these steps, I can provide a comprehensive and informative explanation of the given Go code snippet.
好的，让我们来分析一下 `go/src/image/draw/draw.go` 的第一部分。

**功能归纳：**

这部分 `draw.go` 文件的核心功能是 **定义了用于图像合成（Image Composition）的基础接口、类型和常量**。它并没有实现具体的图像合成算法，而是为实现这些算法奠定了基础。

具体来说，它定义了以下关键元素：

* **`Image` 接口:**  这是一个核心接口，扩展了 `image.Image` 接口，并添加了一个 `Set(x, y int, c color.Color)` 方法。这意味着任何实现了 `Image` 接口的类型都必须能够获取指定坐标的颜色，以及设置指定坐标的颜色。这为修改图像的单个像素提供了能力。

* **`RGBA64Image` 接口:** 这是一个更具体的接口，它同时继承了 `Image` 和 `image.RGBA64Image`。  除了 `Set` 方法外，还添加了 `SetRGBA64(x, y int, c color.RGBA64)` 方法。 这个方法允许直接设置 `color.RGBA64` 类型的颜色，避免了从具体颜色类型到 `color.Color` 接口类型的转换过程中可能产生的内存分配。这是一种性能优化手段。

* **`Quantizer` 接口:**  定义了图像量化的行为。`Quantize` 方法接收一个调色板和一个图像，并返回一个更新后的调色板。这为将真彩色图像转换为调色板图像提供了基础。

* **`Op` 类型:**  这是一个枚举类型，定义了 Porter-Duff 合成操作符，目前只定义了 `Over` 和 `Src` 两种模式。
    * `Over`:  表示“源在目标之上”的合成方式。
    * `Src`:  表示“源覆盖目标”的合成方式。
    `Op` 类型还实现了 `Drawer` 接口。

* **`Drawer` 接口:**  定义了图像绘制的行为。`Draw` 方法接收目标图像、目标矩形、源图像和源起始点，并在目标图像的指定矩形区域上绘制源图像。

* **`FloydSteinberg` 变量:**  这是一个实现了 `Drawer` 接口的变量，使用了 `Src` 操作符并应用了 Floyd-Steinberg 误差扩散算法。这是一种用于抖动图像以减少颜色数量的技术，常用于将真彩色图像转换为调色板图像。

* **辅助函数:**  定义了一些辅助函数，如 `clip` 用于裁剪绘制区域，确保绘制操作在图像边界内；`processBackward` 用于判断是否需要反向处理像素（例如，当源图像和目标图像重叠时）。

**可以推理出它是什么go语言功能的实现：**

这部分代码是 Go 语言标准库 `image/draw` 包中关于 **图像基本绘制和合成操作** 的定义。它利用了 Go 语言的接口、类型系统和常量定义等特性，为实现各种图像合成算法提供了抽象和基础结构。

**Go 代码举例说明：**

虽然这部分代码没有直接实现图像合成，但它定义了如何进行合成的蓝图。我们可以结合 `image` 包中的类型来演示如何使用这里定义的接口：

```go
package main

import (
	"image"
	"image/color"
	"image/draw"
)

func main() {
	// 创建一个 10x10 的 RGBA 图像作为目标图像
	dst := image.NewRGBA(image.Rect(0, 0, 10, 10))

	// 创建一个纯红色的 5x5 的 Uniform 图像作为源图像
	src := image.NewUniform(color.RGBA{255, 0, 0, 255})

	// 定义源图像在目标图像上的绘制位置
	sp := image.Point{X: 2, Y: 2}

	// 定义目标图像上要被覆盖的区域
	r := image.Rect(2, 2, 7, 7) // 注意：这里的大小与源图像一致

	// 使用 Over 操作符进行绘制
	draw.Draw(dst, r, src, sp, draw.Over)

	// 现在 dst 图像的 (2,2) 到 (6,6) 的区域被红色覆盖了
	// 你可以将 dst 图像保存到文件或者进行其他操作
}
```

**假设的输入与输出：**

在上面的例子中：

* **假设输入:**
    * `dst`: 一个 10x10 的空白 RGBA 图像。
    * `src`: 一个纯红色的 Uniform 图像。
    * `r`: 目标图像上的矩形区域 `image.Rect(2, 2, 7, 7)`。
    * `sp`: 源图像的起始点 `image.Point{X: 2, Y: 2}`。
    * `op`: `draw.Over` 操作符。

* **输出:** `dst` 图像在矩形区域 (2,2) 到 (6,6) 的像素颜色将变为红色 (255, 0, 0, 255)。

**命令行参数的具体处理：**

这部分代码本身 **没有涉及到命令行参数的处理**。 命令行参数的处理通常会在使用 `image/draw` 包的上层应用中进行，例如读取图像文件路径、指定合成模式等。 `image/draw` 包专注于图像合成的逻辑实现。

**使用者易犯错的点：**

* **不理解 `Image` 接口的要求:**  使用者可能会尝试将 `image.Image` 类型的实例直接传递给需要 `draw.Image` 类型的函数，导致编译错误。因为 `draw.Image` 接口额外定义了 `Set` 方法。需要确保操作的图像类型实现了 `draw.Image` 接口。

* **误解 `sp` 参数的含义:** `sp` 是源图像的起始点，它与目标图像的 `r.Min` 对齐。 初学者可能会错误地认为 `sp` 是目标图像上的坐标。

* **忽略图像边界:**  如果没有正确理解 `clip` 函数的作用，可能会出现尝试在图像边界之外进行绘制的情况，虽然 `clip` 会处理这种情况，但理解其工作原理有助于避免潜在的错误。

* **不理解不同的 `Op` 操作符的区别:**  错误地选择了合成操作符会导致意料之外的图像合成结果。例如，使用 `Src` 会完全覆盖目标区域，而 `Over` 则会考虑源图像的 alpha 值进行混合。

**总结这部分的功能：**

总而言之，`go/src/image/draw/draw.go` 的第一部分定义了图像合成所需的基本 building blocks：表示可修改像素的图像接口 (`Image`, `RGBA64Image`)，图像量化的接口 (`Quantizer`)，以及定义合成方式和执行合成操作的接口和类型 (`Op`, `Drawer`)。它为后续实现具体的图像合成算法（例如，在文件的第二部分中）提供了必要的抽象和结构。这部分代码是整个 `image/draw` 包的基础。

Prompt: 
```
这是路径为go/src/image/draw/draw.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package draw provides image composition functions.
//
// See "The Go image/draw package" for an introduction to this package:
// https://golang.org/doc/articles/image_draw.html
package draw

import (
	"image"
	"image/color"
	"image/internal/imageutil"
)

// m is the maximum color value returned by image.Color.RGBA.
const m = 1<<16 - 1

// Image is an image.Image with a Set method to change a single pixel.
type Image interface {
	image.Image
	Set(x, y int, c color.Color)
}

// RGBA64Image extends both the [Image] and [image.RGBA64Image] interfaces with a
// SetRGBA64 method to change a single pixel. SetRGBA64 is equivalent to
// calling Set, but it can avoid allocations from converting concrete color
// types to the [color.Color] interface type.
type RGBA64Image interface {
	image.RGBA64Image
	Set(x, y int, c color.Color)
	SetRGBA64(x, y int, c color.RGBA64)
}

// Quantizer produces a palette for an image.
type Quantizer interface {
	// Quantize appends up to cap(p) - len(p) colors to p and returns the
	// updated palette suitable for converting m to a paletted image.
	Quantize(p color.Palette, m image.Image) color.Palette
}

// Op is a Porter-Duff compositing operator.
type Op int

const (
	// Over specifies ``(src in mask) over dst''.
	Over Op = iota
	// Src specifies ``src in mask''.
	Src
)

// Draw implements the [Drawer] interface by calling the Draw function with this
// [Op].
func (op Op) Draw(dst Image, r image.Rectangle, src image.Image, sp image.Point) {
	DrawMask(dst, r, src, sp, nil, image.Point{}, op)
}

// Drawer contains the [Draw] method.
type Drawer interface {
	// Draw aligns r.Min in dst with sp in src and then replaces the
	// rectangle r in dst with the result of drawing src on dst.
	Draw(dst Image, r image.Rectangle, src image.Image, sp image.Point)
}

// FloydSteinberg is a [Drawer] that is the [Src] [Op] with Floyd-Steinberg error
// diffusion.
var FloydSteinberg Drawer = floydSteinberg{}

type floydSteinberg struct{}

func (floydSteinberg) Draw(dst Image, r image.Rectangle, src image.Image, sp image.Point) {
	clip(dst, &r, src, &sp, nil, nil)
	if r.Empty() {
		return
	}
	drawPaletted(dst, r, src, sp, true)
}

// clip clips r against each image's bounds (after translating into the
// destination image's coordinate space) and shifts the points sp and mp by
// the same amount as the change in r.Min.
func clip(dst Image, r *image.Rectangle, src image.Image, sp *image.Point, mask image.Image, mp *image.Point) {
	orig := r.Min
	*r = r.Intersect(dst.Bounds())
	*r = r.Intersect(src.Bounds().Add(orig.Sub(*sp)))
	if mask != nil {
		*r = r.Intersect(mask.Bounds().Add(orig.Sub(*mp)))
	}
	dx := r.Min.X - orig.X
	dy := r.Min.Y - orig.Y
	if dx == 0 && dy == 0 {
		return
	}
	sp.X += dx
	sp.Y += dy
	if mp != nil {
		mp.X += dx
		mp.Y += dy
	}
}

func processBackward(dst image.Image, r image.Rectangle, src image.Image, sp image.Point) bool {
	return dst == src &&
		r.Overlaps(r.Add(sp.Sub(r.Min))) &&
		(sp.Y < r.Min.Y || (sp.Y == r.Min.Y && sp.X < r.Min.X))
}

// Draw calls [DrawMask] with a nil mask.
func Draw(dst Image, r image.Rectangle, src image.Image, sp image.Point, op Op) {
	DrawMask(dst, r, src, sp, nil, image.Point{}, op)
}

// DrawMask aligns r.Min in dst with sp in src and mp in mask and then replaces the rectangle r
// in dst with the result of a Porter-Duff composition. A nil mask is treated as opaque.
func DrawMask(dst Image, r image.Rectangle, src image.Image, sp image.Point, mask image.Image, mp image.Point, op Op) {
	clip(dst, &r, src, &sp, mask, &mp)
	if r.Empty() {
		return
	}

	// Fast paths for special cases. If none of them apply, then we fall back
	// to general but slower implementations.
	//
	// For NRGBA and NRGBA64 image types, the code paths aren't just faster.
	// They also avoid the information loss that would otherwise occur from
	// converting non-alpha-premultiplied color to and from alpha-premultiplied
	// color. See TestDrawSrcNonpremultiplied.
	switch dst0 := dst.(type) {
	case *image.RGBA:
		if op == Over {
			if mask == nil {
				switch src0 := src.(type) {
				case *image.Uniform:
					sr, sg, sb, sa := src0.RGBA()
					if sa == 0xffff {
						drawFillSrc(dst0, r, sr, sg, sb, sa)
					} else {
						drawFillOver(dst0, r, sr, sg, sb, sa)
					}
					return
				case *image.RGBA:
					drawCopyOver(dst0, r, src0, sp)
					return
				case *image.NRGBA:
					drawNRGBAOver(dst0, r, src0, sp)
					return
				case *image.YCbCr:
					// An image.YCbCr is always fully opaque, and so if the
					// mask is nil (i.e. fully opaque) then the op is
					// effectively always Src. Similarly for image.Gray and
					// image.CMYK.
					if imageutil.DrawYCbCr(dst0, r, src0, sp) {
						return
					}
				case *image.Gray:
					drawGray(dst0, r, src0, sp)
					return
				case *image.CMYK:
					drawCMYK(dst0, r, src0, sp)
					return
				}
			} else if mask0, ok := mask.(*image.Alpha); ok {
				switch src0 := src.(type) {
				case *image.Uniform:
					drawGlyphOver(dst0, r, src0, mask0, mp)
					return
				case *image.RGBA:
					drawRGBAMaskOver(dst0, r, src0, sp, mask0, mp)
					return
				case *image.Gray:
					drawGrayMaskOver(dst0, r, src0, sp, mask0, mp)
					return
				// Case order matters. The next case (image.RGBA64Image) is an
				// interface type that the concrete types above also implement.
				case image.RGBA64Image:
					drawRGBA64ImageMaskOver(dst0, r, src0, sp, mask0, mp)
					return
				}
			}
		} else {
			if mask == nil {
				switch src0 := src.(type) {
				case *image.Uniform:
					sr, sg, sb, sa := src0.RGBA()
					drawFillSrc(dst0, r, sr, sg, sb, sa)
					return
				case *image.RGBA:
					d0 := dst0.PixOffset(r.Min.X, r.Min.Y)
					s0 := src0.PixOffset(sp.X, sp.Y)
					drawCopySrc(
						dst0.Pix[d0:], dst0.Stride, r, src0.Pix[s0:], src0.Stride, sp, 4*r.Dx())
					return
				case *image.NRGBA:
					drawNRGBASrc(dst0, r, src0, sp)
					return
				case *image.YCbCr:
					if imageutil.DrawYCbCr(dst0, r, src0, sp) {
						return
					}
				case *image.Gray:
					drawGray(dst0, r, src0, sp)
					return
				case *image.CMYK:
					drawCMYK(dst0, r, src0, sp)
					return
				}
			}
		}
		drawRGBA(dst0, r, src, sp, mask, mp, op)
		return
	case *image.Paletted:
		if op == Src && mask == nil {
			if src0, ok := src.(*image.Uniform); ok {
				colorIndex := uint8(dst0.Palette.Index(src0.C))
				i0 := dst0.PixOffset(r.Min.X, r.Min.Y)
				i1 := i0 + r.Dx()
				for i := i0; i < i1; i++ {
					dst0.Pix[i] = colorIndex
				}
				firstRow := dst0.Pix[i0:i1]
				for y := r.Min.Y + 1; y < r.Max.Y; y++ {
					i0 += dst0.Stride
					i1 += dst0.Stride
					copy(dst0.Pix[i0:i1], firstRow)
				}
				return
			} else if !processBackward(dst, r, src, sp) {
				drawPaletted(dst0, r, src, sp, false)
				return
			}
		}
	case *image.NRGBA:
		if op == Src && mask == nil {
			if src0, ok := src.(*image.NRGBA); ok {
				d0 := dst0.PixOffset(r.Min.X, r.Min.Y)
				s0 := src0.PixOffset(sp.X, sp.Y)
				drawCopySrc(
					dst0.Pix[d0:], dst0.Stride, r, src0.Pix[s0:], src0.Stride, sp, 4*r.Dx())
				return
			}
		}
	case *image.NRGBA64:
		if op == Src && mask == nil {
			if src0, ok := src.(*image.NRGBA64); ok {
				d0 := dst0.PixOffset(r.Min.X, r.Min.Y)
				s0 := src0.PixOffset(sp.X, sp.Y)
				drawCopySrc(
					dst0.Pix[d0:], dst0.Stride, r, src0.Pix[s0:], src0.Stride, sp, 8*r.Dx())
				return
			}
		}
	}

	x0, x1, dx := r.Min.X, r.Max.X, 1
	y0, y1, dy := r.Min.Y, r.Max.Y, 1
	if processBackward(dst, r, src, sp) {
		x0, x1, dx = x1-1, x0-1, -1
		y0, y1, dy = y1-1, y0-1, -1
	}

	// FALLBACK1.17
	//
	// Try the draw.RGBA64Image and image.RGBA64Image interfaces, part of the
	// standard library since Go 1.17. These are like the draw.Image and
	// image.Image interfaces but they can avoid allocations from converting
	// concrete color types to the color.Color interface type.

	if dst0, _ := dst.(RGBA64Image); dst0 != nil {
		if src0, _ := src.(image.RGBA64Image); src0 != nil {
			if mask == nil {
				sy := sp.Y + y0 - r.Min.Y
				my := mp.Y + y0 - r.Min.Y
				for y := y0; y != y1; y, sy, my = y+dy, sy+dy, my+dy {
					sx := sp.X + x0 - r.Min.X
					mx := mp.X + x0 - r.Min.X
					for x := x0; x != x1; x, sx, mx = x+dx, sx+dx, mx+dx {
						if op == Src {
							dst0.SetRGBA64(x, y, src0.RGBA64At(sx, sy))
						} else {
							srgba := src0.RGBA64At(sx, sy)
							a := m - uint32(srgba.A)
							drgba := dst0.RGBA64At(x, y)
							dst0.SetRGBA64(x, y, color.RGBA64{
								R: uint16((uint32(drgba.R)*a)/m) + srgba.R,
								G: uint16((uint32(drgba.G)*a)/m) + srgba.G,
								B: uint16((uint32(drgba.B)*a)/m) + srgba.B,
								A: uint16((uint32(drgba.A)*a)/m) + srgba.A,
							})
						}
					}
				}
				return

			} else if mask0, _ := mask.(image.RGBA64Image); mask0 != nil {
				sy := sp.Y + y0 - r.Min.Y
				my := mp.Y + y0 - r.Min.Y
				for y := y0; y != y1; y, sy, my = y+dy, sy+dy, my+dy {
					sx := sp.X + x0 - r.Min.X
					mx := mp.X + x0 - r.Min.X
					for x := x0; x != x1; x, sx, mx = x+dx, sx+dx, mx+dx {
						ma := uint32(mask0.RGBA64At(mx, my).A)
						switch {
						case ma == 0:
							if op == Over {
								// No-op.
							} else {
								dst0.SetRGBA64(x, y, color.RGBA64{})
							}
						case ma == m && op == Src:
							dst0.SetRGBA64(x, y, src0.RGBA64At(sx, sy))
						default:
							srgba := src0.RGBA64At(sx, sy)
							if op == Over {
								drgba := dst0.RGBA64At(x, y)
								a := m - (uint32(srgba.A) * ma / m)
								dst0.SetRGBA64(x, y, color.RGBA64{
									R: uint16((uint32(drgba.R)*a + uint32(srgba.R)*ma) / m),
									G: uint16((uint32(drgba.G)*a + uint32(srgba.G)*ma) / m),
									B: uint16((uint32(drgba.B)*a + uint32(srgba.B)*ma) / m),
									A: uint16((uint32(drgba.A)*a + uint32(srgba.A)*ma) / m),
								})
							} else {
								dst0.SetRGBA64(x, y, color.RGBA64{
									R: uint16(uint32(srgba.R) * ma / m),
									G: uint16(uint32(srgba.G) * ma / m),
									B: uint16(uint32(srgba.B) * ma / m),
									A: uint16(uint32(srgba.A) * ma / m),
								})
							}
						}
					}
				}
				return
			}
		}
	}

	// FALLBACK1.0
	//
	// If none of the faster code paths above apply, use the draw.Image and
	// image.Image interfaces, part of the standard library since Go 1.0.

	var out color.RGBA64
	sy := sp.Y + y0 - r.Min.Y
	my := mp.Y + y0 - r.Min.Y
	for y := y0; y != y1; y, sy, my = y+dy, sy+dy, my+dy {
		sx := sp.X + x0 - r.Min.X
		mx := mp.X + x0 - r.Min.X
		for x := x0; x != x1; x, sx, mx = x+dx, sx+dx, mx+dx {
			ma := uint32(m)
			if mask != nil {
				_, _, _, ma = mask.At(mx, my).RGBA()
			}
			switch {
			case ma == 0:
				if op == Over {
					// No-op.
				} else {
					dst.Set(x, y, color.Transparent)
				}
			case ma == m && op == Src:
				dst.Set(x, y, src.At(sx, sy))
			default:
				sr, sg, sb, sa := src.At(sx, sy).RGBA()
				if op == Over {
					dr, dg, db, da := dst.At(x, y).RGBA()
					a := m - (sa * ma / m)
					out.R = uint16((dr*a + sr*ma) / m)
					out.G = uint16((dg*a + sg*ma) / m)
					out.B = uint16((db*a + sb*ma) / m)
					out.A = uint16((da*a + sa*ma) / m)
				} else {
					out.R = uint16(sr * ma / m)
					out.G = uint16(sg * ma / m)
					out.B = uint16(sb * ma / m)
					out.A = uint16(sa * ma / m)
				}
				// The third argument is &out instead of out (and out is
				// declared outside of the inner loop) to avoid the implicit
				// conversion to color.Color here allocating memory in the
				// inner loop if sizeof(color.RGBA64) > sizeof(uintptr).
				dst.Set(x, y, &out)
			}
		}
	}
}

func drawFillOver(dst *image.RGBA, r image.Rectangle, sr, sg, sb, sa uint32) {
	// The 0x101 is here for the same reason as in drawRGBA.
	a := (m - sa) * 0x101
	i0 := dst.PixOffset(r.Min.X, r.Min.Y)
	i1 := i0 + r.Dx()*4
	for y := r.Min.Y; y != r.Max.Y; y++ {
		for i := i0; i < i1; i += 4 {
			dr := &dst.Pix[i+0]
			dg := &dst.Pix[i+1]
			db := &dst.Pix[i+2]
			da := &dst.Pix[i+3]

			*dr = uint8((uint32(*dr)*a/m + sr) >> 8)
			*dg = uint8((uint32(*dg)*a/m + sg) >> 8)
			*db = uint8((uint32(*db)*a/m + sb) >> 8)
			*da = uint8((uint32(*da)*a/m + sa) >> 8)
		}
		i0 += dst.Stride
		i1 += dst.Stride
	}
}

func drawFillSrc(dst *image.RGBA, r image.Rectangle, sr, sg, sb, sa uint32) {
	sr8 := uint8(sr >> 8)
	sg8 := uint8(sg >> 8)
	sb8 := uint8(sb >> 8)
	sa8 := uint8(sa >> 8)
	// The built-in copy function is faster than a straightforward for loop to fill the destination with
	// the color, but copy requires a slice source. We therefore use a for loop to fill the first row, and
	// then use the first row as the slice source for the remaining rows.
	i0 := dst.PixOffset(r.Min.X, r.Min.Y)
	i1 := i0 + r.Dx()*4
	for i := i0; i < i1; i += 4 {
		dst.Pix[i+0] = sr8
		dst.Pix[i+1] = sg8
		dst.Pix[i+2] = sb8
		dst.Pix[i+3] = sa8
	}
	firstRow := dst.Pix[i0:i1]
	for y := r.Min.Y + 1; y < r.Max.Y; y++ {
		i0 += dst.Stride
		i1 += dst.Stride
		copy(dst.Pix[i0:i1], firstRow)
	}
}

func drawCopyOver(dst *image.RGBA, r image.Rectangle, src *image.RGBA, sp image.Point) {
	dx, dy := r.Dx(), r.Dy()
	d0 := dst.PixOffset(r.Min.X, r.Min.Y)
	s0 := src.PixOffset(sp.X, sp.Y)
	var (
		ddelta, sdelta int
		i0, i1, idelta int
	)
	if r.Min.Y < sp.Y || r.Min.Y == sp.Y && r.Min.X <= sp.X {
		ddelta = dst.Stride
		sdelta = src.Stride
		i0, i1, idelta = 0, dx*4, +4
	} else {
		// If the source start point is higher than the destination start point, or equal height but to the left,
		// then we compose the rows in right-to-left, bottom-up order instead of left-to-right, top-down.
		d0 += (dy - 1) * dst.Stride
		s0 += (dy - 1) * src.Stride
		ddelta = -dst.Stride
		sdelta = -src.Stride
		i0, i1, idelta = (dx-1)*4, -4, -4
	}
	for ; dy > 0; dy-- {
		dpix := dst.Pix[d0:]
		spix := src.Pix[s0:]
		for i := i0; i != i1; i += idelta {
			s := spix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
			sr := uint32(s[0]) * 0x101
			sg := uint32(s[1]) * 0x101
			sb := uint32(s[2]) * 0x101
			sa := uint32(s[3]) * 0x101

			// The 0x101 is here for the same reason as in drawRGBA.
			a := (m - sa) * 0x101

			d := dpix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
			d[0] = uint8((uint32(d[0])*a/m + sr) >> 8)
			d[1] = uint8((uint32(d[1])*a/m + sg) >> 8)
			d[2] = uint8((uint32(d[2])*a/m + sb) >> 8)
			d[3] = uint8((uint32(d[3])*a/m + sa) >> 8)
		}
		d0 += ddelta
		s0 += sdelta
	}
}

// drawCopySrc copies bytes to dstPix from srcPix. These arguments roughly
// correspond to the Pix fields of the image package's concrete image.Image
// implementations, but are offset (dstPix is dst.Pix[dpOffset:] not dst.Pix).
func drawCopySrc(
	dstPix []byte, dstStride int, r image.Rectangle,
	srcPix []byte, srcStride int, sp image.Point,
	bytesPerRow int) {

	d0, s0, ddelta, sdelta, dy := 0, 0, dstStride, srcStride, r.Dy()
	if r.Min.Y > sp.Y {
		// If the source start point is higher than the destination start
		// point, then we compose the rows in bottom-up order instead of
		// top-down. Unlike the drawCopyOver function, we don't have to check
		// the x coordinates because the built-in copy function can handle
		// overlapping slices.
		d0 = (dy - 1) * dstStride
		s0 = (dy - 1) * srcStride
		ddelta = -dstStride
		sdelta = -srcStride
	}
	for ; dy > 0; dy-- {
		copy(dstPix[d0:d0+bytesPerRow], srcPix[s0:s0+bytesPerRow])
		d0 += ddelta
		s0 += sdelta
	}
}

func drawNRGBAOver(dst *image.RGBA, r image.Rectangle, src *image.NRGBA, sp image.Point) {
	i0 := (r.Min.X - dst.Rect.Min.X) * 4
	i1 := (r.Max.X - dst.Rect.Min.X) * 4
	si0 := (sp.X - src.Rect.Min.X) * 4
	yMax := r.Max.Y - dst.Rect.Min.Y

	y := r.Min.Y - dst.Rect.Min.Y
	sy := sp.Y - src.Rect.Min.Y
	for ; y != yMax; y, sy = y+1, sy+1 {
		dpix := dst.Pix[y*dst.Stride:]
		spix := src.Pix[sy*src.Stride:]

		for i, si := i0, si0; i < i1; i, si = i+4, si+4 {
			// Convert from non-premultiplied color to pre-multiplied color.
			s := spix[si : si+4 : si+4] // Small cap improves performance, see https://golang.org/issue/27857
			sa := uint32(s[3]) * 0x101
			sr := uint32(s[0]) * sa / 0xff
			sg := uint32(s[1]) * sa / 0xff
			sb := uint32(s[2]) * sa / 0xff

			d := dpix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
			dr := uint32(d[0])
			dg := uint32(d[1])
			db := uint32(d[2])
			da := uint32(d[3])

			// The 0x101 is here for the same reason as in drawRGBA.
			a := (m - sa) * 0x101

			d[0] = uint8((dr*a/m + sr) >> 8)
			d[1] = uint8((dg*a/m + sg) >> 8)
			d[2] = uint8((db*a/m + sb) >> 8)
			d[3] = uint8((da*a/m + sa) >> 8)
		}
	}
}

func drawNRGBASrc(dst *image.RGBA, r image.Rectangle, src *image.NRGBA, sp image.Point) {
	i0 := (r.Min.X - dst.Rect.Min.X) * 4
	i1 := (r.Max.X - dst.Rect.Min.X) * 4
	si0 := (sp.X - src.Rect.Min.X) * 4
	yMax := r.Max.Y - dst.Rect.Min.Y

	y := r.Min.Y - dst.Rect.Min.Y
	sy := sp.Y - src.Rect.Min.Y
	for ; y != yMax; y, sy = y+1, sy+1 {
		dpix := dst.Pix[y*dst.Stride:]
		spix := src.Pix[sy*src.Stride:]

		for i, si := i0, si0; i < i1; i, si = i+4, si+4 {
			// Convert from non-premultiplied color to pre-multiplied color.
			s := spix[si : si+4 : si+4] // Small cap improves performance, see https://golang.org/issue/27857
			sa := uint32(s[3]) * 0x101
			sr := uint32(s[0]) * sa / 0xff
			sg := uint32(s[1]) * sa / 0xff
			sb := uint32(s[2]) * sa / 0xff

			d := dpix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
			d[0] = uint8(sr >> 8)
			d[1] = uint8(sg >> 8)
			d[2] = uint8(sb >> 8)
			d[3] = uint8(sa >> 8)
		}
	}
}

func drawGray(dst *image.RGBA, r image.Rectangle, src *image.Gray, sp image.Point) {
	i0 := (r.Min.X - dst.Rect.Min.X) * 4
	i1 := (r.Max.X - dst.Rect.Min.X) * 4
	si0 := (sp.X - src.Rect.Min.X) * 1
	yMax := r.Max.Y - dst.Rect.Min.Y

	y := r.Min.Y - dst.Rect.Min.Y
	sy := sp.Y - src.Rect.Min.Y
	for ; y != yMax; y, sy = y+1, sy+1 {
		dpix := dst.Pix[y*dst.Stride:]
		spix := src.Pix[sy*src.Stride:]

		for i, si := i0, si0; i < i1; i, si = i+4, si+1 {
			p := spix[si]
			d := dpix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
			d[0] = p
			d[1] = p
			d[2] = p
			d[3] = 255
		}
	}
}

func drawCMYK(dst *image.RGBA, r image.Rectangle, src *image.CMYK, sp image.Point) {
	i0 := (r.Min.X - dst.Rect.Min.X) * 4
	i1 := (r.Max.X - dst.Rect.Min.X) * 4
	si0 := (sp.X - src.Rect.Min.X) * 4
	yMax := r.Max.Y - dst.Rect.Min.Y

	y := r.Min.Y - dst.Rect.Min.Y
	sy := sp.Y - src.Rect.Min.Y
	for ; y != yMax; y, sy = y+1, sy+1 {
		dpix := dst.Pix[y*dst.Stride:]
		spix := src.Pix[sy*src.Stride:]

		for i, si := i0, si0; i < i1; i, si = i+4, si+4 {
			s := spix[si : si+4 : si+4] // Small cap improves performance, see https://golang.org/issue/27857
			d := dpix[i : i+4 : i+4]
			d[0], d[1], d[2] = color.CMYKToRGB(s[0], s[1], s[2], s[3])
			d[3] = 255
		}
	}
}

func drawGlyphOver(dst *image.RGBA, r image.Rectangle, src *image.Uniform, mask *image.Alpha, mp image.Point) {
	i0 := dst.PixOffset(r.Min.X, r.Min.Y)
	i1 := i0 + r.Dx()*4
	mi0 := mask.PixOffset(mp.X, mp.Y)
	sr, sg, sb, sa := src.RGBA()
	for y, my := r.Min.Y, mp.Y; y != r.Max.Y; y, my = y+1, my+1 {
		for i, mi := i0, mi0; i < i1; i, mi = i+4, mi+1 {
			ma := uint32(mask.Pix[mi])
			if ma == 0 {
				continue
			}
			ma |= ma << 8

			// The 0x101 is here for the same reason as in drawRGBA.
			a := (m - (sa * ma / m)) * 0x101

			d := dst.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
			d[0] = uint8((uint32(d[0])*a + sr*ma) / m >> 8)
			d[1] = uint8((uint32(d[1])*a + sg*ma) / m >> 8)
			d[2] = uint8((uint32(d[2])*a + sb*ma) / m >> 8)
			d[3] = uint8((uint32(d[3])*a + sa*ma) / m >> 8)
		}
		i0 += dst.Stride
		i1 += dst.Stride
		mi0 += mask.Stride
	}
}

func drawGrayMaskOver(dst *image.RGBA, r image.Rectangle, src *image.Gray, sp image.Point, mask *image.Alpha, mp image.Point) {
	x0, x1, dx := r.Min.X, r.Max.X, 1
	y0, y1, dy := r.Min.Y, r.Max.Y, 1
	if r.Overlaps(r.Add(sp.Sub(r.Min))) {
		if sp.Y < r.Min.Y || sp.Y == r.Min.Y && sp.X < r.Min.X {
			x0, x1, dx = x1-1, x0-1, -1
			y0, y1, dy = y1-1, y0-1, -1
		}
	}

	sy := sp.Y + y0 - r.Min.Y
	my := mp.Y + y0 - r.Min.Y
	sx0 := sp.X + x0 - r.Min.X
	mx0 := mp.X + x0 - r.Min.X
	sx1 := sx0 + (x1 - x0)
	i0 := dst.PixOffset(x0, y0)
	di := dx * 4
	for y := y0; y != y1; y, sy, my = y+dy, sy+dy, my+dy {
		for i, sx, mx := i0, sx0, mx0; sx != sx1; i, sx, mx = i+di, sx+dx, mx+dx {
			mi := mask.PixOffset(mx, my)
			ma := uint32(mask.Pix[mi])
			ma |= ma << 8
			si := src.PixOffset(sx, sy)
			sy := uint32(src.Pix[si])
			sy |= sy << 8
			sa := uint32(0xffff)

			d := dst.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
			dr := uint32(d[0])
			dg := uint32(d[1])
			db := uint32(d[2])
			da := uint32(d[3])

			// dr, dg, db and da are all 8-bit color at the moment, ranging in [0,255].
			// We work in 16-bit color, and so would normally do:
			// dr |= dr << 8
			// and similarly for dg, db and da, but instead we multiply a
			// (which is a 16-bit color, ranging in [0,65535]) by 0x101.
			// This yields the same result, but is fewer arithmetic operations.
			a := (m - (sa * ma / m)) * 0x101

			d[0] = uint8((dr*a + sy*ma) / m >> 8)
			d[1] = uint8((dg*a + sy*ma) / m >> 8)
			d[2] = uint8((db*a + sy*ma) / m >> 8)
			d[3] = uint8((da*a + sa*ma) / m >> 8)
		}
		i0 += dy * dst.Stride
	}
}

func drawRGBAMaskOver(dst *image.RGBA, r image.Rectangle, src *image.RGBA, sp image.Point, mask *image.Alpha, mp image.Point) {
	x0, x1, dx := r.Min.X, r.Max.X, 1
	y0, y1, dy := r.Min.Y, r.Max.Y, 1
	if dst == src && r.Overlaps(r.Add(sp.Sub(r.Min))) {
		if sp.Y < r.Min.Y || sp.Y == r.Min.Y && sp.X < r.Min.X {
			x0, x1, dx = x1-1, x0-1, -1
			y0, y1, dy = y1-1, y0-1, -1
		}
	}

	sy := sp.Y + y0 - r.Min.Y
	my := mp.Y + y0 - r.Min.Y
	sx0 := sp.X + x0 - r.Min.X
	mx0 := mp.X + x0 - r.Min.X
	sx1 := sx0 + (x1 - x0)
	i0 := dst.PixOffset(x0, y0)
	di := dx * 4
	for y := y0; y != y1; y, sy, my = y+dy, sy+dy, my+dy {
		for i, sx, mx := i0, sx0, mx0; sx != sx1; i, sx, mx = i+di, sx+dx, mx+dx {
			mi := mask.PixOffset(mx, my)
			ma := uint32(mask.Pix[mi])
			ma |= ma << 8
			si := src.PixOffset(sx, sy)
			sr := uint32(src.Pix[si+0])
			sg := uint32(src.Pix[si+1])
			sb := uint32(src.Pix[si+2])
			sa := uint32(src.Pix[si+3])
			sr |= sr << 8
			sg |= sg << 8
			sb |= sb << 8
			sa |= sa << 8
			d := dst.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
			dr := uint32(d[0])
			dg := uint32(d[1])
			db := uint32(d[2])
			da := uint32(d[3])

			// dr, dg, db and da are all 8-bit color at the moment, ranging in [0,255].
			// We work in 16-bit color, and so would normally do:
			// dr |= dr << 8
			// and similarly for dg, db and da, but instead we multiply a
			// (which is a 16-bit color, ranging in [0,65535]) by 0x101.
			// This yields the same result, but is fewer arithmetic operations.
			a := (m - (sa * ma / m)) * 0x101

			d[0] = uint8((dr*a + sr*ma) / m >> 8)
			d[1] = uint8((dg*a + sg*ma) / m >> 8)
			d[2] = uint8((db*a + sb*ma) / m >> 8)
			d[3] = uint8((da*a + sa*ma) / m >> 8)
		}
		i0 += dy * dst.Stride
	}
}

func drawRGBA64ImageMaskOver(dst *image.RGBA, r image.Rectangle, src image.RGBA64Image, sp image.Point, mask *image.Alpha, mp image.Point) {
	x0, x1, dx := r.Min.X, r.Max.X, 1
	y0, y1, dy := r.Min.Y, r.Max.Y, 1
	if image.Image(dst) == src && r.Overlaps(r.Add(sp.Sub(r.Min))) {
		if sp.Y < r.Min.Y || sp.Y == r.Min.Y && sp.X < r.Min.X {
			x0, x1, dx = x1-1, x0-1, -1
			y0, y1, dy = y1-1, y0-1, -1
		}
	}

	sy := sp.Y + y0 - r.Min.Y
	my := mp.Y + y0 - r.Min.Y
	sx0 := sp.X + x0 - r.Min.X
	mx0 := mp.X + x0 - r.Min.X
	sx1 := sx0 + (x1 - x0)
	i0 := dst.PixOffset(x0, y0)
	di := dx * 4
	for y := y0; y != y1; y, sy, my = y+dy, sy+dy, my+dy {
		for i, sx, mx := i0, sx0, mx0; sx != sx1; i, sx, mx = i+di, sx+dx, mx+dx {
			mi := mask.PixOffset(mx, my)
			ma := uint32(mask.Pix[mi])
			ma |= ma << 8
			srgba := src.RGBA64At(sx, sy)
			d := dst.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
			dr := uint32(d[0])
			dg := uint32(d[1])
			db := uint32(d[2])
			da := uint32(d[3])

			// dr, dg, db and da are all 8-bit color at the moment, ranging in [0,255].
			// We work in 16-bit color, and so would normally do:
			// dr |= dr << 8
			// and similarly for dg, db and da, but instead we multiply a
			// (which is a 16-bit color, ranging in [0,65535]) by 0x101.
			// This yields the same result, but is fewer arithmetic operations.
			a := (m - (uint32(srgba.A) * ma / m)) * 0x101

			d[0] = uint8((dr*a + uint32(srgba.R)*ma) / m >> 8)
			d[1] = uint8((dg*a + uint32(srgba.G)*ma) / m >> 8)
			d[2] = uint8((db*a + uint32(srgba.B)*ma) / m >> 8)
			d[3] = uint8((da*a + uint32(srgba.A)*ma) / m >> 8)
		}
		i0 += dy * dst.Stride
	}
}

func drawRGBA(dst *image.RGBA, r image.Rectangle, src image.Image, sp image.Point, mask image.Image, mp image.Point, op Op) {
	x0, x1, dx := r.Min.X, r.Max.X, 1
	y0, y1, dy := r.Min.Y, r.Max.Y, 1
	if image.Image(dst) == src && r.Overlaps(r.Add(sp.Sub(r.Min))) {
		if sp.Y < r.Min.Y || sp.Y == r.Min.Y && sp.X < r.Min.X {
			x0, x1, dx = x1-1, x0-1, -1
			y0, y1, dy = y1-1, y0-1, -1
		}
	}

	sy := sp.Y + y0 - r.Min.Y
	my := mp.Y + y0 - r.Min.Y
	sx0 := sp.X + x0 - r.Min.X
	mx0 := mp.X + x0 - r.Min.X
	sx1 := sx0 + (x1 - x0)
	i0 := dst.PixOffset(x0, y0)
	di := dx * 4

	// Try the image.RGBA64Image interface, part of the standard library since
	// Go 1.17.
	//
	// This optimization is similar to how FALLBACK1.17 optimizes FALLBACK1.0
	// in DrawMask, except here the concrete type of dst is known to be
	// *image.RGBA.
	if src0, _ := src.(image.RGBA64Image); src0 != nil {
		if mask == nil {
			if op == Over {
				for y := y0; y != y1; y, sy, my = y+dy, sy+dy, my+dy {
					for i, sx, mx := i0, sx0, mx0; sx != sx1; i, sx, mx = i+di, sx+dx, mx+dx {
						srgba := src0.RGBA64At(sx, sy)
						d := dst.Pix[i : i+4 : i+4]
						dr := uint32(d[0])
						dg := uint32(d[1])
						db := uint32(d[2])
						da := uint32(d[3])
						a := (m - uint32(srgba.A)) * 0x101
						d[0] = uint8((dr*a/m + uint32(srgba.R)) >> 8)
						d[1] = uint8((dg*a/m + uint32(srgba.G)) >> 8)
						d[2] = uint8((db*a/m + uint32(srgba.B)) >> 8)
						d[3] = uint8((da*a/m + uint32(srgba.A)) >> 8)
					}
					i0 += dy * dst.Stride
				}
			} else {
				for y := y0; y != y1; y, sy, my = y+dy, sy+dy, my+dy {
					for i, sx, mx := i0, sx0, mx0; sx != sx1; i, sx, mx = i+di, sx+dx, mx+dx {
						srgba := src0.RGBA64At(sx, sy)
						d := dst.Pix[i : i+4 : i+4]
						d[0] = uint8(srgba.R >> 8)
						d[1] = uint8(srgba.G >> 8)
						d[2] = uint8(srgba.B >> 8)
						d[3] = uint8(srgba.A >> 8)
					}
					i0 += dy * dst.Stride
				}
			}
			return

		} else if mask0, _ := mask.(image.RGBA64Image); mask0 != nil {
			if op == Over {
				for y := y0; y != y1; y, sy, my = y+dy, sy+dy, my+dy {
					for i, sx, mx := i0, sx0, mx0; sx != sx1; i, sx, mx = i+di, sx+dx, mx+dx {
						ma := uint32(mask0.RGBA64At(mx, my).A)
						srgba := src0.RGBA64At(sx, sy)
						d := dst.Pix[i : i+4 : i+4]
						dr := uint32(d[0])
						dg := uint32(d[1])
						db := uint32(d[2])
						da := uint32(d[3])
						a := (m - (uint32(srgba.A) * ma / m)) * 0x101
						d[0] = uint8((dr*a + uint32(srgba.R)*ma) / m >> 8)
						d[1] = uint8((dg*a + uint32(srgba.G)*ma) / m >> 8)
						d[2] = uint8((db*a + uint32(srgba.B)*ma) / m >> 8)
						d[3] = uint8((da*a + uint32(srgba.A)*ma) / m >> 8)
					}
					i0 += dy * dst.Stride
				}
			} else {
				for y := y0; y != y1; y, sy, my = y+dy, sy+dy, my+dy {
					for i, sx, mx := i0, sx0, mx0; sx != sx1; i, sx, mx = i+di, sx+dx, mx+dx {
						ma := uint32(mask0.RGBA64At(mx, my).A)
						srgba := src0.RGBA64At(sx, sy)
						d := dst.Pix[i : i+4 : i+4]
						d[0] = uint8(uint32(srgba.R) * ma / m >> 8)
						d[1] = uint8(uint32(srgba.G) * ma / m >> 8)
						d[2] = uint8(uint32(srgba.B) * ma / m >> 8)
						d[3] = uint8(uint32(srgba.A) * ma / m >> 8)
					}
					i0 += dy * dst.Stride
				}
			}
			return
		}
	}

	// Use the image.Image interface, part of the standard library since Go
	// 1.0.
	//
	// This is similar to FALLBACK1.0 in DrawMask, except here the concrete
	// type of dst is known to be *image.RGBA.
	for y := y0; y != y1; y, sy, my = y+dy, sy+dy, my+dy {
		for i, sx, mx := i0, sx0, mx0; sx != sx1; i, sx, mx = i+di, sx+dx, mx+dx {
			ma := uint32(m)
			if mask != nil {
				_, _, _, ma = mask.At(mx, my).RGBA()
			}
			sr, sg, sb, sa := src.At(sx, sy).RGBA()
			d := dst.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
			if op == Over {
				dr := uint32(d[0])
				dg := uint32(d[1])
				db := uint32(d[2])
				da := uint32(d[3])

				// dr, dg, db and da are all 8-bit color at the moment, ranging in [0,255].
				// We work in 16-bit color, and so would normally do:
				// dr |= dr << 8
				// and similarly for dg, db and da, but instead we multiply a
				// (which is a 16-bit color, ranging in [0,65535]) by 0x101.
				// This yields the same result, but is fewer arithmetic operations.
				a := (m - (sa * ma / m)) * 0x101

				d[0] = uint8((dr*a + sr*ma) / m >> 8)
				d[1] = uint8((dg*a + sg*ma) / m >> 8)
				d[2] = uint8((db*a + sb*ma) / m >> 8)
				d[3] = uint8((da*a + sa*ma) / m >> 8)

			} else {
				d[0] = uint8(sr * ma / m >> 8)
				d[1] = uint8(sg * ma / m >> 8)
				d[2] = uint8(sb * ma / m >> 8)
				d[3] = uint8(sa * ma / m >> 8)
			}
		}
		i0 += dy * dst.Stride
	}
}

// clamp clamps i to the interval [0, 0xffff].
func clamp(i int32) int32 {
	if i < 0 {
		return 0
	}
	if i > 0xffff {
		return 0xffff
	}
	return i
}

// sqDiff returns the squared-difference of x and y, shifted by 2 so that
// adding four of those won't overflow a uint32.
//
// x and y are both assumed to be in the range [0, 0xffff].
func sqDiff(x, y int32) uint32 {
	// This is an optimized code relying on the overflow/wrap around
	// properties of unsigned integers operations guaranteed by the language
	// spec. See sqDiff from the image/color package for more details.
	d := uint32(x - y)
	return (d * d) >> 2
}

func drawPaletted(dst Image, r image.Rectangle, src image.Image, sp image.Point, floydSteinberg bool) {
	// TODO(nigeltao): handle the case where the dst and src overlap.
	// Does it even make sense to try and do Floyd-Steinberg whilst
	// walking the image backward (right-to-left bottom-to-top)?

	// If dst is an *image.Paletted, we have a fast path for dst.Set and
	// dst.At. The dst.Set equivalent is a batch version of the algorithm
	// used by color.Palette's Index method in image/color/color.go, plus
	// optional Floyd-Steinberg error diffusion.
	palette, pix, stride := [][4]int32(nil), []byte(nil), 0
	if p, ok := dst.(*image.Paletted); ok {
		palette = make([][4]int32, len(p.Palette))
		for i, col := range p.Palette {
			r, g, b, a := col.RGBA()
			palette[i][0] = int32(r)
			palette[i][1] = int32(g)
			palette[i][2] = int32(b)
			palette[i][3] = int32(a)
		}
		pix, stride = p.Pix[p.PixOffset(r.Min.X, r.Min.Y):], p.Stride
	}

	// quantErrorCurr and quantErrorNext are the Floyd-Steinberg quantization
	// errors that have been propagated to the pixels in the current and next
	// rows. The +2 simplifies calculation near the edges.
	var quantErrorCurr, quantErrorNext [][4]int32
	if floydSteinberg {
		quantErrorCurr = make([][4]int32, r.Dx()+2)
		quantErrorNext = make([][4]int32, r.Dx()+2)
	}
	pxRGBA := func(x, y int) (r, g, b, a uint32) { return src.At(x, y).RGBA() }
	// Fast paths for special cases to avoid excessive use of the color.Color
	// interface which escapes to the heap but need to be discovered for
	// each pixel on r. See also https://golang.org/issues/15759.
	switch src0 := src.(type) {
	case *image.RGBA:
		pxRGBA = func(x, y int) (r, g, b, a uint32) { return src0.RGBAAt(x, y).RGBA() }
	case *image.NRGBA:
		pxRGBA = func(x, y int) (r, g, b, a uint32) { return src0.NRGBAAt(x, y).RGBA() }
	case *image.YCbCr:
		pxRGBA = func(x, y int) (r, g, b, a uint32) { return src0.YCbCrAt(x, y).RGBA() }
	}

	// Loop over each source pixel.
	out := color.RGBA64{A: 0xffff}
	for y := 0; y != r.Dy(); y++ {
		for x := 0; x != r.Dx(); x++ {
			// er, eg and eb are the pixel's R,G,B values plus the
			// optional Floyd-Steinberg error.
			sr, sg, sb, sa := pxRGBA(sp.X+x, sp.Y+y)
			er, eg, eb, ea := int32(sr), int32(sg), int32(sb), int32(sa)
			if floydSteinberg {
				er = clamp(er + quantErrorCurr[x+1][0]/16)
				eg = clamp(eg + quantErrorCurr[x+1][1]/16)
				eb = clamp(eb + quantErrorCurr[x+1][2]/16)
				ea = clamp(ea + quantErrorCurr[x+1][3]/16)
			}

			if palette != nil {
				// Find the closest palette color in Euclidean R,G,B,A space:
				// the one that minimizes su
"""




```