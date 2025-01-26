Response:
The user wants to understand the functionality of the provided Go code snippet, which is a part of the `image` package in Go's standard library.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Purpose:** The initial comments clearly state that the `image` package provides a basic 2D image library. This is the central theme.

2. **Key Interfaces and Types:** Look for exported interfaces and structs. `Image`, `RGBAImage`, `PalettedImage`, `Config`, `Rectangle`, `Point`, `RGBA`, `RGBA64`, `NRGBA`, `NRGBA64`, `Alpha`, `Alpha16`, `Gray`, `Gray16`, `CMYK`, and `Paletted` stand out. These represent the building blocks of the image library.

3. **Image Interface:**  The `Image` interface is fundamental. Note its methods: `ColorModel()`, `Bounds()`, and `At(x, y int) color.Color`. These define the basic operations on any image.

4. **Concrete Implementations:**  The structs like `RGBA`, `Gray`, etc., are concrete implementations of the `Image` interface for different color models. Observe the common pattern:
    * `Pix []uint8`:  Holds the raw pixel data.
    * `Stride int`:  Defines the row length in bytes.
    * `Rect Rectangle`:  Specifies the image boundaries.
    * Methods like `ColorModel()`, `Bounds()`, `At()`, `RGBAAt()` (or similar), `PixOffset()`, `Set()`, `SubImage()`, and `Opaque()`.

5. **Color Models:**  The code explicitly mentions `image/color`. Realize that the structs are tied to specific color models (RGBA, Gray, etc.).

6. **Creation of Images:** The documentation hints at functions like `NewRGBA` and `NewPaletted`. Observe the `NewXxx` functions in the code. These functions allocate the underlying pixel buffer.

7. **Decoding Images:** The documentation mentions `Decode` and the need to register decoders. While the code doesn't show the decoding logic, it highlights the importance of external packages for specific image formats (like `image/png`).

8. **Security Considerations:** The documentation includes a section on security, specifically about resource exhaustion with large images. Note the recommendation to use `DecodeConfig` before `Decode`.

9. **Helper Functions:** The `pixelBufferLength` function is a helper to calculate the size of the pixel buffer, and it includes panic handling for large or negative dimensions.

10. **Method Functionality:**  For each struct, analyze the purpose of its methods:
    * `At()`:  Retrieves the color at a specific coordinate.
    * `RGBAAt()`/`GrayAt()` etc.:  Optimized retrieval for specific color types, potentially avoiding interface allocations.
    * `PixOffset()`: Calculates the byte offset for a pixel.
    * `Set()`: Modifies the color of a pixel.
    * `SubImage()`: Creates a view of a portion of the original image without copying pixel data.
    * `Opaque()`: Checks if the image is fully opaque (all alpha values are maximum).

11. **Paletted Images:** Recognize the special nature of `PalettedImage` and its `ColorIndexAt()` method, indicating the use of a color palette. The provided code snippet doesn't include the `Palette` field within the `Paletted` struct yet, but the interface definition gives a strong hint.

12. **Synthesize the Functionality:** Based on the above points, formulate a concise summary of the code's capabilities.

13. **Code Example (Mental Draft):** Think about how to demonstrate the usage. Creating a simple `RGBA` image, setting a pixel, and getting its color is a good starting point.

14. **Identify Potential Pitfalls:**  Consider common mistakes users might make. Accessing pixels outside the image bounds is a clear error condition that the code explicitly handles (returning zero values).

15. **Command Line Arguments:**  The provided code doesn't deal with command-line arguments directly. Note this absence.

By following these steps, we can systematically analyze the code and generate a comprehensive and accurate summary of its functionality. The process involves understanding the core concepts, examining the structure and methods, and connecting the code to the broader context of image processing in Go.
这段Go语言代码是 `image` 标准库的一部分，它定义了表示图像的基本接口和一些常用的图像类型。  可以将其功能归纳为：**提供了在Go语言中处理2D图像的基础框架，包括图像数据的表示、访问和创建。**

更具体地说，它实现了以下功能：

1. **定义了 `Image` 接口:**  这是所有图像类型的基本接口，规定了任何图像都应该实现的方法，包括获取颜色模型、边界和指定坐标的颜色。
2. **定义了不同的图像类型:**  提供了一系列预定义的图像类型，用于存储不同格式的像素数据：
    * `RGBA`:  以红绿蓝透明度（RGBA）顺序存储 8 位颜色分量。
    * `RGBA64`: 以红绿蓝透明度（RGBA）顺序存储 16 位颜色分量。
    * `NRGBA`:  以预乘的红绿蓝透明度（NRGBA）顺序存储 8 位颜色分量。
    * `NRGBA64`: 以预乘的红绿蓝透明度（NRGBA）顺序存储 16 位颜色分量。
    * `Alpha`:   存储 8 位透明度值。
    * `Alpha16`: 存储 16 位透明度值。
    * `Gray`:    存储 8 位灰度值。
    * `Gray16`:  存储 16 位灰度值。
    * `CMYK`:    以青品黄黑（CMYK）顺序存储 8 位颜色分量。
    * `Paletted`: 存储调色板索引。
3. **提供了访问和修改像素的方法:** 每种图像类型都实现了 `At` 方法来获取指定坐标的颜色，以及 `Set` 方法（和特定类型的 `SetRGBA`, `SetGray` 等）来设置指定坐标的颜色。
4. **提供了获取图像属性的方法:**  例如 `ColorModel()` 返回图像的颜色模型，`Bounds()` 返回图像的边界。
5. **提供了创建新图像的函数:**  例如 `NewRGBA(r Rectangle)` 可以创建一个指定边界的 `RGBA` 图像。
6. **支持子图操作:**  `SubImage(r Rectangle)` 方法允许创建一个新的 `Image`，它表示原始图像的指定区域，并与原始图像共享像素数据。
7. **提供了判断图像是否完全不透明的方法:** `Opaque()` 方法检查图像的所有像素是否都完全不透明。
8. **定义了 `Config` 结构体:** 用于存储图像的颜色模型和尺寸，这在解码图像配置信息时非常有用。
9. **定义了 `Rectangle` 结构体 (未在此代码段中完整展示，但被使用):** 用于表示图像的边界。

**用Go代码举例说明：**

假设我们要创建一个红色的 10x10 的 `RGBA` 图像：

```go
package main

import (
	"image"
	"image/color"
	"fmt"
)

func main() {
	// 定义图像的边界
	rect := image.Rect(0, 0, 10, 10)

	// 创建一个新的 RGBA 图像
	rgbaImage := image.NewRGBA(rect)

	// 定义红色
	red := color.RGBA{255, 0, 0, 255}

	// 遍历所有像素并将它们设置为红色
	for y := rgbaImage.Bounds().Min.Y; y < rgbaImage.Bounds().Max.Y; y++ {
		for x := rgbaImage.Bounds().Min.X; x < rgbaImage.Bounds().Max.X; x++ {
			rgbaImage.Set(x, y, red)
		}
	}

	// 获取并打印 (0, 0) 像素的颜色
	c := rgbaImage.At(0, 0)
	r, g, b, a := c.RGBA()
	fmt.Printf("Pixel at (0, 0): R=%d, G=%d, B=%d, A=%d\n", r>>8, g>>8, b>>8, a>>8)

	// 创建子图
	subRect := image.Rect(2, 2, 5, 5)
	subImage := rgbaImage.SubImage(subRect)

	// 打印子图的边界
	fmt.Println("SubImage Bounds:", subImage.Bounds())
}
```

**假设的输入与输出：**

在上面的例子中，没有直接的外部输入。代码内部定义了图像的尺寸和颜色。

**输出：**

```
Pixel at (0, 0): R=255, G=0, B=0, A=255
SubImage Bounds: {2 2 5 5}
```

**命令行参数的具体处理：**

这段代码本身不涉及任何命令行参数的处理。`image` 包主要负责图像数据的表示和操作，而图像的加载（例如从文件中读取）和保存通常由 `image` 的子包（如 `image/png`, `image/jpeg` 等）来处理，这些子包可能会涉及到文件路径等命令行参数。

**使用者易犯错的点：**

1. **访问越界像素:** 尝试访问 `Bounds()` 返回范围之外的像素会导致不可预测的行为或返回零值（例如在 `RGBAAt` 中可以看到）。使用者需要确保访问的坐标在图像的有效范围内。

   ```go
   // 假设 rgbaImage 的边界是 0,0 到 10,10
   c := rgbaImage.At(15, 5) // 这是一个越界访问，不会 panic，但返回零值
   fmt.Println(c) // 输出：(0,0,0,0)
   ```

2. **不理解 `Stride` 的含义:**  在直接操作 `Pix` 切片时，如果 `Stride` 计算错误，会导致访问到错误的像素数据。`Stride` 代表一行像素所占的字节数。

3. **混淆预乘和非预乘的 Alpha:**  `RGBA` 和 `NRGBA` 使用不同的 Alpha 表示方式。在处理半透明图像时，需要注意它们之间的区别。

4. **直接修改 `SubImage` 的像素会影响原图:**  `SubImage` 返回的图像与原图共享像素数据。修改子图的像素会直接影响原图。

   ```go
   // ... 上面的代码继续 ...
   red := color.RGBA{255, 0, 0, 255}
   subImage.(*image.RGBA).Set(2, 2, red) // 修改子图中的一个像素

   c := rgbaImage.At(4, 4) // 原图中对应的像素也被修改了
   r, g, b, a := c.RGBA()
   fmt.Printf("Pixel at (4, 4) in original image: R=%d, G=%d, B=%d, A=%d\n", r>>8, g>>8, b>>8, a>>8)
   ```

**总结一下它的功能（针对第1部分）：**

这段代码定义了 Go 语言中处理 2D 图像的核心接口 `Image` 和一系列用于存储不同颜色模型像素数据的具体图像类型（如 `RGBA`, `Gray`, `Alpha` 等）。它提供了创建、访问、修改图像像素以及获取图像基本属性的方法。  本质上，它是 Go 语言 `image` 库中用于在内存中表示和操作图像的基础结构。

Prompt: 
```
这是路径为go/src/image/image.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Package image implements a basic 2-D image library.
//
// The fundamental interface is called [Image]. An [Image] contains colors, which
// are described in the image/color package.
//
// Values of the [Image] interface are created either by calling functions such
// as [NewRGBA] and [NewPaletted], or by calling [Decode] on an [io.Reader] containing
// image data in a format such as GIF, JPEG or PNG. Decoding any particular
// image format requires the prior registration of a decoder function.
// Registration is typically automatic as a side effect of initializing that
// format's package so that, to decode a PNG image, it suffices to have
//
//	import _ "image/png"
//
// in a program's main package. The _ means to import a package purely for its
// initialization side effects.
//
// See "The Go image package" for more details:
// https://golang.org/doc/articles/image_package.html
//
// # Security Considerations
//
// The image package can be used to parse arbitrarily large images, which can
// cause resource exhaustion on machines which do not have enough memory to
// store them. When operating on arbitrary images, [DecodeConfig] should be called
// before [Decode], so that the program can decide whether the image, as defined
// in the returned header, can be safely decoded with the available resources. A
// call to [Decode] which produces an extremely large image, as defined in the
// header returned by [DecodeConfig], is not considered a security issue,
// regardless of whether the image is itself malformed or not. A call to
// [DecodeConfig] which returns a header which does not match the image returned
// by [Decode] may be considered a security issue, and should be reported per the
// [Go Security Policy](https://go.dev/security/policy).
package image

import (
	"image/color"
)

// Config holds an image's color model and dimensions.
type Config struct {
	ColorModel    color.Model
	Width, Height int
}

// Image is a finite rectangular grid of [color.Color] values taken from a color
// model.
type Image interface {
	// ColorModel returns the Image's color model.
	ColorModel() color.Model
	// Bounds returns the domain for which At can return non-zero color.
	// The bounds do not necessarily contain the point (0, 0).
	Bounds() Rectangle
	// At returns the color of the pixel at (x, y).
	// At(Bounds().Min.X, Bounds().Min.Y) returns the upper-left pixel of the grid.
	// At(Bounds().Max.X-1, Bounds().Max.Y-1) returns the lower-right one.
	At(x, y int) color.Color
}

// RGBA64Image is an [Image] whose pixels can be converted directly to a
// color.RGBA64.
type RGBA64Image interface {
	// RGBA64At returns the RGBA64 color of the pixel at (x, y). It is
	// equivalent to calling At(x, y).RGBA() and converting the resulting
	// 32-bit return values to a color.RGBA64, but it can avoid allocations
	// from converting concrete color types to the color.Color interface type.
	RGBA64At(x, y int) color.RGBA64
	Image
}

// PalettedImage is an image whose colors may come from a limited palette.
// If m is a PalettedImage and m.ColorModel() returns a [color.Palette] p,
// then m.At(x, y) should be equivalent to p[m.ColorIndexAt(x, y)]. If m's
// color model is not a color.Palette, then ColorIndexAt's behavior is
// undefined.
type PalettedImage interface {
	// ColorIndexAt returns the palette index of the pixel at (x, y).
	ColorIndexAt(x, y int) uint8
	Image
}

// pixelBufferLength returns the length of the []uint8 typed Pix slice field
// for the NewXxx functions. Conceptually, this is just (bpp * width * height),
// but this function panics if at least one of those is negative or if the
// computation would overflow the int type.
//
// This panics instead of returning an error because of backwards
// compatibility. The NewXxx functions do not return an error.
func pixelBufferLength(bytesPerPixel int, r Rectangle, imageTypeName string) int {
	totalLength := mul3NonNeg(bytesPerPixel, r.Dx(), r.Dy())
	if totalLength < 0 {
		panic("image: New" + imageTypeName + " Rectangle has huge or negative dimensions")
	}
	return totalLength
}

// RGBA is an in-memory image whose At method returns [color.RGBA] values.
type RGBA struct {
	// Pix holds the image's pixels, in R, G, B, A order. The pixel at
	// (x, y) starts at Pix[(y-Rect.Min.Y)*Stride + (x-Rect.Min.X)*4].
	Pix []uint8
	// Stride is the Pix stride (in bytes) between vertically adjacent pixels.
	Stride int
	// Rect is the image's bounds.
	Rect Rectangle
}

func (p *RGBA) ColorModel() color.Model { return color.RGBAModel }

func (p *RGBA) Bounds() Rectangle { return p.Rect }

func (p *RGBA) At(x, y int) color.Color {
	return p.RGBAAt(x, y)
}

func (p *RGBA) RGBA64At(x, y int) color.RGBA64 {
	if !(Point{x, y}.In(p.Rect)) {
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

func (p *RGBA) RGBAAt(x, y int) color.RGBA {
	if !(Point{x, y}.In(p.Rect)) {
		return color.RGBA{}
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	return color.RGBA{s[0], s[1], s[2], s[3]}
}

// PixOffset returns the index of the first element of Pix that corresponds to
// the pixel at (x, y).
func (p *RGBA) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*4
}

func (p *RGBA) Set(x, y int, c color.Color) {
	if !(Point{x, y}.In(p.Rect)) {
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

func (p *RGBA) SetRGBA64(x, y int, c color.RGBA64) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = uint8(c.R >> 8)
	s[1] = uint8(c.G >> 8)
	s[2] = uint8(c.B >> 8)
	s[3] = uint8(c.A >> 8)
}

func (p *RGBA) SetRGBA(x, y int, c color.RGBA) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = c.R
	s[1] = c.G
	s[2] = c.B
	s[3] = c.A
}

// SubImage returns an image representing the portion of the image p visible
// through r. The returned value shares pixels with the original image.
func (p *RGBA) SubImage(r Rectangle) Image {
	r = r.Intersect(p.Rect)
	// If r1 and r2 are Rectangles, r1.Intersect(r2) is not guaranteed to be inside
	// either r1 or r2 if the intersection is empty. Without explicitly checking for
	// this, the Pix[i:] expression below can panic.
	if r.Empty() {
		return &RGBA{}
	}
	i := p.PixOffset(r.Min.X, r.Min.Y)
	return &RGBA{
		Pix:    p.Pix[i:],
		Stride: p.Stride,
		Rect:   r,
	}
}

// Opaque scans the entire image and reports whether it is fully opaque.
func (p *RGBA) Opaque() bool {
	if p.Rect.Empty() {
		return true
	}
	i0, i1 := 3, p.Rect.Dx()*4
	for y := p.Rect.Min.Y; y < p.Rect.Max.Y; y++ {
		for i := i0; i < i1; i += 4 {
			if p.Pix[i] != 0xff {
				return false
			}
		}
		i0 += p.Stride
		i1 += p.Stride
	}
	return true
}

// NewRGBA returns a new [RGBA] image with the given bounds.
func NewRGBA(r Rectangle) *RGBA {
	return &RGBA{
		Pix:    make([]uint8, pixelBufferLength(4, r, "RGBA")),
		Stride: 4 * r.Dx(),
		Rect:   r,
	}
}

// RGBA64 is an in-memory image whose At method returns [color.RGBA64] values.
type RGBA64 struct {
	// Pix holds the image's pixels, in R, G, B, A order and big-endian format. The pixel at
	// (x, y) starts at Pix[(y-Rect.Min.Y)*Stride + (x-Rect.Min.X)*8].
	Pix []uint8
	// Stride is the Pix stride (in bytes) between vertically adjacent pixels.
	Stride int
	// Rect is the image's bounds.
	Rect Rectangle
}

func (p *RGBA64) ColorModel() color.Model { return color.RGBA64Model }

func (p *RGBA64) Bounds() Rectangle { return p.Rect }

func (p *RGBA64) At(x, y int) color.Color {
	return p.RGBA64At(x, y)
}

func (p *RGBA64) RGBA64At(x, y int) color.RGBA64 {
	if !(Point{x, y}.In(p.Rect)) {
		return color.RGBA64{}
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+8 : i+8] // Small cap improves performance, see https://golang.org/issue/27857
	return color.RGBA64{
		uint16(s[0])<<8 | uint16(s[1]),
		uint16(s[2])<<8 | uint16(s[3]),
		uint16(s[4])<<8 | uint16(s[5]),
		uint16(s[6])<<8 | uint16(s[7]),
	}
}

// PixOffset returns the index of the first element of Pix that corresponds to
// the pixel at (x, y).
func (p *RGBA64) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*8
}

func (p *RGBA64) Set(x, y int, c color.Color) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	c1 := color.RGBA64Model.Convert(c).(color.RGBA64)
	s := p.Pix[i : i+8 : i+8] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = uint8(c1.R >> 8)
	s[1] = uint8(c1.R)
	s[2] = uint8(c1.G >> 8)
	s[3] = uint8(c1.G)
	s[4] = uint8(c1.B >> 8)
	s[5] = uint8(c1.B)
	s[6] = uint8(c1.A >> 8)
	s[7] = uint8(c1.A)
}

func (p *RGBA64) SetRGBA64(x, y int, c color.RGBA64) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+8 : i+8] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = uint8(c.R >> 8)
	s[1] = uint8(c.R)
	s[2] = uint8(c.G >> 8)
	s[3] = uint8(c.G)
	s[4] = uint8(c.B >> 8)
	s[5] = uint8(c.B)
	s[6] = uint8(c.A >> 8)
	s[7] = uint8(c.A)
}

// SubImage returns an image representing the portion of the image p visible
// through r. The returned value shares pixels with the original image.
func (p *RGBA64) SubImage(r Rectangle) Image {
	r = r.Intersect(p.Rect)
	// If r1 and r2 are Rectangles, r1.Intersect(r2) is not guaranteed to be inside
	// either r1 or r2 if the intersection is empty. Without explicitly checking for
	// this, the Pix[i:] expression below can panic.
	if r.Empty() {
		return &RGBA64{}
	}
	i := p.PixOffset(r.Min.X, r.Min.Y)
	return &RGBA64{
		Pix:    p.Pix[i:],
		Stride: p.Stride,
		Rect:   r,
	}
}

// Opaque scans the entire image and reports whether it is fully opaque.
func (p *RGBA64) Opaque() bool {
	if p.Rect.Empty() {
		return true
	}
	i0, i1 := 6, p.Rect.Dx()*8
	for y := p.Rect.Min.Y; y < p.Rect.Max.Y; y++ {
		for i := i0; i < i1; i += 8 {
			if p.Pix[i+0] != 0xff || p.Pix[i+1] != 0xff {
				return false
			}
		}
		i0 += p.Stride
		i1 += p.Stride
	}
	return true
}

// NewRGBA64 returns a new [RGBA64] image with the given bounds.
func NewRGBA64(r Rectangle) *RGBA64 {
	return &RGBA64{
		Pix:    make([]uint8, pixelBufferLength(8, r, "RGBA64")),
		Stride: 8 * r.Dx(),
		Rect:   r,
	}
}

// NRGBA is an in-memory image whose At method returns [color.NRGBA] values.
type NRGBA struct {
	// Pix holds the image's pixels, in R, G, B, A order. The pixel at
	// (x, y) starts at Pix[(y-Rect.Min.Y)*Stride + (x-Rect.Min.X)*4].
	Pix []uint8
	// Stride is the Pix stride (in bytes) between vertically adjacent pixels.
	Stride int
	// Rect is the image's bounds.
	Rect Rectangle
}

func (p *NRGBA) ColorModel() color.Model { return color.NRGBAModel }

func (p *NRGBA) Bounds() Rectangle { return p.Rect }

func (p *NRGBA) At(x, y int) color.Color {
	return p.NRGBAAt(x, y)
}

func (p *NRGBA) RGBA64At(x, y int) color.RGBA64 {
	r, g, b, a := p.NRGBAAt(x, y).RGBA()
	return color.RGBA64{uint16(r), uint16(g), uint16(b), uint16(a)}
}

func (p *NRGBA) NRGBAAt(x, y int) color.NRGBA {
	if !(Point{x, y}.In(p.Rect)) {
		return color.NRGBA{}
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	return color.NRGBA{s[0], s[1], s[2], s[3]}
}

// PixOffset returns the index of the first element of Pix that corresponds to
// the pixel at (x, y).
func (p *NRGBA) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*4
}

func (p *NRGBA) Set(x, y int, c color.Color) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	c1 := color.NRGBAModel.Convert(c).(color.NRGBA)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = c1.R
	s[1] = c1.G
	s[2] = c1.B
	s[3] = c1.A
}

func (p *NRGBA) SetRGBA64(x, y int, c color.RGBA64) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	r, g, b, a := uint32(c.R), uint32(c.G), uint32(c.B), uint32(c.A)
	if (a != 0) && (a != 0xffff) {
		r = (r * 0xffff) / a
		g = (g * 0xffff) / a
		b = (b * 0xffff) / a
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = uint8(r >> 8)
	s[1] = uint8(g >> 8)
	s[2] = uint8(b >> 8)
	s[3] = uint8(a >> 8)
}

func (p *NRGBA) SetNRGBA(x, y int, c color.NRGBA) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = c.R
	s[1] = c.G
	s[2] = c.B
	s[3] = c.A
}

// SubImage returns an image representing the portion of the image p visible
// through r. The returned value shares pixels with the original image.
func (p *NRGBA) SubImage(r Rectangle) Image {
	r = r.Intersect(p.Rect)
	// If r1 and r2 are Rectangles, r1.Intersect(r2) is not guaranteed to be inside
	// either r1 or r2 if the intersection is empty. Without explicitly checking for
	// this, the Pix[i:] expression below can panic.
	if r.Empty() {
		return &NRGBA{}
	}
	i := p.PixOffset(r.Min.X, r.Min.Y)
	return &NRGBA{
		Pix:    p.Pix[i:],
		Stride: p.Stride,
		Rect:   r,
	}
}

// Opaque scans the entire image and reports whether it is fully opaque.
func (p *NRGBA) Opaque() bool {
	if p.Rect.Empty() {
		return true
	}
	i0, i1 := 3, p.Rect.Dx()*4
	for y := p.Rect.Min.Y; y < p.Rect.Max.Y; y++ {
		for i := i0; i < i1; i += 4 {
			if p.Pix[i] != 0xff {
				return false
			}
		}
		i0 += p.Stride
		i1 += p.Stride
	}
	return true
}

// NewNRGBA returns a new [NRGBA] image with the given bounds.
func NewNRGBA(r Rectangle) *NRGBA {
	return &NRGBA{
		Pix:    make([]uint8, pixelBufferLength(4, r, "NRGBA")),
		Stride: 4 * r.Dx(),
		Rect:   r,
	}
}

// NRGBA64 is an in-memory image whose At method returns [color.NRGBA64] values.
type NRGBA64 struct {
	// Pix holds the image's pixels, in R, G, B, A order and big-endian format. The pixel at
	// (x, y) starts at Pix[(y-Rect.Min.Y)*Stride + (x-Rect.Min.X)*8].
	Pix []uint8
	// Stride is the Pix stride (in bytes) between vertically adjacent pixels.
	Stride int
	// Rect is the image's bounds.
	Rect Rectangle
}

func (p *NRGBA64) ColorModel() color.Model { return color.NRGBA64Model }

func (p *NRGBA64) Bounds() Rectangle { return p.Rect }

func (p *NRGBA64) At(x, y int) color.Color {
	return p.NRGBA64At(x, y)
}

func (p *NRGBA64) RGBA64At(x, y int) color.RGBA64 {
	r, g, b, a := p.NRGBA64At(x, y).RGBA()
	return color.RGBA64{uint16(r), uint16(g), uint16(b), uint16(a)}
}

func (p *NRGBA64) NRGBA64At(x, y int) color.NRGBA64 {
	if !(Point{x, y}.In(p.Rect)) {
		return color.NRGBA64{}
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+8 : i+8] // Small cap improves performance, see https://golang.org/issue/27857
	return color.NRGBA64{
		uint16(s[0])<<8 | uint16(s[1]),
		uint16(s[2])<<8 | uint16(s[3]),
		uint16(s[4])<<8 | uint16(s[5]),
		uint16(s[6])<<8 | uint16(s[7]),
	}
}

// PixOffset returns the index of the first element of Pix that corresponds to
// the pixel at (x, y).
func (p *NRGBA64) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*8
}

func (p *NRGBA64) Set(x, y int, c color.Color) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	c1 := color.NRGBA64Model.Convert(c).(color.NRGBA64)
	s := p.Pix[i : i+8 : i+8] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = uint8(c1.R >> 8)
	s[1] = uint8(c1.R)
	s[2] = uint8(c1.G >> 8)
	s[3] = uint8(c1.G)
	s[4] = uint8(c1.B >> 8)
	s[5] = uint8(c1.B)
	s[6] = uint8(c1.A >> 8)
	s[7] = uint8(c1.A)
}

func (p *NRGBA64) SetRGBA64(x, y int, c color.RGBA64) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	r, g, b, a := uint32(c.R), uint32(c.G), uint32(c.B), uint32(c.A)
	if (a != 0) && (a != 0xffff) {
		r = (r * 0xffff) / a
		g = (g * 0xffff) / a
		b = (b * 0xffff) / a
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+8 : i+8] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = uint8(r >> 8)
	s[1] = uint8(r)
	s[2] = uint8(g >> 8)
	s[3] = uint8(g)
	s[4] = uint8(b >> 8)
	s[5] = uint8(b)
	s[6] = uint8(a >> 8)
	s[7] = uint8(a)
}

func (p *NRGBA64) SetNRGBA64(x, y int, c color.NRGBA64) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+8 : i+8] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = uint8(c.R >> 8)
	s[1] = uint8(c.R)
	s[2] = uint8(c.G >> 8)
	s[3] = uint8(c.G)
	s[4] = uint8(c.B >> 8)
	s[5] = uint8(c.B)
	s[6] = uint8(c.A >> 8)
	s[7] = uint8(c.A)
}

// SubImage returns an image representing the portion of the image p visible
// through r. The returned value shares pixels with the original image.
func (p *NRGBA64) SubImage(r Rectangle) Image {
	r = r.Intersect(p.Rect)
	// If r1 and r2 are Rectangles, r1.Intersect(r2) is not guaranteed to be inside
	// either r1 or r2 if the intersection is empty. Without explicitly checking for
	// this, the Pix[i:] expression below can panic.
	if r.Empty() {
		return &NRGBA64{}
	}
	i := p.PixOffset(r.Min.X, r.Min.Y)
	return &NRGBA64{
		Pix:    p.Pix[i:],
		Stride: p.Stride,
		Rect:   r,
	}
}

// Opaque scans the entire image and reports whether it is fully opaque.
func (p *NRGBA64) Opaque() bool {
	if p.Rect.Empty() {
		return true
	}
	i0, i1 := 6, p.Rect.Dx()*8
	for y := p.Rect.Min.Y; y < p.Rect.Max.Y; y++ {
		for i := i0; i < i1; i += 8 {
			if p.Pix[i+0] != 0xff || p.Pix[i+1] != 0xff {
				return false
			}
		}
		i0 += p.Stride
		i1 += p.Stride
	}
	return true
}

// NewNRGBA64 returns a new [NRGBA64] image with the given bounds.
func NewNRGBA64(r Rectangle) *NRGBA64 {
	return &NRGBA64{
		Pix:    make([]uint8, pixelBufferLength(8, r, "NRGBA64")),
		Stride: 8 * r.Dx(),
		Rect:   r,
	}
}

// Alpha is an in-memory image whose At method returns [color.Alpha] values.
type Alpha struct {
	// Pix holds the image's pixels, as alpha values. The pixel at
	// (x, y) starts at Pix[(y-Rect.Min.Y)*Stride + (x-Rect.Min.X)*1].
	Pix []uint8
	// Stride is the Pix stride (in bytes) between vertically adjacent pixels.
	Stride int
	// Rect is the image's bounds.
	Rect Rectangle
}

func (p *Alpha) ColorModel() color.Model { return color.AlphaModel }

func (p *Alpha) Bounds() Rectangle { return p.Rect }

func (p *Alpha) At(x, y int) color.Color {
	return p.AlphaAt(x, y)
}

func (p *Alpha) RGBA64At(x, y int) color.RGBA64 {
	a := uint16(p.AlphaAt(x, y).A)
	a |= a << 8
	return color.RGBA64{a, a, a, a}
}

func (p *Alpha) AlphaAt(x, y int) color.Alpha {
	if !(Point{x, y}.In(p.Rect)) {
		return color.Alpha{}
	}
	i := p.PixOffset(x, y)
	return color.Alpha{p.Pix[i]}
}

// PixOffset returns the index of the first element of Pix that corresponds to
// the pixel at (x, y).
func (p *Alpha) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*1
}

func (p *Alpha) Set(x, y int, c color.Color) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	p.Pix[i] = color.AlphaModel.Convert(c).(color.Alpha).A
}

func (p *Alpha) SetRGBA64(x, y int, c color.RGBA64) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	p.Pix[i] = uint8(c.A >> 8)
}

func (p *Alpha) SetAlpha(x, y int, c color.Alpha) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	p.Pix[i] = c.A
}

// SubImage returns an image representing the portion of the image p visible
// through r. The returned value shares pixels with the original image.
func (p *Alpha) SubImage(r Rectangle) Image {
	r = r.Intersect(p.Rect)
	// If r1 and r2 are Rectangles, r1.Intersect(r2) is not guaranteed to be inside
	// either r1 or r2 if the intersection is empty. Without explicitly checking for
	// this, the Pix[i:] expression below can panic.
	if r.Empty() {
		return &Alpha{}
	}
	i := p.PixOffset(r.Min.X, r.Min.Y)
	return &Alpha{
		Pix:    p.Pix[i:],
		Stride: p.Stride,
		Rect:   r,
	}
}

// Opaque scans the entire image and reports whether it is fully opaque.
func (p *Alpha) Opaque() bool {
	if p.Rect.Empty() {
		return true
	}
	i0, i1 := 0, p.Rect.Dx()
	for y := p.Rect.Min.Y; y < p.Rect.Max.Y; y++ {
		for i := i0; i < i1; i++ {
			if p.Pix[i] != 0xff {
				return false
			}
		}
		i0 += p.Stride
		i1 += p.Stride
	}
	return true
}

// NewAlpha returns a new [Alpha] image with the given bounds.
func NewAlpha(r Rectangle) *Alpha {
	return &Alpha{
		Pix:    make([]uint8, pixelBufferLength(1, r, "Alpha")),
		Stride: 1 * r.Dx(),
		Rect:   r,
	}
}

// Alpha16 is an in-memory image whose At method returns [color.Alpha16] values.
type Alpha16 struct {
	// Pix holds the image's pixels, as alpha values in big-endian format. The pixel at
	// (x, y) starts at Pix[(y-Rect.Min.Y)*Stride + (x-Rect.Min.X)*2].
	Pix []uint8
	// Stride is the Pix stride (in bytes) between vertically adjacent pixels.
	Stride int
	// Rect is the image's bounds.
	Rect Rectangle
}

func (p *Alpha16) ColorModel() color.Model { return color.Alpha16Model }

func (p *Alpha16) Bounds() Rectangle { return p.Rect }

func (p *Alpha16) At(x, y int) color.Color {
	return p.Alpha16At(x, y)
}

func (p *Alpha16) RGBA64At(x, y int) color.RGBA64 {
	a := p.Alpha16At(x, y).A
	return color.RGBA64{a, a, a, a}
}

func (p *Alpha16) Alpha16At(x, y int) color.Alpha16 {
	if !(Point{x, y}.In(p.Rect)) {
		return color.Alpha16{}
	}
	i := p.PixOffset(x, y)
	return color.Alpha16{uint16(p.Pix[i+0])<<8 | uint16(p.Pix[i+1])}
}

// PixOffset returns the index of the first element of Pix that corresponds to
// the pixel at (x, y).
func (p *Alpha16) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*2
}

func (p *Alpha16) Set(x, y int, c color.Color) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	c1 := color.Alpha16Model.Convert(c).(color.Alpha16)
	p.Pix[i+0] = uint8(c1.A >> 8)
	p.Pix[i+1] = uint8(c1.A)
}

func (p *Alpha16) SetRGBA64(x, y int, c color.RGBA64) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	p.Pix[i+0] = uint8(c.A >> 8)
	p.Pix[i+1] = uint8(c.A)
}

func (p *Alpha16) SetAlpha16(x, y int, c color.Alpha16) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	p.Pix[i+0] = uint8(c.A >> 8)
	p.Pix[i+1] = uint8(c.A)
}

// SubImage returns an image representing the portion of the image p visible
// through r. The returned value shares pixels with the original image.
func (p *Alpha16) SubImage(r Rectangle) Image {
	r = r.Intersect(p.Rect)
	// If r1 and r2 are Rectangles, r1.Intersect(r2) is not guaranteed to be inside
	// either r1 or r2 if the intersection is empty. Without explicitly checking for
	// this, the Pix[i:] expression below can panic.
	if r.Empty() {
		return &Alpha16{}
	}
	i := p.PixOffset(r.Min.X, r.Min.Y)
	return &Alpha16{
		Pix:    p.Pix[i:],
		Stride: p.Stride,
		Rect:   r,
	}
}

// Opaque scans the entire image and reports whether it is fully opaque.
func (p *Alpha16) Opaque() bool {
	if p.Rect.Empty() {
		return true
	}
	i0, i1 := 0, p.Rect.Dx()*2
	for y := p.Rect.Min.Y; y < p.Rect.Max.Y; y++ {
		for i := i0; i < i1; i += 2 {
			if p.Pix[i+0] != 0xff || p.Pix[i+1] != 0xff {
				return false
			}
		}
		i0 += p.Stride
		i1 += p.Stride
	}
	return true
}

// NewAlpha16 returns a new [Alpha16] image with the given bounds.
func NewAlpha16(r Rectangle) *Alpha16 {
	return &Alpha16{
		Pix:    make([]uint8, pixelBufferLength(2, r, "Alpha16")),
		Stride: 2 * r.Dx(),
		Rect:   r,
	}
}

// Gray is an in-memory image whose At method returns [color.Gray] values.
type Gray struct {
	// Pix holds the image's pixels, as gray values. The pixel at
	// (x, y) starts at Pix[(y-Rect.Min.Y)*Stride + (x-Rect.Min.X)*1].
	Pix []uint8
	// Stride is the Pix stride (in bytes) between vertically adjacent pixels.
	Stride int
	// Rect is the image's bounds.
	Rect Rectangle
}

func (p *Gray) ColorModel() color.Model { return color.GrayModel }

func (p *Gray) Bounds() Rectangle { return p.Rect }

func (p *Gray) At(x, y int) color.Color {
	return p.GrayAt(x, y)
}

func (p *Gray) RGBA64At(x, y int) color.RGBA64 {
	gray := uint16(p.GrayAt(x, y).Y)
	gray |= gray << 8
	return color.RGBA64{gray, gray, gray, 0xffff}
}

func (p *Gray) GrayAt(x, y int) color.Gray {
	if !(Point{x, y}.In(p.Rect)) {
		return color.Gray{}
	}
	i := p.PixOffset(x, y)
	return color.Gray{p.Pix[i]}
}

// PixOffset returns the index of the first element of Pix that corresponds to
// the pixel at (x, y).
func (p *Gray) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*1
}

func (p *Gray) Set(x, y int, c color.Color) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	p.Pix[i] = color.GrayModel.Convert(c).(color.Gray).Y
}

func (p *Gray) SetRGBA64(x, y int, c color.RGBA64) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	// This formula is the same as in color.grayModel.
	gray := (19595*uint32(c.R) + 38470*uint32(c.G) + 7471*uint32(c.B) + 1<<15) >> 24
	i := p.PixOffset(x, y)
	p.Pix[i] = uint8(gray)
}

func (p *Gray) SetGray(x, y int, c color.Gray) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	p.Pix[i] = c.Y
}

// SubImage returns an image representing the portion of the image p visible
// through r. The returned value shares pixels with the original image.
func (p *Gray) SubImage(r Rectangle) Image {
	r = r.Intersect(p.Rect)
	// If r1 and r2 are Rectangles, r1.Intersect(r2) is not guaranteed to be inside
	// either r1 or r2 if the intersection is empty. Without explicitly checking for
	// this, the Pix[i:] expression below can panic.
	if r.Empty() {
		return &Gray{}
	}
	i := p.PixOffset(r.Min.X, r.Min.Y)
	return &Gray{
		Pix:    p.Pix[i:],
		Stride: p.Stride,
		Rect:   r,
	}
}

// Opaque scans the entire image and reports whether it is fully opaque.
func (p *Gray) Opaque() bool {
	return true
}

// NewGray returns a new [Gray] image with the given bounds.
func NewGray(r Rectangle) *Gray {
	return &Gray{
		Pix:    make([]uint8, pixelBufferLength(1, r, "Gray")),
		Stride: 1 * r.Dx(),
		Rect:   r,
	}
}

// Gray16 is an in-memory image whose At method returns [color.Gray16] values.
type Gray16 struct {
	// Pix holds the image's pixels, as gray values in big-endian format. The pixel at
	// (x, y) starts at Pix[(y-Rect.Min.Y)*Stride + (x-Rect.Min.X)*2].
	Pix []uint8
	// Stride is the Pix stride (in bytes) between vertically adjacent pixels.
	Stride int
	// Rect is the image's bounds.
	Rect Rectangle
}

func (p *Gray16) ColorModel() color.Model { return color.Gray16Model }

func (p *Gray16) Bounds() Rectangle { return p.Rect }

func (p *Gray16) At(x, y int) color.Color {
	return p.Gray16At(x, y)
}

func (p *Gray16) RGBA64At(x, y int) color.RGBA64 {
	gray := p.Gray16At(x, y).Y
	return color.RGBA64{gray, gray, gray, 0xffff}
}

func (p *Gray16) Gray16At(x, y int) color.Gray16 {
	if !(Point{x, y}.In(p.Rect)) {
		return color.Gray16{}
	}
	i := p.PixOffset(x, y)
	return color.Gray16{uint16(p.Pix[i+0])<<8 | uint16(p.Pix[i+1])}
}

// PixOffset returns the index of the first element of Pix that corresponds to
// the pixel at (x, y).
func (p *Gray16) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*2
}

func (p *Gray16) Set(x, y int, c color.Color) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	c1 := color.Gray16Model.Convert(c).(color.Gray16)
	p.Pix[i+0] = uint8(c1.Y >> 8)
	p.Pix[i+1] = uint8(c1.Y)
}

func (p *Gray16) SetRGBA64(x, y int, c color.RGBA64) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	// This formula is the same as in color.gray16Model.
	gray := (19595*uint32(c.R) + 38470*uint32(c.G) + 7471*uint32(c.B) + 1<<15) >> 16
	i := p.PixOffset(x, y)
	p.Pix[i+0] = uint8(gray >> 8)
	p.Pix[i+1] = uint8(gray)
}

func (p *Gray16) SetGray16(x, y int, c color.Gray16) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	p.Pix[i+0] = uint8(c.Y >> 8)
	p.Pix[i+1] = uint8(c.Y)
}

// SubImage returns an image representing the portion of the image p visible
// through r. The returned value shares pixels with the original image.
func (p *Gray16) SubImage(r Rectangle) Image {
	r = r.Intersect(p.Rect)
	// If r1 and r2 are Rectangles, r1.Intersect(r2) is not guaranteed to be inside
	// either r1 or r2 if the intersection is empty. Without explicitly checking for
	// this, the Pix[i:] expression below can panic.
	if r.Empty() {
		return &Gray16{}
	}
	i := p.PixOffset(r.Min.X, r.Min.Y)
	return &Gray16{
		Pix:    p.Pix[i:],
		Stride: p.Stride,
		Rect:   r,
	}
}

// Opaque scans the entire image and reports whether it is fully opaque.
func (p *Gray16) Opaque() bool {
	return true
}

// NewGray16 returns a new [Gray16] image with the given bounds.
func NewGray16(r Rectangle) *Gray16 {
	return &Gray16{
		Pix:    make([]uint8, pixelBufferLength(2, r, "Gray16")),
		Stride: 2 * r.Dx(),
		Rect:   r,
	}
}

// CMYK is an in-memory image whose At method returns [color.CMYK] values.
type CMYK struct {
	// Pix holds the image's pixels, in C, M, Y, K order. The pixel at
	// (x, y) starts at Pix[(y-Rect.Min.Y)*Stride + (x-Rect.Min.X)*4].
	Pix []uint8
	// Stride is the Pix stride (in bytes) between vertically adjacent pixels.
	Stride int
	// Rect is the image's bounds.
	Rect Rectangle
}

func (p *CMYK) ColorModel() color.Model { return color.CMYKModel }

func (p *CMYK) Bounds() Rectangle { return p.Rect }

func (p *CMYK) At(x, y int) color.Color {
	return p.CMYKAt(x, y)
}

func (p *CMYK) RGBA64At(x, y int) color.RGBA64 {
	r, g, b, a := p.CMYKAt(x, y).RGBA()
	return color.RGBA64{uint16(r), uint16(g), uint16(b), uint16(a)}
}

func (p *CMYK) CMYKAt(x, y int) color.CMYK {
	if !(Point{x, y}.In(p.Rect)) {
		return color.CMYK{}
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	return color.CMYK{s[0], s[1], s[2], s[3]}
}

// PixOffset returns the index of the first element of Pix that corresponds to
// the pixel at (x, y).
func (p *CMYK) PixOffset(x, y int) int {
	return (y-p.Rect.Min.Y)*p.Stride + (x-p.Rect.Min.X)*4
}

func (p *CMYK) Set(x, y int, c color.Color) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	c1 := color.CMYKModel.Convert(c).(color.CMYK)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = c1.C
	s[1] = c1.M
	s[2] = c1.Y
	s[3] = c1.K
}

func (p *CMYK) SetRGBA64(x, y int, c color.RGBA64) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	cc, mm, yy, kk := color.RGBToCMYK(uint8(c.R>>8), uint8(c.G>>8), uint8(c.B>>8))
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = cc
	s[1] = mm
	s[2] = yy
	s[3] = kk
}

func (p *CMYK) SetCMYK(x, y int, c color.CMYK) {
	if !(Point{x, y}.In(p.Rect)) {
		return
	}
	i := p.PixOffset(x, y)
	s := p.Pix[i : i+4 : i+4] // Small cap improves performance, see https://golang.org/issue/27857
	s[0] = c.C
	s[1] = c.M
	s[2] = c.Y
	s[3] = c.K
}

// SubImage returns an image representing the portion of the image p visible
// through r. The returned value shares pixels with the original image.
func (p *CMYK) SubImage(r Rectangle) Image {
	r = r.Intersect(p.Rect)
	// If r1 and r2 are Rectangles, r1.Intersect(r2) is not guaranteed to be inside
	// either r1 or r2 if the intersection is empty. Without explicitly checking for
	// this, the Pix[i:] expression below can panic.
	if r.Empty() {
		return &CMYK{}
	}
	i := p.PixOffset(r.Min.X, r.Min.Y)
	return &CMYK{
		Pix:    p.Pix[i:],
		Stride: p.Stride,
		Rect:   r,
	}
}

// Opaque scans the entire image and reports whether it is fully opaque.
func (p *CMYK) Opaque() bool {
	return true
}

// NewCMYK returns a new CMYK image with the given bounds.
func NewCMYK(r Rectangle) *CMYK {
	return &CMYK{
		Pix:    make([]uint8, pixelBufferLength(4, r, "CMYK")),
		Stride: 4 * r.Dx(),
		Rect:   r,
	}
}

// Paletted is an in-memory image of uint8 indices into a given palette.
type Paletted struct {
	// Pix holds the image's pixels, as palette indices. The pixel at
	// (x, y) starts at Pix[(y-Rect.Min.Y)*Stride + (x-Rect.Min.X)*1].
	Pix []uint8
	// Stride is the Pix stride (in bytes) between vertically adjacent pixels.
	Stride int
	// Rect is the image's bounds.
	Rect Rectangle
	// Palette
"""




```