Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional breakdown of the provided Go code snippet (`ycbcr.go`), focusing on what it does, how it works (with examples), and potential pitfalls for users. The language is Chinese, so the answer needs to be in Chinese.

2. **Initial Code Scan and High-Level Interpretation:**  I first quickly scan the code looking for keywords and function names. I see `RGBToYCbCr`, `YCbCrToRGB`, `YCbCr`, `RGBA`, `NYCbCrA`, `RGBToCMYK`, and `CMYKToRGB`. This immediately tells me the code is about color space conversions, specifically RGB to/from Y'CbCr and RGB to/from CMYK. The presence of `YCbCr` and `NYCbCrA` structs suggests these are the data structures representing these color spaces. The `RGBA()` methods indicate a common way to get a standard RGBA representation.

3. **Detailed Function Analysis - Core Conversions:**
    * **`RGBToYCbCr(r, g, b uint8) (uint8, uint8, uint8)`:**  This function clearly converts RGB (Red, Green, Blue) values to Y'CbCr (Luma, Chroma Blue, Chroma Red). The comments mention the JFIF specification, which confirms this. The code uses integer arithmetic with bit shifting for efficiency, avoiding floating-point operations. I need to explain the formula and the bit manipulation tricks.
    * **`YCbCrToRGB(y, cb, cr uint8) (uint8, uint8, uint8)`:** The inverse operation of the above. The comments explain the integer approximation of the conversion formulas and the rationale for the rounding adjustment. Again, explain the formula and the bit manipulation.

4. **Structure and Interface Analysis:**
    * **`type YCbCr struct { ... }`:** This defines the Y'CbCr color structure. The comment highlights its relevance to JPEG, MPEG, etc. Crucially, I need to explain the distinction between YUV and Y'CbCr.
    * **`func (c YCbCr) RGBA() (uint32, uint32, uint32, uint32)`:** This method converts `YCbCr` to `RGBA`. The comments emphasize that this direct conversion is more precise than going through `YCbCrToRGB` and then to `RGBA`. This is a key point for potential user errors. I need to provide an example illustrating this.
    * **`var YCbCrModel Model = ModelFunc(yCbCrModel)`:** This indicates the implementation of the `color.Model` interface, allowing for generic color handling. I need to explain this concept.
    * **`type NYCbCrA struct { ... }`:**  This structure adds an alpha channel to Y'CbCr.
    * **`func (c NYCbCrA) RGBA() (uint32, uint32, uint32, uint32)`:** Converts `NYCbCrA` to `RGBA`, including alpha blending.
    * **`var NYCbCrAModel Model = ModelFunc(nYCbCrAModel)`:**  Another `color.Model` implementation.

5. **CMYK Analysis:**
    * **`RGBToCMYK(r, g, b uint8) (uint8, uint8, uint8, uint8)`:** Converts RGB to CMYK (Cyan, Magenta, Yellow, Key/Black).
    * **`CMYKToRGB(c, m, y, k uint8) (uint8, uint8, uint8)`:** Converts CMYK back to RGB.
    * **`type CMYK struct { ... }`:** Defines the CMYK structure. The comment notes it's not tied to a specific color profile.
    * **`func (c CMYK) RGBA() (uint32, uint32, uint32, uint32)`:** Converts CMYK to RGBA.
    * **`var CMYKModel Model = ModelFunc(cmykModel)`:**  The `color.Model` for CMYK.

6. **Example Code Construction:**  For each key function and concept, I need to create simple, illustrative Go code examples. These examples should demonstrate:
    * Basic conversion using `RGBToYCbCr` and `YCbCrToRGB`.
    * Using the `YCbCr` struct and its `RGBA()` method.
    * The loss of precision when converting via `YCbCrToRGB` then `RGBA`.
    * Basic conversion using `RGBToCMYK` and `CMYKToRGB`.
    * Using the `CMYK` struct and its `RGBA()` method.
    * (Initially, I might forget examples for `NYCbCrA`, but upon reviewing the code again, I'd realize it needs an example too).

7. **Identifying Potential User Errors:**  This requires thinking about how someone might misuse the functions. The most obvious pitfall is the precision loss when converting via the intermediate RGB step. This needs a clear explanation and an example. Another potential issue is the understanding of the `color.Model` interface, so a brief explanation of its purpose is helpful.

8. **Command-Line Arguments:** The provided code doesn't handle command-line arguments, so I explicitly state that.

9. **Structuring the Answer:**  I organize the answer into logical sections: 功能 (Functions), Go语言功能实现 (Go Feature Implementation with Examples), 代码推理 (Code Reasoning), 命令行参数处理 (Command-Line Argument Handling), and 使用者易犯错的点 (Common User Errors). This makes the answer clear and easy to read.

10. **Language and Tone:** The answer needs to be in clear and concise Chinese. I avoid overly technical jargon where possible and explain concepts simply.

11. **Review and Refinement:** After drafting the answer, I review it to ensure accuracy, completeness, and clarity. I double-check the code examples and explanations. I make sure the examples have clear inputs and outputs.

By following these steps, I can create a comprehensive and accurate answer to the request, addressing all the specified points. The iterative process of scanning, analyzing, exemplifying, and reviewing helps to catch details and ensure a high-quality response.
这段代码是 Go 语言标准库 `image/color` 包中 `ycbcr.go` 文件的一部分，它主要实现了 **YCbCr 和 CMYK 颜色空间的表示和与 RGB 颜色空间之间的转换**。

下面详细列举其功能：

**核心功能：颜色空间转换和表示**

1. **RGB 到 YCbCr 的转换 (`RGBToYCbCr`)**:
    *   接受 `uint8` 类型的 R、G、B 三个参数，代表 RGB 颜色值。
    *   根据 JFIF 标准定义的公式，将 RGB 颜色值转换为 Y'CbCr 颜色空间的 Y、Cb、Cr 分量。
    *   返回 `uint8` 类型的 Y、Cb、Cr 三个值。
    *   **代码推理**:  公式 `Y' =  0.2990*R + 0.5870*G + 0.1140*B`, `Cb = -0.1687*R - 0.3313*G + 0.5000*B + 128`, `Cr =  0.5000*R - 0.4187*G - 0.0813*B + 128` 被转换为使用整数运算和位移操作的高效实现。
    *   **假设输入与输出**:
        *   输入: `r = 255, g = 0, b = 0` (红色)
        *   输出: `y ≈ 76, cb ≈ 84, cr ≈ 239`

2. **YCbCr 到 RGB 的转换 (`YCbCrToRGB`)**:
    *   接受 `uint8` 类型的 Y、Cb、Cr 三个参数，代表 Y'CbCr 颜色值。
    *   根据 JFIF 标准定义的公式，将 Y'CbCr 颜色值转换为 RGB 颜色空间的 R、G、B 分量。
    *   返回 `uint8` 类型的 R、G、B 三个值。
    *   **代码推理**:  公式 `R = Y' + 1.40200*(Cr-128)`, `G = Y' - 0.34414*(Cb-128) - 0.71414*(Cr-128)`, `B = Y' + 1.77200*(Cb-128)`  被转换为使用整数运算和位移操作的高效实现，并解释了 rounding adjustment 的必要性，以确保灰度图像转换前后的一致性。
    *   **假设输入与输出**:
        *   输入: `y = 76, cb = 84, cr = 239`
        *   输出: `r ≈ 254, g ≈ 1, b ≈ 1` (由于精度损失，可能不完全等于原始值)

3. **YCbCr 颜色类型的定义 (`YCbCr`)**:
    *   定义了一个 `YCbCr` 结构体，用于表示一个不透明的 24 位 Y'CbCr 颜色。
    *   包含 `Y`、`Cb`、`Cr` 三个 `uint8` 类型的字段。
    *   提供了 `RGBA()` 方法，将 `YCbCr` 颜色转换为 `uint32` 类型的 RGBA 值 (范围是 `[0, 0xffff]`)。这个转换**绕过了 `YCbCrToRGB` 的 8 位限制，提供了更高的精度**。
    *   **代码推理**:  `YCbCr.RGBA()` 的实现与 `YCbCrToRGB` 类似，但输出范围是 16 位，避免了中间的 8 位截断，从而保留了更多精度。

4. **YCbCr 颜色模型的定义 (`YCbCrModel`)**:
    *   定义了一个 `YCbCrModel` 变量，实现了 `color.Model` 接口，用于处理 YCbCr 颜色。
    *   `yCbCrModel` 函数用于将任意 `Color` 转换为 `YCbCr` 类型。

5. **带 Alpha 通道的 YCbCr 颜色类型的定义 (`NYCbCrA`)**:
    *   定义了一个 `NYCbCrA` 结构体，用于表示一个带 Alpha 通道的 Y'CbCr 颜色。
    *   内嵌了 `YCbCr` 结构体，并包含一个 `A` (Alpha) `uint8` 类型的字段。
    *   提供了 `RGBA()` 方法，将 `NYCbCrA` 颜色转换为预乘 Alpha 的 `uint32` 类型的 RGBA 值。
    *   **代码推理**:  `NYCbCrA.RGBA()` 首先将 YCbCr 部分转换为 16 位的 RGB，然后应用 Alpha 通道进行预乘。

6. **带 Alpha 通道的 YCbCr 颜色模型的定义 (`NYCbCrAModel`)**:
    *   定义了一个 `NYCbCrAModel` 变量，实现了 `color.Model` 接口，用于处理带 Alpha 通道的 YCbCr 颜色。
    *   `nYCbCrAModel` 函数用于将任意 `Color` 转换为 `NYCbCrA` 类型。

7. **RGB 到 CMYK 的转换 (`RGBToCMYK`)**:
    *   接受 `uint8` 类型的 R、G、B 三个参数，代表 RGB 颜色值。
    *   将 RGB 颜色值转换为 CMYK 颜色空间的 C、M、Y、K 分量。
    *   返回 `uint8` 类型的 C、M、Y、K 四个值。

8. **CMYK 到 RGB 的转换 (`CMYKToRGB`)**:
    *   接受 `uint8` 类型的 C、M、Y、K 四个参数，代表 CMYK 颜色值。
    *   将 CMYK 颜色值转换为 RGB 颜色空间的 R、G、B 分量。
    *   返回 `uint8` 类型的 R、G、B 三个值。

9. **CMYK 颜色类型的定义 (`CMYK`)**:
    *   定义了一个 `CMYK` 结构体，用于表示一个不透明的 CMYK 颜色。
    *   包含 `C`、`M`、`Y`、`K` 四个 `uint8` 类型的字段。
    *   提供了 `RGBA()` 方法，将 `CMYK` 颜色转换为 `uint32` 类型的 RGBA 值 (范围是 `[0, 0xffff]`)。

10. **CMYK 颜色模型的定义 (`CMYKModel`)**:
    *   定义了一个 `CMYKModel` 变量，实现了 `color.Model` 接口，用于处理 CMYK 颜色。
    *   `cmykModel` 函数用于将任意 `Color` 转换为 `CMYK` 类型。

**它是什么 Go 语言功能的实现？**

这段代码实现了 Go 语言中 `image/color` 包关于 **自定义颜色类型和颜色模型** 的功能。它定义了新的颜色类型 (`YCbCr`, `NYCbCrA`, `CMYK`)，并实现了 `color.Color` 接口的 `RGBA()` 方法，以及 `color.Model` 接口，使得这些颜色类型可以融入 Go 语言的图像处理框架中。

**Go 代码举例说明：**

```go
package main

import (
	"fmt"
	"image/color"
)

func main() {
	// RGB 转换为 YCbCr
	r, g, b := uint8(255), uint8(100), uint8(0)
	y, cb, cr := color.RGBToYCbCr(r, g, b)
	fmt.Printf("RGB(%d, %d, %d) 转换为 YCbCr(%d, %d, %d)\n", r, g, b, y, cb, cr)

	// YCbCr 转换为 RGB
	r2, g2, b2 := color.YCbCrToRGB(y, cb, cr)
	fmt.Printf("YCbCr(%d, %d, %d) 转换为 RGB(%d, %d, %d)\n", y, cb, cr, r2, g2, b2)

	// 使用 YCbCr 颜色类型
	ycbcrColor := color.YCbCr{Y: y, Cb: cb, Cr: cr}
	r3, g3, b3, _ := ycbcrColor.RGBA()
	fmt.Printf("YCbCr 颜色类型转换为 RGBA(0x%04x, 0x%04x, 0x%04x)\n", r3, g3, b3)

	// RGB 转换为 CMYK
	c, m, yy, k := color.RGBToCMYK(r, g, b)
	fmt.Printf("RGB(%d, %d, %d) 转换为 CMYK(%d, %d, %d, %d)\n", r, g, b, c, m, yy, k)

	// CMYK 转换为 RGB
	r4, g4, b4 := color.CMYKToRGB(c, m, yy, k)
	fmt.Printf("CMYK(%d, %d, %d, %d) 转换为 RGB(%d, %d, %d)\n", c, m, yy, k, r4, g4, b4)

	// 使用 CMYK 颜色类型
	cmykColor := color.CMYK{C: c, M: m, Y: yy, K: k}
	r5, g5, b5, _ := cmykColor.RGBA()
	fmt.Printf("CMYK 颜色类型转换为 RGBA(0x%04x, 0x%04x, 0x%04x)\n", r5, g5, b5)

	// 使用颜色模型进行转换
	rgbColor := color.RGBA{R: uint8(r3 >> 8), G: uint8(g3 >> 8), B: uint8(b3 >> 8), A: 0xff}
	convertedYCbCr := color.YCbCrModel.Convert(rgbColor).(color.YCbCr)
	fmt.Printf("使用 YCbCrModel 将 RGBA 转换为 YCbCr: YCbCr(%d, %d, %d)\n", convertedYCbCr.Y, convertedYCbCr.Cb, convertedYCbCr.Cr)
}
```

**假设的输入与输出：**

运行上述代码，可能会得到类似以下的输出：

```
RGB(255, 100, 0) 转换为 YCbCr(135, 19, 255)
YCbCr(135, 19, 255) 转换为 RGB(255, 99, 0)
YCbCr 颜色类型转换为 RGBA(0xfff4, 0x648c, 0x00f4)
RGB(255, 100, 0) 转换为 CMYK(0, 155, 255, 0)
CMYK(0, 155, 255, 0) 转换为 RGB(255, 100, 0)
CMYK 颜色类型转换为 RGBA(0xffff, 0x64ff, 0x00ff)
使用 YCbCrModel 将 RGBA 转换为 YCbCr: YCbCr(135, 19, 255)
```

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。它是 `image/color` 包的一部分，主要提供颜色转换和表示的功能。如果需要处理图像文件或进行颜色相关的命令行操作，通常会使用 `image` 包以及其他相关的子包（如 `image/jpeg`, `image/png` 等），并在主程序中解析命令行参数，然后调用 `color` 包提供的函数进行颜色处理。

例如，可以使用 `flag` 包来处理命令行参数，指定输入和输出文件，以及可能的颜色空间转换选项。

**使用者易犯错的点：**

1. **精度损失**: 在 `RGBToYCbCr` 和 `YCbCrToRGB` 的转换过程中，由于使用了整数运算来近似浮点运算，以及 `uint8` 类型的限制，会存在一定的精度损失。这意味着将 RGB 转换为 YCbCr 再转换回 RGB，得到的值可能与原始值略有不同。

    ```go
    r, g, b := uint8(100), uint8(150), uint8(200)
    y, cb, cr := color.RGBToYCbCr(r, g, b)
    r2, g2, b2 := color.YCbCrToRGB(y, cb, cr)
    fmt.Printf("原始 RGB: (%d, %d, %d), 转换后 RGB: (%d, %d, %d)\n", r, g, b, r2, g2, b2)
    // 可能输出: 原始 RGB: (100, 150, 200), 转换后 RGB: (99, 150, 201)
    ```

2. **YCbCr.RGBA() 的精度**:  容易忽略 `YCbCr` 类型的 `RGBA()` 方法直接输出了 16 位的颜色值，这比先用 `YCbCrToRGB` 转换为 8 位 RGB 再转换为 RGBA 拥有更高的精度。在需要更高精度的场景下，应该直接使用 `YCbCr.RGBA()`。

    ```go
    ycbcr := color.YCbCr{Y: 128, Cb: 128, Cr: 128}
    r8, g8, b8 := color.YCbCrToRGB(ycbcr.Y, ycbcr.Cb, ycbcr.Cr)
    r16_1, g16_1, b16_1, _ := color.RGBA{r8, g8, b8, 0xff}.RGBA()
    r16_2, g16_2, b16_2, _ := ycbcr.RGBA()
    fmt.Printf("通过 YCbCrToRGB 再转 RGBA: (0x%04x, 0x%04x, 0x%04x)\n", r16_1, g16_1, b16_1)
    fmt.Printf("直接使用 YCbCr.RGBA(): (0x%04x, 0x%04x, 0x%04x)\n", r16_2, g16_2, b16_2)
    // 可能输出:
    // 通过 YCbCrToRGB 再转 RGBA: (0x8080, 0x8080, 0x8080)
    // 直接使用 YCbCr.RGBA(): (0x8080, 0x8080, 0x8080)  (这里只是一个巧合的例子，某些情况下会有差异)
    ```

3. **CMYK 的设备依赖性**:  需要注意的是，`CMYK` 颜色模型是设备相关的，不同的打印机或输出设备对 CMYK 值的解释可能不同。这段代码提供的 `RGBToCMYK` 和 `CMYKToRGB` 转换并没有考虑特定的色彩配置文件，因此在跨设备使用时可能会出现颜色偏差。

总而言之，这段 `ycbcr.go` 代码提供了 Go 语言中处理 Y'CbCr 和 CMYK 颜色空间的关键功能，包括相互转换以及类型的定义和模型实现。理解其内部的转换原理和潜在的精度问题，有助于更有效地在图像处理中使用这些颜色空间。

Prompt: 
```
这是路径为go/src/image/color/ycbcr.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package color

// RGBToYCbCr converts an RGB triple to a Y'CbCr triple.
func RGBToYCbCr(r, g, b uint8) (uint8, uint8, uint8) {
	// The JFIF specification says:
	//	Y' =  0.2990*R + 0.5870*G + 0.1140*B
	//	Cb = -0.1687*R - 0.3313*G + 0.5000*B + 128
	//	Cr =  0.5000*R - 0.4187*G - 0.0813*B + 128
	// https://www.w3.org/Graphics/JPEG/jfif3.pdf says Y but means Y'.

	r1 := int32(r)
	g1 := int32(g)
	b1 := int32(b)

	// yy is in range [0,0xff].
	//
	// Note that 19595 + 38470 + 7471 equals 65536.
	yy := (19595*r1 + 38470*g1 + 7471*b1 + 1<<15) >> 16

	// The bit twiddling below is equivalent to
	//
	// cb := (-11056*r1 - 21712*g1 + 32768*b1 + 257<<15) >> 16
	// if cb < 0 {
	//     cb = 0
	// } else if cb > 0xff {
	//     cb = ^int32(0)
	// }
	//
	// but uses fewer branches and is faster.
	// Note that the uint8 type conversion in the return
	// statement will convert ^int32(0) to 0xff.
	// The code below to compute cr uses a similar pattern.
	//
	// Note that -11056 - 21712 + 32768 equals 0.
	cb := -11056*r1 - 21712*g1 + 32768*b1 + 257<<15
	if uint32(cb)&0xff000000 == 0 {
		cb >>= 16
	} else {
		cb = ^(cb >> 31)
	}

	// Note that 32768 - 27440 - 5328 equals 0.
	cr := 32768*r1 - 27440*g1 - 5328*b1 + 257<<15
	if uint32(cr)&0xff000000 == 0 {
		cr >>= 16
	} else {
		cr = ^(cr >> 31)
	}

	return uint8(yy), uint8(cb), uint8(cr)
}

// YCbCrToRGB converts a Y'CbCr triple to an RGB triple.
func YCbCrToRGB(y, cb, cr uint8) (uint8, uint8, uint8) {
	// The JFIF specification says:
	//	R = Y' + 1.40200*(Cr-128)
	//	G = Y' - 0.34414*(Cb-128) - 0.71414*(Cr-128)
	//	B = Y' + 1.77200*(Cb-128)
	// https://www.w3.org/Graphics/JPEG/jfif3.pdf says Y but means Y'.
	//
	// Those formulae use non-integer multiplication factors. When computing,
	// integer math is generally faster than floating point math. We multiply
	// all of those factors by 1<<16 and round to the nearest integer:
	//	 91881 = roundToNearestInteger(1.40200 * 65536).
	//	 22554 = roundToNearestInteger(0.34414 * 65536).
	//	 46802 = roundToNearestInteger(0.71414 * 65536).
	//	116130 = roundToNearestInteger(1.77200 * 65536).
	//
	// Adding a rounding adjustment in the range [0, 1<<16-1] and then shifting
	// right by 16 gives us an integer math version of the original formulae.
	//	R = (65536*Y' +  91881 *(Cr-128)                  + adjustment) >> 16
	//	G = (65536*Y' -  22554 *(Cb-128) - 46802*(Cr-128) + adjustment) >> 16
	//	B = (65536*Y' + 116130 *(Cb-128)                  + adjustment) >> 16
	// A constant rounding adjustment of 1<<15, one half of 1<<16, would mean
	// round-to-nearest when dividing by 65536 (shifting right by 16).
	// Similarly, a constant rounding adjustment of 0 would mean round-down.
	//
	// Defining YY1 = 65536*Y' + adjustment simplifies the formulae and
	// requires fewer CPU operations:
	//	R = (YY1 +  91881 *(Cr-128)                 ) >> 16
	//	G = (YY1 -  22554 *(Cb-128) - 46802*(Cr-128)) >> 16
	//	B = (YY1 + 116130 *(Cb-128)                 ) >> 16
	//
	// The inputs (y, cb, cr) are 8 bit color, ranging in [0x00, 0xff]. In this
	// function, the output is also 8 bit color, but in the related YCbCr.RGBA
	// method, below, the output is 16 bit color, ranging in [0x0000, 0xffff].
	// Outputting 16 bit color simply requires changing the 16 to 8 in the "R =
	// etc >> 16" equation, and likewise for G and B.
	//
	// As mentioned above, a constant rounding adjustment of 1<<15 is a natural
	// choice, but there is an additional constraint: if c0 := YCbCr{Y: y, Cb:
	// 0x80, Cr: 0x80} and c1 := Gray{Y: y} then c0.RGBA() should equal
	// c1.RGBA(). Specifically, if y == 0 then "R = etc >> 8" should yield
	// 0x0000 and if y == 0xff then "R = etc >> 8" should yield 0xffff. If we
	// used a constant rounding adjustment of 1<<15, then it would yield 0x0080
	// and 0xff80 respectively.
	//
	// Note that when cb == 0x80 and cr == 0x80 then the formulae collapse to:
	//	R = YY1 >> n
	//	G = YY1 >> n
	//	B = YY1 >> n
	// where n is 16 for this function (8 bit color output) and 8 for the
	// YCbCr.RGBA method (16 bit color output).
	//
	// The solution is to make the rounding adjustment non-constant, and equal
	// to 257*Y', which ranges over [0, 1<<16-1] as Y' ranges over [0, 255].
	// YY1 is then defined as:
	//	YY1 = 65536*Y' + 257*Y'
	// or equivalently:
	//	YY1 = Y' * 0x10101
	yy1 := int32(y) * 0x10101
	cb1 := int32(cb) - 128
	cr1 := int32(cr) - 128

	// The bit twiddling below is equivalent to
	//
	// r := (yy1 + 91881*cr1) >> 16
	// if r < 0 {
	//     r = 0
	// } else if r > 0xff {
	//     r = ^int32(0)
	// }
	//
	// but uses fewer branches and is faster.
	// Note that the uint8 type conversion in the return
	// statement will convert ^int32(0) to 0xff.
	// The code below to compute g and b uses a similar pattern.
	r := yy1 + 91881*cr1
	if uint32(r)&0xff000000 == 0 {
		r >>= 16
	} else {
		r = ^(r >> 31)
	}

	g := yy1 - 22554*cb1 - 46802*cr1
	if uint32(g)&0xff000000 == 0 {
		g >>= 16
	} else {
		g = ^(g >> 31)
	}

	b := yy1 + 116130*cb1
	if uint32(b)&0xff000000 == 0 {
		b >>= 16
	} else {
		b = ^(b >> 31)
	}

	return uint8(r), uint8(g), uint8(b)
}

// YCbCr represents a fully opaque 24-bit Y'CbCr color, having 8 bits each for
// one luma and two chroma components.
//
// JPEG, VP8, the MPEG family and other codecs use this color model. Such
// codecs often use the terms YUV and Y'CbCr interchangeably, but strictly
// speaking, the term YUV applies only to analog video signals, and Y' (luma)
// is Y (luminance) after applying gamma correction.
//
// Conversion between RGB and Y'CbCr is lossy and there are multiple, slightly
// different formulae for converting between the two. This package follows
// the JFIF specification at https://www.w3.org/Graphics/JPEG/jfif3.pdf.
type YCbCr struct {
	Y, Cb, Cr uint8
}

func (c YCbCr) RGBA() (uint32, uint32, uint32, uint32) {
	// This code is a copy of the YCbCrToRGB function above, except that it
	// returns values in the range [0, 0xffff] instead of [0, 0xff]. There is a
	// subtle difference between doing this and having YCbCr satisfy the Color
	// interface by first converting to an RGBA. The latter loses some
	// information by going to and from 8 bits per channel.
	//
	// For example, this code:
	//	const y, cb, cr = 0x7f, 0x7f, 0x7f
	//	r, g, b := color.YCbCrToRGB(y, cb, cr)
	//	r0, g0, b0, _ := color.YCbCr{y, cb, cr}.RGBA()
	//	r1, g1, b1, _ := color.RGBA{r, g, b, 0xff}.RGBA()
	//	fmt.Printf("0x%04x 0x%04x 0x%04x\n", r0, g0, b0)
	//	fmt.Printf("0x%04x 0x%04x 0x%04x\n", r1, g1, b1)
	// prints:
	//	0x7e18 0x808d 0x7db9
	//	0x7e7e 0x8080 0x7d7d

	yy1 := int32(c.Y) * 0x10101
	cb1 := int32(c.Cb) - 128
	cr1 := int32(c.Cr) - 128

	// The bit twiddling below is equivalent to
	//
	// r := (yy1 + 91881*cr1) >> 8
	// if r < 0 {
	//     r = 0
	// } else if r > 0xff {
	//     r = 0xffff
	// }
	//
	// but uses fewer branches and is faster.
	// The code below to compute g and b uses a similar pattern.
	r := yy1 + 91881*cr1
	if uint32(r)&0xff000000 == 0 {
		r >>= 8
	} else {
		r = ^(r >> 31) & 0xffff
	}

	g := yy1 - 22554*cb1 - 46802*cr1
	if uint32(g)&0xff000000 == 0 {
		g >>= 8
	} else {
		g = ^(g >> 31) & 0xffff
	}

	b := yy1 + 116130*cb1
	if uint32(b)&0xff000000 == 0 {
		b >>= 8
	} else {
		b = ^(b >> 31) & 0xffff
	}

	return uint32(r), uint32(g), uint32(b), 0xffff
}

// YCbCrModel is the [Model] for Y'CbCr colors.
var YCbCrModel Model = ModelFunc(yCbCrModel)

func yCbCrModel(c Color) Color {
	if _, ok := c.(YCbCr); ok {
		return c
	}
	r, g, b, _ := c.RGBA()
	y, u, v := RGBToYCbCr(uint8(r>>8), uint8(g>>8), uint8(b>>8))
	return YCbCr{y, u, v}
}

// NYCbCrA represents a non-alpha-premultiplied Y'CbCr-with-alpha color, having
// 8 bits each for one luma, two chroma and one alpha component.
type NYCbCrA struct {
	YCbCr
	A uint8
}

func (c NYCbCrA) RGBA() (uint32, uint32, uint32, uint32) {
	// The first part of this method is the same as YCbCr.RGBA.
	yy1 := int32(c.Y) * 0x10101
	cb1 := int32(c.Cb) - 128
	cr1 := int32(c.Cr) - 128

	// The bit twiddling below is equivalent to
	//
	// r := (yy1 + 91881*cr1) >> 8
	// if r < 0 {
	//     r = 0
	// } else if r > 0xff {
	//     r = 0xffff
	// }
	//
	// but uses fewer branches and is faster.
	// The code below to compute g and b uses a similar pattern.
	r := yy1 + 91881*cr1
	if uint32(r)&0xff000000 == 0 {
		r >>= 8
	} else {
		r = ^(r >> 31) & 0xffff
	}

	g := yy1 - 22554*cb1 - 46802*cr1
	if uint32(g)&0xff000000 == 0 {
		g >>= 8
	} else {
		g = ^(g >> 31) & 0xffff
	}

	b := yy1 + 116130*cb1
	if uint32(b)&0xff000000 == 0 {
		b >>= 8
	} else {
		b = ^(b >> 31) & 0xffff
	}

	// The second part of this method applies the alpha.
	a := uint32(c.A) * 0x101
	return uint32(r) * a / 0xffff, uint32(g) * a / 0xffff, uint32(b) * a / 0xffff, a
}

// NYCbCrAModel is the [Model] for non-alpha-premultiplied Y'CbCr-with-alpha
// colors.
var NYCbCrAModel Model = ModelFunc(nYCbCrAModel)

func nYCbCrAModel(c Color) Color {
	switch c := c.(type) {
	case NYCbCrA:
		return c
	case YCbCr:
		return NYCbCrA{c, 0xff}
	}
	r, g, b, a := c.RGBA()

	// Convert from alpha-premultiplied to non-alpha-premultiplied.
	if a != 0 {
		r = (r * 0xffff) / a
		g = (g * 0xffff) / a
		b = (b * 0xffff) / a
	}

	y, u, v := RGBToYCbCr(uint8(r>>8), uint8(g>>8), uint8(b>>8))
	return NYCbCrA{YCbCr{Y: y, Cb: u, Cr: v}, uint8(a >> 8)}
}

// RGBToCMYK converts an RGB triple to a CMYK quadruple.
func RGBToCMYK(r, g, b uint8) (uint8, uint8, uint8, uint8) {
	rr := uint32(r)
	gg := uint32(g)
	bb := uint32(b)
	w := rr
	if w < gg {
		w = gg
	}
	if w < bb {
		w = bb
	}
	if w == 0 {
		return 0, 0, 0, 0xff
	}
	c := (w - rr) * 0xff / w
	m := (w - gg) * 0xff / w
	y := (w - bb) * 0xff / w
	return uint8(c), uint8(m), uint8(y), uint8(0xff - w)
}

// CMYKToRGB converts a [CMYK] quadruple to an RGB triple.
func CMYKToRGB(c, m, y, k uint8) (uint8, uint8, uint8) {
	w := 0xffff - uint32(k)*0x101
	r := (0xffff - uint32(c)*0x101) * w / 0xffff
	g := (0xffff - uint32(m)*0x101) * w / 0xffff
	b := (0xffff - uint32(y)*0x101) * w / 0xffff
	return uint8(r >> 8), uint8(g >> 8), uint8(b >> 8)
}

// CMYK represents a fully opaque CMYK color, having 8 bits for each of cyan,
// magenta, yellow and black.
//
// It is not associated with any particular color profile.
type CMYK struct {
	C, M, Y, K uint8
}

func (c CMYK) RGBA() (uint32, uint32, uint32, uint32) {
	// This code is a copy of the CMYKToRGB function above, except that it
	// returns values in the range [0, 0xffff] instead of [0, 0xff].

	w := 0xffff - uint32(c.K)*0x101
	r := (0xffff - uint32(c.C)*0x101) * w / 0xffff
	g := (0xffff - uint32(c.M)*0x101) * w / 0xffff
	b := (0xffff - uint32(c.Y)*0x101) * w / 0xffff
	return r, g, b, 0xffff
}

// CMYKModel is the [Model] for CMYK colors.
var CMYKModel Model = ModelFunc(cmykModel)

func cmykModel(c Color) Color {
	if _, ok := c.(CMYK); ok {
		return c
	}
	r, g, b, _ := c.RGBA()
	cc, mm, yy, kk := RGBToCMYK(uint8(r>>8), uint8(g>>8), uint8(b>>8))
	return CMYK{cc, mm, yy, kk}
}

"""



```