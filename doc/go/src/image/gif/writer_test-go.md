Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the given Go code, primarily focusing on GIF encoding. It also probes for specific Go features demonstrated, potential errors, and any command-line interactions (though this specific code doesn't have explicit command-line arguments).

2. **Initial Scan and Keyword Spotting:**  Quickly read through the code, looking for keywords related to images and GIFs: `image`, `gif`, `Encode`, `Decode`, `Palette`, `Bounds`, `Delay`, `LoopCount`, `Disposal`. The presence of `*_test.go` immediately signals that this is test code.

3. **Identify Core Functionality:** The presence of `Encode` and `Decode` functions strongly suggests the primary purpose is GIF encoding and decoding. The `TestWriter` and `TestEncodeAll` functions confirm this is test code for these operations.

4. **Analyze Helper Functions:**  Examine the utility functions:
    * `readImg`: Reads a general image file (supports PNG as implied by the import).
    * `readGIF`: Specifically reads a GIF file.
    * `delta`, `averageDelta`, `averageDeltaBound`: These are helper functions for comparing images, specifically by calculating the difference in RGB values. This is crucial for testing if the encoding/decoding process is lossy and to what extent.
    * `palettesEqual`:  Compares color palettes, handling the case of trailing opaque black entries. This is a detail specific to GIF color handling.

5. **Focus on Test Functions:** The core functionality is tested within the `Test...` functions.
    * `TestWriter`:  This seems to be testing the basic `Encode` and `Decode` for single-frame GIFs, comparing the original and re-encoded images using the `averageDelta`. The `tolerance` field in `testCase` suggests that some lossiness is expected for PNG input.
    * `TestSubImage`: This specifically tests encoding a sub-region of an existing image.
    * `testEncodeAll`:  This tests the `EncodeAll` function, which handles encoding animated GIFs (multiple frames). It checks various aspects like loop count, delays, disposal methods, and the global color table. The `go1Dot5Fields` flag indicates testing for features introduced in Go 1.5.
    * `TestEncodeMismatchDelay`, `TestEncodeZeroGIF`, `TestEncodeAllFramesOutOfBounds`, `TestEncodeNonZeroMinPoint`, `TestEncodeImplicitConfigSize`, `TestEncodePalettes`, `TestEncodeBadPalettes`, `TestColorTablesMatch`, `TestEncodeCroppedSubImages`, `TestEncodeWrappedImage`: These are more specific test cases covering edge conditions, different image configurations (like non-zero Min points), and palette handling.

6. **Infer Go Features:**
    * **Standard Library `image` package:** The code heavily uses interfaces and structs from the `image` package, including `image.Image`, `image.Paletted`, `image.RGBA`, `image.Rectangle`, `color.Palette`, etc. This demonstrates the use of Go's built-in image processing capabilities.
    * **Interfaces:** The `writer` interface (though a no-op) and the use of `image.Image` as an interface are examples of Go's interface-based programming.
    * **Error Handling:** The consistent use of `if err != nil` demonstrates Go's standard error handling practices.
    * **Testing Framework:** The `testing` package is used for writing unit tests.
    * **Anonymous Imports:** `_ "image/png"` demonstrates using an import for its side effects (registering the PNG decoder).
    * **Reflection:** `reflect.DeepEqual` is used for comparing complex data structures.
    * **Buffers:** `bytes.Buffer` is used for in-memory encoding/decoding.

7. **Code Example Construction:** Based on the identified functionality, create concise examples illustrating `Encode` and `EncodeAll`. This involves creating sample `image.Image` and `gif.GIF` structs.

8. **Identify Potential Errors:** Analyze the test cases and function signatures to identify common pitfalls:
    * Incorrect slice lengths for `Image`, `Delay`, and `Disposal` in `GIF` struct.
    * Providing an empty `GIF` struct to `EncodeAll`.
    * Frames with bounds exceeding the configured GIF dimensions.
    * Using palettes with more than 256 colors.

9. **Command Line Arguments:**  Recognize that this specific code snippet is a testing file and doesn't directly process command-line arguments. The tests likely use hardcoded file paths within the test suite.

10. **Review and Refine:**  Read through the generated answer, ensuring clarity, accuracy, and proper formatting. Double-check the code examples and explanations. Ensure the language is clear and addresses all parts of the original request. For instance, initially, I might have missed the subtlety of the `palettesEqual` function handling trailing black entries, but a closer look reveals this specific logic and its importance in GIF processing.

This iterative process of scanning, identifying core functions, analyzing tests, inferring language features, and constructing examples helps in providing a comprehensive and accurate answer to the request.
这段代码是 Go 语言标准库 `image/gif` 包中 `writer_test.go` 文件的一部分，它的主要功能是**测试 GIF 图像编码器的功能**。

具体来说，它通过编写一系列测试用例，验证 `gif` 包中的 `Encode` 和 `EncodeAll` 函数是否能够正确地将 `image.Image` 和 `gif.GIF` 结构体编码成符合 GIF 格式的字节流，并且解码后能够得到与原始图像或动画相似的结果。

下面我们来详细列举一下代码片段中的功能点，并用 Go 代码举例说明：

**1. 读取图像和 GIF 文件:**

*   `readImg(filename string) (image.Image, error)`:  此函数用于读取指定路径的图像文件 (支持 PNG 等格式，因为导入了 `_ "image/png"`)，并返回 `image.Image` 接口和可能的错误。
*   `readGIF(filename string) (*GIF, error)`: 此函数用于读取指定路径的 GIF 文件，并返回 `gif.GIF` 结构体指针和可能的错误。

```go
package main

import (
	"fmt"
	"image"
	_ "image/png" // 导入以支持 PNG 解码
	"image/gif"
	"os"
)

func main() {
	img, err := readImg("../testdata/video-001.png")
	if err != nil {
		fmt.Println("Error reading image:", err)
		return
	}
	fmt.Printf("Read image with bounds: %v\n", img.Bounds())

	g, err := readGIF("../testdata/video-001.gif")
	if err != nil {
		fmt.Println("Error reading GIF:", err)
		return
	}
	fmt.Printf("Read GIF with %d images, loop count: %d\n", len(g.Image), g.LoopCount)
}

func readImg(filename string) (image.Image, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, _, err := image.Decode(f)
	return m, err
}

func readGIF(filename string) (*gif.GIF, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return gif.DecodeAll(f)
}
```

**假设输入:** 存在名为 `../testdata/video-001.png` 和 `../testdata/video-001.gif` 的文件。

**可能输出:**
```
Read image with bounds: image.Rectangle{Min:image.Point{X:0, Y:0}, Max:image.Point{X:150, Y:103}}
Read GIF with 1 images, loop count: 0
```

**2. 计算图像差异:**

*   `delta(u0, u1 uint32) int64`: 计算两个 `uint32` 值的差的绝对值。
*   `averageDelta(m0, m1 image.Image) int64`: 计算两个图像在 RGB 空间的平均差异值。要求两个图像的尺寸相同。
*   `averageDeltaBound(m0, m1 image.Image, b0, b1 image.Rectangle) int64`:  计算两个图像指定区域内的平均差异值。

```go
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
)

func main() {
	file1, _ := os.Open("../testdata/video-001.png") // 忽略错误处理
	defer file1.Close()
	img1, _ := png.Decode(file1)

	file2, _ := os.Open("../testdata/video-001.png") // 忽略错误处理
	defer file2.Close()
	img2, _ := png.Decode(file2)

	avgDiff := averageDelta(img1, img2)
	fmt.Println("Average delta between identical images:", avgDiff) // 应该接近 0
}

func delta(u0, u1 uint32) int64 {
	d := int64(u0) - int64(u1)
	if d < 0 {
		return -d
	}
	return d
}

func averageDelta(m0, m1 image.Image) int64 {
	b := m0.Bounds()
	return averageDeltaBound(m0, m1, b, b)
}

func averageDeltaBound(m0, m1 image.Image, b0, b1 image.Rectangle) int64 {
	var sum, n int64
	for y := b0.Min.Y; y < b0.Max.Y; y++ {
		for x := b0.Min.X; x < b0.Max.X; x++ {
			c0 := m0.At(x, y)
			c1 := m1.At(x-b0.Min.X+b1.Min.X, y-b0.Min.Y+b1.Min.Y)
			r0, g0, b0, _ := c0.RGBA()
			r1, g1, b1, _ := c1.RGBA()
			sum += delta(r0, r1)
			sum += delta(g0, g1)
			sum += delta(b0, b1)
			n += 3
		}
	}
	return sum / n
}
```

**假设输入:** 存在名为 `../testdata/video-001.png` 的文件。

**可能输出:**
```
Average delta between identical images: 0
```

**3. 测试基本的 GIF 编码和解码 (`TestWriter`):**

*   遍历 `testCase` 中定义的测试用例，每个用例包含一个文件名和一个容差值。
*   读取图像文件 (`.png` 或 `.gif`)。
*   使用 `gif.Encode` 将图像编码为 GIF 格式的字节流。
*   使用 `gif.Decode` 将编码后的字节流解码回 `image.Image`。
*   比较原始图像和解码后图像的尺寸，并计算平均差异，判断是否在容差范围内。

```go
package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"os"
)

func main() {
	testCases := []struct {
		filename  string
		tolerance int64
	}{
		{"../testdata/video-001.png", 1 << 12},
		{"../testdata/video-001.gif", 0},
	}

	for _, tc := range testCases {
		m0, err := readImg(tc.filename)
		if err != nil {
			fmt.Println("Error reading image:", err)
			continue
		}

		var buf bytes.Buffer
		err = gif.Encode(&buf, m0, nil)
		if err != nil {
			fmt.Println("Error encoding GIF:", err)
			continue
		}

		m1, err := gif.Decode(&buf)
		if err != nil {
			fmt.Println("Error decoding GIF:", err)
			continue
		}

		if m0.Bounds() != m1.Bounds() {
			fmt.Printf("Bounds differ for %s: %v and %v\n", tc.filename, m0.Bounds(), m1.Bounds())
			continue
		}

		avgDelta := averageDelta(m0, m1)
		if avgDelta > tc.tolerance {
			fmt.Printf("%s: average delta is too high. expected: %d, got %d\n", tc.filename, tc.tolerance, avgDelta)
			continue
		}

		fmt.Printf("Test passed for %s\n", tc.filename)
	}
}

// ... (包含 readImg, averageDelta 等函数的定义)
```

**假设输入:** 存在名为 `../testdata/video-001.png` 和 `../testdata/video-001.gif` 的文件。

**可能输出:**
```
Test passed for ../testdata/video-001.png
Test passed for ../testdata/video-001.gif
```

**4. 测试子图的编码 (`TestSubImage`):**

*   读取一个 GIF 文件。
*   获取该 GIF 图像的一个子区域 (`SubImage`)。
*   编码和解码该子图。
*   比较原始子图和解码后图像的尺寸和内容差异。

```go
package main

import (
	"bytes"
	"fmt"
	"image"
	"image/gif"
	"os"
)

func main() {
	m0, err := readImg("../testdata/video-001.gif")
	if err != nil {
		fmt.Println("Error reading GIF:", err)
		return
	}
	subImg := m0.(*image.Paletted).SubImage(image.Rect(0, 0, 50, 30))

	var buf bytes.Buffer
	err = gif.Encode(&buf, subImg, nil)
	if err != nil {
		fmt.Println("Error encoding sub-image:", err)
		return
	}

	m1, err := gif.Decode(&buf)
	if err != nil {
		fmt.Println("Error decoding sub-image:", err)
		return
	}

	if subImg.Bounds() != m1.Bounds() {
		fmt.Printf("Bounds differ: %v and %v\n", subImg.Bounds(), m1.Bounds())
		return
	}

	avgDelta := averageDelta(subImg, m1)
	if avgDelta != 0 {
		fmt.Println("Images differ")
		return
	}

	fmt.Println("Sub-image test passed")
}

// ... (包含 readImg, averageDelta 等函数的定义)
```

**假设输入:** 存在名为 `../testdata/video-001.gif` 的文件。

**可能输出:**
```
Sub-image test passed
```

**5. 比较调色板 (`palettesEqual`):**

*   该函数用于比较两个 `color.Palette` 是否相等，忽略尾部的透明黑色条目。这在 GIF 处理中很重要，因为尾部的透明黑色条目可能存在也可能不存在。

```go
package main

import (
	"fmt"
	"image/color"
)

func main() {
	p1 := color.Palette{color.RGBA{1, 2, 3, 255}, color.RGBA{4, 5, 6, 255}}
	p2 := color.Palette{color.RGBA{1, 2, 3, 255}, color.RGBA{4, 5, 6, 255}}
	p3 := color.Palette{color.RGBA{1, 2, 3, 255}, color.RGBA{7, 8, 9, 255}}
	p4 := color.Palette{color.RGBA{1, 2, 3, 255}, color.RGBA{4, 5, 6, 255}, color.RGBA{0, 0, 0, 0}}

	fmt.Println("p1 == p2:", palettesEqual(p1, p2)) // true
	fmt.Println("p1 == p3:", palettesEqual(p1, p3)) // false
	fmt.Println("p1 == p4:", palettesEqual(p1, p4)) // true (忽略尾部透明黑色)
}

func palettesEqual(p, q color.Palette) bool {
	n := len(p)
	if n > len(q) {
		n = len(q)
	}
	for i := 0; i < n; i++ {
		if p[i] != q[i] {
			return false
		}
	}
	for i := n; i < len(p); i++ {
		r, g, b, a := p[i].RGBA()
		if r != 0 || g != 0 || b != 0 || a != 0xffff {
			return false
		}
	}
	for i := n; i < len(q); i++ {
		r, g, b, a := q[i].RGBA()
		if r != 0 || g != 0 || b != 0 || a != 0xffff {
			return false
		}
	}
	return true
}
```

**可能输出:**
```
p1 == p2: true
p1 == p3: false
p1 == p4: true
```

**6. 测试动画 GIF 的编码和解码 (`testEncodeAll` 和相关的 `TestEncodeAllGo1Dot4`, `TestEncodeAllGo1Dot5`, `TestEncodeAllGo1Dot5GlobalColorModel`):**

*   `testEncodeAll` 函数是核心的动画 GIF 编码测试函数，它接受一个布尔值 `go1Dot5Fields` 和 `useGlobalColorModel` 作为参数，用于测试不同场景下的 `EncodeAll` 功能。
*   它创建一个 `gif.GIF` 结构体，包含多个图像帧、延迟信息和循环次数。
*   根据 `go1Dot5Fields` 的值，设置 `GIF` 结构体中 Go 1.5 版本新增的字段，如 `Disposal`、`Config` 和 `BackgroundIndex`。
*   使用 `gif.EncodeAll` 将 `gif.GIF` 编码为字节流。
*   使用 `gif.DecodeConfig` 获取编码后 GIF 的配置信息。
*   使用 `gif.DecodeAll` 将编码后的字节流解码回 `gif.GIF` 结构体。
*   比较原始 `gif.GIF` 和解码后的 `gif.GIF` 的各个字段，包括配置、循环次数、背景色索引、图像帧、延迟和处理方法等。
*   `TestEncodeAllGo1Dot4`、`TestEncodeAllGo1Dot5` 和 `TestEncodeAllGo1Dot5GlobalColorModel` 是调用 `testEncodeAll` 函数的具体测试用例，分别测试在 Go 1.4 兼容模式、Go 1.5 及以上版本以及使用全局颜色模型的情况下的编码。

```go
package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/palette"
	"os"
	"reflect"
)

func main() {
	testEncodeScenario(false, false) // 模拟 Go 1.4 环境
	testEncodeScenario(true, false)  // 模拟 Go 1.5 环境
	testEncodeScenario(true, true)   // 模拟 Go 1.5 环境并使用全局颜色模型
}

func testEncodeScenario(go1Dot5Fields bool, useGlobalColorModel bool) {
	const width, height = 50, 50
	frames := []*image.Paletted{
		image.NewPaletted(image.Rect(0, 0, width, height), palette.Plan9),
		image.NewPaletted(image.Rect(0, 0, width, height), palette.WebSafe),
	}

	g0 := &gif.GIF{
		Image:     frames,
		Delay:     []int{10, 20},
		LoopCount: 3,
	}

	globalColorModel, backgroundIndex := color.Model(color.Palette(nil)), uint8(0)
	if useGlobalColorModel {
		globalColorModel, backgroundIndex = color.Palette(palette.WebSafe), uint8(1)
	}

	if go1Dot5Fields {
		g0.Disposal = []byte{gif.DisposalNone, gif.DisposalBackground}
		g0.Config = image.Config{
			ColorModel: globalColorModel,
			Width:      width,
			Height:     height,
		}
		g0.BackgroundIndex = backgroundIndex
	}

	var buf bytes.Buffer
	err := gif.EncodeAll(&buf, g0)
	if err != nil {
		fmt.Println("EncodeAll error:", err)
		return
	}

	config, err := gif.DecodeConfig(&buf)
	if err != nil {
		fmt.Println("DecodeConfig error:", err)
		return
	}

	g1, err := gif.DecodeAll(&buf)
	if err != nil {
		fmt.Println("DecodeAll error:", err)
		return
	}

	if !reflect.DeepEqual(config, g1.Config) {
		fmt.Println("DecodeConfig inconsistent with DecodeAll")
	}
	// ... (更多的断言，例如比较调色板，循环次数等)
	fmt.Println("EncodeAll test passed (go1Dot5Fields:", go1Dot5Fields, ", useGlobalColorModel:", useGlobalColorModel, ")")
}

// ... (包含 readGIF, palettesEqual 等函数的定义)
```

**假设输入:** 存在名为 `../testdata/video-001.gif` 和 `../testdata/video-005.gray.gif` 的文件。

**可能输出:**
```
EncodeAll test passed (go1Dot5Fields: false, useGlobalColorModel: false)
EncodeAll test passed (go1Dot5Fields: true, useGlobalColorModel: false)
EncodeAll test passed (go1Dot5Fields: true, useGlobalColorModel: true)
```

**7. 测试编码过程中的各种错误情况 (`TestEncodeMismatchDelay`, `TestEncodeZeroGIF`, `TestEncodeAllFramesOutOfBounds` 等):**

*   这些测试用例分别测试了在 `gif.GIF` 结构体的 `Image`、`Delay` 和 `Disposal` 切片长度不匹配、尝试编码空的 `gif.GIF` 结构体、动画帧的边界超出配置范围等情况下，编码器是否能够正确地返回错误。

**8. 测试非零起始点的图像编码 (`TestEncodeNonZeroMinPoint`):**

*   测试当输入的 `image.Image` 的 `Bounds().Min` 不是 `(0, 0)` 时，编码器是否能够正确处理。它创建具有不同起始点的 `image.Paletted` 和 `image.RGBA` 图像，并进行编码和解码，验证解码后的图像边界是否为 `(0, 0)`，并且内容是否正确。

**9. 测试隐式配置大小 (`TestEncodeImplicitConfigSize`):**

*   测试在 `gif.GIF` 的 `Config` 字段未设置时，编码器是否能够根据第一帧图像的大小推断出 GIF 的宽度和高度。同时，它也测试了当帧的起始坐标为负数时，编码器是否会报错。

**10. 测试调色板的编码 (`TestEncodePalettes` 和 `TestEncodeBadPalettes`):**

*   `TestEncodePalettes` 测试了编码包含不同调色板的动画 GIF 时，调色板是否能够正确保存。
*   `TestEncodeBadPalettes` 测试了编码包含超过 256 种颜色或包含 `nil` 颜色的调色板时，编码器是否会报错。

**11. 测试颜色表匹配 (`TestColorTablesMatch`):**

*   这个测试用例比较了全局颜色表和局部颜色表在特定条件下的编码结果，用于验证编码器在处理透明色索引时的逻辑。

**12. 测试裁剪后的子图编码 (`TestEncodeCroppedSubImages`):**

*   测试了编码从原始图像裁剪出来的不同大小和位置的子图，确保编码器能够正确处理图像的边界和步长。

**13. 测试包装后的图像编码 (`TestEncodeWrappedImage`):**

*   创建了一个实现了 `image.Image` 接口的自定义类型 `offsetImage`，用于模拟图像数据在内存中的偏移。测试了编码这种包装后的图像，以及带有偏移的包装图像，验证编码器是否能够正确处理。

**14. 基准测试 (`BenchmarkEncodeRandomPaletted`, `BenchmarkEncodeRandomRGBA`, `BenchmarkEncodeRealisticPaletted`, `BenchmarkEncodeRealisticRGBA`):**

*   这些函数用于进行性能测试，分别测试编码随机生成的 `image.Paletted` 和 `image.RGBA` 图像，以及编码从实际图像读取并转换得到的 `image.Paletted` 和 `image.RGBA` 图像的性能。

**关于涉及的 Go 语言功能实现：**

这段代码主要测试了 `image/gif` 包中与 GIF 编码相关的以下 Go 语言功能：

*   **`image.Image` 接口和其实现 (`image.Paletted`, `image.RGBA`)**:  Go 语言标准库 `image` 包中定义的图像接口，以及用于表示索引颜色图像和 RGBA 颜色图像的结构体。
*   **`image/color.Palette` 类型**: 用于表示颜色调色板。
*   **`image/gif.GIF` 结构体**:  用于表示 GIF 图像（包括动画 GIF）。
*   **`image/gif.Encode` 函数**: 将 `image.Image` 编码为 GIF 格式。
*   **`image/gif.EncodeAll` 函数**: 将 `gif.GIF` 编码为 GIF 格式。
*   **`image/gif.Decode` 函数**: 将 GIF 格式的字节流解码为 `image.Image`。
*   **`image/gif.DecodeAll` 函数**: 将 GIF 格式的字节流解码为 `gif.GIF`。
*   **`image/gif.DecodeConfig` 函数**:  解析 GIF 图像的配置信息而不解码整个图像。
*   **`io.Writer` 接口**: `gif.Encode` 和 `gif.EncodeAll` 函数接受 `io.Writer` 作为参数，用于输出编码后的数据。`bytes.Buffer` 实现了 `io.Writer` 接口，用于在内存中存储编码后的数据。
*   **错误处理**: 代码中大量使用了 `error` 类型来处理可能出现的错误。
*   **测试框架 (`testing` 包)**:  使用 `testing` 包编写单元测试和基准测试。
*   **匿名导入 (`_`)**:  `_ "image/png"` 用于注册 PNG 图像的解码器。
*   **反射 (`reflect` 包)**:  `reflect.DeepEqual` 用于深度比较两个结构体是否相等。

**使用者易犯错的点：**

*   **`EncodeAll` 函数要求 `GIF` 结构体的 `Image`、`Delay` 和 `Disposal` 切片长度必须一致。** 如果长度不一致，编码会失败。

    ```go
    package main

    import (
    	"bytes"
    	"fmt"
    	"image"
    	"image/color/palette"
    	"image/gif"
    	"os"
    )

    func main() {
    	// 错误示例：Delay 切片长度与 Image 切片长度不一致
    	g := &gif.GIF{
    		Image: []*image.Paletted{
    			image.NewPaletted(image.Rect(0, 0, 10, 10), palette.Plan9),
    			image.NewPaletted(image.Rect(0, 0, 10, 10), palette.Plan9),
    		},
    		Delay: []int{10}, // 长度为 1，应该为 2
    	}

    	var buf bytes.Buffer
    	err := gif.EncodeAll(&buf, g)
    	if err != nil {
    		fmt.Println("EncodeAll error:", err) // 这里会输出错误
    	}
    }
    ```

*   **向 `EncodeAll` 传递空的 `GIF` 结构体。**  这会导致编码失败。

    ```go
    package main

    import (
    	"bytes"
    	"fmt"
    	"image/gif"
    	"os"
    )

    func main() {
    	emptyGIF := &gif.GIF{}
    	var buf bytes.Buffer
    	err := gif.EncodeAll(&buf, emptyGIF)
    	if err != nil {
    		fmt.Println("EncodeAll error:", err) // 这里会输出错误
    	}
    }
    ```

*   **动画帧的边界超出配置的 GIF 尺寸。** 如果 `gif.GIF` 的 `Config` 字段指定了尺寸，而某些帧的边界超出了这个尺寸，编码会失败。

    ```go
    package main

    import (
    	"bytes"
    	"fmt"
    	"image"
    	"image/color/palette"
    	"image/gif"
    	"os"
    )

    func main() {
    	g := &gif.GIF{
    		Image: []*image.Paletted{
    			image.NewPaletted(image.Rect(0, 0, 20, 20), palette.Plan9),
    		},
    		Delay: []int{10},
    		Config: image.Config{
    			Width:  10,
    			Height: 10,
    		},
    	}

    	var buf bytes.Buffer
    	err := gif.EncodeAll(&buf, g)
    	if err != nil {
    		fmt.Println("EncodeAll error:", err) // 这里会输出错误，因为帧大小 (20x20) 超出了配置 (10x10)
    	}
    }
    ```

这段测试代码覆盖了 `image/gif` 包中编码器的各种功能和边界情况，是理解和正确使用该包的重要参考。

Prompt: 
```
这是路径为go/src/image/gif/writer_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gif

import (
	"bytes"
	"image"
	"image/color"
	"image/color/palette"
	"image/draw"
	_ "image/png"
	"io"
	"math/rand"
	"os"
	"reflect"
	"testing"
)

func readImg(filename string) (image.Image, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, _, err := image.Decode(f)
	return m, err
}

func readGIF(filename string) (*GIF, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return DecodeAll(f)
}

func delta(u0, u1 uint32) int64 {
	d := int64(u0) - int64(u1)
	if d < 0 {
		return -d
	}
	return d
}

// averageDelta returns the average delta in RGB space. The two images must
// have the same bounds.
func averageDelta(m0, m1 image.Image) int64 {
	b := m0.Bounds()
	return averageDeltaBound(m0, m1, b, b)
}

// averageDeltaBound returns the average delta in RGB space. The average delta is
// calculated in the specified bounds.
func averageDeltaBound(m0, m1 image.Image, b0, b1 image.Rectangle) int64 {
	var sum, n int64
	for y := b0.Min.Y; y < b0.Max.Y; y++ {
		for x := b0.Min.X; x < b0.Max.X; x++ {
			c0 := m0.At(x, y)
			c1 := m1.At(x-b0.Min.X+b1.Min.X, y-b0.Min.Y+b1.Min.Y)
			r0, g0, b0, _ := c0.RGBA()
			r1, g1, b1, _ := c1.RGBA()
			sum += delta(r0, r1)
			sum += delta(g0, g1)
			sum += delta(b0, b1)
			n += 3
		}
	}
	return sum / n
}

// lzw.NewWriter wants an interface which is basically the same thing as gif's
// writer interface.  This ensures we're compatible.
var _ writer = blockWriter{}

var testCase = []struct {
	filename  string
	tolerance int64
}{
	{"../testdata/video-001.png", 1 << 12},
	{"../testdata/video-001.gif", 0},
	{"../testdata/video-001.interlaced.gif", 0},
}

func TestWriter(t *testing.T) {
	for _, tc := range testCase {
		m0, err := readImg(tc.filename)
		if err != nil {
			t.Error(tc.filename, err)
			continue
		}
		var buf bytes.Buffer
		err = Encode(&buf, m0, nil)
		if err != nil {
			t.Error(tc.filename, err)
			continue
		}
		m1, err := Decode(&buf)
		if err != nil {
			t.Error(tc.filename, err)
			continue
		}
		if m0.Bounds() != m1.Bounds() {
			t.Errorf("%s, bounds differ: %v and %v", tc.filename, m0.Bounds(), m1.Bounds())
			continue
		}
		// Compare the average delta to the tolerance level.
		avgDelta := averageDelta(m0, m1)
		if avgDelta > tc.tolerance {
			t.Errorf("%s: average delta is too high. expected: %d, got %d", tc.filename, tc.tolerance, avgDelta)
			continue
		}
	}
}

func TestSubImage(t *testing.T) {
	m0, err := readImg("../testdata/video-001.gif")
	if err != nil {
		t.Fatalf("readImg: %v", err)
	}
	m0 = m0.(*image.Paletted).SubImage(image.Rect(0, 0, 50, 30))
	var buf bytes.Buffer
	err = Encode(&buf, m0, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	m1, err := Decode(&buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if m0.Bounds() != m1.Bounds() {
		t.Fatalf("bounds differ: %v and %v", m0.Bounds(), m1.Bounds())
	}
	if averageDelta(m0, m1) != 0 {
		t.Fatalf("images differ")
	}
}

// palettesEqual reports whether two color.Palette values are equal, ignoring
// any trailing opaque-black palette entries.
func palettesEqual(p, q color.Palette) bool {
	n := len(p)
	if n > len(q) {
		n = len(q)
	}
	for i := 0; i < n; i++ {
		if p[i] != q[i] {
			return false
		}
	}
	for i := n; i < len(p); i++ {
		r, g, b, a := p[i].RGBA()
		if r != 0 || g != 0 || b != 0 || a != 0xffff {
			return false
		}
	}
	for i := n; i < len(q); i++ {
		r, g, b, a := q[i].RGBA()
		if r != 0 || g != 0 || b != 0 || a != 0xffff {
			return false
		}
	}
	return true
}

var frames = []string{
	"../testdata/video-001.gif",
	"../testdata/video-005.gray.gif",
}

func testEncodeAll(t *testing.T, go1Dot5Fields bool, useGlobalColorModel bool) {
	const width, height = 150, 103

	g0 := &GIF{
		Image:     make([]*image.Paletted, len(frames)),
		Delay:     make([]int, len(frames)),
		LoopCount: 5,
	}
	for i, f := range frames {
		g, err := readGIF(f)
		if err != nil {
			t.Fatal(f, err)
		}
		m := g.Image[0]
		if m.Bounds().Dx() != width || m.Bounds().Dy() != height {
			t.Fatalf("frame %d had unexpected bounds: got %v, want width/height = %d/%d",
				i, m.Bounds(), width, height)
		}
		g0.Image[i] = m
	}
	// The GIF.Disposal, GIF.Config and GIF.BackgroundIndex fields were added
	// in Go 1.5. Valid Go 1.4 or earlier code should still produce valid GIFs.
	//
	// On the following line, color.Model is an interface type, and
	// color.Palette is a concrete (slice) type.
	globalColorModel, backgroundIndex := color.Model(color.Palette(nil)), uint8(0)
	if useGlobalColorModel {
		globalColorModel, backgroundIndex = color.Palette(palette.WebSafe), uint8(1)
	}
	if go1Dot5Fields {
		g0.Disposal = make([]byte, len(g0.Image))
		for i := range g0.Disposal {
			g0.Disposal[i] = DisposalNone
		}
		g0.Config = image.Config{
			ColorModel: globalColorModel,
			Width:      width,
			Height:     height,
		}
		g0.BackgroundIndex = backgroundIndex
	}

	var buf bytes.Buffer
	if err := EncodeAll(&buf, g0); err != nil {
		t.Fatal("EncodeAll:", err)
	}
	encoded := buf.Bytes()
	config, err := DecodeConfig(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal("DecodeConfig:", err)
	}
	g1, err := DecodeAll(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal("DecodeAll:", err)
	}

	if !reflect.DeepEqual(config, g1.Config) {
		t.Errorf("DecodeConfig inconsistent with DecodeAll")
	}
	if !palettesEqual(g1.Config.ColorModel.(color.Palette), globalColorModel.(color.Palette)) {
		t.Errorf("unexpected global color model")
	}
	if w, h := g1.Config.Width, g1.Config.Height; w != width || h != height {
		t.Errorf("got config width * height = %d * %d, want %d * %d", w, h, width, height)
	}

	if g0.LoopCount != g1.LoopCount {
		t.Errorf("loop counts differ: %d and %d", g0.LoopCount, g1.LoopCount)
	}
	if backgroundIndex != g1.BackgroundIndex {
		t.Errorf("background indexes differ: %d and %d", backgroundIndex, g1.BackgroundIndex)
	}
	if len(g0.Image) != len(g1.Image) {
		t.Fatalf("image lengths differ: %d and %d", len(g0.Image), len(g1.Image))
	}
	if len(g1.Image) != len(g1.Delay) {
		t.Fatalf("image and delay lengths differ: %d and %d", len(g1.Image), len(g1.Delay))
	}
	if len(g1.Image) != len(g1.Disposal) {
		t.Fatalf("image and disposal lengths differ: %d and %d", len(g1.Image), len(g1.Disposal))
	}

	for i := range g0.Image {
		m0, m1 := g0.Image[i], g1.Image[i]
		if m0.Bounds() != m1.Bounds() {
			t.Errorf("frame %d: bounds differ: %v and %v", i, m0.Bounds(), m1.Bounds())
		}
		d0, d1 := g0.Delay[i], g1.Delay[i]
		if d0 != d1 {
			t.Errorf("frame %d: delay values differ: %d and %d", i, d0, d1)
		}
		p0, p1 := uint8(0), g1.Disposal[i]
		if go1Dot5Fields {
			p0 = DisposalNone
		}
		if p0 != p1 {
			t.Errorf("frame %d: disposal values differ: %d and %d", i, p0, p1)
		}
	}
}

func TestEncodeAllGo1Dot4(t *testing.T)                 { testEncodeAll(t, false, false) }
func TestEncodeAllGo1Dot5(t *testing.T)                 { testEncodeAll(t, true, false) }
func TestEncodeAllGo1Dot5GlobalColorModel(t *testing.T) { testEncodeAll(t, true, true) }

func TestEncodeMismatchDelay(t *testing.T) {
	images := make([]*image.Paletted, 2)
	for i := range images {
		images[i] = image.NewPaletted(image.Rect(0, 0, 5, 5), palette.Plan9)
	}

	g0 := &GIF{
		Image: images,
		Delay: make([]int, 1),
	}
	if err := EncodeAll(io.Discard, g0); err == nil {
		t.Error("expected error from mismatched delay and image slice lengths")
	}

	g1 := &GIF{
		Image:    images,
		Delay:    make([]int, len(images)),
		Disposal: make([]byte, 1),
	}
	for i := range g1.Disposal {
		g1.Disposal[i] = DisposalNone
	}
	if err := EncodeAll(io.Discard, g1); err == nil {
		t.Error("expected error from mismatched disposal and image slice lengths")
	}
}

func TestEncodeZeroGIF(t *testing.T) {
	if err := EncodeAll(io.Discard, &GIF{}); err == nil {
		t.Error("expected error from providing empty gif")
	}
}

func TestEncodeAllFramesOutOfBounds(t *testing.T) {
	images := []*image.Paletted{
		image.NewPaletted(image.Rect(0, 0, 5, 5), palette.Plan9),
		image.NewPaletted(image.Rect(2, 2, 8, 8), palette.Plan9),
		image.NewPaletted(image.Rect(3, 3, 4, 4), palette.Plan9),
	}
	for _, upperBound := range []int{6, 10} {
		g := &GIF{
			Image:    images,
			Delay:    make([]int, len(images)),
			Disposal: make([]byte, len(images)),
			Config: image.Config{
				Width:  upperBound,
				Height: upperBound,
			},
		}
		err := EncodeAll(io.Discard, g)
		if upperBound >= 8 {
			if err != nil {
				t.Errorf("upperBound=%d: %v", upperBound, err)
			}
		} else {
			if err == nil {
				t.Errorf("upperBound=%d: got nil error, want non-nil", upperBound)
			}
		}
	}
}

func TestEncodeNonZeroMinPoint(t *testing.T) {
	points := []image.Point{
		{-8, -9},
		{-4, -4},
		{-3, +3},
		{+0, +0},
		{+2, +2},
	}
	for _, p := range points {
		src := image.NewPaletted(image.Rectangle{
			Min: p,
			Max: p.Add(image.Point{6, 6}),
		}, palette.Plan9)
		var buf bytes.Buffer
		if err := Encode(&buf, src, nil); err != nil {
			t.Errorf("p=%v: Encode: %v", p, err)
			continue
		}
		m, err := Decode(&buf)
		if err != nil {
			t.Errorf("p=%v: Decode: %v", p, err)
			continue
		}
		if got, want := m.Bounds(), image.Rect(0, 0, 6, 6); got != want {
			t.Errorf("p=%v: got %v, want %v", p, got, want)
		}
	}

	// Also test having a source image (gray on the diagonal) that has a
	// non-zero Bounds().Min, but isn't an image.Paletted.
	{
		p := image.Point{+2, +2}
		src := image.NewRGBA(image.Rectangle{
			Min: p,
			Max: p.Add(image.Point{6, 6}),
		})
		src.SetRGBA(2, 2, color.RGBA{0x22, 0x22, 0x22, 0xFF})
		src.SetRGBA(3, 3, color.RGBA{0x33, 0x33, 0x33, 0xFF})
		src.SetRGBA(4, 4, color.RGBA{0x44, 0x44, 0x44, 0xFF})
		src.SetRGBA(5, 5, color.RGBA{0x55, 0x55, 0x55, 0xFF})
		src.SetRGBA(6, 6, color.RGBA{0x66, 0x66, 0x66, 0xFF})
		src.SetRGBA(7, 7, color.RGBA{0x77, 0x77, 0x77, 0xFF})

		var buf bytes.Buffer
		if err := Encode(&buf, src, nil); err != nil {
			t.Errorf("gray-diagonal: Encode: %v", err)
			return
		}
		m, err := Decode(&buf)
		if err != nil {
			t.Errorf("gray-diagonal: Decode: %v", err)
			return
		}
		if got, want := m.Bounds(), image.Rect(0, 0, 6, 6); got != want {
			t.Errorf("gray-diagonal: got %v, want %v", got, want)
			return
		}

		rednessAt := func(x int, y int) uint32 {
			r, _, _, _ := m.At(x, y).RGBA()
			// Shift by 8 to convert from 16 bit color to 8 bit color.
			return r >> 8
		}

		// Round-tripping a still (non-animated) image.Image through
		// Encode+Decode should shift the origin to (0, 0).
		if got, want := rednessAt(0, 0), uint32(0x22); got != want {
			t.Errorf("gray-diagonal: rednessAt(0, 0): got 0x%02x, want 0x%02x", got, want)
		}
		if got, want := rednessAt(5, 5), uint32(0x77); got != want {
			t.Errorf("gray-diagonal: rednessAt(5, 5): got 0x%02x, want 0x%02x", got, want)
		}
	}
}

func TestEncodeImplicitConfigSize(t *testing.T) {
	// For backwards compatibility for Go 1.4 and earlier code, the Config
	// field is optional, and if zero, the width and height is implied by the
	// first (and in this case only) frame's width and height.
	//
	// A Config only specifies a width and height (two integers) while an
	// image.Image's Bounds method returns an image.Rectangle (four integers).
	// For a gif.GIF, the overall bounds' top-left point is always implicitly
	// (0, 0), and any frame whose bounds have a negative X or Y will be
	// outside those overall bounds, so encoding should fail.
	for _, lowerBound := range []int{-1, 0, 1} {
		images := []*image.Paletted{
			image.NewPaletted(image.Rect(lowerBound, lowerBound, 4, 4), palette.Plan9),
		}
		g := &GIF{
			Image: images,
			Delay: make([]int, len(images)),
		}
		err := EncodeAll(io.Discard, g)
		if lowerBound >= 0 {
			if err != nil {
				t.Errorf("lowerBound=%d: %v", lowerBound, err)
			}
		} else {
			if err == nil {
				t.Errorf("lowerBound=%d: got nil error, want non-nil", lowerBound)
			}
		}
	}
}

func TestEncodePalettes(t *testing.T) {
	const w, h = 5, 5
	pals := []color.Palette{{
		color.RGBA{0x00, 0x00, 0x00, 0xff},
		color.RGBA{0x01, 0x00, 0x00, 0xff},
		color.RGBA{0x02, 0x00, 0x00, 0xff},
	}, {
		color.RGBA{0x00, 0x00, 0x00, 0xff},
		color.RGBA{0x00, 0x01, 0x00, 0xff},
	}, {
		color.RGBA{0x00, 0x00, 0x03, 0xff},
		color.RGBA{0x00, 0x00, 0x02, 0xff},
		color.RGBA{0x00, 0x00, 0x01, 0xff},
		color.RGBA{0x00, 0x00, 0x00, 0xff},
	}, {
		color.RGBA{0x10, 0x07, 0xf0, 0xff},
		color.RGBA{0x20, 0x07, 0xf0, 0xff},
		color.RGBA{0x30, 0x07, 0xf0, 0xff},
		color.RGBA{0x40, 0x07, 0xf0, 0xff},
		color.RGBA{0x50, 0x07, 0xf0, 0xff},
	}}
	g0 := &GIF{
		Image: []*image.Paletted{
			image.NewPaletted(image.Rect(0, 0, w, h), pals[0]),
			image.NewPaletted(image.Rect(0, 0, w, h), pals[1]),
			image.NewPaletted(image.Rect(0, 0, w, h), pals[2]),
			image.NewPaletted(image.Rect(0, 0, w, h), pals[3]),
		},
		Delay:    make([]int, len(pals)),
		Disposal: make([]byte, len(pals)),
		Config: image.Config{
			ColorModel: pals[2],
			Width:      w,
			Height:     h,
		},
	}

	var buf bytes.Buffer
	if err := EncodeAll(&buf, g0); err != nil {
		t.Fatalf("EncodeAll: %v", err)
	}
	g1, err := DecodeAll(&buf)
	if err != nil {
		t.Fatalf("DecodeAll: %v", err)
	}
	if len(g0.Image) != len(g1.Image) {
		t.Fatalf("image lengths differ: %d and %d", len(g0.Image), len(g1.Image))
	}
	for i, m := range g1.Image {
		if got, want := m.Palette, pals[i]; !palettesEqual(got, want) {
			t.Errorf("frame %d:\ngot  %v\nwant %v", i, got, want)
		}
	}
}

func TestEncodeBadPalettes(t *testing.T) {
	const w, h = 5, 5
	for _, n := range []int{256, 257} {
		for _, nilColors := range []bool{false, true} {
			pal := make(color.Palette, n)
			if !nilColors {
				for i := range pal {
					pal[i] = color.Black
				}
			}

			err := EncodeAll(io.Discard, &GIF{
				Image: []*image.Paletted{
					image.NewPaletted(image.Rect(0, 0, w, h), pal),
				},
				Delay:    make([]int, 1),
				Disposal: make([]byte, 1),
				Config: image.Config{
					ColorModel: pal,
					Width:      w,
					Height:     h,
				},
			})

			got := err != nil
			want := n > 256 || nilColors
			if got != want {
				t.Errorf("n=%d, nilColors=%t: err != nil: got %t, want %t", n, nilColors, got, want)
			}
		}
	}
}

func TestColorTablesMatch(t *testing.T) {
	const trIdx = 100
	global := color.Palette(palette.Plan9)
	if rgb := global[trIdx].(color.RGBA); rgb.R == 0 && rgb.G == 0 && rgb.B == 0 {
		t.Fatalf("trIdx (%d) is already black", trIdx)
	}

	// Make a copy of the palette, substituting trIdx's slot with transparent,
	// just like decoder.decode.
	local := append(color.Palette(nil), global...)
	local[trIdx] = color.RGBA{}

	const testLen = 3 * 256
	const padded = 7
	e := new(encoder)
	if l, err := encodeColorTable(e.globalColorTable[:], global, padded); err != nil || l != testLen {
		t.Fatalf("Failed to encode global color table: got %d, %v; want nil, %d", l, err, testLen)
	}
	if l, err := encodeColorTable(e.localColorTable[:], local, padded); err != nil || l != testLen {
		t.Fatalf("Failed to encode local color table: got %d, %v; want nil, %d", l, err, testLen)
	}
	if bytes.Equal(e.globalColorTable[:testLen], e.localColorTable[:testLen]) {
		t.Fatal("Encoded color tables are equal, expected mismatch")
	}
	if !e.colorTablesMatch(len(local), trIdx) {
		t.Fatal("colorTablesMatch() == false, expected true")
	}
}

func TestEncodeCroppedSubImages(t *testing.T) {
	// This test means to ensure that Encode honors the Bounds and Strides of
	// images correctly when encoding.
	whole := image.NewPaletted(image.Rect(0, 0, 100, 100), palette.Plan9)
	subImages := []image.Rectangle{
		image.Rect(0, 0, 50, 50),
		image.Rect(50, 0, 100, 50),
		image.Rect(0, 50, 50, 50),
		image.Rect(50, 50, 100, 100),
		image.Rect(25, 25, 75, 75),
		image.Rect(0, 0, 100, 50),
		image.Rect(0, 50, 100, 100),
		image.Rect(0, 0, 50, 100),
		image.Rect(50, 0, 100, 100),
	}
	for _, sr := range subImages {
		si := whole.SubImage(sr)
		buf := bytes.NewBuffer(nil)
		if err := Encode(buf, si, nil); err != nil {
			t.Errorf("Encode: sr=%v: %v", sr, err)
			continue
		}
		if _, err := Decode(buf); err != nil {
			t.Errorf("Decode: sr=%v: %v", sr, err)
		}
	}
}

type offsetImage struct {
	image.Image
	Rect image.Rectangle
}

func (i offsetImage) Bounds() image.Rectangle {
	return i.Rect
}

func TestEncodeWrappedImage(t *testing.T) {
	m0, err := readImg("../testdata/video-001.gif")
	if err != nil {
		t.Fatalf("readImg: %v", err)
	}

	// Case 1: Encode a wrapped image.Image
	buf := new(bytes.Buffer)
	w0 := offsetImage{m0, m0.Bounds()}
	err = Encode(buf, w0, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	w1, err := Decode(buf)
	if err != nil {
		t.Fatalf("Dencode: %v", err)
	}
	avgDelta := averageDelta(m0, w1)
	if avgDelta > 0 {
		t.Fatalf("Wrapped: average delta is too high. expected: 0, got %d", avgDelta)
	}

	// Case 2: Encode a wrapped image.Image with offset
	b0 := image.Rectangle{
		Min: image.Point{
			X: 128,
			Y: 64,
		},
		Max: image.Point{
			X: 256,
			Y: 128,
		},
	}
	w0 = offsetImage{m0, b0}
	buf = new(bytes.Buffer)
	err = Encode(buf, w0, nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	w1, err = Decode(buf)
	if err != nil {
		t.Fatalf("Dencode: %v", err)
	}

	b1 := image.Rectangle{
		Min: image.Point{
			X: 0,
			Y: 0,
		},
		Max: image.Point{
			X: 128,
			Y: 64,
		},
	}
	avgDelta = averageDeltaBound(m0, w1, b0, b1)
	if avgDelta > 0 {
		t.Fatalf("Wrapped and offset: average delta is too high. expected: 0, got %d", avgDelta)
	}
}

func BenchmarkEncodeRandomPaletted(b *testing.B) {
	paletted := image.NewPaletted(image.Rect(0, 0, 640, 480), palette.Plan9)
	rnd := rand.New(rand.NewSource(123))
	for i := range paletted.Pix {
		paletted.Pix[i] = uint8(rnd.Intn(256))
	}

	b.SetBytes(640 * 480 * 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(io.Discard, paletted, nil)
	}
}

func BenchmarkEncodeRandomRGBA(b *testing.B) {
	rgba := image.NewRGBA(image.Rect(0, 0, 640, 480))
	bo := rgba.Bounds()
	rnd := rand.New(rand.NewSource(123))
	for y := bo.Min.Y; y < bo.Max.Y; y++ {
		for x := bo.Min.X; x < bo.Max.X; x++ {
			rgba.SetRGBA(x, y, color.RGBA{
				uint8(rnd.Intn(256)),
				uint8(rnd.Intn(256)),
				uint8(rnd.Intn(256)),
				255,
			})
		}
	}

	b.SetBytes(640 * 480 * 4)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(io.Discard, rgba, nil)
	}
}

func BenchmarkEncodeRealisticPaletted(b *testing.B) {
	img, err := readImg("../testdata/video-001.png")
	if err != nil {
		b.Fatalf("readImg: %v", err)
	}
	bo := img.Bounds()
	paletted := image.NewPaletted(bo, palette.Plan9)
	draw.Draw(paletted, bo, img, bo.Min, draw.Src)

	b.SetBytes(int64(bo.Dx() * bo.Dy() * 1))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(io.Discard, paletted, nil)
	}
}

func BenchmarkEncodeRealisticRGBA(b *testing.B) {
	img, err := readImg("../testdata/video-001.png")
	if err != nil {
		b.Fatalf("readImg: %v", err)
	}
	bo := img.Bounds()
	// Converting img to rgba is redundant for video-001.png, which is already
	// in the RGBA format, but for those copy/pasting this benchmark (but
	// changing the source image), the conversion ensures that we're still
	// benchmarking encoding an RGBA image.
	rgba := image.NewRGBA(bo)
	draw.Draw(rgba, bo, img, bo.Min, draw.Src)

	b.SetBytes(int64(bo.Dx() * bo.Dy() * 4))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(io.Discard, rgba, nil)
	}
}

"""



```