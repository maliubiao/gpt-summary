Response:
Let's break down the thought process for answering the request about `palette.go`.

**1. Understanding the Goal:** The core request is to analyze the provided Go code snippet for `palette.go` and explain its functionality, underlying Go concepts, provide examples, and highlight potential pitfalls.

**2. Initial Code Scan & High-Level Functionality:**  A quick read reveals:
    * The package name is `palette`.
    * It imports `image/color`.
    * There are two main exported variables: `Plan9` and `WebSafe`.
    * Both `Plan9` and `WebSafe` are slices of `color.Color`.
    * The comments describe these as color palettes. `Plan9` is a 256-color palette, and `WebSafe` is a 216-color palette.
    * The `Plan9` comment mentions partitioning the RGB space and increasing intensity resolution.
    * The `WebSafe` comment links to the concept of "web-safe colors."
    * There's a comment indicating the file is code-generated.

**3. Identifying the Core Go Concept:**  The key concept here is **predefined color palettes**. The code isn't implementing the *creation* of palettes; it's providing *existing* palettes. This leads to the idea that these palettes can be used to map arbitrary colors to the closest color within the defined set.

**4. Inferring the Use Case:**  If these are predefined palettes, they're likely used in situations where you need to restrict the color space, such as:
    * **Older display systems:** Where the hardware couldn't handle a full range of colors.
    * **Image optimization:** Reducing the number of colors in an image to decrease file size.
    * **Specific artistic styles:** Mimicking the look of older systems.

**5. Developing the Go Code Example:** To demonstrate the functionality, I need to show how these palettes are used. The `color.Palette` type is the relevant interface. A basic example would involve:
    * Creating a `color.Palette` from one of the predefined slices.
    * Defining an arbitrary `color.Color`.
    * Using the `Convert` method of the `color.Palette` to find the closest color in the palette.

    *Initial Thought (Slightly Incorrect):*  I might initially think you can directly use `Plan9` or `WebSafe` as a `color.Palette`. However, a closer look at the `image/color` package documentation (or experimentation) reveals that `Plan9` and `WebSafe` are `[]color.Color`, not `color.Palette`. You need to explicitly *cast* or convert them. The most straightforward way is to create a `color.Palette` type directly.

    *Corrected Approach (Leading to the example code):*
    ```go
    package main

    import (
        "fmt"
        "image/color"
        "image/color/palette"
    )

    func main() {
        // Using the Plan9 palette
        p := color.Palette(palette.Plan9)
        c := color.RGBA{R: 100, G: 150, B: 200, A: 255}
        convertedColor := p.Convert(c)
        fmt.Printf("Original color: %v, Converted color (Plan9): %v\n", c, convertedColor)

        // Using the WebSafe palette
        webSafePalette := color.Palette(palette.WebSafe)
        convertedWebSafe := webSafePalette.Convert(c)
        fmt.Printf("Original color: %v, Converted color (WebSafe): %v\n", c, convertedWebSafe)
    }
    ```

**6. Reasoning about Go Language Features:**  The code directly utilizes:
    * **Packages and Imports:**  `package palette` and `import "image/color"`.
    * **Exported Variables:** `Plan9` and `WebSafe` (starting with capital letters).
    * **Slices:** `[]color.Color`.
    * **Structs:** `color.RGBA`.
    * **Code Generation:**  The `// Code generated by...` comment. This is important to note because it means manual edits to the file will be overwritten.

**7. Considering Command-Line Arguments:**  The provided code snippet doesn't handle any command-line arguments. The `gen.go` mentioned in the comment likely handles that, but it's not part of the given code. So, the answer should state that there's no command-line argument processing within this specific file.

**8. Identifying Potential Pitfalls:**  The main pitfall is misunderstanding how these palettes are used. Users might try to:
    * **Directly manipulate the palette slices:** Since they are exported, someone might try to modify `Plan9` or `WebSafe`. However, since they are usually used for conversion, direct manipulation is less common and might lead to unexpected behavior if the intent is to use a *fixed* palette.
    * **Assume they are `color.Palette`:** Forgetting to explicitly create a `color.Palette` type from the slices.
    * **Expect perfect color matching:**  Understanding that converting a color to a palette will result in the *closest* color, not necessarily an exact match.

    *Developing the Pitfall Example:*
    ```go
    package main

    import (
        "fmt"
        "image/color"
        "image/color/palette"
    )

    func main() {
        // Incorrect assumption: Directly using Plan9 for conversion (will not compile directly)
        // var p color.Palette = palette.Plan9 // This will cause a type mismatch error

        // Correct way: Creating a color.Palette
        p := color.Palette(palette.Plan9)
        c := color.RGBA{R: 120, G: 120, B: 120, A: 255}
        converted := p.Convert(c)
        fmt.Printf("Original: %v, Converted: %v\n", c, converted)

        // Demonstrating the "closest color" concept
        c2 := color.RGBA{R: 121, G: 121, B: 121, A: 255} // Slightly different color
        converted2 := p.Convert(c2)
        fmt.Printf("Original: %v, Converted: %v\n", c2, converted2)
        // converted and converted2 might be the same color from the palette
    }
    ```

**9. Structuring the Answer:**  Finally, organize the information logically:
    * Start with a clear summary of the file's function.
    * Explain the underlying Go concept of predefined color palettes.
    * Provide a Go code example demonstrating usage, including input and output.
    * Detail the Go language features used.
    * Explain the lack of command-line arguments.
    * Describe potential user errors with illustrative examples.
    * Ensure the language used is clear and concise, as requested ("用中文回答").

By following this structured approach, I can comprehensively address all aspects of the prompt and provide a helpful and accurate explanation of the `palette.go` code snippet.
这个 `go/src/image/color/palette/palette.go` 文件定义了两个预定义的颜色调色板：`Plan9` 和 `WebSafe`。

**功能列举:**

1. **定义了 `Plan9` 调色板:**  `Plan9` 是一个包含 256 种颜色的调色板。这个调色板的设计目标是在减少颜色分辨率的同时，增加强度分辨率。它将 24 位的 RGB 颜色空间划分为 4x4x4 的子立方体，每个子立方体包含 4 种深浅不同的颜色。这个调色板包含 16 种灰色阴影，以及每种原色和间色（红、绿、蓝、青、品红、黄）的 13 种色调。它最初用于 Plan 9 操作系统。
2. **定义了 `WebSafe` 调色板:** `WebSafe` 是一个包含 216 种颜色的调色板。这个调色板在早期版本的 Netscape Navigator 浏览器中流行起来，也被称为 Netscape Color Cube。它的设计目的是确保在不同的显示器和操作系统上颜色显示的一致性。

**Go 语言功能的实现：预定义的常量切片**

这个文件主要利用 Go 语言的**常量切片 (constant slice)** 功能来定义这些调色板。`Plan9` 和 `WebSafe` 都是 `[]color.Color` 类型的常量。这意味着它们在编译时就已经确定，并且在运行时不能被修改。

**Go 代码举例说明:**

假设我们想使用 `Plan9` 调色板将一个任意的 RGB 颜色转换为调色板中最接近的颜色。Go 的 `image/color` 包提供了 `Palette` 类型和 `Convert` 方法来实现这个功能。

```go
package main

import (
	"fmt"
	"image/color"
	"image/color/palette"
)

func main() {
	// 使用 Plan9 调色板
	p := color.Palette(palette.Plan9)

	// 定义一个任意的 RGB 颜色
	c := color.RGBA{R: 100, G: 150, B: 200, A: 255}

	// 将该颜色转换为 Plan9 调色板中最接近的颜色
	convertedColor := p.Convert(c)

	fmt.Printf("原始颜色: %v, 转换后的颜色 (Plan9): %v\n", c, convertedColor)

	// 使用 WebSafe 调色板
	webSafePalette := color.Palette(palette.WebSafe)
	convertedWebSafe := webSafePalette.Convert(c)
	fmt.Printf("原始颜色: %v, 转换后的颜色 (WebSafe): %v\n", c, convertedWebSafe)
}
```

**假设的输入与输出:**

如果运行上面的代码，输出可能如下（实际输出取决于 `Convert` 方法的实现细节，即如何确定“最接近”的颜色）：

```
原始颜色: {100 150 200 255}, 转换后的颜色 (Plan9): {100 136 187 255}
原始颜色: {100 150 200 255}, 转换后的颜色 (WebSafe): {99 153 204 255}
```

在这个例子中，我们创建了一个 `color.Palette` 类型的变量 `p`，并将其初始化为 `palette.Plan9`。然后，我们定义了一个 `color.RGBA` 类型的颜色 `c`。最后，我们使用 `p.Convert(c)` 方法将 `c` 转换成 `Plan9` 调色板中最接近的颜色。`WebSafe` 的用法类似。

**代码推理:**

从代码中可以看出，`Plan9` 和 `WebSafe` 都是 `color.RGBA` 结构体的切片。`color.RGBA` 代表一个红、绿、蓝、透明度（Alpha）的颜色值。这些切片中的每个元素都定义了调色板中的一个具体颜色。

注释中提到了 `// Code generated by go run gen.go -output palette.go; DO NOT EDIT.`，这说明这个 `palette.go` 文件是**代码生成的**。很可能存在一个 `gen.go` 文件，它负责生成 `Plan9` 和 `WebSafe` 这两个调色板的数据。这个生成过程可能涉及到读取一些预定义的数据或者通过算法计算出这些颜色值。

**命令行参数的具体处理:**

在这个 `palette.go` 文件中，**没有**涉及到任何命令行参数的处理。 命令行参数的处理通常会在 `main` 函数所在的 `main.go` 文件中进行，并使用 `os.Args` 或 `flag` 包来解析。  `palette.go` 只是定义了一些常量数据。

**使用者易犯错的点:**

一个常见的错误是 **直接使用 `palette.Plan9` 或 `palette.WebSafe` 作为 `color.Palette` 类型的值**。

例如，以下代码会产生编译错误：

```go
package main

import (
	"fmt"
	"image/color"
	"image/color/palette"
)

func main() {
	var p color.Palette = palette.Plan9 // 错误：类型不匹配
	c := color.RGBA{R: 100, G: 150, B: 200, A: 255}
	convertedColor := p.Convert(c)
	fmt.Println(convertedColor)
}
```

错误信息会提示类型不匹配，因为 `palette.Plan9` 的类型是 `[]color.Color`，而 `color.Palette` 是一个接口类型。

**正确的用法是将其转换为 `color.Palette` 类型:**

```go
package main

import (
	"fmt"
	"image/color"
	"image/color/palette"
)

func main() {
	p := color.Palette(palette.Plan9) // 正确：将 []color.Color 转换为 color.Palette
	c := color.RGBA{R: 100, G: 150, B: 200, A: 255}
	convertedColor := p.Convert(c)
	fmt.Println(convertedColor)
}
```

另一个需要注意的是，由于这些调色板是预定义的，**用户不能直接修改 `palette.Plan9` 或 `palette.WebSafe` 的内容**。尝试修改会导致编译错误，因为它们是常量切片。

总而言之，`palette.go` 文件的核心功能是提供了两个常用的、预定义的颜色调色板，方便 Go 语言程序在需要限制颜色范围或使用特定颜色集合时使用。它利用了 Go 语言的常量切片特性来存储这些颜色数据。

Prompt: 
```
这是路径为go/src/image/color/palette/palette.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by go run gen.go -output palette.go; DO NOT EDIT.

package palette

import "image/color"

// Plan9 is a 256-color palette that partitions the 24-bit RGB space
// into 4×4×4 subdivision, with 4 shades in each subcube. Compared to the
// [WebSafe], the idea is to reduce the color resolution by dicing the
// color cube into fewer cells, and to use the extra space to increase the
// intensity resolution. This results in 16 gray shades (4 gray subcubes with
// 4 samples in each), 13 shades of each primary and secondary color (3
// subcubes with 4 samples plus black) and a reasonable selection of colors
// covering the rest of the color cube. The advantage is better representation
// of continuous tones.
//
// This palette was used in the Plan 9 Operating System, described at
// https://9p.io/magic/man2html/6/color
var Plan9 = []color.Color{
	color.RGBA{0x00, 0x00, 0x00, 0xff},
	color.RGBA{0x00, 0x00, 0x44, 0xff},
	color.RGBA{0x00, 0x00, 0x88, 0xff},
	color.RGBA{0x00, 0x00, 0xcc, 0xff},
	color.RGBA{0x00, 0x44, 0x00, 0xff},
	color.RGBA{0x00, 0x44, 0x44, 0xff},
	color.RGBA{0x00, 0x44, 0x88, 0xff},
	color.RGBA{0x00, 0x44, 0xcc, 0xff},
	color.RGBA{0x00, 0x88, 0x00, 0xff},
	color.RGBA{0x00, 0x88, 0x44, 0xff},
	color.RGBA{0x00, 0x88, 0x88, 0xff},
	color.RGBA{0x00, 0x88, 0xcc, 0xff},
	color.RGBA{0x00, 0xcc, 0x00, 0xff},
	color.RGBA{0x00, 0xcc, 0x44, 0xff},
	color.RGBA{0x00, 0xcc, 0x88, 0xff},
	color.RGBA{0x00, 0xcc, 0xcc, 0xff},
	color.RGBA{0x00, 0xdd, 0xdd, 0xff},
	color.RGBA{0x11, 0x11, 0x11, 0xff},
	color.RGBA{0x00, 0x00, 0x55, 0xff},
	color.RGBA{0x00, 0x00, 0x99, 0xff},
	color.RGBA{0x00, 0x00, 0xdd, 0xff},
	color.RGBA{0x00, 0x55, 0x00, 0xff},
	color.RGBA{0x00, 0x55, 0x55, 0xff},
	color.RGBA{0x00, 0x4c, 0x99, 0xff},
	color.RGBA{0x00, 0x49, 0xdd, 0xff},
	color.RGBA{0x00, 0x99, 0x00, 0xff},
	color.RGBA{0x00, 0x99, 0x4c, 0xff},
	color.RGBA{0x00, 0x99, 0x99, 0xff},
	color.RGBA{0x00, 0x93, 0xdd, 0xff},
	color.RGBA{0x00, 0xdd, 0x00, 0xff},
	color.RGBA{0x00, 0xdd, 0x49, 0xff},
	color.RGBA{0x00, 0xdd, 0x93, 0xff},
	color.RGBA{0x00, 0xee, 0x9e, 0xff},
	color.RGBA{0x00, 0xee, 0xee, 0xff},
	color.RGBA{0x22, 0x22, 0x22, 0xff},
	color.RGBA{0x00, 0x00, 0x66, 0xff},
	color.RGBA{0x00, 0x00, 0xaa, 0xff},
	color.RGBA{0x00, 0x00, 0xee, 0xff},
	color.RGBA{0x00, 0x66, 0x00, 0xff},
	color.RGBA{0x00, 0x66, 0x66, 0xff},
	color.RGBA{0x00, 0x55, 0xaa, 0xff},
	color.RGBA{0x00, 0x4f, 0xee, 0xff},
	color.RGBA{0x00, 0xaa, 0x00, 0xff},
	color.RGBA{0x00, 0xaa, 0x55, 0xff},
	color.RGBA{0x00, 0xaa, 0xaa, 0xff},
	color.RGBA{0x00, 0x9e, 0xee, 0xff},
	color.RGBA{0x00, 0xee, 0x00, 0xff},
	color.RGBA{0x00, 0xee, 0x4f, 0xff},
	color.RGBA{0x00, 0xff, 0x55, 0xff},
	color.RGBA{0x00, 0xff, 0xaa, 0xff},
	color.RGBA{0x00, 0xff, 0xff, 0xff},
	color.RGBA{0x33, 0x33, 0x33, 0xff},
	color.RGBA{0x00, 0x00, 0x77, 0xff},
	color.RGBA{0x00, 0x00, 0xbb, 0xff},
	color.RGBA{0x00, 0x00, 0xff, 0xff},
	color.RGBA{0x00, 0x77, 0x00, 0xff},
	color.RGBA{0x00, 0x77, 0x77, 0xff},
	color.RGBA{0x00, 0x5d, 0xbb, 0xff},
	color.RGBA{0x00, 0x55, 0xff, 0xff},
	color.RGBA{0x00, 0xbb, 0x00, 0xff},
	color.RGBA{0x00, 0xbb, 0x5d, 0xff},
	color.RGBA{0x00, 0xbb, 0xbb, 0xff},
	color.RGBA{0x00, 0xaa, 0xff, 0xff},
	color.RGBA{0x00, 0xff, 0x00, 0xff},
	color.RGBA{0x44, 0x00, 0x44, 0xff},
	color.RGBA{0x44, 0x00, 0x88, 0xff},
	color.RGBA{0x44, 0x00, 0xcc, 0xff},
	color.RGBA{0x44, 0x44, 0x00, 0xff},
	color.RGBA{0x44, 0x44, 0x44, 0xff},
	color.RGBA{0x44, 0x44, 0x88, 0xff},
	color.RGBA{0x44, 0x44, 0xcc, 0xff},
	color.RGBA{0x44, 0x88, 0x00, 0xff},
	color.RGBA{0x44, 0x88, 0x44, 0xff},
	color.RGBA{0x44, 0x88, 0x88, 0xff},
	color.RGBA{0x44, 0x88, 0xcc, 0xff},
	color.RGBA{0x44, 0xcc, 0x00, 0xff},
	color.RGBA{0x44, 0xcc, 0x44, 0xff},
	color.RGBA{0x44, 0xcc, 0x88, 0xff},
	color.RGBA{0x44, 0xcc, 0xcc, 0xff},
	color.RGBA{0x44, 0x00, 0x00, 0xff},
	color.RGBA{0x55, 0x00, 0x00, 0xff},
	color.RGBA{0x55, 0x00, 0x55, 0xff},
	color.RGBA{0x4c, 0x00, 0x99, 0xff},
	color.RGBA{0x49, 0x00, 0xdd, 0xff},
	color.RGBA{0x55, 0x55, 0x00, 0xff},
	color.RGBA{0x55, 0x55, 0x55, 0xff},
	color.RGBA{0x4c, 0x4c, 0x99, 0xff},
	color.RGBA{0x49, 0x49, 0xdd, 0xff},
	color.RGBA{0x4c, 0x99, 0x00, 0xff},
	color.RGBA{0x4c, 0x99, 0x4c, 0xff},
	color.RGBA{0x4c, 0x99, 0x99, 0xff},
	color.RGBA{0x49, 0x93, 0xdd, 0xff},
	color.RGBA{0x49, 0xdd, 0x00, 0xff},
	color.RGBA{0x49, 0xdd, 0x49, 0xff},
	color.RGBA{0x49, 0xdd, 0x93, 0xff},
	color.RGBA{0x49, 0xdd, 0xdd, 0xff},
	color.RGBA{0x4f, 0xee, 0xee, 0xff},
	color.RGBA{0x66, 0x00, 0x00, 0xff},
	color.RGBA{0x66, 0x00, 0x66, 0xff},
	color.RGBA{0x55, 0x00, 0xaa, 0xff},
	color.RGBA{0x4f, 0x00, 0xee, 0xff},
	color.RGBA{0x66, 0x66, 0x00, 0xff},
	color.RGBA{0x66, 0x66, 0x66, 0xff},
	color.RGBA{0x55, 0x55, 0xaa, 0xff},
	color.RGBA{0x4f, 0x4f, 0xee, 0xff},
	color.RGBA{0x55, 0xaa, 0x00, 0xff},
	color.RGBA{0x55, 0xaa, 0x55, 0xff},
	color.RGBA{0x55, 0xaa, 0xaa, 0xff},
	color.RGBA{0x4f, 0x9e, 0xee, 0xff},
	color.RGBA{0x4f, 0xee, 0x00, 0xff},
	color.RGBA{0x4f, 0xee, 0x4f, 0xff},
	color.RGBA{0x4f, 0xee, 0x9e, 0xff},
	color.RGBA{0x55, 0xff, 0xaa, 0xff},
	color.RGBA{0x55, 0xff, 0xff, 0xff},
	color.RGBA{0x77, 0x00, 0x00, 0xff},
	color.RGBA{0x77, 0x00, 0x77, 0xff},
	color.RGBA{0x5d, 0x00, 0xbb, 0xff},
	color.RGBA{0x55, 0x00, 0xff, 0xff},
	color.RGBA{0x77, 0x77, 0x00, 0xff},
	color.RGBA{0x77, 0x77, 0x77, 0xff},
	color.RGBA{0x5d, 0x5d, 0xbb, 0xff},
	color.RGBA{0x55, 0x55, 0xff, 0xff},
	color.RGBA{0x5d, 0xbb, 0x00, 0xff},
	color.RGBA{0x5d, 0xbb, 0x5d, 0xff},
	color.RGBA{0x5d, 0xbb, 0xbb, 0xff},
	color.RGBA{0x55, 0xaa, 0xff, 0xff},
	color.RGBA{0x55, 0xff, 0x00, 0xff},
	color.RGBA{0x55, 0xff, 0x55, 0xff},
	color.RGBA{0x88, 0x00, 0x88, 0xff},
	color.RGBA{0x88, 0x00, 0xcc, 0xff},
	color.RGBA{0x88, 0x44, 0x00, 0xff},
	color.RGBA{0x88, 0x44, 0x44, 0xff},
	color.RGBA{0x88, 0x44, 0x88, 0xff},
	color.RGBA{0x88, 0x44, 0xcc, 0xff},
	color.RGBA{0x88, 0x88, 0x00, 0xff},
	color.RGBA{0x88, 0x88, 0x44, 0xff},
	color.RGBA{0x88, 0x88, 0x88, 0xff},
	color.RGBA{0x88, 0x88, 0xcc, 0xff},
	color.RGBA{0x88, 0xcc, 0x00, 0xff},
	color.RGBA{0x88, 0xcc, 0x44, 0xff},
	color.RGBA{0x88, 0xcc, 0x88, 0xff},
	color.RGBA{0x88, 0xcc, 0xcc, 0xff},
	color.RGBA{0x88, 0x00, 0x00, 0xff},
	color.RGBA{0x88, 0x00, 0x44, 0xff},
	color.RGBA{0x99, 0x00, 0x4c, 0xff},
	color.RGBA{0x99, 0x00, 0x99, 0xff},
	color.RGBA{0x93, 0x00, 0xdd, 0xff},
	color.RGBA{0x99, 0x4c, 0x00, 0xff},
	color.RGBA{0x99, 0x4c, 0x4c, 0xff},
	color.RGBA{0x99, 0x4c, 0x99, 0xff},
	color.RGBA{0x93, 0x49, 0xdd, 0xff},
	color.RGBA{0x99, 0x99, 0x00, 0xff},
	color.RGBA{0x99, 0x99, 0x4c, 0xff},
	color.RGBA{0x99, 0x99, 0x99, 0xff},
	color.RGBA{0x93, 0x93, 0xdd, 0xff},
	color.RGBA{0x93, 0xdd, 0x00, 0xff},
	color.RGBA{0x93, 0xdd, 0x49, 0xff},
	color.RGBA{0x93, 0xdd, 0x93, 0xff},
	color.RGBA{0x93, 0xdd, 0xdd, 0xff},
	color.RGBA{0x99, 0x00, 0x00, 0xff},
	color.RGBA{0xaa, 0x00, 0x00, 0xff},
	color.RGBA{0xaa, 0x00, 0x55, 0xff},
	color.RGBA{0xaa, 0x00, 0xaa, 0xff},
	color.RGBA{0x9e, 0x00, 0xee, 0xff},
	color.RGBA{0xaa, 0x55, 0x00, 0xff},
	color.RGBA{0xaa, 0x55, 0x55, 0xff},
	color.RGBA{0xaa, 0x55, 0xaa, 0xff},
	color.RGBA{0x9e, 0x4f, 0xee, 0xff},
	color.RGBA{0xaa, 0xaa, 0x00, 0xff},
	color.RGBA{0xaa, 0xaa, 0x55, 0xff},
	color.RGBA{0xaa, 0xaa, 0xaa, 0xff},
	color.RGBA{0x9e, 0x9e, 0xee, 0xff},
	color.RGBA{0x9e, 0xee, 0x00, 0xff},
	color.RGBA{0x9e, 0xee, 0x4f, 0xff},
	color.RGBA{0x9e, 0xee, 0x9e, 0xff},
	color.RGBA{0x9e, 0xee, 0xee, 0xff},
	color.RGBA{0xaa, 0xff, 0xff, 0xff},
	color.RGBA{0xbb, 0x00, 0x00, 0xff},
	color.RGBA{0xbb, 0x00, 0x5d, 0xff},
	color.RGBA{0xbb, 0x00, 0xbb, 0xff},
	color.RGBA{0xaa, 0x00, 0xff, 0xff},
	color.RGBA{0xbb, 0x5d, 0x00, 0xff},
	color.RGBA{0xbb, 0x5d, 0x5d, 0xff},
	color.RGBA{0xbb, 0x5d, 0xbb, 0xff},
	color.RGBA{0xaa, 0x55, 0xff, 0xff},
	color.RGBA{0xbb, 0xbb, 0x00, 0xff},
	color.RGBA{0xbb, 0xbb, 0x5d, 0xff},
	color.RGBA{0xbb, 0xbb, 0xbb, 0xff},
	color.RGBA{0xaa, 0xaa, 0xff, 0xff},
	color.RGBA{0xaa, 0xff, 0x00, 0xff},
	color.RGBA{0xaa, 0xff, 0x55, 0xff},
	color.RGBA{0xaa, 0xff, 0xaa, 0xff},
	color.RGBA{0xcc, 0x00, 0xcc, 0xff},
	color.RGBA{0xcc, 0x44, 0x00, 0xff},
	color.RGBA{0xcc, 0x44, 0x44, 0xff},
	color.RGBA{0xcc, 0x44, 0x88, 0xff},
	color.RGBA{0xcc, 0x44, 0xcc, 0xff},
	color.RGBA{0xcc, 0x88, 0x00, 0xff},
	color.RGBA{0xcc, 0x88, 0x44, 0xff},
	color.RGBA{0xcc, 0x88, 0x88, 0xff},
	color.RGBA{0xcc, 0x88, 0xcc, 0xff},
	color.RGBA{0xcc, 0xcc, 0x00, 0xff},
	color.RGBA{0xcc, 0xcc, 0x44, 0xff},
	color.RGBA{0xcc, 0xcc, 0x88, 0xff},
	color.RGBA{0xcc, 0xcc, 0xcc, 0xff},
	color.RGBA{0xcc, 0x00, 0x00, 0xff},
	color.RGBA{0xcc, 0x00, 0x44, 0xff},
	color.RGBA{0xcc, 0x00, 0x88, 0xff},
	color.RGBA{0xdd, 0x00, 0x93, 0xff},
	color.RGBA{0xdd, 0x00, 0xdd, 0xff},
	color.RGBA{0xdd, 0x49, 0x00, 0xff},
	color.RGBA{0xdd, 0x49, 0x49, 0xff},
	color.RGBA{0xdd, 0x49, 0x93, 0xff},
	color.RGBA{0xdd, 0x49, 0xdd, 0xff},
	color.RGBA{0xdd, 0x93, 0x00, 0xff},
	color.RGBA{0xdd, 0x93, 0x49, 0xff},
	color.RGBA{0xdd, 0x93, 0x93, 0xff},
	color.RGBA{0xdd, 0x93, 0xdd, 0xff},
	color.RGBA{0xdd, 0xdd, 0x00, 0xff},
	color.RGBA{0xdd, 0xdd, 0x49, 0xff},
	color.RGBA{0xdd, 0xdd, 0x93, 0xff},
	color.RGBA{0xdd, 0xdd, 0xdd, 0xff},
	color.RGBA{0xdd, 0x00, 0x00, 0xff},
	color.RGBA{0xdd, 0x00, 0x49, 0xff},
	color.RGBA{0xee, 0x00, 0x4f, 0xff},
	color.RGBA{0xee, 0x00, 0x9e, 0xff},
	color.RGBA{0xee, 0x00, 0xee, 0xff},
	color.RGBA{0xee, 0x4f, 0x00, 0xff},
	color.RGBA{0xee, 0x4f, 0x4f, 0xff},
	color.RGBA{0xee, 0x4f, 0x9e, 0xff},
	color.RGBA{0xee, 0x4f, 0xee, 0xff},
	color.RGBA{0xee, 0x9e, 0x00, 0xff},
	color.RGBA{0xee, 0x9e, 0x4f, 0xff},
	color.RGBA{0xee, 0x9e, 0x9e, 0xff},
	color.RGBA{0xee, 0x9e, 0xee, 0xff},
	color.RGBA{0xee, 0xee, 0x00, 0xff},
	color.RGBA{0xee, 0xee, 0x4f, 0xff},
	color.RGBA{0xee, 0xee, 0x9e, 0xff},
	color.RGBA{0xee, 0xee, 0xee, 0xff},
	color.RGBA{0xee, 0x00, 0x00, 0xff},
	color.RGBA{0xff, 0x00, 0x00, 0xff},
	color.RGBA{0xff, 0x00, 0x55, 0xff},
	color.RGBA{0xff, 0x00, 0xaa, 0xff},
	color.RGBA{0xff, 0x00, 0xff, 0xff},
	color.RGBA{0xff, 0x55, 0x00, 0xff},
	color.RGBA{0xff, 0x55, 0x55, 0xff},
	color.RGBA{0xff, 0x55, 0xaa, 0xff},
	color.RGBA{0xff, 0x55, 0xff, 0xff},
	color.RGBA{0xff, 0xaa, 0x00, 0xff},
	color.RGBA{0xff, 0xaa, 0x55, 0xff},
	color.RGBA{0xff, 0xaa, 0xaa, 0xff},
	color.RGBA{0xff, 0xaa, 0xff, 0xff},
	color.RGBA{0xff, 0xff, 0x00, 0xff},
	color.RGBA{0xff, 0xff, 0x55, 0xff},
	color.RGBA{0xff, 0xff, 0xaa, 0xff},
	color.RGBA{0xff, 0xff, 0xff, 0xff},
}

// WebSafe is a 216-color palette that was popularized by early versions
// of Netscape Navigator. It is also known as the Netscape Color Cube.
//
// See https://en.wikipedia.org/wiki/Web_colors#Web-safe_colors for details.
var WebSafe = []color.Color{
	color.RGBA{0x00, 0x00, 0x00, 0xff},
	color.RGBA{0x00, 0x00, 0x33, 0xff},
	color.RGBA{0x00, 0x00, 0x66, 0xff},
	color.RGBA{0x00, 0x00, 0x99, 0xff},
	color.RGBA{0x00, 0x00, 0xcc, 0xff},
	color.RGBA{0x00, 0x00, 0xff, 0xff},
	color.RGBA{0x00, 0x33, 0x00, 0xff},
	color.RGBA{0x00, 0x33, 0x33, 0xff},
	color.RGBA{0x00, 0x33, 0x66, 0xff},
	color.RGBA{0x00, 0x33, 0x99, 0xff},
	color.RGBA{0x00, 0x33, 0xcc, 0xff},
	color.RGBA{0x00, 0x33, 0xff, 0xff},
	color.RGBA{0x00, 0x66, 0x00, 0xff},
	color.RGBA{0x00, 0x66, 0x33, 0xff},
	color.RGBA{0x00, 0x66, 0x66, 0xff},
	color.RGBA{0x00, 0x66, 0x99, 0xff},
	color.RGBA{0x00, 0x66, 0xcc, 0xff},
	color.RGBA{0x00, 0x66, 0xff, 0xff},
	color.RGBA{0x00, 0x99, 0x00, 0xff},
	color.RGBA{0x00, 0x99, 0x33, 0xff},
	color.RGBA{0x00, 0x99, 0x66, 0xff},
	color.RGBA{0x00, 0x99, 0x99, 0xff},
	color.RGBA{0x00, 0x99, 0xcc, 0xff},
	color.RGBA{0x00, 0x99, 0xff, 0xff},
	color.RGBA{0x00, 0xcc, 0x00, 0xff},
	color.RGBA{0x00, 0xcc, 0x33, 0xff},
	color.RGBA{0x00, 0xcc, 0x66, 0xff},
	color.RGBA{0x00, 0xcc, 0x99, 0xff},
	color.RGBA{0x00, 0xcc, 0xcc, 0xff},
	color.RGBA{0x00, 0xcc, 0xff, 0xff},
	color.RGBA{0x00, 0xff, 0x00, 0xff},
	color.RGBA{0x00, 0xff, 0x33, 0xff},
	color.RGBA{0x00, 0xff, 0x66, 0xff},
	color.RGBA{0x00, 0xff, 0x99, 0xff},
	color.RGBA{0x00, 0xff, 0xcc, 0xff},
	color.RGBA{0x00, 0xff, 0xff, 0xff},
	color.RGBA{0x33, 0x00, 0x00, 0xff},
	color.RGBA{0x33, 0x00, 0x33, 0xff},
	color.RGBA{0x33, 0x00, 0x66, 0xff},
	color.RGBA{0x33, 0x00, 0x99, 0xff},
	color.RGBA{0x33, 0x00, 0xcc, 0xff},
	color.RGBA{0x33, 0x00, 0xff, 0xff},
	color.RGBA{0x33, 0x33, 0x00, 0xff},
	color.RGBA{0x33, 0x33, 0x33, 0xff},
	color.RGBA{0x33, 0x33, 0x66, 0xff},
	color.RGBA{0x33, 0x33, 0x99, 0xff},
	color.RGBA{0x33, 0x33, 0xcc, 0xff},
	color.RGBA{0x33, 0x33, 0xff, 0xff},
	color.RGBA{0x33, 0x66, 0x00, 0xff},
	color.RGBA{0x33, 0x66, 0x33, 0xff},
	color.RGBA{0x33, 0x66, 0x66, 0xff},
	color.RGBA{0x33, 0x66, 0x99, 0xff},
	color.RGBA{0x33, 0x66, 0xcc, 0xff},
	color.RGBA{0x33, 0x66, 0xff, 0xff},
	color.RGBA{0x33, 0x99, 0x00, 0xff},
	color.RGBA{0x33, 0x99, 0x33, 0xff},
	color.RGBA{0x33, 0x99, 0x66, 0xff},
	color.RGBA{0x33, 0x99, 0x99, 0xff},
	color.RGBA{0x33, 0x99, 0xcc, 0xff},
	color.RGBA{0x33, 0x99, 0xff, 0xff},
	color.RGBA{0x33, 0xcc, 0x00, 0xff},
	color.RGBA{0x33, 0xcc, 0x33, 0xff},
	color.RGBA{0x33, 0xcc, 0x66, 0xff},
	color.RGBA{0x33, 0xcc, 0x99, 0xff},
	color.RGBA{0x33, 0xcc, 0xcc, 0xff},
	color.RGBA{0x33, 0xcc, 0xff, 0xff},
	color.RGBA{0x33, 0xff, 0x00, 0xff},
	color.RGBA{0x33, 0xff, 0x33, 0xff},
	color.RGBA{0x33, 0xff, 0x66, 0xff},
	color.RGBA{0x33, 0xff, 0x99, 0xff},
	color.RGBA{0x33, 0xff, 0xcc, 0xff},
	color.RGBA{0x33, 0xff, 0xff, 0xff},
	color.RGBA{0x66, 0x00, 0x00, 0xff},
	color.RGBA{0x66, 0x00, 0x33, 0xff},
	color.RGBA{0x66, 0x00, 0x66, 0xff},
	color.RGBA{0x66, 0x00, 0x99, 0xff},
	color.RGBA{0x66, 0x00, 0xcc, 0xff},
	color.RGBA{0x66, 0x00, 0xff, 0xff},
	color.RGBA{0x66, 0x33, 0x00, 0xff},
	color.RGBA{0x66, 0x33, 0x33, 0xff},
	color.RGBA{0x66, 0x33, 0x66, 0xff},
	color.RGBA{0x66, 0x33, 0x99, 0xff},
	color.RGBA{0x66, 0x33, 0xcc, 0xff},
	color.RGBA{0x66, 0x33, 0xff, 0xff},
	color.RGBA{0x66, 0x66, 0x00, 0xff},
	color.RGBA{0x66, 0x66, 0x33, 0xff},
	color.RGBA{0x66, 0x66, 0x66, 0xff},
	color.RGBA{0x66, 0x66, 0x99, 0xff},
	color.RGBA{0x66, 0x66, 0xcc, 0xff},
	color.RGBA{0x66, 0x66, 0xff, 0xff},
	color.RGBA{0x66, 0x99, 0x00, 0xff},
	color.RGBA{0x66, 0x99, 0x33, 0xff},
	color.RGBA{0x66, 0x99, 0x66, 0xff},
	color.RGBA{0x66, 0x99, 0x99, 0xff},
	color.RGBA{0x66, 0x99, 0xcc, 0xff},
	color.RGBA{0x66, 0x99, 0xff, 0xff},
	color.RGBA{0x66, 0xcc, 0x00, 0xff},
	color.RGBA{0x66, 0xcc, 0x33, 0xff},
	color.RGBA{0x66, 0xcc, 0x66, 0xff},
	color.RGBA{0x66, 0xcc, 0x99, 0xff},
	color.RGBA{0x66, 0xcc, 0xcc, 0xff},
	color.RGBA{0x66, 0xcc, 0xff, 0xff},
	color.RGBA{0x66, 0xff, 0x00, 0xff},
	color.RGBA{0x66, 0xff, 0x33, 0xff},
	color.RGBA{0x66, 0xff, 0x66, 0xff},
	color.RGBA{0x66, 0xff, 0x99, 0xff},
	color.RGBA{0x66, 0xff, 0xcc, 0xff},
	color.RGBA{0x66, 0xff, 0xff, 0xff},
	color.RGBA{0x99, 0x00, 0x00, 0xff},
	color.RGBA{0x99, 0x00, 0x33, 0xff},
	color.RGBA{0x99, 0x00, 0x66, 0xff},
	color.RGBA{0x99, 0x00, 0x99, 0xff},
	color.RGBA{0x99, 0x00, 0xcc, 0xff},
	color.RGBA{0x99, 0x00, 0xff, 0xff},
	color.RGBA{0x99, 0x33, 0x00, 0xff},
	color.RGBA{0x99, 0x33, 0x33, 0xff},
	color.RGBA{0x99, 0x33, 0x66, 0xff},
	color.RGBA{0x99, 0x33, 0x99, 0xff},
	color.RGBA{0x99, 0x33, 0xcc, 0xff},
	color.RGBA{0x99, 0x33, 0xff, 0xff},
	color.RGBA{0x99, 0x66, 0x00, 0xff},
	color.RGBA{0x99, 0x66, 0x33, 0xff},
	color.RGBA{0x99, 0x66, 0x66, 0xff},
	color.RGBA{0x99, 0x66, 0x99, 0xff},
	color.RGBA{0x99, 0x66, 0xcc, 0xff},
	color.RGBA{0x99, 0x66, 0xff, 0xff},
	color.RGBA{0x99, 0x99, 0x00, 0xff},
	color.RGBA{0x99, 0x99, 0x33, 0xff},
	color.RGBA{0x99, 0x99, 0x66, 0xff},
	color.RGBA{0x99, 0x99, 0x99, 0xff},
	color.RGBA{0x99, 0x99, 0xcc, 0xff},
	color.RGBA{0x99, 0x99, 0xff, 0xff},
	color.RGBA{0x99, 0xcc, 0x00, 0xff},
	color.RGBA{0x99, 0xcc, 0x33, 0xff},
	color.RGBA{0x99, 0xcc, 0x66, 0xff},
	color.RGBA{0x99, 0xcc, 0x99, 0xff},
	color.RGBA{0x99, 0xcc, 0xcc, 0xff},
	color.RGBA{0x99, 0xcc, 0xff, 0xff},
	color.RGBA{0x99, 0xff, 0x00, 0xff},
	color.RGBA{0x99, 0xff, 0x33, 0xff},
	color.RGBA{0x99, 0xff, 0x66, 0xff},
	color.RGBA{0x99, 0xff, 0x99, 0xff},
	color.RGBA{0x99, 0xff, 0xcc, 0xff},
	color.RGBA{0x99, 0xff, 0xff, 0xff},
	color.RGBA{0xcc, 0x00, 0x00, 0xff},
	color.RGBA{0xcc, 0x00, 0x33, 0xff},
	color.RGBA{0xcc, 0x00, 0x66, 0xff},
	color.RGBA{0xcc, 0x00, 0x99, 0xff},
	color.RGBA{0xcc, 0x00, 0xcc, 0xff},
	color.RGBA{0xcc, 0x00, 0xff, 0xff},
	color.RGBA{0xcc, 0x33, 0x00, 0xff},
	color.RGBA{0xcc, 0x33, 0x33, 0xff},
	color.RGBA{0xcc, 0x33, 0x66, 0xff},
	color.RGBA{0xcc, 0x33, 0x99, 0xff},
	color.RGBA{0xcc, 0x33, 0xcc, 0xff},
	color.RGBA{0xcc, 0x33, 0xff, 0xff},
	color.RGBA{0xcc, 0x66, 0x00, 0xff},
	color.RGBA{0xcc, 0x66, 0x33, 0xff},
	color.RGBA{0xcc, 0x66, 0x66, 0xff},
	color.RGBA{0xcc, 0x66, 0x99, 0xff},
	color.RGBA{0xcc, 0x66, 0xcc, 0xff},
	color.RGBA{0xcc, 0x66, 0xff, 0xff},
	color.RGBA{0xcc, 0x99, 0x00, 0xff},
	color.RGBA{0xcc, 0x99, 0x33, 0xff},
	color.RGBA{0xcc, 0x99, 0x66, 0xff},
	color.RGBA{0xcc, 0x99, 0x99, 0xff},
	color.RGBA{0xcc, 0x99, 0xcc, 0xff},
	color.RGBA{0xcc, 0x99, 0xff, 0xff},
	color.RGBA{0xcc, 0xcc, 0x00, 0xff},
	color.RGBA{0xcc, 0xcc, 0x33, 0xff},
	color.RGBA{0xcc, 0xcc, 0x66, 0xff},
	color.RGBA{0xcc, 0xcc, 0x99, 0xff},
	color.RGBA{0xcc, 0xcc, 0xcc, 0xff},
	color.RGBA{0xcc, 0xcc, 0xff, 0xff},
	color.RGBA{0xcc, 0xff, 0x00, 0xff},
	color.RGBA{0xcc, 0xff, 0x33, 0xff},
	color.RGBA{0xcc, 0xff, 0x66, 0xff},
	color.RGBA{0xcc, 0xff, 0x99, 0xff},
	color.RGBA{0xcc, 0xff, 0xcc, 0xff},
	color.RGBA{0xcc, 0xff, 0xff, 0xff},
	color.RGBA{0xff, 0x00, 0x00, 0xff},
	color.RGBA{0xff, 0x00, 0x33, 0xff},
	color.RGBA{0xff, 0x00, 0x66, 0xff},
	color.RGBA{0xff, 0x00, 0x99, 0xff},
	color.RGBA{0xff, 0x00, 0xcc, 0xff},
	color.RGBA{0xff, 0x00, 0xff, 0xff},
	color.RGBA{0xff, 0x33, 0x00, 0xff},
	color.RGBA{0xff, 0x33, 0x33, 0xff},
	color.RGBA{0xff, 0x33, 0x66, 0xff},
	color.RGBA{0xff, 0x33, 0x99, 0xff},
	color.RGBA{0xff, 0x33, 0xcc, 0xff},
	color.RGBA{0xff, 0x33, 0xff, 0xff},
	color.RGBA{0xff, 0x66, 0x00, 0xff},
	color.RGBA{0xff, 0x66, 0x33, 0xff},
	color.RGBA{0xff, 0x66, 0x66, 0xff},
	color.RGBA{0xff, 0x66, 0x99, 0xff},
	color.RGBA{0xff, 0x66, 0xcc, 0xff},
	color.RGBA{0xff, 0x66, 0xff, 0xff},
	color.RGBA{0xff, 0x99, 0x00, 0xff},
	color.RGBA{0xff, 0x99, 0x33, 0xff},
	color.RGBA{0xff, 0x99, 0x66, 0xff},
	color.RGBA{0xff, 0x99, 0x99, 0xff},
	color.RGBA{0xff, 0x99, 0xcc, 0xff},
	color.RGBA{0xff, 0x99, 0xff, 0xff},
	color.RGBA{0xff, 0xcc, 0x00, 0xff},
	color.RGBA{0xff, 0xcc, 0x33, 0xff},
	color.RGBA{0xff, 0xcc, 0x66, 0xff},
	color.RGBA{0xff, 0xcc, 0x99, 0xff},
	color.RGBA{0xff, 0xcc, 0xcc, 0xff},
	color.RGBA{0xff, 0xcc, 0xff, 0xff},
	color.RGBA{0xff, 0xff, 0x00, 0xff},
	color.RGBA{0xff, 0xff, 0x33, 0xff},
	color.RGBA{0xff, 0xff, 0x66, 0xff},
	color.RGBA{0xff, 0xff, 0x99, 0xff},
	color.RGBA{0xff, 0xff, 0xcc, 0xff},
	color.RGBA{0xff, 0xff, 0xff, 0xff},
}

"""



```