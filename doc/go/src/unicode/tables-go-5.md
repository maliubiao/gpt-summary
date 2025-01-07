Response:
Let's break down the thought process for answering the prompt.

**1. Understanding the Goal:**

The core request is to analyze a Go source code snippet (`tables.go`) and explain its functionality, relating it to broader Go features if possible. The specific decomposed instructions (list features, infer Go feature, provide examples, handle command-line arguments, discuss common mistakes, and summarize) guide the analysis. The fact that this is "part 6 of 7" suggests that the previous parts likely established a context, but we need to work with the given snippet in isolation as instructed.

**2. Initial Observation and Keyword Recognition:**

The code is primarily composed of `var` declarations, assigning `&RangeTable` literals to variables with names like `_Other_Lowercase`, `_Other_Math`, `_Pattern_Syntax`, etc. The `RangeTable` struct itself contains `R16` and `R32` fields, which are slices of `Range16` and `Range32` respectively. These `Range` structs contain start, end, and stride values (integers). The `LatinOffset` field in some `RangeTable` instances is also noticeable.

**3. Inferring the Purpose - Character Sets and Properties:**

The naming convention (`_Other_Lowercase`, `_Other_Math`, `_Pattern_Syntax`, etc.) strongly suggests that these variables represent collections of Unicode characters grouped by some property. The `Range` structs, with their start, end, and stride, point to an efficient way of representing character ranges within the Unicode space. This immediately links the code to the Go `unicode` package's role in handling Unicode.

**4. Connecting to Go `unicode` Package:**

The `go/src/unicode/tables.go` path itself confirms that this is a core part of the Go `unicode` package. The variable names like `ASCII_Hex_Digit`, `Bidi_Control`, etc., which are assigned the pre-defined `_...` variables, directly correspond to Unicode character properties. This establishes the main function: defining and making accessible Unicode character properties within Go.

**5. Example Construction - `unicode.Is`:**

Knowing the purpose is to represent Unicode properties, the next step is to illustrate *how* this data is used in Go. The `unicode` package provides functions like `unicode.Is(rangeTable, rune)` to check if a given `rune` belongs to a specified character set. This is the most direct and intuitive usage. Constructing a simple example using `unicode.Is(unicode.Other_Lowercase, 'a')` and `unicode.Is(unicode.Other_Lowercase, 'A')` demonstrates this.

**6. Example Construction - `unicode` Package Constants:**

The code snippet also shows variables like `ASCII_Hex_Digit` being assigned the pre-defined `_ASCII_Hex_Digit`. This indicates that these pre-defined variables are likely exported constants in the `unicode` package. Demonstrating usage with `unicode.ASCII_Hex_Digit` and `unicode.Is` further clarifies this.

**7. Command-Line Arguments and Common Mistakes:**

The provided code snippet doesn't directly handle command-line arguments or perform complex logic. Its primary role is data definition. Therefore, these sections of the prompt should reflect this. For common mistakes, focusing on the *usage* of the `unicode` package and the potential for incorrect assumptions about character properties is key. For instance, confusing similar but distinct properties or not handling the full range of Unicode.

**8. Function Summarization (Part 6 of 7):**

Since this is part 6, the summarization should reflect the specific content of this snippet. It's about the *data* representing various Unicode character properties, not necessarily the higher-level functions that *use* this data. The `RangeTable` structure and its role in efficient representation are important to highlight.

**9. Refinement and Language:**

Throughout the process, use clear and concise Chinese. Explain technical terms appropriately. Ensure the examples are runnable and illustrate the point effectively. The structure should follow the decomposed instructions in the prompt.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Could these be related to regular expressions?  While character properties are used in regex, the primary function here is the fundamental definition of those properties. Regex is a higher-level *use* case.
* **Consideration of `LatinOffset`:**  Acknowledge the `LatinOffset` but avoid deep speculation without more context. It's a detail of the data structure, but its exact usage might be in other parts of the `unicode` package.
* **Focus on `RangeTable`:** Emphasize the `RangeTable` structure and how it optimizes the storage of character sets. This is a key implementation detail exposed by the snippet.
* **Ensure examples are valid Go:** Double-check the syntax and ensure the examples are meaningful and easy to understand.

By following these steps, the analysis becomes structured, accurate, and addresses all aspects of the prompt. The key is to move from the specific code elements to inferring the broader purpose and demonstrating its usage within the Go ecosystem.
这是 `go/src/unicode/tables.go` 文件的一部分，它定义了一些用于表示 Unicode 字符属性的查找表。具体来说，这段代码定义了一系列的 `RangeTable` 类型的变量，每个变量都对应一个特定的 Unicode 字符属性。

**功能列举:**

1. **定义 Unicode 字符属性的范围表:**  这段代码的核心功能是定义各种 Unicode 字符属性的范围。例如，`_Other_Lowercase` 定义了哪些 Unicode 字符被认为是“其他小写字母”。
2. **使用 RangeTable 结构高效存储字符范围:**  `RangeTable` 结构使用 `R16` 和 `R32` 字段来存储字符码点的范围，分别用于表示 16 位和 32 位的 Unicode 码点。这种方式比单独列出每个字符更节省空间。
3. **区分 LatinOffset:**  某些 `RangeTable` 结构（如 `_Other_Lowercase` 和 `_Pattern_Syntax`）包含 `LatinOffset` 字段。这通常用于优化拉丁字母相关的查找，允许更快地判断一个拉丁字母是否属于该属性。
4. **定义并导出 Unicode 属性常量:**  代码中将以 `_` 开头的 `RangeTable` 变量赋值给不带下划线的同名变量，例如 `ASCII_Hex_Digit = _ASCII_Hex_Digit`。这些不带下划线的变量是导出的常量，可以在 `unicode` 包的其他地方和用户代码中使用。
5. **定义 CaseRanges 用于大小写映射:**  `CaseRanges` 变量定义了字符的大小写映射关系。它是一个 `CaseRange` 类型的切片，描述了如何将一个字符转换为大写、小写或 title case。
6. **定义 properties 数组用于快速属性查询:** `properties` 数组是一个简单的字节数组，用于存储前 256 个 Unicode 字符（Latin-1 字符集）的基本属性。

**推理 `unicode` 包的功能实现并举例说明:**

这段代码是 Go 语言 `unicode` 包实现的一部分，该包提供了处理 Unicode 字符的功能。这些 `RangeTable` 用于高效地判断一个给定的 Unicode 字符是否具有特定的属性，例如是否是小写字母、数学符号、空格等等。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"unicode"
)

func main() {
	// 检查字符 'a' 是否是小写字母
	fmt.Println(unicode.IsLower('a')) // 输出: true

	// 检查字符 'α' 是否是小写字母
	fmt.Println(unicode.IsLower('α')) // 输出: true

	// 检查字符 'α' 是否在 _Other_Lowercase 定义的范围内
	fmt.Println(unicode.Is(unicode.Other_Lowercase, 'α')) // 输出: true

	// 检查字符 '$' 是否是数学符号
	fmt.Println(unicode.Is(unicode.Other_Math, '$')) // 输出: true

	// 大小写转换
	fmt.Println(unicode.ToLower('A')) // 输出: a
	fmt.Println(unicode.ToUpper('a')) // 输出: A
}
```

**假设的输入与输出：**

在上面的例子中：

* **输入:** 字符 `'a'`, `'α'`, `'$'`, `'A'`
* **输出:** `true`, `true`, `true`, `a`, `A`

**代码推理：**

`unicode.Is` 函数会接收一个 `RangeTable` 指针和一个 `rune` (Unicode 字符) 作为输入。它会遍历 `RangeTable` 中的 `R16` 和 `R32` 范围，并检查输入的 `rune` 是否落在这些定义的范围内。`LatinOffset` 可以作为优化，如果待检查的字符是拉丁字母，则可以利用 `LatinOffset` 跳过一些范围，提高查找效率。

`unicode.ToLower` 和 `unicode.ToUpper` 函数会使用 `CaseRanges` 表来查找字符的映射关系，从而进行大小写转换。

**命令行参数的具体处理:**

这段代码本身不涉及命令行参数的处理。`unicode` 包提供的功能通常在程序内部使用，而不是通过命令行参数来配置其行为。

**使用者易犯错的点：**

* **混淆不同的 Unicode 属性:**  初学者可能会混淆相似的 Unicode 属性，例如 `unicode.Lower` 和 `unicode.Other_Lowercase`。`unicode.Lower` 包含了所有语言中定义为小写字母的字符，而 `unicode.Other_Lowercase` 则可能包含一些不常见的或特殊的小写形式。理解不同属性之间的细微差别很重要。

    ```go
    package main

    import (
        "fmt"
        "unicode"
    )

    func main() {
        // 'ª' 是一个女性序数指示符，属于 Other_Lowercase
        fmt.Println(unicode.IsLower('ª'))             // 输出: false
        fmt.Println(unicode.Is(unicode.Other_Lowercase, 'ª')) // 输出: true
    }
    ```

* **假设 ASCII 覆盖所有情况:**  开发者可能会错误地认为只处理 ASCII 字符就足够了，而忽略了 Unicode 的广泛性。使用 `unicode` 包的函数可以确保代码能够正确处理各种语言的字符。

**归纳其功能 (作为第 6 部分):**

作为 `go/src/unicode/tables.go` 文件的一部分，这段代码定义了 Go 语言 `unicode` 包中用于表示和查询各种 Unicode 字符属性的关键**数据结构和数据**。它通过 `RangeTable` 结构高效地存储了不同 Unicode 属性的字符范围，并提供了字符大小写映射的规则。这些数据是 `unicode` 包实现其字符分类、转换等功能的基础，使得 Go 语言能够正确且高效地处理全球各种语言的文本。简而言之，**这是 `unicode` 包的核心数据定义部分，描述了各种 Unicode 字符的属性范围和大小写映射关系。**

Prompt: 
```
这是路径为go/src/unicode/tables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共7部分，请归纳一下它的功能

"""
&RangeTable{
	R16: []Range16{
		{0x1885, 0x1886, 1},
		{0x2118, 0x212e, 22},
		{0x309b, 0x309c, 1},
	},
}

var _Other_Lowercase = &RangeTable{
	R16: []Range16{
		{0x00aa, 0x00ba, 16},
		{0x02b0, 0x02b8, 1},
		{0x02c0, 0x02c1, 1},
		{0x02e0, 0x02e4, 1},
		{0x0345, 0x037a, 53},
		{0x10fc, 0x1d2c, 3120},
		{0x1d2d, 0x1d6a, 1},
		{0x1d78, 0x1d9b, 35},
		{0x1d9c, 0x1dbf, 1},
		{0x2071, 0x207f, 14},
		{0x2090, 0x209c, 1},
		{0x2170, 0x217f, 1},
		{0x24d0, 0x24e9, 1},
		{0x2c7c, 0x2c7d, 1},
		{0xa69c, 0xa69d, 1},
		{0xa770, 0xa7f2, 130},
		{0xa7f3, 0xa7f4, 1},
		{0xa7f8, 0xa7f9, 1},
		{0xab5c, 0xab5f, 1},
		{0xab69, 0xab69, 1},
	},
	R32: []Range32{
		{0x10780, 0x10783, 3},
		{0x10784, 0x10785, 1},
		{0x10787, 0x107b0, 1},
		{0x107b2, 0x107ba, 1},
		{0x1e030, 0x1e06d, 1},
	},
	LatinOffset: 1,
}

var _Other_Math = &RangeTable{
	R16: []Range16{
		{0x005e, 0x03d0, 882},
		{0x03d1, 0x03d2, 1},
		{0x03d5, 0x03f0, 27},
		{0x03f1, 0x03f4, 3},
		{0x03f5, 0x2016, 7201},
		{0x2032, 0x2034, 1},
		{0x2040, 0x2061, 33},
		{0x2062, 0x2064, 1},
		{0x207d, 0x207e, 1},
		{0x208d, 0x208e, 1},
		{0x20d0, 0x20dc, 1},
		{0x20e1, 0x20e5, 4},
		{0x20e6, 0x20eb, 5},
		{0x20ec, 0x20ef, 1},
		{0x2102, 0x2107, 5},
		{0x210a, 0x2113, 1},
		{0x2115, 0x2119, 4},
		{0x211a, 0x211d, 1},
		{0x2124, 0x2128, 4},
		{0x2129, 0x212c, 3},
		{0x212d, 0x212f, 2},
		{0x2130, 0x2131, 1},
		{0x2133, 0x2138, 1},
		{0x213c, 0x213f, 1},
		{0x2145, 0x2149, 1},
		{0x2195, 0x2199, 1},
		{0x219c, 0x219f, 1},
		{0x21a1, 0x21a2, 1},
		{0x21a4, 0x21a5, 1},
		{0x21a7, 0x21a9, 2},
		{0x21aa, 0x21ad, 1},
		{0x21b0, 0x21b1, 1},
		{0x21b6, 0x21b7, 1},
		{0x21bc, 0x21cd, 1},
		{0x21d0, 0x21d1, 1},
		{0x21d3, 0x21d5, 2},
		{0x21d6, 0x21db, 1},
		{0x21dd, 0x21e4, 7},
		{0x21e5, 0x2308, 291},
		{0x2309, 0x230b, 1},
		{0x23b4, 0x23b5, 1},
		{0x23b7, 0x23d0, 25},
		{0x23e2, 0x25a0, 446},
		{0x25a1, 0x25ae, 13},
		{0x25af, 0x25b6, 1},
		{0x25bc, 0x25c0, 1},
		{0x25c6, 0x25c7, 1},
		{0x25ca, 0x25cb, 1},
		{0x25cf, 0x25d3, 1},
		{0x25e2, 0x25e4, 2},
		{0x25e7, 0x25ec, 1},
		{0x2605, 0x2606, 1},
		{0x2640, 0x2642, 2},
		{0x2660, 0x2663, 1},
		{0x266d, 0x266e, 1},
		{0x27c5, 0x27c6, 1},
		{0x27e6, 0x27ef, 1},
		{0x2983, 0x2998, 1},
		{0x29d8, 0x29db, 1},
		{0x29fc, 0x29fd, 1},
		{0xfe61, 0xfe63, 2},
		{0xfe68, 0xff3c, 212},
		{0xff3e, 0xff3e, 1},
	},
	R32: []Range32{
		{0x1d400, 0x1d454, 1},
		{0x1d456, 0x1d49c, 1},
		{0x1d49e, 0x1d49f, 1},
		{0x1d4a2, 0x1d4a5, 3},
		{0x1d4a6, 0x1d4a9, 3},
		{0x1d4aa, 0x1d4ac, 1},
		{0x1d4ae, 0x1d4b9, 1},
		{0x1d4bb, 0x1d4bd, 2},
		{0x1d4be, 0x1d4c3, 1},
		{0x1d4c5, 0x1d505, 1},
		{0x1d507, 0x1d50a, 1},
		{0x1d50d, 0x1d514, 1},
		{0x1d516, 0x1d51c, 1},
		{0x1d51e, 0x1d539, 1},
		{0x1d53b, 0x1d53e, 1},
		{0x1d540, 0x1d544, 1},
		{0x1d546, 0x1d54a, 4},
		{0x1d54b, 0x1d550, 1},
		{0x1d552, 0x1d6a5, 1},
		{0x1d6a8, 0x1d6c0, 1},
		{0x1d6c2, 0x1d6da, 1},
		{0x1d6dc, 0x1d6fa, 1},
		{0x1d6fc, 0x1d714, 1},
		{0x1d716, 0x1d734, 1},
		{0x1d736, 0x1d74e, 1},
		{0x1d750, 0x1d76e, 1},
		{0x1d770, 0x1d788, 1},
		{0x1d78a, 0x1d7a8, 1},
		{0x1d7aa, 0x1d7c2, 1},
		{0x1d7c4, 0x1d7cb, 1},
		{0x1d7ce, 0x1d7ff, 1},
		{0x1ee00, 0x1ee03, 1},
		{0x1ee05, 0x1ee1f, 1},
		{0x1ee21, 0x1ee22, 1},
		{0x1ee24, 0x1ee27, 3},
		{0x1ee29, 0x1ee32, 1},
		{0x1ee34, 0x1ee37, 1},
		{0x1ee39, 0x1ee3b, 2},
		{0x1ee42, 0x1ee47, 5},
		{0x1ee49, 0x1ee4d, 2},
		{0x1ee4e, 0x1ee4f, 1},
		{0x1ee51, 0x1ee52, 1},
		{0x1ee54, 0x1ee57, 3},
		{0x1ee59, 0x1ee61, 2},
		{0x1ee62, 0x1ee64, 2},
		{0x1ee67, 0x1ee6a, 1},
		{0x1ee6c, 0x1ee72, 1},
		{0x1ee74, 0x1ee77, 1},
		{0x1ee79, 0x1ee7c, 1},
		{0x1ee7e, 0x1ee80, 2},
		{0x1ee81, 0x1ee89, 1},
		{0x1ee8b, 0x1ee9b, 1},
		{0x1eea1, 0x1eea3, 1},
		{0x1eea5, 0x1eea9, 1},
		{0x1eeab, 0x1eebb, 1},
	},
}

var _Other_Uppercase = &RangeTable{
	R16: []Range16{
		{0x2160, 0x216f, 1},
		{0x24b6, 0x24cf, 1},
	},
	R32: []Range32{
		{0x1f130, 0x1f149, 1},
		{0x1f150, 0x1f169, 1},
		{0x1f170, 0x1f189, 1},
	},
}

var _Pattern_Syntax = &RangeTable{
	R16: []Range16{
		{0x0021, 0x002f, 1},
		{0x003a, 0x0040, 1},
		{0x005b, 0x005e, 1},
		{0x0060, 0x007b, 27},
		{0x007c, 0x007e, 1},
		{0x00a1, 0x00a7, 1},
		{0x00a9, 0x00ab, 2},
		{0x00ac, 0x00b0, 2},
		{0x00b1, 0x00bb, 5},
		{0x00bf, 0x00d7, 24},
		{0x00f7, 0x2010, 7961},
		{0x2011, 0x2027, 1},
		{0x2030, 0x203e, 1},
		{0x2041, 0x2053, 1},
		{0x2055, 0x205e, 1},
		{0x2190, 0x245f, 1},
		{0x2500, 0x2775, 1},
		{0x2794, 0x2bff, 1},
		{0x2e00, 0x2e7f, 1},
		{0x3001, 0x3003, 1},
		{0x3008, 0x3020, 1},
		{0x3030, 0xfd3e, 52494},
		{0xfd3f, 0xfe45, 262},
		{0xfe46, 0xfe46, 1},
	},
	LatinOffset: 10,
}

var _Pattern_White_Space = &RangeTable{
	R16: []Range16{
		{0x0009, 0x000d, 1},
		{0x0020, 0x0085, 101},
		{0x200e, 0x200f, 1},
		{0x2028, 0x2029, 1},
	},
	LatinOffset: 2,
}

var _Prepended_Concatenation_Mark = &RangeTable{
	R16: []Range16{
		{0x0600, 0x0605, 1},
		{0x06dd, 0x070f, 50},
		{0x0890, 0x0891, 1},
		{0x08e2, 0x08e2, 1},
	},
	R32: []Range32{
		{0x110bd, 0x110cd, 16},
	},
}

var _Quotation_Mark = &RangeTable{
	R16: []Range16{
		{0x0022, 0x0027, 5},
		{0x00ab, 0x00bb, 16},
		{0x2018, 0x201f, 1},
		{0x2039, 0x203a, 1},
		{0x2e42, 0x300c, 458},
		{0x300d, 0x300f, 1},
		{0x301d, 0x301f, 1},
		{0xfe41, 0xfe44, 1},
		{0xff02, 0xff07, 5},
		{0xff62, 0xff63, 1},
	},
	LatinOffset: 2,
}

var _Radical = &RangeTable{
	R16: []Range16{
		{0x2e80, 0x2e99, 1},
		{0x2e9b, 0x2ef3, 1},
		{0x2f00, 0x2fd5, 1},
	},
}

var _Regional_Indicator = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x1f1e6, 0x1f1ff, 1},
	},
}

var _Sentence_Terminal = &RangeTable{
	R16: []Range16{
		{0x0021, 0x002e, 13},
		{0x003f, 0x0589, 1354},
		{0x061d, 0x061f, 1},
		{0x06d4, 0x0700, 44},
		{0x0701, 0x0702, 1},
		{0x07f9, 0x0837, 62},
		{0x0839, 0x083d, 4},
		{0x083e, 0x0964, 294},
		{0x0965, 0x104a, 1765},
		{0x104b, 0x1362, 791},
		{0x1367, 0x1368, 1},
		{0x166e, 0x1735, 199},
		{0x1736, 0x1803, 205},
		{0x1809, 0x1944, 315},
		{0x1945, 0x1aa8, 355},
		{0x1aa9, 0x1aab, 1},
		{0x1b5a, 0x1b5b, 1},
		{0x1b5e, 0x1b5f, 1},
		{0x1b7d, 0x1b7e, 1},
		{0x1c3b, 0x1c3c, 1},
		{0x1c7e, 0x1c7f, 1},
		{0x203c, 0x203d, 1},
		{0x2047, 0x2049, 1},
		{0x2e2e, 0x2e3c, 14},
		{0x2e53, 0x2e54, 1},
		{0x3002, 0xa4ff, 29949},
		{0xa60e, 0xa60f, 1},
		{0xa6f3, 0xa6f7, 4},
		{0xa876, 0xa877, 1},
		{0xa8ce, 0xa8cf, 1},
		{0xa92f, 0xa9c8, 153},
		{0xa9c9, 0xaa5d, 148},
		{0xaa5e, 0xaa5f, 1},
		{0xaaf0, 0xaaf1, 1},
		{0xabeb, 0xfe52, 21095},
		{0xfe56, 0xfe57, 1},
		{0xff01, 0xff0e, 13},
		{0xff1f, 0xff61, 66},
	},
	R32: []Range32{
		{0x10a56, 0x10a57, 1},
		{0x10f55, 0x10f59, 1},
		{0x10f86, 0x10f89, 1},
		{0x11047, 0x11048, 1},
		{0x110be, 0x110c1, 1},
		{0x11141, 0x11143, 1},
		{0x111c5, 0x111c6, 1},
		{0x111cd, 0x111de, 17},
		{0x111df, 0x11238, 89},
		{0x11239, 0x1123b, 2},
		{0x1123c, 0x112a9, 109},
		{0x1144b, 0x1144c, 1},
		{0x115c2, 0x115c3, 1},
		{0x115c9, 0x115d7, 1},
		{0x11641, 0x11642, 1},
		{0x1173c, 0x1173e, 1},
		{0x11944, 0x11946, 2},
		{0x11a42, 0x11a43, 1},
		{0x11a9b, 0x11a9c, 1},
		{0x11c41, 0x11c42, 1},
		{0x11ef7, 0x11ef8, 1},
		{0x11f43, 0x11f44, 1},
		{0x16a6e, 0x16a6f, 1},
		{0x16af5, 0x16b37, 66},
		{0x16b38, 0x16b44, 12},
		{0x16e98, 0x1bc9f, 19975},
		{0x1da88, 0x1da88, 1},
	},
	LatinOffset: 1,
}

var _Soft_Dotted = &RangeTable{
	R16: []Range16{
		{0x0069, 0x006a, 1},
		{0x012f, 0x0249, 282},
		{0x0268, 0x029d, 53},
		{0x02b2, 0x03f3, 321},
		{0x0456, 0x0458, 2},
		{0x1d62, 0x1d96, 52},
		{0x1da4, 0x1da8, 4},
		{0x1e2d, 0x1ecb, 158},
		{0x2071, 0x2148, 215},
		{0x2149, 0x2c7c, 2867},
	},
	R32: []Range32{
		{0x1d422, 0x1d423, 1},
		{0x1d456, 0x1d457, 1},
		{0x1d48a, 0x1d48b, 1},
		{0x1d4be, 0x1d4bf, 1},
		{0x1d4f2, 0x1d4f3, 1},
		{0x1d526, 0x1d527, 1},
		{0x1d55a, 0x1d55b, 1},
		{0x1d58e, 0x1d58f, 1},
		{0x1d5c2, 0x1d5c3, 1},
		{0x1d5f6, 0x1d5f7, 1},
		{0x1d62a, 0x1d62b, 1},
		{0x1d65e, 0x1d65f, 1},
		{0x1d692, 0x1d693, 1},
		{0x1df1a, 0x1e04c, 306},
		{0x1e04d, 0x1e068, 27},
	},
	LatinOffset: 1,
}

var _Terminal_Punctuation = &RangeTable{
	R16: []Range16{
		{0x0021, 0x002c, 11},
		{0x002e, 0x003a, 12},
		{0x003b, 0x003f, 4},
		{0x037e, 0x0387, 9},
		{0x0589, 0x05c3, 58},
		{0x060c, 0x061b, 15},
		{0x061d, 0x061f, 1},
		{0x06d4, 0x0700, 44},
		{0x0701, 0x070a, 1},
		{0x070c, 0x07f8, 236},
		{0x07f9, 0x0830, 55},
		{0x0831, 0x083e, 1},
		{0x085e, 0x0964, 262},
		{0x0965, 0x0e5a, 1269},
		{0x0e5b, 0x0f08, 173},
		{0x0f0d, 0x0f12, 1},
		{0x104a, 0x104b, 1},
		{0x1361, 0x1368, 1},
		{0x166e, 0x16eb, 125},
		{0x16ec, 0x16ed, 1},
		{0x1735, 0x1736, 1},
		{0x17d4, 0x17d6, 1},
		{0x17da, 0x1802, 40},
		{0x1803, 0x1805, 1},
		{0x1808, 0x1809, 1},
		{0x1944, 0x1945, 1},
		{0x1aa8, 0x1aab, 1},
		{0x1b5a, 0x1b5b, 1},
		{0x1b5d, 0x1b5f, 1},
		{0x1b7d, 0x1b7e, 1},
		{0x1c3b, 0x1c3f, 1},
		{0x1c7e, 0x1c7f, 1},
		{0x203c, 0x203d, 1},
		{0x2047, 0x2049, 1},
		{0x2e2e, 0x2e3c, 14},
		{0x2e41, 0x2e4c, 11},
		{0x2e4e, 0x2e4f, 1},
		{0x2e53, 0x2e54, 1},
		{0x3001, 0x3002, 1},
		{0xa4fe, 0xa4ff, 1},
		{0xa60d, 0xa60f, 1},
		{0xa6f3, 0xa6f7, 1},
		{0xa876, 0xa877, 1},
		{0xa8ce, 0xa8cf, 1},
		{0xa92f, 0xa9c7, 152},
		{0xa9c8, 0xa9c9, 1},
		{0xaa5d, 0xaa5f, 1},
		{0xaadf, 0xaaf0, 17},
		{0xaaf1, 0xabeb, 250},
		{0xfe50, 0xfe52, 1},
		{0xfe54, 0xfe57, 1},
		{0xff01, 0xff0c, 11},
		{0xff0e, 0xff1a, 12},
		{0xff1b, 0xff1f, 4},
		{0xff61, 0xff64, 3},
	},
	R32: []Range32{
		{0x1039f, 0x103d0, 49},
		{0x10857, 0x1091f, 200},
		{0x10a56, 0x10a57, 1},
		{0x10af0, 0x10af5, 1},
		{0x10b3a, 0x10b3f, 1},
		{0x10b99, 0x10b9c, 1},
		{0x10f55, 0x10f59, 1},
		{0x10f86, 0x10f89, 1},
		{0x11047, 0x1104d, 1},
		{0x110be, 0x110c1, 1},
		{0x11141, 0x11143, 1},
		{0x111c5, 0x111c6, 1},
		{0x111cd, 0x111de, 17},
		{0x111df, 0x11238, 89},
		{0x11239, 0x1123c, 1},
		{0x112a9, 0x1144b, 418},
		{0x1144c, 0x1144d, 1},
		{0x1145a, 0x1145b, 1},
		{0x115c2, 0x115c5, 1},
		{0x115c9, 0x115d7, 1},
		{0x11641, 0x11642, 1},
		{0x1173c, 0x1173e, 1},
		{0x11944, 0x11946, 2},
		{0x11a42, 0x11a43, 1},
		{0x11a9b, 0x11a9c, 1},
		{0x11aa1, 0x11aa2, 1},
		{0x11c41, 0x11c43, 1},
		{0x11c71, 0x11ef7, 646},
		{0x11ef8, 0x11f43, 75},
		{0x11f44, 0x12470, 1324},
		{0x12471, 0x12474, 1},
		{0x16a6e, 0x16a6f, 1},
		{0x16af5, 0x16b37, 66},
		{0x16b38, 0x16b39, 1},
		{0x16b44, 0x16e97, 851},
		{0x16e98, 0x1bc9f, 19975},
		{0x1da87, 0x1da8a, 1},
	},
	LatinOffset: 3,
}

var _Unified_Ideograph = &RangeTable{
	R16: []Range16{
		{0x3400, 0x4dbf, 1},
		{0x4e00, 0x9fff, 1},
		{0xfa0e, 0xfa0f, 1},
		{0xfa11, 0xfa13, 2},
		{0xfa14, 0xfa1f, 11},
		{0xfa21, 0xfa23, 2},
		{0xfa24, 0xfa27, 3},
		{0xfa28, 0xfa29, 1},
	},
	R32: []Range32{
		{0x20000, 0x2a6df, 1},
		{0x2a700, 0x2b739, 1},
		{0x2b740, 0x2b81d, 1},
		{0x2b820, 0x2cea1, 1},
		{0x2ceb0, 0x2ebe0, 1},
		{0x30000, 0x3134a, 1},
		{0x31350, 0x323af, 1},
	},
}

var _Variation_Selector = &RangeTable{
	R16: []Range16{
		{0x180b, 0x180d, 1},
		{0x180f, 0xfe00, 58865},
		{0xfe01, 0xfe0f, 1},
	},
	R32: []Range32{
		{0xe0100, 0xe01ef, 1},
	},
}

var _White_Space = &RangeTable{
	R16: []Range16{
		{0x0009, 0x000d, 1},
		{0x0020, 0x0085, 101},
		{0x00a0, 0x1680, 5600},
		{0x2000, 0x200a, 1},
		{0x2028, 0x2029, 1},
		{0x202f, 0x205f, 48},
		{0x3000, 0x3000, 1},
	},
	LatinOffset: 2,
}

// These variables have type *RangeTable.
var (
	ASCII_Hex_Digit                    = _ASCII_Hex_Digit                    // ASCII_Hex_Digit is the set of Unicode characters with property ASCII_Hex_Digit.
	Bidi_Control                       = _Bidi_Control                       // Bidi_Control is the set of Unicode characters with property Bidi_Control.
	Dash                               = _Dash                               // Dash is the set of Unicode characters with property Dash.
	Deprecated                         = _Deprecated                         // Deprecated is the set of Unicode characters with property Deprecated.
	Diacritic                          = _Diacritic                          // Diacritic is the set of Unicode characters with property Diacritic.
	Extender                           = _Extender                           // Extender is the set of Unicode characters with property Extender.
	Hex_Digit                          = _Hex_Digit                          // Hex_Digit is the set of Unicode characters with property Hex_Digit.
	Hyphen                             = _Hyphen                             // Hyphen is the set of Unicode characters with property Hyphen.
	IDS_Binary_Operator                = _IDS_Binary_Operator                // IDS_Binary_Operator is the set of Unicode characters with property IDS_Binary_Operator.
	IDS_Trinary_Operator               = _IDS_Trinary_Operator               // IDS_Trinary_Operator is the set of Unicode characters with property IDS_Trinary_Operator.
	Ideographic                        = _Ideographic                        // Ideographic is the set of Unicode characters with property Ideographic.
	Join_Control                       = _Join_Control                       // Join_Control is the set of Unicode characters with property Join_Control.
	Logical_Order_Exception            = _Logical_Order_Exception            // Logical_Order_Exception is the set of Unicode characters with property Logical_Order_Exception.
	Noncharacter_Code_Point            = _Noncharacter_Code_Point            // Noncharacter_Code_Point is the set of Unicode characters with property Noncharacter_Code_Point.
	Other_Alphabetic                   = _Other_Alphabetic                   // Other_Alphabetic is the set of Unicode characters with property Other_Alphabetic.
	Other_Default_Ignorable_Code_Point = _Other_Default_Ignorable_Code_Point // Other_Default_Ignorable_Code_Point is the set of Unicode characters with property Other_Default_Ignorable_Code_Point.
	Other_Grapheme_Extend              = _Other_Grapheme_Extend              // Other_Grapheme_Extend is the set of Unicode characters with property Other_Grapheme_Extend.
	Other_ID_Continue                  = _Other_ID_Continue                  // Other_ID_Continue is the set of Unicode characters with property Other_ID_Continue.
	Other_ID_Start                     = _Other_ID_Start                     // Other_ID_Start is the set of Unicode characters with property Other_ID_Start.
	Other_Lowercase                    = _Other_Lowercase                    // Other_Lowercase is the set of Unicode characters with property Other_Lowercase.
	Other_Math                         = _Other_Math                         // Other_Math is the set of Unicode characters with property Other_Math.
	Other_Uppercase                    = _Other_Uppercase                    // Other_Uppercase is the set of Unicode characters with property Other_Uppercase.
	Pattern_Syntax                     = _Pattern_Syntax                     // Pattern_Syntax is the set of Unicode characters with property Pattern_Syntax.
	Pattern_White_Space                = _Pattern_White_Space                // Pattern_White_Space is the set of Unicode characters with property Pattern_White_Space.
	Prepended_Concatenation_Mark       = _Prepended_Concatenation_Mark       // Prepended_Concatenation_Mark is the set of Unicode characters with property Prepended_Concatenation_Mark.
	Quotation_Mark                     = _Quotation_Mark                     // Quotation_Mark is the set of Unicode characters with property Quotation_Mark.
	Radical                            = _Radical                            // Radical is the set of Unicode characters with property Radical.
	Regional_Indicator                 = _Regional_Indicator                 // Regional_Indicator is the set of Unicode characters with property Regional_Indicator.
	STerm                              = _Sentence_Terminal                  // STerm is an alias for Sentence_Terminal.
	Sentence_Terminal                  = _Sentence_Terminal                  // Sentence_Terminal is the set of Unicode characters with property Sentence_Terminal.
	Soft_Dotted                        = _Soft_Dotted                        // Soft_Dotted is the set of Unicode characters with property Soft_Dotted.
	Terminal_Punctuation               = _Terminal_Punctuation               // Terminal_Punctuation is the set of Unicode characters with property Terminal_Punctuation.
	Unified_Ideograph                  = _Unified_Ideograph                  // Unified_Ideograph is the set of Unicode characters with property Unified_Ideograph.
	Variation_Selector                 = _Variation_Selector                 // Variation_Selector is the set of Unicode characters with property Variation_Selector.
	White_Space                        = _White_Space                        // White_Space is the set of Unicode characters with property White_Space.
)

// CaseRanges is the table describing case mappings for all letters with
// non-self mappings.
var CaseRanges = _CaseRanges
var _CaseRanges = []CaseRange{
	{0x0041, 0x005A, d{0, 32, 0}},
	{0x0061, 0x007A, d{-32, 0, -32}},
	{0x00B5, 0x00B5, d{743, 0, 743}},
	{0x00C0, 0x00D6, d{0, 32, 0}},
	{0x00D8, 0x00DE, d{0, 32, 0}},
	{0x00E0, 0x00F6, d{-32, 0, -32}},
	{0x00F8, 0x00FE, d{-32, 0, -32}},
	{0x00FF, 0x00FF, d{121, 0, 121}},
	{0x0100, 0x012F, d{UpperLower, UpperLower, UpperLower}},
	{0x0130, 0x0130, d{0, -199, 0}},
	{0x0131, 0x0131, d{-232, 0, -232}},
	{0x0132, 0x0137, d{UpperLower, UpperLower, UpperLower}},
	{0x0139, 0x0148, d{UpperLower, UpperLower, UpperLower}},
	{0x014A, 0x0177, d{UpperLower, UpperLower, UpperLower}},
	{0x0178, 0x0178, d{0, -121, 0}},
	{0x0179, 0x017E, d{UpperLower, UpperLower, UpperLower}},
	{0x017F, 0x017F, d{-300, 0, -300}},
	{0x0180, 0x0180, d{195, 0, 195}},
	{0x0181, 0x0181, d{0, 210, 0}},
	{0x0182, 0x0185, d{UpperLower, UpperLower, UpperLower}},
	{0x0186, 0x0186, d{0, 206, 0}},
	{0x0187, 0x0188, d{UpperLower, UpperLower, UpperLower}},
	{0x0189, 0x018A, d{0, 205, 0}},
	{0x018B, 0x018C, d{UpperLower, UpperLower, UpperLower}},
	{0x018E, 0x018E, d{0, 79, 0}},
	{0x018F, 0x018F, d{0, 202, 0}},
	{0x0190, 0x0190, d{0, 203, 0}},
	{0x0191, 0x0192, d{UpperLower, UpperLower, UpperLower}},
	{0x0193, 0x0193, d{0, 205, 0}},
	{0x0194, 0x0194, d{0, 207, 0}},
	{0x0195, 0x0195, d{97, 0, 97}},
	{0x0196, 0x0196, d{0, 211, 0}},
	{0x0197, 0x0197, d{0, 209, 0}},
	{0x0198, 0x0199, d{UpperLower, UpperLower, UpperLower}},
	{0x019A, 0x019A, d{163, 0, 163}},
	{0x019C, 0x019C, d{0, 211, 0}},
	{0x019D, 0x019D, d{0, 213, 0}},
	{0x019E, 0x019E, d{130, 0, 130}},
	{0x019F, 0x019F, d{0, 214, 0}},
	{0x01A0, 0x01A5, d{UpperLower, UpperLower, UpperLower}},
	{0x01A6, 0x01A6, d{0, 218, 0}},
	{0x01A7, 0x01A8, d{UpperLower, UpperLower, UpperLower}},
	{0x01A9, 0x01A9, d{0, 218, 0}},
	{0x01AC, 0x01AD, d{UpperLower, UpperLower, UpperLower}},
	{0x01AE, 0x01AE, d{0, 218, 0}},
	{0x01AF, 0x01B0, d{UpperLower, UpperLower, UpperLower}},
	{0x01B1, 0x01B2, d{0, 217, 0}},
	{0x01B3, 0x01B6, d{UpperLower, UpperLower, UpperLower}},
	{0x01B7, 0x01B7, d{0, 219, 0}},
	{0x01B8, 0x01B9, d{UpperLower, UpperLower, UpperLower}},
	{0x01BC, 0x01BD, d{UpperLower, UpperLower, UpperLower}},
	{0x01BF, 0x01BF, d{56, 0, 56}},
	{0x01C4, 0x01C4, d{0, 2, 1}},
	{0x01C5, 0x01C5, d{-1, 1, 0}},
	{0x01C6, 0x01C6, d{-2, 0, -1}},
	{0x01C7, 0x01C7, d{0, 2, 1}},
	{0x01C8, 0x01C8, d{-1, 1, 0}},
	{0x01C9, 0x01C9, d{-2, 0, -1}},
	{0x01CA, 0x01CA, d{0, 2, 1}},
	{0x01CB, 0x01CB, d{-1, 1, 0}},
	{0x01CC, 0x01CC, d{-2, 0, -1}},
	{0x01CD, 0x01DC, d{UpperLower, UpperLower, UpperLower}},
	{0x01DD, 0x01DD, d{-79, 0, -79}},
	{0x01DE, 0x01EF, d{UpperLower, UpperLower, UpperLower}},
	{0x01F1, 0x01F1, d{0, 2, 1}},
	{0x01F2, 0x01F2, d{-1, 1, 0}},
	{0x01F3, 0x01F3, d{-2, 0, -1}},
	{0x01F4, 0x01F5, d{UpperLower, UpperLower, UpperLower}},
	{0x01F6, 0x01F6, d{0, -97, 0}},
	{0x01F7, 0x01F7, d{0, -56, 0}},
	{0x01F8, 0x021F, d{UpperLower, UpperLower, UpperLower}},
	{0x0220, 0x0220, d{0, -130, 0}},
	{0x0222, 0x0233, d{UpperLower, UpperLower, UpperLower}},
	{0x023A, 0x023A, d{0, 10795, 0}},
	{0x023B, 0x023C, d{UpperLower, UpperLower, UpperLower}},
	{0x023D, 0x023D, d{0, -163, 0}},
	{0x023E, 0x023E, d{0, 10792, 0}},
	{0x023F, 0x0240, d{10815, 0, 10815}},
	{0x0241, 0x0242, d{UpperLower, UpperLower, UpperLower}},
	{0x0243, 0x0243, d{0, -195, 0}},
	{0x0244, 0x0244, d{0, 69, 0}},
	{0x0245, 0x0245, d{0, 71, 0}},
	{0x0246, 0x024F, d{UpperLower, UpperLower, UpperLower}},
	{0x0250, 0x0250, d{10783, 0, 10783}},
	{0x0251, 0x0251, d{10780, 0, 10780}},
	{0x0252, 0x0252, d{10782, 0, 10782}},
	{0x0253, 0x0253, d{-210, 0, -210}},
	{0x0254, 0x0254, d{-206, 0, -206}},
	{0x0256, 0x0257, d{-205, 0, -205}},
	{0x0259, 0x0259, d{-202, 0, -202}},
	{0x025B, 0x025B, d{-203, 0, -203}},
	{0x025C, 0x025C, d{42319, 0, 42319}},
	{0x0260, 0x0260, d{-205, 0, -205}},
	{0x0261, 0x0261, d{42315, 0, 42315}},
	{0x0263, 0x0263, d{-207, 0, -207}},
	{0x0265, 0x0265, d{42280, 0, 42280}},
	{0x0266, 0x0266, d{42308, 0, 42308}},
	{0x0268, 0x0268, d{-209, 0, -209}},
	{0x0269, 0x0269, d{-211, 0, -211}},
	{0x026A, 0x026A, d{42308, 0, 42308}},
	{0x026B, 0x026B, d{10743, 0, 10743}},
	{0x026C, 0x026C, d{42305, 0, 42305}},
	{0x026F, 0x026F, d{-211, 0, -211}},
	{0x0271, 0x0271, d{10749, 0, 10749}},
	{0x0272, 0x0272, d{-213, 0, -213}},
	{0x0275, 0x0275, d{-214, 0, -214}},
	{0x027D, 0x027D, d{10727, 0, 10727}},
	{0x0280, 0x0280, d{-218, 0, -218}},
	{0x0282, 0x0282, d{42307, 0, 42307}},
	{0x0283, 0x0283, d{-218, 0, -218}},
	{0x0287, 0x0287, d{42282, 0, 42282}},
	{0x0288, 0x0288, d{-218, 0, -218}},
	{0x0289, 0x0289, d{-69, 0, -69}},
	{0x028A, 0x028B, d{-217, 0, -217}},
	{0x028C, 0x028C, d{-71, 0, -71}},
	{0x0292, 0x0292, d{-219, 0, -219}},
	{0x029D, 0x029D, d{42261, 0, 42261}},
	{0x029E, 0x029E, d{42258, 0, 42258}},
	{0x0345, 0x0345, d{84, 0, 84}},
	{0x0370, 0x0373, d{UpperLower, UpperLower, UpperLower}},
	{0x0376, 0x0377, d{UpperLower, UpperLower, UpperLower}},
	{0x037B, 0x037D, d{130, 0, 130}},
	{0x037F, 0x037F, d{0, 116, 0}},
	{0x0386, 0x0386, d{0, 38, 0}},
	{0x0388, 0x038A, d{0, 37, 0}},
	{0x038C, 0x038C, d{0, 64, 0}},
	{0x038E, 0x038F, d{0, 63, 0}},
	{0x0391, 0x03A1, d{0, 32, 0}},
	{0x03A3, 0x03AB, d{0, 32, 0}},
	{0x03AC, 0x03AC, d{-38, 0, -38}},
	{0x03AD, 0x03AF, d{-37, 0, -37}},
	{0x03B1, 0x03C1, d{-32, 0, -32}},
	{0x03C2, 0x03C2, d{-31, 0, -31}},
	{0x03C3, 0x03CB, d{-32, 0, -32}},
	{0x03CC, 0x03CC, d{-64, 0, -64}},
	{0x03CD, 0x03CE, d{-63, 0, -63}},
	{0x03CF, 0x03CF, d{0, 8, 0}},
	{0x03D0, 0x03D0, d{-62, 0, -62}},
	{0x03D1, 0x03D1, d{-57, 0, -57}},
	{0x03D5, 0x03D5, d{-47, 0, -47}},
	{0x03D6, 0x03D6, d{-54, 0, -54}},
	{0x03D7, 0x03D7, d{-8, 0, -8}},
	{0x03D8, 0x03EF, d{UpperLower, UpperLower, UpperLower}},
	{0x03F0, 0x03F0, d{-86, 0, -86}},
	{0x03F1, 0x03F1, d{-80, 0, -80}},
	{0x03F2, 0x03F2, d{7, 0, 7}},
	{0x03F3, 0x03F3, d{-116, 0, -116}},
	{0x03F4, 0x03F4, d{0, -60, 0}},
	{0x03F5, 0x03F5, d{-96, 0, -96}},
	{0x03F7, 0x03F8, d{UpperLower, UpperLower, UpperLower}},
	{0x03F9, 0x03F9, d{0, -7, 0}},
	{0x03FA, 0x03FB, d{UpperLower, UpperLower, UpperLower}},
	{0x03FD, 0x03FF, d{0, -130, 0}},
	{0x0400, 0x040F, d{0, 80, 0}},
	{0x0410, 0x042F, d{0, 32, 0}},
	{0x0430, 0x044F, d{-32, 0, -32}},
	{0x0450, 0x045F, d{-80, 0, -80}},
	{0x0460, 0x0481, d{UpperLower, UpperLower, UpperLower}},
	{0x048A, 0x04BF, d{UpperLower, UpperLower, UpperLower}},
	{0x04C0, 0x04C0, d{0, 15, 0}},
	{0x04C1, 0x04CE, d{UpperLower, UpperLower, UpperLower}},
	{0x04CF, 0x04CF, d{-15, 0, -15}},
	{0x04D0, 0x052F, d{UpperLower, UpperLower, UpperLower}},
	{0x0531, 0x0556, d{0, 48, 0}},
	{0x0561, 0x0586, d{-48, 0, -48}},
	{0x10A0, 0x10C5, d{0, 7264, 0}},
	{0x10C7, 0x10C7, d{0, 7264, 0}},
	{0x10CD, 0x10CD, d{0, 7264, 0}},
	{0x10D0, 0x10FA, d{3008, 0, 0}},
	{0x10FD, 0x10FF, d{3008, 0, 0}},
	{0x13A0, 0x13EF, d{0, 38864, 0}},
	{0x13F0, 0x13F5, d{0, 8, 0}},
	{0x13F8, 0x13FD, d{-8, 0, -8}},
	{0x1C80, 0x1C80, d{-6254, 0, -6254}},
	{0x1C81, 0x1C81, d{-6253, 0, -6253}},
	{0x1C82, 0x1C82, d{-6244, 0, -6244}},
	{0x1C83, 0x1C84, d{-6242, 0, -6242}},
	{0x1C85, 0x1C85, d{-6243, 0, -6243}},
	{0x1C86, 0x1C86, d{-6236, 0, -6236}},
	{0x1C87, 0x1C87, d{-6181, 0, -6181}},
	{0x1C88, 0x1C88, d{35266, 0, 35266}},
	{0x1C90, 0x1CBA, d{0, -3008, 0}},
	{0x1CBD, 0x1CBF, d{0, -3008, 0}},
	{0x1D79, 0x1D79, d{35332, 0, 35332}},
	{0x1D7D, 0x1D7D, d{3814, 0, 3814}},
	{0x1D8E, 0x1D8E, d{35384, 0, 35384}},
	{0x1E00, 0x1E95, d{UpperLower, UpperLower, UpperLower}},
	{0x1E9B, 0x1E9B, d{-59, 0, -59}},
	{0x1E9E, 0x1E9E, d{0, -7615, 0}},
	{0x1EA0, 0x1EFF, d{UpperLower, UpperLower, UpperLower}},
	{0x1F00, 0x1F07, d{8, 0, 8}},
	{0x1F08, 0x1F0F, d{0, -8, 0}},
	{0x1F10, 0x1F15, d{8, 0, 8}},
	{0x1F18, 0x1F1D, d{0, -8, 0}},
	{0x1F20, 0x1F27, d{8, 0, 8}},
	{0x1F28, 0x1F2F, d{0, -8, 0}},
	{0x1F30, 0x1F37, d{8, 0, 8}},
	{0x1F38, 0x1F3F, d{0, -8, 0}},
	{0x1F40, 0x1F45, d{8, 0, 8}},
	{0x1F48, 0x1F4D, d{0, -8, 0}},
	{0x1F51, 0x1F51, d{8, 0, 8}},
	{0x1F53, 0x1F53, d{8, 0, 8}},
	{0x1F55, 0x1F55, d{8, 0, 8}},
	{0x1F57, 0x1F57, d{8, 0, 8}},
	{0x1F59, 0x1F59, d{0, -8, 0}},
	{0x1F5B, 0x1F5B, d{0, -8, 0}},
	{0x1F5D, 0x1F5D, d{0, -8, 0}},
	{0x1F5F, 0x1F5F, d{0, -8, 0}},
	{0x1F60, 0x1F67, d{8, 0, 8}},
	{0x1F68, 0x1F6F, d{0, -8, 0}},
	{0x1F70, 0x1F71, d{74, 0, 74}},
	{0x1F72, 0x1F75, d{86, 0, 86}},
	{0x1F76, 0x1F77, d{100, 0, 100}},
	{0x1F78, 0x1F79, d{128, 0, 128}},
	{0x1F7A, 0x1F7B, d{112, 0, 112}},
	{0x1F7C, 0x1F7D, d{126, 0, 126}},
	{0x1F80, 0x1F87, d{8, 0, 8}},
	{0x1F88, 0x1F8F, d{0, -8, 0}},
	{0x1F90, 0x1F97, d{8, 0, 8}},
	{0x1F98, 0x1F9F, d{0, -8, 0}},
	{0x1FA0, 0x1FA7, d{8, 0, 8}},
	{0x1FA8, 0x1FAF, d{0, -8, 0}},
	{0x1FB0, 0x1FB1, d{8, 0, 8}},
	{0x1FB3, 0x1FB3, d{9, 0, 9}},
	{0x1FB8, 0x1FB9, d{0, -8, 0}},
	{0x1FBA, 0x1FBB, d{0, -74, 0}},
	{0x1FBC, 0x1FBC, d{0, -9, 0}},
	{0x1FBE, 0x1FBE, d{-7205, 0, -7205}},
	{0x1FC3, 0x1FC3, d{9, 0, 9}},
	{0x1FC8, 0x1FCB, d{0, -86, 0}},
	{0x1FCC, 0x1FCC, d{0, -9, 0}},
	{0x1FD0, 0x1FD1, d{8, 0, 8}},
	{0x1FD8, 0x1FD9, d{0, -8, 0}},
	{0x1FDA, 0x1FDB, d{0, -100, 0}},
	{0x1FE0, 0x1FE1, d{8, 0, 8}},
	{0x1FE5, 0x1FE5, d{7, 0, 7}},
	{0x1FE8, 0x1FE9, d{0, -8, 0}},
	{0x1FEA, 0x1FEB, d{0, -112, 0}},
	{0x1FEC, 0x1FEC, d{0, -7, 0}},
	{0x1FF3, 0x1FF3, d{9, 0, 9}},
	{0x1FF8, 0x1FF9, d{0, -128, 0}},
	{0x1FFA, 0x1FFB, d{0, -126, 0}},
	{0x1FFC, 0x1FFC, d{0, -9, 0}},
	{0x2126, 0x2126, d{0, -7517, 0}},
	{0x212A, 0x212A, d{0, -8383, 0}},
	{0x212B, 0x212B, d{0, -8262, 0}},
	{0x2132, 0x2132, d{0, 28, 0}},
	{0x214E, 0x214E, d{-28, 0, -28}},
	{0x2160, 0x216F, d{0, 16, 0}},
	{0x2170, 0x217F, d{-16, 0, -16}},
	{0x2183, 0x2184, d{UpperLower, UpperLower, UpperLower}},
	{0x24B6, 0x24CF, d{0, 26, 0}},
	{0x24D0, 0x24E9, d{-26, 0, -26}},
	{0x2C00, 0x2C2F, d{0, 48, 0}},
	{0x2C30, 0x2C5F, d{-48, 0, -48}},
	{0x2C60, 0x2C61, d{UpperLower, UpperLower, UpperLower}},
	{0x2C62, 0x2C62, d{0, -10743, 0}},
	{0x2C63, 0x2C63, d{0, -3814, 0}},
	{0x2C64, 0x2C64, d{0, -10727, 0}},
	{0x2C65, 0x2C65, d{-10795, 0, -10795}},
	{0x2C66, 0x2C66, d{-10792, 0, -10792}},
	{0x2C67, 0x2C6C, d{UpperLower, UpperLower, UpperLower}},
	{0x2C6D, 0x2C6D, d{0, -10780, 0}},
	{0x2C6E, 0x2C6E, d{0, -10749, 0}},
	{0x2C6F, 0x2C6F, d{0, -10783, 0}},
	{0x2C70, 0x2C70, d{0, -10782, 0}},
	{0x2C72, 0x2C73, d{UpperLower, UpperLower, UpperLower}},
	{0x2C75, 0x2C76, d{UpperLower, UpperLower, UpperLower}},
	{0x2C7E, 0x2C7F, d{0, -10815, 0}},
	{0x2C80, 0x2CE3, d{UpperLower, UpperLower, UpperLower}},
	{0x2CEB, 0x2CEE, d{UpperLower, UpperLower, UpperLower}},
	{0x2CF2, 0x2CF3, d{UpperLower, UpperLower, UpperLower}},
	{0x2D00, 0x2D25, d{-7264, 0, -7264}},
	{0x2D27, 0x2D27, d{-7264, 0, -7264}},
	{0x2D2D, 0x2D2D, d{-7264, 0, -7264}},
	{0xA640, 0xA66D, d{UpperLower, UpperLower, UpperLower}},
	{0xA680, 0xA69B, d{UpperLower, UpperLower, UpperLower}},
	{0xA722, 0xA72F, d{UpperLower, UpperLower, UpperLower}},
	{0xA732, 0xA76F, d{UpperLower, UpperLower, UpperLower}},
	{0xA779, 0xA77C, d{UpperLower, UpperLower, UpperLower}},
	{0xA77D, 0xA77D, d{0, -35332, 0}},
	{0xA77E, 0xA787, d{UpperLower, UpperLower, UpperLower}},
	{0xA78B, 0xA78C, d{UpperLower, UpperLower, UpperLower}},
	{0xA78D, 0xA78D, d{0, -42280, 0}},
	{0xA790, 0xA793, d{UpperLower, UpperLower, UpperLower}},
	{0xA794, 0xA794, d{48, 0, 48}},
	{0xA796, 0xA7A9, d{UpperLower, UpperLower, UpperLower}},
	{0xA7AA, 0xA7AA, d{0, -42308, 0}},
	{0xA7AB, 0xA7AB, d{0, -42319, 0}},
	{0xA7AC, 0xA7AC, d{0, -42315, 0}},
	{0xA7AD, 0xA7AD, d{0, -42305, 0}},
	{0xA7AE, 0xA7AE, d{0, -42308, 0}},
	{0xA7B0, 0xA7B0, d{0, -42258, 0}},
	{0xA7B1, 0xA7B1, d{0, -42282, 0}},
	{0xA7B2, 0xA7B2, d{0, -42261, 0}},
	{0xA7B3, 0xA7B3, d{0, 928, 0}},
	{0xA7B4, 0xA7C3, d{UpperLower, UpperLower, UpperLower}},
	{0xA7C4, 0xA7C4, d{0, -48, 0}},
	{0xA7C5, 0xA7C5, d{0, -42307, 0}},
	{0xA7C6, 0xA7C6, d{0, -35384, 0}},
	{0xA7C7, 0xA7CA, d{UpperLower, UpperLower, UpperLower}},
	{0xA7D0, 0xA7D1, d{UpperLower, UpperLower, UpperLower}},
	{0xA7D6, 0xA7D9, d{UpperLower, UpperLower, UpperLower}},
	{0xA7F5, 0xA7F6, d{UpperLower, UpperLower, UpperLower}},
	{0xAB53, 0xAB53, d{-928, 0, -928}},
	{0xAB70, 0xABBF, d{-38864, 0, -38864}},
	{0xFF21, 0xFF3A, d{0, 32, 0}},
	{0xFF41, 0xFF5A, d{-32, 0, -32}},
	{0x10400, 0x10427, d{0, 40, 0}},
	{0x10428, 0x1044F, d{-40, 0, -40}},
	{0x104B0, 0x104D3, d{0, 40, 0}},
	{0x104D8, 0x104FB, d{-40, 0, -40}},
	{0x10570, 0x1057A, d{0, 39, 0}},
	{0x1057C, 0x1058A, d{0, 39, 0}},
	{0x1058C, 0x10592, d{0, 39, 0}},
	{0x10594, 0x10595, d{0, 39, 0}},
	{0x10597, 0x105A1, d{-39, 0, -39}},
	{0x105A3, 0x105B1, d{-39, 0, -39}},
	{0x105B3, 0x105B9, d{-39, 0, -39}},
	{0x105BB, 0x105BC, d{-39, 0, -39}},
	{0x10C80, 0x10CB2, d{0, 64, 0}},
	{0x10CC0, 0x10CF2, d{-64, 0, -64}},
	{0x118A0, 0x118BF, d{0, 32, 0}},
	{0x118C0, 0x118DF, d{-32, 0, -32}},
	{0x16E40, 0x16E5F, d{0, 32, 0}},
	{0x16E60, 0x16E7F, d{-32, 0, -32}},
	{0x1E900, 0x1E921, d{0, 34, 0}},
	{0x1E922, 0x1E943, d{-34, 0, -34}},
}
var properties = [MaxLatin1 + 1]uint8{
	0x00: pC,       // '\x00'
	0x01: pC,       // '\x01'
	0x02: pC,       // '\x02'
	0x03: pC,       // '\x03'
	0x04: pC,       // '\x04'
	0x05: pC,       // '\x05'
	0x06: pC,       // '\x06'
	0x07: pC,       // '\a'
	0x08: pC,       // '\b'
	0x09: pC,       // '\t'
	0x0A: pC,       // '\n'
	0x0B: pC,       // '\v'
	0x0C: pC,       // '\f'
	0x0D: pC,       // '\r'
	0x0E: pC,       // '\x0e'
	0x0F: pC,       // '\x0f'
	0x10: pC,       // '\x10'
	0x11: pC,       // '\x11'
	0x12: pC,       // '\x12'
	0x13: pC,       // '\x13'
	0x14: pC,       // '\x14'
	0x15: pC,       // '\x15'
	0x16: pC,       // '\x16'
	0x17: pC,       // '\x17'
	0x18: pC,       // '\x18'
	0x19: pC,       // '\x19'
	0x1A: pC,       // '\x1a'
	0x1B: pC,       // '\x1b'
	0x1C: pC,       // '\x1c'
	0x1D: pC,       // '\x1d'
	0x1E: pC,       // '\x1e'
	0x1F: pC,       // '\x1f'
	0x20: pZ | pp,  // ' '
	0x21: pP | pp,  // '!'
	0x22: pP | pp,  // '"'
	0x23: pP | pp,  // '#'
	0x24: pS | pp,  // '$'
	0x25: pP | pp,  // '%'
	0x26: pP | pp,  // '&'
	0x27: pP | pp,  // '\''
	0x28: pP | pp,  // '('
	0x29: pP | pp,  // ')'
	0x2A: pP | pp,  // '*'
	0x2B: pS | pp,  // '+'
	0x2C: pP | pp,  // ','
	0x2D: pP | pp,  // '-'
	0x2E: pP | pp,  // '.'
	0x2F: pP | pp,  // '/'
	0x30: pN | pp,  // '0'
	0x31: pN | pp,  // '1'
	0x32: pN | pp,  // '2'
	0x33: pN | pp,  // '3'
	0x34: pN | pp,  // '4'
	0x35: pN | pp,  // '5'
	0x36: pN | pp,  // '6'
	0x37: pN | pp,  // '7'
	0x38: pN | pp,  // '8'
	0x39: pN | pp,  // '9'
	0x3A: pP | pp,  // ':'
	0x3B: pP | pp,  // ';'
	0x3C: pS | pp,  // '<'
	0x3D: pS | pp,  // '='
	0x3E: pS | pp,  // '>'
	0x3F: pP | pp,  // '?'
	0x40: pP | pp,  // '@'
	0x41: pLu | pp, // 'A'
	0x42: pLu | pp, // 'B'
	0x43: pLu | pp, // 'C'
	0x44: pLu | pp, // 'D'
	0x45: pLu | pp, // 'E'
	0x46: pLu | pp, // 'F'
	0x47: pLu | pp, // 'G'
	0x48: pLu | pp, // 'H'
	0x49: pLu | pp, // 'I'
	0x4A: pLu | pp, // 'J'
	0x4B: pLu | pp, // 'K'
	0x4C: pLu | pp, // 'L'
	0x4D: pLu | pp, // 'M'
	0x4E: pLu | pp, // 'N'
	0x4F: pLu | pp, // 'O'
	0x50: pLu | pp, // 'P'
	0x51: pLu | pp, // 'Q'
	0x52: pLu | pp, // 'R'
	0x53: pLu | pp, // 'S'
	0x54: pLu | pp, // 'T'
	0x55: pLu | pp, // 'U'
	0x56: pLu | pp, // 'V'
	0x57: pLu | pp, // 'W'
	0x58: pLu | pp, // 'X'
	0x59: pLu | pp, // 'Y'
	0x5A: pLu | pp, // 'Z'
	0x5B: pP | pp,  // '['
	0x5C: pP | pp,  // '\\'
	0x5D: pP | pp,  // ']'
	0x5E: pS | pp,  // '^'
	0x5F: pP | pp,  // '_'
	0x60: pS | pp,  // '`'
	0x61: pLl | pp, // 'a'
	0x62: pLl | pp, // 'b'
	0x63: pLl | pp, // 'c'
	0x64: pLl | pp, // 'd'
	0x65: pLl | pp, // 'e'
	0x66: pLl | pp, // 'f'
	0x67: pLl | pp, // 'g'
	0x68: pLl | pp, // 'h'
	0x69: pLl | pp, // 'i'
	0x6A: pLl | pp, // 'j'
	0x6B: pLl | pp, // 'k'
	0x6C: pLl | pp, // 'l'
	0x6D: pLl | pp, // 'm'
	0x6E: pLl | pp, // 'n'
	0x6F: pLl | pp, // 'o'
	0x70: pLl | pp, // 'p'
	0x71: pLl | pp, // 'q'
	0x72: pLl | pp, // 'r'
	0x73: pLl | pp, // 's'
	0x74: pLl | pp, // 't'
	0x75: pLl | pp, // 'u'
	0x76: pLl | pp, // 'v'
	0x77: pLl | pp, // 'w'
	0x78: pLl | pp, // 'x'
	0x79: pLl | pp, // 'y'
	0x7A: pLl | pp, // 'z'
	0x7B: pP | pp,  // '{'
	0x7C: pS | pp,  // '|'
	0x7D: pP | pp,  // '}'
	0x7E: pS | pp,  // '~'
	0x7F: pC,       // '\x7f'
	0x80: pC,       // '\u0080'
	0x81: pC,       // '\u0081'
	0x82: pC,       // '\u0082'
	0x83: pC,     
"""




```