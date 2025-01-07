Response:
My thought process to arrive at the summary of the provided Go code snippet goes like this:

1. **Identify the File and Language:** The prompt explicitly states the file path (`go/src/unicode/tables.go`) and the language (Go). This immediately tells me the code is part of the Go standard library, specifically related to Unicode support.

2. **Examine the Data Structure:** The code primarily consists of Go structs named `RangeTable` and several variables initialized with literal values of this struct. The `RangeTable` struct has fields `R16` and `R32`, which are slices of `Range16` and `Range32` structs, respectively. These inner structs likely represent ranges of Unicode code points.

3. **Analyze the Data within the Structs:** I observe that each `Range16` and `Range32` struct contains three fields: a start value, an end value, and a step value (always 1 in this snippet, but the name implies it could be different). This strongly suggests that these are defining *contiguous* or nearly contiguous ranges of Unicode code points. The start and end values are hexadecimal, further reinforcing the Unicode association.

4. **Connect the Variable Names to Unicode Properties:**  The variable names like `_Pc`, `_Pd`, `_Pe`, `_Pf`, `_Pi`, `_Po`, `_Ps`, `_S`, `_Sc`, `_Sk`, `_Sm`, `_So`, `_Z`, `_Zl`, `_Zp`, `_Zs` and the later `Cc`, `Cf`, `Co`, `Cs`, `Digit`, `Nd`, `Letter`, `L`, etc., are clearly abbreviations for Unicode character properties or categories. The leading underscore often indicates an internal or private variable.

5. **Infer the Purpose of Each Variable:** Based on the variable names and the `RangeTable` structure, I can deduce that each variable represents a *set* of Unicode characters belonging to a specific category (e.g., `_Pc` for Punctuation, Connector). The `RangeTable` acts as an efficient way to store these sets, especially when the characters are in continuous ranges.

6. **Recognize the "Scripts" Map:** The `Scripts` variable is a map where the keys are strings (like "Adlam", "Ahom") and the values are `*RangeTable`. This directly maps to the concept of Unicode scripts – collections of characters used by specific writing systems.

7. **Synthesize the Functionality:** Combining the above observations, the primary function of this code snippet is to **define and store data structures that represent various sets of Unicode characters, categorized by their general properties (like punctuation, symbols, letters, numbers, and separators) and by their script**.

8. **Formulate the Summary:**  Based on the synthesized functionality, I can now create a concise summary in Chinese, emphasizing the key aspects:
    * Definition of Unicode character properties and scripts.
    * Use of `RangeTable` for efficient storage of code point ranges.
    * Categorization of characters based on general categories (Punctuation, Symbol, etc.) and scripts.

9. **Refine the Language:** I ensure the Chinese terminology is accurate for Unicode concepts (e.g., “Unicode 字符属性”, “Unicode 脚本”). I also use clear and concise language to convey the information effectively.

This step-by-step analysis of the code's structure and naming conventions allows me to accurately deduce its purpose without needing to see the full implementation or know the intricacies of the Go `unicode` package beforehand. The provided snippet itself contains enough clues to understand its high-level function.
这段Go语言代码是 `go/src/unicode/tables.go` 文件的一部分，其主要功能是**定义了大量用于表示不同Unicode字符属性的查找表（Lookup Tables）**。这些查找表使用 `RangeTable` 结构体来存储字符码点的范围，从而高效地表示Unicode字符的不同类别和脚本。

**具体功能归纳:**

1. **定义了不同Unicode字符属性的 `RangeTable` 变量:**  例如 `_Pc`, `_Pd`, `_Pe`, `_Pf`, `_Pi`, `_Po`, `_Ps` 等，分别代表不同的标点符号类别 (Connector, Dash, Close, Final quote, Initial quote, Other, Open)。 `_S`, `_Sc`, `_Sk`, `_Sm`, `_So` 代表不同的符号类别 (Symbol, Currency, Modifier, Math, Other)。 `_Z`, `_Zl`, `_Zp`, `_Zs` 代表不同的分隔符类别 (Separator, Line, Paragraph, Space)。 还有 `_L`, `_Ll`, `_Lu`, `_Lt`, `_Lm`, `_Lo` 代表不同的字母类别 (Letter, Lowercase, Uppercase, Titlecase, Modifier, Other)。 以及 `_N`, `_Nd`, `_Nl`, `_No` 代表不同的数字类别 (Number, Decimal digit, Letter, Other)。`_C`, `_Cc`, `_Cf`, `_Co`, `_Cs` 代表 "Other" 类别 (Control, Format, Private Use, Surrogate)。

2. **定义了包含所有这些 `RangeTable` 变量的公共变量:** 例如 `Cc`, `Cf`, `Co`, `Cs`, `Digit`, `Nd`, `Letter`, `L`, `Lm`, `Lo`, `Lower`, `Ll`, `Mark`, `M`, `Mc`, `Me`, `Mn`, `Nl`, `No`, `Number`, `N`, `Other`, `C`, `Pc`, `Pd`, `Pe`, `Pf`, `Pi`, `Po`, `Ps`, `Punct`, `P`, `Sc`, `Sk`, `Sm`, `So`, `Space`, `Z`, `Symbol`, `S`, `Title`, `Lt`, `Upper`, `Lu`, `Zl`, `Zp`, `Zs`。这些公共变量移除了下划线前缀，并被导出，可以在其他 Go 代码中使用。

3. **定义了 Unicode 脚本的查找表 `Scripts`:**  这是一个 `map[string]*RangeTable`，键是脚本的名称（例如 "Adlam", "Ahom", "Arabic" 等），值是对应脚本包含的字符的 `RangeTable`。例如 `_Arabic` 变量就定义了阿拉伯语字符的范围。

**这段代码是 Go 语言 `unicode` 包实现其字符属性判断功能的基础数据。**  Go 的 `unicode` 包中的函数（例如 `unicode.IsPunct()`, `unicode.IsSpace()`, `unicode.IsLetter()` 等）会使用这些预定义的查找表来判断给定的 Unicode 字符是否属于特定的类别或脚本。

**Go 代码示例说明其功能:**

假设我们要判断一个字符是否是标点符号，可以使用 `unicode.IsPunct()` 函数。 该函数内部会利用此处定义的 `Punct` (`_P`) 这个 `RangeTable` 来进行判断。

```go
package main

import (
	"fmt"
	"unicode"
)

func main() {
	char1 := '?'
	char2 := 'A'
	char3 := ' '

	fmt.Printf("字符 '%c' 是标点符号吗? %t\n", char1, unicode.IsPunct(char1))
	fmt.Printf("字符 '%c' 是标点符号吗? %t\n", char2, unicode.IsPunct(char2))
	fmt.Printf("字符 '%c' 是标点符号吗? %t\n", char3, unicode.IsPunct(char3))
}
```

**假设的输入与输出:**

运行上述代码，输出如下：

```
字符 '?' 是标点符号吗? true
字符 'A' 是标点符号吗? false
字符 ' ' 是标点符号吗? false
```

**代码推理:**

`unicode.IsPunct('?')` 函数会检查字符 '?' 的 Unicode 码点是否落在 `_P` (`Punct`) 这个 `RangeTable` 中定义的任何一个范围内。 因为 '?' 的码点 (U+003F) 落在 `_Po` (Punctuation, Other) 的 `RangeTable` 中（具体可以查看代码中 `_Po` 的定义），所以 `unicode.IsPunct('?')` 返回 `true`。  同理，'A' 和 ' ' 的码点不在标点符号的范围内，所以返回 `false`。

**命令行参数的具体处理:**

这段代码本身不涉及命令行参数的处理。 它只是定义了静态的数据结构。 `unicode` 包的其他部分可能会接收字符作为输入，但 `tables.go` 主要负责提供这些查找表。

**使用者易犯错的点:**

这段代码是 Go 语言标准库的一部分，普通使用者不会直接修改它。 然而，理解其背后的原理有助于理解 Unicode 字符分类的概念，避免在处理文本时做出错误的假设。 例如，新手可能认为空格只有一个，但实际上 Unicode 定义了多种空格字符，它们可能属于不同的类别 (例如，不间断空格属于 `Zs`，但某些控制字符也可能被认为是空格)。

**归纳一下它的功能（针对第3部分）:**

这段代码定义了 Go 语言 `unicode` 包中用于表示以下**标点符号**和**其他符号**类别的 Unicode 字符范围查找表：

* **标点符号 (Punctuation):**
    * `_Pc`: 连接符标点 (Punctuation, Connector)
    * `_Pd`: 破折号标点 (Punctuation, Dash)
    * `_Pe`: 闭合标点 (Punctuation, Close)
    * `_Pf`: 结尾引号标点 (Punctuation, Final quote)
    * `_Pi`: 起始引号标点 (Punctuation, Initial quote)
    * `_Po`: 其他标点 (Punctuation, Other)
    * `_Ps`: 开放标点 (Punctuation, Open)
* **符号 (Symbol):**
    * `_S`:  所有符号 (Symbol)
    * `_Sc`: 货币符号 (Symbol, Currency)
    * `_Sk`: 修饰符号 (Symbol, Modifier)
    * `_Sm`: 数学符号 (Symbol, Math)
    * `_So`: 其他符号 (Symbol, Other)

这些查找表是 Go 语言进行 Unicode 字符属性判断的核心数据来源，使得 Go 程序能够正确地识别和处理不同类型的标点符号和符号。

Prompt: 
```
这是路径为go/src/unicode/tables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共7部分，请归纳一下它的功能

"""
d8, 0x29db, 1},
		{0x29fc, 0x29fd, 1},
		{0x2cf9, 0x2cfc, 1},
		{0x2cfe, 0x2cff, 1},
		{0x2d70, 0x2e00, 144},
		{0x2e01, 0x2e2e, 1},
		{0x2e30, 0x2e4f, 1},
		{0x2e52, 0x2e5d, 1},
		{0x3001, 0x3003, 1},
		{0x3008, 0x3011, 1},
		{0x3014, 0x301f, 1},
		{0x3030, 0x303d, 13},
		{0x30a0, 0x30fb, 91},
		{0xa4fe, 0xa4ff, 1},
		{0xa60d, 0xa60f, 1},
		{0xa673, 0xa67e, 11},
		{0xa6f2, 0xa6f7, 1},
		{0xa874, 0xa877, 1},
		{0xa8ce, 0xa8cf, 1},
		{0xa8f8, 0xa8fa, 1},
		{0xa8fc, 0xa92e, 50},
		{0xa92f, 0xa95f, 48},
		{0xa9c1, 0xa9cd, 1},
		{0xa9de, 0xa9df, 1},
		{0xaa5c, 0xaa5f, 1},
		{0xaade, 0xaadf, 1},
		{0xaaf0, 0xaaf1, 1},
		{0xabeb, 0xfd3e, 20819},
		{0xfd3f, 0xfe10, 209},
		{0xfe11, 0xfe19, 1},
		{0xfe30, 0xfe52, 1},
		{0xfe54, 0xfe61, 1},
		{0xfe63, 0xfe68, 5},
		{0xfe6a, 0xfe6b, 1},
		{0xff01, 0xff03, 1},
		{0xff05, 0xff0a, 1},
		{0xff0c, 0xff0f, 1},
		{0xff1a, 0xff1b, 1},
		{0xff1f, 0xff20, 1},
		{0xff3b, 0xff3d, 1},
		{0xff3f, 0xff5b, 28},
		{0xff5d, 0xff5f, 2},
		{0xff60, 0xff65, 1},
	},
	R32: []Range32{
		{0x10100, 0x10102, 1},
		{0x1039f, 0x103d0, 49},
		{0x1056f, 0x10857, 744},
		{0x1091f, 0x1093f, 32},
		{0x10a50, 0x10a58, 1},
		{0x10a7f, 0x10af0, 113},
		{0x10af1, 0x10af6, 1},
		{0x10b39, 0x10b3f, 1},
		{0x10b99, 0x10b9c, 1},
		{0x10ead, 0x10f55, 168},
		{0x10f56, 0x10f59, 1},
		{0x10f86, 0x10f89, 1},
		{0x11047, 0x1104d, 1},
		{0x110bb, 0x110bc, 1},
		{0x110be, 0x110c1, 1},
		{0x11140, 0x11143, 1},
		{0x11174, 0x11175, 1},
		{0x111c5, 0x111c8, 1},
		{0x111cd, 0x111db, 14},
		{0x111dd, 0x111df, 1},
		{0x11238, 0x1123d, 1},
		{0x112a9, 0x1144b, 418},
		{0x1144c, 0x1144f, 1},
		{0x1145a, 0x1145b, 1},
		{0x1145d, 0x114c6, 105},
		{0x115c1, 0x115d7, 1},
		{0x11641, 0x11643, 1},
		{0x11660, 0x1166c, 1},
		{0x116b9, 0x1173c, 131},
		{0x1173d, 0x1173e, 1},
		{0x1183b, 0x11944, 265},
		{0x11945, 0x11946, 1},
		{0x119e2, 0x11a3f, 93},
		{0x11a40, 0x11a46, 1},
		{0x11a9a, 0x11a9c, 1},
		{0x11a9e, 0x11aa2, 1},
		{0x11b00, 0x11b09, 1},
		{0x11c41, 0x11c45, 1},
		{0x11c70, 0x11c71, 1},
		{0x11ef7, 0x11ef8, 1},
		{0x11f43, 0x11f4f, 1},
		{0x11fff, 0x12470, 1137},
		{0x12471, 0x12474, 1},
		{0x12ff1, 0x12ff2, 1},
		{0x16a6e, 0x16a6f, 1},
		{0x16af5, 0x16b37, 66},
		{0x16b38, 0x16b3b, 1},
		{0x16b44, 0x16e97, 851},
		{0x16e98, 0x16e9a, 1},
		{0x16fe2, 0x1bc9f, 19645},
		{0x1da87, 0x1da8b, 1},
		{0x1e95e, 0x1e95f, 1},
	},
	LatinOffset: 11,
}

var _Pc = &RangeTable{
	R16: []Range16{
		{0x005f, 0x203f, 8160},
		{0x2040, 0x2054, 20},
		{0xfe33, 0xfe34, 1},
		{0xfe4d, 0xfe4f, 1},
		{0xff3f, 0xff3f, 1},
	},
}

var _Pd = &RangeTable{
	R16: []Range16{
		{0x002d, 0x058a, 1373},
		{0x05be, 0x1400, 3650},
		{0x1806, 0x2010, 2058},
		{0x2011, 0x2015, 1},
		{0x2e17, 0x2e1a, 3},
		{0x2e3a, 0x2e3b, 1},
		{0x2e40, 0x2e5d, 29},
		{0x301c, 0x3030, 20},
		{0x30a0, 0xfe31, 52625},
		{0xfe32, 0xfe58, 38},
		{0xfe63, 0xff0d, 170},
	},
	R32: []Range32{
		{0x10ead, 0x10ead, 1},
	},
}

var _Pe = &RangeTable{
	R16: []Range16{
		{0x0029, 0x005d, 52},
		{0x007d, 0x0f3b, 3774},
		{0x0f3d, 0x169c, 1887},
		{0x2046, 0x207e, 56},
		{0x208e, 0x2309, 635},
		{0x230b, 0x232a, 31},
		{0x2769, 0x2775, 2},
		{0x27c6, 0x27e7, 33},
		{0x27e9, 0x27ef, 2},
		{0x2984, 0x2998, 2},
		{0x29d9, 0x29db, 2},
		{0x29fd, 0x2e23, 1062},
		{0x2e25, 0x2e29, 2},
		{0x2e56, 0x2e5c, 2},
		{0x3009, 0x3011, 2},
		{0x3015, 0x301b, 2},
		{0x301e, 0x301f, 1},
		{0xfd3e, 0xfe18, 218},
		{0xfe36, 0xfe44, 2},
		{0xfe48, 0xfe5a, 18},
		{0xfe5c, 0xfe5e, 2},
		{0xff09, 0xff3d, 52},
		{0xff5d, 0xff63, 3},
	},
	LatinOffset: 1,
}

var _Pf = &RangeTable{
	R16: []Range16{
		{0x00bb, 0x2019, 8030},
		{0x201d, 0x203a, 29},
		{0x2e03, 0x2e05, 2},
		{0x2e0a, 0x2e0d, 3},
		{0x2e1d, 0x2e21, 4},
	},
}

var _Pi = &RangeTable{
	R16: []Range16{
		{0x00ab, 0x2018, 8045},
		{0x201b, 0x201c, 1},
		{0x201f, 0x2039, 26},
		{0x2e02, 0x2e04, 2},
		{0x2e09, 0x2e0c, 3},
		{0x2e1c, 0x2e20, 4},
	},
}

var _Po = &RangeTable{
	R16: []Range16{
		{0x0021, 0x0023, 1},
		{0x0025, 0x0027, 1},
		{0x002a, 0x002e, 2},
		{0x002f, 0x003a, 11},
		{0x003b, 0x003f, 4},
		{0x0040, 0x005c, 28},
		{0x00a1, 0x00a7, 6},
		{0x00b6, 0x00b7, 1},
		{0x00bf, 0x037e, 703},
		{0x0387, 0x055a, 467},
		{0x055b, 0x055f, 1},
		{0x0589, 0x05c0, 55},
		{0x05c3, 0x05c6, 3},
		{0x05f3, 0x05f4, 1},
		{0x0609, 0x060a, 1},
		{0x060c, 0x060d, 1},
		{0x061b, 0x061d, 2},
		{0x061e, 0x061f, 1},
		{0x066a, 0x066d, 1},
		{0x06d4, 0x0700, 44},
		{0x0701, 0x070d, 1},
		{0x07f7, 0x07f9, 1},
		{0x0830, 0x083e, 1},
		{0x085e, 0x0964, 262},
		{0x0965, 0x0970, 11},
		{0x09fd, 0x0a76, 121},
		{0x0af0, 0x0c77, 391},
		{0x0c84, 0x0df4, 368},
		{0x0e4f, 0x0e5a, 11},
		{0x0e5b, 0x0f04, 169},
		{0x0f05, 0x0f12, 1},
		{0x0f14, 0x0f85, 113},
		{0x0fd0, 0x0fd4, 1},
		{0x0fd9, 0x0fda, 1},
		{0x104a, 0x104f, 1},
		{0x10fb, 0x1360, 613},
		{0x1361, 0x1368, 1},
		{0x166e, 0x16eb, 125},
		{0x16ec, 0x16ed, 1},
		{0x1735, 0x1736, 1},
		{0x17d4, 0x17d6, 1},
		{0x17d8, 0x17da, 1},
		{0x1800, 0x1805, 1},
		{0x1807, 0x180a, 1},
		{0x1944, 0x1945, 1},
		{0x1a1e, 0x1a1f, 1},
		{0x1aa0, 0x1aa6, 1},
		{0x1aa8, 0x1aad, 1},
		{0x1b5a, 0x1b60, 1},
		{0x1b7d, 0x1b7e, 1},
		{0x1bfc, 0x1bff, 1},
		{0x1c3b, 0x1c3f, 1},
		{0x1c7e, 0x1c7f, 1},
		{0x1cc0, 0x1cc7, 1},
		{0x1cd3, 0x2016, 835},
		{0x2017, 0x2020, 9},
		{0x2021, 0x2027, 1},
		{0x2030, 0x2038, 1},
		{0x203b, 0x203e, 1},
		{0x2041, 0x2043, 1},
		{0x2047, 0x2051, 1},
		{0x2053, 0x2055, 2},
		{0x2056, 0x205e, 1},
		{0x2cf9, 0x2cfc, 1},
		{0x2cfe, 0x2cff, 1},
		{0x2d70, 0x2e00, 144},
		{0x2e01, 0x2e06, 5},
		{0x2e07, 0x2e08, 1},
		{0x2e0b, 0x2e0e, 3},
		{0x2e0f, 0x2e16, 1},
		{0x2e18, 0x2e19, 1},
		{0x2e1b, 0x2e1e, 3},
		{0x2e1f, 0x2e2a, 11},
		{0x2e2b, 0x2e2e, 1},
		{0x2e30, 0x2e39, 1},
		{0x2e3c, 0x2e3f, 1},
		{0x2e41, 0x2e43, 2},
		{0x2e44, 0x2e4f, 1},
		{0x2e52, 0x2e54, 1},
		{0x3001, 0x3003, 1},
		{0x303d, 0x30fb, 190},
		{0xa4fe, 0xa4ff, 1},
		{0xa60d, 0xa60f, 1},
		{0xa673, 0xa67e, 11},
		{0xa6f2, 0xa6f7, 1},
		{0xa874, 0xa877, 1},
		{0xa8ce, 0xa8cf, 1},
		{0xa8f8, 0xa8fa, 1},
		{0xa8fc, 0xa92e, 50},
		{0xa92f, 0xa95f, 48},
		{0xa9c1, 0xa9cd, 1},
		{0xa9de, 0xa9df, 1},
		{0xaa5c, 0xaa5f, 1},
		{0xaade, 0xaadf, 1},
		{0xaaf0, 0xaaf1, 1},
		{0xabeb, 0xfe10, 21029},
		{0xfe11, 0xfe16, 1},
		{0xfe19, 0xfe30, 23},
		{0xfe45, 0xfe46, 1},
		{0xfe49, 0xfe4c, 1},
		{0xfe50, 0xfe52, 1},
		{0xfe54, 0xfe57, 1},
		{0xfe5f, 0xfe61, 1},
		{0xfe68, 0xfe6a, 2},
		{0xfe6b, 0xff01, 150},
		{0xff02, 0xff03, 1},
		{0xff05, 0xff07, 1},
		{0xff0a, 0xff0e, 2},
		{0xff0f, 0xff1a, 11},
		{0xff1b, 0xff1f, 4},
		{0xff20, 0xff3c, 28},
		{0xff61, 0xff64, 3},
		{0xff65, 0xff65, 1},
	},
	R32: []Range32{
		{0x10100, 0x10102, 1},
		{0x1039f, 0x103d0, 49},
		{0x1056f, 0x10857, 744},
		{0x1091f, 0x1093f, 32},
		{0x10a50, 0x10a58, 1},
		{0x10a7f, 0x10af0, 113},
		{0x10af1, 0x10af6, 1},
		{0x10b39, 0x10b3f, 1},
		{0x10b99, 0x10b9c, 1},
		{0x10f55, 0x10f59, 1},
		{0x10f86, 0x10f89, 1},
		{0x11047, 0x1104d, 1},
		{0x110bb, 0x110bc, 1},
		{0x110be, 0x110c1, 1},
		{0x11140, 0x11143, 1},
		{0x11174, 0x11175, 1},
		{0x111c5, 0x111c8, 1},
		{0x111cd, 0x111db, 14},
		{0x111dd, 0x111df, 1},
		{0x11238, 0x1123d, 1},
		{0x112a9, 0x1144b, 418},
		{0x1144c, 0x1144f, 1},
		{0x1145a, 0x1145b, 1},
		{0x1145d, 0x114c6, 105},
		{0x115c1, 0x115d7, 1},
		{0x11641, 0x11643, 1},
		{0x11660, 0x1166c, 1},
		{0x116b9, 0x1173c, 131},
		{0x1173d, 0x1173e, 1},
		{0x1183b, 0x11944, 265},
		{0x11945, 0x11946, 1},
		{0x119e2, 0x11a3f, 93},
		{0x11a40, 0x11a46, 1},
		{0x11a9a, 0x11a9c, 1},
		{0x11a9e, 0x11aa2, 1},
		{0x11b00, 0x11b09, 1},
		{0x11c41, 0x11c45, 1},
		{0x11c70, 0x11c71, 1},
		{0x11ef7, 0x11ef8, 1},
		{0x11f43, 0x11f4f, 1},
		{0x11fff, 0x12470, 1137},
		{0x12471, 0x12474, 1},
		{0x12ff1, 0x12ff2, 1},
		{0x16a6e, 0x16a6f, 1},
		{0x16af5, 0x16b37, 66},
		{0x16b38, 0x16b3b, 1},
		{0x16b44, 0x16e97, 851},
		{0x16e98, 0x16e9a, 1},
		{0x16fe2, 0x1bc9f, 19645},
		{0x1da87, 0x1da8b, 1},
		{0x1e95e, 0x1e95f, 1},
	},
	LatinOffset: 8,
}

var _Ps = &RangeTable{
	R16: []Range16{
		{0x0028, 0x005b, 51},
		{0x007b, 0x0f3a, 3775},
		{0x0f3c, 0x169b, 1887},
		{0x201a, 0x201e, 4},
		{0x2045, 0x207d, 56},
		{0x208d, 0x2308, 635},
		{0x230a, 0x2329, 31},
		{0x2768, 0x2774, 2},
		{0x27c5, 0x27e6, 33},
		{0x27e8, 0x27ee, 2},
		{0x2983, 0x2997, 2},
		{0x29d8, 0x29da, 2},
		{0x29fc, 0x2e22, 1062},
		{0x2e24, 0x2e28, 2},
		{0x2e42, 0x2e55, 19},
		{0x2e57, 0x2e5b, 2},
		{0x3008, 0x3010, 2},
		{0x3014, 0x301a, 2},
		{0x301d, 0xfd3f, 52514},
		{0xfe17, 0xfe35, 30},
		{0xfe37, 0xfe43, 2},
		{0xfe47, 0xfe59, 18},
		{0xfe5b, 0xfe5d, 2},
		{0xff08, 0xff3b, 51},
		{0xff5b, 0xff5f, 4},
		{0xff62, 0xff62, 1},
	},
	LatinOffset: 1,
}

var _S = &RangeTable{
	R16: []Range16{
		{0x0024, 0x002b, 7},
		{0x003c, 0x003e, 1},
		{0x005e, 0x0060, 2},
		{0x007c, 0x007e, 2},
		{0x00a2, 0x00a6, 1},
		{0x00a8, 0x00a9, 1},
		{0x00ac, 0x00ae, 2},
		{0x00af, 0x00b1, 1},
		{0x00b4, 0x00b8, 4},
		{0x00d7, 0x00f7, 32},
		{0x02c2, 0x02c5, 1},
		{0x02d2, 0x02df, 1},
		{0x02e5, 0x02eb, 1},
		{0x02ed, 0x02ef, 2},
		{0x02f0, 0x02ff, 1},
		{0x0375, 0x0384, 15},
		{0x0385, 0x03f6, 113},
		{0x0482, 0x058d, 267},
		{0x058e, 0x058f, 1},
		{0x0606, 0x0608, 1},
		{0x060b, 0x060e, 3},
		{0x060f, 0x06de, 207},
		{0x06e9, 0x06fd, 20},
		{0x06fe, 0x07f6, 248},
		{0x07fe, 0x07ff, 1},
		{0x0888, 0x09f2, 362},
		{0x09f3, 0x09fa, 7},
		{0x09fb, 0x0af1, 246},
		{0x0b70, 0x0bf3, 131},
		{0x0bf4, 0x0bfa, 1},
		{0x0c7f, 0x0d4f, 208},
		{0x0d79, 0x0e3f, 198},
		{0x0f01, 0x0f03, 1},
		{0x0f13, 0x0f15, 2},
		{0x0f16, 0x0f17, 1},
		{0x0f1a, 0x0f1f, 1},
		{0x0f34, 0x0f38, 2},
		{0x0fbe, 0x0fc5, 1},
		{0x0fc7, 0x0fcc, 1},
		{0x0fce, 0x0fcf, 1},
		{0x0fd5, 0x0fd8, 1},
		{0x109e, 0x109f, 1},
		{0x1390, 0x1399, 1},
		{0x166d, 0x17db, 366},
		{0x1940, 0x19de, 158},
		{0x19df, 0x19ff, 1},
		{0x1b61, 0x1b6a, 1},
		{0x1b74, 0x1b7c, 1},
		{0x1fbd, 0x1fbf, 2},
		{0x1fc0, 0x1fc1, 1},
		{0x1fcd, 0x1fcf, 1},
		{0x1fdd, 0x1fdf, 1},
		{0x1fed, 0x1fef, 1},
		{0x1ffd, 0x1ffe, 1},
		{0x2044, 0x2052, 14},
		{0x207a, 0x207c, 1},
		{0x208a, 0x208c, 1},
		{0x20a0, 0x20c0, 1},
		{0x2100, 0x2101, 1},
		{0x2103, 0x2106, 1},
		{0x2108, 0x2109, 1},
		{0x2114, 0x2116, 2},
		{0x2117, 0x2118, 1},
		{0x211e, 0x2123, 1},
		{0x2125, 0x2129, 2},
		{0x212e, 0x213a, 12},
		{0x213b, 0x2140, 5},
		{0x2141, 0x2144, 1},
		{0x214a, 0x214d, 1},
		{0x214f, 0x218a, 59},
		{0x218b, 0x2190, 5},
		{0x2191, 0x2307, 1},
		{0x230c, 0x2328, 1},
		{0x232b, 0x2426, 1},
		{0x2440, 0x244a, 1},
		{0x249c, 0x24e9, 1},
		{0x2500, 0x2767, 1},
		{0x2794, 0x27c4, 1},
		{0x27c7, 0x27e5, 1},
		{0x27f0, 0x2982, 1},
		{0x2999, 0x29d7, 1},
		{0x29dc, 0x29fb, 1},
		{0x29fe, 0x2b73, 1},
		{0x2b76, 0x2b95, 1},
		{0x2b97, 0x2bff, 1},
		{0x2ce5, 0x2cea, 1},
		{0x2e50, 0x2e51, 1},
		{0x2e80, 0x2e99, 1},
		{0x2e9b, 0x2ef3, 1},
		{0x2f00, 0x2fd5, 1},
		{0x2ff0, 0x2ffb, 1},
		{0x3004, 0x3012, 14},
		{0x3013, 0x3020, 13},
		{0x3036, 0x3037, 1},
		{0x303e, 0x303f, 1},
		{0x309b, 0x309c, 1},
		{0x3190, 0x3191, 1},
		{0x3196, 0x319f, 1},
		{0x31c0, 0x31e3, 1},
		{0x3200, 0x321e, 1},
		{0x322a, 0x3247, 1},
		{0x3250, 0x3260, 16},
		{0x3261, 0x327f, 1},
		{0x328a, 0x32b0, 1},
		{0x32c0, 0x33ff, 1},
		{0x4dc0, 0x4dff, 1},
		{0xa490, 0xa4c6, 1},
		{0xa700, 0xa716, 1},
		{0xa720, 0xa721, 1},
		{0xa789, 0xa78a, 1},
		{0xa828, 0xa82b, 1},
		{0xa836, 0xa839, 1},
		{0xaa77, 0xaa79, 1},
		{0xab5b, 0xab6a, 15},
		{0xab6b, 0xfb29, 20414},
		{0xfbb2, 0xfbc2, 1},
		{0xfd40, 0xfd4f, 1},
		{0xfdcf, 0xfdfc, 45},
		{0xfdfd, 0xfdff, 1},
		{0xfe62, 0xfe64, 2},
		{0xfe65, 0xfe66, 1},
		{0xfe69, 0xff04, 155},
		{0xff0b, 0xff1c, 17},
		{0xff1d, 0xff1e, 1},
		{0xff3e, 0xff40, 2},
		{0xff5c, 0xff5e, 2},
		{0xffe0, 0xffe6, 1},
		{0xffe8, 0xffee, 1},
		{0xfffc, 0xfffd, 1},
	},
	R32: []Range32{
		{0x10137, 0x1013f, 1},
		{0x10179, 0x10189, 1},
		{0x1018c, 0x1018e, 1},
		{0x10190, 0x1019c, 1},
		{0x101a0, 0x101d0, 48},
		{0x101d1, 0x101fc, 1},
		{0x10877, 0x10878, 1},
		{0x10ac8, 0x1173f, 3191},
		{0x11fd5, 0x11ff1, 1},
		{0x16b3c, 0x16b3f, 1},
		{0x16b45, 0x1bc9c, 20823},
		{0x1cf50, 0x1cfc3, 1},
		{0x1d000, 0x1d0f5, 1},
		{0x1d100, 0x1d126, 1},
		{0x1d129, 0x1d164, 1},
		{0x1d16a, 0x1d16c, 1},
		{0x1d183, 0x1d184, 1},
		{0x1d18c, 0x1d1a9, 1},
		{0x1d1ae, 0x1d1ea, 1},
		{0x1d200, 0x1d241, 1},
		{0x1d245, 0x1d300, 187},
		{0x1d301, 0x1d356, 1},
		{0x1d6c1, 0x1d6db, 26},
		{0x1d6fb, 0x1d715, 26},
		{0x1d735, 0x1d74f, 26},
		{0x1d76f, 0x1d789, 26},
		{0x1d7a9, 0x1d7c3, 26},
		{0x1d800, 0x1d9ff, 1},
		{0x1da37, 0x1da3a, 1},
		{0x1da6d, 0x1da74, 1},
		{0x1da76, 0x1da83, 1},
		{0x1da85, 0x1da86, 1},
		{0x1e14f, 0x1e2ff, 432},
		{0x1ecac, 0x1ecb0, 4},
		{0x1ed2e, 0x1eef0, 450},
		{0x1eef1, 0x1f000, 271},
		{0x1f001, 0x1f02b, 1},
		{0x1f030, 0x1f093, 1},
		{0x1f0a0, 0x1f0ae, 1},
		{0x1f0b1, 0x1f0bf, 1},
		{0x1f0c1, 0x1f0cf, 1},
		{0x1f0d1, 0x1f0f5, 1},
		{0x1f10d, 0x1f1ad, 1},
		{0x1f1e6, 0x1f202, 1},
		{0x1f210, 0x1f23b, 1},
		{0x1f240, 0x1f248, 1},
		{0x1f250, 0x1f251, 1},
		{0x1f260, 0x1f265, 1},
		{0x1f300, 0x1f6d7, 1},
		{0x1f6dc, 0x1f6ec, 1},
		{0x1f6f0, 0x1f6fc, 1},
		{0x1f700, 0x1f776, 1},
		{0x1f77b, 0x1f7d9, 1},
		{0x1f7e0, 0x1f7eb, 1},
		{0x1f7f0, 0x1f800, 16},
		{0x1f801, 0x1f80b, 1},
		{0x1f810, 0x1f847, 1},
		{0x1f850, 0x1f859, 1},
		{0x1f860, 0x1f887, 1},
		{0x1f890, 0x1f8ad, 1},
		{0x1f8b0, 0x1f8b1, 1},
		{0x1f900, 0x1fa53, 1},
		{0x1fa60, 0x1fa6d, 1},
		{0x1fa70, 0x1fa7c, 1},
		{0x1fa80, 0x1fa88, 1},
		{0x1fa90, 0x1fabd, 1},
		{0x1fabf, 0x1fac5, 1},
		{0x1face, 0x1fadb, 1},
		{0x1fae0, 0x1fae8, 1},
		{0x1faf0, 0x1faf8, 1},
		{0x1fb00, 0x1fb92, 1},
		{0x1fb94, 0x1fbca, 1},
	},
	LatinOffset: 10,
}

var _Sc = &RangeTable{
	R16: []Range16{
		{0x0024, 0x00a2, 126},
		{0x00a3, 0x00a5, 1},
		{0x058f, 0x060b, 124},
		{0x07fe, 0x07ff, 1},
		{0x09f2, 0x09f3, 1},
		{0x09fb, 0x0af1, 246},
		{0x0bf9, 0x0e3f, 582},
		{0x17db, 0x20a0, 2245},
		{0x20a1, 0x20c0, 1},
		{0xa838, 0xfdfc, 21956},
		{0xfe69, 0xff04, 155},
		{0xffe0, 0xffe1, 1},
		{0xffe5, 0xffe6, 1},
	},
	R32: []Range32{
		{0x11fdd, 0x11fe0, 1},
		{0x1e2ff, 0x1ecb0, 2481},
	},
	LatinOffset: 2,
}

var _Sk = &RangeTable{
	R16: []Range16{
		{0x005e, 0x0060, 2},
		{0x00a8, 0x00af, 7},
		{0x00b4, 0x00b8, 4},
		{0x02c2, 0x02c5, 1},
		{0x02d2, 0x02df, 1},
		{0x02e5, 0x02eb, 1},
		{0x02ed, 0x02ef, 2},
		{0x02f0, 0x02ff, 1},
		{0x0375, 0x0384, 15},
		{0x0385, 0x0888, 1283},
		{0x1fbd, 0x1fbf, 2},
		{0x1fc0, 0x1fc1, 1},
		{0x1fcd, 0x1fcf, 1},
		{0x1fdd, 0x1fdf, 1},
		{0x1fed, 0x1fef, 1},
		{0x1ffd, 0x1ffe, 1},
		{0x309b, 0x309c, 1},
		{0xa700, 0xa716, 1},
		{0xa720, 0xa721, 1},
		{0xa789, 0xa78a, 1},
		{0xab5b, 0xab6a, 15},
		{0xab6b, 0xfbb2, 20551},
		{0xfbb3, 0xfbc2, 1},
		{0xff3e, 0xff40, 2},
		{0xffe3, 0xffe3, 1},
	},
	R32: []Range32{
		{0x1f3fb, 0x1f3ff, 1},
	},
	LatinOffset: 3,
}

var _Sm = &RangeTable{
	R16: []Range16{
		{0x002b, 0x003c, 17},
		{0x003d, 0x003e, 1},
		{0x007c, 0x007e, 2},
		{0x00ac, 0x00b1, 5},
		{0x00d7, 0x00f7, 32},
		{0x03f6, 0x0606, 528},
		{0x0607, 0x0608, 1},
		{0x2044, 0x2052, 14},
		{0x207a, 0x207c, 1},
		{0x208a, 0x208c, 1},
		{0x2118, 0x2140, 40},
		{0x2141, 0x2144, 1},
		{0x214b, 0x2190, 69},
		{0x2191, 0x2194, 1},
		{0x219a, 0x219b, 1},
		{0x21a0, 0x21a6, 3},
		{0x21ae, 0x21ce, 32},
		{0x21cf, 0x21d2, 3},
		{0x21d4, 0x21f4, 32},
		{0x21f5, 0x22ff, 1},
		{0x2320, 0x2321, 1},
		{0x237c, 0x239b, 31},
		{0x239c, 0x23b3, 1},
		{0x23dc, 0x23e1, 1},
		{0x25b7, 0x25c1, 10},
		{0x25f8, 0x25ff, 1},
		{0x266f, 0x27c0, 337},
		{0x27c1, 0x27c4, 1},
		{0x27c7, 0x27e5, 1},
		{0x27f0, 0x27ff, 1},
		{0x2900, 0x2982, 1},
		{0x2999, 0x29d7, 1},
		{0x29dc, 0x29fb, 1},
		{0x29fe, 0x2aff, 1},
		{0x2b30, 0x2b44, 1},
		{0x2b47, 0x2b4c, 1},
		{0xfb29, 0xfe62, 825},
		{0xfe64, 0xfe66, 1},
		{0xff0b, 0xff1c, 17},
		{0xff1d, 0xff1e, 1},
		{0xff5c, 0xff5e, 2},
		{0xffe2, 0xffe9, 7},
		{0xffea, 0xffec, 1},
	},
	R32: []Range32{
		{0x1d6c1, 0x1d6db, 26},
		{0x1d6fb, 0x1d715, 26},
		{0x1d735, 0x1d74f, 26},
		{0x1d76f, 0x1d789, 26},
		{0x1d7a9, 0x1d7c3, 26},
		{0x1eef0, 0x1eef1, 1},
	},
	LatinOffset: 5,
}

var _So = &RangeTable{
	R16: []Range16{
		{0x00a6, 0x00a9, 3},
		{0x00ae, 0x00b0, 2},
		{0x0482, 0x058d, 267},
		{0x058e, 0x060e, 128},
		{0x060f, 0x06de, 207},
		{0x06e9, 0x06fd, 20},
		{0x06fe, 0x07f6, 248},
		{0x09fa, 0x0b70, 374},
		{0x0bf3, 0x0bf8, 1},
		{0x0bfa, 0x0c7f, 133},
		{0x0d4f, 0x0d79, 42},
		{0x0f01, 0x0f03, 1},
		{0x0f13, 0x0f15, 2},
		{0x0f16, 0x0f17, 1},
		{0x0f1a, 0x0f1f, 1},
		{0x0f34, 0x0f38, 2},
		{0x0fbe, 0x0fc5, 1},
		{0x0fc7, 0x0fcc, 1},
		{0x0fce, 0x0fcf, 1},
		{0x0fd5, 0x0fd8, 1},
		{0x109e, 0x109f, 1},
		{0x1390, 0x1399, 1},
		{0x166d, 0x1940, 723},
		{0x19de, 0x19ff, 1},
		{0x1b61, 0x1b6a, 1},
		{0x1b74, 0x1b7c, 1},
		{0x2100, 0x2101, 1},
		{0x2103, 0x2106, 1},
		{0x2108, 0x2109, 1},
		{0x2114, 0x2116, 2},
		{0x2117, 0x211e, 7},
		{0x211f, 0x2123, 1},
		{0x2125, 0x2129, 2},
		{0x212e, 0x213a, 12},
		{0x213b, 0x214a, 15},
		{0x214c, 0x214d, 1},
		{0x214f, 0x218a, 59},
		{0x218b, 0x2195, 10},
		{0x2196, 0x2199, 1},
		{0x219c, 0x219f, 1},
		{0x21a1, 0x21a2, 1},
		{0x21a4, 0x21a5, 1},
		{0x21a7, 0x21ad, 1},
		{0x21af, 0x21cd, 1},
		{0x21d0, 0x21d1, 1},
		{0x21d3, 0x21d5, 2},
		{0x21d6, 0x21f3, 1},
		{0x2300, 0x2307, 1},
		{0x230c, 0x231f, 1},
		{0x2322, 0x2328, 1},
		{0x232b, 0x237b, 1},
		{0x237d, 0x239a, 1},
		{0x23b4, 0x23db, 1},
		{0x23e2, 0x2426, 1},
		{0x2440, 0x244a, 1},
		{0x249c, 0x24e9, 1},
		{0x2500, 0x25b6, 1},
		{0x25b8, 0x25c0, 1},
		{0x25c2, 0x25f7, 1},
		{0x2600, 0x266e, 1},
		{0x2670, 0x2767, 1},
		{0x2794, 0x27bf, 1},
		{0x2800, 0x28ff, 1},
		{0x2b00, 0x2b2f, 1},
		{0x2b45, 0x2b46, 1},
		{0x2b4d, 0x2b73, 1},
		{0x2b76, 0x2b95, 1},
		{0x2b97, 0x2bff, 1},
		{0x2ce5, 0x2cea, 1},
		{0x2e50, 0x2e51, 1},
		{0x2e80, 0x2e99, 1},
		{0x2e9b, 0x2ef3, 1},
		{0x2f00, 0x2fd5, 1},
		{0x2ff0, 0x2ffb, 1},
		{0x3004, 0x3012, 14},
		{0x3013, 0x3020, 13},
		{0x3036, 0x3037, 1},
		{0x303e, 0x303f, 1},
		{0x3190, 0x3191, 1},
		{0x3196, 0x319f, 1},
		{0x31c0, 0x31e3, 1},
		{0x3200, 0x321e, 1},
		{0x322a, 0x3247, 1},
		{0x3250, 0x3260, 16},
		{0x3261, 0x327f, 1},
		{0x328a, 0x32b0, 1},
		{0x32c0, 0x33ff, 1},
		{0x4dc0, 0x4dff, 1},
		{0xa490, 0xa4c6, 1},
		{0xa828, 0xa82b, 1},
		{0xa836, 0xa837, 1},
		{0xa839, 0xaa77, 574},
		{0xaa78, 0xaa79, 1},
		{0xfd40, 0xfd4f, 1},
		{0xfdcf, 0xfdfd, 46},
		{0xfdfe, 0xfdff, 1},
		{0xffe4, 0xffe8, 4},
		{0xffed, 0xffee, 1},
		{0xfffc, 0xfffd, 1},
	},
	R32: []Range32{
		{0x10137, 0x1013f, 1},
		{0x10179, 0x10189, 1},
		{0x1018c, 0x1018e, 1},
		{0x10190, 0x1019c, 1},
		{0x101a0, 0x101d0, 48},
		{0x101d1, 0x101fc, 1},
		{0x10877, 0x10878, 1},
		{0x10ac8, 0x1173f, 3191},
		{0x11fd5, 0x11fdc, 1},
		{0x11fe1, 0x11ff1, 1},
		{0x16b3c, 0x16b3f, 1},
		{0x16b45, 0x1bc9c, 20823},
		{0x1cf50, 0x1cfc3, 1},
		{0x1d000, 0x1d0f5, 1},
		{0x1d100, 0x1d126, 1},
		{0x1d129, 0x1d164, 1},
		{0x1d16a, 0x1d16c, 1},
		{0x1d183, 0x1d184, 1},
		{0x1d18c, 0x1d1a9, 1},
		{0x1d1ae, 0x1d1ea, 1},
		{0x1d200, 0x1d241, 1},
		{0x1d245, 0x1d300, 187},
		{0x1d301, 0x1d356, 1},
		{0x1d800, 0x1d9ff, 1},
		{0x1da37, 0x1da3a, 1},
		{0x1da6d, 0x1da74, 1},
		{0x1da76, 0x1da83, 1},
		{0x1da85, 0x1da86, 1},
		{0x1e14f, 0x1ecac, 2909},
		{0x1ed2e, 0x1f000, 722},
		{0x1f001, 0x1f02b, 1},
		{0x1f030, 0x1f093, 1},
		{0x1f0a0, 0x1f0ae, 1},
		{0x1f0b1, 0x1f0bf, 1},
		{0x1f0c1, 0x1f0cf, 1},
		{0x1f0d1, 0x1f0f5, 1},
		{0x1f10d, 0x1f1ad, 1},
		{0x1f1e6, 0x1f202, 1},
		{0x1f210, 0x1f23b, 1},
		{0x1f240, 0x1f248, 1},
		{0x1f250, 0x1f251, 1},
		{0x1f260, 0x1f265, 1},
		{0x1f300, 0x1f3fa, 1},
		{0x1f400, 0x1f6d7, 1},
		{0x1f6dc, 0x1f6ec, 1},
		{0x1f6f0, 0x1f6fc, 1},
		{0x1f700, 0x1f776, 1},
		{0x1f77b, 0x1f7d9, 1},
		{0x1f7e0, 0x1f7eb, 1},
		{0x1f7f0, 0x1f800, 16},
		{0x1f801, 0x1f80b, 1},
		{0x1f810, 0x1f847, 1},
		{0x1f850, 0x1f859, 1},
		{0x1f860, 0x1f887, 1},
		{0x1f890, 0x1f8ad, 1},
		{0x1f8b0, 0x1f8b1, 1},
		{0x1f900, 0x1fa53, 1},
		{0x1fa60, 0x1fa6d, 1},
		{0x1fa70, 0x1fa7c, 1},
		{0x1fa80, 0x1fa88, 1},
		{0x1fa90, 0x1fabd, 1},
		{0x1fabf, 0x1fac5, 1},
		{0x1face, 0x1fadb, 1},
		{0x1fae0, 0x1fae8, 1},
		{0x1faf0, 0x1faf8, 1},
		{0x1fb00, 0x1fb92, 1},
		{0x1fb94, 0x1fbca, 1},
	},
	LatinOffset: 2,
}

var _Z = &RangeTable{
	R16: []Range16{
		{0x0020, 0x00a0, 128},
		{0x1680, 0x2000, 2432},
		{0x2001, 0x200a, 1},
		{0x2028, 0x2029, 1},
		{0x202f, 0x205f, 48},
		{0x3000, 0x3000, 1},
	},
	LatinOffset: 1,
}

var _Zl = &RangeTable{
	R16: []Range16{
		{0x2028, 0x2028, 1},
	},
}

var _Zp = &RangeTable{
	R16: []Range16{
		{0x2029, 0x2029, 1},
	},
}

var _Zs = &RangeTable{
	R16: []Range16{
		{0x0020, 0x00a0, 128},
		{0x1680, 0x2000, 2432},
		{0x2001, 0x200a, 1},
		{0x202f, 0x205f, 48},
		{0x3000, 0x3000, 1},
	},
	LatinOffset: 1,
}

// These variables have type *RangeTable.
var (
	Cc     = _Cc // Cc is the set of Unicode characters in category Cc (Other, control).
	Cf     = _Cf // Cf is the set of Unicode characters in category Cf (Other, format).
	Co     = _Co // Co is the set of Unicode characters in category Co (Other, private use).
	Cs     = _Cs // Cs is the set of Unicode characters in category Cs (Other, surrogate).
	Digit  = _Nd // Digit is the set of Unicode characters with the "decimal digit" property.
	Nd     = _Nd // Nd is the set of Unicode characters in category Nd (Number, decimal digit).
	Letter = _L  // Letter/L is the set of Unicode letters, category L.
	L      = _L
	Lm     = _Lm // Lm is the set of Unicode characters in category Lm (Letter, modifier).
	Lo     = _Lo // Lo is the set of Unicode characters in category Lo (Letter, other).
	Lower  = _Ll // Lower is the set of Unicode lower case letters.
	Ll     = _Ll // Ll is the set of Unicode characters in category Ll (Letter, lowercase).
	Mark   = _M  // Mark/M is the set of Unicode mark characters, category M.
	M      = _M
	Mc     = _Mc // Mc is the set of Unicode characters in category Mc (Mark, spacing combining).
	Me     = _Me // Me is the set of Unicode characters in category Me (Mark, enclosing).
	Mn     = _Mn // Mn is the set of Unicode characters in category Mn (Mark, nonspacing).
	Nl     = _Nl // Nl is the set of Unicode characters in category Nl (Number, letter).
	No     = _No // No is the set of Unicode characters in category No (Number, other).
	Number = _N  // Number/N is the set of Unicode number characters, category N.
	N      = _N
	Other  = _C // Other/C is the set of Unicode control and special characters, category C.
	C      = _C
	Pc     = _Pc // Pc is the set of Unicode characters in category Pc (Punctuation, connector).
	Pd     = _Pd // Pd is the set of Unicode characters in category Pd (Punctuation, dash).
	Pe     = _Pe // Pe is the set of Unicode characters in category Pe (Punctuation, close).
	Pf     = _Pf // Pf is the set of Unicode characters in category Pf (Punctuation, final quote).
	Pi     = _Pi // Pi is the set of Unicode characters in category Pi (Punctuation, initial quote).
	Po     = _Po // Po is the set of Unicode characters in category Po (Punctuation, other).
	Ps     = _Ps // Ps is the set of Unicode characters in category Ps (Punctuation, open).
	Punct  = _P  // Punct/P is the set of Unicode punctuation characters, category P.
	P      = _P
	Sc     = _Sc // Sc is the set of Unicode characters in category Sc (Symbol, currency).
	Sk     = _Sk // Sk is the set of Unicode characters in category Sk (Symbol, modifier).
	Sm     = _Sm // Sm is the set of Unicode characters in category Sm (Symbol, math).
	So     = _So // So is the set of Unicode characters in category So (Symbol, other).
	Space  = _Z  // Space/Z is the set of Unicode space characters, category Z.
	Z      = _Z
	Symbol = _S // Symbol/S is the set of Unicode symbol characters, category S.
	S      = _S
	Title  = _Lt // Title is the set of Unicode title case letters.
	Lt     = _Lt // Lt is the set of Unicode characters in category Lt (Letter, titlecase).
	Upper  = _Lu // Upper is the set of Unicode upper case letters.
	Lu     = _Lu // Lu is the set of Unicode characters in category Lu (Letter, uppercase).
	Zl     = _Zl // Zl is the set of Unicode characters in category Zl (Separator, line).
	Zp     = _Zp // Zp is the set of Unicode characters in category Zp (Separator, paragraph).
	Zs     = _Zs // Zs is the set of Unicode characters in category Zs (Separator, space).
)

// Scripts is the set of Unicode script tables.
var Scripts = map[string]*RangeTable{
	"Adlam":                  Adlam,
	"Ahom":                   Ahom,
	"Anatolian_Hieroglyphs":  Anatolian_Hieroglyphs,
	"Arabic":                 Arabic,
	"Armenian":               Armenian,
	"Avestan":                Avestan,
	"Balinese":               Balinese,
	"Bamum":                  Bamum,
	"Bassa_Vah":              Bassa_Vah,
	"Batak":                  Batak,
	"Bengali":                Bengali,
	"Bhaiksuki":              Bhaiksuki,
	"Bopomofo":               Bopomofo,
	"Brahmi":                 Brahmi,
	"Braille":                Braille,
	"Buginese":               Buginese,
	"Buhid":                  Buhid,
	"Canadian_Aboriginal":    Canadian_Aboriginal,
	"Carian":                 Carian,
	"Caucasian_Albanian":     Caucasian_Albanian,
	"Chakma":                 Chakma,
	"Cham":                   Cham,
	"Cherokee":               Cherokee,
	"Chorasmian":             Chorasmian,
	"Common":                 Common,
	"Coptic":                 Coptic,
	"Cuneiform":              Cuneiform,
	"Cypriot":                Cypriot,
	"Cypro_Minoan":           Cypro_Minoan,
	"Cyrillic":               Cyrillic,
	"Deseret":                Deseret,
	"Devanagari":             Devanagari,
	"Dives_Akuru":            Dives_Akuru,
	"Dogra":                  Dogra,
	"Duployan":               Duployan,
	"Egyptian_Hieroglyphs":   Egyptian_Hieroglyphs,
	"Elbasan":                Elbasan,
	"Elymaic":                Elymaic,
	"Ethiopic":               Ethiopic,
	"Georgian":               Georgian,
	"Glagolitic":             Glagolitic,
	"Gothic":                 Gothic,
	"Grantha":                Grantha,
	"Greek":                  Greek,
	"Gujarati":               Gujarati,
	"Gunjala_Gondi":          Gunjala_Gondi,
	"Gurmukhi":               Gurmukhi,
	"Han":                    Han,
	"Hangul":                 Hangul,
	"Hanifi_Rohingya":        Hanifi_Rohingya,
	"Hanunoo":                Hanunoo,
	"Hatran":                 Hatran,
	"Hebrew":                 Hebrew,
	"Hiragana":               Hiragana,
	"Imperial_Aramaic":       Imperial_Aramaic,
	"Inherited":              Inherited,
	"Inscriptional_Pahlavi":  Inscriptional_Pahlavi,
	"Inscriptional_Parthian": Inscriptional_Parthian,
	"Javanese":               Javanese,
	"Kaithi":                 Kaithi,
	"Kannada":                Kannada,
	"Katakana":               Katakana,
	"Kawi":                   Kawi,
	"Kayah_Li":               Kayah_Li,
	"Kharoshthi":             Kharoshthi,
	"Khitan_Small_Script":    Khitan_Small_Script,
	"Khmer":                  Khmer,
	"Khojki":                 Khojki,
	"Khudawadi":              Khudawadi,
	"Lao":                    Lao,
	"Latin":                  Latin,
	"Lepcha":                 Lepcha,
	"Limbu":                  Limbu,
	"Linear_A":               Linear_A,
	"Linear_B":               Linear_B,
	"Lisu":                   Lisu,
	"Lycian":                 Lycian,
	"Lydian":                 Lydian,
	"Mahajani":               Mahajani,
	"Makasar":                Makasar,
	"Malayalam":              Malayalam,
	"Mandaic":                Mandaic,
	"Manichaean":             Manichaean,
	"Marchen":                Marchen,
	"Masaram_Gondi":          Masaram_Gondi,
	"Medefaidrin":            Medefaidrin,
	"Meetei_Mayek":           Meetei_Mayek,
	"Mende_Kikakui":          Mende_Kikakui,
	"Meroitic_Cursive":       Meroitic_Cursive,
	"Meroitic_Hieroglyphs":   Meroitic_Hieroglyphs,
	"Miao":                   Miao,
	"Modi":                   Modi,
	"Mongolian":              Mongolian,
	"Mro":                    Mro,
	"Multani":                Multani,
	"Myanmar":                Myanmar,
	"Nabataean":              Nabataean,
	"Nag_Mundari":            Nag_Mundari,
	"Nandinagari":            Nandinagari,
	"New_Tai_Lue":            New_Tai_Lue,
	"Newa":                   Newa,
	"Nko":                    Nko,
	"Nushu":                  Nushu,
	"Nyiakeng_Puachue_Hmong": Nyiakeng_Puachue_Hmong,
	"Ogham":                  Ogham,
	"Ol_Chiki":               Ol_Chiki,
	"Old_Hungarian":          Old_Hungarian,
	"Old_Italic":             Old_Italic,
	"Old_North_Arabian":      Old_North_Arabian,
	"Old_Permic":             Old_Permic,
	"Old_Persian":            Old_Persian,
	"Old_Sogdian":            Old_Sogdian,
	"Old_South_Arabian":      Old_South_Arabian,
	"Old_Turkic":             Old_Turkic,
	"Old_Uyghur":             Old_Uyghur,
	"Oriya":                  Oriya,
	"Osage":                  Osage,
	"Osmanya":                Osmanya,
	"Pahawh_Hmong":           Pahawh_Hmong,
	"Palmyrene":              Palmyrene,
	"Pau_Cin_Hau":            Pau_Cin_Hau,
	"Phags_Pa":               Phags_Pa,
	"Phoenician":             Phoenician,
	"Psalter_Pahlavi":        Psalter_Pahlavi,
	"Rejang":                 Rejang,
	"Runic":                  Runic,
	"Samaritan":              Samaritan,
	"Saurashtra":             Saurashtra,
	"Sharada":                Sharada,
	"Shavian":                Shavian,
	"Siddham":                Siddham,
	"SignWriting":            SignWriting,
	"Sinhala":                Sinhala,
	"Sogdian":                Sogdian,
	"Sora_Sompeng":           Sora_Sompeng,
	"Soyombo":                Soyombo,
	"Sundanese":              Sundanese,
	"Syloti_Nagri":           Syloti_Nagri,
	"Syriac":                 Syriac,
	"Tagalog":                Tagalog,
	"Tagbanwa":               Tagbanwa,
	"Tai_Le":                 Tai_Le,
	"Tai_Tham":               Tai_Tham,
	"Tai_Viet":               Tai_Viet,
	"Takri":                  Takri,
	"Tamil":                  Tamil,
	"Tangsa":                 Tangsa,
	"Tangut":                 Tangut,
	"Telugu":                 Telugu,
	"Thaana":                 Thaana,
	"Thai":                   Thai,
	"Tibetan":                Tibetan,
	"Tifinagh":               Tifinagh,
	"Tirhuta":                Tirhuta,
	"Toto":                   Toto,
	"Ugaritic":               Ugaritic,
	"Vai":                    Vai,
	"Vithkuqi":               Vithkuqi,
	"Wancho":                 Wancho,
	"Warang_Citi":            Warang_Citi,
	"Yezidi":                 Yezidi,
	"Yi":                     Yi,
	"Zanabazar_Square":       Zanabazar_Square,
}

var _Adlam = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x1e900, 0x1e94b, 1},
		{0x1e950, 0x1e959, 1},
		{0x1e95e, 0x1e95f, 1},
	},
}

var _Ahom = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11700, 0x1171a, 1},
		{0x1171d, 0x1172b, 1},
		{0x11730, 0x11746, 1},
	},
}

var _Anatolian_Hieroglyphs = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x14400, 0x14646, 1},
	},
}

var _Arabic = &RangeTable{
	R16: []Range16{
		{0x0600, 0x0604, 1},
		{0x0606, 0x060b, 1},
		{0x060d, 0x061a, 1},
		{0x061c, 0x061e, 1},
		{0x0620, 0x063f, 1},
		{0x0641, 0x064a, 1},
		{0x0656, 0x066f, 1},
		{0x0671, 0x06dc, 1},
		{0x06de, 0x06ff, 1},
		{0x0750, 0x077f, 1},
		{0x0870, 0x088e, 1},
		{0x0890, 0x0891, 1},
		{0x0898, 0x08e1, 1},
		{0x08e3, 0x08ff, 1},
		{0xfb50, 0xfbc2, 1},
		{0xfbd3, 0xfd3d, 1},
		{0xfd40, 0xfd8f, 1},
		{0xfd92, 0xfdc7, 1},
		{0xfdcf, 0xfdf0, 33},
		{0xfdf1, 0xfdff, 1},
		{0xfe70, 0xfe74, 1},
		{0xfe76, 0xfefc, 1},
	},
	R32: []Range32{
		{0x10e60, 0x10e7e, 1},
		{0x10efd, 0x10eff, 1},
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
		{0x1eef0, 0x1eef1, 1},
	},
}

var _Armenian = &RangeTable{
	R16: []Range16{
		{0x0531, 0x0556, 1},
		{0x0559, 0x058a, 1},
		{0x058d, 0x058f, 1},
		{0xfb13, 0xfb17, 1},
	},
}

var _Avestan = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10b00, 0x10b35, 1},
		{0x10b39, 0x10b3f, 1},
	},
}

var _Balinese = &RangeTable{
	R16: []Range16{
		{0x1b00, 0x1b4c, 1},
		{0x1b50, 0x1b7e, 1},
	},
}

var _Bamum = &RangeTable{
	R16: []Range16{
		{0xa6a0, 0xa6f7, 1},
	},
	R32: []Range32{
		{0x16800, 0x16a38, 1},
	},
}

var _Bassa_Vah = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x16ad0, 0x16aed, 1},
		{0x16af0, 0x16af5, 1},
	},
}

var _Batak = &RangeTable{
	R16: []Range16{
		{0x1bc0, 0x1bf3, 1},
		{0x1bfc, 0x1bff, 1},
	},
}

var _Bengali = &RangeTable{
	R16: []Range16{
		{0x0980, 0x0983, 1},
		{0x0985, 0x098c, 1},
		{0x098f, 0x0990, 1},
		{0x0993, 0x09a8, 1},
		{0x09aa, 0x09b
"""




```