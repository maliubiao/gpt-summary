Response:
The user wants to understand the functionality of a Go source code file `go/src/unicode/tables.go`, specifically the part provided in the prompt.

The code defines a series of Go variables, each named starting with an underscore followed by a script name (e.g., `_Bengali`, `_Bhaiksuki`). Each of these variables is assigned a pointer to a `RangeTable` struct. The `RangeTable` struct seems to represent a collection of Unicode code point ranges for a specific script.

Therefore, the main function of this code snippet is to define data structures that represent Unicode character ranges for different scripts. This is likely used by the `unicode` package to provide information about Unicode characters, such as determining if a character belongs to a specific script.

To illustrate this, I can show how to use these `RangeTable` variables with functions from the `unicode` package to check if a character belongs to a particular script.
这是 `go/src/unicode/tables.go` 文件的一部分，它定义了一系列 Go 语言的变量，这些变量存储了 Unicode 字符集的各种属性信息，特别是关于不同文字脚本的字符范围。

**功能归纳:**

这部分代码的主要功能是**定义了各种 Unicode 脚本的字符范围表**。 每个变量（例如 `_Bengali`, `_Bhaiksuki`, `_Bopomofo` 等）都对应一个特定的 Unicode 脚本，并存储了该脚本中所有字符的 Unicode 码点范围。

**更具体的功能描述:**

* **定义 RangeTable 结构体变量:**  每个以 `_` 开头的变量，例如 `_Bengali`， 都是指向 `RangeTable` 结构体的指针。`RangeTable` 结构体内部包含了 `R16` 和 `R32` 字段，分别用于存储 16 位和 32 位的 Unicode 码点范围。
* **表示 Unicode 脚本范围:**  `R16` 和 `R32` 字段中的数据定义了该脚本包含的字符码点范围。每个元素是一个结构体，包含起始码点、结束码点以及步长（通常为 1，表示连续的码点，但也可能表示等间隔的码点）。
* **为 unicode 包提供数据:** 这些定义的变量被 `unicode` 标准库包的其他部分使用，以便进行字符属性判断，例如判断一个字符是否属于某个特定的脚本。

**Go 代码示例说明:**

这个代码片段本身是数据定义，通常不会直接执行。它被 `unicode` 包的其他功能模块所使用。我们可以假设 `unicode` 包中存在一个函数，可以利用这些 `RangeTable` 来判断一个字符是否属于某个脚本。

```go
package main

import (
	"fmt"
	"unicode"
)

func main() {
	// 假设 unicode 包中存在一个函数 IsScript(r rune, table *unicode.RangeTable) bool
	// 虽然实际的 unicode 包没有直接暴露这些 RangeTable 变量，
	// 但我们可以通过 unicode.In 来实现类似的功能。

	// 判断字符 'অ' (孟加拉语字母) 是否属于 Bengali 脚本
	char := 'অ'
	isBengali := unicode.In(char, unicode.Bengali)
	fmt.Printf("字符 '%c' 是否属于 Bengali 脚本: %t\n", char, isBengali)

	// 判断字符 'A' (拉丁字母) 是否属于 Bengali 脚本
	char2 := 'A'
	isBengali2 := unicode.In(char2, unicode.Bengali)
	fmt.Printf("字符 '%c' 是否属于 Bengali 脚本: %t\n", char2, isBengali2)
}
```

**假设的输入与输出:**

在这个示例中，我们使用了 `unicode.In` 函数，并假设 `unicode.Bengali`  （在 `unicode/tables.go` 的后续部分定义）引用了前面代码片段中定义的 `_Bengali` 对应的 `RangeTable`。

* **输入 1:** 字符 `'অ'` (Unicode 码点 U+0985)
* **预期输出 1:** `字符 'অ' 是否属于 Bengali 脚本: true`

* **输入 2:** 字符 `'A'` (Unicode 码点 U+0041)
* **预期输出 2:** `字符 'A' 是否属于 Bengali 脚本: false`

**命令行参数处理:**

这段代码不涉及命令行参数的处理。它是 Go 语言源代码的一部分，用于定义静态数据。

**使用者易犯错的点:**

用户不太可能直接操作 `unicode/tables.go` 文件。这个文件是 `unicode` 标准库的一部分，通常由 Go 语言自身维护和使用。 然而，如果用户试图直接修改这些变量，可能会破坏 `unicode` 包的功能，导致程序在处理 Unicode 字符时出现错误。

**总结 (第 4 部分功能归纳):**

这部分 `go/src/unicode/tables.go` 代码的主要功能是**声明和初始化了大量 Go 语言变量，每个变量都是一个指向 `RangeTable` 结构体的指针，用于存储特定 Unicode 脚本的字符码点范围。 这些数据结构是 `unicode` 包实现字符属性判断等功能的基础。**

### 提示词
```
这是路径为go/src/unicode/tables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
0, 1},
		{0x09b2, 0x09b6, 4},
		{0x09b7, 0x09b9, 1},
		{0x09bc, 0x09c4, 1},
		{0x09c7, 0x09c8, 1},
		{0x09cb, 0x09ce, 1},
		{0x09d7, 0x09dc, 5},
		{0x09dd, 0x09df, 2},
		{0x09e0, 0x09e3, 1},
		{0x09e6, 0x09fe, 1},
	},
}

var _Bhaiksuki = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11c00, 0x11c08, 1},
		{0x11c0a, 0x11c36, 1},
		{0x11c38, 0x11c45, 1},
		{0x11c50, 0x11c6c, 1},
	},
}

var _Bopomofo = &RangeTable{
	R16: []Range16{
		{0x02ea, 0x02eb, 1},
		{0x3105, 0x312f, 1},
		{0x31a0, 0x31bf, 1},
	},
}

var _Brahmi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11000, 0x1104d, 1},
		{0x11052, 0x11075, 1},
		{0x1107f, 0x1107f, 1},
	},
}

var _Braille = &RangeTable{
	R16: []Range16{
		{0x2800, 0x28ff, 1},
	},
}

var _Buginese = &RangeTable{
	R16: []Range16{
		{0x1a00, 0x1a1b, 1},
		{0x1a1e, 0x1a1f, 1},
	},
}

var _Buhid = &RangeTable{
	R16: []Range16{
		{0x1740, 0x1753, 1},
	},
}

var _Canadian_Aboriginal = &RangeTable{
	R16: []Range16{
		{0x1400, 0x167f, 1},
		{0x18b0, 0x18f5, 1},
	},
	R32: []Range32{
		{0x11ab0, 0x11abf, 1},
	},
}

var _Carian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x102a0, 0x102d0, 1},
	},
}

var _Caucasian_Albanian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10530, 0x10563, 1},
		{0x1056f, 0x1056f, 1},
	},
}

var _Chakma = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11100, 0x11134, 1},
		{0x11136, 0x11147, 1},
	},
}

var _Cham = &RangeTable{
	R16: []Range16{
		{0xaa00, 0xaa36, 1},
		{0xaa40, 0xaa4d, 1},
		{0xaa50, 0xaa59, 1},
		{0xaa5c, 0xaa5f, 1},
	},
}

var _Cherokee = &RangeTable{
	R16: []Range16{
		{0x13a0, 0x13f5, 1},
		{0x13f8, 0x13fd, 1},
		{0xab70, 0xabbf, 1},
	},
}

var _Chorasmian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10fb0, 0x10fcb, 1},
	},
}

var _Common = &RangeTable{
	R16: []Range16{
		{0x0000, 0x0040, 1},
		{0x005b, 0x0060, 1},
		{0x007b, 0x00a9, 1},
		{0x00ab, 0x00b9, 1},
		{0x00bb, 0x00bf, 1},
		{0x00d7, 0x00f7, 32},
		{0x02b9, 0x02df, 1},
		{0x02e5, 0x02e9, 1},
		{0x02ec, 0x02ff, 1},
		{0x0374, 0x037e, 10},
		{0x0385, 0x0387, 2},
		{0x0605, 0x060c, 7},
		{0x061b, 0x061f, 4},
		{0x0640, 0x06dd, 157},
		{0x08e2, 0x0964, 130},
		{0x0965, 0x0e3f, 1242},
		{0x0fd5, 0x0fd8, 1},
		{0x10fb, 0x16eb, 1520},
		{0x16ec, 0x16ed, 1},
		{0x1735, 0x1736, 1},
		{0x1802, 0x1803, 1},
		{0x1805, 0x1cd3, 1230},
		{0x1ce1, 0x1ce9, 8},
		{0x1cea, 0x1cec, 1},
		{0x1cee, 0x1cf3, 1},
		{0x1cf5, 0x1cf7, 1},
		{0x1cfa, 0x2000, 774},
		{0x2001, 0x200b, 1},
		{0x200e, 0x2064, 1},
		{0x2066, 0x2070, 1},
		{0x2074, 0x207e, 1},
		{0x2080, 0x208e, 1},
		{0x20a0, 0x20c0, 1},
		{0x2100, 0x2125, 1},
		{0x2127, 0x2129, 1},
		{0x212c, 0x2131, 1},
		{0x2133, 0x214d, 1},
		{0x214f, 0x215f, 1},
		{0x2189, 0x218b, 1},
		{0x2190, 0x2426, 1},
		{0x2440, 0x244a, 1},
		{0x2460, 0x27ff, 1},
		{0x2900, 0x2b73, 1},
		{0x2b76, 0x2b95, 1},
		{0x2b97, 0x2bff, 1},
		{0x2e00, 0x2e5d, 1},
		{0x2ff0, 0x2ffb, 1},
		{0x3000, 0x3004, 1},
		{0x3006, 0x3008, 2},
		{0x3009, 0x3020, 1},
		{0x3030, 0x3037, 1},
		{0x303c, 0x303f, 1},
		{0x309b, 0x309c, 1},
		{0x30a0, 0x30fb, 91},
		{0x30fc, 0x3190, 148},
		{0x3191, 0x319f, 1},
		{0x31c0, 0x31e3, 1},
		{0x3220, 0x325f, 1},
		{0x327f, 0x32cf, 1},
		{0x32ff, 0x3358, 89},
		{0x3359, 0x33ff, 1},
		{0x4dc0, 0x4dff, 1},
		{0xa700, 0xa721, 1},
		{0xa788, 0xa78a, 1},
		{0xa830, 0xa839, 1},
		{0xa92e, 0xa9cf, 161},
		{0xab5b, 0xab6a, 15},
		{0xab6b, 0xfd3e, 20947},
		{0xfd3f, 0xfe10, 209},
		{0xfe11, 0xfe19, 1},
		{0xfe30, 0xfe52, 1},
		{0xfe54, 0xfe66, 1},
		{0xfe68, 0xfe6b, 1},
		{0xfeff, 0xff01, 2},
		{0xff02, 0xff20, 1},
		{0xff3b, 0xff40, 1},
		{0xff5b, 0xff65, 1},
		{0xff70, 0xff9e, 46},
		{0xff9f, 0xffe0, 65},
		{0xffe1, 0xffe6, 1},
		{0xffe8, 0xffee, 1},
		{0xfff9, 0xfffd, 1},
	},
	R32: []Range32{
		{0x10100, 0x10102, 1},
		{0x10107, 0x10133, 1},
		{0x10137, 0x1013f, 1},
		{0x10190, 0x1019c, 1},
		{0x101d0, 0x101fc, 1},
		{0x102e1, 0x102fb, 1},
		{0x1bca0, 0x1bca3, 1},
		{0x1cf50, 0x1cfc3, 1},
		{0x1d000, 0x1d0f5, 1},
		{0x1d100, 0x1d126, 1},
		{0x1d129, 0x1d166, 1},
		{0x1d16a, 0x1d17a, 1},
		{0x1d183, 0x1d184, 1},
		{0x1d18c, 0x1d1a9, 1},
		{0x1d1ae, 0x1d1ea, 1},
		{0x1d2c0, 0x1d2d3, 1},
		{0x1d2e0, 0x1d2f3, 1},
		{0x1d300, 0x1d356, 1},
		{0x1d360, 0x1d378, 1},
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
		{0x1d6a8, 0x1d7cb, 1},
		{0x1d7ce, 0x1d7ff, 1},
		{0x1ec71, 0x1ecb4, 1},
		{0x1ed01, 0x1ed3d, 1},
		{0x1f000, 0x1f02b, 1},
		{0x1f030, 0x1f093, 1},
		{0x1f0a0, 0x1f0ae, 1},
		{0x1f0b1, 0x1f0bf, 1},
		{0x1f0c1, 0x1f0cf, 1},
		{0x1f0d1, 0x1f0f5, 1},
		{0x1f100, 0x1f1ad, 1},
		{0x1f1e6, 0x1f1ff, 1},
		{0x1f201, 0x1f202, 1},
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
		{0x1fbf0, 0x1fbf9, 1},
		{0xe0001, 0xe0020, 31},
		{0xe0021, 0xe007f, 1},
	},
	LatinOffset: 6,
}

var _Coptic = &RangeTable{
	R16: []Range16{
		{0x03e2, 0x03ef, 1},
		{0x2c80, 0x2cf3, 1},
		{0x2cf9, 0x2cff, 1},
	},
}

var _Cuneiform = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x12000, 0x12399, 1},
		{0x12400, 0x1246e, 1},
		{0x12470, 0x12474, 1},
		{0x12480, 0x12543, 1},
	},
}

var _Cypriot = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10800, 0x10805, 1},
		{0x10808, 0x1080a, 2},
		{0x1080b, 0x10835, 1},
		{0x10837, 0x10838, 1},
		{0x1083c, 0x1083f, 3},
	},
}

var _Cypro_Minoan = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x12f90, 0x12ff2, 1},
	},
}

var _Cyrillic = &RangeTable{
	R16: []Range16{
		{0x0400, 0x0484, 1},
		{0x0487, 0x052f, 1},
		{0x1c80, 0x1c88, 1},
		{0x1d2b, 0x1d78, 77},
		{0x2de0, 0x2dff, 1},
		{0xa640, 0xa69f, 1},
		{0xfe2e, 0xfe2f, 1},
	},
	R32: []Range32{
		{0x1e030, 0x1e06d, 1},
		{0x1e08f, 0x1e08f, 1},
	},
}

var _Deseret = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10400, 0x1044f, 1},
	},
}

var _Devanagari = &RangeTable{
	R16: []Range16{
		{0x0900, 0x0950, 1},
		{0x0955, 0x0963, 1},
		{0x0966, 0x097f, 1},
		{0xa8e0, 0xa8ff, 1},
	},
	R32: []Range32{
		{0x11b00, 0x11b09, 1},
	},
}

var _Dives_Akuru = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11900, 0x11906, 1},
		{0x11909, 0x1190c, 3},
		{0x1190d, 0x11913, 1},
		{0x11915, 0x11916, 1},
		{0x11918, 0x11935, 1},
		{0x11937, 0x11938, 1},
		{0x1193b, 0x11946, 1},
		{0x11950, 0x11959, 1},
	},
}

var _Dogra = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11800, 0x1183b, 1},
	},
}

var _Duployan = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x1bc00, 0x1bc6a, 1},
		{0x1bc70, 0x1bc7c, 1},
		{0x1bc80, 0x1bc88, 1},
		{0x1bc90, 0x1bc99, 1},
		{0x1bc9c, 0x1bc9f, 1},
	},
}

var _Egyptian_Hieroglyphs = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x13000, 0x13455, 1},
	},
}

var _Elbasan = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10500, 0x10527, 1},
	},
}

var _Elymaic = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10fe0, 0x10ff6, 1},
	},
}

var _Ethiopic = &RangeTable{
	R16: []Range16{
		{0x1200, 0x1248, 1},
		{0x124a, 0x124d, 1},
		{0x1250, 0x1256, 1},
		{0x1258, 0x125a, 2},
		{0x125b, 0x125d, 1},
		{0x1260, 0x1288, 1},
		{0x128a, 0x128d, 1},
		{0x1290, 0x12b0, 1},
		{0x12b2, 0x12b5, 1},
		{0x12b8, 0x12be, 1},
		{0x12c0, 0x12c2, 2},
		{0x12c3, 0x12c5, 1},
		{0x12c8, 0x12d6, 1},
		{0x12d8, 0x1310, 1},
		{0x1312, 0x1315, 1},
		{0x1318, 0x135a, 1},
		{0x135d, 0x137c, 1},
		{0x1380, 0x1399, 1},
		{0x2d80, 0x2d96, 1},
		{0x2da0, 0x2da6, 1},
		{0x2da8, 0x2dae, 1},
		{0x2db0, 0x2db6, 1},
		{0x2db8, 0x2dbe, 1},
		{0x2dc0, 0x2dc6, 1},
		{0x2dc8, 0x2dce, 1},
		{0x2dd0, 0x2dd6, 1},
		{0x2dd8, 0x2dde, 1},
		{0xab01, 0xab06, 1},
		{0xab09, 0xab0e, 1},
		{0xab11, 0xab16, 1},
		{0xab20, 0xab26, 1},
		{0xab28, 0xab2e, 1},
	},
	R32: []Range32{
		{0x1e7e0, 0x1e7e6, 1},
		{0x1e7e8, 0x1e7eb, 1},
		{0x1e7ed, 0x1e7ee, 1},
		{0x1e7f0, 0x1e7fe, 1},
	},
}

var _Georgian = &RangeTable{
	R16: []Range16{
		{0x10a0, 0x10c5, 1},
		{0x10c7, 0x10cd, 6},
		{0x10d0, 0x10fa, 1},
		{0x10fc, 0x10ff, 1},
		{0x1c90, 0x1cba, 1},
		{0x1cbd, 0x1cbf, 1},
		{0x2d00, 0x2d25, 1},
		{0x2d27, 0x2d2d, 6},
	},
}

var _Glagolitic = &RangeTable{
	R16: []Range16{
		{0x2c00, 0x2c5f, 1},
	},
	R32: []Range32{
		{0x1e000, 0x1e006, 1},
		{0x1e008, 0x1e018, 1},
		{0x1e01b, 0x1e021, 1},
		{0x1e023, 0x1e024, 1},
		{0x1e026, 0x1e02a, 1},
	},
}

var _Gothic = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10330, 0x1034a, 1},
	},
}

var _Grantha = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11300, 0x11303, 1},
		{0x11305, 0x1130c, 1},
		{0x1130f, 0x11310, 1},
		{0x11313, 0x11328, 1},
		{0x1132a, 0x11330, 1},
		{0x11332, 0x11333, 1},
		{0x11335, 0x11339, 1},
		{0x1133c, 0x11344, 1},
		{0x11347, 0x11348, 1},
		{0x1134b, 0x1134d, 1},
		{0x11350, 0x11357, 7},
		{0x1135d, 0x11363, 1},
		{0x11366, 0x1136c, 1},
		{0x11370, 0x11374, 1},
	},
}

var _Greek = &RangeTable{
	R16: []Range16{
		{0x0370, 0x0373, 1},
		{0x0375, 0x0377, 1},
		{0x037a, 0x037d, 1},
		{0x037f, 0x0384, 5},
		{0x0386, 0x0388, 2},
		{0x0389, 0x038a, 1},
		{0x038c, 0x038e, 2},
		{0x038f, 0x03a1, 1},
		{0x03a3, 0x03e1, 1},
		{0x03f0, 0x03ff, 1},
		{0x1d26, 0x1d2a, 1},
		{0x1d5d, 0x1d61, 1},
		{0x1d66, 0x1d6a, 1},
		{0x1dbf, 0x1f00, 321},
		{0x1f01, 0x1f15, 1},
		{0x1f18, 0x1f1d, 1},
		{0x1f20, 0x1f45, 1},
		{0x1f48, 0x1f4d, 1},
		{0x1f50, 0x1f57, 1},
		{0x1f59, 0x1f5f, 2},
		{0x1f60, 0x1f7d, 1},
		{0x1f80, 0x1fb4, 1},
		{0x1fb6, 0x1fc4, 1},
		{0x1fc6, 0x1fd3, 1},
		{0x1fd6, 0x1fdb, 1},
		{0x1fdd, 0x1fef, 1},
		{0x1ff2, 0x1ff4, 1},
		{0x1ff6, 0x1ffe, 1},
		{0x2126, 0xab65, 35391},
	},
	R32: []Range32{
		{0x10140, 0x1018e, 1},
		{0x101a0, 0x1d200, 53344},
		{0x1d201, 0x1d245, 1},
	},
}

var _Gujarati = &RangeTable{
	R16: []Range16{
		{0x0a81, 0x0a83, 1},
		{0x0a85, 0x0a8d, 1},
		{0x0a8f, 0x0a91, 1},
		{0x0a93, 0x0aa8, 1},
		{0x0aaa, 0x0ab0, 1},
		{0x0ab2, 0x0ab3, 1},
		{0x0ab5, 0x0ab9, 1},
		{0x0abc, 0x0ac5, 1},
		{0x0ac7, 0x0ac9, 1},
		{0x0acb, 0x0acd, 1},
		{0x0ad0, 0x0ae0, 16},
		{0x0ae1, 0x0ae3, 1},
		{0x0ae6, 0x0af1, 1},
		{0x0af9, 0x0aff, 1},
	},
}

var _Gunjala_Gondi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11d60, 0x11d65, 1},
		{0x11d67, 0x11d68, 1},
		{0x11d6a, 0x11d8e, 1},
		{0x11d90, 0x11d91, 1},
		{0x11d93, 0x11d98, 1},
		{0x11da0, 0x11da9, 1},
	},
}

var _Gurmukhi = &RangeTable{
	R16: []Range16{
		{0x0a01, 0x0a03, 1},
		{0x0a05, 0x0a0a, 1},
		{0x0a0f, 0x0a10, 1},
		{0x0a13, 0x0a28, 1},
		{0x0a2a, 0x0a30, 1},
		{0x0a32, 0x0a33, 1},
		{0x0a35, 0x0a36, 1},
		{0x0a38, 0x0a39, 1},
		{0x0a3c, 0x0a3e, 2},
		{0x0a3f, 0x0a42, 1},
		{0x0a47, 0x0a48, 1},
		{0x0a4b, 0x0a4d, 1},
		{0x0a51, 0x0a59, 8},
		{0x0a5a, 0x0a5c, 1},
		{0x0a5e, 0x0a66, 8},
		{0x0a67, 0x0a76, 1},
	},
}

var _Han = &RangeTable{
	R16: []Range16{
		{0x2e80, 0x2e99, 1},
		{0x2e9b, 0x2ef3, 1},
		{0x2f00, 0x2fd5, 1},
		{0x3005, 0x3007, 2},
		{0x3021, 0x3029, 1},
		{0x3038, 0x303b, 1},
		{0x3400, 0x4dbf, 1},
		{0x4e00, 0x9fff, 1},
		{0xf900, 0xfa6d, 1},
		{0xfa70, 0xfad9, 1},
	},
	R32: []Range32{
		{0x16fe2, 0x16fe3, 1},
		{0x16ff0, 0x16ff1, 1},
		{0x20000, 0x2a6df, 1},
		{0x2a700, 0x2b739, 1},
		{0x2b740, 0x2b81d, 1},
		{0x2b820, 0x2cea1, 1},
		{0x2ceb0, 0x2ebe0, 1},
		{0x2f800, 0x2fa1d, 1},
		{0x30000, 0x3134a, 1},
		{0x31350, 0x323af, 1},
	},
}

var _Hangul = &RangeTable{
	R16: []Range16{
		{0x1100, 0x11ff, 1},
		{0x302e, 0x302f, 1},
		{0x3131, 0x318e, 1},
		{0x3200, 0x321e, 1},
		{0x3260, 0x327e, 1},
		{0xa960, 0xa97c, 1},
		{0xac00, 0xd7a3, 1},
		{0xd7b0, 0xd7c6, 1},
		{0xd7cb, 0xd7fb, 1},
		{0xffa0, 0xffbe, 1},
		{0xffc2, 0xffc7, 1},
		{0xffca, 0xffcf, 1},
		{0xffd2, 0xffd7, 1},
		{0xffda, 0xffdc, 1},
	},
}

var _Hanifi_Rohingya = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10d00, 0x10d27, 1},
		{0x10d30, 0x10d39, 1},
	},
}

var _Hanunoo = &RangeTable{
	R16: []Range16{
		{0x1720, 0x1734, 1},
	},
}

var _Hatran = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x108e0, 0x108f2, 1},
		{0x108f4, 0x108f5, 1},
		{0x108fb, 0x108ff, 1},
	},
}

var _Hebrew = &RangeTable{
	R16: []Range16{
		{0x0591, 0x05c7, 1},
		{0x05d0, 0x05ea, 1},
		{0x05ef, 0x05f4, 1},
		{0xfb1d, 0xfb36, 1},
		{0xfb38, 0xfb3c, 1},
		{0xfb3e, 0xfb40, 2},
		{0xfb41, 0xfb43, 2},
		{0xfb44, 0xfb46, 2},
		{0xfb47, 0xfb4f, 1},
	},
}

var _Hiragana = &RangeTable{
	R16: []Range16{
		{0x3041, 0x3096, 1},
		{0x309d, 0x309f, 1},
	},
	R32: []Range32{
		{0x1b001, 0x1b11f, 1},
		{0x1b132, 0x1b150, 30},
		{0x1b151, 0x1b152, 1},
		{0x1f200, 0x1f200, 1},
	},
}

var _Imperial_Aramaic = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10840, 0x10855, 1},
		{0x10857, 0x1085f, 1},
	},
}

var _Inherited = &RangeTable{
	R16: []Range16{
		{0x0300, 0x036f, 1},
		{0x0485, 0x0486, 1},
		{0x064b, 0x0655, 1},
		{0x0670, 0x0951, 737},
		{0x0952, 0x0954, 1},
		{0x1ab0, 0x1ace, 1},
		{0x1cd0, 0x1cd2, 1},
		{0x1cd4, 0x1ce0, 1},
		{0x1ce2, 0x1ce8, 1},
		{0x1ced, 0x1cf4, 7},
		{0x1cf8, 0x1cf9, 1},
		{0x1dc0, 0x1dff, 1},
		{0x200c, 0x200d, 1},
		{0x20d0, 0x20f0, 1},
		{0x302a, 0x302d, 1},
		{0x3099, 0x309a, 1},
		{0xfe00, 0xfe0f, 1},
		{0xfe20, 0xfe2d, 1},
	},
	R32: []Range32{
		{0x101fd, 0x102e0, 227},
		{0x1133b, 0x1cf00, 48069},
		{0x1cf01, 0x1cf2d, 1},
		{0x1cf30, 0x1cf46, 1},
		{0x1d167, 0x1d169, 1},
		{0x1d17b, 0x1d182, 1},
		{0x1d185, 0x1d18b, 1},
		{0x1d1aa, 0x1d1ad, 1},
		{0xe0100, 0xe01ef, 1},
	},
}

var _Inscriptional_Pahlavi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10b60, 0x10b72, 1},
		{0x10b78, 0x10b7f, 1},
	},
}

var _Inscriptional_Parthian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10b40, 0x10b55, 1},
		{0x10b58, 0x10b5f, 1},
	},
}

var _Javanese = &RangeTable{
	R16: []Range16{
		{0xa980, 0xa9cd, 1},
		{0xa9d0, 0xa9d9, 1},
		{0xa9de, 0xa9df, 1},
	},
}

var _Kaithi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11080, 0x110c2, 1},
		{0x110cd, 0x110cd, 1},
	},
}

var _Kannada = &RangeTable{
	R16: []Range16{
		{0x0c80, 0x0c8c, 1},
		{0x0c8e, 0x0c90, 1},
		{0x0c92, 0x0ca8, 1},
		{0x0caa, 0x0cb3, 1},
		{0x0cb5, 0x0cb9, 1},
		{0x0cbc, 0x0cc4, 1},
		{0x0cc6, 0x0cc8, 1},
		{0x0cca, 0x0ccd, 1},
		{0x0cd5, 0x0cd6, 1},
		{0x0cdd, 0x0cde, 1},
		{0x0ce0, 0x0ce3, 1},
		{0x0ce6, 0x0cef, 1},
		{0x0cf1, 0x0cf3, 1},
	},
}

var _Katakana = &RangeTable{
	R16: []Range16{
		{0x30a1, 0x30fa, 1},
		{0x30fd, 0x30ff, 1},
		{0x31f0, 0x31ff, 1},
		{0x32d0, 0x32fe, 1},
		{0x3300, 0x3357, 1},
		{0xff66, 0xff6f, 1},
		{0xff71, 0xff9d, 1},
	},
	R32: []Range32{
		{0x1aff0, 0x1aff3, 1},
		{0x1aff5, 0x1affb, 1},
		{0x1affd, 0x1affe, 1},
		{0x1b000, 0x1b120, 288},
		{0x1b121, 0x1b122, 1},
		{0x1b155, 0x1b164, 15},
		{0x1b165, 0x1b167, 1},
	},
}

var _Kawi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11f00, 0x11f10, 1},
		{0x11f12, 0x11f3a, 1},
		{0x11f3e, 0x11f59, 1},
	},
}

var _Kayah_Li = &RangeTable{
	R16: []Range16{
		{0xa900, 0xa92d, 1},
		{0xa92f, 0xa92f, 1},
	},
}

var _Kharoshthi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10a00, 0x10a03, 1},
		{0x10a05, 0x10a06, 1},
		{0x10a0c, 0x10a13, 1},
		{0x10a15, 0x10a17, 1},
		{0x10a19, 0x10a35, 1},
		{0x10a38, 0x10a3a, 1},
		{0x10a3f, 0x10a48, 1},
		{0x10a50, 0x10a58, 1},
	},
}

var _Khitan_Small_Script = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x16fe4, 0x18b00, 6940},
		{0x18b01, 0x18cd5, 1},
	},
}

var _Khmer = &RangeTable{
	R16: []Range16{
		{0x1780, 0x17dd, 1},
		{0x17e0, 0x17e9, 1},
		{0x17f0, 0x17f9, 1},
		{0x19e0, 0x19ff, 1},
	},
}

var _Khojki = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11200, 0x11211, 1},
		{0x11213, 0x11241, 1},
	},
}

var _Khudawadi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x112b0, 0x112ea, 1},
		{0x112f0, 0x112f9, 1},
	},
}

var _Lao = &RangeTable{
	R16: []Range16{
		{0x0e81, 0x0e82, 1},
		{0x0e84, 0x0e86, 2},
		{0x0e87, 0x0e8a, 1},
		{0x0e8c, 0x0ea3, 1},
		{0x0ea5, 0x0ea7, 2},
		{0x0ea8, 0x0ebd, 1},
		{0x0ec0, 0x0ec4, 1},
		{0x0ec6, 0x0ec8, 2},
		{0x0ec9, 0x0ece, 1},
		{0x0ed0, 0x0ed9, 1},
		{0x0edc, 0x0edf, 1},
	},
}

var _Latin = &RangeTable{
	R16: []Range16{
		{0x0041, 0x005a, 1},
		{0x0061, 0x007a, 1},
		{0x00aa, 0x00ba, 16},
		{0x00c0, 0x00d6, 1},
		{0x00d8, 0x00f6, 1},
		{0x00f8, 0x02b8, 1},
		{0x02e0, 0x02e4, 1},
		{0x1d00, 0x1d25, 1},
		{0x1d2c, 0x1d5c, 1},
		{0x1d62, 0x1d65, 1},
		{0x1d6b, 0x1d77, 1},
		{0x1d79, 0x1dbe, 1},
		{0x1e00, 0x1eff, 1},
		{0x2071, 0x207f, 14},
		{0x2090, 0x209c, 1},
		{0x212a, 0x212b, 1},
		{0x2132, 0x214e, 28},
		{0x2160, 0x2188, 1},
		{0x2c60, 0x2c7f, 1},
		{0xa722, 0xa787, 1},
		{0xa78b, 0xa7ca, 1},
		{0xa7d0, 0xa7d1, 1},
		{0xa7d3, 0xa7d5, 2},
		{0xa7d6, 0xa7d9, 1},
		{0xa7f2, 0xa7ff, 1},
		{0xab30, 0xab5a, 1},
		{0xab5c, 0xab64, 1},
		{0xab66, 0xab69, 1},
		{0xfb00, 0xfb06, 1},
		{0xff21, 0xff3a, 1},
		{0xff41, 0xff5a, 1},
	},
	R32: []Range32{
		{0x10780, 0x10785, 1},
		{0x10787, 0x107b0, 1},
		{0x107b2, 0x107ba, 1},
		{0x1df00, 0x1df1e, 1},
		{0x1df25, 0x1df2a, 1},
	},
	LatinOffset: 5,
}

var _Lepcha = &RangeTable{
	R16: []Range16{
		{0x1c00, 0x1c37, 1},
		{0x1c3b, 0x1c49, 1},
		{0x1c4d, 0x1c4f, 1},
	},
}

var _Limbu = &RangeTable{
	R16: []Range16{
		{0x1900, 0x191e, 1},
		{0x1920, 0x192b, 1},
		{0x1930, 0x193b, 1},
		{0x1940, 0x1944, 4},
		{0x1945, 0x194f, 1},
	},
}

var _Linear_A = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10600, 0x10736, 1},
		{0x10740, 0x10755, 1},
		{0x10760, 0x10767, 1},
	},
}

var _Linear_B = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10000, 0x1000b, 1},
		{0x1000d, 0x10026, 1},
		{0x10028, 0x1003a, 1},
		{0x1003c, 0x1003d, 1},
		{0x1003f, 0x1004d, 1},
		{0x10050, 0x1005d, 1},
		{0x10080, 0x100fa, 1},
	},
}

var _Lisu = &RangeTable{
	R16: []Range16{
		{0xa4d0, 0xa4ff, 1},
	},
	R32: []Range32{
		{0x11fb0, 0x11fb0, 1},
	},
}

var _Lycian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10280, 0x1029c, 1},
	},
}

var _Lydian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10920, 0x10939, 1},
		{0x1093f, 0x1093f, 1},
	},
}

var _Mahajani = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11150, 0x11176, 1},
	},
}

var _Makasar = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11ee0, 0x11ef8, 1},
	},
}

var _Malayalam = &RangeTable{
	R16: []Range16{
		{0x0d00, 0x0d0c, 1},
		{0x0d0e, 0x0d10, 1},
		{0x0d12, 0x0d44, 1},
		{0x0d46, 0x0d48, 1},
		{0x0d4a, 0x0d4f, 1},
		{0x0d54, 0x0d63, 1},
		{0x0d66, 0x0d7f, 1},
	},
}

var _Mandaic = &RangeTable{
	R16: []Range16{
		{0x0840, 0x085b, 1},
		{0x085e, 0x085e, 1},
	},
}

var _Manichaean = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10ac0, 0x10ae6, 1},
		{0x10aeb, 0x10af6, 1},
	},
}

var _Marchen = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11c70, 0x11c8f, 1},
		{0x11c92, 0x11ca7, 1},
		{0x11ca9, 0x11cb6, 1},
	},
}

var _Masaram_Gondi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11d00, 0x11d06, 1},
		{0x11d08, 0x11d09, 1},
		{0x11d0b, 0x11d36, 1},
		{0x11d3a, 0x11d3c, 2},
		{0x11d3d, 0x11d3f, 2},
		{0x11d40, 0x11d47, 1},
		{0x11d50, 0x11d59, 1},
	},
}

var _Medefaidrin = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x16e40, 0x16e9a, 1},
	},
}

var _Meetei_Mayek = &RangeTable{
	R16: []Range16{
		{0xaae0, 0xaaf6, 1},
		{0xabc0, 0xabed, 1},
		{0xabf0, 0xabf9, 1},
	},
}

var _Mende_Kikakui = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x1e800, 0x1e8c4, 1},
		{0x1e8c7, 0x1e8d6, 1},
	},
}

var _Meroitic_Cursive = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x109a0, 0x109b7, 1},
		{0x109bc, 0x109cf, 1},
		{0x109d2, 0x109ff, 1},
	},
}

var _Meroitic_Hieroglyphs = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10980, 0x1099f, 1},
	},
}

var _Miao = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x16f00, 0x16f4a, 1},
		{0x16f4f, 0x16f87, 1},
		{0x16f8f, 0x16f9f, 1},
	},
}

var _Modi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11600, 0x11644, 1},
		{0x11650, 0x11659, 1},
	},
}

var _Mongolian = &RangeTable{
	R16: []Range16{
		{0x1800, 0x1801, 1},
		{0x1804, 0x1806, 2},
		{0x1807, 0x1819, 1},
		{0x1820, 0x1878, 1},
		{0x1880, 0x18aa, 1},
	},
	R32: []Range32{
		{0x11660, 0x1166c, 1},
	},
}

var _Mro = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x16a40, 0x16a5e, 1},
		{0x16a60, 0x16a69, 1},
		{0x16a6e, 0x16a6f, 1},
	},
}

var _Multani = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11280, 0x11286, 1},
		{0x11288, 0x1128a, 2},
		{0x1128b, 0x1128d, 1},
		{0x1128f, 0x1129d, 1},
		{0x1129f, 0x112a9, 1},
	},
}

var _Myanmar = &RangeTable{
	R16: []Range16{
		{0x1000, 0x109f, 1},
		{0xa9e0, 0xa9fe, 1},
		{0xaa60, 0xaa7f, 1},
	},
}

var _Nabataean = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10880, 0x1089e, 1},
		{0x108a7, 0x108af, 1},
	},
}

var _Nag_Mundari = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x1e4d0, 0x1e4f9, 1},
	},
}

var _Nandinagari = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x119a0, 0x119a7, 1},
		{0x119aa, 0x119d7, 1},
		{0x119da, 0x119e4, 1},
	},
}

var _New_Tai_Lue = &RangeTable{
	R16: []Range16{
		{0x1980, 0x19ab, 1},
		{0x19b0, 0x19c9, 1},
		{0x19d0, 0x19da, 1},
		{0x19de, 0x19df, 1},
	},
}

var _Newa = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11400, 0x1145b, 1},
		{0x1145d, 0x11461, 1},
	},
}

var _Nko = &RangeTable{
	R16: []Range16{
		{0x07c0, 0x07fa, 1},
		{0x07fd, 0x07ff, 1},
	},
}

var _Nushu = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x16fe1, 0x1b170, 16783},
		{0x1b171, 0x1b2fb, 1},
	},
}

var _Nyiakeng_Puachue_Hmong = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x1e100, 0x1e12c, 1},
		{0x1e130, 0x1e13d, 1},
		{0x1e140, 0x1e149, 1},
		{0x1e14e, 0x1e14f, 1},
	},
}

var _Ogham = &RangeTable{
	R16: []Range16{
		{0x1680, 0x169c, 1},
	},
}

var _Ol_Chiki = &RangeTable{
	R16: []Range16{
		{0x1c50, 0x1c7f, 1},
	},
}

var _Old_Hungarian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10c80, 0x10cb2, 1},
		{0x10cc0, 0x10cf2, 1},
		{0x10cfa, 0x10cff, 1},
	},
}

var _Old_Italic = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10300, 0x10323, 1},
		{0x1032d, 0x1032f, 1},
	},
}

var _Old_North_Arabian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10a80, 0x10a9f, 1},
	},
}

var _Old_Permic = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10350, 0x1037a, 1},
	},
}

var _Old_Persian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x103a0, 0x103c3, 1},
		{0x103c8, 0x103d5, 1},
	},
}

var _Old_Sogdian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10f00, 0x10f27, 1},
	},
}

var _Old_South_Arabian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10a60, 0x10a7f, 1},
	},
}

var _Old_Turkic = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10c00, 0x10c48, 1},
	},
}

var _Old_Uyghur = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10f70, 0x10f89, 1},
	},
}

var _Oriya = &RangeTable{
	R16: []Range16{
		{0x0b01, 0x0b03, 1},
		{0x0b05, 0x0b0c, 1},
		{0x0b0f, 0x0b10, 1},
		{0x0b13, 0x0b28, 1},
		{0x0b2a, 0x0b30, 1},
		{0x0b32, 0x0b33, 1},
		{0x0b35, 0x0b39, 1},
		{0x0b3c, 0x0b44, 1},
		{0x0b47, 0x0b48, 1},
		{0x0b4b, 0x0b4d, 1},
		{0x0b55, 0x0b57, 1},
		{0x0b5c, 0x0b5d, 1},
		{0x0b5f, 0x0b63, 1},
		{0x0b66, 0x0b77, 1},
	},
}

var _Osage = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x104b0, 0x104d3, 1},
		{0x104d8, 0x104fb, 1},
	},
}

var _Osmanya = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10480, 0x1049d, 1},
		{0x104a0, 0x104a9, 1},
	},
}

var _Pahawh_Hmong = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x16b00, 0x16b45, 1},
		{0x16b50, 0x16b59, 1},
		{0x16b5b, 0x16b61, 1},
		{0x16b63, 0x16b77, 1},
		{0x16b7d, 0x16b8f, 1},
	},
}

var _Palmyrene = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10860, 0x1087f, 1},
	},
}

var _Pau_Cin_Hau = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11ac0, 0x11af8, 1},
	},
}

var _Phags_Pa = &RangeTable{
	R16: []Range16{
		{0xa840, 0xa877, 1},
	},
}

var _Phoenician = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10900, 0x1091b, 1},
		{0x1091f, 0x1091f, 1},
	},
}

var _Psalter_Pahlavi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10b80, 0x10b91, 1},
		{0x10b99, 0x10b9c, 1},
		{0x10ba9, 0x10baf, 1},
	},
}

var _Rejang = &RangeTable{
	R16: []Range16{
		{0xa930, 0xa953, 1},
		{0xa95f, 0xa95f, 1},
	},
}

var _Runic = &RangeTable{
	R16: []Range16{
		{0x16a0, 0x16ea, 1},
		{0x16ee, 0x16f8, 1},
	},
}

var _Samaritan = &RangeTable{
	R16: []Range16{
		{0x0800, 0x082d, 1},
		{0x0830, 0x083e, 1},
	},
}

var _Saurashtra = &RangeTable{
	R16: []Range16{
		{0xa880, 0xa8c5, 1},
		{0xa8ce, 0xa8d9, 1},
	},
}

var _Sharada = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11180, 0x111df, 1},
	},
}

var _Shavian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10450, 0x1047f, 1},
	},
}

var _Siddham = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11580, 0x115b5, 1},
		{0x115b8, 0x115dd, 1},
	},
}

var _SignWriting = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x1d800, 0x1da8b, 1},
		{0x1da9b, 0x1da9f, 1},
		{0x1daa1, 0x1daaf, 1},
	},
}

var _Sinhala = &RangeTable{
	R16: []Range16{
		{0x0d81, 0x0d83, 1},
		{0x0d85, 0x0d96, 1},
		{0x0d9a, 0x0db1, 1},
		{0x0db3, 0x0dbb, 1},
		{0x0dbd, 0x0dc0, 3},
		{0x0dc1, 0x0dc6, 1},
		{0x0dca, 0x0dcf, 5},
		{0x0dd0, 0x0dd4, 1},
		{0x0dd6, 0x0dd8, 2},
		{0x0dd9, 0x0ddf, 1},
		{0x0de6, 0x0def, 1},
		{0x0df2, 0x0df4, 1},
	},
	R32: []Range32{
		{0x111e1, 0x111f4, 1},
	},
}

var _Sogdian = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10f30, 0x10f59, 1},
	},
}

var _Sora_Sompeng = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x110d0, 0x110e8, 1},
		{0x110f0, 0x110f9, 1},
	},
}

var _Soyombo = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11a50, 0x11aa2, 1},
	},
}

var _Sundanese = &RangeTable{
	R16: []Range16{
		{0x1b80, 0x1bbf, 1},
		{0x1cc0, 0x1cc7, 1},
	},
}

var _Syloti_Nagri = &RangeTable{
	R16: []Range16{
		{0xa800, 0xa82c, 1},
	},
}

var _Syriac = &RangeTable{
	R16: []Range16{
		{0x0700, 0x070d, 1},
		{0x070f, 0x074a, 1},
		{0x074d, 0x074f, 1},
		{0x0860, 0x086a, 1},
	},
}

var _Tagalog = &RangeTable{
	R16: []Range16{
		{0x1700, 0x1715, 1},
		{0x171f, 0x171f, 1},
	},
}

var _Tagbanwa = &RangeTable{
	R16: []Range16{
		{0x1760, 0x176c, 1},
		{0x176e, 0x1770, 1},
		{0x1772, 0x1773, 1},
	},
}

var _Tai_Le = &RangeTable{
	R16: []Range16{
		{0x1950, 0x196d, 1},
		{0x1970, 0x1974, 1},
	},
}

var _Tai_Tham = &RangeTable{
	R16: []Range16{
		{0x1a20, 0x1a5e, 1},
		{0x1a60, 0x1a7c, 1},
		{0x1a7f, 0x1a89, 1},
		{0x1a90, 0x1a99, 1},
		{0x1aa0, 0x1aad, 1},
	},
}

var _Tai_Viet = &RangeTable{
	R16: []Range16{
		{0xaa80, 0xaac2, 1},
		{0xaadb, 0xaadf, 1},
	},
}

var _Takri = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11680, 0x116b9, 1},
		{0x116c0, 0x116c9, 1},
	},
}

var _Tamil = &RangeTable{
	R16: []Range16{
		{0x0b82, 0x0b83, 1},
		{0x0b85, 0x0b8a, 1},
		{0x0b8e, 0x0b90, 1},
		{0x0b92, 0x0b95, 1},
		{0x0b99, 0x0b9a, 1},
		{0x0b9c, 0x0b9e, 2},
		{0x0b9f, 0x0ba3, 4},
		{0x0ba4, 0x0ba8, 4},
		{0x0ba9, 0x0baa, 1},
		{0x0bae, 0x0bb9, 1},
		{0x0bbe, 0x0bc2, 1},
		{0x0bc6, 0x0bc8, 1},
		{0x0bca, 0x0bcd, 1},
		{0x0bd0, 0x0bd7, 7},
		{0x0be6, 0x0bfa, 1},
	},
	R32: []Range32{
		{0x11fc0, 0x11ff1, 1},
		{0x11fff, 0x11fff, 1},
	},
}

var _Tangsa = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x16a70, 0x16abe, 1},
		{0x16ac0, 0x16ac9, 1},
	},
}

var _Tangut = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x16fe0, 0x17000, 32},
		{0x17001, 0x187f7, 1},
		{0x18800, 0x18aff, 1},
		{0x18d00, 0x18d08, 1},
	},
}

var _Telugu = &RangeTable{
	R16: []Range16{
		{0x0c00, 0x0c0c, 1},
		{0x0c0e, 0x0c10, 1},
		{0x0c12, 0x0c28, 1},
		{0x0c2a, 0x0c39, 1},
		{0x0c3c, 0x0c44, 1},
		{0x0c46, 0x0c48, 1},
		{0x0c4a, 0x0c4d, 1},
		{0x0c55, 0x0c56, 1},
		{0x0c58, 0x0c5a, 1},
		{0x0c5d, 0x0c60, 3},
		{0x0c61, 0x0c63, 1},
		{0x0c66, 0x0c6f, 1},
		{0x0c77, 0x0c7f, 1},
	},
}

var _Thaana = &RangeTable{
	R16: []Range16{
		{0x0780, 0x07b1, 1},
	},
}

var _Thai = &RangeTable{
	R16: []Range16{
		{0x0e01, 0x0e3a, 1},
		{0x0e40, 0x0e5b, 1},
	},
}

var _Tibetan = &RangeTable{
	R16: []Range16{
		{0x0f00, 0x0f47, 1},
		{0x0f49, 0x0f6c, 1},
		{0x0f71, 0x0f97, 1},
		{0x0f99, 0x0fbc, 1},
		{0x0fbe, 0x0fcc, 1},
		{0x0fce, 0x0fd4, 1},
		{0x0fd9, 0x0fda, 1},
	},
}

var _Tifinagh = &RangeTable{
	R16: []Range16{
		{0x2d30, 0x2d67, 1},
		{0x2d6f, 0x2d70, 1},
		{0x2d7f, 0x2d7f, 1},
	},
}

var _Tirhuta = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11480, 0x114c7, 1},
		{0x114d0, 0x114d9, 1},
	},
}

var _Toto = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x1e290, 0x1e2ae, 1},
	},
}

var _Ugaritic = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10380, 0x1039d, 1},
		{0x1039f, 0x1039f, 1},
	},
}

var _Vai = &RangeTable{
	R16: []Range16{
		{0xa500, 0xa62b, 1},
	},
}

var _Vithkuqi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10570, 0x1057a, 1},
		{0x1057c, 0x1058a, 1},
		{0x1058c, 0x10592, 1},
		{0x10594, 0x10595, 1},
		{0x10597, 0x105a1, 1},
		{0x105a3, 0x105b1, 1},
		{0x105b3, 0x105b9, 1},
		{0x105bb, 0x105bc, 1},
	},
}

var _Wancho = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x1e2c0, 0x1e2f9, 1},
		{0x1e2ff, 0x1e2ff, 1},
	},
}

var _Warang_Citi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x118a0, 0x118f2, 1},
		{0x118ff, 0x118ff, 1},
	},
}

var _Yezidi = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x10e80, 0x10ea9, 1},
		{0x10eab, 0x10ead, 1},
		{0x10eb0, 0x10eb1, 1},
	},
}

var _Yi = &RangeTable{
	R16: []Range16{
		{0xa000, 0xa48c, 1},
		{0xa490, 0xa4c6, 1},
	},
}

var _Zanabazar_Square = &RangeTable{
	R16: []Range16{},
	R32: []Range32{
		{0x11a00, 0x11a47, 1},
	},
}

// These variables have type *RangeTable.
var (
	Adlam                  = _Adlam                  // Adlam is the set of Unicode characters in script Adlam.
	Ahom                   = _Ahom                   // Ahom is the set of Unicode characters in script Ahom.
	Anatolian_Hieroglyphs  = _Anatolian_Hieroglyphs  // Anatolian_Hieroglyphs is the set of Unicode characters in script Anatolian_Hieroglyphs.
	Arabic                 = _Arabic                 // Arabic is the set of Unicode characters in script Arabic.
	Armenian               = _Armenian               // Armenian is the set of Unicode characters in script Armenian.
	Avestan                = _Avestan                // Avestan is the set of Unicode characters in script Avestan.
	Balinese               = _Balinese               // Balinese is the set of Unicode characters in script Balinese.
	Bamum                  = _Bamum                  // Bamum is the set of Unicode characters in script Bamum.
	Bassa_Vah              = _Bassa_Vah              // Bassa_Vah is the set of Unicode characters in script Bassa_Vah.
	Batak                  = _Batak                  // Batak is the set of Unicode characters in script Batak.
	Bengali                = _Bengali                // Bengali is the set of Unicode characters in script Bengali.
	Bhaiksuki              = _Bhaiksuki              // Bhaiksuki is the set of Unicode characters in script Bhaiksuki.
	Bopomofo               = _Bopomofo               // Bopomofo is the set of Unicode characters in script Bopomofo.
	Brahmi                 = _Brahmi                 // Brahmi is the set of Unicode characters in script Brahmi.
	Braille                = _Braille                // Braille is the set of Unicode characters in script Braille.
	Buginese               = _Buginese               // Buginese is the set of Unicode characters in script Buginese.
	Buhid                  = _Buhid                  // Buhid is the set of Unicode characters in script Buhid.
	Canadian_Aboriginal    = _Canadian_Aboriginal    // Canadian_Aboriginal is the set of Unicode characters in script Canadian_Aboriginal.
	Carian                 = _Carian                 // Carian is the set of Unicode characters in script Carian.
	Caucasian_Albanian     = _Caucasian_Albanian     // Caucasian_Albanian is the set of Unicode characters in script Caucasian_Albanian.
	Chakma                 = _Chakma
```