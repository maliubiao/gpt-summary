Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding and Context:**

* **File Path:** `go/src/unicode/tables.go` - This immediately tells us this is part of the Go standard library, specifically dealing with Unicode. The name `tables.go` suggests it contains data structures holding Unicode property information.
* **Structure:** The code consists primarily of variable declarations, mostly arrays and maps, initialized with seemingly arbitrary numbers and characters. There are comments indicating character representations (e.g., `'¡'`). This strongly hints at character mappings and properties.
* **Part Number:** "Part 7 of 7" signifies this is the *final* piece of a larger dataset. This is important for the final summarization.

**2. Deconstructing the Data Structures:**

* **`asciiCase` Array:** This array is indexed from 0 to `MaxASCII + 1`. The values are `uint8`. The comments show mappings from ASCII codes (e.g., `0x41` to `'A'`). This strongly suggests a direct mapping of ASCII values to their case-folded counterparts. Notice the upper-to-lower case conversion pattern.
* **`caseprops` Array:**  This array is indexed from 0 to 255 (`0xFF`). The values are `pC`, `pZ`, `pP`, etc., combined with bitwise OR (`| pp`). The comments show corresponding Unicode characters. The prefixes `pC`, `pZ`, `pP` are likely constants defined elsewhere, representing Unicode character categories (Control, Separator, Punctuation, etc.). The `pp` flag might indicate a property like "printable." This array seems to define the basic Unicode category and potentially other properties for the first 256 Unicode code points (Latin-1 Supplement).
* **`asciiFold` Array:** Similar to `asciiCase`, but the values are `uint16`. This suggests it handles code points beyond basic ASCII. The values map ASCII characters to their simple case fold equivalents. Notice the mapping of uppercase letters to lowercase.
* **`caseOrbit` Slice:** This is a slice of `foldPair` structs. Each `foldPair` has two `rune` (integer representation of Unicode code point) fields. This structure suggests cycles or orbits in case folding. If you case-fold one element, you get the next, and eventually return to the start (or a different related form).
* **`FoldCategory` Map:**  The keys are strings like "L", "Ll", "Lu", and the values are pointers to `RangeTable` structs. These keys likely correspond to general Unicode categories (Letter, Lowercase Letter, Uppercase Letter). This map provides access to more specific case folding information based on category.
* **`foldL`, `foldLl`, `foldLu`, `foldM`, `foldMn` Variables:** These are all pointers to `RangeTable` structs. They contain `R16` and `R32` fields, which are slices of `Range16` and `Range32` structs, respectively. These structures likely define ranges of Unicode code points and offsets for case folding within specific categories. The `LatinOffset` field suggests optimization for Latin scripts.
* **`FoldScript` Map:** Similar to `FoldCategory`, but the keys are script names like "Common", "Greek", "Inherited". This maps scripts to case folding rules.
* **`foldCommon`, `foldGreek`, `foldInherited` Variables:**  Again, pointers to `RangeTable`, defining script-specific case folding rules.

**3. Inferring Functionality:**

Based on the data structures, the primary function of this code is to provide data for Unicode case folding. This includes:

* **Simple Case Folding:** Converting characters to their lowercase or uppercase equivalents (e.g., 'A' to 'a').
* **Full Case Folding (Implied):** While not explicitly shown in the snippet, the `caseOrbit` suggests a more complex folding process that might involve multiple steps.
* **Case Folding by Category:** Allowing case folding operations to be restricted to specific Unicode categories (e.g., only letters).
* **Case Folding by Script:** Enabling case folding based on the script of the character.

**4. Go Code Examples (with Assumptions):**

Since we don't have the full `unicode` package code, we need to make assumptions about the functions that would use these tables.

* **Assumption 1:** There's a function `unicode.SimpleFold(r rune) rune` that takes a rune and returns its simple case folded counterpart.
* **Assumption 2:** There are functions or methods that use the `FoldCategory` and `FoldScript` maps to perform more targeted case folding.

```go
package main

import (
	"fmt"
	"unicode"
)

func main() {
	// Example of simple case folding (using assumed unicode.SimpleFold)
	fmt.Printf("Simple fold of 'A': %c\n", unicode.SimpleFold('A'))   // Output: Simple fold of 'A': a
	fmt.Printf("Simple fold of 'a': %c\n", unicode.SimpleFold('a'))   // Output: Simple fold of 'a': A (might orbit)
	fmt.Printf("Simple fold of 'K': %c\n", unicode.SimpleFold('K'))   // Output: Simple fold of 'K': k
	fmt.Printf("Simple fold of 'µ': %c\n", unicode.SimpleFold('µ'))   // Output: Simple fold of 'µ': μ

	// Example of category-based folding (conceptual, actual function might differ)
	// Assuming there's a way to access FoldCategory
	if foldLlTable, ok := unicode.FoldCategory["Ll"]; ok {
		// Check if 'A' can be folded to lowercase according to the table
		for _, r16 := range foldLlTable.R16 {
			if 'A' >= rune(r16.Lo) && 'A' <= rune(r16.Hi) {
				fmt.Println("'A' can be folded to lowercase based on category 'Ll'")
				break
			}
		}
	}
}
```

**5. Command-Line Arguments:**

This code snippet *itself* doesn't handle command-line arguments. It's a data definition file. However, the functions in the `unicode` package that *use* this data might be part of larger programs that do. For example, a text processing tool might have a `--case-fold` option.

**6. Common Mistakes:**

Without knowing the exact API of the `unicode` package, it's hard to pinpoint specific user errors related to *this specific data*. However, common mistakes with Unicode case folding in general include:

* **Assuming simple case folding is sufficient for all comparisons:** Some languages have more complex case folding rules.
* **Not considering locale-specific case folding:** Case folding can vary depending on the language. The `unicode` package likely provides mechanisms for this, but the provided snippet doesn't expose that.
* **Incorrectly implementing custom case folding:** Trying to replicate Unicode case folding logic without fully understanding the rules can lead to errors.

**7. Final Summarization (as requested in the prompt):**

This final part of `go/src/unicode/tables.go` primarily defines data structures (arrays, slices, and maps) that hold information crucial for implementing Unicode case folding in Go. It includes mappings for ASCII case conversion, general Unicode character properties related to case, and more complex case folding rules organized by Unicode category and script. This data is likely used by functions within the `unicode` package to perform various case folding operations. Because it's the *final* part, it completes the definition of these tables, providing the necessary information for the full range of Unicode characters.

This systematic breakdown of the code's structure, data, and likely usage allows us to answer the prompt's questions effectively, even without the complete context of the `unicode` package.
这是 `go/src/unicode/tables.go` 文件的第七部分，它主要定义了用于 Unicode 大小写折叠的数据结构。让我们分解一下其功能：

**1. 功能列举:**

* **`asciiCase` 数组:**  存储了 ASCII 字符的大小写转换信息。对于每个 ASCII 字符，它存储了其对应的大小写形式。例如，大写字母 'A' 映射到小写字母 'a'，小写字母 'a' 映射到大写字母 'A'。
* **`caseprops` 数组:**  存储了前 256 个 Unicode 代码点 (基本拉丁字符和拉丁字母补充) 的属性信息。这些信息用位掩码表示，例如 `pC` 可能代表控制字符，`pZ` 代表分隔符，`pP` 代表标点符号， `pp` 可能是指打印字符的属性。
* **`asciiFold` 数组:** 存储了 ASCII 字符的简单大小写折叠信息。简单大小写折叠通常将字符转换为其对应的小写形式（对于有大小写区分的字符）。
* **`caseOrbit` 切片:**  存储了复杂的大小写折叠关系，构成一个“轨道”。例如，某些字符的大小写折叠会形成一个循环，即一个字符折叠成另一个字符，然后那个字符又可以折叠回原始字符或者折叠成第三个字符。
* **`FoldCategory` Map:**  将 Unicode 字符的类别名称（例如 "L" 代表字母, "Ll" 代表小写字母, "Lu" 代表大写字母）映射到 `RangeTable` 结构。这些 `RangeTable` 包含了不在该类别中，但可以通过简单大小写折叠转换到该类别中的代码点范围。
* **`foldL`, `foldLl`, `foldLt`, `foldLu`, `foldM`, `foldMn` 变量:**  这些变量都是指向 `RangeTable` 结构的指针。它们定义了特定 Unicode 类别的大小写折叠规则。`RangeTable` 结构包含了 `R16` (用于表示 16 位代码点范围) 和 `R32` (用于表示 32 位代码点范围) 字段，以及 `LatinOffset` 字段，可能用于优化拉丁字符的处理。
* **`FoldScript` Map:** 将 Unicode 脚本名称（例如 "Common", "Greek", "Inherited"）映射到 `RangeTable` 结构。 这些 `RangeTable` 包含了不在该脚本中，但可以通过简单大小写折叠转换到该脚本中的代码点范围。
* **`foldCommon`, `foldGreek`, `foldInherited` 变量:** 这些变量都是指向 `RangeTable` 结构的指针。它们定义了特定 Unicode 脚本的大小写折叠规则。

**2. Go 语言功能的实现 (大小写折叠):**

这个文件是 Go 语言 `unicode` 包中实现 Unicode 大小写折叠功能的关键数据来源。大小写折叠主要用于不区分大小写地比较字符串或进行文本搜索。

**Go 代码示例:**

假设 `unicode` 包中存在一个名为 `SimpleFold` 的函数，用于执行简单的大小写折叠：

```go
package main

import (
	"fmt"
	"unicode"
)

func main() {
	fmt.Printf("SimpleFold('A'): %c\n", unicode.SimpleFold('A'))   // 输出: SimpleFold('A'): a
	fmt.Printf("SimpleFold('a'): %c\n", unicode.SimpleFold('a'))   // 输出: SimpleFold('a'): A
	fmt.Printf("SimpleFold('K'): %c\n", unicode.SimpleFold('K'))   // 输出: SimpleFold('K'): k
	fmt.Printf("SimpleFold('k'): %c\n", unicode.SimpleFold('k'))   // 输出: SimpleFold('k'): K
	fmt.Printf("SimpleFold('µ'): %c\n", unicode.SimpleFold('µ'))   // 输出: SimpleFold('µ'): μ (希腊小写字母 mu)
	fmt.Printf("SimpleFold('Μ'): %c\n", unicode.SimpleFold('Μ'))   // 输出: SimpleFold('Μ'): μ (希腊小写字母 mu)
}
```

**假设的输入与输出:**

* **输入:** 字符 'A'
* **输出:** 字符 'a' (基于 `asciiFold` 数组)

* **输入:** 字符 'µ' (micro sign)
* **输出:** 字符 'μ' (希腊小写字母 mu) (可能基于 `caseOrbit` 或 `FoldCategory` 中的信息)

**3. 命令行参数的具体处理:**

这个代码片段本身并没有直接处理命令行参数。它是 Go 标准库的一部分，提供数据支持。其他使用 `unicode` 包的 Go 程序可能会处理命令行参数，例如：

```go
package main

import (
	"flag"
	"fmt"
	"strings"
	"unicode"
)

func main() {
	caseFold := flag.Bool("casefold", false, "Perform case-insensitive comparison")
	flag.Parse()

	str1 := "Hello"
	str2 := "hello"

	if *caseFold {
		if strings.EqualFold(str1, str2) {
			fmt.Println("Strings are equal (case-insensitive)")
		} else {
			fmt.Println("Strings are not equal (case-insensitive)")
		}
	} else {
		if str1 == str2 {
			fmt.Println("Strings are equal (case-sensitive)")
		} else {
			fmt.Println("Strings are not equal (case-sensitive)")
		}
	}
}
```

在这个例子中，`flag.Bool` 定义了一个名为 `casefold` 的命令行参数。当用户在命令行中传递 `-casefold` 时，`strings.EqualFold` 函数会被调用，它内部会使用 `unicode` 包提供的功能进行大小写不敏感的比较。

**4. 使用者易犯错的点:**

* **混淆简单折叠和完全折叠:**  `asciiFold` 提供的是简单折叠，而 `caseOrbit` 和 `FoldCategory`/`FoldScript` 支持更复杂的折叠。用户可能错误地认为简单折叠适用于所有情况，导致一些不区分大小写的比较失败。例如，一些特殊的 Unicode 字符的大小写折叠可能涉及多个步骤。
* **忽略语言环境 (Locale):**  虽然这个文件定义了通用的 Unicode 大小写折叠规则，但在某些语言中可能有特殊的折叠规则。Go 的 `golang.org/x/text/unicode/norm` 包提供了更细粒度的控制，可以考虑语言环境的影响。

**5. 归纳其功能 (第七部分):**

作为 `go/src/unicode/tables.go` 的第七部分，该代码片段完成了定义用于 Unicode 大小写折叠的核心数据结构的工作。它提供了 ASCII 字符的大小写转换和简单折叠映射，以及更全面的基于 Unicode 类别和脚本的大小写折叠信息。这些数据被 `unicode` 包内部使用，以实现诸如 `strings.EqualFold` 这样的函数，从而支持 Go 语言进行不区分大小写的字符串操作。该部分是整个 Unicode 数据表定义的最后一部分，因此它总结并补充了前面部分定义的数据，为 Go 语言提供了完整的 Unicode 大小写处理能力。

### 提示词
```
这是路径为go/src/unicode/tables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
// '\u0083'
	0x84: pC,       // '\u0084'
	0x85: pC,       // '\u0085'
	0x86: pC,       // '\u0086'
	0x87: pC,       // '\u0087'
	0x88: pC,       // '\u0088'
	0x89: pC,       // '\u0089'
	0x8A: pC,       // '\u008a'
	0x8B: pC,       // '\u008b'
	0x8C: pC,       // '\u008c'
	0x8D: pC,       // '\u008d'
	0x8E: pC,       // '\u008e'
	0x8F: pC,       // '\u008f'
	0x90: pC,       // '\u0090'
	0x91: pC,       // '\u0091'
	0x92: pC,       // '\u0092'
	0x93: pC,       // '\u0093'
	0x94: pC,       // '\u0094'
	0x95: pC,       // '\u0095'
	0x96: pC,       // '\u0096'
	0x97: pC,       // '\u0097'
	0x98: pC,       // '\u0098'
	0x99: pC,       // '\u0099'
	0x9A: pC,       // '\u009a'
	0x9B: pC,       // '\u009b'
	0x9C: pC,       // '\u009c'
	0x9D: pC,       // '\u009d'
	0x9E: pC,       // '\u009e'
	0x9F: pC,       // '\u009f'
	0xA0: pZ,       // '\u00a0'
	0xA1: pP | pp,  // '¡'
	0xA2: pS | pp,  // '¢'
	0xA3: pS | pp,  // '£'
	0xA4: pS | pp,  // '¤'
	0xA5: pS | pp,  // '¥'
	0xA6: pS | pp,  // '¦'
	0xA7: pP | pp,  // '§'
	0xA8: pS | pp,  // '¨'
	0xA9: pS | pp,  // '©'
	0xAA: pLo | pp, // 'ª'
	0xAB: pP | pp,  // '«'
	0xAC: pS | pp,  // '¬'
	0xAD: 0,        // '\u00ad'
	0xAE: pS | pp,  // '®'
	0xAF: pS | pp,  // '¯'
	0xB0: pS | pp,  // '°'
	0xB1: pS | pp,  // '±'
	0xB2: pN | pp,  // '²'
	0xB3: pN | pp,  // '³'
	0xB4: pS | pp,  // '´'
	0xB5: pLl | pp, // 'µ'
	0xB6: pP | pp,  // '¶'
	0xB7: pP | pp,  // '·'
	0xB8: pS | pp,  // '¸'
	0xB9: pN | pp,  // '¹'
	0xBA: pLo | pp, // 'º'
	0xBB: pP | pp,  // '»'
	0xBC: pN | pp,  // '¼'
	0xBD: pN | pp,  // '½'
	0xBE: pN | pp,  // '¾'
	0xBF: pP | pp,  // '¿'
	0xC0: pLu | pp, // 'À'
	0xC1: pLu | pp, // 'Á'
	0xC2: pLu | pp, // 'Â'
	0xC3: pLu | pp, // 'Ã'
	0xC4: pLu | pp, // 'Ä'
	0xC5: pLu | pp, // 'Å'
	0xC6: pLu | pp, // 'Æ'
	0xC7: pLu | pp, // 'Ç'
	0xC8: pLu | pp, // 'È'
	0xC9: pLu | pp, // 'É'
	0xCA: pLu | pp, // 'Ê'
	0xCB: pLu | pp, // 'Ë'
	0xCC: pLu | pp, // 'Ì'
	0xCD: pLu | pp, // 'Í'
	0xCE: pLu | pp, // 'Î'
	0xCF: pLu | pp, // 'Ï'
	0xD0: pLu | pp, // 'Ð'
	0xD1: pLu | pp, // 'Ñ'
	0xD2: pLu | pp, // 'Ò'
	0xD3: pLu | pp, // 'Ó'
	0xD4: pLu | pp, // 'Ô'
	0xD5: pLu | pp, // 'Õ'
	0xD6: pLu | pp, // 'Ö'
	0xD7: pS | pp,  // '×'
	0xD8: pLu | pp, // 'Ø'
	0xD9: pLu | pp, // 'Ù'
	0xDA: pLu | pp, // 'Ú'
	0xDB: pLu | pp, // 'Û'
	0xDC: pLu | pp, // 'Ü'
	0xDD: pLu | pp, // 'Ý'
	0xDE: pLu | pp, // 'Þ'
	0xDF: pLl | pp, // 'ß'
	0xE0: pLl | pp, // 'à'
	0xE1: pLl | pp, // 'á'
	0xE2: pLl | pp, // 'â'
	0xE3: pLl | pp, // 'ã'
	0xE4: pLl | pp, // 'ä'
	0xE5: pLl | pp, // 'å'
	0xE6: pLl | pp, // 'æ'
	0xE7: pLl | pp, // 'ç'
	0xE8: pLl | pp, // 'è'
	0xE9: pLl | pp, // 'é'
	0xEA: pLl | pp, // 'ê'
	0xEB: pLl | pp, // 'ë'
	0xEC: pLl | pp, // 'ì'
	0xED: pLl | pp, // 'í'
	0xEE: pLl | pp, // 'î'
	0xEF: pLl | pp, // 'ï'
	0xF0: pLl | pp, // 'ð'
	0xF1: pLl | pp, // 'ñ'
	0xF2: pLl | pp, // 'ò'
	0xF3: pLl | pp, // 'ó'
	0xF4: pLl | pp, // 'ô'
	0xF5: pLl | pp, // 'õ'
	0xF6: pLl | pp, // 'ö'
	0xF7: pS | pp,  // '÷'
	0xF8: pLl | pp, // 'ø'
	0xF9: pLl | pp, // 'ù'
	0xFA: pLl | pp, // 'ú'
	0xFB: pLl | pp, // 'û'
	0xFC: pLl | pp, // 'ü'
	0xFD: pLl | pp, // 'ý'
	0xFE: pLl | pp, // 'þ'
	0xFF: pLl | pp, // 'ÿ'
}

var asciiFold = [MaxASCII + 1]uint16{
	0x0000,
	0x0001,
	0x0002,
	0x0003,
	0x0004,
	0x0005,
	0x0006,
	0x0007,
	0x0008,
	0x0009,
	0x000A,
	0x000B,
	0x000C,
	0x000D,
	0x000E,
	0x000F,
	0x0010,
	0x0011,
	0x0012,
	0x0013,
	0x0014,
	0x0015,
	0x0016,
	0x0017,
	0x0018,
	0x0019,
	0x001A,
	0x001B,
	0x001C,
	0x001D,
	0x001E,
	0x001F,
	0x0020,
	0x0021,
	0x0022,
	0x0023,
	0x0024,
	0x0025,
	0x0026,
	0x0027,
	0x0028,
	0x0029,
	0x002A,
	0x002B,
	0x002C,
	0x002D,
	0x002E,
	0x002F,
	0x0030,
	0x0031,
	0x0032,
	0x0033,
	0x0034,
	0x0035,
	0x0036,
	0x0037,
	0x0038,
	0x0039,
	0x003A,
	0x003B,
	0x003C,
	0x003D,
	0x003E,
	0x003F,
	0x0040,
	0x0061,
	0x0062,
	0x0063,
	0x0064,
	0x0065,
	0x0066,
	0x0067,
	0x0068,
	0x0069,
	0x006A,
	0x006B,
	0x006C,
	0x006D,
	0x006E,
	0x006F,
	0x0070,
	0x0071,
	0x0072,
	0x0073,
	0x0074,
	0x0075,
	0x0076,
	0x0077,
	0x0078,
	0x0079,
	0x007A,
	0x005B,
	0x005C,
	0x005D,
	0x005E,
	0x005F,
	0x0060,
	0x0041,
	0x0042,
	0x0043,
	0x0044,
	0x0045,
	0x0046,
	0x0047,
	0x0048,
	0x0049,
	0x004A,
	0x212A,
	0x004C,
	0x004D,
	0x004E,
	0x004F,
	0x0050,
	0x0051,
	0x0052,
	0x017F,
	0x0054,
	0x0055,
	0x0056,
	0x0057,
	0x0058,
	0x0059,
	0x005A,
	0x007B,
	0x007C,
	0x007D,
	0x007E,
	0x007F,
}

var caseOrbit = []foldPair{
	{0x004B, 0x006B},
	{0x0053, 0x0073},
	{0x006B, 0x212A},
	{0x0073, 0x017F},
	{0x00B5, 0x039C},
	{0x00C5, 0x00E5},
	{0x00DF, 0x1E9E},
	{0x00E5, 0x212B},
	{0x0130, 0x0130},
	{0x0131, 0x0131},
	{0x017F, 0x0053},
	{0x01C4, 0x01C5},
	{0x01C5, 0x01C6},
	{0x01C6, 0x01C4},
	{0x01C7, 0x01C8},
	{0x01C8, 0x01C9},
	{0x01C9, 0x01C7},
	{0x01CA, 0x01CB},
	{0x01CB, 0x01CC},
	{0x01CC, 0x01CA},
	{0x01F1, 0x01F2},
	{0x01F2, 0x01F3},
	{0x01F3, 0x01F1},
	{0x0345, 0x0399},
	{0x0392, 0x03B2},
	{0x0395, 0x03B5},
	{0x0398, 0x03B8},
	{0x0399, 0x03B9},
	{0x039A, 0x03BA},
	{0x039C, 0x03BC},
	{0x03A0, 0x03C0},
	{0x03A1, 0x03C1},
	{0x03A3, 0x03C2},
	{0x03A6, 0x03C6},
	{0x03A9, 0x03C9},
	{0x03B2, 0x03D0},
	{0x03B5, 0x03F5},
	{0x03B8, 0x03D1},
	{0x03B9, 0x1FBE},
	{0x03BA, 0x03F0},
	{0x03BC, 0x00B5},
	{0x03C0, 0x03D6},
	{0x03C1, 0x03F1},
	{0x03C2, 0x03C3},
	{0x03C3, 0x03A3},
	{0x03C6, 0x03D5},
	{0x03C9, 0x2126},
	{0x03D0, 0x0392},
	{0x03D1, 0x03F4},
	{0x03D5, 0x03A6},
	{0x03D6, 0x03A0},
	{0x03F0, 0x039A},
	{0x03F1, 0x03A1},
	{0x03F4, 0x0398},
	{0x03F5, 0x0395},
	{0x0412, 0x0432},
	{0x0414, 0x0434},
	{0x041E, 0x043E},
	{0x0421, 0x0441},
	{0x0422, 0x0442},
	{0x042A, 0x044A},
	{0x0432, 0x1C80},
	{0x0434, 0x1C81},
	{0x043E, 0x1C82},
	{0x0441, 0x1C83},
	{0x0442, 0x1C84},
	{0x044A, 0x1C86},
	{0x0462, 0x0463},
	{0x0463, 0x1C87},
	{0x1C80, 0x0412},
	{0x1C81, 0x0414},
	{0x1C82, 0x041E},
	{0x1C83, 0x0421},
	{0x1C84, 0x1C85},
	{0x1C85, 0x0422},
	{0x1C86, 0x042A},
	{0x1C87, 0x0462},
	{0x1C88, 0xA64A},
	{0x1E60, 0x1E61},
	{0x1E61, 0x1E9B},
	{0x1E9B, 0x1E60},
	{0x1E9E, 0x00DF},
	{0x1FBE, 0x0345},
	{0x2126, 0x03A9},
	{0x212A, 0x004B},
	{0x212B, 0x00C5},
	{0xA64A, 0xA64B},
	{0xA64B, 0x1C88},
}

// FoldCategory maps a category name to a table of
// code points outside the category that are equivalent under
// simple case folding to code points inside the category.
// If there is no entry for a category name, there are no such points.
var FoldCategory = map[string]*RangeTable{
	"L":  foldL,
	"Ll": foldLl,
	"Lt": foldLt,
	"Lu": foldLu,
	"M":  foldM,
	"Mn": foldMn,
}

var foldL = &RangeTable{
	R16: []Range16{
		{0x0345, 0x0345, 1},
	},
}

var foldLl = &RangeTable{
	R16: []Range16{
		{0x0041, 0x005a, 1},
		{0x00c0, 0x00d6, 1},
		{0x00d8, 0x00de, 1},
		{0x0100, 0x012e, 2},
		{0x0132, 0x0136, 2},
		{0x0139, 0x0147, 2},
		{0x014a, 0x0178, 2},
		{0x0179, 0x017d, 2},
		{0x0181, 0x0182, 1},
		{0x0184, 0x0186, 2},
		{0x0187, 0x0189, 2},
		{0x018a, 0x018b, 1},
		{0x018e, 0x0191, 1},
		{0x0193, 0x0194, 1},
		{0x0196, 0x0198, 1},
		{0x019c, 0x019d, 1},
		{0x019f, 0x01a0, 1},
		{0x01a2, 0x01a6, 2},
		{0x01a7, 0x01a9, 2},
		{0x01ac, 0x01ae, 2},
		{0x01af, 0x01b1, 2},
		{0x01b2, 0x01b3, 1},
		{0x01b5, 0x01b7, 2},
		{0x01b8, 0x01bc, 4},
		{0x01c4, 0x01c5, 1},
		{0x01c7, 0x01c8, 1},
		{0x01ca, 0x01cb, 1},
		{0x01cd, 0x01db, 2},
		{0x01de, 0x01ee, 2},
		{0x01f1, 0x01f2, 1},
		{0x01f4, 0x01f6, 2},
		{0x01f7, 0x01f8, 1},
		{0x01fa, 0x0232, 2},
		{0x023a, 0x023b, 1},
		{0x023d, 0x023e, 1},
		{0x0241, 0x0243, 2},
		{0x0244, 0x0246, 1},
		{0x0248, 0x024e, 2},
		{0x0345, 0x0370, 43},
		{0x0372, 0x0376, 4},
		{0x037f, 0x0386, 7},
		{0x0388, 0x038a, 1},
		{0x038c, 0x038e, 2},
		{0x038f, 0x0391, 2},
		{0x0392, 0x03a1, 1},
		{0x03a3, 0x03ab, 1},
		{0x03cf, 0x03d8, 9},
		{0x03da, 0x03ee, 2},
		{0x03f4, 0x03f7, 3},
		{0x03f9, 0x03fa, 1},
		{0x03fd, 0x042f, 1},
		{0x0460, 0x0480, 2},
		{0x048a, 0x04c0, 2},
		{0x04c1, 0x04cd, 2},
		{0x04d0, 0x052e, 2},
		{0x0531, 0x0556, 1},
		{0x10a0, 0x10c5, 1},
		{0x10c7, 0x10cd, 6},
		{0x13a0, 0x13f5, 1},
		{0x1c90, 0x1cba, 1},
		{0x1cbd, 0x1cbf, 1},
		{0x1e00, 0x1e94, 2},
		{0x1e9e, 0x1efe, 2},
		{0x1f08, 0x1f0f, 1},
		{0x1f18, 0x1f1d, 1},
		{0x1f28, 0x1f2f, 1},
		{0x1f38, 0x1f3f, 1},
		{0x1f48, 0x1f4d, 1},
		{0x1f59, 0x1f5f, 2},
		{0x1f68, 0x1f6f, 1},
		{0x1f88, 0x1f8f, 1},
		{0x1f98, 0x1f9f, 1},
		{0x1fa8, 0x1faf, 1},
		{0x1fb8, 0x1fbc, 1},
		{0x1fc8, 0x1fcc, 1},
		{0x1fd8, 0x1fdb, 1},
		{0x1fe8, 0x1fec, 1},
		{0x1ff8, 0x1ffc, 1},
		{0x2126, 0x212a, 4},
		{0x212b, 0x2132, 7},
		{0x2183, 0x2c00, 2685},
		{0x2c01, 0x2c2f, 1},
		{0x2c60, 0x2c62, 2},
		{0x2c63, 0x2c64, 1},
		{0x2c67, 0x2c6d, 2},
		{0x2c6e, 0x2c70, 1},
		{0x2c72, 0x2c75, 3},
		{0x2c7e, 0x2c80, 1},
		{0x2c82, 0x2ce2, 2},
		{0x2ceb, 0x2ced, 2},
		{0x2cf2, 0xa640, 31054},
		{0xa642, 0xa66c, 2},
		{0xa680, 0xa69a, 2},
		{0xa722, 0xa72e, 2},
		{0xa732, 0xa76e, 2},
		{0xa779, 0xa77d, 2},
		{0xa77e, 0xa786, 2},
		{0xa78b, 0xa78d, 2},
		{0xa790, 0xa792, 2},
		{0xa796, 0xa7aa, 2},
		{0xa7ab, 0xa7ae, 1},
		{0xa7b0, 0xa7b4, 1},
		{0xa7b6, 0xa7c4, 2},
		{0xa7c5, 0xa7c7, 1},
		{0xa7c9, 0xa7d0, 7},
		{0xa7d6, 0xa7d8, 2},
		{0xa7f5, 0xff21, 22316},
		{0xff22, 0xff3a, 1},
	},
	R32: []Range32{
		{0x10400, 0x10427, 1},
		{0x104b0, 0x104d3, 1},
		{0x10570, 0x1057a, 1},
		{0x1057c, 0x1058a, 1},
		{0x1058c, 0x10592, 1},
		{0x10594, 0x10595, 1},
		{0x10c80, 0x10cb2, 1},
		{0x118a0, 0x118bf, 1},
		{0x16e40, 0x16e5f, 1},
		{0x1e900, 0x1e921, 1},
	},
	LatinOffset: 3,
}

var foldLt = &RangeTable{
	R16: []Range16{
		{0x01c4, 0x01c6, 2},
		{0x01c7, 0x01c9, 2},
		{0x01ca, 0x01cc, 2},
		{0x01f1, 0x01f3, 2},
		{0x1f80, 0x1f87, 1},
		{0x1f90, 0x1f97, 1},
		{0x1fa0, 0x1fa7, 1},
		{0x1fb3, 0x1fc3, 16},
		{0x1ff3, 0x1ff3, 1},
	},
}

var foldLu = &RangeTable{
	R16: []Range16{
		{0x0061, 0x007a, 1},
		{0x00b5, 0x00df, 42},
		{0x00e0, 0x00f6, 1},
		{0x00f8, 0x00ff, 1},
		{0x0101, 0x012f, 2},
		{0x0133, 0x0137, 2},
		{0x013a, 0x0148, 2},
		{0x014b, 0x0177, 2},
		{0x017a, 0x017e, 2},
		{0x017f, 0x0180, 1},
		{0x0183, 0x0185, 2},
		{0x0188, 0x018c, 4},
		{0x0192, 0x0195, 3},
		{0x0199, 0x019a, 1},
		{0x019e, 0x01a1, 3},
		{0x01a3, 0x01a5, 2},
		{0x01a8, 0x01ad, 5},
		{0x01b0, 0x01b4, 4},
		{0x01b6, 0x01b9, 3},
		{0x01bd, 0x01bf, 2},
		{0x01c5, 0x01c6, 1},
		{0x01c8, 0x01c9, 1},
		{0x01cb, 0x01cc, 1},
		{0x01ce, 0x01dc, 2},
		{0x01dd, 0x01ef, 2},
		{0x01f2, 0x01f3, 1},
		{0x01f5, 0x01f9, 4},
		{0x01fb, 0x021f, 2},
		{0x0223, 0x0233, 2},
		{0x023c, 0x023f, 3},
		{0x0240, 0x0242, 2},
		{0x0247, 0x024f, 2},
		{0x0250, 0x0254, 1},
		{0x0256, 0x0257, 1},
		{0x0259, 0x025b, 2},
		{0x025c, 0x0260, 4},
		{0x0261, 0x0265, 2},
		{0x0266, 0x0268, 2},
		{0x0269, 0x026c, 1},
		{0x026f, 0x0271, 2},
		{0x0272, 0x0275, 3},
		{0x027d, 0x0280, 3},
		{0x0282, 0x0283, 1},
		{0x0287, 0x028c, 1},
		{0x0292, 0x029d, 11},
		{0x029e, 0x0345, 167},
		{0x0371, 0x0373, 2},
		{0x0377, 0x037b, 4},
		{0x037c, 0x037d, 1},
		{0x03ac, 0x03af, 1},
		{0x03b1, 0x03ce, 1},
		{0x03d0, 0x03d1, 1},
		{0x03d5, 0x03d7, 1},
		{0x03d9, 0x03ef, 2},
		{0x03f0, 0x03f3, 1},
		{0x03f5, 0x03fb, 3},
		{0x0430, 0x045f, 1},
		{0x0461, 0x0481, 2},
		{0x048b, 0x04bf, 2},
		{0x04c2, 0x04ce, 2},
		{0x04cf, 0x052f, 2},
		{0x0561, 0x0586, 1},
		{0x10d0, 0x10fa, 1},
		{0x10fd, 0x10ff, 1},
		{0x13f8, 0x13fd, 1},
		{0x1c80, 0x1c88, 1},
		{0x1d79, 0x1d7d, 4},
		{0x1d8e, 0x1e01, 115},
		{0x1e03, 0x1e95, 2},
		{0x1e9b, 0x1ea1, 6},
		{0x1ea3, 0x1eff, 2},
		{0x1f00, 0x1f07, 1},
		{0x1f10, 0x1f15, 1},
		{0x1f20, 0x1f27, 1},
		{0x1f30, 0x1f37, 1},
		{0x1f40, 0x1f45, 1},
		{0x1f51, 0x1f57, 2},
		{0x1f60, 0x1f67, 1},
		{0x1f70, 0x1f7d, 1},
		{0x1fb0, 0x1fb1, 1},
		{0x1fbe, 0x1fd0, 18},
		{0x1fd1, 0x1fe0, 15},
		{0x1fe1, 0x1fe5, 4},
		{0x214e, 0x2184, 54},
		{0x2c30, 0x2c5f, 1},
		{0x2c61, 0x2c65, 4},
		{0x2c66, 0x2c6c, 2},
		{0x2c73, 0x2c76, 3},
		{0x2c81, 0x2ce3, 2},
		{0x2cec, 0x2cee, 2},
		{0x2cf3, 0x2d00, 13},
		{0x2d01, 0x2d25, 1},
		{0x2d27, 0x2d2d, 6},
		{0xa641, 0xa66d, 2},
		{0xa681, 0xa69b, 2},
		{0xa723, 0xa72f, 2},
		{0xa733, 0xa76f, 2},
		{0xa77a, 0xa77c, 2},
		{0xa77f, 0xa787, 2},
		{0xa78c, 0xa791, 5},
		{0xa793, 0xa794, 1},
		{0xa797, 0xa7a9, 2},
		{0xa7b5, 0xa7c3, 2},
		{0xa7c8, 0xa7ca, 2},
		{0xa7d1, 0xa7d7, 6},
		{0xa7d9, 0xa7f6, 29},
		{0xab53, 0xab70, 29},
		{0xab71, 0xabbf, 1},
		{0xff41, 0xff5a, 1},
	},
	R32: []Range32{
		{0x10428, 0x1044f, 1},
		{0x104d8, 0x104fb, 1},
		{0x10597, 0x105a1, 1},
		{0x105a3, 0x105b1, 1},
		{0x105b3, 0x105b9, 1},
		{0x105bb, 0x105bc, 1},
		{0x10cc0, 0x10cf2, 1},
		{0x118c0, 0x118df, 1},
		{0x16e60, 0x16e7f, 1},
		{0x1e922, 0x1e943, 1},
	},
	LatinOffset: 4,
}

var foldM = &RangeTable{
	R16: []Range16{
		{0x0399, 0x03b9, 32},
		{0x1fbe, 0x1fbe, 1},
	},
}

var foldMn = &RangeTable{
	R16: []Range16{
		{0x0399, 0x03b9, 32},
		{0x1fbe, 0x1fbe, 1},
	},
}

// FoldScript maps a script name to a table of
// code points outside the script that are equivalent under
// simple case folding to code points inside the script.
// If there is no entry for a script name, there are no such points.
var FoldScript = map[string]*RangeTable{
	"Common":    foldCommon,
	"Greek":     foldGreek,
	"Inherited": foldInherited,
}

var foldCommon = &RangeTable{
	R16: []Range16{
		{0x039c, 0x03bc, 32},
	},
}

var foldGreek = &RangeTable{
	R16: []Range16{
		{0x00b5, 0x0345, 656},
	},
}

var foldInherited = &RangeTable{
	R16: []Range16{
		{0x0399, 0x03b9, 32},
		{0x1fbe, 0x1fbe, 1},
	},
}

// Range entries: 3535 16-bit, 2031 32-bit, 5566 total.
// Range bytes: 21210 16-bit, 24372 32-bit, 45582 total.

// Fold orbit bytes: 88 pairs, 352 bytes
```