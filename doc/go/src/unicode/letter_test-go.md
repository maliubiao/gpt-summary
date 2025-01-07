Response:
Let's break down the thought process to analyze the provided Go code snippet.

**1. Initial Understanding - What is this file about?**

The file path `go/src/unicode/letter_test.go` immediately tells us this is a test file related to the `unicode` package, specifically focusing on "letter" related functionalities. The `_test.go` suffix confirms it's a testing file.

**2. Examining the Imports:**

The `import` statements reveal the dependencies:

* `"flag"`:  Indicates the possibility of command-line flags for controlling test behavior.
* `"fmt"`:  Used for formatted output, likely for debugging or calibration messages.
* `"runtime"`: Suggests interaction with the Go runtime environment, probably for architecture-specific checks (like the `amd64` warning).
* `"sort"`:  Implies sorting operations are performed, possibly for optimizing search algorithms.
* `"strings"`:  Used for string manipulation, specifically `strings.ToLowerSpecial` in one of the tests.
* `"testing"`: The core testing package in Go.
* `.` `"unicode"`: This is a dot import, meaning the exported identifiers from the `unicode` package are directly accessible in this test file without needing the `unicode.` prefix. This is a common practice in Go test files for brevity.

**3. Analyzing the Global Variables:**

The global variables provide crucial information about the functionalities being tested:

* `upperTest`, `notupperTest`: These `[]rune` slices clearly test the `IsUpper` function by providing examples of uppercase and non-uppercase runes.
* `letterTest`, `notletterTest`: Similar to the above, these test the `IsLetter` function.
* `spaceTest`: Tests the `IsSpace` function.
* `caseTest`: This `[]caseT` slice is the most complex. The `caseT` struct has fields `cas` (representing the case type like `UpperCase`, `LowerCase`, `TitleCase`), `in` (the input rune), and `out` (the expected output rune after applying the case conversion). This strongly suggests the code tests the `To`, `ToUpper`, `ToLower`, and `ToTitle` functions.

**4. Examining the Test Functions:**

The function names clearly map to the functions being tested in the `unicode` package:

* `TestIsLetter`, `TestIsUpper`, `TestIsSpace`: Directly test the corresponding `Is...` functions.
* `TestTo`, `TestToUpperCase`, `TestToLowerCase`, `TestToTitleCase`: Test the case conversion functions.
* `TestTurkishCase`:  Suggests testing case conversions with a specific locale (Turkish), implying the existence of locale-specific case conversion logic.
* `TestSimpleFold`:  Indicates testing the `SimpleFold` function, which performs simple case folding.
* `TestCalibrate`: This is interesting. The comment and the use of `flag.Bool` and benchmark functions suggest this test is for performance analysis, specifically comparing linear and binary search for some internal data structure.
* `TestLetterOptimizations`: This test compares the results of the high-level `IsLetter` functions with the more general `Is` function using predefined categories. This is likely to ensure that optimizations for common cases (like Latin-1) are consistent with the broader Unicode categorization.
* `TestLatinOffset`: This test seems to verify the `LatinOffset` field in `RangeTable`, which is probably an optimization related to handling Latin-1 characters efficiently.
* `TestSpecialCaseNoMapping`: Addresses a specific issue (25636) related to special case handling.
* `TestNegativeRune`: Addresses another issue (43254) focusing on how the `unicode` package handles negative rune values (which are invalid).

**5. Code Snippets and Reasoning:**

Based on the analysis of the test functions and global variables, we can deduce the functionalities and provide examples. For instance, the `caseTest` variable directly shows how case conversion functions are expected to behave.

**6. Command Line Arguments:**

The presence of `flag.Bool("calibrate", false, ...)` makes it clear that there's a command-line flag named `-calibrate`. The description explains its purpose: to compute the crossover point for linear vs. binary search. This requires explaining how to use it (`go test -calibrate`).

**7. Common Mistakes:**

Thinking about potential mistakes involves considering how developers might use the `unicode` package functions. A common mistake with case conversion is forgetting that it's locale-sensitive in some cases. The `TestTurkishCase` provides a perfect example of this, as the Turkish locale has different casing rules for 'i'.

**8. Structuring the Answer:**

Finally, organizing the information into logical sections (functionality, Go feature implementation, code examples, command-line arguments, common mistakes) makes the answer clear and easy to understand. Using code formatting and explicitly mentioning assumptions (where relevant) enhances clarity.
这个 `go/src/unicode/letter_test.go` 文件是 Go 语言 `unicode` 标准库的一部分，专门用于测试与 Unicode 字符的字母属性相关的函数。

**它的主要功能包括：**

1. **测试字符是否为大写字母 (IsUpper):**  通过 `upperTest` 和 `notupperTest` 两个 `rune` 切片，测试 `unicode.IsUpper()` 函数对于各种 Unicode 字符的判断是否正确。`upperTest` 包含被认为是 uppercase 的字符，而 `notupperTest` 包含不被认为是 uppercase 的字符。

2. **测试字符是否为字母 (IsLetter):** 通过 `letterTest` 和 `notletterTest` 两个 `rune` 切片，测试 `unicode.IsLetter()` 函数对于各种 Unicode 字符的判断是否正确。`letterTest` 包含被认为是字母的字符，而 `notletterTest` 包含不被认为是字母的字符。

3. **测试字符的大小写转换 (To, ToUpper, ToLower, ToTitle):** 通过 `caseTest` 结构体切片，详细测试了 `unicode.To()`, `unicode.ToUpper()`, `unicode.ToLower()`, 和 `unicode.ToTitle()` 函数。 `caseTest` 中的每个元素都指定了一个大小写转换类型 (`UpperCase`, `LowerCase`, `TitleCase`)，一个输入 `rune` 和期望的输出 `rune`。

4. **测试字符是否为空格 (IsSpace):** 通过 `spaceTest` 切片，测试 `unicode.IsSpace()` 函数对于各种 Unicode 空白字符的判断是否正确。

5. **测试优化后的函数与通用函数的兼容性:** `TestLetterOptimizations` 函数检查了针对 Latin-1 字符的优化版本（例如 `IsLetter` 的实现可能对 Latin-1 字符有特殊处理）是否与通用的 `unicode.Is()` 和 `unicode.To()` 函数的结果一致。

6. **测试特定语言的大小写转换 (TurkishCase):** `TestTurkishCase` 函数测试了 `unicode.TurkishCase` 变量提供的土耳其语特定的大小写转换规则。这是因为某些语言（如土耳其语）的字母大小写转换规则与通用规则有所不同。

7. **测试简单 Case Folding (SimpleFold):** `TestSimpleFold` 函数测试了 `unicode.SimpleFold()` 函数，该函数用于查找与给定字符在简单 case folding 下等效的下一个字符。这对于不区分大小写的比较很有用。

8. **性能校准 (TestCalibrate):** 这个测试用例通过命令行参数 `-calibrate` 触发，用于校准线性搜索和二分搜索在查找 Unicode 属性时的性能交叉点。这有助于优化 `unicode` 包的内部实现。

9. **测试 LatinOffset 的正确性:** `TestLatinOffset` 检查了 `unicode` 包中 `RangeTable` 的 `LatinOffset` 字段是否正确设置。 `LatinOffset` 用于优化对 Latin-1 字符的查找。

10. **测试特殊情况下的 CaseRange (TestSpecialCaseNoMapping):**  这个测试用例处理了 `CaseRange` 中没有映射的情况，确保 `strings.ToLowerSpecial` 等函数在处理这些特殊情况时不会出错。

11. **测试负 Rune 值的处理 (TestNegativeRune):** 这个测试用例确保 `unicode` 包的函数能够正确处理负的 `rune` 值（在 Go 中 `rune` 是 `int32` 的别名），即使这些值在转换为 `uint8` 或 `uint16` 时看起来像合法的 Unicode 字符。这主要是为了防止潜在的越界访问或错误的逻辑判断。

**它是什么 go 语言功能的实现：**

这个测试文件主要测试了 `unicode` 标准库中提供的用于处理 Unicode 字符属性的功能。这些功能允许开发者查询字符是否为字母、数字、空格等，以及进行大小写转换。`unicode` 包是 Go 语言处理文本的基础，确保了 Go 程序能够正确处理各种语言和符号。

**Go 代码举例说明：**

```go
package main

import (
	"fmt"
	"unicode"
)

func main() {
	r := 'A'
	fmt.Printf("IsLetter('%c'): %t\n", r, unicode.IsLetter(r)) // 输出: IsLetter('A'): true
	fmt.Printf("IsUpper('%c'): %t\n", r, unicode.IsUpper(r))   // 输出: IsUpper('A'): true
	fmt.Printf("ToLower('%c'): %c\n", r, unicode.ToLower(r))   // 输出: ToLower('A'): a

	r2 := 'a'
	fmt.Printf("IsLetter('%c'): %t\n", r2, unicode.IsLetter(r2)) // 输出: IsLetter('a'): true
	fmt.Printf("IsLower('%c'): %t\n", r2, unicode.IsLower(r2))   // 输出: IsLower('a'): true
	fmt.Printf("ToUpper('%c'): %c\n", r2, unicode.ToUpper(r2))   // 输出: ToUpper('a'): A

	r3 := ' '
	fmt.Printf("IsSpace('%c'): %t\n", r3, unicode.IsSpace(r3))   // 输出: IsSpace(' '): true
}
```

**假设的输入与输出 (针对大小写转换测试):**

假设 `caseTest` 中有以下一个元素：

```go
{UpperCase, 'a', 'A'},
```

那么 `TestTo` 函数会执行如下逻辑：

```go
r := unicode.To(unicode.UpperCase, 'a')
// 期望 r 的值为 'A'
```

**命令行参数的具体处理：**

该测试文件使用 `flag` 包定义了一个名为 `calibrate` 的布尔类型命令行参数。

```go
var calibrate = flag.Bool("calibrate", false, "compute crossover for linear vs. binary search")
```

* **`flag.Bool("calibrate", false, "compute crossover for linear vs. binary search")`**: 这行代码定义了一个名为 `calibrate` 的命令行标志。
    * `"calibrate"`:  是命令行参数的名称，可以在运行 `go test` 命令时使用 `-calibrate` 来设置。
    * `false`: 是该参数的默认值。如果运行 `go test` 时没有提供 `-calibrate`，则 `*calibrate` 的值为 `false`。
    * `"compute crossover for linear vs. binary search"`: 是该参数的描述，会在 `go test -help` 中显示。

在 `TestCalibrate` 函数中，会检查 `*calibrate` 的值：

```go
func TestCalibrate(t *testing.T) {
	if !*calibrate {
		return
	}
	// ... 进行性能校准的逻辑 ...
}
```

只有当在运行 `go test` 命令时显式地添加了 `-calibrate` 参数（例如：`go test -calibrate ./unicode`），`TestCalibrate` 函数中的性能校准逻辑才会被执行。否则，该测试函数会直接返回，跳过校准过程。

**使用者易犯错的点：**

1. **忽略特定语言的大小写规则:**  直接使用 `unicode.ToUpper` 或 `unicode.ToLower` 可能对于某些语言（如土耳其语）得到错误的结果。应该考虑使用 `unicode.SpecialCase` 或 `unicode.TurkishCase` 等特定于语言的规则。

   **错误示例:**

   ```go
   import (
       "fmt"
       "unicode"
   )

   func main() {
       lowerI := 'ı' // 土耳其语小写无点 i
       upperI := unicode.ToUpper(lowerI)
       fmt.Printf("ToUpper('%c') = '%c'\n", lowerI, upperI) // 错误地输出: ToUpper('ı') = 'I'，应该为 'İ'
   }
   ```

   **正确示例:**

   ```go
   import (
       "fmt"
       "unicode"
   )

   func main() {
       lowerI := 'ı' // 土耳其语小写无点 i
       upperI := unicode.TurkishCase.ToUpper(lowerI)
       fmt.Printf("TurkishCase.ToUpper('%c') = '%c'\n", lowerI, upperI) // 正确输出: TurkishCase.ToUpper('ı') = 'İ'
   }
   ```

2. **混淆 Case Folding 和大小写转换:**  Case folding (如 `unicode.SimpleFold`) 用于不区分大小写的比较，它不一定产生标准的 UpperCase 或 LowerCase 形式。直接用 Case Folding 的结果进行显示可能会不符合预期。

   ```go
   import (
       "fmt"
       "unicode"
   )

   func main() {
       kelvinSign := 'K'
       folded := unicode.SimpleFold(kelvinSign)
       fmt.Printf("SimpleFold('%c') = '%c'\n", kelvinSign, folded) // 输出: SimpleFold('K') = 'k'，这适用于比较，但不适合作为标准小写形式显示
   }
   ```

总而言之，`go/src/unicode/letter_test.go` 是对 Go 语言 `unicode` 包中关于字符字母属性和大小写转换功能进行全面测试的重要组成部分，确保了这些核心功能的正确性和性能。

Prompt: 
```
这是路径为go/src/unicode/letter_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unicode_test

import (
	"flag"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"
	. "unicode"
)

var upperTest = []rune{
	0x41,
	0xc0,
	0xd8,
	0x100,
	0x139,
	0x14a,
	0x178,
	0x181,
	0x376,
	0x3cf,
	0x13bd,
	0x1f2a,
	0x2102,
	0x2c00,
	0x2c10,
	0x2c20,
	0xa650,
	0xa722,
	0xff3a,
	0x10400,
	0x1d400,
	0x1d7ca,
}

var notupperTest = []rune{
	0x40,
	0x5b,
	0x61,
	0x185,
	0x1b0,
	0x377,
	0x387,
	0x2150,
	0xab7d,
	0xffff,
	0x10000,
}

var letterTest = []rune{
	0x41,
	0x61,
	0xaa,
	0xba,
	0xc8,
	0xdb,
	0xf9,
	0x2ec,
	0x535,
	0x620,
	0x6e6,
	0x93d,
	0xa15,
	0xb99,
	0xdc0,
	0xedd,
	0x1000,
	0x1200,
	0x1312,
	0x1401,
	0x2c00,
	0xa800,
	0xf900,
	0xfa30,
	0xffda,
	0xffdc,
	0x10000,
	0x10300,
	0x10400,
	0x20000,
	0x2f800,
	0x2fa1d,
}

var notletterTest = []rune{
	0x20,
	0x35,
	0x375,
	0x619,
	0x700,
	0x1885,
	0xfffe,
	0x1ffff,
	0x10ffff,
}

// Contains all the special cased Latin-1 chars.
var spaceTest = []rune{
	0x09,
	0x0a,
	0x0b,
	0x0c,
	0x0d,
	0x20,
	0x85,
	0xA0,
	0x2000,
	0x3000,
}

type caseT struct {
	cas     int
	in, out rune
}

var caseTest = []caseT{
	// errors
	{-1, '\n', 0xFFFD},
	{UpperCase, -1, -1},
	{UpperCase, 1 << 30, 1 << 30},

	// ASCII (special-cased so test carefully)
	{UpperCase, '\n', '\n'},
	{UpperCase, 'a', 'A'},
	{UpperCase, 'A', 'A'},
	{UpperCase, '7', '7'},
	{LowerCase, '\n', '\n'},
	{LowerCase, 'a', 'a'},
	{LowerCase, 'A', 'a'},
	{LowerCase, '7', '7'},
	{TitleCase, '\n', '\n'},
	{TitleCase, 'a', 'A'},
	{TitleCase, 'A', 'A'},
	{TitleCase, '7', '7'},

	// Latin-1: easy to read the tests!
	{UpperCase, 0x80, 0x80},
	{UpperCase, 'Å', 'Å'},
	{UpperCase, 'å', 'Å'},
	{LowerCase, 0x80, 0x80},
	{LowerCase, 'Å', 'å'},
	{LowerCase, 'å', 'å'},
	{TitleCase, 0x80, 0x80},
	{TitleCase, 'Å', 'Å'},
	{TitleCase, 'å', 'Å'},

	// 0131;LATIN SMALL LETTER DOTLESS I;Ll;0;L;;;;;N;;;0049;;0049
	{UpperCase, 0x0131, 'I'},
	{LowerCase, 0x0131, 0x0131},
	{TitleCase, 0x0131, 'I'},

	// 0133;LATIN SMALL LIGATURE IJ;Ll;0;L;<compat> 0069 006A;;;;N;LATIN SMALL LETTER I J;;0132;;0132
	{UpperCase, 0x0133, 0x0132},
	{LowerCase, 0x0133, 0x0133},
	{TitleCase, 0x0133, 0x0132},

	// 212A;KELVIN SIGN;Lu;0;L;004B;;;;N;DEGREES KELVIN;;;006B;
	{UpperCase, 0x212A, 0x212A},
	{LowerCase, 0x212A, 'k'},
	{TitleCase, 0x212A, 0x212A},

	// From an UpperLower sequence
	// A640;CYRILLIC CAPITAL LETTER ZEMLYA;Lu;0;L;;;;;N;;;;A641;
	{UpperCase, 0xA640, 0xA640},
	{LowerCase, 0xA640, 0xA641},
	{TitleCase, 0xA640, 0xA640},
	// A641;CYRILLIC SMALL LETTER ZEMLYA;Ll;0;L;;;;;N;;;A640;;A640
	{UpperCase, 0xA641, 0xA640},
	{LowerCase, 0xA641, 0xA641},
	{TitleCase, 0xA641, 0xA640},
	// A64E;CYRILLIC CAPITAL LETTER NEUTRAL YER;Lu;0;L;;;;;N;;;;A64F;
	{UpperCase, 0xA64E, 0xA64E},
	{LowerCase, 0xA64E, 0xA64F},
	{TitleCase, 0xA64E, 0xA64E},
	// A65F;CYRILLIC SMALL LETTER YN;Ll;0;L;;;;;N;;;A65E;;A65E
	{UpperCase, 0xA65F, 0xA65E},
	{LowerCase, 0xA65F, 0xA65F},
	{TitleCase, 0xA65F, 0xA65E},

	// From another UpperLower sequence
	// 0139;LATIN CAPITAL LETTER L WITH ACUTE;Lu;0;L;004C 0301;;;;N;LATIN CAPITAL LETTER L ACUTE;;;013A;
	{UpperCase, 0x0139, 0x0139},
	{LowerCase, 0x0139, 0x013A},
	{TitleCase, 0x0139, 0x0139},
	// 013F;LATIN CAPITAL LETTER L WITH MIDDLE DOT;Lu;0;L;<compat> 004C 00B7;;;;N;;;;0140;
	{UpperCase, 0x013f, 0x013f},
	{LowerCase, 0x013f, 0x0140},
	{TitleCase, 0x013f, 0x013f},
	// 0148;LATIN SMALL LETTER N WITH CARON;Ll;0;L;006E 030C;;;;N;LATIN SMALL LETTER N HACEK;;0147;;0147
	{UpperCase, 0x0148, 0x0147},
	{LowerCase, 0x0148, 0x0148},
	{TitleCase, 0x0148, 0x0147},

	// Lowercase lower than uppercase.
	// AB78;CHEROKEE SMALL LETTER GE;Ll;0;L;;;;;N;;;13A8;;13A8
	{UpperCase, 0xab78, 0x13a8},
	{LowerCase, 0xab78, 0xab78},
	{TitleCase, 0xab78, 0x13a8},
	{UpperCase, 0x13a8, 0x13a8},
	{LowerCase, 0x13a8, 0xab78},
	{TitleCase, 0x13a8, 0x13a8},

	// Last block in the 5.1.0 table
	// 10400;DESERET CAPITAL LETTER LONG I;Lu;0;L;;;;;N;;;;10428;
	{UpperCase, 0x10400, 0x10400},
	{LowerCase, 0x10400, 0x10428},
	{TitleCase, 0x10400, 0x10400},
	// 10427;DESERET CAPITAL LETTER EW;Lu;0;L;;;;;N;;;;1044F;
	{UpperCase, 0x10427, 0x10427},
	{LowerCase, 0x10427, 0x1044F},
	{TitleCase, 0x10427, 0x10427},
	// 10428;DESERET SMALL LETTER LONG I;Ll;0;L;;;;;N;;;10400;;10400
	{UpperCase, 0x10428, 0x10400},
	{LowerCase, 0x10428, 0x10428},
	{TitleCase, 0x10428, 0x10400},
	// 1044F;DESERET SMALL LETTER EW;Ll;0;L;;;;;N;;;10427;;10427
	{UpperCase, 0x1044F, 0x10427},
	{LowerCase, 0x1044F, 0x1044F},
	{TitleCase, 0x1044F, 0x10427},

	// First one not in the 5.1.0 table
	// 10450;SHAVIAN LETTER PEEP;Lo;0;L;;;;;N;;;;;
	{UpperCase, 0x10450, 0x10450},
	{LowerCase, 0x10450, 0x10450},
	{TitleCase, 0x10450, 0x10450},

	// Non-letters with case.
	{LowerCase, 0x2161, 0x2171},
	{UpperCase, 0x0345, 0x0399},
}

func TestIsLetter(t *testing.T) {
	for _, r := range upperTest {
		if !IsLetter(r) {
			t.Errorf("IsLetter(U+%04X) = false, want true", r)
		}
	}
	for _, r := range letterTest {
		if !IsLetter(r) {
			t.Errorf("IsLetter(U+%04X) = false, want true", r)
		}
	}
	for _, r := range notletterTest {
		if IsLetter(r) {
			t.Errorf("IsLetter(U+%04X) = true, want false", r)
		}
	}
}

func TestIsUpper(t *testing.T) {
	for _, r := range upperTest {
		if !IsUpper(r) {
			t.Errorf("IsUpper(U+%04X) = false, want true", r)
		}
	}
	for _, r := range notupperTest {
		if IsUpper(r) {
			t.Errorf("IsUpper(U+%04X) = true, want false", r)
		}
	}
	for _, r := range notletterTest {
		if IsUpper(r) {
			t.Errorf("IsUpper(U+%04X) = true, want false", r)
		}
	}
}

func caseString(c int) string {
	switch c {
	case UpperCase:
		return "UpperCase"
	case LowerCase:
		return "LowerCase"
	case TitleCase:
		return "TitleCase"
	}
	return "ErrorCase"
}

func TestTo(t *testing.T) {
	for _, c := range caseTest {
		r := To(c.cas, c.in)
		if c.out != r {
			t.Errorf("To(U+%04X, %s) = U+%04X want U+%04X", c.in, caseString(c.cas), r, c.out)
		}
	}
}

func TestToUpperCase(t *testing.T) {
	for _, c := range caseTest {
		if c.cas != UpperCase {
			continue
		}
		r := ToUpper(c.in)
		if c.out != r {
			t.Errorf("ToUpper(U+%04X) = U+%04X want U+%04X", c.in, r, c.out)
		}
	}
}

func TestToLowerCase(t *testing.T) {
	for _, c := range caseTest {
		if c.cas != LowerCase {
			continue
		}
		r := ToLower(c.in)
		if c.out != r {
			t.Errorf("ToLower(U+%04X) = U+%04X want U+%04X", c.in, r, c.out)
		}
	}
}

func TestToTitleCase(t *testing.T) {
	for _, c := range caseTest {
		if c.cas != TitleCase {
			continue
		}
		r := ToTitle(c.in)
		if c.out != r {
			t.Errorf("ToTitle(U+%04X) = U+%04X want U+%04X", c.in, r, c.out)
		}
	}
}

func TestIsSpace(t *testing.T) {
	for _, c := range spaceTest {
		if !IsSpace(c) {
			t.Errorf("IsSpace(U+%04X) = false; want true", c)
		}
	}
	for _, c := range letterTest {
		if IsSpace(c) {
			t.Errorf("IsSpace(U+%04X) = true; want false", c)
		}
	}
}

// Check that the optimizations for IsLetter etc. agree with the tables.
// We only need to check the Latin-1 range.
func TestLetterOptimizations(t *testing.T) {
	for i := rune(0); i <= MaxLatin1; i++ {
		if Is(Letter, i) != IsLetter(i) {
			t.Errorf("IsLetter(U+%04X) disagrees with Is(Letter)", i)
		}
		if Is(Upper, i) != IsUpper(i) {
			t.Errorf("IsUpper(U+%04X) disagrees with Is(Upper)", i)
		}
		if Is(Lower, i) != IsLower(i) {
			t.Errorf("IsLower(U+%04X) disagrees with Is(Lower)", i)
		}
		if Is(Title, i) != IsTitle(i) {
			t.Errorf("IsTitle(U+%04X) disagrees with Is(Title)", i)
		}
		if Is(White_Space, i) != IsSpace(i) {
			t.Errorf("IsSpace(U+%04X) disagrees with Is(White_Space)", i)
		}
		if To(UpperCase, i) != ToUpper(i) {
			t.Errorf("ToUpper(U+%04X) disagrees with To(Upper)", i)
		}
		if To(LowerCase, i) != ToLower(i) {
			t.Errorf("ToLower(U+%04X) disagrees with To(Lower)", i)
		}
		if To(TitleCase, i) != ToTitle(i) {
			t.Errorf("ToTitle(U+%04X) disagrees with To(Title)", i)
		}
	}
}

func TestTurkishCase(t *testing.T) {
	lower := []rune("abcçdefgğhıijklmnoöprsştuüvyz")
	upper := []rune("ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ")
	for i, l := range lower {
		u := upper[i]
		if TurkishCase.ToLower(l) != l {
			t.Errorf("lower(U+%04X) is U+%04X not U+%04X", l, TurkishCase.ToLower(l), l)
		}
		if TurkishCase.ToUpper(u) != u {
			t.Errorf("upper(U+%04X) is U+%04X not U+%04X", u, TurkishCase.ToUpper(u), u)
		}
		if TurkishCase.ToUpper(l) != u {
			t.Errorf("upper(U+%04X) is U+%04X not U+%04X", l, TurkishCase.ToUpper(l), u)
		}
		if TurkishCase.ToLower(u) != l {
			t.Errorf("lower(U+%04X) is U+%04X not U+%04X", u, TurkishCase.ToLower(l), l)
		}
		if TurkishCase.ToTitle(u) != u {
			t.Errorf("title(U+%04X) is U+%04X not U+%04X", u, TurkishCase.ToTitle(u), u)
		}
		if TurkishCase.ToTitle(l) != u {
			t.Errorf("title(U+%04X) is U+%04X not U+%04X", l, TurkishCase.ToTitle(l), u)
		}
	}
}

var simpleFoldTests = []string{
	// SimpleFold(x) returns the next equivalent rune > x or wraps
	// around to smaller values.

	// Easy cases.
	"Aa",
	"δΔ",

	// ASCII special cases.
	"KkK",
	"Ssſ",

	// Non-ASCII special cases.
	"ρϱΡ",
	"ͅΙιι",

	// Extra special cases: has lower/upper but no case fold.
	"İ",
	"ı",

	// Upper comes before lower (Cherokee).
	"\u13b0\uab80",
}

func TestSimpleFold(t *testing.T) {
	for _, tt := range simpleFoldTests {
		cycle := []rune(tt)
		r := cycle[len(cycle)-1]
		for _, out := range cycle {
			if r := SimpleFold(r); r != out {
				t.Errorf("SimpleFold(%#U) = %#U, want %#U", r, r, out)
			}
			r = out
		}
	}

	if r := SimpleFold(-42); r != -42 {
		t.Errorf("SimpleFold(-42) = %v, want -42", r)
	}
}

// Running 'go test -calibrate' runs the calibration to find a plausible
// cutoff point for linear search of a range list vs. binary search.
// We create a fake table and then time how long it takes to do a
// sequence of searches within that table, for all possible inputs
// relative to the ranges (something before all, in each, between each, after all).
// This assumes that all possible runes are equally likely.
// In practice most runes are ASCII so this is a conservative estimate
// of an effective cutoff value. In practice we could probably set it higher
// than what this function recommends.

var calibrate = flag.Bool("calibrate", false, "compute crossover for linear vs. binary search")

func TestCalibrate(t *testing.T) {
	if !*calibrate {
		return
	}

	if runtime.GOARCH == "amd64" {
		fmt.Printf("warning: running calibration on %s\n", runtime.GOARCH)
	}

	// Find the point where binary search wins by more than 10%.
	// The 10% bias gives linear search an edge when they're close,
	// because on predominantly ASCII inputs linear search is even
	// better than our benchmarks measure.
	n := sort.Search(64, func(n int) bool {
		tab := fakeTable(n)
		blinear := func(b *testing.B) {
			tab := tab
			max := n*5 + 20
			for i := 0; i < b.N; i++ {
				for j := 0; j <= max; j++ {
					linear(tab, uint16(j))
				}
			}
		}
		bbinary := func(b *testing.B) {
			tab := tab
			max := n*5 + 20
			for i := 0; i < b.N; i++ {
				for j := 0; j <= max; j++ {
					binary(tab, uint16(j))
				}
			}
		}
		bmlinear := testing.Benchmark(blinear)
		bmbinary := testing.Benchmark(bbinary)
		fmt.Printf("n=%d: linear=%d binary=%d\n", n, bmlinear.NsPerOp(), bmbinary.NsPerOp())
		return bmlinear.NsPerOp()*100 > bmbinary.NsPerOp()*110
	})
	fmt.Printf("calibration: linear cutoff = %d\n", n)
}

func fakeTable(n int) []Range16 {
	var r16 []Range16
	for i := 0; i < n; i++ {
		r16 = append(r16, Range16{uint16(i*5 + 10), uint16(i*5 + 12), 1})
	}
	return r16
}

func linear(ranges []Range16, r uint16) bool {
	for i := range ranges {
		range_ := &ranges[i]
		if r < range_.Lo {
			return false
		}
		if r <= range_.Hi {
			return (r-range_.Lo)%range_.Stride == 0
		}
	}
	return false
}

func binary(ranges []Range16, r uint16) bool {
	// binary search over ranges
	lo := 0
	hi := len(ranges)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		range_ := &ranges[m]
		if range_.Lo <= r && r <= range_.Hi {
			return (r-range_.Lo)%range_.Stride == 0
		}
		if r < range_.Lo {
			hi = m
		} else {
			lo = m + 1
		}
	}
	return false
}

func TestLatinOffset(t *testing.T) {
	var maps = []map[string]*RangeTable{
		Categories,
		FoldCategory,
		FoldScript,
		Properties,
		Scripts,
	}
	for _, m := range maps {
		for name, tab := range m {
			i := 0
			for i < len(tab.R16) && tab.R16[i].Hi <= MaxLatin1 {
				i++
			}
			if tab.LatinOffset != i {
				t.Errorf("%s: LatinOffset=%d, want %d", name, tab.LatinOffset, i)
			}
		}
	}
}

func TestSpecialCaseNoMapping(t *testing.T) {
	// Issue 25636
	// no change for rune 'A', zero delta, under upper/lower/title case change.
	var noChangeForCapitalA = CaseRange{'A', 'A', [MaxCase]rune{0, 0, 0}}
	got := strings.ToLowerSpecial(SpecialCase([]CaseRange{noChangeForCapitalA}), "ABC")
	want := "Abc"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestNegativeRune(t *testing.T) {
	// Issue 43254
	// These tests cover negative rune handling by testing values which,
	// when cast to uint8 or uint16, look like a particular valid rune.
	// This package has Latin-1-specific optimizations, so we test all of
	// Latin-1 and representative non-Latin-1 values in the character
	// categories covered by IsGraphic, etc.
	nonLatin1 := []uint32{
		// Lu: LATIN CAPITAL LETTER A WITH MACRON
		0x0100,
		// Ll: LATIN SMALL LETTER A WITH MACRON
		0x0101,
		// Lt: LATIN CAPITAL LETTER D WITH SMALL LETTER Z WITH CARON
		0x01C5,
		// M: COMBINING GRAVE ACCENT
		0x0300,
		// Nd: ARABIC-INDIC DIGIT ZERO
		0x0660,
		// P: GREEK QUESTION MARK
		0x037E,
		// S: MODIFIER LETTER LEFT ARROWHEAD
		0x02C2,
		// Z: OGHAM SPACE MARK
		0x1680,
	}
	for i := 0; i < MaxLatin1+len(nonLatin1); i++ {
		base := uint32(i)
		if i >= MaxLatin1 {
			base = nonLatin1[i-MaxLatin1]
		}

		// Note r is negative, but uint8(r) == uint8(base) and
		// uint16(r) == uint16(base).
		r := rune(base - 1<<31)
		if Is(Letter, r) {
			t.Errorf("Is(Letter, 0x%x - 1<<31) = true, want false", base)
		}
		if IsControl(r) {
			t.Errorf("IsControl(0x%x - 1<<31) = true, want false", base)
		}
		if IsDigit(r) {
			t.Errorf("IsDigit(0x%x - 1<<31) = true, want false", base)
		}
		if IsGraphic(r) {
			t.Errorf("IsGraphic(0x%x - 1<<31) = true, want false", base)
		}
		if IsLetter(r) {
			t.Errorf("IsLetter(0x%x - 1<<31) = true, want false", base)
		}
		if IsLower(r) {
			t.Errorf("IsLower(0x%x - 1<<31) = true, want false", base)
		}
		if IsMark(r) {
			t.Errorf("IsMark(0x%x - 1<<31) = true, want false", base)
		}
		if IsNumber(r) {
			t.Errorf("IsNumber(0x%x - 1<<31) = true, want false", base)
		}
		if IsPrint(r) {
			t.Errorf("IsPrint(0x%x - 1<<31) = true, want false", base)
		}
		if IsPunct(r) {
			t.Errorf("IsPunct(0x%x - 1<<31) = true, want false", base)
		}
		if IsSpace(r) {
			t.Errorf("IsSpace(0x%x - 1<<31) = true, want false", base)
		}
		if IsSymbol(r) {
			t.Errorf("IsSymbol(0x%x - 1<<31) = true, want false", base)
		}
		if IsTitle(r) {
			t.Errorf("IsTitle(0x%x - 1<<31) = true, want false", base)
		}
		if IsUpper(r) {
			t.Errorf("IsUpper(0x%x - 1<<31) = true, want false", base)
		}
	}
}

func BenchmarkToUpper(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ToUpper('δ')
	}
}

func BenchmarkToLower(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ToLower('Δ')
	}
}

func BenchmarkSimpleFold(b *testing.B) {
	bench := func(name string, r rune) {
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = SimpleFold(r)
			}
		})
	}
	bench("Upper", 'Δ')
	bench("Lower", 'δ')
	bench("Fold", '\u212A')
	bench("NoFold", '習')
}

"""



```