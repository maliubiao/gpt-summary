Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, which is a test file (`intconv_test.go`) for the `big` package's `Int` type, specifically focusing on string conversions.

2. **Identify Key Areas:**  The file name itself (`intconv_test.go`) strongly suggests it's testing conversions *to* and *from* strings. Looking at the imports (`"bytes"`, `"fmt"`, `"testing"`) confirms this is a test file using standard Go testing practices.

3. **Examine the Test Data Structures:** The code defines two primary data structures: `stringTests` and `formatTests`. These are slices of structs, which are common in Go for organizing test cases.

    * **`stringTests`:**  This looks like a comprehensive set of test cases for converting strings *to* `big.Int`. Key fields are:
        * `in`: The input string.
        * `out`: The expected string representation of the `big.Int` after conversion.
        * `base`: The base to use for conversion.
        * `val`: The expected `int64` value (useful for checking correctness).
        * `ok`: A boolean indicating whether the conversion should succeed.

    * **`formatTests`:** This seems to be testing the formatting of `big.Int` *to* strings using `fmt.Sprintf`. The fields are:
        * `input`:  A string representing a `big.Int` (or "<nil>").
        * `format`: The format string used with `fmt.Sprintf`.
        * `output`: The expected output string after formatting.

4. **Analyze the Test Functions:**  The code defines several test functions, all prefixed with `Test`, which is the standard Go convention for test functions.

    * **`TestIntText`:** This function iterates through `stringTests` and uses the `SetString` method of `big.Int` to parse the input string. It then uses the `Text` method to convert the `big.Int` back to a string with the specified base and compares it to the expected `out` field. This confirms it's testing string-to-`big.Int` and `big.Int`-to-string conversions.

    * **`TestAppendText`:** Similar to `TestIntText`, but instead of `Text`, it uses the `Append` method, which appends the string representation of the `big.Int` to a byte slice. This tests the `Append` method for string conversion.

    * **`TestGetString`:** This function focuses on the `String()` method of `big.Int` (which should be base-10) and the usage of `fmt.Sprintf` with different format specifiers (`%b`, `%o`, `%x`, `%d`). This tests different ways of getting a string representation.

    * **`TestSetString`:**  This is a core test for the `SetString` method. It verifies that the parsing succeeds or fails as expected (based on the `ok` field in `stringTests`) and that the parsed `big.Int` value matches the expected `val`. It also checks for "normalized" representation, which is an internal detail of `big.Int`.

    * **`TestFormat`:** This function iterates through `formatTests` and uses `fmt.Sprintf` to format `big.Int` values according to the specified format strings. It then compares the output with the expected `output`. This confirms it tests the formatting capabilities.

    * **`TestScan`:** This function tests the reverse process - parsing a `big.Int` from a string using `fmt.Fscanf`. It checks that the parsed value is correct and that any remaining part of the input string is as expected.

5. **Infer Functionality:** Based on the test structures and functions, the primary functionality being tested is:

    * **String to `big.Int` Conversion:**  Using `SetString`. This involves handling different bases (binary, octal, decimal, hexadecimal, up to base 36), signs, and optional prefixes like `0b`, `0o`, `0x`.
    * **`big.Int` to String Conversion:** Using `Text`, `Append`, and `String`. This involves converting back to different bases.
    * **Formatted Output:** Using `fmt.Sprintf` with various format specifiers (`%b`, `%o`, `%d`, `%x`, `%X`, and flags like `#`, `+`, ` `, `0`, `-`, and precision).
    * **Scanning from String:** Using `fmt.Fscanf` to parse `big.Int` from formatted strings.

6. **Code Examples (Based on Inference):** Now, create Go code examples to demonstrate these functionalities, drawing inspiration from the test cases. This involves using the `big` package and its `Int` type.

7. **Identify Potential Pitfalls:** Think about common errors users might make when working with string conversions for `big.Int`. For example:

    * Incorrect base specification.
    * Invalid characters for a given base.
    * Expecting separators to work in all cases.
    * Misunderstanding the behavior of `SetString` with base 0.
    * Issues with formatting and precision.

8. **Command-Line Arguments (If Applicable):**  In this specific test file, there are *no* command-line arguments being processed. The tests are self-contained. Note this explicitly.

9. **Structure the Answer:** Organize the findings into a clear and readable format, addressing each part of the original request. Use headings, bullet points, and code blocks for better presentation. Translate technical terms into understandable Chinese.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe the file tests all aspects of `big.Int`.
* **Correction:**  Closer inspection reveals the focus is primarily on string conversions. The file name confirms this.
* **Initial thought:** Are the `stringTests` comprehensive for all edge cases?
* **Refinement:** The comments mention "smoke tests" and that `natconv_test.go` has a "comprehensive set of tests," suggesting this file might focus on more common or representative cases.
* **Initial thought:**  How does `base=0` work in `SetString`?
* **Refinement:** The code and comments indicate that `base=0` auto-detects the base based on prefixes (like `0b`, `0x`).

By following this structured analysis, we can accurately understand the functionality of the provided Go code and answer the request comprehensively.
这段代码是 Go 语言标准库 `math/big` 包中 `intconv_test.go` 文件的一部分，其主要功能是**测试 `big.Int` 类型与字符串之间的转换功能**。具体来说，它测试了以下几个方面：

**1. 将字符串转换为 `big.Int` 类型 (`SetString` 方法)**

*   **功能:**  测试 `big.Int` 的 `SetString(s string, base int)` 方法，该方法尝试将字符串 `s` 按照给定的 `base` 转换为一个 `big.Int`。
*   **测试用例:**  `stringTests` 变量定义了一系列测试用例，包含了各种有效的、无效的输入字符串，以及不同的进制 (`base`)。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	z := new(big.Int)

	// 有效的转换
	z.SetString("12345", 10)
	fmt.Println(z) // 输出: 12345

	z.SetString("0xcafe", 0) // base 为 0 时自动检测进制
	fmt.Println(z) // 输出: 51966

	// 无效的转换
	_, ok := z.SetString("abc", 10)
	fmt.Println(ok) // 输出: false

	_, ok = z.SetString("123", 2) // '3' 不是二进制字符
	fmt.Println(ok) // 输出: false
}
```

*   **假设的输入与输出:**
    *   输入字符串: `"1010"`， base: `2`
    *   预期输出: `big.Int` 的值为 10
    *   输入字符串: `"0xFF"`， base: `0`
    *   预期输出: `big.Int` 的值为 255
    *   输入字符串: `"hello"`， base: `10`
    *   预期输出: `SetString` 返回的 `ok` 为 `false`

**2. 将 `big.Int` 类型转换为字符串 (`Text` 和 `String` 方法)**

*   **功能:** 测试 `big.Int` 的 `Text(base int)` 方法，该方法将 `big.Int` 转换为指定 `base` 的字符串表示。同时测试 `String()` 方法，它是 `Text(10)` 的简写形式。
*   **测试用例:**  `stringTests` 变量中的 `out` 字段定义了预期输出的字符串。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	z := big.NewInt(123)

	// 转换为十进制字符串
	str10 := z.String()
	fmt.Println(str10) // 输出: 123

	// 转换为十六进制字符串
	str16 := z.Text(16)
	fmt.Println(str16) // 输出: 7b

	// 转换为二进制字符串
	str2 := z.Text(2)
	fmt.Println(str2) // 输出: 1111011
}
```

*   **假设的输入与输出:**
    *   `big.Int` 的值为 255， base: `16`
    *   预期输出: `"ff"`
    *   `big.Int` 的值为 -10， base: `2`
    *   预期输出: `"-1010"`

**3. 将 `big.Int` 类型格式化为字符串 (`fmt.Sprintf` 与 `%b`, `%o`, `%d`, `%x` 等格式化动词)**

*   **功能:** 测试使用 `fmt.Sprintf` 函数以及不同的格式化动词来格式化 `big.Int`，例如 `%b` (二进制), `%o` (八进制), `%d` (十进制), `%x` (十六进制小写), `%X` (十六进制大写) 等。
*   **测试用例:** `formatTests` 变量定义了各种输入 `big.Int` (以字符串形式表示), 格式化字符串和预期的输出。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	z := big.NewInt(42)

	fmt.Printf("%b\n", z)   // 输出: 101010
	fmt.Printf("%o\n", z)   // 输出: 52
	fmt.Printf("%d\n", z)   // 输出: 42
	fmt.Printf("%x\n", z)   // 输出: 2a
	fmt.Printf("%X\n", z)   // 输出: 2A
	fmt.Printf("%#b\n", z)  // 输出: 0b101010
	fmt.Printf("%#x\n", z)  // 输出: 0x2a
	fmt.Printf("%08d\n", z) // 输出: 00000042 (填充零)
	fmt.Printf("% 8d\n", z) // 输出:       42 (填充空格)
}
```

*   **假设的输入与输出:**
    *   `big.Int` 的值为 10， 格式化字符串: `"%b"`
    *   预期输出: `"1010"`
    *   `big.Int` 的值为 -10， 格式化字符串: `"%X"`
    *   预期输出: `"-A"`
    *   `big.Int` 的值为 1234， 格式化字符串: `"%06d"`
    *   预期输出: `"001234"`

**4. 从字符串扫描并设置 `big.Int` (`fmt.Fscanf`)**

*   **功能:** 测试使用 `fmt.Fscanf` 函数从字符串中扫描并设置 `big.Int` 的值，支持不同的进制格式。
*   **测试用例:** `scanTests` 变量定义了输入字符串，格式化字符串，预期的 `big.Int` 输出以及剩余未扫描的字符数。
*   **代码示例:**

```go
package main

import (
	"fmt"
	"math/big"
	"strings"
)

func main() {
	var z big.Int
	r := strings.NewReader("1010")
	fmt.Fscanf(r, "%b", &z)
	fmt.Println(&z) // 输出: 10

	r = strings.NewReader("0xFF remaining")
	z.SetInt64(0) // 重置 z 的值
	var remaining string
	n, _ := fmt.Fscanf(r, "%x %s", &z, &remaining)
	fmt.Println(&z, remaining, n) // 输出: 255 remaining 2
}
```

*   **假设的输入与输出:**
    *   输入字符串: `"0b1011001"`， 格式化字符串: `"%v"`
    *   预期输出: `big.Int` 的值为 89
    *   输入字符串: `"0xA"`， 格式化字符串: `"%v"`
    *   预期输出: `big.Int` 的值为 10
    *   输入字符串: `"2+3"`， 格式化字符串: `"%v"`
    *   预期输出: `big.Int` 的值为 2， 剩余字符串: `"+3"`

**代码推理:**

该测试文件通过构造不同的输入字符串和预期的输出，来验证 `big.Int` 类型在字符串转换过程中的正确性。 例如，对于 `stringTests` 中的一个测试用例 `{"10", "10", 16, 16, true}`，可以推断出：

*   当使用 `z.SetString("10", 16)` 时，`big.Int` `z` 的值应该被设置为十进制的 16。
*   当使用 `z.Text(16)` 时，应该返回字符串 `"10"`。
*   当使用 `z.String()` 时，应该返回字符串 `"16"` (因为 `String()` 默认是十进制)。

**命令行参数:**

该测试文件本身**不涉及**命令行参数的处理。它是 Go 语言的单元测试代码，通常通过 `go test` 命令来运行。`go test` 命令有一些标准的命令行参数，例如 `-v` (显示详细输出), `-run` (运行特定的测试用例) 等，但这部分代码本身并没有解析或使用自定义的命令行参数。

**使用者易犯错的点:**

1. **进制错误:** 在使用 `SetString` 时，如果提供的 `base` 与字符串的实际进制不符，会导致转换失败或得到错误的结果。
    *   **例子:**  `z.SetString("10", 2)` 会返回错误，因为 "10" 不是有效的二进制数（只有 0 和 1）。

2. **`base` 为 0 的理解:** 当 `SetString` 的 `base` 参数为 0 时，它会尝试根据字符串的前缀自动判断进制（例如 "0b" 表示二进制, "0x" 表示十六进制）。如果没有前缀，则默认为十进制。容易出错的地方在于，如果没有前缀但包含非十进制字符，会导致解析失败。
    *   **例子:** `z.SetString("ff", 0)` 会解析失败，因为没有 "0x" 前缀，且 "ff" 不是有效的十进制数。

3. **忽略 `SetString` 的返回值:** `SetString` 方法返回一个 `*Int` 和一个 `bool` 值。`bool` 值指示转换是否成功。使用者容易忽略这个返回值，导致在转换失败的情况下继续使用未正确初始化的 `big.Int`，从而引发错误。

4. **格式化字符串的误用:** 在使用 `fmt.Sprintf` 格式化 `big.Int` 时，容易混淆不同的格式化动词，或者对格式化标志（如 `#`, `0`, `+`, `-`）的作用理解不清晰。
    *   **例子:**  期望输出带 "0x" 前缀的十六进制数，却使用了 `"%x"` 而不是 `"%#x"`。

5. **`Fscanf` 的格式匹配:** 使用 `fmt.Fscanf` 时，提供的格式化字符串必须与输入的字符串格式严格匹配，否则可能扫描失败或者只扫描到部分内容。

总而言之，这段代码通过大量的测试用例，细致地检验了 `big.Int` 类型在与字符串相互转换时的各种情况，确保了其功能的健壮性和正确性。对于 `big.Int` 的使用者来说，理解这些测试用例可以帮助他们更好地掌握 `big.Int` 的字符串转换方法，并避免一些常见的错误。

Prompt: 
```
这是路径为go/src/math/big/intconv_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package big

import (
	"bytes"
	"fmt"
	"testing"
)

var stringTests = []struct {
	in   string
	out  string
	base int
	val  int64
	ok   bool
}{
	// invalid inputs
	{in: ""},
	{in: "a"},
	{in: "z"},
	{in: "+"},
	{in: "-"},
	{in: "0b"},
	{in: "0o"},
	{in: "0x"},
	{in: "0y"},
	{in: "2", base: 2},
	{in: "0b2", base: 0},
	{in: "08"},
	{in: "8", base: 8},
	{in: "0xg", base: 0},
	{in: "g", base: 16},

	// invalid inputs with separators
	// (smoke tests only - a comprehensive set of tests is in natconv_test.go)
	{in: "_"},
	{in: "0_"},
	{in: "_0"},
	{in: "-1__0"},
	{in: "0x10_"},
	{in: "1_000", base: 10}, // separators are not permitted for bases != 0
	{in: "d_e_a_d", base: 16},

	// valid inputs
	{"0", "0", 0, 0, true},
	{"0", "0", 10, 0, true},
	{"0", "0", 16, 0, true},
	{"+0", "0", 0, 0, true},
	{"-0", "0", 0, 0, true},
	{"10", "10", 0, 10, true},
	{"10", "10", 10, 10, true},
	{"10", "10", 16, 16, true},
	{"-10", "-10", 16, -16, true},
	{"+10", "10", 16, 16, true},
	{"0b10", "2", 0, 2, true},
	{"0o10", "8", 0, 8, true},
	{"0x10", "16", 0, 16, true},
	{in: "0x10", base: 16},
	{"-0x10", "-16", 0, -16, true},
	{"+0x10", "16", 0, 16, true},
	{"00", "0", 0, 0, true},
	{"0", "0", 8, 0, true},
	{"07", "7", 0, 7, true},
	{"7", "7", 8, 7, true},
	{"023", "19", 0, 19, true},
	{"23", "23", 8, 19, true},
	{"cafebabe", "cafebabe", 16, 0xcafebabe, true},
	{"0b0", "0", 0, 0, true},
	{"-111", "-111", 2, -7, true},
	{"-0b111", "-7", 0, -7, true},
	{"0b1001010111", "599", 0, 0x257, true},
	{"1001010111", "1001010111", 2, 0x257, true},
	{"A", "a", 36, 10, true},
	{"A", "A", 37, 36, true},
	{"ABCXYZ", "abcxyz", 36, 623741435, true},
	{"ABCXYZ", "ABCXYZ", 62, 33536793425, true},

	// valid input with separators
	// (smoke tests only - a comprehensive set of tests is in natconv_test.go)
	{"1_000", "1000", 0, 1000, true},
	{"0b_1010", "10", 0, 10, true},
	{"+0o_660", "432", 0, 0660, true},
	{"-0xF00D_1E", "-15731998", 0, -0xf00d1e, true},
}

func TestIntText(t *testing.T) {
	z := new(Int)
	for _, test := range stringTests {
		if !test.ok {
			continue
		}

		_, ok := z.SetString(test.in, test.base)
		if !ok {
			t.Errorf("%v: failed to parse", test)
			continue
		}

		base := test.base
		if base == 0 {
			base = 10
		}

		if got := z.Text(base); got != test.out {
			t.Errorf("%v: got %s; want %s", test, got, test.out)
		}
	}
}

func TestAppendText(t *testing.T) {
	z := new(Int)
	var buf []byte
	for _, test := range stringTests {
		if !test.ok {
			continue
		}

		_, ok := z.SetString(test.in, test.base)
		if !ok {
			t.Errorf("%v: failed to parse", test)
			continue
		}

		base := test.base
		if base == 0 {
			base = 10
		}

		i := len(buf)
		buf = z.Append(buf, base)
		if got := string(buf[i:]); got != test.out {
			t.Errorf("%v: got %s; want %s", test, got, test.out)
		}
	}
}

func format(base int) string {
	switch base {
	case 2:
		return "%b"
	case 8:
		return "%o"
	case 16:
		return "%x"
	}
	return "%d"
}

func TestGetString(t *testing.T) {
	z := new(Int)
	for i, test := range stringTests {
		if !test.ok {
			continue
		}
		z.SetInt64(test.val)

		if test.base == 10 {
			if got := z.String(); got != test.out {
				t.Errorf("#%da got %s; want %s", i, got, test.out)
			}
		}

		f := format(test.base)
		got := fmt.Sprintf(f, z)
		if f == "%d" {
			if got != fmt.Sprintf("%d", test.val) {
				t.Errorf("#%db got %s; want %d", i, got, test.val)
			}
		} else {
			if got != test.out {
				t.Errorf("#%dc got %s; want %s", i, got, test.out)
			}
		}
	}
}

func TestSetString(t *testing.T) {
	tmp := new(Int)
	for i, test := range stringTests {
		// initialize to a non-zero value so that issues with parsing
		// 0 are detected
		tmp.SetInt64(1234567890)
		n1, ok1 := new(Int).SetString(test.in, test.base)
		n2, ok2 := tmp.SetString(test.in, test.base)
		expected := NewInt(test.val)
		if ok1 != test.ok || ok2 != test.ok {
			t.Errorf("#%d (input '%s') ok incorrect (should be %t)", i, test.in, test.ok)
			continue
		}
		if !ok1 {
			if n1 != nil {
				t.Errorf("#%d (input '%s') n1 != nil", i, test.in)
			}
			continue
		}
		if !ok2 {
			if n2 != nil {
				t.Errorf("#%d (input '%s') n2 != nil", i, test.in)
			}
			continue
		}

		if ok1 && !isNormalized(n1) {
			t.Errorf("#%d (input '%s'): %v is not normalized", i, test.in, *n1)
		}
		if ok2 && !isNormalized(n2) {
			t.Errorf("#%d (input '%s'): %v is not normalized", i, test.in, *n2)
		}

		if n1.Cmp(expected) != 0 {
			t.Errorf("#%d (input '%s') got: %s want: %d", i, test.in, n1, test.val)
		}
		if n2.Cmp(expected) != 0 {
			t.Errorf("#%d (input '%s') got: %s want: %d", i, test.in, n2, test.val)
		}
	}
}

var formatTests = []struct {
	input  string
	format string
	output string
}{
	{"<nil>", "%x", "<nil>"},
	{"<nil>", "%#x", "<nil>"},
	{"<nil>", "%#y", "%!y(big.Int=<nil>)"},

	{"10", "%b", "1010"},
	{"10", "%o", "12"},
	{"10", "%d", "10"},
	{"10", "%v", "10"},
	{"10", "%x", "a"},
	{"10", "%X", "A"},
	{"-10", "%X", "-A"},
	{"10", "%y", "%!y(big.Int=10)"},
	{"-10", "%y", "%!y(big.Int=-10)"},

	{"10", "%#b", "0b1010"},
	{"10", "%#o", "012"},
	{"10", "%O", "0o12"},
	{"-10", "%#b", "-0b1010"},
	{"-10", "%#o", "-012"},
	{"-10", "%O", "-0o12"},
	{"10", "%#d", "10"},
	{"10", "%#v", "10"},
	{"10", "%#x", "0xa"},
	{"10", "%#X", "0XA"},
	{"-10", "%#X", "-0XA"},
	{"10", "%#y", "%!y(big.Int=10)"},
	{"-10", "%#y", "%!y(big.Int=-10)"},

	{"1234", "%d", "1234"},
	{"1234", "%3d", "1234"},
	{"1234", "%4d", "1234"},
	{"-1234", "%d", "-1234"},
	{"1234", "% 5d", " 1234"},
	{"1234", "%+5d", "+1234"},
	{"1234", "%-5d", "1234 "},
	{"1234", "%x", "4d2"},
	{"1234", "%X", "4D2"},
	{"-1234", "%3x", "-4d2"},
	{"-1234", "%4x", "-4d2"},
	{"-1234", "%5x", " -4d2"},
	{"-1234", "%-5x", "-4d2 "},
	{"1234", "%03d", "1234"},
	{"1234", "%04d", "1234"},
	{"1234", "%05d", "01234"},
	{"1234", "%06d", "001234"},
	{"-1234", "%06d", "-01234"},
	{"1234", "%+06d", "+01234"},
	{"1234", "% 06d", " 01234"},
	{"1234", "%-6d", "1234  "},
	{"1234", "%-06d", "1234  "},
	{"-1234", "%-06d", "-1234 "},

	{"1234", "%.3d", "1234"},
	{"1234", "%.4d", "1234"},
	{"1234", "%.5d", "01234"},
	{"1234", "%.6d", "001234"},
	{"-1234", "%.3d", "-1234"},
	{"-1234", "%.4d", "-1234"},
	{"-1234", "%.5d", "-01234"},
	{"-1234", "%.6d", "-001234"},

	{"1234", "%8.3d", "    1234"},
	{"1234", "%8.4d", "    1234"},
	{"1234", "%8.5d", "   01234"},
	{"1234", "%8.6d", "  001234"},
	{"-1234", "%8.3d", "   -1234"},
	{"-1234", "%8.4d", "   -1234"},
	{"-1234", "%8.5d", "  -01234"},
	{"-1234", "%8.6d", " -001234"},

	{"1234", "%+8.3d", "   +1234"},
	{"1234", "%+8.4d", "   +1234"},
	{"1234", "%+8.5d", "  +01234"},
	{"1234", "%+8.6d", " +001234"},
	{"-1234", "%+8.3d", "   -1234"},
	{"-1234", "%+8.4d", "   -1234"},
	{"-1234", "%+8.5d", "  -01234"},
	{"-1234", "%+8.6d", " -001234"},

	{"1234", "% 8.3d", "    1234"},
	{"1234", "% 8.4d", "    1234"},
	{"1234", "% 8.5d", "   01234"},
	{"1234", "% 8.6d", "  001234"},
	{"-1234", "% 8.3d", "   -1234"},
	{"-1234", "% 8.4d", "   -1234"},
	{"-1234", "% 8.5d", "  -01234"},
	{"-1234", "% 8.6d", " -001234"},

	{"1234", "%.3x", "4d2"},
	{"1234", "%.4x", "04d2"},
	{"1234", "%.5x", "004d2"},
	{"1234", "%.6x", "0004d2"},
	{"-1234", "%.3x", "-4d2"},
	{"-1234", "%.4x", "-04d2"},
	{"-1234", "%.5x", "-004d2"},
	{"-1234", "%.6x", "-0004d2"},

	{"1234", "%8.3x", "     4d2"},
	{"1234", "%8.4x", "    04d2"},
	{"1234", "%8.5x", "   004d2"},
	{"1234", "%8.6x", "  0004d2"},
	{"-1234", "%8.3x", "    -4d2"},
	{"-1234", "%8.4x", "   -04d2"},
	{"-1234", "%8.5x", "  -004d2"},
	{"-1234", "%8.6x", " -0004d2"},

	{"1234", "%+8.3x", "    +4d2"},
	{"1234", "%+8.4x", "   +04d2"},
	{"1234", "%+8.5x", "  +004d2"},
	{"1234", "%+8.6x", " +0004d2"},
	{"-1234", "%+8.3x", "    -4d2"},
	{"-1234", "%+8.4x", "   -04d2"},
	{"-1234", "%+8.5x", "  -004d2"},
	{"-1234", "%+8.6x", " -0004d2"},

	{"1234", "% 8.3x", "     4d2"},
	{"1234", "% 8.4x", "    04d2"},
	{"1234", "% 8.5x", "   004d2"},
	{"1234", "% 8.6x", "  0004d2"},
	{"1234", "% 8.7x", " 00004d2"},
	{"1234", "% 8.8x", " 000004d2"},
	{"-1234", "% 8.3x", "    -4d2"},
	{"-1234", "% 8.4x", "   -04d2"},
	{"-1234", "% 8.5x", "  -004d2"},
	{"-1234", "% 8.6x", " -0004d2"},
	{"-1234", "% 8.7x", "-00004d2"},
	{"-1234", "% 8.8x", "-000004d2"},

	{"1234", "%-8.3d", "1234    "},
	{"1234", "%-8.4d", "1234    "},
	{"1234", "%-8.5d", "01234   "},
	{"1234", "%-8.6d", "001234  "},
	{"1234", "%-8.7d", "0001234 "},
	{"1234", "%-8.8d", "00001234"},
	{"-1234", "%-8.3d", "-1234   "},
	{"-1234", "%-8.4d", "-1234   "},
	{"-1234", "%-8.5d", "-01234  "},
	{"-1234", "%-8.6d", "-001234 "},
	{"-1234", "%-8.7d", "-0001234"},
	{"-1234", "%-8.8d", "-00001234"},

	{"16777215", "%b", "111111111111111111111111"}, // 2**24 - 1

	{"0", "%.d", ""},
	{"0", "%.0d", ""},
	{"0", "%3.d", ""},
}

func TestFormat(t *testing.T) {
	for i, test := range formatTests {
		var x *Int
		if test.input != "<nil>" {
			var ok bool
			x, ok = new(Int).SetString(test.input, 0)
			if !ok {
				t.Errorf("#%d failed reading input %s", i, test.input)
			}
		}
		output := fmt.Sprintf(test.format, x)
		if output != test.output {
			t.Errorf("#%d got %q; want %q, {%q, %q, %q}", i, output, test.output, test.input, test.format, test.output)
		}
	}
}

var scanTests = []struct {
	input     string
	format    string
	output    string
	remaining int
}{
	{"1010", "%b", "10", 0},
	{"0b1010", "%v", "10", 0},
	{"12", "%o", "10", 0},
	{"012", "%v", "10", 0},
	{"10", "%d", "10", 0},
	{"10", "%v", "10", 0},
	{"a", "%x", "10", 0},
	{"0xa", "%v", "10", 0},
	{"A", "%X", "10", 0},
	{"-A", "%X", "-10", 0},
	{"+0b1011001", "%v", "89", 0},
	{"0xA", "%v", "10", 0},
	{"0 ", "%v", "0", 1},
	{"2+3", "%v", "2", 2},
	{"0XABC 12", "%v", "2748", 3},
}

func TestScan(t *testing.T) {
	var buf bytes.Buffer
	for i, test := range scanTests {
		x := new(Int)
		buf.Reset()
		buf.WriteString(test.input)
		if _, err := fmt.Fscanf(&buf, test.format, x); err != nil {
			t.Errorf("#%d error: %s", i, err)
		}
		if x.String() != test.output {
			t.Errorf("#%d got %s; want %s", i, x.String(), test.output)
		}
		if buf.Len() != test.remaining {
			t.Errorf("#%d got %d bytes remaining; want %d", i, buf.Len(), test.remaining)
		}
	}
}

"""



```