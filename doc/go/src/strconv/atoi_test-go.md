Response:
Let's break down the thought process for analyzing this Go test file.

1. **Identify the Core Purpose:** The file name `atoi_test.go` and the package name `strconv_test` immediately suggest this file contains tests related to string conversion to integers. Specifically, `atoi` is a common abbreviation for "ASCII to integer".

2. **Scan for Key Functions/Types:**  Look for the main functions being tested. A quick scan reveals `ParseUint`, `ParseInt`, and `Atoi`. The presence of `...BaseTest` structs suggests testing these functions with different bases.

3. **Analyze the Test Structures:**  Notice the consistent pattern of `struct` types like `parseUint64Test`, `parseUint64BaseTest`, etc., and corresponding slice variables like `parseUint64Tests`, `parseUint64BaseTests`. This strongly indicates a table-driven testing approach. Each struct likely represents a single test case with inputs, expected outputs, and expected errors.

4. **Examine Test Cases (Sampling):**  Pick a few test cases from each test suite (e.g., `parseUint64Tests`, `parseInt64BaseTests`). This helps understand the scope of the tests. For instance, the `parseUint64Tests` include:
    * Empty string and expected `ErrSyntax`.
    * Basic positive numbers.
    * Numbers with leading zeros.
    * Invalid characters.
    * Max and out-of-range unsigned 64-bit integers.
    * Underscores (and the rule that they aren't allowed in base 10).
    * Negative signs (and the rule that they aren't allowed for unsigned).

5. **Infer Functionality from Tests:** Based on the test cases, start inferring what the `strconv` functions are doing:
    * `ParseUint`: Parses unsigned integers from strings, with optional base specification. Handles different bases (decimal, hexadecimal, octal, binary). Detects syntax and range errors.
    * `ParseInt`: Similar to `ParseUint` but for signed integers, including handling negative signs.
    * `Atoi`: A convenience function specifically for parsing decimal integers.

6. **Look for Helper Functions/Setup:**  The `init()` function is important. It modifies the error expectations to wrap them in a `NumError` struct. This hints at a custom error handling mechanism. The `equalError` function is a helper for comparing errors.

7. **Identify Specific Test Functions:**  Functions like `TestParseUint64`, `TestParseIntBase`, and `TestAtoi` are the actual test runners. They iterate through the test case slices and call the corresponding `strconv` functions, comparing the results with the expected values.

8. **Consider Edge Cases and Error Handling:** Pay attention to test cases that specifically check for errors (`ErrSyntax`, `ErrRange`). This reveals how the `strconv` package handles invalid input. The `parseBitSizeTests` and `parseBaseTests` arrays test the validation of `bitSize` and `base` arguments.

9. **Look for Benchmarks:** The `BenchmarkParseInt` and `BenchmarkAtoi` functions indicate performance testing of these functions.

10. **Synthesize the Information:**  Combine all the observations to formulate a comprehensive description of the file's functionality.

11. **Code Example (Putting It Together):** Based on the understanding of `ParseInt` and `ParseUint`, construct illustrative examples showing their usage, different bases, and error handling. Think about demonstrating the core functionalities identified in the tests.

12. **Command-Line Arguments (No Direct Evidence):**  The file doesn't contain any direct command-line argument parsing logic. State this explicitly.

13. **Common Mistakes (Based on Test Cases):**  Reflect on the types of errors the tests are designed to catch. This leads to identifying common mistakes like:
    * Using underscores in base 10.
    * Providing negative signs for `ParseUint`.
    * Invalid characters in the input string.
    * Numbers exceeding the maximum representable value.
    * Incorrect base specification.

14. **Review and Refine:** Read through the generated answer to ensure clarity, accuracy, and completeness. Make sure the code examples are correct and illustrate the points effectively.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just tests `Atoi`."  **Correction:**  Realized the file tests `ParseUint`, `ParseInt`, and `Atoi`.
* **Initial thought:** "The errors are simple `error` types." **Correction:** Noticed the `init()` function wraps errors in `NumError`, indicating a more structured error handling approach.
* **Considered including all test cases in the explanation:** **Correction:**  Decided to sample test cases for brevity and focus on the core concepts illustrated by them.
* **Initially missed the `parseBitSizeTests` and `parseBaseTests`:** **Correction:**  Went back and analyzed these to understand the validation of `bitSize` and `base` arguments.

This iterative process of examining the code, inferring functionality from the tests, and then structuring the information leads to a comprehensive understanding of the test file's purpose.
这个 `atoi_test.go` 文件是 Go 语言标准库 `strconv` 包的一部分，专门用于测试字符串到整数转换相关的功能。更具体地说，它主要测试了以下几个函数：

* **`ParseUint(s string, base int, bitSize int) (uint64, error)`:** 将字符串 `s` 按照指定的 `base` (进制) 转换为一个无符号整数，`bitSize` 指定了结果的位数 (如 8, 16, 32, 64)。
* **`ParseInt(s string, base int, bitSize int) (int64, error)`:**  将字符串 `s` 按照指定的 `base` 转换为一个有符号整数，`bitSize` 指定了结果的位数。
* **`Atoi(s string) (int, error)`:**  一个便捷函数，相当于 `ParseInt(s, 10, 0)`，即将字符串 `s` 转换为十进制的有符号整数，并根据平台自动选择 `int` 的大小。

**它主要的功能可以概括为：**

1. **单元测试 `ParseUint` 函数：**
   - 测试在不同输入字符串下，`ParseUint` 函数能否正确地将字符串转换为 `uint64` 类型。
   - 测试了各种边界情况，例如空字符串、零、正数、带有前导零的数、超出范围的数、包含非法字符的字符串以及带有下划线的字符串（在不同进制下的规则）。
   - 测试了不同的进制（通过 `parseUint64BaseTests`），包括 0（自动推断进制）、2、8、10、16 等。
   - 验证了正确的转换结果以及预期的错误类型（如 `ErrSyntax` 表示语法错误，`ErrRange` 表示超出范围）。

2. **单元测试 `ParseInt` 函数：**
   - 类似于 `ParseUint`，但针对有符号整数 `int64`。
   - 测试了正数、负数、零以及超出有符号整数范围的情况。
   - 同样测试了不同进制下的转换。

3. **单元测试 `Atoi` 函数：**
   - 测试了 `Atoi` 函数在不同输入字符串下能否正确转换为 `int` 类型。
   - 由于 `Atoi` 内部调用 `ParseInt`，这里的测试用例与 `ParseInt` 的部分用例类似，但关注的是最终 `int` 类型的结果。

4. **错误处理测试：**
   - 测试了当 `ParseInt` 和 `ParseUint` 的 `bitSize` 参数或 `base` 参数不合法时，是否返回了预期的错误（`BitSizeError` 和 `BaseError`）。
   - 测试了 `NumError` 类型，这是 `strconv` 包中用于包装转换错误的类型，包含了函数名、输入的字符串以及具体的错误信息。

5. **性能基准测试 (`BenchmarkParseInt`, `BenchmarkAtoi`)：**
   - 衡量 `ParseInt` 和 `Atoi` 函数在处理不同位数的正负整数时的性能。

**它可以推理出 `strconv` 包的以下 Go 语言功能的实现：**

* **字符串到无符号整数的转换 (`ParseUint`)：**
  ```go
  package main

  import (
      "fmt"
      "strconv"
  )

  func main() {
      // 将字符串 "12345" 转换为十进制无符号 64 位整数
      numUint, err := strconv.ParseUint("12345", 10, 64)
      if err != nil {
          fmt.Println("转换错误:", err)
      } else {
          fmt.Println("转换结果:", numUint) // 输出: 转换结果: 12345
      }

      // 将字符串 "0xFF" 转换为十六进制无符号 32 位整数
      numUintHex, err := strconv.ParseUint("FF", 16, 32)
      if err != nil {
          fmt.Println("转换错误:", err)
      } else {
          fmt.Println("转换结果:", numUintHex) // 输出: 转换结果: 255
      }

      // 尝试转换超出范围的字符串
      _, err = strconv.ParseUint("18446744073709551616", 10, 64)
      if err != nil {
          fmt.Println("转换错误:", err) // 输出: 转换错误: strconv.ParseUint: parsing "18446744073709551616": range out of range
      }
  }
  ```
  **假设的输入与输出:**
  - 输入字符串: `"12345"`, `base`: `10`, `bitSize`: `64`， 输出: `12345`, `nil`
  - 输入字符串: `"FF"`, `base`: `16`, `bitSize`: `32`， 输出: `255`, `nil`
  - 输入字符串: `"18446744073709551616"`, `base`: `10`, `bitSize`: `64`，输出: `18446744073709551615`, `&strconv.NumError{Func: "ParseUint", Num: "18446744073709551616", Err: strconv.ErrRange}`

* **字符串到有符号整数的转换 (`ParseInt`)：**
  ```go
  package main

  import (
      "fmt"
      "strconv"
  )

  func main() {
      // 将字符串 "-123" 转换为十进制有符号 32 位整数
      numInt, err := strconv.ParseInt("-123", 10, 32)
      if err != nil {
          fmt.Println("转换错误:", err)
      } else {
          fmt.Println("转换结果:", numInt) // 输出: 转换结果: -123
      }

      // 将字符串 "0b101" 转换为二进制有符号 64 位整数
      numIntBin, err := strconv.ParseInt("101", 2, 64)
      if err != nil {
          fmt.Println("转换错误:", err)
      } else {
          fmt.Println("转换结果:", numIntBin) // 输出: 转换结果: 5
      }

      // 尝试转换非法的字符串
      _, err = strconv.ParseInt("abc", 10, 32)
      if err != nil {
          fmt.Println("转换错误:", err) // 输出: 转换错误: strconv.ParseInt: parsing "abc": invalid syntax
      }
  }
  ```
  **假设的输入与输出:**
  - 输入字符串: `"-123"`, `base`: `10`, `bitSize`: `32`， 输出: `-123`, `nil`
  - 输入字符串: `"101"`, `base`: `2`, `bitSize`: `64`， 输出: `5`, `nil`
  - 输入字符串: `"abc"`, `base`: `10`, `bitSize`: `32`，输出: `0`, `&strconv.NumError{Func: "ParseInt", Num: "abc", Err: strconv.ErrSyntax}`

* **字符串到 `int` 类型的转换 (`Atoi`)：**
  ```go
  package main

  import (
      "fmt"
      "strconv"
  )

  func main() {
      // 将字符串 "999" 转换为 int 类型
      num, err := strconv.Atoi("999")
      if err != nil {
          fmt.Println("转换错误:", err)
      } else {
          fmt.Println("转换结果:", num) // 输出: 转换结果: 999
      }

      // 尝试转换非数字字符串
      _, err = strconv.Atoi("hello")
      if err != nil {
          fmt.Println("转换错误:", err) // 输出: 转换错误: strconv.Atoi: parsing "hello": invalid syntax
      }
  }
  ```
  **假设的输入与输出:**
  - 输入字符串: `"999"`，输出: `999`, `nil`
  - 输入字符串: `"hello"`，输出: `0`, `&strconv.NumError{Func: "Atoi", Num: "hello", Err: strconv.ErrSyntax}`

**命令行参数的具体处理：**

这个测试文件本身并不处理命令行参数。它是一个单元测试文件，主要通过 Go 的 `testing` 包来运行测试用例。命令行参数的处理通常会在程序的 `main` 函数中完成，而 `strconv` 包提供的函数是被其他程序调用的工具函数。

**使用者易犯错的点：**

1. **对 `ParseUint` 使用负数或加号：** `ParseUint` 用于解析无符号整数，因此输入字符串不应包含负号 `-` 或正号 `+`。
   ```go
   package main

   import (
       "fmt"
       "strconv"
   )

   func main() {
       _, err := strconv.ParseUint("-10", 10, 64)
       if err != nil {
           fmt.Println("错误:", err) // 输出: 错误: strconv.ParseUint: parsing "-10": invalid syntax
       }
   }
   ```

2. **在 `base=10` 的情况下使用下划线 `_` 分隔数字：**  在 Go 1.13 之后，下划线可以用作数字字面量的分隔符以提高可读性，但在 `ParseUint` 和 `ParseInt` 中，**只有当 `base=0` 时** (表示根据前缀自动推断进制) 才允许使用下划线。对于其他明确指定的 `base`，下划线会被视为语法错误。
   ```go
   package main

   import (
       "fmt"
       "strconv"
   )

   func main() {
       // base=0 时允许下划线 (推断为十进制)
       num1, _ := strconv.ParseUint("1_234_5", 0, 64)
       fmt.Println(num1) // 输出: 12345

       // base=10 时不允许下划线
       _, err := strconv.ParseUint("1_234_5", 10, 64)
       if err != nil {
           fmt.Println("错误:", err) // 输出: 错误: strconv.ParseUint: parsing "1_234_5": invalid syntax
       }
   }
   ```

3. **指定的 `bitSize` 与实际数值不符导致溢出：** 如果 `bitSize` 设置得太小，而输入的字符串表示的数字超出了该位数能表示的范围，`ParseUint` 和 `ParseInt` 会返回 `ErrRange` 错误。
   ```go
   package main

   import (
       "fmt"
       "strconv"
   )

   func main() {
       // 尝试将一个较大的数解析为 uint8 (8 位无符号整数)
       _, err := strconv.ParseUint("256", 10, 8)
       if err != nil {
           fmt.Println("错误:", err) // 输出: 错误: strconv.ParseUint: parsing "256": range out of range
       }
   }
   ```

4. **进制 `base` 的取值范围错误：** `base` 的有效取值范围是 0 和 2 到 36。如果超出这个范围，`ParseUint` 和 `ParseInt` 会返回错误。
   ```go
   package main

   import (
       "fmt"
       "strconv"
   )

   func main() {
       _, err := strconv.ParseUint("10", 1, 64)
       if err != nil {
           fmt.Println("错误:", err) // 输出: 错误: strconv.ParseUint: invalid base 1
       }
   }
   ```

理解这些测试用例可以帮助我们更好地掌握 `strconv` 包中字符串到整数转换的功能，并避免在使用过程中犯常见的错误。

### 提示词
```
这是路径为go/src/strconv/atoi_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package strconv_test

import (
	"errors"
	"fmt"
	"reflect"
	. "strconv"
	"testing"
)

type parseUint64Test struct {
	in  string
	out uint64
	err error
}

var parseUint64Tests = []parseUint64Test{
	{"", 0, ErrSyntax},
	{"0", 0, nil},
	{"1", 1, nil},
	{"12345", 12345, nil},
	{"012345", 12345, nil},
	{"12345x", 0, ErrSyntax},
	{"98765432100", 98765432100, nil},
	{"18446744073709551615", 1<<64 - 1, nil},
	{"18446744073709551616", 1<<64 - 1, ErrRange},
	{"18446744073709551620", 1<<64 - 1, ErrRange},
	{"1_2_3_4_5", 0, ErrSyntax}, // base=10 so no underscores allowed
	{"_12345", 0, ErrSyntax},
	{"1__2345", 0, ErrSyntax},
	{"12345_", 0, ErrSyntax},
	{"-0", 0, ErrSyntax},
	{"-1", 0, ErrSyntax},
	{"+1", 0, ErrSyntax},
}

type parseUint64BaseTest struct {
	in   string
	base int
	out  uint64
	err  error
}

var parseUint64BaseTests = []parseUint64BaseTest{
	{"", 0, 0, ErrSyntax},
	{"0", 0, 0, nil},
	{"0x", 0, 0, ErrSyntax},
	{"0X", 0, 0, ErrSyntax},
	{"1", 0, 1, nil},
	{"12345", 0, 12345, nil},
	{"012345", 0, 012345, nil},
	{"0x12345", 0, 0x12345, nil},
	{"0X12345", 0, 0x12345, nil},
	{"12345x", 0, 0, ErrSyntax},
	{"0xabcdefg123", 0, 0, ErrSyntax},
	{"123456789abc", 0, 0, ErrSyntax},
	{"98765432100", 0, 98765432100, nil},
	{"18446744073709551615", 0, 1<<64 - 1, nil},
	{"18446744073709551616", 0, 1<<64 - 1, ErrRange},
	{"18446744073709551620", 0, 1<<64 - 1, ErrRange},
	{"0xFFFFFFFFFFFFFFFF", 0, 1<<64 - 1, nil},
	{"0x10000000000000000", 0, 1<<64 - 1, ErrRange},
	{"01777777777777777777777", 0, 1<<64 - 1, nil},
	{"01777777777777777777778", 0, 0, ErrSyntax},
	{"02000000000000000000000", 0, 1<<64 - 1, ErrRange},
	{"0200000000000000000000", 0, 1 << 61, nil},
	{"0b", 0, 0, ErrSyntax},
	{"0B", 0, 0, ErrSyntax},
	{"0b101", 0, 5, nil},
	{"0B101", 0, 5, nil},
	{"0o", 0, 0, ErrSyntax},
	{"0O", 0, 0, ErrSyntax},
	{"0o377", 0, 255, nil},
	{"0O377", 0, 255, nil},

	// underscores allowed with base == 0 only
	{"1_2_3_4_5", 0, 12345, nil}, // base 0 => 10
	{"_12345", 0, 0, ErrSyntax},
	{"1__2345", 0, 0, ErrSyntax},
	{"12345_", 0, 0, ErrSyntax},

	{"1_2_3_4_5", 10, 0, ErrSyntax}, // base 10
	{"_12345", 10, 0, ErrSyntax},
	{"1__2345", 10, 0, ErrSyntax},
	{"12345_", 10, 0, ErrSyntax},

	{"0x_1_2_3_4_5", 0, 0x12345, nil}, // base 0 => 16
	{"_0x12345", 0, 0, ErrSyntax},
	{"0x__12345", 0, 0, ErrSyntax},
	{"0x1__2345", 0, 0, ErrSyntax},
	{"0x1234__5", 0, 0, ErrSyntax},
	{"0x12345_", 0, 0, ErrSyntax},

	{"1_2_3_4_5", 16, 0, ErrSyntax}, // base 16
	{"_12345", 16, 0, ErrSyntax},
	{"1__2345", 16, 0, ErrSyntax},
	{"1234__5", 16, 0, ErrSyntax},
	{"12345_", 16, 0, ErrSyntax},

	{"0_1_2_3_4_5", 0, 012345, nil}, // base 0 => 8 (0377)
	{"_012345", 0, 0, ErrSyntax},
	{"0__12345", 0, 0, ErrSyntax},
	{"01234__5", 0, 0, ErrSyntax},
	{"012345_", 0, 0, ErrSyntax},

	{"0o_1_2_3_4_5", 0, 012345, nil}, // base 0 => 8 (0o377)
	{"_0o12345", 0, 0, ErrSyntax},
	{"0o__12345", 0, 0, ErrSyntax},
	{"0o1234__5", 0, 0, ErrSyntax},
	{"0o12345_", 0, 0, ErrSyntax},

	{"0_1_2_3_4_5", 8, 0, ErrSyntax}, // base 8
	{"_012345", 8, 0, ErrSyntax},
	{"0__12345", 8, 0, ErrSyntax},
	{"01234__5", 8, 0, ErrSyntax},
	{"012345_", 8, 0, ErrSyntax},

	{"0b_1_0_1", 0, 5, nil}, // base 0 => 2 (0b101)
	{"_0b101", 0, 0, ErrSyntax},
	{"0b__101", 0, 0, ErrSyntax},
	{"0b1__01", 0, 0, ErrSyntax},
	{"0b10__1", 0, 0, ErrSyntax},
	{"0b101_", 0, 0, ErrSyntax},

	{"1_0_1", 2, 0, ErrSyntax}, // base 2
	{"_101", 2, 0, ErrSyntax},
	{"1_01", 2, 0, ErrSyntax},
	{"10_1", 2, 0, ErrSyntax},
	{"101_", 2, 0, ErrSyntax},
}

type parseInt64Test struct {
	in  string
	out int64
	err error
}

var parseInt64Tests = []parseInt64Test{
	{"", 0, ErrSyntax},
	{"0", 0, nil},
	{"-0", 0, nil},
	{"+0", 0, nil},
	{"1", 1, nil},
	{"-1", -1, nil},
	{"+1", 1, nil},
	{"12345", 12345, nil},
	{"-12345", -12345, nil},
	{"012345", 12345, nil},
	{"-012345", -12345, nil},
	{"98765432100", 98765432100, nil},
	{"-98765432100", -98765432100, nil},
	{"9223372036854775807", 1<<63 - 1, nil},
	{"-9223372036854775807", -(1<<63 - 1), nil},
	{"9223372036854775808", 1<<63 - 1, ErrRange},
	{"-9223372036854775808", -1 << 63, nil},
	{"9223372036854775809", 1<<63 - 1, ErrRange},
	{"-9223372036854775809", -1 << 63, ErrRange},
	{"-1_2_3_4_5", 0, ErrSyntax}, // base=10 so no underscores allowed
	{"-_12345", 0, ErrSyntax},
	{"_12345", 0, ErrSyntax},
	{"1__2345", 0, ErrSyntax},
	{"12345_", 0, ErrSyntax},
	{"123%45", 0, ErrSyntax},
}

type parseInt64BaseTest struct {
	in   string
	base int
	out  int64
	err  error
}

var parseInt64BaseTests = []parseInt64BaseTest{
	{"", 0, 0, ErrSyntax},
	{"0", 0, 0, nil},
	{"-0", 0, 0, nil},
	{"1", 0, 1, nil},
	{"-1", 0, -1, nil},
	{"12345", 0, 12345, nil},
	{"-12345", 0, -12345, nil},
	{"012345", 0, 012345, nil},
	{"-012345", 0, -012345, nil},
	{"0x12345", 0, 0x12345, nil},
	{"-0X12345", 0, -0x12345, nil},
	{"12345x", 0, 0, ErrSyntax},
	{"-12345x", 0, 0, ErrSyntax},
	{"98765432100", 0, 98765432100, nil},
	{"-98765432100", 0, -98765432100, nil},
	{"9223372036854775807", 0, 1<<63 - 1, nil},
	{"-9223372036854775807", 0, -(1<<63 - 1), nil},
	{"9223372036854775808", 0, 1<<63 - 1, ErrRange},
	{"-9223372036854775808", 0, -1 << 63, nil},
	{"9223372036854775809", 0, 1<<63 - 1, ErrRange},
	{"-9223372036854775809", 0, -1 << 63, ErrRange},

	// other bases
	{"g", 17, 16, nil},
	{"10", 25, 25, nil},
	{"holycow", 35, (((((17*35+24)*35+21)*35+34)*35+12)*35+24)*35 + 32, nil},
	{"holycow", 36, (((((17*36+24)*36+21)*36+34)*36+12)*36+24)*36 + 32, nil},

	// base 2
	{"0", 2, 0, nil},
	{"-1", 2, -1, nil},
	{"1010", 2, 10, nil},
	{"1000000000000000", 2, 1 << 15, nil},
	{"111111111111111111111111111111111111111111111111111111111111111", 2, 1<<63 - 1, nil},
	{"1000000000000000000000000000000000000000000000000000000000000000", 2, 1<<63 - 1, ErrRange},
	{"-1000000000000000000000000000000000000000000000000000000000000000", 2, -1 << 63, nil},
	{"-1000000000000000000000000000000000000000000000000000000000000001", 2, -1 << 63, ErrRange},

	// base 8
	{"-10", 8, -8, nil},
	{"57635436545", 8, 057635436545, nil},
	{"100000000", 8, 1 << 24, nil},

	// base 16
	{"10", 16, 16, nil},
	{"-123456789abcdef", 16, -0x123456789abcdef, nil},
	{"7fffffffffffffff", 16, 1<<63 - 1, nil},

	// underscores
	{"-0x_1_2_3_4_5", 0, -0x12345, nil},
	{"0x_1_2_3_4_5", 0, 0x12345, nil},
	{"-_0x12345", 0, 0, ErrSyntax},
	{"_-0x12345", 0, 0, ErrSyntax},
	{"_0x12345", 0, 0, ErrSyntax},
	{"0x__12345", 0, 0, ErrSyntax},
	{"0x1__2345", 0, 0, ErrSyntax},
	{"0x1234__5", 0, 0, ErrSyntax},
	{"0x12345_", 0, 0, ErrSyntax},

	{"-0_1_2_3_4_5", 0, -012345, nil}, // octal
	{"0_1_2_3_4_5", 0, 012345, nil},   // octal
	{"-_012345", 0, 0, ErrSyntax},
	{"_-012345", 0, 0, ErrSyntax},
	{"_012345", 0, 0, ErrSyntax},
	{"0__12345", 0, 0, ErrSyntax},
	{"01234__5", 0, 0, ErrSyntax},
	{"012345_", 0, 0, ErrSyntax},

	{"+0xf", 0, 0xf, nil},
	{"-0xf", 0, -0xf, nil},
	{"0x+f", 0, 0, ErrSyntax},
	{"0x-f", 0, 0, ErrSyntax},
}

type parseUint32Test struct {
	in  string
	out uint32
	err error
}

var parseUint32Tests = []parseUint32Test{
	{"", 0, ErrSyntax},
	{"0", 0, nil},
	{"1", 1, nil},
	{"12345", 12345, nil},
	{"012345", 12345, nil},
	{"12345x", 0, ErrSyntax},
	{"987654321", 987654321, nil},
	{"4294967295", 1<<32 - 1, nil},
	{"4294967296", 1<<32 - 1, ErrRange},
	{"1_2_3_4_5", 0, ErrSyntax}, // base=10 so no underscores allowed
	{"_12345", 0, ErrSyntax},
	{"_12345", 0, ErrSyntax},
	{"1__2345", 0, ErrSyntax},
	{"12345_", 0, ErrSyntax},
}

type parseInt32Test struct {
	in  string
	out int32
	err error
}

var parseInt32Tests = []parseInt32Test{
	{"", 0, ErrSyntax},
	{"0", 0, nil},
	{"-0", 0, nil},
	{"1", 1, nil},
	{"-1", -1, nil},
	{"12345", 12345, nil},
	{"-12345", -12345, nil},
	{"012345", 12345, nil},
	{"-012345", -12345, nil},
	{"12345x", 0, ErrSyntax},
	{"-12345x", 0, ErrSyntax},
	{"987654321", 987654321, nil},
	{"-987654321", -987654321, nil},
	{"2147483647", 1<<31 - 1, nil},
	{"-2147483647", -(1<<31 - 1), nil},
	{"2147483648", 1<<31 - 1, ErrRange},
	{"-2147483648", -1 << 31, nil},
	{"2147483649", 1<<31 - 1, ErrRange},
	{"-2147483649", -1 << 31, ErrRange},
	{"-1_2_3_4_5", 0, ErrSyntax}, // base=10 so no underscores allowed
	{"-_12345", 0, ErrSyntax},
	{"_12345", 0, ErrSyntax},
	{"1__2345", 0, ErrSyntax},
	{"12345_", 0, ErrSyntax},
	{"123%45", 0, ErrSyntax},
}

type numErrorTest struct {
	num, want string
}

var numErrorTests = []numErrorTest{
	{"0", `strconv.ParseFloat: parsing "0": failed`},
	{"`", "strconv.ParseFloat: parsing \"`\": failed"},
	{"1\x00.2", `strconv.ParseFloat: parsing "1\x00.2": failed`},
}

func init() {
	// The parse routines return NumErrors wrapping
	// the error and the string. Convert the tables above.
	for i := range parseUint64Tests {
		test := &parseUint64Tests[i]
		if test.err != nil {
			test.err = &NumError{"ParseUint", test.in, test.err}
		}
	}
	for i := range parseUint64BaseTests {
		test := &parseUint64BaseTests[i]
		if test.err != nil {
			test.err = &NumError{"ParseUint", test.in, test.err}
		}
	}
	for i := range parseInt64Tests {
		test := &parseInt64Tests[i]
		if test.err != nil {
			test.err = &NumError{"ParseInt", test.in, test.err}
		}
	}
	for i := range parseInt64BaseTests {
		test := &parseInt64BaseTests[i]
		if test.err != nil {
			test.err = &NumError{"ParseInt", test.in, test.err}
		}
	}
	for i := range parseUint32Tests {
		test := &parseUint32Tests[i]
		if test.err != nil {
			test.err = &NumError{"ParseUint", test.in, test.err}
		}
	}
	for i := range parseInt32Tests {
		test := &parseInt32Tests[i]
		if test.err != nil {
			test.err = &NumError{"ParseInt", test.in, test.err}
		}
	}
}

func TestParseUint32(t *testing.T) {
	for i := range parseUint32Tests {
		test := &parseUint32Tests[i]
		out, err := ParseUint(test.in, 10, 32)
		if uint64(test.out) != out || !reflect.DeepEqual(test.err, err) {
			t.Errorf("ParseUint(%q, 10, 32) = %v, %v want %v, %v",
				test.in, out, err, test.out, test.err)
		}
	}
}

func TestParseUint64(t *testing.T) {
	for i := range parseUint64Tests {
		test := &parseUint64Tests[i]
		out, err := ParseUint(test.in, 10, 64)
		if test.out != out || !reflect.DeepEqual(test.err, err) {
			t.Errorf("ParseUint(%q, 10, 64) = %v, %v want %v, %v",
				test.in, out, err, test.out, test.err)
		}
	}
}

func TestParseUint64Base(t *testing.T) {
	for i := range parseUint64BaseTests {
		test := &parseUint64BaseTests[i]
		out, err := ParseUint(test.in, test.base, 64)
		if test.out != out || !reflect.DeepEqual(test.err, err) {
			t.Errorf("ParseUint(%q, %v, 64) = %v, %v want %v, %v",
				test.in, test.base, out, err, test.out, test.err)
		}
	}
}

func TestParseInt32(t *testing.T) {
	for i := range parseInt32Tests {
		test := &parseInt32Tests[i]
		out, err := ParseInt(test.in, 10, 32)
		if int64(test.out) != out || !reflect.DeepEqual(test.err, err) {
			t.Errorf("ParseInt(%q, 10 ,32) = %v, %v want %v, %v",
				test.in, out, err, test.out, test.err)
		}
	}
}

func TestParseInt64(t *testing.T) {
	for i := range parseInt64Tests {
		test := &parseInt64Tests[i]
		out, err := ParseInt(test.in, 10, 64)
		if test.out != out || !reflect.DeepEqual(test.err, err) {
			t.Errorf("ParseInt(%q, 10, 64) = %v, %v want %v, %v",
				test.in, out, err, test.out, test.err)
		}
	}
}

func TestParseInt64Base(t *testing.T) {
	for i := range parseInt64BaseTests {
		test := &parseInt64BaseTests[i]
		out, err := ParseInt(test.in, test.base, 64)
		if test.out != out || !reflect.DeepEqual(test.err, err) {
			t.Errorf("ParseInt(%q, %v, 64) = %v, %v want %v, %v",
				test.in, test.base, out, err, test.out, test.err)
		}
	}
}

func TestParseUint(t *testing.T) {
	switch IntSize {
	case 32:
		for i := range parseUint32Tests {
			test := &parseUint32Tests[i]
			out, err := ParseUint(test.in, 10, 0)
			if uint64(test.out) != out || !reflect.DeepEqual(test.err, err) {
				t.Errorf("ParseUint(%q, 10, 0) = %v, %v want %v, %v",
					test.in, out, err, test.out, test.err)
			}
		}
	case 64:
		for i := range parseUint64Tests {
			test := &parseUint64Tests[i]
			out, err := ParseUint(test.in, 10, 0)
			if test.out != out || !reflect.DeepEqual(test.err, err) {
				t.Errorf("ParseUint(%q, 10, 0) = %v, %v want %v, %v",
					test.in, out, err, test.out, test.err)
			}
		}
	}
}

func TestParseInt(t *testing.T) {
	switch IntSize {
	case 32:
		for i := range parseInt32Tests {
			test := &parseInt32Tests[i]
			out, err := ParseInt(test.in, 10, 0)
			if int64(test.out) != out || !reflect.DeepEqual(test.err, err) {
				t.Errorf("ParseInt(%q, 10, 0) = %v, %v want %v, %v",
					test.in, out, err, test.out, test.err)
			}
		}
	case 64:
		for i := range parseInt64Tests {
			test := &parseInt64Tests[i]
			out, err := ParseInt(test.in, 10, 0)
			if test.out != out || !reflect.DeepEqual(test.err, err) {
				t.Errorf("ParseInt(%q, 10, 0) = %v, %v want %v, %v",
					test.in, out, err, test.out, test.err)
			}
		}
	}
}

func TestAtoi(t *testing.T) {
	switch IntSize {
	case 32:
		for i := range parseInt32Tests {
			test := &parseInt32Tests[i]
			out, err := Atoi(test.in)
			var testErr error
			if test.err != nil {
				testErr = &NumError{"Atoi", test.in, test.err.(*NumError).Err}
			}
			if int(test.out) != out || !reflect.DeepEqual(testErr, err) {
				t.Errorf("Atoi(%q) = %v, %v want %v, %v",
					test.in, out, err, test.out, testErr)
			}
		}
	case 64:
		for i := range parseInt64Tests {
			test := &parseInt64Tests[i]
			out, err := Atoi(test.in)
			var testErr error
			if test.err != nil {
				testErr = &NumError{"Atoi", test.in, test.err.(*NumError).Err}
			}
			if test.out != int64(out) || !reflect.DeepEqual(testErr, err) {
				t.Errorf("Atoi(%q) = %v, %v want %v, %v",
					test.in, out, err, test.out, testErr)
			}
		}
	}
}

func bitSizeErrStub(name string, bitSize int) error {
	return BitSizeError(name, "0", bitSize)
}

func baseErrStub(name string, base int) error {
	return BaseError(name, "0", base)
}

func noErrStub(name string, arg int) error {
	return nil
}

type parseErrorTest struct {
	arg     int
	errStub func(name string, arg int) error
}

var parseBitSizeTests = []parseErrorTest{
	{-1, bitSizeErrStub},
	{0, noErrStub},
	{64, noErrStub},
	{65, bitSizeErrStub},
}

var parseBaseTests = []parseErrorTest{
	{-1, baseErrStub},
	{0, noErrStub},
	{1, baseErrStub},
	{2, noErrStub},
	{36, noErrStub},
	{37, baseErrStub},
}

func equalError(a, b error) bool {
	if a == nil {
		return b == nil
	}
	if b == nil {
		return a == nil
	}
	return a.Error() == b.Error()
}

func TestParseIntBitSize(t *testing.T) {
	for i := range parseBitSizeTests {
		test := &parseBitSizeTests[i]
		testErr := test.errStub("ParseInt", test.arg)
		_, err := ParseInt("0", 0, test.arg)
		if !equalError(testErr, err) {
			t.Errorf("ParseInt(\"0\", 0, %v) = 0, %v want 0, %v",
				test.arg, err, testErr)
		}
	}
}

func TestParseUintBitSize(t *testing.T) {
	for i := range parseBitSizeTests {
		test := &parseBitSizeTests[i]
		testErr := test.errStub("ParseUint", test.arg)
		_, err := ParseUint("0", 0, test.arg)
		if !equalError(testErr, err) {
			t.Errorf("ParseUint(\"0\", 0, %v) = 0, %v want 0, %v",
				test.arg, err, testErr)
		}
	}
}

func TestParseIntBase(t *testing.T) {
	for i := range parseBaseTests {
		test := &parseBaseTests[i]
		testErr := test.errStub("ParseInt", test.arg)
		_, err := ParseInt("0", test.arg, 0)
		if !equalError(testErr, err) {
			t.Errorf("ParseInt(\"0\", %v, 0) = 0, %v want 0, %v",
				test.arg, err, testErr)
		}
	}
}

func TestParseUintBase(t *testing.T) {
	for i := range parseBaseTests {
		test := &parseBaseTests[i]
		testErr := test.errStub("ParseUint", test.arg)
		_, err := ParseUint("0", test.arg, 0)
		if !equalError(testErr, err) {
			t.Errorf("ParseUint(\"0\", %v, 0) = 0, %v want 0, %v",
				test.arg, err, testErr)
		}
	}
}

func TestNumError(t *testing.T) {
	for _, test := range numErrorTests {
		err := &NumError{
			Func: "ParseFloat",
			Num:  test.num,
			Err:  errors.New("failed"),
		}
		if got := err.Error(); got != test.want {
			t.Errorf(`(&NumError{"ParseFloat", %q, "failed"}).Error() = %v, want %v`, test.num, got, test.want)
		}
	}
}

func TestNumErrorUnwrap(t *testing.T) {
	err := &NumError{Err: ErrSyntax}
	if !errors.Is(err, ErrSyntax) {
		t.Error("errors.Is failed, wanted success")
	}
}

func BenchmarkParseInt(b *testing.B) {
	b.Run("Pos", func(b *testing.B) {
		benchmarkParseInt(b, 1)
	})
	b.Run("Neg", func(b *testing.B) {
		benchmarkParseInt(b, -1)
	})
}

type benchCase struct {
	name string
	num  int64
}

func benchmarkParseInt(b *testing.B, neg int) {
	cases := []benchCase{
		{"7bit", 1<<7 - 1},
		{"26bit", 1<<26 - 1},
		{"31bit", 1<<31 - 1},
		{"56bit", 1<<56 - 1},
		{"63bit", 1<<63 - 1},
	}
	for _, cs := range cases {
		b.Run(cs.name, func(b *testing.B) {
			s := fmt.Sprintf("%d", cs.num*int64(neg))
			for i := 0; i < b.N; i++ {
				out, _ := ParseInt(s, 10, 64)
				BenchSink += int(out)
			}
		})
	}
}

func BenchmarkAtoi(b *testing.B) {
	b.Run("Pos", func(b *testing.B) {
		benchmarkAtoi(b, 1)
	})
	b.Run("Neg", func(b *testing.B) {
		benchmarkAtoi(b, -1)
	})
}

func benchmarkAtoi(b *testing.B, neg int) {
	cases := []benchCase{
		{"7bit", 1<<7 - 1},
		{"26bit", 1<<26 - 1},
		{"31bit", 1<<31 - 1},
	}
	if IntSize == 64 {
		cases = append(cases, []benchCase{
			{"56bit", 1<<56 - 1},
			{"63bit", 1<<63 - 1},
		}...)
	}
	for _, cs := range cases {
		b.Run(cs.name, func(b *testing.B) {
			s := fmt.Sprintf("%d", cs.num*int64(neg))
			for i := 0; i < b.N; i++ {
				out, _ := Atoi(s)
				BenchSink += out
			}
		})
	}
}
```